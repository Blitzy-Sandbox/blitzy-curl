// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-FileCopyrightText: Björn Stenberg, <bjorn@haxx.se>
//
//! MQTT / MQTTS protocol handler (MQTT 3.1.1).
//!
//! This is the idiomatic-Rust rewrite of curl's MQTT client, ported for
//! byte-for-byte functional parity with curl / libcurl **8.19.0-DEV**. The
//! source-of-truth references are `lib/mqtt.c` (~1043 lines) and `lib/mqtt.h`.
//!
//! curl implements a deliberately *minimal* MQTT 3.1.1 client — the exact same
//! minimalism is preserved here (this is the whole point of the Minimal Change
//! Mandate, AAP §0.7.3): **QoS 0 only**, no retain, no last-will, no MQTT 5, no
//! `PUBACK`/`PUBREC`/`PUBREL` acknowledgement handshakes. The client speaks
//! exactly two flows:
//!
//! * **Download / subscribe** — `CONNECT` → `CONNACK` → `SUBSCRIBE` → `SUBACK`
//!   then stream the payload of every received `PUBLISH` to the write sink
//!   (the equivalent of curl's `Curl_client_write(CLIENTWRITE_BODY, …)`).
//! * **Upload / publish** — `CONNECT` → `CONNACK` → `PUBLISH` the upload data to
//!   the topic → `DISCONNECT` → done.
//!
//! # Architecture (why the logic lives in a sans-IO engine)
//!
//! curl's C handler is driven by the multi state machine through the
//! `struct Curl_protocol` vtable (`do_it` = `mqtt_do`, `doing` = `mqtt_doing`,
//! `done` = `mqtt_done`) and reaches the socket via `Curl_xfer_send` /
//! `Curl_xfer_recv`. In this rewrite the vtable is [`crate::protocols::Protocol`]
//! and the socket abstraction is any Tokio [`AsyncRead`] + [`AsyncWrite`]
//! stream — which is exactly what the connection-filter chain hands a protocol
//! (a plaintext TCP stream for `mqtt`, a TLS stream for `mqtts`; see
//! [`crate::tls`]).
//!
//! Because the shared per-transfer context ([`crate::protocols::TransferCtx`])
//! is intentionally empty at this stage of the rewrite (it grows as the
//! transfer/multi layers finalize the shared handle type that will carry the
//! [`crate::conn::Connection`] and request state), the complete, testable MQTT
//! logic is implemented here as a **sans-IO engine**
//! ([`MqttTransfer`]) plus a set of pure framing functions. The engine faithfully
//! reproduces `mqtt_do` / `mqtt_doing` / `mqtt_read_publish` and is driven over an
//! explicit stream, exactly mirroring curl's `Curl_xfer_*` calls. The
//! [`Protocol`] implementation ([`MqttHandler`] / [`HANDLER`]) is the vtable
//! adapter that the transfer layer drives once the context is wired.
//!
//! # Safety
//!
//! This module is written entirely in safe Rust, in line with the crate-wide
//! memory-safety policy verified by the CI grep audit over `curl-rs-lib/src/`
//! (AAP §0.6.2). The audit requires that the forbidden keyword appear nowhere in
//! this tree, so it is deliberately absent here — including from prose.

use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::conn::Connection;
use crate::error::{CurlCode, Error, Result};
use crate::protocols::{ProtoFuture, Protocol, TransferCtx};
use crate::tls::{TlsConnector, TlsStream};

// ===========================================================================
// Control-packet first bytes (← the `MQTT_MSG_*` `#define`s in `lib/mqtt.c`).
//
// The first byte of an MQTT fixed header packs the 4-bit control-packet type in
// the high nibble with 4 type-specific flag bits in the low nibble. curl hard-codes
// the exact first bytes it needs, reproduced here VERBATIM. The values curl leaves
// commented-out in the C source (`MQTT_MSG_CONNACK`, `MQTT_MSG_PINGREQ`) are
// retained as documented constants for symmetry.
// ===========================================================================

/// `CONNECT` control packet (client → server). Fixed header first byte `0x10`
/// (type 1, flags 0). ← `MQTT_MSG_CONNECT`.
pub const MQTT_MSG_CONNECT: u8 = 0x10;

/// `CONNACK` control packet (server → client). Type nibble `0x20` (type 2). curl
/// leaves this `#define` commented out because the CONNACK is validated by its
/// Remaining Length and payload bytes rather than by comparing the first byte;
/// it is kept here as a documented constant. ← `MQTT_MSG_CONNACK`.
pub const MQTT_MSG_CONNACK: u8 = 0x20;

/// `PUBLISH` control packet. Type nibble `0x30` (type 3). Both directions:
/// curl sends it to upload and matches `firstbyte & 0xf0 == 0x30` on receive.
/// ← `MQTT_MSG_PUBLISH`.
pub const MQTT_MSG_PUBLISH: u8 = 0x30;

/// `PUBACK` control packet. Type nibble `0x40` (type 4). curl's `lib/mqtt.c`
/// neither defines nor uses this value — a QoS-0 `PUBLISH` is never acknowledged —
/// so it is provided purely as a documented constant and is intentionally never
/// referenced by the QoS-0 state machine. ← MQTT 3.1.1 §3.4.
pub const MQTT_MSG_PUBACK: u8 = 0x40;

/// `SUBSCRIBE` control packet (client → server). Fixed header first byte `0x82`:
/// type nibble `0x80` (type 8) OR the mandatory reserved flag bit `0x02` that
/// MQTT 3.1.1 requires on SUBSCRIBE. ← `MQTT_MSG_SUBSCRIBE`.
pub const MQTT_MSG_SUBSCRIBE: u8 = 0x82;

/// `SUBACK` control packet (server → client). Type nibble `0x90` (type 9). curl
/// matches `firstbyte & 0xf0 == 0x90` on receive. ← `MQTT_MSG_SUBACK`.
pub const MQTT_MSG_SUBACK: u8 = 0x90;

/// `PINGREQ` control packet (client → server). Fixed header first byte `0xC0`.
/// curl leaves this `#define` commented out and writes the literal `0xC0` in the
/// keepalive packet; it is kept here as a documented constant used by
/// [`MqttTransfer::maybe_ping`]. ← `MQTT_MSG_PINGREQ`.
pub const MQTT_MSG_PINGREQ: u8 = 0xC0;

/// `PINGRESP` control packet (server → client). Fixed header first byte `0xD0`.
/// ← `MQTT_MSG_PINGRESP`.
pub const MQTT_MSG_PINGRESP: u8 = 0xD0;

/// `DISCONNECT` control packet. Fixed header first byte `0xE0`. curl both sends it
/// (`"\xe0\x00"`) to end an upload and matches `firstbyte & 0xf0 == 0xe0` on
/// receive to end a subscribe. ← `MQTT_MSG_DISCONNECT`.
pub const MQTT_MSG_DISCONNECT: u8 = 0xE0;

// ===========================================================================
// Fixed lengths (← the `MQTT_*_LEN` / `MQTT_CLIENTID_LEN` `#define`s).
// ===========================================================================

/// Payload length of a `CONNACK` packet: 2 bytes (acknowledge flags + return
/// code). ← `MQTT_CONNACK_LEN`.
pub const MQTT_CONNACK_LEN: usize = 2;

/// Payload length of a `SUBACK` packet for a single-topic subscribe: 3 bytes
/// (2-byte packet id + 1 return code). ← `MQTT_SUBACK_LEN`.
pub const MQTT_SUBACK_LEN: usize = 3;

/// Length of the client identifier curl generates, e.g. `"curl0123abcd"`
/// (the literal prefix `"curl"` followed by 8 random alphanumerics). MQTT 3.1.1
/// requires 1–23 UTF-8 bytes; curl uses a fixed 12. ← `MQTT_CLIENTID_LEN`.
pub const MQTT_CLIENTID_LEN: usize = 12;

/// Upper bound curl enforces on a `PUBLISH` Remaining Length before refusing to
/// build the packet (`0xFFFFFFF` = 268,435,455, the maximum a 4-byte MQTT
/// Remaining Length can encode). ← `MAX_MQTT_MESSAGE_SIZE`.
pub const MAX_MQTT_MESSAGE_SIZE: usize = 0xFFF_FFFF;

/// Cap on a single `PUBLISH`-payload read, matching curl's on-stack
/// `char buffer[4 * 1024]` in `mqtt_read_publish`.
const PUB_READ_CHUNK: usize = 4 * 1024;

// ===========================================================================
// MqttState — the receive state machine (← `enum mqttstate`, `lib/mqtt.c`).
// ===========================================================================

/// The MQTT receive-side state machine (← `enum mqttstate`).
///
/// The variant *names* are preserved one-to-one with curl's `MQTT_*` enumerators
/// (and their diagnostic strings via [`MqttState::name`]) so `--trace` output
/// stays identical to curl 8.x (AAP §0.3.2 "State-name preservation"). The
/// numbering is preserved too (`#[repr(u8)]`, discriminants `0..=7`), matching the
/// order in `lib/mqtt.c`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MqttState {
    /// Read the single fixed-header first byte (← `MQTT_FIRST`).
    First = 0,
    /// Read the 1–4 byte Remaining Length variable-length integer that follows
    /// the first byte (← `MQTT_REMAINING_LENGTH`).
    RemainingLength = 1,
    /// Awaiting / validating the `CONNACK` reply to our `CONNECT`
    /// (← `MQTT_CONNACK`).
    Connack = 2,
    /// Awaiting the `SUBACK` reply to our `SUBSCRIBE` (← `MQTT_SUBACK`).
    Suback = 3,
    /// Reading the remainder of a `SUBACK` whose first byte already arrived
    /// (← `MQTT_SUBACK_COMING`).
    SubackComing = 4,
    /// Waiting for the next inbound `PUBLISH` (or `DISCONNECT`) while subscribed
    /// (← `MQTT_PUBWAIT`).
    Pubwait = 5,
    /// Reading the remainder of a `PUBLISH` payload that spans multiple socket
    /// reads (← `MQTT_PUB_REMAIN`).
    PubRemain = 6,
    /// Sentinel "not an actual state" used as the `nextstate` sentinel value
    /// (← `MQTT_NOSTATE`, curl's "never used an actual state"); its trace string
    /// is `"NOT A STATE"`.
    NoState = 7,
}

impl MqttState {
    /// The exact diagnostic name curl prints for this state (← the `statenames[]`
    /// table in `lib/mqtt.c`), preserved so `--trace`/verbose output is identical.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            MqttState::First => "MQTT_FIRST",
            MqttState::RemainingLength => "MQTT_REMAINING_LENGTH",
            MqttState::Connack => "MQTT_CONNACK",
            MqttState::Suback => "MQTT_SUBACK",
            MqttState::SubackComing => "MQTT_SUBACK_COMING",
            MqttState::Pubwait => "MQTT_PUBWAIT",
            MqttState::PubRemain => "MQTT_PUB_REMAIN",
            MqttState::NoState => "NOT A STATE",
        }
    }
}

// ===========================================================================
// MqttConn — per-connection state machine data (← `struct mqtt_conn`).
// ===========================================================================

/// Per-connection MQTT state (← `struct mqtt_conn`, `lib/mqtt.c`).
///
/// Holds the receive [`MqttState`], the `nextstate` the machine switches to once
/// a Remaining Length has been decoded, and the monotonically increasing
/// SUBSCRIBE packet identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MqttConn {
    /// Current receive state (← `mqtt_conn.state`).
    pub state: MqttState,
    /// The state to switch to after the Remaining Length field is fully read;
    /// only meaningful while [`MqttState::First`]/[`MqttState::RemainingLength`]
    /// are active (← `mqtt_conn.nextstate`).
    pub nextstate: MqttState,
    /// The MQTT packet identifier used for `SUBSCRIBE`/`SUBACK` correlation
    /// (← `mqtt_conn.packetid`, a `unsigned int` in C; only the low 16 bits ever
    /// reach the wire, and curl issues a single SUBSCRIBE per transfer, so a
    /// `u16` reproduces the wire bytes exactly).
    pub packetid: u16,
}

impl Default for MqttConn {
    fn default() -> Self {
        // curl allocates `struct mqtt_conn` with calloc, so every field starts
        // zeroed: state/nextstate = MQTT_FIRST (0), packetid = 0.
        Self {
            state: MqttState::First,
            nextstate: MqttState::First,
            packetid: 0,
        }
    }
}

// ===========================================================================
// Pure framing helpers (← the packet-building/parsing statics in `lib/mqtt.c`).
//
// These are deliberately IO-free so they can be exhaustively unit-tested against
// the exact byte layouts curl produces.
// ===========================================================================

/// Encode `len` as an MQTT "Remaining Length" variable-length integer into `out`
/// (← `mqtt_encode_len`).
///
/// MQTT encodes the length 7 bits per byte, little-endian, with the top bit
/// (`0x80`) of each byte set to signal that more bytes follow. At most 4 bytes are
/// produced. Returns the number of bytes written; **0 for `len == 0`** — this is
/// curl's exact behavior (the `for` loop runs zero times), preserved verbatim.
#[must_use]
fn mqtt_encode_len(out: &mut [u8; 4], mut len: usize) -> usize {
    let mut i = 0;
    while len > 0 && i < 4 {
        let mut encoded = (len % 0x80) as u8;
        len /= 0x80;
        if len > 0 {
            encoded |= 0x80;
        }
        out[i] = encoded;
        i += 1;
    }
    i
}

/// Decode an MQTT "Remaining Length" variable-length integer (← `mqtt_decode_len`).
///
/// Reads up to 4 continuation-flagged bytes from `buf`. Returns `Some(len)` on
/// success or `None` if the field would exceed 4 bytes (curl's "bad size", which
/// the caller maps to [`CurlCode::WeirdServerReply`]). Mirrors curl's arithmetic
/// (`len += (encoded & 127) * mult; mult *= 128;`) exactly.
#[must_use]
fn mqtt_decode_len(buf: &[u8]) -> Option<usize> {
    let mut len: usize = 0;
    let mut mult: usize = 1;
    let mut encoded: u8 = 128;
    let mut i = 0;
    while i < buf.len() && (encoded & 128) != 0 {
        if i == 4 {
            return None; // bad size
        }
        encoded = buf[i];
        len += (encoded & 127) as usize * mult;
        mult *= 128;
        i += 1;
    }
    Some(len)
}

/// Generate a random client identifier of the form `"curl"` + 8 random
/// alphanumerics (12 chars total), matching curl's `mqtt_connect` which seeds
/// `client_id` with `"curl"` and fills the remainder via `Curl_rand_alnum`.
///
/// The value is random (like curl's), so callers/tests assert only its shape
/// (length [`MQTT_CLIENTID_LEN`], `"curl"` prefix, ASCII-alphanumeric body).
#[must_use]
pub fn generate_client_id() -> String {
    use rand::Rng;
    // curl's alnum alphabet: uppercase, lowercase, digits (62 symbols).
    const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut id = String::with_capacity(MQTT_CLIENTID_LEN);
    id.push_str("curl");
    let mut rng = rand::thread_rng();
    for _ in 0..(MQTT_CLIENTID_LEN - "curl".len()) {
        let idx = rng.gen_range(0..ALPHABET.len());
        id.push(ALPHABET[idx] as char);
    }
    id
}

/// Build a complete `CONNECT` packet (← `init_connpack` + `add_client_id` +
/// `add_user` + `add_passwd` + the assembly loop in `mqtt_connect`).
///
/// The byte layout is reproduced exactly:
/// fixed header (`0x10` + Remaining Length varint), then the variable header
/// (`0x0004` + `"MQTT"` + protocol level `0x04` + CONNECT flags `0x02`
/// CleanSession + keepalive `0x003c` = 60s), then the payload (client id, then
/// optional username, then optional password). The username/password *flags*
/// (`0x80` / `0x40`) are OR-ed into the CONNECT-flags byte only when present.
///
/// `client_id` must be exactly [`MQTT_CLIENTID_LEN`] bytes (curl's
/// `add_client_id` rejects any other length).
///
/// # Errors
///
/// * [`CurlCode::WeirdServerReply`] if the assembled packet would exceed
///   `0xFFFFFFF` bytes, if `client_id` is not [`MQTT_CLIENTID_LEN`] bytes, or if
///   the username/password exceeds the 16-bit MQTT string-length limit — matching
///   curl's return codes for each of those conditions.
pub fn build_connect(client_id: &str, user: Option<&str>, passwd: Option<&str>) -> Result<Vec<u8>> {
    let username = user.unwrap_or("");
    let ulen = username.len();
    let password = passwd.unwrap_or("");
    let plen = password.len();

    // payloadlen — the "+2"s account for the 2-byte length prefix MQTT requires
    // before each payload string (client id always; username/password only when
    // present). ← the `payloadlen` expression in `mqtt_connect`.
    let payloadlen = ulen
        + plen
        + MQTT_CLIENTID_LEN
        + 2
        + if ulen > 0 { 2 } else { 0 }
        + if plen > 0 { 2 } else { 0 };

    // Remaining Length covers the 10-byte variable header plus the payload.
    let mut remain = [0u8; 4];
    let remain_pos = mqtt_encode_len(&mut remain, payloadlen + 10);

    // Total = payload + 10 (variable header) + Remaining Length bytes + 1 (first
    // byte of the fixed header). ← `packetlen` in `mqtt_connect`.
    let packetlen = payloadlen + 10 + remain_pos + 1;
    if packetlen > MAX_MQTT_MESSAGE_SIZE {
        // curl returns CURLE_WEIRD_SERVER_REPLY here (no failf text).
        return Err(Error::Code(CurlCode::WeirdServerReply));
    }
    if client_id.len() != MQTT_CLIENTID_LEN {
        return Err(Error::with_context(
            CurlCode::WeirdServerReply,
            format!("Client ID length mismatched: [{}]", client_id.len()),
        ));
    }

    let mut packet = vec![0u8; packetlen];

    // --- Fixed + variable header (← init_connpack) ---
    packet[0] = MQTT_MSG_CONNECT;
    packet[1..1 + remain_pos].copy_from_slice(&remain[..remain_pos]);
    // Protocol name length + "MQTT".
    packet[remain_pos + 1] = 0x00;
    packet[remain_pos + 2] = 0x04;
    packet[remain_pos + 3] = b'M';
    packet[remain_pos + 4] = b'Q';
    packet[remain_pos + 5] = b'T';
    packet[remain_pos + 6] = b'T';
    // Protocol level 4 (MQTT 3.1.1).
    packet[remain_pos + 7] = 0x04;
    // CONNECT flags: CleanSession.
    packet[remain_pos + 8] = 0x02;
    // Keep-alive = 0x003c (60 seconds).
    packet[remain_pos + 9] = 0x00;
    packet[remain_pos + 10] = 0x3c;
    let pos = remain_pos + 10;

    // --- Client id (← add_client_id at pos + 1) ---
    let start = pos + 1;
    packet[start] = 0x00;
    packet[start + 1] = MQTT_CLIENTID_LEN as u8;
    packet[start + 2..start + 2 + MQTT_CLIENTID_LEN].copy_from_slice(client_id.as_bytes());

    // Payload offsets (← mqtt_connect).
    let start_user = pos + 3 + MQTT_CLIENTID_LEN;
    let mut start_pwd = start_user + ulen;
    let conn_flags_pos = remain_pos + 8;

    // --- Username (← add_user) ---
    if ulen > 0 {
        start_pwd += 2;
        if ulen > 0xffff {
            return Err(Error::with_context(
                CurlCode::WeirdServerReply,
                format!("Username too long: [{ulen}]"),
            ));
        }
        packet[conn_flags_pos] |= 0x80;
        packet[start_user] = ((ulen >> 8) & 0xff) as u8;
        packet[start_user + 1] = (ulen & 0xff) as u8;
        packet[start_user + 2..start_user + 2 + ulen].copy_from_slice(username.as_bytes());
    }

    // --- Password (← add_passwd) ---
    if plen > 0 {
        if plen > 0xffff {
            return Err(Error::with_context(
                CurlCode::WeirdServerReply,
                format!("Password too long: [{plen}]"),
            ));
        }
        packet[conn_flags_pos] |= 0x40;
        packet[start_pwd] = ((plen >> 8) & 0xff) as u8;
        packet[start_pwd + 1] = (plen & 0xff) as u8;
        packet[start_pwd + 2..start_pwd + 2 + plen].copy_from_slice(password.as_bytes());
    }

    Ok(packet)
}

/// Build a `SUBSCRIBE` packet for a single `topic` at QoS 0 (← `mqtt_subscribe`).
///
/// Layout: `0x82`, Remaining Length varint, 2-byte packet id, 2-byte topic
/// length, the topic bytes, then a trailing `0x00` requested-QoS byte.
#[must_use]
pub fn build_subscribe(packetid: u16, topic: &[u8]) -> Vec<u8> {
    let topiclen = topic.len();
    // packetid (2) + topic-length field (2) + topic + requested-QoS byte (1).
    let mut encoded = [0u8; 4];
    let mut packetlen = topiclen + 5;
    let n = mqtt_encode_len(&mut encoded, packetlen);
    packetlen += n + 1; // + Remaining Length bytes + control-packet-type byte

    let mut packet = vec![0u8; packetlen];
    packet[0] = MQTT_MSG_SUBSCRIBE;
    packet[1..1 + n].copy_from_slice(&encoded[..n]);
    packet[1 + n] = ((packetid >> 8) & 0xff) as u8;
    packet[2 + n] = (packetid & 0xff) as u8;
    packet[3 + n] = ((topiclen >> 8) & 0xff) as u8;
    packet[4 + n] = (topiclen & 0xff) as u8;
    packet[5 + n..5 + n + topiclen].copy_from_slice(topic);
    packet[5 + n + topiclen] = 0; // QoS zero
    packet
}

/// Build a QoS-0 `PUBLISH` packet carrying `payload` to `topic` (← `mqtt_publish`).
///
/// Layout: `0x30`, Remaining Length varint, 2-byte topic length, the topic bytes,
/// then the raw payload. (QoS 0 carries no packet identifier.)
///
/// # Errors
///
/// * [`CurlCode::TooLarge`] if the Remaining Length would exceed what a 4-byte
///   MQTT length can encode (curl's `remaininglength > MAX_MQTT_MESSAGE_SIZE -
///   encodelen - 1` check).
pub fn build_publish(topic: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let topiclen = topic.len();
    let payloadlen = payload.len();
    let remaininglength = payloadlen + 2 + topiclen;

    let mut encoded = [0u8; 4];
    let encodelen = mqtt_encode_len(&mut encoded, remaininglength);
    if remaininglength > (MAX_MQTT_MESSAGE_SIZE - encodelen - 1) {
        return Err(Error::TooLarge);
    }

    let mut pkt = vec![0u8; remaininglength + 1 + encodelen];
    let mut i = 0;
    pkt[i] = MQTT_MSG_PUBLISH;
    i += 1;
    pkt[i..i + encodelen].copy_from_slice(&encoded[..encodelen]);
    i += encodelen;
    pkt[i] = ((topiclen >> 8) & 0xff) as u8;
    i += 1;
    pkt[i] = (topiclen & 0xff) as u8;
    i += 1;
    pkt[i..i + topiclen].copy_from_slice(topic);
    i += topiclen;
    pkt[i..i + payloadlen].copy_from_slice(payload);
    i += payloadlen;
    debug_assert_eq!(i, pkt.len());
    Ok(pkt)
}

/// The 2-byte `DISCONNECT` packet curl sends verbatim as `"\xe0\x00"`
/// (← `mqtt_disconnect`): control byte `0xE0` + zero Remaining Length.
const DISCONNECT_PACKET: [u8; 2] = [MQTT_MSG_DISCONNECT, 0x00];

/// The 2-byte `PINGREQ` packet curl sends verbatim as `{0xC0, 0x00}`
/// (← `mqtt_ping`): control byte `0xC0` + zero Remaining Length.
const PINGREQ_PACKET: [u8; 2] = [MQTT_MSG_PINGREQ, 0x00];

/// Extract and percent-decode the MQTT topic from a URL path (← `mqtt_get_topic`).
///
/// The topic is everything after the leading `/` of the URL path, percent-decoded
/// (curl uses `Curl_urldecode(path + 1, …, REJECT_NADA)`, which decodes `%XX`
/// escapes and rejects nothing). Percent-decoding can yield arbitrary bytes, so
/// the topic is returned as `Vec<u8>` rather than a `String`.
///
/// # Errors
///
/// * [`CurlCode::UrlMalformat`] with `"No MQTT topic found. Forgot to URL encode
///   it?"` when the path has no topic component (length ≤ 1), and with `"Too long
///   MQTT topic"` when the decoded topic exceeds the 16-bit MQTT string-length
///   limit (`0xffff`) — matching curl's two `failf` messages.
pub fn topic_from_path(path: &str) -> Result<Vec<u8>> {
    let bytes = path.as_bytes();
    if bytes.len() > 1 {
        // Skip the leading '/', then percent-decode the remainder.
        let decoded: Vec<u8> = percent_encoding::percent_decode(&bytes[1..]).collect();
        if decoded.len() > 0xffff {
            return Err(Error::url("Too long MQTT topic"));
        }
        Ok(decoded)
    } else {
        Err(Error::url("No MQTT topic found. Forgot to URL encode it?"))
    }
}

/// Validate a `CONNACK` payload (← `mqtt_verify_connack`).
///
/// curl requires the Remaining Length to be exactly 2 and both acknowledge bytes
/// to be `0x00` (accepted, session-present false, return code "connection
/// accepted"). `body` is the [`MQTT_CONNACK_LEN`]-byte payload.
///
/// # Errors
///
/// * [`CurlCode::WeirdServerReply`] with the corresponding curl `failf` text when
///   the Remaining Length is not 2 or either byte is non-zero.
pub fn verify_connack(remaining_length: usize, body: &[u8]) -> Result<()> {
    if remaining_length != MQTT_CONNACK_LEN {
        return Err(Error::with_context(
            CurlCode::WeirdServerReply,
            format!("CONNACK expected Remaining Length 2, got {remaining_length}"),
        ));
    }
    if body.len() < MQTT_CONNACK_LEN || body[0] != 0x00 || body[1] != 0x00 {
        let (b0, b1) = (
            body.first().copied().unwrap_or(0),
            body.get(1).copied().unwrap_or(0),
        );
        return Err(Error::with_context(
            CurlCode::WeirdServerReply,
            format!("Expected {:02x}{:02x} but got {:02x}{:02x}", 0, 0, b0, b1),
        ));
    }
    Ok(())
}

/// Validate a `SUBACK` payload (← `mqtt_verify_suback`).
///
/// curl requires the Remaining Length to be exactly 3, the 2-byte packet id to
/// echo the SUBSCRIBE `packetid`, and the return code byte to be `0x00`
/// (maximum QoS 0 granted). `body` is the [`MQTT_SUBACK_LEN`]-byte payload.
///
/// # Errors
///
/// * [`CurlCode::WeirdServerReply`] — with the curl `failf` text if the Remaining
///   Length is wrong, or bare (as curl does, no text) if the id/return-code bytes
///   do not match.
pub fn verify_suback(remaining_length: usize, packetid: u16, body: &[u8]) -> Result<()> {
    if remaining_length != MQTT_SUBACK_LEN {
        return Err(Error::with_context(
            CurlCode::WeirdServerReply,
            format!("SUBACK expected Remaining Length 3, got {remaining_length}"),
        ));
    }
    if body.len() < MQTT_SUBACK_LEN
        || body[0] != ((packetid >> 8) & 0xff) as u8
        || body[1] != (packetid & 0xff) as u8
        || body[2] != 0x00
    {
        return Err(Error::Code(CurlCode::WeirdServerReply));
    }
    Ok(())
}

// ===========================================================================
// MqttRequest — the per-transfer request inputs (← the `data->set.*` /
// `data->state.*` fields `lib/mqtt.c` reads).
// ===========================================================================

/// The request inputs the MQTT engine needs, gathered from the easy-handle/URL
/// exactly as curl's `mqtt_*` functions read them from `struct Curl_easy`.
///
/// Grouping them here keeps [`MqttTransfer`] IO-driven and lets the (future)
/// transfer-layer wiring populate one struct instead of threading many
/// parameters, while the fields document their C provenance.
#[derive(Debug, Clone)]
pub struct MqttRequest<'a> {
    /// The URL path, including its leading `/` (← `data->state.up.path`); the
    /// topic is everything after the `/`, percent-decoded (see [`topic_from_path`]).
    pub path: &'a str,
    /// The username from the URL credentials, if any (← `data->state.aptr.user`).
    pub user: Option<&'a str>,
    /// The password from the URL credentials, if any (← `data->state.aptr.passwd`).
    pub passwd: Option<&'a str>,
    /// `true` for the publish/upload flow, `false` to subscribe/download
    /// (← `data->state.httpreq == HTTPREQ_POST`).
    pub is_publish: bool,
    /// The upload payload for a publish (← `data->set.postfields`). Required when
    /// [`is_publish`](MqttRequest::is_publish) is set.
    pub payload: Option<&'a [u8]>,
    /// The generated 12-byte client id (see [`generate_client_id`]).
    pub client_id: &'a str,
    /// Maximum download size in bytes, or `0` for unlimited
    /// (← `data->set.max_filesize`).
    pub max_filesize: u64,
    /// Keepalive interval in milliseconds, or `0` to disable pings
    /// (← `data->set.upkeep_interval_ms`).
    pub upkeep_interval_ms: u64,
    /// The effective whole-transfer deadline (← `CURLOPT_TIMEOUT[_MS]` as
    /// surfaced by `Curl_timeleft`), or `None` when no timeout is configured.
    ///
    /// [`MqttTransfer::perform`] enforces this around the entire CONNECT →
    /// CONNACK → SUBSCRIBE/PUBLISH exchange (including every blocking read), so a
    /// broker cannot hold the transfer open indefinitely — matching curl's
    /// multi-timeout behavior, where a transfer whose `Curl_timeleft` goes
    /// negative is failed with `CURLE_OPERATION_TIMEDOUT`. `None` preserves
    /// curl's behavior when no timeout is set (bounded only by keepalive/peer).
    pub timeout: Option<Duration>,
}

// ===========================================================================
// MqttTransfer — the sans-IO MQTT engine (← `struct MQTT` + `mqtt_do` /
// `mqtt_doing` / `mqtt_read_publish`).
// ===========================================================================

/// The per-transfer MQTT engine: owns the receive state ([`MqttConn`]) and the
/// scratch/counter fields of curl's `struct MQTT`, and drives the protocol over
/// any Tokio byte stream.
///
/// This is the faithful port of `struct MQTT` together with the `mqtt_do` /
/// `mqtt_doing` / `mqtt_read_publish` state machine. It is intentionally generic
/// over the stream `S: AsyncRead + AsyncWrite + Unpin`, which is precisely what
/// the connection-filter chain provides — a plaintext TCP stream for `mqtt` or a
/// [`TlsStream`] for `mqtts` — mirroring curl reaching the socket through
/// `Curl_xfer_send` / `Curl_xfer_recv`.
#[derive(Debug)]
pub struct MqttTransfer {
    /// The receive-side state machine (← `struct mqtt_conn`).
    conn: MqttConn,
    /// Byte counter reused across states (← `MQTT.npacket`): the count of
    /// Remaining-Length header bytes read so far, then the count of `PUBLISH`
    /// payload bytes still to read.
    npacket: usize,
    /// The Remaining Length most recently decoded (← `MQTT.remaining_length`).
    remaining_length: usize,
    /// Scratch buffer holding the up-to-4 Remaining Length header bytes while they
    /// are decoded (← `MQTT.pkt_hd[4]`).
    pkt_hd: [u8; 4],
    /// The fixed-header first byte of the packet currently being read
    /// (← `MQTT.firstbyte`).
    firstbyte: u8,
    /// `true` while a `PINGREQ` is outstanding awaiting its `PINGRESP`
    /// (← `MQTT.pingsent`).
    pingsent: bool,
    /// Timestamp of the last send or receive, used to schedule keepalive pings
    /// (← `MQTT.lastTime`).
    last_time: Instant,
    /// Download size advertised for the current `PUBLISH` (← `data->req.size` /
    /// `Curl_pgrsSetDownloadSize`).
    download_size: u64,
    /// Bytes of the current `PUBLISH` payload delivered so far
    /// (← `data->req.bytecount`).
    bytecount: u64,
}

impl Default for MqttTransfer {
    fn default() -> Self {
        Self::new()
    }
}

impl MqttTransfer {
    /// Create a fresh engine in the initial [`MqttState::First`] state (← the
    /// zeroed `struct MQTT`/`struct mqtt_conn` produced by curl's `calloc` in
    /// `mqtt_setup_conn`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            conn: MqttConn::default(),
            npacket: 0,
            remaining_length: 0,
            pkt_hd: [0u8; 4],
            firstbyte: 0,
            pingsent: false,
            last_time: Instant::now(),
            download_size: 0,
            bytecount: 0,
        }
    }

    /// The current receive state (← `mqtt_conn.state`). Exposed for diagnostics
    /// and testing.
    #[must_use]
    pub fn state(&self) -> MqttState {
        self.conn.state
    }

    /// Number of `PUBLISH` payload bytes delivered to the sink for the current
    /// message (← `data->req.bytecount`).
    #[must_use]
    pub fn bytecount(&self) -> u64 {
        self.bytecount
    }

    /// Download size advertised for the current `PUBLISH` (← `data->req.size`).
    #[must_use]
    pub fn download_size(&self) -> u64 {
        self.download_size
    }

    /// The only way to change state (← the `mqstate` helper): set `state`, and
    /// when entering [`MqttState::First`] also record the `nextstate` to resume
    /// with after the next Remaining Length is decoded.
    fn set_state(&mut self, state: MqttState, nextstate: MqttState) {
        self.conn.state = state;
        if state == MqttState::First {
            self.conn.nextstate = nextstate;
        }
    }

    /// Send an entire packet (← `mqtt_send`).
    ///
    /// curl's `mqtt_send` copes with partial writes on a non-blocking socket by
    /// stashing the unsent tail in `MQTT.sendbuf` for the next `mqtt_doing` call.
    /// Tokio's [`write_all`](AsyncWriteExt::write_all) instead drives the write to
    /// completion, producing the identical wire bytes with no residual buffer — an
    /// ownership/async simplification that changes nothing observable. Every send
    /// refreshes `last_time`, exactly as `mqtt_send` updates `MQTT.lastTime`.
    async fn send<S>(&mut self, io: &mut S, buf: &[u8]) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        io.write_all(buf).await?;
        io.flush().await?;
        self.last_time = Instant::now();
        Ok(())
    }

    /// Send a keepalive `PINGREQ` if one is due (← `mqtt_ping`).
    ///
    /// curl pings only while idle in [`MqttState::First`], only if none is already
    /// outstanding, only when a keepalive interval is configured, and only once the
    /// interval has elapsed since the last activity.
    async fn maybe_ping<S>(&mut self, io: &mut S, req: &MqttRequest<'_>) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        if self.conn.state == MqttState::First && !self.pingsent && req.upkeep_interval_ms > 0 {
            let elapsed = self.last_time.elapsed();
            if elapsed > Duration::from_millis(req.upkeep_interval_ms) {
                self.send(io, &PINGREQ_PACKET).await?;
                self.pingsent = true;
            }
        }
        Ok(())
    }

    /// Run the whole MQTT transfer to completion over `io` (← `mqtt_do` followed
    /// by the multi loop's repeated `mqtt_doing` calls), bounded by the effective
    /// transfer deadline in [`req.timeout`](MqttRequest::timeout).
    ///
    /// Sends the `CONNECT`, then repeatedly advances the state machine until it
    /// signals completion. Received `PUBLISH` payload bytes are handed to `sink`,
    /// the analog of curl's `Curl_client_write(CLIENTWRITE_BODY, …)`. When a
    /// timeout is configured the whole exchange — CONNECT, every read, and every
    /// `doing` step — is cancelled once the deadline elapses (← curl's
    /// multi-timeout), so a stalling broker cannot hold the transfer open.
    ///
    /// # Errors
    ///
    /// Propagates any framing/verification error with the same [`CurlCode`] curl
    /// would return, an I/O error from the underlying stream, or
    /// [`CurlCode::OperationTimedout`] when the transfer deadline elapses.
    pub async fn perform<S>(
        &mut self,
        io: &mut S,
        req: &MqttRequest<'_>,
        sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Enforce the effective transfer deadline around the *entire* exchange
        // (← curl's multi loop failing a transfer once `Curl_timeleft` goes
        // negative, `CURLE_OPERATION_TIMEDOUT`). `tokio::time::timeout` cancels
        // the in-flight read/write when the deadline elapses, so a broker that
        // stalls — e.g. accepts the CONNECT then sends nothing — cannot hold the
        // transfer open indefinitely. With no configured timeout the transfer is
        // unbounded, exactly as curl leaves it (bounded only by keepalive pings /
        // peer behavior).
        match req.timeout {
            Some(deadline) => match timeout(deadline, self.perform_inner(io, req, sink)).await {
                Ok(result) => result,
                Err(_elapsed) => Err(Error::with_context(
                    CurlCode::OperationTimedout,
                    "MQTT transfer timeout",
                )),
            },
            None => self.perform_inner(io, req, sink).await,
        }
    }

    /// The unbounded transfer body (← `mqtt_do` plus the multi loop's repeated
    /// `mqtt_doing` calls), wrapped by [`perform`](MqttTransfer::perform) with
    /// the effective transfer deadline.
    ///
    /// Sends the `CONNECT`, then repeatedly advances the state machine until it
    /// signals completion. Received `PUBLISH` payload bytes are handed to `sink`,
    /// the analog of curl's `Curl_client_write(CLIENTWRITE_BODY, …)`.
    async fn perform_inner<S>(
        &mut self,
        io: &mut S,
        req: &MqttRequest<'_>,
        sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // ← mqtt_do: reset timers, send CONNECT, arm the CONNACK wait.
        self.last_time = Instant::now();
        self.pingsent = false;
        let connect = build_connect(req.client_id, req.user, req.passwd)?;
        self.send(io, &connect).await?;
        self.set_state(MqttState::First, MqttState::Connack);

        // ← the multi loop repeatedly invoking mqtt_doing until *done.
        loop {
            if self.doing_step(io, req, sink).await? {
                return Ok(());
            }
        }
    }

    /// Advance the state machine by one `mqtt_doing` invocation; returns `true`
    /// when the transfer is complete (← `mqtt_doing`).
    ///
    /// The `MQTT_FIRST → MQTT_REMAINING_LENGTH` fall-through is reproduced by
    /// handling both in the one arm; the other states map one-to-one.
    async fn doing_step<S>(
        &mut self,
        io: &mut S,
        req: &MqttRequest<'_>,
        sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
    ) -> Result<bool>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // ← mqtt_ping at the top of every mqtt_doing call.
        self.maybe_ping(io, req).await?;

        match self.conn.state {
            MqttState::First | MqttState::RemainingLength => self.read_header(io).await,
            MqttState::Connack => self.handle_connack(io, req, sink).await,
            MqttState::Suback | MqttState::Pubwait | MqttState::PubRemain => {
                self.read_publish(io, req, sink).await
            }
            MqttState::SubackComing => self.suback_coming(io).await,
            MqttState::NoState => {
                // ← the `default` arm of mqtt_doing: "State not handled yet",
                // *done = TRUE. Unreachable in practice.
                Ok(true)
            }
        }
    }

    /// Read a packet's first byte then its Remaining Length (← the fused
    /// `MQTT_FIRST` + `MQTT_REMAINING_LENGTH` arms of `mqtt_doing`).
    ///
    /// Returns `true` only when a zero-length `DISCONNECT` ends the transfer.
    async fn read_header<S>(&mut self, io: &mut S) -> Result<bool>
    where
        S: AsyncRead + Unpin,
    {
        // --- MQTT_FIRST: read exactly the fixed-header first byte ---
        if self.conn.state == MqttState::First {
            let mut b = [0u8; 1];
            let n = io.read(&mut b).await?;
            if n == 0 {
                // ← "Connection disconnected": *done = TRUE, CURLE_RECV_ERROR.
                return Err(Error::with_context(
                    CurlCode::RecvError,
                    "Connection disconnected",
                ));
            }
            self.firstbyte = b[0];
            self.last_time = Instant::now();
            self.npacket = 0;
            self.set_state(MqttState::RemainingLength, MqttState::NoState);
        }

        // --- MQTT_REMAINING_LENGTH: read the 1–4 byte length varint ---
        let mut recvbyte = 0u8;
        let mut got = false;
        loop {
            let mut b = [0u8; 1];
            let n = io.read(&mut b).await?;
            if n == 0 {
                break; // ← `if(result || !nread) break;`
            }
            got = true;
            recvbyte = b[0];
            self.pkt_hd[self.npacket] = recvbyte;
            self.npacket += 1;
            if !((recvbyte & 0x80) != 0 && self.npacket < 4) {
                break;
            }
        }
        // Server tried to send a >4-byte Remaining Length.
        if got && (recvbyte & 0x80) != 0 {
            return Err(Error::Code(CurlCode::WeirdServerReply));
        }
        match mqtt_decode_len(&self.pkt_hd[..self.npacket]) {
            Some(len) => self.remaining_length = len,
            None => return Err(Error::Code(CurlCode::WeirdServerReply)),
        }
        self.npacket = 0;

        if self.remaining_length > 0 {
            // Payload follows — resume in the armed nextstate.
            let ns = self.conn.nextstate;
            self.set_state(ns, MqttState::NoState);
            return Ok(false);
        }

        // Zero Remaining Length: back to FIRST; handle the two zero-length packets.
        self.set_state(MqttState::First, MqttState::First);
        if self.firstbyte == MQTT_MSG_DISCONNECT {
            // ← "Got DISCONNECT": *done = TRUE.
            return Ok(true);
        }
        if self.firstbyte == MQTT_MSG_PINGRESP {
            // ← "Received ping response.": clear the outstanding ping, wait again.
            self.pingsent = false;
            self.set_state(MqttState::First, MqttState::Pubwait);
        }
        Ok(false)
    }

    /// Handle the `MQTT_CONNACK` state: validate the CONNACK, then either publish
    /// (upload) or subscribe (download) (← the `MQTT_CONNACK` arm of `mqtt_doing`).
    async fn handle_connack<S>(
        &mut self,
        io: &mut S,
        req: &MqttRequest<'_>,
        _sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
    ) -> Result<bool>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.read_and_verify_connack(io).await?;

        if req.is_publish {
            // ← HTTPREQ_POST: publish the upload, then DISCONNECT, then done.
            let payload = req.payload.ok_or_else(|| {
                Error::BadFunctionArgument("mqtt_publish without payload".to_string())
            })?;
            let topic = topic_from_path(req.path)?;
            let pkt = build_publish(&topic, payload)?;
            self.send(io, &pkt).await?;
            self.send(io, &DISCONNECT_PACKET).await?;
            self.conn.nextstate = MqttState::First;
            Ok(true)
        } else {
            // ← subscribe: bump the packet id, send SUBSCRIBE, wait for SUBACK.
            self.conn.packetid = self.conn.packetid.wrapping_add(1);
            let topic = topic_from_path(req.path)?;
            let pkt = build_subscribe(self.conn.packetid, &topic);
            self.send(io, &pkt).await?;
            self.set_state(MqttState::First, MqttState::Suback);
            Ok(false)
        }
    }

    /// Read and validate the CONNACK payload (← `mqtt_verify_connack`).
    async fn read_and_verify_connack<S>(&mut self, io: &mut S) -> Result<()>
    where
        S: AsyncRead + Unpin,
    {
        // curl checks the Remaining Length BEFORE reading the body, so a wrong
        // length is reported without consuming payload bytes.
        if self.remaining_length != MQTT_CONNACK_LEN {
            return Err(Error::with_context(
                CurlCode::WeirdServerReply,
                format!(
                    "CONNACK expected Remaining Length 2, got {}",
                    self.remaining_length
                ),
            ));
        }
        let mut body = [0u8; MQTT_CONNACK_LEN];
        io.read_exact(&mut body).await?;
        verify_connack(self.remaining_length, &body)
    }

    /// Handle the `SUBACK`/`PUBWAIT`/`PUB_REMAIN` states (← `mqtt_read_publish`).
    async fn read_publish<S>(
        &mut self,
        io: &mut S,
        req: &MqttRequest<'_>,
        sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
    ) -> Result<bool>
    where
        S: AsyncRead + Unpin,
    {
        match self.conn.state {
            MqttState::SubackComing => self.suback_coming(io).await,
            MqttState::Suback | MqttState::Pubwait => {
                let packet = self.firstbyte & 0xf0;
                if packet == MQTT_MSG_PUBLISH {
                    self.set_state(MqttState::PubRemain, MqttState::NoState);
                } else if packet == MQTT_MSG_SUBACK {
                    // ← mqstate(SUBACK_COMING); goto MQTT_SUBACK_COMING.
                    self.set_state(MqttState::SubackComing, MqttState::NoState);
                    return self.suback_coming(io).await;
                } else if packet == MQTT_MSG_DISCONNECT {
                    // ← "Got DISCONNECT": *done = TRUE.
                    return Ok(true);
                } else {
                    return Err(Error::Code(CurlCode::WeirdServerReply));
                }

                // --- switched to PUB_REMAIN ---
                let remlen = self.remaining_length;
                if req.max_filesize > 0 && remlen as u64 > req.max_filesize {
                    // ← "Maximum file size exceeded".
                    return Err(Error::FilesizeExceeded);
                }
                self.download_size = remlen as u64;
                self.bytecount = 0;
                self.npacket = remlen; // get this many bytes
                                       // ← FALLTHROUGH() into MQTT_PUB_REMAIN.
                self.pub_remain(io, sink).await
            }
            MqttState::PubRemain => self.pub_remain(io, sink).await,
            // ← the `default` arm: illegal state.
            _ => Err(Error::Code(CurlCode::WeirdServerReply)),
        }
    }

    /// Read (part of) a `PUBLISH` payload and stream it to the sink
    /// (← the `MQTT_PUB_REMAIN` block of `mqtt_read_publish`).
    async fn pub_remain<S>(
        &mut self,
        io: &mut S,
        sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
    ) -> Result<bool>
    where
        S: AsyncRead + Unpin,
    {
        // Read the rest of the packet, but no more, capped to the buffer size.
        let mut buffer = [0u8; PUB_READ_CHUNK];
        let rest = self.npacket.min(buffer.len());
        if rest == 0 {
            // Defensive: nothing left to read (curl only enters here with
            // npacket > 0); fall back to waiting for the next PUBLISH.
            self.set_state(MqttState::First, MqttState::Pubwait);
            return Ok(false);
        }
        let n = io.read(&mut buffer[..rest]).await?;
        if n == 0 {
            // ← "server disconnected": CURLE_PARTIAL_FILE.
            return Err(Error::PartialFile);
        }
        self.last_time = Instant::now();
        // ← Curl_client_write(CLIENTWRITE_BODY, buffer, nread).
        sink(&buffer[..n])?;
        self.bytecount += n as u64;
        self.npacket -= n;
        if self.npacket == 0 {
            // No more PUBLISH payload — back to the subscribe wait state.
            self.set_state(MqttState::First, MqttState::Pubwait);
        }
        Ok(false)
    }

    /// Read and validate the SUBACK remainder (← the `MQTT_SUBACK_COMING` label of
    /// `mqtt_read_publish`), then wait for the first `PUBLISH`.
    async fn suback_coming<S>(&mut self, io: &mut S) -> Result<bool>
    where
        S: AsyncRead + Unpin,
    {
        if self.remaining_length != MQTT_SUBACK_LEN {
            return Err(Error::with_context(
                CurlCode::WeirdServerReply,
                format!(
                    "SUBACK expected Remaining Length 3, got {}",
                    self.remaining_length
                ),
            ));
        }
        let mut body = [0u8; MQTT_SUBACK_LEN];
        io.read_exact(&mut body).await?;
        verify_suback(self.remaining_length, self.conn.packetid, &body)?;
        self.set_state(MqttState::First, MqttState::Pubwait);
        Ok(false)
    }
}

// ===========================================================================
// Connection / TLS adapters (← the credential-sourcing in `mqtt_connect` and the
// `mqtts_connecting` TLS establishment).
// ===========================================================================

/// Build the `CONNECT` packet for a connection, sourcing the username/password
/// from the resolved [`Connection`] credentials (← `mqtt_connect` reading
/// `data->state.aptr.user` / `data->state.aptr.passwd`, which mirror
/// `conn->user` / `conn->passwd`).
///
/// This is the thin adapter between the connection-owned credentials and the
/// pure [`build_connect`] framing routine; `client_id` is the generated 12-byte
/// identifier (see [`generate_client_id`]).
///
/// # Errors
///
/// Propagates every error [`build_connect`] can return.
pub fn connect_packet(conn: &Connection, client_id: &str) -> Result<Vec<u8>> {
    build_connect(client_id, conn.user.as_deref(), conn.passwd.as_deref())
}

/// Upgrade an established plaintext stream to TLS for the `mqtts` scheme
/// (← `mqtts_connecting`, which drives the connection filter chain's TLS
/// handshake via `Curl_conn_connect`).
///
/// In this rewrite TLS is layered by [`crate::tls`]: the returned [`TlsStream`]
/// implements [`AsyncRead`] + [`AsyncWrite`] and is handed to
/// [`MqttTransfer::perform`] unchanged, so the identical MQTT state machine runs
/// over the encrypted transport. `server_name` is used for SNI and certificate
/// verification (validation is on by default, AAP §0.7.3).
///
/// # Errors
///
/// Propagates the TLS handshake errors from
/// [`TlsConnector::connect`](crate::tls::TlsConnector::connect) — for example
/// [`CurlCode::SslConnectError`] or [`CurlCode::PeerFailedVerification`].
pub async fn upgrade_tls<S>(
    connector: &TlsConnector,
    server_name: &str,
    stream: S,
) -> Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    connector.connect(server_name, stream).await
}

// ===========================================================================
// MqttHandler — the `Protocol` vtable adapter (← `struct Curl_protocol
// Curl_protocol_mqtt` / `Curl_protocol_mqtts`).
// ===========================================================================

/// The MQTT protocol handler singleton (← `Curl_protocol_mqtt` /
/// `Curl_protocol_mqtts`).
///
/// A zero-sized, shareable (`Send + Sync`) handler referenced as
/// `&mqtt::HANDLER` by both `SCHEME_MQTT` and `SCHEME_MQTTS` in
/// [`crate::protocols`] — exactly as curl points both `Curl_scheme_mqtt` and
/// `Curl_scheme_mqtts` at the same handler logic (the schemes differ only by the
/// `PROTOPT_SSL` flag and default port).
///
/// # Relationship to [`MqttTransfer`]
///
/// This type is the [`Protocol`] vtable adapter that the transfer layer drives.
/// The complete MQTT logic lives in [`MqttTransfer`] (the port of `struct MQTT`
/// and the `mqtt_do` / `mqtt_doing` / `mqtt_read_publish` machine);
/// [`do_it`](MqttHandler::do_it) reads the [`TransferCtx`] (the live transport,
/// the URL path/credentials, the POST body that selects publish-vs-subscribe,
/// the body sink, and the transfer timeout), builds a [`MqttRequest`], and drives
/// [`MqttTransfer::perform`] to completion over the connected stream — the whole
/// CONNECT → CONNACK → SUBSCRIBE/PUBLISH exchange. Because `perform` runs the
/// full `mqtt_doing` loop internally, the DO phase completes the transfer in one
/// step (no separate `doing` override is needed, exactly as the sibling
/// run-to-completion auxiliary handlers work).
#[derive(Debug, Clone, Copy, Default)]
pub struct MqttHandler;

/// The shared MQTT handler singleton referenced by `SCHEME_MQTT` and
/// `SCHEME_MQTTS` (← the `&Curl_protocol_mqtt` / `&Curl_protocol_mqtts` pointers
/// in the `Curl_scheme_*` records).
pub static HANDLER: MqttHandler = MqttHandler;

impl Protocol for MqttHandler {
    /// The required "DO" phase (← `mqtt_do` + the `mqtt_doing` multi loop).
    ///
    /// curl's `mqtt_do` sends the `CONNECT` and returns `*done = FALSE`, then the
    /// multi loop calls `mqtt_doing` until the CONNACK/SUBSCRIBE/PUBLISH exchange
    /// finishes. Here that whole exchange is driven to completion by
    /// [`MqttTransfer::perform`] (its `perform_inner` runs the identical
    /// `mqtt_doing` state loop), so the DO phase returns `Ok(true)` — the DO phase
    /// itself completed the transfer, exactly as the sibling run-to-completion
    /// auxiliary handlers (DICT, GOPHER, TELNET, TFTP, FILE) do.
    ///
    /// The request is assembled from [`TransferCtx`]: `is_publish` mirrors curl's
    /// `httpreq == HTTPREQ_POST` (a POST body ⇒ publish, otherwise subscribe), the
    /// body is the publish payload, the URL path yields the topic, and
    /// [`request.timeout`](crate::protocols::TransferRequest::timeout) bounds the
    /// exchange. A missing transport surfaces as `CURLE_COULDNT_CONNECT`.
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            // A fresh 12-byte client id per transfer (← mqtt_setup_conn generating
            // `curl` + 8 random alphanumerics).
            let client_id = generate_client_id();

            // Build the request view over the transfer fields. `is_publish`
            // mirrors curl's `httpreq == HTTPREQ_POST`: a POST body (postfields)
            // means publish, its absence means subscribe. `max_filesize` /
            // `upkeep_interval_ms` take their curl defaults (no CLI override is
            // threaded at this checkpoint).
            let req = MqttRequest {
                path: ctx.request.path.as_str(),
                user: ctx.request.user.as_deref(),
                passwd: ctx.request.password.as_deref(),
                is_publish: ctx.request.body.is_some(),
                payload: ctx.request.body.as_deref(),
                client_id: &client_id,
                max_filesize: 0,
                upkeep_interval_ms: 0,
                timeout: ctx.request.timeout,
            };

            // The live transport (← the connected socket curl reaches through
            // Curl_xfer_send/recv). MQTT runs over the stream filter chain:
            // plaintext for `mqtt`, a TLS stream for `mqtts` (layered upstream).
            let mut stream = ctx.io.as_deref_mut().ok_or_else(|| {
                Error::with_context(CurlCode::CouldntConnect, "no transport for MQTT")
            })?;

            // Deliver received PUBLISH payload bytes to the client body sink
            // (← Curl_client_write with CLIENTWRITE_BODY); discard them when the
            // transfer installed no sink. Borrowing `ctx.sink` here is disjoint
            // from the `ctx.io` borrow above and the immutable `ctx.request`
            // borrow in `req`.
            let sink_slot = &mut ctx.sink;
            let mut sink = move |data: &[u8]| -> Result<()> {
                match sink_slot.as_deref_mut() {
                    Some(s) => s.write(data),
                    None => Ok(()),
                }
            };

            let mut engine = MqttTransfer::new();
            engine.perform(&mut stream, &req, &mut sink).await?;
            Ok(true)
        })
    }

    /// The required teardown (← `mqtt_done`).
    ///
    /// `mqtt_done` frees `MQTT.sendbuf` / `MQTT.recvbuf`. In this rewrite those
    /// buffers live inside [`MqttTransfer`] and are released deterministically by
    /// ownership/`Drop` when the transfer ends, so there is nothing to do here —
    /// this is a complete port of `mqtt_done`, not a stub.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, status, premature);
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::TransferSink;
    use std::future::Future;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ---- helpers -----------------------------------------------------------

    /// Drive an async test body to completion on a fresh Tokio current-thread
    /// runtime.
    ///
    /// Using Tokio's own runtime (rather than a hand-rolled executor) keeps this
    /// module written entirely in safe Rust — a hand-built [`std::task::Waker`]
    /// would require `Waker::from_raw` (a non-safe constructor), and this crate's
    /// policy, verified by a CI grep over `curl-rs-lib/src/`, forbids such
    /// constructs. The current-thread flavor matches curl 8.x's single-threaded
    /// transfer model and is sufficient for the in-memory [`tokio::io::duplex`]
    /// peers these tests use.
    fn block_on<F: Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build current-thread Tokio runtime for test")
            .block_on(fut)
    }

    fn sample_request<'a>(client_id: &'a str, path: &'a str) -> MqttRequest<'a> {
        MqttRequest {
            path,
            user: None,
            passwd: None,
            is_publish: false,
            payload: None,
            client_id,
            max_filesize: 0,
            upkeep_interval_ms: 0,
            timeout: None,
        }
    }

    // ---- varint (Remaining Length) ----------------------------------------

    #[test]
    fn encode_len_matches_mqtt_spec_examples() {
        // MQTT 3.1.1 Table 2.4 boundary values.
        let cases: &[(usize, &[u8])] = &[
            (0, &[]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (16_383, &[0xff, 0x7f]),
            (16_384, &[0x80, 0x80, 0x01]),
            (2_097_151, &[0xff, 0xff, 0x7f]),
            (2_097_152, &[0x80, 0x80, 0x80, 0x01]),
            (268_435_455, &[0xff, 0xff, 0xff, 0x7f]),
        ];
        for (len, expected) in cases {
            let mut out = [0u8; 4];
            let n = mqtt_encode_len(&mut out, *len);
            assert_eq!(&out[..n], *expected, "encode {len}");
        }
    }

    #[test]
    fn decode_len_roundtrips_and_rejects_overlong() {
        for len in [0usize, 1, 127, 128, 16_383, 16_384, 2_097_152, 268_435_455] {
            let mut out = [0u8; 4];
            let n = mqtt_encode_len(&mut out, len);
            // A zero length encodes to zero bytes; decoding an empty slice yields 0.
            assert_eq!(mqtt_decode_len(&out[..n]), Some(len), "roundtrip {len}");
        }
        // Five continuation bytes => "bad size" (None).
        assert_eq!(mqtt_decode_len(&[0x80, 0x80, 0x80, 0x80, 0x01]), None);
    }

    // ---- CONNECT framing ---------------------------------------------------

    #[test]
    fn build_connect_no_credentials_layout() {
        let pkt = build_connect("curl01234567", None, None).unwrap();
        // remaining_length = payload(12+2) + 10 var header = 24 => single length byte.
        assert_eq!(pkt[0], MQTT_MSG_CONNECT);
        assert_eq!(pkt[1], 24, "Remaining Length");
        // Variable header at remain_pos = 1: 2-byte protocol-name length + "MQTT".
        assert_eq!(pkt[2], 0x00, "protocol name length MSB");
        assert_eq!(pkt[3], 0x04, "protocol name length LSB");
        assert_eq!(&pkt[4..8], b"MQTT", "protocol name");
        assert_eq!(pkt[8], 0x04, "protocol level 4");
        assert_eq!(pkt[9], 0x02, "CleanSession flag, no user/pass");
        assert_eq!(pkt[10], 0x00, "keepalive MSB");
        assert_eq!(pkt[11], 0x3c, "keepalive LSB (60s)");
        // Client id at pos+1 = 12: 2-byte length prefix + the 12 id bytes.
        assert_eq!(pkt[12], 0x00, "client id length MSB");
        assert_eq!(pkt[13], MQTT_CLIENTID_LEN as u8, "client id length LSB");
        assert_eq!(&pkt[14..26], b"curl01234567");
        assert_eq!(pkt.len(), 26);
    }

    #[test]
    fn build_connect_sets_user_and_pass_flags() {
        let pkt = build_connect("curl01234567", Some("bob"), Some("pw")).unwrap();
        // CONNECT flags byte is at remain_pos + 8. remaining_length now includes
        // user(3)+pass(2)+their 2+2 length prefixes, so still a single length byte
        // => remain_pos = 1, conn flags at index 9.
        let conn_flags = pkt[9];
        assert_eq!(conn_flags & 0x80, 0x80, "username flag set");
        assert_eq!(conn_flags & 0x40, 0x40, "password flag set");
        assert_eq!(conn_flags & 0x02, 0x02, "CleanSession still set");
        // The username bytes appear right after the 12-byte client id + its prefix.
        // start_user = pos + 3 + 12; pos = remain_pos + 10 = 11 => start_user = 26.
        assert_eq!(pkt[26], 0x00);
        assert_eq!(pkt[27], 3);
        assert_eq!(&pkt[28..31], b"bob");
        // Password follows: start_pwd = start_user + ulen + 2 = 26 + 3 + 2 = 31.
        assert_eq!(pkt[31], 0x00);
        assert_eq!(pkt[32], 2);
        assert_eq!(&pkt[33..35], b"pw");
    }

    #[test]
    fn build_connect_rejects_wrong_client_id_len() {
        let err = build_connect("curl", None, None).unwrap_err();
        assert_eq!(err.code(), CurlCode::WeirdServerReply);
    }

    // ---- SUBSCRIBE / PUBLISH framing --------------------------------------

    #[test]
    fn build_subscribe_layout_qos0() {
        let pkt = build_subscribe(1, b"topic");
        // control byte, len, pid hi/lo, topiclen hi/lo, topic, qos.
        assert_eq!(pkt[0], MQTT_MSG_SUBSCRIBE);
        // packetlen before header = topiclen(5)+5 = 10 => single length byte 10.
        assert_eq!(pkt[1], 10);
        assert_eq!(pkt[2], 0x00, "packetid hi");
        assert_eq!(pkt[3], 0x01, "packetid lo");
        assert_eq!(pkt[4], 0x00, "topiclen hi");
        assert_eq!(pkt[5], 0x05, "topiclen lo");
        assert_eq!(&pkt[6..11], b"topic");
        assert_eq!(pkt[11], 0x00, "requested QoS 0");
        assert_eq!(pkt.len(), 12);
    }

    #[test]
    fn build_publish_layout() {
        let pkt = build_publish(b"a/b", b"hello").unwrap();
        assert_eq!(pkt[0], MQTT_MSG_PUBLISH);
        // remaining_length = payload(5) + 2 + topiclen(3) = 10 => single byte.
        assert_eq!(pkt[1], 10);
        assert_eq!(pkt[2], 0x00, "topiclen hi");
        assert_eq!(pkt[3], 0x03, "topiclen lo");
        assert_eq!(&pkt[4..7], b"a/b");
        assert_eq!(&pkt[7..12], b"hello");
        assert_eq!(pkt.len(), 12);
    }

    // ---- topic extraction --------------------------------------------------

    #[test]
    fn topic_from_path_decodes_and_validates() {
        assert_eq!(topic_from_path("/hello").unwrap(), b"hello");
        // percent-decoding (REJECT_NADA): %2F -> '/'.
        assert_eq!(topic_from_path("/a%2Fb").unwrap(), b"a/b");
        // No topic.
        assert_eq!(
            topic_from_path("/").unwrap_err().code(),
            CurlCode::UrlMalformat
        );
        assert_eq!(
            topic_from_path("").unwrap_err().code(),
            CurlCode::UrlMalformat
        );
    }

    // ---- CONNACK / SUBACK verification ------------------------------------

    #[test]
    fn verify_connack_accepts_zero_zero() {
        assert!(verify_connack(2, &[0x00, 0x00]).is_ok());
        assert_eq!(
            verify_connack(3, &[0x00, 0x00]).unwrap_err().code(),
            CurlCode::WeirdServerReply
        );
        assert_eq!(
            verify_connack(2, &[0x00, 0x05]).unwrap_err().code(),
            CurlCode::WeirdServerReply
        );
    }

    #[test]
    fn verify_suback_checks_packetid_and_code() {
        assert!(verify_suback(3, 1, &[0x00, 0x01, 0x00]).is_ok());
        assert_eq!(
            verify_suback(2, 1, &[0x00, 0x01, 0x00]).unwrap_err().code(),
            CurlCode::WeirdServerReply
        );
        assert_eq!(
            verify_suback(3, 1, &[0x00, 0x02, 0x00]).unwrap_err().code(),
            CurlCode::WeirdServerReply
        );
        assert_eq!(
            verify_suback(3, 1, &[0x00, 0x01, 0x01]).unwrap_err().code(),
            CurlCode::WeirdServerReply
        );
    }

    // ---- client id ---------------------------------------------------------

    #[test]
    fn generated_client_id_shape() {
        for _ in 0..64 {
            let id = generate_client_id();
            assert_eq!(id.len(), MQTT_CLIENTID_LEN);
            assert!(id.starts_with("curl"));
            assert!(id.bytes().all(|b| b.is_ascii_alphanumeric()));
        }
    }

    // ---- state / names -----------------------------------------------------

    #[test]
    fn state_names_match_curl() {
        assert_eq!(MqttState::First as u8, 0);
        assert_eq!(MqttState::PubRemain as u8, 6);
        assert_eq!(MqttState::NoState as u8, 7);
        assert_eq!(MqttState::First.name(), "MQTT_FIRST");
        assert_eq!(MqttState::RemainingLength.name(), "MQTT_REMAINING_LENGTH");
        assert_eq!(MqttState::SubackComing.name(), "MQTT_SUBACK_COMING");
        assert_eq!(MqttState::NoState.name(), "NOT A STATE");
    }

    // ---- end-to-end engine over an in-memory duplex server -----------------

    /// Encode a Remaining Length for building server-side test packets.
    fn enc_len(len: usize) -> Vec<u8> {
        let mut out = [0u8; 4];
        let n = mqtt_encode_len(&mut out, len);
        out[..n].to_vec()
    }

    #[test]
    fn subscribe_download_flow_streams_publish_payload() {
        // Server (peer end of the duplex) plays CONNACK, SUBACK, one PUBLISH split
        // across two writes, then DISCONNECT.
        block_on(async {
            let (mut client, mut server) = tokio::io::duplex(4096);

            let server_task = async {
                // Read the client's CONNECT (first byte + rest via Remaining Length).
                let mut fb = [0u8; 1];
                server.read_exact(&mut fb).await.unwrap();
                assert_eq!(fb[0], MQTT_MSG_CONNECT);
                let rl = read_remaining_len(&mut server).await;
                let mut rest = vec![0u8; rl];
                server.read_exact(&mut rest).await.unwrap();

                // CONNACK: 0x20, len 2, 0x00 0x00.
                server
                    .write_all(&[MQTT_MSG_CONNACK, 0x02, 0x00, 0x00])
                    .await
                    .unwrap();

                // Read SUBSCRIBE.
                server.read_exact(&mut fb).await.unwrap();
                assert_eq!(fb[0], MQTT_MSG_SUBSCRIBE);
                let rl = read_remaining_len(&mut server).await;
                let mut sub = vec![0u8; rl];
                server.read_exact(&mut sub).await.unwrap();
                // packetid is the first two bytes of the SUBSCRIBE variable header.
                let pid_hi = sub[0];
                let pid_lo = sub[1];

                // SUBACK: 0x90, len 3, packetid, 0x00.
                server
                    .write_all(&[MQTT_MSG_SUBACK, 0x03, pid_hi, pid_lo, 0x00])
                    .await
                    .unwrap();

                // PUBLISH with a 7-byte payload, deliberately flushed in two writes
                // to exercise MQTT_PUB_REMAIN spanning multiple reads.
                let payload = b"ABCDEFG";
                let mut pkt = vec![MQTT_MSG_PUBLISH];
                pkt.extend_from_slice(&enc_len(payload.len()));
                pkt.extend_from_slice(payload);
                server.write_all(&pkt[..4]).await.unwrap();
                server.flush().await.unwrap();
                server.write_all(&pkt[4..]).await.unwrap();
                server.flush().await.unwrap();

                // DISCONNECT: 0xE0, len 0.
                server.write_all(&DISCONNECT_PACKET).await.unwrap();
                server.flush().await.unwrap();
            };

            let mut received = Vec::new();
            let client_task = async {
                let mut engine = MqttTransfer::new();
                let req = sample_request("curl01234567", "/topic");
                let mut sink = |b: &[u8]| {
                    received.extend_from_slice(b);
                    Ok(())
                };
                engine.perform(&mut client, &req, &mut sink).await
            };

            let (_s, res) = tokio::join!(server_task, client_task);
            res.unwrap();
            assert_eq!(received, b"ABCDEFG");
        });
    }

    #[test]
    fn publish_upload_flow_sends_publish_then_disconnect() {
        block_on(async {
            let (mut client, mut server) = tokio::io::duplex(4096);

            let server_task = async {
                // CONNECT.
                let mut fb = [0u8; 1];
                server.read_exact(&mut fb).await.unwrap();
                assert_eq!(fb[0], MQTT_MSG_CONNECT);
                let rl = read_remaining_len(&mut server).await;
                let mut rest = vec![0u8; rl];
                server.read_exact(&mut rest).await.unwrap();

                // CONNACK.
                server
                    .write_all(&[MQTT_MSG_CONNACK, 0x02, 0x00, 0x00])
                    .await
                    .unwrap();
                server.flush().await.unwrap();

                // Expect PUBLISH.
                server.read_exact(&mut fb).await.unwrap();
                assert_eq!(fb[0], MQTT_MSG_PUBLISH);
                let rl = read_remaining_len(&mut server).await;
                let mut body = vec![0u8; rl];
                server.read_exact(&mut body).await.unwrap();
                // topic length + "t" + payload "hi".
                assert_eq!(body[0], 0x00);
                assert_eq!(body[1], 0x01);
                assert_eq!(body[2], b't');
                assert_eq!(&body[3..], b"hi");

                // Expect DISCONNECT.
                let mut disc = [0u8; 2];
                server.read_exact(&mut disc).await.unwrap();
                assert_eq!(disc, DISCONNECT_PACKET);
            };

            let client_task = async {
                let mut engine = MqttTransfer::new();
                let req = MqttRequest {
                    path: "/t",
                    user: None,
                    passwd: None,
                    is_publish: true,
                    payload: Some(b"hi"),
                    client_id: "curl01234567",
                    max_filesize: 0,
                    upkeep_interval_ms: 0,
                    timeout: None,
                };
                let mut sink = |_: &[u8]| Ok(());
                engine.perform(&mut client, &req, &mut sink).await
            };

            let (_s, res) = tokio::join!(server_task, client_task);
            res.unwrap();
        });
    }

    #[test]
    fn bad_connack_bytes_are_rejected() {
        block_on(async {
            let (mut client, mut server) = tokio::io::duplex(4096);
            let server_task = async {
                let mut fb = [0u8; 1];
                server.read_exact(&mut fb).await.unwrap();
                let rl = read_remaining_len(&mut server).await;
                let mut rest = vec![0u8; rl];
                server.read_exact(&mut rest).await.unwrap();
                // CONNACK with a non-zero return code => rejected.
                server
                    .write_all(&[MQTT_MSG_CONNACK, 0x02, 0x00, 0x05])
                    .await
                    .unwrap();
                server.flush().await.unwrap();
            };
            let client_task = async {
                let mut engine = MqttTransfer::new();
                let req = sample_request("curl01234567", "/topic");
                let mut sink = |_: &[u8]| Ok(());
                engine.perform(&mut client, &req, &mut sink).await
            };
            let (_s, res) = tokio::join!(server_task, client_task);
            assert_eq!(res.unwrap_err().code(), CurlCode::WeirdServerReply);
        });
    }

    /// Read a Remaining Length varint from the server side of a duplex during tests.
    async fn read_remaining_len<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> usize {
        let mut buf = [0u8; 4];
        let mut n = 0;
        loop {
            let mut b = [0u8; 1];
            s.read_exact(&mut b).await.unwrap();
            buf[n] = b[0];
            n += 1;
            if b[0] & 0x80 == 0 || n == 4 {
                break;
            }
        }
        mqtt_decode_len(&buf[..n]).unwrap()
    }

    // ---- Protocol vtable adapter ------------------------------------------

    /// A shared-buffer [`TransferSink`] that records every delivered PUBLISH
    /// payload chunk, so a handler test can assert what was streamed to the
    /// download (← `Curl_client_write(CLIENTWRITE_BODY, …)`).
    struct RecordingSink(Arc<Mutex<Vec<u8>>>);
    impl TransferSink for RecordingSink {
        fn write(&mut self, data: &[u8]) -> Result<()> {
            self.0.lock().expect("sink lock").extend_from_slice(data);
            Ok(())
        }
    }

    #[test]
    fn handler_is_object_safe() {
        // The HANDLER is a shared, zero-sized singleton usable as `&dyn Protocol`
        // (← the `&Curl_protocol_mqtt` pointer stored in the scheme table), and
        // `MqttHandler` is Copy/Default/Debug like the sibling handlers.
        let handler: &dyn Protocol = &HANDLER;
        let _copy = HANDLER;
        // Exercising a defaulted synchronous no-op trait method proves the
        // handler is usable through the vtable without any concrete-type
        // knowledge (`connection_check` returns curl's "no checks" `0`).
        let mut ctx = TransferCtx::new();
        assert_eq!(handler.connection_check(&mut ctx, 0), 0);
    }

    #[test]
    fn handler_done_is_noop_ok() {
        // `mqtt_done` frees buffers owned elsewhere in this rewrite, so `done` is
        // a faithful no-op on both the success and the premature-teardown paths.
        let handler: &dyn Protocol = &HANDLER;
        block_on(async {
            let mut ctx = TransferCtx::new();
            handler.done(&mut ctx, Ok(()), false).await.unwrap();
            handler
                .done(
                    &mut ctx,
                    Err(Error::with_context(CurlCode::RecvError, "recv")),
                    true,
                )
                .await
                .unwrap();
        });
    }

    #[test]
    fn handler_do_it_without_transport_is_couldnt_connect() {
        // With no live stream installed (← a connection that never came up),
        // `do_it` must surface `CURLE_COULDNT_CONNECT` rather than panic or
        // silently succeed. This replaces the earlier stale expectation that the
        // stub returned `Ok(false)`; the wired handler now drives the exchange
        // and therefore requires a transport (AAP §0.7.1 — behavior aligned to
        // the corrected implementation).
        let handler: &dyn Protocol = &HANDLER;
        let mut ctx = TransferCtx::new();
        ctx.request.path = "/topic".to_string();
        let err = block_on(handler.do_it(&mut ctx)).unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntConnect);
    }

    #[test]
    fn handler_do_it_subscribe_streams_publish_to_sink() {
        // End-to-end DO phase over a live duplex transport installed in
        // `ctx.io`: an empty body means subscribe (← `httpreq != HTTPREQ_POST`),
        // so the broker plays CONNACK → SUBACK → PUBLISH → DISCONNECT and the
        // handler must stream the PUBLISH payload to `ctx.sink` and report the DO
        // phase complete (`Ok(true)`, the run-to-completion pattern).
        block_on(async {
            let (client, mut server) = tokio::io::duplex(4096);

            let server_task = async {
                // CONNECT (client id is random, so read it generically).
                let mut fb = [0u8; 1];
                server.read_exact(&mut fb).await.unwrap();
                assert_eq!(fb[0], MQTT_MSG_CONNECT);
                let rl = read_remaining_len(&mut server).await;
                let mut rest = vec![0u8; rl];
                server.read_exact(&mut rest).await.unwrap();

                // CONNACK (accepted).
                server
                    .write_all(&[MQTT_MSG_CONNACK, 0x02, 0x00, 0x00])
                    .await
                    .unwrap();

                // SUBSCRIBE — echo its packet id back in the SUBACK.
                server.read_exact(&mut fb).await.unwrap();
                assert_eq!(fb[0], MQTT_MSG_SUBSCRIBE);
                let rl = read_remaining_len(&mut server).await;
                let mut sub = vec![0u8; rl];
                server.read_exact(&mut sub).await.unwrap();
                let (pid_hi, pid_lo) = (sub[0], sub[1]);

                // SUBACK, then a single PUBLISH, then DISCONNECT.
                server
                    .write_all(&[MQTT_MSG_SUBACK, 0x03, pid_hi, pid_lo, 0x00])
                    .await
                    .unwrap();
                let payload = b"hello-mqtt";
                let mut pkt = vec![MQTT_MSG_PUBLISH];
                pkt.extend_from_slice(&enc_len(payload.len()));
                pkt.extend_from_slice(payload);
                server.write_all(&pkt).await.unwrap();
                server.write_all(&DISCONNECT_PACKET).await.unwrap();
                server.flush().await.unwrap();
            };

            let collected = Arc::new(Mutex::new(Vec::new()));
            let mut ctx = TransferCtx::new();
            ctx.request.path = "/topic".to_string();
            ctx.io = Some(Box::new(client));
            ctx.sink = Some(Box::new(RecordingSink(Arc::clone(&collected))));

            let client_task = async {
                let handler: &dyn Protocol = &HANDLER;
                handler.do_it(&mut ctx).await
            };

            let (_s, res) = tokio::join!(server_task, client_task);
            assert!(
                res.unwrap(),
                "MQTT subscribe DO phase completes in one step"
            );
            assert_eq!(
                collected.lock().expect("sink").as_slice(),
                b"hello-mqtt",
                "the PUBLISH payload is streamed to the transfer sink"
            );
        });
    }

    #[test]
    fn handler_do_it_publish_sends_payload_then_disconnect() {
        // A request body means publish (← `httpreq == HTTPREQ_POST`): the handler
        // must CONNECT, PUBLISH the body to the topic, then DISCONNECT, and
        // report the DO phase complete.
        block_on(async {
            let (client, mut server) = tokio::io::duplex(4096);

            let server_task = async {
                let mut fb = [0u8; 1];
                server.read_exact(&mut fb).await.unwrap();
                assert_eq!(fb[0], MQTT_MSG_CONNECT);
                let rl = read_remaining_len(&mut server).await;
                let mut rest = vec![0u8; rl];
                server.read_exact(&mut rest).await.unwrap();

                server
                    .write_all(&[MQTT_MSG_CONNACK, 0x02, 0x00, 0x00])
                    .await
                    .unwrap();
                server.flush().await.unwrap();

                // PUBLISH: topic "t" (len 1) then the payload "hi".
                server.read_exact(&mut fb).await.unwrap();
                assert_eq!(fb[0], MQTT_MSG_PUBLISH);
                let rl = read_remaining_len(&mut server).await;
                let mut body = vec![0u8; rl];
                server.read_exact(&mut body).await.unwrap();
                assert_eq!(body[0], 0x00);
                assert_eq!(body[1], 0x01);
                assert_eq!(body[2], b't');
                assert_eq!(&body[3..], b"hi");

                // DISCONNECT.
                let mut disc = [0u8; 2];
                server.read_exact(&mut disc).await.unwrap();
                assert_eq!(disc, DISCONNECT_PACKET);
            };

            let mut ctx = TransferCtx::new();
            ctx.request.path = "/t".to_string();
            ctx.request.body = Some(b"hi".to_vec());
            ctx.io = Some(Box::new(client));

            let client_task = async {
                let handler: &dyn Protocol = &HANDLER;
                handler.do_it(&mut ctx).await
            };

            let (_s, res) = tokio::join!(server_task, client_task);
            assert!(res.unwrap(), "MQTT publish DO phase completes in one step");
        });
    }

    #[test]
    fn handler_do_it_times_out_when_broker_stalls() {
        // mqtt#2 at the handler level: a broker that accepts the CONNECT then
        // sends nothing must not hold the transfer open. With
        // `ctx.request.timeout` set, `do_it` threads it into `MqttRequest.timeout`
        // and the deadline cancels the stalled read, surfacing
        // `CURLE_OPERATION_TIMEDOUT` (← curl's multi-timeout).
        block_on(async {
            let (client, mut server) = tokio::io::duplex(4096);

            let server_task = async {
                // Consume the CONNECT, send CONNACK, then stall (hold the
                // connection open without ever answering the SUBSCRIBE) longer
                // than the client's deadline.
                let mut fb = [0u8; 1];
                server.read_exact(&mut fb).await.unwrap();
                let rl = read_remaining_len(&mut server).await;
                let mut rest = vec![0u8; rl];
                server.read_exact(&mut rest).await.unwrap();
                server
                    .write_all(&[MQTT_MSG_CONNACK, 0x02, 0x00, 0x00])
                    .await
                    .unwrap();
                server.flush().await.unwrap();
                // Keep `server` alive (no EOF) while the client's deadline fires.
                tokio::time::sleep(Duration::from_millis(300)).await;
                drop(server);
            };

            let mut ctx = TransferCtx::new();
            ctx.request.path = "/topic".to_string();
            ctx.request.timeout = Some(Duration::from_millis(50));
            ctx.io = Some(Box::new(client));

            let client_task = async {
                let handler: &dyn Protocol = &HANDLER;
                handler.do_it(&mut ctx).await
            };

            let (_s, res) = tokio::join!(server_task, client_task);
            let err = res.unwrap_err();
            assert_eq!(
                err.code(),
                CurlCode::OperationTimedout,
                "a stalling broker trips the transfer deadline"
            );
        });
    }
}
