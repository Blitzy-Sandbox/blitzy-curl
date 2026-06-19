//! MQTT / MQTTS protocol engine — the Rust analog of curl's `lib/mqtt.c`.
//!
//! curl ships a deliberately **minimal MQTT 3.1.1 client**: it speaks just
//! enough of the protocol to publish a single message (an *upload*, driven by
//! `-d`/`CURLOPT_POSTFIELDS`) or to subscribe to one topic and stream every
//! received `PUBLISH` payload to the client (a *download*). Only QoS 0 is used,
//! there is no broker/session persistence, and the keep-alive is the bare
//! `PINGREQ` exchange. This module reproduces that behavior **byte-for-byte** on
//! top of the crate's async connection-filter chain.
//!
//! ## Wire shape (MQTT 3.1.1, QoS 0)
//!
//! Every control packet is `fixed-header(1 byte type) + remaining-length(1..4
//! byte varint) + variable-header + payload`. The single trickiest detail —
//! and the one most worth getting exactly right — is the **remaining-length
//! variable-length integer**: a base-128 little-endian encoding where the high
//! bit of each byte signals "another byte follows", spanning 1 byte (≤127),
//! 2 bytes (≤16 383), 3 bytes (≤2 097 151) or 4 bytes (≤268 435 455). See
//! [`encode_remaining_length`] / [`decode_remaining_length`].
//!
//! ## Architecture
//!
//! * [`MqttProtocol`] implements [`Protocol`]; [`MqttProtocol::do_it`] runs the
//!   control plane (connect → `CONNECT` → `CONNACK` → then either
//!   `PUBLISH`+`DISCONNECT` for upload, or `SUBSCRIBE` for download).
//! * [`MqttProtocol::run_subscription`] is the inbound receive loop a download
//!   uses after `SUBSCRIBE` — it verifies the `SUBACK`, then streams each
//!   `PUBLISH` body to the client writer, faithfully mirroring `mqtt.c`'s
//!   `mqtt_doing` + `mqtt_read_publish` state machine (including the keep-alive
//!   `PINGREQ`).
//! * The wire codec and every packet builder/parser are free functions so they
//!   can be unit-tested in isolation against the C oracle's byte layout.
//!
//! `unsafe` is forbidden crate-wide (the attribute is inherited from the crate
//! root and from `protocols/mod.rs`); none is used or re-declared here. All
//! binary buffers are owned `Vec<u8>` / fixed arrays.

use std::time::Duration;

use crate::conn::{
    BoxFuture, Connection, Curl_conn_connect, Curl_conn_recv, Curl_conn_send, FIRSTSOCKET,
};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::{Protocol, ProtocolTransfer, Scheme, TransferDirection};
use crate::transfer::{ClientWriteType, ClientWriter, WriteCallbacks};
use crate::url::{CurlUPart, CurlUrl, CURLU_DEFAULT_PORT, CURLU_URLDECODE};
use crate::util::dynbuf::{DynBuf, DYN_MQTT_RECV, DYN_MQTT_SEND};

// ===========================================================================
// MQTT 3.1.1 control-packet type bytes (fixed-header first byte).
// ===========================================================================
//
// These are the high-nibble packet-type codes OR'd with their fixed low-nibble
// flags, taken verbatim from `lib/mqtt.c`. curl only ever emits/recognizes this
// minimal set (QoS 0).

/// `CONNECT` — client request to connect (`0x10`).
const MQTT_MSG_CONNECT: u8 = 0x10;
/// `PUBLISH`, QoS 0 (`0x30`). Used for upload and matched on inbound download.
const MQTT_MSG_PUBLISH: u8 = 0x30;
/// `SUBSCRIBE` with the mandatory `0x02` flag bits set (`0x82`).
const MQTT_MSG_SUBSCRIBE: u8 = 0x82;
/// `SUBACK` — subscription acknowledgement (`0x90`).
const MQTT_MSG_SUBACK: u8 = 0x90;
/// `PINGREQ` — keep-alive ping request (`0xC0`).
const MQTT_MSG_PINGREQ: u8 = 0xC0;
/// `PINGRESP` — keep-alive ping response (`0xD0`).
const MQTT_MSG_PINGRESP: u8 = 0xD0;
/// `DISCONNECT` — graceful disconnect notification (`0xE0`).
const MQTT_MSG_DISCONNECT: u8 = 0xE0;

/// `CONNACK` remaining length — always 2 (`mqtt.c` `MQTT_CONNACK_LEN`).
const MQTT_CONNACK_LEN: usize = 2;
/// `SUBACK` remaining length — always 3 (`mqtt.c` `MQTT_SUBACK_LEN`).
const MQTT_SUBACK_LEN: usize = 3;
/// Client-id length curl uses: the literal `"curl"` + 8 random alphanumerics
/// (`mqtt.c` `MQTT_CLIENTID_LEN`).
const MQTT_CLIENTID_LEN: usize = 12;

/// Maximum total MQTT message size curl will assemble (`mqtt.c`
/// `MAX_MQTT_MESSAGE_SIZE`, `0xFFFFFFF`). Shared with the send-side dynbuf cap
/// [`DYN_MQTT_SEND`].
const MAX_MQTT_MESSAGE_SIZE: usize = DYN_MQTT_SEND;

/// The full `DISCONNECT` packet — type byte + zero remaining length
/// (`mqtt.c` `mqtt_disconnect` sends the literal `"\xe0\x00"`).
const MQTT_DISCONNECT_PACKET: [u8; 2] = [MQTT_MSG_DISCONNECT, 0x00];
/// The full `PINGREQ` packet — type byte + zero remaining length
/// (`mqtt.c` `mqtt_ping` sends `{0xC0, 0x00}`).
const MQTT_PINGREQ_PACKET: [u8; 2] = [MQTT_MSG_PINGREQ, 0x00];

/// Size of the bounded scratch buffer used when streaming a `PUBLISH` body to
/// the client (`mqtt.c` `mqtt_read_publish` uses `char buffer[4 * 1024]`).
const MQTT_PUBLISH_CHUNK: usize = 4 * 1024;

// ===========================================================================
// `MqttState` — the receive-side state machine (C `enum mqttstate`).
// ===========================================================================

/// The MQTT receive state machine, mirroring `mqtt.c`'s `enum mqttstate`
/// one-to-one (same ordering and meaning).
///
/// curl drives this from its hand-rolled `select`/`poll` loop, re-entering
/// `mqtt_doing` on each readable event. Under Tokio the loop lives inside
/// [`MqttProtocol::run_subscription`], but the *states* are preserved verbatim
/// so the dispatch logic stays a faithful translation: the engine reads the
/// fixed-header byte in [`MqttState::First`], decodes the varint length in
/// [`MqttState::RemainingLength`], then transitions to the per-packet state via
/// the `next` sentinel (`mqtt.c`'s `mqtt_conn::nextstate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MqttState {
    /// `MQTT_FIRST` — read only the fixed-header (first) byte.
    First,
    /// `MQTT_REMAINING_LENGTH` — read the 1..4 byte remaining-length varint.
    RemainingLength,
    /// `MQTT_CONNACK` — awaiting/validating the `CONNACK` (the control plane in
    /// [`MqttProtocol::do_it`] occupies this state).
    ConnAck,
    /// `MQTT_SUBACK` — expecting a `SUBACK` or a `PUBLISH`.
    SubAck,
    /// `MQTT_SUBACK_COMING` — the `SUBACK` remainder is arriving; validate it.
    SubAckComing,
    /// `MQTT_PUBWAIT` — waiting for the next `PUBLISH` (post-`SUBACK`).
    PubWait,
    /// `MQTT_PUB_REMAIN` — streaming the remainder of a `PUBLISH` body.
    PubRemain,
    /// `MQTT_NOSTATE` — the never-an-actual-state sentinel used as `nextstate`.
    NoState,
}

// ===========================================================================
// Remaining-length variable-length integer codec.
// ===========================================================================

/// Encode an MQTT *remaining length* as its 1..4 byte base-128 varint
/// (`mqtt.c` `mqtt_encode_len`).
///
/// Each output byte carries 7 bits of magnitude (little-endian) with the high
/// bit set on every byte except the last. The encoding is identical to
/// `mqtt_encode_len` for any value curl ever encodes (always `> 0`); for the
/// degenerate `0` it returns a single `0x00` byte (the MQTT-spec encoding of
/// zero), which the C code instead emits as a hard-coded literal in the
/// `DISCONNECT`/`PINGREQ` packets.
///
/// # Boundaries
///
/// `≤127` → 1 byte, `≤16 383` → 2 bytes, `≤2 097 151` → 3 bytes,
/// `≤268 435 455` → 4 bytes. The result never exceeds 4 bytes.
fn encode_remaining_length(mut len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    loop {
        let mut encoded = (len & 0x7f) as u8;
        len >>= 7;
        if len > 0 {
            encoded |= 0x80;
        }
        out.push(encoded);
        if len == 0 || out.len() == 4 {
            break;
        }
    }
    out
}

/// Decode an MQTT *remaining length* varint from the front of `buf`
/// (`mqtt.c` `mqtt_decode_len`).
///
/// Returns `(value, bytes_consumed)` on success. A varint that does not
/// terminate within 4 bytes — or a buffer that ends before the terminating byte
/// — is a malformed length and maps to [`CurlError::WeirdServerReply`], exactly
/// as `mqtt.c` rejects a server that "tried to send more".
fn decode_remaining_length(buf: &[u8]) -> Result<(usize, usize)> {
    let mut value: usize = 0;
    let mut mult: usize = 1;
    for (i, &b) in buf.iter().enumerate() {
        value += (b as usize & 0x7f) * mult;
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        if i == 3 {
            // A 4th byte still carrying the continuation bit means the varint
            // would exceed 4 bytes — illegal per MQTT 3.1.1.
            return Err(CurlError::WeirdServerReply);
        }
        mult *= 128;
    }
    // Ran out of bytes before a terminating (high-bit-clear) byte.
    Err(CurlError::WeirdServerReply)
}

// ===========================================================================
// URL → topic extraction (C `mqtt_get_topic`).
// ===========================================================================

/// Map a single ASCII hex digit to its value, or `None` if not a hex digit.
fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode `input` with curl's `REJECT_NADA` semantics — decode every
/// valid `%XX` escape and **reject nothing** (control bytes, NULs and high
/// bytes all pass through). An incomplete or non-hex `%` sequence is copied
/// through literally, matching `Curl_urldecode(..., REJECT_NADA)` as used by
/// `mqtt_get_topic`.
///
/// A dedicated decoder is used (rather than the crate's stricter
/// `escape::urldecode`, which rejects control bytes) precisely to preserve the
/// permissive topic semantics curl's MQTT code relies on.
fn percent_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let c = input[i];
        if c == b'%' && i + 2 < input.len() {
            if let (Some(hi), Some(lo)) = (hexval(input[i + 1]), hexval(input[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Extract the MQTT topic from a parsed URL (`mqtt.c` `mqtt_get_topic`).
///
/// curl takes the URL path with its leading `/` stripped and percent-decodes it
/// (`REJECT_NADA`). An empty path (the bare `mqtt://host` whose path normalizes
/// to `"/"`) is rejected with "No MQTT topic found", and a topic longer than
/// `0xffff` bytes (the MQTT 16-bit length field) is rejected as "Too long". Both
/// map to [`CurlError::UrlMalformat`]; the diagnostic is recorded into
/// `error_buffer` for parity with curl's `failf`.
fn extract_topic(url: &CurlUrl, error_buffer: &mut Option<String>) -> Result<Vec<u8>> {
    // Raw path (no URL-decoding here — we decode ourselves with REJECT_NADA).
    let path = url.get(CurlUPart::Path, 0).unwrap_or_default();
    let bytes = path.as_bytes();
    if bytes.len() > 1 {
        // Strip the leading '/', then percent-decode the remainder.
        let topic = percent_decode(&bytes[1..]);
        if topic.len() > 0xffff {
            crate::failf!(error_buffer, "Too long MQTT topic");
            return Err(CurlError::UrlMalformat);
        }
        Ok(topic)
    } else {
        crate::failf!(error_buffer, "No MQTT topic found. Forgot to URL encode it?");
        Err(CurlError::UrlMalformat)
    }
}

/// The control-packet type (high nibble) of a fixed-header first byte
/// (`mqtt.c` `mq->firstbyte & 0xf0`).
fn mqtt_message_type(firstbyte: u8) -> u8 {
    firstbyte & 0xf0
}

/// Generate curl's MQTT client id: the literal `"curl"` followed by 8 random
/// alphanumeric characters (`mqtt.c` fills `MQTT_CLIENTID_LEN - 4` bytes via
/// `Curl_rand_alnum`).
///
/// Produced synchronously and returned by value (a `Send` `[u8; 12]`) so the
/// non-`Send` `ThreadRng` is never held across an `.await` point in `do_it`.
fn generate_client_id() -> [u8; MQTT_CLIENTID_LEN] {
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    let mut id = [0u8; MQTT_CLIENTID_LEN];
    id[..4].copy_from_slice(b"curl");
    let mut rng = thread_rng();
    for slot in id[4..].iter_mut() {
        *slot = rng.sample(Alphanumeric);
    }
    id
}

// ===========================================================================
// Control-packet builders (C `mqtt_connect`, `mqtt_subscribe`, `mqtt_publish`).
// ===========================================================================

/// Build a `CONNECT` packet byte-for-byte as `mqtt.c`'s `init_connpack` +
/// `add_client_id` + `add_user` + `add_passwd` assemble it.
///
/// Layout: `0x10` · remaining-length varint · variable header
/// (`00 04 'M' 'Q' 'T' 'T'` · level `04` · connect-flags · keep-alive `00 3c`)
/// · payload (`00 0c` + 12-byte client id · optional `ulen`+username · optional
/// `plen`+password). The connect-flags byte starts at `0x02` (CleanSession) and
/// gains `0x80` when a username is present and `0x40` when a password is present
/// — exactly the bits curl's `add_user`/`add_passwd` OR in.
///
/// # Errors
///
/// A username or password longer than `0xffff` bytes, or a total packet larger
/// than [`MAX_MQTT_MESSAGE_SIZE`], yields [`CurlError::WeirdServerReply`] —
/// matching `mqtt.c` exactly (the diagnostic is recorded into `error_buffer`).
fn build_connect_packet(
    client_id: &[u8; MQTT_CLIENTID_LEN],
    username: &[u8],
    password: &[u8],
    error_buffer: &mut Option<String>,
) -> Result<Vec<u8>> {
    let ulen = username.len();
    let plen = password.len();
    if ulen > 0xffff {
        crate::failf!(error_buffer, "Username too long: [{ulen}]");
        return Err(CurlError::WeirdServerReply);
    }
    if plen > 0xffff {
        crate::failf!(error_buffer, "Password too long: [{plen}]");
        return Err(CurlError::WeirdServerReply);
    }

    // `payloadlen` mirrors mqtt.c: client-id (2-byte length prefix + 12 bytes)
    // plus each present credential (2-byte length prefix + bytes).
    let payloadlen = ulen
        + plen
        + MQTT_CLIENTID_LEN
        + 2
        + if ulen > 0 { 2 } else { 0 }
        + if plen > 0 { 2 } else { 0 };

    // The remaining length covers the 10-byte variable header plus the payload.
    let remain = encode_remaining_length(payloadlen + 10);
    let packetlen = payloadlen + 10 + remain.len() + 1;
    if packetlen > MAX_MQTT_MESSAGE_SIZE {
        crate::failf!(error_buffer, "MQTT CONNECT packet too large: {packetlen}");
        return Err(CurlError::WeirdServerReply);
    }

    let mut pkt = Vec::with_capacity(packetlen);
    // --- Fixed header ---
    pkt.push(MQTT_MSG_CONNECT);
    pkt.extend_from_slice(&remain);
    // --- Variable header (10 bytes) ---
    pkt.push(0x00); // protocol name length (MSB)
    pkt.push(0x04); // protocol name length (LSB) = 4
    pkt.extend_from_slice(b"MQTT"); // protocol name
    pkt.push(0x04); // protocol level (MQTT 3.1.1)
    let mut connect_flags = 0x02u8; // CleanSession
    if ulen > 0 {
        connect_flags |= 0x80; // username present
    }
    if plen > 0 {
        connect_flags |= 0x40; // password present
    }
    pkt.push(connect_flags);
    pkt.push(0x00); // keep-alive (MSB)
    pkt.push(0x3c); // keep-alive (LSB) = 60s
    // --- Payload: client id (always present) ---
    pkt.push(0x00);
    pkt.push(MQTT_CLIENTID_LEN as u8);
    pkt.extend_from_slice(client_id);
    // --- Payload: username (optional) ---
    if ulen > 0 {
        pkt.push(((ulen >> 8) & 0xff) as u8);
        pkt.push((ulen & 0xff) as u8);
        pkt.extend_from_slice(username);
    }
    // --- Payload: password (optional) ---
    if plen > 0 {
        pkt.push(((plen >> 8) & 0xff) as u8);
        pkt.push((plen & 0xff) as u8);
        pkt.extend_from_slice(password);
    }

    debug_assert_eq!(pkt.len(), packetlen, "CONNECT packet length mismatch");
    Ok(pkt)
}

/// Build a `SUBSCRIBE` packet byte-for-byte as `mqtt.c`'s `mqtt_subscribe`
/// assembles it (a single topic filter at QoS 0).
///
/// Layout: `0x82` · remaining-length varint · packet-id (2 bytes) ·
/// topic-length (2 bytes) · topic · QoS byte (`0x00`). The remaining length
/// covers `packet-id(2) + topic-length(2) + topic + QoS(1)` = `topiclen + 5`.
fn build_subscribe_packet(topic: &[u8], packet_id: u16) -> Vec<u8> {
    let topiclen = topic.len();
    let remaining = topiclen + 5;
    let encoded = encode_remaining_length(remaining);
    let total = remaining + encoded.len() + 1;

    let mut pkt = Vec::with_capacity(total);
    pkt.push(MQTT_MSG_SUBSCRIBE);
    pkt.extend_from_slice(&encoded);
    pkt.push(((packet_id >> 8) & 0xff) as u8);
    pkt.push((packet_id & 0xff) as u8);
    pkt.push(((topiclen >> 8) & 0xff) as u8);
    pkt.push((topiclen & 0xff) as u8);
    pkt.extend_from_slice(topic);
    pkt.push(0x00); // requested QoS 0

    debug_assert_eq!(pkt.len(), total, "SUBSCRIBE packet length mismatch");
    pkt
}

/// Build a `PUBLISH` packet byte-for-byte as `mqtt.c`'s `mqtt_publish`
/// assembles it (QoS 0 — no packet id).
///
/// Layout: `0x30` · remaining-length varint · topic-length (2 bytes) · topic ·
/// payload. The remaining length covers `topic-length(2) + topic + payload` =
/// `payloadlen + 2 + topiclen`.
///
/// # Errors
///
/// Returns [`CurlError::TooLarge`] when the remaining length would exceed what
/// the varint plus control byte can address (`MAX_MQTT_MESSAGE_SIZE`), matching
/// `mqtt.c`'s `CURLE_TOO_LARGE` guard exactly.
fn build_publish_packet(topic: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let topiclen = topic.len();
    let payloadlen = payload.len();
    let remaining = payloadlen + 2 + topiclen;
    let encoded = encode_remaining_length(remaining);
    let encodelen = encoded.len();

    // mqtt.c: if(remaininglength > (MAX_MQTT_MESSAGE_SIZE - encodelen - 1))
    if remaining > MAX_MQTT_MESSAGE_SIZE - encodelen - 1 {
        return Err(CurlError::TooLarge);
    }

    let total = remaining + 1 + encodelen;
    let mut pkt = Vec::with_capacity(total);
    pkt.push(MQTT_MSG_PUBLISH);
    pkt.extend_from_slice(&encoded);
    pkt.push(((topiclen >> 8) & 0xff) as u8);
    pkt.push((topiclen & 0xff) as u8);
    pkt.extend_from_slice(topic);
    pkt.extend_from_slice(payload);

    debug_assert_eq!(pkt.len(), total, "PUBLISH packet length mismatch");
    Ok(pkt)
}

// ===========================================================================
// Control-packet verifiers (C `mqtt_verify_connack`, `mqtt_verify_suback`).
// ===========================================================================

/// Verify a `CONNACK` (`mqtt.c` `mqtt_verify_connack`).
///
/// The remaining length must be exactly 2 and both acknowledgement bytes must be
/// `0x00` (session-not-present, accepted). Any deviation is
/// [`CurlError::WeirdServerReply`], with curl's exact diagnostic recorded into
/// `error_buffer`.
fn verify_connack(
    remaining_length: usize,
    payload: &[u8],
    error_buffer: &mut Option<String>,
) -> Result<()> {
    if remaining_length != MQTT_CONNACK_LEN {
        crate::failf!(
            error_buffer,
            "CONNACK expected Remaining Length 2, got {remaining_length}"
        );
        return Err(CurlError::WeirdServerReply);
    }
    if payload.len() < MQTT_CONNACK_LEN {
        return Err(CurlError::WeirdServerReply);
    }
    if payload[0] != 0x00 || payload[1] != 0x00 {
        crate::failf!(
            error_buffer,
            "Expected 0000 but got {:02x}{:02x}",
            payload[0],
            payload[1]
        );
        return Err(CurlError::WeirdServerReply);
    }
    Ok(())
}

/// Verify a `SUBACK` (`mqtt.c` `mqtt_verify_suback`).
///
/// The remaining length must be exactly 3, the two packet-id bytes must echo the
/// `SUBSCRIBE` packet id, and the return-code byte must be `0x00` (QoS 0
/// granted). A wrong remaining length records curl's diagnostic; a body mismatch
/// is rejected silently (as `mqtt.c` does — it only resets the buffer). Both map
/// to [`CurlError::WeirdServerReply`].
fn verify_suback(
    remaining_length: usize,
    payload: &[u8],
    packet_id: u16,
    error_buffer: &mut Option<String>,
) -> Result<()> {
    if remaining_length != MQTT_SUBACK_LEN {
        crate::failf!(
            error_buffer,
            "SUBACK expected Remaining Length 3, got {remaining_length}"
        );
        return Err(CurlError::WeirdServerReply);
    }
    if payload.len() < MQTT_SUBACK_LEN {
        return Err(CurlError::WeirdServerReply);
    }
    let want_hi = ((packet_id >> 8) & 0xff) as u8;
    let want_lo = (packet_id & 0xff) as u8;
    if payload[0] != want_hi || payload[1] != want_lo || payload[2] != 0x00 {
        // mqtt.c rejects a mismatched SUBACK body without a failf message.
        return Err(CurlError::WeirdServerReply);
    }
    Ok(())
}

// ===========================================================================
// Async byte-movers over the connection-filter chain (C `mqtt_send`,
// `Curl_xfer_recv`, `mqtt_recv_atleast`).
// ===========================================================================

/// Send the whole of `buf`, looping over partial sends and treating
/// [`CurlError::Again`] as "retry after yielding" (C `mqtt_send` re-queues the
/// unsent tail; under Tokio the runtime simply awaits writability).
async fn send_all(conn: &mut Connection, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        match Curl_conn_send(conn, FIRSTSOCKET, buf, false).await {
            Ok(0) => return Err(CurlError::SendError),
            Ok(n) => buf = &buf[n..],
            Err(CurlError::Again) => tokio::task::yield_now().await,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Receive once into `buf`, transparently retrying [`CurlError::Again`]. Returns
/// the number of bytes read; `0` means the peer closed the connection (EOF).
async fn recv_some(conn: &mut Connection, buf: &mut [u8]) -> Result<usize> {
    loop {
        match Curl_conn_recv(conn, FIRSTSOCKET, buf).await {
            Ok(n) => return Ok(n),
            Err(CurlError::Again) => tokio::task::yield_now().await,
            Err(e) => return Err(e),
        }
    }
}

/// Read exactly one byte; an immediate EOF maps to [`CurlError::RecvError`]
/// (`mqtt.c` MQTT_FIRST: "Connection disconnected" → `CURLE_RECV_ERROR`).
async fn recv_one_byte(conn: &mut Connection) -> Result<u8> {
    let mut b = [0u8; 1];
    if recv_some(conn, &mut b).await? == 0 {
        return Err(CurlError::RecvError);
    }
    Ok(b[0])
}

/// Read the 1..4 byte remaining-length varint one byte at a time, mirroring
/// `mqtt.c`'s `do { recv 1 } while(byte & 0x80 && npacket < 4)` loop, then decode
/// it. A 5th continuation byte or a mid-varint EOF is a malformed length
/// ([`CurlError::WeirdServerReply`]).
async fn recv_remaining_length(conn: &mut Connection) -> Result<usize> {
    let mut bytes = [0u8; 4];
    let mut n = 0usize;
    loop {
        let mut b = [0u8; 1];
        if recv_some(conn, &mut b).await? == 0 {
            return Err(CurlError::WeirdServerReply);
        }
        bytes[n] = b[0];
        n += 1;
        if b[0] & 0x80 == 0 {
            break;
        }
        if n == 4 {
            return Err(CurlError::WeirdServerReply);
        }
    }
    let (value, _consumed) = decode_remaining_length(&bytes[..n])?;
    Ok(value)
}

/// Accumulate bytes into `acc` until it holds at least `nbytes`, mirroring
/// `mqtt.c`'s `mqtt_recv_atleast` (which fills `mq->recvbuf`, a dynbuf capped at
/// [`DYN_MQTT_RECV`]). A premature EOF is [`CurlError::WeirdServerReply`].
async fn recv_atleast(conn: &mut Connection, acc: &mut DynBuf, nbytes: usize) -> Result<()> {
    let mut tmp = [0u8; 1024];
    while acc.curlx_dyn_len() < nbytes {
        let want = (nbytes - acc.curlx_dyn_len()).min(tmp.len());
        let got = recv_some(conn, &mut tmp[..want]).await?;
        if got == 0 {
            return Err(CurlError::WeirdServerReply);
        }
        acc.curlx_dyn_addn(&tmp[..got])?;
    }
    Ok(())
}

/// Read the next fixed-header byte while honoring curl's keep-alive: if more than
/// `upkeep_ms` elapses with no data (and a ping is not already outstanding), send
/// a `PINGREQ` and keep waiting — `mqtt.c`'s `mqtt_ping`, which fires only in the
/// `MQTT_FIRST` state under the `!pingsent && upkeep_interval_ms > 0` guard.
///
/// Returns `None` on EOF. When `upkeep_ms <= 0` the keep-alive is disabled and
/// this is a plain single-byte read.
async fn recv_first_byte_keepalive(
    conn: &mut Connection,
    upkeep_ms: i64,
    verbose: bool,
    pingsent: &mut bool,
) -> Result<Option<u8>> {
    let mut b = [0u8; 1];
    if upkeep_ms <= 0 {
        let n = recv_some(conn, &mut b).await?;
        return Ok(if n == 0 { None } else { Some(b[0]) });
    }

    let dur = Duration::from_millis(upkeep_ms as u64);
    loop {
        match tokio::time::timeout(dur, recv_some(conn, &mut b)).await {
            Ok(res) => {
                let n = res?;
                return Ok(if n == 0 { None } else { Some(b[0]) });
            }
            Err(_elapsed) => {
                // Idle past the upkeep interval: send a single keep-alive ping
                // (mqtt.c's `!pingsent` guard) and continue waiting.
                if !*pingsent {
                    send_all(conn, &MQTT_PINGREQ_PACKET).await?;
                    *pingsent = true;
                    crate::infof!(verbose, "mqtt_ping: sent ping request.");
                }
            }
        }
    }
}

// ===========================================================================
// `MqttProtocol` — the `mqtt` / `mqtts` scheme engine (C `Curl_protocol_mqtt`).
// ===========================================================================

/// The MQTT/MQTTS protocol engine — the Rust analog of `mqtt.c`'s
/// `Curl_protocol_mqtt` / `Curl_protocol_mqtts` function-pointer vtables.
///
/// A handler is a stateless zero-cost wrapper around its `&'static` scheme
/// descriptor (`mqtt` over plain TCP, `mqtts` over a TLS connection filter); all
/// per-transfer state lives in the [`Easy`] handle and [`Connection`], exactly
/// as the C callbacks take `Curl_easy *` / `connectdata *`. The two schemes
/// share identical behavior — `mqtts` differs only in that its connection filter
/// chain terminates in TLS, which [`Curl_conn_connect`] negotiates transparently.
pub struct MqttProtocol {
    /// The static scheme descriptor this handler serves (`mqtt` or `mqtts`).
    scheme: &'static Scheme,
}

impl MqttProtocol {
    /// Construct a handler for the given (static) scheme descriptor. Used by
    /// `crate::protocols::scheme_handler` to map the `mqtt`/`mqtts` schemes to
    /// this engine.
    #[must_use]
    pub(crate) const fn new(scheme: &'static Scheme) -> Self {
        Self { scheme }
    }

    /// Run the inbound subscription receive loop after a `SUBSCRIBE` has been
    /// sent (the download path). Faithfully mirrors `mqtt.c`'s `mqtt_doing` +
    /// `mqtt_read_publish` state machine: validate the `SUBACK`, then stream each
    /// `PUBLISH` payload — the *entire* remaining length, topic header included,
    /// exactly as curl writes it — to the client via `writer`/`sink`, until the
    /// server sends `DISCONNECT`.
    ///
    /// `packet_id` is the id used in the preceding `SUBSCRIBE` (echoed in the
    /// `SUBACK`). The transfer's `max_filesize` (if set) caps each `PUBLISH`
    /// body; the keep-alive `PINGREQ` is driven by `upkeep_interval_ms`.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors, a failed `SUBACK` validation
    /// ([`CurlError::WeirdServerReply`]), an over-size body
    /// ([`CurlError::FilesizeExceeded`]), or a mid-body disconnect
    /// ([`CurlError::PartialFile`]) — matching `mqtt.c`'s error mapping.
    pub async fn run_subscription(
        &self,
        data: &Easy,
        conn: &mut Connection,
        writer: &mut ClientWriter,
        sink: &mut dyn WriteCallbacks,
        packet_id: u16,
    ) -> Result<()> {
        let verbose = data.set.verbose;
        let max_filesize = data.set.max_filesize;
        let upkeep_ms = data.set.upkeep_interval_ms;

        crate::infof!(
            verbose,
            "mqtt: subscribe receive loop on '{}' (sentinel {:?})",
            self.scheme.name,
            MqttState::NoState
        );

        let mut state = MqttState::First;
        let mut nextstate = MqttState::SubAck;
        let mut firstbyte: u8 = 0;
        let mut remaining_length: usize = 0;
        let mut npacket: usize = 0;
        let mut pingsent = false;

        loop {
            match state {
                MqttState::First => {
                    match recv_first_byte_keepalive(conn, upkeep_ms, verbose, &mut pingsent).await? {
                        Some(b) => firstbyte = b,
                        None => {
                            crate::failf!(&mut conn.filter_data.error_buffer, "Connection disconnected");
                            return Err(CurlError::RecvError);
                        }
                    }
                    npacket = 0;
                    state = MqttState::RemainingLength;
                }
                MqttState::RemainingLength => {
                    remaining_length = recv_remaining_length(conn).await?;
                    if remaining_length > 0 {
                        // The length is known; advance to the per-packet state.
                        state = nextstate;
                        nextstate = MqttState::NoState;
                    } else {
                        // A zero-length packet is only DISCONNECT or PINGRESP.
                        match mqtt_message_type(firstbyte) {
                            MQTT_MSG_DISCONNECT => {
                                crate::infof!(verbose, "mqtt: got DISCONNECT");
                                break;
                            }
                            MQTT_MSG_PINGRESP => {
                                crate::infof!(verbose, "mqtt: received ping response.");
                                pingsent = false;
                                state = MqttState::First;
                                nextstate = MqttState::PubWait;
                            }
                            _ => {
                                state = MqttState::First;
                                nextstate = MqttState::PubWait;
                            }
                        }
                    }
                }
                MqttState::SubAck | MqttState::PubWait => {
                    // We are expecting a PUBLISH or a SUBACK.
                    match mqtt_message_type(firstbyte) {
                        MQTT_MSG_PUBLISH => {
                            if max_filesize > 0 && remaining_length as i64 > max_filesize {
                                crate::failf!(&mut conn.filter_data.error_buffer, "Maximum file size exceeded");
                                return Err(CurlError::FilesizeExceeded);
                            }
                            crate::infof!(verbose, "mqtt: Remaining length: {remaining_length} bytes");
                            npacket = remaining_length;
                            state = MqttState::PubRemain;
                        }
                        MQTT_MSG_SUBACK => state = MqttState::SubAckComing,
                        MQTT_MSG_DISCONNECT => {
                            crate::infof!(verbose, "mqtt: got DISCONNECT");
                            break;
                        }
                        _ => {
                            crate::failf!(&mut conn.filter_data.error_buffer, "Unexpected MQTT packet");
                            return Err(CurlError::WeirdServerReply);
                        }
                    }
                }
                MqttState::SubAckComing => {
                    let mut suback = DynBuf::new(DYN_MQTT_RECV);
                    recv_atleast(conn, &mut suback, MQTT_SUBACK_LEN).await?;
                    verify_suback(
                        remaining_length,
                        suback.curlx_dyn_ptr(),
                        packet_id,
                        &mut conn.filter_data.error_buffer,
                    )?;
                    crate::infof!(verbose, "mqtt: SUBACK verified");
                    state = MqttState::First;
                    nextstate = MqttState::PubWait;
                }
                MqttState::PubRemain => {
                    // Stream the remainder of this PUBLISH body to the client,
                    // capped to a 4 KiB scratch buffer per read.
                    let mut buf = [0u8; MQTT_PUBLISH_CHUNK];
                    while npacket > 0 {
                        let want = npacket.min(buf.len());
                        let got = recv_some(conn, &mut buf[..want]).await?;
                        if got == 0 {
                            crate::failf!(&mut conn.filter_data.error_buffer, "server disconnected");
                            return Err(CurlError::PartialFile);
                        }
                        writer.write(ClientWriteType::BODY, &buf[..got], sink)?;
                        npacket -= got;
                    }
                    state = MqttState::First;
                    nextstate = MqttState::PubWait;
                }
                MqttState::ConnAck | MqttState::NoState => {
                    // Neither occurs as a live receive-loop state (CONNACK is the
                    // control plane; NoState is the `nextstate` sentinel).
                    crate::failf!(&mut conn.filter_data.error_buffer, "MQTT state not handled");
                    return Err(CurlError::WeirdServerReply);
                }
            }
        }

        // Graceful end (server DISCONNECT): signal end-of-stream to the writer.
        writer.write(ClientWriteType::BODY | ClientWriteType::EOS, &[], sink)?;
        Ok(())
    }
}

impl Protocol for MqttProtocol {
    fn scheme(&self) -> &'static Scheme {
        self.scheme
    }

    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            // --- Extract everything we need from `data` up front, before any
            // `.await`, so the non-Send `ThreadRng` and the `&Easy` borrow are
            // released before connection I/O begins. ---
            let verbose = data.set.verbose;
            // An upload is requested when the caller supplied a request body
            // (`-d` / CURLOPT_POSTFIELDS). The payload bytes come from the owned
            // `copypostfields` (the safe, CLI/`-d` path); a raw `postfields`
            // pointer without an owned copy cannot be read without `unsafe`.
            let upload = data.set.copypostfields.is_some() || data.set.postfields.is_some();
            let payload: Option<Vec<u8>> = data.set.copypostfields.clone();

            let url_str = data.url().ok_or(CurlError::UrlMalformat)?.to_string();
            let mut url = CurlUrl::new();
            url.set(CurlUPart::Url, Some(&url_str), CURLU_DEFAULT_PORT)
                .map_err(|_| CurlError::UrlMalformat)?;
            let topic = extract_topic(&url, &mut conn.filter_data.error_buffer)?;
            let username = url.get(CurlUPart::User, CURLU_URLDECODE).unwrap_or_default();
            let password = url.get(CurlUPart::Password, CURLU_URLDECODE).unwrap_or_default();
            let client_id = generate_client_id();

            // --- Establish the connection (drives the TLS filter for mqtts). ---
            Curl_conn_connect(conn, FIRSTSOCKET, true).await?;

            // --- CONNECT → CONNACK ---
            let connect_pkt = build_connect_packet(
                &client_id,
                username.as_bytes(),
                password.as_bytes(),
                &mut conn.filter_data.error_buffer,
            )?;
            if let Err(e) = send_all(conn, &connect_pkt).await {
                crate::failf!(&mut conn.filter_data.error_buffer, "Error sending MQTT CONNECT request");
                return Err(e);
            }
            crate::infof!(verbose, "mqtt: CONNECT sent, awaiting {:?}", MqttState::ConnAck);

            // The CONNACK arrives as: fixed-header byte, remaining-length varint
            // (must be 2), then the 2 acknowledgement bytes (both 0x00).
            let _connack_firstbyte = recv_one_byte(conn).await?;
            let connack_remaining = recv_remaining_length(conn).await?;
            let mut connack = DynBuf::new(DYN_MQTT_RECV);
            recv_atleast(conn, &mut connack, MQTT_CONNACK_LEN).await?;
            verify_connack(
                connack_remaining,
                connack.curlx_dyn_ptr(),
                &mut conn.filter_data.error_buffer,
            )?;
            crate::infof!(verbose, "mqtt: CONNACK accepted");

            // --- Upload: PUBLISH then DISCONNECT (mqtt.c HTTPREQ_POST path) ---
            if upload {
                let payload = payload.ok_or(CurlError::BadFunctionArgument)?;
                let publish_pkt = build_publish_packet(&topic, &payload)?;
                send_all(conn, &publish_pkt).await?;
                send_all(conn, &MQTT_DISCONNECT_PACKET).await?;
                crate::infof!(
                    verbose,
                    "mqtt: PUBLISH ({} bytes) + DISCONNECT sent",
                    payload.len()
                );
                return Ok(ProtocolTransfer::new(TransferDirection::Upload));
            }

            // --- Download: SUBSCRIBE; the receive loop runs in
            // `run_subscription` once the engine begins pumping the body. ---
            let packet_id: u16 = 1; // mqtt.c increments `packetid` from 0 → 1.
            let subscribe_pkt = build_subscribe_packet(&topic, packet_id);
            send_all(conn, &subscribe_pkt).await?;
            crate::infof!(
                verbose,
                "mqtt: SUBSCRIBE (packet id {}) sent, awaiting {:?}",
                packet_id,
                MqttState::SubAck
            );
            Ok(ProtocolTransfer::new(TransferDirection::Download))
        })
    }

    fn done<'a>(
        &'a self,
        _data: &'a mut Easy,
        _conn: &'a mut Connection,
        _status: Result<()>,
        _premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        // mqtt.c's `mqtt_done` frees the per-transfer send/recv dynbufs. Here
        // those buffers are locals owned by `do_it` / `run_subscription`, so they
        // are already released by `Drop`; nothing remains to clean up.
        Box::pin(async move { Ok(()) })
    }
}

// ===========================================================================
// Tests
// ===========================================================================
//
// Two tiers, mirroring the file brief's validation checklist:
//
//   * Pure codec / framing unit tests — exercise the binary wire format against
//     `lib/mqtt.c`'s exact byte layout: the remaining-length varint across all
//     1–4 byte boundaries, CONNECT / SUBSCRIBE / PUBLISH framing, CONNACK and
//     SUBACK verification, topic extraction, and percent decoding. These need
//     no I/O and assert byte-for-byte parity with the C oracle.
//
//   * Mock-filter integration tests — drive `do_it` (upload → PUBLISH, download
//     → SUBSCRIBE) and `run_subscription` (the receive state machine) over a
//     scripted, in-memory [`ConnectionFilter`], asserting both the bytes placed
//     on the wire and the body streamed to the client.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::{CfState, ConnectionFilter};
    use crate::conn::{SchemeDescriptor, TRNSPRT_TCP};
    use crate::options::CurlOption;
    use crate::protocols::SCHEME_MQTT;
    use crate::setopt::OptionValue;
    use std::sync::{Arc, Mutex};

    // ---- remaining-length varint: encode ---------------------------------

    #[test]
    fn encode_remaining_length_boundaries() {
        // The four byte-width boundaries the MQTT 3.1.1 spec calls out.
        assert_eq!(encode_remaining_length(0), vec![0x00]);
        assert_eq!(encode_remaining_length(127), vec![0x7f]);
        assert_eq!(encode_remaining_length(128), vec![0x80, 0x01]);
        assert_eq!(encode_remaining_length(16_383), vec![0xff, 0x7f]);
        assert_eq!(encode_remaining_length(16_384), vec![0x80, 0x80, 0x01]);
        assert_eq!(encode_remaining_length(2_097_151), vec![0xff, 0xff, 0x7f]);
        assert_eq!(
            encode_remaining_length(2_097_152),
            vec![0x80, 0x80, 0x80, 0x01]
        );
    }

    // ---- remaining-length varint: decode ---------------------------------

    #[test]
    fn decode_remaining_length_boundaries() {
        assert_eq!(decode_remaining_length(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_remaining_length(&[0x7f]).unwrap(), (127, 1));
        assert_eq!(decode_remaining_length(&[0x80, 0x01]).unwrap(), (128, 2));
        assert_eq!(decode_remaining_length(&[0xff, 0x7f]).unwrap(), (16_383, 2));
        assert_eq!(
            decode_remaining_length(&[0x80, 0x80, 0x01]).unwrap(),
            (16_384, 3)
        );
        assert_eq!(
            decode_remaining_length(&[0xff, 0xff, 0x7f]).unwrap(),
            (2_097_151, 3)
        );
        assert_eq!(
            decode_remaining_length(&[0x80, 0x80, 0x80, 0x01]).unwrap(),
            (2_097_152, 4)
        );
    }

    #[test]
    fn decode_remaining_length_rejects_overlong() {
        // A 4th byte with its continuation bit still set is malformed (MQTT caps
        // the remaining-length field at four bytes).
        assert!(decode_remaining_length(&[0x80, 0x80, 0x80, 0x80]).is_err());
        // Five continuation bytes never terminate within the 4-byte window.
        assert!(decode_remaining_length(&[0x80, 0x80, 0x80, 0x80, 0x01]).is_err());
    }

    #[test]
    fn remaining_length_round_trips() {
        for &n in &[
            0usize, 1, 126, 127, 128, 8192, 16_383, 16_384, 2_097_151, 2_097_152,
        ] {
            let enc = encode_remaining_length(n);
            let (val, used) = decode_remaining_length(&enc).unwrap();
            assert_eq!(val, n, "value round-trip for {n}");
            assert_eq!(used, enc.len(), "consumed-length round-trip for {n}");
        }
    }

    // ---- CONNECT framing --------------------------------------------------

    #[test]
    fn connect_packet_without_credentials() {
        let client_id = *b"curlABCDEFGH";
        let pkt = build_connect_packet(&client_id, b"", b"", &mut None).unwrap();
        // Fixed header + single-byte remaining length (= 24).
        assert_eq!(pkt[0], MQTT_MSG_CONNECT);
        assert_eq!(pkt[1], 24);
        // Variable header: protocol name "MQTT", level 4, flags, keep-alive 60.
        assert_eq!(&pkt[2..8], &[0x00, 0x04, b'M', b'Q', b'T', b'T']);
        assert_eq!(pkt[8], 0x04, "protocol level");
        assert_eq!(pkt[9], 0x02, "connect flags: clean-session only");
        assert_eq!(&pkt[10..12], &[0x00, 0x3c], "keep-alive 60s");
        // Payload: 2-byte client-id length + the 12-byte id.
        assert_eq!(&pkt[12..14], &[0x00, 0x0c]);
        assert_eq!(&pkt[14..26], &client_id);
        assert_eq!(pkt.len(), 26);
    }

    #[test]
    fn connect_packet_with_credentials() {
        let client_id = *b"curlABCDEFGH";
        let pkt = build_connect_packet(&client_id, b"user", b"pass", &mut None).unwrap();
        assert_eq!(pkt[0], MQTT_MSG_CONNECT);
        assert_eq!(pkt[1], 36, "remaining length with creds");
        // Connect flags carry username (0x80) + password (0x40) + clean (0x02).
        assert_eq!(pkt[9], 0xc2);
        // Client id ends at offset 26; the username section follows, then password.
        assert_eq!(&pkt[26..28], &[0x00, 0x04]);
        assert_eq!(&pkt[28..32], b"user");
        assert_eq!(&pkt[32..34], &[0x00, 0x04]);
        assert_eq!(&pkt[34..38], b"pass");
        assert_eq!(pkt.len(), 38);
    }

    #[test]
    fn connect_packet_rejects_overlong_credentials() {
        let client_id = *b"curlABCDEFGH";
        let huge = vec![b'x'; 0x1_0000]; // 65536 > 0xffff
        assert!(build_connect_packet(&client_id, &huge, b"", &mut None).is_err());
        assert!(build_connect_packet(&client_id, b"", &huge, &mut None).is_err());
    }

    // ---- SUBSCRIBE framing ------------------------------------------------

    #[test]
    fn subscribe_packet_layout() {
        let pkt = build_subscribe_packet(b"topic", 1);
        assert_eq!(pkt[0], MQTT_MSG_SUBSCRIBE); // 0x82
        assert_eq!(pkt[1], 10, "remaining length = topiclen(5) + 5");
        assert_eq!(&pkt[2..4], &[0x00, 0x01], "packet id");
        assert_eq!(&pkt[4..6], &[0x00, 0x05], "topic length");
        assert_eq!(&pkt[6..11], b"topic");
        assert_eq!(pkt[11], 0x00, "requested QoS 0");
        assert_eq!(pkt.len(), 12);
    }

    #[test]
    fn subscribe_packet_id_encoded_big_endian() {
        let pkt = build_subscribe_packet(b"x", 0x1234);
        assert_eq!(&pkt[2..4], &[0x12, 0x34]);
    }

    // ---- PUBLISH framing --------------------------------------------------

    #[test]
    fn publish_packet_layout() {
        let pkt = build_publish_packet(b"topic", b"hello").unwrap();
        assert_eq!(pkt[0], MQTT_MSG_PUBLISH); // 0x30
        assert_eq!(pkt[1], 12, "remaining = payload(5) + 2 + topiclen(5)");
        assert_eq!(&pkt[2..4], &[0x00, 0x05], "topic length");
        assert_eq!(&pkt[4..9], b"topic");
        assert_eq!(&pkt[9..14], b"hello");
        assert_eq!(pkt.len(), 14);
    }

    #[test]
    fn publish_packet_empty_payload() {
        let pkt = build_publish_packet(b"t", b"").unwrap();
        // remaining = 0 + 2 + 1 = 3
        assert_eq!(pkt[0], MQTT_MSG_PUBLISH);
        assert_eq!(pkt[1], 3);
        assert_eq!(&pkt[2..4], &[0x00, 0x01]);
        assert_eq!(&pkt[4..5], b"t");
        assert_eq!(pkt.len(), 5);
    }

    // ---- CONNACK verification ---------------------------------------------

    #[test]
    fn connack_accepts_success() {
        assert!(verify_connack(MQTT_CONNACK_LEN, &[0x00, 0x00], &mut None).is_ok());
    }

    #[test]
    fn connack_rejects_nonzero_return_code() {
        assert!(verify_connack(MQTT_CONNACK_LEN, &[0x00, 0x05], &mut None).is_err());
        assert!(verify_connack(MQTT_CONNACK_LEN, &[0x01, 0x00], &mut None).is_err());
    }

    #[test]
    fn connack_rejects_wrong_remaining_length() {
        assert!(verify_connack(3, &[0x00, 0x00], &mut None).is_err());
        assert!(verify_connack(0, &[0x00, 0x00], &mut None).is_err());
    }

    #[test]
    fn connack_rejects_short_payload() {
        assert!(verify_connack(MQTT_CONNACK_LEN, &[0x00], &mut None).is_err());
    }

    // ---- SUBACK verification ----------------------------------------------

    #[test]
    fn suback_accepts_matching_packet_id() {
        assert!(verify_suback(MQTT_SUBACK_LEN, &[0x00, 0x01, 0x00], 1, &mut None).is_ok());
    }

    #[test]
    fn suback_rejects_failure_code() {
        // A third byte of 0x80 is the SUBACK "failure" return code.
        assert!(verify_suback(MQTT_SUBACK_LEN, &[0x00, 0x01, 0x80], 1, &mut None).is_err());
    }

    #[test]
    fn suback_rejects_packet_id_mismatch() {
        assert!(verify_suback(MQTT_SUBACK_LEN, &[0x00, 0x02, 0x00], 1, &mut None).is_err());
    }

    #[test]
    fn suback_rejects_wrong_remaining_length() {
        assert!(verify_suback(2, &[0x00, 0x01, 0x00], 1, &mut None).is_err());
    }

    // ---- topic extraction + percent decoding ------------------------------

    #[test]
    fn extract_topic_simple() {
        let mut url = CurlUrl::new();
        url.set(CurlUPart::Url, Some("mqtt://host/mytopic"), CURLU_DEFAULT_PORT)
            .unwrap();
        let mut eb = None;
        assert_eq!(extract_topic(&url, &mut eb).unwrap(), b"mytopic".to_vec());
    }

    #[test]
    fn extract_topic_multi_segment() {
        let mut url = CurlUrl::new();
        url.set(CurlUPart::Url, Some("mqtt://host/a/b/c"), CURLU_DEFAULT_PORT)
            .unwrap();
        let mut eb = None;
        assert_eq!(extract_topic(&url, &mut eb).unwrap(), b"a/b/c".to_vec());
    }

    #[test]
    fn extract_topic_missing_is_malformat() {
        let mut url = CurlUrl::new();
        url.set(CurlUPart::Url, Some("mqtt://host/"), CURLU_DEFAULT_PORT)
            .unwrap();
        let mut eb = None;
        assert!(matches!(
            extract_topic(&url, &mut eb),
            Err(CurlError::UrlMalformat)
        ));
    }

    #[test]
    fn percent_decode_matches_reject_nada() {
        assert_eq!(percent_decode(b"plain"), b"plain".to_vec());
        assert_eq!(percent_decode(b"a%2Fb"), b"a/b".to_vec()); // 0x2F == '/'
        assert_eq!(percent_decode(b"%41%42"), b"AB".to_vec());
        // Incomplete / invalid escapes are kept verbatim (curl's REJECT_NADA).
        assert_eq!(percent_decode(b"a%2"), b"a%2".to_vec());
        assert_eq!(percent_decode(b"a%zz"), b"a%zz".to_vec());
    }

    // ---- small helpers ----------------------------------------------------

    #[test]
    fn message_type_masks_low_nibble() {
        assert_eq!(mqtt_message_type(0x32), 0x30);
        assert_eq!(mqtt_message_type(0x90), 0x90);
        assert_eq!(mqtt_message_type(0xe5), 0xe0);
    }

    #[test]
    fn client_id_shape() {
        let id = generate_client_id();
        assert_eq!(id.len(), MQTT_CLIENTID_LEN);
        assert_eq!(&id[..4], b"curl");
        assert!(id[4..].iter().all(u8::is_ascii_alphanumeric));
    }

    #[test]
    fn fixed_packet_constants() {
        assert_eq!(MQTT_DISCONNECT_PACKET, [MQTT_MSG_DISCONNECT, 0x00]);
        assert_eq!(MQTT_PINGREQ_PACKET, [MQTT_MSG_PINGREQ, 0x00]);
    }

    // =======================================================================
    // Mock connection filter — a scripted, in-memory bottom-of-chain filter.
    // =======================================================================

    /// A connection filter that satisfies `send` / `recv` from in-memory
    /// buffers. It is marked already-connected so the chain routes I/O straight
    /// to it (and so `Curl_conn_connect` short-circuits to success).
    struct MockFilter {
        state: CfState,
        sent: Arc<Mutex<Vec<u8>>>,
        recv_data: Arc<Mutex<Vec<u8>>>,
    }

    impl MockFilter {
        fn new(recv_data: Arc<Mutex<Vec<u8>>>, sent: Arc<Mutex<Vec<u8>>>) -> Self {
            Self {
                state: CfState {
                    connected: true,
                    ..Default::default()
                },
                sent,
                recv_data,
            }
        }
    }

    impl ConnectionFilter for MockFilter {
        fn name(&self) -> &'static str {
            "MOCK-MQTT"
        }
        fn cf_state(&self) -> &CfState {
            &self.state
        }
        fn cf_state_mut(&mut self) -> &mut CfState {
            &mut self.state
        }
        fn send<'a>(&'a mut self, buf: &'a [u8], _eos: bool) -> BoxFuture<'a, Result<usize>> {
            let sent = self.sent.clone();
            let chunk = buf.to_vec();
            Box::pin(async move {
                sent.lock().unwrap().extend_from_slice(&chunk);
                Ok(chunk.len())
            })
        }
        fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
            let queue = self.recv_data.clone();
            Box::pin(async move {
                let mut guard = queue.lock().unwrap();
                let n = buf.len().min(guard.len());
                buf[..n].copy_from_slice(&guard[..n]);
                guard.drain(..n);
                Ok(n)
            })
        }
    }

    /// A [`WriteCallbacks`] sink that accumulates everything it is handed.
    #[derive(Default)]
    struct VecSink {
        body: Vec<u8>,
        headers: Vec<u8>,
    }

    impl WriteCallbacks for VecSink {
        fn write_body(&mut self, data: &[u8]) -> usize {
            self.body.extend_from_slice(data);
            data.len()
        }
        fn write_header(&mut self, data: &[u8]) -> Option<usize> {
            self.headers.extend_from_slice(data);
            Some(data.len())
        }
    }

    /// Build a [`Connection`] with a single scripted [`MockFilter`] installed as
    /// the (already-connected) bottom of the first socket's filter chain.
    fn make_conn(recv_data: Arc<Mutex<Vec<u8>>>, sent: Arc<Mutex<Vec<u8>>>) -> Connection {
        let scheme = &SCHEME_MQTT;
        let desc = SchemeDescriptor::new(
            scheme.name,
            scheme.default_port,
            scheme.flags,
            scheme.protocol,
        );
        let mut conn = Connection::new(
            format!("{}:{}", scheme.name, scheme.default_port),
            TRNSPRT_TCP,
            desc,
        );
        conn.cfilter[FIRSTSOCKET].add_filter(Box::new(MockFilter::new(recv_data, sent)));
        conn
    }

    /// A minimal CONNACK accepting the connection (remaining length 2, 0x0000).
    const CONNACK_OK: [u8; 4] = [0x20, 0x02, 0x00, 0x00];

    // ---- do_it: upload (PUBLISH) ------------------------------------------

    #[tokio::test]
    async fn do_it_upload_sends_connect_publish_disconnect() {
        let recv = Arc::new(Mutex::new(CONNACK_OK.to_vec()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv, sent.clone());

        let mut data = Easy::new();
        data.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some("mqtt://localhost/topic".to_string())),
        )
        .unwrap();
        data.set.copypostfields = Some(b"payload".to_vec());

        let proto = MqttProtocol::new(&SCHEME_MQTT);
        let xfer = proto.do_it(&mut data, &mut conn).await.expect("upload do_it");
        assert_eq!(xfer.direction, TransferDirection::Upload);

        let wire = sent.lock().unwrap().clone();
        // The first packet on the wire is a CONNECT.
        assert_eq!(wire[0], MQTT_MSG_CONNECT);
        // It ends with PUBLISH(topic, payload) immediately followed by DISCONNECT.
        let publish = build_publish_packet(b"topic", b"payload").unwrap();
        let tail = MQTT_DISCONNECT_PACKET.len();
        assert_eq!(&wire[wire.len() - tail..], &MQTT_DISCONNECT_PACKET);
        assert_eq!(
            &wire[wire.len() - tail - publish.len()..wire.len() - tail],
            &publish[..]
        );
    }

    // ---- do_it: download (SUBSCRIBE) --------------------------------------

    #[tokio::test]
    async fn do_it_download_sends_connect_subscribe() {
        let recv = Arc::new(Mutex::new(CONNACK_OK.to_vec()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv, sent.clone());

        let mut data = Easy::new();
        data.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some("mqtt://localhost/topic".to_string())),
        )
        .unwrap();

        let proto = MqttProtocol::new(&SCHEME_MQTT);
        let xfer = proto
            .do_it(&mut data, &mut conn)
            .await
            .expect("download do_it");
        assert_eq!(xfer.direction, TransferDirection::Download);

        let wire = sent.lock().unwrap().clone();
        assert_eq!(wire[0], MQTT_MSG_CONNECT);
        // It ends with a SUBSCRIBE for the topic at packet id 1.
        let subscribe = build_subscribe_packet(b"topic", 1);
        assert_eq!(&wire[wire.len() - subscribe.len()..], &subscribe[..]);
    }

    // ---- run_subscription: SUBACK → PUBLISH → DISCONNECT ------------------

    #[tokio::test]
    async fn run_subscription_streams_publish_body() {
        // Script the server side: SUBACK(id 1) → a PUBLISH → a DISCONNECT.
        let mut script = Vec::new();
        script.extend_from_slice(&[MQTT_MSG_SUBACK, 0x03, 0x00, 0x01, 0x00]); // SUBACK ok
        let publish = build_publish_packet(b"t", b"DATA").unwrap();
        script.extend_from_slice(&publish);
        script.extend_from_slice(&MQTT_DISCONNECT_PACKET);

        let recv = Arc::new(Mutex::new(script));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv, sent);

        let mut data = Easy::new();
        data.set.upkeep_interval_ms = 0; // disable the keep-alive timer for the test

        let proto = MqttProtocol::new(&SCHEME_MQTT);
        let mut writer = ClientWriter::new();
        let mut sink = VecSink::default();
        proto
            .run_subscription(&data, &mut conn, &mut writer, &mut sink, 1)
            .await
            .expect("run_subscription");

        // The body delivered to the client is the PUBLISH remaining bytes verbatim
        // (2-byte topic length + topic + payload) — curl streams the whole
        // remaining length as body, topic header included.
        assert_eq!(sink.body, vec![0x00, 0x01, b't', b'D', b'A', b'T', b'A']);
    }

    // ---- run_subscription: enforces max-filesize --------------------------

    #[tokio::test]
    async fn run_subscription_enforces_max_filesize() {
        // A PUBLISH whose remaining length (7) exceeds the configured limit (4).
        let publish = build_publish_packet(b"t", b"DATA").unwrap();
        let recv = Arc::new(Mutex::new(publish));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv, sent);

        let mut data = Easy::new();
        data.set.upkeep_interval_ms = 0;
        data.set.max_filesize = 4; // remaining length 7 > 4

        let proto = MqttProtocol::new(&SCHEME_MQTT);
        let mut writer = ClientWriter::new();
        let mut sink = VecSink::default();
        let result = proto
            .run_subscription(&data, &mut conn, &mut writer, &mut sink, 1)
            .await;
        assert!(matches!(result, Err(CurlError::FilesizeExceeded)));
    }
}
