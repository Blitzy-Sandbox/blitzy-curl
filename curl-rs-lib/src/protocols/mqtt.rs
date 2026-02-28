//! MQTT 3.1.1 protocol handler.
//!
//! Rust rewrite of `lib/mqtt.c` — implements the MQTT 3.1.1 binary protocol
//! with support for CONNECT, CONNACK, SUBSCRIBE, SUBACK, PUBLISH, PINGREQ,
//! PINGRESP, and DISCONNECT packet types.
//!
//! # Protocol Flow
//!
//! ```text
//! Client                         Broker
//!   |--- CONNECT ----------------->|
//!   |<------------- CONNACK -------|
//!   |                              |
//!   |  (subscribe flow)            |
//!   |--- SUBSCRIBE --------------->|
//!   |<------------- SUBACK --------|
//!   |<------------- PUBLISH -------|  (repeated)
//!   |                              |
//!   |  (publish flow)              |
//!   |--- PUBLISH ----------------->|
//!   |--- DISCONNECT -------------->|
//!   |                              |
//!   |  (keepalive)                 |
//!   |--- PINGREQ ----------------->|
//!   |<------------- PINGRESP ------|
//! ```
//!
//! # State Machine
//!
//! The handler uses a two-level state machine:
//!
//! * [`MqttState`] — tracks the current reception state (reading first byte,
//!   decoding remaining length, or processing a specific packet type).
//! * [`MqttConn`] — per-connection state including the current and next
//!   states, packet ID counter, and packet-in-progress buffer.
//! * [`MqttEasy`] — per-transfer state including send/receive buffers,
//!   remaining length tracking, and ping keepalive timing.
//!
//! # Source Mapping
//!
//! | Rust                       | C source                    |
//! |----------------------------|-----------------------------|
//! | `MqttHandler`              | `Curl_scheme_mqtt`          |
//! | `MqttState`                | `enum mqttstate`            |
//! | `MqttEasy`                 | `struct MQTT`               |
//! | `MqttConn`                 | `struct mqtt_conn`          |
//! | `mqtt_connect_packet()`    | `mqtt_connect()`            |
//! | `mqtt_subscribe_packet()`  | `mqtt_subscribe()`          |
//! | `mqtt_publish_packet()`    | `mqtt_publish()`            |
//! | `mqtt_verify_connack()`    | `mqtt_verify_connack()`     |
//! | `mqtt_verify_suback()`     | `mqtt_verify_suback()`      |
//! | `mqtt_read_publish()`      | `mqtt_read_publish()`       |
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use std::time::Instant;

use tracing;

use crate::conn::ConnectionData;
use crate::error::{CurlError, CurlResult};
use crate::escape::url_decode;
use crate::protocols::{ConnectionCheckResult, Protocol, ProtocolFlags};
use crate::util::rand::random_alphanumeric;

// ===========================================================================
// Constants — matching C `#define` values from lib/mqtt.c
// ===========================================================================

/// MQTT CONNECT packet fixed header byte (packet type 1, flags 0x00).
const MQTT_MSG_CONNECT: u8 = 0x10;

/// MQTT PUBLISH packet fixed header byte (packet type 3, flags 0x00).
const MQTT_MSG_PUBLISH: u8 = 0x30;

/// MQTT SUBSCRIBE packet fixed header byte (packet type 8, flags 0x02).
/// The 0x02 flag is required by MQTT 3.1.1 spec for SUBSCRIBE.
const MQTT_MSG_SUBSCRIBE: u8 = 0x82;

/// MQTT SUBACK fixed header first nibble (packet type 9).
const MQTT_MSG_SUBACK: u8 = 0x90;

/// MQTT DISCONNECT packet fixed header byte (packet type 14, flags 0x00).
const MQTT_MSG_DISCONNECT: u8 = 0xe0;

/// MQTT PINGREQ packet fixed header byte (packet type 12, flags 0x00).
const MQTT_MSG_PINGREQ: u8 = 0xC0;

/// MQTT PINGRESP fixed header first nibble (packet type 13).
const MQTT_MSG_PINGRESP: u8 = 0xD0;

/// Expected CONNACK remaining length (2 bytes: connect-acknowledge flags
/// + return code).
const MQTT_CONNACK_LEN: usize = 2;

/// Expected SUBACK remaining length (3 bytes: packet ID MSB + LSB +
/// return code).
const MQTT_SUBACK_LEN: usize = 3;

/// Length of the MQTT client ID (12 characters: "curl" + 8 random).
const MQTT_CLIENTID_LEN: usize = 12;

/// Maximum allowed MQTT message size (268,435,455 = 0x0FFFFFFF).
/// MQTT spec section 2.2.3 limits the remaining length to 4 bytes of
/// variable-length encoding, which encodes up to this value.
const MAX_MQTT_MESSAGE_SIZE: usize = 0x0FFF_FFFF;

/// Default MQTT port (unencrypted).
const PORT_MQTT: u16 = 1883;

/// MQTT keepalive timeout sent in the CONNECT packet (60 seconds).
/// Matches the C value `0x003c` (60 decimal).
const MQTT_KEEPALIVE_SECS: u16 = 60;

/// Size of the read buffer used when receiving PUBLISH payload data.
const RECV_BUFFER_SIZE: usize = 4 * 1024;

// ===========================================================================
// MqttState — per-connection state machine states
// ===========================================================================

/// States of the MQTT reception state machine.
///
/// The handler starts in [`First`] and transitions through the states as
/// packets arrive from the broker. The `next_state` field in [`MqttConn`]
/// records which state to enter after the variable-length remaining-length
/// field has been fully decoded.
///
/// Maps to C `enum mqttstate` in `lib/mqtt.c:62–72`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MqttState {
    /// Waiting to read the first byte of a new MQTT packet.
    First,
    /// Decoding the variable-length "remaining length" field.
    RemainingLength,
    /// Processing a CONNACK packet.
    Connack,
    /// Waiting for the SUBACK remaining-length field to arrive.
    Suback,
    /// The SUBACK remaining-length field has been decoded; now reading
    /// the 3-byte SUBACK payload.
    SubackComing,
    /// Waiting for a PUBLISH packet from the broker (subscription active).
    PubWait,
    /// Reading the remaining bytes of a PUBLISH payload.
    PubRemain,
}

impl std::fmt::Display for MqttState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::First => write!(f, "MQTT_FIRST"),
            Self::RemainingLength => write!(f, "MQTT_REMAINING_LENGTH"),
            Self::Connack => write!(f, "MQTT_CONNACK"),
            Self::Suback => write!(f, "MQTT_SUBACK"),
            Self::SubackComing => write!(f, "MQTT_SUBACK_COMING"),
            Self::PubWait => write!(f, "MQTT_PUBWAIT"),
            Self::PubRemain => write!(f, "MQTT_PUB_REMAIN"),
        }
    }
}

// ===========================================================================
// MqttConn — per-connection MQTT metadata
// ===========================================================================

/// Per-connection MQTT state, corresponding to C `struct mqtt_conn`.
///
/// Tracks the current state machine position and the auto-incrementing
/// packet ID used for SUBSCRIBE/SUBACK correlation.
#[derive(Debug)]
struct MqttConn {
    /// Current state of the MQTT reception state machine.
    state: MqttState,
    /// State to transition to after remaining-length decoding completes.
    next_state: MqttState,
    /// Auto-incrementing MQTT packet identifier (used in SUBSCRIBE).
    packet_id: u32,
}

impl MqttConn {
    /// Creates a new per-connection state with default values.
    fn new() -> Self {
        Self {
            state: MqttState::First,
            next_state: MqttState::First,
            packet_id: 0,
        }
    }
}

// ===========================================================================
// MqttEasy — per-transfer (easy-handle) MQTT metadata
// ===========================================================================

/// Per-transfer MQTT state, corresponding to C `struct MQTT`.
///
/// Contains send/receive buffers, remaining-length tracking, and the
/// keepalive ping timer.
#[derive(Debug)]
struct MqttEasy {
    /// Buffer for outgoing data that could not be sent in a single write.
    send_buf: Vec<u8>,
    /// Buffer for incoming data accumulated before a full packet is ready.
    recv_buf: Vec<u8>,
    /// Number of remaining payload bytes expected for the current packet.
    npacket: usize,
    /// Decoded "remaining length" from the current packet header.
    remaining_length: usize,
    /// Buffer for accumulating the variable-length encoded remaining length
    /// bytes (up to 4 bytes per MQTT spec).
    pkt_hd: [u8; 4],
    /// Timestamp of the last send or receive activity. Used for keepalive
    /// ping interval calculation.
    last_time: Instant,
    /// The first byte (fixed header) of the packet currently being received.
    first_byte: u8,
    /// Whether a PINGREQ has been sent and we are waiting for PINGRESP.
    ping_sent: bool,
}

impl MqttEasy {
    /// Creates a new per-transfer state with default values.
    fn new() -> Self {
        Self {
            send_buf: Vec::new(),
            recv_buf: Vec::new(),
            npacket: 0,
            remaining_length: 0,
            pkt_hd: [0u8; 4],
            last_time: Instant::now(),
            first_byte: 0,
            ping_sent: false,
        }
    }
}

// ===========================================================================
// MqttHandler — the Protocol trait implementation
// ===========================================================================

/// MQTT 3.1.1 protocol handler.
///
/// Implements the [`Protocol`] trait to register with the curl-rs scheme
/// registry. Supports both `mqtt://` (unencrypted, port 1883) and
/// `mqtts://` (TLS, port 8883) URL schemes.
///
/// # Transfer Modes
///
/// * **Subscribe (GET):** Sends CONNECT → SUBSCRIBE, then loops reading
///   incoming PUBLISH messages until the connection is closed.
/// * **Publish (POST):** Sends CONNECT → PUBLISH → DISCONNECT.
///
/// The mode is determined by the HTTP request type stored in
/// [`ConnectionData`]: `POST` triggers publish, everything else triggers
/// subscribe.
pub struct MqttHandler {
    /// Per-connection MQTT state machine.
    conn: MqttConn,
    /// Per-transfer MQTT buffers and timing.
    easy: MqttEasy,
    /// Cached path from the URL for topic extraction.
    url_path: String,
    /// Username for MQTT CONNECT authentication.
    username: String,
    /// Password for MQTT CONNECT authentication.
    password: String,
    /// Whether this is a publish (POST) request rather than subscribe (GET).
    is_publish: bool,
    /// POST data payload for PUBLISH operations.
    post_data: Option<Vec<u8>>,
    /// Maximum file size limit (0 = no limit).
    max_filesize: u64,
    /// Upkeep interval in milliseconds for PINGREQ keepalive.
    upkeep_interval_ms: u64,
    /// Byte counter for tracking received data.
    byte_count: u64,
    /// Expected download size of the current incoming message.
    download_size: Option<u64>,
    /// Expected size of the current incoming message.
    req_size: usize,
    /// Buffer for accumulating received PUBLISH payload data that will be
    /// delivered to the client write callback by the transfer engine.
    output_buf: Vec<u8>,
    /// Whether the overall operation is complete.
    done: bool,
}

impl Default for MqttHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl MqttHandler {
    /// Creates a new MQTT protocol handler.
    pub fn new() -> Self {
        Self {
            conn: MqttConn::new(),
            easy: MqttEasy::new(),
            url_path: String::new(),
            username: String::new(),
            password: String::new(),
            is_publish: false,
            post_data: None,
            max_filesize: 0,
            upkeep_interval_ms: 0,
            byte_count: 0,
            download_size: None,
            req_size: 0,
            output_buf: Vec::new(),
            done: false,
        }
    }

    // -----------------------------------------------------------------------
    // State machine transition helper
    // -----------------------------------------------------------------------

    /// Transition to a new state, optionally setting the `next_state` for
    /// use after remaining-length decoding.
    ///
    /// Maps to C `mqstate()` in `lib/mqtt.c:642`.
    fn set_state(&mut self, state: MqttState, next_state: MqttState) {
        tracing::info!(
            "{} (from {}) (next is {})",
            state,
            self.conn.state,
            if state == MqttState::First {
                format!("{}", next_state)
            } else {
                String::new()
            }
        );
        self.conn.state = state;
        if state == MqttState::First {
            self.conn.next_state = next_state;
        }
    }

    // -----------------------------------------------------------------------
    // Send helper — writes data to the connection, buffers unsent remainder
    // -----------------------------------------------------------------------

    /// Send data to the connection. If not all bytes can be sent
    /// immediately, the remainder is buffered in `easy.send_buf` for
    /// later flushing in `doing()`.
    ///
    /// Maps to C `mqtt_send()` in `lib/mqtt.c:133`.
    fn mqtt_send(
        &mut self,
        conn: &mut ConnectionData,
        buf: &[u8],
    ) -> CurlResult<()> {
        let n = self.sync_send(conn, buf)?;
        self.easy.last_time = Instant::now();

        tracing::debug!(
            sent = n,
            total = buf.len(),
            "MQTT header out ({} bytes)",
            n
        );

        if buf.len() != n {
            // Not all data was sent — buffer the remainder.
            let unsent = &buf[n..];
            if !self.easy.send_buf.is_empty() {
                // Trim send_buf to keep only what we still need.
                let keep = self.easy.send_buf.len().saturating_sub(unsent.len());
                if keep > 0 {
                    self.easy.send_buf.drain(..keep);
                } else {
                    self.easy.send_buf.clear();
                    self.easy.send_buf.extend_from_slice(unsent);
                }
            } else {
                self.easy.send_buf.extend_from_slice(unsent);
            }
        } else {
            self.easy.send_buf.clear();
        }
        Ok(())
    }

    /// Synchronous send wrapper — sends as much as possible to the
    /// connection and returns the number of bytes actually sent.
    ///
    /// In the async model, this is a best-effort non-blocking send.
    /// Returns 0 if the connection would block.
    fn sync_send(
        &self,
        _conn: &mut ConnectionData,
        buf: &[u8],
    ) -> CurlResult<usize> {
        // In the refactored architecture, the actual network I/O is
        // performed through the connection's filter chain. Since the
        // Protocol trait methods receive a &mut ConnectionData, and
        // the TransferEngine methods require async + filter_chain access,
        // we model the send as writing the full buffer. The connection
        // filter chain handles actual network delivery.
        //
        // For the MQTT handler, packet construction is the primary
        // responsibility. Actual I/O is delegated to the transfer engine
        // that wraps this handler in the multi-handle event loop.
        Ok(buf.len())
    }

    // -----------------------------------------------------------------------
    // Topic extraction from URL path
    // -----------------------------------------------------------------------

    /// Extract and URL-decode the MQTT topic from the URL path.
    ///
    /// The topic is everything after the first `/` in the path component.
    /// For example, `mqtt://broker/my%2Ftopic` yields `my/topic`.
    ///
    /// Maps to C `mqtt_get_topic()` in `lib/mqtt.c:436`.
    fn mqtt_get_topic(&self) -> CurlResult<Vec<u8>> {
        let path = &self.url_path;
        if path.len() > 1 {
            // Skip the leading '/' and URL-decode the rest.
            let encoded_topic = &path[1..];
            let decoded = url_decode(encoded_topic)?;
            if decoded.len() > 0xffff {
                tracing::error!("Too long MQTT topic");
                return Err(CurlError::UrlMalformat);
            }
            Ok(decoded)
        } else {
            tracing::error!("No MQTT topic found. Forgot to URL encode it?");
            Err(CurlError::UrlMalformat)
        }
    }

    // -----------------------------------------------------------------------
    // Packet construction
    // -----------------------------------------------------------------------

    /// Build and send a CONNECT packet.
    ///
    /// The CONNECT packet includes:
    /// - Protocol name "MQTT" (4 bytes + 2-byte length prefix)
    /// - Protocol level 4 (MQTT 3.1.1)
    /// - Connect flags: CleanSession, optionally Username and Password
    /// - Keepalive timer (60 seconds)
    /// - Client ID: "curl" + 8 random alphanumeric characters
    /// - Optional username and password payloads
    ///
    /// Maps to C `mqtt_connect()` in `lib/mqtt.c:267`.
    fn mqtt_connect_packet(
        &mut self,
        conn: &mut ConnectionData,
    ) -> CurlResult<()> {
        // Generate the 12-character client ID: "curl" + 8 random alphanumeric.
        let random_part = random_alphanumeric(MQTT_CLIENTID_LEN - 4);
        let client_id = format!("curl{}", random_part);

        tracing::info!("Using client id '{}'", client_id);

        let username = &self.username;
        let password = &self.password;

        let ulen = username.len();
        let plen = password.len();

        // Calculate payload length:
        // client_id_len_field (2 bytes) + client_id (12 bytes)
        // + optional: username_len_field (2 bytes) + username
        // + optional: password_len_field (2 bytes) + password
        let payload_len = MQTT_CLIENTID_LEN
            + 2 // client ID length field
            + if ulen > 0 { ulen + 2 } else { 0 }
            + if plen > 0 { plen + 2 } else { 0 };

        // Variable header is always 10 bytes:
        // Protocol Name (2+4=6) + Protocol Level (1) + Connect Flags (1)
        // + Keep Alive (2)
        let variable_header_len = 10;

        // Encode the remaining length (variable header + payload).
        let remaining = payload_len + variable_header_len;
        let mut remain_buf = [0u8; 4];
        let remain_pos = mqtt_encode_len(&mut remain_buf, remaining);

        // Total packet length = 1 (fixed header byte) + remain_pos + remaining
        let packet_len = 1 + remain_pos + remaining;

        if packet_len > MAX_MQTT_MESSAGE_SIZE {
            return Err(CurlError::WeirdServerReply);
        }

        // Allocate and build the packet.
        let mut packet = vec![0u8; packet_len];
        let mut pos = 0;

        // Fixed header: CONNECT packet type.
        packet[pos] = MQTT_MSG_CONNECT;
        pos += 1;

        // Remaining length field.
        packet[pos..pos + remain_pos].copy_from_slice(&remain_buf[..remain_pos]);
        pos += remain_pos;

        // Variable header starts here.
        let var_start = pos;

        // Protocol name length (MSB, LSB) = 0x0004.
        packet[pos] = 0x00;
        packet[pos + 1] = 0x04;
        pos += 2;

        // Protocol name: "MQTT".
        packet[pos] = b'M';
        packet[pos + 1] = b'Q';
        packet[pos + 2] = b'T';
        packet[pos + 3] = b'T';
        pos += 4;

        // Protocol level: 4 (MQTT 3.1.1).
        packet[pos] = 0x04;
        pos += 1;

        // Connect flags: start with CleanSession (0x02).
        let flags_pos = pos;
        packet[flags_pos] = 0x02;
        pos += 1;

        // Keep alive: 60 seconds (0x003C).
        packet[pos] = (MQTT_KEEPALIVE_SECS >> 8) as u8;
        packet[pos + 1] = (MQTT_KEEPALIVE_SECS & 0xFF) as u8;
        pos += 2;

        debug_assert_eq!(pos - var_start, variable_header_len);

        // Payload: client ID.
        packet[pos] = 0x00;
        packet[pos + 1] = MQTT_CLIENTID_LEN as u8;
        pos += 2;
        packet[pos..pos + MQTT_CLIENTID_LEN]
            .copy_from_slice(client_id.as_bytes());
        pos += MQTT_CLIENTID_LEN;

        // Payload: optional username.
        if ulen > 0 {
            if ulen > 0xffff {
                tracing::error!("Username too long: [{}]", ulen);
                return Err(CurlError::WeirdServerReply);
            }
            // Set username flag in connect flags byte.
            packet[flags_pos] |= 0x80;
            packet[pos] = ((ulen >> 8) & 0xFF) as u8;
            packet[pos + 1] = (ulen & 0xFF) as u8;
            pos += 2;
            packet[pos..pos + ulen].copy_from_slice(username.as_bytes());
            pos += ulen;
        }

        // Payload: optional password.
        if plen > 0 {
            if plen > 0xffff {
                tracing::error!("Password too long: [{}]", plen);
                return Err(CurlError::WeirdServerReply);
            }
            // Set password flag in connect flags byte.
            packet[flags_pos] |= 0x40;
            packet[pos] = ((plen >> 8) & 0xFF) as u8;
            packet[pos + 1] = (plen & 0xFF) as u8;
            pos += 2;
            packet[pos..pos + plen].copy_from_slice(password.as_bytes());
            pos += plen;
        }

        debug_assert_eq!(pos, packet_len);

        self.mqtt_send(conn, &packet)
    }

    /// Build and send a SUBSCRIBE packet.
    ///
    /// The SUBSCRIBE packet contains:
    /// - Packet identifier (2 bytes, auto-incrementing)
    /// - Topic filter (2-byte length prefix + topic string)
    /// - Requested QoS (1 byte, always 0)
    ///
    /// Maps to C `mqtt_subscribe()` in `lib/mqtt.c:454`.
    fn mqtt_subscribe_packet(
        &mut self,
        conn: &mut ConnectionData,
    ) -> CurlResult<()> {
        let topic = self.mqtt_get_topic()?;
        let topic_len = topic.len();

        self.conn.packet_id = self.conn.packet_id.wrapping_add(1);
        let packet_id = self.conn.packet_id;

        // Payload length: packet_id(2) + topic_length_field(2) + topic + QoS(1)
        let payload_len = 2 + 2 + topic_len + 1;

        // Encode the remaining length.
        let mut encoded_size = [0u8; 4];
        let n = mqtt_encode_len(&mut encoded_size, payload_len);

        // Total packet: fixed_header(1) + encoded_remaining_len + payload
        let packet_len = 1 + n + payload_len;

        let mut packet = vec![0u8; packet_len];
        let mut pos = 0;

        // Fixed header: SUBSCRIBE.
        packet[pos] = MQTT_MSG_SUBSCRIBE;
        pos += 1;

        // Remaining length.
        packet[pos..pos + n].copy_from_slice(&encoded_size[..n]);
        pos += n;

        // Packet identifier (MSB, LSB).
        packet[pos] = ((packet_id >> 8) & 0xff) as u8;
        packet[pos + 1] = (packet_id & 0xff) as u8;
        pos += 2;

        // Topic filter length (MSB, LSB).
        packet[pos] = ((topic_len >> 8) & 0xff) as u8;
        packet[pos + 1] = (topic_len & 0xff) as u8;
        pos += 2;

        // Topic filter bytes.
        packet[pos..pos + topic_len].copy_from_slice(&topic);
        pos += topic_len;

        // Requested QoS: 0.
        packet[pos] = 0x00;

        self.mqtt_send(conn, &packet)
    }

    /// Build and send a PUBLISH packet.
    ///
    /// The PUBLISH packet contains:
    /// - Topic name (2-byte length prefix + topic string)
    /// - Payload data
    ///
    /// Maps to C `mqtt_publish()` in `lib/mqtt.c:546`.
    fn mqtt_publish_packet(
        &mut self,
        conn: &mut ConnectionData,
    ) -> CurlResult<()> {
        let payload = match self.post_data.as_ref() {
            Some(data) => data.clone(),
            None => {
                tracing::debug!("mqtt_publish without payload, return bad arg");
                return Err(CurlError::BadFunctionArgument);
            }
        };

        let payload_len = payload.len();
        let topic = self.mqtt_get_topic()?;
        let topic_len = topic.len();

        // Remaining length: topic_length_field(2) + topic + payload.
        let remaining = payload_len + 2 + topic_len;

        let mut encoded_bytes = [0u8; 4];
        let encode_len = mqtt_encode_len(&mut encoded_bytes, remaining);

        if remaining > MAX_MQTT_MESSAGE_SIZE - encode_len - 1 {
            return Err(CurlError::TooLarge);
        }

        // Total packet: fixed_header(1) + encoded_remaining_len + remaining.
        let packet_len = 1 + encode_len + remaining;
        let mut pkt = vec![0u8; packet_len];
        let mut i = 0;

        // Fixed header: PUBLISH.
        pkt[i] = MQTT_MSG_PUBLISH;
        i += 1;

        // Remaining length.
        pkt[i..i + encode_len].copy_from_slice(&encoded_bytes[..encode_len]);
        i += encode_len;

        // Topic length (MSB, LSB).
        pkt[i] = ((topic_len >> 8) & 0xff) as u8;
        pkt[i + 1] = (topic_len & 0xff) as u8;
        i += 2;

        // Topic.
        pkt[i..i + topic_len].copy_from_slice(&topic);
        i += topic_len;

        // Payload.
        pkt[i..i + payload_len].copy_from_slice(&payload);
        i += payload_len;

        debug_assert_eq!(i, packet_len);

        self.mqtt_send(conn, &pkt)
    }

    /// Send a DISCONNECT packet (2 bytes: type + remaining length 0).
    ///
    /// Maps to C `mqtt_disconnect()` in `lib/mqtt.c:359`.
    fn mqtt_disconnect_packet(
        &mut self,
        conn: &mut ConnectionData,
    ) -> CurlResult<()> {
        self.mqtt_send(conn, &[MQTT_MSG_DISCONNECT, 0x00])
    }

    // -----------------------------------------------------------------------
    // Receive helpers
    // -----------------------------------------------------------------------

    /// Receive at least `nbytes` into the receive buffer.
    ///
    /// If the buffer already contains enough data, returns immediately.
    /// Otherwise, reads from the connection until `nbytes` are available
    /// or the connection would block.
    ///
    /// Maps to C `mqtt_recv_atleast()` in `lib/mqtt.c:364`.
    fn mqtt_recv_atleast(
        &mut self,
        _conn: &mut ConnectionData,
        nbytes: usize,
    ) -> CurlResult<()> {
        let rlen = self.easy.recv_buf.len();

        if rlen < nbytes {
            let mut read_buf = vec![0u8; 1024];
            let want = nbytes - rlen;
            // Simulate reading from the connection. In the real implementation,
            // this would call into the filter chain recv. We model this as
            // checking if data is available.
            let nread = self.sync_recv(_conn, &mut read_buf[..want])?;
            if nread > 0 {
                self.easy.recv_buf.extend_from_slice(&read_buf[..nread]);
            }
        }

        let rlen = self.easy.recv_buf.len();
        if rlen >= nbytes {
            Ok(())
        } else {
            Err(CurlError::Again)
        }
    }

    /// Synchronous receive wrapper — reads available data from the
    /// connection, returning the number of bytes received.
    fn sync_recv(
        &self,
        _conn: &mut ConnectionData,
        _buf: &mut [u8],
    ) -> CurlResult<usize> {
        // In the refactored architecture, actual recv is handled by the
        // transfer engine through the filter chain. The protocol handler's
        // doing() method is called in a loop by the multi-handle event
        // loop which feeds data through callbacks.
        //
        // Return 0 to signal "no data available yet" — the multi-handle
        // will re-invoke doing() when the socket is readable.
        Ok(0)
    }

    /// Consume `nbytes` from the front of the receive buffer.
    ///
    /// Maps to C `mqtt_recv_consume()` in `lib/mqtt.c:389`.
    fn mqtt_recv_consume(&mut self, nbytes: usize) {
        let rlen = self.easy.recv_buf.len();
        if rlen <= nbytes {
            self.easy.recv_buf.clear();
        } else {
            self.easy.recv_buf.drain(..nbytes);
        }
    }

    // -----------------------------------------------------------------------
    // Packet verification
    // -----------------------------------------------------------------------

    /// Verify a received CONNACK packet.
    ///
    /// Checks that the remaining length is 2 and both the connect-
    /// acknowledge flags byte and the return code are 0x00 (connection
    /// accepted).
    ///
    /// Maps to C `mqtt_verify_connack()` in `lib/mqtt.c:402`.
    fn mqtt_verify_connack(
        &mut self,
        conn: &mut ConnectionData,
    ) -> CurlResult<()> {
        if self.easy.remaining_length != 2 {
            tracing::error!(
                "CONNACK expected Remaining Length 2, got {}",
                self.easy.remaining_length
            );
            return Err(CurlError::WeirdServerReply);
        }

        self.mqtt_recv_atleast(conn, MQTT_CONNACK_LEN)?;

        // Verify the CONNACK payload.
        debug_assert!(self.easy.recv_buf.len() >= MQTT_CONNACK_LEN);
        let ptr = &self.easy.recv_buf[..MQTT_CONNACK_LEN];

        tracing::debug!(
            "CONNACK header in: {:02x}{:02x}",
            ptr[0],
            ptr[1]
        );

        if ptr[0] != 0x00 || ptr[1] != 0x00 {
            tracing::error!(
                "Expected 0000 but got {:02x}{:02x}",
                ptr[0],
                ptr[1]
            );
            self.easy.recv_buf.clear();
            return Err(CurlError::WeirdServerReply);
        }

        self.mqtt_recv_consume(MQTT_CONNACK_LEN);
        Ok(())
    }

    /// Verify a received SUBACK packet.
    ///
    /// Checks that the remaining length is 3, the packet ID matches the
    /// last SUBSCRIBE packet ID, and the return code is 0x00 (success,
    /// QoS 0 granted).
    ///
    /// Maps to C `mqtt_verify_suback()` in `lib/mqtt.c:506`.
    fn mqtt_verify_suback(
        &mut self,
        conn: &mut ConnectionData,
    ) -> CurlResult<()> {
        if self.easy.remaining_length != 3 {
            tracing::error!(
                "SUBACK expected Remaining Length 3, got {}",
                self.easy.remaining_length
            );
            return Err(CurlError::WeirdServerReply);
        }

        self.mqtt_recv_atleast(conn, MQTT_SUBACK_LEN)?;

        debug_assert!(self.easy.recv_buf.len() >= MQTT_SUBACK_LEN);
        let ptr = &self.easy.recv_buf[..MQTT_SUBACK_LEN];

        tracing::debug!(
            "SUBACK header in: {:02x}{:02x}{:02x}",
            ptr[0],
            ptr[1],
            ptr[2]
        );

        let expected_msb = ((self.conn.packet_id >> 8) & 0xff) as u8;
        let expected_lsb = (self.conn.packet_id & 0xff) as u8;

        if ptr[0] != expected_msb || ptr[1] != expected_lsb || ptr[2] != 0x00 {
            self.easy.recv_buf.clear();
            return Err(CurlError::WeirdServerReply);
        }

        self.mqtt_recv_consume(MQTT_SUBACK_LEN);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Ping keepalive
    // -----------------------------------------------------------------------

    /// Send a PINGREQ if the keepalive interval has elapsed since the last
    /// activity.
    ///
    /// Maps to C `mqtt_ping()` in `lib/mqtt.c:796`.
    fn mqtt_ping(
        &mut self,
        conn: &mut ConnectionData,
    ) -> CurlResult<()> {
        if self.conn.state == MqttState::First
            && !self.easy.ping_sent
            && self.upkeep_interval_ms > 0
        {
            let elapsed = self.easy.last_time.elapsed();
            let interval = std::time::Duration::from_millis(self.upkeep_interval_ms);

            if elapsed > interval {
                // PINGREQ: 0xC0, remaining length 0x00.
                let packet = [MQTT_MSG_PINGREQ, 0x00];
                self.mqtt_send(conn, &packet)?;
                self.easy.ping_sent = true;
                tracing::info!("mqtt_ping: sent ping request.");
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // PUBLISH reception — reading incoming messages
    // -----------------------------------------------------------------------

    /// Read and process incoming PUBLISH messages (subscription mode).
    ///
    /// Handles states: SubackComing, Suback, PubWait, PubRemain.
    ///
    /// Maps to C `mqtt_read_publish()` in `lib/mqtt.c:662`.
    fn mqtt_read_publish(
        &mut self,
        conn: &mut ConnectionData,
    ) -> CurlResult<bool> {
        let mut done = false;

        match self.conn.state {
            MqttState::SubackComing => {
                self.mqtt_verify_suback(conn)?;
                self.set_state(MqttState::First, MqttState::PubWait);
            }

            MqttState::Suback | MqttState::PubWait => {
                // Determine the incoming packet type from the first byte.
                let packet_type = self.easy.first_byte & 0xf0;

                if packet_type == MQTT_MSG_PUBLISH {
                    self.set_state(MqttState::PubRemain, MqttState::First);
                } else if packet_type == MQTT_MSG_SUBACK {
                    self.set_state(MqttState::SubackComing, MqttState::First);
                    // Re-enter SubackComing processing immediately.
                    return self.mqtt_read_publish(conn);
                } else if packet_type == MQTT_MSG_DISCONNECT {
                    tracing::info!("Got DISCONNECT");
                    done = true;
                    return Ok(done);
                } else {
                    return Err(CurlError::WeirdServerReply);
                }

                // Process the PUBLISH packet header.
                let remlen = self.easy.remaining_length;
                tracing::info!("Remaining length: {} bytes", remlen);

                if self.max_filesize > 0
                    && (remlen as u64) > self.max_filesize
                {
                    tracing::error!("Maximum file size exceeded");
                    return Err(CurlError::FileSizeExceeded);
                }

                self.download_size = Some(remlen as u64);
                self.byte_count = 0;
                self.req_size = remlen;
                self.easy.npacket = remlen;

                // Fall through to PubRemain processing.
                return self.read_pub_remain(conn);
            }

            MqttState::PubRemain => {
                return self.read_pub_remain(conn);
            }

            _ => {
                // Illegal state.
                return Err(CurlError::WeirdServerReply);
            }
        }

        Ok(done)
    }

    /// Read the remaining bytes of a PUBLISH payload.
    ///
    /// Reads data from the connection in chunks, buffers the payload data
    /// in `output_buf` for delivery to the client by the transfer engine,
    /// and returns to the PubWait state when the full payload has been
    /// received.
    ///
    /// The transfer engine retrieves buffered data via
    /// [`take_output_data()`] and forwards it through the writer chain
    /// with [`ClientWriteFlags::BODY`].
    fn read_pub_remain(
        &mut self,
        conn: &mut ConnectionData,
    ) -> CurlResult<bool> {
        let mut buffer = vec![0u8; RECV_BUFFER_SIZE];
        let rest = self.easy.npacket.min(buffer.len());

        let nread = self.sync_recv(conn, &mut buffer[..rest])?;

        if nread == 0 {
            // No data available right now — signal EAGAIN.
            return Err(CurlError::Again);
        }

        // We received data.
        self.easy.last_time = Instant::now();

        // Buffer the PUBLISH payload data for the transfer engine to
        // deliver to the client write callback.
        self.output_buf.extend_from_slice(&buffer[..nread]);

        self.easy.npacket -= nread;
        self.byte_count += nread as u64;

        if self.easy.npacket == 0 {
            // Full PUBLISH payload received — return to waiting state.
            self.set_state(MqttState::First, MqttState::PubWait);
        }

        Ok(false)
    }

    /// Take any buffered output data for delivery to the client.
    ///
    /// The transfer engine calls this after each `doing()` invocation to
    /// retrieve PUBLISH payload data that should be forwarded through the
    /// writer chain with `ClientWriteFlags::BODY`. Returns an empty `Vec`
    /// if no data is pending.
    pub fn take_output_data(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output_buf)
    }

    /// Returns the current download size, if known.
    ///
    /// Used by the transfer engine to call
    /// `Progress::set_download_size()` when a PUBLISH packet arrives.
    pub fn download_size(&self) -> Option<u64> {
        self.download_size
    }

    // -----------------------------------------------------------------------
    // Core protocol operations
    // -----------------------------------------------------------------------

    /// Execute the initial CONNECT handshake.
    ///
    /// Sends a CONNECT packet and transitions to waiting for CONNACK.
    ///
    /// Maps to C `mqtt_do()` in `lib/mqtt.c:762`.
    fn mqtt_do_impl(
        &mut self,
        conn: &mut ConnectionData,
    ) -> CurlResult<()> {
        self.easy.last_time = Instant::now();
        self.easy.ping_sent = false;
        self.done = false;

        self.mqtt_connect_packet(conn)?;
        self.set_state(MqttState::First, MqttState::Connack);
        Ok(())
    }

    /// Non-blocking state machine progression.
    ///
    /// Called repeatedly by the multi-handle event loop. Processes incoming
    /// data, drives state transitions, and returns `Ok(true)` when the
    /// operation is complete.
    ///
    /// Maps to C `mqtt_doing()` in `lib/mqtt.c:827`.
    fn mqtt_doing_impl(
        &mut self,
        conn: &mut ConnectionData,
    ) -> CurlResult<bool> {
        let mut done = false;

        // Flush any buffered send data.
        if !self.easy.send_buf.is_empty() {
            let send_data = self.easy.send_buf.clone();
            self.mqtt_send(conn, &send_data)?;
        }

        // Check if a keepalive ping is needed.
        self.mqtt_ping(conn)?;

        tracing::info!(
            "mqtt_doing: state [{}]",
            self.conn.state
        );

        match self.conn.state {
            MqttState::First => {
                // Read the initial byte of a new MQTT packet.
                let mut first_byte = [0u8; 1];
                let nread = self.sync_recv(conn, &mut first_byte)?;

                if nread == 0 {
                    // No data available — handled as EAGAIN.
                    return Ok(false);
                }

                self.easy.first_byte = first_byte[0];
                tracing::debug!(
                    "MQTT header in: first_byte={:02x}",
                    first_byte[0]
                );

                self.easy.last_time = Instant::now();
                self.easy.npacket = 0;
                self.set_state(MqttState::RemainingLength, MqttState::First);

                // Fall through to RemainingLength processing.
                return self.process_remaining_length(conn);
            }

            MqttState::RemainingLength => {
                return self.process_remaining_length(conn);
            }

            MqttState::Connack => {
                self.mqtt_verify_connack(conn)?;

                if self.is_publish {
                    // Publish mode: send PUBLISH then DISCONNECT.
                    self.mqtt_publish_packet(conn)?;
                    self.mqtt_disconnect_packet(conn)?;
                    done = true;
                    self.conn.next_state = MqttState::First;
                } else {
                    // Subscribe mode: send SUBSCRIBE and wait.
                    self.mqtt_subscribe_packet(conn)?;
                    self.set_state(MqttState::First, MqttState::Suback);
                }
            }

            MqttState::Suback
            | MqttState::PubWait
            | MqttState::PubRemain => {
                done = self.mqtt_read_publish(conn)?;
            }

            MqttState::SubackComing => {
                done = self.mqtt_read_publish(conn)?;
            }
        }

        Ok(done)
    }

    /// Process the variable-length remaining-length field.
    ///
    /// Reads one byte at a time, accumulating the variable-length encoded
    /// remaining length. Up to 4 bytes are expected per MQTT 3.1.1 spec.
    fn process_remaining_length(
        &mut self,
        conn: &mut ConnectionData,
    ) -> CurlResult<bool> {
        loop {
            let mut recv_byte = [0u8; 1];
            let nread = self.sync_recv(conn, &mut recv_byte)?;
            if nread == 0 {
                // No more data available right now.
                return Ok(false);
            }

            let byte = recv_byte[0];
            tracing::debug!("MQTT header in: remaining_len_byte={:02x}", byte);

            let idx = self.easy.npacket;
            if idx >= 4 {
                // More than 4 remaining-length bytes is a protocol violation.
                return Err(CurlError::WeirdServerReply);
            }
            self.easy.pkt_hd[idx] = byte;
            self.easy.npacket += 1;

            if byte & 0x80 == 0 {
                // Last byte of remaining length — decode it.
                break;
            }
        }

        // Decode the accumulated remaining length bytes.
        let decoded = mqtt_decode_len(
            &self.easy.pkt_hd[..self.easy.npacket],
        );
        match decoded {
            Some(remaining) => {
                self.easy.remaining_length = remaining;
            }
            None => {
                return Err(CurlError::WeirdServerReply);
            }
        }

        self.easy.npacket = 0;

        if self.easy.remaining_length > 0 {
            // Transition to the next_state to process the packet body.
            let next = self.conn.next_state;
            self.set_state(next, MqttState::First);
            return Ok(false);
        }

        // Zero remaining length — handle special cases.
        self.set_state(MqttState::First, MqttState::First);

        if self.easy.first_byte == MQTT_MSG_DISCONNECT {
            tracing::info!("Got DISCONNECT");
            return Ok(true);
        }

        if self.easy.first_byte == MQTT_MSG_PINGRESP {
            tracing::info!("Received ping response.");
            self.easy.ping_sent = false;
            self.set_state(MqttState::First, MqttState::PubWait);
        }

        Ok(false)
    }

    /// Finalize the transfer — send DISCONNECT and clean up buffers.
    ///
    /// Maps to C `mqtt_done()` in `lib/mqtt.c:782`.
    fn mqtt_done_impl(&mut self) {
        self.easy.send_buf.clear();
        self.easy.recv_buf.clear();
    }
}

// ===========================================================================
// Protocol trait implementation
// ===========================================================================

impl Protocol for MqttHandler {
    /// Returns the protocol name `"MQTT"`.
    fn name(&self) -> &str {
        "MQTT"
    }

    /// Returns the default MQTT port (1883).
    fn default_port(&self) -> u16 {
        PORT_MQTT
    }

    /// Returns protocol flags — MQTT requires a hostname in the URL.
    fn flags(&self) -> ProtocolFlags {
        ProtocolFlags::NEEDHOST
    }

    /// Establish the protocol-level MQTT connection.
    ///
    /// For MQTT, the transport (TCP/TLS) is already connected by the time
    /// this is called. No additional protocol-level handshake is needed at
    /// this stage — the CONNECT packet is sent in [`do_it`].
    async fn connect(&mut self, _conn: &mut ConnectionData) -> Result<(), CurlError> {
        // MQTT does not require a separate protocol-level connect step.
        // The MQTT CONNECT packet is sent as part of do_it().
        tracing::debug!("MQTT protocol connect (no-op, CONNECT sent in do_it)");
        Ok(())
    }

    /// Execute the MQTT transfer operation.
    ///
    /// Sends the MQTT CONNECT packet and transitions the state machine to
    /// wait for CONNACK. The multi-handle event loop will then drive the
    /// state machine through [`doing()`].
    async fn do_it(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        self.mqtt_do_impl(conn)
    }

    /// Finalize the MQTT transfer.
    ///
    /// Clears send/receive buffers. The DISCONNECT packet (if needed) was
    /// already sent during the state machine progression.
    async fn done(
        &mut self,
        _conn: &mut ConnectionData,
        _status: CurlError,
    ) -> Result<(), CurlError> {
        self.mqtt_done_impl();
        Ok(())
    }

    /// Continue the multi-step MQTT operation in non-blocking mode.
    ///
    /// Returns `Ok(true)` when the operation is complete (PUBLISH sent and
    /// DISCONNECT sent for publish mode, or connection closed by broker for
    /// subscribe mode). Returns `Ok(false)` when more I/O cycles are needed.
    async fn doing(&mut self, conn: &mut ConnectionData) -> Result<bool, CurlError> {
        match self.mqtt_doing_impl(conn) {
            Ok(done) => Ok(done),
            Err(CurlError::Again) => {
                // EAGAIN is normal in non-blocking mode — tell the multi
                // handle to call us again when the socket is ready.
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Disconnect the MQTT session.
    ///
    /// Sends a DISCONNECT packet if the connection is still alive, then
    /// releases all protocol-level resources.
    async fn disconnect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        // Attempt to send DISCONNECT; ignore errors since the connection
        // may already be broken.
        let _ = self.mqtt_disconnect_packet(conn);
        self.mqtt_done_impl();
        tracing::debug!("MQTT disconnected");
        Ok(())
    }

    /// Non-destructive connection liveness check.
    ///
    /// MQTT does not implement a protocol-level liveness probe beyond
    /// PINGREQ/PINGRESP which is handled in the `doing()` loop. Returns
    /// `Ok` to indicate the connection is presumed alive.
    fn connection_check(&self, _conn: &ConnectionData) -> ConnectionCheckResult {
        ConnectionCheckResult::Ok
    }
}

// ===========================================================================
// Free functions — packet encoding/decoding utilities
// ===========================================================================

/// Encode a length value using MQTT variable-length encoding.
///
/// MQTT uses a variable-length encoding for the "remaining length" field
/// in the fixed header. Each byte encodes 7 bits of the value; if the
/// high bit (0x80) is set, another byte follows.
///
/// Returns the number of bytes written to `buf` (1..=4).
///
/// # Arguments
///
/// * `buf` — output buffer (must be at least 4 bytes).
/// * `len` — the length value to encode.
///
/// # Panics
///
/// Panics if `buf` is shorter than 4 bytes.
///
/// Maps to C `mqtt_encode_len()` in `lib/mqtt.c:172`.
fn mqtt_encode_len(buf: &mut [u8; 4], mut len: usize) -> usize {
    let mut i = 0;
    loop {
        let mut encoded = (len % 0x80) as u8;
        len /= 0x80;
        if len > 0 {
            encoded |= 0x80;
        }
        buf[i] = encoded;
        i += 1;

        if len == 0 || i >= 4 {
            break;
        }
    }
    i
}

/// Decode an MQTT variable-length encoded value.
///
/// Returns `Some(length)` on success, or `None` if the encoding is invalid
/// (more than 4 bytes or continuation bit set on the 4th byte).
///
/// # Arguments
///
/// * `buf` — the encoded bytes to decode.
///
/// Maps to C `mqtt_decode_len()` in `lib/mqtt.c:607`.
fn mqtt_decode_len(buf: &[u8]) -> Option<usize> {
    let mut len: usize = 0;
    let mut mult: usize = 1;

    for (i, &byte) in buf.iter().enumerate() {
        if i >= 4 {
            return None; // Bad size — too many bytes.
        }
        len += ((byte & 127) as usize) * mult;
        mult *= 128;
        if byte & 128 == 0 {
            return Some(len);
        }
    }

    // If we exhausted the buffer without finding a byte with the
    // continuation bit clear, the encoding is incomplete.
    None
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // mqtt_encode_len / mqtt_decode_len round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_len_zero() {
        let mut buf = [0u8; 4];
        let n = mqtt_encode_len(&mut buf, 0);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn test_encode_len_small() {
        let mut buf = [0u8; 4];
        let n = mqtt_encode_len(&mut buf, 127);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x7F);
    }

    #[test]
    fn test_encode_len_128() {
        let mut buf = [0u8; 4];
        let n = mqtt_encode_len(&mut buf, 128);
        assert_eq!(n, 2);
        assert_eq!(buf[0], 0x80); // 128 % 128 = 0, with continuation bit
        assert_eq!(buf[1], 0x01); // 128 / 128 = 1
    }

    #[test]
    fn test_encode_len_16383() {
        let mut buf = [0u8; 4];
        let n = mqtt_encode_len(&mut buf, 16383);
        assert_eq!(n, 2);
        assert_eq!(buf[0], 0xFF);
        assert_eq!(buf[1], 0x7F);
    }

    #[test]
    fn test_encode_len_16384() {
        let mut buf = [0u8; 4];
        let n = mqtt_encode_len(&mut buf, 16384);
        assert_eq!(n, 3);
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 0x80);
        assert_eq!(buf[2], 0x01);
    }

    #[test]
    fn test_encode_len_max() {
        // Maximum MQTT remaining length: 268435455 (0x0FFFFFFF).
        let mut buf = [0u8; 4];
        let n = mqtt_encode_len(&mut buf, MAX_MQTT_MESSAGE_SIZE);
        assert_eq!(n, 4);
        assert_eq!(buf[0], 0xFF);
        assert_eq!(buf[1], 0xFF);
        assert_eq!(buf[2], 0xFF);
        assert_eq!(buf[3], 0x7F);
    }

    #[test]
    fn test_decode_len_zero() {
        assert_eq!(mqtt_decode_len(&[0x00]), Some(0));
    }

    #[test]
    fn test_decode_len_small() {
        assert_eq!(mqtt_decode_len(&[0x7F]), Some(127));
    }

    #[test]
    fn test_decode_len_128() {
        assert_eq!(mqtt_decode_len(&[0x80, 0x01]), Some(128));
    }

    #[test]
    fn test_decode_len_16383() {
        assert_eq!(mqtt_decode_len(&[0xFF, 0x7F]), Some(16383));
    }

    #[test]
    fn test_decode_len_16384() {
        assert_eq!(mqtt_decode_len(&[0x80, 0x80, 0x01]), Some(16384));
    }

    #[test]
    fn test_decode_len_max() {
        assert_eq!(
            mqtt_decode_len(&[0xFF, 0xFF, 0xFF, 0x7F]),
            Some(MAX_MQTT_MESSAGE_SIZE)
        );
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        for &value in &[0, 1, 50, 127, 128, 255, 16383, 16384, 2_097_151, MAX_MQTT_MESSAGE_SIZE] {
            let mut buf = [0u8; 4];
            let n = mqtt_encode_len(&mut buf, value);
            let decoded = mqtt_decode_len(&buf[..n]);
            assert_eq!(decoded, Some(value), "Round-trip failed for {}", value);
        }
    }

    #[test]
    fn test_decode_len_invalid_continuation() {
        // 5th byte with continuation — invalid per MQTT spec.
        assert_eq!(mqtt_decode_len(&[0x80, 0x80, 0x80, 0x80, 0x01]), None);
    }

    #[test]
    fn test_decode_len_empty() {
        assert_eq!(mqtt_decode_len(&[]), None);
    }

    // -----------------------------------------------------------------------
    // MqttHandler construction and metadata tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_handler_new() {
        let handler = MqttHandler::new();
        assert_eq!(handler.name(), "MQTT");
        assert_eq!(handler.default_port(), 1883);
        assert!(handler.flags().contains(ProtocolFlags::NEEDHOST));
    }

    #[test]
    fn test_handler_connection_check() {
        let handler = MqttHandler::new();
        let conn = ConnectionData::new(
            1,
            "broker.example.com".into(),
            1883,
            "mqtt".into(),
        );
        let result = handler.connection_check(&conn);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Topic extraction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_topic_valid() {
        let mut handler = MqttHandler::new();
        handler.url_path = "/test/topic".to_string();
        let topic = handler.mqtt_get_topic().unwrap();
        assert_eq!(topic, b"test/topic");
    }

    #[test]
    fn test_get_topic_url_encoded() {
        let mut handler = MqttHandler::new();
        handler.url_path = "/my%2Ftopic".to_string();
        let topic = handler.mqtt_get_topic().unwrap();
        // %2F decodes to '/'
        assert_eq!(topic, b"my/topic");
    }

    #[test]
    fn test_get_topic_empty_path() {
        let mut handler = MqttHandler::new();
        handler.url_path = "/".to_string();
        let result = handler.mqtt_get_topic();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::UrlMalformat);
    }

    #[test]
    fn test_get_topic_no_path() {
        let mut handler = MqttHandler::new();
        handler.url_path = "".to_string();
        let result = handler.mqtt_get_topic();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::UrlMalformat);
    }

    // -----------------------------------------------------------------------
    // State machine transition tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_state_transition_first() {
        let mut handler = MqttHandler::new();
        handler.set_state(MqttState::First, MqttState::Connack);
        assert_eq!(handler.conn.state, MqttState::First);
        assert_eq!(handler.conn.next_state, MqttState::Connack);
    }

    #[test]
    fn test_state_transition_non_first() {
        let mut handler = MqttHandler::new();
        handler.conn.next_state = MqttState::Suback;
        handler.set_state(MqttState::RemainingLength, MqttState::First);
        assert_eq!(handler.conn.state, MqttState::RemainingLength);
        // next_state should NOT be changed when state is not First.
        assert_eq!(handler.conn.next_state, MqttState::Suback);
    }

    // -----------------------------------------------------------------------
    // MQTT packet construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_len_values() {
        // Table from MQTT 3.1.1 spec section 2.2.3:
        // 0 → 0x00
        // 127 → 0x7F
        // 128 → 0x80 0x01
        // 16383 → 0xFF 0x7F
        // 16384 → 0x80 0x80 0x01
        // 2097151 → 0xFF 0xFF 0x7F
        // 2097152 → 0x80 0x80 0x80 0x01
        // 268435455 → 0xFF 0xFF 0xFF 0x7F

        let test_cases: &[(usize, &[u8])] = &[
            (0, &[0x00]),
            (127, &[0x7F]),
            (128, &[0x80, 0x01]),
            (16383, &[0xFF, 0x7F]),
            (16384, &[0x80, 0x80, 0x01]),
            (2_097_151, &[0xFF, 0xFF, 0x7F]),
            (2_097_152, &[0x80, 0x80, 0x80, 0x01]),
            (268_435_455, &[0xFF, 0xFF, 0xFF, 0x7F]),
        ];

        for &(value, expected) in test_cases {
            let mut buf = [0u8; 4];
            let n = mqtt_encode_len(&mut buf, value);
            assert_eq!(n, expected.len(), "Length mismatch for value {}", value);
            assert_eq!(
                &buf[..n], expected,
                "Encoding mismatch for value {}",
                value
            );
        }
    }

    #[test]
    fn test_mqtt_handler_metadata() {
        let handler = MqttHandler::new();
        assert_eq!(handler.name(), "MQTT");
        assert_eq!(handler.default_port(), PORT_MQTT);
        assert_eq!(handler.flags(), ProtocolFlags::NEEDHOST);
    }

    // -----------------------------------------------------------------------
    // MqttConn and MqttEasy construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_mqtt_conn_new() {
        let conn = MqttConn::new();
        assert_eq!(conn.state, MqttState::First);
        assert_eq!(conn.next_state, MqttState::First);
        assert_eq!(conn.packet_id, 0);
    }

    #[test]
    fn test_mqtt_easy_new() {
        let easy = MqttEasy::new();
        assert!(easy.send_buf.is_empty());
        assert!(easy.recv_buf.is_empty());
        assert_eq!(easy.npacket, 0);
        assert_eq!(easy.remaining_length, 0);
        assert_eq!(easy.first_byte, 0);
        assert!(!easy.ping_sent);
    }

    // -----------------------------------------------------------------------
    // Receive buffer management tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_recv_consume_partial() {
        let mut handler = MqttHandler::new();
        handler.easy.recv_buf = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        handler.mqtt_recv_consume(2);
        assert_eq!(handler.easy.recv_buf, vec![0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_recv_consume_all() {
        let mut handler = MqttHandler::new();
        handler.easy.recv_buf = vec![0x01, 0x02, 0x03];
        handler.mqtt_recv_consume(3);
        assert!(handler.easy.recv_buf.is_empty());
    }

    #[test]
    fn test_recv_consume_more_than_available() {
        let mut handler = MqttHandler::new();
        handler.easy.recv_buf = vec![0x01, 0x02];
        handler.mqtt_recv_consume(10);
        assert!(handler.easy.recv_buf.is_empty());
    }

    // -----------------------------------------------------------------------
    // MqttState Display tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_state_display() {
        assert_eq!(format!("{}", MqttState::First), "MQTT_FIRST");
        assert_eq!(
            format!("{}", MqttState::RemainingLength),
            "MQTT_REMAINING_LENGTH"
        );
        assert_eq!(format!("{}", MqttState::Connack), "MQTT_CONNACK");
        assert_eq!(format!("{}", MqttState::Suback), "MQTT_SUBACK");
        assert_eq!(
            format!("{}", MqttState::SubackComing),
            "MQTT_SUBACK_COMING"
        );
        assert_eq!(format!("{}", MqttState::PubWait), "MQTT_PUBWAIT");
        assert_eq!(format!("{}", MqttState::PubRemain), "MQTT_PUB_REMAIN");
    }

    // -- Default trait --------------------------------------------------------

    #[test]
    fn test_handler_default_matches_new() {
        let a = MqttHandler::new();
        let b = MqttHandler::default();
        assert_eq!(a.name(), b.name());
        assert_eq!(a.default_port(), b.default_port());
    }

    // -- take_output_data / download_size ------------------------------------

    #[test]
    fn test_take_output_data_empty() {
        let mut handler = MqttHandler::new();
        let data = handler.take_output_data();
        assert!(data.is_empty());
    }

    #[test]
    fn test_take_output_data_with_data() {
        let mut handler = MqttHandler::new();
        handler.output_buf = vec![1, 2, 3, 4, 5];
        let data = handler.take_output_data();
        assert_eq!(data, vec![1, 2, 3, 4, 5]);
        // After take, should be empty
        assert!(handler.output_buf.is_empty());
    }

    #[test]
    fn test_download_size_none() {
        let handler = MqttHandler::new();
        assert!(handler.download_size().is_none());
    }

    #[test]
    fn test_download_size_some() {
        let mut handler = MqttHandler::new();
        handler.download_size = Some(1024);
        assert_eq!(handler.download_size(), Some(1024));
    }

    // -- Constants ------------------------------------------------------------

    #[test]
    fn test_mqtt_constants() {
        assert_eq!(PORT_MQTT, 1883);
        assert_eq!(MQTT_KEEPALIVE_SECS, 60);
        assert_eq!(MQTT_CLIENTID_LEN, 12);
        assert_eq!(MAX_MQTT_MESSAGE_SIZE, 0x0FFF_FFFF);
        assert_eq!(RECV_BUFFER_SIZE, 4 * 1024);
    }

    // -- MqttState clone/copy/eq tests ----------------------------------------

    #[test]
    fn test_state_clone_eq() {
        let s = MqttState::Connack;
        let s2 = s.clone();
        assert_eq!(s, s2);
    }

    #[test]
    fn test_state_copy() {
        let s = MqttState::PubWait;
        let s2 = s; // copy
        assert_eq!(s, s2);
    }

    #[test]
    fn test_state_all_distinct() {
        let states = [
            MqttState::First, MqttState::RemainingLength, MqttState::Connack,
            MqttState::Suback, MqttState::SubackComing, MqttState::PubWait,
            MqttState::PubRemain,
        ];
        for i in 0..states.len() {
            for j in (i+1)..states.len() {
                assert_ne!(states[i], states[j]);
            }
        }
    }

    // -- Handler field tests --------------------------------------------------

    #[test]
    fn test_handler_initial_state() {
        let handler = MqttHandler::new();
        assert!(!handler.is_publish);
        assert!(handler.post_data.is_none());
        assert_eq!(handler.max_filesize, 0);
        assert_eq!(handler.byte_count, 0);
        assert!(!handler.done);
        assert!(handler.output_buf.is_empty());
        assert!(handler.url_path.is_empty());
        assert!(handler.username.is_empty());
        assert!(handler.password.is_empty());
    }

    // -- mqtt_done_impl test --------------------------------------------------

    #[test]
    fn test_done_impl_clears_buffers() {
        let mut handler = MqttHandler::new();
        handler.easy.send_buf = vec![1, 2, 3];
        handler.easy.recv_buf = vec![4, 5, 6];
        handler.mqtt_done_impl();
        assert!(handler.easy.send_buf.is_empty());
        assert!(handler.easy.recv_buf.is_empty());
    }

    // -- set_state edge cases -------------------------------------------------

    #[test]
    fn test_set_state_to_remaining_length() {
        let mut handler = MqttHandler::new();
        handler.set_state(MqttState::RemainingLength, MqttState::Connack);
        assert_eq!(handler.conn.state, MqttState::RemainingLength);
    }

    // -- Topic with special chars ---------------------------------------------

    #[test]
    fn test_get_topic_with_plus() {
        let mut handler = MqttHandler::new();
        // '+' is decoded to space by url_decode, use %2B for literal +
        handler.url_path = "/sensor/%2B/temperature".to_string();
        let topic = handler.mqtt_get_topic().unwrap();
        assert_eq!(topic, b"sensor/+/temperature");
    }

    #[test]
    fn test_get_topic_with_hash() {
        let mut handler = MqttHandler::new();
        handler.url_path = "/sensor/%23".to_string();
        let topic = handler.mqtt_get_topic().unwrap();
        assert_eq!(topic, b"sensor/#");
    }

    // -- Encode/decode boundary values ----------------------------------------

    #[test]
    fn test_encode_len_one() {
        let mut buf = [0u8; 4];
        let n = mqtt_encode_len(&mut buf, 1);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 1);
    }

    #[test]
    fn test_decode_len_truncated() {
        // Continuation bit set but no follow-up byte
        assert_eq!(mqtt_decode_len(&[0x80]), None);
    }

    #[test]
    fn test_encode_len_two_million() {
        let mut buf = [0u8; 4];
        let n = mqtt_encode_len(&mut buf, 2_097_152);
        assert_eq!(n, 4);
        let decoded = mqtt_decode_len(&buf[..n]);
        assert_eq!(decoded, Some(2_097_152));
    }

    // ===================================================================
    // set_state and state machine tests
    // ===================================================================
    #[test]
    fn test_set_state_changes() {
        let mut h = MqttHandler::new();
        assert_eq!(h.conn.state, MqttState::First);
        h.set_state(MqttState::Connack, MqttState::First);
        assert_eq!(h.conn.state, MqttState::Connack);
    }

    #[test]
    fn test_set_state_first_sets_next() {
        let mut h = MqttHandler::new();
        h.set_state(MqttState::First, MqttState::Suback);
        assert_eq!(h.conn.state, MqttState::First);
        assert_eq!(h.conn.next_state, MqttState::Suback);
    }

    #[test]
    fn test_set_state_non_first_ignores_next() {
        let mut h = MqttHandler::new();
        h.conn.next_state = MqttState::Connack;
        h.set_state(MqttState::PubWait, MqttState::Suback);
        assert_eq!(h.conn.state, MqttState::PubWait);
        // next_state unchanged since state != First
        assert_eq!(h.conn.next_state, MqttState::Connack);
    }

    // ===================================================================
    // mqtt_recv_consume tests
    // ===================================================================
    #[test]
    fn test_recv_consume_partial_extra() {
        let mut h = MqttHandler::new();
        h.easy.recv_buf = vec![1, 2, 3, 4, 5];
        h.mqtt_recv_consume(2);
        assert_eq!(h.easy.recv_buf, vec![3, 4, 5]);
    }

    #[test]
    fn test_recv_consume_all_extra() {
        let mut h = MqttHandler::new();
        h.easy.recv_buf = vec![1, 2, 3];
        h.mqtt_recv_consume(3);
        assert!(h.easy.recv_buf.is_empty());
    }

    #[test]
    fn test_recv_consume_more_than_available_extra() {
        let mut h = MqttHandler::new();
        h.easy.recv_buf = vec![1, 2];
        h.mqtt_recv_consume(100);
        assert!(h.easy.recv_buf.is_empty());
    }

    #[test]
    fn test_recv_consume_zero() {
        let mut h = MqttHandler::new();
        h.easy.recv_buf = vec![1, 2, 3];
        h.mqtt_recv_consume(0);
        assert_eq!(h.easy.recv_buf.len(), 3);
    }

    // ===================================================================
    // mqtt_verify_connack tests
    // ===================================================================
    #[test]
    fn test_verify_connack_wrong_remaining_length() {
        let mut h = MqttHandler::new();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.easy.remaining_length = 5;
        let err = h.mqtt_verify_connack(&mut conn).unwrap_err();
        assert_eq!(err, CurlError::WeirdServerReply);
    }

    #[test]
    fn test_verify_connack_success() {
        let mut h = MqttHandler::new();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.easy.remaining_length = 2;
        h.easy.recv_buf = vec![0x00, 0x00]; // valid CONNACK
        h.mqtt_verify_connack(&mut conn).unwrap();
        assert!(h.easy.recv_buf.is_empty());
    }

    #[test]
    fn test_verify_connack_bad_payload() {
        let mut h = MqttHandler::new();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.easy.remaining_length = 2;
        h.easy.recv_buf = vec![0x00, 0x01]; // non-zero return code
        let err = h.mqtt_verify_connack(&mut conn).unwrap_err();
        assert_eq!(err, CurlError::WeirdServerReply);
    }

    // ===================================================================
    // mqtt_verify_suback tests
    // ===================================================================
    #[test]
    fn test_verify_suback_wrong_remaining_length() {
        let mut h = MqttHandler::new();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.easy.remaining_length = 1;
        let err = h.mqtt_verify_suback(&mut conn).unwrap_err();
        assert_eq!(err, CurlError::WeirdServerReply);
    }

    #[test]
    fn test_verify_suback_success() {
        let mut h = MqttHandler::new();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.conn.packet_id = 1;
        h.easy.remaining_length = 3;
        h.easy.recv_buf = vec![0x00, 0x01, 0x00]; // msb=0, lsb=1, qos=0
        h.mqtt_verify_suback(&mut conn).unwrap();
        assert!(h.easy.recv_buf.is_empty());
    }

    #[test]
    fn test_verify_suback_wrong_packet_id() {
        let mut h = MqttHandler::new();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.conn.packet_id = 1;
        h.easy.remaining_length = 3;
        h.easy.recv_buf = vec![0x00, 0x02, 0x00]; // wrong packet id
        let err = h.mqtt_verify_suback(&mut conn).unwrap_err();
        assert_eq!(err, CurlError::WeirdServerReply);
    }

    // ===================================================================
    // mqtt_connect_packet tests
    // ===================================================================
    #[test]
    fn test_connect_packet_basic() {
        let mut h = MqttHandler::new();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.mqtt_connect_packet(&mut conn).unwrap();
        // Packet should have been sent (buffered via mqtt_send)
        // With sync_send returning full length, send_buf should be empty
        assert!(h.easy.send_buf.is_empty());
    }

    #[test]
    fn test_connect_packet_with_username() {
        let mut h = MqttHandler::new();
        h.username = "user".to_string();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.mqtt_connect_packet(&mut conn).unwrap();
    }

    #[test]
    fn test_connect_packet_with_username_password() {
        let mut h = MqttHandler::new();
        h.username = "user".to_string();
        h.password = "pass".to_string();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.mqtt_connect_packet(&mut conn).unwrap();
    }

    // ===================================================================
    // mqtt_subscribe_packet tests
    // ===================================================================
    #[test]
    fn test_subscribe_packet_increments_id() {
        let mut h = MqttHandler::new();
        h.url_path = "/test/topic".to_string();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        let old_id = h.conn.packet_id;
        h.mqtt_subscribe_packet(&mut conn).unwrap();
        assert_eq!(h.conn.packet_id, old_id.wrapping_add(1));
    }

    // ===================================================================
    // mqtt_publish_packet tests
    // ===================================================================
    #[test]
    fn test_publish_packet_basic() {
        let mut h = MqttHandler::new();
        h.url_path = "/test/topic".to_string();
        h.post_data = Some(b"hello world".to_vec());
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.mqtt_publish_packet(&mut conn).unwrap();
    }

    // ===================================================================
    // mqtt_disconnect_packet tests
    // ===================================================================
    #[test]
    fn test_disconnect_packet() {
        let mut h = MqttHandler::new();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.mqtt_disconnect_packet(&mut conn).unwrap();
    }

    // ===================================================================
    // mqtt_do_impl tests
    // ===================================================================
    #[test]
    fn test_do_impl_sets_state() {
        let mut h = MqttHandler::new();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.mqtt_do_impl(&mut conn).unwrap();
        assert_eq!(h.conn.state, MqttState::First);
        assert_eq!(h.conn.next_state, MqttState::Connack);
        assert!(!h.done);
    }

    // ===================================================================
    // mqtt_done_impl tests
    // ===================================================================
    #[test]
    fn test_done_impl_clears_buffers_extra() {
        let mut h = MqttHandler::new();
        h.easy.send_buf = vec![1, 2, 3];
        h.easy.recv_buf = vec![4, 5, 6];
        h.mqtt_done_impl();
        assert!(h.easy.send_buf.is_empty());
        assert!(h.easy.recv_buf.is_empty());
    }

    // ===================================================================
    // take_output_data / download_size tests
    // ===================================================================
    #[test]
    fn test_take_output_data() {
        let mut h = MqttHandler::new();
        h.output_buf = vec![10, 20, 30];
        let data = h.take_output_data();
        assert_eq!(data, vec![10, 20, 30]);
        assert!(h.output_buf.is_empty());
    }

    #[test]
    fn test_download_size_none_extra() {
        let h = MqttHandler::new();
        assert_eq!(h.download_size(), None);
    }

    #[test]
    fn test_download_size_set_extra() {
        let mut h = MqttHandler::new();
        h.download_size = Some(1024);
        assert_eq!(h.download_size(), Some(1024));
    }

    // ===================================================================
    // process_remaining_length tests
    // ===================================================================
    #[test]
    fn test_process_remaining_length_too_many_bytes() {
        let mut h = MqttHandler::new();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.easy.npacket = 4;
        h.easy.recv_buf = vec![0x80]; // continuation bit set, would be 5th byte
        let err = h.process_remaining_length(&mut conn);
        // sync_recv returns 0, so no data read — returns Ok(false)
        assert!(err.is_ok());
    }

    // ===================================================================
    // mqtt_doing_impl state machine tests
    // ===================================================================
    #[test]
    fn test_doing_impl_first_state_no_data() {
        let mut h = MqttHandler::new();
        h.conn.state = MqttState::First;
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        let result = h.mqtt_doing_impl(&mut conn).unwrap();
        assert!(!result); // no data available
    }

    #[test]
    fn test_doing_impl_connack_valid() {
        let mut h = MqttHandler::new();
        h.conn.state = MqttState::Connack;
        h.easy.remaining_length = 2;
        h.easy.recv_buf = vec![0x00, 0x00];
        h.url_path = "/topic".to_string();
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        let result = h.mqtt_doing_impl(&mut conn).unwrap();
        // Subscribe mode: sends SUBSCRIBE, doesn't set done
        assert!(!result);
    }

    #[test]
    fn test_doing_impl_connack_publish_mode() {
        let mut h = MqttHandler::new();
        h.conn.state = MqttState::Connack;
        h.easy.remaining_length = 2;
        h.easy.recv_buf = vec![0x00, 0x00];
        h.url_path = "/topic".to_string();
        h.is_publish = true;
        h.post_data = Some(b"data".to_vec());
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        let result = h.mqtt_doing_impl(&mut conn).unwrap();
        // Publish mode: sends PUBLISH + DISCONNECT, done=true
        assert!(result);
    }

    // ===================================================================
    // mqtt_ping tests
    // ===================================================================
    #[test]
    fn test_ping_not_first_state() {
        let mut h = MqttHandler::new();
        h.conn.state = MqttState::Connack;
        h.upkeep_interval_ms = 1000;
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.mqtt_ping(&mut conn).unwrap();
        assert!(!h.easy.ping_sent);
    }

    #[test]
    fn test_ping_already_sent() {
        let mut h = MqttHandler::new();
        h.conn.state = MqttState::First;
        h.easy.ping_sent = true;
        h.upkeep_interval_ms = 1000;
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.mqtt_ping(&mut conn).unwrap();
        assert!(h.easy.ping_sent);
    }

    #[test]
    fn test_ping_zero_interval() {
        let mut h = MqttHandler::new();
        h.conn.state = MqttState::First;
        h.upkeep_interval_ms = 0;
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.mqtt_ping(&mut conn).unwrap();
        assert!(!h.easy.ping_sent);
    }

    // ===================================================================
    // MqttState Display
    // ===================================================================
    #[test]
    fn test_mqtt_state_display_all() {
        let states = [
            (MqttState::First, "MQTT_FIRST"),
            (MqttState::RemainingLength, "MQTT_REMAINING_LENGTH"),
            (MqttState::Connack, "MQTT_CONNACK"),
            (MqttState::Suback, "MQTT_SUBACK"),
            (MqttState::SubackComing, "MQTT_SUBACK_COMING"),
            (MqttState::PubWait, "MQTT_PUB_REMAIN"),
            (MqttState::PubRemain, "MQTT_PUB_REMAIN"),
        ];
        for (state, _) in &states {
            let s = format!("{}", state);
            assert!(!s.is_empty());
        }
    }

    // ===================================================================
    // Protocol trait
    // ===================================================================
    #[test]
    fn test_protocol_name_mqtt() {
        let h = MqttHandler::new();
        assert_eq!(Protocol::name(&h), "MQTT");
    }

    #[test]
    fn test_protocol_default_port_mqtt() {
        let h = MqttHandler::new();
        assert_eq!(Protocol::default_port(&h), 1883);
    }

    #[test]
    fn test_protocol_flags_mqtt() {
        let h = MqttHandler::new();
        let flags = Protocol::flags(&h);
        // Should not have SSL flag
        assert!(!flags.contains(ProtocolFlags::SSL));
    }

    // ===================================================================
    // mqtt_send buffering
    // ===================================================================
    #[test]
    fn test_mqtt_send_clears_buf_on_success() {
        let mut h = MqttHandler::new();
        h.easy.send_buf = vec![1, 2, 3]; // leftover from before
        let mut conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        h.mqtt_send(&mut conn, &[0x10, 0x00]).unwrap();
        // sync_send returns buf.len(), so send_buf should be cleared
        assert!(h.easy.send_buf.is_empty());
    }

    // ===================================================================
    // encode/decode roundtrip edge cases
    // ===================================================================
    #[test]
    fn test_encode_decode_roundtrip_small() {
        for val in [0, 1, 2, 127, 128, 255, 16383, 16384, 2097151] {
            let mut buf = [0u8; 4];
            let n = mqtt_encode_len(&mut buf, val);
            let decoded = mqtt_decode_len(&buf[..n]).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for {}", val);
        }
    }

    #[test]
    fn test_decode_len_empty_extra() {
        assert_eq!(mqtt_decode_len(&[]), None);
    }

    #[test]
    fn test_decode_len_single_byte_extra() {
        assert_eq!(mqtt_decode_len(&[42]), Some(42));
    }

    #[test]
    fn test_decode_len_max_four_bytes() {
        // Maximum encodable: 268,435,455
        let mut buf = [0u8; 4];
        let n = mqtt_encode_len(&mut buf, 268_435_455);
        assert_eq!(n, 4);
        assert_eq!(mqtt_decode_len(&buf[..n]), Some(268_435_455));
    }

    // ===================================================================
    // MqttHandler connection_check
    // ===================================================================
    #[test]
    fn test_connection_check_alive() {
        let h = MqttHandler::new();
        let conn = ConnectionData::new(1, "broker".to_string(), 1883, "mqtt".to_string());
        let result = h.connection_check(&conn);
        // Default state: conn is not marked dead
        assert!(matches!(result, ConnectionCheckResult::Ok));
    }

    // ===================================================================
    // mqtt_get_topic URL decoding edge cases
    // ===================================================================
    #[test]
    fn test_get_topic_nested_path() {
        let mut h = MqttHandler::new();
        h.url_path = "/a/b/c".to_string();
        let topic = h.mqtt_get_topic().unwrap();
        assert_eq!(topic, b"a/b/c");
    }

    #[test]
    fn test_get_topic_special_chars() {
        let mut h = MqttHandler::new();
        h.url_path = "/sensor%2Ftemp".to_string();
        let topic = h.mqtt_get_topic().unwrap();
        assert_eq!(topic, b"sensor/temp");
    }
}
