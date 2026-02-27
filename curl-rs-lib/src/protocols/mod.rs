//! # Protocol Handler Subsystem
//!
//! Root module for the curl-rs protocols layer. This module replaces the C
//! `Curl_handler` function-pointer table and `Curl_scheme` dispatch mechanism
//! with idiomatic Rust types:
//!
//! * [`Protocol`] — async trait defining the per-protocol lifecycle methods
//!   (`connect`, `do_it`, `done`, `doing`, `disconnect`, `connection_check`).
//! * [`ProtocolFlags`] — bitflag set encoding protocol capabilities, mapped
//!   from the C `PROTOPT_*` constants defined in `lib/urldata.h`.
//! * [`Scheme`] — metadata struct describing a URL scheme (name, default port,
//!   flags, TLS requirement).
//! * [`SchemeRegistry`] — `HashMap`-backed lookup table mapping URL scheme
//!   strings to [`Scheme`] metadata, pre-populated with all 27 standard
//!   schemes supported by curl 8.x.
//! * [`ConnectionCheckResult`] — return type for connection liveness probes.
//!
//! ## Source Mapping
//!
//! | Rust type          | C source                                     |
//! |--------------------|----------------------------------------------|
//! | `Protocol`         | `struct Curl_protocol` (lib/urldata.h:428)   |
//! | `ProtocolFlags`    | `PROTOPT_*` macros (lib/urldata.h:526–558)   |
//! | `Scheme`           | `struct Curl_scheme` (lib/urldata.h:515)     |
//! | `SchemeRegistry`   | `Curl_getn_scheme()` (lib/url.c:1477)        |
//! | `ConnectionCheckResult` | `CONNRESULT_*` (lib/urldata.h:564–565)  |
//!
//! ## Safety
//!
//! This module and all its children contain **zero** `unsafe` blocks,
//! per AAP Section 0.7.1.

// ===========================================================================
// Sub-module declarations — protocol handler implementations
// ===========================================================================

/// Shared request/response ("ping-pong") state machine used by FTP, IMAP,
/// POP3, and SMTP command-based protocols.
pub mod pingpong;

/// HTTP/1.x, HTTP/2, and HTTP/3 protocol handlers plus chunked encoding,
/// proxy connect, and AWS SigV4 signing.
#[cfg(feature = "http")]
pub mod http;

/// FTP/FTPS protocol handler with active/passive mode, TLS upgrade, and
/// full state machine.
#[cfg(feature = "ftp")]
pub mod ftp;

/// FTP LIST response parser supporting Unix and Windows NT directory listing
/// formats.
#[cfg(feature = "ftp")]
pub mod ftp_list;

/// SSH-based protocols: SFTP and SCP via the `russh` crate.
pub mod ssh;

/// IMAP/IMAPS protocol handler with SASL authentication and STARTTLS.
#[cfg(feature = "imap")]
pub mod imap;

/// POP3/POP3S protocol handler with multi-auth (SASL/APOP/USER+PASS).
#[cfg(feature = "pop3")]
pub mod pop3;

/// SMTP/SMTPS protocol handler with EHLO/STARTTLS/SASL and MIME reader
/// integration.
#[cfg(feature = "smtp")]
pub mod smtp;

/// RTSP protocol handler implementing all 11 RTSP verbs with RTP
/// interleave support.
#[cfg(feature = "rtsp")]
pub mod rtsp;

/// MQTT 3.1.1 protocol handler with CONNECT/SUBSCRIBE/PUBLISH.
#[cfg(feature = "mqtt")]
pub mod mqtt;

/// RFC 6455 WebSocket handler with frame encode/decode, masking, and
/// control frame management.
pub mod ws;

/// RFC 854 Telnet handler with RFC 1143 option negotiation.
#[cfg(feature = "telnet")]
pub mod telnet;

/// RFC 1350 TFTP handler with option negotiation and retransmission.
#[cfg(feature = "tftp")]
pub mod tftp;

/// Gopher protocol handler with gophers:// TLS support.
pub mod gopher;

/// SMB/CIFS protocol handler with NTLM authentication.
pub mod smb;

/// RFC 2229 DICT protocol handler.
#[cfg(feature = "dict")]
pub mod dict;

/// `file://` protocol handler for local filesystem I/O.
pub mod file;

/// LDAP/LDAPS protocol handler implementing RFC 4516 URL parsing.
pub mod ldap;

// ===========================================================================
// Imports
// ===========================================================================

use std::collections::HashMap;

use crate::conn::ConnectionData;
use crate::error::CurlError;

// ===========================================================================
// Type alias — ergonomic name used in Protocol trait signatures
// ===========================================================================

/// Alias for [`ConnectionData`] — the per-connection state passed to every
/// [`Protocol`] method.
///
/// The agent-prompt references this as `Connection`; the canonical type
/// lives in [`crate::conn::ConnectionData`].
pub type Connection = ConnectionData;

// ===========================================================================
// ConnectionCheckResult
// ===========================================================================

/// Result of a protocol-level connection health check.
///
/// Maps to the C `CONNRESULT_NONE` / `CONNRESULT_DEAD` constants defined in
/// `lib/urldata.h` line 564, extended with an explicit error variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionCheckResult {
    /// Connection is alive and healthy (`CONNRESULT_NONE` = 0).
    Ok,

    /// Connection is dead and must be discarded (`CONNRESULT_DEAD` = 1).
    Dead,

    /// An error occurred during the health probe; the contained
    /// [`CurlError`] describes the failure.
    Error(CurlError),
}

impl ConnectionCheckResult {
    /// Returns `true` if the connection is alive.
    #[inline]
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Returns `true` if the connection is dead.
    #[inline]
    pub fn is_dead(&self) -> bool {
        matches!(self, Self::Dead)
    }

    /// Returns `true` if an error occurred.
    #[inline]
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }
}

// ===========================================================================
// ProtocolFlags — bitflag set for protocol capabilities
// ===========================================================================

/// Bitflag set describing protocol capabilities and requirements.
///
/// Each constant maps (conceptually) to a C `PROTOPT_*` macro from
/// `lib/urldata.h`. The bit positions are internal to the Rust
/// implementation and not ABI-stable.
///
/// # Combining Flags
///
/// Flags compose via `BitOr`:
///
/// ```ignore
/// let flags = ProtocolFlags::SSL | ProtocolFlags::CLOSEACTION;
/// assert!(flags.contains(ProtocolFlags::SSL));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolFlags(u32);

// --- Flag constants ---------------------------------------------------

impl ProtocolFlags {
    /// Connection requires cleanup action before socket close.
    /// Maps to C `PROTOPT_CLOSEACTION` (1 << 2).
    pub const CLOSEACTION: Self = Self(1 << 0);

    /// Protocol requires a hostname in the URL.
    pub const NEEDHOST: Self = Self(1 << 1);

    /// Protocol performs no network I/O (e.g. `file://`).
    /// Maps to C `PROTOPT_NONETWORK` (1 << 4).
    pub const NONETWORK: Self = Self(1 << 2);

    /// Non-HTTP scheme proxied via HTTP CONNECT.
    /// Maps to C `PROTOPT_PROXY_AS_HTTP` (1 << 11).
    pub const PROXY_AS_HTTP: Self = Self(1 << 3);

    /// Protocol inherently uses TLS (e.g. `https`, `ftps`).
    /// Maps to C `PROTOPT_SSL` (1 << 0).
    pub const SSL: Self = Self(1 << 4);

    /// Protocol uses two connections (e.g. FTP control + data).
    /// Maps to C `PROTOPT_DUAL` (1 << 1).
    pub const DUAL: Self = Self(1 << 5);

    /// Credentials are per-request rather than per-connection.
    /// Maps to C `PROTOPT_CREDSPERREQUEST` (1 << 7).
    pub const CREDSPERREQUEST: Self = Self(1 << 6);

    /// Protocol supports wildcard patterns.
    /// Maps to C `PROTOPT_WILDCARD` (1 << 12).
    pub const WILDCARD: Self = Self(1 << 7);

    /// Allow control characters (< 32 ASCII) in user/password.
    /// Maps to C `PROTOPT_USERPWDCTRL` (1 << 13).
    pub const USERPWDCTRL: Self = Self(1 << 8);

    /// Protocol does not use a URL at all.
    pub const NOURL: Self = Self(1 << 9);

    /// Allow options part in the userinfo field of the URL.
    /// Maps to C `PROTOPT_URLOPTIONS` (1 << 10).
    pub const URLOPTIONS: Self = Self(1 << 10);

    /// This protocol may reuse an existing SSL session from the
    /// same protocol family even without the `SSL` flag set.
    /// Maps to C `PROTOPT_SSL_REUSE` (1 << 15).
    pub const SSL_REUSE: Self = Self(1 << 11);

    /// This protocol can reuse connections.
    /// Maps to C `PROTOPT_CONN_REUSE` (1 << 16).
    pub const CONN_REUSE: Self = Self(1 << 12);
}

// --- Core methods ---------------------------------------------------------

impl ProtocolFlags {
    /// Returns a flag set with no bits set.
    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns the raw `u32` bit representation.
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if all bits in `other` are set in `self`.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns `true` if no bits are set.
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Constructs a flag set from a raw `u32` value.
    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the union (bitwise OR) of two flag sets.
    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the intersection (bitwise AND) of two flag sets.
    #[inline]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Returns the complement (bitwise NOT) of this flag set.
    #[inline]
    pub const fn complement(self) -> Self {
        Self(!self.0)
    }

    /// Returns `true` if `self` and `other` share at least one bit.
    #[inline]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

// --- Operator impls -------------------------------------------------------

impl std::ops::BitOr for ProtocolFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for ProtocolFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for ProtocolFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for ProtocolFlags {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl std::ops::Not for ProtocolFlags {
    type Output = Self;
    #[inline]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl Default for ProtocolFlags {
    #[inline]
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for ProtocolFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // List all set flag names for readable debug output.
        let mut first = true;
        let mut emit = |name: &str, f: &mut std::fmt::Formatter<'_>| -> std::fmt::Result {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str(name)
        };

        f.write_str("ProtocolFlags(")?;
        if self.contains(Self::CLOSEACTION) {
            emit("CLOSEACTION", f)?;
        }
        if self.contains(Self::NEEDHOST) {
            emit("NEEDHOST", f)?;
        }
        if self.contains(Self::NONETWORK) {
            emit("NONETWORK", f)?;
        }
        if self.contains(Self::PROXY_AS_HTTP) {
            emit("PROXY_AS_HTTP", f)?;
        }
        if self.contains(Self::SSL) {
            emit("SSL", f)?;
        }
        if self.contains(Self::DUAL) {
            emit("DUAL", f)?;
        }
        if self.contains(Self::CREDSPERREQUEST) {
            emit("CREDSPERREQUEST", f)?;
        }
        if self.contains(Self::WILDCARD) {
            emit("WILDCARD", f)?;
        }
        if self.contains(Self::USERPWDCTRL) {
            emit("USERPWDCTRL", f)?;
        }
        if self.contains(Self::NOURL) {
            emit("NOURL", f)?;
        }
        if self.contains(Self::URLOPTIONS) {
            emit("URLOPTIONS", f)?;
        }
        if self.contains(Self::SSL_REUSE) {
            emit("SSL_REUSE", f)?;
        }
        if self.contains(Self::CONN_REUSE) {
            emit("CONN_REUSE", f)?;
        }
        if first {
            f.write_str("empty")?;
        }
        f.write_str(")")
    }
}

impl std::fmt::Display for ProtocolFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

// ===========================================================================
// Protocol trait — replaces C `Curl_protocol` function-pointer table
// ===========================================================================

/// Core protocol handler trait.
///
/// Every URL scheme handler (HTTP, FTP, SFTP, etc.) implements this trait to
/// participate in the curl transfer lifecycle. The trait replaces the C
/// `struct Curl_protocol` function-pointer table defined in
/// `lib/urldata.h:428`.
///
/// # Lifecycle
///
/// ```text
/// connect() → do_it() → [doing() loop] → done() → disconnect()
/// ```
///
/// * **`connect`** — Establish the protocol-level connection (called after
///   the TCP/TLS transport layers are already connected).
/// * **`do_it`** — Execute the data transfer operation (send request, read
///   response, etc.).
/// * **`doing`** — Continue a multi-step non-blocking operation; returns
///   `Ok(true)` when done.
/// * **`done`** — Complete the transfer, run post-transfer commands (e.g.
///   FTP POSTQUOTE), and finalize state.
/// * **`disconnect`** — Tear down the protocol-level connection and release
///   resources (e.g. send FTP QUIT).
/// * **`connection_check`** — Non-destructive liveness probe for a cached
///   connection.
///
/// # Async
///
/// The async methods use Rust 1.75 native `async fn in trait` (RPITIT).
/// Implementors can use plain `async fn` syntax in their `impl` blocks.
///
/// The `async_fn_in_trait` lint is suppressed because this trait is
/// internal to the curl-rs workspace and all implementors are under our
/// control.  Returned futures do not need blanket `Send` bounds at the
/// trait level — the tokio current-thread runtime used by the CLI binary
/// does not require `Send`.
#[allow(async_fn_in_trait)]
pub trait Protocol: Send + Sync {
    /// Human-readable protocol name (e.g. `"HTTP"`, `"FTP"`, `"SFTP"`).
    fn name(&self) -> &str;

    /// Default TCP port for this protocol (e.g. 80 for HTTP).
    fn default_port(&self) -> u16;

    /// Protocol capability flags.
    fn flags(&self) -> ProtocolFlags;

    /// Establish the protocol-level connection.
    ///
    /// Called **after** the underlying TCP (and optionally TLS) connection is
    /// established. Protocol-specific handshaking (e.g. FTP 220 greeting,
    /// IMAP CAPABILITY) happens here.
    async fn connect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError>;

    /// Execute the primary data-transfer operation.
    ///
    /// For download protocols this sends the request and begins reading the
    /// response; for upload protocols it begins sending data.
    async fn do_it(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError>;

    /// Finalize the transfer.
    ///
    /// `status` carries the result of the transfer (e.g. `CurlError::Ok` on
    /// success). Implementations should run post-transfer commands (FTP
    /// POSTQUOTE, IMAP LOGOUT, etc.) and release per-transfer state.
    async fn done(
        &mut self,
        conn: &mut ConnectionData,
        status: CurlError,
    ) -> Result<(), CurlError>;

    /// Continue a multi-step operation in non-blocking mode.
    ///
    /// Returns `Ok(true)` when the operation is complete, or `Ok(false)` to
    /// indicate more I/O cycles are needed. The default implementation
    /// returns `Ok(true)` (single-step completion).
    async fn doing(&mut self, conn: &mut ConnectionData) -> Result<bool, CurlError> {
        // Default: operation completes in a single step.
        let _ = conn;
        Ok(true)
    }

    /// Disconnect and release all protocol-level resources.
    ///
    /// Called when the connection is being closed. Implementations should
    /// send graceful goodbye commands (e.g. `QUIT`, `LOGOUT`) if the
    /// connection is still alive.
    async fn disconnect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError>;

    /// Non-destructive liveness check for a cached connection.
    ///
    /// Called by the connection pool before reusing a connection.
    /// The default implementation returns [`ConnectionCheckResult::Ok`].
    fn connection_check(&self, conn: &ConnectionData) -> ConnectionCheckResult {
        let _ = conn;
        ConnectionCheckResult::Ok
    }
}

// ===========================================================================
// Scheme — URL-scheme metadata
// ===========================================================================

/// Metadata describing a URL scheme (e.g. `http`, `ftp`, `sftp`).
///
/// This struct replaces the C `struct Curl_scheme` from `lib/urldata.h:515`.
/// It stores static scheme properties used for URL dispatch; actual protocol
/// behaviour is provided by the [`Protocol`] trait.
#[derive(Debug, Clone)]
pub struct Scheme {
    /// URL scheme name in lowercase (e.g. `"http"`, `"ftps"`, `"sftp"`).
    pub name: &'static str,

    /// Default TCP/UDP port number (0 for schemes without a port, such as
    /// `file://`).
    pub default_port: u16,

    /// Protocol capability flags for this scheme.
    pub flags: ProtocolFlags,

    /// Whether the scheme requires a TLS connection by default (e.g.
    /// `https`, `ftps`, `imaps`).
    pub uses_tls: bool,
}

// ===========================================================================
// SchemeRegistry — HashMap-backed scheme lookup
// ===========================================================================

/// Registry mapping URL scheme name strings to [`Scheme`] metadata.
///
/// Replaces the C perfect-hash table in `Curl_getn_scheme()` (lib/url.c:1477)
/// with a standard `HashMap`. The registry is pre-populated with all 27
/// standard schemes supported by curl 8.x.
///
/// Scheme lookups are **case-insensitive**: names are stored and compared in
/// lowercase.
#[derive(Debug, Clone)]
pub struct SchemeRegistry {
    schemes: HashMap<String, Scheme>,
}

impl SchemeRegistry {
    /// Creates a new registry pre-populated with all standard curl 8.x
    /// URL schemes.
    ///
    /// Ports are sourced from the C `PORT_*` constants in
    /// `lib/urldata.h:29–53`.
    pub fn new() -> Self {
        let mut schemes = HashMap::new();

        // Helper closure: insert a scheme entry.
        let mut reg = |name: &'static str,
                       port: u16,
                       flags: ProtocolFlags,
                       tls: bool| {
            schemes.insert(
                name.to_owned(),
                Scheme {
                    name,
                    default_port: port,
                    flags,
                    uses_tls: tls,
                },
            );
        };

        // Pre-computed composite flag sets used by several schemes.
        let http_flags = ProtocolFlags::NEEDHOST
            | ProtocolFlags::PROXY_AS_HTTP
            | ProtocolFlags::CREDSPERREQUEST
            | ProtocolFlags::USERPWDCTRL
            | ProtocolFlags::CONN_REUSE;

        let ftp_flags = ProtocolFlags::NEEDHOST
            | ProtocolFlags::CLOSEACTION
            | ProtocolFlags::DUAL
            | ProtocolFlags::PROXY_AS_HTTP
            | ProtocolFlags::WILDCARD;

        let ssh_flags = ProtocolFlags::NEEDHOST | ProtocolFlags::CLOSEACTION;

        let imap_flags = ProtocolFlags::NEEDHOST
            | ProtocolFlags::CLOSEACTION
            | ProtocolFlags::URLOPTIONS
            | ProtocolFlags::SSL_REUSE
            | ProtocolFlags::CONN_REUSE;

        let pingpong_flags = ProtocolFlags::NEEDHOST | ProtocolFlags::CLOSEACTION;

        // -------------------------------------------------------------------
        // HTTP family (ports 80 / 443)
        // -------------------------------------------------------------------
        reg("http", 80, http_flags, false);
        reg("https", 443, http_flags | ProtocolFlags::SSL, true);

        // -------------------------------------------------------------------
        // FTP family (ports 21 / 990)
        // -------------------------------------------------------------------
        reg("ftp", 21, ftp_flags, false);
        reg("ftps", 990, ftp_flags | ProtocolFlags::SSL, true);

        // -------------------------------------------------------------------
        // SSH family (port 22)
        // -------------------------------------------------------------------
        reg("sftp", 22, ssh_flags, false);
        reg("scp", 22, ssh_flags, false);

        // -------------------------------------------------------------------
        // IMAP family (ports 143 / 993)
        // -------------------------------------------------------------------
        reg("imap", 143, imap_flags, false);
        reg("imaps", 993, imap_flags | ProtocolFlags::SSL, true);

        // -------------------------------------------------------------------
        // POP3 family (ports 110 / 995)
        // -------------------------------------------------------------------
        reg("pop3", 110, pingpong_flags, false);
        reg("pop3s", 995, pingpong_flags | ProtocolFlags::SSL, true);

        // -------------------------------------------------------------------
        // SMTP family (ports 25 / 465)
        // -------------------------------------------------------------------
        reg("smtp", 25, pingpong_flags, false);
        reg("smtps", 465, pingpong_flags | ProtocolFlags::SSL, true);

        // -------------------------------------------------------------------
        // RTSP (port 554)
        // -------------------------------------------------------------------
        reg(
            "rtsp",
            554,
            ProtocolFlags::NEEDHOST | ProtocolFlags::CONN_REUSE,
            false,
        );

        // -------------------------------------------------------------------
        // MQTT family (ports 1883 / 8883)
        // -------------------------------------------------------------------
        reg("mqtt", 1883, ProtocolFlags::NEEDHOST, false);
        reg(
            "mqtts",
            8883,
            ProtocolFlags::NEEDHOST | ProtocolFlags::SSL,
            true,
        );

        // -------------------------------------------------------------------
        // WebSocket family (ports 80 / 443, shares HTTP ports)
        // -------------------------------------------------------------------
        let ws_flags = ProtocolFlags::NEEDHOST
            | ProtocolFlags::CREDSPERREQUEST
            | ProtocolFlags::USERPWDCTRL;
        reg("ws", 80, ws_flags, false);
        reg("wss", 443, ws_flags | ProtocolFlags::SSL, true);

        // -------------------------------------------------------------------
        // Telnet (port 23)
        // -------------------------------------------------------------------
        reg("telnet", 23, ProtocolFlags::NEEDHOST, false);

        // -------------------------------------------------------------------
        // TFTP (port 69)
        // -------------------------------------------------------------------
        reg("tftp", 69, ProtocolFlags::NEEDHOST, false);

        // -------------------------------------------------------------------
        // Gopher family (port 70)
        // -------------------------------------------------------------------
        reg("gopher", 70, ProtocolFlags::NEEDHOST, false);
        reg(
            "gophers",
            70,
            ProtocolFlags::NEEDHOST | ProtocolFlags::SSL,
            true,
        );

        // -------------------------------------------------------------------
        // SMB family (port 445)
        // -------------------------------------------------------------------
        reg(
            "smb",
            445,
            ProtocolFlags::NEEDHOST | ProtocolFlags::CONN_REUSE,
            false,
        );
        reg(
            "smbs",
            445,
            ProtocolFlags::NEEDHOST | ProtocolFlags::SSL | ProtocolFlags::CONN_REUSE,
            true,
        );

        // -------------------------------------------------------------------
        // DICT (port 2628)
        // -------------------------------------------------------------------
        reg("dict", 2628, ProtocolFlags::NEEDHOST, false);

        // -------------------------------------------------------------------
        // FILE (no network, port 0)
        // -------------------------------------------------------------------
        reg(
            "file",
            0,
            ProtocolFlags::NONETWORK | ProtocolFlags::NOURL,
            false,
        );

        // -------------------------------------------------------------------
        // LDAP family (ports 389 / 636)
        // -------------------------------------------------------------------
        reg("ldap", 389, ProtocolFlags::NEEDHOST, false);
        reg(
            "ldaps",
            636,
            ProtocolFlags::NEEDHOST | ProtocolFlags::SSL,
            true,
        );

        Self { schemes }
    }

    /// Looks up a scheme by its URL name string.
    ///
    /// The lookup is **case-insensitive**: `"HTTP"`, `"Http"`, and `"http"`
    /// all match.
    ///
    /// Returns `None` if the scheme is not registered.
    pub fn get_scheme(&self, name: &str) -> Option<&Scheme> {
        // Convert to lowercase for case-insensitive lookup.
        let lower = name.to_ascii_lowercase();
        self.schemes.get(&lower)
    }

    /// Registers a new scheme (or replaces an existing registration).
    ///
    /// The scheme name is stored in lowercase regardless of the case of
    /// `scheme.name`.
    pub fn register(&mut self, scheme: Scheme) {
        let key = scheme.name.to_ascii_lowercase();
        self.schemes.insert(key, scheme);
    }

    /// Returns the number of registered schemes.
    #[inline]
    pub fn len(&self) -> usize {
        self.schemes.len()
    }

    /// Returns `true` if no schemes are registered.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.schemes.is_empty()
    }

    /// Returns an iterator over all registered `(name, scheme)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Scheme)> {
        self.schemes.iter().map(|(k, v)| (k.as_str(), v))
    }
}

impl Default for SchemeRegistry {
    /// Returns a registry pre-populated with all standard schemes (same as
    /// [`SchemeRegistry::new()`]).
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_flags_empty() {
        let flags = ProtocolFlags::empty();
        assert!(flags.is_empty());
        assert_eq!(flags.bits(), 0);
    }

    #[test]
    fn test_protocol_flags_single() {
        let flags = ProtocolFlags::SSL;
        assert!(!flags.is_empty());
        assert!(flags.contains(ProtocolFlags::SSL));
        assert!(!flags.contains(ProtocolFlags::DUAL));
    }

    #[test]
    fn test_protocol_flags_combine() {
        let flags = ProtocolFlags::SSL | ProtocolFlags::CLOSEACTION;
        assert!(flags.contains(ProtocolFlags::SSL));
        assert!(flags.contains(ProtocolFlags::CLOSEACTION));
        assert!(!flags.contains(ProtocolFlags::DUAL));
        assert!(flags.contains(ProtocolFlags::SSL | ProtocolFlags::CLOSEACTION));
    }

    #[test]
    fn test_protocol_flags_debug_output() {
        let flags = ProtocolFlags::SSL | ProtocolFlags::NEEDHOST;
        let dbg = format!("{:?}", flags);
        assert!(dbg.contains("SSL"));
        assert!(dbg.contains("NEEDHOST"));
    }

    #[test]
    fn test_protocol_flags_default_is_empty() {
        let flags = ProtocolFlags::default();
        assert!(flags.is_empty());
    }

    #[test]
    fn test_connection_check_result_variants() {
        assert!(ConnectionCheckResult::Ok.is_ok());
        assert!(ConnectionCheckResult::Dead.is_dead());
        assert!(ConnectionCheckResult::Error(CurlError::CouldntConnect).is_error());
    }

    #[test]
    fn test_scheme_registry_new_has_all_schemes() {
        let reg = SchemeRegistry::new();
        // 27 standard schemes expected.
        assert_eq!(reg.len(), 27);
    }

    #[test]
    fn test_scheme_registry_lookup_http() {
        let reg = SchemeRegistry::new();
        let scheme = reg.get_scheme("http").expect("http must exist");
        assert_eq!(scheme.name, "http");
        assert_eq!(scheme.default_port, 80);
        assert!(!scheme.uses_tls);
        assert!(scheme.flags.contains(ProtocolFlags::NEEDHOST));
    }

    #[test]
    fn test_scheme_registry_lookup_https() {
        let reg = SchemeRegistry::new();
        let scheme = reg.get_scheme("https").expect("https must exist");
        assert_eq!(scheme.name, "https");
        assert_eq!(scheme.default_port, 443);
        assert!(scheme.uses_tls);
        assert!(scheme.flags.contains(ProtocolFlags::SSL));
    }

    #[test]
    fn test_scheme_registry_case_insensitive() {
        let reg = SchemeRegistry::new();
        assert!(reg.get_scheme("HTTP").is_some());
        assert!(reg.get_scheme("Http").is_some());
        assert!(reg.get_scheme("http").is_some());
    }

    #[test]
    fn test_scheme_registry_unknown_scheme() {
        let reg = SchemeRegistry::new();
        assert!(reg.get_scheme("unknown").is_none());
    }

    #[test]
    fn test_scheme_registry_register_custom() {
        let mut reg = SchemeRegistry::new();
        reg.register(Scheme {
            name: "custom",
            default_port: 9999,
            flags: ProtocolFlags::NEEDHOST,
            uses_tls: false,
        });
        let scheme = reg.get_scheme("custom").expect("custom must exist");
        assert_eq!(scheme.default_port, 9999);
    }

    #[test]
    fn test_scheme_ftp_ports() {
        let reg = SchemeRegistry::new();
        assert_eq!(
            reg.get_scheme("ftp").unwrap().default_port,
            21
        );
        assert_eq!(
            reg.get_scheme("ftps").unwrap().default_port,
            990
        );
    }

    #[test]
    fn test_scheme_ssh_ports() {
        let reg = SchemeRegistry::new();
        assert_eq!(
            reg.get_scheme("sftp").unwrap().default_port,
            22
        );
        assert_eq!(
            reg.get_scheme("scp").unwrap().default_port,
            22
        );
    }

    #[test]
    fn test_scheme_file_no_network() {
        let reg = SchemeRegistry::new();
        let scheme = reg.get_scheme("file").unwrap();
        assert_eq!(scheme.default_port, 0);
        assert!(!scheme.uses_tls);
        assert!(scheme.flags.contains(ProtocolFlags::NONETWORK));
    }

    #[test]
    fn test_all_port_values() {
        let reg = SchemeRegistry::new();

        let expected: &[(&str, u16)] = &[
            ("http", 80),
            ("https", 443),
            ("ftp", 21),
            ("ftps", 990),
            ("sftp", 22),
            ("scp", 22),
            ("imap", 143),
            ("imaps", 993),
            ("pop3", 110),
            ("pop3s", 995),
            ("smtp", 25),
            ("smtps", 465),
            ("rtsp", 554),
            ("mqtt", 1883),
            ("mqtts", 8883),
            ("ws", 80),
            ("wss", 443),
            ("telnet", 23),
            ("tftp", 69),
            ("gopher", 70),
            ("gophers", 70),
            ("smb", 445),
            ("smbs", 445),
            ("dict", 2628),
            ("file", 0),
            ("ldap", 389),
            ("ldaps", 636),
        ];

        for &(name, port) in expected {
            let s = reg
                .get_scheme(name)
                .unwrap_or_else(|| panic!("missing scheme: {}", name));
            assert_eq!(
                s.default_port, port,
                "port mismatch for scheme `{}`",
                name
            );
        }
    }

    #[test]
    fn test_tls_schemes() {
        let reg = SchemeRegistry::new();

        let tls_schemes = [
            "https", "ftps", "imaps", "pop3s", "smtps", "mqtts", "wss",
            "gophers", "smbs", "ldaps",
        ];

        for name in &tls_schemes {
            let s = reg.get_scheme(name).unwrap();
            assert!(
                s.uses_tls,
                "scheme `{}` should use TLS",
                name
            );
            assert!(
                s.flags.contains(ProtocolFlags::SSL),
                "scheme `{}` should have SSL flag",
                name
            );
        }
    }
}
