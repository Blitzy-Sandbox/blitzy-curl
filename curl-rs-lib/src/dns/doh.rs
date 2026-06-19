//! DNS-over-HTTPS (DoH) resolver backend.
//!
//! This module is the memory-safe Rust reimplementation of curl's `lib/doh.c`
//! (with the wire-format definitions from `lib/doh.h`). It builds RFC 1035
//! DNS query messages, hands them to an HTTPS transport for a `POST` to the
//! configured `CURLOPT_DOH_URL` endpoint (media type
//! `application/dns-message`), and parses the binary DNS responses into a set
//! of resolved socket addresses.
//!
//! # Byte-for-byte parity (AAP §0.6 G6)
//!
//! The DNS wire encoding ([`encode_query`]) and decoding ([`resp_decode`]) are
//! reproduced **byte-for-byte** from `lib/doh.c`. Every bounds check that the C
//! code performs with `dohlen < index + N` is reproduced here as a Rust
//! slice-length check returning the same [`DohCode`]. This is a hard parity
//! requirement: the existing curl 8.x test suite exercises these paths and the
//! produced/consumed bytes must match exactly.
//!
//! # Memory safety
//!
//! This module contains **zero `unsafe`** and compiles under
//! `#![forbid(unsafe_code)]`. All buffer access uses slices, checked indexing,
//! and `Option`-returning accessors rather than raw pointers — the safe
//! analogue of curl's manual pointer arithmetic.
//!
//! # Transport seam (runtime collaborators)
//!
//! curl's `doh_probe_run` opens an *internal* easy handle (`Curl_open`), sets
//! the DoH URL / HTTP version / `POST` body, registers a write callback that
//! appends the response to a `resp_body` dynbuf, and inherits the parent
//! transfer's DoH SSL options. The equivalent collaborators here —
//! `crate::protocols::http` (which issues the HTTPS `POST`) and `crate::tls`
//! (which supplies the DoH SSL configuration) — are *later-tier siblings*
//! consumed through the transfer engine, **not** direct dependencies of this
//! module (the only `depends_on_folders` for the `dns` module tree is
//! `crate::util`). To keep this module independently compilable and testable,
//! the HTTPS round-trip is abstracted behind the [`DohTransport`] trait, which
//! the engine implements (wiring in `protocols::http` + `tls`) and installs via
//! [`install_transport`]. Unit tests install a mock transport.
//!
//! # HTTPS-RR (TYPE 65)
//!
//! curl's HTTPS resource-record support is gated behind `USE_HTTPSRR`, which is
//! **off** in curl's default build (and `version.rs` does not advertise the
//! capability by default). There is correspondingly no `httpsrr` Cargo feature
//! in this workspace, so the HTTPS-RR probe and record parsing are omitted; the
//! [`DnsType::Https`] variant and [`DOH_SLOT_HTTPS_RR`] slot are retained for
//! wire/ABI parity, and the response decoder simply skips TYPE 65 records —
//! exactly as curl's default build does.

#![forbid(unsafe_code)]

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use crate::dns::{IpVersion, ResolvedAddrs};
use crate::error::{CurlError, Result};
use crate::util::dynbuf::{DynBuf, DYN_DOH_CNAME, DYN_DOH_RESPONSE};

// ===========================================================================
// Wire constants (← lib/doh.h)
// ===========================================================================

/// DNS `CLASS` value for "the Internet" (`IN`). (← `doh.h` `DNS_CLASS_IN`.)
pub const DNS_CLASS_IN: u8 = 0x01;

/// Maximum size, in bytes, of an encoded DoH request packet.
///
/// `256 + 16` (← `doh.h` `DOH_MAX_DNSREQ_SIZE`): a 255-octet maximum DNS name
/// plus the 12-byte header, the QNAME root label, and the 4 `TYPE`/`CLASS`
/// bytes, with headroom. A host whose QNAME encoding would exceed this yields
/// [`DohCode::DnsNameTooLong`].
pub const DOH_MAX_DNSREQ_SIZE: usize = 256 + 16;

/// Maximum number of addresses stored from a single resolve (← `doh.h`
/// `DOH_MAX_ADDR`). Addresses beyond this are silently ignored, matching curl.
pub const DOH_MAX_ADDR: usize = 24;

/// Maximum number of CNAME chains accumulated (← `doh.h` `DOH_MAX_CNAME`).
pub const DOH_MAX_CNAME: usize = 4;

/// Maximum number of HTTPS resource records (← `doh.h` `DOH_MAX_HTTPS`).
///
/// Retained for wire/ABI parity; the HTTPS-RR path is omitted in the default
/// build (curl's `USE_HTTPSRR` is off and there is no `httpsrr` Cargo feature).
#[allow(dead_code)] // parity constant: consumed only by the omitted HTTPS-RR path
pub const DOH_MAX_HTTPS: usize = 4;

/// Meta-key under which curl stashes a probe's request state on its internal
/// easy handle (`Curl_meta_set(doh, CURL_EZM_DOH_PROBE, …)`); see
/// `doh.h` `CURL_EZM_DOH_PROBE`.
///
/// In this implementation the per-probe state is carried by the
/// [`DohProbeRequest`] value passed to the transport rather than by an
/// easy-handle meta table, so the key itself is unused; it is retained for
/// parity with curl's internal bookkeeping.
#[allow(dead_code)] // parity constant: curl's easy-handle meta key, unused here
pub const CURL_EZM_DOH_PROBE: &str = "ezm:doh-p";

/// The DoH request/response media type (`Content-Type` and `Accept`).
///
/// curl sets `Content-Type: application/dns-message` on each probe request
/// (`doh_probe_run`); the matching `Accept` is implied. A [`DohTransport`]
/// implementation MUST send this media type for both headers.
pub const DOH_CONTENT_TYPE: &str = "application/dns-message";

// Probe slot indices (← `doh.h` `enum doh_slot_num`). The IPv4 (A) and IPv6
// (AAAA) slots are always defined; the HTTPS-RR slot exists only under curl's
// `USE_HTTPSRR` and is retained here solely for parity.

/// Probe slot index for the IPv4 (`A`) query (← `DOH_SLOT_IPV4`).
pub const DOH_SLOT_IPV4: usize = 0;

/// Probe slot index for the IPv6 (`AAAA`) query (← `DOH_SLOT_IPV6`).
pub const DOH_SLOT_IPV6: usize = 1;

/// Probe slot index for the HTTPS resource-record query (← `DOH_SLOT_HTTPS_RR`,
/// only under `USE_HTTPSRR`). Retained for parity; the HTTPS-RR path is omitted.
#[allow(dead_code)] // parity constant: consumed only by the omitted HTTPS-RR path
pub const DOH_SLOT_HTTPS_RR: usize = 2;

// ===========================================================================
// DNS RR types (← lib/doh.h `DNStype`)
// ===========================================================================

/// DNS resource-record / query `TYPE` values used by the DoH resolver.
///
/// The numeric values are the IANA-assigned RR type codes and MUST match
/// curl's `DNStype` enum exactly (← `doh.h`), since they are written into the
/// query on the wire and compared against the answer `TYPE` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsType {
    /// IPv4 host address.
    A = 1,
    /// Authoritative name server.
    Ns = 2,
    /// Canonical name (alias).
    Cname = 5,
    /// IPv6 host address.
    Aaaa = 28,
    /// Delegation name.
    Dname = 39,
    /// HTTPS service binding (RR type 65). Retained for parity; not probed by
    /// default (curl `USE_HTTPSRR` is off).
    Https = 65,
}

// ===========================================================================
// DoH result codes (← lib/doh.h `DOHcode`)
// ===========================================================================

/// Result codes for DoH wire encoding/decoding (← `doh.h` `DOHcode`, values
/// `0..=13`). These mirror curl's enumeration exactly so the diagnostic
/// strings ([`DohCode::strerror`]) match `doh_strerror`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DohCode {
    /// Success.
    Ok = 0,
    /// A DNS label was malformed (length out of `1..=63`, or bad high bits).
    DnsBadLabel = 1,
    /// A read would run past the end of the message.
    DnsOutOfRange = 2,
    /// A compression-pointer loop exceeded the iteration guard.
    DnsLabelLoop = 3,
    /// The output buffer was too small (cannot occur with `Vec` growth, kept
    /// for parity).
    TooSmallBuffer = 4,
    /// An accumulation buffer exceeded its cap (CNAME over [`DYN_DOH_CNAME`]).
    OutOfMem = 5,
    /// An `A`/`AAAA` record had the wrong `RDLENGTH`.
    DnsRdataLen = 6,
    /// The message had trailing or missing bytes (final index `!=` length).
    DnsMalformat = 7,
    /// The response `RCODE` was non-zero.
    DnsBadRcode = 8,
    /// An answer `TYPE` was neither the requested type nor `CNAME`/`DNAME`.
    DnsUnexpectedType = 9,
    /// An answer `CLASS` was not `IN`.
    DnsUnexpectedClass = 10,
    /// The response stored no usable content.
    NoContent = 11,
    /// The response transaction `ID` was non-zero (curl always sends `ID = 0`).
    DnsBadId = 12,
    /// The host name's QNAME encoding would exceed [`DOH_MAX_DNSREQ_SIZE`].
    DnsNameTooLong = 13,
}

impl DohCode {
    /// Returns the human-readable diagnostic string for this code, matching
    /// curl's `doh_strerror` table (← `doh.c:44-66`). [`DohCode::Ok`] maps to
    /// the empty string, as in curl.
    #[must_use]
    pub fn strerror(self) -> &'static str {
        match self {
            DohCode::Ok => "",
            DohCode::DnsBadLabel => "Bad label",
            DohCode::DnsOutOfRange => "Out of range",
            DohCode::DnsLabelLoop => "Label loop",
            DohCode::TooSmallBuffer => "Too small",
            DohCode::OutOfMem => "Out of memory",
            DohCode::DnsRdataLen => "RDATA length",
            DohCode::DnsMalformat => "Malformat",
            DohCode::DnsBadRcode => "Bad RCODE",
            DohCode::DnsUnexpectedType => "Unexpected TYPE",
            DohCode::DnsUnexpectedClass => "Unexpected CLASS",
            DohCode::NoContent => "No content",
            DohCode::DnsBadId => "Bad ID",
            DohCode::DnsNameTooLong => "Name too long",
        }
    }
}

impl fmt::Display for DohCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.strerror())
    }
}

// ===========================================================================
// Transport seam — the HTTPS round-trip abstraction
// ===========================================================================

/// DoH SSL/TLS options inherited from the parent transfer.
///
/// curl's `doh_probe_run` copies the parent handle's DoH-specific verification
/// settings (`CURLOPT_DOH_SSL_VERIFYPEER`, `CURLOPT_DOH_SSL_VERIFYHOST`,
/// `CURLOPT_DOH_SSL_VERIFYSTATUS`) and CA material (`CAINFO`, `CAPATH`,
/// `CRLFILE`) onto the internal DoH easy handle. Those settings are carried
/// here and handed to the [`DohTransport`] (which applies them via
/// `crate::tls`) for the DoH request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DohSslConfig {
    /// Verify the DoH server's certificate chain (`CURLOPT_DOH_SSL_VERIFYPEER`).
    pub verify_peer: bool,
    /// Verify the DoH server's hostname (`CURLOPT_DOH_SSL_VERIFYHOST`).
    pub verify_host: bool,
    /// Verify the DoH server's certificate status / OCSP staple
    /// (`CURLOPT_DOH_SSL_VERIFYSTATUS`).
    pub verify_status: bool,
    /// Path to a CA certificate bundle (`CAINFO`).
    pub ca_info: Option<String>,
    /// Path to a directory of CA certificates (`CAPATH`).
    pub ca_path: Option<String>,
    /// Path to a certificate revocation list (`CRLFILE`).
    pub crl_file: Option<String>,
}

impl Default for DohSslConfig {
    /// curl's default DoH posture: certificate validation **on**. Peer and
    /// host verification default to `true`; status checking and explicit CA
    /// material default to off/unset (the system trust store is used).
    fn default() -> Self {
        DohSslConfig {
            verify_peer: true,
            verify_host: true,
            verify_status: false,
            ca_info: None,
            ca_path: None,
            crl_file: None,
        }
    }
}

/// A single DoH probe request to be issued by a [`DohTransport`].
///
/// This is the safe analogue of the per-probe state curl assembles in
/// `doh_probe_run`: the endpoint URL, the encoded DNS query to `POST`, the
/// media type, and the inherited SSL configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DohProbeRequest {
    /// The DoH endpoint URL (`CURLOPT_DOH_URL`).
    pub url: String,
    /// The RFC 1035 DNS query message to send as the `POST` body (the output
    /// of [`encode_query`]).
    pub body: Vec<u8>,
    /// The request/response media type — always [`DOH_CONTENT_TYPE`].
    pub content_type: &'static str,
    /// SSL options inherited from the parent transfer.
    pub ssl: DohSslConfig,
}

/// Options controlling a DoH resolve, beyond the `(url, host, port,
/// ip_version)` carried by the resolver interface.
///
/// The public [`resolve`] entry point uses [`DohOptions::default`] (validation
/// on, non-verbose); the transfer engine may instead call [`run_probes`]
/// directly with a populated value to inherit the parent transfer's SSL
/// configuration and verbosity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DohOptions {
    /// SSL options to apply to each DoH request.
    pub ssl: DohSslConfig,
    /// Whether to emit verbose `[DoH] …` diagnostics (`CURLOPT_VERBOSE`).
    pub verbose: bool,
}

/// The HTTPS round-trip used to carry a DoH probe.
///
/// This is the seam between the (dependency-free) DoH wire logic in this module
/// and the runtime collaborators that actually perform the HTTPS `POST`
/// (`crate::protocols::http`) over a TLS connection configured by
/// `crate::tls`. The transfer engine implements this trait and installs an
/// instance via [`install_transport`]; unit tests install a mock.
///
/// Implementations MUST:
/// * issue an HTTP `POST` of [`DohProbeRequest::body`] to
///   [`DohProbeRequest::url`],
/// * set both `Content-Type` and `Accept` to [`DohProbeRequest::content_type`],
/// * apply [`DohProbeRequest::ssl`] to the TLS configuration, and
/// * return the raw response body on success.
///
/// The returned future is boxed so the trait is object-safe (usable as
/// `dyn DohTransport`), and `Send` so probes can be driven concurrently on a
/// multi-thread runtime.
pub trait DohTransport: Send + Sync {
    /// Performs one DoH HTTPS round-trip, returning the raw response body.
    fn send<'a>(
        &'a self,
        req: DohProbeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;
}

/// Process-wide DoH transport, installed once by the transfer engine.
static DOH_TRANSPORT: OnceLock<Arc<dyn DohTransport>> = OnceLock::new();

/// Installs the process-wide [`DohTransport`] used by [`resolve`].
///
/// Intended to be called once during engine initialization (after
/// `crate::protocols::http` and `crate::tls` are ready). Returns `true` if this
/// call installed the transport, or `false` if one was already installed (the
/// existing transport is kept). This mirrors curl's requirement that a DoH
/// resolve has the multi/transfer machinery available before it can run.
pub fn install_transport(transport: Arc<dyn DohTransport>) -> bool {
    DOH_TRANSPORT.set(transport).is_ok()
}

/// Returns the installed [`DohTransport`], if any.
#[must_use]
pub fn installed_transport() -> Option<Arc<dyn DohTransport>> {
    DOH_TRANSPORT.get().cloned()
}

// ===========================================================================
// Phase A — query encoding (← doh.c `doh_req_encode`, doh.c:72-167)
// ===========================================================================

/// Encodes an RFC 1035 DNS query for `host`/`dnstype` into wire format.
///
/// This is the byte-for-byte reimplementation of curl's `doh_req_encode`. The
/// produced bytes are:
///
/// * a fixed 12-byte header `00 00 | 01 00 | 00 01 | 00 00 | 00 00 | 00 00`
///   (transaction `ID = 0`; `RD` bit set; `QDCOUNT = 1`; all other counts 0);
/// * the `QNAME`: each dot-separated label as a single length byte (which MUST
///   be in `1..=63`) followed by the label bytes, terminated by a `0x00` root
///   label;
/// * the 2-byte `TYPE` (big-endian); and
/// * the 2-byte `CLASS` (`00 01`, i.e. `IN`).
///
/// curl computes `expected_len = 12 + 1 + hostlen + 4`, plus one more byte
/// unless `host` already ends with `.`; if that exceeds
/// [`DOH_MAX_DNSREQ_SIZE`] the name is rejected.
///
/// # Errors
///
/// * [`DohCode::DnsNameTooLong`] if the encoding would exceed
///   [`DOH_MAX_DNSREQ_SIZE`].
/// * [`DohCode::DnsBadLabel`] if any label is empty (e.g. a leading dot or two
///   consecutive dots) or longer than 63 octets.
///
/// A trailing dot is handled exactly as in curl: it terminates the name without
/// emitting a spurious zero-length label.
pub fn encode_query(host: &str, dnstype: DnsType) -> std::result::Result<Vec<u8>, DohCode> {
    let hostlen = host.len();

    // expected_len = 12 (header) + 1 (root label) + hostlen + 4 (TYPE+CLASS),
    // plus one more byte for the first label's length prefix unless the host
    // already ends with a dot (whose place that prefix takes). (← doh.c:106-108)
    let mut expected_len = 12 + 1 + hostlen + 4;
    if !host.ends_with('.') {
        expected_len += 1;
    }

    if expected_len > DOH_MAX_DNSREQ_SIZE {
        return Err(DohCode::DnsNameTooLong);
    }
    // With a growable `Vec` the "buffer too small" condition cannot occur; the
    // size cap above preserves curl's `DOH_TOO_SMALL_BUFFER`/length semantics.

    let mut dnsp: Vec<u8> = Vec::with_capacity(expected_len);

    // 12-byte header, written exactly as curl does (← doh.c:116-127).
    dnsp.extend_from_slice(&[
        0x00, 0x00, // transaction ID = 0
        0x01, 0x00, // flags: RD set (byte2 = 0x01); RA/Z/RCODE = 0 (byte3)
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
    ]);

    // QNAME: walk dot-separated labels exactly like curl's `strchr` loop
    // (← doh.c:130-150). A trailing dot leaves the cursor at end-of-string so
    // the loop terminates without emitting a zero-length label.
    let bytes = host.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let dot = bytes[pos..]
            .iter()
            .position(|&b| b == b'.')
            .map(|d| pos + d);
        let labellen = match dot {
            Some(d) => d - pos,
            None => bytes.len() - pos,
        };
        if labellen > 63 || labellen == 0 {
            // Label too long or empty -> error out (← doh.c:137-141).
            return Err(DohCode::DnsBadLabel);
        }
        // length byte + label bytes
        dnsp.push(labellen as u8);
        dnsp.extend_from_slice(&bytes[pos..pos + labellen]);
        pos += labellen;
        // advance past the dot, but only if there is one
        if dot.is_some() {
            pos += 1;
        }
    }

    // zero-length root label (← doh.c:152)
    dnsp.push(0x00);

    // TYPE, 2 bytes big-endian (← doh.c:154-156). Assigned codes can exceed
    // 255, so both octets are emitted from the full 16-bit value.
    let t = dnstype as u16;
    dnsp.push((t >> 8) as u8);
    dnsp.push((t & 0xff) as u8);

    // CLASS = IN (← doh.c:158-159)
    dnsp.push(0x00);
    dnsp.push(DNS_CLASS_IN);

    // curl `DEBUGASSERT(*olen == expected_len)` (← doh.c:165): a self-check on
    // the length estimate. The degenerate empty-host case (which curl guards
    // with `DEBUGASSERT(hostlen)`) is excluded.
    debug_assert!(host.is_empty() || dnsp.len() == expected_len);

    Ok(dnsp)
}

// ===========================================================================
// Decoded-entry accumulator (← doh.c `struct dohentry` / `struct dohaddr`)
// ===========================================================================

/// A decoded address record (← `doh.h` `struct dohaddr`). The bytes are stored
/// in network byte order exactly as copied from the response `RDATA`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DohAddr {
    /// An IPv4 address (`A` record, 4 octets).
    V4([u8; 4]),
    /// An IPv6 address (`AAAA` record, 16 octets).
    V6([u8; 16]),
}

/// Accumulates the decoded results of one or more DoH probe responses
/// (← `doh.c` `struct dohentry`). A single instance is shared across the IPv4
/// and IPv6 probe decodes so addresses accumulate in slot order.
#[derive(Debug)]
struct DohEntry {
    /// Stored addresses, capped at [`DOH_MAX_ADDR`] (excess silently ignored).
    addr: Vec<DohAddr>,
    /// Accumulated CNAME chains, capped at [`DOH_MAX_CNAME`].
    cname: Vec<DynBuf>,
    /// Minimum observed TTL across all answer records, initialized to
    /// `INT_MAX` (← `doh.c` `de_init`).
    ttl: u32,
}

impl DohEntry {
    /// Creates an empty entry with `ttl = INT_MAX` (← `de_init`, doh.c:702-709).
    fn new() -> Self {
        DohEntry {
            addr: Vec::new(),
            cname: Vec::new(),
            // INT_MAX (0x7FFF_FFFF); the running minimum-TTL sentinel.
            ttl: i32::MAX as u32,
        }
    }

    /// Stores an `A` record's 4 address octets, ignoring it once
    /// [`DOH_MAX_ADDR`] is reached (← `doh_store_a`, doh.c:564-574).
    fn store_a(&mut self, doh: &[u8], index: usize) {
        // silently ignore addresses over the limit
        if self.addr.len() < DOH_MAX_ADDR {
            if let Some(slice) = doh.get(index..index + 4) {
                if let Ok(octets) = <[u8; 4]>::try_from(slice) {
                    self.addr.push(DohAddr::V4(octets));
                }
            }
        }
    }

    /// Stores an `AAAA` record's 16 address octets, ignoring it once
    /// [`DOH_MAX_ADDR`] is reached (← `doh_store_aaaa`, doh.c:576-586).
    fn store_aaaa(&mut self, doh: &[u8], index: usize) {
        // silently ignore addresses over the limit
        if self.addr.len() < DOH_MAX_ADDR {
            if let Some(slice) = doh.get(index..index + 16) {
                if let Ok(octets) = <[u8; 16]>::try_from(slice) {
                    self.addr.push(DohAddr::V6(octets));
                }
            }
        }
    }
}

// ===========================================================================
// Phase B/C — response decoding (← doh.c:521-852)
// ===========================================================================

/// A cursor over a DoH response message, carrying the buffer and the current
/// read index (the safe analogue of curl's `doh`/`index` pair).
struct Decoder<'a> {
    doh: &'a [u8],
    index: usize,
}

impl Decoder<'_> {
    /// Bounds check: returns [`DohCode::DnsOutOfRange`] when fewer than `n`
    /// bytes remain at the current index (← curl's `dohlen < index + n`).
    fn need(&self, n: usize) -> std::result::Result<(), DohCode> {
        if self.doh.len() < self.index + n {
            Err(DohCode::DnsOutOfRange)
        } else {
            Ok(())
        }
    }

    /// Reads a big-endian `u16` at absolute offset `at`, bounds-checked
    /// (← `doh_get16bit`, doh.c:545-549). Header counts are read at fixed
    /// offsets `4/6/8/10`, which are always in range given `dohlen >= 12`.
    fn get16_at(&self, at: usize) -> std::result::Result<u16, DohCode> {
        if self.doh.len() < at + 2 {
            return Err(DohCode::DnsOutOfRange);
        }
        Ok((u16::from(self.doh[at]) << 8) | u16::from(self.doh[at + 1]))
    }

    /// Reads a big-endian `u32` at absolute offset `at`, bounds-checked
    /// (← `doh_get32bit`, doh.c:551-562).
    fn get32_at(&self, at: usize) -> std::result::Result<u32, DohCode> {
        if self.doh.len() < at + 4 {
            return Err(DohCode::DnsOutOfRange);
        }
        Ok((u32::from(self.doh[at]) << 24)
            | (u32::from(self.doh[at + 1]) << 16)
            | (u32::from(self.doh[at + 2]) << 8)
            | u32::from(self.doh[at + 3]))
    }

    /// Skips a (possibly compressed) `QNAME`, advancing the cursor past it
    /// (← `doh_skipqname`, doh.c:521-543).
    fn skipqname(&mut self) -> std::result::Result<(), DohCode> {
        loop {
            if self.doh.len() < self.index + 1 {
                return Err(DohCode::DnsOutOfRange);
            }
            let length = self.doh[self.index];
            if (length & 0xc0) == 0xc0 {
                // name pointer: advance over the two pointer bytes and stop.
                if self.doh.len() < self.index + 2 {
                    return Err(DohCode::DnsOutOfRange);
                }
                self.index += 2;
                break;
            }
            if length & 0xc0 != 0 {
                return Err(DohCode::DnsBadLabel);
            }
            if self.doh.len() < self.index + 1 + length as usize {
                return Err(DohCode::DnsOutOfRange);
            }
            self.index += 1 + length as usize;
            // curl loops `while(length)`: the zero-length root label ends it.
            if length == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Decodes a `CNAME` chain starting at `start`, dot-joining its labels into
    /// a [`DynBuf`] capped at [`DYN_DOH_CNAME`] and following compression
    /// pointers, with a 128-iteration loop guard (← `doh_store_cname`,
    /// doh.c:605-653).
    fn store_cname(&self, start: usize, out: &mut DohEntry) -> std::result::Result<(), DohCode> {
        // skip once the CNAME cap is reached (← doh.c:612-613)
        if out.cname.len() == DOH_MAX_CNAME {
            return Ok(());
        }

        let mut c = DynBuf::curlx_dyn_init(DYN_DOH_CNAME);
        let mut index = start;
        // a valid DNS name can never loop this much (← doh.c:609)
        let mut loop_guard: u32 = 128;

        loop {
            if index >= self.doh.len() {
                return Err(DohCode::DnsOutOfRange);
            }
            let length = self.doh[index];
            if (length & 0xc0) == 0xc0 {
                // compression pointer: jump to the 14-bit offset.
                if index + 1 >= self.doh.len() {
                    return Err(DohCode::DnsOutOfRange);
                }
                let newpos = ((usize::from(length & 0x3f)) << 8) | usize::from(self.doh[index + 1]);
                index = newpos;
                // curl's `continue` re-evaluates `while(length && --loop)`; the
                // pointer byte is non-zero, so the guard decrements on each jump.
                loop_guard -= 1;
                if loop_guard == 0 {
                    return Err(DohCode::DnsLabelLoop);
                }
                continue;
            } else if length & 0xc0 != 0 {
                return Err(DohCode::DnsBadLabel);
            }
            // ordinary label: consume the length byte.
            index += 1;

            if length != 0 {
                // dot-separate successive labels.
                if c.curlx_dyn_len() != 0 && c.curlx_dyn_addn(b".").is_err() {
                    return Err(DohCode::OutOfMem);
                }
                if index + length as usize > self.doh.len() {
                    return Err(DohCode::DnsBadLabel);
                }
                if c.curlx_dyn_addn(&self.doh[index..index + length as usize])
                    .is_err()
                {
                    return Err(DohCode::OutOfMem);
                }
                index += length as usize;
            }

            // curl `while(length && --loop)`: stop at the root label, else
            // decrement the guard and trip the loop limit if exhausted.
            if length == 0 {
                break;
            }
            loop_guard -= 1;
            if loop_guard == 0 {
                return Err(DohCode::DnsLabelLoop);
            }
        }

        out.cname.push(c);
        Ok(())
    }

    /// Dispatches one answer record's `RDATA` by `TYPE` (← `doh_rdata`,
    /// doh.c:655-700). `A`/`AAAA` require an exact `RDLENGTH`; `CNAME` is
    /// chased; `DNAME` and unsupported types (including HTTPS RR by default)
    /// are skipped.
    fn rdata(
        &self,
        rdlength: u16,
        type_val: u16,
        index: usize,
        out: &mut DohEntry,
    ) -> std::result::Result<(), DohCode> {
        if type_val == DnsType::A as u16 {
            if rdlength != 4 {
                return Err(DohCode::DnsRdataLen);
            }
            out.store_a(self.doh, index);
        } else if type_val == DnsType::Aaaa as u16 {
            if rdlength != 16 {
                return Err(DohCode::DnsRdataLen);
            }
            out.store_aaaa(self.doh, index);
        } else if type_val == DnsType::Cname as u16 {
            self.store_cname(index, out)?;
        } else if type_val == DnsType::Dname as u16 {
            // explicit for clarity: just skip; rely on the synthesized CNAME.
        } else if type_val == DnsType::Https as u16 {
            // HTTPS RR (TYPE 65): only handled under curl's `USE_HTTPSRR`, which
            // is off by default (no `httpsrr` Cargo feature). Skip, exactly as
            // curl's default build does (the case is compiled out there).
        } else {
            // unsupported type: just skip it.
        }
        Ok(())
    }
}

/// Decodes a DoH response message, accumulating addresses, CNAMEs, and the
/// minimum TTL into `out` (← `doh_resp_decode`, doh.c:711-852).
///
/// `dnstype` is the type that was queried; answer records must be that type,
/// `CNAME`, or `DNAME`. The decode walks the question, answer, authority, and
/// additional sections and verifies that the final cursor lands exactly at the
/// end of the message.
///
/// # Errors
///
/// Returns the matching [`DohCode`] for any malformation: a short buffer, a
/// non-zero transaction `ID` or `RCODE`, an out-of-range read, an unexpected
/// answer `TYPE`/`CLASS`, a bad `RDLENGTH`, a CNAME loop, trailing/garbage
/// bytes, or a response that stored nothing usable.
fn resp_decode(
    doh: &[u8],
    dnstype: DnsType,
    out: &mut DohEntry,
) -> std::result::Result<(), DohCode> {
    let dohlen = doh.len();

    if dohlen < 12 {
        return Err(DohCode::TooSmallBuffer);
    }
    // transaction ID must be zero (curl always sends ID = 0).
    if doh[0] != 0 || doh[1] != 0 {
        return Err(DohCode::DnsBadId);
    }
    let rcode = doh[3] & 0x0f;
    if rcode != 0 {
        return Err(DohCode::DnsBadRcode);
    }

    let want = dnstype as u16;
    // curl declares `type = 0`; it survives the answer loop and feeds the
    // final "no content" test, so the last answer's TYPE (or 0) is retained.
    let mut last_type: u16 = 0;
    let mut dec = Decoder { doh, index: 12 };

    // -- question section (QDCOUNT @ offset 4) -----------------------------
    let mut qdcount = dec.get16_at(4)?;
    while qdcount > 0 {
        dec.skipqname()?;
        dec.need(4)?; // skip question TYPE + CLASS
        dec.index += 4;
        qdcount -= 1;
    }

    // -- answer section (ANCOUNT @ offset 6) -------------------------------
    let mut ancount = dec.get16_at(6)?;
    while ancount > 0 {
        dec.skipqname()?;

        let type_val = dec.get16_at(dec.index)?;
        if type_val != DnsType::Cname as u16
            && type_val != DnsType::Dname as u16
            && type_val != want
        {
            return Err(DohCode::DnsUnexpectedType);
        }
        last_type = type_val;
        dec.index += 2;

        let dnsclass = dec.get16_at(dec.index)?;
        if dnsclass != u16::from(DNS_CLASS_IN) {
            return Err(DohCode::DnsUnexpectedClass);
        }
        dec.index += 2;

        let ttl = dec.get32_at(dec.index)?;
        if ttl < out.ttl {
            out.ttl = ttl;
        }
        dec.index += 4;

        let rdlength = dec.get16_at(dec.index)?;
        dec.index += 2;
        dec.need(rdlength as usize)?;

        dec.rdata(rdlength, type_val, dec.index, out)?;
        dec.index += rdlength as usize;
        ancount -= 1;
    }

    // -- authority section (NSCOUNT @ offset 8) ----------------------------
    let mut nscount = dec.get16_at(8)?;
    while nscount > 0 {
        dec.skipqname()?;
        dec.need(8)?; // skip TYPE + CLASS + TTL
        dec.index += 2 + 2 + 4;
        let rdlength = dec.get16_at(dec.index)?;
        dec.index += 2;
        dec.need(rdlength as usize)?;
        dec.index += rdlength as usize;
        nscount -= 1;
    }

    // -- additional section (ARCOUNT @ offset 10) --------------------------
    let mut arcount = dec.get16_at(10)?;
    while arcount > 0 {
        dec.skipqname()?;
        dec.need(8)?; // skip TYPE + CLASS + TTL
        dec.index += 2 + 2 + 4;
        let rdlength = dec.get16_at(dec.index)?;
        dec.index += 2;
        dec.need(rdlength as usize)?;
        dec.index += rdlength as usize;
        arcount -= 1;
    }

    // every byte must be accounted for (← doh.c:839-840)
    if dec.index != dohlen {
        return Err(DohCode::DnsMalformat);
    }

    // "nothing stored" check (← doh.c:846; the `USE_HTTTPS` typo means curl's
    // `#else` branch — without the HTTPS-RR term — always compiles).
    if last_type != DnsType::Ns as u16 && out.cname.is_empty() && out.addr.is_empty() {
        return Err(DohCode::NoContent);
    }

    Ok(())
}

// ===========================================================================
// Phase D/E — probe orchestration, verbose display & result assembly
// ===========================================================================

/// Human-readable name for a DNS `TYPE`, used in verbose diagnostics
/// (← curl's `doh_type2name`).
fn type_name(t: DnsType) -> &'static str {
    match t {
        DnsType::A => "A",
        DnsType::Ns => "NS",
        DnsType::Cname => "CNAME",
        DnsType::Aaaa => "AAAA",
        DnsType::Dname => "DNAME",
        DnsType::Https => "HTTPS",
    }
}

/// Emits the decoded entry as verbose `[DoH] …` lines (← `doh_show`,
/// doh.c:854-897). A no-op unless `verbose` is set.
fn doh_show(verbose: bool, d: &DohEntry) {
    if !verbose {
        return;
    }
    crate::infof!(verbose, "[DoH] TTL: {} seconds", d.ttl);
    for a in &d.addr {
        match a {
            DohAddr::V4(b) => {
                crate::infof!(verbose, "[DoH] A: {}.{}.{}.{}", b[0], b[1], b[2], b[3]);
            }
            DohAddr::V6(b) => {
                use std::fmt::Write as _;
                // Render as eight colon-separated 16-bit groups, matching curl's
                // "%s%02x%02x" loop. `write!` to a `String` is infallible.
                let mut s = String::from("[DoH] AAAA: ");
                for (k, pair) in b.chunks_exact(2).enumerate() {
                    if k != 0 {
                        s.push(':');
                    }
                    let _ = write!(s, "{:02x}{:02x}", pair[0], pair[1]);
                }
                crate::infof!(verbose, "{}", s);
            }
        }
    }
    for c in &d.cname {
        // CNAME labels are ASCII DNS names; lossy is a safe display fallback.
        let name = String::from_utf8_lossy(c.curlx_dyn_ptr());
        crate::infof!(verbose, "CNAME: {}", name);
    }
}

/// Processes one probe's transport result into a decode outcome, accumulating
/// any decoded records into `de`.
///
/// Mirrors curl's `doh_probe_done` + `Curl_doh_is_resolved` slot handling: a
/// transport failure (or a response larger than [`DYN_DOH_RESPONSE`], which
/// curl rejects in the response write callback) leaves the slot **skipped** —
/// reported as `Ok(())` so it does not, by itself, fail the resolve (the
/// address-count gate decides that). A delivered response is decoded and its
/// [`DohCode`] result returned.
fn decode_probe(
    res: Result<Vec<u8>>,
    dnstype: DnsType,
    host: &str,
    opts: &DohOptions,
    de: &mut DohEntry,
) -> std::result::Result<(), DohCode> {
    match res {
        Ok(body) => {
            // curl appends the body to a `resp_body` dynbuf capped at
            // DYN_DOH_RESPONSE; an oversize response fails the write callback,
            // and thus the probe. Enforce the same cap (skip on overflow).
            if body.len() > DYN_DOH_RESPONSE {
                crate::infof!(
                    opts.verbose,
                    "[DoH] {} response too large ({} bytes) for {}",
                    type_name(dnstype),
                    body.len(),
                    host
                );
                return Ok(());
            }
            let rc = resp_decode(&body, dnstype, de);
            if let Err(code) = rc {
                crate::infof!(
                    opts.verbose,
                    "[DoH] {} (type {}) for {}",
                    code,
                    type_name(dnstype),
                    host
                );
            }
            rc
        }
        Err(e) => {
            crate::infof!(
                opts.verbose,
                "[DoH] {} request failed for {}: {}",
                type_name(dnstype),
                host,
                e
            );
            Ok(())
        }
    }
}

/// Runs the DoH probes for `host` against `doh_url` and assembles the resolved
/// addresses (← `Curl_doh` + `Curl_doh_is_resolved`, doh.c:435-519, 1199-1295).
///
/// The IPv4 (`A`) probe is always issued. The IPv6 (`AAAA`) probe is issued
/// when IPv6 is built in (the `ipv6` feature — curl's `USE_IPV6` +
/// `Curl_ipv6works`) and `ip_version` is not [`IpVersion::V4`]; note that the
/// `A` probe still runs for IPv6-only and "any" requests, exactly as curl does.
/// Probes are driven concurrently and decoded into one shared accumulator in
/// slot order, so addresses appear in curl's `doh2ai` order (IPv4 then IPv6).
/// Family selection for the final connection is left to the caller, matching
/// curl (whose `doh2ai` returns every resolved address regardless of family).
///
/// The HTTPS round-trip is delegated to `transport`; `opts` carries the
/// inherited SSL configuration and the verbose flag.
///
/// # Errors
///
/// Returns [`CurlError::CouldntResolveHost`] if the host name cannot be encoded,
/// if both probed slots decode with errors, or if no usable address was
/// obtained (curl's `doh2ai` `!numaddr` gate).
pub async fn run_probes(
    transport: &dyn DohTransport,
    doh_url: &str,
    host: &str,
    port: u16,
    ip_version: IpVersion,
    opts: &DohOptions,
) -> Result<ResolvedAddrs> {
    // Encode the mandatory A (IPv4) query (← Curl_doh always probes A).
    let a_body = encode_query(host, DnsType::A).map_err(|code| {
        crate::infof!(
            opts.verbose,
            "[DoH] failed to encode A query for {}: {}",
            host,
            code
        );
        CurlError::CouldntResolveHost
    })?;

    // IPv6 (AAAA) probe gating (← doh.c:482-493).
    let do_aaaa = cfg!(feature = "ipv6") && ip_version != IpVersion::V4;
    let aaaa_body = if do_aaaa {
        Some(encode_query(host, DnsType::Aaaa).map_err(|code| {
            crate::infof!(
                opts.verbose,
                "[DoH] failed to encode AAAA query for {}: {}",
                host,
                code
            );
            CurlError::CouldntResolveHost
        })?)
    } else {
        None
    };

    // Build and dispatch the probe requests concurrently.
    let a_fut = transport.send(DohProbeRequest {
        url: doh_url.to_string(),
        body: a_body,
        content_type: DOH_CONTENT_TYPE,
        ssl: opts.ssl.clone(),
    });

    let aaaa_fut: futures_util::future::OptionFuture<_> = aaaa_body
        .map(|body| {
            transport.send(DohProbeRequest {
                url: doh_url.to_string(),
                body,
                content_type: DOH_CONTENT_TYPE,
                ssl: opts.ssl.clone(),
            })
        })
        .into();

    let (a_res, aaaa_res) = futures_util::future::join(a_fut, aaaa_fut).await;

    // Decode into one shared entry, in slot order (IPv4 then IPv6).
    let mut de = DohEntry::new();
    // curl `memset(rc, 0, ...)`: unprobed / transport-failed slots stay DOH_OK.
    let mut rc: [std::result::Result<(), DohCode>; 2] = [Ok(()), Ok(())];

    rc[DOH_SLOT_IPV4] = decode_probe(a_res, DnsType::A, host, opts, &mut de);
    if do_aaaa {
        if let Some(res) = aaaa_res {
            rc[DOH_SLOT_IPV6] = decode_probe(res, DnsType::Aaaa, host, opts, &mut de);
        }
    }

    // curl: `result = COULDNT_RESOLVE_HOST; if(!rc[IPV4] || !rc[IPV6]) {…}` —
    // proceed unless BOTH probed slots decoded with an error (← doh.c:1240-1241).
    if rc[DOH_SLOT_IPV4].is_err() && rc[DOH_SLOT_IPV6].is_err() {
        return Err(CurlError::CouldntResolveHost);
    }

    doh_show(opts.verbose, &de);

    // curl `doh2ai`: no addresses -> COULDNT_RESOLVE_HOST (← doh.c:931-932).
    if de.addr.is_empty() {
        return Err(CurlError::CouldntResolveHost);
    }

    // Convert the stored records (network byte order) into socket addresses,
    // applying the query port (← doh.c:982-994).
    let mut addrs: Vec<SocketAddr> = Vec::with_capacity(de.addr.len());
    for a in &de.addr {
        let ip = match a {
            DohAddr::V4(b) => IpAddr::V4(Ipv4Addr::from(*b)),
            DohAddr::V6(b) => IpAddr::V6(Ipv6Addr::from(*b)),
        };
        addrs.push(SocketAddr::new(ip, port));
    }

    Ok(ResolvedAddrs::from_vec(addrs))
}

/// Resolves `host`/`port` via DNS-over-HTTPS, the resolver-interface entry point
/// invoked by [`crate::dns::resolve`] when a `CURLOPT_DOH_URL` is configured.
///
/// This obtains the process-wide [`DohTransport`] installed by the transfer
/// engine (which wires `crate::protocols::http` + `crate::tls`) and drives the
/// probes via [`run_probes`] with default [`DohOptions`] (certificate
/// validation on, non-verbose). The engine may instead call [`run_probes`]
/// directly to supply per-transfer SSL inheritance and verbosity.
///
/// # Errors
///
/// Returns [`CurlError::CouldntResolveHost`] if no transport is installed (DoH
/// is unavailable — analogous to curl requiring the multi/transfer machinery)
/// or if the resolve fails (see [`run_probes`]). The caller
/// ([`crate::dns::resolve`]) treats this as the signal to record a negative
/// cache entry.
pub async fn resolve(
    doh_url: &str,
    host: &str,
    port: u16,
    ip_version: IpVersion,
) -> Result<ResolvedAddrs> {
    let Some(transport) = installed_transport() else {
        return Err(CurlError::CouldntResolveHost);
    };
    let opts = DohOptions::default();
    run_probes(transport.as_ref(), doh_url, host, port, ip_version, &opts).await
}

// ===========================================================================
// Tests — round-trip parity against hand-built C-oracle wire vectors.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- shared wire vectors --------------------------------------------

    /// A valid `A` response for `example.com` -> `1.2.3.4`, TTL 300, using a
    /// compression pointer for the answer NAME (45 bytes).
    fn a_response() -> Vec<u8> {
        vec![
            // header: ID=0, flags=0x8180 (QR|RD|RA), QD=1, AN=1, NS=0, AR=0
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            // question QNAME: 7"example" 3"com" 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
            // answer: NAME=ptr(12), TYPE=A, CLASS=IN, TTL=300, RDLENGTH=4, RDATA
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x01, 0x02,
            0x03, 0x04,
        ]
    }

    /// A valid `AAAA` response for `example.com` -> `2001:db8::1`, TTL 300 (57
    /// bytes).
    fn aaaa_response() -> Vec<u8> {
        vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x1c, // QTYPE = AAAA
            0x00, 0x01, // QCLASS = IN
            0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x10,
            // RDATA = 2001:0db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]
    }

    // ---- Phase A: encoding ----------------------------------------------

    #[test]
    fn encode_example_com_a_exact_bytes() {
        let got = encode_query("example.com", DnsType::A).expect("encode");
        let want: Vec<u8> = vec![
            0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // 7 "example"
            0x03, b'c', b'o', b'm', // 3 "com"
            0x00, // root
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn encode_trailing_dot_matches_undotted() {
        // A trailing dot must not emit a spurious zero-length label.
        let dotted = encode_query("example.com.", DnsType::A).expect("encode");
        let plain = encode_query("example.com", DnsType::A).expect("encode");
        assert_eq!(dotted, plain);
    }

    #[test]
    fn encode_aaaa_type_bytes() {
        let got = encode_query("a.test", DnsType::Aaaa).expect("encode");
        // last four bytes are TYPE (00 1c = 28) then CLASS (00 01 = IN)
        let n = got.len();
        assert_eq!(&got[n - 4..], &[0x00, 0x1c, 0x00, 0x01]);
    }

    #[test]
    fn encode_label_too_long_is_bad_label() {
        let host = format!("{}.com", "a".repeat(64)); // 64 > 63
        assert_eq!(encode_query(&host, DnsType::A), Err(DohCode::DnsBadLabel));
    }

    #[test]
    fn encode_leading_dot_is_bad_label() {
        assert_eq!(
            encode_query(".example.com", DnsType::A),
            Err(DohCode::DnsBadLabel)
        );
    }

    #[test]
    fn encode_double_dot_is_bad_label() {
        assert_eq!(encode_query("a..b", DnsType::A), Err(DohCode::DnsBadLabel));
    }

    #[test]
    fn encode_name_too_long() {
        let label = "a".repeat(63);
        // four max labels + 3 dots = 255 chars -> expected_len 273 > 272
        let host = format!("{label}.{label}.{label}.{label}");
        assert_eq!(host.len(), 255);
        assert_eq!(
            encode_query(&host, DnsType::A),
            Err(DohCode::DnsNameTooLong)
        );
    }

    // ---- Phase B/C: decoding (happy paths) ------------------------------

    #[test]
    fn decode_a_record() {
        let mut de = DohEntry::new();
        resp_decode(&a_response(), DnsType::A, &mut de).expect("decode");
        assert_eq!(de.addr, vec![DohAddr::V4([1, 2, 3, 4])]);
        assert_eq!(de.ttl, 300);
        assert!(de.cname.is_empty());
    }

    #[test]
    fn decode_aaaa_record() {
        let mut de = DohEntry::new();
        resp_decode(&aaaa_response(), DnsType::Aaaa, &mut de).expect("decode");
        assert_eq!(
            de.addr,
            vec![DohAddr::V6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ])]
        );
        assert_eq!(de.ttl, 300);
    }

    #[test]
    fn decode_cname_then_a() {
        // Query A for www.example.com; answer 1 = CNAME -> example.com,
        // answer 2 = A example.com -> 5.6.7.8. (63 bytes)
        let doh: Vec<u8> = vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            // QNAME www.example.com
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
            // answer 1: NAME=ptr(12), CNAME, IN, TTL=300, RDLEN=2, RDATA=ptr(16)
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x02, 0xc0, 0x10,
            // answer 2: NAME=ptr(16), A, IN, TTL=300, RDLEN=4, RDATA=5.6.7.8
            0xc0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];
        let mut de = DohEntry::new();
        resp_decode(&doh, DnsType::A, &mut de).expect("decode");
        assert_eq!(de.addr, vec![DohAddr::V4([5, 6, 7, 8])]);
        assert_eq!(de.cname.len(), 1);
        assert_eq!(de.cname[0].curlx_dyn_ptr(), b"example.com");
        assert_eq!(de.ttl, 300);
    }

    #[test]
    fn decode_min_ttl_tracked() {
        // Two A answers with TTL 500 then 100; the minimum (100) must win.
        let doh: Vec<u8> = vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, // answer 1: A, TTL=500, 1.1.1.1
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0xf4, 0x00, 0x04, 0x01, 0x01,
            0x01, 0x01, // answer 2: A, TTL=100, 2.2.2.2
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0x00, 0x04, 0x02, 0x02,
            0x02, 0x02,
        ];
        let mut de = DohEntry::new();
        resp_decode(&doh, DnsType::A, &mut de).expect("decode");
        assert_eq!(
            de.addr,
            vec![DohAddr::V4([1, 1, 1, 1]), DohAddr::V4([2, 2, 2, 2])]
        );
        assert_eq!(de.ttl, 100);
    }

    // ---- Phase B/C: decoding (error paths) ------------------------------

    #[test]
    fn decode_too_small_buffer() {
        let mut de = DohEntry::new();
        assert_eq!(
            resp_decode(&[0u8; 5], DnsType::A, &mut de),
            Err(DohCode::TooSmallBuffer)
        );
    }

    #[test]
    fn decode_bad_id() {
        let mut doh = a_response();
        doh[0] = 0x12; // non-zero transaction ID
        let mut de = DohEntry::new();
        assert_eq!(
            resp_decode(&doh, DnsType::A, &mut de),
            Err(DohCode::DnsBadId)
        );
    }

    #[test]
    fn decode_bad_rcode() {
        let mut doh = a_response();
        doh[3] = 0x83; // RCODE = 3 (NXDOMAIN) in the low nibble
        let mut de = DohEntry::new();
        assert_eq!(
            resp_decode(&doh, DnsType::A, &mut de),
            Err(DohCode::DnsBadRcode)
        );
    }

    #[test]
    fn decode_unexpected_type() {
        let mut doh = a_response();
        // answer TYPE at offsets 31..33 -> set to NS (2): not A/CNAME/DNAME
        doh[31] = 0x00;
        doh[32] = 0x02;
        let mut de = DohEntry::new();
        assert_eq!(
            resp_decode(&doh, DnsType::A, &mut de),
            Err(DohCode::DnsUnexpectedType)
        );
    }

    #[test]
    fn decode_unexpected_class() {
        let mut doh = a_response();
        // answer CLASS at offsets 33..35 -> set to 2 (not IN)
        doh[33] = 0x00;
        doh[34] = 0x02;
        let mut de = DohEntry::new();
        assert_eq!(
            resp_decode(&doh, DnsType::A, &mut de),
            Err(DohCode::DnsUnexpectedClass)
        );
    }

    #[test]
    fn decode_out_of_range() {
        // Drop the final RDATA byte: rdlength=4 but only 3 bytes remain.
        let mut doh = a_response();
        doh.pop();
        let mut de = DohEntry::new();
        assert_eq!(
            resp_decode(&doh, DnsType::A, &mut de),
            Err(DohCode::DnsOutOfRange)
        );
    }

    #[test]
    fn decode_trailing_garbage_is_malformat() {
        let mut doh = a_response();
        doh.push(0xff); // one extra byte after a complete message
        let mut de = DohEntry::new();
        assert_eq!(
            resp_decode(&doh, DnsType::A, &mut de),
            Err(DohCode::DnsMalformat)
        );
    }

    #[test]
    fn decode_no_content() {
        // QDCOUNT=1, ANCOUNT=0: a question, but no answer records.
        let doh: Vec<u8> = vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let mut de = DohEntry::new();
        assert_eq!(
            resp_decode(&doh, DnsType::A, &mut de),
            Err(DohCode::NoContent)
        );
    }

    #[test]
    fn decode_bad_label_high_bits() {
        // A QNAME byte with the 10xxxxxx pattern is an invalid label.
        let doh: Vec<u8> = vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x80, // bad label in the question name
        ];
        let mut de = DohEntry::new();
        assert_eq!(
            resp_decode(&doh, DnsType::A, &mut de),
            Err(DohCode::DnsBadLabel)
        );
    }

    #[test]
    fn decode_cname_compression_loop() {
        // Answer is a CNAME whose RDATA is a compression pointer to itself,
        // which must trip the 128-iteration guard.
        let doh: Vec<u8> = vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, b'a',
            0x00, // QNAME "a"
            0x00, 0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
            // answer: NAME=ptr(12), CNAME, IN, TTL, RDLEN=2, RDATA=ptr(31 -> self)
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x02, 0xc0, 0x1f,
        ];
        let mut de = DohEntry::new();
        assert_eq!(
            resp_decode(&doh, DnsType::A, &mut de),
            Err(DohCode::DnsLabelLoop)
        );
    }

    #[test]
    fn doh_strerror_matches_table() {
        assert_eq!(DohCode::Ok.strerror(), "");
        assert_eq!(DohCode::DnsBadLabel.strerror(), "Bad label");
        assert_eq!(DohCode::DnsNameTooLong.strerror(), "Name too long");
        assert_eq!(DohCode::NoContent.to_string(), "No content");
    }

    // ---- Phase D/E: probe orchestration via a mock transport ------------

    /// A test [`DohTransport`] that returns canned responses keyed by the query
    /// `TYPE` (read from the request body) and records every request it sees.
    struct MockTransport {
        a: Option<Result<Vec<u8>>>,
        aaaa: Option<Result<Vec<u8>>>,
        seen: std::sync::Mutex<Vec<DohProbeRequest>>,
    }

    impl MockTransport {
        fn new(a: Option<Result<Vec<u8>>>, aaaa: Option<Result<Vec<u8>>>) -> Self {
            MockTransport {
                a,
                aaaa,
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl DohTransport for MockTransport {
        fn send<'a>(
            &'a self,
            req: DohProbeRequest,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>> {
            // The query TYPE is the two bytes preceding the final CLASS.
            let n = req.body.len();
            let type_val = if n >= 4 {
                (u16::from(req.body[n - 4]) << 8) | u16::from(req.body[n - 3])
            } else {
                0
            };
            let resp = match type_val {
                x if x == DnsType::A as u16 => self.a.clone(),
                x if x == DnsType::Aaaa as u16 => self.aaaa.clone(),
                _ => None,
            }
            .unwrap_or(Err(CurlError::CouldntResolveHost));
            self.seen.lock().expect("seen lock").push(req);
            Box::pin(async move { resp })
        }
    }

    #[tokio::test]
    async fn run_probes_happy_a_only() {
        let mock = MockTransport::new(Some(Ok(a_response())), None);
        let opts = DohOptions::default();
        let got = run_probes(
            &mock,
            "https://doh.example/dns-query",
            "example.com",
            80,
            IpVersion::V4,
            &opts,
        )
        .await
        .expect("resolve");
        assert_eq!(got.addrs, vec!["1.2.3.4:80".parse().unwrap()]);

        // Exactly one (A) probe was issued, with the right URL / media type /
        // body / inherited (default) SSL config.
        let seen = mock.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].url, "https://doh.example/dns-query");
        assert_eq!(seen[0].content_type, DOH_CONTENT_TYPE);
        assert_eq!(
            seen[0].body,
            encode_query("example.com", DnsType::A).unwrap()
        );
        assert_eq!(seen[0].ssl, DohSslConfig::default());
    }

    #[cfg(feature = "ipv6")]
    #[tokio::test]
    async fn run_probes_dual_stack_orders_v4_then_v6() {
        let mock = MockTransport::new(Some(Ok(a_response())), Some(Ok(aaaa_response())));
        let opts = DohOptions::default();
        let got = run_probes(
            &mock,
            "https://doh.example/dns-query",
            "example.com",
            443,
            IpVersion::Any,
            &opts,
        )
        .await
        .expect("resolve");
        assert_eq!(
            got.addrs,
            vec![
                "1.2.3.4:443".parse().unwrap(),
                "[2001:db8::1]:443".parse().unwrap(),
            ]
        );
        assert_eq!(mock.seen.lock().unwrap().len(), 2);
    }

    #[cfg(feature = "ipv6")]
    #[tokio::test]
    async fn run_probes_v6_request_still_probes_a() {
        // For an IPv6-only request, curl still issues the A probe; with only an
        // A answer available, that address is returned.
        let mock = MockTransport::new(Some(Ok(a_response())), Some(Ok(aaaa_response())));
        let opts = DohOptions::default();
        let got = run_probes(
            &mock,
            "https://doh.example/dns-query",
            "example.com",
            80,
            IpVersion::V6,
            &opts,
        )
        .await
        .expect("resolve");
        // Both probes run for V6; both families appear (family selection is the
        // caller's job, matching curl's doh2ai).
        assert!(got.addrs.contains(&"1.2.3.4:80".parse().unwrap()));
        assert_eq!(mock.seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn run_probes_nxdomain_is_couldnt_resolve() {
        let mut bad = a_response();
        bad[3] = 0x83; // RCODE = 3 -> decode fails with DnsBadRcode
        let mock = MockTransport::new(Some(Ok(bad)), None);
        let opts = DohOptions::default();
        let err = run_probes(
            &mock,
            "https://doh.example/dns-query",
            "example.com",
            80,
            IpVersion::V4,
            &opts,
        )
        .await
        .unwrap_err();
        assert_eq!(err, CurlError::CouldntResolveHost);
    }

    #[tokio::test]
    async fn run_probes_transport_error_is_couldnt_resolve() {
        let mock = MockTransport::new(Some(Err(CurlError::CouldntResolveHost)), None);
        let opts = DohOptions::default();
        let err = run_probes(
            &mock,
            "https://doh.example/dns-query",
            "example.com",
            80,
            IpVersion::V4,
            &opts,
        )
        .await
        .unwrap_err();
        assert_eq!(err, CurlError::CouldntResolveHost);
    }

    #[tokio::test]
    async fn run_probes_empty_answer_is_couldnt_resolve() {
        // A well-formed response that stores nothing decodes to NoContent, which
        // yields no addresses and thus a resolve failure.
        let no_content: Vec<u8> = vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let mock = MockTransport::new(Some(Ok(no_content)), None);
        let opts = DohOptions::default();
        let err = run_probes(
            &mock,
            "https://doh.example/dns-query",
            "example.com",
            80,
            IpVersion::V4,
            &opts,
        )
        .await
        .unwrap_err();
        assert_eq!(err, CurlError::CouldntResolveHost);
    }

    #[tokio::test]
    async fn run_probes_oversize_response_skipped() {
        // A response larger than DYN_DOH_RESPONSE is rejected (probe skipped),
        // leaving no addresses -> COULDNT_RESOLVE_HOST.
        let mut huge = a_response();
        huge.resize(DYN_DOH_RESPONSE + 1, 0x00);
        let mock = MockTransport::new(Some(Ok(huge)), None);
        let opts = DohOptions::default();
        let err = run_probes(
            &mock,
            "https://doh.example/dns-query",
            "example.com",
            80,
            IpVersion::V4,
            &opts,
        )
        .await
        .unwrap_err();
        assert_eq!(err, CurlError::CouldntResolveHost);
    }

    #[tokio::test]
    async fn resolve_uses_installed_transport() {
        // The only test that touches the process-wide transport slot. Installing
        // succeeds at most once; this is the sole installer, so it wins.
        let mock = Arc::new(MockTransport::new(Some(Ok(a_response())), None));
        assert!(install_transport(mock));
        assert!(installed_transport().is_some());

        let got = resolve(
            "https://doh.example/dns-query",
            "example.com",
            80,
            IpVersion::V4,
        )
        .await
        .expect("resolve");
        assert_eq!(got.addrs, vec!["1.2.3.4:80".parse().unwrap()]);
    }
}
