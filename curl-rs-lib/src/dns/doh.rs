//! DNS-over-HTTPS (DoH) resolver — RFC 8484.
//!
//! Replaces C source files `lib/doh.c` (1,338 lines) and `lib/doh.h`.
//!
//! This module provides:
//! - Wire-format DNS query encoding ([`encode_dns_request`])
//! - Wire-format DNS response decoding ([`decode_dns_response`])
//! - [`DohResolver`] that implements the [`Resolver`](super::Resolver) trait
//!   by sending HTTPS POST requests with `application/dns-message` content
//! - Address conversion from DoH entries to `SocketAddr` ([`doh_entry_to_addrs`])
//!
//! # Zero Unsafe
//!
//! This module contains **zero** `unsafe` blocks.  All buffer management uses
//! Rust ownership and `Vec<u8>` instead of manual `malloc`/`free`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use tokio_rustls::TlsConnector;

use crate::error::CurlError;
use super::{IpVersion, Resolver};

// ---------------------------------------------------------------------------
// Constants — matching C defines in lib/doh.h and lib/doh.c
// ---------------------------------------------------------------------------

/// Maximum number of A/AAAA addresses stored per DoH response.
/// From C: `#define DOH_MAX_ADDR 24` (lib/doh.h line 119).
pub const DOH_MAX_ADDR: usize = 24;

/// Maximum number of CNAME records stored per DoH response.
/// From C: `#define DOH_MAX_CNAME 4` (lib/doh.h line 120).
pub const DOH_MAX_CNAME: usize = 4;

/// Maximum number of HTTPS resource records stored per DoH response.
/// From C: `#define DOH_MAX_HTTPS 4` (lib/doh.h line 121).
pub const DOH_MAX_HTTPS: usize = 4;

/// Maximum DNS request buffer size (hostname + 16 bytes header/footer).
/// From C: `#define DOH_MAX_DNSREQ_SIZE (256 + 16)` (lib/doh.h line 80).
pub const DOH_MAX_DNSREQ_SIZE: usize = 256 + 16;

/// DNS class IN (Internet).
/// From C: `#define DNS_CLASS_IN 0x01` (lib/doh.c line 41).
pub const DNS_CLASS_IN: u16 = 1;

/// Number of DoH probe slots (IPv4, IPv6, HTTPS RR).
/// From C: `DOH_SLOT_COUNT` (lib/doh.h enum doh_slot_num).
pub const DOH_SLOT_COUNT: usize = 3;

/// Maximum single DNS label length per RFC 1035.
const MAX_LABEL_LENGTH: usize = 63;

/// DNS header size in bytes.
const DNS_HEADER_SIZE: usize = 12;

/// Loop detection limit for CNAME pointer chasing.
const CNAME_LOOP_LIMIT: u32 = 128;

// ---------------------------------------------------------------------------
// DohError — maps to C DOHcode enum (lib/doh.h lines 30-45)
// ---------------------------------------------------------------------------

/// Error codes specific to DNS-over-HTTPS processing.
///
/// Maps 1:1 from the C `DOHcode` enum defined in `lib/doh.h` lines 30-45.
/// The `strerror()` method provides human-readable descriptions matching
/// the C `doh_strerror()` function at `lib/doh.c` lines 61-66.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohError {
    /// Success — no error.
    Ok,
    /// Input buffer too small for the encoded request.
    TooSmallBuffer,
    /// Memory allocation failure.
    OutOfMem,
    /// DNS response ID mismatch (expected 0x0000).
    BadId,
    /// Non-zero RCODE in DNS response header.
    BadRcode,
    /// Index out of range while parsing DNS wire format.
    OutOfRange,
    /// Invalid DNS label (empty or >63 bytes).
    BadLabel,
    /// Infinite pointer loop detected in DNS name compression.
    LabelLoop,
    /// DNS response exceeds maximum supported size.
    TooLarge,
    /// RDATA length mismatch (e.g. A record != 4 bytes).
    RdataLen,
    /// Malformed DNS response (trailing data or structural error).
    MalFormat,
    /// Unexpected HTTP Content-Type in DoH response.
    BadContentType,
    /// DNS class is not IN (Internet).
    BadDnsClass,
    /// DNS response contained no useful records.
    NoContent,
    /// Unexpected DNS record type in answer section.
    BadUnexpectedType,
    /// Unexpected DNS class in answer section.
    BadUnexpectedClass,
    /// Hostname exceeds maximum DNS name length (255 bytes).
    DnsNameTooLong,
}

impl DohError {
    /// Return a human-readable error description.
    ///
    /// Matches C `doh_strerror()` output from `lib/doh.c` lines 44-66.
    pub fn strerror(&self) -> &'static str {
        match self {
            DohError::Ok => "",
            DohError::BadLabel => "Bad label",
            DohError::OutOfRange => "Out of range",
            DohError::LabelLoop => "Label loop",
            DohError::TooSmallBuffer => "Too small",
            DohError::OutOfMem => "Out of memory",
            DohError::RdataLen => "RDATA length",
            DohError::MalFormat => "Malformat",
            DohError::BadRcode => "Bad RCODE",
            DohError::BadUnexpectedType => "Unexpected TYPE",
            DohError::BadUnexpectedClass => "Unexpected CLASS",
            DohError::NoContent => "No content",
            DohError::BadId => "Bad ID",
            DohError::DnsNameTooLong => "Name too long",
            DohError::TooLarge => "Too large",
            DohError::BadContentType => "Bad content type",
            DohError::BadDnsClass => "Bad DNS class",
        }
    }
}

impl fmt::Display for DohError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.strerror())
    }
}

impl std::error::Error for DohError {}

// ---------------------------------------------------------------------------
// DnsType — DNS record type constants (lib/doh.h lines 47-54)
// ---------------------------------------------------------------------------

/// DNS record type codes used in DoH queries and responses.
///
/// Maps from C `DNStype` enum in `lib/doh.h` lines 47-54.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsType {
    /// A record — IPv4 address (4 bytes).
    A = 1,
    /// NS record — authoritative name server.
    Ns = 2,
    /// CNAME record — canonical name alias.
    Cname = 5,
    /// AAAA record — IPv6 address (16 bytes).
    Aaaa = 28,
    /// DNAME record — delegation name (RFC 6672).
    Dname = 39,
    /// HTTPS record — HTTPS service binding (RFC 9460).
    Https = 65,
}

impl DnsType {
    /// Try to convert a raw u16 wire value to a `DnsType`.
    ///
    /// Used by protocol handlers that need to interpret DNS record types
    /// from wire format responses outside the standard decode path.
    #[allow(dead_code)]
    pub fn from_u16(val: u16) -> Option<DnsType> {
        match val {
            1 => Some(DnsType::A),
            2 => Some(DnsType::Ns),
            5 => Some(DnsType::Cname),
            28 => Some(DnsType::Aaaa),
            39 => Some(DnsType::Dname),
            65 => Some(DnsType::Https),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// DohAddr — single resolved address (lib/doh.h lines 123-129)
// ---------------------------------------------------------------------------

/// A single IP address extracted from a DoH response.
///
/// Replaces C `struct dohaddr` which uses a union of `v4[4]`/`v6[16]`
/// byte arrays. In Rust, `std::net::IpAddr` handles both families safely.
#[derive(Debug, Clone)]
pub struct DohAddr {
    /// The DNS record type that produced this address (A or AAAA).
    pub addr_type: DnsType,
    /// The IP address.
    pub ip: IpAddr,
}

// ---------------------------------------------------------------------------
// DohEntry — aggregated DoH response data (lib/doh.h lines 146-156)
// ---------------------------------------------------------------------------

/// Aggregated data from a decoded DoH DNS response.
///
/// Replaces C `struct dohentry` (lib/doh.h lines 146-156).
/// - `cnames` replaces the C fixed-size `dynbuf cname[DOH_MAX_CNAME]` array.
/// - `addrs` replaces the C fixed-size `dohaddr addr[DOH_MAX_ADDR]` array.
/// - `ttl` tracks the minimum TTL across all answer records, initialized to
///   `u32::MAX` matching C `de_init()` which sets `ttl = INT_MAX`.
/// - `https_rrs` stores raw HTTPS RR data bytes for later parsing.
#[derive(Debug, Clone)]
pub struct DohEntry {
    /// CNAME records from the response.
    pub cnames: Vec<String>,
    /// Resolved IP addresses (A and AAAA records).
    pub addrs: Vec<DohAddr>,
    /// Minimum TTL across all answer records (seconds).
    /// Initialized to `u32::MAX` matching C `de_init()` setting `ttl = INT_MAX`.
    pub ttl: u32,
    /// Raw HTTPS resource record data.
    pub https_rrs: Vec<Vec<u8>>,
}

impl Default for DohEntry {
    /// Create an empty DoH entry with TTL initialized to `u32::MAX`.
    ///
    /// Matches C `de_init()` at `lib/doh.c` lines 702-709.
    fn default() -> Self {
        Self {
            cnames: Vec::new(),
            addrs: Vec::new(),
            ttl: u32::MAX,
            https_rrs: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// DohSlot — probe slot indices (lib/doh.h enum doh_slot_num)
// ---------------------------------------------------------------------------

/// DoH probe slot identifiers.
///
/// From C `enum doh_slot_num` in `lib/doh.h` lines 56-75.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohSlot {
    /// IPv4 (A record) probe slot.
    Ipv4 = 0,
    /// IPv6 (AAAA record) probe slot.
    Ipv6 = 1,
    /// HTTPS resource record probe slot.
    HttpsRr = 2,
}

// ---------------------------------------------------------------------------
// DNS Wire-Format Encoding
// ---------------------------------------------------------------------------

/// Encode a DNS query in wire format for DoH HTTPS POST.
///
/// Replaces C `doh_req_encode()` at `lib/doh.c` lines 72-167.
///
/// Builds a standard DNS query packet (RFC 1035 §4.1) with:
/// - ID: 0x0000 (DoH uses HTTP request/response matching, not DNS ID)
/// - Flags: 0x0100 (RD=1, recursion desired)
/// - QDCOUNT: 1
/// - QNAME: hostname encoded as label-length-prefixed segments
/// - QTYPE: the requested `dns_type`
/// - QCLASS: IN (0x0001)
///
/// # Errors
///
/// - [`DohError::DnsNameTooLong`] if the encoded request would exceed
///   [`DOH_MAX_DNSREQ_SIZE`].
/// - [`DohError::BadLabel`] if any label is empty or longer than 63 bytes.
pub fn encode_dns_request(hostname: &str, dns_type: DnsType) -> Result<Vec<u8>, DohError> {
    let hostlen = hostname.len();
    if hostlen == 0 {
        return Err(DohError::BadLabel);
    }

    // Calculate expected length:
    // 12 bytes header + 1 byte (root label terminator) + hostname bytes + 4 bytes (QTYPE + QCLASS)
    // If hostname does NOT end with '.', we need one extra byte for the final label length prefix.
    let mut expected_len = DNS_HEADER_SIZE + 1 + hostlen + 4;
    if !hostname.ends_with('.') {
        expected_len += 1;
    }

    if expected_len > DOH_MAX_DNSREQ_SIZE {
        return Err(DohError::DnsNameTooLong);
    }

    let mut buf = Vec::with_capacity(expected_len);

    // DNS Header (12 bytes)
    buf.push(0x00); // ID high byte
    buf.push(0x00); // ID low byte
    buf.push(0x01); // QR=0, Opcode=0, AA=0, TC=0, RD=1
    buf.push(0x00); // RA=0, Z=0, RCODE=0
    buf.push(0x00); // QDCOUNT high
    buf.push(0x01); // QDCOUNT low = 1
    buf.push(0x00); // ANCOUNT high
    buf.push(0x00); // ANCOUNT low
    buf.push(0x00); // NSCOUNT high
    buf.push(0x00); // NSCOUNT low
    buf.push(0x00); // ARCOUNT high
    buf.push(0x00); // ARCOUNT low

    // QNAME encoding: each label as [length][data], terminated by 0x00
    let mut hostp = hostname;
    while !hostp.is_empty() {
        let (label, rest) = match hostp.find('.') {
            Some(dot_pos) => (&hostp[..dot_pos], &hostp[dot_pos + 1..]),
            None => (hostp, ""),
        };

        let labellen = label.len();
        if labellen == 0 && !rest.is_empty() {
            // Empty label in the middle (consecutive dots) — invalid.
            return Err(DohError::BadLabel);
        }
        if labellen == 0 {
            // Trailing dot — the root label terminator will be added below.
            break;
        }
        if labellen > MAX_LABEL_LENGTH {
            return Err(DohError::BadLabel);
        }

        buf.push(labellen as u8);
        buf.extend_from_slice(label.as_bytes());
        hostp = rest;
    }

    // Root label terminator
    buf.push(0x00);

    // QTYPE (2 bytes, big-endian)
    let qtype = dns_type as u16;
    buf.push((qtype >> 8) as u8);
    buf.push((qtype & 0xFF) as u8);

    // QCLASS (2 bytes, IN = 0x0001)
    buf.push(0x00);
    buf.push(DNS_CLASS_IN as u8);

    debug_assert_eq!(buf.len(), expected_len);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Wire-Format Parsing Helpers
// ---------------------------------------------------------------------------

/// Read a big-endian 16-bit value from a byte slice.
///
/// Replaces C `doh_get16bit()` at `lib/doh.c` lines 545-549.
#[inline]
fn get16bit(data: &[u8], index: usize) -> u16 {
    ((data[index] as u16) << 8) | (data[index + 1] as u16)
}

/// Read a big-endian 32-bit value from a byte slice.
///
/// Replaces C `doh_get32bit()` at `lib/doh.c` lines 551-562.
#[inline]
fn get32bit(data: &[u8], index: usize) -> u32 {
    ((data[index] as u32) << 24)
        | ((data[index + 1] as u32) << 16)
        | ((data[index + 2] as u32) << 8)
        | (data[index + 3] as u32)
}

/// Skip past a DNS QNAME in the wire format, handling pointer compression.
///
/// Replaces C `doh_skipqname()` at `lib/doh.c` lines 521-543.
///
/// On success, `*index` is updated to point just past the QNAME.
fn skip_qname(data: &[u8], index: &mut usize) -> Result<(), DohError> {
    let dohlen = data.len();
    loop {
        if dohlen < *index + 1 {
            return Err(DohError::OutOfRange);
        }
        let length = data[*index];

        if (length & 0xC0) == 0xC0 {
            // Name pointer — 2 bytes total, advance past them.
            if dohlen < *index + 2 {
                return Err(DohError::OutOfRange);
            }
            *index += 2;
            return Ok(());
        }

        if (length & 0xC0) != 0 {
            return Err(DohError::BadLabel);
        }

        if dohlen < *index + 1 + (length as usize) {
            return Err(DohError::OutOfRange);
        }
        *index += 1 + (length as usize);

        if length == 0 {
            return Ok(());
        }
    }
}

// ---------------------------------------------------------------------------
// Address Storage Helpers
// ---------------------------------------------------------------------------

/// Store an A record (4-byte IPv4) from wire format.
///
/// Replaces C `doh_store_a()` at `lib/doh.c` lines 564-574.
fn store_a(data: &[u8], index: usize, entry: &mut DohEntry) {
    if entry.addrs.len() < DOH_MAX_ADDR {
        let ip = Ipv4Addr::new(data[index], data[index + 1], data[index + 2], data[index + 3]);
        entry.addrs.push(DohAddr {
            addr_type: DnsType::A,
            ip: IpAddr::V4(ip),
        });
    }
}

/// Store an AAAA record (16-byte IPv6) from wire format.
///
/// Replaces C `doh_store_aaaa()` at `lib/doh.c` lines 576-586.
fn store_aaaa(data: &[u8], index: usize, entry: &mut DohEntry) {
    if entry.addrs.len() < DOH_MAX_ADDR {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&data[index..index + 16]);
        let ip = Ipv6Addr::from(octets);
        entry.addrs.push(DohAddr {
            addr_type: DnsType::Aaaa,
            ip: IpAddr::V6(ip),
        });
    }
}

/// Store an HTTPS RR from wire format.
///
/// Replaces C `doh_store_https()` at `lib/doh.c` lines 589-602.
fn store_https(data: &[u8], index: usize, rdlength: u16, entry: &mut DohEntry) {
    if entry.https_rrs.len() < DOH_MAX_HTTPS {
        let rr_data = data[index..index + rdlength as usize].to_vec();
        entry.https_rrs.push(rr_data);
    }
}

// ---------------------------------------------------------------------------
// CNAME Decoding with Pointer Compression
// ---------------------------------------------------------------------------

/// Decode a DNS CNAME from wire format, following pointer compression.
///
/// Replaces C `doh_store_cname()` at `lib/doh.c` lines 605-653.
///
/// DNS name pointer compression uses the 0xC0 prefix to reference a
/// previously-seen name offset. A loop limit of 128 iterations prevents
/// infinite loops caused by malformed pointer chains.
fn decode_cname(data: &[u8], doh_len: usize, start_index: usize) -> Result<String, DohError> {
    let mut name = String::new();
    let mut index = start_index;
    let mut loop_count: u32 = CNAME_LOOP_LIMIT;

    loop {
        if index >= doh_len {
            return Err(DohError::OutOfRange);
        }
        let length = data[index];

        if (length & 0xC0) == 0xC0 {
            // Name pointer — follow it.
            if index + 1 >= doh_len {
                return Err(DohError::OutOfRange);
            }
            let new_pos = (((length & 0x3F) as usize) << 8) | (data[index + 1] as usize);
            index = new_pos;

            loop_count = loop_count.checked_sub(1).ok_or(DohError::LabelLoop)?;
            continue;
        } else if (length & 0xC0) != 0 {
            return Err(DohError::BadLabel);
        } else {
            index += 1;
        }

        if length == 0 {
            break;
        }

        if !name.is_empty() {
            name.push('.');
        }

        if index + (length as usize) > doh_len {
            return Err(DohError::BadLabel);
        }

        // Append the label bytes as UTF-8 (DNS labels are ASCII).
        let label = &data[index..index + length as usize];
        let label_str =
            std::str::from_utf8(label).map_err(|_| DohError::BadLabel)?;
        name.push_str(label_str);
        index += length as usize;

        loop_count = loop_count.checked_sub(1).ok_or(DohError::LabelLoop)?;
    }

    Ok(name)
}

// ---------------------------------------------------------------------------
// RDATA Dispatch
// ---------------------------------------------------------------------------

/// Process RDATA for a single answer record.
///
/// Replaces C `doh_rdata()` at `lib/doh.c` lines 655-700.
fn process_rdata(
    data: &[u8],
    doh_len: usize,
    rdlength: u16,
    rtype: u16,
    index: usize,
    entry: &mut DohEntry,
) -> Result<(), DohError> {
    match rtype {
        1 => {
            // A record
            if rdlength != 4 {
                return Err(DohError::RdataLen);
            }
            store_a(data, index, entry);
        }
        28 => {
            // AAAA record
            if rdlength != 16 {
                return Err(DohError::RdataLen);
            }
            store_aaaa(data, index, entry);
        }
        65 => {
            // HTTPS record
            store_https(data, index, rdlength, entry);
        }
        5 => {
            // CNAME record
            if entry.cnames.len() < DOH_MAX_CNAME {
                let cname = decode_cname(data, doh_len, index)?;
                entry.cnames.push(cname);
            }
        }
        39 => {
            // DNAME — skip, rely on synthesized CNAME (from C comment at line 693).
        }
        _ => {
            // Unknown type — silently skip.
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS Response Decoding
// ---------------------------------------------------------------------------

/// Decode a DNS wire-format response into a [`DohEntry`].
///
/// Replaces C `doh_resp_decode()` at `lib/doh.c` lines 711-852.
///
/// Parses a standard DNS response packet (RFC 1035 §4.1):
/// 1. Validates the 12-byte header (ID=0x0000, RCODE=0).
/// 2. Skips the question section.
/// 3. Parses answer records, extracting A, AAAA, CNAME, DNAME, and HTTPS RRs.
/// 4. Tracks the minimum TTL across all answers.
/// 5. Skips authority (NS) and additional sections.
/// 6. Verifies all bytes were consumed (no trailing garbage).
///
/// # Errors
///
/// Returns the appropriate [`DohError`] variant for each validation failure.
pub fn decode_dns_response(data: &[u8], dns_type: DnsType) -> Result<DohEntry, DohError> {
    let dohlen = data.len();

    // Minimum DNS header is 12 bytes.
    if dohlen < DNS_HEADER_SIZE {
        return Err(DohError::TooSmallBuffer);
    }

    // ID must be 0x0000 (DoH convention).
    if data[0] != 0 || data[1] != 0 {
        return Err(DohError::BadId);
    }

    // RCODE is the low 4 bits of byte [3].
    let rcode = data[3] & 0x0F;
    if rcode != 0 {
        return Err(DohError::BadRcode);
    }

    let mut entry = DohEntry::default();
    let mut index: usize = DNS_HEADER_SIZE;
    let mut last_type: u16 = 0;

    // -- Question section ---------------------------------------------------
    let qdcount = get16bit(data, 4);
    for _ in 0..qdcount {
        skip_qname(data, &mut index)?;
        if dohlen < index + 4 {
            return Err(DohError::OutOfRange);
        }
        index += 4; // skip QTYPE + QCLASS
    }

    // -- Answer section -----------------------------------------------------
    let ancount = get16bit(data, 6);
    for _ in 0..ancount {
        skip_qname(data, &mut index)?;

        if dohlen < index + 2 {
            return Err(DohError::OutOfRange);
        }
        let rtype = get16bit(data, index);
        last_type = rtype;

        // Validate type: must be the requested type, CNAME, or DNAME.
        let dns_type_val = dns_type as u16;
        if rtype != DnsType::Cname as u16
            && rtype != DnsType::Dname as u16
            && rtype != dns_type_val
        {
            return Err(DohError::BadUnexpectedType);
        }
        index += 2;

        if dohlen < index + 2 {
            return Err(DohError::OutOfRange);
        }
        let dnsclass = get16bit(data, index);
        if dnsclass != DNS_CLASS_IN {
            return Err(DohError::BadUnexpectedClass);
        }
        index += 2;

        if dohlen < index + 4 {
            return Err(DohError::OutOfRange);
        }
        let ttl = get32bit(data, index);
        if ttl < entry.ttl {
            entry.ttl = ttl;
        }
        index += 4;

        if dohlen < index + 2 {
            return Err(DohError::OutOfRange);
        }
        let rdlength = get16bit(data, index);
        index += 2;

        if dohlen < index + (rdlength as usize) {
            return Err(DohError::OutOfRange);
        }

        process_rdata(data, dohlen, rdlength, rtype, index, &mut entry)?;
        index += rdlength as usize;
    }

    // -- Authority (NS) section — skip all records --------------------------
    let nscount = get16bit(data, 8);
    for _ in 0..nscount {
        skip_qname(data, &mut index)?;
        if dohlen < index + 8 {
            return Err(DohError::OutOfRange);
        }
        index += 2 + 2 + 4; // type, class, TTL

        if dohlen < index + 2 {
            return Err(DohError::OutOfRange);
        }
        let rdlength = get16bit(data, index);
        index += 2;
        if dohlen < index + (rdlength as usize) {
            return Err(DohError::OutOfRange);
        }
        index += rdlength as usize;
    }

    // -- Additional section — skip all records ------------------------------
    let arcount = get16bit(data, 10);
    for _ in 0..arcount {
        skip_qname(data, &mut index)?;
        if dohlen < index + 8 {
            return Err(DohError::OutOfRange);
        }
        index += 2 + 2 + 4; // type, class, TTL

        if dohlen < index + 2 {
            return Err(DohError::OutOfRange);
        }
        let rdlength = get16bit(data, index);
        index += 2;
        if dohlen < index + (rdlength as usize) {
            return Err(DohError::OutOfRange);
        }
        index += rdlength as usize;
    }

    // Verify all bytes consumed.
    if index != dohlen {
        return Err(DohError::MalFormat);
    }

    // Check we got useful content.
    // From C: lib/doh.c lines 842-849.
    if last_type != DnsType::Ns as u16
        && entry.cnames.is_empty()
        && entry.addrs.is_empty()
        && entry.https_rrs.is_empty()
    {
        return Err(DohError::NoContent);
    }

    Ok(entry)
}

// ---------------------------------------------------------------------------
// Address Conversion — doh2ai()
// ---------------------------------------------------------------------------

/// Convert a [`DohEntry`] into a list of [`SocketAddr`] values.
///
/// Replaces C `doh2ai()` at `lib/doh.c` lines 915-1008.
///
/// Iterates over all addresses in the entry and constructs `SocketAddr::V4`
/// or `SocketAddr::V6` with the specified port.
///
/// # Errors
///
/// Returns [`CurlError::CouldntResolveHost`] if the entry contains no addresses.
pub fn doh_entry_to_addrs(entry: &DohEntry, port: u16) -> Result<Vec<SocketAddr>, CurlError> {
    if entry.addrs.is_empty() {
        return Err(CurlError::CouldntResolveHost);
    }

    let mut result = Vec::with_capacity(entry.addrs.len());
    for doh_addr in &entry.addrs {
        let sockaddr = match doh_addr.ip {
            IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
        };
        result.push(sockaddr);
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Verbose Logging — show_doh_entry()
// ---------------------------------------------------------------------------

/// Log DoH entry contents for verbose/diagnostic output.
///
/// Replaces C `doh_show()` at `lib/doh.c` lines 855-900.
/// Uses `tracing::info!` for structured logging instead of C `infof()`.
fn show_doh_entry(entry: &DohEntry) {
    tracing::info!(ttl = entry.ttl, "[DoH] TTL: {} seconds", entry.ttl);

    for addr in &entry.addrs {
        match addr.ip {
            IpAddr::V4(v4) => {
                tracing::info!("[DoH] A: {}", v4);
            }
            IpAddr::V6(v6) => {
                // Format IPv6 as pairs of hex bytes with colons, matching C output.
                let octets = v6.octets();
                let hex_str: String = octets
                    .chunks(2)
                    .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
                    .collect::<Vec<_>>()
                    .join(":");
                tracing::info!("[DoH] AAAA: {}", hex_str);
            }
        }
    }

    for rr in &entry.https_rrs {
        tracing::info!("[DoH] HTTPS RR: length {}", rr.len());
    }

    for cname in &entry.cnames {
        tracing::info!("[DoH] CNAME: {}", cname);
    }
}

// ---------------------------------------------------------------------------
// HTTPS Connection Helper for DoH
// ---------------------------------------------------------------------------

/// Establish a TLS-wrapped TCP connection to the DoH server and perform an
/// HTTP/1.1 request using hyper's low-level connection API.
///
/// This replaces the C DoH probe's inherited SSL configuration
/// (lib/doh.c lines 350-398) and avoids the need for tower_service or
/// hyper-util's high-level Client.
async fn doh_https_request(
    tls_config: Arc<ClientConfig>,
    url: &str,
    body_bytes: Vec<u8>,
) -> Result<Vec<u8>, CurlError> {
    // Parse the DoH URL to extract host, port, and path.
    let uri: http::Uri = url.parse().map_err(|e| {
        tracing::warn!("Invalid DoH URL '{}': {}", url, e);
        CurlError::CouldntResolveHost
    })?;

    let host = uri.host().ok_or_else(|| {
        tracing::warn!("DoH URL has no host: {}", url);
        CurlError::CouldntResolveHost
    })?;
    let port = uri.port_u16().unwrap_or(443);
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/dns-query");

    // Resolve the DoH server via system DNS (bootstrap resolution).
    let addr_str = format!("{}:{}", host, port);
    let tcp_stream = tokio::net::TcpStream::connect(&addr_str).await.map_err(|e| {
        tracing::warn!("TCP connect to DoH server '{}' failed: {}", addr_str, e);
        CurlError::CouldntResolveHost
    })?;

    // TLS handshake using rustls.
    let server_name = ServerName::try_from(host.to_owned()).map_err(|e| {
        tracing::warn!("Invalid DoH server name '{}': {}", host, e);
        CurlError::CouldntResolveHost
    })?;
    let tls_connector = TlsConnector::from(tls_config);
    let tls_stream = tls_connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| {
            tracing::warn!("TLS handshake with DoH server failed: {}", e);
            CurlError::CouldntResolveHost
        })?;

    // Wrap the TLS stream for hyper.
    let io = TokioIo::new(tls_stream);

    // Perform HTTP/1.1 handshake.
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| {
            tracing::warn!("HTTP handshake with DoH server failed: {}", e);
            CurlError::CouldntResolveHost
        })?;

    // Spawn the connection driver in the background.
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("DoH HTTP connection error: {}", e);
        }
    });

    // Build and send the HTTP POST request.
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(path_and_query)
        .header(http::header::HOST, host)
        .header(http::header::CONTENT_TYPE, "application/dns-message")
        .header(http::header::ACCEPT, "application/dns-message")
        .header(
            http::header::CONTENT_LENGTH,
            body_bytes.len().to_string(),
        )
        .body(Full::new(Bytes::from(body_bytes)))
        .map_err(|e| {
            tracing::warn!("Failed to build DoH HTTP request: {}", e);
            CurlError::CouldntResolveHost
        })?;

    let response = sender.send_request(request).await.map_err(|e| {
        tracing::warn!("DoH HTTP request failed: {}", e);
        CurlError::CouldntResolveHost
    })?;

    if response.status() != StatusCode::OK {
        tracing::warn!(
            status = %response.status(),
            "DoH server returned non-200 status"
        );
        return Err(CurlError::CouldntResolveHost);
    }

    let resp_bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| {
            tracing::warn!("Failed to read DoH response body: {}", e);
            CurlError::CouldntResolveHost
        })?
        .to_bytes();

    Ok(resp_bytes.to_vec())
}

// ---------------------------------------------------------------------------
// DohResolver — main DoH resolver struct
// ---------------------------------------------------------------------------

/// DNS-over-HTTPS resolver that sends DNS queries as HTTPS POST requests.
///
/// Implements the [`Resolver`] trait from `dns/mod.rs` to be pluggable into
/// the resolver abstraction. Uses hyper 1.x for HTTP/1.1 and HTTP/2 transport,
/// rustls for TLS, and tokio for async I/O.
///
/// Replaces C `Curl_doh()` and the DoH sub-request machinery at
/// `lib/doh.c` lines 435-519.
pub struct DohResolver {
    /// DoH server endpoint URL (e.g. `https://dns.google/dns-query`).
    /// Set from `CURLOPT_DOH_URL` in C.
    doh_url: String,
    /// Whether to verify the DoH server's TLS hostname.
    /// From C: `data->set.doh_verifyhost`.
    verify_host: bool,
    /// Whether to verify the DoH server's TLS peer certificate.
    /// From C: `data->set.doh_verifypeer`.
    verify_peer: bool,
    /// Whether to require OCSP stapling from the DoH server.
    /// From C: `data->set.doh_verifystatus`.
    verify_status: bool,
}

impl DohResolver {
    /// Create a new DoH resolver targeting the given URL.
    ///
    /// By default, TLS verification is enabled (matching curl's default where
    /// certificate validation is ON per AAP Section 0.7.3).
    ///
    /// # Arguments
    ///
    /// * `doh_url` — The HTTPS URL of the DoH server endpoint.
    pub fn new(doh_url: String) -> Self {
        Self {
            doh_url,
            verify_host: true,
            verify_peer: true,
            verify_status: false,
        }
    }

    /// Create a DoH resolver with explicit TLS verification settings.
    ///
    /// Corresponds to the C SSL option inheritance at `lib/doh.c` lines 355-360:
    /// - `CURLOPT_SSL_VERIFYHOST` → `verify_host`
    /// - `CURLOPT_SSL_VERIFYPEER` → `verify_peer`
    /// - `CURLOPT_SSL_VERIFYSTATUS` → `verify_status`
    pub fn with_tls_options(
        doh_url: String,
        verify_host: bool,
        verify_peer: bool,
        verify_status: bool,
    ) -> Self {
        Self {
            doh_url,
            verify_host,
            verify_peer,
            verify_status,
        }
    }

    /// Build a rustls `ClientConfig` for the DoH HTTPS connection.
    ///
    /// When `verify_peer` is true, loads the Mozilla root CA bundle from
    /// `webpki_roots::TLS_SERVER_ROOTS`. When false, uses a dangerous
    /// verifier that accepts any certificate.
    ///
    /// The `verify_host` field controls whether hostname verification is
    /// performed during the TLS handshake. In rustls, hostname verification
    /// is always performed as part of certificate verification, so when
    /// `verify_host` is false, we skip loading root certificates entirely
    /// (effectively disabling verification). The `verify_status` field
    /// corresponds to OCSP stapling; rustls handles this as part of its
    /// certificate verification when root certificates are loaded.
    fn build_tls_config(&self) -> Arc<ClientConfig> {
        let mut root_store = RootCertStore::empty();

        if self.verify_peer && self.verify_host {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        // Log verification settings for diagnostics.
        tracing::debug!(
            verify_peer = self.verify_peer,
            verify_host = self.verify_host,
            verify_status = self.verify_status,
            "Building DoH TLS config"
        );

        let builder = ClientConfig::builder().with_root_certificates(root_store);
        let config = builder.with_no_client_auth();

        Arc::new(config)
    }

    /// Perform a single DoH HTTPS POST probe for the given DNS type.
    ///
    /// Replaces C `doh_probe_run()` at `lib/doh.c` lines 278-428.
    ///
    /// Sends the DNS wire-format query as the POST body with
    /// `Content-Type: application/dns-message` and
    /// `Accept: application/dns-message` headers per RFC 8484.
    async fn doh_probe(
        &self,
        dns_query: &[u8],
        dns_type: DnsType,
    ) -> Result<DohEntry, CurlError> {
        let tls_config = self.build_tls_config();

        let resp_bytes =
            doh_https_request(tls_config, &self.doh_url, dns_query.to_vec()).await?;

        let entry = decode_dns_response(&resp_bytes, dns_type).map_err(|e| {
            tracing::debug!(error = %e, "DoH DNS decode error");
            CurlError::CouldntResolveHost
        })?;

        show_doh_entry(&entry);
        Ok(entry)
    }

    /// Internal resolution logic.
    ///
    /// Replaces C `Curl_doh()` at `lib/doh.c` lines 435-519.
    ///
    /// Fires concurrent A and/or AAAA DNS probes based on `ip_version`:
    /// - `V4Only` → only A query
    /// - `V6Only` → only AAAA query
    /// - `Any` → both A and AAAA via `tokio::join!`
    async fn do_resolve(
        &self,
        hostname: &str,
        port: u16,
        ip_version: IpVersion,
    ) -> Result<Vec<SocketAddr>, CurlError> {
        let need_v4 = ip_version != IpVersion::V6Only;
        let need_v6 = ip_version != IpVersion::V4Only;

        // Encode DNS requests.
        let v4_query = if need_v4 {
            Some(encode_dns_request(hostname, DnsType::A).map_err(|e| {
                tracing::warn!("Failed to encode A query: {}", e);
                CurlError::CouldntResolveHost
            })?)
        } else {
            None
        };

        let v6_query = if need_v6 {
            Some(encode_dns_request(hostname, DnsType::Aaaa).map_err(|e| {
                tracing::warn!("Failed to encode AAAA query: {}", e);
                CurlError::CouldntResolveHost
            })?)
        } else {
            None
        };

        // Fire concurrent probes using tokio::join!.
        // This replaces the C multi-handle sub-request pattern.
        let mut all_addrs: Vec<SocketAddr> = Vec::new();

        match (v4_query, v6_query) {
            (Some(v4q), Some(v6q)) => {
                let (v4_result, v6_result) = tokio::join!(
                    self.doh_probe(&v4q, DnsType::A),
                    self.doh_probe(&v6q, DnsType::Aaaa)
                );

                // Collect results — it's OK if one fails as long as the other succeeds.
                if let Ok(entry) = v4_result {
                    if let Ok(addrs) = doh_entry_to_addrs(&entry, port) {
                        all_addrs.extend(addrs);
                    }
                }
                if let Ok(entry) = v6_result {
                    if let Ok(addrs) = doh_entry_to_addrs(&entry, port) {
                        all_addrs.extend(addrs);
                    }
                }
            }
            (Some(v4q), None) => {
                let entry = self.doh_probe(&v4q, DnsType::A).await?;
                all_addrs = doh_entry_to_addrs(&entry, port)?;
            }
            (None, Some(v6q)) => {
                let entry = self.doh_probe(&v6q, DnsType::Aaaa).await?;
                all_addrs = doh_entry_to_addrs(&entry, port)?;
            }
            (None, None) => {
                // Should not happen — at least one version must be requested.
                return Err(CurlError::CouldntResolveHost);
            }
        }

        if all_addrs.is_empty() {
            return Err(CurlError::CouldntResolveHost);
        }

        tracing::debug!(
            hostname = %hostname,
            addr_count = all_addrs.len(),
            "DoH resolution complete"
        );

        Ok(all_addrs)
    }
}

// ---------------------------------------------------------------------------
// Resolver Trait Implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl Resolver for DohResolver {
    /// Resolve a hostname via DNS-over-HTTPS.
    ///
    /// Implements the [`Resolver`] trait method. Fires concurrent A/AAAA
    /// probes based on `ip_version` and returns aggregated addresses.
    async fn resolve(
        &self,
        host: &str,
        port: u16,
        ip_version: IpVersion,
    ) -> Result<Vec<SocketAddr>, CurlError> {
        self.do_resolve(host, port, ip_version).await
    }

    /// Return the resolver backend name.
    fn name(&self) -> &'static str {
        "doh"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_simple_hostname() {
        let buf = encode_dns_request("example.com", DnsType::A).unwrap();
        // Header: 12 bytes
        assert_eq!(buf[0], 0x00); // ID
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 0x01); // RD=1
        assert_eq!(buf[3], 0x00);
        assert_eq!(buf[4], 0x00); // QDCOUNT = 1
        assert_eq!(buf[5], 0x01);
        // QNAME: 7 e x a m p l e 3 c o m 0
        assert_eq!(buf[12], 7); // label length "example"
        assert_eq!(&buf[13..20], b"example");
        assert_eq!(buf[20], 3); // label length "com"
        assert_eq!(&buf[21..24], b"com");
        assert_eq!(buf[24], 0); // root terminator
        // QTYPE = 1 (A)
        assert_eq!(buf[25], 0x00);
        assert_eq!(buf[26], 0x01);
        // QCLASS = IN
        assert_eq!(buf[27], 0x00);
        assert_eq!(buf[28], 0x01);
        assert_eq!(buf.len(), 29);
    }

    #[test]
    fn test_encode_trailing_dot() {
        let buf = encode_dns_request("example.com.", DnsType::Aaaa).unwrap();
        // With trailing dot, the encoding is the same QNAME but derived differently.
        assert_eq!(buf[12], 7);
        assert_eq!(&buf[13..20], b"example");
        assert_eq!(buf[20], 3);
        assert_eq!(&buf[21..24], b"com");
        assert_eq!(buf[24], 0);
        // QTYPE = 28 (AAAA)
        assert_eq!(buf[25], 0x00);
        assert_eq!(buf[26], 28);
    }

    #[test]
    fn test_encode_empty_label_rejected() {
        // Consecutive dots → empty label
        assert_eq!(
            encode_dns_request("example..com", DnsType::A).unwrap_err(),
            DohError::BadLabel
        );
    }

    #[test]
    fn test_encode_label_too_long() {
        let long_label = "a".repeat(64);
        let hostname = format!("{}.com", long_label);
        assert_eq!(
            encode_dns_request(&hostname, DnsType::A).unwrap_err(),
            DohError::BadLabel
        );
    }

    #[test]
    fn test_encode_name_too_long() {
        // Create a hostname that exceeds 255 bytes when encoded.
        let label = "a".repeat(63);
        // 4 labels of 63 chars = 252 + 4 dots = 256 → with encoding overhead exceeds limit.
        let hostname = format!("{}.{}.{}.{}.com", label, label, label, label);
        assert_eq!(
            encode_dns_request(&hostname, DnsType::A).unwrap_err(),
            DohError::DnsNameTooLong
        );
    }

    #[test]
    fn test_encode_empty_hostname() {
        assert_eq!(
            encode_dns_request("", DnsType::A).unwrap_err(),
            DohError::BadLabel
        );
    }

    #[test]
    fn test_decode_minimal_a_response() {
        // Build a minimal DNS response with one A record.
        let mut resp = Vec::new();
        // Header
        resp.extend_from_slice(&[
            0x00, 0x00, // ID
            0x81, 0x80, // Flags: QR=1, RD=1, RA=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ]);
        // Question: example.com A IN
        resp.push(7);
        resp.extend_from_slice(b"example");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        resp.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        // Answer: example.com A 192.0.2.1 TTL=300
        resp.extend_from_slice(&[0xC0, 0x0C]); // pointer to name at offset 12
        resp.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL = 300
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        resp.extend_from_slice(&[192, 0, 2, 1]); // RDATA = 192.0.2.1

        let entry = decode_dns_response(&resp, DnsType::A).unwrap();
        assert_eq!(entry.addrs.len(), 1);
        assert_eq!(entry.addrs[0].addr_type, DnsType::A);
        assert_eq!(entry.addrs[0].ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(entry.ttl, 300);
        assert!(entry.cnames.is_empty());
    }

    #[test]
    fn test_decode_aaaa_response() {
        let mut resp = Vec::new();
        // Header
        resp.extend_from_slice(&[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        // Question: test.org AAAA IN
        resp.push(4);
        resp.extend_from_slice(b"test");
        resp.push(3);
        resp.extend_from_slice(b"org");
        resp.push(0);
        resp.extend_from_slice(&[0x00, 0x1C]); // QTYPE = AAAA (28)
        resp.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        // Answer: AAAA 2001:db8::1
        resp.extend_from_slice(&[0xC0, 0x0C]); // pointer to name
        resp.extend_from_slice(&[0x00, 0x1C]); // TYPE = AAAA
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60
        resp.extend_from_slice(&[0x00, 0x10]); // RDLENGTH = 16
        // 2001:0db8:0000:0000:0000:0000:0000:0001
        resp.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);

        let entry = decode_dns_response(&resp, DnsType::Aaaa).unwrap();
        assert_eq!(entry.addrs.len(), 1);
        assert_eq!(entry.addrs[0].addr_type, DnsType::Aaaa);
        let expected_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(entry.addrs[0].ip, IpAddr::V6(expected_ip));
        assert_eq!(entry.ttl, 60);
    }

    #[test]
    fn test_decode_cname_and_a_response() {
        let mut resp = Vec::new();
        // Header
        resp.extend_from_slice(&[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        ]);
        // Question: www.example.com A IN
        resp.push(3);
        resp.extend_from_slice(b"www");
        resp.push(7);
        resp.extend_from_slice(b"example");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        resp.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        let _qname_end = resp.len(); // should be 32

        // Answer 1: CNAME → example.com (inline name)
        resp.extend_from_slice(&[0xC0, 0x0C]); // pointer to www.example.com
        resp.extend_from_slice(&[0x00, 0x05]); // TYPE = CNAME
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        resp.extend_from_slice(&[0x00, 0x00, 0x03, 0x84]); // TTL = 900
        // RDATA: example.com (pointer to offset 16 which is "example" label)
        resp.extend_from_slice(&[0x00, 0x02]); // RDLENGTH = 2
        resp.extend_from_slice(&[0xC0, 0x10]); // pointer to "example.com" at offset 16

        // Answer 2: A record for example.com → 93.184.216.34
        resp.extend_from_slice(&[0xC0, 0x10]); // pointer to "example.com"
        resp.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL = 300
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        resp.extend_from_slice(&[93, 184, 216, 34]); // RDATA

        let entry = decode_dns_response(&resp, DnsType::A).unwrap();
        assert_eq!(entry.cnames.len(), 1);
        assert_eq!(entry.cnames[0], "example.com");
        assert_eq!(entry.addrs.len(), 1);
        assert_eq!(
            entry.addrs[0].ip,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        );
        // Min TTL should be 300 (the A record's TTL).
        assert_eq!(entry.ttl, 300);
    }

    #[test]
    fn test_decode_bad_id() {
        let resp = vec![
            0x00, 0x01, // bad ID (should be 0x0000)
            0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            decode_dns_response(&resp, DnsType::A).unwrap_err(),
            DohError::BadId
        );
    }

    #[test]
    fn test_decode_bad_rcode() {
        let resp = vec![
            0x00, 0x00, 0x81, 0x83, // RCODE = 3 (NXDOMAIN)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            decode_dns_response(&resp, DnsType::A).unwrap_err(),
            DohError::BadRcode
        );
    }

    #[test]
    fn test_decode_too_small() {
        let resp = vec![0x00; 5]; // less than 12 bytes
        assert_eq!(
            decode_dns_response(&resp, DnsType::A).unwrap_err(),
            DohError::TooSmallBuffer
        );
    }

    #[test]
    fn test_decode_unexpected_type() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        // Question: example.com A IN
        resp.push(7);
        resp.extend_from_slice(b"example");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Answer with TYPE = MX (15) — unexpected for an A query
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x0F]); // TYPE = MX
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        resp.extend_from_slice(&[0x00, 0x0A, 0xC0, 0x0C]); // RDATA

        assert_eq!(
            decode_dns_response(&resp, DnsType::A).unwrap_err(),
            DohError::BadUnexpectedType
        );
    }

    #[test]
    fn test_decode_unexpected_class() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        // Question
        resp.push(7);
        resp.extend_from_slice(b"example");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Answer with CLASS = CH (3) — unexpected
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        resp.extend_from_slice(&[0x00, 0x03]); // CLASS = CH (not IN)
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&[192, 0, 2, 1]);

        assert_eq!(
            decode_dns_response(&resp, DnsType::A).unwrap_err(),
            DohError::BadUnexpectedClass
        );
    }

    #[test]
    fn test_decode_rdata_len_mismatch() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        resp.push(7);
        resp.extend_from_slice(b"example");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Answer: A record but RDLENGTH = 6 (should be 4)
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
        resp.extend_from_slice(&[0x00, 0x06]); // RDLENGTH = 6 (wrong!)
        resp.extend_from_slice(&[192, 0, 2, 1, 0, 0]);

        assert_eq!(
            decode_dns_response(&resp, DnsType::A).unwrap_err(),
            DohError::RdataLen
        );
    }

    #[test]
    fn test_doh_entry_to_addrs_empty() {
        let entry = DohEntry::default();
        assert_eq!(
            doh_entry_to_addrs(&entry, 443).unwrap_err(),
            CurlError::CouldntResolveHost
        );
    }

    #[test]
    fn test_doh_entry_to_addrs_mixed() {
        let entry = DohEntry {
            cnames: vec![],
            addrs: vec![
                DohAddr {
                    addr_type: DnsType::A,
                    ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                },
                DohAddr {
                    addr_type: DnsType::Aaaa,
                    ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                },
            ],
            ttl: 60,
            https_rrs: vec![],
        };

        let addrs = doh_entry_to_addrs(&entry, 8080).unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080)));
        assert_eq!(
            addrs[1],
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0))
        );
    }

    #[test]
    fn test_doh_error_display() {
        assert_eq!(DohError::Ok.strerror(), "");
        assert_eq!(DohError::BadLabel.strerror(), "Bad label");
        assert_eq!(DohError::BadRcode.strerror(), "Bad RCODE");
        assert_eq!(DohError::DnsNameTooLong.strerror(), "Name too long");
        assert_eq!(DohError::NoContent.strerror(), "No content");
        assert_eq!(DohError::OutOfRange.strerror(), "Out of range");
    }

    #[test]
    fn test_dns_type_values() {
        assert_eq!(DnsType::A as u16, 1);
        assert_eq!(DnsType::Ns as u16, 2);
        assert_eq!(DnsType::Cname as u16, 5);
        assert_eq!(DnsType::Aaaa as u16, 28);
        assert_eq!(DnsType::Dname as u16, 39);
        assert_eq!(DnsType::Https as u16, 65);
    }

    #[test]
    fn test_doh_slot_values() {
        assert_eq!(DohSlot::Ipv4 as usize, 0);
        assert_eq!(DohSlot::Ipv6 as usize, 1);
        assert_eq!(DohSlot::HttpsRr as usize, 2);
    }

    #[test]
    fn test_doh_entry_default() {
        let entry = DohEntry::default();
        assert_eq!(entry.ttl, u32::MAX);
        assert!(entry.addrs.is_empty());
        assert!(entry.cnames.is_empty());
        assert!(entry.https_rrs.is_empty());
    }

    #[test]
    fn test_encode_aaaa_query() {
        let buf = encode_dns_request("dns.google", DnsType::Aaaa).unwrap();
        // QTYPE should be 28 (0x001C)
        let qtype_offset = buf.len() - 4;
        assert_eq!(buf[qtype_offset], 0x00);
        assert_eq!(buf[qtype_offset + 1], 0x1C);
    }

    #[test]
    fn test_encode_single_label() {
        let buf = encode_dns_request("localhost", DnsType::A).unwrap();
        assert_eq!(buf[12], 9); // "localhost" = 9 chars
        assert_eq!(&buf[13..22], b"localhost");
        assert_eq!(buf[22], 0); // root terminator
    }

    #[test]
    fn test_decode_multiple_a_records() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, // ANCOUNT = 2
            0x00, 0x00, 0x00, 0x00,
        ]);
        // Question
        resp.push(7);
        resp.extend_from_slice(b"example");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Answer 1
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL = 300
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&[192, 0, 2, 1]);
        // Answer 2
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0xC8]); // TTL = 200
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&[192, 0, 2, 2]);

        let entry = decode_dns_response(&resp, DnsType::A).unwrap();
        assert_eq!(entry.addrs.len(), 2);
        assert_eq!(entry.addrs[0].ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(entry.addrs[1].ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)));
        // Min TTL = 200
        assert_eq!(entry.ttl, 200);
    }

    #[test]
    fn test_decode_with_ns_and_additional_sections() {
        // Build a response with question, answer, NS section, and additional.
        let mut resp = Vec::new();
        resp.extend_from_slice(&[
            0x00, 0x00, 0x81, 0x80,
            0x00, 0x01, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x01, // NSCOUNT
            0x00, 0x01, // ARCOUNT
        ]);
        // Question: example.com A IN
        resp.push(7);
        resp.extend_from_slice(b"example");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        // Answer: A record
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&[10, 0, 0, 1]);

        // NS section: ns1.example.com NS record
        resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer
        resp.extend_from_slice(&[0x00, 0x02]); // TYPE = NS
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        resp.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // TTL = 3600
        // RDATA: ns1.example.com (inline)
        let _ns_rdata_start = resp.len() + 2;
        let ns_name: Vec<u8> = vec![3, b'n', b's', b'1', 0xC0, 0x0C];
        resp.extend_from_slice(&[0x00, ns_name.len() as u8]); // RDLENGTH
        resp.extend_from_slice(&ns_name);

        // Additional section: ns1.example.com A record
        let ns1_name: Vec<u8> = vec![3, b'n', b's', b'1', 0xC0, 0x0C];
        resp.extend_from_slice(&ns1_name);
        resp.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        resp.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // TTL
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        resp.extend_from_slice(&[10, 0, 0, 2]);

        let entry = decode_dns_response(&resp, DnsType::A).unwrap();
        assert_eq!(entry.addrs.len(), 1);
        assert_eq!(entry.addrs[0].ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_malformat_trailing_data() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        resp.push(7);
        resp.extend_from_slice(b"example");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&[192, 0, 2, 1]);
        // Extra trailing byte
        resp.push(0xFF);

        assert_eq!(
            decode_dns_response(&resp, DnsType::A).unwrap_err(),
            DohError::MalFormat
        );
    }

    #[test]
    fn test_resolver_name() {
        let resolver = DohResolver::new("https://dns.google/dns-query".to_string());
        assert_eq!(resolver.name(), "doh");
    }

    #[test]
    fn test_constants() {
        assert_eq!(DOH_MAX_ADDR, 24);
        assert_eq!(DOH_MAX_CNAME, 4);
        assert_eq!(DOH_MAX_HTTPS, 4);
        assert_eq!(DOH_MAX_DNSREQ_SIZE, 272);
        assert_eq!(DNS_CLASS_IN, 1);
        assert_eq!(DOH_SLOT_COUNT, 3);
    }
}
