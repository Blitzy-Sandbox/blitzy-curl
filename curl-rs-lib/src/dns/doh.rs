// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! DNS-over-HTTPS (DoH) name-resolution backend (RFC 8484 over hyper HTTP/2).
//!
//! This module is the idiomatic-Rust rewrite of curl 8.x's DoH implementation,
//! derived from the source-of-truth C files (preserved unmodified in `lib/`):
//!
//! | curl C source            | responsibility reproduced here                        |
//! |--------------------------|-------------------------------------------------------|
//! | `lib/doh.c` (PRIMARY)    | request wireformat encode (`doh_req_encode`), response wireformat decode (`doh_resp_decode` + `doh_skipqname`/`doh_store_a`/`doh_store_aaaa`/`doh_store_cname`/`doh_rdata`), the `dohentry` aggregation, `doh2ai` address conversion, and the `doh_probe_run` transport. |
//! | `lib/doh.h`              | the [`DohCode`] / [`DnsType`] enums, slot numbering, and the `DOH_MAX_*` size constants. |
//!
//! # What DoH does
//!
//! When `CURLOPT_DOH_URL` is configured, curl resolves a hostname by issuing DNS
//! queries **encapsulated in HTTPS** to a DoH server, rather than using the
//! system resolver. curl fires two concurrent probes — an `A` (IPv4) query and
//! an `AAAA` (IPv6) query — as HTTP `POST` requests whose body is a raw
//! RFC 1035 DNS message and whose `Content-Type` is `application/dns-message`
//! (RFC 8484). The two answers are merged into a single ordered address list.
//!
//! This module reproduces that behavior on the mandated Rust stack: the
//! transport is an **internal [`hyper`] HTTP/2 client running on Tokio** (AAP
//! §0.4, "DoH via hyper"), the TLS of the DoH connection is [`rustls`] via
//! [`tokio_rustls`] with certificate validation **on by default**, and the
//! wireformat encode/decode is **pure byte manipulation** with zero `unsafe`
//! (the crate root's `#![forbid(unsafe_code)]` applies here — AAP §0.7.2).
//!
//! # Position in the crate
//!
//! [`DohResolver`] implements the [`Resolver`] trait defined in
//! [`crate::dns`], exactly as [`crate::dns::system::SystemResolver`] does. The
//! [`crate::dns::resolve`] orchestration selects it (via
//! [`ResolveOptions::doh`](crate::dns::ResolveOptions::doh)) when a DoH URL is
//! configured and the host is not a literal IP. The bootstrap resolution of the
//! DoH *server's own* hostname uses the Tokio system resolver
//! ([`tokio::net::lookup_host`]), never DoH recursively — matching curl, whose
//! internal DoH easy handle uses the normal asynchronous resolver.
//!
//! # Error model (parity with curl)
//!
//! Wireformat problems are reported with the [`DohCode`] enum (the exact 14
//! `DOHcode` values of `lib/doh.h`). At the [`Resolver`] boundary every DoH
//! failure — a `DOH_*` wireformat error, a transport failure, or an empty
//! result — surfaces as [`Error::resolve`], i.e.
//! [`CurlCode::CouldntResolveHost`] (`== 6`), matching curl, where a failed DoH
//! lookup is reported as a host-resolution failure.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::dns::{ipv6_works, Address, IpVersion, ResolveFuture, Resolver};
use crate::error::{CurlCode, Error, Result};
use crate::tls::config::TlsConfig;

// ---------------------------------------------------------------------------
// Constants (transcribed verbatim from lib/doh.h and lib/doh.c)
// ---------------------------------------------------------------------------

/// DNS CLASS `IN` ("the Internet") — `DNS_CLASS_IN` (`lib/doh.c:41`). Every DoH
/// query is issued with QCLASS `IN`, and every answer record must carry CLASS
/// `IN` or it is rejected with [`DohCode::UnexpectedClass`].
const DNS_CLASS_IN: u16 = 0x0001;

/// The largest DoH request packet curl will build, based on RFCs 1034/1035 —
/// `DOH_MAX_DNSREQ_SIZE = (256 + 16)` (`lib/doh.h:80`). The request-encoder
/// buffer is exactly this size; an encoding whose length would exceed it is a
/// [`DohCode::NameTooLong`].
pub const DOH_MAX_DNSREQ_SIZE: usize = 256 + 16;

/// Maximum number of addresses (`A` + `AAAA` combined) stored from a set of DoH
/// answers — `DOH_MAX_ADDR` (`lib/doh.h:119`). Addresses beyond this are
/// silently ignored, exactly as `doh_store_a` / `doh_store_aaaa` do.
pub const DOH_MAX_ADDR: usize = 24;

/// Maximum number of CNAME chains recorded from a DoH answer — `DOH_MAX_CNAME`
/// (`lib/doh.h:120`). CNAMEs beyond this are silently skipped
/// (`doh_store_cname`).
pub const DOH_MAX_CNAME: usize = 4;

/// Maximum number of HTTPS resource records recorded — `DOH_MAX_HTTPS`
/// (`lib/doh.h:121`). Records beyond this are silently ignored
/// (`doh_store_https`).
pub const DOH_MAX_HTTPS: usize = 4;

/// The initial [`DohEntry::ttl`] value — curl's `de_init` sets `de->ttl =
/// INT_MAX` (`lib/doh.c:706`) and every answer record lowers it toward the true
/// minimum TTL. Transcribed as `INT_MAX` (not `u32::MAX`) for exact parity.
const DOH_TTL_INIT: u32 = i32::MAX as u32;

/// Upper bound on the size of a DoH HTTP response body accepted before the
/// transfer is abandoned — curl's `DYN_DOH_RESPONSE` (`lib/curlx/dynbuf.h:65`).
/// A DNS message carried over HTTP is small; bounding the body keeps a
/// misbehaving or hostile DoH server from forcing unbounded buffering.
const DOH_RESPONSE_MAX: usize = 3000;

// ---------------------------------------------------------------------------
// Phase 1 — DohCode: the 14 DOHcode wireformat-error values (← lib/doh.h:30-45)
// ---------------------------------------------------------------------------

/// A DoH wireformat status code, reproducing curl's `DOHcode` enum
/// (`lib/doh.h:30-45`) with its exact integer values `0..=13`.
///
/// These classify problems encountered while **encoding a request** or
/// **decoding a response**; they are internal diagnostics (curl logs them via
/// `doh_strerror`) and are ultimately collapsed to
/// [`CurlCode::CouldntResolveHost`] at the [`Resolver`] boundary. The
/// discriminants are frozen so [`DohCode::as_str`] can reproduce curl's
/// `errors[]` message table verbatim for `--trace` parity.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DohCode {
    /// `DOH_OK` (0) — success; no error.
    Ok = 0,
    /// `DOH_DNS_BAD_LABEL` (1) — a QNAME/CNAME label was empty or longer than
    /// 63 bytes, or had reserved high bits set.
    BadLabel = 1,
    /// `DOH_DNS_OUT_OF_RANGE` (2) — a field or record ran past the end of the
    /// buffer.
    OutOfRange = 2,
    /// `DOH_DNS_LABEL_LOOP` (3) — name-compression pointers formed a loop.
    LabelLoop = 3,
    /// `DOH_TOO_SMALL_BUFFER` (4) — the output buffer was smaller than the
    /// encoded request length.
    TooSmallBuffer = 4,
    /// `DOH_OUT_OF_MEM` (5) — an allocation failed (retained for value parity;
    /// the safe-Rust rewrite does not fail allocations here).
    OutOfMem = 5,
    /// `DOH_DNS_RDATA_LEN` (6) — an `A`/`AAAA` record's RDLENGTH did not match
    /// the address size (4 / 16).
    RdataLen = 6,
    /// `DOH_DNS_MALFORMAT` (7) — trailing bytes remained after the declared
    /// record counts were consumed.
    Malformat = 7,
    /// `DOH_DNS_BAD_RCODE` (8) — the response RCODE was non-zero ("no such
    /// name" and friends).
    BadRcode = 8,
    /// `DOH_DNS_UNEXPECTED_TYPE` (9) — an answer record's TYPE was neither the
    /// queried type nor CNAME/DNAME.
    UnexpectedType = 9,
    /// `DOH_DNS_UNEXPECTED_CLASS` (10) — an answer record's CLASS was not `IN`.
    UnexpectedClass = 10,
    /// `DOH_NO_CONTENT` (11) — the response parsed cleanly but stored no
    /// address, CNAME, or HTTPS record.
    NoContent = 11,
    /// `DOH_DNS_BAD_ID` (12) — the response ID was not the fixed `0x0000` curl
    /// sends.
    BadId = 12,
    /// `DOH_DNS_NAME_TOO_LONG` (13) — the encoded request would exceed
    /// [`DOH_MAX_DNSREQ_SIZE`].
    NameTooLong = 13,
}

impl DohCode {
    /// Returns curl's human-readable message for this code — the `errors[]`
    /// table in `lib/doh.c:44-59`, used verbatim so `--trace` DoH diagnostics
    /// match curl 8.x. [`DohCode::Ok`] maps to the empty string, as in curl.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DohCode::Ok => "",
            DohCode::BadLabel => "Bad label",
            DohCode::OutOfRange => "Out of range",
            DohCode::LabelLoop => "Label loop",
            DohCode::TooSmallBuffer => "Too small",
            DohCode::OutOfMem => "Out of memory",
            DohCode::RdataLen => "RDATA length",
            DohCode::Malformat => "Malformat",
            DohCode::BadRcode => "Bad RCODE",
            DohCode::UnexpectedType => "Unexpected TYPE",
            DohCode::UnexpectedClass => "Unexpected CLASS",
            DohCode::NoContent => "No content",
            DohCode::BadId => "Bad ID",
            DohCode::NameTooLong => "Name too long",
        }
    }
}

impl std::fmt::Display for DohCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Phase 1 — DnsType: the DNS record TYPE values used by DoH (← lib/doh.h:47-54)
// ---------------------------------------------------------------------------

/// The DNS record TYPE values curl's DoH code queries and parses, reproducing
/// the relevant members of curl's `DNStype` enum (`lib/doh.h:47-54`).
///
/// Only the types curl actually uses are represented (Minimal Change Mandate):
/// [`DnsType::A`] and [`DnsType::Aaaa`] are the **query** types; [`DnsType::Cname`]
/// and [`DnsType::Dname`] are accepted in answers alongside the queried type;
/// [`DnsType::Https`] is the SVCB/HTTPS record type. `NS` (2) is not represented
/// as a queryable type but its numeric value is handled implicitly by the
/// decoder's "unexpected type" path.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsType {
    /// `CURL_DNS_TYPE_A` (1) — an IPv4 address record.
    A = 1,
    /// `CURL_DNS_TYPE_CNAME` (5) — a canonical-name alias record.
    Cname = 5,
    /// `CURL_DNS_TYPE_AAAA` (28) — an IPv6 address record.
    Aaaa = 28,
    /// `CURL_DNS_TYPE_DNAME` (39, RFC 6672) — a delegation-name record; curl
    /// accepts and ignores it, relying on the synthesized CNAME.
    Dname = 39,
    /// `CURL_DNS_TYPE_HTTPS` (65) — an HTTPS/SVCB resource record.
    Https = 65,
}

impl DnsType {
    /// The 16-bit wire value of this record type.
    #[must_use]
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// A short human-readable name for `--trace` diagnostics — curl's
    /// `doh_type2name` (`lib/doh.c:1011`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            DnsType::A => "A",
            DnsType::Aaaa => "AAAA",
            DnsType::Https => "HTTPS",
            DnsType::Cname => "CNAME",
            DnsType::Dname => "DNAME",
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 1 — DohEntry: the answer-aggregation struct (← struct dohentry)
// ---------------------------------------------------------------------------

/// The accumulated result of decoding one or more DoH answers, the idiomatic
/// replacement for curl's `struct dohentry` (`lib/doh.h:146-156`).
///
/// A single [`DohEntry`] aggregates the records from **both** the `A` and `AAAA`
/// probes (curl decodes each probe's response into the *same* `dohentry`), so
/// the merged [`addr`](DohEntry::addr) list carries IPv4 addresses first
/// (`DOH_SLOT_IPV4`), then IPv6 (`DOH_SLOT_IPV6`), preserving each response's
/// record order — the ordering the connection layer's Happy-Eyeballs logic
/// depends on.
///
/// curl's `struct dohaddr` is a `{ int type; union { v4[4]; v6[16] } }`; here an
/// [`IpAddr`] captures both the family and the octets in one safe type, so the
/// `A`-vs-`AAAA` distinction is the [`IpAddr`] variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohEntry {
    /// Collected `A`/`AAAA` addresses, in decode order, capped at
    /// [`DOH_MAX_ADDR`]. An [`IpAddr::V4`] came from an `A` record, an
    /// [`IpAddr::V6`] from an `AAAA` record.
    addr: Vec<IpAddr>,
    /// Collected CNAME/DNAME target names, capped at [`DOH_MAX_CNAME`].
    cname: Vec<String>,
    /// Collected raw HTTPS-RR record octets, capped at [`DOH_MAX_HTTPS`]. Only
    /// populated when an `HTTPS` (type 65) record is queried and returned; the
    /// `A`/`AAAA` resolution path never fills this (see the module docs).
    https_rrs: Vec<Vec<u8>>,
    /// The minimum TTL seen across all stored records, in seconds. Initialized
    /// to [`DOH_TTL_INIT`] (`INT_MAX`) and lowered by each record — curl's
    /// `if(ttl < d->ttl) d->ttl = ttl` (`lib/doh.c:776`).
    ttl: u32,
}

impl Default for DohEntry {
    fn default() -> Self {
        DohEntry::new()
    }
}

impl DohEntry {
    /// Creates an empty entry with `ttl` initialized to [`DOH_TTL_INIT`] —
    /// curl's `de_init` (`lib/doh.c:702`).
    #[must_use]
    pub fn new() -> Self {
        DohEntry {
            addr: Vec::new(),
            cname: Vec::new(),
            https_rrs: Vec::new(),
            ttl: DOH_TTL_INIT,
        }
    }

    /// Stores one `A` (IPv4) address — curl's `doh_store_a` (`lib/doh.c:564`).
    /// Silently ignores the address once [`DOH_MAX_ADDR`] have been collected.
    fn store_a(&mut self, octets: [u8; 4]) {
        if self.addr.len() < DOH_MAX_ADDR {
            self.addr.push(IpAddr::V4(Ipv4Addr::from(octets)));
        }
    }

    /// Stores one `AAAA` (IPv6) address — curl's `doh_store_aaaa`
    /// (`lib/doh.c:576`). Silently ignores the address once [`DOH_MAX_ADDR`]
    /// have been collected.
    fn store_aaaa(&mut self, octets: [u8; 16]) {
        if self.addr.len() < DOH_MAX_ADDR {
            self.addr.push(IpAddr::V6(Ipv6Addr::from(octets)));
        }
    }

    /// Stores one raw HTTPS-RR record — curl's `doh_store_https`
    /// (`lib/doh.c:589`). Silently ignores the record once [`DOH_MAX_HTTPS`]
    /// have been collected.
    fn store_https(&mut self, raw: &[u8]) {
        if self.https_rrs.len() < DOH_MAX_HTTPS {
            self.https_rrs.push(raw.to_vec());
        }
    }

    /// Lowers [`ttl`](DohEntry::ttl) toward `candidate` — curl's
    /// `if(ttl < d->ttl) d->ttl = ttl` (`lib/doh.c:776`).
    fn observe_ttl(&mut self, candidate: u32) {
        if candidate < self.ttl {
            self.ttl = candidate;
        }
    }

    /// The collected addresses, in decode order.
    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addr
    }

    /// The number of collected addresses — curl's `de->numaddr`.
    #[must_use]
    pub fn numaddr(&self) -> usize {
        self.addr.len()
    }

    /// The collected CNAME/DNAME target names, in decode order.
    #[must_use]
    pub fn cnames(&self) -> &[String] {
        &self.cname
    }

    /// The collected raw HTTPS-RR records, in decode order.
    #[must_use]
    pub fn https_records(&self) -> &[Vec<u8>] {
        &self.https_rrs
    }

    /// The minimum TTL observed across all stored records, in seconds.
    #[must_use]
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Converts the aggregated records to the shared [`Address`], stamping every
    /// address with `port` — curl's `doh2ai` (`lib/doh.c:915`).
    ///
    /// The endpoint order is preserved exactly (IPv4 first, then IPv6, in the
    /// order the records were decoded), which is the Happy-Eyeballs contract of
    /// [`Address`]. The observed minimum TTL is attached (unless it is still the
    /// [`DOH_TTL_INIT`] sentinel, meaning no record set it).
    ///
    /// # Errors
    ///
    /// Returns [`Error::resolve`] ([`CurlCode::CouldntResolveHost`], `== 6`)
    /// when no addresses were collected — curl's `if(!de->numaddr) return
    /// CURLE_COULDNT_RESOLVE_HOST` (`lib/doh.c:931`).
    pub fn to_address(&self, hostname: &str, port: u16) -> Result<Address> {
        if self.addr.is_empty() {
            return Err(Error::resolve(hostname));
        }

        let endpoints: Vec<SocketAddr> = self
            .addr
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();

        let mut address = Address::new(endpoints);
        // curl records the queried hostname as each node's `ai_canonname`
        // (`doh2ai` copies `hostname` into `ai_canonname`).
        address.set_canonical_name(hostname);
        // Attach the TTL only when a record actually lowered it from the
        // INT_MAX sentinel; a bare sentinel is not a real TTL.
        if self.ttl != DOH_TTL_INIT {
            address.set_ttl(Duration::from_secs(u64::from(self.ttl)));
        }
        Ok(address)
    }

    /// Folds the records of `other` into this entry, respecting every `DOH_MAX_*`
    /// cap and lowering the TTL toward the combined minimum.
    ///
    /// curl decodes both the `A` and `AAAA` probe responses into a **single**
    /// `dohentry` (`lib/doh.c:1199` `Curl_doh_is_resolved`), so the caps apply
    /// across the merged set. Because each probe's answer records only match its
    /// queried family, merging the IPv4 (`DOH_SLOT_IPV4`) entry first and the
    /// IPv6 (`DOH_SLOT_IPV6`) entry second yields the IPv4-before-IPv6 endpoint
    /// ordering the Happy-Eyeballs layer expects.
    fn merge_from(&mut self, other: &DohEntry) {
        for &ip in &other.addr {
            if self.addr.len() < DOH_MAX_ADDR {
                self.addr.push(ip);
            }
        }
        for cname in &other.cname {
            if self.cname.len() < DOH_MAX_CNAME {
                self.cname.push(cname.clone());
            }
        }
        for rr in &other.https_rrs {
            if self.https_rrs.len() < DOH_MAX_HTTPS {
                self.https_rrs.push(rr.clone());
            }
        }
        self.observe_ttl(other.ttl);
    }
}

// ---------------------------------------------------------------------------
// Phase 2 — request wireformat encoder (← doh_req_encode, doh.c:72)
// ---------------------------------------------------------------------------

/// Encodes an RFC 8484 / RFC 1035 DNS query for `host` of type `dnstype` into
/// `buf`, returning the number of bytes written — curl's `doh_req_encode`
/// (`lib/doh.c:72`). The `buf`-length parameter exists so the
/// [`DohCode::TooSmallBuffer`] path is reachable and unit-testable, exactly like
/// curl's `UNITTEST doh_req_encode(host, dnstype, dnsp, len, olen)`.
///
/// The produced packet is:
///
/// * a **12-byte header**: id `0x0000`; flags byte 1 `0x01` (only the RD /
///   recursion-desired bit set); flags byte 2 `0x00`; QDCOUNT `1`; ANCOUNT,
///   NSCOUNT, ARCOUNT all `0` — every 16-bit field big-endian;
/// * the **QNAME**: each dot-separated label written as a length byte followed
///   by the label bytes, terminated by a zero (root) byte;
/// * the **QTYPE** (`dnstype`, big-endian) and **QCLASS** (`IN` = `0x0001`).
///
/// # Errors
///
/// * [`DohCode::NameTooLong`] — the encoded length would exceed
///   [`DOH_MAX_DNSREQ_SIZE`].
/// * [`DohCode::TooSmallBuffer`] — `buf` is shorter than the encoded length.
/// * [`DohCode::BadLabel`] — a label is empty (a leading dot or two consecutive
///   dots) or longer than 63 bytes.
pub fn doh_req_encode_into(
    host: &str,
    dnstype: DnsType,
    buf: &mut [u8],
) -> std::result::Result<usize, DohCode> {
    let host_bytes = host.as_bytes();
    let hostlen = host_bytes.len();

    // Expected length: 12-byte header + the QNAME encoding + 4 bytes of
    // QTYPE/QCLASS. The QNAME of a name that ends with a dot is one byte longer
    // than the name (the labels plus the root byte); a name WITHOUT a trailing
    // dot needs one extra byte for that root label — curl's `expected_len`
    // computation (`lib/doh.c:106-108`).
    let mut expected_len = 12 + 1 + hostlen + 4;
    let trailing_dot = host_bytes.last() == Some(&b'.');
    if !trailing_dot {
        expected_len += 1;
    }

    if expected_len > DOH_MAX_DNSREQ_SIZE {
        return Err(DohCode::NameTooLong);
    }
    if buf.len() < expected_len {
        return Err(DohCode::TooSmallBuffer);
    }

    let mut pos = 0usize;

    // 12-byte header. Only the RD bit (0x01 in flags byte 1) and QDCOUNT (=1)
    // are non-zero; every other field is zero. All 16-bit fields big-endian.
    let header: [u8; 12] = [
        0x00, 0x00, // ID = 0x0000 (curl's fixed convention; response must echo)
        0x01, 0x00, // flags: RD set (byte1=0x01), byte2=0x00
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
    ];
    buf[pos..pos + 12].copy_from_slice(&header);
    pos += 12;

    // QNAME: encode each dot-separated label as [len][bytes]. A label that is
    // empty (leading/double dot) or longer than 63 bytes is invalid — curl's
    // `if((labellen > 63) || (!labellen)) return DOH_DNS_BAD_LABEL`.
    let mut i = 0usize;
    while i < hostlen {
        let dot = host_bytes[i..]
            .iter()
            .position(|&b| b == b'.')
            .map(|p| i + p);
        let labellen = match dot {
            Some(d) => d - i,
            None => hostlen - i,
        };
        if labellen == 0 || labellen > 63 {
            return Err(DohCode::BadLabel);
        }
        buf[pos] = labellen as u8;
        pos += 1;
        buf[pos..pos + labellen].copy_from_slice(&host_bytes[i..i + labellen]);
        pos += labellen;
        i += labellen;
        // Advance past the dot, but only if there was one (curl: `if(dot) hostp++`).
        if dot.is_some() {
            i += 1;
        }
    }

    // Root (zero-length) label terminates the QNAME.
    buf[pos] = 0;
    pos += 1;

    // QTYPE (big-endian) then QCLASS = IN (big-endian).
    let qtype = dnstype.as_u16().to_be_bytes();
    buf[pos..pos + 2].copy_from_slice(&qtype);
    pos += 2;
    let qclass = DNS_CLASS_IN.to_be_bytes();
    buf[pos..pos + 2].copy_from_slice(&qclass);
    pos += 2;

    // curl asserts the written length matches the up-front estimate
    // (`DEBUGASSERT(*olen == expected_len)`); mirror it in debug/test builds.
    debug_assert_eq!(pos, expected_len);
    Ok(pos)
}

/// Convenience wrapper over [`doh_req_encode_into`] that returns a freshly
/// allocated request packet, using a [`DOH_MAX_DNSREQ_SIZE`] scratch buffer
/// (exactly the fixed-size `req_body[DOH_MAX_DNSREQ_SIZE]` curl encodes into).
///
/// # Errors
///
/// Propagates the [`DohCode`] from [`doh_req_encode_into`].
pub fn doh_req_encode(host: &str, dnstype: DnsType) -> std::result::Result<Vec<u8>, DohCode> {
    let mut buf = [0u8; DOH_MAX_DNSREQ_SIZE];
    let olen = doh_req_encode_into(host, dnstype, &mut buf)?;
    Ok(buf[..olen].to_vec())
}

// ---------------------------------------------------------------------------
// Phase 3 — response wireformat decoder (← doh_resp_decode, doh.c:711)
// ---------------------------------------------------------------------------

/// The `NS` record TYPE value (`CURL_DNS_TYPE_NS = 2`). Not queried, but its
/// numeric value participates in the `DOH_NO_CONTENT` determination.
const DNS_TYPE_NS: u16 = 2;

/// Reads a big-endian 16-bit field — curl's `doh_get16bit` (`lib/doh.c:545`).
/// The caller guarantees `index + 2 <= doh.len()` (curl checks bounds before
/// every read), so indexing cannot panic.
fn doh_get16bit(doh: &[u8], index: usize) -> u16 {
    u16::from_be_bytes([doh[index], doh[index + 1]])
}

/// Reads a big-endian 32-bit field — curl's `doh_get32bit` (`lib/doh.c:551`).
/// The caller guarantees `index + 4 <= doh.len()`.
fn doh_get32bit(doh: &[u8], index: usize) -> u32 {
    u32::from_be_bytes([doh[index], doh[index + 1], doh[index + 2], doh[index + 3]])
}

/// Advances `index` past a QNAME (a question-section name), honoring a single
/// terminal compression pointer — curl's `doh_skipqname` (`lib/doh.c:521`).
///
/// A `0xC0`-tagged length byte is a name pointer: the parser advances two bytes
/// and stops. Any other reserved high bits are a [`DohCode::BadLabel`]. A
/// truncated buffer is [`DohCode::OutOfRange`].
fn doh_skipqname(doh: &[u8], index: &mut usize) -> std::result::Result<(), DohCode> {
    let dohlen = doh.len();
    loop {
        if dohlen < *index + 1 {
            return Err(DohCode::OutOfRange);
        }
        let length = doh[*index];
        if length & 0xc0 == 0xc0 {
            // Name pointer: advance over the two pointer bytes and finish.
            if dohlen < *index + 2 {
                return Err(DohCode::OutOfRange);
            }
            *index += 2;
            break;
        }
        if length & 0xc0 != 0 {
            return Err(DohCode::BadLabel);
        }
        if dohlen < *index + 1 + length as usize {
            return Err(DohCode::OutOfRange);
        }
        *index += 1 + length as usize;
        if length == 0 {
            break;
        }
    }
    Ok(())
}

/// Decodes a (possibly compressed) domain name in RDATA into `d`'s CNAME list —
/// curl's `doh_store_cname` (`lib/doh.c:605`). Follows `0xC0` compression
/// pointers with a 128-step loop guard; an exhausted guard is
/// [`DohCode::LabelLoop`]. Names beyond [`DOH_MAX_CNAME`] are silently skipped.
///
/// Label bytes are appended as UTF-8 (via lossy conversion). DNS names are
/// ASCII (A-labels) in practice, so this is exact for every valid name; the
/// stored CNAME is used only for diagnostics and the "no content" check, never
/// for the returned address list.
fn doh_store_cname(doh: &[u8], start: usize, d: &mut DohEntry) -> std::result::Result<(), DohCode> {
    if d.cname.len() == DOH_MAX_CNAME {
        return Ok(()); // at capacity — skip, as curl does
    }
    let dohlen = doh.len();
    let mut index = start;
    let mut name = String::new();
    // "a valid DNS name can never loop this much" (lib/doh.c:609).
    let mut loop_guard: u32 = 128;

    loop {
        if index >= dohlen {
            return Err(DohCode::OutOfRange);
        }
        let length = doh[index];
        if length & 0xc0 == 0xc0 {
            // Compression pointer: jump to the 14-bit offset and continue.
            if index + 1 >= dohlen {
                return Err(DohCode::OutOfRange);
            }
            let newpos = (((length & 0x3f) as usize) << 8) | doh[index + 1] as usize;
            index = newpos;
        } else if length & 0xc0 != 0 {
            return Err(DohCode::BadLabel);
        } else {
            index += 1;
            if length != 0 {
                if !name.is_empty() {
                    name.push('.');
                }
                if index + length as usize > dohlen {
                    return Err(DohCode::BadLabel);
                }
                name.push_str(&String::from_utf8_lossy(
                    &doh[index..index + length as usize],
                ));
                index += length as usize;
            }
        }

        // Mirrors curl's do-while condition `while(length && --loop)`: the root
        // label (length == 0) terminates without consuming the guard; every
        // label or pointer follow (length != 0) decrements it.
        if length == 0 {
            break;
        }
        loop_guard -= 1;
        if loop_guard == 0 {
            break;
        }
    }

    if loop_guard == 0 {
        return Err(DohCode::LabelLoop);
    }
    d.cname.push(name);
    Ok(())
}

/// Dispatches one answer record's RDATA to the appropriate store, by TYPE —
/// curl's `doh_rdata` (`lib/doh.c:655`).
///
/// The caller guarantees `index + rdlength <= doh.len()`. `A`/`AAAA` records
/// whose RDLENGTH does not match the address size are [`DohCode::RdataLen`].
/// Unsupported types are silently skipped, exactly as curl does.
fn doh_rdata(
    doh: &[u8],
    rdlength: u16,
    rtype: u16,
    index: usize,
    d: &mut DohEntry,
) -> std::result::Result<(), DohCode> {
    match rtype {
        t if t == DnsType::A as u16 => {
            if rdlength != 4 {
                return Err(DohCode::RdataLen);
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&doh[index..index + 4]);
            d.store_a(octets);
        }
        t if t == DnsType::Aaaa as u16 => {
            if rdlength != 16 {
                return Err(DohCode::RdataLen);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&doh[index..index + 16]);
            d.store_aaaa(octets);
        }
        t if t == DnsType::Https as u16 => {
            // Raw HTTPS-RR octets (curl's `doh_store_https`, under USE_HTTPSRR).
            // Only reached when the queried type is HTTPS; the A/AAAA path never
            // gets here because a type-65 record fails the earlier type check.
            d.store_https(&doh[index..index + rdlength as usize]);
        }
        t if t == DnsType::Cname as u16 => {
            doh_store_cname(doh, index, d)?;
        }
        t if t == DnsType::Dname as u16 => {
            // Explicitly skipped; curl relies on the synthesized CNAME.
        }
        _ => {
            // Unsupported type — skip it (curl's `default`).
        }
    }
    Ok(())
}

/// Decodes a complete DoH response message into `d` — curl's `doh_resp_decode`
/// (`lib/doh.c:711`). `dnstype` is the type that was queried (`A` or `AAAA`);
/// answer records must carry that type or be a CNAME/DNAME.
///
/// The 12-byte header is validated (ID must be the `0x0000` curl sent, else
/// [`DohCode::BadId`]; RCODE must be `0`, else [`DohCode::BadRcode`]), the
/// question section is skipped, and each answer record is parsed and stored. The
/// authority (NS) and additional (AR) sections are skipped. Any trailing bytes
/// are [`DohCode::Malformat`]; a response that stores nothing is
/// [`DohCode::NoContent`].
///
/// # Errors
///
/// Returns the [`DohCode`] classifying the first problem encountered.
pub fn doh_resp_decode(
    doh: &[u8],
    dnstype: DnsType,
    d: &mut DohEntry,
) -> std::result::Result<(), DohCode> {
    let dohlen = doh.len();

    // 12-byte header: length, fixed ID, and RCODE checks.
    if dohlen < 12 {
        return Err(DohCode::TooSmallBuffer);
    }
    // curl sends ID 0x0000 and requires the response to echo it.
    if doh[0] != 0 || doh[1] != 0 {
        return Err(DohCode::BadId);
    }
    let rcode = doh[3] & 0x0f;
    if rcode != 0 {
        return Err(DohCode::BadRcode); // e.g. NXDOMAIN — "no such name"
    }

    let mut index = 12usize;
    let dnstype_val = dnstype.as_u16();

    // Skip the question (QD) section.
    let mut qdcount = doh_get16bit(doh, 4);
    while qdcount > 0 {
        doh_skipqname(doh, &mut index)?;
        if dohlen < index + 4 {
            return Err(DohCode::OutOfRange);
        }
        index += 4; // question's QTYPE + QCLASS
        qdcount -= 1;
    }

    // Parse the answer (AN) section.
    let mut last_type: u16 = 0;
    let mut ancount = doh_get16bit(doh, 6);
    while ancount > 0 {
        doh_skipqname(doh, &mut index)?;

        if dohlen < index + 2 {
            return Err(DohCode::OutOfRange);
        }
        let rtype = doh_get16bit(doh, index);
        last_type = rtype;
        // Accept the queried type, or a CNAME/DNAME (which may alias to it).
        if rtype != DnsType::Cname as u16 && rtype != DnsType::Dname as u16 && rtype != dnstype_val
        {
            return Err(DohCode::UnexpectedType);
        }
        index += 2;

        if dohlen < index + 2 {
            return Err(DohCode::OutOfRange);
        }
        let dnsclass = doh_get16bit(doh, index);
        if dnsclass != DNS_CLASS_IN {
            return Err(DohCode::UnexpectedClass);
        }
        index += 2;

        if dohlen < index + 4 {
            return Err(DohCode::OutOfRange);
        }
        let ttl = doh_get32bit(doh, index);
        d.observe_ttl(ttl);
        index += 4;

        if dohlen < index + 2 {
            return Err(DohCode::OutOfRange);
        }
        let rdlength = doh_get16bit(doh, index);
        index += 2;
        if dohlen < index + rdlength as usize {
            return Err(DohCode::OutOfRange);
        }

        doh_rdata(doh, rdlength, rtype, index, d)?;
        index += rdlength as usize;
        ancount -= 1;
    }

    // Skip the authority (NS) section.
    let mut nscount = doh_get16bit(doh, 8);
    while nscount > 0 {
        doh_skipqname(doh, &mut index)?;
        if dohlen < index + 8 {
            return Err(DohCode::OutOfRange);
        }
        index += 2 + 2 + 4; // TYPE + CLASS + TTL
        if dohlen < index + 2 {
            return Err(DohCode::OutOfRange);
        }
        let rdlength = doh_get16bit(doh, index);
        index += 2;
        if dohlen < index + rdlength as usize {
            return Err(DohCode::OutOfRange);
        }
        index += rdlength as usize;
        nscount -= 1;
    }

    // Skip the additional (AR) section.
    let mut arcount = doh_get16bit(doh, 10);
    while arcount > 0 {
        doh_skipqname(doh, &mut index)?;
        if dohlen < index + 8 {
            return Err(DohCode::OutOfRange);
        }
        index += 2 + 2 + 4; // TYPE + CLASS + TTL
        if dohlen < index + 2 {
            return Err(DohCode::OutOfRange);
        }
        let rdlength = doh_get16bit(doh, index);
        index += 2;
        if dohlen < index + rdlength as usize {
            return Err(DohCode::OutOfRange);
        }
        index += rdlength as usize;
        arcount -= 1;
    }

    // Everything must have been consumed exactly.
    if index != dohlen {
        return Err(DohCode::Malformat);
    }

    // Nothing usable stored (and the last record was not an NS) → no content.
    if last_type != DNS_TYPE_NS && d.cname.is_empty() && d.addr.is_empty() {
        return Err(DohCode::NoContent);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 6 — error mapping (← curl: DoH failures surface as resolve failures)
// ---------------------------------------------------------------------------

/// Logs `detail` for `--trace`/`--verbose` parity and returns the resolver-level
/// error that every DoH failure collapses to.
///
/// curl reports a failed DoH lookup as `CURLE_COULDNT_RESOLVE_HOST`; the
/// specific wireformat cause (a [`DohCode`]) or transport cause is only exposed
/// in verbose/trace output. Accordingly every transport error, TLS failure,
/// wireformat [`DohCode`], and empty result maps here to
/// [`CurlCode::CouldntResolveHost`] (`== 6`), carrying `host` so a direct caller
/// still sees curl's canonical resolve message.
fn resolve_failure(host: &str, detail: &str) -> Error {
    tracing::debug!(target: "curl::dns::doh", host = %host, detail = %detail, "DoH resolution failed");
    Error::with_context(
        CurlCode::CouldntResolveHost,
        format!("Could not resolve host: {host} (DoH: {detail})"),
    )
}

// ---------------------------------------------------------------------------
// Phase 5 — DoH-specific TLS verification options (← doh_probe_run inheritance)
// ---------------------------------------------------------------------------

/// The subset of the parent easy handle's SSL options that curl's
/// `doh_probe_run` (`lib/doh.c:333-401`) inherits onto the internal DoH
/// connection.
///
/// The three verify toggles are the **DoH-specific** options
/// (`CURLOPT_DOH_SSL_VERIFYHOST` / `_VERIFYPEER` / `_VERIFYSTATUS`), which curl
/// defaults to **on / on / off** (`doh_verifyhost` and `doh_verifypeer` are
/// initialized `TRUE` in `lib/url.c:393-394`). The CA sources and CRL are
/// inherited verbatim from the parent handle (`custom_cafile`, `custom_capath`,
/// `custom_cablob`, `STRING_SSL_CRLFILE`). Certificate validation is therefore
/// **on by default**; it is never disabled implicitly (AAP §0.7.3).
///
/// EC-curve selection (`CURLOPT_SSL_EC_CURVES`) is intentionally not surfaced:
/// [`TlsConfig`] exposes no curve knob, and `rustls` performs its own
/// named-group negotiation, so curve inheritance is subsumed by the backend
/// (Minimal Change Mandate — nothing beyond what parity requires is added).
#[derive(Debug, Clone)]
pub struct DohSslOptions {
    /// `CURLOPT_DOH_SSL_VERIFYHOST` — verify the server certificate's hostname
    /// (curl's `SSL_VERIFYHOST = 2` when on). Defaults to `true`.
    pub verify_host: bool,
    /// `CURLOPT_DOH_SSL_VERIFYPEER` — verify the server certificate chain
    /// (curl's `SSL_VERIFYPEER = 1` when on). Defaults to `true`.
    pub verify_peer: bool,
    /// `CURLOPT_DOH_SSL_VERIFYSTATUS` — request an OCSP staple check where the
    /// backend supports it. Defaults to `false`.
    pub verify_status: bool,
    /// Inherited `CURLOPT_CAINFO` — a PEM bundle of trusted CA certificates.
    pub ca_info: Option<PathBuf>,
    /// Inherited `CURLOPT_CAPATH` — a directory of hashed CA certificates.
    pub ca_path: Option<PathBuf>,
    /// Inherited `CURLOPT_CAINFO_BLOB` — an in-memory PEM CA bundle.
    pub ca_info_blob: Option<Vec<u8>>,
    /// Inherited `CURLOPT_CRLFILE` — a PEM certificate-revocation list.
    pub crl_file: Option<PathBuf>,
}

impl Default for DohSslOptions {
    /// The curl DoH defaults: hostname and peer verification **on**, status
    /// check **off**, no explicit CA overrides (the platform/webpki roots are
    /// used) — `lib/url.c:393-394`.
    fn default() -> Self {
        DohSslOptions {
            verify_host: true,
            verify_peer: true,
            verify_status: false,
            ca_info: None,
            ca_path: None,
            ca_info_blob: None,
            crl_file: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 4 — DohResolver: the DoH transport + Resolver implementation
// ---------------------------------------------------------------------------

/// A DNS-over-HTTPS resolver bound to one `CURLOPT_DOH_URL` endpoint, the
/// idiomatic-Rust replacement for curl's `Curl_doh` machinery (`lib/doh.c`).
///
/// Constructed once (when a DoH URL is configured) and shared as a
/// [`Resolver`]; each [`resolve`](Resolver::resolve) call fires the `A` (and,
/// per curl's policy, `AAAA`) probes against the endpoint over an internal
/// [`hyper`] HTTP/2 client (with HTTP/1.1 fallback) on Tokio, then decodes and
/// merges the answers. The endpoint's own TLS configuration (built once from the
/// inherited [`DohSslOptions`]) has certificate validation on by default.
pub struct DohResolver {
    /// The validated DoH endpoint URL (absolute; used as the HTTP/2 request
    /// URI and the source of the HTTP/1.1 origin-form path + `Host`).
    url: Uri,
    /// The endpoint hostname — TLS SNI, the TCP-connect target, and the
    /// HTTP/1.1 `Host` header authority.
    host: String,
    /// The endpoint port (`443` for `https`, `80` for the debug-only `http`).
    port: u16,
    /// The prebuilt `rustls` client config for the DoH connection, or `None`
    /// for a debug-only cleartext (`http`) endpoint. ALPN advertises `h2` then
    /// `http/1.1`, matching curl's `CURL_HTTP_VERSION_2TLS`.
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl std::fmt::Debug for DohResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohResolver")
            .field("url", &self.url)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls.is_some())
            .finish()
    }
}

impl DohResolver {
    /// Builds a DoH resolver for `doh_url` using the default DoH SSL options
    /// (hostname + peer verification on) — the common configuration when only
    /// `CURLOPT_DOH_URL` is set.
    ///
    /// # Errors
    ///
    /// Returns an error if `doh_url` is malformed, is not `https` (outside debug
    /// builds), lacks a host, or if the TLS configuration fails to build.
    pub fn new(doh_url: &str) -> Result<Self> {
        Self::with_options(doh_url, &DohSslOptions::default())
    }

    /// Builds a DoH resolver for `doh_url`, applying the DoH-specific SSL
    /// options inherited from the parent easy handle (Phase 5).
    ///
    /// The endpoint must use `https`; a plaintext `http` endpoint is rejected
    /// except in debug builds, matching curl's `doh_probe_run`, which restricts
    /// `CURLOPT_PROTOCOLS` to HTTPS in production and permits HTTP only under
    /// `DEBUGBUILD`.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::CouldntResolveHost`] for a malformed / non-HTTPS /
    /// host-less URL, or the [`TlsConfig::build`] error if the (validation-on)
    /// `rustls` configuration cannot be constructed.
    pub fn with_options(doh_url: &str, options: &DohSslOptions) -> Result<Self> {
        let url: Uri = doh_url
            .parse()
            .map_err(|_| resolve_failure(doh_url, "malformed DoH URL"))?;

        // curl enforces HTTPS for DoH (DEFAULT_PROTOCOL=https, PROTOCOLS=HTTPS);
        // cleartext HTTP is permitted only in debug builds (DEBUGBUILD), which
        // maps to Rust's `debug_assertions`.
        let is_https = match url.scheme_str() {
            Some("https") => true,
            Some("http") if cfg!(debug_assertions) => false,
            _ => {
                return Err(resolve_failure(
                    doh_url,
                    "DoH URL must use the https scheme",
                ))
            }
        };

        let host = url
            .host()
            .ok_or_else(|| resolve_failure(doh_url, "DoH URL has no host"))?
            .to_owned();
        let port = url.port_u16().unwrap_or(if is_https { 443 } else { 80 });

        let tls = if is_https {
            // Build the DoH connection's rustls config: verification per the
            // DoH options (default on), CA/CRL inherited from the parent, and
            // ALPN advertising h2 then http/1.1 (CURL_HTTP_VERSION_2TLS).
            let mut cfg = TlsConfig::new()
                .with_verify_peer(options.verify_peer)
                .with_verify_host(options.verify_host)
                .with_verify_status(options.verify_status)
                .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
            if let Some(path) = &options.ca_info {
                cfg = cfg.with_ca_info(path.clone());
            }
            if let Some(path) = &options.ca_path {
                cfg = cfg.with_ca_path(path.clone());
            }
            if let Some(blob) = &options.ca_info_blob {
                cfg = cfg.with_ca_info_blob(blob.clone());
            }
            if let Some(path) = &options.crl_file {
                cfg = cfg.with_crl_file(path.clone());
            }
            Some(cfg.build()?)
        } else {
            None
        };

        Ok(DohResolver {
            url,
            host,
            port,
            tls,
        })
    }

    /// The whole DoH resolution: fire the probes curl's `Curl_doh` fires, await
    /// them, merge the successful answers, and convert to an [`Address`].
    async fn resolve_impl(&self, host: &str, port: u16, ip_version: IpVersion) -> Result<Address> {
        // curl's Curl_doh probe policy (lib/doh.c:472-494):
        //   * the A (IPv4) probe is issued UNCONDITIONALLY;
        //   * the AAAA (IPv6) probe is issued iff the caller did not force IPv4
        //     AND the local stack has working IPv6 (Curl_ipv6works).
        // The requested-family narrowing is performed downstream by the
        // resolve() orchestrator via Address::filter_by_ip_version (curl runs no
        // can_resolve_ip_version gate on the DoH path), so a V6-only request
        // discards the IPv4 answers there rather than here.
        let run_aaaa = ip_version != IpVersion::V4 && ipv6_works();

        let a_query =
            doh_req_encode(host, DnsType::A).map_err(|c| resolve_failure(host, c.as_str()))?;

        let (a_result, aaaa_result) = if run_aaaa {
            let aaaa_query = doh_req_encode(host, DnsType::Aaaa)
                .map_err(|c| resolve_failure(host, c.as_str()))?;
            // Fire both probes concurrently and await both, exactly as curl
            // dispatches two sub-transfers and waits for all pending probes.
            let (a, aaaa) = tokio::join!(
                self.run_probe(DnsType::A, a_query),
                self.run_probe(DnsType::Aaaa, aaaa_query),
            );
            (a, Some(aaaa))
        } else {
            (self.run_probe(DnsType::A, a_query).await, None)
        };

        // Merge every probe that decoded successfully into one entry — IPv4
        // (DOH_SLOT_IPV4) first, then IPv6 (DOH_SLOT_IPV6). curl treats the
        // lookup as resolved if AT LEAST one probe decoded OK; both failing (or
        // producing no address) yields COULDNT_RESOLVE_HOST.
        let mut merged = DohEntry::new();
        if let Ok(entry) = &a_result {
            merged.merge_from(entry);
        }
        if let Some(Ok(entry)) = &aaaa_result {
            merged.merge_from(entry);
        }

        // doh2ai: zero addresses (both probes failed, or only CNAME / no-content
        // answers) is a resolution failure (COULDNT_RESOLVE_HOST).
        merged.to_address(host, port)
    }

    /// Runs one DoH probe: connect, (optionally) TLS-handshake, POST the query
    /// over HTTP/2 or HTTP/1.1, and decode the response into a [`DohEntry`].
    async fn run_probe(&self, dnstype: DnsType, query: Vec<u8>) -> Result<DohEntry> {
        // Bootstrap the DoH server's OWN address via the system resolver — never
        // via DoH recursively (curl's internal DoH easy handle uses the normal
        // asynchronous resolver). tokio's TcpStream::connect performs the
        // getaddrinfo lookup and connects to the first reachable address.
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|_| resolve_failure(&self.host, "DoH server TCP connect failed"))?;

        let response = match &self.tls {
            Some(tls) => {
                // TLS handshake with SNI = the DoH server host; validation
                // follows the DoH verify options baked into `tls`.
                let server_name = ServerName::try_from(self.host.clone())
                    .map_err(|_| resolve_failure(&self.host, "invalid TLS server name"))?;
                let connector = TlsConnector::from(tls.clone());
                let tls_stream = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|_| resolve_failure(&self.host, "DoH TLS handshake failed"))?;
                // CURL_HTTP_VERSION_2TLS: prefer HTTP/2 when ALPN negotiated
                // "h2", otherwise fall back to HTTP/1.1.
                let is_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
                let io = TokioIo::new(tls_stream);
                if is_h2 {
                    send_via_h2(&self.host, io, self.build_request(query, true)?).await?
                } else {
                    send_via_h1(&self.host, io, self.build_request(query, false)?).await?
                }
            }
            None => {
                // Debug-only cleartext DoH: HTTP/1.1 only (no ALPN without TLS,
                // and h2c prior-knowledge is not part of curl's DoH path).
                let io = TokioIo::new(tcp);
                send_via_h1(&self.host, io, self.build_request(query, false)?).await?
            }
        };

        let mut entry = DohEntry::new();
        doh_resp_decode(response.as_ref(), dnstype, &mut entry)
            .map_err(|c| resolve_failure(&self.host, c.as_str()))?;
        Ok(entry)
    }

    /// Builds the DoH HTTP `POST` request carrying `body` (the RFC 8484 DNS
    /// message).
    ///
    /// For HTTP/2 (`is_h2`) the absolute endpoint URI is used and hyper derives
    /// the `:authority` / `:scheme` / `:path` pseudo-headers; for HTTP/1.1 an
    /// origin-form (`path?query`) target plus an explicit `Host` header is used,
    /// because the low-level `hyper::client::conn::http1` client does not
    /// synthesize `Host`. Both carry the RFC 8484 media type on `Content-Type`
    /// and `Accept`.
    fn build_request(&self, body: Vec<u8>, is_h2: bool) -> Result<Request<Full<Bytes>>> {
        let uri: Uri = if is_h2 {
            self.url.clone()
        } else {
            let path = self
                .url
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            path.parse::<Uri>()
                .map_err(|_| resolve_failure(&self.host, "invalid DoH request path"))?
        };

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(http::header::CONTENT_TYPE, "application/dns-message")
            .header(http::header::ACCEPT, "application/dns-message");

        if !is_h2 {
            // HTTP/1.1 requires an explicit Host (the low-level client conn does
            // not add one). Use the URL authority (host[:port]).
            let authority = self
                .url
                .authority()
                .map(|a| a.as_str().to_owned())
                .unwrap_or_else(|| self.host.clone());
            builder = builder.header(http::header::HOST, authority);
        }

        builder
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| resolve_failure(&self.host, "failed to build DoH request"))
    }
}

impl Resolver for DohResolver {
    /// Resolves `host` via DoH — curl's `data->set.doh` branch of `Curl_resolv`.
    ///
    /// The returned future borrows both `self` and `host` for `'a`; it is
    /// `Send` because [`DohResolver`] is `Sync` and all state held across
    /// `await` points (TCP/TLS streams, hyper senders) is `Send`.
    fn resolve<'a>(&'a self, host: &'a str, port: u16, ip_version: IpVersion) -> ResolveFuture<'a> {
        Box::pin(self.resolve_impl(host, port, ip_version))
    }
}

// ---------------------------------------------------------------------------
// Phase 4 — hyper transport helpers (← doh_probe_run over hyper HTTP/2 + HTTP/1)
// ---------------------------------------------------------------------------

/// POSTs `req` over a freshly handshaken HTTP/2 connection on `io` and returns
/// the raw response body (the DNS message), bounded to [`DOH_RESPONSE_MAX`].
///
/// The connection future is driven on a spawned Tokio task for the duration of
/// the exchange; it finishes when the request/response completes and the sender
/// is dropped.
async fn send_via_h2<IO>(host: &str, io: IO, req: Request<Full<Bytes>>) -> Result<Bytes>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .map_err(|_| resolve_failure(host, "DoH HTTP/2 handshake failed"))?;
    tokio::spawn(async move {
        // Drive the connection; ignore the result (errors surface as a failed
        // request future below).
        let _ = conn.await;
    });
    sender
        .ready()
        .await
        .map_err(|_| resolve_failure(host, "DoH HTTP/2 connection not ready"))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|_| resolve_failure(host, "DoH HTTP/2 request failed"))?;
    read_dns_response(host, resp).await
}

/// POSTs `req` over a freshly handshaken HTTP/1.1 connection on `io` and returns
/// the raw response body (the DNS message), bounded to [`DOH_RESPONSE_MAX`].
async fn send_via_h1<IO>(host: &str, io: IO, req: Request<Full<Bytes>>) -> Result<Bytes>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|_| resolve_failure(host, "DoH HTTP/1.1 handshake failed"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
        .ready()
        .await
        .map_err(|_| resolve_failure(host, "DoH HTTP/1.1 connection not ready"))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|_| resolve_failure(host, "DoH HTTP/1.1 request failed"))?;
    read_dns_response(host, resp).await
}

/// Validates the DoH HTTP response and collects its body (the DNS message).
///
/// A non-2xx status is a lookup failure (RFC 8484 signals success with a 2xx
/// code). The body is read through [`Limited`] so a hostile or broken server
/// cannot force unbounded buffering — exceeding [`DOH_RESPONSE_MAX`] is a
/// failure.
async fn read_dns_response(host: &str, resp: hyper::Response<Incoming>) -> Result<Bytes> {
    if !resp.status().is_success() {
        return Err(resolve_failure(
            host,
            "DoH server returned a non-2xx HTTP status",
        ));
    }
    let limited = Limited::new(resp.into_body(), DOH_RESPONSE_MAX);
    let collected = limited.collect().await.map_err(|_| {
        resolve_failure(
            host,
            "DoH response body exceeded the size limit or failed to read",
        )
    })?;
    Ok(collected.to_bytes())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// The wireformat vectors below are transcribed verbatim from curl's own DoH
// unit test (`tests/unit/unit1650.c`), which is the behavioral oracle: the
// encoder must produce byte-identical packets and the decoder must return the
// same `DOHcode` and the same addresses/CNAMEs for each vector.

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    // --- Phase 2: request encoder (← unit1650.c `req[]`) --------------------

    #[test]
    fn encode_a_query_matches_curl_vector() {
        // curl's DNS_Q1: "test.host.name", type A.
        let expected: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
\x04test\x04host\x04name\x00\x00\x01\x00\x01";
        let packet = doh_req_encode("test.host.name", DnsType::A).expect("encode A");
        assert_eq!(packet, expected, "A-query bytes must match curl exactly");
        // 12 header + 3 labels (5 each) + root + qtype + qclass.
        assert_eq!(packet.len(), 32);
        // Header invariants: fixed id 0x0000, RD set, QDCOUNT=1.
        assert_eq!(&packet[0..2], &[0x00, 0x00]);
        assert_eq!(packet[2], 0x01);
        assert_eq!(&packet[4..6], &[0x00, 0x01]);
    }

    #[test]
    fn encode_aaaa_query_matches_curl_vector() {
        // curl's DNS_Q2: "test.host.name", type AAAA (0x1c == 28).
        let expected: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
\x04test\x04host\x04name\x00\x00\x1c\x00\x01";
        let packet = doh_req_encode("test.host.name", DnsType::Aaaa).expect("encode AAAA");
        assert_eq!(packet, expected);
    }

    #[test]
    fn encode_trailing_dot_matches_dotless_form() {
        // A fully-qualified name with a trailing dot and its dot-less form encode
        // to the *same* bytes: curl's `expected_len` compensates for the extra
        // hostname byte precisely because "[ label, dot ] pairs preserve overall
        // length" while the dot-less form adds one byte for the label and one for
        // the root — netting the identical QNAME encoding (`lib/doh.c:82-101`).
        let with = doh_req_encode("example.com.", DnsType::A).unwrap();
        let without = doh_req_encode("example.com", DnsType::A).unwrap();
        assert_eq!(
            with, without,
            "trailing-dot and dot-less names must encode to identical bytes"
        );
        // 12 header + [7]example + [3]com + root + QTYPE + QCLASS = 29.
        assert_eq!(with.len(), 29);
    }

    #[test]
    fn encode_label_over_63_is_bad_label() {
        let host = format!("{}.example.com", "z".repeat(64));
        assert_eq!(doh_req_encode(&host, DnsType::A), Err(DohCode::BadLabel));
        // A 63-byte label is the maximum and must encode successfully.
        let ok = format!("{}.example.com", "z".repeat(63));
        assert!(doh_req_encode(&ok, DnsType::A).is_ok());
    }

    #[test]
    fn encode_empty_label_is_bad_label() {
        // A leading dot / doubled dot produces an empty label.
        assert_eq!(
            doh_req_encode(".example.com", DnsType::A),
            Err(DohCode::BadLabel)
        );
        assert_eq!(doh_req_encode("a..b", DnsType::A), Err(DohCode::BadLabel));
    }

    #[test]
    fn encode_name_too_long_exceeds_max_dnsreq_size() {
        // Build a name whose encoded length exceeds DOH_MAX_DNSREQ_SIZE (272):
        // many maximal labels. expected_len = 12 + 1 + hostlen + 4 (+1).
        let label = "z".repeat(60);
        let host = std::iter::repeat(label)
            .take(6)
            .collect::<Vec<_>>()
            .join(".");
        assert!(host.len() > DOH_MAX_DNSREQ_SIZE);
        assert_eq!(doh_req_encode(&host, DnsType::A), Err(DohCode::NameTooLong));
    }

    #[test]
    fn encode_into_reports_too_small_buffer() {
        // A buffer shorter than the encoded length is DOH_TOO_SMALL_BUFFER.
        let mut tiny = [0u8; 4];
        assert_eq!(
            doh_req_encode_into("example.com", DnsType::A, &mut tiny),
            Err(DohCode::TooSmallBuffer)
        );
    }

    // --- Phase 3: response decoder (← unit1650.c `resp[]`) ------------------

    /// curl's DNS_FOO_EXAMPLE_COM (49 bytes): foo.example.com A 127.0.0.1.
    const DNS_FOO_A_127_0_0_1: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\
\x03foo\x07example\x03com\x00\x00\x01\x00\x01\
\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x37\x00\x04\x7f\x00\x00\x01";

    /// curl's AAAA vector (62 bytes): aaaa.example.com AAAA 2020:2020::2020.
    const DNS_AAAA_2020: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\
\x04aaaa\x07example\x03com\x00\x00\x1c\x00\x01\
\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x37\x00\x10\
\x20\x20\x20\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x20";

    #[test]
    fn decode_a_response_yields_ipv4_and_ttl() {
        let mut d = DohEntry::new();
        let rc = doh_resp_decode(DNS_FOO_A_127_0_0_1, DnsType::A, &mut d);
        assert_eq!(rc, Ok(()));
        assert_eq!(d.numaddr(), 1);
        assert_eq!(d.addresses(), &[IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
        // TTL 0x37 == 55 from the single answer record.
        assert_eq!(d.ttl(), 55);
    }

    #[test]
    fn decode_aaaa_response_yields_ipv6() {
        let mut d = DohEntry::new();
        let rc = doh_resp_decode(DNS_AAAA_2020, DnsType::Aaaa, &mut d);
        assert_eq!(rc, Ok(()));
        assert_eq!(
            d.addresses(),
            &[IpAddr::V6(Ipv6Addr::new(
                0x2020, 0x2020, 0, 0, 0, 0, 0, 0x2020
            ))]
        );
    }

    #[test]
    fn decode_too_small_buffer() {
        let mut d = DohEntry::new();
        assert_eq!(
            doh_resp_decode(b"\x00\x00", DnsType::A, &mut d),
            Err(DohCode::TooSmallBuffer)
        );
    }

    #[test]
    fn decode_bad_id() {
        // id != 0 (second byte is 1).
        let pkt = b"\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01";
        let mut d = DohEntry::new();
        assert_eq!(
            doh_resp_decode(pkt, DnsType::A, &mut d),
            Err(DohCode::BadId)
        );
    }

    #[test]
    fn decode_bad_rcode() {
        // id == 0 but RCODE (low nibble of byte 3) == 1 → "no such name".
        let pkt = b"\x00\x00\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01";
        let mut d = DohEntry::new();
        assert_eq!(
            doh_resp_decode(pkt, DnsType::A, &mut d),
            Err(DohCode::BadRcode)
        );
    }

    #[test]
    fn decode_truncated_answer_is_out_of_range() {
        // Header claims QDCOUNT=1 but the question name runs off the end.
        let pkt = b"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\x03foo";
        let mut d = DohEntry::new();
        assert_eq!(
            doh_resp_decode(pkt, DnsType::A, &mut d),
            Err(DohCode::OutOfRange)
        );
    }

    #[test]
    fn decode_cname_only_is_ok_with_no_address() {
        // curl's CNAME vector: curl.curl CNAME anywhere.really (no A record).
        // Decode succeeds (numcname > 0 ⇒ not NoContent) but stores no address.
        let pkt: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\
\x04curl\x04curl\x00\x00\x05\x00\x01\
\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x37\x00\x11\
\x08anywhere\x06really\x00";
        let mut d = DohEntry::new();
        assert_eq!(doh_resp_decode(pkt, DnsType::A, &mut d), Ok(()));
        assert_eq!(d.numaddr(), 0);
        assert_eq!(d.cnames(), &["anywhere.really".to_string()]);
    }

    #[test]
    fn decode_compression_pointer_loop_is_label_loop() {
        // curl's loop vector: a CNAME RDATA whose pointer points back into
        // itself, which the 128-step guard must catch.
        let pkt: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\
\x04curl\x04curl\x00\x00\x05\x00\x01\
\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x37\x00\
\x07\x03any\xc0\x27\x00";
        let mut d = DohEntry::new();
        assert_eq!(
            doh_resp_decode(pkt, DnsType::A, &mut d),
            Err(DohCode::LabelLoop)
        );
    }

    #[test]
    fn decode_skips_authority_section() {
        // AAAA answer + one authority (NS) record; curl skips NS and returns OK.
        // (unit1650.c "packet with NSCOUNT == 1".)
        let pkt: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x01\x00\x00\
\x04aaaa\x07example\x03com\x00\x00\x1c\x00\x01\
\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x37\x00\x10\
\x20\x20\x20\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x20\
\x04test\x04host\x04name\x00\x00\x1c\x00\x01\x00\x00\x00\x01\x00\x04\x01\x01\x01\x01";
        let mut d = DohEntry::new();
        assert_eq!(doh_resp_decode(pkt, DnsType::Aaaa, &mut d), Ok(()));
        assert_eq!(
            d.addresses(),
            &[IpAddr::V6(Ipv6Addr::new(
                0x2020, 0x2020, 0, 0, 0, 0, 0, 0x2020
            ))]
        );
    }

    #[test]
    fn decode_unexpected_type_rejected() {
        // Answer TYPE is MX (15) — neither the queried A nor a CNAME/DNAME.
        let pkt: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\
\x03foo\x07example\x03com\x00\x00\x01\x00\x01\
\xc0\x0c\x00\x0f\x00\x01\x00\x00\x00\x37\x00\x04\x7f\x00\x00\x01";
        let mut d = DohEntry::new();
        assert_eq!(
            doh_resp_decode(pkt, DnsType::A, &mut d),
            Err(DohCode::UnexpectedType)
        );
    }

    #[test]
    fn decode_unexpected_class_rejected() {
        // Answer CLASS is 0x0003 (CHAOS), not IN.
        let pkt: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\
\x03foo\x07example\x03com\x00\x00\x01\x00\x01\
\xc0\x0c\x00\x01\x00\x03\x00\x00\x00\x37\x00\x04\x7f\x00\x00\x01";
        let mut d = DohEntry::new();
        assert_eq!(
            doh_resp_decode(pkt, DnsType::A, &mut d),
            Err(DohCode::UnexpectedClass)
        );
    }

    #[test]
    fn decode_a_wrong_rdlength_is_rdata_len() {
        // An A record with RDLENGTH 3 (not 4).
        let pkt: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\
\x03foo\x07example\x03com\x00\x00\x01\x00\x01\
\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x37\x00\x03\x7f\x00\x00";
        let mut d = DohEntry::new();
        assert_eq!(
            doh_resp_decode(pkt, DnsType::A, &mut d),
            Err(DohCode::RdataLen)
        );
    }

    #[test]
    fn decode_empty_answer_is_no_content() {
        // Valid header, one question, zero answers → nothing stored.
        let pkt: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
\x03foo\x07example\x03com\x00\x00\x01\x00\x01";
        let mut d = DohEntry::new();
        assert_eq!(
            doh_resp_decode(pkt, DnsType::A, &mut d),
            Err(DohCode::NoContent)
        );
    }

    // --- DohEntry aggregation and address conversion (← doh2ai) ------------

    #[test]
    fn entry_to_address_stamps_port_and_preserves_order() {
        let mut d = DohEntry::new();
        d.store_a([10, 0, 0, 1]);
        d.store_aaaa([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        d.observe_ttl(300);
        let address = d.to_address("example.com", 8443).unwrap();
        assert_eq!(
            address.endpoints(),
            &[
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8443),
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
                    8443
                ),
            ]
        );
    }

    #[test]
    fn entry_to_address_empty_is_couldnt_resolve_host() {
        let d = DohEntry::new();
        let err = d.to_address("nowhere.example", 443).unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntResolveHost);
        assert_eq!(err.code() as i32, 6);
    }

    #[test]
    fn entry_store_respects_address_cap() {
        let mut d = DohEntry::new();
        for i in 0..(DOH_MAX_ADDR + 5) {
            d.store_a([10, 0, 0, i as u8]);
        }
        assert_eq!(d.numaddr(), DOH_MAX_ADDR);
    }

    #[test]
    fn entry_merge_orders_ipv4_before_ipv6() {
        let mut a = DohEntry::new();
        a.store_a([1, 1, 1, 1]);
        a.observe_ttl(120);
        let mut aaaa = DohEntry::new();
        aaaa.store_aaaa([0x20, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        aaaa.observe_ttl(60);

        let mut merged = DohEntry::new();
        merged.merge_from(&a);
        merged.merge_from(&aaaa);

        assert_eq!(merged.numaddr(), 2);
        assert!(matches!(merged.addresses()[0], IpAddr::V4(_)));
        assert!(matches!(merged.addresses()[1], IpAddr::V6(_)));
        // Minimum TTL across both probes.
        assert_eq!(merged.ttl(), 60);
    }

    // --- DohCode message table (← doh_strerror errors[]) -------------------

    #[test]
    fn dohcode_values_and_messages_match_curl() {
        assert_eq!(DohCode::Ok as u8, 0);
        assert_eq!(DohCode::BadLabel as u8, 1);
        assert_eq!(DohCode::OutOfRange as u8, 2);
        assert_eq!(DohCode::LabelLoop as u8, 3);
        assert_eq!(DohCode::TooSmallBuffer as u8, 4);
        assert_eq!(DohCode::OutOfMem as u8, 5);
        assert_eq!(DohCode::RdataLen as u8, 6);
        assert_eq!(DohCode::Malformat as u8, 7);
        assert_eq!(DohCode::BadRcode as u8, 8);
        assert_eq!(DohCode::UnexpectedType as u8, 9);
        assert_eq!(DohCode::UnexpectedClass as u8, 10);
        assert_eq!(DohCode::NoContent as u8, 11);
        assert_eq!(DohCode::BadId as u8, 12);
        assert_eq!(DohCode::NameTooLong as u8, 13);
        assert_eq!(DohCode::BadRcode.to_string(), "Bad RCODE");
    }

    #[test]
    fn dnstype_wire_values() {
        assert_eq!(DnsType::A.as_u16(), 1);
        assert_eq!(DnsType::Cname.as_u16(), 5);
        assert_eq!(DnsType::Aaaa.as_u16(), 28);
        assert_eq!(DnsType::Dname.as_u16(), 39);
        assert_eq!(DnsType::Https.as_u16(), 65);
    }

    #[test]
    fn size_constants_match_doh_h() {
        assert_eq!(DOH_MAX_DNSREQ_SIZE, 272);
        assert_eq!(DOH_MAX_ADDR, 24);
        assert_eq!(DOH_MAX_CNAME, 4);
        assert_eq!(DOH_MAX_HTTPS, 4);
    }

    // --- Phase 5: DoH SSL options + URL validation -------------------------

    #[test]
    fn doh_ssl_options_default_verifies() {
        let o = DohSslOptions::default();
        assert!(o.verify_host);
        assert!(o.verify_peer);
        assert!(!o.verify_status);
    }

    #[test]
    fn resolver_parses_https_url_with_default_port() {
        let r = DohResolver::new("https://doh.example/dns-query").expect("valid https DoH URL");
        assert_eq!(r.host, "doh.example");
        assert_eq!(r.port, 443);
        assert!(r.tls.is_some(), "https must build a rustls config");
    }

    #[test]
    fn resolver_parses_explicit_port() {
        let r = DohResolver::new("https://doh.example:8443/q").unwrap();
        assert_eq!(r.port, 8443);
    }

    #[test]
    fn resolver_rejects_non_http_scheme() {
        let err = DohResolver::new("ftp://doh.example/q").unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntResolveHost);
    }

    #[test]
    fn resolver_allows_cleartext_http_in_debug_builds_only() {
        // Tests are compiled with debug_assertions, so cleartext http is
        // accepted here and no TLS config is built. In release this URL is
        // rejected (see `with_options`).
        let result = DohResolver::new("http://127.0.0.1:8053/dns-query");
        if cfg!(debug_assertions) {
            let r = result.expect("http allowed under debug_assertions");
            assert!(r.tls.is_none());
            assert_eq!(r.port, 8053);
        } else {
            assert!(result.is_err());
        }
    }

    // --- Phase 4: end-to-end transport over a local HTTP/1.1 server --------

    /// Reads (and discards) an HTTP request from `sock`, honoring
    /// `Content-Length`, so the client's write completes cleanly.
    async fn drain_http_request(sock: &mut TcpStream) {
        use tokio::io::AsyncReadExt;
        let mut acc: Vec<u8> = Vec::new();
        let mut buf = [0u8; 2048];
        loop {
            match sock.read(&mut buf).await {
                Ok(0) => return,
                Ok(n) => {
                    acc.extend_from_slice(&buf[..n]);
                    if let Some(hdr_end) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                        let clen = content_length(&acc[..hdr_end]);
                        let have = acc.len() - (hdr_end + 4);
                        let mut remaining = clen.saturating_sub(have);
                        while remaining > 0 {
                            match sock.read(&mut buf).await {
                                Ok(0) => return,
                                Ok(n) => remaining = remaining.saturating_sub(n),
                                Err(_) => return,
                            }
                        }
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }

    fn content_length(header: &[u8]) -> usize {
        let text = String::from_utf8_lossy(header).to_ascii_lowercase();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("content-length:") {
                if let Ok(n) = rest.trim().parse::<usize>() {
                    return n;
                }
            }
        }
        0
    }

    #[tokio::test]
    async fn resolve_over_local_http_server_returns_address() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        // A minimal DoH server: accept one connection, read the request, and
        // reply with the canned foo.example.com A 127.0.0.1 DNS message.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = DNS_FOO_A_127_0_0_1.to_vec();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            drain_http_request(&mut sock).await;
            let mut resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\
Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            resp.extend_from_slice(&body);
            sock.write_all(&resp).await.unwrap();
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        });

        // Cleartext http is permitted under debug_assertions (tests run there).
        let url = format!("http://127.0.0.1:{port}/dns-query");
        let resolver = DohResolver::new(&url).expect("build DoH resolver");

        // IPv4-only ⇒ only the A probe fires ⇒ exactly one server connection.
        let address = resolver
            .resolve("foo.example.com", 443, IpVersion::V4)
            .await
            .expect("DoH resolve should succeed");

        assert_eq!(
            address.endpoints(),
            &[SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                443
            )]
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn resolve_maps_server_error_to_couldnt_resolve_host() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        // A server that returns HTTP 500 ⇒ the probe fails ⇒ resolve fails.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            drain_http_request(&mut sock).await;
            let resp = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\
Connection: close\r\n\r\n";
            let _ = sock.write_all(resp).await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        });

        let url = format!("http://127.0.0.1:{port}/dns-query");
        let resolver = DohResolver::new(&url).unwrap();
        let err = resolver
            .resolve("foo.example.com", 443, IpVersion::V4)
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntResolveHost);
        let _ = server.await;
    }
}
