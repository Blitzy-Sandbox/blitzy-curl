// Memory-safety mandate (AAP §0.7.1): `src/tls/` is explicitly named as a module
// that must carry the forbid attribute ("The core crate can apply
// `#![forbid(unsafe_code)]` at the root of the protocol, TLS, and transfer
// modules"). This inner attribute makes the rule compiler-enforced for this
// module *and* every submodule (`config`, `session_cache`, `keylog`,
// `hostname`) — all of which are already `unsafe`-free. ALL raw-pointer work
// lives in `curl-rs-ffi`, never here.
#![forbid(unsafe_code)]
// During the parallel rewrite some of this module's public items (the async
// `connect` primitive, the `TlsConnection` accessors, the session-cache glue,
// the `ALPN_*` constants) are consumed by sibling modules — `crate::conn`
// (the TLS connection filter), `crate::proxy` (HTTPS proxy), `crate::dns::doh`,
// and `crate::protocols::http::h2` — that land in the same migration step. Allow
// dead code so a standalone build of the TLS layer does not trip the
// zero-warnings build gate, mirroring the sibling TLS modules (`config.rs`,
// `session_cache.rs`).
#![allow(dead_code)]

//! TLS layer — the single, safe `rustls` backend (module root).
//!
//! This module is the Rust replacement for curl's `lib/vtls/` backend
//! abstraction and, specifically, the backend-agnostic surface that
//! `lib/vtls/vtls.c` exposed: the `Curl_ssl_*` lifecycle, ALPN selection, and
//! establishing a TLS session over a connection. Where the C tree selected one
//! of six interchangeable C TLS backends at build time (`openssl.c`, `gtls.c`,
//! `mbedtls.c`, `wolfssl.c`, `schannel.c`, `apple.c`) behind the `Curl_ssl`
//! function-pointer vtable, the rewrite collapses them to a single, memory-safe
//! backend built on `rustls` / `tokio-rustls` (Agent Action Plan §0.1.1 /
//! §0.8.1). Certificate validation is on by default; there is no OpenSSL,
//! native-tls, or other C-TLS linkage anywhere (enforced by the workspace
//! `deny.toml`).
//!
//! `vtls.c` (plus `vtls_int.h` for the ALPN wire constants/specs and
//! `lib/vtls/rustls.c` for the negotiated-ALPN read and handshake-completion
//! logic) is consumed as a *behavioral oracle only* — its decisions are
//! re-expressed in safe, idiomatic Rust, never transliterated line by line.
//!
//! # What this module owns
//!
//! `mod.rs` is the typed replacement for curl's `Curl_ssl` vtable. It provides:
//!
//! * **Submodule wiring + re-exports.** The four TLS submodules ([`config`],
//!   [`session_cache`], [`keylog`], [`hostname`]) are declared here and reachable
//!   as `crate::tls::*`; the primary type [`TlsConfig`] and the most commonly
//!   used items are re-exported for a clean consumer surface.
//! * **ALPN selection** ([`alpn_protocols`]) — the `alpn_get_spec` decision tree
//!   from `vtls.c`, reproduced exactly.
//! * **The async TLS connect primitive** ([`connect`]) — the `Curl_ssl_*` connect
//!   lifecycle as one `async` call over [`tokio_rustls::TlsConnector`], returning
//!   a [`TlsConnection`] that carries the established stream, the negotiated
//!   ALPN protocol, and the peer certificate chain. curl's manual
//!   `cr_recv`/`cr_send`/`cr_flush_out` record pump collapses into the
//!   [`tokio::io::AsyncRead`]/[`tokio::io::AsyncWrite`] traits of the returned
//!   [`tokio_rustls::client::TlsStream`].
//! * **Capability reporting** ([`ssl_version_string`]) for `crate::version`.
//! * **Session-cache glue** ([`session_store`] / [`build_client_config`]) that
//!   converts a [`SessionCache`] into the `rustls` session store consumed by
//!   [`config::TlsConfig::build_client_config`].
//!
//! The connection-FILTER wrapping (the `cf-ssl` layer that plugs this primitive
//! into the filter chain) is owned by `crate::conn`; this module deliberately
//! provides only the reusable async connect + negotiated-ALPN + pinned-key
//! primitive that `conn/`, `proxy/`, and `dns/doh` wrap.
//!
//! # `Curl_ssl_*` lifecycle mapping
//!
//! | curl C lifecycle step        | Rust equivalent                                        |
//! |------------------------------|--------------------------------------------------------|
//! | `Curl_ssl_init` (provider)   | one-time crypto-provider install in [`config`] (`OnceLock`/`Once`), coordinated with global init |
//! | `Curl_ssl_connect`           | [`connect`] (this module)                              |
//! | `cr_recv` / `cr_send`        | [`tokio::io::AsyncRead`] / [`tokio::io::AsyncWrite`] on [`TlsConnection::stream`] |
//! | `Curl_ssl_shutdown`          | [`tokio::io::AsyncWriteExt::shutdown`] on the stream    |
//! | `Curl_ssl_close`             | `Drop` of the stream                                   |
//!
//! # Hard TLS rules (AAP §0.7.1, §0.8.1)
//!
//! * **`rustls` exclusively** (via `tokio-rustls`). No OpenSSL / GnuTLS /
//!   mbedTLS / wolfSSL / Schannel / Secure Transport / C-TLS anywhere.
//! * **Certificate validation is ON by default.** This module merely wires the
//!   [`rustls::ClientConfig`] built from a [`TlsConfig`] (whose defaults are
//!   verify-on) into the connector; disabling lives in [`config`] and the
//!   mandatory `--insecure` stderr warning lives in `curl-rs`.
//! * **Zero `unsafe`** — enforced by the `#![forbid(unsafe_code)]` above.

// =============================================================================
// Submodule declarations — reachable as `crate::tls::*`
// =============================================================================

pub mod config;
pub mod hostname;
pub mod keylog;
pub mod session_cache;

// =============================================================================
// Re-exports — a clean `crate::tls::*` consumer surface
// =============================================================================

// The primary type (folder requirement) plus the curl public TLS constants and
// the post-handshake pinned-public-key check, so consumers (`conn/`, `proxy/`,
// `setopt`) can reach them as `crate::tls::*` without a `config::` qualifier.
pub use config::{
    verify_pinned_pubkey, TlsConfig, CURLSSLOPT_ALLOW_BEAST, CURLSSLOPT_AUTO_CLIENT_CERT,
    CURLSSLOPT_EARLYDATA, CURLSSLOPT_NATIVE_CA, CURLSSLOPT_NO_PARTIALCHAIN, CURLSSLOPT_NO_REVOKE,
    CURLSSLOPT_REVOKE_BEST_EFFORT, CURL_SSLVERSION_DEFAULT, CURL_SSLVERSION_LAST,
    CURL_SSLVERSION_MAX_DEFAULT, CURL_SSLVERSION_MAX_NONE, CURL_SSLVERSION_MAX_TLSV1_0,
    CURL_SSLVERSION_MAX_TLSV1_1, CURL_SSLVERSION_MAX_TLSV1_2, CURL_SSLVERSION_MAX_TLSV1_3,
    CURL_SSLVERSION_SSLV2, CURL_SSLVERSION_SSLV3, CURL_SSLVERSION_TLSV1, CURL_SSLVERSION_TLSV1_0,
    CURL_SSLVERSION_TLSV1_1, CURL_SSLVERSION_TLSV1_2, CURL_SSLVERSION_TLSV1_3,
    MAX_PINNED_PUBKEY_SIZE,
};
// The TLS session-resumption cache (per-easy or shared via `crate::share`).
pub use session_cache::SessionCache;

// =============================================================================
// Imports
// =============================================================================

use std::sync::Arc;

use rustls::client::ClientSessionStore;
use rustls::pki_types::{CertificateDer, DnsName, ServerName};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::{CurlError, Result};

// =============================================================================
// ALPN wire-byte protocol identifiers (verified against lib/vtls/vtls_int.h)
// =============================================================================

/// ALPN identifier for HTTP/1.0 (`ALPN_HTTP_1_0` in `vtls_int.h`).
///
/// Offered alongside [`ALPN_HTTP_1_1`] when HTTP/1.0 is explicitly requested,
/// because some old HTTP/1.0 servers understand the `http/1.1` ALPN token but
/// not `http/1.0`.
pub const ALPN_HTTP_1_0: &[u8] = b"http/1.0";
/// ALPN identifier for HTTP/1.1 (`ALPN_HTTP_1_1` in `vtls_int.h`).
pub const ALPN_HTTP_1_1: &[u8] = b"http/1.1";
/// ALPN identifier for HTTP/2 over TLS (`ALPN_H2` in `vtls_int.h`).
pub const ALPN_H2: &[u8] = b"h2";
/// ALPN identifier for HTTP/3 over QUIC (`ALPN_H3` in `vtls_int.h`).
///
/// Kept here for completeness and as the canonical reference value, but **this
/// TCP-TLS module never offers `h3`**: HTTP/3 is negotiated at the QUIC /
/// `quinn` layer (`crate::protocols::http::h3` / the `vquic` equivalent), not in
/// a `tokio-rustls` TLS-over-TCP handshake. [`alpn_protocols`] therefore emits
/// only `h2` / `http/1.1` / `http/1.0`.
pub const ALPN_H3: &[u8] = b"h3";

// =============================================================================
// ALPN selection — curl's `alpn_get_spec` decision tree (lib/vtls/vtls.c)
// =============================================================================

/// Computes the ordered list of ALPN wire-byte protocol identifiers to offer in
/// the TLS ClientHello, reproducing curl's `alpn_get_spec` decision tree
/// (`lib/vtls/vtls.c`) decision-for-decision.
///
/// The returned `Vec<Vec<u8>>` is assigned (by [`config::TlsConfig::build_client_config`])
/// to [`rustls::ClientConfig::alpn_protocols`]; the **order is the client's
/// preference order**, and `rustls` offers the protocols in exactly that order.
///
/// # Parameter mapping (curl `http_majors` → booleans)
///
/// curl's C signature is
/// `alpn_get_spec(http_majors wanted, http_majors preferred, bool only_http_10, bool use_alpn)`,
/// where `wanted` / `preferred` are bitmasks over the `CURL_HTTP_V*` bits
/// (`CURL_HTTP_V1x = 1<<0`, `CURL_HTTP_V2x = 1<<1`, `CURL_HTTP_V3x = 1<<2` —
/// `lib/http.h`). This function takes the decoded booleans the engine's
/// HTTP-version request carries:
///
/// | curl expression                       | parameter      |
/// |---------------------------------------|----------------|
/// | `wanted & CURL_HTTP_V2x`              | `want_h2`      |
/// | `wanted & CURL_HTTP_V1x`              | `want_h1`      |
/// | `preferred == CURL_HTTP_V1x`          | `prefer_h1`    |
/// | the HTTP/1.0-only request flag        | `only_http_10` |
/// | `conn->bits.tls_enable_alpn`          | `use_alpn`     |
///
/// HTTP/3 (`CURL_HTTP_V3x`) plays no part here — it is negotiated at the QUIC
/// layer — so there is no `want_h3` parameter.
///
/// # The five specs (exactly curl's)
///
/// 1. `!use_alpn`                                → `[]`                       (ALPN disabled)
/// 2. `only_http_10 && want_h1`                  → `[http/1.0, http/1.1]`     (`ALPN_SPEC_H10_H11`)
/// 3. `want_h2 && want_h1 && prefer_h1`          → `[http/1.1, h2]`           (`ALPN_SPEC_H11_H2`)
/// 4. `want_h2 && want_h1 && !prefer_h1`         → `[h2, http/1.1]`           (`ALPN_SPEC_H2_H11`)
/// 5. `want_h2 && !want_h1`                       → `[h2]`                     (`ALPN_SPEC_H2`)
/// 6. otherwise                                   → `[http/1.1]`              (`ALPN_SPEC_H11`)
///
/// # Feature gating
///
/// This function is intentionally *not* `#[cfg]`-gated on the `http2` feature: it
/// operates purely on the booleans the caller supplies. A build without HTTP/2
/// support simply never passes `want_h2 = true` (the engine derives `want_h2`
/// from both the requested version *and* `cfg!(feature = "http2")`), so the
/// function stays pure, total, and unit-testable under `--no-default-features`.
#[must_use]
pub fn alpn_protocols(
    want_h2: bool,
    want_h1: bool,
    prefer_h1: bool,
    only_http_10: bool,
    use_alpn: bool,
) -> Vec<Vec<u8>> {
    // (1) ALPN disabled by the application → offer nothing.
    if !use_alpn {
        return Vec::new();
    }

    // (2) HTTP/1.0 explicitly requested: offer http/1.0 first, but also http/1.1
    // so a server that only understands the newer token can still be reached.
    if only_http_10 && want_h1 {
        return vec![ALPN_HTTP_1_0.to_vec(), ALPN_HTTP_1_1.to_vec()];
    }

    // (3,4,5) HTTP/2 is wanted.
    if want_h2 {
        if want_h1 {
            // Offer both; the first entry is the preferred protocol.
            return if prefer_h1 {
                vec![ALPN_HTTP_1_1.to_vec(), ALPN_H2.to_vec()]
            } else {
                vec![ALPN_H2.to_vec(), ALPN_HTTP_1_1.to_vec()]
            };
        }
        // HTTP/2 only.
        return vec![ALPN_H2.to_vec()];
    }

    // (6) Default: HTTP/1.1 only.
    vec![ALPN_HTTP_1_1.to_vec()]
}

// =============================================================================
// ServerName derivation (SNI) — curl's `get_peer_type` (lib/vtls/vtls.c)
// =============================================================================

/// Derives the `rustls` [`ServerName`] for the handshake, reproducing curl's
/// IP-vs-DNS decision in `get_peer_type` (`lib/vtls/vtls.c`).
///
/// * An **IP literal** — IPv4, IPv6, or the bracketed IPv6 form `[::1]` — becomes
///   [`ServerName::IpAddress`]. As in curl, no SNI is sent for IP literals (the
///   TLS SNI extension is only meaningful for DNS names), and `rustls` validates
///   the certificate against the IP address (matching an `iPAddress`
///   `subjectAltName`).
/// * Any **other host** becomes [`ServerName::DnsName`], which `rustls` sends as
///   the SNI value and matches against the certificate's DNS `subjectAltName`s.
///
/// The host is assumed to already be IDN→ACE-encoded upstream by `crate::idn`,
/// so this function performs no Unicode normalization.
///
/// Note that `rustls`'s own `ServerName::try_from(&str)` tries DNS parsing
/// *first* and only falls back to IP, which would mis-treat some inputs; this
/// function deliberately checks for an IP literal first to match curl's
/// `get_peer_type` ordering exactly.
///
/// # Errors
///
/// A host that is neither a valid IP literal nor a valid DNS name maps to
/// [`CurlError::SslConnectError`] (curl's `CURLE_SSL_CONNECT_ERROR`).
fn server_name(host: &str) -> Result<ServerName<'static>> {
    // Accept the bracketed IPv6 literal form (`[::1]`) by stripping a single
    // matching pair of brackets before attempting to parse an IP address.
    let ip_candidate = match (host.strip_prefix('['), host.strip_suffix(']')) {
        (Some(_), Some(_)) => &host[1..host.len() - 1],
        _ => host,
    };

    // IP literal → no SNI, validate against the address (curl `get_peer_type`).
    if let Ok(ip) = ip_candidate.parse::<std::net::IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }

    // Otherwise a DNS name → used as the SNI value. `DnsName::try_from(String)`
    // yields a `DnsName<'static>`, giving an owned `ServerName<'static>`.
    let dns = DnsName::try_from(host.to_owned()).map_err(|_| CurlError::SslConnectError)?;
    Ok(ServerName::DnsName(dns))
}

// =============================================================================
// SubjectPublicKeyInfo extraction — minimal, dependency-free ASN.1 DER walk
// =============================================================================
//
// rustls exposes no pre-handshake pinning hook and no SPKI accessor, so for the
// `CURLOPT_PINNEDPUBLICKEY` check we extract the DER-encoded SubjectPublicKeyInfo
// from the negotiated end-entity certificate ourselves. Rather than pull in a
// full X.509 parser, we walk just enough of the certificate's ASN.1 DER TLV
// structure to locate the `subjectPublicKeyInfo` element and return it verbatim
// (its tag + length + content). This is pure, bounds-checked, `unsafe`-free safe
// Rust.
//
// The extracted bytes are the *complete* `SubjectPublicKeyInfo` SEQUENCE, which
// is exactly what `config::verify_pinned_pubkey` expects: it SHA-256-hashes that
// DER for the `sha256//` pin form, and byte-compares it for the file-pin form
// (where the SPKI comes from `SubjectPublicKeyInfoDer::pem_slice_iter`, likewise
// a full SPKI SEQUENCE).
//
//   Certificate ::= SEQUENCE {
//       tbsCertificate       TBSCertificate,
//       signatureAlgorithm   AlgorithmIdentifier,
//       signatureValue       BIT STRING }
//   TBSCertificate ::= SEQUENCE {
//       version         [0] EXPLICIT Version DEFAULT v1,   -- context tag 0xA0
//       serialNumber         CertificateSerialNumber,
//       signature            AlgorithmIdentifier,
//       issuer               Name,
//       validity             Validity,
//       subject              Name,
//       subjectPublicKeyInfo SubjectPublicKeyInfo,          -- the target
//       ... }

/// DER tag for a constructed SEQUENCE.
const DER_TAG_SEQUENCE: u8 = 0x30;
/// DER tag for an `[0]` context-specific constructed element (the explicit
/// `version` field of `TBSCertificate`).
const DER_TAG_CONTEXT_0: u8 = 0xA0;

/// Reads a single DER TLV (tag–length–value) triplet starting at `pos`.
///
/// Returns `(tag, content_start, content_len, next_pos)` where `content_start`
/// is the offset of the value, `content_len` its length, and `next_pos` the
/// offset immediately after this element (i.e. the start of the following one).
/// Returns `None` on any malformed or out-of-bounds encoding, on the
/// indefinite-length form (`0x80`, invalid in DER), or on a length field wider
/// than 4 octets (far larger than any real certificate field).
fn read_tlv(data: &[u8], pos: usize) -> Option<(u8, usize, usize, usize)> {
    let tag = *data.get(pos)?;
    let len_byte = *data.get(pos + 1)?;

    let (content_start, content_len) = if len_byte < 0x80 {
        // Short form: the length is the byte itself.
        (pos + 2, usize::from(len_byte))
    } else {
        // Long form: the low 7 bits give the number of subsequent length octets.
        let num_len_octets = usize::from(len_byte & 0x7f);
        if num_len_octets == 0 || num_len_octets > 4 {
            // 0 → indefinite length (not valid in DER); >4 → unreasonable.
            return None;
        }
        let mut len: usize = 0;
        for i in 0..num_len_octets {
            let b = *data.get(pos + 2 + i)?;
            len = (len << 8) | usize::from(b);
        }
        (pos + 2 + num_len_octets, len)
    };

    let next_pos = content_start.checked_add(content_len)?;
    if next_pos > data.len() {
        return None;
    }
    Some((tag, content_start, content_len, next_pos))
}

/// Extracts the DER-encoded `SubjectPublicKeyInfo` from an X.509 certificate's
/// DER bytes, returning the complete SPKI element (tag + length + content).
///
/// Returns `None` if the certificate is not well-formed enough to locate the
/// SPKI (a malformed or truncated certificate), in which case the pinned-key
/// check treats it as a mismatch.
fn extract_spki_der(cert: &[u8]) -> Option<Vec<u8>> {
    // Certificate ::= SEQUENCE { ... }
    let (tag, cert_content_start, _cert_len, _cert_end) = read_tlv(cert, 0)?;
    if tag != DER_TAG_SEQUENCE {
        return None;
    }

    // First element of Certificate is tbsCertificate ::= SEQUENCE { ... }.
    let (tag, tbs_start, tbs_len, _tbs_after) = read_tlv(cert, cert_content_start)?;
    if tag != DER_TAG_SEQUENCE {
        return None;
    }
    let tbs_end = tbs_start.checked_add(tbs_len)?;
    if tbs_end > cert.len() {
        return None;
    }

    let mut pos = tbs_start;

    // Optional `[0] EXPLICIT version` — present iff the first tag is 0xA0.
    let (first_tag, _, _, after_first) = read_tlv(cert, pos)?;
    if first_tag == DER_TAG_CONTEXT_0 {
        pos = after_first;
    }

    // Skip the five fields that precede subjectPublicKeyInfo:
    //   serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        let (_, _, _, next) = read_tlv(cert, pos)?;
        if next > tbs_end {
            return None;
        }
        pos = next;
    }

    // The next element is subjectPublicKeyInfo (a SEQUENCE). Return it whole.
    let (tag, _, _, spki_end) = read_tlv(cert, pos)?;
    if tag != DER_TAG_SEQUENCE || spki_end > tbs_end {
        return None;
    }
    Some(cert[pos..spki_end].to_vec())
}

// =============================================================================
// The established TLS connection
// =============================================================================

/// A completed TLS session produced by [`connect`].
///
/// It bundles the three results a consumer needs after a successful handshake:
///
/// * [`stream`](Self::stream) — the encrypted byte stream. It implements
///   [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`], so curl's
///   `cr_recv`/`cr_send` become ordinary async reads/writes and
///   `Curl_ssl_shutdown` becomes [`tokio::io::AsyncWriteExt::shutdown`].
/// * [`alpn`](Self::alpn) — the protocol the peer selected via ALPN (e.g.
///   `b"h2"` or `b"http/1.1"`), or `None` if none was negotiated. This is what
///   `crate::conn` / `crate::protocols::http` consult to pick HTTP/1.1 vs HTTP/2
///   (the `Curl_alpn_set_negotiated` analog).
/// * [`peer_certificates`](Self::peer_certificates) — the peer certificate chain
///   in presentation order (leaf first), for diagnostics and `getinfo`
///   (`CURLINFO_CERTINFO`).
pub struct TlsConnection<IO> {
    /// The established TLS stream — read/write application data here.
    pub stream: TlsStream<IO>,
    /// The ALPN protocol the peer negotiated (e.g. `b"h2"`), if any.
    pub alpn: Option<Vec<u8>>,
    /// The peer certificate chain (leaf first), owned for `'static` use.
    pub peer_certificates: Vec<CertificateDer<'static>>,
}

impl<IO> TlsConnection<IO> {
    /// The negotiated ALPN protocol as a byte slice, if any.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// Whether the peer negotiated HTTP/2 (`h2`) over this TLS session.
    #[must_use]
    pub fn negotiated_h2(&self) -> bool {
        self.alpn.as_deref() == Some(ALPN_H2)
    }

    /// The peer certificate chain (leaf first).
    #[must_use]
    pub fn peer_certificates(&self) -> &[CertificateDer<'static>] {
        &self.peer_certificates
    }

    /// A shared reference to the underlying TLS stream.
    pub fn stream(&self) -> &TlsStream<IO> {
        &self.stream
    }

    /// A mutable reference to the underlying TLS stream (for reading/writing
    /// application data).
    pub fn stream_mut(&mut self) -> &mut TlsStream<IO> {
        &mut self.stream
    }

    /// Consumes the connection, yielding the owned TLS stream.
    #[must_use]
    pub fn into_stream(self) -> TlsStream<IO> {
        self.stream
    }
}

// =============================================================================
// connect — the async TLS connect primitive (curl's `Curl_ssl_connect`)
// =============================================================================

/// Establishes a TLS session over an already-connected byte stream, the async,
/// memory-safe replacement for curl's `Curl_ssl_connect` lifecycle.
///
/// This is the single primitive that the connection layer wraps: `crate::conn`
/// (the `cf-ssl` connection filter), `crate::proxy` (TLS to an HTTPS proxy after
/// the CONNECT tunnel), and `crate::dns::doh` (DoH over HTTPS) all call it with
/// the transport stream they have already established (a TCP socket, a proxy
/// tunnel, …).
///
/// # Parameters
///
/// * `config` — the [`rustls::ClientConfig`] built from a [`TlsConfig`] (use
///   [`build_client_config`] or [`config::TlsConfig::build_client_config`]). It
///   already carries the offered ALPN list, the verifier (validation on by
///   default), the session-resumption store, and the key-log hook.
/// * `host` — the server host (already IDN→ACE-encoded), used to derive the SNI
///   value / IP validation target via [`server_name`].
/// * `pinned_pubkey` — the optional `CURLOPT_PINNEDPUBLICKEY` value (a
///   `sha256//<base64>[;…]` list or a key-file path). When `Some`, the peer's
///   public key is checked **after** the handshake (rustls offers no
///   pre-handshake hook).
/// * `stream` — the connected transport to run TLS over.
///
/// # Returns
///
/// A [`TlsConnection`] carrying the established stream, the negotiated ALPN
/// protocol, and the peer certificate chain.
///
/// # Errors
///
/// * A handshake/verification failure maps via
///   [`config::map_rustls_error`] — certificate problems become
///   `CURLE_PEER_FAILED_VERIFICATION` (curl unifies `CURLE_SSL_CACERT` to the
///   same integer), and any other handshake/transport failure becomes
///   `CURLE_SSL_CONNECT_ERROR`.
/// * An un-parseable `host` maps to `CURLE_SSL_CONNECT_ERROR` (via
///   [`server_name`]).
/// * A pinned-public-key mismatch maps to `CURLE_SSL_PINNEDPUBKEYNOTMATCH`.
pub async fn connect<IO>(
    config: Arc<ClientConfig>,
    host: &str,
    pinned_pubkey: Option<&str>,
    stream: IO,
) -> Result<TlsConnection<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    // Build the connector over the shared client config and resolve the SNI /
    // IP target before touching the wire.
    let connector = TlsConnector::from(config);
    let sni = server_name(host)?;

    // Drive the TLS handshake to completion. `tokio-rustls` wraps any
    // `rustls::Error` (e.g. a certificate-verification failure surfaced by
    // `process_new_packets`) inside an `io::Error`; recover the inner
    // `rustls::Error` for a precise curl error code, falling back to
    // `CURLE_SSL_CONNECT_ERROR` for plain transport errors.
    let tls = connector.connect(sni, stream).await.map_err(|e| {
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
            .map(|rustls_err| config::map_rustls_error(rustls_err.clone()))
            .unwrap_or(CurlError::SslConnectError)
    })?;

    // Read the negotiated ALPN protocol (the `cr_set_negotiated_alpn` /
    // `Curl_alpn_set_negotiated` analog) and capture an owned copy of the peer
    // certificate chain. Both are read from the borrowed connection state before
    // `tls` is moved into the returned `TlsConnection`.
    let (alpn, peer_certificates) = {
        let (_io, conn) = tls.get_ref();
        let alpn = conn.alpn_protocol().map(<[u8]>::to_vec);
        let peer_certificates = conn
            .peer_certificates()
            .map(<[CertificateDer<'static>]>::to_vec)
            .unwrap_or_default();
        (alpn, peer_certificates)
    };

    // Post-handshake pinned-public-key check (`Curl_pin_peer_pubkey`). rustls
    // exposes no pre-handshake hook, so this necessarily runs after the
    // handshake succeeds: extract the leaf certificate's SubjectPublicKeyInfo
    // and delegate the comparison to `config::verify_pinned_pubkey`.
    if let Some(pin) = pinned_pubkey {
        let leaf = peer_certificates
            .first()
            .ok_or(CurlError::SslPinnedpubkeynotmatch)?;
        let spki = extract_spki_der(leaf.as_ref()).ok_or(CurlError::SslPinnedpubkeynotmatch)?;
        config::verify_pinned_pubkey(pin, &spki)?;
    }

    Ok(TlsConnection {
        stream: tls,
        alpn,
        peer_certificates,
    })
}

// =============================================================================
// Capability / version reporting (for crate::version)
// =============================================================================

/// The pinned `rustls` dependency version, kept in lockstep with the workspace
/// `Cargo.toml` pin (`rustls = "=0.23.36"`) and `crate::version`'s `SSL_VERSION`
/// constant.
///
/// `rustls` does not expose its own version string at runtime, so — as the AAP
/// permits — this is a documented constant. The single source of truth for the
/// pin is the workspace manifest; if it changes, update this constant (and
/// `crate::version`) to match. The manifest uses an **exact** requirement
/// (`=0.23.36`, AAP §0.6.1/§0.8.1/§0.8.3), so `Cargo.lock` resolves *exactly*
/// this version — never a newer patch on the `0.23.x` line — guaranteeing the
/// advertised contract version equals the compiled crate, exactly as curl
/// reports its configured TLS-backend version.
pub const RUSTLS_VERSION: &str = "0.23.36";

/// Returns the TLS-backend version string for `crate::version`'s `ssl_version`
/// field, e.g. `"rustls/0.23.36"` (curl's `Curl_ssl_version` output, where the
/// C backends report `"OpenSSL/3.0.0"`, `"GnuTLS/3.8.0"`, etc.).
///
/// Because `rustls` is the sole, always-present TLS backend in this rewrite, TLS
/// (the `SSL` capability) is ON in every build — including
/// `--no-default-features` — so `crate::version` unconditionally reports this
/// string and sets the `CURL_VERSION_SSL` bit.
#[must_use]
pub fn ssl_version_string() -> String {
    format!("rustls/{RUSTLS_VERSION}")
}

// =============================================================================
// TLS session-cache wiring (CURLOPT_SSL_SESSIONID_CACHE)
// =============================================================================

/// Converts an optional [`SessionCache`] into the `rustls` session store that
/// [`config::TlsConfig::build_client_config`] installs for TLS resumption.
///
/// The engine decides *where* the cache lives — a per-easy cache, or one shared
/// across handles via `crate::share` (`CURL_LOCK_DATA_SSL_SESSION`) — and this
/// helper keeps that choice transparent to the TLS layer: either way it yields
/// the same `Arc<dyn ClientSessionStore>` (via [`SessionCache::rustls_store`]),
/// or `None` when no cache is supplied (resumption then disabled).
#[must_use]
pub fn session_store(cache: Option<&SessionCache>) -> Option<Arc<dyn ClientSessionStore>> {
    cache.map(SessionCache::rustls_store)
}

/// Convenience wrapper over [`config::TlsConfig::build_client_config`] that wires
/// in the ALPN list and the optional session cache in one call — the form the
/// connection filter (`crate::conn`) uses.
///
/// Equivalent to `tls.build_client_config(alpn, session_store(cache))`. The
/// resulting [`rustls::ClientConfig`] is reference-counted so it can be shared by
/// many concurrent [`connect`] calls.
///
/// # Errors
///
/// Propagates every error from [`config::TlsConfig::build_client_config`]
/// (unsupported TLS version, empty cipher selection, unreadable CA/CRL bundle,
/// client cert/key problem).
pub fn build_client_config(
    tls: &TlsConfig,
    alpn: &[Vec<u8>],
    cache: Option<&SessionCache>,
) -> Result<Arc<ClientConfig>> {
    tls.build_client_config(alpn, session_store(cache))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- (a) ALPN wire constants ------------------------------------------

    #[test]
    fn alpn_constants_are_exact_wire_bytes() {
        assert_eq!(ALPN_HTTP_1_0, b"http/1.0");
        assert_eq!(ALPN_HTTP_1_1, b"http/1.1");
        assert_eq!(ALPN_H2, b"h2");
        assert_eq!(ALPN_H3, b"h3");
    }

    // ---- (b) alpn_protocols: every branch of curl's alpn_get_spec ----------

    #[test]
    fn alpn_disabled_offers_nothing() {
        // !use_alpn → empty, regardless of the other flags.
        assert!(alpn_protocols(true, true, false, false, false).is_empty());
        assert!(alpn_protocols(true, true, true, true, false).is_empty());
        assert!(alpn_protocols(false, false, false, false, false).is_empty());
    }

    #[test]
    fn alpn_http10_offers_both_10_and_11() {
        // only_http_10 && want_h1 → [http/1.0, http/1.1] (ALPN_SPEC_H10_H11).
        assert_eq!(
            alpn_protocols(false, true, false, true, true),
            vec![b"http/1.0".to_vec(), b"http/1.1".to_vec()]
        );
        // The HTTP/1.0 rule takes precedence even when h2 is also wanted.
        assert_eq!(
            alpn_protocols(true, true, false, true, true),
            vec![b"http/1.0".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn alpn_h2_and_h1_prefer_h1_orders_h11_first() {
        // want_h2 && want_h1 && prefer_h1 → [http/1.1, h2] (ALPN_SPEC_H11_H2).
        assert_eq!(
            alpn_protocols(true, true, true, false, true),
            vec![b"http/1.1".to_vec(), b"h2".to_vec()]
        );
    }

    #[test]
    fn alpn_h2_and_h1_default_orders_h2_first() {
        // want_h2 && want_h1 && !prefer_h1 → [h2, http/1.1] (ALPN_SPEC_H2_H11).
        assert_eq!(
            alpn_protocols(true, true, false, false, true),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn alpn_h2_only() {
        // want_h2 && !want_h1 → [h2] (ALPN_SPEC_H2). prefer_h1 is irrelevant.
        assert_eq!(
            alpn_protocols(true, false, false, false, true),
            vec![b"h2".to_vec()]
        );
        assert_eq!(
            alpn_protocols(true, false, true, false, true),
            vec![b"h2".to_vec()]
        );
    }

    #[test]
    fn alpn_h1_only_and_default() {
        // want_h1 only → [http/1.1] (ALPN_SPEC_H11).
        assert_eq!(
            alpn_protocols(false, true, false, false, true),
            vec![b"http/1.1".to_vec()]
        );
        // Neither explicitly wanted (but ALPN on) → still default to http/1.1.
        assert_eq!(
            alpn_protocols(false, false, false, false, true),
            vec![b"http/1.1".to_vec()]
        );
    }

    // ---- (c) server_name: DNS vs IP literal --------------------------------

    #[test]
    fn server_name_dns_host_is_dnsname() {
        let sn = server_name("example.com").expect("dns name");
        assert!(
            matches!(sn, ServerName::DnsName(_)),
            "expected DnsName, got {sn:?}"
        );
    }

    #[test]
    fn server_name_ipv4_literal_is_ipaddress() {
        let sn = server_name("127.0.0.1").expect("ipv4");
        assert!(
            matches!(sn, ServerName::IpAddress(_)),
            "expected IpAddress, got {sn:?}"
        );
    }

    #[test]
    fn server_name_ipv6_literal_is_ipaddress() {
        let sn = server_name("::1").expect("ipv6");
        assert!(
            matches!(sn, ServerName::IpAddress(_)),
            "expected IpAddress, got {sn:?}"
        );
    }

    #[test]
    fn server_name_bracketed_ipv6_literal_is_ipaddress() {
        let sn = server_name("[::1]").expect("bracketed ipv6");
        assert!(
            matches!(sn, ServerName::IpAddress(_)),
            "expected IpAddress, got {sn:?}"
        );
        // A full bracketed address parses too.
        let sn = server_name("[2001:db8::1]").expect("bracketed ipv6 full");
        assert!(matches!(sn, ServerName::IpAddress(_)));
    }

    #[test]
    fn server_name_invalid_host_errors() {
        // A space is neither a valid IP literal nor a valid DNS label.
        assert!(matches!(
            server_name("bad host"),
            Err(CurlError::SslConnectError)
        ));
    }

    // ---- (d) extract_spki_der ---------------------------------------------

    #[test]
    fn extract_spki_matches_independent_rcgen_spki() {
        use rcgen::PublicKeyData;
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed");
        let extracted = extract_spki_der(ck.cert.der().as_ref()).expect("spki extracted");
        // rcgen's own SubjectPublicKeyInfo DER is an independent oracle.
        let expected = ck.signing_key.subject_public_key_info();
        assert_eq!(
            extracted, expected,
            "extracted SPKI must equal rcgen's SPKI"
        );
    }

    #[test]
    fn extract_spki_rejects_malformed() {
        assert!(extract_spki_der(&[]).is_none(), "empty input");
        assert!(
            extract_spki_der(&[0x02, 0x01, 0x00]).is_none(),
            "not a SEQUENCE"
        );
        assert!(
            extract_spki_der(&[0x30, 0x01, 0x00]).is_none(),
            "truncated tbs"
        );
        // Long-form indefinite length is invalid DER.
        assert!(
            extract_spki_der(&[0x30, 0x80]).is_none(),
            "indefinite length"
        );
    }

    // ---- (e) ssl_version_string -------------------------------------------

    #[test]
    fn ssl_version_string_is_pinned_rustls() {
        assert_eq!(RUSTLS_VERSION, "0.23.36");
        assert_eq!(ssl_version_string(), "rustls/0.23.36");
    }

    // ---- (f) session-cache glue -------------------------------------------

    #[test]
    fn session_store_maps_presence() {
        assert!(session_store(None).is_none());
        let cache = SessionCache::new();
        assert!(session_store(Some(&cache)).is_some());
    }

    // =========================================================================
    // Integration tests — real TLS handshakes over an in-memory duplex pipe.
    // =========================================================================

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Builds a `rustls::ServerConfig` over the `aws_lc_rs` provider (matching
    /// `config.rs`'s client provider) presenting `certs`/`key_der` and offering
    /// `alpn`.
    fn make_server_config(
        certs: Vec<CertificateDer<'static>>,
        key_der: Vec<u8>,
        alpn: Vec<Vec<u8>>,
    ) -> rustls::ServerConfig {
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into());
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server single cert");
        cfg.alpn_protocols = alpn;
        cfg
    }

    /// Generates a self-signed `localhost` leaf and returns (cert DER, PKCS#8 key
    /// DER).
    fn self_signed_localhost() -> (CertificateDer<'static>, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed");
        (ck.cert.der().clone(), ck.signing_key.serialize_der())
    }

    /// Builds a CA and a `localhost` leaf signed by it, returning
    /// (CA cert PEM, leaf cert DER, leaf PKCS#8 key DER).
    fn ca_and_leaf() -> (String, CertificateDer<'static>, Vec<u8>) {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose,
        };

        // Certificate authority (self-signed, CA:TRUE).
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "curl-rs test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");
        let ca_pem = ca_cert.pem();
        let issuer = Issuer::new(ca_params, ca_key);

        // Server leaf signed by the CA, with a localhost SAN + serverAuth EKU.
        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf sign");

        (ca_pem, leaf_cert.der().clone(), leaf_key.serialize_der())
    }

    /// A `TlsConfig` with peer/host verification disabled — used by the
    /// self-signed-cert handshake tests. Built with struct-update syntax (rather
    /// than `Default::default()` + field reassignment) to satisfy clippy's
    /// `field_reassign_with_default`.
    fn insecure_config() -> TlsConfig {
        TlsConfig {
            verify_peer: false,
            verify_host: false,
            ..TlsConfig::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_completes_handshake_negotiates_alpn_and_roundtrips() {
        let (cert, key) = self_signed_localhost();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);

        // Server offers h2 + http/1.1 and echoes "hello" → "world".
        let srv = make_server_config(vec![cert], key, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv));
        let server = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_io).await.expect("server handshake");
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.expect("server read");
            tls.write_all(b"world").await.expect("server write");
            tls.flush().await.expect("server flush");
            buf
        });

        // Client: verification off (so a self-signed cert is accepted), offering
        // h2 + http/1.1.
        let tc = insecure_config();
        let alpn = alpn_protocols(true, true, false, false, true);
        let cfg = tc.build_client_config(&alpn, None).expect("client config");

        let mut conn = connect(cfg, "localhost", None, client_io)
            .await
            .expect("client connect");

        // h2 must be negotiated (both sides offered it first/most-preferred).
        assert_eq!(conn.alpn(), Some(&b"h2"[..]));
        assert!(conn.negotiated_h2());
        assert!(!conn.peer_certificates().is_empty(), "peer chain captured");

        // Application bytes round-trip over the established stream.
        conn.stream.write_all(b"hello").await.expect("client write");
        conn.stream.flush().await.expect("client flush");
        let mut resp = [0u8; 5];
        conn.stream
            .read_exact(&mut resp)
            .await
            .expect("client read");
        assert_eq!(&resp, b"world");

        let echoed = server.await.expect("join server");
        assert_eq!(&echoed, b"hello");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_with_trusted_ca_succeeds() {
        let (ca_pem, leaf_der, leaf_key) = ca_and_leaf();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);

        let srv = make_server_config(vec![leaf_der], leaf_key, vec![b"http/1.1".to_vec()]);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv));
        let server = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_io).await.expect("server handshake");
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.expect("server read");
            buf
        });

        // Client with verification ON (the default), trusting the CA via
        // CAINFO_BLOB.
        let tc = TlsConfig {
            ca_info_blob: Some(ca_pem.into_bytes()),
            ..TlsConfig::default()
        };
        let alpn = alpn_protocols(false, true, false, false, true);
        let cfg = tc.build_client_config(&alpn, None).expect("client config");

        let mut conn = connect(cfg, "localhost", None, client_io)
            .await
            .expect("trusted-CA handshake must succeed");
        assert_eq!(conn.alpn(), Some(&b"http/1.1"[..]));

        conn.stream.write_all(b"ping").await.expect("client write");
        conn.stream.flush().await.expect("client flush");
        let echoed = server.await.expect("join server");
        assert_eq!(&echoed, b"ping");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_rejects_untrusted_cert() {
        let (cert, key) = self_signed_localhost();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);

        let srv = make_server_config(vec![cert], key, vec![b"http/1.1".to_vec()]);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv));
        // The client will reject the cert and abort; the server accept may error.
        let server = tokio::spawn(async move {
            let _ = acceptor.accept(server_io).await;
        });

        // Default config: verification ON, only the bundled webpki roots trusted
        // (which do NOT include our self-signed cert).
        let tc = TlsConfig::default();
        let alpn = alpn_protocols(false, true, false, false, true);
        let cfg = tc.build_client_config(&alpn, None).expect("client config");

        let res = connect(cfg, "localhost", None, client_io).await;
        assert!(
            matches!(res.as_ref(), Err(CurlError::PeerFailedVerification)),
            "untrusted cert must fail verification, got {:?}",
            res.err()
        );
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_rejects_pinned_pubkey_mismatch() {
        let (cert, key) = self_signed_localhost();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);

        let srv = make_server_config(vec![cert], key, vec![b"http/1.1".to_vec()]);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv));
        let server = tokio::spawn(async move {
            // Handshake succeeds (verification is off on the client); the pin
            // check then fails post-handshake, so reads may hit EOF.
            if let Ok(mut tls) = acceptor.accept(server_io).await {
                let mut buf = [0u8; 1];
                let _ = tls.read(&mut buf).await;
            }
        });

        let tc = insecure_config();
        let alpn = alpn_protocols(false, true, false, false, true);
        let cfg = tc.build_client_config(&alpn, None).expect("client config");

        // A syntactically valid but deliberately wrong sha256 pin (32 zero bytes).
        let bogus = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let res = connect(cfg, "localhost", Some(bogus), client_io).await;
        assert!(
            matches!(res.as_ref(), Err(CurlError::SslPinnedpubkeynotmatch)),
            "wrong pin must be rejected, got {:?}",
            res.err()
        );
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_accepts_matching_pinned_pubkey() {
        use crate::util::base64::base64_encode;
        use crate::util::sha256::sha256it;
        use rcgen::PublicKeyData;

        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed");
        let cert = ck.cert.der().clone();
        let key = ck.signing_key.serialize_der();

        // Compute the expected pin INDEPENDENTLY from rcgen's SPKI (not via the
        // module's own extractor), so this exercises extract_spki_der end-to-end.
        let spki = ck.signing_key.subject_public_key_info();
        let digest = sha256it(&spki);
        let b64 = String::from_utf8(base64_encode(&digest).expect("base64")).expect("utf8");
        let pin = format!("sha256//{b64}");

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let srv = make_server_config(vec![cert], key, vec![b"http/1.1".to_vec()]);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv));
        let server = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_io).await.expect("server handshake");
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.expect("server read");
            buf
        });

        let tc = insecure_config();
        let alpn = alpn_protocols(false, true, false, false, true);
        let cfg = tc.build_client_config(&alpn, None).expect("client config");

        let mut conn = connect(cfg, "localhost", Some(&pin), client_io)
            .await
            .expect("matching pin must be accepted");

        conn.stream.write_all(b"pong").await.expect("client write");
        conn.stream.flush().await.expect("client flush");
        let echoed = server.await.expect("join server");
        assert_eq!(&echoed, b"pong");
    }
}
