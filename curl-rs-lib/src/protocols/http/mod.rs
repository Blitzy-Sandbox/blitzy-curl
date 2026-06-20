//! HTTP family module root — the `http`/`https` protocol handler and HTTP
//! version selection for the `curl-rs-lib` core.
//!
//! This module is the root of the HTTP subtree of the C→Rust rewrite of
//! curl 8.19.0-DEV. It is authored *last* in this folder because it ties the
//! sibling engine files together. Its three responsibilities are:
//!
//! 1. **Declare the child modules** of the HTTP family (`chunks`, `proxy`,
//!    `aws_sigv4`, `h1`, and — feature-gated — `h2`/`h3`).
//! 2. **Expose the single HTTP [`Protocol`] handler** ([`HttpProtocol`]) that
//!    serves both `http` and `https` (and backs the `ws`/`wss` Upgrade path via
//!    the parent registry). This mirrors the C implementation, where one
//!    `Curl_protocol_http` method vtable is shared by both `Curl_scheme_http`
//!    and `Curl_scheme_https` (`lib/http.c` L4983-L5040).
//! 3. **Select the wire HTTP version** (HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3) from
//!    the ALPN negotiated by the connection-filter chain and the
//!    `--http1.0`/`--http1.1`/`--http2`/`--http2-prior-knowledge`/`--http3`/
//!    `--http3-only` options (`CURLOPT_HTTP_VERSION`). See
//!    [`select_http_version`].
//!
//! # Behavioral oracle
//!
//! The scheme descriptors and the method-vtable wiring reproduce the
//! `Curl_scheme_http` / `Curl_scheme_https` / `Curl_protocol_http` region of
//! `lib/http.c`. The version-selection precedence reproduces curl's
//! `http_request_version` plus the connect/ALPN handling in `lib/http_proxy.c`
//! (the `http/1.0` / `http/1.1` / `h2` ALPN→version mapping).
//!
//! # Single handler serves `http` + `https` (+ `ws`/`wss`)
//!
//! Exactly one [`Protocol`] implementation ([`HttpProtocol`]) backs every HTTP
//! scheme; instances differ only by the [`Scheme`] descriptor they carry
//! ([`crate::protocols::SCHEME_HTTP`] vs [`crate::protocols::SCHEME_HTTPS`]),
//! and `scheme()` returns that descriptor. This matches the C design (a single
//! shared vtable) and keeps the parent scheme registry simple. The `ws`/`wss`
//! WebSocket schemes reuse the HTTP/1.1 `Upgrade` path implemented in
//! [`h1`], so they too route through this handler.
//!
//! # Feature ⇔ capability ⇔ test-selection coupling (AAP §0.7.3)
//!
//! The compiled set of HTTP engines must stay in lockstep with the capability
//! bits reported by [`crate::version`]:
//!
//! * the whole HTTP family is gated by the `http` Cargo feature (default **on**);
//!   the parent `protocols/mod.rs` declares `pub mod http;` under
//!   `#[cfg(feature = "http")]`;
//! * the [`h2`] engine is gated by `http2` (default **on**) and must match
//!   `crate::version`'s `HTTP2` capability bit;
//! * the [`h3`] engine is gated by `http3` (default **on**) and must match the
//!   `HTTP3` bit.
//!
//! This coupling is load-bearing for the test suite: `runtests` selects the
//! HTTP/2 and HTTP/3 test cases from `curl_version_info`, so if the engines and
//! the reported capabilities ever drift, the wrong subset of tests runs. The
//! [`version_from_alpn`] / [`select_http_version`] helpers therefore gate every
//! reference to the `h2`/`h3` engines behind the same `#[cfg(feature = …)]`,
//! and fall back exactly as a curl build *without* that capability would
//! (`http2` off → HTTP/1.1; `http3` off → an explicit `--http3`/`--http3-only`
//! is rejected with the `CURLE_NOT_BUILT_IN` error class).
//!
//! # `dns::doh` consumer relationship
//!
//! [`crate::dns::doh`] issues its DNS-over-HTTPS query as an HTTP `POST`
//! *through this HTTP engine* — i.e. there is a `dns::doh → protocols::http`
//! dependency, not the reverse. This module must therefore remain usable to
//! drive an internally-originated request. Conversely, **target-host name
//! resolution is owned by [`crate::conn`]/[`crate::dns`] and is never invoked
//! from here**, which is why this module deliberately does *not* import
//! `crate::dns`.
//!
//! # Memory safety
//!
//! `#![forbid(unsafe_code)]` is declared at the crate root (`lib.rs`) and
//! re-declared at `protocols/mod.rs`. Because this `http/mod.rs` is a *child*
//! of `protocols/mod.rs`, the prohibition is already in force here and is
//! intentionally **not** re-declared (re-declaring `forbid` at a non-root
//! module is rejected/redundant). There is no `unsafe` in this file.

// ---------------------------------------------------------------------------
// Phase A — child module declarations
// ---------------------------------------------------------------------------
//
// `pub` (not `pub(crate)`) is intentional: the sibling engines expose many
// building-block items that are consumed across the subtree and by future
// callers; narrowing visibility here would risk `dead_code` under
// `-D warnings`. The `h2`/`h3` engines are feature-gated so the crate compiles
// with HTTP/2 and/or HTTP/3 disabled (the analog of curl's `USE_*` gates).

/// HTTP chunked transfer-encoding parser/encoder (`lib/http_chunks.c`).
pub mod chunks;
/// HTTP proxy support — `CONNECT` tunneling and proxy request rewriting
/// (`lib/http_proxy.c`).
pub mod proxy;
/// AWS Signature Version 4 request signing (`lib/http_aws_sigv4.c`).
pub mod aws_sigv4;
/// HTTP/1.x engine: request serialization, status/header parsing, redirect
/// method rewriting, and the `Upgrade` path reused by `ws`/`wss`
/// (`lib/http.c`, `lib/http1.c`).
pub mod h1;
/// HTTP/2 engine over `h2`/`hyper` (`lib/http2.c`). Gated by `http2`.
#[cfg(feature = "http2")]
pub mod h2;
/// HTTP/3 engine over `quinn`+`h3` (`lib/vquic/*`). Gated by `http3`.
#[cfg(feature = "http3")]
pub mod h3;

// ---------------------------------------------------------------------------
// Imports — strictly limited to this file's declared dependencies.
// ---------------------------------------------------------------------------

use crate::conn::{BoxFuture, Connection, Curl_conn_get_alpn_negotiated};
use crate::easy::Easy;
use crate::error::Result;
// `CurlError` is used by the version selector (to reject an explicit
// `--http3`/`--http3-only` with `CURLE_NOT_BUILT_IN` when HTTP/3 is compiled
// out) and by the transfer driver [`perform_http`] (URL/scheme rejection,
// resolve/connect failures). It is therefore imported unconditionally.
use crate::error::CurlError;
use crate::protocols::{Protocol, ProtocolTransfer, Scheme, TransferDirection};
// ALPN wire-byte constants, compared against the negotiated protocol so this
// module and `crate::tls` never drift. `h3` is selected by transport (QUIC),
// not by TLS-ALPN, so `ALPN_H3` is intentionally not used here; `http/1.1`
// (`ALPN_HTTP_1_1`) is the universal default and is handled by the fall-through
// arm rather than an explicit comparison. [`alpn_protocols`] computes the
// ordered ALPN offer for an HTTPS connection in [`perform_http`].
use crate::tls::{alpn_protocols, ALPN_H2, ALPN_HTTP_1_0};

// ---------------------------------------------------------------------------
// Additional imports for the `perform_http` transfer driver (Phase E). These
// are the building blocks the seam composes: the connection-establishment
// entry point and its filter factories, the DNS resolver (+ `--resolve`
// overrides), the per-easy TLS config, the scheme descriptors, the option
// accessors, and the transfer-engine driver and its parts.
// ---------------------------------------------------------------------------
use crate::conn::connect::{eyeballs_factory, tls_factory, SetupConfig};
use crate::conn::{
    establish_connection, ConnSetup, SchemeDescriptor, CURL_CF_SSL_DISABLE, CURL_CF_SSL_ENABLE,
    FIRSTSOCKET, TRNSPRT_TCP,
};
use crate::dns::{self, load_host_pairs, DnsCache, IpVersion, ResolveParams, ResolvedAddrs};
use crate::progress::Progress;
use crate::protocols::pingpong::tls_config_from_easy;
use crate::protocols::{SCHEME_HTTP, SCHEME_HTTPS};
use crate::request::Request;
use crate::setopt::{HttpReq, OptionValue, StrId};
// `Request`/`Progress` are imported from their own modules above: `transfer.rs`
// pulls them in via a *private* `use`, so they are not re-exported there.
use crate::transfer::{
    drive_transfer, ClientWriter, ErrorBuffer, ProtocolExchange, ReadCallback, TransferLimits,
    TransferParts, WriteCallbacks, CURL_READFUNC_ABORT, CURL_READFUNC_PAUSE,
};
use crate::url::{CurlUPart, CurlUrl, CURLU_DEFAULT_PORT, CURLU_GUESS_SCHEME, CURLU_URLDECODE};
use crate::util::timeval::curlx_now;
// DoH transport seam: this module is the runtime collaborator that carries a
// DoH probe as an HTTP(S) `POST` (see `crate::dns::doh`). The transport is
// installed lazily at [`perform_http`] entry so `--doh-url` resolution can
// re-enter the engine via a short-lived internal easy handle.
use crate::dns::doh::{install_transport as install_doh_transport, DohProbeRequest, DohTransport};
use crate::options::CurlOption;
use crate::slist::SList;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// `CURLOPT_HTTP_VERSION` request values (`CURL_HTTP_VERSION_*`).
// ---------------------------------------------------------------------------
//
// These mirror the public enum carried on the easy handle as `Easy::set.httpwant`
// (a `u8`). Only the values that force a specific selection are named; the
// remaining values — `CURL_HTTP_VERSION_NONE` (0), `CURL_HTTP_VERSION_2_0` (3),
// and `CURL_HTTP_VERSION_2TLS` (4) — express *no cleartext preference* and are
// resolved from the negotiated ALPN (defaulting to HTTP/1.1), so they are
// handled by the catch-all arm of [`select_http_version`].

/// `CURL_HTTP_VERSION_1_0` — force HTTP/1.0.
const CURL_HTTP_VERSION_1_0: u8 = 1;
/// `CURL_HTTP_VERSION_1_1` — force HTTP/1.1.
const CURL_HTTP_VERSION_1_1: u8 = 2;
/// `CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE` — start HTTP/2 on a cleartext `http`
/// connection without ALPN negotiation.
const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: u8 = 5;
/// `CURL_HTTP_VERSION_3` — attempt HTTP/3, gracefully falling back otherwise.
const CURL_HTTP_VERSION_3: u8 = 30;
/// `CURL_HTTP_VERSION_3ONLY` — require HTTP/3 with no fallback.
const CURL_HTTP_VERSION_3ONLY: u8 = 31;

// ---------------------------------------------------------------------------
// Phase D — HTTP version selection
// ---------------------------------------------------------------------------

/// The wire HTTP version chosen for a transfer.
///
/// This is `pub` so that the unused-variant `dead_code` lint never fires when a
/// version is compiled out (`H2` without `http2`, `H3` without `http3`), and so
/// the selected version can be recorded as protocol state for the per-version
/// engines, which assume the selection was already made correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    /// HTTP/1.0.
    Http10,
    /// HTTP/1.1 (curl's universal default).
    Http11,
    /// HTTP/2.
    H2,
    /// HTTP/3 (over QUIC).
    H3,
}

/// Map a negotiated ALPN protocol id to the HTTP version it selects.
///
/// `Some(b"h2")` selects HTTP/2 (or HTTP/1.1 when the `http2` feature is
/// disabled — in which case a curl build without HTTP/2 would never have
/// offered `h2`, so the fallback is purely defensive). `Some(b"http/1.0")`
/// selects HTTP/1.0. `http/1.1` (`ALPN_HTTP_1_1`), any other/unknown token, and
/// the absence of ALPN all select HTTP/1.1 — curl's default. HTTP/3 is *not*
/// reachable from ALPN: it is chosen by transport in [`select_http_version`].
///
/// Kept as a free function over `Option<&[u8]>` so the full ALPN→version truth
/// table is unit-testable directly, without constructing a connection.
fn version_from_alpn(alpn: Option<&[u8]>) -> HttpVersion {
    match alpn {
        Some(a) if a == ALPN_H2 => {
            #[cfg(feature = "http2")]
            {
                HttpVersion::H2
            }
            #[cfg(not(feature = "http2"))]
            {
                HttpVersion::Http11
            }
        }
        Some(a) if a == ALPN_HTTP_1_0 => HttpVersion::Http10,
        _ => HttpVersion::Http11,
    }
}

/// Select the HTTP version for a transfer, reproducing curl's precedence:
/// an explicit `CURLOPT_HTTP_VERSION` wins, then the negotiated ALPN, then the
/// HTTP/1.1 default.
///
/// The precedence, value by value:
///
/// 1. `CURL_HTTP_VERSION_3` / `CURL_HTTP_VERSION_3ONLY` → HTTP/3, *if* the
///    `http3` feature is built; otherwise `CURLE_NOT_BUILT_IN`. (Note: the
///    option setter already rejects these values at `setopt` time when `http3`
///    is disabled, so the error arm is defensive — it can only be reached in a
///    misconfigured build.)
/// 2. `CURL_HTTP_VERSION_1_0` → HTTP/1.0; `CURL_HTTP_VERSION_1_1` → HTTP/1.1.
/// 3. `CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE` → HTTP/2 with no ALPN (cleartext
///    `http`), *if* `http2` is built; otherwise HTTP/1.1.
/// 4. Everything else (`NONE`, `2_0`, `2TLS`, or any future value) → the
///    ALPN-negotiated version, defaulting to HTTP/1.1.
///
/// Every reference to the `h2`/`h3` engines (and the `H2`/`H3` outcomes) stays
/// behind the matching `#[cfg(feature = …)]`, so the crate compiles with those
/// engines disabled and degrades exactly as the corresponding curl build would.
pub(crate) fn select_http_version(easy: &Easy, conn: &Connection) -> Result<HttpVersion> {
    match easy.set.httpwant {
        CURL_HTTP_VERSION_3 | CURL_HTTP_VERSION_3ONLY => {
            #[cfg(feature = "http3")]
            {
                Ok(HttpVersion::H3)
            }
            #[cfg(not(feature = "http3"))]
            {
                Err(CurlError::NotBuiltIn)
            }
        }
        CURL_HTTP_VERSION_1_0 => Ok(HttpVersion::Http10),
        CURL_HTTP_VERSION_1_1 => Ok(HttpVersion::Http11),
        CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE => {
            #[cfg(feature = "http2")]
            {
                Ok(HttpVersion::H2)
            }
            #[cfg(not(feature = "http2"))]
            {
                Ok(HttpVersion::Http11)
            }
        }
        // `NONE`, `2_0`, `2TLS`, and any unknown/future value defer to ALPN.
        _ => {
            let alpn = Curl_conn_get_alpn_negotiated(conn);
            Ok(version_from_alpn(alpn.as_deref().map(str::as_bytes)))
        }
    }
}

// ---------------------------------------------------------------------------
// Phase C — the single HTTP `Protocol` handler (ports `Curl_protocol_http`)
// ---------------------------------------------------------------------------

/// The HTTP protocol handler serving `http` and `https` (and, via the parent
/// registry's `ws`/`wss` Upgrade path, WebSockets).
///
/// One instance is created per scheme via [`HttpProtocol::new`]; the carried
/// [`Scheme`] descriptor is the *only* difference between the `http` and `https`
/// variants, exactly mirroring how the C code shares the single
/// `Curl_protocol_http` vtable between `Curl_scheme_http` and
/// `Curl_scheme_https`.
pub struct HttpProtocol {
    /// The scheme descriptor this instance represents
    /// ([`crate::protocols::SCHEME_HTTP`] or [`crate::protocols::SCHEME_HTTPS`]).
    scheme: &'static Scheme,
}

impl HttpProtocol {
    /// Construct the handler for a specific HTTP scheme descriptor.
    ///
    /// The parent scheme registry passes [`crate::protocols::SCHEME_HTTP`] or
    /// [`crate::protocols::SCHEME_HTTPS`]; the `ws`/`wss` schemes pass their own
    /// descriptors while reusing this handler's HTTP/1.1 Upgrade path.
    #[must_use]
    pub fn new(scheme: &'static Scheme) -> Self {
        Self { scheme }
    }
}

// Method-vtable correspondence to C's `Curl_protocol_http` (`lib/http.c`
// L4983-L5040):
//
//   C slot            → Rust trait method
//   ----------------    -----------------------------------------------------
//   setup_connection  → `setup_connection` (trait default `Ok(())`; the C
//                        `Curl_http_setup_conn` only inspects HTTP/3 wanted-state,
//                        which is handled at version selection, so the no-op
//                        default is faithful for the TCP path).
//   do_it             → `do_it` (version dispatch below).
//   done              → `done` (clears the per-transfer protocol state).
//   write_resp        → `write_resp` (trait default; response-body writing is
//                        owned by the per-version engine driving the exchange).
//   write_resp_hd     → `write_resp_hd` (trait default; as above for headers).
//   follow            → `follow` (trait default; redirect method-rewrite and URL
//                        resolution are realized by `h1`'s helpers driven by the
//                        transfer engine, which alone has the response status
//                        code and the parsed base URL needed by `Curl_http_follow`).
//   connect_it / do_more / connecting / doing / disconnect /
//   connection_check / attach → `ZERO_NULL` in C ⇒ trait defaults here.
//
// All `*_pollset` C members are intentionally omitted from the Rust trait:
// Tokio's readiness model replaces curl's hand-rolled poll sets.
impl Protocol for HttpProtocol {
    fn scheme(&self) -> &'static Scheme {
        self.scheme
    }

    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            // Choose the wire version first; the per-version engines assume the
            // selection has already been made correctly.
            let version = select_http_version(data, conn)?;

            // HTTP/3 runs over a QUIC transport rather than the established TCP
            // connection, so delegate wholesale to the dedicated engine, which
            // owns request construction, transport switching, and its own
            // protocol state. Guarded so the crate links without the `h3` engine.
            #[cfg(feature = "http3")]
            {
                if version == HttpVersion::H3 {
                    let h3_handler = h3::Http3Protocol::new();
                    return h3_handler.do_it(data, conn).await;
                }
            }

            // HTTP/1.x and HTTP/2 share the established (TCP) connection. Derive
            // the transfer direction from the configured request shape, exactly
            // as curl does: a request body (POST fields) means an upload;
            // `--head`/`CURLOPT_NOBODY` means no body; otherwise a download.
            let is_upload =
                data.set.copypostfields.is_some() || data.set.postfields.is_some();
            let no_body = data.set.opt_no_body;
            let direction = if is_upload {
                TransferDirection::Upload
            } else if no_body {
                TransferDirection::None
            } else {
                TransferDirection::Download
            };

            let mut transfer = ProtocolTransfer::new(direction).with_response_headers(true);
            if is_upload {
                if let Some(body) = data.set.copypostfields.as_ref() {
                    transfer = transfer.with_size(body.len() as u64);
                }
            }

            // Record the selected version as per-connection protocol state for
            // the engine that will drive the byte exchange; `done` clears it.
            conn.set_proto_state(Box::new(version));
            Ok(transfer)
        })
    }

    fn done<'a>(
        &'a self,
        _data: &'a mut Easy,
        conn: &'a mut Connection,
        _status: Result<()>,
        _premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Release any protocol state recorded during `do_it`
            // (ports the teardown half of `Curl_http_done`).
            let _ = conn.take_proto_state();
            Ok(())
        })
    }
}

// ===========================================================================
// Phase E — the network transfer driver (`perform_http`)
//
// The integration seam that drives a recognized `http`/`https` transfer end to
// end — the missing top-level wiring identified by QA findings F-CRIT-1 (h1),
// F-CRIT-2 (h2), F-CRIT-3 (h3), F-CRIT-4 (wire parity), and F-FFI-1 (libcurl
// drop-in), all of which share the single root cause that `perform_transfer`
// rejected every network scheme before opening a socket.
//
// This is the Rust analog of curl's `Curl_connect` -> `Curl_do` ->
// `Curl_sendrecv` for HTTP: parse the URL, resolve the host (honoring
// `--resolve`/`--connect-to`), establish the connection-filter chain (plain TCP,
// or TCP + TLS with an ALPN offer), select the wire version (HTTP/1.x, HTTP/2
// via ALPN or prior-knowledge, or HTTP/3 over QUIC), build the request via the
// shared `h1` helpers (so the wire bytes are byte-for-byte identical across
// versions), and drive the response through `transfer::drive_transfer`.
//
// The request body is fully buffered into the prepared exchange *before*
// driving, because `drive_transfer` only reads the response (it never calls
// `send_body`): the h1/h2 engines send their carried body lazily on the first
// poll, and the h3 path pushes the body explicitly before reading.
// ===========================================================================

/// Drive an `http`/`https` transfer to completion.
///
/// Dispatches on the requested HTTP version: `--http3`/`--http3-only` connect
/// over QUIC (HTTP/3); every other request connects over TCP and then selects
/// HTTP/1.0, HTTP/1.1, or HTTP/2 from the forced option or the negotiated ALPN.
///
/// # Errors
///
/// * [`CurlError::UrlMalformat`] — the URL is missing, unparseable, or has no
///   host.
/// * [`CurlError::UnsupportedProtocol`] — a non-HTTP(S) scheme reaches here, or
///   `--http3` is requested for a cleartext URL.
/// * [`CurlError::NotBuiltIn`] — an HTTP version whose feature is compiled out.
/// * [`CurlError::CouldntResolveHost`] / [`CurlError::CouldntConnect`] and any
///   TLS, protocol, or transfer error propagated from the layers below.
pub(crate) async fn perform_http(
    data: &mut Easy,
    sink: &mut dyn WriteCallbacks,
    source: &mut dyn ReadCallback,
) -> Result<()> {
    let verbose = data.set.verbose;

    // (0) Ensure the DoH transport is available before any name resolution.
    //     `--doh-url` resolution (reached below via `resolve_addrs` →
    //     `dns::resolve` → `doh::resolve`) needs a process-wide
    //     `DohTransport`; install ours (idempotent) so the probe `POST` is
    //     carried by this very engine.
    install_doh_transport_once();

    // (1) Resolve the request URL: prefer a pre-parsed `CURLOPT_CURLU` handle
    //     (already deposited by the FFI layer), else parse the stored URL
    //     string. `CURLU_GUESS_SCHEME` mirrors curl's scheme guessing and
    //     `CURLU_DEFAULT_PORT` lets the port query fall back to the default.
    let url = if let Some(uh) = data.set.uh.clone() {
        uh
    } else {
        let url_str = data.url().ok_or(CurlError::UrlMalformat)?.to_string();
        let mut parsed = CurlUrl::new();
        parsed
            .set(
                CurlUPart::Url,
                Some(&url_str),
                CURLU_GUESS_SCHEME | CURLU_DEFAULT_PORT,
            )
            .map_err(|_| CurlError::UrlMalformat)?;
        parsed
    };

    let scheme = url
        .get(CurlUPart::Scheme, 0)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let is_https = scheme.eq_ignore_ascii_case("https");

    // The request host (for the `Host:` header, SNI, and default ALPN). Kept
    // with IPv6 brackets for the header builder, stripped for DNS/SNI/identity.
    let host_bracketed = url.get(CurlUPart::Host, CURLU_URLDECODE).unwrap_or_default();
    if host_bracketed.is_empty() {
        return Err(CurlError::UrlMalformat);
    }
    let host = strip_brackets(&host_bracketed).to_string();
    let default_port = if is_https {
        SCHEME_HTTPS.default_port
    } else {
        SCHEME_HTTP.default_port
    };
    let port = url
        .get(CurlUPart::Port, 0)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(default_port);

    let ipver = IpVersion::from_raw(i64::from(data.set.ipver));
    let httpwant = data.set.httpwant;

    // (2) HTTP/3 connects over QUIC (UDP), not TCP, so it branches before the
    //     TCP connect. `CURL_HTTP_VERSION_3` (30) and `_3ONLY` (31) request it.
    #[cfg(feature = "http3")]
    if matches!(httpwant, CURL_HTTP_VERSION_3 | CURL_HTTP_VERSION_3ONLY) {
        return perform_http3(data, &url, &host, port, ipver, sink, source, verbose).await;
    }
    #[cfg(not(feature = "http3"))]
    if matches!(httpwant, CURL_HTTP_VERSION_3 | CURL_HTTP_VERSION_3ONLY) {
        // Parity with `select_http_version` when HTTP/3 is compiled out.
        return Err(CurlError::NotBuiltIn);
    }

    // (3) Resolve the connect target (honoring `--connect-to`), then its
    //     addresses (honoring `--resolve`, else the system resolver).
    let (connect_host, connect_port) = connect_target(data, &host, port);
    let addrs = resolve_addrs(data, &connect_host, connect_port, ipver, verbose).await?;

    // (4) Build the connection and its filter chain. HTTPS installs a TLS filter
    //     carrying the ALPN offer; cleartext HTTP is a plain TCP chain.
    let desc = http_scheme_descriptor(is_https);
    let mut conn = Connection::new(
        format!("{connect_host}:{connect_port}"),
        TRNSPRT_TCP,
        desc,
    )
    .with_verbose(verbose);
    conn.set_remote(connect_host, connect_port);

    let ssl_mode = if is_https {
        CURL_CF_SSL_ENABLE
    } else {
        CURL_CF_SSL_DISABLE
    };
    let eyeballs = eyeballs_factory(TRNSPRT_TCP, ipver, data.set.happy_eyeballs_timeout, addrs);
    let dispatch = if is_https {
        // ALPN offer: h2 (unless a 1.x version is forced or HTTP/2 is compiled
        // out) plus http/1.1, so the server's ALPN pick selects the version.
        // `--http1.0`/`--http1.1` force HTTP/1.x; the default and `--http2`
        // defer the choice to ALPN.
        let want_h2 = cfg!(feature = "http2")
            && !matches!(httpwant, CURL_HTTP_VERSION_1_0 | CURL_HTTP_VERSION_1_1);
        let only_http_10 = httpwant == CURL_HTTP_VERSION_1_0;
        let alpn = alpn_protocols(want_h2, true, false, only_http_10, data.set.ssl_enable_alpn);
        let tls = tls_config_from_easy(data);
        let ssl = tls_factory(tls, host.clone(), port, None, alpn);
        ConnSetup::Default(SetupConfig::new(ssl_mode, true, eyeballs).with_ssl(ssl))
    } else {
        ConnSetup::Default(SetupConfig::new(ssl_mode, false, eyeballs))
    };
    establish_connection(&mut conn, FIRSTSOCKET, ssl_mode, dispatch, true).await?;

    // (5) Buffer the request body (upload/POST) before building the request, so
    //     the prepared exchange carries it (the transfer driver only reads the
    //     response). A plain GET/HEAD has no body and never touches `source`.
    let body = build_request_body(data, source)?;

    // (6) Select the wire version (forced option, else negotiated ALPN) and
    //     build + drive the matching exchange.
    let version = select_http_version(data, &conn)?;
    match version {
        HttpVersion::Http10 | HttpVersion::Http11 => {
            let http_minor = if version == HttpVersion::Http10 { 0 } else { 1 };
            let custom_headers = collect_custom_headers(data);
            let plan = {
                let inputs = make_inputs(
                    data,
                    &url,
                    &conn,
                    &custom_headers,
                    &host,
                    port,
                    is_https,
                    false,
                    body,
                    http_minor,
                );
                h1::build_request(&inputs)?
            };
            let mut exchange = h1::H1Exchange::new(
                h1::ConnByteStream::new(&mut conn),
                plan,
                data.set.http09_allowed,
                false,
            );
            let result = drive_one(data, &mut exchange, sink).await;
            // Record curl's keep-alive decision for the (future) connection pool;
            // for a single `perform` the connection is dropped right after.
            let keepalive = exchange.keepalive();
            drop(exchange);
            h1::apply_connection_reuse(&mut conn, keepalive);
            result
        }
        HttpVersion::H2 => {
            #[cfg(feature = "http2")]
            {
                let custom_headers = collect_custom_headers(data);
                // Reuse the shared h1 request builder, then map the serialized
                // head to HTTP/2 pseudo-headers (`build_h2_request`), so the
                // request is identical to the h1 path bar the framing.
                let (req, h2_body, no_body) = {
                    let inputs = make_inputs(
                        data,
                        &url,
                        &conn,
                        &custom_headers,
                        &host,
                        port,
                        is_https,
                        false,
                        body,
                        1,
                    );
                    self::h2::build_h2_request(&inputs)?
                };
                // Move the connected (post-TLS) filter chain into an h2-owned IO
                // adapter; the `'static` chain travels with the head.
                let filter = conn.cfilter[FIRSTSOCKET]
                    .take_head()
                    .ok_or(CurlError::FailedInit)?;
                let io = self::h2::ConnFilterIo::new(filter);
                let mut h2conn =
                    self::h2::h2_client_handshake(io, self::h2::H2Settings::default()).await?;
                let mut exchange = h2conn.start_exchange(req, h2_body, no_body).await?;
                let result = drive_one(data, &mut exchange, sink).await;
                h2conn.close();
                result
            }
            #[cfg(not(feature = "http2"))]
            {
                // The version selector never yields H2 without the feature, but
                // keep the arm total with curl's compiled-out parity code.
                let _ = body;
                Err(CurlError::NotBuiltIn)
            }
        }
        // HTTP/3 is selected before the TCP connect (it rides QUIC); neither the
        // ALPN path nor the forced-version path can yield it here. Defensive
        // parity error instead of a panic.
        HttpVersion::H3 => {
            let _ = body;
            Err(CurlError::UnsupportedProtocol)
        }
    }
}

/// Drive an HTTP/3 transfer over QUIC end to end (`quinn` + `h3`).
///
/// HTTP/3 is HTTPS-only; the request is built with the same shared `h1` helpers
/// the TCP path uses (authority, request target, method) so the request head
/// matches HTTP/1.1 and HTTP/2. The request body (if any) is pushed on the QUIC
/// send stream before the response is read, since [`drive_transfer`] only reads.
///
/// # Errors
///
/// [`CurlError::UnsupportedProtocol`] for a non-HTTPS URL, plus any resolve,
/// QUIC-connect, TLS, or transfer error from the layers below.
#[cfg(feature = "http3")]
#[allow(clippy::too_many_arguments)]
async fn perform_http3(
    data: &mut Easy,
    url: &CurlUrl,
    host: &str,
    port: u16,
    ipver: IpVersion,
    sink: &mut dyn WriteCallbacks,
    source: &mut dyn ReadCallback,
    verbose: bool,
) -> Result<()> {
    use crate::protocols::http::h3::{build_h3_request, h3_alpn, Http3Session};

    // HTTP/3 is https-only (curl rejects `--http3` on a cleartext URL).
    let scheme = url.get(CurlUPart::Scheme, 0).unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(CurlError::UnsupportedProtocol);
    }

    // Resolve the UDP endpoint (honoring `--connect-to`/`--resolve`).
    let (connect_host, connect_port) = connect_target(data, host, port);
    let addrs = resolve_addrs(data, &connect_host, connect_port, ipver, verbose).await?;
    let addr = addrs
        .addrs
        .first()
        .copied()
        .ok_or(CurlError::CouldntResolveHost)?;

    // Buffer the request body (POST/upload) up front so the shared request
    // builder can frame it (Content-Length / Transfer-Encoding) and the QUIC
    // send stream can push it before the response is read.
    let body = build_request_body(data, source)?;

    // Build the request via the SAME shared h1 builder the TCP h1/h2 paths use,
    // then translate its serialized head to HTTP/3. This delivers full wire
    // parity (G6) with h1/h2: the correct method (a `-d` POST stays POST —
    // `make_inputs` sets `is_upload = method == Put`, so it is never coerced to
    // PUT), `Host` → `:authority`, `User-Agent`, `Accept`, `Content-Length`,
    // the default `Content-Type` for a plain POST, and every custom `-H` header.
    let is_upload = data.set.method == HttpReq::Put;
    let authority = h1::build_host_header_value(host, port, true);
    // A throwaway direct connection only to compute the origin-form target
    // (HTTP/3 has no forward-proxy absolute-form here).
    let path = {
        let conn = Connection::new("h3", crate::conn::TRNSPRT_QUIC, http_scheme_descriptor(true));
        h1::request_target(url, &conn, None, false, false)?
    };
    let resolved = h1::resolve_http_method(
        data.set.method,
        data.set.opt_no_body,
        data.set.str(StrId::Customrequest),
        false,
        is_upload,
    )?;

    // Derive the full request header set from the shared builder's serialized
    // head (`make_inputs` + `build_request`), exactly as the h2 path does via
    // `build_h2_request`. `build_h3_request` drops the hop-by-hop fields itself
    // (incl. `Host`, which becomes `:authority`), so the complete list is passed
    // through unchanged.
    let custom_headers = collect_custom_headers(data);
    let (request_headers, h3_body) = {
        let conn = Connection::new("h3", crate::conn::TRNSPRT_QUIC, http_scheme_descriptor(true));
        let inputs =
            make_inputs(data, url, &conn, &custom_headers, host, port, true, false, body, 1);
        let plan = h1::build_request(&inputs)?;
        // `plan.head` is "REQUEST-LINE\r\n(name: value\r\n)*\r\n"; skip the
        // request line, then collect each header until the blank separator
        // (`parse_header_line` trims the trailing CRLF and yields `None` for the
        // blank line that ends the head).
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut lines = plan.head.split(|&b| b == b'\n');
        let _request_line = lines.next();
        for line in lines {
            match h1::parse_header_line(line) {
                Some((name, value)) => headers.push((
                    String::from_utf8_lossy(name).into_owned(),
                    String::from_utf8_lossy(value).into_owned(),
                )),
                None => break,
            }
        }
        (headers, plan.body)
    };
    let req = build_h3_request(&resolved.method, "https", &authority, &path, &request_headers)?;

    // Owned `rustls::ClientConfig` (the QUIC connector consumes it by value),
    // carrying the h3 ALPN and honoring `-k` via `tls_config_from_easy`.
    let tls_arc = tls_config_from_easy(data).build_client_config(&h3_alpn(), None)?;
    let tls = std::sync::Arc::try_unwrap(tls_arc).unwrap_or_else(|arc| (*arc).clone());

    // Connect, send the request, push any body, then drive the response.
    let session = Http3Session::connect(addr, host, tls).await?;
    let mut exchange = session.send_request(req).await?;

    // Push the request body (POST or PUT) on the QUIC send stream. Decoupled
    // from `is_upload` so a `-d` POST body (no longer an "upload") is still sent.
    let bytes = match h3_body {
        h1::RequestBody::Sized(b) | h1::RequestBody::Chunked(b) => b,
        h1::RequestBody::None => Vec::new(),
    };
    let mut offset = 0;
    while offset < bytes.len() {
        let sent = exchange.send_body(&bytes[offset..]).await?;
        if sent == 0 {
            break;
        }
        offset += sent;
    }

    let result = drive_one(data, &mut exchange, sink).await;
    session.close();
    result
}

/// Drive a WebSocket (`ws`/`wss`) transfer end to end.
///
/// The WebSocket opening handshake is an ordinary HTTP/1.1 `GET` with the
/// `Upgrade: websocket` / `Sec-WebSocket-*` headers (curl's `Curl_protocol_ws.do_it
/// == Curl_http`), so this reuses the HTTP/1.1 connect + request machinery
/// wholesale, differing only in three ways:
///
/// * the WebSocket Upgrade request headers are injected first
///   ([`ws_inject_request_headers`](crate::protocols::ws::ws_inject_request_headers),
///   curl's `Curl_ws_request`);
/// * the request is built with `is_websocket = true`, forcing the `GET` verb;
/// * the `101 Switching Protocols` response is a header-only message, so after
///   the head is delivered the [`WsConnState`](crate::protocols::ws::WsConnState)
///   RFC 6455 framing engine is installed on the connection (curl's
///   `Curl_ws_accept`).
///
/// Two completion modes mirror curl exactly:
///
/// * **`CURLOPT_CONNECT_ONLY`** (the typical `curl_ws_*` API usage): the live
///   connection and framing engine are handed to the easy handle
///   ([`Easy::attach_ws_connection`]) and the function returns — the application
///   then drives frames with `curl_ws_send`/`curl_ws_recv`.
/// * **plain `curl ws://…`**: the transfer's download continues by reading
///   frames and writing their payloads to the write callback until the server
///   closes the connection, exactly as curl's transfer loop does.
///
/// HTTPS/`wss` rides implicit TLS; the upgrade is always HTTP/1.1 (no ALPN h2),
/// matching curl's WebSocket connection setup which pins HTTP/1.1.
///
/// # Errors
///
/// [`CurlError::UrlMalformat`] for a host-less URL, plus any resolve, connect,
/// TLS, handshake, or frame-transfer error from the layers below.
pub(crate) async fn perform_ws(
    data: &mut Easy,
    scheme: &'static Scheme,
    sink: &mut dyn WriteCallbacks,
    source: &mut dyn ReadCallback,
) -> Result<()> {
    use crate::protocols::ws::{ws_inject_request_headers, WsConnState};

    // (1) Inject the WebSocket Upgrade request headers (curl's `Curl_ws_request`),
    //     each only if the user has not already supplied it.
    ws_inject_request_headers(data)?;

    // (2) Re-derive the request URL/host/port for the request builder. This is
    //     the same resolution `connect_network_scheme` performs internally; the
    //     parse is pure, so doing it here (to feed `make_inputs`) is harmless.
    let url = if let Some(uh) = data.set.uh.clone() {
        uh
    } else {
        let url_str = data.url().ok_or(CurlError::UrlMalformat)?.to_string();
        let mut parsed = CurlUrl::new();
        parsed
            .set(
                CurlUPart::Url,
                Some(&url_str),
                CURLU_GUESS_SCHEME | CURLU_DEFAULT_PORT,
            )
            .map_err(|_| CurlError::UrlMalformat)?;
        parsed
    };
    // `wss` rides TLS; this drives default-port elision in the `Host:` header
    // (443 vs 80). Taken from the resolved scheme descriptor (the single source
    // of truth shared with `connect_network_scheme`) rather than re-parsing.
    let is_wss = scheme.is_ssl();
    let host_bracketed = url.get(CurlUPart::Host, CURLU_URLDECODE).unwrap_or_default();
    if host_bracketed.is_empty() {
        return Err(CurlError::UrlMalformat);
    }
    let host = strip_brackets(&host_bracketed).to_string();
    let port = url
        .get(CurlUPart::Port, 0)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(scheme.default_port);

    // (3) Connect — plain TCP for `ws`, implicit TLS for `wss` — via the shared
    //     network-scheme connector (no ALPN; the upgrade is HTTP/1.1).
    let mut conn = crate::protocols::connect_network_scheme(data, scheme).await?;

    // (4) Build + drive the HTTP/1.1 `GET` Upgrade exchange. `is_websocket = true`
    //     forces `GET`; the `101` is delivered as a header-only response (no
    //     body), so the upgrade headers (including `Sec-WebSocket-Accept`) reach
    //     the sink under `--include`. Any bytes the server already pushed after
    //     the head are returned as the exchange's leftovers.
    let custom_headers = collect_custom_headers(data);
    let body = build_request_body(data, source)?;
    let leftover = {
        let plan = {
            let inputs = make_inputs(
                data,
                &url,
                &conn,
                &custom_headers,
                &host,
                port,
                is_wss,
                true, // is_websocket → forces GET
                body,
                1, // HTTP/1.1
            );
            h1::build_request(&inputs)?
        };
        let mut exchange = h1::H1Exchange::new(
            h1::ConnByteStream::new(&mut conn),
            plan,
            data.set.http09_allowed,
            false,
        );
        drive_one(data, &mut exchange, sink).await?;
        exchange.take_rbuf()
    };

    // (5) Handshake complete: install the RFC 6455 framing engine, seeded with
    //     any post-upgrade bytes the server already sent (curl's `Curl_ws_accept`
    //     writing the leftover into `ws->recvbuf`).
    let mut ws = WsConnState::new(data.set.ws_raw_mode, data.set.ws_no_auto_pong);
    ws.buffer_received(&leftover);

    if data.set.connect_only {
        // CONNECT_ONLY: hand the connection + framing engine to the easy handle
        // for the application's own `curl_ws_send`/`curl_ws_recv`.
        data.attach_ws_connection(conn, ws);
        return Ok(());
    }

    // (6) Plain `curl ws://…`: continue the transfer by reading frames and
    //     writing their payloads to the sink until the server closes.
    ws_cli_recv_loop(&mut conn, &mut ws, sink).await
}

/// The non-`CONNECT_ONLY` WebSocket download loop: read decoded frames and write
/// their payloads to the client `sink` until the server closes the connection.
///
/// This mirrors curl's transfer loop for a plain `curl ws://…`: a clean close
/// ([`CurlError::GotNothing`]) ends the transfer successfully; a short write to
/// the sink fails it with [`CurlError::WriteError`]; any other framing/transport
/// error propagates. A server that sends nothing (e.g. an echo server awaiting
/// the client) leaves this blocked in `recv` — exactly as curl blocks — until
/// the caller's timeout fires.
async fn ws_cli_recv_loop(
    conn: &mut Connection,
    ws: &mut crate::protocols::ws::WsConnState,
    sink: &mut dyn WriteCallbacks,
) -> Result<()> {
    // A 64 KiB receive buffer; `ws_recv` writes at most this many payload bytes
    // per call (a large frame is delivered in successive chunks).
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match ws.ws_recv(conn, &mut buf).await {
            Ok((n, _meta)) => {
                if n > 0 && sink.write_body(&buf[..n]) != n {
                    return Err(CurlError::WriteError);
                }
            }
            // A clean close with no further frames ends the transfer.
            Err(CurlError::GotNothing) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// `perform_http` helpers
// ---------------------------------------------------------------------------

/// Run the transfer-engine byte loop for a prepared `exchange`, delivering the
/// response through the client `sink`. Bundles the per-transfer state
/// ([`Request`]/[`Progress`]/[`ClientWriter`]/[`ErrorBuffer`]/[`TransferLimits`])
/// the same way curl's `Curl_sendrecv` does, reading the handle's `CURLOPT_*`
/// limits (`HEADER`, `VERBOSE`, `TIMEOUT(_MS)`, `LOW_SPEED_*`).
async fn drive_one<P: ProtocolExchange>(
    data: &mut Easy,
    exchange: &mut P,
    sink: &mut dyn WriteCallbacks,
) -> Result<()> {
    let mut request = Request::new();
    // Seed `no_body` from the easy handle, mirroring curl's `Curl_req_hard_reset`
    // (`request->no_body == data->set.opt_no_body`). This is essential for HEAD
    // (`-I` / `CURLOPT_NOBODY`): the response still carries `Content-Length`, so
    // `drive_transfer`'s end-of-transfer `check_partial_file` would otherwise see
    // `size = Some(n)` but `bytecount = 0` and wrongly report `CURLE_PARTIAL_FILE`.
    // With `no_body = true` that check short-circuits, matching curl.
    request.no_body = data.set.opt_no_body;
    let mut progress = Progress::new(Instant::now());
    let mut writer = ClientWriter::with_options(data.set.include_header, false);
    let mut errbuf = ErrorBuffer::with_verbose(data.set.verbose);
    let deadline = (data.set.timeout > 0)
        .then(|| Instant::now() + Duration::from_millis(data.set.timeout as u64));
    let limits = TransferLimits {
        deadline,
        low_speed_limit: data.set.low_speed_limit,
        low_speed_time: u32::from(data.set.low_speed_time),
    };
    drive_transfer(
        TransferParts {
            exchange,
            request: &mut request,
            progress: &mut progress,
            writer: &mut writer,
            write_cb: sink,
            limits: &limits,
            errbuf: &mut errbuf,
        },
        None,
        None,
    )
    .await?;

    // Record the post-transfer `data->info` store so `curl_easy_getinfo`
    // (CURLINFO_RESPONSE_CODE / SIZE_DOWNLOAD / SIZE_UPLOAD / HTTP_VERSION) and
    // the CLI's `--write-out` observe the real values, mirroring the typestate
    // transfer's `complete()` finalize (curl's `Curl_pgrsUpdate` + the
    // `PureInfo` fields). Without this, those fields would stay at their `0`
    // defaults even after a fully successful transfer (e.g. `%{http_code}` would
    // report `000`). The Easy-handle `Info` has no `record_progress` helper (that
    // lives on the typestate `TransferInfo`), so the fields are set directly.
    data.info.response_code = i64::from(request.httpcode);
    data.info.http_version = i64::from(request.httpversion);
    data.info.size_download = progress.download_size();
    data.info.size_upload = progress.upload_size();
    Ok(())
}

/// The [`SchemeDescriptor`] for `http`/`https`, carrying the canonical port and
/// `PROTOPT_*` flags so the connection layer sees the same scheme metadata as
/// the registered handler.
fn http_scheme_descriptor(is_https: bool) -> SchemeDescriptor {
    let scheme: &Scheme = if is_https { &SCHEME_HTTPS } else { &SCHEME_HTTP };
    SchemeDescriptor::new(
        scheme.name,
        scheme.default_port,
        scheme.flags,
        scheme.protocol,
    )
}

/// Strip a single surrounding `[`…`]` IPv6 bracket pair, returning the inner
/// host; non-bracketed input is returned unchanged.
fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host)
}

/// Collect the application's `CURLOPT_HTTPHEADER` lines as owned strings (the
/// `RequestInputs` custom-header slice borrows from this).
fn collect_custom_headers(data: &Easy) -> Vec<String> {
    data.set
        .headers
        .as_ref()
        .map(|list| {
            list.iter()
                .filter_map(|c| c.to_str().ok().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Whether a custom header named `target` is present (case-insensitive),
/// matching [`build_request`]'s own `find_custom_header_value` detection exactly
/// (the untrimmed `curlx_str_cspn` name span via [`proxy::parse_custom_header_line`]).
fn any_custom_header(lines: &[String], target: &str) -> bool {
    lines.iter().any(|line| {
        matches!(
            proxy::parse_custom_header_line(line),
            proxy::CustomHeader::Add { name, .. } if name.eq_ignore_ascii_case(target)
        )
    })
}

/// Whether the application requested a chunked upload via an explicit
/// `Transfer-Encoding: chunked` custom header.
fn upload_is_chunked(data: &Easy) -> bool {
    data.set.headers.as_ref().is_some_and(|list| {
        list.iter().any(|c| {
            c.to_str().is_ok_and(|line| {
                matches!(
                    proxy::parse_custom_header_line(line),
                    proxy::CustomHeader::Add { name, value }
                        if name.eq_ignore_ascii_case("Transfer-Encoding")
                            && value.eq_ignore_ascii_case("chunked")
                )
            })
        })
    })
}

/// Buffer the request body for the transfer:
///
/// * `CURLOPT_COPYPOSTFIELDS` / `-d` -> a sized body of the copied bytes.
/// * An upload (`CURLOPT_UPLOAD` / `-T`, `method == Put`) or a `CURLOPT_POST`
///   without copied fields -> the source read fully (chunked if the application
///   announced `Transfer-Encoding: chunked`, else sized).
/// * Otherwise (GET/HEAD/DELETE without data) -> no body; `source` is untouched.
fn build_request_body(data: &Easy, source: &mut dyn ReadCallback) -> Result<h1::RequestBody> {
    if let Some(fields) = data.set.copypostfields.as_ref() {
        return Ok(h1::RequestBody::Sized(fields.clone()));
    }
    let reads_source = data.set.method == HttpReq::Put || data.set.method == HttpReq::Post;
    if reads_source {
        let bytes = read_full_upload(source)?;
        return Ok(if upload_is_chunked(data) {
            h1::RequestBody::Chunked(bytes)
        } else {
            h1::RequestBody::Sized(bytes)
        });
    }
    Ok(h1::RequestBody::None)
}

/// Read the upload source to end-of-input into one buffer. A buffered request
/// body cannot honor a mid-read pause, so [`CURL_READFUNC_PAUSE`] is a read
/// error rather than a silent truncation; [`CURL_READFUNC_ABORT`] aborts.
fn read_full_upload(source: &mut dyn ReadCallback) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match source.read(&mut buf) {
            0 => break,
            CURL_READFUNC_ABORT => return Err(CurlError::AbortedByCallback),
            CURL_READFUNC_PAUSE => return Err(CurlError::ReadError),
            n if n <= buf.len() => body.extend_from_slice(&buf[..n]),
            _ => return Err(CurlError::ReadError),
        }
    }
    Ok(body)
}

/// Apply `--connect-to` (`CURLOPT_CONNECT_TO`): if an entry matches the request
/// `host`/`port` (an empty field matches anything), return the substituted
/// connect host/port; otherwise the request host/port are used unchanged. The
/// `Host:` header and SNI keep the original host (the caller passes the request
/// host to the request builder), matching curl's `conn->conn_to_host` behavior.
fn connect_target(data: &Easy, host: &str, port: u16) -> (String, u16) {
    let Some(list) = data.set.connect_to.as_ref() else {
        return (host.to_string(), port);
    };
    for entry in list.iter() {
        let Ok(line) = entry.to_str() else { continue };
        let Some((h1, p1, h2, p2)) = split_connect_to(line) else {
            continue;
        };
        let host_matches = h1.is_empty()
            || h1.eq_ignore_ascii_case(host)
            || strip_brackets(&h1).eq_ignore_ascii_case(host);
        let port_matches = p1.is_empty() || p1.parse::<u16>() == Ok(port);
        if host_matches && port_matches {
            let new_host = if h2.is_empty() {
                host.to_string()
            } else {
                strip_brackets(&h2).to_string()
            };
            let new_port = if p2.is_empty() {
                port
            } else {
                p2.parse::<u16>().unwrap_or(port)
            };
            return (new_host, new_port);
        }
    }
    (host.to_string(), port)
}

/// Split one `--connect-to` entry `HOST1:PORT1:HOST2:PORT2` into its four
/// fields, honoring `[bracketed IPv6]` host fields. Returns `None` if the entry
/// does not have the four colon-separated sections.
fn split_connect_to(line: &str) -> Option<(String, String, String, String)> {
    let (h1, rest) = take_host_field(line);
    let rest = rest.strip_prefix(':')?;
    let (p1, rest) = take_plain_field(rest);
    let rest = rest.strip_prefix(':')?;
    let (h2, rest) = take_host_field(rest);
    let rest = rest.strip_prefix(':')?;
    Some((h1, p1, h2, rest.to_string()))
}

/// Take a host field, which may be a `[bracketed IPv6]` literal (kept bracketed)
/// or a plain token up to the next `:`. Returns the field and the remainder
/// (which begins at the delimiter `:` if any).
fn take_host_field(s: &str) -> (String, &str) {
    if let Some(after_open) = s.strip_prefix('[') {
        if let Some(close) = after_open.find(']') {
            let host = &after_open[..close];
            return (format!("[{host}]"), &after_open[close + 1..]);
        }
    }
    take_plain_field(s)
}

/// Take a plain token up to the next `:`; returns the token and the remainder
/// (beginning at the `:` if present, else empty).
fn take_plain_field(s: &str) -> (String, &str) {
    match s.find(':') {
        Some(i) => (s[..i].to_string(), &s[i..]),
        None => (s.to_string(), ""),
    }
}

/// Resolve `host:port` through curl's complete resolution pipeline.
///
/// `--resolve` (`CURLOPT_RESOLVE`) overrides are pre-loaded into a transient
/// cache as **permanent** entries (curl's `Curl_loadhostpairs`), then resolution
/// runs through [`dns::resolve`], which applies the full curl ordering:
/// IDN→ACE, `.onion` rejection, DNS cache lookup (which finds the pre-loaded
/// `--resolve` entries), IP-literal and `localhost` shortcuts, and finally
/// either DoH (`CURLOPT_DOH_URL` / `--doh-url`) or the system resolver.
///
/// Routing through [`dns::resolve`] — rather than calling the system backend
/// directly — is what makes `--doh-url` take effect on the transfer path: the
/// previous implementation consulted only the `--resolve` cache and then went
/// straight to the system resolver, silently ignoring the configured DoH URL.
async fn resolve_addrs(
    data: &Easy,
    host: &str,
    port: u16,
    ipver: IpVersion,
    verbose: bool,
) -> Result<ResolvedAddrs> {
    // A single cache backs both the `--resolve` pre-load and the resolve below,
    // so the permanent pre-loaded entries are visible to `dns::resolve`'s cache
    // lookup (a permanent entry has no timestamp and is never evicted as stale).
    let mut cache = DnsCache::new();
    let mut errbuf: Option<String> = None;

    // Pre-load `--resolve` host:port:addr overrides (curl's `Curl_loadhostpairs`).
    if let Some(list) = data.set.resolve.as_ref() {
        let entries: Vec<String> = list
            .iter()
            .filter_map(|c| c.to_str().ok().map(String::from))
            .collect();
        if !entries.is_empty() {
            load_host_pairs(&mut cache, &entries, curlx_now(), verbose, &mut errbuf)?;
        }
    }

    // Resolve through the full pipeline, honoring `CURLOPT_DOH_URL` so that
    // `--doh-url` routes name resolution through DNS-over-HTTPS rather than the
    // system resolver. All other fields keep curl's defaults from
    // `ResolveParams::new`.
    let mut params = ResolveParams::new(host, port);
    params.ip_version = ipver;
    params.doh_url = data.set.str(StrId::Doh);
    params.verbose = verbose;

    let entry = dns::resolve(&mut cache, &params, &mut errbuf).await?;
    Ok(entry.addrs.clone())
}

// ===========================================================================
// DoH transport — carries a DoH probe as an HTTP(S) `POST` through this engine
// ===========================================================================

/// Installs the engine-backed [`DohTransport`] process-wide (once).
///
/// Invoked at [`perform_http`] entry. [`install_doh_transport`] is itself
/// idempotent (a `OnceLock::set`), so repeated calls — including the re-entrant
/// call made by the DoH probe's own internal transfer — are cheap no-ops after
/// the first.
fn install_doh_transport_once() {
    install_doh_transport(Arc::new(EngineDohTransport));
}

/// The production [`DohTransport`]: it issues each DoH probe as an HTTP(S)
/// `POST` using a short-lived internal easy handle, mirroring curl's
/// `doh->probe[].easy` sub-transfers. Reusing the engine means the DoH request
/// shares the exact connect / TLS / HTTP framing / response-read path as any
/// other transfer — no separate HTTP client, no wire divergence.
struct EngineDohTransport;

impl DohTransport for EngineDohTransport {
    fn send<'a>(
        &'a self,
        req: DohProbeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(doh_probe_post(req))
    }
}

/// A [`WriteCallbacks`] sink that accumulates the DoH response body. Header
/// bytes are discarded (DoH consumes only the binary `application/dns-message`
/// body); returning `None` matches curl's NULL header-callback contract.
#[derive(Default)]
struct DohBodySink {
    body: Vec<u8>,
}

impl WriteCallbacks for DohBodySink {
    fn write_body(&mut self, data: &[u8]) -> usize {
        self.body.extend_from_slice(data);
        data.len()
    }
    fn write_header(&mut self, _data: &[u8]) -> Option<usize> {
        None
    }
}

/// An empty upload source: the DoH `POST` body is supplied via
/// `CURLOPT_COPYPOSTFIELDS`, so the read callback is never the body source.
/// This guards against any path consulting the source (it must not block on,
/// e.g., stdin).
struct EmptyReadSource;

impl ReadCallback for EmptyReadSource {
    fn read(&mut self, _buf: &mut [u8]) -> usize {
        0
    }
}

/// Issues a single DoH probe as an HTTP(S) `POST` and returns the raw response
/// body — the body of [`EngineDohTransport::send`].
///
/// The internal easy handle is configured exactly as curl configures a DoH
/// probe (`doh.c`): `POST` the encoded query as an owned body, set both
/// `Content-Type` and `Accept` to `application/dns-message`, and apply the DoH
/// SSL posture inherited from the parent transfer (`CURLOPT_DOH_SSL_VERIFY*`,
/// CA material). The handle carries no `CURLOPT_DOH_URL`, so resolving the DoH
/// endpoint itself uses the IP-literal shortcut / system resolver — there is no
/// recursion.
async fn doh_probe_post(req: DohProbeRequest) -> Result<Vec<u8>> {
    let mut sub = Easy::new();

    // Endpoint URL (the `CURLOPT_DOH_URL` value).
    sub.setopt(CurlOption::CURLOPT_URL, OptionValue::Str(Some(req.url)))?;

    // `Content-Type` + `Accept: application/dns-message` (curl sets both).
    let mut headers = SList::new();
    headers.append(&format!("Content-Type: {}", req.content_type))?;
    headers.append(&format!("Accept: {}", req.content_type))?;
    sub.setopt(
        CurlOption::CURLOPT_HTTPHEADER,
        OptionValue::Slist(Some(headers)),
    )?;

    // The encoded DNS query is the POST body. `COPYPOSTFIELDS` takes ownership
    // (G1: Rust owns the bytes) and switches the method to `POST`.
    sub.setopt(
        CurlOption::CURLOPT_COPYPOSTFIELDS,
        OptionValue::Bytes(Some(req.body)),
    )?;

    // DoH SSL posture inherited from the parent transfer
    // (`CURLOPT_DOH_SSL_VERIFY*`). `verify_host` maps to curl's 0/2 long.
    sub.setopt(
        CurlOption::CURLOPT_SSL_VERIFYPEER,
        OptionValue::Long(i64::from(req.ssl.verify_peer)),
    )?;
    sub.setopt(
        CurlOption::CURLOPT_SSL_VERIFYHOST,
        OptionValue::Long(if req.ssl.verify_host { 2 } else { 0 }),
    )?;
    sub.setopt(
        CurlOption::CURLOPT_SSL_VERIFYSTATUS,
        OptionValue::Long(i64::from(req.ssl.verify_status)),
    )?;
    if let Some(ca_info) = req.ssl.ca_info {
        sub.setopt(CurlOption::CURLOPT_CAINFO, OptionValue::Str(Some(ca_info)))?;
    }
    if let Some(ca_path) = req.ssl.ca_path {
        sub.setopt(CurlOption::CURLOPT_CAPATH, OptionValue::Str(Some(ca_path)))?;
    }
    if let Some(crl_file) = req.ssl.crl_file {
        sub.setopt(CurlOption::CURLOPT_CRLFILE, OptionValue::Str(Some(crl_file)))?;
    }

    // Drive the probe transfer, collecting the binary response body.
    let mut sink = DohBodySink::default();
    let mut source = EmptyReadSource;
    sub.perform_with(&mut sink, &mut source).await?;
    Ok(sink.body)
}

/// Assemble the [`RequestInputs`] for [`build_request`]/[`build_h2_request`] from
/// the handle's options. Header-suppression flags (`Host`/`Accept`/`Expect`
/// present) are derived from the custom-header lines exactly as the builder's
/// own lookup does; auth/cookie-engine/encoding values that belong to other
/// stateful subsystems are left to their defaults for this HTTP-transfer seam.
#[allow(clippy::too_many_arguments)]
fn make_inputs<'a>(
    data: &'a Easy,
    url: &'a CurlUrl,
    conn: &'a Connection,
    custom_headers: &'a [String],
    host: &'a str,
    port: u16,
    is_https: bool,
    is_websocket: bool,
    body: h1::RequestBody,
    http_minor: u8,
) -> h1::RequestInputs<'a> {
    let (content_length, chunked) = match &body {
        h1::RequestBody::Sized(b) => (Some(b.len() as i64), false),
        h1::RequestBody::Chunked(_) => (None, true),
        h1::RequestBody::None => (None, false),
    };
    h1::RequestInputs {
        url,
        conn,
        method_kind: data.set.method,
        no_body: data.set.opt_no_body,
        custom_request: data.set.str(StrId::Customrequest),
        is_websocket,
        is_upload: data.set.method == HttpReq::Put,
        host,
        port,
        is_https,
        host_header_present: any_custom_header(custom_headers, "Host"),
        user_agent: data.set.str(StrId::Useragent),
        authorization: None,
        proxy_authorization: None,
        range: data.set.str(StrId::SetRange),
        accept_present: any_custom_header(custom_headers, "Accept"),
        te_gzip: false,
        accept_encoding: data.set.str(StrId::Encoding),
        referer: data.set.str(StrId::SetReferer),
        proxy_connection_keepalive: false,
        cookie: data.set.str(StrId::Cookie),
        body,
        content_type: None,
        content_length,
        chunked,
        disable_expect: false,
        expect_present: any_custom_header(custom_headers, "Expect"),
        custom_expect_100: false,
        is_upgrade: false,
        custom_headers,
        proxy_headers: &[],
        sep_headers: false,
        authneg: false,
        allowed_to_host: true,
        http_minor,
        request_target_override: None,
        proxy_transfer_mode: false,
        prefer_ascii: data.set.prefer_ascii,
        expect_100_timeout_ms: data.set.expect_100_timeout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{SchemeDescriptor, TRNSPRT_TCP};
    use crate::protocols::{
        CURLPROTO_HTTP, CURLPROTO_HTTPS, PROTOPT_ALPN, PROTOPT_CONN_REUSE,
        PROTOPT_CREDSPERREQUEST, PROTOPT_SSL, PROTOPT_USERPWDCTRL, SCHEME_HTTP, SCHEME_HTTPS,
    };

    // `CURL_HTTP_VERSION_*` values that map to the ALPN/default path and so are
    // not named as module-level constants (see the catch-all arm rationale).
    const HTTP_VERSION_NONE: u8 = 0;
    const HTTP_VERSION_2_0: u8 = 3;
    const HTTP_VERSION_2TLS: u8 = 4;

    /// Build a bare TCP `Connection` for `scheme` with no ALPN filter installed
    /// (so `Curl_conn_get_alpn_negotiated` yields `None`).
    fn test_conn(scheme: &Scheme) -> Connection {
        let desc = SchemeDescriptor::new(
            scheme.name,
            scheme.default_port,
            scheme.flags,
            scheme.protocol,
        );
        Connection::new(
            format!("{}:{}", scheme.name, scheme.default_port),
            TRNSPRT_TCP,
            desc,
        )
    }

    fn easy_with_httpwant(want: u8) -> Easy {
        let mut e = Easy::new();
        e.set.httpwant = want;
        e
    }

    // ---- Scheme descriptors must match the C `Curl_scheme_http`/`https` ----

    #[test]
    fn http_scheme_descriptor_matches_c() {
        let h = HttpProtocol::new(&SCHEME_HTTP);
        let s = h.scheme();
        assert_eq!(s.name, "http");
        assert_eq!(s.protocol, CURLPROTO_HTTP);
        assert_eq!(s.family, CURLPROTO_HTTP);
        assert_eq!(
            s.flags,
            PROTOPT_CREDSPERREQUEST | PROTOPT_USERPWDCTRL | PROTOPT_CONN_REUSE
        );
        assert_eq!(s.default_port, 80);
        // `http` is cleartext: the SSL flag must be clear.
        assert_eq!(s.flags & PROTOPT_SSL, 0);
    }

    #[test]
    fn https_scheme_descriptor_matches_c() {
        let h = HttpProtocol::new(&SCHEME_HTTPS);
        let s = h.scheme();
        assert_eq!(s.name, "https");
        assert_eq!(s.protocol, CURLPROTO_HTTPS);
        // Family is HTTP for both schemes (connection reuse across http/https).
        assert_eq!(s.family, CURLPROTO_HTTP);
        assert_eq!(
            s.flags,
            PROTOPT_SSL
                | PROTOPT_CREDSPERREQUEST
                | PROTOPT_ALPN
                | PROTOPT_USERPWDCTRL
                | PROTOPT_CONN_REUSE
        );
        assert_eq!(s.default_port, 443);
        // `https` must request both TLS and ALPN.
        assert_ne!(s.flags & PROTOPT_SSL, 0);
        assert_ne!(s.flags & PROTOPT_ALPN, 0);
    }

    #[test]
    fn scheme_accessor_returns_the_instance_descriptor() {
        assert_eq!(HttpProtocol::new(&SCHEME_HTTP).scheme().name, "http");
        assert_eq!(HttpProtocol::new(&SCHEME_HTTPS).scheme().name, "https");
    }

    // ---- `version_from_alpn` truth table ----

    #[test]
    fn alpn_http_1_0_selects_http10() {
        assert_eq!(version_from_alpn(Some(b"http/1.0")), HttpVersion::Http10);
    }

    #[test]
    fn alpn_http_1_1_selects_http11() {
        assert_eq!(version_from_alpn(Some(b"http/1.1")), HttpVersion::Http11);
    }

    #[test]
    fn alpn_absent_selects_http11() {
        assert_eq!(version_from_alpn(None), HttpVersion::Http11);
    }

    #[test]
    fn alpn_unknown_token_selects_http11() {
        assert_eq!(version_from_alpn(Some(b"spdy/3.1")), HttpVersion::Http11);
    }

    #[test]
    fn alpn_h2_selects_h2_or_falls_back() {
        let got = version_from_alpn(Some(b"h2"));
        #[cfg(feature = "http2")]
        assert_eq!(got, HttpVersion::H2);
        #[cfg(not(feature = "http2"))]
        assert_eq!(got, HttpVersion::Http11);
    }

    // ---- `select_http_version` precedence: explicit option > ALPN > default ----

    #[test]
    fn select_default_no_alpn_is_http11() {
        let e = easy_with_httpwant(HTTP_VERSION_NONE);
        let c = test_conn(&SCHEME_HTTPS);
        assert_eq!(select_http_version(&e, &c).unwrap(), HttpVersion::Http11);
    }

    #[test]
    fn select_forces_http10() {
        let e = easy_with_httpwant(CURL_HTTP_VERSION_1_0);
        let c = test_conn(&SCHEME_HTTP);
        assert_eq!(select_http_version(&e, &c).unwrap(), HttpVersion::Http10);
    }

    #[test]
    fn select_forces_http11() {
        let e = easy_with_httpwant(CURL_HTTP_VERSION_1_1);
        let c = test_conn(&SCHEME_HTTP);
        assert_eq!(select_http_version(&e, &c).unwrap(), HttpVersion::Http11);
    }

    #[test]
    fn select_http2_values_without_alpn_default_to_http11() {
        // `2_0` and `2TLS` express a *preference* satisfied via ALPN; with no
        // ALPN negotiated they resolve to HTTP/1.1 (no upgrade was offered).
        let c = test_conn(&SCHEME_HTTPS);
        for want in [HTTP_VERSION_2_0, HTTP_VERSION_2TLS] {
            let e = easy_with_httpwant(want);
            assert_eq!(select_http_version(&e, &c).unwrap(), HttpVersion::Http11);
        }
    }

    #[test]
    fn select_prior_knowledge_picks_h2_or_falls_back() {
        let e = easy_with_httpwant(CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
        let c = test_conn(&SCHEME_HTTP);
        let got = select_http_version(&e, &c).unwrap();
        #[cfg(feature = "http2")]
        assert_eq!(got, HttpVersion::H2);
        #[cfg(not(feature = "http2"))]
        assert_eq!(got, HttpVersion::Http11);
    }

    #[test]
    fn select_http3_values_respect_feature() {
        let c = test_conn(&SCHEME_HTTPS);
        for want in [CURL_HTTP_VERSION_3, CURL_HTTP_VERSION_3ONLY] {
            let e = easy_with_httpwant(want);
            let got = select_http_version(&e, &c);
            #[cfg(feature = "http3")]
            assert_eq!(got.unwrap(), HttpVersion::H3);
            #[cfg(not(feature = "http3"))]
            assert!(got.is_err());
        }
    }

    // ---- `do_it` describes the transfer and records protocol state ----

    #[tokio::test]
    async fn do_it_default_get_describes_download() {
        let handler = HttpProtocol::new(&SCHEME_HTTP);
        let mut data = Easy::new(); // default: no body, not no-body ⇒ download
        let mut conn = test_conn(&SCHEME_HTTP);
        let t = handler.do_it(&mut data, &mut conn).await.expect("do_it ok");
        assert_eq!(t.direction, TransferDirection::Download);
        assert!(t.has_response_headers);
        // The selected version was recorded as protocol state.
        assert!(conn.take_proto_state().is_some());
    }

    #[tokio::test]
    async fn do_it_nobody_describes_no_transfer_direction() {
        let handler = HttpProtocol::new(&SCHEME_HTTP);
        let mut data = Easy::new();
        data.set.opt_no_body = true;
        let mut conn = test_conn(&SCHEME_HTTP);
        let t = handler.do_it(&mut data, &mut conn).await.expect("do_it ok");
        assert_eq!(t.direction, TransferDirection::None);
    }

    #[tokio::test]
    async fn do_it_with_post_fields_describes_upload_with_size() {
        let handler = HttpProtocol::new(&SCHEME_HTTP);
        let mut data = Easy::new();
        data.set.copypostfields = Some(b"field=value".to_vec());
        let mut conn = test_conn(&SCHEME_HTTP);
        let t = handler.do_it(&mut data, &mut conn).await.expect("do_it ok");
        assert_eq!(t.direction, TransferDirection::Upload);
        assert_eq!(t.expected_size, Some("field=value".len() as u64));
    }

    #[tokio::test]
    async fn done_clears_recorded_protocol_state() {
        let handler = HttpProtocol::new(&SCHEME_HTTP);
        let mut data = Easy::new();
        let mut conn = test_conn(&SCHEME_HTTP);
        handler.do_it(&mut data, &mut conn).await.expect("do_it ok");
        // `done` must clear the state recorded by `do_it`.
        handler
            .done(&mut data, &mut conn, Ok(()), false)
            .await
            .expect("done ok");
        assert!(conn.take_proto_state().is_none());
    }
}
