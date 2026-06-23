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

use crate::conn::{
    BoxFuture, Connection, Curl_conn_cf_adjust_pollset, Curl_conn_get_alpn_negotiated,
    Curl_conn_get_first_socket, Curl_conn_get_ip_info, Curl_conn_get_peer_certs,
    Curl_conn_get_remote_addr, Curl_conn_is_alive,
};
use crate::easy::Easy;
use crate::error::Result;
// `CURL_POLL_*` socket-interest flags, used by [`report_socket_to_observer`] to
// translate a connection's [`Pollset`] (read/write interest) into the
// `CURL_POLL_IN`/`OUT`/`INOUT`/`NONE` value an event-loop consumer expects from
// `CURLMOPT_SOCKETFUNCTION`. `CURL_POLL_REMOVE` is emitted by the multi handle
// on transfer completion, not here.
use crate::multi::{CURL_POLL_IN, CURL_POLL_INOUT, CURL_POLL_NONE, CURL_POLL_OUT};
// `CurlError` is used by the version selector (to reject an explicit
// `--http3`/`--http3-only` with `CURLE_NOT_BUILT_IN` when HTTP/3 is compiled
// out) and by the transfer driver [`perform_http`] (URL/scheme rejection,
// resolve/connect failures). It is therefore imported unconditionally.
use crate::error::CurlError;
use crate::protocols::{Protocol, ProtocolTransfer, Scheme, TransferDirection};
// `CURLOPT_MAX_RECV_SPEED_LARGE` / `CURLOPT_MAX_SEND_SPEED_LARGE` (the CLI's
// `--limit-rate`) are enforced by constructing a [`RateLimit`] from the stored
// caps and threading it into the transfer driver. The receive cap is applied in
// [`crate::transfer::drive_transfer`]'s response loop; the send cap is applied
// in the streaming request-body send path. `Direction` itself is only consumed
// inside `drive_transfer`, so only the constructor type is imported here.
use crate::ratelimit::RateLimit;
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
use crate::headers::CURLH_HEADER;
use crate::progress::{Progress, Timer};
use crate::protocols::pingpong::tls_config_from_easy;
use crate::protocols::{SCHEME_HTTP, SCHEME_HTTPS};
use crate::request::Request;
use crate::setopt::{HttpReq, OptionValue, StrId};
// `Request`/`Progress` are imported from their own modules above: `transfer.rs`
// pulls them in via a *private* `use`, so they are not re-exported there.
use crate::transfer::{
    drive_transfer, follow, ClientWriter, ErrorBuffer, FollowOutcome, FollowRequest, FollowType,
    HttpMethod, PostRedir, ProtocolExchange, ReadCallback, RedirectAuthContext, RedirectConfig,
    RedirectState, TransferLimits, TransferParts, WriteCallbacks, CURL_READFUNC_ABORT,
    CURL_READFUNC_PAUSE,
};
use crate::url::{
    CurlUPart, CurlUrl, CURLU_DEFAULT_PORT, CURLU_GUESS_SCHEME, CURLU_PATH_AS_IS, CURLU_URLDECODE,
    CURLU_URLENCODE,
};
use crate::util::timeval::curlx_now;
use std::borrow::Cow;
// DoH transport seam: this module is the runtime collaborator that carries a
// DoH probe as an HTTP(S) `POST` (see `crate::dns::doh`). The transport is
// installed lazily at [`perform_http`] entry so `--doh-url` resolution can
// re-enter the engine via a short-lived internal easy handle.
use crate::dns::doh::{install_transport as install_doh_transport, DohProbeRequest, DohTransport};
use crate::options::CurlOption;
use crate::slist::SList;
use std::ffi::CString;
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

/// Encode one DER-encoded certificate as a PEM block — the textual form curl's
/// TLS backends store in `CURLINFO_CERTINFO`'s `Cert` field (their
/// `PEM_write_bio_X509` output): a `-----BEGIN CERTIFICATE-----` header, the
/// base64 of the DER wrapped at 64 columns (the width OpenSSL's PEM writer
/// uses), and a `-----END CERTIFICATE-----` trailer. No trailing newline — the
/// caller stores it as one `"Cert:<pem>"` certinfo node and the writeout
/// `%{certs}` consumer (`tool_writeout.c` `VAR_CERT`) handles line termination.
fn der_to_pem(der: &[u8]) -> String {
    // `base64_encode` is the workspace's standard-alphabet encoder and emits an
    // unwrapped ASCII string; PEM requires 64-column lines, so re-wrap here.
    let b64 = crate::util::base64::base64_encode(der).unwrap_or_default();
    let mut pem = String::with_capacity(b64.len() + b64.len() / 64 + 64);
    pem.push_str("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.chunks(64) {
        // `b64` is pure base64 alphabet (ASCII), so the decode is lossless.
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----");
    pem
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
//
// `perform_http` is a *redirect orchestrator* around a single-request helper
// [`perform_http_hop`]: it drives one request/response, and — when
// `CURLOPT_FOLLOWLOCATION` is on and the response is a `3xx` carrying a
// `Location` — resolves the next URL, rewrites the method per the redirect
// rules ([`crate::transfer::follow`]/[`redirect_method`]), and loops, enforcing
// `CURLOPT_MAXREDIRS`. This ports curl's `lib/transfer.c` `Curl_follow` loop in
// `multi_do`/`readwrite_data`, which the single-shot engine previously omitted
// (QA finding F6-003).
// ===========================================================================

/// Per-hop request overrides computed by the [`perform_http`] orchestrator and
/// consumed by [`make_inputs`]. These are the request-shaping values that vary
/// across redirect hops (the method/body after a method rewrite) or that the
/// engine computes from stateful subsystems (cookies, authentication, proxy
/// auth) rather than reading verbatim from `data.set`.
///
/// The fields own their strings so the struct does not borrow the easy handle,
/// which lets the orchestrator hold it across the `&mut Easy` hop call. Defaults
/// reproduce the pre-orchestrator single-shot behavior (no auth, inline-cookie
/// only, no proxy), so a hop built with [`HopInputs::single_shot`] is wire-identical
/// to the legacy path.
struct HopInputs {
    /// The request method for this hop (`data->state.httpreq`, possibly rewritten
    /// by a prior redirect).
    method: HttpReq,
    /// `CURLOPT_NOBODY` for this hop (cleared when a POST is downgraded to GET).
    no_body: bool,
    /// The `Authorization` header value, or `None`. (Wired by later findings.)
    authorization: Option<String>,
    /// The `Proxy-Authorization` header value, or `None`. (Wired by later findings.)
    proxy_authorization: Option<String>,
    /// The `Cookie` header value (inline `-b` merged with jar matches), or `None`.
    cookie: Option<String>,
    /// The `Referer` value (auto-referer on redirect, else `CURLOPT_REFERER`).
    referer: Option<String>,
    /// Whether the host's credentials may be sent to this hop's host.
    allowed_to_host: bool,
    /// `true` to send `Proxy-Connection: Keep-Alive` (forward HTTP proxy).
    proxy_connection_keepalive: bool,
    /// The resolved proxy username/password for this hop (the `-x` proxy URL's
    /// embedded userinfo, overlaid by `CURLOPT_PROXYUSERNAME`/`PROXYPASSWORD` —
    /// curl's unified `data->state.aptr.proxyuser`/`proxypasswd`). Deposited by
    /// [`http_connect_hop`]'s forward-proxy branch (where the parsed [`Proxy`] is
    /// in hand) so the reactive **proxy**-auth controller can attempt the proxy's
    /// `407` even when the credentials were supplied only in the proxy URL rather
    /// than via `--proxy-user` (test 335). `None` when no forward HTTP proxy
    /// applies to this hop.
    proxy_user: Option<String>,
    proxy_pass: Option<String>,
    /// `CURLOPT_REQUEST_TARGET`-style request-target override (forward proxy), if any.
    request_target_override: Option<String>,
    /// The reactive-auth seed (Digest/NTLM/`--anyauth` credentials + wanted scheme
    /// mask), or `None` when no challenge-response auth applies to this hop. When
    /// present, the HTTP/1.1 hop driver runs a challenge-response retry loop on
    /// the kept-alive connection (curl's `data->state.authhost` negotiation).
    /// Deposited cross-host-gated exactly like [`authorization`](Self::authorization).
    auth: Option<auth_engine::AuthInputs>,
    /// Suppress the application's custom `Host:` header for this hop, emitting the
    /// auto-generated `Host:` for the *current* host instead.
    ///
    /// curl sends the application's custom `Host:` (`CURLOPT_HTTPHEADER`) only on
    /// the original request and on same-host redirects: lib/http.c uses the custom
    /// value IFF `(!data->state.this_is_a_follow || curl_strequal(first_host,
    /// conn->host.name))`, and otherwise emits the auto `Host:` for the redirect
    /// target's host. When this is `true` (a cross-host redirect), the orchestrator
    /// strips the custom `Host:` line from `custom_headers` so the builder emits
    /// the current host (tests 184/185).
    suppress_custom_host: bool,
}

impl HopInputs {
    /// Build the overrides for a legacy single-shot transfer from `data.set`:
    /// the configured method/body, inline `-b` cookie and `CURLOPT_REFERER`, and
    /// no auth/proxy injection. Used by the HTTP/3 path and as the first-hop seed.
    fn single_shot(data: &Easy) -> Self {
        HopInputs {
            method: data.set.method,
            no_body: data.set.opt_no_body,
            authorization: None,
            proxy_authorization: None,
            cookie: data.set.str(StrId::Cookie).map(str::to_string),
            referer: data.set.str(StrId::SetReferer).map(str::to_string),
            allowed_to_host: true,
            proxy_connection_keepalive: false,
            proxy_user: None,
            proxy_pass: None,
            request_target_override: None,
            auth: None,
            // A single-shot transfer is never a follow, so the custom `Host:`
            // (if any) is always sent (curl's `!this_is_a_follow`).
            suppress_custom_host: false,
        }
    }
}

/// The observable outcome of one request/response hop, captured by [`HopSink`]
/// and returned by [`perform_http_hop`] so the orchestrator can decide whether
/// to follow a redirect. Later findings extend this with the response headers
/// the stateful subsystems consume (`Set-Cookie`, `Strict-Transport-Security`,
/// `Alt-Svc`).
struct HopResult {
    /// The final response status code (`data->req.httpcode`).
    status: i32,
    /// The `Location` header value, if present.
    location: Option<String>,
    /// All `Set-Cookie` header values from this hop's response, in order, for
    /// the cookie engine to store (curl's `Curl_cookie_add` per response).
    #[cfg(feature = "cookies")]
    set_cookies: Vec<String>,
    /// The last `Strict-Transport-Security` header value, if present, for the
    /// HSTS engine to record (curl's `Curl_hsts_parse`).
    #[cfg(feature = "hsts")]
    sts: Option<String>,
    /// The last `Alt-Svc` header value, if present, for the alt-svc cache to
    /// record (curl's `Curl_altsvc_parse`).
    #[cfg(feature = "alt-svc")]
    alt_svc: Option<String>,
}

/// Whether `status` is a redirect the engine follows when `CURLOPT_FOLLOWLOCATION`
/// is on and a `Location` is present — any `3xx` (curl follows on the presence of
/// a `Location` header for a `3xx`; `304`/`305`/`306` never carry one in practice
/// and so never follow).
fn is_redirect_status(status: i32) -> bool {
    (300..400).contains(&status)
}

/// Whether a *followed-redirect* target `scheme` is permitted, the port of C
/// `findprotocol` (`lib/url.c`) evaluated with `data->state.this_is_a_follow`
/// set.
///
/// curl gates every connection on `CURLOPT_PROTOCOLS` (`allowed`) and, when the
/// connection is the result of a redirect, additionally on
/// `CURLOPT_REDIR_PROTOCOLS` (`redir`). The scheme's single `CURLPROTO_*` bit
/// (from its [`scheme_descriptor`](crate::protocols::scheme_descriptor)) must be
/// present in *both* masks. A scheme with no compiled-in handler has bit `0` and
/// is therefore never allowed — matching curl's "not supported" rejection.
///
/// Returns `true` when the redirect may proceed; a `false` result maps to
/// [`CurlError::UnsupportedProtocol`] (`CURLE_UNSUPPORTED_PROTOCOL`, the curl
/// `--proto-redir`/`--proto` denial). The defaults — `allowed = CURLPROTO_ALL`
/// and `redir = CURLPROTO_REDIR` (HTTP|HTTPS|FTP|FTPS) — leave ordinary HTTP(S)
/// redirects untouched.
fn redirect_protocol_allowed(scheme: &str, allowed: u32, redir: u32) -> bool {
    let bit = crate::protocols::scheme_descriptor(scheme).map_or(0, |s| s.protocol);
    bit != 0 && (allowed & bit) != 0 && (redir & bit) != 0
}

/// Whether an HTTP response code is a terminal `CURLOPT_FAILONERROR` failure,
/// reimplementing curl's `http_should_fail()` (`lib/http.c`). The caller has
/// already established that `CURLOPT_FAILONERROR` (`-f`/`--fail`) is set, so this
/// only decides the per-status rules:
///
/// * any code `< 400` never fails;
/// * a `416 Range Not Satisfiable` answer to a resumed `GET` is *not* a failure
///   (the file is presumably already fully downloaded — curl's
///   `state.resume_from && httpreq == GET && httpcode == 416` exception);
/// * any code `>= 400` other than `401`/`407` is always terminal;
/// * a `401`/`407` with no corresponding credential configured is terminal
///   (curl's `!aptr.user` / `!proxy_user_passwd` checks);
/// * a `401`/`407` that survives after credentials were supplied is terminal —
///   curl returns `state.authproblem`, which for this engine's single-shot,
///   preemptive-`Basic` auth (there is no `401`-retry negotiation loop) means a
///   repeated challenge could not be satisfied, i.e. a failure.
///
/// `resume` is `state.resume_from != 0`, `is_get` is `method == GET`, and
/// `has_user`/`has_proxy_user` mirror whether host/proxy credentials are set.
fn http_should_fail(
    code: i32,
    resume: bool,
    is_get: bool,
    has_user: bool,
    has_proxy_user: bool,
) -> bool {
    if code < 400 {
        return false;
    }
    if resume && is_get && code == 416 {
        return false;
    }
    if code != 401 && code != 407 {
        return true;
    }
    if code == 401 && !has_user {
        return true;
    }
    if code == 407 && !has_proxy_user {
        return true;
    }
    // Residual `401`/`407` after credentials were provided: curl returns
    // `data->state.authproblem`. With single-shot preemptive Basic and no auth
    // re-negotiation loop, a still-challenging response means authentication did
    // not succeed, so this is a failure — matching curl's terminal outcome for
    // the non-negotiating case.
    true
}

/// The per-response `CURLOPT_FAILONERROR` (`-f`/`--fail`) verdict, honoring the
/// reactive-auth deferral.
///
/// This wraps [`http_should_fail`] with one extra rule: when `defer_auth_fail`
/// is set (the HTTP/1.x hop loop passes `auth_controller.is_some()`), an
/// intermediate `401`/`407` is the server's auth *challenge* during a live
/// challenge-response negotiation, NOT a terminal error — so the failonerror
/// verdict is deferred (returns `false`) and the negotiation is allowed to run
/// to completion. This mirrors curl's `http_should_fail`, which returns
/// `data->state.authproblem` for an answered-able challenge (FALSE while the
/// negotiation can still proceed). The hop loop re-applies the real
/// [`http_should_fail`] verdict to the TERMINAL response once negotiation ends,
/// so a genuinely rejected/again-`401` final response still fails with exit 22.
///
/// Every non-auth call site (h2/h3/websocket, and any transfer without a
/// reactive controller) passes `defer_auth_fail = false`, so a `401`/`407`
/// fails immediately exactly as before (test 152). (test 150)
fn failonerror_verdict(
    defer_auth_fail: bool,
    code: i32,
    resume: bool,
    is_get: bool,
    has_user: bool,
    has_proxy_user: bool,
) -> bool {
    if defer_auth_fail && (code == 401 || code == 407) {
        return false;
    }
    http_should_fail(code, resume, is_get, has_user, has_proxy_user)
}

/// Map a `HttpReq` request kind to the redirect-logic [`HttpMethod`]. `HEAD`
/// (`CURLOPT_NOBODY`) is represented as `GET` in `data.set.method`, so the
/// rewrite rules see it as a non-POST method, exactly as curl does.
fn http_method_of(method: HttpReq) -> HttpMethod {
    match method {
        HttpReq::Get => HttpMethod::Get,
        HttpReq::Post => HttpMethod::Post,
        HttpReq::PostForm => HttpMethod::PostForm,
        HttpReq::PostMime => HttpMethod::PostMime,
        HttpReq::Put => HttpMethod::Put,
        HttpReq::Head => HttpMethod::Head,
    }
}

/// Parse the numeric status code from the portion of an HTTP status line that
/// follows `HTTP/` (e.g. `"1.1 302 Found"` → `Some(302)`). Returns `None` for a
/// malformed status line.
fn parse_status_code(after_http: &str) -> Option<i32> {
    // After "HTTP/" the layout is "<version> <code> <reason>"; the code is the
    // second whitespace-delimited token.
    let mut parts = after_http.split_whitespace();
    let _version = parts.next()?;
    parts.next()?.parse::<i32>().ok()
}

/// Parse the wire HTTP version from the portion of an HTTP status line that
/// follows `HTTP/`, returning curl's `k->httpversion` integer encoding
/// (`<major> * 10 + <minor>`): `"1.0 401 …"` → `Some(10)`, `"1.1 200 OK"` →
/// `Some(11)`, `"2 200"` → `Some(20)`. The version token is the first
/// whitespace-delimited field; a missing minor defaults to `0` (so `"2"` →
/// `20`). Returns `None` for a malformed token, in which case the caller leaves
/// the running version unchanged.
fn parse_status_version(after_http: &str) -> Option<u8> {
    let token = after_http.split_whitespace().next()?;
    let mut nums = token.split('.');
    let major: u32 = nums.next()?.parse().ok()?;
    let minor: u32 = nums.next().and_then(|m| m.parse().ok()).unwrap_or(0);
    u8::try_from(major.checked_mul(10)?.checked_add(minor)?).ok()
}

/// How a hop's response body is routed to the application sink, decided once
/// (memoized) when the first body byte arrives — by then the status line and all
/// headers have been observed.
///
/// * [`Forward`](BodyDisposition::Forward) — write through to the application
///   (the normal terminal case).
/// * [`Discard`](BodyDisposition::Discard) — drop silently: a `3xx` body that
///   `-L` will follow (curl discards intermediate redirect bodies).
/// * [`BufferAuth`](BodyDisposition::BufferAuth) — buffer a `401`/`407` body
///   *during auth negotiation* so it can be either discarded (if the request is
///   re-issued with credentials) or flushed (if the challenge is terminal and
///   the error page is the real answer). This reproduces curl's behavior of
///   suppressing intermediate auth-probe bodies while still delivering the body
///   of a final, unanswerable `401`/`407`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyDisposition {
    Forward,
    Discard,
    BufferAuth,
}

/// A [`WriteCallbacks`] decorator wrapping the application's sink for one hop.
///
/// It transparently forwards every header line and (final-hop) body byte to the
/// inner sink, while *observing* the bytes to capture the status code and the
/// orchestration-relevant headers (`Location`, `Set-Cookie`,
/// `Strict-Transport-Security`, `Alt-Svc`, `WWW-Authenticate`). When the hop is
/// a redirect that will be followed (`follow_enabled && 3xx && Location
/// present`), the response body is *suppressed* (not forwarded), so only the
/// final response's body reaches the application — matching curl's `-L` behavior
/// of discarding intermediate `3xx` bodies. During HTTP auth negotiation a
/// `401`/`407` body is *buffered* (see [`BodyDisposition`]). Headers are always
/// forwarded (so `-i`/`-D` observe every hop, as curl does).
struct HopSink<'s> {
    /// The application's real sink (body + header callbacks).
    inner: &'s mut dyn WriteCallbacks,
    /// Whether redirect following is enabled (gates body suppression).
    follow_enabled: bool,
    /// The most recent status code parsed from a `HTTP/...` status line.
    status: i32,
    /// The wire HTTP version parsed from the most recent `HTTP/...` status line,
    /// encoded as curl's `k->httpversion` integer (`10` = HTTP/1.0, `11` =
    /// HTTP/1.1, `20` = HTTP/2, `30` = HTTP/3); `0` until a status line is seen.
    /// Read by the auth/redirect loop immediately after each exchange to fold
    /// into the transfer's `rcvd_min` (curl's `data->state.http_neg.rcvd_min`),
    /// which downgrades a later HTTP/1.1 request to HTTP/1.0 once a `1.0` reply
    /// has been observed (`http_may_use_1_1`). `data.info.http_version` is *not*
    /// usable for this because it is published only at transfer finalize, after
    /// this loop has already chosen the resend's version.
    version: u8,
    /// The `Location` header value seen in the current response block.
    location: Option<String>,
    /// Captured `Set-Cookie` header values (for the cookie engine).
    #[cfg(feature = "cookies")]
    set_cookies: Vec<String>,
    /// The last captured `Strict-Transport-Security` header value (HSTS engine).
    #[cfg(feature = "hsts")]
    sts: Option<String>,
    /// The last captured `Alt-Svc` header value (alt-svc cache).
    #[cfg(feature = "alt-svc")]
    alt_svc: Option<String>,
    /// The raw `name: value` header lines (with their CRLF terminators) of the
    /// current response block, for populating the libcurl `HeaderCollector` after
    /// the transfer. Reset on each status line so only the final block's headers
    /// remain (curl's `curl_easy_header()` default reads the most recent request).
    /// The status line itself is excluded (it is not a `name: value` header).
    headers: Vec<Vec<u8>>,
    /// The current response block's `Content-Type` value (trimmed, bytes), for
    /// `CURLINFO_CONTENT_TYPE`. Reset on each status line so a redirect block's
    /// value does not leak into the final one.
    content_type: Option<Vec<u8>>,
    /// The parsed `Retry-After` value in seconds-from-now for
    /// `CURLINFO_RETRY_AFTER` (curl's `data->info.retry_after`), or `None` when
    /// the response carried no `Retry-After` header. Flushed to `data.info` at
    /// the end of the hop; consulted by the CLI `--retry-max-time` budget check
    /// (`retrycheck`) so a too-distant server back-off skips the retry (oracle
    /// test366).
    retry_after: Option<i64>,
    /// The `WWW-Authenticate` (host) / `Proxy-Authenticate` (proxy) challenge
    /// values from the current response block, in order, for the auth controller
    /// to parse on a `401`/`407`. Reset on each status line so only the current
    /// block's challenges are considered (curl's `Curl_http_input_auth` per
    /// response).
    www_authenticate: Vec<String>,
    /// Whether this hop is part of an HTTP auth negotiation (a controller is
    /// active). When set, a `401`/`407` body is buffered rather than forwarded
    /// (see [`BodyDisposition::BufferAuth`]).
    auth_negotiating: bool,
    /// Whether THIS attempt is a body-bearing auth-negotiation probe (the loop's
    /// `authneg` is set AND the method is a body-bearing `POST`/`PUT`). When set
    /// and the probe receives a non-`401` *success* (`status < 300`), curl
    /// re-issues the request with the real body (`Curl_http_auth_act`
    /// else-branch, lib/http.c L597-611) and sets `newurl`, so `http_firstwrite`
    /// ignores THIS response's body (`k->ignorebody`). The body is therefore
    /// DISCARDED (only its headers flow, verbatim under `-i`), matching curl's
    /// suppression of the intermediate auth-probe response body. Oracle: test175
    /// (Digest) and test176 (NTLM) `POST` to a server requiring no auth.
    authneg_probe: bool,
    /// The buffered body of a `401`/`407` captured under
    /// [`BodyDisposition::BufferAuth`], pending the retry/terminal decision.
    auth_body_buf: Vec<u8>,
    /// Whether the current response block's end-of-headers blank line has been
    /// observed (so subsequent body-stream writes are *real* body bytes, not
    /// `CURLOPT_HEADER` header-merge bytes). Set when [`note_header`] sees the
    /// blank line after a status line; reset when a new status line begins (1xx
    /// interim, the redirect's own block) and on [`reset_for_retry`]. This gates
    /// the body-routing decision so it is taken with the status fully known —
    /// the analog of curl deciding `k->ignorebody` once the response head is
    /// parsed, not while header bytes are still flowing onto the `-i` body stream.
    headers_complete: bool,
    /// Memoized body-routing decision (computed once the first *real* body byte
    /// arrives — i.e. after [`headers_complete`](Self::headers_complete), by
    /// which point the status line and all headers have been seen).
    disposition: Option<BodyDisposition>,
    /// The download resume offset (`CURLOPT_RESUME_FROM`, `-C <n>`) for a `GET`
    /// download, or `0` when not resuming. Set by the orchestrator after
    /// construction. Drives the server-ignored-range check (curl's
    /// `http_firstwrite`): a resumed `GET` whose response carries no
    /// `Content-Range` means the server did not honor the requested byte range.
    resume_from: i64,
    /// Whether the current response block carried a `Content-Range:` header
    /// (curl's `k->content_range`). Set in [`note_header`](Self::note_header);
    /// reset on each new status line. When a resume was requested and this is
    /// `false`, the server ignored the range.
    content_range_seen: bool,
    /// The current response block's `Content-Length` value (curl's `k->size`),
    /// or `None` when absent/unpar0seable. Used only by the resume check to
    /// detect the "entire document already downloaded" case (`size ==
    /// resume_from`), which is a success rather than a range error.
    body_size: Option<i64>,
    /// Set by the first-body-write resume check when a resumed `GET` response
    /// did not honor the range and the document is not already complete. The
    /// orchestrator surfaces this as [`CurlError::RangeError`] (`CURLE_RANGE_ERROR`,
    /// 33) after the exchange, and the body is discarded (the local file is left
    /// untouched), matching curl's `http_firstwrite` `CURLE_RANGE_ERROR` return.
    range_error: bool,
    /// The time-condition selector (`CURLOPT_TIMECONDITION`, `-z`): `0` = none,
    /// `1` = if-modified-since, `2` = if-unmodified-since. Set by the orchestrator
    /// after construction. Drives the client-side response time-condition check
    /// (curl's `http_firstwrite` / `Curl_meets_timecondition`): when set and no
    /// byte range was requested, a response whose `Last-Modified` does not satisfy
    /// the condition is delivered as a simulated `304` with the body discarded.
    timecondition: u8,
    /// The time-condition reference instant (`CURLOPT_TIMEVALUE[_LARGE]`) as a Unix
    /// timestamp, compared against the response's `Last-Modified`. Set by the
    /// orchestrator after construction.
    timevalue: i64,
    /// Whether a byte range was requested for this transfer (curl's
    /// `data->state.range`). The time-condition check is gated off when a range is
    /// present (RFC 2616 §13.3.4 — a partial request is not a plain conditional
    /// GET). Set by the orchestrator after construction.
    range_present: bool,
    /// The response document's modification instant (curl's `k->timeofdoc`), parsed
    /// from the current response block's `Last-Modified` header when a time
    /// condition is active. `0` when absent/unparseable (the condition is then
    /// treated as met, matching `Curl_meets_timecondition`). Reset on each new
    /// status line. Consulted by the first-body-write time-condition check.
    timeofdoc: i64,
    /// Set by the first-body-write time-condition check when the response did not
    /// satisfy the configured `If-Modified-Since`/`If-Unmodified-Since` condition.
    /// The orchestrator surfaces this as a simulated `304` (`data.info.timecond =
    /// true`, `response_code = 304`) with the body discarded, matching curl's
    /// `http_firstwrite` "Simulate an HTTP 304 response" path (a success, not an
    /// error).
    condition_unmet: bool,
}

impl<'s> HopSink<'s> {
    /// Wrap the application's sink, marking whether an HTTP auth negotiation is in
    /// progress. When `auth_negotiating` is set, a `401`/`407` body is buffered
    /// rather than forwarded (see [`BodyDisposition`]); otherwise it behaves as a
    /// plain forwarding/redirect-suppressing decorator.
    fn with_auth(
        inner: &'s mut dyn WriteCallbacks,
        follow_enabled: bool,
        auth_negotiating: bool,
    ) -> Self {
        HopSink {
            inner,
            follow_enabled,
            status: 0,
            version: 0,
            location: None,
            #[cfg(feature = "cookies")]
            set_cookies: Vec::new(),
            #[cfg(feature = "hsts")]
            sts: None,
            #[cfg(feature = "alt-svc")]
            alt_svc: None,
            headers: Vec::new(),
            content_type: None,
            retry_after: None,
            www_authenticate: Vec::new(),
            auth_negotiating,
            authneg_probe: false,
            auth_body_buf: Vec::new(),
            headers_complete: false,
            disposition: None,
            resume_from: 0,
            content_range_seen: false,
            body_size: None,
            range_error: false,
            timecondition: 0,
            timevalue: 0,
            range_present: false,
            timeofdoc: 0,
            condition_unmet: false,
        }
    }

    /// Observe one header line: update the status from a status line, or record
    /// the `Location` value for the redirect decision.
    fn note_header(&mut self, raw: &[u8]) {
        let Ok(s) = std::str::from_utf8(raw) else {
            return;
        };
        let line = s.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            // The end-of-headers blank line: a FINAL (`>= 200`) status's blank
            // line begins the message body. Marking the block's headers complete
            // lets the first *real* body write take the redirect/auth disposition
            // with the status fully known — and lets the `CURLOPT_HEADER`
            // header-merge writes that arrive on the body stream *before* this
            // point be forwarded verbatim (curl shows intermediate redirect
            // headers under `-i`).
            //
            // A `1xx` interim response (curl's `k->httpcode < 200`) does NOT begin
            // the body — another response always follows — so its blank line must
            // NOT mark headers complete. Otherwise the interim block's blank line
            // would latch `headers_complete` while `status` is still `1xx`, and
            // the FINAL response's status-line bytes (arriving on the body stream
            // under `-i`, before `note_header` parses them) would be taken as the
            // first "body" write with a stale `1xx` status — wrongly driving the
            // disposition (e.g. discarding the final status line during an
            // auth-negotiation probe with `Expect: 100-continue`; oracle test565).
            // A blank line before any status line (defensive) is likewise ignored.
            if self.status >= 200 {
                self.headers_complete = true;
            }
            return;
        }
        // A status line begins a (possibly new) response block. Update the status
        // and reset the per-block `Location`, captured header lines, and
        // `Content-Type` so a 1xx/redirect block's values do not leak into the
        // final one (curl's header API and `CURLINFO_CONTENT_TYPE` reflect the
        // most recent request's response block).
        if let Some(rest) = line.strip_prefix("HTTP/") {
            if let Some(code) = parse_status_code(rest) {
                self.status = code;
                // Capture the response's wire version (curl's `k->httpversion`)
                // for the transfer's `rcvd_min` downgrade. A malformed version
                // leaves the prior value untouched.
                if let Some(v) = parse_status_version(rest) {
                    self.version = v;
                }
                self.location = None;
                self.headers.clear();
                self.content_type = None;
                self.retry_after = None;
                self.www_authenticate.clear();
                // A fresh response block resets the range-resume observations
                // (curl re-evaluates `k->content_range`/`k->size` per response):
                // a redirect or 1xx block's headers must not leak into the final
                // block's server-ignored-range decision.
                self.content_range_seen = false;
                self.body_size = None;
                // A fresh response block re-evaluates the document modification
                // time (curl re-parses `Last-Modified` into `k->timeofdoc` per
                // response): a redirect or 1xx block's `Last-Modified` must not
                // leak into the final block's time-condition decision.
                self.timeofdoc = 0;
                // A fresh response block: its body boundary has not been reached
                // yet. Reset so a prior block's blank line (a 1xx interim
                // response, or the status line of the next hop arriving on a
                // kept-alive connection) does not leave headers marked complete.
                self.headers_complete = false;
            }
            return;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            // Store the raw header line (with its CRLF terminator) for the libcurl
            // `HeaderCollector` / `%header{}` write-out, and capture `Content-Type`
            // for `CURLINFO_CONTENT_TYPE`. Done for every real header (not just the
            // recognized ones below) so the store mirrors the full response block.
            self.headers.push(raw.to_vec());
            if name.eq_ignore_ascii_case("content-type") {
                self.content_type = Some(value.as_bytes().to_vec());
            }
            // Server-ignored-range observations (curl's `k->content_range` /
            // `k->size`), consulted by the first-body-write resume check. A
            // `Content-Range:` response header means the server honored the
            // requested byte range; its presence alone is what matters here, so
            // the value is not parsed. `Content-Length:` gives the response body
            // size used to detect the "already fully downloaded" case.
            if name.eq_ignore_ascii_case("content-range") {
                self.content_range_seen = true;
            } else if name.eq_ignore_ascii_case("content-length") {
                self.body_size = value.trim().parse::<i64>().ok();
            } else if name.eq_ignore_ascii_case("retry-after") {
                // Parse `Retry-After` (HTTP-date OR delay-seconds) into a
                // seconds-from-now value for `CURLINFO_RETRY_AFTER`, mirroring C
                // `http_header_r` (lib/http.c L3501-3523). curl tries a date
                // first — because a date can start with digits and otherwise be
                // mis-read as a number — then falls back to a decimal count, and
                // caps the result at 21600 (6 hours). The CLI `retrycheck`
                // reads this back via `getinfo` to honor `--retry-max-time`
                // against a server-specified back-off (oracle test366: a 503
                // with `Retry-After: 200` and `--retry-max-time 10` must NOT
                // retry, since 200s exceeds the 10s budget).
                let v = value.trim_start();
                let mut secs: i64 = 0; // zero for unknown or "now"
                let date = crate::util::parsedate::curl_getdate(v);
                if date != -1 {
                    // Parsed as a date; convert a future date to a delta.
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    if date >= now {
                        secs = date - now;
                    }
                } else if let Ok(n) = v.parse::<i64>() {
                    // Decimal delay-seconds (errors ignored, leaving `secs = 0`).
                    secs = n;
                }
                if secs > 21600 {
                    secs = 21600;
                }
                self.retry_after = Some(secs);
            }
            // The response document's modification time (curl's `http_header_l`):
            // parse `Last-Modified` into `timeofdoc` only when a time condition is
            // active, exactly as curl gates on `data->set.timecondition ||
            // data->set.get_filetime`. The first-body-write check compares it
            // against `timevalue`. An unparseable date caps to `0` (the condition
            // is then treated as met — `Curl_getdate_capped` setting `timeofdoc =
            // 0` on failure).
            if self.timecondition != 0 && name.eq_ignore_ascii_case("last-modified") {
                self.timeofdoc = crate::util::parsedate::getdate_capped(value).unwrap_or(0);
            }
            if name.eq_ignore_ascii_case("location") {
                // An empty `Location:` header is ignored — curl does not follow
                // it. The C oracle (lib/http.c, `Curl_copy_header_value` path):
                // `if(!*location || ...) { /* ignore empty header ... */ return
                // CURLE_OK; }` returns without setting `data->req.newurl`, so the
                // 3xx response is delivered as the final result instead of being
                // chased into a redirect loop. `value` is already trimmed above,
                // so a `Location:` with only whitespace is treated as empty.
                // (Regression oracle: tests/data/test54 — "HTTP with blank
                // Location:" expects exactly one request and rc=0.)
                if !value.is_empty() {
                    self.location = Some(value.to_string());
                }
            } else if name.eq_ignore_ascii_case("www-authenticate")
                || name.eq_ignore_ascii_case("proxy-authenticate")
            {
                // Collect every auth challenge in the current response block for
                // the auth controller (curl's `Curl_http_input_auth` consumes
                // each `WWW-Authenticate`/`Proxy-Authenticate` line). Multiple
                // schemes may also appear comma-separated on one line; the
                // controller's `parse_auth_header` handles that split.
                self.www_authenticate.push(value.to_string());
            } else if cfg!(feature = "cookies") && name.eq_ignore_ascii_case("set-cookie") {
                #[cfg(feature = "cookies")]
                self.set_cookies.push(value.to_string());
            } else if cfg!(feature = "hsts")
                && name.eq_ignore_ascii_case("strict-transport-security")
            {
                #[cfg(feature = "hsts")]
                {
                    self.sts = Some(value.to_string());
                }
            } else if cfg!(feature = "alt-svc") && name.eq_ignore_ascii_case("alt-svc") {
                #[cfg(feature = "alt-svc")]
                {
                    self.alt_svc = Some(value.to_string());
                }
            }
        }
    }

    /// Whether this hop's body must be suppressed because it is a redirect that
    /// will be followed.
    fn should_suppress(&self) -> bool {
        self.follow_enabled && is_redirect_status(self.status) && self.location.is_some()
    }

    /// Decide how this hop's body is routed (called once at the first body byte).
    /// A followed redirect is discarded; a `401`/`407` while an auth negotiation
    /// is active is buffered; everything else is forwarded.
    fn decide_disposition(&self) -> BodyDisposition {
        if self.should_suppress() {
            return BodyDisposition::Discard;
        }
        if self.auth_negotiating && (self.status == 401 || self.status == 407) {
            return BodyDisposition::BufferAuth;
        }
        // An auth-negotiation probe (body suppressed, `Content-Length: 0`) that
        // received a non-`401` *success* (`status < 300`) is re-issued with the
        // real body by `Curl_http_auth_act` (lib/http.c L597-611), which sets
        // `newurl`; `http_firstwrite` then ignores THIS response's body. Discard
        // it so only the second (authenticated/body-bearing) response's body
        // reaches the application — its headers already flowed under `-i`.
        // Oracle: test175 (Digest), test176 (NTLM).
        if self.authneg_probe && self.status < 300 {
            return BodyDisposition::Discard;
        }
        BodyDisposition::Forward
    }

    /// Reset the per-attempt observable state before re-issuing the request on
    /// the same connection during auth negotiation. Keeps the inner sink, the
    /// `follow_enabled`/`auth_negotiating` flags; clears the status, captured
    /// headers/challenges, and the memoized body disposition + buffer.
    fn reset_for_retry(&mut self) {
        self.status = 0;
        self.version = 0;
        self.location = None;
        self.headers.clear();
        self.content_type = None;
        self.retry_after = None;
        self.www_authenticate.clear();
        self.auth_body_buf.clear();
        self.headers_complete = false;
        self.disposition = None;
        // The configured resume offset (`resume_from`) persists across an auth
        // resend — the resumed range is re-sent on the retry — but the per-block
        // response observations and the error latch are re-evaluated.
        self.content_range_seen = false;
        self.body_size = None;
        self.range_error = false;
        // The configured time condition (`timecondition`/`timevalue`/
        // `range_present`) likewise persists across an auth resend, while the
        // per-response `Last-Modified` observation and the unmet latch are
        // re-evaluated on the retry's response.
        self.timeofdoc = 0;
        self.condition_unmet = false;
        #[cfg(feature = "cookies")]
        self.set_cookies.clear();
        #[cfg(feature = "hsts")]
        {
            self.sts = None;
        }
        #[cfg(feature = "alt-svc")]
        {
            self.alt_svc = None;
        }
    }

    /// Set whether THIS attempt is a body-bearing auth-negotiation probe — see
    /// [`authneg_probe`](Self::authneg_probe). Called per attempt before driving
    /// the exchange, from the loop's `authneg` state and the request method.
    fn set_authneg_probe(&mut self, v: bool) {
        self.authneg_probe = v;
    }

    /// Discard any buffered auth-probe body (the request is being re-issued with
    /// credentials, so the intermediate `401`/`407` error page is not delivered).
    fn discard_auth_body(&mut self) {
        self.auth_body_buf.clear();
    }

    /// Flush a buffered auth body to the application sink — used when a
    /// `401`/`407` turns out to be terminal (the challenge could not be answered),
    /// so curl delivers the server's error page as the real response body.
    fn flush_auth_body(&mut self) {
        if self.auth_body_buf.is_empty() {
            return;
        }
        let buf = std::mem::take(&mut self.auth_body_buf);
        let mut off = 0;
        while off < buf.len() {
            let n = self.inner.write_body(&buf[off..]);
            if n == 0 {
                break;
            }
            off += n;
        }
    }
}

impl WriteCallbacks for HopSink<'_> {
    fn write_body(&mut self, data: &[u8]) -> usize {
        // Before the end-of-headers blank line, any bytes arriving on the body
        // stream are `CURLOPT_HEADER` (`-i`) header-merge bytes that `CwOut`
        // routes to the body callback *before* delivering them on the header
        // callback (so `note_header` has not yet parsed the status line). They
        // are header content, not body — forward them verbatim and do NOT let
        // them drive or prematurely memoize the body disposition. This is the
        // analog of curl gating only true `CLIENTWRITE_BODY` writes with
        // `k->ignorebody`: intermediate redirect *headers* always flow under
        // `-i`, while the intermediate *body* is suppressed below. Without `-i`
        // no body-stream write occurs until the body, so this branch is inert.
        if !self.headers_complete {
            return self.inner.write_body(data);
        }
        let disposition = match self.disposition {
            Some(d) => d,
            None => {
                // Server-ignored-range check — the port of curl's
                // `http_firstwrite` (lib/http.c), taken at the first real body
                // byte (the only point where the response head — status,
                // `Content-Range`, `Content-Length` — is fully known but no body
                // has yet been written to the client). It applies only to a
                // response that would otherwise be *forwarded* to the client: a
                // followed-redirect body (Discard) or a buffered `401`/`407`
                // auth-probe body (BufferAuth) is not the resumed transfer's real
                // payload, and curl evaluates the resume failure only on the
                // final delivered response (`!k->ignorebody`). A resumed `GET`
                // (`resume_from > 0`, only ever set for `GET` by the orchestrator)
                // whose forwarded response carries no `Content-Range` means the
                // server did not honor the requested byte range. If the response
                // body size equals the resume point the document is already fully
                // downloaded (a success — discard the redundant re-sent body and
                // keep the local file); otherwise the range was not delivered and
                // the transfer must fail with `CURLE_RANGE_ERROR` (33). In both
                // cases the body is discarded so the local output file is left
                // untouched, exactly as curl aborts before `Curl_client_write`.
                let base = self.decide_disposition();
                let d = if matches!(base, BodyDisposition::Forward)
                    && self.resume_from > 0
                    && self.status == 416
                {
                    // A `416 Range Not Satisfiable` answer to a resumed `GET`
                    // (`resume_from > 0`, only ever set for `GET`) is curl's
                    // "the file is presumably already completely downloaded"
                    // case (`lib/http.c` `http_firstwrite`:
                    // `if(state.resume_from && httpreq == GET && httpcode == 416)
                    //   k->ignorebody = TRUE;`). The body is DISCARDED to avoid
                    // appending the server's error page to the already-complete
                    // local file, and this is a SUCCESS (`CURLE_OK`) — NOT a
                    // range error — so `range_error` is left unset. This check
                    // must precede the no-`Content-Range` branch below because a
                    // `416` typically *does* carry a `Content-Range: bytes */N`
                    // header (so `content_range_seen` is true), which would
                    // otherwise skip the discard and forward the error body.
                    // (Regression oracle: tests/data/test92, test194.)
                    BodyDisposition::Discard
                } else if matches!(base, BodyDisposition::Forward)
                    && self.resume_from > 0
                    && !self.content_range_seen
                {
                    if self.body_size != Some(self.resume_from) {
                        self.range_error = true;
                    }
                    BodyDisposition::Discard
                } else if matches!(base, BodyDisposition::Forward)
                    && self.timecondition != 0
                    && !self.range_present
                    && !crate::protocols::file::meets_timecondition(
                        self.timeofdoc,
                        self.timecondition,
                        self.timevalue,
                    )
                {
                    // Client-side time-condition check — the port of curl's
                    // `http_firstwrite` time-condition arm (lib/http.c), taken at
                    // the first real body byte (the response head is fully known).
                    // It runs AFTER the resume/range check, matching curl's order,
                    // and only when no byte range was requested (`!range_present`,
                    // curl's `!data->state.range`, RFC 2616 §13.3.4). A
                    // `-z`/`CURLOPT_TIMECONDITION` response whose `Last-Modified`
                    // does not satisfy the condition (e.g. an `If-Modified-Since`
                    // GET whose document is not newer than `timevalue`) is
                    // delivered as a simulated `304`: the headers already flowed
                    // (verbatim under `-i`, before `headers_complete`) but the body
                    // is discarded and the local output file is left untouched. The
                    // orchestrator surfaces `condition_unmet` as `info.timecond =
                    // true` + `response_code = 304`. Unlike the range error this is
                    // a SUCCESS (`CURLE_OK`), so `range_error` stays unset and the
                    // `Discard` arm pretends the bytes were consumed.
                    self.condition_unmet = true;
                    BodyDisposition::Discard
                } else {
                    base
                };
                self.disposition = Some(d);
                d
            }
        };
        match disposition {
            // Pretend the bytes were consumed so the transfer driver does not
            // treat the discard/buffer as a short write — EXCEPT on a resumed
            // range failure, where curl's `http_firstwrite` returns the error at
            // the first body byte rather than draining the rest of the response.
            // Signal a short write (return 0) so `drive_transfer` aborts the read
            // loop AT ONCE instead of waiting for a close-delimited HTTP/1.0 body
            // to end (which the server need not do promptly — that wait was the
            // observed timeout). The orchestrator translates the latched
            // `range_error` into `CURLE_RANGE_ERROR` (33). The
            // already-fully-downloaded case (`range_error` unset) still returns
            // `data.len()`; its response is `Content-Length`-delimited, so the
            // drain terminates on its own.
            BodyDisposition::Discard => {
                if self.range_error {
                    0
                } else {
                    data.len()
                }
            }
            BodyDisposition::BufferAuth => {
                self.auth_body_buf.extend_from_slice(data);
                data.len()
            }
            BodyDisposition::Forward => self.inner.write_body(data),
        }
    }

    fn write_header(&mut self, data: &[u8]) -> Option<usize> {
        self.note_header(data);
        self.inner.write_header(data)
    }

    // The trace, progress, and diagnostic channels are per-transfer concerns the
    // redirect decorator does not interpret — forward them verbatim to the
    // application sink so every hop's verbose trace, progress meter, and
    // diagnostic output reach the front-end unchanged.
    fn debug(&mut self, infotype: crate::transfer::DebugInfoType, data: &[u8]) {
        self.inner.debug(infotype, data);
    }

    fn progress(&mut self, dltotal: i64, dlnow: i64, ultotal: i64, ulnow: i64) -> i32 {
        self.inner.progress(dltotal, dlnow, ultotal, ulnow)
    }

    fn write_diag(&mut self, bytes: &[u8]) {
        self.inner.write_diag(bytes);
    }

    fn ignorebody(&self) -> bool {
        // curl's `data->req.ignorebody`: an intermediate response whose body the
        // engine does not deliver to the application — a followed redirect
        // (`Discard`) or a buffered `401`/`407` auth-probe (`BufferAuth`). The
        // download-side file-size cap is suppressed for such bodies (see the
        // trait doc / `cw_download_write`'s `!ignorebody` gate). A response that
        // would be forwarded reports `false`. This is a pure read of the
        // already-parsed status; it does not memoize the disposition (which is
        // settled at the first real body byte, possibly downgrading a `Forward`
        // base to `Discard` for the resume/time-condition cases — orthogonal to
        // the redirect/auth ignore-body classification curl uses here).
        !matches!(self.decide_disposition(), BodyDisposition::Forward)
    }
}

/// Derive the `(scheme, is_https, host, port)` request parts from a parsed URL,
/// applying curl's defaults (lowercased scheme, IPv6-bracket stripping for the
/// host identity, and the scheme's default port when none is present). Shared by
/// the HTTP/3 branch, the redirect orchestrator, and [`perform_http_hop`] so the
/// derivation never drifts between them.
///
/// # Errors
///
/// [`CurlError::UrlMalformat`] when the URL has no host.
fn http_url_parts(url: &CurlUrl) -> Result<(String, bool, String, u16)> {
    let scheme = url
        .get(CurlUPart::Scheme, 0)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let is_https = scheme.eq_ignore_ascii_case("https");
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
    // Query the port with `CURLU_DEFAULT_PORT` so a scheme-less URL resolves to
    // the SCHEME's own default (`get_scheme().defport`): 80/`http`, 443/`https`,
    // and — for an `ftp://` URL driven AS HTTP over a forward proxy (the
    // PROTOPT_PROXY_AS_HTTP swap) — 21/`ftp`. curl keys the `Host:` default-port
    // suppression off the GIVEN scheme (`lib/http.c` L2051-2068: only
    // `(HTTPS && 443)` and `(HTTP && 80)` are omitted), so an `ftp` origin must
    // report 21 here to emit `Host: host:21` (tests 208/299/549/550/561). The
    // `is_https`-based fallback only triggers for a scheme `get_scheme` does not
    // recognize. For `http`/`https` this is identical to the previous query (the
    // default already equalled 80/443), so direct HTTP(S) behavior is unchanged.
    let port = url
        .get(CurlUPart::Port, CURLU_DEFAULT_PORT)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(default_port);
    Ok((scheme, is_https, host, port))
}

/// Cookie-engine glue for the HTTP transfer orchestrator (curl's cookie
/// integration across `lib/http.c` and `lib/cookie.c`). Compiled only with the
/// `cookies` feature (curl's `CURL_DISABLE_COOKIES` gate); when it is absent the
/// orchestrator falls back to sending the inline `CURLOPT_COOKIE` value verbatim.
#[cfg(feature = "cookies")]
mod cookie_engine {
    use super::{CurlUrl, Easy, StrId};
    use crate::cookie::{now_unix, CookieJar};
    use crate::error::Result;
    use std::sync::{Arc, Mutex};

    /// A reference-counted handle to the live cookie jar (shared or per-handle).
    pub(super) type JarHandle = Arc<Mutex<CookieJar>>;

    /// Whether the cookie engine is active for this handle: a cookie file was
    /// supplied (`-b`, including curl's empty-string "enable the engine" idiom)
    /// or a cookie jar / non-verb cookielist was set (`-c`). Mirrors curl's
    /// `data->cookies` being non-NULL after `Curl_cookie_init`.
    pub(super) fn active(data: &Easy) -> bool {
        !data.set.cookiefiles.is_empty() || data.set.cookie_engine
    }

    /// Begin the engine: resolve the jar (the `CURLOPT_SHARE` jar when attached,
    /// else a per-handle jar) and load every cookie file once. A missing file is
    /// tolerated and an empty name just enables the engine, exactly as curl's
    /// `Curl_cookie_init` does. Returns the jar to use, or `None` when inactive.
    pub(super) fn begin(data: &mut Easy) -> Option<JarHandle> {
        if !active(data) {
            return None;
        }
        let jar = data.cookie_jar_handle();
        let newsession = data.set.cookiesession;
        let now = now_unix();
        if let Ok(mut guard) = jar.lock() {
            for file in &data.set.cookiefiles {
                // A per-line/file read failure is tolerated (curl warns and
                // continues); there is no way to report it per cookie file.
                let _ = guard.load_file(file, newsession, now);
            }
            // Mark the jar live before any `Set-Cookie` is captured. curl's
            // `Curl_cookie_init` leaves `ci->running = TRUE` whether or not a
            // cookie file was loaded; `load_file` already does this, but a
            // `-c`-only invocation (cookie jar set via `CURLOPT_COOKIEJAR` with
            // no `-b` file) never calls `load_file`, leaving the jar not-running.
            // A not-running jar treats live responses as file reads and so wrongly
            // ACCEPTS `secure`/`__Secure-` cookies received over plain HTTP and
            // mishandles `newsession` — e.g. curl test 61 stores a `secure`
            // cookie delivered over `http://`. Setting it here matches curl.
            guard.set_running(true);
        }
        Some(jar)
    }

    /// Build the `Cookie:` request-header value for `url`: the jar's matching
    /// cookies (sorted by path length, longest first) emitted **first**, then the
    /// inline `CURLOPT_COOKIE` value (if any) appended, `"; "`-separated. This
    /// mirrors curl exactly (lib/http.c L2534-2581): `Curl_cookie_getlist`
    /// emits the jar cookies, then `addcookies` (the inline `-b "name=value"`
    /// string) is appended after them with a `count ? "; " : ""` separator. With
    /// no active jar the inline value is used verbatim (the historical
    /// inline-only behavior).
    pub(super) fn request_header(
        jar: &Option<JarHandle>,
        inline: Option<&str>,
        url: &CurlUrl,
        host_override: Option<&str>,
    ) -> Option<String> {
        let Some(jar) = jar else {
            return inline.map(str::to_string);
        };
        let now = now_unix();
        let matched = jar
            .lock()
            .ok()
            .and_then(|mut j| j.match_for_url_host(url, host_override, now).ok())
            .unwrap_or_default();
        match (inline, matched.is_empty()) {
            // Jar matches first, then the inline `-b` cookies (curl's order).
            (Some(i), false) => Some(format!("{matched}; {i}")),
            (Some(i), true) => Some(i.to_string()),
            (None, false) => Some(matched),
            (None, true) => None,
        }
    }

    /// Store this hop's `Set-Cookie` response headers into the jar, scoped to the
    /// request `url` (curl's `Curl_cookie_add` per `Set-Cookie`). Public-suffix
    /// rejection and domain/path/secure scoping are enforced inside the jar.
    pub(super) fn capture(
        jar: &Option<JarHandle>,
        set_cookies: &[String],
        url: &CurlUrl,
        host_override: Option<&str>,
    ) {
        let Some(jar) = jar else {
            return;
        };
        if set_cookies.is_empty() {
            return;
        }
        let now = now_unix();
        if let Ok(mut guard) = jar.lock() {
            // Per-response cap: curl accepts at most `MAX_SET_COOKIE_AMOUNT` (50)
            // `Set-Cookie` headers per request (`data->req.setcookies`,
            // lib/cookie.c L955 rejects once the counter reaches the cap; the
            // counter is incremented only on a successful add, L1039). The
            // counter is request-scoped — reset per hop in curl's `req` — so a
            // fresh local counter per `capture` call (one per hop) matches.
            // test444: a response with 80 `Set-Cookie` headers stores only the
            // first 50 (cookie-1..cookie-50); the remainder are dropped.
            let mut setcookies: u8 = 0;
            for sc in set_cookies {
                if setcookies >= crate::cookie::MAX_SET_COOKIE_AMOUNT {
                    break;
                }
                // A malformed/blocked cookie is dropped, not fatal (curl ignores
                // a failed `Curl_cookie_add`) and does not count toward the cap
                // (curl increments `setcookies` only after a cookie is actually
                // stored — `Ok(true)`; `Ok(false)` is a no-op/rejection and
                // `Err` a parse failure, neither of which counts).
                if matches!(
                    guard.store_response_url_host(sc, url, host_override, now),
                    Ok(true)
                ) {
                    setcookies += 1;
                }
            }
        }
    }

    /// Flush the jar to the `CURLOPT_COOKIEJAR` destination at transfer end
    /// (curl's `cookie_output`, called from `Curl_cookie_cleanup`). `"-"` writes
    /// the jar to standard output. A no-op when no jar destination was set.
    ///
    /// # Errors
    ///
    /// Propagates a [`CurlError::WriteError`](crate::error::CurlError::WriteError)
    /// from the underlying save; the caller treats it as best-effort, matching
    /// curl's cleanup-time write whose failure does not fail the transfer.
    pub(super) fn end(data: &Easy, jar: &Option<JarHandle>) -> Result<()> {
        let (Some(jar), Some(dest)) = (jar, data.set.str(StrId::Cookiejar)) else {
            return Ok(());
        };
        let now = now_unix();
        let mut guard = jar.lock().map_err(|_| crate::error::CurlError::WriteError)?;
        guard.save(dest, now)
    }
}

/// HSTS-engine glue for the HTTP transfer orchestrator (curl's HSTS integration
/// across `lib/url.c` and `lib/hsts.c`). Compiled only with the `hsts` feature
/// (curl's `CURLOPT_HSTS`/`HSTS_CTRL` gate). The store is consulted *before*
/// connecting to upgrade `http://` → `https://` for a known host, and the
/// `Strict-Transport-Security` response header is recorded per hop.
#[cfg(feature = "hsts")]
mod hsts_engine {
    use super::{strip_brackets, CurlUPart, CurlUrl, Easy};
    use crate::cookie::now_unix;
    use crate::hsts::HstsStore;
    use crate::url::CURLU_URLDECODE;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    /// A reference-counted handle to the live HSTS store (shared or per-handle).
    pub(super) type StoreHandle = Arc<Mutex<HstsStore>>;

    /// Whether the HSTS engine is active: a policy file was supplied
    /// (`--hsts`/`CURLOPT_HSTS`) or the engine was explicitly enabled
    /// (`CURLOPT_HSTS_CTRL` with `CURLHSTS_ENABLE`). Mirrors curl's `data->hsts`
    /// being non-NULL.
    pub(super) fn active(data: &Easy) -> bool {
        !data.set.hstsfiles.is_empty() || data.set.hsts_enable
    }

    /// Begin the engine: resolve the store (shared via `CURLOPT_SHARE` or
    /// per-handle) and load every policy file once (a missing file is tolerated,
    /// curl's `Curl_hsts_loadfile`). Returns the store to use, or `None` when
    /// inactive.
    pub(super) fn begin(data: &mut Easy) -> Option<StoreHandle> {
        if !active(data) {
            return None;
        }
        let store = data.hsts_store_handle();
        let now = now_unix();
        if let Ok(mut guard) = store.lock() {
            for file in &data.set.hstsfiles {
                // A read failure is tolerated; the filename is still remembered
                // for the end-of-transfer save, exactly as curl does.
                let _ = guard.load_file(file, now);
            }
        }
        Some(store)
    }

    /// Before connecting, upgrade a plain-`http` URL to `https` when the host is
    /// a known HSTS host (curl's pre-connect check in `lib/url.c`). Only the
    /// scheme is rewritten: an explicit port is preserved and a default port
    /// re-resolves to 443 via the scheme, matching curl. A no-op for `https`,
    /// IP-literal hosts (the store rejects those), or unknown hosts.
    pub(super) fn maybe_upgrade(store: &Option<StoreHandle>, url: &mut CurlUrl) {
        let Some(store) = store else {
            return;
        };
        let scheme = url.get(CurlUPart::Scheme, 0).unwrap_or_default();
        if !scheme.eq_ignore_ascii_case("http") {
            return;
        }
        let host_bracketed = url.get(CurlUPart::Host, CURLU_URLDECODE).unwrap_or_default();
        if host_bracketed.is_empty() {
            return;
        }
        let host = strip_brackets(&host_bracketed);
        let now = now_unix();
        let known = store
            .lock()
            .map(|s| s.is_known(host, now))
            .unwrap_or(false);
        if known {
            // Rewrite only the scheme; `http_url_parts` re-derives the port from
            // the (kept) explicit port or the new https default (443).
            let _ = url.set(CurlUPart::Scheme, Some("https"), 0);
        }
    }

    /// Record this hop's `Strict-Transport-Security` header against `host`
    /// (curl's `Curl_hsts_parse`). The store ignores IP-literal hosts and
    /// malformed policies without error.
    pub(super) fn capture(store: &Option<StoreHandle>, host: &str, sts: Option<&str>) {
        let (Some(store), Some(sts)) = (store, sts) else {
            return;
        };
        let now = now_unix();
        if let Ok(mut guard) = store.lock() {
            let _ = guard.parse(host, sts, now);
        }
    }

    /// Persist the store to the `--hsts` file at transfer end (curl's
    /// `Curl_hsts_save`). `save(None)` writes to the filename remembered by
    /// [`begin`]'s `load_file`; a read-only store is a successful no-op. A no-op
    /// when no policy file was configured.
    ///
    /// # Errors
    ///
    /// Propagates a save I/O error; the caller treats it as best-effort, matching
    /// curl's cleanup-time write whose failure does not fail the transfer.
    pub(super) fn end(data: &Easy, store: &Option<StoreHandle>) -> Result<(), crate::error::CurlError> {
        let Some(store) = store else {
            return Ok(());
        };
        let Some(dest) = data.set.hstsfiles.first() else {
            return Ok(());
        };
        let guard = store.lock().map_err(|_| crate::error::CurlError::WriteError)?;
        guard.save(Some(Path::new(dest)))
    }
}

/// Alt-Svc-cache glue for the HTTP transfer orchestrator (curl's `lib/altsvc.c`
/// integration). Compiled only with the `alt-svc` feature (curl's `CURLOPT_ALTSVC`
/// gate). Unlike the cookie jar and HSTS store, curl keeps the Alt-Svc cache
/// per-handle (`data->asi`) rather than in the share; this engine loads the cache
/// file at transfer start, records the `Alt-Svc` response header per hop, and
/// writes the cache back at transfer end.
#[cfg(feature = "alt-svc")]
mod altsvc_engine {
    use super::{Easy, StrId};
    use crate::altsvc::{AlpnId, AltSvcCache};
    use crate::cookie::now_unix;

    /// Begin the engine: when `--alt-svc <file>` is set, build the cache and load
    /// any existing entries (curl's `Curl_altsvc_init` + load). A non-zero
    /// `CURLOPT_ALTSVC_CTRL` mask overrides the default H1|H2|H3 flags; a zero
    /// mask (the CLI default) leaves the cache's default flags in place (calling
    /// `ctrl(0)` would be rejected, matching `Curl_altsvc_ctrl`). Returns the
    /// cache to use, or `None` when no file was configured.
    pub(super) fn begin(data: &Easy) -> Option<AltSvcCache> {
        let file = data.set.str(StrId::Altsvc)?;
        // `with_file` records the filename (for the end-of-transfer save) and
        // loads existing entries; a missing file yields an empty, named cache.
        let mut cache = AltSvcCache::with_file(file).unwrap_or_else(|_| {
            let mut c = AltSvcCache::new();
            // Preserve the save target even when the initial load failed.
            let _ = c.load(file);
            c
        });
        let ctrl = data.set.altsvc_ctrl;
        if ctrl != 0 {
            let _ = cache.ctrl(ctrl);
        }
        Some(cache)
    }

    /// Record this hop's `Alt-Svc` header for the request origin `(host, port)`
    /// (curl's `Curl_altsvc_parse`). The source ALPN is HTTP/1.1 — the only
    /// version the TCP h1 path negotiates here; an `h2`/`h3` advert is still
    /// stored against its own destination ALPN by the parser. A no-op when the
    /// header is absent.
    pub(super) fn capture(
        cache: &mut Option<AltSvcCache>,
        host: &str,
        port: u16,
        alt_svc: Option<&str>,
    ) {
        let (Some(cache), Some(value)) = (cache.as_mut(), alt_svc) else {
            return;
        };
        let now = now_unix();
        // A malformed advert is ignored, not fatal (curl ignores parse failures).
        let _ = cache.parse(AlpnId::H1, host, port, value, now);
    }

    /// Persist the cache to the `--alt-svc` file at transfer end (curl's
    /// `Curl_altsvc_save`). `save(None)` writes to the filename recorded by
    /// [`begin`]; a read-only cache is a successful no-op.
    ///
    /// # Errors
    ///
    /// Propagates a save I/O error; the caller treats it as best-effort, matching
    /// curl's cleanup-time write whose failure does not fail the transfer.
    pub(super) fn end(cache: &Option<AltSvcCache>) -> Result<(), crate::error::CurlError> {
        match cache {
            Some(cache) => cache.save(None),
            None => Ok(()),
        }
    }
}

/// Host-credential resolution and preemptive HTTP **Basic** authorization for
/// the redirect orchestrator.
///
/// Mirrors curl's request-time credential seeding (`create_conn` +
/// `Curl_parsenetrc`): an explicit `-u user[:password]`
/// (`CURLOPT_USERNAME`/`CURLOPT_PASSWORD`) takes precedence, and otherwise the
/// `.netrc` file is consulted when `--netrc`/`--netrc-file`/`--netrc-optional`
/// is in effect — filling any field the URL/`-u` did not supply.
///
/// Resolved Basic credentials are emitted **preemptively** on the first request
/// and on same-host redirect hops, exactly as curl 8.x does for
/// `CURLAUTH_BASIC` (curl's Basic scheme is "ready" and needs no server
/// challenge; this is what makes `/needauth` answer `200 authed` on the first
/// request). Cross-host forwarding of the header is gated by the orchestrator on
/// `CURLOPT_UNRESTRICTED_AUTH` (`--location-trusted`).
///
/// Multi-scheme *reactive* negotiation (Digest/NTLM/Negotiate challenge parsing
/// after a `401`) is authentication *depth* — out of this checkpoint's scope
/// (F8) — so only the preemptive Basic path is wired here. The leaf scheme
/// implementations already live in [`crate::auth`].
mod auth_engine {
    use super::{CurlUPart, CurlUrl, Easy, StrId};
    use crate::auth::basic::http_basic_header;
    use crate::auth::bearer::http_bearer_header;
    use crate::auth::digest::{input_digest, output_digest, DigestData};
    use crate::auth::ntlm::{NtlmHandshake, NtlmState};
    use crate::auth::{
        build_auth_mask, parse_auth_header, pick_one_auth, AuthState, CURLAUTH_BASIC,
        CURLAUTH_BEARER, CURLAUTH_DIGEST, CURLAUTH_NEGOTIATE, CURLAUTH_NTLM,
    };
    use crate::conn::h1_proxy::ProxyConnectAuth;
    use crate::error::Result;
    use crate::netrc::{self, CurlNetrcOption};
    use crate::url::CURLU_URLDECODE;
    use std::path::Path;

    /// Resolved host credentials (curl's `data->state.aptr.user`/`passwd`).
    struct HostCreds {
        user: String,
        password: String,
        /// Whether the credentials were resolved from `.netrc` (curl's
        /// `conn->bits.netrc`). curl re-runs `override_login` for every
        /// connection, so `.netrc` is re-resolved against each hop's host; such
        /// credentials are flagged safe to send even across a redirect to a
        /// different host (the `|| conn->bits.netrc` clause of the auth-send gate
        /// at lib/http.c L821-823), whereas `-u`/URL credentials are confined to
        /// the origin host.
        from_netrc: bool,
    }

    /// Reduce a full `"[Proxy-]Authorization: <scheme> …\r\n"` header line to the
    /// bare *value* (`"<scheme> …"`) the h1 request builder expects — it adds the
    /// `Authorization` field name and the terminating CRLF itself (h1.rs:749).
    fn reduce_to_value(line: &str) -> String {
        line.strip_prefix("Authorization: ")
            .or_else(|| line.strip_prefix("Proxy-Authorization: "))
            .unwrap_or(line)
            .trim_end_matches(['\r', '\n'])
            .to_string()
    }

    /// The preemptive `Authorization` *value* for the transfer's resolved
    /// credentials, or `None` when no preemptive header applies.
    ///
    /// Only the two *challenge-free* schemes are ever sent preemptively, and only
    /// when the `CURLOPT_HTTPAUTH` mask names **exactly** that one scheme — curl's
    /// `Curl_http_output_auth` keys on `authhost.picked`, which equals the wanted
    /// mask before any challenge is seen:
    ///
    /// * `CURLOPT_HTTPAUTH == CURLAUTH_BEARER` (`--oauth2-bearer`) → emit
    ///   `Bearer <token>` (no `-u` credentials required). This is what makes
    ///   `--oauth2-bearer` work on every wire version (the F8 AUTH-2 fix; the
    ///   header is reused verbatim by HTTP/1.1, HTTP/2 and HTTP/3).
    /// * `CURLOPT_HTTPAUTH == CURLAUTH_BASIC` (the default, or `--basic`) → emit
    ///   `Basic <base64>` for the resolved credentials.
    ///
    /// Every multi-scheme mask (`--anyauth`) and every challenge-requiring scheme
    /// (`--digest`/`--ntlm`/`--negotiate`) returns `None` here and is driven
    /// reactively by [`HttpAuthController`] after the server's `401` — so
    /// `--anyauth` no longer downgrades to a preemptive Basic (the F8 AUTH-5
    /// root cause) and instead picks the strongest scheme the server offers.
    ///
    /// `host` is the *origin* host the transfer starts against — the `.netrc`
    /// machine the lookup keys on (curl resolves credentials once against the
    /// initial host, then governs cross-host forwarding separately). `url` is the
    /// origin URL, consulted for its embedded userinfo (curl's
    /// `data->state.aptr.user`/`passwd`, parsed from the URL authority) which
    /// seeds the credentials and, crucially, supplies the `.netrc` login hint.
    pub(super) fn preemptive_value(data: &Easy, host: &str, url: &CurlUrl) -> Option<String> {
        let auth = data.set.httpauth;

        // Bearer: a single-scheme `--oauth2-bearer` request. The token is sent
        // without waiting for a challenge and needs no `-u` credentials.
        if auth == CURLAUTH_BEARER {
            let token = data.set.str(StrId::Bearer)?;
            let line = http_bearer_header(token).ok()?;
            return Some(reduce_to_value(&line));
        }

        // Basic: the default scheme (or explicit `--basic`). Requires resolved
        // credentials. A multi-scheme mask (anyauth) is intentionally excluded by
        // the exact-equality test so it does not pre-send Basic.
        if auth == CURLAUTH_BASIC {
            let creds = resolve(data, host, url)?;
            let line = http_basic_header(&creds.user, &creds.password, false).ok()?;
            return Some(reduce_to_value(&line));
        }

        None
    }

    /// Whether the wanted `CURLOPT_HTTPAUTH` mask requires the reactive
    /// challenge-response controller rather than a single preemptive header.
    ///
    /// `true` when any challenge-requiring scheme (Digest, NTLM, Negotiate) is
    /// wanted, **or** more than one scheme is wanted (`--anyauth`), since the
    /// final scheme can then only be chosen after the server's `401` advertises
    /// what it supports. A single `CURLAUTH_BASIC`/`CURLAUTH_BEARER` mask is
    /// challenge-free and handled by [`preemptive_value`].
    pub(super) fn needs_reactive(want: u32) -> bool {
        const REACTIVE: u32 = CURLAUTH_DIGEST | CURLAUTH_NTLM | CURLAUTH_NEGOTIATE;
        let scheme_bits = want & (CURLAUTH_BASIC | CURLAUTH_BEARER | REACTIVE);
        (want & REACTIVE) != 0 || scheme_bits.count_ones() > 1
    }

    /// The immutable per-transfer seed for a reactive [`HttpAuthController`]:
    /// resolved credentials, the optional bearer token, and the wanted scheme
    /// mask. Deposited on each in-scope hop (cross-host-gated exactly like the
    /// preemptive `Authorization` value) so the hop driver can run the
    /// challenge-response loop on the kept-alive connection.
    #[derive(Clone)]
    pub(super) struct AuthInputs {
        pub(super) user: String,
        pub(super) password: String,
        bearer: Option<String>,
        want: u32,
    }

    /// Build the reactive-auth seed for the origin host, or `None` when reactive
    /// auth does not apply (a challenge-free single scheme, or no credentials at
    /// all to attempt with). A `--negotiate -u :` request with no usable
    /// credential returns `None`, leaving curl's existing graceful
    /// `CURLE_NOT_BUILT_IN` (already produced at `setopt` time) untouched.
    pub(super) fn resolve_auth_inputs(data: &Easy, host: &str, url: &CurlUrl) -> Option<AuthInputs> {
        let want = data.set.httpauth;
        if !needs_reactive(want) {
            return None;
        }
        let bearer = data.set.str(StrId::Bearer).map(str::to_string);
        let (user, password) = match resolve(data, host, url) {
            Some(c) => (c.user, c.password),
            None => (String::new(), String::new()),
        };
        // Need at least one credential or a bearer token to attempt anything.
        if user.is_empty() && password.is_empty() && bearer.is_none() {
            return None;
        }
        Some(AuthInputs {
            user,
            password,
            bearer,
            want,
        })
    }

    /// Build the reactive **proxy**-auth seed (curl's `data->state.authproxy`),
    /// or `None` when reactive proxy auth does not apply.
    ///
    /// The proxy analog of [`resolve_auth_inputs`]: it keys on
    /// `CURLOPT_PROXYAUTH` (`--proxy-ntlm`/`--proxy-digest`/`--proxy-anyauth`)
    /// and the proxy credentials (`CURLOPT_PROXYUSERNAME`/`CURLOPT_PROXYPASSWORD`,
    /// curl's `data->state.aptr.proxyuser`/`proxypasswd`). Unlike host auth there
    /// is **no host gating** — a forward proxy is constant across redirect hops,
    /// so the same proxy credentials apply to every hop — and **no bearer**
    /// scheme (proxies do not use `--oauth2-bearer`).
    ///
    /// Returns `None` for the challenge-free single-scheme cases (the default
    /// `CURLAUTH_BASIC`, handled preemptively by
    /// [`proxy_engine::forward_proxy_auth_value`]) and when no proxy credentials
    /// are present to attempt with. A reactive scheme drives the
    /// challenge-response loop against the proxy's `407` exactly as the host
    /// controller drives it against a `401` (tests 81, 162).
    ///
    /// `proxy_url_creds` carries the credentials embedded in the `-x` proxy URL's
    /// userinfo (curl's `proxy_info.user`/`passwd`), resolved by the caller from
    /// the parsed [`Proxy`]. The explicit `CURLOPT_PROXYUSERNAME`/`PROXYPASSWORD`
    /// (`--proxy-user`) take precedence, falling back to the URL userinfo — curl
    /// unifies both into `data->state.aptr.proxyuser`/`proxypasswd` (test 335
    /// supplies the proxy credentials only in the proxy URL). `None` when no
    /// forward proxy applies to the hop.
    #[cfg(feature = "proxy")]
    pub(super) fn resolve_proxy_auth_inputs(
        data: &Easy,
        proxy_url_creds: Option<(Option<String>, Option<String>)>,
    ) -> Option<AuthInputs> {
        let want = data.set.proxyauth;
        if !needs_reactive(want) {
            return None;
        }
        let (url_user, url_pass) = proxy_url_creds.unwrap_or((None, None));
        // `--proxy-user` (CURLOPT_PROXYUSERNAME/PROXYPASSWORD) overrides the proxy
        // URL userinfo, mirroring curl's `parse_proxy` + explicit-override order.
        let user = data
            .set
            .str(StrId::Proxyusername)
            .map(str::to_string)
            .or(url_user)
            .unwrap_or_default();
        let password = data
            .set
            .str(StrId::Proxypassword)
            .map(str::to_string)
            .or(url_pass)
            .unwrap_or_default();
        // Need at least one proxy credential to attempt anything.
        if user.is_empty() && password.is_empty() {
            return None;
        }
        Some(AuthInputs {
            user,
            password,
            bearer: None,
            want,
        })
    }

    /// A per-host HTTP authentication controller driving the challenge-response
    /// schemes (Digest, NTLM) and multi-scheme selection (`--anyauth`) across the
    /// retries of a single hop — curl's `data->state.authhost` plus the
    /// per-connection Digest/NTLM state, scoped to one connection.
    ///
    /// One instance is created per hop from [`AuthInputs`]; it is driven by
    /// [`on_challenge`](Self::on_challenge) on every `401` and produces the next
    /// request's `Authorization` value, or `None` to stop (no acceptable scheme,
    /// rejected credentials, or the multi-pass scheme completed).
    pub(super) struct HttpAuthController {
        state: AuthState,
        digest: DigestData,
        ntlm: NtlmHandshake,
        user: String,
        password: String,
        bearer: Option<String>,
        /// Whether the auth handshake is still *negotiating* — curl's
        /// `conn->bits.authneg`. While true, a POST/PUT request body is
        /// suppressed (sent as `Content-Length: 0`) so the upload payload is not
        /// transmitted before the credentials are accepted; the body rides only
        /// the final, authenticated request. Starts `true` (a reactive controller
        /// always opens with an empty-bodied probe — `--anyauth`/`--digest`/
        /// `--ntlm` send no preemptive credential) and is updated after each
        /// produced credential: a single-pass scheme (Basic/Bearer/Digest) or the
        /// NTLM Type-3 authenticate message clears it (final); the NTLM Type-1
        /// initial message keeps it set (still negotiating).
        last_authneg: bool,
    }

    impl HttpAuthController {
        /// Create a controller seeded with the wanted scheme mask and credentials.
        pub(super) fn new(inputs: AuthInputs) -> Self {
            // Seed `last_authneg` to exactly what curl computes for the FIRST
            // request via `Curl_http_output_auth` + the multipass rule
            // (lib/http.c L791-836):
            //   * `picked` is seeded to `want` (`AuthState::new`). A credential
            //     is emitted by `output_auth_headers` only when `picked` equals a
            //     SINGLE scheme bit (the C `picked == CURLAUTH_<scheme>`
            //     comparisons). A multi-bit `--anyauth` mask (`CURLAUTH_ANY`)
            //     matches no `==` branch and emits nothing.
            //   * `multipass = (a credential was emitted) && !done`; for a
            //     PUT/POST `authneg = multipass`. Per scheme on this first
            //     request:
            //       - Basic / Bearer  : emitted, `done == TRUE`  => authneg FALSE
            //         (preemptive credential => the REAL body rides request #1)
            //       - Digest          : "emitted" but no nonce yet, `done == FALSE`
            //         => authneg TRUE  (body-less probe to fetch the nonce; test 565)
            //       - NTLM            : Type-1 emitted, `done == FALSE`
            //         => authneg TRUE  (body-less probe; the Type-1 rides via
            //         `initial_header`, which re-derives `last_authneg` identically)
            //       - `--anyauth` / multi-bit / none : no credential picked yet
            //         => authneg FALSE (the REAL body rides request #1; the scheme
            //         is chosen only after observing the `401` — tests 154/1072)
            // So the opening probe is body-less ONLY for a single forced Digest or
            // NTLM scheme. For `--anyauth` and for preemptive Basic/Bearer, curl
            // sends the real body on the first request (and, for `--anyauth`,
            // resends it authenticated after the `401`).
            let want = inputs.want;
            let last_authneg = want == CURLAUTH_DIGEST || want == CURLAUTH_NTLM;
            HttpAuthController {
                state: AuthState::new(want),
                digest: DigestData::new(),
                ntlm: NtlmHandshake::new(),
                user: inputs.user,
                password: inputs.password,
                bearer: inputs.bearer,
                last_authneg,
            }
        }

        /// Process a response's `WWW-Authenticate` challenges and return the next
        /// request's `Authorization` *value*, or `None` to stop.
        ///
        /// `method` is the request verb (e.g. `"GET"`) and `target` the origin-form
        /// request target (e.g. `"/digest"`) — both needed to compute the Digest
        /// response hash (`HA2 = MD5(method:uri)`), matching the bytes actually
        /// written on the wire by the h1 builder.
        pub(super) fn on_challenge(
            &mut self,
            challenges: &[String],
            method: &str,
            target: &str,
        ) -> Option<String> {
            // (1) Fold every challenge into the auth state (ORs the advertised
            //     `avail` bits) and detect a rejected Basic/Bearer (the creds or
            //     token we already sent were refused → curl gives up).
            let mut authproblem = false;
            for value in challenges {
                let parsed = parse_auth_header(&mut self.state, value);
                authproblem |= parsed.authproblem;
            }
            if authproblem {
                return None;
            }

            // (2) Pick the single strongest acceptable scheme curl would
            //     (Negotiate > Bearer > Digest > NTLM > Basic), honoring the
            //     bearer mask. `pick_one_auth` clears `avail` afterward, exactly
            //     as curl's `pickoneauth`.
            let mask = build_auth_mask(self.bearer.is_some());
            if !pick_one_auth(&mut self.state, mask) {
                return None;
            }

            // (3) Emit the header for the picked scheme.
            self.produce_header(method, target, challenges)
        }

        /// Whether the currently picked scheme is a connection-bound handshake
        /// that has advanced past its opening message, so the *next* request must
        /// be sent on the SAME connection. Only NTLM qualifies: once the server's
        /// Type-2 challenge has been folded in (state [`NtlmState::Type2`]) the
        /// Type-3 authenticate message is only valid on the connection that
        /// carried the challenge. If that connection has been closed the
        /// negotiation cannot complete on a fresh socket — curl fails the request
        /// rather than silently restarting it. A *not-yet-started* NTLM exchange
        /// (state [`NtlmState::None`]/[`NtlmState::Type1`], i.e. the Type-1
        /// (re)start) is stateless and may freely reconnect, as may the stateless
        /// Digest/Basic/Bearer schemes (`--anyauth`).
        pub(super) fn requires_same_connection(&self) -> bool {
            self.state.picked == CURLAUTH_NTLM
                && matches!(self.ntlm.state(), NtlmState::Type2 | NtlmState::Type3)
        }

        /// Whether the picked scheme is a connection-bound handshake that has now
        /// COMPLETED, leaving the peer authenticated for the lifetime of the
        /// current connection. Only NTLM qualifies, and only once the Type-3
        /// authenticate message has been produced (state [`NtlmState::Type3`]):
        /// curl's `Curl_output_ntlm` returns WITHOUT emitting a header once
        /// `ntlm->state == NTLMSTATE_TYPE3`, because the connection itself is
        /// authenticated and repeating the Type-3 on every subsequent request
        /// over the same socket is both unnecessary and wire-incorrect (tests
        /// 169, 170). The stateless schemes (Basic/Digest/Bearer) are re-sent on
        /// every request and therefore never report as connection-authenticated.
        pub(super) fn connection_authenticated(&self) -> bool {
            self.state.picked == CURLAUTH_NTLM && matches!(self.ntlm.state(), NtlmState::Type3)
        }

        /// Whether the auth handshake is still negotiating (curl's
        /// `conn->bits.authneg`). The request body of a POST/PUT is suppressed
        /// while this is true — see [`last_authneg`](Self::last_authneg). The
        /// initial probe (before any challenge) negotiates; after a challenge it
        /// reflects whether the just-produced credential was the scheme's final
        /// message.
        pub(super) fn is_negotiating(&self) -> bool {
            self.last_authneg
        }

        /// Produce the FIRST request's `Authorization` value for a single reactive
        /// scheme that opens its handshake WITHOUT a server challenge — curl's
        /// preemptive first message. curl pre-picks the sole wanted scheme
        /// (`authhost->picked == authhost->want`, a single bit) and, for NTLM,
        /// emits the challenge-free Type-1 message on the very first request
        /// (`--ntlm`), rather than waiting for a `401`. Digest must wait for the
        /// server's nonce, and a multi-scheme mask (`--anyauth`, a multi-bit
        /// `picked`) must observe the `401` before choosing — both yield `None`,
        /// leaving the first request a credential-less (and, for uploads,
        /// body-less) probe.
        ///
        /// Side effect when it returns `Some`: the NTLM handshake is advanced and
        /// [`last_authneg`](Self::last_authneg) is set from whether the produced
        /// message is final (a Type-1 opening message is still negotiating). The
        /// matching Type-2 challenge that follows is folded by
        /// [`on_challenge`](Self::on_challenge) on the `401`, which then emits the
        /// Type-3 authenticate message on the SAME connection.
        pub(super) fn initial_header(&mut self) -> Option<String> {
            // Only a single, pre-picked NTLM scheme is sent preemptively. `picked`
            // is seeded to `want` at construction, so a single `--ntlm` mask has
            // `picked == CURLAUTH_NTLM` exactly; `--anyauth` (multi-bit) and single
            // `--digest` (`CURLAUTH_DIGEST`) do not match and fall through.
            if self.state.picked == CURLAUTH_NTLM {
                // Type-1 is challenge-free: `output` with no prior server input
                // yields it (curl's `Curl_auth_create_ntlm_type1_message`).
                let out = self.ntlm.output(false, &self.user, &self.password).ok()?;
                // The Type-1 opening message is still negotiating.
                self.last_authneg = !out.done;
                return out.header.map(|line| reduce_to_value(&line));
            }
            None
        }

        /// Produce the `Authorization` value for the currently picked scheme.
        fn produce_header(
            &mut self,
            method: &str,
            target: &str,
            challenges: &[String],
        ) -> Option<String> {
            match self.state.picked {
                CURLAUTH_BASIC => {
                    let line = http_basic_header(&self.user, &self.password, false).ok()?;
                    // Basic is single-pass: the credential is final.
                    self.last_authneg = false;
                    Some(reduce_to_value(&line))
                }
                CURLAUTH_BEARER => {
                    let token = self.bearer.as_deref()?;
                    let line = http_bearer_header(token).ok()?;
                    // Bearer is single-pass: the token is final.
                    self.last_authneg = false;
                    Some(reduce_to_value(&line))
                }
                CURLAUTH_DIGEST => {
                    // Feed the Digest challenge (records the nonce; a stale-less
                    // re-challenge after a prior response errors → bad creds, stop).
                    self.feed_digest(challenges)?;
                    let out = output_digest(
                        &mut self.digest,
                        false,
                        self.state.iestyle,
                        method.as_bytes(),
                        target.as_bytes(),
                        self.user.as_bytes(),
                        self.password.as_bytes(),
                    )
                    .ok()?;
                    // Digest is single-pass: the response is final.
                    self.last_authneg = false;
                    out.header.map(|line| reduce_to_value(&line))
                }
                CURLAUTH_NTLM => {
                    // Advance the NTLM handshake with the server's challenge
                    // (bare `NTLM` → queue Type-1; `NTLM <type2>` → ready Type-3).
                    self.feed_ntlm(challenges)?;
                    let out = self.ntlm.output(false, &self.user, &self.password).ok()?;
                    // NTLM is multi-pass: the Type-1 initial message is still
                    // negotiating (`out.done == false`); only the Type-3
                    // authenticate message is final (`out.done == true`).
                    self.last_authneg = !out.done;
                    out.header.map(|line| reduce_to_value(&line))
                }
                // Negotiate is not built in (no SPNEGO backend) and is masked out
                // at `setopt` time; AWS SigV4 is signed elsewhere. Neither is
                // driven by this loop.
                _ => None,
            }
        }

        /// Feed the Digest challenge to the decoder. Returns `None` (stop) if the
        /// challenge is malformed or a stale-less re-challenge signals bad creds.
        fn feed_digest(&mut self, challenges: &[String]) -> Option<()> {
            for value in challenges {
                let v = value.trim_start();
                if v.len() >= 6 && v.as_bytes()[..6].eq_ignore_ascii_case(b"Digest") {
                    // `input_digest` requires the raw value to start with the
                    // `Digest` scheme token, which it does here.
                    input_digest(&mut self.digest, v.as_bytes()).ok()?;
                    return Some(());
                }
            }
            // Digest was picked but no Digest challenge is present: stop.
            None
        }

        /// Advance the NTLM handshake with the server's challenge. Returns `None`
        /// (stop) if the handshake errors (e.g. the server rejected Type-3).
        fn feed_ntlm(&mut self, challenges: &[String]) -> Option<()> {
            for value in challenges {
                let v = value.trim_start();
                if v.len() >= 4 && v.as_bytes()[..4].eq_ignore_ascii_case(b"NTLM") {
                    self.ntlm.input(v).ok()?;
                    return Some(());
                }
            }
            // NTLM was picked but no NTLM challenge present: feed a bare token to
            // (re)start the handshake from Type-1.
            self.ntlm.input("NTLM").ok()?;
            Some(())
        }
    }

    /// A [`ProxyConnectAuth`] provider that drives the reactive challenge-response
    /// proxy-auth schemes — Digest, NTLM, and the multi-scheme `--anyauth` — on
    /// the HTTP `CONNECT` request, by reusing the engine's [`HttpAuthController`].
    ///
    /// `http_connect_hop` selects this adapter (instead of the lighter
    /// [`StandardProxyAuth`](crate::conn::h1_proxy::StandardProxyAuth), which only
    /// produces proactive Basic) whenever `CURLOPT_PROXYAUTH` requests a reactive
    /// scheme — i.e. when [`resolve_proxy_auth_inputs`] yields credentials.
    ///
    /// It is the `CONNECT`-tunnel analog of `Curl_http_output_auth` driving the
    /// proxy half of the auth state inside the `cf-h1-proxy.c` CONNECT loop
    /// (`Curl_http_proxy_create_CONNECT` calls `Curl_http_output_auth(..,
    /// req->method, HTTPREQ_GET, req->authority, /*proxy*/TRUE)`):
    ///
    /// * NTLM is **proactive** — the challenge-free Type-1 message rides the
    ///   first `CONNECT` ([`HttpAuthController::initial_header`]); the `407`
    ///   Type-2 challenge is folded and the Type-3 authenticate message is sent
    ///   on the second `CONNECT` over the kept-alive connection (test 209).
    /// * Digest is **reactive** — the first `CONNECT` carries no credential; the
    ///   `407` advertises the realm/nonce, and the Digest response (computed over
    ///   the `CONNECT` method and the tunnel authority `host:port`, which is the
    ///   Digest `uri=`) rides the second `CONNECT` (test 206).
    ///
    /// The Digest `uri=` and the `HA2 = MD5("CONNECT:host:port")` target are the
    /// CONNECT authority — exactly the request-line authority produced by
    /// [`H1ProxyConfig`](crate::conn::h1_proxy::H1ProxyConfig) — so [`authority`]
    /// is seeded with the identical `host:port` string.
    pub(super) struct ConnectTunnelAuth {
        /// The reused per-connection reactive controller (Digest/NTLM/anyauth
        /// scheme selection + credential generation).
        controller: HttpAuthController,
        /// The `CONNECT` authority (`host:port`) — the Digest `uri=` value and
        /// the request target for `HA2`. Matches the request-line authority.
        authority: String,
        /// `Proxy-Authenticate` challenge values accumulated from the current
        /// `407` (fed one per [`input_challenge`](ProxyConnectAuth::input_challenge)).
        challenges: Vec<String>,
        /// The full `"Proxy-Authorization: <value>\r\n"` line to emit on the next
        /// `CONNECT`, or [`None`] to send none.
        current: Option<String>,
        /// Set once a `407` could not be answered (rejected credentials or no
        /// acceptable scheme) — curl's `authproblem`.
        authproblem: bool,
    }

    impl ConnectTunnelAuth {
        /// Build the adapter from a freshly-seeded [`HttpAuthController`] and the
        /// `CONNECT` authority. Produces the proactive opening message (NTLM
        /// Type-1) so it rides the first `CONNECT`; Digest / `--anyauth` open
        /// credential-less (`initial_header` → `None`).
        pub(super) fn new(controller: HttpAuthController, authority: String) -> Self {
            let mut me = Self {
                controller,
                authority,
                challenges: Vec::new(),
                current: None,
                authproblem: false,
            };
            if let Some(value) = me.controller.initial_header() {
                me.current = Some(format!("Proxy-Authorization: {value}\r\n"));
            }
            me
        }
    }

    impl ProxyConnectAuth for ConnectTunnelAuth {
        fn authorization(&mut self) -> Result<Option<String>> {
            Ok(self.current.clone())
        }

        fn input_challenge(&mut self, header_value: &str) -> Result<()> {
            // Accumulate the `Proxy-Authenticate` value; `act` folds the whole set
            // once the 407 response completes (matching `HttpAuthController`'s
            // challenge-list `on_challenge` contract).
            self.challenges.push(header_value.to_string());
            Ok(())
        }

        fn act(&mut self, _http_proxy_code: i32) -> Result<bool> {
            // Fold the accumulated 407 challenges and produce the next CONNECT's
            // `Proxy-Authorization` value, computed over the CONNECT method and
            // the tunnel authority (the Digest `uri=`).
            let produced =
                self.controller
                    .on_challenge(&self.challenges, "CONNECT", &self.authority);
            self.challenges.clear();
            match produced {
                Some(value) => {
                    self.current = Some(format!("Proxy-Authorization: {value}\r\n"));
                    Ok(true)
                }
                None => {
                    // No acceptable scheme / rejected credentials: stop, and mark
                    // the auth problem so the tunnel fails rather than retrying.
                    self.current = None;
                    self.authproblem = true;
                    Ok(false)
                }
            }
        }

        fn authproblem(&self) -> bool {
            self.authproblem
        }

        fn close_means_retry(&self) -> bool {
            // A reactive scheme with credentials can recover from a proxy-initiated
            // close during the 407 by reconnecting and restarting the handshake;
            // once we have given up (authproblem) a close is fatal.
            !self.authproblem
        }
    }

    /// Resolve the host credentials with curl's exact precedence (the HTTP
    /// analog of FTP's port of C `override_login`, lib/url.c L2575, plus the
    /// create_conn note at L1761-1763: "username and password set with their own
    /// options override the credentials possibly set in the URL, but netrc does
    /// not"):
    ///   1. the URL userinfo (`http://user:pass@host/`, curl's
    ///      `data->state.aptr.user`/`passwd`) seeds the credentials;
    ///   2. explicit `-u user:password` (CURLOPT_USERPWD →
    ///      `StrId::Username`/`StrId::Password`) overrides the URL userinfo on a
    ///      per-field basis (CREDS_OPTION > CREDS_URL);
    ///   3. `.netrc` (when `CURLOPT_NETRC` is enabled AND no `-u` *username* was
    ///      given AND the password is still unset) fills the remaining gaps,
    ///      keyed by the URL-provided username when one exists.
    ///
    /// Returns `None` when no source supplies a credential.
    ///
    /// The critical fix for multi-account `.netrc` files (test 478/479): the URL
    /// username must be the `.netrc` lookup hint so a host with several `machine`
    /// blocks resolves to the block whose `login` matches (curl's `override_login`
    /// sets `userp = &data->state.aptr.user` and `url_provided = TRUE` when the
    /// URL carried a username, so `Curl_parsenetrc` searches "specific" and keeps
    /// that login). Consulting only `-u` (the prior behavior) ran a "general"
    /// search and wrongly took the first block.
    fn resolve(data: &Easy, host: &str, url: &CurlUrl) -> Option<HostCreds> {
        // explicit `-u` (CURLOPT_USERNAME/PASSWORD).
        let explicit_user = data.set.str(StrId::Username).map(str::to_string);
        let explicit_pass = data.set.str(StrId::Password).map(str::to_string);

        // URL userinfo (empty userinfo is treated as absent, matching the C
        // `CURLUE_NO_USER`/`CURLUE_NO_PASSWORD` handling).
        let url_user = url
            .get(CurlUPart::User, CURLU_URLDECODE)
            .ok()
            .filter(|u| !u.is_empty());
        let url_pass = url
            .get(CurlUPart::Password, CURLU_URLDECODE)
            .ok()
            .filter(|p| !p.is_empty());

        // `CURLOPT_NETRC` mode (0=ignored / 1=optional / 2=required).
        let netrc_opt = CurlNetrcOption::from_long(i64::from(data.set.use_netrc))
            .unwrap_or(CurlNetrcOption::Ignored);

        // For `CURL_NETRC_REQUIRED` curl discards the URL-supplied credentials up
        // front so `.netrc` fully overrides them (C `override_login` L2591-2593);
        // the URL username is still kept as the `.netrc` lookup hint below.
        // Otherwise the URL userinfo is the seed.
        let (mut user, mut password) = if netrc_opt == CurlNetrcOption::Required {
            (None, None)
        } else {
            (url_user.clone(), url_pass.clone())
        };

        // `-u` overrides the URL for each field independently.
        if explicit_user.is_some() {
            user = explicit_user.clone();
        }
        if explicit_pass.is_some() {
            password = explicit_pass.clone();
        }

        // `.netrc`: consulted only when enabled AND `-u` supplied no username
        // (C `use_netrc && !STRING_USERNAME`), and only while the password is
        // still unset (C guards the lookup with `if(!*passwdp)`). The entry is
        // matched by the URL-provided username when one exists (preserved as the
        // hint even under `REQUIRED`); otherwise the first host match is taken
        // and supplies the login too.
        let mut from_netrc = false;
        if netrc_opt != CurlNetrcOption::Ignored
            && explicit_user.is_none()
            && password.is_none()
        {
            // `--netrc-file` overrides the default `~/.netrc` location.
            let file = data.set.str(StrId::NetrcFile).map(Path::new);
            let hint = url_user.as_deref();
            if let Ok(Some(entry)) = netrc::resolve(netrc_opt, file, host, hint) {
                // The host matched a `.netrc` block that yielded usable
                // credentials (curl's `NETRC_OK` → `conn->bits.netrc = TRUE`).
                from_netrc = true;
                if user.is_none() {
                    user = entry.login;
                }
                if password.is_none() {
                    password = entry.password;
                }
            }
        }

        match (user, password) {
            (None, None) => None,
            (u, p) => Some(HostCreds {
                user: u.unwrap_or_default(),
                password: p.unwrap_or_default(),
                from_netrc,
            }),
        }
    }

    /// The resolved host login (`user`, `password`) — URL userinfo overridden by
    /// `-u`, then `.netrc` — exposed so the caller can write it back onto the URL
    /// handle for an `ftp://` request driven AS HTTP over a forward proxy. This
    /// mirrors curl's `override_login` writing `data->state.aptr.user`/`passwd`
    /// onto `data->state.uh` (`curl_url_set(.., CURLUPART_USER/PASSWORD, ..)`,
    /// `lib/url.c` L2666-L2686), which is what makes the absolute proxy request-
    /// target carry `user:pass@host` (the request-target keeps userinfo for the
    /// `ftp` scheme — test 299). Returns `None` when no credentials resolve.
    pub(super) fn resolved_host_login(
        data: &Easy,
        host: &str,
        url: &CurlUrl,
    ) -> Option<(String, String)> {
        resolve(data, host, url).map(|c| (c.user, c.password))
    }

    /// The per-hop preemptive Basic header for a redirect target, restricted to
    /// `.netrc`-sourced credentials. curl re-runs `override_login` for each
    /// connection, so a redirect to a new host re-resolves `.netrc` against that
    /// host; credentials so obtained carry `conn->bits.netrc` and are therefore
    /// sent even across a host change (lib/http.c L821-823: the auth-send gate is
    /// `Curl_auth_allowed_to_host(data) || conn->bits.netrc`), unlike `-u`/URL
    /// credentials which are confined to the origin. Returns the `Authorization`
    /// value only when (a) the wanted scheme is the preemptive Basic case
    /// (matching the exact-equality test in [`preemptive_value`]) AND (b) the
    /// resolved credentials actually came from `.netrc`; `None` otherwise. This
    /// supplements (never replaces) the origin's preemptive value, which already
    /// governs the origin hop and same-host forwarding.
    pub(super) fn preemptive_netrc_value(data: &Easy, host: &str, url: &CurlUrl) -> Option<String> {
        if data.set.httpauth != CURLAUTH_BASIC {
            return None;
        }
        let creds = resolve(data, host, url)?;
        if !creds.from_netrc {
            return None;
        }
        let line = http_basic_header(&creds.user, &creds.password, false).ok()?;
        Some(reduce_to_value(&line))
    }
}

/// Proxy routing engine (F6-001): translate the easy handle's stored proxy
/// options into an effective [`ProxyConfig`], and reduce a forward HTTP proxy's
/// `Proxy-Authorization` line to the request-header value.
///
/// The connection-chain composition (dial target, SOCKS/CONNECT/HTTPS-proxy
/// filters, `conn.bits`) lives inline in [`perform_http_hop`]; this submodule
/// owns only the option→config translation and the auth-line reduction, exactly
/// mirroring the split in curl between `create_conn`'s proxy parsing
/// (`parse_proxy`/`parse_proxy_auth`) and the connection filters that act on it.
#[cfg(feature = "proxy")]
pub(crate) mod proxy_engine {
    use super::{Easy, StrId};
    use crate::error::Result;
    use crate::proxy::{CurlProxyType, Proxy, ProxyConfig};

    /// Build the [`ProxyConfig`] from `data.set` plus the environment (curl's
    /// `create_conn` → `detect_proxy`/`parse_proxy`): an explicit `CURLOPT_PROXY`
    /// wins; an explicit empty string disables the proxy and suppresses the
    /// environment fallback; only an *unset* `CURLOPT_PROXY` consults the
    /// `<scheme>_proxy`/`all_proxy` environment. `CURLOPT_PROXYTYPE` supplies the
    /// default scheme for a scheme-less host, `CURLOPT_PROXYPORT` overrides the
    /// port, and `CURLOPT_PROXYUSERNAME`/`CURLOPT_PROXYPASSWORD` overlay the
    /// credentials. The no-proxy list resolves from the option, else
    /// `NO_PROXY`/`no_proxy`.
    ///
    /// `scheme` is the request URL's scheme (`"http"`/`"https"`), used only to
    /// pick the scheme-specific proxy environment variable.
    pub(crate) fn config(data: &Easy, scheme: &str) -> Result<ProxyConfig> {
        // `CURLOPT_PROXYTYPE` is the default scheme for a scheme-less `-x` host
        // (e.g. `--socks5 host:port` sets the host in `CURLOPT_PROXY` and the
        // type here). An out-of-range value falls back to curl's default (HTTP).
        let default_type =
            CurlProxyType::from_raw(i32::from(data.set.proxytype)).unwrap_or_default();

        // CURLOPT_PROXY precedence (curl: the handle's proxy string is consulted
        // first; `detect_proxy` reads the environment only when it is `NULL`).
        let proxy = match data.set.str(StrId::Proxy) {
            // An explicit empty proxy string means "use no proxy" AND skips the
            // environment (curl: `data->set.str[STRING_PROXY]` set to "").
            Some("") => None,
            Some(spec) => Some(build_proxy(data, spec, default_type)?),
            None => match env_proxy(scheme) {
                Some(spec) => Some(build_proxy(data, &spec, default_type)?),
                None => None,
            },
        };

        // `--preproxy` (a SOCKS proxy in front of an HTTP proxy) defaults to HTTP
        // when scheme-less, exactly like `-x`; it has no environment fallback.
        let pre_proxy = match data.set.str(StrId::PreProxy) {
            Some(spec) if !spec.is_empty() => {
                Some(build_proxy(data, spec, CurlProxyType::default())?)
            }
            _ => None,
        };

        Ok(ProxyConfig {
            proxy,
            pre_proxy,
            no_proxy: crate::proxy::resolve_no_proxy(data.set.str(StrId::Noproxy)),
        })
    }

    /// Look up the proxy environment variables curl consults when no proxy was
    /// set on the handle (curl's `detect_proxy`, `lib/url.c`): the scheme-specific
    /// `<scheme>_proxy` first, then `all_proxy`. This is existing curl 8.x
    /// behavior (not a new variable) and is required for G6 environment parity —
    /// the QA `http_proxy=` variant. `http_proxy` is honored ONLY in lowercase
    /// (curl's long-standing CGI-safety rule, since `HTTP_PROXY` can be poisoned
    /// by a request header in a CGI context); every other name is tried in both
    /// cases.
    fn env_proxy(scheme: &str) -> Option<String> {
        fn nonempty(name: &str) -> Option<String> {
            std::env::var(name).ok().filter(|v| !v.is_empty())
        }
        let lc = format!("{}_proxy", scheme.to_ascii_lowercase());
        if let Some(v) = nonempty(&lc) {
            return Some(v);
        }
        // Uppercase `<SCHEME>_PROXY` — but never `HTTP_PROXY` (CGI safety).
        if !scheme.eq_ignore_ascii_case("http") {
            if let Some(v) = nonempty(&lc.to_ascii_uppercase()) {
                return Some(v);
            }
        }
        nonempty("all_proxy").or_else(|| nonempty("ALL_PROXY"))
    }

    /// Build a [`Proxy`] from a proxy spec string, applying the
    /// `CURLOPT_PROXYPORT` override and the explicit
    /// `CURLOPT_PROXYUSERNAME`/`CURLOPT_PROXYPASSWORD` overlay (curl applies these
    /// after parsing the proxy URL).
    fn build_proxy(data: &Easy, spec: &str, default_type: CurlProxyType) -> Result<Proxy> {
        let mut proxy = Proxy::parse(spec, default_type)?;

        // `CURLOPT_PROXYPORT` overrides any port carried in the proxy URL.
        if data.set.proxyport != 0 {
            proxy.port = data.set.proxyport;
        }

        // Explicit `CURLOPT_PROXYUSERNAME`/`CURLOPT_PROXYPASSWORD` override the
        // proxy URL's userinfo.
        if let Some(u) = data.set.str(StrId::Proxyusername) {
            proxy.user = Some(u.to_string());
        }
        if let Some(p) = data.set.str(StrId::Proxypassword) {
            proxy.passwd = Some(p.to_string());
        }
        Ok(proxy)
    }

    /// Reduce a forward HTTP proxy's `Proxy-Authorization` line to the *value*
    /// the request builder injects (`"Basic <base64>"`), or `None` when no proxy
    /// credentials apply. [`Proxy::proxy_auth`] returns the full header line; the
    /// h1 builder adds the field name, so the prefix and trailing CRLF are
    /// stripped here — exactly as [`auth_engine::preemptive_basic`] does for the
    /// `Authorization` header.
    pub(super) fn forward_proxy_auth_value(proxy: &Proxy, authmask: u32) -> Option<String> {
        let line = proxy.proxy_auth(authmask).ok().flatten()?;
        let value = line
            .strip_prefix("Proxy-Authorization: ")
            .unwrap_or(&line)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        Some(value)
    }
}

/// `CURLOPT_CONNECT_ONLY` for `http`/`https`: establish the connection (TCP, or
/// TLS for `https`) but send **no** request, then park the live connection on
/// the easy handle for the application's own `curl_easy_send` /
/// `curl_easy_recv`.
///
/// This is curl's CONNECT_ONLY contract for the network protocols: `Curl_connect`
/// runs the full connect (resolve → TCP → optional TLS), after which the multi
/// state machine transitions straight to `DONE` without entering the DO/PERFORM
/// phase, leaving `data->conn` live (`lib/multi.c`; `CURLOPT_CONNECT_ONLY` in
/// `lib/setopt.c`). The connection produced here carries only the transport
/// filter stack (socket, plus the rustls filter for `https`) — there is no HTTP
/// filter — so the subsequent raw `curl_easy_send`/`curl_easy_recv` operate on
/// the bare byte stream, exactly as curl's do.
///
/// The WebSocket CONNECT_ONLY path is handled separately by [`perform_ws`] (it
/// must complete the HTTP/1.1 Upgrade and install the RFC 6455 framing engine);
/// this function is the plain-socket case used by `tests/libtest/lib556` and the
/// generic "connect, then talk raw" embedding pattern.
///
/// # Errors
///
/// Any resolve, connect, or TLS error from [`connect_network_scheme`]; the URL
/// itself is validated there.
pub(crate) async fn http_connect_only(data: &mut Easy, scheme: &'static Scheme) -> Result<()> {
    // The DoH transport must be installed before any name resolution, exactly as
    // `perform_http` does, in case `--doh-url` drives the CONNECT_ONLY resolve.
    install_doh_transport_once();

    // Full connect (resolve → TCP → optional TLS), no request — the shared
    // network-scheme connector used by `perform_ws`. For `http` this is a plain
    // TCP connect; for `https` it rides implicit TLS (ALPN selects the default,
    // which a raw CONNECT_ONLY caller drives manually afterwards).
    let conn = crate::protocols::connect_network_scheme(data, scheme).await?;

    // Park the live connection on the handle; `curl_easy_send`/`curl_easy_recv`
    // now read/write its raw byte stream.
    data.attach_connect_only(conn);
    Ok(())
}

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

    // Start the transfer with no observed response version (curl initializes
    // `data->state.http_neg` per transfer). The HTTP/1.0 downgrade
    // (`http_may_use_1_1` / `rcvd_min`) accumulates within THIS transfer only;
    // a downgrade learned on a previous transfer of a reused handle must not
    // leak into this one.
    data.reset_http_rcvd_min();

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
    let mut url = if let Some(uh) = data.set.uh.clone() {
        uh
    } else {
        let url_str = data.url().ok_or(CurlError::UrlMalformat)?.to_string();
        let mut parsed = CurlUrl::new();
        // `CURLOPT_PATH_AS_IS` must preserve the literal `..`/`.` segments of the
        // *given* URL path, so the initial parse forwards `CURLU_PATH_AS_IS` when
        // it is set — exactly as C does in `lib/url.c` (the `!use_set_uh` branch
        // passes `data->set.path_as_is ? CURLU_PATH_AS_IS : 0`). Without this the
        // parser would dedotdotify the request path (e.g. `/../../NNN` → `/NNN`),
        // diverging from curl on the first request line. The relative-redirect
        // resolution still strips dot segments per RFC 3986 (the merge re-parses
        // with `CURLU_PATH_AS_IS` masked off), so a followed `Location` is
        // normalized regardless.
        let path_as_is = if data.set.path_as_is {
            CURLU_PATH_AS_IS
        } else {
            0
        };
        parsed
            .set(
                CurlUPart::Url,
                Some(&url_str),
                CURLU_GUESS_SCHEME | CURLU_DEFAULT_PORT | path_as_is,
            )
            .map_err(|_| CurlError::UrlMalformat)?;
        parsed
    };

    // `CURLOPT_PORT` (`data.set.use_port`, 0 = "use the URL/scheme default"):
    // override the target port on the ORIGINAL request URL, mirroring curl's
    // `create_conn` (lib/url.c L2542-2546: `if(data->set.use_port &&
    // data->state.allow_port) conn->remote_port = data->set.use_port`) and the
    // matching `Host:`-header override (lib/http.c L1213). It is applied exactly
    // once, to the original URL, which preserves curl's `state.allow_port`
    // semantics without a separate flag: the redirect loop below re-parses every
    // absolute `Location` from scratch, so a relative redirect inherits this
    // overridden base port (curl keeps `allow_port` TRUE for the same host) while
    // an absolute redirect carries its own port (curl clears `allow_port`). The
    // single rewrite flows to all three consumers — the connect port, the default
    // `Host:` header value, and the forward-proxy absolute request-URI — because
    // each derives from `http_url_parts(&url)` / the `CurlUrl` port component.
    if data.set.use_port != 0 {
        let _ = url.set(CurlUPart::Port, Some(&data.set.use_port.to_string()), 0);
    }

    let ipver = IpVersion::from_raw(i64::from(data.set.ipver));
    let httpwant = data.set.httpwant;

    // (2) HTTP/3 connects over QUIC (UDP), not TCP, so it branches before the
    //     TCP connect. `CURL_HTTP_VERSION_3` (30) and `_3ONLY` (31) request it.
    //     The forced-HTTP/3 path is single-shot (the redirect orchestrator wraps
    //     the TCP h1/h2 path); a `--http3` transfer that 3xx-redirects is rare
    //     and curl likewise re-negotiates per hop — parity here is the body of
    //     the final hop, which a single forced-H3 request already yields.
    #[cfg(feature = "http3")]
    if matches!(httpwant, CURL_HTTP_VERSION_3 | CURL_HTTP_VERSION_3ONLY) {
        let (_scheme, _is_https, host, port) = http_url_parts(&url)?;
        let hop = HopInputs::single_shot(data);
        // HTTP/3 has no incremental upload path; build the buffered body.
        let body = build_request_body(data, source, false)?;
        return perform_http3(data, &url, &host, port, ipver, &hop, body, sink, verbose).await;
    }
    #[cfg(not(feature = "http3"))]
    if matches!(httpwant, CURL_HTTP_VERSION_3 | CURL_HTTP_VERSION_3ONLY) {
        // Parity with `select_http_version` when HTTP/3 is compiled out.
        return Err(CurlError::NotBuiltIn);
    }

    // (3) Buffer the request body ONCE up front. It is cloned into each hop so
    //     a method-preserving redirect (307/308) can re-send it; the driver only
    //     reads the response, so `source` is consumed here exactly once.
    let base_body = build_request_body(data, source, true)?;

    // Redirect orchestration state. `-L`/`--location` is the only switch that
    // enables following (`http_follow_mode != 0`); without it the loop runs the
    // single hop and returns its body verbatim (the historical single-shot path,
    // byte-for-byte unchanged). `RedirectConfig` mirrors curl's `Curl_follow`
    // inputs so the per-status method transform and the `--max-redirs` budget
    // match curl 8.x exactly.
    let follow_enabled = data.set.http_follow_mode != 0;
    let redirect_cfg = RedirectConfig {
        maxredirs: i64::from(data.set.maxredirs),
        post_redir: PostRedir {
            post301: data.set.post301,
            post302: data.set.post302,
            post303: data.set.post303,
        },
        auto_referer: data.set.http_auto_referer,
        path_as_is: data.set.path_as_is,
        allow_auth_to_other_hosts: data.set.allow_auth_to_other_hosts,
    };
    // Protocol allow-lists enforced on a *followed* redirect, the port of C
    // `findprotocol` (`lib/url.c`) under `data->state.this_is_a_follow`: the
    // target scheme must be permitted by BOTH `CURLOPT_PROTOCOLS`
    // (`allowed_protocols`) and `CURLOPT_REDIR_PROTOCOLS` (`redir_protocols`).
    // `--proto-redir -http` clears the HTTP bit from `redir_protocols`, so an
    // `https://` → `http://` redirect must be rejected with
    // `CURLE_UNSUPPORTED_PROTOCOL`. Defaults (`CURLPROTO_ALL` /
    // `CURLPROTO_REDIR` = HTTP|HTTPS|FTP|FTPS) leave ordinary same-/cross-scheme
    // HTTP(S) redirects untouched.
    let allowed_protocols = data.set.allowed_protocols;
    let redir_protocols = data.set.redir_protocols;
    let mut redirect_state = RedirectState::default();

    // Per-hop request shape, advanced on each follow. A 301/302→GET or 303→GET
    // downgrade flips `method` to GET and clears the body; 307/308 keep both.
    let mut method = data.set.method;
    let mut no_body = data.set.opt_no_body;
    let mut referer_override: Option<String> = None;

    // Activate the cookie engine once for the whole redirect chain: resolve the
    // jar (shared via `CURLOPT_SHARE` or per-handle) and load `-b` files. The
    // handle is held across the loop so each hop emits the jar's cookies and
    // every `Set-Cookie` is captured (curl's `Curl_cookie_init`). When the
    // `cookies` feature is compiled out, the orchestrator sends only inline `-b`.
    #[cfg(feature = "cookies")]
    let cookie_jar = cookie_engine::begin(data);

    // Cookie-scoping host override: when the application supplied a custom
    // `Host:` header, curl matches and stores cookies against that hostname
    // (`data->state.aptr.cookiehost`) rather than the connection/URL host. Held
    // across the redirect chain like the jar itself; `None` when no custom
    // `Host:` was set (cookies then scope to each hop's URL host, the default).
    #[cfg(feature = "cookies")]
    let cookie_host_override: Option<String> = {
        let custom = collect_custom_headers(data);
        h1::find_custom_header_value(&custom, "Host").and_then(cookie_host_from_header_value)
    };

    // Activate the HSTS engine: resolve the store (shared or per-handle) and load
    // the `--hsts` policy file. Held across the loop so every hop's
    // `Strict-Transport-Security` is recorded and each hop's URL is upgrade-checked
    // (curl's `Curl_hsts_loadfile` + pre-connect upgrade).
    #[cfg(feature = "hsts")]
    let hsts_store = hsts_engine::begin(data);

    // Activate the Alt-Svc cache (per-handle in curl, `data->asi`): load the
    // `--alt-svc` file so advertised alternatives are recorded across the chain
    // and written back at the end.
    #[cfg(feature = "alt-svc")]
    let mut altsvc_cache = altsvc_engine::begin(data);

    // Resolve host credentials once for the whole transfer (curl seeds
    // `data->state.aptr.user`/`passwd` in `create_conn`): explicit `-u` or, when
    // enabled, `.netrc`. Basic is emitted preemptively (curl's default scheme)
    // against the *origin* host below; the origin host is also the gate for
    // cross-host credential forwarding on redirects (`--location-trusted`).
    let (oh_scheme, _oh_https, origin_host, oh_port) = http_url_parts(&url)?;
    let preemptive_auth = auth_engine::preemptive_value(data, &origin_host, &url);
    // Reactive-auth seed (Digest/NTLM/`--anyauth`): `None` for the challenge-free
    // single-scheme cases handled by `preemptive_auth` above.
    let reactive_auth = auth_engine::resolve_auth_inputs(data, &origin_host, &url);

    // curl's `override_login` writes the resolved login back onto the URL handle
    // (`curl_url_set(data->state.uh, CURLUPART_USER/PASSWORD, …, CURLU_URLENCODE)`,
    // `lib/url.c` L2666-L2686). For an `ftp://` URL driven AS HTTP over a forward
    // proxy this is what makes the absolute request-target carry
    // `user:pass@host` — `-u`/`.netrc` credentials that are not already embedded
    // in the URL are reflected in the proxied FTP `GET` (test 299). It runs
    // AFTER the Basic/reactive auth above is resolved (those read `-u` directly,
    // so they are unaffected), and is scoped to the `ftp` scheme so the
    // `http`/`https` request line — which never shows userinfo (the proxy
    // request-target clears it for `http`, and the direct request line is
    // origin-form) — is byte-for-byte unchanged. When the URL already carried the
    // login this is an idempotent rewrite.
    if oh_scheme.eq_ignore_ascii_case("ftp") {
        if let Some((u, p)) = auth_engine::resolved_host_login(data, &origin_host, &url) {
            if !u.is_empty() {
                let _ = url.set(CurlUPart::User, Some(&u), CURLU_URLENCODE);
            }
            if !p.is_empty() {
                let _ = url.set(CurlUPart::Password, Some(&p), CURLU_URLENCODE);
            }
        }
    }

    let final_result: Result<()> = loop {
        // Before connecting, upgrade `http`→`https` for an HSTS-known host (curl
        // applies this on every URL parse, including redirect targets).
        #[cfg(feature = "hsts")]
        hsts_engine::maybe_upgrade(&hsts_store, &mut url);

        // Facts about the *current* hop's URL drive the redirect/auth decision
        // (the same derivation the hop helper performs for its connect) and the
        // origin for recorded HSTS/Alt-Svc policies.
        let (cur_scheme, _cur_is_https, cur_host, cur_port) = http_url_parts(&url)?;

        // A GET/HEAD never carries the buffered upload body; a preserved POST/PUT
        // (307/308) re-sends a clone of it.
        let body = match method {
            HttpReq::Post | HttpReq::PostForm | HttpReq::PostMime | HttpReq::Put => {
                base_body.clone()
            }
            HttpReq::Get | HttpReq::Head => h1::RequestBody::None,
        };

        // Credentials may be sent to this hop only when its URL shares the SAME
        // origin as the first request — identical scheme, host, AND port — or
        // when `--location-trusted` (`CURLOPT_UNRESTRICTED_AUTH`) permits keeping
        // them across origins. curl compares all three components (the
        // CVE-2022-27774 hardening): a different port or scheme is a different
        // origin and MUST strip credentials, so matching on host alone would leak
        // credentials to a same-host / different-port (or scheme-changed) redirect
        // target. This single decision governs BOTH the preemptive `Authorization`
        // value and the reactive-auth seed, so a redirect to a different origin
        // strips both unless explicitly trusted — preserving the F8 "auth across
        // redirects" PASS and matching reference curl 8.x exactly.
        let auth_allowed_this_host = (cur_host.eq_ignore_ascii_case(&origin_host)
            && cur_port == oh_port
            && cur_scheme.eq_ignore_ascii_case(&oh_scheme))
            || redirect_cfg.allow_auth_to_other_hosts;

        // Whether to suppress the application's custom `Host:` header on this hop.
        // curl keeps the custom `Host:` only for the original request and for a
        // redirect whose target host matches the *first* request's host
        // (lib/http.c: custom value used IFF `!this_is_a_follow ||
        // curl_strequal(first_host, conn->host.name)`); a cross-host redirect emits
        // the auto `Host:` for the new host instead. `followlocation > 0` marks a
        // follow hop (incremented in `follow` after each redirect), and the host
        // comparison is case-insensitive like curl's `curl_strequal` (tests
        // 184/185). The `Host:` line is stripped from `custom_headers` in
        // `perform_http_hop` when this is set.
        let suppress_custom_host =
            redirect_state.followlocation > 0 && !cur_host.eq_ignore_ascii_case(&origin_host);

        let hop_inputs = HopInputs {
            method,
            no_body,
            // Emit the preemptive Basic/Bearer header (the h1 builder emits
            // `Authorization` unconditionally on this value, so the cross-host
            // decision is made here).
            //
            // The origin's preemptive value governs the origin hop and same-host
            // (or `--location-trusted`) forwarding. When it is NOT allowed on this
            // hop (a cross-host redirect strips `-u`/URL credentials), curl still
            // re-runs `override_login` for the new connection and re-resolves
            // `.netrc` against the new host: such credentials carry
            // `conn->bits.netrc` and are sent even across the host change
            // (lib/http.c L821-823). So a `.netrc`-driven transfer following a
            // redirect to a different host picks up that host's `.netrc` entry
            // (tests 257/479), while a `-u`/URL credential remains confined to the
            // origin (tests 317 and the F8 auth-across-redirects behavior).
            authorization: match preemptive_auth.as_deref() {
                Some(v) if auth_allowed_this_host => Some(v.to_string()),
                _ => auth_engine::preemptive_netrc_value(data, &cur_host, &url),
            },
            // Reactive challenge-response auth (Digest/NTLM/`--anyauth`) seed,
            // gated identically. Rebuilt per hop from the resolved credentials so
            // the per-connection Digest/NTLM state starts fresh on each hop.
            auth: match &reactive_auth {
                Some(seed) if auth_allowed_this_host => Some(seed.clone()),
                _ => None,
            },
            proxy_authorization: None,
            cookie: {
                // Merge inline `CURLOPT_COOKIE` with the jar's cookies that match
                // *this hop's* URL (curl re-derives the `Cookie:` header per hop).
                #[cfg(feature = "cookies")]
                let cookie_hdr = cookie_engine::request_header(
                    &cookie_jar,
                    data.set.str(StrId::Cookie),
                    &url,
                    cookie_host_override.as_deref(),
                );
                #[cfg(not(feature = "cookies"))]
                let cookie_hdr = data.set.str(StrId::Cookie).map(str::to_string);
                cookie_hdr
            },
            referer: referer_override
                .clone()
                .or_else(|| data.set.str(StrId::SetReferer).map(str::to_string)),
            // Whether sensitive custom headers (`Authorization`, `Cookie` supplied
            // via `-H`/`CURLOPT_HTTPHEADER`) may be carried to this hop's host.
            // curl drops them on a cross-host redirect unless `--location-trusted`
            // (`Curl_auth_allowed_to_host`, lib/http.c L1827-1832 — the
            // `Authorization`/`Cookie` custom-header walk is skipped when
            // `!Curl_auth_allowed_to_host(data)`). `auth_allowed_this_host` is the
            // exact equivalent (same host+port+scheme as the first request, or
            // `allow_auth_to_other_hosts`); the `add_custom_headers` machinery
            // already strips those two headers when this is `false` (tests
            // 317/330 — custom `Authorization:`/`Cookie:` not leaked to the new
            // host, while `Proxy-Authorization` is retained for the same proxy).
            allowed_to_host: auth_allowed_this_host,
            proxy_connection_keepalive: false,
            // Populated by `http_connect_hop`'s forward-proxy branch from the
            // resolved `Proxy` (URL userinfo unified with the explicit overlay).
            proxy_user: None,
            proxy_pass: None,
            request_target_override: None,
            suppress_custom_host,
        };

        // Thread the upload source through so a streamed body is pulled
        // incrementally by the codec. A reborrow per iteration keeps `source`
        // available; only a single-pass (streamed) hop actually consumes it, and
        // the streaming gate guarantees the redirect loop runs a single hop.
        let hop = match perform_http_hop(
            data,
            &url,
            hop_inputs,
            body,
            follow_enabled,
            sink,
            Some(&mut *source),
        )
        .await
        {
            Ok(hop) => hop,
            Err(err) => break Err(err),
        };

        // Store this hop's `Set-Cookie`s against the URL the request was sent to,
        // before a redirect reassigns `url` (curl captures per hop so a cookie set
        // on a 3xx is sent on the followed request).
        #[cfg(feature = "cookies")]
        cookie_engine::capture(
            &cookie_jar,
            &hop.set_cookies,
            &url,
            cookie_host_override.as_deref(),
        );

        // Record this hop's HSTS policy and Alt-Svc advert against the origin the
        // request was sent to (`cur_host`/`cur_port`), before a redirect advances
        // `url` — matching curl's per-response `Curl_hsts_parse`/`Curl_altsvc_parse`.
        #[cfg(feature = "hsts")]
        hsts_engine::capture(&hsts_store, &cur_host, hop.sts.as_deref());
        #[cfg(feature = "alt-svc")]
        altsvc_engine::capture(&mut altsvc_cache, &cur_host, cur_port, hop.alt_svc.as_deref());
        // `cur_host` feeds only the HSTS/Alt-Svc origin; discard it when neither
        // engine is compiled in so the binding is not flagged unused.
        #[cfg(not(any(feature = "hsts", feature = "alt-svc")))]
        let _ = &cur_host;

        // Follow a 3xx that carries a `Location`, when `-L` is in effect.
        if follow_enabled && is_redirect_status(hop.status) {
            if let Some(loc) = hop.location.as_deref() {
                let freq = FollowRequest {
                    base: &url,
                    newurl: loc,
                    ftype: FollowType::Redir,
                    status: hop.status,
                    method: http_method_of(method),
                };
                let auth_ctx = RedirectAuthContext {
                    allow_auth_to_other_hosts: redirect_cfg.allow_auth_to_other_hosts,
                    use_port: None,
                    conn_remote_port: i32::from(cur_port),
                    conn_scheme: &cur_scheme,
                };
                match follow(&freq, &redirect_cfg, &mut redirect_state, &auth_ctx) {
                    Ok(FollowOutcome::Follow(fr)) => {
                        // Own the result on the stack so the individual fields can
                        // be moved out without partial-move-from-`Box` concerns.
                        let fr = *fr;
                        url = fr.url;
                        if fr.switched_to_get {
                            method = HttpReq::Get;
                            no_body = false;
                        }
                        referer_override = fr.referer;
                        data.info.redirect_count = redirect_state.followlocation;
                        // Enforce `--proto-redir` / `--proto` on the followed
                        // target (C `findprotocol` under `this_is_a_follow`).
                        // Abort with `CURLE_UNSUPPORTED_PROTOCOL` before the next
                        // request is sent, so no connection to a denied scheme is
                        // ever made.
                        let new_scheme = url
                            .get(CurlUPart::Scheme, 0)
                            .map(|s| s.to_ascii_lowercase())
                            .unwrap_or_default();
                        if !redirect_protocol_allowed(
                            &new_scheme,
                            allowed_protocols,
                            redir_protocols,
                        ) {
                            break Err(CurlError::UnsupportedProtocol);
                        }
                        continue;
                    }
                    Ok(FollowOutcome::TooManyRedirects { would_redirect }) => {
                        data.info.redirect_url = CString::new(would_redirect).ok();
                        break Err(CurlError::TooManyRedirects);
                    }
                    // A `Fake` follow (e.g. a redirect curl would record but not
                    // chase) ends the loop with the current hop as the result.
                    Ok(FollowOutcome::Fake { .. }) => break Ok(()),
                    Err(err) => break Err(err),
                }
            }
        }
        break Ok(());
    };

    // The effective URL is the last hop's URL (curl's `CURLINFO_EFFECTIVE_URL`).
    if let Ok(eff) = url.get(CurlUPart::Url, 0) {
        data.info.effective_url = CString::new(eff).ok();
    }

    // Flush the jar to `-c`'s destination at transfer end (curl's cleanup-time
    // `cookie_output`). A write failure is best-effort and never overrides the
    // transfer result, matching curl.
    #[cfg(feature = "cookies")]
    let _ = cookie_engine::end(data, &cookie_jar);

    // Persist the HSTS store and Alt-Svc cache to their `--hsts`/`--alt-svc`
    // files at transfer end (curl's cleanup-time `Curl_hsts_save`/
    // `Curl_altsvc_save`). Best-effort: a write failure never overrides the
    // transfer result.
    #[cfg(feature = "hsts")]
    let _ = hsts_engine::end(data, &hsts_store);
    #[cfg(feature = "alt-svc")]
    let _ = altsvc_engine::end(&altsvc_cache);

    final_result
}

/// Establish the connection for one HTTP hop: proxy routing, DNS resolution,
/// the SETUP filter chain (eyeballs → socks → ssl_proxy → http_proxy → ssl),
/// the TCP/TLS handshake, and the per-connection `data->info` / verbose-trace
/// publication. Extracted from [`perform_http_hop`] so the reactive-auth loop
/// can RE-establish a fresh connection when the server closes the socket after
/// a `401` challenge (curl reconnects and retries with the credential; e.g. the
/// `swsclose` Digest tests). `host`/`host_ace` are taken by value so the caller
/// retains its copies for the (possibly repeated) reconnect call.
#[allow(clippy::too_many_arguments)]
async fn http_connect_hop(
    data: &mut Easy,
    hop: &mut HopInputs,
    is_https: bool,
    host: String,
    host_ace: String,
    port: u16,
    verbose: bool,
    httpwant: u8,
    ipver: IpVersion,
    op_start: Instant,
    sink: &mut dyn WriteCallbacks,
) -> Result<Connection> {
    #[cfg(feature = "proxy")]
    let proxy_cfg = {
        // The request URL's scheme selects the `<scheme>_proxy` environment
        // variable. curl's `detect_proxy` (`lib/url.c`) builds the variable name
        // `"%s_proxy"` from `conn->scheme->name` — the ORIGINAL URL scheme,
        // resolved BEFORE the `PROTOPT_PROXY_AS_HTTP` handler swap. For a normal
        // `http`/`https` request this equals the `is_https` split, so behavior is
        // preserved; for an `ftp://` URL driven AS HTTP over a forward proxy (the
        // PROTOPT_PROXY_AS_HTTP swap performed by the dispatcher) the scheme is
        // `ftp`, so the `ftp_proxy` environment variable is honored (test 563).
        // `data.info.scheme` is the preflight-recorded scheme (upper-cased);
        // lower-case it for the env lookup and fall back to the `is_https` split
        // if it is somehow unset (HTTP/3 is https-only and handled separately).
        let scheme = data
            .info
            .scheme
            .as_ref()
            .and_then(|s| s.to_str().ok())
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| if is_https { "https" } else { "http" }.to_string());
        proxy_engine::config(data, &scheme)?
    };
    #[cfg(feature = "proxy")]
    let hop_proxy = crate::proxy::proxy_for_target(&proxy_cfg, &host);

    // Forward HTTP-proxy per-REQUEST headers — the Basic `Proxy-Authorization`
    // value and the `Proxy-Connection: Keep-Alive` hint — are a property of the
    // request (and the proxy configuration), NOT of the underlying connection, so
    // curl emits them on every forwarded request whether the proxy connection is
    // freshly opened or reused from the pool. They are set on `hop` HERE, before
    // the connection-reuse check below can `return` early for a kept-alive
    // connection (which would otherwise skip them on a followed same-host redirect
    // — curl tests 184/185, request 2). The connection-LEVEL proxy setup (the
    // filter chain, `conn.bits.httpproxy`/`tunnel_proxy`) stays in the
    // new-connection path further down, since a reused connection already carries
    // it. A CONNECT tunnel (an https target, or `--proxytunnel`) instead carries
    // `Proxy-Authorization` on the CONNECT request, and a SOCKS proxy negotiates
    // auth inside its handshake, so neither sets a forward-request header here.
    #[cfg(feature = "proxy")]
    if let Some(px) = hop_proxy {
        let tunnel = is_https || data.set.tunnel_thru_httpproxy;
        if !px.is_socks() && !tunnel {
            // Seed the PREEMPTIVE forward-proxy `Proxy-Authorization` (Basic) only
            // when none is already set. This block re-runs on every
            // `http_connect_hop` call — including a reactive-auth RECONNECT — so
            // an unconditional assignment would WIPE a value the proxy-auth
            // controller already negotiated (a `Proxy-Authorization: Digest`/`NTLM`
            // computed from a `407` challenge), since `forward_proxy_auth_value`
            // returns `None` for a non-Basic mask. The `is_none()` guard makes the
            // seeding idempotent: the initial connect sets Basic (or leaves `None`
            // for a reactive mask, which the controller then fills), and a later
            // reconnect preserves whatever the controller has produced (tests 168,
            // 169). A `--proxy-user` Basic value is identical on every request, so
            // never re-deriving it is also correct.
            if hop.proxy_authorization.is_none() {
                hop.proxy_authorization =
                    proxy_engine::forward_proxy_auth_value(px, data.set.proxyauth);
            }
            hop.proxy_connection_keepalive = true;
            // Record the resolved proxy credentials so the reactive proxy-auth
            // controller in `perform_http_hop` can attempt the proxy's `407`
            // (`--proxy-digest`/`--proxy-ntlm`/`--proxy-anyauth`) even when the
            // credentials live only in the proxy URL's userinfo (test 335), not in
            // `--proxy-user`. These are the unified values (`Proxy::user`/`passwd`
            // = URL userinfo overlaid by `CURLOPT_PROXYUSERNAME`/`PROXYPASSWORD`),
            // matching curl's `data->state.aptr.proxyuser`/`proxypasswd`.
            hop.proxy_user = px.user.clone();
            hop.proxy_pass = px.passwd.clone();
        }
    }

    // The dial target (where the TCP connection is opened): the proxy host:port
    // when a proxy applies, else the (possibly `--connect-to`-overridden) origin.
    // The recorded remote (`conn.remote_host`/`remote_port`, curl's `conn->host`)
    // stays the *origin* in the proxied case; a dead proxy port therefore surfaces
    // as `CURLE_COULDNT_CONNECT` (exit 7) from `establish_connection` below.
    let (dial_host, dial_port, remote_host, remote_port) = {
        #[cfg(feature = "proxy")]
        {
            match hop_proxy {
                Some(px) => (px.host.clone(), px.port, host_ace.clone(), port),
                None => {
                    let (h, p) = connect_target(data, &host, port);
                    let rh = h.clone();
                    (h, p, rh, p)
                }
            }
        }
        #[cfg(not(feature = "proxy"))]
        {
            let (h, p) = connect_target(data, &host, port);
            let rh = h.clone();
            (h, p, rh, p)
        }
    };

    // ---- Connection reuse: check out an idle keep-alive connection (Issue 3) ---
    // The scheme-aware reuse key is also stored as the connection's `destination`
    // (the pool bundle key), so check-in keys identically. A direct vs a proxied
    // route (`dial` != `remote`) and `http` vs `https` never share a connection.
    let reuse_key = format!(
        "{}|{}:{}|{}:{}",
        if is_https { "https" } else { "http" },
        dial_host,
        dial_port,
        remote_host,
        remote_port
    );
    // `CURLOPT_FRESH_CONNECT` forces a new connection; `CURLOPT_FORBID_REUSE`
    // forbids reuse in both directions. Otherwise consult the pool first.
    if !data.set.reuse_fresh && !data.set.reuse_forbid {
        let pool = data.conn_pool_handle();
        if let Some(mut reused) = crate::conn::pool_checkout(&pool, &reuse_key) {
            // Final liveness probe (curl's `Curl_conn_is_alive`): reuse only a
            // connection that is still open AND carries no unexpected pending
            // bytes — a server FIN / TLS close-notify / stray data makes a
            // supposedly-idle keep-alive socket unsafe to reuse.
            let (alive, pending) = Curl_conn_is_alive(&mut reused);
            if alive && !pending {
                // Mark the connection as pool-reused (curl's `conn->bits.reuse`).
                // This drives two reuse-specific behaviors downstream: the h1
                // codec forbids the HTTP/0.9 no-status-line fallback on a reused
                // connection, and — critically — a reused connection that the
                // peer has silently closed (the `swsclose` keep-alive race the
                // non-blocking liveness peek above can miss) is retried once on a
                // fresh connection by `Curl_retry_request` in `perform_http_hop`
                // (oracle test160). A freshly dialed connection leaves `reuse`
                // at its `false` default.
                reused.bits.reuse = true;
                // Reuse milestones: this hop performed no DNS lookup or TCP/TLS
                // connect, so name-lookup and connect times collapse to "now".
                let reuse_us =
                    Instant::now().saturating_duration_since(op_start).as_micros() as i64;
                data.info.namelookup_time_us = reuse_us;
                data.info.connect_time_us = reuse_us;
                if is_https {
                    data.info.appconnect_time_us = reuse_us;
                }
                // `-v`: match curl's exact reuse trace (lib/url.c L3540,
                // `infof "Reusing existing %s: connection%s with host %s"` where
                // `%s` is the lowercase scheme name `conn->given->name`). curl
                // omits the `* Trying`/`* Connected to` lines on reuse. The
                // `(upgraded to SSL)` middle `%s` is empty here: the reuse key
                // matches scheme, so a reused connection's TLS state already
                // matches the request (no plaintext→SSL upgrade case).
                if verbose {
                    let scheme_name = if is_https { "https" } else { "http" };
                    let line =
                        format!("Reusing existing {scheme_name}: connection with host {host}\n");
                    sink.debug(crate::transfer::DebugInfoType::Text, line.as_bytes());
                }
                // `CURLINFO_USED_PROXY` (`data->info.used_proxy`): mirror curl's
                // `create_conn` (lib/url.c:3630) which sets it from `conn->bits.proxy`
                // for EVERY transfer — including a pooled keep-alive connection that
                // was originally dialed through a proxy. curl-rs has no single
                // `bits.proxy`; the union of the HTTP- and SOCKS-proxy bits is the
                // exact equivalent (NOPROXY bypass already left both `false`).
                data.info.used_proxy =
                    i64::from(reused.bits.httpproxy || reused.bits.socksproxy);
                // Re-publish the connection-derived `data->info` IP quadruple for
                // THIS transfer over the reused connection. curl recomputes the
                // primary/local IP+port for every transfer from the (still-live)
                // connection's sockets (`Curl_conn_get_ip_quadruple` runs on each
                // do-phase, not only on a fresh connect), so `%{local_port}`,
                // `%{local_ip}`, `%{remote_ip}`, `%{remote_port}` report the
                // reused socket's endpoints rather than the unset defaults
                // (`local_port`/`primary_port` would otherwise surface as -1 and
                // the IPs empty). The fresh-connect path below sets the same
                // fields; this is the reuse-branch counterpart it skips by
                // returning early (oracle tests/data/test435). `num_connects` is
                // intentionally NOT incremented here — reuse opens no new
                // connection.
                if let Some((_is_ipv6, quad)) = Curl_conn_get_ip_info(&reused, FIRSTSOCKET) {
                    data.info.primary_ip = CString::new(quad.remote_ip).ok();
                    data.info.local_ip = CString::new(quad.local_ip).ok();
                    data.info.primary_port = i64::from(quad.remote_port);
                    data.info.local_port = i64::from(quad.local_port);
                    data.info.primary_has_ports = true;
                }
                return Ok(reused);
            }
            // Dead or unexpected pending data: `reused` is dropped here (closing
            // its socket); fall through to establish a fresh connection.
        }
    }

    let addrs = resolve_addrs(data, &dial_host, dial_port, ipver, verbose).await?;
    // CURLINFO_NAMELOOKUP_TIME milestone: name resolution for this hop is done.
    let t_resolved = Instant::now();

    // (4) Build the connection and its filter chain. The SETUP meta-filter
    //     assembles the chain in curl's canonical order:
    //     eyeballs → socks → ssl_proxy → http_proxy(CONNECT) → ssl(target).
    let desc = http_scheme_descriptor(is_https);
    // The connection's `destination` is the scheme-aware reuse key (the pool
    // bundle key), NOT a bare host:port: the actual dial target comes from the
    // resolved `addrs`/eyeballs and `set_remote`, while `destination` exists
    // solely to key connection reuse (check-in uses `conn.destination()`).
    let mut conn = Connection::new(reuse_key.clone(), TRNSPRT_TCP, desc).with_verbose(verbose);
    conn.set_remote(remote_host, remote_port);

    let ssl_mode = if is_https {
        CURL_CF_SSL_ENABLE
    } else {
        CURL_CF_SSL_DISABLE
    };
    let eyeballs = eyeballs_factory(TRNSPRT_TCP, ipver, data.set.happy_eyeballs_timeout, data.set.connecttimeout, addrs);

    // The target TLS filter (origin TLS) is installed whenever the *target* URL
    // is https, independent of any proxy in front — it rides on top of the SOCKS
    // tunnel or the HTTP CONNECT tunnel (curl adds the target `ssl` filter last).
    let target_ssl = if is_https {
        let want_h2 = cfg!(feature = "http2")
            && !matches!(httpwant, CURL_HTTP_VERSION_1_0 | CURL_HTTP_VERSION_1_1);
        let only_http_10 = httpwant == CURL_HTTP_VERSION_1_0;
        let alpn = alpn_protocols(want_h2, true, false, only_http_10, data.set.ssl_enable_alpn);
        let tls = tls_config_from_easy(data);
        // `CURLOPT_PINNEDPUBLICKEY` (`--pinnedpubkey`): the SPKI pin set the
        // target TLS filter enforces post-handshake (`tls::connect` →
        // `config::verify_pinned_pubkey`, mapping a mismatch to
        // `CURLE_SSL_PINNEDPUBKEYNOTMATCH`). This MUST be threaded through to the
        // factory — passing `None` here silently disables the pin (a fail-open
        // security-control bypass). curl enforces the pin independently of CA
        // validation, so it applies even under `--insecure`; the post-handshake
        // check in `tls::connect` runs regardless of `verify_peer`.
        let pinned_pubkey = data.set.str(StrId::SslPinnedPublicKey).map(str::to_string);
        Some(tls_factory(tls, host_ace.clone(), port, pinned_pubkey, alpn))
    } else {
        None
    };

    let mut setup = SetupConfig::new(ssl_mode, is_https, eyeballs);

    #[cfg(feature = "proxy")]
    {
        if let Some(px) = hop_proxy {
            use crate::conn::connect::{h1_proxy_factory, socks_factory, tls_proxy_factory};
            use crate::conn::h1_proxy::{H1ProxyConfig, ProxyConnectAuth, StandardProxyAuth};
            use crate::conn::socket::SocksProxyConfig;

            if px.is_socks() {
                // SOCKS4/4a/5/5h: the SOCKS filter dials the origin THROUGH the
                // proxy, so the request itself is origin-form. SOCKS auth
                // (RFC1929 user/pass, SOCKS4 userid) is negotiated inside the
                // handshake from these inputs, never as a request header.
                conn.bits.socksproxy = true;
                let socks_cfg = SocksProxyConfig {
                    httpproxy: false,
                    secondary: false,
                    conn_to_host_set: false,
                    conn_to_port_set: false,
                    proxy_host: None,
                    proxy_port: 0,
                    conn_to_host: None,
                    conn_to_port: 0,
                    secondary_host: None,
                    secondary_port: 0,
                    target_host: host_ace.clone(),
                    target_port: port,
                    proxy_user: px.user.clone(),
                    proxy_password: px.passwd.clone(),
                    proxytype: px.proxytype,
                    socks5_auth: data.set.socks5auth,
                    ip_version: ipver,
                    ipv6_ip: false,
                    verbose,
                };
                setup = setup.with_socks(socks_factory(socks_cfg));
                if let Some(ssl) = target_ssl {
                    setup = setup.with_ssl(ssl);
                }
            } else {
                // HTTP or HTTPS proxy. An HTTPS proxy speaks TLS on the proxy leg
                // first, then behaves exactly like an HTTP proxy for the target.
                if px.is_https() {
                    conn.bits.proxy_ssl = true;
                    let palpn =
                        alpn_protocols(false, true, false, false, data.set.ssl_enable_alpn);
                    let ptls = px.tls.clone().unwrap_or_else(|| tls_config_from_easy(data));
                    // `CURLOPT_PROXY_PINNEDPUBLICKEY` (`--proxy-pinnedpubkey`): the
                    // SPKI pin enforced against the HTTPS *proxy* leaf certificate
                    // (curl pins the proxy connection separately from the target).
                    // As with the target pin above, `None` here would silently
                    // disable proxy pinning.
                    let proxy_pinned_pubkey =
                        data.set.str(StrId::SslPinnedPublicKeyProxy).map(str::to_string);
                    setup = setup.with_ssl_proxy(tls_proxy_factory(
                        ptls,
                        px.host.clone(),
                        px.port,
                        proxy_pinned_pubkey,
                        palpn,
                    ));
                }

                // A CONNECT tunnel is used for an https target, or when
                // `--proxytunnel` forces it for a plain-http target; otherwise the
                // proxy forwards an absolute-URI request.
                let tunnel = is_https || data.set.tunnel_thru_httpproxy;
                conn.bits.httpproxy = true;
                conn.bits.tunnel_proxy = tunnel;

                if tunnel {
                    // Tunnel: the CONNECT carries the `Proxy-Authorization`
                    // (primed by `StandardProxyAuth`), and the target TLS rides on
                    // top once the tunnel is open. The request is origin-form.
                    let scheme = if is_https { "https" } else { "http" };
                    // The `CONNECT` request's HTTP minor version: `--proxy1.0`
                    // (`CURLPROXY_HTTP_1_0`) forces `HTTP/1.0`, every other HTTP
                    // proxy type uses `HTTP/1.1`. Oracle: `cf-h1-proxy.c`
                    // `start_CONNECT` L223 —
                    // `http_minor = (proxytype == CURLPROXY_HTTP_1_0) ? 0 : 1;`.
                    let proxy_http_minor = if px.proxytype.is_http_1_0() { 0 } else { 1 };
                    // The `User-Agent` for the `CONNECT` request comes from the
                    // same source as the main request (`STRING_USERAGENT`). The
                    // builder omits the header when the value is empty (`-A ""`)
                    // or overridden by a custom proxy header — matching curl's
                    // `Curl_http_proxy_create_CONNECT` gate
                    // (`http_proxy.c`): it adds `User-Agent` only when
                    // `data->set.str[STRING_USERAGENT]` is set *and non-empty*.
                    let proxy_user_agent = data.set.str(StrId::Useragent).map(str::to_string);
                    // Select the proxy-auth provider for the CONNECT request. A
                    // reactive scheme (`--proxy-digest`/`--proxy-ntlm`/multi-scheme
                    // `--proxy-anyauth`) drives the challenge-response handshake
                    // via the engine's `HttpAuthController` over the CONNECT
                    // method + authority; the proactive-Basic / no-auth case stays
                    // on the lighter `StandardProxyAuth`. Mirrors curl calling
                    // `Curl_http_output_auth(.., req->method, .., req->authority,
                    // TRUE)` inside `Curl_http_proxy_create_CONNECT`.
                    let proxy_auth: Box<dyn ProxyConnectAuth> =
                        match auth_engine::resolve_proxy_auth_inputs(
                            data,
                            Some((px.user.clone(), px.passwd.clone())),
                        ) {
                            Some(inputs) => {
                                let controller = auth_engine::HttpAuthController::new(inputs);
                                // The CONNECT authority — identical to the request
                                // line authority produced by `H1ProxyConfig`
                                // (Digest `uri=` / `HA2` target).
                                let authority = format!("{host_ace}:{port}");
                                Box::new(auth_engine::ConnectTunnelAuth::new(controller, authority))
                            }
                            None => Box::new(StandardProxyAuth::new(px.clone(), data.set.proxyauth)),
                        };
                    // Custom `CURLOPT_PROXYHEADER` (`--proxy-header`) lines for the
                    // CONNECT request (curl's `HEADER_CONNECT` selection). These
                    // can override the auto `Host`/`User-Agent`/`Proxy-Connection`
                    // (e.g. `--proxy-header "User-Agent: …"`, test287).
                    let proxy_custom_headers = collect_connect_custom_headers(data);
                    let h1cfg = H1ProxyConfig::new(host_ace.clone(), port)
                        .with_http_minor(proxy_http_minor)
                        .with_user_agent(proxy_user_agent)
                        .with_custom_headers(proxy_custom_headers)
                        .with_scheme(scheme, true)
                        .with_auth(proxy_auth);
                    setup = setup.with_http_proxy(h1_proxy_factory(h1cfg));
                    if let Some(ssl) = target_ssl {
                        setup = setup.with_ssl(ssl);
                    }
                }
                // Forward HTTP proxy (no tunnel): `request_target` auto-selects the
                // absolute-URI form from `conn.bits.httpproxy && !tunnel_proxy` (set
                // above). The forward-request headers (`Proxy-Authorization`,
                // `Proxy-Connection: Keep-Alive`) are set on `hop` up-front so they
                // survive a reused proxy connection (curl tests 184/185); `target_ssl`
                // is `None` for a plain-http target, so there is nothing to layer here.
            }
        } else if let Some(ssl) = target_ssl {
            setup = setup.with_ssl(ssl);
        }
    }
    #[cfg(not(feature = "proxy"))]
    if let Some(ssl) = target_ssl {
        setup = setup.with_ssl(ssl);
    }

    let dispatch = ConnSetup::Default(setup);
    // Drive the assembled chain to the connected state. A CONNECT-tunnel failure
    // (a non-2xx final CONNECT response, e.g. a 405/407 with no auth left to try)
    // surfaces as an `Err` here, but curl still records the CONNECT status code
    // and writes the proxy's CONNECT response to the data stream before failing
    // the transfer — so the result is captured rather than propagated with `?`.
    let connect_result =
        establish_connection(&mut conn, FIRSTSOCKET, ssl_mode, dispatch, true).await;

    // CURLINFO_HTTP_CONNECTCODE / `%{http_connect}`: curl sets `info.httpproxycode`
    // the moment the CONNECT status line is parsed, so it is recorded on both the
    // success and the failure path. The CONNECT filter (if any) holds the parsed
    // code; a value of `0` means no CONNECT status line was seen (no tunnel) and
    // is left as the reset default (oracle: tests/data/test217 — a 405 CONNECT
    // makes `%{http_connect}` report 405 while the transfer fails with
    // `CURLE_RECV_ERROR`).
    #[cfg(feature = "proxy")]
    if conn.bits.tunnel_proxy {
        if let Some(code) = conn.cfilter[FIRSTSOCKET].connect_proxy_code() {
            if code > 0 {
                data.info.http_connect_code = i64::from(code);
            }
        }
    }

    // On a *failed* CONNECT tunnel, curl still writes the proxy's CONNECT
    // response (status line + headers + terminating blank line) to the client
    // before failing — the `CLIENTWRITE_CONNECT` path fires for a non-2xx CONNECT
    // exactly as it does for a 2xx one (lib/cf-h1-proxy.c L364-366 emits every
    // CONNECT header line via `CLIENTWRITE_CONNECT`, gated in lib/sendf.c L191-192
    // *only* by `suppress_connect_headers`). Unlike the success path below, this
    // is NOT gated on `!is_https`: a failed CONNECT means no tunnel was
    // established, so the proxy's response IS the response and is surfaced for an
    // https origin too — e.g. an HSTS http→https upgrade routed through a proxy
    // that denies the CONNECT (oracle: tests/data/test440, test441, test493 — a
    // 403 CONNECT to :443 appears on stdout ahead of the error exit), as well as
    // a plain-HTTP proxytunnel (test217/test287 — a 405 CONNECT). The captured
    // lines retain their original CRLF and are written verbatim. The error is
    // then propagated so the transfer fails with the correct code.
    if let Err(e) = connect_result {
        #[cfg(feature = "proxy")]
        if conn.bits.tunnel_proxy && !data.set.suppress_connect_headers {
            if let Some(lines) = conn.cfilter[FIRSTSOCKET].connect_response_headers() {
                for line in &lines {
                    let mut off = 0;
                    while off < line.len() {
                        let n = sink.write_body(&line[off..]);
                        if n == 0 {
                            break;
                        }
                        off += n;
                    }
                }
            }
        }
        return Err(e);
    }
    // CURLINFO_CONNECT_TIME milestone: the TCP (and, for https, the TLS) handshake
    // is complete. curl's `CONNECT_TIME`/`APPCONNECT_TIME` are measured from the
    // operation start (they include the name-lookup phase), so both deltas are
    // relative to `op_start`.
    let t_connected = Instant::now();

    // Publish the connection-derived `data->info` fields now that the socket is
    // up, mirroring curl's per-connection info store (`Curl_conn_get_ip_quadruple`
    // → `data->info.primary` / `conn->primary`). These back `CURLINFO_PRIMARY_IP`
    // / `PRIMARY_PORT` / `LOCAL_IP` / `LOCAL_PORT` (`%{remote_ip}`, `%{remote_port}`,
    // `%{local_ip}`, `%{local_port}`) and `CURLINFO_NUM_CONNECTS` (`%{num_connects}`).
    // Recorded before the transfer drive so the values are present even if the
    // body transfer later fails. The same chain query (`Curl_conn_get_ip_info`)
    // that the socket filter answers via `getpeername`/`getsockname` is used — the
    // peer source is identical to the `* Connected to …` trace above.
    if let Some((_is_ipv6, quad)) = Curl_conn_get_ip_info(&conn, FIRSTSOCKET) {
        data.info.primary_ip = CString::new(quad.remote_ip).ok();
        data.info.local_ip = CString::new(quad.local_ip).ok();
        data.info.primary_port = i64::from(quad.remote_port);
        data.info.local_port = i64::from(quad.local_port);
        data.info.primary_has_ports = true;
    }
    data.info.num_connects += 1;

    // Transfer-phase timings that are known at connect time (curl's
    // `Curl_pgrsTime(TIMER_NAMELOOKUP/CONNECT/APPCONNECT)`). `connect_time`
    // includes the name-lookup phase (measured from `op_start`), matching curl.
    // For an https hop the TLS handshake completes inside `establish_connection`,
    // so `APPCONNECT_TIME` shares the connect instant.
    data.info.namelookup_time_us = t_resolved.saturating_duration_since(op_start).as_micros() as i64;
    let connect_us = t_connected.saturating_duration_since(op_start).as_micros() as i64;
    data.info.connect_time_us = connect_us;
    if is_https {
        data.info.appconnect_time_us = connect_us;
    }

    // Populate `CURLINFO_CERTINFO` (`%{certs}` / `%{num_certs}`) from the
    // verified peer certificate chain when the application requested it
    // (`CURLOPT_CERTINFO`; the CLI sets this whenever `--write-out` is used,
    // mirroring curl's `config2setopts.c` `if(config->writeout)` gate). curl's
    // TLS backends call `Curl_ssl_push_certinfo_len(data, i, "Cert", pem, len)`
    // once per chain certificate during the handshake; the memory-safe core
    // pulls the DER chain the `rustls` filter retained at connect
    // (`Curl_conn_get_peer_certs` → `CF_QUERY_PEER_CERTS`), converts each to
    // PEM, and pushes one `"Cert:<pem>"` entry per certificate — the exact
    // `name:content` node shape the writeout `%{certs}` consumer strips
    // (`tool_writeout.c` `VAR_CERT`). Recorded once at connect, before the
    // transfer drive, so the info is present even if the body later fails.
    if is_https && data.set.ssl.certinfo {
        let der_chain = Curl_conn_get_peer_certs(&conn, FIRSTSOCKET);
        data.info.certinfo.clear();
        for der in &der_chain {
            let mut entry = crate::slist::SList::new();
            // `append` only fails on an interior NUL byte; a PEM block is ASCII
            // text (base64 + armor), so the push is infallible here.
            let _ = entry.append(&format!("Cert:{}", der_to_pem(der)));
            data.info.certinfo.push(entry);
        }
    }

    // CURLINFO_TEXT connection trace (`-v`): emit the `* Trying …` /
    // `* Connected to …` lines curl prints once the socket is connected. The
    // connected peer address is queried from the chain (`Curl_conn_get_remote_addr`,
    // the same source as `CURLINFO_PRIMARY_IP`). A `SocketAddr`'s `Display`
    // already brackets IPv6 and appends `:port`, matching curl's
    // `"  Trying [%s]:%d..."` / `"  Trying %s:%d..."` exactly, while the
    // `Connected to %s (%s) port %u` line pairs the request host (curl's
    // `conn->host.dispname`) with the bare peer IP and port. The front-end's
    // `tool_debug_cb` adds the `* ` line-start marker. Each datum ends in `\n`
    // so the renderer treats it as a complete line.
    if verbose {
        if let Some(peer) = Curl_conn_get_remote_addr(&conn, FIRSTSOCKET) {
            let trying = format!("  Trying {peer}...\n");
            sink.debug(crate::transfer::DebugInfoType::Text, trying.as_bytes());
            let connected = format!(
                "Connected to {} ({}) port {}\n",
                host,
                peer.ip(),
                peer.port()
            );
            sink.debug(crate::transfer::DebugInfoType::Text, connected.as_bytes());
        }
    }

    // ---- Surface the CONNECT-tunnel response to the data stream -------------
    // When a fresh CONNECT tunnel is negotiated for a *plain-HTTP* origin
    // (`--proxytunnel`/`-p` to an `http://` URL), curl writes the proxy's
    // CONNECT response — its status line, each header, and the terminating
    // blank line — to the client as it parses them, tagged
    // `CLIENTWRITE_HEADER | CLIENTWRITE_CONNECT` (`cf-h1-proxy.c` `single_header`
    // → `Curl_client_write`). For a non-TLS origin `cw_download_write`
    // (`lib/sendf.c`) forwards those header bytes onto the body writer, so they
    // appear on the data stream ahead of the tunneled response (oracle:
    // tests/data/test80, test83, test95). The captured lines keep their original
    // CRLF, so they are written verbatim.
    //
    // Three gates mirror curl exactly:
    //  * `conn.bits.tunnel_proxy` — a CONNECT tunnel was actually used (an https
    //    origin, or `--proxytunnel` forcing it for plain http).
    //  * `!is_https` — an https origin keeps the plaintext CONNECT response off
    //    the (now-encrypted) application data stream, and `cw_download_write`
    //    would not forward it onto the body there; only plain-HTTP tunnels
    //    surface it (also avoids regressing https-via-proxy tests, e.g. test446).
    //  * `!suppress_connect_headers` — `CURLOPT_SUPPRESS_CONNECT_HEADERS`
    //    (`--suppress-connect-headers`) opts out of this behavior entirely.
    //
    // This runs only on the fresh-connection path: the reuse branch returned
    // above before any tunnel negotiation, matching curl — a reused tunnel
    // performs no new CONNECT and so writes no CONNECT response.
    #[cfg(feature = "proxy")]
    if conn.bits.tunnel_proxy && !is_https && !data.set.suppress_connect_headers {
        if let Some(lines) = conn.cfilter[FIRSTSOCKET].connect_response_headers() {
            for line in &lines {
                // Drive a possibly-partial body sink to completion for each line
                // (the same write loop `flush_auth_body` uses); a sink returning
                // 0 has stopped accepting, so stop forwarding.
                let mut off = 0;
                while off < line.len() {
                    let n = sink.write_body(&line[off..]);
                    if n == 0 {
                        break;
                    }
                    off += n;
                }
            }
        }
    }

    // `CURLINFO_USED_PROXY` (`data->info.used_proxy`): set on the freshly dialed
    // connection, mirroring curl's `create_conn` (lib/url.c:3630
    // `data->info.used_proxy = conn->bits.proxy`). The proxy decision above set
    // `conn.bits.httpproxy`/`socksproxy` only when a proxy actually applies to this
    // target (`proxy_for_target` returns `None` for a NOPROXY/NO_PROXY host, leaving
    // both `false`), so their union is exactly C's unified `conn->bits.proxy`.
    data.info.used_proxy = i64::from(conn.bits.httpproxy || conn.bits.socksproxy);

    Ok(conn)
}

/// Report this hop's connected socket and its current poll interest to the easy
/// handle's [`crate::transfer::SocketObserver`], if one is installed.
///
/// This is the **production driver of `CURLMOPT_SOCKETFUNCTION`**. The async
/// core owns the real I/O on Tokio's reactor, but a libevent-style event-loop
/// consumer driving `curl_multi_socket_action` still needs to learn *which* fd
/// is in play and in *which* direction — exactly the contract curl's
/// `lib/multi_ev.c` upholds. The multi handle installs a per-task observer in
/// `spawn_pending`; here we translate the connection's [`Pollset`]
/// (`want_read`/`want_write`) into the matching `CURL_POLL_*` value and report
/// it. The owning multi diffs this against the last reported interest and fires
/// the C socket callback only on a real change; `CURL_POLL_REMOVE` is emitted by
/// the multi when the transfer completes (it owns the fd map), not here.
///
/// A no-op when no observer is installed (the easy/CLI single-transfer path) or
/// when the chain has no socket yet (`fd < 0`), so it is safe to call after
/// every (re)connect.
fn report_socket_to_observer(data: &Easy, conn: &Connection) {
    let Some(observer) = data.socket_observer() else {
        return;
    };
    let fd = Curl_conn_get_first_socket(conn);
    if fd < 0 {
        return;
    }
    let ps = Curl_conn_cf_adjust_pollset(conn, FIRSTSOCKET);
    let what = match (ps.want_read, ps.want_write) {
        (true, true) => CURL_POLL_INOUT,
        (true, false) => CURL_POLL_IN,
        (false, true) => CURL_POLL_OUT,
        (false, false) => CURL_POLL_NONE,
    };
    observer.on_socket(fd, what);
}

/// Execute a single HTTP request/response hop and report the captured outcome.
///
/// This is the historical single-shot engine (connect → build → drive), lifted
/// into a helper so the redirect orchestrator in [`perform_http`] can invoke it
/// once per hop. The response sink is wrapped in a [`HopSink`] so the hop's
/// status line, `Location`, `Set-Cookie`, `Strict-Transport-Security`, and
/// `Alt-Svc` headers are captured for the orchestrator while every header is
/// still forwarded to the real sink (so `-i`/`-D` observe every hop); an
/// intermediate 3xx body is suppressed so only the final response body reaches
/// the caller, matching curl `-L`.
///
/// The `hop` inputs carry the per-hop request shape (method/body framing,
/// cookies, referer, authorization), letting the orchestrator vary the method
/// across a redirect chain without re-reading the source body.
///
/// # Errors
///
/// Any URL, resolve, connect, TLS, or transfer error from the layers below, or
/// [`CurlError::UrlMalformat`] for a host-less URL.
async fn perform_http_hop(
    data: &mut Easy,
    url: &CurlUrl,
    hop: HopInputs,
    body: h1::RequestBody,
    follow_enabled: bool,
    sink: &mut dyn WriteCallbacks,
    // The upload read source, threaded in for a [`h1::RequestBody::Streaming`]
    // body so the codec pulls it incrementally (bounded-memory upload, QA Issue
    // #5). `None` for buffered bodies and GET/HEAD; consumed exactly once since
    // streaming is gated to single-pass uploads.
    mut source: Option<&mut dyn ReadCallback>,
) -> Result<HopResult> {
    // The operation start for this hop, captured before DNS resolution and
    // connection setup so the transfer timings (`CURLINFO_*_TIME`) measure from
    // the true beginning of work — curl's `Curl_pgrsStartNow` reference point.
    // The name-lookup and connect milestones below are recorded relative to it,
    // and it is threaded into `drive_one` to seed `Progress`.
    let op_start = Instant::now();
    let verbose = data.set.verbose;
    let httpwant = data.set.httpwant;
    let ipver = IpVersion::from_raw(i64::from(data.set.ipver));

    // The request parts for *this* hop's URL.
    let (_scheme, is_https, host, port) = http_url_parts(url)?;
    // Host used for the `Host:` header and TLS SNI: ACE-encode a Unicode host to
    // its `xn--` Punycode form (curl's `Curl_idnconvert_hostname`). `to_ascii`
    // returns an ASCII or already-`xn--` host byte-for-byte unchanged
    // (idempotent, case-preserving), converts a Unicode host via UTS-46
    // ToASCII, and yields `CURLE_URL_MALFORMAT` for an un-encodable name —
    // matching curl exactly for the wire-observable host that appears in the
    // `Host:` header and the TLS SNI. The DNS layer applies the same conversion
    // independently (`dns::resolve`), so the lookup and the request agree on the
    // ACE form (this resolves F6-007: the Host header previously carried raw
    // UTF-8 while only the resolver path was ACE-encoded).
    let host_ace = crate::idn::to_ascii(&host)?;

    // (3) Decide whether this hop routes through a proxy (F6-001). The CLI/FFI
    //     deposits `-x`/`--proxy`/`--socks*`/`--preproxy`/`--noproxy` into
    //     `data.set`; the engine consults that config here (curl's `create_conn`
    //     proxy setup), where it actually changes the dial target and the filter
    //     chain. When a proxy applies, the TCP connect targets the *proxy*; the
    //     request still targets the origin (curl keeps `conn->host` = origin,
    //     `conn->http_proxy.host` = proxy). `--noproxy`/`NO_PROXY` is honored by
    //     `proxy_for_target`, which returns `None` when the host is bypassed.
    // The per-hop inputs become mutable here: a forward HTTP proxy injects
    // `Proxy-Authorization`/`Proxy-Connection`, and the HTTP/1.1 reactive-auth
    // loop rewrites `authorization` across challenge-response retries. Both the
    // proxy feature and the auth loop mutate `hop`, so the rebind is
    // unconditional (the auth loop is always compiled).
    let mut hop = hop;
    let mut conn = http_connect_hop(
        data,
        &mut hop,
        is_https,
        host.clone(),
        host_ace.clone(),
        port,
        verbose,
        httpwant,
        ipver,
        op_start,
        sink,
    )
    .await?;
    // Report the freshly-connected socket + its poll interest to the multi
    // handle's socket observer (if any), driving `CURLMOPT_SOCKETFUNCTION` for
    // event-loop consumers. No-op on the easy/CLI path (no observer installed).
    report_socket_to_observer(data, &conn);

    // (6) Select the wire version (forced option, else negotiated ALPN) and
    //     build + drive the matching exchange, capturing the hop outcome.
    let version = select_http_version(data, &conn)?;
    // A reactive-auth controller drives the HTTP/1.1 challenge-response loop
    // (Digest/NTLM/`--anyauth`). It applies only to the h1 path: NTLM is a
    // connection-oriented scheme curl forces onto HTTP/1.1, and the cleartext
    // mail/Digest test endpoints all negotiate over h1; HTTP/2 and HTTP/3 keep
    // the single preemptive attempt (which still carries Basic/Bearer).
    let mut auth_controller = match version {
        HttpVersion::Http10 | HttpVersion::Http11 => {
            hop.auth.take().map(auth_engine::HttpAuthController::new)
        }
        _ => None,
    };
    // Single-scheme NTLM opens its handshake preemptively: curl pre-picks the
    // sole wanted scheme and sends the challenge-free Type-1 message on the FIRST
    // request (`--ntlm`), rather than waiting for a `401` (which `--anyauth` does,
    // and which Digest must, lacking a nonce). Seed this hop's `Authorization`
    // with that Type-1 so it rides the first request; the controller's NTLM state
    // advances in lock-step, so the `401`'s Type-2 challenge produces the Type-3
    // authenticate message on the retry. This runs per hop, so the handshake
    // correctly RESTARTS from Type-1 on a redirect target (the new hop's fresh
    // controller), matching curl. Only applies when no preemptive credential is
    // already set (a reactive NTLM transfer carries none).
    if hop.authorization.is_none() {
        if let Some(initial) = auth_controller
            .as_mut()
            .and_then(auth_engine::HttpAuthController::initial_header)
        {
            hop.authorization = Some(initial);
        }
    }
    // A reactive **proxy**-auth controller drives the forward HTTP proxy's
    // challenge-response (`--proxy-ntlm`/`--proxy-digest`/`--proxy-anyauth`)
    // against the proxy's `407`, symmetrically to how `auth_controller` drives
    // the host's `401`. It applies only when a forward HTTP proxy is in effect
    // for this hop — `hop.proxy_connection_keepalive` is set exactly in that case
    // by the forward-proxy block in `http_connect_hop` (which has already run for
    // the initial connect above), and is `false` for a SOCKS proxy, a CONNECT
    // tunnel (https / `--proxytunnel`, whose proxy auth rides the CONNECT request
    // instead), or no proxy at all. Like the host controller it is h1-only (NTLM
    // is a connection-oriented scheme curl forces onto HTTP/1.1).
    #[cfg(feature = "proxy")]
    let mut proxy_auth_controller = match version {
        HttpVersion::Http10 | HttpVersion::Http11 if hop.proxy_connection_keepalive => {
            // The resolved proxy credentials (URL userinfo unified with the
            // `--proxy-user` overlay) were deposited on `hop` by the forward-proxy
            // branch of `http_connect_hop`, so a reactive proxy scheme can attempt
            // the `407` with credentials supplied only in the proxy URL (test 335).
            auth_engine::resolve_proxy_auth_inputs(
                data,
                Some((hop.proxy_user.clone(), hop.proxy_pass.clone())),
            )
            .map(auth_engine::HttpAuthController::new)
        }
        _ => None,
    };
    #[cfg(not(feature = "proxy"))]
    let mut proxy_auth_controller: Option<auth_engine::HttpAuthController> = None;
    // Seed the preemptive proxy NTLM Type-1 into `Proxy-Authorization` so it rides
    // the first forwarded request (mirrors the host NTLM seeding above). Only when
    // no preemptive proxy credential is already set — a forward Basic proxy auth
    // (`forward_proxy_auth_value`) would have populated `hop.proxy_authorization`
    // in `http_connect_hop`, but a reactive NTLM/Digest mask leaves it `None`
    // (`proxy_auth` emits only Basic), so the Type-1 fills it here.
    if hop.proxy_authorization.is_none() {
        if let Some(initial) = proxy_auth_controller
            .as_mut()
            .and_then(auth_engine::HttpAuthController::initial_header)
        {
            hop.proxy_authorization = Some(initial);
        }
    }
    // When auth negotiation is active, a `401`/`407` body is buffered rather than
    // streamed to the application, so an intermediate auth-probe error page is
    // not delivered when the request is about to be re-issued with credentials.
    // Either a host (`401`) or a proxy (`407`) reactive controller arms this.
    let mut hop_sink = HopSink::with_auth(
        sink,
        follow_enabled,
        auth_controller.is_some() || proxy_auth_controller.is_some(),
    );
    // Arm the server-ignored-range check (curl's `http_firstwrite`) for a
    // resumed download. curl gates the check on `data->state.httpreq ==
    // HTTPREQ_GET`, so only a `GET` resume offset is propagated; a `HEAD` has no
    // body to deliver and an upload resume uses `Content-Range` semantics
    // instead. `set_resume_from` is clamped to non-negative — a negative value
    // is the "upload the whole file again" sentinel, not a download resume point.
    hop_sink.resume_from = if data.set.method == HttpReq::Get {
        data.set.set_resume_from.max(0)
    } else {
        0
    };
    // Arm the client-side time-condition check (curl's `http_firstwrite`) for a
    // `-z`/`CURLOPT_TIMECONDITION` request. curl gates it on no byte range being
    // requested (`!data->state.range`, RFC 2616 §13.3.4), so the effective range
    // presence is propagated alongside the condition selector and reference value.
    // `effective_range` is `Some` for an explicit `--range` or a `GET`/`HEAD`
    // resume offset — exactly the cases where curl populates `data->state.range`.
    hop_sink.timecondition = data.set.timecondition;
    hop_sink.timevalue = data.set.timevalue;
    hop_sink.range_present = effective_range(data).is_some();
    let drive_result = match version {
        HttpVersion::Http10 | HttpVersion::Http11 => {
            // The version negotiated for this hop before any in-transfer
            // HTTP/1.0 downgrade. `http_minor` is (re)derived per attempt from
            // this base and the transfer's observed `rcvd_min` (see the loop
            // body), so an auth resend or redirect after a `1.0` response drops
            // to HTTP/1.0 exactly as curl's `http_may_use_1_1` does.
            let base_version = version;
            let mut custom_headers = collect_custom_headers(data);
            // On a cross-host redirect, drop the application's custom `Host:` so
            // the auto `Host:` for the *current* host is sent instead (curl's
            // per-hop rule; tests 184/185). No-op on the original request and on
            // same-host redirects (`suppress_custom_host == false`).
            if hop.suppress_custom_host {
                strip_custom_host_header(&mut custom_headers);
            }

            // Challenge-response retry loop on the kept-alive connection (curl's
            // `data->state.authhost` negotiation). Without a controller this runs
            // exactly once — the historical single-shot path, unchanged. With a
            // controller, a `401` carrying a `WWW-Authenticate` we can answer
            // re-issues the request on the SAME connection with the computed
            // `Authorization` header, capped at `MAX_AUTH_ATTEMPTS` retries
            // (curl's `Curl_auth_allowed` round budget) so a persistently
            // challenging server cannot loop forever.
            const MAX_AUTH_ATTEMPTS: u32 = 10;
            let mut attempt: u32 = 0;
            // curl's `Curl_creader_set_rewind` one-shot: latches once the upload
            // read source has been rewound for the credentialed body resend, so
            // the application rewind callback (`CURLOPT_IOCTLFUNCTION`
            // `CURLIOCMD_RESTARTREAD` / `CURLOPT_SEEKFUNCTION`) fires exactly once
            // per hop before the body is re-sent (QA libtest 552).
            let mut rewound = false;
            // Whether the current connection is freshly (re)established versus
            // reused (from the pool, or for a same-connection retry). This is
            // curl's `conn->bits.reuse` (inverted): it gates the HTTP/0.9
            // fallback and the reused-connection retry below. It is seeded from
            // the connection's pool-reuse state — a connection checked out of the
            // keep-alive pool starts NON-fresh so that, if the peer has silently
            // closed it (the `swsclose` race), `Curl_retry_request` below retries
            // on a fresh connection (oracle test160). A freshly dialed connection
            // starts fresh.
            let mut conn_is_fresh = !conn.bits.reuse;
            // curl's `data->state.retrycount`: bounds the number of times a
            // reused-but-dead connection is retried on a fresh connect (C
            // `CONN_MAX_RETRIES`), independent of the auth-attempt budget.
            const CONN_MAX_RETRIES: u32 = 5;
            let mut conn_retry_count: u32 = 0;
            // curl's `conn->bits.authneg`: while a reactive auth handshake is
            // negotiating, a POST/PUT request body is suppressed (sent as
            // `Content-Length: 0`) so the upload payload is not transmitted before
            // the credentials are accepted — the body rides only the final,
            // authenticated request. A reactive controller opens by negotiating
            // (an empty-bodied probe: `--anyauth`/`--digest`/`--ntlm` send no
            // preemptive credential); without a controller this stays false and
            // the body is always sent on the single attempt.
            let mut authneg = auth_controller
                .as_ref()
                .is_some_and(|c| c.is_negotiating())
                || proxy_auth_controller
                    .as_ref()
                    .is_some_and(|c| c.is_negotiating());
            // curl's `data->state.authhost.done`: latched once the body-less
            // auth-negotiation probe has been re-issued with its real upload
            // body (the `authneg && httpcode < 300` resend below). It prevents
            // that unauthenticated resend from firing more than once on a server
            // that never challenges (tests 175/176).
            let mut authhost_done = false;
            // curl's `data->state.disableexpect` + `data->req.newurl` (lib/http.c
            // exp100 / `Curl_http_auth_act`): a body-bearing request that announced
            // `Expect: 100-continue` and received `417 Expectation Failed` (the
            // server rejected the expectation rather than answering with the
            // interim `100`) is RE-SENT once to the SAME URL with the expectation
            // disabled and the full body. `disable_expect_resend` suppresses the
            // `Expect:` header on the next iteration's head (threaded into
            // `inputs.disable_expect`); `expect_resend_done` latches the one-shot so
            // a server that persistently answers `417` cannot loop. Independent of
            // auth and of `-L` (test357).
            let mut disable_expect_resend = false;
            let mut expect_resend_done = false;
            let result = loop {
                // (curl's `http_request_version` → `http_may_use_1_1`): once a
                // `1.0` response has been seen on this transfer (`rcvd_min == 10`,
                // recorded after each exchange below and persisted across redirect
                // hops on `data`), an HTTP/1.1 request is downgraded to HTTP/1.0.
                // The first request always rides the base version (no response
                // seen yet); an auth resend or a redirect after a `1.0` reply
                // drops to `1.0`. A forced `1.0`, or an `h2`/`h3` hop, is left
                // unchanged (this arm only handles the h1 codec anyway).
                let effective_version =
                    if base_version == HttpVersion::Http11 && data.http_rcvd_min() == 10 {
                        HttpVersion::Http10
                    } else {
                        base_version
                    };
                let http_minor = if effective_version == HttpVersion::Http10 { 0 } else { 1 };
                // (curl's `http_req_set_TE`): a body-bearing request with an
                // indeterminate upload length (`Curl_creader_total_length < 0`)
                // and no explicit `Transfer-Encoding: chunked` header cannot be
                // satisfied over HTTP/1.0 — chunked framing is unavailable there —
                // so curl fails with `CURLE_UPLOAD_FAILED` ("Chunky upload is not
                // supported by HTTP 1.0") BEFORE writing the request. This fires
                // on an auth resend (test 1072) or a followed redirect (test 1073)
                // after a `1.0` reply downgrades the version; a known-length
                // upload (a `-T file`, test 1071) frames with `Content-Length` and
                // is unaffected. A user-forced `Transfer-Encoding: chunked` is the
                // application's choice and is left to the server (curl keeps it).
                if http_minor == 0
                    && matches!(
                        hop.method,
                        HttpReq::Put | HttpReq::Post | HttpReq::PostForm | HttpReq::PostMime
                    )
                    && known_upload_length(data).is_none()
                    && !upload_is_chunked(data)
                {
                    break Err(CurlError::UploadFailed);
                }
                // The request body is re-sent on each auth attempt (curl rewinds
                // and resends), so clone the buffered body per iteration; the
                // GET/HEAD case clones `RequestBody::None` (free). During auth
                // negotiation (`authneg`) the upload payload is replaced with an
                // empty `Content-Length: 0` body — curl's body-less auth probe.
                let attempt_body = if authneg {
                    suppress_upload_body(&body)
                } else {
                    body.clone()
                };
                // Whether this attempt sends a streamed (incrementally read)
                // body, captured before `attempt_body` is moved into the request
                // inputs. The auth-negotiation probe suppresses the body to an
                // empty `Sized`, so a probe is never streamed.
                let attempt_is_streaming =
                    matches!(attempt_body, h1::RequestBody::Streaming { .. });
                let plan = {
                    let mut inputs = make_inputs(
                        data,
                        url,
                        &conn,
                        &custom_headers,
                        &host_ace,
                        port,
                        is_https,
                        false,
                        attempt_body,
                        http_minor,
                        &hop,
                    );
                    // Thread the live auth-negotiation state into request
                    // shaping. During an authneg probe the upload body is
                    // suppressed (`suppress_upload_body`), so curl's client
                    // reader reports a known length of zero
                    // (`Curl_creader_client_length` over `Curl_creader_set_null`).
                    // That zero length both drops a custom `Content-Length` and
                    // — on this body-less probe — suppresses `Expect:
                    // 100-continue` (curl's `addexpect` only adds it for an
                    // unknown or large body). The real payload, and its
                    // `Expect`, ride the authenticated resend, where `authneg`
                    // is false and the chunked body's length is unknown (-1).
                    inputs.authneg = authneg;
                    // Suppress `Expect: 100-continue` on a 417 resend (curl's
                    // `data->state.disableexpect`): once the server has rejected the
                    // expectation with a `417`, the resent request omits the header
                    // and sends the body unconditionally (test357). `false` on every
                    // other attempt, so the normal large-/unknown-body `Expect`
                    // decision in `should_add_expect_100` is unaffected.
                    inputs.disable_expect = disable_expect_resend;
                    // The `multipart/form-data; boundary=…` (or any mime) Content-Type
                    // is a property of the request BODY. During a body-less authneg
                    // probe the payload is replaced with a null reader (the empty
                    // `Content-Length: 0` body above), so curl emits no body framing
                    // headers either — `Curl_mime_prepare_headers` runs only when the
                    // mime part is actually the request body, not on the suppressed
                    // probe. Drop the form Content-Type so the NTLM/Digest Type-1
                    // probe carries only `Content-Length: 0` (test 170); the real
                    // payload, with its Content-Type, rides the authenticated resend.
                    if authneg {
                        inputs.content_type = None;
                    }
                    h1::build_request(&inputs)?
                };
                // Whether THIS attempt announced `Expect: 100-continue` (captured
                // before `plan` is moved into the exchange). A `417` answer to such
                // a request triggers the one-shot resend below (curl's exp100 417
                // handling); a request that never sent the expectation is left
                // untouched.
                let attempt_announced_expect = plan.expect_100;
                // CURLINFO_HEADER_OUT: when verbose, emit the fully serialized
                // request head (request line + header block + terminating CRLF)
                // as a single event before the exchange begins. curl's
                // `tool_debug_cb` splits it on newlines and renders each line with
                // the `> ` prefix (`Curl_debug(…, CURLINFO_HEADER_OUT, …)`).
                if verbose {
                    hop_sink.debug(crate::transfer::DebugInfoType::HeaderOut, &plan.head);
                }
                // A reused connection forbids the HTTP/0.9 no-status-line fallback
                // (curl's reused-conn rule); a freshly (re)established connection
                // permits it. `!conn_is_fresh` is precisely curl's
                // `conn->bits.reuse`.
                let mut exchange = h1::H1Exchange::new(
                    h1::ConnByteStream::new(&mut conn),
                    plan,
                    data.set.http09_allowed,
                    !conn_is_fresh,
                );
                // `CURLOPT_TRANSFER_ENCODING` (`--tr-encoding`): opt into
                // transfer decoding of a compressed `Transfer-Encoding` response
                // body and the chunked-not-last rejection (curl's `is_transfer`
                // path, gated on `data.set.http_transfer_encoding`).
                exchange.set_transfer_decoding(data.set.http_transfer_encoding);
                // `--raw` / `CURLOPT_HTTP_TRANSFER_DECODING` set to 0
                // (`data.set.http_te_skip`): run the chunked decoder in
                // pass-through mode so the original chunked wire bytes reach the
                // client verbatim (curl's `http_te_skip`). Oracle: test326.
                exchange.set_te_skip(data.set.http_te_skip);
                // `--max-filesize` (`CURLOPT_MAXFILESIZE[_LARGE]`): hand the cap
                // to the codec so an *overflowing* advertised `Content-Length`
                // fails up-front with `CURLE_FILESIZE_EXCEEDED` (63), matching
                // curl's `STRE_OVERFLOW` guard. The during-transfer size cap is
                // enforced separately by the transfer driver. Oracle: test393.
                exchange.set_max_filesize(data.set.max_filesize);
                // `--ignore-content-length` (`CURLOPT_IGNORE_CONTENT_LENGTH`):
                // ignore the response `Content-Length` for framing — read the
                // body close-delimited and disable the short-read check (curl's
                // `k->ignore_cl`). Oracle: test269.
                exchange.set_ignore_cl(data.set.ignorecl);
                // `CURLOPT_FOLLOWLOCATION` (`-L`): let the codec reproduce curl's
                // `http_firstwrite` redirect-body suppression — a followed
                // redirect on a closing connection is aborted right after the
                // headers, so a close-delimited redirect body is never read (and
                // cannot hang on a deferred server close). Oracle: test187.
                exchange.set_follow_enabled(follow_enabled);
                // Install the upload source for a streamed body so the codec
                // pulls it incrementally (bounded-memory upload, QA Issue #5),
                // paced by the send-direction rate limiter
                // (`CURLOPT_MAX_SEND_SPEED_LARGE` / `--limit-rate`, QA Issue #4
                // send half). Streaming is gated to provably single-pass uploads
                // (known size, no `-L`, no resume, no reactive auth), so the
                // body is *read* at most once.
                //
                // The source is REBORROWED (`as_deref_mut`), not taken: a
                // streamed upload that announces `Expect: 100-continue` (any size
                // over the 1 KiB threshold does) can receive `417 Expectation
                // Failed` instead of the interim `100`. On `417` the Expect probe
                // sends NO body (the `InterimOutcome::FinalResponse` arm in
                // `H1Exchange::start` skips `stream_upload`), so the source is
                // still at offset 0 and the 417-resend branch below loops once
                // more to send the full body with the expectation disabled
                // (curl's `data->state.disableexpect` rewind-and-resend; test357).
                // Were the borrow `take`n on the probe, the resend would find an
                // empty `upload_source` and fail with `CURLE_READ_ERROR`. The
                // reborrow keeps the source available across the at-most-two
                // iterations while preserving the read-once invariant — the probe
                // reads nothing, the resend performs the single read. When the
                // server answers the normal `100`, the body streams on the first
                // iteration and the loop ends, so the reborrow behaves exactly
                // like the prior single-take.
                if attempt_is_streaming {
                    if let Some(src) = source.as_deref_mut() {
                        let rate = build_rate_limit(0, data.set.max_send_speed);
                        exchange.set_upload_source(src, rate);
                    }
                }
                // Mark a body-bearing auth-negotiation probe so the hop sink
                // suppresses (discards) THIS response's body if it is a non-`401`
                // success — curl re-issues with the real body and `ignorebody`s
                // the probe response (`Curl_http_auth_act` / `http_firstwrite`).
                // GET/HEAD never resend on a success, so the flag is gated to
                // body-bearing methods (tests 175/176).
                hop_sink.set_authneg_probe(
                    authneg
                        && matches!(
                            hop.method,
                            HttpReq::Put | HttpReq::Post | HttpReq::PostForm | HttpReq::PostMime
                        ),
                );
                // `defer_auth_fail = auth_controller.is_some()`: while a reactive
                // controller drives Digest/NTLM/Negotiate/anyauth, an
                // intermediate `401`/`407` is a challenge, not a terminal error,
                // so the `-f` verdict is deferred until the negotiation ends
                // (re-applied to the terminal response after this loop). A plain
                // single-scheme `Basic`/`Bearer` request has no controller, so it
                // fails a `401` immediately exactly as before (test 152).
                let result = drive_one(
                    data,
                    &mut exchange,
                    &mut hop_sink,
                    op_start,
                    auth_controller.is_some() || proxy_auth_controller.is_some(),
                )
                .await;
                let keepalive = exchange.keepalive();
                drop(exchange);
                h1::apply_connection_reuse(&mut conn, keepalive);

                // Fold this exchange's response version into the transfer's
                // running minimum (curl's `data->state.http_neg.rcvd_min`
                // update). The version is read from the hop sink's status-line
                // parser (`HopSink::version`), which is populated *now*, before
                // the next loop iteration — unlike `data.info.http_version`,
                // which is published only at transfer finalize and would still
                // read `0` here. Recording it lets the NEXT attempt — an auth
                // resend, or (via the value persisting on `data`) a followed
                // redirect's first request — downgrade to HTTP/1.0 once a `1.0`
                // reply has been seen.
                data.note_http_response_version(i64::from(hop_sink.version));

                // A transport/protocol error normally ends the hop. But a *reused*
                // connection that died before delivering any response — the case
                // where the server closed an apparently keep-alive socket after a
                // prior challenge (the `swsclose` pattern), which the non-blocking
                // liveness peek below can miss when the peer's FIN has not yet
                // arrived — is retried once on a fresh connection. This is curl's
                // `Curl_retry_request`, scoped to an active auth negotiation so it
                // cannot mask a genuine transport failure on a fresh connection or
                // in a non-auth transfer.
                if result.is_err() {
                    let err_kind = result.as_ref().err();
                    // Existing auth-negotiation reused-connection retry: a server
                    // may close an apparently keep-alive socket after a challenge,
                    // so the credentialed resend reconnects. Preserved verbatim.
                    let auth_retryable = (auth_controller.is_some()
                        || proxy_auth_controller.is_some())
                        && !conn_is_fresh
                        && attempt < MAX_AUTH_ATTEMPTS
                        && matches!(
                            err_kind,
                            Some(CurlError::GotNothing)
                                | Some(CurlError::RecvError)
                                | Some(CurlError::SendError)
                                | Some(CurlError::PartialFile)
                        );
                    // curl's `Curl_retry_request` (lib/transfer.c L614), NOT
                    // scoped to auth: a *reused* connection (`conn->bits.reuse`,
                    // here `!conn_is_fresh`) that died before delivering ANY
                    // response bytes is retried on a fresh connection — for HTTP
                    // regardless of whether a body was expected. The zero-bytes
                    // guard (no status line parsed and no headers captured, curl's
                    // `bytecount + headerbytecount == 0`) ensures a genuine
                    // mid-response failure is never masked. This handles a plain
                    // keep-alive reuse where the peer closed the socket after the
                    // previous response (the `swsclose` pattern; oracle test160's
                    // second URL). Bounded by `CONN_MAX_RETRIES`.
                    let conn_died_retryable = !conn_is_fresh
                        && conn_retry_count < CONN_MAX_RETRIES
                        && hop_sink.status == 0
                        && hop_sink.headers.is_empty()
                        && matches!(
                            err_kind,
                            Some(CurlError::GotNothing)
                                | Some(CurlError::RecvError)
                                | Some(CurlError::SendError)
                        );
                    if auth_retryable || conn_died_retryable {
                        // Charge the auth-attempt budget when this is an auth
                        // resend; otherwise charge the connection-retry budget.
                        if auth_retryable {
                            attempt += 1;
                        } else {
                            conn_retry_count += 1;
                        }
                        hop_sink.reset_for_retry();
                        conn = http_connect_hop(
                            data,
                            &mut hop,
                            is_https,
                            host.clone(),
                            host_ace.clone(),
                            port,
                            verbose,
                            httpwant,
                            ipver,
                            op_start,
                            &mut hop_sink,
                        )
                        .await?;
                        // Re-established connection (retry) — report the new
                        // socket to the multi's observer so the event-loop
                        // consumer tracks the fd change.
                        report_socket_to_observer(data, &conn);
                        conn_is_fresh = true;
                        continue;
                    }
                    break result;
                }

                // curl's lib/http.c `Expect: 100-continue` / `417` handling: a
                // body-bearing request that announced the expectation and received
                // `417 Expectation Failed` (the server refused the `Expect`, e.g.
                // the harness `no-expect` server replies `417` instead of the
                // interim `100`) is RE-SENT once to the SAME URL with the
                // expectation disabled and the full body. curl sets
                // `data->state.disableexpect = TRUE` and `data->req.newurl =`
                // the current URL, routing the resend through the redirect/newurl
                // path — which is why the `417` response itself is delivered to the
                // application (with `--include`, BOTH the `417` and the final
                // response appear in the output; test357's `<datacheck>`). The
                // `417` has already been written to the sink above (no auth
                // buffering applies on a non-auth transfer), so only the
                // per-response parser state is reset before the resend, which
                // reuses a still-alive keep-alive connection or reconnects when the
                // server closed it (the `swsbounce` pattern — sws closes after the
                // `417` and serves the `200` on a fresh accept). Gated to
                // body-bearing methods, independent of auth and of `-L`, and
                // latched (`expect_resend_done`) so a persistently-`417` server
                // cannot loop. The attempt budget is a redundant safety bound.
                if hop_sink.status == 417
                    && attempt_announced_expect
                    && !expect_resend_done
                    && attempt < MAX_AUTH_ATTEMPTS
                    && matches!(
                        hop.method,
                        HttpReq::Put | HttpReq::Post | HttpReq::PostForm | HttpReq::PostMime
                    )
                {
                    expect_resend_done = true;
                    disable_expect_resend = true;
                    attempt += 1;
                    hop_sink.reset_for_retry();
                    // curl's pre-reuse `connalive` peek: reuse the connection only
                    // when it is still open, else reconnect (the `swsbounce` 417
                    // closes the socket), mirroring the auth-neg resend below.
                    let conn_alive = keepalive && Curl_conn_is_alive(&mut conn).0;
                    if conn_alive {
                        conn_is_fresh = false;
                    } else {
                        conn = http_connect_hop(
                            data,
                            &mut hop,
                            is_https,
                            host.clone(),
                            host_ace.clone(),
                            port,
                            verbose,
                            httpwant,
                            ipver,
                            op_start,
                            &mut hop_sink,
                        )
                        .await?;
                        // Re-established connection (417 resend) — report the new
                        // socket to the multi's observer.
                        report_socket_to_observer(data, &conn);
                        conn_is_fresh = true;
                    }
                    continue;
                }

                // Reactive auth: a `401` asks the HOST controller, a `407` the
                // PROXY controller, for the next credential and retries. When the
                // connection is still reusable the retry rides the same socket;
                // when the server closed it after the challenge (curl's `swsclose`
                // Digest/anyauth tests, or any `Connection: close` 401/407) the
                // retry RE-establishes a fresh connection — curl reconnects-and-
                // retries rather than giving up. With neither controller present,
                // or for any status that is not the matching challenge code, or
                // when the attempt budget is exhausted, the response is terminal.
                if auth_controller.is_none() && proxy_auth_controller.is_none() {
                    break result;
                }
                attempt += 1;
                // curl's `Curl_http_auth_act` else-branch (lib/http.c
                // L597-611): a body-bearing request whose upload was SUPPRESSED
                // during auth negotiation (`authneg`, sent as `Content-Length:
                // 0`) but that received a non-`401` *success* (`httpcode < 300`)
                // without ever being challenged must be RE-ISSUED once with the
                // real body and NO `Authorization` header. This is the
                // "`--ntlm`/`--digest` POST to a server that requires no auth"
                // case (tests 175, 176): the body-less probe gets a `200`, so
                // curl resends the upload unauthenticated. Gated to body-bearing
                // methods (`httpreq != GET/HEAD`) and latched (`authhost.done`)
                // so it fires at most once. GET/HEAD have no suppressed body, so
                // they never reach here with `authneg` set on a success.
                if authneg
                    && hop_sink.status < 300
                    && !authhost_done
                    && attempt < MAX_AUTH_ATTEMPTS
                    && matches!(
                        hop.method,
                        HttpReq::Put | HttpReq::Post | HttpReq::PostForm | HttpReq::PostMime
                    )
                {
                    // Latch the resend (curl's `authhost.done = TRUE`) and send
                    // the real body unauthenticated on the next iteration.
                    authhost_done = true;
                    authneg = false;
                    hop.authorization = None;
                    hop_sink.discard_auth_body();
                    hop_sink.reset_for_retry();
                    // The probe's `200` typically arrives on a `swsclose`
                    // (server-closes) connection, so the resend rides a fresh
                    // socket; reuse the connection only when it is still alive
                    // (curl's pre-reuse `connalive` peek), exactly as the `401`
                    // retry below.
                    let conn_alive = keepalive && Curl_conn_is_alive(&mut conn).0;
                    if conn_alive {
                        conn_is_fresh = false;
                    } else {
                        conn = http_connect_hop(
                            data,
                            &mut hop,
                            is_https,
                            host.clone(),
                            host_ace.clone(),
                            port,
                            verbose,
                            httpwant,
                            ipver,
                            op_start,
                            &mut hop_sink,
                        )
                        .await?;
                        // Re-established connection (auth-neg resend) — report
                        // the new socket to the multi's observer.
                        report_socket_to_observer(data, &conn);
                        conn_is_fresh = true;
                    }
                    continue;
                }
                if attempt >= MAX_AUTH_ATTEMPTS {
                    break result;
                }
                // Compute the verb and the origin-form URI the Digest response
                // hashes over (`HA2 = MD5(method:uri)`). curl hashes the ORIGIN
                // path (`data->state.up.path`), NOT the absolute request-line
                // target a forward proxy uses — so a Digest auth through a forward
                // proxy still hashes over `/path`, matching both the host (`401`)
                // and proxy (`407`) Digest `uri=` fields (tests 167, 168). NTLM
                // ignores the target entirely (tests 81, 162).
                let method = h1::resolve_http_method(
                    hop.method,
                    hop.no_body,
                    data.set.str(StrId::Customrequest),
                    false,
                    hop.method == HttpReq::Put,
                )?;
                let target = h1::auth_uri_target(url, hop.request_target_override.as_deref())?;
                // Route the challenge to the matching controller: a `407`
                // (`Proxy-Authenticate`) drives the proxy controller, a `401`
                // (`WWW-Authenticate`) the host controller. The hop sink folds
                // both header families into `www_authenticate` (cleared per
                // response), and a single response carries only the family that
                // matches its status, so there is no cross-contamination.
                // `on_challenge` returns the next credential *value* (e.g.
                // `"NTLM <base64>"`); the tuple also records which header it
                // targets and whether the picked scheme is connection-bound (NTLM
                // past its Type-1). The controller is borrowed only for the call,
                // so `authneg` can be recomputed from both controllers afterward.
                let challenge: Option<(String, bool, bool)> = match hop_sink.status {
                    407 => proxy_auth_controller.as_mut().and_then(|c| {
                        c.on_challenge(&hop_sink.www_authenticate, method.method.as_str(), &target)
                            .map(|next| (next, true, c.requires_same_connection()))
                    }),
                    401 => auth_controller.as_mut().and_then(|c| {
                        c.on_challenge(&hop_sink.www_authenticate, method.method.as_str(), &target)
                            .map(|next| (next, false, c.requires_same_connection()))
                    }),
                    _ => None,
                };
                // No answerable challenge (a non-`401`/`407` status, no matching
                // controller, no acceptable scheme, or rejected credentials): the
                // current response is the real answer. The deferred `failonerror`
                // verdict below turns a terminal `401`/`407` into exit 22 (tests
                // 152, 162).
                let Some((next, is_proxy, same_conn_required)) = challenge else {
                    break result;
                };
                // Decide whether the existing connection can carry the retry. curl
                // reuses a still-open keep-alive connection but RECONNECTS when the
                // server closed the socket after the challenge — an explicit
                // `Connection: close` (`keepalive == false`) or the harness
                // `swsclose` directive (a non-blocking liveness peek,
                // `Curl_conn_is_alive` / curl's pre-reuse `connalive` check,
                // detects the peer's `EOF` so the credential is not written into a
                // dead socket).
                let conn_alive = keepalive && Curl_conn_is_alive(&mut conn).0;
                // A connection-bound NTLM handshake that has already consumed the
                // server's Type-2 challenge cannot continue on a new socket; if the
                // connection is gone the negotiation is unrecoverable, so the
                // current `401`/`407` is the real answer (curl fails likewise).
                if !conn_alive && same_conn_required {
                    break result;
                }
                // Re-issue with the new credential on the matching header. The host
                // credential rewrites `Authorization`; the proxy credential
                // rewrites `Proxy-Authorization` (overwriting any preemptive
                // forward-proxy Basic value with the negotiated scheme). An
                // already-set value on the OTHER header is preserved, so a combined
                // proxy+host transfer carries both.
                if is_proxy {
                    hop.proxy_authorization = Some(next);
                } else {
                    hop.authorization = Some(next);
                    // A host `401` implies the proxy already accepted our
                    // credentials and forwarded the request. If the proxy used a
                    // connection-bound scheme (NTLM) whose handshake has completed,
                    // the proxy is authenticated for the lifetime of THIS
                    // connection, so curl stops repeating `Proxy-Authorization` on
                    // subsequent requests over the same socket (curl's
                    // `Curl_output_ntlm` is a no-op once `ntlm->state ==
                    // NTLMSTATE_TYPE3`). Clear the stale proxy Type-3 so the
                    // host-auth retry (req3) carries only the site `Authorization`
                    // (tests 169, 170). Stateless proxy schemes (Basic/Digest) are
                    // re-sent every request and report `false` here, so a combined
                    // proxy-Digest + host-Digest transfer keeps both (test 168).
                    #[cfg(feature = "proxy")]
                    if proxy_auth_controller
                        .as_ref()
                        .is_some_and(|c| c.connection_authenticated())
                    {
                        hop.proxy_authorization = None;
                    }
                }
                // Update curl's `authneg` from BOTH controllers: the upload body is
                // sent only once neither side is still negotiating. A single-pass
                // scheme (Basic/Bearer/Digest) or the NTLM Type-3 message clears
                // the active side; the NTLM Type-1 initial message keeps it set
                // (the Type-1 probe is still body-less).
                authneg = auth_controller.as_ref().is_some_and(|c| c.is_negotiating())
                    || proxy_auth_controller
                        .as_ref()
                        .is_some_and(|c| c.is_negotiating());
                // curl's `http_perhapsrewind` → `Curl_creader_set_rewind`: once a
                // `401`/`407` challenge has been answered and the body is about to
                // be re-sent with credentials (`!authneg`), curl rewinds the client
                // reader. For a `CURLOPT_READFUNCTION` upload source that fires the
                // application's legacy `CURLOPT_IOCTLFUNCTION`
                // (`CURLIOCMD_RESTARTREAD`) / `CURLOPT_SEEKFUNCTION` rewind hook.
                // The engine buffers the read-callback body up front and re-sends a
                // buffered clone, so this is observable-only — it fires the app
                // callback exactly once per hop (the `rewound` latch) so the wire/
                // stdout output matches curl (QA libtest 552). Gated to a body-
                // bearing upload sourced from a read callback; a `CURLOPT_POSTFIELDS`
                // / form / file body (`!is_fread_set`) or a GET/HEAD never rewinds,
                // and a source with no rewind callback registered no-ops.
                if !authneg
                    && data.set.is_fread_set
                    && matches!(
                        hop.method,
                        HttpReq::Post | HttpReq::Put | HttpReq::PostForm | HttpReq::PostMime
                    )
                    && !rewound
                {
                    if let Some(src) = source.as_deref_mut() {
                        src.rewind();
                    }
                    rewound = true;
                }
                // Drop the buffered probe body and reset the per-attempt observable
                // state for the retry.
                hop_sink.discard_auth_body();
                hop_sink.reset_for_retry();
                // When the connection is no longer usable, re-establish a fresh one
                // for the retry. Both controllers (and any NTLM Type-1 state)
                // persist across the reconnect; only the socket is replaced. The
                // verbose `* Trying …`/`* Connected to …` trace is re-emitted via
                // the hop sink, matching curl's per-connection logging.
                if conn_alive {
                    // The kept-alive connection carries the next attempt (curl's
                    // same-connection challenge-response retry).
                    conn_is_fresh = false;
                } else {
                    conn = http_connect_hop(
                        data,
                        &mut hop,
                        is_https,
                        host.clone(),
                        host_ace.clone(),
                        port,
                        verbose,
                        httpwant,
                        ipver,
                        op_start,
                        &mut hop_sink,
                    )
                    .await?;
                    // Re-established connection (auth resend) — report the new
                    // socket to the multi's observer.
                    report_socket_to_observer(data, &conn);
                    conn_is_fresh = true;
                }
            };
            // Re-apply the deferred `CURLOPT_FAILONERROR` (`-f`/`--fail`) verdict
            // to the TERMINAL auth response. While a reactive-auth controller was
            // active, `drive_one`'s `defer_auth_fail` suppressed the failonerror
            // decision for the intermediate `401`/`407` challenges so the
            // negotiation could run to completion (an answerable challenge is not
            // a terminal error — curl's `http_should_fail` returns the
            // `data->state.authproblem` flag, FALSE during a live negotiation).
            // Now that negotiation has ended, make the real verdict against the
            // final status code: a transfer that authenticated successfully ends
            // `< 400` (no failure), while one that is still `401`/`407` (rejected
            // credentials, no acceptable scheme) fails with
            // `CURLE_HTTP_RETURNED_ERROR` (exit 22) exactly as curl does. Gated to
            // `auth_controller.is_some()` so a non-auth or single-scheme transfer
            // — whose `401`/`407` was already decided inline by `drive_one` — is
            // untouched (test 152 still fails `22`). (tests 150, 152, 162)
            let mut result = result;
            if (auth_controller.is_some() || proxy_auth_controller.is_some())
                && data.set.http_fail_on_error
                && result.is_ok()
                && http_should_fail(
                    hop_sink.status,
                    data.set.set_resume_from != 0,
                    data.set.method == HttpReq::Get,
                    data.set.str(StrId::Username).is_some(),
                    data.set.str(StrId::Proxyusername).is_some(),
                )
            {
                result = Err(CurlError::HttpReturnedError);
            }
            // Deliver the body of a terminal `401`/`407` (an unanswerable
            // challenge's error page) that was buffered during negotiation.
            hop_sink.flush_auth_body();
            result
        }
        HttpVersion::H2 => {
            #[cfg(feature = "http2")]
            {
                let mut custom_headers = collect_custom_headers(data);
                // On a cross-host redirect, drop the application's custom `Host:`
                // so the auto authority for the *current* host is used (curl's
                // per-hop rule; tests 184/185).
                if hop.suppress_custom_host {
                    strip_custom_host_header(&mut custom_headers);
                }
                // HTTP/2 sends a buffered body; if this upload was selected for
                // streaming on the (version-agnostic) build path but the hop
                // negotiated h2, materialize it from the source here so the h2
                // codec sees a buffered body (unchanged h2 behavior, no
                // regression). `source` is otherwise consumed only by the h1
                // branch, which does not run for an h2 hop.
                let body = materialize_streaming_body(body, source.take())?;
                let (req, h2_body, h2_no_body) = {
                    let inputs = make_inputs(
                        data,
                        url,
                        &conn,
                        &custom_headers,
                        &host_ace,
                        port,
                        is_https,
                        false,
                        body,
                        1,
                        &hop,
                    );
                    self::h2::build_h2_request(&inputs)?
                };
                let filter = conn.cfilter[FIRSTSOCKET]
                    .take_head()
                    .ok_or(CurlError::FailedInit)?;
                let io = self::h2::ConnFilterIo::new(filter);
                let mut h2conn =
                    self::h2::h2_client_handshake(io, self::h2::H2Settings::default()).await?;
                let mut exchange = h2conn.start_exchange(req, h2_body, h2_no_body).await?;
                let result =
                    drive_one(data, &mut exchange, &mut hop_sink, op_start, false).await;
                h2conn.close();
                result
            }
            #[cfg(not(feature = "http2"))]
            {
                let _ = body;
                Err(CurlError::NotBuiltIn)
            }
        }
        HttpVersion::H3 => {
            let _ = body;
            Err(CurlError::UnsupportedProtocol)
        }
    };

    // Surface a resumed-download range failure detected at first-body-write
    // (curl's `http_firstwrite` returning `CURLE_RANGE_ERROR`). `HopSink`
    // discarded the body (the local output file is left untouched) and signaled a
    // short write to abort the read loop promptly, so `drive_result` may carry a
    // `WriteError` from that abort — the range error takes precedence and is
    // checked FIRST, mirroring curl propagating `CURLE_RANGE_ERROR` (33) directly
    // from the write path.
    if hop_sink.range_error {
        return Err(CurlError::RangeError);
    }
    // Surface a client-side time-condition miss detected at first-body-write
    // (curl's `http_firstwrite` "Simulate an HTTP 304 response"): `HopSink`
    // discarded the body, and curl reports a synthetic `304` with
    // `CURLINFO_CONDITION_UNMET` set. This is NOT an error — curl returns
    // `CURLE_OK` — so the transfer completes successfully with an empty body and
    // the response code published here overrides the real `200` that `drive_one`
    // recorded from the status line, exactly as curl overwrites `data->info.httpcode
    // = 304`.
    if hop_sink.condition_unmet {
        data.info.timecond = true;
        data.info.response_code = 304;
    }
    drive_result?;

    // CURLINFO_HTTP_VERSION (`%{http_version}`): set from the authoritative wire
    // version actually used for this hop. The h1 `Request` struct does not carry
    // the version, so `drive_one` left `data.info.http_version` at `0`; override
    // it here with curl's internal 10/11/20/30 encoding (`map_http_version`
    // translates it to the public `CURL_HTTP_VERSION_*` value the queries return).
    data.info.http_version = match version {
        HttpVersion::Http10 => 10,
        HttpVersion::Http11 => 11,
        HttpVersion::H2 => 20,
        HttpVersion::H3 => 30,
    };

    // Hand the captured per-hop facts to the orchestrator (ends the `sink`
    // borrow held by `HopSink`).
    let HopSink {
        status,
        location,
        headers,
        content_type,
        retry_after,
        #[cfg(feature = "cookies")]
        set_cookies,
        #[cfg(feature = "hsts")]
        sts,
        #[cfg(feature = "alt-svc")]
        alt_svc,
        ..
    } = hop_sink;

    // CURLINFO_RETRY_AFTER (`%{retry_after}`): the final response block's
    // parsed `Retry-After` (seconds-from-now), captured by `HopSink`. Only a
    // present header overwrites the value reset to 0 by `pre_perform`, matching
    // curl's `http_header_r`, which assigns `data->info.retry_after` solely when
    // the header appears. The CLI retry machinery consults this to weigh a
    // server back-off against `--retry-max-time` (oracle test366).
    if let Some(ra) = retry_after {
        data.info.retry_after = ra;
    }

    // CURLINFO_CONTENT_TYPE (`%{content_type}`, `%header{Content-Type}` via the
    // store below): the final response block's `Content-Type`, captured by
    // `HopSink` while observing the headers. `None`/un-encodable → unset.
    data.info.content_type = content_type.and_then(|v| CString::new(v).ok());

    // Populate the libcurl header store (`HeaderCollector`) with the final
    // response block's header lines so `curl_easy_header()` (AAP §0.7.2) and the
    // CLI's `%header{name}` write-out can read them back. The status line is not
    // a `name: value` header and `HopSink` already excluded it (curl's header API
    // stores only real headers); any residually malformed line is skipped via the
    // discarded `push` error. `pre_perform` reset the collector at transfer start,
    // so these are exactly this transfer's response headers.
    {
        let collector = data.headers_mut();
        for line in &headers {
            let _ = collector.push(line, CURLH_HEADER);
        }
    }

    // ---- Connection reuse: check the connection back in (Issue 3) -----------
    // A keep-alive-eligible HTTP/1.x connection is returned to the handle's pool
    // so the next transfer to the same destination reuses it. `drive_one`'s
    // `apply_connection_reuse` already set `conn.is_closed()` from the response's
    // keep-alive signal (`Connection: close`, HTTP/1.0 without keep-alive, a
    // half-closed socket, …), so `!conn.is_closed()` is precisely curl's reuse
    // eligibility. HTTP/2 and HTTP/3 connections are NOT pooled here: the h2 path
    // takes the socket filter out of the chain and closes the session, leaving
    // the `Connection` spent. `CURLOPT_FORBID_REUSE` closes instead of pooling.
    if !data.set.reuse_forbid
        && matches!(version, HttpVersion::Http10 | HttpVersion::Http11)
        && !conn.is_closed()
    {
        conn.bits.in_cpool = true;
        let pool = data.conn_pool_handle();
        let maxconnects = data.set.maxconnects;
        crate::conn::pool_checkin(&pool, conn, maxconnects);
    }
    // Otherwise `conn` drops at function end, closing its socket.

    Ok(HopResult {
        status,
        location,
        #[cfg(feature = "cookies")]
        set_cookies,
        #[cfg(feature = "hsts")]
        sts,
        #[cfg(feature = "alt-svc")]
        alt_svc,
    })
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
    hop: &HopInputs,
    body: h1::RequestBody,
    sink: &mut dyn WriteCallbacks,
    verbose: bool,
) -> Result<()> {
    use crate::protocols::http::h3::{build_h3_request, h3_alpn, Http3Session};

    // Operation start for the transfer timings, captured before resolve/connect
    // and threaded into `drive_one` to seed `Progress` (see `perform_http_hop`).
    let op_start = Instant::now();

    // HTTP/3 is https-only (curl rejects `--http3` on a cleartext URL).
    let scheme = url.get(CurlUPart::Scheme, 0).unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(CurlError::UnsupportedProtocol);
    }

    // ACE-encode a Unicode host to its `xn--` Punycode form so the `:authority`
    // pseudo-header and the QUIC TLS SNI carry the wire form, matching the
    // h1/h2 path and curl (`Curl_idnconvert_hostname`). Idempotent for an ASCII
    // or already-`xn--` host; `CURLE_URL_MALFORMAT` for an un-encodable name.
    let host_ace = crate::idn::to_ascii(host)?;
    let host = host_ace.as_str();

    // Resolve the UDP endpoint (honoring `--connect-to`/`--resolve`).
    let (connect_host, connect_port) = connect_target(data, host, port);
    let addrs = resolve_addrs(data, &connect_host, connect_port, ipver, verbose).await?;
    let addr = addrs
        .addrs
        .first()
        .copied()
        .ok_or(CurlError::CouldntResolveHost)?;

    // The request body (POST/upload) was buffered by the caller so the shared
    // request builder can frame it (Content-Length / Transfer-Encoding) and the
    // QUIC send stream can push it before the response is read.

    // Build the request via the SAME shared h1 builder the TCP h1/h2 paths use,
    // then translate its serialized head to HTTP/3. This delivers full wire
    // parity (G6) with h1/h2: the correct method (a `-d` POST stays POST —
    // `make_inputs` sets `is_upload = method == Put`, so it is never coerced to
    // PUT), `Host` → `:authority`, `User-Agent`, `Accept`, `Content-Length`,
    // the default `Content-Type` for a plain POST, and every custom `-H` header.
    let is_upload = hop.method == HttpReq::Put;
    let authority = h1::build_host_header_value(host, port, true);
    // A throwaway direct connection only to compute the origin-form target
    // (HTTP/3 has no forward-proxy absolute-form here).
    let path = {
        let conn = Connection::new("h3", crate::conn::TRNSPRT_QUIC, http_scheme_descriptor(true));
        h1::request_target(url, &conn, None, false, false)?
    };
    let resolved = h1::resolve_http_method(
        hop.method,
        hop.no_body,
        data.set.str(StrId::Customrequest),
        false,
        is_upload,
    )?;

    // Derive the full request header set from the shared builder's serialized
    // head (`make_inputs` + `build_request`), exactly as the h2 path does via
    // `build_h2_request`. `build_h3_request` drops the hop-by-hop fields itself
    // (incl. `Host`, which becomes `:authority`), so the complete list is passed
    // through unchanged.
    let mut custom_headers = collect_custom_headers(data);
    // On a cross-host redirect, drop the application's custom `Host:` so the auto
    // `:authority` for the *current* host is used (curl's per-hop rule). The
    // forced-HTTP/3 path is single-shot today, so this is a no-op in practice, but
    // it keeps the rule consistent across all HTTP versions (tests 184/185).
    if hop.suppress_custom_host {
        strip_custom_host_header(&mut custom_headers);
    }
    let (request_headers, h3_body) = {
        let conn = Connection::new("h3", crate::conn::TRNSPRT_QUIC, http_scheme_descriptor(true));
        let inputs = make_inputs(
            data,
            url,
            &conn,
            &custom_headers,
            host,
            port,
            true,
            false,
            body,
            1,
            hop,
        );
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
    // `--pinnedpubkey` (`CURLOPT_PINNEDPUBLICKEY`) is enforced post-handshake
    // over HTTP/3 exactly as it is for HTTP/1.1 and HTTP/2, so a wrong pin
    // aborts the connection (`CURLE_SSL_PINNEDPUBKEYNOTMATCH`) on every wire
    // version — including under `--insecure`, which curl enforces independently
    // of CA validation.
    let h3_pin = data.set.str(StrId::SslPinnedPublicKey);
    let session = Http3Session::connect(addr, host, tls, h3_pin).await?;
    let mut exchange = session.send_request(req).await?;

    // Push the request body (POST or PUT) on the QUIC send stream. Decoupled
    // from `is_upload` so a `-d` POST body (no longer an "upload") is still sent.
    let bytes = match h3_body {
        h1::RequestBody::Sized(b) => b,
        // HTTP/3 carries the body in QUIC stream DATA, not chunked framing, so
        // the per-read blocks are flattened to the raw payload (chunked trailers
        // do not apply to the HTTP/3 framing and are ignored here).
        h1::RequestBody::Chunked(blocks, _) => blocks.concat(),
        h1::RequestBody::None => Vec::new(),
        // The HTTP/3 body is built with `allow_stream = false`, so a streamed
        // body never reaches this path; handled for exhaustiveness only.
        h1::RequestBody::Streaming { .. } => Vec::new(),
    };
    let mut offset = 0;
    while offset < bytes.len() {
        let sent = exchange.send_body(&bytes[offset..]).await?;
        if sent == 0 {
            break;
        }
        offset += sent;
    }

    let result = drive_one(data, &mut exchange, sink, op_start, false).await;
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

    // Operation start for the handshake transfer timings, captured before
    // resolve/connect and threaded into `drive_one` to seed `Progress`.
    let op_start = Instant::now();

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
        // `CURLOPT_PATH_AS_IS` must preserve the literal `..`/`.` segments of the
        // *given* URL path, so the initial parse forwards `CURLU_PATH_AS_IS` when
        // it is set — exactly as C does in `lib/url.c` (the `!use_set_uh` branch
        // passes `data->set.path_as_is ? CURLU_PATH_AS_IS : 0`). Without this the
        // parser would dedotdotify the request path (e.g. `/../../NNN` → `/NNN`),
        // diverging from curl on the first request line. The relative-redirect
        // resolution still strips dot segments per RFC 3986 (the merge re-parses
        // with `CURLU_PATH_AS_IS` masked off), so a followed `Location` is
        // normalized regardless.
        let path_as_is = if data.set.path_as_is {
            CURLU_PATH_AS_IS
        } else {
            0
        };
        parsed
            .set(
                CurlUPart::Url,
                Some(&url_str),
                CURLU_GUESS_SCHEME | CURLU_DEFAULT_PORT | path_as_is,
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
    // The WebSocket handshake carries no upload body; build the buffered body.
    let body = build_request_body(data, source, false)?;
    // The WebSocket Upgrade is a single HTTP/1.1 hop (no redirect following), so
    // the per-hop overrides are the single-shot defaults sourced from `data.set`.
    let hop = HopInputs::single_shot(data);
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
                &hop,
            );
            h1::build_request(&inputs)?
        };
        let mut exchange = h1::H1Exchange::new(
            h1::ConnByteStream::new(&mut conn),
            plan,
            data.set.http09_allowed,
            false,
        );
        drive_one(data, &mut exchange, sink, op_start, false).await?;
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

/// Builds the transfer rate limiter from the handle's configured speed caps,
/// or `None` when both directions are unlimited.
///
/// `recv` is `CURLOPT_MAX_RECV_SPEED_LARGE` and `send` is
/// `CURLOPT_MAX_SEND_SPEED_LARGE` (the CLI surfaces both through `--limit-rate`,
/// which sets the two symmetrically). A value of `0` disables that direction's
/// cap, exactly as libcurl treats an unset/zeroed `curl_off_t` speed limit.
///
/// Returning `None` when neither direction is capped keeps the unlimited fast
/// path free of any per-tick rate accounting — the transfer driver's throttle
/// branch is `if let Some(rl) = …`, so an absent limiter is a true no-op.
///
/// `setopt` already rejects negative caps with `CURLE_BAD_FUNCTION_ARGUMENT`
/// (so the stored values are non-negative here); the defensive `.max(0)` clamp
/// makes [`RateLimit::set_recv_limit`]/[`RateLimit::set_send_limit`] infallible
/// regardless, so their `Result` can be discarded.
fn build_rate_limit(recv: i64, send: i64) -> Option<RateLimit> {
    if recv <= 0 && send <= 0 {
        return None;
    }
    let mut rl = RateLimit::new(Instant::now());
    let _ = rl.set_recv_limit(recv.max(0));
    let _ = rl.set_send_limit(send.max(0));
    Some(rl)
}

/// Run the transfer-engine byte loop for a prepared `exchange`, delivering the
/// response through the client `sink`. Bundles the per-transfer state
/// ([`Request`]/[`Progress`]/[`ClientWriter`]/[`ErrorBuffer`]/[`TransferLimits`])
/// the same way curl's `Curl_sendrecv` does, reading the handle's `CURLOPT_*`
/// limits (`HEADER`, `VERBOSE`, `TIMEOUT(_MS)`, `LOW_SPEED_*`).
async fn drive_one<P: ProtocolExchange>(
    data: &mut Easy,
    exchange: &mut P,
    sink: &mut dyn WriteCallbacks,
    // The hop's operation-start instant, captured by the caller *before* DNS
    // resolution and connection setup. Seeding [`Progress`] with it (rather than
    // `Instant::now()` here, after the connection is already up) makes the
    // recorded `CURLINFO_TOTAL_TIME` / `CURLINFO_STARTTRANSFER_TIME` measure from
    // the true start of the operation — matching curl's `Curl_pgrsStartNow`,
    // which is called at transfer start, not after connect.
    op_start: Instant,
    // Whether `CURLOPT_FAILONERROR` (`-f`/`--fail`) must be DEFERRED for an
    // intermediate `401`/`407`. Set `true` only by the HTTP/1.x reactive-auth
    // hop loop while a challenge-response controller is active: an answerable
    // `401`/`407` is the server's auth *challenge*, not a terminal error, so
    // failonerror must not abort the negotiation mid-handshake (curl's
    // `http_should_fail` returns `data->state.authproblem`, FALSE while the
    // negotiation can still answer). The caller re-applies the real
    // `http_should_fail` verdict to the TERMINAL response after the loop ends.
    // All other call sites (h2/h3/websocket, and any non-auth transfer) pass
    // `false`, so a `401`/`407` fails immediately exactly as before. (test 150)
    defer_auth_fail: bool,
) -> Result<()> {
    let mut request = Request::new();
    // Seed `no_body` from the easy handle, mirroring curl's `Curl_req_hard_reset`
    // (`request->no_body == data->set.opt_no_body`). This is essential for HEAD
    // (`-I` / `CURLOPT_NOBODY`): the response still carries `Content-Length`, so
    // `drive_transfer`'s end-of-transfer `check_partial_file` would otherwise see
    // `size = Some(n)` but `bytecount = 0` and wrongly report `CURLE_PARTIAL_FILE`.
    // With `no_body = true` that check short-circuits, matching curl.
    request.no_body = data.set.opt_no_body;
    let mut progress = Progress::new(op_start);
    // Anchor the operation and single-transfer clocks at `op_start` so the
    // cumulative phase milestones (`Timer::PreTransfer` / `Timer::StartTransfer`,
    // recorded inside `drive_transfer`) accumulate `(now − op_start)` exactly as
    // curl's `Curl_pgrsTime(TIMER_*)` does relative to `t_startsingle`. Without
    // an anchored single-start the phase deltas would collapse to the minimal one
    // microsecond. (`StartOp` also re-bases the queue clock; harmless for a
    // single transfer.)
    progress.time(Timer::StartOp, op_start);
    progress.time(Timer::StartSingle, op_start);
    let mut writer = ClientWriter::with_options(data.set.include_header, false);
    // curl only auto-decompresses a `Content-Encoding` response body when the
    // user opted in via `--compressed` / `CURLOPT_ACCEPT_ENCODING` (so
    // `STRING_ENCODING` is set) *and* content decoding is not disabled
    // (`CURLOPT_HTTP_CONTENT_DECODING`, tracked as `http_ce_skip`). An
    // unsolicited `Content-Encoding` is passed through raw — G6 byte-parity and
    // the minimal-change mandate (F6-008).
    writer.set_content_decoding_enabled(
        data.set.str(StrId::Encoding).is_some() && !data.set.http_ce_skip,
    );
    let mut errbuf = ErrorBuffer::with_verbose(data.set.verbose);
    let deadline = (data.set.timeout > 0)
        .then(|| Instant::now() + Duration::from_millis(data.set.timeout as u64));
    let limits = TransferLimits {
        deadline,
        low_speed_limit: data.set.low_speed_limit,
        low_speed_time: u32::from(data.set.low_speed_time),
        max_filesize: data.set.max_filesize,
    };
    // Build the `CURLOPT_FAILONERROR` (`-f`/`--fail`) predicate once, before the
    // byte loop. It is `Some` only when failonerror is set; the closure captures
    // `Copy` flags (so it borrows nothing from `data`, leaving `data` free to
    // mutate afterward) and is `Send + Sync` for the multi-handle spawn. The
    // HTTP-specific should-fail rules live in `http_should_fail`, so the generic
    // `drive_transfer` loop stays protocol-agnostic — curl likewise confines
    // `http_should_fail()` to `lib/http.c`.
    let fail_closure = data.set.http_fail_on_error.then(|| {
        let resume = data.set.set_resume_from != 0;
        let is_get = data.set.method == HttpReq::Get;
        let has_user = data.set.str(StrId::Username).is_some();
        let has_proxy_user = data.set.str(StrId::Proxyusername).is_some();
        move |code: i32| {
            failonerror_verdict(defer_auth_fail, code, resume, is_get, has_user, has_proxy_user)
        }
    });
    let fail_ref: Option<&(dyn Fn(i32) -> bool + Send + Sync)> = fail_closure
        .as_ref()
        .map(|c| c as &(dyn Fn(i32) -> bool + Send + Sync));

    // Build the receive/send rate limiter from `CURLOPT_MAX_RECV_SPEED_LARGE` /
    // `CURLOPT_MAX_SEND_SPEED_LARGE` (`--limit-rate`). The limiter borrows
    // nothing from `data` (the caps are `Copy` `i64`s), so `data` stays free to
    // mutate after the transfer (the post-transfer `data->info` store below).
    // The receive cap is enforced inside `drive_transfer`'s response loop via
    // this `Some(&mut rl)`; the send cap is carried for the streaming
    // request-body send path. `None` on the unlimited path preserves the fast,
    // accounting-free transfer.
    let mut rate_limit = build_rate_limit(data.set.max_recv_speed, data.set.max_send_speed);
    let rate_ref = rate_limit.as_mut();

    let outcome = drive_transfer(
        TransferParts {
            // Reborrow so `exchange` remains usable after `drive_transfer`
            // returns, to read its written-byte counters into `data.info` below.
            exchange: &mut *exchange,
            request: &mut request,
            progress: &mut progress,
            writer: &mut writer,
            write_cb: sink,
            limits: &limits,
            errbuf: &mut errbuf,
        },
        None,
        rate_ref,
        fail_ref,
    )
    .await;

    // Record the post-transfer `data->info` store so `curl_easy_getinfo`
    // (CURLINFO_RESPONSE_CODE / SIZE_DOWNLOAD / SIZE_UPLOAD / HTTP_VERSION) and
    // the CLI's `--write-out` observe the real values, mirroring the typestate
    // transfer's `complete()` finalize (curl's `Curl_pgrsUpdate` + the
    // `PureInfo` fields). Without this, those fields would stay at their `0`
    // defaults even after a fully successful transfer (e.g. `%{http_code}` would
    // report `000`). The Easy-handle `Info` has no `record_progress` helper (that
    // lives on the typestate `TransferInfo`), so the fields are set directly.
    //
    // This runs REGARDLESS of `outcome`: curl sets `data->info.httpcode` while
    // processing the response headers, independent of the failonerror abort, so a
    // `-f` transfer that fails with `CURLE_HTTP_RETURNED_ERROR` must still expose
    // the real status — `%{http_code}` and the CLI's `"The requested URL returned
    // error: <code>"` message both read it back via `CURLINFO_RESPONSE_CODE`.
    data.info.response_code = i64::from(request.httpcode);
    data.info.http_version = i64::from(request.httpversion);
    data.info.size_download = progress.download_size();
    // Publish the upload payload (CURLINFO_SIZE_UPLOAD / `%{size_upload}`) and
    // the total request size (CURLINFO_REQUEST_SIZE / `%{size_request}`) from
    // the exchange's written-byte counters. curl's HTTP/1.x send path
    // (`Curl_xfer_send`) accumulates each write into `data->progress.uploaded`
    // and `data->req.writebytecount` / `request_size`; the safe core counts the
    // same bytes on the `H1Exchange` (the request head is always written; a
    // sized body counts verbatim, a chunked body counts its framed bytes toward
    // the request size and its raw payload toward the upload size). The
    // direct-write H1 send path never touches `request.writebytecount` (which
    // the byte-loop samples for the progress callback), so seed the progress
    // upload counter here so `upload_size()` reflects the real total. Per curl,
    // `request_size` ACCUMULATES across hops within one perform — `pre_perform`
    // resets `data.info` exactly once per `curl_easy_perform` (redirect/auth
    // resends add to the same total). Non-HTTP/1.x exchanges report `0` (the
    // `ProtocolExchange` trait default), leaving their accounting unchanged.
    let uploaded = exchange.upload_size_sent() as i64;
    if uploaded > 0 {
        progress.set_upload_counter(uploaded);
    }
    data.info.size_upload = progress.upload_size();
    data.info.request_size += exchange.request_size_sent() as i64;

    // Finalize the elapsed-time accounting and publish the transfer-phase timings
    // and header byte count to `data->info`, mirroring curl's `Curl_pgrsDone` /
    // `Curl_pgrsUpdate` at end of transfer. `calc(now, true)` recomputes
    // `timespent = now − op_start` (the `req_done` flag forces a final sample),
    // which `CURLINFO_TOTAL_TIME[_T]` reads back. `Timer::PreTransfer` and
    // `Timer::StartTransfer` were captured inside `drive_transfer`; here we copy
    // their accumulated values across so `%{time_total}`, `%{time_starttransfer}`
    // and `%{time_pretransfer}` reflect the real transfer (they were previously
    // left at `0`). `header_size` is the running inbound-header byte total curl
    // exposes as `CURLINFO_HEADER_SIZE` (`%{size_header}`).
    progress.calc(Instant::now(), true);
    data.info.total_time_us = progress.total_time().as_micros();
    data.info.starttransfer_time_us = progress.starttransfer_time().as_micros();
    data.info.pretransfer_time_us = progress.pretransfer_time().as_micros();
    data.info.header_size = request.headerbytecount as i64;

    // Latch the decompression-bomb diagnostic so the front-end's `curl: (61)
    // <msg>` line and `%{errormsg}` carry curl's specific `failf` text rather
    // than the generic `CURLE_BAD_CONTENT_ENCODING` description. curl writes
    // `"Reject response due to more than 5 content encodings"` from
    // `Curl_build_unencoding_stack`; the safe core records the equivalent on the
    // handle (the C `CURLOPT_ERRORBUFFER` cannot be written from here — the
    // documented foundation limitation). Scoped to this one cause so no other
    // transfer error's diagnostic text changes.
    if matches!(outcome, Err(CurlError::TooManyContentEncodings)) {
        data.set_last_error(CurlError::TooManyContentEncodings.description());
    }

    // Surface any transfer error only after the info store is recorded.
    outcome?;
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

/// The custom headers to apply to a proxy `CONNECT` request, mirroring curl's
/// `HEADER_CONNECT` selection in `dynhds_add_custom` (`lib/http_proxy.c`):
///
/// * with separate headers in effect (`CURLOPT_HEADEROPT == CURLHEADER_SEPARATE`,
///   set by `--proxy-header`), the CONNECT uses the dedicated `CURLOPT_PROXYHEADER`
///   list (`data->set.proxyheaders`) — the regular `-H` list applies only to the
///   origin request;
/// * otherwise (unified headers) the CONNECT reuses the regular `-H` list
///   (`data->set.headers`).
///
/// curl-rs defaults `sep_headers` to `true` and the CLI sets `CURLHEADER_SEPARATE`
/// whenever a proxy or `--proxy-header` is in play, so in practice the CONNECT
/// draws from `proxyheaders` (empty unless `--proxy-header` was given, in which
/// case it carries those lines). The builder (`build_connect_request`) then
/// suppresses the auto-generated `Host`/`User-Agent`/`Proxy-Connection` whenever
/// the custom list overrides them and applies the `name:`/`name;` quirks — so a
/// `--proxy-header "User-Agent: X"` replaces the default CONNECT user agent
/// (oracle: tests/data/test287).
#[cfg(feature = "proxy")]
fn collect_connect_custom_headers(data: &Easy) -> Vec<String> {
    let list = if data.set.sep_headers {
        data.set.proxyheaders.as_ref()
    } else {
        data.set.headers.as_ref()
    };
    list.map(|l| {
        l.iter()
            .filter_map(|c| c.to_str().ok().map(String::from))
            .collect()
    })
    .unwrap_or_default()
}

/// Whether the user's custom header list contains a header named `target`,
/// mirroring curl's `Curl_checkheaders` (lib/http.c). This is curl's "did the
/// application provide header X" test, used to SUPPRESS the auto-generated
/// header of that name (`Host:`, `Accept:`, `Content-Range:`, `Expect:`, `TE:`).
///
/// curl matches the header NAME — the byte span up to the first `:` or `;`
/// delimiter — case-insensitively, and crucially does so REGARDLESS of the
/// header's value. That includes the two value-less directive forms: the
/// *disable* directive `-H "X:"` (empty value after the colon) and the
/// *blank-header* directive `-H "X;"`. Both suppress the auto-generated header
/// X; the custom-header emission then either sends the user's value or — for a
/// disable/blank directive — sends nothing, so the net result is that header X
/// is absent from the request. (Test oracle: tests/data/test461 — `-H "host:"`
/// disables the `Host:` header.)
///
/// Matching `Curl_checkheaders` exactly, the name span must be non-empty and
/// equal `target` with no trailing blanks before the delimiter (`"Host :"`
/// does NOT match, exactly as curl's `head->data[thislen] == ':'` test fails
/// when byte `thislen` is a space).
fn any_custom_header(lines: &[String], target: &str) -> bool {
    lines.iter().any(|line| {
        let bytes = line.as_bytes();
        match bytes.iter().position(|&b| b == b':' || b == b';') {
            Some(sep) if sep > 0 => line[..sep].eq_ignore_ascii_case(target),
            _ => false,
        }
    })
}

/// Remove the application's custom `Host:` header line(s) from `lines`.
///
/// Used on a cross-host redirect, where curl does NOT carry the original
/// request's custom `Host:` value to the new host and instead emits the auto
/// `Host:` for the redirect target (lib/http.c — the custom value is used only
/// when `!this_is_a_follow || curl_strequal(first_host, conn->host.name)`). The
/// header NAME is matched exactly as [`any_custom_header`] (the span up to the
/// first `:`/`;`, case-insensitive, non-empty), so the disable/blank directive
/// forms (`-H "Host:"`, `-H "Host;"`) are dropped too. After stripping,
/// `any_custom_header(lines, "Host")` is `false`, so the request builder emits
/// the auto `Host:` and the proxy header walk no longer re-emits the custom one
/// (avoiding a duplicate `Host:`).
fn strip_custom_host_header(lines: &mut Vec<String>) {
    lines.retain(|line| {
        let bytes = line.as_bytes();
        match bytes.iter().position(|&b| b == b':' || b == b';') {
            Some(sep) if sep > 0 => !line[..sep].eq_ignore_ascii_case("Host"),
            _ => true,
        }
    });
}

/// Derive the cookie-scoping host from a user-supplied `Host:` header value,
/// stripping any `:port` suffix and IPv6 brackets.
///
/// curl scopes cookie matching and storage to `data->state.aptr.cookiehost` —
/// the hostname from the application's custom `Host:` header — instead of the
/// connection/URL host, so that a request to `http://127.0.0.1:PORT/` carrying
/// `-H "Host: www.example.com"` matches and stores cookies for `www.example.com`
/// (curl tests 61/62/73). Returns `None` for an empty value (no override → the
/// URL host is used).
#[cfg(feature = "cookies")]
fn cookie_host_from_header_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    // IPv6 literal: `[addr]` or `[addr]:port` → `addr` (brackets removed).
    let host = if let Some(rest) = value.strip_prefix('[') {
        match rest.find(']') {
            Some(end) => &rest[..end],
            None => rest, // malformed (no closing bracket); best-effort
        }
    } else {
        // `host` or `host:port` → the part before the (single) port colon.
        match value.find(':') {
            Some(i) => &value[..i],
            None => value,
        }
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
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

/// Whether the application supplied a `Transfer-Encoding` request header at all,
/// and if so whether it selects chunked framing — the port of curl's
/// `http_req_set_TE` (lib/http.c) `if(ptr) … else …` split.
///
/// curl's `Curl_checkheaders(data, "Transfer-Encoding")` finds any user-provided
/// `Transfer-Encoding` header matched by NAME, *regardless of value* — including
/// the empty `-H "Transfer-Encoding:"` removal form (which
/// [`proxy::parse_custom_header_line`] classifies as `Skip`, so [`upload_is_chunked`]
/// alone cannot see it). When such a header is present, curl sets
/// `upload_chunky = Curl_compareheader(ptr, "Transfer-Encoding:", "chunked")` and
/// emits NO automatic `Transfer-Encoding`; only when it is absent does curl
/// auto-select chunked for an indeterminate-length upload.
///
/// Returns:
/// * `Some(true)`  — a `Transfer-Encoding` header whose value mentions `chunked`
///   (the application explicitly enabled chunked framing).
/// * `Some(false)` — a `Transfer-Encoding` header present but NOT chunked,
///   including the empty `-H "Transfer-Encoding:"` form that disables curl's
///   automatic chunking even for an unknown upload length (test98).
/// * `None`        — no `Transfer-Encoding` header at all; the caller falls back
///   to the automatic decision (chunked iff the a-priori upload size is unknown).
fn user_transfer_encoding(data: &Easy) -> Option<bool> {
    let list = data.set.headers.as_ref()?;
    for c in list.iter() {
        let Ok(line) = c.to_str() else { continue };
        // Match by header NAME (the span up to the first ':' or ';'), exactly as
        // `Curl_checkheaders` matches — the value (or its absence) does not affect
        // detection, only the chunked/not-chunked outcome below.
        let sep = line.find([':', ';']).unwrap_or(line.len());
        let name = line[..sep].trim();
        if name.eq_ignore_ascii_case("Transfer-Encoding") {
            // The value after a ':' delimiter; empty for the `-H "Transfer-Encoding:"`
            // removal form and for the `-H "Transfer-Encoding;"` blank-header form.
            let value = match line.as_bytes().get(sep) {
                Some(b':') => &line[sep + 1..],
                _ => "",
            };
            // curl's `Curl_compareheader(ptr, "Transfer-Encoding:", "chunked")`:
            // chunked iff the value mentions the token `chunked` (case-insensitive).
            return Some(value.to_ascii_lowercase().contains("chunked"));
        }
    }
    None
}

/// Build the request body for the transfer:
///
/// * `CURLOPT_COPYPOSTFIELDS` / `-d` -> a sized body of the copied bytes.
/// * `CURLOPT_MIMEPOST` / `-F` -> the pre-serialized multipart body (sized).
/// * An upload (`CURLOPT_UPLOAD` / `-T`, `method == Put`) or a `CURLOPT_POST`
///   without copied fields ->
///     * a [`h1::RequestBody::Streaming`] body (read incrementally, bounded
///       memory) when `allow_stream` is set and the upload is provably
///       single-pass — a known size (`CURLOPT_INFILESIZE[_LARGE]`), no
///       redirect-following, and no reactive auth — so the source is read
///       straight through exactly once (QA F11-PERF Issue #5);
///     * otherwise the source is read **fully** into a buffered `Chunked`/`Sized`
///       body (the proven path), so a resend across an auth challenge, a 307/308
///       redirect, or a missing size stays correct.
/// * Otherwise (GET/HEAD/DELETE without data) -> no body; `source` is untouched.
///
/// `allow_stream` is `true` only on the HTTP/1.x path; the HTTP/3 and WebSocket
/// callers pass `false` because those codecs send the buffered body directly and
/// have no streaming upload path.
fn build_request_body(
    data: &Easy,
    source: &mut dyn ReadCallback,
    allow_stream: bool,
) -> Result<h1::RequestBody> {
    // CURLOPT_MIMEPOST (`-F`/`--form`): the engine streams the pre-serialized
    // `multipart/form-data` body produced from the MIME tree. It is a known,
    // sized body (curl frames multipart with `Content-Length` when the size is
    // known), so it is delivered as `Sized`. The matching `Content-Type:
    // multipart/form-data; boundary=…` header is emitted by the request builder
    // from `set.mime_content_type` (see `make_inputs`).
    if let Some(body) = data.set.mime_body.as_ref() {
        return Ok(h1::RequestBody::Sized(body.clone()));
    }
    if let Some(fields) = data.set.copypostfields.as_ref() {
        // A user-forced `Transfer-Encoding: chunked` (`-H`) chunk-frames the
        // in-memory POST data rather than sending it under `Content-Length` —
        // curl honors the application's chosen transfer-encoding (the wire shows
        // a single chunk for the whole buffer, then the `0` terminator, with no
        // `Content-Length`). The length stays a-priori known (copypostfields),
        // so `client_upload_length` still reports it and no `Expect` is added.
        return Ok(if upload_is_chunked(data) {
            // The in-memory POST data is a single read block (one wire chunk).
            // A `CURLOPT_TRAILERFUNCTION` is still honored for the chunked
            // framing: curl invokes the trailer callback once at end-of-body in
            // `add_last_chunk` regardless of the body's source, so an in-memory
            // POST body (`CURLOPT_POSTFIELDS`/`COPYPOSTFIELDS` or `-d`) forced
            // chunked via `Transfer-Encoding: chunked` emits the trailers too.
            // The CLI `-d` path sets no trailer callback, so `trailers()` is
            // empty there (a bare `0\r\n\r\n`), unchanged.
            h1::RequestBody::Chunked(vec![fields.clone()], source.trailers())
        } else {
            h1::RequestBody::Sized(fields.clone())
        });
    }
    let reads_source = data.set.method == HttpReq::Put || data.set.method == HttpReq::Post;
    if reads_source {
        // Transfer-encoding selection (oracle: `lib/http.c` `http_req_set_TE`):
        //   * an explicit `Transfer-Encoding: chunked` header always chunks; else
        //   * an *indeterminate* upload length auto-selects chunked — curl does
        //     this on HTTP/1.1 (`req_clen < 0`), e.g. a `-T -` stdin PUT or a
        //     `CURLOPT_POST` read callback with no `POSTFIELDSIZE`. A known
        //     length (file size / `POSTFIELDSIZE` / in-memory data) uses
        //     `Content-Length` instead.
        // The body is built before the per-hop wire version is known; the h2/h3
        // engines flatten chunked blocks (never emitting chunked framing), and
        // the HTTP/1.0 "chunky upload unsupported" error path is unreachable here
        // (curl-rs issues HTTP/1.1 requests).
        // A user-supplied `Transfer-Encoding` header (curl's `Curl_checkheaders`,
        // matched by NAME) takes precedence over the automatic decision — exactly
        // curl's `http_req_set_TE` `if(ptr) … else …` split. When the application
        // provides ANY `Transfer-Encoding` header, chunked framing is used iff that
        // header selects `chunked`; the empty `-H "Transfer-Encoding:"` removal
        // form is present-but-not-chunked, so it DISABLES curl's automatic chunking
        // even for an indeterminate-length upload (test98: a `-T -` stdin PUT with
        // an explicit `Content-Length` sends a sized body, not chunked). Only when
        // no `Transfer-Encoding` header is supplied does curl auto-select chunked
        // for an unknown a-priori upload length.
        let chunked = match user_transfer_encoding(data) {
            Some(selects_chunked) => selects_chunked,
            None => known_upload_length(data).is_none(),
        };
        // Stream the upload (bounded memory) only when it is provably
        // single-pass, so the source is never re-read:
        //   * `known_size` — `CURLOPT_INFILESIZE[_LARGE]` is set (a regular `-T`
        //     file; the CLI seeds it from the file size). An unknown size keeps
        //     the buffered path (which still derives the length).
        //   * `!follow_enabled` — without `-L` the redirect loop runs a single
        //     hop, so the body is never re-sent to a redirect target.
        //   * `!needs_reactive` — Digest/NTLM/Negotiate/`--anyauth` re-send the
        //     body on a `401`/`407` challenge (and enable the reused-connection
        //     retry); a challenge-free Basic/Bearer/no-auth upload is sent once.
        // When any condition fails, fall back to the buffered read (unchanged
        // behavior), so redirected, reactive-auth, or unknown-size uploads keep
        // their proven resend/rewind semantics.
        let known_size = data.set.filesize >= 0;
        let follow_enabled = data.set.http_follow_mode != 0;
        // A resumed upload (`-C <n>`) repositions the source to the resume offset
        // and uploads only the remainder; the buffered path performs that
        // reposition (read-and-discard the leading bytes, curl's `cr_in_resume_from`
        // CANTSEEK fallback) and computes the post-seek `Content-Length`. The
        // streaming reader has no reposition step, so a resume always takes the
        // buffered path.
        let resume_upload = data.set.set_resume_from > 0;
        let streaming_ok = allow_stream
            && known_size
            && !follow_enabled
            && !resume_upload
            && !auth_engine::needs_reactive(data.set.httpauth);
        if streaming_ok {
            return Ok(h1::RequestBody::Streaming {
                size: Some(data.set.filesize as u64),
                chunked,
            });
        }
        if chunked {
            // A chunked upload preserves the read-callback boundaries: each
            // source read becomes one wire chunk (curl frames every
            // `Curl_creader_read` separately), so the body is buffered as a list
            // of blocks rather than one flat buffer. The `CURLOPT_TRAILERFUNCTION`
            // trailing headers are then collected from the source — curl invokes
            // the trailer callback once, at end-of-body, for a chunked upload
            // (the only framing that can carry trailers).
            let blocks = read_upload_blocks(source)?;
            let trailers = source.trailers();
            return Ok(h1::RequestBody::Chunked(blocks, trailers));
        }
        // A *declared* zero-length upload sends an empty body and reads nothing
        // from the source. curl's sized creader (`Curl_creader_set_fread` bounded
        // by `Curl_creader_total_length == 0`) returns EOF immediately and never
        // falls back to the default read callback / stdin, so a
        // `CURLOPT_POSTFIELDS, NULL` + `CURLOPT_POSTFIELDSIZE, 0` POST (or a
        // `0`-size `-T` PUT) must emit `Content-Length: 0` with no body — and
        // must NOT block reading a never-closing stdin. (A copypostfields/MIME
        // in-memory body is already returned above; an *unsized* upload, where
        // `known_upload_length` is `None`, still reads the source — that is the
        // intentional `-T -`/`-d @-` stdin path.)
        if known_upload_length(data) == Some(0) {
            return Ok(h1::RequestBody::Sized(Vec::new()));
        }
        let full = read_full_upload(source)?;
        // A resumed upload (`-C <n>` on a PUT/POST) "fast forwards" the source to
        // the resume offset and uploads only the remainder, with the resume
        // expressed via a `Content-Range` header (computed by
        // `effective_content_range`) rather than a whole-file `Content-Length`.
        // This mirrors curl's `http_resume` → `Curl_creader_resume_from`: it
        // seeks the client reader forward by `resume_from` (here, the buffered
        // CANTSEEK fallback — drop the leading bytes) and the advertised length
        // becomes the post-seek remainder. A resume offset at or past the end is
        // curl's "File already completely uploaded" → `CURLE_PARTIAL_FILE`.
        let resume_from = data.set.set_resume_from;
        if resume_from > 0 {
            let skip = resume_from as usize;
            if skip >= full.len() {
                return Err(CurlError::PartialFile);
            }
            return Ok(h1::RequestBody::Sized(full[skip..].to_vec()));
        }
        return Ok(h1::RequestBody::Sized(full));
    }
    // A POST_FORM/POST_MIME request whose form/MIME tree serialized to nothing
    // — e.g. `CURLOPT_HTTPPOST, NULL` (test516/lib516 "make an HTTPPOST set to
    // NULL") or an empty form/mime — still sends a body-framed request: curl's
    // `http_add_content_hds` frames `HTTPREQ_POST_FORM`/`HTTPREQ_POST_MIME`
    // with a `Content-Length`, so an empty body must advertise
    // `Content-Length: 0` (an empty `Sized` body) rather than omit it the way a
    // bodyless GET/HEAD (`None`) does. The non-empty case already returned its
    // serialized `mime_body` (`Sized`) at the top of this function, so reaching
    // here with one of these methods means there was no body to serialize.
    if matches!(data.set.method, HttpReq::PostForm | HttpReq::PostMime) {
        return Ok(h1::RequestBody::Sized(Vec::new()));
    }
    Ok(h1::RequestBody::None)
}

/// Collapse a [`h1::RequestBody::Streaming`] body back into a buffered
/// `Sized`/`Chunked` body by reading the upload `source` fully.
///
/// Only the HTTP/1.x codec sends a body incrementally; the HTTP/2 and HTTP/3
/// engines send a buffered body. Because the body is built once, up front,
/// before the per-hop wire version is known (it can be HTTP/2 over a negotiated
/// HTTPS connection), an upload that qualified for streaming may still be routed
/// to the h2 path. This helper restores the proven buffered behavior there with
/// no regression: a non-`Streaming` body is returned unchanged; a `Streaming`
/// body is materialized from the source (or to an empty body when no source is
/// available, which cannot occur for a genuine `Streaming` body).
fn materialize_streaming_body(
    body: h1::RequestBody,
    source: Option<&mut dyn ReadCallback>,
) -> Result<h1::RequestBody> {
    match body {
        h1::RequestBody::Streaming { chunked, .. } => Ok(if chunked {
            // Chunked: materialize as per-read blocks so each read frames as one
            // wire chunk (matching curl), consistent with the buffered path.
            // This path feeds the h2/h3 engines, which carry the body in their
            // own DATA frames and do not emit HTTP/1 chunked trailers, so the
            // trailer set is left empty here.
            let blocks = match source {
                Some(s) => read_upload_blocks(s)?,
                None => Vec::new(),
            };
            h1::RequestBody::Chunked(blocks, Vec::new())
        } else {
            let bytes = match source {
                Some(s) => read_full_upload(s)?,
                None => Vec::new(),
            };
            h1::RequestBody::Sized(bytes)
        }),
        other => Ok(other),
    }
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

/// Read the upload `source` to end-of-input as a list of **blocks**, one entry
/// per read-callback return (`CURLOPT_READFUNCTION` / one `Curl_creader_read`).
///
/// Unlike [`read_full_upload`], which concatenates everything into a single
/// buffer, this preserves the read-callback boundaries so a chunked upload can
/// frame each read as its own wire chunk (curl's behavior — see
/// [`chunks::encode_chunked_blocks`]). A zero-length return signals EOF and is
/// not retained as a block (a zero-size chunk is the body terminator, never a
/// data chunk). The per-read buffer is [`chunks::CURL_CHUNKED_MAXLEN`] (64 KiB),
/// curl's upload buffer granularity, so a large file or pipe is split into the
/// same chunk sizing curl emits. The [`CURL_READFUNC_ABORT`] /
/// [`CURL_READFUNC_PAUSE`] sentinels and an over-long return are handled exactly
/// as in [`read_full_upload`].
fn read_upload_blocks(source: &mut dyn ReadCallback) -> Result<Vec<Vec<u8>>> {
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![0u8; chunks::CURL_CHUNKED_MAXLEN];
    loop {
        match source.read(&mut buf) {
            0 => break,
            CURL_READFUNC_ABORT => return Err(CurlError::AbortedByCallback),
            CURL_READFUNC_PAUSE => return Err(CurlError::ReadError),
            n if n <= buf.len() => blocks.push(buf[..n].to_vec()),
            _ => return Err(CurlError::ReadError),
        }
    }
    Ok(blocks)
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
/// the handle's options and the per-hop overrides in [`HopInputs`].
///
/// Header-suppression flags (`Host`/`Accept`/`Expect` present) are derived from
/// the custom-header lines exactly as the builder's own lookup does. The per-hop
/// `hop` argument supplies the values that vary across a redirect chain or that
/// are produced by the stateful subsystems the orchestrator drives — the request
/// method and body framing, the merged `Cookie` header, the resolved `Referer`,
/// any `Authorization`/`Proxy-Authorization`, the cross-host credential gate
/// (`allowed_to_host`), proxy keep-alive, and a proxy absolute-URI request
/// target. For an un-redirected, un-proxied transfer these reduce to the handle's
/// own options, so the single-hop request is byte-for-byte unchanged.
/// Replace an upload payload with an explicit zero-length body for curl's
/// auth-negotiation probe (`conn->bits.authneg`). A POST/PUT sent during auth
/// negotiation advertises `Content-Length: 0` and transmits no data; the real
/// payload is sent only on the final, authenticated request. A request that has
/// no body ([`RequestBody::None`], i.e. GET/HEAD) is returned unchanged, so the
/// suppression is a no-op there.
fn suppress_upload_body(body: &h1::RequestBody) -> h1::RequestBody {
    match body {
        h1::RequestBody::None => h1::RequestBody::None,
        // A *chunked* upload keeps chunked framing on the auth-negotiation probe:
        // curl sends only the terminating `0\r\n\r\n` (an empty chunked body) and
        // does NOT switch to `Content-Length: 0`. The `Transfer-Encoding: chunked`
        // header — whether user-set (a `-H 'Transfer-Encoding: chunked'`, as in
        // `tests/data/test565`) or engine-added — stays, and emitting
        // `Content-Length: 0` alongside it would be a self-contradictory framing
        // that leaves a server waiting forever for the chunk terminator (the
        // `test565` probe hang / `GOT_NOTHING`). An empty `Chunked` body builds
        // `Transfer-Encoding: chunked` with no `Content-Length` and sends a lone
        // `0` chunk — byte-for-byte the `test565` probe.
        h1::RequestBody::Chunked(..) => h1::RequestBody::Chunked(Vec::new(), Vec::new()),
        // A streamed body is normally never paired with reactive auth (the engine
        // gates streaming off whenever `needs_reactive`), but suppress per its
        // framing for exhaustiveness: a chunked stream collapses to an empty
        // chunked probe, a sized stream to an empty `Content-Length: 0` probe.
        h1::RequestBody::Streaming { chunked: true, .. } => {
            h1::RequestBody::Chunked(Vec::new(), Vec::new())
        }
        // A sized upload suppresses to an empty `Content-Length: 0` probe body.
        h1::RequestBody::Sized(_) | h1::RequestBody::Streaming { .. } => {
            h1::RequestBody::Sized(Vec::new())
        }
    }
}

/// The a-priori known upload length declared by the application's options, or
/// `None` when the upload size is indeterminate (an unsized read callback, or a
/// `-T -` / `-T .` stdin upload).
///
/// This is curl's `Curl_creader_total_length` / `Curl_creader_client_length`
/// for the configured client reader, computed from the source the application
/// selected — *independent of the wire framing chosen later*:
///
/// * `CURLOPT_POSTFIELDS`/`COPYPOSTFIELDS` (`-d`) and `CURLOPT_MIMEPOST` (`-F`)
///   are in-memory sources — their length is always known.
/// * `CURLOPT_INFILESIZE[_LARGE]` (a `-T file` PUT — the CLI seeds it from the
///   file size) and `CURLOPT_POSTFIELDSIZE[_LARGE]` (a sized POST read callback)
///   declare the size up front.
/// * Everything else (an unsized read callback, `-T -`/`-T .` stdin) is
///   indeterminate.
///
/// Two distinct decisions consult this value (`lib/http.c`):
/// * `http_req_set_TE` auto-selects chunked transfer-encoding on HTTP/1.1 when
///   the length is indeterminate (`req_clen < 0`).
/// * `addexpect` adds `Expect: 100-continue` when the length is unknown
///   (`< 0`) or large (`> EXPECT_100_THRESHOLD`).
fn known_upload_length(data: &Easy) -> Option<i64> {
    if let Some(fields) = data.set.copypostfields.as_ref() {
        Some(fields.len() as i64)
    } else if let Some(body) = data.set.mime_body.as_ref() {
        Some(body.len() as i64)
    } else if data.set.method == HttpReq::Put && data.set.filesize >= 0 {
        Some(data.set.filesize)
    } else if data.set.method == HttpReq::Post && data.set.postfieldsize >= 0 {
        Some(data.set.postfieldsize)
    } else {
        None
    }
}

/// The CLIENT upload length curl's `Curl_creader_client_length` reports for the
/// `Expect: 100-continue` decision (`addexpect`): the *a-priori known* size of
/// the upload data source, or `-1` when unknown.
///
/// This is **independent of the wire framing**. curl's `addexpect`
/// (`lib/http.c`) consults the client reader's total via
/// `Curl_creader_client_length`, which is set when the application declares the
/// upload size up front and is `-1` for an unsized read callback / stdin upload:
///
/// * `CURLOPT_POSTFIELDS`/`COPYPOSTFIELDS` (`-d`) and `CURLOPT_MIMEPOST` (`-F`)
///   are in-memory sources — their length is always known.
/// * `CURLOPT_INFILESIZE[_LARGE]` (a `-T file` PUT) and
///   `CURLOPT_POSTFIELDSIZE[_LARGE]` (a sized POST read callback) declare the
///   size up front.
/// * An unsized read callback / stdin upload (`-T -`, a `CURLOPT_POST` read
///   callback with no `POSTFIELDSIZE`) reports `-1`.
///
/// Crucially, a chunked transfer of a *known* source still reports the known
/// length (so it gets no `Expect`), while a chunked transfer of an *unknown*
/// source reports `-1` **even though the engine has buffered the blocks** — the
/// buffered total must not be mistaken for an a-priori known length, or unsized
/// stdin/callback uploads would wrongly drop their `Expect`.
fn client_upload_length(data: &Easy, body: &h1::RequestBody) -> i64 {
    match body {
        // No body: a known zero-length client reader.
        h1::RequestBody::None => 0,
        // A fully-buffered sized body: report the a-priori SOURCE length, not
        // merely the buffered byte count. For an in-memory source (copypostfields/
        // MIME) or a declared-size upload (`CURLOPT_INFILESIZE`/`POSTFIELDSIZE`)
        // the two are equal, so this is unchanged for every previously-reachable
        // Sized body. But a sized-on-the-wire upload whose SOURCE size is unknown —
        // a `-T -` stdin PUT with chunking disabled and a user `Content-Length`
        // (test98) — has `known_upload_length == None`: curl's `addexpect` keys off
        // `Curl_creader_client_length` (the source size, `-1` here), so it still
        // adds `Expect: 100-continue` even though the wire is sized. Reporting the
        // declared source length (falling back to `-1` when never declared) mirrors
        // that, consistent with the `Chunked` arm below.
        h1::RequestBody::Sized(b) => {
            if matches!(data.set.method, HttpReq::PostForm | HttpReq::PostMime)
                && data.set.mime_body.is_none()
            {
                // An empty/NULL form or MIME post (e.g. `CURLOPT_HTTPPOST, NULL`,
                // test516/lib516): no `mime_body` was serialized, so the request body
                // is an empty `Sized` (`build_request_body`'s POST_FORM/POST_MIME
                // fall-through emits `Content-Length: 0`). The mime reader's a-priori
                // client length here is exactly that (zero) serialized byte count, so
                // curl's `addexpect` keys off a *known* length and adds no
                // `Expect: 100-continue`. A populated form/mime instead carries its
                // bytes in `mime_body` and reports its size via `known_upload_length`'s
                // `mime_body` arm (the `else` branch), unchanged.
                b.len() as i64
            } else {
                known_upload_length(data).unwrap_or(-1)
            }
        }
        // A streamed body carries its source-size knowledge directly.
        h1::RequestBody::Streaming { size, .. } => size.map_or(-1, |s| s as i64),
        // A chunked body's client length is the *declared source* size, not the
        // buffered block total: known only when the application declared it up
        // front. A known-size chunked upload reports its length (so it gets no
        // `Expect`), while an unsized read callback / stdin upload reports -1
        // (so curl adds `Expect`) even though the engine has buffered the blocks.
        h1::RequestBody::Chunked(..) => known_upload_length(data).unwrap_or(-1),
    }
}

/// Compute the effective `Range` *value* for the request, the port of curl's
/// `setup_range()` (lib/url.c) feeding `http_range()` (lib/http.c).
///
/// curl folds two distinct user inputs into a single `data->state.range`
/// string and then sends it as a `Range:` (download) or `Content-Range:`
/// (upload) header:
///
/// * An explicit `CURLOPT_RANGE` (`--range`/`-r`) value is used verbatim, for
///   any request method. This is a borrowed handle string.
/// * A `CURLOPT_RESUME_FROM[_LARGE]` (`-C <n>`) resume offset becomes the
///   open-ended range string `"<n>-"`. curl synthesizes this for both
///   downloads and uploads, but only the **download** (`GET`/`HEAD`) path is
///   produced here: an *upload* resume is expressed via a `Content-Range:`
///   header whose value also encodes the total length (and repositions the
///   upload body to the resume point), which is the separate
///   `effective_content_range()` path. Synthesizing a bare `Range:`/`"<n>-"`
///   for an upload would be wrong, so it is deliberately withheld here.
///
/// The two inputs are mutually exclusive at the CLI (`--continue-at` rejects a
/// combination with `--range`), matching curl, so the precedence here (explicit
/// range first) only ever resolves one of them.
fn effective_range(data: &Easy) -> Option<Cow<'_, str>> {
    if let Some(r) = data.set.str(StrId::SetRange) {
        return Some(Cow::Borrowed(r));
    }
    if data.set.set_resume_from != 0
        && matches!(data.set.method, HttpReq::Get | HttpReq::Head)
    {
        return Some(Cow::Owned(format!("{}-", data.set.set_resume_from)));
    }
    None
}

/// The effective upload `Content-Range` header value for a resumed POST/PUT
/// (`-C <n>` on an upload), or `None`.
///
/// This is the upload arm of curl's `http_range()` (lib/http.c): when a byte
/// range applies to a POST/PUT, curl emits a `Content-Range:` header (not a
/// `Range:` header) of the form `bytes <from>-<to>/<total>`, where:
///
/// * `<from>` is the resume offset (`data->state.resume_from`, i.e. `-C <n>`),
/// * `<total>` is the **full** declared upload size, and
/// * `<to>` is `<total> - 1`.
///
/// curl computes `<total>` as `authneg ? infilesize : (resume_from + req_clen)`.
/// For a known-size source those two are identical — the post-seek client-reader
/// length `req_clen` equals `infilesize - resume_from`, so `resume_from +
/// req_clen == infilesize` — so this uses the full declared size directly
/// (`known_upload_length`, i.e. `CURLOPT_INFILESIZE`/`POSTFIELDSIZE`), which is
/// both authneg-independent and matches curl's wire output exactly (e.g.
/// `tests/data/test33`: `-C 50` on a 100-byte PUT emits `Content-Range: bytes
/// 50-99/100`). The body itself is repositioned to the resume offset in
/// `build_request_body` (curl's `http_resume` → `Curl_creader_resume_from`), so
/// the advertised `Content-Length` is the post-seek remainder.
///
/// Returns `None` (no engine `Content-Range`) when:
/// * no resume offset is set (`resume_from <= 0`), or
/// * the request is not an upload (only PUT/POST carry an upload body), or
/// * the declared upload size is unknown (an unsized read-callback/stdin upload
///   — curl would have nothing meaningful to put in `<total>`), or
/// * the application already supplied its own `Content-Range:` header (curl's
///   `Curl_checkheaders(data, "Content-Range")` precedence).
fn effective_content_range(data: &Easy, custom_headers: &[String]) -> Option<String> {
    let resume_from = data.set.set_resume_from;
    if resume_from <= 0 {
        return None;
    }
    if !matches!(data.set.method, HttpReq::Put | HttpReq::Post) {
        return None;
    }
    if any_custom_header(custom_headers, "Content-Range") {
        return None;
    }
    // The full declared upload size (`CURLOPT_INFILESIZE`/`POSTFIELDSIZE`); an
    // indeterminate upload yields `None`, so no `Content-Range` is emitted.
    let total = known_upload_length(data)?;
    if total <= 0 || resume_from >= total {
        // A non-positive total has no range to express; a resume offset at or
        // past the end means there is nothing to upload (handled as
        // `CURLE_PARTIAL_FILE` in `build_request_body`), so emit no header.
        return None;
    }
    Some(format!("bytes {}-{}/{}", resume_from, total - 1, total))
}

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
    hop: &'a HopInputs,
) -> h1::RequestInputs<'a> {
    let (content_length, chunked) = match &body {
        h1::RequestBody::Sized(b) => (Some(b.len() as i64), false),
        h1::RequestBody::Chunked(..) => (None, true),
        h1::RequestBody::None => (None, false),
        // A streamed body carries its framing metadata directly: a known size
        // advertises `Content-Length` (the head builder uses `content_length`,
        // not the body bytes, so an empty-payload `Streaming` still emits the
        // correct header — wire parity), while a chunked stream advertises
        // `Transfer-Encoding: chunked` with no `Content-Length`.
        h1::RequestBody::Streaming { size, chunked } => {
            if *chunked {
                (None, true)
            } else {
                (size.map(|s| s as i64), false)
            }
        }
    };
    // The client reader's a-priori known length (or -1), for the
    // `Expect: 100-continue` decision — computed before `body` is moved.
    let client_upload_len = client_upload_length(data, &body);
    h1::RequestInputs {
        url,
        conn,
        method_kind: hop.method,
        no_body: hop.no_body,
        custom_request: data.set.str(StrId::Customrequest),
        is_websocket,
        is_upload: hop.method == HttpReq::Put,
        host,
        port,
        is_https,
        host_header_present: any_custom_header(custom_headers, "Host"),
        user_agent: data.set.str(StrId::Useragent),
        authorization: hop.authorization.as_deref(),
        proxy_authorization: hop.proxy_authorization.as_deref(),
        range: effective_range(data),
        content_range: effective_content_range(data, custom_headers),
        accept_present: any_custom_header(custom_headers, "Accept"),
        // `CURLOPT_TRANSFER_ENCODING` (`--tr-encoding`): announce `TE: gzip`
        // (and the matching `Connection: TE`, emitted in `h1.rs`) on HTTP/1.x
        // requests so the server may apply a compressed transfer-encoding.
        // Mirrors curl's `http_transfer_encoding` gate in `lib/http.c`, which
        // also honors a user-supplied `TE:` header (`Curl_checkheaders`) and
        // then leaves the announcement to the application.
        te_gzip: data.set.http_transfer_encoding && !any_custom_header(custom_headers, "TE"),
        accept_encoding: data.set.str(StrId::Encoding),
        referer: hop.referer.as_deref(),
        proxy_connection_keepalive: hop.proxy_connection_keepalive,
        cookie: hop.cookie.as_deref(),
        body,
        // `CURLOPT_MIMEPOST` (`-F`): the `multipart/form-data; boundary=…`
        // Content-Type derived from the MIME tree. `None` for every other method,
        // so the HTTP/1 builder's `application/x-www-form-urlencoded` default for
        // a plain `-d` POST is unaffected; the builder only applies this when the
        // application did not supply its own `Content-Type` header.
        content_type: data.set.mime_content_type.as_deref(),
        content_length,
        chunked,
        client_upload_len,
        disable_expect: false,
        expect_present: any_custom_header(custom_headers, "Expect"),
        custom_expect_100: false,
        is_upgrade: false,
        custom_headers,
        proxy_headers: &[],
        sep_headers: false,
        authneg: false,
        allowed_to_host: hop.allowed_to_host,
        http_minor,
        request_target_override: hop.request_target_override.as_deref(),
        // `CURLOPT_PROXY_TRANSFER_MODE` (`data.set.proxy_transfer_mode`): for an
        // `ftp://` URL driven AS HTTP over a forward proxy, append `;type=a`/
        // `;type=i` to the absolute request-target (`http::proxy::request_target`,
        // gated on the `ftp` scheme). Wired from the option so tests 549/550/561
        // emit the correct mode; `prefer_ascii` (below) selects `a` vs `i`.
        proxy_transfer_mode: data.set.proxy_transfer_mode,
        prefer_ascii: data.set.prefer_ascii,
        expect_100_timeout_ms: data.set.expect_100_timeout,
        // `CURLOPT_TIMECONDITION` + `CURLOPT_TIMEVALUE(_LARGE)` (`-z`): the h1
        // builder emits the conditional request header at `H1_HD_CONDITIONALS`.
        timecondition: data.set.timecondition,
        timevalue: data.set.timevalue,
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

    // ---- `der_to_pem`: DER → PEM armoring for `CURLINFO_CERTINFO` (test417) ----

    #[test]
    fn der_to_pem_wraps_armor_and_64_col_base64() {
        // 48 bytes of DER → base64 is exactly 64 chars (48 / 3 * 4), one line.
        let der: Vec<u8> = (0u8..48).collect();
        let pem = der_to_pem(&der);
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines[0], "-----BEGIN CERTIFICATE-----");
        assert_eq!(lines[lines.len() - 1], "-----END CERTIFICATE-----");
        // Exactly one base64 body line of 64 columns between the armor lines.
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1].len(), 64);
        // No trailing newline — the caller / writeout owns line termination.
        assert!(!pem.ends_with('\n'));
        assert!(pem.ends_with("-----END CERTIFICATE-----"));
    }

    #[test]
    fn der_to_pem_wraps_long_body_at_64_columns() {
        // 150 DER bytes → 200 base64 chars → 64 + 64 + 64 + 8 = 4 body lines,
        // the first three exactly 64 columns wide (OpenSSL PEM-writer width).
        let der: Vec<u8> = (0..150).map(|i| (i % 256) as u8).collect();
        let pem = der_to_pem(&der);
        let body: Vec<&str> = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        assert_eq!(body.len(), 4);
        assert_eq!(body[0].len(), 64);
        assert_eq!(body[1].len(), 64);
        assert_eq!(body[2].len(), 64);
        assert_eq!(body[3].len(), 8);
        // The base64 body is colon-free (so the test417 per-line `stripfile`
        // `s/^(.*):(.*)//` keeps every PEM line). The armor lines are too.
        assert!(pem.lines().all(|l| !l.contains(':')));
    }

    #[test]
    fn der_to_pem_empty_der_is_empty_armor() {
        let pem = der_to_pem(&[]);
        assert_eq!(pem, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----");
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

    // ---- pure orchestration helpers --------------------------------------
    //
    // The status/redirect/auth classifiers and the request-shaping helpers are
    // the deterministic core of the hop driver; they are exercised here in
    // isolation (the full hop flow needs a live socket).

    #[test]
    fn is_redirect_status_covers_3xx_only() {
        assert!(!is_redirect_status(200));
        assert!(!is_redirect_status(299));
        assert!(is_redirect_status(300));
        assert!(is_redirect_status(301));
        assert!(is_redirect_status(302));
        assert!(is_redirect_status(307));
        assert!(is_redirect_status(399));
        assert!(!is_redirect_status(400));
    }

    #[test]
    fn redirect_protocol_allowed_enforces_both_masks() {
        use crate::protocols::{
            CURLPROTO_ALL, CURLPROTO_FTP, CURLPROTO_FTPS, CURLPROTO_HTTP, CURLPROTO_HTTPS,
        };
        // curl's default `CURLOPT_REDIR_PROTOCOLS` = HTTP|HTTPS|FTP|FTPS.
        const REDIR: u32 = CURLPROTO_HTTP | CURLPROTO_HTTPS | CURLPROTO_FTP | CURLPROTO_FTPS;

        // Defaults (all allowed, default redir set): ordinary HTTP(S) redirects
        // proceed.
        assert!(redirect_protocol_allowed("http", CURLPROTO_ALL, REDIR));
        assert!(redirect_protocol_allowed("https", CURLPROTO_ALL, REDIR));
        assert!(redirect_protocol_allowed("ftp", CURLPROTO_ALL, REDIR));

        // `--proto-redir -http` clears the HTTP bit from the redir mask: an
        // `http://` redirect is denied, but `https://` still proceeds (test325).
        let no_http_redir = REDIR & !CURLPROTO_HTTP;
        assert!(!redirect_protocol_allowed("http", CURLPROTO_ALL, no_http_redir));
        assert!(redirect_protocol_allowed(
            "https",
            CURLPROTO_ALL,
            no_http_redir
        ));

        // A scheme outside the default redir set (e.g. `gopher`) is denied even
        // when generally allowed — matching curl's restrictive redirect default.
        assert!(!redirect_protocol_allowed("gopher", CURLPROTO_ALL, REDIR));

        // `--proto -http` (the general allow-list) also denies an HTTP redirect
        // regardless of the redir mask.
        assert!(!redirect_protocol_allowed(
            "http",
            CURLPROTO_ALL & !CURLPROTO_HTTP,
            REDIR
        ));

        // An unknown scheme has no protocol bit and is never allowed.
        assert!(!redirect_protocol_allowed(
            "bogus",
            CURLPROTO_ALL,
            CURLPROTO_ALL
        ));
    }

    #[test]
    fn http_should_fail_matches_curl_rules() {
        // < 400 never fails.
        assert!(!http_should_fail(204, false, true, false, false));
        // 416 on a resumed GET is the "already complete" exception.
        assert!(!http_should_fail(416, true, true, false, false));
        // 416 without resume is a normal failure.
        assert!(http_should_fail(416, false, true, false, false));
        // A plain 404 is terminal.
        assert!(http_should_fail(404, false, true, false, false));
        // 401 with no host credential is terminal.
        assert!(http_should_fail(401, false, true, false, false));
        // 401 even with a credential is terminal (no negotiation loop).
        assert!(http_should_fail(401, false, true, true, false));
        // 407 with no proxy credential is terminal.
        assert!(http_should_fail(407, false, true, false, false));
        // 407 with a proxy credential is still terminal here.
        assert!(http_should_fail(407, false, true, false, true));
    }

    #[test]
    fn failonerror_verdict_defers_intermediate_auth_challenges() {
        // With deferral OFF, the verdict is exactly `http_should_fail` (the
        // single-scheme / non-auth path, e.g. test 152): a `401`/`407` fails.
        assert!(failonerror_verdict(false, 401, false, true, true, false));
        assert!(failonerror_verdict(false, 407, false, true, false, true));
        // With deferral ON (a reactive controller is negotiating), an
        // intermediate `401`/`407` is the server's challenge, not a terminal
        // error, so the failonerror verdict is suppressed — the negotiation runs
        // to completion (test 150: the Type-2 `401` must not abort `--fail`).
        assert!(!failonerror_verdict(true, 401, false, true, true, false));
        assert!(!failonerror_verdict(true, 407, false, true, false, true));
        // Deferral only ever masks `401`/`407`. Any other status is decided by
        // `http_should_fail` unchanged, so a non-auth error still fails even
        // while a controller is active.
        assert!(failonerror_verdict(true, 404, false, true, true, false));
        assert!(failonerror_verdict(true, 500, false, true, true, false));
        // And a success is never a failure, deferral or not.
        assert!(!failonerror_verdict(true, 200, false, true, true, false));
        assert!(!failonerror_verdict(false, 200, false, true, true, false));
    }

    #[test]
    fn http_method_of_maps_each_request_kind() {
        assert_eq!(http_method_of(HttpReq::Get), HttpMethod::Get);
        assert_eq!(http_method_of(HttpReq::Post), HttpMethod::Post);
        assert_eq!(http_method_of(HttpReq::PostForm), HttpMethod::PostForm);
        assert_eq!(http_method_of(HttpReq::PostMime), HttpMethod::PostMime);
        assert_eq!(http_method_of(HttpReq::Put), HttpMethod::Put);
        assert_eq!(http_method_of(HttpReq::Head), HttpMethod::Head);
    }

    #[test]
    fn parse_status_code_reads_second_token() {
        assert_eq!(parse_status_code("1.1 302 Found"), Some(302));
        assert_eq!(parse_status_code("2 200 OK"), Some(200));
        // Missing code token.
        assert_eq!(parse_status_code("1.1"), None);
        // Non-numeric code.
        assert_eq!(parse_status_code("1.1 NaN Bad"), None);
        // Empty input.
        assert_eq!(parse_status_code(""), None);
    }

    #[test]
    fn parse_status_version_encodes_major_minor() {
        // `<major>*10 + <minor>` (curl's `k->httpversion`).
        assert_eq!(parse_status_version("1.0 401 Authorization Required"), Some(10));
        assert_eq!(parse_status_version("1.1 200 OK"), Some(11));
        // A missing minor defaults to 0 (HTTP/2 status lines carry no minor).
        assert_eq!(parse_status_version("2 200"), Some(20));
        assert_eq!(parse_status_version("3 200"), Some(30));
        // Malformed/empty version token yields None (caller keeps prior value).
        assert_eq!(parse_status_version(""), None);
        assert_eq!(parse_status_version("x.y 200"), None);
    }

    #[test]
    fn strip_brackets_unwraps_ipv6_literals_only() {
        assert_eq!(strip_brackets("[::1]"), "::1");
        assert_eq!(strip_brackets("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(strip_brackets("example.com"), "example.com");
        // An unbalanced bracket is left untouched.
        assert_eq!(strip_brackets("[half"), "[half");
    }

    #[test]
    fn take_host_field_and_plain_field_split_on_colon() {
        // Plain token up to the colon.
        assert_eq!(take_plain_field("443:rest"), ("443".to_string(), ":rest"));
        assert_eq!(take_plain_field("tail"), ("tail".to_string(), ""));
        // Bracketed IPv6 host keeps its brackets and resumes after ']'.
        let (h, rest) = take_host_field("[::1]:443");
        assert_eq!(h, "[::1]");
        assert_eq!(rest, ":443");
        // Plain host.
        let (h2, rest2) = take_host_field("example.com:80");
        assert_eq!(h2, "example.com");
        assert_eq!(rest2, ":80");
    }

    #[test]
    fn split_connect_to_parses_four_fields() {
        assert_eq!(
            split_connect_to("example.com:443:backend.internal:8080"),
            Some((
                "example.com".to_string(),
                "443".to_string(),
                "backend.internal".to_string(),
                "8080".to_string()
            ))
        );
        // IPv6 host fields keep their brackets.
        assert_eq!(
            split_connect_to("[::1]:443:[::2]:8080"),
            Some((
                "[::1]".to_string(),
                "443".to_string(),
                "[::2]".to_string(),
                "8080".to_string()
            ))
        );
        // Fewer than four fields ⇒ None.
        assert_eq!(split_connect_to("example.com:443:backend"), None);
    }

    #[test]
    fn connect_target_remaps_matching_entry() {
        let mut data = Easy::new();
        // No --connect-to ⇒ identity.
        assert_eq!(connect_target(&data, "example.com", 443), ("example.com".to_string(), 443));

        let mut list = SList::default();
        list.append("example.com:443:backend.internal:8080").unwrap();
        data.set.connect_to = Some(list);
        // Matching host+port ⇒ remapped.
        assert_eq!(
            connect_target(&data, "example.com", 443),
            ("backend.internal".to_string(), 8080)
        );
        // Non-matching port ⇒ identity (the entry's port filter fails).
        assert_eq!(
            connect_target(&data, "example.com", 80),
            ("example.com".to_string(), 80)
        );
    }

    #[test]
    fn any_custom_header_matches_case_insensitively() {
        let lines = vec![
            "Host: example.com".to_string(),
            "X-Trace: 1".to_string(),
        ];
        assert!(any_custom_header(&lines, "host"));
        assert!(any_custom_header(&lines, "X-TRACE"));
        assert!(!any_custom_header(&lines, "Authorization"));
    }

    #[test]
    fn any_custom_header_matches_disable_and_blank_directives() {
        // The disable directive `-H "host:"` (empty value, lowercase name) must
        // count as "Host present" so the auto-generated `Host:` is suppressed —
        // curl's `Curl_checkheaders` matches the name regardless of value.
        // Oracle: tests/data/test461.
        assert!(any_custom_header(&["host:".to_string()], "Host"));
        // The blank-header directive `-H "Accept;"` likewise counts.
        assert!(any_custom_header(&["Accept;".to_string()], "accept"));
        // A name with a trailing blank before the colon does NOT match (curl's
        // `head->data[thislen] == ':'` test fails on the space).
        assert!(!any_custom_header(&["Host :".to_string()], "Host"));
        // A leading-colon line (empty name) never matches.
        assert!(!any_custom_header(&[":bogus".to_string()], "Host"));
    }

    #[test]
    fn strip_custom_host_header_removes_only_host_lines() {
        // A cross-host redirect must drop the application's custom `Host:` so the
        // auto `Host:` for the new host is emitted (tests 184/185). Only `Host`
        // lines are removed; all other custom headers are preserved in order.
        let mut lines = vec![
            "Host: another.visitor.stay.a.while".to_string(),
            "X-Trace: 1".to_string(),
            "Accept: */*".to_string(),
        ];
        strip_custom_host_header(&mut lines);
        assert_eq!(
            lines,
            vec!["X-Trace: 1".to_string(), "Accept: */*".to_string()]
        );
        // After stripping, the auto `Host:` is no longer suppressed.
        assert!(!any_custom_header(&lines, "Host"));

        // Case-insensitive name match, and the disable/blank directive forms
        // (`host:`, `Host;`) are dropped too — matching `any_custom_header`.
        let mut lc = vec!["host: lower.example".to_string(), "X-Keep: y".to_string()];
        strip_custom_host_header(&mut lc);
        assert_eq!(lc, vec!["X-Keep: y".to_string()]);
        let mut disable = vec!["Host:".to_string(), "Host;".to_string(), "Keep: 1".to_string()];
        strip_custom_host_header(&mut disable);
        assert_eq!(disable, vec!["Keep: 1".to_string()]);

        // A header whose NAME merely starts with "Host" (e.g. a hypothetical
        // `Host-Override:`) is NOT a `Host:` header and must be preserved.
        let mut similar = vec!["Host-Override: x".to_string()];
        strip_custom_host_header(&mut similar);
        assert_eq!(similar, vec!["Host-Override: x".to_string()]);
    }

    #[cfg(feature = "cookies")]
    #[test]
    fn cookie_host_from_header_value_strips_port_and_brackets() {
        // Plain hostname (curl test 62's `Host: www.host.foo.com`).
        assert_eq!(
            cookie_host_from_header_value("www.host.foo.com").as_deref(),
            Some("www.host.foo.com")
        );
        // Hostname with a port ⇒ port stripped.
        assert_eq!(
            cookie_host_from_header_value("example.com:8080").as_deref(),
            Some("example.com")
        );
        // IPv6 literal with a port ⇒ brackets and port stripped.
        assert_eq!(
            cookie_host_from_header_value("[::1]:8080").as_deref(),
            Some("::1")
        );
        // IPv6 literal without a port ⇒ brackets stripped.
        assert_eq!(cookie_host_from_header_value("[fe80::1]").as_deref(), Some("fe80::1"));
        // Surrounding whitespace is trimmed (the value after `Host:`).
        assert_eq!(
            cookie_host_from_header_value("  host.example  ").as_deref(),
            Some("host.example")
        );
        // Empty / blank ⇒ no override (fall back to the URL host).
        assert_eq!(cookie_host_from_header_value(""), None);
        assert_eq!(cookie_host_from_header_value("   "), None);
    }

    #[test]
    fn upload_is_chunked_detects_explicit_te_header() {
        let mut data = Easy::new();
        // No headers ⇒ not chunked.
        assert!(!upload_is_chunked(&data));

        let mut list = SList::default();
        list.append("Transfer-Encoding: chunked").unwrap();
        data.set.headers = Some(list);
        assert!(upload_is_chunked(&data));

        // A different header value is not chunked.
        let mut other = SList::default();
        other.append("Content-Type: text/plain").unwrap();
        data.set.headers = Some(other);
        assert!(!upload_is_chunked(&data));
    }

    #[test]
    fn user_transfer_encoding_detects_presence_and_chunked() {
        // No `Transfer-Encoding` header at all ⇒ None (caller auto-decides).
        let mut data = Easy::new();
        assert_eq!(user_transfer_encoding(&data), None);

        let mut other = SList::default();
        other.append("Content-Type: text/plain").unwrap();
        data.set.headers = Some(other);
        assert_eq!(user_transfer_encoding(&data), None);

        // An explicit `Transfer-Encoding: chunked` ⇒ Some(true).
        let mut chunked = SList::default();
        chunked.append("Transfer-Encoding: chunked").unwrap();
        data.set.headers = Some(chunked);
        assert_eq!(user_transfer_encoding(&data), Some(true));

        // The empty `-H "Transfer-Encoding:"` removal form: present but NOT
        // chunked ⇒ Some(false). This is the test98 case — it must DISABLE curl's
        // automatic chunking even for an unknown-length stdin upload, where
        // `upload_is_chunked` alone (which only sees `Add`) returns false.
        let mut empty = SList::default();
        empty.append("Transfer-Encoding:").unwrap();
        data.set.headers = Some(empty);
        assert_eq!(user_transfer_encoding(&data), Some(false));
        assert!(!upload_is_chunked(&data), "the Skip-classified empty form is invisible to upload_is_chunked");

        // Case-insensitive name match and chunked-token detection.
        let mut mixed = SList::default();
        mixed.append("transfer-encoding: CHUNKED").unwrap();
        data.set.headers = Some(mixed);
        assert_eq!(user_transfer_encoding(&data), Some(true));
    }

    #[test]
    fn collect_custom_headers_returns_each_line() {
        let mut data = Easy::new();
        assert!(collect_custom_headers(&data).is_empty());

        let mut list = SList::default();
        list.append("X-One: 1").unwrap();
        list.append("X-Two: 2").unwrap();
        data.set.headers = Some(list);
        let got = collect_custom_headers(&data);
        assert_eq!(got, vec!["X-One: 1".to_string(), "X-Two: 2".to_string()]);
    }

    #[test]
    fn suppress_upload_body_zeroes_sized_and_chunked() {
        assert!(matches!(
            suppress_upload_body(&h1::RequestBody::None),
            h1::RequestBody::None
        ));
        match suppress_upload_body(&h1::RequestBody::Sized(b"abc".to_vec())) {
            h1::RequestBody::Sized(v) => assert!(v.is_empty()),
            _ => panic!("expected empty Sized"),
        }
        // A chunked body keeps chunked framing but with NO blocks: the probe
        // sends only the terminal `0\r\n\r\n` (an empty chunked body), never a
        // contradictory `Content-Length: 0` alongside `Transfer-Encoding:
        // chunked` (the `test565` probe — see `suppress_upload_body`).
        match suppress_upload_body(&h1::RequestBody::Chunked(vec![b"abc".to_vec()], Vec::new())) {
            h1::RequestBody::Chunked(blocks, trailers) => {
                assert!(blocks.is_empty());
                assert!(trailers.is_empty());
            }
            _ => panic!("expected empty Chunked"),
        }
        // A streamed body suppresses to an empty Sized probe as well (the
        // exhaustive arm; not reached at runtime since streaming is gated off
        // for reactive auth, but it must collapse to a body-less probe).
        match suppress_upload_body(&h1::RequestBody::Streaming {
            size: Some(123),
            chunked: false,
        }) {
            h1::RequestBody::Sized(v) => assert!(v.is_empty()),
            _ => panic!("expected empty Sized"),
        }
    }

    // ---- Streaming-upload gate (QA F11-PERF Issue #5 / Issue #4 send half) ----

    /// A [`ReadCallback`] upload source that records how many times it was read,
    /// so a test can assert that the streaming path does **not** consume the
    /// source up front (it is pulled later by the codec) while the buffered path
    /// does.
    struct CountingReader {
        data: Vec<u8>,
        pos: usize,
        reads: usize,
    }
    impl CountingReader {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                pos: 0,
                reads: 0,
            }
        }
    }
    impl ReadCallback for CountingReader {
        fn read(&mut self, buf: &mut [u8]) -> usize {
            self.reads += 1;
            let n = (self.data.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            n
        }
    }

    /// An upload with a known size, no redirect-following, and no reactive auth
    /// is streamed: `build_request_body` returns a `Streaming` body carrying the
    /// size and does **not** read the source up front.
    #[test]
    fn build_request_body_streams_single_pass_without_reading_source() {
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = 1000; // CURLOPT_INFILESIZE[_LARGE]
        data.set.http_follow_mode = 0; // no -L
                                       // httpauth defaults to CURLAUTH_BASIC (not reactive).
        let mut src = CountingReader::new(b"unused-up-front");
        let body = build_request_body(&data, &mut src, true).unwrap();
        assert!(
            matches!(
                body,
                h1::RequestBody::Streaming {
                    size: Some(1000),
                    chunked: false
                }
            ),
            "expected Streaming{{1000, !chunked}}, got {body:?}"
        );
        assert_eq!(src.reads, 0, "source must not be consumed up front");
    }

    /// An explicit `Transfer-Encoding: chunked` upload still streams, as a
    /// chunked `Streaming` body.
    #[test]
    fn build_request_body_streams_chunked_with_te_header() {
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = 50;
        let mut list = SList::default();
        list.append("Transfer-Encoding: chunked").unwrap();
        data.set.headers = Some(list);
        let mut src = CountingReader::new(b"x");
        let body = build_request_body(&data, &mut src, true).unwrap();
        assert!(matches!(
            body,
            h1::RequestBody::Streaming {
                chunked: true,
                ..
            }
        ));
        assert_eq!(src.reads, 0);
    }

    /// An unknown upload size falls back to the buffered path (the source is
    /// read fully), so the length can still be derived — no regression.
    #[test]
    fn build_request_body_buffers_when_size_unknown() {
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = -1; // unknown (e.g. `-T -` from stdin)
        let mut src = CountingReader::new(b"hello");
        let body = build_request_body(&data, &mut src, true).unwrap();
        // An indeterminate upload length auto-selects chunked transfer-encoding
        // (oracle: `http_req_set_TE`: `req_clen < 0` -> chunked on HTTP/1.1),
        // buffered as per-read blocks. It is not streamed (no known size) and is
        // not sent under `Content-Length`.
        assert!(
            matches!(&body, h1::RequestBody::Chunked(blocks, _) if blocks.concat() == b"hello"),
            "unknown-size upload must auto-chunk (buffered)"
        );
        assert!(src.reads > 0, "buffered path must read the source");
    }

    /// Redirect-following (`-L`) keeps the buffered path so the body can be
    /// re-sent to a redirect target.
    #[test]
    fn build_request_body_buffers_when_follow_enabled() {
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = 5;
        data.set.http_follow_mode = 1; // -L
        let mut src = CountingReader::new(b"hello");
        let body = build_request_body(&data, &mut src, true).unwrap();
        assert!(matches!(body, h1::RequestBody::Sized(_)));
        assert!(src.reads > 0);
    }

    /// Reactive auth (Digest/NTLM/Negotiate/`--anyauth`) re-sends the body on a
    /// challenge, so it keeps the buffered path.
    #[test]
    fn build_request_body_buffers_under_reactive_auth() {
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = 5;
        data.set.httpauth = crate::auth::CURLAUTH_DIGEST; // reactive
        let mut src = CountingReader::new(b"hello");
        let body = build_request_body(&data, &mut src, true).unwrap();
        assert!(matches!(body, h1::RequestBody::Sized(_)));
        assert!(src.reads > 0);
    }

    /// `resolve_proxy_auth_inputs` is the proxy analog of
    /// `resolve_auth_inputs`: it builds a reactive controller seed from
    /// `CURLOPT_PROXYAUTH` + the proxy credentials, with NO host gating and NO
    /// bearer scheme. It returns `None` for the challenge-free default
    /// (`CURLAUTH_BASIC`, handled preemptively) and when no proxy credentials are
    /// present (tests 81, 162).
    #[cfg(feature = "proxy")]
    #[test]
    fn resolve_proxy_auth_inputs_gates_on_reactive_scheme_and_creds() {
        use crate::setopt::{apply, CurlOption, OptionValue};
        let set_str = |data: &mut Easy, opt: CurlOption, v: &str| {
            apply(&mut data.set, opt, OptionValue::Str(Some(v.to_string()))).unwrap();
        };

        // Default proxy auth (Basic) with credentials → None (preemptive path).
        let mut data = Easy::new();
        data.set.proxyauth = crate::auth::CURLAUTH_BASIC;
        set_str(&mut data, CurlOption::CURLOPT_PROXYUSERNAME, "puser");
        set_str(&mut data, CurlOption::CURLOPT_PROXYPASSWORD, "ppass");
        assert!(
            auth_engine::resolve_proxy_auth_inputs(&data, None).is_none(),
            "Basic proxy auth must use the preemptive path, not a controller"
        );

        // Reactive proxy NTLM with credentials → Some (drives the 407 loop).
        let mut data = Easy::new();
        data.set.proxyauth = crate::auth::CURLAUTH_NTLM;
        set_str(&mut data, CurlOption::CURLOPT_PROXYUSERNAME, "puser");
        set_str(&mut data, CurlOption::CURLOPT_PROXYPASSWORD, "ppass");
        assert!(
            auth_engine::resolve_proxy_auth_inputs(&data, None).is_some(),
            "NTLM proxy auth with creds must build a reactive controller seed"
        );

        // Reactive proxy NTLM but NO proxy credentials → None (nothing to try).
        let mut data = Easy::new();
        data.set.proxyauth = crate::auth::CURLAUTH_NTLM;
        assert!(
            auth_engine::resolve_proxy_auth_inputs(&data, None).is_none(),
            "no proxy credentials means no reactive proxy auth to attempt"
        );

        // Reactive proxy Digest with credentials embedded ONLY in the proxy URL
        // (no `--proxy-user`) → Some, sourced from the fallback (test 335).
        let mut data = Easy::new();
        data.set.proxyauth = crate::auth::CURLAUTH_DIGEST;
        let seed = auth_engine::resolve_proxy_auth_inputs(
            &data,
            Some((Some("foo".to_string()), Some("bar".to_string()))),
        )
        .expect("proxy-URL userinfo must seed a reactive proxy controller");
        assert_eq!(seed.user, "foo");
        assert_eq!(seed.password, "bar");

        // `--proxy-user` (StrId) overrides the proxy-URL userinfo fallback.
        let mut data = Easy::new();
        data.set.proxyauth = crate::auth::CURLAUTH_DIGEST;
        set_str(&mut data, CurlOption::CURLOPT_PROXYUSERNAME, "explicit");
        set_str(&mut data, CurlOption::CURLOPT_PROXYPASSWORD, "secret");
        let seed = auth_engine::resolve_proxy_auth_inputs(
            &data,
            Some((Some("foo".to_string()), Some("bar".to_string()))),
        )
        .expect("explicit proxy creds must seed a reactive proxy controller");
        assert_eq!(seed.user, "explicit", "--proxy-user overrides URL userinfo");
        assert_eq!(seed.password, "secret");
    }

    /// `effective_range` ports curl's `setup_range()`: a `GET`/`HEAD` resume
    /// offset (`CURLOPT_RESUME_FROM`) becomes the open-ended range string
    /// `"<n>-"`, while an upload (PUT) resume yields nothing here (it uses
    /// `Content-Range` instead). The explicit `--range` passthrough is unchanged
    /// and exercised by the harness `--range` tests.
    #[test]
    fn effective_range_synthesizes_resume_range() {
        // A GET resume offset becomes the open-ended range string "<n>-".
        let mut data = Easy::new();
        data.set.method = HttpReq::Get;
        data.set.set_resume_from = 78;
        assert_eq!(effective_range(&data).as_deref(), Some("78-"));

        // A HEAD resume likewise synthesizes the range.
        let mut data = Easy::new();
        data.set.method = HttpReq::Head;
        data.set.set_resume_from = 5;
        assert_eq!(effective_range(&data).as_deref(), Some("5-"));

        // An UPLOAD (PUT) resume does NOT synthesize a bare range here — upload
        // resume is expressed via Content-Range (a separate path).
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.set_resume_from = 50;
        assert_eq!(effective_range(&data), None);

        // No range and no resume: nothing.
        let data = Easy::new();
        assert_eq!(effective_range(&data), None);
    }

    /// `effective_content_range` ports the upload arm of curl's `http_range()`:
    /// a resumed PUT/POST emits `Content-Range: bytes <from>-<total-1>/<total>`,
    /// where `<total>` is the full declared upload size. This is the
    /// `tests/data/test33` contract (`-C 50` on a 100-byte PUT ⇒
    /// `Content-Range: bytes 50-99/100`).
    #[test]
    fn effective_content_range_for_resumed_upload() {
        // The headline test33 case: PUT, 100-byte file, resume from 50.
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = 100; // CURLOPT_INFILESIZE[_LARGE]
        data.set.set_resume_from = 50;
        assert_eq!(
            effective_content_range(&data, &[]).as_deref(),
            Some("bytes 50-99/100")
        );

        // A resumed POST uses the declared POSTFIELDSIZE as the total.
        let mut data = Easy::new();
        data.set.method = HttpReq::Post;
        data.set.postfieldsize = 200;
        data.set.set_resume_from = 20;
        assert_eq!(
            effective_content_range(&data, &[]).as_deref(),
            Some("bytes 20-199/200")
        );

        // No resume offset ⇒ no Content-Range.
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = 100;
        assert_eq!(effective_content_range(&data, &[]), None);

        // A download (GET) never gets an engine Content-Range (it uses `Range`).
        let mut data = Easy::new();
        data.set.method = HttpReq::Get;
        data.set.set_resume_from = 50;
        assert_eq!(effective_content_range(&data, &[]), None);

        // Unknown upload size (e.g. `-T -`) ⇒ no Content-Range (nothing to put
        // in `<total>`).
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = -1;
        data.set.set_resume_from = 50;
        assert_eq!(effective_content_range(&data, &[]), None);

        // A user-supplied custom `Content-Range:` header takes precedence
        // (curl's `Curl_checkheaders`), so the engine emits none of its own.
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = 100;
        data.set.set_resume_from = 50;
        let custom = vec!["Content-Range: bytes 0-9/10".to_string()];
        assert_eq!(effective_content_range(&data, &custom), None);

        // A resume offset at/past the end ⇒ no header (the body build reports
        // `CURLE_PARTIAL_FILE`).
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = 50;
        data.set.set_resume_from = 50;
        assert_eq!(effective_content_range(&data, &[]), None);
    }

    /// A resumed upload repositions the buffered source to the resume offset
    /// (curl's `http_resume` → `Curl_creader_resume_from` CANTSEEK fallback:
    /// read-and-discard the leading bytes) and uploads only the remainder as a
    /// sized body, so the advertised `Content-Length` is the post-seek size.
    #[test]
    fn build_request_body_resume_repositions_and_buffers() {
        // PUT a 10-byte source, resume from 4 ⇒ the body is the trailing 6 bytes
        // and the source is fully read (buffered, not streamed).
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = 10;
        data.set.set_resume_from = 4;
        let mut src = CountingReader::new(b"0123456789");
        let body = build_request_body(&data, &mut src, true).unwrap();
        match body {
            h1::RequestBody::Sized(b) => assert_eq!(b, b"456789"),
            other => panic!("expected Sized(trailing bytes), got {other:?}"),
        }
        assert!(src.reads > 0, "resume must take the buffered (read) path");

        // A resume offset at/past the end ⇒ CURLE_PARTIAL_FILE ("File already
        // completely uploaded").
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = 5;
        data.set.set_resume_from = 5;
        let mut src = CountingReader::new(b"hello");
        let err = build_request_body(&data, &mut src, true).unwrap_err();
        assert!(
            matches!(err, CurlError::PartialFile),
            "expected PartialFile, got {err:?}"
        );
    }

    /// The HTTP/3 and WebSocket callers pass `allow_stream = false`, so they
    /// always get a buffered body (those codecs have no streaming path).
    #[test]
    fn build_request_body_buffers_when_stream_disallowed() {
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = 5;
        let mut src = CountingReader::new(b"hello");
        let body = build_request_body(&data, &mut src, false).unwrap();
        assert!(matches!(body, h1::RequestBody::Sized(_)));
        assert!(src.reads > 0);
    }

    /// `materialize_streaming_body` reads the source fully for a `Streaming`
    /// body (the h2/h3 fallback) and passes any other body through unchanged.
    #[test]
    fn materialize_streaming_body_reads_source_for_streaming() {
        // Streaming (sized) → buffered Sized with the source bytes.
        let mut src = CountingReader::new(b"streamed-bytes");
        let out = materialize_streaming_body(
            h1::RequestBody::Streaming {
                size: Some(14),
                chunked: false,
            },
            Some(&mut src),
        )
        .unwrap();
        assert!(matches!(out, h1::RequestBody::Sized(ref v) if v == b"streamed-bytes"));
        assert!(src.reads > 0);

        // Streaming (chunked) → buffered Chunked.
        let mut src2 = CountingReader::new(b"abc");
        let out2 = materialize_streaming_body(
            h1::RequestBody::Streaming {
                size: None,
                chunked: true,
            },
            Some(&mut src2),
        )
        .unwrap();
        assert!(matches!(out2, h1::RequestBody::Chunked(ref blocks, _) if blocks.concat() == b"abc"));

        // A non-streaming body passes through untouched.
        let passthrough =
            materialize_streaming_body(h1::RequestBody::Sized(b"x".to_vec()), None).unwrap();
        assert!(matches!(passthrough, h1::RequestBody::Sized(ref v) if v == b"x"));
    }

    // ---- HopSink response-routing core (Issue #4 redirect/body delivery) ----

    /// A `WriteCallbacks` sink that records every body and header byte it is
    /// handed, so tests can assert exactly what the `HopSink` decorator forwarded
    /// to the application after applying its redirect/auth body-routing decision.
    #[derive(Default)]
    struct CapturingSink {
        body: Vec<u8>,
        headers: Vec<u8>,
    }

    impl WriteCallbacks for CapturingSink {
        fn write_body(&mut self, data: &[u8]) -> usize {
            self.body.extend_from_slice(data);
            data.len()
        }
        fn write_header(&mut self, data: &[u8]) -> Option<usize> {
            self.headers.extend_from_slice(data);
            Some(data.len())
        }
    }

    /// Feed a complete response head (status line + header lines + the
    /// end-of-headers blank line) through the sink's header channel, exactly as
    /// the transfer engine delivers it. This drives `note_header` for each line
    /// and leaves `headers_complete` set so a following body write takes its
    /// routing decision with the status fully known.
    fn feed_head(sink: &mut HopSink<'_>, lines: &[&str]) {
        for line in lines {
            let mut raw = line.as_bytes().to_vec();
            raw.extend_from_slice(b"\r\n");
            sink.write_header(&raw);
        }
        sink.write_header(b"\r\n");
    }

    #[test]
    fn hopsink_forwards_final_response_body() {
        // A plain 200 with following enabled: the body is forwarded verbatim and
        // the disposition resolves to Forward.
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, false);
        feed_head(&mut sink, &["HTTP/1.1 200 OK", "Content-Type: text/plain"]);
        assert_eq!(sink.status, 200);
        assert!(!sink.should_suppress());
        assert!(matches!(sink.decide_disposition(), BodyDisposition::Forward));
        assert_eq!(sink.write_body(b"hello world"), 11);
        // Content-Type was captured for CURLINFO_CONTENT_TYPE.
        assert_eq!(sink.content_type.as_deref(), Some(&b"text/plain"[..]));
        // Inner read last (after the sink is no longer used).
        assert_eq!(inner.body, b"hello world");
    }

    #[test]
    fn hopsink_resume_without_content_range_is_range_error() {
        // Port of curl's `http_firstwrite`: a resumed GET (`resume_from > 0`)
        // whose response carries NO `Content-Range` means the server ignored the
        // requested byte range. The re-sent body must be DISCARDED (the local
        // file is left untouched) and the transfer flagged with a range error so
        // the orchestrator returns CURLE_RANGE_ERROR (33). (Regression oracle:
        // tests/data/test38 — "HTTP resume request without server supporting it".)
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, false);
        sink.resume_from = 78; // -C - resolved against a 78-byte local file
        // HTTP/1.0 200 with no Content-Range and no Content-Length (close-delimited).
        feed_head(&mut sink, &["HTTP/1.0 200 Mooo", "Server: myown/1.0"]);
        assert_eq!(sink.status, 200);
        assert!(!sink.content_range_seen);
        // The first body byte triggers the check: latch the error and signal a
        // SHORT write (return 0) so the transfer driver aborts the read loop at
        // once (curl's http_firstwrite returns the error instead of draining the
        // close-delimited body).
        assert_eq!(sink.write_body(b"todelooooo lalalala"), 0);
        assert!(sink.range_error, "missing Content-Range on a resume must error");
        // The body was discarded — the application sink received nothing.
        assert!(inner.body.is_empty(), "resumed body must not reach the file");
    }

    #[test]
    fn hopsink_resume_with_content_range_forwards_body() {
        // A resumed GET whose response DOES carry `Content-Range` (a 206 partial)
        // honored the range: the body is forwarded and no range error is set.
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, false);
        sink.resume_from = 78;
        feed_head(
            &mut sink,
            &[
                "HTTP/1.1 206 Partial Content",
                "Content-Range: bytes 78-99/100",
                "Content-Length: 22",
            ],
        );
        assert!(sink.content_range_seen);
        assert_eq!(sink.write_body(b"the-resumed-remainder!"), 22);
        assert!(!sink.range_error, "an honored range must not error");
        assert_eq!(inner.body, b"the-resumed-remainder!");
    }

    #[test]
    fn hopsink_resume_416_discards_body_is_success() {
        // Port of curl's `http_firstwrite`: a `416 Range Not Satisfiable` answer
        // to a resumed GET (`resume_from > 0`) means the file is presumably
        // already fully downloaded. The error body must be DISCARDED (the local
        // file is left untouched) and this is a SUCCESS — NOT a range error —
        // even though the `416` carries a `Content-Range` header (so
        // `content_range_seen` is true, which would otherwise skip the discard).
        // curl: `if(resume_from && httpreq == GET && httpcode == 416)
        //   k->ignorebody = TRUE;`. (Regression oracle: tests/data/test92, test194.)
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, false);
        sink.resume_from = 87; // -C 87 against an 87-byte local file
        feed_head(
            &mut sink,
            &[
                "HTTP/1.1 416 Requested Range Not Satisfiable",
                "Content-Range: bytes */87",
                "Content-Length: 4",
            ],
        );
        assert_eq!(sink.status, 416);
        assert!(sink.content_range_seen, "a 416 typically carries Content-Range");
        // The body is discarded but the write reports success (the response is
        // Content-Length-delimited and drains on its own — no short-write abort),
        // and no range error is latched.
        assert_eq!(sink.write_body(b"bad\n"), 4);
        assert!(
            !sink.range_error,
            "a 416 to a resumed GET is a success, not a range error"
        );
        assert!(inner.body.is_empty(), "the 416 error body must not reach the file");
    }

    #[test]
    fn hopsink_resume_already_fully_downloaded_is_success() {
        // The "entire document already downloaded" case: the server ignored the
        // range (no Content-Range) but the full response size equals the resume
        // point, so the local file is already complete. curl treats this as a
        // SUCCESS (no error) while still discarding the redundant body.
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, false);
        sink.resume_from = 100;
        feed_head(
            &mut sink,
            &["HTTP/1.1 200 OK", "Content-Length: 100"],
        );
        assert!(!sink.content_range_seen);
        assert_eq!(sink.body_size, Some(100));
        assert_eq!(sink.write_body(b"x"), 1);
        assert!(
            !sink.range_error,
            "size == resume_from means already complete, not an error"
        );
        assert!(inner.body.is_empty(), "redundant body must be discarded");
    }

    #[test]
    fn hopsink_timecondition_unmet_discards_body_simulates_304() {
        // Port of curl's `http_firstwrite` time-condition arm: an
        // `If-Modified-Since` GET (`timecondition == 1`) whose response carries a
        // `Last-Modified` that is NOT newer than `timevalue` does not satisfy the
        // condition, so curl simulates a `304` — the headers flow (under `-i`) but
        // the BODY is discarded and the local file is left untouched. Unlike the
        // range error this is a SUCCESS, so the discard pretends the bytes were
        // consumed (returns the length, not 0) and no error latch is set.
        // (Regression oracle: tests/data/test78 — "HTTP with -z newer date".)
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, false);
        sink.timecondition = 1; // CURL_TIMECOND_IFMODSINCE
        sink.timevalue = 944_996_400; // 1999-12-12 11:00:00 GMT (test78 -z value)
        feed_head(
            &mut sink,
            &[
                "HTTP/1.1 200 OK",
                // 1990-06-13 — older than the 1999 timevalue => not new enough.
                "Last-Modified: Tue, 13 Jun 1990 12:10:00 GMT",
                "Content-Length: 6",
            ],
        );
        assert_eq!(sink.status, 200);
        assert_eq!(sink.timeofdoc, 645_279_000, "Last-Modified parsed to k->timeofdoc");
        // The first body byte triggers the check: the body is discarded but the
        // write reports success (the response is Content-Length-delimited and
        // drains on its own — no short-write abort).
        assert_eq!(sink.write_body(b"-foo-\n"), 6);
        assert!(sink.condition_unmet, "stale doc must flag a simulated 304");
        assert!(!sink.range_error, "a time-condition miss is a success, not a range error");
        assert!(inner.body.is_empty(), "the stale body must not reach the file");
    }

    #[test]
    fn hopsink_timecondition_met_forwards_body() {
        // The complement: an `If-Modified-Since` GET whose `Last-Modified` IS
        // newer than `timevalue` satisfies the condition, so the body is forwarded
        // normally and no simulated 304 is raised.
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, false);
        sink.timecondition = 1; // CURL_TIMECOND_IFMODSINCE
        sink.timevalue = 100_000_000; // 1973 — older than the 1990 document.
        feed_head(
            &mut sink,
            &[
                "HTTP/1.1 200 OK",
                "Last-Modified: Tue, 13 Jun 1990 12:10:00 GMT",
                "Content-Length: 6",
            ],
        );
        assert_eq!(sink.write_body(b"-foo-\n"), 6);
        assert!(!sink.condition_unmet, "a fresh-enough document must be delivered");
        assert_eq!(inner.body, b"-foo-\n");
    }

    #[test]
    fn hopsink_timecondition_skipped_when_range_present() {
        // curl gates the client-side time-condition check on `!data->state.range`
        // (RFC 2616 §13.3.4): when a byte range was also requested the conditional
        // shortcut is skipped and the body is delivered regardless of the
        // `Last-Modified` comparison. `range_present` propagates that gate.
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, false);
        sink.timecondition = 1;
        sink.timevalue = 944_996_400; // would otherwise be "not new enough"
        sink.range_present = true; // a range was requested => check is skipped
        feed_head(
            &mut sink,
            &[
                "HTTP/1.1 200 OK",
                "Last-Modified: Tue, 13 Jun 1990 12:10:00 GMT",
                "Content-Length: 6",
            ],
        );
        assert_eq!(sink.write_body(b"-foo-\n"), 6);
        assert!(!sink.condition_unmet, "a range request disables the time-condition shortcut");
        assert_eq!(inner.body, b"-foo-\n");
    }

    #[test]
    fn hopsink_suppresses_followed_redirect_body() {
        // The Issue #4 core: a 3xx with Location, while following is enabled, must
        // NOT leak its intermediate body to the application — only the final hop's
        // body is delivered. write_body still reports the bytes as consumed so the
        // driver does not see a short write.
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, false);
        feed_head(
            &mut sink,
            &["HTTP/1.1 301 Moved Permanently", "Location: http://example/2"],
        );
        assert_eq!(sink.status, 301);
        assert_eq!(sink.location.as_deref(), Some("http://example/2"));
        assert!(sink.should_suppress());
        assert!(matches!(sink.decide_disposition(), BodyDisposition::Discard));
        assert_eq!(sink.write_body(b"<html>moved</html>"), 18);
        // The intermediate redirect body was discarded, not forwarded.
        assert!(inner.body.is_empty());
        // Headers, however, are always forwarded (curl shows hop headers under -i).
        assert!(!inner.headers.is_empty());
    }

    #[test]
    fn hopsink_empty_location_is_not_followed() {
        // A 3xx carrying a blank `Location:` (only whitespace) must NOT be
        // treated as a redirect target — curl ignores an empty Location and
        // delivers the 3xx response as the final result rather than chasing it
        // (which, with the same URL, would loop until max-redirs). The body is
        // therefore forwarded, not suppressed. (Regression oracle:
        // tests/data/test54 — "HTTP with blank Location:".)
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, false);
        // `Location:` with a single trailing space — trimmed to empty.
        feed_head(
            &mut sink,
            &["HTTP/1.1 302 This is a weirdo text message", "Location: "],
        );
        assert_eq!(sink.status, 302);
        // The empty Location was ignored: no follow target recorded.
        assert!(sink.location.is_none());
        assert!(!sink.should_suppress());
        assert!(matches!(sink.decide_disposition(), BodyDisposition::Forward));
        assert_eq!(sink.write_body(b"This server reply is for testing"), 32);
        assert_eq!(inner.body, b"This server reply is for testing");
    }

    #[test]
    fn hopsink_redirect_without_following_forwards_body() {
        // With following DISABLED, a 3xx body is the real response and must be
        // forwarded (curl without -L prints the redirect page).
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, false, false);
        feed_head(&mut sink, &["HTTP/1.1 302 Found", "Location: http://example/2"]);
        assert!(!sink.should_suppress());
        assert!(matches!(sink.decide_disposition(), BodyDisposition::Forward));
        assert_eq!(sink.write_body(b"see other"), 9);
        assert_eq!(inner.body, b"see other");
    }

    #[test]
    fn hopsink_pre_header_body_bytes_are_forwarded_verbatim() {
        // Under CURLOPT_HEADER (-i) the header-merge bytes arrive on the body
        // stream before the end-of-headers blank line. While headers_complete is
        // false they are header content and must be forwarded verbatim — never
        // suppressed and never allowed to memoize the redirect disposition early
        // (the precise regression behind Issue #4).
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, false);
        // Status seen, but the blank line has NOT been observed yet.
        sink.write_header(b"HTTP/1.1 301 Moved Permanently\r\n");
        sink.write_header(b"Location: http://example/2\r\n");
        assert!(!sink.headers_complete);
        // A body-stream write at this point is the -i header merge: forward it.
        let merged = b"HTTP/1.1 301 Moved Permanently\r\n";
        assert_eq!(sink.write_body(merged), merged.len());
        // The disposition must NOT have been memoized by the pre-header write.
        assert!(sink.disposition.is_none());
        // Inner read last (after the sink is no longer used).
        assert_eq!(inner.body, merged);
    }

    #[test]
    fn hopsink_buffers_then_discards_answered_auth_body() {
        // During auth negotiation a 401 body is buffered (not forwarded); once the
        // challenge is answered and the request re-issued, the probe body is
        // discarded so the intermediate error page never reaches the application.
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, true);
        feed_head(
            &mut sink,
            &["HTTP/1.1 401 Unauthorized", "WWW-Authenticate: Digest realm=\"x\""],
        );
        assert!(matches!(sink.decide_disposition(), BodyDisposition::BufferAuth));
        assert_eq!(sink.write_body(b"auth required"), 13);
        // Not forwarded; held in the auth buffer instead.
        assert_eq!(sink.auth_body_buf, b"auth required");
        // The challenge line was captured for the auth controller.
        assert_eq!(sink.www_authenticate, vec!["Digest realm=\"x\"".to_string()]);
        // Answered → discard the probe body.
        sink.discard_auth_body();
        assert!(sink.auth_body_buf.is_empty());
        // Inner never received the probe body (read last).
        assert!(inner.body.is_empty());
    }

    #[test]
    fn hopsink_flushes_terminal_auth_body() {
        // A 401 whose challenge cannot be answered is terminal: the buffered error
        // page is flushed to the application as the real response body.
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, true);
        feed_head(&mut sink, &["HTTP/1.1 401 Unauthorized", "WWW-Authenticate: Basic"]);
        sink.write_body(b"please log in");
        // Buffered, not yet forwarded.
        assert_eq!(sink.auth_body_buf, b"please log in");
        sink.flush_auth_body();
        // The buffer is emptied by the flush.
        assert!(sink.auth_body_buf.is_empty());
        // Inner now holds the flushed terminal body (read last).
        assert_eq!(inner.body, b"please log in");
    }

    #[test]
    fn hopsink_reset_for_retry_clears_block_state() {
        // Re-issuing on the same connection during auth must clear all per-attempt
        // observable state while keeping the inner sink and the negotiation flags.
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, true);
        feed_head(
            &mut sink,
            &["HTTP/1.1 401 Unauthorized", "Location: /x", "WWW-Authenticate: NTLM"],
        );
        sink.write_body(b"probe");
        sink.reset_for_retry();
        assert_eq!(sink.status, 0);
        assert!(sink.location.is_none());
        assert!(sink.headers.is_empty());
        assert!(sink.content_type.is_none());
        assert!(sink.www_authenticate.is_empty());
        assert!(sink.auth_body_buf.is_empty());
        assert!(!sink.headers_complete);
        assert!(sink.disposition.is_none());
    }

    #[test]
    fn note_header_resets_per_block_state_on_new_status_line() {
        // A new status line (e.g. the next hop on a kept-alive connection) clears
        // the prior block's Location, Content-Type, and captured headers so a
        // redirect block's values never leak into the final response.
        let mut inner = CapturingSink::default();
        let mut sink = HopSink::with_auth(&mut inner, true, false);
        feed_head(
            &mut sink,
            &["HTTP/1.1 301 Moved", "Location: /next", "Content-Type: text/html"],
        );
        assert_eq!(sink.location.as_deref(), Some("/next"));
        assert!(sink.content_type.is_some());
        // The next response block begins; its status line resets the block state.
        sink.write_header(b"HTTP/1.1 200 OK\r\n");
        assert_eq!(sink.status, 200);
        assert!(sink.location.is_none());
        assert!(sink.content_type.is_none());
        assert!(sink.headers.is_empty());
        assert!(!sink.headers_complete);
    }


    #[test]
    fn http_url_parts_derives_scheme_host_and_default_port() {
        fn parts(url: &str) -> (String, bool, String, u16) {
            let mut u = CurlUrl::new();
            u.set(CurlUPart::Url, Some(url), CURLU_GUESS_SCHEME)
                .expect("parse url");
            http_url_parts(&u).expect("derive parts")
        }
        // Plain HTTP with no explicit port → port 80, not https.
        assert_eq!(
            parts("http://example.com/path"),
            ("http".to_string(), false, "example.com".to_string(), 80)
        );
        // HTTPS with no explicit port → port 443, https flagged.
        assert_eq!(
            parts("https://example.com/"),
            ("https".to_string(), true, "example.com".to_string(), 443)
        );
        // An explicit port overrides the scheme default.
        assert_eq!(
            parts("https://example.com:8443/"),
            ("https".to_string(), true, "example.com".to_string(), 8443)
        );
        // An IPv6 literal host has its surrounding brackets stripped for identity.
        assert_eq!(
            parts("http://[::1]:8080/"),
            ("http".to_string(), false, "::1".to_string(), 8080)
        );
    }

    #[test]
    fn hop_inputs_single_shot_seeds_from_easy_set() {
        // `HopInputs::single_shot` seeds the first-hop overrides directly from
        // `data.set`: the configured method/no-body and the inline `-b` cookie
        // and `CURLOPT_REFERER`, with no auth/proxy injection (those are added
        // only on reactive-auth re-issue). This is the seed the HTTP/3 path and
        // the first hop of a follow chain start from.
        let mut e = Easy::new();
        e.setopt(CurlOption::CURLOPT_NOBODY, OptionValue::Long(1))
            .unwrap();
        e.setopt(
            CurlOption::CURLOPT_COOKIE,
            OptionValue::Str(Some("session=abc".into())),
        )
        .unwrap();
        e.setopt(
            CurlOption::CURLOPT_REFERER,
            OptionValue::Str(Some("https://ref.example/".into())),
        )
        .unwrap();

        let hop = HopInputs::single_shot(&e);
        assert_eq!(hop.method, e.set.method, "method must mirror data.set");
        assert!(hop.no_body, "CURLOPT_NOBODY must propagate to the hop");
        assert_eq!(hop.cookie.as_deref(), Some("session=abc"));
        assert_eq!(hop.referer.as_deref(), Some("https://ref.example/"));
        // A first-shot hop injects no auth/proxy credentials.
        assert!(hop.authorization.is_none());
        assert!(hop.proxy_authorization.is_none());
        assert!(hop.auth.is_none());
        // It is allowed to send to the origin host and does not force proxy
        // keep-alive.
        assert!(hop.allowed_to_host);
        assert!(!hop.proxy_connection_keepalive);
        assert!(hop.request_target_override.is_none());
    }
}
