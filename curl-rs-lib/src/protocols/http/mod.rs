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
    BoxFuture, Connection, Curl_conn_get_alpn_negotiated, Curl_conn_get_ip_info,
    Curl_conn_get_remote_addr,
};
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
use crate::url::{CurlUPart, CurlUrl, CURLU_DEFAULT_PORT, CURLU_GUESS_SCHEME, CURLU_URLDECODE};
use crate::util::timeval::curlx_now;
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
    /// `CURLOPT_REQUEST_TARGET`-style request-target override (forward proxy), if any.
    request_target_override: Option<String>,
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
            request_target_override: None,
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

/// A [`WriteCallbacks`] decorator wrapping the application's sink for one hop.
///
/// It transparently forwards every header line and (final-hop) body byte to the
/// inner sink, while *observing* the bytes to capture the status code and the
/// orchestration-relevant headers (`Location`, `Set-Cookie`,
/// `Strict-Transport-Security`, `Alt-Svc`). When the hop is a redirect that will
/// be followed (`follow_enabled && 3xx && Location present`), the response body
/// is *suppressed* (not forwarded), so only the final response's body reaches
/// the application — matching curl's `-L` behavior of discarding intermediate
/// `3xx` bodies. Headers are always forwarded (so `-i`/`-D` observe every hop,
/// as curl does).
struct HopSink<'s> {
    /// The application's real sink (body + header callbacks).
    inner: &'s mut dyn WriteCallbacks,
    /// Whether redirect following is enabled (gates body suppression).
    follow_enabled: bool,
    /// The most recent status code parsed from a `HTTP/...` status line.
    status: i32,
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
    /// Memoized body-suppression decision (computed once the first body byte
    /// arrives — by then all headers, including the status line, have been seen).
    suppress_body: Option<bool>,
}

impl<'s> HopSink<'s> {
    fn new(inner: &'s mut dyn WriteCallbacks, follow_enabled: bool) -> Self {
        HopSink {
            inner,
            follow_enabled,
            status: 0,
            location: None,
            #[cfg(feature = "cookies")]
            set_cookies: Vec::new(),
            #[cfg(feature = "hsts")]
            sts: None,
            #[cfg(feature = "alt-svc")]
            alt_svc: None,
            headers: Vec::new(),
            content_type: None,
            suppress_body: None,
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
                self.location = None;
                self.headers.clear();
                self.content_type = None;
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
            if name.eq_ignore_ascii_case("location") {
                self.location = Some(value.to_string());
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
}

impl WriteCallbacks for HopSink<'_> {
    fn write_body(&mut self, data: &[u8]) -> usize {
        let suppress = match self.suppress_body {
            Some(b) => b,
            None => {
                let b = self.should_suppress();
                self.suppress_body = Some(b);
                b
            }
        };
        if suppress {
            // Pretend the bytes were consumed so the transfer driver does not
            // treat the discard as a short write.
            data.len()
        } else {
            self.inner.write_body(data)
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
    let port = url
        .get(CurlUPart::Port, 0)
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
        }
        Some(jar)
    }

    /// Build the `Cookie:` request-header value for `url`: the inline
    /// `CURLOPT_COOKIE` value (if any) merged with the jar's matching cookies —
    /// inline first, then jar matches, `"; "`-separated — matching curl's
    /// `addcookies` followed by the jar emission. With no active jar the inline
    /// value is used verbatim (the historical inline-only behavior).
    pub(super) fn request_header(
        jar: &Option<JarHandle>,
        inline: Option<&str>,
        url: &CurlUrl,
    ) -> Option<String> {
        let Some(jar) = jar else {
            return inline.map(str::to_string);
        };
        let now = now_unix();
        let matched = jar
            .lock()
            .ok()
            .and_then(|mut j| j.match_for_url(url, now).ok())
            .unwrap_or_default();
        match (inline, matched.is_empty()) {
            (Some(i), false) => Some(format!("{i}; {matched}")),
            (Some(i), true) => Some(i.to_string()),
            (None, false) => Some(matched),
            (None, true) => None,
        }
    }

    /// Store this hop's `Set-Cookie` response headers into the jar, scoped to the
    /// request `url` (curl's `Curl_cookie_add` per `Set-Cookie`). Public-suffix
    /// rejection and domain/path/secure scoping are enforced inside the jar.
    pub(super) fn capture(jar: &Option<JarHandle>, set_cookies: &[String], url: &CurlUrl) {
        let Some(jar) = jar else {
            return;
        };
        if set_cookies.is_empty() {
            return;
        }
        let now = now_unix();
        if let Ok(mut guard) = jar.lock() {
            for sc in set_cookies {
                // A malformed/blocked cookie is dropped, not fatal (curl ignores
                // a failed `Curl_cookie_add`).
                let _ = guard.store_response_url(sc, url, now);
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
    use super::{Easy, StrId};
    use crate::auth::{basic::http_basic_header, CURLAUTH_BASIC};
    use crate::netrc::{self, CurlNetrcOption};
    use std::path::Path;

    /// Resolved host credentials (curl's `data->state.aptr.user`/`passwd`).
    struct HostCreds {
        user: String,
        password: String,
    }

    /// The preemptive `Authorization: Basic` *value* (`"Basic <base64>"`) for
    /// the transfer's resolved credentials, or `None` when no credentials apply
    /// or Basic is not in the `CURLOPT_HTTPAUTH` mask.
    ///
    /// `host` is the *origin* host the transfer starts against — the `.netrc`
    /// machine the lookup keys on (curl resolves credentials once against the
    /// initial host, then governs cross-host forwarding separately).
    pub(super) fn preemptive_basic(data: &Easy, host: &str) -> Option<String> {
        let creds = resolve(data, host)?;

        // Only Basic is sent preemptively; every other scheme requires a server
        // challenge first (auth depth, F8). The default `CURLOPT_HTTPAUTH` is
        // exactly `CURLAUTH_BASIC`, so this gate passes for the common case and
        // correctly suppresses preemptive Basic under `--digest`/`--ntlm`/etc.
        if data.set.httpauth & CURLAUTH_BASIC == 0 {
            return None;
        }

        // Reuse the parity-faithful Basic encoder (`http_output_basic`), then
        // reduce its full header line ("Authorization: Basic <b64>\r\n") to the
        // *value* the h1 request builder expects (it adds the field name).
        let line = http_basic_header(&creds.user, &creds.password, false).ok()?;
        let value = line
            .strip_prefix("Authorization: ")
            .unwrap_or(&line)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        Some(value)
    }

    /// Resolve the host credentials: explicit `-u` first, then `.netrc` (when
    /// enabled) to fill any missing field. Returns `None` when neither source
    /// supplies a credential.
    fn resolve(data: &Easy, host: &str) -> Option<HostCreds> {
        let explicit_user = data.set.str(StrId::Username);
        let explicit_pass = data.set.str(StrId::Password);

        // `CURLOPT_NETRC` mode (0=ignored / 1=optional / 2=required).
        let netrc_opt = CurlNetrcOption::from_long(i64::from(data.set.use_netrc))
            .unwrap_or(CurlNetrcOption::Ignored);

        // netrc is consulted only when enabled AND `-u` did not already supply a
        // complete user:password pair (curl lets netrc fill a missing field, but
        // a full `-u user:pass` wins outright).
        let consult_netrc = netrc_opt != CurlNetrcOption::Ignored
            && !(explicit_user.is_some() && explicit_pass.is_some());

        let mut user = explicit_user.map(str::to_string);
        let mut password = explicit_pass.map(str::to_string);

        if consult_netrc {
            // `--netrc-file` overrides the default `~/.netrc` location.
            let file = data.set.str(StrId::NetrcFile).map(Path::new);
            if let Ok(Some(entry)) = netrc::resolve(netrc_opt, file, host, explicit_user) {
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
            }),
        }
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
mod proxy_engine {
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
    pub(super) fn config(data: &Easy, scheme: &str) -> Result<ProxyConfig> {
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
    let mut url = if let Some(uh) = data.set.uh.clone() {
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
        let body = build_request_body(data, source)?;
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
    let base_body = build_request_body(data, source)?;

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
    let (_oh_scheme, _oh_https, origin_host, _oh_port) = http_url_parts(&url)?;
    let preemptive_basic = auth_engine::preemptive_basic(data, &origin_host);

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

        let hop_inputs = HopInputs {
            method,
            no_body,
            // Emit the preemptive Basic header to the origin host, and to a
            // redirect target only when `--location-trusted`
            // (`CURLOPT_UNRESTRICTED_AUTH`) permits keeping credentials across
            // hosts — matching curl's `Curl_auth_allowed_to_host` gate (the h1
            // builder emits `Authorization` unconditionally on this value, so the
            // cross-host decision is made here).
            authorization: match preemptive_basic.as_deref() {
                Some(v)
                    if cur_host.eq_ignore_ascii_case(&origin_host)
                        || redirect_cfg.allow_auth_to_other_hosts =>
                {
                    Some(v.to_string())
                }
                _ => None,
            },
            proxy_authorization: None,
            cookie: {
                // Merge inline `CURLOPT_COOKIE` with the jar's cookies that match
                // *this hop's* URL (curl re-derives the `Cookie:` header per hop).
                #[cfg(feature = "cookies")]
                let cookie_hdr =
                    cookie_engine::request_header(&cookie_jar, data.set.str(StrId::Cookie), &url);
                #[cfg(not(feature = "cookies"))]
                let cookie_hdr = data.set.str(StrId::Cookie).map(str::to_string);
                cookie_hdr
            },
            referer: referer_override
                .clone()
                .or_else(|| data.set.str(StrId::SetReferer).map(str::to_string)),
            allowed_to_host: true,
            proxy_connection_keepalive: false,
            request_target_override: None,
        };

        let hop = match perform_http_hop(data, &url, hop_inputs, body, follow_enabled, sink).await
        {
            Ok(hop) => hop,
            Err(err) => break Err(err),
        };

        // Store this hop's `Set-Cookie`s against the URL the request was sent to,
        // before a redirect reassigns `url` (curl captures per hop so a cookie set
        // on a 3xx is sent on the followed request).
        #[cfg(feature = "cookies")]
        cookie_engine::capture(&cookie_jar, &hop.set_cookies, &url);

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
    // A forward HTTP proxy injects `Proxy-Authorization`/`Proxy-Connection` into
    // the request shape, so the per-hop inputs become mutable here. Only the
    // `proxy` feature mutates them, so the rebind is gated to avoid an
    // `unused_mut` lint when the feature is off.
    #[cfg(feature = "proxy")]
    let mut hop = hop;
    #[cfg(feature = "proxy")]
    let proxy_cfg = {
        // The request URL's scheme selects the `<scheme>_proxy` environment
        // variable (HTTP/3 is https-only and handled separately; this TCP path is
        // always `http`/`https`).
        let scheme = if is_https { "https" } else { "http" };
        proxy_engine::config(data, scheme)?
    };
    #[cfg(feature = "proxy")]
    let hop_proxy = crate::proxy::proxy_for_target(&proxy_cfg, &host);

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
    let addrs = resolve_addrs(data, &dial_host, dial_port, ipver, verbose).await?;
    // CURLINFO_NAMELOOKUP_TIME milestone: name resolution for this hop is done.
    let t_resolved = Instant::now();

    // (4) Build the connection and its filter chain. The SETUP meta-filter
    //     assembles the chain in curl's canonical order:
    //     eyeballs → socks → ssl_proxy → http_proxy(CONNECT) → ssl(target).
    let desc = http_scheme_descriptor(is_https);
    let mut conn = Connection::new(format!("{dial_host}:{dial_port}"), TRNSPRT_TCP, desc)
        .with_verbose(verbose);
    conn.set_remote(remote_host, remote_port);

    let ssl_mode = if is_https {
        CURL_CF_SSL_ENABLE
    } else {
        CURL_CF_SSL_DISABLE
    };
    let eyeballs = eyeballs_factory(TRNSPRT_TCP, ipver, data.set.happy_eyeballs_timeout, addrs);

    // The target TLS filter (origin TLS) is installed whenever the *target* URL
    // is https, independent of any proxy in front — it rides on top of the SOCKS
    // tunnel or the HTTP CONNECT tunnel (curl adds the target `ssl` filter last).
    let target_ssl = if is_https {
        let want_h2 = cfg!(feature = "http2")
            && !matches!(httpwant, CURL_HTTP_VERSION_1_0 | CURL_HTTP_VERSION_1_1);
        let only_http_10 = httpwant == CURL_HTTP_VERSION_1_0;
        let alpn = alpn_protocols(want_h2, true, false, only_http_10, data.set.ssl_enable_alpn);
        let tls = tls_config_from_easy(data);
        Some(tls_factory(tls, host_ace.clone(), port, None, alpn))
    } else {
        None
    };

    let mut setup = SetupConfig::new(ssl_mode, is_https, eyeballs);

    #[cfg(feature = "proxy")]
    {
        if let Some(px) = hop_proxy {
            use crate::conn::connect::{h1_proxy_factory, socks_factory, tls_proxy_factory};
            use crate::conn::h1_proxy::{H1ProxyConfig, StandardProxyAuth};
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
                    setup = setup.with_ssl_proxy(tls_proxy_factory(
                        ptls,
                        px.host.clone(),
                        px.port,
                        None,
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
                    let h1cfg = H1ProxyConfig::new(host_ace.clone(), port)
                        .with_http_minor(1)
                        .with_scheme(scheme, true)
                        .with_auth(Box::new(StandardProxyAuth::new(
                            px.clone(),
                            data.set.proxyauth,
                        )));
                    setup = setup.with_http_proxy(h1_proxy_factory(h1cfg));
                    if let Some(ssl) = target_ssl {
                        setup = setup.with_ssl(ssl);
                    }
                } else {
                    // Forward HTTP proxy: `request_target` auto-selects the
                    // absolute-URI form from `conn.bits.httpproxy && !tunnel_proxy`;
                    // here we add the Basic `Proxy-Authorization` value and the
                    // `Proxy-Connection: Keep-Alive` hint (curl's forward-proxy
                    // request shape). `target_ssl` is `None` for a plain-http
                    // target, so there is nothing further to layer.
                    hop.proxy_authorization =
                        proxy_engine::forward_proxy_auth_value(px, data.set.proxyauth);
                    hop.proxy_connection_keepalive = true;
                }
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
    establish_connection(&mut conn, FIRSTSOCKET, ssl_mode, dispatch, true).await?;
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

    // (6) Select the wire version (forced option, else negotiated ALPN) and
    //     build + drive the matching exchange, capturing the hop outcome.
    let version = select_http_version(data, &conn)?;
    let mut hop_sink = HopSink::new(sink, follow_enabled);
    let drive_result = match version {
        HttpVersion::Http10 | HttpVersion::Http11 => {
            let http_minor = if version == HttpVersion::Http10 { 0 } else { 1 };
            let custom_headers = collect_custom_headers(data);
            let plan = {
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
                    http_minor,
                    &hop,
                );
                h1::build_request(&inputs)?
            };
            // CURLINFO_HEADER_OUT: when verbose, emit the fully serialized
            // request head (request line + header block + terminating CRLF) as a
            // single event before the exchange begins. curl's `tool_debug_cb`
            // splits it on newlines and renders each line with the `> ` prefix
            // (`Curl_debug(…, CURLINFO_HEADER_OUT, …)` in `Curl_http`).
            if verbose {
                hop_sink.debug(crate::transfer::DebugInfoType::HeaderOut, &plan.head);
            }
            let mut exchange = h1::H1Exchange::new(
                h1::ConnByteStream::new(&mut conn),
                plan,
                data.set.http09_allowed,
                false,
            );
            let result = drive_one(data, &mut exchange, &mut hop_sink, op_start).await;
            let keepalive = exchange.keepalive();
            drop(exchange);
            h1::apply_connection_reuse(&mut conn, keepalive);
            result
        }
        HttpVersion::H2 => {
            #[cfg(feature = "http2")]
            {
                let custom_headers = collect_custom_headers(data);
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
                let result = drive_one(data, &mut exchange, &mut hop_sink, op_start).await;
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
        #[cfg(feature = "cookies")]
        set_cookies,
        #[cfg(feature = "hsts")]
        sts,
        #[cfg(feature = "alt-svc")]
        alt_svc,
        ..
    } = hop_sink;

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
    let custom_headers = collect_custom_headers(data);
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

    let result = drive_one(data, &mut exchange, sink, op_start).await;
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
        drive_one(data, &mut exchange, sink, op_start).await?;
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
    // The hop's operation-start instant, captured by the caller *before* DNS
    // resolution and connection setup. Seeding [`Progress`] with it (rather than
    // `Instant::now()` here, after the connection is already up) makes the
    // recorded `CURLINFO_TOTAL_TIME` / `CURLINFO_STARTTRANSFER_TIME` measure from
    // the true start of the operation — matching curl's `Curl_pgrsStartNow`,
    // which is called at transfer start, not after connect.
    op_start: Instant,
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
        move |code: i32| http_should_fail(code, resume, is_get, has_user, has_proxy_user)
    });
    let fail_ref: Option<&(dyn Fn(i32) -> bool + Send + Sync)> = fail_closure
        .as_ref()
        .map(|c| c as &(dyn Fn(i32) -> bool + Send + Sync));

    let outcome = drive_transfer(
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
    data.info.size_upload = progress.upload_size();

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
        h1::RequestBody::Chunked(_) => (None, true),
        h1::RequestBody::None => (None, false),
    };
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
        range: data.set.str(StrId::SetRange),
        accept_present: any_custom_header(custom_headers, "Accept"),
        te_gzip: false,
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
