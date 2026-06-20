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
// `CurlError` is named only when HTTP/3 is compiled out, to reject an explicit
// `--http3`/`--http3-only` with `CURLE_NOT_BUILT_IN`. Under the default build
// the `http3` engine handles those values, so importing it unconditionally
// would be an unused import.
#[cfg(not(feature = "http3"))]
use crate::error::CurlError;
use crate::protocols::{Protocol, ProtocolTransfer, Scheme, TransferDirection};
// ALPN wire-byte constants, compared against the negotiated protocol so this
// module and `crate::tls` never drift. `h3` is selected by transport (QUIC),
// not by TLS-ALPN, so `ALPN_H3` is intentionally not used here; `http/1.1`
// (`ALPN_HTTP_1_1`) is the universal default and is handled by the fall-through
// arm rather than an explicit comparison.
use crate::tls::{ALPN_H2, ALPN_HTTP_1_0};

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
