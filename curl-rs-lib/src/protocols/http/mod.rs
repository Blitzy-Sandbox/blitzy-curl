// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP handler root — the foundational HTTP/1.1, HTTP/2 and HTTP/3 family
//! (← `lib/http.c` + `lib/http.h`).
//!
//! This is the central module of the entire HTTP protocol family. It defines
//! the shared request/response header machinery, the [`Protocol`]
//! implementation for the `http`/`https` schemes, version
//! negotiation/dispatch across HTTP/1.1, HTTP/2 and HTTP/3, redirect handling,
//! `Expect: 100-continue`, and the authentication glue that drives the
//! mechanisms in [`crate::auth`].
//!
//! The sibling protocol modules [`crate::protocols::rtsp`] and
//! [`crate::protocols::ws`] reuse this module's header machinery
//! (`use crate::protocols::http;`), so the shared items — [`HeaderList`],
//! [`HttpReq`], [`HttpReqData`], [`HttpResp`], [`http_req_to_h2`], and the
//! status-line prefix checks — are declared `pub`.
//!
//! # Parity contract
//!
//! Behaviour is a byte-for-byte port of curl 8.19.0-DEV wherever the behaviour
//! is deterministic: header formatting and ordering, redirect semantics, status
//! parsing, and the authentication negotiation sequence. The diagnostic
//! vocabulary (the `infof`/`failf` message text curl emits under
//! `--trace`/`--verbose`) is preserved verbatim so trace output is identical;
//! those messages are emitted through [`tracing`] here.
//!
//! # Safety
//!
//! This module is entirely safe Rust. The crate root applies
//! [`forbid(unsafe_code)`](crate), which makes the forbidden memory keyword a
//! hard compile error, and a CI grep asserts it never appears anywhere under
//! `curl-rs-lib/src/`. There is no FFI and there are no raw pointers here.
//!
//! # Structural note
//!
//! The C `struct Curl_easy *data` handle threads the entire per-transfer and
//! per-connection state through every `http.c` function. In this workspace that
//! state is owned by the driver ([`crate::transfer`] / [`crate::multi`]) and is
//! *not* exposed through the thin [`TransferCtx`] the [`Protocol`] trait
//! receives. The self-contained header, redirect, auth-selection, and
//! response-parsing logic is therefore ported here as free functions and small
//! value types that take exactly the inputs each needs — which is precisely the
//! form the sibling protocols reuse — while the [`Protocol`] hooks stay thin and
//! delegate the wire transfer to [`h1`], [`h2`] and [`h3`] once the driver hands
//! them the connection. This mirrors the sibling [`crate::protocols::rtsp`]
//! handler exactly.

// ===========================================================================
// HTTP submodule tree.
//
// The whole `http` module is gated by the parent's
// `#[cfg(feature = "http")] pub mod http;`, so these submodules require no
// per-file feature gate. Each is the port target of a distinct curl C source
// file and is developed independently; this root depends only on the module
// paths existing, never on a particular item, so the family reconciles without
// cross-module coupling.
// ===========================================================================

/// AWS SigV4 request signing (← `lib/http_aws_sigv4.c`).
pub mod aws_sigv4;
/// Chunked Transfer-Encoding codec (← `lib/http_chunks.c`).
pub mod chunks;
/// HTTP/1.1 message framing and transfer driver (← `lib/http1.c`).
pub mod h1;
/// HTTP/2 multiplexing and framing (← `lib/http2.c`).
pub mod h2;
/// HTTP/3 over QUIC (← `lib/vquic/curl_ngtcp2.c` + `lib/vquic/curl_quiche.c`).
pub mod h3;
/// HTTP proxy request handling (← `lib/http_proxy.c`).
pub mod proxy;

use std::fmt::Write as _;
use std::net::SocketAddr;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use url::Url;

use crate::auth;
use crate::conn::{Connection, FIRSTSOCKET};
use crate::error::{CurlCode, Error, Result};
use crate::protocols::http::h1::RequestBody;
use crate::protocols::{
    FollowType, Pollset, ProtoFuture, Protocol, TransferCtx, CURLPROTO_FTP, CURLPROTO_HTTP,
    CURLPROTO_HTTPS, CURLPROTO_WS, CURLPROTO_WSS,
};
use crate::tls::AlpnProtocol;

/// The HTTP protocol family bitmask (← `PROTO_FAMILY_HTTP`, `lib/urldata.h`):
/// `http`, `https`, and the WebSocket schemes `ws`/`wss` that ride on HTTP.
pub const PROTO_FAMILY_HTTP: u32 = CURLPROTO_HTTP | CURLPROTO_HTTPS | CURLPROTO_WS | CURLPROTO_WSS;

// ===========================================================================
// Default ports and version banner (← `lib/urldata.h`, `lib/http.c`).
// ===========================================================================

/// The default HTTP port (← `PORT_HTTP`). Registered on the `http` scheme by
/// [`crate::protocols`]; restated here as the protocol's documented default.
pub const PORT_HTTP: u16 = 80;

/// The default HTTPS port (← `PORT_HTTPS`). Registered on the `https` scheme by
/// [`crate::protocols`].
pub const PORT_HTTPS: u16 = 443;

/// The curl-rs release string, matching the reference curl `LIBCURL_VERSION`
/// (`include/curl/curlver.h`). Used to assemble the [`version_string`] banner
/// and the default `User-Agent`.
pub const CURL_RS_VERSION: &str = "8.19.0-DEV";

// ===========================================================================
// HTTP request kind (← `enum Curl_HttpReq`, `lib/http.h`).
// ===========================================================================

/// The kind of HTTP request being issued (← `Curl_HttpReq`).
///
/// The discriminants match curl's `HTTPREQ_*` values exactly (`GET` is `0`
/// through `HEAD` is `5`) because the C code compares and range-checks them
/// numerically (e.g. `httpreq >= HTTPREQ_GET && httpreq <= HTTPREQ_HEAD`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HttpReq {
    /// `GET` (← `HTTPREQ_GET`).
    #[default]
    Get = 0,
    /// `POST` with a raw/`CURLOPT_POSTFIELDS` body (← `HTTPREQ_POST`).
    Post = 1,
    /// `POST` built from a `curl_formadd` form (← `HTTPREQ_POST_FORM`).
    /// We make a difference internally.
    PostForm = 2,
    /// `POST` built from a `curl_mime` structure (← `HTTPREQ_POST_MIME`).
    /// We make a difference internally.
    PostMime = 3,
    /// `PUT` (← `HTTPREQ_PUT`).
    Put = 4,
    /// `HEAD` (← `HTTPREQ_HEAD`).
    Head = 5,
}

impl HttpReq {
    /// The request-method keyword this request kind maps to by default
    /// (before any `CURLOPT_CUSTOMREQUEST` override), matching the `switch`
    /// in `Curl_http_method`: the three POST variants all yield `"POST"`.
    #[must_use]
    pub fn default_method(self) -> &'static str {
        match self {
            HttpReq::Get => "GET",
            HttpReq::Post | HttpReq::PostForm | HttpReq::PostMime => "POST",
            HttpReq::Put => "PUT",
            HttpReq::Head => "HEAD",
        }
    }

    /// Whether this request kind is one of the three POST variants (the C
    /// `Curl_HttpReq` values `HTTPREQ_POST`, `HTTPREQ_POST_FORM`,
    /// `HTTPREQ_POST_MIME`).
    #[must_use]
    pub fn is_post(self) -> bool {
        matches!(self, HttpReq::Post | HttpReq::PostForm | HttpReq::PostMime)
    }
}

// ===========================================================================
// HTTP major-version bitmask (← `http_majors`, `CURL_HTTP_V*`, `lib/http.h`).
// ===========================================================================

/// A bitmask of `CURL_HTTP_V*` values (← `typedef unsigned char http_majors`).
pub type HttpMajors = u8;

/// HTTP/1.x major version bit (← `CURL_HTTP_V1x`).
pub const CURL_HTTP_V1X: HttpMajors = 1 << 0;
/// HTTP/2 major version bit (← `CURL_HTTP_V2x`).
pub const CURL_HTTP_V2X: HttpMajors = 1 << 1;
/// HTTP/3 major version bit (← `CURL_HTTP_V3x`).
pub const CURL_HTTP_V3X: HttpMajors = 1 << 2;

// ===========================================================================
// Requested HTTP version (← `CURL_HTTP_VERSION_*`, public `curl/curl.h`).
//
// The value the application selects through `CURLOPT_HTTP_VERSION`; consumed by
// [`HttpNegotiation::http_neg_init`] (← `Curl_http_neg_init`). Discriminants are
// frozen to the public `curl/curl.h` integers.
// ===========================================================================

/// The application's requested HTTP version (← `CURLOPT_HTTP_VERSION` /
/// `CURL_HTTP_VERSION_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HttpWant {
    /// No preference; negotiate the best available (← `CURL_HTTP_VERSION_NONE`).
    #[default]
    None = 0,
    /// Force HTTP/1.0 (← `CURL_HTTP_VERSION_1_0`).
    Http10 = 1,
    /// Force HTTP/1.1 (← `CURL_HTTP_VERSION_1_1`).
    Http11 = 2,
    /// Prefer HTTP/2, allow fallback (← `CURL_HTTP_VERSION_2_0`).
    Http2 = 3,
    /// HTTP/2 over TLS only, HTTP/1.1 for plain (← `CURL_HTTP_VERSION_2TLS`).
    Http2Tls = 4,
    /// HTTP/2 with prior knowledge, no ALPN/upgrade
    /// (← `CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE`).
    Http2PriorKnowledge = 5,
    /// Prefer HTTP/3, allow fallback to HTTP/2 or HTTP/1.1
    /// (← `CURL_HTTP_VERSION_3`).
    Http3 = 30,
    /// HTTP/3 only, no fallback (← `CURL_HTTP_VERSION_3ONLY`).
    Http3Only = 31,
}

// ===========================================================================
// http_negotiation (← `struct http_negotiation`, `lib/http.h`).
// ===========================================================================

/// The per-transfer HTTP version-negotiation state (← `struct
/// http_negotiation`).
///
/// Records which major versions are wanted, allowed, and preferred, the lowest
/// response version observed so far, and the boolean upgrade/prior-knowledge
/// flags. [`http_neg_init`](HttpNegotiation::http_neg_init) initialises it from
/// the application's [`HttpWant`], mirroring `Curl_http_neg_init`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HttpNegotiation {
    /// Minimum (lowest) version seen in responses so far: `0` (none yet), `9`,
    /// `10`, or `11` (← `rcvd_min`, stored as `09`/`10`/`11`).
    pub rcvd_min: u8,
    /// Wanted major versions when talking to the server (← `wanted`).
    pub wanted: HttpMajors,
    /// Allowed major versions when talking to the server (← `allowed`).
    pub allowed: HttpMajors,
    /// Preferred major version when talking to the server (← `preferred`).
    pub preferred: HttpMajors,
    /// Perform an HTTP Upgrade from 1.1 to 2 (← `h2_upgrade`).
    pub h2_upgrade: bool,
    /// Speak HTTP/2 directly without ALPN/TLS (← `h2_prior_knowledge`).
    pub h2_prior_knowledge: bool,
    /// Accept an HTTP/0.9 response (← `accept_09`).
    pub accept_09: bool,
    /// When using major version 1x, use only 1.0 (← `only_10`).
    pub only_10: bool,
}

impl HttpNegotiation {
    /// Initialise negotiation state from the application's requested version and
    /// the `CURLOPT_HTTP09_ALLOWED` flag (← `Curl_http_neg_init`).
    ///
    /// The mapping from [`HttpWant`] onto `wanted`/`allowed` and the
    /// `only_10`/`h2_upgrade`/`h2_prior_knowledge` flags reproduces the C
    /// `switch(data->set.httpwant)` exactly.
    pub fn http_neg_init(&mut self, want: HttpWant, http09_allowed: bool) {
        *self = HttpNegotiation::default();
        self.accept_09 = http09_allowed;
        match want {
            HttpWant::Http10 => {
                self.wanted = CURL_HTTP_V1X;
                self.allowed = CURL_HTTP_V1X;
                self.only_10 = true;
            }
            HttpWant::Http11 => {
                self.wanted = CURL_HTTP_V1X;
                self.allowed = CURL_HTTP_V1X;
            }
            HttpWant::Http2 => {
                self.wanted = CURL_HTTP_V1X | CURL_HTTP_V2X;
                self.allowed = CURL_HTTP_V1X | CURL_HTTP_V2X;
                self.h2_upgrade = true;
            }
            HttpWant::Http2Tls => {
                self.wanted = CURL_HTTP_V1X | CURL_HTTP_V2X;
                self.allowed = CURL_HTTP_V1X | CURL_HTTP_V2X;
            }
            HttpWant::Http2PriorKnowledge => {
                self.wanted = CURL_HTTP_V2X;
                self.allowed = CURL_HTTP_V2X;
                self.h2_prior_knowledge = true;
            }
            HttpWant::Http3 => {
                self.wanted = CURL_HTTP_V1X | CURL_HTTP_V2X | CURL_HTTP_V3X;
                self.allowed = CURL_HTTP_V1X | CURL_HTTP_V2X | CURL_HTTP_V3X;
            }
            HttpWant::Http3Only => {
                self.wanted = CURL_HTTP_V3X;
                self.allowed = CURL_HTTP_V3X;
            }
            HttpWant::None => {
                self.wanted = CURL_HTTP_V1X | CURL_HTTP_V2X;
                self.allowed = CURL_HTTP_V1X | CURL_HTTP_V2X | CURL_HTTP_V3X;
            }
        }
    }
}

/// Free-function form of [`HttpNegotiation::http_neg_init`]
/// (← `Curl_http_neg_init`), returning a freshly initialised value.
#[must_use]
pub fn http_neg_init(want: HttpWant, http09_allowed: bool) -> HttpNegotiation {
    let mut neg = HttpNegotiation::default();
    neg.http_neg_init(want, http09_allowed);
    neg
}

// ===========================================================================
// HTTP/2 pseudo-header names (← `HTTP_PSEUDO_*`, `lib/http.h`).
// ===========================================================================

/// The HTTP/2 `:method` pseudo-header name (← `HTTP_PSEUDO_METHOD`).
pub const HTTP_PSEUDO_METHOD: &str = ":method";
/// The HTTP/2 `:scheme` pseudo-header name (← `HTTP_PSEUDO_SCHEME`).
pub const HTTP_PSEUDO_SCHEME: &str = ":scheme";
/// The HTTP/2 `:authority` pseudo-header name (← `HTTP_PSEUDO_AUTHORITY`).
pub const HTTP_PSEUDO_AUTHORITY: &str = ":authority";
/// The HTTP/2 `:path` pseudo-header name (← `HTTP_PSEUDO_PATH`).
pub const HTTP_PSEUDO_PATH: &str = ":path";
/// The HTTP/2 `:status` pseudo-header name (← `HTTP_PSEUDO_STATUS`).
pub const HTTP_PSEUDO_STATUS: &str = ":status";

// ===========================================================================
// Frozen size/limit constants (← `lib/http.h`).
//
// These values are part of the observable behaviour contract and must match
// curl 8.x exactly.
// ===========================================================================

/// Bytes of POST data included in the initial request chunk; larger bodies are
/// split across system calls (← `MAX_INITIAL_POST_SIZE`, `64 * 1024`). Must not
/// exceed 64K (a documented VMS constraint in the C source).
pub const MAX_INITIAL_POST_SIZE: usize = 64 * 1024;

/// Request-body size above which `Expect: 100-continue` is added automatically;
/// an unknown length always triggers it (← `EXPECT_100_THRESHOLD`,
/// `1024 * 1024`).
pub const EXPECT_100_THRESHOLD: u64 = 1024 * 1024;

/// Maximum combined size of all response headers for a single HTTP response,
/// any version, including CONNECT (← `MAX_HTTP_RESP_HEADER_SIZE`, `300 * 1024`).
pub const MAX_HTTP_RESP_HEADER_SIZE: usize = 300 * 1024;

/// Maximum number of response headers for a single HTTP response, including
/// CONNECT and redirects (← `MAX_HTTP_RESP_HEADER_COUNT`, `5000`).
pub const MAX_HTTP_RESP_HEADER_COUNT: usize = 5000;

/// "No auth actively selected after a round-trip" sentinel bit
/// (← `CURLAUTH_PICKNONE`, `1 << 30`). Distinct from "no auth selected yet".
pub const CURLAUTH_PICKNONE: u32 = 1 << 30;

// ===========================================================================
// HeaderList — an ordered, case-insensitive HTTP header list
// (← curl's `struct dynhds`, `lib/dynhds.c`).
//
// curl carries request/response headers in a `dynhds` ordered list because wire
// order and exact casing matter for parity (HTTP/1.x preserves case; HTTP/2
// lowercases — see [`http_req_to_h2`]). This is the faithful rewrite: an
// insertion-ordered `Vec<(name, value)>` with case-insensitive lookup. It is
// the shared surface [`HttpReqData`], [`HttpResp`], and the sibling `rtsp`/`ws`
// handlers build on.
// ===========================================================================

/// An ordered, case-insensitive list of HTTP header fields (← `struct
/// dynhds`).
///
/// Insertion order is preserved (it is the wire order) and duplicate field
/// names are permitted (as in HTTP). Field-name comparison for lookup and
/// removal is ASCII-case-insensitive, matching curl's `curl_strequal`. Values
/// and names are stored with their original casing; the HTTP/2 lowercasing is a
/// separate transform applied by [`http_req_to_h2`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeaderList {
    entries: Vec<(String, String)>,
}

impl HeaderList {
    /// Create an empty header list (← a zero-initialised `dynhds`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create an empty header list with capacity for `n` fields.
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self {
            entries: Vec::with_capacity(n),
        }
    }

    /// Append a header field, preserving insertion (wire) order
    /// (← `Curl_dynhds_add`). Duplicate names are kept, as HTTP allows.
    pub fn add(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.entries.push((name.into(), value.into()));
    }

    /// The value of the first field whose name matches `name`
    /// case-insensitively (← `Curl_dynhds_get`), or `None`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether a field named `name` (case-insensitive) is present
    /// (← `Curl_dynhds_get` non-NULL check).
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// The `index`-th field as a `(name, value)` pair (← `Curl_dynhds_getn`),
    /// in insertion order, or `None` if out of range.
    #[must_use]
    pub fn getn(&self, index: usize) -> Option<(&str, &str)> {
        self.entries
            .get(index)
            .map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// The number of fields (← `Curl_dynhds_count`).
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Alias for [`count`](HeaderList::count) using the conventional Rust name.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the list has no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove every field whose name matches `name` case-insensitively,
    /// returning how many were removed (← `Curl_dynhds_remove`).
    pub fn remove(&mut self, name: &str) -> usize {
        let before = self.entries.len();
        self.entries.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        before - self.entries.len()
    }

    /// Clear all fields (← `Curl_dynhds_reset`).
    pub fn reset(&mut self) {
        self.entries.clear();
    }

    /// Iterate the fields as `(name, value)` pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }
}

// ===========================================================================
// HttpReqData — a core HTTP request (← `struct httpreq`, `lib/http.h`).
// ===========================================================================

/// A protocol-version-independent HTTP request: method, target components, and
/// header/trailer lists, excluding the body (← `struct httpreq`).
///
/// This is the neutral representation shared by the h1/h2/h3 send paths and by
/// [`http_req_to_h2`]. The C struct stores `scheme`, `authority`, and `path` as
/// separately owned strings so an HTTP/2/3 sender can assemble pseudo-headers
/// without reparsing; that split is preserved here. In C the request is built
/// by `Curl_http_req_make`/`Curl_http_req_make2` and released by
/// `Curl_http_req_free`; here `Drop` reclaims everything automatically, so no
/// explicit free exists.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpReqData {
    /// The request method, e.g. `GET` (← `char method[]`). Stored uppercase, as
    /// curl emits it.
    pub method: String,
    /// The URI scheme (`http`/`https`), when known (← `char *scheme`).
    pub scheme: Option<String>,
    /// The authority (`host[:port]`), when known (← `char *authority`).
    pub authority: Option<String>,
    /// The request-target path incl. query, when known (← `char *path`).
    pub path: Option<String>,
    /// Ordered request header fields (← `struct dynhds headers`).
    pub headers: HeaderList,
    /// Ordered trailer fields for chunked uploads (← `struct dynhds trailers`).
    pub trailers: HeaderList,
}

impl HttpReqData {
    /// Build a request from a method plus fully split target components
    /// (← `Curl_http_req_make`). Empty component strings are treated as absent,
    /// matching the C convention of a `NULL` pointer.
    #[must_use]
    pub fn make(
        method: &str,
        scheme: Option<&str>,
        authority: Option<&str>,
        path: Option<&str>,
    ) -> Self {
        // curl treats an empty string the same as a missing (NULL) component.
        let norm = |s: Option<&str>| s.filter(|v| !v.is_empty()).map(str::to_owned);
        Self {
            method: method.to_owned(),
            scheme: norm(scheme),
            authority: norm(authority),
            path: norm(path),
            headers: HeaderList::new(),
            trailers: HeaderList::new(),
        }
    }

    /// Build a request from a method and an origin-form or absolute-form target,
    /// splitting scheme/authority/path (← `Curl_http_req_make2`).
    ///
    /// An absolute target such as `https://host/p?q` is decomposed into its
    /// scheme, authority, and path; an origin-form target such as `/p?q` yields
    /// only a path. This mirrors the request-target forms of RFC 9112 §3.2.
    #[must_use]
    pub fn make2(method: &str, target: &str) -> Self {
        // Detect absolute-form: scheme "://" authority path.
        if let Some(scheme_end) = target.find("://") {
            let scheme = &target[..scheme_end];
            // Only treat as absolute when the scheme is a plausible URI scheme
            // (letters/digits/+/-/.). Otherwise fall back to origin-form.
            let scheme_ok = !scheme.is_empty()
                && scheme
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
            if scheme_ok {
                let rest = &target[scheme_end + 3..];
                // Authority ends at the first '/', '?', or '#'.
                let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
                let authority = &rest[..auth_end];
                let path = &rest[auth_end..];
                return Self::make(
                    method,
                    Some(scheme),
                    Some(authority),
                    if path.is_empty() {
                        Some("/")
                    } else {
                        Some(path)
                    },
                );
            }
        }
        // Origin-form (or authority-form for CONNECT): keep the target as-is in
        // the path slot; the sender decides how to interpret it.
        Self::make(method, None, None, Some(target))
    }
}

// ===========================================================================
// HttpResp — a parsed HTTP response head (← `struct http_resp`, `lib/http.h`).
// ===========================================================================

/// A parsed HTTP response's status line and header block, excluding the body
/// (← `struct http_resp`).
///
/// The `prev` link chains an earlier response that preceded this one on the
/// same transfer — a `1xx` informational response, or the response to a
/// CONNECT tunnel request — exactly as curl does. `Drop` walks and frees the
/// chain automatically, replacing `Curl_http_resp_free`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpResp {
    /// The numeric status code, e.g. `200` (← `int status`).
    pub status: i32,
    /// The reason phrase, when present (← `char *description`).
    pub description: Option<String>,
    /// Ordered response header fields (← `struct dynhds headers`).
    pub headers: HeaderList,
    /// Ordered trailer fields (← `struct dynhds trailers`).
    pub trailers: HeaderList,
    /// A preceding response on the same transfer (e.g. `1xx`/CONNECT), if any
    /// (← `struct http_resp *prev`).
    pub prev: Option<Box<HttpResp>>,
}

impl HttpResp {
    /// Build a response head from a status code and optional reason phrase
    /// (← `Curl_http_resp_make`).
    #[must_use]
    pub fn make(status: i32, description: Option<&str>) -> Self {
        Self {
            status,
            description: description.map(str::to_owned),
            headers: HeaderList::new(),
            trailers: HeaderList::new(),
            prev: None,
        }
    }
}

// ===========================================================================
// PHASE 2 — Header machinery.
//
// The self-contained header helpers that the h1/h2/h3 send paths, the redirect
// and auth logic below, and the sibling `rtsp`/`ws` handlers all reuse. Each is
// a faithful port of its `lib/http.c` counterpart, taking exactly the inputs it
// needs rather than the whole `Curl_easy` handle.
// ===========================================================================

/// Whether `x` is an HTTP header field-name separator (← `Curl_headersep`,
/// `lib/transfer.h`): a colon `:` or the semicolon `;` curl accepts on
/// user-supplied `name;`-style empty headers.
#[inline]
#[must_use]
fn header_sep(x: u8) -> bool {
    x == b':' || x == b';'
}

/// Whether `headerline` is the header named `header` (a keyword **with** its
/// trailing colon) carrying `content` somewhere in its value
/// (← `Curl_compareheader`).
///
/// Field-name and content matching are ASCII-case-insensitive per RFC 9110
/// §5.1. The value is taken up to the end of line and its surrounding linear
/// whitespace trimmed, then scanned for `content` as a substring — the
/// documented "contains the content token" contract this function's call sites
/// depend on (chunked/close/100-continue detection over possibly multi-token
/// values such as `Connection: keep-alive, close`).
#[must_use]
pub fn compare_header(headerline: &str, header: &str, content: &str) -> bool {
    debug_assert!(!header.is_empty());
    debug_assert!(!content.is_empty());

    // Must start with the header keyword (which already includes the colon).
    if headerline.len() < header.len()
        || !headerline.as_bytes()[..header.len()].eq_ignore_ascii_case(header.as_bytes())
    {
        return false;
    }

    // The remainder is the value; stop at the first line break, then trim the
    // surrounding linear whitespace curl strips.
    let after = &headerline[header.len()..];
    let value_end = after.find(['\r', '\n']).unwrap_or(after.len());
    let value = after[..value_end].trim_matches(|c: char| c == ' ' || c == '\t');

    if value.len() < content.len() {
        return false;
    }

    // Case-insensitive substring scan for the content token.
    let (vb, cb) = (value.as_bytes(), content.as_bytes());
    (0..=vb.len() - cb.len()).any(|i| vb[i..i + cb.len()].eq_ignore_ascii_case(cb))
}

/// Extract the trimmed value from a `name: value` header line
/// (← `Curl_copy_header_value`).
///
/// The header name runs up to the first colon; the value is everything after
/// it up to the end of line, with leading and trailing linear whitespace
/// removed. A value consisting entirely of whitespace yields an empty string
/// (`Some("")`). `None` is returned only for malformed input with no colon,
/// which the C contract documents as never happening for already-validated
/// `word:` lines.
#[must_use]
pub fn copy_header_value(header: &str) -> Option<String> {
    let colon = header.find(':')?;
    let after = &header[colon + 1..];
    let value_end = after.find(['\r', '\n']).unwrap_or(after.len());
    let value = after[..value_end].trim_matches(|c: char| c == ' ' || c == '\t');
    Some(value.to_owned())
}

/// Find the first line in `headers` that names `this_header` (case-insensitive)
/// followed immediately by a `:`/`;` separator, returning the whole line.
///
/// This is the shared core of curl's `Curl_checkheaders` and
/// `Curl_checkProxyheaders`; the two differ only in which custom-header list
/// the caller passes.
#[must_use]
fn find_header<'a>(headers: &'a [String], this_header: &str) -> Option<&'a str> {
    let tlen = this_header.len();
    headers.iter().find_map(|line| {
        let bytes = line.as_bytes();
        if bytes.len() > tlen
            && bytes[..tlen].eq_ignore_ascii_case(this_header.as_bytes())
            && header_sep(bytes[tlen])
        {
            Some(line.as_str())
        } else {
            None
        }
    })
}

/// Find a user-supplied header matching `this_header` (case-insensitive) in the
/// normal custom-header list (← `Curl_checkheaders`).
///
/// A line matches when it begins with `this_header` followed immediately by a
/// `:`/`;` separator. The full matching line is returned, or `None`.
#[must_use]
pub fn check_headers<'a>(headers: &'a [String], this_header: &str) -> Option<&'a str> {
    find_header(headers, this_header)
}

/// Find a user-supplied header matching `this_header` (case-insensitive) among
/// the proxy custom-header lines (← `Curl_checkProxyheaders`).
///
/// `headers` is the applicable proxy header set the caller selects (the
/// separate proxy header list when configured, otherwise the normal list),
/// mirroring the C selection. Matching is identical to [`check_headers`].
#[must_use]
pub fn check_proxy_headers<'a>(headers: &'a [String], this_header: &str) -> Option<&'a str> {
    find_header(headers, this_header)
}

/// Parse the three-digit numeric status code from the `s` field of a status
/// line (← `Curl_http_decode_status`).
///
/// `s` must be exactly three ASCII digits; anything else is
/// [`CurlCode::BadFunctionArgument`], matching the C contract that also sets
/// the out-status to `-1` on failure.
///
/// # Errors
///
/// Returns [`Error`] mapping to [`CurlCode::BadFunctionArgument`] when `s` is
/// not exactly three digits.
pub fn http_decode_status(s: &str) -> Result<i32> {
    let b = s.as_bytes();
    if b.len() != 3 || !b.iter().all(u8::is_ascii_digit) {
        return Err(Error::from(CurlCode::BadFunctionArgument));
    }
    let status =
        100 * i32::from(b[0] - b'0') + 10 * i32::from(b[1] - b'0') + i32::from(b[2] - b'0');
    Ok(status)
}

/// The transfer-shaped inputs [`http_method`] needs, factored out of the C
/// `Curl_easy` handle (← the fields `Curl_http_method` reads).
#[derive(Clone, Copy, Debug)]
pub struct MethodInput<'a> {
    /// The connection scheme's protocol bit (← `conn->scheme->protocol`).
    pub protocol: u32,
    /// Whether this is an upload (← `data->state.upload`).
    pub upload: bool,
    /// A `CURLOPT_CUSTOMREQUEST` override, if set
    /// (← `data->set.str[STRING_CUSTOMREQUEST]`).
    pub custom_request: Option<&'a str>,
    /// Whether the custom request must be ignored (← `http_ignorecustom`),
    /// set by the redirect logic after a method downgrade.
    pub http_ignorecustom: bool,
    /// Whether the response carries no body, e.g. after a HEAD
    /// (← `data->req.no_body`).
    pub no_body: bool,
    /// The requested [`HttpReq`] kind (← `data->state.httpreq`).
    pub httpreq: HttpReq,
}

/// Resolve the request method string and effective [`HttpReq`] from the
/// transfer options (← `Curl_http_method`).
///
/// The precedence matches curl exactly: WebSocket schemes force `GET`; an
/// upload on an HTTP-family or FTP connection forces `PUT`; an honoured
/// `CURLOPT_CUSTOMREQUEST` wins next; otherwise a bodyless request is `HEAD`
/// and the remaining kinds map to their canonical method strings. The returned
/// [`HttpReq`] is the (possibly overridden) effective kind, preserving the
/// internal form/mime POST distinction for the body-reader selection.
#[must_use]
pub fn http_method<'a>(input: MethodInput<'a>) -> (&'a str, HttpReq) {
    let mut httpreq = input.httpreq;

    if input.protocol & (CURLPROTO_WS | CURLPROTO_WSS) != 0 {
        httpreq = HttpReq::Get;
    } else if input.protocol & (PROTO_FAMILY_HTTP | CURLPROTO_FTP) != 0 && input.upload {
        httpreq = HttpReq::Put;
    }

    let method: &'a str = if let Some(custom) = input.custom_request {
        if !input.http_ignorecustom {
            custom
        } else {
            method_for(input.no_body, httpreq)
        }
    } else {
        method_for(input.no_body, httpreq)
    };

    (method, httpreq)
}

/// Map a bodyless flag and [`HttpReq`] to curl's canonical method literal
/// (← the `switch(httpreq)` in `Curl_http_method`).
#[inline]
fn method_for(no_body: bool, httpreq: HttpReq) -> &'static str {
    if no_body {
        return "HEAD";
    }
    match httpreq {
        HttpReq::Post | HttpReq::PostForm | HttpReq::PostMime => "POST",
        HttpReq::Put => "PUT",
        HttpReq::Head => "HEAD",
        HttpReq::Get => "GET",
    }
}

// ---------------------------------------------------------------------------
// Time-condition header (← `Curl_add_timecondition`).
// ---------------------------------------------------------------------------

/// `CURL_TIMECOND_NONE` — no time condition requested.
pub const CURL_TIMECOND_NONE: u32 = 0;
/// `CURL_TIMECOND_IFMODSINCE` — emit `If-Modified-Since`.
pub const CURL_TIMECOND_IFMODSINCE: u32 = 1;
/// `CURL_TIMECOND_IFUNMODSINCE` — emit `If-Unmodified-Since`.
pub const CURL_TIMECOND_IFUNMODSINCE: u32 = 2;
/// `CURL_TIMECOND_LASTMOD` — condition on `Last-Modified`.
pub const CURL_TIMECOND_LASTMOD: u32 = 3;

/// The transfer inputs [`add_timecondition`] needs (← the `Curl_easy` fields
/// `Curl_add_timecondition` reads).
#[derive(Clone, Copy, Debug)]
pub struct TimeCondInput<'a> {
    /// The `CURLOPT_TIMECONDITION` selector (a `CURL_TIMECOND_*` value).
    pub timecondition: u32,
    /// The `CURLOPT_TIMEVALUE` epoch seconds (← `data->set.timevalue`).
    pub timevalue: i64,
    /// The normal custom-header list, so an overriding user header suppresses
    /// the generated one (← `Curl_checkheaders`).
    pub custom_headers: &'a [String],
}

/// Append an `If-Modified-Since`/`If-Unmodified-Since` header derived from
/// `CURLOPT_TIMECONDITION` + `CURLOPT_TIMEVALUE` to the HTTP/1.x request buffer
/// `out` (← `Curl_add_timecondition`).
///
/// The date is formatted as the RFC 7231 IMF-fixdate curl emits — e.g.
/// `Tue, 15 Nov 1994 12:45:26 GMT` — always in GMT/UTC. Nothing is appended for
/// [`CURL_TIMECOND_NONE`], for [`CURL_TIMECOND_LASTMOD`] (which has no request
/// header), or when the corresponding header was supplied by the user.
///
/// # Errors
///
/// Returns [`CurlCode::BadFunctionArgument`] for an unrecognised time condition
/// or a `timevalue` that is not a representable timestamp (curl's
/// "Invalid TIMEVALUE").
pub fn add_timecondition(input: TimeCondInput<'_>, out: &mut String) -> Result<()> {
    if input.timecondition == CURL_TIMECOND_NONE {
        return Ok(());
    }

    // Resolve the header name for the condition; an unknown selector is a bad
    // argument, exactly as curl's `default:` branch.
    let condp = match input.timecondition {
        CURL_TIMECOND_IFMODSINCE => "If-Modified-Since",
        CURL_TIMECOND_IFUNMODSINCE => "If-Unmodified-Since",
        CURL_TIMECOND_LASTMOD => "Last-Modified",
        _ => return Err(Error::bad_argument("invalid time condition")),
    };

    // A user-supplied header of the same name is sent instead.
    if find_header(input.custom_headers, condp).is_some() {
        return Ok(());
    }

    // `Last-Modified` is only meaningful as a response header; curl computes the
    // date for every selector but only the If-*-Since names are emitted as a
    // request header. The switch above already restricts `condp`, so format and
    // append here.
    let dt = DateTime::<Utc>::from_timestamp(input.timevalue, 0)
        .ok_or_else(|| Error::bad_argument("Invalid TIMEVALUE"))?;
    // "Tue, 15 Nov 1994 12:45:26 GMT" — locale-independent English names.
    let datestr = dt.format("%a, %d %b %Y %H:%M:%S GMT");
    write!(out, "{condp}: {datestr}\r\n").map_err(|_| Error::OutOfMemory)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Header folding (← `Curl_http_to_fold`).
// ---------------------------------------------------------------------------

/// Fold a header buffer in place: strip a trailing CRLF/LF and any trailing
/// linear whitespace so a continuation line can be appended
/// (← `Curl_http_to_fold`).
pub fn http_to_fold(buf: &mut String) {
    let bytes = buf.as_bytes();
    let mut len = bytes.len();
    if len > 0 && bytes[len - 1] == b'\n' {
        len -= 1;
    }
    if len > 0 && bytes[len - 1] == b'\r' {
        len -= 1;
    }
    while len > 0 && (bytes[len - 1] == b' ' || bytes[len - 1] == b'\t') {
        len -= 1;
    }
    buf.truncate(len);
}

// ---------------------------------------------------------------------------
// Response-header size accounting (← `Curl_bump_headersize`).
// ---------------------------------------------------------------------------

/// Running response-header byte counters for a single transfer
/// (← the `Curl_easy` `info.header_size` / `req.allheadercount` /
/// `req.headerbytecount` fields).
///
/// Despite curl's field name, `allheadercount` accumulates *bytes*, not a
/// header count; the header *count* limit ([`MAX_HTTP_RESP_HEADER_COUNT`]) is
/// enforced separately by the header-store layer, not here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeaderSizeState {
    /// Total header bytes reported via `CURLINFO_HEADER_SIZE`.
    pub header_size: u32,
    /// All received header bytes (server + CONNECT).
    pub allheadercount: u32,
    /// Header bytes counted toward the body/transfer accounting (server only).
    pub headerbytecount: u32,
}

/// Accumulate `delta` response-header bytes and enforce the size ceilings
/// (← `Curl_bump_headersize`).
///
/// When `connect_only` is set the bytes count toward the totals but not
/// `headerbytecount`, matching CONNECT-tunnel accounting. The ceilings are
/// [`MAX_HTTP_RESP_HEADER_SIZE`] on the running byte total and twenty times
/// that on the informational header size.
///
/// # Errors
///
/// Returns [`CurlCode::RecvError`] carrying curl's exact
/// `Too large response headers: <bad> > <max>` message when a ceiling is
/// exceeded, matching the C `failf` + `CURLE_RECV_ERROR`.
pub fn bump_headersize(
    state: &mut HeaderSizeState,
    delta: usize,
    connect_only: bool,
) -> Result<()> {
    let mut bad: usize = 0;
    let mut max: u32 = MAX_HTTP_RESP_HEADER_SIZE as u32;

    if delta < MAX_HTTP_RESP_HEADER_SIZE {
        // `delta < 300K` guarantees the `as u32` casts below are lossless.
        let d = delta as u32;
        state.header_size = state.header_size.saturating_add(d);
        state.allheadercount = state.allheadercount.saturating_add(d);
        if !connect_only {
            state.headerbytecount = state.headerbytecount.saturating_add(d);
        }
        if state.allheadercount > max {
            bad = state.allheadercount as usize;
        } else if state.header_size > max.saturating_mul(20) {
            bad = state.header_size as usize;
            max = max.saturating_mul(20);
        }
    } else {
        bad = state.allheadercount as usize + delta;
    }

    if bad != 0 {
        return Err(Error::with_context(
            CurlCode::RecvError,
            format!("Too large response headers: {bad} > {max}"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Custom request headers (← `Curl_add_custom_headers` / `dynhds_add_custom`).
// ---------------------------------------------------------------------------

/// The transfer inputs the custom-header emitters need, factored out of the
/// `Curl_easy` handle (← the fields `Curl_add_custom_headers` reads).
///
/// The list selection curl performs from `conn->bits`/`data->set` is expressed
/// here as the two source lists plus the selecting flags, so the port makes the
/// identical `HEADER_SERVER`/`HEADER_PROXY`/`HEADER_CONNECT` choice.
#[derive(Clone, Copy, Debug)]
pub struct CustomHeadersInput<'a> {
    /// The normal custom-header list (← `data->set.headers`).
    pub server_headers: &'a [String],
    /// The separate proxy custom-header list (← `data->set.proxyheaders`).
    pub proxy_headers: &'a [String],
    /// Whether proxy headers are kept separate (← `data->set.sep_headers`).
    pub sep_headers: bool,
    /// Whether the connection goes through an HTTP proxy
    /// (← `conn->bits.httpproxy`).
    pub httpproxy: bool,
    /// Whether the proxy is a tunnelling (CONNECT) proxy
    /// (← `conn->bits.tunnel_proxy`).
    pub tunnel_proxy: bool,
    /// Whether a `Host` header has already been emitted, so a custom `Host` is
    /// dropped to avoid duplicates (← `data->state.aptr.host != NULL`).
    pub host_already_sent: bool,
    /// The request kind, gating the `Content-Type` suppression for form/mime
    /// POSTs (← `data->state.httpreq`).
    pub httpreq: HttpReq,
    /// Whether an auth-negotiation round is forcing a zero length, suppressing
    /// a custom `Content-Length` (← `data->req.authneg`).
    pub authneg: bool,
    /// Whether sensitive headers may be sent to this host, gating
    /// `Authorization`/`Cookie` (← `Curl_auth_allowed_to_host`).
    pub allowed_to_host: bool,
}

impl<'a> CustomHeadersInput<'a> {
    /// Select the applicable header list(s) exactly as curl's proxy-use switch
    /// (← the `HEADER_SERVER`/`HEADER_PROXY`/`HEADER_CONNECT` cases).
    fn select_lists(&self, is_connect: bool) -> Vec<&'a [String]> {
        if is_connect {
            // HEADER_CONNECT
            vec![if self.sep_headers {
                self.proxy_headers
            } else {
                self.server_headers
            }]
        } else if self.httpproxy && !self.tunnel_proxy {
            // HEADER_PROXY: normal list, plus the separate proxy list if any.
            if self.sep_headers {
                vec![self.server_headers, self.proxy_headers]
            } else {
                vec![self.server_headers]
            }
        } else {
            // HEADER_SERVER
            vec![self.server_headers]
        }
    }

    /// Whether the header named `name` must be suppressed for this request
    /// (← the `else if(... casecompare ...)` suppression chain).
    ///
    /// `include_connection` distinguishes the HTTP/1.x emitter (which drops
    /// `Connection`, handled specially there) from the `dynhds` emitter (which
    /// does not, per `dynhds_add_custom`).
    fn suppressed(&self, name: &str, http_version: i32, include_connection: bool) -> bool {
        (self.host_already_sent && name.eq_ignore_ascii_case("Host"))
            || (self.httpreq == HttpReq::PostForm && name.eq_ignore_ascii_case("Content-Type"))
            || (self.httpreq == HttpReq::PostMime && name.eq_ignore_ascii_case("Content-Type"))
            || (self.authneg && name.eq_ignore_ascii_case("Content-Length"))
            || (include_connection && name.eq_ignore_ascii_case("Connection"))
            || (http_version >= 20 && name.eq_ignore_ascii_case("Transfer-Encoding"))
            || ((name.eq_ignore_ascii_case("Authorization") || name.eq_ignore_ascii_case("Cookie"))
                && !self.allowed_to_host)
    }
}

/// A single parsed custom-header line (← the per-line branching in
/// `Curl_add_custom_headers`).
enum CustomHeader<'a> {
    /// `name;` — send an (illegal) empty header (curl's "quirk #2").
    Blank(&'a str),
    /// `name: value` — a header with content; `line` is the original text and
    /// `value` is the trimmed value.
    Full {
        /// The field name (text before the colon).
        name: &'a str,
        /// The trimmed field value.
        value: &'a str,
        /// The full original line, emitted verbatim on the HTTP/1.x wire.
        line: &'a str,
    },
    /// Ignore this line (no colon, or `name:` with empty value — curl's
    /// "quirk #1" suppression).
    Skip,
}

/// Classify a custom-header line into [`CustomHeader`] (← the `curlx_str_*`
/// parsing shared by the two custom-header emitters).
fn parse_custom_header(line: &str) -> CustomHeader<'_> {
    // "quirk #2": a line ending in ';' with no ':' in the name sends an empty
    // header. The ';' must be the final byte.
    if let Some(semi) = line.find(';') {
        if semi + 1 == line.len() {
            let name = &line[..semi];
            if !name.contains(':') {
                return CustomHeader::Blank(name);
            }
        }
    }
    // Otherwise it must be a "name: value" header; an empty value is dropped.
    if let Some(colon) = line.find(':') {
        let name = &line[..colon];
        let after = &line[colon + 1..];
        let value_end = after.find(['\r', '\n']).unwrap_or(after.len());
        let value = after[..value_end].trim_matches(|c: char| c == ' ' || c == '\t');
        if value.is_empty() {
            return CustomHeader::Skip;
        }
        return CustomHeader::Full { name, value, line };
    }
    CustomHeader::Skip
}

/// Append the applicable `CURLOPT_HTTPHEADER` entries to the HTTP/1.x request
/// buffer `out` (← `Curl_add_custom_headers`).
///
/// Honours empty-header suppression, the `name;`-means-empty quirk, the
/// duplicate-`Host` guard, the form/mime `Content-Type` and auth-neg
/// `Content-Length` deferrals, the special `Connection` handling, the
/// HTTP/2+ `Transfer-Encoding` drop, and the cross-host `Authorization`/`Cookie`
/// gate — exactly as curl. Full headers are emitted verbatim to preserve the
/// user's spacing on the wire.
///
/// # Errors
///
/// Returns [`Error::OutOfMemory`] only if writing to `out` fails.
pub fn add_custom_headers(
    input: &CustomHeadersInput<'_>,
    is_connect: bool,
    http_version: i32,
    out: &mut String,
) -> Result<()> {
    for list in input.select_lists(is_connect) {
        for line in list {
            match parse_custom_header(line) {
                CustomHeader::Skip => {}
                CustomHeader::Blank(name) => {
                    if !input.suppressed(name, http_version, true) {
                        write!(out, "{name}:\r\n").map_err(|_| Error::OutOfMemory)?;
                    }
                }
                CustomHeader::Full { name, line, .. } => {
                    if !input.suppressed(name, http_version, true) {
                        write!(out, "{line}\r\n").map_err(|_| Error::OutOfMemory)?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Append the applicable `CURLOPT_HTTPHEADER` entries to an ordered
/// [`HeaderList`] for HTTP/2 and HTTP/3 senders (← `dynhds_add_custom`).
///
/// Behaves like [`add_custom_headers`] but stores parsed `(name, value)` pairs
/// rather than raw lines, and — matching the C `dynhds` variant — does **not**
/// suppress `Connection` (which the h1 path handles specially); the later
/// [`http_req_to_h2`] transform drops the connection-specific fields per RFC
/// 9113 §8.2.2.
///
/// # Errors
///
/// This port cannot fail; the `Result` mirrors the C signature for parity.
pub fn dynhds_add_custom(
    input: &CustomHeadersInput<'_>,
    is_connect: bool,
    http_version: i32,
    hds: &mut HeaderList,
) -> Result<()> {
    for list in input.select_lists(is_connect) {
        for line in list {
            match parse_custom_header(line) {
                CustomHeader::Skip => {}
                CustomHeader::Blank(name) => {
                    if !input.suppressed(name, http_version, false) {
                        hds.add(name, "");
                    }
                }
                CustomHeader::Full { name, value, .. } => {
                    if !input.suppressed(name, http_version, false) {
                        hds.add(name, value);
                    }
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP/1.x → HTTP/2 header transform (← `Curl_http_req_to_h2`).
// ---------------------------------------------------------------------------

/// Connection-specific field names that must not cross into HTTP/2/3
/// (← `H2_NON_FIELD`, RFC 9113 §8.2.2). Kept case-insensitive here.
const H2_NON_FIELD: [&str; 6] = [
    "Host",
    "Upgrade",
    "Connection",
    "Keep-Alive",
    "Proxy-Connection",
    "Transfer-Encoding",
];

/// Whether a field named `name` may be forwarded into an HTTP/2/3 header block
/// (← `h2_permissible_field`): `false` for the connection-specific
/// [`H2_NON_FIELD`] names, `true` otherwise.
#[must_use]
fn h2_permissible_field(name: &str) -> bool {
    !H2_NON_FIELD.iter().any(|f| f.eq_ignore_ascii_case(name))
}

/// Whether a `TE` field value contains the `trailers` token (←
/// `http_TE_has_token`).
///
/// `TE` is the one connection-specific field HTTP/2 permits, and only with the
/// exact value `trailers` (RFC 9113 §8.2.2). Tokens are comma-separated; any
/// per-token parameters (including quoted strings) after the token name are
/// skipped. A value that does not follow HTTP token syntax yields `false`.
#[must_use]
fn http_te_has_token(fvalue: &str, token: &str) -> bool {
    let b = fvalue.as_bytes();
    let mut i = 0;
    while i < b.len() {
        // Skip leading blanks and commas to the next token.
        while i < b.len() && (b[i] == b' ' || b[i] == b'\t' || b[i] == b',') {
            i += 1;
        }
        // Read the token name, up to the next separator/parameter char.
        let start = i;
        while i < b.len() && !matches!(b[i], b' ' | b'\t' | b'\r' | b';' | b',') {
            i += 1;
        }
        if i == start {
            // No token text found at this position: malformed.
            return false;
        }
        if fvalue[start..i].eq_ignore_ascii_case(token) {
            return true;
        }
        // Skip the remainder of this token's parameters until the next comma,
        // honouring quoted strings so a quoted comma does not split a token.
        while i < b.len() && b[i] != b',' {
            if b[i] == b'"' {
                i += 1;
                let mut closed = false;
                while i < b.len() {
                    match b[i] {
                        b'\\' if i + 1 < b.len() => i += 2, // quoted-pair
                        b'"' => {
                            i += 1;
                            closed = true;
                            break;
                        }
                        _ => i += 1,
                    }
                }
                if !closed {
                    // Unterminated quoted string: reject, as curl does.
                    return false;
                }
            } else {
                i += 1;
            }
        }
    }
    false
}

/// Transform a neutral [`HttpReqData`] into the ordered HTTP/2/3 header list
/// (← `Curl_http_req_to_h2`).
///
/// The transform, applied in curl's exact order:
/// 1. Determine the `:scheme` — from `req.scheme`, else (for non-`CONNECT`
///    methods) a user `:scheme` pseudo-header, else `https`/`http` from
///    `is_ssl`.
/// 2. Determine the `:authority` — from `req.authority`, else the `Host` header.
/// 3. Emit the pseudo-headers `:method`, `:scheme`, `:authority`, `:path` in
///    that order.
/// 4. Forward the remaining fields, lowercasing every field name (RFC 9113
///    §8.1.2), dropping the connection-specific [`H2_NON_FIELD`] names, and
///    admitting `TE` only when its value is exactly `trailers`.
///
/// A `Host` header, if present, is therefore consumed into `:authority` and not
/// forwarded (it is a non-field). The returned [`HeaderList`] preserves the
/// emission order for wire parity.
///
/// # Errors
///
/// This port cannot fail; the `Result` mirrors the C signature for parity.
pub fn http_req_to_h2(req: &HttpReqData, is_ssl: bool) -> Result<HeaderList> {
    // (1) :scheme
    let scheme: Option<String> = if let Some(s) = &req.scheme {
        Some(s.clone())
    } else if req.method != "CONNECT" {
        if let Some(v) = req.headers.get(HTTP_PSEUDO_SCHEME) {
            // A user-supplied ":scheme" pseudo-header overrides; trim leading
            // blanks exactly as curl's `str_passblanks`.
            let trimmed = v.trim_start_matches([' ', '\t']);
            tracing::debug!("set pseudo header {} to {}", HTTP_PSEUDO_SCHEME, trimmed);
            Some(trimmed.to_owned())
        } else {
            Some(if is_ssl { "https" } else { "http" }.to_owned())
        }
    } else {
        None
    };

    // (2) :authority
    let authority: Option<String> = req
        .authority
        .clone()
        .or_else(|| req.headers.get("Host").map(str::to_owned));

    // (3) pseudo-headers in fixed order. Names are already lowercase.
    let mut h2 = HeaderList::with_capacity(req.headers.count() + 4);
    h2.add(HTTP_PSEUDO_METHOD, req.method.clone());
    if let Some(s) = scheme {
        h2.add(HTTP_PSEUDO_SCHEME, s);
    }
    if let Some(a) = authority {
        h2.add(HTTP_PSEUDO_AUTHORITY, a);
    }
    if let Some(p) = &req.path {
        h2.add(HTTP_PSEUDO_PATH, p.clone());
    }

    // (4) forward the regular fields, lowercasing names.
    for (name, value) in req.headers.iter() {
        if name.eq_ignore_ascii_case("TE") {
            // TE is permitted only as "trailers".
            if http_te_has_token(value, "trailers") {
                h2.add(name.to_ascii_lowercase(), "trailers");
            }
        } else if h2_permissible_field(name) {
            h2.add(name.to_ascii_lowercase(), value.to_owned());
        }
    }

    Ok(h2)
}

// ===========================================================================
// PHASE 3a — Version negotiation and dispatch (← `http_may_use_1_1`,
// `http_request_version`, `get_http_string`).
// ===========================================================================

/// The version token curl writes into a request line / version banner for a
/// wire version number (← `get_http_string`): `30`→`"3"`, `20`→`"2"`,
/// `11`→`"1.1"`, anything else →`"1.0"`.
#[must_use]
pub fn get_http_string(httpversion: i32) -> &'static str {
    match httpversion {
        30 => "3",
        20 => "2",
        11 => "1.1",
        _ => "1.0",
    }
}

/// The wire version number an ALPN result maps to (← the mapping behind
/// `Curl_conn_http_version`): `10`/`11`/`20`/`30`, or `0` when nothing was
/// negotiated ([`AlpnProtocol::None`]) so the caller falls back to
/// [`http_may_use_1_1`].
#[must_use]
pub fn alpn_to_http_version(alpn: AlpnProtocol) -> u8 {
    match alpn {
        AlpnProtocol::Http10 => 10,
        AlpnProtocol::Http11 => 11,
        AlpnProtocol::H2 => 20,
        AlpnProtocol::H3 => 30,
        AlpnProtocol::None => 0,
    }
}

/// Whether HTTP/1.1 (as opposed to being forced down to 1.0) may be used on
/// this transfer (← `http_may_use_1_1`).
///
/// `httpversion_seen` is the highest version observed on *this* connection so
/// far (`None` when there is no connection or no response yet), mirroring
/// `conn->httpversion_seen`.
#[must_use]
pub fn http_may_use_1_1(neg: &HttpNegotiation, httpversion_seen: Option<u8>) -> bool {
    // A prior 1.0 response for this transfer pins us to 1.0.
    if neg.rcvd_min == 10 {
        return false;
    }
    // A prior 1.0 response on this connection pins us to 1.0.
    if httpversion_seen == Some(10) {
        return false;
    }
    // We asked for 1.0 and have seen nothing higher on this connection yet.
    // (`map_or(true, ..)` rather than `is_none_or` to hold MSRV 1.75.)
    if neg.only_10 && httpversion_seen.map_or(true, |v| v <= 10) {
        return false;
    }
    // Otherwise 1.1 is allowed unless we are pinned to 1.0.
    !neg.only_10
}

/// The HTTP major version to request (`10`/`11`/`20`/`30`) for this transfer
/// (← `http_request_version`).
///
/// `conn_http_version` is the version an installed HTTP connection filter has
/// already negotiated (e.g. via ALPN — compute it with
/// [`alpn_to_http_version`]), or `0` when none is installed; in that case the
/// choice falls back to 1.1 vs 1.0 via [`http_may_use_1_1`].
#[must_use]
pub fn http_request_version(
    conn_http_version: u8,
    neg: &HttpNegotiation,
    httpversion_seen: Option<u8>,
) -> u8 {
    if conn_http_version != 0 {
        return conn_http_version;
    }
    if http_may_use_1_1(neg, httpversion_seen) {
        11
    } else {
        10
    }
}

// ===========================================================================
// PHASE 3b — The `http`/`https` protocol handler (← `Curl_protocol_http`).
// ===========================================================================

/// The zero-sized `http`/`https` protocol handler (← the `Curl_protocol_http`
/// vtable, `lib/http.c`).
///
/// Its [`Protocol`] methods map 1:1 onto curl's `Curl_protocol_http` function
/// pointers:
///
/// | [`Protocol`] method | curl function |
/// |---|---|
/// | [`setup_connection`](Protocol::setup_connection) | `Curl_http_setup_conn` |
/// | [`do_it`](Protocol::do_it) | `Curl_http` |
/// | [`done`](Protocol::done) | `Curl_http_done` |
/// | [`doing_pollset`](Protocol::doing_pollset) | `Curl_http_doing_pollset` |
/// | [`perform_pollset`](Protocol::perform_pollset) | `Curl_http_perform_pollset` |
/// | [`write_resp`](Protocol::write_resp) | `Curl_http_write_resp` |
/// | [`write_resp_hd`](Protocol::write_resp_hd) | `Curl_http_write_resp_hd` |
/// | [`follow`](Protocol::follow) | `Curl_http_follow` |
///
/// Every other `Curl_protocol_http` slot is `ZERO_NULL` in curl and therefore
/// left as the trait's no-op default here.
///
/// The self-contained request/response, redirect, and auth logic lives in the
/// free functions in this module (which is exactly what the sibling `rtsp`/`ws`
/// handlers reuse). The trait hooks become active once [`TransferCtx`] carries
/// the per-transfer and connection state the driver owns; until then they
/// report the required completion values and defer the wire transfer to
/// [`h1`], [`h2`], and [`h3`] — mirroring the sibling [`crate::protocols::rtsp`]
/// handler.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HttpHandler;

/// The shared `http`/`https` handler instance referenced by
/// [`SCHEME_HTTP`](crate::protocols::SCHEME_HTTP) and
/// [`SCHEME_HTTPS`](crate::protocols::SCHEME_HTTPS).
pub static HANDLER: HttpHandler = HttpHandler;

/// A `const` alias of [`HANDLER`] for callers that need the handler in a
/// `const` context (← the `&Curl_protocol_http` references in curl).
pub const HTTP_HANDLER: HttpHandler = HttpHandler;

/// The per-transfer HTTP state the [`HttpHandler`] hooks thread through
/// [`TransferCtx::proto_state`] across the DO / PERFORM / DONE phases.
///
/// This is the port of the HTTP-specific fields of curl's `struct SingleRequest`
/// (`data->req`) and the HTTP portions of `data->state`: the version
/// negotiation (`data->state.http_neg`), the running response-header byte
/// accounting (`Curl_bump_headersize`), the redirect-follow bookkeeping, and
/// the captured response head. It is type-erased into `proto_state` so the
/// generic [`TransferCtx`] names no HTTP-specific type, exactly as curl keeps
/// the protocol union opaque.
#[derive(Debug, Default)]
struct HttpTransferState {
    /// Per-transfer version-negotiation state (← `data->state.http_neg`).
    neg: HttpNegotiation,
    /// Running response-header byte counters (← `Curl_bump_headersize`).
    hdr_size: HeaderSizeState,
    /// Redirect-follow state advanced by [`http_follow`] (← the follow fields of
    /// `data->state`/`data->info`).
    follow: FollowState,
    /// The response head captured by the DO phase, retained for the driver to
    /// reconcile into the easy handle and for tests to assert against
    /// (← `data->req` response fields).
    resp: Option<HttpResp>,
}

/// Borrow the context's [`HttpTransferState`], installing a fresh one when the
/// `proto_state` slot is empty or holds a different type.
///
/// Every hook calls this so it is self-sufficient even when invoked directly
/// (e.g. by a unit test that did not run [`setup_connection`] first), mirroring
/// curl lazily allocating the HTTP `SingleRequest` state on first use.
fn http_state(ctx: &mut TransferCtx) -> &mut HttpTransferState {
    let needs_init = ctx
        .proto_state
        .as_ref()
        .map_or(true, |b| !b.is::<HttpTransferState>());
    if needs_init {
        ctx.proto_state = Some(Box::<HttpTransferState>::default());
    }
    ctx.proto_state
        .as_mut()
        .and_then(|b| b.downcast_mut::<HttpTransferState>())
        .expect("HttpTransferState was just installed")
}

/// The `Host`/`:authority` value for a request (← curl's `Curl_conn_host`
/// selection): the host, plus `:port` only when the port is not the scheme's
/// default (`80` for `http`/`ws`, `443` for `https`/`wss`), matching curl
/// omitting the default port from the `Host` header.
fn authority_for(scheme: &str, host: &str, port: u16) -> String {
    let default_port = match scheme {
        "https" | "wss" => 443,
        _ => 80,
    };
    if port == 0 || port == default_port {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    }
}

/// Assemble an [`HttpReqData`] from the transfer's request options
/// (← `Curl_http` building the request head), preserving curl's header order:
/// caller-supplied `CURLOPT_HTTPHEADER` lines first, then the option-derived
/// `User-Agent`, `Referer`, `Accept-Encoding`, and (when credentials are
/// present) a Basic `Authorization` header.
///
/// The `Host`/`:authority` and the request target are derived from the parsed
/// URL components; the request-body framing is chosen separately by
/// [`request_body_for`]. Challenge-response mechanisms (Digest/NTLM/Negotiate)
/// are driven across requests by the transfer driver; the initial request
/// carries Basic credentials when supplied, matching curl's default when
/// `--user` is given without a specific scheme.
/// Render the HTTP request head this transfer will send, in curl's `-v`/`--trace` `> `
/// (HEADER_OUT) wire form: the request line, the derived `Host` header, and the
/// option/auth-derived header block, terminated by the blank line.
///
/// Delegates to [`build_http_request`] so the rendered head is exactly what the handler
/// assembles — same header order, same `--user` Basic-auth rule — keeping the trace honest. In
/// particular an `Authorization` header (Basic from `--user`, or a caller-supplied Bearer) is
/// shown verbatim, exactly as curl 8.x prints it under `-v`; the plaintext `--user` password is
/// never emitted because Basic transmits it base64-encoded. Returns an empty vector if the head
/// cannot be built (e.g. malformed credentials), so the caller simply emits no `> ` block. The
/// wire version is rendered as `HTTP/1.1` (the request-line form curl shows for the common
/// case); the negotiated 2/3 upgrade does not change the header vocabulary.
pub(crate) fn trace_request_head_bytes(req: &super::TransferRequest) -> Vec<u8> {
    let out = match build_http_request(req) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let method = if out.method.is_empty() {
        "GET"
    } else {
        out.method.as_str()
    };
    let path = out.path.as_deref().unwrap_or("/");
    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    if let Some(auth) = out.authority.as_deref() {
        head.push_str("Host: ");
        head.push_str(auth);
        head.push_str("\r\n");
    }
    // Render every option/auth-derived header except `Content-Type`, which curl prints last —
    // right after the framing `Content-Length` — for a request that carries a body. Holding it
    // back keeps the `-v` head byte-order-faithful to curl 8.x (`… Content-Length … Content-Type`).
    let mut content_type: Option<&str> = None;
    for (name, value) in out.headers.iter() {
        if name.eq_ignore_ascii_case("Content-Type") {
            content_type = Some(value);
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    // `Content-Length` is chosen by the transport (hyper) at send time from the body length, so
    // it is not present in `out.headers`; synthesize it here so `-v`/`--trace` shows the same
    // `> Content-Length:` line curl prints for a sized body (`-d` post or `-T` upload). Only when
    // the caller did not already carry an explicit framing header.
    if let Some(body) = req.body.as_ref() {
        if !out.headers.contains("Content-Length") && !out.headers.contains("Transfer-Encoding") {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
    }
    if let Some(ct) = content_type {
        head.push_str("Content-Type: ");
        head.push_str(ct);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    head.into_bytes()
}

fn build_http_request(req: &super::TransferRequest) -> Result<HttpReqData> {
    let method = if req.method.is_empty() {
        "GET"
    } else {
        req.method.as_str()
    };
    let authority = authority_for(&req.scheme, &req.host, req.port);
    let path = if req.path.is_empty() {
        "/".to_owned()
    } else {
        match req.query.as_deref() {
            Some(q) if !q.is_empty() => format!("{}?{}", req.path, q),
            _ => req.path.clone(),
        }
    };
    let scheme = if req.scheme.is_empty() {
        None
    } else {
        Some(req.scheme.as_str())
    };

    let mut out = HttpReqData::make(method, scheme, Some(&authority), Some(&path));

    // Caller-supplied headers first ("Name: value" lines), preserving order.
    for line in &req.headers {
        if let Some((name, value)) = line.split_once(':') {
            out.headers.add(name.trim(), value.trim());
        }
    }
    // Option-derived headers, only when the corresponding option was set.
    if let Some(ua) = req.user_agent.as_deref() {
        if !out.headers.contains("User-Agent") {
            out.headers.add("User-Agent", ua);
        }
    }
    if let Some(referer) = req.referer.as_deref() {
        if !out.headers.contains("Referer") {
            out.headers.add("Referer", referer);
        }
    }
    // Default `Accept: */*` — curl always emits this unless the caller supplied
    // their own Accept header (← `lib/http.c:2911-2912`:
    // `if(!Curl_checkheaders(data, STRCONST("Accept"))) ... "Accept: */*\r\n"`).
    // Placed after User-Agent/Referer and before Accept-Encoding to match curl's
    // canonical request-header wire order.
    if !out.headers.contains("Accept") {
        out.headers.add("Accept", "*/*");
    }
    if let Some(enc) = req.accept_encoding.as_deref() {
        if !out.headers.contains("Accept-Encoding") {
            out.headers.add("Accept-Encoding", enc);
        }
    }
    // `Range:` header from `CURLOPT_RANGE` (`-r`) or the resume offset
    // (`CURLOPT_RESUME_FROM` / `-C`), added only when the caller supplied no
    // explicit `Range` header (← `lib/http.c`: `Curl_add_buffer` of
    // `data->state.range` under the `!Curl_checkheaders(data, "Range")` guard).
    // A `CURLOPT_RANGE` string is sent verbatim as `bytes=<range>`; a bare
    // resume offset becomes the open-ended `bytes=<n>-`. The two are mutually
    // exclusive at the CLI (`--continue-at` rejects `--range`), so `range`
    // takes precedence here without ambiguity.
    if !out.headers.contains("Range") {
        if let Some(r) = req.range.as_deref().filter(|s| !s.is_empty()) {
            out.headers.add("Range", format!("bytes={r}"));
        } else if req.resume_from > 0 {
            out.headers.add("Range", format!("bytes={}-", req.resume_from));
        }
    }

    // Basic auth when credentials are present and the caller did not already
    // supply an Authorization header (← the default `--user` path).
    if (req.user.is_some() || req.password.is_some()) && !out.headers.contains("Authorization") {
        let line =
            auth::basic::http_output_basic(req.user.as_deref(), req.password.as_deref(), false)?;
        // `http_output_basic` returns the full "Authorization: <value>\r\n"
        // wire line; add only the field value under the header name.
        if let Some(value) = line
            .strip_prefix("Authorization: ")
            .and_then(|v| v.strip_suffix("\r\n"))
        {
            out.headers.add("Authorization", value);
        }
    }

    // Library-supplied default `Content-Type:` for a body libcurl originated
    // (← `lib/http.c`: `application/x-www-form-urlencoded` for `HTTPREQ_POST`,
    // the `multipart/form-data; boundary=…` type for a form/mime post). Applied
    // only when the caller supplied no explicit `Content-Type` header, so a
    // user `-H 'Content-Type: …'` always wins — exactly curl's
    // `!Curl_checkheaders(data, "Content-Type")` rule. Keyed on the request
    // kind carried in [`post_content_type`](crate::protocols::TransferRequest),
    // not the HTTP method, so `curl -X DELETE -d …` still carries the type.
    if let Some(ct) = req.post_content_type.as_deref() {
        if !out.headers.contains("Content-Type") {
            out.headers.add("Content-Type", ct);
        }
    }

    Ok(out)
}

/// The in-memory request body bytes for this transfer, or `None` for a bodyless
/// request (← `data->set.postfields` / the upload source). A streaming upload
/// fed from a read callback is driven by the transfer driver and is not modeled
/// in [`TransferRequest`]; an upload with no in-memory payload therefore yields
/// `None` here.
fn request_body_bytes(req: &super::TransferRequest) -> Option<Vec<u8>> {
    req.body.clone()
}

/// The HTTP/1 [`RequestBody`] framing for `body`: a known-length body uses
/// `Content-Length` ([`RequestBody::Sized`]); an absent body is
/// [`RequestBody::Empty`].
fn request_body_for(body: Option<Vec<u8>>) -> RequestBody {
    match body {
        Some(b) if !b.is_empty() => RequestBody::Sized(b),
        _ => RequestBody::Empty,
    }
}

/// Select the wire HTTP version (`10`/`11`/`20`/`30`) for this transfer from the
/// connection's negotiated state and the per-transfer negotiation
/// (← `http_request_version` + `Curl_conn_http_version`).
///
/// HTTP/2 prior knowledge (`--http2-prior-knowledge`) forces `2` over cleartext;
/// otherwise the version an installed HTTP filter negotiated
/// ([`Connection::http_version`]) governs, falling back to the TLS ALPN result
/// and finally to the 1.1/1.0 choice in [`http_request_version`].
fn select_http_version(conn: &Connection, neg: &HttpNegotiation) -> u8 {
    if neg.h2_prior_knowledge {
        return 20;
    }
    let conn_ver = conn.http_version();
    let alpn_ver = conn
        .get_alpn_negotiated()
        .map(|s| alpn_to_http_version(AlpnProtocol::from_wire(s.as_bytes())))
        .unwrap_or(0);
    let effective = if conn_ver != 0 { conn_ver } else { alpn_ver };
    http_request_version(effective, neg, None)
}

/// Resolve the connection's peer address for the HTTP/3 (QUIC) engine
/// (← the resolved `conn->remote_addr`). The address the datagram transport
/// needs is a concrete [`SocketAddr`]; when the host is already an IP literal
/// (the common post-resolution case) it is parsed directly, otherwise a
/// `CURLE_COULDNT_RESOLVE_HOST` is surfaced — name resolution itself is owned
/// by the connection/DNS layer, not the protocol handler.
fn resolve_h3_addr(conn: &Connection) -> Result<SocketAddr> {
    let hostport = format!("{}:{}", conn.host.name, conn.remote_port);
    hostport.parse::<SocketAddr>().map_err(|_| {
        Error::with_context(
            CurlCode::CouldntResolveHost,
            format!("[HTTP/3] connection address is not a resolved IP literal: {hostport}"),
        )
    })
}

/// Record the response-head diagnostics into [`TransferCtx::info`] and the
/// running header-byte accounting into the transfer state, enforcing the
/// response-header size ceilings (← `Curl_bump_headersize` + the
/// `data->info.httpcode`/`contenttype` writes in `Curl_http`).
fn record_response(ctx: &mut TransferCtx, resp: HttpResp) -> Result<()> {
    // Response-header COUNT ceiling (← the header-store guard in
    // `Curl_http_header`, `lib/headers.c`:
    //   if(Curl_llist_count(&data->state.httphdrs) >= MAX_HTTP_RESP_HEADER_COUNT) {
    //       failf(data, "Too many response headers, %d is max", ...);
    //       return CURLE_TOO_LARGE;
    //   }
    // curl accepts up to MAX_HTTP_RESP_HEADER_COUNT (5000) stored header lines
    // and rejects the next one with CURLE_TOO_LARGE. `map_response` records one
    // `HeaderList` entry per received header line, so the stored count maps
    // directly onto `headers.count()`. This is version-agnostic on purpose:
    // curl's guard lives in the generic header handler and so governs HTTP/1,
    // HTTP/2, and HTTP/3 alike. The message text is byte-for-byte with curl's
    // `failf` so downstream stderr scrapers keep matching.
    if resp.headers.count() > MAX_HTTP_RESP_HEADER_COUNT {
        return Err(Error::with_context(
            CurlCode::TooLarge,
            format!("Too many response headers, {MAX_HTTP_RESP_HEADER_COUNT} is max"),
        ));
    }

    // Diagnostics observed by `curl_easy_getinfo` (CURLINFO_RESPONSE_CODE,
    // CURLINFO_CONTENT_TYPE) and the CLI write-out / xattr paths.
    ctx.info.httpcode = resp.status;
    if let Some(ct) = resp.headers.get("content-type") {
        ctx.info.set_content_type(ct);
    }

    // Capture the response reason phrase and header fields for the `-v`/`--trace`
    // `< ` (HEADER_IN) dump reconstructed by `Easy::perform_transfer`. This is a
    // handful of small strings and is only consulted by the trace path, so it is
    // negligible when tracing is off (and `resp` is still owned here — the header
    // store below moves it).
    ctx.info.resp_reason = resp.description.clone();
    ctx.info.resp_headers = resp
        .headers
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();

    // Header-size accounting + ceiling enforcement over the response head.
    let connect_only = ctx.request.connect_only;
    let st = http_state(ctx);
    for (name, value) in resp.headers.iter() {
        // Wire length of "Name: value\r\n".
        let delta = name.len() + 2 + value.len() + 2;
        bump_headersize(&mut st.hdr_size, delta, connect_only)?;
    }
    // The trailing empty line that terminates the header block.
    bump_headersize(&mut st.hdr_size, 2, connect_only)?;

    st.resp = Some(resp);
    Ok(())
}

/// Extract the field value of a `Content-Type:` response-header line
/// (case-insensitive), or `None` when `hd` is a different header
/// (← the `Curl_compareheader(headerline, STRCONST("Content-Type:"), ...)`
/// path in curl's header handler). Trailing CRLF and surrounding whitespace are
/// trimmed, matching curl storing the trimmed value in `data->info.contenttype`.
fn parse_content_type_header(hd: &[u8]) -> Option<String> {
    let line = std::str::from_utf8(hd).ok()?;
    let (name, value) = line.split_once(':')?;
    if !name.trim().eq_ignore_ascii_case("content-type") {
        return None;
    }
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

impl Protocol for HttpHandler {
    /// Initialise per-transfer HTTP state before the transfer runs
    /// (← `Curl_http_setup_conn`): install a fresh [`HttpTransferState`] and seed
    /// its [`HttpNegotiation`] from the default "auto" version preference
    /// ([`HttpWant::None`], allowing 1.1/2/3). A transfer that wants a specific
    /// version overrides the negotiation before the DO phase, exactly as curl
    /// derives `data->state.http_neg` from `data->set.httpwant`.
    fn setup_connection<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            let st = http_state(ctx);
            st.neg.http_neg_init(HttpWant::None, false);
            Ok(())
        })
    }

    /// The DO phase (← `Curl_http`): assemble the request head from the transfer
    /// options, select the wire version from the connection's negotiated
    /// state/ALPN ([`select_http_version`]), and drive the exchange over the
    /// connection's primary filter chain — delegating the framing to
    /// [`h1::perform`], [`h2::perform`], or [`h3::perform`] — while streaming the
    /// response body to [`TransferCtx::sink`]. The response head and diagnostics
    /// (status code, content type) are recorded via [`record_response`]. Returns
    /// `true` since HTTP has no split DO/DO_MORE phase.
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            // Copy out the version-negotiation inputs (all `Copy`) so the read of
            // the transfer state ends before the connection/sink are borrowed.
            let neg = http_state(ctx).neg;

            // Build the request and body from the (immutable) request options;
            // owning them ends that borrow before the mutable `conn`/`sink`
            // borrows below. `req` is mutable so the version-dependent
            // `Expect: 100-continue` decision (below) can amend the headers.
            let mut req = build_http_request(&ctx.request)?;
            let body = request_body_bytes(&ctx.request);

            // Version is chosen from the connection's negotiated state.
            let version = {
                let conn = ctx.conn.as_deref().ok_or_else(|| {
                    Error::with_context(
                        CurlCode::BadFunctionArgument,
                        "[HTTP] no connection assigned to transfer",
                    )
                })?;
                select_http_version(conn, &neg)
            };

            // `Expect: 100-continue` announcement (← `addexpect` in `Curl_http`).
            // Once the wire version is known, decide whether to announce the
            // expectation. curl only adds it for HTTP/1.1 uploads whose body is
            // of unknown length or larger than `EXPECT_100_THRESHOLD`, and never
            // when the caller already supplied an `Expect` header (of any value).
            // `data->state.disableexpect` is a runtime flag curl raises only
            // after a 417 retry, so on this first-attempt path it is `false`.
            // A pre-existing `Expect` header suppresses the auto-add exactly as
            // curl's `Curl_checkheaders(data, "Expect")` guard does.
            if version == 11 && req.headers.get("Expect").is_none() {
                // Mirror `Curl_creader_client_length`: a materialised body has a
                // known length; an upload with no materialised body is of unknown
                // length (-1); anything else contributes no body (0).
                let client_len = match &body {
                    Some(b) => b.len() as i64,
                    None if ctx.request.upload => -1,
                    None => 0,
                };
                let mut announce = String::new();
                let announced = addexpect(
                    ExpectInput {
                        upgrade_pending: false,
                        custom_headers: &[],
                        disableexpect: false,
                        httpversion: 11,
                        client_len,
                    },
                    &mut announce,
                )?;
                if announced {
                    // `build_request` forwards `req.headers` to hyper verbatim, so
                    // adding the field here places `Expect: 100-continue` on the
                    // wire (matching curl's request head).
                    req.headers.add("Expect", "100-continue");
                }
            }

            // Drive the exchange. `conn` and `sink` are disjoint fields of `ctx`,
            // so both can be borrowed mutably at once (the disjoint-field-borrow
            // pattern documented on `TransferCtx`).
            // `CURLOPT_FAILONERROR` (`-f`): captured (a `Copy` bool) before the
            // `conn`/`sink` borrows so the per-version engines can suppress the
            // body of an HTTP error response (>= 400) at the source.
            let fail_on_error = ctx.request.fail_on_error;
            let resp = {
                let conn = ctx.conn.as_deref_mut().ok_or_else(|| {
                    Error::with_context(
                        CurlCode::BadFunctionArgument,
                        "[HTTP] no connection assigned to transfer",
                    )
                })?;
                let mut sink = ctx.sink.as_deref_mut();
                let mut write_body = |data: &[u8]| -> Result<()> {
                    match sink.as_mut() {
                        // The response body is delivered to the client sink.
                        Some(s) => s.write(data),
                        // No sink installed => the body is discarded (curl's
                        // write to a NULL/`/dev/null` target).
                        None => Ok(()),
                    }
                };

                match version {
                    30 => {
                        let addr = resolve_h3_addr(conn)?;
                        let b = body.map(Bytes::from);
                        h3::perform(conn, addr, req, b, fail_on_error, &mut write_body).await?
                    }
                    20 => h2::perform(conn, req, body, fail_on_error, &mut write_body).await?,
                    10 => {
                        h1::perform(
                            conn,
                            req,
                            0,
                            request_body_for(body),
                            fail_on_error,
                            &mut write_body,
                        )
                        .await?
                    }
                    _ => {
                        h1::perform(
                            conn,
                            req,
                            1,
                            request_body_for(body),
                            fail_on_error,
                            &mut write_body,
                        )
                        .await?
                    }
                }
            };

            // Record status/content-type diagnostics and the response-header
            // accounting into the context (disjoint `info`/`proto_state` borrows).
            record_response(ctx, resp)?;

            Ok(true)
        })
    }

    /// The DONE phase (← `Curl_http_done`): release the per-request HTTP state
    /// and keep the connection for reuse, closing it instead when the transfer
    /// ended prematurely or failed (its wire state is then unknown and unsafe to
    /// reuse, matching curl's `premature` handling).
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            if premature || status.is_err() {
                if let Some(conn) = ctx.conn.as_deref_mut() {
                    conn.close(FIRSTSOCKET);
                }
            }
            // The connection (when reusable) is retained; only the per-request
            // HTTP scratch state is dropped.
            ctx.proto_state = None;
            Ok(())
        })
    }

    /// Post-process a chunk of response body on its way to the client
    /// (← `Curl_http_write_resp`): forward the bytes to [`TransferCtx::sink`].
    /// This is the byte-streaming hook a chunk-driven driver calls; the DO phase
    /// streams the body directly, so both paths converge on the same sink.
    fn write_resp<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        buf: &'a [u8],
        is_eos: bool,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            if !buf.is_empty() {
                if let Some(sink) = ctx.sink.as_deref_mut() {
                    sink.write(buf)?;
                }
            }
            // End-of-stream needs no HTTP-specific finalisation: the client sink
            // is flushed by its owner, exactly as curl's body write path does.
            let _ = is_eos;
            Ok(())
        })
    }

    /// Post-process a single response header line (← `Curl_http_write_resp_hd`):
    /// enforce the [`bump_headersize`] size ceilings on the accumulated header
    /// bytes and capture the `Content-Type` value into [`TransferCtx::info`] so
    /// `curl_easy_getinfo(CURLINFO_CONTENT_TYPE)` and the CLI write-out/xattr
    /// paths observe it.
    fn write_resp_hd<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        hd: &'a [u8],
        is_eos: bool,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            let connect_only = ctx.request.connect_only;
            {
                let st = http_state(ctx);
                bump_headersize(&mut st.hdr_size, hd.len(), connect_only)?;
            }
            if let Some(ct) = parse_content_type_header(hd) {
                ctx.info.set_content_type(&ct);
            }
            let _ = is_eos;
            Ok(())
        })
    }

    /// Decide whether a redirect/retry to `newurl` is followed
    /// (← `Curl_http_follow`), delegating to the shared, fully-tested
    /// [`http_follow`]: it advances the follow count, applies the auto-`Referer`
    /// and 301/302/303 method switch, and strips credentials on a cross-origin
    /// redirect. The per-transfer redirect *limit* is owned by the driver's
    /// configuration; until it supplies one the handler applies unlimited-depth
    /// follows (`maxredirs = -1`), so the redirect resolution itself is
    /// exercised end-to-end rather than short-circuited.
    fn follow<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        newurl: &'a str,
        kind: FollowType,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            // A non-follow is a no-op by definition (and would trip
            // `http_follow`'s debug assertion), so return early.
            if kind == FollowType::None {
                return Ok(());
            }
            let req_url = ctx.request.url.clone();
            let last_code = ctx.info.httpcode;
            let cfg = FollowConfig {
                maxredirs: -1,
                ..FollowConfig::default()
            };
            let st = http_state(ctx);
            if st.follow.url.is_empty() {
                st.follow.url = req_url;
            }
            st.follow.httpcode = last_code;
            http_follow(&cfg, &mut st.follow, newurl, kind)
        })
    }

    /// Contribute sockets to watch during the DOING phase
    /// (← `Curl_http_doing_pollset`): register read interest on the transfer's
    /// socket so the event loop wakes the transfer when response bytes arrive.
    fn doing_pollset(&self, ctx: &mut TransferCtx, ps: &mut Pollset) {
        if let Some(fd) = ctx.socket_fd {
            ps.add_in(fd);
        }
    }

    /// Contribute sockets to watch during the PERFORM phase
    /// (← `Curl_http_perform_pollset`): register read interest for the response,
    /// and write interest as well while an upload body is still being sent.
    fn perform_pollset(&self, ctx: &mut TransferCtx, ps: &mut Pollset) {
        if let Some(fd) = ctx.socket_fd {
            ps.add_in(fd);
            if ctx.request.upload {
                ps.add_out(fd);
            }
        }
    }
}

// ===========================================================================
// PHASE 4 — Expect: 100-continue (← `addexpect` and the `cr_exp100` reader).
// ===========================================================================

/// The `Expect: 100-continue` upload state (← `enum expect100`,
/// `lib/request.h`).
///
/// The discriminants preserve curl's enum order: [`SendData`](Exp100::SendData)
/// is `0` and every other state is greater, which is exactly the
/// `state > EXP100_SEND_DATA` test curl uses to mean "still holding the body
/// back".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Exp100 {
    /// Enough waiting — send the body now (← `EXP100_SEND_DATA`).
    #[default]
    SendData = 0,
    /// Waiting for the `100 Continue` interim response (←
    /// `EXP100_AWAITING_CONTINUE`).
    AwaitingContinue = 1,
    /// Still sending the request; will wait for `100` once it is fully sent
    /// (← `EXP100_SENDING_REQUEST`).
    SendingRequest = 2,
    /// The expectation failed, e.g. `417 Expectation Failed`
    /// (← `EXP100_FAILED`).
    Failed = 3,
}

/// The action the [`Exp100Reader`] read gate dictates for the body reader
/// (← the `switch(ctx->state)` outcomes of `cr_exp100_read`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exp100Action {
    /// Produce no body bytes yet (`*nread = 0`) — keep waiting.
    Wait,
    /// The expectation failed; fail the read with [`CurlCode::ReadError`]
    /// (← `CURLE_READ_ERROR`).
    Fail,
    /// Pass the read through to the underlying body reader.
    PassThrough,
}

/// The `Expect: 100-continue` client body-reader (← `struct cr_exp100_ctx` and
/// the `cr_exp100` reader), which holds the request body back until the server
/// sends `100 Continue` or a timeout elapses.
///
/// This is the memory-safe rewrite of curl's protocol client reader: it owns
/// the [`Exp100`] state and the wait deadline, and its methods reproduce the
/// C reader's transitions exactly. Time is injected as monotonic milliseconds
/// so the gate is deterministic and testable without a real clock.
#[derive(Clone, Copy, Debug)]
pub struct Exp100Reader {
    state: Exp100,
    /// The `CURLOPT_EXPECT_100_TIMEOUT_MS` value (← `expect_100_timeout`).
    timeout_ms: u64,
    /// Monotonic ms timestamp when the wait began (← `ctx->start`).
    start_ms: Option<u64>,
}

impl Exp100Reader {
    /// Create the reader in the [`SendingRequest`](Exp100::SendingRequest)
    /// state with the given `CURLOPT_EXPECT_100_TIMEOUT_MS`
    /// (← `http_exp100_add_reader`).
    #[must_use]
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            state: Exp100::SendingRequest,
            timeout_ms,
            start_ms: None,
        }
    }

    /// The current [`Exp100`] state.
    #[must_use]
    pub fn state(&self) -> Exp100 {
        self.state
    }

    /// Stop waiting and release the body (← `http_exp100_continue`): if the
    /// reader is past [`SendData`](Exp100::SendData), reset it to `SendData`.
    fn continue_now(&mut self) {
        if self.state > Exp100::SendData {
            self.state = Exp100::SendData;
        }
    }

    /// Note that a `100 Continue` was received (← `http_exp100_got100`), which
    /// releases the held body.
    pub fn got100(&mut self) {
        self.continue_now();
    }

    /// Whether the reader is holding the body awaiting `100`
    /// (← `http_exp100_is_waiting`): state is
    /// [`AwaitingContinue`](Exp100::AwaitingContinue).
    #[must_use]
    pub fn is_waiting(&self) -> bool {
        self.state == Exp100::AwaitingContinue
    }

    /// Give up waiting and send the body anyway (← `http_exp100_send_anyway`).
    pub fn send_anyway(&mut self) {
        self.continue_now();
    }

    /// Finalise the reader when the request completes
    /// (← `cr_exp100_done`): a premature completion marks the expectation
    /// [`Failed`](Exp100::Failed); a clean one allows the body to flow.
    pub fn done(&mut self, premature: bool) {
        self.state = if premature {
            Exp100::Failed
        } else {
            Exp100::SendData
        };
    }

    /// The read gate (← `cr_exp100_read`): decide what the body reader should do
    /// now, given whether the request head is fully sent and the current
    /// monotonic time in milliseconds.
    ///
    /// Mirrors the C state machine: it does not start the wait timer until the
    /// request is fully sent, fails fast when the expectation failed, waits
    /// until the timeout expires, and then falls through to pass the body
    /// through (curl logs `Done waiting for 100-continue` at that point).
    pub fn poll(&mut self, request_fully_sent: bool, now_ms: u64) -> Exp100Action {
        match self.state {
            Exp100::SendingRequest => {
                if !request_fully_sent {
                    // Do not start the timer until the request is fully sent.
                    return Exp100Action::Wait;
                }
                self.state = Exp100::AwaitingContinue;
                self.start_ms = Some(now_ms);
                Exp100Action::Wait
            }
            Exp100::Failed => Exp100Action::Fail,
            Exp100::AwaitingContinue => {
                let elapsed = now_ms.saturating_sub(self.start_ms.unwrap_or(now_ms));
                if elapsed < self.timeout_ms {
                    Exp100Action::Wait
                } else {
                    // Waited long enough — continue anyway.
                    self.continue_now();
                    tracing::info!("Done waiting for 100-continue");
                    Exp100Action::PassThrough
                }
            }
            Exp100::SendData => Exp100Action::PassThrough,
        }
    }
}

/// The transfer inputs [`addexpect`] needs (← the `Curl_easy` fields `addexpect`
/// reads).
#[derive(Clone, Copy, Debug)]
pub struct ExpectInput<'a> {
    /// Whether an `Upgrade:` (HTTP/1.1 upgrade, e.g. to h2c) is pending, in
    /// which case `Expect` is skipped (← `data->req.upgr101 != UPGR101_NONE`).
    pub upgrade_pending: bool,
    /// The normal custom-header list, so a user `Expect` header is honoured
    /// (← `Curl_checkheaders(data, "Expect")`).
    pub custom_headers: &'a [String],
    /// Whether `Expect: 100-continue` is disabled for this transfer
    /// (← `data->state.disableexpect`).
    pub disableexpect: bool,
    /// The negotiated HTTP version number (`10`/`11`/`20`/…); `Expect` is only
    /// added for `11` (← the `httpversion == 11` check).
    pub httpversion: i32,
    /// The client-provided upload length, or a negative value when unknown
    /// (← `Curl_creader_client_length`).
    pub client_len: i64,
}

/// Add `Expect: 100-continue` to the HTTP/1.x request `out` when appropriate,
/// returning whether the expectation was announced (← `addexpect`).
///
/// The expectation is skipped entirely when an `Upgrade:` is pending. A
/// user-supplied `Expect` header is never overridden — instead its value is
/// inspected so the caller learns whether `100-continue` was announced. Absent
/// a user header, `Expect: 100-continue` is added only for HTTP/1.1, only when
/// not disabled, and only when the upload length is unknown or exceeds
/// [`EXPECT_100_THRESHOLD`] — matching curl's "skip it for small PUT/POST"
/// behaviour.
///
/// # Errors
///
/// Returns [`Error::OutOfMemory`] only if writing to `out` fails.
pub fn addexpect(input: ExpectInput<'_>, out: &mut String) -> Result<bool> {
    // Avoid Expect: 100-continue if an Upgrade: is in progress.
    if input.upgrade_pending {
        return Ok(false);
    }

    if let Some(line) = find_header(input.custom_headers, "Expect") {
        // A custom Expect header will be sent as-is; report whether it announces
        // 100-continue so the reader machinery can be armed accordingly.
        return Ok(compare_header(line, "Expect:", "100-continue"));
    }

    if !input.disableexpect && input.httpversion == 11 {
        // Unknown length (< 0) always warrants it; otherwise only above the
        // threshold, so small uploads pay no round-trip.
        if input.client_len < 0 || input.client_len > EXPECT_100_THRESHOLD as i64 {
            out.push_str("Expect: 100-continue\r\n");
            return Ok(true);
        }
    }

    Ok(false)
}

// ===========================================================================
// PHASE 5 — Redirect / follow (← `Curl_http_follow`, `http_switch_to_get`).
// ===========================================================================

/// `CURLFOLLOW_ALL` — follow redirects generically.
pub const CURLFOLLOW_ALL: u32 = 1;
/// `CURLFOLLOW_OBEYCODE` — switch method to GET only when the status code
/// mandates it.
pub const CURLFOLLOW_OBEYCODE: u32 = 2;
/// `CURLFOLLOW_FIRSTONLY` — follow only the first redirect.
pub const CURLFOLLOW_FIRSTONLY: u32 = 3;

/// The redirect options this transfer was configured with (← the `data->set`
/// fields `Curl_http_follow` reads).
///
/// [`Default`] yields an all-zero/false configuration (no redirects permitted,
/// no auto-`Referer`); real transfers populate every field from `CURLOPT_*`.
#[derive(Clone, Debug, Default)]
pub struct FollowConfig {
    /// The redirect limit; `-1` means unlimited (← `set.maxredirs`).
    pub maxredirs: i32,
    /// Whether to set the previous URL as the `Referer` automatically
    /// (← `set.http_auto_referer`).
    pub auto_referer: bool,
    /// Whether auth may be re-sent to a different host/port/scheme
    /// (← `set.allow_auth_to_other_hosts`, `CURLOPT_UNRESTRICTED_AUTH`).
    pub allow_auth_to_other_hosts: bool,
    /// The follow mode (a `CURLFOLLOW_*` value) governing method rewriting
    /// (← `set.http_follow_mode`).
    pub follow_mode: u32,
    /// Keep the method on `301` instead of switching to GET (← `set.post301`,
    /// `CURLOPT_POSTREDIR`).
    pub post301: bool,
    /// Keep the method on `302` (← `set.post302`).
    pub post302: bool,
    /// Keep the method on `303` (← `set.post303`).
    pub post303: bool,
    /// Whether the path is used as-is when resolving the target
    /// (← `set.path_as_is`).
    pub path_as_is: bool,
    /// The `CURLOPT_CUSTOMREQUEST` override, if any (← `set.str[CUSTOMREQUEST]`).
    pub custom_request: Option<String>,
}

/// The mutable per-transfer redirect state (← the `data->state`/`data->info`
/// fields `Curl_http_follow` reads and updates).
#[derive(Clone, Debug, Default)]
pub struct FollowState {
    /// Count of all real follows so far (← `state.requests`).
    pub requests: u32,
    /// Count of redirect-followings incl. auth reloads (← `state.followlocation`).
    pub followlocation: i32,
    /// The current request kind, rewritten by [`http_switch_to_get`]
    /// (← `state.httpreq`).
    pub httpreq: HttpReq,
    /// Whether the custom request method is being ignored (← `state.http_ignorecustom`).
    pub http_ignorecustom: bool,
    /// Whether a custom port is still permitted on the target (← `state.allow_port`).
    pub allow_port: bool,
    /// The computed `Referer` for the next request, if any (← `state.referer`).
    pub referer: Option<String>,
    /// The current, absolute request URL (← `state.url`); updated to the
    /// resolved redirect target.
    pub url: String,
    /// The would-be redirect target recorded in FAKE mode (← `info.wouldredirect`).
    pub wouldredirect: Option<String>,
    /// The host of the very first request (← `state.first_host`).
    pub first_host: String,
    /// The port of the first request (← `state.first_remote_port`).
    pub first_remote_port: u16,
    /// The protocol id of the first request (← `state.first_remote_protocol`).
    pub first_remote_protocol: u32,
    /// The HTTP status code that triggered this follow (← `req.httpcode` /
    /// `info.httpcode`).
    pub httpcode: i32,
    /// Set to `true` when this follow required clearing stored credentials, so
    /// the caller drops `aptr.user`/`aptr.passwd` (← the `Curl_safefree` calls).
    pub cleared_auth: bool,
}

/// Map a URL scheme to its `CURLPROTO_*` bit, for cross-scheme auth comparison.
fn scheme_protocol(scheme: &str) -> u32 {
    if scheme.eq_ignore_ascii_case("https") {
        CURLPROTO_HTTPS
    } else if scheme.eq_ignore_ascii_case("http") {
        CURLPROTO_HTTP
    } else {
        0
    }
}

/// Rewrite the request method to GET after a redirect status that calls for it
/// (← `http_switch_to_get`), preserving curl's exact diagnostic text.
///
/// When the follow mode is [`CURLFOLLOW_OBEYCODE`] and a body-bearing method or
/// a custom request is in effect, the method is switched and any custom request
/// is ignored (`Switch to GET because of <code> response`). Otherwise, when a
/// custom request is set and the mode is not [`CURLFOLLOW_FIRSTONLY`], the
/// custom method is kept (`Stick to <method> instead of GET`). Either way the
/// effective kind becomes GET.
fn http_switch_to_get(cfg: &FollowConfig, st: &mut FollowState, code: i32) {
    let req = cfg.custom_request.as_deref();
    if (req.is_some() || st.httpreq != HttpReq::Get) && cfg.follow_mode == CURLFOLLOW_OBEYCODE {
        tracing::info!("Switch to GET because of {} response", code);
        st.http_ignorecustom = true;
    } else if let Some(r) = req {
        if cfg.follow_mode != CURLFOLLOW_FIRSTONLY {
            tracing::info!("Stick to {} instead of GET", r);
        }
    }
    st.httpreq = HttpReq::Get;
    // The upload rewind reset (`Curl_creader_set_rewind(data, FALSE)`) is
    // performed by the transfer core that owns the client reader.
}

/// Whether the HTTP status is a POST-family method (used by the 301/302/303
/// method-switch checks).
#[inline]
fn is_post_like(req: HttpReq) -> bool {
    matches!(req, HttpReq::Post | HttpReq::PostForm | HttpReq::PostMime)
}

/// Handle a redirect or retry to `newurl` of the given [`FollowType`]
/// (← `Curl_http_follow`).
///
/// This reproduces curl's redirect control flow: it counts real follows,
/// enforces [`FollowConfig::maxredirs`] (downgrading to a FAKE follow that only
/// records the would-be target), maintains the auto-`Referer`, resolves the
/// target against the current URL, strips stored credentials on a cross-origin
/// redirect via the canonical [`crate::auth::allowed_to_host`] gate, and applies
/// the 301/302/303 method switch through [`http_switch_to_get`]. All `infof`
/// diagnostics are preserved verbatim for `--trace` parity.
///
/// The URL resolution uses the `url` crate here; the exact `CURLU_*` flag
/// semantics (URL-encoding, space tolerance, path-as-is) are owned by the
/// workspace URL layer and honoured there.
///
/// # Errors
///
/// * [`Error::TooManyRedirects`] (`CURLE_TOO_MANY_REDIRECTS`, 47) once the
///   redirect limit is reached.
/// * [`Error::url`] / [`Error::OutOfMemory`] when the target cannot be resolved
///   in a non-FAKE follow.
pub fn http_follow(
    cfg: &FollowConfig,
    st: &mut FollowState,
    newurl: &str,
    ftype: FollowType,
) -> Result<()> {
    debug_assert!(ftype != FollowType::None);

    let mut ftype = ftype;
    let mut reached_max = false;

    if ftype != FollowType::Fake {
        st.requests += 1; // count all real follows
    }

    if ftype == FollowType::Redir {
        if cfg.maxredirs != -1 && st.followlocation >= cfg.maxredirs {
            reached_max = true;
            // Switch to FAKE to store the would-be-redirected-to URL.
            ftype = FollowType::Fake;
        } else {
            st.followlocation += 1; // count redirect-followings incl. auth reloads
            if cfg.auto_referer {
                // Previous URL, stripped of credentials and fragment.
                if let Ok(mut u) = Url::parse(&st.url) {
                    u.set_fragment(None);
                    let _ = u.set_username("");
                    let _ = u.set_password(None);
                    st.referer = Some(u.into());
                }
            }
        }
    }

    // A non-401/407 redirect to an absolute URL forbids a custom port.
    let is_absolute = Url::parse(newurl).is_ok();
    let disallowport =
        ftype != FollowType::Retry && st.httpcode != 401 && st.httpcode != 407 && is_absolute;

    // Resolve the target against the current URL.
    let resolved: Option<Url> = match Url::parse(&st.url) {
        Ok(base) => base.join(newurl).ok(),
        Err(_) => Url::parse(newurl).ok(),
    };

    let follow_url: String = match &resolved {
        Some(u) => u.to_string(),
        None => {
            // Parse failure: only tolerated in FAKE mode (store as-is).
            if ftype != FollowType::Fake {
                return Err(Error::url("The redirect target URL could not be parsed"));
            }
            newurl.to_owned()
        }
    };

    // Clear stored auth when redirecting cross-origin, unless permitted. Uses
    // the canonical cross-host gate so behaviour matches the auth layer.
    if let Some(u) = &resolved {
        if !cfg.allow_auth_to_other_hosts && ftype != FollowType::Fake {
            let new_host = u.host_str().unwrap_or("");
            let new_port = u.port_or_known_default().unwrap_or(0);
            let new_proto = scheme_protocol(u.scheme());
            let ctx = auth::AllowedToHostCtx {
                this_is_a_follow: true,
                allow_auth_to_other_hosts: false,
                first_host: Some(&st.first_host),
                conn_host_name: new_host,
                first_remote_port: st.first_remote_port,
                conn_remote_port: new_port,
                first_remote_protocol: st.first_remote_protocol,
                conn_scheme_protocol: new_proto,
            };
            if !auth::allowed_to_host(&ctx) {
                if new_port != st.first_remote_port {
                    tracing::info!(
                        "Clear auth, redirects to port from {} to {}",
                        st.first_remote_port,
                        new_port
                    );
                } else {
                    tracing::info!(
                        "Clear auth, redirects scheme from {} to {}",
                        if st.first_remote_protocol == CURLPROTO_HTTPS {
                            "https"
                        } else {
                            "http"
                        },
                        u.scheme()
                    );
                }
                st.cleared_auth = true;
            }
        }
    }

    if ftype == FollowType::Fake {
        // We were only computing the URL we would have followed.
        st.wouldredirect = Some(follow_url);
        if reached_max {
            tracing::error!("Maximum ({}) redirects followed", cfg.maxredirs);
            return Err(Error::TooManyRedirects);
        }
        return Ok(());
    }

    if disallowport {
        st.allow_port = false;
    }

    st.url = follow_url.clone();
    tracing::info!("Issue another request to this URL: '{}'", follow_url);

    if cfg.follow_mode == CURLFOLLOW_FIRSTONLY
        && cfg.custom_request.is_some()
        && !st.http_ignorecustom
    {
        st.http_ignorecustom = true;
        tracing::info!("Drop custom request method for next request");
    }

    // Method rewrite based on the exact status code (301/302/303).
    match st.httpcode {
        301 => {
            if is_post_like(st.httpreq) && !cfg.post301 {
                http_switch_to_get(cfg, st, 301);
            }
        }
        302 => {
            if is_post_like(st.httpreq) && !cfg.post302 {
                http_switch_to_get(cfg, st, 302);
            }
        }
        // 'See Other': switch to GET/HEAD unless POST is explicitly kept.
        303 if st.httpreq != HttpReq::Get && (!is_post_like(st.httpreq) || !cfg.post303) => {
            http_switch_to_get(cfg, st, 303);
        }
        // 300/304/305/306/307 and unknowns: no method change.
        _ => {}
    }

    Ok(())
}

// ===========================================================================
// PHASE 6 — HTTP authentication glue (← the auth orchestration in `lib/http.c`,
// dispatching into `crate::auth`).
// ===========================================================================

/// Whether `line` begins with the auth scheme keyword `auth`, with no
/// alphanumeric character immediately following (← `authcmp`).
///
/// The trailing-alnum check stops `Negotiate` from matching a hypothetical
/// `Negotiatex` and distinguishes `NTLM` from a longer token.
#[must_use]
fn authcmp(auth: &str, line: &str) -> bool {
    let n = auth.len();
    if line.len() < n || !line.as_bytes()[..n].eq_ignore_ascii_case(auth.as_bytes()) {
        return false;
    }
    match line.as_bytes().get(n) {
        Some(c) => !c.is_ascii_alphanumeric(),
        None => true, // end of string counts as a non-alnum terminator
    }
}

/// Parse a `WWW-Authenticate`/`Proxy-Authenticate` header value, OR-ing every
/// offered scheme into `avail` and returning the bitmask of schemes present
/// (← the scheme-detection half of `Curl_http_input_auth`).
///
/// The line may list several schemes separated by commas; each is matched with
/// [`authcmp`]. This performs the availability bookkeeping only; running a
/// picked mechanism's challenge parser (`input_negotiate` / `decode_type2` /
/// `input_digest`) is the transfer core's job, since those require the
/// connection-scoped mechanism state (`NegotiateData`/`NtlmData`/`DigestData`)
/// this module does not own. The returned bitmask tells the caller which
/// mechanisms to dispatch.
///
/// The [`CURLAUTH_*`](crate::auth) bits used are those of [`crate::auth`].
pub fn http_input_auth(auth: &str, avail: &mut u32) -> u32 {
    let mut detected = 0u32;
    let mut s = auth;
    loop {
        s = s.trim_start_matches([' ', '\t']);
        if s.is_empty() {
            break;
        }
        if authcmp("Negotiate", s) {
            detected |= auth::CURLAUTH_NEGOTIATE;
        } else if authcmp("NTLM", s) {
            detected |= auth::CURLAUTH_NTLM;
        } else if authcmp("Digest", s) {
            detected |= auth::CURLAUTH_DIGEST;
        } else if authcmp("Basic", s) {
            detected |= auth::CURLAUTH_BASIC;
        } else if authcmp("Bearer", s) {
            detected |= auth::CURLAUTH_BEARER;
        }
        // Multiple methods may be listed; advance past the next comma.
        match s.find(',') {
            Some(i) => s = &s[i + 1..],
            None => break,
        }
    }
    *avail |= detected;
    detected
}

/// Select the single most-preferred auth method from those wanted, available,
/// and permitted by `mask` (← `pickoneauth`).
///
/// Delegates the preference order to [`crate::auth::pick_strongest`]
/// (Negotiate > Bearer > Digest > NTLM > Basic > AWS-SigV4). Returns the picked
/// [`CURLAUTH_*`](crate::auth) bit and `true`, or [`CURLAUTH_PICKNONE`] and
/// `false` when nothing qualifies — matching curl's `pick->picked` sentinel.
#[must_use]
pub fn pick_one_auth(want: u32, avail: u32, mask: u32) -> (u32, bool) {
    let picked = auth::pick_strongest(want, avail & mask);
    if picked == auth::CURLAUTH_NONE {
        (CURLAUTH_PICKNONE, false)
    } else {
        (picked, true)
    }
}

/// The inputs [`http_should_fail`] needs (← the `Curl_easy` fields it reads).
#[derive(Clone, Copy, Debug)]
pub struct ShouldFailInput {
    /// Whether `CURLOPT_FAILONERROR` is set (← `set.http_fail_on_error`).
    pub fail_on_error: bool,
    /// The HTTP status code under consideration (← `data->req.httpcode`).
    pub httpcode: i32,
    /// Whether a resume offset is in effect (← `state.resume_from != 0`).
    pub resume_from: bool,
    /// The request kind (← `state.httpreq`).
    pub httpreq: HttpReq,
    /// Whether host credentials are available (← `state.aptr.user`).
    pub have_user: bool,
    /// Whether proxy credentials are available (← `conn->bits.proxy_user_passwd`).
    pub have_proxy_creds: bool,
    /// Whether an authentication problem has been flagged (← `state.authproblem`).
    pub authproblem: bool,
}

/// Whether an HTTP response code should fail the transfer (← `http_should_fail`).
///
/// Returns `false` unless `CURLOPT_FAILONERROR` is set. A code below 400 never
/// fails; a `416` answer to a resumed GET is treated as success; any other code
/// at or above 400 that is neither `401` nor `407` always fails. For `401`/`407`
/// the decision depends on whether credentials exist and whether an auth
/// problem was recorded — exactly as curl.
#[must_use]
pub fn http_should_fail(input: &ShouldFailInput) -> bool {
    if !input.fail_on_error {
        return false;
    }
    if input.httpcode < 400 {
        return false;
    }
    // A 416 to a resume request means the file is already complete.
    if input.resume_from && input.httpreq == HttpReq::Get && input.httpcode == 416 {
        return false;
    }
    // Anything >= 400 that is not an auth challenge is terminal.
    if input.httpcode != 401 && input.httpcode != 407 {
        return true;
    }
    // 401/407: terminal when we have no matching credentials to try.
    if input.httpcode == 401 && !input.have_user {
        return true;
    }
    if input.httpcode == 407 && !input.have_proxy_creds {
        return true;
    }
    input.authproblem
}

/// The authentication mechanism selected for emission on a request
/// (← the `auth` name variable threaded through `output_auth_headers`).
///
/// [`Basic`](PickedAuth::Basic) and [`Bearer`](PickedAuth::Bearer) headers are
/// emitted directly by this module. The remaining variants are *delegation
/// descriptors*: they name the mechanism the transfer core must run against its
/// connection-scoped state (the challenge/response crypto for AWS-SigV4,
/// Negotiate, NTLM, and Digest lives behind those mechanism modules and needs
/// the per-connection handshake state this module does not carry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PickedAuth {
    /// No header emitted (nothing picked, or a guard suppressed emission).
    None,
    /// AWS SigV4 request signing (host only) — delegate to
    /// [`crate::protocols::http::aws_sigv4`].
    AwsSigV4,
    /// SPNEGO/Negotiate — delegate to [`crate::auth::negotiate`].
    Negotiate,
    /// NTLM type-1/type-3 — delegate to [`crate::auth::ntlm`].
    Ntlm,
    /// HTTP Digest — delegate to [`crate::auth::digest`].
    Digest,
    /// HTTP Basic — emitted here via [`crate::auth::basic::http_output_basic`].
    Basic,
    /// OAuth 2.0 Bearer — emitted here directly.
    Bearer,
}

impl PickedAuth {
    /// The human-readable scheme name curl prints in its
    /// `"%s auth using %s with user '%s'"` diagnostic (← the `auth` string).
    #[must_use]
    fn name(self) -> Option<&'static str> {
        match self {
            PickedAuth::None => None,
            PickedAuth::AwsSigV4 => Some("AWS_SIGV4"),
            PickedAuth::Negotiate => Some("Negotiate"),
            PickedAuth::Ntlm => Some("NTLM"),
            PickedAuth::Digest => Some("Digest"),
            PickedAuth::Basic => Some("Basic"),
            PickedAuth::Bearer => Some("Bearer"),
        }
    }
}

/// Per-side (host or proxy) authentication progress (← `struct auth`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthState {
    /// The methods the user wants to use (← `authstatus->want`).
    pub want: u32,
    /// The methods the peer offered (← `authstatus->avail`).
    pub avail: u32,
    /// The single method chosen for this request (← `authstatus->picked`).
    pub picked: u32,
    /// Whether the handshake for the picked method has finished
    /// (← `authstatus->done`).
    pub done: bool,
    /// Whether another request round is required (← `authstatus->multipass`).
    pub multipass: bool,
}

/// Everything [`output_auth_headers`] and [`http_output_auth`] read to build the
/// `Authorization`/`Proxy-Authorization` headers (← the `Curl_easy`/connection
/// fields those functions touch), kept deliberately thin.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthOutputCtx<'a> {
    /// The request method token, e.g. `"GET"` (← `request`).
    pub request: &'a str,
    /// The request-target path (← `path`).
    pub path: &'a str,
    /// Host username, if any (← `conn->user` / `data->state.aptr.user`).
    pub user: Option<&'a str>,
    /// Host password, if any (← `conn->passwd`).
    pub passwd: Option<&'a str>,
    /// Proxy username, if any (← `conn->http_proxy.user`).
    pub proxy_user: Option<&'a str>,
    /// Proxy password, if any (← `conn->http_proxy.passwd`).
    pub proxy_passwd: Option<&'a str>,
    /// Whether proxy credentials are present (← `conn->bits.proxy_user_passwd`).
    pub has_proxy_user_passwd: bool,
    /// The `CURLOPT_XOAUTH2_BEARER` token, if any (← `data->set.str[STRING_BEARER]`).
    pub bearer_token: Option<&'a str>,
    /// Whether the user already supplied an `Authorization` header
    /// (← `Curl_checkheaders(data, "Authorization")`).
    pub user_authorization_header: bool,
    /// Whether the user already supplied a `Proxy-authorization` header
    /// (← `Curl_checkProxyheaders(data, conn, "Proxy-authorization")`).
    pub user_proxy_authorization_header: bool,
}

/// Emit the auth header for the picked mechanism, honoring curl's exact
/// precedence (← `output_auth_headers`, `lib/http.c`).
///
/// The precedence order — checked one mechanism at a time against `picked` — is
/// frozen and must not change:
///
/// 1. **AWS SigV4** (host only; never for a proxy),
/// 2. **Negotiate** (SPNEGO),
/// 3. **NTLM**,
/// 4. **Digest**,
/// 5. **Basic**,
/// 6. **Bearer**.
///
/// `Basic` and `Bearer` lines are written into `out` here; the other four
/// return a [`PickedAuth`] delegation descriptor for the transfer core to run
/// (see [`PickedAuth`]). On emission the `"%s auth using %s with user '%s'"`
/// diagnostic is logged and `state.multipass`/`state.done` are updated exactly
/// as curl does: Basic and Bearer are single-pass (`done` set, `multipass`
/// cleared); for the delegated multi-pass mechanisms `multipass` tracks
/// `!state.done`.
pub fn output_auth_headers(
    picked: u32,
    proxy: bool,
    ctx: &AuthOutputCtx<'_>,
    state: &mut AuthState,
    out: &mut String,
) -> Result<PickedAuth> {
    let mut selected = PickedAuth::None;

    if picked == auth::CURLAUTH_AWS_SIGV4 && !proxy {
        // AWS SigV4 signs the whole request; it is never used for a proxy and
        // is applied by the aws_sigv4 module against the assembled request.
        selected = PickedAuth::AwsSigV4;
    } else if picked == auth::CURLAUTH_NEGOTIATE {
        selected = PickedAuth::Negotiate;
    } else if picked == auth::CURLAUTH_NTLM {
        selected = PickedAuth::Ntlm;
    } else if picked == auth::CURLAUTH_DIGEST {
        selected = PickedAuth::Digest;
    } else if picked == auth::CURLAUTH_BASIC {
        // Only emit when we have credentials for this side and the user did not
        // already provide the header themselves.
        let allowed = if proxy {
            ctx.has_proxy_user_passwd && !ctx.user_proxy_authorization_header
        } else {
            ctx.user.is_some() && !ctx.user_authorization_header
        };
        if allowed {
            let line = if proxy {
                auth::basic::http_output_basic(ctx.proxy_user, ctx.proxy_passwd, true)?
            } else {
                auth::basic::http_output_basic(ctx.user, ctx.passwd, false)?
            };
            out.push_str(&line);
            selected = PickedAuth::Basic;
        }
        // Basic is single-pass regardless of whether a header was emitted.
        state.done = true;
    } else if picked == auth::CURLAUTH_BEARER {
        // Bearer is host-only and suppressed if the user supplied the header.
        if !proxy && ctx.bearer_token.is_some() && !ctx.user_authorization_header {
            let token = ctx.bearer_token.unwrap_or_default();
            write!(out, "Authorization: Bearer {token}\r\n").map_err(|_| Error::OutOfMemory)?;
            selected = PickedAuth::Bearer;
        }
        state.done = true;
    }

    if let Some(name) = selected.name() {
        let who = if proxy { "Proxy" } else { "Server" };
        let user = if proxy {
            ctx.proxy_user.unwrap_or("")
        } else {
            ctx.user.unwrap_or("")
        };
        tracing::info!("{who} auth using {name} with user '{user}'");
        // A picked mechanism still in handshake needs another round.
        state.multipass = !state.done;
    } else {
        state.multipass = false;
    }

    Ok(selected)
}

/// The outcome of [`http_output_auth`]: what (if anything) was emitted for each
/// side, and whether the negotiation phase must suppress the request body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpOutputAuth {
    /// The mechanism emitted/delegated for the origin host.
    pub host: PickedAuth,
    /// The mechanism emitted/delegated for the proxy.
    pub proxy: PickedAuth,
    /// Whether this is an auth-negotiation round that must not send the body
    /// yet (← `data->req.authneg`).
    pub authneg: bool,
}

/// Emit the `Authorization` and `Proxy-Authorization` headers for a request
/// (← `Curl_http_output_auth`).
///
/// Mirrors curl's control flow: if there is nothing to authenticate with (no
/// host credentials, no bearer token, and Negotiate is not wanted) both sides
/// are marked done and no headers are produced. Otherwise any unset `picked`
/// falls back to `want`; proxy auth is emitted only when tunneling state
/// matches `proxytunnel`; and host auth is emitted only when
/// [`crate::auth::allowed_to_host`] permits it (or netrc supplied the
/// credentials). `authneg` is raised when a multi-pass mechanism is mid-flight
/// on a body-bearing request, so the caller withholds the body until the
/// handshake completes.
///
/// `allowed_to_host` is computed by the caller (it needs the connection's host
/// identity) and passed in as `host_auth_allowed`.
#[allow(clippy::too_many_arguments)]
pub fn http_output_auth(
    ctx: &AuthOutputCtx<'_>,
    httpreq: HttpReq,
    proxytunnel: bool,
    httpproxy: bool,
    tunnel_proxy: bool,
    host_auth_allowed: bool,
    host: &mut AuthState,
    proxy: &mut AuthState,
    out: &mut String,
) -> Result<HttpOutputAuth> {
    let want_negotiate = (host.want & auth::CURLAUTH_NEGOTIATE) != 0;

    // Nothing to authenticate with: short-circuit exactly like curl.
    if ctx.user.is_none()
        && !ctx.has_proxy_user_passwd
        && ctx.bearer_token.is_none()
        && !want_negotiate
    {
        host.done = true;
        proxy.done = true;
        return Ok(HttpOutputAuth {
            host: PickedAuth::None,
            proxy: PickedAuth::None,
            authneg: false,
        });
    }

    // An unresolved pick defaults to the full wanted set.
    if host.picked == auth::CURLAUTH_NONE {
        host.picked = host.want;
    }
    if proxy.picked == auth::CURLAUTH_NONE {
        proxy.picked = proxy.want;
    }

    // Proxy authentication: only on the matching tunnel/non-tunnel pass.
    let mut proxy_selected = PickedAuth::None;
    if httpproxy && tunnel_proxy == proxytunnel {
        proxy_selected = output_auth_headers(proxy.picked, true, ctx, proxy, out)?;
    } else {
        proxy.done = true;
    }

    // Host authentication: gated by the cross-host leakage policy.
    let mut host_selected = PickedAuth::None;
    if host_auth_allowed {
        host_selected = output_auth_headers(host.picked, false, ctx, host, out)?;
    } else {
        host.done = true;
    }

    // Suppress the body while a multi-pass handshake is still in progress, but
    // never for GET/HEAD which carry no body to withhold.
    let authneg = ((host.multipass && !host.done) || (proxy.multipass && !proxy.done))
        && httpreq != HttpReq::Get
        && httpreq != HttpReq::Head;

    Ok(HttpOutputAuth {
        host: host_selected,
        proxy: proxy_selected,
        authneg,
    })
}

/// The inputs [`http_auth_act`] evaluates after a response is received
/// (← the `Curl_easy`/connection fields `Curl_http_auth_act` reads).
#[derive(Clone, Copy, Debug)]
pub struct AuthActInput {
    /// The response status code (← `data->req.httpcode`).
    pub httpcode: i32,
    /// Whether this is an auth-negotiation round (← `data->req.authneg`).
    pub authneg: bool,
    /// Whether host credentials exist (← `data->state.aptr.user`).
    pub have_user: bool,
    /// Whether a bearer token is configured (← `data->set.str[STRING_BEARER]`).
    pub have_bearer: bool,
    /// Whether proxy credentials exist (← `conn->bits.proxy_user_passwd`).
    pub have_proxy_creds: bool,
    /// The negotiated HTTP major/minor as curl encodes it (11/20/30); used to
    /// force HTTP/1.1 when NTLM is selected (← `conn->httpversion`).
    pub httpversion: u8,
    /// Whether `CURLOPT_FAILONERROR` is set (← `set.http_fail_on_error`).
    pub fail_on_error: bool,
    /// Whether a resume offset is in effect (← `state.resume_from != 0`).
    pub resume_from: bool,
    /// The request kind (← `state.httpreq`).
    pub httpreq: HttpReq,
    /// Whether an auth problem has been recorded (← `state.authproblem`).
    pub authproblem: bool,
}

/// The decision [`http_auth_act`] produces (← the side effects of
/// `Curl_http_auth_act`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthActOutcome {
    /// The method picked for the host, or [`CURLAUTH_PICKNONE`] (← `authhost.picked`).
    pub host_picked: u32,
    /// The method picked for the proxy, or [`CURLAUTH_PICKNONE`] (← `authproxy.picked`).
    pub proxy_picked: u32,
    /// Whether the transfer must be re-issued to complete authentication.
    pub retry: bool,
    /// Whether HTTP/1.1 must be forced because NTLM was selected
    /// (← the `"Forcing HTTP/1.1 for NTLM"` path).
    pub force_http11: bool,
}

/// React to a completed response's auth state, choosing the mechanism to use on
/// the next request (← `Curl_http_auth_act`).
///
/// Transient `1xx` responses short-circuit with no action. Otherwise, when host
/// credentials (or a bearer token) exist and the status is `401` — or this is a
/// negotiation round that finished below `300` — the strongest available host
/// mechanism is picked via [`pick_one_auth`]; the analogous rule with the
/// bearer bit masked off drives proxy selection on `407`. Selecting NTLM over
/// HTTP/2+ forces HTTP/1.1 (logging `"Forcing HTTP/1.1 for NTLM"`). When
/// [`http_should_fail`] reports the code is terminal, the transfer fails with
/// [`Error::HttpReturnedError`] carrying the status, matching curl's
/// `"The requested URL returned error: %d"`.
pub fn http_auth_act(
    input: &AuthActInput,
    host: &mut AuthState,
    proxy: &mut AuthState,
) -> Result<AuthActOutcome> {
    // Mask off Bearer for proxy selection; proxies never use bearer tokens.
    let mut authmask = !0u32;
    if !input.have_bearer {
        authmask &= !auth::CURLAUTH_BEARER;
    }

    // 1xx are transient — nothing to decide yet.
    if (100..200).contains(&input.httpcode) {
        return Ok(AuthActOutcome {
            host_picked: CURLAUTH_PICKNONE,
            proxy_picked: CURLAUTH_PICKNONE,
            retry: false,
            force_http11: false,
        });
    }

    let mut host_picked = CURLAUTH_PICKNONE;
    let mut proxy_picked = CURLAUTH_PICKNONE;
    let mut retry = false;
    let mut force_http11 = false;

    // Host: on a 401, or a finished (<300) negotiation round.
    if (input.have_user || input.have_bearer)
        && (input.httpcode == 401 || (input.authneg && input.httpcode < 300))
    {
        let (picked, ok) = pick_one_auth(host.want, host.avail, authmask | auth::CURLAUTH_BEARER);
        host.picked = picked;
        host_picked = picked;
        if ok {
            retry = true;
            // NTLM cannot run over a multiplexed connection; force HTTP/1.1.
            if picked == auth::CURLAUTH_NTLM && input.httpversion > 11 {
                tracing::info!("Forcing HTTP/1.1 for NTLM");
                force_http11 = true;
            }
        }
    }

    // Proxy: on a 407, or a finished (<300) negotiation round.
    if input.have_proxy_creds && (input.httpcode == 407 || (input.authneg && input.httpcode < 300))
    {
        let (picked, ok) = pick_one_auth(proxy.want, proxy.avail, authmask);
        proxy.picked = picked;
        proxy_picked = picked;
        if ok {
            retry = true;
        }
    }

    // Terminal-status check.
    let should_fail = http_should_fail(&ShouldFailInput {
        fail_on_error: input.fail_on_error,
        httpcode: input.httpcode,
        resume_from: input.resume_from,
        httpreq: input.httpreq,
        have_user: input.have_user,
        have_proxy_creds: input.have_proxy_creds,
        authproblem: input.authproblem,
    });
    if should_fail {
        // curl: failf("The requested URL returned error: %d", httpcode)
        let code = u32::try_from(input.httpcode).unwrap_or(0);
        return Err(Error::HttpReturnedError(code));
    }

    Ok(AuthActOutcome {
        host_picked,
        proxy_picked,
        retry,
        force_http11,
    })
}

// ===========================================================================
// PHASE 7 — Response parsing (← the status-line, prefix, and header-ingestion
// machinery in `lib/http.c`).
// ===========================================================================

/// The classification of a would-be status line (← `enum statusline`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusLine {
    /// Not enough bytes yet to decide (← `STATUS_UNKNOWN`).
    Unknown,
    /// A complete status line was recognized (← `STATUS_DONE`).
    Done,
    /// Definitely not a status line (← `STATUS_BAD`).
    Bad,
}

/// Whether `buffer` begins with `prefix`, comparing at most `buffer.len()`
/// bytes case-insensitively (← `checkprefixmax`).
#[must_use]
fn check_prefix_max(prefix: &str, buffer: &str) -> bool {
    let ch = prefix.len().min(buffer.len());
    prefix.as_bytes()[..ch].eq_ignore_ascii_case(&buffer.as_bytes()[..ch])
}

/// Whether `s` looks like an HTTP status line, considering the user's
/// `CURLOPT_HTTP200ALIASES` list and the literal `HTTP/` prefix
/// (← `checkhttpprefix`).
///
/// A match yields [`StatusLine::Done`] once at least five bytes are present
/// (enough to have seen `HTTP/`), otherwise [`StatusLine::Unknown`] to request
/// more data. `aliases` are the configured 200-aliases, checked first.
#[must_use]
pub fn check_http_prefix(aliases: &[String], s: &str) -> StatusLine {
    let onmatch = if s.len() >= 5 {
        StatusLine::Done
    } else {
        StatusLine::Unknown
    };
    for alias in aliases {
        if check_prefix_max(alias, s) {
            return onmatch;
        }
    }
    if check_prefix_max("HTTP/", s) {
        return onmatch;
    }
    StatusLine::Bad
}

/// Whether `s` looks like an RTSP status line (← `checkrtspprefix`).
///
/// Exposed to the crate so `rtsp.rs` can reuse the exact prefix check rather
/// than duplicating it (this is the documented RTSP reuse seam).
#[must_use]
pub(crate) fn check_rtsp_prefix(s: &str) -> StatusLine {
    let onmatch = if s.len() >= 5 {
        StatusLine::Done
    } else {
        StatusLine::Unknown
    };
    if check_prefix_max("RTSP/", s) {
        onmatch
    } else {
        StatusLine::Bad
    }
}

/// Dispatch the status-line prefix check by connection scheme (← `checkprotoprefix`).
///
/// RTSP connections use [`check_rtsp_prefix`]; everything else uses
/// [`check_http_prefix`].
#[must_use]
pub fn check_proto_prefix(is_rtsp: bool, aliases: &[String], s: &str) -> StatusLine {
    if is_rtsp {
        check_rtsp_prefix(s)
    } else {
        check_http_prefix(aliases, s)
    }
}

/// A parsed HTTP status line (← the `httpversion`/`httpcode` extraction in the
/// first-header block of `http_rw_hd`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedStatusLine {
    /// The version encoded as curl's `major*10 + minor` (10/11/20/30).
    pub httpversion: u8,
    /// The three-digit status code.
    pub httpcode: i32,
}

/// Parse an HTTP/1.x, HTTP/2, or HTTP/3 status line, returning the version and
/// status code (← the `HTTP/` parse in `http_rw_hd`).
///
/// Accepts `HTTP/1.0`/`HTTP/1.1` (dotted minor, blank required before the code)
/// and `HTTP/2`/`HTTP/3` (version digit then a blank). The status code must be
/// exactly three digits. For HTTP/1.x a trailing space after the code is *not*
/// required (browsers omit it); for HTTP/2 and HTTP/3 it is, matching curl.
/// Returns `None` when the line is not a well-formed status line.
#[must_use]
pub fn parse_status_line(hd: &str) -> Option<ParsedStatusLine> {
    let b = hd.as_bytes();
    let mut i = 0;
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }
    if b.len() < i + 5 || !b[i..i + 5].eq_ignore_ascii_case(b"HTTP/") {
        return None;
    }
    i += 5;

    let three_digits = |b: &[u8], i: usize| -> Option<i32> {
        let d0 = *b.get(i)?;
        let d1 = *b.get(i + 1)?;
        let d2 = *b.get(i + 2)?;
        if d0.is_ascii_digit() && d1.is_ascii_digit() && d2.is_ascii_digit() {
            Some(i32::from(d0 - b'0') * 100 + i32::from(d1 - b'0') * 10 + i32::from(d2 - b'0'))
        } else {
            None
        }
    };
    let is_blank = |c: u8| c == b' ' || c == b'\t';

    match *b.get(i)? {
        b'1' => {
            i += 1;
            if *b.get(i)? != b'.' {
                return None;
            }
            let minor = *b.get(i + 1)?;
            if minor != b'0' && minor != b'1' {
                return None;
            }
            if !is_blank(*b.get(i + 2)?) {
                return None;
            }
            let httpversion = 10 + (minor - b'0');
            let httpcode = three_digits(b, i + 3)?;
            Some(ParsedStatusLine {
                httpversion,
                httpcode,
            })
        }
        vch @ (b'2' | b'3') => {
            if !is_blank(*b.get(i + 1)?) {
                return None;
            }
            let httpversion = (vch - b'0') * 10;
            let httpcode = three_digits(b, i + 2)?;
            // HTTP/2 and HTTP/3 require a blank after the status code.
            if !is_blank(*b.get(i + 5)?) {
                return None;
            }
            Some(ParsedStatusLine {
                httpversion,
                httpcode,
            })
        }
        _ => None,
    }
}

/// The request/response state [`http_statusline`] reads and mutates
/// (← the `SingleRequest` / negotiation fields it touches).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatusLineState {
    /// The just-parsed response version (10/11/20/30) (← `k->httpversion`).
    pub httpversion: u8,
    /// The version we sent, or 0 if none (← `k->httpversion_sent`).
    pub httpversion_sent: u8,
    /// The just-parsed status code (← `k->httpcode`).
    pub httpcode: i32,
    /// Whether a resume offset is in effect (← `state.resume_from`).
    pub resume_from: bool,
    /// The request kind (← `state.httpreq`).
    pub httpreq: HttpReq,
    /// Whether a `CURLOPT_TIMECONDITION` is set (← `set.timecondition`).
    pub timecondition: bool,
    /// Lowest server version seen so far, updated in place (← `http_neg.rcvd_min`).
    pub rcvd_min: u8,
    /// The version recorded on the connection, set here (← `conn->httpversion_seen`).
    pub httpversion_seen: u8,
    /// Whether the connection must close after the body (← `connclose` path).
    pub close_after_body: bool,
    /// Whether this response carries no body (← `k->http_bodyless`).
    pub http_bodyless: bool,
    /// Whether the body should be ignored (← `k->ignorebody`).
    pub ignorebody: bool,
    /// Whether the time condition was met (← `data->info.timecond`).
    pub timecond_met: bool,
    /// The expected body size, or -1 if unknown (← `k->size`).
    pub size: i64,
    /// The maximum download size, or -1 if unknown (← `k->maxdownload`).
    pub maxdownload: i64,
}

/// Validate and record a parsed status line (← `http_statusline`).
///
/// Rejects an unsupported version with [`Error::UnsupportedProtocol`] and a
/// mid-connection major-version switch with a
/// [`CurlCode::WeirdServerReply`]-coded error. On success it records the
/// version on the connection, tracks the lowest version seen, arranges an
/// HTTP/1.0 close-after-body (logging `"HTTP 1.0, assume close after body"`),
/// treats a `416` answer to a resumed GET as success by ignoring its body, and
/// makes `204`/`304` responses body-less (and `304` sets the time-condition
/// flag). Diagnostic text matches curl verbatim.
pub fn http_statusline(st: &mut StatusLineState) -> Result<()> {
    match st.httpversion {
        10 | 11 | 20 | 30 => {
            // A response may not flip the major version mid-connection.
            if st.httpversion_sent != 0 && st.httpversion / 10 != st.httpversion_sent / 10 {
                return Err(Error::with_context(
                    CurlCode::WeirdServerReply,
                    format!(
                        "Version mismatch (from HTTP/{} to HTTP/{})",
                        st.httpversion_sent / 10,
                        st.httpversion / 10
                    ),
                ));
            }
        }
        _ => {
            return Err(Error::UnsupportedProtocol);
        }
    }

    st.httpversion_seen = st.httpversion;
    if st.rcvd_min == 0 || st.rcvd_min > st.httpversion {
        st.rcvd_min = st.httpversion;
    }

    // 416 to a resumed GET means the range is already satisfied; keep the good
    // data and drop the error body.
    if st.resume_from && st.httpreq == HttpReq::Get && st.httpcode == 416 {
        st.ignorebody = true;
    }

    if st.httpversion == 10 {
        tracing::info!("HTTP 1.0, assume close after body");
        st.close_after_body = true;
    }

    st.http_bodyless = (100..200).contains(&st.httpcode);
    match st.httpcode {
        304 => {
            if st.timecondition {
                st.timecond_met = true;
            }
            // 304, like 204, carries no message body.
            st.size = 0;
            st.maxdownload = 0;
            st.http_bodyless = true;
        }
        204 => {
            st.size = 0;
            st.maxdownload = 0;
            st.http_bodyless = true;
        }
        _ => {}
    }
    Ok(())
}

/// The inputs [`http_size`] evaluates (← the `SingleRequest`/`set` fields).
#[derive(Clone, Copy, Debug)]
pub struct SizeInput {
    /// Whether `Content-Length` must be ignored (← `data->req.ignore_cl`).
    pub ignore_cl: bool,
    /// Whether the response is chunked (← `k->chunk`).
    pub chunk: bool,
    /// The announced size, or -1 if unknown (← `k->size`).
    pub size: i64,
    /// The configured maximum file size, or 0 for no limit (← `set.max_filesize`).
    pub max_filesize: i64,
    /// Whether the body is being ignored (← `k->ignorebody`).
    pub ignorebody: bool,
}

/// The resolved size and download cap [`http_size`] produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SizeOutput {
    /// The expected body size, or -1 if unknown (← `k->size`).
    pub size: i64,
    /// The maximum number of body bytes to download, or -1 (← `k->maxdownload`).
    pub maxdownload: i64,
}

/// Resolve the expected download size after all headers are seen (← `http_size`).
///
/// `Content-Length` is ignored (size unknown) whenever the response is chunked
/// or the caller forced it off. Otherwise a known size that exceeds a
/// configured `CURLOPT_MAXFILESIZE` fails with [`Error::FilesizeExceeded`]
/// (unless the body is being ignored), matching curl's
/// `"Maximum file size exceeded"`.
pub fn http_size(input: &SizeInput) -> Result<SizeOutput> {
    if input.ignore_cl || input.chunk {
        return Ok(SizeOutput {
            size: -1,
            maxdownload: -1,
        });
    }
    if input.size != -1 {
        if input.max_filesize != 0 && !input.ignorebody && input.size > input.max_filesize {
            return Err(Error::FilesizeExceeded);
        }
        if input.ignorebody {
            tracing::info!("setting size while ignoring");
        }
        return Ok(SizeOutput {
            size: input.size,
            maxdownload: input.size,
        });
    }
    Ok(SizeOutput {
        size: input.size,
        maxdownload: -1,
    })
}

/// Reject malformed response header bytes (← `verify_header`).
///
/// A NUL byte anywhere in the line, or a non-folded header line past the status
/// line that lacks a colon, is a [`CurlCode::WeirdServerReply`]-coded error.
/// `headerline` is the 1-based header index (line 1 is the status line, which
/// legitimately has no colon; folding — a leading space/tab — is only valid
/// from line 3 onward).
pub fn verify_header(hd: &str, headerline: u32) -> Result<()> {
    if hd.as_bytes().contains(&0) {
        return Err(Error::with_context(
            CurlCode::WeirdServerReply,
            "Nul byte in header",
        ));
    }
    // The first "header" is the status line; it has no colon.
    if headerline < 2 {
        return Ok(());
    }
    let folded = matches!(hd.as_bytes().first(), Some(b' ' | b'\t')) && headerline > 2;
    if !folded && !hd.as_bytes().contains(&b':') {
        return Err(Error::with_context(
            CurlCode::WeirdServerReply,
            "Header without colon",
        ));
    }
    Ok(())
}

/// A classified response header carrying its extracted value (← the actions the
/// per-first-letter handlers `http_header_a`..`http_header_w` take).
///
/// This module recognizes the wire-significant headers and yields a descriptor;
/// the transfer core performs the side effect against the owning subsystem
/// (`Set-Cookie` → the cookie jar, `Location` → redirect, `Content-Encoding` →
/// the decompressors, `Transfer-Encoding: chunked` → the chunked decoder,
/// `Strict-Transport-Security` → HSTS, `Alt-Svc` → the alt-svc cache,
/// `WWW-Authenticate`/`Proxy-Authenticate` → [`http_input_auth`]). Those
/// subsystems are not dependencies of this module, so the descriptor keeps the
/// dispatch faithful without importing them. Values are extracted exactly as
/// [`copy_header_value`] does (leading/trailing whitespace trimmed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseHeader {
    /// `Connection: close` was present (← `connclose`).
    ConnectionClose,
    /// `Connection: keep-alive` was present (← `connkeep`).
    ConnectionKeepAlive,
    /// `Proxy-Connection: close` was present.
    ProxyConnectionClose,
    /// `Proxy-Connection: keep-alive` was present.
    ProxyConnectionKeepAlive,
    /// `Content-Encoding` and its value.
    ContentEncoding(String),
    /// `Content-Length` and its raw value (parsed by the caller).
    ContentLength(String),
    /// `Content-Range` and its value.
    ContentRange(String),
    /// `Content-Type` and its value.
    ContentType(String),
    /// `Last-Modified` and its value.
    LastModified(String),
    /// `Location` and its value (redirect target).
    Location(String),
    /// `Retry-After` and its value.
    RetryAfter(String),
    /// `Set-Cookie` and its value.
    SetCookie(String),
    /// `Strict-Transport-Security` and its value.
    StrictTransportSecurity(String),
    /// `Alt-Svc` and its value.
    AltSvc(String),
    /// `Trailer` and its value.
    Trailer(String),
    /// `Transfer-Encoding` and its value (check for `chunked` with
    /// [`compare_header`]).
    TransferEncoding(String),
    /// `WWW-Authenticate` challenge and its value (feed to [`http_input_auth`]).
    WwwAuthenticate(String),
    /// `Proxy-Authenticate` challenge and its value (feed to [`http_input_auth`]).
    ProxyAuthenticate(String),
    /// `Persistent-Auth` and its value (RTSP/Negotiate persistence).
    PersistentAuth(String),
    /// A header this module does not act on.
    Other,
}

/// Whether `hd` begins with the header field name `name_colon` (which must
/// include its trailing colon), compared case-insensitively (← the `HD_IS` macro).
#[must_use]
fn hd_is(hd: &str, name_colon: &str) -> bool {
    hd.len() >= name_colon.len()
        && hd.as_bytes()[..name_colon.len()].eq_ignore_ascii_case(name_colon.as_bytes())
}

/// Classify a response header line and extract its value (← the per-first-letter
/// dispatch `http_header` performs, `lib/http.c:3661`).
///
/// Only the wire-significant headers curl acts on are recognized; anything else
/// maps to [`ResponseHeader::Other`]. Recognition is case-insensitive on the
/// field name and the returned value is trimmed exactly as [`copy_header_value`].
/// The code-conditional gates curl applies (e.g. only honoring
/// `WWW-Authenticate` on a `401`) are left to the caller, which owns the status
/// code and the target subsystems.
#[must_use]
pub fn classify_response_header(hd: &str) -> ResponseHeader {
    // Dispatch on the first byte, mirroring the C switch, then match names.
    match hd
        .as_bytes()
        .first()
        .copied()
        .map(|c| c.to_ascii_lowercase())
    {
        Some(b'a') => {
            if hd_is(hd, "Alt-Svc:") {
                return ResponseHeader::AltSvc(copy_header_value(hd).unwrap_or_default());
            }
        }
        Some(b'c') => {
            if hd_is(hd, "Connection:") {
                if compare_header(hd, "Connection:", "close") {
                    return ResponseHeader::ConnectionClose;
                }
                if compare_header(hd, "Connection:", "keep-alive") {
                    return ResponseHeader::ConnectionKeepAlive;
                }
                return ResponseHeader::Other;
            }
            if hd_is(hd, "Content-Encoding:") {
                return ResponseHeader::ContentEncoding(copy_header_value(hd).unwrap_or_default());
            }
            if hd_is(hd, "Content-Length:") {
                return ResponseHeader::ContentLength(copy_header_value(hd).unwrap_or_default());
            }
            if hd_is(hd, "Content-Range:") {
                return ResponseHeader::ContentRange(copy_header_value(hd).unwrap_or_default());
            }
            if hd_is(hd, "Content-Type:") {
                return ResponseHeader::ContentType(copy_header_value(hd).unwrap_or_default());
            }
        }
        Some(b'l') => {
            if hd_is(hd, "Last-Modified:") {
                return ResponseHeader::LastModified(copy_header_value(hd).unwrap_or_default());
            }
            if hd_is(hd, "Location:") {
                return ResponseHeader::Location(copy_header_value(hd).unwrap_or_default());
            }
        }
        Some(b'p') => {
            if hd_is(hd, "Proxy-Connection:") {
                if compare_header(hd, "Proxy-Connection:", "close") {
                    return ResponseHeader::ProxyConnectionClose;
                }
                if compare_header(hd, "Proxy-Connection:", "keep-alive") {
                    return ResponseHeader::ProxyConnectionKeepAlive;
                }
                return ResponseHeader::Other;
            }
            if hd_is(hd, "Proxy-authenticate:") {
                return ResponseHeader::ProxyAuthenticate(
                    copy_header_value(hd).unwrap_or_default(),
                );
            }
            if hd_is(hd, "Persistent-Auth:") {
                return ResponseHeader::PersistentAuth(copy_header_value(hd).unwrap_or_default());
            }
        }
        Some(b'r') => {
            if hd_is(hd, "Retry-After:") {
                return ResponseHeader::RetryAfter(copy_header_value(hd).unwrap_or_default());
            }
        }
        Some(b's') => {
            if hd_is(hd, "Set-Cookie:") {
                return ResponseHeader::SetCookie(copy_header_value(hd).unwrap_or_default());
            }
            if hd_is(hd, "Strict-Transport-Security:") {
                return ResponseHeader::StrictTransportSecurity(
                    copy_header_value(hd).unwrap_or_default(),
                );
            }
        }
        Some(b't') => {
            if hd_is(hd, "Transfer-Encoding:") {
                return ResponseHeader::TransferEncoding(copy_header_value(hd).unwrap_or_default());
            }
            if hd_is(hd, "Trailer:") {
                return ResponseHeader::Trailer(copy_header_value(hd).unwrap_or_default());
            }
        }
        Some(b'w') if hd_is(hd, "WWW-Authenticate:") => {
            return ResponseHeader::WwwAuthenticate(copy_header_value(hd).unwrap_or_default());
        }
        _ => {}
    }
    ResponseHeader::Other
}

// ===========================================================================
// PHASE 8 — Version banner and default User-Agent (← `http_useragent` and the
// `curl/<version>` default assembled in `lib/version.c`).
// ===========================================================================

/// The full human-readable version banner, in the mandated form (AAP §0.6.3):
///
/// ```text
/// curl-rs/8.19.0-DEV rustls flate2 brotli zstd hyper quinn russh
/// ```
///
/// This delegates to the crate-root [`crate::version`], which assembles the
/// backend tokens from the enabled Cargo features and caches the result. It is
/// re-exposed here so the HTTP layer (and `--version`) share one authoritative
/// banner rather than duplicating the feature-string assembly.
#[must_use]
pub fn version_banner() -> &'static str {
    crate::version()
}

/// The default `User-Agent` header value, `curl-rs/8.19.0-DEV`
/// (← curl's `curl/<LIBCURL_VERSION>` default).
///
/// Like curl, the default agent is only the product token and version — the
/// backend list from [`version_banner`] is reserved for `--version`, not sent
/// on the wire. A user-supplied `User-Agent` header overrides this (see
/// `http_useragent`), and setting it empty suppresses the header entirely.
#[must_use]
pub fn default_user_agent() -> String {
    format!("curl-rs/{}", crate::VERSION)
}

// ===========================================================================
// Unit tests
//
// These exercise the deterministic, wire-parity-critical logic ported from
// `lib/http.c`: status-line parsing, header machinery and folding, the
// HTTP/2 header transform, redirect resolution, the `Expect: 100-continue`
// threshold, and authentication-header selection/precedence. They are
// dependency-free — the only async surface (the `Protocol` trait methods) is
// driven by a tiny in-file `block_on` built on `std::task` alone, so no
// external runtime or mock daemon is required.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        CURLAUTH_AWS_SIGV4, CURLAUTH_BASIC, CURLAUTH_BEARER, CURLAUTH_DIGEST, CURLAUTH_NEGOTIATE,
        CURLAUTH_NONE, CURLAUTH_NTLM,
    };
    use crate::conn::filters::{CfFuture, FilterCtx};
    use crate::conn::{CfType, ConnectionFilter, FilterChain, Scheme};

    /// Poll a future to completion using only `std::task`. Our futures never
    /// return `Pending`, so a no-op waker suffices; this keeps the tests free
    /// of any async-runtime dependency.
    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
            fn wake_by_ref(self: &Arc<Self>) {}
        }

        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    // ---- Status-line parsing ---------------------------------------------

    #[test]
    fn parse_status_line_http1() {
        let p = parse_status_line("HTTP/1.1 200 OK").unwrap();
        assert_eq!(p.httpversion, 11);
        assert_eq!(p.httpcode, 200);

        let p = parse_status_line("HTTP/1.0 404 Not Found").unwrap();
        assert_eq!(p.httpversion, 10);
        assert_eq!(p.httpcode, 404);

        // HTTP/1.x does not require a trailing space after the code.
        let p = parse_status_line("HTTP/1.1 204").unwrap();
        assert_eq!(p.httpcode, 204);
    }

    #[test]
    fn parse_status_line_http2_and_3() {
        let p = parse_status_line("HTTP/2 200 ").unwrap();
        assert_eq!(p.httpversion, 20);
        assert_eq!(p.httpcode, 200);

        let p = parse_status_line("HTTP/3 204 ").unwrap();
        assert_eq!(p.httpversion, 30);
        assert_eq!(p.httpcode, 204);

        // HTTP/2 and HTTP/3 require the trailing blank after the code.
        assert!(parse_status_line("HTTP/2 200").is_none());
    }

    #[test]
    fn parse_status_line_rejects_garbage() {
        assert!(parse_status_line("NOTHTTP/1.1 200").is_none());
        assert!(parse_status_line("HTTP/9.9 200").is_none());
        assert!(parse_status_line("HTTP/1.1 20 OK").is_none());
        // Leading blanks are tolerated (curl passes them).
        assert!(parse_status_line("   HTTP/1.1 200 OK").is_some());
    }

    #[test]
    fn decode_status_code() {
        // Exactly three digits, like curl's `Curl_http_decode_status`.
        assert_eq!(http_decode_status("200").unwrap(), 200);
        assert_eq!(http_decode_status("404").unwrap(), 404);
        // Anything that is not precisely three digits is rejected.
        assert!(http_decode_status("2").is_err());
        assert!(http_decode_status("abc").is_err());
        assert!(http_decode_status("404 Not Found").is_err());
    }

    // ---- Prefix checks ---------------------------------------------------

    #[test]
    fn prefix_checks() {
        assert_eq!(check_http_prefix(&[], "HTTP/1.1 200 OK"), StatusLine::Done);
        assert_eq!(check_http_prefix(&[], "HTTP"), StatusLine::Unknown);
        assert_eq!(check_http_prefix(&[], "GET / HTTP/1.1"), StatusLine::Bad);

        // A configured HTTP200ALIAS is honoured.
        let aliases = vec!["ICY".to_string()];
        assert_eq!(check_http_prefix(&aliases, "ICY 200 OK"), StatusLine::Done);

        assert_eq!(check_rtsp_prefix("RTSP/1.0 200 OK"), StatusLine::Done);
        assert_eq!(check_rtsp_prefix("HTTP/1.1 200 OK"), StatusLine::Bad);

        assert_eq!(
            check_proto_prefix(true, &[], "RTSP/1.0 200 OK"),
            StatusLine::Done
        );
        assert_eq!(
            check_proto_prefix(false, &[], "HTTP/1.1 200 OK"),
            StatusLine::Done
        );
    }

    // ---- Header machinery ------------------------------------------------

    #[test]
    fn compare_header_scans_tokens() {
        // The content token can appear anywhere in a multi-value header.
        assert!(compare_header(
            "Connection: keep-alive, close",
            "Connection:",
            "close"
        ));
        assert!(compare_header("Connection: close", "Connection:", "close"));
        // Case-insensitive on both the field name and the content token.
        assert!(compare_header("connection: CLOSE", "Connection:", "close"));
        assert!(!compare_header(
            "Connection: keep-alive",
            "Connection:",
            "close"
        ));
        // Wrong field name never matches.
        assert!(!compare_header(
            "Content-Type: close",
            "Connection:",
            "close"
        ));
    }

    #[test]
    fn copy_header_value_trims() {
        assert_eq!(
            copy_header_value("Location: http://example.com/").as_deref(),
            Some("http://example.com/")
        );
        // Surrounding whitespace is trimmed.
        assert_eq!(
            copy_header_value("X-Test:   spaced   ").as_deref(),
            Some("spaced")
        );
        // No colon → no value.
        assert!(copy_header_value("NoColonHere").is_none());
    }

    #[test]
    fn fold_header_continuation() {
        // `Curl_http_to_fold` strips the trailing CRLF (and any trailing
        // whitespace) so the next continuation line can be appended in place.
        let mut buf = String::from("X-Long: part1\r\n");
        http_to_fold(&mut buf);
        assert_eq!(buf, "X-Long: part1");

        // Trailing blanks before the line ending are also removed.
        let mut buf = String::from("X-Long: value  \r\n");
        http_to_fold(&mut buf);
        assert_eq!(buf, "X-Long: value");

        // A lone LF is handled too.
        let mut buf = String::from("A: b\n");
        http_to_fold(&mut buf);
        assert_eq!(buf, "A: b");
    }

    #[test]
    fn verify_header_rules() {
        // Status line (headerline 1) needs no colon.
        assert!(verify_header("HTTP/1.1 200 OK", 1).is_ok());
        // A normal header needs a colon.
        assert!(verify_header("Content-Type: text/html", 2).is_ok());
        assert!(verify_header("no colon here", 2).is_err());
        // Folded continuation (leading space) is valid from line 3.
        assert!(verify_header(" continued value", 3).is_ok());
        // A NUL byte anywhere is rejected.
        assert!(verify_header("Bad:\0value", 2).is_err());
    }

    #[test]
    fn bump_headersize_enforces_limit() {
        let mut st = HeaderSizeState::default();
        // Small increments accumulate without error.
        assert!(bump_headersize(&mut st, 100, false).is_ok());
        // A single delta beyond the cap is rejected with a RECV-mapped error.
        let mut st2 = HeaderSizeState::default();
        let err = bump_headersize(&mut st2, MAX_HTTP_RESP_HEADER_SIZE + 1, false).unwrap_err();
        assert_eq!(err.code(), CurlCode::RecvError);
    }

    #[test]
    fn record_response_enforces_header_count() {
        // Regression for the response-header COUNT ceiling (QA F3-H1-001).
        // curl accepts up to MAX_HTTP_RESP_HEADER_COUNT (5000) response headers
        // and rejects the next one with CURLE_TOO_LARGE (integer 100).
        // `record_response` is the version-agnostic enforcement point.

        // Exactly the limit is accepted.
        let mut ctx = TransferCtx::new();
        let mut resp = HttpResp::make(200, Some("OK"));
        for i in 0..MAX_HTTP_RESP_HEADER_COUNT {
            resp.headers.add(format!("X-H-{i}"), "v");
        }
        assert_eq!(resp.headers.count(), MAX_HTTP_RESP_HEADER_COUNT);
        assert!(
            record_response(&mut ctx, resp).is_ok(),
            "a response with exactly the header limit must be accepted"
        );

        // One header over the limit is rejected with CURLE_TOO_LARGE.
        let mut ctx2 = TransferCtx::new();
        let mut resp2 = HttpResp::make(200, Some("OK"));
        for i in 0..=MAX_HTTP_RESP_HEADER_COUNT {
            resp2.headers.add(format!("X-H-{i}"), "v");
        }
        assert_eq!(resp2.headers.count(), MAX_HTTP_RESP_HEADER_COUNT + 1);
        let err = record_response(&mut ctx2, resp2).unwrap_err();
        assert_eq!(err.code(), CurlCode::TooLarge);
    }

    // ---- HTTP/2 header transform -----------------------------------------

    #[test]
    fn http_req_to_h2_transforms() {
        let mut req = HttpReqData::make("GET", Some("https"), None, Some("/index.html"));
        // Host must be promoted to :authority and dropped as a regular field.
        req.headers.add("Host", "example.com");
        // Connection-specific fields must be dropped per RFC 9113 §8.2.2.
        req.headers.add("Connection", "keep-alive");
        // A normal field is forwarded, lowercased.
        req.headers.add("Accept", "*/*");

        let h2 = http_req_to_h2(&req, true).unwrap();

        // Pseudo-headers come first, in the fixed order.
        assert_eq!(h2.getn(0), Some((HTTP_PSEUDO_METHOD, "GET")));
        assert_eq!(h2.getn(1), Some((HTTP_PSEUDO_SCHEME, "https")));
        assert_eq!(h2.getn(2), Some((HTTP_PSEUDO_AUTHORITY, "example.com")));
        assert_eq!(h2.getn(3), Some((HTTP_PSEUDO_PATH, "/index.html")));

        // Host and Connection are gone; Accept survives lowercased.
        assert_eq!(h2.get("host"), None);
        assert_eq!(h2.get("connection"), None);
        assert_eq!(h2.get("accept"), Some("*/*"));
    }

    #[test]
    fn make2_splits_absolute_and_origin_form() {
        let abs = HttpReqData::make2("GET", "https://host.test/p?q=1");
        assert_eq!(abs.scheme.as_deref(), Some("https"));
        assert_eq!(abs.authority.as_deref(), Some("host.test"));
        assert_eq!(abs.path.as_deref(), Some("/p?q=1"));

        let origin = HttpReqData::make2("GET", "/only/path");
        assert_eq!(origin.scheme, None);
        assert_eq!(origin.path.as_deref(), Some("/only/path"));
    }

    // ---- Version negotiation --------------------------------------------

    #[test]
    fn version_strings() {
        assert_eq!(get_http_string(30), "3");
        assert_eq!(get_http_string(20), "2");
        assert_eq!(get_http_string(11), "1.1");
        assert_eq!(get_http_string(10), "1.0");
        assert_eq!(get_http_string(9), "1.0");
    }

    #[test]
    fn neg_init_and_may_use_1_1() {
        let neg = http_neg_init(HttpWant::None, true);
        // With no explicit preference, HTTP/1.1 remains usable.
        assert!(http_may_use_1_1(&neg, None));
        // Forcing HTTP/1.0 disallows 1.1.
        let neg10 = http_neg_init(HttpWant::Http10, false);
        assert!(!http_may_use_1_1(&neg10, None));
    }

    // ---- Method resolution ----------------------------------------------

    #[test]
    fn http_method_resolution() {
        // A plain GET.
        let (m, req) = http_method(MethodInput {
            protocol: CURLPROTO_HTTP,
            upload: false,
            custom_request: None,
            http_ignorecustom: false,
            no_body: false,
            httpreq: HttpReq::Get,
        });
        assert_eq!(m, "GET");
        assert_eq!(req, HttpReq::Get);

        // A custom request overrides the method string.
        let (m, _) = http_method(MethodInput {
            protocol: CURLPROTO_HTTP,
            upload: false,
            custom_request: Some("PATCH"),
            http_ignorecustom: false,
            no_body: false,
            httpreq: HttpReq::Get,
        });
        assert_eq!(m, "PATCH");
    }

    // ---- Redirect / follow ----------------------------------------------

    fn follow_state(url: &str, code: i32, req: HttpReq) -> FollowState {
        FollowState {
            httpreq: req,
            allow_port: true,
            url: url.to_string(),
            first_host: "example.com".to_string(),
            first_remote_port: 80,
            first_remote_protocol: CURLPROTO_HTTP,
            httpcode: code,
            ..FollowState::default()
        }
    }

    #[test]
    fn follow_resolves_relative_redirect() {
        let cfg = FollowConfig {
            maxredirs: -1,
            ..FollowConfig::default()
        };
        let mut st = follow_state("http://example.com/a/b", 302, HttpReq::Get);
        http_follow(&cfg, &mut st, "/c", FollowType::Redir).unwrap();
        assert_eq!(st.url, "http://example.com/c");
        assert_eq!(st.followlocation, 1);
    }

    #[test]
    fn follow_enforces_maxredirs() {
        let cfg = FollowConfig {
            maxredirs: 0,
            ..FollowConfig::default()
        };
        let mut st = follow_state("http://example.com/", 302, HttpReq::Get);
        let err = http_follow(&cfg, &mut st, "/next", FollowType::Redir).unwrap_err();
        assert_eq!(err.code(), CurlCode::TooManyRedirects);
        // The would-be target is still recorded.
        assert!(st.wouldredirect.is_some());
    }

    #[test]
    fn follow_switches_post_to_get_on_302() {
        let cfg = FollowConfig {
            maxredirs: -1,
            follow_mode: CURLFOLLOW_OBEYCODE,
            ..FollowConfig::default()
        };
        let mut st = follow_state("http://example.com/form", 302, HttpReq::Post);
        http_follow(&cfg, &mut st, "/result", FollowType::Redir).unwrap();
        assert_eq!(st.httpreq, HttpReq::Get);
    }

    #[test]
    fn follow_sets_auto_referer() {
        let cfg = FollowConfig {
            maxredirs: -1,
            auto_referer: true,
            ..FollowConfig::default()
        };
        // Credentials and fragment must be stripped from the Referer.
        let mut st = follow_state("http://user:pass@example.com/a#frag", 302, HttpReq::Get);
        http_follow(&cfg, &mut st, "/b", FollowType::Redir).unwrap();
        assert_eq!(st.referer.as_deref(), Some("http://example.com/a"));
    }

    // ---- Expect: 100-continue -------------------------------------------

    fn expect_input(
        httpversion: i32,
        client_len: i64,
        disableexpect: bool,
    ) -> ExpectInput<'static> {
        ExpectInput {
            upgrade_pending: false,
            custom_headers: &[],
            disableexpect,
            httpversion,
            client_len,
        }
    }

    #[test]
    fn expect_100_added_for_large_body() {
        let mut out = String::new();
        let added = addexpect(
            expect_input(11, EXPECT_100_THRESHOLD as i64 + 1, false),
            &mut out,
        )
        .unwrap();
        assert!(added);
        assert!(out.contains("Expect: 100-continue"));
    }

    #[test]
    fn expect_100_added_for_unknown_length() {
        let mut out = String::new();
        let added = addexpect(expect_input(11, -1, false), &mut out).unwrap();
        assert!(added);
        assert!(out.contains("Expect: 100-continue"));
    }

    #[test]
    fn expect_100_skipped_for_small_body() {
        let mut out = String::new();
        let added = addexpect(expect_input(11, 10, false), &mut out).unwrap();
        assert!(!added);
        assert!(out.is_empty());
    }

    #[test]
    fn expect_100_skipped_when_disabled_or_not_http11() {
        let mut out = String::new();
        assert!(!addexpect(expect_input(11, 1 << 30, true), &mut out).unwrap());
        assert!(out.is_empty());
        // Only HTTP/1.1 uses Expect.
        let mut out2 = String::new();
        assert!(!addexpect(expect_input(20, 1 << 30, false), &mut out2).unwrap());
        assert!(out2.is_empty());
    }

    #[test]
    fn exp100_reader_holds_body_until_continue() {
        let mut r = Exp100Reader::new(1000);
        // Fresh reader is still sending the request head, not yet waiting.
        assert_eq!(r.state(), Exp100::SendingRequest);
        assert!(!r.is_waiting());

        // The wait only begins once the request head is fully sent.
        assert_eq!(r.poll(false, 0), Exp100Action::Wait);
        assert!(!r.is_waiting());
        assert_eq!(r.poll(true, 0), Exp100Action::Wait);
        assert!(r.is_waiting());

        // A 100 response releases the held body.
        r.got100();
        assert!(!r.is_waiting());
        assert_eq!(r.state(), Exp100::SendData);
    }

    #[test]
    fn exp100_reader_sends_anyway_after_timeout() {
        let mut r = Exp100Reader::new(1000);
        // Enter the waiting state at t=0.
        assert_eq!(r.poll(true, 0), Exp100Action::Wait);
        assert!(r.is_waiting());
        // Still within the timeout window → keep waiting.
        assert_eq!(r.poll(true, 500), Exp100Action::Wait);
        // Past the timeout → send the body anyway.
        assert_eq!(r.poll(true, 1500), Exp100Action::PassThrough);
        assert!(!r.is_waiting());
    }

    // ---- Authentication --------------------------------------------------

    #[test]
    fn input_auth_detects_schemes() {
        let mut avail = CURLAUTH_NONE;
        let detected = http_input_auth("Basic realm=\"x\", Digest realm=\"y\"", &mut avail);
        assert_ne!(detected & CURLAUTH_BASIC, 0);
        assert_ne!(detected & CURLAUTH_DIGEST, 0);
        assert_eq!(avail, detected);

        // Negotiate must not be confused with a longer token.
        let mut avail2 = CURLAUTH_NONE;
        let d2 = http_input_auth("Negotiate", &mut avail2);
        assert_eq!(d2, CURLAUTH_NEGOTIATE);
    }

    #[test]
    fn pick_one_auth_prefers_strongest() {
        // Digest beats Basic when both are offered.
        let (picked, ok) = pick_one_auth(
            CURLAUTH_BASIC | CURLAUTH_DIGEST,
            CURLAUTH_BASIC | CURLAUTH_DIGEST,
            !0,
        );
        assert!(ok);
        assert_eq!(picked, CURLAUTH_DIGEST);

        // Only Basic available → Basic.
        let (picked, ok) = pick_one_auth(CURLAUTH_BASIC | CURLAUTH_DIGEST, CURLAUTH_BASIC, !0);
        assert!(ok);
        assert_eq!(picked, CURLAUTH_BASIC);

        // Nothing available → sentinel.
        let (picked, ok) = pick_one_auth(CURLAUTH_BASIC, CURLAUTH_NONE, !0);
        assert!(!ok);
        assert_eq!(picked, CURLAUTH_PICKNONE);
    }

    #[test]
    fn should_fail_logic() {
        let base = ShouldFailInput {
            fail_on_error: true,
            httpcode: 404,
            resume_from: false,
            httpreq: HttpReq::Get,
            have_user: false,
            have_proxy_creds: false,
            authproblem: false,
        };
        // 404 with failonerror → fail.
        assert!(http_should_fail(&base));
        // Below 400 → never fail.
        assert!(!http_should_fail(&ShouldFailInput {
            httpcode: 200,
            ..base
        }));
        // failonerror off → never fail.
        assert!(!http_should_fail(&ShouldFailInput {
            fail_on_error: false,
            ..base
        }));
        // 401 without credentials → fail.
        assert!(http_should_fail(&ShouldFailInput {
            httpcode: 401,
            ..base
        }));
        // 416 on a resumed GET → success.
        assert!(!http_should_fail(&ShouldFailInput {
            httpcode: 416,
            resume_from: true,
            ..base
        }));
    }

    fn basic_ctx() -> AuthOutputCtx<'static> {
        AuthOutputCtx {
            request: "GET",
            path: "/",
            user: Some("user"),
            passwd: Some("pass"),
            bearer_token: Some("tok"),
            ..AuthOutputCtx::default()
        }
    }

    #[test]
    fn output_auth_emits_basic() {
        let ctx = basic_ctx();
        let mut st = AuthState::default();
        let mut out = String::new();
        let picked = output_auth_headers(CURLAUTH_BASIC, false, &ctx, &mut st, &mut out).unwrap();
        assert_eq!(picked, PickedAuth::Basic);
        assert!(out.starts_with("Authorization: Basic "));
        assert!(out.ends_with("\r\n"));
        assert!(st.done);
    }

    #[test]
    fn output_auth_emits_bearer() {
        let ctx = basic_ctx();
        let mut st = AuthState::default();
        let mut out = String::new();
        let picked = output_auth_headers(CURLAUTH_BEARER, false, &ctx, &mut st, &mut out).unwrap();
        assert_eq!(picked, PickedAuth::Bearer);
        assert_eq!(out, "Authorization: Bearer tok\r\n");
        assert!(st.done);
    }

    #[test]
    fn output_auth_delegates_complex_mechanisms() {
        let ctx = basic_ctx();
        let mut out = String::new();

        // Digest/NTLM/Negotiate return delegation descriptors, emitting nothing.
        for (bit, expect) in [
            (CURLAUTH_DIGEST, PickedAuth::Digest),
            (CURLAUTH_NTLM, PickedAuth::Ntlm),
            (CURLAUTH_NEGOTIATE, PickedAuth::Negotiate),
        ] {
            let mut st = AuthState::default();
            out.clear();
            let picked = output_auth_headers(bit, false, &ctx, &mut st, &mut out).unwrap();
            assert_eq!(picked, expect);
            assert!(out.is_empty());
        }

        // AWS SigV4 is host-only: selected for host, suppressed for a proxy.
        let mut st = AuthState::default();
        out.clear();
        assert_eq!(
            output_auth_headers(CURLAUTH_AWS_SIGV4, false, &ctx, &mut st, &mut out).unwrap(),
            PickedAuth::AwsSigV4
        );
        let mut st2 = AuthState::default();
        assert_eq!(
            output_auth_headers(CURLAUTH_AWS_SIGV4, true, &ctx, &mut st2, &mut out).unwrap(),
            PickedAuth::None
        );
    }

    #[test]
    fn auth_act_fails_terminal_status() {
        let input = AuthActInput {
            httpcode: 404,
            authneg: false,
            have_user: false,
            have_bearer: false,
            have_proxy_creds: false,
            httpversion: 11,
            fail_on_error: true,
            resume_from: false,
            httpreq: HttpReq::Get,
            authproblem: false,
        };
        let mut host = AuthState::default();
        let mut proxy = AuthState::default();
        let err = http_auth_act(&input, &mut host, &mut proxy).unwrap_err();
        assert_eq!(err.code(), CurlCode::HttpReturnedError);
    }

    #[test]
    fn auth_act_picks_host_mechanism_on_401() {
        let input = AuthActInput {
            httpcode: 401,
            authneg: false,
            have_user: true,
            have_bearer: false,
            have_proxy_creds: false,
            httpversion: 11,
            fail_on_error: false,
            resume_from: false,
            httpreq: HttpReq::Get,
            authproblem: false,
        };
        let mut host = AuthState {
            want: CURLAUTH_BASIC | CURLAUTH_DIGEST,
            avail: CURLAUTH_BASIC | CURLAUTH_DIGEST,
            ..AuthState::default()
        };
        let mut proxy = AuthState::default();
        let outcome = http_auth_act(&input, &mut host, &mut proxy).unwrap();
        assert!(outcome.retry);
        assert_eq!(outcome.host_picked, CURLAUTH_DIGEST);
    }

    // ---- Status-line effects & sizing -----------------------------------

    #[test]
    fn statusline_validation_and_bodyless() {
        // A normal 200 keeps a body.
        let mut st = StatusLineState {
            httpversion: 11,
            httpcode: 200,
            ..StatusLineState::default()
        };
        http_statusline(&mut st).unwrap();
        assert!(!st.http_bodyless);
        assert_eq!(st.httpversion_seen, 11);

        // 204 is body-less.
        let mut st = StatusLineState {
            httpversion: 11,
            httpcode: 204,
            ..StatusLineState::default()
        };
        http_statusline(&mut st).unwrap();
        assert!(st.http_bodyless);
        assert_eq!(st.size, 0);

        // HTTP/1.0 forces close-after-body.
        let mut st = StatusLineState {
            httpversion: 10,
            httpcode: 200,
            ..StatusLineState::default()
        };
        http_statusline(&mut st).unwrap();
        assert!(st.close_after_body);
    }

    #[test]
    fn statusline_rejects_bad_versions() {
        // Unsupported version.
        let mut st = StatusLineState {
            httpversion: 99,
            httpcode: 200,
            ..StatusLineState::default()
        };
        assert!(matches!(
            http_statusline(&mut st),
            Err(Error::UnsupportedProtocol)
        ));

        // Mid-connection major-version switch.
        let mut st = StatusLineState {
            httpversion: 20,
            httpversion_sent: 11,
            httpcode: 200,
            ..StatusLineState::default()
        };
        assert_eq!(
            http_statusline(&mut st).unwrap_err().code(),
            CurlCode::WeirdServerReply
        );
    }

    #[test]
    fn http_size_resolution() {
        // Known length within limits.
        let out = http_size(&SizeInput {
            ignore_cl: false,
            chunk: false,
            size: 1000,
            max_filesize: 0,
            ignorebody: false,
        })
        .unwrap();
        assert_eq!(out.size, 1000);
        assert_eq!(out.maxdownload, 1000);

        // Chunked → size unknown.
        let out = http_size(&SizeInput {
            ignore_cl: false,
            chunk: true,
            size: 1000,
            max_filesize: 0,
            ignorebody: false,
        })
        .unwrap();
        assert_eq!(out.size, -1);

        // Over the max file size → error.
        let err = http_size(&SizeInput {
            ignore_cl: false,
            chunk: false,
            size: 2000,
            max_filesize: 1000,
            ignorebody: false,
        })
        .unwrap_err();
        assert_eq!(err.code(), CurlCode::FilesizeExceeded);
    }

    // ---- Response header classification ---------------------------------

    #[test]
    fn classify_headers() {
        assert_eq!(
            classify_response_header("Location: http://x/"),
            ResponseHeader::Location("http://x/".to_string())
        );
        assert_eq!(
            classify_response_header("Set-Cookie: a=b"),
            ResponseHeader::SetCookie("a=b".to_string())
        );
        assert_eq!(
            classify_response_header("Content-Length: 42"),
            ResponseHeader::ContentLength("42".to_string())
        );
        assert_eq!(
            classify_response_header("Connection: close"),
            ResponseHeader::ConnectionClose
        );
        assert_eq!(
            classify_response_header("WWW-Authenticate: Basic realm=\"x\""),
            ResponseHeader::WwwAuthenticate("Basic realm=\"x\"".to_string())
        );
        // Case-insensitive field name.
        assert_eq!(
            classify_response_header("transfer-encoding: chunked"),
            ResponseHeader::TransferEncoding("chunked".to_string())
        );
        // Unrecognized header.
        assert_eq!(
            classify_response_header("X-Custom: value"),
            ResponseHeader::Other
        );
    }

    // ---- Version banner --------------------------------------------------

    #[test]
    fn version_helpers() {
        assert!(version_banner().starts_with("curl-rs/8.19.0-DEV"));
        assert!(version_banner().contains("rustls"));
        assert_eq!(default_user_agent(), "curl-rs/8.19.0-DEV");
    }

    // ---- Protocol trait wiring ------------------------------------------

    #[test]
    fn handler_protocol_methods_drive() {
        // The DO phase requires a connection to be assigned to the transfer
        // (curl's `data->conn`); with none present it surfaces the same
        // precondition error curl returns when the protocol layer is reached
        // without a connection. The full happy path is covered end-to-end by
        // `do_it_drives_http1_get_over_filter_chain` below.
        let mut ctx = TransferCtx::default();
        let err = block_on(HANDLER.do_it(&mut ctx)).unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);

        // DONE tears down cleanly even with no connection assigned.
        let mut ctx = TransferCtx::default();
        block_on(HANDLER.done(&mut ctx, Ok(()), false)).unwrap();

        // The exported const handler is equivalent.
        assert_eq!(HTTP_HANDLER, HANDLER);
    }

    // ---- Version selection ----------------------------------------------

    #[test]
    fn select_version_honours_prior_knowledge_and_alpn() {
        // HTTP/2 prior knowledge forces 2 even over cleartext with no ALPN.
        let mut neg = HttpNegotiation::default();
        neg.http_neg_init(HttpWant::None, false);
        neg.h2_prior_knowledge = true;
        let conn = Connection::new(Scheme::new("http", 80), "127.0.0.1", 80);
        assert_eq!(select_http_version(&conn, &neg), 20);

        // Without prior knowledge and no negotiated version, cleartext HTTP
        // defaults to 1.1 (the `_` dispatch arm → `h1::perform`).
        let mut neg = HttpNegotiation::default();
        neg.http_neg_init(HttpWant::None, false);
        let conn = Connection::new(Scheme::new("http", 80), "127.0.0.1", 80);
        assert_eq!(select_http_version(&conn, &neg), 11);

        // The ALPN → wire-version mapping the selector applies to a negotiated
        // "h3" token yields HTTP/3 (the `version == 30` dispatch arm).
        assert_eq!(alpn_to_http_version(AlpnProtocol::from_wire(b"h3")), 30);
        assert_eq!(alpn_to_http_version(AlpnProtocol::from_wire(b"h2")), 20);
    }

    #[test]
    fn resolve_h3_addr_requires_resolved_ip_literal() {
        // A resolved IP-literal host parses to a concrete peer address.
        let conn = Connection::new(Scheme::new("https", 443), "127.0.0.1", 443);
        let addr = resolve_h3_addr(&conn).expect("IP literal resolves");
        assert_eq!(addr.port(), 443);
        assert!(addr.ip().is_loopback());

        // A named host has no literal address; resolution is owned by the
        // connection/DNS layer, so the handler surfaces COULDNT_RESOLVE_HOST.
        let conn = Connection::new(Scheme::new("https", 443), "example.com", 443);
        let err = resolve_h3_addr(&conn).unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntResolveHost);
    }

    // ---- do_it end-to-end over a real FilterChain -----------------------

    /// A leaf [`ConnectionFilter`] wrapping a pre-connected `TcpStream`, letting
    /// `do_it` drive a *real* [`FilterChain`] end-to-end using only whitelisted
    /// `conn` types (mirrors h1's `MockTcpFilter`).
    struct MockTcpFilter {
        stream: Option<tokio::net::TcpStream>,
    }

    impl ConnectionFilter for MockTcpFilter {
        fn name(&self) -> &'static str {
            "MOCK-TCP"
        }

        fn cf_type(&self) -> CfType {
            CfType::IP_CONNECT
        }

        fn connect<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            _blocking: bool,
        ) -> CfFuture<'a, Result<bool>> {
            Box::pin(async move { Ok(self.stream.is_some()) })
        }

        fn send<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a [u8],
            _eos: bool,
        ) -> CfFuture<'a, Result<usize>> {
            Box::pin(async move {
                use tokio::io::AsyncWriteExt;
                let s = self.stream.as_mut().ok_or(Error::Send)?;
                s.write_all(buf).await.map_err(|_| Error::Send)?;
                Ok(buf.len())
            })
        }

        fn recv<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a mut [u8],
        ) -> CfFuture<'a, Result<usize>> {
            Box::pin(async move {
                use tokio::io::AsyncReadExt;
                let s = self.stream.as_mut().ok_or(Error::Recv)?;
                s.read(buf).await.map_err(|_| Error::Recv)
            })
        }
    }

    /// A shared-buffer [`TransferSink`] recording every delivered body chunk.
    struct RecordingSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl crate::protocols::TransferSink for RecordingSink {
        fn write(&mut self, data: &[u8]) -> Result<()> {
            self.0.lock().expect("sink lock").extend_from_slice(data);
            Ok(())
        }
    }

    /// The whole `HttpHandler` lifecycle drives a real HTTP/1.1 GET end-to-end:
    /// `setup_connection` seeds the negotiation, `do_it` builds the request,
    /// selects HTTP/1.1 over the cleartext connection, drives `h1::perform`
    /// over the primary filter chain, streams the response body to the sink,
    /// and records the status code and content type into `ctx.info`. This is
    /// the decisive proof the handler is no longer a no-op placeholder
    /// (review finding: HttpHandler no-op placeholders).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn do_it_drives_http1_get_over_filter_chain() {
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Read the request head (GET has no body).
            let mut buf = [0u8; 4096];
            let mut data = Vec::new();
            while !data.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
            }
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\
                  Connection: close\r\n\r\nhello",
            )
            .await
            .unwrap();
            let _ = sock.shutdown().await;
            data
        });

        // Connect the client socket and wrap it in a mock leaf filter so the
        // handler drives a real FilterChain.
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(MockTcpFilter {
            stream: Some(stream),
        }));
        let mut conn = Connection::new(Scheme::new("http", 80), "127.0.0.1", addr.port());
        conn.cfilter[FIRSTSOCKET] = Some(chain);

        // Build the transfer context: request options, the connection, and a
        // recording sink for the response body.
        let collected = Arc::new(Mutex::new(Vec::new()));
        let mut ctx = TransferCtx::new();
        ctx.request.scheme = "http".to_string();
        ctx.request.host = "127.0.0.1".to_string();
        ctx.request.port = addr.port();
        ctx.request.path = "/e2e".to_string();
        ctx.request.method = "GET".to_string();
        ctx.conn = Some(Box::new(conn));
        ctx.sink = Some(Box::new(RecordingSink(Arc::clone(&collected))));

        // Faithful lifecycle: setup_connection then do_it.
        HANDLER.setup_connection(&mut ctx).await.unwrap();
        let done = HANDLER
            .do_it(&mut ctx)
            .await
            .expect("do_it drives the HTTP/1.1 exchange");
        assert!(done, "HTTP do_it reports the DO phase complete in one step");

        // The request reached the server as a GET on the requested path.
        let captured = srv.await.unwrap();
        assert!(captured.starts_with(b"GET /e2e HTTP/1.1\r\n"));

        // The response body was streamed to the sink and diagnostics recorded.
        assert_eq!(collected.lock().expect("sink").as_slice(), b"hello");
        assert_eq!(ctx.info.httpcode, 200);
        assert_eq!(ctx.info.contenttype.as_deref(), Some("text/plain"));
    }

    // ---- Expect: 100-continue over the do_it exchange -------------------

    /// Drive an HTTP/1.1 `POST` end-to-end through `do_it` over a real
    /// `FilterChain`, returning the request head the mock server received. The
    /// server reads the full request (head + `body.len()` bytes) before
    /// replying, so the client's send always completes — hyper's low-level
    /// client sends the body without waiting for a `100` (the `expect_continue`
    /// gate is server-side only), so no announcement can deadlock this exchange.
    async fn post_and_capture_request_head(body: Vec<u8>) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let body_len = body.len();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8192];
            let mut data = Vec::new();
            // Read through the head terminator, then capture the head.
            let head_end = loop {
                if let Some(p) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    break p + 4;
                }
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break data.len();
                }
                data.extend_from_slice(&buf[..n]);
            };
            let head = data[..head_end].to_vec();
            // Drain the declared body so the client's send completes.
            while data.len() < head_end + body_len {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
            }
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let _ = sock.shutdown().await;
            head
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(MockTcpFilter {
            stream: Some(stream),
        }));
        let mut conn = Connection::new(Scheme::new("http", 80), "127.0.0.1", addr.port());
        conn.cfilter[FIRSTSOCKET] = Some(chain);

        let mut ctx = TransferCtx::new();
        ctx.request.scheme = "http".to_string();
        ctx.request.host = "127.0.0.1".to_string();
        ctx.request.port = addr.port();
        ctx.request.path = "/upload".to_string();
        ctx.request.method = "POST".to_string();
        ctx.request.upload = true;
        ctx.request.body = Some(body);
        ctx.conn = Some(Box::new(conn));

        HANDLER.setup_connection(&mut ctx).await.unwrap();
        let done = HANDLER
            .do_it(&mut ctx)
            .await
            .expect("do_it drives the HTTP/1.1 POST");
        assert!(done, "HTTP do_it reports the DO phase complete in one step");

        srv.await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn do_it_emits_expect_100_for_large_upload() {
        // Regression for the Expect: 100-continue wiring (QA F3-H1-002). A POST
        // whose body exceeds EXPECT_100_THRESHOLD must announce
        // `Expect: 100-continue` on the wire, matching curl's `addexpect` for
        // large uploads. Before the fix the header was never emitted.
        let head =
            post_and_capture_request_head(vec![b'x'; EXPECT_100_THRESHOLD as usize + 1]).await;
        let lower = String::from_utf8_lossy(&head).to_ascii_lowercase();
        assert!(
            lower.contains("expect: 100-continue"),
            "large upload must announce Expect: 100-continue; head was:\n{}",
            String::from_utf8_lossy(&head)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn do_it_omits_expect_100_for_small_upload() {
        // The complement: a small POST body (below the threshold) must NOT
        // announce Expect, so small uploads pay no extra round-trip (curl skips
        // Expect for small PUT/POST — `addexpect`).
        let head = post_and_capture_request_head(vec![b'x'; 16]).await;
        let lower = String::from_utf8_lossy(&head).to_ascii_lowercase();
        assert!(
            !lower.contains("expect:"),
            "small upload must NOT announce Expect; head was:\n{}",
            String::from_utf8_lossy(&head)
        );
    }
}
