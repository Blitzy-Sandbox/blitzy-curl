// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP proxy request handling (← `lib/http_proxy.c` + `lib/http_proxy.h`).
//!
//! This module is the Rust port of curl's **generic HTTP-proxy layer**. It owns
//! the parts of `http_proxy.c` that build proxy *requests* and answer
//! proxy-related connection-filter queries:
//!
//! * [`create_connect`] — build the `CONNECT` request used to establish a
//!   tunnel (← `Curl_http_proxy_create_CONNECT`), byte-for-byte identical to
//!   curl 8.x including header ordering and IPv6 authority bracketing.
//! * [`get_destination`] — resolve the tunnel destination host/port
//!   (← `Curl_http_proxy_get_destination`).
//! * [`HttpProxyFilter`] / [`insert_after`] / [`HttpProxyFilter::query`] — the
//!   generic http-proxy connection filter and its dispatch
//!   (← `Curl_cft_http_proxy` / `Curl_cf_http_proxy_insert_after` /
//!   `Curl_cf_http_proxy_query`).
//! * [`select_tunnel_backend`] + [`install_h1_tunnel`] / [`install_h2_tunnel`]
//!   — the ALPN-driven choice between the HTTP/1.x and HTTP/2 tunnel drivers
//!   (← the ALPN switch inside `http_proxy_cf_connect`).
//! * [`proxy_http_target`] — the absolute-form request-target used for a
//!   *non-tunnel* forward proxy (← curl's `http_target` proxy branch).
//!
//! # Scope boundary
//!
//! curl splits proxy code across three C files mapped to three Rust files owned
//! by different layers. This module is **only** the generic layer
//! (`http_proxy.c`). The byte-level `CONNECT` tunnel state machines live in the
//! connection layer:
//!
//! * HTTP/1.x tunnel: [`crate::conn::h1_proxy`] (← `lib/cf-h1-proxy.c`).
//! * HTTP/2 tunnel: [`crate::conn::h2_proxy`] (← `lib/cf-h2-proxy.c`).
//!
//! **Call-direction inversion.** In C, `cf-h1-proxy.c` calls *up* into
//! `http_proxy.c`'s `Curl_http_proxy_create_CONNECT`. In this workspace the
//! `conn` layer must not depend on `protocols` (that would create an import
//! cycle), so the arrow is inverted: `protocols` depends on `conn`. Concretely,
//! [`crate::conn::h1_proxy`] and [`crate::conn::h2_proxy`] each build their own
//! `CONNECT` request internally from a small self-contained config, and this
//! module *delegates* the actual tunnel to them ([`install_h1_tunnel`] /
//! [`install_h2_tunnel`]) rather than re-implementing the state machines here.
//! [`create_connect`] remains the canonical, wire-parity `CONNECT` builder used
//! for the neutral [`HttpReqData`] representation and for parity testing.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe`; the crate root's
//! `#![forbid(unsafe_code)]` turns any `unsafe` token into a hard compile error.
//! All async is Tokio-only, entering only through the delegated
//! [`crate::conn`] tunnel drivers.

use crate::auth;
use crate::conn::filters::{QueryCtx, QueryOut};
use crate::conn::{h1_proxy, h2_proxy};
use crate::conn::{
    CfQuery, CfType, Connection, ConnectionFilter, FilterChain, ProxyType, SECONDARYSOCKET,
};
use crate::error::{CurlCode, Error, Result};
use crate::protocols::http::{
    self, AuthOutputCtx, AuthState, CustomHeadersInput, HttpReq, HttpReqData,
};

// ===========================================================================
// PHASE 1 — Types & constants (← `enum Curl_proxy_use`, `PROXY_TIMEOUT`,
// `IS_HTTPS_PROXY`, `lib/http_proxy.h`).
// ===========================================================================

/// Which set of user headers applies when emitting a request, and where the
/// request is going (← `enum Curl_proxy_use`, `lib/http_proxy.h`).
///
/// The variant order and meaning match curl's enum exactly so the header-list
/// selection logic can be reproduced verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyUse {
    /// `HEADER_SERVER` — the request goes directly to the origin server.
    HeaderServer,
    /// `HEADER_PROXY` — a regular (non-tunnel) request forwarded to a proxy.
    HeaderProxy,
    /// `HEADER_CONNECT` — a `CONNECT` request sent to a proxy to open a tunnel.
    HeaderConnect,
}

impl ProxyUse {
    /// Classify the applicable [`ProxyUse`] exactly as curl's
    /// `dynhds_add_custom` does: `HEADER_CONNECT` when building the tunnel
    /// request, otherwise `HEADER_PROXY` for a non-tunnel proxy request and
    /// `HEADER_SERVER` for a direct-to-origin request.
    #[must_use]
    pub fn classify(is_connect: bool, httpproxy: bool, tunnel_proxy: bool) -> ProxyUse {
        if is_connect {
            ProxyUse::HeaderConnect
        } else if httpproxy && !tunnel_proxy {
            ProxyUse::HeaderProxy
        } else {
            ProxyUse::HeaderServer
        }
    }
}

/// The default proxy timeout in milliseconds (← `#define PROXY_TIMEOUT
/// (3600 * 1000)`, `lib/http_proxy.h`): one hour.
pub const PROXY_TIMEOUT_MS: u64 = 3600 * 1000;

/// Whether a proxy type denotes an HTTPS (TLS-wrapped) proxy
/// (← `#define IS_HTTPS_PROXY(t)`, `lib/http_proxy.h`): true for
/// [`ProxyType::Https`] (`CURLPROXY_HTTPS`) and [`ProxyType::Https2`]
/// (`CURLPROXY_HTTPS2`).
#[must_use]
pub fn is_https_proxy(t: ProxyType) -> bool {
    matches!(t, ProxyType::Https | ProxyType::Https2)
}

// ===========================================================================
// PHASE 3 — Tunnel destination + CONNECT request construction
// (← `Curl_http_proxy_get_destination`, `Curl_http_proxy_create_CONNECT`).
// ===========================================================================

/// Resolve the destination the `CONNECT` tunnel must reach: the host name, the
/// port, and whether the host is an IPv6 literal
/// (← `Curl_http_proxy_get_destination`, `lib/http_proxy.c:165`).
///
/// The selection follows curl exactly:
///
/// * **host** — the `--connect-to` host override when
///   [`ConnectBits::conn_to_host`](crate::conn::ConnectBits::conn_to_host) is
///   set, else the secondary-socket host on [`SECONDARYSOCKET`], else the
///   primary destination host.
/// * **port** — the secondary port on [`SECONDARYSOCKET`], else the
///   `--connect-to` port override when
///   [`ConnectBits::conn_to_port`](crate::conn::ConnectBits::conn_to_port) is
///   set, else the remote port.
/// * **ipv6_ip** — when the chosen host is *not* the primary destination host
///   it is inspected for a `:` (an IPv6 literal); otherwise curl's precomputed
///   [`ConnectBits::ipv6_ip`](crate::conn::ConnectBits::ipv6_ip) flag is used.
///
/// `sockindex` is the connection socket the tunnel is being built for
/// ([`crate::conn::FIRSTSOCKET`] or [`SECONDARYSOCKET`]).
#[must_use]
pub fn get_destination(conn: &Connection, sockindex: usize) -> (String, u16, bool) {
    // Mirror the C pointer comparison `*phostname != cf->conn->host.name` by
    // tracking which source the host name came from rather than string-
    // comparing (two distinct sources could hold equal strings).
    let (hostname, from_primary_host): (&str, bool) = if conn.bits.conn_to_host {
        (
            conn.conn_to_host.as_ref().map_or("", |h| h.name.as_str()),
            false,
        )
    } else if sockindex == SECONDARYSOCKET {
        (conn.secondaryhostname.as_deref().unwrap_or(""), false)
    } else {
        (conn.host.name.as_str(), true)
    };

    let port: u16 = if sockindex == SECONDARYSOCKET {
        conn.secondary_port
    } else if conn.bits.conn_to_port {
        conn.conn_to_port.unwrap_or(conn.remote_port)
    } else {
        conn.remote_port
    };

    let ipv6_ip = if from_primary_host {
        conn.bits.ipv6_ip
    } else {
        hostname.contains(':')
    };

    (hostname.to_owned(), port, ipv6_ip)
}

/// The per-request inputs [`create_connect`] reads from the easy handle
/// (`struct Curl_easy *data`) — the `data->set` / `data->state` fields that
/// `Curl_http_proxy_create_CONNECT` touches — gathered into one explicit,
/// borrow-checked value so the builder is self-contained and testable (the same
/// approach the [`crate::conn::h1_proxy`] / [`crate::conn::h2_proxy`] filters
/// take with their configs).
#[derive(Clone, Copy, Debug)]
pub struct ConnectRequestCtx<'a> {
    /// The `CURLOPT_USERAGENT` value (`data->set.str[STRING_USERAGENT]`); a
    /// `None` or empty string omits the `User-Agent` header, matching curl's
    /// `... && *data->set.str[STRING_USERAGENT]` guard.
    pub user_agent: Option<&'a str>,
    /// The authentication inputs forwarded to
    /// [`http_output_auth`](crate::protocols::http::http_output_auth) to emit
    /// `Proxy-Authorization` (proxy credentials, bearer token, and the
    /// user-supplied-header guards). The `request`/`path` fields are overridden
    /// internally to the `CONNECT` method and the computed authority, exactly
    /// as curl passes `req->method` / `req->authority`.
    pub auth: AuthOutputCtx<'a>,
    /// The custom-header selection inputs forwarded to
    /// [`dynhds_add_custom`](crate::protocols::http::dynhds_add_custom) for the
    /// proxy headers carried on the `CONNECT` request.
    pub custom_headers: CustomHeadersInput<'a>,
    /// The negotiated HTTP version of the sub-transport that will carry the
    /// tunnel (curl's `ctx->httpversion`), used by `dynhds_add_custom` to
    /// suppress `Transfer-Encoding` on HTTP/2+.
    pub sub_httpversion: i32,
}

/// Split a single serialized header line `"Name: value"` into its trimmed name
/// and value (← the parsing `Curl_dynhds_h1_cadd_line` performs on
/// `data->state.aptr.proxyuserpwd`).
///
/// The split is on the first `:` only — a Base64 credential value never
/// contains one — and leading blanks are stripped from the value. Returns
/// `None` for a line with no colon.
fn split_header_line(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once(':')?;
    Some((name.trim(), value.trim_matches(|c| c == ' ' || c == '\t')))
}

/// Build the `CONNECT` request that establishes an HTTP proxy tunnel
/// (← `Curl_http_proxy_create_CONNECT`, `lib/http_proxy.c:197`).
///
/// The returned [`HttpReqData`] carries the method (`CONNECT`), the authority
/// (`host:port`, IPv6-bracketed), and the header block **in the exact order
/// curl emits it on the wire** — which is behaviorally significant and
/// test-verified:
///
/// 1. `Host: <authority>` — for HTTP/1.x only, unless the user overrode it.
/// 2. `Proxy-Authorization: …` — from
///    [`http_output_auth`](crate::protocols::http::http_output_auth) (curl's
///    `data->state.aptr.proxyuserpwd`), when proxy credentials produce one.
/// 3. `User-Agent: …` — unless overridden and only when non-empty.
/// 4. `Proxy-Connection: Keep-Alive` — for HTTP/1.x only, unless overridden.
/// 5. any user-supplied proxy headers, via
///    [`dynhds_add_custom`](crate::protocols::http::dynhds_add_custom).
///
/// `http_version_major` is the major version curl will speak to the proxy
/// (`1` for HTTP/1.x; `2` for HTTP/2, which omits the `Host`/`Proxy-Connection`
/// connection-specific fields). `proxy_auth` is the proxy-side authentication
/// state, advanced across the `407` retry rounds. Host authentication is never
/// emitted on the tunnel request (curl only sends it once the tunnel is open),
/// so `host_auth_allowed` is fixed to `false` here.
///
/// # Errors
///
/// Propagates any [`Error`] from the auth or custom-header emitters (both
/// effectively infallible in this port; the `Result` preserves curl's
/// signature).
pub fn create_connect(
    conn: &Connection,
    sockindex: usize,
    http_version_major: i32,
    ctx: &ConnectRequestCtx<'_>,
    proxy_auth: &mut AuthState,
) -> Result<HttpReqData> {
    let (hostname, port, ipv6_ip) = get_destination(conn, sockindex);

    // curl: curl_maprintf("%s%s%s:%d", ipv6?"[":"" , host, ipv6?"]":"", port).
    let authority = if ipv6_ip {
        format!("[{hostname}]:{port}")
    } else {
        format!("{hostname}:{port}")
    };

    // Method CONNECT with the authority set; no scheme and no path
    // (← Curl_http_req_make(&req, "CONNECT", …, authority, …, NULL, 0)).
    let mut req = HttpReqData::make("CONNECT", None, Some(&authority), None);

    // Compute the Proxy-Authorization header (← Curl_http_output_auth with
    // proxytunnel = TRUE). The proxy Basic line, if any, lands in `auth_out`;
    // Digest/NTLM/Negotiate are multi-pass and are driven by the h1/h2 tunnel
    // state machine, so nothing is emitted for them here. Host auth is never
    // carried on the tunnel request.
    let mut auth_ctx = ctx.auth;
    auth_ctx.request = "CONNECT";
    let mut auth_out = String::new();
    let mut host_auth = AuthState::default();
    http::http_output_auth(
        &auth_ctx,
        HttpReq::Get,
        /* proxytunnel = */ true,
        /* httpproxy = */ conn.bits.httpproxy,
        /* tunnel_proxy = */ conn.bits.tunnel_proxy,
        /* host_auth_allowed = */ false,
        &mut host_auth,
        proxy_auth,
        &mut auth_out,
    )?;

    // The proxy header list curl checks for user overrides
    // (← Curl_checkProxyheaders): the separate proxy list when configured,
    // otherwise the normal custom-header list.
    let proxy_hdrs: &[String] = if ctx.custom_headers.sep_headers {
        ctx.custom_headers.proxy_headers
    } else {
        ctx.custom_headers.server_headers
    };

    // (1) Host — HTTP/1.x only, unless the user supplied their own.
    if http_version_major == 1 && http::check_proxy_headers(proxy_hdrs, "Host").is_none() {
        req.headers.add("Host", authority.clone());
    }

    // (2) Proxy-Authorization — the line(s) produced by http_output_auth
    // (← adding data->state.aptr.proxyuserpwd to the request headers).
    for line in auth_out.split("\r\n").filter(|l| !l.is_empty()) {
        if let Some((name, value)) = split_header_line(line) {
            req.headers.add(name, value);
        }
    }

    // (3) User-Agent — unless overridden and only when set and non-empty.
    if http::check_proxy_headers(proxy_hdrs, "User-Agent").is_none() {
        if let Some(ua) = ctx.user_agent {
            if !ua.is_empty() {
                req.headers.add("User-Agent", ua);
            }
        }
    }

    // (4) Proxy-Connection: Keep-Alive — HTTP/1.x only, unless overridden.
    if http_version_major == 1
        && http::check_proxy_headers(proxy_hdrs, "Proxy-Connection").is_none()
    {
        req.headers.add("Proxy-Connection", "Keep-Alive");
    }

    // (5) Any user-supplied proxy headers on the CONNECT request
    // (← dynhds_add_custom(data, TRUE, ctx->httpversion, &req->headers)).
    http::dynhds_add_custom(
        &ctx.custom_headers,
        /* is_connect = */ true,
        ctx.sub_httpversion,
        &mut req.headers,
    )?;

    Ok(req)
}

// ===========================================================================
// PHASE 4 — Generic http-proxy filter dispatch
// (← `Curl_cft_http_proxy`, `Curl_cf_http_proxy_insert_after`,
// `Curl_cf_http_proxy_query`, and the ALPN switch in `http_proxy_cf_connect`).
// ===========================================================================

/// The tunnel driver selected from the ALPN the proxy negotiated on its
/// connection (← the ALPN `switch` in `http_proxy_cf_connect`,
/// `lib/http_proxy.c:293`).
///
/// A plain HTTP proxy advertises no ALPN and always uses HTTP/1.1; an HTTPS
/// proxy may negotiate `http/1.0`, `http/1.1`, or `h2` during its TLS
/// handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelBackend {
    /// HTTP/1.0 tunnel (ALPN `http/1.0`) — driven by [`crate::conn::h1_proxy`].
    H1_0,
    /// HTTP/1.1 tunnel (no ALPN, or ALPN `http/1.1`) — driven by
    /// [`crate::conn::h1_proxy`].
    H1_1,
    /// HTTP/2 tunnel (ALPN `h2`) — driven by [`crate::conn::h2_proxy`].
    H2,
}

impl TunnelBackend {
    /// The curl `httpversion` integer this backend records on the proxy filter
    /// (`10`, `11`, or `20`), matching the values assigned in
    /// `http_proxy_cf_connect`.
    #[must_use]
    pub fn httpversion(self) -> i32 {
        match self {
            TunnelBackend::H1_0 => 10,
            TunnelBackend::H1_1 => 11,
            TunnelBackend::H2 => 20,
        }
    }

    /// Whether this backend is served by the HTTP/2 tunnel driver
    /// ([`crate::conn::h2_proxy`]); the HTTP/1.x variants use
    /// [`crate::conn::h1_proxy`].
    #[must_use]
    pub fn is_h2(self) -> bool {
        matches!(self, TunnelBackend::H2)
    }
}

/// Choose the tunnel backend from the proxy connection's negotiated ALPN
/// (← the ALPN `switch` in `http_proxy_cf_connect`, `lib/http_proxy.c:293`).
///
/// `None` (no ALPN — a plain HTTP proxy or an ancient HTTPS proxy) and
/// `Some("http/1.1")` both select [`TunnelBackend::H1_1`]; `Some("http/1.0")`
/// selects [`TunnelBackend::H1_0`]; `Some("h2")` selects [`TunnelBackend::H2`].
///
/// # Errors
///
/// Any other ALPN yields an [`Error`] mapping to
/// [`CurlCode::CouldntConnect`] with curl's exact diagnostic text
/// (`"CONNECT: negotiated ALPN '…' not supported"`).
pub fn select_tunnel_backend(alpn: Option<&str>) -> Result<TunnelBackend> {
    match alpn {
        Some("http/1.0") => Ok(TunnelBackend::H1_0),
        None | Some("http/1.1") => Ok(TunnelBackend::H1_1),
        Some("h2") => Ok(TunnelBackend::H2),
        Some(other) => Err(Error::with_context(
            CurlCode::CouldntConnect,
            format!("CONNECT: negotiated ALPN '{other}' not supported"),
        )),
    }
}

/// The generic HTTP-proxy connection filter (← `struct Curl_cftype
/// Curl_cft_http_proxy`, `lib/http_proxy.c:395`).
///
/// This is the layer curl installs above the transport when a request must go
/// through an HTTP proxy. It carries the proxy endpoint so it can answer
/// [`CfQuery::HostPort`] and it masks the sub-transport's ALPN
/// ([`CfQuery::AlpnNegotiated`] answers "none"), exactly as
/// `Curl_cf_http_proxy_query` does. The actual tunnel bytes are carried by the
/// h1/h2 sub-filter installed beneath it (see [`install_h1_tunnel`] /
/// [`install_h2_tunnel`]); once that sub-filter is connected this layer is a
/// transparent pass-through, so it inherits the delegating default `connect`.
#[derive(Debug, Clone)]
pub struct HttpProxyFilter {
    /// The proxy host name reported by [`CfQuery::HostPort`]
    /// (← `cf->conn->http_proxy.host.name`).
    proxy_host: String,
    /// The proxy port reported by [`CfQuery::HostPort`]
    /// (← `cf->conn->http_proxy.port`).
    proxy_port: u16,
}

impl HttpProxyFilter {
    /// Create the generic http-proxy filter for the proxy endpoint
    /// `proxy_host:proxy_port`.
    #[must_use]
    pub fn new(proxy_host: impl Into<String>, proxy_port: u16) -> Self {
        HttpProxyFilter {
            proxy_host: proxy_host.into(),
            proxy_port,
        }
    }

    /// The proxy host this filter reports.
    #[must_use]
    pub fn proxy_host(&self) -> &str {
        &self.proxy_host
    }

    /// The proxy port this filter reports.
    #[must_use]
    pub fn proxy_port(&self) -> u16 {
        self.proxy_port
    }
}

impl ConnectionFilter for HttpProxyFilter {
    fn name(&self) -> &'static str {
        // ← Curl_cft_http_proxy.name.
        "HTTP-PROXY"
    }

    fn cf_type(&self) -> CfType {
        // ← CF_TYPE_IP_CONNECT | CF_TYPE_PROXY.
        CfType::IP_CONNECT | CfType::PROXY
    }

    fn query(&self, cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        // ← Curl_cf_http_proxy_query.
        match query {
            CfQuery::HostPort => {
                // Report the *proxy* endpoint, not the tunnel destination.
                *out = QueryOut::HostPort {
                    host: self.proxy_host.clone(),
                    port: self.proxy_port,
                };
                Ok(())
            }
            CfQuery::AlpnNegotiated => {
                // curl answers `*palpn = NULL` (no ALPN) and does not delegate:
                // the proxy tunnel is transparent and must not leak the
                // sub-transport's ALPN. `QueryOut::None` is that "no ALPN".
                *out = QueryOut::None;
                Ok(())
            }
            // Every other query travels on down the chain.
            _ => cx.query_next(query, out),
        }
    }
}

/// Insert the generic [`HttpProxyFilter`] into `chain` directly below the
/// filter at `at_index` (← `Curl_cf_http_proxy_insert_after`,
/// `lib/http_proxy.c:413`).
///
/// `proxy_host` / `proxy_port` are the proxy endpoint the filter reports for
/// [`CfQuery::HostPort`].
///
/// # Errors
///
/// Returns [`Error::bad_argument`] (via [`FilterChain::insert_after`]) when
/// `at_index` is out of range.
pub fn insert_after(
    chain: &mut FilterChain,
    at_index: usize,
    proxy_host: impl Into<String>,
    proxy_port: u16,
) -> Result<()> {
    chain.insert_after(
        at_index,
        Box::new(HttpProxyFilter::new(proxy_host, proxy_port)),
    )
}

/// Delegate an HTTP/1.x `CONNECT` tunnel to [`crate::conn::h1_proxy`]
/// (← `Curl_cf_h1_proxy_insert_after`), splicing its filter below `at_index`.
///
/// This is the generic layer's dispatch for [`TunnelBackend::H1_0`] /
/// [`TunnelBackend::H1_1`]; the HTTP/1.x tunnel byte-level state machine lives
/// entirely in the connection layer.
///
/// # Errors
///
/// Propagates [`Error::bad_argument`] when `at_index` is out of range.
pub fn install_h1_tunnel(
    chain: &mut FilterChain,
    at_index: usize,
    config: h1_proxy::H1ProxyConfig,
) -> Result<()> {
    h1_proxy::insert_after(chain, at_index, config)
}

/// Delegate an HTTP/2 `CONNECT` tunnel to [`crate::conn::h2_proxy`]
/// (← `Curl_cf_h2_proxy_insert_after`), splicing its filter below `at_index`
/// over the already-connected `transport`.
///
/// This is the generic layer's dispatch for [`TunnelBackend::H2`]; the HTTP/2
/// tunnel state machine (stream multiplexing, `407` re-issue, byte relay) lives
/// entirely in the connection layer.
///
/// # Errors
///
/// Propagates [`Error::bad_argument`] when `at_index` is out of range.
pub fn install_h2_tunnel<S>(
    chain: &mut FilterChain,
    at_index: usize,
    config: h2_proxy::H2ProxyConfig,
    transport: S,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    h2_proxy::insert_after(chain, at_index, config, transport)
}

/// Build the [`h1_proxy::H1ProxyConfig`](crate::conn::h1_proxy::H1ProxyConfig)
/// for tunnelling `conn`'s destination through its HTTP/1.x proxy.
///
/// The tunnel destination (`host`/`port`) is resolved via [`get_destination`]
/// and the proxy credentials are copied from `conn.http_proxy`. When
/// credentials are present the auth mask defaults to
/// [`auth::CURLAUTH_BASIC`](crate::auth::CURLAUTH_BASIC) and proactive auth is
/// enabled, mirroring curl's default of Basic for `--proxy-user`. `user_agent`
/// and any `extra_headers` are threaded through verbatim.
#[must_use]
pub fn h1_config_from(
    conn: &Connection,
    sockindex: usize,
    user_agent: Option<String>,
    extra_headers: Vec<(String, String)>,
) -> h1_proxy::H1ProxyConfig {
    let (host, port, _ipv6) = get_destination(conn, sockindex);
    let mut config = h1_proxy::H1ProxyConfig::new(host, port);
    config.http_1_0 = conn.http_proxy.proxytype == ProxyType::Http1_0;
    config.user_agent = user_agent;
    config.extra_headers = extra_headers;
    config.proxy_user = conn.http_proxy.user.clone();
    config.proxy_password = conn.http_proxy.passwd.clone();
    if conn.http_proxy.user.is_some() || conn.http_proxy.passwd.is_some() {
        config.want_auth = auth::CURLAUTH_BASIC;
        config.proactive_auth = true;
    }
    config
}

/// Build the [`h2_proxy::H2ProxyConfig`](crate::conn::h2_proxy::H2ProxyConfig)
/// for tunnelling `conn`'s destination through its HTTP/2 proxy.
///
/// The `CONNECT` `:authority` (`host`/`port`) is resolved via
/// [`get_destination`] and the proxy credentials are copied from
/// `conn.http_proxy`.
#[must_use]
pub fn h2_config_from(conn: &Connection, sockindex: usize) -> h2_proxy::H2ProxyConfig {
    let (host, port, _ipv6) = get_destination(conn, sockindex);
    h2_proxy::H2ProxyConfig::with_credentials(
        host,
        port,
        conn.http_proxy.user.clone(),
        conn.http_proxy.passwd.clone(),
    )
}

/// Build the absolute-form request-target sent to a **non-tunnel** forward
/// proxy (← curl's `http_target` proxy branch; the `HEADER_PROXY` case).
///
/// A request forwarded to a proxy (rather than tunnelled through it) uses the
/// absolute URL as its request-target — `scheme://host[:port]path` — instead of
/// the origin-form path. The port is omitted when it equals the scheme's
/// `default_port`, and an IPv6 literal host is bracketed, matching curl's
/// authority formatting. `path` is expected to already begin with `/` (or be a
/// full path-and-query).
#[must_use]
pub fn proxy_http_target(
    scheme: &str,
    host: &str,
    port: u16,
    default_port: u16,
    path: &str,
) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let authority = if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    };
    format!("{scheme}://{authority}{path}")
}

// ===========================================================================
// PHASE 5 — Error mapping (← curl's CONNECT response handling; `CURLE_PROXY`).
// ===========================================================================

/// Map a proxy `CONNECT` response status to a [`Result`], following curl's
/// tunnel-establishment outcome.
///
/// A `2xx` status opens the tunnel (`Ok(())`). Any other status is a rejected
/// tunnel: curl fails the transfer, and this port surfaces it as
/// [`Error::proxy`] (curl error `CURLE_PROXY` = `97`) carrying the rejecting
/// status so `--trace` diagnostics remain informative. This mirrors the
/// failure classification the h1/h2 tunnel state machines apply to the final
/// `CONNECT` response.
///
/// # Errors
///
/// Returns [`Error::proxy`] for any non-`2xx` `status`.
pub fn connect_status_to_result(status: i32) -> Result<()> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(Error::proxy(format!(
            "Received HTTP code {status} from proxy after CONNECT"
        )))
    }
}

// ===========================================================================
// Tests — CONNECT wire-parity (byte-exact request line + header order + IPv6
// authority bracketing), proxy-header injection and user-override suppression,
// `Proxy-Authorization: Basic`, destination resolution, ALPN backend selection,
// generic-filter queries, config building, and error mapping. Everything runs
// in-process against constructed values; no external daemons are required.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{HostName, Scheme, FIRSTSOCKET};

    // -- helpers -----------------------------------------------------------

    /// Serialize an [`HttpReqData`] as the HTTP/1.1 request head the h1 tunnel
    /// driver puts on the wire (`CONNECT <authority> HTTP/1.1\r\n`, the header
    /// block in insertion order, then the terminating blank line). This mirrors
    /// what [`crate::conn::h1_proxy`] emits and lets these tests assert the
    /// `CONNECT` bytes exactly.
    fn serialize_h1(req: &HttpReqData) -> String {
        let target = req.authority.as_deref().unwrap_or("");
        let mut s = format!("{} {} HTTP/1.1\r\n", req.method, target);
        for (name, value) in req.headers.iter() {
            s.push_str(name);
            s.push_str(": ");
            s.push_str(value);
            s.push_str("\r\n");
        }
        s.push_str("\r\n");
        s
    }

    /// A baseline connection to `host:port` reached through a *tunneling* HTTP
    /// proxy, so `Proxy-Authorization` is emitted on the CONNECT (matching)
    /// pass.
    fn tunnel_conn(host: &str, port: u16) -> Connection {
        let mut conn = Connection::new(Scheme::new("https", 443), host, port);
        conn.bits.httpproxy = true;
        conn.bits.tunnel_proxy = true;
        conn
    }

    /// A [`CustomHeadersInput`] over `server_headers` with tunneling defaults
    /// (no separate proxy list; sensitive headers permitted).
    fn custom_over(server_headers: &[String]) -> CustomHeadersInput<'_> {
        CustomHeadersInput {
            server_headers,
            proxy_headers: &[],
            sep_headers: false,
            httpproxy: true,
            tunnel_proxy: true,
            host_already_sent: false,
            httpreq: HttpReq::Get,
            authneg: false,
            allowed_to_host: true,
        }
    }

    /// Build a CONNECT request for `conn` over HTTP/1.x with the given
    /// `user_agent`, custom `server_headers`, and optional proxy credentials.
    fn build_connect(
        conn: &Connection,
        user_agent: Option<&str>,
        server_headers: &[String],
        proxy_creds: Option<(&str, &str)>,
    ) -> HttpReqData {
        let mut auth = AuthOutputCtx::default();
        let mut proxy_auth = AuthState::default();
        if let Some((user, passwd)) = proxy_creds {
            auth.proxy_user = Some(user);
            auth.proxy_passwd = Some(passwd);
            auth.has_proxy_user_passwd = true;
            // An unresolved pick defaults to `want`, so Basic is selected.
            proxy_auth.want = auth::CURLAUTH_BASIC;
        }
        let ctx = ConnectRequestCtx {
            user_agent,
            auth,
            custom_headers: custom_over(server_headers),
            sub_httpversion: 11,
        };
        create_connect(conn, FIRSTSOCKET, 1, &ctx, &mut proxy_auth)
            .expect("CONNECT construction is infallible for these inputs")
    }

    // -- Phase 1: types & constants ---------------------------------------

    #[test]
    fn proxy_timeout_is_one_hour_in_ms() {
        assert_eq!(PROXY_TIMEOUT_MS, 3_600_000);
    }

    #[test]
    fn proxy_use_classify_matches_curl_enum() {
        // is_connect always wins → HEADER_CONNECT.
        assert_eq!(
            ProxyUse::classify(true, false, false),
            ProxyUse::HeaderConnect
        );
        assert_eq!(
            ProxyUse::classify(true, true, true),
            ProxyUse::HeaderConnect
        );
        // Non-tunnel request to a proxy → HEADER_PROXY.
        assert_eq!(
            ProxyUse::classify(false, true, false),
            ProxyUse::HeaderProxy
        );
        // Tunneling proxy (or no proxy) → HEADER_SERVER.
        assert_eq!(
            ProxyUse::classify(false, true, true),
            ProxyUse::HeaderServer
        );
        assert_eq!(
            ProxyUse::classify(false, false, false),
            ProxyUse::HeaderServer
        );
    }

    #[test]
    fn is_https_proxy_only_for_tls_proxy_types() {
        assert!(is_https_proxy(ProxyType::Https));
        assert!(is_https_proxy(ProxyType::Https2));
        assert!(!is_https_proxy(ProxyType::Http));
        assert!(!is_https_proxy(ProxyType::Http1_0));
        assert!(!is_https_proxy(ProxyType::Socks5));
    }

    // -- Phase 3: destination resolution ----------------------------------

    #[test]
    fn get_destination_primary_host() {
        let conn = tunnel_conn("example.com", 8080);
        assert_eq!(
            get_destination(&conn, FIRSTSOCKET),
            ("example.com".to_string(), 8080, false)
        );
    }

    #[test]
    fn get_destination_connect_to_override() {
        let mut conn = tunnel_conn("example.com", 443);
        conn.bits.conn_to_host = true;
        conn.conn_to_host = Some(HostName::new("target.internal"));
        conn.bits.conn_to_port = true;
        conn.conn_to_port = Some(9000);
        assert_eq!(
            get_destination(&conn, FIRSTSOCKET),
            ("target.internal".to_string(), 9000, false)
        );
    }

    #[test]
    fn get_destination_connect_to_ipv6_detected_by_colon() {
        let mut conn = tunnel_conn("example.com", 443);
        conn.bits.conn_to_host = true;
        conn.conn_to_host = Some(HostName::new("::1"));
        // A non-primary host is inspected for a ':' to detect an IPv6 literal.
        assert_eq!(
            get_destination(&conn, FIRSTSOCKET),
            ("::1".to_string(), 443, true)
        );
    }

    #[test]
    fn get_destination_secondary_socket() {
        let mut conn = tunnel_conn("example.com", 443);
        conn.secondaryhostname = Some("data.example".to_string());
        conn.secondary_port = 2121;
        assert_eq!(
            get_destination(&conn, SECONDARYSOCKET),
            ("data.example".to_string(), 2121, false)
        );
    }

    // -- Phase 3: CONNECT request construction (wire parity) --------------

    #[test]
    fn connect_request_basic_wire_bytes() {
        let conn = tunnel_conn("example.com", 443);
        let req = build_connect(&conn, Some("curl-rs/test"), &[], None);
        // Method/authority carry no scheme or path (a proper CONNECT target).
        assert_eq!(req.method, "CONNECT");
        assert_eq!(req.authority.as_deref(), Some("example.com:443"));
        assert!(req.scheme.is_none());
        assert!(req.path.is_none());
        // Header order on the wire: Host, User-Agent, Proxy-Connection.
        assert_eq!(
            serialize_h1(&req),
            "CONNECT example.com:443 HTTP/1.1\r\n\
             Host: example.com:443\r\n\
             User-Agent: curl-rs/test\r\n\
             Proxy-Connection: Keep-Alive\r\n\
             \r\n"
        );
    }

    #[test]
    fn connect_request_proxy_authorization_basic() {
        let conn = tunnel_conn("example.com", 443);
        let req = build_connect(
            &conn,
            Some("curl-rs/test"),
            &[],
            Some(("proxyuser", "secret")),
        );
        // base64("proxyuser:secret") == "cHJveHl1c2VyOnNlY3JldA==". The
        // Proxy-Authorization line sits between Host and User-Agent, exactly as
        // curl emits `data->state.aptr.proxyuserpwd`.
        assert_eq!(
            serialize_h1(&req),
            "CONNECT example.com:443 HTTP/1.1\r\n\
             Host: example.com:443\r\n\
             Proxy-Authorization: Basic cHJveHl1c2VyOnNlY3JldA==\r\n\
             User-Agent: curl-rs/test\r\n\
             Proxy-Connection: Keep-Alive\r\n\
             \r\n"
        );
    }

    #[test]
    fn connect_request_ipv6_authority_bracketed() {
        let mut conn = tunnel_conn("::1", 443);
        conn.bits.ipv6_ip = true;
        let req = build_connect(&conn, Some("curl-rs/test"), &[], None);
        assert_eq!(req.authority.as_deref(), Some("[::1]:443"));
        assert_eq!(
            serialize_h1(&req),
            "CONNECT [::1]:443 HTTP/1.1\r\n\
             Host: [::1]:443\r\n\
             User-Agent: curl-rs/test\r\n\
             Proxy-Connection: Keep-Alive\r\n\
             \r\n"
        );
    }

    #[test]
    fn connect_request_user_host_override_suppresses_auto_host() {
        let conn = tunnel_conn("example.com", 443);
        let headers = vec!["Host: override.example:8443".to_string()];
        let wire = serialize_h1(&build_connect(&conn, Some("curl-rs/test"), &headers, None));
        // The auto Host is suppressed; the user's Host is emitted last via the
        // custom-header pass, so it appears exactly once with the user value.
        assert_eq!(
            wire,
            "CONNECT example.com:443 HTTP/1.1\r\n\
             User-Agent: curl-rs/test\r\n\
             Proxy-Connection: Keep-Alive\r\n\
             Host: override.example:8443\r\n\
             \r\n"
        );
        assert_eq!(wire.matches("Host: ").count(), 1);
    }

    #[test]
    fn connect_request_user_user_agent_override_suppresses_auto() {
        let conn = tunnel_conn("example.com", 443);
        let headers = vec!["User-Agent: custom-agent/1.0".to_string()];
        // The default UA is provided but must be suppressed by the override.
        let wire = serialize_h1(&build_connect(
            &conn,
            Some("default-agent/9.9"),
            &headers,
            None,
        ));
        assert_eq!(
            wire,
            "CONNECT example.com:443 HTTP/1.1\r\n\
             Host: example.com:443\r\n\
             Proxy-Connection: Keep-Alive\r\n\
             User-Agent: custom-agent/1.0\r\n\
             \r\n"
        );
        assert!(!wire.contains("default-agent/9.9"));
        assert_eq!(wire.matches("User-Agent: ").count(), 1);
    }

    #[test]
    fn connect_request_user_proxy_connection_override_suppresses_auto() {
        let conn = tunnel_conn("example.com", 443);
        let headers = vec!["Proxy-Connection: close".to_string()];
        let wire = serialize_h1(&build_connect(&conn, Some("curl-rs/test"), &headers, None));
        assert_eq!(
            wire,
            "CONNECT example.com:443 HTTP/1.1\r\n\
             Host: example.com:443\r\n\
             User-Agent: curl-rs/test\r\n\
             Proxy-Connection: close\r\n\
             \r\n"
        );
        assert!(!wire.contains("Keep-Alive"));
    }

    #[test]
    fn connect_request_http2_omits_connection_specific_headers() {
        // HTTP/2 carries the destination in `:authority`, not a Host header, and
        // omits the hop-by-hop Proxy-Connection field.
        let conn = tunnel_conn("example.com", 443);
        let ctx = ConnectRequestCtx {
            user_agent: Some("curl-rs/test"),
            auth: AuthOutputCtx::default(),
            custom_headers: custom_over(&[]),
            sub_httpversion: 20,
        };
        let mut proxy_auth = AuthState::default();
        let req = create_connect(&conn, FIRSTSOCKET, 2, &ctx, &mut proxy_auth).unwrap();
        assert_eq!(req.authority.as_deref(), Some("example.com:443"));
        let wire = serialize_h1(&req);
        assert!(
            !wire.contains("Host:"),
            "h2 CONNECT uses :authority, not Host"
        );
        assert!(!wire.contains("Proxy-Connection:"));
        assert!(wire.contains("User-Agent: curl-rs/test\r\n"));
    }

    #[test]
    fn split_header_line_trims_name_and_value() {
        assert_eq!(
            split_header_line("Proxy-Authorization: Basic abc=="),
            Some(("Proxy-Authorization", "Basic abc=="))
        );
        assert_eq!(split_header_line("X:  y  "), Some(("X", "y")));
        assert_eq!(split_header_line("no-colon-here"), None);
    }

    // -- Phase 4: ALPN backend selection & filter dispatch ----------------

    #[test]
    fn tunnel_backend_selection_matches_alpn_switch() {
        assert_eq!(select_tunnel_backend(None).unwrap(), TunnelBackend::H1_1);
        assert_eq!(
            select_tunnel_backend(Some("http/1.1")).unwrap(),
            TunnelBackend::H1_1
        );
        assert_eq!(
            select_tunnel_backend(Some("http/1.0")).unwrap(),
            TunnelBackend::H1_0
        );
        assert_eq!(
            select_tunnel_backend(Some("h2")).unwrap(),
            TunnelBackend::H2
        );
        let err = select_tunnel_backend(Some("h3")).unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntConnect);
    }

    #[test]
    fn tunnel_backend_httpversion_and_is_h2() {
        assert_eq!(TunnelBackend::H1_0.httpversion(), 10);
        assert_eq!(TunnelBackend::H1_1.httpversion(), 11);
        assert_eq!(TunnelBackend::H2.httpversion(), 20);
        assert!(TunnelBackend::H2.is_h2());
        assert!(!TunnelBackend::H1_0.is_h2());
        assert!(!TunnelBackend::H1_1.is_h2());
    }

    #[test]
    fn http_proxy_filter_identity_and_type() {
        let filter = HttpProxyFilter::new("proxy.example", 3128);
        assert_eq!(filter.name(), "HTTP-PROXY");
        assert_eq!(filter.cf_type(), CfType::IP_CONNECT | CfType::PROXY);
        assert_eq!(filter.proxy_host(), "proxy.example");
        assert_eq!(filter.proxy_port(), 3128);
    }

    #[test]
    fn http_proxy_filter_query_reports_proxy_endpoint() {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(HttpProxyFilter::new("proxy.example", 8080)));

        // HOST_PORT reports the *proxy* endpoint, not the tunnel destination.
        let mut out = QueryOut::None;
        chain.query(CfQuery::HostPort, &mut out).unwrap();
        match out {
            QueryOut::HostPort { host, port } => {
                assert_eq!(host, "proxy.example");
                assert_eq!(port, 8080);
            }
            other => panic!("expected HostPort, got {other:?}"),
        }

        // The proxy layer masks the sub-transport's ALPN (answers "none").
        let mut out = QueryOut::None;
        chain.query(CfQuery::AlpnNegotiated, &mut out).unwrap();
        assert!(matches!(out, QueryOut::None));
    }

    #[test]
    fn insert_after_splices_generic_proxy_filter() {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(HttpProxyFilter::new("base", 1)));
        insert_after(&mut chain, 0, "proxy.example", 3128).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.tail().unwrap().name(), "HTTP-PROXY");
    }

    #[test]
    fn insert_after_rejects_out_of_range_index() {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        assert!(insert_after(&mut chain, 0, "proxy.example", 3128).is_err());
    }

    #[test]
    fn h1_config_from_sets_credentials_and_basic_default() {
        let mut conn = tunnel_conn("example.com", 8443);
        conn.http_proxy.user = Some("pu".to_string());
        conn.http_proxy.passwd = Some("pp".to_string());
        conn.http_proxy.proxytype = ProxyType::Http1_0;
        let cfg = h1_config_from(
            &conn,
            FIRSTSOCKET,
            Some("agent/1".to_string()),
            vec![("X".to_string(), "Y".to_string())],
        );
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.port, 8443);
        assert!(cfg.http_1_0);
        assert_eq!(cfg.user_agent.as_deref(), Some("agent/1"));
        assert_eq!(cfg.extra_headers, vec![("X".to_string(), "Y".to_string())]);
        assert_eq!(cfg.proxy_user.as_deref(), Some("pu"));
        assert_eq!(cfg.proxy_password.as_deref(), Some("pp"));
        assert_eq!(cfg.want_auth, auth::CURLAUTH_BASIC);
        assert!(cfg.proactive_auth);
    }

    #[test]
    fn h1_config_from_without_credentials_has_no_proactive_auth() {
        let conn = tunnel_conn("example.com", 443);
        let cfg = h1_config_from(&conn, FIRSTSOCKET, None, Vec::new());
        assert!(cfg.proxy_user.is_none());
        assert_eq!(cfg.want_auth, 0);
        assert!(!cfg.proactive_auth);
        assert!(!cfg.http_1_0);
    }

    #[test]
    fn install_h1_tunnel_splices_h1_proxy_filter() {
        let conn = tunnel_conn("example.com", 443);
        let cfg = h1_config_from(&conn, FIRSTSOCKET, Some("agent/1".to_string()), Vec::new());
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(HttpProxyFilter::new("proxy.example", 8080)));
        install_h1_tunnel(&mut chain, 0, cfg).unwrap();
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn h2_config_from_sets_origin_and_credentials() {
        let mut conn = tunnel_conn("example.com", 8443);
        conn.http_proxy.user = Some("pu".to_string());
        conn.http_proxy.passwd = Some("pp".to_string());
        let cfg = h2_config_from(&conn, FIRSTSOCKET);
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.port, 8443);
        assert_eq!(cfg.user.as_deref(), Some("pu"));
        assert_eq!(cfg.pass.as_deref(), Some("pp"));
    }

    #[test]
    fn proxy_http_target_uses_absolute_form() {
        // Default port omitted.
        assert_eq!(
            proxy_http_target("http", "example.com", 80, 80, "/index.html"),
            "http://example.com/index.html"
        );
        // Non-default port included; query preserved.
        assert_eq!(
            proxy_http_target("http", "example.com", 8080, 80, "/a?b=c"),
            "http://example.com:8080/a?b=c"
        );
        // Bare IPv6 literal gets bracketed.
        assert_eq!(
            proxy_http_target("http", "::1", 8080, 80, "/"),
            "http://[::1]:8080/"
        );
        // Already-bracketed IPv6 literal is left as-is.
        assert_eq!(
            proxy_http_target("http", "[::1]", 80, 80, "/"),
            "http://[::1]/"
        );
        assert_eq!(
            proxy_http_target("https", "example.com", 443, 443, "/"),
            "https://example.com/"
        );
    }

    // -- Phase 5: error mapping -------------------------------------------

    #[test]
    fn connect_status_maps_non_2xx_to_curle_proxy() {
        assert!(connect_status_to_result(200).is_ok());
        assert!(connect_status_to_result(204).is_ok());
        assert!(connect_status_to_result(299).is_ok());
        for status in [199, 300, 401, 403, 407, 500, 502] {
            let err = connect_status_to_result(status).unwrap_err();
            assert_eq!(err.code(), CurlCode::Proxy);
            assert_eq!(err.code_i32(), 97);
        }
    }
}
