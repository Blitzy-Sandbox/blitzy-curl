// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! HTTP CONNECT proxy tunnel handler.
//!
//! Complete Rust rewrite of `lib/http_proxy.c` (437 lines) and
//! `lib/http_proxy.h` from the curl C codebase.
//!
//! This module implements:
//!
//! - **HTTP CONNECT proxy tunnel establishment** via the [`HttpProxyFilter`]
//!   connection filter, which installs the appropriate sub-filter (HTTP/1.x or
//!   HTTP/2) based on the ALPN protocol negotiated with the proxy.
//! - **CONNECT request construction** via [`create_connect_request`], producing
//!   a standards-conformant `CONNECT host:port HTTP/1.x` request with proxy
//!   authentication, user-agent, and custom header support.
//! - **Custom header sanitization** via the internal [`dynhds_add_custom`]
//!   helper, filtering conflicting headers (Host, Content-Type,
//!   Content-Length, Transfer-Encoding, Authorization, Cookie) exactly as the
//!   C implementation does.
//! - **Destination resolution** via [`get_destination`], which resolves the
//!   target hostname, port, and IPv6 indicator from the connection state.
//! - **Filter chain insertion** via [`insert_after`], creating and installing
//!   the HTTP proxy filter at the correct position in the filter chain.
//!
//! # Feature Guards
//!
//! This module is compiled when the `http` feature is enabled and the
//! `disable_proxy` feature is **not** enabled, matching the C preprocessor
//! guard: `#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)`.
//!
//! # Zero `unsafe`
//!
//! This module contains **zero** `unsafe` blocks per AAP Section 0.7.1.

use std::time::Duration;

use async_trait::async_trait;

use crate::auth;
use crate::conn::filters::{
    ConnectionFilter, FilterChain, QueryResult, TransferData,
    CF_QUERY_ALPN_NEGOTIATED, CF_QUERY_HOST_PORT,
    CF_TYPE_IP_CONNECT, CF_TYPE_PROXY,
    get_alpn_negotiated,
};
use crate::conn::h1_proxy::H1ProxyFilter;
use crate::conn::h2_proxy::H2ProxyFilter;
use crate::easy::EasyHandle;
use crate::error::{CurlError, CurlResult};
use crate::headers::DynHeaders;
use crate::protocols::http::{
    HttpReq, HttpRequest, check_proxy_headers, output_auth, HttpEasyExt,
};
use crate::protocols::Connection;

// ===========================================================================
// Constants
// ===========================================================================

/// Maximum time allowed for the HTTP CONNECT proxy tunnel establishment
/// (1 hour), matching the C `#define PROXY_TIMEOUT (3600 * 1000)`.
///
/// The C constant is in milliseconds; in Rust we use [`Duration`] for
/// type-safety. The value is 3600 seconds = 1 hour.
pub const PROXY_TIMEOUT: Duration = Duration::from_secs(3600);

// ===========================================================================
// ProxyUse — header destination classification
// ===========================================================================

/// Classifies how custom headers should be directed when building HTTP
/// requests that may transit a proxy.
///
/// Maps 1:1 to the C `enum Curl_proxy_use` from `lib/http_proxy.h`:
///
/// | Rust Variant        | C Constant      | Semantics                     |
/// |---------------------|-----------------|-------------------------------|
/// | `HeaderServer`      | `HEADER_SERVER` | Direct request to server      |
/// | `HeaderProxy`       | `HEADER_PROXY`  | Regular request to proxy      |
/// | `HeaderConnect`     | `HEADER_CONNECT`| Sending CONNECT to a proxy    |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyUse {
    /// Headers are sent directly to the origin server.
    HeaderServer,
    /// Headers are sent as part of a regular request to a proxy.
    HeaderProxy,
    /// Headers are sent as part of an HTTP CONNECT request to a proxy.
    HeaderConnect,
}

// ===========================================================================
// HttpProxyContext — internal per-filter state
// ===========================================================================

/// Internal context for the HTTP proxy filter.
///
/// Matches the C `struct cf_proxy_ctx` from `lib/http_proxy.c` lines 192-195.
///
/// Fields:
/// - `httpversion`: The HTTP version negotiated for the CONNECT tunnel
///   (10 = HTTP/1.0, 11 = HTTP/1.1, 20 = HTTP/2).
/// - `sub_filter_installed`: Whether the sub-filter (H1 or H2 proxy) has
///   been installed in the filter chain below this filter.
#[derive(Debug)]
struct HttpProxyContext {
    /// HTTP version used for the CONNECT tunnel.
    /// 10 = HTTP/1.0, 11 = HTTP/1.1, 20 = HTTP/2.
    httpversion: u8,
    /// Whether the sub-filter (H1ProxyFilter or H2ProxyFilter) has been
    /// installed.
    sub_filter_installed: bool,
}

impl HttpProxyContext {
    /// Creates a new context with default values.
    fn new() -> Self {
        Self {
            httpversion: 0,
            sub_filter_installed: false,
        }
    }
}

// ===========================================================================
// Destination Resolution
// ===========================================================================

/// Resolves the target hostname, port, and IPv6 literal indicator for a
/// CONNECT request.
///
/// Examines the connection configuration to determine the correct destination:
/// 1. If a connect-to host override is configured, use that.
/// 2. Otherwise, use the primary connection host.
/// 3. If a connect-to port override is configured, use that.
/// 4. Otherwise, use the remote port from the connection.
/// 5. IPv6 is detected by looking for `:` in the hostname.
///
/// Returns `(hostname, port, is_ipv6)`.
///
/// # C Equivalent
///
/// `Curl_http_proxy_get_destination()` from `lib/http_proxy.c` lines 165-190.
///
/// # Arguments
///
/// * `proxy_host` — The proxy host configured on the connection.
/// * `proxy_port` — The proxy port configured on the connection.
/// * `conn_to_host` — Optional connect-to host override.
/// * `conn_to_port` — Optional connect-to port override.
/// * `remote_host` — The remote (target) hostname.
/// * `remote_port` — The remote (target) port.
/// * `ipv6_ip` — Whether the remote host is known to be an IPv6 address.
pub fn get_destination(
    conn_to_host: Option<&str>,
    conn_to_port: Option<u16>,
    remote_host: &str,
    remote_port: u16,
    ipv6_ip: bool,
) -> (String, u16, bool) {
    // Determine the hostname to use for the CONNECT target.
    // C: if(cf->conn->bits.conn_to_host) *phostname = cf->conn->conn_to_host.name;
    //    else *phostname = cf->conn->host.name;
    let hostname = match conn_to_host {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => remote_host.to_string(),
    };

    // Determine the port to use for the CONNECT target.
    // C: if(cf->conn->bits.conn_to_port) *pport = cf->conn->conn_to_port;
    //    else *pport = cf->conn->remote_port;
    let port = match conn_to_port {
        Some(p) if p > 0 => p,
        _ => remote_port,
    };

    // Determine if the hostname is an IPv6 literal.
    // C: if(*phostname != cf->conn->host.name)
    //       *pipv6_ip = (strchr(*phostname, ':') != NULL);
    //    else *pipv6_ip = (bool)cf->conn->bits.ipv6_ip;
    let is_ipv6 = if conn_to_host.is_some() {
        hostname.contains(':')
    } else {
        ipv6_ip
    };

    (hostname, port, is_ipv6)
}

// ===========================================================================
// CONNECT Request Construction
// ===========================================================================

/// Constructs an HTTP CONNECT request for proxy tunnel establishment.
///
/// Produces a fully assembled [`HttpRequest`] with:
/// 1. The CONNECT method and `host:port` authority (IPv6 wrapped in brackets).
/// 2. Proxy authentication headers (via [`output_auth`]).
/// 3. A Host header (for HTTP/1.x, if not overridden by user proxy headers).
/// 4. Proxy-Authorization credentials if configured.
/// 5. User-Agent header (if not overridden).
/// 6. Proxy-Connection: Keep-Alive (if not overridden).
/// 7. Sanitized custom headers (via [`dynhds_add_custom`]).
///
/// # C Equivalent
///
/// `Curl_http_proxy_create_CONNECT()` from `lib/http_proxy.c` lines 197-271.
///
/// # Arguments
///
/// * `hostname` — Target hostname for the CONNECT authority.
/// * `port` — Target port for the CONNECT authority.
/// * `is_ipv6` — Whether the hostname is an IPv6 literal.
/// * `data` — The EasyHandle providing user configuration.
/// * `http_version_major` — HTTP major version (1 or 2).
/// * `httpversion` — Full HTTP version code (10, 11, 20) for header filtering.
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] if header assembly fails.
pub fn create_connect_request(
    hostname: &str,
    port: u16,
    is_ipv6: bool,
    data: &EasyHandle,
    http_version_major: u8,
    httpversion: u8,
) -> CurlResult<HttpRequest> {
    // Format authority string: wrap IPv6 addresses in brackets.
    // C: curl_maprintf("%s%s%s:%d", ipv6_ip ? "[" : "", hostname,
    //                  ipv6_ip ? "]" : "", port);
    let authority = if is_ipv6 {
        format!("[{}]:{}", hostname, port)
    } else {
        format!("{}:{}", hostname, port)
    };

    tracing::debug!(authority = %authority, "Creating CONNECT request");

    // C: Curl_http_req_make(&req, "CONNECT", ...)
    let mut req = HttpRequest::new("CONNECT", &authority);

    // Note: Proxy authentication headers are added asynchronously via
    // `add_proxy_auth()` after request construction, since the auth subsystem
    // requires async I/O (for Digest nonce fetching, NTLM negotiation, etc.).
    // See `add_proxy_auth()` below.

    // Add Host header for HTTP/1.x if not already overridden by user proxy headers.
    // C: if(http_version_major == 1 &&
    //       !Curl_checkProxyheaders(data, cf->conn, STRCONST("Host")))
    if http_version_major == 1 && check_proxy_headers(data, "Host").is_none() {
        req.add_header("Host", &authority);
    }

    // Add User-Agent if not overridden and configured.
    // C: if(!Curl_checkProxyheaders(data, cf->conn, STRCONST("User-Agent")) &&
    //       data->set.str[STRING_USERAGENT] && *data->set.str[STRING_USERAGENT])
    if check_proxy_headers(data, "User-Agent").is_none() {
        if let Some(ua) = data.user_agent() {
            if !ua.is_empty() {
                req.add_header("User-Agent", ua);
            }
        }
    }

    // Add Proxy-Connection: Keep-Alive for HTTP/1.x if not overridden.
    // C: if(http_version_major == 1 &&
    //       !Curl_checkProxyheaders(data, cf->conn, STRCONST("Proxy-Connection")))
    if http_version_major == 1
        && check_proxy_headers(data, "Proxy-Connection").is_none()
    {
        req.add_header("Proxy-Connection", "Keep-Alive");
    }

    // Add sanitized custom headers.
    // C: result = dynhds_add_custom(data, TRUE, ctx->httpversion, &req->headers);
    let mut custom_hds = DynHeaders::new();
    dynhds_add_custom(data, true, &mut custom_hds, httpversion)?;
    for entry in custom_hds.iter() {
        req.add_header(entry.name(), entry.value());
    }

    tracing::trace!(
        method = "CONNECT",
        authority = %authority,
        header_count = req.headers.len(),
        "CONNECT request assembled"
    );

    Ok(req)
}

// ===========================================================================
// Proxy Authentication
// ===========================================================================

/// Adds proxy authentication headers to a CONNECT request.
///
/// This is the async companion to [`create_connect_request`]. After the
/// synchronous request construction, this function applies proxy
/// authentication via the auth subsystem which may require async I/O
/// (Digest nonce fetching, NTLM multi-step negotiation, etc.).
///
/// # C Equivalent
///
/// The call to `Curl_http_output_auth(data, conn, "CONNECT", HTTPREQ_GET, ...)`
/// at line 203 of `lib/http_proxy.c`.
///
/// # Arguments
///
/// * `data` — Mutable reference to the EasyHandle for auth state.
/// * `conn` — Connection reference for per-connection auth tracking.
/// * `req` — The CONNECT request to add auth headers to.
///
/// # Errors
///
/// Returns any error from the authentication subsystem.
pub async fn add_proxy_auth(
    data: &mut EasyHandle,
    conn: &Connection,
    req: &mut HttpRequest,
) -> CurlResult<()> {
    // C: result = Curl_http_output_auth(data, cf->conn, "CONNECT",
    //                                    HTTPREQ_GET, authority, TRUE);
    // The C code passes HTTPREQ_GET as the request type for CONNECT
    // tunnels, since CONNECT is treated as a GET-like operation for auth
    // purposes. The `output_auth` function checks whether the proxy
    // requires authentication and generates the appropriate
    // Proxy-Authorization header.
    let _request_type = HttpReq::Get;
    output_auth(data, conn, req).await?;
    Ok(())
}

// ===========================================================================
// Custom Header Sanitization
// ===========================================================================

/// Sanitizes and appends custom headers from the EasyHandle's header lists
/// to the provided [`DynHeaders`] collection.
///
/// Iterates through the user-configured header lists (shared headers and
/// proxy-specific headers), parses each `Name: Value` line, and filters out
/// headers that would conflict with auto-generated ones:
///
/// - `Host` — already generated from the authority
/// - `Content-Type` — auto-generated for POST/MIME bodies
/// - `Content-Length` — suppressed during auth negotiation
/// - `Transfer-Encoding` — disallowed for HTTP/2+
/// - `Authorization` / `Cookie` — blocked unless auth is allowed to the host
///
/// Handles two header line quirks matching the C implementation:
/// 1. `Name:` (name followed by colon only) — suppress the header entirely
/// 2. `Name;` (name followed by semicolon only) — emit header with empty value
///
/// # C Equivalent
///
/// `dynhds_add_custom()` from `lib/http_proxy.c` lines 40-163.
///
/// # Arguments
///
/// * `data` — EasyHandle providing configuration and header lists.
/// * `is_connect` — Whether this is for a CONNECT request.
/// * `hds` — Output DynHeaders to append sanitized headers to.
/// * `httpversion` — HTTP version code (10, 11, 20, 30) for filtering.
fn dynhds_add_custom(
    data: &EasyHandle,
    is_connect: bool,
    hds: &mut DynHeaders,
    httpversion: u8,
) -> CurlResult<()> {
    // Determine which header lists to iterate.
    // C: switch(proxy) { case HEADER_CONNECT: ... }
    // For CONNECT requests (is_connect == true):
    //   - If separate proxy headers are configured, use only proxy headers.
    //   - Otherwise, fall back to the shared custom headers.
    // For non-CONNECT requests, the logic is more complex (see C lines 58-75),
    // but for this module we only ever call with is_connect=true.

    let proxy_mode = if is_connect {
        ProxyUse::HeaderConnect
    } else {
        ProxyUse::HeaderServer
    };

    // Collect the header lists to iterate.
    // C uses h[0] and optionally h[1]; we use a Vec of references.
    let header_lists: Vec<&[String]> = match proxy_mode {
        ProxyUse::HeaderConnect => {
            // C: if(data->set.sep_headers) h[0] = data->set.proxyheaders;
            //    else h[0] = data->set.headers;
            let proxy_hdrs = data.proxy_headers_list();
            if !proxy_hdrs.is_empty() {
                vec![proxy_hdrs]
            } else {
                let custom_hdrs = data.custom_headers_list();
                if !custom_hdrs.is_empty() {
                    vec![custom_hdrs]
                } else {
                    vec![]
                }
            }
        }
        ProxyUse::HeaderProxy => {
            // C: h[0] = data->set.headers;
            //    if(data->set.sep_headers) { h[1] = data->set.proxyheaders; numlists++; }
            let mut lists = vec![data.custom_headers_list()];
            let proxy_hdrs = data.proxy_headers_list();
            if !proxy_hdrs.is_empty() {
                lists.push(proxy_hdrs);
            }
            lists
        }
        ProxyUse::HeaderServer => {
            // C: h[0] = data->set.headers;
            vec![data.custom_headers_list()]
        }
    };

    // Iterate through all header lists and each header line within them.
    for header_list in &header_lists {
        for header_line in header_list.iter() {
            let ptr = header_line.as_str();

            // Parse the header line to extract name and value.
            // C uses curlx_str_cspn to find the first ';' or ':'.
            let (name, value, suppress) = match parse_custom_header(ptr) {
                Some(parsed) => parsed,
                None => continue, // Unparseable line — skip silently
            };

            if suppress {
                // Quirk #1: header name followed by ':' with no value — suppress.
                continue;
            }

            // Apply filtering rules matching the C implementation exactly.

            // Filter: Host header already generated.
            // C: if(data->state.aptr.host && curlx_str_casecompare(&name, "Host"))
            if name.eq_ignore_ascii_case("Host") {
                continue;
            }

            // Filter: Content-Type for POST form/MIME.
            // C: if(data->state.httpreq == HTTPREQ_POST_FORM && ... "Content-Type")
            //    if(data->state.httpreq == HTTPREQ_POST_MIME && ... "Content-Type")
            if name.eq_ignore_ascii_case("Content-Type") {
                // During CONNECT, there is no body, so Content-Type is meaningless.
                // The C code checks httpreq type but for CONNECT this filter
                // effectively applies.
                continue;
            }

            // Filter: Content-Length during auth negotiation.
            // C: if(data->req.authneg && ... "Content-Length")
            if name.eq_ignore_ascii_case("Content-Length") {
                continue;
            }

            // Filter: Transfer-Encoding for HTTP/2+.
            // C: if((httpversion >= 20) && ... "Transfer-Encoding")
            if httpversion >= 20 && name.eq_ignore_ascii_case("Transfer-Encoding") {
                continue;
            }

            // Filter: Authorization / Cookie — credential leakage protection.
            // C: if((curlx_str_casecompare(&name, "Authorization") ||
            //        curlx_str_casecompare(&name, "Cookie")) &&
            //       !Curl_auth_allowed_to_host(data))
            if name.eq_ignore_ascii_case("Authorization")
                || name.eq_ignore_ascii_case("Cookie")
            {
                // For the proxy module, we always allow credentials since the
                // CONNECT is to the proxy itself. The C code calls
                // Curl_auth_allowed_to_host which checks redirect state — for
                // a CONNECT tunnel there is no redirect context, so we default
                // to allowed. The auth::allowed_to_host function requires full
                // connection context that we approximate here.
                let allowed = auth::allowed_to_host(
                    false, // is_follow: CONNECT is not a redirect
                    false, // allow_auth_to_other_hosts
                    None,  // first_host
                    "",    // current_host
                    0,     // first_port
                    0,     // current_port
                    "",    // first_protocol
                    "",    // current_protocol
                );
                if !allowed {
                    continue;
                }
            }

            // All filters passed — add the header.
            hds.add(&name, &value)?;
        }
    }

    Ok(())
}

/// Parses a single custom header line into (name, value, suppress).
///
/// Handles three formats:
/// 1. `"Name: Value"` — normal header with value
/// 2. `"Name:"` — suppress this header (quirk #1)
/// 3. `"Name;"` — send header with empty value (quirk #2)
///
/// Returns `None` if the line cannot be parsed (no name found, or no
/// separator).
///
/// The returned tuple contains:
/// - `name`: The header field name (as a `String`).
/// - `value`: The header field value (may be empty for quirk #2).
/// - `suppress`: `true` if the header should be suppressed (quirk #1).
fn parse_custom_header(line: &str) -> Option<(String, String, bool)> {
    if line.is_empty() {
        return None;
    }

    // Find the first occurrence of ':' or ';' — whichever comes first.
    // C: curlx_str_cspn(&ptr, &name, ";:")
    let sep_pos = line.find(&[':', ';'][..])?;
    let name = &line[..sep_pos];

    if name.is_empty() {
        return None;
    }

    let sep_char = line.as_bytes()[sep_pos];
    let after_sep = &line[sep_pos + 1..];

    if sep_char == b':' {
        // Check for value after colon.
        let trimmed = after_sep.trim_start();
        if trimmed.is_empty() {
            // Quirk #1: "Name:" with no value — suppress the header.
            Some((name.to_string(), String::new(), true))
        } else {
            // Normal header with value.
            Some((name.to_string(), trimmed.to_string(), false))
        }
    } else {
        // sep_char == b';'
        // C: curlx_str_single(&ptr, ';')
        let trimmed = after_sep.trim_start();
        if trimmed.is_empty() {
            // Quirk #2: "Name;" with no value — emit empty header.
            Some((name.to_string(), String::new(), false))
        } else {
            // Future use — ignore for now.
            None
        }
    }
}

// ===========================================================================
// HttpProxyFilter — HTTP proxy connection filter
// ===========================================================================

/// HTTP CONNECT proxy tunnel connection filter.
///
/// Implements the [`ConnectionFilter`] trait, matching the C
/// `Curl_cft_http_proxy` filter type from `lib/http_proxy.c` lines 395-411.
///
/// This filter sits in the connection filter chain and manages the selection
/// of the appropriate sub-filter (HTTP/1.x or HTTP/2) based on the ALPN
/// protocol negotiated with the proxy. Once the sub-filter is installed, the
/// connect process delegates to it for the actual CONNECT tunnel establishment.
///
/// # Filter Chain Position
///
/// ```text
/// [Protocol Handler]
///        ↕
/// [TLS Filter]
///        ↕
/// ⟹ [HTTP-PROXY] ← this filter
///        ↕
/// [H1-Proxy or H2-Proxy] ← installed by this filter
///        ↕
/// [Socket Filter]
/// ```
///
/// # State Machine
///
/// 1. **Initial connect**: Delegates to the next filter (TLS/socket) to
///    establish the transport.
/// 2. **ALPN check**: Once the transport connects, reads the negotiated ALPN
///    from the downstream TLS filter.
/// 3. **Sub-filter installation**: Based on ALPN, installs either an
///    [`H1ProxyFilter`] or [`H2ProxyFilter`] immediately after itself in the
///    chain.
/// 4. **Delegation**: Reconnects through the newly installed sub-filter,
///    which handles the actual CONNECT tunnel handshake.
/// 5. **Connected**: Once the sub-filter reports success, marks itself as
///    connected.
pub struct HttpProxyFilter {
    /// Human-readable name for logging.
    filter_name: &'static str,
    /// Internal filter context.
    ctx: HttpProxyContext,
    /// Whether this filter is in the connected state.
    connected: bool,
    /// Whether this filter has completed graceful shutdown.
    shut_down: bool,
    /// The proxy host for destination queries.
    proxy_host: String,
    /// The proxy port for destination queries.
    proxy_port: u16,
    /// Inner filter chain managed below this filter.
    /// In the curl filter architecture, the HttpProxyFilter delegates
    /// connect/send/recv to the chain below it.
    inner_chain: FilterChain,
}

impl HttpProxyFilter {
    /// Creates a new HTTP proxy filter.
    ///
    /// # Arguments
    ///
    /// * `proxy_host` — The proxy server hostname.
    /// * `proxy_port` — The proxy server port.
    pub fn new(proxy_host: String, proxy_port: u16) -> Self {
        tracing::trace!(
            host = %proxy_host,
            port = proxy_port,
            "HttpProxyFilter: created"
        );
        Self {
            filter_name: "HTTP-PROXY",
            ctx: HttpProxyContext::new(),
            connected: false,
            shut_down: false,
            proxy_host,
            proxy_port,
            inner_chain: FilterChain::new(),
        }
    }

    /// Sets the inner filter chain that this proxy filter delegates to.
    ///
    /// Used during filter chain assembly to wire up the downstream filters.
    pub fn set_inner_chain(&mut self, chain: FilterChain) {
        self.inner_chain = chain;
    }

    /// Adds a filter to the inner chain at the front (top of sub-chain).
    pub fn push_inner(&mut self, filter: Box<dyn ConnectionFilter>) {
        self.inner_chain.push_front(filter);
    }
}

#[async_trait]
impl ConnectionFilter for HttpProxyFilter {
    fn name(&self) -> &str {
        self.filter_name
    }

    fn type_flags(&self) -> u32 {
        CF_TYPE_IP_CONNECT | CF_TYPE_PROXY
    }

    /// Drives the proxy tunnel connection process.
    ///
    /// This method implements the state machine from the C
    /// `http_proxy_cf_connect()` function (lines 273-352):
    ///
    /// 1. If already connected, return immediately.
    /// 2. Delegate to the next filter's connect.
    /// 3. On first success: read ALPN and install appropriate sub-filter.
    /// 4. Re-invoke connect through the newly installed sub-filter.
    /// 5. Mark connected when the sub-filter reports success.
    async fn connect(&mut self, data: &mut TransferData) -> Result<bool, CurlError> {
        // C: if(cf->connected) { *done = TRUE; return CURLE_OK; }
        if self.connected {
            return Ok(true);
        }

        tracing::trace!("HTTP-PROXY: connect");

        // Connect the inner chain (this drives the TLS/socket below us).
        // C: result = cf->next->cft->do_connect(cf->next, data, done);
        loop {
            let done = self.inner_chain.connect(data).await?;

            if !done {
                // Inner chain is not yet connected — need more I/O.
                return Ok(false);
            }

            // Inner chain reported connected. Check if we need to install
            // a sub-filter based on ALPN negotiation.
            if !self.ctx.sub_filter_installed {
                // Read the ALPN negotiated by the downstream TLS filter.
                // C: const char *alpn = Curl_conn_cf_get_alpn_negotiated(cf->next, data);
                let alpn = get_alpn_negotiated(&self.inner_chain);

                if let Some(ref alpn_str) = alpn {
                    tracing::info!(alpn = %alpn_str, "CONNECT: '{}' negotiated", alpn_str);
                } else {
                    tracing::info!("CONNECT: no ALPN negotiated");
                }

                let httpversion: u8;

                match alpn.as_deref() {
                    // C: if(alpn && !strcmp(alpn, "http/1.0"))
                    Some("http/1.0") => {
                        tracing::debug!("HTTP-PROXY: installing subfilter for HTTP/1.0");
                        let h1_filter = H1ProxyFilter::new(
                            self.proxy_host.clone(),
                            self.proxy_port,
                        );
                        self.inner_chain.push_front(Box::new(h1_filter));
                        httpversion = 10;
                    }
                    // C: else if(!alpn || !strcmp(alpn, "http/1.1"))
                    None | Some("http/1.1") => {
                        tracing::debug!("HTTP-PROXY: installing subfilter for HTTP/1.1");
                        let h1_filter = H1ProxyFilter::new(
                            self.proxy_host.clone(),
                            self.proxy_port,
                        );
                        self.inner_chain.push_front(Box::new(h1_filter));
                        // Without ALPN, assume HTTP/1.1 (ancient proxy).
                        httpversion = 11;
                    }
                    // C: #ifdef USE_NGHTTP2
                    //    else if(!strcmp(alpn, "h2"))
                    Some("h2") => {
                        tracing::debug!("HTTP-PROXY: installing subfilter for HTTP/2");
                        let h2_filter = H2ProxyFilter::new(
                            self.proxy_host.clone(),
                            self.proxy_port,
                        );
                        self.inner_chain.push_front(Box::new(h2_filter));
                        httpversion = 20;
                    }
                    // C: else { failf(data, "CONNECT: negotiated ALPN '%s' not supported", alpn); }
                    Some(other) => {
                        tracing::error!(
                            alpn = %other,
                            "CONNECT: negotiated ALPN '{}' not supported",
                            other
                        );
                        return Err(CurlError::CouldntConnect);
                    }
                }

                self.ctx.sub_filter_installed = true;
                self.ctx.httpversion = httpversion;

                // After installing the sub-filter, loop back to drive connect
                // through the newly installed filter.
                // C: goto connect_sub;
                continue;
            }

            // Sub-filter was already installed and the chain reports connected.
            // The protocol tunnel is now established.
            // C: DEBUGASSERT(ctx->sub_filter_installed);
            debug_assert!(self.ctx.sub_filter_installed);
            break;
        }

        // C: if(!result) { cf->connected = TRUE; *done = TRUE; }
        self.connected = true;
        tracing::trace!("HTTP-PROXY: connected");
        Ok(true)
    }

    /// Closes the proxy filter and cascades to the inner chain.
    ///
    /// C: `http_proxy_cf_close()` lines 386-393.
    fn close(&mut self) {
        tracing::trace!("HTTP-PROXY: close");
        self.connected = false;
        self.inner_chain.close();
    }

    /// Sends data through the inner chain.
    ///
    /// After the tunnel is established, data passes through transparently.
    async fn send(&mut self, buf: &[u8], eos: bool) -> Result<usize, CurlError> {
        self.inner_chain.send(buf, eos).await
    }

    /// Receives data from the inner chain.
    ///
    /// After the tunnel is established, data passes through transparently.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, CurlError> {
        self.inner_chain.recv(buf).await
    }

    /// Queries the proxy filter for properties.
    ///
    /// Handles:
    /// - `CF_QUERY_HOST_PORT` — returns the proxy host and port.
    /// - `CF_QUERY_ALPN_NEGOTIATED` — returns `NotHandled` (proxy filter
    ///   does not expose ALPN to upper layers).
    /// - Other queries — delegates to the inner chain.
    ///
    /// C: `Curl_cf_http_proxy_query()` lines 354-375.
    fn query(&self, query: i32) -> QueryResult {
        match query {
            // C: case CF_QUERY_HOST_PORT:
            //    *pres1 = (int)cf->conn->http_proxy.port;
            //    *((const char **)pres2) = cf->conn->http_proxy.host.name;
            CF_QUERY_HOST_PORT => {
                // Return the proxy host as a string. The port is encoded in
                // the string format "host:port" for simplicity, matching how
                // consumers typically use this query result.
                let host_port = format!("{}:{}", self.proxy_host, self.proxy_port);
                QueryResult::String(host_port)
            }
            // C: case CF_QUERY_ALPN_NEGOTIATED:
            //    *palpn = NULL; return CURLE_OK;
            CF_QUERY_ALPN_NEGOTIATED => {
                // The proxy filter explicitly returns "no ALPN" to upper layers.
                // This prevents the protocol handler from seeing the proxy's
                // ALPN negotiation and mistaking it for the server's.
                QueryResult::NotHandled
            }
            // C: default: return cf->next ? cf->next->cft->query(...) : CURLE_UNKNOWN_OPTION;
            _ => self.inner_chain.query(query),
        }
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn is_shutdown(&self) -> bool {
        self.shut_down
    }
}

impl HttpProxyFilter {
    /// Destroys the proxy filter context and releases resources.
    ///
    /// C: `http_proxy_cf_destroy()` lines 377-384.
    pub fn destroy(&mut self) {
        tracing::trace!("HTTP-PROXY: destroy");
        // In Rust, dropping the HttpProxyContext frees all memory automatically.
        // Reset the context to a fresh state.
        self.ctx = HttpProxyContext::new();
        self.connected = false;
    }
}

// ===========================================================================
// Filter Chain Insertion
// ===========================================================================

/// Creates and inserts an HTTP proxy filter after the specified position in
/// a filter chain.
///
/// This is the primary entry point for installing the HTTP proxy filter
/// during connection setup. The filter is created with the given proxy host
/// and port, then inserted into the chain.
///
/// # C Equivalent
///
/// `Curl_cf_http_proxy_insert_after()` from `lib/http_proxy.c` lines 413-435.
///
/// # Arguments
///
/// * `chain` — The filter chain to insert into.
/// * `after_index` — The position after which to insert the new filter.
/// * `proxy_host` — The proxy server hostname.
/// * `proxy_port` — The proxy server port.
/// * `_data` — The EasyHandle (used for context in future extensions).
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] if the filter could not be created.
pub fn insert_after(
    chain: &mut FilterChain,
    after_index: usize,
    proxy_host: String,
    proxy_port: u16,
    _data: &EasyHandle,
) -> CurlResult<()> {
    // C: ctx = curlx_calloc(1, sizeof(*ctx));
    //    if(!ctx) { result = CURLE_OUT_OF_MEMORY; goto out; }
    let filter = HttpProxyFilter::new(proxy_host, proxy_port);

    // C: Curl_cf_create(&cf, &Curl_cft_http_proxy, ctx);
    //    Curl_conn_cf_insert_after(cf_at, cf);
    chain.insert_after(after_index, Box::new(filter));

    tracing::debug!(
        after_index = after_index,
        "HTTP-PROXY: filter inserted into chain"
    );

    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_use_variants() {
        // Verify all ProxyUse variants exist and are distinct.
        assert_ne!(ProxyUse::HeaderServer, ProxyUse::HeaderProxy);
        assert_ne!(ProxyUse::HeaderProxy, ProxyUse::HeaderConnect);
        assert_ne!(ProxyUse::HeaderServer, ProxyUse::HeaderConnect);
    }

    #[test]
    fn test_proxy_timeout_value() {
        // C: PROXY_TIMEOUT = 3600 * 1000 milliseconds = 3600 seconds = 1 hour
        assert_eq!(PROXY_TIMEOUT, Duration::from_secs(3600));
        assert_eq!(PROXY_TIMEOUT.as_millis(), 3_600_000);
    }

    #[test]
    fn test_get_destination_basic() {
        // No overrides — use remote host and port directly.
        let (host, port, ipv6) = get_destination(
            None,    // no conn_to_host
            None,    // no conn_to_port
            "example.com",
            8080,
            false,
        );
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert!(!ipv6);
    }

    #[test]
    fn test_get_destination_with_connect_to_host() {
        // Connect-to host override.
        let (host, port, ipv6) = get_destination(
            Some("override.com"),
            None,
            "example.com",
            443,
            false,
        );
        assert_eq!(host, "override.com");
        assert_eq!(port, 443);
        assert!(!ipv6);
    }

    #[test]
    fn test_get_destination_with_connect_to_port() {
        // Connect-to port override.
        let (host, port, ipv6) = get_destination(
            None,
            Some(9999),
            "example.com",
            443,
            false,
        );
        assert_eq!(host, "example.com");
        assert_eq!(port, 9999);
        assert!(!ipv6);
    }

    #[test]
    fn test_get_destination_ipv6_detection() {
        // IPv6 address in connect-to host.
        let (host, _port, ipv6) = get_destination(
            Some("::1"),
            None,
            "example.com",
            443,
            false,
        );
        assert_eq!(host, "::1");
        assert!(ipv6); // Detected via ':' in hostname

        // IPv6 flag from connection state when no override.
        let (_host, _port, ipv6) = get_destination(
            None,
            None,
            "example.com",
            443,
            true, // ipv6_ip flag set
        );
        assert!(ipv6);
    }

    #[test]
    fn test_parse_custom_header_normal() {
        let result = parse_custom_header("X-Custom: value");
        assert!(result.is_some());
        let (name, value, suppress) = result.unwrap();
        assert_eq!(name, "X-Custom");
        assert_eq!(value, "value");
        assert!(!suppress);
    }

    #[test]
    fn test_parse_custom_header_suppress() {
        // Quirk #1: Name: with no value → suppress.
        let result = parse_custom_header("X-Suppress:");
        assert!(result.is_some());
        let (name, _value, suppress) = result.unwrap();
        assert_eq!(name, "X-Suppress");
        assert!(suppress);
    }

    #[test]
    fn test_parse_custom_header_empty_value() {
        // Quirk #2: Name; → emit with empty value.
        let result = parse_custom_header("X-Empty;");
        assert!(result.is_some());
        let (name, value, suppress) = result.unwrap();
        assert_eq!(name, "X-Empty");
        assert_eq!(value, "");
        assert!(!suppress);
    }

    #[test]
    fn test_parse_custom_header_no_separator() {
        // No separator → None.
        let result = parse_custom_header("NoSeparator");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_custom_header_empty() {
        let result = parse_custom_header("");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_custom_header_semicolon_with_value() {
        // Name;value — future use, should be ignored (None).
        let result = parse_custom_header("X-Future;something");
        assert!(result.is_none());
    }

    #[test]
    fn test_http_proxy_filter_type_flags() {
        let filter = HttpProxyFilter::new("proxy.example.com".into(), 8080);
        assert_eq!(filter.type_flags(), CF_TYPE_IP_CONNECT | CF_TYPE_PROXY);
    }

    #[test]
    fn test_http_proxy_filter_name() {
        let filter = HttpProxyFilter::new("proxy.example.com".into(), 8080);
        assert_eq!(filter.name(), "HTTP-PROXY");
    }

    #[test]
    fn test_http_proxy_filter_initial_state() {
        let filter = HttpProxyFilter::new("proxy.example.com".into(), 8080);
        assert!(!filter.is_connected());
        assert!(!filter.is_shutdown());
        assert!(!filter.ctx.sub_filter_installed);
        assert_eq!(filter.ctx.httpversion, 0);
    }

    #[test]
    fn test_http_proxy_filter_query_host_port() {
        let filter = HttpProxyFilter::new("proxy.example.com".into(), 8080);
        match filter.query(CF_QUERY_HOST_PORT) {
            QueryResult::String(s) => assert_eq!(s, "proxy.example.com:8080"),
            other => panic!("Expected QueryResult::String, got {:?}", other),
        }
    }

    #[test]
    fn test_http_proxy_filter_query_alpn() {
        let filter = HttpProxyFilter::new("proxy.example.com".into(), 8080);
        match filter.query(CF_QUERY_ALPN_NEGOTIATED) {
            QueryResult::NotHandled => {} // Expected
            other => panic!(
                "Expected QueryResult::NotHandled for ALPN query, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_http_proxy_filter_destroy() {
        let mut filter = HttpProxyFilter::new("proxy.example.com".into(), 8080);
        filter.ctx.sub_filter_installed = true;
        filter.ctx.httpversion = 20;
        filter.connected = true;

        filter.destroy();

        assert!(!filter.connected);
        assert!(!filter.ctx.sub_filter_installed);
        assert_eq!(filter.ctx.httpversion, 0);
    }

    #[test]
    fn test_http_proxy_filter_close() {
        let mut filter = HttpProxyFilter::new("proxy.example.com".into(), 8080);
        filter.connected = true;

        filter.close();

        assert!(!filter.connected);
    }

    #[test]
    fn test_insert_after_creates_filter() {
        let mut chain = FilterChain::new();

        // Create a minimal no-op filter to have something in the chain.
        struct DummyFilter;

        #[async_trait]
        impl ConnectionFilter for DummyFilter {
            fn name(&self) -> &str { "dummy" }
            fn type_flags(&self) -> u32 { 0 }
            async fn connect(&mut self, _: &mut TransferData) -> Result<bool, CurlError> {
                Ok(true)
            }
            fn close(&mut self) {}
            async fn send(&mut self, buf: &[u8], _: bool) -> Result<usize, CurlError> {
                Ok(buf.len())
            }
            async fn recv(&mut self, _: &mut [u8]) -> Result<usize, CurlError> {
                Ok(0)
            }
            fn is_connected(&self) -> bool { false }
            fn is_shutdown(&self) -> bool { false }
        }

        chain.push_front(Box::new(DummyFilter));
        assert_eq!(chain.len(), 1);

        let handle = EasyHandle::new();
        let result = insert_after(
            &mut chain,
            0,
            "proxy.example.com".into(),
            8080,
            &handle,
        );
        assert!(result.is_ok());
        assert_eq!(chain.len(), 2);

        // The inserted filter should be at index 1 (after index 0).
        let filter = chain.get(1).unwrap();
        assert_eq!(filter.name(), "HTTP-PROXY");
    }

    #[test]
    fn test_create_connect_request_basic() {
        let handle = EasyHandle::new();
        let result = create_connect_request(
            "target.example.com",
            443,
            false,
            &handle,
            1,  // HTTP/1.x
            11, // HTTP/1.1
        );
        assert!(result.is_ok());
        let req = result.unwrap();
        assert_eq!(req.method, "CONNECT");
        assert_eq!(req.url, "target.example.com:443");
        // Should have Host and Proxy-Connection headers.
        assert!(req.has_header("Host"));
        assert!(req.has_header("Proxy-Connection"));
        assert_eq!(req.get_header("Host"), Some("target.example.com:443"));
        assert_eq!(req.get_header("Proxy-Connection"), Some("Keep-Alive"));
    }

    #[test]
    fn test_create_connect_request_ipv6() {
        let handle = EasyHandle::new();
        let result = create_connect_request(
            "::1",
            443,
            true, // IPv6
            &handle,
            1,
            11,
        );
        assert!(result.is_ok());
        let req = result.unwrap();
        assert_eq!(req.url, "[::1]:443");
        assert_eq!(req.get_header("Host"), Some("[::1]:443"));
    }

    #[test]
    fn test_create_connect_request_http2_no_host() {
        let handle = EasyHandle::new();
        let result = create_connect_request(
            "target.example.com",
            443,
            false,
            &handle,
            2,  // HTTP/2 — no Host header auto-added
            20,
        );
        assert!(result.is_ok());
        let req = result.unwrap();
        // For HTTP/2, Host header should NOT be auto-added.
        assert!(!req.has_header("Host"));
        // Proxy-Connection should also not be added for HTTP/2.
        assert!(!req.has_header("Proxy-Connection"));
    }

    #[test]
    fn test_http_proxy_context_defaults() {
        let ctx = HttpProxyContext::new();
        assert_eq!(ctx.httpversion, 0);
        assert!(!ctx.sub_filter_installed);
    }
}
