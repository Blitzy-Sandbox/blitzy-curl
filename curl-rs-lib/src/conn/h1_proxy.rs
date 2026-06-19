//! HTTP/1.x `CONNECT` tunnel connection filter — the Rust rewrite of curl's
//! `lib/cf-h1-proxy.c` / `lib/cf-h1-proxy.h`.
//!
//! This filter establishes an HTTP/1.0 or HTTP/1.1 `CONNECT` tunnel through a
//! forward proxy. It is spliced into the connection-filter chain **above** the
//! proxy transport (the socket / TLS-to-proxy filter) and **below** the
//! origin-facing filters (origin TLS, then the protocol engine). Its job:
//!
//! 1. Bring the filter below it (the leg to the proxy) up.
//! 2. Send a `CONNECT host:port HTTP/1.x` request to the proxy.
//! 3. Read and parse the proxy's response — handling `407` proxy-auth
//!    challenges (including the multi-pass NTLM / Negotiate handshake that
//!    triggers a follow-up `CONNECT`), `Connection: close`, and the body of a
//!    non-2xx response that must be consumed so the connection can be reused.
//! 4. On a `2xx` response, become a **fully transparent pass-through**: every
//!    `send` / `recv` / `query` is forwarded to the filter below, so the origin
//!    TLS filter and the protocol engine layered above tunnel through the proxy
//!    without ever knowing it is there.
//!
//! # Ownership split (who builds the request, who runs the state machine)
//!
//! curl's `lib/http_proxy.c` (`Curl_http_proxy_get_destination` /
//! `Curl_http_proxy_create_CONNECT`) builds the `CONNECT` request bytes, while
//! `lib/cf-h1-proxy.c` owns the HTTP/1 send/receive/parse state machine and the
//! auth-retry loop. In the Rust workspace [`crate::proxy`] deliberately does
//! **not** expose a request-builder function (its module docs state the
//! byte-for-byte `CONNECT` request "is built by the connection filter in
//! `crate::conn`, not here"); it owns only the [`crate::proxy::Proxy`] handle
//! and its `proxy_auth` hook. Consequently this file reproduces the exact wire
//! format of the request locally (see [`CfH1Proxy::build_connect_request`],
//! faithful to `Curl_http_proxy_create_CONNECT`, `lib/http_proxy.c` L197-271)
//! and owns the state machine, while the per-scheme `Proxy-Authorization`
//! generation and the multi-pass decision are delegated to a
//! [`ProxyConnectAuth`] provider supplied by the engine.
//!
//! # The async collapse (the central C → Rust transformation)
//!
//! curl drives `cf_h1_proxy_connect` re-entrantly from the multi loop: each call
//! advances the `H1_TUNNEL_*` state machine a little, returning `*done = FALSE`
//! while it waits for socket readiness, and is re-invoked when the socket is
//! ready. Under Tokio that whole "return for more multi" loop **collapses into a
//! single [`ConnectionFilter::connect`]`.await`**: the future resolves exactly
//! when the C code would have set `*done = TRUE` and `cf->connected`. The 407
//! multi-pass auth round — which in C returns to the multi loop after a
//! close+reopen — becomes an ordinary inner `await` loop here. curl's
//! `cf_h1_proxy_adjust_pollset` (which arms the pollset for read/write while the
//! request drains / the response arrives) has no analog and is intentionally
//! omitted — Tokio's reactor provides that readiness.
//!
//! # Memory safety (AAP §0.7.1)
//!
//! This module contains **zero** `unsafe` and opts into
//! `#![forbid(unsafe_code)]` so the rule is compiler-enforced. curl's
//! `struct dynbuf rcvbuf` becomes a safe [`DynBuf`] capped at the same
//! [`DYN_PROXY_CONNECT_HEADERS`] (16384-byte) limit; the request bytes are an
//! owned `Vec<u8>`; response parsing uses safe slicing. There is no raw pointer
//! and no manual `free` — every buffer and the owned `next` filter release
//! themselves on `Drop` (replacing C's `tunnel_free` / `cf_h1_proxy_destroy`).
//!
//! # Feature gating
//!
//! curl compiles `cf-h1-proxy.c` under
//! `#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)`. The Rust
//! analog is the `proxy` **and** `http` Cargo features (both default-on); the
//! `pub mod h1_proxy;` declaration in `crate::conn` carries that
//! `#[cfg(all(feature = "proxy", feature = "http"))]` gate, so a build with
//! either disabled drops this filter cleanly.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use crate::auth::{parse_auth_header, pick_one_auth, AuthState, CURLAUTH_BASIC};
use crate::conn::filters::{
    BoxFuture, CfState, ConnectionFilter, FilterChain, FilterData, CF_TYPE_IP_CONNECT,
    CF_TYPE_PROXY,
};
use crate::error::{CurlError, Result};
use crate::proxy::Proxy;
use crate::util::dynbuf::{DynBuf, DYN_PROXY_CONNECT_HEADERS};
use crate::util::sendf;

// =============================================================================
// PHASE 1 — tunnel state (← `h1_tunnel_state` enum, `struct h1_tunnel_state`)
// =============================================================================

/// The CONNECT tunnel's progress — the Rust mirror of C's `h1_tunnel_state`
/// enum (`cf-h1-proxy.c` L44-51).
///
/// The states are visited in order INIT → CONNECT → RECEIVE → RESPONSE and then
/// terminate in either ESTABLISHED (a `2xx` response — the tunnel is up and the
/// filter is transparent) or FAILED (a non-`2xx` final response — the caller
/// must close this filter and bootstrap anew). A 407 multi-pass auth round
/// returns RESPONSE → INIT for the next attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelState {
    /// `H1_TUNNEL_INIT` — initial / reset state; the request has not been built.
    Init,
    /// `H1_TUNNEL_CONNECT` — the CONNECT request is being sent.
    Connect,
    /// `H1_TUNNEL_RECEIVE` — the CONNECT response is being received.
    Receive,
    /// `H1_TUNNEL_RESPONSE` — the CONNECT response has been received completely.
    Response,
    /// `H1_TUNNEL_ESTABLISHED` — a `2xx` was received; the tunnel is open.
    Established,
    /// `H1_TUNNEL_FAILED` — a non-`2xx` final response, or a fatal error.
    Failed,
}

/// The receive-loop sub-state — the Rust mirror of C's `enum keeponval`
/// (`cf-h1-proxy.c` L60-64).
///
/// While receiving, the loop either keeps reading header bytes
/// ([`Keepon::Connect`]), drains and discards a non-2xx response body so the
/// connection can be reused ([`Keepon::Ignore`]), or has reached the end of the
/// response ([`Keepon::Done`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Keepon {
    /// `KEEPON_DONE` — the full response has been read; stop the receive loop.
    Done,
    /// `KEEPON_CONNECT` — keep reading the response headers.
    Connect,
    /// `KEEPON_IGNORE` — keep reading, but discard the response body.
    Ignore,
}

// =============================================================================
// Proxy-authentication provider — the auth half of the CONNECT exchange
// =============================================================================

/// The hook through which the CONNECT state machine drives proxy
/// authentication.
///
/// In C, proxy auth for the tunnel is split across `lib/http.c`
/// (`Curl_http_output_auth` generates the `Proxy-Authorization` header that
/// `Curl_http_proxy_create_CONNECT` then emits; `Curl_http_input_auth` records a
/// `Proxy-Authenticate` challenge; `Curl_http_auth_act` decides whether a
/// follow-up request — `data->req.newurl` — is needed). The challenge/response
/// schemes (Digest, NTLM, Negotiate) keep per-connection state and need the
/// caller's credentials, so that machinery lives outside this filter. This
/// trait is the seam: **this file owns the send/receive/parse state machine and
/// the retry loop**, while an implementor owns the per-scheme header generation
/// and the multi-pass decision.
///
/// The four methods map one-to-one onto the C touch-points:
///
/// * [`authorization`](Self::authorization) ⇐ the `Proxy-Authorization` line
///   produced by `Curl_http_output_auth` and emitted by
///   `Curl_http_proxy_create_CONNECT` (`lib/http_proxy.c` L239-244).
/// * [`input_challenge`](Self::input_challenge) ⇐ `Curl_http_input_auth`
///   (`cf-h1-proxy.c` L290), fed one `Proxy-Authenticate` value per call.
/// * [`act`](Self::act) ⇐ `Curl_http_auth_act` (`cf-h1-proxy.c` L552), called
///   once after a non-2xx response completes; `true` means "send another
///   CONNECT" (curl's `data->req.newurl`).
/// * [`authproblem`](Self::authproblem) ⇐ `data->state.authproblem`, read by
///   the body-handling logic (`cf-h1-proxy.c` L381) to decide whether to drain
///   the 407 body (keeping the connection alive for a retry) or give up.
///
/// Implementors must be [`Send`] so the filter can move across Tokio tasks.
pub trait ProxyConnectAuth: Send {
    /// The `Proxy-Authorization` header **line** (terminated with `\r\n`, e.g.
    /// `"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"`) to include in the next
    /// CONNECT request, or [`None`] to send none. Called by
    /// [`CfH1Proxy::build_connect_request`] for each attempt.
    fn authorization(&mut self) -> Result<Option<String>>;

    /// Feed one `Proxy-Authenticate` header value (the text after the
    /// `Proxy-Authenticate:` name, already trimmed) from a `407` response.
    fn input_challenge(&mut self, header_value: &str) -> Result<()>;

    /// Act on the accumulated challenges after a non-2xx response completes.
    /// Returns `true` if a follow-up CONNECT should be issued (a multi-pass
    /// round or a newly-picked scheme). `http_proxy_code` is the proxy's status
    /// code (e.g. `407`).
    fn act(&mut self, http_proxy_code: i32) -> Result<bool>;

    /// Whether the supplied credentials were rejected (curl's
    /// `data->state.authproblem`). When `true` for a 407, the body is **not**
    /// drained (there is no point keeping the connection for a retry).
    fn authproblem(&self) -> bool;

    /// Whether a mid-handshake connection close from the proxy should be treated
    /// as a recoverable disconnect (so the CONNECT is retried) rather than a hard
    /// failure — the C condition `data->set.proxyauth && data->state.authproxy.avail
    /// && data->state.aptr.proxyuserpwd` (`cf-h1-proxy.c` L451-456). The default
    /// is `false` (no proxy auth ⇒ a close is fatal).
    fn close_means_retry(&self) -> bool {
        false
    }
}

/// The "no proxy authentication" provider — the default when the connection
/// carries no proxy credentials.
///
/// It never emits a `Proxy-Authorization` header, ignores any challenge, and
/// never requests a follow-up, so a `407` from the proxy ends the tunnel as a
/// plain failure (matching curl when no proxy auth is configured).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoProxyAuth;

impl ProxyConnectAuth for NoProxyAuth {
    fn authorization(&mut self) -> Result<Option<String>> {
        Ok(None)
    }

    fn input_challenge(&mut self, _header_value: &str) -> Result<()> {
        Ok(())
    }

    fn act(&mut self, _http_proxy_code: i32) -> Result<bool> {
        Ok(false)
    }

    fn authproblem(&self) -> bool {
        false
    }
}

/// The standard `Proxy-Authorization` provider for the **Basic** scheme, the one
/// scheme [`crate::proxy::Proxy::proxy_auth`] can produce without a
/// server challenge.
///
/// It mirrors curl's default `CURLAUTH_*` flow for the schemes that need no
/// per-connection cryptographic state:
///
/// * If the application asked for exactly Basic and credentials are present,
///   the Basic line is emitted **proactively** on the first CONNECT (curl
///   sends Basic without waiting for a challenge when the method is fixed).
/// * Otherwise the first CONNECT carries no auth; on the `407` the
///   `Proxy-Authenticate` challenge is parsed ([`parse_auth_header`]), a scheme
///   is picked ([`pick_one_auth`]), and — when Basic is chosen and credentials
///   exist — the Basic line is prepared and a follow-up CONNECT is requested.
///
/// The challenge/response schemes (Digest, NTLM, Negotiate) require
/// per-connection state and the actual cryptographic message generation, which
/// is outside this provider's remit; for those the engine supplies its own
/// [`ProxyConnectAuth`] implementation. This provider therefore drives only the
/// Basic path and reports [`authproblem`](ProxyConnectAuth::authproblem) when
/// Basic credentials are rejected.
pub struct StandardProxyAuth {
    /// The parsed proxy configuration (host/credentials + the `proxy_auth`
    /// hook). Source of the Basic `Proxy-Authorization` line.
    proxy: Proxy,
    /// The proxy-side auth state (`data->state.authproxy`): the wanted mask, the
    /// picked scheme, and the advertised availability accumulated from
    /// challenges.
    state: AuthState,
    /// The `CURLOPT_PROXYAUTH` mask the application requested.
    authmask: u32,
    /// The `Proxy-Authorization` line to send on the next CONNECT, once known.
    current_header: Option<String>,
    /// `true` once a Basic challenge for the already-picked Basic scheme came
    /// back — i.e. the credentials were rejected (curl's `authproblem`).
    authproblem: bool,
}

impl StandardProxyAuth {
    /// Build a Basic-scheme proxy-auth provider for `proxy`, honoring the
    /// `CURLOPT_PROXYAUTH` `authmask`.
    ///
    /// When the mask is exactly [`CURLAUTH_BASIC`] and the proxy carries
    /// credentials, the Basic header is primed immediately so it rides the first
    /// CONNECT (curl's proactive-Basic behavior); otherwise it is left empty
    /// until a `407` challenge selects Basic.
    #[must_use]
    pub fn new(proxy: Proxy, authmask: u32) -> Self {
        let mut me = Self {
            proxy,
            state: AuthState::new(authmask),
            authmask,
            current_header: None,
            authproblem: false,
        };
        // Proactive Basic: when the method is fixed to Basic and we have
        // credentials, curl sends the header without waiting for a challenge.
        if authmask == CURLAUTH_BASIC {
            if let Ok(Some(line)) = me.proxy.proxy_auth(CURLAUTH_BASIC) {
                me.current_header = Some(line);
            }
        }
        me
    }

    /// Whether the proxy carries any credential (user or password).
    fn have_credentials(&self) -> bool {
        // `Proxy::proxy_auth` returns `None` without credentials; probe it once
        // through the Basic mask to learn whether a header could be produced.
        matches!(self.proxy.proxy_auth(CURLAUTH_BASIC), Ok(Some(_)))
    }
}

impl ProxyConnectAuth for StandardProxyAuth {
    fn authorization(&mut self) -> Result<Option<String>> {
        Ok(self.current_header.clone())
    }

    fn input_challenge(&mut self, header_value: &str) -> Result<()> {
        // Accumulate advertised methods into `avail` and detect a rejected
        // already-picked Basic credential (curl's `Curl_http_input_auth`).
        let parsed = parse_auth_header(&mut self.state, header_value);
        if parsed.authproblem {
            self.authproblem = true;
        }
        Ok(())
    }

    fn act(&mut self, _http_proxy_code: i32) -> Result<bool> {
        // Already authenticated successfully on this header? Nothing to do.
        if self.authproblem {
            return Ok(false);
        }
        // Pick a scheme from what the proxy advertised. `pick_one_auth` narrows
        // `state.picked` to a single bit and clears `avail`, exactly as curl's
        // `pickoneauth` does.
        let picked = pick_one_auth(&mut self.state, self.authmask);
        if !picked {
            // Nothing acceptable was offered → no follow-up.
            return Ok(false);
        }
        // We can only generate Basic here; for that scheme, prepare the header
        // and ask for one more CONNECT carrying it. (Digest/NTLM/Negotiate are
        // handled by an engine-supplied provider, not this one.)
        if self.state.picked == CURLAUTH_BASIC && self.have_credentials() {
            // Avoid an infinite loop: only retry with Basic if we have not
            // already sent it.
            if self.current_header.is_none() {
                self.current_header = self.proxy.proxy_auth(CURLAUTH_BASIC)?;
                return Ok(self.current_header.is_some());
            }
        }
        Ok(false)
    }

    fn authproblem(&self) -> bool {
        self.authproblem
    }

    fn close_means_retry(&self) -> bool {
        // C: proxy auth requested (`authmask`) AND a challenge was advertised
        // (`state.avail`) AND credentials are present (`aptr.proxyuserpwd`).
        self.authmask != 0 && self.state.avail != 0 && self.have_credentials()
    }
}

// =============================================================================
// Configuration captured at construction (the bits the C reads from
// `cf->conn` / `data->set` at connect time)
// =============================================================================

/// The inputs the CONNECT filter needs that, in C, are read from the easy
/// handle and connection mid-connect.
///
/// Because the Rust filter layer threads only a minimal [`FilterData`]
/// (verbosity + error buffer) — not the whole easy handle — these are captured
/// at construction by `crate::conn`'s SETUP builder (the analog of curl reading
/// `cf->conn->host`, `data->set.str[STRING_USERAGENT]`, `CURLOPT_PROXYHEADER`,
/// etc. inside `Curl_http_proxy_create_CONNECT`).
pub struct H1ProxyConfig {
    /// The tunnel target hostname (curl's `Curl_http_proxy_get_destination`
    /// `*phostname`). For an IPv6 literal this is the bare address (no
    /// brackets); see [`tunnel_ipv6`](Self::tunnel_ipv6).
    pub tunnel_host: String,
    /// The tunnel target port (curl's `*pport`).
    pub tunnel_port: u16,
    /// Whether [`tunnel_host`](Self::tunnel_host) is an IPv6 literal, so the
    /// request-line authority brackets it as `[host]:port` (curl's `*pipv6_ip`).
    pub tunnel_ipv6: bool,
    /// The HTTP/1 minor version for the request line: `0` for a
    /// `CURLPROXY_HTTP_1_0` proxy, `1` otherwise (curl's `http_minor`,
    /// `cf-h1-proxy.c` L223).
    pub http_minor: u8,
    /// The `User-Agent` value (`data->set.str[STRING_USERAGENT]`); when present
    /// and non-empty and not overridden by a custom proxy header, it is emitted.
    pub user_agent: Option<String>,
    /// The `CURLOPT_PROXYHEADER` lines (already selected for the CONNECT request
    /// via curl's `ProxyUse::Connect`). Each is `"Name: value"`, or the quirk
    /// forms `"Name:"` (suppress) / `"Name;"` (send empty) honored by
    /// [`CfH1Proxy::build_connect_request`].
    pub custom_headers: Vec<String>,
    /// The origin scheme name, used only for the
    /// `"<scheme> cannot be done over CONNECT"` diagnostic.
    pub scheme_name: String,
    /// Whether the origin scheme may be tunneled over CONNECT — the negation of
    /// curl's `PROTOPT_NOTCPPROXY` (`cf-h1-proxy.c` L107). When `false` the
    /// filter fails with [`CurlError::UnsupportedProtocol`].
    pub scheme_can_tunnel: bool,
    /// The overall CONNECT timeout. `None` means "no deadline" (curl's
    /// `Curl_timeleft_ms` returning ≥ 0 forever). Maps to curl's proxy CONNECT
    /// timeout; exceeding it yields [`CurlError::OperationTimedout`].
    pub connect_timeout: Option<Duration>,
    /// The proxy-authentication provider (default [`NoProxyAuth`]).
    pub auth: Box<dyn ProxyConnectAuth>,
}

impl H1ProxyConfig {
    /// A configuration tunneling to `tunnel_host:tunnel_port` over HTTP/1.1 with
    /// no authentication, no custom headers, no user-agent, and no timeout. Use
    /// the `with_*` builders to populate the rest.
    #[must_use]
    pub fn new(tunnel_host: impl Into<String>, tunnel_port: u16) -> Self {
        Self {
            tunnel_host: tunnel_host.into(),
            tunnel_port,
            tunnel_ipv6: false,
            http_minor: 1,
            user_agent: None,
            custom_headers: Vec::new(),
            scheme_name: "https".to_string(),
            scheme_can_tunnel: true,
            connect_timeout: None,
            auth: Box::new(NoProxyAuth),
        }
    }

    /// Mark the tunnel target as an IPv6 literal (brackets it in the authority).
    #[must_use]
    pub fn with_ipv6(mut self, ipv6: bool) -> Self {
        self.tunnel_ipv6 = ipv6;
        self
    }

    /// Set the HTTP/1 minor version (`0` for an HTTP/1.0 proxy, else `1`).
    #[must_use]
    pub fn with_http_minor(mut self, minor: u8) -> Self {
        self.http_minor = minor;
        self
    }

    /// Set the `User-Agent` to advertise on the CONNECT request.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: Option<String>) -> Self {
        self.user_agent = user_agent;
        self
    }

    /// Set the `CURLOPT_PROXYHEADER` custom header lines.
    #[must_use]
    pub fn with_custom_headers(mut self, headers: Vec<String>) -> Self {
        self.custom_headers = headers;
        self
    }

    /// Set the origin scheme name and whether it may be tunneled.
    #[must_use]
    pub fn with_scheme(mut self, name: impl Into<String>, can_tunnel: bool) -> Self {
        self.scheme_name = name.into();
        self.scheme_can_tunnel = can_tunnel;
        self
    }

    /// Set the overall CONNECT timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the proxy-authentication provider.
    #[must_use]
    pub fn with_auth(mut self, auth: Box<dyn ProxyConnectAuth>) -> Self {
        self.auth = auth;
        self
    }
}

// =============================================================================
// The per-connect tunnel context (← `struct h1_tunnel_state`, L54-71)
// =============================================================================

/// The mutable state of one CONNECT attempt — the Rust mirror of C's
/// `struct h1_tunnel_state` (`cf-h1-proxy.c` L54-71).
struct H1TunnelState {
    /// The tunnel progress (C: `tunnel_state`).
    tunnel_state: TunnelState,
    /// The receive-loop sub-state (C: `keepon`).
    keepon: Keepon,
    /// The response-header accumulation buffer, capped at
    /// [`DYN_PROXY_CONNECT_HEADERS`] (C: `rcvbuf`). One header line is built up
    /// here at a time.
    rcvbuf: DynBuf,
    /// The fully built CONNECT request bytes awaiting send (C: `request_data`).
    request_data: Vec<u8>,
    /// Bytes of `request_data` already written (C: `nsent`).
    nsent: usize,
    /// Number of header lines processed (C: `headerlines`); line 1 is the
    /// status line.
    headerlines: usize,
    /// The proxy's HTTP status code (C: `data->info.httpproxycode` /
    /// `data->req.httpcode`). `0` until the status line is parsed.
    httpproxycode: i32,
    /// Remaining bytes of a non-2xx response body to read and ignore (C: `cl`).
    cl: i64,
    /// Whether the response used `Transfer-Encoding: chunked` (C:
    /// `chunked_encoding`).
    chunked_encoding: bool,
    /// Whether the proxy signalled the connection must close (C:
    /// `close_connection`), via `Connection: close`, `Proxy-Connection: close`,
    /// or by closing the socket during a 407 with auth available.
    close_connection: bool,
    /// Mid-fold parse flag: the previous line ended and may be continued by a
    /// folded (leading-whitespace) continuation line (C: `maybe_folded`).
    maybe_folded: bool,
    /// Mid-fold parse flag: a folded continuation is being unfolded; leading
    /// blanks are collapsed to one space (C: `leading_unfold`).
    leading_unfold: bool,
    /// Whether a follow-up CONNECT is pending (C: `data->req.newurl`), set by
    /// the auth provider's [`ProxyConnectAuth::act`].
    newurl: bool,
    /// State for skipping a chunked non-2xx body (the Rust analog of C's
    /// `struct Curl_chunker ch`).
    chunk: ChunkSkipper,
    /// The CONNECT response header lines, surfaced to the engine so it can feed
    /// them to the application header callback with the
    /// `CLIENTWRITE_HEADER | CLIENTWRITE_CONNECT` semantics (C: `single_header`
    /// → `Curl_client_write`). Each entry includes its trailing CRLF.
    response_headers: Vec<Vec<u8>>,
}

impl H1TunnelState {
    /// Allocate a fresh tunnel context in the INIT state with an empty,
    /// capacity-`DYN_PROXY_CONNECT_HEADERS` receive buffer (C: `tunnel_init` +
    /// `tunnel_reinit`).
    fn new() -> Self {
        let mut me = Self {
            tunnel_state: TunnelState::Init,
            keepon: Keepon::Connect,
            rcvbuf: DynBuf::curlx_dyn_init(DYN_PROXY_CONNECT_HEADERS),
            request_data: Vec::new(),
            nsent: 0,
            headerlines: 0,
            httpproxycode: 0,
            cl: 0,
            chunked_encoding: false,
            close_connection: false,
            maybe_folded: false,
            leading_unfold: false,
            newurl: false,
            chunk: ChunkSkipper::new(),
            response_headers: Vec::new(),
        };
        me.reinit();
        me
    }

    /// Reset the per-attempt fields back to INIT (C: `tunnel_reinit`, L83-99),
    /// keeping the allocated buffers.
    fn reinit(&mut self) {
        self.rcvbuf.curlx_dyn_reset();
        self.request_data.clear();
        self.tunnel_state = TunnelState::Init;
        self.keepon = Keepon::Connect;
        self.nsent = 0;
        self.headerlines = 0;
        self.cl = 0;
        self.chunked_encoding = false;
        self.close_connection = false;
        self.maybe_folded = false;
        self.leading_unfold = false;
        self.chunk = ChunkSkipper::new();
        // NOTE: `httpproxycode`, `newurl`, and `response_headers` persist across
        // a reinit within one connect (curl clears `httpcode`/`newurl` at the
        // FAILED/ESTABLISHED transitions and `start_CONNECT` respectively); they
        // are reset explicitly at those points.
    }

    /// Whether the tunnel reached ESTABLISHED (C: `tunnel_is_established`).
    fn is_established(&self) -> bool {
        self.tunnel_state == TunnelState::Established
    }

    /// Whether the tunnel reached FAILED (C: `tunnel_is_failed`).
    fn is_failed(&self) -> bool {
        self.tunnel_state == TunnelState::Failed
    }
}

// =============================================================================
// Minimal chunked-body skipper (← the `Curl_chunker` used only to *ignore* a
// non-2xx 407 body so the connection can be reused)
// =============================================================================

/// A tiny chunked-transfer consumer used solely to **discard** the body of a
/// non-2xx (typically `407`) CONNECT response, so the proxy connection can be
/// reused for the follow-up CONNECT.
///
/// It implements just enough of RFC 7230 chunked framing to find the end: a hex
/// chunk-size line, that many data bytes, a trailing CRLF, repeated until a
/// zero-size chunk, then the trailing CRLF after the (empty) trailer. Chunk
/// extensions (`;name=value`) are tolerated by stopping the size scan at the
/// first non-hex character. This never surfaces the body — it only needs to
/// know when the body ends (curl's `Curl_httpchunk_is_done`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChunkSkipper {
    /// The current phase of the chunk parser.
    phase: ChunkPhase,
    /// Bytes remaining in the current data chunk.
    remaining: u64,
    /// Accumulator for the in-progress hex size line.
    size_acc: u64,
    /// Whether at least one hex digit has been seen for the current size.
    size_seen: bool,
    /// Whether the parser has consumed the terminal zero-size chunk.
    done: bool,
}

/// The phase of [`ChunkSkipper`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkPhase {
    /// Reading the hex chunk-size line.
    Size,
    /// Skipping to the end of the size line after the hex digits / extension.
    SizeTail,
    /// Reading `remaining` data bytes.
    Data,
    /// Consuming the CR of the CRLF that follows a data chunk.
    DataCr,
    /// Consuming the LF of the CRLF that follows a data chunk.
    DataLf,
    /// After the zero-size chunk: consuming the final CR.
    TrailerCr,
    /// After the zero-size chunk: consuming the final LF.
    TrailerLf,
}

impl ChunkSkipper {
    /// A fresh skipper positioned at the start of a chunk-size line.
    fn new() -> Self {
        Self {
            phase: ChunkPhase::Size,
            remaining: 0,
            size_acc: 0,
            size_seen: false,
            done: false,
        }
    }

    /// Whether the full chunked body has been consumed (C:
    /// `Curl_httpchunk_is_done`).
    fn is_done(&self) -> bool {
        self.done
    }

    /// Feed one byte of the chunked body, advancing the parser (the C
    /// `Curl_httpchunk_read`). Completion is observed separately via
    /// [`is_done`](Self::is_done), mirroring curl's two-call idiom.
    fn feed(&mut self, byte: u8) {
        match self.phase {
            ChunkPhase::Size => {
                if let Some(d) = hex_val(byte) {
                    self.size_acc = self.size_acc.saturating_mul(16).saturating_add(u64::from(d));
                    self.size_seen = true;
                } else if byte == b'\n' {
                    self.start_data_or_trailer();
                } else if byte == b'\r' {
                    // wait for the LF
                } else {
                    // chunk extension or stray byte: skip to end of line
                    self.phase = ChunkPhase::SizeTail;
                }
            }
            ChunkPhase::SizeTail => {
                if byte == b'\n' {
                    self.start_data_or_trailer();
                }
            }
            ChunkPhase::Data => {
                // Consume one data byte.
                self.remaining = self.remaining.saturating_sub(1);
                if self.remaining == 0 {
                    self.phase = ChunkPhase::DataCr;
                }
            }
            ChunkPhase::DataCr => {
                // Expect CR; tolerate a bare LF.
                if byte == b'\n' {
                    self.begin_next_size();
                } else {
                    self.phase = ChunkPhase::DataLf;
                }
            }
            ChunkPhase::DataLf => {
                // The LF after the data CRLF; begin the next size line.
                self.begin_next_size();
            }
            ChunkPhase::TrailerCr => {
                if byte == b'\n' {
                    self.done = true;
                } else {
                    self.phase = ChunkPhase::TrailerLf;
                }
            }
            ChunkPhase::TrailerLf => {
                self.done = true;
            }
        }
    }

    /// After a size line terminates, move to data (non-zero size) or to the
    /// trailer (zero size = last chunk).
    fn start_data_or_trailer(&mut self) {
        if self.size_seen && self.size_acc > 0 {
            self.remaining = self.size_acc;
            self.phase = ChunkPhase::Data;
        } else {
            // Zero-size (last) chunk: consume the final CRLF then we are done.
            self.phase = ChunkPhase::TrailerCr;
        }
    }

    /// Reset the size accumulator for the next chunk-size line.
    fn begin_next_size(&mut self) {
        self.size_acc = 0;
        self.size_seen = false;
        self.phase = ChunkPhase::Size;
    }
}

/// The value of an ASCII hex digit, or `None`.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// =============================================================================
// Header parsing helpers (safe replacements for `checkprefix`,
// `Curl_copy_header_value`, `Curl_compareheader`)
// =============================================================================

/// Whether `line` begins with `prefix`, compared ASCII-case-insensitively (the
/// C `checkprefix`). `prefix` is given without its value (e.g. `"Content-Length:"`).
fn checkprefix(prefix: &str, line: &[u8]) -> bool {
    let p = prefix.as_bytes();
    line.len() >= p.len() && line[..p.len()].eq_ignore_ascii_case(p)
}

/// The header value following the first `:` in `line`, trimmed of surrounding
/// ASCII whitespace and any trailing CR/LF (the C `Curl_copy_header_value`).
/// Returns an empty string when there is no colon or no value.
fn copy_header_value(line: &[u8]) -> &[u8] {
    match line.iter().position(|&b| b == b':') {
        Some(idx) => {
            let mut v = &line[idx + 1..];
            // Trim leading blanks.
            while let [first, rest @ ..] = v {
                if *first == b' ' || *first == b'\t' {
                    v = rest;
                } else {
                    break;
                }
            }
            // Trim trailing CR/LF and blanks.
            while let [rest @ .., last] = v {
                if matches!(last, b'\r' | b'\n' | b' ' | b'\t') {
                    v = rest;
                } else {
                    break;
                }
            }
            v
        }
        None => &[],
    }
}

/// Whether the header `line` is named `name` and its value contains the token
/// `token`, both compared ASCII-case-insensitively (the C `Curl_compareheader`).
/// The value is split on commas and ASCII whitespace and each token compared
/// whole, so `Connection: keep-alive, close` matches `close`.
fn compareheader(line: &[u8], name: &str, token: &str) -> bool {
    if !checkprefix(name, line) {
        return false;
    }
    let value = copy_header_value(line);
    value
        .split(|&b| b == b',' || b == b' ' || b == b'\t')
        .any(|tok| !tok.is_empty() && tok.eq_ignore_ascii_case(token.as_bytes()))
}

/// The parsed name of a custom header line — the run of bytes up to the first
/// `:` or `;` (the C `curlx_str_cspn(&ptr, &name, ";:")`).
fn custom_header_name(line: &str) -> &str {
    let end = line
        .find([':', ';'])
        .unwrap_or(line.len());
    line[..end].trim_end_matches([' ', '\t'])
}

/// Whether the custom (`CURLOPT_PROXYHEADER`) list contains a header named
/// `name` (case-insensitive) — the C `Curl_checkProxyheaders`. Used to suppress
/// the auto `Host` / `User-Agent` / `Proxy-Connection` headers when the user
/// supplied their own.
fn custom_has_header(custom: &[String], name: &str) -> bool {
    custom
        .iter()
        .any(|line| custom_header_name(line).eq_ignore_ascii_case(name))
}

/// The wire form a custom header line should take, after applying curl's two
/// quirks (`dynhds_add_custom`, `lib/http_proxy.c` L85-122):
///
/// * `"Name: value"` → emit `"Name: value\r\n"`.
/// * `"Name:"` (empty value) → **suppress** (emit nothing).
/// * `"Name;"` (semicolon, nothing after) → emit an empty header `"Name:\r\n"`.
/// * anything else (no `:`/`;`, or junk after `;`) → ignore.
fn custom_header_wire(line: &str) -> Option<String> {
    // Find the first ':' or ';' separator.
    let sep_pos = line.find([':', ';'])?;
    let name = line[..sep_pos].trim_end_matches([' ', '\t']);
    if name.is_empty() {
        return None; // no name → ignore
    }
    let sep = line.as_bytes()[sep_pos];
    let rest = &line[sep_pos + 1..];
    if sep == b':' {
        let value = rest.trim_start_matches([' ', '\t']);
        if value.is_empty() {
            None // quirk #1: suppress
        } else {
            // Trim a trailing CRLF the caller may have included; we add our own.
            let value = value.trim_end_matches(['\r', '\n']);
            Some(format!("{name}: {value}\r\n"))
        }
    } else {
        // sep == ';'
        let after = rest.trim_start_matches([' ', '\t']);
        if after.is_empty() {
            Some(format!("{name}:\r\n")) // quirk #2: empty header
        } else {
            None // reserved for future use → ignore
        }
    }
}

// =============================================================================
// The CONNECT tunnel filter (← `struct Curl_cfilter` + `Curl_cft_h1_proxy`)
// =============================================================================

/// The HTTP/1.x `CONNECT` tunnel connection filter — the Rust replacement for
/// C's `Curl_cft_h1_proxy` vtable plus the `struct h1_tunnel_state` it carries
/// in `cf->ctx`.
///
/// It owns the chain-link/lifecycle [`CfState`] every filter embeds, the
/// per-attempt [`H1TunnelState`], the static [`H1ProxyConfig`] captured at
/// construction, and the [`ProxyConnectAuth`] provider. Once the tunnel is
/// ESTABLISHED the filter is transparent: every `send` / `recv` / `query` uses
/// the trait's pass-through default and is forwarded to the proxy transport
/// below.
pub struct CfH1Proxy {
    /// Chain link (`next`) + `connected` / `shutdown` bits (C: `Curl_cfilter`).
    state: CfState,
    /// The CONNECT tunnel state (C: `cf->ctx`, a `struct h1_tunnel_state`).
    tunnel: H1TunnelState,
    /// Static configuration captured at construction.
    config: H1ProxyConfig,
}

impl CfH1Proxy {
    /// Format the request-line authority `host:port`, bracketing an IPv6 literal
    /// — the C `curl_maprintf("%s%s%s:%d", ipv6?"[":"", host, ipv6?"]":"", port)`
    /// (`lib/http_proxy.c` L212-213).
    fn authority(&self) -> String {
        if self.config.tunnel_ipv6 {
            format!("[{}]:{}", self.config.tunnel_host, self.config.tunnel_port)
        } else {
            format!("{}:{}", self.config.tunnel_host, self.config.tunnel_port)
        }
    }

    /// Build the full CONNECT request bytes — the Rust analog of
    /// `Curl_http_proxy_create_CONNECT` + `Curl_h1_req_write_head`
    /// (`lib/http_proxy.c` L197-271). The header order matches curl's exact wire
    /// order so a proxy (or a test) sees byte-identical requests:
    ///
    /// ```text
    /// CONNECT <authority> HTTP/1.<minor>\r\n
    /// Host: <authority>\r\n                     (HTTP/1, unless custom Host)
    /// Proxy-Authorization: ...\r\n              (when the auth provider has one)
    /// User-Agent: <ua>\r\n                      (when set and not overridden)
    /// Proxy-Connection: Keep-Alive\r\n          (HTTP/1, unless overridden)
    /// <custom CURLOPT_PROXYHEADER lines>
    /// \r\n
    /// ```
    fn build_connect_request(&mut self) -> Result<Vec<u8>> {
        let authority = self.authority();
        let custom = &self.config.custom_headers;

        let mut req = Vec::with_capacity(128);
        // Request line. `http_version_major` is always 1 for this filter, so the
        // only variation is the minor version (1.0 for a CURLPROXY_HTTP_1_0
        // proxy, else 1.1).
        let minor = if self.config.http_minor == 0 { 0 } else { 1 };
        req.extend_from_slice(b"CONNECT ");
        req.extend_from_slice(authority.as_bytes());
        req.extend_from_slice(if minor == 0 {
            b" HTTP/1.0\r\n"
        } else {
            b" HTTP/1.1\r\n"
        });

        // Host: — HTTP/1 only, unless the user supplied a custom Host (then the
        // custom one is emitted in the custom-header loop instead).
        if !custom_has_header(custom, "Host") {
            req.extend_from_slice(b"Host: ");
            req.extend_from_slice(authority.as_bytes());
            req.extend_from_slice(b"\r\n");
        }

        // Proxy-Authorization (a complete line incl. CRLF, when present).
        if let Some(line) = self.config.auth.authorization()? {
            req.extend_from_slice(line.as_bytes());
        }

        // User-Agent — when set, non-empty, and not overridden.
        if !custom_has_header(custom, "User-Agent") {
            if let Some(ua) = self.config.user_agent.as_deref() {
                if !ua.is_empty() {
                    req.extend_from_slice(b"User-Agent: ");
                    req.extend_from_slice(ua.as_bytes());
                    req.extend_from_slice(b"\r\n");
                }
            }
        }

        // Proxy-Connection: Keep-Alive — HTTP/1 only, unless overridden.
        if !custom_has_header(custom, "Proxy-Connection") {
            req.extend_from_slice(b"Proxy-Connection: Keep-Alive\r\n");
        }

        // Custom CURLOPT_PROXYHEADER lines, applying the suppress / empty quirks.
        for line in custom {
            if let Some(wire) = custom_header_wire(line) {
                req.extend_from_slice(wire.as_bytes());
            }
        }

        // End of headers.
        req.extend_from_slice(b"\r\n");
        Ok(req)
    }
}

// =============================================================================
// PHASE 2 — build + stage the CONNECT request, then send it
// =============================================================================

impl CfH1Proxy {
    /// Build the CONNECT request and prime the send state — the Rust analog of
    /// `start_CONNECT` (`cf-h1-proxy.c` L201-235).
    ///
    /// Like the C, it first clears any pending follow-up marker
    /// (`Curl_safefree(data->req.newurl)` — the multi-pass loop relies on this so
    /// the `do/while(newurl)` terminates once a request has been (re)built), then
    /// builds the request bytes and resets the byte counters.
    fn start_connect(&mut self, data: &mut FilterData) -> Result<()> {
        // Clear the follow-up marker (C: `Curl_safefree(data->req.newurl)`).
        // This is the *only* place `newurl` is cleared, so the multi-pass loop's
        // `while(newurl)` condition stays armed until a fresh request is built.
        self.tunnel.newurl = false;

        // Build the request bytes (the wire format lives in
        // `build_connect_request`, faithful to `Curl_http_proxy_create_CONNECT`).
        let request = match self.build_connect_request() {
            Ok(req) => req,
            Err(e) => {
                sendf::failf(&mut data.error_buffer, "Failed sending CONNECT to proxy");
                return Err(e);
            }
        };

        let authority = self.authority();
        sendf::infof(
            data.verbose,
            &format!("Establish HTTP proxy tunnel to {authority}"),
        );

        // Reset the send state (C: `curlx_dyn_reset(&ts->request_data)`,
        // `ts->nsent = 0`, `ts->headerlines = 0`).
        self.tunnel.request_data = request;
        self.tunnel.nsent = 0;
        self.tunnel.headerlines = 0;
        Ok(())
    }

    /// Send the staged CONNECT request fully through the filter below — the Rust
    /// analog of `send_CONNECT` (`cf-h1-proxy.c` L237-270).
    ///
    /// curl sends what it can each re-entrant call, advancing `ts->nsent` and
    /// returning `*done = FALSE` until the whole request has drained. Under Tokio
    /// the "come back later" loop collapses: this awaits until the request is
    /// fully written. A transient [`CurlError::Again`] from the transport is
    /// retried after yielding (the C treats `CURLE_AGAIN` as "wrote nothing,
    /// not done"); the overall CONNECT deadline bounds the wait.
    async fn send_connect(
        &mut self,
        data: &mut FilterData,
        deadline: Option<Instant>,
    ) -> Result<()> {
        // Take the request bytes out so the send loop can borrow them while it
        // also mutably borrows `self.state.next` (disjoint-field borrows aside,
        // moving avoids any aliasing question). They are restored afterwards.
        let request = std::mem::take(&mut self.tunnel.request_data);
        let total = request.len();
        let mut sent = self.tunnel.nsent;

        let mut outcome: Result<()> = Ok(());
        while sent < total {
            // Overall CONNECT timeout (C checks `Curl_timeleft_ms` per pass).
            if deadline_expired(deadline) {
                sendf::failf(
                    &mut data.error_buffer,
                    "Proxy CONNECT aborted due to timeout",
                );
                outcome = Err(CurlError::OperationTimedout);
                break;
            }

            // One send attempt, optionally bounded by the remaining deadline.
            let res: Result<usize> = {
                let next = match self.state.next.as_mut() {
                    Some(n) => n,
                    None => {
                        outcome = Err(CurlError::SendError);
                        break;
                    }
                };
                let fut = next.send(&request[sent..], false);
                match deadline {
                    Some(dl) => match tokio::time::timeout(remaining(dl), fut).await {
                        Ok(r) => r,
                        Err(_elapsed) => {
                            sendf::failf(
                                &mut data.error_buffer,
                                "Proxy CONNECT aborted due to timeout",
                            );
                            outcome = Err(CurlError::OperationTimedout);
                            break;
                        }
                    },
                    None => fut.await,
                }
            };

            match res {
                Ok(n) => sent += n,
                // Transport not ready: yield and retry (C: `CURLE_AGAIN` → not
                // done, come back).
                Err(CurlError::Again) => tokio::task::yield_now().await,
                Err(e) => {
                    sendf::failf(&mut data.error_buffer, "Failed sending CONNECT to proxy");
                    outcome = Err(e);
                    break;
                }
            }
        }

        self.tunnel.nsent = sent;
        self.tunnel.request_data = request;
        outcome
    }
}

// =============================================================================
// PHASE 3 — receive + parse the CONNECT response (byte at a time)
// =============================================================================

impl CfH1Proxy {
    /// Interpret one completed response header line held in `rcvbuf` — the Rust
    /// analog of `on_resp_header` (`cf-h1-proxy.c` L272-348).
    ///
    /// The branches are mutually exclusive (an `if/else if` chain in C):
    /// `Proxy-Authenticate` (on 407) feeds the auth provider; `Content-Length` is
    /// ignored for 2xx (RFC 7231 4.3.6) else recorded as the body length to
    /// drain; `Connection: close` / `Proxy-Connection: close` mark the connection
    /// for closing; `Transfer-Encoding` is ignored for 2xx else (when `chunked`)
    /// arms the chunk skipper; finally the `HTTP/1.x NNN` status line records the
    /// proxy status code.
    fn on_resp_header(&mut self, data: &mut FilterData) -> Result<()> {
        // Copy the line out so we can both read it and mutate `self.tunnel`.
        let line = self.tunnel.rcvbuf.curlx_dyn_ptr().to_vec();
        let code = self.tunnel.httpproxycode;

        if checkprefix("Proxy-authenticate:", &line) && code == 407 {
            // Feed the challenge to the proxy-auth provider (C:
            // `Curl_http_input_auth(data, /*proxy*/ TRUE, auth)`).
            let value = copy_header_value(&line);
            let value = String::from_utf8_lossy(value).into_owned();
            self.config.auth.input_challenge(&value)?;
        } else if checkprefix("Content-Length:", &line) {
            if code / 100 == 2 {
                // "A client MUST ignore any Content-Length ... in a successful
                // response to CONNECT." RFC 7231 4.3.6.
                sendf::infof(
                    data.verbose,
                    &format!("Ignoring Content-Length in CONNECT {code:03} response"),
                );
            } else {
                match parse_content_length(copy_header_value(&line)) {
                    Some(n) => self.tunnel.cl = n,
                    None => {
                        sendf::failf(&mut data.error_buffer, "Unsupported Content-Length value");
                        return Err(CurlError::WeirdServerReply);
                    }
                }
            }
        } else if compareheader(&line, "Connection:", "close") {
            self.tunnel.close_connection = true;
        } else if checkprefix("Transfer-Encoding:", &line) {
            if code / 100 == 2 {
                // Likewise ignored for a successful CONNECT (RFC 7231 4.3.6).
                sendf::infof(
                    data.verbose,
                    &format!("Ignoring Transfer-Encoding in CONNECT {code:03} response"),
                );
            } else if compareheader(&line, "Transfer-Encoding:", "chunked") {
                sendf::infof(data.verbose, "CONNECT responded chunked");
                self.tunnel.chunked_encoding = true;
                // Reset the chunk engine (C: `Curl_httpchunk_reset`).
                self.tunnel.chunk = ChunkSkipper::new();
            }
        } else if compareheader(&line, "Proxy-Connection:", "close") {
            self.tunnel.close_connection = true;
        } else if is_status_line(&line) {
            // Store the proxy's HTTP status code (C: `data->info.httpproxycode =
            // k->httpcode = ...`).
            self.tunnel.httpproxycode = parse_status_code(&line);
        }
        Ok(())
    }

    /// Process one full header line just terminated in `rcvbuf` — the Rust analog
    /// of `single_header` (`cf-h1-proxy.c` L349-417).
    ///
    /// It first surfaces the raw line to the engine (so it can forward it to the
    /// application header callback with the
    /// `CLIENTWRITE_HEADER | CLIENTWRITE_CONNECT` semantics), then — if the line
    /// is the blank end-of-headers line — decides whether to drain a 407 body
    /// ([`Keepon::Ignore`]) or finish ([`Keepon::Done`]); otherwise it dispatches
    /// to [`on_resp_header`](Self::on_resp_header) and resets `rcvbuf` for the
    /// next line.
    fn single_header(&mut self, data: &mut FilterData) -> Result<()> {
        self.tunnel.headerlines += 1;

        // Surface the header line to the engine (C: `Curl_client_write` with
        // `CLIENTWRITE_HEADER | CLIENTWRITE_CONNECT`, plus `CLIENTWRITE_STATUS`
        // for the first line). The engine forwards it to the app callback; here
        // we collect it (the filter layer has no direct callback handle).
        let line = self.tunnel.rcvbuf.curlx_dyn_ptr().to_vec();
        self.tunnel.response_headers.push(line);

        // Is this the blank line that ends the response headers?
        let first = self.tunnel.rcvbuf.curlx_dyn_ptr().first().copied();
        if matches!(first, Some(b'\r') | Some(b'\n')) {
            // End of response headers from the proxy.
            if self.tunnel.httpproxycode == 407 && !self.config.auth.authproblem() {
                // A 407 with no auth problem: ignore the whole response body so
                // the connection can be reused for the authenticated retry.
                self.tunnel.keepon = Keepon::Ignore;
                if self.tunnel.cl != 0 {
                    sendf::infof(
                        data.verbose,
                        &format!("Ignore {} bytes of response-body", self.tunnel.cl),
                    );
                } else if self.tunnel.chunked_encoding {
                    sendf::infof(data.verbose, "Ignore chunked response-body");
                } else {
                    // No length info and not chunked: the body ends with the
                    // close, so we cannot keep the connection alive — bail now.
                    self.tunnel.keepon = Keepon::Done;
                }
            } else {
                self.tunnel.keepon = Keepon::Done;
            }
            return Ok(());
        }

        // A normal header line: interpret then clear the buffer for the next.
        self.on_resp_header(data)?;
        self.tunnel.rcvbuf.curlx_dyn_reset();
        Ok(())
    }

    /// Feed one received byte into the response parser — the Rust analog of the
    /// per-byte body of the `recv_CONNECT_resp` loop (`cf-h1-proxy.c` L466-543),
    /// covering body-ignoring, RFC 7230 obs-fold handling, the
    /// [`DYN_PROXY_CONNECT_HEADERS`] cap, and end-of-line detection.
    fn process_byte(&mut self, byte: u8, data: &mut FilterData) -> Result<()> {
        // While ignoring a non-2xx (407) body, count it down / chunk-skip it.
        if self.tunnel.keepon == Keepon::Ignore {
            if self.tunnel.cl != 0 {
                // Content-Length framed: decrement and stop at zero.
                self.tunnel.cl -= 1;
                if self.tunnel.cl <= 0 {
                    self.tunnel.keepon = Keepon::Done;
                }
            } else if self.tunnel.chunked_encoding {
                // Parse the chunk byte, then test for end-of-body (C:
                // `Curl_httpchunk_read` followed by `Curl_httpchunk_is_done`).
                self.tunnel.chunk.feed(byte);
                if self.tunnel.chunk.is_done() {
                    sendf::infof(data.verbose, "chunk reading DONE");
                    self.tunnel.keepon = Keepon::Done;
                }
            }
            return Ok(());
        }

        // Obs-fold: a line just ended and the next byte decides if it continues.
        if self.tunnel.maybe_folded {
            if is_blank(byte) {
                // A folded continuation: drop the just-added CRLF and unfold.
                http_to_fold(&mut self.tunnel.rcvbuf);
                self.tunnel.leading_unfold = true;
            } else {
                // The previous line is complete: process it, then handle `byte`.
                self.single_header(data)?;
            }
            self.tunnel.maybe_folded = false;
        }

        // Collapse a folded continuation's leading whitespace to a single space.
        if self.tunnel.leading_unfold {
            if is_blank(byte) {
                // Skip additional leading blanks.
                return Ok(());
            }
            if self.tunnel.rcvbuf.curlx_dyn_addn(b" ").is_err() {
                sendf::failf(&mut data.error_buffer, "CONNECT response too large");
                return Err(CurlError::RecvError);
            }
            self.tunnel.leading_unfold = false;
        }

        // Accumulate the byte, enforcing the response-header size cap.
        if self.tunnel.rcvbuf.curlx_dyn_addn(&[byte]).is_err() {
            sendf::failf(&mut data.error_buffer, "CONNECT response too large");
            return Err(CurlError::RecvError);
        }

        // Not the end of a line yet (LF is the line terminator).
        if byte != 0x0a {
            return Ok(());
        }

        // LF seen: if the line *starts* with a newline it is the blank
        // end-of-headers line — process it now. Otherwise the line might be
        // folded by the next byte, so defer until we peek it.
        let first = self.tunnel.rcvbuf.curlx_dyn_ptr().first().copied();
        if matches!(first, Some(b'\r') | Some(b'\n')) {
            self.single_header(data)?;
        } else {
            self.tunnel.maybe_folded = true;
        }
        Ok(())
    }

    /// Receive and parse the whole CONNECT response — the Rust analog of
    /// `recv_CONNECT_resp` (`cf-h1-proxy.c` L418-545).
    ///
    /// curl reads **one byte at a time** so it never over-reads past the blank
    /// line into the tunnelled stream (critical for keep-alive and the multi-pass
    /// auth retry). This awaits bytes from the filter below until the parser
    /// reaches [`Keepon::Done`]; on a clean non-2xx completion it asks the auth
    /// provider whether a follow-up CONNECT is needed
    /// (C: `Curl_http_auth_act` → `data->req.newurl`).
    async fn recv_connect_resp(
        &mut self,
        data: &mut FilterData,
        deadline: Option<Instant>,
    ) -> Result<()> {
        let mut hard_error = false;

        while self.tunnel.keepon != Keepon::Done {
            // Overall CONNECT timeout (C: `Curl_timeleft` per H1_CONNECT pass).
            if deadline_expired(deadline) {
                sendf::failf(
                    &mut data.error_buffer,
                    "Proxy CONNECT aborted due to timeout",
                );
                return Err(CurlError::OperationTimedout);
            }

            // Read exactly one byte (C: `Curl_conn_recv(..., &byte, 1, ...)`).
            let mut buf = [0u8; 1];
            let res: Result<usize> = {
                let next = match self.state.next.as_mut() {
                    Some(n) => n,
                    None => return Err(CurlError::RecvError),
                };
                let fut = next.recv(&mut buf);
                match deadline {
                    Some(dl) => match tokio::time::timeout(remaining(dl), fut).await {
                        Ok(r) => r,
                        Err(_elapsed) => {
                            sendf::failf(
                                &mut data.error_buffer,
                                "Proxy CONNECT aborted due to timeout",
                            );
                            return Err(CurlError::OperationTimedout);
                        }
                    },
                    None => fut.await,
                }
            };

            let nread = match res {
                Ok(n) => n,
                // Transport drained: yield and retry (C: `CURLE_AGAIN` → return
                // and be re-driven when readable).
                Err(CurlError::Again) => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(e) => {
                    self.tunnel.keepon = Keepon::Done;
                    return Err(e);
                }
            };

            if nread == 0 {
                // EOF from the proxy (C: `!nread`).
                if self.config.auth.close_means_retry() {
                    // Proxy auth was requested and available: treat as a "mere"
                    // disconnect that a retry can recover from.
                    self.tunnel.close_connection = true;
                    sendf::infof(data.verbose, "Proxy CONNECT connection closed");
                } else {
                    hard_error = true;
                    sendf::failf(&mut data.error_buffer, "Proxy CONNECT aborted");
                }
                self.tunnel.keepon = Keepon::Done;
                break;
            }

            self.process_byte(buf[0], data)?;
        }

        if hard_error {
            return Err(CurlError::RecvError);
        }

        // On a complete non-2xx response, let the auth provider decide whether a
        // follow-up CONNECT is warranted (C: `Curl_http_auth_act` sets newurl).
        if self.tunnel.httpproxycode / 100 != 2 {
            let code = self.tunnel.httpproxycode;
            self.tunnel.newurl = self.config.auth.act(code)?;
        }
        Ok(())
    }
}

// =============================================================================
// PHASE 4 — the CONNECT state machine + auth follow-ups (← `H1_CONNECT`)
// =============================================================================

impl CfH1Proxy {
    /// Drive INIT → CONNECT → RECEIVE → RESPONSE to ESTABLISHED or FAILED — the
    /// Rust analog of `H1_CONNECT` (`cf-h1-proxy.c` L557-660).
    ///
    /// curl runs this as a re-entrant `do { switch(state) } while(newurl)` that
    /// returns to the multi loop on every I/O wait and on the close+reopen auth
    /// dance. Under Tokio the I/O waits collapse into the awaits inside
    /// [`send_connect`](Self::send_connect) / [`recv_connect_resp`](Self::recv_connect_resp),
    /// and the close+reopen becomes an inline `self.close()` →
    /// `next.connect().await` within the same loop. The multi-pass terminator is
    /// `newurl`: each pass rebuilds the request (which clears `newurl`), so the
    /// loop ends once no follow-up is requested.
    async fn h1_connect(&mut self, data: &mut FilterData) -> Result<()> {
        if self.tunnel.is_established() {
            return Ok(());
        }
        if self.tunnel.is_failed() {
            // Need a filter close and a fresh bootstrap (C: returns RECV_ERROR).
            return Err(CurlError::RecvError);
        }

        let deadline = self.config.connect_timeout.map(|d| Instant::now() + d);

        // The `do { ... } while(newurl)` body. Each iteration is one full
        // INIT→CONNECT→RECEIVE→RESPONSE pass.
        let loop_result: Result<()> = loop {
            // Per-pass overall timeout (C: `if(Curl_timeleft_ms(data) < 0)`).
            if deadline_expired(deadline) {
                sendf::failf(
                    &mut data.error_buffer,
                    "Proxy CONNECT aborted due to timeout",
                );
                break Err(CurlError::OperationTimedout);
            }

            // INIT: build + stage the request, advance to CONNECT.
            if let Err(e) = self.start_connect(data) {
                break Err(e);
            }
            self.tunnel.tunnel_state = TunnelState::Connect;
            // CONNECT entry housekeeping (C: go_state CONNECT resets rcvbuf and
            // arms `keepon = KEEPON_CONNECT`).
            self.tunnel.rcvbuf.curlx_dyn_reset();
            self.tunnel.keepon = Keepon::Connect;

            // CONNECT: send the request to completion.
            if let Err(e) = self.send_connect(data, deadline).await {
                break Err(e);
            }
            self.tunnel.tunnel_state = TunnelState::Receive;

            // RECEIVE: read + parse the response to completion.
            if let Err(e) = self.recv_connect_resp(data, deadline).await {
                break Err(e);
            }
            self.tunnel.tunnel_state = TunnelState::Response;

            // RESPONSE: a follow-up CONNECT may be required (multi-pass auth).
            if self.tunnel.newurl {
                if self.tunnel.close_connection {
                    // Close this filter + the sub-chain, reconnect the leg to the
                    // proxy, then loop (C: close+open "Connect me again please").
                    sendf::infof(data.verbose, "Connect me again please");
                    self.close();
                    match self.state.next.as_mut() {
                        Some(next) => {
                            if let Err(e) = next.connect(data).await {
                                break Err(e);
                            }
                        }
                        None => break Err(CurlError::RecvError),
                    }
                    // `self.close()` already reset the tunnel to INIT.
                } else {
                    // Stay on the connection; reset for the next auth round.
                    self.tunnel.reinit();
                }
                // `newurl` stays set; the next pass's `start_connect` clears it
                // (mirrors the C `while(newurl)` continuation).
                continue;
            }

            // No follow-up: this is the final response.
            break Ok(());
        };

        // Translate the loop outcome into ESTABLISHED / FAILED (C: the code after
        // the `do/while` plus the `out:` label).
        match loop_result {
            Ok(()) => {
                if self.tunnel.httpproxycode / 100 != 2 {
                    // A non-2xx final response with no follow-up to try.
                    self.tunnel.newurl = false;
                    self.tunnel.tunnel_state = TunnelState::Failed;
                    let code = self.tunnel.httpproxycode;
                    sendf::failf(
                        &mut data.error_buffer,
                        &format!("CONNECT tunnel failed, response {code}"),
                    );
                    Err(CurlError::RecvError)
                } else {
                    // 2xx: success — the tunnel is open.
                    self.tunnel.tunnel_state = TunnelState::Established;
                    // C go_state(ESTABLISHED) emits this before the summary line.
                    sendf::infof(data.verbose, "CONNECT phase completed");
                    let code = self.tunnel.httpproxycode;
                    sendf::infof(
                        data.verbose,
                        &format!("CONNECT tunnel established, response {code}"),
                    );
                    Ok(())
                }
            }
            Err(e) => {
                // C `out:` label: any error transitions the tunnel to FAILED.
                self.tunnel.tunnel_state = TunnelState::Failed;
                Err(e)
            }
        }
    }

    /// The accumulated CONNECT response header lines (each including its trailing
    /// CRLF), surfaced for the engine to forward to the application header
    /// callback with curl's `CLIENTWRITE_HEADER | CLIENTWRITE_CONNECT` semantics.
    #[must_use]
    pub fn response_headers(&self) -> &[Vec<u8>] {
        &self.tunnel.response_headers
    }
}

// =============================================================================
// Free helpers used by the state machine
// =============================================================================

/// Whether `byte` is an HTTP "blank" (space or tab) — the C `ISBLANK`.
fn is_blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// Whether the overall CONNECT `deadline` has passed (C: `Curl_timeleft_ms < 0`).
fn deadline_expired(deadline: Option<Instant>) -> bool {
    matches!(deadline, Some(dl) if Instant::now() >= dl)
}

/// The time remaining until `deadline`, saturating at zero.
fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Unfold a header line for an obs-fold continuation — the Rust analog of
/// `Curl_http_to_fold` (`lib/http.c`): drop the trailing LF, then a trailing CR,
/// then any trailing blanks, so the folded continuation appends cleanly after a
/// single inserted space.
fn http_to_fold(buf: &mut DynBuf) {
    let mut len = buf.curlx_dyn_len();
    let bytes = buf.curlx_dyn_ptr();
    // Trim a trailing LF.
    if len > 0 && bytes[len - 1] == b'\n' {
        len -= 1;
    }
    // Trim a trailing CR.
    if len > 0 && buf.curlx_dyn_ptr()[len - 1] == b'\r' {
        len -= 1;
    }
    // Trim trailing blanks.
    while len > 0 && is_blank(buf.curlx_dyn_ptr()[len - 1]) {
        len -= 1;
    }
    // `setlen` only ever shrinks here, so it cannot fail the cap check.
    let _ = buf.curlx_dyn_setlen(len);
}

/// Parse a `Content-Length` value (already trimmed) as a non-negative integer —
/// the C `curlx_str_numblanks`. Rejects empty, non-numeric, and negative inputs.
fn parse_content_length(value: &[u8]) -> Option<i64> {
    if value.is_empty() {
        return None;
    }
    let s = core::str::from_utf8(value).ok()?;
    s.parse::<i64>().ok().filter(|&n| n >= 0)
}

/// Whether `line` is a well-formed `HTTP/1.x NNN ...` status line — the exact C
/// predicate from `on_resp_header` (`!strncmp(header, "HTTP/1.", 7)` with a
/// `'0'`/`'1'` minor, a space, three digits, then a non-digit).
fn is_status_line(line: &[u8]) -> bool {
    line.len() >= 13
        && line[0..7].eq_ignore_ascii_case(b"HTTP/1.")
        && (line[7] == b'0' || line[7] == b'1')
        && line[8] == b' '
        && line[9].is_ascii_digit()
        && line[10].is_ascii_digit()
        && line[11].is_ascii_digit()
        && !line[12].is_ascii_digit()
}

/// Extract the three-digit status code from a line already validated by
/// [`is_status_line`].
fn parse_status_code(line: &[u8]) -> i32 {
    i32::from(line[9] - b'0') * 100
        + i32::from(line[10] - b'0') * 10
        + i32::from(line[11] - b'0')
}

// =============================================================================
// PHASE 5 — the filter vtable (← `Curl_cft_h1_proxy`, `cf_h1_proxy_connect`)
// =============================================================================

impl ConnectionFilter for CfH1Proxy {
    /// C: the vtable `name` field — `"H1-PROXY"` (`cf-h1-proxy.c` L758).
    fn name(&self) -> &'static str {
        "H1-PROXY"
    }

    fn cf_state(&self) -> &CfState {
        &self.state
    }

    fn cf_state_mut(&mut self) -> &mut CfState {
        &mut self.state
    }

    /// C: the vtable `flags` field — `CF_TYPE_IP_CONNECT | CF_TYPE_PROXY`
    /// (`cf-h1-proxy.c` L759).
    fn flags(&self) -> u32 {
        CF_TYPE_IP_CONNECT | CF_TYPE_PROXY
    }

    /// Bring the proxy leg up, then drive the CONNECT tunnel to ESTABLISHED — the
    /// Rust analog of `cf_h1_proxy_connect` (`cf-h1-proxy.c` L663-707).
    ///
    /// Order matches the C exactly: if already connected, done; otherwise connect
    /// the filter below (the leg to the proxy) **first**; then the one-time
    /// `tunnel_init` scheme guard; then the [`h1_connect`](CfH1Proxy::h1_connect)
    /// state machine. On success the filter is marked connected and the now-idle
    /// tunnel buffers are released — the filter becomes a transparent
    /// pass-through (`send`/`recv`/`query` use the trait defaults).
    fn connect<'a>(&'a mut self, data: &'a mut FilterData) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Already established (C: `if(cf->connected) { *done = TRUE; ... }`).
            if self.state.connected {
                return Ok(());
            }

            // Connect the sub-chain first (C: `cf->next->cft->do_connect`).
            match self.state.next.as_mut() {
                Some(next) => next.connect(data).await?,
                // No transport below: cannot tunnel (mirror the def-recv code
                // used by the chain when nothing is connected).
                None => return Err(CurlError::RecvError),
            }

            // One-time tunnel init: reject schemes that cannot be tunnelled
            // (C: `tunnel_init` checks `PROTOPT_NOTCPPROXY`).
            if !self.config.scheme_can_tunnel {
                sendf::failf(
                    &mut data.error_buffer,
                    &format!("{} cannot be done over CONNECT", self.config.scheme_name),
                );
                return Err(CurlError::UnsupportedProtocol);
            }
            sendf::infof(data.verbose, "allocate connect buffer");

            // Drive the CONNECT state machine to ESTABLISHED or FAILED.
            self.h1_connect(data).await?;

            if self.tunnel.is_established() {
                // C: `cf->connected = TRUE` + `tunnel_free` (the tunnel is done;
                // the filter is now transparent). We keep `response_headers` for
                // the engine but release the working buffers.
                self.state.connected = true;
                self.tunnel.rcvbuf.curlx_dyn_free();
                self.tunnel.request_data = Vec::new();
                Ok(())
            } else {
                // Not established and no error surfaced: signal "close + rebuild".
                Err(CurlError::RecvError)
            }
        })
    }

    /// Reset the tunnel and close the sub-chain — the Rust analog of
    /// `cf_h1_proxy_close` (`cf-h1-proxy.c` L745-756): clear `connected`, reset
    /// the tunnel state to INIT, then close the filter below.
    fn close(&mut self) {
        self.state.connected = false;
        // C: `h1_tunnel_go_state(..., H1_TUNNEL_INIT, ...)` ⇒ `tunnel_reinit`.
        self.tunnel.reinit();
        if let Some(next) = self.state.next.as_mut() {
            next.close();
        }
    }

    // NOTE: `shutdown`, `data_pending`, `send`, `recv`, `cntrl`, `is_alive`,
    // `keep_alive`, and `query` are intentionally left as the trait defaults:
    // once the tunnel is ESTABLISHED this filter is fully transparent and every
    // operation is forwarded to the filter below (C: the vtable wires these to
    // `Curl_cf_def_*` / the shared proxy query). curl's `cf_h1_proxy_adjust_pollset`
    // has no analog under Tokio (the reactor provides readiness) and is omitted.
}

impl Drop for CfH1Proxy {
    /// C: `cf_h1_proxy_destroy` → `tunnel_free`. The owned [`DynBuf`], the request
    /// buffer, and the `next` filter all release on drop; this is here to mirror
    /// the C destructor explicitly and to document that no manual teardown
    /// (`free`) is needed — Rust ownership handles it.
    fn drop(&mut self) {
        self.tunnel.rcvbuf.curlx_dyn_free();
    }
}

// =============================================================================
// PHASE 6 — the insert constructor (← `Curl_cf_h1_proxy_insert_after`)
// =============================================================================

/// Create an HTTP/1.x CONNECT-tunnel filter from `config`, ready to be spliced
/// into a connection-filter chain.
///
/// The returned filter starts unconnected with no `next`; [`FilterChain`]
/// wires its `next` when it is inserted. This is the building block used by
/// [`h1_proxy_insert_after`] and by `conn::connect`'s SETUP builder.
#[must_use]
pub fn create_h1_proxy_filter(config: H1ProxyConfig) -> Box<dyn ConnectionFilter> {
    Box::new(CfH1Proxy {
        state: CfState::new(),
        tunnel: H1TunnelState::new(),
        config,
    })
}

/// Splice an HTTP/1.x CONNECT-tunnel filter into `chain` immediately after the
/// filter at `after_index` — the Rust analog of `Curl_cf_h1_proxy_insert_after`
/// (`cf-h1-proxy.c` L775-787).
///
/// `after_index` is the position of the filter the CONNECT filter must sit
/// directly above: in curl this is the transport (socket / Happy-Eyeballs) leg
/// to the proxy, so the CONNECT request travels on the raw connection and the
/// origin TLS filter layers above the established tunnel. Returns
/// [`CurlError::BadFunctionArgument`] when no filter exists at `after_index`
/// (propagated from [`FilterChain::insert_after_index`]).
pub fn h1_proxy_insert_after(
    chain: &mut FilterChain,
    after_index: usize,
    config: H1ProxyConfig,
) -> Result<()> {
    let cf = create_h1_proxy_filter(config);
    chain.insert_after_index(after_index, cf)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CURLAUTH_DIGEST;
    use crate::proxy::{CurlProxyType, Proxy};
    use std::sync::{Arc, Mutex};

    /// Drive a future to completion on a fresh current-thread runtime with the
    /// timer enabled (so `tokio::time::timeout` / `sleep` work — needed by the
    /// CONNECT-timeout test). Mirrors the helper in the `filters`/`haproxy` tests.
    fn run<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("failed to build test runtime")
            .block_on(fut)
    }

    // ---- scripted proxy transport mock --------------------------------------

    /// A leaf transport mock standing in for the connection to the proxy.
    ///
    /// It serves a scripted response **one byte at a time** (matching the
    /// filter's byte-by-byte read), records every byte the filter sends, and
    /// supports the close+reopen auth dance: each [`connect`](ConnectionFilter::connect)
    /// after the first advances to the next response *segment* (so segment 0 is
    /// the pre-close stream and segment 1 the post-reopen stream).
    struct MockProxy {
        state: CfState,
        segments: Vec<Vec<u8>>,
        gen: usize,
        pos: usize,
        opened: bool,
        stall: bool,
        sent: Arc<Mutex<Vec<u8>>>,
        connects: Arc<Mutex<usize>>,
    }

    impl MockProxy {
        fn new(segments: Vec<Vec<u8>>) -> Self {
            Self {
                state: CfState::new(),
                segments,
                gen: 0,
                pos: 0,
                opened: false,
                stall: false,
                sent: Arc::new(Mutex::new(Vec::new())),
                connects: Arc::new(Mutex::new(0)),
            }
        }

        /// A mock whose `recv` never produces data (drives the timeout path).
        fn stalling() -> Self {
            let mut me = Self::new(Vec::new());
            me.stall = true;
            me
        }

        fn sent_handle(&self) -> Arc<Mutex<Vec<u8>>> {
            Arc::clone(&self.sent)
        }

        fn connects_handle(&self) -> Arc<Mutex<usize>> {
            Arc::clone(&self.connects)
        }
    }

    impl ConnectionFilter for MockProxy {
        fn name(&self) -> &'static str {
            "MOCK-PROXY"
        }
        fn cf_state(&self) -> &CfState {
            &self.state
        }
        fn cf_state_mut(&mut self) -> &mut CfState {
            &mut self.state
        }
        fn connect<'a>(&'a mut self, _data: &'a mut FilterData) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                if self.opened {
                    // A reconnect (the close+reopen dance): advance the segment.
                    self.gen += 1;
                    self.pos = 0;
                } else {
                    self.opened = true;
                }
                *self.connects.lock().expect("connects lock") += 1;
                self.state.connected = true;
                Ok(())
            })
        }
        fn send<'a>(&'a mut self, buf: &'a [u8], _eos: bool) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                self.sent.lock().expect("sent lock").extend_from_slice(buf);
                Ok(buf.len())
            })
        }
        fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                if self.stall {
                    // Never resolves before the CONNECT deadline.
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    return Ok(0);
                }
                let seg = match self.segments.get(self.gen) {
                    Some(s) => s,
                    None => return Ok(0),
                };
                if self.pos >= seg.len() {
                    return Ok(0); // EOF for this segment
                }
                let byte = seg[self.pos];
                self.pos += 1;
                if !buf.is_empty() {
                    buf[0] = byte;
                }
                Ok(1)
            })
        }
    }

    // ---- construction helpers ----------------------------------------------

    /// A standalone filter (no transport below) for request-builder tests.
    fn cfg_filter(config: H1ProxyConfig) -> CfH1Proxy {
        CfH1Proxy {
            state: CfState::new(),
            tunnel: H1TunnelState::new(),
            config,
        }
    }

    /// A filter wired over `next` for connect/state-machine tests.
    fn filter_with(next: Box<dyn ConnectionFilter>, config: H1ProxyConfig) -> CfH1Proxy {
        CfH1Proxy {
            state: CfState::with_next(next),
            tunnel: H1TunnelState::new(),
            config,
        }
    }

    /// Drive `connect` to completion and return `(result, error_buffer)`.
    fn drive_connect(filter: &mut CfH1Proxy) -> (Result<()>, Option<String>) {
        let mut data = FilterData::with_verbose(false);
        let r = run(filter.connect(&mut data));
        (r, data.error_buffer)
    }

    /// A test auth provider that returns a fixed `Proxy-Authorization` line.
    struct FixedAuth(Option<String>);
    impl ProxyConnectAuth for FixedAuth {
        fn authorization(&mut self) -> Result<Option<String>> {
            Ok(self.0.clone())
        }
        fn input_challenge(&mut self, _value: &str) -> Result<()> {
            Ok(())
        }
        fn act(&mut self, _code: i32) -> Result<bool> {
            Ok(false)
        }
        fn authproblem(&self) -> bool {
            false
        }
    }

    // ---- constants + vtable identity ---------------------------------------

    #[test]
    fn dyn_proxy_connect_headers_cap_is_16384() {
        // The rcvbuf cap must equal curl's exact DYN_PROXY_CONNECT_HEADERS.
        assert_eq!(DYN_PROXY_CONNECT_HEADERS, 16384);
    }

    #[test]
    fn name_and_flags_match_c_vtable() {
        let cf = cfg_filter(H1ProxyConfig::new("h", 1));
        assert_eq!(cf.name(), "H1-PROXY");
        assert_eq!(cf.flags(), CF_TYPE_IP_CONNECT | CF_TYPE_PROXY);
    }

    // ---- request builder (wire parity) -------------------------------------

    #[test]
    fn build_request_basic_is_byte_exact() {
        let mut cf = cfg_filter(
            H1ProxyConfig::new("example.com", 443)
                .with_user_agent(Some("curl/8.19.0".to_string())),
        );
        let req = cf.build_connect_request().expect("build");
        assert_eq!(
            req,
            b"CONNECT example.com:443 HTTP/1.1\r\n\
              Host: example.com:443\r\n\
              User-Agent: curl/8.19.0\r\n\
              Proxy-Connection: Keep-Alive\r\n\
              \r\n"
        );
    }

    #[test]
    fn build_request_ipv6_brackets_authority() {
        let mut cf = cfg_filter(H1ProxyConfig::new("::1", 8080).with_ipv6(true));
        let req = cf.build_connect_request().expect("build");
        assert_eq!(
            req,
            b"CONNECT [::1]:8080 HTTP/1.1\r\n\
              Host: [::1]:8080\r\n\
              Proxy-Connection: Keep-Alive\r\n\
              \r\n"
        );
    }

    #[test]
    fn build_request_http_1_0_minor() {
        let mut cf = cfg_filter(H1ProxyConfig::new("example.com", 443).with_http_minor(0));
        let req = cf.build_connect_request().expect("build");
        assert_eq!(
            req,
            b"CONNECT example.com:443 HTTP/1.0\r\n\
              Host: example.com:443\r\n\
              Proxy-Connection: Keep-Alive\r\n\
              \r\n"
        );
    }

    #[test]
    fn build_request_custom_header_quirks() {
        // "X-Normal: val" → emitted; "X-Suppress:" → suppressed; "X-Empty;" →
        // empty header; a custom "Host:" overrides (suppresses) the auto Host.
        let mut cf = cfg_filter(H1ProxyConfig::new("example.com", 443).with_custom_headers(vec![
            "X-Normal: val".to_string(),
            "X-Suppress:".to_string(),
            "X-Empty;".to_string(),
            "Host: custom:1".to_string(),
        ]));
        let req = cf.build_connect_request().expect("build");
        let text = String::from_utf8(req).expect("utf8");
        // Exact, deterministic wire form.
        assert_eq!(
            text,
            "CONNECT example.com:443 HTTP/1.1\r\n\
             Proxy-Connection: Keep-Alive\r\n\
             X-Normal: val\r\n\
             X-Empty:\r\n\
             Host: custom:1\r\n\
             \r\n"
        );
        // The auto Host must be gone and the suppressed header absent.
        assert!(!text.contains("Host: example.com:443"));
        assert!(!text.contains("X-Suppress"));
    }

    #[test]
    fn build_request_places_proxy_authorization_after_host() {
        let line = "Proxy-Authorization: Basic dGVzdDo=\r\n".to_string();
        let mut cf = cfg_filter(
            H1ProxyConfig::new("example.com", 443).with_auth(Box::new(FixedAuth(Some(line)))),
        );
        let req = cf.build_connect_request().expect("build");
        let text = String::from_utf8(req).expect("utf8");
        // C order: Host, then Proxy-Authorization (from aptr.proxyuserpwd).
        assert_eq!(
            text,
            "CONNECT example.com:443 HTTP/1.1\r\n\
             Host: example.com:443\r\n\
             Proxy-Authorization: Basic dGVzdDo=\r\n\
             Proxy-Connection: Keep-Alive\r\n\
             \r\n"
        );
    }

    // ---- header parsing helpers --------------------------------------------

    #[test]
    fn checkprefix_is_case_insensitive() {
        assert!(checkprefix("Content-Length:", b"content-LENGTH: 5"));
        assert!(!checkprefix("Content-Length:", b"Content-Type: x"));
    }

    #[test]
    fn copy_header_value_trims() {
        assert_eq!(copy_header_value(b"X:   hello world  \r\n"), b"hello world");
        assert_eq!(copy_header_value(b"Empty:\r\n"), b"");
        assert_eq!(copy_header_value(b"no-colon"), b"");
    }

    #[test]
    fn compareheader_matches_token() {
        assert!(compareheader(b"Connection: close\r\n", "Connection:", "close"));
        assert!(compareheader(
            b"Connection: keep-alive, close\r\n",
            "Connection:",
            "close"
        ));
        assert!(compareheader(
            b"Transfer-Encoding: chunked\r\n",
            "Transfer-Encoding:",
            "chunked"
        ));
        assert!(!compareheader(b"Connection: keep-alive\r\n", "Connection:", "close"));
    }

    #[test]
    fn status_line_recognized_and_parsed() {
        assert!(is_status_line(b"HTTP/1.1 200 Connection established\r\n"));
        assert!(is_status_line(b"HTTP/1.0 407 Proxy Auth\r\n"));
        assert_eq!(parse_status_code(b"HTTP/1.1 200 OK\r\n"), 200);
        assert_eq!(parse_status_code(b"HTTP/1.1 407 x\r\n"), 407);
        // Not a status line: HTTP/2, missing space, too-few digits.
        assert!(!is_status_line(b"HTTP/2 200 x\r\n"));
        assert!(!is_status_line(b"X-Header: value\r\n"));
    }

    #[test]
    fn parse_content_length_rejects_bad() {
        assert_eq!(parse_content_length(b"42"), Some(42));
        assert_eq!(parse_content_length(b"0"), Some(0));
        assert_eq!(parse_content_length(b""), None);
        assert_eq!(parse_content_length(b"-1"), None);
        assert_eq!(parse_content_length(b"12x"), None);
    }

    #[test]
    fn custom_header_wire_quirks() {
        assert_eq!(
            custom_header_wire("X: val").as_deref(),
            Some("X: val\r\n")
        );
        assert_eq!(custom_header_wire("X:"), None); // suppress
        assert_eq!(custom_header_wire("X;").as_deref(), Some("X:\r\n")); // empty
        assert_eq!(custom_header_wire("X; junk"), None); // reserved → ignore
        assert_eq!(custom_header_wire("nojunk"), None); // no separator
        assert!(custom_has_header(&["Host: x".to_string()], "host"));
        assert!(!custom_has_header(&["X: y".to_string()], "Host"));
    }

    // ---- chunk skipper ------------------------------------------------------

    #[test]
    fn chunk_skipper_consumes_body() {
        let mut ch = ChunkSkipper::new();
        // "5\r\nhello\r\n0\r\n\r\n" — one 5-byte chunk then the terminator.
        let body = b"5\r\nhello\r\n0\r\n\r\n";
        for &b in &body[..body.len() - 1] {
            ch.feed(b);
            assert!(!ch.is_done(), "should not finish early");
        }
        ch.feed(body[body.len() - 1]);
        assert!(ch.is_done(), "should finish on the final LF");
    }

    // ---- connect state machine ---------------------------------------------

    #[test]
    fn tunnel_established_on_200() {
        let mock = MockProxy::new(vec![
            b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec()
        ]);
        let sent = mock.sent_handle();
        let mut cf = filter_with(Box::new(mock), H1ProxyConfig::new("example.com", 443));

        let (res, _err) = drive_connect(&mut cf);
        assert!(res.is_ok(), "connect should succeed: {res:?}");
        assert!(cf.tunnel.is_established());
        assert!(cf.is_connected());

        // The CONNECT request reached the proxy verbatim.
        let wire = String::from_utf8(sent.lock().expect("lock").clone()).expect("utf8");
        assert!(wire.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(wire.contains("Host: example.com:443\r\n"));

        // The response header line was surfaced for the engine.
        assert!(cf
            .response_headers()
            .iter()
            .any(|h| h.starts_with(b"HTTP/1.1 200")));
    }

    #[test]
    fn established_filter_is_transparent() {
        let mock = MockProxy::new(vec![
            b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec()
        ]);
        let sent = mock.sent_handle();
        let mut cf = filter_with(Box::new(mock), H1ProxyConfig::new("example.com", 443));
        let (res, _err) = drive_connect(&mut cf);
        assert!(res.is_ok());

        // After establishment, send passes straight through to the transport.
        let n = run(cf.send(b"GET / HTTP/1.1\r\n", false)).expect("send");
        assert_eq!(n, 16);
        let wire = String::from_utf8(sent.lock().expect("lock").clone()).expect("utf8");
        assert!(wire.ends_with("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn multipass_407_then_200_basic() {
        // First CONNECT (no auth) → 407 with a Basic challenge and a small body
        // to drain; the follow-up CONNECT carries Basic and gets a 200.
        let stream = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                       Proxy-Authenticate: Basic realm=\"test\"\r\n\
                       Content-Length: 5\r\n\
                       \r\n\
                       hello\
                       HTTP/1.1 200 Connection established\r\n\
                       \r\n"
            .to_vec();
        let mock = MockProxy::new(vec![stream]);
        let sent = mock.sent_handle();
        let connects = mock.connects_handle();

        // Credentials + a mask that is NOT exactly Basic, so the first CONNECT
        // carries no auth (no proactive Basic) and the challenge drives the pick.
        let proxy = Proxy::parse("http://u:p@proxy:8080", CurlProxyType::Http).expect("proxy");
        let auth = StandardProxyAuth::new(proxy, CURLAUTH_BASIC | CURLAUTH_DIGEST);
        let mut cf = filter_with(
            Box::new(mock),
            H1ProxyConfig::new("example.com", 443).with_auth(Box::new(auth)),
        );

        let (res, _err) = drive_connect(&mut cf);
        assert!(res.is_ok(), "multipass connect should succeed: {res:?}");
        assert!(cf.tunnel.is_established());

        // Exactly one connection generation was used (stay-on-connection retry).
        assert_eq!(*connects.lock().expect("lock"), 1);

        // Two CONNECT requests were sent; the second carried Basic auth.
        let wire = String::from_utf8(sent.lock().expect("lock").clone()).expect("utf8");
        assert_eq!(wire.matches("CONNECT example.com:443").count(), 2);
        assert!(wire.contains("Proxy-Authorization: Basic "));
    }

    #[test]
    fn multipass_407_close_then_reopen() {
        // A 407 that asks the connection to close: the filter must close+reopen
        // the sub-chain (advancing to segment 1) and retry with Basic → 200.
        let seg0 = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                     Proxy-Authenticate: Basic realm=\"x\"\r\n\
                     Connection: close\r\n\
                     Content-Length: 0\r\n\
                     \r\n"
            .to_vec();
        let seg1 = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
        let mock = MockProxy::new(vec![seg0, seg1]);
        let connects = mock.connects_handle();

        let proxy = Proxy::parse("http://u:p@proxy:8080", CurlProxyType::Http).expect("proxy");
        let auth = StandardProxyAuth::new(proxy, CURLAUTH_BASIC | CURLAUTH_DIGEST);
        let mut cf = filter_with(
            Box::new(mock),
            H1ProxyConfig::new("example.com", 443).with_auth(Box::new(auth)),
        );

        let (res, _err) = drive_connect(&mut cf);
        assert!(res.is_ok(), "close+reopen connect should succeed: {res:?}");
        assert!(cf.tunnel.is_established());
        // Two connection generations: initial + the reopened one.
        assert_eq!(*connects.lock().expect("lock"), 2);
    }

    #[test]
    fn non_2xx_502_returns_recv_error() {
        let mock = MockProxy::new(vec![b"HTTP/1.1 502 Bad Gateway\r\n\r\n".to_vec()]);
        let mut cf = filter_with(Box::new(mock), H1ProxyConfig::new("example.com", 443));

        let (res, err) = drive_connect(&mut cf);
        assert_eq!(res, Err(CurlError::RecvError));
        assert!(cf.tunnel.is_failed());
        assert_eq!(
            err.as_deref(),
            Some("CONNECT tunnel failed, response 502")
        );
    }

    #[test]
    fn response_over_cap_is_rejected() {
        // A header line longer than the cap with no terminating blank line.
        let mut stream = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
        stream.extend(std::iter::repeat(b'a').take(20_000));
        let mock = MockProxy::new(vec![stream]);
        let mut cf = filter_with(Box::new(mock), H1ProxyConfig::new("example.com", 443));

        let (res, err) = drive_connect(&mut cf);
        assert_eq!(res, Err(CurlError::RecvError));
        assert_eq!(err.as_deref(), Some("CONNECT response too large"));
    }

    #[test]
    fn scheme_not_tunnelable_is_unsupported_protocol() {
        let mock = MockProxy::new(vec![]);
        let mut cf = filter_with(
            Box::new(mock),
            H1ProxyConfig::new("example.com", 443).with_scheme("dict", false),
        );

        let (res, err) = drive_connect(&mut cf);
        assert_eq!(res, Err(CurlError::UnsupportedProtocol));
        assert_eq!(err.as_deref(), Some("dict cannot be done over CONNECT"));
    }

    #[test]
    fn connect_timeout_is_operation_timedout() {
        let mock = MockProxy::stalling();
        let mut cf = filter_with(
            Box::new(mock),
            H1ProxyConfig::new("example.com", 443)
                .with_timeout(Some(Duration::from_millis(50))),
        );

        let (res, err) = drive_connect(&mut cf);
        assert_eq!(res, Err(CurlError::OperationTimedout));
        assert_eq!(
            err.as_deref(),
            Some("Proxy CONNECT aborted due to timeout")
        );
    }

    #[test]
    fn standard_proxy_auth_proactive_basic_and_retry_flag() {
        // mask == BASIC ⇒ proactive Basic primed at construction.
        let proxy = Proxy::parse("http://u:p@proxy:8080", CurlProxyType::Http).expect("proxy");
        let mut auth = StandardProxyAuth::new(proxy, CURLAUTH_BASIC);
        let header = auth.authorization().expect("auth");
        assert!(header
            .as_deref()
            .is_some_and(|h| h.starts_with("Proxy-Authorization: Basic ")));
        // No challenge seen yet ⇒ a mid-handshake close is not a retry.
        assert!(!auth.close_means_retry());
    }

    #[test]
    fn no_proxy_auth_emits_nothing() {
        let mut auth = NoProxyAuth;
        assert_eq!(auth.authorization().expect("auth"), None);
        assert!(!auth.act(407).expect("act"));
        assert!(!auth.close_means_retry());
    }

    // ---- constructors -------------------------------------------------------

    #[test]
    fn create_and_insert_into_chain() {
        // A chain seeded with a transport at index 0.
        let mut chain = FilterChain::from_head(Box::new(MockProxy::new(vec![])));
        // `create_h1_proxy_filter` yields a correctly-named filter.
        let solo = create_h1_proxy_filter(H1ProxyConfig::new("h", 1));
        assert_eq!(solo.name(), "H1-PROXY");
        // Splice an H1 proxy directly above the transport.
        let r = h1_proxy_insert_after(&mut chain, 0, H1ProxyConfig::new("example.com", 443));
        assert!(r.is_ok());
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.position_by_name("H1-PROXY"), Some(1));
        // Inserting after a non-existent index fails.
        let r = h1_proxy_insert_after(&mut chain, 99, H1ProxyConfig::new("h3", 3));
        assert_eq!(r, Err(CurlError::BadFunctionArgument));
    }
}
