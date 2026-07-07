// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.
//! HTTP/1.x `CONNECT` tunnel proxy filter.
//!
//! This module is the Rust port of curl's `lib/cf-h1-proxy.c` (the
//! `Curl_cft_h1_proxy` connection filter). When curl must reach an origin
//! server *through* an HTTP proxy using tunneling — the classic case being an
//! `https://` URL routed through a plain HTTP proxy, or any request made with
//! `--proxytunnel` — it does **not** speak the origin protocol to the proxy.
//! Instead it opens the transport to the proxy and issues an HTTP/1.1
//!
//! ```text
//! CONNECT host:port HTTP/1.1
//! ```
//!
//! request. The proxy attempts to open a TCP connection to `host:port`; on
//! success it answers with a `2xx` status and from that point on relays every
//! byte in both directions verbatim. Once the tunnel is established this filter
//! becomes a **transparent passthrough**: the layers stacked on top of it
//! (typically the TLS filter, then the HTTP/1 or HTTP/2 protocol handler)
//! operate exactly as if they were connected directly to the origin.
//!
//! # Relationship to the C source-of-truth
//!
//! The implementation mirrors `cf-h1-proxy.c` closely so that the on-the-wire
//! bytes, the response-parsing rules, and the proxy-authentication retry loop
//! are byte-for-byte faithful to curl 8.x:
//!
//! * [`H1TunnelState`] mirrors the C `h1_tunnel_state` enum
//!   (`H1_TUNNEL_INIT`/`CONNECT`/`RECEIVE`/`RESPONSE`/`ESTABLISHED`/`FAILED`).
//! * [`KeepOn`] mirrors the C `enum keeponval`
//!   (`KEEPON_DONE`/`KEEPON_CONNECT`/`KEEPON_IGNORE`).
//! * [`H1TunnelCtx`] mirrors `struct h1_tunnel_state` (the receive buffer, the
//!   serialized request, `nsent`, `headerlines`, the chunk drainer, the
//!   header-folding bits, and the `Content-Length`/`Connection: close`/chunked
//!   flags).
//! * The CONNECT request is serialized exactly as
//!   `Curl_http_proxy_create_CONNECT` + `Curl_h1_req_write_head` do, with the
//!   header order `Host`, `Proxy-Authorization`, `User-Agent`,
//!   `Proxy-Connection`, then any user-supplied proxy headers.
//! * Response parsing reproduces `on_resp_header` / `single_header`
//!   (case-insensitive header prefixes, obsolete line folding, the
//!   `2xx`-ignores-`Content-Length`/`Transfer-Encoding` rule, and the `407`
//!   body-draining behaviour).
//!
//! # Design constraints
//!
//! * **Memory-safe.** This module is written entirely in safe Rust — it uses
//!   no raw-pointer dereferences and no FFI escape hatches of any kind.
//! * **Tokio-only async.** All I/O flows through the sibling connection-filter
//!   contract ([`FilterCtx::send_next`] / [`FilterCtx::recv_next`]); there is no
//!   direct socket access here.
//! * **No `crate::protocols` dependency.** To avoid the `conn` ↔ `protocols`
//!   import cycle, the tiny HTTP/1 CONNECT request builder and response parser
//!   are implemented locally in this module rather than reusing the full
//!   protocol machinery. Proxy authentication is delegated to [`crate::auth`],
//!   a sibling module (no cycle).
//! * **`Error::Proxy` (curl error 97).** Every CONNECT failure path — a
//!   non-`2xx` final response, a malformed response, or a premature disconnect
//!   — surfaces as [`Error::proxy`], preserving curl's diagnostic text.

use crate::auth::{
    self, pick_strongest, CURLAUTH_BASIC, CURLAUTH_DIGEST, CURLAUTH_NEGOTIATE, CURLAUTH_NTLM,
};
use crate::conn::filters::CfFuture;
use crate::conn::filters::{
    ConnectionFilter, FilterCtx, Pollset, QueryCtx, QueryOut, POLL_IN, POLL_OUT,
};
use crate::conn::{CfQuery, CfType, FilterChain};
use crate::error::{Error, Result};

use bytes::BytesMut;

// ===========================================================================
// Buffer-size limits (parity with lib/curlx/dynbuf.h).
// ===========================================================================

/// Maximum number of bytes accepted while receiving the proxy's CONNECT
/// response headers. Mirrors curl's `DYN_PROXY_CONNECT_HEADERS` (16 KiB); once
/// exceeded curl fails with `CURLE_RECV_ERROR` ("CONNECT response too large"),
/// which this port surfaces as [`Error::proxy`].
const MAX_CONNECT_RESP_HEADERS: usize = 16 * 1024;

/// Maximum size of the serialized CONNECT request. Mirrors curl's
/// `DYN_HTTP_REQUEST` (1 MiB).
const MAX_HTTP_REQUEST: usize = 1024 * 1024;

/// Hard safety cap on the number of proxy-authentication rounds. curl relies on
/// the auth mechanisms themselves terminating the loop (a mechanism that cannot
/// make progress stops setting `data->req.newurl`); this cap is a belt-and-
/// braces guard against a misbehaving proxy that keeps answering `407`.
const MAX_AUTH_ROUNDS: u32 = 10;

// ===========================================================================
// Phase 1 — tunnel state machine.
// ===========================================================================

/// The state of the HTTP/1.x CONNECT tunnel handshake.
///
/// Exact parity with curl's `h1_tunnel_state` enum (`lib/cf-h1-proxy.c`):
///
/// | Rust                         | C                     | meaning                              |
/// |------------------------------|-----------------------|--------------------------------------|
/// | [`H1TunnelState::Init`]       | `H1_TUNNEL_INIT`       | initial / default, no tunnel yet     |
/// | [`H1TunnelState::Connect`]    | `H1_TUNNEL_CONNECT`    | the CONNECT request is being sent    |
/// | [`H1TunnelState::Receive`]    | `H1_TUNNEL_RECEIVE`    | the CONNECT response is being read   |
/// | [`H1TunnelState::Response`]   | `H1_TUNNEL_RESPONSE`   | the response was received completely |
/// | [`H1TunnelState::Established`] | `H1_TUNNEL_ESTABLISHED`| tunnel open, filter is transparent   |
/// | [`H1TunnelState::Failed`]      | `H1_TUNNEL_FAILED`     | the CONNECT attempt failed           |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H1TunnelState {
    /// Init / default / no tunnel state (`H1_TUNNEL_INIT`).
    Init,
    /// The CONNECT request is being sent (`H1_TUNNEL_CONNECT`).
    Connect,
    /// The CONNECT response is being received (`H1_TUNNEL_RECEIVE`).
    Receive,
    /// The CONNECT response has been received completely (`H1_TUNNEL_RESPONSE`).
    Response,
    /// The tunnel is established; the filter now relays bytes transparently
    /// (`H1_TUNNEL_ESTABLISHED`).
    Established,
    /// The CONNECT attempt failed (`H1_TUNNEL_FAILED`).
    Failed,
}

/// Whether the receive loop should keep running while establishing the tunnel.
///
/// Mirrors curl's `enum keeponval` (`lib/cf-h1-proxy.c`): the response reader
/// runs while `keepon != KEEPON_DONE`, switching to [`KeepOn::Ignore`] when it
/// must drain (and discard) a `407` response body before it can reuse the
/// connection for the authenticated retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeepOn {
    /// Done reading — the response is complete (`KEEPON_DONE`).
    Done,
    /// Keep reading response headers (`KEEPON_CONNECT`).
    Connect,
    /// Keep reading but discard a response body we must ignore (`KEEPON_IGNORE`).
    Ignore,
}

// ===========================================================================
// Minimal chunked-transfer-encoding drainer.
// ===========================================================================

/// The internal parser state of [`ChunkDrainer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChunkPhase {
    /// Reading the hexadecimal chunk-size digits.
    Size,
    /// Inside a chunk-extension (`;name=value`); ignored up to the CR.
    Ext,
    /// Expecting the LF that terminates the size line.
    SizeLf,
    /// Consuming `remaining` chunk-data bytes.
    Data,
    /// Expecting the CR that follows a chunk's data.
    DataCr,
    /// Expecting the LF that follows a chunk's data CR.
    DataLf,
    /// Reading a trailer line (or the terminating blank line).
    TrailerLine,
    /// Expecting the LF that terminates a trailer line.
    TrailerLf,
    /// The full chunked body (including trailers) has been consumed.
    Done,
}

/// A byte-at-a-time drainer for a chunked-transfer-encoded response body.
///
/// This is intentionally *not* a general-purpose HTTP chunk decoder: the CONNECT
/// tunnel only ever needs to **discard** a `407` response body so that the
/// underlying connection can be reused for the authenticated retry. So the
/// drainer tracks just enough structure — chunk sizes, data spans, the
/// terminating zero-size chunk, and the trailer section — to know precisely
/// where the body ends. It mirrors the role of curl's `Curl_httpchunk_read`
/// loop inside `recv_CONNECT_resp` (the `KEEPON_IGNORE` branch).
#[derive(Clone, Debug)]
struct ChunkDrainer {
    phase: ChunkPhase,
    /// Remaining bytes to consume in the current chunk's data section.
    remaining: u64,
    /// Whether at least one hex digit has been seen for the current size.
    hex_seen: bool,
    /// Whether the trailer line currently being read is empty so far (an empty
    /// trailer line terminates the body).
    line_empty: bool,
}

impl ChunkDrainer {
    /// Creates a drainer positioned at the start of a chunk size line.
    fn new() -> Self {
        ChunkDrainer {
            phase: ChunkPhase::Size,
            remaining: 0,
            hex_seen: false,
            line_empty: true,
        }
    }

    /// Resets the drainer to its initial state, mirroring
    /// `Curl_httpchunk_reset`.
    fn reset(&mut self) {
        self.phase = ChunkPhase::Size;
        self.remaining = 0;
        self.hex_seen = false;
        self.line_empty = true;
    }

    /// Returns `true` once the entire chunked body (final zero chunk and any
    /// trailers) has been consumed, the equivalent of
    /// `Curl_httpchunk_is_done`.
    fn is_done(&self) -> bool {
        self.phase == ChunkPhase::Done
    }

    /// Feeds a single body byte into the drainer, advancing its state. Returns
    /// `true` when the body is fully drained. Extra bytes fed after completion
    /// are ignored (the caller stops once [`is_done`](Self::is_done) is set).
    fn feed(&mut self, byte: u8) -> bool {
        match self.phase {
            ChunkPhase::Size => match byte {
                b'0'..=b'9' => {
                    self.remaining = self.remaining.wrapping_mul(16) + u64::from(byte - b'0');
                    self.hex_seen = true;
                }
                b'a'..=b'f' => {
                    self.remaining = self.remaining.wrapping_mul(16) + u64::from(byte - b'a' + 10);
                    self.hex_seen = true;
                }
                b'A'..=b'F' => {
                    self.remaining = self.remaining.wrapping_mul(16) + u64::from(byte - b'A' + 10);
                    self.hex_seen = true;
                }
                b';' => self.phase = ChunkPhase::Ext,
                b'\r' => self.phase = ChunkPhase::SizeLf,
                b'\n' => self.finish_size_line(),
                _ => {
                    // Tolerate leading blanks; anything else is ignored, mirroring
                    // curl's lenient size parsing.
                }
            },
            ChunkPhase::Ext => {
                if byte == b'\r' {
                    self.phase = ChunkPhase::SizeLf;
                } else if byte == b'\n' {
                    self.finish_size_line();
                }
            }
            ChunkPhase::SizeLf => {
                // The byte is the LF terminating the size line (tolerated even if
                // a stray non-LF slips in).
                self.finish_size_line();
            }
            ChunkPhase::Data => {
                if self.remaining > 0 {
                    self.remaining -= 1;
                }
                if self.remaining == 0 {
                    self.phase = ChunkPhase::DataCr;
                }
            }
            ChunkPhase::DataCr => {
                if byte == b'\n' {
                    // Bare LF (no CR) — restart at the next size line.
                    self.phase = ChunkPhase::Size;
                    self.hex_seen = false;
                } else {
                    self.phase = ChunkPhase::DataLf;
                }
            }
            ChunkPhase::DataLf => {
                self.phase = ChunkPhase::Size;
                self.hex_seen = false;
            }
            ChunkPhase::TrailerLine => match byte {
                b'\r' => self.phase = ChunkPhase::TrailerLf,
                b'\n' => self.finish_trailer_line(),
                _ => self.line_empty = false,
            },
            ChunkPhase::TrailerLf => self.finish_trailer_line(),
            ChunkPhase::Done => {}
        }
        self.is_done()
    }

    /// Handles the end of a chunk-size line: a zero-size chunk begins the
    /// trailer section, otherwise the data section follows.
    fn finish_size_line(&mut self) {
        if self.remaining == 0 {
            self.phase = ChunkPhase::TrailerLine;
            self.line_empty = true;
        } else {
            self.phase = ChunkPhase::Data;
        }
    }

    /// Handles the end of a trailer line: an empty trailer line terminates the
    /// body, otherwise another trailer line may follow.
    fn finish_trailer_line(&mut self) {
        if self.line_empty {
            self.phase = ChunkPhase::Done;
        } else {
            self.phase = ChunkPhase::TrailerLine;
            self.line_empty = true;
        }
    }
}

// ===========================================================================
// Configuration.
// ===========================================================================

/// Static configuration for an [`H1ProxyFilter`], gathered from the easy
/// handle's proxy options at the time the filter is inserted into the chain.
///
/// Everything here corresponds to inputs that curl reads while building the
/// CONNECT request in `Curl_http_proxy_create_CONNECT` and while negotiating
/// proxy authentication in `Curl_http_output_auth`.
#[derive(Clone, Debug)]
pub struct H1ProxyConfig {
    /// The origin host to tunnel to — the CONNECT target (`hostname` in
    /// `Curl_http_proxy_get_destination`). For an IPv6 literal this is the bare
    /// address without brackets; bracketing is applied when the authority is
    /// formatted.
    pub host: String,
    /// The origin port to tunnel to.
    pub port: u16,
    /// Whether the proxy is an HTTP/1.0 proxy (`CURLPROXY_HTTP_1_0`). When set,
    /// the request line uses `HTTP/1.0` and the `Host`/`Proxy-Connection`
    /// headers are omitted, matching curl's `http_minor == 0` path.
    pub http_1_0: bool,
    /// The `User-Agent` value to advertise to the proxy, if any
    /// (`STRING_USERAGENT`). `None` (or empty) omits the header.
    pub user_agent: Option<String>,
    /// Extra user-supplied proxy headers, appended verbatim after the standard
    /// headers in insertion order (curl's `dynhds_add_custom`). Each entry is a
    /// `(name, value)` pair serialized as `"{name}: {value}\r\n"`.
    pub extra_headers: Vec<(String, String)>,
    /// The proxy username (`CURLOPT_PROXYUSERNAME`), if credentials are set.
    pub proxy_user: Option<String>,
    /// The proxy password (`CURLOPT_PROXYPASSWORD`), if credentials are set.
    pub proxy_password: Option<String>,
    /// The bitmask of proxy authentication methods the user permits
    /// (`CURLOPT_PROXYAUTH`, a `CURLAUTH_*` mask). Defaults to
    /// [`CURLAUTH_BASIC`] when unset and credentials are present, mirroring
    /// curl's default of Basic for `--proxy-user`.
    pub want_auth: u32,
    /// Whether to send credentials proactively on the very first CONNECT
    /// (curl's behaviour for a plain `--proxy-user` with Basic). Mechanisms that
    /// require a server challenge first (Digest, Negotiate) ignore this and wait
    /// for the `407`.
    pub proactive_auth: bool,
}

impl H1ProxyConfig {
    /// Creates a configuration for tunneling to `host:port` with no proxy
    /// authentication and HTTP/1.1 semantics.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        H1ProxyConfig {
            host: host.into(),
            port,
            http_1_0: false,
            user_agent: None,
            extra_headers: Vec::new(),
            proxy_user: None,
            proxy_password: None,
            want_auth: 0,
            proactive_auth: false,
        }
    }

    /// Formats the request authority exactly as
    /// `curl_maprintf("%s%s%s:%d", ...)` does: an IPv6 literal (a host
    /// containing a `:`) is wrapped in brackets, then the port is appended.
    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Extracts the bare host portion of an `authority` of the form `host:port` or
/// `[ipv6]:port`, used to derive the SPN host for Negotiate. Returns the input
/// unchanged if it has no recognizable port suffix.
fn host_from_authority(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        // `[ipv6]:port` — the host is everything up to the closing bracket.
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    match authority.rfind(':') {
        Some(idx) => &authority[..idx],
        None => authority,
    }
}

// ===========================================================================
// Proxy authentication state machine.
// ===========================================================================

/// Per-connection proxy-authentication state, driving the `407` retry loop.
///
/// This condenses the pieces of curl's `data->state.authproxy`, the mechanism
/// data hung off `conn`, and the `Curl_http_input_auth` / `Curl_http_auth_act`
/// flow into a single object owned by the filter. The model is
/// challenge/response: the first CONNECT is (optionally) sent with a proactive
/// header, the proxy answers `407` with one or more `Proxy-Authenticate`
/// challenges, [`input_challenge`](Self::input_challenge) feeds them to the
/// relevant `crate::auth` mechanism, and [`build_header`](Self::build_header)
/// emits the `Proxy-Authorization` header for the next round.
struct ProxyAuth {
    /// The `CURLAUTH_*` mask the user permits.
    want: u32,
    /// The `CURLAUTH_*` mask advertised by the proxy so far.
    avail: u32,
    /// The single mechanism chosen for the current round.
    picked: u32,
    /// Whether to send credentials proactively on the first CONNECT.
    proactive: bool,
    /// The proxy username, if any.
    user: Option<String>,
    /// The proxy password, if any.
    passwd: Option<String>,
    /// Digest challenge/response state.
    digest: auth::digest::DigestData,
    /// NTLM handshake state.
    ntlm: auth::ntlm::NtlmData,
    /// NTLM leg counter: `0` = nothing sent, `1` = type-1 sent, `2` = type-3
    /// sent.
    ntlm_stage: u8,
    /// Negotiate (SPNEGO) handshake state.
    #[cfg(feature = "spnego")]
    nego: auth::negotiate::NegotiateData,
    /// Whether the Negotiate handshake reported completion.
    #[cfg(feature = "spnego")]
    nego_done: bool,
    /// Whether a Basic header has already been emitted (single-shot).
    basic_sent: bool,
    /// Whether a Digest header has already been emitted (single-shot per
    /// challenge).
    digest_sent: bool,
    /// Whether the next CONNECT is the very first one (governs proactive auth).
    first_request: bool,
    /// Number of `407` rounds taken so far (bounded by [`MAX_AUTH_ROUNDS`]).
    rounds: u32,
}

impl ProxyAuth {
    /// Builds the auth state from the filter configuration.
    fn new(config: &H1ProxyConfig) -> Self {
        // curl defaults proxy auth to Basic when a `--proxy-user` is supplied
        // without an explicit `CURLOPT_PROXYAUTH`.
        let has_creds = config.proxy_user.is_some() || config.proxy_password.is_some();
        let want = if config.want_auth != 0 {
            config.want_auth
        } else if has_creds {
            CURLAUTH_BASIC
        } else {
            0
        };

        ProxyAuth {
            want,
            avail: 0,
            picked: 0,
            proactive: config.proactive_auth && has_creds,
            user: config.proxy_user.clone(),
            passwd: config.proxy_password.clone(),
            digest: auth::digest::DigestData::default(),
            ntlm: auth::ntlm::NtlmData::default(),
            ntlm_stage: 0,
            #[cfg(feature = "spnego")]
            nego: auth::negotiate::NegotiateData::default(),
            #[cfg(feature = "spnego")]
            nego_done: false,
            basic_sent: false,
            digest_sent: false,
            first_request: true,
            rounds: 0,
        }
    }

    /// Whether proxy credentials are configured at all. Mirrors curl's guard
    /// `data->set.proxyauth && data->state.authproxy.avail &&
    /// data->state.aptr.proxyuserpwd` used to decide whether a premature proxy
    /// disconnect is a "mere" close (retryable) or a hard abort.
    fn has_creds(&self) -> bool {
        self.user.is_some() || self.passwd.is_some()
    }

    /// Feeds one `Proxy-Authenticate` challenge value (already stripped of its
    /// header name and surrounding blanks, e.g. `"Basic realm=\"x\""` or
    /// `"Digest nonce=..."` or `"NTLM <base64>"`) into the matching mechanism.
    ///
    /// Mirrors `Curl_http_input_auth` (`lib/http.c`): it records the advertised
    /// method in [`avail`](Self::avail) and hands mechanism-specific challenge
    /// data to `crate::auth`.
    fn input_challenge(&mut self, value: &str) {
        let scheme = value.split_whitespace().next().unwrap_or("");

        if scheme.eq_ignore_ascii_case("Basic") {
            self.avail |= CURLAUTH_BASIC;
        } else if scheme.eq_ignore_ascii_case("Digest") {
            self.avail |= CURLAUTH_DIGEST;
            // `input_digest` wants the full "Digest ..." value.
            let _ = auth::digest::input_digest(true, value, &mut self.digest);
        } else if scheme.eq_ignore_ascii_case("NTLM") {
            self.avail |= CURLAUTH_NTLM;
            // A bare "NTLM" offer carries no token; a follow-up "NTLM <b64>"
            // carries the type-2 challenge to decode.
            let token = value[scheme.len()..].trim();
            if !token.is_empty() {
                let _ = auth::ntlm::decode_type2_message(token, &mut self.ntlm);
            }
        } else if scheme.eq_ignore_ascii_case("Negotiate") {
            self.input_negotiate_challenge(value);
        }
    }

    /// Feeds a Negotiate challenge (SPNEGO). Compiled out when the `spnego`
    /// feature is disabled, in which case the mechanism is simply never marked
    /// available and the proxy's Negotiate offer is ignored — exactly as a
    /// curl build without a GSS-API backend behaves.
    #[cfg(feature = "spnego")]
    fn input_negotiate_challenge(&mut self, value: &str) {
        self.avail |= CURLAUTH_NEGOTIATE;
        let host = String::new();
        let _ = auth::negotiate::input_negotiate(value, "HTTP", &host, &mut self.nego);
    }

    /// No-op Negotiate challenge handler for builds without the `spnego`
    /// feature.
    #[cfg(not(feature = "spnego"))]
    fn input_negotiate_challenge(&mut self, _value: &str) {
        let _ = CURLAUTH_NEGOTIATE;
    }

    /// Produces the `Proxy-Authorization` header line for the next CONNECT
    /// request, or `None` if no header should be sent this round.
    ///
    /// `method` is the request method (always `"CONNECT"` here) and `authority`
    /// is the CONNECT target `host:port`, used as the digest URI and to derive
    /// the Negotiate SPN host. Mirrors `Curl_http_output_auth`.
    fn build_header(&mut self, method: &str, authority: &str) -> Result<Option<String>> {
        let mech = self.choose_mechanism();
        self.picked = mech;

        match mech {
            CURLAUTH_BASIC => {
                let line = auth::basic::http_output_basic(
                    self.user.as_deref(),
                    self.passwd.as_deref(),
                    true,
                )?;
                self.basic_sent = true;
                Ok(Some(line))
            }
            CURLAUTH_DIGEST => {
                if !self.digest.have_challenge() {
                    return Ok(None);
                }
                let line = auth::digest::output_digest(
                    true,
                    method,
                    authority,
                    false,
                    self.user.as_deref().unwrap_or(""),
                    self.passwd.as_deref().unwrap_or(""),
                    &mut self.digest,
                )?;
                if line.is_some() {
                    self.digest_sent = true;
                }
                Ok(line)
            }
            CURLAUTH_NTLM => self.build_ntlm_header(),
            CURLAUTH_NEGOTIATE => self.build_negotiate_header(authority),
            _ => Ok(None),
        }
    }

    /// Chooses the mechanism to use for the upcoming request. When the proxy has
    /// advertised methods we pick the strongest permitted one; before any
    /// challenge, only proactive Basic/NTLM may be emitted.
    fn choose_mechanism(&self) -> u32 {
        if self.avail != 0 {
            pick_strongest(self.want, self.avail)
        } else if self.first_request && self.proactive {
            // Only mechanisms that can proceed without a server challenge may be
            // sent proactively: Basic (credentials only) and NTLM (type-1).
            let p = pick_strongest(self.want, self.want);
            if p == CURLAUTH_BASIC || p == CURLAUTH_NTLM {
                p
            } else if self.want & CURLAUTH_BASIC != 0 {
                CURLAUTH_BASIC
            } else if self.want & CURLAUTH_NTLM != 0 {
                CURLAUTH_NTLM
            } else {
                0
            }
        } else {
            0
        }
    }

    /// Emits the appropriate NTLM leg (type-1 then type-3), wrapping the raw
    /// base64 token from `crate::auth` into a full header line.
    fn build_ntlm_header(&mut self) -> Result<Option<String>> {
        match self.ntlm_stage {
            0 => {
                let token = auth::ntlm::create_type1_message(&mut self.ntlm)?;
                self.ntlm_stage = 1;
                Ok(Some(format!("Proxy-Authorization: NTLM {token}\r\n")))
            }
            1 => {
                let token = auth::ntlm::create_type3_message(
                    self.user.as_deref().unwrap_or(""),
                    self.passwd.as_deref().unwrap_or(""),
                    &mut self.ntlm,
                )?;
                self.ntlm_stage = 2;
                Ok(Some(format!("Proxy-Authorization: NTLM {token}\r\n")))
            }
            _ => Ok(None),
        }
    }

    /// Emits a Negotiate header when the `spnego` feature is enabled.
    #[cfg(feature = "spnego")]
    fn build_negotiate_header(&mut self, authority: &str) -> Result<Option<String>> {
        let host = host_from_authority(authority).to_string();
        let out = auth::negotiate::output_negotiate(true, "HTTP", &host, &mut self.nego)?;
        self.nego_done = out.done;
        Ok(out.header)
    }

    /// Negotiate is unavailable without the `spnego` feature.
    #[cfg(not(feature = "spnego"))]
    fn build_negotiate_header(&mut self, authority: &str) -> Result<Option<String>> {
        let _ = host_from_authority(authority);
        Ok(None)
    }

    /// Decides whether to loop and re-issue the CONNECT after a response,
    /// mirroring the effect of `Curl_http_auth_act` setting `data->req.newurl`.
    ///
    /// Only a `407` triggers a retry. The strongest permitted advertised
    /// mechanism is selected; single-shot mechanisms (Basic, Digest) retry at
    /// most once, while NTLM and Negotiate are multi-leg. A hard round cap
    /// guards against a pathological proxy.
    fn decide_retry(&mut self, httpcode: u16) -> bool {
        if httpcode != 407 {
            return false;
        }
        self.rounds += 1;
        if self.rounds > MAX_AUTH_ROUNDS {
            return false;
        }

        let mech = if self.avail != 0 {
            pick_strongest(self.want, self.avail)
        } else {
            0
        };
        self.picked = mech;

        match mech {
            CURLAUTH_BASIC => !self.basic_sent,
            CURLAUTH_DIGEST => self.digest.have_challenge() && !self.digest_sent,
            CURLAUTH_NTLM => self.ntlm_stage < 2,
            CURLAUTH_NEGOTIATE => self.negotiate_wants_retry(),
            _ => false,
        }
    }

    /// Whether the Negotiate handshake still has a leg to send.
    #[cfg(feature = "spnego")]
    fn negotiate_wants_retry(&self) -> bool {
        !self.nego_done
    }

    /// Negotiate never retries without the `spnego` feature.
    #[cfg(not(feature = "spnego"))]
    fn negotiate_wants_retry(&self) -> bool {
        false
    }
}

// ===========================================================================
// Total header-size cap.
// ===========================================================================

/// Maximum total size of the response header block. Mirrors curl's
/// `CURL_MAX_HTTP_HEADER` (100 KiB) enforced by `Curl_bump_headersize`. Exceeding
/// it fails the CONNECT as [`Error::proxy`] ("CONNECT response too large").
const MAX_TOTAL_HEADERS: usize = 100 * 1024;

// ===========================================================================
// Tunnel context (mirror of `struct h1_tunnel_state`).
// ===========================================================================

/// The mutable working state of a single CONNECT handshake, reset for each
/// authentication round.
///
/// Field-for-field this mirrors curl's `struct h1_tunnel_state`:
///
/// * `rcvbuf` — the current logical response header line being assembled.
/// * `request_data` — the fully serialized CONNECT request.
/// * `nsent` — how many bytes of `request_data` have been written so far.
/// * `headerlines` — number of response header lines seen.
/// * `chunk` — the drainer used to consume an ignored chunked `407` body.
/// * `keepon` — whether/why the receive loop keeps running.
/// * `cl` — the remaining count of `Content-Length` bytes to ignore.
/// * `chunked_encoding` / `close_connection` — response flags.
/// * `maybe_folded` / `leading_unfold` — obsolete-line-folding parser bits.
/// * `httpcode` — the status code parsed from the proxy's response.
struct H1TunnelCtx {
    rcvbuf: BytesMut,
    request_data: BytesMut,
    nsent: usize,
    headerlines: usize,
    chunk: ChunkDrainer,
    keepon: KeepOn,
    cl: u64,
    state: H1TunnelState,
    chunked_encoding: bool,
    close_connection: bool,
    maybe_folded: bool,
    leading_unfold: bool,
    httpcode: u16,
    total_header_bytes: usize,
}

impl H1TunnelCtx {
    /// Creates a fresh, uninitialized tunnel context in the [`H1TunnelState::Init`]
    /// state.
    fn new() -> Self {
        H1TunnelCtx {
            rcvbuf: BytesMut::new(),
            request_data: BytesMut::new(),
            nsent: 0,
            headerlines: 0,
            chunk: ChunkDrainer::new(),
            keepon: KeepOn::Connect,
            cl: 0,
            state: H1TunnelState::Init,
            chunked_encoding: false,
            close_connection: false,
            maybe_folded: false,
            leading_unfold: false,
            httpcode: 0,
            total_header_bytes: 0,
        }
    }

    /// Resets the context for a new CONNECT attempt, mirroring curl's
    /// `tunnel_reinit` plus the `H1_TUNNEL_CONNECT` state entry (which resets
    /// `rcvbuf` and sets `keepon = KEEPON_CONNECT`).
    fn reinit(&mut self) {
        self.rcvbuf.clear();
        self.request_data.clear();
        self.nsent = 0;
        self.headerlines = 0;
        self.chunk.reset();
        self.keepon = KeepOn::Connect;
        self.cl = 0;
        self.state = H1TunnelState::Init;
        self.chunked_encoding = false;
        self.close_connection = false;
        self.maybe_folded = false;
        self.leading_unfold = false;
        self.httpcode = 0;
        self.total_header_bytes = 0;
    }
}

// ===========================================================================
// Local HTTP/1 header helpers (kept in-module to avoid a `crate::protocols`
// dependency and the resulting `conn` ↔ `protocols` import cycle).
// ===========================================================================

/// Case-insensitive ASCII prefix test, the equivalent of curl's `checkprefix`.
fn starts_ci(haystack: &str, prefix: &str) -> bool {
    let h = haystack.as_bytes();
    let p = prefix.as_bytes();
    h.len() >= p.len() && h[..p.len()].eq_ignore_ascii_case(p)
}

/// Extracts a header's value: everything after the first `:` with surrounding
/// ASCII blanks and the trailing CR/LF trimmed. Port of
/// `Curl_copy_header_value`.
fn copy_header_value(header: &str) -> String {
    let after = match header.find(':') {
        Some(idx) => &header[idx + 1..],
        None => header,
    };
    after
        .trim_matches(|c: char| c == ' ' || c == '\t' || c == '\r' || c == '\n')
        .to_string()
}

/// Returns `true` when the value of the header named `name` contains the token
/// `token` (case-insensitive). Approximates curl's `Curl_compareheader`.
fn header_contains_token(header: &str, name: &str, token: &str) -> bool {
    if !starts_ci(header, name) {
        return false;
    }
    let value = &header[name.len()..];
    value
        .to_ascii_lowercase()
        .contains(&token.to_ascii_lowercase())
}

/// Parses a `Content-Length` value: optional surrounding blanks around a
/// non-negative decimal integer. Port of the `curlx_str_numblanks` usage in
/// `on_resp_header`. Returns `None` for a malformed value.
fn parse_content_length(value: &str) -> Option<u64> {
    let trimmed = value.trim_matches(|c: char| c == ' ' || c == '\t' || c == '\r' || c == '\n');
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    trimmed.parse::<u64>().ok()
}

/// Parses an HTTP/1.x status line of the exact shape curl accepts:
/// `HTTP/1.[01] SP DDD` followed by a non-digit, returning the three-digit
/// status code. Mirrors the final `else if` branch of `on_resp_header`.
fn parse_status_line(header: &str) -> Option<u16> {
    let b = header.as_bytes();
    if b.len() >= 13
        && &b[0..7] == b"HTTP/1."
        && (b[7] == b'0' || b[7] == b'1')
        && b[8] == b' '
        && b[9].is_ascii_digit()
        && b[10].is_ascii_digit()
        && b[11].is_ascii_digit()
        && !b[12].is_ascii_digit()
    {
        let code =
            u16::from(b[9] - b'0') * 100 + u16::from(b[10] - b'0') * 10 + u16::from(b[11] - b'0');
        Some(code)
    } else {
        None
    }
}

// ===========================================================================
// The filter.
// ===========================================================================

/// The HTTP/1.x CONNECT tunnel connection filter (`Curl_cft_h1_proxy`).
///
/// Insert this filter above the transport (and any HAProxy) filter and below
/// the TLS/HTTP filters when tunneling through an HTTP proxy. During
/// [`connect`](ConnectionFilter::connect) it performs the CONNECT handshake;
/// afterwards it is a transparent byte relay, so `send`/`recv`/`data_pending`
/// and `query` inherit the trait's default delegation to the next filter.
pub struct H1ProxyFilter {
    config: H1ProxyConfig,
    auth: ProxyAuth,
    tunnel: H1TunnelCtx,
    established: bool,
}

impl H1ProxyFilter {
    /// Creates a new CONNECT-tunnel filter from the given configuration.
    #[must_use]
    pub fn new(config: H1ProxyConfig) -> Self {
        let auth = ProxyAuth::new(&config);
        H1ProxyFilter {
            config,
            auth,
            tunnel: H1TunnelCtx::new(),
            established: false,
        }
    }

    /// Serializes the CONNECT request for the current round into
    /// `tunnel.request_data`, reproducing the byte layout of
    /// `Curl_http_proxy_create_CONNECT` + `Curl_h1_req_write_head`.
    fn build_request(&mut self) -> Result<()> {
        let authority = self.config.authority();
        let minor = if self.config.http_1_0 { 0 } else { 1 };

        // Compute the Proxy-Authorization line for this round first, mirroring
        // `Curl_http_output_auth` populating `aptr.proxyuserpwd` before the
        // header block is assembled.
        let auth_line = self.auth.build_header("CONNECT", &authority)?;

        let overridden = |name: &str| {
            self.config
                .extra_headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case(name))
        };

        let mut req = String::with_capacity(128);
        req.push_str("CONNECT ");
        req.push_str(&authority);
        req.push_str(" HTTP/1.");
        req.push_str(if minor == 0 { "0" } else { "1" });
        req.push_str("\r\n");

        // Header order: Host, Proxy-Authorization, User-Agent, Proxy-Connection,
        // then user-supplied proxy headers.
        if minor == 1 && !overridden("Host") {
            req.push_str("Host: ");
            req.push_str(&authority);
            req.push_str("\r\n");
        }
        if let Some(line) = auth_line {
            // `line` is already a complete "Proxy-Authorization: ...\r\n".
            req.push_str(&line);
        }
        if !overridden("User-Agent") {
            if let Some(ua) = self.config.user_agent.as_deref() {
                if !ua.is_empty() {
                    req.push_str("User-Agent: ");
                    req.push_str(ua);
                    req.push_str("\r\n");
                }
            }
        }
        if minor == 1 && !overridden("Proxy-Connection") {
            req.push_str("Proxy-Connection: Keep-Alive\r\n");
        }
        for (name, value) in &self.config.extra_headers {
            req.push_str(name);
            req.push_str(": ");
            req.push_str(value);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");

        if req.len() > MAX_HTTP_REQUEST {
            return Err(Error::proxy("CONNECT request too large"));
        }

        self.tunnel.request_data.clear();
        self.tunnel.request_data.extend_from_slice(req.as_bytes());
        self.tunnel.nsent = 0;
        self.tunnel.headerlines = 0;
        Ok(())
    }

    /// Appends one byte to the current response line, enforcing the per-line
    /// size cap (curl's `curlx_dyn_addn` returning an error past
    /// `DYN_PROXY_CONNECT_HEADERS`).
    fn push_rcv(&mut self, byte: u8) -> Result<()> {
        if self.tunnel.rcvbuf.len() >= MAX_CONNECT_RESP_HEADERS {
            return Err(Error::proxy("CONNECT response too large"));
        }
        self.tunnel.rcvbuf.extend_from_slice(&[byte]);
        Ok(())
    }

    /// Removes the trailing `\n`, `\r`, and blanks from the current line so a
    /// folded continuation can be appended after a single space. Port of
    /// `Curl_http_to_fold`.
    fn fold_last_line(&mut self) {
        let buf = &mut self.tunnel.rcvbuf;
        if buf.last() == Some(&b'\n') {
            buf.truncate(buf.len() - 1);
        }
        if buf.last() == Some(&b'\r') {
            buf.truncate(buf.len() - 1);
        }
        while matches!(buf.last(), Some(b' ') | Some(b'\t')) {
            buf.truncate(buf.len() - 1);
        }
    }

    /// Processes one received byte of the CONNECT response, driving the
    /// line-assembly / folding / body-draining state machine. This is the body
    /// of curl's `recv_CONNECT_resp` inner loop for a single byte.
    fn process_response_byte(&mut self, byte: u8) -> Result<()> {
        // Draining an ignored 407 body.
        if self.tunnel.keepon == KeepOn::Ignore {
            if self.tunnel.cl > 0 {
                self.tunnel.cl -= 1;
                if self.tunnel.cl == 0 {
                    self.tunnel.keepon = KeepOn::Done;
                }
            } else if self.tunnel.chunked_encoding && self.tunnel.chunk.feed(byte) {
                tracing::trace!("chunk reading DONE");
                self.tunnel.keepon = KeepOn::Done;
            }
            return Ok(());
        }

        // A completed non-blank header line may fold into the next line.
        if self.tunnel.maybe_folded {
            if byte == b' ' || byte == b'\t' {
                self.fold_last_line();
                self.tunnel.leading_unfold = true;
            } else {
                self.single_header()?;
            }
            self.tunnel.maybe_folded = false;
        }

        // While unfolding, skip leading blanks then insert exactly one space.
        if self.tunnel.leading_unfold {
            if byte == b' ' || byte == b'\t' {
                return Ok(());
            }
            self.push_rcv(b' ')?;
            self.tunnel.leading_unfold = false;
        }

        self.push_rcv(byte)?;

        // Not the end of a line yet.
        if byte != b'\n' {
            return Ok(());
        }

        // End of a line: a line that starts with CR/LF is the blank
        // header-terminating line; anything else is a header that might fold.
        match self.tunnel.rcvbuf.first().copied() {
            Some(b'\r') | Some(b'\n') => self.single_header()?,
            _ => self.tunnel.maybe_folded = true,
        }
        Ok(())
    }

    /// Handles one complete response line, either recording end-of-headers (and
    /// deciding whether a 407 body must be drained) or parsing a header. Port of
    /// `single_header`.
    fn single_header(&mut self) -> Result<()> {
        self.tunnel.headerlines += 1;
        let line_len = self.tunnel.rcvbuf.len();
        self.tunnel.total_header_bytes = self.tunnel.total_header_bytes.saturating_add(line_len);
        if self.tunnel.total_header_bytes > MAX_TOTAL_HEADERS {
            return Err(Error::proxy("CONNECT response too large"));
        }

        // A line starting with CR/LF is the blank line that ends the headers.
        if matches!(
            self.tunnel.rcvbuf.first().copied(),
            Some(b'\r') | Some(b'\n')
        ) {
            if self.tunnel.httpcode == 407 && self.auth_can_proceed() {
                // We intend to retry with credentials, so drain the body to keep
                // the connection reusable.
                self.tunnel.keepon = KeepOn::Ignore;
                if self.tunnel.cl > 0 {
                    tracing::trace!(bytes = self.tunnel.cl, "Ignore bytes of response-body");
                } else if self.tunnel.chunked_encoding {
                    tracing::trace!("Ignore chunked response-body");
                } else {
                    // No body framing: cannot keep the connection alive, bail.
                    self.tunnel.keepon = KeepOn::Done;
                }
            } else {
                self.tunnel.keepon = KeepOn::Done;
            }
            return Ok(());
        }

        // A real header line — parse it, then reset the line buffer.
        let header = String::from_utf8_lossy(&self.tunnel.rcvbuf).into_owned();
        self.on_resp_header(&header)?;
        self.tunnel.rcvbuf.clear();
        Ok(())
    }

    /// Parses a single response header line, updating the tunnel flags and
    /// feeding any authentication challenge to [`ProxyAuth`]. Port of
    /// `on_resp_header`.
    fn on_resp_header(&mut self, header: &str) -> Result<()> {
        let code = self.tunnel.httpcode;

        if (starts_ci(header, "Proxy-authenticate:") && code == 407)
            || (starts_ci(header, "WWW-Authenticate:") && code == 401)
        {
            let value = copy_header_value(header);
            self.auth.input_challenge(&value);
        } else if starts_ci(header, "Content-Length:") {
            if code / 100 == 2 {
                tracing::trace!(code, "Ignoring Content-Length in 2xx CONNECT response");
            } else {
                let value = copy_header_value(header);
                match parse_content_length(&value) {
                    Some(n) => self.tunnel.cl = n,
                    None => return Err(Error::proxy("Unsupported Content-Length value")),
                }
            }
        } else if header_contains_token(header, "Connection:", "close") {
            self.tunnel.close_connection = true;
        } else if starts_ci(header, "Transfer-Encoding:") {
            if code / 100 == 2 {
                tracing::trace!(code, "Ignoring Transfer-Encoding in 2xx CONNECT response");
            } else if header_contains_token(header, "Transfer-Encoding:", "chunked") {
                tracing::trace!("CONNECT responded chunked");
                self.tunnel.chunked_encoding = true;
                self.tunnel.chunk.reset();
            }
        } else if header_contains_token(header, "Proxy-Connection:", "close") {
            self.tunnel.close_connection = true;
        } else if let Some(status) = parse_status_line(header) {
            self.tunnel.httpcode = status;
        }
        Ok(())
    }

    /// Side-effect-free predicate: can a proxy-auth mechanism make progress
    /// against the challenges seen so far? This is the analogue of curl's
    /// `!data->state.authproblem`, used to decide whether a 407 body should be
    /// drained (so the connection can be reused for the authenticated retry).
    fn auth_can_proceed(&self) -> bool {
        if self.tunnel.httpcode != 407 {
            return false;
        }
        let mech = if self.auth.avail != 0 {
            pick_strongest(self.auth.want, self.auth.avail)
        } else {
            0
        };
        match mech {
            CURLAUTH_BASIC => !self.auth.basic_sent,
            CURLAUTH_DIGEST => self.auth.digest.have_challenge() && !self.auth.digest_sent,
            CURLAUTH_NTLM => self.auth.ntlm_stage < 2,
            CURLAUTH_NEGOTIATE => self.auth.negotiate_wants_retry(),
            _ => false,
        }
    }
}

impl ConnectionFilter for H1ProxyFilter {
    fn name(&self) -> &'static str {
        "HTTP-PROXY"
    }

    fn cf_type(&self) -> CfType {
        CfType::PROXY | CfType::HTTP
    }

    fn connect<'a>(
        &'a mut self,
        cx: &'a mut FilterCtx<'_>,
        blocking: bool,
    ) -> CfFuture<'a, Result<bool>> {
        Box::pin(async move {
            // Already tunneling — the filter is transparent from here on.
            if self.established {
                return Ok(true);
            }

            // Drive the sub-chain (socket, optional HAProxy) to connected first.
            if !cx.connect_next(blocking).await? {
                return Ok(false);
            }

            // The CONNECT handshake, including the proxy-auth retry loop.
            loop {
                // --- INIT: build the request and enter the CONNECT state. ---
                self.tunnel.reinit();
                self.build_request()?;
                self.tunnel.state = H1TunnelState::Connect;

                // --- CONNECT: write the request in full, resuming across
                //     partial sends (curl's CURLE_AGAIN handling). ---
                while self.tunnel.nsent < self.tunnel.request_data.len() {
                    let start = self.tunnel.nsent;
                    let n = cx
                        .send_next(&self.tunnel.request_data[start..], false)
                        .await?;
                    if n == 0 {
                        return Err(Error::proxy("Failed sending CONNECT to proxy"));
                    }
                    self.tunnel.nsent += n;
                }
                self.auth.first_request = false;
                self.tunnel.state = H1TunnelState::Receive;

                // --- RECEIVE: read one byte at a time so we never consume any
                //     tunnel payload that belongs to the layer above. ---
                loop {
                    let mut byte = [0u8; 1];
                    let n = cx.recv_next(&mut byte).await?;
                    if n == 0 {
                        // The proxy closed the connection mid-handshake.
                        if self.auth.has_creds() && self.auth.avail != 0 {
                            // With proxy auth in flight, treat this as a mere
                            // disconnect and let the retry re-open the chain.
                            self.tunnel.close_connection = true;
                            self.tunnel.keepon = KeepOn::Done;
                            tracing::info!("Proxy CONNECT connection closed");
                            break;
                        }
                        return Err(Error::proxy("Proxy CONNECT aborted"));
                    }
                    self.process_response_byte(byte[0])?;
                    if self.tunnel.keepon == KeepOn::Done {
                        break;
                    }
                }
                self.tunnel.state = H1TunnelState::Response;

                // --- RESPONSE: success, retry, or failure. ---
                let code = self.tunnel.httpcode;
                if code / 100 == 2 {
                    self.tunnel.state = H1TunnelState::Established;
                    self.established = true;
                    tracing::info!(code, "CONNECT tunnel established");
                    return Ok(true);
                }

                if self.auth.decide_retry(code) {
                    if self.tunnel.close_connection {
                        // Close and re-open the sub-chain before retrying, then
                        // loop to re-issue the CONNECT (curl's "Connect me
                        // again please").
                        tracing::info!("Connect me again please");
                        cx.close_next();
                        self.tunnel.close_connection = false;
                        if !cx.connect_next(true).await? {
                            return Ok(false);
                        }
                    }
                    continue;
                }

                // Non-2xx with no usable retry: the tunnel failed.
                self.tunnel.state = H1TunnelState::Failed;
                return Err(Error::proxy(format!(
                    "CONNECT tunnel failed, response {code}"
                )));
            }
        })
    }

    fn close(&mut self, cx: &mut FilterCtx<'_>) {
        // Reset our tunnel state and delegate the close downward.
        self.established = false;
        self.tunnel.reinit();
        cx.close_next();
    }

    fn adjust_pollset(&self, cx: &QueryCtx<'_>, ps: &mut Pollset) {
        // Once established the filter is transparent; the layers above and below
        // register their own interest.
        if self.established {
            return;
        }

        // Ask the sub-chain for the socket we are tunneling over.
        let mut out = QueryOut::None;
        if cx.query_next(CfQuery::Socket, &mut out).is_ok() {
            if let QueryOut::Socket(fd) = out {
                if self.tunnel.state == H1TunnelState::Connect {
                    // Still sending the CONNECT request → wait for writability.
                    ps.set(fd, POLL_OUT);
                } else {
                    // Waiting for the CONNECT response → wait for readability.
                    ps.set(fd, POLL_IN);
                }
            }
        }
    }
}

// ===========================================================================
// Factory.
// ===========================================================================

/// Inserts a freshly created [`H1ProxyFilter`] into `chain` immediately after
/// the filter at `at_index`, mirroring `Curl_cf_h1_proxy_insert_after`.
///
/// The new filter therefore sits *above* the transport it tunnels over (the
/// filter previously at `at_index`, e.g. the socket or HAProxy filter) and
/// *below* whatever is added later (TLS, HTTP). Returns
/// [`Error::bad_argument`](crate::error::Error::bad_argument) if `at_index` is
/// out of range, matching [`FilterChain::insert_after`].
///
/// [`Error::bad_argument`]: crate::error::Error::bad_argument
pub fn insert_after(chain: &mut FilterChain, at_index: usize, config: H1ProxyConfig) -> Result<()> {
    chain.insert_after(at_index, Box::new(H1ProxyFilter::new(config)))
}

// ===========================================================================
// Tests.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::{
        copy_header_value, header_contains_token, host_from_authority, insert_after,
        parse_content_length, parse_status_line, ChunkDrainer, H1ProxyConfig, H1ProxyFilter,
        H1TunnelState,
    };
    use crate::conn::filters::{CfFuture, ConnectionFilter, FilterCtx, QueryCtx, QueryOut};
    use crate::conn::{CfQuery, CfType, FilterChain, FIRSTSOCKET};
    use crate::error::{Error, Result};

    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // -- Pure-function unit tests ------------------------------------------

    #[test]
    fn status_line_parsing_matches_curl() {
        assert_eq!(
            parse_status_line("HTTP/1.1 200 Connection established\r\n"),
            Some(200)
        );
        assert_eq!(parse_status_line("HTTP/1.0 407 Proxy Auth\r\n"), Some(407));
        assert_eq!(parse_status_line("HTTP/1.1 403\r\n"), Some(403));
        // A four-digit code is rejected (curl requires a non-digit at [12]).
        assert_eq!(parse_status_line("HTTP/1.1 2001 Nope\r\n"), None);
        // HTTP/2.x is not an HTTP/1 status line.
        assert_eq!(parse_status_line("HTTP/2.0 200 x\r\n"), None);
        assert_eq!(parse_status_line("garbage\r\n"), None);
    }

    #[test]
    fn header_value_copy_trims_blanks_and_crlf() {
        assert_eq!(copy_header_value("Content-Length:  42\r\n"), "42");
        assert_eq!(
            copy_header_value("Proxy-Authenticate: Basic realm=\"x\"\r\n"),
            "Basic realm=\"x\""
        );
        assert_eq!(copy_header_value("X:\tvalue \r\n"), "value");
    }

    #[test]
    fn content_length_parsing() {
        assert_eq!(parse_content_length(" 42 "), Some(42));
        assert_eq!(parse_content_length("0"), Some(0));
        assert_eq!(parse_content_length(""), None);
        assert_eq!(parse_content_length("12x"), None);
        assert_eq!(parse_content_length("-1"), None);
    }

    #[test]
    fn header_token_matching_is_case_insensitive() {
        assert!(header_contains_token(
            "Connection: close\r\n",
            "Connection:",
            "close"
        ));
        assert!(header_contains_token(
            "Proxy-Connection: Keep-Alive, Close\r\n",
            "Proxy-Connection:",
            "close"
        ));
        assert!(!header_contains_token(
            "Connection: keep-alive\r\n",
            "Connection:",
            "close"
        ));
        assert!(!header_contains_token(
            "X-Other: close\r\n",
            "Connection:",
            "close"
        ));
    }

    #[test]
    fn authority_and_host_extraction() {
        let cfg = H1ProxyConfig::new("example.com", 443);
        assert_eq!(cfg.authority(), "example.com:443");
        let v6 = H1ProxyConfig::new("::1", 8080);
        assert_eq!(v6.authority(), "[::1]:8080");
        assert_eq!(host_from_authority("example.com:443"), "example.com");
        assert_eq!(host_from_authority("[::1]:8080"), "::1");
        assert_eq!(host_from_authority("bare"), "bare");
    }

    #[test]
    fn chunk_drainer_zero_chunk_no_trailers() {
        let mut d = ChunkDrainer::new();
        let body = b"0\r\n\r\n";
        let mut done = false;
        for &b in body {
            done = d.feed(b);
        }
        assert!(done);
        assert!(d.is_done());
    }

    #[test]
    fn chunk_drainer_one_data_chunk() {
        let mut d = ChunkDrainer::new();
        let body = b"5\r\nhello\r\n0\r\n\r\n";
        let mut done = false;
        for &b in body {
            done = d.feed(b);
        }
        assert!(done);
    }

    #[test]
    fn chunk_drainer_with_trailer_headers() {
        let mut d = ChunkDrainer::new();
        let body = b"3\r\nabc\r\n0\r\nX-Trailer: v\r\n\r\n";
        let mut done = false;
        for &b in body {
            done = d.feed(b);
        }
        assert!(done);
    }

    // -- Mock-proxy integration harness ------------------------------------

    /// A minimal socket "tail" filter for tests: it performs real byte I/O over
    /// a Tokio [`TcpStream`], optionally capping each `send` to force partial
    /// writes (to exercise the CONNECT send-resume path).
    struct TcpTail {
        stream: Option<TcpStream>,
        max_send: Option<usize>,
    }

    impl TcpTail {
        fn new(stream: TcpStream) -> Self {
            TcpTail {
                stream: Some(stream),
                max_send: None,
            }
        }

        fn with_max_send(stream: TcpStream, max: usize) -> Self {
            TcpTail {
                stream: Some(stream),
                max_send: Some(max),
            }
        }
    }

    impl ConnectionFilter for TcpTail {
        fn name(&self) -> &'static str {
            "TCP"
        }

        fn cf_type(&self) -> CfType {
            CfType::IP_CONNECT
        }

        fn connect<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            _blocking: bool,
        ) -> CfFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }

        fn send<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a [u8],
            _eos: bool,
        ) -> CfFuture<'a, Result<usize>> {
            Box::pin(async move {
                let cap = match self.max_send {
                    Some(m) => m.min(buf.len()),
                    None => buf.len(),
                };
                let s = self.stream.as_mut().expect("stream present");
                let n = s
                    .write(&buf[..cap])
                    .await
                    .map_err(|e| Error::proxy(format!("send io error: {e}")))?;
                Ok(n)
            })
        }

        fn recv<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a mut [u8],
        ) -> CfFuture<'a, Result<usize>> {
            Box::pin(async move {
                let s = self.stream.as_mut().expect("stream present");
                let n = s
                    .read(buf)
                    .await
                    .map_err(|e| Error::proxy(format!("recv io error: {e}")))?;
                Ok(n)
            })
        }

        fn query(&self, _cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
            if query == CfQuery::Socket {
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    if let Some(s) = &self.stream {
                        *out = QueryOut::Socket(s.as_raw_fd());
                    }
                }
            }
            Ok(())
        }
    }

    /// Reads a single HTTP request head (up to and including the terminating
    /// `\r\n\r\n`) one byte at a time, so no tunnel-payload bytes are consumed.
    async fn read_request_head(sock: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        loop {
            let n = sock.read(&mut b).await.expect("server read");
            if n == 0 {
                break;
            }
            buf.push(b[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Builds a chain `[H1ProxyFilter, TcpTail]` over `stream` and drives the
    /// CONNECT handshake with a hard timeout so a bug fails fast.
    async fn connect_through_proxy(
        stream: TcpStream,
        config: H1ProxyConfig,
        max_send: Option<usize>,
    ) -> (FilterChain, Result<bool>) {
        let tail = match max_send {
            Some(m) => TcpTail::with_max_send(stream, m),
            None => TcpTail::new(stream),
        };
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(tail));
        chain.add(Box::new(H1ProxyFilter::new(config)));
        let res = tokio::time::timeout(Duration::from_secs(5), chain.connect(true))
            .await
            .expect("connect timed out");
        (chain, res)
    }

    // -- Integration tests -------------------------------------------------

    #[tokio::test]
    async fn exact_connect_request_bytes_no_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let req = read_request_head(&mut sock).await;
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            req
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let (_chain, res) =
            connect_through_proxy(stream, H1ProxyConfig::new("example.com", 443), None).await;
        assert!(res.unwrap());

        let req = server.await.unwrap();
        assert_eq!(
            req,
            "CONNECT example.com:443 HTTP/1.1\r\n\
             Host: example.com:443\r\n\
             Proxy-Connection: Keep-Alive\r\n\
             \r\n"
        );
    }

    #[tokio::test]
    async fn tunnel_established_then_transparent_passthrough() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _req = read_request_head(&mut sock).await;
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            // Passthrough: read the client's payload, then reply with our own.
            let mut got = [0u8; 5];
            sock.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"hello");
            sock.write_all(b"world").await.unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut chain, res) =
            connect_through_proxy(stream, H1ProxyConfig::new("example.com", 443), None).await;
        assert!(res.unwrap());

        // The filter is now transparent: send/recv delegate straight through.
        let sent = chain.send(b"hello", false).await.unwrap();
        assert_eq!(sent, 5);
        let mut buf = [0u8; 5];
        let mut got = 0;
        while got < 5 {
            got += chain.recv(&mut buf[got..]).await.unwrap();
        }
        assert_eq!(&buf, b"world");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn proxy_auth_407_basic_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // First CONNECT: no credentials yet.
            let first = read_request_head(&mut sock).await;
            sock.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"proxy\"\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
            // Second CONNECT: must carry the Basic credentials.
            let second = read_request_head(&mut sock).await;
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            (first, second)
        });

        let mut config = H1ProxyConfig::new("example.com", 443);
        config.proxy_user = Some("aladdin".to_string());
        config.proxy_password = Some("opensesame".to_string());

        let stream = TcpStream::connect(addr).await.unwrap();
        let (_chain, res) = connect_through_proxy(stream, config, None).await;
        assert!(res.unwrap());

        let (first, second) = server.await.unwrap();
        // The first request must NOT include auth.
        assert!(!first.contains("Proxy-Authorization"));
        // The second must include the exact Basic header (RFC 7617 base64 of
        // "aladdin:opensesame").
        assert!(
            second.contains("Proxy-Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l\r\n"),
            "second request missing correct Basic header:\n{second}"
        );
    }

    #[tokio::test]
    async fn proxy_connect_403_returns_error_proxy_97() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _req = read_request_head(&mut sock).await;
            sock.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let (_chain, res) =
            connect_through_proxy(stream, H1ProxyConfig::new("example.com", 443), None).await;

        let err = res.expect_err("403 must fail the CONNECT");
        // The binding requirement is the integer error code: CURLE_PROXY == 97.
        assert_eq!(err.code_i32(), 97, "CURLE_PROXY must map to integer 97");
        // `Error::Proxy`'s `Display` is curl's fixed `strerror` text
        // ("proxy handshake error"), preserved byte-for-byte for parity with
        // `curl_easy_strerror(CURLE_PROXY)`. The offending status code lives in
        // the carried detail string — the analogue of curl's `failf` message
        // that populates the easy handle's error buffer, kept separate from the
        // canonical strerror text. Assert on that detail.
        match err {
            Error::Proxy(detail) => assert!(
                detail.contains("403"),
                "proxy detail should mention the status code, got: {detail:?}"
            ),
            other => panic!("expected Error::Proxy, got {other:?}"),
        }

        server.await.unwrap();
    }

    #[tokio::test]
    async fn partial_send_resume() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let req = read_request_head(&mut sock).await;
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            req
        });

        // Cap each send at 4 bytes so the request is written across many chunks.
        let stream = TcpStream::connect(addr).await.unwrap();
        let (_chain, res) =
            connect_through_proxy(stream, H1ProxyConfig::new("example.com", 443), Some(4)).await;
        assert!(res.unwrap());

        let req = server.await.unwrap();
        assert!(req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn multi_read_header_assembly() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _req = read_request_head(&mut sock).await;
            // Deliver the response split across two writes mid-status-line and
            // mid-header, to prove byte-at-a-time assembly.
            sock.write_all(b"HTTP/1.1 200 Conn").await.unwrap();
            sock.write_all(b"ection established\r").await.unwrap();
            sock.write_all(b"\n\r\n").await.unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let (_chain, res) =
            connect_through_proxy(stream, H1ProxyConfig::new("example.com", 443), None).await;
        assert!(res.unwrap());

        server.await.unwrap();
    }

    #[tokio::test]
    async fn auth_407_drains_content_length_body_before_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _first = read_request_head(&mut sock).await;
            // 407 with a 5-byte body that the client must drain before retrying
            // on the same connection.
            sock.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"p\"\r\n\
                  Content-Length: 5\r\n\r\nhello",
            )
            .await
            .unwrap();
            let second = read_request_head(&mut sock).await;
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            second
        });

        let mut config = H1ProxyConfig::new("example.com", 443);
        config.proxy_user = Some("aladdin".to_string());
        config.proxy_password = Some("opensesame".to_string());

        let stream = TcpStream::connect(addr).await.unwrap();
        let (_chain, res) = connect_through_proxy(stream, config, None).await;
        assert!(res.unwrap());

        let second = server.await.unwrap();
        assert!(second.contains("Proxy-Authorization: Basic "));
    }

    #[tokio::test]
    async fn auth_407_drains_chunked_body_before_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _first = read_request_head(&mut sock).await;
            sock.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"p\"\r\n\
                  Transfer-Encoding: chunked\r\n\r\n\
                  5\r\nhello\r\n0\r\n\r\n",
            )
            .await
            .unwrap();
            let second = read_request_head(&mut sock).await;
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            second
        });

        let mut config = H1ProxyConfig::new("example.com", 443);
        config.proxy_user = Some("aladdin".to_string());
        config.proxy_password = Some("opensesame".to_string());

        let stream = TcpStream::connect(addr).await.unwrap();
        let (_chain, res) = connect_through_proxy(stream, config, None).await;
        assert!(res.unwrap());

        let second = server.await.unwrap();
        assert!(second.contains("Proxy-Authorization: Basic "));
    }

    #[tokio::test]
    async fn insert_after_places_http_proxy_filter() {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        // A bare placeholder tail to insert after.
        chain.add(Box::new(PlaceholderTail));
        assert_eq!(chain.len(), 1);

        insert_after(&mut chain, 0, H1ProxyConfig::new("example.com", 443)).unwrap();
        assert_eq!(chain.len(), 2);
        // The inserted filter sits directly below index 0.
        // (We cannot borrow it by index publicly, but the tail is still the
        // placeholder and the head is unchanged, so the HTTP-PROXY filter is at
        // index 1.)
        assert_eq!(chain.head().unwrap().name(), "PLACEHOLDER");

        // Out-of-range index is rejected, mirroring FilterChain::insert_after.
        let err = insert_after(&mut chain, 99, H1ProxyConfig::new("h", 1)).unwrap_err();
        assert!(matches!(
            err,
            Error::BadFunctionArgument(_) | Error::Code(_)
        ));
    }

    #[test]
    fn filter_identity_name_and_type() {
        let f = H1ProxyFilter::new(H1ProxyConfig::new("h", 80));
        assert_eq!(f.name(), "HTTP-PROXY");
        let t = f.cf_type();
        assert!(t.contains(CfType::PROXY));
        assert!(t.contains(CfType::HTTP));
        assert!(!t.contains(CfType::SSL));
        // A freshly built filter starts in the Init tunnel state.
        assert_eq!(f.tunnel.state, H1TunnelState::Init);
    }

    /// A do-nothing tail filter used only for structural (`insert_after`) tests.
    struct PlaceholderTail;

    impl ConnectionFilter for PlaceholderTail {
        fn name(&self) -> &'static str {
            "PLACEHOLDER"
        }
        fn cf_type(&self) -> CfType {
            CfType::IP_CONNECT
        }
        fn connect<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            _blocking: bool,
        ) -> CfFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }
    }
}
