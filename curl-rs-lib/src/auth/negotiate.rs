//! HTTP `Negotiate` (SPNEGO) authentication — **feature-gated OFF by default**.
//!
//! This module is the memory-safe Rust replacement for curl's SPNEGO glue,
//! combining the responsibilities of two C translation units that are treated
//! here strictly as a **behavioral oracle**:
//!
//! * `lib/http_negotiate.c` — the HTTP layer glue (`Curl_input_negotiate`,
//!   `Curl_output_negotiate`) that drives the per-connection state machine and
//!   formats the `Authorization: Negotiate …` header.
//! * `lib/vauth/spnego_gssapi.c` — the SPNEGO mechanism itself
//!   (`Curl_auth_is_spnego_supported`, `Curl_auth_decode_spnego_message`,
//!   `Curl_auth_create_spnego_message`, `Curl_auth_cleanup_spnego`), which in C
//!   is backed by a system GSS-API (`libgssapi`).
//!
//! # Why this module is OFF by default (the version-parity contract)
//!
//! curl's *default* build does **not** enable SPNEGO: it reports neither the
//! `SPNEGO` / `GSS-API` capability strings nor the `CURL_VERSION_SPNEGO`
//! (`1 << 8`) feature bit. The Rust rewrite must report the **same** default
//! capability set so that `curl --version`, `curl-config --features`, and the
//! `runtests` feature-detection select the identical subset of tests
//! (Agent Action Plan §0.7.3). To guarantee that, the **entire module** —
//! every type, function, and test below — is compiled only under the
//! `spnego` Cargo feature, which is **not** part of the crate's `default`
//! feature set. This gate is kept in lockstep with `crate::version`, whose
//! `feature_names()` deliberately omits `SPNEGO`: when `spnego` is off, this
//! module contributes nothing and the reported capability set stays equal to
//! stock curl's default build.
//!
//! The companion `crate::auth` picker (`pickoneauth`) lists `Negotiate` as the
//! highest-priority scheme, but only behind the same `spnego` feature; with the
//! feature off, both the picker branch and this module are compiled out
//! together, so they can never disagree.
//!
//! # GSS-API scope caveat (shared with `crate::auth::kerberos`)
//!
//! SPNEGO genuinely requires a GSS-API provider to mint and verify security
//! tokens, and there is no pure-Rust GSS-API implementation to depend on. In
//! line with the minimal-change mandate (AAP §0.8.1) this module therefore does
//! **not** ship a from-scratch GSS-API: the token-exchange step
//! ([`gss_accept_sec_context`]) is a documented stub that reports
//! [`CurlError::AuthError`], mirroring exactly the `CURLE_AUTH_ERROR` that curl
//! returns from `gss_init_sec_context()` failure (`GSS_ERROR`). Everything that
//! does **not** require a provider — the per-connection state machine, the
//! base64 challenge decode/response encode, the SPN construction, and the
//! `Authorization` header formatting — is implemented faithfully and is fully
//! unit-tested. When a real provider becomes available it slots in behind the
//! same [`gss_accept_sec_context`] seam without disturbing this glue.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` and compiles cleanly under the
//! crate-root `#![forbid(unsafe_code)]`. There are no SSPI/Windows branches
//! (out of scope): the design follows only curl's `HAVE_GSSAPI` path.

// The whole module is conditional on the `spnego` feature. Declared as an inner
// attribute so the file is self-gating regardless of whether the parent module
// declares it with `#[cfg(feature = "spnego")] pub mod negotiate;` or plainly:
// when the feature is absent, this module compiles to nothing and reports no
// SPNEGO capability, matching curl's default build (AAP §0.7.3).
#![cfg(feature = "spnego")]

use crate::auth::build_spn;
use crate::error::{CurlError, Result};
use crate::util::base64::{base64_decode, base64_encode};

/// The default GSS service name used when the caller does not set one, matching
/// the `"HTTP"` default in `Curl_input_negotiate`/`Curl_output_negotiate`.
const DEFAULT_SERVICE: &str = "HTTP";

/// The HTTP `Negotiate` authentication scheme token, used both to strip the
/// scheme prefix off an inbound challenge and to format the outbound header.
const SCHEME: &str = "Negotiate";

// =============================================================================
// Phase A — state model (mirrors `curlnegotiate` from lib/urldata.h)
// =============================================================================

/// Per-connection Negotiate state-machine position.
///
/// This is the exact mirror of C's `curlnegotiate` enum (`lib/urldata.h`):
///
/// ```text
/// GSS_AUTHNONE → GSS_AUTHRECV → GSS_AUTHSENT → GSS_AUTHDONE
///                                            ↘ GSS_AUTHSUCC
/// ```
///
/// In the full engine these values live on the connection as
/// `http_negotiate_state` (origin host) and `proxy_negotiate_state` (proxy),
/// owned by `crate::conn`. Here the state is carried inside [`NegotiateData`]
/// so the host and proxy channels are each a single self-contained object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NegotiateState {
    /// No Negotiate exchange in progress (`GSS_AUTHNONE`). Initial state.
    #[default]
    AuthNone,
    /// A challenge was received from the server (`GSS_AUTHRECV`).
    AuthRecv,
    /// Our challenge-response has been sent (`GSS_AUTHSENT`).
    AuthSent,
    /// The handshake completed locally; no further header is required
    /// (`GSS_AUTHDONE`).
    AuthDone,
    /// The server accepted authentication (`GSS_AUTHSUCC`).
    AuthSucc,
}

/// Mirror of the GSS-API major-status values this glue inspects.
///
/// curl only distinguishes three outcomes when deciding whether the security
/// context is finished (`Curl_output_negotiate`): `GSS_S_COMPLETE` and
/// `GSS_S_CONTINUE_NEEDED` both mean "a token was produced, advance to
/// `GSS_AUTHDONE`", while anything else leaves the state at `GSS_AUTHSENT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum GssStatus {
    /// No status recorded yet (initial / after cleanup).
    #[default]
    None,
    /// `GSS_S_CONTINUE_NEEDED` — a token was produced and more legs may follow.
    ///
    /// Modeled for fidelity with the oracle, whose `Curl_output_negotiate`
    /// advances to `GSS_AUTHDONE` on `GSS_S_COMPLETE` **or**
    /// `GSS_S_CONTINUE_NEEDED`. Because this build ships no GSS-API provider
    /// (see the module-level scope caveat), [`gss_accept_sec_context`] never
    /// succeeds, so this success-path variant is not constructed by the library
    /// path yet — a real provider constructs it with no change to this glue.
    /// The targeted `allow` keeps the modeled status set complete (and the
    /// matching `matches!` arm in [`output_negotiate`] exact) without tripping
    /// the zero-warnings (`-D dead_code`) gate; a unit test still exercises the
    /// transition it drives.
    #[allow(dead_code)]
    ContinueNeeded,
    /// `GSS_S_COMPLETE` — the local side of the context is complete.
    Complete,
}

/// Per-connection SPNEGO (`Negotiate`) context and persistence flags.
///
/// This is the Rust mirror of C's `struct negotiatedata` (`lib/vauth/vauth.h`)
/// together with the per-connection `curlnegotiate` state. In curl the GSS-API
/// members (`context`, `spn`, `output_token`, `status`) are raw library handles
/// freed by `Curl_auth_cleanup_spnego`; here they are ordinary owned Rust
/// values reclaimed automatically by `Drop`, so [`reset`](NegotiateData::reset)
/// only has to restore the initial field values — there is nothing to free by
/// hand.
///
/// The four `BIT(...)` persistence flags from the C struct
/// (`noauthpersist`, `havenoauthpersist`, `havenegdata`,
/// `havemultiplerequests`) are preserved verbatim because they drive the
/// connection-reuse decisions in [`output_negotiate`].
#[derive(Debug, Clone, Default)]
pub struct NegotiateData {
    /// State-machine position (the connection's `*_negotiate_state`).
    state: NegotiateState,
    /// The imported service principal name, e.g. `"HTTP@example.com"`. Built
    /// once via [`build_spn`] and cached for the lifetime of the exchange
    /// (mirrors `nego->spn`, which is only generated when `!nego->spn`).
    spn: Option<String>,
    /// The most recent locally generated output token awaiting transmission
    /// (mirrors `nego->output_token`). Base64-encoded into the `Authorization`
    /// header by [`create_spnego_message`].
    output_token: Option<Vec<u8>>,
    /// Whether a security context has been established (mirrors the
    /// `nego->context != GSS_C_NO_CONTEXT` test that gates re-entry in
    /// `Curl_output_negotiate`).
    context_established: bool,
    /// Last GSS-API major status (mirrors `nego->status`).
    status: GssStatus,
    /// `noauthpersist` — do not keep the credentials/context across requests.
    noauthpersist: bool,
    /// `havenoauthpersist` — the no-persist decision was made externally and
    /// must not be recomputed.
    havenoauthpersist: bool,
    /// `havenegdata` — the last inbound challenge carried token data.
    havenegdata: bool,
    /// `havemultiplerequests` — more than one request was needed, so the
    /// context must persist across the connection.
    havemultiplerequests: bool,
}

/// Connection-derived inputs for a single Negotiate input/output step.
///
/// These correspond to the values `Curl_input_negotiate`/
/// `Curl_output_negotiate` read out of `conn`/`data` (selecting the proxy or
/// origin-host variants via the `proxy` flag). Bundling them keeps the public
/// functions readable and avoids a long positional parameter list.
#[derive(Debug, Clone, Copy)]
pub struct NegotiateRequest<'a> {
    /// `true` to authenticate against the proxy (emits the `Proxy-` header
    /// prefix and selects the proxy state), `false` for the origin host.
    pub proxy: bool,
    /// The GSS service type (e.g. `"HTTP"`). `None` selects the
    /// [`DEFAULT_SERVICE`] (`"HTTP"`), matching curl's default.
    pub service: Option<&'a str>,
    /// The target hostname used to build the service principal name.
    pub host: &'a str,
    /// The configured username. The SPNEGO/GSS-API mechanism itself does not
    /// consume it (`(void)user;` in `spnego_gssapi.c`) — it relies on ambient
    /// credentials — but it is threaded through for parity with the C glue,
    /// which resolves `conn->user` for every auth scheme.
    pub user: &'a str,
    /// The configured password. Unused by the mechanism for the same reason as
    /// [`user`](NegotiateRequest::user) (`(void)password;`).
    pub password: &'a str,
    /// Optional TLS channel-binding data (`tls-server-end-point`).
    ///
    /// When the connection is over TLS, curl supplies endpoint channel-binding
    /// bytes to the GSS-API layer under `GSS_C_CHANNEL_BOUND_FLAG` semantics
    /// (`Curl_ssl_get_channel_binding`). This is therefore **TLS-dependent**:
    /// callers pass `Some(..)` only on a TLS connection that produced binding
    /// data, and `None` otherwise. The value is forwarded to
    /// [`gss_accept_sec_context`] exactly as the C code forwards
    /// `nego->channel_binding_data`.
    pub channel_binding: Option<&'a [u8]>,
}

/// The result of [`output_negotiate`].
///
/// Replaces the C side effects of `Curl_output_negotiate`, which writes the
/// formatted header into `data->state.aptr.userpwd`/`proxyuserpwd` and sets
/// `authp->done`. Returning them keeps this module free of engine state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NegotiateOutput {
    /// The full header line to emit this round, e.g.
    /// `"Authorization: Negotiate YII…\r\n"` (or `Proxy-Authorization:` for a
    /// proxy). `None` when no header is to be sent (handshake already complete,
    /// or auth gave up and the request continues unauthenticated).
    pub header: Option<String>,
    /// Mirror of `authp->done`: when `true`, the Negotiate handshake is
    /// finished (successfully or by giving up) and no further `Authorization`
    /// header should be generated for this connection.
    pub done: bool,
}

/// Whether SPNEGO (`Negotiate`) is supported by this build.
///
/// Mirrors `Curl_auth_is_spnego_supported()`, which returns `TRUE` whenever the
/// SPNEGO code is compiled in. Because this entire module only exists under the
/// `spnego` feature, the function unconditionally returns `true` here; in a
/// default build the function does not exist at all (and the picker reports
/// Negotiate as unavailable), exactly mirroring curl's compile-time behavior.
#[must_use]
pub fn is_spnego_supported() -> bool {
    true
}

impl NegotiateData {
    /// Creates a fresh, idle Negotiate context (state `AuthNone`, no SPN, no
    /// token, all persistence flags clear).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current state-machine position.
    ///
    /// The engine uses this to mirror reads of `conn->http_negotiate_state` /
    /// `conn->proxy_negotiate_state`.
    #[must_use]
    pub fn state(&self) -> NegotiateState {
        self.state
    }

    /// Resets the context to its initial state.
    ///
    /// This is the combined effect of curl's `http_auth_nego_reset()` (which
    /// sets the connection state back to `GSS_AUTHNONE`) and
    /// `Curl_auth_cleanup_spnego()` (which releases the GSS-API context, output
    /// token and SPN and clears every persistence flag). Because all members
    /// are owned Rust values, there is nothing to free explicitly — restoring
    /// the default field values is sufficient and `Drop` reclaims the rest.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// =============================================================================
// Phase B — input / decode
// (mirrors `Curl_input_negotiate` + `Curl_auth_decode_spnego_message`)
// =============================================================================

/// Processes an inbound `Negotiate` (SPNEGO) challenge header.
///
/// This is the Rust port of `Curl_input_negotiate` (`lib/http_negotiate.c`)
/// fused with `Curl_auth_decode_spnego_message` (`lib/vauth/spnego_gssapi.c`).
/// `nego` carries the per-connection state and is mutated in place; `req`
/// supplies the connection-derived inputs; `header` is the raw inbound header
/// value, which is expected to begin with the `Negotiate` scheme token (the
/// HTTP layer matched it case-insensitively before dispatching here).
///
/// Behavior, step by step, matching the oracle exactly:
///
/// 1. The `Negotiate` scheme prefix and any following blanks are stripped, and
///    `havenegdata` is set to whether token data remains
///    (`neg_ctx->havenegdata = len != 0`).
/// 2. If **no** token data remains:
///    * state `AuthSucc` → the server restarted the handshake, so the context
///      is reset and a fresh exchange begins;
///    * any state other than `AuthNone` → the server rejected us with no further
///      mechanism, so the context is reset and [`CurlError::LoginDenied`]
///      (`CURLE_LOGIN_DENIED`) is returned;
///    * state `AuthNone` → fall through to generate the initial token.
/// 3. The (optional) base64 challenge is decoded and the security context is
///    advanced via [`gss_accept_sec_context`]. Any error resets the context
///    before propagating, exactly as `if(result) http_auth_nego_reset(...)`.
///
/// # Errors
///
/// * [`CurlError::LoginDenied`] — the server rejected authentication with no
///   continuation, or a second challenge arrived after a completed context.
/// * [`CurlError::BadContentEncoding`] — the challenge was not valid base64.
/// * [`CurlError::AuthError`] — token generation failed; with no GSS-API
///   provider compiled in this is the normal outcome (see the module-level
///   scope caveat), and the caller continues unauthenticated.
pub fn input_negotiate(
    nego: &mut NegotiateData,
    req: &NegotiateRequest<'_>,
    header: &str,
) -> Result<()> {
    let service = req.service.unwrap_or(DEFAULT_SERVICE);

    // Strip the "Negotiate" scheme prefix, then leading blanks (SP/HTAB), the
    // equivalent of `header += strlen("Negotiate"); curlx_str_passblanks(...)`.
    // The HTTP layer guarantees the prefix is present; if it is somehow absent
    // we defensively treat the whole value as the token rather than panicking.
    let after_scheme = strip_scheme_prefix(header);
    let token = after_scheme.trim_start_matches([' ', '\t']);

    nego.havenegdata = !token.is_empty();

    if token.is_empty() {
        match nego.state {
            NegotiateState::AuthSucc => {
                // "Negotiate auth restarted" — drop the finished context and
                // begin a new exchange (falls through to token generation).
                nego.reset();
            }
            NegotiateState::AuthNone => {
                // First leg: nothing received yet, generate the initial token.
            }
            _ => {
                // The server rejected us and supplied no further mechanism.
                nego.reset();
                return Err(CurlError::LoginDenied);
            }
        }
    }

    // Initialize the security context and decode the challenge. On any failure
    // the context is reset before the error propagates, matching
    // `if(result) http_auth_nego_reset(conn, neg_ctx, proxy);`.
    let result = decode_spnego_message(nego, service, req.host, token, req.channel_binding);
    if result.is_err() {
        nego.reset();
    }
    result
}

/// Strips a leading `Negotiate` scheme token from a challenge header value.
///
/// Mirrors the positional `header += strlen("Negotiate")` in
/// `Curl_input_negotiate`. The scheme match is ASCII-case-insensitive (HTTP
/// auth-scheme names are case-insensitive); if the value does not start with
/// the scheme token the input is returned unchanged.
fn strip_scheme_prefix(header: &str) -> &str {
    if header.len() >= SCHEME.len() && header[..SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
        &header[SCHEME.len()..]
    } else {
        header
    }
}

/// Decodes a SPNEGO challenge and advances the security context.
///
/// Rust port of `Curl_auth_decode_spnego_message`. The challenge `chlg64` is
/// the base64 token already stripped of its scheme prefix (it may be empty for
/// the initial leg). On success the freshly generated output token is stored on
/// `nego` for [`create_spnego_message`] to encode.
fn decode_spnego_message(
    nego: &mut NegotiateData,
    service: &str,
    host: &str,
    chlg64: &str,
    channel_binding: Option<&[u8]>,
) -> Result<()> {
    // "We finished our part successfully, but the server is challenging us
    // again — it rejected the result. There is nothing better to do than fail."
    if nego.context_established && nego.status == GssStatus::Complete {
        return Err(CurlError::LoginDenied);
    }

    // Generate and cache the service principal name once (mirrors the
    // `if(!nego->spn)` guard). SPNEGO uses the host-based form `service@host`,
    // which is `Curl_auth_build_spn(service, NULL, host)` in the oracle.
    if nego.spn.is_none() {
        nego.spn = Some(build_spn(service, None, Some(host)));
    }

    // Decode the optional base64 challenge. curl only decodes when the value is
    // non-empty and does not begin with '='; a leading '=' (or otherwise empty
    // result) is reported as a malformed challenge.
    let challenge: Option<Vec<u8>> = if chlg64.is_empty() {
        None
    } else if chlg64.starts_with('=') {
        // `if(!chlg) { infof("empty challenge"); return CURLE_BAD_CONTENT_ENCODING; }`
        return Err(CurlError::BadContentEncoding);
    } else {
        Some(base64_decode(chlg64.as_bytes())?)
    };

    // Advance the GSS-API security context. With no provider compiled in this
    // fails with CURLE_AUTH_ERROR, the same code curl returns on GSS_ERROR.
    let spn = nego.spn.as_deref().ok_or(CurlError::AuthError)?;
    let output_token = gss_accept_sec_context(spn, challenge.as_deref(), channel_binding)?;

    // A successful context must yield a non-empty token (mirrors the
    // `if(!output_token.value || !output_token.length)` guard).
    if output_token.is_empty() {
        return Err(CurlError::AuthError);
    }

    nego.output_token = Some(output_token);
    nego.context_established = true;
    Ok(())
}

/// GSS-API security-context advancement seam (`gss_init_sec_context`).
///
/// This is the single point at which a real GSS-API provider would be invoked.
/// Because there is no pure-Rust GSS-API implementation to depend on (see the
/// module-level scope caveat), this build cannot mint a SPNEGO token, so the
/// function reports [`CurlError::AuthError`] — byte-for-byte the
/// `CURLE_AUTH_ERROR` curl returns when `gss_init_sec_context()` fails with
/// `GSS_ERROR`. The downstream effect is curl's documented compatibility
/// behavior: the request proceeds unauthenticated rather than aborting.
///
/// The `spn`, `challenge`, and `channel_binding` inputs are exactly what a
/// provider would consume (the imported service name, the decoded inbound
/// token, and the TLS endpoint channel-binding bytes); they are accepted here
/// so the seam's signature is already correct for a future provider.
fn gss_accept_sec_context(
    spn: &str,
    challenge: Option<&[u8]>,
    channel_binding: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // Inputs a real provider consumes; explicitly discarded to document intent
    // and keep the signature stable for a drop-in GSS-API backend.
    let _ = (spn, challenge, channel_binding);
    Err(CurlError::AuthError)
}

// =============================================================================
// Phase C — output
// (mirrors `Curl_output_negotiate` + `Curl_auth_create_spnego_message`)
// =============================================================================

/// Produces the outbound `Authorization: Negotiate …` header (if any) and
/// reports whether the handshake is finished.
///
/// Rust port of `Curl_output_negotiate` (`lib/http_negotiate.c`) fused with
/// `Curl_auth_create_spnego_message` (`lib/vauth/spnego_gssapi.c`). The
/// per-connection [`NegotiateData`] is advanced through the state machine and
/// the formatted header is returned in [`NegotiateOutput`] rather than being
/// written into engine state.
///
/// The flow mirrors the oracle precisely:
///
/// 1. Reset `authp->done` to `false`.
/// 2. Persistence bookkeeping:
///    * state `AuthRecv` → if the last challenge carried data, record that
///      multiple requests are in flight (`havemultiplerequests = true`);
///    * state `AuthSucc` → unless the no-persist decision was made externally,
///      derive `noauthpersist` from whether multiple requests were needed.
/// 3. If the context is not persistent, or the state is neither `AuthDone` nor
///    `AuthSucc`, a new token is generated:
///    * if a non-persistent already-succeeded context exists, it is reset
///      first;
///    * if no security context exists yet, [`input_negotiate`] is driven with a
///      bare `"Negotiate"` to mint the initial token. A
///      [`CurlError::AuthError`] there is curl's compatibility signal to
///      **continue unauthenticated** (`authp->done = TRUE; return CURLE_OK;`),
///      so this returns a header-less, `done: true` result;
///    * the token is base64-encoded and formatted into the header, the state
///      advances to `AuthSent`, and, if the GSS status is complete/continue, to
///      `AuthDone`.
/// 4. If the resulting state is `AuthDone` or `AuthSucc`, `done` is set.
/// 5. `havenegdata` is cleared for the next round.
///
/// # Errors
///
/// Propagates any non-`AuthError` failure from [`input_negotiate`] (for example
/// [`CurlError::LoginDenied`]) and any failure from
/// [`create_spnego_message`].
pub fn output_negotiate(
    nego: &mut NegotiateData,
    req: &NegotiateRequest<'_>,
) -> Result<NegotiateOutput> {
    let mut done = false;
    let mut header: Option<String> = None;

    // Persistence bookkeeping driven by the current state. Expressed with match
    // guards (a failed guard falls through to the `_` no-op arm), which is the
    // exact equivalent of curl's nested `if(*state == GSS_AUTHRECV) { if(...) }`
    // / `else if(*state == GSS_AUTHSUCC) { if(...) }`.
    match nego.state {
        // GSS_AUTHRECV: a fresh challenge that carried data means more than one
        // request is in flight, so the context must persist.
        NegotiateState::AuthRecv if nego.havenegdata => {
            nego.havemultiplerequests = true;
        }
        // GSS_AUTHSUCC: unless the no-persist decision was made externally,
        // derive it from whether multiple requests were needed.
        NegotiateState::AuthSucc if !nego.havenoauthpersist => {
            nego.noauthpersist = !nego.havemultiplerequests;
        }
        _ => {}
    }

    let needs_token = nego.noauthpersist
        || (nego.state != NegotiateState::AuthDone && nego.state != NegotiateState::AuthSucc);

    if needs_token {
        // Drop a finished-but-non-persistent context before re-authenticating.
        if nego.noauthpersist && nego.state == NegotiateState::AuthSucc {
            nego.reset();
        }

        // Generate the initial token if no security context exists yet.
        if !nego.context_established {
            match input_negotiate(nego, req, SCHEME) {
                Ok(()) => {}
                Err(CurlError::AuthError) => {
                    // Negotiate failed and there is no provider/credential:
                    // continue unauthenticated to stay compatible with curl's
                    // behavior prior to curl-7_64_0-158-g6c6035532.
                    return Ok(NegotiateOutput {
                        header: None,
                        done: true,
                    });
                }
                Err(other) => return Err(other),
            }
        }

        // Base64-encode the generated response and format the header.
        let encoded = create_spnego_message(nego)?;
        header = Some(build_authorization_header(req.proxy, &encoded));

        nego.state = NegotiateState::AuthSent;
        if matches!(nego.status, GssStatus::Complete | GssStatus::ContinueNeeded) {
            nego.state = NegotiateState::AuthDone;
        }
    }

    // An already-authenticated connection must not send further headers.
    if nego.state == NegotiateState::AuthDone || nego.state == NegotiateState::AuthSucc {
        done = true;
    }

    // Clear the per-round inbound-data flag for the next exchange.
    nego.havenegdata = false;

    Ok(NegotiateOutput { header, done })
}

/// Base64-encodes the pending output token into the response message text.
///
/// Rust port of `Curl_auth_create_spnego_message`. Returns the base64 text as a
/// `String` (the encoder emits the ASCII base64 alphabet). An absent or empty
/// token, or an empty encoding, is reported as
/// [`CurlError::RemoteAccessDenied`], matching the
/// `CURLE_REMOTE_ACCESS_DENIED` curl returns for an empty result.
fn create_spnego_message(nego: &NegotiateData) -> Result<String> {
    let token = nego
        .output_token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or(CurlError::RemoteAccessDenied)?;

    let encoded = base64_encode(token)?;
    if encoded.is_empty() {
        return Err(CurlError::RemoteAccessDenied);
    }

    // The base64 alphabet is ASCII, so this conversion never fails in practice;
    // map any unexpected non-UTF-8 byte to an auth error rather than panicking.
    String::from_utf8(encoded).map_err(|_| CurlError::AuthError)
}

/// Formats the complete `Authorization: Negotiate <base64>\r\n` header line.
///
/// Mirrors the `curl_maprintf("%sAuthorization: Negotiate %s\r\n", proxy ?
/// "Proxy-" : "", base64)` in `Curl_output_negotiate`. When `proxy` is `true`
/// the line uses the `Proxy-Authorization` header name.
fn build_authorization_header(proxy: bool, base64: &str) -> String {
    let prefix = if proxy { "Proxy-" } else { "" };
    format!("{prefix}Authorization: {SCHEME} {base64}\r\n")
}

// =============================================================================
// Phase D — unit tests
//
// These run under `--features spnego` only (the whole module is gated). They
// exercise the parts that do not need a GSS-API provider: the state machine,
// the empty/non-empty challenge handling, the base64 decode/encode error
// surface, and the `Authorization` header shape. Where a real provider would
// otherwise be required, the context is pre-seeded to simulate an established
// security context — exactly the `if(!neg_ctx->context)` skip path in the
// oracle.
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// `base64_encode(b"abc")` — used to assert the exact header shape without
    /// re-deriving the encoding inside the test.
    const ABC_B64: &str = "YWJj";

    /// Builds a minimal origin-host request against `example.com`.
    fn host_req() -> NegotiateRequest<'static> {
        NegotiateRequest {
            proxy: false,
            service: None,
            host: "example.com",
            user: "",
            password: "",
            channel_binding: None,
        }
    }

    #[test]
    fn spnego_is_supported_when_compiled() {
        // Mirrors `Curl_auth_is_spnego_supported() == TRUE` under USE_SPNEGO.
        assert!(is_spnego_supported());
    }

    #[test]
    fn new_context_is_idle() {
        let nego = NegotiateData::new();
        assert_eq!(nego.state(), NegotiateState::AuthNone);
        assert!(nego.spn.is_none());
        assert!(nego.output_token.is_none());
        assert!(!nego.context_established);
    }

    #[test]
    fn reset_restores_initial_state() {
        let mut nego = NegotiateData::new();
        nego.state = NegotiateState::AuthSucc;
        nego.context_established = true;
        nego.output_token = Some(vec![1, 2, 3]);
        nego.spn = Some("HTTP@example.com".to_string());
        nego.havenegdata = true;
        nego.havemultiplerequests = true;

        nego.reset();

        assert_eq!(nego.state(), NegotiateState::AuthNone);
        assert!(nego.spn.is_none());
        assert!(nego.output_token.is_none());
        assert!(!nego.context_established);
        assert!(!nego.havenegdata);
        assert!(!nego.havemultiplerequests);
    }

    #[test]
    fn strip_scheme_prefix_is_case_insensitive_and_tolerant() {
        assert_eq!(strip_scheme_prefix("Negotiate abc"), " abc");
        assert_eq!(strip_scheme_prefix("negotiate abc"), " abc");
        assert_eq!(strip_scheme_prefix("NEGOTIATE"), "");
        // A value that does not start with the scheme is returned unchanged.
        assert_eq!(strip_scheme_prefix("Other data"), "Other data");
    }

    // ---- Phase B: input/decode state transitions ----------------------------

    #[test]
    fn empty_challenge_in_authsucc_restarts_handshake() {
        // state == GSS_AUTHSUCC + empty token => "Negotiate auth restarted":
        // the context is reset and a fresh exchange is attempted. With no
        // provider the fresh attempt fails with AuthError (NOT LoginDenied),
        // which is how the restart is observable.
        let mut nego = NegotiateData::new();
        nego.state = NegotiateState::AuthSucc;

        let result = input_negotiate(&mut nego, &host_req(), "Negotiate");

        assert_eq!(result, Err(CurlError::AuthError));
        assert_ne!(result, Err(CurlError::LoginDenied));
        assert_eq!(nego.state(), NegotiateState::AuthNone);
        assert!(!nego.havenegdata);
    }

    #[test]
    fn empty_challenge_in_non_none_state_is_login_denied() {
        // state != GSS_AUTHNONE (and != AUTHSUCC) + empty token => the server
        // rejected us with no further mechanism => CURLE_LOGIN_DENIED, context
        // reset.
        let mut nego = NegotiateData::new();
        nego.state = NegotiateState::AuthSent;

        let result = input_negotiate(&mut nego, &host_req(), "Negotiate");

        assert_eq!(result, Err(CurlError::LoginDenied));
        assert_eq!(nego.state(), NegotiateState::AuthNone);
    }

    #[test]
    fn empty_challenge_in_authnone_attempts_initial_token() {
        // state == GSS_AUTHNONE + empty token => generate the initial token.
        // No provider => AuthError (not LoginDenied), and the SPN was built.
        let mut nego = NegotiateData::new();

        let result = input_negotiate(&mut nego, &host_req(), "Negotiate");

        assert_eq!(result, Err(CurlError::AuthError));
        // reset() ran on the error path, so the context is idle again.
        assert_eq!(nego.state(), NegotiateState::AuthNone);
    }

    #[test]
    fn valid_challenge_without_provider_is_auth_error() {
        // A well-formed base64 challenge decodes fine, then the GSS step fails
        // because no provider is compiled in => CURLE_AUTH_ERROR.
        let mut nego = NegotiateData::new();

        let result = input_negotiate(&mut nego, &host_req(), "Negotiate YWJj");

        assert_eq!(result, Err(CurlError::AuthError));
        assert_eq!(nego.state(), NegotiateState::AuthNone);
    }

    #[test]
    fn malformed_base64_challenge_is_bad_content_encoding() {
        // A challenge beginning with '=' is rejected before any GSS work, the
        // same as curl's `if(!chlg) return CURLE_BAD_CONTENT_ENCODING;`.
        let mut nego = NegotiateData::new();

        let result = input_negotiate(&mut nego, &host_req(), "Negotiate =abc");

        assert_eq!(result, Err(CurlError::BadContentEncoding));
    }

    #[test]
    fn second_challenge_after_completed_context_is_login_denied() {
        // context established + GSS_S_COMPLETE + a new challenge => the server
        // rejected our completed context => CURLE_LOGIN_DENIED.
        let mut nego = NegotiateData::new();
        nego.context_established = true;
        nego.status = GssStatus::Complete;
        nego.state = NegotiateState::AuthRecv;

        let result = input_negotiate(&mut nego, &host_req(), "Negotiate YWJj");

        assert_eq!(result, Err(CurlError::LoginDenied));
        assert_eq!(nego.state(), NegotiateState::AuthNone);
    }

    // ---- Phase C: output / header shape -------------------------------------

    #[test]
    fn build_authorization_header_shapes() {
        assert_eq!(
            build_authorization_header(false, ABC_B64),
            "Authorization: Negotiate YWJj\r\n"
        );
        assert_eq!(
            build_authorization_header(true, ABC_B64),
            "Proxy-Authorization: Negotiate YWJj\r\n"
        );
    }

    #[test]
    fn output_emits_authorization_header_from_established_context() {
        // Pre-seed an established context with a pending token (the state a real
        // provider would leave behind) and confirm the exact header shape and
        // the AUTHRECV -> AUTHSENT transition.
        let mut nego = NegotiateData::new();
        nego.context_established = true;
        nego.output_token = Some(b"abc".to_vec());
        nego.state = NegotiateState::AuthRecv;

        let out = output_negotiate(&mut nego, &host_req()).expect("output ok");

        assert_eq!(
            out.header.as_deref(),
            Some("Authorization: Negotiate YWJj\r\n")
        );
        assert!(!out.done);
        assert_eq!(nego.state(), NegotiateState::AuthSent);
        assert!(!nego.havenegdata);
    }

    #[test]
    fn output_emits_proxy_authorization_header() {
        let mut nego = NegotiateData::new();
        nego.context_established = true;
        nego.output_token = Some(b"abc".to_vec());
        nego.state = NegotiateState::AuthRecv;

        let req = NegotiateRequest {
            proxy: true,
            ..host_req()
        };
        let out = output_negotiate(&mut nego, &req).expect("output ok");

        assert_eq!(
            out.header.as_deref(),
            Some("Proxy-Authorization: Negotiate YWJj\r\n")
        );
    }

    #[test]
    fn output_advances_to_done_when_status_complete() {
        // status complete/continue advances AUTHSENT -> AUTHDONE and marks done.
        let mut nego = NegotiateData::new();
        nego.context_established = true;
        nego.output_token = Some(b"abc".to_vec());
        nego.state = NegotiateState::AuthRecv;
        nego.status = GssStatus::Complete;

        let out = output_negotiate(&mut nego, &host_req()).expect("output ok");

        assert_eq!(
            out.header.as_deref(),
            Some("Authorization: Negotiate YWJj\r\n")
        );
        assert!(out.done);
        assert_eq!(nego.state(), NegotiateState::AuthDone);
    }

    #[test]
    fn output_advances_to_done_when_status_continue_needed() {
        // The CONTINUE_NEEDED arm of the AUTHSENT -> AUTHDONE transition must
        // behave identically to COMPLETE (both map to GSS_AUTHDONE in curl).
        let mut nego = NegotiateData::new();
        nego.context_established = true;
        nego.output_token = Some(b"abc".to_vec());
        nego.state = NegotiateState::AuthRecv;
        nego.status = GssStatus::ContinueNeeded;

        let out = output_negotiate(&mut nego, &host_req()).expect("output ok");

        assert_eq!(
            out.header.as_deref(),
            Some("Authorization: Negotiate YWJj\r\n")
        );
        assert!(out.done);
        assert_eq!(nego.state(), NegotiateState::AuthDone);
    }

    #[test]
    fn output_without_provider_continues_unauthenticated() {
        // A fresh handle with no context drives input_negotiate, which fails
        // with AuthError (no provider). curl's compatibility behavior is to
        // continue unauthenticated: no header, done == true, CURLE_OK.
        let mut nego = NegotiateData::new();

        let out = output_negotiate(&mut nego, &host_req()).expect("ok, unauthenticated");

        assert_eq!(out.header, None);
        assert!(out.done);
    }

    #[test]
    fn output_no_header_when_already_done() {
        // An already-finished context emits no further header but reports done.
        let mut nego = NegotiateData::new();
        nego.state = NegotiateState::AuthDone;
        nego.context_established = true;

        let out = output_negotiate(&mut nego, &host_req()).expect("output ok");

        assert_eq!(out.header, None);
        assert!(out.done);
    }

    #[test]
    fn create_spnego_message_rejects_empty_token() {
        // An absent/empty output token maps to CURLE_REMOTE_ACCESS_DENIED, like
        // the empty-result guard in Curl_auth_create_spnego_message.
        let empty = NegotiateData::new();
        assert_eq!(
            create_spnego_message(&empty),
            Err(CurlError::RemoteAccessDenied)
        );
    }

    #[test]
    fn create_spnego_message_encodes_token() {
        let mut nego = NegotiateData::new();
        nego.output_token = Some(b"abc".to_vec());
        assert_eq!(create_spnego_message(&nego), Ok(ABC_B64.to_string()));
    }
}
