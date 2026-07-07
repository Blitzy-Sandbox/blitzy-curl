// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP Negotiate (SPNEGO) authentication — RFC 4178.
//!
//! Language rewrite of curl 8.19.0-DEV `lib/vauth/spnego_gssapi.c` (the
//! `#if defined(HAVE_GSSAPI) && defined(USE_SPNEGO)` GSS-API path — RFC 4178
//! Simple and Protected GSS-API Negotiation) and `lib/http_negotiate.c` (the
//! HTTP `WWW-Authenticate: Negotiate` / `Proxy-Authenticate: Negotiate` glue —
//! `#if !defined(CURL_DISABLE_HTTP) && defined(USE_SPNEGO)`), plus the
//! `struct negotiatedata` blob from `lib/vauth/vauth.h`.
//!
//! Negotiate is a SPNEGO wrapper over the Kerberos V5 / GSS-API mechanism, so
//! **all** GSS-API work is delegated to [`crate::auth::kerberos`] — the single
//! feature-gated FFI site in the whole crate. This module therefore contains
//! **zero `unsafe`** (the crate root's `#![forbid(unsafe_code)]` makes that a
//! hard compile error regardless), and any C linkage lives exclusively behind
//! `kerberos.rs`.
//!
//! The Windows SSPI variant `lib/vauth/spnego_sspi.c` is intentionally
//! **dropped** — Windows is out of scope for this rewrite (AAP §0.2.2), so only
//! the pure GSS-API path is reproduced.
//!
//! # Feature gating and the unsafe policy (AAP §0.6.2, §0.7.2)
//!
//! Only the two genuinely GSS-API-dependent SPNEGO *token* routines —
//! [`decode_spnego_message`] and [`create_spnego_message`] — are feature-gated
//! (mirroring curl's `spnego_gssapi.c`, which is `#if HAVE_GSSAPI`):
//!
//! * **Default build (`spnego` off):** they compile as pure-Rust "unsupported"
//!   stubs returning `CURLE_NOT_BUILT_IN`, exactly as curl behaves when it is
//!   built without SPNEGO (where `Curl_auth_is_spnego_supported()` is `FALSE`).
//!   There is **zero `unsafe` and zero C linkage** — this is the always-compiled
//!   path the CI grep audit (`grep -rn 'unsafe' curl-rs-lib/src/`) inspects.
//! * **Feature build (`spnego` on):** they delegate the GSS-API
//!   `init_sec_context` work to [`crate::auth::kerberos`] (which itself uses a
//!   safe GSS-API wrapper), so even the feature build stays free of `unsafe`
//!   here.
//!
//! The HTTP-glue routines ([`input_negotiate`], [`output_negotiate`],
//! [`cleanup_negotiate`]) and the small wire-format helper
//! ([`negotiate_header_line`]) are **always compiled**: they only manipulate the
//! feature-independent per-connection state and delegate the actual token
//! generation to the two gated routines above. In a default build they surface
//! `CURLE_NOT_BUILT_IN` transparently (propagated from the token stubs), so the
//! HTTP layer may call them unconditionally after checking
//! [`is_spnego_supported`].
//
// DEP NOTE (FLAG #3): the `spnego` Cargo feature (default-OFF) is declared in
// `curl-rs-lib/Cargo.toml` as `spnego = ["gssapi"]` — it enables SPNEGO, which
// delegates all GSS-API work to `crate::auth::kerberos` (whose `gssapi` feature
// it transitively turns on). A real GSS-API provider crate for the `gssapi`
// feature is still owned by the manifest maintainer (see the matching DEP NOTE
// in `auth::kerberos`); this module needs none directly — it only ever calls
// `kerberos`'s feature-stable public API. Absent the `spnego` feature this
// module's SPNEGO token functions are pure-Rust "unsupported" stubs with zero
// `unsafe`. Do NOT introduce a default-ON SPNEGO feature — curl's own Negotiate
// support is optional/off in typical builds.

use crate::error::{CurlCode, Error, Result};

// base64 is a hard workspace dependency (AAP §0.5.1) and is used by the
// always-compiled HTTP glue: `input_negotiate` base64-decodes the inbound
// challenge and `output_negotiate` base64-encodes the outbound token. curl uses
// the standard alphabet with `=` padding (`curlx_base64_decode` /
// `curlx_base64_encode`), which is exactly `STANDARD` here.
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

// ===========================================================================
// Phase A — the Negotiate state machine and per-connection state.
// ===========================================================================

/// The Negotiate (SPNEGO) handshake phase.
///
/// Verbatim port of curl's `curlnegotiate` enum (`lib/urldata.h` L320-326),
/// used per-connection as `conn->http_negotiate_state` and
/// `conn->proxy_negotiate_state`. The variant **names** are preserved exactly
/// (`GSS_AUTH*`) so `--trace` / diagnostic output stays identical to curl
/// (AAP §0.3.2 "state-name preservation"), and the discriminant **order**
/// follows the C source of truth (`AuthNone, AuthRecv, AuthSent, AuthDone,
/// AuthSucc`). The enum is purely internal (no `#[repr]`, no FFI exposure), so
/// its integer values are never observed across a boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CurlNegotiate {
    /// `GSS_AUTHNONE` — no Negotiate exchange in progress (the initial state).
    #[default]
    AuthNone,
    /// `GSS_AUTHRECV` — a server challenge has been received and decoded.
    AuthRecv,
    /// `GSS_AUTHSENT` — our challenge-response token has been sent.
    AuthSent,
    /// `GSS_AUTHDONE` — the local side of the handshake is complete.
    AuthDone,
    /// `GSS_AUTHSUCC` — the handshake completed and the request succeeded.
    AuthSucc,
}

/// Per-connection Negotiate (SPNEGO) state.
///
/// Port of C `struct negotiatedata` (`lib/vauth/vauth.h` L295-324). In curl this
/// blob was stored in a connection meta-hashmap under `CURL_META_NEGO_CONN` and
/// released by the hand-written `nego_conn_dtor`; here ownership plus `Drop`
/// replace that (the GSS-API context lives inside [`kerberos::Kerberos5Data`],
/// which releases it on drop). One instance backs the origin host and another
/// the proxy — matching curl's separate `http_negotiate_state` /
/// `proxy_negotiate_state` — and each therefore carries its own [`state`].
///
/// The four `BIT(x)` bitfields curl tracks become plain `bool`s with their names
/// preserved so connection-reuse decisions and `--trace` diagnostics stay
/// recognizable. The GSS-API context/token/status fields exist only behind the
/// `spnego` feature (they are delegated to [`kerberos`] types); when the feature
/// is off this reduces to a small pure-Rust state record.
///
/// [`state`]: NegotiateData::state
/// [`kerberos`]: crate::auth::kerberos
/// [`kerberos::Kerberos5Data`]: crate::auth::kerberos::Kerberos5Data
#[derive(Debug, Default)]
pub struct NegotiateData {
    /// The handshake phase for this connection/target (curl's
    /// `conn->http_negotiate_state` / `proxy_negotiate_state`, co-located here
    /// because this struct is already per-target).
    pub state: CurlNegotiate,
    /// `noauthpersist` — the connection must **not** be kept authenticated
    /// across requests (a fresh Negotiate handshake is required each time).
    pub noauthpersist: bool,
    /// `havenoauthpersist` — whether [`noauthpersist`](Self::noauthpersist) has
    /// been explicitly determined for this connection yet.
    pub havenoauthpersist: bool,
    /// `havenegdata` — whether the most recent inbound header carried a
    /// non-empty Negotiate token.
    pub havenegdata: bool,
    /// `havemultiplerequests` — whether more than one request has ridden this
    /// connection during the handshake (used to derive `noauthpersist`).
    pub havemultiplerequests: bool,

    /// The GSS-API context state, delegated to [`kerberos`]. This is the single
    /// place `negotiate.rs` holds any GSS-API handle, and it lives entirely
    /// inside the safe [`kerberos::Kerberos5Data`] wrapper.
    ///
    /// [`kerberos`]: crate::auth::kerberos
    /// [`kerberos::Kerberos5Data`]: crate::auth::kerberos::Kerberos5Data
    #[cfg(feature = "spnego")]
    krb5: crate::auth::kerberos::Kerberos5Data,
    /// The most recent output token produced by the GSS-API step, awaiting
    /// transmission (curl's `nego->output_token`). Base64-encoding for the wire
    /// is performed by [`output_negotiate`], not here.
    #[cfg(feature = "spnego")]
    output_token: Option<Vec<u8>>,
    /// Whether a GSS-API security context has been established (mirrors the
    /// non-null test on curl's `nego->context`).
    #[cfg(feature = "spnego")]
    have_context: bool,
    /// Whether the last GSS-API step reported completion (mirrors
    /// `nego->status == GSS_S_COMPLETE`); used to detect a server that rejects
    /// an already-completed handshake by challenging again.
    #[cfg(feature = "spnego")]
    status_complete: bool,
}

/// The outcome of [`output_negotiate`]: the header to emit (if any) and whether
/// the auth phase is complete.
///
/// This bundles the two side effects curl's `Curl_output_negotiate` produces —
/// it writes the `Authorization` / `Proxy-Authorization` header string into
/// `data->state.aptr.*` and sets `authp->done` — into an explicit, testable
/// return value rather than mutating shared transfer state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NegotiateOutput {
    /// The complete header line to send this round, e.g.
    /// `"Authorization: Negotiate <base64>\r\n"` (or the `"Proxy-"` variant), or
    /// `None` when no header should be emitted (the handshake is already done
    /// and persistent).
    pub header: Option<String>,
    /// Mirrors curl's `authp->done`: `true` once the Negotiate handshake is
    /// complete and the real request may proceed unauthenticated-of-further-
    /// challenges.
    pub done: bool,
}

// ===========================================================================
// Phase B — always-compiled surface (capability query, wire helper, cleanup).
//
// These functions exist in every build so the HTTP layer can call them
// unconditionally. Only the two token routines in Phase C are feature-gated.
// ===========================================================================

/// Whether this build supports SPNEGO / Negotiate.
///
/// Port of `Curl_auth_is_spnego_supported` (`lib/vauth/spnego_gssapi.c`), which
/// returns `TRUE` only when curl was compiled with a working GSS-API SPNEGO
/// backend. Here that maps one-to-one to the `spnego` Cargo feature, so the
/// answer is a compile-time constant.
#[inline]
#[must_use]
pub fn is_spnego_supported() -> bool {
    cfg!(feature = "spnego")
}

/// Format a Negotiate `Authorization` / `Proxy-Authorization` header line from
/// an already-base64-encoded token.
///
/// This isolates the single wire-format string curl emits so it can be asserted
/// byte-for-byte in tests independently of the GSS-API machinery. It reproduces
/// the exact `printf` template from `Curl_output_negotiate`
/// (`lib/http_negotiate.c` L215):
///
/// ```c
/// aprintf("%sAuthorization: Negotiate %s\r\n", proxy ? "Proxy-" : "", encoded);
/// ```
///
/// `proxy` selects the `"Proxy-"` prefix (a `407` proxy challenge) versus the
/// origin-server form (a `401`). `encoded` is the base64 SPNEGO token. The
/// returned string includes the trailing CRLF, matching curl exactly.
#[must_use]
pub fn negotiate_header_line(proxy: bool, encoded: &str) -> String {
    format!(
        "{}Authorization: Negotiate {}\r\n",
        if proxy { "Proxy-" } else { "" },
        encoded
    )
}

/// Release the SPNEGO/GSS-API resources held in `nego` and clear the bitfields.
///
/// Port of `Curl_auth_cleanup_spnego` (`lib/vauth/spnego_gssapi.c` L259-289): it
/// frees the GSS-API output token, deletes the security context, releases the
/// imported service-principal name, and resets the four status booleans. Here
/// the GSS-API teardown is delegated to [`kerberos::cleanup_gssapi`] (and would
/// also happen on drop); the boolean reset is feature-independent so it always
/// runs.
///
/// [`kerberos::cleanup_gssapi`]: crate::auth::kerberos::cleanup_gssapi
pub fn cleanup_spnego(nego: &mut NegotiateData) {
    // Free GSS-API state (feature-gated: only these fields carry it).
    #[cfg(feature = "spnego")]
    {
        // Release the security context and any cached credentials/name (uses the
        // feature-gated `cleanup_gssapi` import declared alongside Phase C).
        cleanup_gssapi(&mut nego.krb5);
        // Drop any pending output token and reset the context/status trackers.
        nego.output_token = None;
        nego.have_context = false;
        nego.status_complete = false;
    }

    // Reset the four status bits (curl clears these unconditionally).
    nego.noauthpersist = false;
    nego.havenoauthpersist = false;
    nego.havenegdata = false;
    nego.havemultiplerequests = false;
}

/// Reset the Negotiate state on a connection back to the pristine
/// [`CurlNegotiate::AuthNone`] and release all SPNEGO resources.
///
/// Port of the static `http_auth_nego_reset` helper in `lib/http_negotiate.c`
/// (L37-47), which sets `*negostate = GSS_AUTHNONE` and then calls
/// `Curl_auth_cleanup_spnego`. curl invokes it when a Negotiate handshake needs
/// to restart (e.g. a fresh `GSS_AUTHSUCC` re-challenge) and during connection
/// teardown.
pub fn cleanup_negotiate(nego: &mut NegotiateData) {
    nego.state = CurlNegotiate::AuthNone;
    cleanup_spnego(nego);
}

// ===========================================================================
// Phase C — SPNEGO token functions (GSS-API dependent).
//
// These are the only feature-gated routines. They mirror curl's
// `spnego_gssapi.c`, which is itself `#if HAVE_GSSAPI`. The default build
// supplies pure-Rust stubs returning `CURLE_NOT_BUILT_IN`; the feature build
// delegates all GSS-API work to `crate::auth::kerberos` (the single FFI site),
// so this module still contains zero `unsafe` in either configuration.
// ===========================================================================

/// Decode an inbound SPNEGO challenge and produce the next output token
/// (default build: SPNEGO not compiled in).
///
/// Stub returning `CURLE_NOT_BUILT_IN`, exactly as curl behaves without SPNEGO.
/// The signature is identical to the feature-on version so [`input_negotiate`]
/// (always compiled) can call it unconditionally.
///
/// # Errors
///
/// Always returns [`crate::error::Error`] mapping to `CURLE_NOT_BUILT_IN`.
#[cfg(not(feature = "spnego"))]
pub fn decode_spnego_message(
    _service: &str,
    _host: &str,
    _chlg: Option<&[u8]>,
    _nego: &mut NegotiateData,
) -> Result<()> {
    Err(Error::from(CurlCode::NotBuiltIn))
}

/// Return the SPNEGO output token for transmission (default build: SPNEGO not
/// compiled in).
///
/// Stub returning `CURLE_NOT_BUILT_IN`. The signature matches the feature-on
/// version so [`output_negotiate`] (always compiled) can call it
/// unconditionally.
///
/// # Errors
///
/// Always returns [`crate::error::Error`] mapping to `CURLE_NOT_BUILT_IN`.
#[cfg(not(feature = "spnego"))]
pub fn create_spnego_message(_nego: &mut NegotiateData) -> Result<Vec<u8>> {
    Err(Error::from(CurlCode::NotBuiltIn))
}

// --- Feature build (`spnego` on): delegate GSS-API to `crate::auth::kerberos`.
//
// Placed next to the routines that use them (the `crate::auth::kerberos` module
// mirrors this convention for its own feature-gated `use`s).
#[cfg(feature = "spnego")]
use crate::auth::kerberos::{cleanup_gssapi, create_gssapi_user_message};

/// Decode an inbound SPNEGO challenge and produce the next output token.
///
/// Port of `Curl_auth_decode_spnego_message` (`lib/vauth/spnego_gssapi.c`
/// L72-201). The C `user`/`password` parameters are omitted because the C
/// function discards them (`(void)user; (void)password;`, L93-94) — SPNEGO draws
/// its credentials from the ambient GSS-API credential cache.
///
/// The `chlg` is the server's most recent token, **already base64-decoded** by
/// the caller [`input_negotiate`] (the split follows the module's design: the
/// HTTP glue owns base64, mirroring how curl passes the decoded buffer into
/// `Curl_gss_init_sec_context`). A `None` challenge is the initiating call
/// (curl's `GSS_C_EMPTY_BUFFER` input). `input_negotiate` maps an invalid or
/// present-but-empty base64 challenge to `CURLE_BAD_CONTENT_ENCODING` (the
/// analog of the C decode+`!chlg` check at L132-144), so this routine receives
/// either `None` or non-empty bytes.
///
/// All GSS-API work — building and importing the service principal name and
/// running one `init_sec_context` step — is delegated to
/// [`crate::auth::kerberos::create_gssapi_user_message`], which curl performs
/// with mutual authentication requested (the `TRUE` argument at L170), so `true`
/// is passed here.
///
/// # Errors
///
/// * `CURLE_LOGIN_DENIED` — a challenge arrived after we already completed our
///   part of the handshake (an established context with completed status), i.e.
///   the server rejected our token and re-challenged (C L96-102).
/// * `CURLE_AUTH_ERROR` — the GSS-API step failed, or produced no output token
///   (SPNEGO always requires an outbound token; C L177-192).
#[cfg(feature = "spnego")]
pub fn decode_spnego_message(
    service: &str,
    host: &str,
    chlg: Option<&[u8]>,
    nego: &mut NegotiateData,
) -> Result<()> {
    // C L96-102: if we already established a context and completed our side, a
    // fresh challenge means the server rejected us. We cannot invent anything
    // better, so tear down and report a login denial.
    if nego.have_context && nego.status_complete {
        cleanup_spnego(nego);
        return Err(Error::LoginDenied);
    }

    // C L104-171: build/import the SPN (first call only) and run one GSS-API
    // init_sec_context step. Delegated wholesale to kerberos, which builds the
    // host-based SPN internally via `crate::auth::build_spn(service, None,
    // Some(host))` and requests mutual auth (curl passes TRUE at L170).
    let output = create_gssapi_user_message(&mut nego.krb5, service, host, true, chlg)?;

    // C L162-176: a context now exists and its status was recorded. For SPNEGO's
    // single-leg HTTP client flow the successful step is terminal, so mark the
    // status complete; this arms the L96 replay guard on any subsequent
    // (non-empty) re-challenge. (The kerberos safe wrapper does not surface the
    // raw GSS_S_COMPLETE vs GSS_S_CONTINUE_NEEDED major status across the
    // delegation boundary; completion-on-token-produced is the faithful model
    // for the Negotiate/HTTP exchange, which the client completes in one step.)
    nego.have_context = true;

    match output {
        // C L194-200: stash the produced token for `create_spnego_message`.
        Some(token) if !token.is_empty() => {
            nego.output_token = Some(token);
            nego.status_complete = true;
            Ok(())
        }
        // C L187-192: SPNEGO requires a non-empty output token; its absence is a
        // hard GSS failure (unlike SASL Kerberos, which tolerates an empty
        // mutual-auth continuation).
        _ => {
            nego.output_token = None;
            Err(Error::auth("SPNEGO handshake failure (no output token)"))
        }
    }
}

/// Return the SPNEGO output token produced by the last
/// [`decode_spnego_message`], ready for the caller to base64-encode.
///
/// Port of `Curl_auth_create_spnego_message` (`lib/vauth/spnego_gssapi.c`
/// L219-247). curl base64-encodes `nego->output_token` there; in this module the
/// wire encoding is performed by [`output_negotiate`], so this returns the raw
/// token bytes. The token is cloned (not consumed) to mirror curl, where
/// `output_token` persists in the struct until [`cleanup_spnego`] releases it.
///
/// # Errors
///
/// Returns `CURLE_REMOTE_ACCESS_DENIED` when there is no output token to send
/// (C L238-243), releasing the (empty) token on that error path as curl does.
#[cfg(feature = "spnego")]
pub fn create_spnego_message(nego: &mut NegotiateData) -> Result<Vec<u8>> {
    match nego.output_token.as_deref() {
        Some(token) if !token.is_empty() => Ok(token.to_vec()),
        _ => {
            // C L239-241: release the token and fail — nothing to send.
            nego.output_token = None;
            Err(Error::from(CurlCode::RemoteAccessDenied))
        }
    }
}

// ===========================================================================
// Phase D — HTTP glue (`lib/http_negotiate.c`).
//
// These orchestrate the SPNEGO token routines above and are always compiled:
// they only manipulate the feature-independent per-connection state and
// delegate the GSS-API-dependent steps to Phase C. In a default build the
// delegated calls surface `CURLE_NOT_BUILT_IN`, so the HTTP layer may invoke
// these unconditionally after checking `is_spnego_supported`.
// ===========================================================================

/// Strip a leading (case-insensitive) `"Negotiate"` auth-scheme token.
///
/// Reproduces curl's `header += strlen("Negotiate")` (`http_negotiate.c` L98),
/// which advances a fixed 9 bytes after the caller has already matched the
/// scheme case-insensitively (`checkprefix`, i.e. `curl_strnequal`). If the
/// prefix is absent the input is returned unchanged. The first nine bytes, when
/// they match, are ASCII, so slicing at that offset always lands on a UTF-8
/// character boundary.
fn strip_negotiate_scheme(header: &str) -> &str {
    const SCHEME: &str = "Negotiate";
    let bytes = header.as_bytes();
    if bytes.len() >= SCHEME.len() && bytes[..SCHEME.len()].eq_ignore_ascii_case(SCHEME.as_bytes())
    {
        &header[SCHEME.len()..]
    } else {
        header
    }
}

/// Process an inbound `WWW-Authenticate: Negotiate` (or `Proxy-Authenticate:
/// Negotiate`) header and advance the handshake.
///
/// Port of `Curl_input_negotiate` (`lib/http_negotiate.c` L49-149). The caller
/// resolves and supplies the `service` (curl: `CURLOPT_SERVICE_NAME` /
/// `CURLOPT_PROXY_SERVICE_NAME`, defaulting to `"HTTP"`) and `host`, and selects
/// the correct per-target [`NegotiateData`] (origin vs proxy), so the C `proxy`
/// branch's field-plumbing collapses away here.
///
/// `header` is the full header value beginning with the `"Negotiate"` scheme
/// token; the remainder after the scheme and any blanks is the base64 challenge,
/// which may be empty on the initial `401`/`407`. This routine performs the
/// base64 decode (the module's HTTP glue owns base64) and delegates the GSS-API
/// step to [`decode_spnego_message`]. On success the state advances to
/// [`CurlNegotiate::AuthRecv`] (curl sets `GSS_AUTHRECV` in `http.c` after a
/// successful `Curl_input_negotiate`).
///
/// # Errors
///
/// * `CURLE_LOGIN_DENIED` — an empty challenge arrived while a handshake was
///   already in progress (state neither `AuthNone` nor `AuthSucc`): the server
///   rejected us and offered no further mechanism (C L108-113).
/// * `CURLE_BAD_CONTENT_ENCODING` — the challenge was present but not valid
///   base64 / decoded to nothing (C's `curlx_base64_decode` failure and the
///   `!chlg` guard, spnego_gssapi.c L132-144).
/// * `CURLE_AUTH_ERROR` — a GSS-API failure from [`decode_spnego_message`].
/// * `CURLE_NOT_BUILT_IN` — SPNEGO is not compiled in (a real challenge cannot
///   be processed); propagated from the [`decode_spnego_message`] stub.
pub fn input_negotiate(
    header: &str,
    service: &str,
    host: &str,
    nego: &mut NegotiateData,
) -> Result<()> {
    // C reads the current state (from the connection) *before* any reset below.
    let state = nego.state;

    // C L98-99: advance past the scheme token, then skip blanks. curl's
    // `curlx_str_passblanks` skips ASCII space and TAB only (ISBLANK) — not
    // CR/LF — so match that exactly.
    let token = strip_negotiate_scheme(header).trim_start_matches([' ', '\t']);

    // C L101-102.
    nego.havenegdata = !token.is_empty();

    // C L103-114: empty-token state guard.
    if token.is_empty() {
        if state == CurlNegotiate::AuthSucc {
            // C L104-106: "Negotiate auth restarted" — reset and re-initiate.
            cleanup_negotiate(nego);
        } else if state != CurlNegotiate::AuthNone {
            // C L108-112: the server rejected our authentication and supplied no
            // further negotiation data.
            cleanup_negotiate(nego);
            return Err(Error::LoginDenied);
        }
        // C: state == GSS_AUTHNONE falls through — this is the initiating call.
    }

    // C L132-144 (relocated to the HTTP glue per the module design): base64-decode
    // the challenge. curl's `curlx_base64_decode` reports `CURLE_BAD_CONTENT_ENCODING`
    // on invalid input, and a non-empty challenge that decodes to nothing hits the
    // `!chlg` guard with the same code; both map here.
    let chlg: Option<Vec<u8>> = if token.is_empty() {
        None
    } else {
        match BASE64.decode(token) {
            Ok(bytes) if !bytes.is_empty() => Some(bytes),
            _ => {
                cleanup_negotiate(nego);
                return Err(Error::bad_content_encoding(
                    "SPNEGO handshake failure (invalid challenge message)",
                ));
            }
        }
    };

    // C L137-146: initialize the security context / decode the challenge, then
    // reset the whole Negotiate state on any failure.
    match decode_spnego_message(service, host, chlg.as_deref(), nego) {
        Ok(()) => {
            // curl advances the connection state to GSS_AUTHRECV after a
            // successful Curl_input_negotiate (http.c).
            nego.state = CurlNegotiate::AuthRecv;
            Ok(())
        }
        Err(e) => {
            cleanup_negotiate(nego);
            Err(e)
        }
    }
}

/// Produce the outgoing `Authorization: Negotiate` / `Proxy-Authorization:
/// Negotiate` header for the current handshake step, driving the state machine.
///
/// Port of `Curl_output_negotiate` (`lib/http_negotiate.c` L151-260). The two
/// side effects curl produces — writing the header into `data->state.aptr.*` and
/// setting `authp->done` — are returned explicitly as a [`NegotiateOutput`]
/// instead of mutating shared transfer state. `proxy` selects the `"Proxy-"`
/// header prefix; `service`/`host` are used only to kick-start a fresh handshake
/// (curl calls `Curl_input_negotiate(conn, proxy, "Negotiate")` when no context
/// exists yet).
///
/// The state transitions and the `noauthpersist` / `havemultiplerequests`
/// bookkeeping are preserved verbatim so connection-reuse behavior and
/// `--trace` diagnostics match curl. A produced token drives the state to
/// [`CurlNegotiate::AuthDone`]: curl sets `GSS_AUTHSENT` and then immediately
/// `GSS_AUTHDONE` whenever the GSS status is `COMPLETE` or `CONTINUE_NEEDED`
/// (L235-240), which always holds once an output token exists, so the transient
/// `AuthSent` is never an observable resting state and the code advances
/// straight to `AuthDone`.
///
/// # Errors
///
/// * `CURLE_NOT_BUILT_IN` — SPNEGO is not compiled in; propagated from the
///   kick-start [`input_negotiate`] / [`create_spnego_message`] stubs when a
///   token would need to be produced.
/// * `CURLE_REMOTE_ACCESS_DENIED` — [`create_spnego_message`] had no token to
///   send.
/// * Any error from the kick-start [`input_negotiate`] other than
///   `CURLE_AUTH_ERROR` (which curl swallows to continue unauthenticated for
///   backward compatibility, L201-206).
pub fn output_negotiate(
    proxy: bool,
    service: &str,
    host: &str,
    nego: &mut NegotiateData,
) -> Result<NegotiateOutput> {
    // C L178: authp->done = FALSE.
    let mut out = NegotiateOutput {
        header: None,
        done: false,
    };

    let state = nego.state;

    // C L180-189: track whether the connection carried multiple requests and,
    // once authenticated, whether the credentials may persist across requests.
    if state == CurlNegotiate::AuthRecv {
        if nego.havenegdata {
            nego.havemultiplerequests = true;
        }
    } else if state == CurlNegotiate::AuthSucc && !nego.havenoauthpersist {
        nego.noauthpersist = !nego.havemultiplerequests;
    }

    // C L191-249: produce a token unless the handshake is already done on a
    // persistent connection.
    if nego.noauthpersist || (state != CurlNegotiate::AuthDone && state != CurlNegotiate::AuthSucc)
    {
        // C L194-198: drop a stale, already-succeeded context when the connection
        // must not persist authentication.
        if nego.noauthpersist && state == CurlNegotiate::AuthSucc {
            cleanup_negotiate(nego);
        }

        // C L199-209: with no established context yet, kick-start the handshake by
        // feeding an empty "Negotiate" challenge to the input path. curl tests
        // `!neg_ctx->context`; the equivalent here is the pristine `AuthNone`
        // state (a context exists once any decode has advanced the state).
        if nego.state == CurlNegotiate::AuthNone {
            match input_negotiate("Negotiate", service, host, nego) {
                // C L201-206: a GSS auth error is swallowed — continue
                // unauthenticated to preserve pre-7.64.0 behavior.
                Err(e) if e.code() == CurlCode::AuthError => {
                    out.done = true;
                    return Ok(out);
                }
                // C L207-208: any other error propagates.
                Err(e) => return Err(e),
                Ok(()) => {}
            }
        }

        // C L211-213: build the SPNEGO response token.
        let token = create_spnego_message(nego)?;

        // C L215-216: base64-encode and format the header line, byte-for-byte
        // identical to curl's `"%sAuthorization: Negotiate %s\r\n"`. `token` is
        // consumed by the encode (it is not needed afterwards).
        let encoded = BASE64.encode(token);
        out.header = Some(negotiate_header_line(proxy, &encoded));

        // C L235-240: GSS_AUTHSENT then, because a token was produced (GSS status
        // COMPLETE or CONTINUE_NEEDED), GSS_AUTHDONE. Nothing observes the state
        // between these straight-line statements, so advance directly to AuthDone.
        nego.state = CurlNegotiate::AuthDone;
    }

    // C L251-255: once done or already succeeded, no header is sent in future
    // requests.
    if nego.state == CurlNegotiate::AuthDone || nego.state == CurlNegotiate::AuthSucc {
        out.done = true;
    }

    // C L257: consume the "have negotiation data" flag for this round.
    nego.havenegdata = false;

    Ok(out)
}

// ===========================================================================
// Tests
//
// The bulk run in the default build (SPNEGO off): they cover the capability
// query, the wire-format helper (byte-exact against curl), the state machine and
// its `CURLE_LOGIN_DENIED` / `CURLE_BAD_CONTENT_ENCODING` guards, cleanup, and
// the `CURLE_NOT_BUILT_IN` behavior of the delegated token routines. A smaller
// set is `#[cfg(feature = "spnego")]`: those inject token state directly (no live
// GSS-API needed) to assert the happy-path header formatting, state advance, and
// the replay `CURLE_LOGIN_DENIED` guard once the feature is built.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // ---- Capability query ------------------------------------------------

    #[test]
    fn spnego_support_matches_feature_flag() {
        // Mirrors curl's `Curl_auth_is_spnego_supported()`: true only when built
        // with SPNEGO.
        assert_eq!(is_spnego_supported(), cfg!(feature = "spnego"));
    }

    // ---- Types, defaults, derives ---------------------------------------

    #[test]
    fn state_default_is_authnone() {
        // The C `curlnegotiate` enum starts at GSS_AUTHNONE.
        assert_eq!(CurlNegotiate::default(), CurlNegotiate::AuthNone);
    }

    #[test]
    fn negotiate_data_default_is_pristine() {
        let n = NegotiateData::default();
        assert_eq!(n.state, CurlNegotiate::AuthNone);
        assert!(!n.noauthpersist);
        assert!(!n.havenoauthpersist);
        assert!(!n.havenegdata);
        assert!(!n.havemultiplerequests);
        // `#[derive(Debug)]` is required by `ConnAuthState`; ensure it works.
        assert!(format!("{n:?}").contains("NegotiateData"));
    }

    #[test]
    fn negotiate_output_default_and_derives() {
        let a = NegotiateOutput::default();
        assert_eq!(
            a,
            NegotiateOutput {
                header: None,
                done: false
            }
        );
        // Clone + PartialEq + Debug.
        let b = a.clone();
        assert_eq!(a, b);
        assert!(format!("{a:?}").contains("NegotiateOutput"));
    }

    // ---- Wire-format parity: "%sAuthorization: Negotiate %s\r\n" ---------

    #[test]
    fn header_line_host_form_is_byte_exact() {
        assert_eq!(
            negotiate_header_line(false, "YII_token=="),
            "Authorization: Negotiate YII_token==\r\n"
        );
    }

    #[test]
    fn header_line_proxy_form_uses_prefix() {
        assert_eq!(
            negotiate_header_line(true, "YII_token=="),
            "Proxy-Authorization: Negotiate YII_token==\r\n"
        );
    }

    #[test]
    fn header_line_preserves_empty_token_spacing() {
        // curl emits the trailing space before the (empty) token verbatim.
        assert_eq!(
            negotiate_header_line(false, ""),
            "Authorization: Negotiate \r\n"
        );
    }

    // ---- Scheme stripping (curl `header += strlen("Negotiate")`) ---------

    #[test]
    fn scheme_strip_is_case_insensitive_and_exact() {
        assert_eq!(strip_negotiate_scheme("Negotiate abc"), " abc");
        assert_eq!(strip_negotiate_scheme("negotiate abc"), " abc");
        assert_eq!(strip_negotiate_scheme("NEGOTIATE"), "");
        // No prefix → unchanged; short strings do not panic.
        assert_eq!(strip_negotiate_scheme("Basic xyz"), "Basic xyz");
        assert_eq!(strip_negotiate_scheme("Neg"), "Neg");
        assert_eq!(strip_negotiate_scheme(""), "");
    }

    // ---- cleanup_spnego / cleanup_negotiate ------------------------------

    #[test]
    fn cleanup_spnego_clears_all_bits() {
        let mut n = NegotiateData {
            noauthpersist: true,
            havenoauthpersist: true,
            havenegdata: true,
            havemultiplerequests: true,
            ..Default::default()
        };
        cleanup_spnego(&mut n);
        assert!(!n.noauthpersist);
        assert!(!n.havenoauthpersist);
        assert!(!n.havenegdata);
        assert!(!n.havemultiplerequests);
    }

    #[test]
    fn cleanup_negotiate_resets_state_and_bits() {
        let mut n = NegotiateData {
            state: CurlNegotiate::AuthSucc,
            havenegdata: true,
            havemultiplerequests: true,
            ..Default::default()
        };
        cleanup_negotiate(&mut n);
        assert_eq!(n.state, CurlNegotiate::AuthNone);
        assert!(!n.havenegdata);
        assert!(!n.havemultiplerequests);
    }

    // ---- input_negotiate: feature-independent state guards ---------------

    #[test]
    fn input_empty_rechallenge_midhandshake_is_login_denied() {
        // C L108-112: an empty challenge while a handshake is in progress (state
        // neither AUTHNONE nor AUTHSUCC) means the server rejected us.
        for st in [
            CurlNegotiate::AuthRecv,
            CurlNegotiate::AuthSent,
            CurlNegotiate::AuthDone,
        ] {
            let mut n = NegotiateData {
                state: st,
                ..Default::default()
            };
            let err = input_negotiate("Negotiate", "HTTP", "host.example", &mut n)
                .expect_err("empty re-challenge mid-handshake must be denied");
            assert_eq!(err.code(), CurlCode::LoginDenied, "state {st:?}");
            // The guard resets the state machine (http_auth_nego_reset).
            assert_eq!(n.state, CurlNegotiate::AuthNone);
        }
    }

    #[test]
    fn input_invalid_base64_is_bad_content_encoding() {
        // '@' is outside the base64 alphabet → curl's curlx_base64_decode failure.
        let mut n = NegotiateData::default();
        let err = input_negotiate("Negotiate @@@@", "HTTP", "host.example", &mut n)
            .expect_err("invalid base64 challenge must be rejected");
        assert_eq!(err.code(), CurlCode::BadContentEncoding);
        assert_eq!(n.state, CurlNegotiate::AuthNone);
    }

    #[cfg(not(feature = "spnego"))]
    #[test]
    fn input_empty_initial_clears_havenegdata() {
        // Initial 401 (state AUTHNONE, empty token): havenegdata is cleared to
        // reflect the empty token. Gated to the default build so the feature-on
        // decode delegation (which would drive a live GSS-API step) is not
        // exercised from a unit test.
        let mut n = NegotiateData {
            havenegdata: true,
            ..Default::default()
        };
        let _ = input_negotiate("Negotiate", "HTTP", "host.example", &mut n);
        assert!(!n.havenegdata);
    }

    // ---- input_negotiate: delegation reports NOT_BUILT_IN (default build) -

    #[cfg(not(feature = "spnego"))]
    #[test]
    fn input_initial_call_reports_not_built_in() {
        // Empty challenge in AUTHNONE → initiating decode is delegated; without
        // SPNEGO that surfaces CURLE_NOT_BUILT_IN and the state is reset.
        let mut n = NegotiateData::default();
        let err = input_negotiate("Negotiate", "HTTP", "host.example", &mut n)
            .expect_err("default build cannot process a Negotiate handshake");
        assert_eq!(err.code(), CurlCode::NotBuiltIn);
        assert_eq!(n.state, CurlNegotiate::AuthNone);
    }

    #[cfg(not(feature = "spnego"))]
    #[test]
    fn input_authsucc_empty_challenge_restarts_then_delegates() {
        // C L104-106: empty challenge in AUTHSUCC restarts the handshake (reset to
        // AUTHNONE), then the initiating decode delegation reports NOT_BUILT_IN.
        let mut n = NegotiateData {
            state: CurlNegotiate::AuthSucc,
            ..Default::default()
        };
        let err = input_negotiate("Negotiate", "HTTP", "host.example", &mut n)
            .expect_err("default build cannot restart a Negotiate handshake");
        assert_eq!(err.code(), CurlCode::NotBuiltIn);
        assert_eq!(n.state, CurlNegotiate::AuthNone);
    }

    #[cfg(not(feature = "spnego"))]
    #[test]
    fn input_valid_token_reports_not_built_in() {
        // A well-formed base64 challenge parses, then the decode delegation reports
        // NOT_BUILT_IN on the default build. "dG9rZW4=" == "token".
        let mut n = NegotiateData::default();
        let err = input_negotiate("Negotiate dG9rZW4=", "HTTP", "host.example", &mut n)
            .expect_err("default build cannot decode a Negotiate token");
        assert_eq!(err.code(), CurlCode::NotBuiltIn);
        assert_eq!(n.state, CurlNegotiate::AuthNone);
    }

    // ---- output_negotiate: state machine (default build) -----------------

    #[cfg(not(feature = "spnego"))]
    #[test]
    fn output_fresh_handshake_reports_not_built_in() {
        // Fresh (AUTHNONE) output kick-starts input → decode stub → NOT_BUILT_IN.
        // That is not CURLE_AUTH_ERROR, so it propagates (is not swallowed).
        let mut n = NegotiateData::default();
        let err = output_negotiate(false, "HTTP", "host.example", &mut n)
            .expect_err("default build cannot start a Negotiate handshake");
        assert_eq!(err.code(), CurlCode::NotBuiltIn);
    }

    #[test]
    fn output_already_done_emits_no_header() {
        // C L191-255: AUTHDONE on a persistent connection produces no header and
        // reports done — no token routine is invoked (build-independent).
        let mut n = NegotiateData {
            state: CurlNegotiate::AuthDone,
            ..Default::default()
        };
        let out = output_negotiate(false, "HTTP", "host.example", &mut n)
            .expect("done handshake needs no token");
        assert!(out.done);
        assert_eq!(out.header, None);
    }

    #[test]
    fn output_succeeded_multi_request_stays_persistent() {
        // C L185-188: AUTHSUCC with multiple requests keeps noauthpersist false, so
        // no re-auth is triggered and no header is emitted (build-independent).
        let mut n = NegotiateData {
            state: CurlNegotiate::AuthSucc,
            havemultiplerequests: true,
            ..Default::default()
        };
        let out = output_negotiate(false, "HTTP", "host.example", &mut n)
            .expect("persistent succeeded handshake needs no token");
        assert!(out.done);
        assert_eq!(out.header, None);
        assert!(!n.noauthpersist);
    }

    #[cfg(not(feature = "spnego"))]
    #[test]
    fn output_succeeded_single_request_triggers_reauth() {
        // C L186-198: AUTHSUCC with a single request sets noauthpersist, which
        // tears down the context (→ AUTHNONE) and re-initiates; the default build
        // then reports NOT_BUILT_IN from the kick-start delegation.
        let mut n = NegotiateData {
            state: CurlNegotiate::AuthSucc,
            havemultiplerequests: false,
            ..Default::default()
        };
        let err = output_negotiate(false, "HTTP", "host.example", &mut n)
            .expect_err("default build cannot re-authenticate");
        assert_eq!(err.code(), CurlCode::NotBuiltIn);
        // The non-persistent branch reset the connection before re-initiating.
        assert_eq!(n.state, CurlNegotiate::AuthNone);
    }

    #[cfg(not(feature = "spnego"))]
    #[test]
    fn output_authrecv_with_negdata_marks_multiple_requests() {
        // C L180-184: AUTHRECV carrying negotiation data flags multiple requests.
        // The token production then reports NOT_BUILT_IN on the default build, but
        // the flag was already set.
        let mut n = NegotiateData {
            state: CurlNegotiate::AuthRecv,
            havenegdata: true,
            ..Default::default()
        };
        let err = output_negotiate(false, "HTTP", "host.example", &mut n)
            .expect_err("default build cannot create a token");
        assert_eq!(err.code(), CurlCode::NotBuiltIn);
        assert!(n.havemultiplerequests);
    }

    // ---- Token routines: NOT_BUILT_IN on the default build ---------------

    #[cfg(not(feature = "spnego"))]
    #[test]
    fn decode_and_create_report_not_built_in() {
        let mut n = NegotiateData::default();
        assert_eq!(
            decode_spnego_message("HTTP", "host.example", None, &mut n)
                .expect_err("no SPNEGO in the default build")
                .code(),
            CurlCode::NotBuiltIn
        );
        assert_eq!(
            create_spnego_message(&mut n)
                .expect_err("no SPNEGO in the default build")
                .code(),
            CurlCode::NotBuiltIn
        );
    }

    // ---- Feature-on: token-driven paths without a live GSS-API provider ---
    //
    // These inject the output token / context flags directly (private fields are
    // reachable from this child module) so they exercise the happy-path header
    // formatting, the state advance to AUTHDONE, and the replay guard purely from
    // in-memory state. They compile and pass once the `spnego` feature (and its
    // GSS-API provider) is enabled; they are excluded from the default CI build.

    #[cfg(feature = "spnego")]
    #[test]
    fn create_returns_injected_token_and_keeps_it() {
        let mut n = NegotiateData {
            output_token: Some(b"raw-token".to_vec()),
            ..Default::default()
        };
        assert_eq!(
            create_spnego_message(&mut n).unwrap(),
            b"raw-token".to_vec()
        );
        // curl frees output_token only in cleanup, so it must persist here.
        assert_eq!(n.output_token.as_deref(), Some(&b"raw-token"[..]));
    }

    #[cfg(feature = "spnego")]
    #[test]
    fn create_without_token_is_remote_access_denied() {
        let mut n = NegotiateData::default();
        assert_eq!(
            create_spnego_message(&mut n).unwrap_err().code(),
            CurlCode::RemoteAccessDenied
        );
    }

    #[cfg(feature = "spnego")]
    #[test]
    fn output_formats_header_and_advances_to_authdone() {
        let mut n = NegotiateData {
            state: CurlNegotiate::AuthRecv,
            output_token: Some(b"TOK".to_vec()),
            ..Default::default()
        };
        let out = output_negotiate(false, "HTTP", "host.example", &mut n).unwrap();
        let b64 = BASE64.encode(b"TOK");
        assert_eq!(
            out.header.as_deref(),
            Some(format!("Authorization: Negotiate {b64}\r\n").as_str())
        );
        assert!(out.done);
        assert_eq!(n.state, CurlNegotiate::AuthDone);
    }

    #[cfg(feature = "spnego")]
    #[test]
    fn output_proxy_variant_header_form() {
        let mut n = NegotiateData {
            state: CurlNegotiate::AuthRecv,
            output_token: Some(b"X".to_vec()),
            ..Default::default()
        };
        let out = output_negotiate(true, "HTTP", "host.example", &mut n).unwrap();
        let b64 = BASE64.encode(b"X");
        assert_eq!(
            out.header.as_deref(),
            Some(format!("Proxy-Authorization: Negotiate {b64}\r\n").as_str())
        );
    }

    #[cfg(feature = "spnego")]
    #[test]
    fn decode_replay_after_completion_is_login_denied() {
        // C L96-102: a challenge after we already completed our part (context +
        // completed status) is a server rejection → CURLE_LOGIN_DENIED, decided
        // before any GSS-API call.
        let mut n = NegotiateData {
            have_context: true,
            status_complete: true,
            ..Default::default()
        };
        assert_eq!(
            decode_spnego_message("HTTP", "host.example", Some(b"srvtok"), &mut n)
                .unwrap_err()
                .code(),
            CurlCode::LoginDenied
        );
    }
}
