//! Kerberos V5 ("GSSAPI") SASL mechanism — RFC 4752.
//!
//! This module is the memory-safe Rust successor to libcurl's
//! `lib/vauth/krb5_gssapi.c` (used here strictly as a *behavioral oracle*, not
//! transliterated line-by-line). It implements the client side of the
//! Kerberos V5 SASL mechanism — the `GSSAPI` authentication exchange used by the
//! mail protocols (SMTP / IMAP / POP3) and others — in two phases:
//!
//! 1. the **user-message** phase ([`create_gssapi_user_message`]), which builds
//!    the service principal name (SPN), advances the GSSAPI security context,
//!    and emits the next authentication token; and
//! 2. the **security-message** phase ([`create_gssapi_security_message`]), the
//!    RFC 4752 §3.1 security-layer negotiation, which unwraps the server's
//!    security token, selects the protection layer and maximum buffer size, and
//!    wraps the client response (optionally carrying an authorization identity).
//!
//! # Feature gate — OFF by default (in lockstep with `version.rs`)
//!
//! The **entire module is compiled only when the `gssapi` feature is enabled**
//! (the inner `#![cfg(feature = "gssapi")]` below makes the file self-gating).
//! That feature is **absent from the crate's default set**, exactly mirroring
//! curl's default build, which enables neither `HAVE_GSSAPI` nor
//! `USE_KERBEROS5`. Consequently a default `curl-rs` reports neither
//! `CURL_VERSION_GSSAPI` (`1 << 17`) nor `CURL_VERSION_KERBEROS5` (`1 << 18`),
//! and [`crate::version`]'s capability list deliberately omits `GSS-API`,
//! `Kerberos` and `SPNEGO`. This module's default-off state and that version
//! report are coupled (AAP §0.7.3): the capability string a stock `curl 8.x`
//! prints and the one `curl-rs` prints stay identical only because *both* are
//! off by default. Do not enable this feature by default without also updating
//! `version.rs`, or the `runtests` feature-detection gate will select the wrong
//! subset of tests.
//!
//! # Scope and the GSSAPI-backend limitation (read carefully)
//!
//! curl's `krb5_gssapi.c` is *entirely* backed by a C GSS-API library: every
//! token is produced by `gss_import_name`, `gss_init_sec_context`, `gss_unwrap`
//! and `gss_wrap`, which in turn depend on the host's Kerberos credential
//! infrastructure (a ticket cache, a `keytab`, the KDC, …). Unlike SASL SCRAM —
//! which is pure arithmetic over HMAC/SHA-2 and *is* reimplemented natively —
//! GSSAPI/Kerberos cannot be reproduced as self-contained Rust without a full
//! GSSAPI provider, and **no production-grade pure-Rust GSSAPI stack is in
//! scope for this rewrite** (AAP §0.6.2 collapses the C auth backends but does
//! not add a Rust GSSAPI provider).
//!
//! Therefore the three credential-dependent steps —
//! [`gss_init_sec_context`](self), [`gss_unwrap_token`](self) and
//! [`gss_wrap_token`](self) — are isolated, clearly-documented seams that return
//! [`CurlError::NotBuiltIn`] (curl's `CURLE_NOT_BUILT_IN`). Every part that does
//! **not** require a credential provider is implemented faithfully and unit
//! tested: SPN construction (delegated to [`crate::auth::build_spn`] so it stays
//! consistent with `negotiate.rs`), base64 token framing, the RFC 4752 §3.1
//! four-octet security header parse, the security-layer check, and the response
//! framing including the authorization identity. Because the feature is off by
//! default, the default build *never* reaches the `NotBuiltIn` seams — they are
//! only observable if a downstream integrator opts in to `gssapi` without
//! wiring a GSSAPI provider, in which case "not built in" is precisely the
//! correct, curl-compatible signal.
//!
//! # Wire framing
//!
//! On the SASL wire the exchanged tokens are base64 text. To keep the framing
//! local and consistent, this module accepts the server challenge as base64
//! ([`base64_decode`]) and returns the client token as base64
//! ([`base64_encode`]); callers therefore move raw, ready-to-send/parse bytes in
//! and out. This mirrors the contract used across the `auth` modules.
//!
//! # Memory safety
//!
//! This module contains **zero `unsafe`** and compiles cleanly under the
//! crate-root `#![forbid(unsafe_code)]` (restated below for isolation). It holds
//! no raw pointers and no manual allocation: the C `struct kerberos5data`
//! (a `gss_name_t` SPN plus a `gss_ctx_id_t` context, both freed by hand in
//! `Curl_auth_cleanup_gssapi`) becomes the owned [`Krb5Data`], whose `Drop` is
//! automatic; [`cleanup_gssapi`] is retained only for naming parity with the C
//! oracle.

// Self-gate the whole module on the `gssapi` feature so the file is correct no
// matter how `auth/mod.rs` declares it. With the feature off (the default), the
// module body is compiled out entirely, exactly as required.
#![cfg(feature = "gssapi")]
// Defensive, self-documenting restatement of the crate-root memory-safety
// guarantee; `forbid` is idempotent with the crate root's
// `#![forbid(unsafe_code)]` and keeps this module safe even in isolation.
#![forbid(unsafe_code)]
// This is a leaf authentication module. Its public surface
// (`create_gssapi_user_message`, `create_gssapi_security_message`,
// `is_gssapi_supported`, `cleanup_gssapi`, the `Krb5Data` handle) is consumed by
// the SASL driver and the mail-protocol engines, which are authored in parallel
// and may not yet exist in a partially-assembled workspace. Allowing `dead_code`
// keeps the module self-contained under the workspace's `-D warnings` gate. This
// masks no defect: every item below is reached either internally (the GSSAPI
// seams and framing helpers from the two `create_*` entry points) or by the
// in-file test suite. The same justification is used by `proxy/noproxy.rs`.
#![allow(dead_code)]

use crate::auth::build_spn;
use crate::error::{CurlError, Result};
use crate::util::base64::{base64_decode, base64_encode};

/// SASL security-layer bit: **no security layer** (RFC 4752 §3.3 / curl's
/// `GSSAUTH_P_NONE`). The client neither integrity-protects nor encrypts
/// application data after authentication.
pub const GSSAUTH_P_NONE: u8 = 1;

/// SASL security-layer bit: **integrity protection** (curl's
/// `GSSAUTH_P_INTEGRITY`). Declared for completeness of the RFC 4752 layer
/// space; like upstream curl, this client never negotiates an active security
/// layer, so it is not selected.
pub const GSSAUTH_P_INTEGRITY: u8 = 2;

/// SASL security-layer bit: **confidentiality / privacy** (curl's
/// `GSSAUTH_P_PRIVACY`). Declared for completeness; not negotiated, as above.
pub const GSSAUTH_P_PRIVACY: u8 = 4;

/// The exact length, in octets, of the decrypted security token the server
/// sends in the security-message phase (RFC 4752 §3.1): one security-layer
/// octet followed by a three-octet big-endian maximum buffer size.
const SECURITY_TOKEN_LEN: usize = 4;

/// Client-side Kerberos V5 (GSSAPI) authentication state.
///
/// This is the owned, memory-safe replacement for the C `struct kerberos5data`
/// (`lib/vauth/vauth.h`), which on POSIX holds a `gss_name_t spn` and a
/// `gss_ctx_id_t context`. Here the SPN is an owned [`String`] and the security
/// context is represented by a simple establishment flag, because no GSSAPI
/// provider is wired in to produce a real `gss_ctx_id_t` (see the module
/// documentation). The handle threads state across the multi-round SASL
/// handshake: the SPN is built once on the first user-message round and reused,
/// and the requested mutual-authentication flag is remembered.
///
/// All fields are private; the read-only accessors expose what callers and the
/// test-suite need. Cleanup is automatic via `Drop`; [`cleanup_gssapi`] /
/// [`Krb5Data::reset`] exist for naming parity with the C oracle and to allow a
/// handle to be reused for a fresh exchange.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Krb5Data {
    /// The service principal name (e.g. `imap@mail.example.com`), built once on
    /// the first user-message round via [`crate::auth::build_spn`]. `None`
    /// until the first round has run.
    spn: Option<String>,
    /// Whether mutual authentication was requested for this exchange (the C
    /// `mutual_auth` parameter). Influences the initial empty-token semantics.
    mutual_auth: bool,
    /// Whether a GSSAPI security context has been fully established. Without a
    /// wired-in GSSAPI provider this never becomes `true`; it is retained so
    /// the lifecycle mirrors the C `context != GSS_C_NO_CONTEXT` checks and so a
    /// reused handle reports a clean state.
    context_established: bool,
}

impl Krb5Data {
    /// Creates a fresh, empty Kerberos V5 authentication state.
    ///
    /// Equivalent to a zeroed C `struct kerberos5data`: no SPN, mutual
    /// authentication not requested, and no established context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            spn: None,
            mutual_auth: false,
            context_established: false,
        }
    }

    /// Returns the service principal name built for this exchange, or `None` if
    /// no user-message round has run yet.
    #[must_use]
    pub fn spn(&self) -> Option<&str> {
        self.spn.as_deref()
    }

    /// Returns whether mutual authentication was requested for this exchange.
    #[must_use]
    pub fn mutual_auth(&self) -> bool {
        self.mutual_auth
    }

    /// Returns whether a GSSAPI security context has been fully established.
    ///
    /// Always `false` in this build, because no GSSAPI provider is wired in to
    /// complete the handshake (see the module documentation).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.context_established
    }

    /// Resets the handle to its freshly-constructed state, releasing the SPN and
    /// clearing the context flag so it can be reused for a new exchange.
    ///
    /// This is the safe-Rust analogue of `Curl_auth_cleanup_gssapi`: in C that
    /// function releases the `gss_ctx_id_t` and `gss_name_t`; here dropping the
    /// owned `String` frees the SPN, and there is no raw context to release.
    pub fn reset(&mut self) {
        self.spn = None;
        self.mutual_auth = false;
        self.context_established = false;
    }
}

/// Reports whether Kerberos V5 (GSSAPI) authentication is supported.
///
/// Mirrors curl's `Curl_auth_is_gssapi_supported`, which unconditionally returns
/// `TRUE` whenever the GSS-API code is compiled in. Because this entire module
/// only exists when the `gssapi` feature is enabled, the compiled answer is
/// likewise always `true`; when the feature is off the function does not exist
/// and [`crate::version`] does not advertise the capability bit.
#[must_use]
pub fn is_gssapi_supported() -> bool {
    true
}

/// Generates the next Kerberos V5 (GSSAPI) **user** token for the SASL exchange.
///
/// Safe-Rust successor to `Curl_auth_create_gssapi_user_message`. On the first
/// round it builds the service principal name with
/// `build_spn(service, None, host)` — the host-based form `service@host`,
/// matching the C call `Curl_auth_build_spn(service, NULL, host)` — and stores
/// it on `krb5`. If the server sent a `challenge` (the previous round's token,
/// base64-encoded) it is decoded and fed into the context; an explicitly empty
/// challenge is rejected with [`CurlError::BadContentEncoding`], exactly as curl
/// flags an "empty challenge message". The advanced context's output token is
/// returned base64-encoded, ready for the SASL wire.
///
/// # Parameters
///
/// * `krb5` — the per-exchange authentication state (modified in place).
/// * `service` — the service type (`smtp`, `imap`, `pop`, …).
/// * `host` — the target hostname.
/// * `mutual_auth` — whether mutual authentication is requested.
/// * `challenge` — the optional server challenge, base64-encoded; `None` on the
///   initial round.
///
/// # Errors
///
/// * [`CurlError::BadContentEncoding`] if a present challenge is empty or is not
///   valid base64.
/// * [`CurlError::NotBuiltIn`] from the [`gss_init_sec_context`] seam, because no
///   GSSAPI provider is wired into this build (see the module documentation).
///   The default `curl-rs` build never reaches this path.
///
/// # Note on `userp` / `passwdp`
///
/// curl's signature also takes a username and password but ignores both (GSSAPI
/// uses ambient Kerberos credentials, not a SASL username/password); they are
/// omitted here for the same reason.
pub fn create_gssapi_user_message(
    krb5: &mut Krb5Data,
    service: &str,
    host: &str,
    mutual_auth: bool,
    challenge: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // Remember the requested mutual-authentication mode for this exchange.
    krb5.mutual_auth = mutual_auth;

    // Build (and conceptually import) the SPN once, on the first round. The
    // delegation to `build_spn` keeps the SPN identical to the one
    // `negotiate.rs` produces. `build_spn(service, None, host)` yields the
    // host-based `service@host`, matching the C `(service, NULL, host)` call.
    if krb5.spn.is_none() {
        krb5.spn = Some(build_spn(service, None, Some(host)));
    }

    // Decode the optional server challenge from its base64 wire form. A present
    // but empty challenge is a protocol error, mirroring curl's explicit
    // "empty challenge message" rejection before any token processing.
    let input_token = match challenge {
        Some(chlg) => {
            if chlg.is_empty() {
                return Err(CurlError::BadContentEncoding);
            }
            Some(base64_decode(chlg)?)
        }
        None => None,
    };

    // Advance the GSSAPI security context one step. This is the credential-
    // dependent seam: without a wired-in GSSAPI provider it returns
    // `CURLE_NOT_BUILT_IN` (see the module documentation).
    let output_token = gss_init_sec_context(krb5, input_token.as_deref(), mutual_auth)?;

    // Frame the produced token as base64 for the SASL wire and return it.
    let encoded = base64_encode(&output_token)?;
    Ok(encoded)
}

/// Generates the Kerberos V5 (GSSAPI) **security-layer** response (RFC 4752 §3.1).
///
/// Safe-Rust successor to `Curl_auth_create_gssapi_security_message`. The
/// mandatory `challenge` (base64-encoded) carries the server's wrapped security
/// token; it is decoded, unwrapped, and required to be exactly four octets — a
/// one-octet security-layer bitmask followed by a three-octet big-endian maximum
/// message size. curl supports no active security layer, so the server must
/// offer [`GSSAUTH_P_NONE`]; otherwise the exchange fails. The client response
/// echoes the selected (no-)security layer and a zero receive-buffer size, with
/// the optional authorization identity (`authzid`) appended, then is wrapped and
/// returned base64-encoded.
///
/// # Parameters
///
/// * `krb5` — the per-exchange authentication state.
/// * `authzid` — the optional authorization identity to assert.
/// * `challenge` — the server's security token, base64-encoded (required).
///
/// # Errors
///
/// * [`CurlError::BadContentEncoding`] if the challenge is empty, is not valid
///   base64, the unwrapped token is not exactly four octets, or the server does
///   not offer the `GSSAUTH_P_NONE` security layer.
/// * [`CurlError::NotBuiltIn`] from the [`gss_unwrap_token`] / [`gss_wrap_token`]
///   seams, because no GSSAPI provider is wired into this build. The default
///   `curl-rs` build never reaches this path.
pub fn create_gssapi_security_message(
    krb5: &mut Krb5Data,
    authzid: Option<&str>,
    challenge: &[u8],
) -> Result<Vec<u8>> {
    // A security message requires a non-empty challenge (RFC 4752 §3.1); curl
    // reports an "empty security message" here.
    if challenge.is_empty() {
        return Err(CurlError::BadContentEncoding);
    }

    // Decode the base64 SASL-wire challenge into the wrapped security token.
    let wrapped = base64_decode(challenge)?;

    // Decrypt (unwrap) the server's security token. Credential-dependent seam:
    // returns `CURLE_NOT_BUILT_IN` with no GSSAPI provider wired in.
    let token = gss_unwrap_token(krb5, &wrapped)?;

    // Parse the four-octet security header: layer bitmask + max receive size.
    let (offered_layer, _server_max_size) = parse_security_challenge(&token)?;

    // The client supports no active security layer, so the server must have
    // offered "no security layer"; reject anything else (RFC 4752 §3.1).
    if offered_layer & GSSAUTH_P_NONE == 0 {
        return Err(CurlError::BadContentEncoding);
    }
    // Select exactly the no-security-layer option to echo back to the server.
    let selected_layer = offered_layer & GSSAUTH_P_NONE;

    // Frame the response (selected layer + zero receive buffer + authzid).
    let response = build_security_response(selected_layer, authzid);

    // Encrypt (wrap) the response. Credential-dependent seam: returns
    // `CURLE_NOT_BUILT_IN` with no GSSAPI provider wired in.
    let sealed = gss_wrap_token(krb5, &response)?;

    // Frame the wrapped response as base64 for the SASL wire and return it.
    let encoded = base64_encode(&sealed)?;
    Ok(encoded)
}

/// Releases the Kerberos V5 (GSSAPI) state held by `krb5`.
///
/// Naming-parity wrapper for curl's `Curl_auth_cleanup_gssapi`. In Rust the
/// owned [`Krb5Data`] frees its SPN automatically on `Drop`; this resets the
/// handle in place so it can be reused, which is the observable behavior the C
/// cleanup provides for a struct that outlives the exchange.
pub fn cleanup_gssapi(krb5: &mut Krb5Data) {
    krb5.reset();
}

// ===========================================================================
// GSSAPI credential seams (no pure-Rust provider is wired in — see module docs)
// ===========================================================================

/// Advances the GSSAPI security context (`gss_init_sec_context`).
///
/// A real implementation would call into a GSSAPI/Kerberos credential stack —
/// acquiring credentials, importing the host-based SPN, and exchanging context
/// tokens with the KDC-issued service ticket — to produce the next output
/// token. No such pure-Rust provider is in scope for this rewrite (see the
/// module documentation), so this seam returns [`CurlError::NotBuiltIn`]
/// (`CURLE_NOT_BUILT_IN`). The default `curl-rs` build compiles this module out
/// entirely and never reaches here.
fn gss_init_sec_context(
    _krb5: &mut Krb5Data,
    _input_token: Option<&[u8]>,
    _mutual_auth: bool,
) -> Result<Vec<u8>> {
    Err(CurlError::NotBuiltIn)
}

/// Decrypts a server security token (`gss_unwrap`).
///
/// Credential-dependent seam with no pure-Rust GSSAPI provider wired in; returns
/// [`CurlError::NotBuiltIn`]. See [`gss_init_sec_context`] and the module
/// documentation.
fn gss_unwrap_token(_krb5: &mut Krb5Data, _wrapped: &[u8]) -> Result<Vec<u8>> {
    Err(CurlError::NotBuiltIn)
}

/// Encrypts a client response token (`gss_wrap`).
///
/// Credential-dependent seam with no pure-Rust GSSAPI provider wired in; returns
/// [`CurlError::NotBuiltIn`]. See [`gss_init_sec_context`] and the module
/// documentation.
fn gss_wrap_token(_krb5: &mut Krb5Data, _plaintext: &[u8]) -> Result<Vec<u8>> {
    Err(CurlError::NotBuiltIn)
}

// ===========================================================================
// Pure RFC 4752 §3.1 framing helpers (credential-independent; fully tested)
// ===========================================================================

/// Parses the four-octet decrypted security token (RFC 4752 §3.1).
///
/// Returns `(security_layer_bitmask, server_max_receive_size)`, where the size
/// is the three trailing octets interpreted big-endian. The token must be
/// exactly [`SECURITY_TOKEN_LEN`] octets long; any other length is malformed and
/// yields [`CurlError::BadContentEncoding`], matching curl's
/// "invalid security data" rejection.
fn parse_security_challenge(token: &[u8]) -> Result<(u8, u32)> {
    if token.len() != SECURITY_TOKEN_LEN {
        return Err(CurlError::BadContentEncoding);
    }
    let sec_layer = token[0];
    let max_size = (u32::from(token[1]) << 16) | (u32::from(token[2]) << 8) | u32::from(token[3]);
    Ok((sec_layer, max_size))
}

/// Builds the client security-layer response message (RFC 4752 §3.1).
///
/// The first octet is the selected security layer (`sec_layer`); the next three
/// are the client's maximum receive buffer size, big-endian. curl never
/// negotiates an active security layer, so it advertises a **zero** receive
/// buffer (it needs no buffer unless it would encrypt data). The optional
/// authorization identity is appended verbatim. This mirrors the C message
/// construction byte-for-byte.
fn build_security_response(sec_layer: u8, authzid: Option<&str>) -> Vec<u8> {
    // curl reports a zero maximum receive buffer because it does not encrypt.
    let max_size: u32 = 0;

    let authzid_bytes: &[u8] = match authzid {
        Some(id) => id.as_bytes(),
        None => &[],
    };

    let mut message = Vec::with_capacity(SECURITY_TOKEN_LEN + authzid_bytes.len());
    message.push(sec_layer);
    message.push((max_size >> 16) as u8);
    message.push((max_size >> 8) as u8);
    message.push(max_size as u8);
    message.extend_from_slice(authzid_bytes);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- capability probe --------------------------------------------------

    #[test]
    fn gssapi_is_reported_supported_when_compiled() {
        // Mirrors curl's `Curl_auth_is_gssapi_supported` returning TRUE whenever
        // the GSS-API code is compiled in (which, here, means the `gssapi`
        // feature is enabled — otherwise this module would not exist).
        assert!(is_gssapi_supported());
    }

    // ---- security-layer constants -----------------------------------------

    #[test]
    fn security_layer_constants_match_rfc4752() {
        // The RFC 4752 / curl `GSSAUTH_P_*` bit values.
        assert_eq!(GSSAUTH_P_NONE, 1);
        assert_eq!(GSSAUTH_P_INTEGRITY, 2);
        assert_eq!(GSSAUTH_P_PRIVACY, 4);
        // They are distinct single bits.
        assert_eq!(GSSAUTH_P_NONE & GSSAUTH_P_INTEGRITY, 0);
        assert_eq!(GSSAUTH_P_NONE & GSSAUTH_P_PRIVACY, 0);
    }

    // ---- handle lifecycle --------------------------------------------------

    #[test]
    fn new_handle_is_empty() {
        let krb5 = Krb5Data::new();
        assert_eq!(krb5.spn(), None);
        assert!(!krb5.mutual_auth());
        assert!(!krb5.is_complete());
        // `Default` agrees with `new`.
        assert_eq!(krb5, Krb5Data::default());
    }

    #[test]
    fn reset_and_cleanup_clear_state() {
        let mut krb5 = Krb5Data::new();
        // Drive one user-message round to populate the SPN and mutual-auth flag.
        let _ = create_gssapi_user_message(&mut krb5, "imap", "mail.example.com", true, None);
        assert!(krb5.spn().is_some());
        assert!(krb5.mutual_auth());

        krb5.reset();
        assert_eq!(krb5.spn(), None);
        assert!(!krb5.mutual_auth());

        // `cleanup_gssapi` is the naming-parity wrapper for `reset`.
        let mut krb5b = Krb5Data::new();
        let _ = create_gssapi_user_message(&mut krb5b, "smtp", "host", false, None);
        cleanup_gssapi(&mut krb5b);
        assert_eq!(krb5b, Krb5Data::new());
    }

    // ---- user message: SPN construction (delegates to build_spn) -----------

    #[test]
    fn user_message_builds_spn_via_build_spn() {
        let mut krb5 = Krb5Data::new();
        let service = "imap";
        let host = "mail.example.com";

        // The result is the credential-dependent `NotBuiltIn` seam, but the SPN
        // must have been constructed and stored as a side effect.
        let result = create_gssapi_user_message(&mut krb5, service, host, false, None);
        assert_eq!(result, Err(CurlError::NotBuiltIn));

        // The SPN must equal exactly what the shared `build_spn` produces for
        // `(service, None, host)`, proving the delegation (and keeping this in
        // lockstep with `negotiate.rs`). For the host-based GSSAPI form that is
        // `service@host`.
        let expected = build_spn(service, None, Some(host));
        assert_eq!(krb5.spn(), Some(expected.as_str()));
    }

    #[test]
    fn user_message_remembers_mutual_auth_flag() {
        let mut krb5 = Krb5Data::new();
        let _ = create_gssapi_user_message(&mut krb5, "smtp", "host", true, None);
        assert!(krb5.mutual_auth());

        // A second exchange with mutual auth off updates the flag.
        let mut krb5b = Krb5Data::new();
        let _ = create_gssapi_user_message(&mut krb5b, "smtp", "host", false, None);
        assert!(!krb5b.mutual_auth());
    }

    #[test]
    fn user_message_spn_built_once_and_reused() {
        let mut krb5 = Krb5Data::new();
        let _ = create_gssapi_user_message(&mut krb5, "imap", "first.example.com", false, None);
        let first = krb5.spn().map(str::to_owned);
        assert!(first.is_some());

        // A later round with different arguments must NOT rebuild the SPN: curl
        // only constructs it when `!krb5->spn`.
        let _ = create_gssapi_user_message(&mut krb5, "smtp", "second.example.com", false, None);
        assert_eq!(krb5.spn().map(str::to_owned), first);
    }

    #[test]
    fn user_message_rejects_empty_challenge() {
        let mut krb5 = Krb5Data::new();
        // A present-but-empty challenge is a protocol error, before any token
        // processing — matching curl's "empty challenge message" rejection.
        let result = create_gssapi_user_message(&mut krb5, "imap", "host", false, Some(b""));
        assert_eq!(result, Err(CurlError::BadContentEncoding));
    }

    #[test]
    fn user_message_decodes_then_reaches_seam() {
        let mut krb5 = Krb5Data::new();
        // A valid (non-empty) base64 challenge decodes successfully, so the flow
        // reaches the credential seam and reports `NotBuiltIn` rather than a
        // decoding error.
        let challenge = base64_encode(b"server-token-bytes").expect("encode");
        let result = create_gssapi_user_message(&mut krb5, "imap", "host", false, Some(&challenge));
        assert_eq!(result, Err(CurlError::NotBuiltIn));
    }

    #[test]
    fn user_message_rejects_invalid_base64_challenge() {
        let mut krb5 = Krb5Data::new();
        // `"!!!"` is not valid base64 (illegal symbols, length not a multiple of
        // four); decoding fails with `BadContentEncoding`.
        let result = create_gssapi_user_message(&mut krb5, "imap", "host", false, Some(b"!!!"));
        assert_eq!(result, Err(CurlError::BadContentEncoding));
    }

    // ---- security message --------------------------------------------------

    #[test]
    fn security_message_rejects_empty_challenge() {
        let mut krb5 = Krb5Data::new();
        let result = create_gssapi_security_message(&mut krb5, None, b"");
        assert_eq!(result, Err(CurlError::BadContentEncoding));
    }

    #[test]
    fn security_message_reaches_unwrap_seam() {
        let mut krb5 = Krb5Data::new();
        // A valid, non-empty base64 challenge decodes, so the flow reaches the
        // `gss_unwrap` seam and reports `NotBuiltIn`.
        let challenge = base64_encode(&[GSSAUTH_P_NONE, 0, 0, 0]).expect("encode");
        let result = create_gssapi_security_message(&mut krb5, Some("authz"), &challenge);
        assert_eq!(result, Err(CurlError::NotBuiltIn));
    }

    #[test]
    fn security_message_rejects_invalid_base64_challenge() {
        let mut krb5 = Krb5Data::new();
        let result = create_gssapi_security_message(&mut krb5, None, b"!!!");
        assert_eq!(result, Err(CurlError::BadContentEncoding));
    }

    // ---- pure framing helpers ---------------------------------------------

    #[test]
    fn parse_security_challenge_extracts_layer_and_size() {
        // sec_layer = GSSAUTH_P_NONE; max size = 0x010203 big-endian.
        let (layer, size) = parse_security_challenge(&[GSSAUTH_P_NONE, 0x01, 0x02, 0x03])
            .expect("valid four-octet token");
        assert_eq!(layer, GSSAUTH_P_NONE);
        assert_eq!(size, 0x0001_0203);

        // Maximum 24-bit value round-trips.
        let (_, size_max) = parse_security_challenge(&[0, 0xFF, 0xFF, 0xFF]).expect("valid token");
        assert_eq!(size_max, 0x00FF_FFFF);
    }

    #[test]
    fn parse_security_challenge_rejects_wrong_length() {
        // Anything other than exactly four octets is malformed.
        for bad in [&b""[..], &b"abc"[..], &b"abcde"[..]] {
            assert_eq!(
                parse_security_challenge(bad),
                Err(CurlError::BadContentEncoding)
            );
        }
    }

    #[test]
    fn build_security_response_frames_layer_size_and_authzid() {
        // No authorization identity: four octets, selected layer then zero size.
        let msg = build_security_response(GSSAUTH_P_NONE, None);
        assert_eq!(msg, vec![GSSAUTH_P_NONE, 0, 0, 0]);

        // With an authorization identity it is appended verbatim after the
        // four-octet header.
        let msg = build_security_response(GSSAUTH_P_NONE, Some("user@realm"));
        let mut expected = vec![GSSAUTH_P_NONE, 0, 0, 0];
        expected.extend_from_slice(b"user@realm");
        assert_eq!(msg, expected);
    }

    #[test]
    fn build_then_parse_round_trips_the_layer() {
        // The selected layer byte we emit parses back to the same value (the
        // size we emit is always zero).
        let msg = build_security_response(GSSAUTH_P_NONE, None);
        let (layer, size) = parse_security_challenge(&msg).expect("round-trip");
        assert_eq!(layer, GSSAUTH_P_NONE);
        assert_eq!(size, 0);
    }
}
