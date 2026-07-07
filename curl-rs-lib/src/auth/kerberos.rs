//! Kerberos V5 ("GSSAPI") SASL mechanism — RFC 4752.
//!
//! Port of curl 8.19.0-DEV `lib/vauth/krb5_gssapi.c` (the
//! `#if defined(HAVE_GSSAPI) && defined(USE_KERBEROS5)` code path). The Windows
//! SSPI variant `lib/vauth/krb5_sspi.c` is intentionally **dropped**: Windows is
//! out of scope for this rewrite, so only the GSS-API implementation is
//! reproduced.
//!
//! # Feature gating and the unsafe policy
//!
//! This module is the **only** place in the entire workspace where optional OS
//! C linkage (GSS-API / Kerberos) is permitted, and it is **strictly
//! feature-gated** behind the default-**off** `gssapi` Cargo feature:
//!
//! * **Default build (`gssapi` off):** compiles as a pure-Rust "unsupported"
//!   stub with **zero `unsafe` and zero C linkage**, mirroring curl's behavior
//!   when it is built without GSS-API (where `Curl_auth_is_gssapi_supported()`
//!   evaluates to `FALSE`). This is the always-compiled path that the CI grep
//!   audit (`grep -rn 'unsafe' curl-rs-lib/src/`) inspects; it finds nothing.
//! * **Feature build (`gssapi` on):** the GSS-API implementation is enabled and
//!   is written entirely against the [`libgssapi`] **safe** wrapper crate, so
//!   even the feature build contains **zero `unsafe`** and the crate-wide
//!   `#![forbid(unsafe_code)]` remains intact — no lint relaxation in `lib.rs`
//!   is required.
//!
//! The public item surface (`Kerberos5Data`, [`is_gssapi_supported`],
//! [`create_gssapi_user_message`], [`create_gssapi_security_message`] and
//! [`cleanup_gssapi`]) is **identical across both feature states** so that
//! `negotiate.rs` and `sasl.rs` — which delegate all of their GSS-API
//! operations here — compile and call unconditionally.
//
// DEP NOTE (FLAG #3): the `gssapi` Cargo feature and a GSS-API provider crate
// (prefer a SAFE wrapper such as `libgssapi`, which exposes GSS-API through a
// safe Rust API) MUST be declared, **default-OFF**, in `curl-rs-lib/Cargo.toml`
// by the manifest owner. No GSSAPI crate is listed in AAP §0.5.1 and the
// `gssapi` feature is not yet declared. Absent the feature this module is a
// pure-Rust "unsupported" stub with zero `unsafe`. Do NOT introduce a
// default-ON GSSAPI feature — curl's own GSS-API support is optional/off in
// typical builds. Crate versions are intentionally NOT hard-coded here.
//
// LINT BRIDGE: the module-scoped `allow(unexpected_cfgs)` below is required
// until the `gssapi` feature is declared in Cargo.toml. On toolchains that emit
// `--check-cfg` (Rust >= 1.80 / current stable, used by the CI clippy/test
// legs) an undeclared `cfg(feature = "gssapi")` is reported as an "unexpected
// cfg value" and `cargo clippy -- -D warnings` fails. This allow keeps the file
// warning-clean on both the MSRV (1.75) and stable toolchains and becomes a
// harmless no-op the moment the feature is declared.
#![allow(unexpected_cfgs)]

/// Reports whether Kerberos V5 (GSS-API) authentication is supported by this
/// build.
///
/// Port of `Curl_auth_is_gssapi_supported()` (`lib/vauth/krb5_gssapi.c` L50-53),
/// which returns `TRUE` only when curl is compiled with GSS-API. Here that maps
/// directly to whether the `gssapi` Cargo feature is enabled: `false` in the
/// default pure-Rust build, `true` when the feature is on.
#[must_use]
pub fn is_gssapi_supported() -> bool {
    cfg!(feature = "gssapi")
}

// ===========================================================================
// Default build (`gssapi` OFF): pure-Rust "unsupported" stub — zero unsafe.
// ===========================================================================

/// Per-connection Kerberos V5 state (port of C `struct kerberos5data`).
///
/// In the default build (no `gssapi` feature) this is an empty marker type:
/// there is no GSS-API context to hold. Its name matches
/// `crate::auth::ConnAuthState`'s `krb5` field, and it derives [`Default`] so
/// that field's `Option::get_or_insert_with(Default::default)` accessor works.
///
/// An empty *braced* struct (rather than a unit struct) is used deliberately so
/// that `Kerberos5Data::default()` reads cleanly under Clippy in both feature
/// states — Clippy's `default_constructed_unit_structs` fires only for unit
/// structs.
#[cfg(not(feature = "gssapi"))]
#[derive(Debug, Default)]
pub struct Kerberos5Data {}

/// Generates a GSS-API (Kerberos V5) user-token message.
///
/// Stub for the default build: GSS-API is not compiled in, so this reports
/// `CURLE_NOT_BUILT_IN` exactly as curl does when the mechanism is unavailable.
/// The signature is identical to the feature-on implementation so callers in
/// `sasl.rs` / `negotiate.rs` compile unconditionally.
#[cfg(not(feature = "gssapi"))]
pub fn create_gssapi_user_message(
    _krb5: &mut Kerberos5Data,
    _service: &str,
    _host: &str,
    _mutual_auth: bool,
    _challenge: Option<&[u8]>,
) -> crate::error::Result<Option<Vec<u8>>> {
    Err(crate::error::Error::from(crate::error::CurlCode::NotBuiltIn))
}

/// Generates a GSS-API (Kerberos V5) security-layer message.
///
/// Stub for the default build: reports `CURLE_NOT_BUILT_IN`.
#[cfg(not(feature = "gssapi"))]
pub fn create_gssapi_security_message(
    _krb5: &mut Kerberos5Data,
    _authzid: Option<&str>,
    _challenge: &[u8],
) -> crate::error::Result<Vec<u8>> {
    Err(crate::error::Error::from(crate::error::CurlCode::NotBuiltIn))
}

/// Releases the Kerberos V5 state.
///
/// Stub for the default build: there is no GSS-API state to release, so this is
/// a no-op (kept for API parity with the feature-on build).
#[cfg(not(feature = "gssapi"))]
pub fn cleanup_gssapi(_krb5: &mut Kerberos5Data) {}

// ===========================================================================
// Feature build (`gssapi` ON): GSS-API via the `libgssapi` safe wrapper.
//
// This block is compiled only with `--features gssapi` (once the feature and a
// provider crate are declared in Cargo.toml — see the DEP NOTE above). It is
// written entirely against `libgssapi`'s safe API and therefore contains no
// `unsafe`. It reproduces the RFC 4752 GSS-API SASL flow of
// `lib/vauth/krb5_gssapi.c` byte-for-byte where the exchange is deterministic.
// ===========================================================================

#[cfg(feature = "gssapi")]
use crate::auth::build_spn;
#[cfg(feature = "gssapi")]
use crate::error::Error;
#[cfg(feature = "gssapi")]
use libgssapi::{
    context::{ClientCtx, CtxFlags, SecurityContext},
    name::Name,
    oid::{GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE},
};

/// The RFC 4752 "no security layer" protection value (`lib/curl_gssapi.h`).
///
/// curl also defines `GSSAUTH_P_INTEGRITY` (2) and `GSSAUTH_P_PRIVACY` (4), but
/// the SASL client only ever selects "no security layer", so only this bit is
/// needed here.
#[cfg(feature = "gssapi")]
const GSSAUTH_P_NONE: u8 = 1;

/// Per-connection Kerberos V5 state (port of C `struct kerberos5data`).
///
/// The `libgssapi` [`ClientCtx`] owns the underlying `gss_ctx_id_t` **and** the
/// imported service principal name (`gss_name_t`) that curl tracks separately
/// as `krb5->spn`; both are released when the context is dropped. Storing the
/// context alone is therefore sufficient — there is no separate `spn` field to
/// keep (which would otherwise be dead state).
#[cfg(feature = "gssapi")]
#[derive(Default)]
pub struct Kerberos5Data {
    /// The client security context, established on the first
    /// [`create_gssapi_user_message`] call and advanced on each subsequent one.
    context: Option<ClientCtx>,
}

// A manual `Debug` impl avoids requiring `libgssapi`'s handle types to be
// `Debug` and never prints opaque credential material.
#[cfg(feature = "gssapi")]
impl std::fmt::Debug for Kerberos5Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kerberos5Data")
            .field(
                "context",
                &self.context.as_ref().map(|_| "<gss_ctx_id_t>"),
            )
            .finish()
    }
}

/// Generates a GSS-API (Kerberos V5) user-token message ready for the SASL
/// layer to base64-encode.
///
/// Port of `Curl_auth_create_gssapi_user_message()`
/// (`lib/vauth/krb5_gssapi.c` L76-161). The `userp`/`passwdp` arguments of the C
/// function are omitted because it discards them (`(void)userp; (void)passwdp;`)
/// — Kerberos draws its credentials from the ambient credential cache.
///
/// The `challenge` is the server's most recent token (already base64-decoded by
/// the SASL layer), or `None` on the initiating call. The returned value mirrors
/// curl's three-way `bufref` result:
///
/// * `Some(token)` — a non-empty output token to transmit;
/// * `Some(empty)` — no token but mutual auth requested (C sets an empty
///   string);
/// * `None` — no token and mutual auth not requested (C sets `NULL`).
///
/// # Errors
///
/// Returns [`crate::error::Error`] mapping to `CURLE_BAD_CONTENT_ENCODING` for a
/// present-but-empty challenge, and to `CURLE_AUTH_ERROR` for GSS-API name
/// import or context-initialization failures — matching the C.
#[cfg(feature = "gssapi")]
pub fn create_gssapi_user_message(
    krb5: &mut Kerberos5Data,
    service: &str,
    host: &str,
    mutual_auth: bool,
    challenge: Option<&[u8]>,
) -> crate::error::Result<Option<Vec<u8>>> {
    // A present-but-empty challenge is a protocol failure. (krb5_gssapi.c
    // L123-130)
    if let Some(chlg) = challenge {
        if chlg.is_empty() {
            return Err(Error::bad_content_encoding(
                "GSSAPI handshake failure (empty challenge message)",
            ));
        }
    }

    // First invocation: no context yet, so import the service principal name and
    // create the client security context. (krb5_gssapi.c L96-141)
    if krb5.context.is_none() {
        // curl calls Curl_auth_build_spn(service, NULL, host); passing the host
        // in the realm slot yields the host-based principal "service@host".
        let spn = build_spn(service, None, Some(host));

        // Import the SPN as a host-based service name
        // (GSS_C_NT_HOSTBASED_SERVICE). (krb5_gssapi.c L108-118)
        let target = Name::new(spn.as_bytes(), Some(GSS_NT_HOSTBASED_SERVICE))
            .map_err(|e| Error::auth(format!("gss_import_name() failed: {e}")))?;

        // Request flags mirror Curl_gss_init_sec_context (lib/curl_gssapi.c):
        // replay detection is always requested; mutual authentication is added
        // only when asked for. Passing no credential uses the default
        // credentials (GSS_C_NO_CREDENTIAL) from the credential cache.
        let mut flags = CtxFlags::GSS_C_REPLAY_FLAG;
        if mutual_auth {
            flags |= CtxFlags::GSS_C_MUTUAL_FLAG;
        }

        krb5.context = Some(ClientCtx::new(None, target, flags, Some(GSS_MECH_KRB5)));
    }

    // Perform a single GSS-API initialization step, feeding the server's token
    // (if any) and producing the next output token. curl drives the loop across
    // SASL round trips, one step per call. (krb5_gssapi.c L132-151)
    let ctx = krb5.context.as_mut().expect("context created above");
    let output = ctx
        .step(challenge, None)
        .map_err(|e| Error::auth(format!("gss_init_sec_context() failed: {e}")))?;

    // Translate the output token to curl's bufref outcome. (krb5_gssapi.c
    // L153-158)
    match output {
        Some(token) if !token.is_empty() => Ok(Some(token.to_vec())),
        _ if mutual_auth => Ok(Some(Vec::new())),
        _ => Ok(None),
    }
}

/// Generates a GSS-API (Kerberos V5) security-layer message ready for the SASL
/// layer to base64-encode.
///
/// Port of `Curl_auth_create_gssapi_security_message()`
/// (`lib/vauth/krb5_gssapi.c` L179-293). The server's `challenge` (a wrapped
/// security token) is unwrapped, the offered security layer and maximum message
/// size are inspected, and the client's response is built selecting "no security
/// layer" with a zero-length receive buffer, then wrapped for transmission.
///
/// # Errors
///
/// Returns [`crate::error::Error`] mapping to `CURLE_BAD_CONTENT_ENCODING` for an
/// empty challenge, a failed unwrap, a non-four-octet payload, or an
/// unsupported security layer; and to `CURLE_AUTH_ERROR` if wrapping the
/// response fails — matching the C.
#[cfg(feature = "gssapi")]
pub fn create_gssapi_security_message(
    krb5: &mut Kerberos5Data,
    authzid: Option<&str>,
    challenge: &[u8],
) -> crate::error::Result<Vec<u8>> {
    // A valid, non-empty challenge is required. (krb5_gssapi.c L198-206)
    if challenge.is_empty() {
        return Err(Error::bad_content_encoding(
            "GSSAPI handshake failure (empty security message)",
        ));
    }

    let ctx = krb5
        .context
        .as_mut()
        .ok_or_else(|| Error::auth("GSSAPI security context not established"))?;

    // Decrypt the inbound challenge. A failure here is treated as bad content
    // encoding, exactly as curl maps a gss_unwrap() error. (krb5_gssapi.c
    // L208-215)
    let plaintext = ctx
        .unwrap(challenge)
        .map_err(|e| Error::bad_content_encoding(format!("gss_unwrap() failed: {e}")))?;

    // Per RFC 4752 §3.1 the security data must be exactly four octets.
    // (krb5_gssapi.c L217-222)
    if plaintext.len() != 4 {
        return Err(Error::bad_content_encoding(
            "GSSAPI handshake failure (invalid security data)",
        ));
    }

    // Extract the security layer and the maximum message size. (krb5_gssapi.c
    // L224-228)
    let sec_layer = plaintext[0];
    let mut max_size = (u32::from(plaintext[1]) << 16)
        | (u32::from(plaintext[2]) << 8)
        | u32::from(plaintext[3]);

    // The server must offer the "no security layer" option. (krb5_gssapi.c
    // L233-239)
    if sec_layer & GSSAUTH_P_NONE == 0 {
        return Err(Error::bad_content_encoding(
            "GSSAPI handshake failure (invalid security layer)",
        ));
    }
    // We do not support a security layer, so keep only GSSAUTH_P_NONE ...
    let sec_layer = sec_layer & GSSAUTH_P_NONE;
    // ... and, since we never encrypt, advertise a zero-length receive buffer.
    // (krb5_gssapi.c L241-247)
    if max_size > 0 {
        max_size = 0;
    }

    // Build the response: the four-octet security-layer / maximum-message-size
    // header, optionally followed by the authorization identity. (krb5_gssapi.c
    // L249-267)
    let authzid_bytes = authzid.unwrap_or("").as_bytes();
    let mut message = Vec::with_capacity(4 + authzid_bytes.len());
    message.push(sec_layer);
    message.push(((max_size >> 16) & 0xFF) as u8);
    message.push(((max_size >> 8) & 0xFF) as u8);
    message.push((max_size & 0xFF) as u8);
    if !authzid_bytes.is_empty() {
        message.extend_from_slice(authzid_bytes);
    }

    // Encrypt the response with confidentiality disabled (curl's gss_wrap with
    // conf_req = 0). (krb5_gssapi.c L273-282)
    let wrapped = ctx
        .wrap(false, &message)
        .map_err(|e| Error::auth(format!("gss_wrap() failed: {e}")))?;

    // Return the wrapped response for the SASL layer to base64-encode.
    // (krb5_gssapi.c L284-292)
    Ok(wrapped.to_vec())
}

/// Releases the Kerberos V5 GSS-API state.
///
/// Port of `Curl_auth_cleanup_gssapi()` (`lib/vauth/krb5_gssapi.c` L305-321).
/// Dropping the [`ClientCtx`] releases the underlying `gss_ctx_id_t` and the
/// service name it owns, so clearing the option performs both the
/// `gss_delete_sec_context` and `gss_release_name` that the C code does — with
/// no manual FFI.
#[cfg(feature = "gssapi")]
pub fn cleanup_gssapi(krb5: &mut Kerberos5Data) {
    krb5.context = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gssapi_supported_matches_feature_flag() {
        // curl returns TRUE from Curl_auth_is_gssapi_supported() only when built
        // with GSS-API; here that is exactly the `gssapi` feature state.
        assert_eq!(is_gssapi_supported(), cfg!(feature = "gssapi"));
    }

    #[test]
    fn kerberos5data_default_and_debug() {
        // ConnAuthState relies on `Kerberos5Data: Default` (via
        // `get_or_insert_with(Default::default)`) and derives `Debug`, so both
        // must be available in every feature configuration.
        let krb5 = Kerberos5Data::default();
        let _ = format!("{krb5:?}");
    }

    #[cfg(not(feature = "gssapi"))]
    #[test]
    fn stub_user_message_reports_not_built_in() {
        use crate::error::CurlCode;

        let mut krb5 = Kerberos5Data::default();
        let err = create_gssapi_user_message(&mut krb5, "imap", "host.example.com", false, None)
            .expect_err("stub must not succeed");
        assert_eq!(err.code(), CurlCode::NotBuiltIn);
    }

    #[cfg(not(feature = "gssapi"))]
    #[test]
    fn stub_security_message_reports_not_built_in() {
        use crate::error::CurlCode;

        let mut krb5 = Kerberos5Data::default();
        let err = create_gssapi_security_message(&mut krb5, None, &[0x01, 0x00, 0x00, 0x00])
            .expect_err("stub must not succeed");
        assert_eq!(err.code(), CurlCode::NotBuiltIn);
    }

    #[cfg(not(feature = "gssapi"))]
    #[test]
    fn stub_cleanup_is_a_noop() {
        let mut krb5 = Kerberos5Data::default();
        cleanup_gssapi(&mut krb5);
    }
}
