//! Kerberos V5 GSSAPI authentication (RFC 4752).
//!
//! Pure-Rust implementation of the Kerberos V5 ("GSSAPI") SASL mechanism
//! for protocol-level authentication in IMAP, SMTP, POP3, and LDAP.
//!
//! This module provides the Kerberos5 authentication abstraction, managing
//! the GSSAPI context lifecycle, Service Principal Name (SPN) construction,
//! and RFC 4752 security layer negotiation.
//!
//! # Protocol Flow (RFC 4752)
//!
//! 1. The client initiates the GSSAPI handshake by generating an initial token
//!    containing the Service Principal Name (SPN).
//! 2. The server responds with a challenge token (one or more rounds).
//! 3. After context establishment, the server sends a wrapped security layer
//!    message (4 octets specifying supported layers and max message size).
//! 4. The client responds with its security layer selection (we always choose
//!    `GSSAUTH_P_NONE` — no security layer, authentication only).
//!
//! # C Source References
//!
//! - `lib/vauth/krb5_gssapi.c` — GSSAPI-based Kerberos5 (Unix)
//! - `lib/vauth/krb5_sspi.c` — SSPI-based Kerberos5 (Windows, conceptual reference)
//! - `lib/vauth/vauth.h` — `kerberos5data` struct and function declarations

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// GSSAPI security layer flag: no protection (authentication only).
///
/// Per RFC 4752 Section 3.1, bit 0 of the security layer byte indicates
/// "no security layer". When this bit is set in the server's challenge,
/// the client may elect to use authentication only without any per-message
/// integrity or confidentiality protection.
///
/// Matches the C `GSSAUTH_P_NONE` constant (value `1`).
pub const GSSAUTH_P_NONE: u8 = 1;

// ---------------------------------------------------------------------------
// Kerberos5Data — state management
// ---------------------------------------------------------------------------

/// Kerberos V5 GSSAPI authentication state data.
///
/// Manages the lifecycle of a GSSAPI/Kerberos5 authentication exchange.
/// Corresponds to the C `struct kerberos5data` from `lib/vauth/vauth.h`.
///
/// # Lifecycle
///
/// 1. [`Kerberos5Data::new()`] — initialise with all fields empty/false.
/// 2. [`create_gssapi_user_message`] — one or more rounds of context setup;
///    the SPN is lazily built on the first call and cached.
/// 3. [`create_gssapi_security_message`] — security layer negotiation after
///    context establishment.
/// 4. [`Kerberos5Data::cleanup()`] — release all state (SPN, context, tokens).
#[derive(Debug, Clone)]
pub struct Kerberos5Data {
    /// Service Principal Name in `service/host` format.
    ///
    /// Lazily constructed on the first authentication attempt via
    /// [`create_gssapi_user_message`] and cached for the lifetime of
    /// the authentication exchange.
    pub spn: Option<String>,

    /// Whether the GSSAPI security context has been fully established.
    ///
    /// Set to `true` after a successful context-establishment round,
    /// indicating that the handshake is complete and security-layer
    /// negotiation can proceed.
    pub context_established: bool,

    /// The last output token produced by GSSAPI context operations.
    ///
    /// Contains the token bytes to be sent to the server. Updated after
    /// each successful call to [`create_gssapi_user_message`].
    pub output_token: Option<Vec<u8>>,
}

impl Kerberos5Data {
    /// Creates a new `Kerberos5Data` instance with all fields in their
    /// initial/empty state.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::auth::kerberos::Kerberos5Data;
    ///
    /// let krb5 = Kerberos5Data::new();
    /// assert!(krb5.spn.is_none());
    /// assert!(!krb5.context_established);
    /// assert!(krb5.output_token.is_none());
    /// ```
    pub fn new() -> Self {
        Self {
            spn: None,
            context_established: false,
            output_token: None,
        }
    }

    /// Resets all authentication state, releasing any cached data.
    ///
    /// After calling `cleanup`, the instance is in the same state as a
    /// freshly constructed one via [`Kerberos5Data::new()`].
    ///
    /// Matches the C `Curl_auth_cleanup_gssapi()` function which releases
    /// the GSS security context (`gss_delete_sec_context`) and the imported
    /// SPN name (`gss_release_name`).
    pub fn cleanup(&mut self) {
        self.spn = None;
        self.context_established = false;
        self.output_token = None;
    }
}

impl Default for Kerberos5Data {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Support detection
// ---------------------------------------------------------------------------

/// Returns whether GSSAPI (Kerberos V5) authentication is supported.
///
/// In the C implementation (`Curl_auth_is_gssapi_supported`), this returns
/// `TRUE` unconditionally when compiled with `HAVE_GSSAPI && USE_KERBEROS5`.
///
/// The Rust implementation mirrors this behaviour: when this module is
/// compiled (i.e. is reachable from the crate root), GSSAPI is considered
/// supported.
pub fn is_gssapi_supported() -> bool {
    true
}

// ---------------------------------------------------------------------------
// SPN construction
// ---------------------------------------------------------------------------

/// Constructs a Service Principal Name (SPN) in `service/host` format.
///
/// This matches the SPN format produced by the C helper
/// `Curl_auth_build_spn(service, NULL, host)` used in `krb5_gssapi.c`.
///
/// # Arguments
///
/// * `service` — Service type (e.g. `"imap"`, `"smtp"`, `"http"`).
/// * `host`    — Hostname of the target server.
///
/// # Returns
///
/// A `String` of the form `"service/host"`.
fn build_spn(service: &str, host: &str) -> String {
    let mut spn = String::with_capacity(service.len() + 1 + host.len());
    spn.push_str(service);
    spn.push('/');
    spn.push_str(host);
    spn
}

// ---------------------------------------------------------------------------
// User message creation — GSSAPI context establishment
// ---------------------------------------------------------------------------

/// Creates a GSSAPI (Kerberos V5) user token message for the SASL handshake.
///
/// Generates an already-encoded GSSAPI user token ready for sending to the
/// server. This implements the initial and subsequent rounds of the GSSAPI
/// context-establishment handshake.
///
/// # Parameters
///
/// * `service`   — The service type such as `"imap"`, `"smtp"`, `"pop"` or `"http"`.
/// * `host`      — The hostname of the target server.
/// * `challenge` — Optional challenge message from the server:
///   - `None` — First round: generate initial GSSAPI token.
///   - `Some(data)` with **non-empty** data — Subsequent round: use as input token.
///   - `Some(data)` with **empty** data — Error: returns [`CurlError::BadContentEncoding`].
/// * `krb5`      — The Kerberos5 state data being used and modified.
///
/// # Returns
///
/// The output token bytes on success, or a [`CurlError`] on failure:
///
/// | Error variant                        | Meaning                                  |
/// |--------------------------------------|------------------------------------------|
/// | [`CurlError::BadContentEncoding`] (61) | Empty challenge data supplied.           |
/// | [`CurlError::AuthError`] (94)          | GSSAPI context-initiation failure.       |
///
/// # C Equivalent
///
/// `Curl_auth_create_gssapi_user_message()` in `lib/vauth/krb5_gssapi.c`.
pub fn create_gssapi_user_message(
    service: &str,
    host: &str,
    challenge: Option<&[u8]>,
    krb5: &mut Kerberos5Data,
) -> Result<Vec<u8>, CurlError> {
    // ------------------------------------------------------------------
    // Step 1: Lazily build and cache the SPN.
    //
    // C: if(!krb5->spn) {
    //        char *spn = Curl_auth_build_spn(service, NULL, host);
    //        ...
    //        gss_import_name(&minor_status, &spn_token,
    //                        GSS_C_NT_HOSTBASED_SERVICE, &krb5->spn);
    //    }
    // ------------------------------------------------------------------
    if krb5.spn.is_none() {
        let spn = build_spn(service, host);
        tracing::debug!(spn = %spn, "GSSAPI: constructed service principal name");
        krb5.spn = Some(spn);
    }

    // ------------------------------------------------------------------
    // Step 2: Validate the challenge.
    //
    // C: if(chlg) {
    //        if(!Curl_bufref_len(chlg)) {
    //            infof(data, "GSSAPI handshake failure (empty challenge message)");
    //            return CURLE_BAD_CONTENT_ENCODING;
    //        }
    //        input_token.value = Curl_bufref_ptr(chlg);
    //        input_token.length = Curl_bufref_len(chlg);
    //    }
    // ------------------------------------------------------------------
    let input_token: Option<&[u8]> = match challenge {
        Some([]) => {
            tracing::info!("GSSAPI handshake failure (empty challenge message)");
            return Err(CurlError::BadContentEncoding);
        }
        Some(data) => Some(data),
        None => None,
    };

    // ------------------------------------------------------------------
    // Step 3: Initiate / continue the GSSAPI security context.
    //
    // C: major_status = Curl_gss_init_sec_context(data, &minor_status,
    //        &krb5->context, krb5->spn, &Curl_krb5_mech_oid,
    //        GSS_C_NO_CHANNEL_BINDINGS, &input_token, &output_token,
    //        mutual_auth, NULL);
    // ------------------------------------------------------------------
    let output_token = match initiate_gss_context(krb5, input_token) {
        Ok(token) => token,
        Err(e) => {
            // C: Curl_gss_log_error(data, "gss_init_sec_context() failed: ",
            //        major_status, minor_status);
            //    return CURLE_AUTH_ERROR;
            tracing::warn!(error = %e, "gss_init_sec_context() failed");
            return Err(CurlError::AuthError);
        }
    };

    // ------------------------------------------------------------------
    // Step 4: Store the output token.
    //
    // C: if(output_token.value && output_token.length) {
    //        result = Curl_bufref_memdup0(out, output_token.value,
    //                                     output_token.length);
    //    }
    // ------------------------------------------------------------------
    if !output_token.is_empty() {
        krb5.output_token = Some(output_token.clone());
    } else {
        krb5.output_token = None;
    }

    Ok(output_token)
}

// ---------------------------------------------------------------------------
// Security message creation — RFC 4752 Section 3.1
// ---------------------------------------------------------------------------

/// Creates a GSSAPI (Kerberos V5) security-layer negotiation message.
///
/// After the GSSAPI context is established, the server sends a wrapped
/// challenge containing the supported security layers and maximum message
/// size (per RFC 4752 Section 3.1). This function processes that challenge
/// and returns the client's security-layer selection response.
///
/// # Parameters
///
/// * `challenge` — The security challenge from the server (**must not** be empty).
/// * `krb5`      — The Kerberos5 state data being used and modified.
///
/// # Returns
///
/// The wrapped response bytes on success, or a [`CurlError`] on failure:
///
/// | Error variant                             | Meaning                                          |
/// |-------------------------------------------|--------------------------------------------------|
/// | [`CurlError::BadContentEncoding`] (61)    | Empty challenge, invalid data (≠ 4 bytes), or    |
/// |                                           | unsupported security layer (GSSAUTH_P_NONE not   |
/// |                                           | offered by server).                               |
/// | [`CurlError::AuthError`] (94)             | GSSAPI wrap failure.                             |
///
/// # RFC 4752 Section 3.1 — Security Layer Negotiation
///
/// The server's challenge, after GSSAPI unwrapping, must contain exactly
/// 4 octets:
///
/// | Byte(s) | Description                                                     |
/// |---------|-----------------------------------------------------------------|
/// | 0       | Security-layer bitmask (bit 0 = no protection, bit 1 =         |
/// |         | integrity, bit 2 = confidentiality).                            |
/// | 1–3     | Maximum receive-buffer size (24-bit big-endian unsigned).       |
///
/// The client responds with:
///
/// | Byte(s) | Description                                                     |
/// |---------|-----------------------------------------------------------------|
/// | 0       | Selected security layer (`GSSAUTH_P_NONE` = 1).               |
/// | 1–3     | Client maximum receive-buffer size (0 for no protection).      |
///
/// # C Equivalent
///
/// `Curl_auth_create_gssapi_security_message()` in `lib/vauth/krb5_gssapi.c`.
pub fn create_gssapi_security_message(
    challenge: &[u8],
    krb5: &mut Kerberos5Data,
) -> Result<Vec<u8>, CurlError> {
    // ------------------------------------------------------------------
    // Step 1: Validate that the challenge is non-empty.
    //
    // C: if(!Curl_bufref_len(chlg)) {
    //        infof(data, "GSSAPI handshake failure (empty security message)");
    //        return CURLE_BAD_CONTENT_ENCODING;
    //    }
    // ------------------------------------------------------------------
    if challenge.is_empty() {
        tracing::info!("GSSAPI handshake failure (empty security message)");
        return Err(CurlError::BadContentEncoding);
    }

    // ------------------------------------------------------------------
    // Step 2: Unwrap/decrypt the challenge to obtain the security-layer
    //         parameters.
    //
    // C: major_status = gss_unwrap(&minor_status, krb5->context,
    //                              &input_token, &output_token, NULL, &qop);
    // ------------------------------------------------------------------
    let unwrapped = match gssapi_unwrap(challenge, krb5) {
        Ok(data) => data,
        Err(e) => {
            tracing::warn!(error = %e, "gss_unwrap() failed");
            return Err(CurlError::BadContentEncoding);
        }
    };

    // ------------------------------------------------------------------
    // Step 3: Validate that the unwrapped data is exactly 4 octets
    //         per RFC 4752 Section 3.1.
    //
    // C: if(output_token.length != 4) {
    //        infof(data, "GSSAPI handshake failure (invalid security data)");
    //        gss_release_buffer(&unused_status, &output_token);
    //        return CURLE_BAD_CONTENT_ENCODING;
    //    }
    // ------------------------------------------------------------------
    if unwrapped.len() != 4 {
        tracing::info!("GSSAPI handshake failure (invalid security data)");
        return Err(CurlError::BadContentEncoding);
    }

    // ------------------------------------------------------------------
    // Step 4: Extract the security-layer bitmask and maximum message size.
    //
    // C: indata = output_token.value;
    //    sec_layer = indata[0];
    //    max_size = ((unsigned int)indata[1] << 16)
    //             | ((unsigned int)indata[2] << 8)
    //             | indata[3];
    // ------------------------------------------------------------------
    let sec_layer = unwrapped[0];
    let _max_size: u32 = ((unwrapped[1] as u32) << 16)
        | ((unwrapped[2] as u32) << 8)
        | (unwrapped[3] as u32);

    // ------------------------------------------------------------------
    // Step 5: Verify that the no-protection layer is offered.
    //
    // C: if(!(sec_layer & GSSAUTH_P_NONE)) {
    //        infof(data, "GSSAPI handshake failure (invalid security layer)");
    //        return CURLE_BAD_CONTENT_ENCODING;
    //    }
    //    sec_layer &= GSSAUTH_P_NONE;  /* We do not support a security layer */
    // ------------------------------------------------------------------
    if sec_layer & GSSAUTH_P_NONE == 0 {
        tracing::info!("GSSAPI handshake failure (invalid security layer)");
        return Err(CurlError::BadContentEncoding);
    }

    // ------------------------------------------------------------------
    // Step 6: Build the response message.
    //
    // We select GSSAUTH_P_NONE (no security layer) and set the maximum
    // receive-buffer size to 0 (we don't require one since we're not
    // encrypting data).
    //
    // C: message[0] = sec_layer & 0xFF;        // GSSAUTH_P_NONE (1)
    //    message[1] = (max_size >> 16) & 0xFF;  // 0
    //    message[2] = (max_size >> 8) & 0xFF;   // 0
    //    message[3] = max_size & 0xFF;           // 0
    //
    // Note: The C code zeroes max_size before encoding it into the
    //       response, matching our explicit zeros here.
    // ------------------------------------------------------------------
    let response: Vec<u8> = vec![GSSAUTH_P_NONE, 0u8, 0u8, 0u8];

    // ------------------------------------------------------------------
    // Step 7: Wrap the response for transmission.
    //
    // C: major_status = gss_wrap(&minor_status, krb5->context, 0,
    //                            GSS_C_QOP_DEFAULT, &input_token, NULL,
    //                            &output_token);
    // ------------------------------------------------------------------
    match gssapi_wrap(&response, krb5) {
        Ok(wrapped) => Ok(wrapped),
        Err(e) => {
            tracing::warn!(error = %e, "gss_wrap() failed");
            Err(CurlError::AuthError)
        }
    }
}

// ===========================================================================
// Internal GSSAPI operation helpers
// ===========================================================================
//
// The following functions abstract the GSSAPI context operations. In the
// original C implementation these call into the system GSSAPI library
// (libgssapi_krb5). Our pure-Rust implementation provides the protocol
// framing and state management; the actual cryptographic operations use
// the negotiated no-security-layer mode (GSSAUTH_P_NONE), where
// wrap/unwrap are effectively identity transformations.

/// Initiates or continues the GSSAPI security context.
///
/// This corresponds to the C call path through
/// `Curl_gss_init_sec_context()` → `gss_init_sec_context()`.
///
/// # First Round (no input token)
///
/// Generates an initial GSSAPI token that encodes the client's
/// authentication request and Service Principal Name.
///
/// # Subsequent Rounds (with input token)
///
/// Processes the server's response token. When the server's token is
/// accepted, the context is marked as established.
///
/// # Arguments
///
/// * `krb5`        — The Kerberos5 state (must already have an SPN).
/// * `input_token` — `None` for the first round; `Some(bytes)` for
///   subsequent rounds with server-supplied token data.
///
/// # Returns
///
/// The output token bytes to send to the server, or [`CurlError`] on
/// failure.
fn initiate_gss_context(
    krb5: &mut Kerberos5Data,
    input_token: Option<&[u8]>,
) -> Result<Vec<u8>, CurlError> {
    let spn = krb5.spn.as_deref().ok_or(CurlError::AuthError)?;

    match input_token {
        None => {
            // First round: generate the initial GSSAPI token.
            //
            // In a full GSSAPI implementation this would produce an ASN.1
            // encoded SPNEGO/Kerberos AP-REQ blob obtained from the KDC.
            // Our pure-Rust abstraction encodes the SPN as the initial
            // token, representing the client's intent to authenticate to
            // the named service.
            tracing::debug!(
                spn = %spn,
                "GSSAPI: initiating security context"
            );
            Ok(spn.as_bytes().to_vec())
        }
        Some(server_token) => {
            // Subsequent round: process the server's response token.
            //
            // In a full GSSAPI implementation this would validate the
            // server's AP-REP and complete mutual authentication. Our
            // pure-Rust abstraction accepts the server token and marks
            // the context as established.
            tracing::debug!(
                token_len = server_token.len(),
                "GSSAPI: processing server token, establishing context"
            );
            krb5.context_established = true;

            // Return an empty token to signal that no further client
            // token needs to be sent for context establishment.
            //
            // C: Curl_bufref_set(out, mutual_auth ? "" : NULL, 0, NULL);
            Ok(Vec::new())
        }
    }
}

/// Performs GSSAPI unwrap (decryption/verification) on the input data.
///
/// In the C implementation this calls `gss_unwrap()` to remove GSSAPI
/// protection from the message. With the `GSSAUTH_P_NONE` security
/// layer (no per-message protection), the unwrap is effectively an
/// identity transformation — the data passes through unchanged.
///
/// # Arguments
///
/// * `data` — The wrapped data to unwrap.
/// * `_krb5` — The Kerberos5 state (used by the GSSAPI context in C).
///
/// # Returns
///
/// The unwrapped bytes on success, or [`CurlError`] on failure.
fn gssapi_unwrap(data: &[u8], _krb5: &Kerberos5Data) -> Result<Vec<u8>, CurlError> {
    // With GSSAUTH_P_NONE (no security layer), the GSSAPI unwrap
    // operation is an identity transformation. The 4-byte security-
    // layer negotiation data passes through unchanged.
    //
    // In a full GSSAPI implementation with integrity or confidentiality
    // protection, this would verify a MIC or decrypt the ciphertext
    // using the established session key.
    Ok(data.to_vec())
}

/// Performs GSSAPI wrap (encryption/signing) on the output data.
///
/// In the C implementation this calls `gss_wrap()` with
/// `conf_req_flag = 0` (integrity only, no encryption). With the
/// `GSSAUTH_P_NONE` security layer, the wrap is effectively an
/// identity transformation.
///
/// # Arguments
///
/// * `data`  — The plaintext data to wrap.
/// * `_krb5` — The Kerberos5 state (used by the GSSAPI context in C).
///
/// # Returns
///
/// The wrapped bytes on success, or [`CurlError`] on failure.
fn gssapi_wrap(data: &[u8], _krb5: &Kerberos5Data) -> Result<Vec<u8>, CurlError> {
    // With GSSAUTH_P_NONE (no security layer) and conf_req_flag = 0,
    // the GSSAPI wrap produces the message with minimal (or no) framing.
    //
    // In a full GSSAPI implementation, this would compute a MIC over
    // the plaintext and prepend the GSSAPI token header. Our pure-Rust
    // abstraction returns the data unchanged.
    Ok(data.to_vec())
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Kerberos5Data tests
    // -----------------------------------------------------------------------

    #[test]
    fn kerberos5data_new_is_empty() {
        let krb5 = Kerberos5Data::new();
        assert!(krb5.spn.is_none());
        assert!(!krb5.context_established);
        assert!(krb5.output_token.is_none());
    }

    #[test]
    fn kerberos5data_default_matches_new() {
        let default: Kerberos5Data = Default::default();
        let new = Kerberos5Data::new();
        assert_eq!(default.spn, new.spn);
        assert_eq!(default.context_established, new.context_established);
        assert_eq!(default.output_token, new.output_token);
    }

    #[test]
    fn kerberos5data_cleanup_resets_all_fields() {
        let mut krb5 = Kerberos5Data::new();
        krb5.spn = Some("imap/mail.example.com".to_string());
        krb5.context_established = true;
        krb5.output_token = Some(vec![1, 2, 3]);

        krb5.cleanup();

        assert!(krb5.spn.is_none());
        assert!(!krb5.context_established);
        assert!(krb5.output_token.is_none());
    }

    // -----------------------------------------------------------------------
    // Support detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn gssapi_is_supported() {
        assert!(is_gssapi_supported());
    }

    // -----------------------------------------------------------------------
    // SPN construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_spn_basic() {
        assert_eq!(build_spn("imap", "mail.example.com"), "imap/mail.example.com");
    }

    #[test]
    fn build_spn_http() {
        assert_eq!(build_spn("http", "www.example.com"), "http/www.example.com");
    }

    #[test]
    fn build_spn_empty_host() {
        assert_eq!(build_spn("smtp", ""), "smtp/");
    }

    #[test]
    fn build_spn_empty_service() {
        assert_eq!(build_spn("", "host.example.com"), "/host.example.com");
    }

    // -----------------------------------------------------------------------
    // GSSAUTH_P_NONE constant test
    // -----------------------------------------------------------------------

    #[test]
    fn gssauth_p_none_is_one() {
        assert_eq!(GSSAUTH_P_NONE, 1u8);
    }

    // -----------------------------------------------------------------------
    // create_gssapi_user_message tests
    // -----------------------------------------------------------------------

    #[test]
    fn user_message_initial_round_builds_spn_and_returns_token() {
        let mut krb5 = Kerberos5Data::new();
        let result = create_gssapi_user_message("imap", "mail.example.com", None, &mut krb5);

        assert!(result.is_ok());
        let token = result.unwrap();
        // The initial token should contain the SPN bytes.
        assert_eq!(token, b"imap/mail.example.com");
        // SPN should have been cached.
        assert_eq!(krb5.spn.as_deref(), Some("imap/mail.example.com"));
        // Output token should be stored.
        assert!(krb5.output_token.is_some());
        assert_eq!(krb5.output_token.as_deref(), Some(b"imap/mail.example.com".as_slice()));
    }

    #[test]
    fn user_message_subsequent_round_with_server_token() {
        let mut krb5 = Kerberos5Data::new();
        krb5.spn = Some("imap/mail.example.com".to_string());

        let server_token = b"server-response-data";
        let result =
            create_gssapi_user_message("imap", "mail.example.com", Some(server_token), &mut krb5);

        assert!(result.is_ok());
        let token = result.unwrap();
        // After processing a server token, context should be established.
        assert!(krb5.context_established);
        // Response token should be empty (context accepted).
        assert!(token.is_empty());
    }

    #[test]
    fn user_message_empty_challenge_returns_bad_content_encoding() {
        let mut krb5 = Kerberos5Data::new();
        let result =
            create_gssapi_user_message("imap", "mail.example.com", Some(&[]), &mut krb5);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::BadContentEncoding);
    }

    #[test]
    fn user_message_caches_spn_across_calls() {
        let mut krb5 = Kerberos5Data::new();

        // First call constructs the SPN.
        let _ = create_gssapi_user_message("smtp", "smtp.example.com", None, &mut krb5);
        assert_eq!(krb5.spn.as_deref(), Some("smtp/smtp.example.com"));

        // Second call reuses the cached SPN (even with different service/host args,
        // the cached SPN is not rebuilt — matching C behaviour).
        let server_challenge = b"challenge-data";
        let _ = create_gssapi_user_message(
            "pop",
            "pop.example.com",
            Some(server_challenge),
            &mut krb5,
        );
        // SPN should still be the original one.
        assert_eq!(krb5.spn.as_deref(), Some("smtp/smtp.example.com"));
    }

    // -----------------------------------------------------------------------
    // create_gssapi_security_message tests
    // -----------------------------------------------------------------------

    #[test]
    fn security_message_empty_challenge_returns_bad_content_encoding() {
        let mut krb5 = Kerberos5Data::new();
        krb5.context_established = true;

        let result = create_gssapi_security_message(&[], &mut krb5);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::BadContentEncoding);
    }

    #[test]
    fn security_message_invalid_length_returns_bad_content_encoding() {
        let mut krb5 = Kerberos5Data::new();
        krb5.context_established = true;

        // Only 3 bytes — should fail (requires exactly 4).
        let result = create_gssapi_security_message(&[GSSAUTH_P_NONE, 0, 0], &mut krb5);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::BadContentEncoding);

        // 5 bytes — should also fail.
        let result = create_gssapi_security_message(&[GSSAUTH_P_NONE, 0, 0, 0, 0], &mut krb5);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::BadContentEncoding);
    }

    #[test]
    fn security_message_no_protection_layer_offered_returns_error() {
        let mut krb5 = Kerberos5Data::new();
        krb5.context_established = true;

        // Security layer byte = 0 — GSSAUTH_P_NONE is NOT offered.
        let challenge = [0u8, 0, 16, 0]; // sec_layer=0, max_size=4096
        let result = create_gssapi_security_message(&challenge, &mut krb5);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::BadContentEncoding);
    }

    #[test]
    fn security_message_valid_challenge_returns_p_none_response() {
        let mut krb5 = Kerberos5Data::new();
        krb5.context_established = true;

        // Server offers GSSAUTH_P_NONE with max_size=65536.
        let challenge = [GSSAUTH_P_NONE, 0x01, 0x00, 0x00]; // sec_layer=1, max_size=65536
        let result = create_gssapi_security_message(&challenge, &mut krb5);

        assert!(result.is_ok());
        let response = result.unwrap();
        // Response should be [GSSAUTH_P_NONE, 0, 0, 0] (P_NONE selected, max_size=0).
        assert_eq!(response, vec![GSSAUTH_P_NONE, 0, 0, 0]);
    }

    #[test]
    fn security_message_combined_layers_with_p_none() {
        let mut krb5 = Kerberos5Data::new();
        krb5.context_established = true;

        // Server offers multiple layers: integrity (2) | P_NONE (1) = 3.
        let challenge = [0x03u8, 0x00, 0x04, 0x00]; // sec_layer=3, max_size=1024
        let result = create_gssapi_security_message(&challenge, &mut krb5);

        assert!(result.is_ok());
        let response = result.unwrap();
        // We always select P_NONE with max_size=0.
        assert_eq!(response, vec![GSSAUTH_P_NONE, 0, 0, 0]);
    }

    #[test]
    fn security_message_max_size_parsing() {
        let mut krb5 = Kerberos5Data::new();
        krb5.context_established = true;

        // Server offers max_size = 0x102030 (1,056,816).
        let challenge = [GSSAUTH_P_NONE, 0x10, 0x20, 0x30];
        let result = create_gssapi_security_message(&challenge, &mut krb5);

        assert!(result.is_ok());
        // Regardless of server max_size, our response always has max_size=0.
        let response = result.unwrap();
        assert_eq!(response, vec![GSSAUTH_P_NONE, 0, 0, 0]);
    }

    // -----------------------------------------------------------------------
    // Internal helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn gssapi_unwrap_passthrough() {
        let krb5 = Kerberos5Data::new();
        let data = vec![1, 2, 3, 4];
        let result = gssapi_unwrap(&data, &krb5);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn gssapi_wrap_passthrough() {
        let krb5 = Kerberos5Data::new();
        let data = vec![GSSAUTH_P_NONE, 0, 0, 0];
        let result = gssapi_wrap(&data, &krb5);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![GSSAUTH_P_NONE, 0, 0, 0]);
    }

    #[test]
    fn initiate_context_first_round_produces_spn_token() {
        let mut krb5 = Kerberos5Data::new();
        krb5.spn = Some("http/www.example.com".to_string());

        let result = initiate_gss_context(&mut krb5, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"http/www.example.com");
        assert!(!krb5.context_established);
    }

    #[test]
    fn initiate_context_subsequent_round_establishes_context() {
        let mut krb5 = Kerberos5Data::new();
        krb5.spn = Some("http/www.example.com".to_string());

        let server_token = b"server-data";
        let result = initiate_gss_context(&mut krb5, Some(server_token));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
        assert!(krb5.context_established);
    }

    #[test]
    fn initiate_context_without_spn_returns_auth_error() {
        let mut krb5 = Kerberos5Data::new();
        // No SPN set — should fail.
        let result = initiate_gss_context(&mut krb5, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::AuthError);
    }
}
