//! Cleartext credential generation: HTTP **Basic** authentication headers and
//! the cleartext **SASL** mechanisms (`PLAIN`, `LOGIN`, `EXTERNAL`).
//!
//! This module is the memory-safe Rust home for every "credentials sent in the
//! clear" code path. It co-locates two upstream curl surfaces that share the
//! same trust model — the credential is transmitted without a
//! challenge/response exchange, relying on the transport (typically TLS) for
//! confidentiality:
//!
//! * **HTTP Basic** — [`http_basic_header`] reproduces `http_output_basic()`
//!   from `lib/http.c`. It base64-encodes `user:password` and frames it as a
//!   complete `Authorization` (or `Proxy-Authorization`) header line.
//! * **SASL PLAIN / LOGIN / EXTERNAL** — [`sasl_plain_message`],
//!   [`sasl_login_message`] and [`sasl_external_message`] reproduce the three
//!   builders in `lib/vauth/cleartext.c` (`Curl_auth_create_plain_message`,
//!   `Curl_auth_create_login_message`, `Curl_auth_create_external_message`).
//!   These feed the mail (IMAP/POP3/SMTP) SASL state machine.
//!
//! # Oracle, not transliteration
//!
//! The C sources are read as a **behavioral oracle** for the exact wire bytes;
//! the implementation here is idiomatic Rust, not a line-by-line port. The two
//! externally observable contracts that this module reproduces byte-for-byte
//! are:
//!
//! * the HTTP Basic header — `"{prefix}Authorization: Basic {base64}\r\n"`,
//!   where the base64 payload is exactly `base64("user:password")`; and
//! * the SASL PLAIN response — the NUL-separated triple
//!   `authzid \0 authcid \0 passwd`.
//!
//! Wire parity matters because curl's regression suite compares these bytes
//! directly.
//!
//! # Separation of concerns: who applies base64?
//!
//! HTTP Basic is **fully framed here** — [`http_basic_header`] returns a ready
//! header line with the base64 already applied, mirroring `http_output_basic()`.
//!
//! The SASL builders, by contrast, return **raw** bytes. In curl the SASL state
//! machine (the future `sasl.rs`) applies base64 framing afterwards, honoring
//! the `SASL_FLAG_BASE64` flag and the `"="` empty-response convention.
//! Reproducing that split keeps the base64 decision with the caller, exactly as
//! upstream does — so these functions deliberately do **not** base64-encode
//! their output.
//!
//! # Memory safety
//!
//! This module contains **zero `unsafe`** and compiles cleanly under the
//! `#![forbid(unsafe_code)]` declared at the `curl-rs-lib` crate root
//! (AAP §0.7.1). Every value is an owned `String` / `Vec<u8>`; there is no
//! manual allocation, no raw pointers, and no C linkage.

use crate::error::{CurlError, Result};
use crate::util::base64::base64_encode;

/// Maximum length, in bytes, accepted for any single SASL credential field.
///
/// Parity with curl's `CURL_MAX_INPUT_LENGTH` macro (`lib/urldata.h`, value
/// `8000000`). `Curl_auth_create_plain_message()` rejects an `authzid`,
/// `authcid` or `passwd` whose length **exceeds** this bound with
/// `CURLE_TOO_LARGE`; [`sasl_plain_message`] applies the identical cap.
///
/// The comparison is strictly greater-than (curl's
/// `len > CURL_MAX_INPUT_LENGTH`), so a field of *exactly* this length is still
/// accepted.
///
/// This is a different constant from the base64 input cap
/// (`crate::util::base64::CURL_MAX_BASE64_INPUT`, `16000000`); the two guard
/// different stages and must not be conflated.
pub const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

/// Build an HTTP **Basic** authentication header line.
///
/// Reproduces `http_output_basic()` from `lib/http.c`. The credential string
/// `"{user}:{password}"` is base64-encoded and framed as a complete header
/// line, terminated with `\r\n`, for example:
///
/// ```text
/// Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n
/// ```
///
/// When `proxy` is `true` the header name is prefixed with `Proxy-`, producing
/// a `Proxy-Authorization` line for authenticating to an HTTP proxy; otherwise
/// the prefix is empty.
///
/// # Credentials are per-transfer
///
/// curl deliberately pulls Basic credentials from the *transfer* state, not the
/// connection: `aptr.user` / `aptr.passwd` for the origin host and
/// `aptr.proxyuser` / `aptr.proxypasswd` for the proxy. This function therefore
/// takes the user/password as parameters and leaves the choice of which pair to
/// supply to the HTTP engine. An absent credential is represented by the empty
/// string (curl substitutes `""` for a `NULL` `user` / `pwd`), so
/// `http_basic_header("", "", false)` encodes the single byte `":"`.
///
/// Note that, exactly as in curl, the credentials are joined with the *first*
/// `:` only — any `:` inside `password` is included verbatim, matching
/// RFC 7617's "the user-id must not contain a colon" guidance without enforcing
/// it.
///
/// # Errors
///
/// * [`CurlError::TooLarge`] — propagated from [`base64_encode`] if the
///   `user:password` string is implausibly large (curl's `if(result)` branch).
/// * [`CurlError::RemoteAccessDenied`] — if base64 produces an empty payload,
///   matching curl's `!authorization` branch (`CURLE_REMOTE_ACCESS_DENIED`).
///   This is unreachable in practice — the credential string always contains at
///   least the `":"` separator, so it always encodes to a non-empty value — but
///   the check is retained for exact behavioral parity.
///
/// # Examples
///
/// ```ignore
/// // RFC 7617 canonical example.
/// let h = http_basic_header("Aladdin", "open sesame", false)?;
/// assert_eq!(h, "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n");
/// ```
pub fn http_basic_header(user: &str, password: &str, proxy: bool) -> Result<String> {
    // curl: `out = curl_maprintf("%s:%s", user ? user : "", pwd ? pwd : "")`.
    // In Rust an absent credential is already the empty string, so a plain
    // colon-join reproduces the cleartext exactly — including the degenerate
    // ":" case when both are empty.
    let cleartext = format!("{user}:{password}");

    // curl: `curlx_base64_encode(out, strlen(out), &authorization, &size)`.
    // Any encoder error (e.g. CURLE_TOO_LARGE) propagates here, mirroring
    // curl's `if(result) goto fail`.
    let encoded = base64_encode(cleartext.as_bytes())?;

    // curl: `if(!authorization) { result = CURLE_REMOTE_ACCESS_DENIED; ... }`.
    // Unreachable in practice (the cleartext always contains the ":" byte), but
    // kept for byte-for-byte behavioral parity with the oracle.
    if encoded.is_empty() {
        return Err(CurlError::RemoteAccessDenied);
    }

    // `base64_encode` is contractually ASCII base64 *text*, so this conversion
    // never fails; the impossible non-UTF-8 case is mapped to the same
    // "could not build credentials" code rather than panicking — preserving the
    // crate-wide no-panic, no-`unsafe` discipline.
    let authorization = String::from_utf8(encoded).map_err(|_| CurlError::RemoteAccessDenied)?;

    // curl: `curl_maprintf("%sAuthorization: Basic %s\r\n",
    //                       proxy ? "Proxy-" : "", authorization)`.
    let prefix = if proxy { "Proxy-" } else { "" };
    Ok(format!("{prefix}Authorization: Basic {authorization}\r\n"))
}

/// Build the raw **SASL PLAIN** message (RFC 4616).
///
/// Reproduces `Curl_auth_create_plain_message()` from `lib/vauth/cleartext.c`.
/// The PLAIN response is the NUL-separated triple
///
/// ```text
/// authzid \0 authcid \0 passwd
/// ```
///
/// i.e. the bytes of `authzid`, a `0x00` separator, the bytes of `authcid`,
/// another `0x00` separator, and the bytes of `passwd`. The total length is
/// `authzid.len() + authcid.len() + passwd.len() + 2`. An empty `authzid` — the
/// common case, where the authorization identity defaults to the authentication
/// identity — simply contributes zero leading bytes, so the message begins with
/// a `0x00`.
///
/// # Raw output — caller applies base64
///
/// The returned bytes are **not** base64-encoded. As in curl, the SASL state
/// machine applies base64 framing afterwards (honoring `SASL_FLAG_BASE64`);
/// keeping that step with the caller preserves the upstream separation of
/// concerns. See the [module documentation](self).
///
/// # Errors
///
/// Returns [`CurlError::TooLarge`] (curl's `CURLE_TOO_LARGE`) if any one of the
/// three fields exceeds [`CURL_MAX_INPUT_LENGTH`] bytes.
///
/// # Examples
///
/// ```ignore
/// // Empty authorization identity, username "user", password "pass".
/// assert_eq!(sasl_plain_message("", "user", "pass")?, b"\0user\0pass");
/// ```
pub fn sasl_plain_message(authzid: &str, authcid: &str, passwd: &str) -> Result<Vec<u8>> {
    let zlen = authzid.len();
    let clen = authcid.len();
    let plen = passwd.len();

    // curl: reject any field strictly larger than CURL_MAX_INPUT_LENGTH.
    if zlen > CURL_MAX_INPUT_LENGTH || clen > CURL_MAX_INPUT_LENGTH || plen > CURL_MAX_INPUT_LENGTH
    {
        return Err(CurlError::TooLarge);
    }

    // curl: `len = zlen + clen + plen + 2` (the two NUL separators).
    let mut message = Vec::with_capacity(zlen + clen + plen + 2);
    message.extend_from_slice(authzid.as_bytes());
    message.push(0);
    message.extend_from_slice(authcid.as_bytes());
    message.push(0);
    message.extend_from_slice(passwd.as_bytes());

    debug_assert_eq!(message.len(), zlen + clen + plen + 2);
    Ok(message)
}

/// Build a raw **SASL LOGIN** message fragment.
///
/// Reproduces `Curl_auth_create_login_message()` from `lib/vauth/cleartext.c`,
/// which is a verbatim copy of the input value (`Curl_bufref_set(out, value,
/// strlen(value), NULL)`). The LOGIN mechanism transmits the username and the
/// password in **separate** steps, so each call carries exactly one field with
/// no framing or separators.
///
/// As with [`sasl_plain_message`], the bytes are returned **raw**; the SASL
/// state machine applies base64 afterwards.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(sasl_login_message("username"), b"username");
/// ```
#[must_use]
pub fn sasl_login_message(value: &str) -> Vec<u8> {
    value.as_bytes().to_vec()
}

/// Build a raw **SASL EXTERNAL** message (RFC 4422 Appendix A).
///
/// Reproduces `Curl_auth_create_external_message()` from
/// `lib/vauth/cleartext.c`, which the oracle defines as *"the same formatting as
/// the login message"* — a verbatim copy of the authorization identity.
/// EXTERNAL derives the actual identity from the established TLS client
/// certificate, so `authzid` is frequently empty (yielding an empty message,
/// which the caller base64-encodes to the `"="` empty response).
///
/// The bytes are returned **raw**; the SASL state machine applies base64
/// afterwards.
///
/// # Examples
///
/// ```ignore
/// // EXTERNAL commonly sends an empty authorization identity.
/// assert!(sasl_external_message("").is_empty());
/// ```
#[must_use]
pub fn sasl_external_message(authzid: &str) -> Vec<u8> {
    // cleartext.c: "This is the same formatting as the login message".
    sasl_login_message(authzid)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- HTTP Basic header (Phase A) ------------------------------------

    /// RFC 7617 §2 worked example: user "Aladdin", password "open sesame".
    #[test]
    fn basic_header_rfc7617_canonical_example() {
        let header = http_basic_header("Aladdin", "open sesame", false).unwrap();
        assert_eq!(
            header,
            "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"
        );
    }

    /// The proxy variant uses the exact same payload but a `Proxy-` prefix.
    #[test]
    fn basic_header_proxy_variant_prefixes_proxy() {
        let header = http_basic_header("Aladdin", "open sesame", true).unwrap();
        assert_eq!(
            header,
            "Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"
        );
    }

    /// Both fields empty -> cleartext is just ":" -> base64 "Og==".
    #[test]
    fn basic_header_empty_user_and_password_encodes_colon() {
        let header = http_basic_header("", "", false).unwrap();
        assert_eq!(header, "Authorization: Basic Og==\r\n");
        // And the proxy form of the same.
        let proxy = http_basic_header("", "", true).unwrap();
        assert_eq!(proxy, "Proxy-Authorization: Basic Og==\r\n");
    }

    /// Empty user only -> ":pass".
    #[test]
    fn basic_header_empty_user_only() {
        let expected_b64 = String::from_utf8(base64_encode(b":pass").unwrap()).unwrap();
        let header = http_basic_header("", "pass", false).unwrap();
        assert_eq!(header, format!("Authorization: Basic {expected_b64}\r\n"));
    }

    /// Empty password only -> "user:".
    #[test]
    fn basic_header_empty_password_only() {
        let expected_b64 = String::from_utf8(base64_encode(b"user:").unwrap()).unwrap();
        let header = http_basic_header("user", "", false).unwrap();
        assert_eq!(header, format!("Authorization: Basic {expected_b64}\r\n"));
    }

    /// The payload must equal `base64("user:password")` exactly, including any
    /// `:` embedded in the password (curl joins on the first colon only).
    #[test]
    fn basic_header_payload_is_base64_of_user_colon_password() {
        let user = "user";
        let password = "p@ss:word";
        let header = http_basic_header(user, password, false).unwrap();
        let expected_b64 =
            String::from_utf8(base64_encode(format!("{user}:{password}").as_bytes()).unwrap())
                .unwrap();
        assert_eq!(header, format!("Authorization: Basic {expected_b64}\r\n"));
    }

    /// The header line is always CRLF-terminated and correctly named.
    #[test]
    fn basic_header_is_crlf_terminated_and_named() {
        let header = http_basic_header("a", "b", false).unwrap();
        assert!(header.ends_with("\r\n"));
        assert!(header.starts_with("Authorization: Basic "));
        assert!(!header.starts_with("Proxy-"));

        let proxy = http_basic_header("a", "b", true).unwrap();
        assert!(proxy.starts_with("Proxy-Authorization: Basic "));
        assert!(proxy.ends_with("\r\n"));
    }

    // ---- SASL PLAIN (Phase B) -------------------------------------------

    /// Canonical case: empty authzid, "user", "pass" -> `\0user\0pass`.
    #[test]
    fn plain_message_empty_authzid() {
        let msg = sasl_plain_message("", "user", "pass").unwrap();
        assert_eq!(msg, b"\0user\0pass");
    }

    /// With a non-empty authorization identity.
    #[test]
    fn plain_message_with_authzid() {
        let msg = sasl_plain_message("authz", "user", "pass").unwrap();
        assert_eq!(msg, b"authz\0user\0pass");
    }

    /// All three fields empty collapses to exactly the two separators.
    #[test]
    fn plain_message_all_empty_is_two_nuls() {
        let msg = sasl_plain_message("", "", "").unwrap();
        assert_eq!(msg, b"\0\0");
    }

    /// Total length is `zlen + clen + plen + 2`, and the two `0x00` separators
    /// sit at the field boundaries (parity with curl's `len` computation).
    #[test]
    fn plain_message_length_and_nul_positions() {
        let (z, c, p) = ("zz", "user", "secret");
        let msg = sasl_plain_message(z, c, p).unwrap();
        assert_eq!(msg.len(), z.len() + c.len() + p.len() + 2);
        assert_eq!(msg[z.len()], 0u8);
        assert_eq!(msg[z.len() + 1 + c.len()], 0u8);
        // Exactly two NUL bytes overall (the fields here contain none).
        assert_eq!(msg.iter().filter(|&&b| b == 0).count(), 2);
    }

    /// A field one byte beyond the cap is rejected with `CURLE_TOO_LARGE`,
    /// regardless of which of the three fields overflows.
    #[test]
    fn plain_message_over_long_field_is_too_large() {
        let too_long = "a".repeat(CURL_MAX_INPUT_LENGTH + 1);

        assert_eq!(
            sasl_plain_message(&too_long, "user", "pass"),
            Err(CurlError::TooLarge)
        );
        assert_eq!(
            sasl_plain_message("", &too_long, "pass"),
            Err(CurlError::TooLarge)
        );
        assert_eq!(
            sasl_plain_message("", "user", &too_long),
            Err(CurlError::TooLarge)
        );
    }

    /// A field of *exactly* the cap length is accepted (the bound is strictly
    /// greater-than, matching curl's `len > CURL_MAX_INPUT_LENGTH`).
    #[test]
    fn plain_message_field_at_exact_cap_is_accepted() {
        let at_cap = "a".repeat(CURL_MAX_INPUT_LENGTH);
        let msg = sasl_plain_message("", &at_cap, "").unwrap();
        assert_eq!(msg.len(), CURL_MAX_INPUT_LENGTH + 2);
        assert_eq!(msg[0], 0u8);
        assert_eq!(msg[CURL_MAX_INPUT_LENGTH + 1], 0u8);
    }

    // ---- SASL LOGIN + EXTERNAL (Phase C) --------------------------------

    /// LOGIN is a verbatim passthrough of the single field.
    #[test]
    fn login_message_is_raw_passthrough() {
        assert_eq!(sasl_login_message("username"), b"username");
        assert_eq!(sasl_login_message("s3cr3t"), b"s3cr3t");
    }

    /// An empty LOGIN field yields an empty message.
    #[test]
    fn login_message_empty_is_empty() {
        assert!(sasl_login_message("").is_empty());
    }

    /// Multi-byte UTF-8 is preserved verbatim (no transformation).
    #[test]
    fn login_message_preserves_utf8_bytes() {
        let value = "naïve-Ωmega";
        assert_eq!(sasl_login_message(value), value.as_bytes());
    }

    /// EXTERNAL uses "the same formatting as the login message" (cleartext.c).
    #[test]
    fn external_message_matches_login_message() {
        for v in ["", "alice", "id@example.com"] {
            assert_eq!(sasl_external_message(v), sasl_login_message(v));
        }
    }

    /// The common EXTERNAL case: an empty authorization identity (the real
    /// identity comes from the TLS client certificate) yields an empty message.
    #[test]
    fn external_message_empty_authzid_is_empty() {
        assert!(sasl_external_message("").is_empty());
    }

    /// A non-empty EXTERNAL identity is passed through verbatim.
    #[test]
    fn external_message_non_empty_passthrough() {
        assert_eq!(sasl_external_message("alice"), b"alice");
    }
}
