//! HTTP Basic authentication and the SASL *cleartext* mechanisms
//! (PLAIN, LOGIN, EXTERNAL).
//!
//! This module is a language rewrite of two source-of-truth regions of curl
//! 8.19.0-DEV:
//!
//! * the HTTP Basic output path `http_output_basic()` in `lib/http.c`
//!   (L236-297), which builds the `Authorization: Basic …` (or the
//!   `Proxy-Authorization:` proxy variant) request header; and
//! * the SASL cleartext mechanisms in `lib/vauth/cleartext.c`
//!   (`Curl_auth_create_plain_message`, `Curl_auth_create_login_message`, and
//!   `Curl_auth_create_external_message`), used by the mail protocols (IMAP,
//!   POP3, SMTP) and by OpenLDAP.
//!
//! # Encoding responsibility (the key distinction)
//!
//! HTTP Basic transmits its credentials **base64-encoded inside the header
//! value**, so [`http_output_basic`] performs the base64 step itself and
//! returns a ready-to-send header line (a [`String`]).
//!
//! The three SASL functions are different: they return the **raw**, *un*-encoded
//! message bytes — including the embedded NUL (`0x00`) separators of the PLAIN
//! mechanism. The SASL engine (`crate::auth::sasl`) is responsible for the
//! base64 wrapping when it frames the mechanism response. Consequently these
//! functions return `Vec<u8>` rather than [`String`], because the PLAIN message
//! is not valid UTF-8 (it contains interior NUL bytes) and must never be lossily
//! re-encoded.
//!
//! # Parity constraints (AAP §0.6, §0.7)
//!
//! * **Wire parity** — the exact byte layout of every message produced here is a
//!   hard requirement; the `"Proxy-"` prefix logic and the trailing `\r\n` of the
//!   Basic header, and the `authzid \0 authcid \0 passwd` layout of the PLAIN
//!   message, are reproduced byte-for-byte.
//! * **Minimal Change Mandate** — only the behavior curl already implements is
//!   ported; no new mechanisms, defaults, or abstractions are introduced.
//! * **Memory safety** — this module is written entirely in safe Rust. The
//!   crate root forbids the escape-hatch keyword crate-wide, and a CI grep audit
//!   enforces that no such blocks appear anywhere in this subtree.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::error::Error;

/// Upper bound on the byte length of a single SASL credential component.
///
/// Transcribed from curl's `CURL_MAX_INPUT_LENGTH` (`lib/urldata.h:131`), whose
/// value is `8000000` (8 MB). curl uses it to reject absurdly large inputs
/// before they are concatenated into a mechanism message; exceeding it yields
/// `CURLE_TOO_LARGE`. The constant is defined locally because the crate exposes
/// no shared equivalent, and it is kept so the `CURLE_TOO_LARGE` behavior of
/// [`create_plain_message`] matches curl exactly.
const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

/// Build an HTTP `Authorization: Basic …` header line (or its `Proxy-` variant).
///
/// Port of `http_output_basic()` (`lib/http.c` L243-297). The cleartext
/// credential string `"{user}:{pwd}"` is assembled — treating an absent
/// `user`/`pwd` as the empty string, exactly as the C `user ? user : ""` /
/// `pwd ? pwd : ""` guards do — then base64-encoded (standard alphabet, with
/// `=` padding, matching curl's `curlx_base64_encode`). The returned string is
/// the **complete header line**, including the scheme word and the terminating
/// CRLF, so the caller writes it to the wire verbatim:
///
/// ```text
/// Authorization: Basic dXNlcjpwYXNz\r\n
/// Proxy-Authorization: Basic dXNlcjpwYXNz\r\n   (when `proxy` is true)
/// ```
///
/// # Parameters
///
/// * `user` — the username; `None` is treated as an empty username.
/// * `pwd` — the password; `None` is treated as an empty password.
/// * `proxy` — when `true`, emit the `Proxy-Authorization` header (the C
///   `data->state.aptr.proxyuserpwd` path) instead of `Authorization`.
///
/// # Errors
///
/// This function is infallible in practice — base64 encoding of an in-memory
/// buffer cannot fail — but returns [`crate::error::Result`] (via
/// `Result<String, Error>`) to preserve the fallible C signature and to remain
/// composable with the surrounding auth pipeline. The C `CURLE_OUT_OF_MEMORY`
/// path is intentionally dropped: Rust allocations abort the process on true
/// out-of-memory rather than surfacing a recoverable error.
///
/// # Feature gating
///
/// curl guards this behind `#ifndef CURL_DISABLE_BASIC_AUTH`. Basic auth is a
/// default-on capability here and no `basic-auth` Cargo feature exists, so the
/// function is always compiled (ungated), matching the stock curl 8.x build.
pub fn http_output_basic(
    user: Option<&str>,
    pwd: Option<&str>,
    proxy: bool,
) -> Result<String, Error> {
    // C: curl_maprintf("%s:%s", user ? user : "", pwd ? pwd : "").
    // A missing credential collapses to the empty string.
    let user = user.unwrap_or("");
    let pwd = pwd.unwrap_or("");
    let cleartext = format!("{user}:{pwd}");

    // C: curlx_base64_encode(...) — standard base64 alphabet, '=' padded.
    let encoded = STANDARD.encode(cleartext.as_bytes());

    // C: curl_maprintf("%sAuthorization: Basic %s\r\n", proxy ? "Proxy-" : "",
    // authorization). The scheme word and trailing CRLF are part of the wire
    // bytes and must be reproduced exactly.
    let prefix = if proxy { "Proxy-" } else { "" };
    Ok(format!("{prefix}Authorization: Basic {encoded}\r\n"))
}

/// Build the raw SASL **PLAIN** mechanism message (RFC 4616).
///
/// Port of `Curl_auth_create_plain_message()` (`lib/vauth/cleartext.c`
/// L50-74). The message is the concatenation
///
/// ```text
/// authzid  0x00  authcid  0x00  passwd
/// ```
///
/// where the authorization identity (`authzid`) is optional — when it is `None`
/// (the C `NULL`) or empty, the leading segment is empty but **the first NUL
/// separator is still present**. The total length is therefore
/// `authzid_len + authcid_len + passwd_len + 2`.
///
/// The returned bytes are **not** base64-encoded: they contain interior NUL
/// bytes and are handed to the SASL engine (`crate::auth::sasl`), which performs
/// the base64 wrapping when it frames the response. This is why the return type
/// is `Vec<u8>` and not [`String`].
///
/// # Errors
///
/// Returns [`Error::TooLarge`] (the analogue of curl's `CURLE_TOO_LARGE`) if the
/// byte length of `authzid`, `authcid`, or `passwd` individually exceeds
/// [`CURL_MAX_INPUT_LENGTH`]. The C `CURLE_OUT_OF_MEMORY` path is dropped, as
/// Rust `Vec` growth aborts on genuine allocation failure.
pub fn create_plain_message(
    authzid: Option<&str>,
    authcid: &str,
    passwd: &str,
) -> Result<Vec<u8>, Error> {
    // C: zlen = authzid ? strlen(authzid) : 0; clen/plen = strlen(...).
    let zlen = authzid.map_or(0, str::len);
    let clen = authcid.len();
    let plen = passwd.len();

    // C: reject any oversized component with CURLE_TOO_LARGE before building.
    if zlen > CURL_MAX_INPUT_LENGTH || clen > CURL_MAX_INPUT_LENGTH || plen > CURL_MAX_INPUT_LENGTH
    {
        return Err(Error::TooLarge);
    }

    // C: len = zlen + clen + plen + 2 (the two NUL separators). Pre-size the
    // buffer so no reallocation occurs while assembling the exact byte layout.
    let mut message = Vec::with_capacity(zlen + clen + plen + 2);
    if let Some(authzid) = authzid {
        message.extend_from_slice(authzid.as_bytes());
    }
    message.push(0); // first NUL: authzid | authcid separator
    message.extend_from_slice(authcid.as_bytes());
    message.push(0); // second NUL: authcid | passwd separator
    message.extend_from_slice(passwd.as_bytes());

    Ok(message)
}

/// Build the raw SASL **LOGIN** mechanism message.
///
/// Port of `Curl_auth_create_login_message()` (`lib/vauth/cleartext.c`
/// L89-92). The message is simply the raw bytes of `value` — there is no NUL
/// separator and no encoding (the C code is
/// `Curl_bufref_set(out, value, strlen(value), NULL)`).
///
/// The SASL LOGIN mechanism is a two-step exchange: the engine calls this once
/// for the **username** and once for the **password**, sending each raw value
/// (base64-wrapped by the engine) in sequence. This single function serves both
/// steps.
#[must_use]
pub fn create_login_message(value: &str) -> Vec<u8> {
    value.as_bytes().to_vec()
}

/// Build the raw SASL **EXTERNAL** mechanism message (RFC 4422 §A).
///
/// Port of `Curl_auth_create_external_message()` (`lib/vauth/cleartext.c`
/// L107-111). As the C comment notes, "this is the same formatting as the login
/// message", and the C function delegates to `Curl_auth_create_login_message`.
/// This port mirrors that exactly by delegating to [`create_login_message`],
/// returning the raw bytes of `user`.
#[must_use]
pub fn create_external_message(user: &str) -> Vec<u8> {
    // C delegates to Curl_auth_create_login_message; preserve that delegation.
    create_login_message(user)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CurlCode;

    // --- Phase A: http_output_basic ----------------------------------------

    #[test]
    fn http_basic_encodes_user_and_password() {
        // base64("user:pass") == "dXNlcjpwYXNz"; the full line carries the
        // scheme word and the trailing CRLF.
        let header = http_output_basic(Some("user"), Some("pass"), false).unwrap();
        assert_eq!(header, "Authorization: Basic dXNlcjpwYXNz\r\n");
    }

    #[test]
    fn http_basic_proxy_variant_prefixes_proxy() {
        // The only difference for a proxy is the leading "Proxy-" token.
        let header = http_output_basic(Some("user"), Some("pass"), true).unwrap();
        assert_eq!(header, "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n");
    }

    #[test]
    fn http_basic_missing_credentials_are_empty_strings() {
        // C treats NULL user/pwd as "": the cleartext is the single byte ":"
        // (0x3A), whose standard base64 is "Og==".
        let header = http_output_basic(None, None, false).unwrap();
        assert_eq!(header, "Authorization: Basic Og==\r\n");

        // The proxy variant of the empty-credential case.
        let proxied = http_output_basic(None, None, true).unwrap();
        assert_eq!(proxied, "Proxy-Authorization: Basic Og==\r\n");
    }

    #[test]
    fn http_basic_missing_password_only() {
        // user present, pwd absent -> cleartext "user:"; base64("user:").
        let header = http_output_basic(Some("user"), None, false).unwrap();
        let expected = format!("Authorization: Basic {}\r\n", STANDARD.encode(b"user:"));
        assert_eq!(header, expected);
    }

    #[test]
    fn http_basic_missing_username_only() {
        // user absent, pwd present -> cleartext ":pass"; base64(":pass").
        let header = http_output_basic(None, Some("pass"), false).unwrap();
        let expected = format!("Authorization: Basic {}\r\n", STANDARD.encode(b":pass"));
        assert_eq!(header, expected);
    }

    #[test]
    fn http_basic_output_is_round_trip_decodable() {
        // Decoding the base64 blob must recover the exact "user:pass" cleartext,
        // confirming standard-alphabet, padded encoding.
        let header = http_output_basic(Some("Aladdin"), Some("open sesame"), false).unwrap();
        let blob = header
            .strip_prefix("Authorization: Basic ")
            .and_then(|s| s.strip_suffix("\r\n"))
            .expect("well-formed header line");
        let decoded = STANDARD.decode(blob).unwrap();
        assert_eq!(decoded, b"Aladdin:open sesame");
    }

    // --- Phase B: create_plain_message -------------------------------------

    #[test]
    fn plain_message_without_authzid() {
        // create_plain_message(None, "user", "pass") ->
        // [0, 'u','s','e','r', 0, 'p','a','s','s'] (len 10 = 0 + 4 + 4 + 2).
        let msg = create_plain_message(None, "user", "pass").unwrap();
        assert_eq!(
            msg,
            vec![0, b'u', b's', b'e', b'r', 0, b'p', b'a', b's', b's']
        );
        assert_eq!(msg.len(), 10);
    }

    #[test]
    fn plain_message_with_authzid() {
        // authzid "admin" -> "admin\0user\0pass" (len 15 = 5 + 4 + 4 + 2).
        let msg = create_plain_message(Some("admin"), "user", "pass").unwrap();
        assert_eq!(msg, b"admin\0user\0pass");
        assert_eq!(msg.len(), 15);
    }

    #[test]
    fn plain_message_empty_authzid_still_emits_leading_nul() {
        // Some("") must behave like the empty leading segment: identical bytes
        // to the None case (the first NUL is always present).
        let with_empty = create_plain_message(Some(""), "user", "pass").unwrap();
        let with_none = create_plain_message(None, "user", "pass").unwrap();
        assert_eq!(with_empty, with_none);
        assert_eq!(with_empty[0], 0);
    }

    #[test]
    fn plain_message_all_empty_is_two_nuls() {
        // Every component empty -> just the two separators: [0, 0].
        let msg = create_plain_message(None, "", "").unwrap();
        assert_eq!(msg, vec![0, 0]);
        assert_eq!(msg.len(), 2);
    }

    #[test]
    fn plain_message_preserves_utf8_credential_bytes() {
        // Multi-byte UTF-8 credentials are copied byte-for-byte.
        let msg = create_plain_message(None, "usér", "pä55").unwrap();
        let mut expected = Vec::new();
        expected.push(0);
        expected.extend_from_slice("usér".as_bytes());
        expected.push(0);
        expected.extend_from_slice("pä55".as_bytes());
        assert_eq!(msg, expected);
    }

    #[test]
    fn plain_message_rejects_oversized_authcid() {
        // A component exceeding CURL_MAX_INPUT_LENGTH yields CURLE_TOO_LARGE.
        let huge = "a".repeat(CURL_MAX_INPUT_LENGTH + 1);
        let err = create_plain_message(None, &huge, "pass").unwrap_err();
        assert_eq!(err.code(), CurlCode::TooLarge);
        assert_eq!(err.code_i32(), 100);
    }

    #[test]
    fn plain_message_rejects_oversized_passwd() {
        let huge = "b".repeat(CURL_MAX_INPUT_LENGTH + 1);
        let err = create_plain_message(None, "user", &huge).unwrap_err();
        assert_eq!(err.code(), CurlCode::TooLarge);
    }

    #[test]
    fn plain_message_rejects_oversized_authzid() {
        let huge = "c".repeat(CURL_MAX_INPUT_LENGTH + 1);
        let err = create_plain_message(Some(&huge), "user", "pass").unwrap_err();
        assert_eq!(err.code(), CurlCode::TooLarge);
    }

    #[test]
    fn plain_message_accepts_component_at_exact_limit() {
        // Exactly CURL_MAX_INPUT_LENGTH is allowed (the guard is strictly `>`);
        // use empty companions to keep the allocation modest.
        let at_limit = "d".repeat(CURL_MAX_INPUT_LENGTH);
        let msg = create_plain_message(None, &at_limit, "").unwrap();
        assert_eq!(msg.len(), CURL_MAX_INPUT_LENGTH + 2);
        assert_eq!(msg[0], 0);
        assert_eq!(msg[CURL_MAX_INPUT_LENGTH + 1], 0);
    }

    // --- Phase C: create_login_message -------------------------------------

    #[test]
    fn login_message_is_raw_value_bytes() {
        assert_eq!(create_login_message("user"), b"user");
        assert_eq!(create_login_message("s3cr3t"), b"s3cr3t");
    }

    #[test]
    fn login_message_empty_is_empty() {
        assert_eq!(create_login_message(""), Vec::<u8>::new());
    }

    // --- Phase D: create_external_message ----------------------------------

    #[test]
    fn external_message_is_raw_user_bytes() {
        assert_eq!(create_external_message("id"), b"id");
    }

    #[test]
    fn external_message_matches_login_message() {
        // EXTERNAL uses the exact same formatting as LOGIN (C delegates).
        assert_eq!(
            create_external_message("someid"),
            create_login_message("someid")
        );
    }

    // --- Cross-cutting: message-structure / wire parity --------------------

    #[test]
    fn plain_message_contains_exactly_two_nul_separators() {
        // The message must contain exactly the two structural NULs when the
        // credentials themselves carry none.
        let msg = create_plain_message(Some("z"), "c", "p").unwrap();
        assert_eq!(msg.iter().filter(|&&b| b == 0).count(), 2);
    }
}
