//! Basic/cleartext SASL authentication (PLAIN, LOGIN, EXTERNAL).
//!
//! Pure-Rust rewrite of `lib/vauth/cleartext.c` from curl 8.19.0-DEV.
//!
//! Implements three cleartext SASL authentication mechanisms used by
//! IMAP, SMTP, POP3, and LDAP protocols:
//!
//! - **PLAIN** (RFC 4616) — sends `authzid \0 authcid \0 passwd` in a single message
//! - **LOGIN** — sends username and password as raw bytes in separate rounds
//! - **EXTERNAL** — sends the authorization identity (delegates to LOGIN)
//!
//! # Wire Format
//!
//! PLAIN messages contain embedded NUL (`\0`) bytes, so the return type is
//! `Vec<u8>` rather than `String`. LOGIN and EXTERNAL simply pass through
//! the UTF-8 bytes unchanged.
//!
//! # Size Validation
//!
//! Each component of the PLAIN message is validated against
//! [`CURL_MAX_INPUT_LENGTH`] (8 MB). Exceeding this limit returns
//! [`CurlError::TooLarge`], matching the C `CURLE_TOO_LARGE` behavior.

use crate::error::CurlError;

/// Maximum allowed length for any single SASL authentication input field.
///
/// Matches the C `CURL_MAX_INPUT_LENGTH` constant (8 million bytes).
/// Any PLAIN message component (authzid, authcid, or passwd) that exceeds
/// this limit causes [`create_plain_message`] to return
/// [`CurlError::TooLarge`].
pub const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

/// Constructs a PLAIN SASL authentication message per RFC 4616.
///
/// The PLAIN message format is:
///
/// ```text
/// [authzid] NUL [authcid] NUL [passwd]
/// ```
///
/// where NUL is a single `0x00` byte. The `authzid` (authorization identity)
/// is optional; when `None`, it is treated as an empty string, matching the
/// C implementation's `authzid == NULL ? 0 : strlen(authzid)` logic.
///
/// # Arguments
///
/// * `authzid` — Optional authorization identity. `None` is equivalent to
///   an empty string.
/// * `authcid` — The authentication identity (username).
/// * `passwd`  — The password.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` containing the assembled PLAIN message with embedded NUL
///   bytes.
/// * `Err(CurlError::TooLarge)` if any single component exceeds
///   [`CURL_MAX_INPUT_LENGTH`].
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::auth::basic::{create_plain_message, CURL_MAX_INPUT_LENGTH};
/// // With authorization identity
/// let msg = create_plain_message(Some("admin"), "user", "secret").unwrap();
/// assert_eq!(msg, b"admin\0user\0secret");
///
/// // Without authorization identity (None treated as empty)
/// let msg = create_plain_message(None, "user", "secret").unwrap();
/// assert_eq!(msg, b"\0user\0secret");
/// ```
pub fn create_plain_message(
    authzid: Option<&str>,
    authcid: &str,
    passwd: &str,
) -> Result<Vec<u8>, CurlError> {
    // Resolve the authorization identity: None → empty string, matching the
    // C code: `authzid == NULL ? 0 : strlen(authzid)`.
    let authzid_bytes = authzid.unwrap_or("").as_bytes();
    let authcid_bytes = authcid.as_bytes();
    let passwd_bytes = passwd.as_bytes();

    // Validate each component against the maximum input length, matching the
    // C guard at cleartext.c line 62–64:
    //   if((zlen > CURL_MAX_INPUT_LENGTH) || (clen > CURL_MAX_INPUT_LENGTH) ||
    //      (plen > CURL_MAX_INPUT_LENGTH))
    //     return CURLE_TOO_LARGE;
    if authzid_bytes.len() > CURL_MAX_INPUT_LENGTH
        || authcid_bytes.len() > CURL_MAX_INPUT_LENGTH
        || passwd_bytes.len() > CURL_MAX_INPUT_LENGTH
    {
        return Err(CurlError::TooLarge);
    }

    // Total length = authzid + NUL + authcid + NUL + passwd
    // Matching C line 66: `len = zlen + clen + plen + 2;`
    let total_len = authzid_bytes
        .len()
        .wrapping_add(1)
        .wrapping_add(authcid_bytes.len())
        .wrapping_add(1)
        .wrapping_add(passwd_bytes.len());

    // Pre-allocate the exact capacity needed.
    let mut buf = Vec::with_capacity(total_len);

    // Build the PLAIN message: [authzid, 0x00, authcid, 0x00, passwd]
    // Matching C line 68:
    //   auth = curl_maprintf("%s%c%s%c%s", authzid ? authzid : "", '\0',
    //                        authcid, '\0', passwd);
    buf.extend_from_slice(authzid_bytes);
    buf.push(0x00);
    buf.extend_from_slice(authcid_bytes);
    buf.push(0x00);
    buf.extend_from_slice(passwd_bytes);

    Ok(buf)
}

/// Constructs a LOGIN SASL authentication message.
///
/// LOGIN authentication sends the username and password as raw bytes in
/// two separate rounds. This function simply returns the provided value
/// as its byte representation — no transformation is applied.
///
/// This matches the C `Curl_auth_create_login_message` function which
/// calls `Curl_bufref_set(out, value, strlen(value), NULL)`.
///
/// # Arguments
///
/// * `value` — The username or password to encode.
///
/// # Returns
///
/// The value as a `Vec<u8>` byte vector. This function cannot fail.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::auth::basic::create_login_message;
/// let msg = create_login_message("myuser");
/// assert_eq!(msg, b"myuser");
///
/// let msg = create_login_message("secret_password");
/// assert_eq!(msg, b"secret_password");
/// ```
pub fn create_login_message(value: &str) -> Vec<u8> {
    value.as_bytes().to_vec()
}

/// Constructs an EXTERNAL SASL authentication message.
///
/// The EXTERNAL mechanism uses the authorization identity from the TLS
/// client certificate or other external source. The message format is
/// identical to LOGIN — the user string is passed through as raw bytes.
///
/// This matches the C `Curl_auth_create_external_message` which simply
/// delegates to `Curl_auth_create_login_message(user, out)`.
///
/// # Arguments
///
/// * `user` — The authorization identity (username).
///
/// # Returns
///
/// The user string as a `Vec<u8>` byte vector. This function cannot fail.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::auth::basic::create_external_message;
/// let msg = create_external_message("admin");
/// assert_eq!(msg, b"admin");
/// ```
pub fn create_external_message(user: &str) -> Vec<u8> {
    // Identical to LOGIN — matching C behavior at cleartext.c line 110:
    //   Curl_auth_create_login_message(user, out);
    create_login_message(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PLAIN message tests
    // -----------------------------------------------------------------------

    #[test]
    fn plain_with_authzid() {
        let msg = create_plain_message(Some("admin"), "user", "secret").unwrap();
        assert_eq!(msg, b"admin\0user\0secret");
    }

    #[test]
    fn plain_without_authzid() {
        // None authzid should produce an empty prefix before the first NUL.
        let msg = create_plain_message(None, "user", "secret").unwrap();
        assert_eq!(msg, b"\0user\0secret");
    }

    #[test]
    fn plain_empty_authzid_string() {
        // Explicit empty string should behave identically to None.
        let msg = create_plain_message(Some(""), "user", "secret").unwrap();
        assert_eq!(msg, b"\0user\0secret");
    }

    #[test]
    fn plain_empty_all_fields() {
        let msg = create_plain_message(None, "", "").unwrap();
        // Two NUL bytes: \0 (authzid→empty) \0 (separator)
        assert_eq!(msg, b"\0\0");
    }

    #[test]
    fn plain_length_calculation() {
        // Verify total length = authzid_len + 1 + authcid_len + 1 + passwd_len
        let msg = create_plain_message(Some("az"), "ac", "pw").unwrap();
        assert_eq!(msg.len(), 2 + 1 + 2 + 1 + 2); // 8 bytes
        assert_eq!(msg, b"az\0ac\0pw");
    }

    #[test]
    fn plain_too_large_authzid() {
        let big = "x".repeat(CURL_MAX_INPUT_LENGTH + 1);
        let result = create_plain_message(Some(&big), "user", "pass");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::TooLarge);
    }

    #[test]
    fn plain_too_large_authcid() {
        let big = "y".repeat(CURL_MAX_INPUT_LENGTH + 1);
        let result = create_plain_message(None, &big, "pass");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::TooLarge);
    }

    #[test]
    fn plain_too_large_passwd() {
        let big = "z".repeat(CURL_MAX_INPUT_LENGTH + 1);
        let result = create_plain_message(None, "user", &big);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::TooLarge);
    }

    #[test]
    fn plain_exactly_max_length_ok() {
        // Exactly at the limit should succeed (not > but ==).
        let at_limit = "a".repeat(CURL_MAX_INPUT_LENGTH);
        let result = create_plain_message(None, &at_limit, "pw");
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg.len(), 0 + 1 + CURL_MAX_INPUT_LENGTH + 1 + 2);
    }

    #[test]
    fn plain_unicode_content() {
        // UTF-8 multi-byte characters should pass through byte-for-byte.
        let msg = create_plain_message(None, "ユーザ", "パスワード").unwrap();
        let expected: Vec<u8> = [
            b"".as_slice(),
            &[0x00],
            "ユーザ".as_bytes(),
            &[0x00],
            "パスワード".as_bytes(),
        ]
        .concat();
        assert_eq!(msg, expected);
    }

    // -----------------------------------------------------------------------
    // LOGIN message tests
    // -----------------------------------------------------------------------

    #[test]
    fn login_basic() {
        let msg = create_login_message("hello");
        assert_eq!(msg, b"hello");
    }

    #[test]
    fn login_empty() {
        let msg = create_login_message("");
        assert!(msg.is_empty());
    }

    #[test]
    fn login_preserves_bytes() {
        let msg = create_login_message("p@$$w0rd!");
        assert_eq!(msg, b"p@$$w0rd!");
    }

    // -----------------------------------------------------------------------
    // EXTERNAL message tests
    // -----------------------------------------------------------------------

    #[test]
    fn external_delegates_to_login() {
        let external = create_external_message("admin");
        let login = create_login_message("admin");
        assert_eq!(external, login);
    }

    #[test]
    fn external_empty() {
        let msg = create_external_message("");
        assert!(msg.is_empty());
    }

    // -----------------------------------------------------------------------
    // Constant value tests
    // -----------------------------------------------------------------------

    #[test]
    fn max_input_length_value() {
        assert_eq!(CURL_MAX_INPUT_LENGTH, 8_000_000);
    }
}
