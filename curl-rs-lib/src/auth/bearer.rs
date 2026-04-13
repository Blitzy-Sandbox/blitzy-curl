//! OAuth2 Bearer token authentication (RFC 6749, XOAUTH2)
//!
//! Pure-Rust rewrite of `lib/vauth/oauth2.c`. Provides SASL message
//! construction for the two OAuth 2.0 SASL mechanisms used by IMAP, SMTP,
//! POP3, and LDAP protocols:
//!
//! * **OAUTHBEARER** (RFC 7628) — [`create_oauth_bearer_message`]
//! * **XOAUTH2** (Google-specific) — [`create_xoauth_bearer_message`]
//!
//! Both functions produce strings containing embedded ASCII SOH (`\x01`)
//! separators that are byte-for-byte compatible with curl 8.x output.

use std::fmt::Write;

use crate::error::CurlError;

/// Construct an OAuth 2.0 Bearer SASL message (OAUTHBEARER, RFC 7628).
///
/// The produced string uses the GS2 header format with embedded SOH (`\x01`)
/// control characters as field separators, matching the C implementation in
/// `lib/vauth/oauth2.c` lines 50–70.
///
/// # Format
///
/// ```text
/// n,a=<user>,\x01host=<host>\x01port=<port>\x01auth=Bearer <bearer>\x01\x01
/// ```
///
/// When `port` is `0` or `80`, the `port=` field is omitted entirely (matching
/// the C conditional at line 59).
///
/// # Parameters
///
/// * `user`   — The username (authorization identity).
/// * `host`   — The hostname of the target server.
/// * `port`   — The server port. Ports `0` and `80` suppress the `port=` field.
/// * `bearer` — The OAuth 2.0 Bearer access token.
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] if internal string formatting fails,
/// mirroring the `CURLE_OUT_OF_MEMORY` return in the C implementation when
/// `curl_maprintf` returns `NULL`.
///
/// # Examples
///
/// ```ignore
/// let msg = create_oauth_bearer_message("user", "imap.example.com", 993, "ya29.token")?;
/// assert!(msg.starts_with("n,a=user,\x01"));
/// assert!(msg.contains("port=993\x01"));
/// ```
pub fn create_oauth_bearer_message(
    user: &str,
    host: &str,
    port: u16,
    bearer: &str,
) -> Result<String, CurlError> {
    // Pre-compute an approximate capacity to reduce reallocations.
    // The fixed overhead is roughly: "n,a=" + ",\x01host=" + "\x01auth=Bearer " + "\x01\x01"
    // plus optional "port=<port>\x01".
    let capacity = 4 + user.len() + 7 + host.len() + 15 + bearer.len() + 2 + 12;
    let mut message = String::with_capacity(capacity);

    // Build the OAUTHBEARER SASL message.
    // The C implementation (oauth2.c lines 59-64) omits the port= field when
    // port is 0 or 80, matching standard HTTP default behaviour.
    if port == 0 || port == 80 {
        write!(
            &mut message,
            "n,a={},\x01host={}\x01auth=Bearer {}\x01\x01",
            user, host, bearer
        )
        .map_err(|_| CurlError::OutOfMemory)?;
    } else {
        write!(
            &mut message,
            "n,a={},\x01host={}\x01port={}\x01auth=Bearer {}\x01\x01",
            user, host, port, bearer
        )
        .map_err(|_| CurlError::OutOfMemory)?;
    }

    Ok(message)
}

/// Construct an XOAUTH2 SASL authentication message.
///
/// The XOAUTH2 mechanism is a Google-specific extension that uses a simpler
/// format than OAUTHBEARER. The produced string uses embedded SOH (`\x01`)
/// control characters as field separators, matching the C implementation at
/// `lib/vauth/oauth2.c` line 91.
///
/// # Format
///
/// ```text
/// user=<user>\x01auth=Bearer <bearer>\x01\x01
/// ```
///
/// # Parameters
///
/// * `user`   — The username.
/// * `bearer` — The OAuth 2.0 Bearer access token.
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] if internal string formatting fails,
/// mirroring the `CURLE_OUT_OF_MEMORY` return in the C implementation when
/// `curl_maprintf` returns `NULL`.
///
/// # Examples
///
/// ```ignore
/// let msg = create_xoauth_bearer_message("user@gmail.com", "ya29.token")?;
/// assert_eq!(msg, "user=user@gmail.com\x01auth=Bearer ya29.token\x01\x01");
/// ```
pub fn create_xoauth_bearer_message(
    user: &str,
    bearer: &str,
) -> Result<String, CurlError> {
    // Pre-compute approximate capacity: "user=" + "\x01auth=Bearer " + "\x01\x01"
    let capacity = 5 + user.len() + 14 + bearer.len() + 2;
    let mut message = String::with_capacity(capacity);

    // Build the XOAUTH2 SASL message (oauth2.c line 91).
    write!(
        &mut message,
        "user={}\x01auth=Bearer {}\x01\x01",
        user, bearer
    )
    .map_err(|_| CurlError::OutOfMemory)?;

    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // create_oauth_bearer_message tests
    // ------------------------------------------------------------------

    #[test]
    fn oauth_bearer_with_standard_port() {
        let msg = create_oauth_bearer_message("user", "host.example.com", 993, "my_token")
            .expect("should succeed");
        assert_eq!(
            msg,
            "n,a=user,\x01host=host.example.com\x01port=993\x01auth=Bearer my_token\x01\x01"
        );
    }

    #[test]
    fn oauth_bearer_port_zero_omits_port() {
        let msg = create_oauth_bearer_message("user", "host.example.com", 0, "tok")
            .expect("should succeed");
        assert_eq!(
            msg,
            "n,a=user,\x01host=host.example.com\x01auth=Bearer tok\x01\x01"
        );
        // Ensure port= field is absent.
        assert!(!msg.contains("port="));
    }

    #[test]
    fn oauth_bearer_port_80_omits_port() {
        let msg = create_oauth_bearer_message("user", "host.example.com", 80, "tok")
            .expect("should succeed");
        assert_eq!(
            msg,
            "n,a=user,\x01host=host.example.com\x01auth=Bearer tok\x01\x01"
        );
        assert!(!msg.contains("port="));
    }

    #[test]
    fn oauth_bearer_port_443() {
        let msg = create_oauth_bearer_message("admin", "mail.example.com", 443, "abc123")
            .expect("should succeed");
        assert_eq!(
            msg,
            "n,a=admin,\x01host=mail.example.com\x01port=443\x01auth=Bearer abc123\x01\x01"
        );
    }

    #[test]
    fn oauth_bearer_soh_bytes() {
        // Verify that the separator is truly 0x01 (SOH), not a newline or space.
        let msg = create_oauth_bearer_message("u", "h", 1, "t")
            .expect("should succeed");
        let bytes = msg.as_bytes();
        // Count SOH bytes — with a non-default port there are exactly 5:
        //   ",\x01" + "h\x01" + "1\x01" + "t\x01" + "\x01"
        let soh_count = bytes.iter().filter(|&&b| b == 0x01).count();
        assert_eq!(soh_count, 5, "expected 5 SOH bytes, found {soh_count}");
    }

    #[test]
    fn oauth_bearer_empty_user_and_host() {
        let msg = create_oauth_bearer_message("", "", 0, "token")
            .expect("should succeed");
        assert_eq!(msg, "n,a=,\x01host=\x01auth=Bearer token\x01\x01");
    }

    // ------------------------------------------------------------------
    // create_xoauth_bearer_message tests
    // ------------------------------------------------------------------

    #[test]
    fn xoauth_bearer_basic() {
        let msg = create_xoauth_bearer_message("user@gmail.com", "ya29.access_token")
            .expect("should succeed");
        assert_eq!(
            msg,
            "user=user@gmail.com\x01auth=Bearer ya29.access_token\x01\x01"
        );
    }

    #[test]
    fn xoauth_bearer_soh_bytes() {
        // Verify that the separator is truly 0x01 (SOH).
        let msg = create_xoauth_bearer_message("u", "t")
            .expect("should succeed");
        let bytes = msg.as_bytes();
        let soh_count = bytes.iter().filter(|&&b| b == 0x01).count();
        assert_eq!(soh_count, 3, "expected 3 SOH bytes, found {soh_count}");
    }

    #[test]
    fn xoauth_bearer_empty_user() {
        let msg = create_xoauth_bearer_message("", "tok")
            .expect("should succeed");
        assert_eq!(msg, "user=\x01auth=Bearer tok\x01\x01");
    }

    #[test]
    fn xoauth_bearer_empty_bearer() {
        let msg = create_xoauth_bearer_message("user", "")
            .expect("should succeed");
        assert_eq!(msg, "user=user\x01auth=Bearer \x01\x01");
    }

    #[test]
    fn xoauth_bearer_special_characters() {
        let msg = create_xoauth_bearer_message("user@example.com", "tok/with+special=chars")
            .expect("should succeed");
        assert_eq!(
            msg,
            "user=user@example.com\x01auth=Bearer tok/with+special=chars\x01\x01"
        );
    }
}
