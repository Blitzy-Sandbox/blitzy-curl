//! OAuth 2.0 bearer-token message framing for SASL (`OAUTHBEARER` and `XOAUTH2`).
//!
//! Language rewrite of curl 8.19.0-DEV `lib/vauth/oauth2.c` (98 lines). That C
//! translation unit contains exactly two functions, and this module is a
//! faithful 1:1 port of both:
//!
//! * [`create_oauth_bearer_message`] ← `Curl_auth_create_oauth_bearer_message`
//!   (`lib/vauth/oauth2.c` L50-70) — the SASL `OAUTHBEARER` mechanism defined by
//!   RFC 7628, built on a GS2 header (`n,a=<user>,`).
//! * [`create_xoauth_bearer_message`] ← `Curl_auth_create_xoauth_bearer_message`
//!   (`lib/vauth/oauth2.c` L86-97) — Google's older, non-standard `XOAUTH2`
//!   framing.
//!
//! # Wire parity (mandatory)
//!
//! Both messages are delimited by the SOH control byte `0x01` (written `\u{1}`
//! here; the C source writes it as the octal escape `\1`). The field order and
//! the exact number of separators — including the **two** trailing `0x01 0x01`
//! bytes that close each message — form a byte-for-byte contract with curl 8.x
//! and must never change. To keep those control bytes unambiguous, both
//! functions return the **raw** message as a [`Vec<u8>`].
//!
//! # What this module deliberately does *not* do
//!
//! * **No base64.** The C callers hand the raw string to the SASL engine, which
//!   base64-encodes it immediately before transmission; that responsibility
//!   lives in `crate::auth::sasl`, not here.
//! * **No error type.** The only failure the C code could report was
//!   `CURLE_OUT_OF_MEMORY` from `curl_maprintf`. In Rust, building a `String`
//!   does not surface a recoverable allocation error, so that path vanishes and
//!   both functions return infallibly (no `Result`).
//! * **No feature gate.** The C file compiles both functions inside a shared
//!   `#if !CURL_DISABLE_IMAP || !CURL_DISABLE_SMTP || !CURL_DISABLE_POP3 ||
//!   (!CURL_DISABLE_LDAP && USE_OPENLDAP)` block. Those protocols are all
//!   default-on in this rewrite, so the functions are always compiled (Minimal
//!   Change Mandate: no gate is added).
//!
//! This module is pure, allocation-only, safe Rust: it performs no I/O and no
//! cryptography, and it contains none of the memory escape-hatch blocks that the
//! crate root forbids crate-wide (a CI grep audit enforces their absence
//! throughout this subtree, so this file avoids that keyword even in prose).

/// Generate a SASL `OAUTHBEARER` (RFC 7628) client message, ready for the SASL
/// engine to base64-encode and send.
///
/// Port of `Curl_auth_create_oauth_bearer_message` (`lib/vauth/oauth2.c`
/// L50-70). The returned bytes reproduce curl's two `curl_maprintf` format
/// strings exactly, selected by the port:
///
/// * `port == 0 || port == 80` — the default-port form, which omits the explicit
///   `port` field:
///
///   ```text
///   n,a=<user>,<0x01>host=<host><0x01>auth=Bearer <bearer><0x01><0x01>
///   ```
///
/// * any other port — the same form with a `port=<port><0x01>` field inserted
///   immediately **before** `auth=`:
///
///   ```text
///   n,a=<user>,<0x01>host=<host><0x01>port=<port><0x01>auth=Bearer <bearer><0x01><0x01>
///   ```
///
/// `<0x01>` denotes the SOH separator byte. The `port` parameter is [`i64`] to
/// mirror the C `long port` argument (formatted with `%ld`).
///
/// # Parameters
///
/// * `user` — the username (the GS2 `a=` authorization identity).
/// * `host` — the target hostname.
/// * `port` — the target port; both `0` and `80` select the default-port form.
/// * `bearer` — the OAuth 2.0 bearer token.
///
/// # Returns
///
/// The raw, **un-base64-encoded** message bytes. Base64 encoding is applied
/// later by the SASL engine (`crate::auth::sasl`).
#[must_use]
pub fn create_oauth_bearer_message(user: &str, host: &str, port: i64, bearer: &str) -> Vec<u8> {
    // Mirror the two `curl_maprintf` branches from the C source verbatim. `\u{1}`
    // is the SOH (0x01) separator that the C code writes as the octal escape `\1`.
    let message = if port == 0 || port == 80 {
        // Default port (80) or unset (0): no explicit `port` field is emitted.
        format!("n,a={user},\u{1}host={host}\u{1}auth=Bearer {bearer}\u{1}\u{1}")
    } else {
        // Any non-default port inserts `port=<port>\u{1}` immediately before
        // `auth=` — the single detail that distinguishes this branch.
        format!("n,a={user},\u{1}host={host}\u{1}port={port}\u{1}auth=Bearer {bearer}\u{1}\u{1}")
    };

    // Return raw bytes so the SOH separators stay unambiguous; the SASL engine
    // base64-encodes this later. `String` is UTF-8 and `0x01` is a valid
    // single-byte code point, so `into_bytes` preserves the framing exactly.
    message.into_bytes()
}

/// Generate a Google `XOAUTH2` client message, ready for the SASL engine to
/// base64-encode and send.
///
/// Port of `Curl_auth_create_xoauth_bearer_message` (`lib/vauth/oauth2.c`
/// L86-97). Reproduces the single C `curl_maprintf` format string exactly:
///
/// ```text
/// user=<user><0x01>auth=Bearer <bearer><0x01><0x01>
/// ```
///
/// `<0x01>` denotes the SOH separator byte. Unlike
/// [`create_oauth_bearer_message`], the `XOAUTH2` framing carries neither a GS2
/// header nor `host`/`port` fields.
///
/// # Parameters
///
/// * `user` — the username.
/// * `bearer` — the OAuth 2.0 bearer token.
///
/// # Returns
///
/// The raw, **un-base64-encoded** message bytes; base64 is applied later by the
/// SASL engine (`crate::auth::sasl`).
#[must_use]
pub fn create_xoauth_bearer_message(user: &str, bearer: &str) -> Vec<u8> {
    // C: curl_maprintf("user=%s\1auth=Bearer %s\1\1", user, bearer). `\u{1}` is
    // the SOH (0x01) separator; the result is returned raw (base64 happens in
    // the SASL engine, not here).
    format!("user={user}\u{1}auth=Bearer {bearer}\u{1}\u{1}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SOH (Start of Heading) — the `0x01` separator byte the framing uses.
    const SOH: u8 = 0x01;

    // --- create_oauth_bearer_message: default-port form --------------------

    #[test]
    fn oauth_bearer_port_zero_matches_curl() {
        // The exact validation vector for the `port == 0` branch (agent prompt).
        assert_eq!(
            create_oauth_bearer_message("user@example.com", "mail.example.com", 0, "tok"),
            b"n,a=user@example.com,\x01host=mail.example.com\x01auth=Bearer tok\x01\x01".to_vec(),
        );
    }

    #[test]
    fn oauth_bearer_port_80_uses_default_form() {
        // Port 80 takes the same branch as port 0: no `port=` field is emitted.
        let msg = create_oauth_bearer_message("u", "h", 80, "t");
        assert_eq!(msg, b"n,a=u,\x01host=h\x01auth=Bearer t\x01\x01".to_vec());
        // Explicitly confirm the default-port form carries no `port=` field.
        assert!(!contains(&msg, b"port="));
    }

    // --- create_oauth_bearer_message: explicit-port form -------------------

    #[test]
    fn oauth_bearer_nondefault_port_inserts_port_before_auth() {
        // Port 143 (IMAP) selects the else-branch; assert the full framing...
        let msg = create_oauth_bearer_message("user@example.com", "mail.example.com", 143, "tok");
        assert_eq!(
            msg,
            b"n,a=user@example.com,\x01host=mail.example.com\x01port=143\x01auth=Bearer tok\x01\x01"
                .to_vec(),
        );
        // ...and, per the agent prompt, that the `port=143\x01` segment appears
        // strictly BEFORE `auth=` — the distinguishing detail of this branch.
        let port_idx = find(&msg, b"port=143\x01").expect("port segment present");
        let auth_idx = find(&msg, b"auth=Bearer").expect("auth segment present");
        assert!(
            port_idx < auth_idx,
            "port field must precede the auth field"
        );
    }

    #[test]
    fn oauth_bearer_large_port_formats_like_c_long() {
        // A large value exercises `%ld` / i64 decimal-formatting parity.
        let msg = create_oauth_bearer_message("u", "h", 2_147_483_647, "t");
        assert_eq!(
            msg,
            b"n,a=u,\x01host=h\x01port=2147483647\x01auth=Bearer t\x01\x01".to_vec(),
        );
    }

    // --- create_xoauth_bearer_message --------------------------------------

    #[test]
    fn xoauth_bearer_matches_curl() {
        // The exact validation vector from the agent prompt.
        assert_eq!(
            create_xoauth_bearer_message("user", "tok"),
            b"user=user\x01auth=Bearer tok\x01\x01".to_vec(),
        );
    }

    // --- structural invariants shared by every message ---------------------

    #[test]
    fn every_message_ends_with_two_soh_bytes() {
        for msg in [
            create_oauth_bearer_message("u", "h", 0, "t"),
            create_oauth_bearer_message("u", "h", 993, "t"),
            create_xoauth_bearer_message("u", "t"),
        ] {
            let n = msg.len();
            assert!(n >= 2, "message too short to hold its trailing separators");
            assert_eq!(
                &msg[n - 2..],
                &[SOH, SOH],
                "every message must close with two 0x01 bytes",
            );
        }
    }

    #[test]
    fn empty_user_and_bearer_are_preserved_verbatim() {
        // curl's maprintf substitutes an empty `%s` with nothing; the separators
        // and literals remain, so the framing is still well-formed.
        assert_eq!(
            create_oauth_bearer_message("", "h", 0, ""),
            b"n,a=,\x01host=h\x01auth=Bearer \x01\x01".to_vec(),
        );
        assert_eq!(
            create_xoauth_bearer_message("", ""),
            b"user=\x01auth=Bearer \x01\x01".to_vec(),
        );
    }

    // --- small byte-substring helpers (test-only) --------------------------

    /// Return the index of the first occurrence of `needle` within `haystack`.
    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    /// Whether `haystack` contains `needle`.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        find(haystack, needle).is_some()
    }
}
