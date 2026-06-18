//! HTTP **Bearer** authorization and the OAuth 2.0 **SASL** bearer-token
//! mechanisms (`OAUTHBEARER` and Google `XOAUTH2`).
//!
//! This module is the memory-safe Rust replacement for the two pieces of
//! upstream libcurl that deal with bearer tokens, deliberately co-located here
//! so that every bearer-token wire format lives in one place:
//!
//! * The HTTP `Authorization: Bearer …` header generator from `lib/http.c`
//!   (`http_output_bearer()`), reproduced by [`http_bearer_header`].
//! * The SASL bearer-token *initial client response* builders from
//!   `lib/vauth/oauth2.c` (`Curl_auth_create_oauth_bearer_message` /
//!   `Curl_auth_create_xoauth_bearer_message`), reproduced by
//!   [`sasl_oauth_bearer_message`] and [`sasl_xoauth_bearer_message`].
//!
//! The C tree is used purely as a **behavioral oracle**: the byte sequences
//! produced here match curl 8.x exactly, because they are observed directly on
//! the wire (HTTP header bytes and, after base64 framing, SASL exchanges) and
//! are pinned by the regression suite.
//!
//! # Wire-format parity (the must-match details)
//!
//! * **The `OAUTHBEARER` / `XOAUTH2` field separator is `\x01`** (SOH, byte
//!   `0x01`), and each SASL message is terminated by **two** consecutive
//!   `\x01` bytes. This is mandated by RFC 7628 (OAUTHBEARER) and Google's
//!   XOAUTH2 specification, and curl emits it verbatim (its format strings use
//!   the `\1` escape). The separators are control bytes, never visible
//!   characters, so the tests in this module compare exact bytes.
//! * **The `port=` field is omitted for the default HTTP ports.** curl writes a
//!   `port=` field into the OAUTHBEARER GS2 message *only* when the port is
//!   neither `0` nor `80`; for `0` (meaning "unset/default") and `80` the field
//!   is dropped entirely. This is a deliberate upstream behavior, preserved
//!   byte-for-byte by [`sasl_oauth_bearer_message`].
//! * **Tokens and identities are inserted verbatim.** Matching curl, the bearer
//!   token (curl's `STRING_BEARER` option value) and the `user`/`host` fields
//!   are substituted without escaping, validation, or CR/LF filtering. curl
//!   applies no such checks — these values originate from the application via
//!   `curl_easy_setopt` or the command line and are trusted — and reproducing
//!   the bytes exactly is required for parity.
//!
//! # Raw bytes, not base64
//!
//! The two SASL builders return the **raw** message bytes. In curl the base64
//! framing of a SASL initial response is applied by the SASL state machine
//! (`lib/curl_sasl.c` / `lib/vauth/vauth.c`), not by the message builders
//! themselves; the same split is preserved here, so the eventual `sasl.rs`
//! caller is responsible for base64-encoding the bytes returned by
//! [`sasl_oauth_bearer_message`] / [`sasl_xoauth_bearer_message`]. The HTTP
//! header produced by [`http_bearer_header`] is emitted as-is — it is a header
//! line, not a base64-framed SASL response.
//!
//! # Error semantics
//!
//! Each function returns the crate-wide `Result` for signature parity with the
//! C functions (which return `CURLcode`). In curl the *only* failure mode of
//! these builders is an allocation failure (`CURLE_OUT_OF_MEMORY`) from
//! `curl_maprintf`. In safe Rust, `String`/`Vec` construction aborts the
//! process on allocation failure rather than returning an error, so there is no
//! fallible path left to surface and these functions therefore always return
//! `Ok`. The `Result` return type is retained so the call sites match the C
//! contract and so a future fallible refinement would not change the
//! signatures.
//!
//! # Memory safety
//!
//! This module contains **zero `unsafe`** and compiles cleanly under the
//! `#![forbid(unsafe_code)]` declared at the `curl-rs-lib` crate root
//! (AAP §0.7.1). All buffers are owned `String` / `Vec<u8>` values; there is no
//! manual allocation and no raw-pointer handling.

use crate::error::Result;

/// Build the HTTP **Bearer** `Authorization` header line.
///
/// Reproduces `http_output_bearer()` from `lib/http.c`, which formats
/// `"Authorization: Bearer %s\r\n"` from curl's `STRING_BEARER` option value.
/// The returned string includes the trailing CRLF (`\r\n`) so it can be written
/// directly into the request header block — exactly as curl stores it in
/// `data->state.aptr.userpwd`.
///
/// This is a **host** authorization header only: curl has no proxy Bearer
/// variant (`http_output_bearer` only ever writes the host `userpwd` slot), so
/// there is intentionally no proxy counterpart here.
///
/// The `token` is inserted **verbatim**, matching curl, which performs no
/// escaping or validation of the bearer value (it is the trusted
/// `CURLOPT_XOAUTH2_BEARER` / `--oauth2-bearer` value).
///
/// # Examples
///
/// ```ignore
/// assert_eq!(
///     http_bearer_header("mytoken").unwrap(),
///     "Authorization: Bearer mytoken\r\n",
/// );
/// ```
pub fn http_bearer_header(token: &str) -> Result<String> {
    // Mirrors curl's `curl_maprintf("Authorization: Bearer %s\r\n", bearer)`.
    Ok(format!("Authorization: Bearer {token}\r\n"))
}

/// Build the SASL **`OAUTHBEARER`** initial client response (RFC 7628).
///
/// Reproduces `Curl_auth_create_oauth_bearer_message()` from
/// `lib/vauth/oauth2.c`. The message is a GS2 header (`n,a=<user>,`) followed by
/// `\x01`-separated `key=value` fields and a trailing empty field, i.e. it ends
/// with two consecutive `\x01` bytes. With the `port=` field omitted (default
/// ports) the layout is:
///
/// ```text
/// n,a=<user>,<SOH>host=<host><SOH>auth=Bearer <bearer><SOH><SOH>
/// ```
///
/// where `<SOH>` denotes the byte `0x01`.
///
/// # Port handling (exact curl behavior)
///
/// curl includes a `port=<port>` field **only** when `port` is neither `0` nor
/// `80`; for the default HTTP ports (`0` meaning "unset/default", and `80`) the
/// field is omitted entirely. With the field present the layout is:
///
/// ```text
/// n,a=<user>,<SOH>host=<host><SOH>port=<port><SOH>auth=Bearer <bearer><SOH><SOH>
/// ```
///
/// This default-port omission is a deliberate upstream behavior and is
/// preserved byte-for-byte.
///
/// The returned bytes are the **raw** message; the SASL caller is responsible
/// for the base64 framing (see the [module documentation](self)).
///
/// # Examples
///
/// ```ignore
/// // Non-default port → a `port=` field is inserted between host and auth.
/// let msg = sasl_oauth_bearer_message("user@example.com", "example.com", 443, "tok").unwrap();
/// assert_eq!(
///     msg,
///     b"n,a=user@example.com,\x01host=example.com\x01port=443\x01auth=Bearer tok\x01\x01".to_vec(),
/// );
/// ```
pub fn sasl_oauth_bearer_message(
    user: &str,
    host: &str,
    port: u16,
    bearer: &str,
) -> Result<Vec<u8>> {
    // Match `Curl_auth_create_oauth_bearer_message` exactly: the `port=` field
    // is present only for non-default HTTP ports. Port 0 ("unset") and port 80
    // are treated identically and omit the field. `\x01` is the SOH separator
    // (curl's `\1`); the message ends with two SOH bytes.
    let message = if port == 0 || port == 80 {
        format!("n,a={user},\x01host={host}\x01auth=Bearer {bearer}\x01\x01")
    } else {
        format!("n,a={user},\x01host={host}\x01port={port}\x01auth=Bearer {bearer}\x01\x01")
    };

    Ok(message.into_bytes())
}

/// Build the Google **`XOAUTH2`** initial client response.
///
/// Reproduces `Curl_auth_create_xoauth_bearer_message()` from
/// `lib/vauth/oauth2.c`:
///
/// ```text
/// user=<user><SOH>auth=Bearer <bearer><SOH><SOH>
/// ```
///
/// where `<SOH>` denotes the byte `0x01`. Unlike [`sasl_oauth_bearer_message`],
/// the XOAUTH2 form carries no GS2 header and no `host`/`port` fields — it is
/// simply the `user` and the bearer token.
///
/// The returned bytes are the **raw** message; the SASL caller applies the
/// base64 framing (see the [module documentation](self)).
///
/// # Examples
///
/// ```ignore
/// let msg = sasl_xoauth_bearer_message("foo", "tok").unwrap();
/// assert_eq!(msg, b"user=foo\x01auth=Bearer tok\x01\x01".to_vec());
/// ```
pub fn sasl_xoauth_bearer_message(user: &str, bearer: &str) -> Result<Vec<u8>> {
    // Mirrors curl's `curl_maprintf("user=%s\1auth=Bearer %s\1\1", user, bearer)`.
    Ok(format!("user={user}\x01auth=Bearer {bearer}\x01\x01").into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SASL field separator / terminator byte (`SOH`, `0x01`). Defined in
    /// the test module so the production build carries no unused constant.
    const SOH: u8 = 0x01;

    /// Tiny substring search over byte slices (test-only helper used to assert
    /// the presence/absence and ordering of `\x01`-delimited fields).
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        haystack.windows(needle.len()).any(|window| window == needle)
    }

    // ---- Phase A: HTTP Bearer header ---------------------------------------

    #[test]
    fn http_bearer_header_matches_curl_format() {
        // The canonical example from the task spec.
        assert_eq!(
            http_bearer_header("mytoken").unwrap(),
            "Authorization: Bearer mytoken\r\n",
        );
    }

    #[test]
    fn http_bearer_header_has_single_trailing_crlf() {
        let header = http_bearer_header("abc.def.ghi").unwrap();
        assert_eq!(header, "Authorization: Bearer abc.def.ghi\r\n");
        assert!(header.starts_with("Authorization: Bearer "));
        assert!(header.ends_with("\r\n"));
        // Exactly one CRLF, and it is at the very end (no header injection,
        // no duplicate terminators).
        assert_eq!(header.matches("\r\n").count(), 1);
    }

    #[test]
    fn http_bearer_header_inserts_token_verbatim() {
        // curl performs no escaping/validation; an empty token still yields the
        // literal prefix followed by CRLF.
        assert_eq!(http_bearer_header("").unwrap(), "Authorization: Bearer \r\n");

        // A realistic JWT (dots, dashes, underscores) is passed through untouched.
        let jwt = "eyJhbGciOiJI.UzI1NiIsInR5.cCI6Ik_pXVCJ9-x";
        assert_eq!(
            http_bearer_header(jwt).unwrap(),
            format!("Authorization: Bearer {jwt}\r\n"),
        );
    }

    // ---- Phase B: SASL OAUTHBEARER -----------------------------------------

    #[test]
    fn oauth_bearer_port_zero_omits_port_field() {
        let msg =
            sasl_oauth_bearer_message("user@example.com", "example.com", 0, "mF_9.B5f-4.1JqM")
                .unwrap();
        assert_eq!(
            msg,
            b"n,a=user@example.com,\x01host=example.com\x01auth=Bearer mF_9.B5f-4.1JqM\x01\x01"
                .to_vec(),
        );
        // Port 0 ("unset") must NOT emit a `port=` field.
        assert!(!contains_subslice(&msg, b"port="));
    }

    #[test]
    fn oauth_bearer_port_80_omits_port_field() {
        let msg = sasl_oauth_bearer_message("u", "h", 80, "t").unwrap();
        assert_eq!(msg, b"n,a=u,\x01host=h\x01auth=Bearer t\x01\x01".to_vec());
        // Port 80 is the default HTTP port and is treated exactly like port 0.
        assert!(!contains_subslice(&msg, b"port="));
    }

    #[test]
    fn oauth_bearer_port_443_includes_port_field() {
        let msg = sasl_oauth_bearer_message("u", "h", 443, "t").unwrap();
        assert_eq!(
            msg,
            b"n,a=u,\x01host=h\x01port=443\x01auth=Bearer t\x01\x01".to_vec(),
        );
        // `port=443` is inserted, framed by SOH, between the host and auth fields.
        assert!(contains_subslice(&msg, b"\x01port=443\x01auth=Bearer "));
    }

    #[test]
    fn oauth_bearer_exact_soh_placement_with_port() {
        let msg =
            sasl_oauth_bearer_message("alice", "imap.example.com", 143, "vF9dft4qmTc2").unwrap();
        let expected: &[u8] =
            b"n,a=alice,\x01host=imap.example.com\x01port=143\x01auth=Bearer vF9dft4qmTc2\x01\x01";
        assert_eq!(msg, expected.to_vec());

        // With the port present there are exactly five SOH bytes: after the GS2
        // header (`n,a=<user>,`), after `host`, after `port`, then the two-byte
        // terminator.
        assert_eq!(msg.iter().filter(|&&b| b == SOH).count(), 5);
        // The message terminates with two SOH bytes.
        assert_eq!(&msg[msg.len() - 2..], &[SOH, SOH]);
        // The GS2 header prefix is byte-for-byte exact.
        assert!(msg.starts_with(b"n,a=alice,\x01host=imap.example.com\x01port=143\x01"));
    }

    #[test]
    fn oauth_bearer_exact_soh_placement_without_port() {
        let msg = sasl_oauth_bearer_message("alice", "imap.example.com", 80, "tok").unwrap();
        assert_eq!(
            msg,
            b"n,a=alice,\x01host=imap.example.com\x01auth=Bearer tok\x01\x01".to_vec(),
        );
        // Without the port there are exactly four SOH bytes: after the GS2
        // header (`n,a=<user>,`), after `host`, then the two-byte terminator.
        assert_eq!(msg.iter().filter(|&&b| b == SOH).count(), 4);
        assert_eq!(&msg[msg.len() - 2..], &[SOH, SOH]);
        assert!(msg.starts_with(b"n,a=alice,\x01host=imap.example.com\x01auth=Bearer "));
    }

    #[test]
    fn oauth_bearer_high_port_rendered_as_decimal() {
        // A non-default, multi-digit port is rendered in decimal (curl's `%ld`).
        let msg = sasl_oauth_bearer_message("u", "h", 8080, "t").unwrap();
        assert_eq!(
            msg,
            b"n,a=u,\x01host=h\x01port=8080\x01auth=Bearer t\x01\x01".to_vec(),
        );
    }

    // ---- Phase C: SASL XOAUTH2 ---------------------------------------------

    #[test]
    fn xoauth_bearer_matches_exact_bytes() {
        // The canonical example from the task spec.
        let msg = sasl_xoauth_bearer_message("foo", "tok").unwrap();
        assert_eq!(msg, b"user=foo\x01auth=Bearer tok\x01\x01".to_vec());
    }

    #[test]
    fn xoauth_bearer_soh_placement_and_no_gs2_header() {
        let msg = sasl_xoauth_bearer_message("someone@gmail.com", "ya29.token").unwrap();
        assert_eq!(
            msg,
            b"user=someone@gmail.com\x01auth=Bearer ya29.token\x01\x01".to_vec(),
        );
        // Exactly three SOH bytes: after the `user` field, then the two-byte
        // terminator.
        assert_eq!(msg.iter().filter(|&&b| b == SOH).count(), 3);
        assert_eq!(&msg[msg.len() - 2..], &[SOH, SOH]);
        // XOAUTH2 has no GS2 header and no host/port fields.
        assert!(!contains_subslice(&msg, b"n,a="));
        assert!(!contains_subslice(&msg, b"host="));
        assert!(!contains_subslice(&msg, b"port="));
    }

    #[test]
    fn xoauth_bearer_inserts_fields_verbatim() {
        // Empty user/bearer still produce the literal scaffold (parity with
        // curl's unconditional `curl_maprintf`).
        let msg = sasl_xoauth_bearer_message("", "").unwrap();
        assert_eq!(msg, b"user=\x01auth=Bearer \x01\x01".to_vec());
    }
}

