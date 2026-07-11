// SPDX-License-Identifier: curl

//! Hostname / certificate-identity verification helpers (RFC 6125 §6.4.3).
//!
//! This module is a faithful, byte-for-byte Rust port of curl's
//! `lib/vtls/hostcheck.c` (and its declaration-only companion
//! `lib/vtls/hostcheck.h`). It implements the wildcard-aware matching curl
//! uses to decide whether a hostname is covered by a certificate identity
//! (a Subject Alternative Name `dNSName` or, as a legacy fallback, the
//! Subject Common Name).
//!
//! In the C tree this logic was compiled only for the OpenSSL and Schannel
//! backends (`#if defined(USE_OPENSSL) || defined(USE_SCHANNEL)`). In the Rust
//! rewrite the single TLS backend is `rustls`, whose `webpki`-based verifier
//! normally performs its own RFC 6125 name checking. This module reproduces
//! curl's exact matching semantics so that:
//!
//! * the custom certificate verifier in `tls::config` can honor curl's
//!   `SSL_VERIFYHOST` semantics (`0` = skip name check, `2` = enforce it)
//!   identically to curl 8.x, and
//! * diagnostic behavior stays byte-for-byte compatible with the reference
//!   implementation, which is the project's binary success condition.
//!
//! The matching rules preserved here are precisely those of RFC 6125
//! §6.4.3, with curl's additional pragmatics:
//!
//! * A `*` wildcard is honored **only** as the entire left-most label — the
//!   pattern must literally begin with `"*."`. Patterns such as `"a*"`,
//!   `"a*b"`, `"*b"`, or `"**llo"` are treated as ordinary (non-wildcard)
//!   literals and compared verbatim.
//! * A wildcard pattern must contain **at least two dots**, so `"*.com"`
//!   never matches (it would be far too broad).
//! * Wildcards never match an IP-address literal, nor a hostname whose first
//!   byte is a dot.
//! * A single trailing dot is stripped from both the hostname and the pattern
//!   before comparison (fully-qualified names are normalized), mirroring what
//!   browsers do.
//! * Label comparison is ASCII case-insensitive only. Hostnames reach this
//!   layer already in their ACE / ASCII (`xn--…`) form, so no Unicode
//!   case-folding is performed — exactly as curl's `curl_strnequal`.
//!
//! # Relationship to `webpki` IP handling
//!
//! IP-address server names are validated against certificate `iPAddress`
//! SAN entries by `webpki` in the normal verification path. The functions in
//! this module are for **DNS-name** matching and deliberately refuse to
//! wildcard-match IP literals (see [`cert_hostcheck`]).
//!
//! # Safety
//!
//! This module is written entirely in safe Rust and never panics on
//! certificate- or network-derived input: all inputs are treated as
//! untrusted byte data and every function returns a plain `bool`. (The token
//! that denotes non-safe Rust is intentionally absent from this file so the
//! crate-wide `grep` audit stays green.)

use std::net::IpAddr;

/// Compare two host-label byte strings for equality, ASCII case-insensitively.
///
/// Mirrors curl's `pmatch()`: the strings must be the same length and equal
/// under an ASCII case-insensitive comparison (curl uses `curl_strnequal`).
/// Bytes outside the ASCII letter range — including non-ASCII bytes such as
/// those found in raw ACE labels — are compared for exact equality.
fn pmatch(hostname: &[u8], pattern: &[u8]) -> bool {
    // Length is checked explicitly first to mirror the C control flow; the
    // subsequent comparison also requires equal lengths, so this is a fast
    // reject for the common mismatched-length case.
    if hostname.len() != pattern.len() {
        return false;
    }
    hostname.eq_ignore_ascii_case(pattern)
}

/// Strip a single trailing `.` from a byte slice, if one is present.
///
/// This performs the "ignore trailing dots" normalization of RFC 6125 that
/// curl applies to both the hostname and the pattern before matching. Only
/// **one** trailing dot is removed, matching curl's single `len--` step.
fn strip_trailing_dot(input: &[u8]) -> &[u8] {
    match input.split_last() {
        Some((&b'.', rest)) => rest,
        _ => input,
    }
}

/// Return `true` when `host` is a numeric IPv4 or IPv6 address literal.
///
/// This is the idiomatic Rust equivalent of curl's `Curl_host_is_ipnum()`,
/// which tries `inet_pton()` for both `AF_INET` and `AF_INET6`. Rust's
/// [`IpAddr`] parser applies the same strictness — for example it rejects a
/// trailing dot (`"127.0.0.1."` is *not* a valid literal), exactly like
/// `inet_pton`.
fn host_is_ipnum(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

/// Byte-slice convenience wrapper over [`host_is_ipnum`].
///
/// Hostnames that are not valid UTF-8 cannot be IP-address literals (which are
/// pure ASCII), so invalid UTF-8 is reported as "not an IP number". Treating
/// such input as a non-IP is safe: it merely means the plain-comparison path
/// still applies and no wildcard refusal is triggered on its behalf.
fn host_is_ipnum_bytes(host: &[u8]) -> bool {
    match std::str::from_utf8(host) {
        Ok(text) => host_is_ipnum(text),
        Err(_) => false,
    }
}

/// Match a hostname against a (possibly wildcard) certificate identity pattern.
///
/// Direct port of curl's `hostmatch()` implementing RFC 6125 §6.4.3. Both
/// arguments are raw, untrusted byte slices (a SAN `dNSName` may legally
/// contain non-ASCII bytes). The caller ([`cert_hostcheck`]) guarantees both
/// slices are non-empty; the empty guards below simply make the function
/// panic-free in isolation.
///
/// Note that the IP-literal and leading-dot checks are performed against the
/// **original** `hostname` bytes — not the trailing-dot-normalized view —
/// because curl feeds the un-normalized, NUL-terminated hostname to
/// `inet_pton`. This distinction is observable (e.g. `"1.2.3.4."` is not an IP
/// literal even though `"1.2.3.4"` is) and is preserved for exact parity.
fn hostmatch(hostname: &[u8], pattern: &[u8]) -> bool {
    // Defensive, panic-free handling of empty input. In curl these are
    // `DEBUGASSERT`s because the sole caller rejects empty strings first.
    if hostname.is_empty() || pattern.is_empty() {
        return false;
    }

    // Normalize both by stripping a single trailing dot before matching.
    let host_norm = strip_trailing_dot(hostname);
    let pat_norm = strip_trailing_dot(pattern);

    // A pattern that does not begin with "*." is not a wildcard: compare
    // literally (ASCII case-insensitively). This gate is what restricts the
    // wildcard to the left-most label only — "a*", "a*b", "*b", "**llo" all
    // fall through to a plain comparison here.
    if !pat_norm.starts_with(b"*.") {
        return pmatch(host_norm, pat_norm);
    }

    // Wildcard pattern. Never wildcard-match an IP-address literal (some certs
    // carry an IP in the CN), and never match a hostname that begins with a
    // dot. Both checks use the original hostname bytes for `inet_pton` parity.
    if host_is_ipnum_bytes(hostname) || hostname.first() == Some(&b'.') {
        return false;
    }

    // Require at least two dots in the pattern to avoid an over-broad wildcard
    // (e.g. reject "*.com"). Locate the first and last dot in the pattern; if
    // there is no dot, or only a single dot, fall back to a plain comparison.
    let first_dot = pat_norm.iter().position(|&b| b == b'.');
    let last_dot = pat_norm.iter().rposition(|&b| b == b'.');
    match (first_dot, last_dot) {
        (Some(first), Some(last)) if first != last => {
            // At least two dots: compare the hostname's parent domain (from
            // its first dot, inclusive) against the pattern's parent domain
            // (from its first dot, inclusive). A hostname with no dot cannot
            // match a wildcard pattern.
            match host_norm.iter().position(|&b| b == b'.') {
                Some(host_dot) => pmatch(&host_norm[host_dot..], &pat_norm[first..]),
                None => false,
            }
        }
        _ => pmatch(host_norm, pat_norm),
    }
}

/// Check whether a certificate identity `pattern` matches `hostname`.
///
/// This is the public entry point and the stable primitive of this module; it
/// is a direct port of curl's `Curl_cert_hostcheck()`. `pattern` is a
/// certificate identity (a SAN `dNSName` or the Subject CN, possibly
/// containing a `*` wildcard) and `hostname` is the name being connected to.
///
/// Returns `true` on a match and `false` otherwise. If either argument is
/// empty the result is `false`, matching curl. The matching rules are those
/// documented at the module level (RFC 6125 §6.4.3 with curl's pragmatics).
///
/// # Examples
///
/// ```ignore
/// assert!(cert_hostcheck("*.example.com", "www.example.com"));
/// assert!(!cert_hostcheck("*.example.com", "example.com"));
/// assert!(!cert_hostcheck("*.168.1.1", "192.168.1.1")); // never wildcard an IP
/// ```
pub fn cert_hostcheck(pattern: &str, hostname: &str) -> bool {
    if pattern.is_empty() || hostname.is_empty() {
        return false;
    }
    hostmatch(hostname.as_bytes(), pattern.as_bytes())
}

/// Return `true` if **any** of the supplied certificate identities matches
/// `hostname`.
///
/// This is a small convenience for the custom `rustls` certificate verifier in
/// `tls::config`, used when it must perform manual name matching (curl's
/// `SSL_VERIFYHOST == 2` path). It mirrors how curl iterates the SAN
/// `dNSName` entries and then falls back to the Subject CN, matching each
/// candidate with [`cert_hostcheck`]. The actual extraction of SAN / CN
/// strings from the peer certificate is performed by the verifier (or by
/// `webpki`); this helper only runs the matching.
///
/// IP-address hostnames are handled by `webpki`'s `iPAddress` SAN validation
/// in the normal path — this function is for DNS-name identities and, via
/// [`cert_hostcheck`], correctly refuses to wildcard-match IP literals.
///
/// Accepts any slice of string-like identities (`&str`, `String`, …).
pub fn verify_host(cert_identities: &[impl AsRef<str>], hostname: &str) -> bool {
    cert_identities
        .iter()
        .any(|identity| cert_hostcheck(identity.as_ref(), hostname))
}

#[cfg(test)]
mod tests {
    use super::{cert_hostcheck, host_is_ipnum, hostmatch, verify_host};

    /// Byte-level equivalent of curl's
    /// `Curl_cert_hostcheck(pattern, patternlen, host, hostlen)`. Used to drive
    /// the canonical corpus below, which includes non-UTF-8 inputs that cannot
    /// be expressed as `&str`.
    fn cc(pattern: &[u8], host: &[u8]) -> bool {
        if pattern.is_empty() || host.is_empty() {
            return false;
        }
        hostmatch(host, pattern)
    }

    /// The complete `hostcheck` test corpus transcribed verbatim from curl's
    /// `tests/unit/unit1397.c` (unittest 1397). Each tuple is
    /// `(host, pattern, expected_match)`.
    #[test]
    fn curl_unittest_1397_corpus() {
        let cases: &[(&[u8], &[u8], bool)] = &[
            (b".hello.com", b"*.hello.com", false),
            (b"a.hello.com", b"*.hello.com", true),
            (b"", b"", false),
            (b"a", b"", false),
            (b"", b"b", false),
            (b"a", b"b", false),
            (b"aa", b"bb", false),
            (b"\xff", b"\xff", true),
            (b"aa.aa.aa", b"aa.aa.bb", false),
            (b"aa.aa.aa", b"aa.aa.aa", true),
            (b"aa.aa.aa", b"*.aa.bb", false),
            (b"aa.aa.aa", b"*.aa.aa", true),
            (b"192.168.0.1", b"192.168.0.1", true),
            (b"192.168.0.1", b"*.168.0.1", false),
            (b"192.168.0.1", b"*.0.1", false),
            (b"h.ello", b"*.ello", false),
            (b"h.ello.", b"*.ello", false),
            (b"h.ello", b"*.ello.", false),
            (b"h.e.llo", b"*.e.llo", true),
            (b"h.e.llo", b" *.e.llo", false),
            (b" h.e.llo", b"*.e.llo", true),
            (b"h.e.llo.", b"*.e.llo", true),
            (b"*.e.llo.", b"*.e.llo", true),
            (b"************.e.llo.", b"*.e.llo", true),
            (b"\xfe\xfe.e.llo.", b"*.e.llo", true),
            (b"h.e.llo.", b"*.e.llo.", true),
            (b"h.e.llo", b"*.e.llo.", true),
            (b".h.e.llo", b"*.e.llo.", false),
            (b"h.e.llo", b"*.*.llo.", false),
            (b"h.e.llo", b"h.*.llo", false),
            (b"h.e.llo", b"h.e.*", false),
            (b"hello", b"*.ello", false),
            (b"hello", b"**llo", false),
            (b"bar.foo.example.com", b"*.example.com", false),
            (b"foo.example.com", b"*.example.com", true),
            (b"baz.example.net", b"b*z.example.net", false),
            (b"foobaz.example.net", b"*baz.example.net", false),
            (b"xn--l8j.example.local", b"x*.example.local", false),
            (b"xn--l8j.example.net", b"*.example.net", true),
            (b"xn--l8j.example.net", b"*j.example.net", false),
            (b"xn--l8j.example.net", b"xn--l8j.example.net", true),
            (b"xn--l8j.example.net", b"xn--l8j.*.net", false),
            (b"xl8j.example.net", b"*.example.net", true),
            (
                b"fe80::3285:a9ff:fe46:b619",
                b"*::3285:a9ff:fe46:b619",
                false,
            ),
            (
                b"fe80::3285:a9ff:fe46:b619",
                b"fe80::3285:a9ff:fe46:b619",
                true,
            ),
        ];

        for (host, pattern, expected) in cases {
            let got = cc(pattern, host);
            assert_eq!(
                got,
                *expected,
                "host={:?} pattern={:?}: expected {} got {}",
                String::from_utf8_lossy(host),
                String::from_utf8_lossy(pattern),
                expected,
                got
            );
        }
    }

    /// The overlong-hostname case from unittest 1397: a 300-byte dotless label
    /// (60 each of A,B,C,D,E) followed by ".e.llo." must still match
    /// "*.e.llo". Built at runtime because adjacent byte-string literals do
    /// not concatenate in Rust.
    #[test]
    fn curl_unittest_1397_overlong_label() {
        let mut host = Vec::new();
        for letter in [b'A', b'B', b'C', b'D', b'E'] {
            host.extend(std::iter::repeat(letter).take(60));
        }
        host.extend_from_slice(b".e.llo.");
        assert!(hostmatch(&host, b"*.e.llo"));
    }

    // ---- Public `cert_hostcheck` (&str) API: the agent-prompt required set ----

    #[test]
    fn wildcard_matches_single_label() {
        assert!(cert_hostcheck("*.example.com", "www.example.com"));
    }

    #[test]
    fn wildcard_requires_a_label() {
        assert!(!cert_hostcheck("*.example.com", "example.com"));
    }

    #[test]
    fn wildcard_matches_only_one_label() {
        assert!(!cert_hostcheck("*.example.com", "www.sub.example.com"));
    }

    #[test]
    fn exact_match_is_ascii_case_insensitive() {
        assert!(cert_hostcheck("www.example.com", "www.example.com"));
        assert!(cert_hostcheck("www.example.com", "WWW.Example.COM"));
        assert!(cert_hostcheck("WWW.Example.COM", "www.example.com"));
    }

    #[test]
    fn wildcard_needs_at_least_two_dots() {
        assert!(!cert_hostcheck("*.com", "example.com"));
    }

    #[test]
    fn never_wildcard_match_ip() {
        assert!(!cert_hostcheck("*.168.1.1", "192.168.1.1"));
    }

    #[test]
    fn trailing_dot_is_normalized() {
        // Trailing dot on the hostname.
        assert!(cert_hostcheck("*.example.com", "www.example.com."));
        // Trailing dot on the pattern.
        assert!(cert_hostcheck("*.example.com.", "www.example.com"));
        // Trailing dot on both, non-wildcard.
        assert!(cert_hostcheck("www.example.com.", "www.example.com."));
    }

    #[test]
    fn empty_inputs_never_match() {
        assert!(!cert_hostcheck("", "x"));
        assert!(!cert_hostcheck("x", ""));
        assert!(!cert_hostcheck("", ""));
    }

    /// curl feeds the *original* (un-normalized) hostname to `inet_pton`, so a
    /// hostname with a trailing dot is not an IP literal and falls through to
    /// label matching; without the trailing dot it is an IP literal and the
    /// wildcard is refused. This locks in the "original hostname bytes" parity
    /// detail of [`super::hostmatch`].
    #[test]
    fn trailing_dot_ip_parity_edge() {
        assert!(cert_hostcheck("*.2.3.4", "1.2.3.4."));
        assert!(!cert_hostcheck("*.2.3.4", "1.2.3.4"));
    }

    // ---- IP-literal detection ----

    #[test]
    fn host_is_ipnum_detects_literals() {
        assert!(host_is_ipnum("192.168.1.1"));
        assert!(host_is_ipnum("::1"));
        assert!(!host_is_ipnum("example.com"));
        // Extra parity spot-checks.
        assert!(host_is_ipnum("fe80::3285:a9ff:fe46:b619"));
        assert!(!host_is_ipnum("1.2.3.4.")); // trailing dot => not an IP
        assert!(!host_is_ipnum("256.1.1.1")); // out of range => not an IP
    }

    // ---- `verify_host` convenience helper ----

    #[test]
    fn verify_host_matches_any_identity() {
        let sans = ["mail.example.com", "*.example.com"];
        assert!(verify_host(&sans, "www.example.com"));
        assert!(verify_host(&sans, "mail.example.com"));
        assert!(!verify_host(&sans, "www.other.com"));

        // Empty identity list never matches.
        let empty: [&str; 0] = [];
        assert!(!verify_host(&empty, "www.example.com"));

        // Works with owned `String` identities too (any `AsRef<str>`).
        let owned = vec![String::from("*.example.com")];
        assert!(verify_host(&owned, "api.example.com"));
        assert!(!verify_host(&owned, "example.com"));
    }
}
