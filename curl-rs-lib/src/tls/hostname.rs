//! Hostname verification utilities for TLS certificate matching.
//!
//! This module provides RFC 6125 §6.4.3 compliant wildcard-aware hostname
//! matching, rewritten from the C implementation in `lib/vtls/hostcheck.c`.
//!
//! # Rustls Integration
//!
//! In the Rust rewrite of curl, rustls handles TLS hostname verification
//! internally via its `ServerCertVerifier` implementation. This module
//! provides **auxiliary** hostname matching utilities used for:
//!
//! - Pre-validation before establishing connections
//! - Hostname normalization for TLS session cache key generation
//! - Diagnostics and logging of hostname matching decisions
//! - Edge cases such as proxy hostname verification and pinned public
//!   key scenarios
//!
//! # Safety
//!
//! This module contains zero `unsafe` blocks — all operations are pure
//! Rust string manipulation using the standard library.
//!
//! # RFC 6125 §6.4.3 Wildcard Rules
//!
//! The wildcard matching implemented here follows these rules:
//!
//! 1. Only the leftmost label may be a wildcard (`*`).
//! 2. Partial wildcards (e.g., `a*.example.com`, `*b.example.com`) are
//!    **not** supported — they are treated as literal patterns.
//! 3. Wildcard patterns must contain at least two dots (e.g., `*.com` is
//!    rejected but `*.example.com` is accepted).
//! 4. Wildcards never match IP address literals.
//! 5. Trailing dots in both hostname and pattern are stripped before
//!    comparison (browser normalization behavior).

use std::net::IpAddr;

/// Maximum hostname length for validation, matching the DNS specification
/// limit of 253 characters for a fully qualified domain name.
pub const MAX_HOSTNAME_LEN: usize = 253;

/// Checks whether the given string represents an IP address (IPv4 or IPv6).
///
/// This replaces the C `Curl_host_is_ipnum()` function. Handles:
/// - Standard IPv4 addresses (e.g., `192.168.1.1`)
/// - Standard IPv6 addresses (e.g., `::1`, `2001:db8::1`)
/// - Bracketed IPv6 addresses (e.g., `[::1]`)
///
/// # Examples
///
/// ```ignore
/// assert!(is_ip_address("192.168.1.1"));
/// assert!(is_ip_address("::1"));
/// assert!(is_ip_address("[::1]"));
/// assert!(!is_ip_address("example.com"));
/// ```
fn is_ip_address(hostname: &str) -> bool {
    // Try parsing directly as an IP address (handles both IPv4 and IPv6).
    if hostname.parse::<IpAddr>().is_ok() {
        return true;
    }

    // Handle bracketed IPv6 notation: `[::1]` or `[2001:db8::1]`.
    if hostname.starts_with('[') && hostname.ends_with(']') {
        let inner = &hostname[1..hostname.len() - 1];
        if inner.parse::<IpAddr>().is_ok() {
            return true;
        }
    }

    false
}

/// Case-insensitive, length-aware string comparison.
///
/// Both strings must have equal length for a match. Comparison is performed
/// using ASCII case-insensitive semantics (sufficient for DNS hostnames).
///
/// This replaces the C `pmatch()` function from `hostcheck.c` lines 41-47,
/// which used `curl_strnequal` for length-bounded case-insensitive comparison.
fn pmatch(hostname: &str, pattern: &str) -> bool {
    if hostname.len() != pattern.len() {
        return false;
    }
    hostname.eq_ignore_ascii_case(pattern)
}

/// Performs RFC 6125 §6.4.3 wildcard-aware hostname matching against a
/// certificate pattern.
///
/// This is the internal matching engine, rewritten from the C `hostmatch()`
/// function in `hostcheck.c` lines 73-114. It implements:
///
/// 1. Trailing dot normalization on both hostname and pattern.
/// 2. Direct case-insensitive comparison for non-wildcard patterns.
/// 3. IP literal rejection (wildcards never match IPs).
/// 4. Leftmost-label-only wildcard matching with a minimum of two dots
///    in the pattern.
/// 5. Suffix comparison: the hostname suffix after the first label is
///    compared against the pattern suffix after the wildcard label.
fn hostmatch(hostname: &str, pattern: &str) -> bool {
    // Strip trailing dots from both hostname and pattern, matching the
    // normalization behavior in C lines 86-89.
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    let pattern = pattern.strip_suffix('.').unwrap_or(pattern);

    // If the pattern does not start with "*.", perform a direct literal
    // comparison. This also handles partial wildcards like "a*.example.com"
    // which are intentionally treated as literal patterns per RFC 6125.
    // (Matches C line 91-92: `if(strncmp(pattern, "*.", 2))`)
    if !pattern.starts_with("*.") {
        return pmatch(hostname, pattern);
    }

    // Wildcard patterns must never match IP address literals or hostnames
    // that begin with a dot.
    // (Matches C lines 95-96)
    if is_ip_address(hostname) || hostname.starts_with('.') {
        return false;
    }

    // Require at least 2 dots in the pattern to prevent overly broad
    // wildcard matches (e.g., `*.com` must not match `example.com`).
    // Find the first dot in the pattern (which is the dot after `*`).
    // (Matches C lines 100-103)
    let pattern_first_dot = match pattern.find('.') {
        Some(pos) => pos,
        // No dot found at all — fall back to literal comparison.
        None => return pmatch(hostname, pattern),
    };

    // Check if there is a second dot by searching the remainder of the
    // pattern after the first dot. If the first dot is the only dot,
    // the wildcard is too broad — fall back to literal comparison.
    let pattern_after_first_dot = &pattern[pattern_first_dot + 1..];
    if !pattern_after_first_dot.contains('.') {
        // Only one dot in pattern (e.g., `*.com`) — reject wildcard,
        // fall back to literal comparison which will naturally fail.
        return pmatch(hostname, pattern);
    }

    // Wildcard match: compare the hostname suffix (starting from the
    // first dot) against the pattern suffix (starting from the first dot).
    // This ensures the wildcard replaces exactly one DNS label.
    // (Matches C lines 105-111)
    match hostname.find('.') {
        Some(hostname_first_dot) => {
            let hostname_suffix = &hostname[hostname_first_dot..];
            let pattern_suffix = &pattern[pattern_first_dot..];
            pmatch(hostname_suffix, pattern_suffix)
        }
        // Hostname has no dot — cannot match a wildcard pattern.
        // (Matches C line 113)
        None => false,
    }
}

/// Verifies whether a certificate pattern matches a given hostname,
/// following RFC 6125 §6.4.3 wildcard matching rules.
///
/// This is the public entry point, rewritten from the C
/// `Curl_cert_hostcheck()` function in `hostcheck.c` lines 119-125.
///
/// # Arguments
///
/// * `pattern` — The certificate name pattern (e.g., `*.example.com`
///   or `www.example.com`). This corresponds to the Subject Alternative
///   Name (SAN) or Common Name (CN) from an X.509 certificate.
/// * `hostname` — The hostname being verified against the certificate
///   pattern.
///
/// # Returns
///
/// `true` if the pattern matches the hostname according to RFC 6125
/// §6.4.3 rules, `false` otherwise.
///
/// # Matching Rules
///
/// - Both `pattern` and `hostname` must be non-empty.
/// - Trailing dots are stripped before comparison.
/// - Non-wildcard patterns are compared case-insensitively.
/// - Wildcard patterns (`*.example.com`) match exactly one DNS label
///   in the leftmost position.
/// - Partial wildcards (`a*.example.com`) are treated as literal patterns.
/// - Wildcards never match IP address literals.
/// - Wildcard patterns require at least two dots (e.g., `*.com` is
///   rejected).
///
/// # Examples
///
/// ```
/// use curl_rs_lib::tls::hostname::cert_hostcheck;
///
/// // Wildcard matching
/// assert!(cert_hostcheck("*.example.com", "foo.example.com"));
/// assert!(!cert_hostcheck("*.example.com", "example.com"));
///
/// // Exact matching
/// assert!(cert_hostcheck("www.example.com", "www.example.com"));
///
/// // IP literals are never matched by wildcards
/// assert!(!cert_hostcheck("*.example.com", "192.168.1.1"));
///
/// // Trailing dots are normalized
/// assert!(cert_hostcheck("www.example.com.", "www.example.com"));
/// ```
pub fn cert_hostcheck(pattern: &str, hostname: &str) -> bool {
    // Input validation: both pattern and hostname must be non-empty.
    // (Matches C line 122-123: `if(match && *match && hostname && *hostname)`)
    if pattern.is_empty() || hostname.is_empty() {
        return false;
    }

    hostmatch(hostname, pattern)
}

/// Normalizes a hostname for use as a session cache key or for peer
/// comparison.
///
/// The normalization process:
/// 1. Converts the hostname to ASCII lowercase.
/// 2. Strips any trailing dot.
///
/// This is useful for generating consistent TLS session cache keys
/// and for hostname-based connection pool matching.
///
/// # Arguments
///
/// * `hostname` — The hostname to normalize.
///
/// # Returns
///
/// A new `String` containing the normalized hostname.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::tls::hostname::normalize_hostname;
///
/// assert_eq!(normalize_hostname("WWW.Example.COM."), "www.example.com");
/// assert_eq!(normalize_hostname("example.com"), "example.com");
/// assert_eq!(normalize_hostname(""), "");
/// ```
pub fn normalize_hostname(hostname: &str) -> String {
    let lowered = hostname.to_ascii_lowercase();
    match lowered.strip_suffix('.') {
        Some(stripped) => stripped.to_owned(),
        None => lowered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // is_ip_address helper tests
    // ---------------------------------------------------------------

    #[test]
    fn test_is_ip_address_ipv4() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("0.0.0.0"));
        assert!(is_ip_address("255.255.255.255"));
        assert!(is_ip_address("127.0.0.1"));
    }

    #[test]
    fn test_is_ip_address_ipv6() {
        assert!(is_ip_address("::1"));
        assert!(is_ip_address("2001:db8::1"));
        assert!(is_ip_address("fe80::1%25eth0") == false); // scoped, not parseable by IpAddr
        assert!(is_ip_address("::ffff:192.168.1.1")); // IPv4-mapped IPv6
    }

    #[test]
    fn test_is_ip_address_bracketed_ipv6() {
        assert!(is_ip_address("[::1]"));
        assert!(is_ip_address("[2001:db8::1]"));
    }

    #[test]
    fn test_is_ip_address_not_ip() {
        assert!(!is_ip_address("example.com"));
        assert!(!is_ip_address("www.example.com"));
        assert!(!is_ip_address("localhost"));
        assert!(!is_ip_address(""));
        assert!(!is_ip_address("not-an-ip"));
    }

    // ---------------------------------------------------------------
    // pmatch helper tests
    // ---------------------------------------------------------------

    #[test]
    fn test_pmatch_equal() {
        assert!(pmatch("example.com", "example.com"));
        assert!(pmatch("EXAMPLE.COM", "example.com"));
        assert!(pmatch("Example.Com", "example.com"));
    }

    #[test]
    fn test_pmatch_different_length() {
        assert!(!pmatch("example.com", "example.co"));
        assert!(!pmatch("a", "ab"));
    }

    #[test]
    fn test_pmatch_different_content() {
        assert!(!pmatch("foo.com", "bar.com"));
    }

    #[test]
    fn test_pmatch_empty() {
        assert!(pmatch("", ""));
        assert!(!pmatch("a", ""));
        assert!(!pmatch("", "a"));
    }

    // ---------------------------------------------------------------
    // cert_hostcheck — exact matching
    // ---------------------------------------------------------------

    #[test]
    fn test_exact_match() {
        assert!(cert_hostcheck("www.example.com", "www.example.com"));
    }

    #[test]
    fn test_exact_match_case_insensitive() {
        assert!(cert_hostcheck("WWW.EXAMPLE.COM", "www.example.com"));
        assert!(cert_hostcheck("www.example.com", "WWW.EXAMPLE.COM"));
    }

    #[test]
    fn test_exact_match_trailing_dot_pattern() {
        assert!(cert_hostcheck("www.example.com.", "www.example.com"));
    }

    #[test]
    fn test_exact_match_trailing_dot_hostname() {
        assert!(cert_hostcheck("www.example.com", "www.example.com."));
    }

    #[test]
    fn test_exact_match_both_trailing_dots() {
        assert!(cert_hostcheck("www.example.com.", "www.example.com."));
    }

    // ---------------------------------------------------------------
    // cert_hostcheck — wildcard matching
    // ---------------------------------------------------------------

    #[test]
    fn test_wildcard_match_basic() {
        assert!(cert_hostcheck("*.example.com", "foo.example.com"));
        assert!(cert_hostcheck("*.example.com", "bar.example.com"));
        assert!(cert_hostcheck("*.example.com", "a.example.com"));
    }

    #[test]
    fn test_wildcard_no_match_bare_domain() {
        // `*.example.com` must not match `example.com` (no label to replace)
        assert!(!cert_hostcheck("*.example.com", "example.com"));
    }

    #[test]
    fn test_wildcard_no_match_multi_label() {
        // Wildcard replaces exactly one label — must not match two labels.
        assert!(!cert_hostcheck("*.example.com", "sub.foo.example.com"));
    }

    #[test]
    fn test_wildcard_too_broad() {
        // `*.com` has only one dot — must not match via wildcard.
        assert!(!cert_hostcheck("*.com", "example.com"));
    }

    #[test]
    fn test_wildcard_ip_literal_rejection() {
        // Wildcards must never match IP address literals.
        assert!(!cert_hostcheck("*.168.1.1", "192.168.1.1"));
        assert!(!cert_hostcheck("*.example.com", "192.168.1.1"));
    }

    #[test]
    fn test_wildcard_hostname_starts_with_dot() {
        assert!(!cert_hostcheck("*.example.com", ".example.com"));
    }

    // ---------------------------------------------------------------
    // cert_hostcheck — partial wildcard rejection
    // ---------------------------------------------------------------

    #[test]
    fn test_partial_wildcard_prefix() {
        // `a*.example.com` is a partial wildcard — treated as literal.
        assert!(!cert_hostcheck("a*.example.com", "ab.example.com"));
    }

    #[test]
    fn test_partial_wildcard_suffix() {
        // `*b.example.com` is a partial wildcard — treated as literal.
        assert!(!cert_hostcheck("*b.example.com", "ab.example.com"));
    }

    #[test]
    fn test_partial_wildcard_middle() {
        // `a*b.example.com` is a partial wildcard — treated as literal.
        assert!(!cert_hostcheck("a*b.example.com", "aXb.example.com"));
    }

    // ---------------------------------------------------------------
    // cert_hostcheck — input validation
    // ---------------------------------------------------------------

    #[test]
    fn test_empty_pattern() {
        assert!(!cert_hostcheck("", "example.com"));
    }

    #[test]
    fn test_empty_hostname() {
        assert!(!cert_hostcheck("example.com", ""));
    }

    #[test]
    fn test_both_empty() {
        assert!(!cert_hostcheck("", ""));
    }

    // ---------------------------------------------------------------
    // cert_hostcheck — case sensitivity with wildcards
    // ---------------------------------------------------------------

    #[test]
    fn test_wildcard_case_insensitive() {
        assert!(cert_hostcheck("*.EXAMPLE.COM", "foo.example.com"));
        assert!(cert_hostcheck("*.example.com", "FOO.EXAMPLE.COM"));
    }

    // ---------------------------------------------------------------
    // cert_hostcheck — trailing dot with wildcards
    // ---------------------------------------------------------------

    #[test]
    fn test_wildcard_trailing_dot() {
        assert!(cert_hostcheck("*.example.com.", "foo.example.com"));
        assert!(cert_hostcheck("*.example.com", "foo.example.com."));
    }

    // ---------------------------------------------------------------
    // normalize_hostname tests
    // ---------------------------------------------------------------

    #[test]
    fn test_normalize_lowercase() {
        assert_eq!(normalize_hostname("WWW.EXAMPLE.COM"), "www.example.com");
    }

    #[test]
    fn test_normalize_strip_trailing_dot() {
        assert_eq!(normalize_hostname("www.example.com."), "www.example.com");
    }

    #[test]
    fn test_normalize_combined() {
        assert_eq!(
            normalize_hostname("WWW.Example.COM."),
            "www.example.com"
        );
    }

    #[test]
    fn test_normalize_already_normal() {
        assert_eq!(normalize_hostname("example.com"), "example.com");
    }

    #[test]
    fn test_normalize_empty() {
        assert_eq!(normalize_hostname(""), "");
    }

    #[test]
    fn test_normalize_single_char() {
        assert_eq!(normalize_hostname("A"), "a");
    }

    #[test]
    fn test_normalize_only_dot() {
        assert_eq!(normalize_hostname("."), "");
    }

    // ---------------------------------------------------------------
    // MAX_HOSTNAME_LEN constant
    // ---------------------------------------------------------------

    #[test]
    fn test_max_hostname_len() {
        assert_eq!(MAX_HOSTNAME_LEN, 253);
    }
}
