//! No-proxy hostname/IP matching for the `NO_PROXY` / `no_proxy` environment variable.
//!
//! Determines whether a given hostname or IP address matches any entry in a
//! comma-separated no-proxy list. When a match is found, the proxy should be
//! bypassed for that host.
//!
//! # Supported Match Types
//!
//! - **Hostname suffix matching** — e.g., `.example.com` matches `sub.example.com`
//! - **IPv4 CIDR matching** — e.g., `192.168.1.0/24`
//! - **IPv6 CIDR matching** — e.g., `fe80::/10`
//! - **Wildcard** — `*` bypasses the proxy for all hosts
//!
//! # C Source Mapping
//!
//! | Rust function   | C function                                    |
//! |-----------------|-----------------------------------------------|
//! | `check_noproxy` | `Curl_check_noproxy` (`lib/noproxy.c:182-260`) |
//! | `cidr4_match`   | `Curl_cidr4_match` (`lib/noproxy.c:44-75`)     |
//! | `cidr6_match`   | `Curl_cidr6_match` (`lib/noproxy.c:77-110`)    |

use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Classification of a name as either a hostname or an IP address.
///
/// Mirrors the C `enum nametype` from `lib/noproxy.c:112-116`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameType {
    /// A hostname (not parseable as an IP address).
    Host,
    /// An IPv4 address.
    Ipv4,
    /// An IPv6 address.
    Ipv6,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Classify a name string as a hostname, IPv4 address, or IPv6 address.
///
/// Attempts to parse the name as an IPv4 address first (via
/// [`Ipv4Addr::from_str`]), then IPv6 (via [`Ipv6Addr::from_str`]).
/// If neither succeeds, the name is classified as a hostname.
///
/// Replaces the C classification block in `Curl_check_noproxy`
/// (`lib/noproxy.c:208-218`) which uses `curlx_inet_pton(AF_INET/AF_INET6)`.
fn classify_name(name: &str) -> NameType {
    if name.parse::<Ipv4Addr>().is_ok() {
        NameType::Ipv4
    } else if name.parse::<Ipv6Addr>().is_ok() {
        NameType::Ipv6
    } else {
        NameType::Host
    }
}

/// Strip surrounding `[` and `]` brackets from a string.
///
/// Returns the inner content only when **both** the leading `[` and trailing
/// `]` are present; otherwise returns the original string unchanged.
///
/// Used to normalise IPv6 address literals that arrive in URL bracket
/// notation (e.g. `[::1]` → `::1`).
fn strip_brackets(s: &str) -> &str {
    if let Some(inner) = s.strip_prefix('[') {
        inner.strip_suffix(']').unwrap_or(s)
    } else {
        s
    }
}

/// Match a hostname against a no-proxy pattern using suffix matching.
///
/// Both the hostname and pattern have leading/trailing dots stripped before
/// comparison.  The pattern matches if:
///
/// 1. It equals the hostname exactly (case-insensitive), **or**
/// 2. It is a suffix of the hostname at a **dot boundary** (case-insensitive).
///
/// # Matching rules (from C comments in `lib/noproxy.c:132-144`):
///
/// ```text
/// A: "example.com"     matches pattern "example.com"
/// B: "www.example.com" matches pattern "example.com"  (dot-boundary suffix)
/// C: "nonexample.com"  does NOT match  "example.com"  (no dot boundary)
/// ```
fn match_host(name: &str, token: &str) -> bool {
    if name.is_empty() || token.is_empty() {
        return false;
    }

    // Strip trailing dot from token (pattern).
    // Matches C: if(token[tokenlen - 1] == '.') tokenlen--;
    let token = token.strip_suffix('.').unwrap_or(token);
    if token.is_empty() {
        return false;
    }

    // Strip leading dot from token.
    // Matches C: if(tokenlen && (*token == '.')) { token++; tokenlen--; }
    let token = token.strip_prefix('.').unwrap_or(token);
    if token.is_empty() {
        return false;
    }

    let name_len = name.len();
    let token_len = token.len();

    if token_len == name_len {
        // Case A: exact match (case-insensitive).
        // Matches C: curl_strnequal(token, name, namelen)
        name.eq_ignore_ascii_case(token)
    } else if token_len < name_len {
        // Case B: suffix match at a dot boundary.
        // The character in `name` immediately before the matching suffix must
        // be a `.` — this prevents "nonexample.com" from matching "example.com".
        // Matches C: (name[namelen - tokenlen - 1] == '.') &&
        //            curl_strnequal(token, name + (namelen - tokenlen), tokenlen)
        let boundary_idx = name_len - token_len - 1;
        name.as_bytes()[boundary_idx] == b'.'
            && name[name_len - token_len..].eq_ignore_ascii_case(token)
    } else {
        // Case C: token is longer than name — cannot match.
        false
    }
}

/// Parse CIDR notation from a no-proxy entry and delegate to the appropriate
/// CIDR matching function.
///
/// If the entry contains a `/`, the part after it is parsed as the prefix
/// length (number of network bits).  Otherwise, `bits` defaults to `0` which
/// triggers exact-address comparison in the CIDR functions.
///
/// Replicates `match_ip()` from `lib/noproxy.c:148-176`.
fn match_ip(name: &str, token: &str, name_type: NameType) -> bool {
    // C code: if(tokenlen >= sizeof(checkip)) return FALSE;  [checkip is char[128]]
    if token.len() >= 128 {
        return false;
    }

    let (network, bits) = if let Some(slash_pos) = token.find('/') {
        let raw_network = &token[..slash_pos];
        let bits_str = &token[slash_pos + 1..];

        // Parse prefix length.  Must be a valid non-negative integer ≤ 128.
        // Matches C: curlx_str_number(&p, &value, 128) — rejects non-numeric,
        // values > 128, and any trailing content after the number.
        let bits: u32 = match bits_str.parse() {
            Ok(b) => b,
            Err(_) => return false,
        };
        if bits > 128 {
            return false;
        }

        // Strip brackets from the network portion (e.g. "[::1]" → "::1").
        (strip_brackets(raw_network), bits)
    } else {
        // No CIDR suffix — bits = 0 triggers exact match in the CIDR functions.
        (strip_brackets(token), 0u32)
    };

    match name_type {
        NameType::Ipv4 => cidr4_match(name, network, bits),
        NameType::Ipv6 => cidr6_match(name, network, bits),
        NameType::Host => false,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check whether the given IPv4 address falls within the specified CIDR range.
///
/// Parses both `ipv4` and `network` as [`Ipv4Addr`] values, then compares the
/// first `bits` of both addresses under a bitmask.
///
/// # Behaviour
///
/// | `bits` value | Semantics                                  |
/// |--------------|--------------------------------------------|
/// | `0`          | Exact address comparison (same as `32`)    |
/// | `1..=31`     | CIDR prefix comparison with mask           |
/// | `32`         | Exact address comparison                   |
/// | `> 32`       | Returns `false` (invalid prefix length)    |
///
/// Invalid IP address strings cause the function to return `false`.
///
/// Replaces `Curl_cidr4_match()` from `lib/noproxy.c:44-75`.
pub fn cidr4_match(ipv4: &str, network: &str, bits: u32) -> bool {
    // C: if(bits > 32) return FALSE;
    if bits > 32 {
        return false;
    }

    let addr: Ipv4Addr = match ipv4.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let net: Ipv4Addr = match network.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    // Convert to a host-order u32 for bitmask operations.
    // `Ipv4Addr::octets()` returns bytes in big-endian (network) order,
    // so `u32::from_be_bytes` gives the "natural" value — equivalent to
    // the C code's `htonl(inet_pton_result)`.
    let addr_u32 = u32::from_be_bytes(addr.octets());
    let net_u32 = u32::from_be_bytes(net.octets());

    if bits != 0 && bits != 32 {
        // Apply CIDR mask: shift 0xFFFFFFFF left by (32 − bits) to zero out
        // the host portion.
        // Matches C: unsigned int mask = 0xffffffff << (32 - bits);
        let mask = 0xFFFF_FFFFu32 << (32 - bits);
        // If any masked bit differs, the addresses are in different networks.
        // Matches C: if((haddr ^ hcheck) & mask) return FALSE; return TRUE;
        (addr_u32 ^ net_u32) & mask == 0
    } else {
        // bits == 0 (no CIDR suffix, exact match) or bits == 32 (full /32).
        // Matches C: return address == check;
        addr_u32 == net_u32
    }
}

/// Check whether the given IPv6 address falls within the specified CIDR range.
///
/// Parses both `ipv6` and `network` as [`Ipv6Addr`] values, then performs a
/// byte-by-byte comparison of the first `bits` of both addresses.
///
/// # Behaviour
///
/// | `bits` value | Semantics                                  |
/// |--------------|--------------------------------------------|
/// | `0`          | Treated as `128` (exact match, C compat)   |
/// | `1..=128`    | Prefix comparison over `bits` bits         |
/// | `> 128`      | Returns `false` (invalid prefix length)    |
///
/// Invalid IP address strings cause the function to return `false`.
///
/// Replaces `Curl_cidr6_match()` from `lib/noproxy.c:77-110`.
pub fn cidr6_match(ipv6: &str, network: &str, bits: u32) -> bool {
    // C: if(!bits) bits = 128;
    let bits = if bits == 0 { 128 } else { bits };

    let full_bytes = (bits / 8) as usize;
    let rest = bits & 0x07;

    // Validate prefix length: must be ≤ 128.
    // Matches C: if((bytes > 16) || ((bytes == 16) && rest)) return FALSE;
    if full_bytes > 16 || (full_bytes == 16 && rest != 0) {
        return false;
    }

    let addr: Ipv6Addr = match ipv6.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let net: Ipv6Addr = match network.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let addr_bytes = addr.octets();
    let net_bytes = net.octets();

    // Compare full bytes (leading bytes that are entirely within the prefix).
    // Matches C: if(bytes && memcmp(address, check, bytes)) return FALSE;
    if full_bytes > 0 && addr_bytes[..full_bytes] != net_bytes[..full_bytes] {
        return false;
    }

    // Compare partial byte at the boundary using a bitmask.
    // Matches C: if(rest && ((address[bytes] ^ check[bytes]) &
    //                        (0xff << (8 - rest)))) return FALSE;
    if rest != 0 {
        let mask: u8 = 0xFF << (8 - rest);
        if (addr_bytes[full_bytes] ^ net_bytes[full_bytes]) & mask != 0 {
            return false;
        }
    }

    true
}

/// Check whether a hostname or IP address should bypass the proxy.
///
/// Returns `true` if `name` matches any entry in the comma-separated
/// `no_proxy` list, meaning the proxy should **not** be used for this host.
///
/// # Matching Rules
///
/// - If `name` or `no_proxy` is empty, returns `false` (use proxy).
/// - If `no_proxy` is exactly `"*"`, returns `true` (bypass all).
/// - IPv6 names may be enclosed in brackets (`[::1]`); brackets are stripped
///   before classification.
/// - **Hostnames** are matched using case-insensitive suffix matching at dot
///   boundaries (e.g., pattern `example.com` matches `sub.example.com` but
///   not `notexample.com`).
/// - **IPv4 addresses** are matched using exact comparison or CIDR notation
///   (e.g., `192.168.1.0/24`).
/// - **IPv6 addresses** are matched using exact comparison or CIDR notation
///   (e.g., `fe80::/10`).
///
/// # C Source Mapping
///
/// Replaces `Curl_check_noproxy()` from `lib/noproxy.c:182-260`.
pub fn check_noproxy(name: &str, no_proxy: &str) -> bool {
    // Empty name: nothing to match (e.g. FILE transfer with no host).
    // Matches C: if(!name || name[0] == '\0') return FALSE;
    if name.is_empty() {
        return false;
    }

    // Empty no_proxy list: no entries to match → use proxy.
    // Matches C: if(no_proxy && no_proxy[0]) { ... } return FALSE;
    if no_proxy.is_empty() {
        return false;
    }

    // Wildcard: entire no_proxy string is "*" → bypass proxy for everything.
    // Matches C: if(!strcmp("*", no_proxy)) return TRUE;
    if no_proxy == "*" {
        return true;
    }

    // Strip brackets from IPv6 names like "[::1]".
    // In the C codebase callers strip brackets before invoking
    // Curl_check_noproxy; in Rust the function handles it directly for
    // ergonomic use from URL-parsing code that retains bracket notation.
    let name = strip_brackets(name);

    // Classify name as hostname, IPv4, or IPv6.
    // Matches C: inet_pton(AF_INET, name, ...) / inet_pton(AF_INET6, name, ...)
    let name_type = classify_name(name);

    // For hostnames, strip a single trailing dot (adjusting the effective
    // comparison length).
    // Matches C: if(name[namelen - 1] == '.') namelen--;
    let name = if name_type == NameType::Host {
        name.strip_suffix('.').unwrap_or(name)
    } else {
        name
    };

    // Iterate over comma-separated entries in the no_proxy list.
    // Matches C loop: tokenise by commas, trim whitespace around each entry.
    for segment in no_proxy.split(',') {
        let token = segment.trim();
        if token.is_empty() {
            continue;
        }

        let matched = match name_type {
            NameType::Host => match_host(name, token),
            NameType::Ipv4 | NameType::Ipv6 => match_ip(name, token, name_type),
        };

        if matched {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── cidr4_match ────────────────────────────────────────────────────

    #[test]
    fn cidr4_exact_match_bits_zero() {
        // bits=0 triggers raw address comparison (no CIDR mask).
        assert!(cidr4_match("192.168.1.1", "192.168.1.1", 0));
        assert!(!cidr4_match("192.168.1.1", "192.168.1.2", 0));
    }

    #[test]
    fn cidr4_exact_match_bits_32() {
        assert!(cidr4_match("192.168.1.1", "192.168.1.1", 32));
        assert!(!cidr4_match("192.168.1.1", "192.168.1.2", 32));
    }

    #[test]
    fn cidr4_subnet_24() {
        assert!(cidr4_match("192.168.1.100", "192.168.1.0", 24));
        assert!(cidr4_match("192.168.1.255", "192.168.1.0", 24));
        assert!(cidr4_match("192.168.1.0", "192.168.1.0", 24));
        assert!(!cidr4_match("192.168.2.100", "192.168.1.0", 24));
    }

    #[test]
    fn cidr4_subnet_16() {
        assert!(cidr4_match("172.16.0.1", "172.16.255.255", 16));
        assert!(!cidr4_match("172.17.0.1", "172.16.0.0", 16));
    }

    #[test]
    fn cidr4_subnet_8() {
        assert!(cidr4_match("10.0.0.1", "10.255.255.255", 8));
        assert!(!cidr4_match("11.0.0.1", "10.0.0.0", 8));
    }

    #[test]
    fn cidr4_subnet_1() {
        // /1 checks only the most significant bit.
        assert!(cidr4_match("0.0.0.0", "127.255.255.255", 1));
        assert!(!cidr4_match("128.0.0.0", "0.0.0.0", 1));
    }

    #[test]
    fn cidr4_invalid_bits() {
        assert!(!cidr4_match("192.168.1.1", "192.168.1.0", 33));
    }

    #[test]
    fn cidr4_invalid_addresses() {
        assert!(!cidr4_match("invalid", "192.168.1.0", 24));
        assert!(!cidr4_match("192.168.1.1", "invalid", 24));
        assert!(!cidr4_match("", "192.168.1.0", 24));
    }

    // ── cidr6_match ────────────────────────────────────────────────────

    #[test]
    fn cidr6_exact_match_bits_128() {
        assert!(cidr6_match("::1", "::1", 128));
        assert!(!cidr6_match("::1", "::2", 128));
    }

    #[test]
    fn cidr6_exact_match_bits_zero() {
        // bits=0 is normalised to 128 (full match).
        assert!(cidr6_match("::1", "::1", 0));
        assert!(!cidr6_match("::1", "::2", 0));
    }

    #[test]
    fn cidr6_subnet_10() {
        assert!(cidr6_match("fe80::1", "fe80::", 10));
        assert!(cidr6_match("fe80::ffff", "fe80::", 10));
        // febf:: shares the top 10 bits with fe80::
        assert!(cidr6_match("febf::1", "fe80::", 10));
        // fec0:: differs in the 10th bit.
        assert!(!cidr6_match("fec0::1", "fe80::", 10));
    }

    #[test]
    fn cidr6_subnet_64() {
        assert!(cidr6_match(
            "2001:db8::1",
            "2001:db8::",
            64
        ));
        assert!(!cidr6_match(
            "2001:db9::1",
            "2001:db8::",
            64
        ));
    }

    #[test]
    fn cidr6_invalid_bits() {
        assert!(!cidr6_match("::1", "::1", 129));
    }

    #[test]
    fn cidr6_invalid_addresses() {
        assert!(!cidr6_match("invalid", "::1", 128));
        assert!(!cidr6_match("::1", "invalid", 128));
    }

    // ── match_host (internal helper) ───────────────────────────────────

    #[test]
    fn host_exact_match() {
        assert!(match_host("example.com", "example.com"));
        assert!(match_host("example.com", "EXAMPLE.COM"));
        assert!(match_host("Example.Com", "example.com"));
    }

    #[test]
    fn host_suffix_match_at_dot_boundary() {
        assert!(match_host("sub.example.com", "example.com"));
        assert!(match_host("sub.example.com", ".example.com"));
        assert!(match_host("deep.sub.example.com", "example.com"));
    }

    #[test]
    fn host_no_match_without_dot_boundary() {
        // "notexample.com" does NOT have a '.' before "example.com".
        assert!(!match_host("notexample.com", "example.com"));
        assert!(!match_host("notexample.com", ".example.com"));
    }

    #[test]
    fn host_trailing_dot_on_pattern() {
        assert!(match_host("example.com", "example.com."));
        assert!(match_host("sub.example.com", ".example.com."));
    }

    #[test]
    fn host_leading_dot_matches_exact() {
        // ".example.com" should match "example.com" itself (after dot strip).
        assert!(match_host("example.com", ".example.com"));
    }

    #[test]
    fn host_empty_inputs() {
        assert!(!match_host("", "example.com"));
        assert!(!match_host("example.com", ""));
        assert!(!match_host("", ""));
    }

    #[test]
    fn host_pattern_longer_than_name() {
        assert!(!match_host("com", "example.com"));
    }

    #[test]
    fn host_evil_suffix() {
        // "example.com.evil.org" must NOT match "example.com".
        assert!(!match_host("example.com.evil.org", "example.com"));
    }

    // ── check_noproxy (integration) ───────────────────────────────────

    #[test]
    fn noproxy_hostname_with_leading_dot() {
        assert!(check_noproxy("foo.example.com", ".example.com"));
        assert!(check_noproxy("example.com", ".example.com"));
        assert!(!check_noproxy("notexample.com", ".example.com"));
    }

    #[test]
    fn noproxy_hostname_without_leading_dot() {
        assert!(check_noproxy("foo.example.com", "example.com"));
        assert!(check_noproxy("example.com", "example.com"));
        assert!(!check_noproxy("notexample.com", "example.com"));
    }

    #[test]
    fn noproxy_ipv4_cidr() {
        assert!(check_noproxy("192.168.1.100", "192.168.1.0/24"));
        assert!(!check_noproxy("192.168.2.100", "192.168.1.0/24"));
    }

    #[test]
    fn noproxy_ipv4_exact() {
        assert!(check_noproxy("192.168.1.1", "192.168.1.1"));
        assert!(!check_noproxy("192.168.1.1", "192.168.1.2"));
    }

    #[test]
    fn noproxy_ipv6_cidr() {
        assert!(check_noproxy("::1", "::1/128"));
        assert!(check_noproxy("fe80::1", "fe80::/10"));
    }

    #[test]
    fn noproxy_ipv6_exact() {
        assert!(check_noproxy("::1", "::1"));
    }

    #[test]
    fn noproxy_ipv6_brackets_on_name() {
        assert!(check_noproxy("[::1]", "::1"));
        assert!(check_noproxy("[::1]", "::1/128"));
    }

    #[test]
    fn noproxy_wildcard() {
        assert!(check_noproxy("anything", "*"));
        assert!(check_noproxy("192.168.1.1", "*"));
        assert!(check_noproxy("::1", "*"));
    }

    #[test]
    fn noproxy_wildcard_not_as_substring() {
        // Wildcard only triggers when the entire no_proxy string is "*".
        // "*.example.com" is not a valid wildcard — it is treated as a
        // hostname pattern (and likely won't match due to the literal '*').
        assert!(!check_noproxy("foo.example.com", "*.example.com"));
    }

    #[test]
    fn noproxy_empty_inputs() {
        assert!(!check_noproxy("host", ""));
        assert!(!check_noproxy("", "example.com"));
        assert!(!check_noproxy("", ""));
    }

    #[test]
    fn noproxy_multiple_entries() {
        assert!(check_noproxy("b.com", "a.com, b.com, c.com"));
        assert!(check_noproxy("sub.b.com", "a.com, b.com, c.com"));
        assert!(!check_noproxy("d.com", "a.com, b.com, c.com"));
    }

    #[test]
    fn noproxy_whitespace_around_entries() {
        assert!(check_noproxy("example.com", "  example.com  "));
        assert!(check_noproxy(
            "example.com",
            "other.com , example.com , more.com"
        ));
    }

    #[test]
    fn noproxy_trailing_dot_on_hostname() {
        assert!(check_noproxy("example.com.", "example.com"));
        assert!(check_noproxy("sub.example.com.", ".example.com"));
    }

    #[test]
    fn noproxy_consecutive_commas() {
        assert!(check_noproxy("b.com", "a.com,,b.com"));
        assert!(check_noproxy("b.com", "a.com,,,b.com"));
    }

    #[test]
    fn noproxy_mixed_types() {
        let list = "192.168.1.0/24, .internal.corp, ::1";
        assert!(check_noproxy("192.168.1.50", list));
        assert!(check_noproxy("host.internal.corp", list));
        assert!(check_noproxy("::1", list));
        assert!(!check_noproxy("10.0.0.1", list));
        assert!(!check_noproxy("external.com", list));
    }

    // ── classify_name (internal helper) ────────────────────────────────

    #[test]
    fn classify_ipv4() {
        assert_eq!(classify_name("192.168.1.1"), NameType::Ipv4);
        assert_eq!(classify_name("0.0.0.0"), NameType::Ipv4);
        assert_eq!(classify_name("255.255.255.255"), NameType::Ipv4);
    }

    #[test]
    fn classify_ipv6() {
        assert_eq!(classify_name("::1"), NameType::Ipv6);
        assert_eq!(classify_name("fe80::1"), NameType::Ipv6);
        assert_eq!(classify_name("2001:db8::1"), NameType::Ipv6);
    }

    #[test]
    fn classify_host() {
        assert_eq!(classify_name("example.com"), NameType::Host);
        assert_eq!(classify_name("not-an-ip"), NameType::Host);
        assert_eq!(classify_name(""), NameType::Host);
    }

    // ── strip_brackets (internal helper) ───────────────────────────────

    #[test]
    fn brackets_both_present() {
        assert_eq!(strip_brackets("[::1]"), "::1");
        assert_eq!(strip_brackets("[fe80::1]"), "fe80::1");
        assert_eq!(strip_brackets("[]"), "");
    }

    #[test]
    fn brackets_unbalanced() {
        assert_eq!(strip_brackets("[::1"), "[::1");
        assert_eq!(strip_brackets("::1]"), "::1]");
    }

    #[test]
    fn brackets_none() {
        assert_eq!(strip_brackets("::1"), "::1");
        assert_eq!(strip_brackets("example.com"), "example.com");
    }
}
