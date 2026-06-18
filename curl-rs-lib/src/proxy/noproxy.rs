// SPDX-License-Identifier: curl
//
//! `NO_PROXY` / `CURLOPT_NOPROXY` host matcher.
//!
//! This module is the memory-safe Rust reimplementation of libcurl's
//! `lib/noproxy.c`. It answers a single question: *given a target host and the
//! resolved no-proxy list, must the proxy be bypassed for this host?* The
//! public entry point [`check_noproxy`] returns `true` when the host matches
//! the list — i.e. the proxy **must NOT** be used.
//!
//! # Behavioral parity (the C file is a REFERENCE oracle, not a transliteration)
//!
//! curl's no-proxy semantics are wire/behavior-observable and are exercised by
//! the immutable `tests/data` regression definitions, so the *results* of this
//! module for any input are byte-for-byte identical to curl 8.x (AAP §0.6 G6,
//! §0.8.2). In particular the three subtle rules that the suite pins down are
//! reproduced exactly:
//!
//! 1. **Tail-match boundary** — a shorter token only matches a longer host when
//!    it aligns on a label boundary, i.e. the host byte immediately before the
//!    matched suffix is a `.` (so `example.com` matches `www.example.com` but
//!    not `nonexample.com`).
//! 2. **`bits == 0` ⇒ exact match** — a CIDR token with a zero prefix length
//!    (the default when no `/bits` is given) means *exact address equality*,
//!    **not** match-all. (For IPv6 a zero is first promoted to a full `/128`,
//!    which is likewise an exact match.)
//! 3. **One-dot normalization** — exactly one leading and one trailing `.` are
//!    stripped from both the host and each token before comparison.
//!
//! # Memory safety
//!
//! Per the project mandate (AAP §0.7.1) this module contains **zero `unsafe`**
//! and is compiled under `#![forbid(unsafe_code)]`. IP literals are parsed with
//! [`std::net`] (`Ipv4Addr`/`Ipv6Addr::from_str`), the safe analogue of curl's
//! `inet_pton`; there is no raw FFI here.
//!
//! # Feature gating
//!
//! The whole of `lib/noproxy.c` is wrapped in `#ifndef CURL_DISABLE_PROXY`. The
//! Rust analogue is the `proxy` Cargo feature (default **on**): the parent
//! `proxy/mod.rs` declares this module under `#[cfg(feature = "proxy")]`, so a
//! `--no-default-features` build excludes the file entirely. Items here are
//! therefore *not* individually re-gated.
//!
//! # Environment passthrough
//!
//! This file does **not** read the environment. The caller (`mod.rs` /
//! `setopt` / `easy`) resolves the effective no-proxy string — `CURLOPT_NOPROXY`
//! overrides, otherwise the `NO_PROXY` / `no_proxy` environment variables are
//! honored (AAP §0.8.3 permits only those, plus `HOME`) — and passes the
//! already-resolved string in. The host is likewise passed **without a port**
//! (the caller strips it); no port handling happens here.

// Defensive, self-documenting restatement of the crate-root guarantee. `forbid`
// is idempotent with the crate root's `#![forbid(unsafe_code)]`, and keeps this
// module memory-safe even when inspected or compiled in isolation.
#![forbid(unsafe_code)]
// This is the foundational file of the `proxy` module (authored first; it has
// zero intra-folder dependencies). Its public surface mirrors curl's: the
// `UNITTEST`-exposed `Curl_cidr4_match` / `Curl_cidr6_match` become `pub`
// helpers, and the `Curl_check_noproxy` entry point is consumed by the sibling
// `proxy/mod.rs` (the which-proxy decision), which is authored in parallel. In
// a partially assembled workspace those consumers may not yet exist, so
// `dead_code` is allowed here to keep the module self-contained under the
// workspace's `-D warnings` gate. This masks no defect: every item below is
// reached either internally (the CIDR helpers via `match_ip`, the matchers via
// `check_noproxy`) or by the in-file test suite.
#![allow(dead_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::util::strcase::strncasecompare;
use crate::util::strparse::Str;

/// Returns `true` for the bytes curl's `ISBLANK` macro treats as blank: ASCII
/// space (`0x20`) and horizontal tab (`0x09`).
///
/// This is the exact blank set used by `curlx_str_passblanks`. Other whitespace
/// (newline `\n`, carriage return `\r`, form feed, vertical tab) is **not**
/// blank for no-proxy tokenization, matching curl. `strparse`'s own `is_blank`
/// is private, so the predicate is restated here.
#[inline]
const fn is_blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// How the target host was classified, mirroring curl's `enum nametype`.
///
/// The classification selects the matcher: a hostname is tail-matched against
/// each token ([`match_host`]); an IPv4/IPv6 literal is CIDR-matched
/// ([`match_ip`]).
#[derive(Clone, Copy)]
enum NameType {
    /// A regular hostname (not an IP literal).
    Host,
    /// An IPv4 address literal (curl's `TYPE_IPV4`).
    Ipv4,
    /// An IPv6 address literal (curl's `TYPE_IPV6`).
    Ipv6,
}

/// Returns `true` when `ipv4` lies within the `network`/`bits` IPv4 CIDR range.
///
/// Safe, behavior-exact port of curl's `Curl_cidr4_match` (exposed `pub` to
/// mirror the C `UNITTEST` export, and used internally by [`match_ip`]). Both
/// arguments are parsed as dotted-quad IPv4 literals; either failing to parse
/// yields `false`.
///
/// # Prefix semantics (curl quirk preserved)
///
/// * `bits > 32` is rejected as strange input (`false`).
/// * `bits` in `1..=31` compares only the high `bits` of the address against
///   the network, using a big-endian prefix mask.
/// * `bits == 32` **or** `bits == 0` both require **exact** address equality.
///   The `bits == 0` case is curl's documented quirk: a zero prefix means an
///   exact match, *not* a match-all.
///
/// `u32::from(Ipv4Addr)` places the first octet in the most-significant byte,
/// which is identical to curl's `htonl(inet_pton(AF_INET, ...))` host-order
/// value — so the masked comparison matches curl bit-for-bit.
#[must_use]
pub fn cidr4_match(ipv4: &str, network: &str, bits: u32) -> bool {
    if bits > 32 {
        // Strange input: no valid IPv4 prefix is longer than 32 bits.
        return false;
    }

    let Ok(address) = ipv4.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(check) = network.parse::<Ipv4Addr>() else {
        return false;
    };

    // Big-endian integer form: first octet in the high byte (== curl's htonl).
    let address = u32::from(address);
    let check = u32::from(check);

    if bits != 0 && bits != 32 {
        // Compare only the high `bits`. `32 - bits` is in `1..=31` here, so the
        // shift is always well-defined (never `<< 32`).
        let mask = 0xffff_ffff_u32 << (32 - bits);
        ((address ^ check) & mask) == 0
    } else {
        // `bits == 32` (full-length) or `bits == 0` (curl quirk): exact match.
        address == check
    }
}

/// Returns `true` when `ipv6` lies within the `network`/`bits` IPv6 CIDR range.
///
/// Safe, behavior-exact port of curl's `Curl_cidr6_match` (exposed `pub` to
/// mirror the C `UNITTEST` export, and used internally by [`match_ip`]). Both
/// arguments are parsed as IPv6 literals; either failing to parse yields
/// `false`.
///
/// # Prefix semantics (curl quirk preserved)
///
/// * `bits == 0` is first promoted to a full `/128` (curl: a zero prefix
///   defaults to a complete match for IPv6).
/// * The prefix is split into whole bytes (`bits / 8`) plus a partial,
///   high-order remainder of `bits % 8` bits.
/// * A `bits` that needs more than 16 bytes — `bytes > 16`, or `bytes == 16`
///   with a non-zero partial byte — is rejected (`false`).
///
/// curl gates this on `USE_IPV6`; in Rust `std::net::Ipv6Addr` is always
/// available, so the algorithm is unconditional but otherwise identical.
#[must_use]
pub fn cidr6_match(ipv6: &str, network: &str, bits: u32) -> bool {
    // A zero prefix length defaults to a full /128 match.
    let bits = if bits == 0 { 128 } else { bits };

    let bytes = (bits / 8) as usize;
    let rest = bits & 0x07;
    if bytes > 16 || (bytes == 16 && rest != 0) {
        return false;
    }

    let Ok(address) = ipv6.parse::<Ipv6Addr>() else {
        return false;
    };
    let Ok(check) = network.parse::<Ipv6Addr>() else {
        return false;
    };
    let address = address.octets();
    let check = check.octets();

    // Whole-byte portion of the prefix must match exactly.
    if bytes != 0 && address[..bytes] != check[..bytes] {
        return false;
    }

    // Partial trailing byte: compare only its top `rest` bits. When `rest != 0`
    // the earlier guard guarantees `bytes <= 15`, so `address[bytes]` is in
    // bounds. `0xff_u8 << (8 - rest)` keeps the high `rest` bits (the shift
    // amount is in `1..=7`); this equals curl's `0xff << (8 - rest)` masked
    // against the <= 0xff byte XOR.
    if rest != 0 {
        let mask = 0xff_u8 << (8 - rest);
        if ((address[bytes] ^ check[bytes]) & mask) != 0 {
            return false;
        }
    }

    true
}

/// Matches a single hostname `token` against the (already trailing-dot-stripped)
/// host `name`, returning `true` on a domain match.
///
/// Safe, behavior-exact port of curl's `match_host`. Both arguments are raw
/// bytes; comparison is ASCII case-insensitive via [`strncasecompare`] (curl's
/// `curl_strnequal`) because hosts reaching here are already ASCII/ACE
/// (punycode), never Unicode.
///
/// The caller guarantees the token is non-empty (the tokenizer only tests
/// tokens with `tokenlen > 0`). The matching proceeds as:
///
/// 1. strip exactly **one** trailing `.` from the token, then
/// 2. strip exactly **one** leading `.` from the token (only if anything
///    remains), then apply the three cases:
///    * **A — exact** (`tokenlen == namelen`): case-insensitive equality.
///    * **B — tail/domain** (`tokenlen < namelen`): the host byte just before
///      the candidate suffix must be `.` (label boundary) **and** the suffix
///      must equal the token case-insensitively.
///    * **C** (`tokenlen > namelen`): never a match.
fn match_host(token: &[u8], name: &[u8]) -> bool {
    let mut token = token;

    // (1) Ignore one trailing dot in the token (e.g. `example.com.`).
    if token.last() == Some(&b'.') {
        token = &token[..token.len() - 1];
    }
    // (2) Ignore one leading dot in the token (e.g. `.example.com`), but only
    // when something remains after step 1.
    if !token.is_empty() && token[0] == b'.' {
        token = &token[1..];
    }

    let tokenlen = token.len();
    let namelen = name.len();

    if tokenlen == namelen {
        // Case A: exact match.
        strncasecompare(token, name, namelen)
    } else if tokenlen < namelen {
        // Case B: tail-match the domain. The token must align on a label
        // boundary, i.e. the host byte immediately preceding the suffix is a
        // dot. `namelen - tokenlen >= 1` here, so the index cannot underflow.
        name[namelen - tokenlen - 1] == b'.'
            && strncasecompare(token, &name[namelen - tokenlen..], tokenlen)
    } else {
        // Case C: token longer than the host — cannot match.
        false
    }
}

/// Matches an IP-literal host `name` against a CIDR `token` of the form
/// `address` or `address/bits`, returning `true` on a match.
///
/// Safe, behavior-exact port of curl's `match_ip`. `nametype` selects the
/// address family ([`NameType::Ipv6`] ⇒ [`cidr6_match`], otherwise
/// [`cidr4_match`] — curl's `else` branch, since hostnames never reach here).
/// The `name` passed in is the **original** host string (not the
/// trailing-dot-stripped host used for hostname matching); both `name` and the
/// token address are (re-)parsed as IPs inside the CIDR helpers.
fn match_ip(nametype: NameType, token: &[u8], name: &str) -> bool {
    // curl copies the token into a fixed `char checkip[128]` buffer; a token
    // that would not fit (with its NUL terminator) simply cannot match.
    if token.len() >= 128 {
        return false;
    }

    // Split off an optional `/bits` suffix at the FIRST '/'.
    let (addr_bytes, bits) = match token.iter().position(|&b| b == b'/') {
        Some(slash) => {
            // Parse the prefix length exactly as curl does:
            //   `if(curlx_str_number(&p, &value, 128) || *p) return FALSE;`
            // i.e. a decimal number capped at 128, rejecting any trailing
            // characters. A too-large-for-this-family value (e.g. 100 for IPv4)
            // passes here and is rejected inside the CIDR helper below.
            let mut cursor = Str::from_bytes(&token[slash + 1..]);
            let mut value: u64 = 0;
            if cursor.curlx_str_number(&mut value, 128).is_err() || !cursor.is_empty() {
                return false;
            }
            // `value <= 128` (the parse cap), so the cast cannot truncate.
            (&token[..slash], value as u32)
        }
        // No slash ⇒ `bits == 0`, which the CIDR helpers interpret as an exact
        // address match (IPv4) or a full /128 (IPv6).
        None => (token, 0u32),
    };

    // The address portion is ASCII; reinterpret it as `&str` for std IP
    // parsing. A non-UTF-8 slice (impossible for a token sourced from a `&str`,
    // but handled safely) cannot be an IP literal, so it never matches.
    let Ok(addr) = std::str::from_utf8(addr_bytes) else {
        return false;
    };

    match nametype {
        NameType::Ipv6 => cidr6_match(name, addr, bits),
        // TYPE_HOST never reaches `match_ip`; this is curl's IPv4 `else` arm.
        NameType::Ipv4 | NameType::Host => cidr4_match(name, addr, bits),
    }
}

/// Checks whether `name` is covered by the no-proxy list `no_proxy`.
///
/// Returns `true` when the host matches and therefore the proxy **must NOT** be
/// used. This is the safe, behavior-exact port of curl's `Curl_check_noproxy`
/// and the module's public entry point (consumed by the sibling `proxy/mod.rs`
/// which-proxy decision).
///
/// The `no_proxy` argument is the **already-resolved** list (this function does
/// not consult the environment — see the module docs), a comma-separated set of
/// host patterns, IPs, or CIDR ranges, or a lone `*` to bypass all proxies.
/// `name` is the target host **without a port**.
///
/// # Algorithm
///
/// 1. An empty `name` (e.g. a `FILE` transfer with no host) never matches.
/// 2. An empty `no_proxy` never matches.
/// 3. A `no_proxy` equal to exactly `"*"` always matches (bypass everything).
/// 4. Otherwise the host is classified (IPv4 literal / IPv6 literal /
///    hostname — with one trailing dot ignored for hostnames only) and the
///    list is tokenized on commas, with surrounding ASCII blanks ignored. Each
///    non-empty token is tested with [`match_host`] or [`match_ip`]; the first
///    match short-circuits to `true`. A blank that is **not** followed by a
///    comma terminates the scan (a curl quirk preserved here), and runs of
///    consecutive commas yield empty tokens that are skipped.
#[must_use]
pub fn check_noproxy(name: &str, no_proxy: &str) -> bool {
    // (1) No hostname at all — nothing to interrogate the list with.
    if name.is_empty() {
        return false;
    }
    // (2) An empty no-proxy list never matches.
    if no_proxy.is_empty() {
        return false;
    }
    // (3) A lone asterisk overrides all proxy variables.
    if no_proxy == "*" {
        return true;
    }

    // (4) Classify the host. IPv4 is tried first, then IPv6, mirroring curl's
    // `inet_pton(AF_INET)` then `inet_pton(AF_INET6)` order.
    let name_bytes = name.as_bytes();
    let mut namelen = name_bytes.len();
    let nametype = if name.parse::<Ipv4Addr>().is_ok() {
        NameType::Ipv4
    } else if name.parse::<Ipv6Addr>().is_ok() {
        NameType::Ipv6
    } else {
        // Hostname: ignore exactly one trailing dot (the FQDN root label). This
        // strip happens ONLY in the host branch, never for IP literals.
        if name_bytes[namelen - 1] == b'.' {
            namelen -= 1;
        }
        NameType::Host
    };
    // The effective host slice used for hostname matching (trailing dot, if
    // any, removed). Unused for IP literals, which match on the original string.
    let name_eff = &name_bytes[..namelen];

    // Tokenize the comma/blank-separated list, walking it with the shared
    // `strparse` cursor so blank-skipping matches curl's `curlx_str_passblanks`
    // (ASCII space/tab only) exactly.
    let mut cursor = Str::from_bytes(no_proxy.as_bytes());
    while !cursor.is_empty() {
        // Skip leading blanks before the token.
        cursor.curlx_str_passblanks();

        // Capture the token: every byte up to the next blank or comma.
        let rest = cursor.curlx_str();
        let tokenlen = rest
            .iter()
            .position(|&b| is_blank(b) || b == b',')
            .unwrap_or(rest.len());

        if tokenlen > 0 {
            let token = &rest[..tokenlen];
            let matched = match nametype {
                NameType::Host => match_host(token, name_eff),
                // IPv4 / IPv6 literal hosts use CIDR matching.
                NameType::Ipv4 | NameType::Ipv6 => match_ip(nametype, token, name),
            };
            if matched {
                return true;
            }
        }

        // Advance past the token. `tokenlen <= rest.len()`, so this never fails;
        // the `Result` is intentionally discarded.
        let _ = cursor.curlx_str_nudge(tokenlen);

        // Skip blanks after the token; a non-comma here ends the scan.
        cursor.curlx_str_passblanks();
        if cursor.curlx_str().first() != Some(&b',') {
            break;
        }

        // Skip any number of consecutive commas (empty tokens are ignored).
        while cursor.curlx_str().first() == Some(&b',') {
            let _ = cursor.curlx_str_nudge(1);
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- check_noproxy: guard cases -------------------------------------

    #[test]
    fn empty_host_never_matches() {
        // A FILE transfer (no host) must never be considered in the list.
        assert!(!check_noproxy("", "example.com"));
        assert!(!check_noproxy("", "*"));
        assert!(!check_noproxy("", ""));
    }

    #[test]
    fn empty_no_proxy_never_matches() {
        assert!(!check_noproxy("example.com", ""));
        assert!(!check_noproxy("192.168.1.5", ""));
    }

    #[test]
    fn lone_asterisk_matches_everything() {
        assert!(check_noproxy("example.com", "*"));
        assert!(check_noproxy("192.168.1.5", "*"));
        assert!(check_noproxy("2001:db8::1", "*"));
    }

    #[test]
    fn asterisk_must_be_the_whole_string() {
        // "*" is only special as an exact whole-string match; embedded in a
        // list it is just a literal token that cannot match a real host.
        assert!(!check_noproxy("example.com", "*.example.com"));
        assert!(!check_noproxy("example.com", "*,foo.com"));
    }

    // ---- check_noproxy: hostname tail-matching --------------------------

    #[test]
    fn host_exact_and_tail_match() {
        // Case A: exact.
        assert!(check_noproxy("example.com", "example.com"));
        // Case B: tail/domain match on a label boundary.
        assert!(check_noproxy("www.example.com", "example.com"));
        assert!(check_noproxy("a.b.example.com", "example.com"));
    }

    #[test]
    fn host_non_label_boundary_does_not_match() {
        // The byte before the suffix is 'n', not '.', so this is NOT a match.
        assert!(!check_noproxy("nonexample.com", "example.com"));
        // Token longer than the host (case C) cannot match.
        assert!(!check_noproxy("com", "example.com"));
        assert!(check_noproxy("example.com", "com")); // but the host tail "com" does match
    }

    #[test]
    fn host_dot_normalization() {
        // One leading and one trailing dot are stripped from the token.
        assert!(check_noproxy("www.example.com", ".example.com."));
        assert!(check_noproxy("www.example.com", ".example.com"));
        assert!(check_noproxy("www.example.com", "example.com."));
        // A single trailing dot on the host itself is also stripped.
        assert!(check_noproxy("www.example.com.", "example.com"));
        assert!(check_noproxy("example.com.", "example.com"));
    }

    #[test]
    fn host_match_is_ascii_case_insensitive() {
        assert!(check_noproxy("EXAMPLE.com", "example.COM"));
        assert!(check_noproxy("WWW.Example.Com", "example.com"));
        assert!(check_noproxy("example.com", "ExAmPlE.cOm"));
    }

    // ---- check_noproxy: tokenizer ---------------------------------------

    #[test]
    fn tokenizer_handles_blanks_and_commas() {
        // Blanks around commas are ignored; empty tokens are skipped; the
        // matching token is the second entry.
        assert!(check_noproxy("a.com", " foo.com , a.com ,bar.com"));
        // Match the first and last entries too.
        assert!(check_noproxy("foo.com", "foo.com,a.com,bar.com"));
        assert!(check_noproxy("bar.com", "foo.com,a.com,bar.com"));
        // A host present in none of the tokens.
        assert!(!check_noproxy("nope.com", "foo.com,a.com,bar.com"));
    }

    #[test]
    fn tokenizer_tolerates_consecutive_and_edge_commas() {
        assert!(check_noproxy("a.com", "foo.com,,a.com"));
        assert!(check_noproxy("a.com", ",,a.com,,"));
        assert!(check_noproxy("a.com", ",a.com"));
        assert!(check_noproxy("a.com", "a.com,"));
        // Only commas / blanks ⇒ no real token ⇒ no match.
        assert!(!check_noproxy("a.com", ",,,"));
        assert!(!check_noproxy("a.com", "   "));
    }

    #[test]
    fn blank_not_before_comma_terminates_scan() {
        // curl quirk: after a token, blanks are skipped and if the next byte is
        // not a comma the scan stops. Here "a.com" is never reached because the
        // space after "example.com" is not followed by a comma.
        assert!(!check_noproxy("a.com", "example.com a.com"));
        // But the first token is still tested.
        assert!(check_noproxy("example.com", "example.com a.com"));
    }

    // ---- check_noproxy: IP-literal hosts via match_ip -------------------

    #[test]
    fn ipv4_host_cidr_token_matches() {
        // Second token's /24 range covers the host.
        assert!(check_noproxy("192.168.1.5", "10.0.0.0/8,192.168.1.0/24"));
        // Out of every listed range.
        assert!(!check_noproxy("192.168.2.5", "10.0.0.0/8,192.168.1.0/24"));
    }

    #[test]
    fn ipv4_host_exact_token_without_bits() {
        // No "/bits" ⇒ exact address equality.
        assert!(check_noproxy("192.168.1.5", "192.168.1.5"));
        assert!(!check_noproxy("192.168.1.6", "192.168.1.5"));
    }

    #[test]
    fn ipv6_host_cidr_token_matches() {
        assert!(check_noproxy("2001:db8::1", "2001:db8::/32"));
        assert!(check_noproxy("2001:db8::1", "2001:db8::1"));
        assert!(!check_noproxy("2001:dead::1", "2001:db8::/32"));
    }

    #[test]
    fn ip_family_mismatch_does_not_match() {
        // IPv4 host vs IPv6 token, and vice versa, never match.
        assert!(!check_noproxy("192.168.1.5", "2001:db8::/32"));
        assert!(!check_noproxy("2001:db8::1", "192.168.1.0/24"));
    }

    #[test]
    fn ip_literal_host_does_not_tail_match_hostname_token() {
        // An IP host is CIDR-matched, never hostname-tail-matched, so a textual
        // token that is not a valid IP cannot match it.
        assert!(!check_noproxy("192.168.1.5", "example.com"));
    }

    #[test]
    fn malformed_cidr_bits_rejected() {
        // Trailing junk after the bits is rejected (curl: `|| *p`).
        assert!(!check_noproxy("192.168.1.5", "192.168.1.0/24x"));
        // Multiple slashes ⇒ trailing characters after the first number.
        assert!(!check_noproxy("192.168.1.5", "192.168.1.0/24/8"));
        // Empty bits after the slash ⇒ no number ⇒ rejected.
        assert!(!check_noproxy("192.168.1.5", "192.168.1.0/"));
    }

    // ---- cidr4_match ----------------------------------------------------

    #[test]
    fn cidr4_prefix_matching() {
        assert!(cidr4_match("192.168.1.5", "192.168.1.0", 24));
        assert!(!cidr4_match("192.168.2.5", "192.168.1.0", 24));
        assert!(cidr4_match("10.1.2.3", "10.0.0.0", 8));
        assert!(!cidr4_match("11.1.2.3", "10.0.0.0", 8));
    }

    #[test]
    fn cidr4_bits_zero_is_exact_match_not_match_all() {
        assert!(cidr4_match("1.2.3.4", "1.2.3.4", 0));
        assert!(!cidr4_match("1.2.3.5", "1.2.3.4", 0));
    }

    #[test]
    fn cidr4_bits_thirtytwo_is_exact_match() {
        assert!(cidr4_match("1.2.3.4", "1.2.3.4", 32));
        assert!(!cidr4_match("1.2.3.5", "1.2.3.4", 32));
    }

    #[test]
    fn cidr4_bits_over_thirtytwo_is_rejected() {
        assert!(!cidr4_match("1.2.3.4", "1.2.3.4", 33));
        assert!(!cidr4_match("1.2.3.4", "1.2.3.4", 128));
    }

    #[test]
    fn cidr4_invalid_addresses_do_not_match() {
        assert!(!cidr4_match("not-an-ip", "1.2.3.4", 24));
        assert!(!cidr4_match("1.2.3.4", "not-an-ip", 24));
        // An IPv6 string is not a valid IPv4 literal.
        assert!(!cidr4_match("2001:db8::1", "1.2.3.4", 24));
    }

    // ---- cidr6_match ----------------------------------------------------

    #[test]
    fn cidr6_prefix_matching() {
        assert!(cidr6_match("2001:db8::1", "2001:db8::", 32));
        assert!(!cidr6_match("2001:dead::1", "2001:db8::", 32));
        assert!(cidr6_match("2001:db8:abcd::1", "2001:db8:abcd::", 48));
        assert!(!cidr6_match("2001:db8:abce::1", "2001:db8:abcd::", 48));
    }

    #[test]
    fn cidr6_bits_zero_promotes_to_full_match() {
        // bits == 0 ⇒ /128 exact match.
        assert!(cidr6_match("2001:db8::1", "2001:db8::1", 0));
        assert!(!cidr6_match("2001:db8::1", "2001:db8::2", 0));
    }

    #[test]
    fn cidr6_partial_byte_prefix() {
        // /1 compares only the top bit of the first byte.
        assert!(cidr6_match("ff00::", "ff80::", 1)); // both have the high bit set
        assert!(!cidr6_match("ff00::", "7f00::", 1)); // high bit differs
        // /33 compares 4 whole bytes plus the top bit of the 5th.
        assert!(cidr6_match("2001:db8:8000::", "2001:db8:8000::", 33));
        assert!(!cidr6_match("2001:db8:8000::", "2001:db8::", 33));
    }

    #[test]
    fn cidr6_full_128_prefix() {
        assert!(cidr6_match("2001:db8::1", "2001:db8::1", 128));
        assert!(!cidr6_match("2001:db8::1", "2001:db8::2", 128));
    }

    #[test]
    fn cidr6_too_many_bytes_is_rejected() {
        // bytes > 16.
        assert!(!cidr6_match("2001:db8::1", "2001:db8::1", 200));
        // bytes == 16 with a non-zero partial byte (129 ⇒ bytes 16, rest 1).
        assert!(!cidr6_match("2001:db8::1", "2001:db8::1", 129));
    }

    #[test]
    fn cidr6_invalid_addresses_do_not_match() {
        assert!(!cidr6_match("not-an-ip", "2001:db8::", 32));
        assert!(!cidr6_match("2001:db8::1", "not-an-ip", 32));
        // An IPv4 string is not a valid IPv6 literal.
        assert!(!cidr6_match("1.2.3.4", "2001:db8::", 32));
    }

    // ---- curl tests/unit/unit1614.c parity (authoritative upstream) -----
    //
    // The following three tests reproduce the case tables of curl's own
    // `tests/unit/unit1614.c` verbatim, so this port's observable results are
    // byte-for-byte identical to curl 8.x for `Curl_cidr4_match`,
    // `Curl_cidr6_match`, and `Curl_check_noproxy`. (curl gates the IPv6 tables
    // on `USE_IPV6`; here IPv6 is always available via `std::net`, so they run
    // unconditionally.)

    #[test]
    fn curl_unit1614_cidr4_cases() {
        // (ipv4, network, bits, expected match)
        let cases: &[(&str, &str, u32, bool)] = &[
            ("192.160.0.1", "192.160.0.1", 33, false),
            ("192.160.0.1", "192.160.0.1", 32, true),
            ("192.160.0.1", "192.160.0.1", 0, true),
            ("192.160.0.1", "192.160.0.1", 24, true),
            ("192.160.0.1", "192.160.0.1", 26, true),
            ("192.160.0.1", "192.160.0.1", 20, true),
            ("192.160.0.1", "192.160.0.1", 18, true),
            ("192.160.0.1", "192.160.0.1", 12, true),
            ("192.160.0.1", "192.160.0.1", 8, true),
            ("192.160.0.1", "10.0.0.1", 8, false),
            ("192.160.0.1", "10.0.0.1", 32, false),
            ("192.160.0.1", "10.0.0.1", 0, false),
        ];
        for &(a, n, bits, expected) in cases {
            assert_eq!(cidr4_match(a, n, bits), expected, "cidr4 {a} in {n}/{bits}");
        }
    }

    #[test]
    fn curl_unit1614_cidr6_cases() {
        // (ipv6, network, bits, expected match)
        let cases: &[(&str, &str, u32, bool)] = &[
            ("::1", "::1", 0, true),
            ("::1", "::1", 128, true),
            ("::1", "0:0::1", 128, true),
            ("::1", "0:0::1", 129, false),
            (
                "fe80::ab47:4396:55c9:8474",
                "fe80::ab47:4396:55c9:8474",
                64,
                true,
            ),
        ];
        for &(a, n, bits, expected) in cases {
            assert_eq!(cidr6_match(a, n, bits), expected, "cidr6 {a} in {n}/{bits}");
        }
    }

    #[test]
    fn curl_unit1614_check_noproxy_cases() {
        // A 128-byte "address" token — too long for curl's `checkip[128]`
        // buffer, so it cannot match (`tokenlen >= 128`).
        let big128 = concat!(
            "localhost,127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.",
            "127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.",
            "0.0.1.127.0.0.1.127.0.0."
        );
        // A 127-byte "address" token — fits the buffer but is not a valid IP.
        let big127 = concat!(
            "localhost,127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.",
            "127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.",
            "0.0.1.127.0.0.1.127.0.0"
        );

        // (name, no_proxy, expected match)
        let cases: &[(&str, &str, bool)] = &[
            ("www.example.com", "localhost .example.com .example.de", false),
            ("www.example.com", "localhost,.example.com,.example.de", true),
            ("www.example.com.", "localhost,.example.com,.example.de", true),
            ("example.com", "localhost,.example.com,.example.de", true),
            ("example.com.", "localhost,.example.com,.example.de", true),
            ("www.example.com", "localhost,.example.com.,.example.de", true),
            ("www.example.com", "localhost,www.example.com.,.example.de", true),
            ("example.com", "localhost,example.com,.example.de", true),
            ("example.com.", "localhost,example.com,.example.de", true),
            ("nexample.com", "localhost,example.com,.example.de", false),
            ("www.example.com", "localhost,example.com,.example.de", true),
            ("127.0.0.1", "127.0.0.1,localhost", true),
            ("127.0.0.1", "127.0.0.1,localhost,", true),
            ("127.0.0.1", "127.0.0.1/8,localhost,", true),
            ("127.0.0.1", "127.0.0.1/28,localhost,", true),
            ("127.0.0.1", "127.0.0.1/31,localhost,", true),
            ("127.0.0.1", "localhost,127.0.0.1", true),
            ("127.0.0.1", big128, false),
            ("127.0.0.1", big127, false),
            ("localhost", "localhost,127.0.0.1", true),
            ("localhost", "127.0.0.1,localhost", true),
            ("foobar", "barfoo", false),
            ("foobar", "foobar", true),
            ("192.168.0.1", "foobar", false),
            ("192.168.0.1", "192.168.0.0/16", true),
            ("192.168.0.1", "192.168.0.0/16a", false),
            ("192.168.0.1", "192.168.0.0/16 ", true),
            ("192.168.0.1", "192.168.0.0/a16", false),
            ("192.168.0.1", "192.168.0.0/ 16", false),
            ("192.168.0.1", "192.168.0.0/24", true),
            ("192.168.0.1", "192.168.0.0/32", false),
            ("192.168.0.1", "192.168.0.1/32", true),
            ("192.168.0.1", "192.168.0.1/33", false),
            ("192.168.0.1", "192.168.0.0", false),
            ("192.168.1.1", "192.168.0.0/24", false),
            ("192.168.1.1", "192.168.0.0/33", false),
            ("192.168.1.1", "foo, bar, 192.168.0.0/24", false),
            ("192.168.1.1", "foo, bar, 192.168.0.0/16", true),
            ("::1", "foo, bar, 192.168.0.0/16", false),
            ("::1", "foo, bar, ::1/64", true),
            ("::1", "::1/64", true),
            ("::1", "::1/96", true),
            ("::1", "::1/129", false),
            ("::1", "::1/128", true),
            ("::1", "::1/127", true),
            ("::1", "::1/a127", false),
            ("::1", "::1/127a", false),
            ("::1", "::1/ 127", false),
            ("::1", "::1/127 ", true),
            ("::1", "::1/126", true),
            ("::1", "::1/125", true),
            ("::1", "::1/124", true),
            ("::1", "::1/123", true),
            ("::1", "::1/122", true),
            ("2001:db8:8000::1", "2001:db8::/65", false),
            ("2001:db8:8000::1", "2001:db8::/66", false),
            ("2001:db8:8000::1", "2001:db8::/67", false),
            ("2001:db8:8000::1", "2001:db8::/68", false),
            ("2001:db8:8000::1", "2001:db8::/69", false),
            ("2001:db8:8000::1", "2001:db8::/70", false),
            ("2001:db8:8000::1", "2001:db8::/71", false),
            ("2001:db8:8000::1", "2001:db8::/72", false),
            ("2001:db8::1", "2001:db8::/65", true),
            ("2001:db8::1", "2001:db8::/66", true),
            ("2001:db8::1", "2001:db8::/67", true),
            ("2001:db8::1", "2001:db8::/68", true),
            ("2001:db8::1", "2001:db8::/69", true),
            ("2001:db8::1", "2001:db8::/70", true),
            ("2001:db8::1", "2001:db8::/71", true),
            ("2001:db8::1", "2001:db8::/72", true),
            ("::1", "::1/129", false),
            ("bar", "foo, bar, ::1/64", true),
            ("BAr", "foo, bar, ::1/64", true),
            ("BAr", "foo,,,,,              bar, ::1/64", true),
            ("www.example.com", "foo, .example.com", true),
            ("www.example.com", "www2.example.com, .example.net", false),
            ("example.com", ".example.com, .example.net", true),
            ("nonexample.com", ".example.com, .example.net", false),
        ];
        for &(a, n, expected) in cases {
            assert_eq!(check_noproxy(a, n), expected, "noproxy {a:?} in {n:?}");
        }
    }
}
