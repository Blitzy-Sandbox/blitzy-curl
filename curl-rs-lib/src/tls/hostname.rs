//! RFC 6125 §6.4.3 hostname / wildcard certificate-name matching.
//!
//! This module is a memory-safe Rust reimplementation of libcurl's certificate
//! hostname matcher, `lib/vtls/hostcheck.c` (consulted as a *behavioral oracle*,
//! not transliterated line-by-line). It reproduces curl's **exact** RFC 6125
//! wildcard rules — including the subtle, security-relevant edge cases that
//! curl's own unit test `tests/unit/unit1397.c` pins down.
//!
//! # Why this exists (it is a parity *shim*)
//!
//! In the normal TLS handshake, `rustls`/`webpki` performs the *primary*
//! server-certificate hostname verification (it does its own RFC 6125 matching
//! for the default `SSL_VERIFYHOST = 2` path). This module therefore is **not**
//! on the default verification hot-path; it is a parity shim used by
//! [`crate::tls::config`]'s custom `ServerCertVerifier` for the paths where curl
//! does a *manual / explicit* name check:
//!
//! * the `SSL_VERIFYHOST = 0` case (verify the chain but **not** the name, where
//!   any name comparison curl still performs must match curl byte-for-byte), and
//! * any other place that must replicate curl's name-matching independently of
//!   webpki's built-in check.
//!
//! Because the decision this code returns is security-relevant and observable by
//! the curl test-suite, it matches `hostcheck.c` precisely rather than
//! approximately.
//!
//! # The three layers (mirroring `hostcheck.c`)
//!
//! 1. [`pmatch`] — the leaf comparison: equal length **and** an ASCII
//!    case-insensitive byte equality (via the shared
//!    [`crate::util::strcase::strncasecompare`] helper).
//! 2. [`hostmatch`] — the RFC 6125 §6.4.3 wildcard algorithm (curl's
//!    `@unittest: 1397` function).
//! 3. [`cert_hostcheck`] — the public entry point (curl's `Curl_cert_hostcheck`):
//!    a non-empty guard wrapping [`hostmatch`].
//!
//! # Encoding assumption (`&str` public API, byte-level core)
//!
//! The public API ([`cert_hostcheck`] / [`matches_any`]) takes `&str`. Hostnames
//! and certificate dNSName SAN entries are ASCII by the time they reach a name
//! check: internationalized names are converted to their ASCII-compatible
//! encoding (A-label / "xn--…") upstream in [`crate::idn`] before comparison, so
//! the byte/`char` distinction does not arise in practice. Internally the
//! RFC 6125 length/dot logic operates on the underlying **bytes**
//! (`str::as_bytes`), which (a) faithfully mirrors the `size_t`/pointer index
//! arithmetic of the C oracle and (b) lets the parity tests exercise curl's
//! non-ASCII byte vectors (e.g. `\xff`) exactly.
//!
//! # Memory safety
//!
//! Per the project memory-safety mandate (AAP §0.7.1, §0.8.2) `src/tls/` must
//! contain **zero `unsafe`**. This module is pure string/slice logic and is
//! compiled under `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]
// Rationale for `allow(dead_code)`: in the partially-assembled workspace this
// module can land before `crate::tls::config` (authored in parallel) wires up
// the custom `ServerCertVerifier` that consumes [`cert_hostcheck`] /
// [`matches_any`], and before `tls/mod.rs` decides how to re-export it. Allowing
// `dead_code` keeps the module self-contained under the workspace's
// `-D warnings` gate without masking defects: every private helper here is
// exercised by the public functions and by the unit tests below. (Mirrors the
// sibling `util/strparse.rs`, which allows it for the same construction-order
// reason.)
#![allow(dead_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::util::strcase::strncasecompare;

/// Returns `true` if `pattern` matches `hostname` under curl's certificate
/// name-matching rules (RFC 6125 §6.4.3 with curl's normalizations).
///
/// This is the Rust counterpart of curl's `Curl_cert_hostcheck`. `pattern` is a
/// name presented by the certificate (a Subject Alternative Name dNSName entry,
/// or a legacy CN), which may be an exact name (`www.example.com`) or a
/// leftmost-label wildcard (`*.example.com`). `hostname` is the name the client
/// intended to reach.
///
/// Both arguments must be non-empty for a match to be possible; an empty
/// `pattern` or `hostname` always yields `false` (mirroring the
/// `match && *match && hostname && *hostname` guard in the C source).
///
/// # Argument order
///
/// The order is `(pattern, hostname)` — the same order as curl's
/// `Curl_cert_hostcheck(match, matchlen, hostname, hostlen)`. Take care not to
/// transpose them.
///
/// # Examples
///
/// ```ignore
/// use curl_rs_lib::tls::hostname::cert_hostcheck;
///
/// assert!(cert_hostcheck("*.example.com", "www.example.com"));
/// assert!(cert_hostcheck("*.example.com", "WWW.EXAMPLE.COM")); // case-insensitive
/// assert!(!cert_hostcheck("*.example.com", "example.com"));    // no bare-domain match
/// assert!(!cert_hostcheck("*.example.com", "a.b.example.com")); // single-label wildcard
/// assert!(!cert_hostcheck("*.com", "example.com"));            // >= 2 dots required
/// ```
#[must_use]
pub fn cert_hostcheck(pattern: &str, hostname: &str) -> bool {
    // Operate on the underlying bytes: the RFC 6125 index logic is byte-oriented
    // and the inputs are ASCII post-IDN (see the module docs).
    cert_hostcheck_bytes(pattern.as_bytes(), hostname.as_bytes())
}

/// Returns `true` if `hostname` matches **any** of the certificate's presented
/// dNSName SAN entries under curl's name-matching rules.
///
/// Each entry in `dns_names` is treated as a `pattern` and checked against
/// `hostname` via [`cert_hostcheck`]; the function short-circuits on the first
/// match. This is the helper consumed by [`crate::tls::config`]'s custom
/// verifier when it must replicate curl's matching across the full SAN set —
/// for example on the `SSL_VERIFYHOST = 0` chain-only path, or any edge case
/// where the decision must be independent of webpki's built-in check.
///
/// Note that for the default (`SSL_VERIFYHOST = 2`) path, `webpki` already
/// performs RFC 6125 matching during the handshake; this helper exists for
/// parity and for the explicit-check paths.
///
/// # Examples
///
/// ```ignore
/// use curl_rs_lib::tls::hostname::matches_any;
///
/// let sans = ["*.example.com", "example.com"];
/// assert!(matches_any("www.example.com", sans));
/// assert!(matches_any("example.com", sans));
/// assert!(!matches_any("example.org", sans));
/// ```
#[must_use]
pub fn matches_any<'a>(hostname: &str, dns_names: impl IntoIterator<Item = &'a str>) -> bool {
    dns_names
        .into_iter()
        .any(|san| cert_hostcheck(san, hostname))
}

/// Byte-level core of [`cert_hostcheck`] (curl's `Curl_cert_hostcheck`).
///
/// Returns `false` unless both `pattern` and `hostname` are non-empty, in which
/// case the decision is delegated to [`hostmatch`]. Kept separate from the
/// `&str` wrapper so the non-empty guard is shared and so the parity tests can
/// feed raw byte vectors (including non-UTF-8 bytes such as `\xff`) exactly as
/// curl's `unit1397` does.
fn cert_hostcheck_bytes(pattern: &[u8], hostname: &[u8]) -> bool {
    if !pattern.is_empty() && !hostname.is_empty() {
        hostmatch(hostname, pattern)
    } else {
        false
    }
}

/// Matches `hostname` against `pattern` using RFC 6125 §6.4.3, reproducing
/// curl's `hostmatch` (the `@unittest: 1397` function) byte-for-byte.
///
/// The rules, applied in order:
///
/// 1. **Normalize** by stripping a single trailing `.` from *both* `hostname`
///    and `pattern` (so trailing-dot FQDNs compare equal to their dotless form,
///    matching browser behavior).
/// 2. **No wildcard**: if `pattern` does not begin with the two bytes `*.`,
///    return an exact [`pmatch`]. (The `*.` test inspects the *original* pattern
///    bytes, faithful to the C `strncmp(pattern, "*.", 2)`.)
/// 3. **Wildcard guards**: a wildcard never matches when `hostname` is an
///    IP-address literal, nor when `hostname` begins with `.`.
/// 4. **At least two dots** are required in the (normalized) pattern. A pattern
///    with zero or one dot (e.g. `*.com`) falls back to an exact [`pmatch`],
///    which all but always fails — this rejects overly-broad wildcards.
/// 5. **Match**: the leftmost `*` matches **exactly one** leftmost label. The
///    substring of `hostname` from its first `.` (inclusive) must [`pmatch`] the
///    substring of `pattern` from its first `.` (inclusive). If `hostname` has
///    no `.`, there is no match.
///
/// `hostname` and `pattern` are guaranteed non-empty by the only caller
/// ([`cert_hostcheck_bytes`]); the function is nonetheless written so no slice
/// index can panic.
fn hostmatch(hostname: &[u8], pattern: &[u8]) -> bool {
    // Defensive: the caller guarantees non-empty, but never index a 0-len slice.
    if hostname.is_empty() || pattern.is_empty() {
        return false;
    }

    // (1) Normalize: strip a single trailing '.' from each by shrinking the
    // effective length, exactly as the C code decrements `hostlen`/`patternlen`.
    let mut hostlen = hostname.len();
    if hostname[hostlen - 1] == b'.' {
        hostlen -= 1;
    }
    let mut patternlen = pattern.len();
    if pattern[patternlen - 1] == b'.' {
        patternlen -= 1;
    }
    let nhost = &hostname[..hostlen];
    let npat = &pattern[..patternlen];

    // (2) No wildcard: pattern does not begin with "*." -> exact compare.
    // Faithful to `strncmp(pattern, "*.", 2)`, this checks the ORIGINAL pattern
    // bytes (a trailing-dot strip can never remove this two-byte prefix, and the
    // degenerate "*." case converges to the same `pmatch` either way).
    if !pattern.starts_with(b"*.") {
        return pmatch(nhost, npat);
    }

    // (3) Wildcard guards: never wildcard-match an IP literal, nor a host with a
    // leading dot. `hostname[0]` is the original first byte (unaffected by the
    // trailing-dot normalization), exactly as curl checks `hostname[0] == '.'`.
    // The IP check uses the full original host string, mirroring
    // `Curl_host_is_ipnum(hostname)`; non-UTF-8 hosts are never IP literals.
    let host_is_ip = std::str::from_utf8(hostname).is_ok_and(host_is_ip_literal);
    if host_is_ip || hostname[0] == b'.' {
        return false;
    }

    // (4) Require at least two dots in the normalized pattern: the first dot and
    // the last dot must be at different positions. Zero or one dot (e.g.
    // "*.com") falls through to an exact `pmatch`, which rejects the wildcard.
    let first_dot = npat.iter().position(|&b| b == b'.');
    let last_dot = npat.iter().rposition(|&b| b == b'.');
    match (first_dot, last_dot) {
        (Some(pattern_label_end), Some(pattern_label_last))
            if pattern_label_end != pattern_label_last =>
        {
            // (5) Wildcard match: compare everything from each name's first dot
            // (inclusive). The leftmost `*` thus consumes exactly one host label;
            // every label after the first must match exactly (case-insensitive).
            match nhost.iter().position(|&b| b == b'.') {
                Some(hostname_label_end) => {
                    pmatch(&nhost[hostname_label_end..], &npat[pattern_label_end..])
                }
                // Wildcard pattern but the host has no further label: no match.
                None => false,
            }
        }
        // No dot, or only a single dot, in the pattern: fall back to exact
        // compare so overly-broad wildcards (e.g. "*.com") do not match.
        _ => pmatch(nhost, npat),
    }
}

/// The leaf comparison of curl's matcher (`pmatch` in `hostcheck.c`).
///
/// Returns `false` immediately if the two byte slices differ in length;
/// otherwise it is an ASCII case-insensitive equality comparison performed by
/// the shared [`crate::util::strcase::strncasecompare`] helper (which folds only
/// `A`–`Z`, matching curl's `Curl_strncasecompare`). The case folding is
/// deliberately not re-implemented here so it stays consistent with the rest of
/// the crate.
fn pmatch(hostname: &[u8], pattern: &[u8]) -> bool {
    if hostname.len() != pattern.len() {
        return false;
    }
    // Lengths are equal here, so comparing `hostname.len()` bytes is a full,
    // exact, case-insensitive equality check.
    strncasecompare(hostname, pattern, hostname.len())
}

/// Returns `true` if `host` is a numeric IP-address literal (IPv4 or IPv6),
/// analogous to curl's `Curl_host_is_ipnum` (which uses `inet_pton` for
/// `AF_INET` and `AF_INET6`). Used by [`hostmatch`]'s wildcard guard so that a
/// `*.`-wildcard pattern can never match an IP literal.
///
/// An IPv6 literal may optionally be wrapped in brackets (e.g. `[fe80::1]`); the
/// brackets are stripped before parsing. IPv4 literals are never bracketed.
fn host_is_ip_literal(host: &str) -> bool {
    // IPv4 dotted-quad, e.g. "192.168.0.1".
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    // IPv6, optionally bracketed, e.g. "[fe80::1]" or "fe80::3285:a9ff:fe46:b619".
    let candidate = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    candidate.parse::<Ipv6Addr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One row of curl's `tests/unit/unit1397.c` table: `(host, pattern,
    /// expected_match)`. Byte slices (not `&str`) so the non-UTF-8 vectors
    /// (`\xff`, `\xfe\xfe`) are reproduced exactly. curl invokes
    /// `Curl_cert_hostcheck(pattern, patternlen, host, hostlen)`, which maps to
    /// our [`cert_hostcheck_bytes(pattern, host)`].
    type Case = (&'static [u8], &'static [u8], bool);

    /// Every fixed-size vector from curl's `unit1397` matcher test, transcribed
    /// verbatim. The single dynamically-sized "very long leftmost label" case is
    /// asserted separately in [`unit1397_long_label`].
    const UNIT1397_CASES: &[Case] = &[
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

    /// Full behavioral parity with curl's `unit1397` matcher test: every
    /// transcribed vector must produce exactly curl's expected decision.
    #[test]
    fn unit1397_parity() {
        for &(host, pattern, expected) in UNIT1397_CASES {
            let got = cert_hostcheck_bytes(pattern, host);
            assert_eq!(
                got,
                expected,
                "unit1397 mismatch: host={:?} pattern={:?} expected {} got {}",
                String::from_utf8_lossy(host),
                String::from_utf8_lossy(pattern),
                expected,
                got
            );
        }
    }

    /// curl's `unit1397` includes a ~290-byte leftmost label followed by
    /// `.e.llo.`; a wildcard `*.e.llo` must match it (the `*` consumes the whole
    /// long first label). The label content is irrelevant — only that it is a
    /// single dotless, non-IP, non-leading-dot label.
    #[test]
    fn unit1397_long_label() {
        let mut host = vec![b'A'; 290];
        host.extend_from_slice(b".e.llo.");
        assert!(cert_hostcheck_bytes(b"*.e.llo", &host));
    }

    /// The exact assertions enumerated in the task's validation checklist,
    /// exercised through the public `&str` API.
    #[test]
    fn prompt_required_assertions() {
        // `*.example.com` matches a single leftmost label, case-insensitively...
        assert!(cert_hostcheck("*.example.com", "www.example.com"));
        assert!(cert_hostcheck("*.example.com", "WWW.EXAMPLE.COM"));
        // ...but NOT the bare domain, NOT multiple labels, NOT a different domain.
        assert!(!cert_hostcheck("*.example.com", "example.com"));
        assert!(!cert_hostcheck("*.example.com", "a.b.example.com"));
        assert!(!cert_hostcheck("*.example.com", "www.example.org"));

        // `*.com` is rejected by the >= 2-dots-in-pattern guard.
        assert!(!cert_hostcheck("*.com", "example.com"));

        // The wildcard must be the *entire* leftmost label: `f*.` is not a
        // wildcard label, so it can only match literally (and the lengths
        // differ here anyway).
        assert!(!cert_hostcheck("f*.example.com", "foo.example.com"));

        // A `*.`-wildcard never matches an IP-address literal.
        assert!(!cert_hostcheck("*.example.com", "127.0.0.1"));
        assert!(!cert_hostcheck("*.0.0.1", "127.0.0.1"));

        // Trailing-dot normalization on either side.
        assert!(cert_hostcheck("*.example.com", "www.example.com."));
        assert!(cert_hostcheck("*.example.com.", "www.example.com"));

        // Plain (non-wildcard) exact + ASCII case-insensitive matches.
        assert!(cert_hostcheck("example.com", "example.com"));
        assert!(cert_hostcheck("EXAMPLE.com", "example.COM"));
        assert!(!cert_hostcheck("example.com", "example.org"));

        // Empty inputs are never a match.
        assert!(!cert_hostcheck("", ""));
        assert!(!cert_hostcheck("", "example.com"));
        assert!(!cert_hostcheck("example.com", ""));
    }

    /// A leading-dot host is never matched by a wildcard pattern.
    #[test]
    fn leading_dot_host_never_wildcard_matches() {
        assert!(!cert_hostcheck("*.hello.com", ".hello.com"));
        assert!(!cert_hostcheck("*.e.llo.", ".h.e.llo"));
    }

    /// [`host_is_ip_literal`] detects IPv4 and IPv6 (bracketed or bare) and
    /// rejects ordinary hostnames and empty input.
    #[test]
    fn host_is_ip_literal_detection() {
        // IPv4 literals.
        assert!(host_is_ip_literal("192.168.0.1"));
        assert!(host_is_ip_literal("127.0.0.1"));
        assert!(host_is_ip_literal("0.0.0.0"));
        // IPv6 literals, bare and bracketed.
        assert!(host_is_ip_literal("::1"));
        assert!(host_is_ip_literal("fe80::3285:a9ff:fe46:b619"));
        assert!(host_is_ip_literal("[fe80::1]"));
        assert!(host_is_ip_literal("[::1]"));
        // Not IP literals.
        assert!(!host_is_ip_literal("example.com"));
        assert!(!host_is_ip_literal("www.example.com"));
        assert!(!host_is_ip_literal("*.example.com"));
        assert!(!host_is_ip_literal(""));
        assert!(!host_is_ip_literal("[notanip]"));
        assert!(!host_is_ip_literal("192.168.0.256")); // out of range octet
    }

    /// [`matches_any`] returns `true` iff at least one presented SAN entry
    /// matches, short-circuiting; an empty SAN set yields `false`.
    #[test]
    fn matches_any_behavior() {
        let sans = ["*.example.com", "example.com", "cdn.example.net"];

        // Matches via the wildcard entry.
        assert!(matches_any("www.example.com", sans));
        // Matches via the exact entries.
        assert!(matches_any("example.com", sans));
        assert!(matches_any("cdn.example.net", sans));
        // Case-insensitive against the wildcard entry.
        assert!(matches_any("WWW.EXAMPLE.COM", sans));

        // No entry matches.
        assert!(!matches_any("foo.example.net", sans));
        assert!(!matches_any("example.org", sans));
        assert!(!matches_any("a.b.example.com", sans));

        // An empty SAN list never matches.
        let empty: [&str; 0] = [];
        assert!(!matches_any("example.com", empty));

        // Works with an owned collection / borrowed iterator yielding `&str`.
        let owned = vec!["*.host.com"];
        assert!(matches_any("a.host.com", owned));
        let names = ["a.test", "b.test"];
        assert!(matches_any("b.test", names.iter().copied()));
    }

    /// The leaf [`pmatch`] requires equal length and folds only ASCII letters;
    /// non-ASCII bytes are compared literally (never Unicode-folded).
    #[test]
    fn pmatch_length_and_ascii_folding() {
        assert!(pmatch(b"abc", b"ABC"));
        assert!(pmatch(b"Example.COM", b"example.com"));
        assert!(!pmatch(b"abc", b"abcd")); // length mismatch
        assert!(!pmatch(b"abc", b"abd"));
        // Non-ASCII bytes are equal only when identical (no case folding).
        assert!(pmatch(b"\xff", b"\xff"));
        assert!(pmatch(b"\xfe\xfe", b"\xfe\xfe"));
        // Empty vs empty is a (degenerate) equal-length match.
        assert!(pmatch(b"", b""));
    }
}
