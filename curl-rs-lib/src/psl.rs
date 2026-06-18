//! Public Suffix List (PSL) integration.
//!
//! This module is the Rust replacement for libcurl's `lib/psl.c` / `lib/psl.h`,
//! which in the C tree wrap the external [`libpsl`] C library. Its single,
//! externally observable job is **cookie super-domain protection**: deciding
//! whether a `Set-Cookie` `Domain=` attribute is an acceptable scope for the
//! host that returned it, so that a server cannot set a cookie for a domain that
//! is "too broad" (for example `Domain=.co.uk`). The Rust core consumes this
//! from [`crate::cookie`] exactly where the C code calls
//! `psl_is_cookie_domain_acceptable()` (see `is_public_suffix()` in
//! `lib/cookie.c`).
//!
//! Instead of binding to the C `libpsl`, this module wraps the pure-Rust
//! [`publicsuffix`] crate (per the migration plan, AAP §0.6.1). The capability
//! is surfaced through `CURL_VERSION_PSL` (bit `1 << 20`) by `crate::version`.
//!
//! # Behavioral parity with the C oracle
//!
//! The C functions `Curl_psl_use` / `Curl_psl_release` / `Curl_psl_destroy`
//! maintain a per-share cached `psl_ctx_t` handle with a 72-hour TTL
//! (`PSL_TTL`), refreshing it from `psl_latest()` (falling back to
//! `psl_builtin()`) under a `CURL_LOCK_DATA_PSL` share lock. That machinery
//! exists purely because the C library can re-load an updated list from disk at
//! runtime.
//!
//! **This Rust port deliberately does not transliterate that caching/TTL/locking
//! logic.** A [`publicsuffix::List`] is parsed once from a bundled, immutable
//! snapshot of the Public Suffix List and is then cheap to query and trivially
//! `Sync`, so there is nothing to refresh and nothing to lock. The only piece of
//! the C caching contract that is preserved is "build it once and share it",
//! offered through [`Psl::global`] (an [`OnceLock`]). There are **no network
//! fetches and no runtime file I/O** (AAP §0.8.3): the list is embedded at
//! compile time.
//!
//! # The acceptance algorithm
//!
//! [`Psl::is_cookie_domain_acceptable`] mirrors `libpsl`'s
//! `psl_is_cookie_domain_acceptable(psl, host, cookie_domain)` exactly:
//!
//! 1. Both inputs are lowercased and any leading dots are stripped from
//!    `cookie_domain`; an empty `cookie_domain` is rejected.
//! 2. If `host == cookie_domain`, the cookie is accepted (an exact match is
//!    always acceptable — this is why a host may set a cookie for its own name
//!    even when that name happens to be a public suffix).
//! 3. Otherwise `cookie_domain` must be a strict, label-boundary suffix of
//!    `host`.
//! 4. And `cookie_domain` must be **strictly longer** than the longest public
//!    suffix of `host` — i.e. the cookie domain must sit at or below the
//!    registrable-domain boundary. This is what rejects `Domain=.co.uk` for a
//!    host like `example.co.uk`, while accepting `Domain=example.co.uk`.
//!
//! This reproduces curl's `tests/data/test1136` ("Check cookies against PSL")
//! byte-for-byte, including the `*.ck` wildcard, the `!www.ck` exception, and
//! the `*.compute-1.amazonaws.com` private-section rules (see the unit tests).
//!
//! # Feature gating
//!
//! The PSL itself is gated behind the `psl` cargo feature (consistent with the
//! `CURL_VERSION_PSL` reporting in `crate::version`). The containing crate's
//! `Cargo.toml` is expected to declare:
//!
//! ```toml
//! [dependencies]
//! publicsuffix = { workspace = true, optional = true }
//!
//! [features]
//! default = ["psl"]          # curl's default build links libpsl
//! psl = ["dep:publicsuffix"]
//! ```
//!
//! When the feature is **disabled**, this module still compiles and exposes the
//! identical API, but falls back to curl's conservative no-`libpsl` heuristic
//! (`bad_domain()` in `lib/cookie.c`): a domain is treated as a public suffix
//! unless it contains an interior dot or is exactly `localhost`. This matches
//! curl's behavior when built without `USE_LIBPSL`.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` and is compiled under a module-level
//! `#![forbid(unsafe_code)]` (in addition to the crate-wide
//! `#![forbid(unsafe_code)]`), satisfying AAP §0.7.1.
//!
//! [`libpsl`]: https://github.com/rockdaboot/libpsl
//! [`publicsuffix`]: https://crates.io/crates/publicsuffix

#![forbid(unsafe_code)]

#[cfg(feature = "psl")]
use crate::error::CurlError;

// The `publicsuffix::Psl` trait provides the `.suffix()` lookup on `List`; it is
// brought into scope anonymously so it does not collide with our own `Psl` type.
#[cfg(feature = "psl")]
use publicsuffix::{List, Psl as _};

use std::sync::OnceLock;

/// The embedded Public Suffix List snapshot.
///
/// This is a verbatim copy of the canonical list published at
/// <https://publicsuffix.org/list/public_suffix_list.dat>, vendored into the
/// crate so the library is fully self-contained and performs no network or
/// runtime file access. It is parsed once by [`Psl::builtin`].
#[cfg(feature = "psl")]
const EMBEDDED_PSL: &str = include_str!("../data/public_suffix_list.dat");

/// Process-wide, lazily initialized [`Psl`] instance.
///
/// This is the moral equivalent of the C code's per-share cached `psl_ctx_t`:
/// the list is built exactly once on first use and shared thereafter. Because
/// the underlying list is immutable there is no TTL and no locking to manage.
static GLOBAL_PSL: OnceLock<Psl> = OnceLock::new();

/// A handle to the Public Suffix List used for cookie-domain validation.
///
/// Construct one with [`Psl::builtin`] (or [`Psl::new`]) for the bundled list,
/// [`Psl::from_bytes`] to supply a custom list, or obtain the shared
/// process-wide instance with [`Psl::global`].
///
/// When the crate is built **without** the `psl` feature this is a zero-sized
/// type and the query methods use curl's conservative no-`libpsl` fallback.
#[derive(Debug, Clone)]
pub struct Psl {
    /// The parsed Public Suffix List. Present only when the `psl` feature is on.
    #[cfg(feature = "psl")]
    list: List,

    /// Zero-sized placeholder so the type and its API exist unchanged when the
    /// `psl` feature is disabled.
    #[cfg(not(feature = "psl"))]
    _private: (),
}

impl Default for Psl {
    /// Equivalent to [`Psl::builtin`].
    fn default() -> Self {
        Self::builtin()
    }
}

impl Psl {
    /// Builds a [`Psl`] from the bundled Public Suffix List snapshot.
    ///
    /// With the `psl` feature enabled this parses the embedded list. Parsing the
    /// vendored list cannot realistically fail, but should it ever do so this is
    /// total: it falls back to an empty [`List`], which still applies the
    /// "prevailing star rule" (an unknown top-level label is treated as a public
    /// suffix), matching `libpsl`'s default behavior for unknown TLDs.
    ///
    /// With the `psl` feature disabled this is a no-op constructor for the
    /// zero-sized fallback handle.
    #[must_use]
    pub fn builtin() -> Self {
        #[cfg(feature = "psl")]
        {
            let list = EMBEDDED_PSL.parse::<List>().unwrap_or_else(|_| List::new());
            Self { list }
        }
        #[cfg(not(feature = "psl"))]
        {
            Self { _private: () }
        }
    }

    /// Alias for [`Psl::builtin`].
    ///
    /// Provided to mirror the `Psl::builtin()` / `Psl::new()` pairing described
    /// in the module's contract; both yield a ready-to-query handle backed by
    /// the bundled list.
    #[must_use]
    pub fn new() -> Self {
        Self::builtin()
    }

    /// Returns the process-wide shared [`Psl`], building it on first use.
    ///
    /// This is the recommended accessor for hot paths such as cookie
    /// acceptance: the (immutable) list is parsed at most once for the lifetime
    /// of the process and then shared by reference, analogous to the cached
    /// handle that the C `Curl_psl_use` returns — but without the TTL refresh or
    /// share locking, neither of which is needed for an immutable list.
    #[must_use]
    pub fn global() -> &'static Psl {
        GLOBAL_PSL.get_or_init(Psl::builtin)
    }

    /// Builds a [`Psl`] from a caller-supplied Public Suffix List in the
    /// standard text format (the same format as `public_suffix_list.dat`).
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if the bytes do not parse into
    /// a non-empty list.
    ///
    /// Only available when the `psl` feature is enabled (a custom list is
    /// meaningless for the no-`libpsl` fallback).
    #[cfg(feature = "psl")]
    pub fn from_bytes(bytes: &[u8]) -> crate::error::Result<Self> {
        let list = List::from_bytes(bytes).map_err(|_| CurlError::BadFunctionArgument)?;
        Ok(Self { list })
    }

    /// Reports whether a real Public Suffix List is loaded.
    ///
    /// Returns `true` only when the `psl` feature is enabled and a non-empty
    /// list was parsed. When `false`, the conservative no-`libpsl` fallback is
    /// in effect. This mirrors the C side distinguishing a usable `psl_ctx_t`
    /// from the `#ifndef USE_LIBPSL` no-op build.
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        #[cfg(feature = "psl")]
        {
            !self.list.is_empty()
        }
        #[cfg(not(feature = "psl"))]
        {
            false
        }
    }

    /// Returns `true` if `domain` is itself a public suffix.
    ///
    /// A domain is a public suffix when it is equal to its own longest public
    /// suffix — for example `com`, `co.uk`, and (via the prevailing star rule)
    /// any unknown single-label TLD are public suffixes, whereas `example.com`
    /// is not. The input is lowercased and leading dots are stripped first.
    ///
    /// With the `psl` feature disabled this uses curl's conservative fallback:
    /// a domain is treated as a public suffix unless it contains an interior dot
    /// or is exactly `localhost`.
    #[must_use]
    pub fn is_public_suffix(&self, domain: &str) -> bool {
        let lowered = domain.to_ascii_lowercase();
        let domain = strip_leading_dots(&lowered);
        if domain.is_empty() {
            return false;
        }

        #[cfg(feature = "psl")]
        {
            self.list
                .suffix(domain.as_bytes())
                .map(|suffix| suffix.as_bytes() == domain.as_bytes())
                .unwrap_or(false)
        }
        #[cfg(not(feature = "psl"))]
        {
            bad_domain(domain)
        }
    }

    /// Returns `true` if a cookie may be set for `cookie_domain` by `host`.
    ///
    /// This is the exact predicate that `crate::cookie` evaluates before
    /// accepting a `Domain=` attribute, and it reproduces `libpsl`'s
    /// `psl_is_cookie_domain_acceptable(psl, host, cookie_domain)`:
    ///
    /// * an exact match (`host == cookie_domain`) is always acceptable;
    /// * otherwise `cookie_domain` must be a strict, label-boundary suffix of
    ///   `host` **and** be strictly more specific (longer) than the longest
    ///   public suffix of `host`.
    ///
    /// Both arguments are lowercased internally and a leading dot on
    /// `cookie_domain` is ignored, so callers may pass values exactly as they
    /// appear on the wire.
    ///
    /// With the `psl` feature disabled this uses curl's conservative fallback:
    /// the structural suffix check still applies, but "is a public suffix" is
    /// approximated by [`bad_domain`] (reject bare, dot-less domains).
    #[must_use]
    pub fn is_cookie_domain_acceptable(&self, host: &str, cookie_domain: &str) -> bool {
        let host = host.to_ascii_lowercase();
        let cookie_lower = cookie_domain.to_ascii_lowercase();
        let cookie_domain = strip_leading_dots(&cookie_lower);

        if cookie_domain.is_empty() {
            return false;
        }
        // An exact match is always acceptable (and the common case for a cookie
        // that omits an explicit Domain= and defaults to the request host).
        if host.as_str() == cookie_domain {
            return true;
        }

        #[cfg(feature = "psl")]
        {
            // The cookie domain must be a label-boundary suffix of the host ...
            if !host_within_domain(&host, cookie_domain) {
                return false;
            }
            // ... and it must reach below the host's public-suffix boundary,
            // i.e. be strictly longer than the host's longest public suffix.
            let suffix_len = self
                .list
                .suffix(host.as_bytes())
                .map(|suffix| suffix.as_bytes().len())
                .unwrap_or(0);
            cookie_domain.len() > suffix_len
        }
        #[cfg(not(feature = "psl"))]
        {
            host_within_domain(&host, cookie_domain) && !bad_domain(cookie_domain)
        }
    }
}

/// Removes any leading `.` characters from a domain.
///
/// Mirrors `libpsl`'s `while (*cookie_domain == '.') cookie_domain++;` so that
/// `".co.uk"` and `"co.uk"` are treated identically.
fn strip_leading_dots(domain: &str) -> &str {
    domain.trim_start_matches('.')
}

/// Returns `true` iff `cookie_domain` is a strict, label-boundary suffix of
/// `host`.
///
/// Both inputs must already be lowercased and have their leading dots removed.
/// "Strict" means `cookie_domain` must be shorter than `host`; "label-boundary"
/// means the character of `host` immediately preceding the matched suffix must
/// be a `.` (so that `ample.com` is not considered a suffix of `example.com`).
///
/// The comparison is performed on raw bytes to avoid any possibility of a UTF-8
/// char-boundary panic on unexpected (non-ASCII) input.
fn host_within_domain(host: &str, cookie_domain: &str) -> bool {
    let host = host.as_bytes();
    let cookie = cookie_domain.as_bytes();
    let (host_len, cookie_len) = (host.len(), cookie.len());

    if cookie_len == 0 || cookie_len >= host_len {
        return false;
    }
    let boundary = host_len - cookie_len;
    host[boundary - 1] == b'.' && &host[boundary..] == cookie
}

/// curl's conservative no-`libpsl` heuristic (`bad_domain()` in `lib/cookie.c`).
///
/// Returns `true` when `domain` is considered "bad" — i.e. likely a TLD or other
/// protected suffix that a cookie must not be scoped to. A domain is **not** bad
/// (acceptable) when it is exactly `localhost`, or when it contains a dot that is
/// not the trailing byte (an interior dot). Leading dots are expected to have
/// been stripped by the caller.
///
/// Only compiled when the `psl` feature is disabled; with the feature enabled
/// the real Public Suffix List is authoritative instead.
#[cfg(not(feature = "psl"))]
fn bad_domain(domain: &str) -> bool {
    // "localhost" is explicitly allowed, matching curl's special case.
    if domain.eq_ignore_ascii_case("localhost") {
        return false;
    }
    // A dot that is not the trailing byte makes the domain acceptable.
    if let Some(first_dot) = domain.as_bytes().iter().position(|&b| b == b'.') {
        if domain.len() - first_dot > 1 {
            return false;
        }
    }
    // No dot at all, or only a trailing dot, and not localhost: bad.
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Tests that hold regardless of the `psl` feature ------------------

    #[test]
    fn exact_match_is_accepted() {
        let psl = Psl::builtin();
        assert!(psl.is_cookie_domain_acceptable("example.com", "example.com"));
        assert!(psl.is_cookie_domain_acceptable("www.example.com", "www.example.com"));
        // A leading dot on the cookie domain is ignored.
        assert!(psl.is_cookie_domain_acceptable("example.com", ".example.com"));
        // Case is normalized on both sides.
        assert!(psl.is_cookie_domain_acceptable("Example.COM", "example.com"));
    }

    #[test]
    fn empty_cookie_domain_is_rejected() {
        let psl = Psl::builtin();
        assert!(!psl.is_cookie_domain_acceptable("example.com", ""));
        assert!(!psl.is_cookie_domain_acceptable("example.com", "."));
        assert!(!psl.is_cookie_domain_acceptable("example.com", "..."));
    }

    #[test]
    fn non_suffix_is_rejected() {
        let psl = Psl::builtin();
        // Not a suffix of the host at all.
        assert!(!psl.is_cookie_domain_acceptable("www.example.com", "notexample.com"));
        // A textual suffix but not on a label boundary.
        assert!(!psl.is_cookie_domain_acceptable("www.example.com", "ample.com"));
        // Cookie domain longer than the host can never be its suffix.
        assert!(!psl.is_cookie_domain_acceptable("com", "example.com"));
    }

    #[test]
    fn empty_domain_is_not_a_public_suffix() {
        let psl = Psl::builtin();
        assert!(!psl.is_public_suffix(""));
        assert!(!psl.is_public_suffix("."));
    }

    #[test]
    fn global_returns_a_shared_instance() {
        let a = Psl::global();
        let b = Psl::global();
        assert!(std::ptr::eq(a, b));
    }

    #[test]
    fn host_within_domain_boundaries() {
        assert!(host_within_domain("www.example.com", "example.com"));
        assert!(host_within_domain("a.b.c", "b.c"));
        assert!(host_within_domain("a.b.c", "c"));
        // Not on a label boundary.
        assert!(!host_within_domain("www.example.com", "ample.com"));
        assert!(!host_within_domain("abc", "c"));
        // Must be strict (equal-length is not "within").
        assert!(!host_within_domain("example.com", "example.com"));
        // Cookie domain longer than host.
        assert!(!host_within_domain("com", "example.com"));
        // Empty cookie domain.
        assert!(!host_within_domain("example.com", ""));
    }

    #[test]
    fn strip_leading_dots_removes_all_leading_dots() {
        assert_eq!(strip_leading_dots(".co.uk"), "co.uk");
        assert_eq!(strip_leading_dots("...co.uk"), "co.uk");
        assert_eq!(strip_leading_dots("co.uk"), "co.uk");
        assert_eq!(strip_leading_dots(""), "");
        assert_eq!(strip_leading_dots("."), "");
    }

    // ---- Tests specific to the enabled Public Suffix List -----------------

    #[cfg(feature = "psl")]
    #[test]
    fn builtin_list_is_loaded() {
        assert!(Psl::builtin().is_loaded());
    }

    #[cfg(feature = "psl")]
    #[test]
    fn is_public_suffix_recognizes_known_and_starred_suffixes() {
        let psl = Psl::builtin();
        // Plain ICANN suffixes.
        assert!(psl.is_public_suffix("com"));
        assert!(psl.is_public_suffix("co.uk"));
        // Case-insensitive and leading-dot tolerant.
        assert!(psl.is_public_suffix("CO.UK"));
        assert!(psl.is_public_suffix(".co.uk"));
        // A registrable domain is not a public suffix.
        assert!(!psl.is_public_suffix("example.com"));
        // Bare TLD via the prevailing star rule.
        assert!(psl.is_public_suffix("ck"));
        // `*.ck` makes example.ck a public suffix ...
        assert!(psl.is_public_suffix("example.ck"));
        // ... but the `!www.ck` exception makes www.ck registrable.
        assert!(!psl.is_public_suffix("www.ck"));
    }

    #[cfg(feature = "psl")]
    #[test]
    fn rejects_public_suffix_cookie_domains() {
        let psl = Psl::builtin();
        // The headline validation case: a cookie for Domain=.co.uk is rejected.
        assert!(!psl.is_cookie_domain_acceptable("example.co.uk", ".co.uk"));
        assert!(!psl.is_cookie_domain_acceptable("www.example.co.uk", "co.uk"));
        assert!(!psl.is_cookie_domain_acceptable("www.example.com", "com"));
        assert!(!psl.is_cookie_domain_acceptable("www.example.com", ".com"));

        // Registrable domains (and sub-domains thereof) are accepted.
        assert!(psl.is_cookie_domain_acceptable("www.example.co.uk", "example.co.uk"));
        assert!(psl.is_cookie_domain_acceptable("www.example.com", "example.com"));
        assert!(psl.is_cookie_domain_acceptable("a.b.example.com", "b.example.com"));
    }

    /// Byte-for-byte reproduction of curl's `tests/data/test1136`
    /// ("Check cookies against PSL"). Three request hosts are each offered the
    /// same five `Set-Cookie` `Domain=` attributes; exactly the three cookies in
    /// the expected jar must be accepted. This exercises the `*.ck` wildcard,
    /// the `!www.ck` exception, and the `*.compute-1.amazonaws.com` private rule.
    #[cfg(feature = "psl")]
    #[test]
    fn test1136_psl_cookie_parity() {
        use std::collections::BTreeSet;

        let psl = Psl::builtin();
        let hosts = ["www.example.ck", "www.ck", "z-1.compute-1.amazonaws.com"];
        let cookies = [
            ("test1", "example.ck"),
            ("test2", "www.example.ck"),
            ("test3", "ck"),
            ("test4", "www.ck"),
            ("test5", "z-1.compute-1.amazonaws.com"),
        ];

        let mut accepted: BTreeSet<&str> = BTreeSet::new();
        for host in hosts {
            for (name, cookie_domain) in cookies {
                if psl.is_cookie_domain_acceptable(host, cookie_domain) {
                    accepted.insert(name);
                }
            }
        }

        let expected: BTreeSet<&str> = ["test2", "test4", "test5"].into_iter().collect();
        assert_eq!(
            accepted, expected,
            "PSL cookie acceptance must match curl tests/data/test1136"
        );
    }

    #[cfg(feature = "psl")]
    #[test]
    fn from_bytes_parses_and_validates_custom_lists() {
        let data = b"// ===BEGIN ICANN DOMAINS===\ncom\nuk\nco.uk\n";
        let psl = Psl::from_bytes(data).expect("a non-empty list must parse");
        assert!(psl.is_public_suffix("com"));
        assert!(psl.is_public_suffix("co.uk"));
        assert!(!psl.is_cookie_domain_acceptable("example.co.uk", "co.uk"));
        assert!(psl.is_cookie_domain_acceptable("www.example.co.uk", "example.co.uk"));

        // An empty / unparseable list is reported as an error.
        assert!(Psl::from_bytes(b"").is_err());
    }

    // ---- Tests specific to the conservative no-`libpsl` fallback ----------

    #[cfg(not(feature = "psl"))]
    #[test]
    fn fallback_handle_reports_not_loaded() {
        assert!(!Psl::builtin().is_loaded());
    }

    #[cfg(not(feature = "psl"))]
    #[test]
    fn fallback_treats_single_label_as_public_suffix() {
        let psl = Psl::builtin();
        // Bare, dot-less labels are treated as public suffixes.
        assert!(psl.is_public_suffix("com"));
        assert!(psl.is_public_suffix("ck"));
        // A domain with an interior dot is not (we can't prove it is a suffix).
        assert!(!psl.is_public_suffix("example.com"));
        // localhost is explicitly exempt.
        assert!(!psl.is_public_suffix("localhost"));
    }

    #[cfg(not(feature = "psl"))]
    #[test]
    fn fallback_cookie_acceptance_matches_bad_domain() {
        let psl = Psl::builtin();
        // Exact match is always acceptable.
        assert!(psl.is_cookie_domain_acceptable("example.com", "example.com"));
        // A cookie domain with an interior dot that the host is within: accepted.
        assert!(psl.is_cookie_domain_acceptable("www.example.com", "example.com"));
        // A bare TLD cookie domain: rejected by the bad_domain heuristic.
        assert!(!psl.is_cookie_domain_acceptable("www.example.com", "com"));
        // Not a suffix of the host: rejected.
        assert!(!psl.is_cookie_domain_acceptable("www.example.com", "other.com"));
    }
}
