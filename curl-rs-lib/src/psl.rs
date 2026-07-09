//! Public Suffix List (PSL) handling — the cookie "supercookie" defense.
//!
//! This is a memory-safe Rust rewrite of curl's `lib/psl.c`. curl links the C
//! `libpsl` library to obtain a Public Suffix List and answer the two questions
//! the cookie engine needs: *is this domain a public suffix?* and *what is the
//! registrable domain (eTLD+1) of this host?* Rejecting cookies whose `Domain`
//! attribute is a public suffix (for example `com` or `co.uk`) is what prevents
//! a site from setting a "supercookie" that would then be sent to every site
//! under a whole top-level domain.
//!
//! # Relationship to `lib/psl.c`
//!
//! The C module exposes a `PslCache` struct together with `Curl_psl_use`,
//! `Curl_psl_release`, and `Curl_psl_destroy`. Those functions exist purely to
//! lazily load the list, cache it behind a time-to-live, and guard it with the
//! share lock (`CURL_LOCK_DATA_PSL`) so that many easy handles can share one
//! `psl_ctx_t`. In idiomatic Rust that entire lifecycle collapses into
//! ownership: [`Psl`] wraps the parsed list in an [`Arc`], so *use* is a cheap
//! clone of the handle and *release* / *destroy* is simply `Drop`. No manual
//! locking or refresh bookkeeping is required, and the handle stays cheap to
//! share across handles exactly as curl shared a single PSL context (see the
//! `Arc<Mutex<..>>` cross-handle sharing model in the technical specification).
//!
//! # libpsl replacement
//!
//! Rather than linking `libpsl`, this module is built on the pure-Rust
//! [`publicsuffix`] crate. curl feeds `libpsl` lowercased input — `lib/cookie.c`
//! notes that "the PSL check requires lowercase domain name and pattern" — while
//! the `publicsuffix` crate matches ASCII-case-sensitively. This module
//! therefore lowercases its input internally so that its answers reproduce
//! curl's observable behaviour regardless of the caller's letter case.
//!
//! # Fallback behaviour
//!
//! curl can be built without `libpsl` (with `USE_LIBPSL` undefined); it still
//! functions, just without supercookie protection, and in that configuration
//! its cookie code treats "no PSL" as "not a public suffix". [`Psl::default`]
//! and [`Psl::empty`] model exactly that build: [`Psl::is_public_suffix`]
//! returns `false` and [`Psl::registrable_domain`] returns `None` when no list
//! is loaded. The higher-level cookie fallback (a "domain must contain a dot or
//! be `localhost`" heuristic) lives in the cookie engine, not here, mirroring
//! the `#ifndef USE_LIBPSL` branch of `lib/cookie.c`.
//!
//! # Memory safety
//!
//! This module is written entirely in safe Rust; it performs no raw-pointer
//! work, in keeping with the crate-wide policy that confines such low-level
//! constructs to the FFI layer.

use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};

// `publicsuffix::Psl` is the trait that provides the `suffix()` and `domain()`
// query methods on `List`. It is imported anonymously (`as _`) so its methods
// are in scope for method-call syntax without colliding with our own [`Psl`]
// struct defined below.
use publicsuffix::{List, Psl as _};

use crate::error::{Error, Result};

/// The Public Suffix List bundled into the library at build time.
///
/// This is the verbatim `public_suffix_list.dat` published at
/// <https://publicsuffix.org/list/>, embedded with [`include_str!`] so the
/// cookie engine's "supercookie" defense is active out of the box. It is the
/// pure-Rust equivalent of curl being built against `libpsl`, which ships (or
/// loads) a list and enables the defense by default. The data is licensed
/// MPL-2.0 (annotated in `REUSE.toml`), separate from the crate's own license.
const BUNDLED_PUBLIC_SUFFIX_LIST: &str = include_str!("public_suffix_list.dat");

/// A shared, reference-counted Public Suffix List handle.
///
/// `Psl` is the Rust replacement for curl's `PslCache` / `psl_ctx_t` pair. It
/// owns an optional parsed [`publicsuffix::List`] behind an [`Arc`], which makes
/// the handle:
///
/// * **cheap to clone / share** — cloning only bumps the reference count, so a
///   single parsed list can back every easy handle, just as curl shared one
///   `psl_ctx_t` under the PSL share lock; and
/// * **fallback-friendly** — an empty handle (no list) represents a curl build
///   without `libpsl`, in which case every query degrades to the safe
///   "unknown / not a public suffix" answer.
///
/// The type is `Send + Sync` (the inner `List` is), so it can be stored in the
/// `Arc<Mutex<..>>` cookie-sharing structures used elsewhere in the crate.
#[derive(Clone, Default)]
pub struct Psl {
    /// The parsed list, or `None` when no PSL is available (the "built without
    /// libpsl" fallback). Wrapped in an [`Arc`] so the potentially large list
    /// is allocated once and shared by every clone of the handle.
    inner: Option<Arc<List>>,
}

impl fmt::Debug for Psl {
    /// Formats the handle without dumping the (potentially very large) parsed
    /// list; only its availability is reported.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Psl")
            .field("available", &self.is_available())
            .finish()
    }
}

impl FromStr for Psl {
    type Err = Error;

    /// Parses a handle from the textual Public Suffix List format (the
    /// `public_suffix_list.dat` layout: one rule per line, `//` comments, and
    /// optional `// ===BEGIN ICANN DOMAINS===` section markers).
    ///
    /// This is the pure-Rust analogue of curl loading a list through `libpsl`
    /// (`psl_latest` / `psl_load_file`). A malformed or empty list yields
    /// [`Error::bad_argument`] (`CURLE_BAD_FUNCTION_ARGUMENT`).
    ///
    /// The return type is written as the fully-qualified [`std::result::Result`]
    /// because the crate-local [`Result`](crate::error::Result) alias fixes the
    /// error type and therefore takes a single type parameter.
    fn from_str(list: &str) -> std::result::Result<Self, Self::Err> {
        let parsed = List::from_str(list)
            .map_err(|e| Error::bad_argument(format!("invalid public suffix list: {e}")))?;
        Ok(Self {
            inner: Some(Arc::new(parsed)),
        })
    }
}

impl Psl {
    /// Creates an empty handle with no list loaded.
    ///
    /// This models a curl build compiled without `libpsl`: the handle is valid
    /// and cheap, but every query returns the conservative fallback answer
    /// ([`is_public_suffix`](Self::is_public_suffix) is always `false` and
    /// [`registrable_domain`](Self::registrable_domain) is always `None`).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns a handle backed by the Public Suffix List bundled with the
    /// library (see [`BUNDLED_PUBLIC_SUFFIX_LIST`]).
    ///
    /// This is the list used by default in
    /// [`CookieJar::new`](crate::cookie::CookieJar::new), giving the cookie
    /// engine its supercookie defense out of the box — the behavior of a curl
    /// built with `libpsl`. The embedded list is parsed exactly once, on the
    /// first call, and cached in a process-wide [`OnceLock`]; every subsequent
    /// call — and every clone of the returned handle — only bumps the shared
    /// [`Arc`] reference count, so obtaining the handle is cheap. If the
    /// embedded data ever fails to parse it degrades to an
    /// [`empty`](Self::empty) handle rather than panicking, matching the
    /// conservative no-list fallback (a `bundled_list_is_available_*` unit test
    /// guards against the embedded data silently regressing to that state).
    #[must_use]
    pub fn bundled() -> Self {
        static BUNDLED: OnceLock<Psl> = OnceLock::new();
        BUNDLED
            .get_or_init(|| {
                BUNDLED_PUBLIC_SUFFIX_LIST
                    .parse::<Self>()
                    .unwrap_or_default()
            })
            .clone()
    }

    /// Parses a handle from raw Public Suffix List bytes.
    ///
    /// This is a convenience wrapper over the [`FromStr`] implementation for the
    /// common case of loading a list file from disk. The bytes must be valid
    /// UTF-8 (the PSL is published as UTF-8); otherwise [`Error::bad_argument`]
    /// is returned.
    pub fn from_bytes(list: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(list).map_err(|e| {
            Error::bad_argument(format!("public suffix list is not valid UTF-8: {e}"))
        })?;
        text.parse()
    }

    /// Returns `true` when a list is loaded and PSL queries are meaningful.
    ///
    /// This mirrors the C code's `Curl_psl_use` returning a non-`NULL`
    /// `psl_ctx_t` (equivalently, the `if(psl)` guard in `lib/cookie.c`): the
    /// cookie engine can use it to choose between the PSL-backed path and the
    /// no-PSL fallback path.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.inner.is_some()
    }

    /// Returns `true` if `domain` is itself a public suffix.
    ///
    /// This mirrors `libpsl`'s `psl_is_public_suffix`, the check curl uses to
    /// decide whether a cookie's `Domain` attribute names a public suffix (and
    /// must therefore be rejected). A domain is a public suffix when the list's
    /// computed public-suffix span covers the entire input — for example `com`
    /// and `co.uk` are public suffixes, whereas `example.com` is not. Following
    /// the PSL algorithm's implicit `*` rule, an unknown single label (such as a
    /// not-yet-delegated TLD) is also treated as a public suffix, matching
    /// `libpsl`'s default behaviour.
    ///
    /// Input is compared ASCII-case-insensitively (curl lowercases before its
    /// PSL checks). When no list is loaded this returns `false`, matching curl's
    /// non-`libpsl` build.
    #[must_use]
    pub fn is_public_suffix(&self, domain: &str) -> bool {
        let Some(list) = self.inner.as_ref() else {
            return false;
        };
        // Reproduce curl's "requires lowercase" contract: match case-insensitively.
        let normalized = domain.to_ascii_lowercase();
        match list.suffix(normalized.as_bytes()) {
            // The whole input is a public suffix iff the computed suffix span is
            // the entire input.
            Some(suffix) => suffix.as_bytes() == normalized.as_bytes(),
            None => false,
        }
    }

    /// Returns the registrable domain (eTLD+1) of `host`, if one exists.
    ///
    /// This mirrors `libpsl`'s `psl_registrable_domain`: for
    /// `www.example.co.uk` it returns `example.co.uk`, i.e. the public suffix
    /// (`co.uk`) plus one additional label. A bare public suffix such as `com`
    /// or `co.uk` has no registrable domain and yields `None`, as does any input
    /// when no list is loaded (the non-`libpsl` fallback).
    ///
    /// Like `libpsl`, the result is a borrowed slice of the input `host` (the C
    /// API returns a pointer into the caller's string), so the original letter
    /// case is preserved even though matching itself is case-insensitive. The
    /// returned slice therefore borrows from `host`, not from `self`.
    pub fn registrable_domain<'h>(&self, host: &'h str) -> Option<&'h str> {
        let list = self.inner.as_ref()?;
        // Match case-insensitively on a lowercased copy. ASCII lowercasing never
        // changes the byte length, so a byte offset computed on `normalized`
        // maps 1:1 onto `host`.
        let normalized = host.to_ascii_lowercase();
        let domain = list.domain(normalized.as_bytes())?;
        let suffix_len = domain.as_bytes().len();
        if suffix_len == 0 {
            return None;
        }
        // The registrable domain is always a trailing span of the host. Recover
        // that span from the *original* `host` to preserve its case. The span
        // begins at a label boundary (the byte before it is `.`), so it is a
        // valid UTF-8 boundary; `get` returns `None` rather than panicking if
        // that ever fails to hold.
        let start = host.len().checked_sub(suffix_len)?;
        host.get(start..)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny, self-contained Public Suffix List covering the rules exercised by
    /// the tests. The ICANN section markers ensure the rules are parsed as
    /// canonical ICANN suffixes, exactly as they appear in the published list.
    const TEST_PSL: &str = "\
// ===BEGIN ICANN DOMAINS===
com
net
org
uk
co.uk
// ===END ICANN DOMAINS===
";

    /// Builds a handle backed by [`TEST_PSL`].
    fn loaded() -> Psl {
        TEST_PSL.parse::<Psl>().expect("test PSL should parse")
    }

    /// Compile-time proof that the handle is cheaply shareable across threads,
    /// as required for the `Arc<Mutex<..>>` cookie-sharing model.
    #[test]
    fn handle_is_send_sync_clone() {
        fn assert_traits<T: Send + Sync + Clone>() {}
        assert_traits::<Psl>();
    }

    // ---------------------------------------------------------------------
    // Bundled Public Suffix List (default-on supercookie defense, F5-PSL-001)
    // ---------------------------------------------------------------------

    #[test]
    fn bundled_list_is_available_and_classifies_correctly() {
        // The list embedded via include_str! must parse and be live; a silent
        // parse failure (which would disable the supercookie defense) must be
        // caught here rather than shipped.
        let psl = Psl::bundled();
        assert!(
            psl.is_available(),
            "bundled PSL must parse and be available"
        );
        // Real public suffixes drawn from the published list.
        assert!(psl.is_public_suffix("com"));
        assert!(psl.is_public_suffix("co.uk"));
        assert!(psl.is_public_suffix("github.io")); // a private-section suffix
                                                    // Registrable domains (eTLD+1) are not themselves public suffixes.
        assert!(!psl.is_public_suffix("example.com"));
        assert!(!psl.is_public_suffix("bbc.co.uk"));
        assert_eq!(psl.registrable_domain("www.bbc.co.uk"), Some("bbc.co.uk"));
    }

    #[test]
    fn bundled_handle_is_cached_and_cheap_to_share() {
        // Repeated calls return equivalent, cheaply-cloned handles: the list is
        // parsed once and shared via Arc across every caller and clone.
        let a = Psl::bundled();
        let b = Psl::bundled();
        assert!(a.is_available() && b.is_available());
        assert_eq!(a.is_public_suffix("co.uk"), b.is_public_suffix("co.uk"));
    }

    // ---------------------------------------------------------------------
    // Required parity cases from the agent specification.
    // ---------------------------------------------------------------------

    #[test]
    fn required_com_is_public_suffix() {
        assert!(loaded().is_public_suffix("com"));
    }

    #[test]
    fn required_example_com_is_not_public_suffix() {
        assert!(!loaded().is_public_suffix("example.com"));
    }

    #[test]
    fn required_registrable_domain_of_multi_label_host() {
        assert_eq!(
            loaded().registrable_domain("www.example.co.uk"),
            Some("example.co.uk")
        );
    }

    // ---------------------------------------------------------------------
    // is_public_suffix — additional semantics.
    // ---------------------------------------------------------------------

    #[test]
    fn multi_label_public_suffix_is_recognized() {
        assert!(loaded().is_public_suffix("co.uk"));
        assert!(loaded().is_public_suffix("uk"));
    }

    #[test]
    fn registrable_second_level_is_not_a_public_suffix() {
        assert!(!loaded().is_public_suffix("example.co.uk"));
    }

    #[test]
    fn unknown_single_label_is_public_suffix_via_star_rule() {
        // The PSL algorithm's implicit `*` rule treats an unknown single label
        // as a public suffix, matching libpsl's psl_is_public_suffix.
        assert!(loaded().is_public_suffix("thistldoesnotexist"));
        // ...but a registrable name under that unknown label is not.
        assert!(!loaded().is_public_suffix("host.thistldoesnotexist"));
    }

    #[test]
    fn public_suffix_matching_is_case_insensitive() {
        // curl lowercases before its PSL checks; we reproduce that regardless of
        // the caller's letter case.
        assert!(loaded().is_public_suffix("COM"));
        assert!(loaded().is_public_suffix("Co.Uk"));
        assert!(!loaded().is_public_suffix("Example.COM"));
    }

    #[test]
    fn empty_domain_is_not_a_public_suffix() {
        assert!(!loaded().is_public_suffix(""));
    }

    // ---------------------------------------------------------------------
    // registrable_domain — additional semantics.
    // ---------------------------------------------------------------------

    #[test]
    fn registrable_domain_of_second_level_host() {
        assert_eq!(
            loaded().registrable_domain("example.com"),
            Some("example.com")
        );
    }

    #[test]
    fn bare_public_suffix_has_no_registrable_domain() {
        assert_eq!(loaded().registrable_domain("com"), None);
        assert_eq!(loaded().registrable_domain("co.uk"), None);
    }

    #[test]
    fn registrable_domain_preserves_original_case() {
        // Matching is case-insensitive, but the returned slice borrows the
        // original `host`, so its case is preserved (as libpsl returns a pointer
        // into the caller's string).
        assert_eq!(
            loaded().registrable_domain("WWW.Example.CO.UK"),
            Some("Example.CO.UK")
        );
    }

    #[test]
    fn registrable_domain_of_empty_host_is_none() {
        assert_eq!(loaded().registrable_domain(""), None);
    }

    // ---------------------------------------------------------------------
    // Fallback behaviour — no list loaded (curl built without libpsl).
    // ---------------------------------------------------------------------

    #[test]
    fn empty_handle_reports_unavailable() {
        assert!(!Psl::empty().is_available());
        assert!(!Psl::default().is_available());
    }

    #[test]
    fn loaded_handle_reports_available() {
        assert!(loaded().is_available());
    }

    #[test]
    fn empty_handle_treats_everything_as_not_public_suffix() {
        let psl = Psl::empty();
        assert!(!psl.is_public_suffix("com"));
        assert!(!psl.is_public_suffix("co.uk"));
        assert!(!psl.is_public_suffix("example.com"));
    }

    #[test]
    fn empty_handle_has_no_registrable_domain() {
        let psl = Psl::default();
        assert_eq!(psl.registrable_domain("www.example.co.uk"), None);
        assert_eq!(psl.registrable_domain("example.com"), None);
    }

    // ---------------------------------------------------------------------
    // Construction: from_bytes, cloning, and parse errors.
    // ---------------------------------------------------------------------

    #[test]
    fn from_bytes_parses_like_from_str() {
        let psl = Psl::from_bytes(TEST_PSL.as_bytes()).expect("bytes should parse");
        assert!(psl.is_public_suffix("com"));
        assert_eq!(
            psl.registrable_domain("www.example.co.uk"),
            Some("example.co.uk")
        );
    }

    #[test]
    fn clone_shares_the_same_list_cheaply() {
        let original = loaded();
        let clone = original.clone();
        // Both handles answer identically because they share one Arc'd list.
        assert!(clone.is_public_suffix("com"));
        assert_eq!(
            clone.registrable_domain("a.example.com"),
            Some("example.com")
        );
        assert!(original.is_available());
    }

    #[test]
    fn empty_list_text_is_a_parse_error() {
        assert!("".parse::<Psl>().is_err());
    }

    #[test]
    fn invalid_utf8_bytes_are_a_parse_error() {
        // 0xFF is never a valid UTF-8 byte.
        let err = Psl::from_bytes(&[0xFF, 0xFE, 0x00]);
        assert!(err.is_err());
    }

    #[test]
    fn debug_does_not_dump_the_list() {
        let rendered = format!("{:?}", loaded());
        assert!(rendered.contains("Psl"));
        assert!(rendered.contains("available"));
        // The rule text must not leak into the Debug output.
        assert!(!rendered.contains("co.uk"));
    }
}
