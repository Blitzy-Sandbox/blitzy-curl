//! Internationalized Domain Name (IDN) conversion.
//!
//! Hostnames that contain non-ASCII characters cannot be placed on the wire
//! (in DNS queries or in an HTTP `Host:` header) as-is; they must first be
//! converted to their **ASCII Compatible Encoding** (ACE), i.e. the `xn--`
//! *Punycode* form defined by [IDNA]/[UTS-46]. This module performs that
//! conversion and its inverse.
//!
//! # Relationship to the C implementation
//!
//! This is the memory-safe Rust counterpart of `lib/idn.c` in the curl C tree
//! (the behavioral/ABI oracle). The C code wraps `libidn2` (or, on Windows,
//! `IdnToAscii`, or Apple's ICU `uidna_*`); this module instead wraps the
//! pure-Rust [`idna`] crate, so **no `libidn2`/ICU/C library is linked**. The
//! externally observable behavior — when conversion is triggered, the exact
//! `xn--` output, and the error codes — is reproduced faithfully because the
//! produced host is wire-observable and is compared verbatim by the curl test
//! suite (`tests/data`).
//!
//! The C entry points and their Rust equivalents:
//!
//! | C (`lib/idn.c`)            | direction          | Rust here        |
//! |----------------------------|--------------------|------------------|
//! | `Curl_is_ASCII_name`       | detect non-ASCII   | [`needs_idn`]    |
//! | `Curl_idn_decode` (ToASCII)| Unicode → ACE      | [`to_ascii`]     |
//! | `Curl_idn_encode` (ToUnicode)| ACE → Unicode    | [`from_ascii`]   |
//!
//! (Note curl's confusing naming: `Curl_idn_decode` is the ToASCII path and
//! `Curl_idn_encode` is the ToUnicode path. The Rust names here are chosen to
//! describe the *result* — `to_ascii` / `from_ascii` — to avoid that trap.)
//!
//! # Feature gating
//!
//! IDN support is gated behind the `idn` Cargo feature, mirroring curl's
//! `USE_IDN` compile gate and the [`CURL_VERSION_IDN`] capability bit
//! (`1 << 10`) reported by the version module. With the feature **enabled**,
//! [`to_ascii`]/[`from_ascii`] perform real UTS-46 conversion. With the feature
//! **disabled**, an ASCII host still passes through unchanged, but a non-ASCII
//! host cannot be converted: [`to_ascii`] returns
//! [`CurlError::NotBuiltIn`](crate::error::CurlError::NotBuiltIn), exactly like
//! curl's no-IDN build reports a feature that "was not found built-in".
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` and compiles cleanly under the
//! crate-root `#![forbid(unsafe_code)]`. All allocation and bounds handling is
//! delegated to the safe [`idna`] crate and the standard library.
//!
//! [IDNA]: https://datatracker.ietf.org/doc/html/rfc5890
//! [UTS-46]: https://www.unicode.org/reports/tr46/
//! [`idna`]: https://docs.rs/idna/
//! [`CURL_VERSION_IDN`]: https://curl.se/libcurl/c/curl_version_info.html

use crate::error::{CurlError, Result};

/// Returns `true` if `host` requires IDN conversion, i.e. it contains at least
/// one non-ASCII byte.
///
/// This is the trigger condition curl uses in `Curl_idnconvert_hostname`: it
/// is the logical inverse of curl's `Curl_is_ASCII_name`, which scans the
/// hostname for any byte with the high bit set (`& 0x80`). A hostname made up
/// entirely of ASCII (including the empty string) does **not** need conversion
/// and is left untouched.
///
/// Because a Rust [`str`] is always valid UTF-8, "contains a non-ASCII byte"
/// and "contains a non-ASCII scalar value" are equivalent here; both are
/// captured by [`str::is_ascii`].
///
/// # Examples
///
/// ```text
/// needs_idn("example.com")  == false   // pure ASCII
/// needs_idn("xn--4cab6c.se") == false  // already ACE-encoded, so ASCII
/// needs_idn("")             == false   // empty is treated as ASCII
/// needs_idn("münchen.de")   == true    // contains U+00FC
/// ```
#[must_use]
pub fn needs_idn(host: &str) -> bool {
    !host.is_ascii()
}

/// Converts a hostname to its ASCII Compatible Encoding (ACE / `xn--`
/// Punycode), returning the wire-ready, resolvable form.
///
/// This is the safe equivalent of curl's `Curl_idnconvert_hostname` +
/// `Curl_idn_decode` (the ToASCII path):
///
/// * If `host` is already pure ASCII it is returned **byte-for-byte
///   unchanged**. This matches curl, which never feeds an ASCII name to
///   `libidn2` — so the original case and form (e.g. `EXAMPLE.com`, a trailing
///   dot, or an already-`xn--` label) are preserved exactly. This matters
///   because the host is wire-observable (it appears in the DNS query and the
///   `Host:` header).
/// * Otherwise the name is converted with UTS-46 ToASCII. Unicode label
///   separators — `.` (U+002E), the ideographic full stop `。` (U+3002), the
///   fullwidth full stop `．` (U+FF0E) and the halfwidth ideographic full stop
///   `｡` (U+FF61) — are all normalized to `.` as part of UTS-46 mapping, just
///   as `libidn2` does. Input is normalized to NFC and processed
///   non-transitionally, matching curl's `IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL`
///   flags.
///
/// # Errors
///
/// * [`CurlError::UrlMalformat`] (`CURLE_URL_MALFORMAT`, 3) if the name cannot
///   be converted — e.g. a label exceeds the 63-octet DNS limit, the whole
///   name exceeds 253 octets, or the input maps to an empty ("blank") name.
///   This mirrors `libidn2` rejecting the name and curl mapping that to
///   `CURLE_URL_MALFORMAT`.
/// * [`CurlError::NotBuiltIn`] (`CURLE_NOT_BUILT_IN`, 4) **only when the `idn`
///   feature is disabled** and the host is non-ASCII: IDN support is not
///   compiled in, so the name cannot be converted. An ASCII host still passes
///   through successfully even without the feature.
///
/// # Examples
///
/// ```text
/// to_ascii("EXAMPLE.com") == Ok("EXAMPLE.com")        // ASCII: unchanged
/// to_ascii("åäö.se")      == Ok("xn--4cab6c.se")      // (with `idn` feature)
/// to_ascii("中文。com")    == Ok("xn--fiq228c.com")    // ideographic separator
/// ```
pub fn to_ascii(host: &str) -> Result<String> {
    if needs_idn(host) {
        // Non-ASCII: requires an IDN backend to encode to ACE.
        convert_to_ascii(host)
    } else {
        // Pure ASCII: pass through unchanged, preserving case and form exactly
        // as curl does (it never runs ASCII names through libidn2).
        Ok(host.to_owned())
    }
}

/// ToASCII conversion of a known-non-ASCII host, with the `idn` feature ON.
///
/// Uses the UTS-46 ToASCII operation with the configuration that matches
/// `libidn2`'s `idn2_lookup_ul` as used by curl:
///
/// * `AsciiDenyList::EMPTY` — UseSTD3ASCIIRules is **off**. curl/`libidn2` does
///   not reject characters such as `_` in host labels, so neither do we.
/// * `Hyphens::Allow` — lenient hyphen handling, matching `libidn2`'s default.
/// * `DnsLength::Verify` — enforce the DNS 63-octet-per-label / 253-octet-total
///   limits. This is required for byte-for-byte parity: curl's test suite
///   expects an over-long IDN host to fail with `CURLE_URL_MALFORMAT`, and the
///   convenience function [`idna::domain_to_ascii`] uses `DnsLength::Ignore`
///   (no length check), so the explicit [`idna::uts46::Uts46`] builder is used
///   here instead.
///
/// A successful-but-empty result is also treated as malformed, mirroring the
/// explicit zero-length guard in curl's `Curl_idn_decode` (a Unicode name that
/// maps to a blank name is rejected).
#[cfg(feature = "idn")]
fn convert_to_ascii(host: &str) -> Result<String> {
    use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};

    match Uts46::new().to_ascii(
        host.as_bytes(),
        AsciiDenyList::EMPTY,
        Hyphens::Allow,
        DnsLength::Verify,
    ) {
        Ok(ace) => {
            let ace = ace.into_owned();
            if ace.is_empty() {
                // A non-empty Unicode input that maps to a blank name is
                // rejected, exactly like curl's Curl_idn_decode zero-length
                // guard (tests/data/test763).
                Err(CurlError::UrlMalformat)
            } else {
                Ok(ace)
            }
        }
        // Any UTS-46 processing or DNS-length failure is a malformed URL host,
        // matching curl's mapping of a libidn2 lookup failure.
        Err(_) => Err(CurlError::UrlMalformat),
    }
}

/// ToASCII conversion of a known-non-ASCII host, with the `idn` feature OFF.
///
/// No IDN backend is compiled in, so a non-ASCII host cannot be converted.
/// curl's no-IDN build reports this class of problem as
/// `CURLE_NOT_BUILT_IN`; returning that here lets `url.rs` surface the
/// equivalent URL-API condition (`CURLUE_LACKS_IDN`) to callers.
#[cfg(not(feature = "idn"))]
fn convert_to_ascii(_host: &str) -> Result<String> {
    Err(CurlError::NotBuiltIn)
}

/// Converts an ACE (`xn--` Punycode) hostname back to its Unicode display
/// form — the safe equivalent of curl's `Curl_idn_encode` (the ToUnicode
/// path).
///
/// This is the inverse of [`to_ascii`] and is used where curl decodes a host
/// for *display* purposes. The conversion is performed with UTS-46 ToUnicode.
///
/// # Errors
///
/// * [`CurlError::UrlMalformat`] (`CURLE_URL_MALFORMAT`, 3) if the input cannot
///   be decoded (e.g. a malformed `xn--` label). On failure no partial,
///   replacement-character-bearing string is returned — only the error — so the
///   result is never accidentally used on the wire.
///
/// When the `idn` feature is disabled there is no decoder, so the input is
/// returned unchanged (the ACE form is displayed verbatim); this path never
/// fails. curl's no-IDN build simply does not provide `Curl_idn_encode`, so
/// there is no wire-parity constraint on this direction.
///
/// # Examples
///
/// ```text
/// from_ascii("xn--4cab6c.se") == Ok("åäö.se")   // (with `idn` feature)
/// from_ascii("example.com")   == Ok("example.com")
/// ```
pub fn from_ascii(host: &str) -> Result<String> {
    convert_from_ascii(host)
}

/// ToUnicode conversion with the `idn` feature ON.
///
/// [`idna::domain_to_unicode`] returns a best-effort string together with a
/// result flag; per its contract the string must not be used on a network when
/// the flag signals an error, so a failure is surfaced as
/// [`CurlError::UrlMalformat`] and the partial string is discarded.
#[cfg(feature = "idn")]
fn convert_from_ascii(host: &str) -> Result<String> {
    let (unicode, result) = idna::domain_to_unicode(host);
    match result {
        Ok(()) => Ok(unicode),
        Err(_) => Err(CurlError::UrlMalformat),
    }
}

/// ToUnicode conversion with the `idn` feature OFF: no decoder available, so
/// the (ASCII) input is returned unchanged for display.
#[cfg(not(feature = "idn"))]
fn convert_from_ascii(host: &str) -> Result<String> {
    Ok(host.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CurlError;

    // Non-ASCII test inputs, written with `\u{}` escapes so the source file is
    // unambiguous regardless of editor/encoding. The expected ACE outputs are
    // pure ASCII and are written literally. Every vector below was taken from,
    // or verified against, the curl 8.x `tests/data` IDN cases.
    const A_RING: char = '\u{e5}'; // å
    const A_UML: char = '\u{e4}'; // ä
    const O_UML: char = '\u{f6}'; // ö
    const U_UML: char = '\u{fc}'; // ü

    fn aao_se() -> String {
        // "åäö.se"
        format!("{A_RING}{A_UML}{O_UML}.se")
    }

    // ---- needs_idn: feature-agnostic trigger detection -------------------

    #[test]
    fn needs_idn_false_for_ascii() {
        assert!(!needs_idn("example.com"));
        assert!(!needs_idn("WWW.Example.COM"));
        assert!(!needs_idn("xn--4cab6c.se")); // already ACE => ASCII
        assert!(!needs_idn("127.0.0.1"));
        assert!(!needs_idn("under_score.host")); // '_' is ASCII
        assert!(!needs_idn("trailing.dot.")); // trailing dot is ASCII
        assert!(!needs_idn("")); // empty == ASCII (matches Curl_is_ASCII_name)
    }

    #[test]
    fn needs_idn_true_for_non_ascii() {
        assert!(needs_idn(&aao_se()));
        assert!(needs_idn(&format!("m{U_UML}nchen.de")));
        assert!(needs_idn("\u{4e2d}\u{6587}.com")); // 中文.com
        assert!(needs_idn(&format!("mixed.{O_UML}.example"))); // one non-ASCII label
    }

    // ---- to_ascii: ASCII passthrough is feature-agnostic -----------------

    #[test]
    fn to_ascii_ascii_passthrough_preserves_case_and_form() {
        // curl never runs ASCII names through libidn2, so case and form are
        // preserved byte-for-byte (NOT lower-cased like idna::domain_to_ascii).
        assert_eq!(to_ascii("EXAMPLE.com").unwrap(), "EXAMPLE.com");
        assert_eq!(to_ascii("Example.Com").unwrap(), "Example.Com");
        assert_eq!(to_ascii("example.com.").unwrap(), "example.com.");
        assert_eq!(to_ascii("xn--4cab6c.se").unwrap(), "xn--4cab6c.se");
        assert_eq!(to_ascii("under_score.host").unwrap(), "under_score.host");
        assert_eq!(to_ascii("127.0.0.1").unwrap(), "127.0.0.1");
        assert_eq!(to_ascii("").unwrap(), "");
    }

    // ---- Behavior with the `idn` feature ENABLED -------------------------

    #[cfg(feature = "idn")]
    mod idn_enabled {
        use super::*;

        // ß (U+00DF) — only exercised by the feature-on conversion vectors.
        const SHARP_S: char = '\u{df}';

        #[test]
        fn to_ascii_known_vectors_match_curl() {
            // tests/data/test1448, test2046, test2047, test962-967, ...
            assert_eq!(to_ascii(&aao_se()).unwrap(), "xn--4cab6c.se");
            // tests/data/test165 (multi-label)
            assert_eq!(
                to_ascii(&format!("www.{A_RING}{A_UML}{O_UML}.se")).unwrap(),
                "www.xn--4cab6c.se"
            );
            // tests/data/test165 — non-transitional ß (NOT folded to "ss")
            assert_eq!(
                to_ascii(&format!("www.gro{SHARP_S}e.de")).unwrap(),
                "www.xn--groe-xna.de"
            );
            assert_eq!(
                to_ascii(&format!("m{U_UML}nchen.de")).unwrap(),
                "xn--mnchen-3ya.de"
            );
            assert_eq!(to_ascii("\u{4e2d}\u{6587}.com").unwrap(), "xn--fiq228c.com");
        }

        #[test]
        fn to_ascii_normalizes_unicode_separators() {
            // U+3002 ideographic full stop is treated as a label separator,
            // producing the same ACE as the ASCII '.' form.
            assert_eq!(
                to_ascii("\u{4e2d}\u{6587}\u{3002}com").unwrap(),
                "xn--fiq228c.com"
            );
            // U+FF0E fullwidth full stop, likewise.
            assert_eq!(
                to_ascii("\u{4e2d}\u{6587}\u{ff0e}com").unwrap(),
                "xn--fiq228c.com"
            );
        }

        #[test]
        fn to_ascii_round_trips_with_from_ascii() {
            let ace = to_ascii(&aao_se()).unwrap();
            assert_eq!(ace, "xn--4cab6c.se");
            assert_eq!(from_ascii(&ace).unwrap(), aao_se());
        }

        #[test]
        fn to_ascii_too_long_label_is_malformat() {
            // tests/data/test1035: an over-long IDN host => CURLE_URL_MALFORMAT.
            let host = format!(
                "too-long-IDN-name-c{U_UML}rl-r{U_UML}le{SHARP_S}\
                 -la-la-la-dee-da-flooby-nooby.local"
            );
            assert_eq!(to_ascii(&host), Err(CurlError::UrlMalformat));
        }

        #[test]
        fn to_ascii_blank_name_is_malformat() {
            // tests/data/test763: ZERO WIDTH SPACE + ZERO WIDTH NON-JOINER map
            // to nothing, yielding a blank name => CURLE_URL_MALFORMAT.
            assert_eq!(to_ascii("\u{200b}\u{200c}"), Err(CurlError::UrlMalformat));
            // A lone soft hyphen (U+00AD) likewise maps to an empty name.
            assert_eq!(to_ascii("\u{00ad}"), Err(CurlError::UrlMalformat));
        }

        #[test]
        fn from_ascii_decodes_ace() {
            assert_eq!(from_ascii("xn--4cab6c.se").unwrap(), aao_se());
            assert_eq!(
                from_ascii("xn--mnchen-3ya.de").unwrap(),
                format!("m{U_UML}nchen.de")
            );
        }

        #[test]
        fn from_ascii_plain_ascii_is_returned() {
            assert_eq!(from_ascii("example.com").unwrap(), "example.com");
        }

        #[test]
        fn from_ascii_malformed_ace_is_malformat() {
            // A truncated/invalid Punycode label cannot be decoded.
            assert_eq!(from_ascii("xn--"), Err(CurlError::UrlMalformat));
        }
    }

    // ---- Behavior with the `idn` feature DISABLED ------------------------

    #[cfg(not(feature = "idn"))]
    mod idn_disabled {
        use super::*;

        #[test]
        fn to_ascii_non_ascii_reports_not_built_in() {
            assert_eq!(to_ascii(&aao_se()), Err(CurlError::NotBuiltIn));
            assert_eq!(
                to_ascii(&format!("m{U_UML}nchen.de")),
                Err(CurlError::NotBuiltIn)
            );
        }

        #[test]
        fn to_ascii_ascii_still_passes_through() {
            assert_eq!(to_ascii("example.com").unwrap(), "example.com");
            assert_eq!(to_ascii("EXAMPLE.com").unwrap(), "EXAMPLE.com");
            assert_eq!(to_ascii("xn--4cab6c.se").unwrap(), "xn--4cab6c.se");
        }

        #[test]
        fn from_ascii_passes_input_through() {
            // No decoder compiled in: the ACE form is displayed verbatim.
            assert_eq!(from_ascii("xn--4cab6c.se").unwrap(), "xn--4cab6c.se");
            assert_eq!(from_ascii("example.com").unwrap(), "example.com");
        }
    }

    // ---- Error-code parity with curl -------------------------------------

    #[test]
    fn mapped_error_codes_match_curl_integers() {
        // CURLE_URL_MALFORMAT == 3, CURLE_NOT_BUILT_IN == 4.
        assert_eq!(CurlError::UrlMalformat.code(), 3);
        assert_eq!(CurlError::NotBuiltIn.code(), 4);
    }
}
