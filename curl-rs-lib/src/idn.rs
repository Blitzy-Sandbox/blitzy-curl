//! Internationalized Domain Name (IDN) handling.
//!
//! This module provides functions for converting between Unicode hostnames and
//! their ASCII (Punycode) equivalents, as well as normalizing hostnames for
//! network use. It replaces all C IDN backends (libidn2, Win32
//! `IdnToAscii`/`IdnToUnicode`, and Apple ICU `UIDNA`) from `lib/idn.c` with
//! a single pure-Rust implementation powered by the [`idna`] crate.
//!
//! The `idna` crate implements UTS #46 (Unicode IDNA Compatibility Processing)
//! with non-transitional processing, which provides IDNA 2008-equivalent
//! resolution — matching the behavior of libidn2 with `IDN2_NONTRANSITIONAL`.
//!
//! # Functions
//!
//! * [`idn_to_ascii`] — convert a Unicode hostname to ASCII (Punycode)
//! * [`idn_to_unicode`] — convert a Punycode hostname back to Unicode
//! * [`normalize_hostname`] — lowercase and IDN-convert a hostname for network use
//!
//! # Error Mapping
//!
//! | C error code             | Rust error variant            |
//! |--------------------------|-------------------------------|
//! | `CURLE_URL_MALFORMAT`(3) | [`CurlError::UrlMalformat`]  |
//! | `CURLE_OUT_OF_MEMORY`(27)| [`CurlError::OutOfMemory`]   |

use crate::error::CurlError;
use idna::{domain_to_ascii_cow, domain_to_unicode, AsciiDenyList};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns `true` when every byte in `hostname` is in the ASCII range
/// (0x00–0x7F). This mirrors the C function `Curl_is_ASCII_name()` from
/// `lib/idn.c`, which checks each unsigned byte for the high bit.
///
/// An empty string is considered ASCII (matching C behavior where a NULL
/// pointer also returns `true`).
#[inline]
fn is_ascii_name(hostname: &str) -> bool {
    hostname.bytes().all(|b| b & 0x80 == 0)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Convert a Unicode hostname to its ASCII (Punycode) representation.
///
/// This is the Rust equivalent of `Curl_idn_decode()` in `lib/idn.c`. It
/// accepts a hostname that may contain non-ASCII (Unicode) characters and
/// returns the IDNA-processed ASCII form suitable for DNS resolution and
/// wire-level protocol use.
///
/// Processing is performed by [`idna::domain_to_ascii_cow`] using
/// [`AsciiDenyList::URL`], which enforces the WHATWG URL Standard's
/// [forbidden domain code point](https://url.spec.whatwg.org/#forbidden-domain-code-point)
/// check in addition to the standard UTS #46 algorithm with non-transitional
/// processing.
///
/// # Errors
///
/// * [`CurlError::UrlMalformat`] — the hostname contains invalid IDN
///   characters, violates IDNA rules, or results in an empty ASCII label.
///   This matches the C `CURLE_URL_MALFORMAT` (code 3) returned by
///   `Curl_idn_decode()`.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::idn::idn_to_ascii;
/// // Pure ASCII passes through unchanged (lowercased).
/// assert_eq!(idn_to_ascii("example.com").unwrap(), "example.com");
///
/// // Unicode labels are converted to Punycode.
/// assert_eq!(idn_to_ascii("münchen.de").unwrap(), "xn--mnchen-3ya.de");
/// ```
pub fn idn_to_ascii(hostname: &str) -> Result<String, CurlError> {
    // Empty input is not a valid hostname.
    if hostname.is_empty() {
        return Err(CurlError::UrlMalformat);
    }

    // Attempt the UTS #46 domain-to-ASCII conversion.
    // `domain_to_ascii_cow` takes `&[u8]` and an `AsciiDenyList`.
    // Using `AsciiDenyList::URL` matches the WHATWG URL Standard behavior
    // and provides the strictest deny-list appropriate for URL hostnames.
    let ascii = domain_to_ascii_cow(hostname.as_bytes(), AsciiDenyList::URL)
        .map_err(|_: idna::Errors| CurlError::UrlMalformat)?;

    // The C implementation rejects zero-length results after conversion
    // (see `Curl_idn_decode` in lib/idn.c, line 317–320).
    let result = ascii.into_owned();
    if result.is_empty() {
        return Err(CurlError::UrlMalformat);
    }

    Ok(result)
}

/// Convert an ASCII (Punycode) hostname back to its Unicode representation.
///
/// This is the Rust equivalent of `Curl_idn_encode()` in `lib/idn.c`. It
/// accepts a Punycode-encoded hostname and returns the human-readable Unicode
/// form.
///
/// Processing is performed by [`idna::domain_to_unicode`] using UTS #46 with
/// non-transitional processing.
///
/// # Errors
///
/// * [`CurlError::UrlMalformat`] — the input is not valid Punycode or
///   violates IDNA rules. This matches the C `CURLE_URL_MALFORMAT` returned
///   by `Curl_idn_encode()` when `idn2_to_unicode_8z8z()` fails.
/// * [`CurlError::OutOfMemory`] — allocation failure during conversion.
///   This matches the C `CURLE_OUT_OF_MEMORY` returned when `idn2_to_unicode_8z8z()`
///   reports `IDNA_MALLOC_ERROR`.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::idn::idn_to_unicode;
/// // Punycode is decoded to Unicode.
/// assert_eq!(idn_to_unicode("xn--mnchen-3ya.de").unwrap(), "münchen.de");
///
/// // Plain ASCII passes through unchanged.
/// assert_eq!(idn_to_unicode("example.com").unwrap(), "example.com");
/// ```
pub fn idn_to_unicode(hostname: &str) -> Result<String, CurlError> {
    // Empty input is not a valid hostname.
    if hostname.is_empty() {
        return Err(CurlError::UrlMalformat);
    }

    // `domain_to_unicode` returns a tuple: (String, Result<(), Errors>).
    // The first element is always populated (using REPLACEMENT CHARACTER for
    // error illustration), but we only return it when the result is Ok.
    let (unicode, result) = domain_to_unicode(hostname);

    // If UTS #46 processing reported errors, map to UrlMalformat to match
    // the C behavior of returning CURLE_URL_MALFORMAT on idn2 failure.
    result.map_err(|_: idna::Errors| CurlError::UrlMalformat)?;

    // Reject empty results (defensive, mirrors C behavior).
    if unicode.is_empty() {
        return Err(CurlError::UrlMalformat);
    }

    // Allocate the result using try_reserve to provide a graceful error
    // path for allocation failures, matching the C behavior where
    // idn2_to_unicode_8z8z() returning IDNA_MALLOC_ERROR maps to
    // CURLE_OUT_OF_MEMORY. With Rust's default allocator OOM panics, but
    // custom allocators may return Err from try_reserve instead.
    alloc_checked(unicode)
}

/// Attempt to allocate a checked copy of the given string, returning
/// [`CurlError::OutOfMemory`] on allocation failure. This mirrors the C
/// pattern where `curlx_strdup()` failure triggers `CURLE_OUT_OF_MEMORY`.
#[inline]
fn alloc_checked(s: String) -> Result<String, CurlError> {
    // Fast path: the string is already allocated, verify capacity is sane.
    // In practice this always succeeds under the default global allocator.
    // Under a custom allocator that reports capacity exhaustion, the
    // try_reserve_exact call would fail and we'd return OutOfMemory.
    let mut buf = String::new();
    buf.try_reserve_exact(s.len())
        .map_err(|_| CurlError::OutOfMemory)?;
    buf.push_str(&s);
    Ok(buf)
}

/// Normalize a hostname for network use.
///
/// This is the Rust equivalent of `Curl_idnconvert_hostname()` in
/// `lib/idn.c`. It performs the following steps:
///
/// 1. If the hostname is pure ASCII, it is lowercased and returned directly.
/// 2. If the hostname contains non-ASCII characters, it is converted to ASCII
///    (Punycode) via [`idn_to_ascii`], which inherently lowercases and
///    normalizes the result.
///
/// The returned string is always a valid ASCII hostname suitable for DNS
/// resolution and wire-level protocol headers.
///
/// # Errors
///
/// * [`CurlError::UrlMalformat`] — the hostname contains invalid IDN
///   characters or violates IDNA rules.
/// * [`CurlError::OutOfMemory`] — allocation failure (in practice
///   extremely unlikely with Rust's allocator, but preserved for API
///   symmetry with the C implementation).
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::idn::normalize_hostname;
/// // ASCII hostnames are simply lowercased.
/// assert_eq!(normalize_hostname("Example.COM").unwrap(), "example.com");
///
/// // Unicode hostnames are converted to Punycode.
/// assert_eq!(normalize_hostname("München.DE").unwrap(), "xn--mnchen-3ya.de");
/// ```
pub fn normalize_hostname(hostname: &str) -> Result<String, CurlError> {
    // Empty input is not a valid hostname.
    if hostname.is_empty() {
        return Err(CurlError::UrlMalformat);
    }

    if is_ascii_name(hostname) {
        // Pure ASCII: lowercase and return.
        // The C implementation sets `host->dispname = host->name` and returns
        // CURLE_OK for ASCII names without further IDN processing.
        // We additionally lowercase for normalization, matching the behavior
        // of `domain_to_ascii_cow` which also lowercases ASCII labels.
        Ok(hostname.to_ascii_lowercase())
    } else {
        // Non-ASCII: perform full IDN conversion to ASCII (Punycode).
        // `idn_to_ascii` uses `domain_to_ascii_cow` which handles
        // lowercasing, NFC normalization, and Punycode encoding.
        idn_to_ascii(hostname)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- idn_to_ascii tests --

    #[test]
    fn ascii_passthrough() {
        // Pure ASCII hostname should pass through lowercased.
        let result = idn_to_ascii("example.com").unwrap();
        assert_eq!(result, "example.com");
    }

    #[test]
    fn ascii_uppercase_lowered() {
        // UTS #46 lowercases ASCII labels.
        let result = idn_to_ascii("EXAMPLE.COM").unwrap();
        assert_eq!(result, "example.com");
    }

    #[test]
    fn unicode_to_punycode() {
        // German IDN: "münchen.de" → "xn--mnchen-3ya.de"
        let result = idn_to_ascii("münchen.de").unwrap();
        assert_eq!(result, "xn--mnchen-3ya.de");
    }

    #[test]
    fn mixed_ascii_and_unicode_labels() {
        // Only the non-ASCII label should be Punycode-encoded.
        let result = idn_to_ascii("www.münchen.de").unwrap();
        assert_eq!(result, "www.xn--mnchen-3ya.de");
    }

    #[test]
    fn chinese_domain() {
        // Chinese IDN example.
        let result = idn_to_ascii("中文.com").unwrap();
        assert_eq!(result, "xn--fiq228c.com");
    }

    #[test]
    fn empty_hostname_rejected() {
        let result = idn_to_ascii("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::UrlMalformat);
    }

    // -- idn_to_unicode tests --

    #[test]
    fn punycode_to_unicode() {
        let result = idn_to_unicode("xn--mnchen-3ya.de").unwrap();
        assert_eq!(result, "münchen.de");
    }

    #[test]
    fn ascii_domain_to_unicode_passthrough() {
        // Plain ASCII domain should pass through unchanged.
        let result = idn_to_unicode("example.com").unwrap();
        assert_eq!(result, "example.com");
    }

    #[test]
    fn unicode_empty_rejected() {
        let result = idn_to_unicode("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::UrlMalformat);
    }

    // -- normalize_hostname tests --

    #[test]
    fn normalize_ascii_lowercased() {
        let result = normalize_hostname("Example.COM").unwrap();
        assert_eq!(result, "example.com");
    }

    #[test]
    fn normalize_unicode_to_punycode() {
        let result = normalize_hostname("München.DE").unwrap();
        assert_eq!(result, "xn--mnchen-3ya.de");
    }

    #[test]
    fn normalize_already_lowercase_ascii() {
        let result = normalize_hostname("already.lowercase.com").unwrap();
        assert_eq!(result, "already.lowercase.com");
    }

    #[test]
    fn normalize_empty_rejected() {
        let result = normalize_hostname("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::UrlMalformat);
    }

    // -- is_ascii_name helper tests --

    #[test]
    fn is_ascii_name_pure_ascii() {
        assert!(is_ascii_name("example.com"));
        assert!(is_ascii_name("HELLO"));
        assert!(is_ascii_name(""));
    }

    #[test]
    fn is_ascii_name_with_unicode() {
        assert!(!is_ascii_name("münchen.de"));
        assert!(!is_ascii_name("中文.com"));
        assert!(!is_ascii_name("café"));
    }

    // -- Edge cases --

    #[test]
    fn single_label_ascii() {
        let result = idn_to_ascii("localhost").unwrap();
        assert_eq!(result, "localhost");
    }

    #[test]
    fn single_label_unicode() {
        let result = idn_to_ascii("münchen").unwrap();
        assert_eq!(result, "xn--mnchen-3ya");
    }

    #[test]
    fn normalize_mixed_case_unicode() {
        // The IDN conversion should handle case-folding for Unicode chars.
        let result = normalize_hostname("MÜNCHEN.DE").unwrap();
        assert_eq!(result, "xn--mnchen-3ya.de");
    }

    #[test]
    fn roundtrip_idn_conversion() {
        // Converting to ASCII and back should yield a normalized Unicode form.
        let original = "münchen.de";
        let ascii = idn_to_ascii(original).unwrap();
        let back = idn_to_unicode(&ascii).unwrap();
        assert_eq!(back, "münchen.de");
    }

    #[test]
    fn trailing_dot_handled() {
        // FQDN with trailing dot — UTS #46 should handle this.
        let result = idn_to_ascii("example.com.").unwrap();
        assert_eq!(result, "example.com.");
    }

    #[test]
    fn multiple_unicode_labels() {
        // Multiple non-ASCII labels in a single hostname.
        let result = idn_to_ascii("münchen.münchen.de").unwrap();
        assert_eq!(result, "xn--mnchen-3ya.xn--mnchen-3ya.de");
    }
}
