// SPDX-License-Identifier: curl

//! Internationalized Domain Name (IDN) conversions.
//!
//! This module is an idiomatic-Rust rewrite of curl's `lib/idn.c`. It converts
//! host labels between their Unicode representation and the
//! ASCII-Compatible Encoding (ACE / Punycode — the `xn--…` form) that DNS and
//! the on-the-wire protocols require. Conversion happens for a hostname before
//! it is resolved and connected to, and — in the opposite direction — to derive
//! a human-readable *display* name (used, for example, in `--trace` output).
//!
//! # Relationship to `lib/idn.c`
//!
//! curl performs IDN work through a small set of functions whose names are, by
//! historical accident, the opposite of what one might expect:
//!
//! | curl (`lib/idn.c`)                              | direction        | this module        |
//! |-------------------------------------------------|------------------|--------------------|
//! | `Curl_idnconvert_hostname` → `Curl_idn_decode` → `idn_decode` → `idn2_lookup_*` | Unicode → ACE | [`to_ascii`]   |
//! | `Curl_idn_encode` → `idn_encode` → `idn2_to_unicode_8z8z`                       | ACE → Unicode | [`from_ascii`] |
//! | `Curl_is_ASCII_name`                            | classification   | [`is_ascii_name`]  |
//!
//! In other words curl's `*_decode` path produces the ASCII (ACE) form used on
//! the wire, and curl's `*_encode` path produces the Unicode form used for
//! display. The function names in this module ([`to_ascii`] / [`from_ascii`])
//! describe the *effect* rather than curl's inverted vocabulary, but the
//! observable behavior is preserved exactly.
//!
//! # Backend
//!
//! The C code selected an IDN backend at compile time: GNU `libidn2`
//! (`idn2_lookup_ul` / `idn2_lookup_u8`), the Windows `normaliz` API
//! (`IdnToAscii` / `IdnToUnicode`), or the Apple ICU `uidna_*` API. This rewrite
//! collapses all of those onto the single pure-Rust [`idna`] crate, which
//! implements the same Unicode Technical Standard #46 (UTS #46) processing that
//! `idn2` performs in its non-transitional mode. No C IDN library is linked, and
//! the Windows / macOS platform branches from the C source are intentionally not
//! carried forward — only the four target platforms are supported and they all
//! share this one code path (AAP §0.2.2). Because the backend is now always
//! compiled in, the "IDN" feature is unconditionally advertised in the version
//! string; there is no build-time `#[cfg]` gate on this module.
//!
//! # Error mapping
//!
//! curl reports every IDN conversion failure as `CURLE_URL_MALFORMAT` (the C
//! `idn_decode`/`idn_encode` helpers do so directly, and `Curl_idn_decode`
//! additionally rejects an empty result the same way). The libidn2
//! "too old library" (`CURLE_NOT_BUILT_IN`) and out-of-memory
//! (`CURLE_OUT_OF_MEMORY`) branches cannot arise with a pure-Rust, always-present
//! backend, so they are not reproduced. This module therefore maps all failures
//! to [`Error::url`], which carries [`crate::error::CurlCode::UrlMalformat`] and
//! renders curl's canonical `strerror` text, keeping stderr and
//! `curl_easy_strerror` output byte-stable.
//!
//! # Memory-safety guarantee
//!
//! This module is written entirely in safe Rust: it performs no raw-pointer
//! manipulation and never panics on caller-supplied input — every fallible
//! operation returns an [`Error`] instead. The keyword that opts out of the
//! compiler's memory-safety checks is intentionally absent from this file, so
//! the crate-wide `grep` audit of `curl-rs-lib/src/` stays green.

use crate::error::{Error, Result};

use idna::{domain_to_ascii, domain_to_unicode};

/// Reports whether `host` is a plain ASCII name that needs no IDN conversion.
///
/// This mirrors curl's `Curl_is_ASCII_name`: a name qualifies as "ASCII" when
/// none of its bytes has the high bit (`0x80`) set. The C function treats a
/// `NULL` pointer as ASCII (returning `TRUE`); the Rust equivalent — the empty
/// string — likewise reports `true`, because a `&str` can never be null and an
/// empty name contains no non-ASCII byte. [`str::is_ascii`] performs precisely
/// this per-byte `< 0x80` test.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::idn::is_ascii_name;
/// assert!(is_ascii_name("example.com"));
/// assert!(is_ascii_name("")); // empty ⇒ ASCII, matching curl's NULL handling
/// assert!(is_ascii_name("xn--bcher-kva.example")); // ACE labels are ASCII
/// assert!(!is_ascii_name("bücher.example"));
/// ```
#[must_use]
pub fn is_ascii_name(host: &str) -> bool {
    host.is_ascii()
}

/// Converts a UTF-8 hostname to its ASCII-Compatible Encoding (ACE / Punycode).
///
/// This is the conversion curl applies to a hostname before resolution and
/// connection — `Curl_idnconvert_hostname` in `lib/idn.c`, which calls
/// `Curl_idn_decode` → `idn_decode` → `idn2_lookup_*`. The returned string is
/// the `xn--…`-encoded form suitable for DNS and for placement on the wire.
///
/// # Behavior
///
/// * **ASCII pass-through.** If `host` is already a pure-ASCII name (see
///   [`is_ascii_name`]) it is returned verbatim, with its byte content —
///   including letter case — left completely untouched. This mirrors the
///   `if(!Curl_is_ASCII_name(host->name))` gate in `Curl_idnconvert_hostname`:
///   curl only invokes the IDN machinery for names that actually contain
///   non-ASCII bytes, so an ASCII name is never normalized or lower-cased here.
/// * **Unicode conversion.** Otherwise the name is processed with UTS #46 (via
///   [`idna::domain_to_ascii`]), the same standard `idn2` applies in its
///   non-transitional mode, yielding the ACE form.
///
/// # Errors
///
/// Returns [`Error::url`] (mapping to `CURLE_URL_MALFORMAT`) when the name
/// cannot be converted to a valid ACE form, and — mirroring the `if(!d[0])`
/// guard in curl's `Curl_idn_decode` — when conversion succeeds but produces an
/// empty label, which is not an acceptable hostname.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::idn::to_ascii;
/// assert_eq!(to_ascii("bücher.example").unwrap(), "xn--bcher-kva.example");
/// assert_eq!(to_ascii("example.com").unwrap(), "example.com");
/// ```
pub fn to_ascii(host: &str) -> Result<String> {
    // curl performs IDN ToASCII only for names that actually contain non-ASCII
    // bytes; a pure-ASCII name (the empty string included) is already in its
    // wire form and is returned verbatim, preserving its exact bytes and case.
    // This is the `if(!Curl_is_ASCII_name(host->name))` gate from
    // `Curl_idnconvert_hostname`.
    if is_ascii_name(host) {
        return Ok(host.to_owned());
    }

    match domain_to_ascii(host) {
        // Successful, non-empty ACE encoding — the normal path.
        Ok(ascii) if !ascii.is_empty() => Ok(ascii),
        // A conversion that yields an empty label is rejected exactly as curl's
        // `Curl_idn_decode` does with its `if(!d[0])` check.
        Ok(_) => Err(Error::url(format!(
            "IDN hostname {host:?} converted to an empty ASCII label"
        ))),
        // Any UTS #46 failure maps to `CURLE_URL_MALFORMAT`, matching curl's
        // `idn_decode` handling of a failed `idn2_lookup_*` lookup. The opaque
        // `idna::Errors` value carries no actionable detail, so the retained
        // context names the offending host.
        Err(_) => Err(Error::url(format!(
            "IDN hostname {host:?} could not be converted to ASCII (ACE/Punycode)"
        ))),
    }
}

/// Converts an ASCII-Compatible-Encoded (ACE / Punycode) hostname back to its
/// Unicode representation.
///
/// This is curl's `Curl_idn_encode` → `idn_encode` → `idn2_to_unicode_8z8z`
/// path, used to produce a human-readable *display* name (for example the
/// `dispname` shown in `--trace` / `--verbose` diagnostics).
///
/// Unlike [`to_ascii`], this direction has **no** ASCII pass-through gate: ACE
/// labels (`xn--…`) are themselves ASCII, so gating on ASCII-ness would defeat
/// the decoding. A name that contains no encoded labels simply round-trips
/// through the normalization unchanged.
///
/// # Errors
///
/// [`idna::domain_to_unicode`] is best-effort — it always returns a string, but
/// when the accompanying result is an error the string contains U+FFFD
/// REPLACEMENT CHARACTERs and, per the UTS #46 specification, must not be used
/// in a network protocol. curl's `idn_encode` likewise reports failure as
/// `CURLE_URL_MALFORMAT`, so this function surfaces [`Error::url`] rather than
/// the lossy string.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::idn::from_ascii;
/// assert_eq!(from_ascii("xn--bcher-kva.example").unwrap(), "bücher.example");
/// assert_eq!(from_ascii("example.com").unwrap(), "example.com");
/// ```
pub fn from_ascii(host: &str) -> Result<String> {
    let (unicode, result) = domain_to_unicode(host);
    match result {
        Ok(()) => Ok(unicode),
        // On any UTS #46 error the decoded string is lossy (REPLACEMENT
        // CHARACTERs) and unusable; report the malformed-URL error curl uses.
        Err(_) => Err(Error::url(format!(
            "ACE hostname {host:?} could not be converted to Unicode"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CurlCode;

    /// The canonical textbook IDN example — German "bücher" (books) — and its
    /// ACE / Punycode form. Used across the encode/decode/round-trip tests.
    const UNICODE_HOST: &str = "bücher.example";
    const ACE_HOST: &str = "xn--bcher-kva.example";

    #[test]
    fn to_ascii_encodes_unicode_host() {
        // The headline parity assertion from the file specification.
        assert_eq!(to_ascii(UNICODE_HOST).unwrap(), ACE_HOST);
    }

    #[test]
    fn to_ascii_passes_through_ascii_verbatim() {
        // A plain ASCII name is returned unchanged.
        assert_eq!(to_ascii("example.com").unwrap(), "example.com");
        // Crucially, the ASCII gate must NOT normalize or lower-case: curl's
        // `Curl_is_ASCII_name` short-circuit leaves the bytes exactly as given.
        assert_eq!(to_ascii("Example.COM").unwrap(), "Example.COM");
        // An already-ACE label is ASCII, so it too passes through untouched
        // (no double-encoding).
        assert_eq!(to_ascii(ACE_HOST).unwrap(), ACE_HOST);
        // The empty name is curl's NULL-equivalent: ASCII ⇒ returned as-is.
        assert_eq!(to_ascii("").unwrap(), "");
    }

    #[test]
    fn from_ascii_decodes_ace() {
        assert_eq!(from_ascii(ACE_HOST).unwrap(), UNICODE_HOST);
    }

    #[test]
    fn from_ascii_passes_plain_ascii() {
        // A name with no encoded labels round-trips through normalization
        // unchanged.
        assert_eq!(from_ascii("example.com").unwrap(), "example.com");
    }

    #[test]
    fn round_trips_unicode_host() {
        let ace = to_ascii(UNICODE_HOST).unwrap();
        assert_eq!(ace, ACE_HOST);
        assert_eq!(from_ascii(&ace).unwrap(), UNICODE_HOST);
    }

    #[test]
    fn to_ascii_rejects_invalid_unicode_host() {
        // A label may not begin with a Unicode combining mark (a UTS #46
        // validity criterion). U+0300 COMBINING GRAVE ACCENT is non-ASCII, so
        // the input passes the ASCII gate and then fails UTS #46 processing.
        // curl reports such failures as CURLE_URL_MALFORMAT (== 3).
        let err = to_ascii("\u{0300}bad.example").unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
        assert_eq!(err.code_i32(), 3);
    }

    #[test]
    fn from_ascii_rejects_invalid_input() {
        // The same leading-combining-mark violation is rejected on the decode
        // path, again mapping to CURLE_URL_MALFORMAT.
        let err = from_ascii("\u{0300}bad.example").unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn is_ascii_name_matches_curl() {
        // Mirrors Curl_is_ASCII_name across its edge cases.
        assert!(is_ascii_name("example.com"));
        assert!(is_ascii_name("")); // NULL/empty ⇒ ASCII in curl
        assert!(is_ascii_name(ACE_HOST)); // xn--… labels are ASCII
        assert!(is_ascii_name("Example.COM"));
        assert!(!is_ascii_name(UNICODE_HOST));
        assert!(!is_ascii_name("bücher"));
    }

    #[test]
    fn conversions_never_panic_on_odd_input() {
        // Robustness contract: neither direction may panic on arbitrary
        // caller-supplied input — every failure must surface as an `Err`.
        let odd_inputs = [
            "",
            ".",
            "..",
            "a.",
            "-",
            "xn--",
            "xn--a",
            "☃.example",
            "α.β.γ",
            "127.0.0.1",
            "192.168.0.1",
            "under_score",
            "läbel",
        ];
        for host in odd_inputs {
            // Results are intentionally discarded; we only assert the absence
            // of a panic and that any error carries the malformed-URL code.
            if let Err(err) = to_ascii(host) {
                assert_eq!(err.code(), CurlCode::UrlMalformat);
            }
            if let Err(err) = from_ascii(host) {
                assert_eq!(err.code(), CurlCode::UrlMalformat);
            }
        }
    }
}
