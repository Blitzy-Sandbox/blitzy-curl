// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The junk scan: the cheapest gate in the parser, and the first one.
//!
//! Port of `Curl_junkscan`, defined at `lib/urlapi.c` L223-L239 and declared
//! at `lib/urlapi-int.h` L33. The C comment introducing it, at L222, is the
//! whole specification in one line: scan for byte values `<= 31`, `127` and
//! sometimes space.
//!
//! Two callers exist in the C tree and both matter to this port.
//!
//! - `parseurl` calls it at `lib/urlapi.c` L1124, before any other stage
//!   looks at the string, as
//!   `Curl_junkscan(url, &urllen, !!(flags & CURLU_ALLOW_SPACE))`. The `!!`
//!   normalizes the masked flag to a C boolean, which is why the parameter
//!   here is a `bool` and the flag test belongs to the caller in
//!   `src/parse/mod.rs` rather than to this module.
//! - `lib/doh.c` L1127 calls it as `Curl_junkscan(dnsname, &olen, FALSE)` to
//!   reject unacceptable hostname content in a DNS-over-HTTPS reply. It uses
//!   only the truthiness of the returned code and never reads the length,
//!   which is the clearest illustration of the contract below: a length is
//!   produced on success and on no other path.
//!
//! The symbol belongs to the eight-symbol drop-in set, so this behavior is
//! ABI-fixed: `src/ffi.rs` exports `Curl_junkscan` with C linkage, converts
//! the incoming `*const c_char` to a slice, and writes the measured length
//! through the caller's `size_t *`. That division of labor is deliberate.
//! Everything in this module is pure byte inspection over a slice, with no
//! raw pointer, no allocation and no `unsafe`, which is what makes it
//! testable on its own.
//!
//! Those two modules, `src/parse/mod.rs` and `src/ffi.rs`, are also the only
//! in-crate consumers, and there is no feature setting under which either
//! stops calling this one. That is why this module carries no blanket
//! allowance for dead code, unlike `src/alloc.rs`, whose reachable surface
//! genuinely varies with the feature matrix: a dead-code warning pointing
//! here would mean the pipeline had come unwired, which is a finding to act
//! on rather than one to silence.
//!
//! # The rule, byte for byte
//!
//! Given the string and the `allowspace` flag, in the order the C performs
//! them:
//!
//! 1. Measure the string. `lib/urlapi.c` L225 uses `strlen`; this module
//!    uses the length of the slice it is handed.
//! 2. If that length is greater than `CURL_MAX_INPUT_LENGTH`, reject the
//!    input. L229-L230.
//! 3. Choose one threshold: `0x1f` when spaces are allowed, `0x20` when they
//!    are not. L232.
//! 4. Reject the input if any byte is less than or equal to that threshold,
//!    or is exactly `0x7f`. L233-L236. Every comparison is unsigned, because
//!    the C reads the string through the `const unsigned char *` cast made at
//!    L228.
//! 5. Otherwise report the length. L237-L238.
//!
//! Bytes with the high bit set are therefore accepted, and that is no
//! oversight in the original: `tests/libtest/lib1560.c` L668 parses
//! `https://\xff.127.0.0.1` successfully, so a scan that rejected `0x80`
//! through `0xff` would fail the parity diff and would also make every
//! internationalized domain name unparsable.
//!
//! # It is `CURLUE_MALFORMED_INPUT`, never `CURLUE_TOO_LARGE`
//!
//! Both rejections here return `CURLUE_MALFORMED_INPUT`, the length ceiling
//! included. That reads like the wrong code, and the crate really does
//! define `CURLUE_TOO_LARGE`, so the temptation to correct it is genuine.
//! `lib/urlapi.c` L230 is unambiguous. The other consumer of the same
//! constant is the one that fits the intuition: the ceiling `curl_url_set`
//! applies at `lib/urlapi.c` L1824 does yield `CURLUE_TOO_LARGE`, which is
//! the behavior the documentation of `CURL_MAX_INPUT_LENGTH` in
//! `src/abi.rs` describes. Two ceilings, two codes, one constant, and
//! transformation rule T6 governs: faithful over correct.
//!
//! # One threshold, not two predicates
//!
//! The flag selects a number and nothing else, exactly as at L232. Spaces
//! are allowed by moving the threshold down to `0x1f`, so `0x20` survives
//! for being strictly greater than it; spaces are rejected by leaving the
//! threshold at `0x20`, so `0x20` falls to the `<=`. Written instead as two
//! predicates behind an `if`, the same behavior would state the boundary
//! twice and could drift on one future edit. `0x7f` sits outside that
//! mechanism altogether, in a comparison of its own, which is why no value
//! of `allowspace` can ever admit it.
//!
//! # Two rejection sets, and why they must not be unified
//!
//! This crate contains a second, similar-looking control-byte test. They are
//! different predicates, run at different times on different data, and
//! folding them into one shared helper would be a silent behavior change:
//!
//! - Set A, owned by this module, from `lib/urlapi.c` L232-L234. Rejects a
//!   byte `<= 0x1f`, or `<= 0x20` when spaces are not allowed, plus `0x7f`.
//!   It inspects the raw input, before any decoding has happened.
//! - Set B, owned by `src/decode.rs`, from `lib/escape.c` L139. Rejects a
//!   byte `< 0x20` and nothing else. It inspects each byte after
//!   percent-decoding.
//!
//! Set B is strictly narrower. It admits `0x20` unconditionally and it
//! admits `0x7f`, so a `%7f` escape in a path decodes to a byte set B passes
//! and set A would have rejected -- and both outcomes are correct, because
//! set A never sees that byte: it inspected the three characters `%`, `7`
//! and `f` instead. `lib/escape.c` L97 documents set B as rejecting byte
//! codes lower than 32, and that is the whole of it.
//!
//! For the same reason `u8::is_ascii_control` is not used below. It covers
//! `0x00` through `0x1f` plus `0x7f`, which happens to equal set A when
//! spaces are allowed and to differ from it by exactly the space when they
//! are not. Naming the standard-library predicate would hide that the space
//! is the entire point of the flag.
//!
//! # What a byte slice means here
//!
//! The C takes a NUL-terminated string and measures it itself, so the range
//! it scans can never contain a NUL: `strlen` stopped at the first one. A
//! slice carries its own length and can contain one, and this module rejects
//! it, because `0x00` is less than or equal to either threshold. That is the
//! safe direction, and it is unreachable from `src/ffi.rs`, which hands over
//! the bytes up to the terminator and no further.
//!
//! # The length is load-bearing
//!
//! Every later stage of `parseurl` works from the length this stage reports
//! rather than measuring the string again, so an off-by-one here corrupts
//! the whole pipeline instead of one part of one URL. Returning it inside a
//! `Result` reproduces the C's own discipline of writing `*urllen` at L237
//! only, after both rejections have been passed.
//!
//! # Verification
//!
//! The tests at the end of this file are spot checks against the C
//! semantics, one per rule above plus a sweep of all 256 byte values.
//! Coverage through the exported C entry points lives in
//! `rust-urlapi/tests/`, and the authoritative oracle,
//! `tests/libtest/lib1560.c`, cannot be run against a single module at all:
//! end-to-end verification happens through
//! `rust-urlapi/scripts/run-parity.sh`.

use crate::abi::{CURLUcode, CURLUE_MALFORMED_INPUT, CURL_MAX_INPUT_LENGTH};

/// Rejects an input carrying a byte the URL API refuses to accept, and
/// measures it.
///
/// `Curl_junkscan` at `lib/urlapi.c` L223-L239. The module documentation
/// carries the full rule, the two rejection sets and the slice contract.
///
/// # Parameters
///
/// - `url`: the bytes of the input, up to but not including the terminating
///   NUL of the C caller's string. `src/ffi.rs` owns that conversion.
/// - `allowspace`: whether a space, `0x20`, is acceptable. `parseurl`
///   derives it from `CURLU_ALLOW_SPACE` at `lib/urlapi.c` L1124, and
///   `lib/doh.c` L1127 passes false.
///
/// # Returns
///
/// The length of the input in bytes, which is what the C writes through
/// `*urllen` at L237 and what every later parse stage uses in place of a
/// fresh measurement.
///
/// # Errors
///
/// `CURLUE_MALFORMED_INPUT`, the only code this function can produce, when
/// the input is longer than `CURL_MAX_INPUT_LENGTH` or contains a byte the
/// scan rejects. No length accompanies it, matching the C, which leaves the
/// caller's `*urllen` untouched on both failure paths.
pub(crate) fn junkscan(url: &[u8], allowspace: bool) -> Result<usize, CURLUcode> {
    // lib/urlapi.c L225 measures with strlen; a slice arrives measured.
    // L229-L230: the comparison is strictly greater than, so an input of
    // exactly CURL_MAX_INPUT_LENGTH bytes is accepted. Tested before the
    // scan, as in the C, so an oversized input is rejected without being
    // walked.
    let urllen = url.len();
    if urllen > CURL_MAX_INPUT_LENGTH {
        return Err(CURLUE_MALFORMED_INPUT);
    }

    // lib/urlapi.c L232. The flag chooses a number and the predicate below
    // is the same either way: 0x1f leaves the space just above the
    // threshold, 0x20 puts it just inside.
    let control: u8 = if allowspace { 0x1f } else { 0x20 };

    // lib/urlapi.c L233-L236. Unsigned throughout, which is what the
    // const unsigned char * cast at L228 buys the C and what u8 gives here
    // for free. An iterator rather than an index because the crate denies
    // direct indexing, and `any` short-circuits at exactly the byte where
    // the C loop returns. 0x7f is DEL, spelled 127 in the C; it is compared
    // on its own and so is junk whatever `allowspace` says.
    //
    // This line is rejection set A. Set B lives in `src/decode.rs` and is
    // narrower; the two must not be folded into one helper, for the reasons
    // in the module documentation above.
    if url.iter().any(|&byte| byte <= control || byte == 0x7f) {
        return Err(CURLUE_MALFORMED_INPUT);
    }

    // lib/urlapi.c L237-L238. The length becomes available to the caller
    // here and on no other path.
    Ok(urllen)
}

#[cfg(test)]
mod tests {
    // The two long inputs in `the_length_ceiling_is_inclusive` need the heap,
    // and they reach it through the `alloc` crate rather than through `std`
    // so that this module compiles the same way whichever the crate root
    // turns out to declare. Every other module in this crate imports from
    // `core` alone, and this keeps that property intact.
    extern crate alloc;

    use super::junkscan;
    use crate::abi::{CURLUcode, CURLUE_MALFORMED_INPUT, CURLUE_OK, CURL_MAX_INPUT_LENGTH};
    use alloc::vec;

    /// The verdict in the shape `src/ffi.rs` has to present to C: a result
    /// code always, and a length only when that code is `CURLUE_OK`.
    ///
    /// This mirrors the wrapper rather than replacing it. The point is to
    /// pin the half of the contract a `Result` expresses only implicitly,
    /// namely that nothing is written through `*urllen` on a failure path.
    fn c_verdict(url: &[u8], allowspace: bool) -> (CURLUcode, Option<usize>) {
        match junkscan(url, allowspace) {
            Ok(urllen) => (CURLUE_OK, Some(urllen)),
            Err(code) => (code, None),
        }
    }

    /// An empty string has no byte to reject, so the loop at
    /// `lib/urlapi.c` L233 never runs and L237 reports zero.
    #[test]
    fn empty_input_is_accepted_with_zero_length() {
        assert_eq!(junkscan(b"", false), Ok(0));
        assert_eq!(junkscan(b"", true), Ok(0));
    }

    /// The reported length is the byte count of the input, nine here, and
    /// the flag has no bearing on a string that contains no space.
    #[test]
    fn an_ordinary_url_reports_its_byte_length() {
        assert_eq!(junkscan(b"http://x/", false), Ok(9));
        assert_eq!(junkscan(b"http://x/", true), Ok(9));
    }

    /// `tests/libtest/lib1560.c` L671 asserts exactly this input with no
    /// flags and expects `CURLUE_MALFORMED_INPUT`. This stage is what
    /// produces it, and `CURLU_ALLOW_SPACE` is what turns it off.
    #[test]
    fn a_space_is_junk_unless_the_caller_allows_it() {
        let url = b"https://127.0. 1";
        assert_eq!(junkscan(url, false), Err(CURLUE_MALFORMED_INPUT));
        assert_eq!(junkscan(url, true), Ok(url.len()));
    }

    /// One of the five `CURLU_ALLOW_SPACE` successes in
    /// `tests/libtest/lib1560.c` L322-L340. The space is in the query here,
    /// but this stage does not know that: it sees one flat string, and the
    /// parts are not separated until later stages run.
    #[test]
    fn a_space_further_into_the_url_survives_when_allowed() {
        let url = b"https://user:password@example.net/get?this=and what";
        assert_eq!(junkscan(url, true), Ok(url.len()));
        assert_eq!(junkscan(url, false), Err(CURLUE_MALFORMED_INPUT));
    }

    /// `0x1f` is the byte immediately below the space, so lowering the
    /// threshold to admit the space does not reach it.
    #[test]
    fn byte_0x1f_is_junk_even_when_spaces_are_allowed() {
        let url = b"http://exam\x1fple.com/";
        assert_eq!(junkscan(url, true), Err(CURLUE_MALFORMED_INPUT));
        assert_eq!(junkscan(url, false), Err(CURLUE_MALFORMED_INPUT));
    }

    /// `0x7f` is tested separately from the threshold at `lib/urlapi.c`
    /// L234, so `allowspace` cannot reach it either.
    #[test]
    fn byte_0x7f_is_junk_under_either_flag() {
        let url = b"http://exam\x7fple.com/";
        assert_eq!(junkscan(url, false), Err(CURLUE_MALFORMED_INPUT));
        assert_eq!(junkscan(url, true), Err(CURLUE_MALFORMED_INPUT));
    }

    /// `0x21` is the first byte above the higher of the two thresholds, so
    /// it is accepted regardless of the flag. It is also a reminder that
    /// this stage judges bytes and not URL syntax.
    #[test]
    fn byte_0x21_is_accepted_under_either_flag() {
        let url = b"http://exam\x21ple.com/";
        assert_eq!(junkscan(url, false), Ok(url.len()));
        assert_eq!(junkscan(url, true), Ok(url.len()));
    }

    /// Every one of the 256 byte values, under both flags, against the
    /// accepted set stated positively.
    ///
    /// The expectation is deliberately not a second copy of the rejecting
    /// predicate: it is the complement, written as the ranges of bytes that
    /// survive, so reproducing a mistake would take making it twice in two
    /// different forms. It also pins the two boundaries most easily lost,
    /// that `0x80` through `0xff` are accepted and that `0x7f` is the only
    /// rejected byte above the space.
    #[test]
    fn every_byte_value_matches_the_c_predicate() {
        // Accepted unconditionally: the printable ASCII range above the
        // space, and every byte with the high bit set. The space itself is
        // conditional and is added below; 0x00 through 0x1f and 0x7f appear
        // in neither, so they are junk in both modes.
        //
        // 0x00 deserves a word. The C can never be handed a NUL inside the
        // range it scans, because its own strlen stopped at the first one, so
        // this row of the sweep has no C counterpart to diverge from. It
        // records the slice contract instead: a NUL reaching this function is
        // junk, which is the safe direction.
        const ACCEPTED: [(u8, u8); 2] = [(0x21, 0x7e), (0x80, 0xff)];

        for byte in 0..=u8::MAX {
            let input = [byte];
            for allowspace in [false, true] {
                let accepted = ACCEPTED
                    .iter()
                    .any(|&(low, high)| (low..=high).contains(&byte))
                    || (allowspace && byte == 0x20);
                let expected = if accepted {
                    Ok(1)
                } else {
                    Err(CURLUE_MALFORMED_INPUT)
                };

                assert_eq!(
                    junkscan(&input, allowspace),
                    expected,
                    "byte {byte:#04x} with allowspace {allowspace}"
                );
            }
        }
    }

    /// The ceiling is inclusive, because `lib/urlapi.c` L229 compares with a
    /// strict `>`. One byte more is rejected with
    /// `CURLUE_MALFORMED_INPUT`, not with `CURLUE_TOO_LARGE`, which is the
    /// trap the module documentation warns about.
    #[test]
    fn the_length_ceiling_is_inclusive() {
        let at_ceiling = vec![b'a'; CURL_MAX_INPUT_LENGTH];
        assert_eq!(junkscan(&at_ceiling, false), Ok(CURL_MAX_INPUT_LENGTH));
        assert_eq!(junkscan(&at_ceiling, true), Ok(CURL_MAX_INPUT_LENGTH));

        // saturating_add rather than a bare + because the crate denies
        // unchecked arithmetic, and the saturating form cannot wrap round to
        // a small length and quietly turn this into a passing case.
        let over_ceiling = vec![b'a'; CURL_MAX_INPUT_LENGTH.saturating_add(1)];
        assert_eq!(junkscan(&over_ceiling, false), Err(CURLUE_MALFORMED_INPUT));
        assert_eq!(junkscan(&over_ceiling, true), Err(CURLUE_MALFORMED_INPUT));
    }

    /// A length crosses into C on the success path only, which is what
    /// `lib/doh.c` L1127 relies on when it ignores its own out-parameter
    /// after a non-zero return.
    #[test]
    fn a_length_reaches_the_caller_only_on_success() {
        assert_eq!(c_verdict(b"http://x/", false), (CURLUE_OK, Some(9)));
        assert_eq!(
            c_verdict(b"http://x /", false),
            (CURLUE_MALFORMED_INPUT, None)
        );
        assert_eq!(c_verdict(b"http://x /", true), (CURLUE_OK, Some(10)));
    }
}
