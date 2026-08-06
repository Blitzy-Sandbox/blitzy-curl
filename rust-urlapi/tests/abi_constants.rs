// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Run-time verification of the numeric ABI surface of `curl_urlapi_rs`.
//!
//! This file is the run-time half of a deliberate double guarantee. The
//! compile-time half is the `_ABI_PARITY` block in `src/lib.rs`, which is in
//! force for every build of every feature configuration and every target; this
//! file re-checks the same 60 numbers under `cargo test`, where a regression
//! surfaces as a named failing test rather than only as a build error. Both
//! halves are required rather than one being a substitute for the other: the
//! plan asks for the values to be enforced twice (0.4.2.1) and names this file
//! as the run-time pass in acceptance criterion A3 (0.9.2).
//!
//! # `include/curl/urlapi.h` is the only authority
//!
//! Every number here was transcribed from `include/curl/urlapi.h` L34-L105 and
//! from nowhere else. The manual pages are specifically not a source, and the
//! counts are worth stating so that nobody has to re-derive them:
//! `docs/libcurl/curl_url_get.md` documents nine of the sixteen flags as
//! entries of its own, at L52, L57, L62, L67, L81, L91, L104, L118 and L130,
//! and `docs/libcurl/curl_url_set.md` documents nine at L167, L177, L182, L198,
//! L204, L220, L227, L234 and L245. An editor who "corrects" the flag family
//! below against either page alone would silently delete seven bits from the
//! check. More decisively still, neither page states a numeric value or a bit
//! position anywhere at all, so no reading of them could confirm one of these
//! numbers even for a flag they do name. The four supporting constants are not
//! in the public header, so each is cited to the C file that does define it.
//!
//! Nothing may be added either. This port introduces no new `CURLUcode` value,
//! no new `CURLUPart` value and no new `CURLU_*` flag, so a new name appearing
//! in `src/abi.rs` is a defect rather than something to extend this file with.
//!
//! # Why every expectation is a literal integer
//!
//! Parity here is positional. `CURLUE_OK` at L35 carries no explicit value,
//! L36-L66 carry the ordinal as a trailing comment for 1 through 31, and
//! `CURLUE_LAST` at L67 carries no comment at all, so the number 32 appears
//! nowhere in curl's C source: it exists only because 32 enumerators are
//! declared before it and C numbers enumerators sequentially from zero.
//! `CURLUPart` at L70-L82 states no ordinals whatsoever. Callers switch on
//! these numbers, so inserting, removing or reordering a single entry is an ABI
//! break that no compiler on either side of the boundary reports.
//!
//! Three consequences shape this file. Each expectation is a literal, never
//! derived from another constant, because `CURLUE_BAD_PARTPOINTER + 1` would
//! follow a wrong `CURLUE_BAD_PARTPOINTER` and pass. The expectations are not a
//! Rust `enum` and not an array indexed by ordinal, for the same reason. And
//! the sentinel `CURLUE_LAST` is checked like every other value, because a
//! shift in it is precisely the signal that a code was inserted.
//!
//! The spellings are chosen to be independent of the ones already in the crate.
//! `src/lib.rs` writes the flags as the header's `1 << n` shifts and the unit
//! tests at the end of `src/abi.rs` cross-check them as hexadecimal masks in an
//! array; this file asserts each flag twice more, once as the shift and once as
//! a plain decimal, and asserts the two enumerations one named constant at a
//! time rather than array against array. A transcription slip therefore has to
//! be made in several different shapes before it can survive, which is the only
//! defence against a mistake that is consistent between the definition and its
//! check.
//!
//! # Structural checks
//!
//! Per-constant equality catches a typo in one value. It cannot catch an entry
//! deleted along with its own assertion, an entry inserted, or a whole block
//! shifted by one: every individual line would still agree. The three
//! structural tests here close that gap, each with its own failure signature --
//! the result codes and the part identifiers are pairwise distinct and fill
//! their ranges exactly, with the documented maximum at the top, and the
//! sixteen flags are single-bit, mutually disjoint and cover the low sixteen
//! bits and nothing above them.
//!
//! # Posture
//!
//! There is no `unsafe` here. This file reads constants and calls no
//! `extern "C"` function, which makes it the one file under
//! `rust-urlapi/tests/` that needs none. There is no `#[cfg(feature = ...)]`
//! either: nothing in `src/abi.rs` is feature-gated, because an ABI does not
//! vary with the features a particular build selects, so `cargo test` and
//! `cargo test --no-default-features --features idn-libidn2` are required to
//! give identical results. Anything that made them differ would be a reference
//! to a gated item and should be removed rather than wrapped in a `cfg`.
//!
//! The crate is named once, `use curl_urlapi_rs::abi;`, and every reference is
//! qualified from there. Named imports rather than a glob are the crate-wide
//! rule (0.4.3), and at sixty constants a glob would also stop a reader seeing
//! which module each name belongs to. Reaching `abi` at all is possible because
//! `src/lib.rs` declares it `pub mod abi;` -- an integration test links the
//! crate as an external crate and can name only its public items -- and because
//! `Cargo.toml` lists the `rlib` crate type beside `staticlib` and `cdylib`.
//! Neither of those two facts is incidental; removing either breaks this file.
//!
//! An assertion here may never be weakened to make something pass. These tests
//! supplement the authoritative oracles, `tests/libtest/lib1560.c` executed
//! unmodified through `rust-urlapi/harness/` and the byte-for-byte demo diff
//! against the reference link; they do not replace them. A value that does not
//! match the header means the port is wrong, so the fix belongs in
//! `src/abi.rs`.

use curl_urlapi_rs::abi;

// ---------------------------------------------------------------------------
// CURLUcode -- the 33 result codes, include/curl/urlapi.h:L34-L68
// ---------------------------------------------------------------------------

/// Every `CURLUcode` value against the ordinal the header gives it.
///
/// The header's own trailing comments cover 1 through 31, so those are a direct
/// transcription. The two that carry no comment are the two worth re-deriving
/// by hand: `CURLUE_OK` is 0 because it is declared first at L35, and
/// `CURLUE_LAST` is 32 because 32 enumerators precede it at L67.
#[test]
fn error_codes_match_the_header() {
    assert_eq!(abi::CURLUE_OK, 0);
    assert_eq!(abi::CURLUE_BAD_HANDLE, 1);
    assert_eq!(abi::CURLUE_BAD_PARTPOINTER, 2);
    assert_eq!(abi::CURLUE_MALFORMED_INPUT, 3);
    assert_eq!(abi::CURLUE_BAD_PORT_NUMBER, 4);
    assert_eq!(abi::CURLUE_UNSUPPORTED_SCHEME, 5);
    assert_eq!(abi::CURLUE_URLDECODE, 6);
    assert_eq!(abi::CURLUE_OUT_OF_MEMORY, 7);
    assert_eq!(abi::CURLUE_USER_NOT_ALLOWED, 8);
    assert_eq!(abi::CURLUE_UNKNOWN_PART, 9);
    assert_eq!(abi::CURLUE_NO_SCHEME, 10);
    assert_eq!(abi::CURLUE_NO_USER, 11);
    assert_eq!(abi::CURLUE_NO_PASSWORD, 12);
    assert_eq!(abi::CURLUE_NO_OPTIONS, 13);
    assert_eq!(abi::CURLUE_NO_HOST, 14);
    assert_eq!(abi::CURLUE_NO_PORT, 15);
    assert_eq!(abi::CURLUE_NO_QUERY, 16);
    assert_eq!(abi::CURLUE_NO_FRAGMENT, 17);
    assert_eq!(abi::CURLUE_NO_ZONEID, 18);
    assert_eq!(abi::CURLUE_BAD_FILE_URL, 19);
    assert_eq!(abi::CURLUE_BAD_FRAGMENT, 20);
    assert_eq!(abi::CURLUE_BAD_HOSTNAME, 21);
    assert_eq!(abi::CURLUE_BAD_IPV6, 22);
    assert_eq!(abi::CURLUE_BAD_LOGIN, 23);
    assert_eq!(abi::CURLUE_BAD_PASSWORD, 24);
    assert_eq!(abi::CURLUE_BAD_PATH, 25);
    assert_eq!(abi::CURLUE_BAD_QUERY, 26);
    assert_eq!(abi::CURLUE_BAD_SCHEME, 27);
    assert_eq!(abi::CURLUE_BAD_SLASHES, 28);
    assert_eq!(abi::CURLUE_BAD_USER, 29);
    assert_eq!(abi::CURLUE_LACKS_IDN, 30);
    assert_eq!(abi::CURLUE_TOO_LARGE, 31);
    assert_eq!(abi::CURLUE_LAST, 32);
}

// ---------------------------------------------------------------------------
// CURLUPart -- the 11 part identifiers, include/curl/urlapi.h:L70-L82
// ---------------------------------------------------------------------------

/// Every `CURLUPart` value against its position in the header.
///
/// The header gives no ordinals at all here, so all eleven of these numbers
/// come from declaration order alone. `CURLUPART_ZONEID` at L81 is the newest
/// entry -- its comment records that it arrived in 7.65.0 -- which is why it is
/// last and therefore 10.
#[test]
fn part_identifiers_match_the_header() {
    assert_eq!(abi::CURLUPART_URL, 0);
    assert_eq!(abi::CURLUPART_SCHEME, 1);
    assert_eq!(abi::CURLUPART_USER, 2);
    assert_eq!(abi::CURLUPART_PASSWORD, 3);
    assert_eq!(abi::CURLUPART_OPTIONS, 4);
    assert_eq!(abi::CURLUPART_HOST, 5);
    assert_eq!(abi::CURLUPART_PORT, 6);
    assert_eq!(abi::CURLUPART_PATH, 7);
    assert_eq!(abi::CURLUPART_QUERY, 8);
    assert_eq!(abi::CURLUPART_FRAGMENT, 9);
    assert_eq!(abi::CURLUPART_ZONEID, 10);
}

// ---------------------------------------------------------------------------
// CURLU_* -- the 16 behaviour flags, include/curl/urlapi.h:L84-L105
//
// The flag family is asserted twice, in the two spellings below. The header
// writes each flag as `(1 << n)`, and the first test repeats exactly that so a
// reader can check the bit position against the source without arithmetic. The
// second resolves the same sixteen values to plain decimals, which is what a
// caller combining flags actually sends across the boundary, so that a slip in
// one spelling cannot hide behind the other.
//
// Sixteen is the whole set. The manual pages list nine each; the header is
// authoritative and this is what it defines.
// ---------------------------------------------------------------------------

/// Every `CURLU_*` flag against the shift the header uses to define it.
#[test]
fn flag_bits_match_the_header_shifts() {
    assert_eq!(abi::CURLU_DEFAULT_PORT, 1 << 0);
    assert_eq!(abi::CURLU_NO_DEFAULT_PORT, 1 << 1);
    assert_eq!(abi::CURLU_DEFAULT_SCHEME, 1 << 2);
    assert_eq!(abi::CURLU_NON_SUPPORT_SCHEME, 1 << 3);
    assert_eq!(abi::CURLU_PATH_AS_IS, 1 << 4);
    assert_eq!(abi::CURLU_DISALLOW_USER, 1 << 5);
    assert_eq!(abi::CURLU_URLDECODE, 1 << 6);
    assert_eq!(abi::CURLU_URLENCODE, 1 << 7);
    assert_eq!(abi::CURLU_APPENDQUERY, 1 << 8);
    assert_eq!(abi::CURLU_GUESS_SCHEME, 1 << 9);
    assert_eq!(abi::CURLU_NO_AUTHORITY, 1 << 10);
    assert_eq!(abi::CURLU_ALLOW_SPACE, 1 << 11);
    assert_eq!(abi::CURLU_PUNYCODE, 1 << 12);
    assert_eq!(abi::CURLU_PUNY2IDN, 1 << 13);
    assert_eq!(abi::CURLU_GET_EMPTY, 1 << 14);
    assert_eq!(abi::CURLU_NO_GUESS_SCHEME, 1 << 15);
}

/// The same sixteen flags as the decimal values a caller passes.
#[test]
fn flag_bits_match_their_decimal_values() {
    assert_eq!(abi::CURLU_DEFAULT_PORT, 1);
    assert_eq!(abi::CURLU_NO_DEFAULT_PORT, 2);
    assert_eq!(abi::CURLU_DEFAULT_SCHEME, 4);
    assert_eq!(abi::CURLU_NON_SUPPORT_SCHEME, 8);
    assert_eq!(abi::CURLU_PATH_AS_IS, 16);
    assert_eq!(abi::CURLU_DISALLOW_USER, 32);
    assert_eq!(abi::CURLU_URLDECODE, 64);
    assert_eq!(abi::CURLU_URLENCODE, 128);
    assert_eq!(abi::CURLU_APPENDQUERY, 256);
    assert_eq!(abi::CURLU_GUESS_SCHEME, 512);
    assert_eq!(abi::CURLU_NO_AUTHORITY, 1024);
    assert_eq!(abi::CURLU_ALLOW_SPACE, 2048);
    assert_eq!(abi::CURLU_PUNYCODE, 4096);
    assert_eq!(abi::CURLU_PUNY2IDN, 8192);
    assert_eq!(abi::CURLU_GET_EMPTY, 16384);
    assert_eq!(abi::CURLU_NO_GUESS_SCHEME, 32768);
}

// ---------------------------------------------------------------------------
// Structural properties
//
// The three tests below list the constants in header declaration order and then
// make claims about the set as a whole. Each list's length is written into its
// type, so an entry added to or removed from `src/abi.rs` and mirrored here
// fails to compile rather than quietly shrinking the check. The arrays hold the
// named constants only; every expected number stays a literal in the tests
// above, so nothing here can paper over a wrong value.
// ---------------------------------------------------------------------------

/// The result codes are 33 distinct values filling 0 to 32 with no gap.
///
/// This is the test that catches what per-constant equality cannot: a code
/// inserted or deleted along with its own assertion, or a block shifted by one.
/// Contiguity is what makes the ordinals positions in the first place -- C
/// numbers enumerators sequentially from zero only while nothing assigns an
/// explicit value, and `include/curl/urlapi.h` L34-L68 assigns none -- and
/// `CURLUE_LAST` sits at the top by construction, one past the last real code.
#[test]
fn error_codes_are_pairwise_distinct_and_fill_zero_to_thirty_two() {
    const CODES: [abi::CURLUcode; 33] = [
        abi::CURLUE_OK,
        abi::CURLUE_BAD_HANDLE,
        abi::CURLUE_BAD_PARTPOINTER,
        abi::CURLUE_MALFORMED_INPUT,
        abi::CURLUE_BAD_PORT_NUMBER,
        abi::CURLUE_UNSUPPORTED_SCHEME,
        abi::CURLUE_URLDECODE,
        abi::CURLUE_OUT_OF_MEMORY,
        abi::CURLUE_USER_NOT_ALLOWED,
        abi::CURLUE_UNKNOWN_PART,
        abi::CURLUE_NO_SCHEME,
        abi::CURLUE_NO_USER,
        abi::CURLUE_NO_PASSWORD,
        abi::CURLUE_NO_OPTIONS,
        abi::CURLUE_NO_HOST,
        abi::CURLUE_NO_PORT,
        abi::CURLUE_NO_QUERY,
        abi::CURLUE_NO_FRAGMENT,
        abi::CURLUE_NO_ZONEID,
        abi::CURLUE_BAD_FILE_URL,
        abi::CURLUE_BAD_FRAGMENT,
        abi::CURLUE_BAD_HOSTNAME,
        abi::CURLUE_BAD_IPV6,
        abi::CURLUE_BAD_LOGIN,
        abi::CURLUE_BAD_PASSWORD,
        abi::CURLUE_BAD_PATH,
        abi::CURLUE_BAD_QUERY,
        abi::CURLUE_BAD_SCHEME,
        abi::CURLUE_BAD_SLASHES,
        abi::CURLUE_BAD_USER,
        abi::CURLUE_LACKS_IDN,
        abi::CURLUE_TOO_LARGE,
        abi::CURLUE_LAST,
    ];

    // Pairwise rather than by counting distinct values, so a failure names the
    // colliding pair instead of only reporting that the count is wrong.
    for (position, left) in CODES.iter().enumerate() {
        for right in CODES.iter().skip(position + 1) {
            assert_ne!(
                left, right,
                "two CURLUcode constants share the value {left}"
            );
        }
    }

    // Sorting first means this passes only if the values are exactly 0 through
    // 32, whatever order they were listed in; combined with the length pinned
    // above, no value can be missing, repeated or out of range.
    let mut ordered = CODES;
    ordered.sort_unstable();
    assert!(
        ordered.iter().copied().eq(0..=32),
        "the CURLUcode set is not exactly 0 through 32: {ordered:?}"
    );

    assert_eq!(
        CODES.iter().copied().max(),
        Some(abi::CURLUE_LAST),
        "CURLUE_LAST must be the largest CURLUcode value"
    );
}

/// The part identifiers are 11 distinct values filling 0 to 10 with no gap.
///
/// Same shape as the result codes, and the same reasoning: `CURLUPart` at
/// `include/curl/urlapi.h` L70-L82 assigns no explicit value to any enumerator,
/// so the run has to be contiguous from zero, and `CURLUPART_ZONEID` is the
/// maximum because it is declared last.
#[test]
fn part_identifiers_are_pairwise_distinct_and_fill_zero_to_ten() {
    const PARTS: [abi::CURLUPart; 11] = [
        abi::CURLUPART_URL,
        abi::CURLUPART_SCHEME,
        abi::CURLUPART_USER,
        abi::CURLUPART_PASSWORD,
        abi::CURLUPART_OPTIONS,
        abi::CURLUPART_HOST,
        abi::CURLUPART_PORT,
        abi::CURLUPART_PATH,
        abi::CURLUPART_QUERY,
        abi::CURLUPART_FRAGMENT,
        abi::CURLUPART_ZONEID,
    ];

    for (position, left) in PARTS.iter().enumerate() {
        for right in PARTS.iter().skip(position + 1) {
            assert_ne!(
                left, right,
                "two CURLUPart constants share the value {left}"
            );
        }
    }

    let mut ordered = PARTS;
    ordered.sort_unstable();
    assert!(
        ordered.iter().copied().eq(0..=10),
        "the CURLUPart set is not exactly 0 through 10: {ordered:?}"
    );

    assert_eq!(
        PARTS.iter().copied().max(),
        Some(abi::CURLUPART_ZONEID),
        "CURLUPART_ZONEID must be the largest CURLUPart value"
    );
}

/// The flags are 16 single-bit, mutually disjoint values covering bits 0 to 15.
///
/// Callers combine these with bitwise or, which only works while no two of them
/// claim the same bit and no flag claims more than one. The union check is the
/// cheapest guard of the three: a duplicated bit leaves a hole and a block
/// shifted by one unions to 0x0001fffe, so either way the total stops being
/// exactly the low sixteen bits.
#[test]
fn flag_bits_are_single_bit_pairwise_disjoint_and_cover_the_low_sixteen() {
    // The flags are declared `c_uint` in `src/abi.rs` because that is how they
    // travel: `curl_url_get` at `include/curl/urlapi.h` L133-L134 and
    // `curl_url_set` at L141-L142 both take them as `unsigned int flags`.
    const FLAGS: [::core::ffi::c_uint; 16] = [
        abi::CURLU_DEFAULT_PORT,
        abi::CURLU_NO_DEFAULT_PORT,
        abi::CURLU_DEFAULT_SCHEME,
        abi::CURLU_NON_SUPPORT_SCHEME,
        abi::CURLU_PATH_AS_IS,
        abi::CURLU_DISALLOW_USER,
        abi::CURLU_URLDECODE,
        abi::CURLU_URLENCODE,
        abi::CURLU_APPENDQUERY,
        abi::CURLU_GUESS_SCHEME,
        abi::CURLU_NO_AUTHORITY,
        abi::CURLU_ALLOW_SPACE,
        abi::CURLU_PUNYCODE,
        abi::CURLU_PUNY2IDN,
        abi::CURLU_GET_EMPTY,
        abi::CURLU_NO_GUESS_SCHEME,
    ];

    for flag in FLAGS {
        assert_eq!(
            flag.count_ones(),
            1,
            "flag {flag:#06x} does not have exactly one bit set"
        );
    }

    for (position, left) in FLAGS.iter().enumerate() {
        for right in FLAGS.iter().skip(position + 1) {
            assert_eq!(
                left & right,
                0,
                "flags {left:#06x} and {right:#06x} share a bit"
            );
        }
    }

    let covered = FLAGS.iter().copied().fold(0, |union, flag| union | flag);
    assert_eq!(
        covered, 0x0000_ffff,
        "the sixteen flags must cover bits 0 to 15 and nothing above them"
    );
}

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// Both aliases carry the whole asserted range, and carry it signed.
///
/// `src/abi.rs` declares `CURLUcode` and `CURLUPart` as `c_int` rather than as
/// an unsigned type, and that is not cosmetic. A C enumeration whose
/// enumerators all fit in `int` has `int` as its compatible type, and `int` is
/// what a C caller compiled against `include/curl/urlapi.h` passes to
/// `curl_url_get` and `curl_url_set` and receives back from them. The typed
/// bindings below are the plain statement that the constants really are of the
/// alias type; the widening round-trip is the statement that no value is lost
/// on the way through, which is the property a narrower or unsigned alias would
/// break.
#[test]
fn the_type_aliases_carry_the_full_asserted_range() {
    let last: abi::CURLUcode = abi::CURLUE_LAST;
    let zoneid: abi::CURLUPart = abi::CURLUPART_ZONEID;
    assert_eq!(last, 32);
    assert_eq!(zoneid, 10);

    // Out to the widest signed integer and back again. The two extremes of the
    // asserted range are enough: 0 is the bottom of both enumerations and these
    // are their tops, so anything between them is covered by the contiguity
    // tests above.
    assert_eq!(i64::from(last), 32);
    assert_eq!(i64::from(zoneid), 10);
    assert_eq!(abi::CURLUcode::try_from(i64::from(last)), Ok(last));
    assert_eq!(abi::CURLUPart::try_from(i64::from(zoneid)), Ok(zoneid));

    // Signedness, asserted through the alias so that swapping it for an
    // unsigned type fails here rather than at some call site months later.
    assert_eq!(
        abi::CURLUcode::MIN.signum(),
        -1,
        "CURLUcode must stay signed"
    );
    assert_eq!(
        abi::CURLUPart::MIN.signum(),
        -1,
        "CURLUPart must stay signed"
    );

    // Both mirror the same C type, so they must remain the same width as each
    // other whatever platform decides what that width is.
    assert_eq!(
        ::core::mem::size_of::<abi::CURLUcode>(),
        ::core::mem::size_of::<abi::CURLUPart>(),
        "both aliases mirror C's int and must stay the same width"
    );
}

// ---------------------------------------------------------------------------
// Supporting constants
//
// None of these four is in include/curl/urlapi.h, so each is cited to the C
// file that defines it rather than to the header. They are object-like macros
// in the C, which is why they carry no ordinal and no bit position to check
// positionally: here the value itself is the whole claim.
// ---------------------------------------------------------------------------

/// The four supporting constants, each against its own C source.
#[test]
fn supporting_constants_match_their_c_sources() {
    // lib/urlapi.c:L55, a ceiling on the accepted input rather than a
    // measurement of the scheme table. Its comment at L54 gives the reason: the
    // scheme is not URL encoded and the longest schemes libcurl supports are
    // well inside this bound.
    assert_eq!(abi::MAX_SCHEME_LEN, 40);

    // lib/urlapi.c:L84, the scheme substituted when CURLU_DEFAULT_SCHEME is set
    // and the input carried none. Lower case, five bytes, and no terminator:
    // this is the canonical `&str` spelling.
    assert_eq!(abi::DEFAULT_SCHEME, "https");
    assert_eq!(abi::DEFAULT_SCHEME.len(), 5);
    assert_eq!(abi::DEFAULT_SCHEME.as_bytes(), b"https");

    // lib/urldata.h:L131. The comment at L129-L130 states the purpose: a
    // maximum input length is a precaution against abuse and makes junk input
    // easier to detect. Exceeding it yields CURLUE_TOO_LARGE.
    assert_eq!(abi::CURL_MAX_INPUT_LENGTH, 8_000_000);

    // lib/urldata.h:L545, the only PROTOPT_* bit this module reads. Bit 10 is
    // correct and is not an off-by-one: L544 records bit 9 as retired, so the
    // sequence of defined bits has a hole just below this one. Asserted as the
    // shift the C uses and as the decimal it resolves to.
    assert_eq!(abi::PROTOPT_URLOPTIONS, 1 << 10);
    assert_eq!(abi::PROTOPT_URLOPTIONS, 1024);
}

/// `DEFAULT_SCHEME_CSTR` is `DEFAULT_SCHEME` plus one NUL byte and nothing
/// else.
///
/// `src/abi.rs` keeps a NUL-terminated companion spelling for the one context
/// that genuinely needs a C string: `lib/urlapi.c` L1456 assigns
/// `DEFAULT_SCHEME` to the variable L1460 hands to `Curl_get_scheme`, whose
/// parameter is `const char *` (`lib/url.h` L76), and in the drop-in
/// configuration that lookup really is the C function. It is a second spelling
/// of one value rather than a fifth supporting constant, so the invariant tying
/// it to the canonical form matters more than its bytes do -- checking both is
/// what stops the two drifting apart. It is a byte string rather than a `CStr`
/// because the crate's declared minimum is Rust 1.75 and C string literals
/// arrived in 1.77.
#[test]
fn the_terminated_default_scheme_tracks_the_canonical_one() {
    assert_eq!(abi::DEFAULT_SCHEME_CSTR, b"https\0");
    assert_eq!(
        abi::DEFAULT_SCHEME_CSTR.len(),
        abi::DEFAULT_SCHEME.len() + 1
    );
    assert_eq!(
        abi::DEFAULT_SCHEME_CSTR.strip_suffix(b"\0"),
        Some(abi::DEFAULT_SCHEME.as_bytes()),
        "DEFAULT_SCHEME_CSTR must be DEFAULT_SCHEME plus exactly one NUL byte"
    );
}
