// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The error translation layer: every numeric conversion in one file.
//!
//! `lib/urlapi.c` converts between numeric domains in three shapes, in three
//! different places, and none of them is where a reader would look for it.
//! This module gathers all three, so that a reviewer auditing ABI parity
//! reads one file and one file only:
//!
//! - `cc2cu`, the compact macro at `lib/urlapi.c:L120-L122`, folds a
//!   `CURLcode` returned by the dynamic buffer helpers into a `CURLUcode`.
//!   Ported as [`cc2cu`].
//! - the identical conversion written twice, inside `host_decode` at
//!   `lib/urlapi.c:L1338-L1344` and inside `host_encode` at L1349-L1355,
//!   folds a `CURLcode` returned by the IDN helpers. Ported as [`idn2cu`],
//!   gathered here rather than duplicated at its two call sites.
//! - `curl_url_strerror`, `lib/strerror.c:L420-L531`, turns a `CURLUcode`
//!   into a human readable string. Ported as [`strerror_bytes`] with the two
//!   views [`strerror_cstr`] and [`strerror`], and the alternative arm as
//!   [`strerror_nonverbose_bytes`] with its own two views.
//!
//! Gathering them carries an obligation with it: no other module of this
//! crate may reproduce any of these mappings at a call site. A second copy
//! of the fold, or of one message string, defeats the only property this
//! module exists to provide.
//!
//! # The switch order is not the enum order
//!
//! The verbose arm of `curl_url_strerror` is a `switch` whose cases run in
//! the enumeration's declaration order as far as `CURLUE_NO_ZONEID` at
//! `lib/strerror.c:L478`, and then stop doing so. The remaining thirteen
//! cases are written in this order:
//!
//! `CURLUE_BAD_LOGIN` 23, `CURLUE_BAD_IPV6` 22, `CURLUE_BAD_HOSTNAME` 21,
//! `CURLUE_BAD_FILE_URL` 19, `CURLUE_BAD_SLASHES` 28, `CURLUE_BAD_SCHEME`
//! 27, `CURLUE_BAD_PATH` 25, `CURLUE_BAD_FRAGMENT` 20, `CURLUE_BAD_QUERY`
//! 26, `CURLUE_BAD_PASSWORD` 24, `CURLUE_BAD_USER` 29, `CURLUE_LACKS_IDN`
//! 30, `CURLUE_TOO_LARGE` 31.
//!
//! In C this costs nothing, because a `switch` selects by label rather than
//! by position. A port that transcribes the strings into an array and then
//! indexes it by the code silently maps eleven of them to the wrong string,
//! and eleven wrong error messages is exactly the kind of defect that
//! survives a test suite which only checks return codes. The mapping below
//! is therefore an explicit `match` keyed on the code, with every arm
//! carrying the ordinal and the `lib/strerror.c` line it came from, written
//! in the C file's own order so that the two can be read side by side.
//!
//! # The strings are quoted, not written
//!
//! Every message is copied byte for byte from `lib/strerror.c`, including
//! the subject-verb disagreement in the message for `CURLUE_USER_NOT_ALLOWED`
//! at L449. Faithful beats correct for observable output as much as for
//! behaviour: the demo program's standard output is compared byte for byte
//! against the same program linked against the C implementation, so a
//! grammatical improvement here is a parity failure. Nothing in this file
//! may be paraphrased.
//!
//! # Nothing here allocates
//!
//! This module is the one documented exception to the crate's rule that
//! every buffer crossing into C originates in `src/alloc.rs`. The reason is
//! the contract: `include/curl/urlapi.h:L144-L149` declares
//! `curl_url_strerror` as returning `const char *`, and
//! `docs/libcurl/curl_url_strerror.md:L54-L56` documents the return value as
//! a pointer to a null-terminated string with no obligation on the caller at
//! all. Callers do not free it, and `tests/libtest/lib1560.c` and the demo
//! both rely on that. In C the strings are literals in the object file's
//! read-only data; here they are `'static` byte literals, which is the same
//! thing. Handing back allocated memory would leak on every call.
//!
//! That is also why the literals are `&'static [u8]` ending in an explicit
//! NUL rather than `CStr` constants: the crate targets Rust 1.75 per
//! `rust-urlapi/Cargo.toml`, and C string literals, `c"No error"`, arrived
//! in 1.77. `src/abi.rs` resolves the same problem the same way for
//! `DEFAULT_SCHEME_CSTR`.
//!
//! # Which arm is exported, and why that is a feature and not a `#cfg`
//!
//! `lib/strerror.c` compiles one of two bodies. Under `CURLVERBOSE` at L422
//! it is the 33 message switch; otherwise, at L525-L530, it answers with
//! `"No error"` or `"Error"` and nothing else. Both are ported, as separate
//! functions rather than as one function behind a switch, for a specific
//! reason: `rust-urlapi/Cargo.toml` fixes the feature set, and a seventh
//! feature for verbosity may not be invented. `src/ffi.rs` therefore selects
//! [`strerror`], the verbose form, because that is what an ordinary libcurl
//! build produces and what the parity oracles compare against. The
//! non-verbose form exists so that the `#else` branch is ported rather than
//! dropped; it is `pub(crate)`, so only this crate reaches it.
//!
//! The `strerror` feature is a different question again. It governs whether
//! `src/ffi.rs` *exports* the symbol, because `curl_url_strerror` is not
//! implemented in `lib/urlapi.c` at all: it lives in `lib/strerror.c:L420`,
//! which is out of scope and unmodifiable, so exporting it from the Rust
//! archive in the drop-in configuration would define a symbol that
//! `strerror.c.o` already defines and the link would fail. The table itself
//! stays unconditional here; see the comment on the module's `dead_code`
//! allowance below.
//!
//! # No `unsafe`, no panic, no dependency
//!
//! This module contains no `unsafe`. The crate confines every `unsafe` block
//! to `src/ffi.rs`, and every other module carries `#![forbid(unsafe_code)]`,
//! so the boundary is a compiler guarantee rather than a convention;
//! `docs/MEMORY-OWNERSHIP.md` holds the inventory.
//! Nothing below can panic: there is no indexing, no arithmetic, no
//! `unwrap` and no `expect`, and the one fallible call, the `CStr`
//! validation in [`as_cstr`], handles its error arm by returning the empty C
//! string. The module needs neither `libc` nor `src/alloc.rs`, and depends
//! on `src/abi.rs` alone.

// The plan puts every `unsafe` block in `src/ffi.rs` (0.3.3) and the
// technical specification forbids `unsafe` outside FFI code (1.3.2.1).
// `forbid` rather than `deny` because an inner `allow` here would be a
// design change and should have to be argued for, not slipped in. This
// module needs nothing from C, so the attribute costs it nothing and turns
// the crate's single-unsafe-island property into a compiler guarantee
// instead of a convention.
#![forbid(unsafe_code)]

use core::ffi::{c_char, c_int, CStr};

use crate::abi::{
    CURLUcode, CURLUE_BAD_FILE_URL, CURLUE_BAD_FRAGMENT, CURLUE_BAD_HANDLE, CURLUE_BAD_HOSTNAME,
    CURLUE_BAD_IPV6, CURLUE_BAD_LOGIN, CURLUE_BAD_PARTPOINTER, CURLUE_BAD_PASSWORD,
    CURLUE_BAD_PATH, CURLUE_BAD_PORT_NUMBER, CURLUE_BAD_QUERY, CURLUE_BAD_SCHEME,
    CURLUE_BAD_SLASHES, CURLUE_BAD_USER, CURLUE_LACKS_IDN, CURLUE_LAST, CURLUE_MALFORMED_INPUT,
    CURLUE_NO_FRAGMENT, CURLUE_NO_HOST, CURLUE_NO_OPTIONS, CURLUE_NO_PASSWORD, CURLUE_NO_PORT,
    CURLUE_NO_QUERY, CURLUE_NO_SCHEME, CURLUE_NO_USER, CURLUE_NO_ZONEID, CURLUE_OK,
    CURLUE_OUT_OF_MEMORY, CURLUE_TOO_LARGE, CURLUE_UNKNOWN_PART, CURLUE_UNSUPPORTED_SCHEME,
    CURLUE_URLDECODE, CURLUE_USER_NOT_ALLOWED,
};

/// The part of libcurl's `CURLcode` domain that this crate produces.
///
/// `lib/urlapi.c` never returns a `CURLcode`. It receives them, from helpers
/// that live in other translation units, and folds them into `CURLUcode`
/// before returning. This type stands for those received values, and it
/// carries exactly the five the port can produce, each with the ordinal
/// `include/curl/curl.h` gives it:
///
/// - `CURLE_OK` 0, L519.
/// - `CURLE_URL_MALFORMAT` 3, L522. Produced by percent decoding when it
///   rejects a byte, `lib/escape.c:L142`, and by three IDN paths,
///   `lib/idn.c:L267`, L288 and L318.
/// - `CURLE_NOT_BUILT_IN` 4, L523. Produced by exactly one path, a libidn2
///   too old to be used, `lib/idn.c:L271`.
/// - `CURLE_OUT_OF_MEMORY` 27, L554. Produced by a failed reallocation in
///   the dynamic buffer, `lib/curlx/dynbuf.c:L108`, and by a failed
///   duplication of libidn2's own buffer, `lib/idn.c:L313`.
/// - `CURLE_TOO_LARGE` 100, L645. Produced by a dynamic buffer asked to
///   exceed its ceiling, `lib/curlx/dynbuf.c:L84`.
///
/// # Why this one is an enumeration when `src/abi.rs` has none
///
/// `src/abi.rs` writes every value out as an explicit integer constant
/// precisely because a Rust `enum`'s discriminants are implicit and a later
/// reordering would change the numbers without a compiler error. That
/// argument applies to values that cross the C boundary, and none of these
/// do: no exported function takes or returns a `CURLcode`, and this type is
/// `pub(crate)`. An enumeration is therefore the better choice here, because
/// it makes the domain closed and the folds below exhaustive by
/// construction. The discriminants are pinned to the C ordinals anyway, with
/// `repr(i32)`, so that [`CURLcode::as_raw`] can report the value C would
/// have used and so that the numbers are visible to an auditor.
///
/// The variant names keep the C spelling for the same reason the constants
/// in `src/abi.rs` do: every one of them can be grepped for in the C sources
/// this module was ported from. The naming allowance below is the entire cost
/// of that, and it is narrowed to this item.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub(crate) enum CURLcode {
    /// `CURLE_OK`, `include/curl/curl.h:L519`. No error.
    CURLE_OK = 0,
    /// `CURLE_URL_MALFORMAT`, `include/curl/curl.h:L522`.
    CURLE_URL_MALFORMAT = 3,
    /// `CURLE_NOT_BUILT_IN`, `include/curl/curl.h:L523`.
    // Constructed only by the libidn2 version guard at `lib/idn.c` L271, so
    // the no-IDN and `idn-pure` configurations never build one. Retained
    // unconditionally, and not gated per backend, because `idn2cu` folds it in
    // every configuration and the tests below pin these five discriminants
    // against `include/curl/curl.h` whichever backend is selected.
    #[allow(dead_code)]
    CURLE_NOT_BUILT_IN = 4,
    /// `CURLE_OUT_OF_MEMORY`, `include/curl/curl.h:L554`.
    CURLE_OUT_OF_MEMORY = 27,
    /// `CURLE_TOO_LARGE`, `include/curl/curl.h:L645`.
    CURLE_TOO_LARGE = 100,
}

impl CURLcode {
    /// Whether this is the success value.
    ///
    /// The C idiom is `if(!result)`, as at `lib/idn.c:L307`, which reads as
    /// truth testing an integer. This is the same test spelled so that it
    /// cannot be confused with a boolean field.
    #[must_use]
    pub(crate) const fn is_ok(self) -> bool {
        matches!(self, Self::CURLE_OK)
    }

    /// Whether this is one of the four failure values.
    ///
    /// The C idiom is `if(result)`, as at `lib/urlapi.c:L169` and L892.
    #[must_use]
    pub(crate) const fn is_err(self) -> bool {
        !self.is_ok()
    }

    /// The integer C would have used for this value.
    ///
    /// Not part of any ABI: no exported function of this crate accepts or
    /// returns a `CURLcode`. It exists so that the discriminants pinned in
    /// the declaration are reachable, for a diagnostic or a test, without
    /// anyone writing the numbers a second time.
    // No production caller: nothing this crate exports accepts or returns a
    // `CURLcode`, as the paragraph above says. Retained so the discriminants
    // pinned in the declaration are reachable without writing them twice.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn as_raw(self) -> c_int {
        self as c_int
    }
}

/// Folds a `CURLcode` into a `CURLUcode`, reproducing `cc2cu`.
///
/// `lib/urlapi.c:L120-L122` is the whole of the original:
///
/// ```c
/// /* convert CURLcode to CURLUcode */
/// #define cc2cu(x) \
///   ((x) == CURLE_TOO_LARGE ? CURLUE_TOO_LARGE : CURLUE_OUT_OF_MEMORY)
/// ```
///
/// # This is lossy on purpose and must not be widened
///
/// One value maps across; every other `CURLcode` in existence, including
/// values that have nothing to do with memory, becomes
/// `CURLUE_OUT_OF_MEMORY`. `CURLcode::CURLE_URL_MALFORMAT` becomes an
/// out-of-memory report. So does `CURLcode::CURLE_NOT_BUILT_IN`. So, and
/// this is the one worth stating out loud, does `CURLcode::CURLE_OK`.
///
/// That is not a defect in the port and it must not be repaired: the C macro
/// behaves this way, and reproducing it is the point. Anyone tempted to add
/// arms should look at the call sites first, because they explain why the
/// original gets away with it: all eight of them, `lib/urlapi.c:L170`, L598,
/// L623, L893, L1885, L1905, L1912 and L1920, fold the result of a
/// `curlx_dyn_add*` call, and a dynamic buffer returns only `CURLE_OK`,
/// `CURLE_TOO_LARGE` at `lib/curlx/dynbuf.c:L84` or `CURLE_OUT_OF_MEMORY` at
/// L108. Every one of those sites also tests the value first, so the success
/// case never reaches the macro.
///
/// # How to use it correctly
///
/// Call it only on a value already known to be a failure, exactly as the C
/// does, and only on a value that came from a dynamic buffer. A code from
/// percent decoding or from the IDN helpers needs a different mapping:
/// `lib/urlapi.c:L593` answers a failed decode with `CURLUE_BAD_HOSTNAME`
/// rather than folding it, and the IDN paths use [`idn2cu`]. Feeding this
/// function a `CURLcode::CURLE_URL_MALFORMAT` produces a truthful-looking
/// out-of-memory error that never happened, which is worse than no mapping
/// at all.
///
/// Note also that faithfulness does not mean the C is uniform. Where
/// `lib/urlapi.c:L1893-L1894` handles a dynamic buffer failure it returns
/// `CURLUE_OUT_OF_MEMORY` directly instead of folding, so a `too large`
/// there is reported as out of memory. That site belongs to the encoder, not
/// to this module, and the port reproduces it there rather than quietly
/// routing it through this function.
#[must_use]
pub(crate) const fn cc2cu(code: CURLcode) -> CURLUcode {
    match code {
        CURLcode::CURLE_TOO_LARGE => CURLUE_TOO_LARGE,
        // Everything else, success included. See the note above before
        // adding an arm here.
        _ => CURLUE_OUT_OF_MEMORY,
    }
}

/// Folds a `CURLcode` from the IDN helpers into a `CURLUcode`.
///
/// `lib/urlapi.c` writes this conversion out twice, identically, once in
/// each direction. `host_decode` at L1338-L1344:
///
/// ```c
/// CURLcode result = Curl_idn_decode(host, allochost);
/// if(result)
///   return (result == CURLE_OUT_OF_MEMORY) ?
///     CURLUE_OUT_OF_MEMORY : CURLUE_BAD_HOSTNAME;
/// return CURLUE_OK;
/// ```
///
/// and `host_encode` at L1349-L1355, which differs only in calling
/// `Curl_idn_encode`. The mapping lives here so that all numeric
/// translation is auditable in one file; the libidn2 call sequence it
/// applies to stays in `src/idn.rs`.
///
/// # Why this one is total where [`cc2cu`] is lossy
///
/// The C tests for failure before converting and returns `CURLUE_OK`
/// separately, so success has a defined answer here and this function is
/// safe to call on any value, unconditionally. Only out of memory maps
/// across; the two remaining failures, `CURLcode::CURLE_URL_MALFORMAT` from
/// `lib/idn.c:L267`, L288 or L318 and `CURLcode::CURLE_NOT_BUILT_IN` from
/// the too-old-libidn2 path at `lib/idn.c:L271`, both become
/// `CURLUE_BAD_HOSTNAME`. A caller therefore cannot distinguish a hostname
/// libidn2 rejected from a libidn2 too old to ask, which is the original's
/// behaviour and is reproduced rather than refined.
///
/// A build without IDN support does not reach this function at all:
/// `lib/urlapi.c:L1334-L1336` replaces both helpers with macros that yield
/// `CURLUE_LACKS_IDN`, and `src/idn.rs` reproduces that.
// No production caller without an IDN backend, for the reason the paragraph
// immediately above gives: the C replaces both helpers with macros and this
// fold is never reached. Retained rather than gated on `have_idn`, so that the
// tests below pin the mapping in every configuration.
#[allow(dead_code)]
#[must_use]
pub(crate) const fn idn2cu(code: CURLcode) -> CURLUcode {
    match code {
        // lib/urlapi.c:L1344 and L1355, the `return CURLUE_OK` that follows
        // the failure test.
        CURLcode::CURLE_OK => CURLUE_OK,
        CURLcode::CURLE_OUT_OF_MEMORY => CURLUE_OUT_OF_MEMORY,
        // CURLE_URL_MALFORMAT and CURLE_NOT_BUILT_IN, both indistinguishable
        // to the caller. lib/urlapi.c:L1341-L1342 and L1352-L1353.
        _ => CURLUE_BAD_HOSTNAME,
    }
}

/// The message for `code`, NUL terminated, as the verbose arm of
/// `curl_url_strerror` returns it.
///
/// This is the single source of truth for the 33 messages;
/// [`strerror_cstr`] and [`strerror`] are views of it and add nothing.
/// Ported from the `switch` at `lib/strerror.c:L423-L522` together with the
/// fallthrough return at L524, which the C reaches two ways: through
/// `case CURLUE_LAST: break;` at L520-L521, and by no case matching at all.
///
/// The arms are written in the C file's order, not in the enumeration's,
/// with each carrying its ordinal and its `lib/strerror.c` line, so that the
/// two files can be read side by side. See the note on the switch order in
/// this module's documentation for why that ordering matters: the eleven
/// arms after `CURLUE_NO_ZONEID` are the ones a positional port gets wrong.
///
/// # Returns
///
/// A `'static` byte literal whose last byte is NUL and which contains no
/// other NUL, so it is a valid C string and a valid `CStr`. Nothing is
/// allocated, so nothing is owned and the caller frees nothing.
// The `CURLUE_LAST` arm and the wildcard answer with the same string, which
// is what makes them worth writing separately: `lib/strerror.c:L520-L521`
// spends a case label on the sentinel so that the C compiler can see the
// switch cover every enumerator, and L524 then serves both it and every
// value outside the enumeration. Collapsing the two loses that structure
// from the file a reviewer is diffing against the C.
#[allow(clippy::match_same_arms)]
#[must_use]
pub(crate) const fn strerror_bytes(code: CURLUcode) -> &'static [u8] {
    match code {
        // 0, lib/strerror.c:L425.
        CURLUE_OK => b"No error\0",
        // 1, lib/strerror.c:L428.
        CURLUE_BAD_HANDLE => b"An invalid CURLU pointer was passed as argument\0",
        // 2, lib/strerror.c:L431.
        CURLUE_BAD_PARTPOINTER => b"An invalid 'part' argument was passed as argument\0",
        // 3, lib/strerror.c:L434.
        CURLUE_MALFORMED_INPUT => b"Malformed input to a URL function\0",
        // 4, lib/strerror.c:L437.
        CURLUE_BAD_PORT_NUMBER => b"Port number was not a decimal number between 0 and 65535\0",
        // 5, lib/strerror.c:L440.
        CURLUE_UNSUPPORTED_SCHEME => b"Unsupported URL scheme\0",
        // 6, lib/strerror.c:L443.
        CURLUE_URLDECODE => b"URL decode error, most likely because of rubbish in the input\0",
        // 7, lib/strerror.c:L446.
        CURLUE_OUT_OF_MEMORY => b"A memory function failed\0",
        // 8, lib/strerror.c:L449. The subject-verb disagreement is the
        // original's and is kept: this string is compared byte for byte.
        CURLUE_USER_NOT_ALLOWED => b"Credentials was passed in the URL when prohibited\0",
        // 9, lib/strerror.c:L452.
        CURLUE_UNKNOWN_PART => b"An unknown part ID was passed to a URL API function\0",
        // 10, lib/strerror.c:L455.
        CURLUE_NO_SCHEME => b"No scheme part in the URL\0",
        // 11, lib/strerror.c:L458.
        CURLUE_NO_USER => b"No user part in the URL\0",
        // 12, lib/strerror.c:L461.
        CURLUE_NO_PASSWORD => b"No password part in the URL\0",
        // 13, lib/strerror.c:L464.
        CURLUE_NO_OPTIONS => b"No options part in the URL\0",
        // 14, lib/strerror.c:L467.
        CURLUE_NO_HOST => b"No host part in the URL\0",
        // 15, lib/strerror.c:L470.
        CURLUE_NO_PORT => b"No port part in the URL\0",
        // 16, lib/strerror.c:L473.
        CURLUE_NO_QUERY => b"No query part in the URL\0",
        // 17, lib/strerror.c:L476.
        CURLUE_NO_FRAGMENT => b"No fragment part in the URL\0",
        // 18, lib/strerror.c:L479. The last case in enumeration order; the
        // eleven that follow are where the C file stops being ordered.
        CURLUE_NO_ZONEID => b"No zoneid part in the URL\0",
        // 23, lib/strerror.c:L482.
        CURLUE_BAD_LOGIN => b"Bad login part\0",
        // 22, lib/strerror.c:L485.
        CURLUE_BAD_IPV6 => b"Bad IPv6 address\0",
        // 21, lib/strerror.c:L488.
        CURLUE_BAD_HOSTNAME => b"Bad hostname\0",
        // 19, lib/strerror.c:L491.
        CURLUE_BAD_FILE_URL => b"Bad file:// URL\0",
        // 28, lib/strerror.c:L494.
        CURLUE_BAD_SLASHES => b"Unsupported number of slashes following scheme\0",
        // 27, lib/strerror.c:L497.
        CURLUE_BAD_SCHEME => b"Bad scheme\0",
        // 25, lib/strerror.c:L500.
        CURLUE_BAD_PATH => b"Bad path\0",
        // 20, lib/strerror.c:L503.
        CURLUE_BAD_FRAGMENT => b"Bad fragment\0",
        // 26, lib/strerror.c:L506.
        CURLUE_BAD_QUERY => b"Bad query\0",
        // 24, lib/strerror.c:L509.
        CURLUE_BAD_PASSWORD => b"Bad password\0",
        // 29, lib/strerror.c:L512.
        CURLUE_BAD_USER => b"Bad user\0",
        // 30, lib/strerror.c:L515.
        CURLUE_LACKS_IDN => b"libcurl lacks IDN support\0",
        // 31, lib/strerror.c:L518.
        CURLUE_TOO_LARGE => b"A value or data field is larger than allowed\0",
        // 32, lib/strerror.c:L520-L521. The sentinel has a case of its own
        // that breaks out of the switch and falls through to the string
        // below, so it is written out here for the same reason: to mirror
        // the C structure exactly. The wildcard would cover it.
        CURLUE_LAST => b"CURLUcode unknown\0",
        // lib/strerror.c:L524. Any value outside the enumeration, which a
        // caller can produce because the parameter is an `int` at the ABI.
        _ => b"CURLUcode unknown\0",
    }
}

/// The message for `code` as a `CStr`, the safe Rust view of
/// [`strerror_bytes`].
///
/// Useful to the crate's own tests and to any Rust caller that wants to
/// inspect the text rather than hand a pointer to C. It performs no
/// allocation and no copy: the returned `CStr` borrows the same `'static`
/// literal.
// No production caller: `curl_url_strerror` hands C a pointer, so the
// exported path uses `strerror` instead. Retained as the safe view of the
// same literal, which is what the tests below read the messages through.
#[allow(dead_code)]
#[must_use]
pub(crate) fn strerror_cstr(code: CURLUcode) -> &'static CStr {
    as_cstr(strerror_bytes(code))
}

/// The message for `code` as a C string pointer, the value
/// `curl_url_strerror` returns.
///
/// This is the module's entry point for `src/ffi.rs`, whose exported
/// `curl_url_strerror` is a null-check-free forward to it: the parameter is
/// an integer, so there is no pointer to validate and no failure mode. The
/// returned pointer is never null and always points at a NUL terminated
/// `'static` literal, which is what `include/curl/urlapi.h:L144-L149` and
/// `docs/libcurl/curl_url_strerror.md:L54-L56` promise.
///
/// # Ownership
///
/// None transfers. The caller must not free this pointer, and
/// `docs/libcurl/curl_url_strerror.md` deliberately imposes no obligation on
/// it, unlike `docs/libcurl/curl_url_get.md:L45` which requires a
/// `curl_free()`. This is the one string-returning path of the whole API
/// that does not come from `src/alloc.rs`; see this module's documentation
/// for why that exception is the correct behaviour rather than an oversight.
// No production caller when the `strerror` feature is off: the only thing that
// returns this pointer is `curl_url_strerror`, which the drop-in configuration
// must not export because `lib/strerror.c` already defines it. Retained
// unconditionally rather than gated, so the tests below pin the same pointer in
// both configurations.
#[allow(dead_code)]
#[must_use]
pub(crate) const fn strerror(code: CURLUcode) -> *const c_char {
    // No cast of provenance and no allocation: the pointer is the address of
    // a `'static` literal in this object's read-only data, which is exactly
    // where the C compiler puts the strings of lib/strerror.c. `c_char` is
    // `i8` on some targets and `u8` on others, so the element type is cast
    // rather than assumed; the address is unchanged either way.
    strerror_bytes(code).as_ptr().cast::<c_char>()
}

/// The message for `code`, NUL terminated, as the *non-verbose* arm of
/// `curl_url_strerror` returns it.
///
/// `lib/strerror.c:L525-L530` is the `#else` of `#ifdef CURLVERBOSE`, and is
/// the whole body when the 33 strings are compiled out:
///
/// ```c
/// if(error == CURLUE_OK)
///   return "No error";
/// else
///   return "Error";
/// ```
///
/// Two answers, and the second one covers every code including values
/// outside the enumeration.
///
/// # Why this exists and what selects it
///
/// It is ported so that the arm is reproduced rather than dropped. Nothing
/// in this crate selects it: `src/ffi.rs` exports [`strerror`], the verbose
/// form, because that is what an ordinary libcurl build produces and what
/// the parity oracles compare against, and a `verbose` Cargo feature may not
/// be invented because `rust-urlapi/Cargo.toml` fixes the feature set. Being
/// `pub(crate)`, this form is reachable only from inside the crate -- the
/// tests below drive it. Exporting it would need a new entry point in
/// `src/ffi.rs`, which is a decision outside this crate.
// No production caller: this crate always builds the verbose form, for the
// reason the paragraph above gives. Retained because the AAP requires this
// module to carry the non-verbose two-string variant of
// `lib/strerror.c`, and the tests below prove it is the C's two strings.
#[allow(dead_code)]
#[must_use]
pub(crate) const fn strerror_nonverbose_bytes(code: CURLUcode) -> &'static [u8] {
    if code == CURLUE_OK {
        b"No error\0"
    } else {
        b"Error\0"
    }
}

/// The non-verbose message for `code` as a `CStr`.
///
/// The safe Rust view of [`strerror_nonverbose_bytes`], for symmetry with
/// [`strerror_cstr`].
// No production caller, as for `strerror_nonverbose_bytes`. Retained for
// symmetry with `strerror_cstr`, so that both message sets offer the same
// three views.
#[allow(dead_code)]
#[must_use]
pub(crate) fn strerror_nonverbose_cstr(code: CURLUcode) -> &'static CStr {
    as_cstr(strerror_nonverbose_bytes(code))
}

/// The non-verbose message for `code` as a C string pointer.
///
/// The counterpart of [`strerror`] for the `#else` arm, with the same
/// ownership rules: nothing is allocated and the caller frees nothing.
// No production caller, as for `strerror_nonverbose_bytes`. Retained
// because this is the pointer form, the one an exported entry point would
// return, and so the shape the C's `#else` arm actually has.
#[allow(dead_code)]
#[must_use]
pub(crate) const fn strerror_nonverbose(code: CURLUcode) -> *const c_char {
    strerror_nonverbose_bytes(code).as_ptr().cast::<c_char>()
}

/// Views one of this module's literals as a `CStr`.
///
/// Every literal above is authored with a trailing NUL and none contains an
/// interior one, so the validation cannot fail; the crate's own test
/// `every_message_is_a_valid_c_string` proves that for all 33 of them plus
/// the out-of-range fallthrough.
///
/// The error arm is still handled rather than dismissed, and it is handled
/// without `unwrap` or `expect`, which `src/lib.rs` denies, and without
/// `CStr::from_bytes_with_nul_unchecked`, which is `unsafe` and belongs to
/// `src/ffi.rs` if it belongs anywhere. It answers with the empty C string,
/// because the one thing this function must never do is return null or
/// abort: `curl_url_strerror` is called from error paths, frequently inside
/// a `printf` argument list as at `docs/libcurl/curl_url_strerror.md:L47`,
/// and a null there is a crash in the caller. An empty message is a visible,
/// harmless failure; the test is what stops it ever happening.
// Dead only because both of its callers are: this is their shared view of
// one of this module's literals.
#[allow(dead_code)]
fn as_cstr(message: &'static [u8]) -> &'static CStr {
    // `unwrap_or_default` here is not the forbidden `unwrap`: it cannot
    // panic, which is why clippy prefers it to the equivalent `match`. The
    // default of `&CStr` is the empty C string, a single NUL byte in
    // read-only memory, so the fallback allocates nothing and is never null
    // either.
    CStr::from_bytes_with_nul(message).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        as_cstr, cc2cu, idn2cu, strerror, strerror_bytes, strerror_cstr, strerror_nonverbose,
        strerror_nonverbose_bytes, strerror_nonverbose_cstr, CURLcode,
    };
    use crate::abi::{
        CURLUcode, CURLUE_BAD_FILE_URL, CURLUE_BAD_FRAGMENT, CURLUE_BAD_HANDLE,
        CURLUE_BAD_HOSTNAME, CURLUE_BAD_IPV6, CURLUE_BAD_LOGIN, CURLUE_BAD_PARTPOINTER,
        CURLUE_BAD_PASSWORD, CURLUE_BAD_PATH, CURLUE_BAD_PORT_NUMBER, CURLUE_BAD_QUERY,
        CURLUE_BAD_SCHEME, CURLUE_BAD_SLASHES, CURLUE_BAD_USER, CURLUE_LACKS_IDN, CURLUE_LAST,
        CURLUE_MALFORMED_INPUT, CURLUE_NO_FRAGMENT, CURLUE_NO_HOST, CURLUE_NO_OPTIONS,
        CURLUE_NO_PASSWORD, CURLUE_NO_PORT, CURLUE_NO_QUERY, CURLUE_NO_SCHEME, CURLUE_NO_USER,
        CURLUE_NO_ZONEID, CURLUE_OK, CURLUE_OUT_OF_MEMORY, CURLUE_TOO_LARGE, CURLUE_UNKNOWN_PART,
        CURLUE_UNSUPPORTED_SCHEME, CURLUE_URLDECODE, CURLUE_USER_NOT_ALLOWED,
    };

    /// The 33 messages, keyed by code and written in the *enumeration's*
    /// order.
    ///
    /// The implementation writes them in `lib/strerror.c`'s order, which for
    /// the last eleven is a different order. Spelling the expectations the
    /// other way round is deliberate: a transcription that mixed up two
    /// codes would have to make the identical mistake twice, in two
    /// different orderings, to survive this table. Every string here was
    /// copied from the `case` label it belongs to rather than from the
    /// position it occupies.
    ///
    /// Formatting is suppressed deliberately. This is reference data, and one
    /// code per line is what makes it checkable against
    /// `lib/strerror.c:L423-L522` at a glance; rustfmt breaks the longer
    /// entries across four lines each, which turns a table into prose.
    #[rustfmt::skip]
    const EXPECTED: [(CURLUcode, &str); 33] = [
        (CURLUE_OK,                "No error"),
        (CURLUE_BAD_HANDLE,        "An invalid CURLU pointer was passed as argument"),
        (CURLUE_BAD_PARTPOINTER,   "An invalid 'part' argument was passed as argument"),
        (CURLUE_MALFORMED_INPUT,   "Malformed input to a URL function"),
        (CURLUE_BAD_PORT_NUMBER,   "Port number was not a decimal number between 0 and 65535"),
        (CURLUE_UNSUPPORTED_SCHEME, "Unsupported URL scheme"),
        (CURLUE_URLDECODE,         "URL decode error, most likely because of rubbish in the input"),
        (CURLUE_OUT_OF_MEMORY,     "A memory function failed"),
        (CURLUE_USER_NOT_ALLOWED,  "Credentials was passed in the URL when prohibited"),
        (CURLUE_UNKNOWN_PART,      "An unknown part ID was passed to a URL API function"),
        (CURLUE_NO_SCHEME,         "No scheme part in the URL"),
        (CURLUE_NO_USER,           "No user part in the URL"),
        (CURLUE_NO_PASSWORD,       "No password part in the URL"),
        (CURLUE_NO_OPTIONS,        "No options part in the URL"),
        (CURLUE_NO_HOST,           "No host part in the URL"),
        (CURLUE_NO_PORT,           "No port part in the URL"),
        (CURLUE_NO_QUERY,          "No query part in the URL"),
        (CURLUE_NO_FRAGMENT,       "No fragment part in the URL"),
        (CURLUE_NO_ZONEID,         "No zoneid part in the URL"),
        (CURLUE_BAD_FILE_URL,      "Bad file:// URL"),
        (CURLUE_BAD_FRAGMENT,      "Bad fragment"),
        (CURLUE_BAD_HOSTNAME,      "Bad hostname"),
        (CURLUE_BAD_IPV6,          "Bad IPv6 address"),
        (CURLUE_BAD_LOGIN,         "Bad login part"),
        (CURLUE_BAD_PASSWORD,      "Bad password"),
        (CURLUE_BAD_PATH,          "Bad path"),
        (CURLUE_BAD_QUERY,         "Bad query"),
        (CURLUE_BAD_SCHEME,        "Bad scheme"),
        (CURLUE_BAD_SLASHES,       "Unsupported number of slashes following scheme"),
        (CURLUE_BAD_USER,          "Bad user"),
        (CURLUE_LACKS_IDN,         "libcurl lacks IDN support"),
        (CURLUE_TOO_LARGE,         "A value or data field is larger than allowed"),
        (CURLUE_LAST,              "CURLUcode unknown"),
    ];

    /// What every code outside the enumeration answers with, and what the
    /// sentinel answers with too. `lib/strerror.c:L524`.
    const UNKNOWN: &str = "CURLUcode unknown";

    /// Renders one of the module's NUL terminated literals as text.
    ///
    /// Deliberately free of `unwrap`, `expect` and indexing, all of which
    /// `src/lib.rs` denies, in the tests as much as in the code. A literal
    /// that lost its terminator, gained an interior NUL or stopped being
    /// UTF-8 renders as the empty string, which fails every assertion below
    /// rather than passing quietly.
    fn text(message: &'static [u8]) -> &'static str {
        match message.split_last() {
            // `unwrap_or_default` cannot panic and is not the forbidden
            // `unwrap`; the default of `&str` is the empty string.
            Some((&0, body)) => core::str::from_utf8(body).unwrap_or_default(),
            _ => "",
        }
    }

    /// Whether `message` is a well-formed C string: terminated, with no
    /// interior NUL and with something in it.
    fn is_valid_c_string(message: &[u8]) -> bool {
        match message.split_last() {
            Some((&0, body)) => !body.is_empty() && !body.contains(&0),
            _ => false,
        }
    }

    /// The five `CURLcode` values this crate produces carry the ordinals
    /// `include/curl/curl.h` gives them, and the success test agrees with
    /// them.
    ///
    /// The ordinals come from L519, L522, L523, L554 and L645 of that header,
    /// in the order asserted below.
    #[test]
    fn curlcode_discriminants_match_the_c_ordinals() {
        assert_eq!(CURLcode::CURLE_OK.as_raw(), 0);
        assert_eq!(CURLcode::CURLE_URL_MALFORMAT.as_raw(), 3);
        assert_eq!(CURLcode::CURLE_NOT_BUILT_IN.as_raw(), 4);
        assert_eq!(CURLcode::CURLE_OUT_OF_MEMORY.as_raw(), 27);
        assert_eq!(CURLcode::CURLE_TOO_LARGE.as_raw(), 100);

        assert!(CURLcode::CURLE_OK.is_ok());
        assert!(!CURLcode::CURLE_OK.is_err());
        for code in [
            CURLcode::CURLE_URL_MALFORMAT,
            CURLcode::CURLE_NOT_BUILT_IN,
            CURLcode::CURLE_OUT_OF_MEMORY,
            CURLcode::CURLE_TOO_LARGE,
        ] {
            assert!(code.is_err(), "{code:?} is a failure value");
            assert!(!code.is_ok(), "{code:?} is a failure value");
        }
    }

    /// `cc2cu` maps one value across and folds the rest, including success.
    ///
    /// `lib/urlapi.c:L120-L122`. The success case is asserted because it is
    /// the surprising one and because a later reader who "fixes" it has to
    /// break a test that says the behaviour is intentional.
    #[test]
    fn cc2cu_folds_everything_except_too_large() {
        assert_eq!(cc2cu(CURLcode::CURLE_TOO_LARGE), CURLUE_TOO_LARGE);

        for code in [
            CURLcode::CURLE_OUT_OF_MEMORY,
            CURLcode::CURLE_URL_MALFORMAT,
            CURLcode::CURLE_NOT_BUILT_IN,
            CURLcode::CURLE_OK,
        ] {
            assert_eq!(
                cc2cu(code),
                CURLUE_OUT_OF_MEMORY,
                "the C macro folds {code:?} to CURLUE_OUT_OF_MEMORY; do not widen it"
            );
        }
    }

    /// `idn2cu` maps out of memory across, success to success and both
    /// remaining failures to a bad hostname.
    ///
    /// `lib/urlapi.c:L1338-L1344` and L1349-L1355.
    #[test]
    fn idn2cu_maps_only_out_of_memory_across() {
        assert_eq!(idn2cu(CURLcode::CURLE_OK), CURLUE_OK);
        assert_eq!(idn2cu(CURLcode::CURLE_OUT_OF_MEMORY), CURLUE_OUT_OF_MEMORY);
        assert_eq!(idn2cu(CURLcode::CURLE_URL_MALFORMAT), CURLUE_BAD_HOSTNAME);
        assert_eq!(
            idn2cu(CURLcode::CURLE_NOT_BUILT_IN),
            CURLUE_BAD_HOSTNAME,
            "a libidn2 too old is indistinguishable from a rejected hostname"
        );
    }

    /// All 33 messages, verified against the table above rather than against
    /// their position.
    #[test]
    fn verbose_messages_match_lib_strerror() {
        for (code, expected) in EXPECTED {
            assert_eq!(
                text(strerror_bytes(code)),
                expected,
                "message for CURLUcode {code} does not match its lib/strerror.c case label"
            );
        }
    }

    /// The spread the file's specification calls out by number: the two ends,
    /// the ungrammatical one, the boundary where the C switch stops being
    /// ordered, two of the codes on the wrong side of it, the sentinel and a
    /// value that is not a code at all.
    #[test]
    fn verbose_spot_checks_across_the_range() {
        assert_eq!(text(strerror_bytes(0)), "No error");
        assert_eq!(
            text(strerror_bytes(8)),
            "Credentials was passed in the URL when prohibited",
            "lib/strerror.c:L449 disagrees with itself grammatically and is quoted anyway"
        );
        assert_eq!(text(strerror_bytes(18)), "No zoneid part in the URL");
        assert_eq!(
            text(strerror_bytes(19)),
            "Bad file:// URL",
            "19 is CURLUE_BAD_FILE_URL, which the C switch lists fourth from last"
        );
        assert_eq!(
            text(strerror_bytes(23)),
            "Bad login part",
            "23 is CURLUE_BAD_LOGIN, which the C switch lists first after NO_ZONEID"
        );
        assert_eq!(text(strerror_bytes(30)), "libcurl lacks IDN support");
        assert_eq!(
            text(strerror_bytes(31)),
            "A value or data field is larger than allowed"
        );
        assert_eq!(
            text(strerror_bytes(32)),
            UNKNOWN,
            "CURLUE_LAST is never an error"
        );
        assert_eq!(text(strerror_bytes(99)), UNKNOWN);
    }

    /// The sentinel, everything above it and everything below zero fall
    /// through to one string. The parameter is an `int` at the ABI, so a
    /// caller really can pass any of these.
    #[test]
    fn unknown_codes_answer_with_the_fallthrough() {
        for code in [33, 99, 1000, -1, -99, CURLUcode::MIN, CURLUcode::MAX] {
            assert_eq!(
                text(strerror_bytes(code)),
                UNKNOWN,
                "code {code} is not a CURLUcode"
            );
        }
        assert_eq!(text(strerror_bytes(CURLUE_LAST)), UNKNOWN);
    }

    /// Every message, and every fallthrough, is a valid C string: terminated,
    /// no interior NUL, printable ASCII only, and not empty.
    ///
    /// The ASCII part is not cosmetic. `scripts/spacecheck.pl` rejects a
    /// non-ASCII byte in this file, so a string copied through a tool that
    /// substituted a typographic character would fail the repository's own
    /// gate; this catches it here first.
    #[test]
    fn every_message_is_a_valid_c_string() {
        for code in -8..=40 {
            let message = strerror_bytes(code);
            assert!(
                is_valid_c_string(message),
                "malformed literal for code {code}"
            );
            assert!(
                message
                    .iter()
                    .all(|byte| *byte == 0 || (0x20..0x7f).contains(byte)),
                "message for code {code} is not printable ASCII"
            );
            assert_eq!(
                strerror_cstr(code).to_bytes_with_nul(),
                message,
                "the CStr view diverged from the byte table for code {code}"
            );
        }
    }

    /// The 33 messages are 33 distinct strings, so no two codes report each
    /// other's error.
    #[test]
    fn messages_are_distinct() {
        for (outer, (left, _)) in EXPECTED.iter().enumerate() {
            for (inner, (right, _)) in EXPECTED.iter().enumerate() {
                if outer != inner {
                    assert_ne!(
                        text(strerror_bytes(*left)),
                        text(strerror_bytes(*right)),
                        "codes {left} and {right} share a message"
                    );
                }
            }
        }
    }

    /// The non-verbose arm has exactly two answers.
    ///
    /// `lib/strerror.c:L525-L530`.
    #[test]
    fn nonverbose_has_exactly_two_answers() {
        assert_eq!(text(strerror_nonverbose_bytes(CURLUE_OK)), "No error");
        for code in [1, 8, 18, 31, CURLUE_LAST, 99, -1, CURLUcode::MAX] {
            assert_eq!(
                text(strerror_nonverbose_bytes(code)),
                "Error",
                "the non-verbose arm says nothing else about code {code}"
            );
        }
        assert_eq!(
            strerror_nonverbose_cstr(CURLUE_OK).to_bytes(),
            b"No error",
            "the CStr view diverged from the byte table"
        );
    }

    /// The pointers handed to C are never null, are stable across calls and
    /// address the literal itself.
    ///
    /// Stability is the interesting part: it is what proves nothing is
    /// allocated and nothing is copied per call, which is what makes it
    /// correct for the caller never to free the result. The `'static`
    /// lifetime is proved by the signatures at compile time; this is the
    /// run-time half.
    #[test]
    fn pointers_are_static_and_never_null() {
        for (code, _) in EXPECTED {
            let first = strerror(code);
            let second = strerror(code);
            assert!(!first.is_null(), "null message pointer for code {code}");
            assert!(
                core::ptr::eq(first, second),
                "pointer for code {code} is not stable"
            );
            assert!(
                core::ptr::eq(first.cast::<u8>(), strerror_bytes(code).as_ptr()),
                "the pointer for code {code} does not address the literal"
            );

            let plain = strerror_nonverbose(code);
            assert!(!plain.is_null(), "null non-verbose pointer for code {code}");
            assert!(
                core::ptr::eq(plain, strerror_nonverbose(code)),
                "non-verbose pointer for code {code} is not stable"
            );
        }
    }

    /// The unreachable arm of the `CStr` view answers with the empty string
    /// rather than aborting.
    ///
    /// No literal in this module can reach it, which is what
    /// `every_message_is_a_valid_c_string` establishes. This test documents
    /// the behaviour anyway, by feeding the helper the two shapes it rejects,
    /// because "cannot happen" and "is handled" are different claims and the
    /// second one is the one that keeps a caller's `printf` from dereferencing
    /// null.
    #[test]
    fn as_cstr_falls_back_to_the_empty_string() {
        assert_eq!(as_cstr(b"interior\0nul\0").to_bytes(), b"");
        assert_eq!(as_cstr(b"no terminator").to_bytes(), b"");
        assert_eq!(
            as_cstr(b"well formed\0").to_bytes(),
            b"well formed",
            "a valid literal passes through unchanged"
        );
    }
}
