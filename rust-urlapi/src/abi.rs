// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Numeric ABI surface of curl's URL API.
//!
//! This module restates in Rust every number that crosses the C boundary of
//! the URL API: the 33 `CURLUcode` result codes, the 11 `CURLUPart` part
//! identifiers and the 16 `CURLU_*` behaviour flags declared in
//! `include/curl/urlapi.h`:L34-L105, plus the four supporting constants the
//! implementation needs from `lib/urlapi.c` and `lib/urldata.h`.
//!
//! It is the foundation of the crate. Every other module depends on it and
//! it depends on nothing. There are no imports, no functions, no `unsafe`,
//! and deliberately no `#[cfg(feature = ...)]` anywhere, because an ABI does
//! not vary with the features a particular build happens to select. The two
//! type aliases below are the single place in the crate where the width of a
//! C integer is decided.
//!
//! # Parity here is positional, not textual
//!
//! No line of C anywhere in the tree states that `CURLUE_BAD_IPV6` is 22. It
//! is 22 because it is the twenty-third entry declared in the `typedef enum`
//! that opens at `include/curl/urlapi.h`:L34, and C assigns enumerators
//! sequentially from zero when no explicit value is given. The same is true
//! of `CURLUPart` at L70-L82. The numbers are a consequence of declaration
//! order, and callers switch on them numerically, so inserting, removing or
//! reordering a single entry silently breaks every compiled caller.
//!
//! Two consequences shape this file.
//!
//! First, every value is written out as an explicit integer constant. A Rust
//! `enum` would be the idiomatic choice and is the wrong one here: its
//! discriminants are also implicit, so a later edit could reorder a variant
//! and change 33 numbers at once without producing a single compiler error.
//! An explicit constant cannot drift, and a wrong one is visible in a diff.
//!
//! Second, the values are asserted rather than merely written once, in three
//! places that fail in three different ways. `src/lib.rs` asserts every one of
//! them at **compile time**, so a wrong constant fails the build rather than
//! the parity run. The small `tests` module at the end of this file is the
//! fast local check. And `rust-urlapi/tests/abi_constants.rs` is the run-time
//! pass over the same set: it exists, it is one of the crate's five Cargo
//! integration tests, and it re-derives all 33 result codes, 11 part
//! identifiers and 16 flag bits from this module's `pub` constants -- which is
//! why the module is `pub` at all. It checks the properties the literals alone
//! cannot show, contiguity and uniqueness of the ordinals and the bit union of
//! the flags, so the three checks overlap deliberately rather than
//! redundantly.
//!
//! # The header is the only authority
//!
//! The manual pages are an incomplete record of the flag set: the nine flags
//! documented in `docs/libcurl/curl_url_get.md` and the nine documented in
//! `docs/libcurl/curl_url_set.md` overlap but do not add up to sixteen.
//! Anyone auditing this file against those pages will find fewer flags there
//! and must not "correct" this file to match. `include/curl/urlapi.h` alone
//! is authoritative, and all sixteen bits it defines are reproduced below.
//!
//! Likewise nothing may be added. This port introduces no new `CURLUcode`
//! value, no new `CURLUPart` value and no new `CURLU_*` flag; it
//! re-implements the existing ones and nothing else. The file therefore
//! defines exactly 33 plus 11 plus 16 ABI constants, the four supporting
//! constants, one companion spelling of `DEFAULT_SCHEME`, and no more.

// The plan puts every `unsafe` block in `src/ffi.rs` (0.3.3) and the
// technical specification forbids `unsafe` outside FFI code (1.3.2.1).
// `forbid` rather than `deny` because an inner `allow` here would be a
// design change and should have to be argued for, not slipped in. This
// module needs nothing from C, so the attribute costs it nothing and turns
// the crate's single-unsafe-island property into a compiler guarantee
// instead of a convention.
#![forbid(unsafe_code)]

/// Result type of the URL API, `CURLUcode`.
///
/// Declared at `include/curl/urlapi.h`:L34-L68 as an anonymous
/// `typedef enum` named `CURLUcode`. A C enumeration whose enumerators all
/// fit in `int` has `int` as its compatible type on every platform curl
/// supports, and `int` is what the C compiler passes and returns for
/// `curl_url_get`, `curl_url_set` and `curl_url_strerror`. The alias is
/// therefore `c_int` and not `u32`: matching the signedness matters because
/// the value travels through signatures that C code was compiled against.
///
/// The values are the `CURLUE_*` constants in this module.
pub type CURLUcode = ::core::ffi::c_int;

/// Part selector of the URL API, `CURLUPart`.
///
/// Declared at `include/curl/urlapi.h`:L70-L82 as an anonymous
/// `typedef enum` named `CURLUPart`, so the same reasoning as for
/// `CURLUcode` applies: the C compatible type is `int`, hence `c_int` rather
/// than `u32`. It is the second parameter of both `curl_url_get` (L133-L134)
/// and `curl_url_set` (L141-L142).
///
/// The values are the `CURLUPART_*` constants in this module.
pub type CURLUPart = ::core::ffi::c_int;

// ---------------------------------------------------------------------------
// CURLUcode -- the 33 result codes, include/curl/urlapi.h:L34-L68
//
// Written in declaration order. The header carries the ordinal as a trailing
// comment for 1 through 31 but not for the first and last entries, so those
// two are the ones worth double-checking against the source: CURLUE_OK is 0
// because it is declared first, and CURLUE_LAST is 32 because 32 entries
// precede it.
// ---------------------------------------------------------------------------

/// No error. `include/curl/urlapi.h`:L35, the first enumerator, so 0.
pub const CURLUE_OK: CURLUcode = 0;

/// An invalid `CURLU` pointer was passed as argument.
///
/// `include/curl/urlapi.h`:L36. Returned instead of dereferencing a null
/// handle, which is why the exported entry points in `src/ffi.rs` check for
/// it before forming any reference.
pub const CURLUE_BAD_HANDLE: CURLUcode = 1;

/// An invalid `part` argument was passed as argument.
///
/// `include/curl/urlapi.h`:L37. Returned by `curl_url_get` when the
/// out-parameter pointer is null.
pub const CURLUE_BAD_PARTPOINTER: CURLUcode = 2;

/// Malformed input to a URL function. `include/curl/urlapi.h`:L38.
pub const CURLUE_MALFORMED_INPUT: CURLUcode = 3;

/// Port number was not a decimal number between 0 and 65535.
///
/// `include/curl/urlapi.h`:L39.
pub const CURLUE_BAD_PORT_NUMBER: CURLUcode = 4;

/// Unsupported URL scheme. `include/curl/urlapi.h`:L40.
pub const CURLUE_UNSUPPORTED_SCHEME: CURLUcode = 5;

/// URL decode error, most likely because of rubbish in the input.
///
/// `include/curl/urlapi.h`:L41.
pub const CURLUE_URLDECODE: CURLUcode = 6;

/// A memory function failed. `include/curl/urlapi.h`:L42.
pub const CURLUE_OUT_OF_MEMORY: CURLUcode = 7;

/// Credentials were passed in the URL when prohibited.
///
/// `include/curl/urlapi.h`:L43.
pub const CURLUE_USER_NOT_ALLOWED: CURLUcode = 8;

/// An unknown part identifier was passed to a URL API function.
///
/// `include/curl/urlapi.h`:L44.
pub const CURLUE_UNKNOWN_PART: CURLUcode = 9;

/// No scheme part in the URL. `include/curl/urlapi.h`:L45.
pub const CURLUE_NO_SCHEME: CURLUcode = 10;

/// No user part in the URL. `include/curl/urlapi.h`:L46.
pub const CURLUE_NO_USER: CURLUcode = 11;

/// No password part in the URL. `include/curl/urlapi.h`:L47.
pub const CURLUE_NO_PASSWORD: CURLUcode = 12;

/// No options part in the URL. `include/curl/urlapi.h`:L48.
pub const CURLUE_NO_OPTIONS: CURLUcode = 13;

/// No host part in the URL. `include/curl/urlapi.h`:L49.
pub const CURLUE_NO_HOST: CURLUcode = 14;

/// No port part in the URL. `include/curl/urlapi.h`:L50.
pub const CURLUE_NO_PORT: CURLUcode = 15;

/// No query part in the URL. `include/curl/urlapi.h`:L51.
pub const CURLUE_NO_QUERY: CURLUcode = 16;

/// No fragment part in the URL. `include/curl/urlapi.h`:L52.
pub const CURLUE_NO_FRAGMENT: CURLUcode = 17;

/// No zone identifier part in the URL. `include/curl/urlapi.h`:L53.
pub const CURLUE_NO_ZONEID: CURLUcode = 18;

/// Bad `file://` URL. `include/curl/urlapi.h`:L54.
pub const CURLUE_BAD_FILE_URL: CURLUcode = 19;

/// Bad fragment. `include/curl/urlapi.h`:L55.
pub const CURLUE_BAD_FRAGMENT: CURLUcode = 20;

/// Bad hostname. `include/curl/urlapi.h`:L56.
pub const CURLUE_BAD_HOSTNAME: CURLUcode = 21;

/// Bad IPv6 address. `include/curl/urlapi.h`:L57.
pub const CURLUE_BAD_IPV6: CURLUcode = 22;

/// Bad login part. `include/curl/urlapi.h`:L58.
pub const CURLUE_BAD_LOGIN: CURLUcode = 23;

/// Bad password. `include/curl/urlapi.h`:L59.
pub const CURLUE_BAD_PASSWORD: CURLUcode = 24;

/// Bad path. `include/curl/urlapi.h`:L60.
pub const CURLUE_BAD_PATH: CURLUcode = 25;

/// Bad query. `include/curl/urlapi.h`:L61.
pub const CURLUE_BAD_QUERY: CURLUcode = 26;

/// Bad scheme. `include/curl/urlapi.h`:L62.
pub const CURLUE_BAD_SCHEME: CURLUcode = 27;

/// Unsupported number of slashes following the scheme.
///
/// `include/curl/urlapi.h`:L63.
pub const CURLUE_BAD_SLASHES: CURLUcode = 28;

/// Bad user. `include/curl/urlapi.h`:L64.
pub const CURLUE_BAD_USER: CURLUcode = 29;

/// This build lacks IDN support. `include/curl/urlapi.h`:L65.
///
/// `lib/urlapi.c`:L1334-L1336 defines the host encode and decode helpers as
/// macros yielding this code when `USE_IDN` is undefined, so it is what an
/// internationalised host name produces in a build without that support.
pub const CURLUE_LACKS_IDN: CURLUcode = 30;

/// A value or data field is larger than allowed.
///
/// `include/curl/urlapi.h`:L66.
pub const CURLUE_TOO_LARGE: CURLUcode = 31;

/// Sentinel one past the last real code. `include/curl/urlapi.h`:L67.
///
/// Never returned as an error, and part of the ABI nonetheless: the
/// verbose arm of `curl_url_strerror` matches it explicitly at
/// `lib/strerror.c`:L520-L521 so that the compiler can prove the switch is
/// exhaustive, then falls through to `"CURLUcode unknown"` at L524.
pub const CURLUE_LAST: CURLUcode = 32;

// ---------------------------------------------------------------------------
// CURLUPart -- the 11 part identifiers, include/curl/urlapi.h:L70-L82
//
// The header gives no ordinals here at all, so these numbers exist purely by
// declaration order.
// ---------------------------------------------------------------------------

/// The whole URL. `include/curl/urlapi.h`:L71, the first enumerator, so 0.
pub const CURLUPART_URL: CURLUPart = 0;

/// The scheme. `include/curl/urlapi.h`:L72.
pub const CURLUPART_SCHEME: CURLUPart = 1;

/// The user name. `include/curl/urlapi.h`:L73.
pub const CURLUPART_USER: CURLUPart = 2;

/// The password. `include/curl/urlapi.h`:L74.
pub const CURLUPART_PASSWORD: CURLUPart = 3;

/// The options, carried in the userinfo field.
///
/// `include/curl/urlapi.h`:L75. Only accepted for schemes whose descriptor
/// carries `PROTOPT_URLOPTIONS`; see that constant below.
pub const CURLUPART_OPTIONS: CURLUPart = 4;

/// The host name or numeric address. `include/curl/urlapi.h`:L76.
pub const CURLUPART_HOST: CURLUPart = 5;

/// The port number. `include/curl/urlapi.h`:L77.
pub const CURLUPART_PORT: CURLUPart = 6;

/// The path. `include/curl/urlapi.h`:L78.
pub const CURLUPART_PATH: CURLUPart = 7;

/// The query. `include/curl/urlapi.h`:L79.
pub const CURLUPART_QUERY: CURLUPart = 8;

/// The fragment. `include/curl/urlapi.h`:L80.
pub const CURLUPART_FRAGMENT: CURLUPart = 9;

/// The zone identifier of a numeric IPv6 address, added in 7.65.0.
///
/// `include/curl/urlapi.h`:L81, which carries that "added in 7.65.0" note
/// itself. It is the final enumerator, so it is 10.
pub const CURLUPART_ZONEID: CURLUPart = 10;

// ---------------------------------------------------------------------------
// CURLU_* -- the 16 behaviour flags, include/curl/urlapi.h:L84-L105
//
// This is the one part of the ABI the C header does spell out, as
// `#define CURLU_xxx (1 << n)`. Each is written below as the same explicit
// shift so that the bit position stays visible at the definition site rather
// than having to be recovered from a decimal or hexadecimal value.
//
// The type is `c_uint` because that is how the flags travel: both
// `curl_url_get` at include/curl/urlapi.h:L133-L134 and `curl_url_set` at
// L141-L142 take them as `unsigned int flags`.
// ---------------------------------------------------------------------------

/// Return the default port number.
///
/// `include/curl/urlapi.h`:L84.
pub const CURLU_DEFAULT_PORT: ::core::ffi::c_uint = 1 << 0;

/// Act as if no port number was set, if the port number matches the default
/// for the scheme.
///
/// `include/curl/urlapi.h`:L85-L87. Needs the numeric port kept alongside the
/// port string on the handle, because the comparison is against the
/// scheme descriptor's default port rather than against text.
pub const CURLU_NO_DEFAULT_PORT: ::core::ffi::c_uint = 1 << 1;

/// Return the default scheme if it is missing.
///
/// `include/curl/urlapi.h`:L88-L89. The scheme substituted is
/// `DEFAULT_SCHEME`, defined below.
pub const CURLU_DEFAULT_SCHEME: ::core::ffi::c_uint = 1 << 2;

/// Allow a non-supported scheme.
///
/// `include/curl/urlapi.h`:L90.
pub const CURLU_NON_SUPPORT_SCHEME: ::core::ffi::c_uint = 1 << 3;

/// Leave dot sequences in the path alone.
///
/// `include/curl/urlapi.h`:L91. When absent, the path goes through the dot
/// segment removal ported in `src/parse/path.rs`.
pub const CURLU_PATH_AS_IS: ::core::ffi::c_uint = 1 << 4;

/// No user name and password allowed.
///
/// `include/curl/urlapi.h`:L92. A URL carrying credentials then fails with
/// `CURLUE_USER_NOT_ALLOWED`.
pub const CURLU_DISALLOW_USER: ::core::ffi::c_uint = 1 << 5;

/// URL decode on get.
///
/// `include/curl/urlapi.h`:L93.
pub const CURLU_URLDECODE: ::core::ffi::c_uint = 1 << 6;

/// URL encode on set.
///
/// `include/curl/urlapi.h`:L94.
pub const CURLU_URLENCODE: ::core::ffi::c_uint = 1 << 7;

/// Append a form style part.
///
/// `include/curl/urlapi.h`:L95. Only meaningful for `CURLUPART_QUERY`.
pub const CURLU_APPENDQUERY: ::core::ffi::c_uint = 1 << 8;

/// Legacy curl-style scheme guessing.
///
/// `include/curl/urlapi.h`:L96. Selects the host name prefix guess table
/// ported in `src/parse/scheme.rs`, and records on the handle that the
/// resulting scheme was guessed rather than given.
pub const CURLU_GUESS_SCHEME: ::core::ffi::c_uint = 1 << 9;

/// Allow an empty authority when the scheme is unknown.
///
/// `include/curl/urlapi.h`:L97-L98.
pub const CURLU_NO_AUTHORITY: ::core::ffi::c_uint = 1 << 10;

/// Allow spaces in the URL.
///
/// `include/curl/urlapi.h`:L99. Without it a space is rejected by the junk
/// scan ported in `src/parse/junk.rs`.
pub const CURLU_ALLOW_SPACE: ::core::ffi::c_uint = 1 << 11;

/// Get the host name in punycode.
///
/// `include/curl/urlapi.h`:L100. This bit, `CURLU_PUNY2IDN` and
/// `CURLU_URLENCODE` share one `if` / `else if` chain at
/// `lib/urlapi.c`:L1392-L1420, so combining them is accepted rather than
/// rejected and the chain decides by precedence: `CURLU_URLENCODE` first at
/// L1392, then this bit at L1401, then `CURLU_PUNY2IDN` at L1411. Passing
/// both punycode bits therefore converts one way only, and passing
/// `CURLU_URLENCODE` alongside either suppresses both conversions with no
/// error reported.
pub const CURLU_PUNYCODE: ::core::ffi::c_uint = 1 << 12;

/// Convert a punycode host name back to its internationalised form.
///
/// `include/curl/urlapi.h`:L101, whose own comment writes the direction as
/// punycode to IDN.
pub const CURLU_PUNY2IDN: ::core::ffi::c_uint = 1 << 13;

/// Allow empty queries and fragments when extracting the URL or the
/// components.
///
/// `include/curl/urlapi.h`:L102-L104. Needs the two presence bits kept on
/// the handle, because an empty query that was present in the input has to
/// be distinguishable from a query that was absent.
pub const CURLU_GET_EMPTY: ::core::ffi::c_uint = 1 << 14;

/// For get, do not accept a guess.
///
/// `include/curl/urlapi.h`:L105. Retrieving the scheme of a handle whose
/// scheme was guessed then yields `CURLUE_NO_SCHEME`, and retrieving the
/// whole URL omits the scheme prefix.
pub const CURLU_NO_GUESS_SCHEME: ::core::ffi::c_uint = 1 << 15;

// ---------------------------------------------------------------------------
// Supporting constants
//
// None of these is part of the public header. Four are object-like macros,
// each in a different C file and each cited to that file rather than to
// include/curl/urlapi.h. The fifth, DEFAULT_SCHEME_CSTR, is not a separate
// value at all: it is a second spelling of DEFAULT_SCHEME for the one caller
// that needs the terminated form.
//
// NONE OF THESE FIVE BELONGS IN THE PUBLIC MIRROR HEADER, and the mechanism
// that keeps them out is not in this file. include/curl/urlapi.h declares no
// such constant, so a header that mirrors it must not either. But cbindgen
// sees any item declared `pub` at its definition site, and rust-urlapi/
// cbindgen.toml lists "constants" in item_types for the sake of the sixteen
// CURLU_* flag bits, so MAX_SCHEME_LEN, CURL_MAX_INPUT_LENGTH and
// PROTOPT_URLOPTIONS would otherwise be emitted -- MAX_SCHEME_LEN
// unprefixed, occupying a global macro name in every consumer. They are
// therefore named in that file's [export] exclude list, which is where the
// header's surface is decided. DEFAULT_SCHEME and DEFAULT_SCHEME_CSTR need
// no entry: a &str and a &[u8] have no C representation and cbindgen skips
// them of its own accord.
//
// Narrowing the three to pub(crate) would also keep them out, and is
// deliberately NOT what was done. src/ffi.rs and src/getset.rs are
// cross-module consumers of all three, so "what may the crate reach" and
// "what may the header declare" are different questions; answering the
// second by constraining the first would couple them for no gain and would
// have to be undone the moment a fourth consumer appeared. The visibility
// below is the one the crate needs; cbindgen.toml is the export contract.
// ---------------------------------------------------------------------------

/// Longest scheme the implementation accepts, in bytes.
///
/// `lib/urlapi.c`:L55, whose own comment at L54 explains the choice: the
/// scheme is not URL encoded, and the longest schemes libcurl supports are
/// well inside this bound. It is a ceiling on the accepted input rather
/// than a measurement of the scheme table.
///
/// The C uses it in three size contexts, all of which are lengths: the
/// buffer precondition at L186, the scan bound at L195 and the array size
/// `MAX_SCHEME_LEN + 5` at L1452. `usize` is therefore the useful Rust type,
/// and is what `src/parse/scheme.rs`, `src/getset.rs` and `src/ffi.rs`
/// compare slice lengths against.
pub const MAX_SCHEME_LEN: usize = 40;

/// Scheme substituted when `CURLU_DEFAULT_SCHEME` is set and no scheme was
/// given.
///
/// `lib/urlapi.c`:L84. This `&str` form is canonical: it is what the code
/// copies onto the handle at L968 followed by L1004, and what any Rust
/// comparison or formatting should use. Use `DEFAULT_SCHEME_CSTR` only where
/// a C string is genuinely required.
pub const DEFAULT_SCHEME: &str = "https";

/// `DEFAULT_SCHEME` with a trailing NUL byte, for the one context that needs
/// a C string.
///
/// `lib/urlapi.c`:L1456 assigns `DEFAULT_SCHEME` to the same variable that
/// L1462 hands to `Curl_get_scheme`, whose parameter is `const char *`. In
/// the drop-in configuration that lookup really is the C function, so the
/// value has to be available NUL terminated without an allocation. Every
/// other consumer wants `DEFAULT_SCHEME`, which is the canonical spelling;
/// this one exists so that no caller has to build the terminated form by
/// hand and risk the two drifting apart.
///
/// A byte string rather than a `CStr` because the crate targets Rust 1.75
/// and C string literals, `c"https"`, arrived in 1.77. `as_ptr` on this
/// slice yields the required pointer with no conversion at all.
pub const DEFAULT_SCHEME_CSTR: &[u8] = b"https\0";

/// Ceiling on any string accepted by the URL API, in bytes.
///
/// `lib/urldata.h`:L131, whose comment at L129-L130 gives the reason: a
/// maximum input length is a precaution against abuse and makes junk input
/// easier and better to detect. Exceeding it yields `CURLUE_TOO_LARGE`.
///
/// Used as a length in every consumer, hence `usize`: the junk scan in
/// `src/parse/junk.rs`, the ceiling `curl_url_set` applies at
/// `lib/urlapi.c`:L1824, and the too-big limit of every dynamic buffer the
/// port creates.
pub const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

/// Scheme capability bit permitting an options part in the userinfo field of
/// the URL.
///
/// `lib/urldata.h`:L545. It is the only `PROTOPT_*` bit this module reads,
/// and the URL API consults it in two places, `lib/urlapi.c`:L290 when
/// deciding whether to split options out of the credentials and L1477 when
/// serialising them back.
///
/// The bit position is 10 and that is not an off-by-one. `lib/urldata.h`:L544
/// records that bit 9 is retired -- it was `PROTOPT_STREAM` and is now free
/// -- so the sequence of defined bits has a hole in it just below this one.
///
/// `u32` because the field it is tested against, `flags` of
/// `struct Curl_scheme` at `lib/urldata.h`:L522, is a `uint32_t`. That
/// matters in the drop-in configuration, where `src/scheme.rs` describes
/// that C structure in order to read the descriptor `Curl_get_scheme`
/// returns.
pub const PROTOPT_URLOPTIONS: u32 = 1 << 10;

#[cfg(test)]
mod tests {
    use super::*;

    /// The 33 result codes in header declaration order, checked against the
    /// ordinals written out longhand.
    ///
    /// The array types pin the counts at compile time, and the second array
    /// deliberately spells the values a different way from the definitions so
    /// that a copied mistake has to be made twice to survive.
    #[test]
    fn error_codes_are_contiguous_from_zero() {
        const CODES: [CURLUcode; 33] = [
            CURLUE_OK,
            CURLUE_BAD_HANDLE,
            CURLUE_BAD_PARTPOINTER,
            CURLUE_MALFORMED_INPUT,
            CURLUE_BAD_PORT_NUMBER,
            CURLUE_UNSUPPORTED_SCHEME,
            CURLUE_URLDECODE,
            CURLUE_OUT_OF_MEMORY,
            CURLUE_USER_NOT_ALLOWED,
            CURLUE_UNKNOWN_PART,
            CURLUE_NO_SCHEME,
            CURLUE_NO_USER,
            CURLUE_NO_PASSWORD,
            CURLUE_NO_OPTIONS,
            CURLUE_NO_HOST,
            CURLUE_NO_PORT,
            CURLUE_NO_QUERY,
            CURLUE_NO_FRAGMENT,
            CURLUE_NO_ZONEID,
            CURLUE_BAD_FILE_URL,
            CURLUE_BAD_FRAGMENT,
            CURLUE_BAD_HOSTNAME,
            CURLUE_BAD_IPV6,
            CURLUE_BAD_LOGIN,
            CURLUE_BAD_PASSWORD,
            CURLUE_BAD_PATH,
            CURLUE_BAD_QUERY,
            CURLUE_BAD_SCHEME,
            CURLUE_BAD_SLASHES,
            CURLUE_BAD_USER,
            CURLUE_LACKS_IDN,
            CURLUE_TOO_LARGE,
            CURLUE_LAST,
        ];
        const ORDINALS: [CURLUcode; 33] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];

        assert_eq!(CODES, ORDINALS, "CURLUcode ordinals or ordering drifted");
    }

    /// The 11 part identifiers in header declaration order.
    #[test]
    fn part_identifiers_are_contiguous_from_zero() {
        const PARTS: [CURLUPart; 11] = [
            CURLUPART_URL,
            CURLUPART_SCHEME,
            CURLUPART_USER,
            CURLUPART_PASSWORD,
            CURLUPART_OPTIONS,
            CURLUPART_HOST,
            CURLUPART_PORT,
            CURLUPART_PATH,
            CURLUPART_QUERY,
            CURLUPART_FRAGMENT,
            CURLUPART_ZONEID,
        ];
        const ORDINALS: [CURLUPart; 11] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        assert_eq!(PARTS, ORDINALS, "CURLUPart ordinals or ordering drifted");
    }

    /// The 16 flag bits, cross-checked against hexadecimal masks rather than
    /// against the shifts used to define them.
    #[test]
    fn flag_bits_cover_the_low_sixteen_bits() {
        const FLAGS: [::core::ffi::c_uint; 16] = [
            CURLU_DEFAULT_PORT,
            CURLU_NO_DEFAULT_PORT,
            CURLU_DEFAULT_SCHEME,
            CURLU_NON_SUPPORT_SCHEME,
            CURLU_PATH_AS_IS,
            CURLU_DISALLOW_USER,
            CURLU_URLDECODE,
            CURLU_URLENCODE,
            CURLU_APPENDQUERY,
            CURLU_GUESS_SCHEME,
            CURLU_NO_AUTHORITY,
            CURLU_ALLOW_SPACE,
            CURLU_PUNYCODE,
            CURLU_PUNY2IDN,
            CURLU_GET_EMPTY,
            CURLU_NO_GUESS_SCHEME,
        ];
        const MASKS: [::core::ffi::c_uint; 16] = [
            0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080, 0x0100, 0x0200, 0x0400,
            0x0800, 0x1000, 0x2000, 0x4000, 0x8000,
        ];

        assert_eq!(FLAGS, MASKS, "CURLU_* bit positions or ordering drifted");

        // Each flag is exactly one bit, and together they fill bits 0 to 15.
        // Those two facts together prove the sixteen are distinct, which is
        // the property callers rely on when they combine them.
        for flag in FLAGS {
            assert_eq!(flag.count_ones(), 1, "flag {flag:#06x} is not one bit");
        }
        let covered = FLAGS.iter().copied().fold(0, |acc, flag| acc | flag);
        assert_eq!(covered, 0xffff, "the sixteen flags are not distinct");
    }

    /// The spot checks the file's own instructions call for, kept separate so
    /// a failure names the individual constant rather than a whole array.
    #[test]
    fn representative_values_match_the_header() {
        assert_eq!(CURLUE_OK, 0);
        assert_eq!(CURLUE_TOO_LARGE, 31);
        assert_eq!(CURLUE_LAST, 32);
        assert_eq!(CURLUPART_URL, 0);
        assert_eq!(CURLUPART_ZONEID, 10);
        assert_eq!(CURLU_DEFAULT_PORT, 1);
        assert_eq!(CURLU_NO_GUESS_SCHEME, 0x8000);
    }

    /// Both aliases must stay signed, because the C compatible type of the
    /// two enumerations is `int` and the sign travels through the exported
    /// function signatures.
    #[test]
    fn aliases_are_signed_c_integers() {
        assert_eq!(CURLUcode::MIN.signum(), -1, "CURLUcode must be signed");
        assert_eq!(CURLUPart::MIN.signum(), -1, "CURLUPart must be signed");
    }

    /// The four supporting constants, plus the invariant that ties
    /// `DEFAULT_SCHEME_CSTR` to `DEFAULT_SCHEME` so the two cannot diverge.
    #[test]
    fn supporting_constants_match_their_c_sources() {
        assert_eq!(MAX_SCHEME_LEN, 40, "lib/urlapi.c:L55");
        assert_eq!(DEFAULT_SCHEME, "https", "lib/urlapi.c:L84");
        assert_eq!(CURL_MAX_INPUT_LENGTH, 8_000_000, "lib/urldata.h:L131");
        assert_eq!(PROTOPT_URLOPTIONS, 0x0400, "lib/urldata.h:L545");

        // The terminated spelling must be the canonical one plus a NUL and
        // nothing else, so the two cannot drift apart.
        assert_eq!(
            DEFAULT_SCHEME_CSTR.strip_suffix(b"\0"),
            Some(DEFAULT_SCHEME.as_bytes()),
            "DEFAULT_SCHEME_CSTR must be DEFAULT_SCHEME plus one NUL byte"
        );
    }
}
