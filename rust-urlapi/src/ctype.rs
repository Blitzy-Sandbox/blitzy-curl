// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! ASCII classification, hexadecimal conversion and case folding.
//!
//! `lib/urlapi.c` defines none of these helpers. It borrows all of them from
//! sibling translation units, and an object file that stands in for
//! `lib/urlapi.o` cannot borrow them back, so this module re-implements
//! every one. The correspondence, C name first:
//!
//! - `ISDIGIT`, `ISUPPER`, `ISLOWER`, `ISALPHA`, `ISALNUM`, `ISXDIGIT`,
//!   `ISODIGIT` and `ISUNRESERVED` from `lib/curl_ctype.h` L38-L49 become
//!   `is_digit`, `is_upper`, `is_lower`, `is_alpha`, `is_alnum`,
//!   `is_xdigit`, `is_odigit` and `is_unreserved`.
//! - `ISURLPUNTCS` at `lib/curl_ctype.h` L47-L48 becomes `is_url_punct`.
//!   The C macro name carries a misspelling. It is quoted here once, for
//!   traceability, and deliberately not carried into an identifier, because
//!   the repository spell-checks every tracked file and this one is tracked.
//! - `Curl_hexbyte` at `lib/escape.c` L222 becomes `hexbyte`, with the
//!   `Curl_udigits` table from `lib/mprintf.c` L39 folded into it.
//! - `curlx_hexval` at `lib/curlx/strparse.h` L111, together with the
//!   `curlx_hexasciitable` it indexes at `lib/curlx/strparse.c` L148,
//!   becomes `hexval`.
//! - `Curl_raw_tolower` at `lib/strcase.c` L81 becomes `raw_tolower`, and
//!   `Curl_strntolower` at L106 becomes `strntolower`.
//! - `curl_strequal` at `lib/strequal.c` L76 becomes `eq_ignore_case`, and
//!   `checkprefix` at `lib/strcase.h` L33 becomes
//!   `starts_with_ignore_case`.
//!
//! `Curl_raw_toupper` at `lib/strcase.c` L74 and `Curl_strntoupper` at L91
//! are deliberately absent: `lib/urlapi.c` calls neither, and a port of
//! them would be dead code, which is a warning, and the crate is built
//! warning-free.
//!
//! Nothing here depends on another module of this crate, which is what puts
//! this module at the bottom of the crate's module graph, and nothing here
//! is `unsafe`: every function is a pure operation over `u8` or over byte
//! slices.
//!
//! # Locale independence is the whole point
//!
//! curl reimplements these predicates rather than calling `<ctype.h>`
//! because the C library's versions are locale-dependent, and the comments
//! at `lib/strcase.c` L72-L73 and L79-L80 say so outright. curl's macros
//! are plain ASCII range comparisons with no locale input at all, which is
//! the correct reading, because URL syntax is defined in terms of ASCII.
//!
//! The port keeps that property by keeping the mechanism: every predicate
//! below is a range comparison written out literally, over `u8` and never
//! over `char`. Rust's `char` methods are Unicode-aware and would accept
//! characters curl rejects. Even the ASCII-restricted conveniences on `u8`
//! are avoided in the bodies, because matching curl's accepted set by luck
//! on ordinary input and diverging on one boundary byte is precisely the
//! failure this port cannot afford. Where a standard-library method does
//! agree, the agreement is recorded in a comment and pinned by a test
//! rather than relied upon.
//!
//! # The asymmetry to preserve, not fix
//!
//! Percent escapes that curl *emits* are uppercase, because `Curl_hexbyte`
//! indexes `Curl_udigits`, which is `"0123456789ABCDEF"`. Percent escapes
//! *already present* in a value handed to `curl_url_set()` are lower-cased
//! in place instead, by the pass at `lib/urlapi.c` L1922-L1932, which runs
//! only when the caller did not ask for encoding. So setting a path to
//! `a<b` with `CURLU_URLENCODE` stores `a%3Cb`, while setting it to `a%3Cb`
//! with no flags stores `a%3cb`.
//!
//! That looks like an inconsistency, and it is not a bug to be corrected
//! here: transformation rule T6, faithful over correct, governs. Both
//! behaviors are reachable through the public API, both are asserted by
//! `tests/libtest/lib1560.c`, and "fixing" either one fails the parity
//! diff. This module therefore emits uppercase unconditionally and supplies
//! `raw_tolower` for the other side of the asymmetry to use.

/// `ISDIGIT` at `lib/curl_ctype.h` L44: `'0'` through `'9'`.
///
/// Called from `lib/urlapi.c` L1670, where the port setter rejects a value
/// whose first byte is not a decimal digit.
// This and the two predicates after it carry a targeted allow for
// clippy::manual_is_ascii_check, which would rewrite each as the matching
// u8::is_ascii_* method. That suggestion is behaviorally correct, and it is
// not taken. Those methods are documented as exactly these ranges, and the
// test module pins the agreement over all 256 byte values, so nothing is
// being worked around; what is being kept is the bound itself. This module
// exists to reproduce a set of C macros, and a reviewer diffing it against
// lib/curl_ctype.h has to read the same two literals the macro states, at
// the same place, in order to confirm the port. Replacing the range with a
// method name hides the one detail most worth checking and turns an
// off-by-one from a visible edit into an invisible one. The allow is placed
// per function rather than at module scope so that any future range check
// has to argue its own case instead of inheriting this one.
#[allow(clippy::manual_is_ascii_check)]
pub(crate) const fn is_digit(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9')
}

/// `ISUPPER` at `lib/curl_ctype.h` L42: `'A'` through `'Z'`.
///
/// Called from `lib/urlapi.c` L1925, where an existing percent escape is
/// lower-cased only if at least one of its two digits is upper case.
// Allowed for the reason given above `is_digit`.
#[allow(clippy::manual_is_ascii_check)]
pub(crate) const fn is_upper(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z')
}

/// `ISLOWER` at `lib/curl_ctype.h` L43: `'a'` through `'z'`.
// Allowed for the reason given above `is_digit`.
#[allow(clippy::manual_is_ascii_check)]
pub(crate) const fn is_lower(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z')
}

/// `ISALPHA` at `lib/curl_ctype.h` L38, defined there as
/// `ISLOWER(x) || ISUPPER(x)`.
///
/// Reproduced as that same disjunction rather than merged into one range,
/// both because the two halves are not contiguous and because keeping the
/// shape of the macro keeps the port auditable against it.
///
/// Called from `lib/urlapi.c` L194, the first byte of a scheme in
/// `Curl_is_absolute_url`, and L1650, the same test in the scheme setter.
/// RFC 3986 3.1 requires a scheme to start with a letter, which is why a
/// digit does not qualify.
pub(crate) const fn is_alpha(byte: u8) -> bool {
    is_lower(byte) || is_upper(byte)
}

/// `ISALNUM` at `lib/curl_ctype.h` L41, defined there as
/// `ISDIGIT(x) || ISLOWER(x) || ISUPPER(x)`.
///
/// Called from `lib/urlapi.c` L197 and L1653, the second and later bytes of
/// a scheme, where the macro is combined with an explicit allowance for
/// `+`, `-` and `.` to form RFC 3986 3.1's scheme production.
pub(crate) const fn is_alnum(byte: u8) -> bool {
    is_digit(byte) || is_lower(byte) || is_upper(byte)
}

/// `ISXDIGIT` at `lib/curl_ctype.h` L39, defined there as
/// `ISDIGIT(x) || ISLOWHEXALHA(x) || ISUPHEXALHA(x)`, whose two helper
/// macros at L27 and L28 are `'a'`-`'f'` and `'A'`-`'F'`.
///
/// Both letter cases are accepted. A port that took only one would reject
/// half of all valid percent escapes, and mixed-case escapes such as `%aB`
/// appear in real input.
///
/// Called from `lib/escape.c` L127, guarding the two digits of an escape
/// before `Curl_urldecode` converts them, and from `lib/urlapi.c` L1924,
/// guarding the lower-casing pass.
pub(crate) const fn is_xdigit(byte: u8) -> bool {
    is_digit(byte) || matches!(byte, b'a'..=b'f' | b'A'..=b'F')
}

/// `ISODIGIT` at `lib/curl_ctype.h` L40: `'0'` through `'7'`.
///
/// The C tree defines this macro and, as of this port, calls it nowhere:
/// the octal scanner reached through `curlx_str_octal` at
/// `lib/curlx/strparse.c` L209 tests its digits with the local
/// `valid_digit` at L142-L143 instead, bounded by `'7'`. The predicate is
/// provided here because `strparse.rs` needs exactly that bound for the
/// octal scanner, and having one named home for it keeps the range from
/// being written out a second time.
pub(crate) const fn is_odigit(byte: u8) -> bool {
    matches!(byte, b'0'..=b'7')
}

/// The URL punctuation set: exactly `-`, `.`, `_` and `~`.
///
/// `ISURLPUNTCS` at `lib/curl_ctype.h` L47-L48. These four are the
/// non-alphanumeric characters RFC 3986 2.3 calls unreserved, so they are
/// never percent-encoded and never need to be.
pub(crate) const fn is_url_punct(byte: u8) -> bool {
    matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// `ISUNRESERVED` at `lib/curl_ctype.h` L49, defined there as
/// `ISALNUM(x) || ISURLPUNTCS(x)`: 66 bytes in total, 62 alphanumeric plus
/// the four punctuation characters.
///
/// This is the most behaviorally load-bearing predicate in the crate. It is
/// the preserved set for the assignment-side percent-encoder at
/// `lib/urlapi.c` L1897 and for `curl_easy_escape` at `lib/escape.c` L72,
/// so its accepted set decides the output of the port for essentially every
/// encoded input, and an off-by-one at either end of either range would
/// change one character's encoding everywhere at once.
///
/// Two exclusions are worth naming because they surprise readers. `+` is
/// not unreserved; the path mode adds it separately through
/// `allowed_in_path` at `lib/urlapi.c` L1779-L1803, and the query mode
/// substitutes it for a space instead. `%` is not unreserved either, which
/// is why handing an already-encoded value to the encoder encodes it a
/// second time.
pub(crate) const fn is_unreserved(byte: u8) -> bool {
    is_alnum(byte) || is_url_punct(byte)
}

/// One nibble as an uppercase ASCII hexadecimal digit.
///
/// `Curl_hexbyte` at `lib/escape.c` L225-L226 indexes `Curl_udigits`, the
/// table at `lib/mprintf.c` L39, which is `"0123456789ABCDEF"`. That table
/// is expressed here as arithmetic over its two runs rather than as an
/// indexed lookup, because the crate root denies direct indexing and the
/// alternatives, `get` plus `unwrap`, are denied too.
///
/// The wrapping operators are not papering over a possible overflow. They
/// are chosen so that no expression in this module can panic, and both are
/// exact for every input that can reach them: the mask restricts the value
/// to `0..=15`, `b'0'` plus `9` is `b'9'`, and `b'A'` plus `5` is `b'F'`.
const fn upper_hex_digit(nibble: u8) -> u8 {
    match nibble & 0x0f {
        // 0x30..=0x39, that is '0' through '9'.
        digit @ 0..=9 => b'0'.wrapping_add(digit),
        // 0x41..=0x46, that is 'A' through 'F'. The mask above rules out
        // everything above 15, so this arm sees only 10..=15.
        letter => b'A'.wrapping_add(letter.wrapping_sub(10)),
    }
}

/// Format one byte as two uppercase ASCII hexadecimal digits, most
/// significant digit first.
///
/// `Curl_hexbyte` at `lib/escape.c` L222-L227. The C function writes through
/// a `dest` pointer that the caller promises has room for two bytes, and its
/// three call sites in the ported code all build a three-byte `{ '%' }`
/// array and hand it the second element: `lib/urlapi.c` L159 in the
/// retrieval-side encoder, L1909 in the assignment-side encoder, and
/// `lib/escape.c` L80 in `curl_easy_escape`.
///
/// Returning the pair by value instead keeps the port free of `unsafe` and
/// of the direct indexing the crate root denies, and it puts the two-byte
/// width in the type where a reviewer cannot miss it.
///
/// Uppercase is not a preference here, it is the observable behavior, and
/// the module documentation explains the asymmetry it creates. Do not
/// "align" this with `Curl_hexencode` at `lib/escape.c` L200, which formats
/// lowercase out of `Curl_ldigits` at `lib/mprintf.c` L36; that function
/// serves DNS-over-HTTPS names and random hexadecimal strings, and no part
/// of the URL API uses it.
pub(crate) const fn hexbyte(val: u8) -> [u8; 2] {
    [
        // val >> 4 and val & 0x0F at lib/escape.c L225-L226. The shift is
        // written as a method call so that no arithmetic operator appears.
        upper_hex_digit(val.wrapping_shr(4)),
        upper_hex_digit(val & 0x0f),
    ]
}

/// The binary value of one ASCII hexadecimal digit, or `None` for any byte
/// that is not one.
///
/// `curlx_hexval` at `lib/curlx/strparse.h` L111 indexes
/// `curlx_hexasciitable`, the table at `lib/curlx/strparse.c` L148, with
/// `x - '0'` and masks the result with `0x0f`. Two properties of that table
/// matter to the port. It spans `'0'` (0x30) through `'f'` (0x66) only, so
/// any other byte indexes outside it, which is why the comment above the
/// macro says it works on valid hexadecimal input and the caller must check
/// first. And the entry for `'0'` is 16 rather than 0, which looks like an
/// error and is not: `valid_digit` at `lib/curlx/strparse.c` L142-L143
/// accepts a character by testing that its entry is non-zero, so `'0'`
/// needs a non-zero entry, and the `& 0x0f` in the macro turns it back into
/// 0 for the value.
///
/// Every C call site does gate first, so out-of-range input is undefined
/// behavior there rather than a defined result: `Curl_urldecode` tests
/// `ISXDIGIT` at `lib/escape.c` L127 before converting at L129-L130,
/// `curlx_inet_pton` tests it at `lib/curlx/inet_pton.c` L133 before
/// converting at L135, and `str_num_base` goes through `valid_digit` at
/// `lib/curlx/strparse.c` L174 and L182.
///
/// This port returns `Option` so that the undefined case becomes a value
/// the caller has to handle, which is what keeps `decode.rs` free of the
/// unchecked arithmetic and of the sentinel comparisons the crate root
/// denies. The accepted set is exactly `is_xdigit`, which a test pins for
/// all 256 byte values.
pub(crate) const fn hexval(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        // 'A' is 10, per curlx_hexasciitable's 0x41 row.
        b'A'..=b'F' => Some(byte.wrapping_sub(b'A').wrapping_add(10)),
        // 'a' is 10 as well, per its 0x61 row.
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// ASCII lower-case fold, locale-independent.
///
/// `Curl_raw_tolower` at `lib/strcase.c` L81-L84 is a lookup into
/// `tolowermap`, the 256-entry table at L52, which maps `'A'`-`'Z'`
/// (0x41-0x5A) onto `'a'`-`'z'` (0x61-0x7A) and is the identity everywhere
/// else, high-bit bytes included. The comment above it at L79-L80 gives the
/// reason for the table: `tolower()` is altered by the current locale.
///
/// The table is expressed here as the range test it encodes. Setting bit 5
/// is exact on that range and only on that range, and it cannot overflow,
/// so no arithmetic operator appears. `u8::to_ascii_lowercase` computes the
/// same function; the fold is written out anyway, so that the one used by
/// the comparison helpers below is visibly the one used by the port's
/// lower-casing pass, and a test pins the agreement for all 256 values.
///
/// Called from `lib/urlapi.c` L1926-L1927, on the two digits of an existing
/// percent escape, and from inside `strntolower`.
pub(crate) const fn raw_tolower(byte: u8) -> u8 {
    match byte {
        // 0x41..=0x5A with bit 5 set is 0x61..=0x7A.
        b'A'..=b'Z' => byte | 0x20,
        _ => byte,
    }
}

/// Copy a lower-cased `src` into `dest`, at most `n` bytes, with the C
/// function's surprising semantics intact. Returns the number of bytes
/// written.
///
/// `Curl_strntolower` at `lib/strcase.c` L106-L114 has a six-line body, and
/// three of its properties are unusual enough that the comment above it at
/// L101-L105 spells two of them out:
///
/// 1. `n < 1` returns immediately, writing nothing at all.
/// 2. At most `n` bytes are copied *including any NUL*, so the destination
///    is **not** null-terminated when the limit is reached. That is the
///    behavior a naive port loses, and losing it is invisible to any test
///    that only reads back a short scheme into a zeroed buffer.
/// 3. Source and destination may overlap; the loop walks forward one byte
///    at a time.
///
/// The one caller in this port is `Curl_is_absolute_url` at
/// `lib/urlapi.c` L214, and the very next line, `buf[i] = 0` at L215,
/// writes the terminator itself precisely because this function may not
/// have. So do not assume a terminator on return: use the returned count.
///
/// Three narrowings of the C contract, documented rather than hidden:
///
/// - `src` holds the string's bytes *without* a terminator, which is the
///   Rust convention. A position at or past `src.len()` therefore plays the
///   part of the C string's NUL: reaching it copies one zero byte and
///   stops, exactly as the C loop's `while(*src++ ...)` test does. So
///   `strntolower(d, b"ab", 8)` writes three bytes, `b'a'`, `b'b'` and `0`,
///   and returns 3, which is what the C writes for `"ab"`.
/// - `dest.len()` caps the copy as well as `n` does. C would run off the
///   end of a short destination; this cannot, and the return value reports
///   what was actually written. The port's own call site sizes its buffer
///   from the maximum scheme length, so `n` is always the binding limit
///   there and the cap never changes an outcome.
/// - The overlap allowance cannot be expressed at all, because `&mut [u8]`
///   and `&[u8]` may not alias. The port's call site copies out of the URL
///   into a separate scheme buffer, so nothing overlapped in the first
///   place. A future caller that wants an in-place fold should map
///   `raw_tolower` over the slice instead of reaching for this function.
pub(crate) fn strntolower(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    // Forces the module's compile-time boundary check to be evaluated in
    // every build; see BOUNDARY_PROOF for why it needs a live referent. This
    // binding emits no code.
    let () = BOUNDARY_PROOF;
    // The `if(n < 1) return;` at lib/strcase.c L108-L109. `n` is unsigned
    // there as it is here, so "less than one" means exactly zero.
    if n == 0 {
        return 0;
    }
    let mut written = 0usize;
    // Chaining an endless run of zeroes onto `src` stands in for the C
    // string's NUL, and the `break` below is the loop's `while(*src++ ...)`
    // test: the terminator is copied first and ends the loop after itself.
    let terminated = src.iter().copied().chain(core::iter::repeat(0));
    for (slot, byte) in dest.iter_mut().zip(terminated).take(n) {
        *slot = raw_tolower(byte);
        // Saturating rather than `+= 1` because the crate root denies
        // unchecked arithmetic. The count cannot reach the saturation point
        // in any case: it is bounded by `n` and by `dest.len()`.
        written = written.saturating_add(1);
        if byte == 0 {
            break;
        }
    }
    written
}

/// Case-insensitive ASCII equality, with `curl_strequal` semantics.
///
/// `curl_strequal` at `lib/strequal.c` L76-L84 delegates to `casecompare`
/// at L36-L50, which folds both sides and compares byte by byte, then
/// confirms that both strings ended together. Its null-pointer arms, where
/// two nulls compare equal and one null does not, do not survive the move
/// to slices: absence is an `Option<&[u8]>` at the call site here, not a
/// null byte pointer, so the caller decides what absence means.
///
/// The fold used is `raw_tolower`, where the C folds with
/// `Curl_raw_toupper`. That is the same relation, not an approximation of
/// it: on ASCII, `tolower(a) == tolower(b)` holds exactly when
/// `toupper(a) == toupper(b)`, because each map is the identity outside the
/// letters and pairs `c` with `c | 0x20` inside them. Using the module's one
/// fold keeps a single definition of "the same letter", and a test pins the
/// two boundary pairs that a sloppier fold would conflate, `[` with `{` and
/// `@` with a backquote.
///
/// `<[u8]>::eq_ignore_ascii_case` computes the same predicate and is not
/// called, for the reason given in the module documentation.
///
/// Used for the scheme comparisons in `getset.rs`, among them the `"file"`
/// test at `lib/urlapi.c` L1440, and for scheme-name lookup in `scheme.rs`.
pub(crate) fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| raw_tolower(*x) == raw_tolower(*y))
}

/// Case-insensitive ASCII prefix test, with `checkprefix` semantics.
///
/// `checkprefix(a, b)` at `lib/strcase.h` L33 expands to
/// `curl_strnequal(b, a, strlen(a))`, so the literal is the prefix and the
/// other argument is the candidate being tested. Note the swap: the
/// parameters here are in the order the reader expects, candidate first.
///
/// `curl_strnequal` at `lib/strequal.c` L87-L94 delegates to `ncasecompare`
/// at L52-L64, whose two exits are worth reproducing exactly. It stops
/// early on the candidate's NUL and then folds and compares one further
/// byte, so a candidate shorter than the prefix ends up comparing its
/// terminator against a non-zero prefix byte and fails; that is the length
/// guard below. And when the whole prefix has been consumed it returns true
/// without looking at the candidate's next byte, so a prefix of length zero
/// matches everything, this port included.
///
/// Used at `lib/urlapi.c` L874-L875, the `"localhost/"` and `"127.0.0.1/"`
/// tests that decide whether a file URL's authority is acceptable, and at
/// L989-L999, the six-entry hostname-prefix table that guesses a scheme.
pub(crate) fn starts_with_ignore_case(candidate: &[u8], prefix: &[u8]) -> bool {
    // `zip` stops at the shorter side, so the guard is what makes the pairs
    // below span the whole prefix rather than only its start.
    prefix.len() <= candidate.len()
        && candidate
            .iter()
            .zip(prefix.iter())
            .all(|(x, y)| raw_tolower(*x) == raw_tolower(*y))
}

/// The letter and digit range boundaries, against `lib/curl_ctype.h`.
///
/// The bytes just outside a range matter as much as the ones just inside, so
/// both ends of every range are tested. Where the neighbor is not a
/// printable character worth naming it is written as a numeric literal:
/// 0x2f and 0x3a flank the digits, 0x40 and 0x5b flank the upper-case
/// letters, and 0x60 and 0x7b flank the lower-case ones.
const fn letter_boundaries_hold() -> bool {
    // ISDIGIT, lib/curl_ctype.h L44.
    let digit = !is_digit(0x2f) && is_digit(b'0') && is_digit(b'9') && !is_digit(0x3a);
    // ISUPPER at L42 and ISLOWER at L43.
    let upper = !is_upper(0x40) && is_upper(b'A') && is_upper(b'Z') && !is_upper(0x5b);
    let lower = !is_lower(0x60) && is_lower(b'a') && is_lower(b'z') && !is_lower(0x7b);
    // ISALPHA at L38 and ISALNUM at L41. The two letter runs are not
    // contiguous, so the bytes between them are checked explicitly.
    let alpha =
        is_alpha(b'A') && is_alpha(b'z') && !is_alpha(b'0') && !is_alpha(0x5b) && !is_alpha(0x60);
    let alnum =
        is_alnum(b'0') && is_alnum(b'Z') && is_alnum(b'a') && !is_alnum(b'_') && !is_alnum(0x40);
    digit && upper && lower && alpha && alnum
}

/// The hexadecimal and octal boundaries, and both directions of the
/// hexadecimal conversion.
const fn hex_boundaries_hold() -> bool {
    // ISXDIGIT at lib/curl_ctype.h L39, both letter cases, and ISODIGIT at
    // L40.
    let hexadecimal = is_xdigit(b'0')
        && is_xdigit(b'9')
        && is_xdigit(b'A')
        && is_xdigit(b'F')
        && is_xdigit(b'a')
        && is_xdigit(b'f')
        && !is_xdigit(b'G')
        && !is_xdigit(b'g')
        && !is_xdigit(0x40)
        && !is_xdigit(0x60);
    let octal = !is_odigit(0x2f) && is_odigit(b'0') && is_odigit(b'7') && !is_odigit(b'8');
    // Curl_hexbyte at lib/escape.c L222, uppercase out of Curl_udigits.
    // Destructured rather than indexed, which the crate root denies.
    let [zero_hi, zero_lo] = hexbyte(0x00);
    let [nibble_hi, nibble_lo] = hexbyte(0x0f);
    let [mixed_hi, mixed_lo] = hexbyte(0xa5);
    let [full_hi, full_lo] = hexbyte(0xff);
    let emitted = zero_hi == b'0'
        && zero_lo == b'0'
        && nibble_hi == b'0'
        && nibble_lo == b'F'
        && mixed_hi == b'A'
        && mixed_lo == b'5'
        && full_hi == b'F'
        && full_lo == b'F';
    // curlx_hexval at lib/curlx/strparse.h L111.
    let parsed = matches!(hexval(b'0'), Some(0))
        && matches!(hexval(b'9'), Some(9))
        && matches!(hexval(b'A'), Some(10))
        && matches!(hexval(b'F'), Some(15))
        && matches!(hexval(b'a'), Some(10))
        && matches!(hexval(b'f'), Some(15))
        && hexval(b'G').is_none()
        && hexval(b'g').is_none()
        && hexval(b'/').is_none()
        && hexval(0x00).is_none();
    hexadecimal && octal && emitted && parsed
}

/// The unreserved set and the case fold, including the high-bit bytes that a
/// locale-dependent implementation would get wrong.
const fn unreserved_boundaries_hold() -> bool {
    // The URL punctuation set at lib/curl_ctype.h L47-L48. The rejected
    // characters are chosen for being adjacent in ASCII or easy to confuse
    // with the accepted ones.
    let punct = is_url_punct(b'-')
        && is_url_punct(b'.')
        && is_url_punct(b'_')
        && is_url_punct(b'~')
        && !is_url_punct(b',')
        && !is_url_punct(b'/')
        && !is_url_punct(b'+')
        && !is_url_punct(b'%');
    // ISUNRESERVED at L49.
    let unreserved = is_unreserved(b'0')
        && is_unreserved(b'Z')
        && is_unreserved(b'a')
        && is_unreserved(b'~')
        && !is_unreserved(b' ')
        && !is_unreserved(b'%')
        && !is_unreserved(b'+')
        && !is_unreserved(0x00)
        && !is_unreserved(0x80)
        && !is_unreserved(0xff);
    // Curl_raw_tolower at lib/strcase.c L81, against tolowermap at L52. The
    // 0x80 and 0xff entries are the locale-independence check: a
    // Latin-1-aware fold would move them.
    let fold = raw_tolower(b'A') == b'a'
        && raw_tolower(b'Z') == b'z'
        && raw_tolower(b'a') == b'a'
        && raw_tolower(0x40) == 0x40
        && raw_tolower(0x5b) == 0x5b
        && raw_tolower(0x00) == 0x00
        && raw_tolower(0x80) == 0x80
        && raw_tolower(0xff) == 0xff;
    punct && unreserved && fold
}

/// Every range boundary in this module, checked against the C macros.
///
/// An off-by-one at one of these boundaries would change the encoding of a
/// single character and nothing else, which is the class of defect a
/// behavioral diff finds late, in an unrelated assertion, or not at all.
/// Evaluating the check in a `const` context turns it into a compile error
/// instead.
///
/// The exhaustive comparison over all 256 byte values lives in the test
/// module below. This is the subset that cannot be skipped by not running
/// tests.
const fn boundaries_hold() -> bool {
    letter_boundaries_hold() && hex_boundaries_hold() && unreserved_boundaries_hold()
}

/// Compile-time proof that this module still agrees with the C it ports.
///
/// Evaluating `boundaries_hold` in a `const` initializer is what turns a
/// boundary regression into a compile error instead of a test failure.
///
/// The initializer has to be *forced*, which is why this constant is named
/// and referenced from `strntolower` rather than written as the more usual
/// anonymous `const _: () = assert!(..)`. A `const` item's body is only
/// evaluated when the item is reachable, and reachability is exactly what
/// differs across the toolchains this crate supports: on current stable an
/// anonymous `const _` is a root, so everything it calls counts as used,
/// while on 1.75, the declared minimum, it is not, so every function behind
/// it draws a dead-code warning. Both toolchains agree once a live function
/// names the constant, and `strntolower` is live in any build that links the
/// facade, because `Curl_is_absolute_url` calls it. Binding a unit constant
/// emits no code, so the check costs nothing at run time.
const BOUNDARY_PROOF: () = assert!(
    boundaries_hold(),
    "src/ctype.rs diverges from lib/curl_ctype.h, lib/escape.c or \
     lib/strcase.c"
);

#[cfg(test)]
mod tests {
    use super::{
        eq_ignore_case, hexbyte, hexval, is_alnum, is_alpha, is_digit, is_lower, is_odigit,
        is_unreserved, is_upper, is_url_punct, is_xdigit, raw_tolower, starts_with_ignore_case,
        strntolower,
    };

    // The accepted sets, written out as literal enumerations rather than as
    // range comparisons. That is the point: an expectation built from the
    // same range expression as the implementation would reproduce an
    // off-by-one on both sides and prove nothing, so the expectations here
    // are derived independently, by membership in an explicit list.
    const DIGITS: &[u8] = b"0123456789";
    const OCTAL_DIGITS: &[u8] = b"01234567";
    const UPPERS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const HEX_DIGITS: &[u8] = b"0123456789ABCDEFabcdef";
    const URL_PUNCT: &[u8] = b"-._~";

    /// The lower-case fold, derived from the two letter lists by position
    /// instead of from a range test, and without indexing.
    fn expected_tolower(byte: u8) -> u8 {
        for (upper, lower) in UPPERS.iter().zip(LOWERS.iter()) {
            if *upper == byte {
                return *lower;
            }
        }
        byte
    }

    #[test]
    fn predicates_match_the_c_macros_for_every_byte() {
        for byte in 0u8..=u8::MAX {
            let digit = DIGITS.contains(&byte);
            let upper = UPPERS.contains(&byte);
            let lower = LOWERS.contains(&byte);
            let punct = URL_PUNCT.contains(&byte);
            // ISDIGIT L44, ISUPPER L42, ISLOWER L43.
            assert_eq!(is_digit(byte), digit, "is_digit {byte:#04x}");
            assert_eq!(is_upper(byte), upper, "is_upper {byte:#04x}");
            assert_eq!(is_lower(byte), lower, "is_lower {byte:#04x}");
            // ISALPHA L38, ISALNUM L41.
            assert_eq!(is_alpha(byte), upper || lower, "is_alpha {byte:#04x}");
            assert_eq!(
                is_alnum(byte),
                digit || upper || lower,
                "is_alnum {byte:#04x}"
            );
            // ISXDIGIT L39, ISODIGIT L40.
            assert_eq!(
                is_xdigit(byte),
                HEX_DIGITS.contains(&byte),
                "is_xdigit {byte:#04x}"
            );
            assert_eq!(
                is_odigit(byte),
                OCTAL_DIGITS.contains(&byte),
                "is_odigit {byte:#04x}"
            );
            // The URL punctuation set L47-L48, ISUNRESERVED L49.
            assert_eq!(is_url_punct(byte), punct, "is_url_punct {byte:#04x}");
            assert_eq!(
                is_unreserved(byte),
                digit || upper || lower || punct,
                "is_unreserved {byte:#04x}"
            );
            // Curl_raw_tolower, lib/strcase.c L81.
            assert_eq!(
                raw_tolower(byte),
                expected_tolower(byte),
                "raw_tolower {byte:#04x}"
            );
        }
    }

    #[test]
    fn the_unreserved_set_is_sixty_six_bytes_wide() {
        // 62 alphanumeric plus the four punctuation characters. A count is a
        // cheap guard against a range that grew or shrank at one end without
        // anybody noticing which end.
        let accepted = (0u8..=u8::MAX).filter(|byte| is_unreserved(*byte));
        assert_eq!(accepted.count(), 66);
    }

    #[test]
    fn no_predicate_accepts_a_high_bit_byte() {
        // This is the locale-independence check. A C library's isalpha() may
        // accept 0xe4 under a Latin-1 locale and its tolower() may move it;
        // curl's table-driven and range-driven versions never do, and
        // neither does this port.
        for byte in 0x80u8..=u8::MAX {
            assert!(!is_digit(byte), "{byte:#04x}");
            assert!(!is_upper(byte), "{byte:#04x}");
            assert!(!is_lower(byte), "{byte:#04x}");
            assert!(!is_alpha(byte), "{byte:#04x}");
            assert!(!is_alnum(byte), "{byte:#04x}");
            assert!(!is_xdigit(byte), "{byte:#04x}");
            assert!(!is_odigit(byte), "{byte:#04x}");
            assert!(!is_url_punct(byte), "{byte:#04x}");
            assert!(!is_unreserved(byte), "{byte:#04x}");
            assert!(hexval(byte).is_none(), "{byte:#04x}");
            assert_eq!(raw_tolower(byte), byte, "{byte:#04x}");
        }
    }

    #[test]
    fn predicates_agree_with_the_standard_library() {
        // The evidence behind the targeted allow above is_digit. Rust
        // documents u8::is_ascii_digit and its neighbors as exactly the
        // ranges this module writes out, so the two must agree on all 256
        // values. Keeping the range in the source and the equivalence in a
        // test gives both properties at once: the bound stays visible for a
        // reviewer diffing against lib/curl_ctype.h, and the claim that the
        // standard library computes the same predicate is checked rather
        // than asserted. If a future release ever widened one of these
        // methods, this test would fail instead of the port drifting.
        for byte in 0u8..=u8::MAX {
            assert_eq!(is_digit(byte), byte.is_ascii_digit(), "{byte:#04x}");
            assert_eq!(is_upper(byte), byte.is_ascii_uppercase(), "{byte:#04x}");
            assert_eq!(is_lower(byte), byte.is_ascii_lowercase(), "{byte:#04x}");
            assert_eq!(is_alpha(byte), byte.is_ascii_alphabetic(), "{byte:#04x}");
            assert_eq!(is_alnum(byte), byte.is_ascii_alphanumeric(), "{byte:#04x}");
            assert_eq!(is_xdigit(byte), byte.is_ascii_hexdigit(), "{byte:#04x}");
        }
    }

    #[test]
    fn raw_tolower_agrees_with_the_standard_library() {
        // Pins the claim made at the definition site rather than trusting
        // it. u8::to_ascii_lowercase is itself an ASCII-only fold, so the
        // two must agree on all 256 values; if a future Rust release ever
        // widened it, this test would say so instead of the port silently
        // drifting.
        for byte in 0u8..=u8::MAX {
            assert_eq!(raw_tolower(byte), byte.to_ascii_lowercase(), "{byte}");
        }
    }

    #[test]
    fn hexbyte_emits_uppercase() {
        // The spread from the porting checklist, most significant digit
        // first.
        assert_eq!(hexbyte(0x00), [b'0', b'0']);
        assert_eq!(hexbyte(0x0f), [b'0', b'F']);
        assert_eq!(hexbyte(0x10), [b'1', b'0']);
        assert_eq!(hexbyte(0xa5), [b'A', b'5']);
        assert_eq!(hexbyte(0xff), [b'F', b'F']);
        for byte in 0u8..=u8::MAX {
            let [high, low] = hexbyte(byte);
            // Never a lower-case letter, for any input: that is the whole
            // content of the Curl_udigits versus Curl_ldigits distinction.
            assert!(!is_lower(high) && !is_lower(low), "{byte:#04x}");
            assert!(is_xdigit(high) && is_xdigit(low), "{byte:#04x}");
            // Independent oracle: the formatter's own uppercase conversion.
            let formatted = format!("{byte:02X}");
            assert_eq!(hexbyte(byte).as_slice(), formatted.as_bytes());
        }
    }

    #[test]
    fn hexval_round_trips_and_rejects_non_hex() {
        for byte in 0u8..=u8::MAX {
            // Accepted set is exactly ISXDIGIT, which is what every C call
            // site gates on before reaching curlx_hexval.
            assert_eq!(hexval(byte).is_some(), is_xdigit(byte), "{byte:#04x}");
            // Independent oracle for the value, not just the acceptance.
            assert_eq!(
                hexval(byte).map(u32::from),
                char::from(byte).to_digit(16),
                "{byte:#04x}"
            );
            // Round trip through hexbyte. The shift is a method call because
            // the crate root denies unchecked arithmetic.
            let [high, low] = hexbyte(byte);
            let rebuilt = hexval(high)
                .zip(hexval(low))
                .map(|(top, bottom)| top.wrapping_shl(4) | bottom);
            assert_eq!(rebuilt, Some(byte), "{byte:#04x}");
        }
        assert_eq!(hexval(b'0'), Some(0));
        assert_eq!(hexval(b'9'), Some(9));
        assert_eq!(hexval(b'A'), Some(10));
        assert_eq!(hexval(b'F'), Some(15));
        assert_eq!(hexval(b'a'), Some(10));
        assert_eq!(hexval(b'f'), Some(15));
        // The four bytes adjacent to the accepted runs, which an off-by-one
        // would let through: '/' 0x2f, ':' 0x3a, 'G' 0x47, 'g' 0x67.
        assert_eq!(hexval(b'/'), None);
        assert_eq!(hexval(b':'), None);
        assert_eq!(hexval(b'G'), None);
        assert_eq!(hexval(b'g'), None);
    }

    #[test]
    fn strntolower_writes_nothing_for_a_zero_limit() {
        // The `if(n < 1) return;` at lib/strcase.c L108-L109.
        let mut dest = [0xffu8; 4];
        assert_eq!(strntolower(&mut dest, b"AB", 0), 0);
        assert_eq!(dest, [0xff; 4]);
    }

    #[test]
    fn strntolower_folds_a_normal_case() {
        let mut dest = [0xffu8; 8];
        assert_eq!(strntolower(&mut dest, b"HtTp", 4), 4);
        // Four folded bytes and no terminator, because the limit was reached
        // exactly.
        assert_eq!(dest, [b'h', b't', b't', b'p', 0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn strntolower_omits_the_terminator_when_the_limit_is_reached() {
        // The behavior a naive port loses. The C copies at most n bytes
        // including any NUL, so when n bytes of content are copied there is
        // no room left for a terminator and none is written. Curl_is_absolute
        // _url at lib/urlapi.c L215 writes its own for exactly this reason.
        let mut dest = [0xffu8; 8];
        assert_eq!(strntolower(&mut dest, b"HTTPS", 5), 5);
        assert_eq!(dest, [b'h', b't', b't', b'p', b's', 0xff, 0xff, 0xff]);
    }

    #[test]
    fn strntolower_copies_the_terminator_when_it_fits() {
        // Mirrors the C for a source shorter than n: the loop copies the NUL
        // and then ends, so the count includes it.
        let mut dest = [0xffu8; 8];
        assert_eq!(strntolower(&mut dest, b"AB", 5), 3);
        assert_eq!(dest, [b'a', b'b', 0, 0xff, 0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn strntolower_is_capped_by_the_destination() {
        // The narrowing documented at the definition site: C would run past
        // the end of a short destination, this stops and reports what it
        // wrote.
        let mut dest = [0xffu8; 2];
        assert_eq!(strntolower(&mut dest, b"ABCDE", 5), 2);
        assert_eq!(dest, [b'a', b'b']);
    }

    #[test]
    fn strntolower_leaves_high_bit_bytes_alone() {
        let mut dest = [0xffu8; 4];
        assert_eq!(strntolower(&mut dest, &[b'A', 0xc3, 0x96, b'Z'], 4), 4);
        assert_eq!(dest, [b'a', 0xc3, 0x96, b'z']);
    }

    #[test]
    fn eq_ignore_case_folds_ascii_only() {
        assert!(eq_ignore_case(b"file", b"FILE"));
        assert!(eq_ignore_case(b"HtTpS", b"https"));
        assert!(eq_ignore_case(b"", b""));
        assert!(!eq_ignore_case(b"file", b"fil"));
        assert!(!eq_ignore_case(b"file", b"file "));
        assert!(!eq_ignore_case(b"file", b"gile"));
        assert!(!eq_ignore_case(b"", b"f"));
        // The two pairs a fold that used a bare bit-flip would conflate:
        // '[' 0x5b with '{' 0x7b, and '@' 0x40 with the backquote 0x60.
        assert!(!eq_ignore_case(b"[", b"{"));
        assert!(!eq_ignore_case(b"@", b"`"));
        // High-bit bytes are compared as they are, never folded, so the two
        // halves of an accented letter's UTF-8 encoding stay distinct.
        assert!(!eq_ignore_case(&[0xc3, 0x96], &[0xc3, 0xb6]));
        assert!(eq_ignore_case(&[0x80], &[0x80]));
    }

    #[test]
    fn eq_ignore_case_agrees_with_the_standard_library() {
        // Exhaustive over every ordered pair of bytes, which also proves the
        // claim at the definition site that folding down and folding up
        // decide equality identically on ASCII.
        for left in 0u8..=u8::MAX {
            for right in 0u8..=u8::MAX {
                let a = [left];
                let b = [right];
                assert_eq!(
                    eq_ignore_case(&a, &b),
                    a.eq_ignore_ascii_case(&b),
                    "{left:#04x} {right:#04x}"
                );
            }
        }
    }

    #[test]
    fn starts_with_ignore_case_matches_checkprefix() {
        // The scheme guess table at lib/urlapi.c L989-L999.
        assert!(starts_with_ignore_case(b"ftp.example.com", b"ftp."));
        assert!(starts_with_ignore_case(b"FTP.EXAMPLE.COM", b"ftp."));
        assert!(!starts_with_ignore_case(b"tftp.example.com", b"ftp."));
        // The file-URL authority tests at L874-L875.
        assert!(starts_with_ignore_case(b"localhost/path", b"localhost/"));
        assert!(starts_with_ignore_case(b"127.0.0.1/path", b"127.0.0.1/"));
        assert!(!starts_with_ignore_case(b"localhost", b"localhost/"));
        // A candidate shorter than the prefix fails: this is where
        // ncasecompare stops on the terminator and compares one more byte.
        assert!(!starts_with_ignore_case(b"ftp", b"ftp."));
        assert!(!starts_with_ignore_case(b"", b"a"));
        // A zero-length prefix matches everything, because ncasecompare
        // returns true as soon as max reaches zero.
        assert!(starts_with_ignore_case(b"anything", b""));
        assert!(starts_with_ignore_case(b"", b""));
        // An exact match is a prefix match.
        assert!(starts_with_ignore_case(b"IMAP.", b"imap."));
    }
}
