// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Scheme detection, scheme resolution and the legacy scheme guess.
//!
//! Three C functions live here, because all three answer the same question
//! -- which scheme, if any, does this input carry -- and they run one after
//! another in the parse pipeline:
//!
//! | C function | C location | This module |
//! |------------|------------|-------------|
//! | `Curl_is_absolute_url` | `lib/urlapi.c` L182-L220 | [`is_absolute_url`] |
//! | `parse_scheme` | `lib/urlapi.c` L935-L982 | [`parse_scheme`] |
//! | `guess_scheme` | `lib/urlapi.c` L984-L1010 | [`guess_scheme`] |
//!
//! The first is the only one of the three that is not `static` in the C. It
//! belongs to the eight-symbol drop-in set, declared at
//! `lib/urlapi-int.h` L28-L29, and its behavior is therefore ABI-fixed:
//! `src/ffi.rs` exports it under that name for `lib/http1.c` L220,
//! `lib/url.c` L1661 and `lib/http.c` L1177. The facade owns the
//! `*const c_char` to slice conversion, the `char *buf` to `Option` mapping
//! and the `DEBUGASSERT`; nothing here touches a raw pointer, so the whole
//! module is `#![forbid(unsafe_code)]` and unit-testable on its own.
//!
//! The two `static` functions have one caller each, `parseurl` at
//! `lib/urlapi.c` L1138 and L1152, which is `src/parse/mod.rs`.
//!
//! # Stage order, and why these three are one module
//!
//! `parseurl` at `lib/urlapi.c` L1128-L1152 runs them in a fixed order and
//! each one consumes what the one before it produced:
//!
//! 1. L1128-L1130 calls `Curl_is_absolute_url` with a 41-byte buffer and
//!    the guess mask, and keeps both results: the returned scheme length and
//!    the lower-cased scheme now sitting in that buffer.
//! 2. L1133 tests that buffer against the literal `"file"` with `strcmp`, an
//!    exact byte comparison. It works only because step 1 lower-cased, which
//!    is what makes `FILE://` reach the file-URL branch.
//! 3. L1138 hands both results to `parse_scheme`, which resolves the scheme,
//!    counts the slashes after the colon and reports where the host starts.
//! 4. L1143-L1152 parses the authority from there and, only if no scheme was
//!    stored, calls `guess_scheme` on the host it accumulated.
//!
//! Step 4 is why `guess_scheme` reads a host name rather than the input:
//! `tests/libtest/lib1560.c` L357-L360 parses
//! `ftp.user:moo@example.com/color/` with `CURLU_GUESS_SCHEME` and expects
//! `http`, because by the time the guess runs the credentials have been
//! split off and the host is plain `example.com`. The neighboring case at
//! L353-L356, `user:moo@ftp.example.com/color/`, expects `ftp` for the same
//! reason.
//!
//! # `Curl_is_absolute_url`, byte for byte
//!
//! Given the input, an optional scheme buffer and the guess flag, in the
//! order the C performs them:
//!
//! 1. L189 stores a terminator in the first byte of the buffer, when one was
//!    supplied. This happens **before** anything can return, so the buffer
//!    always holds a defined value, an empty C string, even on the paths that
//!    then answer zero. A caller may read it unconditionally, and
//!    `parseurl` does.
//! 2. L190-L193, on Windows only: a guessing caller is answered zero for an
//!    input that opens with a drive prefix, so `c:/x` is a path rather than a
//!    scheme named `c`.
//! 3. L194 requires the first byte to be a letter, which is RFC 3986 3.1's
//!    rule and the reason a digit does not qualify.
//! 4. L195-L205 then walks bytes 1 through 39 and stops at the first that is
//!    not a letter, digit, `+`, `-` or `.`. The C loop body is empty: the
//!    accepting arm does nothing and the rejecting arm breaks, so the index
//!    is left pointing at the offending byte. If all 39 are acceptable the
//!    index comes to rest at 40, `MAX_SCHEME_LEN`, and 40 is a legal answer.
//! 5. L206 accepts when the index is non-zero, the byte at the index is a
//!    colon, and either the byte after the colon is `/` or the caller is not
//!    guessing.
//! 6. L213-L216 lower-cases the scheme into the buffer and terminates it, and
//!    L217 answers the index. Any other outcome answers zero, at L219.
//!
//! The two halves of step 5 are worth reading twice, because the comment at
//! L207-L209 explains a case that is easy to mistake for a bug. Without
//! guessing, a scheme always ends at the colon, so `data:text/html,x` is
//! detected as scheme `data`. With guessing on, `data:80` could equally be
//! the host `data` with a port, so the colon alone is not enough and a
//! following slash is required. `tests/libtest/lib1560.c` L641 pins the
//! consequence: `about:80` with `CURLU_DEFAULT_SCHEME` becomes
//! `https://about:80/`, host `about` and port 80, not scheme `about`.
//!
//! Step 4's bound is pinned by a pair of rows at L677-L685: a 40-byte scheme
//! parses and reads back lower-cased, and a 41-byte one is rejected with
//! `CURLUE_BAD_SCHEME`. The rejection comes from [`parse_scheme`] rather
//! than from here, and the route is worth following once, because it is how
//! every over-long scheme is refused. Here, the 41st byte is a letter, so
//! the walk runs out of bound at index 40, the byte there is a letter and
//! not a colon, and the answer is zero. A zero-length scheme then reaches
//! the no-scheme arm of [`parse_scheme`], which rejects it unless the caller
//! asked for a default or a guess. The same route rejects `1h://x` at L176
//! for opening with a digit and `htt ps://x` at L320 for the space.
//!
//! # `parse_scheme`: the order of its two rejections is behavior
//!
//! `lib/urlapi.c` L951-L957 tests an unsupported scheme **first** and the
//! slash count **second**, so an input with both faults answers
//! `CURLUE_UNSUPPORTED_SCHEME` and never reaches the slash test. The two
//! codes are distinct, `tests/libtest/lib1560.c` asserts both -- L545 for
//! `CURLUE_BAD_SLASHES` and L635-L640 for `CURLUE_UNSUPPORTED_SCHEME` --
//! and swapping the tests for tidiness would fail the parity diff.
//!
//! The slash count has an asymmetry of its own: L945 counts up to four, and
//! L955 accepts one, two or three. The fourth is counted only so that four
//! or more can be told apart from three, which is why L543-L545's
//! `http:////user:...` is rejected rather than treated as three slashes and
//! a path.
//!
//! # `guess_scheme`: six prefixes and a default that is not `https`
//!
//! `lib/urlapi.c` L989-L1002 is an ordered `checkprefix` chain over the host
//! name -- `ftp.`, `dict.`, `ldap.`, `imap.`, `smtp.`, `pop3.` -- and
//! anything else becomes `http`. The trailing dot is part of every prefix
//! and the comparison is case-insensitive, both of which are observable:
//! `tests/libtest/lib1560.c` L698-L700 turns `smtp.example.com` into
//! `smtp://`, while L740-L742 leaves `smtp/path/html` as `http://` because
//! there is no dot, and L701-L703 leaves `https.example.com` as `http://`
//! because `https.` is not in the table.
//!
//! The default is `http`. `DEFAULT_SCHEME` is `https` and belongs to
//! [`parse_scheme`]; confusing the two would rewrite the expected output of
//! sixteen rows in `get_url_list`.
//!
//! # `guessed_scheme` is set here and nowhere else in this module
//!
//! [`guess_scheme`] sets it, at `lib/urlapi.c` L1008. [`parse_scheme`] does
//! not, not even on the `CURLU_DEFAULT_SCHEME` path that also stores a
//! scheme the input did not carry. That asymmetry is deliberate in the C and
//! is observable through `CURLU_NO_GUESS_SCHEME`, which suppresses a guessed
//! scheme at L1512 and L1559 but leaves a defaulted one alone. It is also
//! the seed of the faithfully reproduced `FB1`, recorded in
//! `docs/KNOWN-DIVERGENCES.md`: `curl_url_dup()` copies the two other flag
//! bits and not this one, so a duplicate of a guessed handle reports the
//! scheme that the original would have suppressed. `handle.rs` owns that
//! half; this module's part is simply not to set the flag where the C does
//! not.
//!
//! # Memory ownership
//!
//! Both scheme-storing functions allocate through [`CBuf::from_slice`],
//! which is `src/alloc.rs`'s port of `curlx_strdup` and uses the **C
//! allocator**. That is required rather than preferred: a scheme stored on
//! the handle can be handed back to the caller of `curl_url_get()`, and
//! `docs/libcurl/curl_url_get.md` L45 obliges that caller to release it with
//! `curl_free()`. `CString::into_raw` is banned crate-wide for the mirror
//! reason -- its pointer has to come back to Rust -- and appears nowhere
//! here. `docs/MEMORY-OWNERSHIP.md` records the whole chain.
//!
//! The store goes through [`CurlUrl::store`], which releases whatever the
//! field held. The C assigns over the field instead, at L977 and L1004, and
//! that is safe there for a reason that does not generalize: `parseurl`
//! parses into a zeroed temporary at L1197-L1202, so the field is always
//! absent when either assignment runs, and `guess_scheme` is additionally
//! guarded by `!u->scheme` at L1151. Releasing first is identical in that
//! context and cannot leak in any other, which is the trade `handle.rs`
//! documents on `store` itself.
//!
//! # Verification
//!
//! The tests at the foot of this file pin every boundary named above against
//! `lib/urlapi.c` and against the rows of `tests/libtest/lib1560.c` they come
//! from, and they are what this file can check on its own.
//!
//! They are not intended to be the last word. The end-to-end oracle is the
//! unmodified `tests/libtest/lib1560.c` compiled against the reference C
//! library and against this crate, with the two outputs diffed byte for byte.
//! `rust-urlapi/scripts/run-parity.sh` drives that comparison, and it reports
//! byte-identical output in both link modes across its whole environment
//! matrix, so the claims here rest on a run that happened rather than on one
//! still to come.

// The plan puts every `unsafe` block in `src/ffi.rs` (0.3.3) and the
// technical specification forbids `unsafe` outside FFI code (1.3.2.1).
// `forbid` rather than `deny` because an inner `allow` here would be a
// design change and should have to be argued for, not slipped in. This
// module needs nothing from C directly -- the one foreign call it depends
// on, `Curl_get_scheme`, is reached through the safe wrapper in
// `src/scheme.rs`, which selects between that import and the built-in table
// at compile time -- so the attribute costs it nothing and turns the crate's
// single-unsafe-island property into a compiler guarantee instead of a
// convention.
#![forbid(unsafe_code)]

use core::ffi::c_uint;

use crate::abi::{
    CURLUcode, CURLUE_BAD_SCHEME, CURLUE_BAD_SLASHES, CURLUE_OUT_OF_MEMORY,
    CURLUE_UNSUPPORTED_SCHEME, CURLU_DEFAULT_SCHEME, CURLU_GUESS_SCHEME, CURLU_NON_SUPPORT_SCHEME,
    DEFAULT_SCHEME, MAX_SCHEME_LEN,
};
use crate::alloc::CBuf;
use crate::ctype::{is_alnum, is_alpha, starts_with_ignore_case, strntolower};
use crate::handle::{CurlUrl, StringField};
use crate::scheme::getn_scheme;

/// How many slashes after the scheme's colon the C bothers to count.
///
/// `lib/urlapi.c` L945, the `(i < 4)` half of the loop condition. The
/// accepted window at L955 is one to three, so the fourth is counted for one
/// purpose only: to distinguish "more than three" from "exactly three"
/// without walking a run of slashes of unbounded length.
const MAX_COUNTED_SLASHES: usize = 4;

/// The most slashes after the scheme's colon that `parse_scheme` accepts.
///
/// `lib/urlapi.c` L955, the `(i > 3)` half of the rejection. Kept as its own
/// constant beside [`MAX_COUNTED_SLASHES`] because the two numbers are
/// different and their difference is the whole point: the fourth slash is
/// counted so that a run of four or more can be told from a run of three and
/// refused. A single constant serving both roles would quietly turn
/// `http:////host` into an accepted URL.
const MAX_ACCEPTED_SLASHES: usize = 3;

/// The legacy host-name prefixes that imply a scheme, in the C's order.
///
/// `lib/urlapi.c` L989-L1000, one row per `checkprefix` arm. The order is
/// preserved because the C chain is `else if` throughout, so the first match
/// wins. The six prefixes differ in their first byte, so no host name can
/// match two of them and the first-match rule decides nothing here; the C's
/// order is kept rather than sorted so that the table can be diffed against
/// L989-L1000 line for line, and so that adding a seventh row cannot change
/// what the existing six answer.
///
/// The trailing dot belongs to the prefix. Without it `smtp/path/html` would
/// guess `smtp`, and `tests/libtest/lib1560.c` L740-L742 requires `http`.
const GUESS_TABLE: [(&[u8], &[u8]); 6] = [
    (b"ftp.", b"ftp"),
    (b"dict.", b"dict"),
    (b"ldap.", b"ldap"),
    (b"imap.", b"imap"),
    (b"smtp.", b"smtp"),
    (b"pop3.", b"pop3"),
];

/// The scheme guessed for a host name no row of [`GUESS_TABLE`] matches.
///
/// `lib/urlapi.c` L1001-L1002. It is `http` and not `https`: the `https`
/// spelling is `DEFAULT_SCHEME` at L84, which belongs to [`parse_scheme`]'s
/// `CURLU_DEFAULT_SCHEME` path instead. Sixteen rows of `get_url_list` in
/// `tests/libtest/lib1560.c` distinguish the two.
const GUESS_FALLBACK: &[u8] = b"http";

/// Whether a byte may continue a scheme already begun by a letter.
///
/// The condition inside the scan at `lib/urlapi.c` L197,
/// `s && (ISALNUM(s) || (s == '+') || (s == '-') || (s == '.'))`, which is
/// RFC 3986 3.1's `*( ALPHA / DIGIT / "+" / "-" / "." )` quoted in the
/// comment at L198-L200.
///
/// The `s &&` guard is reproduced literally, and it carries weight in both
/// languages. In the C it is what stops the scan at the string's terminator.
/// Here the caller stands a zero byte in for the end of the slice, so the
/// same test ends the scan at the same place, and a genuine embedded zero --
/// which `Curl_junkscan` has already rejected by the time `parseurl` gets
/// this far -- ends it too rather than being taken for scheme content.
const fn is_scheme_continuation(byte: u8) -> bool {
    byte != 0 && (is_alnum(byte) || byte == b'+' || byte == b'-' || byte == b'.')
}

/// Whether the input opens with an MS-DOS or Windows drive prefix.
///
/// `STARTS_WITH_DRIVE_PREFIX` at `lib/urlapi.c` L38-L44, whose comment gives
/// the example `c:` in `c:foo`. The macro spells out two letter ranges,
/// `'a'`-`'z'` and `'A'`-`'Z'`, which together are exactly `ISALPHA`, so
/// `is_alpha` is called instead of writing the ranges a second time. It then
/// requires the second byte to be a colon.
///
/// The macro is defined inside `#ifdef _WIN32`, and so is its single use at
/// L191. This function is compiled everywhere all the same, and the platform
/// test lives at the call site as `cfg!(windows)` rather than as an attribute
/// here. The generated code is the same -- on a non-Windows target the
/// condition folds to false and the branch disappears -- but the predicate
/// stays type-checked and unit-tested on every platform, rather than
/// bit-rotting behind an attribute that no parity run on this platform can
/// reach. `cfg!(windows)` is true for exactly the targets that define
/// `_WIN32`, the MSVC and MinGW families both.
///
/// Not a `const fn`, unlike the predicate above it: `<[u8]>::get` is not
/// const-stable on the toolchain this crate targets, and the alternative,
/// direct indexing, is denied by the crate root and would panic on a
/// one-byte input rather than answering false.
fn starts_with_drive_prefix(url: &[u8]) -> bool {
    // `first` and `get` rather than `url[0]` and `url[1]`: the C reads a
    // NUL-terminated string, where a one-byte input makes `str[1]` the
    // terminator and the comparison against `':'` simply fails. Absence here
    // has to fail the same way, and the crate root denies direct indexing.
    matches!(url.first(), Some(&byte) if is_alpha(byte)) && matches!(url.get(1), Some(&b':'))
}

/// Reports the length of the input's scheme, or zero if it has none, and
/// copies that scheme out lower-cased.
///
/// `Curl_is_absolute_url` at `lib/urlapi.c` L182-L220, one of the eight
/// drop-in symbols. The module documentation carries the rule step by step,
/// the reasoning behind the colon-and-slash test, and the route by which an
/// over-long scheme ends up rejected.
///
/// # Parameters
///
/// - `url`: the input, up to but not including the terminating NUL of the C
///   caller's string. Positions at or past its end stand in for that
///   terminator, so a slice behaves as the C string does.
/// - `buf`: where to put the lower-cased scheme, or `None`. It is optional
///   because one of the two C callers passes a null pointer: `set_url` at
///   `lib/urlapi.c` L1713 asks only whether the input is absolute and has
///   nowhere to put a scheme. `parseurl` at L1128 passes a 41-byte buffer.
///   When present, the buffer must hold more than `MAX_SCHEME_LEN` bytes,
///   which is the release-build content of the `DEBUGASSERT` at L186. Both
///   callers that supply one owe that: `src/parse/mod.rs`'s port of `parseurl`
///   sizes its `SCHEMEBUF_LEN` array to `MAX_SCHEME_LEN + 1` to satisfy it,
///   and `src/ffi.rs` carries it as a documented precondition on
///   `Curl_is_absolute_url`, whose `buflen` comes from a C caller this crate
///   cannot see. A shorter buffer is never unsound here -- every write below
///   is bounds-checked -- but it truncates the scheme and skips the
///   terminator, so honoring the contract remains the caller's job.
/// - `guess_scheme`: whether the caller might be looking at an input with no
///   scheme at all. `parseurl` derives it at L1128-L1130 as
///   `flags & (CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME)`, a masked flag
///   word that C narrows to a boolean on the way in, so the masking belongs
///   to the caller and this parameter stays a plain `bool`.
///
/// # Returns
///
/// The scheme's length in bytes, between 1 and `MAX_SCHEME_LEN` inclusive,
/// or zero when the input carries no scheme. Note that zero is not an error:
/// `parseurl` answers it by consulting `CURLU_DEFAULT_SCHEME` and
/// `CURLU_GUESS_SCHEME`, and only rejects the input when neither is set.
///
/// # Effect on `buf`
///
/// The first byte is set to zero before any other work, so a supplied buffer
/// always ends up holding a valid C string even when the answer is zero. On
/// a non-zero answer it holds the scheme, lower-cased, terminated. Reading it
/// after a zero answer therefore yields the empty string rather than
/// whatever the caller left there, which is what lets `parseurl` compare it
/// against `"file"` at L1133 without checking the length first.
pub(crate) fn is_absolute_url(url: &[u8], mut buf: Option<&mut [u8]>, guess_scheme: bool) -> usize {
    // lib/urlapi.c L185. Zero is both the initial value and the answer for
    // an input whose first byte is not a letter, because the scan at L195 is
    // then skipped entirely and the `i &&` guard at L206 fails.
    let mut i: usize = 0;

    // lib/urlapi.c L188-L189, and the comment there: always leave a defined
    // value in buf. This runs before every return, the Windows one included.
    // An empty buffer has no first byte to write, which the C's precondition
    // rules out; there is nothing to do in that case and nothing to report,
    // exactly as for a null pointer.
    if let Some(slot) = buf.as_deref_mut().and_then(<[u8]>::first_mut) {
        *slot = 0;
    }

    // lib/urlapi.c L190-L193, the `#ifdef _WIN32` block. Only a guessing
    // caller is affected: without guessing, `c:/x` really is a scheme named
    // `c`, and `lib/urlapi.c`'s own file-URL handling relies on that.
    if cfg!(windows) && guess_scheme && starts_with_drive_prefix(url) {
        return 0;
    }

    // lib/urlapi.c L194-L205. The first byte must be a letter, and then the
    // scan runs over indices 1 through MAX_SCHEME_LEN - 1 and stops at the
    // first byte that cannot continue a scheme.
    if matches!(url.first(), Some(&byte) if is_alpha(byte)) {
        // Chaining an endless run of zeroes onto the slice is what makes a
        // position past the end behave as the C string's NUL does: the guard
        // inside `is_scheme_continuation` rejects it and the scan stops
        // there. Without it, an input shorter than the bound would run the
        // iterator dry and be mistaken for a 40-byte scheme.
        //
        // `take` then `skip` reproduces the loop header at L195 exactly:
        // `take(MAX_SCHEME_LEN)` is `i < MAX_SCHEME_LEN` and `skip(1)` is
        // `i = 1`. Neither is written as arithmetic, which the crate root
        // denies, and no index is formed by hand.
        i = url
            .iter()
            .copied()
            .chain(core::iter::repeat(0))
            .enumerate()
            .take(MAX_SCHEME_LEN)
            .skip(1)
            .find(|&(_, byte)| !is_scheme_continuation(byte))
            // No offending byte among indices 1 through 39 means all 39
            // could continue the scheme, so the C loop exits on its own
            // condition with the index at MAX_SCHEME_LEN. That is a legal
            // answer, and `tests/libtest/lib1560.c` L677-L681 requires it:
            // a 40-byte scheme parses.
            .map_or(MAX_SCHEME_LEN, |(index, _)| index);
    }

    // lib/urlapi.c L206. Three conditions, in the C's order and with its
    // short-circuiting. `saturating_add` because the crate root denies
    // unchecked arithmetic; it cannot saturate, since `i` is at most 40.
    // Reading one byte past the colon is where the C relies on its
    // terminator, and `get` reproduces that: an absent byte is not `/`, just
    // as a NUL is not.
    let scheme_ends_here = i != 0 && matches!(url.get(i), Some(&b':'));
    let slash_follows = matches!(url.get(i.saturating_add(1)), Some(&b'/'));
    if scheme_ends_here && (slash_follows || !guess_scheme) {
        // lib/urlapi.c L212-L216. The length is the name part only, so the
        // colon is excluded, and the copy is exactly that many bytes.
        // `buf` is consumed here rather than reborrowed with `as_deref_mut`,
        // because this is its last use; the zeroing above needed the reborrow
        // precisely because it was not.
        if let Some(dest) = buf {
            // L214. `strntolower` may leave the destination unterminated --
            // that is the C function's documented behavior at
            // `lib/strcase.c` L101-L105 -- which is precisely why L215
            // writes the terminator itself. Its return value is the count
            // written and is `i` here, because the bytes being copied hold
            // no zero and the buffer is longer than `i`; the C ignores it,
            // and so does this call.
            strntolower(dest, url, i);
            // L215, `buf[i] = 0`. Written at `i` rather than at whatever the
            // copy reported, so the terminator lands where the C puts it.
            // The precondition on the buffer's length makes this always
            // present: `i` is at most `MAX_SCHEME_LEN` and the buffer holds
            // more than that. A shorter buffer than the contract allows
            // leaves the scheme unterminated rather than writing out of
            // bounds, which is the safe direction and the only one Rust can
            // take.
            if let Some(slot) = dest.get_mut(i) {
                *slot = 0;
            }
        }
        return i;
    }
    0
}

/// Resolves the scheme onto the handle and reports where the host starts.
///
/// `parse_scheme` at `lib/urlapi.c` L935-L982. The module documentation
/// carries the two rejections and why their order is behavior rather than
/// style.
///
/// # Parameters
///
/// - `url`: the whole input, the same slice [`is_absolute_url`] was given.
///   The host offset is measured from its start, so it must not be a
///   subslice.
/// - `handle`: the handle being populated. Only its scheme field is touched,
///   and only when a scheme was resolved.
/// - `scheme`: the lower-cased scheme [`is_absolute_url`] copied out, empty
///   when it answered zero. Its length plays the part of the C's separate
///   `schemelen` parameter, which is sound because the two always agree:
///   `parseurl` obtains both from the one call at L1128-L1130, and that
///   function writes the buffer and returns the length together, or writes an
///   empty string and returns zero. Folding them into one argument removes
///   the only way they could be passed inconsistently.
/// - `flags`: the caller's flag word. Three bits are read here:
///   `CURLU_NON_SUPPORT_SCHEME`, `CURLU_DEFAULT_SCHEME` and
///   `CURLU_GUESS_SCHEME`.
///
/// # Returns
///
/// The offset into `url` at which the host name starts, which is what the C
/// writes through `*hostpp` at L959 and L973. `parseurl` continues from there
/// with `strcspn(hostp, "/?#")` at L1143, so an offset into the original
/// slice is the shape that caller wants. The offset is one past the colon
/// plus however many slashes followed for an input that carried a scheme,
/// and zero for one that did not.
///
/// # Errors
///
/// - `CURLUE_UNSUPPORTED_SCHEME` when the scheme is not one libcurl knows and
///   the caller did not set `CURLU_NON_SUPPORT_SCHEME`. L951-L953.
/// - `CURLUE_BAD_SLASHES` when the colon was followed by no slash at all or
///   by four or more. L955-L957.
/// - `CURLUE_BAD_SCHEME` when the input carried no scheme and the caller set
///   neither `CURLU_DEFAULT_SCHEME` nor `CURLU_GUESS_SCHEME`. L964-L965.
/// - `CURLUE_OUT_OF_MEMORY` when the scheme cannot be copied onto the handle.
///   L978-L979.
///
/// Nothing is reported alongside an error, which matches the C: it writes
/// `*hostpp` at L959 before the allocation at L977 can fail, but its one
/// caller checks the result first, at L1139-L1140, and never reads the
/// offset on a failing path.
pub(crate) fn parse_scheme(
    url: &[u8],
    handle: &mut CurlUrl,
    scheme: &[u8],
    flags: c_uint,
) -> Result<usize, CURLUcode> {
    // lib/urlapi.c L940. `None` is the C's null `schemep`, and it means "no
    // scheme to store", which is a successful outcome rather than an error:
    // it is what `CURLU_GUESS_SCHEME` alone leaves behind for `guess_scheme`
    // to fill in later.
    let schemep: Option<&[u8]>;
    let hostp: usize;

    // lib/urlapi.c L942. An empty scheme slice is the C's `schemelen == 0`.
    if scheme.is_empty() {
        // lib/urlapi.c L964-L965. Neither flag set means the input had to
        // carry a scheme and did not. This is the arm that rejects every
        // input whose scheme is malformed or over-long, because
        // `is_absolute_url` reports those as no scheme at all rather than as
        // a bad one; `tests/libtest/lib1560.c` L176-L179, L320, L685 and
        // L814 all arrive here.
        if (flags & (CURLU_DEFAULT_SCHEME | CURLU_GUESS_SCHEME)) == 0 {
            return Err(CURLUE_BAD_SCHEME);
        }

        // lib/urlapi.c L967-L968. `CURLU_DEFAULT_SCHEME` supplies `https`
        // now; `CURLU_GUESS_SCHEME` on its own supplies nothing here, and
        // `parseurl` calls `guess_scheme` at L1151-L1152 instead once it has
        // a host name to guess from. When both flags are set the default
        // wins, because storing a scheme here is what makes the
        // `!u->scheme` guard at L1151 fail.
        //
        // The handle's `guessed_scheme` flag is deliberately NOT set on this
        // path. See the module documentation: only `guess_scheme` sets it,
        // and `CURLU_NO_GUESS_SCHEME` can tell the two apart because of that.
        schemep = if (flags & CURLU_DEFAULT_SCHEME) != 0 {
            Some(DEFAULT_SCHEME.as_bytes())
        } else {
            None
        };

        // lib/urlapi.c L970-L973 and its comment: the URL was badly
        // formatted, so try again treating the whole of it as the authority.
        hostp = 0;
    } else {
        // lib/urlapi.c L944, `p = &url[schemelen + 1]`, one past the colon.
        // `saturating_add` for the crate's arithmetic policy; it cannot
        // saturate, because `scheme.len()` is at most `MAX_SCHEME_LEN`.
        let after_colon = scheme.len().saturating_add(1);
        // The range is always within the slice: `is_absolute_url` only
        // reports a length when the byte at that index is a colon, so the
        // slice holds at least one byte more than the scheme. The empty
        // fallback keeps that argument out of the compiled code's trust
        // boundary -- it is checked rather than asserted -- and it degrades
        // the way the C does for a string that ends at the colon, where `p`
        // addresses the terminator and no slash is found.
        let after_scheme = url.get(after_colon..).unwrap_or(&[]);

        // lib/urlapi.c L945-L948. Count the leading slashes, but no more
        // than four of them.
        let slashes = after_scheme
            .iter()
            .take(MAX_COUNTED_SLASHES)
            .take_while(|&&byte| byte == b'/')
            .count();

        // lib/urlapi.c L950-L953, and this test comes FIRST. Swapping it
        // with the slash test below would answer `CURLUE_BAD_SLASHES` for an
        // input that is faulty in both ways, where the C answers
        // `CURLUE_UNSUPPORTED_SCHEME`.
        //
        // The lookup is `crate::scheme`'s safe wrapper, which is
        // `Curl_get_scheme` from the linked libcurl in the drop-in
        // configuration and the crate's own table in the standalone one. The
        // length-delimited form is used because the scheme is a slice here;
        // the C reaches the same table through `Curl_get_scheme`, which is a
        // one-line forward to it at `lib/url.c` L1469-L1472 that measures
        // the string with `strlen`. Note what is NOT tested: `->run`, the
        // protocol-enabled marker. `parse_scheme` accepts a scheme libcurl
        // knows the name of even when that build cannot drive it; only the
        // scheme setter at L1646 is stricter.
        if getn_scheme(scheme).is_none() && (flags & CURLU_NON_SUPPORT_SCHEME) == 0 {
            return Err(CURLUE_UNSUPPORTED_SCHEME);
        }

        // lib/urlapi.c L955-L957, and its comment: less than one or more
        // than three slashes. Written as a range match rather than as
        // `slashes < 1 || slashes > 3` so that the accepted window reads as
        // one thing; the two forms accept the same counts.
        if !matches!(slashes, 1..=MAX_ACCEPTED_SLASHES) {
            return Err(CURLUE_BAD_SLASHES);
        }

        // lib/urlapi.c L950 assigns `schemep = schemebuf` before either
        // test; the order is immaterial because neither test reads it and
        // both return without reaching the store.
        schemep = Some(scheme);
        // lib/urlapi.c L959, `*hostpp = p`: the host starts after the colon
        // and after the slashes that were counted.
        hostp = after_colon.saturating_add(slashes);
    }

    // lib/urlapi.c L976-L980. One store for both arms, exactly as the C has
    // one.
    if let Some(bytes) = schemep {
        // L977, `u->scheme = curlx_strdup(schemep)`. The C allocator, so the
        // caller of `curl_url_get()` can release the copy this eventually
        // becomes with `curl_free()`; see the module documentation.
        let stored = CBuf::from_slice(bytes).ok_or(CURLUE_OUT_OF_MEMORY)?;
        handle.store(StringField::Scheme, stored);
    }
    Ok(hostp)
}

/// Guesses a scheme from the host name and stores it, marking it as guessed.
///
/// `guess_scheme` at `lib/urlapi.c` L984-L1010, reached from `parseurl` at
/// L1151-L1152 only when the caller set `CURLU_GUESS_SCHEME`, the authority
/// parsed, and no scheme has been stored. The module documentation carries
/// the table, the significance of the trailing dot and why the default is
/// `http`.
///
/// # Parameters
///
/// - `handle`: the handle being populated. Its scheme field and its
///   `guessed_scheme` flag are both written on success.
/// - `hostname`: the host name to guess from, which the C reads as
///   `curlx_dyn_ptr(host)` at L986 -- the dynamic buffer `parseurl`
///   accumulated, not the raw input. Pass `DynBuf::as_bytes()`. A borrowed
///   slice rather than the buffer itself, because nothing here needs to grow
///   or own it, and the handle is not consulted for the host either: at this
///   point in the pipeline the buffer has not yet been handed over, which
///   happens at L1185.
///
/// An empty slice is accepted and guesses `http`, matching what the C's
/// `checkprefix` chain does with an empty string. The C would instead
/// dereference a null pointer if the buffer had never been allocated, and its
/// caller rules that out: L1148 only reaches here when the authority was
/// non-empty.
///
/// # Errors
///
/// `CURLUE_OUT_OF_MEMORY`, the only code this function can produce, when the
/// guessed scheme cannot be copied onto the handle. L1005-L1006. The flag is
/// not set on that path, which is the C's order at L1004-L1008 and matters:
/// a handle left without a scheme must not claim to have guessed one.
pub(crate) fn guess_scheme(handle: &mut CurlUrl, hostname: &[u8]) -> Result<(), CURLUcode> {
    // lib/urlapi.c L989-L1002. The `else if` chain becomes a search over the
    // table in the same order, and the final `else` becomes the fallback.
    // `starts_with_ignore_case` is the port of `checkprefix`, whose
    // case-insensitivity comes from `curl_strnequal` at `lib/strcase.h` L33;
    // note that it takes the candidate first and the prefix second, the
    // reverse of the macro's argument order.
    let schemep = GUESS_TABLE
        .iter()
        .find(|&&(prefix, _)| starts_with_ignore_case(hostname, prefix))
        .map_or(GUESS_FALLBACK, |&(_, scheme)| scheme);

    // lib/urlapi.c L1004-L1006. The C allocator again, for the reason in the
    // module documentation. `store` releases any previous value; the C
    // assigns over the field, which is equivalent here because L1151 only
    // calls this function when the field is absent.
    let stored = CBuf::from_slice(schemep).ok_or(CURLUE_OUT_OF_MEMORY)?;
    handle.store(StringField::Scheme, stored);

    // lib/urlapi.c L1008, and this is the only place in the port that sets
    // the flag, as L1008 is the only place in the C. It runs after the store
    // has succeeded, so the two never disagree.
    handle.set_guessed_scheme(true);

    Ok(())
}

#[cfg(test)]
mod tests {
    // The crate root denies the panicking constructs so that no panic can
    // ever reach the C boundary. A test's entire job is to panic when an
    // assertion fails, and a test never crosses that boundary, so the
    // denials are relaxed here and only here. The allowance is scoped to
    // this module and enumerated rather than blanket. Inner attributes have
    // to precede every item, `extern crate` included, so they lead.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::panic)]

    // The two long inputs below need the heap, and they reach it through the
    // `alloc` crate rather than through `std` so that this module compiles
    // the same way whichever the crate root turns out to declare. Everything
    // else here imports from `core` alone.
    extern crate alloc;

    // Imported by name rather than through a glob, as everywhere else in the
    // crate, so each use site names its source.
    use super::{
        guess_scheme, is_absolute_url, is_scheme_continuation, parse_scheme,
        starts_with_drive_prefix, GUESS_FALLBACK, GUESS_TABLE, MAX_ACCEPTED_SLASHES,
        MAX_COUNTED_SLASHES,
    };
    use crate::abi::{
        CURLUcode, CURLUE_BAD_SCHEME, CURLUE_BAD_SLASHES, CURLUE_UNSUPPORTED_SCHEME,
        CURLU_DEFAULT_SCHEME, CURLU_GUESS_SCHEME, CURLU_NON_SUPPORT_SCHEME, DEFAULT_SCHEME,
        MAX_SCHEME_LEN,
    };
    use crate::handle::CurlUrl;
    use alloc::vec;
    use core::ffi::c_uint;

    /// The byte a fresh scheme buffer is filled with before every call.
    ///
    /// Not zero, deliberately. `Curl_is_absolute_url` promises to leave a
    /// defined value in the buffer whatever it answers, and a buffer that was
    /// already zeroed cannot tell a written terminator from an untouched one.
    /// `0xaa` also has its high bit set, so it doubles as a check that the
    /// copy stops where it should rather than running on.
    const FILLER: u8 = 0xaa;

    /// A scheme buffer the size `parseurl` uses.
    ///
    /// `char schemebuf[MAX_SCHEME_LEN + 1]` at `lib/urlapi.c` L1114, so 41
    /// bytes: room for the longest accepted scheme plus its terminator. That
    /// is one more than `MAX_SCHEME_LEN`, which is what the `DEBUGASSERT` at
    /// L186 requires. Note it is deliberately not the `MAX_SCHEME_LEN + 5`
    /// buffer `urlget_url` uses at L1452; the two are different sizes for
    /// different jobs and are not harmonized here.
    fn scheme_buf() -> [u8; MAX_SCHEME_LEN + 1] {
        [FILLER; MAX_SCHEME_LEN + 1]
    }

    /// The C string a buffer holds: everything up to the first zero byte.
    fn c_string(buf: &[u8]) -> &[u8] {
        let end = buf.iter().position(|&byte| byte == 0).unwrap_or(buf.len());
        &buf[..end]
    }

    /// Calls with a buffer and reports both results the C caller keeps: the
    /// length, and the scheme left in the buffer.
    ///
    /// The buffer is checked for a terminator before its content is read,
    /// because "the answer was 4 and the buffer happens to start with the
    /// right four bytes" is not the same claim as "the buffer holds the
    /// four-byte string `http`".
    fn detect(url: &[u8], guess_scheme: bool) -> (usize, alloc::vec::Vec<u8>) {
        let mut buf = scheme_buf();
        let len = is_absolute_url(url, Some(&mut buf), guess_scheme);
        assert!(
            buf.contains(&0),
            "the buffer must always be left holding a valid C string"
        );
        // The answer must agree with the buffer, and the byte just past the
        // scheme must be the terminator rather than a survivor of FILLER.
        assert_eq!(buf[len], 0, "the terminator belongs at index {len}");
        (len, c_string(&buf).to_vec())
    }

    /// Calls without a buffer, the way `set_url` does at
    /// `lib/urlapi.c` L1713.
    fn detect_nobuf(url: &[u8], guess_scheme: bool) -> usize {
        is_absolute_url(url, None, guess_scheme)
    }

    /// A scheme accepted by the lookup in **both** link configurations.
    ///
    /// The standalone build answers from the 33-row table in
    /// `src/scheme.rs`; a `cargo test` of the drop-in build answers from the
    /// four-row double in `src/ffi.rs`, which holds `https`, `imap`, `file`
    /// and a disabled `rtmp`. `https` is in both, so a test using it asserts
    /// the same thing either way. `http` is deliberately not used below: the
    /// double does not carry it.
    const KNOWN_SCHEME: &[u8] = b"https";

    /// A scheme rejected by the lookup in both configurations.
    ///
    /// Seven bytes, which is the longest name `Curl_getn_scheme` will even
    /// hash, per `lib/url.c` L1524 -- so this exercises the lookup rather
    /// than its length guard. It is the scheme of
    /// `tests/libtest/lib1560.c` L638, `example://foo`.
    const UNKNOWN_SCHEME: &[u8] = b"example";

    /// The three sub-tests of `Curl_is_absolute_url` that need no buffer.
    ///
    /// `tests/libtest/lib1560.c` L176-L179: an input whose first byte is not
    /// a letter carries no scheme, so all four of these end up rejected with
    /// `CURLUE_BAD_SCHEME` by the no-scheme arm of `parse_scheme`.
    #[test]
    fn the_first_byte_of_a_scheme_must_be_a_letter() {
        for url in [
            &b"1h://example.net"[..],
            b"..://example.net",
            b"-ht://example.net",
            b"+ftp://example.net",
            b"9://x",
            b":://x",
            b"://x",
        ] {
            assert_eq!(detect(url, false).0, 0, "input {url:?}");
            assert_eq!(detect(url, true).0, 0, "input {url:?}");
        }
    }

    /// An ordinary scheme is measured and copied out lower-cased.
    ///
    /// The lower-casing is not cosmetic. `parseurl` compares the buffer
    /// against the literal `"file"` with `strcmp` at `lib/urlapi.c` L1133, so
    /// it is what makes `FILE://` reach the file-URL branch, and
    /// `tests/libtest/lib1560.c` L757 requires `HTTP://test/` to read back as
    /// `http://test/`.
    #[test]
    fn a_scheme_is_reported_and_copied_out_lower_cased() {
        assert_eq!(detect(b"http://x", false), (4, b"http".to_vec()));
        assert_eq!(detect(b"HTTP://x", false), (4, b"http".to_vec()));
        assert_eq!(detect(b"hTtP://x", false), (4, b"http".to_vec()));
        assert_eq!(detect(b"FILE://x", false), (4, b"file".to_vec()));
        assert_eq!(detect(b"HTTPS://x", true), (5, b"https".to_vec()));
        // The copy is the name part only: the colon is excluded, per the
        // comment at lib/urlapi.c L211.
        assert_eq!(detect(b"ftp://a:b@c/d", false), (3, b"ftp".to_vec()));
    }

    /// Every byte the C accepts after the first, and the ones it does not.
    ///
    /// `lib/urlapi.c` L197 accepts a letter, a digit, `+`, `-` or `.`. The
    /// first two rows come from `tests/libtest/lib1560.c` L180-L185, which
    /// parses `hej.hej://example.net` and `ht-tp://example.net` successfully
    /// under `CURLU_NON_SUPPORT_SCHEME`.
    #[test]
    fn the_scheme_continuation_set_is_alnum_plus_three_punctuation_bytes() {
        assert_eq!(detect(b"hej.hej://example.net", false).0, 7);
        assert_eq!(detect(b"ht-tp://example.net", false).0, 5);
        assert_eq!(detect(b"a+b://x", false).0, 3);
        assert_eq!(detect(b"h1://x", false).0, 2);
        assert_eq!(detect(b"a1+-.z://x", false).0, 6);
        // A space is not in the set, which is why
        // tests/libtest/lib1560.c L319-L320 rejects `htt ps://...` with
        // CURLUE_BAD_SCHEME even under CURLU_ALLOW_SPACE.
        assert_eq!(detect(b"htt ps://example.net", false).0, 0);
        // Neither is an underscore, nor any of the other bytes a reader
        // might expect a scheme to tolerate.
        for url in [&b"a_b://x"[..], b"a~b://x", b"a%b://x", b"a/b://x"] {
            assert_eq!(detect(url, false).0, 0, "input {url:?}");
        }
    }

    /// The predicate itself, at its boundaries.
    ///
    /// The set is small enough to check exhaustively over all 256 byte
    /// values, which is the only way to be sure no extra byte crept in.
    #[test]
    fn the_continuation_predicate_accepts_exactly_the_c_set() {
        for byte in 0..=u8::MAX {
            let expected = byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.');
            assert_eq!(
                is_scheme_continuation(byte),
                expected,
                "byte {byte:#04x} disagrees with lib/curl_ctype.h L41 plus L197's three"
            );
        }
        // The zero byte is rejected by the `s &&` guard rather than by the
        // classification, and it is the only byte for which the two reasons
        // could be confused.
        assert!(!is_scheme_continuation(0));
    }

    /// A colon alone ends a scheme only when the caller is not guessing.
    ///
    /// `lib/urlapi.c` L206 and the comment at L207-L209. Without guessing,
    /// `data:` is a scheme, which is how `data:` and `mailto:` URLs are
    /// detected at all -- `tests/libtest/lib1560.c` L634-L640 expects
    /// `CURLUE_UNSUPPORTED_SCHEME` for five such inputs, and that code can
    /// only be reached with a non-zero scheme length. With guessing on, the
    /// same text could be a host name and a port, which L641 pins:
    /// `about:80` becomes `https://about:80/`.
    #[test]
    fn a_colon_not_followed_by_a_slash_needs_a_non_guessing_caller() {
        assert_eq!(detect(b"data:foo", true).0, 0);
        assert_eq!(detect(b"data:foo", false), (4, b"data".to_vec()));
        assert_eq!(detect(b"about:config", true).0, 0);
        assert_eq!(detect(b"about:config", false), (5, b"about".to_vec()));
        assert_eq!(detect(b"about:80", true).0, 0);
        assert_eq!(detect(b"about:80", false), (5, b"about".to_vec()));
        assert_eq!(detect(b"d:anything-really", false), (1, b"d".to_vec()));
        // A following slash satisfies the guessing caller as well.
        assert_eq!(detect(b"data:/foo", true), (4, b"data".to_vec()));
        // And one colon with nothing at all after it is still a scheme for a
        // non-guessing caller: the byte past the colon is the terminator,
        // which is not a slash, so only the second half of the disjunction
        // can carry it.
        assert_eq!(detect(b"https:", false), (5, b"https".to_vec()));
        assert_eq!(detect(b"https:", true).0, 0);
    }

    /// Forty bytes of scheme are accepted and forty-one are not.
    ///
    /// The two inputs are the ones at `tests/libtest/lib1560.c` L677-L685,
    /// copied byte for byte, together with the lower-cased expectation the
    /// first of them reads back as. Their lengths are asserted rather than
    /// counted by eye, because a typo in either literal would turn this test
    /// into a tautology.
    #[test]
    fn the_scheme_bound_is_exactly_max_scheme_len() {
        let forty = &b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://hostname/path"[..];
        let forty_one = &b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://hostname/path"[..];
        let tail = b"://hostname/path".len();
        assert_eq!(forty.len() - tail, MAX_SCHEME_LEN);
        assert_eq!(forty_one.len() - tail, MAX_SCHEME_LEN + 1);

        let lowered = vec![b'a'; MAX_SCHEME_LEN];
        assert_eq!(detect(forty, false), (MAX_SCHEME_LEN, lowered.clone()));
        assert_eq!(detect(forty, true), (MAX_SCHEME_LEN, lowered));

        // The scan runs out of bound with the 41st byte still a letter, so
        // the byte at the index is not a colon and the answer is zero. The
        // scheme is not silently truncated to 40.
        assert_eq!(detect(forty_one, false).0, 0);
        assert_eq!(detect(forty_one, true).0, 0);

        // A 40-byte scheme with no slash after the colon is still 40 bytes
        // for a non-guessing caller, which proves the bound and the
        // colon-slash rule are independent.
        let bare = &b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:x"[..];
        assert_eq!(detect(bare, false).0, MAX_SCHEME_LEN);
        assert_eq!(detect(bare, true).0, 0);
    }

    /// The `huge()` sub-test's first row, at
    /// `tests/libtest/lib1560.c` L1938-L1955.
    ///
    /// It builds a scheme of 119,999 bytes and expects `CURLUE_BAD_SCHEME`
    /// under `CURLU_NON_SUPPORT_SCHEME`. This half of the route is here: the
    /// detection answers zero. The other half, the rejection, is
    /// [`no_scheme_and_neither_flag_is_bad_scheme`].
    #[test]
    fn a_ridiculously_long_scheme_is_no_scheme() {
        let mut url = vec![b'a'; 119_999];
        url.extend_from_slice(b"://c:c@c/c?c#c");
        assert_eq!(detect(&url, false).0, 0);
        assert_eq!(detect_nobuf(&url, false), 0);
    }

    /// The buffer is left holding a valid C string on every path, including
    /// the ones that answer zero.
    ///
    /// `lib/urlapi.c` L188-L189 and its comment. `parseurl` relies on this at
    /// L1133, where it runs `strcmp(schemebuf, "file")` without first
    /// checking whether the length was non-zero.
    #[test]
    fn the_buffer_is_always_left_defined() {
        for url in [
            &b""[..],
            b" ",
            b"1h://x",
            b"example.com/path/html",
            b"htt ps://x",
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://x",
        ] {
            let mut buf = scheme_buf();
            let len = is_absolute_url(url, Some(&mut buf), false);
            assert_eq!(len, 0, "input {url:?}");
            assert_eq!(buf[0], 0, "input {url:?} left the buffer undefined");
            assert!(c_string(&buf).is_empty(), "input {url:?}");
        }
    }

    /// Nothing past the terminator is touched.
    ///
    /// The copy is `i` bytes and the terminator is one more, so byte `i + 1`
    /// onwards must still hold the filler. A copy that ran to the buffer's
    /// end, or one that terminated in the wrong place, shows up here and
    /// nowhere else.
    #[test]
    fn the_copy_writes_the_scheme_the_terminator_and_no_more() {
        let mut buf = scheme_buf();
        let len = is_absolute_url(b"HTTPS://example.com/path", Some(&mut buf), false);
        assert_eq!(len, 5);
        assert_eq!(&buf[..5], b"https");
        assert_eq!(buf[5], 0);
        assert!(
            buf[6..].iter().all(|&byte| byte == FILLER),
            "bytes past the terminator were disturbed: {buf:?}"
        );

        // At the bound, the terminator lands in the buffer's last byte and
        // there is nothing after it. This is the case a 40-byte buffer would
        // have got wrong, which is why L1114 sizes it at 41.
        let mut full = scheme_buf();
        let len = is_absolute_url(
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://x",
            Some(&mut full),
            false,
        );
        assert_eq!(len, MAX_SCHEME_LEN);
        assert_eq!(
            &full[..MAX_SCHEME_LEN],
            vec![b'a'; MAX_SCHEME_LEN].as_slice()
        );
        assert_eq!(full[MAX_SCHEME_LEN], 0);
    }

    /// A `None` buffer is accepted, and answers exactly what a buffer would.
    ///
    /// `set_url` at `lib/urlapi.c` L1713 passes `NULL` and `0`, so a
    /// signature that demanded a buffer would break that caller outright.
    /// The answers are compared against the buffered call rather than against
    /// literals, so the two can never drift apart.
    #[test]
    fn the_buffer_is_optional() {
        for url in [
            &b"http://x"[..],
            b"HTTPS://x",
            b"data:foo",
            b"example.com/path",
            b"",
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://x",
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://x",
        ] {
            for guess in [false, true] {
                assert_eq!(
                    detect_nobuf(url, guess),
                    detect(url, guess).0,
                    "input {url:?} guess {guess}"
                );
            }
        }
    }

    /// An empty buffer is tolerated rather than a panic.
    ///
    /// The C's precondition rules it out -- `DEBUGASSERT(!buf || (buflen >
    /// MAX_SCHEME_LEN))` at L186 -- and `src/ffi.rs` honors it, so this is
    /// not a reachable state. It is tested because the crate is held to
    /// having no panic path even in principle: the answer stays correct and
    /// the unwritable buffer is simply left alone.
    #[test]
    fn a_buffer_too_small_for_the_contract_does_not_panic() {
        let mut empty: [u8; 0] = [];
        assert_eq!(is_absolute_url(b"http://x", Some(&mut empty), false), 4);

        let mut tiny = [FILLER; 2];
        assert_eq!(is_absolute_url(b"http://x", Some(&mut tiny), false), 4);
        // Two bytes cannot hold `http` and its terminator. The copy fills
        // what it can and the terminator has nowhere to go, which is the
        // safe direction: the C would have written past the end.
        assert_eq!(tiny, [b'h', b't']);
    }

    /// The drive-prefix predicate, against the macro at
    /// `lib/urlapi.c` L38-L44.
    #[test]
    fn the_drive_prefix_predicate_matches_the_macro() {
        for url in [&b"c:"[..], b"C:", b"c:foo", b"Z:\\dir\\file", b"a:/x"] {
            assert!(starts_with_drive_prefix(url), "input {url:?}");
        }
        for url in [
            &b""[..],
            b"c",
            b"1:",
            b":c",
            b"c;",
            b"c|",
            b"cc:",
            b"_:",
            b"c\0",
        ] {
            assert!(!starts_with_drive_prefix(url), "input {url:?}");
        }
    }

    /// A drive prefix is a scheme unless the caller is guessing, and then
    /// only on Windows.
    ///
    /// `lib/urlapi.c` L190-L193 sits inside `#ifdef _WIN32`, so the expected
    /// answer depends on the target. Stating both here documents the
    /// divergence the AAP records as ported-but-not-validated-on-this-
    /// platform, and keeps the platform test from being silently inverted.
    #[test]
    fn a_drive_prefix_is_only_special_for_a_guessing_windows_caller() {
        // Not guessing: unaffected on every platform, because the early
        // return at L191 is guarded by `guess_scheme`.
        assert_eq!(detect(b"c:/x", false), (1, b"c".to_vec()));
        assert_eq!(detect(b"c:\\x", false), (1, b"c".to_vec()));

        // Guessing: Windows answers zero so the input is treated as a path;
        // elsewhere the ordinary rule applies and `c:/x` is scheme `c`.
        let expected = if cfg!(windows) { 0 } else { 1 };
        assert_eq!(detect(b"c:/x", true).0, expected);

        // A two-letter name is not a drive prefix, so it is unaffected on
        // every platform.
        assert_eq!(detect(b"cc://x", true), (2, b"cc".to_vec()));
    }

    /// Runs `parse_scheme` on a fresh handle and reports everything a caller
    /// can observe: the result, the stored scheme and the guessed flag.
    ///
    /// The scheme argument is taken separately from the URL, exactly as the C
    /// takes `schemebuf` separately from `url`, so a test can pin the
    /// no-scheme arm without having to find an input that produces it.
    fn resolve(
        url: &[u8],
        scheme: &[u8],
        flags: c_uint,
    ) -> (Result<usize, CURLUcode>, Option<alloc::vec::Vec<u8>>, bool) {
        let mut handle = CurlUrl::new();
        let result = parse_scheme(url, &mut handle, scheme, flags);
        let stored = handle.scheme().map(<[u8]>::to_vec);
        (result, stored, handle.guessed_scheme())
    }

    /// The unsupported-scheme test runs before the slash-count test.
    ///
    /// `lib/urlapi.c` L951-L953 then L955-L957. The input below is faulty in
    /// both ways at once -- an unknown scheme and four slashes -- so it is
    /// the one input that can tell the order apart. Turning the first fault
    /// off with `CURLU_NON_SUPPORT_SCHEME` then exposes the second, which
    /// proves the input really did carry both.
    #[test]
    fn an_unsupported_scheme_is_reported_before_a_bad_slash_count() {
        let url = b"example:////hostname/path";
        assert_eq!(
            resolve(url, UNKNOWN_SCHEME, 0).0,
            Err(CURLUE_UNSUPPORTED_SCHEME)
        );
        assert_eq!(
            resolve(url, UNKNOWN_SCHEME, CURLU_NON_SUPPORT_SCHEME).0,
            Err(CURLUE_BAD_SLASHES)
        );
        // With no slashes at all the same pairing holds, so the order is not
        // an artifact of the count being four.
        assert_eq!(
            resolve(b"example:hostname", UNKNOWN_SCHEME, 0).0,
            Err(CURLUE_UNSUPPORTED_SCHEME)
        );
        assert_eq!(
            resolve(
                b"example:hostname",
                UNKNOWN_SCHEME,
                CURLU_NON_SUPPORT_SCHEME
            )
            .0,
            Err(CURLUE_BAD_SLASHES)
        );
    }

    /// Nothing is stored on a rejected input.
    ///
    /// The C returns before reaching the store at L977 on all three of its
    /// rejection paths, so a failed parse leaves the handle's scheme field
    /// exactly as it found it. `parseurl` frees the whole temporary at
    /// L1188-L1191 in any case, but the property is worth holding on its own:
    /// `Curl_url_set_authority` reaches neighboring code with a live handle.
    #[test]
    fn a_rejected_input_stores_no_scheme() {
        for (url, scheme, flags) in [
            (&b"example://x"[..], UNKNOWN_SCHEME, 0),
            (b"https:x", KNOWN_SCHEME, 0),
            (b"https:////x", KNOWN_SCHEME, 0),
            (b"example.com/path", &b""[..], 0),
        ] {
            let (result, stored, guessed) = resolve(url, scheme, flags);
            assert!(result.is_err(), "input {url:?} should have been rejected");
            assert_eq!(stored, None, "input {url:?}");
            assert!(!guessed, "input {url:?}");
        }
    }

    /// One, two or three slashes are accepted; none and four are not.
    ///
    /// `lib/urlapi.c` L945 counts up to four and L955 accepts one to three.
    /// The four-slash row is `tests/libtest/lib1560.c` L543-L545,
    /// `http:////user:password@example.com:1234/...` with
    /// `CURLU_DEFAULT_SCHEME`, which expects `CURLUE_BAD_SLASHES`.
    #[test]
    fn the_accepted_slash_count_is_one_to_three() {
        assert_eq!(
            resolve(b"https:hostname", KNOWN_SCHEME, 0).0,
            Err(CURLUE_BAD_SLASHES)
        );
        // The offsets are 6 + the slash count: one past the five-byte scheme
        // and its colon, then past the slashes themselves.
        assert_eq!(resolve(b"https:/hostname", KNOWN_SCHEME, 0).0, Ok(7));
        assert_eq!(resolve(b"https://hostname", KNOWN_SCHEME, 0).0, Ok(8));
        assert_eq!(resolve(b"https:///hostname", KNOWN_SCHEME, 0).0, Ok(9));
        assert_eq!(
            resolve(b"https:////hostname", KNOWN_SCHEME, 0).0,
            Err(CURLUE_BAD_SLASHES)
        );
        // Five and more are rejected too, and the count stops at four rather
        // than walking the whole run.
        assert_eq!(
            resolve(b"https://///////hostname", KNOWN_SCHEME, 0).0,
            Err(CURLUE_BAD_SLASHES)
        );
        // An input that ends at the colon has nothing to count.
        assert_eq!(
            resolve(b"https:", KNOWN_SCHEME, 0).0,
            Err(CURLUE_BAD_SLASHES)
        );
        // The two bounds are different numbers and the difference is the
        // point: the fourth slash is counted only so that it can be refused.
        assert_eq!(MAX_COUNTED_SLASHES, MAX_ACCEPTED_SLASHES + 1);
    }

    /// The reported offset is where the host name begins.
    ///
    /// `lib/urlapi.c` L959, `*hostpp = p`, which `parseurl` then walks from
    /// with `strcspn(hostp, "/?#")` at L1143. The offsets are checked by
    /// slicing the input rather than by comparing numbers, so the assertion
    /// says what the caller will actually see.
    #[test]
    fn the_offset_points_at_the_host_name() {
        for (url, expected) in [
            (&b"https://hostname/path"[..], &b"hostname/path"[..]),
            (b"https:/hostname/path", b"hostname/path"),
            (b"https:///hostname/path", b"hostname/path"),
            (
                b"https://user:pass@host:1234/p?q#f",
                b"user:pass@host:1234/p?q#f",
            ),
            (b"https://", b""),
        ] {
            let offset = resolve(url, KNOWN_SCHEME, 0).0.unwrap();
            assert_eq!(&url[offset..], expected, "input {url:?}");
        }
        // The no-scheme arm reports zero, so the whole input is the
        // authority. lib/urlapi.c L973.
        let url = b"example.com/path/html";
        let offset = resolve(url, b"", CURLU_DEFAULT_SCHEME).0.unwrap();
        assert_eq!(offset, 0);
        assert_eq!(&url[offset..], &url[..]);
    }

    /// A known scheme is stored, and stored as given rather than re-derived.
    ///
    /// The bytes handed in are already lower-cased by `is_absolute_url`, and
    /// this function copies them verbatim: `schemep = schemebuf` at
    /// `lib/urlapi.c` L950 followed by the `curlx_strdup` at L977. The
    /// `guessed_scheme` flag stays clear, because the input carried the
    /// scheme.
    #[test]
    fn a_known_scheme_is_stored_and_not_marked_guessed() {
        let (result, stored, guessed) = resolve(b"https://hostname", KNOWN_SCHEME, 0);
        assert_eq!(result, Ok(8));
        assert_eq!(stored.as_deref(), Some(&b"https"[..]));
        assert!(!guessed);

        // An unknown scheme is stored just the same once
        // CURLU_NON_SUPPORT_SCHEME admits it, which is what
        // tests/libtest/lib1560.c L180-L185 relies on for `hej.hej` and
        // `ht-tp`.
        let (result, stored, guessed) =
            resolve(b"example://foo", UNKNOWN_SCHEME, CURLU_NON_SUPPORT_SCHEME);
        assert_eq!(result, Ok(10));
        assert_eq!(stored.as_deref(), Some(UNKNOWN_SCHEME));
        assert!(!guessed);
    }

    /// The scheme-enabled marker is not consulted here.
    ///
    /// `lib/urlapi.c` L951 tests only whether the lookup found a descriptor.
    /// The `->run` pointer, which distinguishes a scheme libcurl knows the
    /// name of from one this build can drive, is tested at L1646 in the
    /// scheme *setter* and nowhere else. The drop-in test double carries a
    /// disabled `rtmp` row for exactly this case; the standalone table
    /// reports every row as implemented, as `src/scheme.rs` documents, so the
    /// assertion below is the one both configurations agree on.
    #[test]
    fn a_disabled_protocol_is_still_a_known_scheme_here() {
        let (result, stored, _) = resolve(b"rtmp://hostname", b"rtmp", 0);
        assert_eq!(result, Ok(7));
        assert_eq!(stored.as_deref(), Some(&b"rtmp"[..]));
    }

    /// No scheme and neither scheme-supplying flag is `CURLUE_BAD_SCHEME`.
    ///
    /// `lib/urlapi.c` L964-L965. This is where every malformed or over-long
    /// scheme ends up, because `is_absolute_url` reports those as no scheme
    /// rather than as a bad one: `tests/libtest/lib1560.c` L176-L179
    /// (`1h://`, `..://`, `-ht://`, `+ftp://`), L320 (`htt ps://` with
    /// `CURLU_ALLOW_SPACE`), L685 (the 41-byte scheme), L814
    /// (`example.com/path/html` with no flags) and L1950 (`huge()`'s first
    /// row) all arrive at this line.
    #[test]
    fn no_scheme_and_neither_flag_is_bad_scheme() {
        assert_eq!(
            resolve(b"example.com/path/html", b"", 0).0,
            Err(CURLUE_BAD_SCHEME)
        );
        // Flags that are not one of the two make no difference, which is what
        // L320 and L685 exercise: both set CURLU_NON_SUPPORT_SCHEME, and one
        // adds CURLU_ALLOW_SPACE.
        for flags in [
            CURLU_NON_SUPPORT_SCHEME,
            CURLU_NON_SUPPORT_SCHEME | (1 << 11),
            !(CURLU_DEFAULT_SCHEME | CURLU_GUESS_SCHEME),
        ] {
            assert_eq!(
                resolve(b"1h://example.net", b"", flags).0,
                Err(CURLUE_BAD_SCHEME),
                "flags {flags:#x}"
            );
        }
    }

    /// `CURLU_DEFAULT_SCHEME` stores `https` and does **not** mark it
    /// guessed.
    ///
    /// `lib/urlapi.c` L967-L968 stores it; nothing on that path touches
    /// `u->guessed_scheme`, which only `guess_scheme` sets at L1008. The
    /// asymmetry is observable through `CURLU_NO_GUESS_SCHEME` and is the
    /// seed of `FB1`; see `docs/KNOWN-DIVERGENCES.md`. Setting the flag here
    /// would suppress the scheme of every `CURLU_DEFAULT_SCHEME` parse read
    /// back under that flag.
    #[test]
    fn the_default_scheme_is_stored_but_not_marked_guessed() {
        let (result, stored, guessed) = resolve(b"example.com/path", b"", CURLU_DEFAULT_SCHEME);
        assert_eq!(result, Ok(0));
        assert_eq!(stored.as_deref(), Some(DEFAULT_SCHEME.as_bytes()));
        assert_eq!(stored.as_deref(), Some(&b"https"[..]));
        assert!(
            !guessed,
            "CURLU_DEFAULT_SCHEME must not set guessed_scheme; only guess_scheme() does"
        );
    }

    /// `CURLU_GUESS_SCHEME` on its own stores nothing.
    ///
    /// `lib/urlapi.c` L964-L968: the flag gets past the rejection but only
    /// `CURLU_DEFAULT_SCHEME` assigns `schemep`, so the store at L976 is
    /// skipped and the field stays absent. That is exactly the state the
    /// `!u->scheme` guard at L1151 is looking for when it decides to call
    /// `guess_scheme`.
    #[test]
    fn the_guess_flag_alone_leaves_the_scheme_for_later() {
        let (result, stored, guessed) = resolve(b"ftp.example.com/path", b"", CURLU_GUESS_SCHEME);
        assert_eq!(result, Ok(0));
        assert_eq!(stored, None);
        assert!(!guessed);
    }

    /// With both flags set the default wins and no guess ever runs.
    ///
    /// `lib/urlapi.c` L967 is not an `else if`, so `CURLU_DEFAULT_SCHEME`
    /// alone decides. Storing here is what makes the `!u->scheme` guard at
    /// L1151 fail, which is why `https://` and not `ftp://` comes out of an
    /// input whose host begins `ftp.`.
    #[test]
    fn the_default_scheme_beats_the_guess_flag() {
        let (result, stored, guessed) = resolve(
            b"ftp.example.com/path",
            b"",
            CURLU_DEFAULT_SCHEME | CURLU_GUESS_SCHEME,
        );
        assert_eq!(result, Ok(0));
        assert_eq!(stored.as_deref(), Some(&b"https"[..]));
        assert!(!guessed);
    }

    /// Runs `guess_scheme` on a fresh handle and reports what it stored.
    fn guess(hostname: &[u8]) -> (Option<alloc::vec::Vec<u8>>, bool) {
        let mut handle = CurlUrl::new();
        assert!(!handle.guessed_scheme(), "a fresh handle has not guessed");
        assert_eq!(guess_scheme(&mut handle, hostname), Ok(()));
        (handle.scheme().map(<[u8]>::to_vec), handle.guessed_scheme())
    }

    /// The six prefixes, each mapping to its own scheme, in any letter case.
    ///
    /// `lib/urlapi.c` L989-L1000. The rows are the ones
    /// `tests/libtest/lib1560.c` L698-L720 asserts through the public API.
    /// The case-insensitivity comes from `checkprefix` at
    /// `lib/strcase.h` L33, which is `curl_strnequal`.
    #[test]
    fn the_six_host_prefixes_map_to_their_schemes() {
        for (prefix, scheme) in GUESS_TABLE {
            let mut host = prefix.to_vec();
            host.extend_from_slice(b"example.com");
            assert_eq!(guess(&host), (Some(scheme.to_vec()), true), "host {host:?}");

            let upper: alloc::vec::Vec<u8> =
                host.iter().map(|byte| byte.to_ascii_uppercase()).collect();
            assert_eq!(
                guess(&upper),
                (Some(scheme.to_vec()), true),
                "host {upper:?}"
            );

            // The prefix on its own, with nothing after the dot, still
            // matches: `checkprefix` looks only as far as the literal.
            assert_eq!(guess(prefix), (Some(scheme.to_vec()), true));
        }
        // The table is the C's six rows, in the C's order.
        assert_eq!(
            GUESS_TABLE.map(|(prefix, _)| prefix),
            [
                &b"ftp."[..],
                b"dict.",
                b"ldap.",
                b"imap.",
                b"smtp.",
                b"pop3."
            ]
        );
    }

    /// Anything the table does not match guesses `http`, never `https`.
    ///
    /// `lib/urlapi.c` L1001-L1002. Three of these rows are the ones that
    /// catch a confusion with `DEFAULT_SCHEME`: `tests/libtest/lib1560.c`
    /// L701-L703 requires `https.example.com` to become `http://`, L740-L757
    /// requires the six dotless names to become `http://`, and L715-L721
    /// requires plain `example.com` to become `http://`.
    #[test]
    fn an_unmatched_host_guesses_http() {
        for host in [
            &b"www.example.com"[..],
            b"example.com",
            b"https.example.com",
            b"http.example.com",
            b"ftpx.example.com",
            b"ftp",
            b"smtp",
            b"dict",
            b"ldap",
            b"imap",
            b"pop3",
            b"ftp-example.com",
            b"xftp.example.com",
            b"",
            b"[::1]",
            b"127.0.0.1",
        ] {
            assert_eq!(
                guess(host),
                (Some(b"http".to_vec()), true),
                "host {host:?} must guess http"
            );
        }
        assert_eq!(GUESS_FALLBACK, b"http");
        assert_ne!(GUESS_FALLBACK, DEFAULT_SCHEME.as_bytes());
    }

    /// The trailing dot is part of every prefix.
    ///
    /// Without it, `smtp/path/html` would guess `smtp` where
    /// `tests/libtest/lib1560.c` L740-L742 requires `http`. The pairs below
    /// differ only in that byte.
    #[test]
    fn the_trailing_dot_decides() {
        for (prefix, scheme) in GUESS_TABLE {
            let dotted = prefix;
            let undotted = &prefix[..prefix.len() - 1];
            assert_eq!(guess(dotted).0.as_deref(), Some(scheme));
            assert_eq!(guess(undotted).0.as_deref(), Some(GUESS_FALLBACK));

            // And a byte other than the dot does not stand in for it.
            let mut hyphenated = undotted.to_vec();
            hyphenated.extend_from_slice(b"-example.com");
            assert_eq!(guess(&hyphenated).0.as_deref(), Some(GUESS_FALLBACK));
        }
    }

    /// The flag is set on the way out, after the copy has succeeded.
    ///
    /// `lib/urlapi.c` L1004-L1008 in that order. This is the only place in
    /// the port that sets it, so a handle reporting a guessed scheme can only
    /// have come through here.
    #[test]
    fn the_guess_marks_the_handle() {
        let mut handle = CurlUrl::new();
        assert!(!handle.guessed_scheme());
        assert_eq!(handle.scheme(), None);
        assert_eq!(guess_scheme(&mut handle, b"ftp.example.com"), Ok(()));
        assert_eq!(handle.scheme(), Some(&b"ftp"[..]));
        assert!(handle.guessed_scheme());
    }

    /// A guess replaces whatever the field held, without leaking it.
    ///
    /// The C assigns straight over `u->scheme` at L1004, which is sound there
    /// because L1151 only calls the function when the field is absent. The
    /// port releases first, through `CurlUrl::store`, so the same call is
    /// also correct on a populated handle. The observable behavior -- the new
    /// scheme, the flag set -- is identical either way; only the leak the C
    /// would take differs, and a leak is not observable through the URL API.
    #[test]
    fn a_guess_onto_a_populated_handle_replaces_the_scheme() {
        let mut handle = CurlUrl::new();
        assert_eq!(
            parse_scheme(b"https://x", &mut handle, KNOWN_SCHEME, 0),
            Ok(8)
        );
        assert_eq!(handle.scheme(), Some(&b"https"[..]));
        assert!(!handle.guessed_scheme());

        assert_eq!(guess_scheme(&mut handle, b"imap.example.com"), Ok(()));
        assert_eq!(handle.scheme(), Some(&b"imap"[..]));
        assert!(handle.guessed_scheme());
    }

    /// One row of [`the_three_stages_agree_with_the_oracle`], in order: the
    /// input; the caller's flag word; the offset the scheme stage should
    /// report, which is where the **authority** starts and so may still
    /// include userinfo and a port; the host name the authority stage would
    /// have distilled from that authority, which is what the guess runs on;
    /// the scheme the pipeline should end up storing, `None` meaning
    /// "whatever the detection copied out" for the one row whose scheme is
    /// forty bytes long; and the expected `guessed_scheme` flag.
    ///
    /// The offset and the host are separate fields on purpose. The offset is
    /// this module's own answer and is asserted exactly. The host is an input
    /// supplied by the row, because distilling it from the authority --
    /// stripping the credentials off the front and the port off the end --
    /// belongs to `src/parse/authority.rs` and is not re-derived here. The
    /// pair `about:80` shows why the two cannot be conflated: the authority
    /// is `about:80` and the host is `about`.
    ///
    /// Named rather than written inline because the tuple is wide enough that
    /// clippy asks for it, and because naming the six parts once is more use
    /// to a reader than a comment above the table would be.
    type OracleRow = (
        &'static [u8],
        c_uint,
        usize,
        &'static [u8],
        Option<&'static [u8]>,
        bool,
    );

    /// The three stages, run in `parseurl`'s own order over the rows of
    /// `tests/libtest/lib1560.c` that this module decides.
    ///
    /// Each row names the input, the caller's flags, and what the pipeline
    /// should have stored as the scheme by the time the authority has been
    /// parsed. It is an integration check across the module's three
    /// functions, standing in for the part of `src/parse/mod.rs` that
    /// sequences them, and it is what catches a mistake that leaves each
    /// function individually correct: passing the wrong guess mask, guessing
    /// from the input instead of the host, or comparing the scheme buffer
    /// before it was lower-cased.
    #[test]
    fn the_three_stages_agree_with_the_oracle() {
        let rows: &[OracleRow] = &[
            // tests/libtest/lib1560.c L698-L700 and its five siblings.
            (
                b"smtp.example.com/path/html",
                CURLU_GUESS_SCHEME,
                0,
                b"smtp.example.com",
                Some(b"smtp"),
                true,
            ),
            // L701-L703: `https.` is not in the table.
            (
                b"https.example.com/path/html",
                CURLU_GUESS_SCHEME,
                0,
                b"https.example.com",
                Some(b"http"),
                true,
            ),
            // L740-L742: no dot, so no match.
            (
                b"smtp/path/html",
                CURLU_GUESS_SCHEME,
                0,
                b"smtp",
                Some(b"http"),
                true,
            ),
            // L357-L360: the guess sees the host, not the input, so the
            // leading `ftp.` of the user name does not decide it. The offset
            // is zero and the authority still carries the credentials, which
            // is exactly why the guess cannot run until the authority stage
            // has finished with them.
            (
                b"ftp.user:moo@example.com/color/",
                CURLU_GUESS_SCHEME,
                0,
                b"example.com",
                Some(b"http"),
                true,
            ),
            // L353-L356: the same input shape with the prefix on the host.
            (
                b"user:moo@ftp.example.com/color/",
                CURLU_GUESS_SCHEME,
                0,
                b"ftp.example.com",
                Some(b"ftp"),
                true,
            ),
            // L810-L812: the default is stored and not marked guessed.
            (
                b"example.com/path/html",
                CURLU_DEFAULT_SCHEME,
                0,
                b"example.com",
                Some(b"https"),
                false,
            ),
            // L641: `about:80` under CURLU_DEFAULT_SCHEME is host `about`
            // and port 80, so the scheme is the default rather than `about`.
            // The colon survives into the authority and the authority stage
            // is what splits it off, which is why the offset is zero and the
            // host is shorter than the authority.
            (
                b"about:80",
                CURLU_DEFAULT_SCHEME,
                0,
                b"about",
                Some(b"https"),
                false,
            ),
            // L757: an explicit scheme is lower-cased and not guessed. Five
            // bytes of scheme, its colon and two slashes puts the authority
            // at 8.
            (b"HTTPS://test/", 0, 8, b"test", Some(b"https"), false),
            // L677-L681: the 40-byte scheme, admitted by
            // CURLU_NON_SUPPORT_SCHEME and stored lower-cased. Forty bytes,
            // the colon and two slashes puts the authority at 43.
            (
                b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://hostname/path",
                CURLU_NON_SUPPORT_SCHEME,
                43,
                b"hostname",
                None,
                false,
            ),
        ];

        for &(url, flags, expected_offset, host, expected_scheme, expected_guessed) in rows {
            let mut handle = CurlUrl::new();
            let mut buf = scheme_buf();

            // Stage 2, lib/urlapi.c L1128-L1130: the guess argument is the
            // masked flag word, not a single flag test.
            let guess_mask = (flags & (CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME)) != 0;
            let schemelen = is_absolute_url(url, Some(&mut buf), guess_mask);
            let scheme = c_string(&buf);
            assert_eq!(scheme.len(), schemelen, "input {url:?}");

            // Stage 3, L1138.
            let offset = parse_scheme(url, &mut handle, scheme, flags)
                .unwrap_or_else(|code| panic!("input {url:?} was rejected with {code}"));
            assert_eq!(offset, expected_offset, "input {url:?} authority offset");

            // The authority runs from the offset to the first of `/?#`, which
            // is `strcspn(hostp, "/?#")` at L1143. The row's host is a piece
            // of that authority rather than the whole of it, so the check
            // here is containment; distilling one from the other belongs to
            // `src/parse/authority.rs`.
            let authority = url[offset..]
                .split(|byte| matches!(byte, b'/' | b'?' | b'#'))
                .next()
                .unwrap_or_default();
            assert!(
                authority.windows(host.len()).any(|window| window == host),
                "input {url:?} authority {authority:?} does not contain host {host:?}"
            );

            // Stage 4, L1151-L1152, under exactly the C's two conditions.
            if (flags & CURLU_GUESS_SCHEME) != 0 && handle.scheme().is_none() {
                assert_eq!(guess_scheme(&mut handle, host), Ok(()), "input {url:?}");
            }

            // The 40-byte row stores its own scheme rather than one of the
            // literals above, so it is checked against the buffer instead.
            let expected = expected_scheme.unwrap_or(scheme);
            assert_eq!(handle.scheme(), Some(expected), "input {url:?}");
            assert_eq!(
                handle.guessed_scheme(),
                expected_guessed,
                "input {url:?} guessed flag"
            );
        }
    }
}
