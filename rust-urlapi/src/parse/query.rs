// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The fragment and query stages: two functions that only look like one.
//!
//! Port of `handle_fragment`, `lib/urlapi.c` L1012-L1034, and of
//! `handle_query`, L1036-L1064. `parseurl` runs them as the fifth and sixth
//! stages of its seven, calling them at L1168 and L1177, after the authority
//! is settled and before the path is handled.
//! `src/parse/mod.rs` owns that ordering and computes the two lengths; this
//! module only consumes them.
//!
//! Both functions are twenty-three lines of C and they differ in exactly
//! three places. Every one of the three is observable through the public
//! API, so both are written out in full below rather than derived from one
//! helper parameterised over the member. **Do not merge them.** The next
//! section says what merging would cost, and it is not a stylistic
//! objection: transformation rule T6 of the Agent Action Plan, faithful over
//! correct, governs this file as it governs `src/encode.rs`, which refuses
//! the same invitation for the same reason.
//!
//! # The three deliberate differences
//!
//! | # | Difference | `handle_fragment` | `handle_query` |
//! |---|---|---|---|
//! | 1 | the encoder's `query` argument | `FALSE` at L1022 | `TRUE` at L1046 |
//! | 2 | a lone delimiter | stores nothing | stores `""` at L1059 |
//! | 3 | the members written | `fragment`, `fragment_present` | `query`, `query_present` |
//!
//! ## Difference 1 changes the output bytes
//!
//! `urlencode_str` opens with `bool left = !query;` at L135, the negation,
//! and a space becomes `%20` while `left` holds and `+` once it does not.
//! Passing `FALSE` therefore starts the fragment in the `%20` state and
//! passing `TRUE` starts the query already in the `+` state. One set of
//! bytes, two answers, decided by this one argument.
//!
//! `tests/libtest/lib1560.c` asserts both halves, and in one case both in
//! the same URL. Setting the whole URL to
//! `http://example.net/there/it/is/../../tes t case=/0002? yes no` with
//! `CURLU_URLENCODE|CURLU_ALLOW_SPACE` must yield
//! `http://example.net/there/tes%20t%20case=/0002?+yes+no`: the spaces in
//! the path are `%20`, because `handle_path` also passes `FALSE` at L1073,
//! and the spaces in the query are `+`. The fragment side is pinned by
//! `https://curl.se/#  ` parsed with the same flags, whose fragment is
//! `%20%20`, and by `https://user@example.net?hello# space `, whose fragment
//! is `%20space%20` even though a `?` appeared earlier in the URL -- because
//! the `?` is not inside the slice this stage is handed.
//!
//! One consequence is faithful and surprising enough to be worth stating.
//! `left` also falls to false when a `?` is *copied through* the loop, at
//! L164-L165, and nothing sets it back. A fragment containing a question
//! mark therefore switches to the plus form part way along: `#a ?b c`
//! encodes to `a%20?b+c`. That is the C's behaviour and it is reproduced
//! rather than tidied; a test below pins it.
//!
//! ## Difference 2 is the single-delimiter empty-string case
//!
//! A bare `?` stores a freshly allocated empty string at L1059. A bare `#`
//! stores nothing at all and leaves the member absent. Both nevertheless set
//! their presence bit, at L1039 and L1016, because both bits are written
//! before the length is ever tested.
//!
//! The asymmetry is not redundancy. `curl_url_get` supports a blank value by
//! a different mechanism in each case, and neither mechanism covers the
//! other:
//!
//! - `CURLUPART_QUERY`, L1609-L1615, reads `u->query` and then discards it
//!   when it is empty *and* `CURLU_GET_EMPTY` is absent. It never consults
//!   `query_present`. So the empty string stored at L1059 is the only thing
//!   that distinguishes `http://x/?` from `http://x/`, and a port that left
//!   the member absent for a bare `?` would answer `CURLUE_NO_QUERY` where
//!   the C answers `""`.
//! - `CURLUPART_FRAGMENT`, L1617-L1622, reads `u->fragment` and substitutes
//!   `""` when it is absent, `fragment_present` is set *and*
//!   `CURLU_GET_EMPTY` is given. Here the bit is the only thing that
//!   distinguishes `http://x/#` from `http://x/`.
//!
//! `urlget_url` then needs both, at L1432-L1435: `show_fragment` tests
//! `u->fragment || (u->fragment_present && GET_EMPTY)` while `show_query`
//! tests `(u->query && u->query[0]) || (u->query_present && GET_EMPTY)` --
//! note the extra `u->query[0]`, which exists precisely because a stored
//! query may be empty and a stored fragment never is.
//!
//! Four `get_parts` cases in `tests/libtest/lib1560.c` fail the moment
//! either half is dropped: `https://curl.se/?` and `https://curl.se/#` and
//! `https://curl.se/?#` under `CURLU_GET_EMPTY`, which expect an empty
//! query, an empty fragment and both respectively, and the same inputs under
//! no flags, which expect `CURLUE_NO_QUERY` and `CURLUE_NO_FRAGMENT`.
//!
//! # The length governs, not the slice
//!
//! Both functions take a slice *and* a length, as the C takes a pointer and
//! a length, and the length is authoritative. That is load-bearing rather
//! than defensive, and the query is where it shows.
//!
//! `parseurl` handles the fragment first and then shortens its own
//! bookkeeping, `pathlen -= fraglen` at L1170, before locating the query
//! with `memchr(path, '?', pathlen)` at L1174. The resulting `qlen` stops
//! where the fragment starts -- but the bytes in memory do not, because
//! nothing has been copied or truncated. For `https://x/?a=b#f` this stage
//! receives bytes beginning `?a=b#f` and a `qlen` of `4`, and it must store
//! `a=b`. `tests/libtest/lib1560.c` pins it with
//! `https://user@example.net?hello# space `, whose query is `hello` and not
//! `hello# space `.
//!
//! The fragment has no such exposure, since L1165 finds it with an unbounded
//! `strchr` and it runs to the end of the input, but the two are written the
//! same way so that neither can drift.
//!
//! # Ownership
//!
//! Every buffer stored here comes from `crate::alloc`, so it lives in the C
//! allocator and the caller's `curl_free()` releases it correctly. That is
//! the documented contract at `docs/libcurl/curl_url_get.md`:L45, and it is
//! why `CString::into_raw` is banned crate-wide: its pointer has to come
//! back to Rust to be released. `docs/MEMORY-OWNERSHIP.md` carries the whole
//! chain.
//!
//! Neither C function releases a previous value before overwriting the
//! member, and no explicit release is added here either. Both are reachable
//! only from `parseurl`, which parses into a zeroed temporary and swaps it
//! into the live handle only on success, L1197-L1209, so the member is
//! always absent on entry and there is nothing a release could reach.
//! Inserting a defensive one would be a behaviour change dressed up as a
//! safety fix, and it would obscure that the C's assignments are bare
//! assignments.
//!
//! One difference from C follows from the types rather than from a decision,
//! and is stated so it is not mistaken for one. Storing into an
//! `Option<CBuf>` runs the displaced value's `Drop`, so on the unreachable
//! path where a member did already hold a buffer, Rust releases it where C
//! would leak the pointer. That is the same argument `crate::handle`'s
//! `clear` makes about `FB2`: reproducing the observable behaviour is the
//! requirement, reproducing a leak is not, and no leak is observable through
//! the URL API.
//!
//! # Visibility
//!
//! Both C functions are `static` and neither is declared in
//! `lib/urlapi-int.h`, so neither is a symbol of the object file this crate
//! replaces. They are `pub(crate)` here and carry no `#[no_mangle]` and no
//! `extern "C"`, which is what keeps the exported set equal to the C object
//! file's -- acceptance criterion A2. Nothing outside this crate should be
//! able to name either of them.
//!
//! # Verification
//!
//! The unit tests below cover each difference on its own.
//!
//! End to end, the parity run over the unmodified `tests/libtest/lib1560.c` is
//! what is to settle it: the `get_parts`, `append` and `get_nothing` sub-tests
//! -- exit codes 4, 5 and 7 in the mapping the Agent Action Plan gives at
//! 0.6.8 -- all exercise this file, and `set_parts`, exit code 2, reaches it
//! through every whole-URL assignment. `rust-urlapi/scripts/run-parity.sh`
//! drives that run, and all four of those sub-tests pass in both link
//! modes.

// The plan puts every `unsafe` block in `src/ffi.rs` (AAP 0.3.3) and the
// technical specification forbids `unsafe` outside FFI code (1.3.2.1). This
// module needs none: it inspects slices and stores owned buffers, and both
// `crate::alloc` and `crate::dynbuf` are shaped so that a parse stage never
// sees a raw pointer. `forbid` rather than `deny`, so that an inner `allow`
// has to be argued for rather than slipped in.
#![forbid(unsafe_code)]

use core::ffi::c_uint;

use crate::abi::{CURLUcode, CURLUE_OK, CURLUE_OUT_OF_MEMORY};
use crate::abi::{CURLU_URLENCODE, CURL_MAX_INPUT_LENGTH};
use crate::alloc::CBuf;
use crate::dynbuf::DynBuf;
use crate::encode::urlencode_str;
use crate::handle::{CurlUrl, StringField};

/// Records the fragment on the handle, reproducing `handle_fragment`.
///
/// `lib/urlapi.c` L1012-L1034. The module documentation carries the three
/// differences from [`handle_query`] and the reason the two are not one
/// function.
///
/// # Parameters
///
/// - `u`: the handle under construction. Always a freshly zeroed temporary
///   in practice, per L1197-L1209, so `fragment` is absent on entry.
/// - `fragment`: the bytes from the `#` onward, delimiter included, as the C
///   receives `fragment` pointing at the `#` it found at L1165.
/// - `fraglen`: how many of those bytes belong to the fragment, delimiter
///   included, as computed at L1167. A slice longer than this is clamped;
///   the length is authoritative.
/// - `flags`: the caller's flag word. Only `CURLU_URLENCODE` is consulted,
///   at L1019.
///
/// # Returns
///
/// `CURLUE_OK`, which is L1033 and every path that reaches it, or
/// `CURLUE_OUT_OF_MEMORY` from L1030, or whatever
/// [`crate::encode::urlencode_str`] reported at L1023 -- which is
/// `CURLUE_TOO_LARGE` or `CURLUE_OUT_OF_MEMORY`, already folded through
/// `crate::error::cc2cu` by that function.
#[must_use = "the result code reports a failed allocation and must be handled"]
pub(crate) fn handle_fragment(
    u: &mut CurlUrl,
    fragment: &[u8],
    fraglen: usize,
    flags: c_uint,
) -> CURLUcode {
    // L1016, and it is the first statement for a reason: the bit is set
    // before the length is tested, so a bare `#` sets it even though the
    // branch below then stores nothing. That combination is the whole of
    // difference 2 on this side, and `CURLU_GET_EMPTY` reads it at L1620.
    u.set_fragment_present(true);

    // L1017. Strictly greater than one, so a slice carrying only the `#`
    // falls straight through to L1033 with the member left absent.
    if fraglen > 1 {
        // L1018 in the C: "skip the leading '#' in the copy but include the
        // terminating null". The skip is the `fragment + 1` and `fraglen - 1`
        // of L1022 and L1028; the terminator comes from whichever branch
        // below runs, since both `crate::dynbuf` and `crate::alloc`
        // guarantee one.
        //
        // `get` and `saturating_sub` rather than `+ 1` and `- 1` because the
        // crate root denies direct indexing and unchecked arithmetic. Both
        // are exact here: the guard above has already established a length of
        // at least two, and a shorter slice can only make `tail` emptier,
        // never make either expression wrong.
        let tail = fragment.get(1..).unwrap_or_default();
        let bodylen = fraglen.saturating_sub(1);

        if (flags & CURLU_URLENCODE) != 0 {
            // L1021: the ceiling is `CURL_MAX_INPUT_LENGTH`, not the length
            // of this fragment. Encoding can treble a byte, so sizing the
            // buffer to the input would reject inputs the C accepts.
            let mut enc = DynBuf::new(CURL_MAX_INPUT_LENGTH);
            // L1022, and the `false` is difference 1. `relative` is `true`,
            // which suppresses the verbatim host prefix: there is no
            // authority inside a fragment, and copying one would be wrong
            // rather than merely wasteful.
            let result = urlencode_str(&mut enc, tail, bodylen, true, false);
            if result != CURLUE_OK {
                // L1023-L1024. Nothing is released here and nothing needs to
                // be: a failed append has already freed the buffer, which is
                // contract 1 of `src/dynbuf.rs` and matches `dyn_nappend` at
                // `lib/curlx/dynbuf.c`, and dropping `enc` covers every other
                // way out.
                return result;
            }
            // L1025, `u->fragment = curlx_dyn_ptr(&enc)`, ownership and all.
            // Assigned through the slot rather than stored, so that the null
            // case is transcribed as well as the ordinary one: `into_cbuf`
            // yields `None` exactly where `curlx_dyn_ptr` yields NULL, and
            // the C assigns that null without treating it as an error. It is
            // unreachable from here -- the guard above forces at least one
            // byte to be appended -- and is written out anyway rather than
            // asserted away, because an assertion would be a panic path.
            *u.field_mut(StringField::Fragment) = enc.into_cbuf();
        } else {
            // L1027-L1031, `curlx_memdup0(fragment + 1, fraglen - 1)`. The
            // clamp is where a slice longer than `fraglen` is cut back to it.
            let body = tail.get(..bodylen).unwrap_or(tail);
            let Some(copy) = CBuf::from_slice(body) else {
                return CURLUE_OUT_OF_MEMORY;
            };
            u.store(StringField::Fragment, copy);
        }
    }

    // L1033. There is deliberately no `else` on L1017: a bare `#` leaves the
    // member absent, and only the presence bit records that it was there.
    // Compare [`handle_query`], which does have one.
    CURLUE_OK
}

/// Records the query on the handle, reproducing `handle_query`.
///
/// `lib/urlapi.c` L1036-L1064. Read it beside [`handle_fragment`]: the two
/// are the same twenty-three lines apart from the three differences the
/// module documentation lists, and the `else` branch at the end is the one
/// that is easiest to lose and hardest to notice missing.
///
/// # Parameters
///
/// - `u`: the handle under construction, with `query` absent on entry for
///   the reason [`handle_fragment`] gives.
/// - `query`: the bytes from the `?` onward, delimiter included, as the C
///   receives `query` pointing at the `?` found at L1174.
/// - `qlen`: how many of those bytes belong to the query, delimiter
///   included, as computed at L1176. This stops short of any fragment while
///   the slice does not, so the clamp below is what keeps fragment bytes out
///   of the query.
/// - `flags`: the caller's flag word. Only `CURLU_URLENCODE` is consulted,
///   at L1041.
///
/// # Returns
///
/// `CURLUE_OK`, which is L1063, or `CURLUE_OUT_OF_MEMORY` from L1054 or
/// L1061, or whatever [`crate::encode::urlencode_str`] reported at L1047.
#[must_use = "the result code reports a failed allocation and must be handled"]
pub(crate) fn handle_query(u: &mut CurlUrl, query: &[u8], qlen: usize, flags: c_uint) -> CURLUcode {
    // L1039, unconditional and first, exactly as at L1016. `urlget_url`
    // reads it at L1435 and `urlset_clear` clears it at L1767.
    u.set_query_present(true);

    if qlen > 1 {
        // L1045 in the C: "skip the leading question mark". Same two
        // expressions as L1018's, and exact for the same reason.
        let tail = query.get(1..).unwrap_or_default();
        let bodylen = qlen.saturating_sub(1);

        if (flags & CURLU_URLENCODE) != 0 {
            // L1041-L1050. L1044's ceiling is `CURL_MAX_INPUT_LENGTH` here
            // too, and for the same reason.
            let mut enc = DynBuf::new(CURL_MAX_INPUT_LENGTH);
            // L1046, and the `true` is difference 1: `urlencode_str` starts
            // with `left` already false, so the first space becomes `+` with
            // no `?` needed to get there. `relative` is `true`, as at L1022.
            let result = urlencode_str(&mut enc, tail, bodylen, true, true);
            if result != CURLUE_OK {
                // L1047-L1048; the buffer is already released.
                return result;
            }
            // L1049, `u->query = curlx_dyn_ptr(&enc)`. Assigned through the
            // slot for the reason L1025 is.
            *u.field_mut(StringField::Query) = enc.into_cbuf();
        } else {
            // L1051-L1055, `curlx_memdup0(query + 1, qlen - 1)`. This clamp
            // is the one that matters: for `https://x/?a=b#f` the slice
            // continues into the fragment and `qlen` does not.
            let body = tail.get(..bodylen).unwrap_or(tail);
            let Some(copy) = CBuf::from_slice(body) else {
                return CURLUE_OUT_OF_MEMORY;
            };
            u.store(StringField::Query, copy);
        }
    } else {
        // L1057-L1062, `u->query = curlx_strdup("")` under the C's own
        // comment "single byte query". THIS BRANCH IS DIFFERENCE 2 and it
        // has no counterpart in [`handle_fragment`]. It is what makes
        // `curl_url_get(u, CURLUPART_QUERY, &p, CURLU_GET_EMPTY)` answer `""`
        // rather than `CURLUE_NO_QUERY` for `http://x/?`, because L1609-L1615
        // never looks at `query_present`. Deleting it, or folding these two
        // functions into one that cannot express it, silently breaks four
        // assertions in `tests/libtest/lib1560.c`.
        //
        // `CBuf::from_slice` on an empty slice yields a one-byte block
        // holding just the terminator, never `None`, which is precisely
        // `curlx_strdup("")`; only a genuine allocation failure takes the
        // `else` below, and the C treats that the same way at L1060-L1061.
        let Some(empty) = CBuf::from_slice(b"") else {
            return CURLUE_OUT_OF_MEMORY;
        };
        u.store(StringField::Query, empty);
    }

    CURLUE_OK
}

#[cfg(test)]
mod tests {
    use super::{handle_fragment, handle_query};
    use crate::abi::{CURLUE_OK, CURLU_ALLOW_SPACE, CURLU_GET_EMPTY, CURLU_URLENCODE};
    use crate::handle::CurlUrl;
    use core::ffi::c_uint;

    /// A fresh handle, which is what `parseurl` always hands these two
    /// functions: it parses into a zeroed temporary and swaps on success,
    /// `lib/urlapi.c` L1197-L1209.
    fn handle() -> CurlUrl {
        CurlUrl::new()
    }

    /// A lone `#` sets the presence bit and stores nothing.
    ///
    /// L1016 runs, L1017 does not, and there is no `else`. Half of
    /// difference 2, and the half that is easy to get right by accident;
    /// `a_lone_question_mark_stores_an_empty_string` is the half that is not.
    #[test]
    fn a_lone_hash_sets_the_present_bit_and_stores_nothing() {
        let mut u = handle();
        assert_eq!(handle_fragment(&mut u, b"#", 1, 0), CURLUE_OK);
        assert!(u.fragment_present());
        assert_eq!(u.fragment(), None);
    }

    /// A lone `?` sets the presence bit *and* stores an empty string.
    ///
    /// The regression guard for difference 2. The assertion is deliberately
    /// `Some(b"")` and not merely "not `None`": the member has to be present
    /// and empty, because L1613 discriminates on `!ptr[0]` and L1434 on
    /// `u->query[0]`. A port that stored nothing here would still pass
    /// `query_present()` and would fail four `get_parts` cases in
    /// `tests/libtest/lib1560.c`.
    #[test]
    fn a_lone_question_mark_stores_an_empty_string() {
        let mut u = handle();
        assert_eq!(handle_query(&mut u, b"?", 1, 0), CURLUE_OK);
        assert!(u.query_present());
        assert_eq!(u.query(), Some(b"".as_slice()));
    }

    /// The `> 1` guard, at the other boundary: a zero length behaves as a
    /// length of one, in both functions and in their two different ways.
    ///
    /// `parseurl` cannot produce it, since a delimiter was found before
    /// either function is called, but the guard is `> 1` rather than `!= 1`
    /// and the two sides of it are worth pinning independently of how they
    /// are reached.
    #[test]
    fn a_zero_length_takes_the_same_branch_as_a_lone_delimiter() {
        let mut frag = handle();
        assert_eq!(handle_fragment(&mut frag, b"", 0, 0), CURLUE_OK);
        assert!(frag.fragment_present());
        assert_eq!(frag.fragment(), None);

        let mut qry = handle();
        assert_eq!(handle_query(&mut qry, b"", 0, 0), CURLUE_OK);
        assert!(qry.query_present());
        assert_eq!(qry.query(), Some(b"".as_slice()));
    }

    /// The delimiter is dropped and the rest is stored verbatim.
    ///
    /// `curlx_memdup0(fragment + 1, fraglen - 1)` at L1028, with no encoding
    /// flag, so nothing is transformed.
    #[test]
    fn a_fragment_is_stored_without_its_delimiter() {
        let mut u = handle();
        assert_eq!(handle_fragment(&mut u, b"#abc", 4, 0), CURLUE_OK);
        assert!(u.fragment_present());
        assert_eq!(u.fragment(), Some(b"abc".as_slice()));
    }

    /// The query counterpart of the above: L1052, delimiter dropped, bytes
    /// untouched.
    #[test]
    fn a_query_is_stored_without_its_delimiter() {
        let mut u = handle();
        assert_eq!(handle_query(&mut u, b"?a=b", 4, 0), CURLUE_OK);
        assert!(u.query_present());
        assert_eq!(u.query(), Some(b"a=b".as_slice()));
    }

    /// Without `CURLU_URLENCODE` a space survives as a space.
    ///
    /// `tests/libtest/lib1560.c` asserts it through
    /// `https://user@example.net?he l lo` parsed with `CURLU_ALLOW_SPACE`
    /// alone, whose query reads back as `he l lo`.
    #[test]
    fn without_the_encode_flag_a_space_is_stored_as_a_space() {
        let mut u = handle();
        assert_eq!(handle_query(&mut u, b"?he l lo", 8, 0), CURLUE_OK);
        assert_eq!(u.query(), Some(b"he l lo".as_slice()));
    }

    /// Difference 1, both sides, in one test so that neither can regress
    /// alone.
    ///
    /// `FALSE` at L1022 leaves `urlencode_str` in its `%20` state; `TRUE` at
    /// L1046 starts it in its `+` state. `tests/libtest/lib1560.c` pins the
    /// fragment side with `https://curl.se/#  ` under
    /// `CURLU_URLENCODE|CURLU_ALLOW_SPACE`, whose fragment is `%20%20`, and
    /// the query side with the whole-URL assignment whose ` yes no` becomes
    /// `+yes+no`.
    #[test]
    fn encoding_gives_a_fragment_percent_twenty_and_a_query_plus() {
        let mut frag = handle();
        assert_eq!(
            handle_fragment(&mut frag, b"#a b", 4, CURLU_URLENCODE),
            CURLUE_OK
        );
        assert_eq!(frag.fragment(), Some(b"a%20b".as_slice()));

        let mut qry = handle();
        assert_eq!(
            handle_query(&mut qry, b"?a b", 4, CURLU_URLENCODE),
            CURLUE_OK
        );
        assert_eq!(qry.query(), Some(b"a+b".as_slice()));
    }

    /// Two spaces, as `tests/libtest/lib1560.c` spells the fragment case.
    ///
    /// `https://curl.se/#  ` parsed with `CURLU_URLENCODE|CURLU_ALLOW_SPACE`
    /// has the fragment `%20%20`. `CURLU_ALLOW_SPACE` is what got the spaces
    /// past `Curl_junkscan` and has no meaning to this stage, which is the
    /// point of passing it here: only `CURLU_URLENCODE` is read.
    #[test]
    fn an_all_space_fragment_encodes_to_percent_twenty_twice() {
        let mut u = handle();
        assert_eq!(
            handle_fragment(&mut u, b"#  ", 3, CURLU_URLENCODE | CURLU_ALLOW_SPACE),
            CURLUE_OK
        );
        assert_eq!(u.fragment(), Some(b"%20%20".as_slice()));
    }

    /// A `?` inside the fragment flips the space rule part way along.
    ///
    /// `left` starts true because L1022 passes `FALSE`, and falls at
    /// L164-L165 when the `?` is copied through. Faithful and surprising; the
    /// module documentation says why it is reproduced rather than tidied.
    #[test]
    fn a_question_mark_inside_a_fragment_switches_to_the_plus_form() {
        let mut u = handle();
        assert_eq!(
            handle_fragment(&mut u, b"#a ?b c", 7, CURLU_URLENCODE),
            CURLUE_OK
        );
        assert_eq!(u.fragment(), Some(b"a%20?b+c".as_slice()));
    }

    /// A control byte in the query is escaped, upper-case, as `%02`.
    ///
    /// `urlencode_str` escapes every byte below `0x20` and every byte from
    /// `0x7f` up, at L157-L161. `tests/libtest/lib1560.c` asserts the same
    /// transformation on the append path, where `name=joe\x02` becomes
    /// `name=joe%02`.
    ///
    /// The byte is written as a numeric escape rather than literally so that
    /// `scripts/spacecheck.pl` sees no control byte in this file.
    #[test]
    fn a_control_byte_in_the_query_is_percent_escaped() {
        let mut u = handle();
        assert_eq!(
            handle_query(&mut u, b"?name=joe\x02", 10, CURLU_URLENCODE),
            CURLUE_OK
        );
        assert_eq!(u.query(), Some(b"name=joe%02".as_slice()));
    }

    /// A high byte is escaped too, upper-case, and is not mistaken for the
    /// start of anything.
    ///
    /// L157's upper bound is `>= 0x7f`, so `0x7f` itself is escaped. That is
    /// a wider set than the decoder's, which `src/decode.rs` documents.
    #[test]
    fn a_high_byte_in_the_fragment_is_percent_escaped() {
        let mut u = handle();
        assert_eq!(
            handle_fragment(&mut u, b"#a\x7f\xffz", 5, CURLU_URLENCODE),
            CURLUE_OK
        );
        assert_eq!(u.fragment(), Some(b"a%7F%FFz".as_slice()));
    }

    /// The length wins over the slice, on the copy path.
    ///
    /// This is the shape `parseurl` really produces: L1170 shortens `pathlen`
    /// past the fragment before L1174 finds the `?`, so `qlen` stops at the
    /// `#` while the bytes carry on. Storing `a=b#f` here would be wrong, and
    /// `tests/libtest/lib1560.c` catches it through
    /// `https://user@example.net?hello# space `, whose query is `hello`.
    #[test]
    fn the_query_length_bounds_the_copy_short_of_a_following_fragment() {
        let mut u = handle();
        assert_eq!(handle_query(&mut u, b"?a=b#f", 4, 0), CURLUE_OK);
        assert_eq!(u.query(), Some(b"a=b".as_slice()));
    }

    /// The length wins over the slice on the encoding path as well.
    ///
    /// `urlencode_str` is handed the same `bodylen`, so the fragment's bytes
    /// never enter the encoder and cannot contribute a stray `%20` -- or, via
    /// its `?` rule, change what a later space becomes.
    #[test]
    fn the_query_length_bounds_the_encoder_too() {
        let mut u = handle();
        assert_eq!(
            handle_query(&mut u, b"?he lo# f", 6, CURLU_URLENCODE),
            CURLUE_OK
        );
        assert_eq!(u.query(), Some(b"he+lo".as_slice()));
    }

    /// The fragment side of the same clamp.
    ///
    /// L1165 finds the fragment with an unbounded `strchr`, so in the real
    /// pipeline `fraglen` reaches the end of the input and there is nothing
    /// to clamp. The clamp is still written, and still tested, so that the
    /// two functions cannot drift apart on a detail that is invisible from
    /// the call site.
    #[test]
    fn the_fragment_length_bounds_the_copy() {
        let mut u = handle();
        assert_eq!(handle_fragment(&mut u, b"#abcdef", 4, 0), CURLUE_OK);
        assert_eq!(u.fragment(), Some(b"abc".as_slice()));
    }

    /// Only `CURLU_URLENCODE` is consulted. Every other bit is ignored.
    ///
    /// L1019 and L1041 mask for that one flag, so `CURLU_GET_EMPTY`, which
    /// decides what the *getter* does with a blank value, must not change
    /// what is stored here, and neither must anything else. Asserted by
    /// setting every bit except `CURLU_URLENCODE` and requiring the verbatim
    /// copy.
    #[test]
    fn no_flag_but_the_encode_flag_changes_what_is_stored() {
        let everything_else: c_uint = !CURLU_URLENCODE;
        assert_eq!(everything_else & CURLU_URLENCODE, 0);
        assert_eq!(everything_else & CURLU_GET_EMPTY, CURLU_GET_EMPTY);

        let mut frag = handle();
        assert_eq!(
            handle_fragment(&mut frag, b"#a b", 4, everything_else),
            CURLUE_OK
        );
        assert_eq!(frag.fragment(), Some(b"a b".as_slice()));

        let mut qry = handle();
        assert_eq!(
            handle_query(&mut qry, b"?a b", 4, everything_else),
            CURLUE_OK
        );
        assert_eq!(qry.query(), Some(b"a b".as_slice()));
    }

    /// Neither function touches the other's members, which is difference 3.
    ///
    /// The guard against a merge that parameterises over the field and then
    /// gets the parameter wrong at one of the two call sites in
    /// `src/parse/mod.rs`.
    #[test]
    fn each_function_writes_only_its_own_members() {
        let mut frag = handle();
        assert_eq!(handle_fragment(&mut frag, b"#f", 2, 0), CURLUE_OK);
        assert_eq!(frag.fragment(), Some(b"f".as_slice()));
        assert!(frag.fragment_present());
        assert_eq!(frag.query(), None);
        assert!(!frag.query_present());

        let mut qry = handle();
        assert_eq!(handle_query(&mut qry, b"?q", 2, 0), CURLUE_OK);
        assert_eq!(qry.query(), Some(b"q".as_slice()));
        assert!(qry.query_present());
        assert_eq!(qry.fragment(), None);
        assert!(!qry.fragment_present());
    }

    /// Both stages on one handle, in `parseurl`'s order: fragment at L1168,
    /// then query at L1177.
    ///
    /// For `https://curl.se/?#` the fragment slice is `#` with a length of
    /// one and the query slice is `?#` with a length of one, because L1170
    /// took the fragment's byte off `pathlen` first. The result is the
    /// combination `tests/libtest/lib1560.c` expects under
    /// `CURLU_GET_EMPTY`: an empty query and an empty fragment, reached by
    /// the two different mechanisms.
    #[test]
    fn a_bare_query_and_a_bare_fragment_together() {
        let mut u = handle();
        assert_eq!(handle_fragment(&mut u, b"#", 1, 0), CURLUE_OK);
        assert_eq!(handle_query(&mut u, b"?#", 1, 0), CURLUE_OK);

        assert!(u.fragment_present());
        assert_eq!(u.fragment(), None);
        assert!(u.query_present());
        assert_eq!(u.query(), Some(b"".as_slice()));
    }
}
