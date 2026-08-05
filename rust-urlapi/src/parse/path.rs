// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The path stage: dot-segment removal, and the path field of the handle.
//!
//! Three C functions and one macro live here, and the module map in
//! `rust-urlapi/docs/PORTING-NOTES.md` assigns all four to this file:
//!
//! | C | `lib/urlapi.c` | role |
//! |---|---|---|
//! | `is_dot` | L682-L697 | dot detection, literal and percent-encoded |
//! | `ISSLASH` | L699 | one-byte predicate, used only by `dedotdotify` |
//! | `dedotdotify` | L716-L821 | RFC 3986 section 5.2.4 dot-segment removal |
//! | `handle_path` | L1066-L1108 | step 8 of the parse pipeline |
//!
//! # What reaches this module, and what it may assume
//!
//! `parseurl` calls `handle_path(u, path, pathlen, flags)` at L1183, and the
//! comment above that line states the precondition: "the fragment and query
//! parts are trimmed off from the path". They are trimmed by the two stages
//! immediately before, at L1165-L1171 and L1174-L1179, each of which
//! subtracts its own span from `pathlen` without moving `path`. So `path`
//! still points into the whole URL and `pathlen` is shorter than the bytes
//! that follow it. That is why [`handle_path`] takes a length beside the
//! slice rather than a slice already cut to size, exactly as
//! `crate::encode::urlencode_str` does for the same reason.
//!
//! The doc comment on `dedotdotify` at L709 restates the precondition from
//! the other side: "The function handles a path. It should not contain the
//! query nor fragment." This module relies on that and must not re-perform
//! the trimming, because a second pass would treat a `?` inside an
//! already-encoded path as a query delimiter.
//!
//! One further property is worth stating because the C leans on it and the
//! Rust port does not need to: by the time L1098 calls `dedotdotify`, the
//! bytes it is handed are always a freshly allocated, NUL-terminated copy of
//! exactly `pathlen` bytes -- either the encoder's buffer from L1077 or the
//! `curlx_memdup0` from L1086. The C's `is_dot` therefore reads a terminator
//! rather than running off the end when it is called with nothing left. Here
//! the cursor is a slice, so an empty cursor is simply an empty slice and no
//! terminator is involved.
//!
//! # The five RFC steps, and where each one is
//!
//! `lib/urlapi.c` L677-L680 cites
//! <https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.4> and then
//! transcribes the algorithm's steps as comments beside the code. The
//! lettering below is the C's own:
//!
//! - **A** and **D** run once, before the loop, at L728-L755. A strips a
//!   leading `./` or `../`; D removes an input consisting only of `.` or
//!   `..`. Both are inside a single `if(is_dot(...))`, so an input that does
//!   not begin with a dot skips the pair entirely.
//! - **B**, **C** and **E** are the loop body at L757-L809. B handles `/.`
//!   and `/./`, C handles `/..` and `/../` and is the only step that removes
//!   anything already written, and E is the fallthrough that copies input to
//!   output.
//!
//! Step E is where the code and its own comment disagree. The comment at
//! L801-L804 describes moving a whole path segment, up to but not including
//! the next slash. The code at L806-L808 appends **one byte**. The one-byte
//! form is what makes the `continue` arms of B and C correct, because each of
//! those leaves the cursor pointing at a slash that the next iteration has to
//! re-examine; a segment-at-a-time loop would have consumed it. This port
//! follows the code.
//!
//! # Oracles
//!
//! `tests/unit/unit1395.c` L39-L111 is the project's own table for
//! `dedotdotify`, seventy-one input and output pairs, driven at L115. It is
//! reproduced in this module's tests and is the authority for every
//! expectation here. Two of its rows are worth reading before changing
//! anything in this file: `{ "/..", "/" }` and `{ "/.", "/" }`. Both produce
//! a single slash rather than an empty output, because step C appends one at
//! L795 when the dot segment ends the input.
//!
//! The empty output has its own rows -- `{ "./", "" }`, `{ "..", "" }` and
//! `{ "../", "" }` -- and they are the reason the tail at L814-L818 allocates
//! an empty string instead of answering with a null pointer. The distinction
//! is observable through the public API and `tests/libtest/lib1560.c` L778
//! asserts it: `file:./` yields `file://`, not `file:///`. The path is set to
//! a zero-length string, and the whole-URL template at L1528 substitutes `/`
//! only for a null path.
//!
//! End to end, this module is to be exercised by the parity run over the
//! unmodified `tests/libtest/lib1560.c`. The two sub-tests that press hardest
//! on it are `set_url` and `get_url`, exit codes 1 and 3 in the table in
//! `AAP` 0.6.8, and the dot-segment cases they carry are at
//! `tests/libtest/lib1560.c` L779-L784, L1253-L1259, L1289-L1297 and
//! L1336-L1339. `rust-urlapi/scripts/run-parity.sh` is the script that is to
//! drive that run; it is a later deliverable and does not exist yet, so until
//! it does the tests at the foot of this file are the oracle in force.
//!
//! # No allocation escapes by accident
//!
//! Two functions here produce memory that the C side eventually frees with
//! `curl_free()`: [`dedotdotify`] hands back an owned `crate::alloc::CBuf`,
//! and [`handle_path`] stores one in the handle. Neither returns a raw
//! pointer, so the obligation stays typed until `src/ffi.rs` releases it into
//! C. `rust-urlapi/docs/MEMORY-OWNERSHIP.md` records the chain.

// Reachability here matches the C. `handle_path` is called from the parse
// pipeline at `lib/urlapi.c` L1183, so its consumer is `src/parse/mod.rs`,
// which declares `mod path;` and runs the stage from the same position;
// `src/getset.rs` reaches the dot-segment removal through the path setter.
// `is_dot` and `dedotdotify` are reached only from inside this file, and
// `dedotdotify` is additionally exported to C in unit-test builds of the
// original, which this port deliberately does not reproduce. Every consumer
// named here exists and is compiled unconditionally.
//
// No dead-code allowance is stated here. The crate-level one in `src/lib.rs`
// covers the whole feature matrix in one place, which is where the reason for
// it belongs; see "DEAD-CODE POLICY" there.

// The plan puts every `unsafe` block in `src/ffi.rs` (0.3.3) and the
// technical specification forbids `unsafe` outside FFI code (1.3.2.1).
// `forbid` rather than `deny` because an inner `allow` here would be a
// design change and should have to be argued for, not slipped in. This
// module needs nothing from C, so the attribute costs it nothing and turns
// the crate's single-unsafe-island property into a compiler guarantee
// instead of a convention.
#![forbid(unsafe_code)]

use core::ffi::c_uint;

use crate::abi::{
    CURLUcode, CURLUE_OK, CURLUE_OUT_OF_MEMORY, CURLU_PATH_AS_IS, CURLU_URLENCODE,
    CURL_MAX_INPUT_LENGTH,
};
use crate::alloc::CBuf;
use crate::dynbuf::DynBuf;
use crate::encode::urlencode_str;
use crate::handle::{CurlUrl, StringField};

/// Whether one byte is the path separator.
///
/// `ISSLASH(x)` at `lib/urlapi.c` L699, `((x) == '/')`. A backslash is *not*
/// a separator here, which matters: `parse_file` treats `\` as one at L917
/// and L924, but dot-segment removal does not, so `\..\` is ordinary path
/// content. Only `dedotdotify` uses the macro in the original, at L737, L749,
/// L758, L769 and L779, which is why this stays private to the module.
#[must_use]
const fn is_slash(byte: u8) -> bool {
    byte == b'/'
}

/// Whether a cursor's first byte is the path separator.
///
/// Stands in for the C's `ISSLASH(*p)`, which dereferences a pointer that may
/// be sitting on the terminator. Every C use is either guarded by a
/// non-zero-length test first -- L734 before L737, L746 before L749 -- or is
/// the left half of a disjunction whose right half is the length test, at
/// L779. An empty cursor therefore answers false in both languages: the C
/// reads a NUL, and this reads no byte at all.
#[must_use]
fn starts_with_slash(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(&byte) if is_slash(byte))
}

/// Drops the first byte of a cursor.
///
/// The C spells this `p + 1` at L739 and L751 and `&input[1]` at L759, always
/// on a cursor already known to hold at least one byte. Returning an empty
/// slice when it does not is the only defined answer available and keeps the
/// crate's ban on direct slicing intact; no call site in this module can
/// reach that case.
#[must_use]
fn drop_first(bytes: &[u8]) -> &[u8] {
    bytes.get(1..).unwrap_or_default()
}

/// Consumes a dot at the cursor, literal or percent-encoded, and reports
/// whether it did.
///
/// `is_dot` at `lib/urlapi.c` L682-L697. The C signature is
/// `static bool is_dot(const char **str, size_t *clen)` and both parameters
/// are in-out: a match advances `*str` past the dot and subtracts the same
/// amount from `*clen`. **The mutation is the mechanism**, not a convenience.
/// [`dedotdotify`] never re-derives a position; it calls this and then reads
/// whatever is left, so a non-mutating predicate cannot be substituted.
///
/// # Why one cursor rather than a pointer and a length
///
/// The C pair can desynchronize, and the two branches advance by different
/// amounts -- one byte at L686-L687 and three at L692-L693 -- so every branch
/// has to remember to touch both. A slice carries its own length, so the pair
/// collapses into one value and that whole class of bug disappears. The
/// remaining length is `cursor.len()`, which is exactly `*clen`.
///
/// # The two forms, byte for byte
///
/// - A literal `.`, L685-L689. **No length guard**, because the C reads
///   `*p` unconditionally; the callers only ever reach it with a byte
///   available, and where they do not the byte read is the string's
///   terminator. An empty slice matches neither arm here, which is the same
///   answer.
/// - The percent-encoded form, L690-L694. Guarded by `*clen >= 3`, which the
///   three-element slice pattern reproduces exactly. `(p[2] | 0x20) == 'e'`
///   is a single-byte case fold, so both `%2E` and `%2e` match. It is written
///   as the C writes it rather than as a case-insensitive comparison over the
///   slice, because the fold is one `or` against one byte and a reviewer
///   diffing this against L691 should see the same expression.
///
/// Note what the fold does *not* do. It only tests the third byte, so `%2` is
/// no match for want of a third byte, and `%2f` is no match because `f` folds
/// to `f`. `%2f` is the encoded form of the separator, and leaving it alone is
/// why `tests/unit/unit1395.c` L40 expects `%2f%2e%2e%2f/../a` to keep its
/// encoded prefix intact: no `/` character exists inside it, so step C finds
/// nothing to trim.
///
/// # Returns
///
/// `true` when a dot was consumed and the cursor has moved. `false` with the
/// cursor untouched otherwise, including for an empty cursor.
pub(crate) fn is_dot(cursor: &mut &[u8]) -> bool {
    // The inner reference is copied out first, and the copy is what the
    // arms match on. `&[u8]` is `Copy`, so this takes the cursor's value
    // rather than borrowing the slot, which is what lets an arm assign
    // through `cursor` while holding a binding taken from the same bytes.
    // Written without a type annotation on purpose: annotating it would make
    // the dereference look like one auto-deref could have performed, and it
    // is not -- the point is to copy.
    let bytes = *cursor;
    match bytes {
        // L685-L689. `rest` is the C's `(*str)++` and, because it is a
        // slice, its `(*clen)--` as well.
        [b'.', rest @ ..] => {
            *cursor = rest;
            true
        }
        // L690-L694. The three fixed elements are the `*clen >= 3` guard.
        [b'%', b'2', third, rest @ ..] if (*third | 0x20) == b'e' => {
            *cursor = rest;
            true
        }
        _ => false,
    }
}

/// The failure half of `dedotdotify`'s return value.
///
/// The C returns a plain `int`, not a `CURLUcode`: zero for success at L724
/// and L820, one for failure at L817 and L820. This zero-sized type is that
/// `int`'s failure value and nothing more.
///
/// # Why not carry a `CURLUcode` here
///
/// Because the C does not, and the difference is observable. Inside
/// `dedotdotify` a failed append can be either `CURLE_OUT_OF_MEMORY` or
/// `CURLE_TOO_LARGE`, per `lib/curlx/dynbuf.c` L84 and L108, and the C throws
/// that distinction away when it collapses the result to `1` at L820. Its
/// only caller then maps `1` to `CURLUE_OUT_OF_MEMORY` at
/// `lib/urlapi.c` L1099-L1100, so a too-large output is reported as an
/// out-of-memory error. A `Result<_, CURLUcode>` here would invite
/// propagating `CURLUE_TOO_LARGE` instead, which is a different answer for
/// the same input, and no type would object. Keeping the failure opaque
/// leaves the one mapping the C performs at the one site the C performs it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DedotFailure;

/// Removes dot segments from a path, per RFC 3986 section 5.2.4.
///
/// `dedotdotify` at `lib/urlapi.c` L716-L821, whose forward declaration at
/// L715 carries the `UNITTEST` marker so that `tests/unit/unit1395.c` can
/// reach it. That marker expands to `static` in an ordinary build, which is
/// why this is `pub(crate)` and carries no `#[no_mangle]`: it is not part of
/// the eight-symbol drop-in set, and an extra exported symbol would fail
/// acceptance criterion A2.
///
/// The module documentation carries the step lettering and the oracles. What
/// follows is the shape of the answer, which is the part a caller has to get
/// right.
///
/// # Parameters
///
/// - `input`: the path, with neither query nor fragment, per the C's own
///   precondition at L709. Its length is the C's `clen`.
///
/// # Returns
///
/// - `Ok(None)` -- **success with no output**, which the C spells as a zero
///   return with `*outp` left null at L721-L724. It means "nothing to do";
///   the caller keeps whatever path it already had. The C reaches it for an
///   input shorter than two bytes and, per the comment at L722, because "the
///   path always starts with a slash, and a slash has not dot".
/// - `Ok(Some(buf))` -- a replacement path, owned by the caller. It may be
///   **zero bytes long**, and that is a different answer from `Ok(None)`:
///   L814-L818 allocates an empty string rather than leaving the pointer
///   null, and [`handle_path`] installs whatever it is given. See the module
///   documentation for the `file:./` case that makes the difference visible.
/// - `Err(DedotFailure)` -- the output buffer could not be grown or the empty
///   string could not be allocated. One and one only mapping follows, in
///   [`handle_path`].
///
/// # Errors
///
/// [`DedotFailure`] on any allocation failure. The buffer has already been
/// released on that path: a failed append releases it, which is contract 1 of
/// `crate::dynbuf`, and every other exit drops it.
pub(crate) fn dedotdotify(input: &[u8]) -> Result<Option<CBuf>, DedotFailure> {
    // L721-L724. The C nulls the out-parameter first and then returns zero,
    // so a short input is a success that produces nothing.
    if input.len() < 2 {
        return Ok(None);
    }

    // L726: `curlx_dyn_init(&out, clen + 1)`. The ceiling is derived from the
    // input rather than from CURL_MAX_INPUT_LENGTH, and it is exact rather
    // than defensive: this function only ever removes bytes, so an output
    // that needed more room than the input plus a terminator would be a bug
    // in the port and the buffer would refuse the append. `saturating_add`
    // because the crate denies arithmetic that could wrap; an input of
    // `usize::MAX` bytes cannot exist, so the saturation is unreachable.
    let mut out = DynBuf::new(input.len().saturating_add(1));

    // The C's `input` and `clen`, as one value. Every assignment below
    // corresponds to a C assignment of both.
    let mut cursor: &[u8] = input;

    // L728-L755: steps A and D, once, before the loop.
    //
    // A. "If the input buffer begins with a prefix of `../` or `./`, then
    // remove that prefix from the input buffer".
    if is_dot(&mut cursor) {
        // L731-L732: `p = input; blen = clen`. The shadow pair exists so
        // that a second `is_dot` that matches but leads nowhere does not
        // disturb the real cursor. Probing on a copy and committing only on
        // success is that discipline, made structural.
        let mut probe: &[u8] = cursor;

        if cursor.is_empty() {
            // L734-L736: the input was exactly `.` or `%2e`. Jump to the
            // tail with the output still empty, which becomes an allocated
            // empty string.
            return finish(out);
        } else if starts_with_slash(probe) {
            // L737-L741: `./`. Consume the slash too.
            cursor = drop_first(probe);
        } else if is_dot(&mut probe) {
            // D. "if the input buffer consists only of `.` or `..`, then
            // remove that from the input buffer". L743-L754.
            if probe.is_empty() {
                // L746-L748: the input was exactly `..`, in any mixture of
                // literal and encoded dots. Empty output again.
                return finish(out);
            } else if starts_with_slash(probe) {
                // L749-L753: `../`. `input = p + 1` and `clen = blen - 1`
                // are one operation on a slice.
                cursor = drop_first(probe);
            }
            // L754 has no third arm, and the omission is deliberate. When
            // the second dot is followed by neither a slash nor the end of
            // the input, **nothing is consumed**: `cursor` still points just
            // past the first dot, and the loop below starts on the second
            // one and copies it out as ordinary content. So `..x` becomes
            // `.x` and `%2e%2ex` becomes `%2ex`, both confirmed against the
            // C. Committing the probe here would swallow a byte.
        }
    }

    // L757-L809: steps B, C and E.
    //
    // The C loop condition is `while(clen && !result)`, so a failed append
    // ends it. Here a failed append returns immediately, which reaches the
    // same place: the C falls through to L810 with a non-zero result, leaves
    // `*outp` null and answers 1.
    while !cursor.is_empty() {
        if starts_with_slash(cursor) {
            // L759-L760: `p = &input[1]; blen = clen - 1`.
            let mut probe: &[u8] = drop_first(cursor);

            // B. "if the input buffer begins with a prefix of `/./` or `/.`,
            // where `.` is a complete path segment, then replace that prefix
            // with `/`". L761-L773.
            if is_dot(&mut probe) {
                if probe.is_empty() {
                    // L765-L767: `/.` at the very end. One slash is written
                    // and the walk stops, which is why unit1395 expects
                    // `/1/.` to give `/1/` and `/.` to give `/`.
                    if out.addn(b"/").is_err() {
                        return Err(DedotFailure);
                    }
                    break;
                } else if starts_with_slash(probe) {
                    // L769-L772: `/./`. Commit the probe, which leaves the
                    // cursor on the second slash so the next iteration sees
                    // it, and write nothing.
                    cursor = probe;
                    continue;
                } else if is_dot(&mut probe) && (starts_with_slash(probe) || probe.is_empty()) {
                    // C. "if the input buffer begins with a prefix of `/../`
                    // or `/..`, where `..` is a complete path segment, then
                    // replace that prefix with `/` and remove the last
                    // segment and its preceding `/` (if any) from the output
                    // buffer". L775-L797.
                    //
                    // The second half of the guard is what makes the segment
                    // "complete": a third byte that is neither a slash nor
                    // the end means this is not a dot segment at all, and
                    // control falls through to step E with the cursor
                    // untouched. That is how `/..x` survives whole.
                    //
                    // L780-L788: remove the last segment from the output.
                    // The C reads the length at L781 and only searches when
                    // it is non-zero; a reverse search over an empty slice
                    // answers `None`, so that guard is subsumed rather than
                    // dropped. `memrchr` at L784 becomes `rposition`.
                    if let Some(index) = out.as_bytes().iter().rposition(|&byte| is_slash(byte)) {
                        // L787: `curlx_dyn_setlen(&out, last - ptr)` trims
                        // at the slash, so the slash goes with the segment.
                        // The C ignores this return value and the dynamic
                        // buffer's declaration is not WARN_UNUSED_RESULT.
                        if !out.setlen(index) {
                            // Unreachable: `index` came from a search over
                            // the current content, so it is strictly below
                            // the current length and the request is in
                            // bounds. Reported rather than asserted, because
                            // this crate has no panic paths, and a silently
                            // untrimmed output would be worse than an error.
                            return Err(DedotFailure);
                        }
                    }

                    if !probe.is_empty() {
                        // L790-L793: `/../`. As with `/./`, the cursor lands
                        // on the trailing slash and nothing is written.
                        cursor = probe;
                        continue;
                    }
                    // L795-L796: `/..` at the very end. One slash, then
                    // stop. `/..` therefore gives `/`, not an empty output;
                    // unit1395 L107 and L109 both pin that.
                    if out.addn(b"/").is_err() {
                        return Err(DedotFailure);
                    }
                    break;
                }
            }
        }

        // E. "move the first path segment in the input buffer to the end of
        // the output buffer". L801-L808. The C moves one byte, not one
        // segment; the module documentation explains why the code and its
        // comment differ and why the byte-at-a-time form is the correct one
        // to port.
        match cursor.split_first() {
            Some((&byte, rest)) => {
                if out.addn(&[byte]).is_err() {
                    return Err(DedotFailure);
                }
                cursor = rest;
            }
            // Unreachable: the loop condition established a non-empty
            // cursor. Ending the walk is the safe answer if it ever were.
            None => break,
        }
    }

    finish(out)
}

/// The tail of [`dedotdotify`], which is the C's `end:` label.
///
/// `lib/urlapi.c` L810-L820, reached by falling out of the loop and by the
/// two `goto end` jumps at L736 and L748. It is a function here because a
/// `goto` is not available and because the two jumps and the fallthrough must
/// not drift apart.
///
/// The C tests `curlx_dyn_len(&out)` at L812 and picks one of two answers.
/// This tests emptiness instead, so the predicate reads positively, and the
/// arms are otherwise the C's own:
///
/// - Empty output, L814-L818: `curlx_strdup("")`, a freshly allocated
///   zero-length string. **Not a null pointer.** The caller replaces the path
///   whenever the output is non-null, so this is what turns an input of `./`
///   into an empty path rather than leaving the path unchanged.
/// - Non-empty output, L812-L813: `*outp = curlx_dyn_ptr(&out)`, which hands
///   the block over and never frees it again.
///
/// # Errors
///
/// [`DedotFailure`] when the empty string cannot be allocated, which is the
/// C's `if(!*outp) return 1` at L816-L817.
fn finish(out: DynBuf) -> Result<Option<CBuf>, DedotFailure> {
    if out.is_empty() {
        // L815. An empty slice yields a one-byte block holding only the
        // terminator, per `crate::alloc::CBuf::from_slice`, which is what
        // `curlx_strdup("")` produces.
        return CBuf::from_slice(b"").map(Some).ok_or(DedotFailure);
    }
    // L813. Ownership moves out of the buffer and into the returned value,
    // so nothing is copied and nothing is freed twice. `None` cannot arise
    // here: a non-empty buffer has an allocation by construction. It is
    // handled rather than asserted, and the buffer is dropped on that arm
    // rather than leaked.
    out.into_cbuf().map(Some).ok_or(DedotFailure)
}

/// Step 8 of the parse pipeline: install the path, encoding and de-dotting it.
///
/// `handle_path` at `lib/urlapi.c` L1066-L1108, called once, from `parseurl`
/// at L1183. `static` in the C, so this is `pub(crate)` with no C linkage.
///
/// # Parameters
///
/// - `u`: the handle being filled. `parseurl` passes a zeroed temporary at
///   L1202, so its path is absent on entry and the atomic swap at L1204-L1207
///   means a failure here leaves the caller's live handle untouched.
/// - `path`: the bytes at the start of the path. It normally runs past the end
///   of the path, because the query and fragment stages trim `pathlen` without
///   moving the pointer; see the module documentation.
/// - `pathlen`: how many of those bytes are the path. Beyond `path.len()` it
///   is clamped, which is the only defined answer available; C would read past
///   the caller's buffer. `crate::encode::urlencode_str` clamps its own length
///   for the same reason.
/// - `flags`: the caller's `CURLU_*` set. Two bits are read here,
///   `CURLU_URLENCODE` and `CURLU_PATH_AS_IS`.
///
/// # The order of operations, and why it is not interchangeable
///
/// Encoding runs **before** dot-segment removal, L1070-L1078 before
/// L1095-L1105, and `tests/libtest/lib1560.c` L1336-L1339 is the case that
/// pins it: `/there/it/is/../../tes t case=/...` under
/// `CURLU_URLENCODE|CURLU_ALLOW_SPACE` becomes `/there/tes%20t%20case=/...`.
/// The spaces are escaped first and the dot segments are removed from the
/// escaped bytes.
///
/// In this order the encoder sees the whole path *before* any segment is
/// removed, and L1076 then replaces `pathlen` with the encoded length, which
/// is what every step after it works from -- the truncation at L1093 and the
/// de-dot call at L1098 both. Reversing the two would hand the encoder the
/// already-shortened path instead, so the length the later steps work from
/// would no longer be the encoded length of the input.
///
/// The encoder is called with `relative` true and `query` false, L1073. True
/// means "this is not a whole URL", so no authority prefix is copied through
/// verbatim; false means the space rule starts in its `%20` state and stays
/// there, because a path contains no `?` to flip it. Both are properties of
/// the part being encoded rather than choices.
///
/// # Returns
///
/// `crate::abi::CURLUE_OK`, or the encoder's own failure code from L1074-L1075,
/// or `crate::abi::CURLUE_OUT_OF_MEMORY` for a failed copy at L1088 or a
/// failed de-dot at L1099-L1100.
#[must_use = "the result code reports a parse failure and must be handled"]
pub(crate) fn handle_path(
    u: &mut CurlUrl,
    path: &[u8],
    pathlen: usize,
    flags: c_uint,
) -> CURLUcode {
    // The C trusts `pathlen` because its caller computed it from the same
    // string. A slice cannot be read past its end, so the length is brought
    // inside the slice once, here, and every use below is then in bounds by
    // construction. At the one real call site the two are already consistent.
    let mut pathlen = pathlen.min(path.len());

    // The C's local `path` is a pointer that starts at the caller's bytes and
    // is retargeted at `u->path` twice, at L1077 and at L1089. Everything
    // after those two lines reads through it, so which of the two it points
    // at decides what L1098 de-dots. This flag is that pointer's identity,
    // and it is tracked rather than inferred because the third combination --
    // a handle that already holds a path, with CURLU_URLENCODE clear -- takes
    // neither assignment and so still reads the caller's bytes. `parseurl`
    // hands over a zeroed handle at L1202 and cannot reach that combination,
    // but reproducing it costs one boolean and removes the only place this
    // port would otherwise have answered differently from the C.
    let mut path_from_handle = false;

    // L1070-L1078: percent-encode the path in place of copying it.
    if pathlen != 0 && (flags & CURLU_URLENCODE) != 0 {
        // L1072. The ceiling is CURL_MAX_INPUT_LENGTH here, not the input
        // length: encoding can triple a byte, so the output may legitimately
        // be longer than the input.
        let mut enc = DynBuf::new(CURL_MAX_INPUT_LENGTH);
        let result = urlencode_str(&mut enc, path, pathlen, true, false);
        if result != CURLUE_OK {
            // L1074-L1075. The buffer has already been released by the
            // failed append, contract 1 of `crate::dynbuf`; there is nothing
            // to clean up and freeing it again would be a double free.
            return result;
        }
        // L1076: the encoded length replaces the caller's length for the
        // rest of this function.
        pathlen = enc.len();
        // L1077: `path = u->path = curlx_dyn_ptr(&enc)`. The C stores the
        // pointer whether or not it is null and does not free what the field
        // held, which is safe there only because the field is known to be
        // null. Assigning the option covers both halves: `None` when nothing
        // was appended, which is the C's null, and a release of any previous
        // value as part of the assignment.
        //
        // From here on the handle owns the path bytes, and the C's local
        // `path` and `u->path` are the same pointer.
        *u.field_mut(StringField::Path) = enc.into_cbuf();
        path_from_handle = true;
    }

    // L1080-L1083: "there is no path left or just the slash, unset".
    //
    // The C nulls its local `path`, which disables both the copy and the
    // de-dot below and so ends the function. It does **not** clear `u->path`,
    // so an encoded buffer installed above survives. What survives is small:
    // the encode branch appends at least one byte, so reaching here with it
    // having run means `pathlen` is exactly one and the buffer holds exactly
    // one byte, which for every input `parseurl` can produce is the bare
    // slash. Returning early is the same control flow with the dead
    // assignment removed; the test module pins the surviving buffer.
    if pathlen <= 1 {
        return CURLUE_OK;
    }

    // The caller's bytes, cut to the length that is the path. This is the C's
    // `path` before either retargeting, and the only two places it is read
    // are the copy at L1086 and, in the combination that takes neither
    // retargeting, the de-dot at L1098.
    let window = path.get(..pathlen).unwrap_or(path);

    if !u.has(StringField::Path) {
        // L1086-L1089: `curlx_memdup0(path, pathlen)`, exactly `pathlen`
        // bytes plus a terminator. This is the ordinary path, taken whenever
        // CURLU_URLENCODE is clear.
        let Some(copy) = CBuf::from_slice(window) else {
            return CURLUE_OUT_OF_MEMORY;
        };
        u.store(StringField::Path, copy);
        // L1089: `path = u->path`.
        path_from_handle = true;
    } else if (flags & CURLU_URLENCODE) != 0 {
        // L1091-L1093: `u->path[pathlen] = 0`, whose comment reads "it might
        // have encoded more than just the path so cut it".
        //
        // FAITHFULLY REPRODUCED, AND IT IS A NO-OP. Do not delete it.
        // Transformation rule T6 says to reproduce surprising code rather
        // than tidy it, and the analysis is worth keeping beside it so that
        // nobody rediscovers this as dead code and removes something that
        // matters along with it:
        //
        // 1. This arm is reachable only when `u->path` is already set. The
        //    only assignment to it before this point is L1077, in the
        //    encode branch.
        // 2. That branch requires CURLU_URLENCODE, and this arm tests the
        //    same bit, so the two conditions agree rather than being
        //    independent.
        // 3. That branch also set `pathlen = curlx_dyn_len(&enc)` at L1076,
        //    one line earlier, and nothing has changed either since.
        //
        // So `pathlen` is the buffer's own length and the write lands on the
        // terminator the dynamic buffer already placed there. The C's
        // comment describes a cut that cannot happen, because the encoder
        // was handed the trimmed length and could not have run past it.
        //
        // `truncate` is the shape that write has in this crate: it shortens
        // and re-terminates, and it returns without doing anything when the
        // content is already that length -- which is this case, every time.
        // It is used rather than nothing at all so that the C's *intent*
        // survives too: were the arm ever reached with a shorter `pathlen`,
        // both languages would cut at `pathlen`.
        if let Some(buf) = u.field_mut(StringField::Path).as_mut() {
            buf.truncate(pathlen);
        }
    }
    // There is no third arm here, matching the C. The combination it would
    // cover -- a handle that already holds a path, with CURLU_URLENCODE clear
    // -- leaves both `u->path` and the C's `path` exactly as they were, which
    // `path_from_handle` records by staying false.

    // L1095-L1105: "remove ../ and ./ sequences according to RFC3986".
    if (flags & CURLU_PATH_AS_IS) == 0 {
        // L1098: `dedotdotify(path, pathlen, &dedot)`, over whichever bytes
        // the C's `path` points at. On the two retargeted paths that is the
        // handle's own buffer, whose length is `pathlen` because the copy at
        // L1086 and the encoder at L1076 each made it so; the fallback there
        // is unreachable, since the field was stored one branch earlier.
        // Otherwise it is the caller's window, untouched.
        let source = if path_from_handle {
            u.path().unwrap_or_default()
        } else {
            window
        };
        match dedotdotify(source) {
            // L1099-L1100. This is the single point at which the C's `int`
            // becomes a `CURLUcode`, and the only code it can become; see
            // `DedotFailure` for why the distinction is not carried further.
            Err(DedotFailure) => return CURLUE_OUT_OF_MEMORY,
            // L1101-L1104: `if(dedot) { curlx_free(u->path); u->path = dedot; }`.
            // A non-null output replaces the path and the old buffer is
            // released first, which the assignment inside `store` does.
            // The output may be zero bytes long, and storing it is what makes
            // that observable; see `dedotdotify` and the module
            // documentation.
            Ok(Some(dedot)) => u.store(StringField::Path, dedot),
            // A null output means the path is left exactly as it is, which
            // for an input shorter than two bytes is the only sensible
            // answer. `pathlen > 1` holds here, so the source is two bytes or
            // more and this arm is unreachable through either branch above;
            // it is spelled out because the C spells its own `if(dedot)` out.
            Ok(None) => {}
        }
    }

    CURLUE_OK
}

#[cfg(test)]
mod tests {
    // The crate root denies the panicking constructs so that no panic can
    // ever reach the C boundary. A test's whole job is to panic when an
    // assertion fails, and no test crosses that boundary, so the denials are
    // relaxed here and only here, enumerated rather than blanket. This is the
    // same allowance, for the same reason, as the one in `src/parse/junk.rs`.
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]

    // The comparisons below need somewhere to put a copy of an output, and
    // they reach the heap through the `alloc` crate rather than through `std`
    // so that this module compiles the same way whichever the crate root
    // turns out to declare. Every other import here comes from `core` or from
    // a sibling module.
    extern crate alloc;

    use core::ffi::c_uint;

    use super::{dedotdotify, handle_path, is_dot, is_slash, starts_with_slash, DedotFailure};
    use crate::abi::{CURLUcode, CURLUE_OK, CURLU_PATH_AS_IS, CURLU_URLENCODE};
    use crate::handle::{CurlUrl, StringField};
    use alloc::vec::Vec;

    /// Runs `is_dot` and reports both halves of what the C mutates: whether
    /// it matched, and how far the cursor moved.
    ///
    /// The C advances a pointer and decrements a length separately, at
    /// L686-L687 and L692-L693. One number covers both here, which is the
    /// whole point of the slice cursor.
    fn probe(input: &[u8]) -> (bool, usize) {
        let mut cursor: &[u8] = input;
        let matched = is_dot(&mut cursor);
        (matched, input.len() - cursor.len())
    }

    /// Runs `dedotdotify` and copies the output out, so that assertions can
    /// compare byte slices instead of buffers.
    ///
    /// `crate::alloc::CBuf` has no `PartialEq`, deliberately, so the content
    /// is copied. The `Result` and `Option` are preserved exactly, because
    /// the three outcomes are three different answers: see the function's own
    /// documentation.
    fn dedot(input: &[u8]) -> Result<Option<Vec<u8>>, DedotFailure> {
        dedotdotify(input).map(|out| out.map(|buf| buf.as_bytes().to_vec()))
    }

    /// The expectation shape of [`dedot`], spelled from a string literal.
    ///
    /// The `Result` wrapper is the point rather than an accident: an
    /// expectation written this way states all three of the outcomes at once,
    /// so a row that starts failing because the function errored reads
    /// differently from one that produced the wrong bytes.
    fn want(output: Option<&str>) -> Result<Option<Vec<u8>>, DedotFailure> {
        Ok(output.map(|text| text.as_bytes().to_vec()))
    }

    /// `ISSLASH(x)` is `((x) == '/')` and nothing else, L699. A backslash is
    /// not a separator for dot-segment removal even though `parse_file`
    /// treats it as one at L917 and L924.
    #[test]
    fn isslash_matches_only_the_forward_slash() {
        assert!(is_slash(b'/'));
        for byte in 0..=u8::MAX {
            assert_eq!(is_slash(byte), byte == b'/', "byte {byte:#04x}");
        }

        // The cursor form answers false for an empty cursor, which is where
        // the C reads a terminator: L779's disjunction relies on it.
        assert!(starts_with_slash(b"/x"));
        assert!(!starts_with_slash(b"x/"));
        assert!(!starts_with_slash(b"\\"));
        assert!(!starts_with_slash(b""));
    }

    /// The literal-dot branch, L685-L689: one byte consumed, no length guard.
    #[test]
    fn is_dot_consumes_a_literal_dot() {
        assert_eq!(probe(b"."), (true, 1));
        assert_eq!(probe(b"./"), (true, 1));
        assert_eq!(probe(b".."), (true, 1));
        assert_eq!(probe(b".%2e"), (true, 1));
    }

    /// The percent-encoded branch, L690-L694: three bytes consumed, and the
    /// `| 0x20` fold accepts either case of the final byte.
    #[test]
    fn is_dot_consumes_either_case_of_the_encoded_dot() {
        assert_eq!(probe(b"%2e"), (true, 3));
        assert_eq!(probe(b"%2E"), (true, 3));
        assert_eq!(probe(b"%2e/x"), (true, 3));
        assert_eq!(probe(b"%2Ex"), (true, 3));
    }

    /// What is not a dot. `%2f` is the encoded separator and must survive,
    /// which is what keeps `%2f%2e%2e%2f` intact in unit1395's first rows.
    #[test]
    fn is_dot_rejects_everything_else_without_moving() {
        for input in [
            &b"%2f"[..],
            b"%2F",
            b"%2d",
            b"%3e",
            b"%22",
            b"x",
            b"/",
            b"",
            b"e",
            b"2",
        ] {
            assert_eq!(probe(input), (false, 0), "input {input:?}");
        }
    }

    /// The length guard at L690 protects the encoded branch alone. Two bytes
    /// are not enough for it however promising they look, and unit1395 L55
    /// pins the consequence: `%2` comes back unchanged.
    #[test]
    fn is_dot_needs_three_bytes_for_the_encoded_form() {
        assert_eq!(probe(b"%2"), (false, 0));
        assert_eq!(probe(b"%"), (false, 0));
        // The same two bytes with a third present do match, so the guard is
        // the only thing separating the two cases.
        assert_eq!(probe(b"%2e"), (true, 3));
    }

    /// `tests/unit/unit1395.c` L39-L112, transcribed row for row.
    ///
    /// This is the project's own table for this function and it is the
    /// authority for every other expectation in this module. `None` is the
    /// C's null output, which is a success that changes nothing.
    ///
    /// Two rows deserve to be read before anything in this file is changed:
    /// `("/..", Some("/"))` and `("/.", Some("/"))`. Neither yields an empty
    /// output. Step C appends a slash at L795 when the dot segment ends the
    /// input, and step B does the same at L766.
    #[test]
    fn the_unit1395_table_matches_row_for_row() {
        const PAIRS: [(&str, Option<&str>); 71] = [
            ("%2f%2e%2e%2f/../a", Some("%2f%2e%2e%2f/a")),
            ("%2f%2e%2e%2f/../", Some("%2f%2e%2e%2f/")),
            ("%2f%2e%2e%2f/.", Some("%2f%2e%2e%2f/")),
            ("%2f%2e%2e%2f/", Some("%2f%2e%2e%2f/")),
            ("%2f%2e%2e%2f", Some("%2f%2e%2e%2f")),
            ("%2f%2e%2e%2", Some("%2f%2e%2e%2")),
            ("%2f%2e%2e%", Some("%2f%2e%2e%")),
            ("%2f%2e%2e", Some("%2f%2e%2e")),
            ("%2f%2e%2", Some("%2f%2e%2")),
            ("%2f%2e%", Some("%2f%2e%")),
            ("%2f%2e", Some("%2f%2e")),
            ("%2f%2", Some("%2f%2")),
            ("%2f%", Some("%2f%")),
            ("%2f", Some("%2f")),
            ("%2", Some("%2")),
            ("%", None),
            ("2", None),
            ("e", None),
            (".", None),
            ("./", Some("")),
            ("..", Some("")),
            ("../", Some("")),
            ("../a", Some("a")),
            ("///moo.", Some("///moo.")),
            (".///moo.", Some("//moo.")),
            ("./moo..", Some("moo..")),
            ("./moo../", Some("moo../")),
            ("./moo../.m", Some("moo../.m")),
            ("./moo", Some("moo")),
            ("../moo", Some("moo")),
            ("../moo?", Some("moo?")),
            ("../moo?#", Some("moo?#")),
            ("../moo?#?..", Some("moo?#?..")),
            ("/../moo/..", Some("/")),
            ("/a/c/%2e%2E/b", Some("/a/b")),
            ("/a/%2e/g", Some("/a/g")),
            ("/a/b/c/./g", Some("/a/b/c/g")),
            ("/a/c/../b", Some("/a/b")),
            ("/a/b/c/./../../g", Some("/a/g")),
            ("/a/b/c/./%2e%2E/../g", Some("/a/g")),
            ("/a/b/c/./../%2e%2E/g", Some("/a/g")),
            ("/a/b/c/%2E/%2e%2E/%2e%2E/g", Some("/a/g")),
            ("mid/content=5/../6", Some("mid/6")),
            ("/hello/../moo", Some("/moo")),
            ("/1/../1", Some("/1")),
            ("/1/./1", Some("/1/1")),
            ("/1/%2e/1", Some("/1/1")),
            ("/1/%2E/1", Some("/1/1")),
            ("/1/..", Some("/")),
            ("/1/.", Some("/1/")),
            ("/1/%2e", Some("/1/")),
            ("/1/%2E", Some("/1/")),
            ("/1/./..", Some("/")),
            ("/1/%2e/.%2E", Some("/")),
            ("/1/./%2e.", Some("/")),
            ("/1/./../2", Some("/2")),
            ("/hello/1/./../2", Some("/hello/2")),
            ("test/this", Some("test/this")),
            ("test/this/../now", Some("test/now")),
            ("/1../moo../foo", Some("/1../moo../foo")),
            ("/../../moo", Some("/moo")),
            ("/../../moo?", Some("/moo?")),
            ("/123?", Some("/123?")),
            ("/", None),
            ("", None),
            ("/.../", Some("/.../")),
            ("/.", Some("/")),
            ("/..", Some("/")),
            ("/moo/..", Some("/")),
            ("/..", Some("/")),
            ("/.", Some("/")),
        ];

        for (input, output) in PAIRS {
            assert_eq!(
                dedot(input.as_bytes()),
                want(output),
                "input {input:?} expected {output:?}"
            );
        }
    }

    /// An input shorter than two bytes is a success with no output, L723-L724.
    ///
    /// The comment at L722 gives the reason: "the path always starts with a
    /// slash, and a slash has not dot", so one byte cannot hold a dot segment
    /// and there is nothing to rewrite. The caller keeps its path untouched.
    #[test]
    fn a_short_input_produces_no_output() {
        assert_eq!(dedot(b""), want(None));
        assert_eq!(dedot(b"/"), want(None));
        assert_eq!(dedot(b"."), want(None));
        assert_eq!(dedot(b"a"), want(None));
        // Two bytes is enough to reach the buffer, and then even an input
        // with no dot at all comes back as a copy rather than as nothing.
        assert_eq!(dedot(b"/a"), want(Some("/a")));
    }

    /// The empty output is an allocated empty string, never a null pointer,
    /// L814-L818.
    ///
    /// This is the one distinction in this function that is visible from
    /// outside the library. `tests/libtest/lib1560.c` L778 asserts that
    /// `file:./` gives `file://`: the path is set to a zero-length string,
    /// and the whole-URL template at L1528 substitutes `/` only for a null
    /// path. Had this arm answered `None`, the path would have stayed unset
    /// and the URL would have read `file:///`.
    #[test]
    fn an_empty_result_is_an_allocated_empty_string() {
        for input in [&b"./"[..], b"..", b"../", b"%2e", b"%2E", b".%2E", b"%2e."] {
            let out = dedotdotify(input).unwrap();
            assert!(out.is_some(), "input {input:?} produced no output");
            let buf = out.unwrap();
            assert!(buf.is_empty(), "input {input:?}");
            assert_eq!(buf.len(), 0, "input {input:?}");
            // One byte of allocation, holding only the terminator, which is
            // what `curlx_strdup("")` produces.
            assert_eq!(buf.as_bytes_with_nul(), b"\0", "input {input:?}");
        }
    }

    /// The RFC's own worked examples from section 5.2.4, and the two the C
    /// carries in its table.
    #[test]
    fn the_rfc_examples_resolve() {
        assert_eq!(dedot(b"/a/b/c/./../../g"), want(Some("/a/g")));
        assert_eq!(dedot(b"/mid/content=5/../6"), want(Some("/mid/6")));
        assert_eq!(dedot(b"mid/content=5/../6"), want(Some("mid/6")));
        assert_eq!(dedot(b"/a/b/c/./g"), want(Some("/a/b/c/g")));
    }

    /// The four single-segment shapes, each of which exercises a different
    /// arm: step C with a tail, step C at the end, step B with a tail and
    /// step B at the end.
    #[test]
    fn the_four_single_segment_shapes() {
        assert_eq!(dedot(b"/../foo"), want(Some("/foo")));
        assert_eq!(dedot(b"/./foo"), want(Some("/foo")));
        assert_eq!(dedot(b"/foo/.."), want(Some("/")));
        assert_eq!(dedot(b"/foo/."), want(Some("/foo/")));
    }

    /// A dot segment has to be *complete*. The second half of step C's guard
    /// at L779 requires a slash or the end of the input after the second dot,
    /// so anything else falls through to step E and survives byte for byte.
    #[test]
    fn an_incomplete_dot_segment_is_ordinary_content() {
        assert_eq!(dedot(b"/..x"), want(Some("/..x")));
        assert_eq!(dedot(b"/.../"), want(Some("/.../")));
        assert_eq!(dedot(b"/..."), want(Some("/...")));
        assert_eq!(dedot(b"/1../moo../foo"), want(Some("/1../moo../foo")));
        // A leading `..` followed by neither slash nor end consumes only the
        // first dot, per the missing third arm at L754. The probe is
        // discarded, so the second dot is copied out as content.
        assert_eq!(dedot(b"..x"), want(Some(".x")));
        assert_eq!(dedot(b"%2e%2ex"), want(Some("%2ex")));
        assert_eq!(dedot(b".x"), want(Some("x")));
        assert_eq!(dedot(b"...."), want(Some("...")));
    }

    /// The encoded dot is interchangeable with the literal one everywhere,
    /// which is what `tests/libtest/lib1560.c` L1256 and L1259 rely on.
    #[test]
    fn encoded_and_literal_dots_are_interchangeable() {
        assert_eq!(dedot(b"/a/%2e%2e/b"), want(Some("/b")));
        assert_eq!(dedot(b"/a/../b"), want(Some("/b")));
        assert_eq!(dedot(b"/a/c/%2e%2E/b"), want(Some("/a/b")));
        assert_eq!(dedot(b"/a/b/c/%2E/%2e%2E/%2e%2E/g"), want(Some("/a/g")));
        assert_eq!(dedot(b".%2e/path/./%2E/./../moo"), want(Some("path/moo")));
    }

    /// Step C does nothing when the output holds no slash to trim at, L785.
    ///
    /// `%2f` is not a separator, so an encoded prefix offers step C nothing
    /// to remove and the `..` simply disappears. The first five rows of
    /// unit1395 all turn on this.
    #[test]
    fn step_c_trims_nothing_when_the_output_holds_no_slash() {
        assert_eq!(dedot(b"%2f%2e%2e%2f/../a"), want(Some("%2f%2e%2e%2f/a")));
        assert_eq!(dedot(b"a/../.."), want(Some("a/")));
        assert_eq!(dedot(b"/../../moo"), want(Some("/moo")));
        assert_eq!(dedot(b"/..//"), want(Some("//")));
        assert_eq!(dedot(b"//"), want(Some("//")));
    }

    /// Every output is at most as long as its input, which is what makes the
    /// `clen + 1` ceiling at L726 exact rather than merely generous.
    #[test]
    fn the_output_never_grows() {
        const INPUTS: [&str; 12] = [
            "/a/b/c/./../../g",
            "/../../moo",
            "%2f%2e%2e%2f/../a",
            "/1/%2e/.%2E",
            "/.../",
            "./moo../.m",
            "/moo/..",
            "..x",
            "/123?",
            "test/this/../now",
            "//",
            "/a/%2e%2e/b",
        ];

        for input in INPUTS {
            let out = dedot(input.as_bytes()).unwrap();
            let len = out.map_or(0, |bytes| bytes.len());
            assert!(len <= input.len(), "input {input:?} grew to {len}");
        }
    }

    /// A sweep over short inputs, asserting only the invariants rather than
    /// specific answers: the walk always terminates, never fails, never
    /// grows, and never answers `None` for an input of two bytes or more.
    #[test]
    fn the_walk_terminates_for_every_short_input() {
        const ALPHABET: [u8; 6] = *b"/.%2ex";

        for a in ALPHABET {
            for b in ALPHABET {
                for c in ALPHABET {
                    for d in ALPHABET {
                        let input = [a, b, c, d];
                        let out = dedot(&input).unwrap();
                        assert!(
                            out.is_some(),
                            "input {input:?} produced no output despite four bytes"
                        );
                        let bytes = out.unwrap();
                        assert!(bytes.len() <= input.len(), "input {input:?}");
                    }
                }
            }
        }
    }

    /// Reads the handle's path as a copy, so assertions can compare slices.
    fn path_of(u: &CurlUrl) -> Option<Vec<u8>> {
        u.path().map(<[u8]>::to_vec)
    }

    /// Drives `handle_path` on a fresh handle and reports the code and the
    /// resulting path together.
    fn install(path: &[u8], pathlen: usize, flags: c_uint) -> (CURLUcode, Option<Vec<u8>>) {
        let mut u = CurlUrl::new();
        let code = handle_path(&mut u, path, pathlen, flags);
        (code, path_of(&u))
    }

    /// L1080-L1083: "there is no path left or just the slash, unset". Both an
    /// empty path and a bare slash leave the field absent, and the getter's
    /// own substitution at L1606-L1607 is what makes such a handle read back
    /// as `/`.
    #[test]
    fn an_empty_or_single_byte_path_is_left_unset() {
        assert_eq!(install(b"", 0, 0), (CURLUE_OK, None));
        assert_eq!(install(b"/", 1, 0), (CURLUE_OK, None));
        // The length decides, not the slice: a longer buffer with a shorter
        // path is the normal case, because the query and fragment stages trim
        // the length without moving the pointer.
        assert_eq!(install(b"/?q=1", 1, 0), (CURLUE_OK, None));
        assert_eq!(install(b"/#frag", 1, 0), (CURLUE_OK, None));
    }

    /// The ordinary path: copy exactly `pathlen` bytes, then remove dot
    /// segments. L1086-L1089 followed by L1095-L1105.
    #[test]
    fn a_plain_path_is_copied_and_dedotted() {
        assert_eq!(install(b"/a/../b", 7, 0), (CURLUE_OK, Some(b"/b".to_vec())));
        assert_eq!(
            install(b"/hello/../here", 14, 0),
            (CURLUE_OK, Some(b"/here".to_vec()))
        );
        assert_eq!(install(b"/..", 3, 0), (CURLUE_OK, Some(b"/".to_vec())));
        assert_eq!(install(b"/ab", 3, 0), (CURLUE_OK, Some(b"/ab".to_vec())));
    }

    /// The length parameter is honoured, so a query or fragment sitting past
    /// it never reaches the path. This is the precondition `parseurl`
    /// establishes at L1165-L1179 and states at L1182.
    #[test]
    fn only_pathlen_bytes_become_the_path() {
        assert_eq!(
            install(b"/a/../b?q=1", 7, 0),
            (CURLUE_OK, Some(b"/b".to_vec()))
        );
        assert_eq!(
            install(b"/a/../b#frag", 7, 0),
            (CURLUE_OK, Some(b"/b".to_vec()))
        );
        // A length past the end of the slice is clamped rather than read
        // through, which is the one place this port cannot follow the C
        // literally. No reachable call site produces it.
        assert_eq!(install(b"/ab", 99, 0), (CURLUE_OK, Some(b"/ab".to_vec())));
    }

    /// `CURLU_PATH_AS_IS` suppresses dot-segment removal entirely, L1095.
    ///
    /// `tests/libtest/lib1560.c` L779-L784 carries the same input twice, once
    /// with the flag and once without, and expects `/hello/../here` to be
    /// preserved in the first case and reduced to `/here` in the second.
    #[test]
    fn path_as_is_suppresses_dedotdotify() {
        assert_eq!(
            install(b"/hello/../here", 14, CURLU_PATH_AS_IS),
            (CURLUE_OK, Some(b"/hello/../here".to_vec()))
        );
        assert_eq!(
            install(b"/a/../b", 7, CURLU_PATH_AS_IS),
            (CURLUE_OK, Some(b"/a/../b".to_vec()))
        );
        assert_eq!(install(b"/a/../b", 7, 0), (CURLUE_OK, Some(b"/b".to_vec())));
    }

    /// `CURLU_URLENCODE` escapes the path before the dot segments are
    /// removed, L1070-L1078 before L1095-L1105.
    ///
    /// The encoder is called with `relative` true and `query` false, so a
    /// space becomes `%20` rather than `+` and no authority prefix is copied
    /// through. `tests/libtest/lib1560.c` L1336-L1339 is the end-to-end case.
    #[test]
    fn urlencode_escapes_before_the_dot_segments_are_removed() {
        assert_eq!(
            install(b"/a b", 4, CURLU_URLENCODE),
            (CURLUE_OK, Some(b"/a%20b".to_vec()))
        );
        assert_eq!(
            install(b"/a b/../c d", 11, CURLU_URLENCODE),
            (CURLUE_OK, Some(b"/c%20d".to_vec()))
        );
        assert_eq!(
            install(b"/there/it/is/../../tes t case=/x", 32, CURLU_URLENCODE),
            (CURLUE_OK, Some(b"/there/tes%20t%20case=/x".to_vec()))
        );
        // The two flags are independent: encoding still happens when
        // dot-segment removal is suppressed.
        assert_eq!(
            install(b"/a/../b c", 9, CURLU_URLENCODE | CURLU_PATH_AS_IS),
            (CURLUE_OK, Some(b"/a/../b%20c".to_vec()))
        );
    }

    /// The encoded length replaces the caller's for every later step, L1076.
    ///
    /// A path whose encoding is longer than its input would be truncated back
    /// to the input length if the substitution were missed, so this pins it
    /// with a case where the two lengths differ by more than one byte.
    #[test]
    fn the_encoded_length_replaces_the_original() {
        // Three spaces, each three bytes once escaped: 7 bytes in, 13 out.
        assert_eq!(
            install(b"/a b c ", 7, CURLU_URLENCODE),
            (CURLUE_OK, Some(b"/a%20b%20c%20".to_vec()))
        );
        // A byte at or above 0x7f escapes as well, per L157-L161 of the
        // encoder, and the length grows the same way. The hexadecimal is
        // UPPERCASE, because `Curl_hexbyte` at `lib/escape.c` L222-L227 reads
        // `Curl_udigits`; the reference build answers `/%FFx` for this input.
        assert_eq!(
            install(b"/\xffx", 3, CURLU_URLENCODE),
            (CURLUE_OK, Some(b"/%FFx".to_vec()))
        );
        assert_eq!(
            install(b"/a\x80\xc3\xb6z", 6, CURLU_URLENCODE),
            (CURLUE_OK, Some(b"/a%80%C3%B6z".to_vec()))
        );
    }

    /// The observable empty path, reached through this function rather than
    /// through `dedotdotify` alone.
    ///
    /// `file:./` gives a path of `./`, which de-dots to a zero-length string,
    /// and `tests/libtest/lib1560.c` L778 expects the resulting URL to be
    /// `file://`. The field must be present and empty, not absent.
    #[test]
    fn a_dedotted_path_may_be_present_and_empty() {
        let (code, path) = install(b"./", 2, 0);
        assert_eq!(code, CURLUE_OK);
        assert_eq!(path, Some(Vec::new()));
        // Present, and distinguishable from absent.
        let mut u = CurlUrl::new();
        assert_eq!(handle_path(&mut u, b"./", 2, 0), CURLUE_OK);
        assert!(u.has(StringField::Path));
        assert_eq!(u.path(), Some(&b""[..]));
    }

    /// The `pathlen <= 1` early return does not undo an installed encode
    /// buffer, which is the C's own behaviour at L1077 followed by L1080-L1083.
    ///
    /// The C nulls its local `path` and leaves `u->path` alone, so a bare
    /// slash under `CURLU_URLENCODE` ends up stored where the same input
    /// without the flag leaves the field absent. Neither state is
    /// distinguishable through the public API, because the getter at
    /// L1606-L1607 and the whole-URL template at L1528 both substitute `/`
    /// for an absent path. It is reproduced because it is what the C does,
    /// and because a getter that stopped substituting would make it visible.
    #[test]
    fn a_single_byte_path_still_keeps_its_encode_buffer() {
        assert_eq!(
            install(b"/", 1, CURLU_URLENCODE),
            (CURLUE_OK, Some(b"/".to_vec()))
        );
        assert_eq!(install(b"/", 1, 0), (CURLUE_OK, None));
        // A zero length skips the encode branch outright, per the `pathlen &&`
        // half of the test at L1070, so no buffer is installed either way.
        assert_eq!(install(b"", 0, CURLU_URLENCODE), (CURLUE_OK, None));
    }

    /// The de-dotted buffer replaces the copy rather than being appended to
    /// it, L1101-L1104, and the handle owns exactly one path buffer
    /// afterwards. Repeating the call on the same handle exercises the
    /// release-then-store order that `crate::handle::CurlUrl::store`
    /// guarantees; a leak here would not be observable, but a double free
    /// or a stale pointer would be.
    ///
    /// It also pins the combination `parseurl` cannot reach: a handle that
    /// already holds a path, called again with `CURLU_URLENCODE` clear. The C
    /// takes neither retargeting of its local `path`, so it de-dots the
    /// **caller's** bytes and stores the result, discarding what the field
    /// held. `path_from_handle` reproduces that, and this test is what keeps
    /// it reproduced.
    #[test]
    fn repeated_installs_replace_the_previous_path() {
        let mut u = CurlUrl::new();
        assert_eq!(handle_path(&mut u, b"/first/../a", 11, 0), CURLUE_OK);
        assert_eq!(u.path(), Some(&b"/a"[..]));
        assert_eq!(handle_path(&mut u, b"/second/../b", 12, 0), CURLUE_OK);
        assert_eq!(u.path(), Some(&b"/b"[..]));
        assert_eq!(handle_path(&mut u, b"/third/../c", 11, 0), CURLUE_OK);
        assert_eq!(u.path(), Some(&b"/c"[..]));
        // With CURLU_URLENCODE the same repeat goes through the encode branch
        // instead, which installs its own buffer and retargets `path` at
        // L1077, so the answer comes from the caller's bytes either way.
        assert_eq!(
            handle_path(&mut u, b"/fourth/../d e", 14, CURLU_URLENCODE),
            CURLUE_OK
        );
        assert_eq!(u.path(), Some(&b"/d%20e"[..]));
    }

    /// `handle_path` reports success for every input this module can be
    /// handed, because the only failures it has are allocation failures. The
    /// sweep is over the flag combinations that reach it rather than over
    /// content, which the `dedotdotify` tests cover.
    #[test]
    fn every_flag_combination_succeeds() {
        const FLAGS: [c_uint; 4] = [
            0,
            CURLU_URLENCODE,
            CURLU_PATH_AS_IS,
            CURLU_URLENCODE | CURLU_PATH_AS_IS,
        ];

        for flags in FLAGS {
            for input in [&b""[..], b"/", b"/a", b"/a/../b", b"/..", b"./", b"/a b"] {
                let (code, _) = install(input, input.len(), flags);
                assert_eq!(code, CURLUE_OK, "input {input:?} flags {flags:#x}");
            }
        }
    }
}
