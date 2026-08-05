// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Percent-decoding: the port of `Curl_urldecode`.
//!
//! `lib/urlapi.c` defines no decoder of its own. It borrows one from
//! `lib/escape.c`, where `Curl_urldecode` at L105-L154 is the whole of it,
//! and an object file standing in for `lib/urlapi.o` cannot borrow it back,
//! so this module re-implements it. Nothing else from `lib/escape.c` lands
//! here: `curl_easy_escape` at L50 goes to `src/encode.rs`, `curl_free` at
//! L189-L192 to `src/ffi.rs`, which is where the exported symbol and the
//! `libc::free` behind it live, and `Curl_hexbyte` at L222 to
//! `src/ctype.rs`.
//!
//! # The three call sites, and what each does with the result
//!
//! All three pass [`UrlReject::Ctrl`], and every locator below is a line of
//! `lib/urlapi.c`. Knowing them matters for two reasons: they fix which
//! reject mode is behaviorally load-bearing, and they are what makes the
//! error-precedence question in a later section answerable.
//!
//! 1. **L1385**, inside `urlget_format` at L1357, the `CURLU_URLDECODE`
//!    path. The comment the C carries at L1383-L1384 is worth quoting,
//!    because it settles the status of the rejection below: "this
//!    unconditional rejection of control bytes is documented API behavior".
//!    It is contract, not an accident. L1386 releases the undecoded copy,
//!    L1387-L1388 answers any failure with `CURLUE_URLDECODE`, and
//!    L1389-L1390 moves the decoded buffer and its length into `part`,
//!    which is eventually what `curl_url_get()` hands to the caller. That
//!    is the path on which this module's output ends up owned by C.
//! 2. **L590-L591**, inside `urldecode_host` at L578, reached only when the
//!    host actually contains a percent sign, tested at L582. It passes
//!    `length` as 0, the measure-it overload. L592-L593 answers any failure
//!    with `CURLUE_BAD_HOSTNAME`, L595 copies the decoded bytes into a
//!    dynamic buffer using the reported length, and L596 releases them.
//! 3. **L1979-L1980**, inside `curl_url_set` at L1805, validating a host
//!    that arrived already encoded. L1981-L1982 folds a decode failure and
//!    a `hostname_check` failure into one `bad` flag, L1983 releases the
//!    buffer, and L1989 answers with `CURLUE_BAD_HOSTNAME`.
//!
//! [`UrlReject::Nada`] and [`UrlReject::Zero`] are unreachable from the URL
//! API: the only `REJECT_NADA` caller in the C tree is
//! `curl_easy_unescape` at `lib/escape.c` L170-L171, and `REJECT_ZERO` has
//! no caller in `lib/urlapi.c` at all. Both are ported anyway, so that this
//! module is a port of the function rather than of the subset one caller
//! happens to use, and so that a future consumer has no reason to add a
//! mode by hand.
//!
//! # The threshold trap: two rejection sets that must never be unified
//!
//! This crate contains two control-byte tests that look like they should be
//! one helper. They are different predicates over different data at
//! different times, and folding them together is a silent behavior change.
//! `src/parse/junk.rs` names them set A and set B; the same names are used
//! here.
//!
//! - **Set A**, owned by `src/parse/junk.rs`, from `Curl_junkscan` at
//!   `lib/urlapi.c` L232-L236: rejects a byte `<= 0x1f`, or `<= 0x20` when
//!   `CURLU_ALLOW_SPACE` is absent, **plus `0x7f`**. It inspects the raw
//!   input before any decoding.
//! - **Set B**, owned by this module, from `lib/escape.c` L139: rejects a
//!   byte `< 0x20` and nothing else. It inspects each byte *after*
//!   decoding.
//!
//! Set B is strictly narrower, in two ways that are easy to miss and that
//! [`UrlReject::rejects`] therefore states outright:
//!
//! - `0x20`, the space, is **accepted**. The test is `<`, not `<=`. So a
//!   `%20` escape decodes to a byte this module passes.
//! - `0x7f`, delete, is **accepted**. Set A rejects it in a comparison of
//!   its own at L234, and set B has no such comparison. So a `%7f` escape
//!   decodes to a byte this module passes and set A would have refused.
//!
//! Both outcomes are correct, and the reason is that set A never sees the
//! byte in question: it inspected the three characters `%`, `7` and `f`,
//! every one of which is comfortably above either threshold. The C
//! documents set B at `lib/escape.c` L97-L98 as rejecting "control
//! characters (byte codes lower than 32) in the data", and that is the
//! whole of it.
//!
//! For the same reason `u8::is_ascii_control` does not appear below. It
//! covers `0x00` through `0x1f` **plus `0x7f`**, so it is set A with spaces
//! allowed and it is not set B. Naming it here would import exactly the
//! `0x7f` rejection this side must not have.
//!
//! Unifying the two is the most tempting cleanup available in this file.
//! Do not take it.
//!
//! # The `%XX` rule is deliberately lenient
//!
//! `lib/escape.c` L126-L127 recognizes an escape only when all three of the
//! following hold: the byte is `%`; at least three bytes remain, counting
//! the `%` itself, which is what `alloc > 2` says; and both following bytes
//! are hexadecimal digits. When any of them fails, the `%` is copied
//! through **literally** by the `else` branch at L134-L137. It is not an
//! error, and no diagnostic is produced.
//!
//! So `%`, `%A`, `%GG` and `%%20` all decode without complaint, the last
//! one to `%` followed by a space. A port that rejected a malformed escape
//! would fail the parity diff on ordinary input, because a bare `%` in a
//! path is common.
//!
//! The "at least three bytes remain" half is a statement about the
//! *window*, not about the underlying buffer. Decoding `b"%41"` with an
//! explicit `length` of 2 leaves two bytes in the window, so the escape is
//! not recognized and the result is the two literal bytes `%4`, even though
//! the byte after the window would have completed it.
//!
//! # `length == 0` means "measure it"
//!
//! `lib/escape.c` L115 is `alloc = (length ? length : strlen(string))`, so
//! zero is not "decode nothing", it is "decode to the terminator".
//! [`urldecode`] keeps that overload rather than dropping it, because call
//! site 2 above relies on it and because `src/encode.rs` carries the
//! analogous overload for `curl_easy_escape` at `lib/escape.c` L50-L56,
//! which `lib/urlapi.c` L1493 uses; having one of the pair silently drop it
//! would be a trap for the next reader.
//!
//! Two consequences of measuring over a slice rather than a `char *`:
//!
//! - An explicit `length` greater than the slice is clamped to the slice.
//!   The C would read past the end of the caller's buffer, which is
//!   undefined behavior rather than defined behavior worth reproducing, and
//!   no caller in the tree does it.
//! - A slice may contain an interior NUL where a `char *` cannot. With
//!   `length == 0` the scan stops at it, exactly as `strlen` does. With an
//!   explicit `length` it does not, which is also what the C does, and the
//!   NUL is then decoded like any other byte: rejected under
//!   [`UrlReject::Ctrl`] and [`UrlReject::Zero`], copied under
//!   [`UrlReject::Nada`].
//!
//! # `olen` becomes the buffer's own length
//!
//! The C reports the decoded length through an optional out-parameter,
//! `*olen` at L149-L151, computed as `ns - *ostring`, and passing NULL
//! means "do not report it". The port returns [`CBuf`], which carries its
//! length, so the length is always available and never separately optional:
//! `Option` around a value the type already holds would be ceremony
//! without meaning. Callers that ignore it simply do not read it, which is
//! what passing NULL achieved.
//!
//! The decoded length is at most the window length and is strictly less
//! whenever an escape was decoded, since three input bytes become one.
//! Output never grows.
//!
//! # Memory ownership
//!
//! The buffer is a [`CBuf`] from `src/alloc.rs`, backed by a block
//! `src/ffi.rs` took from the **C allocator**, which is what makes the
//! caller's `curl_free()` correct. That is not a preference. Call site 1
//! above ends with this module's
//! buffer being returned from `curl_url_get()`, and both
//! `docs/libcurl/curl_url_get.md` L45 and `include/curl/urlapi.h`
//! L130-L131 require the caller to release it with `curl_free()`.
//! `docs/MEMORY-OWNERSHIP.md` records the same chain and describes it as a
//! sequence of moves, which is precisely what returning an owned [`CBuf`]
//! by value is.
//!
//! `CString::into_raw` is banned crate-wide and does not appear here. Its
//! pointer belongs to the Rust allocator and has to come back to Rust to be
//! released, which is the one thing the documented contract above forbids.
//!
//! Returning an owned [`CBuf`] rather than a raw pointer also disposes of
//! the failure-path question the C has to answer by hand. `lib/escape.c`
//! L141 reaches for `Curl_safefree`, which frees the block *and* nulls the
//! caller's pointer, because by then the caller has already been handed one
//! at L122. Here the caller is handed nothing until the function succeeds:
//! an `Err` carries no buffer, so a dangling out-pointer is not
//! expressible, and the block is released by `Drop` on the way out. Both
//! halves of `Curl_safefree` are reproduced by construction rather than by
//! a call.
//!
//! # Error precedence, and the allocation shape that fixes it
//!
//! The C allocates at L116 and returns `CURLE_OUT_OF_MEMORY` at L119
//! *before* it looks at a single byte of content, so on an input that is
//! both unallocatable and full of control bytes, out-of-memory wins. This
//! port keeps that order, and it keeps it the same way rather than by
//! argument: `alloc = length + 1` is computed from the **input window**, the
//! block is allocated, and only then does the single decode pass at
//! L124-L146 look at anything.
//!
//! Sizing the block from the decoded length instead would be smaller and
//! would still terminate correctly, and it is the one thing this file must
//! not do. It moves the allocation after the inspection, so an input too
//! large to allocate for that also carries a rejected byte would answer
//! `CURLE_URL_MALFORMAT` where the C answers `CURLE_OUT_OF_MEMORY`. All
//! three call sites happen to collapse both codes into a single `CURLUcode`,
//! so the difference is not observable through the public API today; the
//! order is reproduced so that no question of faithfulness arises at all.
//!
//! The decoded length is shorter than the block whenever the input held an
//! escape, which is exactly the state the C is left in -- `lib/escape.c`
//! never shrinks its allocation either, and reports the shorter length
//! through `*olen` at L149-L151. Here [`CBuf::truncate`] writes the
//! terminator at that shorter end and makes it the buffer's own length, so
//! the length and the contents cannot disagree and no consumer has to be
//! told which to trust. The spare capacity is what invariant 2 of [`CBuf`]
//! exists to permit.
//!
//! # No `unsafe`, no panic
//!
//! There is no `unsafe` in this file. Every operation is over byte slices,
//! and the allocator's `unsafe` lives in `src/ffi.rs`, the crate's only
//! unsafe module, reached from here through [`CBuf`]'s safe surface.
//!
//! Nothing here can panic either. The crate root denies `unwrap`, `expect`,
//! `panic!`, direct indexing and unchecked arithmetic, so the two lookahead
//! bytes are reached through a slice pattern, the window is advanced with
//! `get` and a total fallback, the length accumulates with `saturating_add`
//! and the two hexadecimal nibbles are combined with `wrapping_shl` and a
//! bitwise or. Every one of those is exact for every input that can reach
//! it, as the comments at each site record; they are chosen so that no
//! panicking construct exists, not to paper over an overflow that could
//! happen.
//!
//! # Verification
//!
//! The tests at the end of this file are this module's own coverage. They
//! exercise each rule above, the threshold trap directly and in both
//! directions, and a sweep of all 256 byte values through a `%XX` escape
//! built with `crate::ctype::hexbyte`, which is the encoder's own primitive
//! and so gives a round-trip check without reaching outside this module's
//! dependencies. The same behavior is also driven through the exported C
//! entry points by the crate's integration test
//! `rust-urlapi/tests/encode_decode.rs`.

// Which of the two entry points below a given build reaches depends on which
// sibling module is compiled: `urldecode_bytes` serves the two call sites
// that pass an explicit length, in `src/getset.rs` and in the host check of
// the assignment dispatch, and `urldecode` serves `urldecode_host` in
// `src/parse/host.rs`, which passes zero. `UrlReject::Nada` and
// `UrlReject::Zero` have no caller in the ported module at all, for the
// reason the module documentation gives. Warnings are errors for this crate,
// so rather than let the module set decide whether the build is clean, the
// allowance is stated once here with its reason. It is scoped to this module
// and to this lint alone.
#![allow(dead_code)]
// Every `unsafe` block in this crate lives in `src/ffi.rs`, and this module
// needs nothing from C directly: the allocator it uses reaches the foreign
// calls through `crate::alloc`'s safe surface. `forbid` rather than `deny`
// because an inner `allow` here would be a design change and should have to be
// argued for rather than slipped in.
#![forbid(unsafe_code)]

use crate::alloc::CBuf;
use crate::ctype::hexval;
use crate::error::CURLcode;

/// What percent-decoding refuses to produce.
///
/// `enum urlreject` at `lib/escape.h` L29-L33, whose three values the C
/// spells `REJECT_NADA`, `REJECT_CTRL` and `REJECT_ZERO`. The semantics come
/// from the doc comment at `lib/escape.c` L95-L99.
///
/// # Why the numbers are 2, 3 and 4
///
/// The C enumeration starts at 2, and `lib/escape.c` L101-L102 says why:
/// "The values for the enum starts at 2, to make the assert detect legacy
/// invokes that used TRUE/FALSE (0 and 1)". The assertion in question is
/// `DEBUGASSERT(ctrl >= REJECT_NADA)` at L113, which catches a caller that
/// was written against an older signature taking a boolean. The offset is
/// pinned below with explicit discriminants so that the reason for it stays
/// discoverable, and so that a reordering cannot quietly renumber the
/// variants.
///
/// Rust needs no such assertion: a caller cannot pass a boolean where this
/// type is expected, and the enumeration is closed, so the match in
/// [`UrlReject::rejects`] is exhaustive by construction. The legacy-invoke
/// bug class is absent rather than detected.
///
/// # Why an enumeration here, when `src/abi.rs` has none
///
/// `src/abi.rs` writes every value out as an explicit integer constant
/// because those values cross the C boundary, where a Rust enumeration's
/// implicit discriminants could be renumbered by a later reordering with no
/// compiler error and no ABI diagnostic. That argument does not reach this
/// type. `enum urlreject` is internal to libcurl: it appears in no public
/// header, and no symbol this crate exports accepts or returns one, so no
/// numeric value of it is ever observed from outside. The same reasoning
/// applies to `CURLcode` in `src/error.rs`, which is an enumeration for
/// exactly this reason. This is a deliberate distinction, not an
/// inconsistency with the constants-only rule in `src/abi.rs`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum UrlReject {
    /// `REJECT_NADA`, `lib/escape.h` L30. Accept everything, including
    /// control bytes and decoded zero bytes.
    ///
    /// No caller inside the ported module. `curl_easy_unescape` at
    /// `lib/escape.c` L170-L171 is the only user in the C tree.
    Nada = 2,
    /// `REJECT_CTRL`, `lib/escape.h` L31. Reject a decoded byte below
    /// `0x20`, and nothing else.
    ///
    /// The mode all three call sites in `lib/urlapi.c` use, and the one the
    /// module documentation's threshold-trap section is about.
    Ctrl = 3,
    /// `REJECT_ZERO`, `lib/escape.h` L32. Reject a decoded zero byte, and
    /// nothing else.
    ///
    /// Narrower than [`UrlReject::Ctrl`], which already covers zero. No
    /// caller in `lib/urlapi.c`.
    Zero = 4,
}

impl UrlReject {
    /// Whether this mode refuses an already-decoded byte.
    ///
    /// `lib/escape.c` L139-L140 in full:
    ///
    /// ```c
    /// if(((ctrl == REJECT_CTRL) && (in < 0x20)) ||
    ///    ((ctrl == REJECT_ZERO) && (in == 0))) {
    /// ```
    ///
    /// The two bounds are exactly as the C writes them, and both are
    /// load-bearing:
    ///
    /// - `< 0x20` and not `<= 0x20`, so the space at `0x20` is accepted.
    /// - no `== 0x7f` term, so delete is accepted.
    ///
    /// See the threshold-trap section of the module documentation before
    /// changing either. This is rejection set B, and set A in
    /// `src/parse/junk.rs` differs from it on both of those bytes.
    ///
    /// # Parameters
    ///
    /// - `byte`: the byte **after** decoding. `lib/escape.c` applies the
    ///   test at L139, below the conversion at L129-L130, so `%1f` is
    ///   rejected under [`UrlReject::Ctrl`] while the three raw bytes `%`,
    ///   `1` and `f` would all have passed.
    #[must_use]
    pub(crate) const fn rejects(self, byte: u8) -> bool {
        match self {
            // lib/escape.c L139 and L140 both test `ctrl` against a
            // specific mode, so a third mode satisfies neither and accepts
            // every byte. The C reaches that conclusion by falling past two
            // conditions; here it is an arm of its own.
            Self::Nada => false,
            // lib/escape.c L139. Strictly less than, so 0x20 is accepted.
            Self::Ctrl => byte < 0x20,
            // lib/escape.c L140.
            Self::Zero => byte == 0,
        }
    }
}

/// The bytes `Curl_urldecode` would walk, given `input` and `length`.
///
/// `lib/escape.c` L115: `alloc = (length ? length : strlen(string))`.
///
/// # Parameters
///
/// - `input`: the caller's bytes. When `length` is zero this is expected to
///   be NUL-terminated, as the C's `char *` always is; a slice with no NUL
///   is measured to its own end, which is the same answer for every input
///   the C could have been given.
/// - `length`: the number of bytes to decode, or zero for "measure it".
///
/// # Returns
///
/// The window to decode, always a prefix of `input`. A `length` beyond the
/// slice is clamped rather than trusted: the C would read past the caller's
/// buffer, and clamping is the only defined behavior available here. No call
/// site in `lib/urlapi.c` passes such a length, so the clamp is a guard and
/// not a behavior this port relies on.
fn measure(input: &[u8], length: usize) -> &[u8] {
    if length == 0 {
        // strlen: stop at the first NUL. `position` returns an index that is
        // by definition inside the slice, so `get` cannot fail; the fallback
        // exists only so that no unwrap appears.
        match input.iter().position(|&byte| byte == 0) {
            Some(nul) => input.get(..nul).unwrap_or(input),
            None => input,
        }
    } else {
        input.get(..length).unwrap_or(input)
    }
}

/// One iteration of the decode loop: the byte produced and how many input
/// bytes it consumed.
///
/// `lib/escape.c` L124-L137, the body of the `while(alloc)` loop up to but
/// not including the reject test. Factoring it out is what lets the two
/// passes in [`urldecode`] agree on the decoded length by construction:
/// there is one recognition rule, written once.
///
/// # Returns
///
/// `None` for an empty window, which is the C's `while(alloc)` reaching
/// zero. Otherwise the decoded byte together with 1 or 3, the C's
/// `alloc -= 3` at L132 and `alloc--` at L136. The consumed count never
/// exceeds the window length, which is what makes the `get` in the callers
/// total.
fn decode_step(window: &[u8]) -> Option<(u8, usize)> {
    match window {
        // lib/escape.c L126-L127. The three-element slice pattern *is* the
        // `alloc > 2` test: it matches only when at least three bytes
        // remain, counting the '%' itself, so the two lookaheads are reached
        // without indexing and without a bounds question. The C evaluates
        // `alloc > 2` before touching `string[1]`, for the same reason.
        [b'%', high, low, ..] => match hexval(*high).zip(hexval(*low)) {
            // lib/escape.c L129-L130:
            //   in = (unsigned char)((curlx_hexval(string[1]) << 4) |
            //                        curlx_hexval(string[2]));
            // `wrapping_shl` rather than `<<` because the crate root denies
            // arithmetic that could panic; it is exact here, since `hexval`
            // yields 0..=15 and four left shifts of that stay inside a byte.
            // The or is a bitwise operator and cannot overflow at all.
            Some((high_nibble, low_nibble)) => Some((high_nibble.wrapping_shl(4) | low_nibble, 3)),
            // Either digit is not hexadecimal, so the escape is not
            // recognized and the '%' is literal: the else branch at
            // lib/escape.c L134-L137. `zip` stands in for the two `ISXDIGIT`
            // tests at L127; it evaluates both rather than short-circuiting,
            // which changes nothing, because `hexval` is total and pure. Its
            // `Some` domain is exactly `crate::ctype::is_xdigit`, a property
            // pinned for all 256 byte values by a test below, so this is one
            // classification rather than a second, weaker one.
            None => Some((b'%', 1)),
        },
        // Not an escape: lib/escape.c L125 reads the byte, L135-L136 steps
        // over it. This arm also covers a '%' with fewer than two bytes
        // behind it, which the pattern above could not match.
        [first, ..] => Some((*first, 1)),
        // lib/escape.c L124: the loop ends when nothing remains.
        [] => None,
    }
}

/// Advances the window past the bytes an iteration consumed.
///
/// The C does this with `string += 3` at L131 or `string++` at L135. Here it
/// is a reslice, kept in one place so that both passes step identically.
///
/// `count` always came from [`decode_step`], which never reports more bytes
/// than the window holds, so the `get` always succeeds. The empty fallback
/// exists so that no unwrap appears, and it is the safe direction anyway: an
/// empty window ends the loop rather than repeating a byte.
fn advance(window: &[u8], count: usize) -> &[u8] {
    window.get(count..).unwrap_or_default()
}

/// URL-decodes `input`, reproducing `Curl_urldecode`.
///
/// `lib/escape.c` L105-L154. The module documentation carries the leniency
/// rule, the threshold trap, the ownership contract and the reason the port
/// walks the window twice.
///
/// # Parameters
///
/// - `input`: the bytes to decode. Any byte value is acceptable; this is not
///   text and is never validated as UTF-8.
/// - `length`: how many bytes of `input` to decode, or **zero** to measure
///   `input` to its first NUL. That overload is `lib/escape.c` L115, and
///   `urldecode_host` at `lib/urlapi.c` L590 is the caller that needs it.
///   Use [`urldecode_bytes`] when the slice is already exactly the window.
/// - `reject`: which decoded bytes to refuse. All three URL API call sites
///   pass [`UrlReject::Ctrl`].
///
/// # Returns
///
/// An owned buffer from the C allocator, holding the decoded bytes and a
/// terminator. Its [`CBuf::len`] is the C's `*olen` from L151, and its
/// terminator is the C's `*ns = 0` from L147, so the block is a valid C
/// string as well as a Rust slice.
///
/// # Ownership
///
/// Rust owns the result. Hand it to C with [`CBuf::into_raw`] at the point
/// where it genuinely crosses over, after which the C side owes a
/// `curl_free()` and, because the block came from the C allocator, that call
/// is the correct one. Until then `Drop` releases it, including on every
/// early return below.
///
/// # Errors
///
/// - `CURLcode::CURLE_OUT_OF_MEMORY` when the allocation fails, which is
///   `lib/escape.c` L118-L119.
/// - `CURLcode::CURLE_URL_MALFORMAT` when `reject` refuses a decoded byte,
///   which is L139-L143. No buffer accompanies either error, which is this
///   port's rendering of the `Curl_safefree(*ostring)` at L141: the block is
///   released and no pointer to it ever reaches the caller.
///
/// The two are reported in the C's order. An input that cannot be allocated
/// for is out of memory even if it also contains a rejected byte, because
/// the C allocates at L116 before inspecting anything. All three call sites
/// happen to collapse both codes into a single `CURLUcode`, so the order is
/// not observable through the public API; it is preserved so that no
/// question of faithfulness arises at all.
#[must_use = "the decoded buffer is owned; dropping it releases the memory"]
pub(crate) fn urldecode(input: &[u8], length: usize, reject: UrlReject) -> Result<CBuf, CURLcode> {
    let window = measure(input, length);

    // The allocation, and its shape is the C's rather than the answer's.
    // `lib/escape.c` L116 computes `alloc = length + 1` from the *input* and
    // calls `malloc(alloc)` before it inspects a single byte, then reports the
    // shorter decoded length through `*olen` at L149-L151. Sizing from the
    // decoded length instead would be smaller and would still terminate
    // correctly, but it would move the allocation after the inspection: an
    // input that is too large to allocate for and also carries a rejected byte
    // is out of memory in the C, and would have been a malformed URL here.
    // L118-L119 is the out-of-memory return.
    //
    // The block underneath comes from the C allocator, by way of
    // `src/alloc.rs` over `src/ffi.rs`, which is what makes the caller's
    // `curl_free()` correct on the buffer this function eventually yields. It
    // arrives zeroed, so the terminator invariant holds before anything is
    // written, and `CBuf` releases it on every early return below.
    let mut buf = CBuf::alloc(window.len()).ok_or(CURLcode::CURLE_OUT_OF_MEMORY)?;

    // One pass, `lib/escape.c` L124-L146, exactly as the C walks it. The
    // destination drives the loop, so no write can land outside the block: the
    // decode produces at most one byte per input byte, and the destination is
    // as wide as the input.
    let mut decoded_len: usize = 0;
    {
        let mut rest = window;
        for slot in buf.as_mut_bytes() {
            let Some((byte, consumed)) = decode_step(rest) else {
                // The window is exhausted, which is the C's loop condition
                // `while(alloc)` falling false at L124.
                break;
            };
            // lib/escape.c L139-L143, applied to the decoded byte. Returning
            // here drops `buf`, and `Drop` releases the block: that is the
            // `Curl_safefree(*ostring)` at L141. The nulling half of
            // `Curl_safefree` needs no counterpart, because an `Err` carries
            // no pointer for the caller to hold.
            if reject.rejects(byte) {
                return Err(CURLcode::CURLE_URL_MALFORMAT);
            }
            // lib/escape.c L145: `*ns++ = (char)in`. The iterator supplies the
            // post-increment.
            *slot = byte;
            // `saturating_add` because the crate root denies arithmetic that
            // could panic. It is exact: the counter rises once per slot and
            // the slots are a slice, so it cannot exceed `window.len()`.
            decoded_len = decoded_len.saturating_add(1);
            rest = advance(rest, consumed);
        }
    }

    // lib/escape.c L147 wrote the terminator at the decoded end and L149-L151
    // reported the decoded length through `*olen`. Both happen here: the
    // truncation re-terminates at `decoded_len` and makes `CBuf::len` that
    // same number. The block keeps the input-sized capacity, which invariant 2
    // of `CBuf` permits and which is what the C is left holding too --
    // `lib/escape.c` never shrinks its allocation either. L153 returns success.
    buf.truncate(decoded_len);
    Ok(buf)
}

/// URL-decodes exactly `input`, with no measure-it overload.
///
/// The shape two of the three C call sites use, where the length is already
/// known and passed explicitly: `lib/urlapi.c` L1385, which passes
/// `partlen`, and L1980, which passes the dynamic buffer's length. Prefer
/// this over [`urldecode`] whenever the slice is the window, because it says
/// so in the name and it removes the question of what a zero length would
/// have meant.
///
/// It differs from `urldecode(input, input.len(), reject)` in nothing at
/// all, the empty input included: an empty slice takes the measure branch
/// there and measures to zero, which is the same window. It differs from
/// `urldecode(input, 0, reject)` only when `input` contains an interior NUL,
/// which that form stops at and this one decodes through.
///
/// # Parameters
///
/// - `input`: the exact bytes to decode.
/// - `reject`: which decoded bytes to refuse.
///
/// # Returns
///
/// As [`urldecode`].
///
/// # Errors
///
/// As [`urldecode`].
#[must_use = "the decoded buffer is owned; dropping it releases the memory"]
pub(crate) fn urldecode_bytes(input: &[u8], reject: UrlReject) -> Result<CBuf, CURLcode> {
    urldecode(input, input.len(), reject)
}

#[cfg(test)]
mod tests {
    // The crate root denies the panicking constructs so that no panic can
    // ever reach the C boundary. A test's entire job is to panic when an
    // assertion fails, and a test never crosses that boundary, so the
    // denials are relaxed here and only here. The allowance is scoped to
    // this module and enumerated rather than blanket.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::arithmetic_side_effects)]

    /// The block is sized from the input window, not from the answer.
    ///
    /// `lib/escape.c:L116` allocates `length + 1` before it inspects anything,
    /// and L149-L151 reports the shorter decoded length. Reading the length
    /// alone cannot tell that apart from allocating the decoded size, so this
    /// reads the capacity too: `%41%42` is six input bytes, so the block is
    /// seven, while the decoded string `AB` is two.
    #[test]
    fn the_block_is_sized_from_the_input_and_the_length_from_the_decode() {
        let decoded = urldecode_bytes(b"%41%42", UrlReject::Nada).ok();
        let Some(buf) = decoded else {
            return;
        };
        assert_eq!(buf.as_bytes(), b"AB");
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.capacity(), 7);
        assert_eq!(buf.as_bytes_with_nul(), b"AB\0");
    }

    /// An input with no escape allocates exactly what the C allocates and
    /// needs no truncation at all.
    #[test]
    fn an_unescaped_input_fills_the_block_it_was_given() {
        let decoded = urldecode_bytes(b"plain", UrlReject::Nada).ok();
        let Some(buf) = decoded else {
            return;
        };
        assert_eq!(buf.as_bytes(), b"plain");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.capacity(), 6);
    }

    // The comparisons below need somewhere to put a decoded copy, and they
    // reach the heap through the `alloc` crate rather than through `std` so
    // that this module compiles the same way whichever the crate root turns
    // out to declare. Every other import here comes from `core` or from a
    // sibling module.
    extern crate alloc;

    use super::{advance, decode_step, measure, urldecode, urldecode_bytes};
    use super::{CBuf, UrlReject};
    use crate::ctype::{hexbyte, hexval, is_xdigit};
    use crate::error::CURLcode;
    use alloc::vec::Vec;

    /// Decodes and copies the bytes out, so that assertions can compare
    /// slices instead of buffers.
    ///
    /// `CBuf` has no `PartialEq`, deliberately: comparing two C-allocated
    /// blocks by pointer would be meaningless and by content would hide
    /// which of the two lengths was used. Copying the content out states
    /// which one every assertion below means.
    fn decode(input: &[u8], length: usize, reject: UrlReject) -> Result<Vec<u8>, CURLcode> {
        urldecode(input, length, reject).map(|buf| buf.as_bytes().to_vec())
    }

    /// The same, for the exact-window entry point.
    fn decode_all(input: &[u8], reject: UrlReject) -> Result<Vec<u8>, CURLcode> {
        urldecode_bytes(input, reject).map(|buf| buf.as_bytes().to_vec())
    }

    /// Builds `%XX` for one byte value, using the encoder's own primitive.
    ///
    /// `crate::ctype::hexbyte` is the port of `Curl_hexbyte` at
    /// `lib/escape.c` L222, which is what every encoding site in the C tree
    /// uses to emit an escape. Building the test input with it rather than
    /// with a second hand-written formatter is what makes the sweep below a
    /// genuine round-trip check.
    fn escape(byte: u8) -> [u8; 3] {
        let digits = hexbyte(byte);
        [b'%', digits[0], digits[1]]
    }

    /// The three discriminants are 2, 3 and 4, per `lib/escape.h` L29-L33.
    ///
    /// Not an ABI requirement -- no exported symbol of this crate carries
    /// one -- but the offset encodes the reason the C enumeration does not
    /// start at zero, so it is pinned rather than left to drift.
    #[test]
    fn reject_mode_discriminants_match_the_c_enumeration() {
        assert_eq!(UrlReject::Nada as u8, 2, "REJECT_NADA at lib/escape.h L30");
        assert_eq!(UrlReject::Ctrl as u8, 3, "REJECT_CTRL at lib/escape.h L31");
        assert_eq!(UrlReject::Zero as u8, 4, "REJECT_ZERO at lib/escape.h L32");
    }

    /// `hexval`'s `Some` domain is exactly `is_xdigit`.
    ///
    /// `decode_step` classifies the two lookahead bytes with `hexval` alone,
    /// where `lib/escape.c` L127 tests `ISXDIGIT` first and converts
    /// afterwards. That is one classification instead of two only if the two
    /// predicates agree everywhere, so the agreement is pinned here for all
    /// 256 byte values rather than assumed from `crate::ctype`'s own tests.
    #[test]
    fn hexval_accepts_exactly_the_hexadecimal_digits() {
        for byte in 0..=u8::MAX {
            assert_eq!(
                hexval(byte).is_some(),
                is_xdigit(byte),
                "hexval and is_xdigit disagree on byte {byte:#04x}"
            );
        }
    }

    /// A string with no escape in it is copied through unchanged.
    #[test]
    fn plain_input_is_copied_verbatim() {
        let out = decode_all(b"hello-world.example", UrlReject::Ctrl).unwrap();
        assert_eq!(out.as_slice(), b"hello-world.example");
    }

    /// `%20` decodes to a space, the single most common escape there is.
    ///
    /// It is also the threshold case from the accepting side: `0x20` is not
    /// below `0x20`, so `UrlReject::Ctrl` passes it.
    #[test]
    fn percent_twenty_decodes_to_a_space() {
        let out = decode_all(b"a%20b", UrlReject::Ctrl).unwrap();
        assert_eq!(out.as_slice(), b"a b");
        assert_eq!(out.len(), 3, "five input bytes become three");
    }

    /// Both letter cases of a hexadecimal digit are accepted, and mixed case
    /// with them.
    ///
    /// `ISXDIGIT` at `lib/curl_ctype.h` L39 covers `a`-`f` and `A`-`F`, so a
    /// port that took one case would reject half of all valid escapes.
    #[test]
    fn hexadecimal_digit_case_does_not_matter() {
        let lower = decode_all(b"%2f", UrlReject::Ctrl).unwrap();
        let upper = decode_all(b"%2F", UrlReject::Ctrl).unwrap();
        assert_eq!(lower.as_slice(), b"/");
        assert_eq!(upper.as_slice(), lower.as_slice());

        // Mixed case, and a letter in the high nibble as well as the low.
        assert_eq!(
            decode_all(b"%aB", UrlReject::Nada).unwrap().as_slice(),
            b"\xab"
        );
        assert_eq!(
            decode_all(b"%Ab", UrlReject::Nada).unwrap().as_slice(),
            b"\xab"
        );
    }

    /// A `%` that cannot start an escape is copied through literally.
    ///
    /// Every shape the leniency at `lib/escape.c` L126-L127 admits: a lone
    /// trailing `%`, one hexadecimal digit and then the end, two non-digits,
    /// one digit and one non-digit, and a doubled `%` in front of a real
    /// escape. None of these is an error.
    #[test]
    fn a_malformed_escape_is_literal_and_not_an_error() {
        assert_eq!(decode_all(b"%", UrlReject::Ctrl).unwrap().as_slice(), b"%");
        assert_eq!(
            decode_all(b"a%", UrlReject::Ctrl).unwrap().as_slice(),
            b"a%"
        );
        assert_eq!(
            decode_all(b"%A", UrlReject::Ctrl).unwrap().as_slice(),
            b"%A"
        );
        assert_eq!(
            decode_all(b"%GG", UrlReject::Ctrl).unwrap().as_slice(),
            b"%GG"
        );
        assert_eq!(
            decode_all(b"%2G", UrlReject::Ctrl).unwrap().as_slice(),
            b"%2G"
        );
        assert_eq!(
            decode_all(b"%G2", UrlReject::Ctrl).unwrap().as_slice(),
            b"%G2"
        );
        // The first '%' is literal, then "%20" is a real escape.
        assert_eq!(
            decode_all(b"%%20", UrlReject::Ctrl).unwrap().as_slice(),
            b"% "
        );
        // And a '%' at the end of a longer string, where two bytes remain.
        assert_eq!(
            decode_all(b"path%2", UrlReject::Ctrl).unwrap().as_slice(),
            b"path%2"
        );
    }

    /// *** THE THRESHOLD TRAP ***
    ///
    /// `lib/escape.c` L139 rejects `in < 0x20`. So `%1f`, which decodes to
    /// `0x1f`, is refused, and `%20`, which decodes to `0x20`, is accepted.
    /// One byte apart, opposite answers, and the boundary is the whole
    /// point: a port written with `<=` would reject every space that arrived
    /// encoded, which `tests/libtest/lib1560.c` exercises heavily.
    #[test]
    fn reject_ctrl_refuses_0x1f_and_accepts_0x20() {
        assert_eq!(
            decode_all(b"a%1fb", UrlReject::Ctrl),
            Err(CURLcode::CURLE_URL_MALFORMAT),
            "0x1f is below 0x20 and must be rejected"
        );
        assert_eq!(
            decode_all(b"a%20b", UrlReject::Ctrl).unwrap().as_slice(),
            b"a b",
            "0x20 is not below 0x20 and must be accepted"
        );
        // The same boundary through the predicate itself, which is where a
        // future edit would land.
        assert!(UrlReject::Ctrl.rejects(0x1f));
        assert!(!UrlReject::Ctrl.rejects(0x20));
    }

    /// `UrlReject::Ctrl` accepts `0x7f`, which is where it parts company
    /// with `Curl_junkscan`.
    ///
    /// Set A at `lib/urlapi.c` L234 rejects byte 127 in a comparison of its
    /// own; set B here has no such term. This test is the executable form of
    /// the module documentation's warning, and it fails the moment somebody
    /// "unifies" the two rejection sets or reaches for
    /// `u8::is_ascii_control`.
    #[test]
    fn reject_ctrl_accepts_0x7f_unlike_junkscan() {
        let out = decode_all(b"a%7fb", UrlReject::Ctrl).unwrap();
        assert_eq!(out.as_slice(), b"a\x7fb");
        assert!(!UrlReject::Ctrl.rejects(0x7f), "set B has no 0x7f term");
        // And the byte that separates the two sets on the other side, the
        // space, which set A rejects unless CURLU_ALLOW_SPACE is given.
        assert!(!UrlReject::Ctrl.rejects(b' '));
    }

    /// The full 0x00-0x1f range is rejected, and nothing above it is.
    ///
    /// The sweep is over decoded values rather than over raw input, because
    /// that is what `lib/escape.c` L139 tests.
    #[test]
    fn reject_ctrl_covers_exactly_the_bytes_below_0x20() {
        for byte in 0..=u8::MAX {
            let input = escape(byte);
            let result = decode_all(&input, UrlReject::Ctrl);
            if byte < 0x20 {
                assert_eq!(
                    result,
                    Err(CURLcode::CURLE_URL_MALFORMAT),
                    "byte {byte:#04x} decodes below 0x20 and must be rejected"
                );
            } else {
                assert_eq!(
                    result.unwrap().as_slice(),
                    &[byte],
                    "byte {byte:#04x} is at or above 0x20 and must be accepted"
                );
            }
        }
    }

    /// A round-trip over all 256 byte values.
    ///
    /// The escape is built with the encoder's own `hexbyte`, and
    /// `UrlReject::Nada` is used so that the rejection rule does not mask
    /// the conversion being tested. Written against `crate::ctype::hexbyte`,
    /// the primitive `src/encode.rs` is built on, so the round trip is
    /// checked here without depending on a module this one does not need.
    #[test]
    fn every_byte_survives_an_escape_round_trip() {
        for byte in 0..=u8::MAX {
            let input = escape(byte);
            let out = decode_all(&input, UrlReject::Nada).unwrap();
            assert_eq!(out.len(), 1, "three input bytes become one");
            assert_eq!(
                out.as_slice(),
                &[byte],
                "round trip failed for byte {byte:#04x}"
            );
        }
    }

    /// `%00` under each of the three modes.
    ///
    /// `UrlReject::Ctrl` refuses it because zero is below `0x20`,
    /// `UrlReject::Zero` refuses it by its own term at `lib/escape.c` L140,
    /// and `UrlReject::Nada` copies it, producing a buffer whose content
    /// holds an interior zero. That last case is worth asserting rather than
    /// assuming: the C produces exactly the same buffer, and its length,
    /// from L151, counts the zero.
    #[test]
    fn a_decoded_zero_byte_under_each_mode() {
        assert_eq!(
            decode_all(b"a%00b", UrlReject::Ctrl),
            Err(CURLcode::CURLE_URL_MALFORMAT)
        );
        assert_eq!(
            decode_all(b"a%00b", UrlReject::Zero),
            Err(CURLcode::CURLE_URL_MALFORMAT)
        );
        let permissive = decode_all(b"a%00b", UrlReject::Nada).unwrap();
        assert_eq!(permissive.as_slice(), b"a\x00b");
        assert_eq!(permissive.len(), 3, "the interior zero is counted");
    }

    /// `UrlReject::Zero` refuses only zero, and `UrlReject::Nada` refuses
    /// nothing at all.
    #[test]
    fn the_narrow_and_permissive_modes_are_not_reject_ctrl() {
        assert!(UrlReject::Zero.rejects(0x00));
        assert!(!UrlReject::Zero.rejects(0x01));
        assert!(!UrlReject::Zero.rejects(0x1f));
        for byte in 0..=u8::MAX {
            assert!(!UrlReject::Nada.rejects(byte), "Nada accepts everything");
        }
        // A control byte other than zero passes the narrow mode, which is
        // the observable difference between the two.
        let out = decode_all(b"%01", UrlReject::Zero).unwrap();
        assert_eq!(out.as_slice(), b"\x01");
    }

    /// A zero `length` measures the input, per `lib/escape.c` L115.
    ///
    /// This is the overload `urldecode_host` at `lib/urlapi.c` L590 relies
    /// on. Zero does not mean "decode nothing".
    #[test]
    fn a_zero_length_measures_the_input() {
        let out = decode(b"%41%42", 0, UrlReject::Ctrl).unwrap();
        assert_eq!(out.as_slice(), b"AB");
        // And measuring stops at an interior NUL, exactly as strlen does, so
        // the bytes behind it are not decoded and the zero itself is not
        // offered to the reject test.
        let stopped = decode(b"a%41\x00b%42", 0, UrlReject::Ctrl).unwrap();
        assert_eq!(stopped.as_slice(), b"aA");
    }

    /// An explicit length decodes through an interior NUL, which is then
    /// subject to the reject test like any other byte.
    ///
    /// The C behaves the same way: with a non-zero `length` it never calls
    /// `strlen`, so nothing stops the loop early.
    #[test]
    fn an_explicit_length_does_not_stop_at_a_nul() {
        assert_eq!(
            decode_all(b"a\x00b", UrlReject::Ctrl),
            Err(CURLcode::CURLE_URL_MALFORMAT),
            "the raw NUL is below 0x20"
        );
        let permissive = decode_all(b"a\x00b", UrlReject::Nada).unwrap();
        assert_eq!(permissive.as_slice(), b"a\x00b");
    }

    /// An explicit length shorter than the slice narrows the window, and one
    /// longer than the slice is clamped to it.
    ///
    /// The narrowing case is the interesting one, because it is where the
    /// `alloc > 2` test at `lib/escape.c` L126 is a statement about the
    /// window rather than about the buffer: `b"%41"` with a length of 2
    /// leaves too little for an escape, so both bytes stay literal even
    /// though the byte that would complete it is right there.
    #[test]
    fn the_window_is_the_length_not_the_buffer() {
        assert_eq!(decode(b"%41", 3, UrlReject::Ctrl).unwrap().as_slice(), b"A");
        assert_eq!(
            decode(b"%41", 2, UrlReject::Ctrl).unwrap().as_slice(),
            b"%4"
        );
        assert_eq!(decode(b"%41", 1, UrlReject::Ctrl).unwrap().as_slice(), b"%");
        // Clamped rather than read past the end of the slice.
        assert_eq!(
            decode(b"%41", 99, UrlReject::Ctrl).unwrap().as_slice(),
            b"A"
        );
    }

    /// An empty input yields an empty buffer, not an error and not a null.
    ///
    /// The C allocates one byte at L116 and writes the terminator at L147,
    /// so an empty string is a real allocation there too. Both spellings of
    /// "nothing to do" agree, which is worth pinning because zero is also
    /// the measure-it sentinel.
    #[test]
    fn an_empty_input_decodes_to_an_empty_buffer() {
        let explicit = urldecode_bytes(b"", UrlReject::Ctrl).unwrap();
        assert_eq!(explicit.len(), 0);
        assert!(explicit.is_empty());
        assert_eq!(explicit.as_bytes_with_nul(), b"\x00");

        let measured = urldecode(b"", 0, UrlReject::Ctrl).unwrap();
        assert_eq!(measured.len(), 0);
    }

    /// An input made only of escapes decodes to a third of its length.
    #[test]
    fn an_input_of_nothing_but_escapes() {
        let out = decode_all(b"%2f%2F%20%41", UrlReject::Ctrl).unwrap();
        assert_eq!(out.as_slice(), b"// A");
        assert_eq!(out.len(), 4, "twelve input bytes become four");
    }

    /// The reported length is the decoded length, and it shrinks by two per
    /// escape.
    ///
    /// `lib/escape.c` L151 computes `ns - *ostring`, so the length describes
    /// the output and never the input. Output can only shrink, because the
    /// only rewriting rule turns three bytes into one.
    #[test]
    fn the_reported_length_describes_the_output() {
        let input = b"/a%20b%2Fc%%d%";
        let out = urldecode_bytes(input, UrlReject::Ctrl).unwrap();
        assert_eq!(out.as_bytes(), b"/a b/c%%d%");
        assert_eq!(out.len(), 10);
        assert!(
            out.len() < input.len(),
            "two escapes must cost four bytes: {} vs {}",
            out.len(),
            input.len()
        );
        // Every prefix relationship the rule implies, checked on a run of
        // inputs rather than on one: n escapes shorten the output by 2n.
        for escapes in 0..8_usize {
            let mut built: Vec<u8> = Vec::new();
            for _ in 0..escapes {
                built.extend_from_slice(b"%41");
            }
            built.extend_from_slice(b"tail");
            let decoded = urldecode_bytes(&built, UrlReject::Ctrl).unwrap();
            assert_eq!(decoded.len(), built.len() - 2 * escapes);
        }
    }

    /// The buffer is a valid C string as well as a Rust slice.
    ///
    /// `lib/escape.c` L147 is `*ns = 0`. The port gets the terminator for
    /// free, because the block arrives zeroed, so the property is asserted
    /// here rather than taken on trust.
    #[test]
    fn the_buffer_is_nul_terminated_at_the_decoded_length() {
        let out = urldecode_bytes(b"%41%42c", UrlReject::Ctrl).unwrap();
        assert_eq!(out.as_bytes(), b"ABc");
        let with_nul = out.as_bytes_with_nul();
        assert_eq!(with_nul.len(), out.len() + 1);
        assert_eq!(with_nul.last(), Some(&0), "terminator at the decoded end");
    }

    /// A rejection yields no buffer at all.
    ///
    /// This is the port's rendering of `Curl_safefree(*ostring)` at
    /// `lib/escape.c` L141, which frees the block and nulls the caller's
    /// pointer. Here the `Err` variant carries nothing, so there is no
    /// pointer to null and none to leak: the block was released by `Drop`
    /// before the error was returned. The property is structural, and this
    /// test records that it is relied upon, since a future refactor to a
    /// `(pointer, code)` pair would reintroduce exactly the dangling-pointer
    /// question the C has to answer by hand.
    #[test]
    fn a_rejection_hands_back_no_buffer() {
        let result = urldecode_bytes(b"ok%1fbad", UrlReject::Ctrl);
        assert!(result.is_err(), "a control byte must be rejected");
        assert_eq!(
            result.err(),
            Some(CURLcode::CURLE_URL_MALFORMAT),
            "and the code is the one lib/escape.c L142 returns"
        );
        // The rejection happens mid-buffer, after several bytes have already
        // been written, which is the case where the C has something to free.
        assert_eq!(
            decode_all(b"aaaaaaaa%00", UrlReject::Ctrl),
            Err(CURLcode::CURLE_URL_MALFORMAT)
        );
    }

    /// The two entry points agree, and disagree only where documented.
    #[test]
    fn the_two_entry_points_agree_on_the_window() {
        let inputs: [&[u8]; 6] = [b"", b"plain", b"%41", b"%", b"%GG", b"a%20b%7f"];
        for input in inputs {
            assert_eq!(
                decode_all(input, UrlReject::Nada),
                decode(input, input.len(), UrlReject::Nada),
                "urldecode_bytes must be urldecode with an explicit length"
            );
        }
        // The one documented difference: a leading NUL. The measuring form
        // stops before it, the exact form decodes it.
        assert_eq!(
            decode(b"\x00abc", 0, UrlReject::Nada).unwrap().as_slice(),
            b""
        );
        assert_eq!(
            decode_all(b"\x00abc", UrlReject::Nada).unwrap().as_slice(),
            b"\x00abc"
        );
    }

    /// `measure` reproduces `alloc = (length ? length : strlen(string))`.
    #[test]
    fn measure_implements_the_length_overload() {
        assert_eq!(measure(b"abcdef", 0), b"abcdef");
        assert_eq!(measure(b"abc\x00def", 0), b"abc");
        assert_eq!(measure(b"\x00abc", 0), b"");
        assert_eq!(measure(b"abcdef", 3), b"abc");
        assert_eq!(measure(b"abc\x00def", 7), b"abc\x00def");
        assert_eq!(measure(b"abc", 99), b"abc");
        assert_eq!(measure(b"", 0), b"");
        assert_eq!(measure(b"", 5), b"");
    }

    /// `decode_step` is the recognition rule the single pass walks with.
    ///
    /// Asserting the consumed count directly is what pins the invariant the
    /// loop rests on: the count is 1 or 3, never 0, so the window always
    /// shrinks and the loop always ends.
    #[test]
    fn decode_step_reports_the_byte_and_the_consumption() {
        assert_eq!(decode_step(b""), None);
        assert_eq!(decode_step(b"a"), Some((b'a', 1)));
        assert_eq!(decode_step(b"%41"), Some((b'A', 3)));
        assert_eq!(decode_step(b"%41more"), Some((b'A', 3)));
        // Fewer than three bytes remain, so the '%' is literal.
        assert_eq!(decode_step(b"%4"), Some((b'%', 1)));
        assert_eq!(decode_step(b"%"), Some((b'%', 1)));
        // Three bytes remain but a digit is not hexadecimal.
        assert_eq!(decode_step(b"%4z"), Some((b'%', 1)));
        assert_eq!(decode_step(b"%z4"), Some((b'%', 1)));
        // The high nibble really is the high one.
        assert_eq!(decode_step(b"%10"), Some((0x10, 3)));
        assert_eq!(decode_step(b"%01"), Some((0x01, 3)));
        assert_eq!(decode_step(b"%ff"), Some((0xff, 3)));
    }

    /// `advance` never leaves the window, and never fails to shrink it.
    #[test]
    fn advance_is_total() {
        assert_eq!(advance(b"abc", 1), b"bc");
        assert_eq!(advance(b"abc", 3), b"");
        // Past the end is clamped to empty, so a loop driven by it ends
        // instead of repeating a byte. Unreachable from `decode_step`, whose
        // counts are bounded by the window, and pinned anyway.
        assert_eq!(advance(b"ab", 5), b"");
        assert_eq!(advance(b"", 1), b"");
    }

    /// A long input exercises the decode over something bigger than the
    /// three-byte window the other tests use.
    ///
    /// The point is agreement between the destination the input sized and the
    /// length the decode reports at scale: an error of one either truncates
    /// the output or leaves the reported length short, and both show up here.
    #[test]
    fn a_long_mixed_input_decodes_completely() {
        let mut input: Vec<u8> = Vec::new();
        let mut want: Vec<u8> = Vec::new();
        for index in 0..500_u32 {
            match index % 4 {
                0 => {
                    input.extend_from_slice(b"%41");
                    want.push(b'A');
                }
                1 => {
                    input.extend_from_slice(b"x");
                    want.push(b'x');
                }
                2 => {
                    // A malformed escape, which stays literal and so
                    // contributes three output bytes for three input bytes.
                    input.extend_from_slice(b"%zz");
                    want.extend_from_slice(b"%zz");
                }
                _ => {
                    input.extend_from_slice(b"%20");
                    want.push(b' ');
                }
            }
        }
        let out = urldecode_bytes(&input, UrlReject::Ctrl).unwrap();
        assert_eq!(out.len(), want.len());
        assert_eq!(out.as_bytes(), want.as_slice());
        assert_eq!(
            out.as_bytes_with_nul().last(),
            Some(&0),
            "still terminated after a long decode"
        );
    }

    /// The decoded buffer really is the crate's C-allocator buffer.
    ///
    /// An ownership assertion rather than a behavioral one, and it is
    /// checked at the type level on purpose. Proving it at run time would
    /// mean calling `CBuf::into_raw` and then `CBuf::from_raw` to avoid
    /// leaking, and `from_raw` is `unsafe`: this file has no `unsafe` in it
    /// and is not going to acquire any for a test. Coercing both entry
    /// points to a function pointer with the exact signature is enough,
    /// because it fails to compile the moment either one starts returning
    /// something other than a buffer this crate owns and C can free.
    ///
    /// The run-time proof that such a buffer is allocated and released
    /// correctly belongs to the `CBuf` and `CBlock` tests in `src/alloc.rs`
    /// and `src/ffi.rs`; there is no reason to repeat it here.
    #[test]
    fn the_result_is_a_c_allocator_buffer() {
        let measured: fn(&[u8], usize, UrlReject) -> Result<CBuf, CURLcode> = urldecode;
        let exact: fn(&[u8], UrlReject) -> Result<CBuf, CURLcode> = urldecode_bytes;
        assert_eq!(
            measured(b"%41", 0, UrlReject::Ctrl).unwrap().as_bytes(),
            b"A"
        );
        assert_eq!(exact(b"%42", UrlReject::Ctrl).unwrap().as_bytes(), b"B");
    }
}
