// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Relative-URL resolution: `redirect_url` at `lib/urlapi.c` L1214-L1284.
//!
//! One function, and the comment above it at L1211-L1213 is its whole
//! specification in a line: "Concatenate a relative URL onto a base URL
//! making it absolute."
//!
//! It is `static` in the C and is declared in neither
//! `include/curl/urlapi.h` nor `lib/urlapi-int.h`, so nothing here carries an
//! export attribute. `src/ffi.rs` owns the entire exported surface, and
//! acceptance criterion A2 requires the archive's symbol set to equal the
//! eight globals `lib/urlapi.o` defines, so an extra export here would fail
//! the surface check rather than help it.
//!
//! # The one caller, and the three things it has already ruled out
//!
//! `set_url` at `lib/urlapi.c` L1685-L1730 reaches this function at L1727 and
//! is its only caller anywhere in the tree. It arrives having already
//! disposed of everything else it could have done, which is why nothing below
//! defends against any of it:
//!
//! 1. **A zero-length value never gets here.** L1697-L1710 handles it, and
//!    that branch is flag-sensitive in a way this function takes no part in:
//!    it re-reads the whole URL through `curl_url_get` **with the caller's
//!    flags**, so `""` is a successful no-op when those flags let the handle
//!    serialize itself and `CURLUE_MALFORMED_INPUT` when they do not --
//!    `CURLU_DEFAULT_SCHEME` on a scheme-less handle being the flag that
//!    actually moves the answer, and `CURLU_NO_GUESS_SCHEME` not being one,
//!    for the reason `set_url` sets out at its own documentation.
//!    `src/getset.rs` owns that behavior. No empty-string handling belongs
//!    here.
//! 2. **An absolute value never gets here.** L1713-L1715 replaces the handle
//!    outright, passing the guess argument as the bitwise or of
//!    `CURLU_GUESS_SCHEME` and `CURLU_DEFAULT_SCHEME`.
//! 3. **A base that cannot be serialized never gets here.** L1719-L1723 falls
//!    back to replacing the handle with the new value instead.
//!
//! So `base` is always a URL that `urlget_url` produced from **this very
//! handle**, two lines earlier. Every assumption below rests on exactly that,
//! and the two places it bends are called out where they bend.
//!
//! # The separator, and why C can be cavalier about it
//!
//! L1225 is the whole computation:
//!
//! ```c
//! const char *protsep = base + strlen(u->scheme) + 3;   /* past "://" */
//! ```
//!
//! `protsep` is meant to point at the first byte after `scheme://`, which for
//! an ordinary URL is the start of the host name. The C adds the three
//! punctuation bytes unconditionally and never checks that they are there,
//! because for the caller above they always are: `urlget_url` writes
//! `"%s://"` at L1513 and the `file:` branch writes the literal `file://` at
//! L1441.
//!
//! There are two shapes where that reasoning does not hold, and neither is a
//! reason to depart from the C:
//!
//! - **The prefix can be missing entirely.** L1512-L1515 emits an *empty*
//!   scheme buffer when `CURLU_NO_GUESS_SCHEME` is set and the handle's
//!   scheme was guessed, while `u->scheme` is still populated. `protsep` then
//!   lands some bytes into the host name instead of at its start. Everything
//!   downstream still works on that input -- the searches simply start later
//!   -- so this port reproduces it rather than compensating.
//! - **`protsep` can point past a credential.** For
//!   `http://user:foo@example.com/path` it addresses `user:foo@...`, not the
//!   host, because the userinfo sits between the `://` and the host name. The
//!   C comment at L1224 says "hostname" regardless. Harmless, since every
//!   search from here is for a delimiter that follows the authority, and the
//!   `../../newpage` case at `tests/libtest/lib1560.c` L1355-L1358 pins that
//!   the credentials survive.
//!
//! What this port cannot reproduce is reading past the end of the string.
//! `strlen(u->scheme) + 3` can exceed the length of `base` in the first shape
//! above, and C would then walk off the allocation; the crate root denies
//! unchecked arithmetic and direct indexing precisely so that cannot happen
//! here. The offset is therefore clamped to the length of `base`, which makes
//! the searches operate on an empty tail and produce no cutoff -- a defined
//! outcome where the C has none. The divergence is confined to inputs on
//! which the C is undefined.
//!
//! # The four branches
//!
//! L1231-L1267 switches on the first byte of the relative part. `cutoff` is
//! where the base gets truncated, `useurl` is what gets appended, and
//! `host_changed` decides whether the appended text has an authority of its
//! own.
//!
//! | Branch | First byte | `cutoff` | Other effects |
//! |---|---|---|---|
//! | protocol-relative | `/` with a second `/` | `protsep` | `useurl` skips both slashes; `host_changed` |
//! | root-relative | `/` alone | first `/` at or after `protsep` | -- |
//! | fragment-only | `#` | first `#` at or after `protsep`, only when a fragment is set | -- |
//! | default | anything else | see below | -- |
//!
//! An empty relative part would take the default branch in the C, because
//! `relurl[0]` is then the terminating NUL, and it takes the default branch
//! here too, because `first()` reports `None`. The agreement is incidental:
//! guarantee 1 above means an empty relative part never arrives.
//!
//! # The default branch, and its three subtleties
//!
//! L1250-L1266, in order, is where nearly every surprise in this function
//! lives:
//!
//! ```c
//! if(u->query && u->query[0])            cutoff = strchr(protsep, '?');
//! else if(u->fragment && u->fragment[0]) cutoff = strchr(protsep, '#');
//!
//! if(relurl[0] != '?') {
//!   cutoff = memrchr(protsep, '/',
//!                    cutoff ? (size_t)(cutoff - protsep) : strlen(protsep));
//!   if(cutoff)
//!     cutoff++;
//! }
//! ```
//!
//! 1. **Both tests require a non-empty string, not merely a non-null one.**
//!    `u->query[0]` is the second half of each test and it is load-bearing: a
//!    bare `?` in a URL stores a query of `""`, at L1057-L1062, so a handle
//!    really can hold an empty query and an empty query does **not** trigger
//!    the strip. `tests/libtest/lib1560.c` L1246-L1247 is the case that pins
//!    it, `file:///basic?` plus `?yay` giving `file:///basic?yay`.
//!
//!    The fragment-only branch is deliberately **not** symmetric: L1246 tests
//!    `u->fragment` alone, with no `[0]`. That asymmetry is unobservable
//!    through a parse, because a bare `#` leaves the fragment null and only
//!    records `fragment_present` at L1016-L1032, so a fragment is either
//!    absent or non-empty. It is reproduced exactly anyway. Folding the two
//!    tests into one helper would erase a difference that the C makes and
//!    that a future setter could expose.
//! 2. **The two are mutually exclusive.** A non-empty query wins outright and
//!    the fragment is not considered at all, which is what the `else if`
//!    says.
//! 3. **The last-slash truncation is skipped for a query-only relative
//!    part.** L1259 guards it on `relurl[0] != '?'`, so `?y` replaces the
//!    query and keeps the whole path, while `y` replaces the last path
//!    segment. `tests/libtest/lib1560.c` L1273-L1281 covers both directions.
//!
//! The fourth subtlety has no comment in the C at all: **the assignment at
//! L1261 is unconditional**. When the reverse search finds no slash it
//! stores null, *discarding* a cutoff the query or fragment search had just
//! found, and the base is then kept whole so the relative part is appended to
//! whatever was already there. The `if(cutoff)` at L1263 guards only the
//! increment, not the assignment.
//!
//! # Assembly, and the flag that is taken away
//!
//! L1269-L1283 concatenates and re-parses:
//!
//! - `prelen` is the distance from `base` to `cutoff`, or the whole length of
//!   `base` when there is no cutoff. L1264's increment is what keeps the
//!   final slash inside that prefix.
//! - The encoder's `relative` argument is `!host_changed`, L1275. On the
//!   protocol-relative branch it is therefore **false**, which sends
//!   `urlencode_str` through `find_host_sep` to copy the new authority
//!   verbatim -- host names must not be percent-encoded or IDN resolution
//!   fails, which is the reason recorded at L124-L128. On every other branch
//!   it is true and the whole relative part is encoded. The `query` argument
//!   is always false.
//! - **`CURLU_PATH_AS_IS` is cleared for the re-parse**, L1277. Dot-segment
//!   removal therefore always runs on the result of a redirect, even for a
//!   caller that asked for the path to be left alone. That is deliberate in
//!   the C and is reproduced here without comment in the code beyond naming
//!   the line; `tests/libtest/lib1560.c` L1254-L1259 asserts it three times
//!   over.
//! - Either append failing yields `CURLUE_OUT_OF_MEMORY`, L1279-L1280. Note
//!   what that is *not*: it does not go through `cc2cu`, so a
//!   `CURLE_TOO_LARGE` from the length ceiling is reported as an
//!   out-of-memory rather than as `CURLUE_TOO_LARGE`. Every other assembly
//!   site in the module folds through `cc2cu`; this one does not, and
//!   "improving" it would change an ABI-visible result code.
//!
//! # Memory ownership
//!
//! The scratch buffer is initialized at L1272 and freed at L1282 on **both**
//! paths. It is never handed to the handle and never handed to C, which makes
//! it the exception in this module: `docs/MEMORY-OWNERSHIP.md` catalogues ten
//! sites where a buffer's allocation moves to a new owner, and this is not
//! one of them. `docs/KNOWN-DIVERGENCES.md` records it as "L1272 in
//! `redirect_url`, freed unconditionally at L1282".
//!
//! Two consequences follow. Neither the success path nor the failure path may
//! release the buffer twice: on the failure path the append that failed has
//! already released it, which is contract 1 of `src/dynbuf.rs`, and the free
//! that runs afterwards is harmless only because releasing an empty buffer is
//! defined. And the bytes handed to `parseurl_and_replace` are *borrowed*,
//! never moved, so the handle ends up owning copies that its own stages made.
//!
//! # Panic and unsafe posture
//!
//! Nothing here can panic and nothing here is `unsafe`. That matters more in
//! this file than in most, because the C is built almost entirely from
//! pointer differences -- `cutoff - protsep` at L1262, `cutoff - base` at
//! L1269, and the `+ 3` at L1225 -- and every one of them is a subtraction or
//! an addition that the crate root denies in its unchecked form. All of it is
//! expressed here as offsets into `base` with `saturating_add`,
//! `saturating_sub` and bounds-checked slicing, so a mistake can produce a
//! wrong prefix but never an out-of-bounds read and never a panic. An error
//! code is never substituted for a panic either: that would hide exactly the
//! class of defect the parity diff exists to expose.
//!
//! # End-to-end verification
//!
//! The tests at the end of this file drive all four branches and each
//! subtlety above.
//!
//! The end-to-end oracle is the unmodified `tests/libtest/lib1560.c`,
//! whose `set_url_list` table at L1226-L1381 is forty-odd redirect cases. The
//! sub-test this file drives is `set_url`, whose failure is reported as exit
//! code 1 by that entry point. `rust-urlapi/scripts/run-parity.sh` runs it and
//! that sub-test passes in both link modes. Expectations below were taken from
//! that table rather than from a reading of RFC 3986, and the ones that came
//! from it name their line.

// The plan puts every `unsafe` block in `src/ffi.rs` (AAP 0.3.3) and the
// technical specification forbids `unsafe` outside FFI code (1.3.2.1). This
// module inspects two byte slices, appends to a buffer and calls back into
// its own parent, so it needs nothing from C at all. `forbid` rather than
// `deny`, so that an inner `allow` has to be argued for rather than slipped
// in.
#![forbid(unsafe_code)]

use core::ffi::c_uint;

use crate::abi::{CURLUcode, CURLUE_MALFORMED_INPUT, CURLUE_OK, CURLUE_OUT_OF_MEMORY};
use crate::abi::{CURLU_PATH_AS_IS, CURL_MAX_INPUT_LENGTH};
use crate::dynbuf::DynBuf;
use crate::encode::urlencode_str;
use crate::handle::CurlUrl;

use super::parseurl_and_replace;

/// The three bytes L1225 steps over, `:` and the two slashes.
///
/// Named rather than written as a literal because it is the one number in
/// this file that encodes an assumption about the *shape* of the base string
/// rather than a position within it. The module documentation explains when
/// that assumption does not hold and what is done about it.
const SCHEME_PUNCTUATION_LEN: usize = 3;

/// `strchr(&base[from], needle)`, reported as an absolute offset into `base`.
///
/// Three call sites, all in [`redirect_url`]: L1241, L1247 and L1254. Each
/// searches forward from `protsep` for one delimiter byte, and each stores the
/// result straight into `cutoff`, which is why an index is returned rather
/// than a slice -- `cutoff` is later subtracted from `base` at L1269, and an
/// offset makes that a comparison of two numbers instead of pointer
/// arithmetic.
///
/// # Where this differs from `strchr`
///
/// `strchr` stops at the terminating NUL and this stops at the end of the
/// slice. The two coincide for every caller, because `base` holds exactly the
/// bytes of a C string produced by `urlget_url`, which assembles it from the
/// handle's own NUL-terminated members and so cannot contain an interior NUL.
/// `src/ffi.rs` owns the conversion that establishes that.
///
/// `from` is always the clamped separator offset, so `get(from..)` succeeds
/// and the `None` this can return always means "the delimiter is absent",
/// never "the start was out of range".
fn strchr_from(base: &[u8], from: usize, needle: u8) -> Option<usize> {
    let tail = base.get(from..)?;

    tail.iter()
        .position(|&byte| byte == needle)
        // Exact rather than saturating in practice: `at` is an index within
        // `tail`, so `from + at` is an index within `base`. Spelled
        // saturating because the crate root denies the bare operator.
        .map(|at| from.saturating_add(at))
}

/// `memrchr(&base[from], needle, bound)`, reported as an absolute offset into
/// `base`.
///
/// One call site, L1261, and it is the only backwards search in the module.
/// The `bound` is what the C computes inline: the distance from `protsep` to
/// the cutoff a forward search already found, or the length of the remaining
/// string when it found nothing. Passing it in keeps that choice visible at
/// the call site, where the C makes it, instead of hiding it here.
///
/// The increment at L1263-L1264 is deliberately **not** applied here. It
/// belongs to the caller, because it is guarded separately in the C and
/// because it is what makes the trailing slash part of the retained prefix
/// rather than the discarded tail.
///
/// A `bound` longer than the remaining bytes is clamped to them, which cannot
/// happen from the one call site -- both of the C's expressions are bounded by
/// `strlen(protsep)` -- and is defined here rather than checked, so that no
/// panic and no unchecked slice appears.
fn memrchr_from(base: &[u8], from: usize, bound: usize, needle: u8) -> Option<usize> {
    let tail = base.get(from..)?;
    let window = tail.get(..bound).unwrap_or(tail);

    window
        .iter()
        .rposition(|&byte| byte == needle)
        .map(|at| from.saturating_add(at))
}

/// Concatenates a relative URL onto the handle's own serialized URL and
/// replaces the handle with the result.
///
/// `redirect_url` at `lib/urlapi.c` L1214-L1284. The module documentation
/// carries the branch table, the four subtleties of the default branch, the
/// cleared `CURLU_PATH_AS_IS` and the ownership of the scratch buffer; this
/// comment covers only the contract.
///
/// # Parameters
///
/// - `base`: the handle's current URL, exactly the bytes `urlget_url` produced
///   and no terminating NUL. `set_url` obtains it at L1719 and releases it at
///   L1728, so it is borrowed here and outlives the call.
/// - `relurl`: the relative part, holding the bytes up to the C caller's
///   terminating NUL. Never empty in practice; see guarantee 1 in the module
///   documentation.
/// - `u`: the live handle. Written only if the re-parse succeeds, which
///   [`parseurl_and_replace`] guarantees. `base` must not alias anything owned
///   by `u`, which the signature enforces here and which holds in the C
///   because L1700 and L1719 hand back a fresh allocation rather than an
///   interior pointer.
/// - `flags`: the caller's `CURLU_*` word. Only one bit is read, and only to
///   remove it; see L1277.
///
/// # Returns
///
/// `CURLUE_OK` with the handle replaced by the resolved URL.
///
/// # Errors
///
/// - `CURLUE_MALFORMED_INPUT` for an absent base, L1227-L1228.
/// - `CURLUE_OUT_OF_MEMORY` when either append fails, L1279-L1280, including
///   the case the C would elsewhere have reported as `CURLUE_TOO_LARGE`.
/// - Otherwise whatever the re-parse reported, unchanged, with the handle
///   untouched.
#[must_use = "the resolution verdict is the return value and must be handled"]
pub(crate) fn redirect_url(
    base: &[u8],
    relurl: &[u8],
    u: &mut CurlUrl,
    flags: c_uint,
) -> CURLUcode {
    // L1226-L1228. The C's `DEBUGASSERT(base && relurl && u)` is discharged
    // by the types for `relurl` and `u`: a slice cannot be null and neither
    // can a reference. The `if(!base)` that follows it is dead in the C for
    // the same reason the assertion is -- L1725 asserts `oldurl` is set and
    // L1719 only reaches L1727 having succeeded -- and its comment says so:
    // "should never happen".
    //
    // A pointer test cannot be written against a slice, so the nearest
    // reachable expression of "there is no base URL to concatenate onto" is
    // taken instead, and it returns the same code the C does. Like the C's,
    // this is unreachable from `set_url`, because `urlget_url` produces at
    // minimum `scheme://host/` or `file:///`, never nothing.
    if base.is_empty() {
        return CURLUE_MALFORMED_INPUT;
    }

    // Everything the handle is consulted for is read now, as plain scalars,
    // before any of it is needed. That is not tidiness: `parseurl_and_replace`
    // below takes the handle mutably, so no borrow of it may still be live by
    // then, and copying out four values is the cheapest way to make that a
    // property of the code rather than a thing to remember.
    //
    // L1225. `strlen(u->scheme)` on a null scheme would fault in the C; the
    // caller's guarantee is what stops it, since a handle whose URL
    // serialized has a scheme or reached the `file:` branch. An absent scheme
    // is treated as zero-length here, which keeps the arithmetic defined on an
    // input the C cannot survive.
    let scheme_len = u.scheme().map_or(0, |scheme| scheme.len());
    // L1252, the full `u->query && u->query[0]`. Subtlety 1.
    let query_nonempty = u.query().is_some_and(|query| !query.is_empty());
    // L1246, `u->fragment` alone. Deliberately not the same test as the next
    // line; see subtlety 1.
    let fragment_present = u.fragment().is_some();
    // L1255, the full `u->fragment && u->fragment[0]`.
    let fragment_nonempty = u.fragment().is_some_and(|fragment| !fragment.is_empty());

    // L1225, clamped. The clamp is the whole subject of "why C can be
    // cavalier about it" in the module documentation: the sum can exceed the
    // length of `base`, C would then read past the allocation, and this port
    // may not. Clamping to the length leaves an empty tail, so every search
    // below reports "not found" and the base is kept whole.
    let protsep = scheme_len
        .saturating_add(SCHEME_PUNCTUATION_LEN)
        .min(base.len());

    // L1218-L1220. `cutoff` is an absolute offset into `base` where the C
    // holds a pointer into it, and `None` is the C's null.
    let mut host_changed = false;
    let mut useurl: &[u8] = relurl;
    let mut cutoff: Option<usize> = None;

    // L1230-L1267. `first()` stands in for `relurl[0]`; an empty relative part
    // reaches the default arm here exactly as the terminating NUL would take
    // it to `default` in the C.
    match relurl.first() {
        Some(&b'/') => {
            // L1233. `relurl.get(1)` is `None` for a one-byte "/", which is
            // not `Some(&b'/')`, so a lone slash takes the root-relative
            // branch just as the C's NUL does.
            if relurl.get(1) == Some(&b'/') {
                // L1234-L1237, protocol-relative: `//example.com/path`. The
                // base is cut at the separator, so only `scheme://` survives,
                // and the two leading slashes are dropped from what gets
                // appended because the retained prefix already ends in them.
                //
                // `host_changed` is set here and nowhere else, and its only
                // use is to invert the encoder's `relative` argument at L1275.
                cutoff = Some(protsep);
                useurl = relurl.get(2..).unwrap_or(&[]);
                host_changed = true;
            } else {
                // L1240-L1241, an absolute path: everything from the first
                // slash of the old path onwards is discarded, so the authority
                // and any credentials are kept.
                cutoff = strchr_from(base, protsep, b'/');
            }
        }
        Some(&b'#') => {
            // L1244-L1247, fragment-only. The search runs only when the
            // handle already has a fragment; with no fragment there is nothing
            // to cut and `cutoff` stays null, so the whole base is kept and
            // the new fragment is appended to it. Both halves are asserted
            // below.
            //
            // Note again that this tests presence alone, with no `[0]`, unlike
            // the query and fragment tests in the default arm.
            if fragment_present {
                cutoff = strchr_from(base, protsep, b'#');
            }
        }
        _ => {
            // L1250-L1257. A non-empty query wins; the two are mutually
            // exclusive, which is subtlety 2.
            if query_nonempty {
                cutoff = strchr_from(base, protsep, b'?');
            } else if fragment_nonempty {
                cutoff = strchr_from(base, protsep, b'#');
            }

            // L1259. Skipped for a query-only relative part, which is what
            // lets `?y` keep the whole path. Subtlety 3.
            if relurl.first() != Some(&b'?') {
                // L1262. The search length is the distance to the cutoff a
                // forward search just found, or the whole remaining string
                // when it found none. Both subtractions are exact -- a cutoff
                // came from a search that started at `protsep`, and `protsep`
                // is clamped to the length -- and are spelled saturating
                // because the crate root denies the bare operator.
                let bound = match cutoff {
                    Some(at) => at.saturating_sub(protsep),
                    None => base.len().saturating_sub(protsep),
                };

                // L1261 and L1263-L1264. The assignment is UNCONDITIONAL: a
                // window with no slash in it stores null and so DISCARDS the
                // cutoff the query or fragment search just found, leaving the
                // base whole. Only the increment is guarded, and it is what
                // keeps the slash itself inside the retained prefix.
                cutoff = memrchr_from(base, protsep, bound, b'/').map(|at| at.saturating_add(1));
            }
        }
    }

    // L1269. A null cutoff means "keep the whole base".
    let prelen = cutoff.unwrap_or(base.len());
    // Every branch produces a cutoff no larger than the length of `base`:
    // `protsep` is clamped to it, a forward search reports an index inside it,
    // and the backwards search reports at most the last byte, whose increment
    // is the length itself. So the slice always succeeds and the fallback is
    // unreachable; it is written so the bound is checked by the compiler
    // instead of argued for in a comment.
    let prefix = base.get(..prelen).unwrap_or(base);

    // L1272. The ceiling is the same `CURL_MAX_INPUT_LENGTH` the parser uses,
    // so an assembled URL that no longer fits is refused here rather than
    // deeper in.
    let mut urlbuf = DynBuf::new(CURL_MAX_INPUT_LENGTH);

    // L1274-L1275. Rust's `&&` short-circuits exactly as C's does, so a failed
    // first append means the encoder is never called -- which matters, because
    // that append has already released the buffer.
    //
    // The encoder's `relative` argument is `!host_changed`: false on the
    // protocol-relative branch, which makes `urlencode_str` copy the new
    // authority verbatim, and true everywhere else. The `query` argument is
    // always false.
    let assembled = urlbuf.addn(prefix).is_ok()
        && urlencode_str(&mut urlbuf, useurl, useurl.len(), !host_changed, false) == CURLUE_OK;

    let uc = if assembled {
        // L1276-L1277. CURLU_PATH_AS_IS is cleared for the re-parse, so dot
        // segments are always removed from a redirect result even when the
        // caller asked for the path to be left alone. The bytes are borrowed
        // from the buffer, not handed to it: the handle ends up owning copies
        // the parse stages made.
        parseurl_and_replace(urlbuf.as_bytes(), u, flags & !CURLU_PATH_AS_IS)
    } else {
        // L1279-L1280. Both failures collapse to one code, and this site
        // deliberately does not fold through `crate::error::cc2cu`: a
        // CURLE_TOO_LARGE from the ceiling is reported as an out-of-memory
        // here, unlike at every other assembly site in the module.
        CURLUE_OUT_OF_MEMORY
    };

    // L1282, and it runs on both paths. Dropping the buffer at the end of the
    // scope would release it just as well; the explicit call keeps the
    // line-for-line correspondence and states that the allocation goes nowhere
    // -- this buffer is never handed to the handle and never handed to C. A
    // failed append released it already, and releasing an emptied buffer is
    // defined, so the two paths converge here safely.
    urlbuf.free();

    uc
}

#[cfg(test)]
mod tests {
    //! Tests for the four branches, the four subtleties of the default
    //! branch, the cleared `CURLU_PATH_AS_IS` and the two arithmetic guards.
    //!
    //! Every case is driven in the shape `set_url` uses: a base URL string
    //! and a relative string, with the handle first parsed from that same
    //! base so that its scheme, query and fragment agree with it exactly as
    //! the caller's guarantee promises.
    //!
    //! Assertions are made on the handle's members rather than on a
    //! serialized URL, because serialization belongs to `src/getset.rs`. That
    //! is not a weaker test: the members are what the serializer reads, and
    //! the members are where an off-by-one in a cutoff shows up.
    //!
    //! Where a case comes from `tests/libtest/lib1560.c` its line is named,
    //! because a case the reference suite already asserts outranks one
    //! invented here: if this file and that table ever disagree, the parity
    //! run says which is wrong.
    //!
    //! # Why every base is `https:` or `file:` where the reference table says
    //! `http:`
    //!
    //! Because both feature configurations have to be green, and they resolve
    //! schemes from different places. With `scheme-table` on, `src/scheme.rs`
    //! answers from its own built-in table; with it off -- the drop-in
    //! configuration, `--no-default-features --features idn-libidn2` -- the
    //! lookup is `Curl_get_scheme`, imported from a libcurl that no test
    //! binary links against, so `src/ffi.rs` supplies a `cfg(test)` stand-in
    //! for it. That stand-in has four rows: `https`, `imap`, `file` and
    //! `rtmp`. A base with an `http:` scheme therefore parses in one
    //! configuration and answers `CURLUE_UNSUPPORTED_SCHEME` in the other,
    //! through `parse_scheme` at `lib/urlapi.c` L951-L953.
    //!
    //! Nothing is weakened by the substitution, and that is a property of the
    //! function rather than a hope: the only thing `redirect_url` reads from
    //! the scheme is its **length**, at L1225. `https` is one byte longer than
    //! `http`, so every offset below shifts by exactly one and every expected
    //! part is unchanged. The `http:` cases themselves are covered where they
    //! can be covered properly, by the parity run against a real libcurl.

    // The crate root denies the panicking constructs so that no panic can
    // reach the C boundary. A test's whole job is to panic when an assertion
    // fails, and no test crosses that boundary, so the denials are relaxed
    // here and only here, enumerated rather than blanket. This is the same
    // allowance, for the same reason, as the one in `src/parse/mod.rs`.
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]

    use core::ffi::c_uint;

    use super::{memrchr_from, redirect_url, strchr_from};
    use crate::abi::{CURLUcode, CURLUE_MALFORMED_INPUT, CURLUE_OK, CURLU_PATH_AS_IS};
    use crate::handle::CurlUrl;
    use crate::parse::parseurl_and_replace;

    /// No flags at all, which is what most of these cases want.
    const NO_FLAGS: c_uint = 0;

    /// Builds the exact situation `set_url` hands to `redirect_url` and
    /// reports the verdict alongside the handle.
    ///
    /// The handle is parsed from `base` first, which is what makes the test
    /// faithful: `lib/urlapi.c` L1719 obtains the base by serializing this
    /// very handle, so the handle's query and fragment always describe the
    /// string being cut. Constructing the two independently would test a
    /// situation the caller cannot produce.
    fn resolve(base: &[u8], relurl: &[u8], flags: c_uint) -> (CURLUcode, CurlUrl) {
        let mut u = CurlUrl::new();
        let parsed = parseurl_and_replace(base, &mut u, flags);
        assert_eq!(
            parsed, CURLUE_OK,
            "the base must parse before it can be a base"
        );

        let code = redirect_url(base, relurl, &mut u, flags);
        (code, u)
    }

    /// Parses a handle and leaves it alone, for the two cases that hand
    /// `redirect_url` a base its caller could never produce.
    fn handle_from(url: &[u8]) -> CurlUrl {
        let mut u = CurlUrl::new();
        assert_eq!(parseurl_and_replace(url, &mut u, NO_FLAGS), CURLUE_OK);
        u
    }

    /// A base with a path of two segments, which is what most of the default
    /// branch's cases want to cut.
    const TWO_SEGMENTS: &[u8] = b"https://a.example/p/q";

    /// The separator offset for every `https:` base below, and the argument the
    /// two search helpers are exercised with directly.
    ///
    /// Five bytes of scheme plus the three of `://`, which is L1225 evaluated
    /// by hand. Named so the helper tests read as offsets from the separator
    /// rather than as bare numbers.
    const PROTSEP: usize = 8;

    /// L1233-L1237. The base is cut at the separator, so only `http://`
    /// survives, and the relative part supplies a new authority.
    ///
    /// `tests/libtest/lib1560.c` L1231-L1234 is the same shape:
    /// `//somewhere.example.com/reply/1314` onto
    /// `http://firstplace.example.com/want/1314`.
    #[test]
    fn a_protocol_relative_part_replaces_the_authority() {
        let (code, u) = resolve(TWO_SEGMENTS, b"//b.example/r", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.scheme(), Some(b"https".as_slice()));
        // The host is genuinely replaced, not merely accepted: the base's own
        // host was a.example.
        assert_eq!(u.host(), Some(b"b.example".as_slice()));
        assert_eq!(u.path(), Some(b"/r".as_slice()));
    }

    /// L1275. On the protocol-relative branch the encoder is called with
    /// `relative == false`, so it splits the relative part at the authority
    /// and encodes only what follows.
    ///
    /// The space lands in the path, after the split, so it is encoded. The
    /// companion test below puts one before the split, where it is not.
    #[test]
    fn the_tail_of_a_protocol_relative_part_is_still_encoded() {
        let (code, u) = resolve(TWO_SEGMENTS, b"//b.example/a b", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.host(), Some(b"b.example".as_slice()));
        assert_eq!(u.path(), Some(b"/a%20b".as_slice()));
    }

    /// The discriminating pair for `!host_changed` at L1275, and the reason
    /// the argument cannot be simplified to a constant.
    ///
    /// A space inside the relative part's authority is copied **verbatim**,
    /// because `urlencode_str` appends everything up to `find_host_sep` in one
    /// unexamined append -- the reason is at L124-L128, that encoding a host
    /// name breaks IDN resolution. The assembled URL therefore still holds a
    /// raw space, and `Curl_junkscan` at L1124 rejects it, since
    /// `CURLU_ALLOW_SPACE` is not set.
    ///
    /// The identical bytes offered as a root-relative part take
    /// `relative == true`, are encoded from the first byte, and succeed. Swap
    /// the argument and one half of this test fails whichever way it is swapped.
    #[test]
    fn the_new_authority_is_not_encoded_but_a_root_relative_path_is() {
        let (verbatim, untouched) = resolve(TWO_SEGMENTS, b"//b example/r", NO_FLAGS);
        assert_eq!(verbatim, CURLUE_MALFORMED_INPUT);
        // L1204's success test never unlocked the swap, so the handle still
        // holds what the base parsed to.
        assert_eq!(untouched.host(), Some(b"a.example".as_slice()));
        assert_eq!(untouched.path(), Some(b"/p/q".as_slice()));

        let (encoded, u) = resolve(TWO_SEGMENTS, b"/b example/r", NO_FLAGS);
        assert_eq!(encoded, CURLUE_OK);
        assert_eq!(u.host(), Some(b"a.example".as_slice()));
        assert_eq!(u.path(), Some(b"/b%20example/r".as_slice()));
    }

    /// L1240-L1241. The authority survives and the whole path is replaced.
    #[test]
    fn a_root_relative_part_keeps_the_authority_and_replaces_the_path() {
        let (code, u) = resolve(TWO_SEGMENTS, b"/r", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.host(), Some(b"a.example".as_slice()));
        assert_eq!(u.path(), Some(b"/r".as_slice()));
    }

    /// L1233 at its boundary. A one-byte `/` has no second byte, so it is
    /// root-relative and not protocol-relative -- in the C because `relurl[1]`
    /// is the terminating NUL, and here because `get(1)` reports `None`.
    ///
    /// The result is `http://a.example/`, whose one-byte path `handle_path`
    /// unsets at L1080-L1083, so an absent path here is the correct answer and
    /// not a lost one.
    #[test]
    fn a_lone_slash_is_root_relative() {
        let (code, u) = resolve(TWO_SEGMENTS, b"/", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.host(), Some(b"a.example".as_slice()));
        assert_eq!(u.path(), None);
    }

    /// L1244-L1247 with a fragment present: the old fragment is cut away and
    /// the new one takes its place, with the path untouched.
    ///
    /// `tests/libtest/lib1560.c` L1279-L1280,
    /// `http://example.org/foo?bar#original` plus `#weird`.
    #[test]
    fn a_fragment_only_part_replaces_an_existing_fragment() {
        let (code, u) = resolve(b"https://a.example/p#old", b"#new", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/p".as_slice()));
        assert_eq!(u.fragment(), Some(b"new".as_slice()));
    }

    /// L1246 with no fragment: the search never runs, `cutoff` stays null, and
    /// L1269 therefore keeps the whole base.
    ///
    /// `tests/libtest/lib1560.c` L1240-L1241 is the same shape through the
    /// `file:` scheme, `file:///basic#` plus `#yay`, where the base's own
    /// fragment was empty and so absent.
    #[test]
    fn a_fragment_only_part_with_no_existing_fragment_keeps_the_whole_base() {
        let (code, u) = resolve(b"https://a.example/p", b"#new", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/p".as_slice()));
        assert_eq!(u.fragment(), Some(b"new".as_slice()));
    }

    /// L1261-L1264. The reverse search finds the last slash and the increment
    /// keeps it, so only the final segment is replaced.
    #[test]
    fn a_plain_relative_part_replaces_the_last_path_segment() {
        let (code, u) = resolve(TWO_SEGMENTS, b"r", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/p/r".as_slice()));
    }

    /// L1252-L1254. A non-empty query is cut away by a plain relative part.
    ///
    /// `tests/libtest/lib1560.c` L1285-L1286,
    /// `http://example.org/foo?bar` plus `moo?hey#weird`.
    #[test]
    fn a_non_empty_query_is_dropped_by_a_plain_relative_part() {
        let (code, u) = resolve(b"https://a.example/p?x=1", b"r", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/r".as_slice()));
        assert_eq!(u.query(), None);
    }

    /// Subtlety 1, the literal shape: a handle whose query is `""` does not
    /// trigger the strip at L1252, because the test is `u->query[0]` and not
    /// merely `u->query`.
    ///
    /// The base carries the `?` a `CURLU_GET_EMPTY` serialization would emit,
    /// so the discarded delimiter is really present in the string being cut.
    #[test]
    fn an_empty_query_does_not_trigger_the_strip() {
        let (code, u) = resolve(b"https://a.example/p?", b"r", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.query(), None);
        assert_eq!(u.path(), Some(b"/r".as_slice()));
    }

    /// Subtlety 1, the case that actually discriminates, and the regression
    /// guard for the `[0]` in `u->query[0]`.
    ///
    /// With the relative part starting `?` the truncation at L1259 is skipped,
    /// so `cutoff` is whatever the query test left it as, and the two readings
    /// of L1252 give different answers:
    ///
    /// - testing emptiness, which is what the C does: no cutoff, the whole
    ///   base is kept, and the query becomes `?y`;
    /// - testing presence alone: the cutoff is the `?`, the base is truncated
    ///   before it, and the query becomes `y`.
    ///
    /// Only the first is correct. Compare the previous test, where both
    /// readings agree and so nothing is pinned.
    #[test]
    fn an_empty_query_leaves_the_base_whole_for_a_query_only_part() {
        let (code, u) = resolve(b"https://a.example/p?", b"?y", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/p".as_slice()));
        assert_eq!(u.query(), Some(b"?y".as_slice()));
    }

    /// Subtlety 3. A query-only relative part skips the last-slash truncation
    /// at L1259, so the whole path survives and only the query changes.
    ///
    /// `tests/libtest/lib1560.c` L1274-L1275,
    /// `http://example.org/foo?bar` plus `?weird`.
    #[test]
    fn a_query_only_part_keeps_the_whole_path() {
        let (code, u) = resolve(TWO_SEGMENTS, b"?y=2", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/p/q".as_slice()));
        assert_eq!(u.query(), Some(b"y=2".as_slice()));
    }

    /// Subtlety 2. A non-empty query wins outright: the `else if` at L1255
    /// means the fragment is not considered, so the cut lands on the `?` and
    /// takes the fragment with it.
    #[test]
    fn a_non_empty_query_wins_over_a_non_empty_fragment() {
        let (code, u) = resolve(b"https://a.example/p/q?x=1#old", b"?y", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/p/q".as_slice()));
        assert_eq!(u.query(), Some(b"y".as_slice()));
        assert_eq!(u.fragment(), None);
    }

    /// L1255-L1257. With no query at all, a non-empty fragment is what gets
    /// cut away.
    ///
    /// `tests/libtest/lib1560.c` L1272-L1273,
    /// `http://example.org/#original` plus `?weird#moo`.
    #[test]
    fn a_non_empty_fragment_is_cut_when_there_is_no_query() {
        let (code, u) = resolve(b"https://a.example/p/q#old", b"?y", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/p/q".as_slice()));
        assert_eq!(u.query(), Some(b"y".as_slice()));
        assert_eq!(u.fragment(), None);
    }

    /// Subtlety 4, and it has no comment in the C: the assignment at L1261 is
    /// unconditional, so a window with no slash in it **discards** the cutoff
    /// the query search just found.
    ///
    /// Here the base has no path at all, so the bytes between the separator
    /// and the `?` are the host alone. The reverse search finds no slash, the
    /// cutoff becomes null, the base is kept whole, and the relative part is
    /// appended to the query rather than replacing anything.
    ///
    /// `urlget_url` always writes `u->path ? u->path : "/"` at L1528, so no
    /// base it produces can take this route today. The case is kept because
    /// the assignment must stay unconditional: guarding it on the earlier
    /// result would be a silent behavior change here, and this is the only
    /// test that would notice.
    #[test]
    fn the_reverse_search_assignment_is_unconditional() {
        let (code, u) = resolve(b"https://a.example?x=1", b"r", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.host(), Some(b"a.example".as_slice()));
        assert_eq!(u.path(), None);
        assert_eq!(u.query(), Some(b"x=1r".as_slice()));
    }

    /// L1277, the regression guard for the cleared flag. Dot-segment removal
    /// runs on a redirect result **even though the caller asked for
    /// `CURLU_PATH_AS_IS`**.
    ///
    /// Forwarding the caller's flags unchanged would leave the path as
    /// `/p/../r`, and that is the only thing this test can fail on.
    #[test]
    fn path_as_is_is_cleared_for_the_reparse() {
        let (code, u) = resolve(TWO_SEGMENTS, b"../r", CURLU_PATH_AS_IS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/r".as_slice()));
    }

    /// L1275 with `relative == true`: the whole relative part goes through the
    /// encoder, so a space becomes `%20`.
    ///
    /// `left` starts true because the `query` argument is false, which is what
    /// makes this `%20` rather than `+`.
    #[test]
    fn a_space_in_the_relative_part_is_percent_encoded() {
        let (code, u) = resolve(TWO_SEGMENTS, b"a b", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/p/a%20b".as_slice()));
    }

    /// L1259-L1264 through the `file:` scheme, where `urlget_url` drops the
    /// host at L1441 and the separator therefore lands on the path.
    ///
    /// `tests/libtest/lib1560.c` L1247-L1248, `file:///basic?hello` plus `?q`.
    #[test]
    fn the_file_scheme_replaces_its_query() {
        let (code, u) = resolve(b"file:///basic?hello", b"?q", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.scheme(), Some(b"file".as_slice()));
        assert_eq!(u.path(), Some(b"/basic".as_slice()));
        assert_eq!(u.query(), Some(b"q".as_slice()));
    }

    /// A relative part carrying its own query and fragment: all three parts of
    /// the tail are replaced in one go.
    ///
    /// `tests/libtest/lib1560.c` L1285-L1286,
    /// `http://example.org/foo?bar` plus `moo?hey#weird`.
    #[test]
    fn a_relative_part_may_carry_its_own_query_and_fragment() {
        let (code, u) = resolve(b"https://example.org/foo?bar", b"moo?hey#weird", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/moo".as_slice()));
        assert_eq!(u.query(), Some(b"hey".as_slice()));
        assert_eq!(u.fragment(), Some(b"weird".as_slice()));
    }

    /// The dot-segment case from `tests/libtest/lib1560.c` L1254-L1256,
    /// `http://example.org/` plus `../path/././../././../moo`, expecting
    /// `http://example.org/moo`.
    ///
    /// It walks above the root and the removal absorbs that rather than
    /// failing, which is `dedotdotify`'s behavior and not this function's; the
    /// point here is that the cut retained the trailing slash so the relative
    /// part had somewhere to attach.
    #[test]
    fn the_dot_segment_case_from_the_reference_table() {
        let (code, u) = resolve(
            b"https://example.org/",
            b"../path/././../././../moo",
            NO_FLAGS,
        );

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.host(), Some(b"example.org".as_slice()));
        assert_eq!(u.path(), Some(b"/moo".as_slice()));
    }

    /// `tests/libtest/lib1560.c` L1296-L1299, the three-slash protocol-relative
    /// case: `///example.org/../path/../../` onto `http://example.org/`.
    ///
    /// Two slashes are consumed by the branch itself, so the assembled URL has
    /// three after the colon, and `parse_scheme` accepts one to three at
    /// L945-L957. A fourth would be `CURLUE_BAD_SLASHES`, which is why this
    /// case is worth pinning here rather than only in the scheme stage.
    #[test]
    fn three_slashes_still_parse_after_the_protocol_relative_cut() {
        let (code, u) = resolve(
            b"https://example.org/",
            b"///example.org/../path/../../",
            NO_FLAGS,
        );

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.host(), Some(b"example.org".as_slice()));
        assert_eq!(u.path(), Some(b"/".as_slice()));
    }

    /// `tests/libtest/lib1560.c` L1355-L1358: the separator points at the
    /// userinfo rather than at the host, and the credentials still survive.
    ///
    /// This is the case that shows why the C comment at L1224 saying
    /// "hostname" is harmless. Every search from the separator is for a
    /// delimiter that follows the whole authority, so starting inside the
    /// credentials changes nothing.
    #[test]
    fn credentials_survive_a_relative_part() {
        let (code, u) = resolve(
            b"https://user:foo@example.com/path?query#frag",
            b"../../newpage",
            NO_FLAGS,
        );

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.user(), Some(b"user".as_slice()));
        assert_eq!(u.password(), Some(b"foo".as_slice()));
        assert_eq!(u.host(), Some(b"example.com".as_slice()));
        assert_eq!(u.path(), Some(b"/newpage".as_slice()));
        assert_eq!(u.query(), None);
        assert_eq!(u.fragment(), None);
    }

    /// `tests/libtest/lib1560.c` L1300-L1303: a relative part that looks like
    /// a port, `:23`, is just another path segment.
    ///
    /// It reaches the default branch, because its first byte is neither `/`
    /// nor `#`, and nothing about it is special.
    #[test]
    fn a_colon_leading_relative_part_is_a_path_segment() {
        let (code, u) = resolve(b"https://example.org/foo/bar", b":23", NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.host(), Some(b"example.org".as_slice()));
        assert_eq!(u.path(), Some(b"/foo/:23".as_slice()));
        assert_eq!(u.port(), None);
    }

    /// L1227-L1228, the guard that is dead in the C too. A slice cannot be
    /// null, so the nearest reachable expression of an absent base is an empty
    /// one, and it returns the code the C returns.
    ///
    /// The handle must come out untouched, because the guard returns before
    /// anything is assembled.
    #[test]
    fn an_absent_base_is_malformed_input() {
        let mut u = handle_from(TWO_SEGMENTS);

        assert_eq!(
            redirect_url(b"", b"r", &mut u, NO_FLAGS),
            CURLUE_MALFORMED_INPUT
        );
        assert_eq!(u.host(), Some(b"a.example".as_slice()));
        assert_eq!(u.path(), Some(b"/p/q".as_slice()));
    }

    /// The clamp at L1225. A base shorter than the scheme plus three bytes is
    /// where C walks off the allocation; here the separator is pinned to the
    /// end of the string, every search reports nothing, and the base is kept
    /// whole.
    ///
    /// The handle's scheme is `https`, five bytes, so the unclamped offset
    /// would be eight against a two-byte base. The assembled `abr` has no
    /// scheme and no flag permits guessing one, so the re-parse rejects it --
    /// a defined result code where the C has undefined behavior, and the
    /// handle is left exactly as it was.
    #[test]
    fn a_base_shorter_than_the_separator_offset_is_clamped() {
        let mut u = handle_from(b"https://a.example/p");

        let code = redirect_url(b"ab", b"r", &mut u, NO_FLAGS);

        assert_ne!(code, CURLUE_OK);
        assert_eq!(u.scheme(), Some(b"https".as_slice()));
        assert_eq!(u.host(), Some(b"a.example".as_slice()));
        assert_eq!(u.path(), Some(b"/p".as_slice()));
    }

    /// A base that is exactly the separator offset long: the tail is empty,
    /// which is the boundary the clamp shares with a well-formed input.
    ///
    /// `http://` is seven bytes and the scheme is four, so the separator is
    /// the one-past-the-end offset without any clamping at all. Nothing is
    /// found, the base is kept, and the relative part is appended to it.
    #[test]
    fn a_base_that_ends_at_the_separator_keeps_everything() {
        let mut u = handle_from(TWO_SEGMENTS);

        let code = redirect_url(b"https://", b"a.example/r", &mut u, NO_FLAGS);

        assert_eq!(code, CURLUE_OK);
        assert_eq!(u.host(), Some(b"a.example".as_slice()));
        assert_eq!(u.path(), Some(b"/r".as_slice()));
    }

    /// [`strchr_from`] reports absolute offsets, starts where it is told, and
    /// answers `None` for an absent byte.
    ///
    /// The separator for a five-byte scheme is offset eight, which is where
    /// every search below starts, and `https://a.example/p?q` puts its `/` at
    /// seventeen and its `?` at nineteen.
    #[test]
    fn the_forward_search_reports_absolute_offsets() {
        let base: &[u8] = b"https://a.example/p?q";

        assert_eq!(strchr_from(base, PROTSEP, b'/'), Some(17));
        assert_eq!(strchr_from(base, PROTSEP, b'?'), Some(19));
        assert_eq!(strchr_from(base, PROTSEP, b'#'), None);
        // The start is honoured, so a byte before it is invisible.
        assert_eq!(strchr_from(base, 18, b'/'), None);
        // An empty tail can never match, which is the clamped-separator case.
        assert_eq!(strchr_from(base, base.len(), b'/'), None);
    }

    /// [`memrchr_from`] searches backwards inside the bound it is given, and
    /// the bound is exclusive.
    ///
    /// The bounds below are the two the one call site can pass -- the distance
    /// to a cutoff and the whole remaining length -- plus the two degenerate
    /// values that must not panic.
    #[test]
    fn the_reverse_search_honours_its_bound() {
        let base: &[u8] = b"https://a.example/p/q";

        // The whole remaining string: the later slash, at nineteen, wins.
        assert_eq!(
            memrchr_from(base, PROTSEP, base.len() - PROTSEP, b'/'),
            Some(19)
        );
        // Bounded to exclude that slash: the earlier one, at seventeen, wins.
        assert_eq!(memrchr_from(base, PROTSEP, 11, b'/'), Some(17));
        // Bounded before every slash, and with a zero-length window.
        assert_eq!(memrchr_from(base, PROTSEP, 9, b'/'), None);
        assert_eq!(memrchr_from(base, PROTSEP, 0, b'/'), None);
        // A bound past the end is clamped rather than panicking.
        assert_eq!(memrchr_from(base, PROTSEP, usize::MAX, b'/'), Some(19));
    }
}
