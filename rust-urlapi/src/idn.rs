// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Internationalised-domain conversion: the one capability `lib/urlapi.c`
//! borrows from `lib/idn.c`.
//!
//! `lib/urlapi.c` performs no internationalised-domain work of its own. It
//! calls two static wrappers, `host_decode` at L1338 and `host_encode` at
//! L1347, which forward to `Curl_idn_decode` at `lib/idn.c` L302 and
//! `Curl_idn_encode` at L327, which in turn drive whichever IDN library the
//! build selected. This module is that entire chain re-implemented, and it is
//! the only place in the crate that knows an IDN library exists at all.
//!
//! # The naming inversion, which is not a bug
//!
//! Read this before anything else in the file. curl's names run opposite to
//! intuition, and this port keeps them:
//!
//! | curl name | direction | libidn2 entry point | serves |
//! |---|---|---|---|
//! | `Curl_idn_decode` | UTF-8 to ASCII punycode | `idn2_lookup_ul` | `CURLU_PUNYCODE` |
//! | `Curl_idn_encode` | ASCII punycode to UTF-8 | `idn2_to_unicode_8z8z` | `CURLU_PUNY2IDN` |
//!
//! *Decoding* therefore produces the punycode form and *encoding* consumes
//! it, which is the reverse of what either word suggests. The wrappers inherit
//! the inversion: `host_decode` is what `CURLU_PUNYCODE` reaches, and
//! `host_encode` is what `CURLU_PUNY2IDN` reaches. Both names are kept exactly
//! so that this file can be read side by side with `lib/idn.c` and
//! `lib/urlapi.c`; renaming them to something clearer would cost the port its
//! reviewability, which is a worse outcome than a paragraph of explanation.
//!
//! The direction words are also why the two entry points are *not*
//! symmetrical, and the asymmetry is real behaviour rather than an oversight.
//! See `idn_decode` and `idn_encode` below.
//!
//! # Three configurations, selected at compile time
//!
//! This is the plan's "capability provider selected at compile time" pattern,
//! the Rust expression of `#ifdef USE_IDN` under transformation rule T5.
//! `rust-urlapi/build.rs` reproduces the C's two gates as two separate
//! questions rather than deriving one from the other: `have_idn` stands for
//! `USE_IDN` at `lib/idn.h` L29-L30, and `idn_backend_libidn2` or
//! `idn_backend_pure` names the backend, standing for `USE_LIBIDN2` at
//! `lib/curl_setup.h` L720-L724. That script also refuses a request for both
//! backends, mirroring the `#error` at L726-L728, so this module may assume at
//! most one backend cfg is set and does not re-check it.
//!
//! | Configuration | Stands in for | Parity claimed |
//! |---|---|---|
//! | `idn_backend_libidn2`, the default | `USE_LIBIDN2` | yes, bit for bit |
//! | `idn_backend_pure` | no C equivalent | no, see below |
//! | neither, so no `have_idn` | `USE_IDN` undefined | yes, `CURLUE_LACKS_IDN` |
//!
//! [`host_decode`] and [`host_encode`] exist in all three, so `src/getset.rs`
//! contains no `#[cfg]` of its own: every conditional in the port's IDN
//! handling lives in this file. That mirrors how `lib/urlapi.c` sees only two
//! wrapper names whatever the build.
//!
//! # The six steps of the libidn2 sequence
//!
//! Each of these is individually observable, and dropping any one of them
//! produces a port that converts the easy names and diverges on precisely the
//! names `tests/libtest/lib1560.c` asserts. All six are reproduced:
//!
//! 1. **The version guard.** `idn2_check_version` at `lib/idn.c` L252, whose
//!    failure is `CURLE_NOT_BUILT_IN` at L271.
//! 2. **The exact flag word.** `IDN2_NFC_INPUT` at L253, with
//!    `IDN2_NONTRANSITIONAL` added at L258 only inside the version test at
//!    L254. The conditional is reproduced, not just the answer it gives here.
//! 3. **The lookup.** L261.
//! 4. **The transitional retry on *any* failure.** L262-L265, which the
//!    comment at L263-L264 explains as a fallback to TR46 transitional mode
//!    for better IDNA2003 compatibility. Still failing afterwards is
//!    `CURLE_URL_MALFORMAT` at L267.
//! 5. **Re-duplication through curl's allocator, then `idn2_free`.**
//!    L306-L315 and L331-L340. See the ownership section below.
//! 6. **Rejection of a zero-length result, on the decode path only.**
//!    L316-L323, against L341-L342 which has no such check.
//!
//! Step 4 is worth one concrete example, because a reader may reasonably
//! suspect a retry with strictly *fewer* flags of being dead code. Against
//! libidn2 2.3.8 the name `\u{2603}.de` fails the first call with
//! `IDN2_DISALLOWED` and succeeds on the retry as `xn--n3h.de`. The retry
//! decides the outcome, and the test module asserts exactly that.
//!
//! # The locale trap: preserved deliberately, never papered over
//!
//! `lib/idn.c` L39-L40 reaches the library through `idn2_lookup_ul`, the
//! entry point that interprets its input **in the encoding of the process
//! locale**. Conversion of a non-ASCII name therefore succeeds only where the
//! locale's codeset is UTF-8; under any other codeset libidn2 converts
//! nothing, reporting `IDN2_ICONV_FAIL`, and the module turns that into
//! `CURLUE_BAD_HOSTNAME`. Binding the C library directly is what makes this
//! crate inherit that sensitivity for free, which is the desired outcome, so
//! this module adds no `setlocale` call, no locale normalisation and no UTF-8
//! pre-validation. Any of the three would hide a difference the parity diff
//! exists to expose.
//!
//! Three separate things in curl's own harness exist because of this, and all
//! three have to be present together or the internationalised-domain
//! assertions silently do not run:
//!
//! - `tests/data/test1560` sets the locale environment variable.
//! - `tests/libtest/first.c` L231 calls `setlocale(LC_ALL, "")`. Without it
//!   even a UTF-8 environment leaves the process in the `C` locale, and every
//!   non-ASCII lookup fails.
//! - `tests/runtests.pl` L836-L839 exports `CURL_TEST_HAVE_CODESET_UTF8` when
//!   it finds UTF-8 support, and `tests/libtest/lib1560.c` reads it at L2036
//!   and gates three sub-tests on it, at L1446, L1548 and L1591.
//!
//! One refinement of that picture was measured rather than assumed, and it is
//! recorded here because it is invisible in the C source: only the **decode**
//! direction is locale-sensitive. `idn2_to_unicode_8z8z` is UTF-8 in and
//! UTF-8 out, so the `CURLU_PUNY2IDN` direction converts identically under
//! any codeset. `lib1560.c` L1445-L1446 nevertheless gates both directions on
//! the same flag, which is conservative rather than wrong. On Windows the
//! trap does not arise at all, because L36-L37 selects the byte-oriented
//! `idn2_lookup_u8` instead.
//!
//! # Memory ownership: two allocators are live at once
//!
//! This is the most intricate ownership handoff in the crate, and it is the
//! reason `lib/idn.c` L306-L315 exists at all. libidn2 allocates its result
//! with its own allocator, so that buffer must go back to `idn2_free`; but
//! what curl keeps has to come from curl's allocator, because the caller of
//! `curl_url_get` releases it with `curl_free`
//! (`docs/libcurl/curl_url_get.md` L45). The C therefore duplicates the
//! string and frees the original:
//!
//! ```c
//! char *c = curlx_strdup(d);   /* curl's allocator */
//! idn2_free(d);                /* libidn2's allocator */
//! if(c) d = c; else result = CURLE_OUT_OF_MEMORY;
//! ```
//!
//! The port keeps both halves and makes the boundary a type. [`CBuf`] owns
//! C-allocator memory and is what leaves this module; `Idn2Buf`, private to
//! the libidn2 backend, owns libidn2 memory and can only be released by
//! `idn2_free`. Nothing else in the crate can hold the second kind, and a
//! failure on any path releases it, which is what the `Drop` implementation
//! buys over the C's straight-line code. Note that a failed re-duplication
//! reports out of memory *after* the original has already been freed, exactly
//! as at L309-L313.
//!
//! # The map from C to this file
//!
//! | C | here |
//! |---|---|
//! | `Curl_is_ASCII_name`, `lib/idn.c` L223 | [`is_ascii_name`] |
//! | `Curl_idn_decode`, L302 | `idn_decode` |
//! | `Curl_idn_encode`, L327 | `idn_encode` |
//! | `static idn_decode`, L247 | `libidn2::idn_decode`, `pure::idn_decode` |
//! | `static idn_encode`, L282 | `libidn2::idn_encode`, `pure::idn_encode` |
//! | `host_decode`, `lib/urlapi.c` L1338 | [`host_decode`] |
//! | `host_encode`, L1347 | [`host_encode`] |
//! | the no-IDN macros, L1334-L1336 | the `not(have_idn)` arms |
//!
//! The two layers keep their C names, which means the crate holds `idn_decode`
//! twice: once here for the exported `Curl_idn_decode`, and once inside each
//! backend module for the file-scope static of the same name. That is the
//! faithful reading. `Curl_` is dropped because every other port of a `Curl_`
//! symbol in this crate drops it, and the backend's copy is reached only
//! through its module path, so the two never look alike at a call site.

// The consumer of this module is `src/getset.rs`: `host_decode` and
// `host_encode` stand in for the calls at `lib/urlapi.c` L1404 and L1414 in
// `urlget_format` and at L1499 and L1506 in `urlget_url`, and `is_ascii_name`
// for the four gates at L1402, L1412, L1498 and L1505. The `Curl_idn_*` layer
// is crate-visible because it is not static in C and because it is the only
// layer at which the three `CURLcode` values are still distinguishable; the
// wrappers above it fold two of them together.
//
// Which of these a given build reaches is therefore decided by the feature set
// and by the consumers rather than by this file, and warnings are errors for
// this crate. Rather than let the feature matrix decide whether the build is
// clean, the allowance is stated once here with its reason. It is scoped to
// this module and to this lint alone.
#![allow(dead_code)]

use crate::abi::CURLUcode;
use crate::alloc::CBuf;

#[cfg(have_idn)]
use crate::error::{idn2cu, CURLcode};

#[cfg(not(have_idn))]
use crate::abi::CURLUE_LACKS_IDN;

// The two aliases below also make the contradictory pair a compile error, and
// they do it without restating the check `rust-urlapi/build.rs` already
// performs. Naming both backends `backend` means a build that somehow arrived
// with both cfgs set stops at `error[E0252]: the name backend is defined
// multiple times` rather than silently picking one, so the guarantee survives a
// build that bypassed the script. That is a property of the aliasing rather
// than a check written on purpose, and it is recorded here so that nobody
// "fixes" it by giving the two aliases different names.

/// The backend `lib/curl_setup.h` L720-L724 would have selected.
///
/// Binding the same C library curl binds is what makes bit-for-bit parity
/// attainable, the locale sensitivity included, which is why this is the
/// default.
#[cfg(idn_backend_libidn2)]
use self::libidn2 as backend;

/// The pure-Rust alternative, which has no C equivalent at all.
///
/// Opt-in, and not bit-for-bit; `rust-urlapi/docs/KNOWN-DIVERGENCES.md`
/// records what differs.
#[cfg(idn_backend_pure)]
use self::pure as backend;

/// Whether a hostname contains only bytes below `0x80`.
///
/// `Curl_is_ASCII_name` at `lib/idn.c` L223-L236, in full:
///
/// ```c
/// const unsigned char *ch = (const unsigned char *)hostname;
/// if(!hostname) /* bad input, consider it ASCII! */
///   return TRUE;
/// while(*ch) {
///   if(*ch++ & 0x80)
///     return FALSE;
/// }
/// return TRUE;
/// ```
///
/// Two properties of that loop are load-bearing and both are reproduced here.
///
/// **A missing hostname counts as ASCII.** The C comment says so in as many
/// words, and it is not a detail: this function is the gate on both
/// conversions, and which way a null host falls decides which branch of the
/// `if`/`else if` chain at `lib/urlapi.c` L1401-L1420 runs. A null host makes
/// `!Curl_is_ASCII_name(u->host)` false, so `CURLU_PUNYCODE` converts
/// nothing, while `Curl_is_ASCII_name(u->host)` is true, so `CURLU_PUNY2IDN`
/// proceeds. `None` here is that null, and it returns `true`.
///
/// **The test is the high bit of each byte and nothing more.** There is no
/// UTF-8 validation, no code-point awareness and no rejection of a lone
/// continuation byte; a byte scan is the whole of it. `0x80` through `0xff`
/// are equally "not ASCII" however they arrived.
///
/// The scan stops at an interior zero byte, because the C loop stops at its
/// terminator. No call site in this crate can produce one, since
/// `Curl_junkscan` at `lib/urlapi.c` L223-L246 rejects control bytes in the
/// input, but reproducing the C's stopping condition costs one combinator and
/// removes the question.
///
/// # Ownership
///
/// Nothing changes hands. The argument is borrowed for the call and no
/// allocation occurs.
#[must_use]
pub(crate) fn is_ascii_name(hostname: Option<&[u8]>) -> bool {
    match hostname {
        // lib/idn.c L228-L229.
        None => true,
        Some(bytes) => bytes
            .iter()
            .copied()
            // The `while(*ch)` terminator test at L231.
            .take_while(|byte| *byte != 0)
            // The `*ch++ & 0x80` test at L232, inverted because this asks
            // whether every byte passes rather than whether one fails.
            .all(|byte| (byte & 0x80) == 0),
    }
}

/// Convert a name to its ASCII punycode form, rejecting an empty result.
///
/// `Curl_idn_decode` at `lib/idn.c` L302-L325. Despite the name this is the
/// *lookup* direction, UTF-8 in and punycode out; see the module
/// documentation. It is what `CURLU_PUNYCODE` ultimately reaches.
///
/// ```c
/// char *d = NULL;
/// CURLcode result = idn_decode(input, &d);
/// #ifdef USE_LIBIDN2
///   ... duplicate through curl's allocator, idn2_free the original ...
/// #endif
/// if(!result) {
///   if(!d[0]) { /* ended up zero length, not acceptable */
///     result = CURLE_URL_MALFORMAT;
///     curlx_free(d);
///   }
///   else
///     *output = d;
/// }
/// return result;
/// ```
///
/// The re-duplication block is `#ifdef USE_LIBIDN2`, that is, it belongs to
/// one backend rather than to this layer, so the port puts it inside that
/// backend. What remains here is exactly what the C leaves outside the
/// preprocessor guard: the zero-length rejection, and nothing else.
///
/// # The zero-length rejection is not defensive
///
/// It is reachable. Against libidn2 2.3.8 an empty input is `IDN2_OK` with an
/// empty result, so `idn_decode(b"")` reports `CURLE_URL_MALFORMAT` and, once
/// folded by [`host_decode`], `CURLUE_BAD_HOSTNAME`. `idn_encode` has no such
/// check and accepts the same empty result, which is the C's asymmetry at
/// L316-L323 against L341-L342 and is reproduced rather than tidied.
///
/// # Ownership
///
/// `input` is borrowed for the call. On success the caller receives a fresh
/// [`CBuf`] over C-allocator memory, which is the buffer
/// `docs/libcurl/curl_url_get.md` L45 promises can be released with
/// `curl_free`. On the zero-length path the buffer this function built is
/// released here, which is `curlx_free(d)` at L319.
///
/// # Errors
///
/// `CURLcode::CURLE_URL_MALFORMAT` for a name the backend rejected or a
/// zero-length result, `CURLcode::CURLE_NOT_BUILT_IN` for a libidn2 too old
/// to use, and `CURLcode::CURLE_OUT_OF_MEMORY` for an allocation failure.
/// [`host_decode`] folds the first two together.
#[cfg(have_idn)]
pub(crate) fn idn_decode(input: &CBuf) -> Result<CBuf, CURLcode> {
    // L305. `?` is the `if(!result)` that guards everything after it: the C
    // tests the code three times on the way down, and each test is this
    // early return.
    let decoded = backend::idn_decode(input)?;
    // L317. `!d[0]` on a NUL-terminated string is "the first byte is the
    // terminator", which for an owned buffer is its length being zero.
    if decoded.is_empty() {
        // L318-L319. Dropping `decoded` here is `curlx_free(d)`; the C frees
        // before returning the code, and so does this.
        drop(decoded);
        return Err(CURLcode::CURLE_URL_MALFORMAT);
    }
    // L322, `*output = d`.
    Ok(decoded)
}

/// Convert an ASCII punycode name back to its Unicode form.
///
/// `Curl_idn_encode` at `lib/idn.c` L327-L344. Despite the name this is the
/// direction that *consumes* punycode and produces UTF-8; see the module
/// documentation. It is what `CURLU_PUNY2IDN` ultimately reaches.
///
/// ```c
/// char *d = NULL;
/// CURLcode result = idn_encode(puny, &d);
/// #ifdef USE_LIBIDN2
///   ... duplicate through curl's allocator, idn2_free the original ...
/// #endif
/// if(!result)
///   *output = d;
/// return result;
/// ```
///
/// **There is deliberately no zero-length check.** `Curl_idn_decode` has one
/// at L317 and this function does not, so an empty result is accepted here and
/// rejected there. Adding one for symmetry would change observable behaviour:
/// against libidn2 2.3.8 an empty input converts to an empty output with
/// `IDNA_SUCCESS`, so `idn_encode(b"")` succeeds and yields an empty buffer.
/// Transformation rule T6, faithful over correct, governs this.
///
/// # Ownership
///
/// As for [`idn_decode`]: `puny` is borrowed, and a successful call hands back
/// C-allocator memory the caller owns.
///
/// # Errors
///
/// `CURLcode::CURLE_URL_MALFORMAT` for input the backend could not convert and
/// `CURLcode::CURLE_OUT_OF_MEMORY` for an allocation failure, the latter
/// including libidn2's own `IDNA_MALLOC_ERROR`. Note that this path has no
/// version guard, because the C's does not either: `idn_encode` at L282-L300
/// calls straight into the library.
#[cfg(have_idn)]
pub(crate) fn idn_encode(puny: &CBuf) -> Result<CBuf, CURLcode> {
    // L330 and L341-L342, in one line, because the C's remaining work on this
    // path is the `#ifdef USE_LIBIDN2` block that belongs to the backend.
    backend::idn_encode(puny)
}

/// The `CURLU_PUNYCODE` entry point: a hostname in its punycode form.
///
/// `host_decode` at `lib/urlapi.c` L1338-L1345:
///
/// ```c
/// CURLcode result = Curl_idn_decode(host, allochost);
/// if(result)
///   return (result == CURLE_OUT_OF_MEMORY) ?
///     CURLUE_OUT_OF_MEMORY : CURLUE_BAD_HOSTNAME;
/// return CURLUE_OK;
/// ```
///
/// The fold is lossy and stays lossy. Only an allocation failure crosses over
/// as itself; a name libidn2 rejected and a libidn2 too old to ask are both
/// `CURLUE_BAD_HOSTNAME`, and a caller cannot tell them apart. That is the
/// original's behaviour and enriching it would be a behavioural change, so the
/// conversion is delegated to [`crate::error::idn2cu`], where every numeric
/// translation in the crate lives.
///
/// Reached from two places, both of which first check that the host is *not*
/// already ASCII, at `lib/urlapi.c` L1402 and L1498:
/// `urlget_format` for `CURLUPART_HOST` at L1404, and `urlget_url` for the
/// whole-URL serialisation at L1499.
///
/// # Ownership
///
/// `host` is borrowed. A successful call returns C-allocator memory the caller
/// owns; in the C that value lands in `part` at L1408 or in `allochost` at
/// L1499, and both are released with `curlx_free`.
///
/// # Errors
///
/// `CURLUE_OUT_OF_MEMORY` for an allocation failure, `CURLUE_BAD_HOSTNAME` for
/// anything else the backend reported, and `CURLUE_LACKS_IDN` when the crate
/// was built with no backend at all.
#[cfg(have_idn)]
pub(crate) fn host_decode(host: &CBuf) -> Result<CBuf, CURLUcode> {
    idn_decode(host).map_err(idn2cu)
}

/// The `CURLU_PUNY2IDN` entry point: a hostname in its Unicode form.
///
/// `host_encode` at `lib/urlapi.c` L1347-L1354, which differs from
/// [`host_decode`] in exactly one respect, the function it calls. The fold is
/// the same and is delegated to the same place.
///
/// Reached from two places, both of which first check that the host *is*
/// ASCII, at `lib/urlapi.c` L1412 and L1505: `urlget_format` at L1414 and
/// `urlget_url` at L1506. Note the gate is the opposite way round from
/// [`host_decode`]'s, and that it accepts a null host, which
/// [`is_ascii_name`] explains.
///
/// # Ownership
///
/// As for [`host_decode`].
///
/// # Errors
///
/// As for [`host_decode`]. Unlike that function this one has no zero-length
/// rejection, so an empty conversion is a success.
#[cfg(have_idn)]
pub(crate) fn host_encode(host: &CBuf) -> Result<CBuf, CURLUcode> {
    idn_encode(host).map_err(idn2cu)
}

/// The `CURLU_PUNYCODE` entry point of a build with no IDN support.
///
/// `lib/urlapi.c` L1334-L1335 replaces the whole function with a macro:
///
/// ```c
/// #ifndef USE_IDN
/// #define host_decode(x, y) CURLUE_LACKS_IDN
/// ```
///
/// So the C evaluates neither argument and always reports code 30. This does
/// the same. The signature is kept identical to the supported form so that
/// `src/getset.rs` needs no `#[cfg]`, which is the whole point of putting the
/// conditional here.
///
/// # Ownership
///
/// Nothing changes hands and nothing is allocated. The C macro discards both
/// of its arguments, and the binding below is where this one discards its own.
///
/// # Errors
///
/// Always `CURLUE_LACKS_IDN`.
#[cfg(not(have_idn))]
pub(crate) fn host_decode(host: &CBuf) -> Result<CBuf, CURLUcode> {
    let _discarded = host;
    Err(CURLUE_LACKS_IDN)
}

/// The `CURLU_PUNY2IDN` entry point of a build with no IDN support.
///
/// `lib/urlapi.c` L1336, the companion macro to the one [`host_decode`]
/// documents, and identical to it in every respect including the code it
/// reports.
///
/// # Ownership
///
/// Nothing changes hands and nothing is allocated.
///
/// # Errors
///
/// Always `CURLUE_LACKS_IDN`.
#[cfg(not(have_idn))]
pub(crate) fn host_encode(host: &CBuf) -> Result<CBuf, CURLUcode> {
    let _discarded = host;
    Err(CURLUE_LACKS_IDN)
}

/// The default backend: libidn2, bound directly.
///
/// This module stands in for the `USE_LIBIDN2` arms of `lib/idn.c`, which are
/// the `#include <idn2.h>` at L33, the `IDN2_LOOKUP` macro at L35-L41, the
/// `USE_LIBIDN2` body of `idn_decode` at L251-L271, the whole of `idn_encode`
/// at L285-L288, and the re-duplication blocks at L306-L315 and L331-L340.
///
/// It is the crate's third FFI island, after `src/ffi.rs` and the platform
/// address conversion in `src/inet.rs`. Every `unsafe` block below is a call
/// into libidn2 or a read of memory libidn2 returned, and each carries the
/// invariant it relies on. What leaves the module is a [`CBuf`] and a
/// `CURLcode`, so the layer above contains no `unsafe` at all and
/// `src/getset.rs` never sees a raw pointer.
///
/// `rust-urlapi/build.rs` emits `cargo:rustc-link-lib=idn2` for this
/// configuration, so nothing here has to arrange the link.
#[cfg(idn_backend_libidn2)]
mod libidn2 {
    use core::ptr;
    use core::slice;
    use libc::{c_char, c_int, c_void};

    use super::{CBuf, CURLcode};

    /// `IDN2_OK`, `idn2.h`. The success value of every entry point here.
    const IDN2_OK: c_int = 0;

    /// `IDN2_MALLOC`, `idn2.h`. libidn2 could not allocate.
    const IDN2_MALLOC: c_int = -100;

    /// `IDN2_NFC_INPUT`, `idn2.h`: normalise the input to normalisation form
    /// C. Requested at `lib/idn.c` L253.
    const IDN2_NFC_INPUT: c_int = 1;

    /// `IDN2_TRANSITIONAL`, `idn2.h`: Unicode TR46 transitional processing.
    /// The retry at `lib/idn.c` L265 passes this **alone**, dropping
    /// `IDN2_NFC_INPUT` along with everything else.
    const IDN2_TRANSITIONAL: c_int = 4;

    /// `IDN2_NONTRANSITIONAL`, `idn2.h`: Unicode TR46 non-transitional
    /// processing. Added at `lib/idn.c` L258.
    const IDN2_NONTRANSITIONAL: c_int = 8;

    /// `IDNA_SUCCESS`, `idn2.h`, which that header defines as `IDN2_OK`.
    ///
    /// `idn_encode` at `lib/idn.c` L287 tests the `IDNA_*` compatibility names
    /// where `idn_decode` tests the `IDN2_*` ones, for the same two values.
    /// Both spellings are kept here, aliased exactly as `idn2.h` aliases them,
    /// so that each call site can be read against the C line it came from.
    const IDNA_SUCCESS: c_int = IDN2_OK;

    /// `IDNA_MALLOC_ERROR`, `idn2.h`, which that header defines as
    /// `IDN2_MALLOC`. Tested at `lib/idn.c` L288.
    const IDNA_MALLOC_ERROR: c_int = IDN2_MALLOC;

    /// The version handed to `idn2_check_version`, NUL terminated.
    ///
    /// `lib/idn.c` L252 passes `IDN2_VERSION`, the version string of the
    /// **header** the C was compiled against, so the guard asks "is the
    /// library at least as new as the header I was built from". A Rust binding
    /// has no header and therefore no such string, so the closest faithful
    /// question is "is the library at least as new as the version these
    /// declarations were written against", and the answer here is the same
    /// floor `rust-urlapi/build.rs` checks with pkg-config, 2.0.0.
    ///
    /// One consequence is worth stating rather than leaving to be discovered.
    /// Where a C build has newer headers than its runtime library, its guard
    /// fails and ours does not, so the C reports `CURLE_NOT_BUILT_IN` and this
    /// port converts the name. That is a mismatched installation, which
    /// `build.rs` already warns about at configure time, and it is the only
    /// input on which the two disagree. Everything the guard is actually for,
    /// namely a libidn2 too old to honour these declarations, behaves
    /// identically.
    const IDN2_VERSION: &[u8] = b"2.0.0\0";

    /// The same floor in the packed form `IDN2_VERSION_NUMBER` uses, which is
    /// what the preprocessor test at `lib/idn.c` L254 compares.
    ///
    /// libidn2 encodes 2.0.0 as `0x02000000`; the installed 2.3.8 reports
    /// `0x02030008`.
    const IDN2_VERSION_NUMBER: u32 = 0x0200_0000;

    /// The release that introduced `IDN2_NONTRANSITIONAL`, 0.20.0, encoded the
    /// same way. This is the literal the C compares against at `lib/idn.c`
    /// L254.
    const NONTRANSITIONAL_SINCE: u32 = 0x0014_0000;

    /// The flag word of the first lookup, built exactly as `lib/idn.c`
    /// L253-L260 builds it:
    ///
    /// ```c
    /// int flags = IDN2_NFC_INPUT
    /// #if IDN2_VERSION_NUMBER >= 0x00140000
    ///   | IDN2_NONTRANSITIONAL
    /// #endif
    ///   ;
    /// ```
    ///
    /// The conditional is reproduced rather than collapsed into its answer.
    /// With the floor above it selects the two-flag arm, which is what a build
    /// against any libidn2 2.x header also selects, but writing the structure
    /// out keeps the reason visible and keeps a lowered floor honest.
    const LOOKUP_FLAGS: c_int = if IDN2_VERSION_NUMBER >= NONTRANSITIONAL_SINCE {
        IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL
    } else {
        IDN2_NFC_INPUT
    };

    // The declarations from `<idn2.h>`, which `lib/idn.c` L33 includes for
    // exactly these entry points. `libc` does not carry them, so they are
    // written out here; that is the whole of the binding, and no additional
    // crate is involved.
    //
    // The signatures are `idn2.h` verbatim. `idn2_check_version` returns the
    // library's own version string, or null when the requested version is
    // newer than the library, and the C reads only which of the two it got.
    // Both lookup entry points are declared because the C header declares
    // both and the macro at L35-L41 chooses between them per platform.
    extern "C" {
        /// `const char *idn2_check_version(const char *req_version)`.
        fn idn2_check_version(req_version: *const c_char) -> *const c_char;

        /// `int idn2_lookup_ul(const char *src, char **lookupname, int flags)`.
        ///
        /// The **locale-aware** entry point, and so the origin of the locale
        /// trap the module documentation describes. Selected by `lib/idn.c`
        /// L39-L40 on every platform except Windows with wide characters.
        fn idn2_lookup_ul(src: *const c_char, lookupname: *mut *mut c_char, flags: c_int) -> c_int;

        /// `int idn2_lookup_u8(const uint8_t *src, uint8_t **lookupname,
        /// int flags)`.
        ///
        /// The byte-oriented entry point, which reads its input as UTF-8 and
        /// is therefore indifferent to the locale. Selected by `lib/idn.c`
        /// L36-L37 for Windows with wide characters.
        fn idn2_lookup_u8(src: *const u8, lookupname: *mut *mut u8, flags: c_int) -> c_int;

        /// `int idn2_to_unicode_8z8z(const char *input, char **output,
        /// int flags)`.
        ///
        /// UTF-8 in, UTF-8 out, with no locale involvement. Called at
        /// `lib/idn.c` L286.
        fn idn2_to_unicode_8z8z(
            input: *const c_char,
            output: *mut *mut c_char,
            flags: c_int,
        ) -> c_int;

        /// `void idn2_free(void *ptr)`.
        ///
        /// The only correct release for a buffer libidn2 allocated, because
        /// libidn2 may have been built against a different allocator than the
        /// caller. `Idn2Buf` exists so that nothing else can be called on one.
        fn idn2_free(ptr: *mut c_void);
    }

    /// A NUL-terminated string **libidn2 owns**, released with `idn2_free`.
    ///
    /// This is one half of the two-allocator handoff the module documentation
    /// describes, and the type exists to make the halves impossible to
    /// confuse. [`CBuf`] owns C-allocator memory and is released with `free`;
    /// this owns libidn2 memory and is released with `idn2_free`. The C keeps
    /// both in a variable of the same type, `char *d`, and relies on the
    /// programmer to remember which release each one needs.
    ///
    /// It is private to this module and never escapes it: the only way out is
    /// [`reduplicate`], which copies the bytes into a `CBuf` and releases this
    /// one. That is what `lib/idn.c` L306-L315 does, and confining it to one
    /// function means the ordering cannot be got wrong at a second site.
    ///
    /// # Invariants
    ///
    /// 1. `ptr` is non-null and was returned by libidn2.
    /// 2. `len` is the index of its terminator, so `len + 1` bytes are
    ///    readable from `ptr`.
    /// 3. No other owner exists, so `Drop` is the one and only release.
    struct Idn2Buf {
        /// Start of the libidn2-allocated string.
        ptr: *mut c_char,
        /// Length in bytes, excluding the terminator.
        len: usize,
    }

    impl Idn2Buf {
        /// Adopts a pointer libidn2 produced, measuring it.
        ///
        /// Returning `None` for null is what lets a caller adopt the
        /// out-parameter unconditionally and then decide what the return code
        /// meant, which is the order the C works in: it inspects `rc` and
        /// leaves `decoded` alone.
        ///
        /// # Ownership
        ///
        /// Ownership moves *into* the returned value. The caller must not free
        /// `p` afterwards, and must not keep the pointer: `Drop` is now the
        /// only release.
        ///
        /// # Safety
        ///
        /// `p` must be null, or a NUL-terminated string returned by libidn2
        /// and not yet freed, with no other owner. A pointer from any other
        /// allocator must never be passed here, because `idn2_free` is the
        /// only release this type will ever perform.
        #[must_use = "discarding the value frees the string immediately"]
        unsafe fn from_raw(p: *mut c_char) -> Option<Self> {
            if p.is_null() {
                return None;
            }
            // SAFETY: the caller guarantees `p` points at a live,
            // NUL-terminated string, which is `strlen`'s precondition. Its
            // result is the index of that terminator, establishing invariant
            // 2; invariant 1 holds because the null case already returned, and
            // invariant 3 is the caller's guarantee.
            let len = unsafe { libc::strlen(p) };
            Some(Self { ptr: p, len })
        }

        /// The string's bytes, without the terminator.
        ///
        /// # Ownership
        ///
        /// Nothing changes hands. The lifetime of the result is tied to the
        /// borrow, so it cannot outlive the string, and the obligation to
        /// release stays with this value.
        fn as_bytes(&self) -> &[u8] {
            // SAFETY: invariant 1 gives a non-null pointer into a live
            // allocation and invariant 2 makes `self.len` bytes from its start
            // readable and initialised, since libidn2 wrote the string there.
            // `u8` has an alignment of one, which any pointer satisfies. The
            // returned lifetime is tied to `&self`, so the slice cannot
            // outlive the allocation, and `&self` rules out concurrent
            // mutation.
            unsafe { slice::from_raw_parts(self.ptr.cast::<u8>(), self.len) }
        }
    }

    impl Drop for Idn2Buf {
        /// `idn2_free(d)` at `lib/idn.c` L309 and L334.
        fn drop(&mut self) {
            // SAFETY: invariant 1 says `self.ptr` came from libidn2 and
            // invariant 3 says this value is its only owner, which together
            // are `idn2_free`'s precondition. `Drop` runs at most once per
            // value and there is no other way out of this type, so the string
            // is released exactly once.
            unsafe { idn2_free(self.ptr.cast::<c_void>()) };
        }
    }

    /// `IDN2_LOOKUP` at `lib/idn.c` L39-L40, the arm every platform except
    /// Windows with wide characters takes.
    ///
    /// # Safety
    ///
    /// `name` must be a valid pointer to a NUL-terminated string, readable for
    /// the duration of the call. `host` must be a valid, writable location for
    /// one pointer. On success libidn2 writes a string it owns there, which
    /// the caller must release with `idn2_free` exactly once.
    #[cfg(not(windows))]
    unsafe fn lookup(name: *const c_char, host: *mut *mut c_char, flags: c_int) -> c_int {
        // SAFETY: the preconditions are exactly this call's own and are
        // forwarded from the caller unchanged.
        unsafe { idn2_lookup_ul(name, host, flags) }
    }

    /// `IDN2_LOOKUP` at `lib/idn.c` L36-L37, the Windows arm.
    ///
    /// The two casts are the macro's own. They are a reinterpretation of
    /// `char` as `uint8_t`, which have the same size and alignment on every
    /// platform this crate targets, and no conversion of the bytes.
    ///
    /// The plan states that Windows-only paths are ported as conditional code
    /// and validated on that platform rather than here, and this is one of
    /// them. Selecting the byte-oriented entry point means the Windows build
    /// has no locale trap at all.
    ///
    /// # Safety
    ///
    /// As for the other arm.
    #[cfg(windows)]
    unsafe fn lookup(name: *const c_char, host: *mut *mut c_char, flags: c_int) -> c_int {
        // SAFETY: the preconditions are forwarded from the caller, and the
        // casts change only how the same bytes are named, exactly as the C
        // macro's casts do.
        unsafe { idn2_lookup_u8(name.cast::<u8>(), host.cast::<*mut u8>(), flags) }
    }

    /// The version guard at `lib/idn.c` L252.
    ///
    /// `if(idn2_check_version(IDN2_VERSION))` reads the returned pointer as a
    /// truth value and nothing more, so this returns a `bool` and the string
    /// libidn2 reports is deliberately not examined. That string points into
    /// libidn2's own static data and must not be freed.
    fn version_ok() -> bool {
        // SAFETY: `IDN2_VERSION` is a NUL-terminated ASCII literal with static
        // lifetime, so the pointer is valid for reads for the whole call, and
        // `idn2_check_version` only reads it. Its result is either null or a
        // pointer to libidn2's own static version string; only its nullness is
        // read here, so nothing is dereferenced and nothing is freed.
        let reported = unsafe { idn2_check_version(IDN2_VERSION.as_ptr().cast::<c_char>()) };
        !reported.is_null()
    }

    /// Copy a libidn2 string into C-allocator memory and release the original.
    ///
    /// `lib/idn.c` L306-L315 and L331-L340, which are the same five lines
    /// written twice:
    ///
    /// ```c
    /// char *c = curlx_strdup(d);
    /// idn2_free(d);
    /// if(c)
    ///   d = c;
    /// else
    ///   result = CURLE_OUT_OF_MEMORY;
    /// ```
    ///
    /// # Why this exists at all
    ///
    /// Because two allocators are live at once. libidn2 allocated the string
    /// with its own allocator, so it must go back to `idn2_free`; and the
    /// value curl keeps has to come from curl's allocator, because whoever
    /// called `curl_url_get` releases it with `curl_free`
    /// (`docs/libcurl/curl_url_get.md` L45, repeated at
    /// `include/curl/urlapi.h` L130-L131). Handing libidn2's pointer straight
    /// to C would mean a buffer freed by an allocator that never allocated it.
    ///
    /// # Ownership
    ///
    /// `original` is consumed, and it is released here rather than at the end
    /// of the caller: the C frees it *before* testing whether the duplication
    /// worked, and the explicit `drop` below preserves that order. On failure
    /// the original is therefore already gone, which is why the C's own
    /// out-of-memory report at L313 does not free anything. The returned
    /// [`CBuf`] owns C-allocator memory and is what may cross into C.
    ///
    /// # Errors
    ///
    /// `CURLcode::CURLE_OUT_OF_MEMORY` if the copy could not be allocated.
    fn reduplicate(original: Idn2Buf) -> Result<CBuf, CURLcode> {
        // L308. `CBuf::from_slice` is `curlx_strdup` for bytes already in
        // hand: it allocates from the C allocator and appends a terminator.
        let duplicate = CBuf::from_slice(original.as_bytes());
        // L309. Releasing the libidn2 string here, and not one line later,
        // is deliberate: it is the order the C uses, and it keeps the two
        // allocators from both owning a copy of the same name for any longer
        // than the C does.
        drop(original);
        // L310-L313.
        match duplicate {
            Some(buf) => Ok(buf),
            None => Err(CURLcode::CURLE_OUT_OF_MEMORY),
        }
    }

    /// The `USE_LIBIDN2` body of `static idn_decode` at `lib/idn.c`
    /// L247-L280, followed by the re-duplication at L306-L315.
    ///
    /// The re-duplication belongs here rather than one layer up because the C
    /// guards it with `#ifdef USE_LIBIDN2`, which makes it a property of this
    /// backend and not of `Curl_idn_decode`. The other backends in `lib/idn.c`
    /// allocate with curl's allocator to begin with and skip the block
    /// entirely, and `super::pure` does the same.
    ///
    /// # Errors
    ///
    /// `CURLcode::CURLE_NOT_BUILT_IN` when the library is too old (L271),
    /// `CURLcode::CURLE_URL_MALFORMAT` when both lookups failed (L267), and
    /// `CURLcode::CURLE_OUT_OF_MEMORY` when the duplication failed (L313).
    pub(super) fn idn_decode(input: &CBuf) -> Result<CBuf, CURLcode> {
        // L252 and L269-L271. The guard is the first thing the C does and the
        // first thing done here; a library too old to trust is not asked.
        if !version_ok() {
            return Err(CURLcode::CURLE_NOT_BUILT_IN);
        }

        // The borrow is bound rather than used inline so that it is plainly
        // live for every call below. `as_bytes_with_nul` is documented as the
        // way to lend a C-string pointer without giving up ownership: the
        // slice is NUL terminated, `input` keeps owning the block, and libidn2
        // only reads it.
        let source = input.as_bytes_with_nul();
        let name: *const c_char = source.as_ptr().cast::<c_char>();

        let mut decoded: *mut c_char = ptr::null_mut();
        // SAFETY: `name` points at the NUL-terminated `source` slice, which is
        // borrowed from `input` for the whole function, so it is readable for
        // the call. `decoded` is a live local, so `&mut decoded` is a valid
        // writable location for one pointer.
        let mut rc = unsafe { lookup(name, &mut decoded, LOOKUP_FLAGS) };
        // SAFETY: `decoded` is null unless libidn2 wrote a string it owns
        // there, which is exactly this function's precondition, and nothing
        // else has taken ownership of it.
        let mut owned = unsafe { Idn2Buf::from_raw(decoded) };

        if rc != IDN2_OK {
            // L262-L265, the retry. The comment there calls it a fallback to
            // TR46 transitional mode for better IDNA2003 compatibility, and it
            // is not decoration: against libidn2 2.3.8 the first call rejects
            // `\u{2603}.de` with IDN2_DISALLOWED and the retry converts it to
            // `xn--n3h.de`. Note that the flag word is replaced rather than
            // extended, so IDN2_NFC_INPUT is not passed the second time.
            //
            // Dropping `owned` first releases anything a failed call left
            // behind. The C reuses `&decoded` and would abandon such a buffer,
            // but no libidn2 allocates on failure -- measured across the
            // failing codes this port can provoke, the out-parameter is always
            // null -- so `owned` is `None` here in practice and this is
            // insurance rather than a behavioural difference.
            drop(owned);
            decoded = ptr::null_mut();
            // SAFETY: as for the first call. `name` still points at the same
            // live borrow and `decoded` has been reset to null.
            rc = unsafe { lookup(name, &mut decoded, IDN2_TRANSITIONAL) };
            // SAFETY: as for the first adoption.
            owned = unsafe { Idn2Buf::from_raw(decoded) };
        }

        if rc != IDN2_OK {
            // L266-L267. Dropping `owned` on the way out releases anything
            // libidn2 left behind, which in practice is nothing.
            return Err(CURLcode::CURLE_URL_MALFORMAT);
        }

        match owned {
            // L277-L278 hands the string up, and L306-L315 immediately
            // re-owns it through curl's allocator.
            Some(buf) => reduplicate(buf),
            // Unreachable against any libidn2 that honours its own contract:
            // IDN2_OK with a null out-parameter. The C would pass that null to
            // `curlx_strdup` at L308 and then read `d[0]` at L317, both of
            // which are undefined, so there is no behaviour to be faithful to.
            // Reporting a malformed name is the one defined answer.
            None => Err(CURLcode::CURLE_URL_MALFORMAT),
        }
    }

    /// The `USE_LIBIDN2` body of `static idn_encode` at `lib/idn.c`
    /// L282-L300, followed by the re-duplication at L331-L340.
    ///
    /// Three differences from [`idn_decode`] are all deliberate. There is no
    /// version guard, because L282-L300 has none. The flag argument is `0`,
    /// spelled out at L286, rather than a computed word. And there is no
    /// retry: one call, and its verdict stands.
    ///
    /// # Errors
    ///
    /// `CURLcode::CURLE_OUT_OF_MEMORY` when libidn2 reported
    /// `IDNA_MALLOC_ERROR` or the duplication failed, and
    /// `CURLcode::CURLE_URL_MALFORMAT` for every other libidn2 failure
    /// (L287-L288).
    pub(super) fn idn_encode(puny: &CBuf) -> Result<CBuf, CURLcode> {
        // Bound for the same reason as in `idn_decode`.
        let source = puny.as_bytes_with_nul();
        let input: *const c_char = source.as_ptr().cast::<c_char>();

        let mut enc: *mut c_char = ptr::null_mut();
        // SAFETY: `input` points at the NUL-terminated `source` slice, which
        // is borrowed from `puny` for the whole function, so it is readable
        // for the call. `enc` is a live local, so `&mut enc` is a valid
        // writable location for one pointer. The third argument is the literal
        // flag word the C passes.
        let rc = unsafe { idn2_to_unicode_8z8z(input, &mut enc, 0) };
        // SAFETY: `enc` is null unless libidn2 wrote a string it owns there,
        // and nothing else has taken ownership of it.
        let owned = unsafe { Idn2Buf::from_raw(enc) };

        if rc != IDNA_SUCCESS {
            // L287-L288. The C returns here without freeing, because a failed
            // conversion allocates nothing; dropping `owned` on the way out
            // covers the case where one somehow did.
            return Err(if rc == IDNA_MALLOC_ERROR {
                CURLcode::CURLE_OUT_OF_MEMORY
            } else {
                CURLcode::CURLE_URL_MALFORMAT
            });
        }

        match owned {
            // L298 hands the string up, and L331-L340 re-owns it through
            // curl's allocator.
            Some(buf) => reduplicate(buf),
            // Unreachable, for the reason given in `idn_decode`. An empty
            // input converts to an empty *allocated* string, not to null.
            None => Err(CURLcode::CURLE_URL_MALFORMAT),
        }
    }
}

/// The alternative backend: the pure-Rust `idna` crate, and no C library.
///
/// # This backend has no C counterpart
///
/// `lib/idn.c` offers three implementations, `USE_LIBIDN2`, `USE_WIN32_IDN` and
/// `USE_APPLE_IDN`, and this is a fourth that curl does not have. It exists so
/// that the crate can be built where no C internationalised-domain library is
/// available, and it is off by default because **parity is claimed for the
/// libidn2 backend alone**. `rust-urlapi/docs/KNOWN-DIVERGENCES.md` records
/// the five differences in full; in brief they are:
///
/// 1. **No transitional retry.** The `idna` crate offers no second attempt, so
///    a name that the C converts only on the retry at `lib/idn.c` L262-L265
///    fails here. `\u{2603}.de` is such a name.
/// 2. **Locale-independence.** `idn2_lookup_ul` reads its input in the
///    encoding of the process locale and fails outright where that encoding is
///    not UTF-8; this backend reads Rust text, which is UTF-8 by definition,
///    and converts the same name under any locale. It therefore **succeeds
///    where the C fails**, which is the more surprising direction for a
///    divergence to run.
/// 3. **Different Unicode tables.** Each backend carries its own copy of the
///    data that case mapping and normalisation consult, versioned
///    independently.
/// 4. **Thirty further crates**, against the one the default configuration
///    needs.
/// 5. **A minimum toolchain of 1.86**, above this crate's declared 1.75 and
///    above curl's own documented floor, contributed by the dependency tree
///    rather than by this code.
///
/// Reproducing the C's locale failure here would take an explicit check of the
/// locale's codeset before conversion, deliberately refusing input this
/// backend can convert perfectly well. **That is deliberately absent.** A
/// divergence in an opt-in configuration is reported rather than worked
/// around, so it is recorded here and in the divergences document and the
/// backend is left as it is.
///
/// # No `unsafe`
///
/// There is none in this module, and there is nothing for it to do: the
/// backend is pure Rust from end to end, and the only allocation that crosses
/// into C is made by [`CBuf`], which owns its own safety argument.
#[cfg(idn_backend_pure)]
mod pure {
    use core::str;

    use super::{CBuf, CURLcode};

    /// The `USE_*` body of `static idn_decode` at `lib/idn.c` L247-L280,
    /// expressed through the `idna` crate.
    ///
    /// `idna::domain_to_ascii` performs the UTS46 `ToASCII` operation, which
    /// is the same operation `idn2_lookup_ul` performs, with the differences
    /// the module documentation lists.
    ///
    /// There is no re-duplication step, and none is needed: the result is a
    /// Rust `String` and the bytes are copied into C-allocator memory exactly
    /// once, by [`CBuf::from_slice`]. That mirrors the C, where the
    /// re-duplication block at L306-L315 is `#ifdef USE_LIBIDN2` and the
    /// Windows and Apple backends allocate through curl's allocator to begin
    /// with.
    ///
    /// # Errors
    ///
    /// `CURLcode::CURLE_URL_MALFORMAT` if the name is not valid UTF-8 or the
    /// crate rejected it, and `CURLcode::CURLE_OUT_OF_MEMORY` if the copy could
    /// not be allocated.
    pub(super) fn idn_decode(input: &CBuf) -> Result<CBuf, CURLcode> {
        // The C hands libidn2 a byte string and lets it decide; this crate
        // takes `&str`, so invalid UTF-8 has to be rejected here. The C
        // rejects it too, one layer further in: `idn2_lookup_ul` reports
        // IDN2_ICONV_FAIL or IDN2_ENCODING_ERROR, both of which become
        // CURLE_URL_MALFORMAT at L267, which is the code used here.
        let name = str::from_utf8(input.as_bytes()).map_err(|_| CURLcode::CURLE_URL_MALFORMAT)?;
        let ascii = idna::domain_to_ascii(name).map_err(|_| CURLcode::CURLE_URL_MALFORMAT)?;
        own(&ascii)
    }

    /// The `USE_*` body of `static idn_encode` at `lib/idn.c` L282-L300,
    /// expressed through the `idna` crate.
    ///
    /// `idna::domain_to_unicode` performs UTS46 `ToUnicode`, the operation
    /// `idn2_to_unicode_8z8z` performs. It reports its verdict beside the
    /// converted text rather than instead of it, so the verdict is consulted
    /// first and the text used only when it is clean, which is how the C reads
    /// its own return code at L287.
    ///
    /// # Errors
    ///
    /// `CURLcode::CURLE_URL_MALFORMAT` if the input is not valid UTF-8 or the
    /// crate rejected it, and `CURLcode::CURLE_OUT_OF_MEMORY` if the copy could
    /// not be allocated. There is no equivalent of libidn2's
    /// `IDNA_MALLOC_ERROR`, because a Rust allocation failure aborts rather
    /// than returning.
    pub(super) fn idn_encode(puny: &CBuf) -> Result<CBuf, CURLcode> {
        let name = str::from_utf8(puny.as_bytes()).map_err(|_| CURLcode::CURLE_URL_MALFORMAT)?;
        let (unicode, verdict) = idna::domain_to_unicode(name);
        verdict.map_err(|_| CURLcode::CURLE_URL_MALFORMAT)?;
        own(&unicode)
    }

    /// Copy converted text into C-allocator memory.
    ///
    /// The single point at which this backend produces something that may
    /// cross into C, which is what keeps the ownership rule in
    /// `rust-urlapi/docs/MEMORY-OWNERSHIP.md` true of this configuration as
    /// well: every buffer handed to C comes from `src/alloc.rs`.
    ///
    /// # Errors
    ///
    /// `CURLcode::CURLE_OUT_OF_MEMORY` if the allocation failed.
    fn own(text: &str) -> Result<CBuf, CURLcode> {
        match CBuf::from_slice(text.as_bytes()) {
            Some(buf) => Ok(buf),
            None => Err(CURLcode::CURLE_OUT_OF_MEMORY),
        }
    }
}

#[cfg(test)]
mod tests {
    // The crate root denies the panicking constructs, so that a panic is
    // designed out of the port rather than caught. A test is the one place
    // where a panic is the reporting mechanism, so the allowances are stated
    // here and scoped to this module, as in every other test module of this
    // crate.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::arithmetic_side_effects)]

    use super::{host_decode, host_encode, is_ascii_name};
    use crate::abi::CURLUcode;
    use crate::alloc::CBuf;

    #[cfg(have_idn)]
    use super::{idn_decode, idn_encode};
    #[cfg(have_idn)]
    use crate::abi::{CURLUE_BAD_HOSTNAME, CURLUE_OUT_OF_MEMORY};
    #[cfg(have_idn)]
    use crate::error::{idn2cu, CURLcode};

    #[cfg(not(have_idn))]
    use crate::abi::CURLUE_LACKS_IDN;

    /// The reference vectors, Unicode form first and punycode second.
    ///
    /// **Every non-ASCII byte is written as a Rust escape, never as literal
    /// UTF-8.** That is not a style preference. `scripts/spacecheck.pl` checks
    /// every tracked file for non-ASCII bytes at L179, and its sole allowance
    /// at L50-L54 is a character class over the two individual bytes `0xC3` and
    /// `0xB6`. An o with diaeresis therefore passes, because both of its bytes
    /// are in that class, while an a with diaeresis (`0xC3 0xA4`), an a with
    /// ring above (`0xC3 0xA5`), a sharp s (`0xC3 0x9F`) and any CJK character
    /// are all flagged. The canonical vectors are made of precisely those
    /// characters, so a file that spelled them out would fail the gate.
    /// `str::as_bytes` on an escaped literal yields the same UTF-8 the C test
    /// file writes as `\xc3\xa4` hex escapes at `tests/libtest/lib1560.c`
    /// L207-L215 and L630.
    ///
    /// The first pair is the assertion at `tests/libtest/lib1560.c` L630-L631,
    /// guarded there by `#ifdef USE_IDN` at L629. All three were confirmed
    /// against libidn2 2.3.8 in both directions.
    #[cfg(any(idn_backend_libidn2, idn_backend_pure))]
    const REFERENCE: [(&str, &str); 3] = [
        // U+00E4 latin small letter a with diaeresis, U+00F6 the o form,
        // U+00E5 latin small letter a with ring above.
        ("r\u{e4}ksm\u{f6}rg\u{e5}s.se", "xn--rksmrgs-5wao1o.se"),
        // U+00DF latin small letter sharp s.
        ("fa\u{df}.de", "xn--fa-hia.de"),
        // U+4E2D and U+6587, the two ideographs of the CJK example.
        ("\u{4e2d}\u{6587}.tw", "xn--fiq228c.tw"),
    ];

    /// The name whose conversion the transitional retry decides.
    ///
    /// U+2603 snowman. `IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL` rejects it with
    /// `IDN2_DISALLOWED`, and the retry with `IDN2_TRANSITIONAL` alone converts
    /// it, so a port that dropped `lib/idn.c` L262-L265 would report
    /// `CURLUE_BAD_HOSTNAME` here.
    #[cfg(all(idn_backend_libidn2, unix))]
    const RETRY_ONLY: (&str, &str) = ("\u{2603}.de", "xn--n3h.de");

    /// A C-allocator buffer over `bytes`, which is what both entry points take.
    ///
    /// The allocation cannot realistically fail for these lengths, and a test
    /// that could not allocate has nothing to report, so unwrapping here is
    /// the honest choice.
    fn cbuf(bytes: &[u8]) -> CBuf {
        CBuf::from_slice(bytes).unwrap()
    }

    /// Assert that [`host_decode`] turns `input` into exactly `expected`.
    ///
    /// The outcome is reshaped into `Result<&[u8], &CURLUcode>` so that one
    /// `assert_eq!` compares both the code and the bytes, and so that a failure
    /// prints which of the two went wrong.
    fn decodes_to(input: &str, expected: &str) {
        let outcome = host_decode(&cbuf(input.as_bytes()));
        let produced = outcome.as_ref().map(CBuf::as_bytes);
        assert_eq!(produced, Ok(expected.as_bytes()), "decoding {input:?}");
    }

    /// Assert that [`host_encode`] turns `input` into exactly `expected`.
    fn encodes_to(input: &str, expected: &str) {
        let outcome = host_encode(&cbuf(input.as_bytes()));
        let produced = outcome.as_ref().map(CBuf::as_bytes);
        assert_eq!(produced, Ok(expected.as_bytes()), "encoding {input:?}");
    }

    /// Assert that [`host_decode`] reports exactly `expected` for `input`.
    fn decode_fails(input: &[u8], expected: CURLUcode) {
        let outcome = host_decode(&cbuf(input));
        let produced = outcome.as_ref().map(CBuf::as_bytes);
        assert_eq!(produced, Err(&expected), "decoding {input:?}");
    }

    /// Assert that [`host_encode`] reports exactly `expected` for `input`.
    fn encode_fails(input: &[u8], expected: CURLUcode) {
        let outcome = host_encode(&cbuf(input));
        let produced = outcome.as_ref().map(CBuf::as_bytes);
        assert_eq!(produced, Err(&expected), "encoding {input:?}");
    }

    /// A null hostname is ASCII, which `lib/idn.c` L228 states outright.
    ///
    /// It matters because this is the gate on both conversions: a null host
    /// makes the `CURLU_PUNYCODE` branch at `lib/urlapi.c` L1402 do nothing and
    /// lets the `CURLU_PUNY2IDN` branch at L1412 proceed.
    #[test]
    fn a_missing_hostname_counts_as_ascii() {
        assert!(is_ascii_name(None));
    }

    /// The loop at L231 never runs for an empty string, so L235 reports true.
    #[test]
    fn an_empty_hostname_is_ascii() {
        assert!(is_ascii_name(Some(b"")));
    }

    /// Names made only of bytes below `0x80`, punycode among them.
    #[test]
    fn a_plain_ascii_hostname_is_ascii() {
        assert!(is_ascii_name(Some(b"example.com")));
        assert!(is_ascii_name(Some(b"xn--rksmrgs-5wao1o.se")));
        assert!(is_ascii_name(Some(b"[::1]")));
        assert!(is_ascii_name(Some(b"\x7f")));
    }

    /// One high byte anywhere in the name is enough, so all three positions
    /// are checked rather than just the convenient one.
    #[test]
    fn the_high_bit_is_found_at_the_first_middle_and_last_position() {
        assert!(!is_ascii_name(Some(b"\x80xample.com")));
        assert!(!is_ascii_name(Some(b"exa\x80ple.com")));
        assert!(!is_ascii_name(Some(b"example.co\x80")));
    }

    /// The test is the high bit and nothing else: no UTF-8 validation, so a
    /// lone continuation byte counts exactly as much as a well-formed
    /// sequence does.
    #[test]
    fn every_byte_is_classified_by_its_high_bit_alone() {
        for byte in 1..=u8::MAX {
            let name = [byte];
            assert_eq!(is_ascii_name(Some(&name)), byte < 0x80, "byte 0x{byte:02x}");
        }
    }

    /// The C loop stops at its terminator, so bytes after an interior zero are
    /// never examined. No call site can produce one, because `Curl_junkscan`
    /// rejects control bytes, but the stopping condition is reproduced.
    #[test]
    fn the_scan_stops_at_an_interior_terminator() {
        assert!(is_ascii_name(Some(b"ok\0\x80")));
        assert!(is_ascii_name(Some(b"\0")));
        assert!(!is_ascii_name(Some(b"\x80\0ok")));
    }

    /// The reference name is not ASCII, which is what puts it on the
    /// conversion path in the first place.
    #[cfg(any(idn_backend_libidn2, idn_backend_pure))]
    #[test]
    fn the_reference_names_are_not_ascii() {
        for (unicode, puny) in REFERENCE {
            assert!(!is_ascii_name(Some(unicode.as_bytes())), "{unicode:?}");
            assert!(is_ascii_name(Some(puny.as_bytes())), "{puny:?}");
        }
    }

    /// An already-ASCII name survives the lookup unchanged.
    ///
    /// Locale-independent, and true of both backends: `idn2_lookup_ul` needs no
    /// character conversion for input that is ASCII in every codeset, which was
    /// confirmed under both `LC_ALL=C.UTF-8` and `LC_ALL=C`.
    #[cfg(have_idn)]
    #[test]
    fn an_ascii_name_passes_through_the_lookup_unchanged() {
        ensure_locale();
        decodes_to("example.com", "example.com");
        encodes_to("example.com", "example.com");
    }

    /// Bytes that are not valid UTF-8 are a bad hostname under either backend.
    ///
    /// libidn2 reports `IDN2_ICONV_FAIL` or `IDN2_ENCODING_ERROR` depending on
    /// the codeset, and the pure backend rejects the input before it reaches
    /// the `idna` crate. All of those fold to the same code, which is the
    /// point: the fold is lossy on purpose.
    #[cfg(have_idn)]
    #[test]
    fn bytes_that_are_not_utf8_are_a_bad_hostname() {
        ensure_locale();
        decode_fails(b"\xff\xfe", CURLUE_BAD_HOSTNAME);
    }

    /// A zero-length decode result is rejected, at `lib/idn.c` L316-L323.
    ///
    /// Reachable rather than defensive: an empty name is `IDN2_OK` with an
    /// empty result, so the check is what turns it into a failure. The two
    /// layers are asserted separately because the wrapper's fold hides which
    /// of three codes the inner layer produced.
    #[cfg(have_idn)]
    #[test]
    fn a_zero_length_decode_result_is_rejected() {
        ensure_locale();
        assert_eq!(
            idn_decode(&cbuf(b"")).err(),
            Some(CURLcode::CURLE_URL_MALFORMAT)
        );
        decode_fails(b"", CURLUE_BAD_HOSTNAME);
    }

    /// A zero-length encode result is **accepted**, because `lib/idn.c`
    /// L341-L342 has no equivalent of the check at L317.
    ///
    /// This is the asymmetry between the two directions, asserted rather than
    /// described so that a later tidying edit that adds the missing check for
    /// symmetry fails here.
    #[cfg(have_idn)]
    #[test]
    fn a_zero_length_encode_result_is_accepted() {
        ensure_locale();
        let outcome = idn_encode(&cbuf(b""));
        let produced = outcome.as_ref().map(CBuf::as_bytes);
        assert_eq!(produced, Ok(&b""[..]));
        encodes_to("", "");
    }

    /// The `CURLcode` fold of `lib/urlapi.c` L1341-L1343 and L1352-L1353.
    ///
    /// Out of memory crosses over as itself and everything else becomes
    /// `CURLUE_BAD_HOSTNAME`, including `CURLE_NOT_BUILT_IN` from the
    /// too-old-library guard, so a caller cannot tell a rejected name from a
    /// libidn2 it could not use. The two ordinals are pinned here as well,
    /// because they are what a C caller switches on.
    #[cfg(have_idn)]
    #[test]
    fn the_curlcode_fold_is_lossy_in_exactly_one_direction() {
        assert_eq!(idn2cu(CURLcode::CURLE_OUT_OF_MEMORY), CURLUE_OUT_OF_MEMORY);
        assert_eq!(idn2cu(CURLcode::CURLE_URL_MALFORMAT), CURLUE_BAD_HOSTNAME);
        assert_eq!(idn2cu(CURLcode::CURLE_NOT_BUILT_IN), CURLUE_BAD_HOSTNAME);
        assert_eq!(CURLUE_OUT_OF_MEMORY, 7);
        assert_eq!(CURLUE_BAD_HOSTNAME, 21);
    }

    /// Put the process in the locale its environment names, exactly once.
    ///
    /// A Rust program never calls `setlocale`, so it starts in the `C` locale
    /// whatever the environment says, and `idn2_lookup_ul` then fails on every
    /// non-ASCII name with `IDN2_ICONV_FAIL`. `tests/libtest/first.c` L231
    /// makes the same call for the same reason, and a harness that omits it
    /// passes while exercising none of the conversion path.
    ///
    /// Once, and before any lookup. `Once::call_once` blocks its other callers
    /// until the initialiser has returned, and every test here that reaches
    /// libidn2 calls this first, so no lookup can observe the locale while it
    /// is being changed.
    #[cfg(all(idn_backend_libidn2, unix))]
    fn ensure_locale() {
        // Reached through `std` rather than assumed to be in the prelude, so
        // that this module compiles the same way whichever the crate root
        // turns out to declare. Every non-test module of this crate imports
        // from `core` and `libc` alone.
        extern crate std;
        use libc::c_char;
        use std::sync::Once;

        static SELECTED: Once = Once::new();

        SELECTED.call_once(|| {
            // The empty string is what asks for the environment's own locale,
            // and it is exactly what `tests/libtest/first.c` L231 passes.
            const FROM_ENVIRONMENT: &[u8] = b"\0";
            // SAFETY: the pointer is to a NUL-terminated static literal, which
            // `setlocale` only reads. The returned pointer is to libc's own
            // storage and is deliberately not read or freed. `Once` guarantees
            // this runs on one thread with every other caller blocked, which
            // is what makes a call that mutates process-wide state safe here.
            unsafe { libc::setlocale(libc::LC_ALL, FROM_ENVIRONMENT.as_ptr().cast::<c_char>()) };
        });
    }

    /// Nothing to do where the locale entry points are not bound.
    ///
    /// The Windows arm of `IDN2_LOOKUP` at `lib/idn.c` L36-L37 selects
    /// `idn2_lookup_u8`, which reads UTF-8 directly, so there is no locale to
    /// arrange on that platform and nothing for the codeset to change.
    #[cfg(all(have_idn, not(all(idn_backend_libidn2, unix))))]
    fn ensure_locale() {}

    /// Whether the process locale's codeset is UTF-8.
    ///
    /// This is the same question `tests/runtests.pl` answers with
    /// `is_utf8_supported()` at L836 and exports as
    /// `CURL_TEST_HAVE_CODESET_UTF8` at L837-L839 for
    /// `tests/libtest/lib1560.c` to read at L2036 and gate three sub-tests on.
    /// Asking the C library directly is better than reading the variable,
    /// because the variable can be right about the environment and wrong about
    /// the machine: on this container `LC_ALL=en_US.UTF-8` names a locale that
    /// is not generated and yields the codeset `ANSI_X3.4-1968`, where a check
    /// of the variable's spelling would have concluded UTF-8.
    #[cfg(all(idn_backend_libidn2, unix))]
    fn utf8_codeset() -> bool {
        use core::ffi::CStr;

        ensure_locale();
        // SAFETY: `nl_langinfo` returns a pointer to libc's own static,
        // NUL-terminated storage for the current locale, never null for a
        // valid item, and `CODESET` is a valid item. The locale is fixed by
        // `ensure_locale` before this runs and is never changed again, so the
        // string cannot be rewritten while it is borrowed here.
        let codeset = unsafe { CStr::from_ptr(libc::nl_langinfo(libc::CODESET)) };
        codeset.to_bytes() == b"UTF-8"
    }

    /// The three reference vectors convert to punycode where the codeset is
    /// UTF-8, which is the direction `CURLU_PUNYCODE` asks for.
    ///
    /// The first pair is what `tests/libtest/lib1560.c` L630-L631 asserts.
    /// Where the codeset is not UTF-8 there is nothing to assert here and the
    /// companion test below asserts the failure instead, so exactly one of the
    /// two is meaningful in any given environment and neither is ever vacuous.
    #[cfg(all(idn_backend_libidn2, unix))]
    #[test]
    fn the_reference_vectors_convert_to_punycode_under_a_utf8_codeset() {
        if !utf8_codeset() {
            return;
        }
        for (unicode, puny) in REFERENCE {
            decodes_to(unicode, puny);
        }
    }

    /// The locale trap itself: where the codeset is not UTF-8, libidn2
    /// converts no non-ASCII name at all and the module reports
    /// `CURLUE_BAD_HOSTNAME`.
    ///
    /// This is the behaviour that has to be preserved rather than repaired,
    /// because it is what the reference build does. It is also what makes the
    /// pure backend a documented divergence: that backend succeeds here.
    #[cfg(all(idn_backend_libidn2, unix))]
    #[test]
    fn a_non_ascii_name_fails_under_a_non_utf8_codeset() {
        if utf8_codeset() {
            return;
        }
        for (unicode, _) in REFERENCE {
            decode_fails(unicode.as_bytes(), CURLUE_BAD_HOSTNAME);
        }
    }

    /// The transitional retry at `lib/idn.c` L262-L265 decides this outcome.
    ///
    /// The first lookup rejects the name with `IDN2_DISALLOWED` and the retry
    /// converts it, so a port that omitted the retry -- the single likeliest
    /// omission in this module -- would report `CURLUE_BAD_HOSTNAME` and fail
    /// here. The retry is also why the flag word is *replaced* rather than
    /// extended: the second call passes `IDN2_TRANSITIONAL` alone.
    #[cfg(all(idn_backend_libidn2, unix))]
    #[test]
    fn the_transitional_retry_decides_the_outcome() {
        if !utf8_codeset() {
            return;
        }
        let (unicode, puny) = RETRY_ONLY;
        decodes_to(unicode, puny);
    }

    /// The punycode direction needs no codeset gate, and this test records why.
    ///
    /// `idn2_to_unicode_8z8z` is UTF-8 in and UTF-8 out, with no locale
    /// involvement, so every one of these conversions succeeds under any
    /// codeset. That was measured, not assumed.
    /// `tests/libtest/lib1560.c` L1445-L1446 gates `CURLU_PUNY2IDN` on
    /// `has_utf8` alongside `CURLU_PUNYCODE` anyway, which is conservative
    /// rather than wrong.
    #[cfg(idn_backend_libidn2)]
    #[test]
    fn the_reference_vectors_convert_back_from_punycode_under_any_codeset() {
        ensure_locale();
        for (unicode, puny) in REFERENCE {
            encodes_to(puny, unicode);
        }
    }

    /// A name libidn2 rejects under every flag set is a bad hostname.
    ///
    /// `-bad-.example` fails the first lookup with `IDN2_HYPHEN_STARTEND` and
    /// the retry with the same, so this reaches `CURLE_URL_MALFORMAT` at
    /// `lib/idn.c` L267 through the retry rather than around it. It is ASCII,
    /// so no character conversion is involved and the verdict does not depend
    /// on the codeset.
    #[cfg(idn_backend_libidn2)]
    #[test]
    fn a_name_libidn2_rejects_is_a_bad_hostname() {
        ensure_locale();
        decode_fails(b"-bad-.example", CURLUE_BAD_HOSTNAME);
    }

    /// Punycode libidn2 cannot decode is a bad hostname.
    ///
    /// `idn2_to_unicode_8z8z` reports `IDN2_PUNYCODE_BAD_INPUT`, which is
    /// neither `IDNA_SUCCESS` nor `IDNA_MALLOC_ERROR`, so L288 selects
    /// `CURLE_URL_MALFORMAT` and the wrapper folds it.
    #[cfg(idn_backend_libidn2)]
    #[test]
    fn punycode_that_cannot_be_converted_is_a_bad_hostname() {
        ensure_locale();
        encode_fails(b"xn--!!!", CURLUE_BAD_HOSTNAME);
    }

    /// The pure backend converts the reference vectors in both directions,
    /// under any locale.
    ///
    /// Agreement on these names is expected and is not a parity claim. The
    /// backend has no transitional retry, is locale-independent and carries its
    /// own Unicode tables, all of which
    /// `rust-urlapi/docs/KNOWN-DIVERGENCES.md` records.
    #[cfg(idn_backend_pure)]
    #[test]
    fn the_reference_vectors_round_trip_under_the_pure_backend() {
        for (unicode, puny) in REFERENCE {
            decodes_to(unicode, puny);
            encodes_to(puny, unicode);
        }
    }

    /// Without a backend both operations report `CURLUE_LACKS_IDN`, code 30.
    ///
    /// `lib/urlapi.c` L1334-L1336 replaces both wrappers with macros that
    /// evaluate no argument and yield that code, which is what this
    /// configuration reproduces. The ordinal is pinned because a C caller
    /// switches on it.
    #[cfg(not(have_idn))]
    #[test]
    fn without_a_backend_both_operations_report_lacks_idn() {
        assert_eq!(CURLUE_LACKS_IDN, 30);
        decode_fails(b"example.com", CURLUE_LACKS_IDN);
        encode_fails(b"xn--rksmrgs-5wao1o.se", CURLUE_LACKS_IDN);
        // Even the inputs the supported configurations treat specially, an
        // empty name among them, get the same answer: the macros look at
        // nothing at all.
        decode_fails(b"", CURLUE_LACKS_IDN);
        encode_fails(b"", CURLUE_LACKS_IDN);
    }
}
