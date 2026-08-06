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
//! The backend is chosen by `#[cfg]`, which is this crate's expression of
//! the C's `#ifdef USE_IDN`.
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
//! locale**. The result for a non-ASCII name is therefore locale-dependent:
//! the bytes are decoded according to the locale's codeset before any IDN
//! processing happens, so a locale whose codeset cannot represent them fails
//! and a locale that decodes them differently produces a different name.
//! Measured in the `C` locale, whose codeset is ASCII, every non-ASCII name
//! tested fails with `IDN2_ICONV_FAIL`, which the module turns into
//! `CURLUE_BAD_HOSTNAME`; under `C.UTF-8` the same names convert. Locales
//! other than those two were not measured, and no claim is made about them
//! beyond the general dependence.
//!
//! Binding the C library directly is what makes this crate inherit that
//! sensitivity for free, which is the desired outcome, so this module adds no
//! `setlocale` call, no locale normalisation and no UTF-8 pre-validation. Any
//! of the three would hide a difference the parity diff exists to expose.
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
// wrappers above it fold two of them together. Which of these a given build
// reaches is therefore decided by the feature set.
//
// No dead-code allowance appears in this module, and none is needed: every item
// below is reached from this crate's own paths in every configuration it
// builds. There is no crate-wide allowance either -- an item without a
// production caller carries its own, with its reason, as "DEAD-CODE POLICY" in
// `src/lib.rs` requires.

// `unsafe` belongs to `src/ffi.rs` alone, and the lint matters more here than
// in most modules: the default backend really does call into libidn2, and
// keeping that call in `crate::ffi::idn2` is what lets this module state that
// it makes none itself.
#![forbid(unsafe_code)]

use crate::abi::CURLUcode;
use crate::alloc::CBuf;

#[cfg(have_idn)]
use crate::error::{idn2cu, CURLcode};

#[cfg(not(have_idn))]
use crate::abi::CURLUE_LACKS_IDN;

// Exactly one backend. `rust-urlapi/build.rs` already refuses a request for
// both, mirroring the `#error` at `lib/curl_setup.h` L726-L728; stating it
// again here means a compilation that reached rustc with both cfgs set stops
// with this message instead of silently taking whichever arm comes first.
#[cfg(all(idn_backend_libidn2, idn_backend_pure))]
compile_error!(
    "curl-urlapi-rs: the \"idn-libidn2\" and \"idn-pure\" backends are \
     mutually exclusive; select exactly one. Only \"idn-libidn2\" carries \
     the bit-for-bit parity claim; see docs/KNOWN-DIVERGENCES.md."
);

/// The backend `lib/curl_setup.h` L720-L724 would have selected.
///
/// Binding the same C library curl binds is what makes bit-for-bit parity
/// attainable, the locale sensitivity included, which is why this is the
/// default.
#[cfg(idn_backend_libidn2)]
use crate::ffi::idn2 as backend;

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
/// The asymmetry is the C's, and it is reproduced rather than smoothed over.
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

// The libidn2 binding is a foreign call, so it lives in the crate's single
// unsafe island: `crate::ffi::idn2`. What moved is the binding -- the flag
// constants, the four `extern` declarations, the libidn2-owned buffer type,
// the two lookup arms, the version guard, the re-duplication through curl's
// allocator, and the two entry points that sequence them. What stayed is this
// module's whole interface: `Curl_idn_decode` and `Curl_idn_encode` above,
// the two `host_*` folds, the ASCII gate, the pure-Rust alternative below,
// and the backend selection. The relocated module presents the same safe
// surface it always did -- a `CBuf` in, a `CBuf` or a `CURLcode` out -- so
// nothing here or in `src/getset.rs` changes.

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
/// 2. **Locale-independence.** `idn2_lookup_ul` decodes its input according to
///    the process locale's codeset, so its result depends on the locale; in
///    the `C` locale it fails. This backend reads Rust text, which is UTF-8 by
///    definition, and converts the same name under any locale. It therefore
///    **succeeds where the C fails in the `C` locale**, which is the more
///    surprising direction for a divergence to run.
/// 3. **Different Unicode tables.** Each backend carries its own copy of the
///    data that case mapping and normalisation consult, versioned
///    independently.
/// 4. **Twenty-nine further crates**, against the one the default configuration
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
    use core::fmt::{self, Write};

    use super::{CBuf, CURLcode};
    use crate::abi::CURL_MAX_INPUT_LENGTH;
    use crate::dynbuf::DynBuf;
    use idna::uts46::Uts46;
    use idna::uts46::{AsciiDenyList, ErrorPolicy, Hyphens, ProcessingError, ProcessingSuccess};

    /// A [`Write`] sink that accumulates into C-allocator memory and **can
    /// fail**.
    ///
    /// This exists for one reason: an allocation failure has to be reportable.
    /// The convenience entry points of the `idna` crate build a `String`, and a
    /// `String` that cannot grow aborts the process, which would turn an
    /// out-of-memory condition into a crash at a point where the C returns
    /// `CURLE_OUT_OF_MEMORY` (`lib/idn.c` L313 and L338). `Uts46::process` is
    /// the crate's fallible entry point -- it writes into a caller-supplied
    /// sink and reports [`ProcessingError::SinkError`] when the sink refuses --
    /// so the fallible allocator can be put underneath it.
    ///
    /// The buffer is a [`DynBuf`], which is curl's own growable buffer over the
    /// C allocator, so the bytes are in the right allocator from the first
    /// write rather than being copied into it at the end. The ceiling is
    /// `CURL_MAX_INPUT_LENGTH` (`lib/urldata.h` L131), which is the ceiling the
    /// whole URL is already held to by `Curl_junkscan()` at `lib/urlapi.c`
    /// L229-L230, and a host name is part of a URL.
    struct CSink {
        /// The accumulated text.
        buf: DynBuf,
        /// Whether a write has failed. Set once and never cleared: after a
        /// refusal the content is incomplete, and the crate's contract is that
        /// partial sink output must not be used.
        failed: bool,
    }

    impl CSink {
        /// An empty sink. Nothing is allocated until the first write, which is
        /// [`DynBuf`]'s own behaviour and C's.
        fn new() -> Self {
            Self::with_ceiling(CURL_MAX_INPUT_LENGTH)
        }

        /// The same, with the ceiling named.
        ///
        /// [`CSink::new`] is the only production caller and it passes the one
        /// ceiling this backend uses. The parameter exists so that the tests
        /// below can reach the refusal path with a handful of bytes instead of
        /// eight million, which is the only way to exercise it without making
        /// the allocator fail for real.
        fn with_ceiling(toobig: usize) -> Self {
            Self {
                buf: DynBuf::new(toobig),
                failed: false,
            }
        }

        /// Hand the accumulated text over as a [`CBuf`], terminator included.
        ///
        /// # Errors
        ///
        /// `CURLcode::CURLE_OUT_OF_MEMORY` if any write failed, or if the
        /// handover itself cannot produce a terminated buffer.
        fn finish(self) -> Result<CBuf, CURLcode> {
            if self.failed {
                return Err(CURLcode::CURLE_OUT_OF_MEMORY);
            }
            match self.buf.into_cbuf() {
                Some(buf) => Ok(buf),
                // `into_cbuf` reports `None` for a buffer that never allocated,
                // which is a sink that received nothing. An empty name is not
                // an error in either implementation -- libidn2 converts it to
                // an empty *allocated* string -- so an empty allocation is what
                // is produced, and only its failure is an error.
                None => CBuf::from_slice(&[]).ok_or(CURLcode::CURLE_OUT_OF_MEMORY),
            }
        }
    }

    impl Write for CSink {
        /// Append UTF-8 text, reporting a refusal rather than aborting.
        ///
        /// The error type carries no payload, which is why `failed` is recorded
        /// here as well: `Uts46::process` returns `SinkError` and the reason has
        /// to survive to [`CSink::finish`].
        fn write_str(&mut self, text: &str) -> fmt::Result {
            if self.buf.addn(text.as_bytes()) == CURLcode::CURLE_OK {
                return Ok(());
            }
            self.failed = true;
            Err(fmt::Error)
        }
    }

    /// The UTS46 processor, with the data compiled into the binary.
    ///
    /// Constructing it is free -- `Uts46::new` is a `const fn` over compiled
    /// tables -- so it is built per call rather than kept in a static, which
    /// keeps the module free of any shared mutable state.
    fn processor() -> Uts46 {
        Uts46::new()
    }

    /// Run one UTS46 operation into a fallible C-allocator sink.
    ///
    /// `output_as_unicode` is the crate's own way of selecting the operation:
    /// `false` for every label is _ToASCII_, `true` for every label is
    /// _ToUnicode_, which is exactly how `Uts46::to_ascii` and
    /// `Uts46::to_unicode` are built.
    ///
    /// The option set is the one the crate's own convenience entry points use
    /// for these two operations -- an empty ASCII deny list, hyphens allowed,
    /// no DNS-length verification -- so the conversion itself is unchanged and
    /// only the allocation path is different. `ErrorPolicy::FailFast` is used
    /// for both, because the error text the alternative produces is discarded
    /// unread: the C has no equivalent of it, and this port must not hand a
    /// name containing U+FFFD to anything.
    ///
    /// # Errors
    ///
    /// `CURLcode::CURLE_URL_MALFORMAT` if the input is not well-formed UTF-8 or
    /// the crate rejected the name, and `CURLcode::CURLE_OUT_OF_MEMORY` if the
    /// sink could not allocate.
    fn convert(name: &[u8], output_as_unicode: bool) -> Result<CBuf, CURLcode> {
        let mut sink = CSink::new();
        let outcome = processor().process(
            name,
            AsciiDenyList::EMPTY,
            Hyphens::Allow,
            ErrorPolicy::FailFast,
            |_, _, _| output_as_unicode,
            &mut sink,
            None,
        );
        match outcome {
            // The input is already the answer, and the crate guarantees it is
            // ASCII in this case. Copying it into the C allocator is the same
            // single copy the sink path performs.
            Ok(ProcessingSuccess::Passthrough) => {
                CBuf::from_slice(name).ok_or(CURLcode::CURLE_OUT_OF_MEMORY)
            }
            Ok(ProcessingSuccess::WroteToSink) => sink.finish(),
            // The name is invalid, which is what `lib/idn.c` L267 and L288
            // report as CURLE_URL_MALFORMAT.
            Err(ProcessingError::ValidityError) => Err(CURLcode::CURLE_URL_MALFORMAT),
            // The sink refused, which here means the C allocator refused. This
            // is the whole point of using the fallible entry point: the C
            // reports CURLE_OUT_OF_MEMORY at L313 and L338 rather than
            // aborting, and so does this.
            Err(ProcessingError::SinkError) => Err(CURLcode::CURLE_OUT_OF_MEMORY),
        }
    }

    /// The `USE_*` body of `static idn_decode` at `lib/idn.c` L247-L280,
    /// expressed through the `idna` crate.
    ///
    /// The operation is UTS46 _ToASCII_, which is the operation
    /// `idn2_lookup_ul` performs, with the differences the module documentation
    /// lists.
    ///
    /// There is no re-duplication step, and none is needed: the bytes are
    /// written into C-allocator memory as they are produced. That mirrors the
    /// C, where the re-duplication block at L306-L315 is `#ifdef USE_LIBIDN2`
    /// and the Windows and Apple backends allocate through curl's allocator to
    /// begin with.
    ///
    /// # Errors
    ///
    /// `CURLcode::CURLE_URL_MALFORMAT` if the name is not valid UTF-8 or the
    /// crate rejected it, and `CURLcode::CURLE_OUT_OF_MEMORY` if the buffer
    /// could not be allocated.
    pub(super) fn idn_decode(input: &CBuf) -> Result<CBuf, CURLcode> {
        // The C hands libidn2 a byte string and lets it decide; `process`
        // checks the UTF-8 itself and treats ill-formed input as an error,
        // which is the same verdict one layer further in: `idn2_lookup_ul`
        // reports IDN2_ICONV_FAIL or IDN2_ENCODING_ERROR, both of which become
        // CURLE_URL_MALFORMAT at L267.
        convert(input.as_bytes(), false)
    }

    /// The `USE_*` body of `static idn_encode` at `lib/idn.c` L282-L300,
    /// expressed through the `idna` crate.
    ///
    /// The operation is UTS46 _ToUnicode_, the operation
    /// `idn2_to_unicode_8z8z` performs.
    ///
    /// # Errors
    ///
    /// `CURLcode::CURLE_URL_MALFORMAT` if the input is not valid UTF-8 or the
    /// crate rejected it, and `CURLcode::CURLE_OUT_OF_MEMORY` if the buffer
    /// could not be allocated. Unlike the libidn2 backend there is no
    /// `IDNA_MALLOC_ERROR` to translate, because the failure arrives as the
    /// sink's own refusal instead.
    pub(super) fn idn_encode(puny: &CBuf) -> Result<CBuf, CURLcode> {
        convert(puny.as_bytes(), true)
    }

    /// The sink's own behaviour, which is what makes the out-of-memory report
    /// reachable rather than merely written down.
    #[cfg(test)]
    mod tests {
        // As in every test module of this crate: a test's job is to panic when
        // an assertion fails, and a test never crosses the C boundary.
        #![allow(clippy::unwrap_used)]
        #![allow(clippy::arithmetic_side_effects)]

        use super::{convert, CBuf, CSink, CURLcode, Write};

        /// A sink that received nothing still yields a terminated buffer, which
        /// is what libidn2 does with an empty name: an empty *allocated*
        /// string, not a null.
        #[test]
        fn an_empty_sink_yields_an_empty_terminated_buffer() {
            let sink = CSink::with_ceiling(16);
            let buf = sink.finish().unwrap();
            assert_eq!(buf.as_bytes(), b"");
            assert_eq!(buf.as_bytes_with_nul(), b"\0");
        }

        /// Writes accumulate in order, and the handover carries the terminator.
        #[test]
        fn writes_accumulate_in_order() {
            let mut sink = CSink::with_ceiling(64);
            sink.write_str("xn--").unwrap();
            sink.write_str("n3h").unwrap();
            sink.write_str(".de").unwrap();
            let buf = sink.finish().unwrap();
            assert_eq!(buf.as_bytes(), b"xn--n3h.de");
            assert_eq!(buf.as_bytes_with_nul(), b"xn--n3h.de\0");
        }

        /// A refused write is reported as `CURLE_OUT_OF_MEMORY`, and the
        /// refusal is sticky.
        ///
        /// This is the whole reason the sink exists, in one assertion. The
        /// convenience entry points of the `idna` crate build a `String`, whose
        /// growth cannot fail without aborting the process; the sink refuses
        /// instead, `Uts46::process` turns the refusal into
        /// `ProcessingError::SinkError`, and [`convert`] maps that to the code
        /// the C reports at `lib/idn.c` L313 and L338.
        #[test]
        fn a_refused_write_is_reported_as_out_of_memory() {
            // The ceiling is `dyn_nappend`'s: a write fails when
            // `len + idx + 1` exceeds it, so eight bytes fit in a ceiling of
            // nine and a ninth does not.
            let mut sink = CSink::with_ceiling(9);
            assert!(sink.write_str("12345678").is_ok());
            assert!(sink.write_str("9").is_err());
            // Sticky: even a write that would now fit cannot clear it.
            assert!(sink.failed);
            assert_eq!(
                sink.finish().err(),
                Some(CURLcode::CURLE_OUT_OF_MEMORY),
                "a refused write must surface as the C's own report"
            );
        }

        /// The passthrough and sink paths agree on the answer.
        ///
        /// An already-canonical ASCII name is returned as itself, without the
        /// sink being written at all, while the same name in upper case has to
        /// be folded and therefore travels through the sink. Both must produce
        /// the same bytes, which is what makes the passthrough arm of
        /// [`convert`] safe to take.
        #[test]
        fn the_passthrough_and_sink_paths_agree() {
            let lower = CBuf::from_slice(b"example.com").unwrap();
            let upper = CBuf::from_slice(b"EXAMPLE.COM").unwrap();
            let from_passthrough = convert(lower.as_bytes(), false).unwrap();
            let from_sink = convert(upper.as_bytes(), false).unwrap();
            assert_eq!(from_passthrough.as_bytes(), b"example.com");
            assert_eq!(from_sink.as_bytes(), b"example.com");
        }

        /// Ill-formed UTF-8 is a malformed name, not a panic.
        ///
        /// `Uts46::process` checks the encoding itself, which is why this
        /// backend needs no `str::from_utf8` of its own; the verdict is the one
        /// `lib/idn.c` L267 reports for libidn2's `IDN2_ICONV_FAIL`.
        #[test]
        fn ill_formed_utf8_is_a_malformed_name() {
            let bad = CBuf::from_slice(&[0xC3, 0x28]).unwrap();
            assert_eq!(
                convert(bad.as_bytes(), false).err(),
                Some(CURLcode::CURLE_URL_MALFORMAT)
            );
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
    #[cfg(have_idn)]
    fn decodes_to(input: &str, expected: &str) {
        let outcome = host_decode(&cbuf(input.as_bytes()));
        let produced = outcome.as_ref().map(CBuf::as_bytes);
        assert_eq!(produced, Ok(expected.as_bytes()), "decoding {input:?}");
    }

    /// Assert that [`host_encode`] turns `input` into exactly `expected`.
    #[cfg(have_idn)]
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
    // Both callers are conditional and their conditions do not overlap: the
    // libidn2 backend asserts a rejected name, and a build with no backend
    // asserts `CURLUE_LACKS_IDN`. The pure backend rejects neither input, so it
    // has nothing to assert through this helper.
    #[cfg(any(idn_backend_libidn2, not(have_idn)))]
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

    // The locale and codeset probes these tests need, `ensure_locale` and
    // `utf8_codeset`, call `setlocale` and `nl_langinfo` and so live with
    // every other foreign call, in `crate::ffi::test_locale`. They are
    // imported by name below and used exactly as they were here.
    #[cfg(all(idn_backend_libidn2, unix))]
    use crate::ffi::test_locale::{ensure_locale, utf8_codeset};

    /// Nothing to arrange where the locale entry points are not bound.
    ///
    /// The Windows arm of `IDN2_LOOKUP` at `lib/idn.c` L36-L37 selects
    /// `idn2_lookup_u8`, which reads UTF-8 directly, so there is no locale to
    /// arrange on that platform and nothing for the codeset to change.
    #[cfg(all(have_idn, not(all(idn_backend_libidn2, unix))))]
    fn ensure_locale() {}

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
