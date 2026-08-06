// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Dot-segment removal and the path stage, driven through the C surface.
//!
//! The behavioural authority for every expectation in this file is
//! `lib/urlapi.c`; the vectors come from `tests/libtest/lib1560.c`. Every
//! assertion below carries a comment naming the line of `lib/urlapi.c` that
//! produces it, or the row of `tests/libtest/lib1560.c` it is ported from. An
//! expectation without such a citation would be a guess.
//!
//! # Everything goes through the public API, and has to
//!
//! Three C functions do the work: `is_dot` at `lib/urlapi.c` L682-L697,
//! `dedotdotify` at L716-L821, and `handle_path` at L1066-L1108, with
//! `redirect_url` at L1214-L1284 feeding the last of them on the relative-URL
//! path. None of the three is reachable from here, for two independent reasons.
//!
//! * The module tree in `src/lib.rs` exports only `abi` and `ffi`; `parse`
//!   and everything beneath it is crate-private. There is no path from an
//!   integration test to `parse::path`.
//! * `dedotdotify` carries the `UNITTEST` marker at `lib/urlapi.c` L715-L716,
//!   so even the C exports it only in unit-test builds. It is not one of the
//!   eight symbols the drop-in replacement must define, and widening the
//!   crate's exported surface to reach it from a test would add API surface the
//!   port may not add.
//!
//! So every case here goes through `curl_url()`, `curl_url_set(CURLUPART_URL,
//! ...)`, `curl_url_get(CURLUPART_URL, ...)`, `curl_url_get(CURLUPART_PATH,
//! ...)` and `curl_url_cleanup()` -- which is also how
//! `tests/libtest/lib1560.c` reaches this code, in its `set_url` driver at
//! L1388-L1426 and its `get_url` driver at L1541-L1577.
//!
//! Those entry points are reached by symbol rather than by Rust path.
//! `src/ffi.rs` places all ten exported functions in a `pub(crate) mod
//! exports`, so `curl_urlapi_rs::ffi` is an empty module from outside the crate
//! and naming `ffi::curl_url` here would not compile. This file declares the
//! four entry points it needs in its own `extern "C"` block, mirroring
//! `include/curl/urlapi.h` L113-L142, and lets the linker resolve them against
//! the `#[no_mangle]` definitions in the `rlib`. That is the same view a C
//! consumer of the drop-in archive gets, so a mangled, missing or wrongly-typed
//! export fails this file at link time.
//!
//! # Memory ownership
//!
//! `docs/libcurl/curl_url_get.md` L45 requires the returned content pointer to
//! be freed with curl's free function, and L46 forbids altering the pointed
//! string. [`get_part`] is the only place a returned pointer is touched: it
//! copies the bytes out and releases the buffer with `libc::free`, exactly
//! once, and never writes through the pointer.
//!
//! `libc::free` is the right release path in every configuration the crate
//! builds in. `src/alloc.rs` is the sole producer of C-visible memory and it
//! allocates from the C allocator, so plain `free` is what `curl_free` reduces
//! to (`lib/escape.c` L189-L192 forwarding to the resolution chain in
//! `lib/curl_setup.h` L1461-L1484). `ffi::curl_free` is deliberately *not*
//! used: it exists only under the default-on `cfree` feature and is absent from
//! the drop-in configuration, where a real libcurl supplies it instead.
//! `libc` is an unconditional `[dependencies]` entry, so it is available to
//! this target in both configurations.
//!
//! Panicking is fine here. The crate root's denial of `unwrap`, `expect`,
//! indexing and `panic!` binds library code, which must never let a panic reach
//! the C boundary; a test's whole job is to panic on a failed assertion and it
//! never crosses that boundary. `[profile.release]` sets `panic = "abort"` and
//! the `dev`/`test` profiles are left at their defaults, so `cargo test` runs
//! unwinding as usual.

use core::ffi::{c_char, c_uint, c_void, CStr};
use std::ffi::CString;

use curl_urlapi_rs::abi;

/// Opaque stand-in for `CURLU`.
///
/// `include/curl/urlapi.h` L107 is `typedef struct Curl_URL CURLU;` with no
/// definition in sight, so the handle is an incomplete type to every consumer
/// and is only ever held behind a pointer. A zero-sized `repr(C)` struct is the
/// usual way to say that in Rust: it can be pointed at and never constructed,
/// and every thin pointer has the same ABI, so `*mut CurlU` is exactly what the
/// header's `CURLU *` is.
#[repr(C)]
struct CurlU {
    _opaque: [u8; 0],
}

// The four entry points this file drives, transcribed from
// `include/curl/urlapi.h`: `curl_url` L113, `curl_url_cleanup` L120,
// `curl_url_get` L133-L134 and `curl_url_set` L141-L142. Deliberately no more
// than four -- `curl_url_dup` L126, `curl_url_strerror` L149 and the three
// internal entry points declared in `lib/urlapi-int.h` are not exercised by any
// case below, and declaring an unused foreign function would leave a symbol
// reference this file cannot justify.
//
// `curl_url_get` takes `*const CurlU` because the C takes `const CURLU *`; no
// mutable reference to a handle is ever formed while a get is in flight.
extern "C" {
    fn curl_url() -> *mut CurlU;

    fn curl_url_cleanup(handle: *mut CurlU);

    fn curl_url_get(
        handle: *const CurlU,
        what: abi::CURLUPart,
        part: *mut *mut c_char,
        flags: c_uint,
    ) -> abi::CURLUcode;

    fn curl_url_set(
        handle: *mut CurlU,
        what: abi::CURLUPart,
        part: *const c_char,
        flags: c_uint,
    ) -> abi::CURLUcode;
}

// This file must compile and pass under the crate's default features and under
// the drop-in configuration, `--no-default-features --features idn-libidn2`.
// The difference that reaches this file is the scheme backend, and it needs
// solving in two places rather than one.
//
// 1. LINKING. With `scheme-table` off, `src/scheme.rs` aliases its backend to
//    `crate::ffi::scheme_import`, which declares `Curl_get_scheme` and
//    `Curl_getn_scheme` as foreign functions for a real libcurl to define.
//    `src/ffi.rs` provides stand-ins only under `#[cfg(test)]`, which covers
//    the crate's own unit tests and not a separate integration-test binary, so
//    *any* integration test fails to link in that configuration with two
//    undefined symbols. The two definitions below fix that, and they are gated
//    so they exist only in the configuration that needs them.
//
//    They return null, which is a legal answer from that function rather than a
//    fudge: `lib/url.c` L1469-L1472 returns null for a name its table does not
//    hold, and null is what the crate's `describe` turns into `None`. Returning
//    null also means no `struct Curl_scheme` has to be described here -- the
//    layout contract in `src/ffi.rs` is delicate enough (`curl_prot_t` width
//    silently moves `flags` and `defport`) that duplicating it in a test file
//    would create a second place for it to rot. The return type is written as
//    `*const c_void` for the same reason; at the C ABI a pointer is a pointer.
//
// 2. PARSING. With the table gone, `http` is not a recognised scheme, and
//    `lib/urlapi.c` L951-L953 rejects an unrecognised scheme unless
//    `CURLU_NON_SUPPORT_SCHEME` is set. [`MODE_FLAGS`] adds that flag in that
//    configuration and nothing in the default one, so the vectors below carry
//    the flags of their own `lib1560.c` rows and nothing else when the table is
//    present.
//
// The flag is expectation-neutral for every vector in this file, which is why
// it can be added blindly. `lib/urlapi.c` consults the scheme table at exactly
// these places: L951 (gated by the flag itself), L283-L291 (decides only
// whether credential *options* are parsed, and is reached only when the
// authority holds an `@`, which none of these vectors does), L1460-L1478 and
// L1586-L1601 (act only under `CURLU_DEFAULT_PORT` or `CURLU_NO_DEFAULT_PORT`,
// neither of which is passed here, and on `options`, which is always absent),
// and L1645 (`set_url_scheme`, and `CURLUPART_SCHEME` is never set here). The
// equivalence is also checked rather than only argued, because `cargo test` in
// both configurations has to give the same answers for every case below.

#[cfg(feature = "scheme-table")]
const MODE_FLAGS: c_uint = 0;

#[cfg(not(feature = "scheme-table"))]
const MODE_FLAGS: c_uint = abi::CURLU_NON_SUPPORT_SCHEME;

/// Link-time stand-in for `Curl_get_scheme`, `lib/url.c` L1469-L1472.
///
/// Present only in the drop-in configuration, where the crate imports the
/// symbol from libcurl and no libcurl participates in this binary's link. The
/// name is a C identifier and must stay spelled the way libcurl spells it, so
/// the Rust naming convention cannot apply.
#[cfg(not(feature = "scheme-table"))]
#[no_mangle]
#[allow(non_snake_case)]
extern "C" fn Curl_get_scheme(_scheme: *const c_char) -> *const c_void {
    core::ptr::null()
}

/// Link-time stand-in for `Curl_getn_scheme`, `lib/url.c` L1477-L1541.
///
/// Present only in the drop-in configuration, for the same reason as
/// `Curl_get_scheme` above.
#[cfg(not(feature = "scheme-table"))]
#[no_mangle]
#[allow(non_snake_case)]
extern "C" fn Curl_getn_scheme(_scheme: *const c_char, _len: usize) -> *const c_void {
    core::ptr::null()
}

/// An owned URL handle that cleans itself up.
///
/// `curl_url_cleanup` is called from `Drop` rather than at the end of each test
/// so that a failed assertion unwinds without leaking the handle. The type
/// holds the raw pointer the C gave back and hands out no reference to the
/// pointee, matching the opacity `include/curl/urlapi.h` L107 imposes.
struct Handle(*mut CurlU);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `curl_url` in `new_handle`, was checked
        // non-null there, has not been freed (this is the only free and it runs
        // once, at drop), and is not aliased because `Handle` is neither `Copy`
        // nor cloneable. `curl_url_cleanup` accepting the handle `curl_url`
        // issued is the contract at `include/curl/urlapi.h` L110-L111 and
        // L116-L120.
        unsafe { curl_url_cleanup(self.0) };
    }
}

/// Allocates a fresh handle, mirroring `lib/urlapi.c` L1288-L1291.
///
/// A free function rather than an inherent `new`, so no `Default`
/// implementation is implied for a type whose only sensible construction can
/// fail on allocation.
fn new_handle() -> Handle {
    // SAFETY: `curl_url` takes no arguments and only allocates, so there is no
    // precondition to uphold. It returns null on allocation failure, which the
    // assertion below turns into a test failure rather than a null dereference.
    let raw = unsafe { curl_url() };
    assert!(!raw.is_null(), "curl_url() returned null: out of memory");
    Handle(raw)
}

/// Runs `curl_url_set` for one part, returning the raw `CURLUcode`.
///
/// `value` is copied into a `CString` because the C requires a terminated
/// string. `CString::new` is used rather than a `c"..."` literal on purpose:
/// C string literals need Rust 1.77 and `Cargo.toml` declares
/// `rust-version = "1.75"`.
fn set_part(handle: &Handle, what: abi::CURLUPart, value: &str, flags: c_uint) -> abi::CURLUcode {
    let terminated = CString::new(value).expect("test vector contains an interior NUL byte");
    // SAFETY: the handle is live and exclusively ours for the duration of the
    // call. `terminated` outlives the call and yields a non-null pointer to a
    // NUL-terminated buffer, which is what `curl_url_set` reads and all it
    // reads -- it copies what it keeps, so nothing outlives this borrow.
    unsafe { curl_url_set(handle.0, what, terminated.as_ptr(), flags) }
}

/// Runs `curl_url_get` for one part and returns the code with an owned copy of
/// the content.
///
/// The single place in this file that touches a pointer the API returned. It
/// copies the bytes out and releases the buffer with `libc::free` exactly once,
/// honouring `docs/libcurl/curl_url_get.md` L45, and never writes through the
/// pointer, honouring L46. `None` means no buffer was produced.
///
/// The returned code, not the pointer, decides whether a buffer exists, and the
/// order matters. `lib/urlapi.c` L1552 stores null into the caller's slot on
/// entry, before anything can fail, and every failing return sits after it -- so
/// a failure is required to leave the slot null, and this function asserts that
/// instead of assuming it. Dereferencing a pointer written by a *failing* call
/// would be undefined behaviour, and a test that reaches for undefined behaviour
/// exactly when the defect it hunts is present cannot report that defect. Only a
/// `CURLUE_OK` result is read, and `tests/host_ip.rs` and the other suites order
/// it identically.
///
/// The copy goes through `String::from_utf8_lossy`. Every expectation in this
/// file is ASCII, so for a correct port the conversion is exact; for an
/// incorrect one it yields a visibly different string rather than a panic, which
/// makes the assertion's diff readable.
fn get_part(
    handle: &Handle,
    what: abi::CURLUPart,
    flags: c_uint,
) -> (abi::CURLUcode, Option<String>) {
    let mut content: *mut c_char = core::ptr::null_mut();
    // SAFETY: the handle is live, and it is passed as `*const` because the C
    // signature is `const CURLU *` -- no mutable reference to the pointee is
    // formed here. `content` is a valid, writable, properly aligned slot for
    // the one pointer the callee stores, and it is initialised to null first so
    // that the null test below is meaningful even if the callee wrote nothing.
    let code = unsafe { curl_url_get(handle.0, what, &mut content, flags) };
    if code != abi::CURLUE_OK {
        // Nothing was produced, so there is nothing to read and nothing to
        // release. The slot is checked rather than ignored: L1552's
        // unconditional null is what lets a caller avoid releasing a stale
        // pointer, so a violation is reported here, never dereferenced.
        assert!(
            content.is_null(),
            "get part {what} flags {flags:#x} failed with {code} yet stored a \
             pointer; lib/urlapi.c L1552 nulls the slot before any failing \
             return can be taken"
        );
        return (code, None);
    }
    if content.is_null() {
        // Success with no buffer is a real answer rather than a fault -- a blank
        // part retrieved under `CURLU_GET_EMPTY` reaches it -- so it is reported
        // as "no content" and which vectors arrive here stays a property of the
        // vectors.
        return (code, None);
    }
    // SAFETY: the call reported `CURLUE_OK` and `content` is non-null, so per the
    // contract at `include/curl/urlapi.h` L130-L131 it points at a
    // NUL-terminated buffer this caller now owns. `CStr::from_ptr` only reads up
    // to that terminator, and the bytes are copied before the buffer is released
    // on the next line.
    let owned = String::from_utf8_lossy(unsafe { CStr::from_ptr(content) }.to_bytes()).into_owned();
    // SAFETY: `content` was allocated by the crate's C-allocator adapter, has
    // not been freed, and is freed exactly once here. See the module
    // documentation for why `libc::free` rather than `ffi::curl_free`.
    unsafe { libc::free(content.cast::<c_void>()) };
    (code, Some(owned))
}

/// Parses `input` into a fresh handle and asserts it succeeded.
///
/// [`MODE_FLAGS`] is added to the caller's flags, never substituted for them.
fn parsed(input: &str, urlflags: c_uint) -> Handle {
    let handle = new_handle();
    let code = set_part(&handle, abi::CURLUPART_URL, input, urlflags | MODE_FLAGS);
    assert_eq!(
        code,
        abi::CURLUE_OK,
        "curl_url_set(CURLUPART_URL, {input:?}, {urlflags:#x}) failed with {code}"
    );
    handle
}

/// The whole URL as `curl_url_get(CURLUPART_URL, ...)` serialises it, asserting
/// the call succeeded.
///
/// `urlget_url` at `lib/urlapi.c` L1425-L1539 is what builds it, and L1528 is
/// the detail that matters most here: a handle with no stored path serialises
/// its path as `/`.
fn whole_url(handle: &Handle, getflags: c_uint) -> String {
    let (code, content) = get_part(handle, abi::CURLUPART_URL, getflags);
    assert_eq!(code, abi::CURLUE_OK, "curl_url_get(CURLUPART_URL) failed");
    content.expect("CURLUE_OK from curl_url_get(CURLUPART_URL) without a buffer")
}

/// The path as `curl_url_get(CURLUPART_PATH, ...)` reports it, asserting the
/// call succeeded.
///
/// `CURLUPART_PATH` is the one part that can never be reported missing:
/// `lib/urlapi.c` L1604-L1607 substitutes `/` when the field is null, so the
/// `ifmissing` code initialised at L1545 is unreachable for it.
fn path_of(handle: &Handle, getflags: c_uint) -> String {
    let (code, content) = get_part(handle, abi::CURLUPART_PATH, getflags);
    assert_eq!(code, abi::CURLUE_OK, "curl_url_get(CURLUPART_PATH) failed");
    content.expect("CURLUE_OK from curl_url_get(CURLUPART_PATH) without a buffer")
}

/// One row of a parse-then-read case, modelled on `struct urltestcase` at
/// `tests/libtest/lib1560.c` L125-L131.
///
/// The C row carries `in`, `out`, `urlflags`, `getflags` and an expected code.
/// This one drops the code, because [`run_get_cases`] only drives rows that
/// succeed, and adds `path` so a failure localises to the path stage instead of
/// only to serialisation.
struct GetCase {
    input: &'static str,
    url: &'static str,
    path: &'static str,
    urlflags: c_uint,
    origin: &'static str,
}

/// One row of a base-then-relative case, modelled on `struct redircase` at
/// `tests/libtest/lib1560.c` L88-L95, with the same added `path` column as
/// [`GetCase`].
struct RedirCase {
    base: &'static str,
    relative: &'static str,
    url: &'static str,
    path: &'static str,
    urlflags: c_uint,
    setflags: c_uint,
    origin: &'static str,
}

/// Drives every [`GetCase`], the way `get_url` does at
/// `tests/libtest/lib1560.c` L1541-L1577: set the URL, then read it back.
///
/// The read uses flags of zero, as the rows below all do; `checkparts` at L69
/// applies one flag set to every part it reads and this follows that.
fn run_get_cases(cases: &[GetCase]) {
    for case in cases {
        let handle = parsed(case.input, case.urlflags);
        assert_eq!(
            whole_url(&handle, 0),
            case.url,
            "CURLUPART_URL for {:?} ({})",
            case.input,
            case.origin
        );
        assert_eq!(
            path_of(&handle, 0),
            case.path,
            "CURLUPART_PATH for {:?} ({})",
            case.input,
            case.origin
        );
    }
}

/// Drives every [`RedirCase`], the way `set_url` does at
/// `tests/libtest/lib1560.c` L1388-L1426: set the base, set the relative part
/// over it, then read the whole URL back with flags of zero (L1406).
fn run_redir_cases(cases: &[RedirCase]) {
    for case in cases {
        let handle = parsed(case.base, case.urlflags);
        let code = set_part(
            &handle,
            abi::CURLUPART_URL,
            case.relative,
            case.setflags | MODE_FLAGS,
        );
        assert_eq!(
            code,
            abi::CURLUE_OK,
            "setting {:?} over {:?} failed with {code} ({})",
            case.relative,
            case.base,
            case.origin
        );
        assert_eq!(
            whole_url(&handle, 0),
            case.url,
            "CURLUPART_URL after {:?} over {:?} ({})",
            case.relative,
            case.base,
            case.origin
        );
        assert_eq!(
            path_of(&handle, 0),
            case.path,
            "CURLUPART_PATH after {:?} over {:?} ({})",
            case.relative,
            case.base,
            case.origin
        );
    }
}

/// `CURLU_PATH_AS_IS` decides whether dot segments survive the parse.
///
/// The pair is `tests/libtest/lib1560.c` L779-L781 and L782-L784: the same
/// input, one flag apart, two different results. The mechanism is a single
/// condition, `if(!(flags & CURLU_PATH_AS_IS))` at `lib/urlapi.c` L1095, which
/// is the only thing standing between `handle_path` and the dot removal at
/// L1096-L1105. Everything else about the parse is identical, which is why this
/// pair isolates the flag so cleanly.
///
/// Both rows assert the path as well as the whole URL. The C table only checks
/// the serialised URL, so a port that stored the right path and serialised it
/// wrongly, or the reverse, would look the same from there.
#[test]
fn path_as_is_decides_whether_dot_segments_survive() {
    run_get_cases(&[
        GetCase {
            // lib1560.c L779-L781. The dot segment is kept verbatim.
            input: "http://example.com/hello/../here",
            url: "http://example.com/hello/../here",
            path: "/hello/../here",
            urlflags: abi::CURLU_PATH_AS_IS,
            origin: "lib1560.c:779-781",
        },
        GetCase {
            // lib1560.c L782-L784. Same input, no flag: rule C of
            // `dedotdotify` (lib/urlapi.c L779-L797) drops `/hello` when it
            // reaches `/../`, leaving `/here`.
            input: "http://example.com/hello/../here",
            url: "http://example.com/here",
            path: "/here",
            urlflags: 0,
            origin: "lib1560.c:782-784",
        },
    ]);
}

/// `%2e` and `%2E` are dots, and mixing the two forms changes nothing.
///
/// `is_dot` at `lib/urlapi.c` L682-L697 accepts two spellings. A literal `.`
/// advances one byte (L685-L689). A `%2` followed by a byte that folds to `e`
/// under `| 0x20` advances three (L690-L695) -- and since only `0x65` and
/// `0x45` satisfy `b | 0x20 == 0x65`, that third byte is `e` or `E` and nothing
/// else.
///
/// The three rows are `tests/libtest/lib1560.c` L1253-L1255, L1256-L1258 and
/// L1259-L1261: the same destination reached from a literal-dot path, from a
/// mixed path, and from a path that mixes both spellings *and* both cases
/// inside single segments. The last is the strongest single case for the fold,
/// because `.%2E`, `%2E` and `%2e%2E` all have to resolve for it to land on
/// `/moo`.
#[test]
fn both_spellings_and_both_cases_of_the_dot_resolve() {
    run_redir_cases(&[
        RedirCase {
            // lib1560.c L1253-L1255: literal dots only, the control row.
            base: "http://example.org/",
            relative: "../path/././../././../moo",
            url: "http://example.org/moo",
            path: "/moo",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1253-1255",
        },
        RedirCase {
            // lib1560.c L1256-L1258: `.%2e` for `..` and `%2E` for `.`.
            base: "http://example.org/",
            relative: ".%2e/path/././../%2E/./../moo",
            url: "http://example.org/moo",
            path: "/moo",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1256-1258",
        },
        RedirCase {
            // lib1560.c L1259-L1261: both spellings and both cases, some of
            // them inside one segment.
            base: "http://example.org/",
            relative: ".%2e/path/./%2e/.%2E/%2E/./%2e%2E/moo",
            url: "http://example.org/moo",
            path: "/moo",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1259-1261",
        },
    ]);
}

/// Only `e` and `E` complete the encoded dot, and only with three bytes left.
///
/// These rows are not in the C table; they are read straight off the predicate
/// at `lib/urlapi.c` L690-L695, which is the kind of boundary a table of
/// end-to-end URLs does not isolate.
///
/// * `%2E` alone is a dot, so `/hello/%2E/here` takes rule B at L764-L773 and
///   collapses to `/hello/here`.
/// * `%2e%2e` is two dots, so `/hello/%2e%2e/here` takes rule C at L779-L797
///   and drops `/hello` as well, leaving `/here`.
/// * `%2f` and `%2d` fail the fold -- `'f' | 0x20` is `'f'` and `'d' | 0x20` is
///   `'d'` -- so neither is a dot and both paths come through untouched. `%2f`
///   is the interesting one: it is the encoding of `/`, and a port that decoded
///   before dedotting rather than after would see a segment boundary here and
///   produce something different.
/// * A trailing `%2` is not a dot either. The `*clen >= 3` guard at L690 stops
///   the third-byte read from running off the end of the path; the byte it would
///   have read is the terminator, and `0 | 0x20` is `0x20`, not `'e'`, so the
///   answer is the same with the guard as without it -- the guard is there for
///   the read, not for the result. `/hello/..%2` also shows that a `..` becomes
///   inert once a non-slash byte follows it, since rule C at L779 requires
///   `ISSLASH(*p) || !blen`.
#[test]
fn only_e_and_capital_e_complete_the_encoded_dot() {
    run_get_cases(&[
        GetCase {
            // lib/urlapi.c L690-L695 with a folding third byte, then rule B.
            input: "http://example.org/hello/%2E/here",
            url: "http://example.org/hello/here",
            path: "/hello/here",
            urlflags: 0,
            origin: "derived from lib/urlapi.c:690-695 and 764-773",
        },
        GetCase {
            // Two encoded dots in one segment, then rule C.
            input: "http://example.org/hello/%2e%2e/here",
            url: "http://example.org/here",
            path: "/here",
            urlflags: 0,
            origin: "derived from lib/urlapi.c:690-695 and 779-797",
        },
        GetCase {
            // `'f' | 0x20 != 'e'`, so `%2f` is an ordinary three-byte run.
            input: "http://example.org/hello/%2f/here",
            url: "http://example.org/hello/%2f/here",
            path: "/hello/%2f/here",
            urlflags: 0,
            origin: "derived from lib/urlapi.c:691",
        },
        GetCase {
            // `'d' | 0x20 != 'e'`, likewise.
            input: "http://example.org/hello/%2d/here",
            url: "http://example.org/hello/%2d/here",
            path: "/hello/%2d/here",
            urlflags: 0,
            origin: "derived from lib/urlapi.c:691",
        },
        GetCase {
            // Fewer than three bytes remain, so the `*clen >= 3` guard at L690
            // declines before the fold is even attempted.
            input: "http://example.org/foo/%2",
            url: "http://example.org/foo/%2",
            path: "/foo/%2",
            urlflags: 0,
            origin: "derived from lib/urlapi.c:690",
        },
        GetCase {
            // `..` followed by `%2` rather than a slash or the end, so rule C
            // (L779) does not apply and nothing is removed.
            input: "http://example.org/hello/..%2",
            url: "http://example.org/hello/..%2",
            path: "/hello/..%2",
            urlflags: 0,
            origin: "derived from lib/urlapi.c:779 and 690",
        },
    ]);
}

/// The dot-removal and relative-resolution rows of `set_url_list`, ported.
///
/// `redirect_url` at `lib/urlapi.c` L1214-L1284 builds the combined URL and
/// hands it back to the parser, so each row exercises one of its four branches
/// and then the path stage. The branches, and the rows that reach them:
///
/// * protocol-relative, L1232-L1238: `//...` and `///...`
/// * root-relative, L1239-L1241: `/moo#frag`
/// * default, L1250-L1266: everything else, including the `?`-leading rows that
///   skip the truncation at L1259-L1264
///
/// Two rows are worth singling out. `///example.org/../path/../../` reaches the
/// same place as the two-slash form because `parse_scheme` swallows one to three
/// slashes after the colon (L945-L957), so the third slash is absorbed rather
/// than becoming an empty host. And `:23` is *not* an absolute URL --
/// `Curl_is_absolute_url` needs an alphabetic first byte (L194) -- so it is
/// appended after the base's last slash like any other relative path, which is
/// the browser-compatible answer the row records.
#[test]
fn set_url_list_dot_and_relative_rows() {
    run_redir_cases(&[
        RedirCase {
            // lib1560.c L1250-L1252: root-relative with a fragment. The base's
            // own fragment is cut at the first slash after the host
            // (L1239-L1241), and the fragment supplied here replaces it.
            base: "http://example.org#without/ash",
            relative: "/moo#frag",
            url: "http://example.org/moo#frag",
            path: "/moo",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1250-1252",
        },
        RedirCase {
            // lib1560.c L1288-L1291: more leading `..` than there are segments
            // to remove, which rule C tolerates -- L782 only trims the output
            // when there is something in it.
            base: "http://example.org/",
            relative: "../path/././../../moo",
            url: "http://example.org/moo",
            path: "/moo",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1288-1291",
        },
        RedirCase {
            // lib1560.c L1292-L1295: protocol-relative, so the host changes and
            // the cut is at the start of the host (L1235-L1237). The path
            // collapses to `/` because the trailing `../../` walks past the
            // root.
            base: "http://example.org/",
            relative: "//example.org/../path/../../",
            url: "http://example.org/",
            path: "/",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1292-1295",
        },
        RedirCase {
            // lib1560.c L1296-L1299: three slashes, same result. The extra
            // slash is swallowed by the one-to-three-slash tolerance at
            // lib/urlapi.c L945-L957.
            base: "http://example.org/",
            relative: "///example.org/../path/../../",
            url: "http://example.org/",
            path: "/",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1296-1299",
        },
        RedirCase {
            // lib1560.c L1300-L1303: a colon-leading relative part is a path,
            // not a scheme.
            base: "http://example.org/foo/bar",
            relative: ":23",
            url: "http://example.org/foo/:23",
            path: "/foo/:23",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1300-1303",
        },
        RedirCase {
            // lib1560.c L1263-L1264: the base's query is dropped at L1252-L1254
            // and, because the relative part starts with `?`, the last-slash
            // truncation at L1259-L1264 is skipped. The base's path was never
            // stored (it was empty), so it serialises as `/` (L1528).
            base: "http://example.org?bar/moo",
            relative: "?weird",
            url: "http://example.org/?weird",
            path: "/",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1263-1264",
        },
        RedirCase {
            // lib1560.c L1265-L1266: the same skip, this time with a path worth
            // keeping. `/foo` survives precisely because L1259 declines to
            // truncate after the last slash for a `?`-leading relative part.
            base: "http://example.org/foo?bar",
            relative: "?weird",
            url: "http://example.org/foo?weird",
            path: "/foo",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1265-1266",
        },
        RedirCase {
            // lib1560.c L1267-L1268: no query on the base, so no cut at all,
            // and the path still survives.
            base: "http://example.org/foo",
            relative: "?weird",
            url: "http://example.org/foo?weird",
            path: "/foo",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1267-1268",
        },
        RedirCase {
            // lib1560.c L1269-L1270: no path and no query on the base, so
            // `cutoff` stays null and the whole base is kept (L1269).
            base: "http://example.org",
            relative: "?weird",
            url: "http://example.org/?weird",
            path: "/",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1269-1270",
        },
        RedirCase {
            // lib1560.c L1271-L1272: the base's fragment is cut at L1255-L1257
            // and the relative part supplies both a query and a fragment.
            base: "http://example.org/#original",
            relative: "?weird#moo",
            url: "http://example.org/?weird#moo",
            path: "/",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1271-1272",
        },
        RedirCase {
            // lib1560.c L1286-L1287: the default branch with a path-leading
            // relative part, so the truncation at L1261-L1264 does run and
            // `/foo` is replaced rather than extended.
            base: "http://example.org/foo?bar",
            relative: "moo?hey#weird",
            url: "http://example.org/moo?hey#weird",
            path: "/moo",
            urlflags: 0,
            setflags: 0,
            origin: "lib1560.c:1286-1287",
        },
        RedirCase {
            // lib1560.c L1336-L1339: dot removal and percent-encoding in one
            // row. The relative part is absolute, so `set_url` replaces outright
            // at L1713-L1715 and `handle_path` sees the flags directly: the two
            // spaces in the path become `%20` (L1070-L1077, via L151-L153) and
            // the two in the query become `+` (L1041-L1046, `query` true so
            // `left` starts false at L135), while `/it/is/../../` collapses to
            // nothing. This is the encode-and-dedot path end to end.
            base: "http://example.com/please/../gimme/%TESTNUMBER?foobar#hello",
            relative: "http://example.net/there/it/is/../../tes t case=/%TESTNUMBER0002? yes no",
            url: "http://example.net/there/tes%20t%20case=/%TESTNUMBER0002?+yes+no",
            path: "/there/tes%20t%20case=/%TESTNUMBER0002",
            urlflags: 0,
            setflags: abi::CURLU_URLENCODE | abi::CURLU_ALLOW_SPACE,
            origin: "lib1560.c:1336-1339",
        },
    ]);
}

/// `CURLU_PATH_AS_IS` is force-cleared when a relative URL is applied.
///
/// `redirect_url` rebuilds the combined URL and re-parses it with
/// `flags & ~CURLU_PATH_AS_IS` at `lib/urlapi.c` L1276-L1277. The flag the
/// caller passed to `curl_url_set` therefore cannot suppress dot removal on
/// this path, only on the absolute path that goes through
/// `parseurl_and_replace` directly at L1715.
///
/// No row of `set_url_list` isolates this, because every row that carries
/// `CURLU_PATH_AS_IS` in that table sets an absolute URL. It is exactly the sort
/// of asymmetry a refactor would erase without any test noticing, so it is
/// asserted here directly, and asserted twice: once with a base parsed normally,
/// and once with a base parsed with the flag set, to show that the flag's effect
/// on the base does not carry into the relative step either. The base's own
/// `/foo/bar` has no dot segment, so the two rows must agree.
#[test]
fn path_as_is_is_cleared_on_the_relative_url_path() {
    run_redir_cases(&[
        RedirCase {
            // lib/urlapi.c L1277 clears the flag before the re-parse, so
            // `/foo/../moo` is dedotted even though CURLU_PATH_AS_IS was asked
            // for.
            base: "http://example.org/foo/bar",
            relative: "../moo",
            url: "http://example.org/moo",
            path: "/moo",
            urlflags: 0,
            setflags: abi::CURLU_PATH_AS_IS,
            origin: "derived from lib/urlapi.c:1276-1277",
        },
        RedirCase {
            // Same, with the base also parsed as-is. The flag governs one parse
            // at a time and is not remembered on the handle, so the answer does
            // not change.
            base: "http://example.org/foo/bar",
            relative: "../moo",
            url: "http://example.org/moo",
            path: "/moo",
            urlflags: abi::CURLU_PATH_AS_IS,
            setflags: abi::CURLU_PATH_AS_IS,
            origin: "derived from lib/urlapi.c:1276-1277",
        },
    ]);
}

/// The path is percent-encoded first and dot-dedotted second, over the encoded
/// bytes.
///
/// `handle_path` runs the encoder at `lib/urlapi.c` L1070-L1077 and only then
/// the dot removal at L1095-L1105. The step between them is the one that makes
/// the order load-bearing: L1076 recomputes `pathlen` from the encoded buffer,
/// so the dedot pass is told how long the *encoded* path is.
///
/// It is worth being precise about what "order matters" means here, because the
/// obvious claim is false. `urlencode_str` substitutes only three byte classes
/// -- a space, a byte below `0x20`, and a byte at or above `0x7f` (L151-L161) --
/// and no character it can emit is a `.` or a `/`. The dot-and-slash structure
/// `dedotdotify` keys on is therefore identical before and after encoding, and
/// the two orders produce the same string. What the order actually protects is
/// the length: dedotting the encoded buffer with the *pre*-encoding length would
/// truncate it. For the first row below, 9 raw bytes against 11 encoded ones,
/// that mistake yields `/a/` instead of `/a/b` -- so the assertion does pin
/// L1076 even though it cannot pin an ordering difference that does not exist.
///
/// The three rows together show the two steps are independent and both real:
///
/// * `/a/ /../b` encodes to `/a/%20/../b`, and `..` then removes the whole
///   `%20` segment (rule C, L779-L797), so the space disappears entirely.
/// * `/a/ ../b` encodes to `/a/%20../b` and nothing is removed, because after
///   encoding the `..` is still preceded by a non-slash byte and rule C at L779
///   needs a complete segment. This is the commutation property made visible.
/// * The first input again with `CURLU_PATH_AS_IS`: the encoding still happens,
///   the dot removal does not. Only L1095 is skipped, which is the cleanest
///   possible demonstration that the two steps are separate.
#[test]
fn the_path_is_encoded_before_dot_segments_are_removed() {
    let encode = abi::CURLU_URLENCODE | abi::CURLU_ALLOW_SPACE;
    run_get_cases(&[
        GetCase {
            // Encoded to `/a/%20/../b` at L1070-L1077 with pathlen recomputed at
            // L1076, then rule C removes the `%20` segment.
            input: "http://example.org/a/ /../b",
            url: "http://example.org/a/b",
            path: "/a/b",
            urlflags: encode,
            origin: "derived from lib/urlapi.c:1070-1077 and 1095-1105",
        },
        GetCase {
            // `..` is not a complete segment before encoding and is not one
            // after it either, so neither order removes anything.
            input: "http://example.org/a/ ../b",
            url: "http://example.org/a/%20../b",
            path: "/a/%20../b",
            urlflags: encode,
            origin: "derived from lib/urlapi.c:151-161 and 779",
        },
        GetCase {
            // Encoding is not gated on CURLU_PATH_AS_IS; only the dot removal
            // at L1095 is.
            input: "http://example.org/a/ /../b",
            url: "http://example.org/a/%20/../b",
            path: "/a/%20/../b",
            urlflags: encode | abi::CURLU_PATH_AS_IS,
            origin: "derived from lib/urlapi.c:1070-1077 and 1095",
        },
    ]);
}

/// Relative resolution and `CURLU_URLENCODE` in one call: the tail is encoded,
/// the authority is not, and the dot segments still go.
///
/// Everything up to here has exercised those mechanisms one at a time. This is
/// the public path that runs all of them in a single `curl_url_set`, and it is
/// the only place `urlencode_str`'s `relative` argument is observable at all.
///
/// # The one call site where the host exemption is live
///
/// `redirect_url` ends at `lib/urlapi.c` L1275 with
/// `urlencode_str(&urlbuf, useurl, strlen(useurl), !host_changed, FALSE)`. That
/// fourth argument is `relative`, and this is the only call in the file that
/// can pass it as FALSE -- `urlget_format` hardcodes TRUE at L1395. FALSE
/// switches on the block at L138-L148, which calls `find_host_sep` (L104-L118),
/// copies everything up to the first `/` or `?` after a `//` **verbatim**, and
/// encodes only what follows. The in-source comment at L124-L127 gives the
/// reason: encoding a hostname would break internationalised-domain resolution.
///
/// `host_changed` is TRUE for exactly one of the four branches, the
/// protocol-relative one at L1232-L1238, so:
///
/// * a **plain relative** value is encoded end to end -- the base's own
///   authority is not at risk, because L1272 copies the base prefix straight
///   out of the base and only `useurl` reaches the encoder;
/// * a **protocol-relative** value carries its own authority, and that
///   authority is what the exemption protects.
///
/// # How "verbatim" is made observable
///
/// A space is the only byte that can demonstrate it. The encoder substitutes
/// three classes -- a space, a byte below `0x20` and a byte at or above `0x7f`
/// (L151-L161) -- and of those only the space can survive the re-parse inside
/// an authority: `hostname_check` at L457 rejects a space in a *host*, and a
/// byte below 0x20 or 127 is refused by `Curl_junkscan` before that. But the
/// exemption covers the whole authority, userinfo included, and a space is legal
/// in the userinfo -- `parse_hostname_login` splits at the `@` and percent-
/// decodes with `REJECT_CTRL`, which passes 0x20. So a space in the **user** of
/// a protocol-relative value comes back as a space if and only if the authority
/// was copied verbatim; had the encoder touched it, it would come back as
/// `%20`, and would then have been decoded to a space again by a *different*
/// mechanism -- which is why the assertion below reads the user part rather
/// than inferring from the whole URL alone.
///
/// `CURLU_ALLOW_SPACE` is therefore required on the call, and not incidentally:
/// L1276-L1277 re-parses the rebuilt URL, and `Curl_junkscan` refuses a raw
/// space without it (L232-L235). The same re-parse is what removes the dot
/// segments, and it is handed `flags & ~CURLU_PATH_AS_IS`, so the third row
/// below asserts that a caller passing `CURLU_PATH_AS_IS` alongside
/// `CURLU_URLENCODE` still gets its dots removed --
/// [`path_as_is_is_cleared_on_the_relative_url_path`] pins that clearing on its
/// own, and this row is the combination.
#[test]
fn a_relative_url_is_encoded_without_its_authority_being_encoded() {
    run_redir_cases(&[
        RedirCase {
            // Plain relative, so `relative` is TRUE and the whole value is
            // encoded: the space becomes %20 while `left` still holds (L152).
            // The base is cut after its last slash (L1259-L1264), its query and
            // fragment go with the cut, and `.`/`..` are resolved by the
            // re-parse.
            base: "http://example.org/a/b/c?q=1#f",
            relative: "../d e/./f/../g",
            url: "http://example.org/a/d%20e/g",
            path: "/a/d%20e/g",
            urlflags: 0,
            setflags: abi::CURLU_URLENCODE | abi::CURLU_ALLOW_SPACE,
            origin: "derived from lib/urlapi.c:1275 with relative=TRUE",
        },
        RedirCase {
            // Protocol-relative, so `host_changed` is TRUE and `relative` is
            // FALSE. `find_host_sep` stops at the first slash of
            // `us er@ex.org/p q/...`, so `us er@ex.org` is copied byte for byte
            // -- the space in the userinfo included -- and only `/p q/./x/../y`
            // is encoded. The base is cut at the start of its host (L1235-L1237),
            // so the base's own user, query and fragment all go.
            base: "http://user@example.org/a/b?q=1#f",
            relative: "//us er@ex.org/p q/./x/../y",
            url: "http://us er@ex.org/p%20q/y",
            path: "/p%20q/y",
            urlflags: 0,
            setflags: abi::CURLU_URLENCODE | abi::CURLU_ALLOW_SPACE,
            origin: "derived from lib/urlapi.c:1275 with relative=FALSE",
        },
        RedirCase {
            // The same protocol-relative value with CURLU_PATH_AS_IS added.
            // L1277 clears it before the re-parse, so the answer is identical to
            // the row above: encoding happens, and so does dot removal.
            base: "http://user@example.org/a/b?q=1#f",
            relative: "//us er@ex.org/p q/./x/../y",
            url: "http://us er@ex.org/p%20q/y",
            path: "/p%20q/y",
            urlflags: 0,
            setflags: abi::CURLU_URLENCODE | abi::CURLU_ALLOW_SPACE | abi::CURLU_PATH_AS_IS,
            origin: "derived from lib/urlapi.c:1275-1277",
        },
    ]);

    // The authority, read part by part, because that is the claim the rows above
    // cannot make on their own: a whole-URL read would show the same bytes
    // whether the space had survived the encoder or been encoded and then
    // decoded by the re-parse.
    let handle = parsed("http://user@example.org/a/b?q=1#f", 0);
    let code = set_part(
        &handle,
        abi::CURLUPART_URL,
        "//us er@ex.org/p q/./x/../y",
        abi::CURLU_URLENCODE | abi::CURLU_ALLOW_SPACE | MODE_FLAGS,
    );
    assert_eq!(code, abi::CURLUE_OK, "the protocol-relative set failed");

    let (code, user) = get_part(&handle, abi::CURLUPART_USER, 0);
    assert_eq!(code, abi::CURLUE_OK, "the resolved URL has a user");
    assert_eq!(
        user.as_deref(),
        Some("us er"),
        "the authority is copied verbatim, so the space is still a space"
    );

    let (code, host) = get_part(&handle, abi::CURLUPART_HOST, 0);
    assert_eq!(code, abi::CURLUE_OK, "and a host");
    assert_eq!(host.as_deref(), Some("ex.org"), "which came from the value");

    // The base's query went with the cut at L1235-L1237, which is the other half
    // of "the authority changed": nothing of the old authority or of what
    // followed it survives.
    let (code, query) = get_part(&handle, abi::CURLUPART_QUERY, 0);
    assert_eq!(
        code,
        abi::CURLUE_NO_QUERY,
        "the base's query does not survive a protocol-relative resolution"
    );
    assert!(query.is_none(), "and no buffer is written for it");
}

/// A path of one byte or none is not stored, and the getter reports `/` anyway.
///
/// Two independent steps, and they are worth separating because they can hide
/// each other. `handle_path` at `lib/urlapi.c` L1080-L1083 leaves the field null
/// when the remaining path is empty or is just the slash -- "there is no path
/// left or just the slash, unset". Then `curl_url_get` substitutes `/` for a
/// null path at L1604-L1607, and `urlget_url` does the same when serialising at
/// L1528. So the field really is absent internally, yet no caller can ever
/// observe a missing path: `CURLUPART_PATH` is the one part whose `ifmissing`
/// code, initialised at L1545, is unreachable.
///
/// Both inputs below take the L1080 branch, one with a zero-length remainder and
/// one with a one-byte remainder, and both come out as `/`.
#[test]
fn a_short_path_is_unset_and_still_reads_back_as_a_slash() {
    run_get_cases(&[
        GetCase {
            // Nothing after the host at all: pathlen 0, so L1080 unsets.
            input: "http://example.org",
            url: "http://example.org/",
            path: "/",
            urlflags: 0,
            origin: "derived from lib/urlapi.c:1080-1083 and 1604-1607",
        },
        GetCase {
            // Just the slash: pathlen 1, so L1080 unsets that too.
            input: "http://example.org/",
            url: "http://example.org/",
            path: "/",
            urlflags: 0,
            origin: "derived from lib/urlapi.c:1080-1083 and 1604-1607",
        },
    ]);
}

/// Paths that collapse completely, and the one that collapses to nothing at all.
///
/// `dedotdotify` has three ways to finish, and the difference between the last
/// two is observable:
///
/// * Rule C runs out of input with the output already empty, and appends a slash
///   at `lib/urlapi.c` L795. A relative `..` against `/foo/bar` takes this route
///   and lands on `/`.
/// * Rule B sees `/.` at the very end and appends a slash at L766. A relative
///   `.` keeps the directory and lands on `/foo/`.
/// * Rule A consumes a leading `./` and leaves nothing behind, jumping to `end`
///   at L736 with an empty buffer. L812-L818 then stores an *empty allocated
///   string* rather than a null pointer, which is why `file:./` at
///   `tests/libtest/lib1560.c` L778 serialises as `file://` with nothing after
///   the slashes: the file arm of `urlget_url` at L1441-L1446 prints `u->path`
///   with no `/` default of its own, and the path it prints is present but
///   empty.
///
/// That last row is the one place in this file where `CURLUPART_PATH` comes back
/// as the empty string instead of `/`. It is not a contradiction of the previous
/// test: there the field was null and the getter supplied `/`, here the field is
/// non-null and holds no bytes, so L1604-L1607 has nothing to substitute for.
#[test]
fn paths_that_collapse_entirely() {
    run_redir_cases(&[
        RedirCase {
            // Rule C with an empty output buffer, lib/urlapi.c L790-L796.
            base: "http://example.org/foo/bar",
            relative: "..",
            url: "http://example.org/",
            path: "/",
            urlflags: 0,
            setflags: 0,
            origin: "derived from lib/urlapi.c:779-796",
        },
        RedirCase {
            // Rule B's `/.` tail, lib/urlapi.c L765-L768.
            base: "http://example.org/foo/bar",
            relative: ".",
            url: "http://example.org/foo/",
            path: "/foo/",
            urlflags: 0,
            setflags: 0,
            origin: "derived from lib/urlapi.c:764-768",
        },
    ]);

    // lib1560.c L778: `file:./` -> `file://`. `parse_file` takes the path from
    // `&url[5]` (lib/urlapi.c L835-L836), so the path here is `./`; rule A
    // consumes it whole and L814-L818 stores an empty string.
    let handle = parsed("file:./", 0);
    assert_eq!(
        whole_url(&handle, 0),
        "file://",
        "CURLUPART_URL for file:./ (lib1560.c:778)"
    );
    assert_eq!(
        path_of(&handle, 0),
        "",
        "CURLUPART_PATH for file:./ is present but empty (lib/urlapi.c:814-818)"
    );
}

/// The leading-dot prologue, all four of its branches, reached from a real URL.
///
/// `dedotdotify` runs rules A and D once, before the loop, on a path whose first
/// byte is a dot -- `lib/urlapi.c` L728-L755. That prologue is *separate code*
/// from the `/./` and `/../` handling inside the loop at L757-L811, and it is
/// the only part of the function a path beginning with a slash can never reach.
/// Every path this crate sees through an `http:` URL begins with a slash,
/// because `parseurl` L1143-L1144 sets the path to what `strcspn(hostp, "/?#")`
/// stopped at and a relative value is resolved against a base first. So the
/// prologue has exactly one public door: a `file:` URL, where `parse_file`
/// L835-L836 takes the path from `&url[5]` and does not require a slash there.
///
/// The four branches, and what distinguishes each from the others:
///
/// * L734-L736, `.` alone. Consumed, nothing left, jump to `end`. Covered by
///   `file:./` in [`paths_that_collapse_entirely`] and by `file:%2e/x` below.
/// * L737-L741, `./` followed by more. The prefix goes, the remainder is the
///   path.
/// * L746-L748, `..` alone at the end. Both dots consumed, jump to `end`.
/// * L749-L753, `../` followed by more. The three bytes go, the remainder is
///   the path.
///
/// # The row that pins "once, not repeatedly"
///
/// `file:../../y` gives `../y`, not `y`. The prologue is a straight-line `if`
/// rather than a loop, so it strips the *first* `../` and the loop then copies
/// what remains verbatim -- L757's body only recognises a dot segment after a
/// slash, and `../y` starts with a dot. A port that wrapped the prologue in a
/// `while` would produce `y` here and pass every other row in this file.
///
/// # The encoded spelling is the same code
///
/// `is_dot` at L682-L697 accepts `%2e` in either case as well as a literal dot,
/// and the prologue calls it twice, so `%2e%2e/x` takes exactly the L749-L753
/// branch that `../x` takes. The rows below pair each literal form with its
/// encoded one. `only_e_and_capital_e_complete_the_encoded_dot` covers which
/// third bytes qualify; this covers where in the path they may appear.
///
/// # And one input that never gets that far
///
/// `file:.` is seven bytes -- wait, six -- and `parse_file` L830-L832 rejects
/// anything of six or fewer with `CURLUE_BAD_FILE_URL` before a path exists at
/// all. It is here so that the shortest spelling of the L734-L736 branch is not
/// silently assumed to reach it.
#[test]
fn the_leading_dot_prologue_is_reached_through_a_file_url() {
    // L749-L753 and its encoded twin: `../` at the front, something after it.
    for input in ["file:../x", "file:%2e%2e/x", "file:%2E%2E/x"] {
        let handle = parsed(input, 0);
        assert_eq!(
            path_of(&handle, 0),
            "x",
            "CURLUPART_PATH for {input:?} (lib/urlapi.c:749-753)"
        );
        // The file arm of `urlget_url` at L1441-L1446 prints `u->path` with no
        // `/` default of its own, so a path with no leading slash serialises
        // straight after the two slashes of `file://`.
        assert_eq!(
            whole_url(&handle, 0),
            "file://x",
            "CURLUPART_URL for {input:?} (lib/urlapi.c:1441-1446)"
        );
    }

    // L746-L748 and its encoded twin: `..` and nothing after it. `goto end`
    // with an empty buffer, so L812-L818 stores an allocated empty string --
    // the same outcome `file:./` reaches through L734-L736.
    for input in ["file:..", "file:%2e%2e", "file:%2E%2E"] {
        let handle = parsed(input, 0);
        assert_eq!(
            path_of(&handle, 0),
            "",
            "CURLUPART_PATH for {input:?} (lib/urlapi.c:746-748 and 812-818)"
        );
        assert_eq!(
            whole_url(&handle, 0),
            "file://",
            "CURLUPART_URL for {input:?}"
        );
    }

    // L737-L741, the single-dot-then-slash branch, in its encoded spelling. The
    // literal `file:./` is in `paths_that_collapse_entirely`; this is the same
    // branch with something left over, which that row does not have.
    let handle = parsed("file:%2e/x", 0);
    assert_eq!(
        path_of(&handle, 0),
        "x",
        "CURLUPART_PATH for file:%2e/x (lib/urlapi.c:737-741)"
    );
    assert_eq!(whole_url(&handle, 0), "file://x");

    // The prologue runs once. See the note above -- this is the row that says
    // so, and it is the reason the branch cannot be implemented as a loop.
    let handle = parsed("file:../../y", 0);
    assert_eq!(
        path_of(&handle, 0),
        "../y",
        "CURLUPART_PATH for file:../../y: the prologue strips one prefix, not all \
         of them (lib/urlapi.c:728-755)"
    );
    assert_eq!(whole_url(&handle, 0), "file://../y");

    // The prologue hands its remainder to the loop, which then does its own
    // work: `../a/../b` loses the leading `../` at L749-L753 and the inner
    // `/../` to rule C at L790-L796.
    let handle = parsed("file:../a/../b", 0);
    assert_eq!(
        path_of(&handle, 0),
        "a/b",
        "CURLUPART_PATH for file:../a/../b: prologue then rule C"
    );
    assert_eq!(whole_url(&handle, 0), "file://a/b");

    // And the length gate, which answers before any of the above.
    let handle = new_handle();
    let code = set_part(&handle, abi::CURLUPART_URL, "file:.", MODE_FLAGS);
    assert_eq!(
        code,
        abi::CURLUE_BAD_FILE_URL,
        "file: URLs of six bytes or fewer are rejected at lib/urlapi.c:830-832, \
         before a path exists to dedot"
    );
}

/// The late `set_url` rows, where dot removal has to leave the credentials in
/// place.
///
/// `tests/libtest/lib1560.c` L1364-L1375, three consecutive rows that every
/// other test in this file skips. They matter because `redirect_url` at
/// `lib/urlapi.c` L1214-L1284 does not edit the handle: it serialises the old
/// URL, splices the relative part onto the text, and re-parses the result at
/// L1277. So the user and the password survive a `../../` only if they were
/// serialised into that intermediate text and parsed back out of it, and a port
/// that resolved the path *in place* instead would drop them while producing the
/// right path.
///
/// The rows are driven the way `set_url` drives them at L1388-L1426 -- set the
/// base, set the relative value over it, read the whole URL with flags of zero
/// -- and then the parts are read as well, which the C row does not do. That is
/// the point: `http://user:foo@example.com/newpage` is what the C compares, and
/// the parts are what say *why* it is right.
#[test]
fn late_redirect_rows_keep_the_credentials_across_dot_removal() {
    // L1364-L1367, the row with no credentials, so the pair below is a
    // comparison rather than a single observation. `../../` climbs past the
    // root, which rule C at L779-L796 clamps to `/`, and the fragment comes
    // from the relative value rather than the base.
    run_redir_cases(&[
        RedirCase {
            base: "http://example.com/path?query#frag",
            relative: "../../newpage#foo",
            url: "http://example.com/newpage#foo",
            path: "/newpage",
            urlflags: 0,
            setflags: 0,
            origin: "tests/libtest/lib1560.c:1364-1367",
        },
        RedirCase {
            base: "http://user:foo@example.com/path?query#frag",
            relative: "../../newpage",
            url: "http://user:foo@example.com/newpage",
            path: "/newpage",
            urlflags: 0,
            setflags: 0,
            origin: "tests/libtest/lib1560.c:1368-1371",
        },
        RedirCase {
            base: "http://user:foo@example.com/path?query#frag",
            relative: "../newpage",
            url: "http://user:foo@example.com/newpage",
            path: "/newpage",
            urlflags: 0,
            setflags: 0,
            origin: "tests/libtest/lib1560.c:1372-1375",
        },
    ]);

    // The same two rows again, with the credentials read as parts. `../../` and
    // `../` reach the root by different routes -- two applications of rule C
    // against a one-segment path versus one -- and both must leave the user and
    // the password exactly as the base had them.
    for relative in ["../../newpage", "../newpage"] {
        let handle = parsed("http://user:foo@example.com/path?query#frag", 0);
        let code = set_part(&handle, abi::CURLUPART_URL, relative, MODE_FLAGS);
        assert_eq!(
            code,
            abi::CURLUE_OK,
            "setting {relative:?} over the credentialled base failed with {code}"
        );
        let (code, user) = get_part(&handle, abi::CURLUPART_USER, 0);
        assert_eq!(code, abi::CURLUE_OK, "the user survived {relative:?}");
        assert_eq!(user.as_deref(), Some("user"));
        let (code, password) = get_part(&handle, abi::CURLUPART_PASSWORD, 0);
        assert_eq!(code, abi::CURLUE_OK, "the password survived {relative:?}");
        assert_eq!(password.as_deref(), Some("foo"));
        // And the base's query and fragment did not, because the re-parse at
        // L1277 sees a URL the splice built without them: L1265-L1269 truncates
        // the base at its last slash after stripping any `?` or `#`.
        let (code, _) = get_part(&handle, abi::CURLUPART_QUERY, 0);
        assert_eq!(
            code,
            abi::CURLUE_NO_QUERY,
            "the base's query did not survive {relative:?}"
        );
        let (code, _) = get_part(&handle, abi::CURLUPART_FRAGMENT, 0);
        assert_eq!(
            code,
            abi::CURLUE_NO_FRAGMENT,
            "the base's fragment did not survive {relative:?}"
        );
    }
}
