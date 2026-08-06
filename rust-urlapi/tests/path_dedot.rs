// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Dot-segment removal and the path stage, driven through the C surface.
//!
//! The behavioural authority for every expectation in this file is
//! `lib/urlapi.c`; the vectors come from `tests/libtest/lib1560.c`. Both are
//! read-only references and neither is edited. Every assertion below carries a
//! comment naming the line of `lib/urlapi.c` that produces it, or the row of
//! `tests/libtest/lib1560.c` it is ported from. An expectation without such a
//! citation would be a guess, and a guess that happened to match the port
//! would prove nothing.
//!
//! # What this file tests, and what it deliberately does not
//!
//! Three C functions do the work: `is_dot` at `lib/urlapi.c` L682-L697,
//! `dedotdotify` at L716-L821, and `handle_path` at L1066-L1108, with
//! `redirect_url` at L1214-L1284 feeding the last of them on the relative-URL
//! path. None of the three is reachable from here, and that is intentional
//! twice over.
//!
//! * `src/lib.rs` L376-L390 exports only `abi` and `ffi`; `parse` and
//!   everything beneath it is crate-private. There is no path from an
//!   integration test to `parse::path`.
//! * `dedotdotify` carries the `UNITTEST` marker at `lib/urlapi.c` L715-L716,
//!   so even the C exports it only in unit-test builds. It is not one of the
//!   eight symbols the drop-in replacement must define, and widening the crate's
//!   exported surface to reach it from a test would break the "no new API
//!   surface" constraint the port is built under.
//!
//! So every case here goes through the public API: `curl_url()`, then
//! `curl_url_set(CURLUPART_URL, ...)`, then `curl_url_get(CURLUPART_URL, ...)`
//! and `curl_url_get(CURLUPART_PATH, ...)`, then `curl_url_cleanup()`. That is
//! also how `tests/libtest/lib1560.c` itself reaches this code -- see its
//! `set_url` driver at L1388-L1426 and its `get_url` driver at L1541-L1577 --
//! so the coverage is expressed exactly as the authoritative oracle expresses
//! it.
//!
//! # How the C entry points are reached
//!
//! Not by a Rust path. `src/ffi.rs` places all ten exported functions in a
//! `pub(crate) mod exports`, which `src/lib.rs` documents as deliberate: every
//! item that file declares is crate-private and they "reach the symbol table
//! purely by attribute". `curl_urlapi_rs::ffi` is therefore an empty module
//! from outside the crate, and naming `ffi::curl_url` here would not compile.
//!
//! This file declares the four entry points it needs in its own `extern "C"`
//! block instead, mirroring `include/curl/urlapi.h` L113-L142, and lets the
//! linker resolve them against the `#[no_mangle]` definitions in the `rlib`.
//! That is strictly closer to the thing being validated: it is the same view a
//! C consumer of the drop-in archive gets, so a mangled, missing or
//! wrongly-typed export fails this file at link time rather than passing it on
//! a Rust-internal path no C caller could use.
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
//! # Testing posture
//!
//! These cases supplement the two authoritative oracles -- `lib1560.c` run
//! unmodified through `rust-urlapi/harness/`, and the byte-for-byte demo diff
//! -- and never substitute for them. No assertion here may be weakened to make
//! something pass: if a case fails, the port is wrong and `src/parse/path.rs`
//! or `src/parse/redirect.rs` is what needs fixing.
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

// ---------------------------------------------------------------------------
// The C surface
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Feature-configuration plumbing
// ---------------------------------------------------------------------------

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
// equivalence is not merely argued: the two configurations were run side by
// side and produced identical output for all of the cases below.

/// Flags every vector adds to its own, to keep one set of expectations valid in
/// both feature configurations. See the block comment above.
#[cfg(feature = "scheme-table")]
const MODE_FLAGS: c_uint = 0;

/// Flags every vector adds to its own, to keep one set of expectations valid in
/// both feature configurations. See the block comment above.
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
/// pointer, honouring L46. `None` means no buffer was produced, which is what
/// `lib/urlapi.c` L1552 guarantees for every failing code.
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
    if content.is_null() {
        return (code, None);
    }
    // SAFETY: `content` is non-null and, per the contract at
    // `include/curl/urlapi.h` L130-L131, points at a NUL-terminated buffer this
    // caller now owns. `CStr::from_ptr` only reads up to that terminator, and
    // the bytes are copied before the buffer is released on the next line.
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

// ---------------------------------------------------------------------------
// Vector tables
// ---------------------------------------------------------------------------

/// One row of a parse-then-read case, modelled on `struct urltestcase` at
/// `tests/libtest/lib1560.c` L125-L131.
///
/// The C row carries `in`, `out`, `urlflags`, `getflags` and an expected code.
/// This one drops the code, because [`run_get_cases`] only drives rows that
/// succeed, and adds `path` so a failure localises to the path stage instead of
/// only to serialisation.
struct GetCase {
    /// The URL handed to `curl_url_set(CURLUPART_URL, ...)`.
    input: &'static str,
    /// What `curl_url_get(CURLUPART_URL, ...)` must return.
    url: &'static str,
    /// What `curl_url_get(CURLUPART_PATH, ...)` must return.
    path: &'static str,
    /// Flags for the set, before [`MODE_FLAGS`] is added.
    urlflags: c_uint,
    /// Where the row comes from, quoted in the failure message.
    origin: &'static str,
}

/// One row of a base-then-relative case, modelled on `struct redircase` at
/// `tests/libtest/lib1560.c` L88-L95, with the same added `path` column as
/// [`GetCase`].
struct RedirCase {
    /// The base URL, set first.
    base: &'static str,
    /// The value then handed to `curl_url_set(CURLUPART_URL, ...)`.
    relative: &'static str,
    /// What `curl_url_get(CURLUPART_URL, ..., 0)` must then return.
    url: &'static str,
    /// What `curl_url_get(CURLUPART_PATH, ..., 0)` must then return.
    path: &'static str,
    /// Flags for the base set, before [`MODE_FLAGS`] is added.
    urlflags: c_uint,
    /// Flags for the relative set, before [`MODE_FLAGS`] is added.
    setflags: c_uint,
    /// Where the row comes from, quoted in the failure message.
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

// ---------------------------------------------------------------------------
// CURLU_PATH_AS_IS: the on/off pair
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// The percent-encoded dot
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// The rest of the dot-removal rows from set_url_list
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Behaviours no row of the C table isolates
// ---------------------------------------------------------------------------

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
