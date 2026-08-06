// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Percent-encoding and percent-decoding parity tests for `curl-urlapi-rs`.
//!
//! `AAP` 0.2.1.4 lists this file and 0.4.1.5 states its job: port selected
//! encoder and decoder table cases from `tests/libtest/lib1560.c` to Rust. The
//! behavioural authority is `lib/urlapi.c` itself, and every expectation below
//! carries the line of C it came from. An expectation with no citation would be
//! a guess.
//!
//! Two things about the expectations are worth stating before the first test.
//!
//! They were not read off the C by eye. Each one was produced by a C program
//! linked against a libcurl built from the unmodified tree, printing every byte
//! of every answer, and then compared against this crate's answer for the same
//! input. So a failure here means the port diverged from the reference, which is
//! the only thing this file is for. Per `AAP` 0.9, these tests *supplement* the
//! two authoritative oracles -- `tests/libtest/lib1560.c` run unmodified
//! through `rust-urlapi/harness/`, and the byte-for-byte demo diff -- and no
//! assertion here should be weakened to make something pass. If one fails, the
//! encoder or the decoder is wrong, not the test.
//!
//! And they are all written as byte strings. `AAP` 0.7.2 holds new files to the
//! repository's own gates, and `scripts/spacecheck.pl` L173-L196 rejects both
//! literal control bytes and non-ASCII bytes in any tracked file, so a vector
//! containing byte `0x02` or byte `0xFF` cannot be spelled literally. It cannot
//! be spelled as a `str` escape either: Rust rejects `"\xff"` in a `str`
//! literal outright, and `"\u{ff}"` is the *character* U+00FF, which encodes as
//! the two bytes `0xC3 0xBF` and is therefore a different input entirely. That
//! substitution silently turns `%FF` into `%C3%BF`. Byte strings -- `b"...\xff"`
//! -- are exact, stay pure ASCII in the source, and are what every helper here
//! takes.
//!
//! # How the crate is reached
//!
//! Through the C ABI, with the four entry points declared in the `extern` block
//! below rather than called as Rust paths.
//!
//! That is not a stylistic choice. `src/lib.rs` L376-L390 makes `abi` and `ffi`
//! public and keeps the other thirteen modules crate-private, so `encode` and
//! `decode` cannot be called from here at all -- an integration test is a
//! separate crate. `src/ffi.rs` L2561 then declares the exported functions
//! inside `pub(crate) mod exports`, and nothing re-exports them, so
//! `curl_urlapi_rs::ffi::exports::curl_url` is a privacy error too. What makes
//! the functions reachable is the attribute, not the module tree:
//! `src/ffi.rs` L2482-L2496 spells this out, that `#[no_mangle]` puts the
//! symbol in the table under the name C asks for and that `pub` contributes
//! nothing to the symbol table either way. Declaring the four symbols here
//! creates the undefined references that pull them out of the `rlib`, and it
//! exercises exactly the surface a C caller sees: raw pointers, integer codes,
//! and no Rust types in between.
//!
//! # Who owns the returned buffers
//!
//! `docs/libcurl/curl_url_get.md` L45 obliges the caller to release the
//! returned content pointer with `curl_free`, and L46 forbids altering the
//! string it points at. Both obligations are met in one place, [`Url::get`],
//! which copies the bytes out and releases the block immediately, so no
//! returned pointer outlives the call that produced it and none is ever written
//! through.
//!
//! The release call is `libc::free`, deliberately, and it is correct for a
//! reason rather than by luck: `src/alloc.rs` is the crate's only producer of
//! C-visible memory and it allocates every one of those buffers with the C
//! allocator, which is the whole point of `AAP` 0.6.4. `libc::free` also needs
//! no feature gate, whereas `ffi::curl_free` exists only under the `cfree`
//! feature and is absent from the drop-in configuration -- see the feature note
//! below.
//!
//! # Feature configurations
//!
//! `Cargo.toml` declares six features and two configurations are validated:
//! the defaults, and `--no-default-features --features idn-libidn2`, which is
//! the drop-in one. This file compiles and passes under both, which takes three
//! deliberate accommodations.
//!
//! It never names `ffi::curl_url_strerror` (feature `strerror`) or
//! `ffi::curl_free` (feature `cfree`); [`shown`] renders a code as a number and
//! `libc::free` releases the buffers.
//!
//! It supplies `Curl_get_scheme` and `Curl_getn_scheme` itself when
//! `scheme-table` is off. That accommodation is the interesting one and
//! [`libcurl_scheme_shim`] documents why it is needed and why it is honest.
//!
//! And every assertion that depends on internationalised-domain support is
//! gated on the backend that would perform it, because the three backends give
//! three different answers and `AAP` 0.6.3 records all three. The tests at the
//! end of this file take each in turn.

use core::ffi::{c_char, c_uint, c_void, CStr};
use core::ptr;

use curl_urlapi_rs::abi;

// The C-linkage surface under test.
//
// Four of the eight symbols `src/ffi.rs` exports, declared with the exact
// signatures that file gives them and that `include/curl/urlapi.h` L113-L141
// declares:
//
// - `curl_url` L113, `lib/urlapi.c` L1288-L1291.
// - `curl_url_cleanup` L120, `lib/urlapi.c` L1293-L1299.
// - `curl_url_set` L141, `lib/urlapi.c` L1805.
// - `curl_url_get` L133, `lib/urlapi.c` L1541.
//
// `curl_url_get` takes the handle as `*const` and the destination as
// `*mut *mut c_char`, matching `const CURLU *` and `char **`. The constness is
// load-bearing rather than decorative: the crate never forms a unique reference
// to the handle on this path, so a caller may legitimately hold other pointers
// to it across the call.
extern "C" {
    fn curl_url() -> *mut c_void;
    fn curl_url_cleanup(handle: *mut c_void);
    fn curl_url_set(
        handle: *mut c_void,
        what: abi::CURLUPart,
        part: *const c_char,
        flags: c_uint,
    ) -> abi::CURLUcode;
    fn curl_url_get(
        handle: *const c_void,
        what: abi::CURLUPart,
        part: *mut *mut c_char,
        flags: c_uint,
    ) -> abi::CURLUcode;
}

/// libcurl's scheme lookup, supplied for the drop-in configuration only.
///
/// # Why this module has to exist
///
/// With `scheme-table` off the crate does not compile a table; it imports
/// libcurl's own lookup. `src/scheme.rs` L1310-L1327 states that this is
/// deliberate and that the archive must show the symbol as *undefined*, or the
/// drop-in link acquires a duplicate of something `lib/url.c` already defines.
/// The consequence lands here: a `cargo test` in that configuration links no
/// libcurl at all, so every integration test binary fails with
///
/// ```text
/// undefined symbol: Curl_get_scheme   (referenced by src/ffi.rs:1992)
/// undefined symbol: Curl_getn_scheme  (referenced by src/ffi.rs:2017)
/// ```
///
/// regardless of what the test file contains. The two ways out are to compile
/// this file away under `#![cfg(feature = "scheme-table")]`, which would mean
/// the drop-in configuration is never exercised at all, or to supply the two
/// symbols the way the real link supplies them. This module does the second.
/// It is the same accommodation `harness/shims.c` makes for the `curl_mprintf`
/// family in the standalone link, and it never reaches the shipped archive: it
/// is compiled into a test binary and nowhere else.
///
/// # What it has to get right
///
/// The layout, and only the layout. `src/ffi.rs` L1886-L1909 mirrors
/// `struct Curl_scheme` from `lib/urldata.h` L515-L524 and reads three of its
/// six fields through the returned pointer, so the offsets are the entire
/// contract; L1904-L1943 in that file explain that a wrong integer width here
/// does not fail to compile, it silently returns one field's bytes as another's.
/// [`CurlScheme`] therefore repeats that shape field for field.
///
/// The lookup itself follows `lib/url.c` L1477-L1540: names of one to seven
/// bytes only, compared case-insensitively, null for anything else. The table
/// holds `http` and `https` because those are the only schemes any vector in
/// this file uses -- `AAP` 0.6.7 lists all twenty-five default ports, and
/// reproducing them here would duplicate `src/scheme.rs`'s table to no purpose,
/// since the default configuration tests against that table directly.
#[cfg(not(feature = "scheme-table"))]
mod libcurl_scheme_shim {
    use core::ffi::{c_char, c_void, CStr};
    use core::{ptr, slice};

    /// `struct Curl_scheme`, `lib/urldata.h` L515-L524.
    ///
    /// Field for field as `src/ffi.rs` L1886-L1909 describes it: two pointers,
    /// two 32-bit protocol words, the flag word, and the 16-bit default port.
    /// `protocol` and `family` are never read by anything -- neither by the
    /// crate nor here -- and they are present precisely because the two fields
    /// that *are* read sit after them and cannot be located otherwise.
    #[allow(dead_code)]
    #[repr(C)]
    pub(super) struct CurlScheme {
        /// L516. Never read: this shim compares the caller's bytes itself, and
        /// the crate looks at the three fields below and nothing else.
        name: *const c_char,
        /// L517, the implementation pointer. Read only for null-ness, which is
        /// how a disabled protocol is detected at `lib/urlapi.c` L1646.
        run: *const c_void,
        /// L518-L519, `curl_prot_t`, 32 bits while `PROTO_TYPE_SMALL` is
        /// defined. Never read; its width positions everything after it.
        protocol: u32,
        /// L520-L521, `curl_prot_t`. Never read, same caveat.
        family: u32,
        /// L522, the `PROTOPT_*` bits. Read for `PROTOPT_URLOPTIONS`. Neither
        /// scheme here carries it -- `AAP` 0.6.7 records that only the six mail
        /// and message-retrieval schemes do.
        flags: u32,
        /// L523, the default port.
        defport: u16,
    }

    // SAFETY: every field is immutable for the whole program and the two
    // pointer fields address `'static` data -- a NUL-terminated literal and a
    // marker byte. Nothing writes through either, and no interior mutability is
    // reachable, so sharing a `&'static CurlScheme` across threads exposes
    // nothing that is not already read-only. The impl is needed only because a
    // raw pointer is not `Sync` by default.
    unsafe impl Sync for CurlScheme {}

    /// A non-null stand-in for `const struct Curl_protocol *`.
    ///
    /// `lib/urlapi.c` L1646 tests the `run` field for null to decide whether a
    /// protocol is disabled, and never dereferences it. A single byte is
    /// therefore a complete stand-in: it gives the field a non-null value, so
    /// both schemes below report as implemented, which is what a libcurl built
    /// with HTTP and HTTPS enabled reports.
    static PROTOCOL_MARKER: u8 = 0;

    /// `Curl_scheme_http`, default port 80 per `lib/urldata.h` L33.
    static HTTP: CurlScheme = CurlScheme {
        name: b"http\0".as_ptr().cast::<c_char>(),
        run: &PROTOCOL_MARKER as *const u8 as *const c_void,
        protocol: 0,
        family: 0,
        flags: 0,
        defport: 80,
    };

    /// `Curl_scheme_https`, default port 443 per `lib/urldata.h` L34.
    static HTTPS: CurlScheme = CurlScheme {
        name: b"https\0".as_ptr().cast::<c_char>(),
        run: &PROTOCOL_MARKER as *const u8 as *const c_void,
        protocol: 0,
        family: 0,
        flags: 0,
        defport: 443,
    };

    /// The name-to-descriptor table this shim searches.
    ///
    /// A list rather than the perfect hash `lib/url.c` L1488-L1522 builds: the
    /// hash is a size optimisation over sixty-seven slots and reproducing it
    /// for two entries would obscure the only property that matters, which is
    /// which names resolve and to what.
    static TABLE: [(&[u8], &CurlScheme); 2] = [(b"http", &HTTP), (b"https", &HTTPS)];

    /// The shared body of both entry points.
    ///
    /// `lib/url.c` L1524 bounds the name to one through seven bytes before
    /// touching the table, and L1537 compares case-insensitively through
    /// `curl_strnequal`. Both are reproduced, because the parser reaches this
    /// lookup with a scheme it has already lower-cased and the setter reaches
    /// it with whatever the caller passed.
    fn lookup(name: &[u8]) -> *const CurlScheme {
        if name.is_empty() || name.len() > 7 {
            return ptr::null();
        }
        for (candidate, scheme) in TABLE {
            if candidate.eq_ignore_ascii_case(name) {
                return scheme as *const CurlScheme;
            }
        }
        ptr::null()
    }

    /// `Curl_get_scheme`, `lib/url.c` L1469-L1472: `strlen` and forward.
    ///
    /// # Safety
    ///
    /// `scheme` must be non-null and point at a NUL-terminated byte string that
    /// stays readable and unmodified for the duration of the call. That is what
    /// `src/ffi.rs` L1984-L1994 promises when it calls this through a `&CStr`.
    #[no_mangle]
    #[allow(non_snake_case)]
    pub unsafe extern "C" fn Curl_get_scheme(scheme: *const c_char) -> *const CurlScheme {
        if scheme.is_null() {
            return ptr::null();
        }
        // SAFETY: the caller's precondition is exactly `CStr::from_ptr`'s -- a
        // non-null pointer to NUL-terminated bytes that outlive the call. The
        // borrow ends with this statement, before anything else runs.
        let name = unsafe { CStr::from_ptr(scheme) }.to_bytes();
        lookup(name)
    }

    /// `Curl_getn_scheme`, `lib/url.c` L1477-L1540, the length-delimited form.
    ///
    /// # Safety
    ///
    /// `scheme` must point at `len` readable, initialised bytes that stay valid
    /// and unmodified for the duration of the call, or `len` must be zero. No
    /// terminator is needed, which is the reason this entry point exists;
    /// `src/ffi.rs` L2006-L2018 satisfies it from a non-empty slice.
    #[no_mangle]
    #[allow(non_snake_case)]
    pub unsafe extern "C" fn Curl_getn_scheme(
        scheme: *const c_char,
        len: libc::size_t,
    ) -> *const CurlScheme {
        if scheme.is_null() || len == 0 {
            return ptr::null();
        }
        // SAFETY: by the caller's precondition `scheme` addresses `len`
        // readable, initialised bytes for the whole call. `u8` and `c_char`
        // share size and alignment, so the cast changes only the sign ascribed
        // to those bytes, and the comparison below is total over all of them.
        let name = unsafe { slice::from_raw_parts(scheme.cast::<u8>(), len) };
        lookup(name)
    }
}

// The part identifiers and flag bits this file uses, imported by name from
// `src/abi.rs` -- never by glob, per `AAP` 0.4.3 -- and given short local names
// so that a vector table reads as a table. The values are
// `include/curl/urlapi.h` L70-L105 and `src/abi.rs` restates them as explicit
// integers; `tests/abi_constants.rs` is what proves those integers, so nothing
// here re-checks them.
const URL: abi::CURLUPart = abi::CURLUPART_URL;
const SCHEME: abi::CURLUPart = abi::CURLUPART_SCHEME;
const USER: abi::CURLUPart = abi::CURLUPART_USER;
const HOST: abi::CURLUPart = abi::CURLUPART_HOST;
const PORT: abi::CURLUPart = abi::CURLUPART_PORT;
const PATH: abi::CURLUPart = abi::CURLUPART_PATH;
const QUERY: abi::CURLUPart = abi::CURLUPART_QUERY;
const FRAGMENT: abi::CURLUPart = abi::CURLUPART_FRAGMENT;

const NONE: c_uint = 0;
const ENCODE: c_uint = abi::CURLU_URLENCODE;
const DECODE: c_uint = abi::CURLU_URLDECODE;
const APPEND: c_uint = abi::CURLU_APPENDQUERY;
const SPACE: c_uint = abi::CURLU_ALLOW_SPACE;
const NON_SUPPORT: c_uint = abi::CURLU_NON_SUPPORT_SCHEME;

/// Renders arbitrary bytes as printable ASCII for an assertion message.
///
/// Every byte outside the printable range becomes `\xNN`, so a failure reports
/// what actually came back rather than whatever a terminal makes of it. This is
/// also the reason no assertion message here mentions `curl_url_strerror`: that
/// symbol exists only under the `strerror` feature and this file must build
/// without it, so a code is reported as the number `src/abi.rs` gives it.
fn shown(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out
}

/// Compares two byte strings and reports both, escaped, on a mismatch.
fn same(context: &str, got: &[u8], want: &[u8]) {
    assert!(
        got == want,
        "{context}\n     got: \"{}\"\n  wanted: \"{}\"",
        shown(got),
        shown(want)
    );
}

/// A `CURLU *` that cleans itself up.
///
/// The handle is opaque -- `include/curl/urlapi.h` L107 makes `CURLU` an
/// incomplete type -- so `*mut c_void` is the whole of what a caller may know
/// about it, and `Drop` covers the `curl_url_cleanup` that
/// `include/curl/urlapi.h` L120 requires even when an assertion unwinds out of
/// a test.
struct Url(*mut c_void);

impl Url {
    /// `curl_url()`, `lib/urlapi.c` L1288-L1291.
    fn new() -> Url {
        // SAFETY: `curl_url` takes no argument and has no precondition. It
        // returns either null, on allocation failure, or a fresh handle this
        // value now owns.
        let handle = unsafe { curl_url() };
        assert!(!handle.is_null(), "curl_url() returned NULL");
        Url(handle)
    }

    /// A handle with `part` already assigned, asserting that it took.
    ///
    /// The two-step that most tests here start from: parse an input, then
    /// interrogate or amend it.
    fn parsed(input: &[u8], flags: c_uint) -> Url {
        let url = Url::new();
        let code = url.set(URL, input, flags);
        assert_eq!(
            code,
            abi::CURLUE_OK,
            "set URL \"{}\" flags {flags:#x} returned {code}",
            shown(input)
        );
        url
    }

    /// `curl_url_set()`, `lib/urlapi.c` L1805, returning the code.
    ///
    /// Takes the value as bytes rather than as `&str` so that a vector can hold
    /// any byte the C table held; see the note on byte strings at the top of
    /// this file.
    fn set(&self, what: abi::CURLUPart, value: &[u8], flags: c_uint) -> abi::CURLUcode {
        assert!(
            !value.contains(&0),
            "an embedded NUL cannot reach a C string API: \"{}\"",
            shown(value)
        );
        let mut terminated = Vec::with_capacity(value.len() + 1);
        terminated.extend_from_slice(value);
        terminated.push(0);
        // SAFETY: the handle is non-null and live for as long as `self`, and
        // nothing else touches it during the call. `terminated` is a
        // NUL-terminated buffer that outlives the call and is not aliased, which
        // is what `const char *` asks for; `curl_url_set` copies whatever it
        // keeps and retains no pointer into it.
        unsafe { curl_url_set(self.0, what, terminated.as_ptr().cast::<c_char>(), flags) }
    }

    /// [`Url::set`], asserting success.
    fn set_ok(&self, what: abi::CURLUPart, value: &[u8], flags: c_uint) {
        let code = self.set(what, value, flags);
        assert_eq!(
            code,
            abi::CURLUE_OK,
            "set part {what} to \"{}\" flags {flags:#x} returned {code}",
            shown(value)
        );
    }

    /// `curl_url_get()`, `lib/urlapi.c` L1541.
    ///
    /// Returns the code together with an owned copy of the bytes, and releases
    /// the buffer before returning. `docs/libcurl/curl_url_get.md` L45 makes
    /// releasing it the caller's obligation and L46 forbids altering it: the
    /// copy is read-only and the block is freed exactly once, here, so no
    /// pointer this function received can be used again by anyone.
    ///
    /// `libc::free` is the right release call because `src/alloc.rs` is the
    /// crate's only producer of C-visible memory and takes every one of these
    /// blocks from the C allocator. It is also the only release call available
    /// in both feature configurations, since `ffi::curl_free` is gated on
    /// `cfree`.
    fn get(&self, what: abi::CURLUPart, flags: c_uint) -> (abi::CURLUcode, Option<Vec<u8>>) {
        let mut part: *mut c_char = ptr::null_mut();
        // SAFETY: the handle is non-null and live, and this call takes it as
        // `*const`, so no unique reference to it is formed and holding `self`
        // across the call is sound. `part` is a live, writable, properly
        // aligned local that nothing else aliases.
        let code = unsafe { curl_url_get(self.0.cast_const(), what, &mut part, flags) };
        if part.is_null() {
            return (code, None);
        }
        // SAFETY: `part` is non-null and, since the call reported through it,
        // addresses a NUL-terminated buffer this thread now owns. `to_bytes`
        // copies nothing, so the `Vec` is built before the block is released and
        // the borrow has ended by the time `free` runs.
        let bytes = unsafe { CStr::from_ptr(part) }.to_bytes().to_vec();
        // SAFETY: the block came from the C allocator by way of
        // `src/alloc.rs`, this is its first and only release, and no reference
        // into it survives the statement above.
        unsafe { libc::free(part.cast::<c_void>()) };
        (code, Some(bytes))
    }

    /// [`Url::get`], asserting success and yielding the bytes.
    fn text(&self, what: abi::CURLUPart, flags: c_uint) -> Vec<u8> {
        let (code, part) = self.get(what, flags);
        assert_eq!(
            code,
            abi::CURLUE_OK,
            "get part {what} flags {flags:#x} returned {code}"
        );
        part.unwrap_or_else(|| panic!("get part {what} flags {flags:#x} reported OK with NULL"))
    }

    /// [`Url::get`], asserting failure and yielding the code.
    ///
    /// The buffer is asserted to be null as well, because `lib/urlapi.c` L1552
    /// clears the caller's pointer before anything can fail and no failing path
    /// writes it afterwards.
    fn failing(&self, what: abi::CURLUPart, flags: c_uint) -> abi::CURLUcode {
        let (code, part) = self.get(what, flags);
        assert_ne!(
            code,
            abi::CURLUE_OK,
            "get part {what} flags {flags:#x} was expected to fail"
        );
        assert!(
            part.is_none(),
            "get part {what} failed with {code} but still wrote a buffer"
        );
        code
    }
}

impl Drop for Url {
    fn drop(&mut self) {
        // SAFETY: the handle came from `curl_url()`, has not been cleaned up --
        // nothing else in this file calls `curl_url_cleanup` -- and is being
        // consumed here for the last time, with no other pointer to it in use.
        unsafe { curl_url_cleanup(self.0) };
    }
}

// ---------------------------------------------------------------------------
// Assignment-side encoding: the append_list table
// ---------------------------------------------------------------------------

/// One row of the `append_list` table.
///
/// The input URL, the query value to append, the expected whole URL, and the
/// query flags -- four of the six members of `struct querycase` at
/// `tests/libtest/lib1560.c` L133-L140. The remaining two are constant across
/// every row this file ports: `urlflags` is zero and `ucode` is `CURLUE_OK`, so
/// carrying them would add two columns of noise. The alias exists because the
/// tuple type is unreadable written out, which is what `clippy::type_complexity`
/// objects to, and because the C members have names worth keeping in view.
type AppendCase = (&'static [u8], &'static [u8], &'static [u8], c_uint);

/// `append_list`, `tests/libtest/lib1560.c` L1613-L1629, ported row for row.
///
/// Driven exactly as `append()` at L1631-L1677 drives it: assign the whole URL
/// with the row's URL flags, assign the query with the row's query flags plus
/// `CURLU_APPENDQUERY`, then read the whole URL back with no flags and compare.
/// Every row is load-bearing and the comment beside each says what it proves.
///
/// One property is common to all seven and worth naming once: the input scheme
/// is written `HTTP://` and every expectation reads `http://`, because the
/// parser lower-cases the scheme through `Curl_strntolower` on the way in.
#[test]
fn append_query_table_from_lib1560() {
    let table: [AppendCase; 7] = [
        // A byte below the space becomes an escape: `lib/urlapi.c` L1907-L1910
        // takes the else branch for it and `Curl_hexbyte`, `lib/escape.c` L222,
        // writes the two digits. The 0x02 is a `\x02` escape here rather than a
        // literal byte, which `scripts/spacecheck.pl` L173 would reject.
        (
            b"HTTP://test/?s",
            b"name=joe\x02",
            b"http://test/?s&name=joe%02",
            ENCODE,
        ),
        // Only the FIRST `=` is exempt. `equalsencode` is set from `appendquery`
        // at L1863, tested at L1899, and cleared at L1900-L1902 the first time an
        // `=` is passed through, so the second one falls to the escape branch.
        // The digits are upper-case because `Curl_hexbyte` emits upper-case;
        // asserting `%3d` here would be the single easiest mistake to make.
        (
            b"HTTP://test/?size=2#f",
            b"name=joe=",
            b"http://test/?size=2&name=joe%3D#f",
            ENCODE,
        ),
        // A space becomes `+`, not `%20`, because `plusencode` is set from
        // `urlencode` for the query part at L1861 and tested at L1892.
        (
            b"HTTP://test/?size=2#f",
            b"name=joe doe",
            b"http://test/?size=2&name=joe+doe#f",
            ENCODE,
        ),
        // No existing query, so no separator: `querylen` is zero at L1939 and
        // the whole append block at L1941 is skipped.
        (b"HTTP://test/", b"name=joe", b"http://test/?name=joe", NONE),
        // An existing query that does not end in `&` gets one, L1940.
        (
            b"HTTP://test/?size=2",
            b"name=joe",
            b"http://test/?size=2&name=joe",
            NONE,
        ),
        // An existing query that already ends in `&` does NOT get a second one:
        // `addamperand` at L1940 is false. This is the row that proves the
        // separator is not doubled.
        (
            b"HTTP://test/?size=2&",
            b"name=joe",
            b"http://test/?size=2&name=joe",
            NONE,
        ),
        // The fragment survives the append, because appending rewrites only the
        // query and the serialisation at L1517-L1532 re-emits the rest.
        (
            b"HTTP://test/?size=2#f",
            b"name=joe",
            b"http://test/?size=2&name=joe#f",
            NONE,
        ),
    ];

    for (input, query, want, query_flags) in table {
        let url = Url::parsed(input, NONE);
        url.set_ok(QUERY, query, query_flags | APPEND);
        same(
            &format!(
                "append \"{}\" (flags {query_flags:#x}) to \"{}\"",
                shown(query),
                shown(input)
            ),
            &url.text(URL, NONE),
            want,
        );
    }
}

/// The first-`=` exemption applies once, not once per assignment.
///
/// `lib/urlapi.c` L1900-L1902 clears `equalsencode` inside the loop, so a value
/// carrying several `=` keeps the first and escapes the rest. Row two of
/// [`append_query_table_from_lib1560`] shows one escaped `=`; this shows that
/// the exemption does not somehow reset.
#[test]
fn append_query_exempts_only_the_first_equals() {
    let url = Url::parsed(b"https://x/", NONE);
    url.set_ok(QUERY, b"a=b=c=d", ENCODE | APPEND);
    same(
        "three equals signs, one exempt",
        &url.text(QUERY, NONE),
        b"a=b%3Dc%3Dd",
    );
}

/// Without `CURLU_APPENDQUERY` there is no exemption at all.
///
/// `equalsencode` comes from `appendquery` at L1863 and nothing else sets it, so
/// a plain query assignment escapes every `=`. The same assignment on the path
/// keeps them, because `allowed_in_path` at L1795-L1796 lists `=` -- which is
/// the point of [`set_path_allows_eighteen_extra_bytes`].
#[test]
fn set_query_without_append_escapes_every_equals() {
    let url = Url::parsed(b"https://x/", NONE);
    url.set_ok(QUERY, b"a=b", ENCODE);
    same(
        "no append, so no exemption",
        &url.text(QUERY, NONE),
        b"a%3Db",
    );
}

/// The separator rules at `lib/urlapi.c` L1935-L1962, each in isolation.
#[test]
fn append_query_separator_is_added_only_when_needed() {
    // An empty-but-present query: `https://x/?` parses with `query_present` set
    // and the query itself empty, so `querylen` is zero at L1939 and no
    // separator appears.
    let url = Url::parsed(b"https://x/?", NONE);
    url.set_ok(QUERY, b"a=b", APPEND);
    same("append onto an empty query", &url.text(QUERY, NONE), b"a=b");
    same(
        "and the whole URL keeps its single delimiter",
        &url.text(URL, NONE),
        b"https://x/?a=b",
    );

    // A trailing `&` suppresses the separator however many there are: L1940
    // looks at the last byte only.
    let url = Url::parsed(b"https://x/?a=1&&", NONE);
    url.set_ok(QUERY, b"b=2", APPEND);
    same(
        "a doubled trailing ampersand is left as it was",
        &url.text(QUERY, NONE),
        b"a=1&&b=2",
    );
}

/// Appending without `CURLU_URLENCODE` stores the value as given.
///
/// The encoder at L1887-L1913 is not entered, so the space is neither `%20` nor
/// `+` -- it stays a space, and the whole URL carries it. The only transformation
/// the else branch at L1915-L1932 performs is the case fold that
/// [`set_without_encode_folds_existing_escapes_to_lower_case`] covers.
#[test]
fn append_query_without_encode_keeps_the_space() {
    let url = Url::parsed(b"https://x/", NONE);
    url.set_ok(QUERY, b"name=joe doe", APPEND);
    same(
        "a space survives an unencoded append",
        &url.text(QUERY, NONE),
        b"name=joe doe",
    );
    same(
        "and reaches the serialised URL",
        &url.text(URL, NONE),
        b"https://x/?name=joe doe",
    );
}

// ---------------------------------------------------------------------------
// Retrieval-side encoding: the space rule and the `left` state
// ---------------------------------------------------------------------------

/// A space becomes `%20` before the query delimiter and `+` after it.
///
/// `urlencode_str`, `lib/urlapi.c` L130-L170, keeps a `left` state initialised
/// at L135 to the negation of "this is the query part". While `left` holds, a
/// space becomes `%20` (L152-L153); once it is cleared, a space becomes `+`
/// (L154-L155); and encountering a `?` in the input clears it (L164-L165).
///
/// `AAP` 0.6.2 makes the point that follows and it is easy to get wrong: the
/// plus rule applies to everything *after the query delimiter*, not to "a part
/// named query". The `left` flip is a property of the bytes being encoded, so
/// the part identifier only decides the initial value. The fragment case at the
/// end of this test is that distinction made visible.
#[test]
fn get_encode_space_depends_on_the_query_delimiter() {
    // `tests/libtest/lib1560.c` L171-L173: two trailing spaces in the fragment,
    // encoded at parse time because the URL flags carry CURLU_URLENCODE.
    let url = Url::parsed(b"https://curl.se/#  ", ENCODE | SPACE);
    same(
        "two spaces in a fragment, encoded at parse time",
        &url.text(FRAGMENT, NONE),
        b"%20%20",
    );
    same(
        "and they are already escaped in the stored URL",
        &url.text(URL, NONE),
        b"https://curl.se/#%20%20",
    );

    // `tests/libtest/lib1560.c` L192-L194, the same flags over a URL with a
    // user, a query and a spaced fragment.
    let url = Url::parsed(b"https://user@example.net?hello# space ", SPACE | ENCODE);
    same("the user is untouched", &url.text(USER, NONE), b"user");
    same("the query is untouched", &url.text(QUERY, NONE), b"hello");
    same(
        "the fragment spaces became %20, not +",
        &url.text(FRAGMENT, NONE),
        b"%20space%20",
    );

    // `tests/libtest/lib1560.c` L253-L255: spaces allowed at parse time, encoded
    // on the way out. The query part starts with `left` false, so `+`.
    let url = Url::parsed(b"https://user@example.net?he l lo", SPACE);
    same(
        "spaces in the query encode as +",
        &url.text(QUERY, ENCODE),
        b"he+l+lo",
    );
    // L256-L258: the identical handle with no get flags returns the bytes as
    // stored, because the encoder at L1391-L1397 is simply not entered.
    same(
        "and are left alone without CURLU_URLENCODE",
        &url.text(QUERY, NONE),
        b"he l lo",
    );

    // The same input spread over path, query and fragment. The path starts with
    // `left` true, the query with it false.
    let url = Url::parsed(b"https://curl.se/a b?c d#e f", SPACE);
    same("path space", &url.text(PATH, ENCODE), b"/a%20b");
    same("query space", &url.text(QUERY, ENCODE), b"c+d");
    same("fragment space", &url.text(FRAGMENT, ENCODE), b"e%20f");
}

/// A `?` inside a non-query part flips `left` mid-part.
///
/// This is the sharp end of the rule above. The fragment is not the query part,
/// so `left` starts true at L135 and its first space becomes `%20`; the `?`
/// inside it then clears `left` at L164-L165, and the space after it becomes
/// `+`. One part, both spellings, decided by a byte in the middle.
#[test]
fn get_encode_left_state_flips_inside_a_fragment() {
    let url = Url::parsed(b"https://x/#a b?c d", SPACE);
    same(
        "the fragment kept its literal spaces",
        &url.text(FRAGMENT, NONE),
        b"a b?c d",
    );
    same(
        "%20 before the question mark, + after it",
        &url.text(FRAGMENT, ENCODE),
        b"a%20b?c+d",
    );
}

/// Bytes below the space and from 0x7f up become upper-case escapes.
///
/// `lib/urlapi.c` L157-L162 covers exactly `*iptr < ' '` and `*iptr >= 0x7f`,
/// and the digits come from `Curl_hexbyte`, whose comment at `lib/escape.c`
/// L219-L221 says UPPERCASE and whose body at L222-L228 indexes the upper-case
/// digit table. Both halves of the range are asserted, and so is the case, since
/// a lower-case pair would still look plausible.
#[test]
fn get_encode_escapes_are_upper_case_hex() {
    // `tests/libtest/lib1560.c` L246-L252: a host of multi-byte UTF-8, given
    // twice in the C table -- once as `%`-escapes and once as raw bytes -- with
    // the same expectation. Both spellings are exercised here for the same
    // reason: the parser percent-decodes the host at L579-L603, so the two
    // inputs converge on identical stored bytes.
    let raw: &[u8] = b"https://\xe2\x84\x82\xe1\xb5\xa4\xe2\x93\x87\xe2\x84\x92\
                       \xe3\x80\x82\xf0\x9d\x90\x92\xf0\x9f\x84\xb4";
    let escaped: &[u8] = b"https://%e2%84%82%e1%b5%a4%e2%93%87%e2%84%92\
                           %e3%80%82%f0%9d%90%92%f0%9f%84%b4";
    let want: &[u8] = b"%E2%84%82%E1%B5%A4%E2%93%87%E2%84%92%E3%80%82%F0%9D%90%92%F0%9F%84%B4";
    for input in [raw, escaped] {
        let url = Url::parsed(input, NONE);
        same(
            &format!("host of \"{}\" encoded", shown(input)),
            &url.text(HOST, ENCODE),
            want,
        );
        let mut whole = b"https://".to_vec();
        whole.extend_from_slice(want);
        whole.push(b'/');
        same("and the whole URL agrees", &url.text(URL, ENCODE), &whole);
    }

    // `tests/libtest/lib1560.c` L654-L655. The input escape is lower case and
    // the output escape is upper case, because the parser decodes `%c0` to the
    // byte 0xC0 at L579-L603 and the encoder re-creates the escape from that
    // byte. Nothing carries the original spelling across.
    let url = Url::parsed(b"https://_%c0_", NONE);
    same(
        "with no flags the decoded byte is emitted raw",
        &url.text(URL, NONE),
        b"https://_\xc0_/",
    );
    same(
        "with CURLU_URLENCODE it comes back upper case",
        &url.text(URL, ENCODE),
        b"https://_%C0_/",
    );
    same(
        "and so does the host alone",
        &url.text(HOST, ENCODE),
        b"_%C0_",
    );

    // `tests/libtest/lib1560.c` L668-L669: a raw 0xFF byte in the host. It
    // survives `Curl_junkscan` because that function rejects only the low bytes
    // and 127 (L223-L239), never the high half.
    let url = Url::parsed(b"https://\xff.127.0.0.1", NONE);
    same(
        "a raw high byte in a host encodes as %FF",
        &url.text(URL, ENCODE),
        b"https://%FF.127.0.0.1/",
    );
    same("host alone", &url.text(HOST, ENCODE), b"%FF.127.0.0.1");
}

/// The host escape differs between a part read and a whole-URL read.
///
/// The two paths use different predicates and the difference is deliberate, so
/// this test pins both. `AAP` 0.6.2 flags it as the pair that must not be
/// unified.
///
/// - A part read goes through `urlget_format`, which calls `urlencode_str` with
///   `relative` set to TRUE at L1395. That switches off the host-separator skip
///   at L139-L148, so the host is encoded like any other bytes: the predicate is
///   the byte range at L157-L162, and nothing else is touched. The comment at
///   L126-L128 explaining that hostnames must not be encoded therefore applies
///   only where `relative` is FALSE, which is the relative-resolution call at
///   L1275.
/// - A whole-URL read goes through `urlget_url`, which at L1493 hands the host to
///   `curl_easy_escape`. That predicate is `ISUNRESERVED`, `lib/escape.c` L72
///   over `lib/curl_ctype.h` L47-L49: alphanumerics plus `-`, `.`, `_` and `~`,
///   and everything else escaped.
///
/// `|` is the byte that separates them. `hostname_check` at L457 does not list it
/// among the rejected characters, so it can appear in a stored host; it is inside
/// the byte range `urlencode_str` leaves alone; and it is not unreserved. So a
/// part read keeps it and a whole-URL read escapes it.
#[test]
fn get_host_encoding_differs_from_whole_url_host_escaping() {
    let url = Url::parsed(b"https://a|b.example", NONE);
    same("stored as parsed", &url.text(HOST, NONE), b"a|b.example");
    same(
        "a part read leaves the pipe alone: it is in neither escape range",
        &url.text(HOST, ENCODE),
        b"a|b.example",
    );
    same(
        "a whole-URL read escapes it, because it is not unreserved",
        &url.text(URL, ENCODE),
        b"https://a%7Cb.example/",
    );
    same(
        "and leaves it alone with no flags",
        &url.text(URL, NONE),
        b"https://a|b.example/",
    );

    // The same asymmetry over a host assigned rather than parsed, and with the
    // three unreserved punctuation marks alongside so that the whole-URL read is
    // shown discriminating rather than escaping indiscriminately.
    let url = Url::parsed(b"https://example.net", NONE);
    url.set_ok(HOST, b"a|b~c-d.e", NONE);
    same(
        "part read: pipe kept, and so are ~ - .",
        &url.text(HOST, ENCODE),
        b"a|b~c-d.e",
    );
    same(
        "whole-URL read: only the pipe is escaped",
        &url.text(URL, ENCODE),
        b"https://a%7Cb~c-d.e/",
    );
}

/// A whole-URL read encodes the host and nothing else.
///
/// `urlget_url` L1425-L1537 assembles the answer from the stored parts through
/// the template at L1517-L1532 and never runs a codec over the path, the query
/// or the fragment. The only conversion it performs is the host escape at L1493.
/// So `CURLU_URLENCODE` and `CURLU_URLDECODE` are both inert for those three
/// parts on this path, which is what makes the space vectors above readable: the
/// spaces reach the serialised URL untouched.
#[test]
fn get_whole_url_leaves_path_query_and_fragment_alone() {
    let url = Url::parsed(b"https://x/%41?%41#%41", NONE);
    for flags in [NONE, ENCODE, DECODE, ENCODE | DECODE] {
        same(
            &format!("whole URL with flags {flags:#x}"),
            &url.text(URL, flags),
            b"https://x/%41?%41#%41",
        );
    }

    let url = Url::parsed(b"https://curl.se/a b?c d#e f", SPACE);
    for flags in [NONE, ENCODE, DECODE] {
        same(
            &format!("spaces in a whole URL with flags {flags:#x}"),
            &url.text(URL, flags),
            b"https://curl.se/a b?c d#e f",
        );
    }
}

// ---------------------------------------------------------------------------
// Parts where a codec is meaningless, cleared, or overridden
// ---------------------------------------------------------------------------

/// The scheme is never encoded on assignment.
///
/// `lib/urlapi.c` L1834 gives `CURLUPART_SCHEME` its own return before the
/// encoder at L1887 is ever reached, so no flag can make a value acceptable that
/// the scheme charset check rejects. Two inputs demonstrate it from opposite
/// directions: a space is rejected rather than turned into `%20`, and an
/// already-escaped space is rejected too, because `%` is not a scheme character
/// either. `CURLU_NON_SUPPORT_SCHEME` is passed throughout so that the failure
/// cannot be mistaken for an unknown-scheme rejection.
#[test]
fn set_scheme_is_never_encoded() {
    let url = Url::parsed(b"https://curl.se/", NONE);

    // A scheme of legal characters is stored verbatim: RFC 3986 3.1 allows the
    // digit, the `+`, the `-` and the `.`, which L182-L221 implements.
    url.set_ok(SCHEME, b"ht-tp+x.1", NON_SUPPORT);
    same(
        "a legal scheme is stored as given",
        &url.text(SCHEME, NONE),
        b"ht-tp+x.1",
    );

    assert_eq!(
        url.set(SCHEME, b"foo bar", NON_SUPPORT | ENCODE),
        abi::CURLUE_BAD_SCHEME,
        "a space is rejected, not encoded to %20"
    );
    assert_eq!(
        url.set(SCHEME, b"foo%20bar", NON_SUPPORT | ENCODE),
        abi::CURLUE_BAD_SCHEME,
        "and a pre-escaped space is rejected too, because % is not a scheme byte"
    );
    same(
        "neither attempt disturbed the stored scheme",
        &url.text(SCHEME, NONE),
        b"ht-tp+x.1",
    );
}

/// `CURLU_URLDECODE` is cleared for the scheme and for the port on retrieval.
///
/// `lib/urlapi.c` L1558 clears it for `CURLUPART_SCHEME` and L1585 for
/// `CURLUPART_PORT`, both with a comment saying "never". Neither part can
/// legally contain a `%` in the first place, so the clearing is belt and braces
/// -- but it is observable in that no flag combination changes the answer, and a
/// port is a good witness because it is regenerated rather than stored verbatim.
#[test]
fn get_scheme_and_port_ignore_the_codecs() {
    let url = Url::parsed(b"https://curl.se/", NONE);
    for flags in [NONE, DECODE, ENCODE, DECODE | ENCODE] {
        same(
            &format!("scheme with flags {flags:#x}"),
            &url.text(SCHEME, flags),
            b"https",
        );
    }

    // `set_url_port` at L1666-L1683 parses the digits with `curlx_str_number`
    // and re-prints the number, so the leading zeroes are gone before any
    // retrieval flag could matter.
    url.set_ok(PORT, b"0080", NONE);
    for flags in [NONE, DECODE, ENCODE, DECODE | ENCODE] {
        same(
            &format!("port with flags {flags:#x}"),
            &url.text(PORT, flags),
            b"80",
        );
    }
    same(
        "and the regenerated port is what the URL carries",
        &url.text(URL, NONE),
        b"https://curl.se:80/",
    );
}

/// The path allows eighteen bytes the other parts escape.
///
/// `allowed_in_path`, `lib/urlapi.c` L1779-L1803, returns TRUE for exactly
/// `!` `$` `&` `'` `(` `)` `{` `}` `[` `]` `*` `+` `,` `;` `=` `:` `@` and `/`,
/// and L1898 consults it only when `pathmode` is set, which happens for
/// `CURLUPART_PATH` at L1856 and nowhere else. So the same value assigned to the
/// path and to the query gives two different answers, and this test asserts both
/// against the same input string.
///
/// The second half feeds bytes that are in neither the unreserved set nor the
/// path allowance, and every one of them is escaped in both parts.
#[test]
fn set_path_allows_eighteen_extra_bytes() {
    // The eighteen, followed by one alphanumeric of each case, a digit, and the
    // four unreserved punctuation marks from `lib/curl_ctype.h` L47-L48.
    let allowed: &[u8] = b"!$&'(){}[]*+,;=:@/aZ9-._~";

    let url = Url::parsed(b"https://curl.se/", NONE);
    url.set_ok(PATH, allowed, ENCODE);
    same(
        "the path keeps all eighteen, plus the unreserved set",
        &url.text(PATH, NONE),
        b"/!$&'(){}[]*+,;=:@/aZ9-._~",
    );

    // The same string on the query and on the fragment, where `pathmode` is
    // false: only the unreserved tail survives. Note `=` becoming `%3D` -- no
    // append, so no exemption -- and `+` becoming `%2B`, because `plusencode` at
    // L1892 converts a space to `+` and never the reverse.
    let escaped: &[u8] = b"%21%24%26%27%28%29%7B%7D%5B%5D%2A%2B%2C%3B%3D%3A%40%2FaZ9-._~";
    url.set_ok(QUERY, allowed, ENCODE);
    same(
        "the query escapes all eighteen",
        &url.text(QUERY, NONE),
        escaped,
    );
    url.set_ok(FRAGMENT, allowed, ENCODE);
    same(
        "and so does the fragment",
        &url.text(FRAGMENT, NONE),
        escaped,
    );

    // Bytes in neither set. `%` is here too: with CURLU_URLENCODE it is escaped
    // to `%25` rather than being read as the start of an existing escape, which
    // is the difference from the else branch at L1915-L1932.
    url.set_ok(PATH, b"a\"b<c>d^e`f|g#h?i%j\\k", ENCODE);
    same(
        "and the path escapes everything outside both sets",
        &url.text(PATH, NONE),
        b"/a%22b%3Cc%3Ed%5Ee%60f%7Cg%23h%3Fi%25j%5Ck",
    );
}

/// Assigning the path forces a leading slash.
///
/// `lib/urlapi.c` L1857 sets `leadingslash` for `CURLUPART_PATH`, and L1882 adds
/// the slash when the value does not already start with one. It is added before
/// the encoder runs, so it is never itself escaped -- which matters because `/`
/// is in the path allowance anyway and would survive either way, and this test
/// would not distinguish the two orders if the slash were escapable.
#[test]
fn set_path_forces_a_leading_slash() {
    let url = Url::parsed(b"https://curl.se/", NONE);
    for flags in [NONE, ENCODE] {
        url.set_ok(PATH, b"no-slash", flags);
        same(
            &format!("a slash is prepended with flags {flags:#x}"),
            &url.text(PATH, NONE),
            b"/no-slash",
        );
        url.set_ok(PATH, b"/has-slash", flags);
        same(
            &format!("and not doubled with flags {flags:#x}"),
            &url.text(PATH, NONE),
            b"/has-slash",
        );
    }
}

/// On assignment a space becomes `+` for the query and `%20` everywhere else.
///
/// `plusencode` is set at `lib/urlapi.c` L1861 from `urlencode`, in the
/// `CURLUPART_QUERY` arm and no other, and L1892 is the only place it is read.
/// Every other part therefore falls through to the escape branch at L1907-L1910.
/// This is the assignment-side mirror of
/// [`get_encode_space_depends_on_the_query_delimiter`], and the two rules are not
/// the same rule: this one keys off the part identifier, that one off a `?` in
/// the bytes.
#[test]
fn set_space_becomes_plus_only_for_the_query() {
    let url = Url::parsed(b"https://curl.se/", NONE);

    url.set_ok(QUERY, b"a b", ENCODE);
    same("query", &url.text(QUERY, NONE), b"a+b");

    url.set_ok(PATH, b"a b", ENCODE);
    same("path", &url.text(PATH, NONE), b"/a%20b");

    url.set_ok(FRAGMENT, b"a b", ENCODE);
    same("fragment", &url.text(FRAGMENT, NONE), b"a%20b");

    url.set_ok(USER, b"a b", ENCODE);
    same("user", &url.text(USER, NONE), b"a%20b");
}

// ---------------------------------------------------------------------------
// The not-encoding branch: pre-existing escapes fold to lower case
// ---------------------------------------------------------------------------

/// Without `CURLU_URLENCODE`, an existing `%XX` is folded to lower case.
///
/// `lib/urlapi.c` L1915-L1932 is the else branch of the encoder. It stores the
/// value as given and then walks it, and at L1923-L1924 it rewrites a `%` only
/// when both following bytes are hex digits **and at least one of them is upper
/// case**, lower-casing both at L1925-L1926 and stepping past the triplet at
/// L1927. Anything else advances one byte at L1930.
///
/// Each vector in this test isolates one arm of that condition. The two-part
/// structure of the walk is why the trailing `%` cases matter: `p[1]` and `p[2]`
/// are read for a `%` at the very end of the string, and the NUL terminator
/// fails `ISXDIGIT`, so no rewrite happens and nothing runs off the end.
#[test]
fn set_without_encode_folds_existing_escapes_to_lower_case() {
    let url = Url::parsed(b"https://curl.se/", NONE);

    url.set_ok(QUERY, b"a=%C3%A4&b=%c3%a4&c=%Ff&d=%zz&e=%2&f=%", NONE);
    same(
        "upper folded, lower kept, non-hex and truncated escapes untouched",
        &url.text(QUERY, NONE),
        b"a=%c3%a4&b=%c3%a4&c=%ff&d=%zz&e=%2&f=%",
    );

    // Mixed case within one triplet: either digit being upper case triggers the
    // fold, and both digits are folded, not just the offending one.
    url.set_ok(FRAGMENT, b"%AB%cd%Ef%aB", NONE);
    same(
        "both digits fold whichever one was upper case",
        &url.text(FRAGMENT, NONE),
        b"%ab%cd%ef%ab",
    );

    // The path takes the same branch. `%2F` folds to `%2f` and is emphatically
    // not decoded: an assignment never decodes, whatever the flags.
    url.set_ok(PATH, b"/%C3%A4/%2F", NONE);
    same(
        "the path folds too, and decodes nothing",
        &url.text(PATH, NONE),
        b"/%c3%a4/%2f",
    );
}

/// Nothing but a well-formed escape is touched by the fold.
///
/// The complement of the test above, stated separately because the fold walks
/// every byte of the value and a regression here would look like corruption
/// rather than like a case difference. Upper-case letters outside an escape must
/// survive; so must a `%` that begins nothing.
#[test]
fn set_without_encode_leaves_everything_else_alone() {
    let url = Url::parsed(b"https://curl.se/", NONE);
    let untouched: &[u8] = b"ABC=DEF&G%zz%2%%%gh%";
    url.set_ok(QUERY, untouched, NONE);
    same(
        "plain upper case and malformed escapes are stored verbatim",
        &url.text(QUERY, NONE),
        untouched,
    );
}

/// New escapes are UPPER case; pre-existing escapes fold to LOWER case.
///
/// The two halves of this pair are the most surprising thing in the encoder and
/// they are trivially easy to state backwards, so they are asserted side by side
/// on one input.
///
/// - With `CURLU_URLENCODE` the `%` of the input is itself not unreserved, so it
///   takes the escape branch at L1907-L1910 and `Curl_hexbyte` writes `%25` in
///   upper case. The `C3` and `A4` that followed it are now ordinary
///   alphanumerics -- unreserved, passed through at L1903 -- so they keep the
///   case they were written in.
/// - Without the flag the same input reaches L1915-L1932 instead and the escape
///   is recognised, so both digit pairs fold to lower case.
///
/// The same input, two flag settings, and the case moves in opposite directions.
#[test]
fn new_escapes_are_upper_case_and_existing_ones_fold_to_lower_case() {
    let existing: &[u8] = b"%C3%A4";

    let url = Url::parsed(b"https://curl.se/", NONE);
    url.set_ok(QUERY, existing, ENCODE);
    same(
        "encoding treats the % as data and creates upper-case escapes",
        &url.text(QUERY, NONE),
        b"%25C3%25A4",
    );

    url.set_ok(QUERY, existing, NONE);
    same(
        "not encoding recognises the escapes and folds them down",
        &url.text(QUERY, NONE),
        b"%c3%a4",
    );

    // And the retrieval encoder agrees with the assignment encoder about case:
    // the byte 0xC3 stored raw comes back as `%C3`, upper case, from the same
    // `Curl_hexbyte`. Assigned without encoding, so the raw bytes are stored.
    url.set_ok(QUERY, b"\xc3\xa4", NONE);
    same(
        "and the retrieval encoder is upper case as well",
        &url.text(QUERY, ENCODE),
        b"%C3%A4",
    );
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// `CURLU_URLDECODE` decodes once, not repeatedly.
///
/// `tests/libtest/lib1560.c` L196-L199. `urlget_format` calls `Curl_urldecode`
/// exactly once, at `lib/urlapi.c` L1385, over the stored bytes. So `%252f`
/// becomes `%2f` -- the `%25` decodes to a `%` and the `2f` that follows it is
/// just two more output bytes -- and it does *not* then become `/`. `%40`, having
/// nothing after it to be re-read, becomes `@` in the same single pass.
#[test]
fn get_urldecode_is_a_single_pass() {
    let url = Url::parsed(b"https://example.com%252f%40@example.net", NONE);
    same(
        "stored as the input spelled it",
        &url.text(USER, NONE),
        b"example.com%252f%40",
    );
    same(
        "one pass: %25 becomes % and the 2f after it stays text",
        &url.text(USER, DECODE),
        b"example.com%2f@",
    );
}

/// A `+` decodes to a space in the query, and nowhere else.
///
/// `lib/urlapi.c` L1612 sets `plusdecode` in the `CURLUPART_QUERY` arm of
/// `curl_url_get`, and only when `CURLU_URLDECODE` is present; L1631 hands it to
/// `urlget_format`, which acts on it at L1371-L1378. Both halves of that guard
/// are tested: the path and the fragment keep their `+` even with the flag, and
/// the query keeps its `+` without it.
#[test]
fn get_plus_decodes_to_space_in_the_query_only() {
    let url = Url::parsed(b"https://curl.se/a+b?c+d#e+f", NONE);

    same("stored", &url.text(QUERY, NONE), b"c+d");
    same("query, decoded", &url.text(QUERY, DECODE), b"c d");
    same("query, not decoded", &url.text(QUERY, NONE), b"c+d");
    same("path, decoded", &url.text(PATH, DECODE), b"/a+b");
    same("fragment, decoded", &url.text(FRAGMENT, DECODE), b"e+f");
}

/// The plus conversion runs before the percent decoding, not after.
///
/// `lib/urlapi.c` L1371-L1378 rewrites `+` to a space in place, and only then
/// does L1385 percent-decode. The order is observable in one input: the literal
/// `+` becomes a space because it is seen first, while the `%2b` becomes a `+`
/// that the plus pass has already gone past and so survives as a `+`. If the two
/// steps were swapped, both would end up as spaces.
#[test]
fn get_plus_conversion_precedes_percent_decoding() {
    let url = Url::parsed(b"https://x/?a=%2bb+c", NONE);
    same("stored", &url.text(QUERY, NONE), b"a=%2bb+c");
    same(
        "the literal plus became a space, the escaped one became a plus",
        &url.text(QUERY, DECODE),
        b"a=+b c",
    );
}

/// `REJECT_CTRL` rejects bytes below 0x20 and nothing else.
///
/// `lib/urlapi.c` L1385 passes `REJECT_CTRL` to `Curl_urldecode`,
/// `lib/escape.c` L105, and the comment at L1383-L1384 calls the rejection
/// documented API behaviour. The threshold is `< 0x20` -- strictly below, and
/// byte 127 is not in the set. L1388 turns a rejection into `CURLUE_URLDECODE`.
///
/// Four vectors pin the boundary from both sides: `%00` and `%01` are rejected,
/// `%20` decodes to a space, and `%7F` decodes to byte 0x7F and succeeds. The
/// last is the one that would break if the threshold were ever widened to match
/// the parser's rejection set, which is what
/// [`junkscan_rejects_more_than_reject_ctrl_does`] is about.
#[test]
fn get_urldecode_rejects_only_bytes_below_0x20() {
    for (escape, part) in [(&b"%00"[..], QUERY), (&b"%01"[..], QUERY)] {
        let mut input = b"https://curl.se/?".to_vec();
        input.extend_from_slice(escape);
        let url = Url::parsed(&input, NONE);
        same("stored undecoded", &url.text(part, NONE), escape);
        assert_eq!(
            url.failing(part, DECODE),
            abi::CURLUE_URLDECODE,
            "decoding \"{}\" must be rejected",
            shown(escape)
        );
    }

    // The first byte that is not rejected.
    let url = Url::parsed(b"https://curl.se/%20?%20", NONE);
    same("0x20 in a path", &url.text(PATH, DECODE), b"/ ");
    same("0x20 in a query", &url.text(QUERY, DECODE), b" ");

    // Byte 127 is above the threshold, so it decodes. The escape is spelled in
    // both cases in the input to show that the decoder is case-insensitive about
    // the digits while the encoder always emits upper case.
    let url = Url::parsed(b"https://curl.se/%7F?%7f", NONE);
    same("stored as written", &url.text(PATH, NONE), b"/%7F");
    same("0x7f decodes in a path", &url.text(PATH, DECODE), b"/\x7f");
    same("and in a query", &url.text(QUERY, DECODE), b"\x7f");
    same(
        "and decoding then encoding round-trips it in upper case",
        &url.text(PATH, DECODE | ENCODE),
        b"/%7F",
    );
}

/// A malformed escape survives decoding untouched.
///
/// `Curl_urldecode`, `lib/escape.c` L105, advances one byte when a `%` is not
/// followed by two hex digits, so the input is copied rather than rejected. This
/// is the decoder's counterpart to the assignment-side fold declining to rewrite
/// the same shapes, which
/// [`set_without_encode_folds_existing_escapes_to_lower_case`] asserts.
#[test]
fn get_urldecode_passes_malformed_escapes_through() {
    let url = Url::parsed(b"https://x/?a=%zz&b=%2&c=%", NONE);
    same(
        "nothing decodes and nothing is rejected",
        &url.text(QUERY, DECODE),
        b"a=%zz&b=%2&c=%",
    );
}

/// The parser's rejection set is wider than the decoder's, on purpose.
///
/// `Curl_junkscan`, `lib/urlapi.c` L223-L239, rejects `p[i] <= control` or
/// `p[i] == 127`, where `control` is 0x1f when `CURLU_ALLOW_SPACE` is given and
/// 0x20 otherwise (L232). So byte 127 is rejected **always**, and a space unless
/// the flag is present. `REJECT_CTRL` rejects `< 0x20` and stops there.
///
/// The two sets therefore disagree about exactly two bytes, and both halves of
/// the disagreement are asserted here on the same byte:
///
/// - A **literal** 0x7F anywhere in a URL is `CURLUE_MALFORMED_INPUT`, and
///   `CURLU_ALLOW_SPACE` does not help, because that flag moves `control` and
///   leaves the `== 127` test standing.
/// - The **escape** `%7F` parses, and then decodes to that same byte without
///   complaint, as [`get_urldecode_rejects_only_bytes_below_0x20`] shows.
///
/// These are two distinct sets owned by two distinct modules -- `src/parse/junk.rs`
/// mirrors the first, `src/decode.rs` the second -- and they must never be
/// merged. Unifying them in either direction breaks something: widening
/// `REJECT_CTRL` to include 127 breaks the `%7F` retrieval, and narrowing
/// `Curl_junkscan` to `< 0x20` admits URLs the C rejects. The literal byte is
/// written `\x7f` here because `scripts/spacecheck.pl` L173 rejects a raw 0x7F in
/// a tracked file.
#[test]
fn junkscan_rejects_more_than_reject_ctrl_does() {
    let url = Url::new();
    for flags in [NONE, SPACE] {
        assert_eq!(
            url.set(URL, b"https://curl.se/a\x7fb", flags),
            abi::CURLUE_MALFORMED_INPUT,
            "a literal 0x7f is rejected at parse time with flags {flags:#x}"
        );
    }
    // The low control bytes are rejected under either flag as well: 0x1f is
    // below `control` in both settings.
    for flags in [NONE, SPACE] {
        assert_eq!(
            url.set(URL, b"https://curl.se/a\x1fb", flags),
            abi::CURLUE_MALFORMED_INPUT,
            "a literal 0x1f is rejected with flags {flags:#x}"
        );
    }

    // The escaped form of the very same byte is accepted and decodes.
    let url = Url::parsed(b"https://curl.se/a%7Fb", NONE);
    same(
        "the escape passes the junk scan and survives decoding",
        &url.text(PATH, DECODE),
        b"/a\x7fb",
    );
}

/// A space in a URL needs `CURLU_ALLOW_SPACE`.
///
/// `Curl_junkscan` L232 sets `control` to 0x20 without the flag and 0x1f with it,
/// and L233-L234 rejects anything at or below it. `tests/libtest/lib1560.c` L175
/// is the shortest witness: the one-character URL `" "` is
/// `CURLUE_MALFORMED_INPUT`. The paired assertion is that the same input parses
/// once the flag is given, so the rejection is the flag's doing and not a
/// side-effect of the string being otherwise unusable.
#[test]
fn parse_space_requires_allow_space() {
    let url = Url::new();
    assert_eq!(
        url.set(URL, b" ", NONE),
        abi::CURLUE_MALFORMED_INPUT,
        "lib1560.c L175: a lone space is malformed input"
    );
    assert_eq!(
        url.set(URL, b"https://curl.se/a b", NONE),
        abi::CURLUE_MALFORMED_INPUT,
        "and so is a space inside an otherwise valid URL"
    );

    url.set_ok(URL, b"https://curl.se/a b", SPACE);
    same(
        "with the flag it parses and the space is stored as it stands",
        &url.text(URL, NONE),
        b"https://curl.se/a b",
    );
    same("in the path", &url.text(PATH, NONE), b"/a b");
}

// ---------------------------------------------------------------------------
// Non-ASCII vectors and internationalised domains
// ---------------------------------------------------------------------------

// The three non-ASCII hostnames the reference measurements in `AAP` 0.6.3 use,
// with the compatibility form of each. They are written as byte escapes because
// that is literally what the C table holds -- `tests/libtest/lib1560.c` L630
// spells the first one `"r\xc3\xa4ksm\xc3\xb6rg\xc3\xa5s.se"` -- and because
// `scripts/spacecheck.pl` L182-L196 rejects the bytes themselves in a tracked
// file. The character spelling is checked against the byte spelling by
// [`the_non_ascii_vectors_are_the_characters_they_name`], which is the only place
// the two forms meet: `\u{e4}` cannot be used in the vectors, because a `str`
// literal encodes it as two bytes and the whole point of a vector is its bytes.

/// `r{U+00E4}ksm{U+00F6}rg{U+00E5}s.se`, the host at `lib1560.c` L630.
const SWEDISH: &[u8] = b"r\xc3\xa4ksm\xc3\xb6rg\xc3\xa5s.se";
/// Its compatibility form, asserted at `lib1560.c` L631.
const SWEDISH_ACE: &[u8] = b"xn--rksmrgs-5wao1o.se"; // spellchecker:disable-line
/// `fa{U+00DF}.de`, the sharp-s name from the `AAP` 0.6.3 measurement.
const SHARP_S: &[u8] = b"fa\xc3\x9f.de";
/// Its compatibility form.
const SHARP_S_ACE: &[u8] = b"xn--fa-hia.de"; // spellchecker:disable-line
/// `{U+4E2D}{U+6587}.tw`, the CJK name from the same measurement.
const CJK: &[u8] = b"\xe4\xb8\xad\xe6\x96\x87.tw";
/// Its compatibility form.
const CJK_ACE: &[u8] = b"xn--fiq228c.tw"; // spellchecker:disable-line

/// The byte vectors really are the characters their names claim.
///
/// A one-line guard against the mistake this file's header warns about. `"\xff"`
/// is not a legal `str` escape and `"\u{ff}"` is a two-byte encoding of a
/// different thing, so a vector transcribed through the character spelling can
/// silently become the wrong input. Comparing the two spellings once, here, makes
/// the byte constants above self-documenting and keeps every other test free of
/// character escapes.
#[test]
fn the_non_ascii_vectors_are_the_characters_they_name() {
    assert_eq!(SWEDISH, "r\u{e4}ksm\u{f6}rg\u{e5}s.se".as_bytes());
    assert_eq!(SHARP_S, "fa\u{df}.de".as_bytes());
    assert_eq!(CJK, "\u{4e2d}\u{6587}.tw".as_bytes());
}

/// Encoding a non-ASCII host needs no internationalised-domain support at all.
///
/// Percent-encoding is a byte operation: `urlencode_str` L157-L162 escapes every
/// byte from 0x7f up without asking what character it belongs to, and
/// `curl_easy_escape` escapes everything outside `ISUNRESERVED`. Neither consults
/// a locale or a Unicode table, so this test holds in every feature
/// configuration and under every locale -- which is what makes it the right place
/// to pin the upper-case hex over multi-byte input.
#[test]
fn host_urlencode_of_a_non_ascii_name_is_locale_independent() {
    let mut input = b"https://".to_vec();
    input.extend_from_slice(SWEDISH);
    let url = Url::parsed(&input, NONE);
    same("stored as the bytes given", &url.text(HOST, NONE), SWEDISH);
    same(
        "each byte escaped, upper case",
        &url.text(HOST, ENCODE),
        b"r%C3%A4ksm%C3%B6rg%C3%A5s.se",
    );
    same(
        "and the whole URL agrees, through curl_easy_escape",
        &url.text(URL, ENCODE),
        b"https://r%C3%A4ksm%C3%B6rg%C3%A5s.se/",
    );
}

/// `CURLU_URLENCODE` overrides both internationalised-domain flags.
///
/// `lib/urlapi.c` L1391-L1420 is a single if / else-if / else-if chain:
/// `urlencode` first, then `punycode`, then `depunyfy`. So the two conversions
/// are mutually exclusive with encoding and with each other, and passing
/// `CURLU_PUNYCODE` alongside `CURLU_URLENCODE` changes nothing at all. `AAP`
/// 0.6.2 records the exclusivity; this asserts it.
///
/// It is worth having as an unconditional test because the answer does not depend
/// on which backend is compiled: the conversion is never reached, so even a build
/// with no support whatsoever must produce the escaped form rather than
/// `CURLUE_LACKS_IDN`.
#[test]
fn urlencode_overrides_the_idn_flags() {
    let mut input = b"https://".to_vec();
    input.extend_from_slice(SWEDISH);
    let url = Url::parsed(&input, NONE);
    let escaped: &[u8] = b"r%C3%A4ksm%C3%B6rg%C3%A5s.se";
    same(
        "urlencode wins over punycode",
        &url.text(HOST, ENCODE | abi::CURLU_PUNYCODE),
        escaped,
    );
    same(
        "and over puny2idn",
        &url.text(HOST, ENCODE | abi::CURLU_PUNY2IDN),
        escaped,
    );
    same(
        "and over both at once",
        &url.text(HOST, ENCODE | abi::CURLU_PUNYCODE | abi::CURLU_PUNY2IDN),
        escaped,
    );
}

/// The environment's locale, adopted for the calling thread and then restored.
///
/// # Why the locale has to be adopted at all
///
/// A Rust program never calls `setlocale`, so it runs in the `C` locale whatever
/// the environment says. `lib/idn.c` L39-L40 reaches libidn2 through
/// `idn2_lookup_ul`, the entry point that reads its input in the encoding of the
/// process locale, so in the `C` locale every non-ASCII hostname fails to
/// convert. `tests/libtest/first.c` L231 is where curl's own harness performs
/// the equivalent call, and `AAP` 0.6.3 notes that a harness omitting it passes
/// while exercising none of this.
///
/// # Why the per-thread interface and not `setlocale`
///
/// `setlocale` mutates process-wide state, and Cargo runs the tests in this
/// binary on several threads at once, so calling it here would race with
/// whatever else is in flight. `newlocale` followed by `uselocale` installs the
/// locale for the calling thread only, which makes the change invisible to every
/// other test and removes the race rather than hoping to lose it. The measured
/// effect is the same: the codeset becomes the environment's.
///
/// The type is a guard rather than a function because the locale object has to
/// outlive the work and then be released. `Drop` puts the thread back on the
/// locale it had -- whatever `uselocale` handed back, which is the global locale
/// for a thread that never had one of its own -- and only then frees the object,
/// at which point it is current in no thread and releasing it is defined. Doing
/// it in that order is the difference between a clean run under a leak detector
/// and one leaked locale per test.
#[cfg(all(unix, any(feature = "idn-libidn2", feature = "idn-pure")))]
struct ThreadLocale {
    /// The locale this guard installed, or null if it could not be built.
    installed: libc::locale_t,
    /// What the thread was using before, to be restored by `Drop`.
    previous: libc::locale_t,
    /// `nl_langinfo(CODESET)` as it reads with `installed` in force.
    codeset: Vec<u8>,
}

#[cfg(all(unix, any(feature = "idn-libidn2", feature = "idn-pure")))]
impl ThreadLocale {
    fn adopt_environment() -> ThreadLocale {
        // SAFETY: the second argument is a NUL-terminated empty string, which is
        // `newlocale`'s documented request for "take every category from the
        // environment", and the third is the null base, which asks for a fresh
        // object rather than a modification of an existing one. The literal
        // outlives the call. A null return means the locale could not be built
        // and is handled below rather than dereferenced.
        let installed = unsafe {
            libc::newlocale(
                libc::LC_ALL_MASK,
                b"\0".as_ptr().cast::<c_char>(),
                ptr::null_mut(),
            )
        };
        let previous = if installed.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: `installed` is a live locale object, and this call takes
            // it for the calling thread only. The returned handle is the
            // thread's previous locale, kept for `Drop` and never dereferenced
            // here.
            unsafe { libc::uselocale(installed) }
        };
        // SAFETY: `nl_langinfo` returns a pointer to a NUL-terminated string
        // owned by the C library and valid until this thread's locale changes
        // next. The bytes are copied out immediately, well inside that window,
        // and the pointer is never written through.
        let codeset = unsafe { CStr::from_ptr(libc::nl_langinfo(libc::CODESET)) }
            .to_bytes()
            .to_vec();
        ThreadLocale {
            installed,
            previous,
            codeset,
        }
    }

    /// The codeset name now in force, for an assertion message.
    fn codeset(&self) -> &[u8] {
        &self.codeset
    }

    /// Whether the codeset is UTF-8.
    ///
    /// Compared with the punctuation removed and the case folded, because the
    /// name is spelled `UTF-8` by glibc and `utf8` or `UTF8` elsewhere and none
    /// of those is a different encoding.
    ///
    /// Only the `idn-libidn2` backend needs the answer: it is the one whose
    /// result depends on the codeset, which is precisely the divergence
    /// `rust-urlapi/docs/KNOWN-DIVERGENCES.md` L591-L633 records.
    #[cfg(feature = "idn-libidn2")]
    fn is_utf8(&self) -> bool {
        let letters: Vec<u8> = self
            .codeset
            .iter()
            .filter(|byte| byte.is_ascii_alphanumeric())
            .map(u8::to_ascii_uppercase)
            .collect();
        letters == b"UTF8"
    }
}

#[cfg(all(unix, any(feature = "idn-libidn2", feature = "idn-pure")))]
impl Drop for ThreadLocale {
    fn drop(&mut self) {
        if self.installed.is_null() {
            return;
        }
        // SAFETY: `previous` is what `uselocale` returned for this thread, so it
        // is either a live locale object or the sentinel standing for the global
        // locale, and passing either back is how the interface is restored. The
        // call cannot fail for a handle it produced itself.
        unsafe { libc::uselocale(self.previous) };
        // SAFETY: after the restore above, `installed` is current in no thread
        // -- it was only ever installed in this one -- and no reference into it
        // exists, so releasing it here is defined and is its first and only
        // release.
        unsafe { libc::freelocale(self.installed) };
    }
}

/// The same guard for platforms without the POSIX per-thread locale interface.
///
/// The codeset reads as empty, meaning "unknown", which
/// [`punycode_conversion_follows_the_locale_codeset`] treats as the non-UTF-8
/// case. That is the conservative reading, because a locale that was never
/// adopted behaves exactly that way.
#[cfg(all(not(unix), any(feature = "idn-libidn2", feature = "idn-pure")))]
struct ThreadLocale;

#[cfg(all(not(unix), any(feature = "idn-libidn2", feature = "idn-pure")))]
impl ThreadLocale {
    fn adopt_environment() -> ThreadLocale {
        ThreadLocale
    }

    fn codeset(&self) -> &[u8] {
        b""
    }

    #[cfg(feature = "idn-libidn2")]
    fn is_utf8(&self) -> bool {
        false
    }
}

/// `CURLU_PUNYCODE` converts only when the locale codeset is UTF-8.
///
/// This is the locale trap `AAP` 0.6.3 documents, and
/// `rust-urlapi/docs/KNOWN-DIVERGENCES.md` L591-L633 records the same
/// measurement against libidn2 2.3.8: under a UTF-8 codeset the three names
/// convert, and under any other codeset `idn2_lookup_ul` reports that it could
/// not convert the string, which `lib/urlapi.c` L1338-L1355 maps to
/// `CURLUE_BAD_HOSTNAME`.
///
/// Both outcomes are asserted exactly rather than either being tolerated: the
/// codeset is established first, and it decides which of the two answers is the
/// correct one. So this test never fails merely because the runner's locale is
/// `C`, and it never passes vacuously either.
#[cfg(feature = "idn-libidn2")]
#[test]
fn punycode_conversion_follows_the_locale_codeset() {
    let locale = ThreadLocale::adopt_environment();
    let codeset = locale.codeset().to_vec();
    let utf8 = locale.is_utf8();

    for (name, ace) in [
        (SWEDISH, SWEDISH_ACE),
        (SHARP_S, SHARP_S_ACE),
        (CJK, CJK_ACE),
    ] {
        let mut input = b"https://".to_vec();
        input.extend_from_slice(name);
        let url = Url::parsed(&input, NONE);
        if utf8 {
            same(
                &format!("\"{}\" under codeset {}", shown(name), shown(&codeset)),
                &url.text(HOST, abi::CURLU_PUNYCODE),
                ace,
            );
        } else {
            assert_eq!(
                url.failing(HOST, abi::CURLU_PUNYCODE),
                abi::CURLUE_BAD_HOSTNAME,
                "\"{}\" cannot convert under codeset {}",
                shown(name),
                shown(&codeset)
            );
        }
    }

    // `tests/libtest/lib1560.c` L629-L631, the whole-URL form of the first name,
    // which is the assertion curl's own suite makes. The conversion happens at
    // `lib/urlapi.c` L1495-L1500 rather than in `urlget_format`, so it is a
    // second code path over the same libidn2 call.
    let mut input = b"https://".to_vec();
    input.extend_from_slice(SWEDISH);
    input.extend_from_slice(b"/path?q#frag");
    let url = Url::parsed(&input, NONE);
    if utf8 {
        let mut want = b"https://".to_vec();
        want.extend_from_slice(SWEDISH_ACE);
        want.extend_from_slice(b"/path?q#frag");
        same(
            "lib1560.c L630-L631, the whole URL",
            &url.text(URL, abi::CURLU_PUNYCODE),
            &want,
        );
    } else {
        assert_eq!(
            url.failing(URL, abi::CURLU_PUNYCODE),
            abi::CURLUE_BAD_HOSTNAME,
            "the whole-URL path fails the same way"
        );
    }
}

/// `CURLU_PUNY2IDN` converts whatever the locale says.
///
/// The two directions are not symmetric and this is the half that surprises.
/// `idn_decode` at `lib/idn.c` L247-L279 goes through the locale-aware
/// `IDN2_LOOKUP`, but `idn_encode` at L281-L297 calls `idn2_to_unicode_8z8z`,
/// which is UTF-8 in and UTF-8 out and reads no locale at all. So the
/// compatibility-to-Unicode direction succeeds in the `C` locale, where the
/// Unicode-to-compatibility direction cannot.
///
/// The no-op halves are asserted alongside, because each conversion is guarded by
/// `Curl_is_ASCII_name` -- `lib/idn.c` L223-L236 -- at `lib/urlapi.c` L1400 and
/// L1411: `CURLU_PUNYCODE` on a host that is already ASCII does nothing, and
/// `CURLU_PUNY2IDN` on a host that is not ASCII does nothing. Neither reports an
/// error, and neither converts.
#[cfg(feature = "idn-libidn2")]
#[test]
fn puny2idn_conversion_ignores_the_locale() {
    let locale = ThreadLocale::adopt_environment();
    let codeset = locale.codeset().to_vec();

    for (name, ace) in [
        (SWEDISH, SWEDISH_ACE),
        (SHARP_S, SHARP_S_ACE),
        (CJK, CJK_ACE),
    ] {
        let mut input = b"https://".to_vec();
        input.extend_from_slice(ace);
        let url = Url::parsed(&input, NONE);
        same(
            &format!(
                "\"{}\" back to Unicode under codeset {}",
                shown(ace),
                shown(&codeset)
            ),
            &url.text(HOST, abi::CURLU_PUNY2IDN),
            name,
        );
        same(
            "and punycode on an ASCII host is a no-op",
            &url.text(HOST, abi::CURLU_PUNYCODE),
            ace,
        );
    }

    let mut input = b"https://".to_vec();
    input.extend_from_slice(SWEDISH);
    let url = Url::parsed(&input, NONE);
    same(
        "puny2idn on a non-ASCII host is a no-op",
        &url.text(HOST, abi::CURLU_PUNY2IDN),
        SWEDISH,
    );
}

/// The pure-Rust backend converts regardless of the locale.
///
/// `rust-urlapi/docs/KNOWN-DIVERGENCES.md` L591-L633 records this as a genuine
/// divergence running the opposite way from the usual one: the `idna` crate reads
/// its input as Rust text, which is UTF-8 by definition, so it is indifferent to
/// the process locale and converts a name the C path would refuse. That is
/// exactly why this backend is opt-in and outside the parity claim, and why this
/// test is separate from
/// [`punycode_conversion_follows_the_locale_codeset`] rather than sharing its
/// codeset branch.
///
/// The three names are the ones `AAP` 0.6.3 measured through both backends,
/// where the two agreed, so the compatibility forms asserted here are the same
/// ones the C produces under a UTF-8 codeset. The differences the document
/// records -- the absent transitional retry and the independently versioned
/// Unicode tables -- are not reachable through these three.
#[cfg(feature = "idn-pure")]
#[test]
fn punycode_conversion_with_the_pure_backend_ignores_the_locale() {
    let locale = ThreadLocale::adopt_environment();
    let codeset = locale.codeset().to_vec();
    for (name, ace) in [
        (SWEDISH, SWEDISH_ACE),
        (SHARP_S, SHARP_S_ACE),
        (CJK, CJK_ACE),
    ] {
        let mut input = b"https://".to_vec();
        input.extend_from_slice(name);
        let url = Url::parsed(&input, NONE);
        same(
            &format!("\"{}\" under codeset {}", shown(name), shown(&codeset)),
            &url.text(HOST, abi::CURLU_PUNYCODE),
            ace,
        );
    }
}

/// With no backend compiled in, both conversions report `CURLUE_LACKS_IDN`.
///
/// `lib/urlapi.c` L1334-L1336 turns `host_decode` and `host_encode` into macros
/// yielding `CURLUE_LACKS_IDN`, value 30, when support is not built. The guards
/// still apply, so this is asserted on inputs that reach the conversion: a
/// non-ASCII host for `CURLU_PUNYCODE`, and an ASCII one for `CURLU_PUNY2IDN`.
///
/// The complement is [`urlencode_overrides_the_idn_flags`], which must keep
/// working in this configuration precisely because it never reaches either macro.
#[cfg(not(any(feature = "idn-libidn2", feature = "idn-pure")))]
#[test]
fn idn_flags_report_lacks_idn_without_a_backend() {
    for (name, ace) in [
        (SWEDISH, SWEDISH_ACE),
        (SHARP_S, SHARP_S_ACE),
        (CJK, CJK_ACE),
    ] {
        let mut input = b"https://".to_vec();
        input.extend_from_slice(name);
        let url = Url::parsed(&input, NONE);
        assert_eq!(
            url.failing(HOST, abi::CURLU_PUNYCODE),
            abi::CURLUE_LACKS_IDN,
            "\"{}\" cannot be converted without a backend",
            shown(name)
        );
        // The name is still parsed, stored and retrieved: only the conversion is
        // unavailable.
        same("the host itself is untouched", &url.text(HOST, NONE), name);

        let mut input = b"https://".to_vec();
        input.extend_from_slice(ace);
        let url = Url::parsed(&input, NONE);
        assert_eq!(
            url.failing(HOST, abi::CURLU_PUNY2IDN),
            abi::CURLUE_LACKS_IDN,
            "and \"{}\" cannot be converted back",
            shown(ace)
        );
        same("nor is this one disturbed", &url.text(HOST, NONE), ace);
    }
}
