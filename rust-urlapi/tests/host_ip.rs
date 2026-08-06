// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Host, address, zone-identifier and port coverage, driven through the C ABI.
//!
//! The subject is the part of the port that turns an authority into a stored
//! host: `Curl_parse_port` at `lib/urlapi.c` L335-L387, `ipv6_parse` at
//! L390-L442, `hostname_check` at L444-L462, `ipv4_normalize` at L477-L575 and
//! `urldecode_host` at L578-L602, plus the two places the results surface --
//! the zone assembly inside whole-URL serialisation at L1480-L1491 and the
//! host setter's zone-identifier release at L1848.
//!
//! # Why this file only ever calls the C entry points
//!
//! Two independent reasons, and either alone would be enough.
//!
//! `src/lib.rs` publishes exactly two modules, `abi` and `ffi`, and every item
//! inside `src/ffi.rs` -- its `exports` module included -- is `pub(crate)`.
//! A Cargo integration test links this crate as an external crate, so it can
//! name only `pub` items: `parse::port`, `parse::host` and `parse::ipv6` are
//! unreachable from here by construction, and even `ffi::curl_url_get` is not
//! nameable. What *is* reachable is the C ABI itself, because `#[no_mangle]`
//! visibility is a linker property rather than a Rust one. The `extern "C"`
//! block below therefore declares the five entry points and the linker
//! resolves them against the `rlib`, which is exactly the surface a C consumer
//! sees. `use curl_urlapi_rs::abi` keeps the crate on the link line and
//! supplies the numeric constants.
//!
//! The second reason is scope. The isolated port extractor is declared inside
//! `#ifdef UNITTESTS` at `lib/urlapi-int.h` L35-L38 and is not one of the
//! eight symbols the replaced object file defines, so it is not exported here
//! and cannot be. `tests/unit/unit1653.c` L30-L40 calls it directly, handing
//! it a `CURLU *` together with a `struct dynbuf *` the test built itself;
//! satisfying that would need a ninth exported symbol *and* bit-compatible
//! interoperation with C's dynamic-buffer layout. That is reportable
//! constraint R2, it is out of scope, and the name appears in this file only
//! in prose.
//!
//! # The rule for every `unit1653` vector below
//!
//! **Transcribe the inputs, re-derive the expectations. Never copy a
//! `fail_unless` across.** That test drives the port extractor in isolation,
//! so the address validation that `parse_authority` L634-L651 runs
//! *afterwards* never happens for it. Three vectors show how far apart the two
//! answers can be:
//!
//! * `[fe80::250:56ff;fea7:da15]:808` -- `unit1653.c` L81-L88 expects success
//!   with port `808`. Through the public API the `strspn` at L401 stops on the
//!   `;`, which is not `%`, so L424-L425 rejects the whole thing with
//!   `CURLUE_BAD_IPV6`.
//! * `[fe80::250:56ff:fea7:da15!25eth3]:180` -- L178-L185 expects success with
//!   port `180`. Through the public API `strspn` stops on the `!` and the
//!   answer is again `CURLUE_BAD_IPV6`.
//! * `[fe80::250:56ff:fea7:da15%eth3]:80` -- L194-L198 expects success, and
//!   through the public API it *is* successful, with zone identifier `eth3`.
//!   Agreement here is a coincidence of this particular vector, not a rule.
//!
//! Every expectation in this file was derived from `lib/urlapi.c` for the full
//! pipeline and then confirmed against a build of the unmodified C
//! implementation. A later editor who "restores" a `unit1653` value will break
//! a test that is currently correct.
//!
//! # Two configurations, one set of expectations
//!
//! The crate builds with default features (`strerror`, `cfree`,
//! `scheme-table`, `idn-libidn2`) and in the drop-in configuration
//! (`--no-default-features --features idn-libidn2`). This file compiles and
//! passes in both, which takes two deliberate choices.
//!
//! *Freeing.* Buffers come back from `curl_url_get` allocated by the C
//! allocator -- `src/alloc.rs` is the sole producer of C-visible memory -- and
//! `docs/libcurl/curl_url_get.md` L45 requires them to be released with curl's
//! free function. `libc::free` is that function in both supported
//! configurations, where `curlx_free` resolves to plain `free` or to the
//! `Curl_cfree` hook still holding its default. `ffi::curl_free` is not used,
//! and could not be: it exists only under the `cfree` feature. Nothing is ever
//! written through a returned pointer, per L46 of the same page.
//!
//! `curl_url_strerror` is not called either, for the same kind of reason and one
//! more. It exists only under the `strerror` feature, so any use would need a
//! `cfg`; and a failure message that reads differently depending on the
//! configuration is worse than one that does not, so every assertion below
//! reports the numeric code and the input instead. The codes are the ABI, and
//! `src/abi.rs` names them.
//!
//! *Scheme resolution.* This is the most scheme-dependent of the crate's
//! tests: default-port injection and suppression read `h->defport`, and almost
//! every vector starts with `https`. With `scheme-table` on, the crate answers
//! from its own table; with it off, `src/ffi.rs` L1822 imports
//! `Curl_get_scheme` from libcurl, and a Cargo test has no libcurl, so the
//! link fails on an undefined symbol before any test runs. Gating the
//! scheme-dependent tests away would silently delete most of this file in the
//! configuration that matters most, so instead `scheme_standin` below supplies the
//! two symbols under `cfg(not(feature = "scheme-table"))`, answering for
//! `http` and `https` exactly as the built-in table does. Every expectation
//! below then holds unchanged in both configurations, which is checked rather
//! than assumed.
//!
//! No internationalised-domain assertion appears here, and that is a decision
//! rather than an omission: none of these vectors needs a non-ASCII name, the
//! default backend goes through `idn2_lookup_ul` and so answers differently
//! outside a UTF-8 locale, and the `idn-pure` backend is documented as not
//! bit-for-bit. `docs/KNOWN-DIVERGENCES.md` records both. An assertion here
//! would therefore be testing the runner's environment. The `lib1560` parity
//! run, which sets the locale and the codeset marker the way
//! `tests/data/test1560` and `tests/runtests.pl` L837-L839 do, is where that
//! behaviour is checked.
//!
//! # Posture
//!
//! These tests supplement the two authoritative oracles -- unmodified
//! `tests/libtest/lib1560.c` through `rust-urlapi/harness/`, and the
//! byte-for-byte demo diff. A failure here means the port is wrong, so the fix
//! belongs in `src/parse/host.rs`, `src/parse/ipv6.rs` or `src/parse/port.rs`
//! and never in this file. Assertions may panic: the crate root's denial of
//! the panicking constructs binds library code, which crosses the C boundary,
//! and a test binary does not.

use curl_urlapi_rs::abi;

use libc::{c_char, c_int, c_uint, c_void};
use std::ffi::{CStr, CString};
use std::ptr;

/// The opaque handle, `typedef struct Curl_URL CURLU` at
/// `include/curl/urlapi.h` L107.
///
/// A C consumer never sees the definition and neither does this file. The
/// zero-length array gives the type no size and no alignment demand of its
/// own, so `*mut CurlU` is a plain pointer -- which is the whole of the ABI
/// contract, and the property that let the port choose its own field order.
#[repr(C)]
struct CurlU {
    _opaque: [u8; 0],
}

// The five entry points, spelled as `include/curl/urlapi.h` L113-L142 declares
// them and as `src/ffi.rs` L2801, L2827, L2876, L2962 and L3060 define them.
// `CURLUcode` and `CURLUPart` are both `c_int` and the flag word is `c_uint`,
// per `src/abi.rs` L92 and L103.
extern "C" {
    fn curl_url() -> *mut CurlU;
    fn curl_url_cleanup(handle: *mut CurlU);
    fn curl_url_dup(input: *const CurlU) -> *mut CurlU;
    fn curl_url_get(
        handle: *const CurlU,
        what: c_int,
        part: *mut *mut c_char,
        flags: c_uint,
    ) -> c_int;
    fn curl_url_set(handle: *mut CurlU, what: c_int, part: *const c_char, flags: c_uint) -> c_int;
}

/// An owned handle that cleans itself up, so a failing assertion cannot leak
/// one.
///
/// `curl_url_cleanup` releases the handle and the ten strings it owns. It does
/// **not** release anything a previous `curl_url_get` returned --
/// `include/curl/urlapi.h` L116-L118 is explicit about that -- which is why
/// every getter below frees its own result.
struct Handle {
    raw: *mut CurlU,
}

impl Handle {
    /// `curl_url()`, `lib/urlapi.c` L1288-L1291.
    fn new() -> Self {
        // SAFETY: the constructor takes no arguments and either allocates a
        // zeroed handle or returns null, which the assertion catches.
        let raw = unsafe { curl_url() };
        assert!(!raw.is_null(), "curl_url() returned null");
        Handle { raw }
    }

    /// `curl_url_dup()`, `lib/urlapi.c` L1310-L1332.
    fn dup(&self) -> Self {
        // SAFETY: `self.raw` is a live handle for the whole borrow, and the
        // duplicate is a fresh allocation this wrapper takes ownership of.
        let raw = unsafe { curl_url_dup(self.raw) };
        assert!(!raw.is_null(), "curl_url_dup() returned null");
        Handle { raw }
    }

    /// `curl_url_set()` with a byte-string value.
    ///
    /// Byte strings rather than `&str` because one vector's host is the single
    /// byte `0xff`, which no Rust string literal can hold and which
    /// `\u{ff}`-style escaping would silently turn into the two UTF-8 bytes
    /// `0xc3 0xbf`.
    fn set(&self, what: c_int, value: &[u8], flags: c_uint) -> c_int {
        let owned = CString::new(value).expect("test input holds an interior NUL");
        // SAFETY: `self.raw` is a live handle, and `owned` keeps the
        // NUL-terminated bytes alive and unmodified across the call, which is
        // all `curl_url_set` reads -- it copies whatever it keeps.
        unsafe { curl_url_set(self.raw, what, owned.as_ptr(), flags) }
    }

    /// `curl_url_set()` with a null value, which clears the part rather than
    /// assigning it -- `lib/urlapi.c` L1819-L1821 into `urlset_clear` at
    /// L1732.
    fn clear(&self, what: c_int) -> c_int {
        // SAFETY: `self.raw` is a live handle and a null `part` is an
        // explicitly documented argument rather than a violated precondition.
        unsafe { curl_url_set(self.raw, what, ptr::null(), 0) }
    }

    /// `curl_url_get()`, returning the code and an owned copy of the part.
    ///
    /// The C buffer is copied out and released immediately with `libc::free`,
    /// so each returned pointer is freed exactly once and nothing borrows it
    /// afterwards. The pointer is only ever read.
    fn get(&self, what: c_int, flags: c_uint) -> (c_int, Option<Vec<u8>>) {
        let mut out: *mut c_char = ptr::null_mut();
        // SAFETY: `self.raw` is a live handle, `out` is a writable slot for
        // one pointer, and the call is the only writer of it. `curl_url_get`
        // takes `*const` and mutates nothing behind the handle pointer.
        let code = unsafe { curl_url_get(self.raw, what, &mut out, flags) };
        if code != abi::CURLUE_OK {
            assert!(
                out.is_null(),
                "curl_url_get() failed with {code} yet stored a pointer; \
                 lib/urlapi.c L1552 nulls the slot before it can fail"
            );
            return (code, None);
        }
        if out.is_null() {
            // `src/getset.rs` documents this: the C stores whatever
            // `curlx_dyn_ptr` gave it at L1399 and reports success, so a null
            // with `CURLUE_OK` is a real answer rather than a fault. No case in
            // this file reaches it, and treating it as an answer rather than
            // asserting against it keeps that a property of the vectors.
            return (code, None);
        }
        // SAFETY: the call succeeded and stored a non-null pointer to a
        // NUL-terminated buffer the caller owns, so it is readable up to and
        // including its terminator.
        let bytes = unsafe { CStr::from_ptr(out) }.to_bytes().to_vec();
        // SAFETY: the buffer came from the C allocator by way of
        // `src/alloc.rs`, so plain `free` is the deallocator the documented
        // contract at docs/libcurl/curl_url_get.md L45 names, and this is its
        // only release. `bytes` already owns a copy.
        unsafe { libc::free(out.cast::<c_void>()) };
        (code, Some(bytes))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: `self.raw` was produced by `curl_url()` or `curl_url_dup()`,
        // has not been released before -- nothing else in this file calls
        // `curl_url_cleanup` -- and is not used again.
        unsafe { curl_url_cleanup(self.raw) };
    }
}

/// Renders a part for an assertion message, which is only ever reached on
/// failure.
fn shown(value: &Option<Vec<u8>>) -> String {
    match value {
        None => "<none>".to_owned(),
        Some(bytes) => {
            let mut out = String::from("<");
            for byte in bytes {
                if (0x20..0x7f).contains(byte) {
                    out.push(char::from(*byte));
                } else {
                    out.push_str(&format!("\\x{byte:02x}"));
                }
            }
            out.push('>');
            out
        }
    }
}

/// Parses `input` as a whole URL and returns the resulting handle, or the code
/// that stopped it.
fn parse(input: &[u8], set_flags: c_uint) -> Result<Handle, c_int> {
    let handle = Handle::new();
    let code = handle.set(abi::CURLUPART_URL, input, set_flags);
    if code == abi::CURLUE_OK {
        Ok(handle)
    } else {
        Err(code)
    }
}

/// Asserts that parsing `input` and reading `what` back yields `expected`.
fn expect_part(
    input: &[u8],
    set_flags: c_uint,
    what: c_int,
    get_flags: c_uint,
    expected: &str,
    why: &str,
) {
    match parse(input, set_flags) {
        Err(code) => panic!(
            "{}: curl_url_set(CURLUPART_URL) rejected {} with {code}, expected \
             it to succeed and yield <{expected}>",
            why,
            shown(&Some(input.to_vec()))
        ),
        Ok(handle) => {
            let (code, value) = handle.get(what, get_flags);
            assert_eq!(
                code,
                abi::CURLUE_OK,
                "{}: curl_url_get() on {} returned {code}, expected <{expected}>",
                why,
                shown(&Some(input.to_vec()))
            );
            assert_eq!(
                value.as_deref(),
                Some(expected.as_bytes()),
                "{}: {} gave {} rather than <{expected}>",
                why,
                shown(&Some(input.to_vec())),
                shown(&value)
            );
        }
    }
}

/// Asserts that parsing `input` and reading it back as a whole URL yields
/// `expected`.
fn expect_url(input: &[u8], set_flags: c_uint, get_flags: c_uint, expected: &str, why: &str) {
    expect_part(
        input,
        set_flags,
        abi::CURLUPART_URL,
        get_flags,
        expected,
        why,
    );
}

/// Asserts that parsing `input` fails with `expected`, and that a handle it
/// failed on was left alone.
fn expect_parse_error(input: &[u8], set_flags: c_uint, expected: c_int, why: &str) {
    let handle = Handle::new();
    let code = handle.set(abi::CURLUPART_URL, input, set_flags);
    assert_eq!(
        code,
        expected,
        "{}: curl_url_set(CURLUPART_URL) on {} returned {code}, expected \
         {expected}",
        why,
        shown(&Some(input.to_vec()))
    );
    // A failed parse frees the whole temporary at `lib/urlapi.c` L1188-L1191
    // and never touches the live handle, so a fresh one still has no host --
    // `CURLUE_NO_HOST`, 14, from the `ifmissing` at L1576.
    let (host_code, _) = handle.get(abi::CURLUPART_HOST, 0);
    assert_eq!(
        host_code,
        abi::CURLUE_NO_HOST,
        "{why}: a failed parse left something behind in the handle"
    );
}

/// Asserts that reading `what` back reports the part as missing, with the
/// `ifmissing` code `curl_url_get` assigns it at `lib/urlapi.c` L1554-L1626.
fn expect_missing(handle: &Handle, what: c_int, expected: c_int, why: &str) {
    let (code, value) = handle.get(what, 0);
    assert_eq!(
        code,
        expected,
        "{}: expected the part to be missing with {expected}, got {code} {}",
        why,
        shown(&value)
    );
    assert!(
        value.is_none(),
        "{why}: a missing part still produced a buffer"
    );
}

/// The scheme table libcurl would supply, for the drop-in configuration only.
///
/// With `scheme-table` off the crate reads the real table through
/// `Curl_get_scheme`, declared at `src/ffi.rs` L1916-L1927 against the mirror
/// of `struct Curl_scheme` at `lib/urldata.h` L515-L524. A Cargo test links no
/// libcurl, so without a stand-in the test binary does not link at all: the
/// symbol is referenced from `src/ffi.rs` L1992 and L2017 whether or not any
/// test calls it. The crate has the same problem for its own unit tests and
/// solves it the same way at `src/ffi.rs` L2180 and L2193, under `cfg(test)`,
/// which does not extend to an integration test.
///
/// Two rows, because two are all this file's vectors name. The parser reads
/// exactly three members of a descriptor -- `flags`, tested only for
/// `PROTOPT_URLOPTIONS`; `defport`; and `run`, tested only for null -- so the
/// rows carry the default ports from `lib/urldata.h` L32-L33, a non-null `run`
/// for "this protocol is implemented", and `flags` of zero, which is the
/// truthful value for the one bit that is read: neither descriptor sets
/// `PROTOPT_URLOPTIONS`, at `lib/http.c` L5011-L5023 and L5028-L5040. The
/// answers therefore match the built-in table at `src/scheme.rs` L588-L603 for
/// these two names, and every expectation in this file holds in both
/// configurations.
#[cfg(not(feature = "scheme-table"))]
mod scheme_standin {
    use libc::{c_char, c_void, size_t};
    use std::ffi::CStr;
    use std::ptr;
    use std::slice;

    /// The three members the parser reads, in the positions
    /// `lib/urldata.h` L515-L524 puts them, with the two it never reads
    /// present because their width decides the offsets of the rest.
    #[repr(C)]
    pub struct CurlScheme {
        name: *const c_char,
        run: *const c_void,
        protocol: u32,
        family: u32,
        flags: u32,
        defport: u16,
    }

    /// Wrapper so the table can be a `static`: `CurlScheme` holds raw
    /// pointers and is therefore not `Sync` on its own.
    struct Table([CurlScheme; 2]);

    // SAFETY: every pointer in the table addresses a `'static` item -- a byte
    // literal or `RUN_MARKER` -- and the table is immutable for the whole
    // program, so sharing it across threads hands out nothing but shared
    // access to constant memory.
    unsafe impl Sync for Table {}

    /// Stands in for `&Curl_protocol_http`: only its address matters, because
    /// `lib/urlapi.c` L1646 tests the member for null and nothing
    /// dereferences it.
    static RUN_MARKER: u8 = 0;

    static TABLE: Table = Table([
        // lib/http.c L5011-L5023, port from lib/urldata.h L32.
        CurlScheme {
            name: b"http\0".as_ptr().cast::<c_char>(),
            run: (&RUN_MARKER as *const u8).cast::<c_void>(),
            protocol: 1 << 0,
            family: 1 << 0,
            flags: 0,
            defport: 80,
        },
        // lib/http.c L5028-L5040, port from lib/urldata.h L33.
        CurlScheme {
            name: b"https\0".as_ptr().cast::<c_char>(),
            run: (&RUN_MARKER as *const u8).cast::<c_void>(),
            protocol: 1 << 1,
            family: 1 << 0,
            flags: 0,
            defport: 443,
        },
    ]);

    /// Case-insensitive lookup, the rule `Curl_getn_scheme` follows at
    /// `lib/url.c` L1524-L1540. A name the table does not hold answers null,
    /// which is what makes `CURLU_NON_SUPPORT_SCHEME` and
    /// `CURLUE_UNSUPPORTED_SCHEME` reachable.
    fn find(name: &[u8]) -> *const CurlScheme {
        for row in &TABLE.0 {
            // SAFETY: each `name` above is a byte literal ending in exactly
            // one NUL with static lifetime, so it is a valid C string.
            let stored = unsafe { CStr::from_ptr(row.name) }.to_bytes();
            if stored.eq_ignore_ascii_case(name) {
                return row;
            }
        }
        ptr::null()
    }

    // The two names are C identifiers and must stay spelled as libcurl spells
    // them, so the Rust naming convention cannot apply here.
    #[allow(non_snake_case)]
    #[no_mangle]
    extern "C" fn Curl_get_scheme(scheme: *const c_char) -> *const CurlScheme {
        if scheme.is_null() {
            return ptr::null();
        }
        // SAFETY: the caller is `src/ffi.rs` L1992, which passes
        // `CStr::as_ptr`, so the pointer is NUL terminated and stays valid for
        // the call. Nothing is written through it.
        find(unsafe { CStr::from_ptr(scheme) }.to_bytes())
    }

    #[allow(non_snake_case)]
    #[no_mangle]
    extern "C" fn Curl_getn_scheme(scheme: *const c_char, len: size_t) -> *const CurlScheme {
        if scheme.is_null() || len == 0 {
            return ptr::null();
        }
        // SAFETY: the caller is `src/ffi.rs` L2017, which rejects an empty
        // slice and then passes that slice's pointer with its own length, so
        // exactly `len` initialised bytes are readable and stay borrowed for
        // the call. `u8` and `c_char` share size and alignment.
        find(unsafe { slice::from_raw_parts(scheme.cast::<u8>(), len) })
    }
}

// ---------------------------------------------------------------------------
// IPv4 normalisation, `ipv4_normalize` at `lib/urlapi.c` L477-L575.
// ---------------------------------------------------------------------------
//
// The function walks up to four dot-separated parts and accepts three radices
// per part, chosen by prefix at L497-L506: `0x` is hexadecimal, a leading `0`
// alone is octal, anything else decimal. Every part is scanned with a ceiling
// of `UINT_MAX`, so a part that overflows 32 bits is a syntax error rather
// than a wrap.
//
// The arity then decides the range check and the recomposition, at L530-L570:
//
// * one part   -- 32 bits, split 8.8.8.8 with no further check;
// * two parts  -- 8 + 24, so `parts[0] > 0xff` or `parts[1] > 0xffffff` fails;
// * three      -- 8 + 8 + 16;
// * four       -- 8 + 8 + 8 + 8.
//
// Failure means `HOST_NAME`, and `parse_authority` L640-L643 then treats the
// text as an ordinary hostname: percent-decoded and character-checked, but
// otherwise stored exactly as written. That is why every rejecting case below
// asserts the input coming back unchanged. A mangled result would be the real
// failure, and asserting `CURLUE_OK` alone would not catch it.

#[test]
fn ipv4_single_part_is_thirty_two_bits() {
    // lib1560.c L658.
    expect_url(
        b"https://16843009",
        0,
        0,
        "https://1.1.1.1/",
        "one part, 0x01010101 split 8.8.8.8 at L531-L538",
    );
    // The same handle read as a host rather than a URL, so the assertion is
    // about the stored value and not about serialisation.
    expect_part(
        b"https://16843009",
        0,
        abi::CURLUPART_HOST,
        0,
        "1.1.1.1",
        "one part, stored normalised",
    );
    // 0xffffffff is the largest one-part value that fits, the ceiling at L500
    // and L506 being UINT_MAX rather than the per-arity limits below.
    expect_url(
        b"https://0xffffffff",
        0,
        0,
        "https://255.255.255.255/",
        "one part at the 32-bit ceiling",
    );
    // 4294967296 is one past it, so `curlx_str_number` fails at L508-L509 and
    // the text survives as a hostname. lib1560.c L676.
    expect_url(
        b"https://4294967296",
        0,
        0,
        "https://4294967296/",
        "one part over 32 bits stays a hostname",
    );
    // The hexadecimal form of the same overflow, rejected by `curlx_str_hex`
    // at L500 for the same reason.
    expect_url(
        b"https://0x100000000",
        0,
        0,
        "https://0x100000000/",
        "one hexadecimal part over 32 bits stays a hostname",
    );
}

#[test]
fn ipv4_two_parts_split_eight_and_twenty_four() {
    // lib1560.c L659: octal first part, `0177` being 127.
    expect_url(
        b"https://0177.1",
        0,
        0,
        "https://127.0.0.1/",
        "two parts, octal then decimal, L540-L549",
    );
    // lib1560.c L665.
    expect_url(
        b"https://1.0xffffff",
        0,
        0,
        "https://1.255.255.255/",
        "two parts, the second filling all 24 bits",
    );
    // The hexadecimal spelling of 127 in the first part.
    expect_url(
        b"https://0x7f.1",
        0,
        0,
        "https://127.0.0.1/",
        "two parts, hexadecimal then decimal",
    );
    // 0xffff is well inside 24 bits, so the second part supplies the low three
    // octets and the middle one comes out zero.
    expect_url(
        b"https://255.0xffff",
        0,
        0,
        "https://255.0.255.255/",
        "two parts, the second under the 24-bit ceiling",
    );
}

#[test]
fn ipv4_three_parts_split_eight_eight_and_sixteen() {
    // lib1560.c L660: octal, octal, hexadecimal in one address.
    expect_url(
        b"https://0111.02.0x3",
        0,
        0,
        "https://73.2.0.3/",
        "three parts, three radices, L550-L559",
    );
    // lib1560.c L662: the same shape with an octal third part, `030` being 24.
    expect_url(
        b"https://0111.02.030",
        0,
        0,
        "https://73.2.0.24/",
        "three parts, all octal after the first",
    );
    // 65535 is the largest third part that fits its 16 bits, L551.
    expect_url(
        b"https://1.2.65535",
        0,
        0,
        "https://1.2.255.255/",
        "three parts, the third at the 16-bit ceiling",
    );
    // One past it, so L551-L552 returns HOST_NAME and the text survives.
    expect_url(
        b"https://1.2.65536",
        0,
        0,
        "https://1.2.65536/",
        "three parts, the third over 16 bits, stays a hostname",
    );
    // lib1560.c L675: 0x100 exceeds the third part's own 8 bits.
    expect_url(
        b"https://1.2.0x100.3",
        0,
        0,
        "https://1.2.0x100.3/",
        "four parts, the third over 8 bits, stays a hostname",
    );
}

#[test]
fn ipv4_four_parts_are_four_octets() {
    // lib1560.c L664: hexadecimal, hexadecimal, octal, decimal.
    expect_url(
        b"https://0xff.0xff.0377.255",
        0,
        0,
        "https://255.255.255.255/",
        "four parts, mixed radix, L560-L571",
    );
    // Already normal, and normalisation is idempotent.
    expect_url(
        b"https://0.0.0.0",
        0,
        0,
        "https://0.0.0.0/",
        "four zero octets",
    );
    // lib1560.c L672: the last part is over 8 bits.
    expect_url(
        b"https://1.2.3.256",
        0,
        0,
        "https://1.2.3.256/",
        "four parts, the last over 8 bits, stays a hostname",
    );
    // The first part over 8 bits, which is the same check read from the other
    // end of L561-L562.
    expect_url(
        b"https://256.1.1.1",
        0,
        0,
        "https://256.1.1.1/",
        "four parts, the first over 8 bits, stays a hostname",
    );
}

#[test]
fn ipv4_syntax_errors_leave_the_host_alone() {
    // A trailing dot means a fifth, empty part: `*c == '.'` with `n == 3` hits
    // L515-L516 and returns HOST_NAME. lib1560.c L661 and L663.
    expect_url(
        b"https://0111.02.0x3.",
        0,
        0,
        "https://0111.02.0x3./",
        "trailing dot after three parts",
    );
    expect_url(
        b"https://0111.02.030.",
        0,
        0,
        "https://0111.02.030./",
        "trailing dot, octal parts",
    );
    // lib1560.c L673.
    expect_url(
        b"https://1.2.3.256.",
        0,
        0,
        "https://1.2.3.256./",
        "trailing dot after four parts",
    );
    // lib1560.c L674: five parts, so the fourth dot is one too many.
    expect_url(
        b"https://1.2.3.4.5",
        0,
        0,
        "https://1.2.3.4.5/",
        "five parts",
    );
    // lib1560.c L667: a leading letter, so the very first scan fails.
    expect_url(
        b"https://a127.0.0.1",
        0,
        0,
        "https://a127.0.0.1/",
        "leading alphabetic",
    );
    // lib1560.c L677: digits then letters, which fails at the `default` arm of
    // L525-L526 rather than in the number scanner.
    expect_url(
        b"https://123host",
        0,
        0,
        "https://123host/",
        "digits followed by letters",
    );
    // lib1560.c L670: the number scanners are unsigned, so a minus sign is not
    // part of any radix.
    expect_url(
        b"https://127.-0.0.1",
        0,
        0,
        "https://127.-0.0.1/",
        "minus sign in the second part",
    );
    // `08` is a leading zero, so L502-L503 scans it as octal and stops on the
    // `8`, which is not an octal digit; the leftover byte reaches L525-L526.
    expect_url(
        b"https://08",
        0,
        0,
        "https://08/",
        "a leading zero makes 8 an invalid digit",
    );
}

#[test]
fn a_space_in_the_authority_is_caught_before_the_address_code() {
    // lib1560.c L671. The expectation is `CURLUE_MALFORMED_INPUT`, 3, and the
    // reason is worth stating because the case is easy to misfile as an address
    // error: `Curl_junkscan` at L223-L246 runs first, from `parseurl` L1124,
    // and with `CURLU_ALLOW_SPACE` absent its threshold is 0x20 inclusive at
    // L232, so the space is rejected at L234-L235 before any host parsing has
    // happened at all. `ipv4_normalize` never sees this input.
    expect_parse_error(
        b"https://127.0. 1",
        0,
        abi::CURLUE_MALFORMED_INPUT,
        "space in the authority, rejected by the junk scan",
    );
}

#[test]
fn a_high_byte_host_is_kept_and_escaped_on_the_way_out() {
    // lib1560.c L668-L669. The single byte 0xff is not in `hostname_check`'s
    // rejected set at L455, so it is stored as it arrived; `urlget_url` L1493
    // then runs the host through `curl_easy_escape` because `CURLU_URLENCODE`
    // is set, and the escape is upper-case hexadecimal per `Curl_hexbyte` at
    // `lib/escape.c` L222.
    //
    // The byte is written as `\xff` inside a byte-string literal. A Rust string
    // literal cannot hold it, `\u{ff}` would encode the two UTF-8 bytes
    // 0xc3 0xbf instead, and a raw high byte in the source would fail
    // `scripts/spacecheck.pl`, which allows exactly one non-ASCII sequence
    // repository-wide and this is not it.
    expect_url(
        b"https://\xff.127.0.0.1",
        0,
        abi::CURLU_URLENCODE,
        "https://%FF.127.0.0.1/",
        "0xff host byte, escaped on retrieval",
    );
}

// ---------------------------------------------------------------------------
// Hostname rejection, `hostname_check` at `lib/urlapi.c` L444-L462.
// ---------------------------------------------------------------------------
//
// Three answers, in this order: an empty host is `CURLUE_NO_HOST` at L450-L451;
// a host starting with `[` is handed to `ipv6_parse` at L452-L453; anything
// else is measured with `strcspn` against the rejected set at L456 and is
// `CURLUE_BAD_HOSTNAME` if any of those bytes appears.
//
// The order relative to percent-decoding matters and is asserted below.
// `parse_authority` L640-L643 calls `urldecode_host` first and only then
// `hostname_check`, so the check sees decoded bytes: `%41` is the letter A and
// passes, while `%40` is `@` and does not.

#[test]
fn braces_and_brackets_in_a_hostname_are_rejected() {
    // lib1560.c L259-L262, plus L263 for the backslash. All of `{`, `}`, `]`
    // and `\` are in the rejected set at L456.
    for (input, why) in [
        (&b"https://exam{}[]ple.net"[..], "all four bracket bytes"),
        (&b"https://exam{ple.net"[..], "opening brace"),
        (&b"https://exam}ple.net"[..], "closing brace"),
        (&b"https://exam]ple.net"[..], "closing square bracket"),
        (&b"https://exam\\ple.net"[..], "backslash"),
    ] {
        expect_parse_error(input, 0, abi::CURLUE_BAD_HOSTNAME, why);
    }
    // lib1560.c L195: a bare `%` survives `urldecode_host`, because
    // `Curl_urldecode` only treats it specially when two hexadecimal digits
    // follow, and `%` is itself in the rejected set.
    expect_parse_error(
        b"https://test%test",
        0,
        abi::CURLUE_BAD_HOSTNAME,
        "a percent sign that is not an escape",
    );
}

#[test]
fn percent_escapes_that_decode_to_a_rejected_byte_are_rejected() {
    // lib1560.c L643-L649 and L651-L653. Each of these decodes to one byte of the set at
    // L456, which is the point: the check runs on the decoded text, so hiding
    // the byte behind an escape does not smuggle it through.
    for (input, why) in [
        (&b"http://example.com%40127.0.0.1/"[..], "%40 is @"),
        (&b"http://example.com%21127.0.0.1/"[..], "%21 is !"),
        (&b"http://example.com%3f127.0.0.1/"[..], "%3f is ?"),
        (&b"http://example.com%23127.0.0.1/"[..], "%23 is #"),
        (&b"http://example.com%3a127.0.0.1/"[..], "%3a is :"),
        (&b"http://example.com%09127.0.0.1/"[..], "%09 is a tab"),
        (&b"http://example.com%2F127.0.0.1/"[..], "%2F is /"),
        (&b"https://%20"[..], "%20 is a space"),
        (&b"https://%25"[..], "%25 is a percent sign"),
    ] {
        expect_parse_error(input, 0, abi::CURLUE_BAD_HOSTNAME, why);
    }
    // lib1560.c L652: `%0D` is a carriage return, which `Curl_urldecode` itself
    // refuses in `REJECT_CTRL` mode -- `lib/escape.c` L105 with the mode
    // `urldecode_host` passes at L590-L591. That maps the failure to
    // `CURLUE_BAD_HOSTNAME` at L592-L593 rather than to `CURLUE_URLDECODE`, so
    // the code is the same 21 even though the rejecting stage is different.
    expect_parse_error(
        b"https://%41%0D",
        0,
        abi::CURLUE_BAD_HOSTNAME,
        "%0D is a control byte the decoder itself refuses",
    );
}

#[test]
fn a_percent_escape_that_decodes_to_a_legal_byte_is_accepted_and_decoded() {
    // lib1560.c L650. This is the case that proves the ordering: the host is
    // stored decoded, so the letter A is what comes back, from the part and
    // from the serialised URL alike.
    expect_url(
        b"https://%41",
        0,
        0,
        "https://A/",
        "%41 decodes to A before the character check",
    );
    expect_part(
        b"https://%41",
        0,
        abi::CURLUPART_HOST,
        0,
        "A",
        "the decoded byte is what gets stored",
    );
}

#[test]
fn an_empty_host_is_no_host() {
    // `parseurl` L1143 measures the authority with `strcspn(hostp, "/?#")`, so
    // for "https://" the length is zero, no `CURLU_NO_AUTHORITY` is set, and
    // L1160 answers `CURLUE_NO_HOST`, 14. `hostname_check` L450-L451 and
    // `parse_authority` L631-L632 are the other two places the same answer is
    // produced, both unreachable from this input because the authority never
    // reaches them.
    expect_parse_error(
        b"https://",
        0,
        abi::CURLUE_NO_HOST,
        "an authority of zero length",
    );
    // The host setter refuses an empty value too, at L1972-L1973, but with
    // `CURLUE_BAD_HOSTNAME` rather than `CURLUE_NO_HOST`: `bad = TRUE` on the
    // `!n` branch and L1987-L1989 returns the one code for every reason.
    let handle = parse(b"https://example.org/", 0).expect("base URL parses");
    assert_eq!(
        handle.set(abi::CURLUPART_HOST, b"", 0),
        abi::CURLUE_BAD_HOSTNAME,
        "an empty value for CURLUPART_HOST is bad rather than absent"
    );
    expect_part(
        b"https://example.org/",
        0,
        abi::CURLUPART_HOST,
        0,
        "example.org",
        "a rejected host setter leaves the previous host in place",
    );
}

#[test]
fn forty_bytes_is_the_longest_scheme_and_forty_one_is_too_long() {
    // lib1560.c L678-L681. `MAX_SCHEME_LEN` is 40 at `lib/urlapi.c` L55, and
    // `Curl_is_absolute_url` L194-L195 scans at most that many bytes, so a
    // 40-byte scheme is recognised -- and lower-cased into `schemebuf` by
    // `Curl_strntolower` at L213. `CURLU_NON_SUPPORT_SCHEME` is needed because
    // the name is in no scheme table, which is what L951-L953 would otherwise
    // reject.
    expect_url(
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://hostname/path",
        abi::CURLU_NON_SUPPORT_SCHEME,
        0,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa://hostname/path",
        "a 40-byte scheme is the longest accepted, and is lower-cased",
    );
    // lib1560.c L682-L685, and the outcome is derived rather than assumed: with
    // 41 bytes the loop at L194 stops at `i == MAX_SCHEME_LEN` with `url[40]`
    // still a letter rather than the colon L206 requires, so
    // `Curl_is_absolute_url` returns 0. `parse_scheme` L961 then finds neither
    // `CURLU_DEFAULT_SCHEME` nor `CURLU_GUESS_SCHEME` set and answers
    // `CURLUE_BAD_SCHEME`, 27 -- not `CURLUE_UNSUPPORTED_SCHEME` and not a
    // "too long" code, because from the parser's point of view there is no
    // scheme here at all.
    expect_parse_error(
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://hostname/path",
        abi::CURLU_NON_SUPPORT_SCHEME,
        abi::CURLUE_BAD_SCHEME,
        "a 41-byte scheme is not seen as a scheme",
    );
}

// ---------------------------------------------------------------------------
// Bracketed IPv6, `ipv6_parse` at `lib/urlapi.c` L390-L442.
// ---------------------------------------------------------------------------
//
// The stages, in order, because each one's output is the next one's input:
//
// 1. L395-L396 rejects anything shorter than four bytes, `[::]` being the
//    shortest valid form.
// 2. L401 measures the leading run of `0123456789abcdefABCDEF:.` with `strspn`.
// 3. If the run is short of the address, L403-L427 requires the stopping byte
//    to be `%` and reads a zone identifier; anything else is
//    `CURLUE_BAD_IPV6` at L424-L425.
// 4. L429-L441 round-trips the address through `curlx_inet_pton` and
//    `curlx_inet_ntop`, which is what lower-cases it and collapses its longest
//    zero run.
//
// One note on step 4, because it pins an expectation to the platform rather
// than to curl: on this reference platform those two are the system functions
// and not curl's in-tree Vixie copy, so the exact spelling of a normalised
// address -- which zero run gets collapsed when two are the same length -- is
// the C library's choice. The cases below use addresses whose longest zero run
// is unambiguous, so the same text is produced either way.

#[test]
fn a_bracketed_address_is_lower_cased_and_its_zero_run_collapsed() {
    // lib1560.c L620-L622. Upper-case hexadecimal in, lower-case out, and the
    // trailing `0:0:0` becomes `::`.
    expect_url(
        b"https://[FE80:0:A:0:409B:0:0:0]:80/moo",
        0,
        0,
        "https://[fe80:0:a:0:409b::]:80/moo",
        "normalisation through inet_pton and inet_ntop at L433-L435",
    );
    // The shortest form there is, and the one L395-L396's threshold is written
    // around: four bytes exactly.
    expect_url(
        b"https://[::]/",
        0,
        0,
        "https://[::]/",
        "the shortest valid bracketed address",
    );
    // A dotted quad inside an address is legal input to `inet_pton`, and both
    // `.` and the upper-case hexadecimal digits are in the L401 legal set.
    expect_url(
        b"https://[::FFFF:1.2.3.4]/",
        0,
        0,
        "https://[::ffff:1.2.3.4]/",
        "an embedded IPv4 tail, lower-cased",
    );
    // A dotted quad on its own is not an IPv6 address, and here the rejection
    // comes from `inet_pton` at L434 rather than from the legal-byte scan,
    // which accepts every one of these bytes.
    expect_parse_error(
        b"https://[1.2.3.4]/",
        0,
        abi::CURLUE_BAD_IPV6,
        "a bare dotted quad in brackets is not an address",
    );
}

#[test]
fn a_bracketed_host_shorter_than_four_bytes_is_rejected_by_the_length_gate() {
    // L395-L396. Each of these is caught by the gate before the legal-byte scan
    // or `inet_pton` gets a chance, which is why the case is constructed from
    // bytes that the scan would otherwise accept: `1` and `:` are both in the
    // L401 set.
    for (input, why) in [
        (&b"https://[1]/"[..], "three bytes"),
        (&b"https://[:]/"[..], "three bytes, all legal"),
        (&b"https://[]/"[..], "two bytes"),
    ] {
        expect_parse_error(input, 0, abi::CURLUE_BAD_IPV6, why);
    }
}

#[test]
fn a_byte_outside_the_legal_set_must_be_a_percent_sign() {
    // L401 followed by L424-L425: the run stops, the stopping byte is not `%`,
    // and there is no third possibility.
    expect_parse_error(
        b"https://[fe80::20c:29gf]/",
        0,
        abi::CURLUE_BAD_IPV6,
        "g is not a hexadecimal digit",
    );
    expect_parse_error(
        b"https://[fe80::250:56ff;fea7:da15]/",
        0,
        abi::CURLUE_BAD_IPV6,
        "a semicolon inside the brackets",
    );
    // The other branch of the same test: the stopping byte *is* `%`, so the
    // zone reader at L405-L423 runs and the address is accepted.
    expect_part(
        b"https://[fe80::20c:29ff:fe9c:409b%25eth0]/",
        0,
        abi::CURLUPART_ZONEID,
        0,
        "eth0",
        "a percent sign hands the rest to the zone reader",
    );
}

#[test]
fn a_zone_identifier_is_split_off_and_the_address_kept_separately() {
    // The parse path stores the two apart: L421-L422 writes the closing bracket
    // over the `%` and terminates there, so the host is the address alone,
    // while L418 keeps the zone. Serialisation puts them back together at
    // L1480-L1491.
    let input = &b"https://[fe80::20c:29ff:fe9c:409b%25eth0]/hello.html"[..];
    expect_part(
        input,
        0,
        abi::CURLUPART_HOST,
        0,
        "[fe80::20c:29ff:fe9c:409b]",
        "the stored host is the address without the zone",
    );
    expect_part(
        input,
        0,
        abi::CURLUPART_ZONEID,
        0,
        "eth0",
        "the zone is stored on its own",
    );
    expect_url(
        input,
        0,
        0,
        "https://[fe80::20c:29ff:fe9c:409b%25eth0]/hello.html",
        "and the two are rejoined with a literal %25 on the way out",
    );
}

#[test]
fn the_twenty_five_skip_fires_only_on_a_real_percent_escape() {
    // L410-L412: `h` is skipped past a leading "25" only when those two bytes
    // are followed by a byte that is present and is not `]`. Three cases pin
    // the three ways that condition can go.
    //
    // Fires: "25" then "eth0", so the zone is what came after the escape.
    expect_part(
        b"https://[fe80::20c:29ff:fe9c:409b%25eth0]/",
        0,
        abi::CURLUPART_ZONEID,
        0,
        "eth0",
        "%25eth0 -- the skip fires and the zone is eth0",
    );
    // Does not fire, because the first two bytes are not "25". This is
    // `unit1653.c` L194's vector shape; the expectation is re-derived for the
    // full pipeline, where it happens to agree: a zone written without the
    // escape reads back identically.
    expect_part(
        b"https://[fe80::20c:29ff:fe9c:409b%eth0]/",
        0,
        abi::CURLUPART_ZONEID,
        0,
        "eth0",
        "%eth0 -- the skip does not fire and the zone is still eth0",
    );
    // The two spellings serialise the same way as well, because L1486-L1487
    // always writes `%25` regardless of how the input spelled it.
    expect_url(
        b"https://[fe80::20c:29ff:fe9c:409b%eth0]/",
        0,
        0,
        "https://[fe80::20c:29ff:fe9c:409b%25eth0]/",
        "an unescaped zone is escaped on the way out",
    );
    // Fires, and the zone keeps the two bytes that followed: the skip consumes
    // "25" and the zone is "00abc", not "2500abc" and not "abc".
    expect_part(
        b"https://[fe80::20c:29ff:fe9c:409b%2500abc]/",
        0,
        abi::CURLUPART_ZONEID,
        0,
        "00abc",
        "%2500abc -- the skip consumes 25 and leaves 00abc",
    );
    // Does not fire, because `h[2]` is the closing bracket. This is the case
    // that looks like an empty zone and is not: the zone becomes the literal
    // "25", and the URL therefore carries it as `%2525`. lib1560.c L689-L691
    // asserts exactly that serialisation.
    expect_part(
        b"https://[fe80::20c:29ff:fe9c:409b%25]/",
        0,
        abi::CURLUPART_ZONEID,
        0,
        "25",
        "%25] -- the skip cannot fire, so the zone is the text 25",
    );
    expect_url(
        b"https://[fe80::20c:29ff:fe9c:409b%25]/",
        0,
        0,
        "https://[fe80::20c:29ff:fe9c:409b%2525]/",
        "and 25 comes back out as %2525",
    );
    // A zone may itself contain a percent sign, because the reader copies bytes
    // until `]` and inspects none of them. After the skip consumes "25" the
    // remainder is "a%25b" verbatim.
    expect_part(
        b"https://[fe80::20c:29ff:fe9c:409b%25a%25b]/",
        0,
        abi::CURLUPART_ZONEID,
        0,
        "a%25b",
        "the zone reader copies bytes without interpreting them",
    );
    // A zone with a dot in it, for the same reason.
    expect_part(
        b"https://[fe80::1%25eth0.5]/",
        0,
        abi::CURLUPART_ZONEID,
        0,
        "eth0.5",
        "a dot is an ordinary zone byte",
    );
}

#[test]
fn an_empty_zone_and_an_over_long_zone_are_both_rejected() {
    // The genuinely empty zone is `%` immediately before `]`: the skip cannot
    // fire because the two bytes are not "25", the copy loop stops at once on
    // `]`, and `!i` at L415-L416 rejects it. lib1560.c L686-L688.
    expect_parse_error(
        b"https://[fe80::20c:29ff:fe9c:409b%]/",
        0,
        abi::CURLUE_BAD_IPV6,
        "a percent sign with nothing between it and the bracket",
    );
    // The length ceiling, and this is the expectation to read carefully rather
    // than assume, because the shape of the code invites the wrong answer. The
    // buffer at L407 is a fixed 16 bytes and the copy loop at L413-L414 stops
    // at `i < 15`, which looks like truncation -- but the loop's other exit is
    // the `]`, and L415-L416 then insists that the byte it stopped on *is* the
    // `]`. A zone of exactly 15 bytes stops on the bracket and is accepted
    // whole; a zone of 16 stops on the cap with a letter under `h`, and the
    // answer is `CURLUE_BAD_IPV6`. Nothing is ever truncated.
    expect_part(
        b"https://[fe80::1%25abcdefghijklmno]/",
        0,
        abi::CURLUPART_ZONEID,
        0,
        "abcdefghijklmno",
        "a 15-byte zone is the longest that fits",
    );
    expect_parse_error(
        b"https://[fe80::1%25abcdefghijklmnop]/",
        0,
        abi::CURLUE_BAD_IPV6,
        "a 16-byte zone is rejected, not truncated",
    );
    // The ceiling applies to what is left *after* the skip, not to the written
    // text: "2500abcdefghijklm" is 17 bytes, the skip removes two, and the
    // remaining 15 fit exactly.
    expect_part(
        b"https://[fe80::1%2500abcdefghijklm]/",
        0,
        abi::CURLUPART_ZONEID,
        0,
        "00abcdefghijklm",
        "the 15-byte ceiling is measured after the 25 skip",
    );
}

#[test]
fn a_zone_that_is_not_an_address_suffix_is_still_a_zone() {
    // lib1560.c L695-L697. `[::%25fakeit]` has nothing after the `%` that
    // resembles an interface name, and the reader does not care: the address is
    // `[::]` and the zone is `fakeit`.
    let input = &b"https://[::%25fakeit]/moo"[..];
    expect_part(
        input,
        0,
        abi::CURLUPART_HOST,
        0,
        "[::]",
        "the address ends where the percent sign starts",
    );
    expect_part(
        input,
        0,
        abi::CURLUPART_ZONEID,
        0,
        "fakeit",
        "and everything up to the bracket is the zone",
    );
    expect_url(
        input,
        0,
        0,
        "https://[::%25fakeit]/moo",
        "which round-trips unchanged",
    );
}

// ---------------------------------------------------------------------------
// The `scopeid` scenario, with the values the upstream sub-test never checks.
// ---------------------------------------------------------------------------
//
// `lib1560.c` L1681-L1809 walks this exact sequence and inspects **only return
// codes**: every step frees the retrieved buffer without looking at it. That is
// precisely why finding FB3 survives upstream, and it is why this file repeats
// the sequence and asserts the strings.
//
// The sequence also crosses the asymmetry that FB3 is about. The parse path
// splits the zone off the host and stores the two separately; the host setter
// does not, because it validates a decoded *copy* at L1974-L1983 and stores the
// original text. The zone identifier therefore ends up recorded twice over --
// once inside the host string and once in its own field -- and serialisation,
// which appends the field to the host unconditionally at L1480-L1491, writes it
// twice. That is reproduced here rather than fixed.

#[test]
fn the_scopeid_sequence_holds_the_values_upstream_never_looks_at() {
    let handle = parse(b"https://[fe80::20c:29ff:fe9c:409b%25eth0]/hello.html", 0)
        .expect("lib1560.c L1688-L1689: the zoned URL parses");

    // Step 1. The parse path separated them, so the host has no zone in it.
    assert_eq!(
        handle.get(abi::CURLUPART_HOST, 0).1.as_deref(),
        Some(&b"[fe80::20c:29ff:fe9c:409b]"[..]),
        "step 1: the stored host is the address alone, per L421-L422"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_ZONEID, 0).1.as_deref(),
        Some(&b"eth0"[..]),
        "step 1: the zone was stored on its own at L418"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://[fe80::20c:29ff:fe9c:409b%25eth0]/hello.html"[..]),
        "step 1: serialisation rejoins them at L1486-L1487"
    );

    // Step 2. `curl_url_set(CURLUPART_HOST, ...)` releases the zone identifier
    // at L1848, before it has even looked at the new value, so an address with
    // no zone leaves the field empty rather than stale.
    assert_eq!(
        handle.set(abi::CURLUPART_HOST, b"[::1]", 0),
        abi::CURLUE_OK,
        "step 2: setting the host to another address succeeds"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_HOST, 0).1.as_deref(),
        Some(&b"[::1]"[..]),
        "step 2: the new address is stored"
    );
    expect_missing(
        &handle,
        abi::CURLUPART_ZONEID,
        abi::CURLUE_NO_ZONEID,
        "step 2: the host setter freed the zone identifier at L1848",
    );
    assert_eq!(
        handle.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://[::1]/hello.html"[..]),
        "step 2: the path survives a host replacement"
    );

    // Step 3. An ordinary hostname, so nothing bracketed is involved at all.
    assert_eq!(
        handle.set(abi::CURLUPART_HOST, b"example.com", 0),
        abi::CURLUE_OK,
        "step 3: setting the host to a name succeeds"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://example.com/hello.html"[..]),
        "step 3: the name is serialised without brackets"
    );

    // Step 4. The zone comes back, because the setter's validation path runs
    // `hostname_check` on the decoded copy at L1981 and that delegates to
    // `ipv6_parse` at L452-L453, which writes `u->zoneid` at L418 as a side
    // effect. The copy is then freed, so the *stored* host keeps the whole
    // original text including `%25eth0` -- unlike step 1, where the parse path
    // truncated it.
    assert_eq!(
        handle.set(abi::CURLUPART_HOST, b"[fe80::20c:29ff:fe9c:409b%25eth0]", 0),
        abi::CURLUE_OK,
        "step 4: setting a zoned address succeeds"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_HOST, 0).1.as_deref(),
        Some(&b"[fe80::20c:29ff:fe9c:409b%25eth0]"[..]),
        "step 4: the setter stores the text it was given, zone included"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_ZONEID, 0).1.as_deref(),
        Some(&b"eth0"[..]),
        "step 4: and ipv6_parse recorded the zone a second time"
    );
    // The consequence, reproduced rather than repaired: the zone appears twice.
    // L1480 tests `u->host[0] == '['`, which holds, and L1486-L1487 appends
    // `%25` plus the field to the host string with the host's own copy of the
    // zone still in it.
    assert_eq!(
        handle.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://[fe80::20c:29ff:fe9c:409b%25eth0%25eth0]/hello.html"[..]),
        "step 4: the zone is serialised twice, once from the host and once \
         from the field"
    );

    // Step 5. Assigning the zone identifier replaces only the field, so the
    // host's embedded copy stays and the two spellings sit side by side.
    assert_eq!(
        handle.set(abi::CURLUPART_ZONEID, b"clown", 0),
        abi::CURLUE_OK,
        "step 5: setting the zone identifier succeeds"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_ZONEID, 0).1.as_deref(),
        Some(&b"clown"[..]),
        "step 5: the field holds the new value"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://[fe80::20c:29ff:fe9c:409b%25eth0%25clown]/hello.html"[..]),
        "step 5: the host keeps its own zone text and the field is appended"
    );
}

#[test]
fn a_zone_identifier_is_serialised_only_for_a_bracketed_host() {
    // The asymmetry L1480-L1491 creates, stated on its own: the field is
    // retrievable whatever the host looks like, but it is written into a URL
    // only when `u->host[0] == '['`. So a zone on a name is inert in the URL
    // and still visible through the part.
    let handle = parse(b"https://example.com/", 0).expect("base URL parses");
    assert_eq!(
        handle.set(abi::CURLUPART_ZONEID, b"eth7", 0),
        abi::CURLUE_OK,
        "the zone setter at L1850-L1851 does not care about the host"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_ZONEID, 0).1.as_deref(),
        Some(&b"eth7"[..]),
        "and the part reads it straight back from L1578-L1580"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://example.com/"[..]),
        "yet the URL cannot carry it, because the host does not start with ["
    );
    // A duplicate carries the same state, since `curl_url_dup` copies the zone
    // identifier along with the other nine strings at L1314-L1323.
    let copy = handle.dup();
    assert_eq!(
        copy.get(abi::CURLUPART_ZONEID, 0).1.as_deref(),
        Some(&b"eth7"[..]),
        "the duplicate carries the inert zone identifier too"
    );
    assert_eq!(
        copy.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://example.com/"[..]),
        "and serialises it the same way, which is to say not at all"
    );

    // An empty zone identifier is a value rather than an absence: the setter
    // stores it, the getter returns it with `CURLUE_OK` -- `CURLUPART_ZONEID`
    // has no `CURLU_GET_EMPTY` gate, unlike the query at L1613-L1615 -- and a
    // bracketed host then serialises a bare `%25`.
    let zoned = parse(b"https://[::1]/", 0).expect("bracketed URL parses");
    assert_eq!(
        zoned.set(abi::CURLUPART_ZONEID, b"", 0),
        abi::CURLUE_OK,
        "an empty zone identifier is accepted"
    );
    let (code, value) = zoned.get(abi::CURLUPART_ZONEID, 0);
    assert_eq!(code, abi::CURLUE_OK, "and read back with no flags");
    assert_eq!(
        value.as_deref(),
        Some(&b""[..]),
        "as the empty string it was set to"
    );
    assert_eq!(
        zoned.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://[::1%25]/"[..]),
        "which serialises as a bare %25 on a bracketed host"
    );
    // Passing null clears it instead, `urlset_clear` at L1755-L1756, and then
    // the part really is absent.
    assert_eq!(
        zoned.clear(abi::CURLUPART_ZONEID),
        abi::CURLUE_OK,
        "clearing the zone identifier succeeds"
    );
    expect_missing(
        &zoned,
        abi::CURLUPART_ZONEID,
        abi::CURLUE_NO_ZONEID,
        "a cleared zone identifier is absent rather than empty",
    );
    assert_eq!(
        zoned.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://[::1]/"[..]),
        "and the URL loses the %25 with it"
    );
}

#[test]
fn a_failing_host_setter_still_destroys_the_zone_identifier() {
    // L1846-L1848 releases the zone identifier as part of *selecting* the host
    // field, before the value has been decoded or checked. The validation at
    // L1965-L1991 can then reject the value and return
    // `CURLUE_BAD_HOSTNAME` -- and the zone is gone anyway. Host and path are
    // untouched, so this is a partial mutation on a failing call, and it is
    // observable through the public API, which the truncation half of FB4 is
    // not.
    let handle = parse(b"https://[fe80::1%25eth0]/p", 0).expect("zoned URL parses");
    assert_eq!(
        handle.get(abi::CURLUPART_ZONEID, 0).1.as_deref(),
        Some(&b"eth0"[..]),
        "the zone identifier is there to begin with"
    );
    assert_eq!(
        handle.set(abi::CURLUPART_HOST, b"exam{ple.net", 0),
        abi::CURLUE_BAD_HOSTNAME,
        "the host setter rejects the value at L1987-L1989"
    );
    expect_missing(
        &handle,
        abi::CURLUPART_ZONEID,
        abi::CURLUE_NO_ZONEID,
        "yet the zone identifier was released before the check ran",
    );
    assert_eq!(
        handle.get(abi::CURLUPART_HOST, 0).1.as_deref(),
        Some(&b"[fe80::1]"[..]),
        "while the host itself is unchanged, because L1994-L1995 never ran"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://[fe80::1]/p"[..]),
        "so the URL is the old one minus a zone it can no longer show"
    );
}

#[test]
fn the_host_setter_reports_every_address_fault_as_a_bad_hostname() {
    // The parse path answers `CURLUE_BAD_IPV6`, 22, straight from
    // `ipv6_parse`. The setter funnels the same failure through `bad = TRUE`
    // at L1981-L1982 and returns `CURLUE_BAD_HOSTNAME`, 21, at L1987-L1989, so
    // the same input yields two different codes depending on which entry point
    // saw it. Worth pinning, because a port that forwarded the inner code would
    // pass every whole-URL test and still be wrong here.
    let handle = parse(b"https://example.org/", 0).expect("base URL parses");
    for (value, why) in [
        (&b"[fe80::1%25abcdefghijklmnop]"[..], "a 16-byte zone"),
        (&b"[1]"[..], "shorter than four bytes"),
        (&b"[fe80::20c:29gf]"[..], "an illegal byte"),
        (&b"%25"[..], "an escape that decodes to a percent sign"),
    ] {
        assert_eq!(
            handle.set(abi::CURLUPART_HOST, value, 0),
            abi::CURLUE_BAD_HOSTNAME,
            "{why}: the host setter reports one code for every fault"
        );
    }
    // And the host is still the original, since none of those reached L1993.
    assert_eq!(
        handle.get(abi::CURLUPART_HOST, 0).1.as_deref(),
        Some(&b"example.org"[..]),
        "four rejected values later, the host is untouched"
    );
    // A value the setter accepts is stored as written rather than decoded,
    // which is the mirror image of the parse path: `https://%41` stores the
    // letter A, while `curl_url_set(CURLUPART_HOST, "%41")` stores the three
    // bytes `%41`. L1974-L1983 decodes only to run the check, then frees the
    // copy, and L1994-L1995 stores `newp`.
    assert_eq!(
        handle.set(abi::CURLUPART_HOST, b"%41", 0),
        abi::CURLUE_OK,
        "an escape that decodes to a legal byte is accepted"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_HOST, 0).1.as_deref(),
        Some(&b"%41"[..]),
        "and stored still encoded, unlike the parse path"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://%41/"[..]),
        "so the URL carries the escape rather than the letter"
    );
    // The setter does not normalise an address, either: `ipv4_normalize` is
    // reached from `parse_authority` L634 and from nowhere in `curl_url_set`.
    assert_eq!(
        handle.set(abi::CURLUPART_HOST, b"16843009", 0),
        abi::CURLUE_OK,
        "a one-part numeric address is a legal hostname"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_HOST, 0).1.as_deref(),
        Some(&b"16843009"[..]),
        "and the setter leaves it exactly as written"
    );
}

// ---------------------------------------------------------------------------
// Port extraction, and finding FB4.
// ---------------------------------------------------------------------------
//
// The port is cut off the authority by the internal extractor at
// `lib/urlapi.c` L335-L387 -- named here in prose only, because it is exported
// under `#ifdef UNITTESTS` alone and is out of reach of this file by design.
// It finds the separator two different ways: for a bracketed host, the byte
// after the `]` at L343-L354, which must be `:` or nothing; otherwise the first
// `:` anywhere in the authority at L356-L357.
//
// **FB4, the bare-colon leniency, L359-L376.** A separator with no digits after
// it is not an error: the code cuts the name off at the colon, ignores it, and
// lets the default port apply. The in-source rationale is browser
// compatibility, L363-L365 -- Firefox, Chrome and Safari all behave this way --
// and it is conditioned on a scheme being present so that "something that looks
// like a scheme" does not get to work, L367-L368. Concretely `L373` is
// `return has_scheme ? CURLUE_OK : CURLUE_BAD_PORT_NUMBER`, and both branches
// are covered below.
//
// FB4 has a second half that is worth stating even though it turns out not to
// be assertable. The truncation at L370, `curlx_dyn_setlen(host, keep)`,
// happens *before* both failing returns, at L373 and at L376, so inside the
// extractor the host stays cut even when the call reports an error. It cannot
// be observed through the public API, and the reason is a property of the
// parser rather than a gap in this test: `parseurl` L1122 builds into a `struct
// dynbuf` local to itself and `parseurl_and_replace` L1197-L1209 copies the
// temporary over the live handle only when the parse succeeded, freeing
// everything at L1188-L1191 otherwise. A failing whole-URL set therefore leaves
// no truncated host anywhere a caller can reach. The host setter cannot reach
// it either: `curl_url_set(CURLUPART_HOST, ...)` never calls the extractor at
// all. So rather than assert something untestable, the atomicity that hides it
// is asserted directly, below.

#[test]
fn a_bare_colon_is_ignored_when_a_scheme_is_present() {
    // FB4's success branch. The colon and everything the extractor cut with it
    // are simply gone: the host is the name alone and no port is stored, so
    // `CURLUPART_PORT` reports `CURLUE_NO_PORT`, 15, and the URL comes back
    // without a colon.
    let input = &b"https://example.com:/path"[..];
    expect_url(
        input,
        0,
        0,
        "https://example.com/path",
        "FB4: a scheme is present, so the bare colon is ignored",
    );
    expect_part(
        input,
        0,
        abi::CURLUPART_HOST,
        0,
        "example.com",
        "FB4: the host was cut at the colon by L370",
    );
    let handle = parse(input, 0).expect("FB4: the bare colon parses");
    expect_missing(
        &handle,
        abi::CURLUPART_PORT,
        abi::CURLUE_NO_PORT,
        "FB4: nothing was stored as a port",
    );
    // "lets the default port apply" is exactly what L1586-L1594 then does.
    expect_part(
        input,
        0,
        abi::CURLUPART_PORT,
        abi::CURLU_DEFAULT_PORT,
        "443",
        "FB4: and the scheme's default is what a caller asking for one gets",
    );

    // The same case in bracketed form. The input comes from `unit1653.c`
    // L166-L170, which drives the extractor directly with `has_scheme` true;
    // the expectation here is re-derived for the full pipeline, where the
    // scheme is what makes `has_scheme` true -- `parseurl` L1149-L1150 passes
    // `u->scheme != NULL` -- and where `ipv6_parse` runs afterwards and
    // normalises the address.
    let bracketed = &b"https://[fe80::250:56ff:fea7:da15]:/"[..];
    expect_url(
        bracketed,
        0,
        0,
        "https://[fe80::250:56ff:fea7:da15]/",
        "FB4: a bracketed host with a bare colon, from unit1653.c L166-L170",
    );
    let handle = parse(bracketed, 0).expect("FB4: the bracketed form parses");
    expect_missing(
        &handle,
        abi::CURLUPART_PORT,
        abi::CURLUE_NO_PORT,
        "FB4: no port from a bracketed host either",
    );
}

#[test]
fn a_bare_colon_without_a_scheme_is_a_bad_port_number() {
    // FB4's failing branch, and the input is `unit1653.c` L207-L208: 64 letter
    // `a`s followed by a colon. The expectation is re-derived rather than
    // copied, and the derivation is what makes the case work at all.
    //
    // Reaching this through the public API needs a parse in which no scheme is
    // found, because that is the only way `has_scheme` is false. The 64-byte run
    // supplies it: `Curl_is_absolute_url` L195 scans at most `MAX_SCHEME_LEN`,
    // 40, bytes, so it stops with `url[40]` still a letter rather than the colon
    // L206 requires and reports "not absolute". `parse_scheme` L964-L965 then
    // needs a flag to proceed at all, and with `CURLU_GUESS_SCHEME` it takes the
    // L967-L973 branch, which leaves `u->scheme` null and hands the whole input
    // to the authority parser. `parseurl` L1149-L1150 therefore passes
    // `has_scheme = FALSE`, the extractor finds the trailing colon with no
    // digits after it, and L373 answers `CURLUE_BAD_PORT_NUMBER`, 4 -- which is
    // the same code `unit1653.c` L212 expects, by a different route.
    let sixty_four_a = [b'a'; 64];
    let mut input = Vec::from(&sixty_four_a[..]);
    input.push(b':');
    expect_parse_error(
        &input,
        abi::CURLU_GUESS_SCHEME,
        abi::CURLUE_BAD_PORT_NUMBER,
        "FB4: no scheme, so the bare colon is rejected -- unit1653.c L202-L212",
    );
    // Without a guessing flag the input never gets that far: `parse_scheme`
    // L961-L962 finds neither `CURLU_DEFAULT_SCHEME` nor `CURLU_GUESS_SCHEME`
    // and answers `CURLUE_BAD_SCHEME`, 27. Same input, different code, because
    // the flags decide which stage gets to object first.
    expect_parse_error(
        &input,
        0,
        abi::CURLUE_BAD_SCHEME,
        "the same input with no flags never reaches the port stage",
    );
    // 40 `a`s behave the same way, and for a reason worth pinning: the scan
    // *does* reach a colon at index 40, but L206 also requires the byte after it
    // to be `/` when guessing, and here the string ends. So this is still not an
    // absolute URL, `has_scheme` is still false, and the answer is still
    // `CURLUE_BAD_PORT_NUMBER` -- the "looks like a scheme" case the comment at
    // L367-L368 is about.
    let forty_a = [b'a'; 40];
    let mut short_input = Vec::from(&forty_a[..]);
    short_input.push(b':');
    expect_parse_error(
        &short_input,
        abi::CURLU_GUESS_SCHEME,
        abi::CURLUE_BAD_PORT_NUMBER,
        "FB4: 40 bytes and a colon is not a scheme when guessing",
    );
}

#[test]
fn a_failing_whole_url_set_leaves_the_handle_exactly_as_it_was() {
    // The atomicity that makes FB4's truncation unobservable, asserted as the
    // property it is. `https://second.example.com:80x/b` fails in the port
    // stage at L375-L376, by which point L370 has already cut the temporary's
    // host to `second.example.com` -- and none of that reaches the handle,
    // because L1188-L1191 frees the temporary and L1197-L1209 never runs its
    // copy.
    let handle = parse(b"https://example.com/a", 0).expect("the first URL parses");
    assert_eq!(
        handle.set(abi::CURLUPART_URL, b"https://second.example.com:80x/b", 0),
        abi::CURLUE_BAD_PORT_NUMBER,
        "trailing junk after the port number is rejected at L375-L376"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_HOST, 0).1.as_deref(),
        Some(&b"example.com"[..]),
        "and the live handle still holds the host it had, not a truncated one"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://example.com/a"[..]),
        "nor is any other part of it disturbed"
    );
}

#[test]
fn a_port_number_must_be_digits_and_fit_in_sixteen_bits() {
    // Through the whole-URL path first, where the extractor's own check at
    // L375-L376 is `curlx_str_number(&portptr, &port, 0xffff) || *portptr`:
    // over the ceiling, or anything left over, is `CURLUE_BAD_PORT_NUMBER`, 4.
    expect_parse_error(
        b"https://example.com:80x/",
        0,
        abi::CURLUE_BAD_PORT_NUMBER,
        "trailing junk after the digits",
    );
    expect_parse_error(
        b"https://example.com:65536/",
        0,
        abi::CURLUE_BAD_PORT_NUMBER,
        "one past the 0xffff ceiling",
    );
    expect_url(
        b"https://example.com:65535/",
        0,
        0,
        "https://example.com:65535/",
        "the ceiling itself is fine",
    );
    // Leading zeroes disappear, because L378-L381 does not keep the text: it
    // stores the parsed number and prints it back out, which is what the
    // comment at L379 calls getting rid of leading zeroes.
    expect_part(
        b"https://example.com:0080/",
        0,
        abi::CURLUPART_PORT,
        0,
        "80",
        "the port is regenerated from the number, not kept as text",
    );
    expect_url(
        b"https://example.com:0080/",
        0,
        0,
        "https://example.com:80/",
        "so the serialised URL carries the regenerated form",
    );

    // Then through the setter, `set_url_port` at L1666-L1683, which is a
    // different function with the same two rules plus one of its own: L1670-L1672
    // requires the *first* byte to be a digit before the scanner even runs, so a
    // leading letter is rejected there rather than by the scanner.
    let handle = parse(b"https://example.com/", 0).expect("base URL parses");
    assert_eq!(
        handle.set(abi::CURLUPART_PORT, b"0080", 0),
        abi::CURLUE_OK,
        "the setter accepts leading zeroes"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_PORT, 0).1.as_deref(),
        Some(&b"80"[..]),
        "and regenerates the text at L1676-L1680, same as the parse path"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://example.com:80/"[..]),
        "which is what the URL then carries"
    );
    for (value, why) in [
        (&b"65536"[..], "over the 0xffff ceiling at L1673"),
        (
            &b"80x"[..],
            "trailing junk, the `*provided_port` half of L1673",
        ),
        (
            &b"x80"[..],
            "a leading letter, rejected by !ISDIGIT at L1670-L1672",
        ),
        (
            &b""[..],
            "empty, so byte zero is the terminator and not a digit",
        ),
        (&b"999999999999999999999"[..], "far over the ceiling"),
    ] {
        assert_eq!(
            handle.set(abi::CURLUPART_PORT, value, 0),
            abi::CURLUE_BAD_PORT_NUMBER,
            "{why}"
        );
    }
    // Each of those failed before L1679-L1681 could store anything, so the port
    // set earlier is still there. `set_url_port` frees the old value only after
    // the new one has been formatted successfully.
    assert_eq!(
        handle.get(abi::CURLUPART_PORT, 0).1.as_deref(),
        Some(&b"80"[..]),
        "five rejected values later, the stored port is untouched"
    );
    // Zero is a legal port here: it is a digit, it is under the ceiling, and
    // nothing in this module treats it as absent -- `u->port` non-null is what
    // "has a port" means, at L1583-L1584.
    assert_eq!(
        handle.set(abi::CURLUPART_PORT, b"0", 0),
        abi::CURLUE_OK,
        "zero is a number like any other"
    );
    assert_eq!(
        handle.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://example.com:0/"[..]),
        "and it is serialised as one"
    );
    // Passing null clears it, `urlset_clear` L1758-L1761, which also resets
    // `portnum`.
    assert_eq!(
        handle.clear(abi::CURLUPART_PORT),
        abi::CURLUE_OK,
        "clearing the port succeeds"
    );
    expect_missing(
        &handle,
        abi::CURLUPART_PORT,
        abi::CURLUE_NO_PORT,
        "a cleared port is absent",
    );
    assert_eq!(
        handle.get(abi::CURLUPART_URL, 0).1.as_deref(),
        Some(&b"https://example.com/"[..]),
        "and the URL loses its colon with it"
    );
}

#[test]
fn the_default_port_is_added_on_request_and_suppressed_on_request() {
    // Two flags, two directions, both reading `h->defport` out of the scheme
    // descriptor. With `scheme-table` on that comes from the built-in table at
    // `src/scheme.rs`; with it off, from libcurl by way of `Curl_get_scheme`,
    // which is what `scheme_standin` supplies here. Either way https is 443
    // and http is 80, per `lib/urldata.h` L32-L33.
    //
    // Injection, `curl_url_get` L1586-L1594: no port is stored, the caller asks
    // for a default, so one is formatted into a local buffer and returned.
    expect_part(
        b"https://example.com/",
        0,
        abi::CURLUPART_PORT,
        abi::CURLU_DEFAULT_PORT,
        "443",
        "CURLU_DEFAULT_PORT supplies the scheme's port when none is stored",
    );
    expect_part(
        b"http://example.com/",
        0,
        abi::CURLUPART_PORT,
        abi::CURLU_DEFAULT_PORT,
        "80",
        "and answers per scheme, not with a fixed number",
    );
    // Without the flag the same handle reports the part as missing, which is
    // what makes the flag meaningful.
    let handle = parse(b"https://example.com/", 0).expect("base URL parses");
    expect_missing(
        &handle,
        abi::CURLUPART_PORT,
        abi::CURLUE_NO_PORT,
        "no flag, no port",
    );

    // Suppression, L1595-L1602: a port *is* stored, it equals the scheme's
    // default, and the caller asked for it to be hidden. Note the condition is
    // `h->defport == u->portnum`, a numeric comparison against the stored
    // number rather than a string one.
    expect_part(
        b"https://example.com:443/",
        0,
        abi::CURLUPART_PORT,
        0,
        "443",
        "no flag yet -- the port is genuinely stored and reported",
    );
    let explicit = parse(b"https://example.com:443/", 0).expect("explicit 443 parses");
    let (code, value) = explicit.get(abi::CURLUPART_PORT, abi::CURLU_NO_DEFAULT_PORT);
    assert_eq!(
        code,
        abi::CURLUE_NO_PORT,
        "CURLU_NO_DEFAULT_PORT hides a stored port that equals the default, \
         got {} instead",
        shown(&value)
    );
    // A port that is not the default survives the same flag untouched.
    expect_part(
        b"https://example.com:8443/",
        0,
        abi::CURLUPART_PORT,
        abi::CURLU_NO_DEFAULT_PORT,
        "8443",
        "a non-default port is not what the flag suppresses",
    );

    // The whole-URL path has its own copy of both rules, at L1460-L1476, so it
    // has to be exercised separately: passing the flag to `CURLUPART_URL` is not
    // the same code path as passing it to `CURLUPART_PORT`. lib1560.c L785-L787
    // is this row.
    expect_url(
        b"http://example.com:80",
        0,
        abi::CURLU_NO_DEFAULT_PORT,
        "http://example.com/",
        "lib1560.c L785-L787: the default port is dropped from the URL",
    );
    expect_url(
        b"http://example.com:8080",
        0,
        abi::CURLU_NO_DEFAULT_PORT,
        "http://example.com:8080/",
        "while a non-default port stays in it",
    );
    // And with a bracketed host, to show the suppression is about the port and
    // not about the host's shape.
    expect_url(
        b"https://[::]:443/",
        0,
        abi::CURLU_NO_DEFAULT_PORT,
        "https://[::]/",
        "suppression works the same for a bracketed host",
    );
    expect_url(
        b"https://[::]:8443/",
        0,
        0,
        "https://[::]:8443/",
        "and a non-default port on one is kept",
    );
    // Suppression follows the scheme rather than the number: 443 is https's
    // default and not http's, so the identical port on http is kept.
    expect_url(
        b"http://example.com:443/",
        0,
        abi::CURLU_NO_DEFAULT_PORT,
        "http://example.com:443/",
        "443 is not http's default, so nothing is suppressed",
    );
}

// ---------------------------------------------------------------------------
// The `unit1653.c` vectors, wrapped in a scheme and a path.
// ---------------------------------------------------------------------------
//
// Every input below is transcribed from `tests/unit/unit1653.c`. Not one
// expectation is: each was derived from `lib/urlapi.c` for the full pipeline,
// where `parse_authority` L627 extracts the port and then L634-L651 validates
// the address, a stage the unit test never reaches. See the note at the top of
// this file for three vectors where the two answers differ.
//
// The wrapping is `https://` plus a trailing `/`, so the authority is delimited
// the way `parseurl` L1143 delimits it and a scheme is present -- which is what
// makes `has_scheme` true, matching the `TRUE` argument only one of the unit
// test's own calls passes.

#[test]
fn unit1653_addresses_that_survive_the_whole_pipeline() {
    // unit1653.c L56, no port. Re-derived: the address is valid, so it
    // normalises to itself and no port is stored. The unit test's own
    // assertion at L61-L62 -- that reading the port back fails -- holds here
    // too, and for the same reason.
    let plain = &b"https://[fe80::250:56ff:fea7:da15]/"[..];
    expect_url(
        plain,
        0,
        0,
        "https://[fe80::250:56ff:fea7:da15]/",
        "unit1653.c L56: a valid address with no port, expectation re-derived",
    );
    let handle = parse(plain, 0).expect("unit1653.c L56 parses");
    let (code, value) = handle.get(abi::CURLUPART_PORT, abi::CURLU_NO_DEFAULT_PORT);
    assert_eq!(
        code,
        abi::CURLUE_NO_PORT,
        "unit1653.c L61-L62: no port is stored, got {}",
        shown(&value)
    );

    // unit1653.c L126, an ordinary port. Re-derived: L375-L376 accepts the
    // digits and L378-L381 stores them, and the address still normalises.
    expect_url(
        b"https://[fe80::250:56ff:fea7:da15]:81/",
        0,
        0,
        "https://[fe80::250:56ff:fea7:da15]:81/",
        "unit1653.c L126: port 81, expectation re-derived",
    );

    // unit1653.c L98 and L114, a zone identifier with and without a port. The
    // unit test checks only the port; here the zone identifier is checked as
    // well, because through the full pipeline the address stage runs and
    // records it.
    let zoned_with_port = &b"https://[fe80::250:56ff:fea7:da15%25eth3]:80/"[..];
    expect_url(
        zoned_with_port,
        0,
        0,
        "https://[fe80::250:56ff:fea7:da15%25eth3]:80/",
        "unit1653.c L98: zone identifier and port, expectation re-derived",
    );
    expect_part(
        zoned_with_port,
        0,
        abi::CURLUPART_PORT,
        0,
        "80",
        "unit1653.c L103-L105: port 80, which does agree",
    );
    expect_part(
        zoned_with_port,
        0,
        abi::CURLUPART_ZONEID,
        0,
        "eth3",
        "and the zone identifier the unit test never asks for",
    );
    expect_url(
        b"https://[fe80::250:56ff:fea7:da15%25eth3]/",
        0,
        0,
        "https://[fe80::250:56ff:fea7:da15%25eth3]/",
        "unit1653.c L114: zone identifier, no port, expectation re-derived",
    );

    // unit1653.c L194. Re-derived, and this is the vector where the two answers
    // happen to agree: a zone written without the `%25` escape is accepted, and
    // the address stage reads `eth3` out of it because the L411 skip does not
    // fire on the bytes `et`.
    let unescaped = &b"https://[fe80::250:56ff:fea7:da15%eth3]:80/"[..];
    expect_part(
        unescaped,
        0,
        abi::CURLUPART_ZONEID,
        0,
        "eth3",
        "unit1653.c L194: an unescaped zone identifier, expectation re-derived",
    );
    // It serialises with the escape, so the two spellings converge on output.
    expect_url(
        unescaped,
        0,
        0,
        "https://[fe80::250:56ff:fea7:da15%25eth3]:80/",
        "and comes back out escaped, per L1486-L1487",
    );
}

#[test]
fn unit1653_vectors_the_address_stage_rejects() {
    // unit1653.c L81. The unit test expects success with port 808 at L85-L88,
    // because in isolation the port extractor never looks inside the brackets:
    // it finds the `]`, checks that a `:` follows, and parses `808`. Through the
    // public API the address stage then runs, the L401 `strspn` stops on the
    // `;`, and since that byte is not `%` the answer is `CURLUE_BAD_IPV6`, 22,
    // from L424-L425. **The unit test's expectation is wrong for this path and
    // must not be restored.**
    expect_parse_error(
        b"https://[fe80::250:56ff;fea7:da15]:808/",
        0,
        abi::CURLUE_BAD_IPV6,
        "unit1653.c L81: semicolon inside the brackets, expectation re-derived",
    );
    // unit1653.c L178, and the same story: L182-L185 expects success with port
    // 180, the `strspn` stops on the `!`, and the whole call is
    // `CURLUE_BAD_IPV6`. The unit test's own comment says the port extractor
    // "does not care" about zone syntax, which is true of the extractor and not
    // of the API.
    expect_parse_error(
        b"https://[fe80::250:56ff:fea7:da15!25eth3]:180/",
        0,
        abi::CURLUE_BAD_IPV6,
        "unit1653.c L178: exclamation mark where the percent sign belongs, \
         expectation re-derived",
    );
    // unit1653.c L70, no closing bracket. Here the two paths agree on the code:
    // the extractor itself answers `CURLUE_BAD_IPV6` at L345-L346, before the
    // address stage is reached at all.
    expect_parse_error(
        b"https://[fe80::250:56ff:fea7:da15|",
        0,
        abi::CURLUE_BAD_IPV6,
        "unit1653.c L70: no closing bracket, rejected by L345-L346",
    );
    // unit1653.c L142, a semicolon where the port separator belongs. L349-L351
    // insists the byte after the `]` is a colon, so this is
    // `CURLUE_BAD_PORT_NUMBER`, 4 -- an error about the port and not about the
    // address, even though the address is fine.
    expect_parse_error(
        b"https://[fe80::250:56ff:fea7:da15];81/",
        0,
        abi::CURLUE_BAD_PORT_NUMBER,
        "unit1653.c L142: semicolon after the bracket, rejected by L349-L351",
    );
    // unit1653.c L153, digits with no separator at all, rejected by the same
    // two lines for the same reason.
    expect_parse_error(
        b"https://[fe80::250:56ff:fea7:da15]80/",
        0,
        abi::CURLUE_BAD_PORT_NUMBER,
        "unit1653.c L153: no colon after the bracket",
    );
    // Not a `unit1653` vector, but the same shape one step further along: a
    // valid address, a valid zone, and then a stray byte after the `]`. The
    // address stage would accept it; L349-L351 does not get that far.
    expect_parse_error(
        b"https://[fe80::1%25eth0]x/",
        0,
        abi::CURLUE_BAD_PORT_NUMBER,
        "a stray byte after the bracket, even with a valid zone identifier",
    );
    // lib1560.c L623-L625 and L626-L628 are the same rule with different
    // stray bytes, and are the rows the parity oracle asserts.
    expect_parse_error(
        b"https://[::%25fakeit];80/moo",
        0,
        abi::CURLUE_BAD_PORT_NUMBER,
        "lib1560.c L623-L625: a semicolon instead of the port colon",
    );
    expect_parse_error(
        b"https://[fe80::20c:29ff:fe9c:409b]-80/moo",
        0,
        abi::CURLUE_BAD_PORT_NUMBER,
        "lib1560.c L626-L628: a hyphen instead of the port colon",
    );
}
