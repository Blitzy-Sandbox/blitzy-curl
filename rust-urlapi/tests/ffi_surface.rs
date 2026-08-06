// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The exported C-linkage surface of `curl-urlapi-rs`, driven from Rust.
//!
//! This file does two jobs that no other test in the crate does.
//!
//! It **calls every exported symbol through its C name**, so the thing under
//! test is the archive's ABI rather than a Rust module path. `src/lib.rs`
//! explains why that is the only way in: `src/ffi.rs` declares its
//! exports `pub(crate)` inside `mod exports`, and they reach the symbol table
//! purely by `#[no_mangle]`. A Cargo integration test links the crate as an
//! external crate, so `curl_urlapi_rs::ffi::exports::curl_url_get` is not a
//! nameable path -- while the symbol `curl_url_get` is. The `extern "C"` block
//! below therefore restates the surface exactly as
//! `include/curl/urlapi.h` L113-L149 and `lib/urlapi-int.h` L28-L33 declare
//! it, which makes any signature drift a link or type error here.
//!
//! And it **asserts that the six faithfully reproduced findings are still
//! reproduced**, which is acceptance criterion `A10` of the Agent Action Plan
//! at its 0.9.2. Those assertions read backwards on first encounter: a test
//! named `fb1_..._is_preserved` fails when the implementation behaves *more*
//! sensibly than `lib/urlapi.c`, because the plan's 0.8.1 requires apparent
//! bugs to be reproduced and noted rather than silently fixed.
//!
//! # Where each finding is covered
//!
//! | Finding | Covered by |
//! |---------|------------|
//! | `FB1` duplication drops the guessed-scheme flag | this file, `fb1_dup_drops_guessed_scheme_is_preserved` |
//! | `FB2` the credential exit path nulls three fields | this file, `fb2_authority_wipes_credentials_is_preserved` |
//! | `FB3` the zone identifier is never cleared | this file, `fb3_stale_zoneid_survives_authority_change_is_preserved` |
//! | `FB4` a bare colon is a valid port, with a scheme | `rust-urlapi/tests/host_ip.rs` |
//! | `FB5` one header declaration names no parameter | `rust-urlapi/include/curl_urlapi_rs.h`, not reachable from Rust |
//! | `FB6` two writes land one byte past the logical length | this file, `fb6_terminator_capacity_is_modelled`, indirectly |
//!
//! `rust-urlapi/docs/KNOWN-DIVERGENCES.md` is the authority for all six. Two of
//! them, `FB2` and `FB3`, are leaks in the C as well as behaviours, and only the
//! API-visible half is reproduced: `Drop` on an owned buffer releases what the C
//! abandons. A leak is invisible to `curl_url_get()`, `curl_url_set()` and
//! `curl_url_dup()`, so no assertion here can see the difference, and the tests
//! say so at their sites.
//!
//! # Two things this file needs that a test would not normally need
//!
//! An integration test may panic -- that is how it reports failure -- and it
//! must use `unsafe` to reach an `extern "C"` entry point. The crate root's
//! denial of the panicking constructs and the prohibition on `unsafe` outside
//! FFI code both bind *library* code. Every `unsafe` block here still carries a
//! `// SAFETY:` comment naming the precondition it relies on, and the lint that
//! requires one is switched on below rather than left to discipline.
//!
//! `Curl_parse_port` is deliberately absent. `lib/urlapi-int.h` L35-L38 puts
//! it behind `#ifdef UNITTESTS`, so it is not one of the eight symbols the
//! object file being replaced defines, and `tests/unit/unit1653.c` -- which
//! is the only caller -- is reportable constraint `R2` of the plan at its
//! 0.2.4.2. Testing it would require the crate to export a ninth symbol, which
//! the symbol-set comparison `rust-urlapi/scripts/check-abi.sh` is to perform
//! would then reject.

// A `// SAFETY:` comment on every `unsafe` block and on the one `unsafe impl`,
// enforced rather than assumed. This is the same posture the crate root's lint
// block takes for the library, restated here because a test crate inherits no
// lint configuration from the crate it links.
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_char, c_uint, c_void, CStr};
use core::{mem, ptr};
use std::ffi::CString;

use libc::size_t;

use curl_urlapi_rs::abi::{
    CURLUPart, CURLUcode, CURLUE_BAD_HANDLE, CURLUE_BAD_HOSTNAME, CURLUE_BAD_IPV6,
    CURLUE_BAD_PARTPOINTER, CURLUE_BAD_PORT_NUMBER, CURLUE_BAD_SCHEME, CURLUE_MALFORMED_INPUT,
    CURLUE_NO_FRAGMENT, CURLUE_NO_HOST, CURLUE_NO_OPTIONS, CURLUE_NO_PASSWORD, CURLUE_NO_PORT,
    CURLUE_NO_QUERY, CURLUE_NO_SCHEME, CURLUE_NO_USER, CURLUE_NO_ZONEID, CURLUE_OK,
    CURLUE_UNKNOWN_PART, CURLUE_UNSUPPORTED_SCHEME, CURLUE_USER_NOT_ALLOWED, CURLUPART_FRAGMENT,
    CURLUPART_HOST, CURLUPART_OPTIONS, CURLUPART_PASSWORD, CURLUPART_PATH, CURLUPART_PORT,
    CURLUPART_QUERY, CURLUPART_SCHEME, CURLUPART_URL, CURLUPART_USER, CURLUPART_ZONEID,
    CURLU_ALLOW_SPACE, CURLU_APPENDQUERY, CURLU_DEFAULT_PORT, CURLU_DEFAULT_SCHEME,
    CURLU_DISALLOW_USER, CURLU_GET_EMPTY, CURLU_GUESS_SCHEME, CURLU_NON_SUPPORT_SCHEME,
    CURLU_NO_AUTHORITY, CURLU_NO_DEFAULT_PORT, CURLU_NO_GUESS_SCHEME, CURLU_PUNY2IDN,
    CURLU_PUNYCODE, CURLU_URLDECODE, CURLU_URLENCODE, CURL_MAX_INPUT_LENGTH, MAX_SCHEME_LEN,
};

// `CURLUE_TOO_LARGE` is read only by the `strerror`-gated test, so importing it
// unconditionally would be an unused import in the drop-in configuration -- and
// an unused import is a warning, which the zero-warning requirement makes a
// failure.
#[cfg(feature = "strerror")]
use curl_urlapi_rs::abi::CURLUE_TOO_LARGE;

/// The opaque handle behind `CURLU *`.
///
/// `include/curl/urlapi.h` L107 is `typedef struct Curl_URL CURLU;` with no
/// definition anywhere public, so a consumer has a pointer and nothing else.
/// This declaration says exactly that and no more: a zero-sized field makes
/// the type impossible to construct or to read through by accident, which is
/// the property an opaque handle is supposed to have. Nothing in this file
/// dereferences it.
#[repr(C)]
pub struct CurlUrl {
    _opaque: [u8; 0],
}

/// The C scalar carrying curl's `bool` across the two internal entry points.
///
/// `lib/curl_setup.h` gives `bool` one of three representations and which one
/// is a property of the libcurl this archive is linked beside, not of the
/// crate. `exports::CurlBool` in `src/ffi.rs` selects between them on the
/// `curl_bool_int` and `curl_bool_enum` cfg flags that `build.rs` emits from
/// `CURL_URLAPI_CURL_BOOL`, and this alias mirrors all three arms so that the
/// test and the crate cannot disagree about the argument width in any
/// configuration.
#[cfg(not(any(curl_bool_int, curl_bool_enum)))]
type CurlBool = u8;

/// The `typedef int bool` arm, `lib/curl_setup.h` L1007-L1012.
#[cfg(curl_bool_int)]
type CurlBool = core::ffi::c_int;

/// The `typedef enum { bool_false, bool_true } bool` arm,
/// `lib/curl_setup.h` L1020-L1024.
#[cfg(curl_bool_enum)]
type CurlBool = c_uint;

const C_TRUE: CurlBool = 1;

const C_FALSE: CurlBool = 0;

// The names are C identifiers and must stay spelled the way libcurl spells
// them, so the Rust naming convention cannot apply. The allowance is scoped to
// this block.
#[allow(non_snake_case)]
extern "C" {
    /// `include/curl/urlapi.h` L113, `lib/urlapi.c` L1288-L1291.
    fn curl_url() -> *mut CurlUrl;

    /// `include/curl/urlapi.h` L120, `lib/urlapi.c` L1293-L1299.
    fn curl_url_cleanup(handle: *mut CurlUrl);

    /// `include/curl/urlapi.h` L126, `lib/urlapi.c` L1310-L1332.
    ///
    /// `const CURLU *` in the C, so `*const` here: the handle is read, never
    /// written.
    fn curl_url_dup(input: *const CurlUrl) -> *mut CurlUrl;

    /// `include/curl/urlapi.h` L133-L134, `lib/urlapi.c` L1541-L1633.
    fn curl_url_get(
        handle: *const CurlUrl,
        what: CURLUPart,
        part: *mut *mut c_char,
        flags: c_uint,
    ) -> CURLUcode;

    /// `include/curl/urlapi.h` L141-L142, `lib/urlapi.c` L1805-L1998.
    fn curl_url_set(
        handle: *mut CurlUrl,
        what: CURLUPart,
        part: *const c_char,
        flags: c_uint,
    ) -> CURLUcode;

    /// `lib/urlapi-int.h` L28-L29, `lib/urlapi.c` L182-L220.
    ///
    /// Consumed by `lib/http1.c` L220, `lib/url.c` L1661 and `lib/http.c`
    /// L1177, which is why the archive has to define it.
    fn Curl_is_absolute_url(
        url: *const c_char,
        buf: *mut c_char,
        buflen: size_t,
        guess_scheme: CurlBool,
    ) -> size_t;

    /// `lib/urlapi-int.h` L33, `lib/urlapi.c` L223-L239.
    ///
    /// Consumed by `lib/doh.c` L1127.
    fn Curl_junkscan(url: *const c_char, urllen: *mut size_t, allowspace: CurlBool) -> CURLUcode;

    /// `lib/urlapi-int.h` L31, `lib/urlapi.c` L657-L675.
    ///
    /// Consumed by `lib/http2.c` L739 for HTTP/2 server push. `FB2` and `FB3`
    /// are reachable through this exported entry point, which is why they are
    /// asserted against it below. The one in-tree caller does not trigger
    /// either: `set_transfer_url` builds a fresh handle with `curl_url()` and
    /// sets only the scheme before this call, so there are no credentials and no
    /// zone identifier for it to discard.
    fn Curl_url_set_authority(u: *mut CurlUrl, authority: *const c_char) -> CURLUcode;
}

// The two feature-gated exports, each declared only in the configuration that
// defines it. Neither is implemented in `lib/urlapi.c` at all, so neither is
// among the eight symbols the object file being replaced defines: in the
// drop-in link `strerror.c.o` supplies `curl_url_strerror` and `escape.c.o`
// supplies `curl_free`. Declaring either import unconditionally would make
// this test binary demand a symbol that nothing in that configuration defines,
// which is the mirror image of the duplicate-definition failure the crate's own
// features exist to avoid.
#[cfg(feature = "strerror")]
extern "C" {
    /// `include/curl/urlapi.h` L149, `lib/strerror.c` L420-L531.
    fn curl_url_strerror(code: CURLUcode) -> *const c_char;
}

#[cfg(feature = "cfree")]
extern "C" {
    /// `lib/escape.c` L189-L192.
    fn curl_free(p: *mut c_void);
}

/// The two scheme-table entry points libcurl would supply in drop-in mode.
///
/// # Why this module exists at all
///
/// With `scheme-table` off -- which is the drop-in configuration,
/// `--no-default-features --features idn-libidn2` -- `src/scheme.rs` selects
/// `crate::ffi::scheme_import` as its backend, and that module declares
/// `Curl_get_scheme` and `Curl_getn_scheme` as imports from `lib/url.c`
/// L1469-L1541. In a real drop-in link libcurl defines them. In a `cargo test`
/// link nothing does, and because that module's `get_scheme` and `getn_scheme`
/// call them from a path `curl_url_set` reaches, the linker cannot
/// discard the reference: without this module the test binary fails to link
/// with two undefined symbols and the drop-in configuration could not be
/// tested at all.
///
/// So this module stands in for libcurl, which is exactly the role the real
/// libcurl plays in the mode being tested.
///
/// # Why nine rows and only one meaningful flag bit
///
/// `lib/urlapi.c` reads three members of the descriptor and no others: the
/// `PROTOPT_URLOPTIONS` bit of `flags`, tested at its L290 and L1477;
/// `defport`, read at L1465, L1472, L1591 and L1599; and whether `run` is
/// null, tested at L1646. Every other member is unobservable through the URL
/// API, so the rows below carry the URL-options bit and nothing else in
/// `flags`, and say so rather than transcribing bits no assertion can see.
///
/// The nine rows are the nine protocols `tests/data/test1560` declares as
/// required features -- file, https, http, pop3, smtp, imap, ldap, dict, ftp
/// -- which is the set the plan's 0.6.7 identifies as the minimum a standalone
/// table must cover. Their default ports are `lib/urldata.h` L29-L53 and the
/// three carrying the URL-options bit are the mail and message-retrieval
/// protocols, matching `src/scheme.rs`'s own table for the same names. Every
/// row is marked implemented, which models the reference build the parity run
/// compares against.
///
/// A name outside the nine resolves to null, which is what libcurl answers for
/// a scheme its table does not hold. No assertion in this file depends on a
/// scheme being present in one configuration and absent in the other: the only
/// unknown scheme used is `gargle`, which neither this table nor
/// `src/scheme.rs`'s 33-row one contains.
#[cfg(not(feature = "scheme-table"))]
mod libcurl_scheme_stand_in {
    use core::ffi::{c_char, CStr};
    use core::{mem, ptr, slice};

    use libc::size_t;

    /// Mirror of `struct Curl_scheme`, `lib/urldata.h` L515-L524.
    ///
    /// The field order and the widths are the contract, because
    /// `scheme_import::describe` in `src/ffi.rs` reads `flags` and `defport`
    /// through a pointer to this shape and locates them by the offsets the
    /// members before them produce. [`layout_matches_the_crate_s_mirror`]
    /// pins it.
    ///
    /// `run` is a nullable function pointer rather than `*const c_void`, which
    /// is what lets the table below be a `static`: a raw pointer is not `Sync`
    /// and a function pointer is, and the crate only ever tests this member
    /// against null. Rust guarantees no relationship between function-pointer
    /// and data-pointer representation, so nothing here assumes one -- the test
    /// asserts that the two happen to agree on the target being built, and
    /// asserts each subsequent field's offset directly, so a target where they
    /// disagree fails loudly instead of silently shifting `flags` and
    /// `defport`.
    ///
    /// Every member is written and none is read from Rust, because the reader
    /// is the crate on the other side of a raw pointer. That is what the
    /// dead-code allowance is for.
    #[allow(dead_code)]
    #[repr(C)]
    pub struct CurlScheme {
        /// L516-L517, `const char *`.
        name: *const c_char,
        /// L518 in the C is `const struct Curl_protocol *run`; only its
        /// nullness is ever read, at `lib/urlapi.c` L1646.
        run: Option<extern "C" fn()>,
        /// L518-L519, `curl_prot_t`, 32 bits while `PROTO_TYPE_SMALL` is
        /// defined. Never read, but its width places `flags` and `defport`.
        protocol: u32,
        /// L520-L521, `curl_prot_t`. Never read, same caveat.
        family: u32,
        /// L522, `uint32_t` of `PROTOPT_*` bits.
        flags: u32,
        /// L523, `uint16_t`.
        defport: u16,
    }

    /// A `static` array of descriptors, wrapped so that it can be one.
    ///
    /// `CurlScheme` holds a raw pointer, so it is not `Sync` and cannot be
    /// placed in a `static` directly. The wrapper carries the assertion
    /// instead.
    pub struct Descriptors(&'static [CurlScheme]);

    // SAFETY: every field of every descriptor is either a plain integer or a
    // pointer into this binary's read-only data -- the `name` pointers address
    // string literals with `'static` storage and the `run` slots address a
    // `'static` function. Nothing is ever written after initialisation and no
    // interior mutability is present, so concurrent shared access from any
    // number of threads reads immutable memory. That is precisely the
    // condition `Sync` asks for, and it is the same condition libcurl's own
    // `const struct Curl_scheme` objects satisfy.
    unsafe impl Sync for Descriptors {}

    /// The address the `run` member points at when a protocol is implemented.
    ///
    /// Its identity is irrelevant and it is never called; `lib/urlapi.c` L1646
    /// only tests the pointer against null. A function with `'static` storage
    /// is the cheapest thing that gives a stable non-null address inside a
    /// `static` initialiser.
    extern "C" fn implemented_marker() {}

    /// `PROTOPT_URLOPTIONS`, `lib/urldata.h` L545.
    ///
    /// Restated here as a literal rather than imported from
    /// `curl_urlapi_rs::abi` on purpose: this module models *libcurl's* side
    /// of the boundary, and a stand-in that derived its bit position from the
    /// code under test could not detect a change to it.
    const URL_OPTIONS: u32 = 1 << 10;

    macro_rules! descriptor {
        ($name:literal, $defport:expr, $flags:expr) => {
            CurlScheme {
                // A trailing NUL makes the literal a C string, and
                // `str::as_ptr` is `const`, so the whole row is a constant.
                name: concat!($name, "\0").as_ptr().cast::<c_char>(),
                run: Some(implemented_marker),
                protocol: 0,
                family: 0,
                flags: $flags,
                defport: $defport,
            }
        };
    }

    /// The nine rows, in the order `scripts/schemetable.c` L33-L65 lists them.
    static TABLE: Descriptors = Descriptors(&[
        descriptor!("dict", 2628, 0),
        // The one row with no default port, `lib/urldata.h` has no PORT_FILE.
        descriptor!("file", 0, 0),
        descriptor!("ftp", 21, 0),
        descriptor!("http", 80, 0),
        descriptor!("https", 443, 0),
        descriptor!("imap", 143, URL_OPTIONS),
        descriptor!("ldap", 389, 0),
        descriptor!("pop3", 110, URL_OPTIONS),
        descriptor!("smtp", 25, URL_OPTIONS),
    ]);

    /// `Curl_get_scheme`, `lib/url.c` L1469-L1472.
    ///
    /// # Safety
    ///
    /// `scheme` must be null or a NUL-terminated C string that stays valid and
    /// unmodified for the duration of the call. That is what
    /// `scheme_import::get_scheme` in `src/ffi.rs` passes: `CStr::as_ptr` on
    /// a live borrow.
    #[no_mangle]
    #[allow(non_snake_case)]
    pub unsafe extern "C" fn Curl_get_scheme(scheme: *const c_char) -> *const CurlScheme {
        if scheme.is_null() {
            return ptr::null();
        }
        // SAFETY: `scheme` is non-null by the test above and NUL-terminated,
        // valid and unmodified for this call by the function's precondition.
        // The borrow does not outlive this statement and `lookup` retains no
        // part of it.
        let name = unsafe { CStr::from_ptr(scheme) }.to_bytes();
        lookup(name)
    }

    /// `Curl_getn_scheme`, `lib/url.c` L1477-L1541.
    ///
    /// The `len && (len <= 7)` guard is L1524's, reproduced so that an
    /// over-long name answers null here exactly as it would in libcurl --
    /// seven bytes is `gophers`, the longest name the real table holds.
    ///
    /// # Safety
    ///
    /// `scheme` must be null, or point to `len` readable, initialised bytes
    /// that stay valid and unmodified for the duration of the call. No
    /// terminator is required. That is what `scheme_import::getn_scheme` in
    /// `src/ffi.rs` passes.
    #[no_mangle]
    #[allow(non_snake_case)]
    pub unsafe extern "C" fn Curl_getn_scheme(
        scheme: *const c_char,
        len: size_t,
    ) -> *const CurlScheme {
        if scheme.is_null() || len == 0 || len > 7 {
            return ptr::null();
        }
        // SAFETY: `scheme` is non-null and `len` is non-zero, both checked
        // above, and by the function's precondition the pointer addresses
        // `len` readable, initialised bytes that stay valid and unmodified for
        // this call. `u8` and `c_char` share size and alignment, so the cast
        // changes only the sign ascribed to the bytes. The borrow does not
        // outlive this statement.
        let name = unsafe { slice::from_raw_parts(scheme.cast::<u8>(), len) };
        lookup(name)
    }

    fn lookup(name: &[u8]) -> *const CurlScheme {
        for row in TABLE.0 {
            // SAFETY: `row.name` was initialised from a NUL-terminated string
            // literal with `'static` storage in the `static` above, so it is
            // non-null, aligned, readable and terminated for the whole
            // program. The borrow does not outlive this statement.
            let stored = unsafe { CStr::from_ptr(row.name) }.to_bytes();
            if stored.len() == name.len()
                && stored
                    .iter()
                    .zip(name.iter())
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
            {
                return row;
            }
        }
        ptr::null()
    }

    /// The mirror must have the layout `scheme_import::CurlScheme` in
    /// `src/ffi.rs` assumes.
    ///
    /// The three offsets the crate depends on are asserted directly, because a
    /// total size can be right while a field sits in the wrong place. On a
    /// 64-bit target: `name` 8 at 0, `run` 8 at 8, `protocol` 4 at 16, `family`
    /// 4 at 20, `flags` 4 at 24, `defport` 2 at 28, two bytes of tail padding,
    /// 32 in all. A 64-bit `curl_prot_t` would make it 40, so the size
    /// discriminates that case too. Twenty-four bytes on a 32-bit target.
    ///
    /// The first assertion is the one that would otherwise be an assumption:
    /// `run` is a function pointer and the C member it mirrors is a data
    /// pointer, and Rust guarantees nothing about the two having the same
    /// representation. This asserts it for the target actually being built,
    /// which is the only scope in which it can be asserted at all.
    #[test]
    fn layout_matches_the_crate_s_mirror() {
        let pointer_width = mem::size_of::<*const c_char>();
        assert_eq!(
            mem::size_of::<Option<extern "C" fn()>>(),
            pointer_width,
            "on this target a function pointer is not the width of a data \
             pointer, so `run` cannot stand in for `const struct \
             Curl_protocol *`"
        );
        assert_eq!(
            mem::align_of::<Option<extern "C" fn()>>(),
            mem::align_of::<*const c_char>(),
            "on this target a function pointer is not aligned like a data \
             pointer, so the members after `run` would move"
        );

        assert_eq!(mem::offset_of!(CurlScheme, name), 0);
        assert_eq!(mem::offset_of!(CurlScheme, run), pointer_width);
        assert_eq!(
            mem::offset_of!(CurlScheme, protocol),
            2 * pointer_width,
            "protocol must follow the two pointers with no padding"
        );
        assert_eq!(
            mem::offset_of!(CurlScheme, family),
            2 * pointer_width + 4,
            "family must follow protocol, so curl_prot_t is 32 bits here"
        );
        assert_eq!(
            mem::offset_of!(CurlScheme, flags),
            2 * pointer_width + 8,
            "flags is read through this offset by ffi::scheme_import"
        );
        assert_eq!(
            mem::offset_of!(CurlScheme, defport),
            2 * pointer_width + 12,
            "defport is read through this offset by ffi::scheme_import"
        );

        let expected = match pointer_width {
            8 => 32,
            4 => 24,
            other => panic!("unexpected pointer width {other}"),
        };
        assert_eq!(
            mem::size_of::<CurlScheme>(),
            expected,
            "the struct Curl_scheme stand-in no longer has the shape \
             ffi::scheme_import reads through it"
        );
        assert_eq!(mem::align_of::<CurlScheme>(), pointer_width);
    }
}

/// Every part identifier the API defines, in the order
/// `include/curl/urlapi.h` L70-L82 declares them.
///
/// Used by [`Handle::snapshot`] so that a "nothing changed" claim covers the
/// whole handle rather than the parts a test happened to think of.
const ALL_PARTS: [CURLUPart; 11] = [
    CURLUPART_URL,
    CURLUPART_SCHEME,
    CURLUPART_USER,
    CURLUPART_PASSWORD,
    CURLUPART_OPTIONS,
    CURLUPART_HOST,
    CURLUPART_PORT,
    CURLUPART_PATH,
    CURLUPART_QUERY,
    CURLUPART_FRAGMENT,
    CURLUPART_ZONEID,
];

type Part = (CURLUcode, Option<String>);

/// Turns a test vector into a C string.
///
/// Panics on an interior NUL, which is a defect in the vector rather than a
/// property of the API: `curl_url_set` takes `const char *` and measures with
/// `strlen` at `lib/urlapi.c` L1823, so a vector containing a NUL could not
/// express what it meant to express.
fn c_string(value: &str) -> CString {
    CString::new(value).expect("test vector must not contain an interior NUL")
}

/// An owned `CURLU *` that releases itself through the exported
/// `curl_url_cleanup()`.
///
/// The wrapper exists for two reasons. It calls the real export from `Drop`, so
/// a handle is released even when an assertion panics part way through a test
/// and a leak checker run over this binary stays meaningful. And it splits the
/// API by constness exactly as the C header does -- `get`, `dup` and `snapshot`
/// take `&self` because `curl_url_get` and `curl_url_dup` take
/// `const CURLU *` at `include/curl/urlapi.h` L126 and L133, while `set`,
/// `clear` and `set_authority` take `&mut self` because their C counterparts
/// take a mutable `CURLU *` at L141 and `lib/urlapi-int.h` L31. A call that
/// mutated through a shared borrow would not compile, which is the closest
/// Rust can come to checking the C's own contract.
struct Handle(*mut CurlUrl);

impl Handle {
    fn new() -> Self {
        // SAFETY: `curl_url` takes no arguments and has no preconditions. It
        // returns either null or a fresh, exclusively owned handle, and this
        // value becomes that handle's sole owner.
        let raw = unsafe { curl_url() };
        assert!(!raw.is_null(), "curl_url() returned NULL");
        Self(raw)
    }

    fn parse(url: &str, flags: c_uint) -> Self {
        let mut handle = Self::new();
        let code = handle.set(CURLUPART_URL, url, flags);
        assert_eq!(
            code, CURLUE_OK,
            "setting CURLUPART_URL to {url:?} with flags {flags:#x} failed"
        );
        handle
    }

    fn as_const(&self) -> *const CurlUrl {
        self.0.cast_const()
    }

    /// Relinquishes ownership, for the one test that has to sequence
    /// `curl_url_cleanup()` against a buffer it still holds.
    fn into_raw(self) -> *mut CurlUrl {
        let raw = self.0;
        // Suppresses this value's `Drop`, so the handle is released exactly
        // once -- by whoever now holds the pointer.
        mem::forget(self);
        raw
    }

    /// `curl_url_get()`, with the returned buffer copied and released.
    ///
    /// The copy is what makes this safe to hand back: the pointer
    /// `curl_url_get` produces is the caller's to free, `docs/libcurl/
    /// curl_url_get.md` L45 says so and `include/curl/urlapi.h` L130-L131
    /// repeats it, and `libc::free` is the correct release in every
    /// configuration this crate builds. `src/alloc.rs` is the sole producer of
    /// C-visible memory in the crate and it allocates through the C allocator,
    /// so a plain `free` -- which is what `curl_free` resolves to in both
    /// supported link modes -- matches the allocator that produced the block.
    /// `rust-urlapi/docs/MEMORY-OWNERSHIP.md` records the whole chain and the
    /// two configurations it excludes.
    ///
    /// The buffer is never written through, which `curl_url_get.md` L46 asks
    /// of a caller even though the `char *` type does not enforce it.
    ///
    /// # The code decides, not the pointer
    ///
    /// `lib/urlapi.c` L1552 writes null into the caller's slot on entry, before
    /// anything can fail, and every failing return sits after it -- so a failing
    /// call is required to leave the slot null, and this helper *asserts* that
    /// rather than relying on it. The order is what makes the helper fail safely:
    /// were the pointer inspected first, a defect that returned an error
    /// alongside a stale or dangling pointer would be dereferenced here, and the
    /// test would commit undefined behaviour at exactly the moment it was
    /// supposed to report a contract violation. Only a `CURLUE_OK` result is
    /// read, and only a `CURLUE_OK` result is released.
    /// # Release before anything that can fail
    ///
    /// The order of the three steps below is deliberate: copy the bytes with
    /// an infallible operation, **release**, and only then decode. The
    /// tempting order -- decode into a `String` and free afterwards -- leaks
    /// the C buffer on the panic path, because the decode is fallible and a
    /// test binary's response to failure is to unwind. That leak is invisible
    /// while every vector is ASCII, which is exactly what makes it worth
    /// designing out rather than relying on: a vector added later that is not
    /// ASCII-compatible would turn every such call into a leak, silently.
    /// `Vec::from` on a byte slice cannot fail, so nothing between the
    /// retrieval and the release can unwind.
    fn get(&self, what: CURLUPart, flags: c_uint) -> Part {
        let mut raw: *mut c_char = ptr::null_mut();
        // SAFETY: `self.0` is a live handle this value owns, so it is non-null,
        // aligned and initialised, and no other pointer to it is in use. `raw`
        // is a local `*mut c_char` that is writable and properly aligned, and
        // it cannot alias the handle. Nothing else touches either during the
        // call, which is single threaded.
        let code = unsafe { curl_url_get(self.as_const(), what, &mut raw, flags) };
        if code != CURLUE_OK {
            assert!(
                raw.is_null(),
                "curl_url_get(part {what}, flags {flags:#x}) failed with {code} \
                 yet stored a pointer; lib/urlapi.c L1552 nulls the slot before \
                 any failing return can be taken"
            );
            return (code, None);
        }
        if raw.is_null() {
            // `CURLUE_OK` with no buffer is an answer rather than a fault: a
            // blank part retrieved under `CURLU_GET_EMPTY` takes the empty
            // dynamic buffer at `lib/urlapi.c` L1399 and reports success. Which
            // vectors reach it stays a property of the vectors.
            return (code, None);
        }

        // SAFETY: `raw` is non-null by the test above, and on this path
        // `curl_url_get` has written a pointer to a NUL-terminated buffer that
        // it allocated and handed to this caller. Nothing else holds it, so
        // reading it here cannot race, and the borrow ends before the release
        // below. `to_vec` copies, and copying cannot fail, so no unwind can
        // occur between here and that release.
        let bytes = unsafe { CStr::from_ptr(raw) }.to_bytes().to_vec();
        // SAFETY: `raw` came from this crate's C allocator by way of
        // `src/alloc.rs`, has not been released, and no reference into it
        // survives -- `bytes` is an independent copy. This is the documented
        // release, and it happens exactly once for this pointer.
        unsafe { libc::free(raw.cast::<c_void>()) };
        // The buffer is gone by the time this can panic, so a non-ASCII vector
        // would fail the test without also leaking.
        let owned = String::from_utf8(bytes)
            .expect("the URL API returns ASCII-compatible bytes for these vectors");
        (code, owned.into())
    }

    fn code(&self, what: CURLUPart, flags: c_uint) -> CURLUcode {
        self.get(what, flags).0
    }

    fn text(&self, what: CURLUPart, flags: c_uint) -> String {
        let (code, content) = self.get(what, flags);
        assert_eq!(code, CURLUE_OK, "part {what} unexpectedly failed");
        content.expect("CURLUE_OK must come with content for these parts")
    }

    fn set(&mut self, what: CURLUPart, value: &str, flags: c_uint) -> CURLUcode {
        let value = c_string(value);
        // SAFETY: `self.0` is a live handle this value owns exclusively, so the
        // call has the unique access `curl_url_set` requires. `value` is a
        // NUL-terminated C string kept alive by the local binding for the whole
        // call and never modified during it.
        unsafe { curl_url_set(self.0, what, value.as_ptr(), flags) }
    }

    /// `curl_url_set()` with a null value, which clears the part rather than
    /// erroring -- `lib/urlapi.c` L1819-L1821 routes it to `urlset_clear`.
    fn clear(&mut self, what: CURLUPart) -> CURLUcode {
        // SAFETY: `self.0` is a live, exclusively owned handle. A null `part`
        // is the documented way to clear, `include/curl/urlapi.h` L138-L139, so
        // it is a valid argument rather than a violated precondition.
        unsafe { curl_url_set(self.0, what, ptr::null(), 0) }
    }

    fn dup(&self) -> Self {
        // SAFETY: `self.0` is a live handle this value owns; the call reads it
        // and never writes it, which is what `const CURLU *` promises. The
        // result is either null or a fresh handle with no relationship to the
        // original's storage.
        let raw = unsafe { curl_url_dup(self.as_const()) };
        assert!(!raw.is_null(), "curl_url_dup() returned NULL");
        Self(raw)
    }

    /// `Curl_url_set_authority()`, `lib/urlapi-int.h` L31.
    ///
    /// Never called with a null authority. `lib/urlapi.c` L662 guards it with
    /// `DEBUGASSERT(authority)`, which compiles to nothing in a release build,
    /// and L666's `strlen(authority)` then dereferences it -- so a null
    /// argument is undefined behaviour in the C original and there is no parity
    /// oracle for it. `Curl_url_set_authority` in `src/ffi.rs` answers
    /// `CURLUE_MALFORMED_INPUT` instead, which is a defined outcome the C does
    /// not have; that hardening is unobservable to any conforming caller and is
    /// deliberately not exercised here.
    fn set_authority(&mut self, authority: &str) -> CURLUcode {
        let authority = c_string(authority);
        // SAFETY: `self.0` is a live, exclusively owned handle -- the mutable
        // borrow guarantees no other access -- and `authority` is a
        // NUL-terminated C string kept alive by the local binding for the whole
        // call and never modified during it.
        unsafe { Curl_url_set_authority(self.0, authority.as_ptr()) }
    }

    /// Every part of the handle, read with `flags`.
    ///
    /// This is what a "nothing changed" or "the copy matches the original"
    /// claim is measured against. Reading all eleven means such a claim cannot
    /// hold merely because the part that moved was not looked at.
    fn snapshot(&self, flags: c_uint) -> Vec<Part> {
        ALL_PARTS
            .iter()
            .map(|&what| self.get(what, flags))
            .collect()
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the handle this value has owned since it was
        // constructed, it has not been released -- `into_raw` is the only way
        // to relinquish it and that suppresses this `Drop` -- and no other
        // pointer to it or reference into it survives, because `Drop` runs when
        // the sole owner goes away.
        unsafe { curl_url_cleanup(self.0) };
    }
}

/// `Curl_is_absolute_url()` with no output buffer, `lib/urlapi.c` L188.
///
/// Every in-tree caller but one passes null here, and with no buffer there is
/// nothing to size and no second pointer to reason about.
fn scheme_len(url: &str, guess_scheme: CurlBool) -> usize {
    let url = c_string(url);
    // SAFETY: `url` is a NUL-terminated C string kept alive by the local
    // binding for the whole call. A null `buf` is explicitly tolerated by the
    // C at L188-L189 and by `src/ffi.rs`, so `buflen` is unread and zero is a
    // valid argument for it.
    unsafe { Curl_is_absolute_url(url.as_ptr(), ptr::null_mut(), 0, guess_scheme) }
}

/// `Curl_is_absolute_url()` with an output buffer, returning both results.
///
/// The buffer is `MAX_SCHEME_LEN + 1` bytes, which is the size the C demands.
/// `lib/urlapi.c` L186 asserts `!buf || (buflen > MAX_SCHEME_LEN)` and L215
/// writes the terminator *at* index `MAX_SCHEME_LEN` for a forty-byte scheme,
/// so forty-one is the minimum rather than a comfortable margin --
/// `tests/libtest/lib1560.c` L677-L681 requires a forty-byte scheme to parse,
/// which makes the last byte reachable.
///
/// The buffer is pre-filled with a non-zero byte so that L188-L189's
/// unconditional `buf[0] = 0` is observable rather than indistinguishable from
/// a zeroed buffer.
fn scheme_into_buf(url: &str, guess_scheme: CurlBool) -> (usize, Vec<u8>) {
    let url = c_string(url);
    let mut buf = vec![b'Z' as c_char; MAX_SCHEME_LEN + 1];
    // SAFETY: `url` is a NUL-terminated C string alive for the whole call.
    // `buf` is `MAX_SCHEME_LEN + 1` writable, aligned, initialised bytes and
    // `buflen` is exactly that count, which satisfies the C's own requirement
    // that the buffer exceed `MAX_SCHEME_LEN`. `url` and `buf` are distinct
    // allocations, so the two pointers cannot alias.
    let len =
        unsafe { Curl_is_absolute_url(url.as_ptr(), buf.as_mut_ptr(), buf.len(), guess_scheme) };
    let bytes = buf.iter().map(|&byte| byte as u8).collect();
    (len, bytes)
}

fn buf_text(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    bytes.split_at(end).0
}

/// `Curl_junkscan()`, with the out-parameter pre-seeded so that the C's
/// discipline about it is observable.
///
/// `lib/urlapi.c` L237 writes `*urllen` only after both `return` statements
/// above it have been passed, so a failing scan leaves the caller's value
/// alone. The sentinel is returned unchanged in that case, which is what the
/// callers assert.
fn junkscan(url: &str, allowspace: CurlBool) -> (CURLUcode, size_t) {
    let url = c_string(url);
    let mut len: size_t = JUNKSCAN_SENTINEL;
    // SAFETY: `url` is a NUL-terminated C string alive for the whole call, and
    // `len` is a local `size_t` that is writable, aligned and cannot alias it.
    let code = unsafe { Curl_junkscan(url.as_ptr(), &mut len, allowspace) };
    (code, len)
}

/// A value `Curl_junkscan()` would never compute, so that finding it afterwards
/// proves the out-parameter was left alone.
const JUNKSCAN_SENTINEL: size_t = 0x5A5A_5A5A;

/// `curl_url()` hands back a usable, empty handle and `curl_url_cleanup()`
/// releases it.
///
/// The C is `curlx_calloc(1, sizeof(struct Curl_URL))` at `lib/urlapi.c` L1290,
/// so every member starts absent. "Absent" is observable one part at a time,
/// and the codes below are the `ifmissing` values `curl_url_get`'s switch
/// assigns at L1554-L1620 -- with two that are not simply "missing":
/// `CURLUPART_PATH` synthesises `"/"` at L1607-L1609 because the C stores no
/// path for a handle that has none, and `CURLUPART_URL` fails with
/// `CURLUE_NO_HOST` from `urlget_url` at L1448-L1449 rather than with an
/// unknown-part code.
#[test]
fn curl_url_returns_a_zeroed_handle_and_cleanup_releases_it() {
    let handle = Handle::new();

    assert_eq!(handle.code(CURLUPART_SCHEME, 0), CURLUE_NO_SCHEME);
    assert_eq!(handle.code(CURLUPART_USER, 0), CURLUE_NO_USER);
    assert_eq!(handle.code(CURLUPART_PASSWORD, 0), CURLUE_NO_PASSWORD);
    assert_eq!(handle.code(CURLUPART_OPTIONS, 0), CURLUE_NO_OPTIONS);
    assert_eq!(handle.code(CURLUPART_HOST, 0), CURLUE_NO_HOST);
    assert_eq!(handle.code(CURLUPART_PORT, 0), CURLUE_NO_PORT);
    assert_eq!(handle.code(CURLUPART_QUERY, 0), CURLUE_NO_QUERY);
    assert_eq!(handle.code(CURLUPART_FRAGMENT, 0), CURLUE_NO_FRAGMENT);
    assert_eq!(handle.code(CURLUPART_ZONEID, 0), CURLUE_NO_ZONEID);

    // L1607-L1609: a handle with no path reads back as "/", with CURLUE_OK.
    assert_eq!(handle.text(CURLUPART_PATH, 0), "/");
    // L1448-L1449 in urlget_url, reached through L1624-L1625.
    assert_eq!(handle.code(CURLUPART_URL, 0), CURLUE_NO_HOST);

    drop(handle);
}

/// `curl_url_set()` and `curl_url_get()` across a spread of parts and flags.
///
/// One handle carrying all ten strings, then every part read back. The vector
/// is the first entry of the upstream duplication list at
/// `tests/libtest/lib1560.c` L1973-L1979, widened with an `;options`
/// credential so that the options member is populated too -- which needs a
/// scheme whose descriptor carries `PROTOPT_URLOPTIONS`, because
/// `lib/urlapi.c` L288-L290 only asks `Curl_parse_login_details` for options
/// when the scheme's flags have that bit. `imap` is one of the three that do.
#[test]
fn set_and_get_round_trip_every_part() {
    let handle = Handle::parse("imap://user:pwd;opt@[fe80::1%25eth0]:143/path?q=1#frag", 0);

    assert_eq!(handle.text(CURLUPART_SCHEME, 0), "imap");
    assert_eq!(handle.text(CURLUPART_USER, 0), "user");
    assert_eq!(handle.text(CURLUPART_PASSWORD, 0), "pwd");
    assert_eq!(handle.text(CURLUPART_OPTIONS, 0), "opt");
    // The brackets are part of the stored host, `lib/urlapi.c` L421 and L439.
    assert_eq!(handle.text(CURLUPART_HOST, 0), "[fe80::1]");
    // The zone is stored separately, L418, and never inside the host.
    assert_eq!(handle.text(CURLUPART_ZONEID, 0), "eth0");
    assert_eq!(handle.text(CURLUPART_PORT, 0), "143");
    assert_eq!(handle.text(CURLUPART_PATH, 0), "/path");
    assert_eq!(handle.text(CURLUPART_QUERY, 0), "q=1");
    assert_eq!(handle.text(CURLUPART_FRAGMENT, 0), "frag");

    // The whole-URL template, `lib/urlapi.c` L1517-L1532. The zone comes back
    // as `%25eth0` inside the brackets, which L1483-L1487 builds.
    assert_eq!(
        handle.text(CURLUPART_URL, 0),
        "imap://user:pwd;opt@[fe80::1%25eth0]:143/path?q=1#frag"
    );

    // 143 is imap's default port, `lib/urldata.h` L45, so CURLU_NO_DEFAULT_PORT
    // suppresses it -- L1598-L1601 for the part, L1468-L1474 for the whole URL.
    assert_eq!(
        handle.code(CURLUPART_PORT, CURLU_NO_DEFAULT_PORT),
        CURLUE_NO_PORT
    );
    assert_eq!(
        handle.text(CURLUPART_URL, CURLU_NO_DEFAULT_PORT),
        "imap://user:pwd;opt@[fe80::1%25eth0]/path?q=1#frag"
    );
}

/// The flags that change how a part is read, one representative each.
///
/// `CURLU_DEFAULT_PORT` supplies the scheme's port for a handle that has none,
/// `lib/urlapi.c` L1587-L1595. `CURLU_URLENCODE` on set and `CURLU_URLDECODE`
/// on get are inverses for a path, L1888-L1930 and L1373-L1381. The plus sign
/// is the query's alone: `urlencode_str` writes `+` for a space once past the
/// query delimiter, L1898-L1901, and `plusdecode` reverses it at L1612 only for
/// `CURLUPART_QUERY`. Appending inserts the separator itself, L1936-L1962, and
/// spares the first `=` from encoding, L1904-L1908.
#[test]
fn the_read_and_write_flags_do_what_the_c_does() {
    let mut handle = Handle::parse("http://example.com/", 0);

    // 80 is http's default port, `lib/urldata.h` L36.
    assert_eq!(handle.text(CURLUPART_PORT, CURLU_DEFAULT_PORT), "80");

    assert_eq!(
        handle.set(CURLUPART_PATH, "/a b/c", CURLU_URLENCODE),
        CURLUE_OK
    );
    assert_eq!(handle.text(CURLUPART_PATH, 0), "/a%20b/c");
    assert_eq!(handle.text(CURLUPART_PATH, CURLU_URLDECODE), "/a b/c");

    assert_eq!(
        handle.set(CURLUPART_QUERY, "x y", CURLU_URLENCODE),
        CURLUE_OK
    );
    assert_eq!(handle.text(CURLUPART_QUERY, 0), "x+y");
    assert_eq!(handle.text(CURLUPART_QUERY, CURLU_URLDECODE), "x y");

    assert_eq!(
        handle.set(
            CURLUPART_QUERY,
            "a=b c",
            CURLU_APPENDQUERY | CURLU_URLENCODE
        ),
        CURLUE_OK
    );
    assert_eq!(handle.text(CURLUPART_QUERY, 0), "x+y&a=b+c");
    assert_eq!(
        handle.text(CURLUPART_URL, 0),
        "http://example.com/a%20b/c?x+y&a=b+c"
    );

    // A scheme the table does not hold is rejected unless the caller says
    // otherwise, L1645-L1647.
    assert_eq!(
        handle.set(CURLUPART_SCHEME, "gargle", 0),
        CURLUE_UNSUPPORTED_SCHEME
    );
    assert_eq!(
        handle.set(CURLUPART_SCHEME, "gargle", CURLU_NON_SUPPORT_SCHEME),
        CURLUE_OK
    );

    // The port setter regenerates the text from the number, L1666-L1683, so it
    // rejects anything that is not a decimal number in range.
    assert_eq!(handle.set(CURLUPART_PORT, "65535", 0), CURLUE_OK);
    assert_eq!(
        handle.set(CURLUPART_PORT, "65536", 0),
        CURLUE_BAD_PORT_NUMBER
    );
    assert_eq!(handle.set(CURLUPART_PORT, "x", 0), CURLUE_BAD_PORT_NUMBER);
    assert_eq!(handle.set(CURLUPART_PORT, "", 0), CURLUE_BAD_PORT_NUMBER);
    assert_eq!(handle.text(CURLUPART_PORT, 0), "65535");

    // Credentials in the input are refused outright when the caller forbids
    // them, L299-L303 by way of L1197's parse.
    let mut strict = Handle::new();
    assert_eq!(
        strict.set(
            CURLUPART_URL,
            "http://bob@example.com/",
            CURLU_DISALLOW_USER
        ),
        CURLUE_USER_NOT_ALLOWED
    );
}

/// `CURLU_NO_AUTHORITY`: an empty host is permitted where it would otherwise be
/// an error, on all three paths that can produce one.
///
/// The flag has two reading sites in `lib/urlapi.c` and both are exercised here,
/// because they are separate pieces of code with the same name in them.
///
/// **The parse**, L1154-L1158. When the authority between `//` and the path is
/// empty, `parse_authority` is never called: the flag makes L1155-L1156 store an
/// empty host instead, and without it L1159 answers `CURLUE_NO_HOST`. Every row
/// below comes from `tests/libtest/lib1560.c`'s `get_url_list` at L836-L844,
/// including the contrasting row that must fail, so the pair pins the flag
/// rather than just the permitted half.
///
/// **The host setter**, L1965-L1968. `curl_url_set(CURLUPART_HOST, "")` finds
/// `curlx_dyn_len(&enc) == 0` and skips the hostname check only when the flag is
/// passed; otherwise L1972-L1973 sets `bad` and the setter answers
/// `CURLUE_BAD_HOSTNAME`. Those two rows are
/// `tests/libtest/lib1560.c`'s `setget_parts_list` at L1138-L1148, whose
/// expected serialisations they also carry -- and the failing one is asserted to
/// have changed nothing, which that table cannot express.
///
/// **The relative path** reaches the parse site a second way, through
/// `redirect_url`'s re-parse: `tests/libtest/lib1560.c`'s `set_url_list` at
/// L1377-L1380 hands `http://?hi` to a handle that has a full URL and expects
/// `http:///?hi`. The flag is passed to the *set*, and the re-parse at L1276 is
/// where it takes effect.
///
/// `CURLU_NON_SUPPORT_SCHEME` accompanies the first two groups because the C
/// rows use `custom-scheme`, which no scheme table holds; that is the same
/// reason the C table passes it, and it keeps the assertions independent of
/// which scheme backend is compiled in.
///
/// One property is worth naming because it looks like a mistake: the stored
/// empty host reads back as an empty string with `CURLUE_OK` and **no**
/// `CURLU_GET_EMPTY` needed. The flag at L1587-L1591 governs a part that is
/// *absent*; this host is present and empty, so nothing suppresses it.
#[test]
fn no_authority_permits_an_empty_host() {
    let permissive = CURLU_NON_SUPPORT_SCHEME | CURLU_NO_AUTHORITY;

    // lib1560.c L839-L841: the empty authority is accepted and serialises with
    // three slashes.
    let empty = Handle::parse("custom-scheme://?expected=test-new-good", permissive);
    assert_eq!(
        empty.text(CURLUPART_URL, 0),
        "custom-scheme:///?expected=test-new-good"
    );
    assert_eq!(
        empty.text(CURLUPART_HOST, 0),
        "",
        "the host is present and empty, so it needs no CURLU_GET_EMPTY"
    );
    assert_eq!(empty.text(CURLUPART_HOST, CURLU_GET_EMPTY), "");
    // The path is synthesised, L1607-L1609, and the query survived the parse.
    assert_eq!(empty.text(CURLUPART_PATH, 0), "/");
    assert_eq!(empty.text(CURLUPART_QUERY, 0), "expected=test-new-good");

    // lib1560.c L836-L838: the same input without the flag. L1159.
    let mut refused = Handle::new();
    assert_eq!(
        refused.set(
            CURLUPART_URL,
            "custom-scheme://?expected=test-bad",
            CURLU_NON_SUPPORT_SCHEME
        ),
        CURLUE_NO_HOST,
        "without CURLU_NO_AUTHORITY an empty authority is CURLUE_NO_HOST"
    );

    // lib1560.c L842-L844: the flag permits an empty authority without
    // requiring one -- a host that is there is parsed as usual.
    let host_bearing = Handle::parse("custom-scheme://host?expected=test-still-good", permissive);
    assert_eq!(
        host_bearing.text(CURLUPART_URL, 0),
        "custom-scheme://host/?expected=test-still-good"
    );

    // lib1560.c L1138-L1148, both rows, on one handle so the difference is the
    // flag and nothing else. The refusal first, so that the success cannot be
    // credited to a handle that was already empty.
    let mut setter = Handle::parse("custom-scheme://host", CURLU_NON_SUPPORT_SCHEME);
    let before = setter.snapshot(CURLU_GET_EMPTY);
    assert_eq!(
        setter.set(CURLUPART_HOST, "", CURLU_NON_SUPPORT_SCHEME),
        CURLUE_BAD_HOSTNAME,
        "L1972-L1973: an empty host is not okay without the flag"
    );
    assert_eq!(
        setter.snapshot(CURLU_GET_EMPTY),
        before,
        "and the refusal changed nothing"
    );
    assert_eq!(setter.text(CURLUPART_URL, 0), "custom-scheme://host/");

    assert_eq!(
        setter.set(CURLUPART_HOST, "", permissive),
        CURLUE_OK,
        "L1966-L1967: with the flag the hostname check is skipped"
    );
    assert_eq!(setter.text(CURLUPART_URL, 0), "custom-scheme:///");
    assert_eq!(setter.text(CURLUPART_HOST, 0), "");

    // lib1560.c L1377-L1380: the flag on a relative set, taking effect in
    // `redirect_url`'s re-parse rather than in the first parse.
    let mut redirected = Handle::parse("http://user:foo@example.com/path?query#frag", 0);
    assert_eq!(
        redirected.set(CURLUPART_URL, "http://?hi", CURLU_NO_AUTHORITY),
        CURLUE_OK
    );
    assert_eq!(redirected.text(CURLUPART_URL, 0), "http:///?hi");
    assert_eq!(redirected.text(CURLUPART_HOST, 0), "");
    // The old authority is gone with it: this value was absolute, so L1715
    // replaced the handle outright rather than resolving against it.
    assert_eq!(redirected.code(CURLUPART_USER, 0), CURLUE_NO_USER);
}

/// `Curl_is_absolute_url()`, `lib/urlapi.c` L182-L220.
///
/// The acceptance condition is L206: `i && (url[i] == ':') &&
/// ((url[i + 1] == '/') || !guess_scheme)`. Three properties fall out of it and
/// all three are asserted here.
///
/// The **guessing asymmetry** is the interesting one. `data:text/html` is an
/// absolute URL when the caller is not guessing and is *not* one when it is,
/// because in guessing mode `data` could be the hostname `data` with a port
/// number -- which is what the in-source comment at L207-L209 says. The same
/// condition makes `h:` absolute with a single-letter scheme when not guessing.
///
/// The **result reports what was measured**, never how much of `buf` was
/// written, and it is zero for anything that is not absolute.
///
/// The **scan is bounded at forty**, L195's `i < MAX_SCHEME_LEN`, so a
/// forty-byte scheme is the longest that can be recognised.
#[test]
fn curl_is_absolute_url_measures_the_scheme() {
    // A relative URL, and a first byte that is not a letter, L194.
    assert_eq!(scheme_len("relative/path", C_FALSE), 0);
    assert_eq!(scheme_len("1http://x", C_FALSE), 0);
    assert_eq!(scheme_len("", C_FALSE), 0);
    // A lone letter has no colon after it, so L206's second test fails.
    assert_eq!(scheme_len("h", C_FALSE), 0);

    // The guessing asymmetry, L206-L209.
    assert_eq!(scheme_len("data:text/html", C_FALSE), 4);
    assert_eq!(scheme_len("data:text/html", C_TRUE), 0);
    // A slash after the colon satisfies the condition either way.
    assert_eq!(scheme_len("h:/", C_TRUE), 1);
    assert_eq!(scheme_len("h:", C_FALSE), 1);
    assert_eq!(scheme_len("HTTP://", C_TRUE), 4);

    // RFC 3986 3.1's scheme alphabet, which L197 spells out: a letter followed
    // by letters, digits, '+', '-' and '.'.
    assert_eq!(scheme_len("http+ssh-1.x://a", C_FALSE), 12);
}

/// `Curl_is_absolute_url()` with a buffer: `buf[0]` is cleared first and the
/// scheme is written lower-cased.
///
/// L188-L189 assigns `buf[0] = 0` before anything else and the comment there
/// says why -- "always leave a defined value in buf" -- so a caller that
/// ignores the return value still finds an empty string rather than whatever
/// was in its stack. The buffer is pre-filled with `'Z'` by
/// [`scheme_into_buf`] so that this is observable.
///
/// On success L214-L215 writes through `Curl_strntolower`, `lib/strcase.c`
/// L106, and terminates at index `i`. That is why the buffer has to be
/// `MAX_SCHEME_LEN + 1` bytes and not `MAX_SCHEME_LEN`: for a forty-byte
/// scheme the terminator lands at index forty.
#[test]
fn curl_is_absolute_url_writes_a_lower_cased_scheme() {
    let (len, buf) = scheme_into_buf("HTTPS://x", C_FALSE);
    assert_eq!(len, 5);
    assert_eq!(buf_text(&buf), b"https");

    let (len, buf) = scheme_into_buf("HTTP+SSH-1.X://a", C_FALSE);
    assert_eq!(len, 12);
    assert_eq!(buf_text(&buf), b"http+ssh-1.x");

    // Not absolute: nothing is written, but buf[0] is still cleared. L188-L189.
    let (len, buf) = scheme_into_buf("relative/path", C_FALSE);
    assert_eq!(len, 0);
    assert_eq!(buf.first(), Some(&0));
    assert_eq!(buf_text(&buf), b"");

    // The guessing asymmetry again, this time proving the buffer is cleared on
    // the rejecting side of it.
    let (len, buf) = scheme_into_buf("data:text/html", C_TRUE);
    assert_eq!(len, 0);
    assert_eq!(buf.first(), Some(&0));
    let (len, buf) = scheme_into_buf("data:text/html", C_FALSE);
    assert_eq!(len, 4);
    assert_eq!(buf_text(&buf), b"data");

    // Exactly MAX_SCHEME_LEN bytes is the longest scheme the bounded loop at
    // L195 can reach, and the terminator for it lands at index MAX_SCHEME_LEN.
    // `tests/libtest/lib1560.c` L677-L681 requires this length to parse.
    let longest = "A".repeat(MAX_SCHEME_LEN);
    let (len, buf) = scheme_into_buf(&format!("{longest}://x"), C_FALSE);
    assert_eq!(len, MAX_SCHEME_LEN);
    assert_eq!(buf_text(&buf), "a".repeat(MAX_SCHEME_LEN).as_bytes());

    // One byte more and the loop's bound stops before the colon, so L206's
    // `url[i] == ':'` sees a letter instead and the answer is zero.
    let too_long = "A".repeat(MAX_SCHEME_LEN + 1);
    let (len, buf) = scheme_into_buf(&format!("{too_long}://x"), C_FALSE);
    assert_eq!(len, 0);
    assert_eq!(buf.first(), Some(&0));
}

/// `Curl_junkscan()`, `lib/urlapi.c` L223-L239.
///
/// Two properties, and the second is the one a caller can get wrong.
///
/// The **rejection set** is L232-L235: `p[i] <= control || p[i] == 127`, where
/// `control` is `0x1f` when spaces are allowed and `0x20` when they are not.
/// So a space is the only byte the flag moves. Byte `0x7f` is rejected in both
/// modes because it is tested separately, and byte `0x1f` is rejected in both
/// because it is at or below the lower threshold. Getting `control` backwards
/// would show up as a space being accepted when it should not be.
///
/// The **out-parameter is written only on success**. L237 sits after both
/// `return` statements, so a failing scan leaves the caller's `size_t`
/// untouched -- asserted by seeding it with a sentinel and finding the sentinel
/// afterwards.
#[test]
fn curl_junkscan_rejects_control_bytes_and_writes_the_length_only_on_success() {
    assert_eq!(junkscan("abc", C_FALSE), (CURLUE_OK, 3));
    assert_eq!(junkscan("", C_FALSE), (CURLUE_OK, 0));

    // The space is the only byte `allowspace` moves, L231.
    assert_eq!(
        junkscan("a b", C_FALSE),
        (CURLUE_MALFORMED_INPUT, JUNKSCAN_SENTINEL)
    );
    assert_eq!(junkscan("a b", C_TRUE), (CURLUE_OK, 3));

    // Byte 127 is tested on its own, so no flag reaches it. Written as a Rust
    // escape rather than as a raw byte because `scripts/spacecheck.pl` treats a
    // literal 0x7f in a tracked file as binary content.
    assert_eq!(
        junkscan("a\x7fb", C_FALSE),
        (CURLUE_MALFORMED_INPUT, JUNKSCAN_SENTINEL)
    );
    assert_eq!(
        junkscan("a\x7fb", C_TRUE),
        (CURLUE_MALFORMED_INPUT, JUNKSCAN_SENTINEL)
    );

    // Byte 0x1f is at the lower threshold, so `<=` rejects it either way.
    assert_eq!(
        junkscan("a\x1fb", C_FALSE),
        (CURLUE_MALFORMED_INPUT, JUNKSCAN_SENTINEL)
    );
    assert_eq!(
        junkscan("a\x1fb", C_TRUE),
        (CURLUE_MALFORMED_INPUT, JUNKSCAN_SENTINEL)
    );
}

/// `Curl_junkscan()` refuses anything longer than `CURL_MAX_INPUT_LENGTH`.
///
/// L229-L230, against the eight-million-byte ceiling `lib/urldata.h` L131
/// sets. The boundary is what matters, so both sides of it are exercised:
/// exactly eight million passes and one byte more does not, and the failing
/// call leaves the out-parameter alone like every other failing call.
///
/// The buffer is built directly rather than through `CString` because the
/// vector is uniform and needs no NUL search.
#[test]
fn curl_junkscan_refuses_input_over_the_ceiling() {
    let mut buffer = vec![b'a'; CURL_MAX_INPUT_LENGTH + 1];
    // The terminator `strlen` at L225 stops on. It is beyond the 'a' bytes, so
    // the measured length is CURL_MAX_INPUT_LENGTH + 1.
    buffer.push(0);

    let mut len: size_t = JUNKSCAN_SENTINEL;
    // SAFETY: `buffer` holds CURL_MAX_INPUT_LENGTH + 2 initialised bytes whose
    // last is NUL, so the pointer addresses a valid NUL-terminated C string
    // that stays alive and unmodified for the call. `len` is a local `size_t`
    // in a distinct allocation, so it cannot alias the string.
    let code = unsafe { Curl_junkscan(buffer.as_ptr().cast::<c_char>(), &mut len, C_FALSE) };
    assert_eq!(code, CURLUE_MALFORMED_INPUT, "L229-L230 rejects the length");
    assert_eq!(len, JUNKSCAN_SENTINEL, "L237 is after the failing return");

    // Exactly at the ceiling, `n > CURL_MAX_INPUT_LENGTH` is false.
    let at_the_limit = {
        let mut buffer = vec![b'a'; CURL_MAX_INPUT_LENGTH];
        buffer.push(0);
        buffer
    };
    let mut len: size_t = JUNKSCAN_SENTINEL;
    // SAFETY: `at_the_limit` is a live local vector whose last byte is a NUL,
    // so the pointer addresses a readable, NUL-terminated buffer that stays
    // valid and unmodified for the call; `len` points at a live local the callee
    // may write once; and neither pointer is retained past the call.
    let code = unsafe { Curl_junkscan(at_the_limit.as_ptr().cast::<c_char>(), &mut len, C_FALSE) };
    assert_eq!(code, CURLUE_OK);
    assert_eq!(len, CURL_MAX_INPUT_LENGTH);
}

/// `Curl_url_set_authority()` replaces the host and the port of a live handle.
///
/// `lib/urlapi.c` L657-L675. It runs the whole authority stage -- credential
/// split, port extraction, address normalisation -- and on success L672-L673
/// frees the old host and installs the new one. On failure L670 releases the
/// working buffer and the handle keeps the host it had, which is the atomicity
/// property the authority path does have.
///
/// The two things it does that surprise a reader are `FB2` and `FB3` below.
/// This test is the ordinary behaviour those two sit on top of.
#[test]
fn curl_url_set_authority_replaces_host_and_port() {
    let mut handle = Handle::parse("http://example.com/path", 0);

    assert_eq!(handle.set_authority("other.example:8080"), CURLUE_OK);
    assert_eq!(handle.text(CURLUPART_HOST, 0), "other.example");
    assert_eq!(handle.text(CURLUPART_PORT, 0), "8080");
    assert_eq!(handle.text(CURLUPART_PATH, 0), "/path");
    assert_eq!(
        handle.text(CURLUPART_URL, 0),
        "http://other.example:8080/path"
    );

    // A malformed authority fails and changes nothing. `[bad` has no closing
    // bracket, so `Curl_parse_port` rejects it at L343-L346 with
    // `CURLUE_BAD_IPV6` before `ipv6_parse` is reached at all.
    assert_eq!(handle.set_authority("[bad"), CURLUE_BAD_IPV6);
    assert_eq!(handle.text(CURLUPART_HOST, 0), "other.example");
    assert_eq!(
        handle.text(CURLUPART_URL, 0),
        "http://other.example:8080/path"
    );
}

/// A null handle is an error code, never a fault.
///
/// `lib/urlapi.c` L1548-L1549 for the reader and L1817-L1818 for the writer.
/// Both are answered before anything else happens, and neither may abort:
/// libcurl's own callers rely on this, and a Rust port that panicked here would
/// abort the process at the `extern "C"` boundary rather than return.
///
/// The reader's out-pointer is what makes the *ordering* observable, and it is
/// pre-seeded with a value no allocator would produce rather than with null.
/// L1548-L1549's `if(!u) return CURLUE_BAD_HANDLE;` precedes L1552's
/// unconditional `*part = NULL`, so a null handle must leave the caller's
/// pointer exactly as it was. Seeding it with null would have proved nothing:
/// the pointer would read null afterwards whether the C returned early or fell
/// through to L1552, which are two different behaviours. The sentinel
/// distinguishes them, and the contrast is
/// [`a_null_part_pointer_is_bad_partpointer_and_a_real_one_is_cleared`], where
/// the handle *is* live and the same seed is asserted to have been overwritten
/// with null.
#[test]
fn a_null_handle_is_bad_handle() {
    // A value that is never dereferenced and never freed. `usize::MAX` cannot
    // come from an allocator, so finding it afterwards can only mean nothing was
    // written; and it is the same sentinel the live-handle test uses, so the two
    // outcomes are being compared on equal terms.
    let sentinel = usize::MAX as *mut c_char;
    let mut part: *mut c_char = sentinel;
    // SAFETY: a null handle is the case under test and `curl_url_get` answers
    // it from the raw pointer at L1548 without dereferencing. `part` is a
    // writable, aligned local; the value it holds is never dereferenced by this
    // test, and the call under test must not write through it either.
    let code = unsafe { curl_url_get(ptr::null(), CURLUPART_URL, &mut part, 0) };
    assert_eq!(code, CURLUE_BAD_HANDLE);
    assert_eq!(
        part, sentinel,
        "L1548-L1549 returns before L1552, so the caller's pointer is untouched"
    );

    // And the same call with a null out-pointer as well: the handle is tested
    // first, so this is still CURLUE_BAD_HANDLE and not CURLUE_BAD_PARTPOINTER.
    // SAFETY: both arguments are null, which is the case under test; neither is
    // dereferenced, because L1548 answers from the handle alone.
    let code = unsafe { curl_url_get(ptr::null(), CURLUPART_URL, ptr::null_mut(), 0) };
    assert_eq!(
        code, CURLUE_BAD_HANDLE,
        "L1548 precedes L1550, so the handle decides when both are null"
    );

    let value = c_string("https://example.com/");
    // SAFETY: a null handle is the case under test, answered at L1817 without
    // dereferencing. `value` is a NUL-terminated C string alive for the call.
    let code = unsafe { curl_url_set(ptr::null_mut(), CURLUPART_URL, value.as_ptr(), 0) };
    assert_eq!(code, CURLUE_BAD_HANDLE);

    // The clearing form takes the same path: L1817's test precedes L1819's.
    // SAFETY: both pointers are null on purpose. L1817 tests the handle before
    // touching it, and a null `part` is the documented request to clear, read
    // as a value rather than dereferenced. Nothing is allocated, borrowed or
    // released, so no lifetime or ownership obligation arises.
    let code = unsafe { curl_url_set(ptr::null_mut(), CURLUPART_SCHEME, ptr::null(), 0) };
    assert_eq!(code, CURLUE_BAD_HANDLE);
}

/// A null out-pointer is an error code, and a real one is cleared on entry.
///
/// `lib/urlapi.c` L1550-L1551 answers the null case, and L1552's
/// `*part = NULL` runs unconditionally on every other path -- *before* the
/// switch, so it happens even when the read is about to fail. That second half
/// is what stops the classic caller bug of releasing a pointer left over from
/// an earlier call, so it is asserted by seeding the out-pointer with a
/// recognisable non-null value and finding it null afterwards.
#[test]
fn a_null_part_pointer_is_bad_partpointer_and_a_real_one_is_cleared() {
    let handle = Handle::new();

    // SAFETY: `handle` owns a live handle; the null `part` is the case under
    // test and L1550 answers it from the raw pointer without writing through
    // it.
    let code = unsafe { curl_url_get(handle.as_const(), CURLUPART_URL, ptr::null_mut(), 0) };
    assert_eq!(code, CURLUE_BAD_PARTPOINTER);

    // A value no allocator would return, so that finding null afterwards can
    // only mean L1552 wrote it. `usize::MAX` is deliberately never dereferenced
    // and never freed.
    let sentinel = usize::MAX as *mut c_char;
    for (what, expected) in [
        (CURLUPART_SCHEME, CURLUE_NO_SCHEME),
        (CURLUPART_HOST, CURLUE_NO_HOST),
        (CURLUPART_URL, CURLUE_NO_HOST),
        // Out of range, so the switch's `default` at L1626-L1628 leaves
        // `ifmissing` at its L1545 initial value.
        (9999, CURLUE_UNKNOWN_PART),
    ] {
        let mut part = sentinel;
        // SAFETY: `handle` owns a live handle and `part` is a writable, aligned
        // local holding a value that is never dereferenced. The call writes
        // through `part` and reads the handle; the two cannot alias, since
        // `part` is a stack slot this frame owns.
        let code = unsafe { curl_url_get(handle.as_const(), what, &mut part, 0) };
        assert_eq!(code, expected, "part {what}");
        assert!(
            part.is_null(),
            "L1552 must clear *part before the switch, part {what}"
        );
    }
}

/// `curl_url_cleanup(NULL)` does nothing.
///
/// `lib/urlapi.c` L1295 wraps the whole body in `if(u)`, and
/// `docs/libcurl/curl_url_cleanup.md` states it for the reader: passing null
/// makes the function return immediately with no action. Reaching the assertion
/// after the call is the whole of the test.
#[test]
fn cleanup_of_a_null_handle_is_a_no_op() {
    // SAFETY: null is the case under test. L1295 tests the pointer before
    // touching it, so nothing is dereferenced and nothing is released.
    unsafe { curl_url_cleanup(ptr::null_mut()) };
    // Twice, because "no action" has to hold for a repeat too.
    // SAFETY: null again, which L1295 tests before touching the pointer, so
    // nothing is dereferenced and nothing is released. No ownership is
    // transferred by either call, so the repeat is not a double free.
    unsafe { curl_url_cleanup(ptr::null_mut()) };
}

/// `curl_url_dup(NULL)` answers null, which is a defined outcome the C does not
/// have.
///
/// This is the one place in this file that asserts a **hardening** rather than a
/// reproduction, and the distinction matters. `lib/urlapi.c` L1312 allocates and
/// L1314's `DUP(u, in, scheme)` expands to `if((in)->scheme)`, which
/// dereferences the argument with no null guard anywhere before it. A null
/// argument is therefore undefined behaviour in the C original and there is no
/// parity oracle for it: the reference does not have an answer to compare
/// against.
///
/// `curl_url_dup` in `src/ffi.rs` defines one. It reaches the handle through
/// `as_ref`, which distinguishes null from non-null without dereferencing, and
/// returns null -- the same value an allocation failure produces there, so
/// every caller already has to handle it. The hardening is unobservable to
/// any conforming caller, because a conforming caller never passes null, and it
/// is asserted here rather than left undefined so that a later edit cannot
/// quietly turn it into a fault.
#[test]
fn dup_of_a_null_handle_answers_null() {
    // SAFETY: null is the case under test and `curl_url_dup` in `src/ffi.rs`
    // answers it through `as_ref` without dereferencing. Nothing is allocated,
    // so nothing leaks.
    let copy = unsafe { curl_url_dup(ptr::null()) };
    assert!(
        copy.is_null(),
        "a null input must answer null, not fault -- see curl_url_dup in \
         src/ffi.rs"
    );
}

/// A null value clears the part rather than failing, for every part.
///
/// `lib/urlapi.c` L1819-L1821 routes a null `part` to `urlset_clear`, and
/// `include/curl/urlapi.h` L138-L139 documents it. The expectations are the
/// `clear_url_list` table at `tests/libtest/lib1560.c` L1862-L1874, read
/// against `urlset_clear`'s own arms at L1732-L1777: every part becomes absent
/// except `CURLUPART_PATH`, which reads back as the synthesised `"/"` because
/// L1607-L1609 supplies one for a handle that stores none.
///
/// Two differences from the upstream sub-test are deliberate. Upstream clears
/// `CURLUPART_URL` on each iteration -- L1889 -- which wipes the whole handle
/// and so exercises one arm eleven times; this clears the part that was just
/// set, which exercises all ten arms. And upstream's final row,
/// `{ CURLUPART_URL, NULL, NULL, CURLUE_OK }` at L1873, is its loop terminator
/// rather than a case: the loop condition at L1884 is `clear_url_list[i].in`,
/// so a null `in` ends it. The whole-URL arm is therefore given its own
/// assertion below.
#[test]
fn a_null_value_clears_the_part() {
    let rows: [(CURLUPart, &str, CURLUcode, Option<&str>); 10] = [
        (CURLUPART_SCHEME, "http", CURLUE_NO_SCHEME, None),
        (CURLUPART_USER, "user", CURLUE_NO_USER, None),
        (CURLUPART_PASSWORD, "password", CURLUE_NO_PASSWORD, None),
        (CURLUPART_OPTIONS, "options", CURLUE_NO_OPTIONS, None),
        (CURLUPART_HOST, "host", CURLUE_NO_HOST, None),
        (CURLUPART_ZONEID, "eth0", CURLUE_NO_ZONEID, None),
        (CURLUPART_PORT, "1234", CURLUE_NO_PORT, None),
        (CURLUPART_PATH, "/hello", CURLUE_OK, Some("/")),
        (CURLUPART_QUERY, "a=b", CURLUE_NO_QUERY, None),
        (CURLUPART_FRAGMENT, "anchor", CURLUE_NO_FRAGMENT, None),
    ];

    for (what, value, expected, content) in rows {
        let mut handle = Handle::new();
        assert_eq!(handle.set(what, value, 0), CURLUE_OK, "setting part {what}");
        assert_eq!(handle.clear(what), CURLUE_OK, "clearing part {what}");
        let (code, actual) = handle.get(what, 0);
        assert_eq!(code, expected, "reading part {what} after the clear");
        assert_eq!(actual.as_deref(), content, "content of part {what}");
    }

    // The whole-URL arm, L1735-L1738: the handle is freed and zeroed, so the
    // clear succeeds and the handle afterwards is indistinguishable from a
    // fresh one -- which means a whole-URL read fails with CURLUE_NO_HOST at
    // L1448-L1449, not with CURLUE_OK.
    let mut handle = Handle::parse("https://user:pwd@example.com:8080/p?q#f", 0);
    assert_eq!(handle.clear(CURLUPART_URL), CURLUE_OK);
    assert_eq!(handle.code(CURLUPART_URL, 0), CURLUE_NO_HOST);
    assert_eq!(handle.snapshot(0), Handle::new().snapshot(0));
}

/// An out-of-range part identifier is `CURLUE_UNKNOWN_PART`, on both sides.
///
/// `tests/libtest/lib1560.c` L1178 casts `9999` for exactly this, so the value
/// is the upstream suite's own.
///
/// The two sides reach the answer differently and both are worth pinning. On
/// set, `lib/urlapi.c` L1873-L1874 is an explicit `default: return
/// CURLUE_UNKNOWN_PART`, and `urlset_clear`'s L1774-L1775 is the same for the
/// clearing form. On get there is no such `return`: L1545 initialises
/// `ifmissing` to `CURLUE_UNKNOWN_PART`, L1626-L1628's `default` sets `ptr` to
/// null without changing it, and L1631-L1633 then returns `ifmissing` because
/// `ptr` is null. Every other arm overwrites `ifmissing` with its own code,
/// which is why the initial value is only ever seen here.
#[test]
fn an_unknown_part_is_unknown_part() {
    let mut handle = Handle::parse("https://example.com/p", 0);

    assert_eq!(handle.code(9999, 0), CURLUE_UNKNOWN_PART);
    assert_eq!(handle.set(9999, "x", 0), CURLUE_UNKNOWN_PART);
    assert_eq!(handle.clear(9999), CURLUE_UNKNOWN_PART);

    // A negative value takes the same `default` arm, since the C switches on an
    // `int`-width enumeration.
    assert_eq!(handle.code(-1, 0), CURLUE_UNKNOWN_PART);
    assert_eq!(handle.set(-1, "x", 0), CURLUE_UNKNOWN_PART);

    assert_eq!(handle.text(CURLUPART_URL, 0), "https://example.com/p");
}

/// The two reading entry points do not mutate the handle.
///
/// `curl_url_get` and `curl_url_dup` take `const CURLU *` at
/// `include/curl/urlapi.h` L133 and L126, and `src/ffi.rs` models both as
/// `*const`. That is a promise the type system cannot check across an FFI
/// boundary -- a `*const` can be cast away, and the C's own `const` can be too
/// -- so the only real test is behavioural: read the whole handle, exercise
/// every reading path, read the whole handle again, and require the two
/// snapshots to be identical.
///
/// The snapshot is taken twice more with the flag combinations that make a
/// reader do the most work -- `CURLU_GET_EMPTY`, which consults
/// `query_present` and `fragment_present` at L1432-L1435; `CURLU_URLDECODE`,
/// which runs the decoder at L1373-L1381; `CURLU_URLENCODE`, which allocates an
/// escaped host at L1492-L1495; and the punycode flags, which reach the IDN
/// backend at L1402-L1420 -- because a mutation is likelier on a path that
/// allocates than on one that copies a pointer.
#[test]
fn reading_a_handle_never_changes_it() {
    let handle = Handle::parse("imap://user:pwd;opt@[fe80::1%25eth0]:143/a%20b?q=1#frag", 0);
    let before = handle.snapshot(0);
    let before_empty = handle.snapshot(CURLU_GET_EMPTY);

    for flags in [
        0,
        CURLU_GET_EMPTY,
        CURLU_URLDECODE,
        CURLU_URLENCODE,
        CURLU_DEFAULT_PORT,
        CURLU_NO_DEFAULT_PORT,
        CURLU_DEFAULT_SCHEME,
        CURLU_NO_GUESS_SCHEME,
        CURLU_PUNYCODE,
        CURLU_PUNY2IDN,
    ] {
        let _ = handle.snapshot(flags);
    }

    let copy = handle.dup();
    let _ = copy.snapshot(0);
    drop(copy);

    assert_eq!(
        handle.snapshot(0),
        before,
        "curl_url_get or curl_url_dup mutated the handle"
    );
    assert_eq!(handle.snapshot(CURLU_GET_EMPTY), before_empty);
}

/// The URL the two cleanup-ownership tests below share.
const KEEPME_URL: &str = "https://example.com/keepme";

/// How many identical requests the recycling probe replays after cleanup.
///
/// Cleanup legitimately releases the handle and its own strings, so several
/// blocks reach the allocator's free lists alongside any block it wrongly
/// released. Replaying the request more than once means the block under test does
/// not have to be the very first one handed back for the probe to notice it.
const RECYCLE_SAMPLES: usize = 8;

/// The returned buffer is a separate allocation from the handle, in the one
/// direction that can be observed with no unsafe ordering at all.
///
/// `include/curl/urlapi.h` L116-L118 states the contract from the other side:
/// cleanup frees the handle and the resources used for parsing, and "will not
/// free strings previously returned with the URL API". That is a statement about
/// two allocations being independent, and independence is symmetric -- so it can
/// be tested by releasing the *buffer* first, which is always safe, instead of by
/// releasing the handle first and then reaching into the buffer, which is not.
///
/// If the getter had handed out a pointer into the handle's own storage -- the
/// mistake the contract exists to forbid, and the reason `src/alloc.rs` is the
/// crate's sole producer of C-visible memory -- then freeing the buffer would
/// have released memory the handle still uses, and the reads that follow would
/// disagree. Every one of the eleven parts is read afterwards, so the claim
/// cannot hold merely because the part that moved was not looked at.
///
/// [`cleanup_does_not_recycle_a_previously_returned_string`] covers the other
/// direction.
///
/// The sequence has to be spelled out rather than expressed through
/// [`Handle::get`], because that helper releases the buffer before it returns.
/// The release still precedes every fallible step, for the reason that helper
/// records: an assertion is an unwind, and an unwind before the release is a
/// leak of a C allocation.
#[test]
fn a_returned_buffer_is_independent_of_the_handle_that_produced_it() {
    let handle = Handle::parse(KEEPME_URL, 0);
    let before = handle.snapshot(CURLU_GET_EMPTY);

    let mut part: *mut c_char = ptr::null_mut();
    // SAFETY: `handle` owns a live handle and `part` is a writable, aligned
    // local that cannot alias it.
    let code = unsafe { curl_url_get(handle.as_const(), CURLUPART_URL, &mut part, 0) };
    // Neither assertion can leak. `lib/urlapi.c` L1552 writes null into
    // `*part` before the switch, so a retrieval that reports anything but
    // `CURLUE_OK` has handed this caller nothing to release.
    assert_eq!(code, CURLUE_OK);
    assert!(!part.is_null());

    // Read the buffer while the handle is still live and nothing has been
    // released, so this read is unconditionally sound.
    // SAFETY: the call reported `CURLUE_OK` and a non-null pointer, so it
    // addresses a NUL-terminated buffer this caller owns, and nothing has been
    // freed since.
    let kept = unsafe { CStr::from_ptr(part) }
        .to_str()
        .expect("the getter returns ASCII for this vector")
        .to_owned();
    assert_eq!(kept, KEEPME_URL);

    // Release the buffer first. This is the documented release at
    // `docs/libcurl/curl_url_get.md` L45, performed exactly once, and `kept` is
    // an independent copy so no borrow into the block survives.
    // SAFETY: the block came from this crate's C allocator through
    // `src/alloc.rs`, it has not been released, and no reference into it is live.
    unsafe { libc::free(part.cast::<c_void>()) };

    // The handle is untouched by that release: it still answers every part
    // exactly as it did, and it still serialises to the same URL.
    assert_eq!(
        handle.snapshot(CURLU_GET_EMPTY),
        before,
        "freeing a buffer curl_url_get() handed out disturbed the handle, so the \
         two are not independent allocations"
    );
    assert_eq!(handle.text(CURLUPART_URL, 0), KEEPME_URL);

    // `handle`'s own `Drop` performs the single `curl_url_cleanup()`, after the
    // buffer is already gone -- so no ordering in this test can touch released
    // memory.
}

/// `curl_url_cleanup()` does not release a string the getter handed out earlier.
///
/// # Why this is not tested by reading the buffer afterwards
///
/// The obvious shape -- retrieve a part, clean the handle up, then read the
/// buffer back -- is fail-unsafe, and precisely when it matters. If the defect
/// it hunts is present, cleanup has released that block, and reading it is a
/// use-after-free: the test would commit undefined behaviour instead of
/// reporting the contract violation, and under a hardened or a sanitizing
/// allocator it would abort with a diagnostic about the *test* rather than fail
/// with one about the implementation. A test may not prove liveness by reading
/// memory after the operation under test.
///
/// # What it does instead
///
/// It records the block's address as a plain integer -- taking an address is not
/// a dereference, so the value stays usable as evidence whatever cleanup does to
/// the block it names -- and then asks the C allocator whether that block has
/// been returned to it. If cleanup had wrongly freed it, the block would now sit
/// on the free list for its size class, and glibc's per-thread cache is
/// last-in-first-out, so an identical request would be handed it straight back.
/// The probe therefore replays the very operation that produced it,
/// [`RECYCLE_SAMPLES`] times, keeping every reply alive so each replay samples a
/// distinct block; a replay is size-exact by construction, which no hand-picked
/// `malloc` size could guarantee. Nothing reads the block under test, so a
/// regression surfaces as the assertion below, and a false failure is impossible:
/// an allocation that is still live can never be handed out a second time.
///
/// The release at the end is *guarded* by that assertion rather than being the
/// evidence for it. On the failing path the assertion panics first, so the
/// release is unreachable and no double free can occur; on the passing path the
/// block has been shown to be still allocated, so the release is the ordinary
/// documented one and the buffer does not leak.
///
/// # What the probe does not prove, and what covers that
///
/// Recycling is strong evidence rather than a proof: an allocator is free to
/// satisfy a request without reusing the most recently freed block.
/// [`a_returned_buffer_is_independent_of_the_handle_that_produced_it`] carries
/// the deterministic half of the contract, and
/// `rust-urlapi/docs/MEMORY-OWNERSHIP.md` records the sanitizer evidence for the
/// direction neither test can observe safely. curl's own allocation counter is
/// not available as an instrument here, because the parity harness is
/// deliberately built without the memory-debug configuration -- `AAP` 0.2.4.3,
/// reportable constraint `R3`.
#[test]
fn cleanup_does_not_recycle_a_previously_returned_string() {
    let handle = Handle::parse(KEEPME_URL, 0);

    let mut part: *mut c_char = ptr::null_mut();
    // SAFETY: `handle` owns a live handle and `part` is a writable, aligned
    // local that cannot alias it.
    let code = unsafe { curl_url_get(handle.as_const(), CURLUPART_URL, &mut part, 0) };
    assert_eq!(code, CURLUE_OK);
    assert!(!part.is_null());

    // Everything this test needs from the block is taken now, while it is
    // unambiguously live: its bytes, and its address as an integer.
    // SAFETY: the call reported `CURLUE_OK` and a non-null pointer, so it
    // addresses a NUL-terminated buffer this caller owns, and nothing has been
    // freed since.
    let kept = unsafe { CStr::from_ptr(part) }
        .to_str()
        .expect("the getter returns ASCII for this vector")
        .to_owned();
    assert_eq!(kept, KEEPME_URL);
    let block = part as usize;

    // The array is on the stack and is filled in below, so the probe adds no
    // heap traffic of its own beyond the replies it is measuring.
    let mut samples: [*mut c_char; RECYCLE_SAMPLES] = [ptr::null_mut(); RECYCLE_SAMPLES];

    // The operation under test. `into_raw` suppresses the wrapper's own `Drop`,
    // so this is the single release of the handle.
    let raw = handle.into_raw();
    // SAFETY: `raw` is the live handle `Handle::parse` produced, it has not been
    // released, and no other pointer to it survives -- `into_raw` consumed the
    // only owner.
    unsafe { curl_url_cleanup(raw) };

    for slot in &mut samples {
        let probe = Handle::parse(KEEPME_URL, 0);
        let mut fresh: *mut c_char = ptr::null_mut();
        // SAFETY: `probe` owns a live handle and `fresh` is a writable, aligned
        // local that cannot alias it.
        let rc = unsafe { curl_url_get(probe.as_const(), CURLUPART_URL, &mut fresh, 0) };
        assert_eq!(rc, CURLUE_OK);
        assert!(!fresh.is_null());
        assert_ne!(
            fresh as usize, block,
            "the allocator re-issued the block curl_url_get() had handed out, so \
             curl_url_cleanup() released a buffer the caller still owns; \
             include/curl/urlapi.h L116-L118 forbids exactly that"
        );
        *slot = fresh;
    }

    for sample in samples {
        // SAFETY: each entry came from the `curl_url_get` above, is non-null,
        // has not been released, is released exactly once here, and no reference
        // into it is live.
        unsafe { libc::free(sample.cast::<c_void>()) };
    }

    // Reached only because the assertion above found the block still allocated,
    // which is what makes this release -- the documented one at
    // `docs/libcurl/curl_url_get.md` L45 -- safe rather than a second free.
    // SAFETY: the block came from this crate's C allocator through
    // `src/alloc.rs`, it has been shown to be still allocated, it is released
    // exactly once here, and `kept` is an independent copy so no reference into
    // it is live.
    unsafe { libc::free(part.cast::<c_void>()) };
}

/// The input the guessed-scheme cases are built from.
///
/// `tests/libtest/lib1560.c` L1985 uses exactly this string in its duplication
/// sub-test, so the construction below is the upstream one and not an invention.
/// Parsed with `CURLU_GUESS_SCHEME` it takes the scheme-less branch of
/// `parse_scheme` at `lib/urlapi.c` L961-L974 -- `Curl_is_absolute_url` answers
/// zero for it in guessing mode, which is the asymmetry
/// [`curl_is_absolute_url_measures_the_scheme`] pins -- and `guess_scheme` at
/// L984-L1008 then stores `"http"` and sets the flag at L1008. The hostname
/// prefix table at L989-L1000 has no entry matching `example.com`, so the
/// `else` at L1000-L1001 supplies `http`.
const GUESSED_INPUT: &str = "example.com:1234";

/// `FB1`: `curl_url_dup()` does not copy `guessed_scheme`, and the port does
/// not either.
///
/// This asserts a faithful reproduction of a C oddity, required by the Agent
/// Action Plan at its 0.6.6 and 0.8.1 and recorded in
/// `rust-urlapi/docs/KNOWN-DIVERGENCES.md` under `FB1`. The invariant is that
/// the copy differs from the original in exactly this way, so a failure here
/// means the port diverged from the reference and `src/handle.rs` is where it
/// diverged.
///
/// # What the C does
///
/// The `DUP` macro at `lib/urlapi.c` L1301-L1308 and its ten uses at
/// L1314-L1323 copy `scheme`, `user`, `password`, `options`, `host`, `port`,
/// `path`, `query`, `fragment` and `zoneid`. L1324-L1326 then copy `portnum`,
/// `fragment_present` and `query_present`. `guessed_scheme` is a real member of
/// the structure at L81 and is copied by nothing.
///
/// # The two observable consequences
///
/// Both need `CURLU_NO_GUESS_SCHEME`, because that is the only flag the member
/// gates, and both are asserted on the original as well as the copy so that the
/// difference is the subject rather than a coincidence.
///
/// Reading `CURLUPART_SCHEME` short-circuits at L1559-L1560 only when
/// `u->guessed_scheme` is set, so the original refuses and the copy answers.
///
/// Reading `CURLUPART_URL` blanks `schemebuf` at L1512-L1515 only when
/// `u->guessed_scheme` is set, so the original omits the prefix and the copy
/// emits it.
///
/// # Why the upstream suite provably cannot catch this
///
/// The duplication sub-test at `tests/libtest/lib1560.c` L1970-L2032 *does*
/// include `GUESSED_INPUT` in its list, at L1985, and *does* parse it with
/// `CURLU_GUESS_SCHEME` at L1997-L1998. But its two reads are
/// `curl_url_get(h, CURLUPART_URL, &h_str, 0)` at L2004 and
/// `curl_url_get(copy, CURLUPART_URL, &copy_str, 0)` at L2008 -- flags of zero
/// -- and L2012 merely compares the two strings. With flags of zero, L1512's
/// first disjunct is true for both handles and both emit the prefix, so the
/// comparison passes. That is exactly why the divergence survives upstream, and
/// it is why this assertion has to exist somewhere other than in `lib1560.c`.
#[test]
fn fb1_dup_drops_guessed_scheme_is_preserved() {
    let original = Handle::parse(GUESSED_INPUT, CURLU_GUESS_SCHEME);
    let copy = original.dup();

    // Consequence one: CURLUPART_SCHEME, L1559-L1560.
    assert_eq!(
        original.code(CURLUPART_SCHEME, CURLU_NO_GUESS_SCHEME),
        CURLUE_NO_SCHEME,
        "the original's guessed_scheme is set, so L1559-L1560 refuses"
    );
    assert_eq!(
        copy.text(CURLUPART_SCHEME, CURLU_NO_GUESS_SCHEME),
        "http",
        "FB1: the copy's guessed_scheme is clear, so L1559 does not fire and the \
         guessed scheme is handed out under the very flag that asks for it not \
         to be. Reproduced deliberately -- see KNOWN-DIVERGENCES.md FB1."
    );

    // Consequence two: CURLUPART_URL, L1512-L1515.
    assert_eq!(
        original.text(CURLUPART_URL, CURLU_NO_GUESS_SCHEME),
        "example.com:1234/",
        "the original suppresses the scheme prefix"
    );
    assert_eq!(
        copy.text(CURLUPART_URL, CURLU_NO_GUESS_SCHEME),
        "http://example.com:1234/",
        "FB1: the copy emits the prefix the flag asked to be suppressed. \
         Reproduced deliberately -- see KNOWN-DIVERGENCES.md FB1."
    );

    // And the pair the upstream sub-test compares, which agrees. Asserting it
    // here is what shows the divergence is confined to the flagged reads rather
    // than being a broken copy: with flags of zero L1512's first disjunct is
    // true for both handles, so both emit the prefix.
    assert_eq!(
        original.text(CURLUPART_URL, 0),
        "http://example.com:1234/",
        "the L2004 read"
    );
    assert_eq!(
        copy.text(CURLUPART_URL, 0),
        "http://example.com:1234/",
        "the L2008 read, which is why L2012's comparison passes upstream"
    );
    assert_eq!(
        original.text(CURLUPART_URL, 0),
        copy.text(CURLUPART_URL, 0),
        "upstream's own assertion, restated"
    );

    // An explicitly set scheme clears the member at L1662, so a handle that
    // never guessed shows no difference between original and copy under the
    // flag. This is the control: it proves the two assertions above turn on
    // `guessed_scheme` and not on duplication in general.
    let explicit = Handle::parse("http://example.com:1234/", 0);
    let explicit_copy = explicit.dup();
    assert_eq!(
        explicit.text(CURLUPART_SCHEME, CURLU_NO_GUESS_SCHEME),
        "http"
    );
    assert_eq!(
        explicit_copy.text(CURLUPART_SCHEME, CURLU_NO_GUESS_SCHEME),
        "http"
    );
    assert_eq!(
        explicit.snapshot(CURLU_NO_GUESS_SCHEME),
        explicit_copy.snapshot(CURLU_NO_GUESS_SCHEME),
        "with no guessed scheme, a copy is indistinguishable under every part"
    );
}

/// What `curl_url_dup()` *does* copy: all ten strings, byte for byte.
///
/// Without this, [`fb1_dup_drops_guessed_scheme_is_preserved`] could pass for
/// the wrong reason -- a duplicate that copied nothing at all would also make
/// the copy's `guessed_scheme` clear. So the ten `DUP` calls at
/// `lib/urlapi.c` L1314-L1323 get their own assertion, over the whole part set
/// rather than the parts a reader might think of.
///
/// The vector is the first entry of the upstream duplication list at
/// `tests/libtest/lib1560.c` L1973-L1979, which is chosen to populate as many
/// members as one URL can: scheme, user, password, a bracketed host, a zone
/// identifier, a port, a path, a query and a fragment. Only `options` is
/// absent, because `http`'s descriptor does not carry `PROTOPT_URLOPTIONS` and
/// L288-L290 therefore never asks for one; the `imap` handle in
/// [`set_and_get_round_trip_every_part`] covers that member and it is covered
/// again below.
#[test]
fn dup_copies_all_ten_strings_and_the_numeric_port() {
    let original = Handle::parse(
        "http://user:pwd@[2a04:4e42:e00::347%25eth0]:80/path?query#fraggie",
        0,
    );
    let copy = original.dup();

    assert_eq!(
        original.snapshot(0),
        copy.snapshot(0),
        "the ten DUP calls at L1314-L1323 must reproduce every part"
    );

    // Spelled out for the two members a whole-part comparison could hide.
    // `zoneid` is the tenth DUP and the one a reader is likeliest to forget,
    // and it is invisible in a plain part read of the host.
    assert_eq!(copy.text(CURLUPART_ZONEID, 0), "eth0");
    assert_eq!(copy.text(CURLUPART_HOST, 0), "[2a04:4e42:e00::347]");

    // `portnum` is a number rather than a string, copied at L1324, and the only
    // thing that reads it is the default-port comparison at L1598-L1601. Port 80
    // is http's default, `lib/urldata.h` L36, so a copy whose `portnum` did not
    // transfer would answer the port here instead of suppressing it.
    assert_eq!(
        original.code(CURLUPART_PORT, CURLU_NO_DEFAULT_PORT),
        CURLUE_NO_PORT
    );
    assert_eq!(
        copy.code(CURLUPART_PORT, CURLU_NO_DEFAULT_PORT),
        CURLUE_NO_PORT,
        "L1324 must copy portnum, or the default-port test at L1600 misfires"
    );

    // The options member, on a scheme whose descriptor carries the bit.
    let with_options = Handle::parse("imap://user:pwd;opt@example.com/box", 0);
    let options_copy = with_options.dup();
    assert_eq!(options_copy.text(CURLUPART_OPTIONS, 0), "opt");
    assert_eq!(with_options.snapshot(0), options_copy.snapshot(0));
}

/// `curl_url_dup()` copies `query_present` and `fragment_present`.
///
/// L1325-L1326. Neither member is a string and neither is visible without
/// `CURLU_GET_EMPTY`, which is what makes them easy to lose in a port.
///
/// `http://example.com/?#` sets both. `handle_query` at `lib/urlapi.c`
/// L1036-L1063 sets `query_present` unconditionally and, for a single-byte
/// query, stores an empty string at L1058-L1060. `handle_fragment` at
/// L1012-L1034 sets `fragment_present` unconditionally and, for a single-byte
/// fragment, stores nothing at all -- the `fraglen > 1` test at L1016 is false
/// -- so `u->fragment` stays null.
///
/// Reading them back therefore needs both members and the flag:
/// `CURLUPART_QUERY` clears an empty query at L1613-L1615 unless
/// `CURLU_GET_EMPTY` is set, `CURLUPART_FRAGMENT` synthesises an empty string
/// at L1620-L1622 only when the member is set and the flag is given, and
/// `urlget_url`'s `show_query` and `show_fragment` at L1432-L1435 consult both.
#[test]
fn dup_copies_the_query_and_fragment_presence_flags() {
    let original = Handle::parse("http://example.com/?#", 0);
    let copy = original.dup();

    assert_eq!(original.code(CURLUPART_QUERY, 0), CURLUE_NO_QUERY);
    assert_eq!(copy.code(CURLUPART_QUERY, 0), CURLUE_NO_QUERY);
    assert_eq!(original.code(CURLUPART_FRAGMENT, 0), CURLUE_NO_FRAGMENT);
    assert_eq!(copy.code(CURLUPART_FRAGMENT, 0), CURLUE_NO_FRAGMENT);
    assert_eq!(original.text(CURLUPART_URL, 0), "http://example.com/");
    assert_eq!(copy.text(CURLUPART_URL, 0), "http://example.com/");

    // With it, both members surface -- which they cannot do on the copy unless
    // L1325-L1326 transferred them.
    assert_eq!(original.text(CURLUPART_QUERY, CURLU_GET_EMPTY), "");
    assert_eq!(
        copy.text(CURLUPART_QUERY, CURLU_GET_EMPTY),
        "",
        "L1326 must copy query_present"
    );
    assert_eq!(original.text(CURLUPART_FRAGMENT, CURLU_GET_EMPTY), "");
    assert_eq!(
        copy.text(CURLUPART_FRAGMENT, CURLU_GET_EMPTY),
        "",
        "L1325 must copy fragment_present"
    );
    assert_eq!(
        original.text(CURLUPART_URL, CURLU_GET_EMPTY),
        "http://example.com/?#"
    );
    assert_eq!(
        copy.text(CURLUPART_URL, CURLU_GET_EMPTY),
        "http://example.com/?#",
        "both delimiters come back only if both presence members transferred"
    );

    assert_eq!(
        original.snapshot(CURLU_GET_EMPTY),
        copy.snapshot(CURLU_GET_EMPTY)
    );
}

// ===========================================================================
// Section 7 -- FB2, FB3 and FB6
//
// FB4 and FB5 are not here, and both are accounted for. FB4 is the bare-colon
// port leniency at `lib/urlapi.c` L363-L373 -- a trailing colon with no digits
// truncates the host and succeeds, but only when a scheme is present -- and it
// is covered by `rust-urlapi/tests/host_ip.rs`, which owns the host and address
// vectors. FB5 is that `include/curl/urlapi.h` L149 declares
// `curl_url_strerror` with no parameter name where its manual page names one;
// that is a property of the mirror header, `rust-urlapi/include/
// curl_urlapi_rs.h`, and no Rust code can observe it. All six findings are
// therefore accounted for: four here, one in a sibling test file, one in a
// header.
// ===========================================================================

/// `FB2`: the credential exit path discards `user`, `password` and `options`,
/// and the port does the same.
///
/// This asserts a faithful reproduction of a C oddity, required by the Agent
/// Action Plan at its 0.6.6 and recorded in
/// `rust-urlapi/docs/KNOWN-DIVERGENCES.md` under `FB2`. The invariant is that
/// the three members are cleared, so a failure here means the port diverged
/// from the reference and `src/parse/authority.rs` is where it diverged.
///
/// # What the C does
///
/// `parse_hostname_login`'s shared exit label at `lib/urlapi.c` L323-L330 frees
/// the three *local* pointers and then assigns null to `u->user`,
/// `u->password` and `u->options` unconditionally -- without freeing them. Three
/// paths reach it:
///
/// - no `@` in the authority at all, at L273-L275, with `result` still
///   `CURLUE_OK`, which is the path *every* credential-free authority takes;
/// - an allocation failure at L292-L296;
/// - a `CURLU_DISALLOW_USER` violation at L300-L303.
///
/// # Why it is harmless in one place and not the other
///
/// On the ordinary parse path the handle is a zeroed temporary --
/// `parseurl_and_replace` at L1197-L1209 parses into it and swaps only on
/// success -- so nulling three already-null members costs nothing.
/// `Curl_url_set_authority` at L657-L675 is different: it operates on the
/// **live** handle and passes `CURLU_DISALLOW_USER` at L667, and
/// `lib/http2.c` L739 calls it that way for HTTP/2 server push. So a handle
/// that carried credentials loses them, silently, on both the succeeding and
/// the failing path.
///
/// # What is asserted, and what cannot be
///
/// The wipe is observable and is asserted. The leak is not: no sequence of
/// `curl_url_get`, `curl_url_set` or `curl_url_dup` calls can distinguish a
/// leaked buffer from a released one, and `KNOWN-DIVERGENCES.md` records under
/// `FB2` that the port releases where the C abandons, because `Drop` on an owned
/// buffer runs when the field is reassigned. Only an allocation counter could
/// see that, and the parity harness deliberately runs without curl's own
/// counter -- reportable constraint `R3` at the plan's 0.2.4.3.
#[test]
fn fb2_authority_wipes_credentials_is_preserved() {
    // The succeeding path: an authority with no '@' at all, L273-L275.
    let mut handle = Handle::parse("http://user:pwd@example.com/path", 0);
    assert_eq!(handle.text(CURLUPART_USER, 0), "user");
    assert_eq!(handle.text(CURLUPART_PASSWORD, 0), "pwd");

    assert_eq!(
        handle.set_authority("example.com"),
        CURLUE_OK,
        "an authority with no credentials succeeds"
    );
    assert_eq!(handle.text(CURLUPART_HOST, 0), "example.com");
    assert_eq!(
        handle.code(CURLUPART_USER, 0),
        CURLUE_NO_USER,
        "FB2: L328 nulled u->user on a SUCCEEDING call. Reproduced \
         deliberately -- see KNOWN-DIVERGENCES.md FB2."
    );
    assert_eq!(
        handle.code(CURLUPART_PASSWORD, 0),
        CURLUE_NO_PASSWORD,
        "FB2: L329 nulled u->password. Reproduced deliberately."
    );
    // And the whole URL no longer carries them, since L1518-L1523's template
    // emits the credential group only for the members that are present.
    assert_eq!(handle.text(CURLUPART_URL, 0), "http://example.com/path");

    // The failing path: an authority that does carry a user, rejected at
    // L300-L303 because L667 passes CURLU_DISALLOW_USER. The rejection does not
    // undo the wipe, and it does not install the new host either -- L669-L670
    // releases the working buffer and leaves `u->host` alone.
    let mut handle = Handle::parse("http://user:pwd@example.com/path", 0);
    assert_eq!(
        handle.set_authority("bob@other.example"),
        CURLUE_USER_NOT_ALLOWED
    );
    assert_eq!(
        handle.text(CURLUPART_HOST, 0),
        "example.com",
        "a rejected authority leaves the host alone, L669-L670"
    );
    assert_eq!(
        handle.code(CURLUPART_USER, 0),
        CURLUE_NO_USER,
        "FB2: the credentials are wiped even though the call FAILED, because \
         L300-L303 jumps to the same label. Reproduced deliberately."
    );
    assert_eq!(handle.code(CURLUPART_PASSWORD, 0), CURLUE_NO_PASSWORD);
    assert_eq!(handle.text(CURLUPART_URL, 0), "http://example.com/path");

    // The options member takes the same wipe, on a scheme whose descriptor
    // carries PROTOPT_URLOPTIONS so that the member can be populated at all.
    let mut handle = Handle::parse("imap://user:pwd;opt@example.com/box", 0);
    assert_eq!(handle.text(CURLUPART_OPTIONS, 0), "opt");
    assert_eq!(handle.set_authority("other.example"), CURLUE_OK);
    assert_eq!(
        handle.code(CURLUPART_OPTIONS, 0),
        CURLUE_NO_OPTIONS,
        "FB2: L330 nulled u->options too. Reproduced deliberately."
    );

    // The control: the public setter is not affected, because it never routes
    // through `parse_hostname_login`. `curl_url_set(CURLUPART_HOST, ..)` reaches
    // L1846-L1848 instead, which touches the host and the zone identifier only.
    let mut handle = Handle::parse("http://user:pwd@example.com/path", 0);
    assert_eq!(handle.set(CURLUPART_HOST, "other.example", 0), CURLUE_OK);
    assert_eq!(
        handle.text(CURLUPART_USER, 0),
        "user",
        "the public host setter must NOT wipe credentials -- only the authority \
         path does, and that asymmetry is the finding"
    );
    assert_eq!(handle.text(CURLUPART_PASSWORD, 0), "pwd");
    assert_eq!(
        handle.text(CURLUPART_URL, 0),
        "http://user:pwd@other.example/path"
    );
}

/// `FB3`: the zone identifier is stored over an existing value and never
/// cleared, and the port does the same.
///
/// This asserts a faithful reproduction of a C oddity, required by the Agent
/// Action Plan at its 0.6.6 and recorded in
/// `rust-urlapi/docs/KNOWN-DIVERGENCES.md` under `FB3`. The invariant is that
/// the stale zone stays readable, so a failure here means the port diverged
/// from the reference and `src/parse/ipv6.rs` is where it diverged.
///
/// # What the C does
///
/// `ipv6_parse`'s zone branch runs from `lib/urlapi.c` L405 to L423 and assigns
/// `u->zoneid` at L418. There is no free of a previous value before that
/// assignment, and there is no `else` branch that clears the member when the
/// address has no zone. So the member is only ever written, never reset.
///
/// # Why it is reachable
///
/// `parse_authority`'s `HOST_NAME` arm at L640-L644 -- the arm a plain hostname
/// takes -- never touches `u->zoneid` either, and
/// `Curl_url_set_authority` at L657-L675 runs `parse_authority` on a live
/// handle. So replacing a zoned IPv6 host with a plain hostname through the
/// authority path leaves the old zone readable.
///
/// # The asymmetry, which is the actual bug
///
/// Three ways of changing the host disagree, and the disagreement is what makes
/// this a finding rather than a design choice:
///
/// - `Curl_url_set_authority` leaves the zone in place, because neither L418 nor
///   L640-L644 clears it;
/// - `curl_url_set(CURLUPART_HOST, ..)` **does** clear it, at L1848's
///   `Curl_safefree(u->zoneid)`;
/// - `curl_url_set(CURLUPART_HOST, NULL, 0)` does **not**, because
///   `urlset_clear`'s host arm at L1752-L1754 frees the host alone.
///
/// # What a stale zone does and does not affect
///
/// It stays readable through `CURLUPART_ZONEID` and stays invisible in the
/// serialised URL, because L1480-L1491 emits the zone only when the host begins
/// with `[`. So the handle carries a value that no URL it can produce could ever
/// contain.
///
/// As with `FB2`, the leak half is not reproduced and cannot be observed here;
/// `KNOWN-DIVERGENCES.md` records it under `FB3`.
#[test]
fn fb3_stale_zoneid_survives_authority_change_is_preserved() {
    let mut handle = Handle::parse("https://[fe80::1%25eth0]/path", 0);
    assert_eq!(handle.text(CURLUPART_HOST, 0), "[fe80::1]");
    assert_eq!(handle.text(CURLUPART_ZONEID, 0), "eth0");
    assert_eq!(
        handle.text(CURLUPART_URL, 0),
        "https://[fe80::1%25eth0]/path"
    );

    assert_eq!(handle.set_authority("example.com"), CURLUE_OK);
    assert_eq!(handle.text(CURLUPART_HOST, 0), "example.com");
    assert_eq!(
        handle.text(CURLUPART_ZONEID, 0),
        "eth0",
        "FB3: the zone identifier survives a host that cannot have one, because \
         L418 is the only write and L640-L644 does not clear. Reproduced \
         deliberately -- see KNOWN-DIVERGENCES.md FB3."
    );
    assert_eq!(
        handle.text(CURLUPART_URL, 0),
        "https://example.com/path",
        "the stale zone stays invisible in the URL, L1480-L1491 emits it only \
         for a bracketed host"
    );

    // The asymmetry, one path at a time. The public host setter clears it, L1848.
    let mut handle = Handle::parse("https://[fe80::1%25eth0]/path", 0);
    assert_eq!(handle.set(CURLUPART_HOST, "example.com", 0), CURLUE_OK);
    assert_eq!(
        handle.code(CURLUPART_ZONEID, 0),
        CURLUE_NO_ZONEID,
        "L1848 frees the zone identifier, so this path and the authority path \
         disagree -- that disagreement is FB3"
    );

    // Clearing the host does not, L1752-L1754.
    let mut handle = Handle::parse("https://[fe80::1%25eth0]/path", 0);
    assert_eq!(handle.clear(CURLUPART_HOST), CURLUE_OK);
    assert_eq!(handle.code(CURLUPART_HOST, 0), CURLUE_NO_HOST);
    assert_eq!(
        handle.text(CURLUPART_ZONEID, 0),
        "eth0",
        "FB3, further asymmetry: urlset_clear's host arm frees the host alone, \
         so clearing the host and replacing it behave differently. Reproduced \
         deliberately."
    );

    // A second zoned address replaces the first, which is the write at L418
    // landing on a member that already held a value.
    let mut handle = Handle::parse("https://[fe80::1%25eth0]/path", 0);
    assert_eq!(handle.set_authority("[fe80::2%25eth1]"), CURLUE_OK);
    assert_eq!(handle.text(CURLUPART_HOST, 0), "[fe80::2]");
    assert_eq!(handle.text(CURLUPART_ZONEID, 0), "eth1");

    // And a rejected authority leaves whatever the previous one wrote, because
    // L669-L670 unwinds the host and nothing unwinds the zone.
    let mut handle = Handle::parse("https://[fe80::1%25eth0]/path", 0);
    assert_eq!(handle.set_authority("[bad"), CURLUE_BAD_IPV6);
    assert_eq!(handle.text(CURLUPART_HOST, 0), "[fe80::1]");
    assert_eq!(handle.text(CURLUPART_ZONEID, 0), "eth0");
}

/// **FB6: the terminator one byte past the logical length has to be
/// addressable.**
///
/// This one has no value to read, so it is asserted indirectly, and saying why
/// is most of the test. `ipv6_parse` writes a terminator one byte beyond the
/// length it is tracking, twice, and relies on the dynamic buffer having a byte
/// there. `lib/urlapi.c` L397-L398 advances `hostname` past the opening bracket
/// and takes two off `hlen`, so from then on index `hlen` is the closing bracket
/// and index `hlen + 1` is the string's own terminator.
///
/// The first write is L421-L422, in the zone branch: the bracket goes back at
/// `hostname[len]` and the terminator at `hostname[len + 1]`. Room is guaranteed
/// because `len` stopped short of the zone text still in the input.
///
/// The second is the tight one, L432-L439: the address is terminated for
/// `curlx_inet_pton`, `curlx_inet_ntop` writes the normalised form back with
/// room for `hlen + 1` bytes, L436 recomputes `hlen` with `strlen` because the
/// normalised form can be **shorter**, L437 terminates at `hostname[hlen + 1]`
/// and L439 restores the bracket at `hostname[hlen]`.
///
/// So `FB6` is a capacity requirement on `rust-urlapi/src/dynbuf.rs` rather than
/// an observable value: a host modelled as a slice of exactly its logical length
/// has nowhere to put that write, and trimming instead of modelling the extra
/// byte would change behaviour for input at the maximum length.
/// `KNOWN-DIVERGENCES.md` records it under `FB6`, and a unit test in
/// `src/parse/ipv6.rs` asserts the highest byte written is that slot.
///
/// What this test can do is exercise the shapes that a naive port would get
/// wrong, and require them to round-trip exactly: a zone identifier at exactly
/// the fifteen-byte cap the loop at L416 imposes, and a bracketed address whose
/// normalised form is materially shorter than its input, which is what makes
/// L436-L437 re-terminate at a new length at all.
#[test]
fn fb6_terminator_capacity_is_modelled() {
    // A normalised form far shorter than the input: eight groups of four
    // becomes `[fe80::1]`. If the second terminator write were dropped or the
    // host trimmed to the pre-normalisation length, the trailing bytes of the
    // long form would still be readable after the bracket.
    let handle = Handle::parse("https://[fe80:0000:0000:0000:0000:0000:0000:0001]/p", 0);
    assert_eq!(handle.text(CURLUPART_HOST, 0), "[fe80::1]");
    assert_eq!(handle.text(CURLUPART_URL, 0), "https://[fe80::1]/p");

    // Both writes on one input: the zone branch runs L421-L422 and then
    // normalisation runs L432-L439, and the zone is at exactly the cap.
    // `while(*h && (*h != ']') && (i < 15))` at L416 copies at most fifteen
    // bytes, and L417's `if(!i || (']' != *h))` then requires the very next byte
    // to be the closing bracket -- so fifteen is the longest zone that parses
    // and sixteen is rejected.
    let fifteen = "abcdefghijklmno";
    assert_eq!(fifteen.len(), 15);
    let handle = Handle::parse(
        &format!("https://[fe80:0000:0000:0000:0000:0000:0000:0001%25{fifteen}]/p"),
        0,
    );
    assert_eq!(handle.text(CURLUPART_HOST, 0), "[fe80::1]");
    assert_eq!(handle.text(CURLUPART_ZONEID, 0), fifteen);
    assert_eq!(
        handle.text(CURLUPART_URL, 0),
        format!("https://[fe80::1%25{fifteen}]/p")
    );

    // Sixteen: the loop stops with `*h` still a letter, so L417 fails.
    let mut handle = Handle::new();
    assert_eq!(
        handle.set(CURLUPART_URL, "https://[fe80::1%25abcdefghijklmnop]/p", 0),
        CURLUE_BAD_IPV6,
        "L416's cap is fifteen and L417 requires the bracket immediately after"
    );

    // A shortening normalisation *and* a zone *and* a default port to suppress,
    // which is the densest shape the serialiser has to rebuild: L1483-L1487
    // splices the zone back inside the brackets using the host's length, so a
    // host whose stored length disagreed with its terminator would show up here.
    let handle = Handle::parse(
        "https://[2a04:4e42:0e00:0000:0000:0000:0000:0347%25eth0]:443/p",
        0,
    );
    assert_eq!(handle.text(CURLUPART_HOST, 0), "[2a04:4e42:e00::347]");
    assert_eq!(handle.text(CURLUPART_ZONEID, 0), "eth0");
    assert_eq!(
        handle.text(CURLUPART_URL, 0),
        "https://[2a04:4e42:e00::347%25eth0]:443/p"
    );
    assert_eq!(
        handle.text(CURLUPART_URL, CURLU_NO_DEFAULT_PORT),
        "https://[2a04:4e42:e00::347%25eth0]/p"
    );

    // The shortest address the function accepts at all, L394-L395's `hlen < 4`.
    let handle = Handle::parse("https://[::]/p", 0);
    assert_eq!(handle.text(CURLUPART_HOST, 0), "[::]");
    let mut handle = Handle::new();
    assert_eq!(
        handle.set(CURLUPART_URL, "https://[:]/p", 0),
        CURLUE_BAD_IPV6
    );
}

/// Setting `CURLUPART_URL` to `""` on a handle that already holds a URL is a
/// no-op SUCCESS.
///
/// `set_url` at `lib/urlapi.c` L1685-L1730 begins with `if(!part_size)`, and the
/// comment at L1698-L1699 records the intent: a blank URL is not a valid URL on
/// its own and is accepted only because a complete one is already present and
/// this is a redirect. L1700 reads the whole URL back out, L1701-L1704 releases
/// the copy and returns `CURLUE_OK`, and nothing about the handle changes.
///
/// The return code alone would not establish that. So the whole handle is
/// snapshotted before and after, which is what "no-op" actually claims.
#[test]
fn setting_the_whole_url_to_empty_is_a_successful_no_op() {
    let mut handle = Handle::parse("https://user:pwd@example.com:8080/p?q#f", 0);
    let before = handle.snapshot(CURLU_GET_EMPTY);

    assert_eq!(
        handle.set(CURLUPART_URL, "", 0),
        CURLUE_OK,
        "L1705 returns CURLUE_OK for an empty value on a complete handle"
    );
    assert_eq!(
        handle.snapshot(CURLU_GET_EMPTY),
        before,
        "L1701-L1704 changes nothing at all"
    );
    assert_eq!(
        handle.text(CURLUPART_URL, 0),
        "https://user:pwd@example.com:8080/p?q#f"
    );

    assert_eq!(handle.set(CURLUPART_URL, "", 0), CURLUE_OK);
    assert_eq!(handle.snapshot(CURLU_GET_EMPTY), before);
}

/// Setting `CURLUPART_URL` to `""` on a handle that cannot produce a URL fails.
///
/// L1700's read is what decides, and L1709 turns any failure other than
/// out-of-memory into `CURLUE_MALFORMED_INPUT`. A fresh handle has no host, so
/// `urlget_url` returns `CURLUE_NO_HOST` at L1448-L1449 and the empty set becomes
/// `CURLUE_MALFORMED_INPUT` -- note the code the caller sees is *not* the one the
/// read produced, which is why tracing L1709 matters.
#[test]
fn setting_the_whole_url_to_empty_fails_on_a_handle_that_has_no_url() {
    let mut handle = Handle::new();
    // The read L1700 performs, shown first so that the mapping at L1709 is
    // visible rather than inferred.
    assert_eq!(handle.code(CURLUPART_URL, 0), CURLUE_NO_HOST);
    assert_eq!(
        handle.set(CURLUPART_URL, "", 0),
        CURLUE_MALFORMED_INPUT,
        "L1709 maps every non-OOM failure to CURLUE_MALFORMED_INPUT"
    );
    assert_eq!(handle.snapshot(0), Handle::new().snapshot(0));

    let mut handle = Handle::new();
    assert_eq!(handle.set(CURLUPART_SCHEME, "https", 0), CURLUE_OK);
    assert_eq!(handle.code(CURLUPART_URL, 0), CURLUE_NO_HOST);
    assert_eq!(handle.set(CURLUPART_URL, "", 0), CURLUE_MALFORMED_INPUT);
}

/// The empty-string outcome depends on the caller's flags.
///
/// L1700 hands the caller's `flags` to `curl_url_get` **unfiltered**, so whether
/// `""` is a success depends on whether the handle can produce a whole URL under
/// exactly those flags. That makes a flag describing how to *read* a URL decide
/// the outcome of a *write*, which nothing in the documented API suggests.
///
/// The reachable case is a handle with a host and no scheme. `urlget_url` needs a
/// scheme: L1453-L1454 takes the stored one, L1455-L1456 substitutes
/// `DEFAULT_SCHEME` when `CURLU_DEFAULT_SCHEME` is given, and L1457-L1458 returns
/// `CURLUE_NO_SCHEME` when neither applies. So with flags of zero the read fails
/// and L1709 answers `CURLUE_MALFORMED_INPUT`; with `CURLU_DEFAULT_SCHEME` the
/// read succeeds and L1705 answers `CURLUE_OK`. One handle, one empty string,
/// opposite outcomes.
///
/// The substituted scheme is *not* stored -- L1455 assigns a local -- so the
/// successful call really is a no-op and the handle still has no scheme
/// afterwards.
#[test]
fn the_empty_string_outcome_depends_on_the_read_flags() {
    let mut handle = Handle::new();
    assert_eq!(handle.set(CURLUPART_HOST, "example.com", 0), CURLUE_OK);

    // The two reads L1700 would perform, so that the two writes below are
    // explained rather than merely observed.
    assert_eq!(handle.code(CURLUPART_URL, 0), CURLUE_NO_SCHEME);
    assert_eq!(
        handle.text(CURLUPART_URL, CURLU_DEFAULT_SCHEME),
        "https://example.com/"
    );

    assert_eq!(
        handle.set(CURLUPART_URL, "", 0),
        CURLUE_MALFORMED_INPUT,
        "L1457-L1458 refuses, L1709 maps it"
    );
    assert_eq!(
        handle.set(CURLUPART_URL, "", CURLU_DEFAULT_SCHEME),
        CURLUE_OK,
        "L1455-L1456 substitutes DEFAULT_SCHEME, so the read succeeds and \
         L1705 returns CURLUE_OK -- the same call, one flag apart"
    );

    // The substitution was local to the read: the handle still has no scheme.
    assert_eq!(handle.code(CURLUPART_SCHEME, 0), CURLUE_NO_SCHEME);
    assert_eq!(handle.code(CURLUPART_URL, 0), CURLUE_NO_SCHEME);
}

/// `CURLU_NO_GUESS_SCHEME` on a guessed-scheme handle makes the empty-string
/// write `CURLUE_MALFORMED_INPUT`, which is what `AAP` 0.6.5 specifies.
///
/// # The contract
///
/// 0.6.5 states it in as many words: "Setting the whole URL to the empty string
/// with the no-guess-scheme flag on a handle whose scheme was guessed **fails**
/// with malformed input ... while the identical call with no flags **succeeds**
/// as a no-op." Both halves are asserted below, and the plan governs the
/// implementation, so this is the contract the crate implements and this test
/// is what holds it in place.
///
/// # It is a bounded divergence from the C, and saying so is part of the test
///
/// The reference answers `CURLUE_OK` for this one call. That is not a doubt
/// about the requirement; it is the shape of the divergence, and a reader who
/// does not know it will eventually "correct" the wrong side.
///
/// `CURLU_NO_GUESS_SCHEME` has two unrelated effects in two different branches
/// of the reader. In the `CURLUPART_SCHEME` branch it is an error: L1559-L1560
/// return `CURLUE_NO_SCHEME` when the member is set. In the whole-URL branch it
/// is only a formatting choice: L1512-L1515 blank `schemebuf` and the function
/// carries on to return `CURLUE_OK`. L1700 asks for `CURLUPART_URL`, and
/// L1624-L1625 dispatches that straight into `urlget_url`, so the read meets the
/// second behaviour and never reaches the guard 0.6.5 attributes the failure to.
/// A probe linked against a `libcurl.a` built from the unmodified tree confirms
/// it: `CURLUE_OK`, with the flag and without it, handle unchanged.
///
/// The port therefore tests the combination *ahead* of that read, in
/// `src/getset.rs`'s `set_url`, because the read cannot produce the answer.
/// `rust-urlapi/docs/KNOWN-DIVERGENCES.md` carries the entry "Divergence: the
/// empty whole-URL write under `CURLU_NO_GUESS_SCHEME`", which records the
/// measurement and bounds the divergence to exactly this combination.
///
/// # Why the divergence costs no acceptance criterion
///
/// Nothing measurable reaches it. `tests/libtest/lib1560.c` writes `""` to
/// `CURLUPART_URL` in one place only -- `set_url_list` at its L1227-L1230, with
/// set-flags of zero -- so `A5` runs unaffected by this test's subject; and
/// `rust-urlapi/demo/urlapi_demo.c` keeps the combination out of its transcript,
/// which is what `A7`, a byte-for-byte diff against the same demo linked against
/// the unmodified C, requires of it.
///
/// What the oracle *does* pin is the read, and the port leaves that alone: its
/// `get_url_list` asserts that a guessed handle's whole-URL read under
/// `CURLU_NO_GUESS_SCHEME` succeeds with the prefix suppressed, while its
/// `get_parts_list` asserts `CURLUE_NO_SCHEME` for the scheme part of the same
/// handle under the same flag. Both are asserted below alongside the write, so
/// a change that widened the divergence onto the read side would fail here
/// before it failed the oracle.
#[test]
fn an_empty_url_and_no_guess_scheme_is_malformed_input() {
    let mut handle = Handle::parse(GUESSED_INPUT, CURLU_GUESS_SCHEME);
    let before = handle.snapshot(CURLU_GET_EMPTY);

    // The read side, untouched by the divergence: CURLUE_OK with the prefix
    // suppressed, L1512-L1515. tests/libtest/lib1560.c asserts this vector.
    assert_eq!(
        handle.text(CURLUPART_URL, CURLU_NO_GUESS_SCHEME),
        "example.com:1234/"
    );
    // The scheme branch, for contrast. It is a different part, and it is the
    // one L1559-L1560 governs.
    assert_eq!(
        handle.code(CURLUPART_SCHEME, CURLU_NO_GUESS_SCHEME),
        CURLUE_NO_SCHEME
    );

    assert_eq!(
        handle.set(CURLUPART_URL, "", CURLU_NO_GUESS_SCHEME),
        CURLUE_MALFORMED_INPUT,
        "AAP 0.6.5 specifies malformed input for this combination; the \
         reference answers CURLUE_OK and the divergence is bounded and \
         recorded in docs/KNOWN-DIVERGENCES.md"
    );
    // The other half of 0.6.5: the identical call with no flags is the no-op.
    assert_eq!(handle.set(CURLUPART_URL, "", 0), CURLUE_OK);
    assert_eq!(
        handle.snapshot(CURLU_GET_EMPTY),
        before,
        "neither call mutates the handle: the refusal is not a partial write \
         and the success is a no-op"
    );

    // The refusal needs a *guessed* scheme, not merely the flag. A handle
    // carrying its scheme explicitly succeeds, because L1512's second disjunct
    // is true when the member is clear and 0.6.5's condition names the member.
    let mut explicit = Handle::parse("https://example.com/p", 0);
    assert_eq!(
        explicit.set(CURLUPART_URL, "", CURLU_NO_GUESS_SCHEME),
        CURLUE_OK
    );
    assert_eq!(explicit.text(CURLUPART_URL, 0), "https://example.com/p");

    // And with CURLU_DEFAULT_SCHEME instead of a guess, which stores no scheme
    // at all and so does not set the member either.
    let mut defaulted = Handle::parse("example.com/p", CURLU_DEFAULT_SCHEME);
    assert_eq!(
        defaulted.set(CURLUPART_URL, "", CURLU_NO_GUESS_SCHEME),
        CURLUE_OK
    );
}

/// `set_url`'s three dispatch branches, one case each.
///
/// After the empty-string rule, `lib/urlapi.c` L1713-L1725 chooses between three
/// outcomes and the choice is not obvious from the outside.
///
/// **Absolute replaces.** L1713-L1714 asks `Curl_is_absolute_url` with the
/// caller's flags narrowed to `CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME` -- the
/// narrowing is what makes the guessing asymmetry apply here -- and L1715 hands
/// an absolute value to `parseurl_and_replace`, which discards everything the
/// handle held.
///
/// **An incomplete old URL also replaces.** L1719 reads the whole URL, L1720-
/// L1721 propagates an allocation failure, and L1722-L1723 treats the new value
/// as a replacement even though it is relative.
///
/// **Otherwise the relative part is applied.** L1725 hands the old URL and the
/// new value to `redirect_url`, which resolves one against the other.
///
/// # Reaching the middle branch takes two conditions at once, not one
///
/// This is the part worth spelling out, because getting it wrong produces a case
/// that looks like it tests the middle branch and in fact tests the first. Both
/// conditions must hold:
///
/// 1. the new value must **not** be absolute, or L1713-L1715 answers first; and
/// 2. the old handle must fail to serialise, or L1725 answers instead.
///
/// Condition 1 is stricter than "has no scheme". `Curl_is_absolute_url` at
/// L195-L206 scans an alphanumeric-plus-`+-.` run and requires the byte after it
/// to be a colon; so `https://replaced.example/p` is absolute and
/// `other.example/p` is not, because its run stops at a slash. And the flag
/// argument at L1714 is narrowed to `CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME`,
/// which only ever makes the function *stricter* -- L206's second disjunct
/// demands `://` rather than `:` once guessing is on -- so no flag can turn a
/// slash-terminated run into an absolute URL.
///
/// Condition 2 needs a handle that holds something and still cannot produce a
/// URL. Two exist and both are used below: a host with no scheme, which L1453-
/// L1458 refuses with `CURLUE_NO_SCHEME`, and a path with no host, which L1448-
/// L1449 refuses with `CURLUE_NO_HOST`.
///
/// # Why the outcome is nevertheless distinguishable
///
/// The middle and first branches both call `parseurl_and_replace`, so the answer
/// alone cannot tell them apart -- which is exactly how a case satisfying only
/// condition 1 can masquerade as coverage of the middle one. What separates them
/// is what happens when the middle branch is *not* taken: control reaches L1725
/// with no old URL, and resolving a relative value against nothing yields
/// `CURLUE_MALFORMED_INPUT` rather than a parse. So a non-absolute value that
/// succeeds over a handle which cannot serialise can only have come through
/// L1722-L1723, and the assertions below are written to fail if it ever comes
/// through anywhere else.
#[test]
fn set_url_dispatches_to_replace_or_resolve() {
    // Branch one: absolute, L1713-L1715. Every part of the old handle goes,
    // including the query and the fragment.
    let mut handle = Handle::parse("https://user:pwd@example.com:8080/a/b?q#f", 0);
    assert_eq!(
        handle.set(CURLUPART_URL, "http://other.example/z", 0),
        CURLUE_OK
    );
    assert_eq!(handle.text(CURLUPART_URL, 0), "http://other.example/z");
    assert_eq!(handle.code(CURLUPART_USER, 0), CURLUE_NO_USER);
    assert_eq!(handle.code(CURLUPART_QUERY, 0), CURLUE_NO_QUERY);
    assert_eq!(handle.code(CURLUPART_FRAGMENT, 0), CURLUE_NO_FRAGMENT);

    // Branch three: relative, L1725. `..` climbs one segment and the query
    // replaces the old one. `redirect_url` force-clears CURLU_PATH_AS_IS at
    // L1277, so the dot segments are removed rather than kept.
    assert_eq!(handle.set(CURLUPART_URL, "../rel?x", 0), CURLUE_OK);
    assert_eq!(handle.text(CURLUPART_URL, 0), "http://other.example/rel?x");

    // A fragment-only relative value, the L1240-L1243 branch of redirect_url.
    assert_eq!(handle.set(CURLUPART_URL, "#frag", 0), CURLUE_OK);
    assert_eq!(
        handle.text(CURLUPART_URL, 0),
        "http://other.example/rel?x#frag"
    );

    // A root-relative value, the L1234-L1238 branch.
    assert_eq!(handle.set(CURLUPART_URL, "/root", 0), CURLUE_OK);
    assert_eq!(handle.text(CURLUPART_URL, 0), "http://other.example/root");

    // A protocol-relative value, the L1226-L1232 branch, which changes the host.
    assert_eq!(handle.set(CURLUPART_URL, "//third.example/x", 0), CURLUE_OK);
    assert_eq!(handle.text(CURLUPART_URL, 0), "http://third.example/x");

    // Branch one again, over an incomplete handle. Kept because it is worth
    // knowing that an absolute value replaces whatever state the handle is in,
    // but it is NOT coverage of the middle branch: `https://replaced.example/p`
    // satisfies `Curl_is_absolute_url`, so L1713-L1715 returns before L1719 is
    // ever reached, whatever the handle holds.
    let mut handle = Handle::new();
    assert_eq!(handle.set(CURLUPART_HOST, "example.com", 0), CURLUE_OK);
    assert_eq!(handle.code(CURLUPART_URL, 0), CURLUE_NO_SCHEME);
    assert_eq!(
        handle.set(CURLUPART_URL, "https://replaced.example/p", 0),
        CURLUE_OK
    );
    assert_eq!(handle.text(CURLUPART_URL, 0), "https://replaced.example/p");

    // Branch two, first reachable shape: a host and no scheme. The value has no
    // colon anywhere, so condition 1 holds; the whole-URL read answers
    // CURLUE_NO_SCHEME, so condition 2 holds; and L1722-L1723 replaces.
    let mut hostonly = Handle::new();
    assert_eq!(hostonly.set(CURLUPART_HOST, "example.com", 0), CURLUE_OK);
    assert_eq!(
        hostonly.code(CURLUPART_URL, CURLU_GUESS_SCHEME),
        CURLUE_NO_SCHEME,
        "the handle cannot serialise even with the flag the set will carry, \
         which is condition 2"
    );
    assert_eq!(
        scheme_len("other.example/p", C_TRUE),
        0,
        "and the value is not absolute even in guessing mode, condition 1"
    );
    assert_eq!(
        hostonly.set(CURLUPART_URL, "other.example/p", CURLU_GUESS_SCHEME),
        CURLUE_OK
    );
    // The old host is gone, replaced rather than resolved against: a resolution
    // would have kept `example.com` and appended to it.
    assert_eq!(
        hostonly.text(CURLUPART_URL, 0),
        "http://other.example/p",
        "replaced, and the scheme guessed by the reparse rather than carried \
         over from a handle that never had one"
    );
    assert_eq!(hostonly.text(CURLUPART_HOST, 0), "other.example");
    assert_eq!(hostonly.text(CURLUPART_SCHEME, 0), "http");
    // The scheme is the guessed one, which is what proves the value went through
    // the parser: L1512-L1515 suppresses a guessed scheme under
    // CURLU_NO_GUESS_SCHEME, and L1559-L1560 refuses to report it.
    assert_eq!(
        hostonly.code(CURLUPART_SCHEME, CURLU_NO_GUESS_SCHEME),
        CURLUE_NO_SCHEME,
        "and it is marked guessed, not stored outright"
    );

    // Branch two, second reachable shape: a path and no host, which L1448-L1449
    // refuses for a different reason. Two shapes rather than one, because a port
    // that special-cased the missing scheme would still pass with only the first.
    let mut pathonly = Handle::new();
    assert_eq!(pathonly.set(CURLUPART_PATH, "/old", 0), CURLUE_OK);
    assert_eq!(
        pathonly.code(CURLUPART_URL, CURLU_GUESS_SCHEME),
        CURLUE_NO_HOST
    );
    assert_eq!(
        pathonly.set(CURLUPART_URL, "rel.example/q", CURLU_GUESS_SCHEME),
        CURLUE_OK
    );
    assert_eq!(pathonly.text(CURLUPART_URL, 0), "http://rel.example/q");
    assert_eq!(
        pathonly.text(CURLUPART_PATH, 0),
        "/q",
        "the old path went with everything else; it was not resolved against"
    );

    // The negative that pins the branch down. Same non-absolute value, same
    // incomplete handle, no flags -- so L1722-L1723 still runs, but the reparse
    // it delegates to has nothing to guess with and L951-L953 answers
    // CURLUE_BAD_SCHEME. Not CURLUE_MALFORMED_INPUT: that is what L1725 would
    // have produced from an empty base, so this code is itself evidence that
    // control took the middle branch and not the last one.
    let mut noflags = Handle::new();
    assert_eq!(noflags.set(CURLUPART_HOST, "example.com", 0), CURLUE_OK);
    assert_eq!(
        noflags.set(CURLUPART_URL, "other.example/p", 0),
        CURLUE_BAD_SCHEME
    );
    assert_eq!(
        noflags.text(CURLUPART_HOST, 0),
        "example.com",
        "and the refused replacement left the handle exactly as it was, because \
         parseurl_and_replace swaps only on success"
    );
}

/// A failed whole-URL set leaves the handle byte-identical.
///
/// `parseurl_and_replace` at `lib/urlapi.c` L1197-L1209 parses into a zeroed
/// temporary and swaps into the live handle only on success; a failed parse
/// releases the whole temporary at L1188-L1191 and the live handle is never
/// touched. So no partial mutation is observable, and that is asserted over the
/// whole part set rather than over the parts a reader might suspect.
///
/// Four different failures are used, so that the property is not established by
/// one early rejection alone: a bad IPv6 address, a bad zone identifier, an
/// unsupported scheme, and a value over the input-length ceiling at
/// L1824-L1826 -- which returns before the parse even starts.
#[test]
fn a_failed_whole_url_set_changes_nothing() {
    let mut handle = Handle::parse("https://user:pwd@example.com:8080/p?q#f", 0);
    let before = handle.snapshot(CURLU_GET_EMPTY);

    // Truncated bracketed address: no closing bracket, so `Curl_parse_port`
    // rejects it at L343-L346.
    assert_eq!(
        handle.set(CURLUPART_URL, "https://[fe80::1%25", 0),
        CURLUE_BAD_IPV6
    );
    assert_eq!(handle.snapshot(CURLU_GET_EMPTY), before);

    // Zone identifier one byte over the cap, L416-L417.
    assert_eq!(
        handle.set(CURLUPART_URL, "http://[fe80::1%25abcdefghijklmnop]/x", 0),
        CURLUE_BAD_IPV6
    );
    assert_eq!(handle.snapshot(CURLU_GET_EMPTY), before);

    // A scheme no table holds, L951-L953. Absent from the crate's own 33-row
    // table and from this file's nine-row stand-in alike, so the answer is the
    // same in both link modes.
    assert_eq!(
        handle.set(CURLUPART_URL, "gargle://example.com/x", 0),
        CURLUE_UNSUPPORTED_SCHEME
    );
    assert_eq!(handle.snapshot(CURLU_GET_EMPTY), before);

    // Over the ceiling, L1824-L1826, which rejects before the switch.
    let huge = format!("https://example.com/{}", "a".repeat(CURL_MAX_INPUT_LENGTH));
    assert_eq!(handle.set(CURLUPART_URL, &huge, 0), CURLUE_MALFORMED_INPUT);
    assert_eq!(handle.snapshot(CURLU_GET_EMPTY), before);

    // A relative value that cannot be resolved leaves the handle alone too --
    // this one reaches `redirect_url` at L1725 rather than the parser directly.
    assert_eq!(
        handle.set(CURLUPART_URL, "//[fe80::1%25abcdefghijklmnop]/x", 0),
        CURLUE_BAD_IPV6
    );
    assert_eq!(handle.snapshot(CURLU_GET_EMPTY), before);
}

/// `curl_url_strerror()` returns the message `lib/strerror.c` produces.
///
/// Compiled only under the `strerror` feature, which is on for the standalone
/// configuration and must be **off** for the drop-in one -- `strerror.c.o`
/// already defines the symbol there, so exporting it as well would give the
/// linker two definitions. Gating the *import* as well as the call is what makes
/// this file compile in both configurations rather than only in one.
///
/// The strings are the verbose arm of `lib/strerror.c` L420-L531, transcribed
/// from that file rather than invented. Three properties are checked: the
/// messages themselves for a spread of codes; that every code in range has a
/// message that is neither null nor empty; and that the sentinel and everything
/// outside the range fall through to L529's "CURLUcode unknown", which the
/// `case CURLUE_LAST: break;` at L525-L526 arranges for the sentinel and the
/// absent `default` arranges for the rest.
///
/// # Ownership
///
/// Nothing changes hands. The pointer addresses a string literal in this
/// object's read-only data, exactly as the C's strings live in `strerror.c.o`,
/// so it must not be freed -- which is why this is the one string-returning
/// entry point of the API with no release obligation.
/// `docs/libcurl/curl_url_strerror.md` imposes none.
#[cfg(feature = "strerror")]
#[test]
fn curl_url_strerror_returns_the_c_messages() {
    use curl_urlapi_rs::abi::CURLUE_LAST;

    fn message(code: CURLUcode) -> &'static str {
        // SAFETY: `curl_url_strerror` returns a pointer to a NUL-terminated
        // string literal with `'static` storage for every possible argument --
        // `lib/strerror.c` L529 is the fallthrough, so there is no null path --
        // and the referent is never written, so a `'static` borrow of it is
        // sound and cannot race.
        let raw = unsafe { curl_url_strerror(code) };
        assert!(!raw.is_null(), "no code may produce a null message");
        // SAFETY: `raw` is non-null by the test above and, as argued there,
        // addresses a NUL-terminated `'static` string literal.
        unsafe { CStr::from_ptr(raw) }
            .to_str()
            .expect("the message table is ASCII")
    }

    // A spread across the table, transcribed from lib/strerror.c.
    assert_eq!(message(CURLUE_OK), "No error");
    assert_eq!(
        message(CURLUE_BAD_HANDLE),
        "An invalid CURLU pointer was passed as argument"
    );
    assert_eq!(
        message(CURLUE_BAD_PARTPOINTER),
        "An invalid 'part' argument was passed as argument"
    );
    assert_eq!(
        message(CURLUE_MALFORMED_INPUT),
        "Malformed input to a URL function"
    );
    assert_eq!(
        message(CURLUE_BAD_PORT_NUMBER),
        "Port number was not a decimal number between 0 and 65535"
    );
    assert_eq!(message(CURLUE_UNSUPPORTED_SCHEME), "Unsupported URL scheme");
    assert_eq!(
        message(CURLUE_USER_NOT_ALLOWED),
        "Credentials was passed in the URL when prohibited"
    );
    assert_eq!(
        message(CURLUE_UNKNOWN_PART),
        "An unknown part ID was passed to a URL API function"
    );
    assert_eq!(message(CURLUE_NO_SCHEME), "No scheme part in the URL");
    assert_eq!(message(CURLUE_NO_ZONEID), "No zoneid part in the URL");
    assert_eq!(message(CURLUE_BAD_IPV6), "Bad IPv6 address");
    assert_eq!(
        message(CURLUE_TOO_LARGE),
        "A value or data field is larger than allowed"
    );

    // Every code the enumeration defines has a real message. The range is
    // 0..CURLUE_LAST exclusive, since the sentinel is not an error.
    for code in 0..CURLUE_LAST {
        let text = message(code);
        assert!(!text.is_empty(), "code {code} has an empty message");
        assert_ne!(
            text, "CURLUcode unknown",
            "code {code} is in range and must have its own message"
        );
    }

    // The sentinel and everything outside the range fall through, L525-L529.
    assert_eq!(message(CURLUE_LAST), "CURLUcode unknown");
    assert_eq!(message(CURLUE_LAST + 1), "CURLUcode unknown");
    assert_eq!(message(9999), "CURLUcode unknown");
    assert_eq!(message(-1), "CURLUcode unknown");
    assert_eq!(message(CURLUcode::MIN), "CURLUcode unknown");
    assert_eq!(message(CURLUcode::MAX), "CURLUcode unknown");
}

/// `curl_free()` releases a buffer `curl_url_get()` handed out.
///
/// Compiled only under the `cfree` feature, which is on for the standalone
/// configuration and must be **off** for the drop-in one, where
/// `lib/escape.c` L189-L192 already defines the symbol.
///
/// Every other release in this file goes through `libc::free`, which is correct
/// in every configuration because `src/alloc.rs` allocates through the C
/// allocator. This test exists so that the *exported symbol* is exercised at
/// least once rather than merely compiled: it is the release
/// `include/curl/urlapi.h` L130-L131 and `docs/libcurl/curl_url_get.md` L45
/// actually name, and in a standalone link this crate is the only thing that
/// supplies it.
///
/// `curl_free(NULL)` is exercised too. `lib/escape.c` L191 forwards to
/// `curlx_free`, which resolves to `free` in a non-memory-debug build, and
/// `free(NULL)` is defined to do nothing.
///
/// # Why nothing here is skipped on a null pointer
///
/// Each call's code is asserted **immediately**, before the pointer is looked
/// at, and every part's expectation is stated up front. Deciding what to do from
/// the pointer alone -- skipping the part when it is null, without having looked
/// at the code -- would let a getter that failed and wrote nothing quietly
/// remove itself from this test's coverage: the release path this test exists to
/// exercise would go unexercised and the test would still report success. So the
/// two vectors below between them cover all eleven parts with a buffer, and the
/// only null the test tolerates is one it names in advance.
#[cfg(feature = "cfree")]
#[test]
fn curl_free_releases_a_getter_buffer() {
    /// Retrieves one part, asserts the code first and the pointer second, and
    /// releases the buffer through the exported symbol. Returns whether a buffer
    /// was produced.
    fn release_through_curl_free(
        handle: &Handle,
        what: CURLUPart,
        expected: CURLUcode,
        buffer_expected: bool,
    ) {
        let mut part: *mut c_char = ptr::null_mut();
        // SAFETY: `handle` owns a live handle and `part` is a writable, aligned
        // local in a distinct allocation, so it cannot alias the handle.
        let code = unsafe { curl_url_get(handle.as_const(), what, &mut part, CURLU_GET_EMPTY) };
        // The pointer is null-checked and never dereferenced, so nothing is read
        // out of it before the code has been judged. `lib/urlapi.c` L1552 writes
        // null into the caller's slot ahead of every failing return, so a
        // non-null pointer here means the call reported `CURLUE_OK`.
        let produced = !part.is_null();
        if produced {
            // SAFETY: `part` came from this crate's C allocator through
            // `src/alloc.rs`, it has not been released, and no reference into it
            // exists. This is the documented release, performed exactly once for
            // this pointer, through the very function the header names. It runs
            // ahead of the assertions below rather than after them, because an
            // assertion that fired first would abandon this buffer -- the
            // release is the subject of the test and must not be the thing
            // skipped when the test fails.
            unsafe { curl_free(part.cast::<c_void>()) };
        }
        assert_eq!(
            code, expected,
            "part {what} was expected to answer {expected}"
        );
        assert_eq!(
            produced,
            buffer_expected,
            "part {what} answered {code} and {} a buffer, which is not what this \
             vector expects; a part that produces none exercises no release",
            if produced { "produced" } else { "withheld" }
        );
    }

    // Every one of the eleven parts is populated here, so every read succeeds
    // and every read yields a buffer to release: the scheme owns
    // `PROTOPT_URLOPTIONS` so the options survive parsing, and the bracketed
    // host carries a zone identifier.
    let full = Handle::parse("imap://user:pwd;crazy@[fe80::1%25eth0]:143/p?q#f", 0);
    for what in ALL_PARTS {
        release_through_curl_free(&full, what, CURLUE_OK, true);
    }

    // The remaining allocation shape is the synthesised "/" that `lib/urlapi.c`
    // L1604-L1607 substitutes for an absent path -- a buffer with no stored
    // member behind it. This handle also pins the nulls: the four absent parts
    // answer their own missing codes and withhold a buffer, which is asserted
    // rather than skipped over.
    let sparse = Handle::parse("https://example.com", 0);
    release_through_curl_free(&sparse, CURLUPART_URL, CURLUE_OK, true);
    release_through_curl_free(&sparse, CURLUPART_SCHEME, CURLUE_OK, true);
    release_through_curl_free(&sparse, CURLUPART_HOST, CURLUE_OK, true);
    release_through_curl_free(&sparse, CURLUPART_PATH, CURLUE_OK, true);
    release_through_curl_free(&sparse, CURLUPART_USER, CURLUE_NO_USER, false);
    release_through_curl_free(&sparse, CURLUPART_PORT, CURLUE_NO_PORT, false);
    release_through_curl_free(&sparse, CURLUPART_QUERY, CURLUE_NO_QUERY, false);
    release_through_curl_free(&sparse, CURLUPART_ZONEID, CURLUE_NO_ZONEID, false);

    // A null pointer is a no-op, `lib/escape.c` L191 into `free(NULL)`.
    // SAFETY: null is the case under test and is the one argument `free`
    // accepts unconditionally.
    unsafe { curl_free(ptr::null_mut()) };
}

/// Scheme resolution answers the same way in both link modes.
///
/// # The decision this test records
///
/// `src/scheme.rs` has two backends. Under `scheme-table` it compiles its own
/// 33-row table, transcribed from each protocol module's `const struct
/// Curl_scheme` literal. Without it, L1327 selects `crate::ffi::scheme_import`,
/// which reads the real descriptor libcurl hands back -- and in a `cargo test`
/// link there is no libcurl, so the nine-row stand-in in
/// [`libcurl_scheme_stand_in`] plays that part.
///
/// Rather than gate the scheme-dependent assertions on the feature, this file
/// keeps them **ungated** and confines itself to answers the two tables agree
/// on. That is a stronger arrangement: a gated assertion checks one
/// configuration, while an ungated one checks that the configurations agree,
/// which is the property a drop-in replacement actually has to have. The
/// stand-in's nine rows carry the same default ports and the same
/// `PROTOPT_URLOPTIONS` bit as the crate's rows of the same name, and the only
/// unknown scheme any test uses -- `gargle` -- is absent from both.
///
/// `CURLU_NON_SUPPORT_SCHEME` is used where an assertion genuinely does not care
/// whether the scheme resolves, at `lib/urlapi.c` L951-L953 for a parse and
/// L1646-L1647 for a set.
///
/// # What the module reads, and nothing else
///
/// Three members, and this test covers all three: the default port, at L1465,
/// L1472, L1591 and L1599; the `PROTOPT_URLOPTIONS` bit of the flags, at L290
/// and L1477; and whether `run` is null, at L1646.
///
/// The one thing the two backends are **not** claimed to agree on is which
/// protocols a given libcurl actually implements. The stand-in and the crate's
/// table both model the reference build, where nothing is disabled, so every row
/// reports itself implemented; a real drop-in link answers for the libcurl it was
/// linked against. `KNOWN-DIVERGENCES.md` records that under "the standalone
/// table models one build", and no assertion here depends on it.
#[test]
fn scheme_resolution_agrees_across_both_backends() {
    // The default port, read for the part. `lib/urldata.h` L36, L37 and L45.
    for (scheme, port) in [("http", "80"), ("https", "443"), ("imap", "143")] {
        let handle = Handle::parse(&format!("{scheme}://example.com/"), 0);
        assert_eq!(handle.text(CURLUPART_PORT, CURLU_DEFAULT_PORT), port);
        assert_eq!(
            handle.text(CURLUPART_URL, CURLU_DEFAULT_PORT),
            format!("{scheme}://example.com:{port}/")
        );
        // Suppressed again when it matches, L1468-L1474 and L1598-L1601.
        let handle = Handle::parse(&format!("{scheme}://example.com:{port}/"), 0);
        assert_eq!(
            handle.code(CURLUPART_PORT, CURLU_NO_DEFAULT_PORT),
            CURLUE_NO_PORT
        );
        assert_eq!(
            handle.text(CURLUPART_URL, CURLU_NO_DEFAULT_PORT),
            format!("{scheme}://example.com/")
        );
    }

    // `file` is the one row with no default port at all, so L1465's
    // `curl_msnprintf` writes "0" for it. Asserting the number rather than
    // assuming the row is absent is the point.
    let handle = Handle::parse("file:///tmp/x", 0);
    assert_eq!(handle.text(CURLUPART_PORT, CURLU_DEFAULT_PORT), "0");

    // The PROTOPT_URLOPTIONS bit, L288-L290. Only the mail and
    // message-retrieval protocols carry it, so the same input splits
    // differently under two schemes -- which is a scheme-table read, not a
    // parser difference.
    let handle = Handle::parse("imap://user;opt@example.com/", 0);
    assert_eq!(handle.text(CURLUPART_USER, 0), "user");
    assert_eq!(handle.text(CURLUPART_OPTIONS, 0), "opt");
    let handle = Handle::parse("pop3://user;opt@example.com/", 0);
    assert_eq!(handle.text(CURLUPART_OPTIONS, 0), "opt");
    let handle = Handle::parse("smtp://user;opt@example.com/", 0);
    assert_eq!(handle.text(CURLUPART_OPTIONS, 0), "opt");
    // http does not, so the semicolon and everything after it stay in the user.
    let handle = Handle::parse("http://user;opt@example.com/", 0);
    assert_eq!(handle.text(CURLUPART_USER, 0), "user;opt");
    assert_eq!(handle.code(CURLUPART_OPTIONS, 0), CURLUE_NO_OPTIONS);
    // The same bit suppresses the options in the whole-URL template, L1476-L1478.
    let mut handle = Handle::parse("http://example.com/", 0);
    assert_eq!(handle.set(CURLUPART_OPTIONS, "opt", 0), CURLUE_OK);
    assert_eq!(
        handle.text(CURLUPART_URL, 0),
        "http://example.com/",
        "L1477 drops the options for a scheme without the bit"
    );

    // Whether `run` is null, L1645-L1647. A scheme neither table holds is
    // refused, and the flag overrides the refusal.
    let mut handle = Handle::parse("http://example.com/", 0);
    assert_eq!(
        handle.set(CURLUPART_SCHEME, "gargle", 0),
        CURLUE_UNSUPPORTED_SCHEME
    );
    assert_eq!(
        handle.set(CURLUPART_SCHEME, "gargle", CURLU_NON_SUPPORT_SCHEME),
        CURLUE_OK
    );
    assert_eq!(handle.text(CURLUPART_URL, 0), "gargle://example.com/");
    // The same on the parsing path, L951-L953.
    let mut fresh = Handle::new();
    assert_eq!(
        fresh.set(CURLUPART_URL, "gargle://example.com/x", 0),
        CURLUE_UNSUPPORTED_SCHEME
    );
    assert_eq!(
        fresh.set(
            CURLUPART_URL,
            "gargle://example.com/x",
            CURLU_NON_SUPPORT_SCHEME
        ),
        CURLUE_OK
    );

    // A scheme lookup is case insensitive, `lib/url.c` L1537's folded compare.
    let handle = Handle::parse("HTTP://example.com/", 0);
    assert_eq!(handle.text(CURLUPART_SCHEME, 0), "http");
    assert_eq!(handle.text(CURLUPART_PORT, CURLU_DEFAULT_PORT), "80");
}

/// The internationalised-domain flags, in the only shapes that are
/// locale-independent.
///
/// `lib/urlapi.c` L1402-L1420 puts the conversions behind
/// `Curl_is_ASCII_name`, `lib/idn.c` L223-L236: `CURLU_PUNYCODE` converts only a
/// **non**-ASCII host, and `CURLU_PUNY2IDN` converts only an ASCII one. So an
/// ASCII host under `CURLU_PUNYCODE` never reaches a backend at all, in any
/// configuration, and that is what is asserted here.
///
/// # Why nothing stronger is asserted
///
/// The default backend binds libidn2 and goes through `idn2_lookup_ul`, which
/// `lib/idn.c` L36-L40 selects: that entry point interprets its input in the
/// encoding of the process locale, so converting a non-ASCII host succeeds under
/// a UTF-8 codeset and fails with `CURLUE_BAD_HOSTNAME` outside one. A test that
/// asserted a conversion would therefore pass or fail according to the runner's
/// environment, which is not a property of the port. The optional `idn-pure`
/// backend is locale-independent instead and is documented in
/// `KNOWN-DIVERGENCES.md` as **not** bit-for-bit, which is a second reason not to
/// pin a conversion here.
///
/// Non-ASCII conversion belongs to the oracle rather than to this file:
/// `tests/libtest/lib1560.c` asserts it under the locale and codeset environment
/// `tests/data/test1560` and `tests/runtests.pl` set up between them, with the
/// harness calling `setlocale(LC_ALL, "")` as `tests/libtest/first.c` L231 does.
///
/// Any vector that needed a non-ASCII byte would also have to be written as a
/// Rust escape, because `scripts/spacecheck.pl` rejects a byte above 0x7f in a
/// tracked file.
#[test]
fn the_idn_flags_are_no_ops_for_the_ascii_cases() {
    let handle = Handle::parse("https://example.com/p", 0);

    // ASCII host, CURLU_PUNYCODE: L1409's `!Curl_is_ASCII_name` is false, so no
    // conversion is attempted and the host is copied verbatim.
    assert_eq!(handle.text(CURLUPART_HOST, CURLU_PUNYCODE), "example.com");
    assert_eq!(
        handle.text(CURLUPART_URL, CURLU_PUNYCODE),
        "https://example.com/p"
    );

    // An already-encoded name is ASCII too, so the same branch is taken and the
    // compatibility form is handed back unchanged.
    let handle = Handle::parse("https://xn--rksmrgs-5wao1o.se/p", 0);
    assert_eq!(
        handle.text(CURLUPART_HOST, CURLU_PUNYCODE),
        "xn--rksmrgs-5wao1o.se"
    );
    assert_eq!(handle.text(CURLUPART_HOST, 0), "xn--rksmrgs-5wao1o.se");
}

/// The internationalised-domain flags without a backend.
///
/// With neither `idn-libidn2` nor `idn-pure`, `lib/urlapi.c` L1334-L1336 turns
/// both conversions into macros yielding `CURLUE_LACKS_IDN`, and
/// `src/idn.rs` reproduces that. The reachable half is `CURLU_PUNY2IDN` on an
/// ASCII host, because L1415-L1416 calls the encoder exactly when the name **is**
/// ASCII -- `CURLU_PUNYCODE` on an ASCII host never calls anything, so it
/// succeeds even with no backend.
///
/// Neither of the two configurations this file is required to pass in reaches
/// this test: both enable `idn-libidn2`. It is compiled for
/// `--no-default-features` alone, which `rust-urlapi/Cargo.toml`'s own
/// verification matrix lists, so the arm is checked rather than merely asserted
/// to exist.
#[cfg(not(any(feature = "idn-libidn2", feature = "idn-pure")))]
#[test]
fn without_a_backend_the_idn_conversions_lack_idn() {
    use curl_urlapi_rs::abi::CURLUE_LACKS_IDN;

    let handle = Handle::parse("https://example.com/p", 0);

    // The encoder is called for an ASCII name, L1415-L1416, and there is none.
    assert_eq!(
        handle.code(CURLUPART_HOST, CURLU_PUNY2IDN),
        CURLUE_LACKS_IDN
    );
    assert_eq!(handle.code(CURLUPART_URL, CURLU_PUNY2IDN), CURLUE_LACKS_IDN);

    // The decoder is not, because the name is ASCII, so this still succeeds.
    assert_eq!(handle.text(CURLUPART_HOST, CURLU_PUNYCODE), "example.com");
}

// ===========================================================================
// The allocation ceiling, implicit requirement I11 -- first instrument
// ===========================================================================

/// The URL rows the allocation workload parses, with the flags each needs.
///
/// Twenty rows, chosen to span the allocating shapes of the module rather than
/// to be numerous: credentials, an explicit port, a query and a fragment; a
/// bare host; FTP; a bracketed IPv6 address with a zone identifier; a `file:`
/// URL; IMAP with options, which is one of the three protocols carrying
/// `PROTOPT_URLOPTIONS`; two IPv4 forms that `ipv4_normalize` rewrites, one
/// decimal and one octal; two paths `dedotdotify` rewrites; a bare `?` and a
/// bare `#`, which set the presence bits without content; two guessed schemes;
/// an unsupported scheme; the encoder-and-space row taken from
/// `tests/libtest/lib1560.c`; POP3, DICT and LDAP, so more of the scheme table
/// is touched; and a dotted quad with a deep path.
///
/// Every row must parse. A row that failed would silently cost fewer
/// allocations than intended and quietly loosen the measurement, so
/// [`Handle::parse`] asserting success is part of the instrument.
const ALLOCATION_WORKLOAD: [(&str, c_uint); 20] = [
    ("https://user:pwd@example.com:8080/a/b/c?x=1&y=2#frag", 0),
    ("http://example.org/", 0),
    ("ftp://ftp.example.com/pub/file.txt", 0),
    (
        "http://[2a04:4e42:e00::347%25eth0]:80/path?query#fraggie",
        0,
    ),
    ("file:///tmp/a/b/c", 0),
    ("imap://user;auth=x:pwd@mail.example.com/INBOX", 0),
    ("https://16843009/", 0),
    ("https://0177.1/x", 0),
    ("http://example.com/hello/../here?q#f", 0),
    ("http://example.com/a/./b/../c/", 0),
    ("https://example.com?", 0),
    ("https://example.com#", 0),
    ("smtp.example.com/mail", CURLU_GUESS_SCHEME),
    ("example.com:1234", CURLU_GUESS_SCHEME),
    ("custom-scheme://host/path?q", CURLU_NON_SUPPORT_SCHEME),
    (
        "http://example.net/there/it/is/../../tes t case=/x? yes no",
        CURLU_URLENCODE | CURLU_ALLOW_SPACE,
    ),
    ("pop3://pop.example.com:995/1", 0),
    ("dict://dict.example.com/d:word", 0),
    ("ldap://ldap.example.com:389/dc=example", 0),
    (
        "https://192.168.0.1:443/deep/path/with/segments?a=b&c=d#top",
        0,
    ),
];

/// The ceiling `tests/data/test1560` asserts: `<limits>Allocations: 3000`.
const ALLOCATION_CEILING: u64 = 3000;

/// Rounds of [`allocation_workload_round`] the measurement runs.
///
/// Six, because six is what makes the reference cost exactly
/// [`ALLOCATION_CEILING`] -- see the test's own documentation for the
/// measurement. Fewer would leave headroom the assertion could not detect
/// spending; more would put the reference itself over its own ceiling and the
/// comparison would stop meaning anything.
const ALLOCATION_ROUNDS: u64 = 6;

/// One round of the workload: every row, then one part-by-part construction.
///
/// The shape mirrors what `tests/libtest/lib1560.c` does to a handle, which is
/// what the ceiling was set for: parse, read every part twice under two
/// different flag sets, duplicate, read the copy, release both. The two flag
/// sets matter because `CURLU_GET_EMPTY | CURLU_DEFAULT_PORT` reaches
/// allocating paths the plain read does not -- a default port is formatted at
/// `lib/urlapi.c` L1591 and L1599, and an empty part becomes a returned
/// allocation rather than an error.
///
/// The trailing block is the `setget_parts` shape: build a URL one part at a
/// time, read it, then apply a relative value and read it again. It is included
/// because assignment allocates on a different path from parsing -- the encode
/// buffer at L1880 and the append-query buffer at L1944 -- and a round without
/// it would measure only half the API.
fn allocation_workload_round() {
    for (url, flags) in ALLOCATION_WORKLOAD {
        let handle = Handle::parse(url, flags);
        // Every part, with no flags and then with the two that make more of
        // them allocate. The results are dropped; `Handle::get` releases each
        // C buffer as it goes, so a round leaks nothing and round N costs the
        // same as round 1.
        let _plain = handle.snapshot(0);
        let _full = handle.snapshot(CURLU_GET_EMPTY | CURLU_DEFAULT_PORT);
        let copy = handle.dup();
        let _serialised = copy.get(CURLUPART_URL, 0);
    }

    let mut built = Handle::new();
    assert_eq!(built.set(CURLUPART_SCHEME, "https", 0), CURLUE_OK);
    assert_eq!(built.set(CURLUPART_HOST, "example.org", 0), CURLUE_OK);
    assert_eq!(built.set(CURLUPART_USER, "bob", 0), CURLUE_OK);
    assert_eq!(built.set(CURLUPART_PASSWORD, "s3cret", 0), CURLUE_OK);
    assert_eq!(built.set(CURLUPART_PORT, "8443", 0), CURLUE_OK);
    assert_eq!(built.set(CURLUPART_PATH, "/one/two", 0), CURLUE_OK);
    assert_eq!(built.set(CURLUPART_QUERY, "k=v", 0), CURLUE_OK);
    assert_eq!(
        built.set(CURLUPART_QUERY, "k2=v2", CURLU_APPENDQUERY),
        CURLUE_OK
    );
    assert_eq!(built.set(CURLUPART_FRAGMENT, "here", 0), CURLUE_OK);
    let _url = built.get(CURLUPART_URL, 0);
    assert_eq!(built.set(CURLUPART_URL, "../elsewhere?z", 0), CURLUE_OK);
    let _resolved = built.get(CURLUPART_URL, 0);
}

/// This crate's allocation count stays under the ceiling `test1560` asserts.
///
/// # What the ceiling is, and why it cannot be measured the way curl measures it
///
/// `tests/data/test1560` carries `<limits>Allocations: 3000</limits>`.
/// `tests/runtests.pl` L1790-L1822 enforces it from the memory-debug log, summing
/// the mallocs, callocs, reallocs, strdups and wcsdups that
/// `tests/memanalyzer.pm` L439 adds together. The plan records that limit as
/// implicit requirement I11 and records at 0.2.4.3 why this port cannot be put on
/// the same scale: under the memory-debug configuration `curl_free` becomes a
/// tracking free that validates each pointer against its own table
/// (`lib/curl_setup.h` L1461), and a block this crate took straight from the C
/// allocator would be rejected or mis-accounted, so the parity harness is built
/// without it. 0.9.4 names the remedy in the same breath -- "An independent
/// allocation count via the platform's own tooling is the available substitute"
/// -- and `curl_urlapi_rs::ffi::metrics` is that substitute. Its own
/// documentation sets out the counting rule and why counting three functions
/// counts everything.
///
/// # Both numbers below were measured, not chosen
///
/// The reference figures come from relinking `/opt/curl-reference` --
/// `libcurl.a` built from the unmodified tree -- with
/// `-Wl,--wrap=malloc,calloc,realloc,strdup` and running the same workload:
///
/// | rounds | reference | this port |
/// |--------|-----------|-----------|
/// | 1      | 500       | 475       |
/// | 2      | 1000      | 950       |
/// | 3      | 1500      | 1425      |
/// | 6      | **3000**  | **2850**  |
/// | 7      | 3500      | 3325      |
///
/// Six rounds is therefore the calibration: it is the exact point at which the C
/// original spends its whole budget. Comparing this port against 3000 at that
/// point asks the only question worth asking -- would the original have fitted,
/// and does this port fit in the same room -- and the answer has 5% of margin,
/// not an order of magnitude. Per operation the two agree everywhere but one:
/// `curl_url()` 1 and 1, parsing a full URL 9 and 9, `curl_url_dup` 9 and 9,
/// reading the host 1 and 1, releasing a copy 0 and 0, appending to a query 2 and
/// 2, and reading the whole URL 2 for the reference against 1 here. That single
/// difference is the whole of the 25-allocation-per-round gap, and it runs in this
/// port's favour, so the comparison is not flattered by it.
///
/// For scale, the real thing: `lib1560` itself, run through
/// `/opt/curl-reference/obj/libtests.c.o` relinked with the same wrappers, prints
/// `success` and costs 2840 allocations -- 809 mallocs, 410 callocs, 1146
/// reallocs and 475 strdups -- against the same 3000. So the ceiling in curl's own
/// suite runs at 95% utilisation, and a workload calibrated to sit exactly at it
/// is measuring on the same scale rather than a generous one.
///
/// # Three assertions, because the ceiling alone would be worth little
///
/// A count under a ceiling is also what a counter wired to nothing reports. So
/// the measurement is bracketed:
///
/// 1. **The counter is live.** One `curl_url()` must move it, and by exactly the
///    1 the reference spends.
/// 2. **It is linear.** Two rounds must cost exactly twice one round. That is
///    what proves each round releases everything it took: a leak would make round
///    two cost more, and a cache would make it cost less. It is also what makes
///    extrapolating to six rounds legitimate.
/// 3. **Six rounds fit.** Under [`ALLOCATION_CEILING`], and equal to six times
///    the single-round cost, so the ceiling is met by a count that is still
///    exactly linear rather than by a workload that quietly stopped working.
///
/// # The reading is per thread, which is what makes it exact
///
/// Cargo runs this binary's tests on several threads at once. `metrics` counts
/// per thread, so nothing another test allocates in parallel is visible here and
/// nothing this test allocates disturbs anything else. The reset at the start of
/// each measurement affects the calling thread alone.
#[test]
fn the_allocation_count_stays_under_the_test1560_ceiling() {
    use curl_urlapi_rs::ffi::metrics::{c_allocations, reset_c_allocations};

    // 1. The counter is live, and one handle costs the 1 the reference spends.
    reset_c_allocations();
    assert_eq!(
        c_allocations(),
        0,
        "the reset must be observable, or nothing below means anything"
    );
    let probe = Handle::new();
    assert_eq!(
        c_allocations(),
        1,
        "curl_url() must cost exactly one allocation, as it does in the reference"
    );
    drop(probe);
    assert_eq!(
        c_allocations(),
        1,
        "and releasing it must cost none: memanalyzer.pm L439 leaves frees out of \
         the sum, so this counter does too"
    );

    // 2. Linearity. Measured as two separate resets rather than one running
    //    total, so that a round which allocated and never released would show up
    //    as `two != one * 2` instead of hiding inside a cumulative figure.
    reset_c_allocations();
    allocation_workload_round();
    let one_round = c_allocations();
    assert!(
        one_round > 0,
        "a round of {} rows must allocate something",
        ALLOCATION_WORKLOAD.len()
    );

    reset_c_allocations();
    allocation_workload_round();
    allocation_workload_round();
    let two_rounds = c_allocations();
    assert_eq!(
        two_rounds,
        one_round.saturating_mul(2),
        "two rounds cost {two_rounds} against {one_round} for one; the workload \
         must be exactly repeatable, or it is leaking or caching and the \
         extrapolation below is unsound"
    );

    // 3. The ceiling, at the round count where the reference spends exactly it.
    reset_c_allocations();
    for _ in 0..ALLOCATION_ROUNDS {
        allocation_workload_round();
    }
    let measured = c_allocations();
    assert_eq!(
        measured,
        one_round.saturating_mul(ALLOCATION_ROUNDS),
        "still linear at {ALLOCATION_ROUNDS} rounds"
    );
    assert!(
        measured <= ALLOCATION_CEILING,
        "{ALLOCATION_ROUNDS} rounds cost {measured} allocations, over the \
         {ALLOCATION_CEILING} that tests/data/test1560 allows. The same workload \
         costs the unmodified C exactly {ALLOCATION_CEILING}, so this is the port \
         having become materially more allocation-hungry than the original, which \
         is what implicit requirement I11 forbids"
    );
}

// ===========================================================================
// The allocation ceiling, implicit requirement I11 -- second instrument
//
// Two independent instruments measure the same ceiling, and both are kept
// deliberately. The one above counts at the crate's own C allocator, so it
// reports exactly what this module spends and nothing else, and it needs no
// platform support. The one below interposes the process allocator, so it
// also sees whatever the surrounding code spends and is therefore the
// stricter of the two, at the cost of being glibc-specific. Neither
// subsumes the other: a regression that moved an allocation out of
// `src/alloc.rs` into, say, a `Vec` would be invisible to the first and
// caught by the second, while the second's total is only meaningful on a
// target whose symbols it can interpose. `docs/MEMORY-OWNERSHIP.md` records
// both sets of numbers.
// ===========================================================================

/// Vectors for the allocation workload, drawn from `tests/libtest/lib1560.c`.
///
/// Twenty-four inputs chosen to cover the shapes that allocate differently:
/// credentials with and without a password, options for a protocol that has
/// them, an explicit port and a default one, a bracketed address with and
/// without a zone identifier, the four IPv4 arities, a `file` URL (which takes
/// its own serialisation branch at `lib/urlapi.c` L1440-L1447), dot segments
/// that shorten the path, a query and fragment present and absent, and a long
/// path. The list is fixed so the count below is reproducible; it is not a
/// sample of anything and adding to it changes the numbers.
const WORKLOAD_URLS: [&str; 24] = [
    "https://example.com/",
    "https://user:password@example.com:8080/path/to/thing?q=1&r=2#frag",
    "http://user@example.com/",
    "imap://user;options@mail.example.com/INBOX",
    "https://[fe80::1]:443/p",
    "https://[fe80::1%25eth0]/p",
    "https://127.0.0.1/",
    "https://16843009/",
    "https://0177.1/",
    "https://0111.02.0x3/",
    "https://0xff.0xff.0377.255/",
    "file:///tmp/some/where",
    "https://example.com/a/./b/../c/",
    "https://example.com/?onlyquery",
    "https://example.com/#onlyfragment",
    "https://example.com/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z",
    "ftp://ftp.example.com/pub/file.txt",
    "smtp://user;opt@smtp.example.com/",
    "pop3://user:pw@pop3.example.com/",
    "dict://dict.example.com/d:word",
    "ldap://ldap.example.com/dc=example,dc=com",
    "https://user:pw@[fe80::1%25eth0]:8443/deep/path?a=b&c=d#f",
    "https://example.com/%41%42%43?%44=%45#%46",
    "https://xn--rksmrgs-5wao1o.se/p", // spellchecker:disable-line
];

/// Values the workload assigns, pre-converted so the measured window allocates
/// nothing on the Rust side.
const WORKLOAD_SETS: [(CURLUPart, &str, c_uint); 4] = [
    (
        CURLUPART_QUERY,
        "added=value",
        CURLU_APPENDQUERY | CURLU_URLENCODE,
    ),
    (CURLUPART_PATH, "/replaced path/x", CURLU_URLENCODE),
    (CURLUPART_FRAGMENT, "replaced", 0),
    (CURLUPART_PORT, "4443", 0),
];

/// How many C-allocator blocks one workload cycle may take.
///
/// A cycle is one vector through [`allocation_cycle`]: a parse, eleven part
/// reads, two whole-URL reads under different codec flags, a duplication with a
/// read and a release, four part assignments and a final read, then the release
/// of the handle.
///
/// Measured: **575 allocations for the twenty-four cycles**, 23.96 per cycle on
/// average, with a spread of 18 for the `file` vector to 45 for the one carrying
/// credentials, a zone identifier, a port, a query and a fragment at once. The
/// figure is identical in all four feature configurations the manifest offers and
/// in both the dev and release profiles, which is why one constant serves them
/// all.
///
/// The budget is amortised across the workload rather than applied per vector,
/// because a single expensive vector is not a defect -- the spread above is
/// inherent to the shapes being parsed. Forty leaves 67 per cent of headroom over
/// the measured average, which is room for a differently-shaped implementation of
/// the same operations, while an implementation that allocated twice as much for
/// them would take about 1,150 and fail. That is the guard the total ceiling
/// below cannot provide: 24 cycles against 3,000 would let the per-operation cost
/// grow five-fold unnoticed.
const ALLOCATIONS_PER_CYCLE_BUDGET: u64 = 40;

/// The ceiling `tests/data/test1560` L38-L40 asserts for the whole of
/// `lib1560`: `<limits>Allocations: 3000</limits>`.
///
/// `tests/memanalyzer.pm` L439 defines what curl counts under that name --
/// `mallocs + callocs + reallocs + strdups + wcsdups`, cumulative over the run
/// and with frees excluded -- which is what the counter below reproduces. The
/// crate calls no `strdup` and no `wcsdup`, so three of those five terms are the
/// whole of it.
const TEST1560_ALLOCATION_CEILING: u64 = 3000;

/// The C-allocator counters, and why they are interposed rather than added to
/// the crate.
///
/// # What is required
///
/// `AAP` I11 makes the allocation ceiling part of the specification, and 0.9.4
/// says how it has to be measured here: curl's own counter belongs to the
/// memory-debug build, which reportable constraint `R3` at 0.2.4.3 puts out of
/// reach for this crate -- `curl_dbg_free` would back-offset a pointer that
/// carries no `struct memdebug` header -- so "an independent allocation count
/// via the platform's own tooling is the available substitute".
///
/// # How this counts
///
/// This module defines `malloc`, `calloc`, `realloc` and `free` in the test
/// binary and forwards each to glibc's own `__libc_*` entry point. A definition
/// in the executable takes precedence over the one in a shared libc for every
/// object linked into it, so the crate's `libc::malloc` calls in
/// `src/ffi.rs` -- which are the only way a C-visible block is ever produced,
/// per `src/alloc.rs` -- arrive here first. No `LD_PRELOAD`, no build
/// configuration, and nothing added to the library: the crate under test is the
/// same code a consumer links.
///
/// `__libc_malloc` and its three companions are the glibc-internal aliases for
/// the real allocator, which is what makes forwarding possible without the
/// `dlsym` bootstrap problem -- `dlsym` itself can allocate, and an interposer
/// that has to call it before it can allocate is a recursion waiting to happen.
/// That is also why this whole module is gated on glibc: on any other C library
/// the aliases do not exist, and the fallback test below runs the same workload
/// without counting.
///
/// # Two different questions, two different counters
///
/// `tests/memanalyzer.pm` L439 counts `mallocs + callocs + reallocs`, and a
/// `realloc` is one allocation by that reckoning even though it replaces a block
/// rather than adding one -- glibc's `realloc` releases the old extent itself
/// and never calls `free`. So the allocation *metric* and the outstanding-block
/// *balance* cannot come from one pair of counters, and conflating them was a
/// real defect in the first version of this module: it read one block
/// permanently outstanding for the long-path vector, which is not a leak at all
/// but a `realloc` that grew a dynamic buffer.
///
/// `ALLOCATIONS` is therefore the metric, incremented by all three of `malloc`,
/// `calloc` and `realloc`, which is exactly what the ceiling is expressed in.
/// `CREATED` and `DESTROYED` are the balance, and they treat a `realloc` as
/// neutral -- one block in, one block out -- except in its two degenerate forms:
/// `realloc(NULL, n)` creates a block, as `malloc` would, and `realloc(p, 0)`
/// destroys one, as glibc's `free` would. Neither form is reachable from this
/// crate, whose `CBlock::resize` passes a live pointer and a nonzero size, but
/// an interposer that answered wrongly for a call it merely *might* see would be
/// worth less than one that answers for all of them.
///
/// # Why the counters are thread-local
///
/// Cargo runs the tests in this binary concurrently, and the interposition is
/// process-wide. A global counter would therefore charge this test for every
/// allocation every other test in the binary made while it happened to be
/// running, which is not a measurement of anything. A thread-local counter sees
/// only the thread that is measuring, and `ARMED` narrows that to the window
/// that is being measured.
///
/// The cells are `const`-initialised and hold a type with no destructor, so
/// touching them from inside `malloc` neither allocates nor registers a
/// destructor -- either of which would be a recursion. `try_with` rather than
/// `with`, because a thread-local access during thread teardown is an error
/// rather than a panic-worthy event, and an interposer must never panic.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod count {
    use core::cell::Cell;
    use core::ffi::c_void;

    use libc::size_t;

    extern "C" {
        /// glibc's own `malloc`, reachable under a name nothing interposes.
        fn __libc_malloc(size: size_t) -> *mut c_void;
        /// glibc's own `calloc`.
        fn __libc_calloc(count: size_t, size: size_t) -> *mut c_void;
        /// glibc's own `realloc`.
        fn __libc_realloc(block: *mut c_void, size: size_t) -> *mut c_void;
        /// glibc's own `free`.
        fn __libc_free(block: *mut c_void);
    }

    thread_local! {
        /// Whether this thread is inside the measured window.
        static ARMED: Cell<bool> = const { Cell::new(false) };
        /// The metric: `mallocs + callocs + reallocs`, per
        /// `tests/memanalyzer.pm` L439.
        static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
        /// Blocks that came into existence while armed.
        static CREATED: Cell<u64> = const { Cell::new(0) };
        /// Blocks that ceased to exist while armed.
        static DESTROYED: Cell<u64> = const { Cell::new(0) };
    }

    /// Adds one to `counter` if this thread is measuring.
    fn tally(counter: &'static std::thread::LocalKey<Cell<u64>>) {
        if ARMED.try_with(Cell::get).unwrap_or(false) {
            let _ = counter.try_with(|cell| cell.set(cell.get().saturating_add(1)));
        }
    }

    /// What one measured window observed.
    pub struct Counts {
        /// `mallocs + callocs + reallocs`, the ceiling's own unit.
        pub allocations: u64,
        /// Blocks created, with a `realloc` counted as neutral.
        pub created: u64,
        /// Blocks destroyed, with a `realloc` counted as neutral.
        pub destroyed: u64,
    }

    /// Opens the measured window and zeroes the counters.
    pub fn arm() {
        ALLOCATIONS.with(|cell| cell.set(0));
        CREATED.with(|cell| cell.set(0));
        DESTROYED.with(|cell| cell.set(0));
        ARMED.with(|cell| cell.set(true));
    }

    /// Closes the window and yields what it observed.
    pub fn disarm() -> Counts {
        ARMED.with(|cell| cell.set(false));
        Counts {
            allocations: ALLOCATIONS.with(Cell::get),
            created: CREATED.with(Cell::get),
            destroyed: DESTROYED.with(Cell::get),
        }
    }

    /// The interposed `malloc`.
    #[no_mangle]
    pub extern "C" fn malloc(size: size_t) -> *mut c_void {
        tally(&ALLOCATIONS);
        tally(&CREATED);
        // SAFETY: `__libc_malloc` has the same contract as `malloc` and no
        // precondition beyond it. The argument is passed through unaltered and
        // the result is returned unaltered, so this wrapper is transparent to
        // every caller.
        unsafe { __libc_malloc(size) }
    }

    /// The interposed `calloc`.
    #[no_mangle]
    pub extern "C" fn calloc(count: size_t, size: size_t) -> *mut c_void {
        tally(&ALLOCATIONS);
        tally(&CREATED);
        // SAFETY: as `malloc` above -- both arguments are passed through and
        // `__libc_calloc` has `calloc`'s contract, zeroing included.
        unsafe { __libc_calloc(count, size) }
    }

    /// The interposed `realloc`.
    ///
    /// One allocation for the metric, and neutral for the balance: the block it
    /// returns replaces the one it was given, and glibc releases that one itself
    /// without going through `free`. The two degenerate forms are counted for
    /// what they do instead -- see the module documentation.
    #[no_mangle]
    pub extern "C" fn realloc(block: *mut c_void, size: size_t) -> *mut c_void {
        tally(&ALLOCATIONS);
        if block.is_null() {
            tally(&CREATED);
        } else if size == 0 {
            tally(&DESTROYED);
        }
        // SAFETY: `block` is whatever the caller passed, and `realloc`'s own
        // contract is what constrains it -- either null or a live block from
        // this allocator. This wrapper neither reads nor writes through it, and
        // `__libc_realloc` is the allocator that would have received it.
        unsafe { __libc_realloc(block, size) }
    }

    /// The interposed `free`.
    ///
    /// A null pointer is not counted, because `free(NULL)` is defined to do
    /// nothing and counting it would make the balance depend on how often a
    /// caller passes null rather than on how many blocks were let go.
    #[no_mangle]
    pub extern "C" fn free(block: *mut c_void) {
        if !block.is_null() {
            tally(&DESTROYED);
        }
        // SAFETY: `block` is the caller's, constrained by `free`'s own contract,
        // and is passed through untouched to the allocator that would have
        // received it.
        unsafe { __libc_free(block) }
    }
}

/// One cycle of the allocation workload, over one URL, allocating nothing on the
/// Rust side.
///
/// Everything this performs is a call through the C ABI on inputs that were
/// converted before the window opened, and every buffer it receives is released
/// with `libc::free` before it returns. It copies nothing into Rust, which is
/// the reason it does not use [`Handle`]: that type's `get` builds a `String`
/// and its `set` builds a `CString`, and either would put Rust allocations
/// inside a window that is meant to measure the crate.
///
/// Returns the number of calls that reported a code other than `CURLUE_OK`, so
/// the caller can assert on it *after* closing the window -- a failing
/// `assert_eq!` formats a message, which allocates, and would corrupt the
/// measurement it was reporting.
fn allocation_cycle(url: &CStr, sets: &[(CURLUPart, CString, c_uint)]) -> u32 {
    let mut unexpected = 0;

    // SAFETY: no arguments, no preconditions. A null return is an allocation
    // failure, which the caller reports as an unexpected outcome below.
    let handle = unsafe { curl_url() };
    if handle.is_null() {
        return 1;
    }

    // SAFETY: `handle` is the live handle just obtained, exclusively owned here.
    // `url` is a NUL-terminated C string owned by the caller for the whole call.
    if unsafe { curl_url_set(handle, CURLUPART_URL, url.as_ptr(), 0) } != CURLUE_OK {
        unexpected += 1;
    }

    // Every part, then the whole URL under each codec. A part that is absent
    // reports its own code and writes nothing, which is not an error here: the
    // vectors deliberately include handles that lack a query, a fragment or a
    // zone identifier, so this loop counts allocations rather than checking
    // codes.
    for what in ALL_PARTS {
        read_and_release(handle, what, CURLU_GET_EMPTY);
    }
    read_and_release(handle, CURLUPART_URL, CURLU_URLENCODE);
    read_and_release(handle, CURLUPART_URL, CURLU_URLDECODE);

    // SAFETY: `handle` is live and is read, never written, which is what
    // `const CURLU *` promises.
    let copy = unsafe { curl_url_dup(handle.cast_const()) };
    if copy.is_null() {
        unexpected += 1;
    } else {
        read_and_release(copy, CURLUPART_URL, 0);
        // SAFETY: `copy` is the handle `curl_url_dup` just returned, released
        // exactly once here, with no other pointer to it in existence.
        unsafe { curl_url_cleanup(copy) };
    }

    for (what, value, flags) in sets {
        // SAFETY: `handle` is live and exclusively owned here, and `value` is a
        // NUL-terminated C string the caller keeps alive for the whole call.
        if unsafe { curl_url_set(handle, *what, value.as_ptr(), *flags) } != CURLUE_OK {
            unexpected += 1;
        }
    }
    read_and_release(handle, CURLUPART_URL, 0);

    // SAFETY: `handle` has not been released, is released exactly once here, and
    // nothing else holds it.
    unsafe { curl_url_cleanup(handle) };
    unexpected
}

/// Reads one part and releases whatever came back, copying nothing.
///
/// The counterpart to [`Handle::get`] for the measured window: it exists so that
/// a buffer the crate allocated is accounted for and released without a `Vec` or
/// a `String` being created to look at it.
fn read_and_release(handle: *mut CurlUrl, what: CURLUPart, flags: c_uint) {
    let mut part: *mut c_char = ptr::null_mut();
    // SAFETY: `handle` is a live handle owned by the caller, passed as `*const`
    // so no unique reference is formed. `part` is a writable, aligned local in
    // this frame, so it cannot alias the handle.
    let code = unsafe { curl_url_get(handle.cast_const(), what, &mut part, flags) };
    let _ = code;
    if !part.is_null() {
        // SAFETY: `part` is non-null, so `curl_url_get` wrote a block it
        // allocated through `src/alloc.rs` and handed to this caller. This is
        // its first and only release, and nothing refers into it.
        unsafe { libc::free(part.cast::<c_void>()) };
    }
}

/// Converts the workload's inputs, before any window opens.
fn workload_inputs() -> (Vec<CString>, Vec<(CURLUPart, CString, c_uint)>) {
    let urls = WORKLOAD_URLS.iter().map(|url| c_string(url)).collect();
    let sets = WORKLOAD_SETS
        .iter()
        .map(|&(what, value, flags)| (what, c_string(value), flags))
        .collect();
    (urls, sets)
}

/// **`AAP` I11: the port stays inside `tests/data/test1560`'s allocation
/// ceiling, and this measures it rather than asserting it.**
///
/// # What the ceiling is, and what the harness measured
///
/// `tests/data/test1560` L38-L40 declares `<limits>Allocations: 3000</limits>`
/// for the whole of `lib1560`, counted as `tests/memanalyzer.pm` L439 defines
/// it. That counter runs only in a memory-debug build, which reportable
/// constraint `R3` at `AAP` 0.2.4.3 keeps out of reach here, so 0.9.4 names the
/// substitute: an independent count from the platform's own tooling.
///
/// Both halves of that substitute exist. Around the **parity harness**, with an
/// interposing counter loaded into the process, the unmodified
/// `tests/libtest/lib1560.c` costs 3,114 blocks linked against the reference
/// `libcurl.a` and 3,046 linked against this crate -- in the drop-in link and in
/// the standalone one alike, with 2,839 releases in every case. The port is
/// therefore 68 blocks *cheaper* than the C for the identical test, which is
/// what I11's "not materially more allocation-hungry" asks about. Both totals
/// sit just above 3,000 because a process-wide counter also sees stdio, locale
/// and libidn2 activity that curl's own counter never attributed to curl.
///
/// This test is the other half: the same accounting, inside the crate's own
/// suite, so a regression is caught by `cargo test` rather than by remembering
/// to run a harness. Measured, it costs 575 allocations for its twenty-four
/// cycles, of which exactly one is a `realloc` -- the dynamic buffer growing for
/// the long-path vector -- and it leaves nothing outstanding. It is not a re-measurement of `lib1560` -- a Rust
/// integration test cannot run that file -- but a fixed workload of comparable
/// shape and volume, and its three assertions are chosen so that each catches
/// something the others would miss.
///
/// # The three assertions
///
/// **Under the ceiling.** The whole workload must cost at most 3,000 blocks,
/// which is the literal number `tests/data/test1560` asserts.
///
/// **Under the per-cycle budget.** [`ALLOCATIONS_PER_CYCLE_BUDGET`] is the sharp
/// one: 24 cycles against a 3,000 ceiling leaves room for a per-operation cost
/// to double unnoticed, and the budget does not.
///
/// **Nothing outstanding.** Every block the window obtained must have been
/// released inside it. The workload releases every buffer it is handed and
/// cleans up every handle, so the two counters have to agree exactly -- and
/// without that, "under the ceiling" could be satisfied by an implementation
/// that leaked instead of allocating again.
///
/// A fourth guard is on the instrumentation itself: a count of zero fails, since
/// the most likely way for this test to become worthless is for the
/// interposition to stop taking effect and for the counters to read zero
/// forever.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn the_allocation_count_stays_within_the_test1560_ceiling() {
    let (urls, sets) = workload_inputs();

    count::arm();
    let mut unexpected = 0;
    for url in &urls {
        unexpected += allocation_cycle(url, &sets);
    }
    let counts = count::disarm();

    // Printed rather than only asserted, so `cargo test -- --nocapture` reports
    // the measurement instead of merely the verdict. Outside the window, because
    // formatting allocates.
    println!(
        "allocation workload: {} cycles, {} allocations, {} created, {} \
         destroyed",
        urls.len(),
        counts.allocations,
        counts.created,
        counts.destroyed
    );

    assert_eq!(
        unexpected, 0,
        "{unexpected} call(s) in the workload reported an unexpected code, so \
         the counts below are not measuring the work they were meant to measure"
    );
    assert!(
        counts.allocations > 0,
        "the interposed allocator counted nothing at all, so this test is not \
         measuring the crate; see the `count` module for how the interposition \
         is supposed to take effect"
    );
    assert!(
        counts.allocations <= TEST1560_ALLOCATION_CEILING,
        "the workload took {} allocations from the C allocator, over the {} \
         that tests/data/test1560 allows for the whole of lib1560",
        counts.allocations,
        TEST1560_ALLOCATION_CEILING
    );
    let cycles = urls.len() as u64;
    let budget = cycles * ALLOCATIONS_PER_CYCLE_BUDGET;
    assert!(
        counts.allocations <= budget,
        "the workload took {} allocations over {cycles} cycles, more than the \
         {budget} its per-cycle budget of {} allows",
        counts.allocations,
        ALLOCATIONS_PER_CYCLE_BUDGET
    );
    assert_eq!(
        counts.created, counts.destroyed,
        "{} blocks were created and {} destroyed, so the workload is holding \
         something it allocated -- every buffer it reads is freed and every \
         handle it makes is cleaned up, so the two must agree",
        counts.created, counts.destroyed
    );
}

/// The same workload where the counter cannot be built, so the vectors are still
/// exercised.
///
/// The interposition in [`count`] forwards to glibc's `__libc_*` aliases, which
/// exist on no other C library, and `AAP` 0.8.5 scopes this work to the platform
/// parity is demonstrated on. Rather than let a quarter of this file's vectors
/// vanish on such a target, the workload runs and its outcomes are checked; only
/// the count is absent, and its absence is loud in this test's name rather than
/// silent.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
#[test]
fn the_allocation_workload_runs_without_a_counter_on_this_target() {
    let (urls, sets) = workload_inputs();
    let mut unexpected = 0;
    for url in &urls {
        unexpected += allocation_cycle(url, &sets);
    }
    assert_eq!(
        unexpected, 0,
        "{unexpected} call(s) reported an unexpected code"
    );
}

// ===========================================================================
// Undefined and hostile flag words
// ===========================================================================

// `include/curl/urlapi.h` L84-L105 defines sixteen `CURLU_*` bits, and both
// entry points take the word as a plain `unsigned int`. Neither validates it:
// `curl_url_get` at `lib/urlapi.c` L1541 and `curl_url_set` at L1805 only ever
// test individual bits, and the only assignments to `flags` in the whole
// translation unit are the two targeted clears of `CURLU_URLDECODE` at L1558 for
// the scheme and L1585 for the port. There is no mask, no range check and no
// `CURLUE_*` code for a bad flag, so an undefined bit cannot be rejected -- it
// can only be ignored, and a caller who passes one gets the behaviour of the
// bits it recognises.
//
// That is worth pinning rather than assuming, because it is the sort of property
// a port acquires by accident and loses by accident: a Rust implementation that
// modelled the word as an enum, matched it exhaustively, or asserted on it would
// answer differently for every one of the vectors below while passing every
// vector built only from defined bits.
//
// Every expectation in this section was measured against a `libcurl.a` built
// from the unmodified tree, not reasoned out. The probe drove 2158 vectors --
// four base URLs by seven flag words by eleven parts on the reading side, and the
// same grid by six values on the writing side -- against the reference and
// against this crate linked in the drop-in configuration, and the two outputs
// were byte-identical. What is asserted below is the load-bearing subset of that
// grid, with the mechanism named at each line.

/// A bit above the defined sixteen, adjacent to them.
const UNKNOWN_LOW: c_uint = 1 << 16;

/// The top bit, as far from the defined sixteen as the word allows.
const UNKNOWN_HIGH: c_uint = 1 << 31;

/// Every undefined bit at once, and no defined one.
const UNKNOWN_ALL: c_uint = 0xffff_0000;

/// The four base URLs the grid is built on, each chosen for the parts it
/// populates: `rich` for credentials and an escaped path, `guessed` for the
/// guessed-scheme marker, `imap` for options and a zone identifier, and
/// `minimal` for the absences.
const FLAG_BASES: [(&str, c_uint); 4] = [
    ("https://user:pwd@example.com:8080/p%20q?a=b+c#f", 0),
    ("example.com", CURLU_GUESS_SCHEME),
    ("imap://u:p;crazy@[fe80::1%25eth0]:143/p?q#f", 0),
    ("https://example.com", 0),
];

/// An undefined bit changes nothing about a read, for any part of any handle.
///
/// The three words carry no defined bit at all, so each must answer exactly as
/// flags of zero do -- the same code and the same bytes, for all eleven parts of
/// all four bases. Comparing whole [`Handle::snapshot`] values rather than codes
/// means a divergence in the content is caught as well as one in the code.
#[test]
fn an_undefined_flag_bit_is_inert_on_a_read() {
    for (url, urlflags) in FLAG_BASES {
        let handle = Handle::parse(url, urlflags);
        let plain = handle.snapshot(0);
        for word in [UNKNOWN_LOW, UNKNOWN_HIGH, UNKNOWN_ALL] {
            assert_eq!(
                handle.snapshot(word),
                plain,
                "reading {url} under the undefined word {word:#x} answered \
                 differently from flags of zero, so an undefined bit was given a \
                 meaning; lib/urlapi.c L1541 tests defined bits only"
            );
        }
    }
}

/// An undefined bit riding along with a defined one does not disturb it.
///
/// The pairing matters separately from the previous test: an implementation that
/// rejected or masked the whole word would still pass that one by failing
/// uniformly, but it cannot pass this one, where the defined bit's effect has to
/// survive intact.
#[test]
fn an_undefined_flag_bit_does_not_disturb_a_defined_one() {
    for (url, urlflags) in FLAG_BASES {
        let handle = Handle::parse(url, urlflags);
        for defined in [
            CURLU_GET_EMPTY,
            CURLU_URLDECODE,
            CURLU_URLENCODE,
            CURLU_DEFAULT_PORT,
            CURLU_NO_DEFAULT_PORT,
            CURLU_DEFAULT_SCHEME,
            CURLU_NO_GUESS_SCHEME,
            CURLU_PUNYCODE,
            CURLU_PUNY2IDN,
        ] {
            let alone = handle.snapshot(defined);
            for word in [UNKNOWN_LOW, UNKNOWN_HIGH, UNKNOWN_ALL] {
                assert_eq!(
                    handle.snapshot(defined | word),
                    alone,
                    "adding the undefined word {word:#x} to {defined:#x} changed \
                     the answer for {url}"
                );
            }
        }
    }
}

/// An undefined bit changes nothing about a write either.
///
/// Each case runs on its own freshly parsed handle so the writes cannot
/// accumulate, and both the returned code and the handle's resulting whole URL
/// are compared, because a write that answered the same code while storing
/// something different would otherwise pass.
#[test]
fn an_undefined_flag_bit_is_inert_on_a_write() {
    // Values chosen so that each part sees both an acceptable and an
    // unacceptable one: `9999` is a valid port but not a valid scheme, `/a b`
    // carries a byte the encoder has to decide about, and `k=v` carries the `=`
    // the query appender treats specially.
    const VALUES: [&str; 6] = ["x", "ftp", "9999", "/a b", "k=v", "eth0"];

    for (url, urlflags) in FLAG_BASES {
        for what in ALL_PARTS {
            for value in VALUES {
                let mut plain = Handle::parse(url, urlflags);
                let expected = (plain.set(what, value, 0), plain.get(CURLUPART_URL, 0));
                for word in [UNKNOWN_LOW, UNKNOWN_HIGH, UNKNOWN_ALL] {
                    let mut handle = Handle::parse(url, urlflags);
                    let actual = (handle.set(what, value, word), handle.get(CURLUPART_URL, 0));
                    assert_eq!(
                        actual, expected,
                        "writing {value:?} to part {what} of {url} under the \
                         undefined word {word:#x} answered differently from \
                         flags of zero; lib/urlapi.c L1805 tests defined bits only"
                    );
                }
            }
        }
    }
}

/// Every bit in the word set at once, on the reading side.
///
/// `c_uint::MAX` turns on all sixteen defined bits together, including four
/// pairs that contradict each other, so it is the sharpest available test of
/// which arm of each `if` / `else if` the C actually takes. Each line below names
/// the mechanism that decides it, and every one was measured against the
/// reference before being written down.
#[test]
fn every_flag_bit_at_once_on_a_read() {
    let all = c_uint::MAX;

    // A guessed scheme. The flag has two unrelated effects in two arms, and this
    // is where both are visible at once.
    let guessed = Handle::parse("example.com", CURLU_GUESS_SCHEME);
    // The scheme arm treats `CURLU_NO_GUESS_SCHEME` as an error, L1559-L1560, and
    // no other bit in the word overrides it.
    assert_eq!(guessed.code(CURLUPART_SCHEME, all), CURLUE_NO_SCHEME);
    // The whole-URL arm treats it as a formatting choice, L1512-L1515, so the
    // prefix is blank and the call succeeds. The `:80` is `CURLU_DEFAULT_PORT`
    // winning at L1461-L1466: the two port bits are an `if` / `else if`, the
    // first arm is taken when there is no stored port, and `CURLU_NO_DEFAULT_PORT`
    // in the second arm never gets a turn.
    assert_eq!(guessed.text(CURLUPART_URL, all), "example.com:80/");

    // Same injection with an explicit scheme, so the prefix stays.
    let minimal = Handle::parse("https://example.com", 0);
    assert_eq!(minimal.text(CURLUPART_URL, all), "https://example.com:443/");

    // A stored port that equals the scheme's default goes the other way: the
    // `else if` at L1469-L1475 is the arm taken, `CURLU_NO_DEFAULT_PORT` drops
    // the port from the whole URL -- and in the port arm at L1595-L1602 it drops
    // the pointer itself, so the part falls through to `ifmissing` and reports
    // the port missing on a handle that has one.
    let imap = Handle::parse("imap://u:p;crazy@[fe80::1%25eth0]:143/p?q#f", 0);
    assert_eq!(imap.code(CURLUPART_PORT, all), CURLUE_NO_PORT);
    assert_eq!(imap.text(CURLUPART_PORT, 0), "143");
    // The whole URL keeps the zone, L1480-L1491, keeps the options because imap
    // owns `PROTOPT_URLOPTIONS`, L1477-L1478, and loses the port.
    assert_eq!(
        imap.text(CURLUPART_URL, all),
        "imap://u:p;crazy@[fe80::1%25eth0]/p?q#f"
    );
    // The host part on its own never carries the zone: only the whole-URL arm
    // assembles that. Neither IDN bit touches a bracketed address.
    assert_eq!(imap.text(CURLUPART_HOST, all), "[fe80::1]");
    assert_eq!(imap.text(CURLUPART_ZONEID, all), "eth0");

    // Decoding and encoding are not an `if` / `else if` pair -- L1380-L1391
    // decodes first and L1392 then encodes what it produced -- so with both bits
    // set an escape survives a round trip instead of one bit winning.
    let rich = Handle::parse("https://user:pwd@example.com:8080/p%20q?a=b+c#f", 0);
    assert_eq!(rich.text(CURLUPART_PATH, all), "/p%20q");
    // The query round trip is not symmetric, and that is the point: L1612 turns
    // the `+` into a space on the way in, and the encoder's `left` state starts
    // false for the query part, so the space comes back out as `+` rather than as
    // `%20`.
    assert_eq!(rich.text(CURLUPART_QUERY, all), "a=b+c");
    // The absences still answer their own codes, with no buffer, under the same
    // word -- `Handle::get` asserts the null out-pointer on every failing read.
    assert_eq!(rich.code(CURLUPART_OPTIONS, all), CURLUE_NO_OPTIONS);
    assert_eq!(rich.code(CURLUPART_ZONEID, all), CURLUE_NO_ZONEID);
    // And an out-of-range part is still unknown, not undefined behaviour.
    assert_eq!(rich.code(9999, all), CURLUE_UNKNOWN_PART);

    // None of it moved anything: the handle answers exactly as it did before.
    assert_eq!(
        rich.snapshot(0),
        Handle::parse("https://user:pwd@example.com:8080/p%20q?a=b+c#f", 0).snapshot(0),
        "reading under a hostile flag word mutated the handle"
    );
}

/// Every bit in the word set at once, on the writing side.
///
/// The writing side has bits the reading side does not, and two of them are
/// destructive rather than cosmetic: `CURLU_DISALLOW_USER` can refuse, and
/// `CURLU_URLENCODE` changes what is stored. Both are measured here, together
/// with the atomicity that has to hold when the refusal happens.
#[test]
fn every_flag_bit_at_once_on_a_write() {
    let all = c_uint::MAX;
    const RICH: &str = "https://user:pwd@example.com:8080/p%20q?a=b+c#f";

    // A relative whole-URL write is resolved against the serialised base and
    // re-parsed, so `CURLU_DISALLOW_USER` meets the base's own credentials and
    // refuses, L300-L303 into `CURLUE_USER_NOT_ALLOWED`.
    let mut handle = Handle::parse(RICH, 0);
    let before = handle.snapshot(CURLU_GET_EMPTY);
    assert_eq!(handle.set(CURLUPART_URL, "x", all), CURLUE_USER_NOT_ALLOWED);
    // L1197-L1209 parses into a zeroed temporary and swaps only on success, so
    // the refusal left nothing half-written.
    assert_eq!(
        handle.snapshot(CURLU_GET_EMPTY),
        before,
        "a write that failed under a hostile flag word still mutated the handle"
    );

    // `CURLU_NON_SUPPORT_SCHEME` is in the word, so L1646-L1647's
    // disabled-protocol check is skipped and an unknown scheme is accepted --
    // while the syntax check at L1650-L1660 still refuses one that does not begin
    // with a letter.
    let mut scheme = Handle::parse(RICH, 0);
    assert_eq!(scheme.set(CURLUPART_SCHEME, "x", all), CURLUE_OK);
    assert_eq!(scheme.text(CURLUPART_SCHEME, 0), "x");
    assert_eq!(scheme.set(CURLUPART_SCHEME, "9999", all), CURLUE_BAD_SCHEME);
    assert_eq!(
        scheme.text(CURLUPART_SCHEME, 0),
        "x",
        "the rejected scheme was stored anyway"
    );

    // `CURLU_URLENCODE` is in the word too, so what is stored is the encoded
    // form. The user part is not path mode, so `/` is encoded as well as the
    // space.
    let mut user = Handle::parse(RICH, 0);
    assert_eq!(user.set(CURLUPART_USER, "/a b", all), CURLUE_OK);
    assert_eq!(user.text(CURLUPART_USER, 0), "%2Fa%20b");

    // Options are accepted and stored for any scheme -- the assignment dispatch
    // has no capability gate -- but the whole URL suppresses them unless the
    // scheme owns `PROTOPT_URLOPTIONS`, L1477-L1478, and https does not.
    let mut options = Handle::parse(RICH, 0);
    assert_eq!(options.set(CURLUPART_OPTIONS, "crazy", all), CURLUE_OK);
    assert_eq!(options.text(CURLUPART_OPTIONS, 0), "crazy");
    assert!(!options.text(CURLUPART_URL, 0).contains("crazy"));

    // An out-of-range part is still unknown on the writing side, L1874.
    let mut bogus = Handle::parse(RICH, 0);
    assert_eq!(bogus.set(9999, "x", all), CURLUE_UNKNOWN_PART);
}

/// The null preconditions outrank the flag word, whatever is in it.
///
/// `lib/urlapi.c` L1548-L1551 and L1817-L1818 test the handle and the part
/// pointer before the flags are consulted at all, so a hostile word cannot buy
/// its way past them -- and the out-pointer is still cleared at L1552.
#[test]
fn a_hostile_flag_word_does_not_bypass_the_null_preconditions() {
    // A value no allocator would return, so that finding null afterwards can
    // only mean L1552 wrote it. It is never dereferenced and never freed.
    let sentinel = usize::MAX as *mut c_char;
    let value = c_string("x");

    for word in [UNKNOWN_LOW, UNKNOWN_HIGH, UNKNOWN_ALL, c_uint::MAX] {
        let mut out = sentinel;
        // SAFETY: a null handle is the precondition under test, and `out` is a
        // writable, aligned local whose value is never dereferenced.
        let code = unsafe { curl_url_get(ptr::null(), CURLUPART_URL, &mut out, word) };
        assert_eq!(code, CURLUE_BAD_HANDLE, "flags {word:#x}");

        let handle = Handle::parse("https://example.com/p", 0);
        // SAFETY: a null part pointer is the precondition under test, and L1550
        // answers it from the raw pointer without writing through it. The handle
        // is live for the duration of the call.
        let code = unsafe { curl_url_get(handle.as_const(), CURLUPART_URL, ptr::null_mut(), word) };
        assert_eq!(code, CURLUE_BAD_PARTPOINTER, "flags {word:#x}");

        // The out-pointer is cleared before the switch, so a failing read under a
        // hostile word cannot leave a stale pointer behind for the caller to free.
        let mut out = sentinel;
        // SAFETY: the handle is live and `out` is a writable, aligned local
        // holding a value that is never dereferenced.
        let code = unsafe { curl_url_get(handle.as_const(), CURLUPART_ZONEID, &mut out, word) };
        assert_eq!(code, CURLUE_NO_ZONEID, "flags {word:#x}");
        assert!(
            out.is_null(),
            "L1552 must clear the slot before failing, flags {word:#x}"
        );

        // SAFETY: a null handle is the precondition under test, and `value` is a
        // NUL-terminated buffer that outlives the call.
        let code = unsafe { curl_url_set(ptr::null_mut(), CURLUPART_HOST, value.as_ptr(), word) };
        assert_eq!(code, CURLUE_BAD_HANDLE, "flags {word:#x}");
    }
}
