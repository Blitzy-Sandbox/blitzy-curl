// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! `curl_url_*` — the C ABI for the libcurl URL API (`include/curl/urlapi.h`).
//!
//! This module is the `extern "C"` surface of curl's URL API. It re-exposes the safe-Rust
//! parser [`curl_rs_lib::urlapi::Url`] behind the opaque `CURLU*` handle exactly as declared
//! in `include/curl/urlapi.h` (6 `CURL_EXTERN` functions), so existing C/C++ consumers relink
//! against the Rust implementation without recompilation. Behavior is derived 1:1 from the
//! curl 8.19.0-DEV reference — the C entry points in `lib/urlapi.c` and the message table in
//! `lib/strerror.c` are preserved as the read-only source of truth.
//!
//! ## Handle mapping (opaque `CURLU*` ↔ `Box<Url>`)
//!
//! A `CURLU*` handle is a heap-boxed [`Url`] surfaced to C as an opaque `void*`
//! (`include/curl/urlapi.h` types it as `typedef struct Curl_URL CURLU;` — the fields are
//! never exposed). The pointer is produced by [`curl_url`] / [`curl_url_dup`] via
//! [`crate::box_into_raw`], borrowed with [`crate::as_ref`] / [`crate::as_mut`], and reclaimed
//! by [`curl_url_cleanup`] via [`crate::box_from_raw`]. curl's manual
//! `malloc`/`free`/`strdup` bookkeeping (`curl_url_cleanup`, the `DUP` macro in
//! `lib/urlapi.c`) is subsumed by Rust ownership: cleanup is a `Box` drop and `dup` is a deep
//! [`Clone`].
//!
//! ## Frozen ABI (`include/curl/urlapi.h`)
//!
//! [`CURLUcode`] (`CURLUE_OK == 0` … `CURLUE_TOO_LARGE == 31`, plus the `CURLUE_LAST`
//! sentinel), [`CURLUPart`] (11 variants, `CURLUPART_URL == 0` … `CURLUPART_ZONEID == 10`),
//! and the `CURLU_*` flag bits are a **frozen integer contract** transcribed verbatim from the
//! header. Their `#[repr(i32)]` discriminants / `c_uint` values are pinned and unit-tested so
//! a consumer that hard-codes `CURLUE_NO_HOST == 14` keeps working. `cbindgen` regenerates the
//! matching C declarations from these definitions (see `cbindgen.toml`
//! `[export].include = [… "CURLUcode", "CURLUPart" …]` and `add_sentinel = false`, which is why
//! `CURLUE_LAST` is declared explicitly here).
//!
//! ## Inbound integers, not enums (memory-safety, AAP §0.6.2 / §0.7.2)
//!
//! The URL-part selector and the strerror code are received as [`libc::c_int`], **not** as the
//! `#[repr(i32)]` enums. Materializing an out-of-range value as a fieldless `#[repr(i32)]` enum
//! is undefined behavior, and eliminating that UB class is the entire reason for this rewrite.
//! Receiving the ABI-identical integer (a C `enum` *is* an `int`) and converting it with an
//! explicit, total match keeps every entry point sound for arbitrary C input: an unknown part
//! yields `CURLUE_UNKNOWN_PART` and an unknown strerror code yields curl's `"CURLUcode
//! unknown"` — matching curl's own behavior exactly. This mirrors the crate's inbound-code
//! convention (`crate::code_from_c_int`). The result code is returned as `c_int` (the header's
//! `CURLUcode` is an `int`), which also composes cleanly with [`crate::ffi_guard`].
//!
//! ## Unsafe & unwind policy (AAP §0.6.2 / §0.7.2)
//!
//! `curl-rs-lib` is `#![forbid(unsafe_code)]`; this boundary module is where `unsafe` lives.
//! Every `unsafe` block below carries a `// SAFETY:` comment stating the invariant it upholds
//! (enforced by the CI grep audit and AddressSanitizer), and `#![deny(unsafe_op_in_unsafe_fn)]`
//! keeps that discipline inside the `unsafe extern "C"` entry points. No panic may unwind
//! across the FFI boundary: fallible bodies run under [`crate::ffi_guard`], and the
//! handle-producing / reclaiming entry points run under [`std::panic::catch_unwind`], returning
//! a null pointer or a benign error on a caught panic.

// Require every unsafe operation to sit inside an explicit `unsafe { … }` block — even within
// an `unsafe fn` — so each carries its own adjacent `// SAFETY:` note (AAP §0.7.2).
#![deny(unsafe_op_in_unsafe_fn)]

use crate::{as_mut, as_ref, box_from_raw, box_into_raw, cstr_to_str, ffi_guard, str_to_c_owned};
use curl_rs_lib::urlapi::CurlUPart as CorePart;
use curl_rs_lib::urlapi::Url;
use libc::{c_char, c_int, c_uint, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

// ===========================================================================
// CURLUcode — the URL-API result code (transcribed verbatim from urlapi.h).
// ===========================================================================

/// libcurl URL-API result codes (`CURLUcode`).
///
/// A language-faithful transcription of the `CURLUcode` enumeration in
/// `include/curl/urlapi.h`; every discriminant matches the C header exactly, so the integer
/// contract is preserved across the FFI boundary. The trailing `CURLUE_LAST` sentinel is
/// declared explicitly (cbindgen's `add_sentinel = false`) to reproduce the header. The
/// representation is `i32`, matching curl's C `enum` (a plain `int`); a fieldless
/// `#[repr(i32)]` enum can be cast to its discriminant with `code as c_int`, which is exactly
/// the value an FFI caller observes. The variant names use curl's `SCREAMING_SNAKE_CASE`
/// spelling (permitted by the crate-level `allow(non_camel_case_types)` in `lib.rs`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CURLUcode {
    CURLUE_OK = 0,
    CURLUE_BAD_HANDLE = 1,
    CURLUE_BAD_PARTPOINTER = 2,
    CURLUE_MALFORMED_INPUT = 3,
    CURLUE_BAD_PORT_NUMBER = 4,
    CURLUE_UNSUPPORTED_SCHEME = 5,
    CURLUE_URLDECODE = 6,
    CURLUE_OUT_OF_MEMORY = 7,
    CURLUE_USER_NOT_ALLOWED = 8,
    CURLUE_UNKNOWN_PART = 9,
    CURLUE_NO_SCHEME = 10,
    CURLUE_NO_USER = 11,
    CURLUE_NO_PASSWORD = 12,
    CURLUE_NO_OPTIONS = 13,
    CURLUE_NO_HOST = 14,
    CURLUE_NO_PORT = 15,
    CURLUE_NO_QUERY = 16,
    CURLUE_NO_FRAGMENT = 17,
    CURLUE_NO_ZONEID = 18,
    CURLUE_BAD_FILE_URL = 19,
    CURLUE_BAD_FRAGMENT = 20,
    CURLUE_BAD_HOSTNAME = 21,
    CURLUE_BAD_IPV6 = 22,
    CURLUE_BAD_LOGIN = 23,
    CURLUE_BAD_PASSWORD = 24,
    CURLUE_BAD_PATH = 25,
    CURLUE_BAD_QUERY = 26,
    CURLUE_BAD_SCHEME = 27,
    CURLUE_BAD_SLASHES = 28,
    CURLUE_BAD_USER = 29,
    CURLUE_LACKS_IDN = 30,
    CURLUE_TOO_LARGE = 31,
    /// Sentinel; not a real error code (`CURLUE_LAST` in `urlapi.h`).
    CURLUE_LAST = 32,
}

// ===========================================================================
// CURLUPart — the addressable URL components (transcribed verbatim from urlapi.h).
// ===========================================================================

/// The individual URL components addressable by [`curl_url_get`] / [`curl_url_set`]
/// (`CURLUPart`). Discriminants match `include/curl/urlapi.h` exactly (`CURLUPART_URL == 0` …
/// `CURLUPART_ZONEID == 10`). This is the ABI-visible declaration; the inbound `what` selector
/// is received as `c_int` and mapped to the core [`CurlUPart`] soundly (see [`core_part`]).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CURLUPart {
    CURLUPART_URL = 0,
    CURLUPART_SCHEME = 1,
    CURLUPART_USER = 2,
    CURLUPART_PASSWORD = 3,
    CURLUPART_OPTIONS = 4,
    CURLUPART_HOST = 5,
    CURLUPART_PORT = 6,
    CURLUPART_PATH = 7,
    CURLUPART_QUERY = 8,
    CURLUPART_FRAGMENT = 9,
    /// Added in curl 7.65.0.
    CURLUPART_ZONEID = 10,
}

// ===========================================================================
// CURLU_* flag bits — transcribed verbatim from urlapi.h (values are ABI-frozen).
// ===========================================================================
//
// These bits are accepted by `curl_url_get` / `curl_url_set` and share the exact numeric
// values of the core parser's flag constants (`curl_rs_lib::urlapi::{DEFAULT_PORT, …}`), so the
// raw `flags` integer is forwarded to the core unchanged (a C `enum`/bitmask `unsigned int`
// maps directly onto the core's `u32`).

/// `CURLU_DEFAULT_PORT` — return the default port number for the scheme on get.
pub const CURLU_DEFAULT_PORT: c_uint = 1 << 0;
/// `CURLU_NO_DEFAULT_PORT` — on get, omit a stored port that equals the scheme default.
pub const CURLU_NO_DEFAULT_PORT: c_uint = 1 << 1;
/// `CURLU_DEFAULT_SCHEME` — treat a scheme-less URL as using the default scheme.
pub const CURLU_DEFAULT_SCHEME: c_uint = 1 << 2;
/// `CURLU_NON_SUPPORT_SCHEME` — accept a scheme curl has no built-in handler for.
pub const CURLU_NON_SUPPORT_SCHEME: c_uint = 1 << 3;
/// `CURLU_PATH_AS_IS` — do not apply RFC 3986 dot-segment removal to the path.
pub const CURLU_PATH_AS_IS: c_uint = 1 << 4;
/// `CURLU_DISALLOW_USER` — reject a URL carrying user/password credentials.
pub const CURLU_DISALLOW_USER: c_uint = 1 << 5;
/// `CURLU_URLDECODE` — URL-decode the component on get.
pub const CURLU_URLDECODE: c_uint = 1 << 6;
/// `CURLU_URLENCODE` — URL-encode the component on set.
pub const CURLU_URLENCODE: c_uint = 1 << 7;
/// `CURLU_APPENDQUERY` — append (rather than replace) when setting the query.
pub const CURLU_APPENDQUERY: c_uint = 1 << 8;
/// `CURLU_GUESS_SCHEME` — enable curl's legacy hostname-based scheme guessing.
pub const CURLU_GUESS_SCHEME: c_uint = 1 << 9;
/// `CURLU_NO_AUTHORITY` — allow an empty authority when the scheme is unknown.
pub const CURLU_NO_AUTHORITY: c_uint = 1 << 10;
/// `CURLU_ALLOW_SPACE` — allow (unencoded) space characters in the URL.
pub const CURLU_ALLOW_SPACE: c_uint = 1 << 11;
/// `CURLU_PUNYCODE` — return the hostname in its ACE/Punycode form on get.
pub const CURLU_PUNYCODE: c_uint = 1 << 12;
/// `CURLU_PUNY2IDN` — convert a Punycode hostname back to IDN/Unicode on get.
pub const CURLU_PUNY2IDN: c_uint = 1 << 13;
/// `CURLU_GET_EMPTY` — return/emit empty query and fragment components.
pub const CURLU_GET_EMPTY: c_uint = 1 << 14;
/// `CURLU_NO_GUESS_SCHEME` — on get, do not return a scheme that was guessed.
pub const CURLU_NO_GUESS_SCHEME: c_uint = 1 << 15;

// ===========================================================================
// Internal conversion — inbound C `what` integer → core `CurlUPart`, soundly.
// ===========================================================================

/// Maps a raw C `CURLUPart` integer to the core [`CurlUPart`].
///
/// The selector is received as `c_int` (not the [`CURLUPart`] enum) so an out-of-range value
/// from C is reported by the caller as `CURLUE_UNKNOWN_PART` instead of materializing an
/// invalid `#[repr(i32)]` discriminant (which would be undefined behavior — AAP §0.6.2). The
/// literal arms are the frozen ABI discriminants from `include/curl/urlapi.h`.
#[inline]
fn core_part(what: c_int) -> Option<CorePart> {
    match what {
        0 => Some(CorePart::Url),
        1 => Some(CorePart::Scheme),
        2 => Some(CorePart::User),
        3 => Some(CorePart::Password),
        4 => Some(CorePart::Options),
        5 => Some(CorePart::Host),
        6 => Some(CorePart::Port),
        7 => Some(CorePart::Path),
        8 => Some(CorePart::Query),
        9 => Some(CorePart::Fragment),
        10 => Some(CorePart::ZoneId),
        _ => None,
    }
}

// ===========================================================================
// The 6 CURL_EXTERN entry points (byte-exact ABI from include/curl/urlapi.h).
// ===========================================================================

/// `CURLU *curl_url(void);`
///
/// Creates a new, empty `CURLU` handle and returns a pointer to it, or null on failure. The
/// handle must be freed with [`curl_url_cleanup`].
#[no_mangle]
pub extern "C" fn curl_url() -> *mut c_void {
    // Constructing an empty handle cannot fail; the guard only defends against an unexpected
    // panic (returning null, matching curl's out-of-memory NULL return) so nothing unwinds
    // across the FFI boundary.
    catch_unwind(|| box_into_raw(Url::new()) as *mut c_void).unwrap_or(ptr::null_mut())
}

/// `void curl_url_cleanup(CURLU *handle);`
///
/// Frees a `CURLU` handle previously returned by [`curl_url`] / [`curl_url_dup`]. A null handle
/// is a no-op (matching curl's `if(u)` guard). Strings previously returned by [`curl_url_get`]
/// are **not** freed by this call.
///
/// # Safety
/// `handle` must be null or a valid `CURLU*` produced by [`curl_url`] / [`curl_url_dup`] that
/// has not already been freed; it must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn curl_url_cleanup(handle: *mut c_void) {
    // Guard the reclaim+drop so a hypothetical panic in `Drop` cannot unwind across FFI.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: per the documented contract `handle` is null or a live `Box<Url>` pointer
        // from `curl_url`/`curl_url_dup` not previously reclaimed; `box_from_raw` null-checks
        // and reconstructs the `Box` exactly once, transferring ownership back to Rust so the
        // value drops here.
        drop(unsafe { box_from_raw(handle as *mut Url) });
    }));
}

/// `CURLU *curl_url_dup(const CURLU *in);`
///
/// Duplicates a `CURLU` handle and returns an independent deep copy (or null on failure / a
/// null input). The new handle must also be freed with [`curl_url_cleanup`].
///
/// # Safety
/// `input` must be null or a valid `CURLU*` produced by [`curl_url`] / [`curl_url_dup`] that
/// remains valid for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn curl_url_dup(input: *const c_void) -> *mut c_void {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: per the documented contract `input` is null or points to a valid, live `Url`
        // for the duration of this call with no conflicting mutable alias; `as_ref` null-checks
        // and forms a shared reference used only to clone.
        let existing = match unsafe { as_ref::<Url>(input as *const Url) } {
            Some(u) => u,
            // curl dereferences a NULL `in` (UB); we defensively return null instead.
            None => return ptr::null_mut(),
        };
        box_into_raw(existing.dup()) as *mut c_void
    }))
    .unwrap_or(ptr::null_mut())
}

/// `CURLUcode curl_url_get(const CURLU *handle, CURLUPart what, char **part,
///                         unsigned int flags);`
///
/// Extracts a component from the handle. On success a heap-allocated, NUL-terminated copy is
/// written to `*part` (the caller must release it with `curl_free`) and `CURLUE_OK` is
/// returned. A missing component returns the specific `CURLUE_NO_*` code with `*part` left
/// NULL. Returns `CURLUE_BAD_HANDLE` for a null handle and `CURLUE_BAD_PARTPOINTER` for a null
/// `part`. `flags` (`CURLU_DEFAULT_PORT`, `CURLU_URLDECODE`, `CURLU_PUNYCODE`, …) are honored.
///
/// # Safety
/// `handle` must be null or a valid `CURLU*`; `part` must be null or point to a writable
/// `*mut c_char` slot. Both must remain valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_url_get(
    handle: *const c_void,
    what: c_int,
    part: *mut *mut c_char,
    flags: c_uint,
) -> c_int {
    ffi_guard(
        CURLUcode::CURLUE_OUT_OF_MEMORY as c_int,
        AssertUnwindSafe(move || {
            // Null handle → CURLUE_BAD_HANDLE (matches `lib/urlapi.c`: `if(!u)`).
            // SAFETY: per the documented contract `handle` is null or points to a valid, live
            // `Url` for this call with no conflicting mutable alias; `as_ref` null-checks and
            // forms a shared reference.
            let url = match unsafe { as_ref::<Url>(handle as *const Url) } {
                Some(u) => u,
                None => return CURLUcode::CURLUE_BAD_HANDLE as c_int,
            };
            // Null out-pointer → CURLUE_BAD_PARTPOINTER (matches `if(!part)`).
            if part.is_null() {
                return CURLUcode::CURLUE_BAD_PARTPOINTER as c_int;
            }
            // Match curl: clear `*part` before doing anything else, so on any error the caller
            // observes NULL.
            // SAFETY: `part` is non-null (checked) and, per the contract, points to a writable
            // `*mut c_char` slot owned by the caller.
            unsafe { *part = ptr::null_mut() };

            // Resolve the component id; an unknown id is CURLUE_UNKNOWN_PART.
            let what = match core_part(what) {
                Some(p) => p,
                None => return CURLUcode::CURLUE_UNKNOWN_PART as c_int,
            };

            // `flags` is `c_uint`, which is `u32` — the exact type the core `get` expects, so
            // the raw bitmask forwards unchanged (no remapping of the frozen `CURLU_*` bits).
            match url.get(what, flags) {
                Ok(s) => {
                    let owned = str_to_c_owned(&s);
                    if owned.is_null() {
                        // Interior NUL / allocation failure: mirror curl's OOM path.
                        return CURLUcode::CURLUE_OUT_OF_MEMORY as c_int;
                    }
                    // SAFETY: `part` is non-null; hand the owned C string to the caller, who
                    // releases it with `curl_free` (symmetric with `str_to_c_owned`).
                    unsafe { *part = owned };
                    CURLUcode::CURLUE_OK as c_int
                }
                // Missing component: `*part` stays NULL; return the specific CURLUE_NO_* code.
                Err(code) => code as c_int,
            }
        }),
    )
}

/// `CURLUcode curl_url_set(CURLU *handle, CURLUPart what, const char *part,
///                         unsigned int flags);`
///
/// Sets, replaces, or (when `part` is null) clears a component. The string is copied. Returns
/// `CURLUE_OK` or the specific error code, and `CURLUE_BAD_HANDLE` for a null handle. `flags`
/// (`CURLU_URLENCODE`, `CURLU_APPENDQUERY`, `CURLU_NON_SUPPORT_SCHEME`, `CURLU_GUESS_SCHEME`,
/// `CURLU_PATH_AS_IS`, …) are honored.
///
/// # Safety
/// `handle` must be null or a valid `CURLU*`; `part` must be null or a valid NUL-terminated C
/// string. Both must remain valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_url_set(
    handle: *mut c_void,
    what: c_int,
    part: *const c_char,
    flags: c_uint,
) -> c_int {
    ffi_guard(
        CURLUcode::CURLUE_OUT_OF_MEMORY as c_int,
        AssertUnwindSafe(move || {
            // Null handle → CURLUE_BAD_HANDLE (matches `lib/urlapi.c`: `if(!u)`).
            // SAFETY: per the documented contract `handle` is null or points to a valid, live
            // `Url` for this call with no other alias; `as_mut` null-checks and forms the unique
            // reference used to mutate the handle.
            let url = match unsafe { as_mut::<Url>(handle as *mut Url) } {
                Some(u) => u,
                None => return CURLUcode::CURLUE_BAD_HANDLE as c_int,
            };
            // Resolve the component id; an unknown id is CURLUE_UNKNOWN_PART.
            let what = match core_part(what) {
                Some(p) => p,
                None => return CURLUcode::CURLUE_UNKNOWN_PART as c_int,
            };
            // A null `part` clears the component (curl contract). A non-null value must be valid
            // UTF-8 for the core `&str` API; non-UTF-8 is reported as malformed input.
            let value: Option<&str> = if part.is_null() {
                None
            } else {
                // SAFETY: `part` is non-null and, per the contract, a valid NUL-terminated C
                // string alive for this call; `cstr_to_str` reads up to the NUL and validates
                // UTF-8.
                match unsafe { cstr_to_str(part) } {
                    Some(s) => Some(s),
                    None => return CURLUcode::CURLUE_MALFORMED_INPUT as c_int,
                }
            };
            // `flags` is `c_uint` == `u32`, forwarded unchanged to the core `set`.
            match url.set(what, value, flags) {
                Ok(()) => CURLUcode::CURLUE_OK as c_int,
                Err(code) => code as c_int,
            }
        }),
    )
}

/// `const char *curl_url_strerror(CURLUcode);`
///
/// Returns a static, process-lifetime, NUL-terminated human-readable message for a
/// `CURLUcode`. The returned pointer must **not** be freed. The messages are transcribed
/// verbatim from curl 8.x (`lib/strerror.c` / [`curl_rs_lib::urlapi::strerror`]); an
/// out-of-range value yields `"CURLUcode unknown"`, matching curl.
///
/// The code is received as `c_int` (not the [`CURLUcode`] enum) so any value — including ones
/// outside the valid range — is handled without risking UB from an invalid `#[repr(i32)]`
/// discriminant.
#[no_mangle]
pub extern "C" fn curl_url_strerror(error: c_int) -> *const c_char {
    // Static byte-string literals (1.75-compatible; no `c"…"` literals) with explicit NUL
    // terminators, kept byte-identical to `curl_rs_lib::error::url_strerror` (asserted in the
    // tests) which itself reproduces `lib/strerror.c`.
    let msg: &'static [u8] = match error {
        0 => b"No error\0",
        1 => b"An invalid CURLU pointer was passed as argument\0",
        2 => b"An invalid 'part' argument was passed as argument\0",
        3 => b"Malformed input to a URL function\0",
        4 => b"Port number was not a decimal number between 0 and 65535\0",
        5 => b"Unsupported URL scheme\0",
        6 => b"URL decode error, most likely because of rubbish in the input\0",
        7 => b"A memory function failed\0",
        8 => b"Credentials was passed in the URL when prohibited\0",
        9 => b"An unknown part ID was passed to a URL API function\0",
        10 => b"No scheme part in the URL\0",
        11 => b"No user part in the URL\0",
        12 => b"No password part in the URL\0",
        13 => b"No options part in the URL\0",
        14 => b"No host part in the URL\0",
        15 => b"No port part in the URL\0",
        16 => b"No query part in the URL\0",
        17 => b"No fragment part in the URL\0",
        18 => b"No zoneid part in the URL\0",
        19 => b"Bad file:// URL\0",
        20 => b"Bad fragment\0",
        21 => b"Bad hostname\0",
        22 => b"Bad IPv6 address\0",
        23 => b"Bad login part\0",
        24 => b"Bad password\0",
        25 => b"Bad path\0",
        26 => b"Bad query\0",
        27 => b"Bad scheme\0",
        28 => b"Unsupported number of slashes following scheme\0",
        29 => b"Bad user\0",
        30 => b"libcurl lacks IDN support\0",
        31 => b"A value or data field is larger than allowed\0",
        _ => b"CURLUcode unknown\0",
    };
    msg.as_ptr() as *const c_char
}

// ===========================================================================
// Tests — exercise the C ABI surface end-to-end through the extern "C" entry
// points. They transcribe representative cases from curl's URL-API regression
// suite (lib1560 / `tests/unit/unit1560.c`): full-URL round-trips, the frozen
// integer ABI, per-component get/set, null-safety, unknown-part handling, the
// clear-on-null contract, flag behaviors, `dup` deep-copy, and `strerror`
// parity with the core (and hence curl 8.x).
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use curl_rs_lib::error::CurlUCode;
    use curl_rs_lib::urlapi::strerror as core_strerror;
    use std::ffi::{CStr, CString};

    /// Reclaims a C string produced by [`curl_url_get`] and returns its Rust `String`, freeing
    /// the C allocation — exactly the round-trip a caller performs with `curl_free` (which, like
    /// [`str_to_c_owned`], is symmetric with `CString::into_raw`/`from_raw`).
    ///
    /// # Safety
    /// `p` must be a non-null pointer previously written by [`curl_url_get`] and not yet freed.
    unsafe fn take_owned(p: *mut c_char) -> String {
        assert!(!p.is_null(), "expected a non-null part pointer");
        // SAFETY: `p` was produced by `str_to_c_owned` (`CString::into_raw`) and has not been
        // reclaimed; `CString::from_raw` takes back that exact allocation once.
        let owned = unsafe { CString::from_raw(p) };
        owned.into_string().expect("URL part is valid UTF-8")
    }

    /// Read a component through the FFI, freeing any returned string, and assert the error-path
    /// contract that `*part` is left NULL.
    fn get_part(handle: *const c_void, what: CURLUPart, flags: c_uint) -> (c_int, Option<String>) {
        let mut p: *mut c_char = ptr::null_mut();
        // SAFETY: `handle` is a valid handle (or null, which yields BAD_HANDLE) and `&mut p` is
        // a valid writable `*mut c_char` slot for the duration of the call.
        let rc = unsafe { curl_url_get(handle, what as c_int, &mut p, flags) };
        if rc == CURLUcode::CURLUE_OK as c_int {
            // SAFETY: on CURLUE_OK, `curl_url_get` wrote a freshly allocated C string into `p`.
            (rc, Some(unsafe { take_owned(p) }))
        } else {
            assert!(p.is_null(), "on a non-OK return, *part must be NULL");
            (rc, None)
        }
    }

    /// Set a component from a Rust `&str` through the FFI.
    fn set_part(handle: *mut c_void, what: CURLUPart, value: &str, flags: c_uint) -> c_int {
        let c = CString::new(value).expect("test input has no interior NUL");
        // SAFETY: `handle` is valid (or null); `c` outlives the call and is a valid C string.
        unsafe { curl_url_set(handle, what as c_int, c.as_ptr(), flags) }
    }

    #[test]
    fn curlucode_integer_values_are_frozen_abi() {
        assert_eq!(CURLUcode::CURLUE_OK as c_int, 0);
        assert_eq!(CURLUcode::CURLUE_BAD_HANDLE as c_int, 1);
        assert_eq!(CURLUcode::CURLUE_BAD_PARTPOINTER as c_int, 2);
        assert_eq!(CURLUcode::CURLUE_MALFORMED_INPUT as c_int, 3);
        assert_eq!(CURLUcode::CURLUE_BAD_PORT_NUMBER as c_int, 4);
        assert_eq!(CURLUcode::CURLUE_UNSUPPORTED_SCHEME as c_int, 5);
        assert_eq!(CURLUcode::CURLUE_URLDECODE as c_int, 6);
        assert_eq!(CURLUcode::CURLUE_OUT_OF_MEMORY as c_int, 7);
        assert_eq!(CURLUcode::CURLUE_USER_NOT_ALLOWED as c_int, 8);
        assert_eq!(CURLUcode::CURLUE_UNKNOWN_PART as c_int, 9);
        assert_eq!(CURLUcode::CURLUE_NO_SCHEME as c_int, 10);
        assert_eq!(CURLUcode::CURLUE_NO_USER as c_int, 11);
        assert_eq!(CURLUcode::CURLUE_NO_PASSWORD as c_int, 12);
        assert_eq!(CURLUcode::CURLUE_NO_OPTIONS as c_int, 13);
        assert_eq!(CURLUcode::CURLUE_NO_HOST as c_int, 14);
        assert_eq!(CURLUcode::CURLUE_NO_PORT as c_int, 15);
        assert_eq!(CURLUcode::CURLUE_NO_QUERY as c_int, 16);
        assert_eq!(CURLUcode::CURLUE_NO_FRAGMENT as c_int, 17);
        assert_eq!(CURLUcode::CURLUE_NO_ZONEID as c_int, 18);
        assert_eq!(CURLUcode::CURLUE_BAD_FILE_URL as c_int, 19);
        assert_eq!(CURLUcode::CURLUE_BAD_FRAGMENT as c_int, 20);
        assert_eq!(CURLUcode::CURLUE_BAD_HOSTNAME as c_int, 21);
        assert_eq!(CURLUcode::CURLUE_BAD_IPV6 as c_int, 22);
        assert_eq!(CURLUcode::CURLUE_BAD_LOGIN as c_int, 23);
        assert_eq!(CURLUcode::CURLUE_BAD_PASSWORD as c_int, 24);
        assert_eq!(CURLUcode::CURLUE_BAD_PATH as c_int, 25);
        assert_eq!(CURLUcode::CURLUE_BAD_QUERY as c_int, 26);
        assert_eq!(CURLUcode::CURLUE_BAD_SCHEME as c_int, 27);
        assert_eq!(CURLUcode::CURLUE_BAD_SLASHES as c_int, 28);
        assert_eq!(CURLUcode::CURLUE_BAD_USER as c_int, 29);
        assert_eq!(CURLUcode::CURLUE_LACKS_IDN as c_int, 30);
        assert_eq!(CURLUcode::CURLUE_TOO_LARGE as c_int, 31);
        assert_eq!(CURLUcode::CURLUE_LAST as c_int, 32);
    }

    #[test]
    fn curlupart_integer_values_are_frozen_abi() {
        assert_eq!(CURLUPart::CURLUPART_URL as c_int, 0);
        assert_eq!(CURLUPart::CURLUPART_SCHEME as c_int, 1);
        assert_eq!(CURLUPart::CURLUPART_USER as c_int, 2);
        assert_eq!(CURLUPart::CURLUPART_PASSWORD as c_int, 3);
        assert_eq!(CURLUPart::CURLUPART_OPTIONS as c_int, 4);
        assert_eq!(CURLUPart::CURLUPART_HOST as c_int, 5);
        assert_eq!(CURLUPart::CURLUPART_PORT as c_int, 6);
        assert_eq!(CURLUPart::CURLUPART_PATH as c_int, 7);
        assert_eq!(CURLUPart::CURLUPART_QUERY as c_int, 8);
        assert_eq!(CURLUPart::CURLUPART_FRAGMENT as c_int, 9);
        assert_eq!(CURLUPart::CURLUPART_ZONEID as c_int, 10);
    }

    #[test]
    fn curlu_flag_bits_are_exact() {
        assert_eq!(CURLU_DEFAULT_PORT, 1 << 0);
        assert_eq!(CURLU_NO_DEFAULT_PORT, 1 << 1);
        assert_eq!(CURLU_DEFAULT_SCHEME, 1 << 2);
        assert_eq!(CURLU_NON_SUPPORT_SCHEME, 1 << 3);
        assert_eq!(CURLU_PATH_AS_IS, 1 << 4);
        assert_eq!(CURLU_DISALLOW_USER, 1 << 5);
        assert_eq!(CURLU_URLDECODE, 1 << 6);
        assert_eq!(CURLU_URLENCODE, 1 << 7);
        assert_eq!(CURLU_APPENDQUERY, 1 << 8);
        assert_eq!(CURLU_GUESS_SCHEME, 1 << 9);
        assert_eq!(CURLU_NO_AUTHORITY, 1 << 10);
        assert_eq!(CURLU_ALLOW_SPACE, 1 << 11);
        assert_eq!(CURLU_PUNYCODE, 1 << 12);
        assert_eq!(CURLU_PUNY2IDN, 1 << 13);
        assert_eq!(CURLU_GET_EMPTY, 1 << 14);
        assert_eq!(CURLU_NO_GUESS_SCHEME, 1 << 15);
    }

    #[test]
    fn new_handle_is_non_null_and_cleanup_is_null_safe() {
        let h = curl_url();
        assert!(!h.is_null(), "curl_url() must return a non-null handle");
        // SAFETY: `h` is a live handle from curl_url() and is freed exactly once here.
        unsafe { curl_url_cleanup(h) };
        // A null handle is a no-op.
        // SAFETY: passing null to curl_url_cleanup is explicitly a no-op.
        unsafe { curl_url_cleanup(ptr::null_mut()) };
    }

    #[test]
    fn round_trip_parse_and_extract_every_component() {
        let h = curl_url();
        assert!(!h.is_null());
        let full = "http://user:pass@example.com:8080/a/b?x=1&y=2#frag";
        assert_eq!(set_part(h, CURLUPart::CURLUPART_URL, full, 0), 0);

        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_SCHEME, 0).1.as_deref(),
            Some("http")
        );
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_USER, 0).1.as_deref(),
            Some("user")
        );
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_PASSWORD, 0).1.as_deref(),
            Some("pass")
        );
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_HOST, 0).1.as_deref(),
            Some("example.com")
        );
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_PORT, 0).1.as_deref(),
            Some("8080")
        );
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_PATH, 0).1.as_deref(),
            Some("/a/b")
        );
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_QUERY, 0).1.as_deref(),
            Some("x=1&y=2")
        );
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_FRAGMENT, 0).1.as_deref(),
            Some("frag")
        );

        // The whole-URL re-serialization round-trips.
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_URL, 0).1.as_deref(),
            Some(full)
        );

        // SAFETY: `h` is freed exactly once.
        unsafe { curl_url_cleanup(h) };
    }

    #[test]
    fn missing_component_reports_specific_code_and_clears_out_ptr() {
        let h = curl_url();
        assert_eq!(set_part(h, CURLUPart::CURLUPART_HOST, "example.com", 0), 0);
        // Pre-seed the out-pointer with a non-null sentinel to prove it is cleared.
        let mut p: *mut c_char = ptr::NonNull::<c_char>::dangling().as_ptr();
        // SAFETY: `h` is valid and `&mut p` is a writable slot.
        let rc = unsafe { curl_url_get(h, CURLUPart::CURLUPART_QUERY as c_int, &mut p, 0) };
        assert_eq!(rc, CURLUcode::CURLUE_NO_QUERY as c_int);
        assert!(p.is_null(), "a missing part must reset *part to NULL");
        // SAFETY: `h` is freed exactly once.
        unsafe { curl_url_cleanup(h) };
    }

    #[test]
    fn null_out_pointer_is_bad_partpointer() {
        let h = curl_url();
        // SAFETY: `h` is valid; passing a null `part` out-pointer is the tested contract.
        let rc = unsafe { curl_url_get(h, CURLUPart::CURLUPART_HOST as c_int, ptr::null_mut(), 0) };
        assert_eq!(rc, CURLUcode::CURLUE_BAD_PARTPOINTER as c_int);
        // SAFETY: `h` is freed exactly once.
        unsafe { curl_url_cleanup(h) };
    }

    #[test]
    fn null_handle_is_bad_handle() {
        let mut p: *mut c_char = ptr::null_mut();
        // SAFETY: passing a null handle is the tested contract; `&mut p` is a valid slot.
        let rc_get =
            unsafe { curl_url_get(ptr::null(), CURLUPart::CURLUPART_HOST as c_int, &mut p, 0) };
        assert_eq!(rc_get, CURLUcode::CURLUE_BAD_HANDLE as c_int);
        assert!(p.is_null());
        assert_eq!(
            set_part(ptr::null_mut(), CURLUPart::CURLUPART_HOST, "h", 0),
            CURLUcode::CURLUE_BAD_HANDLE as c_int
        );
    }

    #[test]
    fn unknown_part_id_is_unknown_part() {
        let h = curl_url();
        let mut p: *mut c_char = ptr::null_mut();
        // SAFETY: `h` is valid; `&mut p` is a writable slot; 99 is an out-of-range part id.
        let rc_get = unsafe { curl_url_get(h, 99, &mut p, 0) };
        assert_eq!(rc_get, CURLUcode::CURLUE_UNKNOWN_PART as c_int);
        assert!(p.is_null());
        // An out-of-range `what` on set is likewise CURLUE_UNKNOWN_PART.
        let v = CString::new("x").unwrap();
        // SAFETY: `h` is valid; `v` outlives the call; -1 is an out-of-range part id.
        let rc_set = unsafe { curl_url_set(h, -1, v.as_ptr(), 0) };
        assert_eq!(rc_set, CURLUcode::CURLUE_UNKNOWN_PART as c_int);
        // SAFETY: `h` is freed exactly once.
        unsafe { curl_url_cleanup(h) };
    }

    #[test]
    fn setting_null_part_clears_the_component() {
        let h = curl_url();
        assert_eq!(set_part(h, CURLUPart::CURLUPART_FRAGMENT, "frag", 0), 0);
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_FRAGMENT, 0).1.as_deref(),
            Some("frag")
        );
        // A null `part` clears the component.
        // SAFETY: `h` is valid; a null `part` is the documented clear contract.
        let rc = unsafe { curl_url_set(h, CURLUPart::CURLUPART_FRAGMENT as c_int, ptr::null(), 0) };
        assert_eq!(rc, CURLUcode::CURLUE_OK as c_int);
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_FRAGMENT, 0).0,
            CURLUcode::CURLUE_NO_FRAGMENT as c_int
        );
        // SAFETY: `h` is freed exactly once.
        unsafe { curl_url_cleanup(h) };
    }

    #[test]
    fn appendquery_flag_joins_with_ampersand() {
        let h = curl_url();
        assert_eq!(set_part(h, CURLUPart::CURLUPART_QUERY, "a=1", 0), 0);
        assert_eq!(
            set_part(h, CURLUPart::CURLUPART_QUERY, "b=2", CURLU_APPENDQUERY),
            0
        );
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_QUERY, 0).1.as_deref(),
            Some("a=1&b=2")
        );
        // SAFETY: `h` is freed exactly once.
        unsafe { curl_url_cleanup(h) };
    }

    #[test]
    fn default_port_flag_returns_scheme_default() {
        let h = curl_url();
        assert_eq!(
            set_part(h, CURLUPart::CURLUPART_URL, "http://example.com/", 0),
            0
        );
        // Without a stored port and without the flag, the port is reported missing.
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_PORT, 0).0,
            CURLUcode::CURLUE_NO_PORT as c_int
        );
        // With CURLU_DEFAULT_PORT the scheme default (80 for http) is returned.
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_PORT, CURLU_DEFAULT_PORT)
                .1
                .as_deref(),
            Some("80")
        );
        // SAFETY: `h` is freed exactly once.
        unsafe { curl_url_cleanup(h) };
    }

    #[test]
    fn dup_is_an_independent_deep_copy() {
        let h = curl_url();
        assert_eq!(
            set_part(h, CURLUPart::CURLUPART_URL, "http://a.com/p", 0),
            0
        );
        // SAFETY: `h` is a valid handle for the duration of this call.
        let dup = unsafe { curl_url_dup(h) };
        assert!(!dup.is_null());
        // Mutating the original must not affect the copy.
        assert_eq!(set_part(h, CURLUPart::CURLUPART_HOST, "b.com", 0), 0);
        assert_eq!(
            get_part(dup, CURLUPart::CURLUPART_HOST, 0).1.as_deref(),
            Some("a.com")
        );
        assert_eq!(
            get_part(h, CURLUPart::CURLUPART_HOST, 0).1.as_deref(),
            Some("b.com")
        );
        // SAFETY: both handles are freed exactly once.
        unsafe { curl_url_cleanup(h) };
        // SAFETY: freed exactly once.
        unsafe { curl_url_cleanup(dup) };
    }

    #[test]
    fn dup_of_null_is_null() {
        // SAFETY: passing null to curl_url_dup is defensively handled (returns null).
        assert!(unsafe { curl_url_dup(ptr::null()) }.is_null());
    }

    #[test]
    fn strerror_matches_core_and_handles_unknown() {
        for code in 0..=31 {
            let core = core_strerror(CurlUCode::try_from(code).expect("0..=31 are valid codes"));
            // SAFETY: curl_url_strerror returns a static, NUL-terminated pointer.
            let ffi = unsafe { CStr::from_ptr(curl_url_strerror(code)) }
                .to_str()
                .expect("message is valid UTF-8");
            assert_eq!(ffi, core, "strerror text mismatch for code {code}");
        }
        // CURLUE_LAST (32) and out-of-range values yield curl's "CURLUcode unknown".
        for bad in [32, 99, -1, i32::MAX, i32::MIN] {
            // SAFETY: curl_url_strerror returns a static, NUL-terminated pointer for any input.
            let ffi = unsafe { CStr::from_ptr(curl_url_strerror(bad)) }
                .to_str()
                .expect("message is valid UTF-8");
            assert_eq!(ffi, "CURLUcode unknown", "unexpected message for {bad}");
        }
    }
}
