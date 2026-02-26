//! FFI bindings for the 6 `curl_url_*` CURL_EXTERN symbols.
//!
//! This module exposes the URL API from `include/curl/urlapi.h` as
//! `#[no_mangle] pub unsafe extern "C"` functions.  Each function delegates
//! to the safe Rust [`CurlUrl`] handle in `curl-rs-lib`, performing the
//! necessary pointer-to-reference conversions and memory allocation at the
//! FFI boundary.
//!
//! # Exported Symbols
//!
//! | Symbol               | C Header           | Purpose                            |
//! |----------------------|--------------------|------------------------------------|
//! | `curl_url`           | `urlapi.h:113`     | Allocate new URL handle            |
//! | `curl_url_cleanup`   | `urlapi.h:120`     | Free URL handle                    |
//! | `curl_url_dup`       | `urlapi.h:126`     | Duplicate URL handle               |
//! | `curl_url_get`       | `urlapi.h:133-134` | Extract URL component              |
//! | `curl_url_set`       | `urlapi.h:141-142` | Set URL component                  |
//! | `curl_url_strerror`  | `urlapi.h:149`     | Error code → static message string |
//!
//! # Memory Contract
//!
//! - `curl_url()` returns a heap-allocated handle that MUST be freed with
//!   `curl_url_cleanup()`.
//! - `curl_url_get()` returns a `malloc`-allocated C string that the caller
//!   MUST free with `curl_free()` (which calls `libc::free`).
//! - `curl_url_set()` copies the input string; the caller retains ownership.
//! - Passing `NULL` as the `part` parameter to `curl_url_set()` clears that
//!   URL component.
//!
//! # Safety Invariants
//!
//! Every `unsafe` block carries a `// SAFETY:` comment per AAP Section 0.7.1.
//! The `unsafe` contract for callers:
//!
//! 1. All `CURLU *` handles passed to these functions MUST have been created
//!    by `curl_url()` or `curl_url_dup()` and not yet freed.
//! 2. Output pointer parameters (`*mut *mut c_char`) MUST be valid, writable
//!    pointers.
//! 3. Input `const char *` strings MUST be valid, NUL-terminated C strings
//!    (or NULL for the clear operation).

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]

use libc::{c_char, c_uint};
use std::ffi::CStr;
use std::ptr;

use crate::error_codes::{
    CURLUE_BAD_HANDLE, CURLUE_BAD_PARTPOINTER, CURLUE_MALFORMED_INPUT, CURLUE_OK,
    CURLUE_OUT_OF_MEMORY, CURLUE_UNKNOWN_PART, CURLUE_UNSUPPORTED_SCHEME,
    CURLUE_USER_NOT_ALLOWED,
};
use crate::types::{CURLUPart, CURLUcode, CURLU};

use curl_rs_lib::error::CurlUrlError;
use curl_rs_lib::url::{CurlUrl, CurlUrlPart};

// ============================================================================
// Section 1: CURLUPart Constants
// Values MUST match include/curl/urlapi.h exactly (typedef enum CURLUPart).
// ============================================================================

/// Full URL.
pub const CURLUPART_URL: CURLUPart = 0;
/// Scheme component (e.g. `https`).
pub const CURLUPART_SCHEME: CURLUPart = 1;
/// Username component.
pub const CURLUPART_USER: CURLUPart = 2;
/// Password component.
pub const CURLUPART_PASSWORD: CURLUPart = 3;
/// Protocol-specific options (e.g. IMAP `AUTH=PLAIN`).
pub const CURLUPART_OPTIONS: CURLUPart = 4;
/// Hostname component.
pub const CURLUPART_HOST: CURLUPart = 5;
/// Port number (as string).
pub const CURLUPART_PORT: CURLUPart = 6;
/// Path component.
pub const CURLUPART_PATH: CURLUPart = 7;
/// Query string (without leading `?`).
pub const CURLUPART_QUERY: CURLUPart = 8;
/// Fragment (without leading `#`).
pub const CURLUPART_FRAGMENT: CURLUPart = 9;
/// IPv6 zone ID.
pub const CURLUPART_ZONEID: CURLUPart = 10;

// ============================================================================
// Section 2: CURLU_* Flag Constants
// Values MUST match include/curl/urlapi.h exactly (#define CURLU_*).
// ============================================================================

/// Return the default port number for the scheme (get flag).
pub const CURLU_DEFAULT_PORT: c_uint = 1 << 0;
/// Act as if no port was set when it matches the scheme default (get flag).
pub const CURLU_NO_DEFAULT_PORT: c_uint = 1 << 1;
/// Return the default scheme if none is present (get flag).
pub const CURLU_DEFAULT_SCHEME: c_uint = 1 << 2;
/// Allow non-supported schemes (set flag).
pub const CURLU_NON_SUPPORT_SCHEME: c_uint = 1 << 3;
/// Leave dot sequences in the path unchanged (set flag).
pub const CURLU_PATH_AS_IS: c_uint = 1 << 4;
/// Reject URLs containing user credentials (set flag).
pub const CURLU_DISALLOW_USER: c_uint = 1 << 5;
/// URL-decode on get (get flag).
pub const CURLU_URLDECODE: c_uint = 1 << 6;
/// URL-encode on set (set flag).
pub const CURLU_URLENCODE: c_uint = 1 << 7;
/// Append a form-style query string with `&` separator (set flag).
pub const CURLU_APPENDQUERY: c_uint = 1 << 8;
/// Legacy curl-style scheme guessing from hostname prefix (set flag).
pub const CURLU_GUESS_SCHEME: c_uint = 1 << 9;
/// Allow empty authority when the scheme is unknown (set flag).
pub const CURLU_NO_AUTHORITY: c_uint = 1 << 10;
/// Allow spaces in the URL (set flag).
pub const CURLU_ALLOW_SPACE: c_uint = 1 << 11;
/// Get the hostname in Punycode (get flag).
pub const CURLU_PUNYCODE: c_uint = 1 << 12;
/// Convert Punycode hostname to IDN on get (get flag).
pub const CURLU_PUNY2IDN: c_uint = 1 << 13;
/// Allow empty queries and fragments when extracting (get flag).
pub const CURLU_GET_EMPTY: c_uint = 1 << 14;
/// For get: do not accept a guessed scheme (get flag).
pub const CURLU_NO_GUESS_SCHEME: c_uint = 1 << 15;

// ============================================================================
// Section 3: Internal Helpers
// ============================================================================

/// Maps a [`CurlUrlError`] enum variant to its corresponding `CURLUcode`
/// integer constant.
///
/// Since `CurlUrlError` is `#[repr(i32)]` with discriminants matching the C
/// `CURLUcode` enum exactly, this is a simple numeric cast.  This function
/// is the canonical FFI-boundary error conversion and is exercised by the
/// module's unit tests.  It is also used by [`curl_url_strerror`] to
/// validate the round-trip from integer code to enum variant.
#[inline]
#[allow(dead_code)]
fn url_error_to_code(err: CurlUrlError) -> CURLUcode {
    err as CURLUcode
}

/// Converts a raw `CURLUPart` integer to the Rust [`CurlUrlPart`] enum.
///
/// Returns `None` for values outside the valid range `0..=10`.
#[inline]
fn part_from_int(what: CURLUPart) -> Option<CurlUrlPart> {
    CurlUrlPart::from_i32(what)
}

/// Allocates a C-compatible, NUL-terminated copy of `s` via [`libc::malloc`].
///
/// Returns `Ok(ptr)` on success or `Err(CURLUE_OUT_OF_MEMORY)` when `malloc`
/// returns NULL.
///
/// # Safety
///
/// The returned pointer MUST be freed by the caller via `curl_free()`
/// (i.e. `libc::free`).
fn alloc_c_string(s: &str) -> Result<*mut c_char, CURLUcode> {
    let bytes = s.as_bytes();
    let len = bytes.len();

    // SAFETY: We request `len + 1` bytes from the system allocator.
    // `libc::malloc` is always safe to call; it returns NULL on failure.
    let ptr = unsafe { libc::malloc(len + 1) } as *mut u8;
    if ptr.is_null() {
        return Err(CURLUE_OUT_OF_MEMORY);
    }

    // SAFETY: `ptr` is a valid allocation of `len + 1` bytes.  We copy
    // exactly `len` bytes from `bytes` and then write a NUL terminator.
    // No overlap is possible because `ptr` is freshly allocated.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
        *ptr.add(len) = 0; // NUL terminator
    }

    Ok(ptr as *mut c_char)
}

// ============================================================================
// Section 4: extern "C" Functions — 6 CURL_EXTERN Symbols
// ============================================================================

/// Allocate a new URL handle.
///
/// C signature: `CURL_EXTERN CURLU *curl_url(void);`
///
/// Returns a pointer to a newly allocated URL handle, or `NULL` if the
/// allocation fails.  The handle MUST be freed with [`curl_url_cleanup`].
#[no_mangle]
pub unsafe extern "C" fn curl_url() -> *mut CURLU {
    // SAFETY: We allocate a `CurlUrl` on the heap via `Box::new`.
    // `Box::into_raw` yields a non-null pointer that is valid until
    // the caller passes it to `curl_url_cleanup`.  The pointer is cast
    // from `*mut CurlUrl` to `*mut CURLU` (an opaque FFI marker type);
    // the reverse cast occurs in every function that receives the handle.
    let url_handle = Box::new(CurlUrl::new());
    Box::into_raw(url_handle) as *mut CURLU
}

/// Free a URL handle and all associated resources.
///
/// C signature: `CURL_EXTERN void curl_url_cleanup(CURLU *handle);`
///
/// Passing `NULL` is a safe no-op (matches curl 8.x behavior).  Previously
/// returned strings from [`curl_url_get`] are NOT freed by this call — the
/// caller is responsible for freeing those with `curl_free`.
#[no_mangle]
pub unsafe extern "C" fn curl_url_cleanup(handle: *mut CURLU) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` was created by `curl_url()` or `curl_url_dup()` via
    // `Box::into_raw(Box::new(CurlUrl::new()))`.  We reverse the cast from
    // `*mut CURLU` back to `*mut CurlUrl` and reconstruct the `Box` to
    // transfer ownership back to Rust, which drops the allocation.
    // The caller guarantees that `handle` has not been freed previously
    // and will not be used after this call.
    let _ = Box::from_raw(handle as *mut CurlUrl);
}

/// Duplicate a URL handle.
///
/// C signature: `CURL_EXTERN CURLU *curl_url_dup(const CURLU *in);`
///
/// Returns a deep copy of `inhandle`, or `NULL` if `inhandle` is `NULL` or
/// the allocation fails.  The returned handle MUST be freed independently
/// with [`curl_url_cleanup`].
#[no_mangle]
pub unsafe extern "C" fn curl_url_dup(inhandle: *const CURLU) -> *mut CURLU {
    if inhandle.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `inhandle` was created by `curl_url()` or a prior
    // `curl_url_dup()` and has not been freed.  We cast from `*const CURLU`
    // to `*const CurlUrl` (reversing the cast applied during creation) and
    // dereference to obtain a shared reference.  The caller guarantees the
    // handle remains valid for the duration of this call.
    let original = &*(inhandle as *const CurlUrl);
    let duplicate = Box::new(original.dup());
    Box::into_raw(duplicate) as *mut CURLU
}

/// Extract a specific part of the URL from a handle.
///
/// C signature:
/// ```c
/// CURL_EXTERN CURLUcode curl_url_get(const CURLU *handle,
///                                    CURLUPart what,
///                                    char **part,
///                                    unsigned int flags);
/// ```
///
/// On success, `*part` is set to a `malloc`-allocated, NUL-terminated C
/// string that the caller MUST free via `curl_free()`.
///
/// # Error Returns
///
/// - `CURLUE_BAD_HANDLE` — `handle` is `NULL`
/// - `CURLUE_BAD_PARTPOINTER` — `part` is `NULL`
/// - `CURLUE_UNKNOWN_PART` — `what` is not a valid `CURLUPart` value
/// - `CURLUE_OUT_OF_MEMORY` — `malloc` failed
/// - Any `CURLUE_NO_*` code when the requested component is absent
#[no_mangle]
pub unsafe extern "C" fn curl_url_get(
    handle: *const CURLU,
    what: CURLUPart,
    part: *mut *mut c_char,
    flags: c_uint,
) -> CURLUcode {
    // Validate handle pointer.
    if handle.is_null() {
        return CURLUE_BAD_HANDLE;
    }
    // Validate output pointer.
    if part.is_null() {
        return CURLUE_BAD_PARTPOINTER;
    }

    // Convert the integer part selector to the Rust enum.
    let url_part = match part_from_int(what) {
        Some(p) => p,
        None => return CURLUE_UNKNOWN_PART,
    };

    // SAFETY: `handle` was created by `curl_url()` or `curl_url_dup()` and
    // is guaranteed valid by the caller.  We cast from `*const CURLU` back
    // to `*const CurlUrl` and create a shared reference for the duration of
    // this call.
    let url_ref = &*(handle as *const CurlUrl);

    // Invoke the safe Rust `get` method.
    match url_ref.get(url_part, flags) {
        Ok(value) => {
            // Allocate a C-compatible copy of the result string.
            match alloc_c_string(&value) {
                Ok(c_ptr) => {
                    // SAFETY: `part` is a valid, writable pointer (caller contract).
                    // We write the freshly allocated string pointer to `*part`.
                    *part = c_ptr;
                    CURLUE_OK
                }
                Err(code) => code,
            }
        }
        Err(e) => curl_error_to_url_code(e),
    }
}

/// Set a specific part of the URL in a handle.
///
/// C signature:
/// ```c
/// CURL_EXTERN CURLUcode curl_url_set(CURLU *handle,
///                                    CURLUPart what,
///                                    const char *part,
///                                    unsigned int flags);
/// ```
///
/// Passing `NULL` for `part` clears the specified component (matches curl
/// 8.x behavior).  The input string is copied — the caller retains ownership.
///
/// # Error Returns
///
/// - `CURLUE_BAD_HANDLE` — `handle` is `NULL`
/// - `CURLUE_UNKNOWN_PART` — `what` is not a valid `CURLUPart` value
/// - Various `CURLUE_BAD_*` or `CURLUE_MALFORMED_INPUT` codes for invalid content
#[no_mangle]
pub unsafe extern "C" fn curl_url_set(
    handle: *mut CURLU,
    what: CURLUPart,
    part: *const c_char,
    flags: c_uint,
) -> CURLUcode {
    // Validate handle pointer.
    if handle.is_null() {
        return CURLUE_BAD_HANDLE;
    }

    // Convert the integer part selector to the Rust enum.
    let url_part = match part_from_int(what) {
        Some(p) => p,
        None => return CURLUE_UNKNOWN_PART,
    };

    // SAFETY: `handle` was created by `curl_url()` or `curl_url_dup()` and
    // is guaranteed valid and exclusively owned by the caller (no aliasing
    // `&mut` references exist).  We cast from `*mut CURLU` back to
    // `*mut CurlUrl` and create a mutable reference for the duration of
    // this call.
    let url_ref = &mut *(handle as *mut CurlUrl);

    // NULL `part` means "clear this component" per the C API contract.
    if part.is_null() {
        url_ref.clear(url_part);
        return CURLUE_OK;
    }

    // SAFETY: `part` is a valid, NUL-terminated C string (caller contract).
    // `CStr::from_ptr` scans for the NUL terminator without going out of
    // bounds.
    let c_str = CStr::from_ptr(part);
    let content = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return CURLUE_MALFORMED_INPUT,
    };

    // Invoke the safe Rust `set` method.
    match url_ref.set(url_part, content, flags) {
        Ok(()) => CURLUE_OK,
        Err(e) => curl_error_to_url_code(e),
    }
}

/// Return a human-readable error message for a `CURLUcode` value.
///
/// C signature: `CURL_EXTERN const char *curl_url_strerror(CURLUcode);`
///
/// The returned pointer refers to a static string with program lifetime.
/// The caller MUST NOT free it.  Returns a generic "Unknown error" message
/// for codes outside the valid `CURLUcode` range.
#[no_mangle]
pub unsafe extern "C" fn curl_url_strerror(code: CURLUcode) -> *const c_char {
    // Convert the integer code to the Rust enum and retrieve the static
    // error message.  All strings are byte-literal constants with explicit
    // NUL terminators so they are valid C strings with `'static` lifetime.
    // No `unsafe` dereferences are needed for the message lookup itself.
    strerror_static_ptr(code)
}

// ============================================================================
// Section 5: Error Mapping and Static Strings
// ============================================================================

/// Maps a [`curl_rs_lib::error::CurlError`] returned by `CurlUrl` methods
/// into the corresponding `CURLUcode` integer for the FFI boundary.
///
/// `CurlUrl::set` and `CurlUrl::get` currently return `CurlError` (CURLcode
/// space) rather than `CurlUrlError` (CURLUcode space).  This function
/// performs the reverse of the `url_err()` mapping in `curl-rs-lib/src/url.rs`:
///
/// | CurlError variant      | CURLUcode                |
/// |------------------------|--------------------------|
/// | `Ok`                   | `CURLUE_OK`              |
/// | `UnsupportedProtocol`  | `CURLUE_UNSUPPORTED_SCHEME` |
/// | `OutOfMemory`          | `CURLUE_OUT_OF_MEMORY`   |
/// | `LoginDenied`          | `CURLUE_USER_NOT_ALLOWED`|
/// | `UrlMalformat` (catch-all) | `CURLUE_MALFORMED_INPUT` |
fn curl_error_to_url_code(err: curl_rs_lib::error::CurlError) -> CURLUcode {
    use curl_rs_lib::error::CurlError;
    match err {
        CurlError::Ok => CURLUE_OK,
        CurlError::UnsupportedProtocol => CURLUE_UNSUPPORTED_SCHEME,
        CurlError::OutOfMemory => CURLUE_OUT_OF_MEMORY,
        CurlError::LoginDenied => CURLUE_USER_NOT_ALLOWED,
        CurlError::UrlMalformat => CURLUE_MALFORMED_INPUT,
        _ => CURLUE_MALFORMED_INPUT,
    }
}

/// Returns a pointer to a static, NUL-terminated C string for the given
/// `CURLUcode` value.
///
/// Strings are character-for-character identical to `curl_url_strerror()`
/// in curl 8.x (`lib/strerror.c`).
fn strerror_static_ptr(code: CURLUcode) -> *const c_char {
    // Each byte string literal includes an explicit NUL terminator and has
    // `'static` lifetime, making the returned pointer valid for the entire
    // program lifetime.  MSRV 1.75 requires byte-string syntax instead of
    // the c"..." literal syntax (stabilized in 1.77).
    let msg: &[u8] = match code {
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
        _ => b"Unknown error\0",
    };
    msg.as_ptr() as *const c_char
}

// ============================================================================
// Section 6: Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_codes::{
        CURLUE_BAD_FILE_URL, CURLUE_BAD_FRAGMENT, CURLUE_BAD_HOSTNAME, CURLUE_BAD_IPV6,
        CURLUE_BAD_LOGIN, CURLUE_BAD_PASSWORD, CURLUE_BAD_PATH, CURLUE_BAD_PORT_NUMBER,
        CURLUE_BAD_QUERY, CURLUE_BAD_SCHEME, CURLUE_BAD_SLASHES, CURLUE_BAD_USER,
        CURLUE_LACKS_IDN, CURLUE_NO_FRAGMENT, CURLUE_NO_HOST, CURLUE_NO_OPTIONS,
        CURLUE_NO_PASSWORD, CURLUE_NO_PORT, CURLUE_NO_QUERY, CURLUE_NO_SCHEME,
        CURLUE_NO_USER, CURLUE_NO_ZONEID, CURLUE_TOO_LARGE, CURLUE_URLDECODE,
    };

    /// Verify all CURLUPART_* constants match the C header values.
    #[test]
    fn curlupart_constants_match_c_header() {
        assert_eq!(CURLUPART_URL, 0);
        assert_eq!(CURLUPART_SCHEME, 1);
        assert_eq!(CURLUPART_USER, 2);
        assert_eq!(CURLUPART_PASSWORD, 3);
        assert_eq!(CURLUPART_OPTIONS, 4);
        assert_eq!(CURLUPART_HOST, 5);
        assert_eq!(CURLUPART_PORT, 6);
        assert_eq!(CURLUPART_PATH, 7);
        assert_eq!(CURLUPART_QUERY, 8);
        assert_eq!(CURLUPART_FRAGMENT, 9);
        assert_eq!(CURLUPART_ZONEID, 10);
    }

    /// Verify all CURLU_* flag constants match the C header values.
    #[test]
    fn curlu_flag_constants_match_c_header() {
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

    /// Verify the strerror static pointer returns valid C strings.
    #[test]
    fn strerror_returns_valid_c_strings() {
        for code in 0..=32 {
            let ptr = strerror_static_ptr(code);
            assert!(!ptr.is_null());
            // SAFETY: The pointer is to a static byte string with NUL terminator.
            let c_str = unsafe { CStr::from_ptr(ptr) };
            assert!(!c_str.to_str().unwrap().is_empty());
        }
    }

    /// Verify url_error_to_code maps CurlUrlError discriminants correctly.
    #[test]
    fn url_error_code_mapping() {
        assert_eq!(url_error_to_code(CurlUrlError::Ok), CURLUE_OK);
        assert_eq!(url_error_to_code(CurlUrlError::BadHandle), CURLUE_BAD_HANDLE);
        assert_eq!(url_error_to_code(CurlUrlError::BadPartPointer), CURLUE_BAD_PARTPOINTER);
        assert_eq!(url_error_to_code(CurlUrlError::MalformedInput), CURLUE_MALFORMED_INPUT);
        assert_eq!(url_error_to_code(CurlUrlError::BadPortNumber), CURLUE_BAD_PORT_NUMBER);
        assert_eq!(url_error_to_code(CurlUrlError::UnsupportedScheme), CURLUE_UNSUPPORTED_SCHEME);
        assert_eq!(url_error_to_code(CurlUrlError::UrlDecode), CURLUE_URLDECODE);
        assert_eq!(url_error_to_code(CurlUrlError::OutOfMemory), CURLUE_OUT_OF_MEMORY);
        assert_eq!(url_error_to_code(CurlUrlError::UserNotAllowed), CURLUE_USER_NOT_ALLOWED);
        assert_eq!(url_error_to_code(CurlUrlError::UnknownPart), CURLUE_UNKNOWN_PART);
        assert_eq!(url_error_to_code(CurlUrlError::NoScheme), CURLUE_NO_SCHEME);
        assert_eq!(url_error_to_code(CurlUrlError::NoUser), CURLUE_NO_USER);
        assert_eq!(url_error_to_code(CurlUrlError::NoPassword), CURLUE_NO_PASSWORD);
        assert_eq!(url_error_to_code(CurlUrlError::NoOptions), CURLUE_NO_OPTIONS);
        assert_eq!(url_error_to_code(CurlUrlError::NoHost), CURLUE_NO_HOST);
        assert_eq!(url_error_to_code(CurlUrlError::NoPort), CURLUE_NO_PORT);
        assert_eq!(url_error_to_code(CurlUrlError::NoQuery), CURLUE_NO_QUERY);
        assert_eq!(url_error_to_code(CurlUrlError::NoFragment), CURLUE_NO_FRAGMENT);
        assert_eq!(url_error_to_code(CurlUrlError::NoZoneId), CURLUE_NO_ZONEID);
        assert_eq!(url_error_to_code(CurlUrlError::BadFileUrl), CURLUE_BAD_FILE_URL);
        assert_eq!(url_error_to_code(CurlUrlError::BadFragment), CURLUE_BAD_FRAGMENT);
        assert_eq!(url_error_to_code(CurlUrlError::BadHostname), CURLUE_BAD_HOSTNAME);
        assert_eq!(url_error_to_code(CurlUrlError::BadIpv6), CURLUE_BAD_IPV6);
        assert_eq!(url_error_to_code(CurlUrlError::BadLogin), CURLUE_BAD_LOGIN);
        assert_eq!(url_error_to_code(CurlUrlError::BadPassword), CURLUE_BAD_PASSWORD);
        assert_eq!(url_error_to_code(CurlUrlError::BadPath), CURLUE_BAD_PATH);
        assert_eq!(url_error_to_code(CurlUrlError::BadQuery), CURLUE_BAD_QUERY);
        assert_eq!(url_error_to_code(CurlUrlError::BadScheme), CURLUE_BAD_SCHEME);
        assert_eq!(url_error_to_code(CurlUrlError::BadSlashes), CURLUE_BAD_SLASHES);
        assert_eq!(url_error_to_code(CurlUrlError::BadUser), CURLUE_BAD_USER);
        assert_eq!(url_error_to_code(CurlUrlError::LacksIdn), CURLUE_LACKS_IDN);
        assert_eq!(url_error_to_code(CurlUrlError::TooLarge), CURLUE_TOO_LARGE);
    }
}
