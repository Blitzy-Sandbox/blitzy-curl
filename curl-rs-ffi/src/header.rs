//! FFI bindings for the `curl_easy_header` and `curl_easy_nextheader` functions.
//!
//! This module exposes the 2 `CURL_EXTERN` symbols declared in
//! `include/curl/header.h` as `#[no_mangle] pub unsafe extern "C"` functions:
//!
//! - [`curl_easy_header`] — retrieve a specific HTTP response header by name
//!   and index.
//! - [`curl_easy_nextheader`] — iterate through response headers matching an
//!   origin bitmask filter.
//!
//! # Memory Ownership
//!
//! Both functions return pointers to `curl_header` structs that are **owned by
//! the library** — the caller MUST NOT free them.  Each returned struct and its
//! backing name/value C strings live in a heap-allocated [`FFIHeaderAlloc`] that
//! persists for the lifetime of the easy handle (or, in this implementation,
//! for the lifetime of the process).  The `anchor` field is set to null and
//! should not be dereferenced by callers.
//!
//! Internally, each call produces a new allocation via `Box::into_raw`, which
//! keeps the `curl_header` struct, its backing `CString` buffers, and the
//! original Rust [`Header`] alive.  The Rust `Header` is preserved so that
//! `curl_easy_nextheader` can resume iteration by passing it back to
//! [`Headers::next()`].
//!
//! # C Header Reference
//!
//! These functions correspond exactly to the two `CURL_EXTERN` symbols
//! declared in `include/curl/header.h`:
//!
//! ```c
//! CURL_EXTERN CURLHcode curl_easy_header(CURL *easy,
//!                                        const char *name,
//!                                        size_t index,
//!                                        unsigned int origin,
//!                                        int request,
//!                                        struct curl_header **hout);
//!
//! CURL_EXTERN struct curl_header *curl_easy_nextheader(CURL *easy,
//!                                                      unsigned int origin,
//!                                                      int request,
//!                                                      struct curl_header *prev);
//! ```
//!
//! # Safety
//!
//! All `unsafe` blocks in this module are in the `src/ffi/` directory (the
//! `curl-rs-ffi` crate), as mandated by AAP Section 0.7.1.  Every `unsafe`
//! block carries a `// SAFETY:` comment explaining the invariant that makes
//! the operation sound.
//!
//! # ABI Compatibility
//!
//! - Function names, parameter types, and return types match `include/curl/header.h`
//!   exactly (AAP Section 0.7.2).
//! - The `curl_header` struct is `#[repr(C)]` with 6 fields in the exact order
//!   defined by the C header (imported from [`crate::types`]).
//! - All `CURLH_*` and `CURLHE_*` constants match their C integer values exactly
//!   (imported from [`crate::types`] and [`crate::error_codes`]).
//!
//! # Edition and MSRV
//!
//! Rust edition 2021, MSRV 1.75.

use std::ffi::{CStr, CString};
use std::ptr;

use libc::{c_char, c_int, c_uint, c_void, size_t};

use crate::error_codes::{
    CURLHE_BAD_ARGUMENT, CURLHE_BADINDEX, CURLHE_MISSING, CURLHE_NOHEADERS, CURLHE_NOREQUEST,
    CURLHE_NOT_BUILT_IN, CURLHE_OK, CURLHE_OUT_OF_MEMORY,
};
use crate::types::{curl_header, CURLHcode, CURL};

use curl_rs_lib::easy::EasyHandle;
use curl_rs_lib::headers::{CurlHcode, Header, Headers};

// ---------------------------------------------------------------------------
// FFIHeaderAlloc — internal allocation for persisting C-compatible headers
// ---------------------------------------------------------------------------

/// Internal allocation that bundles a C-compatible [`curl_header`] struct with
/// its backing name/value `CString` buffers and the original Rust [`Header`].
///
/// # Layout Guarantee
///
/// The `#[repr(C)]` attribute with `c_header` as the **first** field ensures
/// that the address of an `FFIHeaderAlloc` instance equals the address of its
/// `c_header` field.  This property allows safe round-tripping between
/// `*mut curl_header` and `*mut FFIHeaderAlloc` via pointer casts, which is
/// required by [`curl_easy_nextheader`] to recover the preserved `rust_header`
/// from a previously-returned `curl_header` pointer.
#[repr(C)]
struct FFIHeaderAlloc {
    /// The C-compatible header struct returned to the caller via
    /// `*hout` (for `curl_easy_header`) or as a direct return value
    /// (for `curl_easy_nextheader`).
    c_header: curl_header,

    /// The original Rust [`Header`] object, preserved so that
    /// [`curl_easy_nextheader`] can pass it to [`Headers::next()`] to
    /// resume iteration from the correct position.
    rust_header: Header,

    /// Backing storage for `c_header.name`.  The `c_header.name` pointer
    /// points into this `CString`'s heap buffer.  Dropping this field would
    /// invalidate `c_header.name`, so it lives as long as the allocation.
    _name_cstr: CString,

    /// Backing storage for `c_header.value`.  Same lifetime semantics as
    /// `_name_cstr` above.
    _value_cstr: CString,
}

// ---------------------------------------------------------------------------
// Helper: convert Rust Header to leaked FFI allocation
// ---------------------------------------------------------------------------

/// Converts a Rust [`Header`] into a heap-allocated [`FFIHeaderAlloc`] and
/// returns a raw pointer to the embedded `curl_header`.
///
/// The allocation is intentionally leaked via [`Box::into_raw`].  It remains
/// valid for the lifetime of the process.  The caller receives a pointer to
/// the `c_header` field, which is ABI-compatible with `struct curl_header *`
/// in C.
///
/// # Panics
///
/// Does not panic.  If `header.name()` or `header.value()` contains an
/// interior NUL byte (which is illegal in HTTP headers), the corresponding
/// `CString` will be replaced with an empty string.
fn header_to_ffi(header: Header) -> *mut curl_header {
    // Create NUL-terminated C strings from the Rust header data.
    // HTTP header names and values must not contain NUL bytes, so
    // `CString::new` should always succeed.  As a safety net, we fall
    // back to an empty CString if the input is somehow invalid.
    let name_cstr = CString::new(header.name()).unwrap_or_default();
    let value_cstr = CString::new(header.value()).unwrap_or_default();

    // Capture raw pointers BEFORE moving the CStrings into the Box.
    //
    // This is safe because `CString` allocates its buffer on the heap.
    // Moving a `CString` transfers ownership of the heap allocation
    // without changing the buffer's address — only the stack-resident
    // (pointer, length, capacity) triple is bitwise-copied.  Therefore
    // `name_ptr` and `value_ptr` remain valid after the move.
    let name_ptr = name_cstr.as_ptr() as *mut c_char;
    let value_ptr = value_cstr.as_ptr() as *mut c_char;

    // Populate the C struct fields from the Rust Header's public accessors.
    let amount: size_t = header.amount();
    let index: size_t = header.index();
    let origin: c_uint = header.origin().as_u32();

    let alloc = Box::new(FFIHeaderAlloc {
        c_header: curl_header {
            name: name_ptr,
            value: value_ptr,
            amount,
            index,
            origin,
            // The `anchor` field is described as "handle privately used by
            // libcurl" in the C header.  Callers must not dereference it.
            // We set it to null; iteration state is preserved in
            // `rust_header` instead.
            anchor: ptr::null_mut::<c_void>(),
        },
        rust_header: header,
        _name_cstr: name_cstr,
        _value_cstr: value_cstr,
    });

    // Leak the allocation so that the returned pointer remains valid.
    let alloc_ptr = Box::into_raw(alloc);

    // SAFETY: `c_header` is the first field of the `#[repr(C)]` struct
    // `FFIHeaderAlloc`, so its address equals `alloc_ptr`.  The pointer
    // is non-null because `Box::into_raw` always returns non-null for
    // non-ZST allocations.
    unsafe { &mut (*alloc_ptr).c_header as *mut curl_header }
}

// ---------------------------------------------------------------------------
// Helper: map Rust CurlHcode enum to FFI CURLHcode integer
// ---------------------------------------------------------------------------

/// Maps a Rust [`CurlHcode`] enum variant to the corresponding FFI
/// `CURLHcode` integer constant.
///
/// Each arm explicitly maps to the imported `CURLHE_*` constant, ensuring
/// that all eight error codes from [`crate::error_codes`] are referenced
/// and verifiable.
///
/// | Rust variant              | C constant             | Value |
/// |---------------------------|------------------------|-------|
/// | `CurlHcode::Ok`          | `CURLHE_OK`            |   0   |
/// | `CurlHcode::BadIndex`    | `CURLHE_BADINDEX`      |   1   |
/// | `CurlHcode::Missing`     | `CURLHE_MISSING`       |   2   |
/// | `CurlHcode::NoHeaders`   | `CURLHE_NOHEADERS`     |   3   |
/// | `CurlHcode::NoRequest`   | `CURLHE_NOREQUEST`     |   4   |
/// | `CurlHcode::OutOfMemory` | `CURLHE_OUT_OF_MEMORY` |   5   |
/// | `CurlHcode::BadArgument` | `CURLHE_BAD_ARGUMENT`  |   6   |
/// | `CurlHcode::NotBuiltIn`  | `CURLHE_NOT_BUILT_IN`  |   7   |
#[inline]
fn curlhcode_to_ffi(code: CurlHcode) -> CURLHcode {
    match code {
        CurlHcode::Ok => CURLHE_OK,
        CurlHcode::BadIndex => CURLHE_BADINDEX,
        CurlHcode::Missing => CURLHE_MISSING,
        CurlHcode::NoHeaders => CURLHE_NOHEADERS,
        CurlHcode::NoRequest => CURLHE_NOREQUEST,
        CurlHcode::OutOfMemory => CURLHE_OUT_OF_MEMORY,
        CurlHcode::BadArgument => CURLHE_BAD_ARGUMENT,
        CurlHcode::NotBuiltIn => CURLHE_NOT_BUILT_IN,
    }
}

// ===========================================================================
// Public FFI Functions (2 CURL_EXTERN symbols)
// ===========================================================================

/// Retrieve a specific HTTP response header by name and index.
///
/// This is the Rust FFI implementation of the C function
/// `curl_easy_header()` declared in `include/curl/header.h`.
///
/// # Parameters
///
/// - `easy`: Opaque easy handle (`*mut CURL`) previously returned by
///   `curl_easy_init()`.  Must not be `NULL`.
/// - `name`: NUL-terminated C string containing the header field name
///   to look up.  Comparison is case-insensitive.  Must not be `NULL`.
/// - `index`: Zero-based index among headers sharing the same name
///   within the filtered result set (by origin and request).
/// - `origin`: Bitmask of `CURLH_*` constants (`CURLH_HEADER`,
///   `CURLH_TRAILER`, `CURLH_CONNECT`, `CURLH_1XX`, `CURLH_PSEUDO`)
///   selecting which header origins to search.  Must be non-zero.
/// - `request`: Request number in the redirect chain.  `0` selects the
///   most recent (last) request, `-1` selects the first request.
///   Values `> 0` select specific intermediate requests.
/// - `hout`: Output pointer.  On success, `*hout` is set to point to a
///   `curl_header` struct owned by the library.  The caller MUST NOT
///   free the returned pointer.
///
/// # Returns
///
/// - `CURLHE_OK` (0) on success — `*hout` points to a valid `curl_header`.
/// - `CURLHE_BAD_ARGUMENT` (6) if `easy`, `name`, or `hout` is `NULL`,
///   or if `origin` is zero or out of range.
/// - `CURLHE_NOHEADERS` (3) if no response headers have been recorded yet.
/// - `CURLHE_NOREQUEST` (4) if the specified request number has not been
///   reached (e.g., fewer redirects occurred than `request`).
/// - `CURLHE_MISSING` (2) if no header with the given name matches the
///   origin and request filters.
/// - `CURLHE_BADINDEX` (1) if `index` is ≥ the number of matching headers.
///
/// # Safety
///
/// - `easy` must be a valid, non-null pointer returned by `curl_easy_init()`
///   that has not yet been cleaned up via `curl_easy_cleanup()`.
/// - `name` must be a valid, non-null pointer to a NUL-terminated C string.
/// - `hout` must be a valid, non-null, writable pointer to `*mut curl_header`.
/// - No other thread may concurrently modify the easy handle.
///
/// # C Equivalent
///
/// ```c
/// CURL_EXTERN CURLHcode curl_easy_header(CURL *easy,
///                                        const char *name,
///                                        size_t index,
///                                        unsigned int origin,
///                                        int request,
///                                        struct curl_header **hout);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_easy_header(
    easy: *mut CURL,
    name: *const c_char,
    index: size_t,
    origin: c_uint,
    request: c_int,
    hout: *mut *mut curl_header,
) -> CURLHcode {
    // -----------------------------------------------------------------------
    // Argument validation — return CURLHE_BAD_ARGUMENT for null pointers.
    // -----------------------------------------------------------------------

    // SAFETY: We check for null before any dereference.  Null is a valid
    // sentinel value in the C calling convention; returning an error code
    // rather than dereferencing null prevents undefined behaviour.
    if easy.is_null() || name.is_null() || hout.is_null() {
        return CURLHE_BAD_ARGUMENT;
    }

    // -----------------------------------------------------------------------
    // Convert the opaque CURL pointer to a Rust EasyHandle reference.
    // -----------------------------------------------------------------------

    // SAFETY: The `easy` pointer was originally created by `curl_easy_init()`,
    // which allocates an `EasyHandle` on the heap via `Box::new(EasyHandle)`
    // and returns the result of `Box::into_raw(...)` cast to `*mut CURL`.
    // The caller guarantees (per the C API contract) that:
    //   1. The pointer is non-null (checked above).
    //   2. It was returned by `curl_easy_init()` and has not been cleaned up.
    //   3. No other thread is concurrently modifying the handle.
    // Therefore dereferencing as `&EasyHandle` is sound.
    let handle: &EasyHandle = &*(easy as *const EasyHandle);

    // -----------------------------------------------------------------------
    // Convert the C name string to a Rust &str.
    // -----------------------------------------------------------------------

    // SAFETY: `name` is non-null (checked above) and is guaranteed to be a
    // valid, NUL-terminated C string per the API contract.  `CStr::from_ptr`
    // reads bytes until it finds the NUL terminator.
    let name_cstr = CStr::from_ptr(name);
    let name_str = match name_cstr.to_str() {
        Ok(s) => s,
        // The header name contains non-UTF-8 bytes.  While HTTP header
        // names are ASCII, we treat this as a bad argument rather than
        // panicking.
        Err(_) => return CURLHE_BAD_ARGUMENT,
    };

    // -----------------------------------------------------------------------
    // Delegate to the Rust Headers::get() implementation.
    // -----------------------------------------------------------------------

    let headers: &Headers = handle.response_headers();

    match headers.get(name_str, index, origin, request) {
        Ok(header) => {
            // Convert the Rust Header to a C curl_header on the heap.
            let c_hdr_ptr: *mut curl_header = header_to_ffi(header);

            // SAFETY: `hout` is non-null (checked above) and points to a
            // writable `*mut curl_header` per the C API contract.  We write
            // the newly-allocated curl_header pointer through it.
            *hout = c_hdr_ptr;
            CURLHE_OK
        }
        Err(code) => {
            // Map the Rust error code to the corresponding C integer.
            // Do NOT modify *hout on error — match C curl 8.x behaviour.
            curlhcode_to_ffi(code)
        }
    }
}

/// Iterate through HTTP response headers matching an origin filter.
///
/// This is the Rust FFI implementation of the C function
/// `curl_easy_nextheader()` declared in `include/curl/header.h`.
///
/// # Parameters
///
/// - `easy`: Opaque easy handle (`*mut CURL`) previously returned by
///   `curl_easy_init()`.  Must not be `NULL`.
/// - `origin`: Bitmask of `CURLH_*` constants selecting which header
///   origins to include in iteration.  Must be non-zero.
/// - `request`: Request number in the redirect chain.  `0` selects the
///   most recent (last) request, `-1` selects the first request.
/// - `prev`: Pointer to the `curl_header` returned by the previous call
///   to this function (or to [`curl_easy_header`]).  Pass `NULL` to start
///   iteration from the first matching header.
///
/// # Returns
///
/// - A non-null `*mut curl_header` pointing to the next header matching
///   the filters, or `NULL` if no more headers match.  The returned struct
///   is owned by the library — the caller MUST NOT free it.
///
/// # Safety
///
/// - `easy` must be a valid, non-null pointer returned by `curl_easy_init()`.
/// - `prev` must be `NULL` or a pointer previously returned by
///   `curl_easy_header` or `curl_easy_nextheader` for the **same** easy
///   handle.  Passing a pointer from a different handle is undefined
///   behaviour.
/// - No other thread may concurrently modify the easy handle.
///
/// # C Equivalent
///
/// ```c
/// CURL_EXTERN struct curl_header *curl_easy_nextheader(CURL *easy,
///                                                      unsigned int origin,
///                                                      int request,
///                                                      struct curl_header *prev);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_easy_nextheader(
    easy: *mut CURL,
    origin: c_uint,
    request: c_int,
    prev: *mut curl_header,
) -> *mut curl_header {
    // -----------------------------------------------------------------------
    // Argument validation — return NULL for invalid arguments.
    // -----------------------------------------------------------------------

    // SAFETY: A null easy handle violates the API contract.  We return NULL
    // (no more headers) rather than dereferencing null.
    if easy.is_null() {
        return ptr::null_mut();
    }

    // -----------------------------------------------------------------------
    // Convert the opaque CURL pointer to a Rust EasyHandle reference.
    // -----------------------------------------------------------------------

    // SAFETY: Same rationale as `curl_easy_header` above — the `easy`
    // pointer was created by `curl_easy_init()` via `Box::into_raw` of
    // an `EasyHandle`.  The caller guarantees it is valid and unshared.
    let handle: &EasyHandle = &*(easy as *const EasyHandle);
    let headers: &Headers = handle.response_headers();

    // -----------------------------------------------------------------------
    // Recover the previous Rust Header for iteration, if applicable.
    // -----------------------------------------------------------------------

    let prev_rust_header: Option<&Header> = if prev.is_null() {
        // Start from the beginning — no previous header.
        None
    } else {
        // SAFETY: The `prev` pointer was returned by a prior call to
        // `curl_easy_header` or `curl_easy_nextheader`, both of which
        // produce pointers via `header_to_ffi()`.  That function allocates
        // an `FFIHeaderAlloc` with `#[repr(C)]` layout where `c_header` is
        // the **first** field.  Therefore the address of the `FFIHeaderAlloc`
        // equals the address of its `c_header` field, and casting `prev`
        // (a `*mut curl_header`) to `*const FFIHeaderAlloc` is sound.
        //
        // The allocation was produced by `Box::into_raw` and has not been
        // deallocated (the library owns it), so the pointer is still valid.
        let alloc: &FFIHeaderAlloc = &*(prev as *const FFIHeaderAlloc);
        Some(&alloc.rust_header)
    };

    // -----------------------------------------------------------------------
    // Delegate to the Rust Headers::next() implementation.
    // -----------------------------------------------------------------------

    match headers.next(origin, request, prev_rust_header) {
        Some(header) => header_to_ffi(header),
        None => ptr::null_mut(),
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the `curlhcode_to_ffi` helper produces the correct
    /// integer values for all `CurlHcode` variants.
    #[test]
    fn test_curlhcode_mapping() {
        assert_eq!(curlhcode_to_ffi(CurlHcode::Ok), CURLHE_OK);
        assert_eq!(curlhcode_to_ffi(CurlHcode::BadIndex), CURLHE_BADINDEX);
        assert_eq!(curlhcode_to_ffi(CurlHcode::Missing), CURLHE_MISSING);
        assert_eq!(curlhcode_to_ffi(CurlHcode::NoHeaders), CURLHE_NOHEADERS);
        assert_eq!(curlhcode_to_ffi(CurlHcode::NoRequest), CURLHE_NOREQUEST);
        assert_eq!(
            curlhcode_to_ffi(CurlHcode::OutOfMemory),
            CURLHE_OUT_OF_MEMORY
        );
        assert_eq!(
            curlhcode_to_ffi(CurlHcode::BadArgument),
            CURLHE_BAD_ARGUMENT
        );
        assert_eq!(
            curlhcode_to_ffi(CurlHcode::NotBuiltIn),
            CURLHE_NOT_BUILT_IN
        );
    }

    /// Verify that `curl_easy_header` returns `CURLHE_BAD_ARGUMENT` when
    /// the easy handle pointer is null.
    #[test]
    fn test_curl_easy_header_null_easy() {
        unsafe {
            let mut hout: *mut curl_header = ptr::null_mut();
            let name = b"Content-Type\0".as_ptr() as *const c_char;
            let result = curl_easy_header(
                ptr::null_mut(), // null easy handle
                name,
                0,
                1, // CURLH_HEADER
                0,
                &mut hout,
            );
            assert_eq!(result, CURLHE_BAD_ARGUMENT);
            assert!(hout.is_null());
        }
    }

    /// Verify that `curl_easy_header` returns `CURLHE_BAD_ARGUMENT` when
    /// the name pointer is null.
    #[test]
    fn test_curl_easy_header_null_name() {
        unsafe {
            let mut hout: *mut curl_header = ptr::null_mut();
            // We use a dummy non-null pointer for `easy` — the function
            // should check `name` before dereferencing `easy`.
            let fake_easy = 0x1000usize as *mut CURL;
            let result = curl_easy_header(
                fake_easy,
                ptr::null(), // null name
                0,
                1,
                0,
                &mut hout,
            );
            assert_eq!(result, CURLHE_BAD_ARGUMENT);
        }
    }

    /// Verify that `curl_easy_header` returns `CURLHE_BAD_ARGUMENT` when
    /// the output pointer is null.
    #[test]
    fn test_curl_easy_header_null_hout() {
        unsafe {
            let fake_easy = 0x1000usize as *mut CURL;
            let name = b"Content-Type\0".as_ptr() as *const c_char;
            let result = curl_easy_header(
                fake_easy,
                name,
                0,
                1,
                0,
                ptr::null_mut(), // null hout
            );
            assert_eq!(result, CURLHE_BAD_ARGUMENT);
        }
    }

    /// Verify that `curl_easy_nextheader` returns NULL when the easy
    /// handle pointer is null.
    #[test]
    fn test_curl_easy_nextheader_null_easy() {
        unsafe {
            let result = curl_easy_nextheader(
                ptr::null_mut(), // null easy handle
                1,               // CURLH_HEADER
                0,
                ptr::null_mut(), // start from beginning
            );
            assert!(result.is_null());
        }
    }

    /// Verify that the `curlhcode_to_ffi` mapping agrees with the
    /// `CurlHcode::as_i32()` discriminant for all variants (cross-check).
    #[test]
    fn test_curlhcode_cross_check() {
        // Ensure the explicit match arms in curlhcode_to_ffi agree with
        // the enum discriminant from as_i32().
        let variants = [
            CurlHcode::Ok,
            CurlHcode::BadIndex,
            CurlHcode::Missing,
            CurlHcode::NoHeaders,
            CurlHcode::NoRequest,
            CurlHcode::OutOfMemory,
            CurlHcode::BadArgument,
            CurlHcode::NotBuiltIn,
        ];
        for variant in &variants {
            assert_eq!(
                curlhcode_to_ffi(*variant),
                variant.as_i32(),
                "curlhcode_to_ffi mismatch for {:?}",
                variant
            );
        }
    }
}
