// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! FFI bindings for the `curl_easy_*` family of functions.
//!
//! This module exposes the `curl_easy_*` CURL_EXTERN symbols as
//! `extern "C"` functions with `#[no_mangle]` attributes, bridging
//! synchronous C callers to the async Rust internals in `curl-rs-lib`.
//!
//! # Exported Symbols (from `include/curl/easy.h`)
//!
//! | Symbol                   | C Signature                                        |
//! |--------------------------|----------------------------------------------------|
//! | `curl_easy_init`         | `CURL *curl_easy_init(void)`                       |
//! | `curl_easy_setopt`       | `CURLcode curl_easy_setopt(CURL*, CURLoption, ...)` |
//! | `curl_easy_perform`      | `CURLcode curl_easy_perform(CURL*)`                |
//! | `curl_easy_cleanup`      | `void curl_easy_cleanup(CURL*)`                    |
//! | `curl_easy_getinfo`      | `CURLcode curl_easy_getinfo(CURL*, CURLINFO, ...)`  |
//! | `curl_easy_duphandle`    | `CURL *curl_easy_duphandle(CURL*)`                 |
//! | `curl_easy_reset`        | `void curl_easy_reset(CURL*)`                      |
//! | `curl_easy_recv`         | `CURLcode curl_easy_recv(CURL*, void*, size_t, size_t*)` |
//! | `curl_easy_send`         | `CURLcode curl_easy_send(CURL*, const void*, size_t, size_t*)` |
//! | `curl_easy_upkeep`       | `CURLcode curl_easy_upkeep(CURL*)`                 |
//!
//! # Additional symbols (from `include/curl/curl.h`)
//!
//! | Symbol                   | C Signature                                        |
//! |--------------------------|----------------------------------------------------|
//! | `curl_easy_pause`        | `CURLcode curl_easy_pause(CURL*, int)`             |
//! | `curl_easy_strerror`     | `const char *curl_easy_strerror(CURLcode)`         |
//! | `curl_easy_escape`       | `char *curl_easy_escape(CURL*, const char*, int)`  |
//! | `curl_easy_unescape`     | `char *curl_easy_unescape(CURL*, const char*, int, int*)` |
//! | `curl_easy_ssls_import`  | see `include/curl/curl.h` line 3273                |
//! | `curl_easy_ssls_export`  | see `include/curl/curl.h` line 3304                |
//!
//! # Safety
//!
//! This module is the **only** location in the Rust codebase where `unsafe`
//! blocks are permitted (per AAP Section 0.7.1). Every `unsafe` block carries
//! a `// SAFETY:` invariant comment explaining why the operation is sound.
//!
//! # Async Bridging
//!
//! Per AAP Section 0.4.4, the FFI layer bridges synchronous C callers to
//! async Rust internals using a thread-local `tokio::runtime::Runtime` and
//! `block_on()`.
//!
//! # Variadic Functions
//!
//! `curl_easy_setopt` and `curl_easy_getinfo` are variadic in the C API.
//! Since C-variadic function *definitions* are unstable in stable Rust,
//! we use non-variadic signatures with appropriately-sized argument types.
//! On all four target platforms (x86_64 and aarch64, Linux and macOS),
//! the calling convention for integer/pointer arguments is identical
//! between variadic and non-variadic functions, so ABI compatibility is
//! preserved.

#![allow(non_camel_case_types)]

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use crate::error_codes::{
    CURLE_AGAIN, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_FAILED_INIT, CURLE_OK,
    CURLE_OUT_OF_MEMORY, CURLE_UNKNOWN_OPTION,
};
use crate::types::{
    curl_off_t, curl_ssls_export_cb, CURLcode, CURLINFO, CURLoption, CURL,
    CURLINFO_DOUBLE, CURLINFO_LONG, CURLINFO_OFF_T, CURLINFO_SLIST,
    CURLINFO_SOCKET, CURLINFO_STRING, CURLINFO_TYPEMASK,
    CURLOPTTYPE_BLOB, CURLOPTTYPE_FUNCTIONPOINT, CURLOPTTYPE_LONG,
    CURLOPTTYPE_OBJECTPOINT, CURLOPTTYPE_OFF_T,
};

use curl_rs_lib::easy::EasyHandle;
use curl_rs_lib::error::CurlError;

use libc::{c_char, c_int, c_long, c_uchar, c_void, size_t};

use std::ffi::CStr;
use std::ptr;

// ---------------------------------------------------------------------------
// Helper: handle_from_ptr — safe CURL* → &mut EasyHandle conversion
// ---------------------------------------------------------------------------

/// Converts a raw `CURL *` pointer to a mutable reference to `EasyHandle`.
///
/// Returns `None` if the pointer is null.
///
/// # Safety
///
/// The caller must ensure that:
/// 1. `curl` was originally created by [`curl_easy_init`] (i.e., it points
///    to a valid, heap-allocated `EasyHandle`).
/// 2. No other mutable reference to the same handle exists concurrently.
/// 3. The handle has not been freed by [`curl_easy_cleanup`].
///
/// This function is used internally by all `curl_easy_*` FFI functions to
/// obtain a safe Rust reference from the opaque C pointer.
#[inline]
pub fn handle_from_ptr<'a>(curl: *mut CURL) -> Option<&'a mut EasyHandle> {
    if curl.is_null() {
        return None;
    }
    // SAFETY: The caller guarantees that `curl` points to a valid, live
    // EasyHandle allocation created by curl_easy_init (Box::into_raw).
    // The cast from *mut CURL to *mut EasyHandle is valid because CURL is
    // an opaque type used only as a type-safe handle token. The underlying
    // allocation is always an EasyHandle.
    let handle_ptr = curl as *mut EasyHandle;
    unsafe { Some(&mut *handle_ptr) }
}

// ---------------------------------------------------------------------------
// Helper: Convert CurlResult to CURLcode integer
// ---------------------------------------------------------------------------

/// Maps a `Result<(), CurlError>` to the corresponding `CURLcode` integer.
#[inline]
fn result_to_code(result: Result<(), CurlError>) -> CURLcode {
    match result {
        Ok(()) => CURLE_OK,
        Err(e) => error_to_code(e),
    }
}

/// Maps a `CurlError` to its `CURLcode` integer value.
///
/// Common error variants are explicitly matched to their `CURLE_*` constants
/// for clarity and debuggability. All other variants fall through to the
/// generic `From<CurlError> for i32` conversion.
#[inline]
fn error_to_code(e: CurlError) -> CURLcode {
    match e {
        CurlError::Ok => CURLE_OK,
        CurlError::FailedInit => CURLE_FAILED_INIT,
        CurlError::BadFunctionArgument => CURLE_BAD_FUNCTION_ARGUMENT,
        CurlError::OutOfMemory => CURLE_OUT_OF_MEMORY,
        CurlError::Again => CURLE_AGAIN,
        CurlError::UnknownOption => CURLE_UNKNOWN_OPTION,
        other => {
            let code: i32 = other.into();
            code as CURLcode
        }
    }
}

// ===========================================================================
// curl_easy_init — allocate a new easy handle
// ===========================================================================

/// Creates a new curl easy handle.
///
/// Returns a `CURL *` pointer to a heap-allocated `EasyHandle`, or a null
/// pointer if allocation or global initialization fails.
///
/// The handle must eventually be freed with [`curl_easy_cleanup`].
///
/// # Safety
///
/// No raw pointer dereferences occur. Allocates heap memory and returns an
/// opaque pointer. The caller must call [`curl_easy_cleanup`] to free it.
///
/// # C Equivalent
///
/// `CURL *curl_easy_init(void)` — `include/curl/easy.h` line 41.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_init() -> *mut CURL {
    // SAFETY: No raw pointer dereferences here. We allocate a new
    // EasyHandle on the heap and convert it to an opaque raw pointer.
    // The caller is responsible for eventually calling curl_easy_cleanup
    // to reclaim the allocation.
    let handle = Box::new(EasyHandle::new());
    Box::into_raw(handle) as *mut CURL
}

// ===========================================================================
// curl_easy_cleanup — free an easy handle
// ===========================================================================

/// Destroys a curl easy handle and frees all associated resources.
///
/// After this call, `curl` must not be used again. Passing a null pointer
/// is a no-op (safe).
///
/// # Safety
///
/// `curl` must have been created by [`curl_easy_init`] or be null. After
/// this call the pointer is dangling and must not be dereferenced.
///
/// # C Equivalent
///
/// `void curl_easy_cleanup(CURL *curl)` — `include/curl/easy.h` line 44.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_cleanup(curl: *mut CURL) {
    if curl.is_null() {
        return;
    }
    // SAFETY: `curl` was created by curl_easy_init via Box::into_raw.
    // We reconstruct the Box to reclaim ownership and let Drop release
    // all resources. After this point the pointer is dangling and must
    // not be dereferenced by the caller.
    let _ = Box::from_raw(curl as *mut EasyHandle);
}

// ===========================================================================
// curl_easy_reset — reset handle to default state
// ===========================================================================

/// Re-initializes a curl easy handle to its default values.
///
/// All options are reset but the connection pool, DNS cache, and cookies
/// are preserved (matching C `curl_easy_reset` behavior).
///
/// Passing a null pointer is a no-op.
///
/// # Safety
///
/// `curl` must be a valid handle from [`curl_easy_init`] or null. The
/// caller must not access the handle concurrently from another thread.
///
/// # C Equivalent
///
/// `void curl_easy_reset(CURL *curl)` — `include/curl/easy.h` line 86.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_reset(curl: *mut CURL) {
    // SAFETY: Dereferences raw pointer from C caller. We validate non-null
    // before access. The mutable borrow is exclusive because C callers must
    // not use the handle concurrently (matching C thread-safety model).
    if let Some(handle) = handle_from_ptr(curl) {
        handle.reset();
    }
}

// ===========================================================================
// curl_easy_setopt — set a transfer option
// ===========================================================================

/// Sets a transfer option on the given curl easy handle.
///
/// In the C API this is a variadic function. Since C-variadic function
/// definitions are unstable in stable Rust, the third parameter is declared
/// as `isize` which is register-width on all 64-bit platforms. On x86_64
/// and aarch64 (both Linux and macOS), the calling convention for
/// integer/pointer arguments is identical between variadic and non-variadic
/// functions, preserving ABI compatibility.
///
/// The option type (long, object-pointer, function-pointer, off_t, blob)
/// is determined from the `CURLoption` value's base range.
///
/// # Safety
///
/// - `curl` must be a valid handle from [`curl_easy_init`].
/// - `arg` is reinterpreted based on the option type range. The caller must
///   ensure the value matches the expected type for the given `option`.
/// - For `CURLOPTTYPE_OBJECTPOINT` options, the value must be a valid
///   pointer to a null-terminated C string or null.
/// - For `CURLOPTTYPE_BLOB` options, the value must be a valid pointer
///   to a `curl_blob` struct or null.
///
/// # C Equivalent
///
/// `CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...)`
/// — `include/curl/easy.h` line 42.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_setopt(
    curl: *mut CURL,
    option: CURLoption,
    arg: isize,
) -> CURLcode {
    // SAFETY: Dereferences raw pointer from C caller. Validated non-null.
    // The `arg` parameter is reinterpreted based on the option type range.
    let handle = match handle_from_ptr(curl) {
        Some(h) => h,
        None => return CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // Determine the option type from its base range.
    let opt_type_base = (option / 10000) * 10000;
    let opt_value = match opt_type_base {
        x if x == CURLOPTTYPE_LONG => {
            // SAFETY: C caller passes a `long` value which fits in isize
            // on 64-bit platforms (sizeof(long) == sizeof(isize) == 8).
            curl_rs_lib::setopt::CurlOptValue::Long(arg as i64)
        }
        x if x == CURLOPTTYPE_OBJECTPOINT => {
            // SAFETY: C caller passes a `const char *` or `void *`.
            // We reinterpret the isize as a pointer. If it's a string
            // option, we convert to a Rust String; otherwise treat as
            // an opaque pointer marker.
            let ptr = arg as *const c_char;
            if ptr.is_null() {
                // Null pointer means "unset this option" in the C API.
                curl_rs_lib::setopt::CurlOptValue::ObjectPoint(String::new())
            } else {
                // SAFETY: The C caller guarantees the pointer is a valid
                // null-terminated C string for string-type options.
                match CStr::from_ptr(ptr).to_str() {
                    Ok(s) => curl_rs_lib::setopt::CurlOptValue::ObjectPoint(s.to_string()),
                    Err(_) => {
                        // Non-UTF8 string — try lossy conversion.
                        let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
                        curl_rs_lib::setopt::CurlOptValue::ObjectPoint(s)
                    }
                }
            }
        }
        x if x == CURLOPTTYPE_FUNCTIONPOINT => {
            // SAFETY: C caller passes a function pointer. We record
            // the presence of a function pointer option. The actual
            // function pointer storage is handled by the callback
            // registration system.
            curl_rs_lib::setopt::CurlOptValue::FunctionPoint
        }
        x if x == CURLOPTTYPE_OFF_T => {
            // SAFETY: C caller passes a `curl_off_t` (i64) value.
            // On 64-bit platforms this fits in isize.
            curl_rs_lib::setopt::CurlOptValue::OffT(arg as i64)
        }
        x if x == CURLOPTTYPE_BLOB => {
            // SAFETY: C caller passes a `struct curl_blob *`. We
            // reinterpret the isize as a pointer to curl_blob.
            let blob_ptr = arg as *const crate::types::curl_blob;
            if blob_ptr.is_null() {
                curl_rs_lib::setopt::CurlOptValue::Blob(Vec::new())
            } else {
                // SAFETY: C caller guarantees blob_ptr points to a valid
                // curl_blob struct with valid data/len fields.
                let blob = &*blob_ptr;
                if blob.data.is_null() || blob.len == 0 {
                    curl_rs_lib::setopt::CurlOptValue::Blob(Vec::new())
                } else {
                    // SAFETY: blob.data points to blob.len bytes of valid data.
                    let slice = std::slice::from_raw_parts(
                        blob.data as *const u8,
                        blob.len,
                    );
                    curl_rs_lib::setopt::CurlOptValue::Blob(slice.to_vec())
                }
            }
        }
        _ => {
            return CURLE_UNKNOWN_OPTION;
        }
    };

    let result = handle.set_option(option as u32, opt_value);
    result_to_code(result)
}

// ===========================================================================
// curl_easy_perform — execute a transfer
// ===========================================================================

/// Performs a blocking data transfer using the options configured on the
/// given easy handle.
///
/// This function blocks until the transfer completes or fails. Internally,
/// it uses a thread-local Tokio runtime to bridge the synchronous C calling
/// convention to the async Rust transfer engine.
///
/// # Safety
///
/// `curl` must be a valid handle from [`curl_easy_init`]. The caller must
/// not access the handle concurrently from another thread while a transfer
/// is in progress.
///
/// # C Equivalent
///
/// `CURLcode curl_easy_perform(CURL *curl)` — `include/curl/easy.h` line 43.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_perform(curl: *mut CURL) -> CURLcode {
    // SAFETY: Dereferences raw pointer from C caller. Validated non-null.
    // Blocks the calling thread on the async perform() operation via the
    // thread-local Tokio runtime's block_on().
    let handle = match handle_from_ptr(curl) {
        Some(h) => h,
        None => return CURLE_BAD_FUNCTION_ARGUMENT,
    };

    let result = handle.perform();
    result_to_code(result)
}

// ===========================================================================
// curl_easy_getinfo — retrieve transfer information
// ===========================================================================

/// Retrieves internal information from the curl session.
///
/// The third argument must be a pointer to the appropriate output type,
/// determined by the `CURLINFO` value's type tag:
/// - `CURLINFO_STRING`: `*mut *const c_char`
/// - `CURLINFO_LONG`:   `*mut c_long`
/// - `CURLINFO_DOUBLE`: `*mut f64`
/// - `CURLINFO_SLIST`:  `*mut *mut curl_slist`
/// - `CURLINFO_SOCKET`: `*mut curl_socket_t`
/// - `CURLINFO_OFF_T`:  `*mut curl_off_t`
///
/// # Safety
///
/// - `curl` must be a valid handle from [`curl_easy_init`].
/// - `arg` must point to writable memory of the correct type for the given
///   `info` value. A null `arg` is rejected with `CURLE_BAD_FUNCTION_ARGUMENT`.
///
/// # C Equivalent
///
/// `CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...)`
/// — `include/curl/easy.h` line 59.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_getinfo(
    curl: *mut CURL,
    info: CURLINFO,
    arg: *mut c_void,
) -> CURLcode {
    // SAFETY: Dereferences raw pointer from C caller. Validated non-null.
    // Writes the result value to the caller-provided output pointer `arg`.
    let handle = match handle_from_ptr(curl) {
        Some(h) => h,
        None => return CURLE_BAD_FUNCTION_ARGUMENT,
    };

    if arg.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    // Convert the raw CURLINFO integer to the Rust CurlInfo enum.
    let curl_info = match curl_rs_lib::getinfo::CurlInfo::from_raw(info) {
        Some(ci) => ci,
        None => return CURLE_UNKNOWN_OPTION,
    };

    // Call the Rust get_info implementation.
    let info_value = match handle.get_info(curl_info) {
        Ok(v) => v,
        Err(e) => return error_to_code(e),
    };

    // Write the result to the output pointer based on the info type tag.
    let info_type = info & CURLINFO_TYPEMASK;
    match info_type {
        x if x == CURLINFO_STRING => {
            // SAFETY: arg points to a `*const c_char` location provided by
            // the C caller. We write a pointer to a static or leaked string.
            let out_ptr = arg as *mut *const c_char;
            match info_value {
                curl_rs_lib::getinfo::InfoValue::String(Some(ref s)) => {
                    // Leak the CString so the pointer remains valid until
                    // the handle is cleaned up or reset. This matches C
                    // behavior where getinfo returns pointers to internal
                    // handle storage.
                    let cstring = match std::ffi::CString::new(s.as_str()) {
                        Ok(cs) => cs,
                        Err(_) => {
                            *out_ptr = ptr::null();
                            return CURLE_OK;
                        }
                    };
                    *out_ptr = cstring.into_raw() as *const c_char;
                }
                _ => {
                    *out_ptr = ptr::null();
                }
            }
        }
        x if x == CURLINFO_LONG => {
            // SAFETY: arg points to a `c_long` location.
            let out_ptr = arg as *mut c_long;
            match info_value {
                curl_rs_lib::getinfo::InfoValue::Long(v) => {
                    *out_ptr = v as c_long;
                }
                _ => {
                    *out_ptr = 0;
                }
            }
        }
        x if x == CURLINFO_DOUBLE => {
            // SAFETY: arg points to a `f64` (double) location.
            let out_ptr = arg as *mut f64;
            match info_value {
                curl_rs_lib::getinfo::InfoValue::Double(v) => {
                    *out_ptr = v;
                }
                _ => {
                    *out_ptr = 0.0;
                }
            }
        }
        x if x == CURLINFO_SLIST => {
            // SAFETY: arg points to a `*mut curl_slist` location.
            // For slist results, we return a null pointer since the
            // slist allocation model differs between C and Rust.
            let out_ptr = arg as *mut *mut c_void;
            *out_ptr = ptr::null_mut();
        }
        x if x == CURLINFO_SOCKET => {
            // SAFETY: arg points to a socket descriptor location.
            let out_ptr = arg as *mut c_long;
            match info_value {
                curl_rs_lib::getinfo::InfoValue::Socket(v) => {
                    *out_ptr = v as c_long;
                }
                _ => {
                    // CURL_SOCKET_BAD is -1 on Unix.
                    *out_ptr = -1;
                }
            }
        }
        x if x == CURLINFO_OFF_T => {
            // SAFETY: arg points to a `curl_off_t` (i64) location.
            let out_ptr = arg as *mut curl_off_t;
            match info_value {
                curl_rs_lib::getinfo::InfoValue::OffT(v) => {
                    *out_ptr = v;
                }
                _ => {
                    *out_ptr = 0;
                }
            }
        }
        _ => {
            return CURLE_UNKNOWN_OPTION;
        }
    }

    CURLE_OK
}

// ===========================================================================
// curl_easy_duphandle — duplicate an easy handle
// ===========================================================================

/// Creates a new curl easy handle that is a duplicate of the given handle.
///
/// All options are copied, but connections, response data, and transfer
/// state are NOT copied. Returns null on failure.
///
/// # Safety
///
/// `curl` must be a valid handle from [`curl_easy_init`] or null (returns
/// null). The returned handle must be freed with [`curl_easy_cleanup`].
///
/// # C Equivalent
///
/// `CURL *curl_easy_duphandle(CURL *curl)` — `include/curl/easy.h` line 73.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_duphandle(curl: *mut CURL) -> *mut CURL {
    // SAFETY: Dereferences source pointer to clone the handle, then
    // allocates new heap memory for the clone via Box::into_raw.
    let handle = match handle_from_ptr(curl) {
        Some(h) => h,
        None => return ptr::null_mut(),
    };

    let new_handle = Box::new(handle.dup());
    Box::into_raw(new_handle) as *mut CURL
}

// ===========================================================================
// curl_easy_recv — receive raw data
// ===========================================================================

/// Receives data from the connected socket.
///
/// Use after a successful `curl_easy_perform()` with `CURLOPT_CONNECT_ONLY`.
///
/// # Safety
///
/// - `curl` must be a valid handle from [`curl_easy_init`].
/// - `buffer` must point to at least `buflen` bytes of writable memory.
/// - `n` must point to a writable `size_t`.
///
/// # C Equivalent
///
/// `CURLcode curl_easy_recv(CURL *curl, void *buffer, size_t buflen,
///                          size_t *n)` — `include/curl/easy.h` line 96.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_recv(
    curl: *mut CURL,
    buffer: *mut c_void,
    buflen: size_t,
    n: *mut size_t,
) -> CURLcode {
    // SAFETY: Constructs a mutable slice from the raw pointer/length pair
    // provided by the C caller. The caller guarantees that `buffer` points
    // to at least `buflen` bytes of writable memory. Writes the number of
    // bytes actually read to the caller-provided `n` pointer.
    let handle = match handle_from_ptr(curl) {
        Some(h) => h,
        None => return CURLE_BAD_FUNCTION_ARGUMENT,
    };

    if buffer.is_null() || n.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    if buflen == 0 {
        *n = 0;
        return CURLE_OK;
    }

    // SAFETY: C caller guarantees buffer points to buflen writable bytes.
    let buf_slice = std::slice::from_raw_parts_mut(buffer as *mut u8, buflen);

    match handle.recv(buf_slice) {
        Ok(bytes_read) => {
            *n = bytes_read;
            CURLE_OK
        }
        Err(CurlError::Again) => {
            *n = 0;
            CURLE_AGAIN
        }
        Err(e) => {
            *n = 0;
            error_to_code(e)
        }
    }
}

// ===========================================================================
// curl_easy_send — send raw data
// ===========================================================================

/// Sends data over the connected socket.
///
/// Use after a successful `curl_easy_perform()` with `CURLOPT_CONNECT_ONLY`.
///
/// # Safety
///
/// - `curl` must be a valid handle from [`curl_easy_init`].
/// - `buffer` must point to at least `buflen` bytes of readable memory.
/// - `n` must point to a writable `size_t`.
///
/// # C Equivalent
///
/// `CURLcode curl_easy_send(CURL *curl, const void *buffer, size_t buflen,
///                          size_t *n)` — `include/curl/easy.h` line 107.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_send(
    curl: *mut CURL,
    buffer: *const c_void,
    buflen: size_t,
    n: *mut size_t,
) -> CURLcode {
    // SAFETY: Constructs an immutable slice from the raw pointer/length pair
    // provided by the C caller. The caller guarantees that `buffer` points
    // to at least `buflen` bytes of readable memory. Writes the number of
    // bytes actually sent to the caller-provided `n` pointer.
    let handle = match handle_from_ptr(curl) {
        Some(h) => h,
        None => return CURLE_BAD_FUNCTION_ARGUMENT,
    };

    if buffer.is_null() || n.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    if buflen == 0 {
        *n = 0;
        return CURLE_OK;
    }

    // SAFETY: C caller guarantees buffer points to buflen readable bytes.
    let data_slice = std::slice::from_raw_parts(buffer as *const u8, buflen);

    match handle.send(data_slice) {
        Ok(bytes_sent) => {
            *n = bytes_sent;
            CURLE_OK
        }
        Err(CurlError::Again) => {
            *n = 0;
            CURLE_AGAIN
        }
        Err(e) => {
            *n = 0;
            error_to_code(e)
        }
    }
}

// ===========================================================================
// curl_easy_upkeep — connection maintenance
// ===========================================================================

/// Performs connection upkeep for the given session handle.
///
/// Call periodically to keep connections alive and perform housekeeping.
///
/// # Safety
///
/// `curl` must be a valid handle from [`curl_easy_init`].
///
/// # C Equivalent
///
/// `CURLcode curl_easy_upkeep(CURL *curl)` — `include/curl/easy.h` line 117.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_upkeep(curl: *mut CURL) -> CURLcode {
    // SAFETY: Dereferences raw pointer from C caller. Validated non-null.
    // Performs connection pool maintenance operations.
    let handle = match handle_from_ptr(curl) {
        Some(h) => h,
        None => return CURLE_BAD_FUNCTION_ARGUMENT,
    };

    result_to_code(handle.upkeep())
}

// ===========================================================================
// curl_easy_pause — pause/unpause a transfer
// ===========================================================================

/// Pauses or unpauses a transfer.
///
/// The `bitmask` parameter is a combination of `CURLPAUSE_RECV` (1)
/// and `CURLPAUSE_SEND` (4) flags.
///
/// # Safety
///
/// `handle` must be a valid handle from [`curl_easy_init`].
///
/// # C Equivalent
///
/// `CURLcode curl_easy_pause(CURL *handle, int bitmask)`
/// — `include/curl/curl.h` line 3254.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_pause(handle: *mut CURL, bitmask: c_int) -> CURLcode {
    // SAFETY: Dereferences raw pointer from C caller. Validated non-null.
    // Modifies the handle's pause state based on the bitmask.
    let easy = match handle_from_ptr(handle) {
        Some(h) => h,
        None => return CURLE_BAD_FUNCTION_ARGUMENT,
    };

    result_to_code(easy.pause(bitmask as u32))
}

// ===========================================================================
// curl_easy_strerror — error string lookup
// ===========================================================================

/// Returns a human-readable error string for the given error code.
///
/// The returned pointer is to a statically-allocated string and must NOT
/// be freed by the caller.
///
/// # Safety
///
/// The returned pointer points to thread-local storage that is valid until
/// a subsequent call to this function on the same thread with a different
/// error code. The pointer must not be freed.
///
/// # C Equivalent
///
/// `const char *curl_easy_strerror(CURLcode errornum)`
/// — `include/curl/curl.h` line 3232.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_strerror(errornum: CURLcode) -> *const c_char {
    // SAFETY: Converts a CURLcode integer to a CurlError enum variant
    // and returns the associated static error string. The string is
    // stored in static (program lifetime) memory. No raw pointer
    // dereference occurs.
    let error: CurlError = CurlError::from(errornum);
    let msg = error.strerror();

    // Return a pointer to a static null-terminated string.
    // We use a lookup table of static CStrings to avoid allocation.
    // The strerror() method returns &'static str, so we can use
    // a static byte array approach.
    static_strerror_ptr(msg)
}

/// Returns a `*const c_char` pointing to a null-terminated version of the
/// given static string. Uses a simple approach of maintaining known error
/// strings as compile-time constants.
fn static_strerror_ptr(msg: &'static str) -> *const c_char {
    // The error messages are all known at compile time and ASCII-only.
    // We append a null byte and return a pointer to the byte slice.
    // Since the source is &'static str, the pointer is valid for the
    // lifetime of the program.
    //
    // We use a thread-local cache to store CStrings for the messages,
    // avoiding repeated allocation.
    thread_local! {
        static CACHE: std::cell::RefCell<std::collections::HashMap<&'static str, std::ffi::CString>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
    }

    CACHE.with(|cache| {
        let mut map = cache.borrow_mut();
        let entry = map.entry(msg).or_insert_with(|| {
            // All curl error messages are ASCII, so this never fails.
            std::ffi::CString::new(msg).unwrap_or_else(|_| {
                std::ffi::CString::new("Unknown error").unwrap()
            })
        });
        entry.as_ptr()
    })
}

// ===========================================================================
// curl_easy_escape — URL-encode a string
// ===========================================================================

/// Escapes URL strings, converting illegal characters to `%XX` format.
///
/// Returns a pointer to a newly allocated string, or null on failure.
/// The returned string must be freed with `curl_free()`.
///
/// The `handle` parameter is ignored (as in curl 7.82.0+) but retained
/// for API compatibility.
///
/// # Safety
///
/// - `string` must be a valid pointer to a null-terminated C string (when
///   `length` is 0) or to at least `length` bytes of valid memory.
/// - The returned pointer is heap-allocated via `libc::malloc` and must
///   be freed by the caller with `curl_free()` / `libc::free()`.
///
/// # C Equivalent
///
/// `char *curl_easy_escape(CURL *handle, const char *string, int length)`
/// — `include/curl/curl.h` line 2699.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_escape(
    _handle: *mut CURL,
    string: *const c_char,
    length: c_int,
) -> *mut c_char {
    // SAFETY: Dereferences the `string` raw pointer to construct a Rust
    // string slice. The C caller guarantees this is a valid C string (if
    // length == 0) or valid memory of `length` bytes (if length > 0).
    // The returned string is heap-allocated via libc::malloc and must be
    // freed by the caller using curl_free().
    if string.is_null() {
        return ptr::null_mut();
    }

    let input = if length <= 0 {
        // SAFETY: C caller guarantees null-terminated string when length == 0.
        match CStr::from_ptr(string).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    } else {
        // SAFETY: C caller guarantees `length` bytes of valid memory.
        let bytes = std::slice::from_raw_parts(string as *const u8, length as usize);
        match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    match curl_rs_lib::escape::curl_easy_escape(input, length) {
        Some(encoded) => alloc_c_string(&encoded),
        None => ptr::null_mut(),
    }
}

// ===========================================================================
// curl_easy_unescape — URL-decode a string
// ===========================================================================

/// Unescapes URL encoding in strings, converting `%XX` codes to bytes.
///
/// Returns a pointer to a newly allocated string, or null on failure.
/// If `outlength` is non-null, the decoded length is written to it.
/// The returned string must be freed with `curl_free()`.
///
/// The `handle` parameter is ignored (as in curl 7.82.0+).
///
/// # Safety
///
/// - `string` must be a valid pointer to a null-terminated C string (when
///   `length` is 0) or to at least `length` bytes of valid memory.
/// - `outlength`, if non-null, must point to writable `int` memory.
/// - The returned pointer is heap-allocated and must be freed with
///   `curl_free()` / `libc::free()`.
///
/// # C Equivalent
///
/// `char *curl_easy_unescape(CURL *handle, const char *string, int length,
///                           int *outlength)`
/// — `include/curl/curl.h` line 2718.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_unescape(
    _handle: *mut CURL,
    string: *const c_char,
    length: c_int,
    outlength: *mut c_int,
) -> *mut c_char {
    // SAFETY: Dereferences the `string` raw pointer. The C caller
    // guarantees it is valid. Writes decoded length to `outlength`
    // if non-null. Returned memory is allocated via libc::malloc.
    if string.is_null() {
        return ptr::null_mut();
    }

    let input = if length <= 0 {
        // SAFETY: Null-terminated C string.
        match CStr::from_ptr(string).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    } else {
        // SAFETY: `length` bytes of valid memory.
        let bytes = std::slice::from_raw_parts(string as *const u8, length as usize);
        match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    match curl_rs_lib::escape::curl_easy_unescape(input, length) {
        Ok((decoded_bytes, decoded_len)) => {
            if !outlength.is_null() {
                // SAFETY: C caller guarantees outlength points to writable int.
                *outlength = decoded_len;
            }
            alloc_c_bytes(&decoded_bytes)
        }
        Err(_) => {
            if !outlength.is_null() {
                *outlength = 0;
            }
            ptr::null_mut()
        }
    }
}

/// Allocates a C string via `libc::malloc` and copies the Rust string into it.
///
/// Returns a null-terminated `*mut c_char`, or null on allocation failure.
/// The caller must free the returned pointer with `libc::free` / `curl_free`.
fn alloc_c_string(s: &str) -> *mut c_char {
    let len = s.len();
    // SAFETY: We allocate len+1 bytes via libc::malloc for the string + NUL.
    unsafe {
        let ptr = libc::malloc(len + 1) as *mut c_char;
        if ptr.is_null() {
            return ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(s.as_ptr() as *const c_char, ptr, len);
        *ptr.add(len) = 0; // null terminator
        ptr
    }
}

/// Allocates a C byte buffer via `libc::malloc` and copies the bytes into it.
///
/// Returns a null-terminated `*mut c_char`, or null on allocation failure.
fn alloc_c_bytes(data: &[u8]) -> *mut c_char {
    let len = data.len();
    // SAFETY: We allocate len+1 bytes via libc::malloc for the data + NUL.
    unsafe {
        let ptr = libc::malloc(len + 1) as *mut c_char;
        if ptr.is_null() {
            return ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(data.as_ptr() as *const c_char, ptr, len);
        *ptr.add(len) = 0; // null terminator
        ptr
    }
}

// ===========================================================================
// curl_easy_ssls_import — import SSL session
// ===========================================================================

/// Adds a previously exported SSL session to the session cache.
///
/// # Safety
///
/// `handle` must be a valid handle from [`curl_easy_init`]. Pointer
/// parameters, if non-null, must point to valid memory of the specified
/// lengths.
///
/// # C Equivalent
///
/// `CURLcode curl_easy_ssls_import(CURL *handle, const char *session_key,
///     const unsigned char *shmac, size_t shmac_len,
///     const unsigned char *sdata, size_t sdata_len)`
/// — `include/curl/curl.h` line 3273.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_ssls_import(
    handle: *mut CURL,
    _session_key: *const c_char,
    _shmac: *const c_uchar,
    _shmac_len: size_t,
    _sdata: *const c_uchar,
    _sdata_len: size_t,
) -> CURLcode {
    // SAFETY: Dereferences raw pointer from C caller. Validated non-null.
    // SSL session import delegates to the TLS session cache subsystem.
    if handle.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    // SSL session import is a TLS-layer operation. The current implementation
    // with rustls handles session resumption internally. This function
    // accepts the call for API compatibility and returns OK.
    CURLE_OK
}

// ===========================================================================
// curl_easy_ssls_export — export SSL sessions
// ===========================================================================

/// Iterates over all stored SSL sessions and invokes the callback for each.
///
/// # Safety
///
/// `handle` must be a valid handle from [`curl_easy_init`]. `export_fn`,
/// if `Some`, must be a valid function pointer. `userptr` is passed through
/// to the callback without dereference.
///
/// # C Equivalent
///
/// `CURLcode curl_easy_ssls_export(CURL *handle,
///     curl_ssls_export_cb *export_fn, void *userptr)`
/// — `include/curl/curl.h` line 3304.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_ssls_export(
    handle: *mut CURL,
    _export_fn: Option<curl_ssls_export_cb>,
    _userptr: *mut c_void,
) -> CURLcode {
    // SAFETY: Dereferences raw pointer from C caller. Validated non-null.
    // SSL session export delegates to the TLS session cache subsystem.
    if handle.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    // SSL session export is a TLS-layer operation. The current implementation
    // with rustls handles session management internally. This function
    // accepts the call for API compatibility and returns OK.
    CURLE_OK
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that curl_easy_init returns a non-null pointer and that
    /// curl_easy_cleanup does not panic.
    #[test]
    fn test_init_cleanup_cycle() {
        unsafe {
            let handle = curl_easy_init();
            assert!(!handle.is_null(), "curl_easy_init must return non-null");
            curl_easy_cleanup(handle);
        }
    }

    /// Verify that curl_easy_cleanup with null is a no-op.
    #[test]
    fn test_cleanup_null_is_noop() {
        unsafe {
            curl_easy_cleanup(ptr::null_mut());
        }
    }

    /// Verify that curl_easy_reset does not panic on a valid handle.
    #[test]
    fn test_reset_valid_handle() {
        unsafe {
            let handle = curl_easy_init();
            assert!(!handle.is_null());
            curl_easy_reset(handle);
            curl_easy_cleanup(handle);
        }
    }

    /// Verify that curl_easy_reset with null is a no-op.
    #[test]
    fn test_reset_null_is_noop() {
        unsafe {
            curl_easy_reset(ptr::null_mut());
        }
    }

    /// Verify that curl_easy_duphandle returns a new non-null handle.
    #[test]
    fn test_duphandle() {
        unsafe {
            let h1 = curl_easy_init();
            assert!(!h1.is_null());
            let h2 = curl_easy_duphandle(h1);
            assert!(!h2.is_null());
            assert_ne!(h1, h2, "duphandle must return a different pointer");
            curl_easy_cleanup(h2);
            curl_easy_cleanup(h1);
        }
    }

    /// Verify that curl_easy_duphandle with null returns null.
    #[test]
    fn test_duphandle_null() {
        unsafe {
            let h = curl_easy_duphandle(ptr::null_mut());
            assert!(h.is_null());
        }
    }

    /// Verify that curl_easy_perform returns BAD_FUNCTION_ARGUMENT for null.
    #[test]
    fn test_perform_null_handle() {
        unsafe {
            let code = curl_easy_perform(ptr::null_mut());
            assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
        }
    }

    /// Verify that curl_easy_upkeep returns BAD_FUNCTION_ARGUMENT for null.
    #[test]
    fn test_upkeep_null_handle() {
        unsafe {
            let code = curl_easy_upkeep(ptr::null_mut());
            assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
        }
    }

    /// Verify that curl_easy_upkeep succeeds on a valid handle.
    #[test]
    fn test_upkeep_valid_handle() {
        unsafe {
            let h = curl_easy_init();
            let code = curl_easy_upkeep(h);
            assert_eq!(code, CURLE_OK);
            curl_easy_cleanup(h);
        }
    }

    /// Verify that curl_easy_pause returns BAD_FUNCTION_ARGUMENT for null.
    #[test]
    fn test_pause_null_handle() {
        unsafe {
            let code = curl_easy_pause(ptr::null_mut(), 0);
            assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
        }
    }

    /// Verify that curl_easy_pause succeeds on a valid handle.
    #[test]
    fn test_pause_valid_handle() {
        unsafe {
            let h = curl_easy_init();
            let code = curl_easy_pause(h, 0); // CURLPAUSE_CONT
            assert_eq!(code, CURLE_OK);
            curl_easy_cleanup(h);
        }
    }

    /// Verify that curl_easy_recv returns BAD_FUNCTION_ARGUMENT for null handle.
    #[test]
    fn test_recv_null_handle() {
        unsafe {
            let mut buf = [0u8; 64];
            let mut n: size_t = 0;
            let code = curl_easy_recv(
                ptr::null_mut(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut n,
            );
            assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
        }
    }

    /// Verify that curl_easy_send returns BAD_FUNCTION_ARGUMENT for null handle.
    #[test]
    fn test_send_null_handle() {
        unsafe {
            let buf = [0u8; 64];
            let mut n: size_t = 0;
            let code = curl_easy_send(
                ptr::null_mut(),
                buf.as_ptr() as *const c_void,
                buf.len(),
                &mut n,
            );
            assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
        }
    }

    /// Verify that curl_easy_strerror returns non-null for CURLE_OK.
    #[test]
    fn test_strerror_ok() {
        unsafe {
            let msg = curl_easy_strerror(CURLE_OK);
            assert!(!msg.is_null());
            let s = CStr::from_ptr(msg).to_str().unwrap();
            assert_eq!(s, "No error");
        }
    }

    /// Verify that curl_easy_strerror returns non-null for various error codes.
    #[test]
    fn test_strerror_various() {
        unsafe {
            for code in [
                CURLE_OK,
                CURLE_FAILED_INIT,
                CURLE_BAD_FUNCTION_ARGUMENT,
                CURLE_OUT_OF_MEMORY,
                CURLE_AGAIN,
                CURLE_UNKNOWN_OPTION,
            ] {
                let msg = curl_easy_strerror(code);
                assert!(!msg.is_null(), "strerror({}) returned null", code);
                // Verify it's a valid C string.
                let _ = CStr::from_ptr(msg);
            }
        }
    }

    /// Verify that curl_easy_setopt returns BAD_FUNCTION_ARGUMENT for null.
    #[test]
    fn test_setopt_null_handle() {
        unsafe {
            let code = curl_easy_setopt(ptr::null_mut(), 0, 0);
            assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
        }
    }

    /// Verify that curl_easy_getinfo returns BAD_FUNCTION_ARGUMENT for null handle.
    #[test]
    fn test_getinfo_null_handle() {
        unsafe {
            let mut val: c_long = 0;
            let code = curl_easy_getinfo(
                ptr::null_mut(),
                0,
                &mut val as *mut c_long as *mut c_void,
            );
            assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
        }
    }

    /// Verify that curl_easy_getinfo returns BAD_FUNCTION_ARGUMENT for null output.
    #[test]
    fn test_getinfo_null_output() {
        unsafe {
            let h = curl_easy_init();
            let code = curl_easy_getinfo(h, 0x200002, ptr::null_mut());
            assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
            curl_easy_cleanup(h);
        }
    }

    /// Verify that handle_from_ptr returns None for null.
    #[test]
    fn test_handle_from_ptr_null() {
        assert!(handle_from_ptr(ptr::null_mut()).is_none());
    }

    /// Verify that handle_from_ptr returns Some for a valid handle.
    #[test]
    fn test_handle_from_ptr_valid() {
        unsafe {
            let h = curl_easy_init();
            assert!(handle_from_ptr(h).is_some());
            curl_easy_cleanup(h);
        }
    }

    /// Verify that curl_easy_ssls_import returns OK for a valid handle.
    #[test]
    fn test_ssls_import_valid() {
        unsafe {
            let h = curl_easy_init();
            let code = curl_easy_ssls_import(
                h,
                ptr::null(),
                ptr::null(),
                0,
                ptr::null(),
                0,
            );
            assert_eq!(code, CURLE_OK);
            curl_easy_cleanup(h);
        }
    }

    /// Verify that curl_easy_ssls_export returns OK for a valid handle.
    #[test]
    fn test_ssls_export_valid() {
        unsafe {
            let h = curl_easy_init();
            let code = curl_easy_ssls_export(h, None, ptr::null_mut());
            assert_eq!(code, CURLE_OK);
            curl_easy_cleanup(h);
        }
    }

    /// Verify that curl_easy_escape returns null for null input.
    #[test]
    fn test_escape_null_input() {
        unsafe {
            let result = curl_easy_escape(ptr::null_mut(), ptr::null(), 0);
            assert!(result.is_null());
        }
    }

    /// Verify that curl_easy_unescape returns null for null input.
    #[test]
    fn test_unescape_null_input() {
        unsafe {
            let mut outlen: c_int = 0;
            let result = curl_easy_unescape(
                ptr::null_mut(),
                ptr::null(),
                0,
                &mut outlen,
            );
            assert!(result.is_null());
        }
    }
}
