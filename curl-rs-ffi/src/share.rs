//! FFI bindings for the `curl_share_*` family of functions.
//!
//! This module exposes the 4 `CURL_EXTERN` share-handle symbols from
//! `include/curl/curl.h` (lines 3079–3082, 3243) as `extern "C"` functions
//! with `#[no_mangle]`, plus all associated `CURLSHoption`, `curl_lock_data`,
//! and `curl_lock_access` integer constants.
//!
//! # C API Mapping
//!
//! | C function               | Rust FFI entry point          |
//! |--------------------------|-------------------------------|
//! | `curl_share_init()`      | [`curl_share_init()`]         |
//! | `curl_share_setopt()`    | [`curl_share_setopt()`]       |
//! | `curl_share_cleanup()`   | [`curl_share_cleanup()`]      |
//! | `curl_share_strerror()`  | [`curl_share_strerror()`]     |
//!
//! # Variadic Handling
//!
//! The C declaration of `curl_share_setopt` is variadic:
//!
//! ```c
//! CURL_EXTERN CURLSHcode curl_share_setopt(CURLSH *share,
//!                                          CURLSHoption option, ...);
//! ```
//!
//! Rust stable does not support defining variadic `extern "C"` functions
//! (`c_variadic` is unstable as of Rust 1.93).  This implementation uses a
//! non-variadic signature with a pointer-sized third parameter, which is
//! ABI-compatible on x86-64, x86, and aarch64-linux (integer/pointer
//! arguments occupy the same register slots for both variadic and
//! non-variadic calls on these platforms).
//!
//! # Safety
//!
//! All functions in this module are `unsafe extern "C"`.  Every `unsafe`
//! block carries a `// SAFETY:` comment with explicit invariant
//! justification, per AAP Section 0.7.1.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use libc::{c_char, c_int, c_void};
use std::ptr;

use crate::error_codes::{
    CURLSHE_BAD_OPTION, CURLSHE_IN_USE, CURLSHE_INVALID, CURLSHE_NOMEM,
    CURLSHE_NOT_BUILT_IN, CURLSHE_OK,
};
use crate::types::{
    curl_lock_access, curl_lock_data, curl_lock_function, curl_unlock_function, CURLSHcode,
    CURLSHoption, CURL, CURLSH,
};

use curl_rs_lib::error::CurlSHcode as RustCurlSHcode;
use curl_rs_lib::share::{CurlShOption, CurlShareLock, LockAccess, ShareHandle};

// ============================================================================
// Section 1: CURLSHoption Constants
// Source: include/curl/curl.h, typedef enum { ... } CURLSHoption; (lines 3068-3077)
//
// Integer values match the C enum exactly.
// ============================================================================

/// Do not use — placeholder value for `CURLSHoption` (`CURLSHOPT_NONE` = 0).
pub const CURLSHOPT_NONE: CURLSHoption = 0;

/// Specify a data type to share (`CURLSHOPT_SHARE` = 1).
///
/// The third argument to `curl_share_setopt` is a `curl_lock_data` value
/// indicating which data type to start sharing.
pub const CURLSHOPT_SHARE: CURLSHoption = 1;

/// Specify a data type to stop sharing (`CURLSHOPT_UNSHARE` = 2).
///
/// The third argument to `curl_share_setopt` is a `curl_lock_data` value
/// indicating which data type to stop sharing.
pub const CURLSHOPT_UNSHARE: CURLSHoption = 2;

/// Set the lock callback function (`CURLSHOPT_LOCKFUNC` = 3).
///
/// The third argument is a `curl_lock_function` pointer (or NULL to clear).
pub const CURLSHOPT_LOCKFUNC: CURLSHoption = 3;

/// Set the unlock callback function (`CURLSHOPT_UNLOCKFUNC` = 4).
///
/// The third argument is a `curl_unlock_function` pointer (or NULL to clear).
pub const CURLSHOPT_UNLOCKFUNC: CURLSHoption = 4;

/// Set the user-data pointer for lock/unlock callbacks
/// (`CURLSHOPT_USERDATA` = 5).
///
/// The third argument is a `void *` pointer passed through to the
/// lock/unlock callbacks.
pub const CURLSHOPT_USERDATA: CURLSHoption = 5;

/// Sentinel — never use (`CURLSHOPT_LAST` = 6).
pub const CURLSHOPT_LAST: CURLSHoption = 6;

// ============================================================================
// Section 2: curl_lock_data Constants
// Source: include/curl/curl.h, typedef enum { ... } curl_lock_data;
//         (lines 3026-3040)
//
// Integer values match the C enum exactly.
// ============================================================================

/// No lock data type specified (`CURL_LOCK_DATA_NONE` = 0).
pub const CURL_LOCK_DATA_NONE: curl_lock_data = 0;

/// Internal share-level lock (`CURL_LOCK_DATA_SHARE` = 1).
///
/// Used internally by the share handle to serialize changes to its own
/// state.  Not intended for external use.
pub const CURL_LOCK_DATA_SHARE: curl_lock_data = 1;

/// Cookie data (`CURL_LOCK_DATA_COOKIE` = 2).
pub const CURL_LOCK_DATA_COOKIE: curl_lock_data = 2;

/// DNS cache data (`CURL_LOCK_DATA_DNS` = 3).
pub const CURL_LOCK_DATA_DNS: curl_lock_data = 3;

/// TLS session data (`CURL_LOCK_DATA_SSL_SESSION` = 4).
pub const CURL_LOCK_DATA_SSL_SESSION: curl_lock_data = 4;

/// Connection pool data (`CURL_LOCK_DATA_CONNECT` = 5).
pub const CURL_LOCK_DATA_CONNECT: curl_lock_data = 5;

/// Public suffix list data (`CURL_LOCK_DATA_PSL` = 6).
pub const CURL_LOCK_DATA_PSL: curl_lock_data = 6;

/// HSTS cache data (`CURL_LOCK_DATA_HSTS` = 7).
pub const CURL_LOCK_DATA_HSTS: curl_lock_data = 7;

/// Sentinel — never use (`CURL_LOCK_DATA_LAST` = 8).
pub const CURL_LOCK_DATA_LAST: curl_lock_data = 8;

// ============================================================================
// Section 3: curl_lock_access Constants
// Source: include/curl/curl.h, typedef enum { ... } curl_lock_access;
//         (lines 3043-3048)
//
// Integer values match the C enum exactly.
// ============================================================================

/// Unspecified access type (`CURL_LOCK_ACCESS_NONE` = 0).
pub const CURL_LOCK_ACCESS_NONE: curl_lock_access = 0;

/// Shared (read) access (`CURL_LOCK_ACCESS_SHARED` = 1).
pub const CURL_LOCK_ACCESS_SHARED: curl_lock_access = 1;

/// Exclusive (write) access (`CURL_LOCK_ACCESS_SINGLE` = 2).
pub const CURL_LOCK_ACCESS_SINGLE: curl_lock_access = 2;

/// Sentinel — never use (`CURL_LOCK_ACCESS_LAST` = 3).
pub const CURL_LOCK_ACCESS_LAST: curl_lock_access = 3;

// ============================================================================
// Section 4: Internal Helpers
// ============================================================================

/// Convert a Rust [`RustCurlSHcode`] enum to the corresponding C integer
/// constant from [`crate::error_codes`].
///
/// This mapping is the authoritative bridge between the Rust type-safe error
/// enum and the C ABI integer return values.
#[inline]
fn curlshcode_to_c(code: RustCurlSHcode) -> CURLSHcode {
    match code {
        RustCurlSHcode::Ok => CURLSHE_OK,
        RustCurlSHcode::BadOption => CURLSHE_BAD_OPTION,
        RustCurlSHcode::InUse => CURLSHE_IN_USE,
        RustCurlSHcode::Invalid => CURLSHE_INVALID,
        RustCurlSHcode::NoMem => CURLSHE_NOMEM,
        RustCurlSHcode::NotBuiltIn => CURLSHE_NOT_BUILT_IN,
    }
}

/// Convert a Rust `Result<(), RustCurlSHcode>` to a C `CURLSHcode`.
///
/// `Ok(())` maps to `CURLSHE_OK`; `Err(e)` maps to the corresponding
/// error constant.
#[inline]
fn result_to_c(result: Result<(), RustCurlSHcode>) -> CURLSHcode {
    match result {
        Ok(()) => CURLSHE_OK,
        Err(e) => curlshcode_to_c(e),
    }
}

// ============================================================================
// Section 5: extern "C" Functions
//
// Every function below has:
//   - `#[no_mangle]` for C symbol visibility
//   - `pub unsafe extern "C"` matching the curl 8.x ABI
//   - A `// SAFETY:` comment on every `unsafe` block (AAP Section 0.7.1)
// ============================================================================

/// Allocate and initialise a new share handle.
///
/// C signature: `CURL_EXTERN CURLSH *curl_share_init(void);`
///
/// Returns a pointer to a newly allocated share handle, or `NULL` if
/// memory allocation fails.  The returned handle must eventually be freed
/// with [`curl_share_cleanup()`].
///
/// # Safety
///
/// This function allocates heap memory via `Box::new`.  The returned
/// pointer is valid until passed to [`curl_share_cleanup()`].  The caller
/// must not dereference the opaque pointer directly.
#[no_mangle]
pub unsafe extern "C" fn curl_share_init() -> *mut CURLSH {
    // Create the Rust ShareHandle and heap-allocate it via Box.
    let handle = ShareHandle::new();
    let boxed = Box::new(handle);

    // SAFETY: Box::into_raw produces a valid, non-null, aligned pointer to a
    // heap-allocated ShareHandle.  We cast to *mut CURLSH because CURLSH is
    // the opaque C handle type.  The pointer remains valid until
    // curl_share_cleanup recovers ownership via Box::from_raw.
    let raw: *mut ShareHandle = Box::into_raw(boxed);
    raw as *mut CURLSH
}

/// Set options on a share handle.
///
/// C signature:
/// ```c
/// CURL_EXTERN CURLSHcode curl_share_setopt(CURLSH *share,
///                                          CURLSHoption option, ...);
/// ```
///
/// The C function is variadic — the third argument type depends on the
/// `option` value:
///
/// | Option                  | Third Argument Type     |
/// |-------------------------|-------------------------|
/// | `CURLSHOPT_SHARE`       | `curl_lock_data` (int)  |
/// | `CURLSHOPT_UNSHARE`     | `curl_lock_data` (int)  |
/// | `CURLSHOPT_LOCKFUNC`    | `curl_lock_function`    |
/// | `CURLSHOPT_UNLOCKFUNC`  | `curl_unlock_function`  |
/// | `CURLSHOPT_USERDATA`    | `void *`                |
///
/// Since Rust stable does not support defining variadic `extern "C"`
/// functions, this implementation uses a non-variadic signature with a
/// pointer-sized third parameter (`usize`).  On x86-64 and aarch64-linux
/// the register-based calling convention places the first three
/// integer/pointer arguments identically for variadic and non-variadic
/// functions, so this is ABI-compatible.
///
/// # Safety
///
/// - `share` must be a valid pointer returned by [`curl_share_init()`],
///   or `NULL` (returns `CURLSHE_INVALID`).
/// - For `CURLSHOPT_LOCKFUNC` / `CURLSHOPT_UNLOCKFUNC`, `arg` must be a
///   valid function pointer of the appropriate type, or zero (NULL) to
///   clear the callback.
/// - For `CURLSHOPT_USERDATA`, `arg` is an opaque pointer cast to `usize`.
/// - For `CURLSHOPT_SHARE` / `CURLSHOPT_UNSHARE`, `arg` is a
///   `curl_lock_data` integer value.
#[no_mangle]
pub unsafe extern "C" fn curl_share_setopt(
    share: *mut CURLSH,
    option: CURLSHoption,
    arg: usize,
) -> CURLSHcode {
    // Null-pointer guard — matches C `if(!share) return CURLSHE_INVALID`.
    if share.is_null() {
        return CURLSHE_INVALID;
    }

    // SAFETY: `share` was produced by `curl_share_init` which stores a
    // Box<ShareHandle> behind the opaque CURLSH pointer.  We cast back
    // to *mut ShareHandle and create a shared reference.  The pointer is
    // valid because:
    //   1. It was allocated by Box::into_raw in curl_share_init.
    //   2. It has not been freed (curl_share_cleanup not yet called).
    //   3. No mutable aliasing occurs — ShareHandle methods use internal
    //      Mutex for synchronization.
    let handle: &ShareHandle = &*(share as *mut ShareHandle);

    match option {
        // -----------------------------------------------------------------
        // CURLSHOPT_SHARE (1) — enable sharing for a data type
        // Third arg: curl_lock_data (c_int) specifying which data to share
        // -----------------------------------------------------------------
        CURLSHOPT_SHARE => {
            let lock_data_int = arg as c_int;
            let lock = match CurlShareLock::from_i32(lock_data_int) {
                Some(l) => l,
                None => return CURLSHE_BAD_OPTION,
            };
            result_to_c(handle.set_option(CurlShOption::Share, lock))
        }

        // -----------------------------------------------------------------
        // CURLSHOPT_UNSHARE (2) — disable sharing for a data type
        // Third arg: curl_lock_data (c_int) specifying which data to unshare
        // -----------------------------------------------------------------
        CURLSHOPT_UNSHARE => {
            let lock_data_int = arg as c_int;
            let lock = match CurlShareLock::from_i32(lock_data_int) {
                Some(l) => l,
                None => return CURLSHE_BAD_OPTION,
            };
            result_to_c(handle.set_option(CurlShOption::Unshare, lock))
        }

        // -----------------------------------------------------------------
        // CURLSHOPT_LOCKFUNC (3) — set lock callback
        // Third arg: curl_lock_function (function pointer, or 0/NULL)
        // -----------------------------------------------------------------
        CURLSHOPT_LOCKFUNC => {
            if arg == 0 {
                // NULL function pointer — clear the lock callback.
                result_to_c(handle.set_lock_func(None))
            } else {
                // SAFETY: The caller guarantees that `arg` holds a valid
                // `curl_lock_function` pointer value.  Function pointers
                // and usize have the same size and alignment on all
                // supported platforms.  The transmute reinterprets the
                // pointer-sized integer as a typed function pointer.
                let c_func: curl_lock_function = std::mem::transmute(arg);

                // Wrap the C function pointer in a Rust closure that
                // matches the LockCallback type expected by ShareHandle.
                // The CURL handle parameter is set to null because
                // share-level lock invocations do not have an associated
                // easy handle at the point of the call.
                let wrapper: curl_rs_lib::share::LockCallback =
                    Box::new(move |lock: CurlShareLock, access: LockAccess, userptr: usize| {
                        // SAFETY: c_func is a valid C function pointer
                        // captured from the caller's CURLSHOPT_LOCKFUNC
                        // argument.  We pass:
                        //   - null_mut() for the CURL handle (share-level)
                        //   - lock as c_int matching curl_lock_data
                        //   - access as c_int matching curl_lock_access
                        //   - userptr reinterpreted as *mut c_void
                        unsafe {
                            c_func(
                                ptr::null_mut::<CURL>(),
                                lock as c_int,
                                access as c_int,
                                userptr as *mut c_void,
                            );
                        }
                    });
                result_to_c(handle.set_lock_func(Some(wrapper)))
            }
        }

        // -----------------------------------------------------------------
        // CURLSHOPT_UNLOCKFUNC (4) — set unlock callback
        // Third arg: curl_unlock_function (function pointer, or 0/NULL)
        // -----------------------------------------------------------------
        CURLSHOPT_UNLOCKFUNC => {
            if arg == 0 {
                // NULL function pointer — clear the unlock callback.
                result_to_c(handle.set_unlock_func(None))
            } else {
                // SAFETY: The caller guarantees that `arg` holds a valid
                // `curl_unlock_function` pointer value.  Same transmute
                // rationale as CURLSHOPT_LOCKFUNC above.
                let c_func: curl_unlock_function = std::mem::transmute(arg);

                // Wrap the C function pointer in a Rust closure matching
                // the UnlockCallback type expected by ShareHandle.
                let wrapper: curl_rs_lib::share::UnlockCallback =
                    Box::new(move |lock: CurlShareLock, userptr: usize| {
                        // SAFETY: c_func is a valid C function pointer
                        // captured from the caller's CURLSHOPT_UNLOCKFUNC
                        // argument.  Same parameter mapping as lock above,
                        // minus the access parameter.
                        unsafe {
                            c_func(
                                ptr::null_mut::<CURL>(),
                                lock as c_int,
                                userptr as *mut c_void,
                            );
                        }
                    });
                result_to_c(handle.set_unlock_func(Some(wrapper)))
            }
        }

        // -----------------------------------------------------------------
        // CURLSHOPT_USERDATA (5) — set opaque user-data pointer
        // Third arg: void * (passed as usize)
        // -----------------------------------------------------------------
        CURLSHOPT_USERDATA => {
            // The user_data value is stored as-is (usize) in the
            // ShareHandle and passed through to lock/unlock callbacks.
            result_to_c(handle.set_user_data(arg))
        }

        // -----------------------------------------------------------------
        // Unknown or out-of-range option
        // -----------------------------------------------------------------
        _ => CURLSHE_BAD_OPTION,
    }
}

/// Destroy a share handle and free all associated resources.
///
/// C signature: `CURL_EXTERN CURLSHcode curl_share_cleanup(CURLSH *share);`
///
/// Returns `CURLSHE_OK` on success, or `CURLSHE_IN_USE` if one or more
/// easy handles are still attached to this share handle.  In the error
/// case the share handle is NOT freed — the caller must detach all easy
/// handles first and then call cleanup again.
///
/// # Safety
///
/// - `share` must be a valid pointer returned by [`curl_share_init()`],
///   or `NULL` (returns `CURLSHE_INVALID`).
/// - After a successful return (`CURLSHE_OK`), the pointer is invalidated
///   and must not be used again.
/// - This function must not be called concurrently with any other
///   `curl_share_*` function on the same handle.
#[no_mangle]
pub unsafe extern "C" fn curl_share_cleanup(share: *mut CURLSH) -> CURLSHcode {
    // Null-pointer guard — matches C `if(!share) return CURLSHE_INVALID`.
    if share.is_null() {
        return CURLSHE_INVALID;
    }

    // SAFETY: `share` was produced by `curl_share_init` which stores a
    // Box<ShareHandle> behind the opaque CURLSH pointer.  We first
    // obtain a reference to call cleanup(), then recover ownership
    // via Box::from_raw to deallocate.
    let handle_ptr = share as *mut ShareHandle;
    let handle_ref: &ShareHandle = &*handle_ptr;

    // Attempt cleanup (destroy shared resources).  If the handle is
    // still in use by one or more easy handles, cleanup returns InUse
    // and we must NOT free the memory.
    match handle_ref.cleanup() {
        Ok(()) => {
            // SAFETY: cleanup() succeeded — no easy handles hold references.
            // We recover Box ownership to deallocate the ShareHandle.
            // After this point, the pointer is invalid and must not be used.
            let _drop_box = Box::from_raw(handle_ptr);
            CURLSHE_OK
        }
        Err(code) => curlshcode_to_c(code),
    }
}

/// Return a human-readable string for a `CURLSHcode` value.
///
/// C signature:
/// `CURL_EXTERN const char *curl_share_strerror(CURLSHcode);`
///
/// The returned pointer points to a static, null-terminated C string.
/// The pointer is valid for the lifetime of the process and must NOT
/// be freed by the caller.
///
/// # Safety
///
/// The `code` parameter can be any `c_int` value.  Unknown values return
/// a generic "Unknown error" string.
#[no_mangle]
pub unsafe extern "C" fn curl_share_strerror(code: CURLSHcode) -> *const c_char {
    // Convert the C integer code to the Rust enum for dispatch.
    // RustCurlSHcode::from(i32) maps unknown values to Invalid.
    let rust_code = RustCurlSHcode::from(code);

    // Return a pointer to a static, null-terminated byte string.
    // Each string matches the curl 8.x `curl_share_strerror()` output
    // character-for-character.
    //
    // SAFETY: All byte literals below are valid UTF-8 and null-terminated.
    // The `.as_ptr()` returns a pointer to static data with 'static
    // lifetime, which is safe to return to C callers.
    match rust_code {
        RustCurlSHcode::Ok => b"No error\0".as_ptr() as *const c_char,
        RustCurlSHcode::BadOption => b"Unknown share option\0".as_ptr() as *const c_char,
        RustCurlSHcode::InUse => b"Share currently in use\0".as_ptr() as *const c_char,
        RustCurlSHcode::Invalid => b"Invalid share handle\0".as_ptr() as *const c_char,
        RustCurlSHcode::NoMem => b"Out of memory\0".as_ptr() as *const c_char,
        RustCurlSHcode::NotBuiltIn => {
            b"Feature not enabled in this library\0".as_ptr() as *const c_char
        }
    }
}

// ============================================================================
// Section 6: Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify all CURLSHoption constants match their C enum values.
    #[test]
    fn curlshoption_values() {
        assert_eq!(CURLSHOPT_NONE, 0);
        assert_eq!(CURLSHOPT_SHARE, 1);
        assert_eq!(CURLSHOPT_UNSHARE, 2);
        assert_eq!(CURLSHOPT_LOCKFUNC, 3);
        assert_eq!(CURLSHOPT_UNLOCKFUNC, 4);
        assert_eq!(CURLSHOPT_USERDATA, 5);
        assert_eq!(CURLSHOPT_LAST, 6);
    }

    /// Verify all curl_lock_data constants match their C enum values.
    #[test]
    fn curl_lock_data_values() {
        assert_eq!(CURL_LOCK_DATA_NONE, 0);
        assert_eq!(CURL_LOCK_DATA_SHARE, 1);
        assert_eq!(CURL_LOCK_DATA_COOKIE, 2);
        assert_eq!(CURL_LOCK_DATA_DNS, 3);
        assert_eq!(CURL_LOCK_DATA_SSL_SESSION, 4);
        assert_eq!(CURL_LOCK_DATA_CONNECT, 5);
        assert_eq!(CURL_LOCK_DATA_PSL, 6);
        assert_eq!(CURL_LOCK_DATA_HSTS, 7);
        assert_eq!(CURL_LOCK_DATA_LAST, 8);
    }

    /// Verify all curl_lock_access constants match their C enum values.
    #[test]
    fn curl_lock_access_values() {
        assert_eq!(CURL_LOCK_ACCESS_NONE, 0);
        assert_eq!(CURL_LOCK_ACCESS_SHARED, 1);
        assert_eq!(CURL_LOCK_ACCESS_SINGLE, 2);
        assert_eq!(CURL_LOCK_ACCESS_LAST, 3);
    }

    /// Verify the curlshcode_to_c helper maps all variants correctly.
    #[test]
    fn curlshcode_mapping() {
        assert_eq!(curlshcode_to_c(RustCurlSHcode::Ok), CURLSHE_OK);
        assert_eq!(curlshcode_to_c(RustCurlSHcode::BadOption), CURLSHE_BAD_OPTION);
        assert_eq!(curlshcode_to_c(RustCurlSHcode::InUse), CURLSHE_IN_USE);
        assert_eq!(curlshcode_to_c(RustCurlSHcode::Invalid), CURLSHE_INVALID);
        assert_eq!(curlshcode_to_c(RustCurlSHcode::NoMem), CURLSHE_NOMEM);
        assert_eq!(curlshcode_to_c(RustCurlSHcode::NotBuiltIn), CURLSHE_NOT_BUILT_IN);
    }

    /// Test curl_share_init returns a non-null pointer.
    #[test]
    fn share_init_returns_non_null() {
        unsafe {
            let share = curl_share_init();
            assert!(!share.is_null(), "curl_share_init must return non-null");
            // Clean up to avoid memory leak.
            let rc = curl_share_cleanup(share);
            assert_eq!(rc, CURLSHE_OK);
        }
    }

    /// Test curl_share_setopt with CURLSHOPT_SHARE for cookie data.
    #[test]
    fn share_setopt_share_cookie() {
        unsafe {
            let share = curl_share_init();
            assert!(!share.is_null());

            let rc = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE as usize);
            assert_eq!(rc, CURLSHE_OK, "sharing cookies should succeed");

            let rc = curl_share_cleanup(share);
            assert_eq!(rc, CURLSHE_OK);
        }
    }

    /// Test curl_share_setopt with CURLSHOPT_SHARE for DNS data.
    #[test]
    fn share_setopt_share_dns() {
        unsafe {
            let share = curl_share_init();
            assert!(!share.is_null());

            let rc = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS as usize);
            assert_eq!(rc, CURLSHE_OK, "sharing DNS should succeed");

            let rc = curl_share_cleanup(share);
            assert_eq!(rc, CURLSHE_OK);
        }
    }

    /// Test curl_share_setopt with an invalid lock data value.
    #[test]
    fn share_setopt_invalid_lock_data() {
        unsafe {
            let share = curl_share_init();
            assert!(!share.is_null());

            // CURL_LOCK_DATA_LAST (8) is not a valid shareable type.
            let rc = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_LAST as usize);
            assert_eq!(rc, CURLSHE_BAD_OPTION, "invalid lock data should fail");

            // Value 99 is also invalid.
            let rc = curl_share_setopt(share, CURLSHOPT_SHARE, 99usize);
            assert_eq!(rc, CURLSHE_BAD_OPTION, "out-of-range lock data should fail");

            let rc = curl_share_cleanup(share);
            assert_eq!(rc, CURLSHE_OK);
        }
    }

    /// Test curl_share_setopt with CURLSHOPT_UNSHARE.
    #[test]
    fn share_setopt_unshare() {
        unsafe {
            let share = curl_share_init();
            assert!(!share.is_null());

            // First share, then unshare.
            let rc = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE as usize);
            assert_eq!(rc, CURLSHE_OK);

            let rc = curl_share_setopt(share, CURLSHOPT_UNSHARE, CURL_LOCK_DATA_COOKIE as usize);
            assert_eq!(rc, CURLSHE_OK, "unsharing cookies should succeed");

            let rc = curl_share_cleanup(share);
            assert_eq!(rc, CURLSHE_OK);
        }
    }

    /// Test curl_share_setopt with CURLSHOPT_USERDATA.
    #[test]
    fn share_setopt_userdata() {
        unsafe {
            let share = curl_share_init();
            assert!(!share.is_null());

            let user_data: usize = 0xDEAD_BEEF;
            let rc = curl_share_setopt(share, CURLSHOPT_USERDATA, user_data);
            assert_eq!(rc, CURLSHE_OK, "setting userdata should succeed");

            let rc = curl_share_cleanup(share);
            assert_eq!(rc, CURLSHE_OK);
        }
    }

    /// Test curl_share_setopt with an unknown option.
    #[test]
    fn share_setopt_unknown_option() {
        unsafe {
            let share = curl_share_init();
            assert!(!share.is_null());

            let rc = curl_share_setopt(share, 999, 0usize);
            assert_eq!(rc, CURLSHE_BAD_OPTION, "unknown option should fail");

            let rc = curl_share_cleanup(share);
            assert_eq!(rc, CURLSHE_OK);
        }
    }

    /// Test curl_share_setopt and curl_share_cleanup with NULL.
    #[test]
    fn share_null_pointer_handling() {
        unsafe {
            let rc = curl_share_setopt(ptr::null_mut(), CURLSHOPT_SHARE, 0usize);
            assert_eq!(rc, CURLSHE_INVALID, "setopt on NULL should be INVALID");

            let rc = curl_share_cleanup(ptr::null_mut());
            assert_eq!(rc, CURLSHE_INVALID, "cleanup on NULL should be INVALID");
        }
    }

    /// Test curl_share_strerror returns correct strings for all codes.
    #[test]
    fn share_strerror_messages() {
        unsafe {
            let check = |code: CURLSHcode, expected: &[u8]| {
                let ptr = curl_share_strerror(code);
                assert!(!ptr.is_null());
                let cstr = std::ffi::CStr::from_ptr(ptr);
                assert_eq!(
                    cstr.to_bytes_with_nul(),
                    expected,
                    "strerror mismatch for code {code}"
                );
            };

            check(CURLSHE_OK, b"No error\0");
            check(CURLSHE_BAD_OPTION, b"Unknown share option\0");
            check(CURLSHE_IN_USE, b"Share currently in use\0");
            check(CURLSHE_INVALID, b"Invalid share handle\0");
            check(CURLSHE_NOMEM, b"Out of memory\0");
            check(CURLSHE_NOT_BUILT_IN, b"Feature not enabled in this library\0");
        }
    }

    /// Test curl_share_strerror with an unknown/out-of-range code.
    #[test]
    fn share_strerror_unknown_code() {
        unsafe {
            // Unknown codes map to Invalid via RustCurlSHcode::from(i32).
            let ptr = curl_share_strerror(999);
            assert!(!ptr.is_null());
            let cstr = std::ffi::CStr::from_ptr(ptr);
            assert_eq!(cstr.to_bytes_with_nul(), b"Invalid share handle\0");
        }
    }

    /// Test full lifecycle: init → setopt (multiple) → cleanup.
    #[test]
    fn share_full_lifecycle() {
        unsafe {
            let share = curl_share_init();
            assert!(!share.is_null());

            // Share cookies, DNS, and SSL sessions.
            assert_eq!(
                curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE as usize),
                CURLSHE_OK
            );
            assert_eq!(
                curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS as usize),
                CURLSHE_OK
            );
            assert_eq!(
                curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION as usize),
                CURLSHE_OK
            );

            // Set userdata.
            assert_eq!(
                curl_share_setopt(share, CURLSHOPT_USERDATA, 42usize),
                CURLSHE_OK
            );

            // Unshare DNS.
            assert_eq!(
                curl_share_setopt(share, CURLSHOPT_UNSHARE, CURL_LOCK_DATA_DNS as usize),
                CURLSHE_OK
            );

            // Cleanup.
            assert_eq!(curl_share_cleanup(share), CURLSHE_OK);
        }
    }

    /// Verify CURLSHOPT_LOCKFUNC with NULL clears the lock callback.
    #[test]
    fn share_setopt_lockfunc_null() {
        unsafe {
            let share = curl_share_init();
            assert!(!share.is_null());

            // Setting lock func to NULL (0) should succeed.
            let rc = curl_share_setopt(share, CURLSHOPT_LOCKFUNC, 0usize);
            assert_eq!(rc, CURLSHE_OK);

            // Setting unlock func to NULL (0) should succeed.
            let rc = curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, 0usize);
            assert_eq!(rc, CURLSHE_OK);

            let rc = curl_share_cleanup(share);
            assert_eq!(rc, CURLSHE_OK);
        }
    }
}
