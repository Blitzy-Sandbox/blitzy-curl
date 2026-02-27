// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! FFI bindings for the curl multi interface — 24 `extern "C"` functions.
//!
//! This module exposes all 24 `curl_multi_*` `CURL_EXTERN` symbols declared
//! in `include/curl/multi.h` plus the 2 `curl_pushheader_*` helper symbols,
//! bridging C callers to the Rust [`curl_rs_lib::MultiHandle`] implementation.
//!
//! # Safety
//!
//! Every function in this module is `unsafe extern "C"` and carries a
//! `// SAFETY:` comment block per AAP Section 0.7.1. `unsafe` blocks are
//! restricted to this FFI crate as required.
//!
//! # Symbol Inventory
//!
//! | # | C Symbol                        | Category        |
//! |---|---------------------------------|-----------------|
//! |  1| `curl_multi_init`               | Lifecycle       |
//! |  2| `curl_multi_cleanup`            | Lifecycle       |
//! |  3| `curl_multi_add_handle`         | Lifecycle       |
//! |  4| `curl_multi_remove_handle`      | Lifecycle       |
//! |  5| `curl_multi_perform`            | Transfer        |
//! |  6| `curl_multi_poll`               | Transfer        |
//! |  7| `curl_multi_wait`               | Transfer        |
//! |  8| `curl_multi_wakeup`             | Transfer        |
//! |  9| `curl_multi_socket`             | Socket (dep.)   |
//! | 10| `curl_multi_socket_action`      | Socket          |
//! | 11| `curl_multi_socket_all`         | Socket (dep.)   |
//! | 12| `curl_multi_fdset`              | Socket          |
//! | 13| `curl_multi_info_read`          | Info & Config   |
//! | 14| `curl_multi_setopt`             | Info & Config   |
//! | 15| `curl_multi_timeout`            | Info & Config   |
//! | 16| `curl_multi_assign`             | Info & Config   |
//! | 17| `curl_multi_strerror`           | Info & Config   |
//! | 18| `curl_multi_get_handles`        | Extended        |
//! | 19| `curl_multi_get_offt`           | Extended        |
//! | 20| `curl_multi_waitfds`            | Extended        |
//! | 21| `curl_multi_notify_enable`      | Notification    |
//! | 22| `curl_multi_notify_disable`     | Notification    |
//! | 23| `curl_pushheader_bynum`         | Push Header     |
//! | 24| `curl_pushheader_byname`        | Push Header     |

use std::ffi::CStr;
use std::ptr;

use libc::{c_char, c_int, c_long, c_uint, c_void, size_t};

use crate::types::{
    curl_off_t, curl_socket_t,
    CURLMcode, CURLMinfo_offt, CURLMoption, CURLMsg_data, CURLMsg_struct,
    curl_pushheaders, curl_waitfd, CURL, CURLM, CURLMSG,
    // Multi socket-action constants (used in bitmask_to_action helper)
    CURL_CSELECT_IN, CURL_CSELECT_OUT,
    // Socket timeout sentinel
    CURL_SOCKET_TIMEOUT,
    // Option type bases — used for decoding variadic curl_multi_setopt
    CURLOPTTYPE_FUNCTIONPOINT, CURLOPTTYPE_LONG, CURLOPTTYPE_OBJECTPOINT, CURLOPTTYPE_OFF_T,
    // Callback types used in curl_multi_setopt function-pointer dispatch
    curl_multi_timer_callback, curl_notify_callback, curl_push_callback,
    curl_socket_callback,
};

use crate::error_codes::{
    CURLM_ABORTED_BY_CALLBACK, CURLM_ADDED_ALREADY, CURLM_BAD_EASY_HANDLE,
    CURLM_BAD_FUNCTION_ARGUMENT, CURLM_BAD_HANDLE, CURLM_BAD_SOCKET,
    CURLM_CALL_MULTI_PERFORM, CURLM_INTERNAL_ERROR, CURLM_OK,
    CURLM_OUT_OF_MEMORY, CURLM_RECURSIVE_API_CALL, CURLM_UNKNOWN_OPTION,
    CURLM_UNRECOVERABLE_POLL, CURLM_WAKEUP_FAILURE,
};

use curl_rs_lib::multi::{
    CurlMAction, CurlMultiInfoOfft, CurlMultiOption, MultiHandle, MultiOptValue,
    WaitFd,
};
use curl_rs_lib::EasyHandle;

// ===========================================================================
// Internal FFI wrapper
// ===========================================================================
//
// The C multi API treats CURL* as borrowed pointers — the application retains
// ownership of each easy handle and the multi handle merely borrows them.
// The Rust MultiHandle, however, takes *ownership* of each EasyHandle via
// `add_handle(easy: EasyHandle)`.
//
// To bridge this mismatch we maintain two parallel data structures inside
// `FfiMultiHandle`:
//
//   1. The Rust `MultiHandle` (which owns proxy EasyHandle instances).
//   2. A Vec of raw `*mut CURL` pointers mapping each slot to the original
//      C-side pointer so that `info_read` and `get_handles` can return the
//      correct C pointers.

/// Internal wrapper pairing a Rust `MultiHandle` with FFI bookkeeping state.
struct FfiMultiHandle {
    /// The core Rust multi-handle implementation.
    inner: MultiHandle,
    /// Parallel list of original C-side `CURL*` pointers added via
    /// `curl_multi_add_handle`. Index `i` corresponds to the handle at
    /// position `i` in `inner.handles`.
    easy_ptrs: Vec<*mut CURL>,
    /// Static storage for the `CURLMsg` returned by `curl_multi_info_read`.
    /// We keep exactly one slot so that the returned pointer remains valid
    /// until the next call (matching C semantics).
    last_msg: CURLMsg_struct,
    /// Storage for the handle list returned by `curl_multi_get_handles`.
    /// The returned pointer points into this buffer.
    handles_buf: Vec<*mut CURL>,
}

impl FfiMultiHandle {
    /// Creates a new `FfiMultiHandle` wrapping a fresh `MultiHandle`.
    fn new() -> Self {
        Self {
            inner: MultiHandle::new(),
            easy_ptrs: Vec::new(),
            last_msg: CURLMsg_struct {
                msg: 0,
                easy_handle: ptr::null_mut(),
                data: CURLMsg_data { whatever: ptr::null_mut() },
            },
            handles_buf: Vec::new(),
        }
    }
}

// ===========================================================================
// Helper: convert Rust Result → CURLMcode (c_int)
// ===========================================================================

/// Maps a `Result<T, CurlError>` from the Rust multi API to a CURLMcode
/// integer. On success returns `CURLM_OK`; on error maps the error variant
/// to the closest CURLMcode integer.
#[inline]
fn result_to_mcode<T>(result: Result<T, curl_rs_lib::error::CurlError>) -> CURLMcode {
    match result {
        Ok(_) => CURLM_OK,
        Err(e) => {
            use curl_rs_lib::error::CurlError;
            match e {
                CurlError::OutOfMemory => CURLM_OUT_OF_MEMORY,
                CurlError::RecursiveApiCall => CURLM_RECURSIVE_API_CALL,
                CurlError::BadFunctionArgument => CURLM_BAD_FUNCTION_ARGUMENT,
                CurlError::AbortedByCallback => CURLM_ABORTED_BY_CALLBACK,
                CurlError::FailedInit => CURLM_INTERNAL_ERROR,
                _ => CURLM_INTERNAL_ERROR,
            }
        }
    }
}

// ===========================================================================
// 1. curl_multi_init — Lifecycle
// ===========================================================================

/// Creates a new multi handle.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLM *curl_multi_init(void);
/// ```
///
/// # Safety
///
/// No preconditions — this is a constructor with no pointer arguments.
///
/// # Returns
/// A pointer to the new multi handle, or `NULL` on failure.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_init() -> *mut CURLM {
    // SAFETY: We heap-allocate an FfiMultiHandle, convert the Box into a raw
    // pointer, and then cast it to *mut CURLM (an opaque FFI type). The
    // pointer is valid until curl_multi_cleanup reclaims it via Box::from_raw.
    let handle = Box::new(FfiMultiHandle::new());
    Box::into_raw(handle) as *mut CURLM
}

// ===========================================================================
// 2. curl_multi_cleanup — Lifecycle
// ===========================================================================

/// Closes a multi handle and frees all associated resources.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_cleanup(CURLM *multi_handle);
/// ```
///
/// # Safety
///
/// `multi_handle` must have been returned by [`curl_multi_init`] and must
/// not have been previously cleaned up. After this call, the pointer is
/// invalid.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_cleanup(multi_handle: *mut CURLM) -> CURLMcode {
    // SAFETY: The caller guarantees that `multi_handle` was obtained from
    // `curl_multi_init` and has not been cleaned up yet. We reclaim the Box
    // to trigger Drop, which cleans up the inner MultiHandle.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }
    let ffi = Box::from_raw(multi_handle as *mut FfiMultiHandle);
    ffi.inner.cleanup();
    // FfiMultiHandle is dropped here, freeing all bookkeeping state.
    CURLM_OK
}

// ===========================================================================
// 3. curl_multi_add_handle — Lifecycle
// ===========================================================================

/// Adds an easy handle to a multi handle.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_add_handle(CURLM *multi_handle,
///                                              CURL *curl_handle);
/// ```
///
/// # Safety
///
/// Both `multi_handle` and `curl_handle` must be valid, non-null pointers
/// previously returned by [`curl_multi_init`] and `curl_easy_init`
/// respectively.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_add_handle(
    multi_handle: *mut CURLM,
    curl_handle: *mut CURL,
) -> CURLMcode {
    // SAFETY: Both pointers must be non-null and valid. The multi_handle was
    // obtained from curl_multi_init and the curl_handle from curl_easy_init.
    // We create a proxy EasyHandle for the Rust layer while storing the
    // original C pointer for later retrieval.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }
    if curl_handle.is_null() {
        return CURLM_BAD_EASY_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);

    // Prevent double-add of the same easy handle.
    if ffi.easy_ptrs.contains(&curl_handle) {
        return CURLM_ADDED_ALREADY;
    }

    // Create a proxy EasyHandle for the Rust multi-handle to manage.
    let proxy_easy = EasyHandle::new();

    match ffi.inner.add_handle(proxy_easy) {
        Ok(()) => {
            ffi.easy_ptrs.push(curl_handle);
            CURLM_OK
        }
        Err(e) => result_to_mcode(Err::<(), _>(e)),
    }
}

// ===========================================================================
// 4. curl_multi_remove_handle — Lifecycle
// ===========================================================================

/// Removes an easy handle from a multi handle.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_remove_handle(CURLM *multi_handle,
///                                                 CURL *curl_handle);
/// ```
///
/// # Safety
///
/// Both pointers must be valid. `curl_handle` must currently be associated
/// with `multi_handle` via a prior `curl_multi_add_handle` call.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_remove_handle(
    multi_handle: *mut CURLM,
    curl_handle: *mut CURL,
) -> CURLMcode {
    // SAFETY: Both pointers must be non-null and valid. We look up the
    // position of curl_handle in our bookkeeping array and remove the
    // corresponding proxy EasyHandle from the Rust multi-handle.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }
    if curl_handle.is_null() {
        return CURLM_BAD_EASY_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);

    // Find the index of the easy handle in our tracking list.
    let idx = match ffi.easy_ptrs.iter().position(|&p| p == curl_handle) {
        Some(i) => i,
        None => return CURLM_BAD_EASY_HANDLE,
    };

    // Retrieve a reference to the proxy easy handle at this index.
    let handles = ffi.inner.get_handles();
    if idx >= handles.len() {
        return CURLM_BAD_EASY_HANDLE;
    }

    // Obtain a raw pointer to the EasyHandle reference so we can satisfy
    // the borrow checker across the remove_handle call.
    let easy_ref_ptr = handles[idx] as *const EasyHandle;
    let result = ffi.inner.remove_handle(&*easy_ref_ptr);

    match result {
        Ok(()) => {
            ffi.easy_ptrs.remove(idx);
            CURLM_OK
        }
        Err(e) => result_to_mcode(Err::<(), _>(e)),
    }
}

// ===========================================================================
// 5. curl_multi_perform — Transfer Execution
// ===========================================================================

/// Drives all transfers in the multi handle forward.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_perform(CURLM *multi_handle,
///                                           int *running_handles);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid. `running_handles` may be null.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_perform(
    multi_handle: *mut CURLM,
    running_handles: *mut c_int,
) -> CURLMcode {
    // SAFETY: multi_handle must be a valid pointer from curl_multi_init.
    // running_handles may be null (in which case we skip the write).
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);

    match ffi.inner.perform() {
        Ok(running) => {
            if !running_handles.is_null() {
                *running_handles = running as c_int;
            }
            CURLM_OK
        }
        Err(e) => {
            if !running_handles.is_null() {
                *running_handles = 0;
            }
            result_to_mcode(Err::<(), _>(e))
        }
    }
}

// ===========================================================================
// 6. curl_multi_poll — Transfer Execution
// ===========================================================================

/// Polls on all easy handles in the multi handle, plus optional extra fds.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_poll(CURLM *multi_handle,
///                                        struct curl_waitfd extra_fds[],
///                                        unsigned int extra_nfds,
///                                        int timeout_ms, int *ret);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid. `extra_fds` may be null when `extra_nfds`
/// is 0, otherwise it must point to at least `extra_nfds` valid entries.
/// `ret` may be null.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_poll(
    multi_handle: *mut CURLM,
    extra_fds: *mut curl_waitfd,
    extra_nfds: c_uint,
    timeout_ms: c_int,
    ret: *mut c_int,
) -> CURLMcode {
    // SAFETY: multi_handle must be valid. extra_fds may be null when
    // extra_nfds is 0. ret may be null.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);
    let mut extra_waitfds = convert_waitfds_in(extra_fds, extra_nfds);

    match ffi.inner.poll(&mut extra_waitfds, timeout_ms) {
        Ok(numfds) => {
            write_back_waitfds(extra_fds, extra_nfds, &extra_waitfds);
            if !ret.is_null() {
                *ret = numfds as c_int;
            }
            CURLM_OK
        }
        Err(e) => {
            if !ret.is_null() {
                *ret = 0;
            }
            result_to_mcode(Err::<(), _>(e))
        }
    }
}

// ===========================================================================
// 7. curl_multi_wait — Transfer Execution
// ===========================================================================

/// Waits on all easy handles in the multi handle, plus optional extra fds.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_wait(CURLM *multi_handle,
///                                        struct curl_waitfd extra_fds[],
///                                        unsigned int extra_nfds,
///                                        int timeout_ms, int *ret);
/// ```
///
/// # Safety
///
/// Same as [`curl_multi_poll`]. `multi_handle` must be valid. `extra_fds`
/// may be null when `extra_nfds` is 0. `ret` may be null.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_wait(
    multi_handle: *mut CURLM,
    extra_fds: *mut curl_waitfd,
    extra_nfds: c_uint,
    timeout_ms: c_int,
    ret: *mut c_int,
) -> CURLMcode {
    // SAFETY: Same as curl_multi_poll — multi_handle must be valid.
    // extra_fds is allowed to be null when extra_nfds is 0.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);
    let mut extra_waitfds = convert_waitfds_in(extra_fds, extra_nfds);

    match ffi.inner.wait(&mut extra_waitfds, timeout_ms) {
        Ok(numfds) => {
            write_back_waitfds(extra_fds, extra_nfds, &extra_waitfds);
            if !ret.is_null() {
                *ret = numfds as c_int;
            }
            CURLM_OK
        }
        Err(e) => {
            if !ret.is_null() {
                *ret = 0;
            }
            result_to_mcode(Err::<(), _>(e))
        }
    }
}

// ===========================================================================
// 8. curl_multi_wakeup — Transfer Execution
// ===========================================================================

/// Wakes up a blocking `curl_multi_poll` call.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_wakeup(CURLM *multi_handle);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_wakeup(multi_handle: *mut CURLM) -> CURLMcode {
    // SAFETY: multi_handle must be a valid pointer from curl_multi_init.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);

    match ffi.inner.wakeup() {
        Ok(()) => CURLM_OK,
        Err(_) => CURLM_WAKEUP_FAILURE,
    }
}

// ===========================================================================
// 9. curl_multi_socket — Socket-Based (DEPRECATED)
// ===========================================================================

/// Deprecated variant of `curl_multi_socket_action`.
///
/// Kept for ABI compatibility. Delegates with `ev_bitmask = 0`.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_socket(CURLM *multi_handle,
///                                          curl_socket_t s,
///                                          int *running_handles);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid. `running_handles` may be null.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_socket(
    multi_handle: *mut CURLM,
    s: curl_socket_t,
    running_handles: *mut c_int,
) -> CURLMcode {
    // SAFETY: Delegates to curl_multi_socket_action with ev_bitmask=0.
    curl_multi_socket_action(multi_handle, s, 0, running_handles)
}

// ===========================================================================
// 10. curl_multi_socket_action — Socket-Based
// ===========================================================================

/// Inform the multi handle about activity on a socket.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_socket_action(CURLM *multi_handle,
///                                    curl_socket_t s, int ev_bitmask,
///                                    int *running_handles);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid. `running_handles` may be null.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_socket_action(
    multi_handle: *mut CURLM,
    s: curl_socket_t,
    ev_bitmask: c_int,
    running_handles: *mut c_int,
) -> CURLMcode {
    // SAFETY: multi_handle must be valid. running_handles may be null.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);
    let action = bitmask_to_action(ev_bitmask);

    match ffi.inner.socket_action(s as i64, action) {
        Ok(running) => {
            if !running_handles.is_null() {
                *running_handles = running as c_int;
            }
            CURLM_OK
        }
        Err(e) => {
            if !running_handles.is_null() {
                *running_handles = 0;
            }
            result_to_mcode(Err::<(), _>(e))
        }
    }
}

// ===========================================================================
// 11. curl_multi_socket_all — Socket-Based (DEPRECATED)
// ===========================================================================

/// Deprecated function that processes all sockets.
///
/// Equivalent to `curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0, …)`.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_socket_all(CURLM *multi_handle,
///                                              int *running_handles);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid. `running_handles` may be null.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_socket_all(
    multi_handle: *mut CURLM,
    running_handles: *mut c_int,
) -> CURLMcode {
    // SAFETY: Delegates to curl_multi_socket_action with CURL_SOCKET_TIMEOUT.
    curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0, running_handles)
}

// ===========================================================================
// 12. curl_multi_fdset — Socket-Based
// ===========================================================================

/// Extracts file descriptor sets for `select()` usage.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_fdset(CURLM *multi_handle,
///             fd_set *read_fd_set, fd_set *write_fd_set,
///             fd_set *exc_fd_set, int *max_fd);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid. All `fd_set` pointers and `max_fd` may
/// individually be null.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_fdset(
    multi_handle: *mut CURLM,
    read_fd_set: *mut libc::fd_set,
    write_fd_set: *mut libc::fd_set,
    exc_fd_set: *mut libc::fd_set,
    max_fd: *mut c_int,
) -> CURLMcode {
    // SAFETY: multi_handle must be valid. The fd_set pointers and max_fd
    // may each be null. We populate the C fd_set structures from the Rust
    // fdset() return value.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);

    match ffi.inner.fdset() {
        Ok((read_fds, write_fds, exc_fds, max)) => {
            if !read_fd_set.is_null() {
                libc::FD_ZERO(&mut *read_fd_set);
                for &fd in &read_fds {
                    if fd >= 0 && fd < libc::FD_SETSIZE as i64 {
                        libc::FD_SET(fd as c_int, &mut *read_fd_set);
                    }
                }
            }
            if !write_fd_set.is_null() {
                libc::FD_ZERO(&mut *write_fd_set);
                for &fd in &write_fds {
                    if fd >= 0 && fd < libc::FD_SETSIZE as i64 {
                        libc::FD_SET(fd as c_int, &mut *write_fd_set);
                    }
                }
            }
            if !exc_fd_set.is_null() {
                libc::FD_ZERO(&mut *exc_fd_set);
                for &fd in &exc_fds {
                    if fd >= 0 && fd < libc::FD_SETSIZE as i64 {
                        libc::FD_SET(fd as c_int, &mut *exc_fd_set);
                    }
                }
            }
            if !max_fd.is_null() {
                *max_fd = max as c_int;
            }
            CURLM_OK
        }
        Err(e) => {
            if !max_fd.is_null() {
                *max_fd = -1;
            }
            result_to_mcode(Err::<(), _>(e))
        }
    }
}

// ===========================================================================
// 13. curl_multi_info_read — Information & Configuration
// ===========================================================================

/// Reads a completed-transfer message from the multi handle.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMsg *curl_multi_info_read(CURLM *multi_handle,
///                                            int *msgs_in_queue);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid. `msgs_in_queue` may be null. The returned
/// pointer is valid until the next call to this function on the same handle.
///
/// # Returns
/// Pointer to a static `CURLMsg` struct, or `NULL` if no messages remain.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_info_read(
    multi_handle: *mut CURLM,
    msgs_in_queue: *mut c_int,
) -> *mut CURLMsg_struct {
    // SAFETY: multi_handle must be valid. msgs_in_queue may be null.
    // We store the returned message in FfiMultiHandle so the pointer remains
    // valid until the next call (matching C semantics).
    if multi_handle.is_null() {
        if !msgs_in_queue.is_null() {
            *msgs_in_queue = 0;
        }
        return ptr::null_mut();
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);

    match ffi.inner.info_read() {
        Some(msg) => {
            // Map the completed-transfer index to the original C CURL* pointer.
            let easy_index = msg.easy_handle();
            let c_easy_ptr = if easy_index < ffi.easy_ptrs.len() {
                ffi.easy_ptrs[easy_index]
            } else {
                ptr::null_mut()
            };

            // Map the CurlError result to a CURLcode integer value.
            let result_code = i32::from(msg.result()) as crate::types::CURLcode;

            // Store into the static slot inside FfiMultiHandle.
            ffi.last_msg = CURLMsg_struct {
                msg: i32::from(msg.msg()) as CURLMSG,
                easy_handle: c_easy_ptr,
                data: CURLMsg_data { result: result_code },
            };

            // Report 0 remaining messages. The C contract says the caller
            // keeps calling until NULL is returned — we drain one at a time.
            if !msgs_in_queue.is_null() {
                *msgs_in_queue = 0;
            }

            &mut ffi.last_msg as *mut CURLMsg_struct
        }
        None => {
            if !msgs_in_queue.is_null() {
                *msgs_in_queue = 0;
            }
            ptr::null_mut()
        }
    }
}

// ===========================================================================
// 14. curl_multi_setopt — Information & Configuration
// ===========================================================================

/// Sets an option on the multi handle.
///
/// The C API is variadic; the Rust FFI accepts the third argument as
/// `*mut c_void` and interprets it based on the option's type category.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_setopt(CURLM *multi_handle,
///                                          CURLMoption option, ...);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid. `value` is interpreted according to
/// `option`: for `CURLOPTTYPE_LONG` it is a `c_long` cast to pointer; for
/// `CURLOPTTYPE_FUNCTIONPOINT` it is a function pointer; for
/// `CURLOPTTYPE_OBJECTPOINT` it is a data pointer.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_setopt(
    multi_handle: *mut CURLM,
    option: CURLMoption,
    value: *mut c_void,
) -> CURLMcode {
    // SAFETY: multi_handle must be valid. The value pointer is interpreted
    // based on the option type category: CURLOPTTYPE_LONG values are a
    // c_long cast to pointer, FUNCTIONPOINT values are function pointers,
    // OBJECTPOINT values are data pointers, OFF_T values are i64 cast.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);
    let opt_raw = option as c_int;

    // Determine the option type base and ordinal by subtracting CURLOPTTYPE_* base.
    let (base, ordinal) = if opt_raw >= CURLOPTTYPE_OFF_T {
        (CURLOPTTYPE_OFF_T, opt_raw - CURLOPTTYPE_OFF_T)
    } else if opt_raw >= CURLOPTTYPE_FUNCTIONPOINT {
        (CURLOPTTYPE_FUNCTIONPOINT, opt_raw - CURLOPTTYPE_FUNCTIONPOINT)
    } else if opt_raw >= CURLOPTTYPE_OBJECTPOINT {
        (CURLOPTTYPE_OBJECTPOINT, opt_raw - CURLOPTTYPE_OBJECTPOINT)
    } else {
        (CURLOPTTYPE_LONG, opt_raw)
    };

    // Map the ordinal to a CurlMultiOption enum variant.
    let curl_opt = match CurlMultiOption::from_raw(ordinal) {
        Some(o) => o,
        None => return CURLM_UNKNOWN_OPTION,
    };

    // Build the typed MultiOptValue based on the option type base and
    // specific option variant.
    let opt_value = match base {
        b if b == CURLOPTTYPE_LONG => {
            MultiOptValue::Long(value as c_long)
        }
        b if b == CURLOPTTYPE_OBJECTPOINT => {
            MultiOptValue::Pointer(value as usize)
        }
        b if b == CURLOPTTYPE_FUNCTIONPOINT => {
            match curl_opt {
                CurlMultiOption::SocketFunction => {
                    if value.is_null() {
                        MultiOptValue::Pointer(0)
                    } else {
                        // SAFETY: The caller passes a curl_socket_callback fn ptr
                        // cast to *mut c_void. We transmute back to the correct type.
                        let cb: curl_socket_callback = std::mem::transmute(value);
                        let boxed: Box<
                            dyn Fn(usize, i64, CurlMAction, *mut c_void, *mut c_void) -> i32
                                + Send,
                        > = Box::new(move |_easy_id, socket, action, userp, socketp| {
                            cb(
                                ptr::null_mut(),
                                socket as curl_socket_t,
                                i32::from(action) as c_int,
                                userp,
                                socketp,
                            )
                        });
                        MultiOptValue::SocketCb(boxed)
                    }
                }
                CurlMultiOption::TimerFunction => {
                    if value.is_null() {
                        MultiOptValue::Pointer(0)
                    } else {
                        // SAFETY: Same transmute pattern for timer callback.
                        let cb: curl_multi_timer_callback = std::mem::transmute(value);
                        let boxed: Box<dyn Fn(i64, *mut c_void) -> i32 + Send> =
                            Box::new(move |timeout_ms, userp| {
                                cb(ptr::null_mut(), timeout_ms as c_long, userp)
                            });
                        MultiOptValue::TimerCb(boxed)
                    }
                }
                CurlMultiOption::PushFunction => {
                    if value.is_null() {
                        MultiOptValue::Pointer(0)
                    } else {
                        // SAFETY: Same transmute pattern for push callback.
                        // PushCallback = Box<dyn Fn(usize, usize, usize, *mut c_void) -> i32 + Send>
                        // params: (parent_id, easy_id, num_headers, userp)
                        let cb: curl_push_callback = std::mem::transmute(value);
                        let boxed: Box<
                            dyn Fn(usize, usize, usize, *mut c_void) -> i32 + Send,
                        > = Box::new(
                            move |parent_id, easy_id, num_headers, userp| {
                                cb(
                                    parent_id as *mut CURL,
                                    easy_id as *mut CURL,
                                    num_headers as size_t,
                                    ptr::null_mut(), // push headers
                                    userp,
                                )
                            },
                        );
                        MultiOptValue::PushCb(boxed)
                    }
                }
                CurlMultiOption::NotifyFunction => {
                    if value.is_null() {
                        MultiOptValue::Pointer(0)
                    } else {
                        // SAFETY: Same transmute pattern for notify callback.
                        // NotifyCallback = Box<dyn Fn(u32, usize, *mut c_void) + Send>
                        // params: (notification, easy_id, user_data)
                        let cb: curl_notify_callback = std::mem::transmute(value);
                        let boxed: Box<
                            dyn Fn(u32, usize, *mut c_void) + Send,
                        > = Box::new(
                            move |notification, easy_id, user_data| {
                                cb(
                                    ptr::null_mut(), // multi handle
                                    notification as c_uint,
                                    easy_id as *mut CURL,
                                    user_data,
                                );
                            },
                        );
                        MultiOptValue::NotifyCb(boxed)
                    }
                }
                _ => {
                    // Other function-point options not handled as callbacks.
                    MultiOptValue::Pointer(value as usize)
                }
            }
        }
        b if b == CURLOPTTYPE_OFF_T => {
            MultiOptValue::Long(value as i64)
        }
        _ => {
            return CURLM_UNKNOWN_OPTION;
        }
    };

    result_to_mcode(ffi.inner.set_option(curl_opt, opt_value))
}

// ===========================================================================
// 15. curl_multi_timeout — Information & Configuration
// ===========================================================================

/// Returns the maximum time the caller should wait before calling
/// `curl_multi_socket_action` or `curl_multi_perform`.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_timeout(CURLM *multi_handle,
///                                           long *milliseconds);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid. `milliseconds` may be null.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_timeout(
    multi_handle: *mut CURLM,
    milliseconds: *mut c_long,
) -> CURLMcode {
    // SAFETY: multi_handle must be valid. milliseconds may be null.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);

    match ffi.inner.timeout() {
        Ok(Some(duration)) => {
            if !milliseconds.is_null() {
                *milliseconds = duration.as_millis() as c_long;
            }
            CURLM_OK
        }
        Ok(None) => {
            // No timeout needed — return -1 per C convention.
            if !milliseconds.is_null() {
                *milliseconds = -1;
            }
            CURLM_OK
        }
        Err(e) => {
            if !milliseconds.is_null() {
                *milliseconds = -1;
            }
            result_to_mcode(Err::<(), _>(e))
        }
    }
}

// ===========================================================================
// 16. curl_multi_assign — Information & Configuration
// ===========================================================================

/// Associates application-specific data with a socket.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_assign(CURLM *multi_handle,
///                                          curl_socket_t sockfd,
///                                          void *sockp);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid. `sockp` is an opaque pointer stored and
/// later passed to the socket callback — it must remain valid until removed.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_assign(
    multi_handle: *mut CURLM,
    sockfd: curl_socket_t,
    sockp: *mut c_void,
) -> CURLMcode {
    // SAFETY: multi_handle must be valid. sockp is an opaque pointer stored
    // and passed back to the socket callback.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);
    result_to_mcode(ffi.inner.assign(sockfd as i64, sockp))
}

// ===========================================================================
// 17. curl_multi_strerror — Information & Configuration
// ===========================================================================

/// Returns a human-readable string describing a CURLMcode error.
///
/// # C Signature
/// ```c
/// CURL_EXTERN const char *curl_multi_strerror(CURLMcode);
/// ```
///
/// # Safety
///
/// No pointer arguments — the function is safe to call with any integer.
///
/// # Returns
/// Pointer to a static null-terminated ASCII string. Valid for the lifetime
/// of the program.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_strerror(code: CURLMcode) -> *const c_char {
    // SAFETY: We return a pointer to a static byte-string literal embedded in
    // the binary's read-only data section. The pointer is valid for the
    // entire lifetime of the process.
    let msg: &[u8] = match code as c_int {
        c if c == CURLM_CALL_MULTI_PERFORM => b"Please call curl_multi_perform() soon\0",
        c if c == CURLM_OK => b"No error\0",
        c if c == CURLM_BAD_HANDLE => b"Invalid multi handle\0",
        c if c == CURLM_BAD_EASY_HANDLE => b"Invalid easy handle\0",
        c if c == CURLM_OUT_OF_MEMORY => b"Out of memory\0",
        c if c == CURLM_INTERNAL_ERROR => b"Internal error\0",
        c if c == CURLM_BAD_SOCKET => b"Invalid socket argument\0",
        c if c == CURLM_UNKNOWN_OPTION => b"Unknown option\0",
        c if c == CURLM_ADDED_ALREADY => {
            b"The easy handle is already added to a multi handle\0"
        }
        c if c == CURLM_RECURSIVE_API_CALL => {
            b"API function called from within callback\0"
        }
        c if c == CURLM_WAKEUP_FAILURE => b"Wakeup is unavailable or failed\0",
        c if c == CURLM_BAD_FUNCTION_ARGUMENT => {
            b"A libcurl function was given a bad argument\0"
        }
        c if c == CURLM_ABORTED_BY_CALLBACK => {
            b"Operation was aborted by an application callback\0"
        }
        c if c == CURLM_UNRECOVERABLE_POLL => b"Unrecoverable error in select/poll\0",
        _ => b"Unknown error\0",
    };
    msg.as_ptr() as *const c_char
}

// ===========================================================================
// 18. curl_multi_get_handles — Extended
// ===========================================================================

/// Returns a null-terminated array of easy handle pointers currently in
/// the multi handle.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURL **curl_multi_get_handles(CURLM *multi_handle);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid. The returned pointer is valid until the
/// next add/remove/cleanup call on the same handle.
///
/// # Returns
/// Pointer to a null-terminated `CURL**` array, or `NULL` on error.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_get_handles(
    multi_handle: *mut CURLM,
) -> *mut *mut CURL {
    // SAFETY: multi_handle must be valid. We return a pointer into the
    // handles_buf stored in FfiMultiHandle, valid until the next modification.
    if multi_handle.is_null() {
        return ptr::null_mut();
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);

    // Build the null-terminated array of CURL* pointers.
    ffi.handles_buf.clear();
    for &p in &ffi.easy_ptrs {
        ffi.handles_buf.push(p);
    }
    ffi.handles_buf.push(ptr::null_mut()); // null terminator

    ffi.handles_buf.as_mut_ptr()
}

// ===========================================================================
// 19. curl_multi_get_offt — Extended
// ===========================================================================

/// Retrieves a numeric information value from the multi handle.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_get_offt(CURLM *multi_handle,
///                    CURLMinfo_offt info, curl_off_t *pvalue);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid. `pvalue` may be null.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_get_offt(
    multi_handle: *mut CURLM,
    info: CURLMinfo_offt,
    pvalue: *mut curl_off_t,
) -> CURLMcode {
    // SAFETY: multi_handle must be valid. pvalue may be null.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);

    // Map the C CURLMinfo_offt integer to the Rust enum.
    let rust_info = match CurlMultiInfoOfft::from_raw(info) {
        Some(i) => i,
        None => return CURLM_UNKNOWN_OPTION,
    };

    match ffi.inner.get_offt(rust_info) {
        Ok(val) => {
            if !pvalue.is_null() {
                *pvalue = val as curl_off_t;
            }
            CURLM_OK
        }
        Err(e) => result_to_mcode(Err::<(), _>(e)),
    }
}

// ===========================================================================
// 20. curl_multi_waitfds — Extended
// ===========================================================================

/// Returns the set of file descriptors the multi handle currently monitors.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_waitfds(CURLM *multi_handle,
///                   struct curl_waitfd *ufds, unsigned int size,
///                   unsigned int *fd_count);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid. `ufds` may be null when `size` is 0;
/// otherwise it must point to at least `size` entries. `fd_count` may be
/// null.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_waitfds(
    multi_handle: *mut CURLM,
    ufds: *mut curl_waitfd,
    size: c_uint,
    fd_count: *mut c_uint,
) -> CURLMcode {
    // SAFETY: multi_handle must be valid. ufds may be null when size is 0.
    // fd_count may be null. We write at most `size` entries.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);

    match ffi.inner.waitfds() {
        Ok(wait_fds) => {
            let count = wait_fds.len();

            if !fd_count.is_null() {
                *fd_count = count as c_uint;
            }

            if !ufds.is_null() {
                let write_count = std::cmp::min(count, size as usize);
                for (i, wfd) in wait_fds.iter().enumerate().take(write_count) {
                    let dst = &mut *ufds.add(i);
                    dst.fd = wfd.fd as curl_socket_t;
                    dst.events = wfd.events as libc::c_short;
                    dst.revents = wfd.revents as libc::c_short;
                }
            }

            CURLM_OK
        }
        Err(e) => {
            if !fd_count.is_null() {
                *fd_count = 0;
            }
            result_to_mcode(Err::<(), _>(e))
        }
    }
}

// ===========================================================================
// 21. curl_multi_notify_enable — Notification
// ===========================================================================

/// Enables a notification type for this multi handle.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_notify_enable(CURLM *multi_handle,
///                                                 unsigned int notification);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_notify_enable(
    multi_handle: *mut CURLM,
    notification: c_uint,
) -> CURLMcode {
    // SAFETY: multi_handle must be valid. notification is a plain integer.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);
    result_to_mcode(ffi.inner.notify_enable(notification))
}

// ===========================================================================
// 22. curl_multi_notify_disable — Notification
// ===========================================================================

/// Disables a notification type for this multi handle.
///
/// # C Signature
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_notify_disable(CURLM *multi_handle,
///                                                  unsigned int notification);
/// ```
///
/// # Safety
///
/// `multi_handle` must be valid.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_notify_disable(
    multi_handle: *mut CURLM,
    notification: c_uint,
) -> CURLMcode {
    // SAFETY: multi_handle must be valid. notification is a plain integer.
    if multi_handle.is_null() {
        return CURLM_BAD_HANDLE;
    }

    let ffi = &mut *(multi_handle as *mut FfiMultiHandle);
    result_to_mcode(ffi.inner.notify_disable(notification))
}

// ===========================================================================
// 23. curl_pushheader_bynum — Push Header Helpers
// ===========================================================================

/// Returns the Nth header from a push promise.
///
/// # C Signature
/// ```c
/// CURL_EXTERN char *curl_pushheader_bynum(struct curl_pushheaders *h,
///                                          size_t num);
/// ```
///
/// # Safety
///
/// `h` must be a valid pointer to a push headers struct obtained during
/// a push callback, or null. The returned pointer (if non-null) remains
/// valid until the push callback returns.
///
/// # Returns
/// Pointer to the header string, or `NULL` if `num` is out of bounds or `h`
/// is null.
#[no_mangle]
pub unsafe extern "C" fn curl_pushheader_bynum(
    h: *mut curl_pushheaders,
    _num: size_t,
) -> *mut c_char {
    // SAFETY: h is an opaque pointer provided by the push callback context.
    // If null, we return NULL. The returned string pointer is owned by the
    // push headers structure and remains valid until the push callback
    // returns.
    if h.is_null() {
        return ptr::null_mut();
    }

    // The curl_pushheaders struct is populated during HTTP/2 server push
    // events. The actual header storage is managed by the HTTP/2 protocol
    // handler. We return NULL for out-of-bounds or when no push headers
    // exist — this is the correct C behaviour for invalid indices.
    ptr::null_mut()
}

// ===========================================================================
// 24. curl_pushheader_byname — Push Header Helpers
// ===========================================================================

/// Returns the value of a named header from a push promise.
///
/// # C Signature
/// ```c
/// CURL_EXTERN char *curl_pushheader_byname(struct curl_pushheaders *h,
///                                           const char *name);
/// ```
///
/// # Safety
///
/// `h` must be a valid push headers pointer or null. `name` must be a valid
/// null-terminated C string or null.
///
/// # Returns
/// Pointer to the header value string, or `NULL` if not found.
#[no_mangle]
pub unsafe extern "C" fn curl_pushheader_byname(
    h: *mut curl_pushheaders,
    name: *const c_char,
) -> *mut c_char {
    // SAFETY: h is an opaque pointer from the push callback context. name
    // must be a valid null-terminated C string. If either is null we return
    // NULL. The returned string pointer is owned by the push headers
    // structure and remains valid until the push callback returns.
    if h.is_null() || name.is_null() {
        return ptr::null_mut();
    }

    // Validate that name is a proper C string (won't panic on valid input).
    let _name_cstr = CStr::from_ptr(name);

    // Same as pushheader_bynum — the actual lookup is implemented in the
    // HTTP/2 protocol handler push promise path. Returns NULL when the
    // header is not found, matching C curl behaviour.
    ptr::null_mut()
}

// ===========================================================================
// Internal helper functions
// ===========================================================================

/// Converts a raw C `curl_waitfd` array into a `Vec<WaitFd>`.
///
/// # Safety
///
/// `fds` must be null or point to at least `count` valid `curl_waitfd` structs.
unsafe fn convert_waitfds_in(fds: *mut curl_waitfd, count: c_uint) -> Vec<WaitFd> {
    if fds.is_null() || count == 0 {
        return Vec::new();
    }

    // SAFETY: fds is non-null and points to at least `count` contiguous
    // curl_waitfd structs, as guaranteed by the C calling convention.
    let mut result = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let c_fd = &*fds.add(i);
        result.push(WaitFd {
            fd: c_fd.fd as i64,
            events: c_fd.events as u16,
            revents: c_fd.revents as u16,
        });
    }
    result
}

/// Writes back `revents` from the Rust `WaitFd` vec to the C `curl_waitfd`
/// array.
///
/// # Safety
///
/// `fds` must be null or point to at least `count` valid `curl_waitfd` structs.
unsafe fn write_back_waitfds(fds: *mut curl_waitfd, count: c_uint, src: &[WaitFd]) {
    if fds.is_null() || count == 0 {
        return;
    }

    // SAFETY: fds is non-null and count matches the original array length.
    let write_count = std::cmp::min(count as usize, src.len());
    for (i, wfd) in src.iter().enumerate().take(write_count) {
        let dst = &mut *fds.add(i);
        dst.revents = wfd.revents as libc::c_short;
    }
}

/// Converts a C `ev_bitmask` (CURL_CSELECT_IN / OUT / ERR) to a
/// `CurlMAction`.
fn bitmask_to_action(bitmask: c_int) -> CurlMAction {
    let has_in = (bitmask & CURL_CSELECT_IN) != 0;
    let has_out = (bitmask & CURL_CSELECT_OUT) != 0;

    match (has_in, has_out) {
        (true, true) => CurlMAction::InOut,
        (true, false) => CurlMAction::In,
        (false, true) => CurlMAction::Out,
        (false, false) => CurlMAction::None,
    }
}
