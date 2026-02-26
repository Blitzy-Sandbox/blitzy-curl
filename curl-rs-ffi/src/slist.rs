//! FFI bindings for the `curl_slist_*` family of functions.
//!
//! This module exposes the 2 `CURL_EXTERN` symbols from `include/curl/curl.h`
//! that manage singly-linked lists of C strings:
//!
//! - [`curl_slist_append`] — appends a copy of a C string to a linked list
//! - [`curl_slist_free_all`] — frees an entire linked list and its string data
//!
//! # Memory Management
//!
//! All node and string allocations use [`libc::malloc`] / [`libc::free`] so that
//! the resulting linked lists are fully compatible with C callers.  This is
//! intentional: a C consumer that receives a `curl_slist *` from the Rust-backed
//! library can safely pass it to `curl_slist_free_all`, and vice-versa.
//!
//! Each [`curl_slist`] node is a heap-allocated `struct curl_slist` whose `data`
//! field points to a separately `malloc`'d copy of the input string (including
//! the NUL terminator).  The `next` field points to the subsequent node, or is
//! `NULL` for the tail.
//!
//! # Safety Contract (applies to both functions)
//!
//! - The `data` pointer passed to `curl_slist_append` must be a valid,
//!   NUL-terminated C string.  Passing `NULL` or an unterminated buffer is
//!   undefined behaviour, matching curl 8.x semantics.
//! - The `list` pointer passed to either function must be `NULL` or a valid
//!   pointer previously returned by `curl_slist_append`.
//! - `curl_slist_free_all` must not be called with a pointer that was already
//!   freed (double-free is undefined behaviour, matching C semantics).
//! - No other thread may concurrently access or modify the list while either
//!   function is executing on it.

use core::ptr;

use libc::{c_char, c_void, free, malloc, memcpy, size_t, strlen};

use crate::types::curl_slist;

/// Appends a copy of the NUL-terminated C string `data` to the singly-linked
/// list `list`.
///
/// If `list` is `NULL`, a new single-element list is created and returned.
/// Otherwise the new node is appended at the **tail** of the existing list and
/// the original head pointer is returned unchanged.
///
/// The input string `data` is **copied** into a freshly `malloc`'d buffer; the
/// caller retains ownership of the original string.
///
/// # Returns
///
/// * On success — pointer to the **head** of the (possibly new) list.
/// * On allocation failure (`malloc` returns `NULL`) — `NULL`.  When `list`
///   was non-`NULL` and this function returns `NULL`, the original list is
///   **not** freed — but the caller has lost their only handle to the head
///   unless they retained it separately.  This matches the exact behaviour of
///   curl 8.x `curl_slist_append`.
///
/// # Safety
///
/// * `data` must point to a valid NUL-terminated C string.
/// * `list` must be `NULL` or a valid pointer returned by a prior call to
///   `curl_slist_append`.
///
/// # C equivalent
///
/// ```c
/// CURL_EXTERN struct curl_slist *curl_slist_append(struct curl_slist *list,
///                                                  const char *data);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_slist_append(
    list: *mut curl_slist,
    data: *const c_char,
) -> *mut curl_slist {
    // SAFETY: Allocate a new curl_slist node via libc::malloc.  malloc is
    // guaranteed to return a pointer suitably aligned for any fundamental
    // type, or NULL on failure.  size_of::<curl_slist>() accurately reflects
    // the #[repr(C)] layout which matches the C struct.
    let node_size: size_t = core::mem::size_of::<curl_slist>();
    let node_ptr: *mut curl_slist = malloc(node_size) as *mut curl_slist;
    if node_ptr.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `data` is guaranteed by the caller to be a valid NUL-terminated
    // C string.  strlen reads up to (but not including) the NUL terminator and
    // returns the byte length of the string content.
    let data_len: size_t = strlen(data);

    // SAFETY: Allocate data_len + 1 bytes for the string copy, which includes
    // space for the NUL terminator.  malloc returns a valid pointer or NULL.
    let data_copy: *mut c_char = malloc(data_len + 1) as *mut c_char;
    if data_copy.is_null() {
        // SAFETY: node_ptr was allocated by malloc above and has not been
        // freed yet.  We free it here to avoid a memory leak before returning
        // NULL to signal allocation failure.
        free(node_ptr as *mut c_void);
        return ptr::null_mut();
    }

    // SAFETY: Both data_copy and data are valid, non-NULL pointers.
    // data_copy points to data_len + 1 bytes of freshly allocated memory.
    // data points to at least data_len + 1 readable bytes (the string content
    // plus NUL terminator, as guaranteed by strlen having returned data_len).
    // The regions cannot overlap because data_copy is a fresh allocation.
    // We copy data_len + 1 bytes to include the NUL terminator.
    memcpy(
        data_copy as *mut c_void,
        data as *const c_void,
        data_len + 1,
    );

    // SAFETY: node_ptr points to a valid malloc'd region of
    // size_of::<curl_slist>() bytes.  We write both fields through raw
    // pointer dereference, which is valid for malloc'd memory that is at
    // least as large and aligned as the target type.  After these writes
    // the node is a fully initialised curl_slist.
    (*node_ptr).data = data_copy;
    (*node_ptr).next = ptr::null_mut();

    // If the input list is NULL, the new node is the entire list.
    if list.is_null() {
        return node_ptr;
    }

    // SAFETY: list is non-NULL and, per the caller contract, points to a valid
    // curl_slist chain.  We walk the ->next pointers until we reach the tail
    // node (whose next is NULL), then link the new node there.
    let mut last: *mut curl_slist = list;
    while !(*last).next.is_null() {
        last = (*last).next;
    }
    (*last).next = node_ptr;

    list
}

/// Frees every node in the singly-linked list `list`, including each node's
/// `data` string buffer.
///
/// This function is a **no-op** if `list` is `NULL`, matching curl 8.x
/// behaviour.
///
/// After this call, `list` — and every `next` pointer in the chain — is
/// invalid and must not be dereferenced.
///
/// # Safety
///
/// * `list` must be `NULL` or a valid pointer returned by `curl_slist_append`.
/// * The list must not have been already freed (double-free is undefined
///   behaviour).
/// * No other thread may be concurrently accessing or modifying the list.
///
/// # C equivalent
///
/// ```c
/// CURL_EXTERN void curl_slist_free_all(struct curl_slist *list);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_slist_free_all(list: *mut curl_slist) {
    // NULL is explicitly a no-op, matching curl 8.x behaviour.
    if list.is_null() {
        return;
    }

    let mut current: *mut curl_slist = list;
    while !current.is_null() {
        // SAFETY: current is non-NULL and points to a valid curl_slist node
        // that was allocated by curl_slist_append (via libc::malloc).  We read
        // the next pointer before freeing the node so we can continue the walk.
        let next: *mut curl_slist = (*current).next;

        // SAFETY: (*current).data was allocated by libc::malloc inside
        // curl_slist_append and has not yet been freed.  We check for NULL
        // defensively, although curl_slist_append never stores a NULL data
        // pointer in a successfully created node.
        let data_ptr: *mut c_char = (*current).data;
        if !data_ptr.is_null() {
            free(data_ptr as *mut c_void);
        }

        // SAFETY: current was allocated by libc::malloc inside
        // curl_slist_append and has not yet been freed.  After this call
        // the pointer is dangling and must not be dereferenced.
        free(current as *mut c_void);

        current = next;
    }
}
