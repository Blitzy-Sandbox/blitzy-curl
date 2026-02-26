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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// Helper: create a CString and return its raw pointer. The CString is
    /// returned so the caller can keep it alive (preventing dangling).
    fn c_str(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// Helper: count the number of nodes in a curl_slist chain.
    unsafe fn list_len(mut head: *const curl_slist) -> usize {
        let mut count = 0;
        while !head.is_null() {
            count += 1;
            head = (*head).next;
        }
        count
    }

    /// Helper: collect all string values in a curl_slist chain.
    unsafe fn list_values(mut head: *const curl_slist) -> Vec<String> {
        let mut values = Vec::new();
        while !head.is_null() {
            let cstr = std::ffi::CStr::from_ptr((*head).data);
            values.push(cstr.to_str().unwrap().to_owned());
            head = (*head).next;
        }
        values
    }

    // -- curl_slist_append: create from NULL --------------------------------

    #[test]
    fn append_to_null_creates_single_element_list() {
        let s = c_str("first");
        // SAFETY: Passing NULL head and a valid C string pointer.
        let head = unsafe { curl_slist_append(ptr::null_mut(), s.as_ptr()) };
        assert!(!head.is_null());
        assert_eq!(unsafe { list_len(head) }, 1);
        assert_eq!(unsafe { list_values(head) }, vec!["first"]);
        // SAFETY: head is a valid list returned by curl_slist_append.
        unsafe { curl_slist_free_all(head) };
    }

    // -- curl_slist_append: append to existing ------------------------------

    #[test]
    fn append_multiple_elements() {
        let s1 = c_str("alpha");
        let s2 = c_str("beta");
        let s3 = c_str("gamma");

        // SAFETY: Building a list from valid C strings and NULL initial head.
        let mut head = unsafe { curl_slist_append(ptr::null_mut(), s1.as_ptr()) };
        head = unsafe { curl_slist_append(head, s2.as_ptr()) };
        head = unsafe { curl_slist_append(head, s3.as_ptr()) };

        assert!(!head.is_null());
        assert_eq!(unsafe { list_len(head) }, 3);
        assert_eq!(
            unsafe { list_values(head) },
            vec!["alpha", "beta", "gamma"]
        );
        // SAFETY: head is a valid list.
        unsafe { curl_slist_free_all(head) };
    }

    // -- curl_slist_append: data is copied ----------------------------------

    #[test]
    fn append_copies_data() {
        let s = c_str("original");
        // SAFETY: Valid C string pointer.
        let head = unsafe { curl_slist_append(ptr::null_mut(), s.as_ptr()) };
        assert!(!head.is_null());

        // The node's data pointer should NOT be the same as our CString —
        // it should be a fresh copy.
        let node_data = unsafe { (*head).data };
        assert_ne!(node_data as *const c_char, s.as_ptr());

        // But the content should be identical.
        let content = unsafe { std::ffi::CStr::from_ptr(node_data) };
        assert_eq!(content.to_str().unwrap(), "original");

        unsafe { curl_slist_free_all(head) };
    }

    // -- curl_slist_free_all: NULL is no-op ---------------------------------

    #[test]
    fn free_all_null_is_noop() {
        // SAFETY: Passing NULL is documented as a no-op.
        unsafe { curl_slist_free_all(ptr::null_mut()) };
        // If we get here without crashing, the test passes.
    }

    // -- curl_slist_free_all: single element --------------------------------

    #[test]
    fn free_all_single_element() {
        let s = c_str("only");
        // SAFETY: Valid inputs.
        let head = unsafe { curl_slist_append(ptr::null_mut(), s.as_ptr()) };
        assert!(!head.is_null());
        // SAFETY: head is a valid list.
        unsafe { curl_slist_free_all(head) };
        // No crash = success; we cannot verify the memory is actually freed
        // without an allocator hook, but the code path is exercised.
    }

    // -- curl_slist_append: empty string ------------------------------------

    #[test]
    fn append_empty_string() {
        let s = c_str("");
        // SAFETY: An empty C string is valid (just a NUL byte).
        let head = unsafe { curl_slist_append(ptr::null_mut(), s.as_ptr()) };
        assert!(!head.is_null());
        assert_eq!(unsafe { list_values(head) }, vec![""]);
        unsafe { curl_slist_free_all(head) };
    }

    // -- curl_slist_append: long string -------------------------------------

    #[test]
    fn append_long_string() {
        let long = "A".repeat(8192);
        let s = c_str(&long);
        // SAFETY: Valid long C string.
        let head = unsafe { curl_slist_append(ptr::null_mut(), s.as_ptr()) };
        assert!(!head.is_null());
        let values = unsafe { list_values(head) };
        assert_eq!(values[0], long);
        unsafe { curl_slist_free_all(head) };
    }

    // -- curl_slist_append: tail pointer is null ----------------------------

    #[test]
    fn last_node_next_is_null() {
        let s1 = c_str("a");
        let s2 = c_str("b");
        // SAFETY: Building a 2-element list.
        let mut head = unsafe { curl_slist_append(ptr::null_mut(), s1.as_ptr()) };
        head = unsafe { curl_slist_append(head, s2.as_ptr()) };

        // Walk to last node.
        let mut last = head;
        unsafe {
            while !(*last).next.is_null() {
                last = (*last).next;
            }
            assert!((*last).next.is_null());
        }
        unsafe { curl_slist_free_all(head) };
    }

    // -- Multi-element free_all --------------------------------------------

    #[test]
    fn free_all_multi_element() {
        let s1 = c_str("one");
        let s2 = c_str("two");
        let s3 = c_str("three");
        let s4 = c_str("four");

        let mut head = unsafe { curl_slist_append(ptr::null_mut(), s1.as_ptr()) };
        head = unsafe { curl_slist_append(head, s2.as_ptr()) };
        head = unsafe { curl_slist_append(head, s3.as_ptr()) };
        head = unsafe { curl_slist_append(head, s4.as_ptr()) };

        assert_eq!(unsafe { list_len(head) }, 4);
        // SAFETY: head is a valid 4-element list.
        unsafe { curl_slist_free_all(head) };
        // No crash = success.
    }
}
