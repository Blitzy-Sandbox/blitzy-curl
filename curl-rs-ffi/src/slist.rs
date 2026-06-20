//! The public `curl_slist` string-list C API (`curl_slist_append`,
//! `curl_slist_free_all`).
//!
//! This module implements libcurl's two exported string-list symbols directly
//! over the raw, C-visible linked list `#[repr(C)] struct curl_slist` defined in
//! [`crate::types`] (mirroring `include/curl/curl.h`):
//!
//! ```c
//! struct curl_slist {
//!   char *data;              /* a heap-allocated, NUL-terminated string */
//!   struct curl_slist *next; /* the next node, or NULL at the tail      */
//! };
//! ```
//!
//! # Why this operates on the *raw* list, not the core [`SList`]
//!
//! C callers build a list incrementally — each `curl_slist_append` returns the
//! head, which the caller holds between calls — and only later hand the head to,
//! e.g., `curl_easy_setopt(handle, CURLOPT_HTTPHEADER, list)`, finally releasing
//! it with `curl_slist_free_all`. Because the caller observes and owns the raw
//! `curl_slist*` nodes the whole time, these functions must manipulate that
//! intrusive C linked list verbatim. They do **not** operate on
//! `curl-rs-lib`'s safe [`SList`] (a `Vec<CString>`): the core converts a raw
//! list into an [`SList`] only at the moment an `slist`-typed option is applied,
//! via the [`raw_to_core`] helper below.
//!
//! # Behavioral oracle
//!
//! The semantics replicate `lib/slist.c` exactly:
//!
//! * `curl_slist_append` duplicates the string, allocates a node, appends it at
//!   the **tail**, and returns the address of the **first** record (so the same
//!   call serves as both initializer and appender).
//! * `curl_slist_free_all` walks the chain head-to-tail, freeing each node's
//!   `data` and then the node itself; a NULL list is a no-op.
//!
//! The one intentional, memory-safety-driven divergence is the NULL-`data`
//! case: curl's `curl_slist_append` calls `strdup(data)`, and the underlying
//! `strdup` has no NULL guard (passing NULL is undefined behavior in C, guarded
//! only by a `DEBUGASSERT(data)`). The safe Rust port instead returns NULL for
//! a NULL `data` **without touching the input list**, eliminating the UB by
//! construction (AAP §0.7.1) while preserving the observable "returns NULL on
//! failure, leaves the input list untouched" contract.
//!
//! # Memory ownership ("anything allocated by Rust is freed by Rust")
//!
//! Each node is a leaked [`Box<curl_slist>`] (`Box::into_raw`) and each `data`
//! is a leaked [`CString`] (`CString::into_raw`). `curl_slist_free_all`
//! reclaims them with [`Box::from_raw`] / [`CString::from_raw`], so every
//! allocation is freed exactly once, by Rust, and never with the C `free`.
//!
//! # Memory safety
//!
//! `curl-rs-ffi` is the only crate permitted `unsafe`. Every `unsafe` operation
//! here sits in an explicit `unsafe { … }` block carrying a `// SAFETY:`
//! comment (the crate denies `unsafe_op_in_unsafe_fn`), and every exported
//! `unsafe extern "C"` entry point documents its preconditions under a
//! `# Safety` section.

use core::ffi::c_char;
use core::ptr;
use std::ffi::{CStr, CString};

use curl_rs_lib::SList;

use crate::types::curl_slist;

// =============================================================================
// Exported symbol 1 / 2 — curl_slist_append
// =============================================================================

/// Append a string to a libcurl string list (`curl_slist_append`).
///
/// Appends a copy of the NUL-terminated string `data` to the end of the list
/// whose head is `list`. If `list` is NULL a new single-node list is created,
/// so this function doubles as the list initializer. It always returns the
/// address of the **first** record — the new head when `list` was NULL, or the
/// original head otherwise. The caller retains ownership of both `data` (the
/// bytes are copied) and the returned list (which must eventually be released
/// with [`curl_slist_free_all`]).
///
/// On failure it returns NULL: specifically when `data` is NULL (a copy cannot
/// be made). Per curl's contract the input `list` is **not** freed on failure —
/// the caller remains responsible for it.
///
/// # Safety
///
/// * `list` must be NULL, or the head of a valid `curl_slist` chain previously
///   produced by `curl_slist_append` (Rust-allocated nodes terminated by a NULL
///   `next`) that is not aliased or mutated concurrently for the duration of
///   the call. Ownership of the chain is retained by the caller.
/// * `data` must be NULL, or a pointer to a valid NUL-terminated C string that
///   remains valid for the duration of the call. Its bytes are copied; the
///   caller retains ownership.
#[no_mangle]
pub unsafe extern "C" fn curl_slist_append(
    list: *mut curl_slist,
    data: *const c_char,
) -> *mut curl_slist {
    // curl duplicates `data` via strdup() before doing anything else; strdup has
    // no NULL guard (NULL is UB in C). The memory-safe port rejects NULL by
    // returning NULL and leaving `list` untouched — matching the documented
    // "returns NULL on failure, does not free the input list" contract.
    if data.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: per the `# Safety` contract `data` is a valid NUL-terminated C
    // string for the duration of the call. `CStr::from_ptr` borrows it and
    // `to_owned` copies the bytes (including the terminator) into an owned
    // `CString` — the exact effect of curl's `strdup(data)`.
    let owned: CString = unsafe { CStr::from_ptr(data) }.to_owned();

    // Transfer ownership of the duplicated string to a raw `*mut c_char` that
    // the new node owns; it is reclaimed by `curl_slist_free_all` via
    // `CString::from_raw`.
    let raw_data: *mut c_char = owned.into_raw();

    // Allocate the new tail node on the heap and leak it to a raw pointer; it is
    // reclaimed by `curl_slist_free_all` via `Box::from_raw`.
    let new_node: *mut curl_slist = Box::into_raw(Box::new(curl_slist {
        data: raw_data,
        next: ptr::null_mut(),
    }));

    // If there is no existing list, the new node *is* the head.
    if list.is_null() {
        return new_node;
    }

    // Otherwise walk to the final node and link the new node onto the tail,
    // preserving insertion order, then return the original head (curl returns
    // the address of the first record).
    //
    // SAFETY: `list` is non-null and, per the `# Safety` contract, is the head
    // of a valid chain terminated by a NULL `next`. Every `tail` visited is a
    // valid, uniquely-owned node, so reading `(*tail).next` and writing the
    // final `(*tail).next` are both sound.
    unsafe {
        let mut tail: *mut curl_slist = list;
        while !(*tail).next.is_null() {
            tail = (*tail).next;
        }
        (*tail).next = new_node;
    }

    list
}

// =============================================================================
// Exported symbol 2 / 2 — curl_slist_free_all
// =============================================================================

/// Free an entire libcurl string list (`curl_slist_free_all`).
///
/// Walks the chain head-to-tail, freeing every node and its `data`. Passing
/// NULL is a no-op. After this call the `list` pointer (and every node reachable
/// from it) is dangling and must not be used again.
///
/// # Safety
///
/// * `list` must be NULL, or the head of a `curl_slist` chain produced by
///   [`curl_slist_append`] (Rust-allocated nodes and `data` strings) that the
///   caller owns. Each node and its `data` is freed exactly once; callers must
///   not pass a list they do not own, must not free the same list twice, and
///   must not use `list` (or any node within it) afterwards.
#[no_mangle]
pub unsafe extern "C" fn curl_slist_free_all(list: *mut curl_slist) {
    // A NULL list is an explicit no-op (matches `lib/slist.c`).
    if list.is_null() {
        return;
    }

    let mut cur: *mut curl_slist = list;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node of a chain built by
        // `curl_slist_append`. Its `data`/`next` are `Copy` fields read out
        // *before* the node is freed, so the node is still live for the reads.
        // Capturing `next` first lets us advance after freeing `cur` without
        // touching freed memory.
        let next: *mut curl_slist = unsafe { (*cur).next };
        // SAFETY: `cur` is non-null and points to a live, valid node here; `data` is a `Copy` value read out before the node is freed.
        let data: *mut c_char = unsafe { (*cur).data };

        if !data.is_null() {
            // SAFETY: `data` was produced by `CString::into_raw` in
            // `curl_slist_append`; reconstructing the `CString` and dropping it
            // frees exactly that allocation, exactly once.
            drop(unsafe { CString::from_raw(data) });
        }

        // SAFETY: `cur` was produced by `Box::into_raw` in `curl_slist_append`;
        // reconstructing the `Box` and dropping it frees exactly that node,
        // exactly once.
        drop(unsafe { Box::from_raw(cur) });

        cur = next;
    }
}

// =============================================================================
// Internal interop helpers (NOT exported — `pub(crate)`)
// =============================================================================
//
// These bridge the raw C `curl_slist` form (above) and the core crate's safe
// `SList`. They are consumed by the sibling FFI modules (`easy.rs`, `multi.rs`)
// when an `slist`-typed option is applied (inbound) or an `slist`-typed info is
// retrieved (outbound). They are `#[allow(dead_code)]` because those sibling
// modules are produced independently in the same workspace build and may not
// reference them yet; the attribute keeps the zero-warnings gate green in the
// interim and is harmless once the consumers land.

/// Convert a borrowed raw C `curl_slist` chain into the core crate's owning
/// [`SList`] (the **inbound** marshaling path).
///
/// Used by the option setters when an `slist`-typed option
/// (`CURLOPT_HTTPHEADER`, `CURLOPT_QUOTE`, `CURLOPT_RESOLVE`, …) is applied: the
/// C caller's raw list is deep-copied into an owned [`SList`] stored on the
/// handle. The input chain is only read; the caller retains ownership of it.
///
/// # Safety
///
/// `list` must be NULL, or the head of a valid `curl_slist` chain — each node's
/// `data` either NULL or a valid NUL-terminated C string, the chain terminated
/// by a NULL `next`. The chain is read only (never freed or mutated).
#[allow(dead_code)] // consumed by easy.rs/multi.rs slist-option application (sibling FFI modules).
pub(crate) unsafe fn raw_to_core(list: *const curl_slist) -> SList {
    let mut items: Vec<CString> = Vec::new();
    let mut cur: *const curl_slist = list;

    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node of a valid chain per the `# Safety`
        // contract, so reading its `Copy` `data`/`next` fields is sound.
        let data: *mut c_char = unsafe { (*cur).data };
        // SAFETY: `cur` is non-null and points to a live, valid node here; `next` is a `Copy` value read out before the node is freed.
        let next: *const curl_slist = unsafe { (*cur).next };

        if data.is_null() {
            // A well-formed node always has a non-NULL `data`; tolerate a NULL
            // by mapping it to an empty entry rather than dereferencing NULL.
            items.push(CString::default());
        } else {
            // SAFETY: `data` is a valid NUL-terminated C string (chain
            // invariant); `from_ptr` borrows it and `to_owned` copies it.
            items.push(unsafe { CStr::from_ptr(data) }.to_owned());
        }

        cur = next;
    }

    SList::from_cstrings(items)
}

/// Convert the core crate's owning [`SList`] into a freshly allocated raw C
/// `curl_slist` chain owned by the caller (the **outbound** marshaling path).
///
/// Used by the getinfo paths that return a string list (`CURLINFO_SSL_ENGINES`,
/// `CURLINFO_COOKIELIST`): the core list is cloned node-by-node into a C chain
/// that the C caller subsequently releases with [`curl_slist_free_all`]. An
/// empty list yields NULL — the canonical empty `curl_slist*`.
///
/// On allocation failure mid-build the partial chain is freed and NULL is
/// returned, so no memory is leaked.
#[allow(dead_code)] // consumed by easy.rs/multi.rs slist-returning getinfo paths (sibling FFI modules).
pub(crate) fn core_to_raw(list: &SList) -> *mut curl_slist {
    let mut head: *mut curl_slist = ptr::null_mut();

    for entry in list.iter_cstring() {
        // SAFETY: `entry.as_ptr()` is a valid NUL-terminated C string for the
        // duration of the call (it borrows the owned `CString` held by `list`),
        // and `curl_slist_append` copies it. `head` is NULL or a chain this
        // function built with `curl_slist_append`, satisfying its contract.
        let appended: *mut curl_slist = unsafe { curl_slist_append(head, entry.as_ptr()) };

        if appended.is_null() {
            // Append failed (allocation failure): free the partial chain built
            // so far and signal failure with NULL, leaking nothing.
            //
            // SAFETY: `head` is NULL or a chain built by `curl_slist_append`,
            // exactly what `curl_slist_free_all` requires.
            unsafe { curl_slist_free_all(head) };
            return ptr::null_mut();
        }

        head = appended;
    }

    head
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an owned `CString` from a NUL-free `&str`. The returned value must
    /// be kept alive by the caller for as long as its `.as_ptr()` is in use.
    fn cs(s: &str) -> CString {
        CString::new(s).expect("test input must be NUL-free")
    }

    /// Append three strings and verify the raw chain: insertion order, exact
    /// `data` bytes, and a NULL-terminated `next` linkage. Then free the whole
    /// list. Run under Miri this proves there is no leak and no double-free.
    #[test]
    fn append_builds_ordered_chain_then_frees_cleanly() {
        let a = cs("Host: example.com");
        let b = cs("X-Trace: 1");
        let c = cs("Accept: */*");

        // SAFETY: each `data` is a valid NUL-terminated C string kept alive by
        // its owning `CString`; appending onto a NULL head is valid.
        let list = unsafe {
            let l = curl_slist_append(ptr::null_mut(), a.as_ptr());
            let l = curl_slist_append(l, b.as_ptr());
            curl_slist_append(l, c.as_ptr())
        };
        assert!(!list.is_null());

        // SAFETY: `list` is the three-node chain just built; walking it and
        // reading each node's fields is sound.
        unsafe {
            let n0 = list;
            let n1 = (*n0).next;
            let n2 = (*n1).next;
            assert!(!n1.is_null());
            assert!(!n2.is_null());
            assert_eq!(CStr::from_ptr((*n0).data).to_bytes(), b"Host: example.com");
            assert_eq!(CStr::from_ptr((*n1).data).to_bytes(), b"X-Trace: 1");
            assert_eq!(CStr::from_ptr((*n2).data).to_bytes(), b"Accept: */*");
            // The tail terminates the chain.
            assert!((*n2).next.is_null());
        }

        // SAFETY: `list` is a chain built solely by `curl_slist_append`.
        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn append_to_null_head_returns_new_head() {
        let a = cs("first");
        // SAFETY: valid C string; NULL head creates a new single-node list.
        let list = unsafe { curl_slist_append(ptr::null_mut(), a.as_ptr()) };
        assert!(!list.is_null());
        // SAFETY: single-node chain just built.
        unsafe {
            assert_eq!(CStr::from_ptr((*list).data).to_bytes(), b"first");
            assert!((*list).next.is_null());
            curl_slist_free_all(list);
        }
    }

    #[test]
    fn append_null_data_returns_null_and_keeps_list() {
        let a = cs("keep me");
        // SAFETY: valid C string; NULL head.
        let list = unsafe { curl_slist_append(ptr::null_mut(), a.as_ptr()) };
        assert!(!list.is_null());

        // Appending NULL data must return NULL WITHOUT freeing or altering the
        // input list (matches lib/slist.c's "returns NULL, list untouched").
        // SAFETY: NULL `data` is handled by the early guard; `list` is valid.
        let res = unsafe { curl_slist_append(list, ptr::null()) };
        assert!(res.is_null());

        // The original list is intact and still owned by us.
        // SAFETY: `list` was not modified by the failed append.
        unsafe {
            assert_eq!(CStr::from_ptr((*list).data).to_bytes(), b"keep me");
            assert!((*list).next.is_null());
            curl_slist_free_all(list);
        }
    }

    #[test]
    fn append_null_data_to_null_list_is_null() {
        // SAFETY: both arguments NULL; the NULL-`data` guard returns NULL.
        let res = unsafe { curl_slist_append(ptr::null_mut(), ptr::null()) };
        assert!(res.is_null());
    }

    #[test]
    fn free_all_null_is_noop() {
        // SAFETY: NULL is the documented no-op input.
        unsafe { curl_slist_free_all(ptr::null_mut()) };
    }

    #[test]
    fn append_empty_string_node_is_allowed() {
        let empty = cs("");
        // SAFETY: "" is a valid (empty) NUL-terminated C string.
        let list = unsafe { curl_slist_append(ptr::null_mut(), empty.as_ptr()) };
        assert!(!list.is_null());
        // SAFETY: single-node chain just built.
        unsafe {
            assert_eq!(CStr::from_ptr((*list).data).to_bytes(), b"");
            curl_slist_free_all(list);
        }
    }

    #[test]
    fn raw_to_core_copies_all_entries_in_order() {
        let a = cs("one");
        let b = cs("two");
        let c = cs("three");
        // SAFETY: valid C strings kept alive by their `CString`s.
        let list = unsafe {
            let l = curl_slist_append(ptr::null_mut(), a.as_ptr());
            let l = curl_slist_append(l, b.as_ptr());
            curl_slist_append(l, c.as_ptr())
        };

        // SAFETY: `list` is a valid chain built by `curl_slist_append`.
        let core = unsafe { raw_to_core(list) };
        assert_eq!(core.len(), 3);
        let collected: Vec<&[u8]> = core.iter_cstring().map(|e| e.to_bytes()).collect();
        assert_eq!(collected, vec![&b"one"[..], &b"two"[..], &b"three"[..]]);

        // SAFETY: free the raw list we built (raw_to_core only read it).
        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn raw_to_core_of_null_is_empty() {
        // SAFETY: a NULL chain marshals to an empty list.
        let core = unsafe { raw_to_core(ptr::null()) };
        assert!(core.is_empty());
        assert_eq!(core.len(), 0);
    }

    #[test]
    fn core_to_raw_builds_chain_then_frees() {
        let core = SList::from_cstrings(vec![cs("alpha"), cs("beta")]);
        let raw = core_to_raw(&core);
        assert!(!raw.is_null());
        // SAFETY: `raw` is a two-node chain built by `core_to_raw`.
        unsafe {
            let n0 = raw;
            let n1 = (*n0).next;
            assert!(!n1.is_null());
            assert_eq!(CStr::from_ptr((*n0).data).to_bytes(), b"alpha");
            assert_eq!(CStr::from_ptr((*n1).data).to_bytes(), b"beta");
            assert!((*n1).next.is_null());
            curl_slist_free_all(raw);
        }
    }

    #[test]
    fn core_to_raw_of_empty_is_null() {
        let core = SList::new();
        let raw = core_to_raw(&core);
        assert!(raw.is_null());
        // free_all(NULL) is a safe no-op.
        // SAFETY: NULL input.
        unsafe { curl_slist_free_all(raw) };
    }

    /// Round-trip raw -> core -> raw and confirm contents survive both
    /// marshaling directions, then free both independent chains.
    #[test]
    fn raw_core_raw_round_trip_preserves_contents() {
        let a = cs("k1: v1");
        let b = cs("k2: v2");
        // SAFETY: valid C strings kept alive by their `CString`s.
        let raw_in = unsafe {
            let l = curl_slist_append(ptr::null_mut(), a.as_ptr());
            curl_slist_append(l, b.as_ptr())
        };

        // SAFETY: `raw_in` is a valid chain.
        let core = unsafe { raw_to_core(raw_in) };
        assert_eq!(core.len(), 2);

        let raw_out = core_to_raw(&core);
        assert!(!raw_out.is_null());

        // SAFETY: both `raw_out` and `raw_in` are valid, independent chains.
        unsafe {
            assert_eq!(CStr::from_ptr((*raw_out).data).to_bytes(), b"k1: v1");
            let second = (*raw_out).next;
            assert!(!second.is_null());
            assert_eq!(CStr::from_ptr((*second).data).to_bytes(), b"k2: v2");
            assert!((*second).next.is_null());

            curl_slist_free_all(raw_out);
            curl_slist_free_all(raw_in);
        }
    }

    /// Build a large list to exercise the append-at-tail walk and the free
    /// loop on a long chain (meaningful under Miri).
    #[test]
    fn large_list_builds_and_frees() {
        let owned: Vec<CString> = (0..256).map(|i| cs(&format!("entry-{i}"))).collect();

        let mut list: *mut curl_slist = ptr::null_mut();
        for entry in &owned {
            // SAFETY: each `entry` is a valid NUL-terminated C string; `list` is
            // NULL or a chain built here by `curl_slist_append`.
            list = unsafe { curl_slist_append(list, entry.as_ptr()) };
            assert!(!list.is_null());
        }

        // SAFETY: `list` is the 256-node chain just built.
        unsafe {
            // Spot-check head and tail.
            assert_eq!(CStr::from_ptr((*list).data).to_bytes(), b"entry-0");
            let mut tail = list;
            while !(*tail).next.is_null() {
                tail = (*tail).next;
            }
            assert_eq!(CStr::from_ptr((*tail).data).to_bytes(), b"entry-255");
            curl_slist_free_all(list);
        }
    }
}
