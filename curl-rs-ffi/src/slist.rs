// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! `curl_slist` — the public `#[repr(C)]` string linked-list type and its two `CURL_EXTERN`
//! entry points (`curl_slist_append`, `curl_slist_free_all`).
//!
//! This module is a 1:1 C-ABI reproduction of the `struct curl_slist` definition in
//! `include/curl/curl.h` and the string-list behavior in `lib/slist.c` of the curl 8.19.0-DEV
//! reference tree. `curl_slist` is a foundational ABI type: the slist-typed `CURLOPT_*` options
//! (`CURLOPT_HTTPHEADER`, `CURLOPT_QUOTE`, `CURLOPT_POSTQUOTE`, `CURLOPT_TELNETOPTIONS`, …)
//! consumed by `easy.rs`, the mime-header path in `share.rs`, and several slist-returning
//! `CURLINFO_*` getinfo results all traffic in `curl_slist` chains, so the type and its allocator
//! live here and the siblings reuse the `pub(crate)` bridge helpers ([`slist_to_vec`],
//! [`vec_to_slist`]) rather than duplicating `unsafe`.
//!
//! ## Memory model (allocator symmetry)
//!
//! Each node is a heap [`Box<curl_slist>`](Box) (reclaimed with [`Box::from_raw`]) whose `data`
//! field is an owned C string produced by [`CString::into_raw`] (reclaimed with
//! [`CString::from_raw`]). [`curl_slist_append`] is the sole producer and [`curl_slist_free_all`]
//! the sole reclaimer, and the two are deliberately kept allocator-symmetric — the exact
//! discipline AddressSanitizer verifies for this crate (AAP §0.6.2). This mirrors curl's C model
//! where `curl_slist_append` `strdup`s the datum and `curl_slist_free_all` frees each datum then
//! the node.
//!
//! ## Unsafe & panic policy (AAP §0.6.2 / §0.7.2)
//!
//! `curl-rs-ffi` is the only workspace crate permitted `unsafe`. Every `unsafe` block below
//! carries a `// SAFETY:` comment stating the invariant it upholds, and no operation here can
//! unwind across the `extern "C"` boundary: the entry points contain no `unwrap`/`expect`/`panic`
//! and no fallible arithmetic, so they are panic-free by construction (a null or
//! non-representable argument is handled by returning null, never by panicking).

// Require every unsafe operation to sit inside an explicit `unsafe { … }` block — even inside an
// `unsafe fn` — so each carries its own adjacent `// SAFETY:` note, matching the crate-root
// `helpers` module and satisfying the AAP §0.7.2 mandate that every unsafe block be justified.
// (The lowercase `curl_slist` type name and the C `curl_*` symbol spelling are permitted by the
// crate-root `#![allow(non_camel_case_types)]` / `#![allow(non_snake_case)]` in `lib.rs`.)
#![deny(unsafe_op_in_unsafe_fn)]

use libc::c_char;
use std::ffi::{CStr, CString};
use std::ptr;

/// Linked-list node for string lists (`struct curl_slist` in `include/curl/curl.h`).
///
/// This is the frozen public ABI type backing the `CURLOPT_QUOTE` family, `CURLOPT_HTTPHEADER`,
/// `curl_mime_headers`, and the slist-returning `CURLINFO_*` results. The layout is transcribed
/// verbatim from curl 8.19.0-DEV — exactly two fields, in this order:
///
/// ```c
/// struct curl_slist {
///   char *data;
///   struct curl_slist *next;
/// };
/// ```
///
/// `#[repr(C)]` with `pub` fields guarantees `cbindgen` regenerates the identical C declaration
/// (`typedef struct curl_slist { char *data; struct curl_slist *next; } curl_slist;`) and that
/// C consumers observe the same field offsets and struct size as curl 8.x.
#[repr(C)]
pub struct curl_slist {
    /// Owned, NUL-terminated C string for this node — allocated by [`curl_slist_append`] via
    /// [`CString::into_raw`] and freed by [`curl_slist_free_all`] via [`CString::from_raw`].
    pub data: *mut c_char,
    /// The next node in the chain, or null at the tail.
    pub next: *mut curl_slist,
}

/// Append a string to a `curl_slist`, creating the list if `list` is null (`curl_slist_append`).
///
/// Faithful reproduction of `curl_slist_append` in `lib/slist.c`. The incoming string is
/// **duplicated** (curl uses `strdup`); the node takes ownership of the copy. Returns the head of
/// the list (the original `list` when non-null, otherwise the new node), or null on failure.
///
/// Behavior parity with curl 8.x:
/// * `data == NULL` → returns null. curl's `curl_slist_append` calls `strdup(data)` (whose
///   `curl_dbg_strdup` `DEBUGASSERT`s a non-null argument) and returns NULL when the duplication
///   fails; returning null here reproduces that "NULL on failure" contract while being
///   memory-safe — it never dereferences a null `data`. Any `list` the caller passed is left
///   untouched and still owned by the caller.
/// * `list == NULL` → the freshly allocated node becomes, and is returned as, the head.
/// * otherwise → the node is linked at the tail and the original `list` head is returned.
///
/// No leak is possible on any path: the string copy is materialized as an owned [`CString`]
/// *before* the node is allocated, and node allocation via [`Box`] aborts (it does not unwind or
/// return null) on out-of-memory, so there is never a partially-constructed node holding an
/// orphaned string to clean up — curl's branch that frees `dupdata` on node-`malloc` failure has
/// no reachable analogue here.
///
/// # Panics
///
/// Never. [`CStr::to_owned`] cannot fail for a valid C string (there is no interior NUL to
/// reject), and the function performs no `unwrap`/`expect`/panicking arithmetic, so it cannot
/// unwind across the FFI boundary.
#[no_mangle]
// FFI entry point: `list`/`data` are raw pointers owned by the C caller, which by the documented
// C API contract passes either null or a valid `curl_slist` chain / NUL-terminated C string. The
// function stays a plain (non-`unsafe`) `extern "C"` fn so it is callable exactly like curl's C
// `curl_slist_append`; the internal pointer work is confined to `unsafe` blocks that each carry a
// `// SAFETY:` justification, so this targeted allow is sound.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn curl_slist_append(list: *mut curl_slist, data: *const c_char) -> *mut curl_slist {
    // Match lib/slist.c: a null datum is a failure — return null without touching `list`.
    if data.is_null() {
        return ptr::null_mut();
    }

    // `strdup` semantics: copy the caller's C string into an owned `CString`. `to_owned` copies
    // the bytes up to (and re-appends) the NUL terminator, exactly like `strdup`, and is
    // infallible for a valid C string (a C string has no interior NUL to reject).
    //
    // SAFETY: `data` is non-null (checked above) and, per the C API contract, points to a valid
    // NUL-terminated C string that stays valid for the duration of this call. `CStr::from_ptr`
    // reads up to the NUL to form the borrow, which `to_owned` immediately copies into an
    // independent allocation.
    let dup: CString = unsafe { CStr::from_ptr(data) }.to_owned();
    // Transfer the owned copy to a raw pointer; reclaimed symmetrically by `curl_slist_free_all`
    // via `CString::from_raw`.
    let dup_ptr: *mut c_char = dup.into_raw();

    // Allocate the new node on the heap. `Box` aborts (does not unwind) on OOM, which is sound
    // across the FFI boundary.
    let node: *mut curl_slist = Box::into_raw(Box::new(curl_slist {
        data: dup_ptr,
        next: ptr::null_mut(),
    }));

    // First item: the new node *is* the whole list (curl uses this as an init function too).
    if list.is_null() {
        return node;
    }

    // Walk to the tail of the caller-owned chain and link the new node in.
    //
    // SAFETY: `list` is non-null (checked above) and, per the C API contract, is a well-formed
    // `curl_slist` chain built by prior `curl_slist_append` calls — every node is a live,
    // properly aligned allocation and the tail's `next` is null — so the walk visits each node
    // once and terminates at the last node, whose `next` we then set to the new node.
    unsafe {
        let mut tail: *mut curl_slist = list;
        while !(*tail).next.is_null() {
            tail = (*tail).next;
        }
        (*tail).next = node;
    }

    list
}

/// Free an entire `curl_slist` chain (`curl_slist_free_all`).
///
/// Faithful reproduction of `curl_slist_free_all` in `lib/slist.c`: walks the chain and, for each
/// node, frees the node's `data` string and then the node itself, capturing `next` *before* the
/// node is released to avoid a use-after-free. A null `list` is a no-op. Each node and each datum
/// is freed exactly once (no double-free), symmetric with the allocation performed by
/// [`curl_slist_append`].
///
/// # Panics
///
/// Never — the function performs only null-checked raw-pointer frees and cannot unwind across the
/// FFI boundary.
#[no_mangle]
// FFI entry point over a caller-owned raw pointer; see `curl_slist_append` for why the plain
// `extern "C"` signature is retained and the allow is sound. Each deref is inside a `// SAFETY:`ed
// `unsafe` block.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn curl_slist_free_all(list: *mut curl_slist) {
    // A null list frees nothing; the loop below already handles this, and starting from `list`
    // makes the no-op contract explicit (parity with the `if(!list) return;` guard in slist.c).
    let mut item: *mut curl_slist = list;
    while !item.is_null() {
        // SAFETY: `item` is non-null (loop condition) and, per the C API contract, points to a
        // live `curl_slist` node produced by `curl_slist_append`; reading its `next` and `data`
        // fields is valid. `next` is captured here, before the node is freed below, so the
        // subsequent reclaim cannot read freed memory.
        let next: *mut curl_slist = unsafe { (*item).next };
        let data: *mut c_char = unsafe { (*item).data };

        if !data.is_null() {
            // SAFETY: `data` is non-null (checked) and was produced by `CString::into_raw` in
            // `curl_slist_append` (or `vec_to_slist`), so reconstructing the `CString` reclaims
            // exactly that allocation. This node is visited once, so `data` is reclaimed once and
            // never used afterwards — no double-free, no use-after-free.
            drop(unsafe { CString::from_raw(data) });
        }

        // SAFETY: `item` was produced by `Box::into_raw` in `curl_slist_append` (transitively via
        // `vec_to_slist`), so reconstructing the `Box` reclaims exactly that node allocation.
        // `next` was already read above, the node is visited once, and `item` is overwritten
        // immediately after, so the node is freed exactly once with no later access.
        drop(unsafe { Box::from_raw(item) });

        item = next;
    }
}

/// Collect a borrowed `curl_slist` chain into an owned `Vec<String>` (crate-internal read bridge).
///
/// Walks the chain from `list`, converting each node's `data` with [`CStr::to_string_lossy`]
/// (non-UTF-8 bytes become U+FFFD replacements rather than an error), and stops at the null tail.
/// A node with a null `data` is skipped defensively (a well-formed list never has one). This is
/// the read bridge sibling modules reuse — e.g. `easy.rs` when translating an incoming
/// `CURLOPT_HTTPHEADER` / `CURLOPT_QUOTE` slist into `curl_rs_lib` builder calls, and `share.rs`
/// for `curl_mime_headers` — so the raw-pointer walk is written and audited exactly once.
///
/// # Safety
///
/// `list` must be either null or the head of a well-formed `curl_slist` chain: every node must be
/// a live, properly aligned allocation whose `data` is null or a valid NUL-terminated C string,
/// and the chain must terminate at a null `next` (no cycles). These invariants hold for any chain
/// built by [`curl_slist_append`] / [`vec_to_slist`] or handed in by a conforming C caller.
#[allow(dead_code)] // Consumed by sibling FFI modules (easy.rs / share.rs) authored in parallel
                    // (AAP §0.7.3 build-order); retained now as the shared, audited read bridge.
pub(crate) unsafe fn slist_to_vec(list: *const curl_slist) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur: *const curl_slist = list;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null (loop condition) and, per this function's documented
        // precondition, points to a live `curl_slist` node in a well-formed chain; forming a
        // shared reference to read its fields is sound (no `&mut` alias exists during the walk).
        let node: &curl_slist = unsafe { &*cur };
        if !node.data.is_null() {
            // SAFETY: `node.data` is non-null (checked) and, per the precondition, a valid
            // NUL-terminated C string; `CStr::from_ptr` reads up to the NUL to form the borrow,
            // which `to_string_lossy` copies. The borrow does not outlive this statement.
            let s: String = unsafe { CStr::from_ptr(node.data) }
                .to_string_lossy()
                .into_owned();
            out.push(s);
        }
        cur = node.next;
    }
    out
}

/// Build an owned `curl_slist` chain from Rust string slices (crate-internal write bridge).
///
/// Reuses [`curl_slist_append`] for every item so the allocation stays symmetric with
/// [`curl_slist_free_all`]; the returned chain must be freed with `curl_slist_free_all`. An item
/// containing an interior NUL cannot be represented as a C string and is skipped (the internal
/// getinfo strings this serves — e.g. `CURLINFO_SSL_ENGINES`, `CURLINFO_COOKIELIST` — never
/// contain one), so the function never panics. Returns null for an empty slice. This is the write
/// bridge for `CURLINFO_*` paths that must hand an slist back to a C caller.
#[allow(dead_code)] // Consumed by sibling getinfo paths authored in parallel (AAP §0.7.3).
pub(crate) fn vec_to_slist(items: &[&str]) -> *mut curl_slist {
    let mut head: *mut curl_slist = ptr::null_mut();
    for item in items {
        // Skip entries that cannot be represented as C strings (interior NUL); return-null-style
        // handling, never an `unwrap`, so nothing can unwind toward an FFI caller.
        let Ok(cstr) = CString::new(*item) else {
            continue;
        };
        // `curl_slist_append` copies the datum (strdup semantics), so `cstr` may be dropped at the
        // end of this iteration. Calling this safe `extern "C"` fn needs no `unsafe`: `head` is
        // null or a chain we built, and `cstr.as_ptr()` is a valid NUL-terminated C string.
        let appended: *mut curl_slist = curl_slist_append(head, cstr.as_ptr());
        if !appended.is_null() {
            head = appended;
        }
    }
    head
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append a `&str` to `list`, assert the append succeeded, and return the new head.
    ///
    /// The temporary `CString` is dropped when this helper returns; because
    /// `curl_slist_append` duplicates the datum (strdup semantics), the resulting node owns an
    /// independent copy, so dropping the source here is correct.
    fn append_str(list: *mut curl_slist, s: &str) -> *mut curl_slist {
        let c = CString::new(s).expect("test inputs contain no interior NUL");
        let head = curl_slist_append(list, c.as_ptr());
        assert!(!head.is_null(), "append of {s:?} must succeed");
        head
    }

    #[test]
    fn append_to_null_creates_single_node_head() {
        let head = append_str(ptr::null_mut(), "Accept: application/json");
        // SAFETY: `head` is a single valid node just produced by `curl_slist_append`.
        unsafe {
            assert!((*head).next.is_null(), "a single-node list has a null tail");
            let got = CStr::from_ptr((*head).data)
                .to_str()
                .expect("stored datum is valid UTF-8");
            assert_eq!(got, "Accept: application/json");
        }
        curl_slist_free_all(head);
    }

    #[test]
    fn append_preserves_insertion_order_and_links_tail() {
        let mut head = ptr::null_mut();
        for s in ["one", "two", "three"] {
            head = append_str(head, s);
        }
        // Directly walk the raw chain to prove `append` linked the nodes at the tail, in order,
        // independently of the `slist_to_vec` bridge.
        // SAFETY: `head` is a well-formed 3-node chain just built via `curl_slist_append`.
        unsafe {
            let n0 = head;
            assert_eq!(CStr::from_ptr((*n0).data).to_str().unwrap(), "one");
            let n1 = (*n0).next;
            assert!(!n1.is_null());
            assert_eq!(CStr::from_ptr((*n1).data).to_str().unwrap(), "two");
            let n2 = (*n1).next;
            assert!(!n2.is_null());
            assert_eq!(CStr::from_ptr((*n2).data).to_str().unwrap(), "three");
            assert!((*n2).next.is_null(), "tail of a 3-node list must be null");
        }
        curl_slist_free_all(head);
    }

    #[test]
    fn append_null_data_returns_null_and_leaves_list_intact() {
        // Null data with a null list → null.
        assert!(curl_slist_append(ptr::null_mut(), ptr::null()).is_null());

        // Null data with an existing list → null, and the existing list is untouched (and still
        // owned by the caller, exactly like curl 8.x).
        let head = append_str(ptr::null_mut(), "keep-me");
        let res = curl_slist_append(head, ptr::null());
        assert!(res.is_null(), "a null datum must yield a null return");
        // SAFETY: `head` is still the valid, unmodified single-node list.
        unsafe {
            assert_eq!(CStr::from_ptr((*head).data).to_str().unwrap(), "keep-me");
            assert!((*head).next.is_null());
        }
        curl_slist_free_all(head);
    }

    #[test]
    fn append_duplicates_the_input_string() {
        // Prove strdup semantics: scribbling over the source buffer after appending must not
        // affect the node's stored copy.
        let mut buf: Vec<u8> = b"original\0".to_vec();
        let head = curl_slist_append(ptr::null_mut(), buf.as_ptr() as *const c_char);
        assert!(!head.is_null());
        // Overwrite the source bytes, keeping it a valid but differing C string ("XXXXXXXX\0").
        for b in buf.iter_mut() {
            *b = b'X';
        }
        *buf.last_mut().unwrap() = 0;
        // SAFETY: `head` is a valid node whose datum was duplicated by `append`, so it is
        // independent of the now-overwritten `buf`.
        unsafe {
            assert_eq!(
                CStr::from_ptr((*head).data).to_str().unwrap(),
                "original",
                "the appended copy must be independent of the mutated source buffer"
            );
        }
        curl_slist_free_all(head);
        drop(buf);
    }

    #[test]
    fn free_all_null_is_a_noop() {
        // Must neither crash nor do anything observable.
        curl_slist_free_all(ptr::null_mut());
    }

    #[test]
    fn slist_to_vec_roundtrip_and_null() {
        let mut head = ptr::null_mut();
        for s in ["alpha", "beta", "gamma"] {
            head = append_str(head, s);
        }
        // SAFETY: `head` is a well-formed chain just built via `curl_slist_append`.
        let v = unsafe { slist_to_vec(head) };
        assert_eq!(
            v,
            vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()]
        );
        curl_slist_free_all(head);

        // A null chain yields an empty vector (allowed input per the documented contract).
        // SAFETY: null is an explicitly permitted argument to `slist_to_vec`.
        let empty = unsafe { slist_to_vec(ptr::null()) };
        assert!(empty.is_empty());
    }

    #[test]
    fn vec_to_slist_roundtrip_and_empty() {
        let head = vec_to_slist(&["x-1", "x-2", "x-3"]);
        assert!(!head.is_null());
        // SAFETY: `head` is a well-formed chain built by `vec_to_slist` via `curl_slist_append`.
        let v = unsafe { slist_to_vec(head) };
        assert_eq!(
            v,
            vec!["x-1".to_string(), "x-2".to_string(), "x-3".to_string()]
        );
        curl_slist_free_all(head);

        // An empty slice produces a null (empty) list.
        assert!(vec_to_slist(&[]).is_null());
    }

    #[test]
    fn vec_to_slist_skips_interior_nul_entries() {
        // "a\0b" cannot be a C string, so it is skipped, leaving only the representable items.
        let head = vec_to_slist(&["ok1", "a\0b", "ok2"]);
        assert!(!head.is_null());
        // SAFETY: `head` is a well-formed chain produced by `vec_to_slist`.
        let v = unsafe { slist_to_vec(head) };
        assert_eq!(v, vec!["ok1".to_string(), "ok2".to_string()]);
        curl_slist_free_all(head);
    }
}
