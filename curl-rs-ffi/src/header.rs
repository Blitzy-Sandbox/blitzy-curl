// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! `curl_easy_header` / `curl_easy_nextheader` — the libcurl response-header C ABI.
//!
//! This module is the `extern "C"` home of the two public header-API functions declared in
//! `include/curl/header.h` (`curl_easy_header`, `curl_easy_nextheader`). It is derived 1:1 from
//! that header and from the C entry point `lib/headers.c`, which is retained in-tree as a
//! read-only source-of-truth reference (AAP §0.4.1). The frozen ABI surface it owns — the
//! [`curl_header`] struct, the [`CURLHcode`] result enum, and the `CURLH_*` origin bit flags —
//! is transcribed byte-for-byte from `header.h` so `cbindgen` regenerates identical
//! declarations and integer values (AAP §0.6.1).
//!
//! # Handle model
//! The opaque C `CURL *` is a `Box<`[`curl_rs_lib::url::Easy`]`>` in disguise (the same mapping
//! `easy.rs` establishes): both functions receive it as `*mut c_void` and borrow it through the
//! crate-root [`as_ref`](crate::as_ref) helper, which performs the null check and bounds the
//! borrow to the call. The handle is never reclaimed here — its lifetime is owned by
//! `curl_easy_init` / `curl_easy_cleanup` in `easy.rs`.
//!
//! # Returned-pointer ownership
//! Exactly like curl (`data->state.headerout[0]` / `[1]` in `lib/headers.c`), a `curl_header *`
//! handed back to the caller is **owned by the easy handle**, not by the caller: the caller must
//! never free it. It stays valid until the next `curl_easy_header` / `curl_easy_nextheader` call
//! on the same handle (which overwrites the slot) or until the handle is cleaned up. This crate
//! keeps that per-handle output storage in a small side table (see [`HeaderState`]) because the
//! core [`Easy`] type does not (yet) carry the output slots itself.
//!
//! # Iteration model
//! [`curl_easy_nextheader`] is stateless from the caller's point of view: the iteration cursor is
//! carried in the returned header's `anchor` field. curl stores the internal list node there; we
//! store the absolute index of the header within the collected set (encoded as `index + 1`, so a
//! genuine cursor is never the null pointer). Passing that header back as `prev` resumes
//! iteration after it.
//!
//! # Safety and unwinding (AAP §0.6.2 / §0.7.2 — binding)
//! `curl-rs-ffi` is the sole crate permitted to use `unsafe`; `curl-rs-lib` is built with
//! `#![forbid(unsafe_code)]`. Every `unsafe` block below carries a `// SAFETY:` comment stating
//! the invariant it upholds. No panic may unwind across the `extern "C"` boundary: the
//! `CURLHcode`-returning [`curl_easy_header`] runs its body inside [`ffi_guard`](crate::ffi_guard)
//! (mapping any panic to `CURLHE_BAD_ARGUMENT`), and the pointer-returning
//! [`curl_easy_nextheader`] runs inside [`catch_unwind`] (mapping any panic to the null sentinel),
//! mirroring curl's own error / `NULL` returns.

// Force every raw-pointer operation into an explicit `unsafe { … }` block carrying its own
// adjacent `// SAFETY:` note, even inside any future `unsafe fn`, as mandated by AAP §0.7.2.
#![deny(unsafe_op_in_unsafe_fn)]
// The two exported functions here are `#[no_mangle] pub extern "C"` entry points on the libcurl C
// ABI boundary that receive raw pointers from C callers and dereference them, so Clippy's
// `not_unsafe_ptr_arg_deref` would fire on each. The libcurl ABI declares these as ordinary
// (non-`unsafe`) C functions and the Minimal Change Mandate requires reproducing those exact
// signatures; pointer validity is instead documented per function and upheld by a `// SAFETY:`
// comment at every dereference. The lint is therefore allowed module-wide — identical to the
// established convention in the sibling `global.rs` / `mprintf.rs`.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::{as_ref, ffi_guard};
use curl_rs_lib::url::Easy;
use libc::{c_char, c_int, c_uint, c_void, size_t};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::{Mutex, OnceLock};

// ===========================================================================
// Frozen ABI surface (include/curl/header.h) — cbindgen-visible.
// ===========================================================================

/// `struct curl_header` — one response header handed to the caller (`include/curl/header.h`).
///
/// Field order, names, and types are transcribed **exactly** from `header.h`
/// (`name`, `value`, `amount`, `index`, `origin`, `anchor`); `#[repr(C)]` freezes the layout so
/// `cbindgen` regenerates a byte-identical declaration. A `curl_header` is owned by the easy
/// handle and must not be freed by the caller (see the module-level ownership note).
#[repr(C)]
pub struct curl_header {
    /// Header name. May differ in letter case from the queried name (curl copies the stored
    /// spelling verbatim). Points into handle-owned storage.
    pub name: *mut c_char,
    /// Header value, with surrounding blanks trimmed. Points into handle-owned storage.
    pub value: *mut c_char,
    /// Number of headers using this name within the selected `origin`/request set.
    pub amount: size_t,
    /// Zero-based index of this instance among those `amount` headers.
    pub index: size_t,
    /// Origin of this header (see the `CURLH_*` bits). libcurl additionally ORs a reserved bit
    /// into this value, so callers must test it with `&`, never `==`.
    pub origin: c_uint,
    /// Opaque handle used privately by libcurl to make [`curl_easy_nextheader`] stateless. The
    /// caller must treat it as opaque and only pass the whole `curl_header` back as `prev`.
    pub anchor: *mut c_void,
}

/// `CURLHcode` — the result code returned by [`curl_easy_header`] (`include/curl/header.h`).
///
/// `#[repr(i32)]` with explicit ordering matches curl's C `enum` (a plain `int`); the integer
/// values are a frozen ABI contract (`CURLHE_OK == 0`, and so on for all eight variants).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CURLHcode {
    /// All fine.
    CURLHE_OK = 0,
    /// The header exists but not with the requested index.
    CURLHE_BADINDEX = 1,
    /// No such header exists.
    CURLHE_MISSING = 2,
    /// No headers at all exist (yet).
    CURLHE_NOHEADERS = 3,
    /// No request with the given number was used.
    CURLHE_NOREQUEST = 4,
    /// Out of memory while processing.
    CURLHE_OUT_OF_MEMORY = 5,
    /// A function argument was not acceptable.
    CURLHE_BAD_ARGUMENT = 6,
    /// The header API was disabled in the build.
    CURLHE_NOT_BUILT_IN = 7,
}

// --- 'origin' bits (include/curl/header.h) ---------------------------------

/// `CURLH_HEADER` — a plain header sent by the server.
pub const CURLH_HEADER: c_uint = 1 << 0;
/// `CURLH_TRAILER` — a header that arrived as a trailer.
pub const CURLH_TRAILER: c_uint = 1 << 1;
/// `CURLH_CONNECT` — a header from a `CONNECT` request.
pub const CURLH_CONNECT: c_uint = 1 << 2;
/// `CURLH_1XX` — a header from a `1xx` informational response.
pub const CURLH_1XX: c_uint = 1 << 3;
/// `CURLH_PSEUDO` — an HTTP/2 or HTTP/3 pseudo header.
pub const CURLH_PSEUDO: c_uint = 1 << 4;

/// The union of every valid `origin` bit. An `origin` argument with any bit outside this mask
/// (or with no bit set) is rejected with [`CURLHcode::CURLHE_BAD_ARGUMENT`], exactly as
/// `lib/headers.c` rejects `type > (CURLH_HEADER | … | CURLH_PSEUDO)` and `!type`.
///
/// Kept private (not part of the public header surface) so `cbindgen` does not emit it.
const CURLH_MASK: c_uint = CURLH_HEADER | CURLH_TRAILER | CURLH_CONNECT | CURLH_1XX | CURLH_PSEUDO;

/// libcurl deterministically ORs bit 27 into the `origin` it reports so applications cannot do
/// `origin == CURLH_HEADER` equality tests (the extra bit keeps the low bits reserved).
/// Transcribed from `lib/headers.c` `copy_header_external`: `hs->type | (1 << 27)`.
///
/// Kept private (an implementation detail of the reported value), so `cbindgen` does not emit it.
const RESERVED_ORIGIN_BIT: c_uint = 1 << 27;

// ===========================================================================
// Internal header model + core bridge.
//
// These are plain Rust types (deliberately NOT `#[repr(C)]` and NOT listed in
// `cbindgen.toml`'s export set) so they never leak into the generated C header.
// ===========================================================================

/// One collected response header, mirroring the fields of curl's `struct Curl_header_store`
/// (`lib/headers.c`) that the header API consults: the stored `name`/`value`, the single origin
/// bit the header was tagged with (`hs->type`), and the request number it belongs to
/// (`hs->request`).
struct CollectedHeader {
    name: String,
    value: String,
    /// Exactly one `CURLH_*` bit — the origin this header was recorded with.
    origin_type: c_uint,
    /// The request index (`data->state.requests` at push time) this header belongs to.
    request: c_int,
}

impl CollectedHeader {
    /// Whether this header matches a query, using curl's own predicate from `lib/headers.c`:
    /// a case-insensitive name compare (`curl_strequal`), the origin bitmask test
    /// (`hs->type & type`), and an exact request-number match (`hs->request == request`).
    fn matches(&self, name: &[u8], origin_mask: c_uint, request: c_int) -> bool {
        self.request == request
            && (self.origin_type & origin_mask) != 0
            && self.name.as_bytes().eq_ignore_ascii_case(name)
    }
}

/// The set of response headers currently collected on `handle`, in insertion order.
///
// NOTE (core bridge): curl stores every parsed response header in `data->state.httphdrs` (see
// `lib/headers.c` `Curl_headers_push`), each tagged with its origin bit (`CURLH_*`) and the
// request number it belongs to. The core `curl_rs_lib::url::Easy` does not yet mirror that store
// — its `EasyState` currently exposes `requests` but no header list — so there are no collected
// headers to expose at this build stage. Returning an empty set makes `curl_easy_header` report
// `CURLHE_NOHEADERS` and `curl_easy_nextheader` report end-of-iteration, which is byte-for-byte
// the behavior curl exhibits before any header has been collected. When the transfer core lands
// and `Easy` gains a header accessor, map each stored header here into a `CollectedHeader`
// (preserving insertion order); the full lookup/iteration logic below then runs unchanged.
fn stored_headers(handle: &Easy) -> Vec<CollectedHeader> {
    let _ = handle;
    Vec::new()
}

/// The most recent request number on `handle` — curl's `data->state.requests`.
///
/// curl's field is a C `int`; the core stores it as `i64`, so it is clamped into the `c_int`
/// range (it is a small, non-negative counter in practice) to keep the `request > requests`
/// comparison and the `request == -1` "last request" remap faithful and wrap-free.
fn last_request(handle: &Easy) -> c_int {
    handle.state.requests.clamp(0, c_int::MAX as i64) as c_int
}

// ===========================================================================
// Pure lookup / iteration algorithm (no `unsafe`, fully unit-testable).
//
// These functions are a direct transliteration of the matching logic in
// `lib/headers.c`; they operate only on a `&[CollectedHeader]` so they can be
// exercised in isolation regardless of the core crate's state.
// ===========================================================================

/// The outcome of a successful [`header_lookup`]: the absolute index of the picked header within
/// the collected set, plus the total number of headers matching the query.
struct Pick {
    abs_index: usize,
    amount: size_t,
}

/// Resolve the `nameindex`-th header matching `(name, origin_mask, request)`.
///
/// Mirrors the body of `curl_easy_header` after its `NOHEADERS`/`NOREQUEST` guards: it counts the
/// matches (`amount`), then locates the requested instance. Returns [`CURLHcode::CURLHE_MISSING`]
/// when nothing matches and [`CURLHcode::CURLHE_BADINDEX`] when matches exist but not at
/// `nameindex`.
fn header_lookup(
    headers: &[CollectedHeader],
    name: &[u8],
    nameindex: size_t,
    origin_mask: c_uint,
    request: c_int,
) -> Result<Pick, CURLHcode> {
    // First pass: total number of matches (curl's `amount`).
    let amount = headers
        .iter()
        .filter(|h| h.matches(name, origin_mask, request))
        .count();
    if amount == 0 {
        return Err(CURLHcode::CURLHE_MISSING);
    }
    if nameindex >= amount {
        return Err(CURLHcode::CURLHE_BADINDEX);
    }
    // Second pass: the `nameindex`-th match (curl walks the list counting until `match == index`).
    let mut seen: usize = 0;
    for (i, h) in headers.iter().enumerate() {
        if h.matches(name, origin_mask, request) {
            if seen == nameindex {
                return Ok(Pick {
                    abs_index: i,
                    amount,
                });
            }
            seen += 1;
        }
    }
    // Unreachable given the counts above (curl's own "this should not happen"); return MISSING
    // defensively rather than ever panicking across the FFI boundary.
    Err(CURLHcode::CURLHE_MISSING)
}

/// Find the next header matching `(origin_mask, request)` at or after the cursor.
///
/// Mirrors `curl_easy_nextheader`'s advance: with no predecessor (`prev_abs == None`) it starts at
/// the head of the list; otherwise it resumes at the position right after the predecessor. Returns
/// the absolute index of the next match, or `None` when iteration is exhausted.
fn next_pick(
    headers: &[CollectedHeader],
    origin_mask: c_uint,
    request: c_int,
    prev_abs: Option<usize>,
) -> Option<usize> {
    let start = match prev_abs {
        // `+ 1` cannot overflow for any realistic header count; `usize::MAX` would simply skip all.
        Some(i) => i.saturating_add(1),
        None => 0,
    };
    headers
        .iter()
        .enumerate()
        .skip(start)
        .find(|(_, h)| (h.origin_type & origin_mask) != 0 && h.request == request)
        .map(|(i, _)| i)
}

/// For the header picked by [`next_pick`], compute its `(index, amount)` within the same-name
/// match set — curl's counting loop in `curl_easy_nextheader`: `amount` is how many headers share
/// the picked name under the `(origin_mask, request)` filter, and `index` is the zero-based
/// position of the picked entry among them.
fn occurrence(
    headers: &[CollectedHeader],
    pick: usize,
    origin_mask: c_uint,
    request: c_int,
) -> (size_t, size_t) {
    let picked_name = headers[pick].name.as_bytes();
    let mut amount: usize = 0;
    let mut index: usize = 0;
    for (i, h) in headers.iter().enumerate() {
        if h.request == request
            && (h.origin_type & origin_mask) != 0
            && h.name.as_bytes().eq_ignore_ascii_case(picked_name)
        {
            amount += 1;
        }
        if i == pick {
            // `amount >= 1` here because the picked header itself matches; `saturating_sub`
            // guards against underflow so this can never panic.
            index = amount.saturating_sub(1);
        }
    }
    (index, amount)
}

/// Build a `CString` from `s`, truncating at the first interior NUL if present.
///
/// Response header names/values are text without embedded NULs (curl's store is already
/// NUL-terminated at the same point), so truncation is faithful; `unwrap_or_default` guarantees
/// the conversion is total and never panics.
fn cstring_lossy(s: &str) -> CString {
    match CString::new(s.as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            let pos = e.nul_position();
            CString::new(&s.as_bytes()[..pos]).unwrap_or_default()
        }
    }
}

// ===========================================================================
// Handle-owned output storage.
//
// curl keeps two per-handle output slots (`data->state.headerout[0]` for
// `curl_easy_header`, `[1]` for `curl_easy_nextheader`) and returns a pointer into them. The
// core `Easy` does not carry those slots, so this crate keeps them in a per-handle side table
// keyed by the handle's address. Only the raw `curl_header` pointer is exposed to C; its
// backing `CString`s are owned here and kept alive for exactly as long as the slot holds them.
// ===========================================================================

/// The owned backing for one output slot.
///
/// The `name`/`value` `CString`s own the NUL-terminated buffers that the slot's `curl_header`
/// points into (their heap allocations are stable across moves of this struct, so the pointers
/// stay valid while the `CString`s live here). `hdr_ptr` is the raw, heap-allocated
/// `curl_header` handed to C, stored as `usize` so this whole struct stays `Send` (a plain
/// pointer field would make it `!Send` and the global table `!Sync`); the allocation is freed
/// exactly once in [`Drop`].
struct SlotStorage {
    // Read only through the raw pointers inside `hdr_ptr`'s `curl_header`, never directly, so the
    // fields are intentionally not otherwise accessed — they exist to own the backing buffers.
    #[allow(dead_code)]
    name: CString,
    #[allow(dead_code)]
    value: CString,
    hdr_ptr: usize,
}

impl Drop for SlotStorage {
    fn drop(&mut self) {
        // SAFETY: `hdr_ptr` was produced by `Box::into_raw::<curl_header>` in `HeaderState::store`
        // and is owned solely by this `SlotStorage`; reconstructing the `Box` here reclaims and
        // frees that allocation exactly once (this `Drop` runs at most once per value).
        unsafe {
            drop(Box::from_raw(self.hdr_ptr as *mut curl_header));
        }
    }
}

/// One easy handle's header output slots: index `0` for [`curl_easy_header`], `1` for
/// [`curl_easy_nextheader`] — the direct analogue of curl's `data->state.headerout[2]`.
#[derive(Default)]
struct HeaderState {
    slots: [Option<SlotStorage>; 2],
}

impl HeaderState {
    /// Populate output `slot` with a fresh `curl_header` describing `picked` and return the raw
    /// pointer to hand back to C.
    ///
    /// Replacing the slot drops any previous [`SlotStorage`], which frees the prior `curl_header`
    /// and its backing strings — i.e. it invalidates the pointer handed out by the previous call
    /// on this slot, exactly matching curl's "valid only until the next call" contract.
    fn store(
        &mut self,
        slot: usize,
        picked: &CollectedHeader,
        amount: size_t,
        index: size_t,
        anchor_abs: usize,
    ) -> *mut curl_header {
        let name_c = cstring_lossy(&picked.name);
        let value_c = cstring_lossy(&picked.value);
        // Compute the pointers before moving the `CString`s into `self`; the moves relocate only
        // the 3-word `CString` handles, never their heap buffers, so the pointers stay valid.
        let hdr = Box::new(curl_header {
            name: name_c.as_ptr() as *mut c_char,
            value: value_c.as_ptr() as *mut c_char,
            amount,
            index,
            // Reproduce curl's reserved-bit OR so callers cannot `==`-compare the origin.
            origin: picked.origin_type | RESERVED_ORIGIN_BIT,
            // Encode the iteration cursor as `abs_index + 1` so a real cursor is never null.
            anchor: (anchor_abs + 1) as *mut c_void,
        });
        let hdr_ptr = Box::into_raw(hdr) as usize;
        self.slots[slot] = Some(SlotStorage {
            name: name_c,
            value: value_c,
            hdr_ptr,
        });
        hdr_ptr as *mut curl_header
    }
}

/// The process-wide table of per-handle header output slots, keyed by handle address.
///
/// `HeaderState` is fully `Send` (its fields are `CString`/`usize`), so a `Mutex`-guarded map of
/// them is `Sync` and needs no `unsafe impl`. Access is serialized by the mutex; the raw pointers
/// handed to C are only ever dereferenced by the single thread using that handle (libcurl's
/// documented contract), so no data race is possible.
fn registry() -> &'static Mutex<HashMap<usize, HeaderState>> {
    static HEADER_REGISTRY: OnceLock<Mutex<HashMap<usize, HeaderState>>> = OnceLock::new();
    HEADER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Populate output `slot` for the handle at address `easy_key` and return the handle-owned
/// `curl_header` pointer. Recovers from a poisoned mutex (a panic in another holder) rather than
/// propagating it across the FFI boundary.
fn store_header_slot(
    easy_key: usize,
    slot: usize,
    picked: &CollectedHeader,
    amount: size_t,
    index: size_t,
    anchor_abs: usize,
) -> *mut curl_header {
    let mut guard = registry()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let state = guard.entry(easy_key).or_default();
    state.store(slot, picked, amount, index, anchor_abs)
}

/// Drop the header output storage associated with an easy handle, invalidating any outstanding
/// `curl_header *` it handed out.
///
// NOTE (cleanup hook): curl frees `data->state.headerout[*]` as part of tearing the handle down.
// The sibling `curl_easy_cleanup` (in `easy.rs`) should call this once the core header store is
// wired, so a handle's output slots are released with it. It is intentionally `pub` (part of the
// crate's Rust-internal API, hence exempt from the dead-code lint) and is a no-op for a handle
// that never produced a header — which is every handle at the current build stage, so nothing is
// ever leaked today.
pub fn drop_header_state(easy: *const c_void) {
    let mut guard = registry()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    guard.remove(&(easy as usize));
}

// ===========================================================================
// The 2 CURL_EXTERN entry points (include/curl/header.h).
// ===========================================================================

/// `CURLHcode curl_easy_header(CURL *easy, const char *name, size_t index, unsigned int origin,`
/// `int request, struct curl_header **hout);`
///
/// Look up the header named `name` (case-insensitively), the `index`-th instance, filtered by the
/// `origin` bitmask, for request number `request` (`0` selects the first request; `-1` selects the
/// most recent one). On success the resolved header is written into handle-owned storage, `*hout`
/// is pointed at it, and [`CURLHcode::CURLHE_OK`] is returned. The `curl_header` must not be freed
/// by the caller and is valid only until the next header-API call on this handle (see the
/// module-level ownership note). Error mapping is transcribed from `lib/headers.c`.
///
/// Returns the [`CURLHcode`] as its `i32` discriminant (curl's `CURLHcode` is a plain C `int`).
#[no_mangle]
pub extern "C" fn curl_easy_header(
    easy: *mut c_void,
    name: *const c_char,
    index: size_t,
    origin: c_uint,
    request: c_int,
    hout: *mut *mut curl_header,
) -> c_int {
    ffi_guard(
        CURLHcode::CURLHE_BAD_ARGUMENT as c_int,
        AssertUnwindSafe(move || {
            // Argument validation — the single combined `CURLHE_BAD_ARGUMENT` gate from
            // `lib/headers.c`: null name / out-pointer / handle, an `origin` carrying bits outside
            // the known mask, a zero `origin`, or a `request` below -1.
            if name.is_null()
                || hout.is_null()
                || easy.is_null()
                || origin > CURLH_MASK
                || origin == 0
                || request < -1
            {
                return CURLHcode::CURLHE_BAD_ARGUMENT as c_int;
            }

            // SAFETY: `easy` is non-null (checked) and, per the libcurl handle contract, a live
            // `Box<Easy>` produced by `curl_easy_init`; `as_ref` re-checks null and borrows it for
            // this call only. The handle is never reclaimed here.
            let handle = match unsafe { as_ref::<Easy>(easy as *const Easy) } {
                Some(h) => h,
                None => return CURLHcode::CURLHE_BAD_ARGUMENT as c_int,
            };

            let headers = stored_headers(handle);
            // curl: `if(!Curl_llist_count(&data->state.httphdrs)) return CURLHE_NOHEADERS;`
            if headers.is_empty() {
                return CURLHcode::CURLHE_NOHEADERS as c_int;
            }

            let requests = last_request(handle);
            if request > requests {
                return CURLHcode::CURLHE_NOREQUEST as c_int;
            }
            // `-1` means "the most recent request".
            let request = if request == -1 { requests } else { request };

            // SAFETY: `name` is non-null (checked) and, per the C contract, a valid NUL-terminated
            // C string that stays alive for this call; only its bytes (up to the NUL) are read.
            let name_bytes = unsafe { CStr::from_ptr(name) }.to_bytes();

            match header_lookup(&headers, name_bytes, index, origin, request) {
                Err(code) => code as c_int,
                Ok(pick) => {
                    let out = store_header_slot(
                        easy as usize,
                        0,
                        &headers[pick.abs_index],
                        pick.amount,
                        index,
                        pick.abs_index,
                    );
                    // SAFETY: `hout` is non-null (checked) and, per the C contract, points to a
                    // caller-owned `struct curl_header *`; writing one pointer there is in bounds.
                    unsafe {
                        *hout = out;
                    }
                    CURLHcode::CURLHE_OK as c_int
                }
            }
        }),
    )
}

/// `struct curl_header *curl_easy_nextheader(CURL *easy, unsigned int origin, int request,`
/// `struct curl_header *prev);`
///
/// Iterate the collected headers matching `origin`/`request`. With `prev` null the first matching
/// header is returned; otherwise iteration resumes after `prev` (its `anchor` carries the cursor).
/// Returns null when iteration is exhausted. The returned `curl_header` is handle-owned (not freed
/// by the caller) and valid until the next header-API call on this handle.
#[no_mangle]
pub extern "C" fn curl_easy_nextheader(
    easy: *mut c_void,
    origin: c_uint,
    request: c_int,
    prev: *mut curl_header,
) -> *mut curl_header {
    catch_unwind(AssertUnwindSafe(move || {
        // curl dereferences `easy` here without a null check; we null-check first so a stray NULL
        // yields NULL instead of undefined behavior — a safe superset that is identical for every
        // valid handle.
        if easy.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `easy` is non-null (checked) and a live `Box<Easy>` per the handle contract;
        // `as_ref` re-checks null and borrows it for this call only, never reclaiming it.
        let handle = match unsafe { as_ref::<Easy>(easy as *const Easy) } {
            Some(h) => h,
            None => return ptr::null_mut(),
        };

        let requests = last_request(handle);
        if request > requests {
            return ptr::null_mut();
        }
        let request = if request == -1 { requests } else { request };

        let headers = stored_headers(handle);

        // Decode the iteration cursor from the previous header's `anchor`. We stored
        // `abs_index + 1`, so a genuine cursor is never zero; a null / zero anchor means "no valid
        // predecessor" and ends iteration (curl's `if(!pick) return NULL`).
        let prev_abs = if prev.is_null() {
            None
        } else {
            // SAFETY: `prev` is non-null and, per the C contract, a pointer previously returned by
            // `curl_easy_header` / `curl_easy_nextheader` for this handle; only its scalar `anchor`
            // field is read here.
            let anchor = unsafe { (*prev).anchor } as usize;
            if anchor == 0 {
                return ptr::null_mut();
            }
            Some(anchor - 1)
        };

        match next_pick(&headers, origin, request, prev_abs) {
            None => ptr::null_mut(),
            Some(p) => {
                let (index, amount) = occurrence(&headers, p, origin, request);
                store_header_slot(easy as usize, 1, &headers[p], amount, index, p)
            }
        }
    }))
    .unwrap_or(ptr::null_mut())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(name: &str, value: &str, origin_type: c_uint, request: c_int) -> CollectedHeader {
        CollectedHeader {
            name: name.to_string(),
            value: value.to_string(),
            origin_type,
            request,
        }
    }

    /// A representative collected set covering: duplicate names, case differences, a pseudo
    /// header, a header on a different request, and a same-name header of a different origin.
    fn sample() -> Vec<CollectedHeader> {
        vec![
            hdr("Content-Type", "text/html", CURLH_HEADER, 0), // 0
            hdr("Set-Cookie", "a=1", CURLH_HEADER, 0),         // 1
            hdr("set-cookie", "b=2", CURLH_HEADER, 0),         // 2 (same name, different case)
            hdr(":status", "200", CURLH_PSEUDO, 0),            // 3
            hdr("X-Trace", "z", CURLH_HEADER, 1),              // 4 (different request)
            hdr("Set-Cookie", "c=3", CURLH_TRAILER, 0),        // 5 (same name, different origin)
        ]
    }

    // --- CollectedHeader::matches ---

    #[test]
    fn matches_is_case_insensitive_on_name() {
        let h = hdr("Content-Type", "x", CURLH_HEADER, 0);
        assert!(h.matches(b"content-type", CURLH_HEADER, 0));
        assert!(h.matches(b"CONTENT-TYPE", CURLH_HEADER, 0));
        assert!(!h.matches(b"content-length", CURLH_HEADER, 0));
    }

    #[test]
    fn matches_respects_origin_mask_and_request() {
        let h = hdr("X", "y", CURLH_TRAILER, 2);
        assert!(h.matches(b"x", CURLH_TRAILER, 2));
        assert!(h.matches(b"x", CURLH_HEADER | CURLH_TRAILER, 2)); // any overlapping bit
        assert!(!h.matches(b"x", CURLH_HEADER, 2)); // no overlap
        assert!(!h.matches(b"x", CURLH_TRAILER, 3)); // wrong request
    }

    // --- header_lookup ---

    #[test]
    fn lookup_missing_when_no_match_or_empty() {
        let hs = sample();
        assert_eq!(
            header_lookup(&hs, b"nope", 0, CURLH_HEADER, 0).err(),
            Some(CURLHcode::CURLHE_MISSING)
        );
        let empty: Vec<CollectedHeader> = Vec::new();
        assert_eq!(
            header_lookup(&empty, b"x", 0, CURLH_HEADER, 0).err(),
            Some(CURLHcode::CURLHE_MISSING)
        );
    }

    #[test]
    fn lookup_single_instance() {
        let hs = sample();
        let p = header_lookup(&hs, b"content-type", 0, CURLH_HEADER, 0).unwrap();
        assert_eq!(p.amount, 1);
        assert_eq!(p.abs_index, 0);
    }

    #[test]
    fn lookup_counts_amount_and_selects_by_index() {
        let hs = sample();
        // Two "Set-Cookie" headers with CURLH_HEADER, request 0 (indices 1 and 2).
        let p0 = header_lookup(&hs, b"set-cookie", 0, CURLH_HEADER, 0).unwrap();
        assert_eq!(p0.amount, 2);
        assert_eq!(p0.abs_index, 1);
        let p1 = header_lookup(&hs, b"set-cookie", 1, CURLH_HEADER, 0).unwrap();
        assert_eq!(p1.amount, 2);
        assert_eq!(p1.abs_index, 2);
    }

    #[test]
    fn lookup_badindex_when_index_out_of_range() {
        let hs = sample();
        assert_eq!(
            header_lookup(&hs, b"set-cookie", 2, CURLH_HEADER, 0).err(),
            Some(CURLHcode::CURLHE_BADINDEX)
        );
    }

    #[test]
    fn lookup_filters_by_origin_and_request() {
        let hs = sample();
        // The trailer Set-Cookie (index 5) is invisible under a CURLH_HEADER mask, visible here.
        let p = header_lookup(&hs, b"set-cookie", 0, CURLH_TRAILER, 0).unwrap();
        assert_eq!(p.amount, 1);
        assert_eq!(p.abs_index, 5);
        // Request 1 only has X-Trace.
        assert_eq!(
            header_lookup(&hs, b"x-trace", 0, CURLH_HEADER, 1)
                .unwrap()
                .abs_index,
            4
        );
        // ...and X-Trace does not exist under request 0.
        assert_eq!(
            header_lookup(&hs, b"x-trace", 0, CURLH_HEADER, 0).err(),
            Some(CURLHcode::CURLHE_MISSING)
        );
    }

    // --- next_pick / occurrence ---

    #[test]
    fn next_pick_iterates_matching_set_in_order() {
        let hs = sample();
        // CURLH_HEADER, request 0 → indices 0,1,2 (Content-Type, Set-Cookie, set-cookie).
        let a = next_pick(&hs, CURLH_HEADER, 0, None).unwrap();
        assert_eq!(a, 0);
        let b = next_pick(&hs, CURLH_HEADER, 0, Some(a)).unwrap();
        assert_eq!(b, 1);
        let c = next_pick(&hs, CURLH_HEADER, 0, Some(b)).unwrap();
        assert_eq!(c, 2);
        assert_eq!(next_pick(&hs, CURLH_HEADER, 0, Some(c)), None);
    }

    #[test]
    fn next_pick_none_on_empty_or_no_match() {
        let hs = sample();
        assert_eq!(next_pick(&hs, CURLH_1XX, 0, None), None); // no 1xx headers
        let empty: Vec<CollectedHeader> = Vec::new();
        assert_eq!(next_pick(&empty, CURLH_HEADER, 0, None), None);
    }

    #[test]
    fn occurrence_reports_index_and_amount() {
        let hs = sample();
        // set-cookie occurrences under CURLH_HEADER/req0 are indices 1 and 2.
        assert_eq!(occurrence(&hs, 1, CURLH_HEADER, 0), (0, 2));
        assert_eq!(occurrence(&hs, 2, CURLH_HEADER, 0), (1, 2));
        // Content-Type is unique.
        assert_eq!(occurrence(&hs, 0, CURLH_HEADER, 0), (0, 1));
    }

    // --- cstring_lossy ---

    #[test]
    fn cstring_lossy_roundtrips_and_truncates_interior_nul() {
        assert_eq!(
            cstring_lossy("Content-Type").to_str().unwrap(),
            "Content-Type"
        );
        assert_eq!(cstring_lossy("ab\0cd").to_bytes(), b"ab");
        assert_eq!(cstring_lossy("").to_bytes(), b"");
    }

    // --- marshaling / anchor round-trip ---

    #[test]
    fn store_populates_fields_reserved_bit_and_anchor() {
        let mut state = HeaderState::default();
        let ch = hdr("Set-Cookie", "a=1", CURLH_HEADER, 0);
        let p = state.store(0, &ch, 2, 1, 5);
        assert!(!p.is_null());
        // SAFETY: `p` points at the live slot 0 owned by `state`, which outlives this block; no
        // other reference aliases it and the slot is not overwritten before these reads.
        unsafe {
            assert_eq!((*p).amount, 2);
            assert_eq!((*p).index, 1);
            assert_eq!((*p).origin, CURLH_HEADER | RESERVED_ORIGIN_BIT);
            assert_eq!((*p).anchor as usize, 6); // 5 + 1
            assert_eq!(CStr::from_ptr((*p).name).to_str().unwrap(), "Set-Cookie");
            assert_eq!(CStr::from_ptr((*p).value).to_str().unwrap(), "a=1");
        }
    }

    #[test]
    fn store_overwrites_same_slot() {
        let mut state = HeaderState::default();
        let first = state.store(1, &hdr("A", "1", CURLH_HEADER, 0), 1, 0, 0);
        assert!(!first.is_null());
        // Overwriting slot 1 frees `first`; it must not be dereferenced after this point.
        let second = state.store(1, &hdr("B", "2", CURLH_TRAILER, 0), 1, 0, 3);
        // SAFETY: `second` points at the current contents of slot 1, owned by the live `state`.
        unsafe {
            assert_eq!(CStr::from_ptr((*second).name).to_str().unwrap(), "B");
            assert_eq!((*second).origin, CURLH_TRAILER | RESERVED_ORIGIN_BIT);
            assert_eq!((*second).anchor as usize, 4);
        }
    }

    // --- extern "C" entry points (reachable behaviors) ---

    fn easy_ptr(e: &mut Easy) -> *mut c_void {
        e as *mut Easy as *mut c_void
    }

    #[test]
    fn header_bad_argument_on_null_and_invalid_inputs() {
        let mut e = Easy::default();
        let ep = easy_ptr(&mut e);
        let name = CString::new("X").unwrap();
        let mut out: *mut curl_header = ptr::null_mut();
        let hout = &mut out as *mut *mut curl_header;
        let bad = CURLHcode::CURLHE_BAD_ARGUMENT as c_int;

        // null name
        assert_eq!(
            curl_easy_header(ep, ptr::null(), 0, CURLH_HEADER, 0, hout),
            bad
        );
        // null hout
        assert_eq!(
            curl_easy_header(ep, name.as_ptr(), 0, CURLH_HEADER, 0, ptr::null_mut()),
            bad
        );
        // null handle
        assert_eq!(
            curl_easy_header(ptr::null_mut(), name.as_ptr(), 0, CURLH_HEADER, 0, hout),
            bad
        );
        // origin == 0
        assert_eq!(curl_easy_header(ep, name.as_ptr(), 0, 0, 0, hout), bad);
        // origin above the valid mask
        assert_eq!(
            curl_easy_header(ep, name.as_ptr(), 0, CURLH_MASK + 1, 0, hout),
            bad
        );
        // request < -1
        assert_eq!(
            curl_easy_header(ep, name.as_ptr(), 0, CURLH_HEADER, -2, hout),
            bad
        );
    }

    #[test]
    fn header_noheaders_when_store_empty() {
        // Valid arguments, but no headers collected yet → CURLHE_NOHEADERS (curl's empty-store
        // path). This is the reachable behavior at the current build stage (see `stored_headers`).
        let mut e = Easy::default();
        let ep = easy_ptr(&mut e);
        let name = CString::new("Content-Type").unwrap();
        let mut out: *mut curl_header = ptr::null_mut();
        let hout = &mut out as *mut *mut curl_header;
        assert_eq!(
            curl_easy_header(ep, name.as_ptr(), 0, CURLH_HEADER, 0, hout),
            CURLHcode::CURLHE_NOHEADERS as c_int
        );
        assert!(out.is_null());
    }

    #[test]
    fn nextheader_null_handle_and_empty_store_return_null() {
        assert!(curl_easy_nextheader(ptr::null_mut(), CURLH_HEADER, 0, ptr::null_mut()).is_null());
        let mut e = Easy::default();
        let ep = easy_ptr(&mut e);
        assert!(curl_easy_nextheader(ep, CURLH_HEADER, 0, ptr::null_mut()).is_null());
    }

    // --- frozen ABI values ---

    #[test]
    fn curlhcode_frozen_integer_values() {
        assert_eq!(CURLHcode::CURLHE_OK as i32, 0);
        assert_eq!(CURLHcode::CURLHE_BADINDEX as i32, 1);
        assert_eq!(CURLHcode::CURLHE_MISSING as i32, 2);
        assert_eq!(CURLHcode::CURLHE_NOHEADERS as i32, 3);
        assert_eq!(CURLHcode::CURLHE_NOREQUEST as i32, 4);
        assert_eq!(CURLHcode::CURLHE_OUT_OF_MEMORY as i32, 5);
        assert_eq!(CURLHcode::CURLHE_BAD_ARGUMENT as i32, 6);
        assert_eq!(CURLHcode::CURLHE_NOT_BUILT_IN as i32, 7);
    }

    #[test]
    fn curlh_origin_bits_frozen() {
        assert_eq!(CURLH_HEADER, 1);
        assert_eq!(CURLH_TRAILER, 2);
        assert_eq!(CURLH_CONNECT, 4);
        assert_eq!(CURLH_1XX, 8);
        assert_eq!(CURLH_PSEUDO, 16);
        assert_eq!(CURLH_MASK, 31);
    }
}
