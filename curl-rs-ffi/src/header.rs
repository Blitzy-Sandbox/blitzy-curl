//! The public HTTP response-header access C API (`curl_easy_header`,
//! `curl_easy_nextheader`).
//!
//! This module implements libcurl's two exported header-API symbols
//! (`CURL_EXTERN` in `include/curl/header.h`) over the safe header store kept by
//! the async core ([`curl_rs_lib`]):
//!
//! ```c
//! CURLHcode curl_easy_header(CURL *easy, const char *name, size_t index,
//!                            unsigned int origin, int request,
//!                            struct curl_header **hout);
//! struct curl_header *curl_easy_nextheader(CURL *easy, unsigned int origin,
//!                                          int request,
//!                                          struct curl_header *prev);
//! ```
//!
//! # Behavioral oracle
//!
//! The semantics replicate `lib/headers.c` exactly:
//!
//! * `curl_easy_header` looks up the `index`-th instance of a named header,
//!   filtered by the `origin` bitmask and the `request` number (`-1` selects the
//!   most recent request in a redirect/auth chain), and writes a populated
//!   [`curl_header`] to `*hout`. The argument guard, the empty-store
//!   ([`CURLHE_NOHEADERS`](CURLHcode::CURLHE_NOHEADERS)), bad-request
//!   ([`CURLHE_NOREQUEST`](CURLHcode::CURLHE_NOREQUEST)), missing-name
//!   ([`CURLHE_MISSING`](CURLHcode::CURLHE_MISSING)) and out-of-range-index
//!   ([`CURLHE_BADINDEX`](CURLHcode::CURLHE_BADINDEX)) precedence all match the C
//!   function. The filtering / counting itself is performed by
//!   [`HeaderCollector::header`](curl_rs_lib::headers::HeaderCollector::header),
//!   the safe-core equivalent.
//! * `curl_easy_nextheader` iterates the stored headers in the given
//!   origin/request scope, resuming after `prev` (or from the first header when
//!   `prev` is NULL) via the opaque `anchor`, and returns NULL once the scope is
//!   exhausted. It maps to
//!   [`HeaderCollector::nextheader_from`](curl_rs_lib::headers::HeaderCollector::nextheader_from).
//!
//! As in C, the returned `origin` field carries a reserved bit (`1 << 27`) OR'd
//! into the real `CURLH_*` bits so that applications cannot do `==` comparisons
//! against the documented constants; that bit is already applied by the core
//! when it builds a [`Header`](curl_rs_lib::headers::Header).
//!
//! # Ownership and lifetime ("the struct is owned by the easy handle")
//!
//! `include/curl/header.h` documents that the `struct curl_header *` returned by
//! either function — and the `name`/`value` strings inside it — is **owned by
//! the easy handle** and remains valid only until the next call to a header
//! function, `curl_easy_perform`, or `curl_easy_cleanup`. Callers must **not**
//! free it.
//!
//! curl keeps that storage on the handle in `data->state.headerout[0]`
//! (`curl_easy_header`) and `data->state.headerout[1]` (`curl_easy_nextheader`)
//! — two independent slots, so an interleaved `header()` + `nextheader()` usage
//! does not clobber the other's result.
//!
//! The safe core ([`curl_rs_lib::easy::Easy`], the type behind the opaque
//! `CURL`) deliberately holds **no** C types or raw pointers (its protocol/TLS/
//! transfer roots carry `#![forbid(unsafe_code)]`), so the C-visible
//! [`curl_header`] (with its `*mut c_char` name/value and `*mut c_void` anchor)
//! and the NUL-terminated backing strings cannot live inside `Easy`. This FFI
//! layer therefore maintains the C-facing storage itself, in a **per-handle**,
//! thread-local registry keyed by the handle address ([`HEADER_STORE`]). Each
//! handle owns two slots mirroring `headerout[0]`/`[1]`; each slot owns the
//! [`CString`]s that back its `name`/`value` pointers. Writing a slot drops the
//! previous backing strings, invalidating the previously returned pointer for
//! that slot exactly as curl reuses `headerout[slot]`. The boxed per-handle
//! record gives the returned `*mut curl_header` a stable address that survives
//! map growth. Storage is released at thread exit, and eagerly via
//! [`drop_handle_headers`] (which the FFI `curl_easy_cleanup`/`curl_easy_reset`
//! shims call once authored).
//!
//! # Memory safety
//!
//! `curl-rs-ffi` is the only crate permitted `unsafe`. Every `unsafe` operation
//! here sits in an explicit `unsafe { … }` block carrying a `// SAFETY:` comment
//! (the crate denies `unsafe_op_in_unsafe_fn`), and every exported
//! `unsafe extern "C"` entry point documents its preconditions under a
//! `# Safety` section. The only raw-pointer dereferences are the four C-boundary
//! reads/writes (`name`, `easy`, `*hout`, `prev->anchor`); the lookup, filtering
//! and string handling are entirely safe.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};

use libc::size_t;

use curl_rs_lib::Easy;

use crate::error_codes::CURLHcode;
use crate::types::{curl_header, CURL};

// =============================================================================
// Per-handle, C-facing header storage
// =============================================================================

/// Builds an all-zero/NULL [`curl_header`] for an empty slot.
///
/// `curl_header` is `#[repr(C)]` and intentionally derives no `Default` (it
/// holds raw pointers), so slots are initialized with this explicit constant.
const fn empty_curl_header() -> curl_header {
    curl_header {
        name: ptr::null_mut(),
        value: ptr::null_mut(),
        amount: 0,
        index: 0,
        origin: 0,
        anchor: ptr::null_mut(),
    }
}

/// One C-facing output slot — the analog of a single `data->state.headerout[i]`.
///
/// `name`/`value` own the NUL-terminated bytes that `hdr.name`/`hdr.value` point
/// at; keeping them here ties their lifetime to the slot (and thus the handle).
/// Overwriting the slot drops the previous [`CString`]s, which is precisely what
/// invalidates the pointer returned by the previous call for this slot.
struct HeaderSlot {
    name: Option<CString>,
    value: Option<CString>,
    hdr: curl_header,
}

impl HeaderSlot {
    fn new() -> Self {
        HeaderSlot {
            name: None,
            value: None,
            hdr: empty_curl_header(),
        }
    }
}

/// The two output slots owned by a single easy handle: slot `0` is written by
/// [`curl_easy_header`] and slot `1` by [`curl_easy_nextheader`], mirroring
/// curl's `data->state.headerout[0]` / `headerout[1]`.
struct HandleHeaderStore {
    slots: [HeaderSlot; 2],
}

impl HandleHeaderStore {
    fn new() -> Self {
        HandleHeaderStore {
            slots: [HeaderSlot::new(), HeaderSlot::new()],
        }
    }
}

thread_local! {
    /// Per-handle C-facing header storage, keyed by the handle address.
    ///
    /// Thread-local because an easy handle must not be used concurrently from
    /// multiple threads; this keeps the returned `curl_header*` lock-free and
    /// per-handle while remaining `!Send`/`!Sync`-safe (the records hold raw
    /// pointers). Entries are dropped at thread exit, and eagerly by
    /// [`drop_handle_headers`].
    static HEADER_STORE: RefCell<HashMap<usize, Box<HandleHeaderStore>>> =
        RefCell::new(HashMap::new());
}

/// Stores a freshly built header into `slot` (`0` or `1`) of `handle`'s record
/// and returns a stable `*mut curl_header` pointing at it.
///
/// The `name`/`value` backing [`CString`]s are moved into the slot first, so the
/// returned `hdr.name`/`hdr.value` point at storage owned by the slot. The
/// per-handle record is boxed, so the returned pointer keeps a stable address
/// across later `HashMap` growth; it stays valid until this same slot is written
/// again or the handle's storage is dropped.
#[allow(clippy::too_many_arguments)]
fn store_header(
    handle: usize,
    slot: usize,
    name: Option<CString>,
    value: Option<CString>,
    amount: size_t,
    index: size_t,
    origin: c_uint,
    anchor: usize,
) -> *mut curl_header {
    HEADER_STORE.with(|cell| {
        let mut map = cell.borrow_mut();
        let store = map
            .entry(handle)
            .or_insert_with(|| Box::new(HandleHeaderStore::new()));
        let s = &mut store.slots[slot];

        // Install the new backing strings first. Dropping any previous CStrings
        // here is what invalidates the pointer the previous call handed out for
        // THIS slot — matching curl's reuse of `headerout[slot]`.
        s.name = name;
        s.value = value;

        let name_ptr: *mut c_char = match &s.name {
            Some(c) => c.as_ptr().cast_mut(),
            None => ptr::null_mut(),
        };
        let value_ptr: *mut c_char = match &s.value {
            Some(c) => c.as_ptr().cast_mut(),
            None => ptr::null_mut(),
        };

        s.hdr = curl_header {
            name: name_ptr,
            value: value_ptr,
            amount,
            index,
            origin,
            // `anchor` is opaque to the application; we stash the core store
            // index in it so `curl_easy_nextheader(prev)` can resume iteration.
            // It is never dereferenced as a pointer.
            anchor: anchor as *mut c_void,
        };

        // The slot lives inside a `Box` held by the thread-local map, so this
        // address is stable across subsequent map mutations/growth.
        &mut s.hdr as *mut curl_header
    })
}

/// Releases the per-handle C-facing header storage associated with `easy`.
///
/// This is **not** a libcurl C export (it carries no `#[no_mangle]`); it is an
/// internal helper that the FFI `curl_easy_cleanup` / `curl_easy_reset`
/// implementations call so the thread-local registry does not retain an entry
/// for a destroyed or reset handle. Passing a handle with no stored header (or a
/// NULL pointer) is a no-op. `easy` is used only as an identity key and is never
/// dereferenced, so this function is safe.
pub fn drop_handle_headers(easy: *const CURL) {
    let key = easy as usize;
    HEADER_STORE.with(|cell| {
        cell.borrow_mut().remove(&key);
    });
}

// =============================================================================
// Exported symbol 1 / 2 — curl_easy_header
// =============================================================================

/// Look up a single HTTP response header by name (`curl_easy_header`).
///
/// Retrieves the `index`-th instance of the header named `name` from the headers
/// collected on the easy handle `easy`, restricted to the origins selected by
/// the `origin` bitmask (`CURLH_HEADER`, `CURLH_TRAILER`, `CURLH_CONNECT`,
/// `CURLH_1XX`, `CURLH_PSEUDO`) and to the response numbered `request` in a
/// redirect/authentication chain (`0` = first, `-1` = the most recent). On
/// success a populated [`curl_header`] is written to `*hout` and
/// [`CURLHE_OK`](CURLHcode::CURLHE_OK) is returned.
///
/// The written `struct curl_header` — and the `name`/`value` strings within it —
/// is **owned by the easy handle**: it stays valid until the next call to
/// `curl_easy_header`/`curl_easy_nextheader`, `curl_easy_perform`, or
/// `curl_easy_cleanup` on this handle, and the caller must **not** free it.
///
/// Returns, matching `lib/headers.c` precedence:
/// * [`CURLHE_BAD_ARGUMENT`](CURLHcode::CURLHE_BAD_ARGUMENT) — `easy`, `name` or
///   `hout` is NULL, `origin` is `0` or has bits outside the documented mask, or
///   `request < -1`.
/// * [`CURLHE_NOHEADERS`](CURLHcode::CURLHE_NOHEADERS) — no headers collected yet.
/// * [`CURLHE_NOREQUEST`](CURLHcode::CURLHE_NOREQUEST) — `request` exceeds the
///   highest request number seen.
/// * [`CURLHE_MISSING`](CURLHcode::CURLHE_MISSING) — no header with that name in
///   the requested scope.
/// * [`CURLHE_BADINDEX`](CURLHcode::CURLHE_BADINDEX) — fewer than `index + 1`
///   such headers exist.
///
/// # Safety
///
/// * `easy` must be NULL, or a valid easy handle returned by `curl_easy_init`
///   (a live `Box<Easy>` pointer) that is not used concurrently from another
///   thread for the duration of the call.
/// * `name` must be NULL, or a pointer to a valid NUL-terminated C string that
///   remains valid for the duration of the call. Its bytes are only read.
/// * `hout` must be NULL, or a valid, writable pointer to one `*mut curl_header`.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_header(
    easy: *mut CURL,
    name: *const c_char,
    index: size_t,
    origin: c_uint,
    request: c_int,
    hout: *mut *mut curl_header,
) -> CURLHcode {
    // Argument guard: curl returns CURLHE_BAD_ARGUMENT for any NULL here. The
    // origin-mask and request-range validation is performed identically by the
    // core lookup ([`HeaderCollector::header`]), preserving C's error order.
    if easy.is_null() || name.is_null() || hout.is_null() {
        return CURLHcode::CURLHE_BAD_ARGUMENT;
    }

    // SAFETY: per the `# Safety` contract `name` is a valid NUL-terminated C
    // string for the duration of the call. `to_string_lossy().into_owned()`
    // copies it; a non-UTF-8 name (never produced on the HTTP wire) simply fails
    // to match any stored (UTF-8) header, yielding CURLHE_MISSING — the correct
    // outcome.
    let name_owned = unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned();

    // SAFETY: per the `# Safety` contract `easy` is a live handle produced by
    // `curl_easy_init` (a leaked `Box<Easy>`) and is not used concurrently, so an
    // exclusive reference is valid for the duration of the call.
    let data: &mut Easy = unsafe { &mut *(easy as *mut Easy) };

    // Run the lookup and materialize OWNED output in the same expression, so the
    // mutable borrow of `data` ends here — before we touch the thread-local
    // store or write through `hout`.
    let built = match data
        .headers_mut()
        .header(name_owned.as_str(), index, origin, request)
    {
        Ok(h) => Ok((
            CString::new(h.name.as_bytes()),
            CString::new(h.value.as_bytes()),
            h.amount,
            h.index,
            h.origin,
            h.anchor,
        )),
        Err(e) => Err(CURLHcode::from(e)),
    };

    let (name_res, value_res, amount, inst_index, origin_bits, anchor) = match built {
        Ok(tuple) => tuple,
        Err(code) => return code,
    };

    // A header matched but its name/value could not be expressed as a C string
    // (an interior NUL — impossible for real wire headers). Report a processing
    // failure rather than hand back a malformed pointer.
    let (cname, cvalue) = match (name_res, value_res) {
        (Ok(n), Ok(v)) => (Some(n), Some(v)),
        _ => return CURLHcode::CURLHE_OUT_OF_MEMORY,
    };

    let out = store_header(
        easy as usize,
        0,
        cname,
        cvalue,
        amount,
        inst_index,
        origin_bits,
        anchor,
    );

    // SAFETY: per the `# Safety` contract `hout` is non-null and points to
    // writable storage for exactly one `*mut curl_header`.
    unsafe {
        *hout = out;
    }
    CURLHcode::CURLHE_OK
}

// =============================================================================
// Exported symbol 2 / 2 — curl_easy_nextheader
// =============================================================================

/// Iterate the collected HTTP response headers (`curl_easy_nextheader`).
///
/// Returns the next header on `easy` within the `origin` bitmask and `request`
/// number (`-1` = the most recent request), resuming **after** `prev`. Pass
/// `prev = NULL` to obtain the first matching header; pass the previously
/// returned header to continue. Returns NULL when the scope is exhausted, when
/// `request` exceeds the highest request seen, or when `easy` is NULL.
///
/// The returned `struct curl_header` is **owned by the easy handle** under the
/// same lifetime rule as [`curl_easy_header`] (it occupies a separate slot, so
/// it does not clobber a value previously obtained from `curl_easy_header`); the
/// caller must **not** free it.
///
/// # Safety
///
/// * `easy` must be NULL, or a valid easy handle returned by `curl_easy_init`
///   that is not used concurrently from another thread for the duration of the
///   call.
/// * `prev` must be NULL, or a `curl_header` pointer previously returned by
///   `curl_easy_header` / `curl_easy_nextheader` on this handle and still valid
///   (its `anchor` is read to resume iteration). It is not dereferenced as a
///   pointer beyond reading the opaque `anchor` value.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_nextheader(
    easy: *mut CURL,
    origin: c_uint,
    request: c_int,
    prev: *mut curl_header,
) -> *mut curl_header {
    if easy.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: per the `# Safety` contract `easy` is a live handle produced by
    // `curl_easy_init` and is not used concurrently, so an exclusive reference
    // is valid for the duration of the call.
    let data: &mut Easy = unsafe { &mut *(easy as *mut Easy) };

    let prev_anchor: Option<usize> = if prev.is_null() {
        None
    } else {
        // SAFETY: per the `# Safety` contract `prev` was returned by an earlier
        // `curl_easy_header`/`curl_easy_nextheader` call on THIS handle and is
        // still live; its `anchor` field carries the core store index to resume
        // after (it is read as an opaque value, never dereferenced).
        Some(unsafe { (*prev).anchor } as usize)
    };

    // Run the lookup and materialize OWNED output, ending the borrow of `data`
    // before the thread-local store is touched.
    let built = data
        .headers_mut()
        .nextheader_from(origin, request, prev_anchor)
        .map(|h| {
            (
                CString::new(h.name.as_bytes()),
                CString::new(h.value.as_bytes()),
                h.amount,
                h.index,
                h.origin,
                h.anchor,
            )
        });

    let (name_res, value_res, amount, inst_index, origin_bits, anchor) = match built {
        Some(tuple) => tuple,
        None => return ptr::null_mut(),
    };

    let (cname, cvalue) = match (name_res, value_res) {
        (Ok(n), Ok(v)) => (Some(n), Some(v)),
        // Interior NUL in a materialized header (impossible for wire headers):
        // end iteration defensively rather than return a malformed pointer.
        _ => return ptr::null_mut(),
    };

    store_header(
        easy as usize,
        1,
        cname,
        cvalue,
        amount,
        inst_index,
        origin_bits,
        anchor,
    )
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::{curl_easy_header, curl_easy_nextheader, drop_handle_headers};
    use crate::error_codes::CURLHcode;
    use crate::types::{curl_header, CURL, CURLH_HEADER, CURLH_PSEUDO, CURLH_TRAILER};
    use curl_rs_lib::Easy;
    use std::ffi::{CStr, CString};
    use std::ptr;

    /// Reserved bit OR'd into the returned `origin` (`copy_header_external`).
    const CURLH_RESERVED_BIT: u32 = 1 << 27;

    /// Obtain the opaque `CURL*` handle for an `Easy` (the FFI ABI: `CURL` is an
    /// opaque alias for the boxed `Easy`). The returned raw pointer carries no
    /// borrow, so `easy` is free to be re-borrowed through it by the FFI shims.
    fn handle_of(easy: &mut Easy) -> *mut CURL {
        easy as *mut Easy as *mut CURL
    }

    /// Read a returned `curl_header`'s `value` as a `&str` for assertions.
    ///
    /// # Safety
    /// `h` must be a non-null `curl_header*` returned by the API on a live handle.
    unsafe fn value_of(h: *mut curl_header) -> String {
        // SAFETY: caller guarantees `h` is a valid header pointer with a valid
        // NUL-terminated `value` owned by the handle.
        unsafe { CStr::from_ptr((*h).value) }
            .to_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn header_null_arguments_return_bad_argument() {
        let mut easy = Easy::new();
        easy.headers_mut().push(b"X-A: 1\r\n", CURLH_HEADER).unwrap();
        let h = handle_of(&mut easy);
        let nm = CString::new("x-a").unwrap();
        let mut out: *mut curl_header = ptr::null_mut();

        // NULL easy / name / hout each yield CURLHE_BAD_ARGUMENT.
        // SAFETY: controlled test invocation of `curl_easy_header`; the NULL
        // easy handle here intentionally exercises the bad-argument path, and
        // the remaining pointer arguments are valid for the call.
        let c1 = unsafe {
            curl_easy_header(ptr::null_mut(), nm.as_ptr(), 0, CURLH_HEADER, -1, &mut out)
        };
        assert_eq!(c1, CURLHcode::CURLHE_BAD_ARGUMENT);
        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let c2 = unsafe { curl_easy_header(h, ptr::null(), 0, CURLH_HEADER, -1, &mut out) };
        assert_eq!(c2, CURLHcode::CURLHE_BAD_ARGUMENT);
        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let c3 = unsafe { curl_easy_header(h, nm.as_ptr(), 0, CURLH_HEADER, -1, ptr::null_mut()) };
        assert_eq!(c3, CURLHcode::CURLHE_BAD_ARGUMENT);

        drop_handle_headers(h);
    }

    #[test]
    fn header_no_headers_collected() {
        let mut easy = Easy::new();
        let h = handle_of(&mut easy);
        let nm = CString::new("any").unwrap();
        let mut out: *mut curl_header = ptr::null_mut();
        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let code = unsafe { curl_easy_header(h, nm.as_ptr(), 0, CURLH_HEADER, -1, &mut out) };
        assert_eq!(code, CURLHcode::CURLHE_NOHEADERS);
        drop_handle_headers(h);
    }

    #[test]
    fn header_found_populates_struct() {
        let mut easy = Easy::new();
        easy.headers_mut()
            .push(b"Content-Type: text/html\r\n", CURLH_HEADER)
            .unwrap();
        let h = handle_of(&mut easy);
        let nm = CString::new("content-type").unwrap();
        let mut out: *mut curl_header = ptr::null_mut();

        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let code = unsafe { curl_easy_header(h, nm.as_ptr(), 0, CURLH_HEADER, -1, &mut out) };
        assert_eq!(code, CURLHcode::CURLHE_OK);
        assert!(!out.is_null());

        // SAFETY: `out` was just set by the FFI call above to a valid, non-null object; the shared borrow does not outlive it.
        let hdr = unsafe { &*out };
        // SAFETY: `hdr.name` is non-null and a valid NUL-terminated C string for the duration of the borrow.
        let name = unsafe { CStr::from_ptr(hdr.name) }.to_str().unwrap();
        // SAFETY: `hdr.value` is non-null and a valid NUL-terminated C string for the duration of the borrow.
        let value = unsafe { CStr::from_ptr(hdr.value) }.to_str().unwrap();
        assert_eq!(name, "Content-Type"); // wire case preserved
        assert_eq!(value, "text/html");
        assert_eq!(hdr.amount, 1);
        assert_eq!(hdr.index, 0);
        // Low bits equal CURLH_HEADER; the reserved bit is OR'd in so `==`
        // against the documented constant is impossible (matches curl).
        assert_eq!(hdr.origin & CURLH_HEADER, CURLH_HEADER);
        assert_ne!(hdr.origin & CURLH_RESERVED_BIT, 0);
        assert_ne!(hdr.origin, CURLH_HEADER);

        drop_handle_headers(h);
    }

    #[test]
    fn header_missing_bad_index_and_bad_argument() {
        let mut easy = Easy::new();
        easy.headers_mut().push(b"A: 1\r\n", CURLH_HEADER).unwrap();
        let h = handle_of(&mut easy);
        let mut out: *mut curl_header = ptr::null_mut();

        let nb = CString::new("b").unwrap();
        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let c1 = unsafe { curl_easy_header(h, nb.as_ptr(), 0, CURLH_HEADER, -1, &mut out) };
        assert_eq!(c1, CURLHcode::CURLHE_MISSING);

        let na = CString::new("a").unwrap();
        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let c2 = unsafe { curl_easy_header(h, na.as_ptr(), 1, CURLH_HEADER, -1, &mut out) };
        assert_eq!(c2, CURLHcode::CURLHE_BADINDEX);

        // Existing name but wrong origin mask -> missing.
        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let c3 = unsafe { curl_easy_header(h, na.as_ptr(), 0, CURLH_TRAILER, -1, &mut out) };
        assert_eq!(c3, CURLHcode::CURLHE_MISSING);

        // origin == 0 and request < -1 are rejected by the core as bad argument.
        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let c4 = unsafe { curl_easy_header(h, na.as_ptr(), 0, 0, -1, &mut out) };
        assert_eq!(c4, CURLHcode::CURLHE_BAD_ARGUMENT);
        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let c5 = unsafe { curl_easy_header(h, na.as_ptr(), 0, CURLH_HEADER, -2, &mut out) };
        assert_eq!(c5, CURLHcode::CURLHE_BAD_ARGUMENT);

        drop_handle_headers(h);
    }

    #[test]
    fn header_no_request_number() {
        let mut easy = Easy::new();
        easy.headers_mut().push(b"A: 1\r\n", CURLH_HEADER).unwrap();
        let h = handle_of(&mut easy);
        let na = CString::new("a").unwrap();
        let mut out: *mut curl_header = ptr::null_mut();
        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let code = unsafe { curl_easy_header(h, na.as_ptr(), 0, CURLH_HEADER, 5, &mut out) };
        assert_eq!(code, CURLHcode::CURLHE_NOREQUEST);
        drop_handle_headers(h);
    }

    #[test]
    fn header_request_chain_indexing() {
        let mut easy = Easy::new();
        {
            let hc = easy.headers_mut();
            hc.push(b"Stage: first\r\n", CURLH_HEADER).unwrap();
            hc.bump_request();
            hc.push(b"Stage: second\r\n", CURLH_HEADER).unwrap();
        }
        let h = handle_of(&mut easy);
        let nm = CString::new("stage").unwrap();
        let mut out: *mut curl_header = ptr::null_mut();

        // request 0 selects the first response; request 1 / -1 the second.
        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let c0 = unsafe { curl_easy_header(h, nm.as_ptr(), 0, CURLH_HEADER, 0, &mut out) };
        assert_eq!(c0, CURLHcode::CURLHE_OK);
        // SAFETY: `out` was set by the FFI call above to a valid `curl_header` pointer; `value_of` only reads through it.
        assert_eq!(unsafe { value_of(out) }, "first");

        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let c1 = unsafe { curl_easy_header(h, nm.as_ptr(), 0, CURLH_HEADER, 1, &mut out) };
        assert_eq!(c1, CURLHcode::CURLHE_OK);
        // SAFETY: `out` was set by the FFI call above to a valid `curl_header` pointer; `value_of` only reads through it.
        assert_eq!(unsafe { value_of(out) }, "second");

        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let cl = unsafe { curl_easy_header(h, nm.as_ptr(), 0, CURLH_HEADER, -1, &mut out) };
        assert_eq!(cl, CURLHcode::CURLHE_OK);
        // SAFETY: `out` was set by the FFI call above to a valid `curl_header` pointer; `value_of` only reads through it.
        assert_eq!(unsafe { value_of(out) }, "second");

        drop_handle_headers(h);
    }

    #[test]
    fn nextheader_iterates_in_order_then_null() {
        let mut easy = Easy::new();
        {
            let hc = easy.headers_mut();
            hc.push(b"A: 1\r\n", CURLH_HEADER).unwrap();
            hc.push(b"B: 2\r\n", CURLH_HEADER).unwrap();
            // A pseudo header is excluded by the CURLH_HEADER mask below.
            hc.push(b":status: 200\r\n", CURLH_PSEUDO).unwrap();
            hc.push(b"C: 3\r\n", CURLH_HEADER).unwrap();
        }
        let h = handle_of(&mut easy);

        let mut names: Vec<String> = Vec::new();
        let mut prev: *mut curl_header = ptr::null_mut();
        loop {
            // SAFETY: controlled test invocation of `curl_easy_nextheader`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
            let cur = unsafe { curl_easy_nextheader(h, CURLH_HEADER, -1, prev) };
            if cur.is_null() {
                break;
            }
            // SAFETY: `cur` is non-null and points to a live, valid node here; `name` is a `Copy` value read out before the node is freed.
            let nm = unsafe { CStr::from_ptr((*cur).name) }
                .to_str()
                .unwrap()
                .to_owned();
            names.push(nm);
            prev = cur;
        }
        assert_eq!(
            names,
            vec!["A".to_owned(), "B".to_owned(), "C".to_owned()]
        );

        drop_handle_headers(h);
    }

    #[test]
    fn header_then_nextheader_anchor_roundtrip_and_slot_separation() {
        let mut easy = Easy::new();
        {
            let hc = easy.headers_mut();
            hc.push(b"Set-Cookie: a=1\r\n", CURLH_HEADER).unwrap();
            hc.push(b"Set-Cookie: b=2\r\n", CURLH_HEADER).unwrap();
        }
        let h = handle_of(&mut easy);
        let nm = CString::new("set-cookie").unwrap();
        let mut out: *mut curl_header = ptr::null_mut();

        // SAFETY: controlled test invocation of `curl_easy_header`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let code = unsafe { curl_easy_header(h, nm.as_ptr(), 0, CURLH_HEADER, -1, &mut out) };
        assert_eq!(code, CURLHcode::CURLHE_OK);
        // SAFETY: `out` was set by the FFI call above to a valid `curl_header` pointer; `value_of` only reads through it.
        assert_eq!(unsafe { value_of(out) }, "a=1");
        // SAFETY: `out` is non-null and points to a live, valid node here; `amount` is a `Copy` value read out before the node is freed.
        assert_eq!(unsafe { (*out).amount }, 2);
        // SAFETY: `out` is non-null and points to a live, valid node here; `index` is a `Copy` value read out before the node is freed.
        assert_eq!(unsafe { (*out).index }, 0);

        // Resume iteration from the header() result via its opaque anchor: the
        // next Set-Cookie in scope is the second instance.
        // SAFETY: controlled test invocation of `curl_easy_nextheader`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let nxt = unsafe { curl_easy_nextheader(h, CURLH_HEADER, -1, out) };
        assert!(!nxt.is_null());
        // SAFETY: `nxt` was set by the FFI call above to a valid `curl_header` pointer; `value_of` only reads through it.
        assert_eq!(unsafe { value_of(nxt) }, "b=2");
        // SAFETY: `nxt` is non-null and points to a live, valid node here; `index` is a `Copy` value read out before the node is freed.
        assert_eq!(unsafe { (*nxt).index }, 1);

        // Slot separation: curl_easy_nextheader uses a distinct slot, so the
        // earlier curl_easy_header result (`out`) is still intact.
        // SAFETY: `out` was set by the FFI call above to a valid `curl_header` pointer; `value_of` only reads through it.
        assert_eq!(unsafe { value_of(out) }, "a=1");

        drop_handle_headers(h);
    }

    #[test]
    fn nextheader_first_when_prev_null_and_exhausts() {
        let mut easy = Easy::new();
        easy.headers_mut()
            .push(b"Only: here\r\n", CURLH_HEADER)
            .unwrap();
        let h = handle_of(&mut easy);

        // SAFETY: controlled test invocation of `curl_easy_nextheader`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let first = unsafe { curl_easy_nextheader(h, CURLH_HEADER, -1, ptr::null_mut()) };
        assert!(!first.is_null());
        // SAFETY: `first` is non-null and points to a live, valid node here; `name` is a `Copy` value read out before the node is freed.
        let name = unsafe { CStr::from_ptr((*first).name) }.to_str().unwrap();
        assert_eq!(name, "Only");
        // SAFETY: `first` is non-null and points to a live, valid node here; `amount` is a `Copy` value read out before the node is freed.
        assert_eq!(unsafe { (*first).amount }, 1);
        // SAFETY: `first` is non-null and points to a live, valid node here; `index` is a `Copy` value read out before the node is freed.
        assert_eq!(unsafe { (*first).index }, 0);

        // No further header of this type.
        // SAFETY: controlled test invocation of `curl_easy_nextheader`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let next = unsafe { curl_easy_nextheader(h, CURLH_HEADER, -1, first) };
        assert!(next.is_null());

        drop_handle_headers(h);
    }

    #[test]
    fn nextheader_null_easy_returns_null() {
        let r =
            // SAFETY: controlled test invocation of `curl_easy_nextheader`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
            unsafe { curl_easy_nextheader(ptr::null_mut(), CURLH_HEADER, -1, ptr::null_mut()) };
        assert!(r.is_null());
    }

    #[test]
    fn nextheader_request_beyond_seen_returns_null() {
        let mut easy = Easy::new();
        easy.headers_mut().push(b"A: 1\r\n", CURLH_HEADER).unwrap();
        let h = handle_of(&mut easy);
        // SAFETY: controlled test invocation of `curl_easy_nextheader`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
        let r = unsafe { curl_easy_nextheader(h, CURLH_HEADER, 9, ptr::null_mut()) };
        assert!(r.is_null());
        drop_handle_headers(h);
    }

    #[test]
    fn drop_handle_headers_is_safe_noop() {
        // NULL and unknown handles are no-ops (no deref, no panic).
        drop_handle_headers(ptr::null());
        let mut easy = Easy::new();
        let h = handle_of(&mut easy);
        drop_handle_headers(h);
        // Double-drop is also safe.
        drop_handle_headers(h);
    }
}

