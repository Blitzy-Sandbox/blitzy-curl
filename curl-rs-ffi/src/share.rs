// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! # `curl_share_*`, `curl_mime_*`, and the deprecated `curl_form*` C ABI entry points
//!
//! This module is the `extern "C"` home of 19 public `CURL_EXTERN` functions of the
//! curl/libcurl 8.19.0-DEV surface, all declared in `include/curl/curl.h` and backed by the C
//! reference implementations `lib/curl_share.c`, `lib/mime.c`, and `lib/formdata.c` (retained in
//! the tree as read-only source-of-truth references):
//!
//! * **Cross-handle sharing (4):** [`curl_share_init`], [`curl_share_setopt`],
//!   [`curl_share_cleanup`], [`curl_share_strerror`].
//! * **MIME multipart (12):** [`curl_mime_init`], [`curl_mime_free`], [`curl_mime_addpart`],
//!   [`curl_mime_name`], [`curl_mime_filename`], [`curl_mime_type`], [`curl_mime_encoder`],
//!   [`curl_mime_data`], [`curl_mime_filedata`], [`curl_mime_data_cb`], [`curl_mime_subparts`],
//!   [`curl_mime_headers`].
//! * **Deprecated HTTP form API (3):** [`curl_formadd`], [`curl_formget`], [`curl_formfree`].
//!   These were deprecated in curl 7.56.0 in favour of the mime API, but the symbols MUST remain
//!   exported for ABI parity — a `nm -gD` drop-in comparison against curl 8.x `libcurl.so` must
//!   still resolve them (AAP §0.6.1, §0.7.2).
//!
//! ## Handle model
//!
//! Following the crate's opaque-handle discipline (see `lib.rs`), C handles are heap-boxed Rust
//! state exposed as raw pointers:
//!
//! * `CURLSH *` ↔ `Box<Arc<Mutex<ShareState>>>`. The boxed [`ShareState`] holds the FFI-only
//!   lock/unlock callbacks plus a clone of the core cross-handle sharing object,
//!   [`curl_rs_lib::multi::Share`] — the `Arc<Mutex<…>>` fine-grained sharing model (AAP §0.3.2).
//!   That inner `Arc<Share>` is the real clone-handle attached easy handles hold (via
//!   `CURLOPT_SHARE`), and it owns the per-data-class shared caches (cookies / DNS / connection
//!   pool / PSL / HSTS / SSL sessions, each independently locked) together with the `specifier`
//!   bitmask and the `dirty` attach count. Boxing the outer `Arc<Mutex<ShareState>>` gives the
//!   share a stable raw address that survives being handed across the FFI boundary.
//! * `curl_mime *` ↔ `Box<MimeHandle>` and `curl_mimepart *` ↔ a `Box<PartHandle>` owned by that
//!   `MimeHandle`. The part handles buffer each part's configuration (see [`PartHandle`] for why
//!   the FFI layer buffers rather than boxing `curl_rs_lib::mime::Part` directly) and are
//!   assembled into a `curl_rs_lib::mime::Mime` on demand via [`MimeHandle::to_core_mime`].
//! * `struct curl_httppost *` is the **public `#[repr(C)]` ABI struct** ([`curl_httppost`]); the
//!   deprecated form chain is walked directly through it and converted into the core
//!   `curl_rs_lib::mime` model.
//!
//! ## Unsafe & panic policy (AAP §0.6.2 / §0.7.2 — binding)
//!
//! `curl-rs-ffi` is the only workspace crate permitted `unsafe`. Every `unsafe` block below
//! carries a `// SAFETY:` comment stating the invariant it upholds, and no panic may unwind
//! across the `extern "C"` boundary: fallible bodies run inside [`crate::ffi_guard`], and the
//! remaining entry points are panic-free by construction (null/invalid inputs return an error
//! code or null, never panic; mutex poisoning is recovered rather than propagated).
//!
//! ## Variadic mechanism (MSRV 1.75, `c_variadic` unavailable)
//!
//! [`curl_share_setopt`] and [`curl_formadd`] are C variadics (`…, …)`). True Rust C-variadic
//! *definitions* require the nightly-only `c_variadic` feature (rust-lang/rust#44930), which is
//! unavailable on the pinned stable MSRV (1.75). Consistent with `easy.rs` and `mprintf.rs`, both
//! functions therefore take fixed parameters and omit the `…`: [`curl_share_setopt`] captures its
//! single promoted argument as `arg: usize` (ABI-correct on the System V AMD64 target — the third
//! integer/pointer argument is passed in `rdx` whether or not the callee is declared variadic).
//! [`curl_formadd`] is the harder case: it does not merely *receive* one promoted argument, it must
//! *read* an open-ended `CURLFORM_*` option list to build the form chain, and that list cannot be
//! walked without `va_list` machinery on stable. A C trampoline that walked the varargs is ruled
//! out by AAP §0.5.2 (no new C linkage). It therefore matches curl's own form-API-disabled build
//! exactly — returning `CURL_FORMADD_DISABLED` and appending nothing, identical to the
//! `#else /* if disabled */` stub in `lib/formdata.c` — which is the honest, ABI-compatible signal
//! (never a false `CURL_FORMADD_OK`). Modern callers use the mime API. `cbindgen` header generation
//! is best-effort and never clobbers the committed `include/curl/curl.h`, which keeps the real
//! `…, …)` declarations and remains the authoritative ABI surface.

// Require every unsafe operation to sit inside an explicit `unsafe { … }` block, even inside an
// `unsafe fn`, so each carries its own adjacent `// SAFETY:` note (AAP §0.7.2). The lowercase C
// type names and the `curl_*` symbol spelling are permitted by the crate-root
// `#![allow(non_camel_case_types)]` / `#![allow(non_snake_case)]` in `lib.rs`.
#![deny(unsafe_op_in_unsafe_fn)]

use crate::easy::{
    curl_off_t, curl_read_callback, curl_seek_callback, CURL_READFUNC_ABORT, CURL_READFUNC_PAUSE,
    CURL_SEEKFUNC_OK,
};
use crate::global::curl_free_callback;
use crate::slist::{curl_slist, curl_slist_free_all, slist_to_vec};
use crate::{as_mut, as_ref, box_from_raw, box_into_raw, ffi_guard, CURLcode};
use curl_rs_lib::error::{share_strerror, CurlShCode, Error};
use curl_rs_lib::mime::{Encoding, HttpPost, Mime, MimeReadCallback, ReadOutcome};
use curl_rs_lib::multi::Share;
use libc::{c_char, c_int, c_long, c_void, size_t};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::mem;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};

// ===========================================================================================
// Phase 1 — Frozen ABI enums, typedefs, and structs (cbindgen-visible, explicit discriminants)
//
// Every integer value below is frozen against `include/curl/curl.h` (AAP §0.7.2): a C consumer
// hard-coding e.g. `CURLSHE_IN_USE == 2` or `CURL_FORMADD_NULL == 3` must keep working. The
// discriminants are therefore written explicitly and must never be reordered.
// ===========================================================================================

/// Return codes for the `curl_share_*` family (`CURLSHcode` in `include/curl/curl.h`).
///
/// Layout mirrors `curl-rs-lib`'s `CurlShCode` but is redeclared here as the `#[repr(i32)]`
/// C-ABI enum that `cbindgen` renders and that the FFI functions return as `c_int`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CURLSHcode {
    /// All fine (0).
    CURLSHE_OK = 0,
    /// An invalid option was passed to `curl_share_setopt` (1).
    CURLSHE_BAD_OPTION = 1,
    /// The share object is currently in use by a running transfer (2).
    CURLSHE_IN_USE = 2,
    /// An invalid share handle was passed (3).
    CURLSHE_INVALID = 3,
    /// Out of memory (4).
    CURLSHE_NOMEM = 4,
    /// The requested sharing feature is not built in (5).
    CURLSHE_NOT_BUILT_IN = 5,
    /// Never used — marks the end of the enum (6).
    CURLSHE_LAST = 6,
}

/// Options accepted by `curl_share_setopt` (`CURLSHoption` in `include/curl/curl.h`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CURLSHoption {
    /// Placeholder / no-op (0).
    CURLSHOPT_NONE = 0,
    /// Begin sharing the data class given by the `curl_lock_data` argument (1).
    CURLSHOPT_SHARE = 1,
    /// Stop sharing the data class given by the `curl_lock_data` argument (2).
    CURLSHOPT_UNSHARE = 2,
    /// Register the mutex-lock callback (3).
    CURLSHOPT_LOCKFUNC = 3,
    /// Register the mutex-unlock callback (4).
    CURLSHOPT_UNLOCKFUNC = 4,
    /// Set the opaque pointer passed back to the lock/unlock callbacks (5).
    CURLSHOPT_USERDATA = 5,
    /// Never used — marks the end of the enum (6).
    CURLSHOPT_LAST = 6,
}

/// The data classes a share object can protect (`curl_lock_data` in `include/curl/curl.h`).
///
/// Order and values are frozen; the sharing bitmask in [`ShareState`] uses `1 << (value)`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum curl_lock_data {
    CURL_LOCK_DATA_NONE = 0,
    /// Internal state lock (never user-requestable).
    CURL_LOCK_DATA_SHARE = 1,
    CURL_LOCK_DATA_COOKIE = 2,
    CURL_LOCK_DATA_DNS = 3,
    CURL_LOCK_DATA_SSL_SESSION = 4,
    CURL_LOCK_DATA_CONNECT = 5,
    CURL_LOCK_DATA_PSL = 6,
    CURL_LOCK_DATA_HSTS = 7,
    CURL_LOCK_DATA_LAST = 8,
}

/// The access level requested by the lock callback (`curl_lock_access` in `include/curl/curl.h`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum curl_lock_access {
    /// Unspecified action (0).
    CURL_LOCK_ACCESS_NONE = 0,
    /// Shared (read) access (1).
    CURL_LOCK_ACCESS_SHARED = 1,
    /// Single (write) access (2).
    CURL_LOCK_ACCESS_SINGLE = 2,
    /// Never used — marks the end of the enum (3).
    CURL_LOCK_ACCESS_LAST = 3,
}

/// User mutex-lock callback registered via `CURLSHOPT_LOCKFUNC`.
///
/// Matches `typedef void (*curl_lock_function)(CURL *handle, curl_lock_data data,
/// curl_lock_access locktype, void *userptr);` (`CURL *` is an opaque `void *`).
pub type curl_lock_function = Option<
    unsafe extern "C" fn(
        handle: *mut c_void,
        data: curl_lock_data,
        locktype: curl_lock_access,
        userptr: *mut c_void,
    ),
>;

/// User mutex-unlock callback registered via `CURLSHOPT_UNLOCKFUNC`.
///
/// Matches `typedef void (*curl_unlock_function)(CURL *handle, curl_lock_data data,
/// void *userptr);`.
pub type curl_unlock_function =
    Option<unsafe extern "C" fn(handle: *mut c_void, data: curl_lock_data, userptr: *mut c_void)>;

/// Opaque MIME multipart handle (`typedef struct curl_mime curl_mime;`).
///
/// The zero-length field makes this a proper opaque C type: consumers only ever hold a
/// `curl_mime *`; the real state lives in the [`MimeHandle`] this pointer is cast from.
#[repr(C)]
pub struct curl_mime {
    _private: [u8; 0],
}

/// Opaque MIME part handle (`typedef struct curl_mimepart curl_mimepart;`).
///
/// A `curl_mimepart *` is a borrowed pointer to a [`PartHandle`] owned by its [`MimeHandle`]; it
/// is freed together with the mime and MUST NOT be freed by the caller.
#[repr(C)]
pub struct curl_mimepart {
    _private: [u8; 0],
}

/// Options for the deprecated `curl_formadd` varargs (`CURLformoption` in `include/curl/curl.h`).
///
/// Declared for header/ABI completeness (`cbindgen` renders the full enum). The values cannot be
/// consumed at runtime on the stable MSRV (no `va_list`); see the module-level variadic note.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CURLformoption {
    CURLFORM_NOTHING = 0,
    CURLFORM_COPYNAME = 1,
    CURLFORM_PTRNAME = 2,
    CURLFORM_NAMELENGTH = 3,
    CURLFORM_COPYCONTENTS = 4,
    CURLFORM_PTRCONTENTS = 5,
    CURLFORM_CONTENTSLENGTH = 6,
    CURLFORM_FILECONTENT = 7,
    CURLFORM_ARRAY = 8,
    CURLFORM_OBSOLETE = 9,
    CURLFORM_FILE = 10,
    CURLFORM_BUFFER = 11,
    CURLFORM_BUFFERPTR = 12,
    CURLFORM_BUFFERLENGTH = 13,
    CURLFORM_CONTENTTYPE = 14,
    CURLFORM_CONTENTHEADER = 15,
    CURLFORM_FILENAME = 16,
    CURLFORM_END = 17,
    CURLFORM_OBSOLETE2 = 18,
    CURLFORM_STREAM = 19,
    CURLFORM_CONTENTLEN = 20,
    /// Never used — marks the end of the enum (21).
    CURLFORM_LASTENTRY = 21,
}

/// Result codes returned by `curl_formadd` (`CURLFORMcode` in `include/curl/curl.h`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CURLFORMcode {
    /// The FORM was OK (0).
    CURL_FORMADD_OK = 0,
    /// Out of memory (1).
    CURL_FORMADD_MEMORY = 1,
    /// A given option was given twice (2).
    CURL_FORMADD_OPTION_TWICE = 2,
    /// A null pointer was given for a `char` (3).
    CURL_FORMADD_NULL = 3,
    /// An unknown option was used (4).
    CURL_FORMADD_UNKNOWN_OPTION = 4,
    /// The form info was not complete (5).
    CURL_FORMADD_INCOMPLETE = 5,
    /// An illegal option was used in an array (6).
    CURL_FORMADD_ILLEGAL_ARRAY = 6,
    /// The form API was disabled at build time (7).
    CURL_FORMADD_DISABLED = 7,
    /// Never used — marks the end of the enum (8).
    CURL_FORMADD_LAST = 8,
}

/// A single node of the deprecated HTTP POST form chain (`struct curl_httppost`).
///
/// All 14 fields are reproduced in their exact `include/curl/curl.h` order and C types so the
/// `#[repr(C)]` layout is byte-identical to curl 8.x. `long` maps to [`c_long`] and `curl_off_t`
/// to [`curl_off_t`] (`long long` on the supported 64-bit targets).
#[repr(C)]
pub struct curl_httppost {
    /// Next entry in the list.
    pub next: *mut curl_httppost,
    /// Pointer to allocated name.
    pub name: *mut c_char,
    /// Length of name length.
    pub namelength: c_long,
    /// Pointer to allocated data contents.
    pub contents: *mut c_char,
    /// Length of contents field, see also `CURL_HTTPPOST_LARGE`.
    pub contentslength: c_long,
    /// Pointer to allocated buffer contents.
    pub buffer: *mut c_char,
    /// Length of buffer field.
    pub bufferlength: c_long,
    /// Content-Type.
    pub contenttype: *mut c_char,
    /// List of extra headers for this form.
    pub contentheader: *mut curl_slist,
    /// If one field name has more than one file, this link should link to following files.
    pub more: *mut curl_httppost,
    /// As defined below (`CURL_HTTPPOST_*`).
    pub flags: c_long,
    /// The `CONTENTTYPE` (extra) filename.
    pub showfilename: *mut c_char,
    /// Pointer to allocated data for `HTTPPOST_CALLBACK`.
    pub userp: *mut c_void,
    /// Alternative length of contents field. Used if `CURL_HTTPPOST_LARGE` is set.
    pub contentlen: curl_off_t,
}

/// `flags` bit: specified content is a filename.
pub const CURL_HTTPPOST_FILENAME: c_long = 1 << 0;
/// `flags` bit: specified content is a filename to read from.
pub const CURL_HTTPPOST_READFILE: c_long = 1 << 1;
/// `flags` bit: `name` is only stored by pointer, not copied.
pub const CURL_HTTPPOST_PTRNAME: c_long = 1 << 2;
/// `flags` bit: `contents` is only stored by pointer, not copied.
pub const CURL_HTTPPOST_PTRCONTENTS: c_long = 1 << 3;
/// `flags` bit: this is a buffer.
pub const CURL_HTTPPOST_BUFFER: c_long = 1 << 4;
/// `flags` bit: `buffer` is only stored by pointer, not copied.
pub const CURL_HTTPPOST_PTRBUFFER: c_long = 1 << 5;
/// `flags` bit: `contents` is obtained from a callback.
pub const CURL_HTTPPOST_CALLBACK: c_long = 1 << 6;
/// `flags` bit: use `contentlen` (`curl_off_t`) instead of `contentslength` (`long`).
pub const CURL_HTTPPOST_LARGE: c_long = 1 << 7;

/// Callback used by `curl_formget` to receive the serialized form in chunks
/// (`typedef size_t (*curl_formget_callback)(void *arg, const char *buf, size_t len);`).
pub type curl_formget_callback =
    Option<unsafe extern "C" fn(arg: *mut c_void, buf: *const c_char, len: size_t) -> size_t>;

/// `datasize` sentinel meaning "the data is a NUL-terminated C string" (`CURL_ZERO_TERMINATED`
/// = `(size_t)-1` in `include/curl/curl.h`).
const CURL_ZERO_TERMINATED: size_t = size_t::MAX;

// ===========================================================================================
// Phase 2 — Cross-handle sharing (CURLSH*): the 4 `curl_share_*` symbols
// ===========================================================================================

/// The mutable state behind a `CURLSH *` handle.
///
/// A `CURLSH *` is a `Box<Arc<Mutex<ShareState>>>` erased to `*mut c_void`. The [`ShareState`]
/// holds the FFI-only lock/unlock callbacks plus a clone of the core cross-handle sharing object,
/// [`Share`] — the actual `Arc` clone-handle attached easy handles hold (AAP §0.3.2, fine-grained
/// per-data-type locking). The specifier bitmask and the `dirty` attach count live on that core
/// `Share` (as atomics) so they stay consistent across the FFI handle and every attached easy
/// handle. All fields are `Send + Sync` (`Share` is `Send + Sync`, the user pointer is stored as
/// its integer address rather than a raw pointer, and C function pointers are `Send + Sync`), so
/// `Arc<Mutex<ShareState>>` is soundly shareable across the multi-thread runtime without tripping
/// `clippy::arc_with_non_send_sync`.
struct ShareState {
    /// The core cross-handle sharing object: the per-data-class shared caches (each independently
    /// locked), the `specifier` bitmask, and the `dirty` attach count. Cloned into each attached
    /// easy handle by `CURLOPT_SHARE` (see [`share_core`]); this is the FFI handle's own reference.
    core: Arc<Share>,
    /// User lock callback registered via `CURLSHOPT_LOCKFUNC`.
    lockfunc: curl_lock_function,
    /// User unlock callback registered via `CURLSHOPT_UNLOCKFUNC`.
    unlockfunc: curl_unlock_function,
    /// Opaque user token passed to the lock/unlock callbacks (`CURLSHOPT_USERDATA`). Stored as its
    /// pointer-width address so the state stays `Send + Sync`; cast back to `*mut c_void` at call.
    clientdata: usize,
}

impl ShareState {
    /// Create a fresh share state with only the internal `CURL_LOCK_DATA_SHARE` class enabled,
    /// matching `curl_share_init` in `lib/curl_share.c`.
    fn new() -> Self {
        ShareState {
            // `Share::new` seeds the specifier with `CURL_LOCK_DATA_SHARE` and a zero attach count.
            core: Arc::new(Share::new()),
            lockfunc: None,
            unlockfunc: None,
            clientdata: 0,
        }
    }

    /// Returns whether the given data class is currently shared (used by the easy layer and by
    /// tests to observe `CURLSHOPT_SHARE`/`CURLSHOPT_UNSHARE`). Delegates to the core [`Share`],
    /// which stores the specifier as a `1 << curl_lock_data` bitmask.
    #[allow(dead_code)]
    pub(crate) fn shares(&self, data: curl_lock_data) -> bool {
        self.core.shares(1u32 << (data as u32))
    }
}

/// Interpret a raw `CURLSH *` and clone out its core [`Share`] — the `Arc` an easy handle holds
/// while attached (`CURLOPT_SHARE`). Returns `None` for a null/invalid handle.
///
/// # Safety
/// `share` must be null or a pointer previously returned by [`curl_share_init`] and not yet
/// reclaimed by [`curl_share_cleanup`].
pub(crate) unsafe fn share_core(share: *mut c_void) -> Option<Arc<Share>> {
    // SAFETY: delegated to this function's contract; `share_arc` null-checks and borrows the boxed
    // `Arc<Mutex<ShareState>>` without taking ownership, and `Arc::clone` of the inner `core` is a
    // cheap refcount bump that hands the caller an independent handle onto the same share.
    let arc = unsafe { share_arc(share) }?;
    Some(Arc::clone(&lock_state(arc).core))
}

/// Interpret a raw `CURLSH *` as its boxed `Arc<Mutex<ShareState>>`.
///
/// # Safety
/// `share` must be null or a pointer previously returned by [`curl_share_init`] and not yet
/// reclaimed by [`curl_share_cleanup`]. The returned borrow is valid for the current call only.
unsafe fn share_arc<'a>(share: *mut c_void) -> Option<&'a Arc<Mutex<ShareState>>> {
    // SAFETY: delegated to the caller's contract above; `as_ref` performs the null check and forms
    // a shared borrow of the boxed `Arc` without taking ownership.
    unsafe { as_ref::<Arc<Mutex<ShareState>>>(share as *const Arc<Mutex<ShareState>>) }
}

/// Lock the share state, recovering (rather than propagating) a poisoned mutex so no panic can
/// unwind across the FFI boundary.
fn lock_state(arc: &Arc<Mutex<ShareState>>) -> std::sync::MutexGuard<'_, ShareState> {
    match arc.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// `CURLSH *curl_share_init(void);`
///
/// Allocate a new share object with default (all-unshared, no callbacks) state and return an
/// opaque handle, or null on allocation failure. Mirrors `curl_share_init` in `lib/curl_share.c`.
#[no_mangle]
pub extern "C" fn curl_share_init() -> *mut c_void {
    // `Arc::new`/`Box::new` can only fail by aborting on OOM; `catch_unwind` upholds the no-unwind
    // contract defensively and yields null on the (practically unreachable) unwind path.
    std::panic::catch_unwind(|| {
        let handle: Arc<Mutex<ShareState>> = Arc::new(Mutex::new(ShareState::new()));
        box_into_raw(handle) as *mut c_void
    })
    .unwrap_or(ptr::null_mut())
}

/// `CURLSHcode curl_share_setopt(CURLSH *share, CURLSHoption option, ...);`
///
/// Variadic in C; on the stable MSRV the single promoted argument is captured as `arg: usize`
/// (see the module-level variadic note). Dispatches on `option`:
/// `CURLSHOPT_SHARE`/`CURLSHOPT_UNSHARE` toggle a `curl_lock_data` class, `CURLSHOPT_LOCKFUNC`/
/// `CURLSHOPT_UNLOCKFUNC` store the callback pointers, and `CURLSHOPT_USERDATA` stores the token.
/// Returns `CURLSHE_IN_USE` while the share is attached to a running transfer and
/// `CURLSHE_BAD_OPTION` for an unknown option or data class, matching `lib/curl_share.c`.
///
/// # Safety
/// `share` must be null or a valid handle from [`curl_share_init`]; for `LOCKFUNC`/`UNLOCKFUNC`
/// the promoted argument must be a matching C function pointer (or null); for `SHARE`/`UNSHARE`
/// it is a `curl_lock_data` promoted to `int`; for `USERDATA` it is an opaque pointer.
#[no_mangle]
pub unsafe extern "C" fn curl_share_setopt(share: *mut c_void, option: c_int, arg: usize) -> c_int {
    ffi_guard(CURLSHcode::CURLSHE_INVALID as c_int, move || {
        // SAFETY: `share` honours the documented contract; `share_arc` null-checks and borrows.
        let arc = match unsafe { share_arc(share) } {
            Some(a) => a,
            None => return CURLSHcode::CURLSHE_INVALID as c_int,
        };
        let mut state = lock_state(arc);
        // SAFETY: for the LOCKFUNC/UNLOCKFUNC options the transmute of `arg` reproduces the C
        // function pointer as documented; all other options read `arg` as a plain integer.
        let code = unsafe { share_setopt_dispatch(&mut state, option, arg) };
        code as c_int
    })
}

/// Apply one `curl_share_setopt` option to `state`. Returns the [`CURLSHcode`] result.
///
/// # Safety
/// For `CURLSHOPT_LOCKFUNC`/`CURLSHOPT_UNLOCKFUNC`, `arg` must be a valid `curl_lock_function` /
/// `curl_unlock_function` pointer value (or 0 for `None`). Other options treat `arg` as data.
unsafe fn share_setopt_dispatch(state: &mut ShareState, option: c_int, arg: usize) -> CURLSHcode {
    // curl forbids modifying a share while it is attached to a live handle. The attach count
    // lives on the core `Share` so it stays correct across the FFI handle and every easy handle.
    if state.core.in_use() {
        return CURLSHcode::CURLSHE_IN_USE;
    }

    const OPT_SHARE: c_int = CURLSHoption::CURLSHOPT_SHARE as c_int;
    const OPT_UNSHARE: c_int = CURLSHoption::CURLSHOPT_UNSHARE as c_int;
    const OPT_LOCKFUNC: c_int = CURLSHoption::CURLSHOPT_LOCKFUNC as c_int;
    const OPT_UNLOCKFUNC: c_int = CURLSHoption::CURLSHOPT_UNLOCKFUNC as c_int;
    const OPT_USERDATA: c_int = CURLSHoption::CURLSHOPT_USERDATA as c_int;

    match option {
        OPT_SHARE => share_set_data_class(state, arg, true),
        OPT_UNSHARE => share_set_data_class(state, arg, false),
        OPT_LOCKFUNC => {
            // SAFETY: per the contract the promoted argument is a `curl_lock_function` pointer (or
            // NULL). `curl_lock_function` is `Option<unsafe extern "C" fn(..)>`, a niche-optimized
            // pointer-sized value, so transmuting the pointer-width `arg` reproduces it exactly
            // (a zero `arg` becomes `None`).
            let f: curl_lock_function = unsafe { mem::transmute::<usize, curl_lock_function>(arg) };
            state.lockfunc = f;
            CURLSHcode::CURLSHE_OK
        }
        OPT_UNLOCKFUNC => {
            // SAFETY: as above; the argument is a `curl_unlock_function` pointer (or NULL), which
            // is pointer-sized and niche-optimized, so the transmute is valid (0 → `None`).
            let f: curl_unlock_function =
                unsafe { mem::transmute::<usize, curl_unlock_function>(arg) };
            state.unlockfunc = f;
            CURLSHcode::CURLSHE_OK
        }
        OPT_USERDATA => {
            // Store the opaque token by its address; cast back to `*mut c_void` at callback time.
            state.clientdata = arg;
            CURLSHcode::CURLSHE_OK
        }
        _ => CURLSHcode::CURLSHE_BAD_OPTION,
    }
}

/// Enable or disable sharing of the data class named by `arg` (a `curl_lock_data` promoted to
/// `int`). Only the user-requestable classes `COOKIE..=HSTS` are accepted, matching the switch in
/// `lib/curl_share.c`; `NONE`, the internal `SHARE`, and out-of-range values are
/// `CURLSHE_BAD_OPTION`.
fn share_set_data_class(state: &mut ShareState, arg: usize, enable: bool) -> CURLSHcode {
    let raw = arg as c_int;
    const COOKIE: c_int = curl_lock_data::CURL_LOCK_DATA_COOKIE as c_int; // 2
    const HSTS: c_int = curl_lock_data::CURL_LOCK_DATA_HSTS as c_int; // 7
    if !(COOKIE..=HSTS).contains(&raw) {
        return CURLSHcode::CURLSHE_BAD_OPTION;
    }
    // Toggle the class on the core `Share`, whose specifier is a `1 << curl_lock_data` bitmask
    // (matching curl's `share->specifier`); this is the same bit the attaching easy handle reads.
    state.core.set_class(1u32 << (raw as u32), enable);
    CURLSHcode::CURLSHE_OK
}

/// `CURLSHcode curl_share_cleanup(CURLSH *share);`
///
/// Tear down a share object. Returns `CURLSHE_INVALID` for a null handle and `CURLSHE_IN_USE`
/// (without freeing) while transfers are still attached, otherwise reclaims the handle and returns
/// `CURLSHE_OK`. The registered lock/unlock callbacks are invoked around teardown exactly as in
/// `lib/curl_share.c`.
///
/// # Safety
/// `share` must be null or a valid handle from [`curl_share_init`] that has not already been
/// cleaned up. After a successful (`CURLSHE_OK`) call the pointer is dangling and must not be
/// reused.
#[no_mangle]
pub unsafe extern "C" fn curl_share_cleanup(share: *mut c_void) -> c_int {
    ffi_guard(CURLSHcode::CURLSHE_INVALID as c_int, move || {
        if share.is_null() {
            return CURLSHcode::CURLSHE_INVALID as c_int;
        }
        // Snapshot the callbacks/token/dirty count under the lock, then drop the borrow before
        // deciding whether to reclaim. `curl_lock_function`, `usize`, and `u32` are all `Copy`.
        // SAFETY: `share` is non-null (checked) and, per the contract, a live handle; borrowing
        // the boxed `Arc` to lock its mutex is sound.
        let (lockfunc, unlockfunc, clientdata, dirty) = {
            let arc = unsafe { &*(share as *const Arc<Mutex<ShareState>>) };
            let state = lock_state(arc);
            (
                state.lockfunc,
                state.unlockfunc,
                state.clientdata,
                // The attach count lives on the core `Share`; a non-zero value means easy handles
                // are still attached, so teardown must be refused with `CURLSHE_IN_USE`.
                state.core.attached(),
            )
        };

        // curl takes the single-access lock around teardown.
        if let Some(lock) = lockfunc {
            // SAFETY: `lock` is the C callback registered via `CURLSHOPT_LOCKFUNC`; invoking it
            // with (NULL handle, DATA_SHARE, ACCESS_SINGLE, clientdata) matches `lib/curl_share.c`.
            unsafe {
                lock(
                    ptr::null_mut(),
                    curl_lock_data::CURL_LOCK_DATA_SHARE,
                    curl_lock_access::CURL_LOCK_ACCESS_SINGLE,
                    clientdata as *mut c_void,
                );
            }
        }

        if dirty > 0 {
            // Still in use: release the lock we just took and refuse to free.
            if let Some(unlock) = unlockfunc {
                // SAFETY: `unlock` is the registered `CURLSHOPT_UNLOCKFUNC` callback; releasing the
                // lock taken immediately above.
                unsafe {
                    unlock(
                        ptr::null_mut(),
                        curl_lock_data::CURL_LOCK_DATA_SHARE,
                        clientdata as *mut c_void,
                    );
                }
            }
            return CURLSHcode::CURLSHE_IN_USE as c_int;
        }

        // Not in use: release the lock, then reclaim (drop) the boxed Arc. Ordering the unlock
        // before the free mirrors `lib/curl_share.c`.
        if let Some(unlock) = unlockfunc {
            // SAFETY: registered unlock callback; final release of the share lock.
            unsafe {
                unlock(
                    ptr::null_mut(),
                    curl_lock_data::CURL_LOCK_DATA_SHARE,
                    clientdata as *mut c_void,
                );
            }
        }
        // SAFETY: `share` is the non-null pointer produced by `box_into_raw::<Arc<..>>` in
        // `curl_share_init` and not previously reclaimed; the snapshot borrow above has ended
        // (NLL), so `box_from_raw` takes unique ownership exactly once and drops the Arc.
        let reclaimed = unsafe { box_from_raw(share as *mut Arc<Mutex<ShareState>>) };
        drop(reclaimed);
        CURLSHcode::CURLSHE_OK as c_int
    })
}

/// `const char *curl_share_strerror(CURLSHcode);`
///
/// Returns a static, process-lifetime, NUL-terminated message for the given code (never freed by
/// the caller). The parameter is received as [`c_int`] rather than the [`CURLSHcode`] enum to
/// avoid undefined behaviour if a C caller passes an out-of-range value; the committed
/// `include/curl/curl.h` keeps the `CURLSHcode` parameter type (the authoritative ABI). Messages
/// come from `curl_rs_lib::error::share_strerror`, matching `curl_share_strerror` in
/// `lib/strerror.c` including the `"CURLSHcode unknown"` fallback.
#[no_mangle]
pub extern "C" fn curl_share_strerror(code: c_int) -> *const c_char {
    share_strerror_ptr(code)
}

/// Intern the fixed share messages once and hand back a process-lifetime pointer. The map is
/// guarded by a poison-recovering mutex so no panic can escape across the FFI boundary.
fn share_strerror_ptr(code: c_int) -> *const c_char {
    static CACHE: OnceLock<Mutex<HashMap<c_int, &'static CStr>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let interned: &&'static CStr = map.entry(code).or_insert_with(|| {
        let msg: &str = match CurlShCode::try_from(code) {
            Ok(sh) => share_strerror(sh),
            // Matches the `default`/`CURLSHE_LAST` arm of `curl_share_strerror` in strerror.c.
            Err(_) => "CURLSHcode unknown",
        };
        let owned = CString::new(msg)
            .or_else(|_| CString::new("CURLSHcode unknown"))
            .unwrap_or_default();
        // Leak once per distinct code to obtain a process-lifetime `&'static CStr` whose pointer
        // stays valid for the entire program, as the C contract requires.
        &*Box::leak(owned.into_boxed_c_str())
    });
    interned.as_ptr()
}

// ===========================================================================================
// Phase 3 — MIME multipart handle model (FFI-side buffering)
//
// Why the FFI layer buffers instead of boxing `curl_rs_lib::mime::Part` directly:
// the core `Mime` stores its parts in a private `Vec<Part>` and `Mime::addpart()` returns a
// borrow of only the *last* element — there is no `part_mut(index)`, no way to push a
// pre-built `Part`, the `Part` fields are private, and its callback is not `Clone`. A
// `curl_mimepart *` handed to C must, however, remain individually addressable and mutable for
// the whole lifetime of the mime (the caller keeps calling `curl_mime_name`, `curl_mime_data`,
// … on it in any order). We therefore buffer each part's configuration in a heap-stable
// `Box<PartHandle>` and assemble a real `curl_rs_lib::mime::Mime` on demand via
// `MimeHandle::to_core_mime` (used when the mime is attached to a transfer, and by the unit
// tests to prove the core backing).
// ===========================================================================================

/// Buffered body source for a [`PartHandle`], mirroring the `MIMEKIND_*` variants in `lib/mime.c`.
// Several fields (the `Data`/`Subparts` payloads and the `Callback` `datasize`/`readfunc`/
// `seekfunc`) are read only by `MimeHandle::to_core_mime`, the FFI→core bridge invoked from the
// sibling `easy.rs` `CURLOPT_MIMEPOST` (attach-to-transfer) path authored in parallel per AAP
// §0.7.3 build-order. Until that consumer is wired the reads are not yet visible to this crate's
// dead-code analysis, so the scoped allow keeps `-D warnings` clean without masking dead code
// elsewhere (mirrors the `slist_to_vec` precedent in `slist.rs`).
#[allow(dead_code)]
#[derive(Default)]
enum PartSource {
    /// No body set (or a body cleared by a NULL argument) — `MIMEKIND_NONE`.
    #[default]
    None,
    /// In-memory data (`curl_mime_data`), binary-safe — `MIMEKIND_DATA`.
    Data(Vec<u8>),
    /// A local file whose contents form the body (`curl_mime_filedata`) — `MIMEKIND_FILE`.
    File(PathBuf),
    /// A callback-driven streaming body (`curl_mime_data_cb`) — `MIMEKIND_CALLBACK`. The `arg`
    /// token is stored as its address; `freefunc` is invoked exactly once when this source is
    /// dropped (see [`PartSource`]'s `Drop`).
    Callback {
        datasize: i64,
        readfunc: curl_read_callback,
        seekfunc: curl_seek_callback,
        freefunc: curl_free_callback,
        arg: usize,
    },
    /// A nested multipart (`curl_mime_subparts`); owned by this part — `MIMEKIND_MULTIPART`.
    Subparts(Box<MimeHandle>),
}

impl Drop for PartSource {
    fn drop(&mut self) {
        // A callback source owns its user token: curl invokes the registered free callback
        // exactly once when the source is released (either replaced by another setter or dropped
        // with the mime). Assigning a new `source` or dropping the `PartHandle` runs this exactly
        // once, upholding that contract; the other variants own only plain Rust memory.
        if let PartSource::Callback {
            freefunc: Some(free),
            arg,
            ..
        } = self
        {
            let free = *free;
            let arg = *arg as *mut c_void;
            // Guard the C free callback with `catch_unwind` so a panic cannot unwind out of
            // `Drop` and across the FFI boundary (AAP §0.6.2/§0.7.2). `Drop` has no way to report
            // an error and a double panic would abort the process, so a panicking free callback is
            // swallowed here — the token is considered released regardless.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // SAFETY: `free` is the `curl_free_callback` the caller registered via
                // `curl_mime_data_cb`, and `arg` is its matching user token; invoking it once here
                // is exactly the documented free contract.
                unsafe {
                    free(arg);
                }
            }));
        }
    }
}

/// The buffered configuration of a single MIME part (the state behind a `curl_mimepart *`).
///
/// Each `curl_mimepart *` points at one of these, boxed and owned by its [`MimeHandle`]; the
/// metadata mirrors `struct curl_mimepart` in `lib/mime.c`. Because both `curl_mime_filedata` and
/// `curl_mime_filename` write `filename` (the latter overriding, curl's documented "last call
/// wins" side effect), call-order is preserved naturally by mutating the same buffered field.
#[derive(Default)]
struct PartHandle {
    /// Content-Disposition `name` (`curl_mime_name`).
    name: Option<String>,
    /// Content-Disposition `filename` (`curl_mime_filename`, or the basename side effect of
    /// `curl_mime_filedata`).
    filename: Option<String>,
    /// `Content-Type` (`curl_mime_type`).
    mimetype: Option<String>,
    /// Content-transfer-encoding name (`curl_mime_encoder`), pre-validated against [`Encoding`].
    encoder: Option<String>,
    /// Extra user headers (`curl_mime_headers`), already duplicated into owned strings.
    headers: Vec<String>,
    /// The part body (`curl_mime_data` / `filedata` / `data_cb` / `subparts`).
    source: PartSource,
}

/// The state behind a `curl_mime *` handle: an ordered list of heap-stable part handles.
///
/// Parts are boxed so a `curl_mimepart *` returned by [`curl_mime_addpart`] keeps a stable address
/// even as later `addpart` calls grow the `Vec`.
///
/// `pub(crate)` so the sibling `easy.rs` `CURLOPT_MIMEPOST` path (authored in parallel per AAP
/// §0.7.3 build-order) can cast the opaque `curl_mime *` back to this type and call
/// [`MimeHandle::to_core_mime`] when attaching the mime to a transfer.
pub(crate) struct MimeHandle {
    /// Each part is boxed so a `curl_mimepart *` handed out by [`MimeHandle::addpart`] keeps a
    /// stable heap address even as later `addpart` calls grow this `Vec` and reallocate its
    /// backing storage. Replacing `Box<PartHandle>` with a bare `PartHandle` (as `clippy::vec_box`
    /// suggests) would dangle every previously returned `curl_mimepart *` on the next growth — a
    /// use-after-free in conforming C callers — so the lint is intentionally allowed here.
    #[allow(clippy::vec_box)]
    parts: Vec<Box<PartHandle>>,
}

impl MimeHandle {
    /// Create an empty mime.
    fn new() -> Self {
        MimeHandle { parts: Vec::new() }
    }

    /// Append a fresh part and return a stable raw pointer to it (owned by this mime).
    fn addpart(&mut self) -> *mut PartHandle {
        self.parts.push(Box::<PartHandle>::default());
        // The just-pushed `Box` owns a heap `PartHandle` whose address is independent of the
        // `Vec`'s backing storage, so returning a pointer into it is stable across future growth.
        let last = self
            .parts
            .last_mut()
            .expect("a part was just pushed, so last_mut cannot be None");
        (&mut **last) as *mut PartHandle
    }

    /// Assemble a real `curl_rs_lib::mime::Mime` from the buffered parts.
    ///
    /// The body source is applied first, then the metadata, so a caller-supplied `filename` always
    /// wins over the basename side effect the core `set_filedata` may set — reproducing curl's
    /// "last call wins" ordering regardless of the order in which the FFI setters were called.
    ///
    /// `pub(crate)` and `#[allow(dead_code)]`: this is the FFI→core mime bridge consumed by the
    /// sibling `easy.rs` `CURLOPT_MIMEPOST` (attach-to-transfer) path authored in parallel per AAP
    /// §0.7.3 build-order; until that consumer is wired it has no in-crate caller (mirrors the
    /// `slist_to_vec` precedent in `slist.rs`).
    #[allow(dead_code)]
    pub(crate) fn to_core_mime(&self) -> Result<Mime, Error> {
        let mut mime = Mime::new();
        for ph in &self.parts {
            let part = mime.addpart();
            match &ph.source {
                PartSource::None => {}
                PartSource::Data(bytes) => {
                    part.set_data(bytes)?;
                }
                PartSource::File(path) => {
                    part.set_filedata(path)?;
                }
                PartSource::Callback {
                    datasize,
                    readfunc,
                    seekfunc,
                    arg,
                    ..
                } => {
                    // A non-owning forwarding reader: the owning free callback stays with the
                    // `PartHandle` (dropped on `curl_mime_free`), so this reader must NOT free.
                    let reader = CMimeCallbackReader {
                        readfunc: *readfunc,
                        seekfunc: *seekfunc,
                        arg: *arg,
                    };
                    part.set_data_cb(*datasize, Box::new(reader))?;
                }
                PartSource::Subparts(sub) => {
                    let child = sub.to_core_mime()?;
                    part.set_subparts(child)?;
                }
            }
            if let Some(name) = ph.name.as_deref() {
                part.set_name(Some(name))?;
            }
            if let Some(filename) = ph.filename.as_deref() {
                part.set_filename(Some(filename))?;
            }
            if let Some(mimetype) = ph.mimetype.as_deref() {
                part.set_type(Some(mimetype))?;
            }
            if let Some(encoder) = ph.encoder.as_deref() {
                part.set_encoder(Some(encoder))?;
            }
            if !ph.headers.is_empty() {
                part.set_headers(ph.headers.clone())?;
            }
        }
        Ok(mime)
    }
}

/// A non-owning [`MimeReadCallback`] that forwards to a C `curl_mime_data_cb` read/seek callback.
///
/// It borrows the C callback pointers and the user token (as its address) from the owning
/// [`PartHandle`]; that `PartHandle` retains sole ownership of the token and frees it via the
/// registered free callback on `curl_mime_free`, so this reader frees nothing on drop. The mime
/// (and hence the `PartHandle`) must outlive any transfer that borrows this reader — exactly the
/// lifetime contract curl places on a mime attached with `CURLOPT_MIMEPOST`. All fields are C
/// function pointers plus an integer address, so the struct is `Send` (as [`MimeReadCallback`]
/// requires) without any `unsafe impl`.
// Constructed only inside `MimeHandle::to_core_mime`, the FFI→core bridge consumed by the sibling
// `easy.rs` `CURLOPT_MIMEPOST` path authored in parallel per AAP §0.7.3 build-order; the scoped
// allow keeps `-D warnings` clean until that consumer is wired (mirrors `slist_to_vec`).
#[allow(dead_code)]
struct CMimeCallbackReader {
    readfunc: curl_read_callback,
    seekfunc: curl_seek_callback,
    arg: usize,
}

impl MimeReadCallback for CMimeCallbackReader {
    fn read(&mut self, buf: &mut [u8]) -> ReadOutcome {
        let readfunc = match self.readfunc {
            Some(f) => f,
            None => return ReadOutcome::Bytes(0),
        };
        if buf.is_empty() {
            return ReadOutcome::Bytes(0);
        }
        // The call is wrapped in `catch_unwind` so a panicking callback aborts the read rather
        // than unwinding across the FFI boundary (AAP §0.6.2).
        let n = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: `readfunc` is the C read callback registered via `curl_mime_data_cb`. We
            // pass a pointer to our buffer, element size 1, count `buf.len()`, and the user token
            // — exactly the `curl_read_callback` contract. The callback writes at most `buf.len()`
            // bytes.
            unsafe {
                readfunc(
                    buf.as_mut_ptr() as *mut c_char,
                    1,
                    buf.len(),
                    self.arg as *mut c_void,
                )
            }
        })) {
            Ok(n) => n,
            // A panicking read callback is treated as an abort of the transfer.
            Err(_) => return ReadOutcome::Abort,
        };
        if n == CURL_READFUNC_ABORT {
            ReadOutcome::Abort
        } else if n == CURL_READFUNC_PAUSE {
            ReadOutcome::Pause
        } else {
            // Clamp to the buffer to stay memory-safe even if a misbehaving callback over-reports.
            ReadOutcome::Bytes(n.min(buf.len()))
        }
    }

    fn seek(&mut self, offset: i64, whence: i32) -> bool {
        let seekfunc = match self.seekfunc {
            Some(f) => f,
            None => return false,
        };
        // The call is wrapped in `catch_unwind` so a panicking callback fails the seek rather than
        // unwinding across the FFI boundary (AAP §0.6.2).
        let r = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: `seekfunc` is the C seek callback registered via `curl_mime_data_cb`;
            // invoked with the user token, offset, and origin per the `curl_seek_callback`
            // contract.
            unsafe {
                seekfunc(
                    self.arg as *mut c_void,
                    offset as curl_off_t,
                    whence as c_int,
                )
            }
        })) {
            Ok(r) => r,
            // A panicking seek callback is treated as a failed seek.
            Err(_) => return false,
        };
        r == CURL_SEEKFUNC_OK
    }
}

/// Borrow a raw `curl_mimepart *` as a mutable [`PartHandle`].
///
/// # Safety
/// `part` must be null or a live `curl_mimepart *` returned by [`curl_mime_addpart`] whose owning
/// mime has not been freed. The borrow is valid for the current call only.
unsafe fn part_mut<'a>(part: *mut curl_mimepart) -> Option<&'a mut PartHandle> {
    // SAFETY: delegated to the caller's contract above; `as_mut` null-checks the pointer.
    unsafe { as_mut::<PartHandle>(part as *mut PartHandle) }
}

/// Borrow a C string as an owned lossy `String`; NULL → `None`.
///
/// MIME/form names and filenames are almost always ASCII, but curl accepts arbitrary bytes; a
/// lossy conversion keeps a non-UTF-8 value as *some* string (never silently dropping a non-null
/// argument), while the core string API only accepts `&str`.
///
/// # Safety
/// `value` must be null or a valid NUL-terminated C string readable for the current call.
unsafe fn cstr_to_string_lossy(value: *const c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: non-null (checked) and, per the contract, a valid NUL-terminated C string.
    Some(
        unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned(),
    )
}

// ===========================================================================================
// Phase 3 — MIME multipart: the 12 `curl_mime_*` symbols
// ===========================================================================================

/// `curl_mime *curl_mime_init(CURL *easy);`
///
/// Create a new (empty) MIME structure. curl roots the mime's storage in the easy handle and
/// returns NULL for a NULL handle; we honour the NULL check without dereferencing the handle (the
/// mime is standalone until attached via `CURLOPT_MIMEPOST`). Returns NULL on allocation failure.
#[no_mangle]
pub extern "C" fn curl_mime_init(easy: *mut c_void) -> *mut curl_mime {
    if easy.is_null() {
        return ptr::null_mut();
    }
    std::panic::catch_unwind(|| box_into_raw(MimeHandle::new()) as *mut curl_mime)
        .unwrap_or(ptr::null_mut())
}

/// `void curl_mime_free(curl_mime *mime);`
///
/// Release a MIME structure and everything it owns. NULL-safe.
///
/// # Safety
/// `mime` must be null or a `curl_mime *` from [`curl_mime_init`] that has not already been freed
/// and has not been attached as subparts of another part (which would have transferred ownership).
/// After this call the pointer is dangling.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_free(mime: *mut curl_mime) {
    if mime.is_null() {
        return;
    }
    // SAFETY: per the contract `mime` is a live `curl_mime *` (boxed `MimeHandle`) not yet freed;
    // `box_from_raw` takes ownership exactly once. Dropping the `MimeHandle` drops every
    // `PartHandle` (each `PartSource::Callback` invokes its free callback exactly once) and any
    // nested subpart mimes, recursively.
    let reclaimed = unsafe { box_from_raw(mime as *mut MimeHandle) };
    drop(reclaimed);
}

/// `curl_mimepart *curl_mime_addpart(curl_mime *mime);`
///
/// Append and return a new part. The returned `curl_mimepart *` is **owned by the mime** and must
/// NOT be freed by the caller; it is released by [`curl_mime_free`]. Returns NULL for a NULL mime.
///
/// # Safety
/// `mime` must be null or a live `curl_mime *` from [`curl_mime_init`].
#[no_mangle]
pub unsafe extern "C" fn curl_mime_addpart(mime: *mut curl_mime) -> *mut curl_mimepart {
    // SAFETY: per the contract `mime` is null or a live `curl_mime *` (boxed `MimeHandle`);
    // `as_mut` null-checks and yields a unique borrow for this call.
    let mh = match unsafe { as_mut::<MimeHandle>(mime as *mut MimeHandle) } {
        Some(m) => m,
        None => return ptr::null_mut(),
    };
    mh.addpart() as *mut curl_mimepart
}

/// Shared body for the string-setting `curl_mime_*` metadata setters.
///
/// # Safety
/// `part` is null or a live `curl_mimepart *`; `value` is null or a valid C string for this call.
unsafe fn mime_set_string(
    part: *mut curl_mimepart,
    value: *const c_char,
    set: impl FnOnce(&mut PartHandle, Option<String>),
) -> c_int {
    // SAFETY: `part` honours the documented contract.
    let ph = match unsafe { part_mut(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
    };
    // SAFETY: `value` honours the documented contract.
    let s = unsafe { cstr_to_string_lossy(value) };
    set(ph, s);
    CURLcode::CURLE_OK as c_int
}

/// `CURLcode curl_mime_name(curl_mimepart *part, const char *name);`
///
/// # Safety
/// `part` is null or a live part; `name` is null or a valid C string for this call.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_name(part: *mut curl_mimepart, name: *const c_char) -> c_int {
    // SAFETY: arguments honour the documented contract.
    unsafe { mime_set_string(part, name, |ph, s| ph.name = s) }
}

/// `CURLcode curl_mime_filename(curl_mimepart *part, const char *filename);`
///
/// # Safety
/// `part` is null or a live part; `filename` is null or a valid C string for this call.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_filename(
    part: *mut curl_mimepart,
    filename: *const c_char,
) -> c_int {
    // SAFETY: arguments honour the documented contract.
    unsafe { mime_set_string(part, filename, |ph, s| ph.filename = s) }
}

/// `CURLcode curl_mime_type(curl_mimepart *part, const char *mimetype);`
///
/// # Safety
/// `part` is null or a live part; `mimetype` is null or a valid C string for this call.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_type(
    part: *mut curl_mimepart,
    mimetype: *const c_char,
) -> c_int {
    // SAFETY: arguments honour the documented contract.
    unsafe { mime_set_string(part, mimetype, |ph, s| ph.mimetype = s) }
}

/// `CURLcode curl_mime_encoder(curl_mimepart *part, const char *encoding);`
///
/// Sets the content-transfer-encoding (`"base64"`, `"quoted-printable"`, `"7bit"`, `"8bit"`, or
/// `"binary"`). A NULL `encoding` resets to the default (no encoder); an unknown name yields
/// `CURLE_BAD_FUNCTION_ARGUMENT`, validated immediately against [`Encoding`] to match `lib/mime.c`.
///
/// # Safety
/// `part` is null or a live part; `encoding` is null or a valid C string for this call.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_encoder(
    part: *mut curl_mimepart,
    encoding: *const c_char,
) -> c_int {
    // SAFETY: `part` honours the documented contract.
    let ph = match unsafe { part_mut(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
    };
    // SAFETY: `encoding` honours the documented contract.
    match unsafe { cstr_to_string_lossy(encoding) } {
        None => {
            ph.encoder = None;
            CURLcode::CURLE_OK as c_int
        }
        Some(name) => {
            if Encoding::from_name(&name).is_none() {
                return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int;
            }
            ph.encoder = Some(name);
            CURLcode::CURLE_OK as c_int
        }
    }
}

/// `CURLcode curl_mime_data(curl_mimepart *part, const char *data, size_t datasize);`
///
/// Set the part body to a copy of `datasize` bytes (binary-safe — the data may contain NULs). A
/// `datasize` of `CURL_ZERO_TERMINATED` treats `data` as a C string (`strlen`). A NULL `data`
/// clears the body (matching `curl_mime_data` in `lib/mime.c`).
///
/// # Safety
/// `part` is null or a live part; `data` is null or points to at least `datasize` readable bytes
/// (or is a valid C string when `datasize == CURL_ZERO_TERMINATED`) for this call.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_data(
    part: *mut curl_mimepart,
    data: *const c_char,
    datasize: size_t,
) -> c_int {
    // SAFETY: `part` honours the documented contract.
    let ph = match unsafe { part_mut(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
    };
    if data.is_null() {
        // curl cleans the part content and returns OK when `data` is NULL.
        ph.source = PartSource::None;
        return CURLcode::CURLE_OK as c_int;
    }
    let len = if datasize == CURL_ZERO_TERMINATED {
        // SAFETY: `data` is non-null (checked) and, per the `CURL_ZERO_TERMINATED` contract, a
        // valid NUL-terminated C string.
        unsafe { libc::strlen(data) }
    } else {
        datasize
    };
    let bytes = if len == 0 {
        Vec::new()
    } else {
        // SAFETY: `data` points to at least `len` readable bytes per the contract; we form a
        // temporary read-only slice and immediately copy it into an owned `Vec` (no aliasing
        // outlives this call).
        unsafe { std::slice::from_raw_parts(data as *const u8, len) }.to_vec()
    };
    ph.source = PartSource::Data(bytes);
    CURLcode::CURLE_OK as c_int
}

/// `CURLcode curl_mime_filedata(curl_mimepart *part, const char *filename);`
///
/// Set the part body to the contents of a local file. As a side effect the part's `filename` is
/// set to the file's base name (overridable by a later `curl_mime_filename`, per curl). Returns
/// `CURLE_READ_ERROR` if the file cannot be `stat`'d and NULL `filename` clears the body — both
/// matching `curl_mime_filedata` in `lib/mime.c`.
///
/// # Safety
/// `part` is null or a live part; `filename` is null or a valid C string for this call.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_filedata(
    part: *mut curl_mimepart,
    filename: *const c_char,
) -> c_int {
    // SAFETY: `part` honours the documented contract.
    let ph = match unsafe { part_mut(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
    };
    // SAFETY: `filename` honours the documented contract.
    let path = match unsafe { cstr_to_string_lossy(filename) } {
        Some(p) => p,
        None => {
            // NULL filename: clean the body only (metadata such as name/filename is preserved).
            ph.source = PartSource::None;
            return CURLcode::CURLE_OK as c_int;
        }
    };
    // curl `stat`s the file eagerly and reports CURLE_READ_ERROR here if that fails, leaving the
    // body unset. Reproduce that return-code behaviour; the actual read happens in `to_core_mime`.
    if std::fs::metadata(&path).is_err() {
        return CURLcode::CURLE_READ_ERROR as c_int;
    }
    // Side effect: default the Content-Disposition filename to the base name (a later
    // `curl_mime_filename` overrides it, since both write `ph.filename` in call order).
    if let Some(base) = Path::new(&path).file_name() {
        ph.filename = Some(base.to_string_lossy().into_owned());
    }
    ph.source = PartSource::File(PathBuf::from(path));
    CURLcode::CURLE_OK as c_int
}

/// `CURLcode curl_mime_data_cb(curl_mimepart *part, curl_off_t datasize,
/// curl_read_callback readfunc, curl_seek_callback seekfunc, curl_free_callback freefunc,
/// void *arg);`
///
/// Set a streaming body driven by C callbacks. The part takes ownership of `arg` and releases it
/// through `freefunc` exactly once when the source is replaced or the mime is freed.
///
/// # Safety
/// `part` is null or a live part. `readfunc`/`seekfunc`/`freefunc` are valid C callbacks (or NULL)
/// and `arg` is the token they expect; the trio and token must remain valid until the mime is
/// freed (curl's documented lifetime for a callback body).
#[no_mangle]
pub unsafe extern "C" fn curl_mime_data_cb(
    part: *mut curl_mimepart,
    datasize: curl_off_t,
    readfunc: curl_read_callback,
    seekfunc: curl_seek_callback,
    freefunc: curl_free_callback,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: `part` honours the documented contract.
    let ph = match unsafe { part_mut(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
    };
    // Assigning `source` drops the previous source first; if that was another callback body its
    // `freefunc` runs exactly once (see `PartSource`'s `Drop`), matching curl's cleanup-then-set.
    ph.source = PartSource::Callback {
        datasize,
        readfunc,
        seekfunc,
        freefunc,
        arg: arg as usize,
    };
    CURLcode::CURLE_OK as c_int
}

/// `CURLcode curl_mime_subparts(curl_mimepart *part, curl_mime *subparts);`
///
/// Attach a nested multipart. **Ownership of `subparts` transfers to `part`**: after a successful
/// call the caller MUST NOT call [`curl_mime_free`] on `subparts` (doing so would be a double
/// free) — curl documents the same transfer. A NULL `subparts` clears the body.
///
/// # Safety
/// `part` is null or a live part; `subparts` is null or a live `curl_mime *` from
/// [`curl_mime_init`] that has not been freed and is not already attached elsewhere.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_subparts(
    part: *mut curl_mimepart,
    subparts: *mut curl_mime,
) -> c_int {
    // SAFETY: `part` honours the documented contract.
    let ph = match unsafe { part_mut(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
    };
    if subparts.is_null() {
        // NULL detaches/frees any existing subparts (clean the body), returning OK.
        ph.source = PartSource::None;
        return CURLcode::CURLE_OK as c_int;
    }
    // OWNERSHIP TRANSFER: take ownership of the subparts mime. After this the caller must not free
    // `subparts` themselves — it is dropped when this part (and its owning mime) is freed.
    // SAFETY: per the contract `subparts` is a live `curl_mime *` (boxed `MimeHandle`) not
    // previously freed or attached; `box_from_raw` takes ownership exactly once.
    let child = match unsafe { box_from_raw(subparts as *mut MimeHandle) } {
        Some(c) => c,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
    };
    ph.source = PartSource::Subparts(child);
    CURLcode::CURLE_OK as c_int
}

/// `CURLcode curl_mime_headers(curl_mimepart *part, struct curl_slist *headers,
/// int take_ownership);`
///
/// Attach custom headers to the part. The header lines are always duplicated into owned strings.
/// If `take_ownership != 0`, the passed `curl_slist` is freed here (curl frees it on the part's
/// teardown); otherwise the caller retains ownership of their list.
///
/// # Safety
/// `part` is null or a live part; `headers` is null or a well-formed `curl_slist` chain valid for
/// this call. When `take_ownership != 0`, `headers` must be owned by the caller and not used
/// afterwards.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_headers(
    part: *mut curl_mimepart,
    headers: *mut curl_slist,
    take_ownership: c_int,
) -> c_int {
    // SAFETY: `part` honours the documented contract.
    let ph = match unsafe { part_mut(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
    };
    // SAFETY: per the contract `headers` is null or a well-formed `curl_slist` chain valid for the
    // call; `slist_to_vec` walks it read-only and copies each datum into an owned `String`, so the
    // buffered headers are independent of the C list regardless of ownership.
    let lines = unsafe { slist_to_vec(headers as *const curl_slist) };
    ph.headers = lines;
    if take_ownership != 0 && !headers.is_null() {
        // The caller handed us ownership; free the C list now (we already duplicated its data).
        // `curl_slist_free_all` is a safe `extern "C"` wrapper that reclaims the chain once.
        curl_slist_free_all(headers);
    }
    CURLcode::CURLE_OK as c_int
}

// ===========================================================================================
// Phase 4 — Deprecated HTTP form API: the 3 `curl_form*` symbols (still exported for ABI parity)
//
// These were deprecated in curl 7.56.0 in favour of `curl_mime_*`, but the symbols MUST remain
// exported (verified by `nm -gD`). The public `struct curl_httppost` chain is the ABI; it is
// converted into the core `curl_rs_lib::mime` model for serialization.
// ===========================================================================================

/// Read an owned byte buffer from a C pointer: `len` bytes when positive, else the NUL-terminated
/// string. NULL → `None`.
///
/// # Safety
/// `ptr` must be null or point to at least `len` readable bytes (when `len > 0`) or a valid
/// NUL-terminated C string (when `len <= 0`), valid for the current call.
unsafe fn read_c_bytes(ptr: *const c_char, len: i64) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    if len > 0 {
        let len = len as usize;
        // SAFETY: `ptr` points to at least `len` readable bytes per the contract; the slice is
        // copied into an owned `Vec` and does not outlive this call.
        Some(unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }.to_vec())
    } else {
        // SAFETY: `ptr` is a valid NUL-terminated C string per the contract.
        Some(unsafe { CStr::from_ptr(ptr) }.to_bytes().to_vec())
    }
}

/// Convert one public `curl_httppost` node into the core buffered [`HttpPost`].
///
/// # Safety
/// The node's pointer fields must each be null or valid for the current call, and its length
/// fields must correctly describe the buffers they annotate (the `struct curl_httppost` contract).
unsafe fn httppost_node_to_core(node: &curl_httppost) -> HttpPost {
    // Content length: `contentlen` (`curl_off_t`) when LARGE is set, else `contentslength`. Both
    // source fields are 64-bit on every supported (LP64) target, so no width conversion is needed.
    let clen: i64 = if node.flags & CURL_HTTPPOST_LARGE != 0 {
        node.contentlen
    } else {
        node.contentslength
    };
    // Built as a single struct literal (rather than `default()` + reassignment) so the mapping
    // from the C node to the core buffered form is expressed in one place.
    HttpPost {
        // `name` honours `namelength` (>0 => that many bytes; else NUL-terminated).
        // SAFETY: `name` is null or valid per the struct contract.
        name: unsafe { read_c_bytes(node.name, node.namelength) },
        namelength: if node.namelength > 0 {
            node.namelength as usize
        } else {
            0
        },
        // SAFETY: `contents` is null or valid for `clen` bytes / NUL-terminated per the contract.
        contents: unsafe { read_c_bytes(node.contents, clen) },
        contentlen: if clen > 0 { clen } else { 0 },
        // `buffer` honours `bufferlength`.
        // SAFETY: `buffer` is null or valid for `bufferlength` bytes per the contract.
        buffer: unsafe { read_c_bytes(node.buffer, node.bufferlength) },
        bufferlen: if node.bufferlength > 0 {
            node.bufferlength as usize
        } else {
            0
        },
        // SAFETY: `contenttype`/`showfilename` are null or valid C strings per the contract.
        contenttype: unsafe { cstr_to_string_lossy(node.contenttype) },
        // SAFETY: `contentheader` is null or a well-formed slist chain per the contract.
        contentheader: unsafe { slist_to_vec(node.contentheader as *const curl_slist) },
        showfilename: unsafe { cstr_to_string_lossy(node.showfilename) },
        flags: node.flags as u32,
        // Recurse the `more` chain (extra files belonging to the same field).
        // SAFETY: `more` is null or a well-formed curl_httppost chain per the contract.
        more: unsafe { httppost_chain_to_core(node.more as *const curl_httppost) },
    }
}

/// Walk a public `curl_httppost` chain (via `next`) into a `Vec<HttpPost>`.
///
/// # Safety
/// `form` must be null or a well-formed `curl_httppost` chain valid for the current call.
unsafe fn httppost_chain_to_core(form: *const curl_httppost) -> Vec<HttpPost> {
    let mut posts = Vec::new();
    let mut cur = form;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null (loop guard) and a live node per the contract.
        let node = unsafe { &*cur };
        // SAFETY: `node`'s fields honour the struct contract.
        posts.push(unsafe { httppost_node_to_core(node) });
        cur = node.next as *const curl_httppost;
    }
    posts
}

/// Reclaim a `char *` owned under the crate's form-allocation model (`CString::into_raw`). NULL-
/// safe.
///
/// # Safety
/// `ptr` must be null or a pointer produced by `CString::into_raw` and not already reclaimed.
unsafe fn free_owned_cstring(ptr: *mut c_char) {
    if !ptr.is_null() {
        // SAFETY: `ptr` came from `CString::into_raw` per the contract; reclaim it exactly once.
        drop(unsafe { CString::from_raw(ptr) });
    }
}

/// `CURLFORMcode curl_formadd(struct curl_httppost **httppost, struct curl_httppost **last_post,
/// ...);`
///
/// Deprecated (curl 7.56.0). This builder is variadic over `CURLFORM_*` options. Constructing the
/// form chain requires *reading* those variadic arguments, which is impossible on the pinned
/// stable MSRV: a C `va_list` cannot be walked without the nightly-only `c_variadic` feature (see
/// the module-level variadic note), and the alternative — a C trampoline that walks the varargs —
/// would introduce new C linkage that AAP §0.5.2 prohibits (no C dependency beyond optional OS
/// GSSAPI). Because neither the variadic option list nor an ABI shim can be provided under those
/// constraints, this entry point behaves exactly like curl's own form-API-disabled build: it
/// returns `CURL_FORMADD_DISABLED` and appends nothing, byte-for-byte identical to the
/// `#else /* if disabled */` stub in `lib/formdata.c` that a `CURL_DISABLE_FORM_API` curl ships.
/// This is the honest, ABI-compatible signal the finding requires — a caller sees a documented
/// non-success code rather than a false `CURL_FORMADD_OK` that would imply a field was added.
/// Modern callers must use the mime API (`curl_mime_*`); the symbol remains exported for ABI
/// parity.
///
/// # Safety
/// `httppost` and `last_post` must be null or valid `struct curl_httppost **` for the call. This
/// implementation never dereferences them (it matches curl's disabled-build stub, which likewise
/// ignores both pointers), so any pointer value — including NULL — is accepted.
#[no_mangle]
pub unsafe extern "C" fn curl_formadd(
    httppost: *mut *mut curl_httppost,
    last_post: *mut *mut curl_httppost,
) -> c_int {
    // Mirror curl's `CURL_DISABLE_FORM_API` stub verbatim: ignore both output pointers and report
    // that the deprecated variadic builder is unavailable in this build.
    let _ = (httppost, last_post);
    CURLFORMcode::CURL_FORMADD_DISABLED as c_int
}

/// `int curl_formget(struct curl_httppost *form, void *arg, curl_formget_callback append);`
///
/// Serialize a form (as `multipart/form-data`) and hand it to `append` in chunks. Returns 0 on
/// success and non-zero on failure, matching `curl_formget` in `lib/formdata.c`.
///
/// # Safety
/// `form` must be null or a well-formed `curl_httppost` chain valid for the call; `append` is a
/// valid `curl_formget_callback` (or NULL) and `arg` the token it expects.
#[no_mangle]
pub unsafe extern "C" fn curl_formget(
    form: *mut curl_httppost,
    arg: *mut c_void,
    append: curl_formget_callback,
) -> c_int {
    ffi_guard(-1, move || {
        let append_fn = match append {
            Some(f) => f,
            None => return -1,
        };
        // SAFETY: per the contract `form` is null or a well-formed chain valid for the call; the
        // conversion walks it read-only and copies out owned buffers.
        let posts = unsafe { httppost_chain_to_core(form as *const curl_httppost) };
        let arg_addr = arg as usize;
        let mut failed = false;
        let result = curl_rs_lib::mime::formget(&posts, |chunk: &[u8]| {
            if failed {
                return Err(Error::bad_argument("curl_formget: append callback aborted"));
            }
            // The call is wrapped in `catch_unwind` so a panicking callback aborts the form walk
            // rather than unwinding across the FFI boundary (AAP §0.6.2).
            let n = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // SAFETY: `append_fn` is the C callback; invoked with the user token, the chunk
                // pointer, and its length per the `curl_formget_callback` contract. A well-behaved
                // callback returns `chunk.len()`; anything else is treated as an abort.
                unsafe {
                    append_fn(
                        arg_addr as *mut c_void,
                        chunk.as_ptr() as *const c_char,
                        chunk.len(),
                    )
                }
            })) {
                Ok(n) => n,
                Err(_) => {
                    // A panicking append callback is treated as an abort of the form walk.
                    failed = true;
                    return Err(Error::bad_argument(
                        "curl_formget: append callback panicked",
                    ));
                }
            };
            if n != chunk.len() {
                failed = true;
                Err(Error::bad_argument("curl_formget: short append write"))
            } else {
                Ok(())
            }
        });
        if result.is_ok() && !failed {
            0
        } else {
            -1
        }
    })
}

/// `void curl_formfree(struct curl_httppost *form);`
///
/// Free a form chain previously built with [`curl_formadd`]. NULL-safe and symmetric with the
/// crate's form-allocation model (`Box<curl_httppost>` nodes, `CString` string fields, and slist
/// headers), walking both the `next` and `more` links. Because this build's [`curl_formadd`] is
/// disabled (it returns `CURL_FORMADD_DISABLED` and allocates no chain), in practice this receives
/// NULL; the traversal is nonetheless the correct complement for any `curl_httppost` chain valid
/// under this crate's allocation model and is only ever validly invoked on such chains (the C
/// contract restricts `curl_formfree` to `curl_formadd` output).
///
/// # Safety
/// `form` must be null or a `curl_httppost` chain produced by [`curl_formadd`] and not already
/// freed. After this call the chain is dangling.
#[no_mangle]
pub unsafe extern "C" fn curl_formfree(form: *mut curl_httppost) {
    let mut cur = form;
    while !cur.is_null() {
        // Snapshot every field we need before freeing so no borrow is alive during reclamation
        // (all fields are `Copy` raw pointers / integers).
        // SAFETY: per the contract `cur` is a live node from `curl_formadd`; reading its fields is
        // sound.
        let (next, more, flags, name, contents, contenttype, showfilename, contentheader) = {
            let node = unsafe { &*cur };
            (
                node.next,
                node.more,
                node.flags,
                node.name,
                node.contents,
                node.contenttype,
                node.showfilename,
                node.contentheader,
            )
        };

        // Free the `more` sub-chain (extra files for the same field) first.
        if !more.is_null() {
            // SAFETY: `more` is a live sub-chain under the same allocation model.
            unsafe { curl_formfree(more) };
        }

        // Free owned string fields, honouring the PTR* "stored by pointer, not copied" flags.
        if flags & CURL_HTTPPOST_PTRNAME == 0 {
            // SAFETY: `name` is an owned `CString` unless PTRNAME says it was borrowed.
            unsafe { free_owned_cstring(name) };
        }
        if flags & CURL_HTTPPOST_PTRCONTENTS == 0 {
            // SAFETY: `contents` is an owned `CString` unless PTRCONTENTS says it was borrowed.
            unsafe { free_owned_cstring(contents) };
        }
        // `contenttype` and `showfilename` are always crate-owned copies.
        // SAFETY: owned `CString`s under the crate's allocation model.
        unsafe { free_owned_cstring(contenttype) };
        // SAFETY: owned `CString` under the crate's allocation model.
        unsafe { free_owned_cstring(showfilename) };
        // NOTE: `buffer` is intentionally not reclaimed here — no `curl_httppost` node produced
        // under this crate's allocation model sets it (the disabled `curl_formadd` allocates no
        // chain), so it is always null and there is nothing to free.
        if !contentheader.is_null() {
            // Free the attached header list (safe `extern "C"` wrapper; reclaims the chain once).
            curl_slist_free_all(contentheader);
        }

        // Reclaim the node box itself.
        // SAFETY: `cur` was produced by `Box::into_raw::<curl_httppost>` per the allocation model
        // and the field snapshot above has ended, so `box_from_raw` takes ownership exactly once.
        drop(unsafe { box_from_raw(cur) });

        cur = next;
    }
}

// ===========================================================================================
// Unit tests — ABI freezing, share lifecycle, mime buffering/ownership, and form conversion.
// ===========================================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use curl_rs_lib::mime::MimeStrategy;

    /// A non-null sentinel used where a `CURL *` is only null-checked (never dereferenced).
    fn dummy_easy() -> *mut c_void {
        1usize as *mut c_void
    }

    fn cstr(s: &str) -> *mut c_char {
        CString::new(s).unwrap().into_raw()
    }

    // ----- Phase 1: frozen ABI integer values -------------------------------------------------

    #[test]
    fn share_enum_values_are_frozen() {
        assert_eq!(CURLSHcode::CURLSHE_OK as i32, 0);
        assert_eq!(CURLSHcode::CURLSHE_BAD_OPTION as i32, 1);
        assert_eq!(CURLSHcode::CURLSHE_IN_USE as i32, 2);
        assert_eq!(CURLSHcode::CURLSHE_INVALID as i32, 3);
        assert_eq!(CURLSHcode::CURLSHE_NOMEM as i32, 4);
        assert_eq!(CURLSHcode::CURLSHE_NOT_BUILT_IN as i32, 5);
        assert_eq!(CURLSHcode::CURLSHE_LAST as i32, 6);

        assert_eq!(CURLSHoption::CURLSHOPT_NONE as i32, 0);
        assert_eq!(CURLSHoption::CURLSHOPT_SHARE as i32, 1);
        assert_eq!(CURLSHoption::CURLSHOPT_UNSHARE as i32, 2);
        assert_eq!(CURLSHoption::CURLSHOPT_LOCKFUNC as i32, 3);
        assert_eq!(CURLSHoption::CURLSHOPT_UNLOCKFUNC as i32, 4);
        assert_eq!(CURLSHoption::CURLSHOPT_USERDATA as i32, 5);
        assert_eq!(CURLSHoption::CURLSHOPT_LAST as i32, 6);
    }

    #[test]
    fn lock_enum_values_are_frozen() {
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_NONE as i32, 0);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_SHARE as i32, 1);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_COOKIE as i32, 2);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_DNS as i32, 3);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_SSL_SESSION as i32, 4);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_CONNECT as i32, 5);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_PSL as i32, 6);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_HSTS as i32, 7);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_LAST as i32, 8);

        assert_eq!(curl_lock_access::CURL_LOCK_ACCESS_NONE as i32, 0);
        assert_eq!(curl_lock_access::CURL_LOCK_ACCESS_SHARED as i32, 1);
        assert_eq!(curl_lock_access::CURL_LOCK_ACCESS_SINGLE as i32, 2);
        assert_eq!(curl_lock_access::CURL_LOCK_ACCESS_LAST as i32, 3);
    }

    #[test]
    fn form_enum_values_are_frozen() {
        assert_eq!(CURLFORMcode::CURL_FORMADD_OK as i32, 0);
        assert_eq!(CURLFORMcode::CURL_FORMADD_MEMORY as i32, 1);
        assert_eq!(CURLFORMcode::CURL_FORMADD_OPTION_TWICE as i32, 2);
        assert_eq!(CURLFORMcode::CURL_FORMADD_NULL as i32, 3);
        assert_eq!(CURLFORMcode::CURL_FORMADD_UNKNOWN_OPTION as i32, 4);
        assert_eq!(CURLFORMcode::CURL_FORMADD_INCOMPLETE as i32, 5);
        assert_eq!(CURLFORMcode::CURL_FORMADD_ILLEGAL_ARRAY as i32, 6);
        assert_eq!(CURLFORMcode::CURL_FORMADD_DISABLED as i32, 7);
        assert_eq!(CURLFORMcode::CURL_FORMADD_LAST as i32, 8);

        assert_eq!(CURLformoption::CURLFORM_NOTHING as i32, 0);
        assert_eq!(CURLformoption::CURLFORM_COPYNAME as i32, 1);
        assert_eq!(CURLformoption::CURLFORM_END as i32, 17);
        assert_eq!(CURLformoption::CURLFORM_CONTENTLEN as i32, 20);
        assert_eq!(CURLformoption::CURLFORM_LASTENTRY as i32, 21);

        assert_eq!(CURL_HTTPPOST_FILENAME, 1);
        assert_eq!(CURL_HTTPPOST_READFILE, 2);
        assert_eq!(CURL_HTTPPOST_PTRNAME, 4);
        assert_eq!(CURL_HTTPPOST_PTRCONTENTS, 8);
        assert_eq!(CURL_HTTPPOST_BUFFER, 16);
        assert_eq!(CURL_HTTPPOST_PTRBUFFER, 32);
        assert_eq!(CURL_HTTPPOST_CALLBACK, 64);
        assert_eq!(CURL_HTTPPOST_LARGE, 128);
        assert_eq!(CURL_ZERO_TERMINATED, size_t::MAX);
    }

    #[test]
    fn curl_httppost_layout_is_lp64_stable() {
        // 14 fields, each 8 bytes on the supported 64-bit targets, no padding.
        assert_eq!(mem::size_of::<curl_httppost>(), 14 * 8);
        assert_eq!(mem::align_of::<curl_httppost>(), 8);
        // Opaque handles are genuinely zero-sized.
        assert_eq!(mem::size_of::<curl_mime>(), 0);
        assert_eq!(mem::size_of::<curl_mimepart>(), 0);
    }

    // ----- Phase 2: share lifecycle -----------------------------------------------------------

    #[test]
    fn share_init_and_cleanup_roundtrip() {
        let sh = curl_share_init();
        assert!(!sh.is_null());
        // Freshly initialised: only the internal SHARE class is enabled.
        // SAFETY: `sh` is a live handle just created.
        let arc = unsafe { share_arc(sh) }.unwrap();
        assert!(lock_state(arc).shares(curl_lock_data::CURL_LOCK_DATA_SHARE));
        assert!(!lock_state(arc).shares(curl_lock_data::CURL_LOCK_DATA_COOKIE));
        // SAFETY: `sh` is live and not previously cleaned up.
        let rc = unsafe { curl_share_cleanup(sh) };
        assert_eq!(rc, CURLSHcode::CURLSHE_OK as c_int);
    }

    #[test]
    fn share_cleanup_null_is_invalid() {
        // SAFETY: null is an explicitly handled input.
        let rc = unsafe { curl_share_cleanup(ptr::null_mut()) };
        assert_eq!(rc, CURLSHcode::CURLSHE_INVALID as c_int);
    }

    #[test]
    fn share_setopt_share_and_unshare_classes() {
        let sh = curl_share_init();
        // Enable COOKIE + DNS.
        // SAFETY: `sh` live; args are `curl_lock_data` integers.
        unsafe {
            assert_eq!(
                curl_share_setopt(
                    sh,
                    CURLSHoption::CURLSHOPT_SHARE as c_int,
                    curl_lock_data::CURL_LOCK_DATA_COOKIE as usize,
                ),
                CURLSHcode::CURLSHE_OK as c_int
            );
            assert_eq!(
                curl_share_setopt(
                    sh,
                    CURLSHoption::CURLSHOPT_SHARE as c_int,
                    curl_lock_data::CURL_LOCK_DATA_DNS as usize,
                ),
                CURLSHcode::CURLSHE_OK as c_int
            );
        }
        // SAFETY: `sh` is the live share handle created by `curl_share_init` above and not yet
        // cleaned up, so reconstructing the boxed `Arc` handle to inspect its state is sound.
        let arc = unsafe { share_arc(sh) }.unwrap();
        assert!(lock_state(arc).shares(curl_lock_data::CURL_LOCK_DATA_COOKIE));
        assert!(lock_state(arc).shares(curl_lock_data::CURL_LOCK_DATA_DNS));

        // Disable COOKIE again.
        // SAFETY: `sh` live.
        unsafe {
            assert_eq!(
                curl_share_setopt(
                    sh,
                    CURLSHoption::CURLSHOPT_UNSHARE as c_int,
                    curl_lock_data::CURL_LOCK_DATA_COOKIE as usize,
                ),
                CURLSHcode::CURLSHE_OK as c_int
            );
        }
        assert!(!lock_state(arc).shares(curl_lock_data::CURL_LOCK_DATA_COOKIE));
        assert!(lock_state(arc).shares(curl_lock_data::CURL_LOCK_DATA_DNS));

        // Rejected classes and options.
        // SAFETY: `sh` live.
        unsafe {
            // NONE (0), the internal SHARE (1), and out-of-range are BAD_OPTION.
            assert_eq!(
                curl_share_setopt(sh, CURLSHoption::CURLSHOPT_SHARE as c_int, 0),
                CURLSHcode::CURLSHE_BAD_OPTION as c_int
            );
            assert_eq!(
                curl_share_setopt(
                    sh,
                    CURLSHoption::CURLSHOPT_SHARE as c_int,
                    curl_lock_data::CURL_LOCK_DATA_SHARE as usize,
                ),
                CURLSHcode::CURLSHE_BAD_OPTION as c_int
            );
            assert_eq!(
                curl_share_setopt(sh, CURLSHoption::CURLSHOPT_SHARE as c_int, 99),
                CURLSHcode::CURLSHE_BAD_OPTION as c_int
            );
            // Unknown option.
            assert_eq!(
                curl_share_setopt(sh, 999, 0),
                CURLSHcode::CURLSHE_BAD_OPTION as c_int
            );
            curl_share_cleanup(sh);
        }
    }

    #[repr(C)]
    struct LockCounters {
        lock: u32,
        unlock: u32,
        last_ud: usize,
    }

    unsafe extern "C" fn count_lock(
        _h: *mut c_void,
        _d: curl_lock_data,
        _l: curl_lock_access,
        ud: *mut c_void,
    ) {
        // SAFETY: the test registers a valid `*mut LockCounters` as userdata.
        let c = unsafe { &mut *(ud as *mut LockCounters) };
        c.lock += 1;
        c.last_ud = ud as usize;
    }

    unsafe extern "C" fn count_unlock(_h: *mut c_void, _d: curl_lock_data, ud: *mut c_void) {
        // SAFETY: the test registers a valid `*mut LockCounters` as userdata.
        let c = unsafe { &mut *(ud as *mut LockCounters) };
        c.unlock += 1;
        c.last_ud = ud as usize;
    }

    #[test]
    fn share_callbacks_and_userdata_are_invoked_on_cleanup() {
        let sh = curl_share_init();
        let cptr = Box::into_raw(Box::new(LockCounters {
            lock: 0,
            unlock: 0,
            last_ud: 0,
        }));

        let lock_fn: curl_lock_function = Some(count_lock);
        let unlock_fn: curl_unlock_function = Some(count_unlock);
        // SAFETY: transmuting the niche-optimized fn-option to its pointer-width integer is the
        // documented way to pass it through the `arg: usize` variadic shim.
        let lock_arg = unsafe { mem::transmute::<curl_lock_function, usize>(lock_fn) };
        let unlock_arg = unsafe { mem::transmute::<curl_unlock_function, usize>(unlock_fn) };

        // SAFETY: `sh` live; args are a fn pointer, a fn pointer, and a userdata pointer.
        unsafe {
            curl_share_setopt(sh, CURLSHoption::CURLSHOPT_LOCKFUNC as c_int, lock_arg);
            curl_share_setopt(sh, CURLSHoption::CURLSHOPT_UNLOCKFUNC as c_int, unlock_arg);
            curl_share_setopt(sh, CURLSHoption::CURLSHOPT_USERDATA as c_int, cptr as usize);
            let rc = curl_share_cleanup(sh);
            assert_eq!(rc, CURLSHcode::CURLSHE_OK as c_int);
        }

        // SAFETY: `cptr` is our live box; reclaim it now that the share is gone.
        let counters = unsafe { Box::from_raw(cptr) };
        assert_eq!(
            counters.lock, 1,
            "lock callback should fire once on cleanup"
        );
        assert_eq!(
            counters.unlock, 1,
            "unlock callback should fire once on cleanup"
        );
        assert_eq!(counters.last_ud, cptr as usize, "userdata must round-trip");
    }

    #[test]
    fn share_in_use_blocks_setopt_and_cleanup() {
        let sh = curl_share_init();
        // Simulate an attached transfer by bumping the core share's attach count (curl's
        // `share->dirty++`), the same call `Easy::attach_share` makes via `CURLOPT_SHARE`.
        {
            // SAFETY: `sh` is a live handle; borrowing to read the guarded state is sound.
            let arc = unsafe { share_arc(sh) }.unwrap();
            lock_state(arc).core.attach();
        }
        // SAFETY: `sh` live.
        unsafe {
            assert_eq!(
                curl_share_setopt(
                    sh,
                    CURLSHoption::CURLSHOPT_SHARE as c_int,
                    curl_lock_data::CURL_LOCK_DATA_DNS as usize,
                ),
                CURLSHcode::CURLSHE_IN_USE as c_int
            );
            assert_eq!(curl_share_cleanup(sh), CURLSHcode::CURLSHE_IN_USE as c_int);
        }
        // Detach and cleanup for real (curl's `share->dirty--`).
        {
            // SAFETY: `sh` is still live — the preceding IN_USE `curl_share_cleanup` did not free
            // it — so borrowing the boxed `Arc` handle to drop the attach count is sound.
            let arc = unsafe { share_arc(sh) }.unwrap();
            lock_state(arc).core.detach();
        }
        // SAFETY: `sh` still live (the IN_USE cleanup did not free it).
        let rc = unsafe { curl_share_cleanup(sh) };
        assert_eq!(rc, CURLSHcode::CURLSHE_OK as c_int);
    }

    #[test]
    fn curlopt_share_attaches_wires_dirty_and_blocks_cleanup() {
        // Frozen ABI integers: the option id and the success code.
        const CURLOPT_SHARE: c_int = crate::easy::CURLoption::CURLOPT_SHARE as c_int;
        let ok = CURLcode::CURLE_OK as c_int;

        // A share configured to share the cookie jar.
        let sh = curl_share_init();
        // SAFETY: `sh` is a live handle from `curl_share_init`.
        unsafe {
            assert_eq!(
                curl_share_setopt(
                    sh,
                    CURLSHoption::CURLSHOPT_SHARE as c_int,
                    curl_lock_data::CURL_LOCK_DATA_COOKIE as usize,
                ),
                CURLSHcode::CURLSHE_OK as c_int
            );
        }
        // The class is recorded on the core share (fine-grained specifier bit — M4).
        {
            // SAFETY: `sh` still live.
            let arc = unsafe { share_arc(sh) }.unwrap();
            assert!(lock_state(arc).shares(curl_lock_data::CURL_LOCK_DATA_COOKIE));
        }

        // Attach it to an easy handle through the real `CURLOPT_SHARE` FFI path (M1).
        let h = crate::easy::curl_easy_init();
        assert!(!h.is_null());
        // SAFETY: `h` is a live easy handle and `sh` a live share; the promoted argument is the
        // `CURLSH *` the option expects.
        let rc = unsafe { crate::easy::curl_easy_setopt(h, CURLOPT_SHARE, sh as usize) };
        assert_eq!(rc, ok, "CURLOPT_SHARE must accept a valid share handle");

        // The share now reports one attached handle, so setopt/cleanup are refused.
        {
            // SAFETY: `sh` still live.
            let arc = unsafe { share_arc(sh) }.unwrap();
            assert_eq!(
                lock_state(arc).core.attached(),
                1,
                "attaching an easy handle must bump the share's dirty count"
            );
        }
        // SAFETY: `sh` live and in use.
        assert_eq!(
            unsafe { curl_share_cleanup(sh) },
            CURLSHcode::CURLSHE_IN_USE as c_int,
            "cleanup must refuse while an easy handle is attached"
        );

        // Cleaning up the easy handle detaches it (its `Drop` calls `detach_share`).
        // SAFETY: `h` is a live handle; cleanup reclaims and drops it.
        unsafe { crate::easy::curl_easy_cleanup(h) };
        {
            // SAFETY: `sh` still live (the IN_USE cleanup did not free it).
            let arc = unsafe { share_arc(sh) }.unwrap();
            assert_eq!(
                lock_state(arc).core.attached(),
                0,
                "cleaning up the easy handle must drop the share's dirty count"
            );
        }

        // With no handle attached, cleanup now succeeds.
        // SAFETY: `sh` live and no longer in use.
        assert_eq!(
            unsafe { curl_share_cleanup(sh) },
            CURLSHcode::CURLSHE_OK as c_int
        );
    }

    #[test]
    fn curlopt_share_null_detaches() {
        const CURLOPT_SHARE: c_int = crate::easy::CURLoption::CURLOPT_SHARE as c_int;
        let ok = CURLcode::CURLE_OK as c_int;
        let sh = curl_share_init();
        let h = crate::easy::curl_easy_init();
        // SAFETY: both are live handles produced by their `*_init` constructors.
        unsafe {
            assert_eq!(
                crate::easy::curl_easy_setopt(h, CURLOPT_SHARE, sh as usize),
                ok
            );
            // Re-issuing `CURLOPT_SHARE` with NULL detaches ("share nothing"), dropping dirty.
            assert_eq!(crate::easy::curl_easy_setopt(h, CURLOPT_SHARE, 0), ok);
        }
        {
            // SAFETY: `sh` still live.
            let arc = unsafe { share_arc(sh) }.unwrap();
            assert_eq!(
                lock_state(arc).core.attached(),
                0,
                "CURLOPT_SHARE with NULL must detach"
            );
        }
        // SAFETY: not in use → OK.
        assert_eq!(
            unsafe { curl_share_cleanup(sh) },
            CURLSHcode::CURLSHE_OK as c_int
        );
        // SAFETY: live handle.
        unsafe { crate::easy::curl_easy_cleanup(h) };
    }

    #[test]
    fn share_strerror_matches_curl_and_interns() {
        let msg = |code: CURLSHcode| -> String {
            // SAFETY: `curl_share_strerror` returns a process-lifetime NUL-terminated pointer.
            unsafe {
                CStr::from_ptr(curl_share_strerror(code as c_int))
                    .to_string_lossy()
                    .into_owned()
            }
        };
        assert_eq!(msg(CURLSHcode::CURLSHE_OK), "No error");
        assert_eq!(msg(CURLSHcode::CURLSHE_BAD_OPTION), "Unknown share option");
        assert_eq!(msg(CURLSHcode::CURLSHE_IN_USE), "Share currently in use");
        assert_eq!(msg(CURLSHcode::CURLSHE_INVALID), "Invalid share handle");
        assert_eq!(msg(CURLSHcode::CURLSHE_NOMEM), "Out of memory");
        assert_eq!(
            msg(CURLSHcode::CURLSHE_NOT_BUILT_IN),
            "Feature not enabled in this library"
        );
        // Unknown / CURLSHE_LAST fall back to curl's "CURLSHcode unknown".
        assert_eq!(msg(CURLSHcode::CURLSHE_LAST), "CURLSHcode unknown");
        // `curl_share_strerror` returns process-lifetime interned pointers (safe to call); the
        // same code must map to the same stable address.
        let a = curl_share_strerror(CURLSHcode::CURLSHE_OK as c_int);
        let b = curl_share_strerror(CURLSHcode::CURLSHE_OK as c_int);
        assert_eq!(a, b, "strerror must intern (stable pointer per code)");
    }

    // ----- Phase 3: mime -----------------------------------------------------------------------

    #[test]
    fn mime_init_null_easy_is_null_valid_is_boxed() {
        assert!(curl_mime_init(ptr::null_mut()).is_null());
        let mime = curl_mime_init(dummy_easy());
        assert!(!mime.is_null());
        // SAFETY: `mime` is a live handle from init.
        unsafe { curl_mime_free(mime) };
    }

    #[test]
    fn mime_free_null_is_safe() {
        // SAFETY: null is an explicitly handled input.
        unsafe { curl_mime_free(ptr::null_mut()) };
    }

    #[test]
    fn mime_metadata_setters() {
        let mime = curl_mime_init(dummy_easy());
        // SAFETY: `mime` live.
        let part = unsafe { curl_mime_addpart(mime) };
        assert!(!part.is_null());
        // SAFETY: `part` live; args are valid C strings / null.
        unsafe {
            let name = cstr("field");
            assert_eq!(curl_mime_name(part, name), CURLcode::CURLE_OK as c_int);
            drop(CString::from_raw(name));
            let fname = cstr("file.txt");
            assert_eq!(curl_mime_filename(part, fname), CURLcode::CURLE_OK as c_int);
            drop(CString::from_raw(fname));
            let ct = cstr("text/plain");
            assert_eq!(curl_mime_type(part, ct), CURLcode::CURLE_OK as c_int);
            drop(CString::from_raw(ct));
            // Valid encoder, then reset with NULL, then an invalid one.
            let enc = cstr("base64");
            assert_eq!(curl_mime_encoder(part, enc), CURLcode::CURLE_OK as c_int);
            drop(CString::from_raw(enc));
            assert_eq!(
                curl_mime_encoder(part, ptr::null()),
                CURLcode::CURLE_OK as c_int
            );
            let bad = cstr("rot13");
            assert_eq!(
                curl_mime_encoder(part, bad),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int
            );
            drop(CString::from_raw(bad));
        }
        // Null part is rejected.
        // SAFETY: null is an explicitly handled input.
        unsafe {
            assert_eq!(
                curl_mime_name(ptr::null_mut(), ptr::null()),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int
            );
        }
        // Inspect the buffered part state directly.
        // SAFETY: `part` is a live PartHandle owned by `mime`.
        let ph = unsafe { &*(part as *const PartHandle) };
        assert_eq!(ph.name.as_deref(), Some("field"));
        assert_eq!(ph.filename.as_deref(), Some("file.txt"));
        assert_eq!(ph.mimetype.as_deref(), Some("text/plain"));
        // `encoder` was reset by the NULL call; the invalid one did not change it.
        assert_eq!(ph.encoder, None);
        // SAFETY: `mime` live.
        unsafe { curl_mime_free(mime) };
    }

    #[test]
    fn mime_data_is_binary_safe_and_handles_zero_terminated() {
        let mime = curl_mime_init(dummy_easy());
        // SAFETY: `mime` live.
        let part = unsafe { curl_mime_addpart(mime) };

        let data = b"ab\0cd"; // embedded NUL
                              // SAFETY: `part` live; `data` points to 5 readable bytes.
        unsafe {
            assert_eq!(
                curl_mime_data(part, data.as_ptr() as *const c_char, data.len()),
                CURLcode::CURLE_OK as c_int
            );
        }
        {
            // SAFETY: `part` is a live PartHandle.
            let ph = unsafe { &*(part as *const PartHandle) };
            match &ph.source {
                PartSource::Data(d) => assert_eq!(d.as_slice(), b"ab\0cd"),
                _ => panic!("expected Data source"),
            }
        }

        // CURL_ZERO_TERMINATED => strlen.
        // SAFETY: `part` live; the buffer is a valid C string.
        unsafe {
            let zt = cstr("xyz");
            assert_eq!(
                curl_mime_data(part, zt, CURL_ZERO_TERMINATED),
                CURLcode::CURLE_OK as c_int
            );
            drop(CString::from_raw(zt));
        }
        {
            // SAFETY: `part` live.
            let ph = unsafe { &*(part as *const PartHandle) };
            match &ph.source {
                PartSource::Data(d) => assert_eq!(d.as_slice(), b"xyz"),
                _ => panic!("expected Data source"),
            }
        }

        // NULL data clears the body.
        // SAFETY: `part` live; null data is explicitly handled.
        unsafe {
            assert_eq!(
                curl_mime_data(part, ptr::null(), 0),
                CURLcode::CURLE_OK as c_int
            );
        }
        {
            // SAFETY: `part` live.
            let ph = unsafe { &*(part as *const PartHandle) };
            assert!(matches!(ph.source, PartSource::None));
        }
        // SAFETY: `mime` live.
        unsafe { curl_mime_free(mime) };
    }

    #[test]
    fn mime_filedata_sets_basename_and_reports_read_error() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "blitzy_adhoc_share_mime_{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, b"file body contents").unwrap();
        let path_c = cstr(path.to_str().unwrap());

        let mime = curl_mime_init(dummy_easy());
        // SAFETY: `mime` live.
        let part = unsafe { curl_mime_addpart(mime) };
        // SAFETY: `part` live; `path_c` a valid C string.
        unsafe {
            assert_eq!(
                curl_mime_filedata(part, path_c),
                CURLcode::CURLE_OK as c_int
            );
        }
        {
            // SAFETY: `part` live.
            let ph = unsafe { &*(part as *const PartHandle) };
            assert!(matches!(ph.source, PartSource::File(_)));
            // The base name is set as the default Content-Disposition filename.
            assert_eq!(
                ph.filename.as_deref(),
                path.file_name().and_then(|s| s.to_str())
            );
        }
        // A missing file reports CURLE_READ_ERROR.
        // SAFETY: `part` live; the path is a valid C string naming a nonexistent file.
        unsafe {
            let missing = cstr("/nonexistent/blitzy/does/not/exist.dat");
            assert_eq!(
                curl_mime_filedata(part, missing),
                CURLcode::CURLE_READ_ERROR as c_int
            );
            drop(CString::from_raw(missing));
        }
        // SAFETY: `mime` live.
        unsafe { curl_mime_free(mime) };
        drop(unsafe { CString::from_raw(path_c) });
        let _ = std::fs::remove_file(&path);
    }

    // Callback body context for the data_cb tests.
    #[repr(C)]
    struct ReadCtx {
        buf: Vec<u8>,
        pos: usize,
        free_calls: u32,
    }

    unsafe extern "C" fn ctx_read(
        dst: *mut c_char,
        size: size_t,
        nitems: size_t,
        arg: *mut c_void,
    ) -> size_t {
        // SAFETY: the test registers a valid `*mut ReadCtx` as the callback token.
        let ctx = unsafe { &mut *(arg as *mut ReadCtx) };
        let want = size.saturating_mul(nitems);
        let remaining = ctx.buf.len() - ctx.pos;
        let n = want.min(remaining);
        if n > 0 {
            // SAFETY: `dst` has room for `want >= n` bytes per the read-callback contract; the
            // source slice `ctx.buf[pos..pos+n]` is in bounds.
            unsafe {
                ptr::copy_nonoverlapping(ctx.buf.as_ptr().add(ctx.pos), dst as *mut u8, n);
            }
            ctx.pos += n;
        }
        n
    }

    unsafe extern "C" fn ctx_free(arg: *mut c_void) {
        // SAFETY: valid `*mut ReadCtx`; we only bump a counter (no deallocation).
        let ctx = unsafe { &mut *(arg as *mut ReadCtx) };
        ctx.free_calls += 1;
    }

    #[test]
    fn mime_data_cb_streams_and_frees_exactly_once() {
        let body = b"streaming callback body".to_vec();
        let ctx = Box::into_raw(Box::new(ReadCtx {
            buf: body.clone(),
            pos: 0,
            free_calls: 0,
        }));

        let mime = curl_mime_init(dummy_easy());
        // SAFETY: `mime` live.
        let part = unsafe { curl_mime_addpart(mime) };
        // SAFETY: `part` live; callbacks + token are valid.
        unsafe {
            assert_eq!(
                curl_mime_data_cb(
                    part,
                    body.len() as curl_off_t,
                    Some(ctx_read),
                    None,
                    Some(ctx_free),
                    ctx as *mut c_void,
                ),
                CURLcode::CURLE_OK as c_int
            );
        }

        // Assemble the core mime and read the whole part through the forwarding reader.
        // SAFETY: `mime` is a live MimeHandle.
        let mh = unsafe { &*(mime as *const MimeHandle) };
        let core = mh.to_core_mime().expect("to_core_mime");
        let mut reader = core.into_reader(MimeStrategy::Mail).expect("into_reader");
        let mut out = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = reader.fill(&mut buf).expect("fill");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert!(
            out.windows(body.len()).any(|w| w == body.as_slice()),
            "rendered body must contain the streamed bytes"
        );

        // Freeing the mime must invoke the free callback exactly once.
        // SAFETY: `mime` live.
        unsafe { curl_mime_free(mime) };
        // SAFETY: `ctx` is our live box; the free callback only bumped a counter, so it is intact.
        let ctx = unsafe { Box::from_raw(ctx) };
        assert_eq!(ctx.free_calls, 1, "free callback must fire exactly once");
    }

    #[test]
    fn mime_data_cb_replacing_source_frees_previous_arg() {
        let ctx = Box::into_raw(Box::new(ReadCtx {
            buf: Vec::new(),
            pos: 0,
            free_calls: 0,
        }));
        let mime = curl_mime_init(dummy_easy());
        // SAFETY: `mime` live.
        let part = unsafe { curl_mime_addpart(mime) };
        // SAFETY: `part` live; callback + token valid.
        unsafe {
            curl_mime_data_cb(part, 0, None, None, Some(ctx_free), ctx as *mut c_void);
            // Replacing with a data body must drop (free) the previous callback source.
            let d = cstr("plain");
            curl_mime_data(part, d, CURL_ZERO_TERMINATED);
            drop(CString::from_raw(d));
        }
        // SAFETY: `ctx` still our box (free callback only counts).
        {
            let seen = unsafe { &*ctx }.free_calls;
            assert_eq!(seen, 1, "old callback arg freed when source replaced");
        }
        // SAFETY: `mime` live.
        unsafe { curl_mime_free(mime) };
        drop(unsafe { Box::from_raw(ctx) });
    }

    #[test]
    fn mime_subparts_transfers_ownership_and_null_clears() {
        let parent = curl_mime_init(dummy_easy());
        // SAFETY: `parent` live.
        let part = unsafe { curl_mime_addpart(parent) };

        let child = curl_mime_init(dummy_easy());
        // SAFETY: `child` live.
        let child_part = unsafe { curl_mime_addpart(child) };
        // SAFETY: `child_part` live; args valid.
        unsafe {
            let d = cstr("child-body");
            curl_mime_data(child_part, d, CURL_ZERO_TERMINATED);
            drop(CString::from_raw(d));
            assert_eq!(curl_mime_subparts(part, child), CURLcode::CURLE_OK as c_int);
        }
        {
            // SAFETY: `part` live; ownership of `child` moved into it.
            let ph = unsafe { &*(part as *const PartHandle) };
            assert!(matches!(ph.source, PartSource::Subparts(_)));
        }
        // NULL subparts clears the body.
        // SAFETY: `parent` live; add a second part and clear it.
        let part2 = unsafe { curl_mime_addpart(parent) };
        // SAFETY: `part2` live.
        unsafe {
            assert_eq!(
                curl_mime_subparts(part2, ptr::null_mut()),
                CURLcode::CURLE_OK as c_int
            );
        }
        // Freeing the parent frees the transferred child too — no double free (child not freed
        // separately).
        // SAFETY: `parent` live; `child` is owned by it now and must NOT be freed separately.
        unsafe { curl_mime_free(parent) };
    }

    #[test]
    fn mime_headers_duplicate_and_optionally_take_ownership() {
        let mime = curl_mime_init(dummy_easy());
        // SAFETY: `mime` live.
        let part = unsafe { curl_mime_addpart(mime) };

        // take_ownership = 0: we keep and free our own list.
        let mut list =
            crate::slist::curl_slist_append(ptr::null_mut(), b"X-A: 1\0".as_ptr() as *const c_char);
        list = crate::slist::curl_slist_append(list, b"X-B: 2\0".as_ptr() as *const c_char);
        // SAFETY: `part` live; `list` a valid 2-element slist.
        unsafe {
            assert_eq!(
                curl_mime_headers(part, list, 0),
                CURLcode::CURLE_OK as c_int
            );
        }
        {
            // SAFETY: `part` live.
            let ph = unsafe { &*(part as *const PartHandle) };
            assert_eq!(ph.headers, vec!["X-A: 1".to_string(), "X-B: 2".to_string()]);
        }
        // We still own `list`; free it ourselves.
        crate::slist::curl_slist_free_all(list);

        // take_ownership = 1: the call frees the list for us.
        let owned =
            crate::slist::curl_slist_append(ptr::null_mut(), b"X-C: 3\0".as_ptr() as *const c_char);
        // SAFETY: `part` live; `owned` transferred to the call.
        unsafe {
            assert_eq!(
                curl_mime_headers(part, owned, 1),
                CURLcode::CURLE_OK as c_int
            );
        }
        {
            // SAFETY: `part` live.
            let ph = unsafe { &*(part as *const PartHandle) };
            assert_eq!(ph.headers, vec!["X-C: 3".to_string()]);
        }
        // SAFETY: `mime` live.
        unsafe { curl_mime_free(mime) };
    }

    #[test]
    fn mime_to_core_roundtrip_has_content() {
        let mime = curl_mime_init(dummy_easy());
        // SAFETY: `mime` live.
        let part = unsafe { curl_mime_addpart(mime) };
        // SAFETY: `part` live; args valid C strings / bytes.
        unsafe {
            let name = cstr("greeting");
            curl_mime_name(part, name);
            drop(CString::from_raw(name));
            let data = b"hello world";
            curl_mime_data(part, data.as_ptr() as *const c_char, data.len());
        }
        // SAFETY: `mime` live.
        let mh = unsafe { &*(mime as *const MimeHandle) };
        let core = mh.to_core_mime().expect("to_core_mime");
        assert!(core.content_length(MimeStrategy::Form) > 0);
        // SAFETY: `mime` live.
        unsafe { curl_mime_free(mime) };
    }

    // ----- Phase 4: deprecated form API --------------------------------------------------------

    #[test]
    fn formadd_reports_disabled_and_appends_nothing() {
        // The deprecated variadic builder cannot walk its `CURLFORM_*` option list on stable MSRV
        // 1.75 (no `c_variadic`) and a C trampoline is barred by AAP §0.5.2, so this build matches
        // curl's own `CURL_DISABLE_FORM_API` stub: `curl_formadd` returns `CURL_FORMADD_DISABLED`
        // for every input — including NULL — and never appends a node (`lib/formdata.c`). This is
        // the honest ABI signal that replaced the former false `CURL_FORMADD_OK` no-op.
        // SAFETY: the disabled stub never dereferences its pointer arguments.
        unsafe {
            assert_eq!(
                curl_formadd(ptr::null_mut(), ptr::null_mut()),
                CURLFORMcode::CURL_FORMADD_DISABLED as c_int
            );
        }
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();
        // SAFETY: valid double-pointers; the disabled builder ignores them and appends nothing.
        unsafe {
            assert_eq!(
                curl_formadd(&mut post, &mut last),
                CURLFORMcode::CURL_FORMADD_DISABLED as c_int
            );
        }
        assert!(post.is_null(), "disabled builder appends nothing");
        assert!(last.is_null(), "disabled builder appends nothing");
    }

    #[test]
    fn formfree_null_is_safe() {
        // SAFETY: null is an explicitly handled input.
        unsafe { curl_formfree(ptr::null_mut()) };
    }

    unsafe extern "C" fn collect_form(arg: *mut c_void, buf: *const c_char, len: size_t) -> size_t {
        // SAFETY: the test registers a valid `*mut Vec<u8>` sink as the token.
        let sink = unsafe { &mut *(arg as *mut Vec<u8>) };
        // SAFETY: `buf` points to `len` readable bytes per the curl_formget_callback contract.
        let slice = unsafe { std::slice::from_raw_parts(buf as *const u8, len) };
        sink.extend_from_slice(slice);
        len
    }

    #[test]
    fn formget_serializes_a_manual_httppost_chain() {
        // Build one field node under the crate's allocation model (Box node, CString fields).
        let node = Box::into_raw(Box::new(curl_httppost {
            next: ptr::null_mut(),
            name: cstr("greeting"),
            namelength: 0,
            contents: cstr("hello"),
            contentslength: 0,
            buffer: ptr::null_mut(),
            bufferlength: 0,
            contenttype: ptr::null_mut(),
            contentheader: ptr::null_mut(),
            more: ptr::null_mut(),
            flags: 0,
            showfilename: ptr::null_mut(),
            userp: ptr::null_mut(),
            contentlen: 0,
        }));

        let mut out: Vec<u8> = Vec::new();
        let out_ptr = &mut out as *mut Vec<u8> as *mut c_void;
        // SAFETY: `node` is a well-formed chain; `collect_form` + `out_ptr` are valid.
        let rc = unsafe { curl_formget(node, out_ptr, Some(collect_form)) };
        assert_eq!(rc, 0);
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("greeting"), "serialized form names the field");
        assert!(text.contains("hello"), "serialized form carries the value");

        // Reject a null append callback.
        // SAFETY: `node` live; explicit null-callback path.
        let rc2 = unsafe { curl_formget(node, out_ptr, None) };
        assert_eq!(rc2, -1);

        // Free symmetrically (frees the CString fields + the node box).
        // SAFETY: `node` was built under the crate's allocation model and not yet freed.
        unsafe { curl_formfree(node) };
    }
}
