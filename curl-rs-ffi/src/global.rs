//! Process-global init / version / escape / free — the 16 "miscellaneous"
//! exported `curl_*` symbols of the drop-in `libcurl` C ABI.
//!
//! This module is the FFI realization of curl's process-global and stateless
//! utility entry points, sourced from the C behavioral/ABI oracle
//! `include/curl/curl.h` and the implementation oracles `lib/version.c`,
//! `lib/escape.c`, `lib/getenv.c`, `lib/parsedate.c`, and `lib/strequal.c`
//! (Agent Action Plan §0.5.1). It exports **exactly 16** symbols, each of which
//! is listed in `lib/libcurl.def`:
//!
//! | Family   | Symbols |
//! |----------|---------|
//! | global   | `curl_global_init`, `curl_global_init_mem`, `curl_global_cleanup`, `curl_global_trace`, `curl_global_sslset` |
//! | version  | `curl_version`, `curl_version_info` |
//! | escape   | `curl_easy_escape`, `curl_easy_unescape`, `curl_escape`, `curl_unescape` |
//! | misc     | `curl_getdate`, `curl_getenv`, `curl_strequal`, `curl_strnequal`, `curl_free` |
//!
//! # The crate-wide C-heap string contract (this module owns `curl_free`)
//!
//! Every C-visible heap buffer that any module of this crate returns to a C
//! caller and expects the caller to release with [`curl_free`] —
//! [`curl_easy_escape`] / [`curl_easy_unescape`] output, [`curl_getenv`]
//! results, `curl_url_get` strings, `curl_maprintf` / `curl_mvaprintf` output,
//! `getinfo` string copies, and so on — **must** be allocated with a single,
//! content-independent scheme that [`curl_free`] can reclaim given only a
//! `void*`.
//!
//! That scheme is **`libc::malloc` + `libc::free`** (AAP §0.7.1, which phrases
//! the intent as "`CString::into_raw` values reclaimed by `curl_free`"; the
//! `libc` allocator pair is the robust realization). It is chosen because it is:
//!
//! * **content-independent** — it works for [`curl_easy_unescape`] output that
//!   may contain embedded NUL bytes, which a `CString` cannot represent;
//! * **faithful to curl** — historical C `libcurl` allocates these buffers with
//!   its `malloc` and frees them in `curl_free`, so a C test program in
//!   `tests/libtest` that (incorrectly but historically) calls the raw `free()`
//!   still hits the same allocator;
//! * **uniform** — allocation and deallocation are paired across the *entire*
//!   crate, so a buffer produced by any module is freed identically here.
//!
//! Sibling FFI modules (`easy.rs`, `url.rs`, `mprintf.rs`, `mime.rs`, …) MUST
//! allocate `curl_free`-reclaimable buffers through the [`c_strdup_bytes`],
//! [`c_strdup_str`], and [`c_alloc_bytes`] helpers exported here (or an
//! allocation that is byte-for-byte equivalent: `libc::malloc(len + 1)`).
//!
//! > Note: the `curl_slist` API (`slist.rs`) is a **separate** ownership domain.
//! > Its nodes/strings are owned by Rust (`Box`/`CString`) and released by
//! > `curl_slist_free_all`, never by `curl_free`; the two contracts do not mix,
//! > exactly as in C (`curl_slist_free_all` vs `curl_free`).
//!
//! # Memory safety
//!
//! `curl-rs-ffi` is the only crate permitted `unsafe`. Every `unsafe` operation
//! here sits in an explicit `unsafe { … }` block carrying a `// SAFETY:` comment
//! (the crate denies `unsafe_op_in_unsafe_fn`), and every exported
//! `unsafe extern "C"` entry point documents its preconditions under a
//! `# Safety` section. Entry points that take no raw pointers
//! (`curl_global_init`, `curl_global_cleanup`, `curl_version`,
//! `curl_version_info`, …) are ordinary safe `extern "C"` functions.

// The C symbol/type names use C `snake_case` / `SCREAMING_CASE` spelling
// (`curl_version_info_data`, `CURLcode`, `curl_sslbackend`, …) rather than
// Rust's `UpperCamelCase`. The crate root also sets this allow; declaring it
// here keeps the module warning-free when compiled or linted in isolation
// (mirrors `types.rs` / `error_codes.rs`).
#![allow(non_camel_case_types)]

// The async core. The Agent Action Plan prescribes the `core` alias
// (`use curl_rs_lib as core;`). Because that alias shadows the standard `core`
// crate inside this module, every standard C primitive type and helper is taken
// from `std::ffi` / `std` / `libc` below (never `core::ffi`).
use curl_rs_lib as core;

use std::env;
use std::ffi::{c_char, c_int, c_long, c_uint, c_void, CStr, CString};
use std::ptr;
use std::slice;
use std::sync::OnceLock;

use libc::{size_t, time_t};

use crate::error_codes::{int_to_sslset, result_to_code, CURLcode, CURLsslset};
use crate::types::{
    curl_calloc_callback, curl_free_callback, curl_malloc_callback, curl_realloc_callback,
    curl_ssl_backend, curl_sslbackend, curl_strdup_callback, curl_version_info_data, CURLversion,
    CURL,
};

// =============================================================================
// Phase 0 — the crate-wide C-heap string contract (libc::malloc / libc::free)
// =============================================================================

/// Copies `bytes` into a freshly `libc::malloc`'d, NUL-terminated C buffer and
/// returns the owning pointer, or NULL on allocation failure.
///
/// The buffer is exactly `bytes.len() + 1` bytes: the `bytes` are copied
/// verbatim and a trailing NUL terminator is written, so the result is a valid
/// C string for inputs without interior NULs and a NUL-terminated byte blob for
/// inputs that contain them. Ownership transfers to the caller, who must release
/// it with [`curl_free`] (which calls `libc::free`).
///
/// This is the single primitive behind the crate-wide C-heap contract; the
/// `curl_free`-reclaimable buffers produced anywhere in the crate route through
/// here (directly or via [`c_strdup_str`] / [`c_alloc_bytes`]).
///
/// # Safety
///
/// The returned pointer, if non-NULL, is owned by the caller and must be freed
/// exactly once with [`curl_free`] (or an equivalent `libc::free`). Reading the
/// buffer beyond `bytes.len()` (past the terminator) is undefined behavior.
#[must_use]
pub(crate) unsafe fn c_strdup_bytes(bytes: &[u8]) -> *mut c_char {
    // `len + 1` cannot overflow `usize` for any slice that actually exists in
    // memory (its length is already a valid `usize` strictly below `usize::MAX`,
    // since at least one address is unused), so the `+ 1` is always sound.
    let total = bytes.len() + 1;

    // SAFETY: `total` is a non-zero byte count (`>= 1`). `libc::malloc` either
    // returns a pointer to at least `total` writable bytes or NULL; we handle
    // the NULL case immediately below before any write.
    let raw = unsafe { libc::malloc(total) } as *mut u8;
    if raw.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `raw` points to `total == bytes.len() + 1` freshly allocated,
    // writable bytes. The source `bytes` is a valid slice of `bytes.len()` bytes
    // and cannot overlap the just-allocated destination, so the non-overlapping
    // copy is in bounds; the final write stores the NUL terminator at the last
    // (`bytes.len()`) byte, which is within the allocation.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), raw, bytes.len());
        *raw.add(bytes.len()) = 0;
    }

    raw as *mut c_char
}

/// Copies a UTF-8 string into a `libc::malloc`'d, NUL-terminated C string.
///
/// A thin wrapper over [`c_strdup_bytes`] for the common case of an ASCII /
/// UTF-8 string with no interior NULs (e.g. percent-encoded URL output). Returns
/// NULL on allocation failure. The caller must release the result with
/// [`curl_free`].
///
/// # Safety
///
/// Same contract as [`c_strdup_bytes`]: the returned pointer (if non-NULL) is
/// owned by the caller and must be freed once with [`curl_free`].
#[must_use]
pub(crate) unsafe fn c_strdup_str(s: &str) -> *mut c_char {
    // SAFETY: delegates to `c_strdup_bytes`, whose contract is upheld by the
    // caller (the returned pointer is freed with `curl_free`).
    unsafe { c_strdup_bytes(s.as_bytes()) }
}

/// Copies a binary byte slice into a `libc::malloc`'d buffer with a trailing NUL
/// terminator, preserving any embedded NUL bytes.
///
/// This is the allocator for [`curl_easy_unescape`], whose decoded output may
/// legitimately contain interior NUL bytes; the caller learns the true byte
/// count from the `outlength` out-parameter and reclaims the buffer with
/// [`curl_free`]. The implementation is identical to [`c_strdup_bytes`]; the
/// distinct name documents the *binary* (not C-string) intent at call sites.
///
/// # Safety
///
/// Same contract as [`c_strdup_bytes`]: the returned pointer (if non-NULL) is
/// owned by the caller and must be freed once with [`curl_free`].
#[must_use]
pub(crate) unsafe fn c_alloc_bytes(data: &[u8]) -> *mut c_char {
    // SAFETY: delegates to `c_strdup_bytes`, whose contract is upheld by the
    // caller (the returned pointer is freed with `curl_free`).
    unsafe { c_strdup_bytes(data) }
}

// =============================================================================
// Phase 1 — curl_free
// =============================================================================

/// `curl_free` — free a buffer that `libcurl` previously returned (curl.h).
///
/// Releases a heap buffer handed out by any of this library's allocating entry
/// points ([`curl_easy_escape`], [`curl_easy_unescape`], [`curl_getenv`],
/// `curl_url_get`, `curl_maprintf`, …). A NULL pointer is a no-op, matching
/// curl's `curl_free` (whose `curlx_free` is NULL-tolerant). The pointer is
/// released with `libc::free`, the exact counterpart of the crate-wide
/// `libc::malloc` allocation scheme (see the module-level contract).
///
/// # Safety
///
/// `p` must be either NULL or a pointer previously returned by a `libcurl`
/// allocating function of this crate (i.e. allocated via the crate's
/// `libc::malloc`-based helpers) and not yet freed. Passing any other pointer —
/// a stack address, a foreign-allocator pointer, or a pointer already freed — is
/// undefined behavior; this mirrors curl's documented `curl_free` contract.
#[no_mangle]
pub unsafe extern "C" fn curl_free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    // SAFETY: per the `# Safety` contract `p` is non-NULL here and was allocated
    // by this crate via `libc::malloc` (the `c_strdup_*` / `c_alloc_bytes`
    // helpers), so freeing it with the matching `libc::free` is sound and frees
    // the allocation exactly once.
    unsafe { libc::free(p) };
}

// =============================================================================
// CURL_GLOBAL_* flag bits (include/curl/curl.h:L3014-L3019)
//
// The `flags` bitmask accepted by `curl_global_init` / `curl_global_init_mem`.
// Typed `c_long` to match the C `long flags` parameter exactly. They are
// accepted for ABI compatibility; the rustls-based core has no per-flag
// subsystem to toggle (`CURL_GLOBAL_SSL` has had "no purpose since 7.57.0" and
// `CURL_GLOBAL_WIN32` is a Windows Winsock concern handled by the Rust std
// library), so every bit is accepted and the value is recorded by the core.
// =============================================================================

/// `CURL_GLOBAL_SSL` — initialize the SSL layer (no purpose since curl 7.57.0).
pub const CURL_GLOBAL_SSL: c_long = 1 << 0;
/// `CURL_GLOBAL_WIN32` — initialize the Win32 socket layer.
pub const CURL_GLOBAL_WIN32: c_long = 1 << 1;
/// `CURL_GLOBAL_ALL` — initialize everything possible (`SSL | WIN32`).
pub const CURL_GLOBAL_ALL: c_long = CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32;
/// `CURL_GLOBAL_NOTHING` — initialize nothing extra.
pub const CURL_GLOBAL_NOTHING: c_long = 0;
/// `CURL_GLOBAL_DEFAULT` — the recommended default (`CURL_GLOBAL_ALL`).
pub const CURL_GLOBAL_DEFAULT: c_long = CURL_GLOBAL_ALL;
/// `CURL_GLOBAL_ACK_EINTR` — historically acknowledged `EINTR` during waits.
pub const CURL_GLOBAL_ACK_EINTR: c_long = 1 << 2;

// =============================================================================
// Phase 2 — global init / cleanup / trace
// =============================================================================

/// `curl_global_init` — set up the program-wide state `libcurl` needs (curl.h).
///
/// Forwards to the core's idempotent, reference-counted global initializer,
/// which installs the rustls crypto provider and sets up logging exactly once
/// per balanced init/cleanup pairing. The `flags` bitmask
/// (`CURL_GLOBAL_*`) is accepted and recorded for ABI compatibility; the
/// rustls-based core has no per-flag subsystem that requires separate toggling.
///
/// Returns `CURLE_OK` on success or a mapped [`CURLcode`] on failure, matching
/// curl's contract that a non-zero return means initialization failed and the
/// library must not be used.
#[no_mangle]
pub extern "C" fn curl_global_init(flags: c_long) -> CURLcode {
    // `c_long` is the same primitive as the core's `i64` flag parameter on every
    // supported (LP64) target, so it is forwarded directly.
    result_to_code(core::global_init(flags))
}

/// `curl_global_init_mem` — like [`curl_global_init`] but with caller-supplied
/// memory-allocation callbacks (curl.h).
///
/// In C, this installs custom `malloc`/`free`/`realloc`/`strdup`/`calloc`
/// functions so that all of `libcurl`'s allocations route through the caller's
/// allocator. The Rust rewrite manages its own allocator (the safe core relies
/// on Rust ownership and `Drop`, and `memdebug.c` is retired per AAP §0.3.2), so
/// the custom allocators **cannot** be wired into Rust's global allocator on
/// stable Rust. The callbacks are therefore *accepted but unused*: this function
/// behaves exactly like `curl_global_init(flags)`, preserving the ABI and return
/// code. Passing non-NULL callbacks is safe and never crashes.
///
/// # Safety
///
/// The callback function pointers, if non-NULL, must be valid C function
/// pointers with the documented `curl_*_callback` signatures. They are not
/// invoked by this build, so even a dangling pointer cannot be dereferenced
/// here; the `unsafe` marker exists only to match the C-ABI surface that
/// historically accepts raw function pointers.
#[no_mangle]
pub unsafe extern "C" fn curl_global_init_mem(
    flags: c_long,
    _m: curl_malloc_callback,
    _f: curl_free_callback,
    _r: curl_realloc_callback,
    _s: curl_strdup_callback,
    _c: curl_calloc_callback,
) -> CURLcode {
    // The custom allocators are intentionally ignored — memory safety is
    // provided natively by Rust (AAP §0.3.2). Behave like the plain initializer.
    // (`c_long` is the same primitive as the core's `i64` on supported targets.)
    result_to_code(core::global_init(flags))
}

/// `curl_global_cleanup` — release the program-wide state set up by
/// [`curl_global_init`] (curl.h).
///
/// Forwards to the core's idempotent, reference-counted global cleanup. It is
/// safe to call multiple times and safe to call without a matching init (an
/// unbalanced extra call is a no-op), matching curl's tolerant behavior.
#[no_mangle]
pub extern "C" fn curl_global_cleanup() {
    core::global_cleanup();
}

/// `curl_global_trace` — configure global trace/debug feature filters (curl.h).
///
/// Accepts a comma-separated list of trace feature names (the same grammar as
/// the `CURL_DEBUG` environment variable, e.g. `"all"`, `"http/2,ssl"`). curl
/// parses this leniently — unknown names are ignored rather than rejected — and
/// always reports success for a syntactically acceptable string. The core does
/// not expose a runtime trace-filter configuration, so the configuration is
/// parsed for validity (a NULL pointer is tolerated as "no configuration") and
/// `CURLE_OK` is returned, mirroring curl's lenient contract.
///
/// # Safety
///
/// `config` must be either NULL or a valid pointer to a NUL-terminated C string
/// that remains valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_global_trace(config: *const c_char) -> CURLcode {
    if config.is_null() {
        // A NULL configuration is accepted as "no trace features", like curl.
        return CURLcode::CURLE_OK;
    }
    // SAFETY: `config` is non-NULL per the check above; the caller guarantees it
    // points to a valid NUL-terminated C string for the duration of the call.
    let cstr = unsafe { CStr::from_ptr(config) };
    // Lenient parse: walk the comma-separated tokens purely to honor curl's
    // grammar. Tokens are not required to be known; unknown features are
    // ignored, exactly as curl's `curl_global_trace` accepts them. Invalid
    // UTF-8 is treated as an empty/again-accepted configuration.
    if let Ok(s) = cstr.to_str() {
        for token in s.split(',') {
            let _feature = token.trim();
            // No runtime trace registry to populate; acceptance is the contract.
        }
    }
    CURLcode::CURLE_OK
}

// =============================================================================
// Phase 3 — curl_global_sslset
// =============================================================================

/// Returns a process-lifetime, NULL-terminated array describing the one TLS
/// backend this library is built with (rustls).
///
/// The array — `[ &rustls_backend, NULL ]` — and the [`curl_ssl_backend`] it
/// points at are allocated once and intentionally leaked so the pointer handed
/// back to C callers via `curl_global_sslset`'s `avail` out-parameter stays
/// valid for the entire process lifetime (curl's own `available_backends` array
/// is likewise a static with program lifetime). The pointer value is cached as a
/// `usize` because raw pointers are not `Sync` and so cannot live in a `static`
/// / `OnceLock<*const _>` directly.
fn ssl_backends() -> *const *const curl_ssl_backend {
    static CELL: OnceLock<usize> = OnceLock::new();
    let addr = *CELL.get_or_init(|| {
        // The backend name is a `'static` byte literal, valid for the whole
        // program; `as_ptr()` yields a stable `*const c_char`.
        let name = b"rustls\0".as_ptr() as *const c_char;
        // Leak the descriptor so its address is stable forever.
        let backend: *const curl_ssl_backend = Box::leak(Box::new(curl_ssl_backend {
            id: curl_sslbackend::CURLSSLBACKEND_RUSTLS,
            name,
        }));
        // Leak the NULL-terminated pointer array; element 0 is the backend,
        // element 1 is the sentinel NULL.
        let array: *const [*const curl_ssl_backend; 2] =
            Box::leak(Box::new([backend, ptr::null()]));
        array as *const *const curl_ssl_backend as usize
    });
    addr as *const *const curl_ssl_backend
}

/// `curl_global_sslset` — select the TLS backend by id or name and/or query the
/// set of available backends (curl.h).
///
/// This build links exactly one TLS backend, **rustls**
/// (`CURLSSLBACKEND_RUSTLS = 14`). When `avail` is non-NULL it is always set to
/// the process-lifetime list returned by [`ssl_backends`] (mirroring curl, which
/// fills `*avail` unconditionally). Backend selection is delegated to the core's
/// [`core::global_sslset`], which mirrors `lib/vtls/vtls.c`'s `Curl_init_sslset`
/// for a single-backend, non-multi-SSL build:
///
/// * `id == CURLSSLBACKEND_RUSTLS`, or `name` case-insensitively equal to
///   `"rustls"` → [`CURLsslset::CURLSSLSET_OK`];
/// * any other id or name (including `id == NONE` with no name) →
///   [`CURLsslset::CURLSSLSET_UNKNOWN_BACKEND`].
///
/// The `SslSetResult` and `CURLsslset` discriminants are identical, so the core
/// result maps to the C enum by integer value via [`int_to_sslset`].
///
/// # Safety
///
/// `name`, if non-NULL, must point to a valid NUL-terminated C string. `avail`,
/// if non-NULL, must point to a writable `*const *const curl_ssl_backend` slot.
/// Both are read/written only while valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_global_sslset(
    id: curl_sslbackend,
    name: *const c_char,
    avail: *mut *const *const curl_ssl_backend,
) -> CURLsslset {
    // curl always publishes the available-backends list when the caller asks for
    // it, independent of whether selection succeeds.
    if !avail.is_null() {
        // SAFETY: `avail` is non-NULL per the check; the caller guarantees it
        // points to a writable slot of type `*const *const curl_ssl_backend`.
        // The stored pointer has process lifetime (see `ssl_backends`).
        unsafe { *avail = ssl_backends() };
    }

    // Decode the optional backend name. Backend names are ASCII; invalid UTF-8
    // cannot match "rustls", so mapping it to `None` yields the correct
    // UNKNOWN_BACKEND outcome (and is irrelevant when `id` already matches).
    let name_opt: Option<&str> = if name.is_null() {
        None
    } else {
        // SAFETY: `name` is non-NULL per the check; the caller guarantees a
        // valid NUL-terminated C string valid for the duration of the call.
        unsafe { CStr::from_ptr(name) }.to_str().ok()
    };

    // `id` is a `#[repr(C)]` field-less enum, so `as i32` yields its exact
    // discriminant for the core's integer-typed selector.
    let result = core::global_sslset(id as i32, name_opt);

    // `SslSetResult` and `CURLsslset` share discriminants 0..=3.
    int_to_sslset(result as i32)
}

// =============================================================================
// Phase 4 — curl_version and curl_version_info (feature detection)
//
// These power `runtests` feature gating (AAP §0.7.3): the reported feature set
// and protocol list MUST equal curl's default build, so the data is sourced
// verbatim from `curl-rs-lib`'s single source of truth (`core::version`).
// =============================================================================

/// Leaks a `&str` into a process-lifetime, NUL-terminated C string.
///
/// The returned pointer is valid for the entire program and must NOT be freed
/// (it backs the static [`curl_version_info_data`] and [`curl_version`] data,
/// neither of which the C caller frees). An interior NUL — impossible for the
/// curated version/host/scheme/feature strings — yields a NULL pointer rather
/// than a panic, which a C caller treats as "field not present".
fn leak_cstring(s: &str) -> *const c_char {
    match CString::new(s) {
        // `into_raw` transfers ownership out of Rust; never reclaiming it makes
        // the allocation live for the process lifetime (an intentional leak).
        Ok(cs) => cs.into_raw() as *const c_char,
        Err(_) => ptr::null(),
    }
}

/// Maps an optional `&str` to a leaked C string, or NULL when absent.
///
/// Used for every nullable field of [`curl_version_info_data`] (TLS/zlib/SSH
/// versions, CA paths, …): `Some` becomes a process-lifetime C string and `None`
/// becomes `ptr::null()`, mirroring curl, which leaves unavailable fields NULL.
fn leak_opt_cstring(o: Option<&str>) -> *const c_char {
    match o {
        Some(s) => leak_cstring(s),
        None => ptr::null(),
    }
}

/// Builds a process-lifetime, NULL-terminated `*const *const c_char` array from
/// a slice of strings (curl's `protocols` and `feature_names` arrays).
///
/// Each element is a leaked C string; a trailing NULL terminates the array, the
/// convention `curl_version_info` consumers rely on to iterate without a count.
/// The backing `Vec` is leaked so the array stays valid for the whole process.
fn leak_cstr_array(items: &[&str]) -> *const *const c_char {
    let mut ptrs: Vec<*const c_char> = Vec::with_capacity(items.len() + 1);
    for &item in items {
        ptrs.push(leak_cstring(item));
    }
    // NULL sentinel so C callers can iterate until they hit a NULL entry.
    ptrs.push(ptr::null());
    // `Vec::leak` yields a `&'static mut [_]`; its base pointer has process
    // lifetime and is exactly the `const char * const *` the C ABI expects.
    let leaked: &'static mut [*const c_char] = Vec::leak(ptrs);
    leaked.as_ptr()
}

/// `curl_version` — return the human-readable `libcurl` version banner (curl.h).
///
/// The returned `char *` points at a **static**, process-lifetime string that
/// the caller must NOT free (curl documents this; the non-`const` return type is
/// purely historical). The banner is sourced from `core::version()` — e.g.
/// `"curl-rs/8.19.0-DEV rustls/0.23.36 …"` — and its product-name prefix
/// (`core::version::NAME`, `"curl-rs"`) is rewritten to `"libcurl"` so the
/// banner reads `"libcurl/8.19.0-DEV …"`, matching the C `libcurl` identity the
/// test suite and ABI consumers expect. The `CString` is created once and cached
/// in a `OnceLock`; the returned pointer aliases that cached, never-freed buffer.
#[no_mangle]
pub extern "C" fn curl_version() -> *mut c_char {
    static BANNER: OnceLock<CString> = OnceLock::new();
    let banner = BANNER.get_or_init(|| {
        let raw = core::version::version();
        // Rewrite the leading product name ("curl-rs") to "libcurl" for ABI
        // parity; if the banner ever lacks that prefix, fall back verbatim.
        let text = match raw.strip_prefix(core::version::NAME) {
            Some(rest) => format!("libcurl{rest}"),
            None => raw.to_string(),
        };
        // The banner is curated ASCII with no interior NUL; the fallback keeps
        // `curl_version` infallible even in the impossible error case.
        CString::new(text).unwrap_or_else(|_| {
            // SAFETY: the byte literal is a valid C string with a single
            // trailing NUL and no interior NUL, so the unchecked constructor's
            // precondition holds. (MSRV 1.75 forbids `c"…"` literals.)
            unsafe { CStr::from_bytes_with_nul_unchecked(b"libcurl/8.19.0-DEV\0") }.to_owned()
        })
    });
    // The pointer aliases the cached, process-lifetime buffer; callers must not
    // free it. The `*mut` cast only satisfies the historical C signature.
    banner.as_ptr() as *mut c_char
}

/// `curl_version_info` — return the static capability/version descriptor of this
/// build (curl.h).
///
/// Returns a pointer to a single process-lifetime [`curl_version_info_data`]
/// populated once from `core::version_info()` — the single source of truth that
/// also backs `curl --version`, so the reported `features` bitmask,
/// `feature_names`, and `protocols` exactly match curl's default build (the
/// premise of `runtests` feature gating, AAP §0.7.3). The struct's `age` field
/// reports the highest layout this build supports (`CURLVERSION_TWELFTH`),
/// regardless of the caller-requested `_age` (curl ignores the stamp and returns
/// the full struct; older callers simply read the valid prefix). Every nullable
/// field with no Rust analog is NULL. All backing strings and the
/// NULL-terminated `protocols` / `feature_names` arrays are intentionally leaked
/// so the returned pointers remain valid for the entire process.
#[no_mangle]
pub extern "C" fn curl_version_info(_age: CURLversion) -> *mut curl_version_info_data {
    // Raw pointers are not `Sync`, so the built struct's address is cached as a
    // `usize` (re-cast to a pointer on return) instead of stored directly.
    static INFO: OnceLock<usize> = OnceLock::new();
    let addr = *INFO.get_or_init(|| {
        let info = core::version::version_info();
        let data = curl_version_info_data {
            // Highest supported layout age; the requested `_age` is ignored, as
            // in curl's `curl_version_info` (`(void)stamp`).
            age: CURLversion::CURLVERSION_TWELFTH,
            version: leak_cstring(info.version),
            version_num: info.version_num as c_uint,
            host: leak_cstring(info.host),
            features: info.features as c_int,
            ssl_version: leak_opt_cstring(info.ssl_version),
            ssl_version_num: info.ssl_version_num as c_long,
            libz_version: leak_opt_cstring(info.libz_version),
            protocols: leak_cstr_array(info.protocols),
            ares: leak_opt_cstring(info.ares),
            ares_num: info.ares_num as c_int,
            libidn: leak_opt_cstring(info.libidn),
            iconv_ver_num: info.iconv_ver_num as c_int,
            libssh_version: leak_opt_cstring(info.libssh_version),
            brotli_ver_num: info.brotli_ver_num as c_uint,
            brotli_version: leak_opt_cstring(info.brotli_version),
            nghttp2_ver_num: info.nghttp2_ver_num as c_uint,
            nghttp2_version: leak_opt_cstring(info.nghttp2_version),
            quic_version: leak_opt_cstring(info.quic_version),
            cainfo: leak_opt_cstring(info.cainfo),
            capath: leak_opt_cstring(info.capath),
            zstd_ver_num: info.zstd_ver_num as c_uint,
            zstd_version: leak_opt_cstring(info.zstd_version),
            hyper_version: leak_opt_cstring(info.hyper_version),
            gsasl_version: leak_opt_cstring(info.gsasl_version),
            feature_names: leak_cstr_array(info.feature_names),
            rtmp_version: leak_opt_cstring(info.rtmp_version),
        };
        // Leak the struct so its address is valid for the whole process.
        let leaked: &'static mut curl_version_info_data = Box::leak(Box::new(data));
        leaked as *mut curl_version_info_data as usize
    });
    addr as *mut curl_version_info_data
}

// =============================================================================
// Phase 5 — escape / unescape (4 symbols)
//
// Behavior mirrors `lib/escape.c` exactly. Encoding/decoding is delegated to
// `core::escape`; the buffers handed back to C are allocated through the
// crate-wide `c_strdup_str` / `c_alloc_bytes` helpers so they are reclaimable
// by `curl_free`.
// =============================================================================

/// `curl_easy_escape` — URL-percent-encode a buffer, returning a new heap C
/// string the caller frees with [`curl_free`] (curl.h, `lib/escape.c`).
///
/// Faithful to `curl_easy_escape`:
///
/// * a NULL `string` or a negative `length` returns NULL;
/// * `length == 0` means "measure with `strlen`"; a non-zero `length` reads
///   exactly that many *raw* bytes (which may include embedded NULs);
/// * an effective length of zero returns a freshly allocated **empty** C string
///   (not NULL), matching curl's `curlx_strdup("")`;
/// * an absurd length (`> usize::MAX / 16`) returns NULL, the guard curl applies
///   before allocating its `length * 3 + 1` buffer.
///
/// The `handle` argument is ignored, exactly as curl has ignored it since 7.82.0.
///
/// # Safety
///
/// `string` must be NULL or point to at least `length` readable bytes (or, when
/// `length == 0`, a valid NUL-terminated C string). `handle` is not dereferenced.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_escape(
    handle: *mut CURL,
    string: *const c_char,
    length: c_int,
) -> *mut c_char {
    // `handle` is ignored (curl: "data is ignored since 7.82.0").
    let _ = handle;

    if string.is_null() || length < 0 {
        return ptr::null_mut();
    }

    // A non-zero `length` is used verbatim; `length == 0` means `strlen`.
    let len: usize = if length != 0 {
        length as usize
    } else {
        // SAFETY: `string` is non-NULL (checked) and, with `length == 0`, the
        // caller guarantees a NUL-terminated C string, so `strlen` is in bounds.
        unsafe { libc::strlen(string) }
    };

    if len == 0 {
        // Empty input → an allocated empty C string, never NULL (curl parity).
        // SAFETY: returns a `curl_free`-able buffer (NULL only on allocation
        // failure), honoring the crate-wide C-heap contract.
        return unsafe { c_strdup_str("") };
    }

    // curl rejects lengths that would overflow its `length * 3 + 1` buffer.
    if len > usize::MAX / 16 {
        return ptr::null_mut();
    }

    // Read the input as RAW bytes — escaping operates on bytes and the input may
    // legitimately contain embedded NULs when an explicit `length` was given.
    // SAFETY: `string` points to at least `len` readable bytes — either an
    // explicit non-negative `length`, or the measured `strlen` above.
    let bytes = unsafe { slice::from_raw_parts(string as *const u8, len) };
    let encoded = core::escape::escape(bytes);

    // SAFETY: hands back a `curl_free`-able heap copy of the encoded ASCII
    // (NULL on allocation failure), per the crate-wide C-heap contract.
    unsafe { c_strdup_str(&encoded) }
}

/// `curl_escape` — deprecated alias for [`curl_easy_escape`] with no handle
/// (curl.h, `lib/escape.c`). Retained for ABI compatibility with old callers.
///
/// # Safety
///
/// Same contract as [`curl_easy_escape`]: `string` must be NULL or reference at
/// least `length` readable bytes (or a NUL-terminated string when `length == 0`).
#[no_mangle]
pub unsafe extern "C" fn curl_escape(string: *const c_char, length: c_int) -> *mut c_char {
    // SAFETY: forwards the caller's pointer/length contract unchanged to
    // `curl_easy_escape`, passing a NULL (ignored) handle, exactly as curl does.
    unsafe { curl_easy_escape(ptr::null_mut(), string, length) }
}

/// `curl_easy_unescape` — URL-percent-decode a buffer, returning a new heap
/// buffer the caller frees with [`curl_free`] (curl.h, `lib/escape.c`).
///
/// Faithful to `curl_easy_unescape`:
///
/// * a NULL `string` or a negative `length` returns NULL;
/// * `length == 0` means "measure with `strlen`"; otherwise exactly `length`
///   raw bytes are decoded;
/// * decoding uses curl's `REJECT_NADA` policy — every byte is accepted and a
///   malformed `%`-escape is preserved verbatim (`"%"`, `"%2"`, `"%zz"` decode
///   to themselves), so this never fails on content;
/// * the decoded output may contain embedded NUL bytes, so it is returned as a
///   NUL-terminated *binary* buffer ([`c_alloc_bytes`]) and the true byte count
///   is written to `outlength` when that pointer is non-NULL;
/// * matching curl, the `outlength` path also enforces the `INT_MAX` ceiling:
///   if the decoded length cannot be represented in an `int`, NULL is returned
///   and `*outlength` is left untouched (when `outlength` is NULL the ceiling is
///   not checked, exactly as in `lib/escape.c`).
///
/// The `handle` argument is ignored, exactly as curl has ignored it since 7.82.0.
///
/// # Safety
///
/// `string` must be NULL or point to at least `length` readable bytes (or a
/// valid NUL-terminated C string when `length == 0`). `outlength`, if non-NULL,
/// must point to a writable `c_int`. `handle` is not dereferenced.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_unescape(
    handle: *mut CURL,
    string: *const c_char,
    length: c_int,
    outlength: *mut c_int,
) -> *mut c_char {
    // `handle` is ignored (curl: "data is ignored since 7.82.0").
    let _ = handle;

    // curl only proceeds when `string` is non-NULL and `length >= 0`; otherwise
    // it returns its NULL-initialized `str` and leaves `*outlength` untouched.
    if string.is_null() || length < 0 {
        return ptr::null_mut();
    }

    // `length == 0` → decode the whole NUL-terminated string (curl's
    // `alloc = length ? length : strlen(string)`); else decode `length` bytes.
    let inputlen: usize = if length != 0 {
        length as usize
    } else {
        // SAFETY: `string` is non-NULL (checked) and NUL-terminated for the
        // `length == 0` case per the caller's contract, so `strlen` is sound.
        unsafe { libc::strlen(string) }
    };

    // SAFETY: `string` references at least `inputlen` readable bytes — an
    // explicit non-negative `length`, or the measured `strlen` above.
    let bytes = unsafe { slice::from_raw_parts(string as *const u8, inputlen) };

    // REJECT_NADA: never rejects content, but propagate any error as curl's
    // "return NULL on decode error" just in case the policy ever changes.
    let decoded = match core::escape::unescape(bytes, false) {
        Ok(d) => d,
        Err(_) => return ptr::null_mut(),
    };

    if !outlength.is_null() {
        // curl: if the size does not fit an int, free and return NULL without
        // writing `*outlength`. We have not allocated a C buffer yet (the data
        // lives in `decoded`, dropped here), so simply bail with NULL.
        if decoded.len() > c_int::MAX as usize {
            return ptr::null_mut();
        }
        // SAFETY: `outlength` is non-NULL (checked) and the caller guarantees it
        // points to a writable `c_int`; the value fits an `int` (checked above).
        unsafe { *outlength = decoded.len() as c_int };
    }

    // Embedded NULs are preserved; the buffer is NUL-terminated and reclaimable
    // by `curl_free`.
    // SAFETY: returns a `curl_free`-able buffer (NULL only on allocation
    // failure), honoring the crate-wide C-heap contract.
    unsafe { c_alloc_bytes(&decoded) }
}

/// `curl_unescape` — deprecated alias for [`curl_easy_unescape`] with no handle
/// and no length out-parameter (curl.h, `lib/escape.c`).
///
/// # Safety
///
/// Same contract as [`curl_easy_unescape`]: `string` must be NULL or reference
/// at least `length` readable bytes (or a NUL-terminated string when
/// `length == 0`).
#[no_mangle]
pub unsafe extern "C" fn curl_unescape(string: *const c_char, length: c_int) -> *mut c_char {
    // SAFETY: forwards the caller's pointer/length contract unchanged to
    // `curl_easy_unescape` with a NULL (ignored) handle and no length out-param,
    // exactly as curl's deprecated alias does.
    unsafe { curl_easy_unescape(ptr::null_mut(), string, length, ptr::null_mut()) }
}

// =============================================================================
// Phase 6 — misc utilities (getenv, getdate, strequal, strnequal)
// =============================================================================

/// `curl_getenv` — read an environment variable into a heap C string the caller
/// frees with [`curl_free`] (curl.h, `lib/getenv.c`).
///
/// Mirrors curl's POSIX path `(env && env[0]) ? strdup(env) : NULL`: an unset
/// variable **and** a set-but-empty variable both return NULL; only a non-empty
/// value yields an allocated copy. On Unix the raw value bytes are copied
/// verbatim (environment values are arbitrary byte strings); on other platforms
/// the value is taken via a lossy UTF-8 view.
///
/// # Safety
///
/// `variable` must be NULL or a valid NUL-terminated C string. A NULL pointer
/// returns NULL (C's `getenv(NULL)` is undefined; this is a defensive guard).
#[no_mangle]
pub unsafe extern "C" fn curl_getenv(variable: *const c_char) -> *mut c_char {
    if variable.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `variable` is non-NULL (checked) and the caller guarantees a valid
    // NUL-terminated C string for the duration of the call.
    let name = unsafe { CStr::from_ptr(variable) };

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        // Environment variable *names* may be arbitrary non-NUL bytes on Unix.
        let key = std::ffi::OsStr::from_bytes(name.to_bytes());
        match env::var_os(key) {
            // Set-but-empty is treated as "unset" (NULL), matching curl's
            // `env[0]` check.
            Some(val) if !val.as_bytes().is_empty() => {
                // SAFETY: hands back a `curl_free`-able heap copy of the raw
                // value bytes (NULL on allocation failure).
                unsafe { c_strdup_bytes(val.as_bytes()) }
            }
            _ => ptr::null_mut(),
        }
    }
    #[cfg(not(unix))]
    {
        let key = name.to_string_lossy();
        match env::var_os(key.as_ref()) {
            Some(val) => {
                let text = val.to_string_lossy();
                if text.is_empty() {
                    ptr::null_mut()
                } else {
                    // SAFETY: hands back a `curl_free`-able heap copy of the
                    // value (NULL on allocation failure).
                    unsafe { c_strdup_str(&text) }
                }
            }
            None => ptr::null_mut(),
        }
    }
}

/// `curl_getdate` — parse an HTTP/RFC date string to seconds since the Unix
/// epoch, or `-1` on failure (curl.h, `lib/parsedate.c`).
///
/// Accepts the date grammars curl supports (RFC 1123, RFC 850, asctime, and the
/// common variants) by delegating to the core date parser, which mirrors
/// `lib/parsedate.c`. A NULL pointer or a string that is not valid UTF-8 yields
/// `-1` (the latter cannot be a valid ASCII date). The `unused` second argument
/// is ignored, exactly as in curl.
///
/// # Safety
///
/// `p` must be NULL or a valid NUL-terminated C string. `unused` is never
/// dereferenced (it exists only to match curl's historical signature).
#[no_mangle]
pub unsafe extern "C" fn curl_getdate(p: *const c_char, unused: *const time_t) -> time_t {
    // The second argument has been unused since curl's earliest releases.
    let _ = unused;

    if p.is_null() {
        return -1;
    }
    // SAFETY: `p` is non-NULL (checked) and the caller guarantees a valid
    // NUL-terminated C string for the duration of the call.
    let cstr = unsafe { CStr::from_ptr(p) };
    match cstr.to_str() {
        // Dates are ASCII; the core parser returns the epoch seconds or -1.
        Ok(s) => core::util::parsedate::curl_getdate(s) as time_t,
        // Non-UTF-8 input cannot be a valid date string.
        Err(_) => -1,
    }
}

/// `curl_strequal` — locale-independent ASCII case-insensitive string equality
/// (curl.h, `lib/strequal.c`). Returns `1` when equal, `0` otherwise.
///
/// Matches curl's NULL handling exactly: two non-NULL strings are compared
/// case-insensitively (equal length and matching letters ignoring ASCII case);
/// two NULL pointers compare equal (`1`); a single NULL pointer compares unequal
/// (`0`).
///
/// # Safety
///
/// Each of `s1` and `s2` must be NULL or a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn curl_strequal(s1: *const c_char, s2: *const c_char) -> c_int {
    if !s1.is_null() && !s2.is_null() {
        // SAFETY: both are non-NULL (checked) and the caller guarantees valid
        // NUL-terminated C strings for the duration of the call.
        let c1 = unsafe { CStr::from_ptr(s1) };
        let c2 = unsafe { CStr::from_ptr(s2) };
        // `strcasecompare` over the NUL-stripped bytes reproduces curl's
        // `casecompare` (equal length + ASCII-case-insensitive match).
        c_int::from(core::util::strcase::strcasecompare(
            c1.to_bytes(),
            c2.to_bytes(),
        ))
    } else {
        // Both NULL → equal (1); exactly one NULL → unequal (0).
        c_int::from(s1.is_null() && s2.is_null())
    }
}

/// `curl_strnequal` — like [`curl_strequal`] but comparing at most `n`
/// characters (curl.h, `lib/strequal.c`). Returns `1` when the prefixes are
/// equal, `0` otherwise.
///
/// Matches curl's NULL handling exactly: two non-NULL strings have their first
/// `n` characters compared case-insensitively; two NULL pointers compare equal
/// only when `n` is non-zero (`1`), and any single NULL pointer compares unequal
/// (`0`).
///
/// # Safety
///
/// Each of `s1` and `s2` must be NULL or a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn curl_strnequal(s1: *const c_char, s2: *const c_char, n: size_t) -> c_int {
    if !s1.is_null() && !s2.is_null() {
        // SAFETY: both are non-NULL (checked) and the caller guarantees valid
        // NUL-terminated C strings for the duration of the call.
        let c1 = unsafe { CStr::from_ptr(s1) };
        let c2 = unsafe { CStr::from_ptr(s2) };
        // `strncasecompare` reproduces curl's `ncasecompare` semantics over the
        // NUL-stripped bytes, including the NUL-terminated edge handling.
        // `size_t` is the same primitive as the `usize` parameter `strncasecompare`
        // takes on every supported target, so `n` is forwarded directly.
        c_int::from(core::util::strcase::strncasecompare(
            c1.to_bytes(),
            c2.to_bytes(),
            n,
        ))
    } else {
        // Both NULL with non-zero n → equal (1); otherwise unequal (0).
        c_int::from(s1.is_null() && s2.is_null() && n != 0)
    }
}

// =============================================================================
// Tests — exercise all 16 exported symbols and the C-heap helpers.
//
// These are in-crate unit tests; they call the `extern "C"` entry points and
// the `pub(crate)` helpers directly. C strings are built with `CString` and
// every buffer the library returns is released with `curl_free`, validating the
// crate-wide C-heap contract end-to-end.
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// Reads a library-returned C string into an owned `String` and frees it via
    /// `curl_free`, exercising the round-trip allocation/deallocation contract.
    ///
    /// # Safety
    /// `p` must be NULL or a `curl_free`-able C string from this library.
    unsafe fn take_cstr(p: *mut c_char) -> Option<String> {
        if p.is_null() {
            return None;
        }
        // SAFETY: `p` is a non-NULL NUL-terminated C string from the library.
        let owned = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        // SAFETY: `p` was allocated by the library and is freed exactly once.
        unsafe { curl_free(p as *mut c_void) };
        Some(owned)
    }

    /// Reads `len` raw bytes from a library-returned buffer (which may contain
    /// embedded NULs) and frees it via `curl_free`.
    ///
    /// # Safety
    /// `p` must be NULL or a `curl_free`-able buffer of at least `len` bytes.
    unsafe fn take_bytes(p: *mut c_char, len: usize) -> Option<Vec<u8>> {
        if p.is_null() {
            return None;
        }
        // SAFETY: `p` references at least `len` valid bytes (the library wrote
        // `len` data bytes plus a terminator).
        let bytes = unsafe { slice::from_raw_parts(p as *const u8, len) }.to_vec();
        // SAFETY: `p` was allocated by the library and is freed exactly once.
        unsafe { curl_free(p as *mut c_void) };
        Some(bytes)
    }

    // ---- Phase 0 / 1: C-heap helpers + curl_free --------------------------

    #[test]
    fn c_heap_helpers_allocate_curl_free_able_buffers() {
        // c_strdup_str → NUL-terminated copy, reclaimable by curl_free.
        // SAFETY: helper returns a curl_free-able buffer; `take_cstr` frees it.
        let s = unsafe { take_cstr(c_strdup_str("hello")) };
        assert_eq!(s.as_deref(), Some("hello"));

        // c_strdup_bytes of an empty slice → a valid empty C string (1 byte NUL).
        // SAFETY: as above.
        let empty = unsafe { take_cstr(c_strdup_bytes(b"")) };
        assert_eq!(empty.as_deref(), Some(""));

        // c_alloc_bytes preserves embedded NUL bytes (the unescape use case).
        let data = [b'a', 0u8, b'b'];
        // SAFETY: helper returns a curl_free-able buffer of data.len()+1 bytes;
        // `take_bytes` reads exactly data.len() bytes then frees it.
        let bytes = unsafe { take_bytes(c_alloc_bytes(&data), data.len()) };
        assert_eq!(bytes.as_deref(), Some(&data[..]));
    }

    #[test]
    fn curl_free_null_is_a_noop() {
        // Must not crash on NULL (curl's contract).
        // SAFETY: NULL is an explicitly supported argument (no-op).
        unsafe { curl_free(ptr::null_mut()) };
    }

    // ---- Phase 2: global init / cleanup / trace ---------------------------

    #[test]
    fn global_init_cleanup_trace_succeed() {
        assert_eq!(curl_global_init(CURL_GLOBAL_DEFAULT), CURLcode::CURLE_OK);
        // init_mem with NULL allocator callbacks behaves like global_init.
        // SAFETY: NULL callbacks are explicitly supported (accepted-but-unused).
        let rc = unsafe { curl_global_init_mem(CURL_GLOBAL_ALL, None, None, None, None, None) };
        assert_eq!(rc, CURLcode::CURLE_OK);

        // trace: NULL config and a comma-separated list are both accepted.
        // SAFETY: NULL is supported; the CString outlives the call.
        assert_eq!(
            unsafe { curl_global_trace(ptr::null()) },
            CURLcode::CURLE_OK
        );
        let cfg = CString::new("all,http/2,ssl").unwrap();
        // SAFETY: `cfg` is a valid NUL-terminated C string for the call.
        assert_eq!(
            unsafe { curl_global_trace(cfg.as_ptr()) },
            CURLcode::CURLE_OK
        );

        // Cleanup is balanced and tolerant of extra calls.
        curl_global_cleanup();
        curl_global_cleanup();
    }

    #[test]
    fn global_flag_constants_match_curl() {
        assert_eq!(CURL_GLOBAL_SSL, 1 << 0);
        assert_eq!(CURL_GLOBAL_WIN32, 1 << 1);
        assert_eq!(CURL_GLOBAL_ALL, (1 << 0) | (1 << 1));
        assert_eq!(CURL_GLOBAL_NOTHING, 0);
        assert_eq!(CURL_GLOBAL_DEFAULT, CURL_GLOBAL_ALL);
        assert_eq!(CURL_GLOBAL_ACK_EINTR, 1 << 2);
    }

    // ---- Phase 3: curl_global_sslset --------------------------------------

    #[test]
    fn sslset_selects_rustls_by_id_and_name() {
        // By id.
        // SAFETY: NULL name and avail are supported arguments.
        let by_id = unsafe {
            curl_global_sslset(
                curl_sslbackend::CURLSSLBACKEND_RUSTLS,
                ptr::null(),
                ptr::null_mut(),
            )
        };
        assert_eq!(by_id, CURLsslset::CURLSSLSET_OK);

        // By case-insensitive name, with id NONE.
        let name = CString::new("RuStLs").unwrap();
        // SAFETY: `name` is a valid C string for the call; avail is NULL.
        let by_name = unsafe {
            curl_global_sslset(
                curl_sslbackend::CURLSSLBACKEND_NONE,
                name.as_ptr(),
                ptr::null_mut(),
            )
        };
        assert_eq!(by_name, CURLsslset::CURLSSLSET_OK);

        // A different backend is unknown in this single-backend build.
        let other = CString::new("openssl").unwrap();
        // SAFETY: `other` is a valid C string for the call; avail is NULL.
        let unknown = unsafe {
            curl_global_sslset(
                curl_sslbackend::CURLSSLBACKEND_OPENSSL,
                other.as_ptr(),
                ptr::null_mut(),
            )
        };
        assert_eq!(unknown, CURLsslset::CURLSSLSET_UNKNOWN_BACKEND);

        // NONE + NULL name → unknown (matches the C oracle / core).
        // SAFETY: NULL name and avail are supported arguments.
        let none = unsafe {
            curl_global_sslset(
                curl_sslbackend::CURLSSLBACKEND_NONE,
                ptr::null(),
                ptr::null_mut(),
            )
        };
        assert_eq!(none, CURLsslset::CURLSSLSET_UNKNOWN_BACKEND);
    }

    #[test]
    fn sslset_populates_avail_with_rustls_then_null() {
        let mut avail: *const *const curl_ssl_backend = ptr::null();
        // SAFETY: `avail` points to a writable slot; name is NULL.
        let rc = unsafe {
            curl_global_sslset(
                curl_sslbackend::CURLSSLBACKEND_RUSTLS,
                ptr::null(),
                &mut avail,
            )
        };
        assert_eq!(rc, CURLsslset::CURLSSLSET_OK);
        assert!(!avail.is_null(), "avail must be populated");

        // First entry is the rustls backend; second entry is the NULL sentinel.
        // SAFETY: `avail` is the library's static, NULL-terminated array.
        let first = unsafe { *avail };
        assert!(!first.is_null(), "first backend entry must be non-NULL");
        // SAFETY: `first` points to the static rustls `curl_ssl_backend`.
        let backend = unsafe { &*first };
        assert_eq!(backend.id, curl_sslbackend::CURLSSLBACKEND_RUSTLS);
        // SAFETY: `backend.name` is the static "rustls" C string.
        let name = unsafe { CStr::from_ptr(backend.name) };
        assert_eq!(name.to_str().unwrap(), "rustls");
        // SAFETY: the array element after the first is the NULL terminator.
        let second = unsafe { *avail.add(1) };
        assert!(second.is_null(), "array must be NULL-terminated");
    }

    // ---- Phase 4: curl_version / curl_version_info ------------------------

    #[test]
    fn version_banner_starts_with_libcurl() {
        let p = curl_version();
        assert!(!p.is_null());
        // The banner is static; read it without freeing.
        // SAFETY: `p` is the library's static, process-lifetime banner string.
        let banner = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
        assert!(
            banner.starts_with("libcurl/8.19.0-DEV"),
            "banner was: {banner}"
        );
        // The TLS backend identity must appear in the banner.
        assert!(banner.contains("rustls/0.23.36"), "banner was: {banner}");
    }

    #[test]
    fn version_info_reports_expected_fields() {
        let p = curl_version_info(CURLversion::CURLVERSION_TWELFTH);
        assert!(!p.is_null());
        // SAFETY: `p` is the library's static, process-lifetime descriptor.
        let info = unsafe { &*p };

        // Age is the highest supported layout, regardless of the requested age.
        assert_eq!(info.age, CURLversion::CURLVERSION_TWELFTH);
        assert_eq!(info.version_num, 0x0008_1300);

        // SAFETY: `version` is a non-NULL static C string.
        let version = unsafe { CStr::from_ptr(info.version) }.to_str().unwrap();
        assert_eq!(version, "8.19.0-DEV");

        // ssl_version must be the rustls identity.
        assert!(!info.ssl_version.is_null());
        // SAFETY: `ssl_version` is a non-NULL static C string here.
        let ssl = unsafe { CStr::from_ptr(info.ssl_version) }
            .to_str()
            .unwrap();
        assert_eq!(ssl, "rustls/0.23.36");

        // Feature bits must include SSL and HTTP2 (default-build invariants).
        // Reference the crate directly: inside this test module the glob-imported
        // `core` alias is ambiguous with the built-in `core` crate in a `use`.
        use curl_rs_lib::version::version_bits::{CURL_VERSION_HTTP2, CURL_VERSION_SSL};
        assert_ne!(info.features & CURL_VERSION_SSL, 0);
        assert_ne!(info.features & CURL_VERSION_HTTP2, 0);

        // host is populated.
        assert!(!info.host.is_null());

        // protocols: NULL-terminated, contains http + https (lowercase schemes).
        // SAFETY: `protocols` is the static NULL-terminated array built here.
        let protos = unsafe { collect_cstr_array(info.protocols) };
        assert!(protos.iter().any(|s| s == "http"), "protocols: {protos:?}");
        assert!(protos.iter().any(|s| s == "https"), "protocols: {protos:?}");

        // feature_names: NULL-terminated, contains SSL + HTTP2.
        // SAFETY: `feature_names` is the static NULL-terminated array built here.
        let feats = unsafe { collect_cstr_array(info.feature_names) };
        assert!(feats.iter().any(|s| s == "SSL"), "features: {feats:?}");
        assert!(feats.iter().any(|s| s == "HTTP2"), "features: {feats:?}");
    }

    #[test]
    fn version_info_is_stable_across_calls() {
        // The descriptor is a single process-lifetime object.
        let a = curl_version_info(CURLversion::CURLVERSION_TWELFTH);
        let b = curl_version_info(CURLversion::CURLVERSION_FIRST);
        assert_eq!(a, b, "curl_version_info must return the same static struct");
    }

    /// Collects a NULL-terminated `*const *const c_char` array into owned strings.
    ///
    /// # Safety
    /// `arr` must be NULL or a NULL-terminated array of valid C-string pointers.
    unsafe fn collect_cstr_array(arr: *const *const c_char) -> Vec<String> {
        let mut out = Vec::new();
        if arr.is_null() {
            return out;
        }
        let mut i = 0isize;
        loop {
            // SAFETY: `arr` is NULL-terminated, so iterating until a NULL entry
            // stays in bounds.
            let entry = unsafe { *arr.offset(i) };
            if entry.is_null() {
                break;
            }
            // SAFETY: `entry` is a valid NUL-terminated C string.
            out.push(
                unsafe { CStr::from_ptr(entry) }
                    .to_string_lossy()
                    .into_owned(),
            );
            i += 1;
        }
        out
    }

    // ---- Phase 5: escape / unescape ---------------------------------------

    #[test]
    fn escape_unescape_round_trip() {
        let input = CString::new("a b/c?").unwrap();
        // length 0 → strlen; handle ignored.
        // SAFETY: `input` is a valid C string for the call.
        let escaped_ptr = unsafe { curl_easy_escape(ptr::null_mut(), input.as_ptr(), 0) };
        // SAFETY: library buffer; `take_cstr` reads and frees it.
        let escaped = unsafe { take_cstr(escaped_ptr) }.expect("escape returned NULL");
        assert_eq!(escaped, "a%20b%2Fc%3F");

        // Round-trip back through unescape.
        let enc = CString::new(escaped).unwrap();
        let mut outlen: c_int = -1;
        // SAFETY: `enc` is a valid C string; `outlen` is writable.
        let decoded_ptr =
            unsafe { curl_easy_unescape(ptr::null_mut(), enc.as_ptr(), 0, &mut outlen) };
        assert_eq!(outlen, 6);
        // SAFETY: library buffer of `outlen` bytes; read and free.
        let decoded = unsafe { take_bytes(decoded_ptr, outlen as usize) }.expect("NULL");
        assert_eq!(decoded, b"a b/c?");
    }

    #[test]
    fn escape_edge_cases() {
        // NULL string → NULL.
        // SAFETY: NULL string is an explicitly supported argument.
        assert!(unsafe { curl_easy_escape(ptr::null_mut(), ptr::null(), 0) }.is_null());

        // Negative length → NULL.
        let s = CString::new("x").unwrap();
        // SAFETY: `s` is a valid C string; negative length is handled.
        assert!(unsafe { curl_easy_escape(ptr::null_mut(), s.as_ptr(), -1) }.is_null());

        // Empty string (length 0 → strlen == 0) → allocated empty string, NOT NULL.
        let empty = CString::new("").unwrap();
        // SAFETY: `empty` is a valid C string for the call.
        let p = unsafe { curl_easy_escape(ptr::null_mut(), empty.as_ptr(), 0) };
        // SAFETY: library buffer; read and free.
        assert_eq!(unsafe { take_cstr(p) }.as_deref(), Some(""));
    }

    #[test]
    fn escape_reads_explicit_length_with_embedded_nul() {
        // With an explicit positive length, raw bytes (incl. embedded NUL) are
        // escaped — curl's behavior when `inlength` is given.
        let raw = [b'a', 0u8, b'b'];
        // SAFETY: `raw` has 3 readable bytes; we pass length 3 explicitly.
        let p = unsafe { curl_easy_escape(ptr::null_mut(), raw.as_ptr() as *const c_char, 3) };
        // SAFETY: library buffer; read and free.
        let escaped = unsafe { take_cstr(p) }.expect("NULL");
        // 'a' is unreserved, NUL → %00, 'b' is unreserved.
        assert_eq!(escaped, "a%00b");
    }

    #[test]
    fn escape_alias_matches_easy_escape() {
        let s = CString::new("a+b").unwrap();
        // SAFETY: `s` is a valid C string for both calls.
        let via_alias = unsafe { take_cstr(curl_escape(s.as_ptr(), 0)) };
        // SAFETY: as above.
        let via_easy = unsafe { take_cstr(curl_easy_escape(ptr::null_mut(), s.as_ptr(), 0)) };
        assert_eq!(via_alias, via_easy);
        assert_eq!(via_alias.as_deref(), Some("a%2Bb"));
    }

    #[test]
    fn unescape_preserves_embedded_nul() {
        // "%00" decodes to a single NUL byte; outlength reports 1.
        let enc = CString::new("%00").unwrap();
        let mut outlen: c_int = -1;
        // SAFETY: `enc` is a valid C string; `outlen` is writable.
        let p = unsafe { curl_easy_unescape(ptr::null_mut(), enc.as_ptr(), 0, &mut outlen) };
        assert_eq!(outlen, 1);
        // SAFETY: library buffer of `outlen` bytes; read and free.
        let bytes = unsafe { take_bytes(p, outlen as usize) }.expect("NULL");
        assert_eq!(bytes, vec![0u8]);
    }

    #[test]
    fn unescape_alias_and_null_input() {
        // NULL input → NULL.
        // SAFETY: NULL string is an explicitly supported argument.
        assert!(unsafe { curl_unescape(ptr::null(), 0) }.is_null());

        // Alias decodes like easy_unescape without an outlength.
        let enc = CString::new("%41%42").unwrap();
        // SAFETY: `enc` is a valid C string for the call.
        let decoded = unsafe { take_cstr(curl_unescape(enc.as_ptr(), 0)) };
        assert_eq!(decoded.as_deref(), Some("AB"));
    }

    // ---- Phase 6: getenv / getdate / strequal / strnequal -----------------

    #[test]
    fn getenv_reads_set_unset_and_empty() {
        // PATH is reliably set and non-empty on the test host.
        let path_key = CString::new("PATH").unwrap();
        // SAFETY: `path_key` is a valid C string for the call.
        let path = unsafe { take_cstr(curl_getenv(path_key.as_ptr())) };
        assert!(path.is_some() && !path.unwrap().is_empty());

        // A unique, definitely-unset variable → NULL.
        let missing = CString::new("CURL_RS_DEFINITELY_UNSET_VAR_XYZ").unwrap();
        // SAFETY: `missing` is a valid C string for the call.
        assert!(unsafe { curl_getenv(missing.as_ptr()) }.is_null());

        // A set-but-empty variable → NULL (curl's `env[0]` check).
        let empty_key = "CURL_RS_EMPTY_VAR_TEST";
        // Only this test mutates the environment in this binary.
        // SAFETY (edition 2021): `set_var`/`remove_var` are safe in this edition;
        // no other test in this binary concurrently reads/writes the env.
        env::set_var(empty_key, "");
        let empty_c = CString::new(empty_key).unwrap();
        // SAFETY: `empty_c` is a valid C string for the call.
        let got = unsafe { curl_getenv(empty_c.as_ptr()) };
        env::remove_var(empty_key);
        assert!(got.is_null(), "empty env var must yield NULL");

        // NULL variable name → NULL (defensive).
        // SAFETY: NULL is an explicitly supported (defensive) argument.
        assert!(unsafe { curl_getenv(ptr::null()) }.is_null());
    }

    #[test]
    fn getdate_parses_known_and_rejects_invalid() {
        // Canonical RFC 1123 vector from the core parser's own tests.
        let good = CString::new("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        // SAFETY: `good` is a valid C string; `unused` is NULL (ignored).
        let t = unsafe { curl_getdate(good.as_ptr(), ptr::null()) };
        assert_eq!(t, 784_111_777 as time_t);

        // Invalid date → -1.
        let bad = CString::new("not a date").unwrap();
        // SAFETY: `bad` is a valid C string for the call.
        assert_eq!(unsafe { curl_getdate(bad.as_ptr(), ptr::null()) }, -1);

        // NULL → -1.
        // SAFETY: NULL is an explicitly supported argument.
        assert_eq!(unsafe { curl_getdate(ptr::null(), ptr::null()) }, -1);
    }

    #[test]
    fn strequal_matches_curl_semantics() {
        let a = CString::new("Hello").unwrap();
        let b = CString::new("hELLO").unwrap();
        let c = CString::new("Hellp").unwrap();
        let pre = CString::new("Hell").unwrap();

        // Case-insensitive equality → 1.
        // SAFETY: all are valid C strings for the calls.
        assert_eq!(unsafe { curl_strequal(a.as_ptr(), b.as_ptr()) }, 1);
        // Different content → 0.
        assert_eq!(unsafe { curl_strequal(a.as_ptr(), c.as_ptr()) }, 0);
        // Different length (prefix) → 0.
        assert_eq!(unsafe { curl_strequal(a.as_ptr(), pre.as_ptr()) }, 0);
        // Both NULL → 1.
        // SAFETY: NULL pointers are explicitly supported.
        assert_eq!(unsafe { curl_strequal(ptr::null(), ptr::null()) }, 1);
        // One NULL → 0.
        assert_eq!(unsafe { curl_strequal(a.as_ptr(), ptr::null()) }, 0);
        assert_eq!(unsafe { curl_strequal(ptr::null(), a.as_ptr()) }, 0);
    }

    #[test]
    fn strnequal_matches_curl_semantics() {
        let abc = CString::new("abcDEF").unwrap();
        let abx = CString::new("ABCxyz").unwrap();
        let ab = CString::new("ab").unwrap();
        let abc2 = CString::new("abc").unwrap();

        // First 3 chars match case-insensitively → 1.
        // SAFETY: all are valid C strings for the calls.
        assert_eq!(unsafe { curl_strnequal(abc.as_ptr(), abx.as_ptr(), 3) }, 1);
        // First 4 chars differ ('D' vs 'x') → 0.
        assert_eq!(unsafe { curl_strnequal(abc.as_ptr(), abx.as_ptr(), 4) }, 0);
        // n == 0 with two non-NULL strings → 1 (compared nothing).
        assert_eq!(unsafe { curl_strnequal(abc.as_ptr(), abx.as_ptr(), 0) }, 1);
        // "ab" vs "abc" within n=3: shorter string ends first → 0.
        assert_eq!(unsafe { curl_strnequal(ab.as_ptr(), abc2.as_ptr(), 3) }, 0);
        // "ab" vs "abc" within n=2: equal prefix → 1.
        assert_eq!(unsafe { curl_strnequal(ab.as_ptr(), abc2.as_ptr(), 2) }, 1);
        // Both NULL with non-zero n → 1.
        // SAFETY: NULL pointers are explicitly supported.
        assert_eq!(unsafe { curl_strnequal(ptr::null(), ptr::null(), 5) }, 1);
        // Both NULL with n == 0 → 0.
        assert_eq!(unsafe { curl_strnequal(ptr::null(), ptr::null(), 0) }, 0);
        // One NULL → 0.
        assert_eq!(unsafe { curl_strnequal(abc.as_ptr(), ptr::null(), 3) }, 0);
    }
}
