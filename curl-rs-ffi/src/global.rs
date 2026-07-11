// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! `curl_global_*` lifecycle and free-standing C utility entry points.
//!
//! This module is the `extern "C"` home of two related groups of the libcurl public ABI,
//! transcribed 1:1 from `include/curl/curl.h` and derived from the curl 8.19.0-DEV C entry
//! points `lib/easy.c` (global init / cleanup), `lib/getenv.c`, `lib/parsedate.c`
//! (`curl_getdate`), `lib/strequal.c` (`curl_strequal` / `curl_strnequal`), and `lib/escape.c`
//! (`curl_escape` / `curl_unescape`). It owns **12** `CURL_EXTERN` symbols:
//!
//! ## Global library lifecycle (5)
//!
//! * [`curl_global_init`] — one-time process initialization.
//! * [`curl_global_init_mem`] — init while registering custom allocator callbacks.
//! * [`curl_global_cleanup`] — one-time process teardown.
//! * [`curl_global_trace`] — configure `--trace` component selection.
//! * [`curl_global_sslset`] — select / query the TLS backend.
//!
//! ## Free-standing utilities (7)
//!
//! * [`curl_free`] — free a buffer previously handed to C by this library.
//! * [`curl_getenv`] — duplicate an environment variable's value.
//! * [`curl_getdate`] — parse an HTTP / RFC date string to a Unix `time_t`.
//! * [`curl_strequal`] / [`curl_strnequal`] — locale-independent case-insensitive ASCII compare.
//! * [`curl_escape`] / [`curl_unescape`] — legacy URL percent-encode / -decode aliases.
//!
//! # Behavioural parity with curl 8.x
//!
//! Every symbol reproduces its curl 8.x behaviour, including the load-bearing edge cases that
//! downstream consumers and the unmodified `tests/` corpus depend on:
//!
//! * The `CURL_GLOBAL_*` flag bits and the `CURLsslset` / `curl_sslbackend` integer values are a
//!   frozen ABI contract copied verbatim from `include/curl/curl.h`.
//! * Under the Rust ownership model there is no C-style global allocator to swap, so
//!   [`curl_global_init_mem`] accepts the five allocator callbacks but they are inert (Rust owns
//!   allocation); it still enforces curl's non-null-callback precondition
//!   (`CURLE_FAILED_INIT` when any callback is null) and otherwise returns `CURLE_OK`.
//! * Because this build ships a single audited TLS backend (`rustls`, AAP §0.7.3),
//!   [`curl_global_sslset`] mirrors curl's *single-backend* path: it publishes the one-element
//!   backend list through `avail` and returns `CURLSSLSET_OK` only when the request selects
//!   rustls, else `CURLSSLSET_UNKNOWN_BACKEND`.
//!
//! # Allocation contract (read before touching sibling modules)
//!
//! Any `char *` this library hands to C — from [`curl_escape`], [`curl_unescape`],
//! [`curl_getenv`], and, in sibling modules, from `curl_easy_escape` / `curl_url_get` /
//! `curl_maprintf` — is allocated with [`CString::into_raw`] (the crate-root
//! [`str_to_c_owned`](crate::str_to_c_owned) helper, or this module's [`bytes_to_c_owned`] for
//! byte payloads that are not valid UTF-8). [`curl_free`] is the exact inverse: it reclaims such
//! a pointer with [`CString::from_raw`]. **Every module that returns an owned string to C MUST
//! allocate it the same way** so that a caller's `curl_free` is always symmetric with the
//! allocation.
//!
//! # Unsafe & panic policy (AAP §0.6.2 / §0.7.2)
//!
//! This is the FFI boundary crate — the sole place `unsafe` is permitted — and every `unsafe`
//! block below carries a `// SAFETY:` comment stating the invariant it upholds. No panic is
//! allowed to unwind across the `extern "C"` boundary: the entry points here are written to be
//! panic-free on any caller input (no `unwrap`/`expect` on caller data), and [`curl_getdate`],
//! whose arithmetic-heavy parser is the only place a panic is even conceivable (e.g. a debug
//! overflow check), additionally runs under [`std::panic::catch_unwind`].

// Every function in this module is a `#[no_mangle] pub extern "C"` entry point on the libcurl C
// ABI boundary. By construction they receive raw pointers from C callers and dereference them,
// so Clippy's `not_unsafe_ptr_arg_deref` would fire on each. The libcurl ABI declares these as
// ordinary (non-`unsafe`) C functions, and the Minimal Change Mandate requires reproducing those
// exact signatures; the pointer-validity contract is instead documented per function and upheld
// by a `// SAFETY:` comment at every dereference. The lint is therefore allowed module-wide.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use libc::{c_char, c_int, c_long, c_void, size_t, time_t};
use std::ffi::{CStr, CString};
use std::sync::{Once, OnceLock};

// ===========================================================================
// Frozen ABI: `CURL_GLOBAL_*` flag bits (from include/curl/curl.h)
// ===========================================================================
//
// The values are a frozen contract transcribed verbatim from `include/curl/curl.h`. They are
// typed `c_long` to match the `long flags` parameter of `curl_global_init` /
// `curl_global_init_mem`, so callers combine them without casts.

/// `CURL_GLOBAL_SSL` — historically initialized the SSL library. No purpose since curl 7.57.0
/// (kept for ABI parity); rustls needs no global initialization.
pub const CURL_GLOBAL_SSL: c_long = 1 << 0;
/// `CURL_GLOBAL_WIN32` — initialize the Win32 socket stack. Inert here: Windows is not a
/// supported target (AAP §0.6.5).
pub const CURL_GLOBAL_WIN32: c_long = 1 << 1;
/// `CURL_GLOBAL_ALL` — initialize everything possible (`SSL | WIN32`).
pub const CURL_GLOBAL_ALL: c_long = CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32;
/// `CURL_GLOBAL_NOTHING` — initialize nothing extra.
pub const CURL_GLOBAL_NOTHING: c_long = 0;
/// `CURL_GLOBAL_DEFAULT` — the recommended default (`CURL_GLOBAL_ALL`).
pub const CURL_GLOBAL_DEFAULT: c_long = CURL_GLOBAL_ALL;
/// `CURL_GLOBAL_ACK_EINTR` — historically opted into acknowledging `EINTR`; retained for ABI
/// parity.
pub const CURL_GLOBAL_ACK_EINTR: c_long = 1 << 2;

// ===========================================================================
// Frozen ABI: TLS-backend selection types (from include/curl/curl.h)
// ===========================================================================

/// Result of [`curl_global_sslset`] (`CURLsslset` in `include/curl/curl.h`).
///
/// `#[repr(i32)]` with explicit discriminants pins the integer values as a frozen ABI contract
/// (`CURLSSLSET_OK == 0`), so `cbindgen` and every FFI consumer observe identical integers.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CURLsslset {
    /// The requested backend was selected (or matched the single available backend).
    CURLSSLSET_OK = 0,
    /// The requested backend is not available; `avail` (if given) lists what is.
    CURLSSLSET_UNKNOWN_BACKEND = 1,
    /// The backend was already committed and cannot be changed now.
    CURLSSLSET_TOO_LATE = 2,
    /// libcurl was built without any TLS support.
    CURLSSLSET_NO_BACKENDS = 3,
}

/// The TLS backend identifier enumeration (`curl_sslbackend` in `include/curl/curl.h`).
///
/// All curl 8.x discriminants are reproduced verbatim (including the deprecated / obsolete ones)
/// so the integer surface matches the reference header exactly. This Rust build only ever
/// *selects* [`CURLSSLBACKEND_RUSTLS`](curl_sslbackend::CURLSSLBACKEND_RUSTLS), but a consumer
/// may pass any of these values (or `-1`, curl's "use the `name` argument instead" sentinel) to
/// [`curl_global_sslset`].
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum curl_sslbackend {
    CURLSSLBACKEND_NONE = 0,
    CURLSSLBACKEND_OPENSSL = 1,
    CURLSSLBACKEND_GNUTLS = 2,
    CURLSSLBACKEND_NSS = 3,
    CURLSSLBACKEND_OBSOLETE4 = 4,
    CURLSSLBACKEND_GSKIT = 5,
    CURLSSLBACKEND_POLARSSL = 6,
    CURLSSLBACKEND_WOLFSSL = 7,
    CURLSSLBACKEND_SCHANNEL = 8,
    CURLSSLBACKEND_SECURETRANSPORT = 9,
    CURLSSLBACKEND_AXTLS = 10,
    CURLSSLBACKEND_MBEDTLS = 11,
    CURLSSLBACKEND_MESALINK = 12,
    CURLSSLBACKEND_BEARSSL = 13,
    CURLSSLBACKEND_RUSTLS = 14,
}

/// A single entry of the TLS-backend availability list (`struct curl_ssl_backend` in
/// `include/curl/curl.h`).
///
/// `#[repr(C)]` fixes the field order and layout to `{ curl_sslbackend id; const char *name; }`.
/// Instances are read-only, process-lifetime statics produced by [`avail_backends`] and handed
/// to C through [`curl_global_sslset`]'s `avail` out-parameter; the caller must never free them.
#[repr(C)]
pub struct curl_ssl_backend {
    /// The backend identifier (e.g. [`CURLSSLBACKEND_RUSTLS`](curl_sslbackend::CURLSSLBACKEND_RUSTLS)).
    pub id: curl_sslbackend,
    /// A NUL-terminated, process-lifetime backend name (e.g. `"rustls"`).
    pub name: *const c_char,
}

// ===========================================================================
// Frozen ABI: custom-allocator callback typedefs (from include/curl/curl.h)
// ===========================================================================
//
// These are the signatures `curl_global_init_mem` accepts. They are reproduced for ABI /
// header parity; under the Rust ownership model they are inert (see `curl_global_init_mem`).
// `Option<unsafe extern "C" fn(..)>` is the null-optimized, `#[repr(C)]`-compatible spelling of
// a C function pointer that may be NULL.

/// `curl_malloc_callback` — a `malloc`-style allocator: `void *(*)(size_t size)`.
pub type curl_malloc_callback = Option<unsafe extern "C" fn(size: size_t) -> *mut c_void>;
/// `curl_free_callback` — a `free`-style deallocator: `void (*)(void *ptr)`.
pub type curl_free_callback = Option<unsafe extern "C" fn(ptr: *mut c_void)>;
/// `curl_realloc_callback` — a `realloc`-style reallocator: `void *(*)(void *ptr, size_t size)`.
pub type curl_realloc_callback =
    Option<unsafe extern "C" fn(ptr: *mut c_void, size: size_t) -> *mut c_void>;
/// `curl_strdup_callback` — a `strdup`-style duplicator: `char *(*)(const char *str)`.
pub type curl_strdup_callback = Option<unsafe extern "C" fn(str_: *const c_char) -> *mut c_char>;
/// `curl_calloc_callback` — a `calloc`-style allocator: `void *(*)(size_t nmemb, size_t size)`.
pub type curl_calloc_callback =
    Option<unsafe extern "C" fn(nmemb: size_t, size: size_t) -> *mut c_void>;

// ===========================================================================
// Internal helpers (not exported): one-time init, owned buffers, backend list
// ===========================================================================

/// Process-wide one-time initialization latch.
static GLOBAL_INIT: Once = Once::new();

/// Run the library's one-time global initialization, exactly once per process.
///
/// curl's C `global_init()` performs a cascade of subsystem initializations (`Curl_ssl_init`,
/// `Curl_ssh_init`, `Curl_async_global_init`, Win32 socket startup, …) guarded by an
/// `initialized++` reference count. Under this rewrite those subsystems initialize lazily or via
/// the Rust runtime, and the sole C-only step (`Curl_win32_init`) targets an unsupported
/// platform (AAP §0.6.5), so global init has no eager work to perform — it only needs an
/// idempotent latch. [`std::sync::Once`] provides exactly that, coalescing repeated
/// `curl_global_init` / `curl_global_init_mem` calls just as curl's reference count does.
//
// NOTE(reconciliation): `curl-rs-lib` does not currently expose a `global_init()` entry point.
// If one is later added (e.g. to install a process-default rustls `CryptoProvider`), invoke it
// from inside this `call_once` closure — the ABI contract of the callers does not change.
fn ensure_global_init() {
    GLOBAL_INIT.call_once(|| {
        // Intentionally empty: there is no eager global state to construct under the Rust
        // ownership model. The latch itself is the observable behaviour (idempotency).
    });
}

/// Allocate a C-owned, NUL-terminated copy of `bytes` for return to a C caller.
///
/// This is the byte-oriented sibling of the crate-root [`str_to_c_owned`](crate::str_to_c_owned)
/// helper, used for payloads (such as URL-decoded data from [`curl_unescape`], or environment
/// values from [`curl_getenv`]) that need not be valid UTF-8. Ownership transfers to the caller,
/// who must release the result with [`curl_free`]: allocation is performed through [`CString`],
/// so `curl_free`'s [`CString::from_raw`] is the exact inverse.
///
/// Returns [`std::ptr::null_mut`] when `bytes` contains an interior NUL byte, since a C string
/// cannot represent it — this fails cleanly rather than silently truncating.
fn bytes_to_c_owned(bytes: Vec<u8>) -> *mut c_char {
    match CString::new(bytes) {
        Ok(cstring) => cstring.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Convert an [`std::ffi::OsString`] into its raw byte representation.
///
/// On Unix targets — Linux and macOS, the only supported platforms (AAP §0.6.5) — an environment
/// value is an arbitrary NUL-free byte string, taken verbatim via `OsStringExt::into_vec` with no
/// UTF-8 assumption (matching C `getenv`, which returns raw bytes). A UTF-8 fallback keeps the
/// crate compiling on other hosts, where it yields `None` for non-UTF-8 values.
#[cfg(unix)]
fn os_string_into_bytes(value: std::ffi::OsString) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStringExt;
    Some(value.into_vec())
}

#[cfg(not(unix))]
fn os_string_into_bytes(value: std::ffi::OsString) -> Option<Vec<u8>> {
    value.into_string().ok().map(String::into_bytes)
}

/// Leak `s` as a process-lifetime, NUL-terminated C string and return a pointer to its bytes.
///
/// Used only for the fixed backend-name strings surfaced through [`curl_global_sslset`]. The
/// allocation intentionally lives for the whole process (never freed), mirroring the `leak_cstr`
/// helper the crate root uses for the version strings. The `.expect` runs at first-init on a
/// compile-time-known literal (never on caller input), so it cannot panic in practice and no
/// panic can reach the FFI boundary.
fn leak_cstr_static(s: &str) -> *const c_char {
    let cstring = CString::new(s).expect("static backend name contains no interior NUL");
    Box::leak(cstring.into_boxed_c_str()).as_ptr()
}

/// A `Sync`/`Send` wrapper over the process-lifetime TLS-backend availability list.
///
/// The list handed to C is a `const curl_ssl_backend *[]` — a NUL-terminated array of pointers to
/// backend descriptors — which for this single-backend build holds exactly the rustls descriptor
/// followed by a null terminator. Raw pointers are `!Sync`/`!Send`, so the data is wrapped in
/// this type (whose impls are justified below), published once through an [`OnceLock`], and
/// thereafter only read.
struct AvailBackends {
    /// The single rustls backend descriptor. Boxed so its address is stable and `'static`;
    /// referenced by `list[0]`. Kept alive for the process by living inside the `OnceLock`.
    _backend: Box<curl_ssl_backend>,
    /// The NUL-terminated array handed to C: `[&*_backend, null()]`.
    list: [*const curl_ssl_backend; 2],
}

// SAFETY: an `AvailBackends` is constructed exactly once, stored immutably in a `OnceLock`, and
// thereafter only read; its contained pointers are handed to C solely for reading. Every pointee
// has process lifetime (`_backend`'s heap box lives inside the `OnceLock`, and `name` points at a
// leaked C string), so sharing the raw pointers across threads creates neither a data race nor a
// dangling reference.
unsafe impl Sync for AvailBackends {}
// SAFETY: identical rationale to the `Sync` impl above — the value is immutable after
// construction and all pointees live for the entire process.
unsafe impl Send for AvailBackends {}

/// Storage for the availability list, initialized on first use.
static AVAIL_BACKENDS: OnceLock<AvailBackends> = OnceLock::new();

/// Return a pointer to the first element of the process-lifetime, NUL-terminated
/// `const curl_ssl_backend *[]` availability list (a single entry: rustls).
///
/// The returned pointer, and everything it transitively references, is valid for the entire
/// process, so it is safe to publish to a C caller through [`curl_global_sslset`]'s `avail`
/// out-parameter.
fn avail_backends() -> *const *const curl_ssl_backend {
    let backends = AVAIL_BACKENDS.get_or_init(|| {
        let backend = Box::new(curl_ssl_backend {
            id: curl_sslbackend::CURLSSLBACKEND_RUSTLS,
            name: leak_cstr_static("rustls"),
        });
        // Capture the stable heap address of the descriptor *before* moving the box into the
        // struct. Moving a `Box` relocates only the 8-byte handle, never the heap contents, so
        // this pointer stays valid for as long as `_backend` (the whole process) lives.
        let entry: *const curl_ssl_backend = &*backend as *const curl_ssl_backend;
        AvailBackends {
            _backend: backend,
            list: [entry, std::ptr::null()],
        }
    });
    backends.list.as_ptr()
}

// ===========================================================================
// Phase 1 — Global library lifecycle (5 CURL_EXTERN symbols)
// ===========================================================================

/// `CURLcode curl_global_init(long flags);`
///
/// Perform the library's one-time global initialization. `flags` is a bitmask of the
/// `CURL_GLOBAL_*` constants selecting which subsystems curl's C implementation would initialize
/// (`CURL_GLOBAL_SSL`, `CURL_GLOBAL_WIN32`, …). Under the Rust ownership model none of those
/// subsystems needs eager global setup and the sole Windows-only step targets an unsupported
/// platform, so the flags are accepted for ABI parity and initialization always succeeds.
///
/// The call is idempotent (latched by [`std::sync::Once`]): invoking it repeatedly, or pairing it
/// with [`curl_global_init_mem`], is safe and cheap. Returns `CURLE_OK`.
#[no_mangle]
pub extern "C" fn curl_global_init(flags: c_long) -> crate::CURLcode {
    // `flags` selects subsystems for C; none require eager global setup here. Accepted for ABI
    // parity and intentionally not consulted.
    let _ = flags;
    ensure_global_init();
    crate::CURLcode::CURLE_OK
}

/// `CURLcode curl_global_init_mem(long flags, curl_malloc_callback m, curl_free_callback f,
/// curl_realloc_callback r, curl_strdup_callback s, curl_calloc_callback c);`
///
/// Like [`curl_global_init`], but additionally registers custom memory-management callbacks. As
/// in curl 8.x (`lib/easy.c`), all five callbacks must be non-null; otherwise the function fails
/// early with `CURLE_FAILED_INIT`.
///
/// Under the Rust ownership model there is no process-wide C allocator to replace: the callbacks
/// are accepted (satisfying the ABI and the non-null precondition) but are deliberately never
/// invoked — Rust owns every allocation this library performs. The function then runs the same
/// one-time initialization as [`curl_global_init`] and returns `CURLE_OK`.
#[no_mangle]
pub extern "C" fn curl_global_init_mem(
    flags: c_long,
    m: curl_malloc_callback,
    f: curl_free_callback,
    r: curl_realloc_callback,
    s: curl_strdup_callback,
    c: curl_calloc_callback,
) -> crate::CURLcode {
    // Parity with lib/easy.c: reject the call unless every allocator callback is provided.
    if m.is_none() || f.is_none() || r.is_none() || s.is_none() || c.is_none() {
        return crate::CURLcode::CURLE_FAILED_INIT;
    }
    // The callbacks are validated above and then intentionally ignored (Rust owns allocation);
    // `flags` is accepted for ABI parity as in `curl_global_init`.
    let _ = flags;
    ensure_global_init();
    crate::CURLcode::CURLE_OK
}

/// `void curl_global_cleanup(void);`
///
/// Release resources acquired by global initialization. Because this library constructs no eager
/// global state (see `ensure_global_init`), there is nothing to tear down. Mirroring curl's own
/// best-effort, no-fail cleanup, this is safe to call any number of times — including with no
/// prior [`curl_global_init`].
#[no_mangle]
pub extern "C" fn curl_global_cleanup() {
    // Intentionally empty: no eagerly-constructed global state exists to free. Idempotent and
    // safe to call even without a preceding init.
}

/// `CURLcode curl_global_trace(const char *config);`
///
/// Configure which trace components are active for `--trace` / `CURL_TRACE` diagnostics. `config`
/// is a comma/space-separated list of component names (e.g. `"all"`, `"ids"`, `"time"`,
/// `"multi"`, `"http/2"`), or null to select none.
///
/// The diagnostic vocabulary is preserved for behavioural parity (AAP §0.7.3). Routing of the
/// selected components into the `tracing` subscriber is owned by `curl-rs-lib`; this ABI shim
/// validates and accepts the request and — exactly like curl on the supported platforms — always
/// reports success. Unrecognized tokens are tolerated rather than rejected.
#[no_mangle]
pub extern "C" fn curl_global_trace(config: *const c_char) -> crate::CURLcode {
    // SAFETY: per the C contract, `config` is either null or a valid NUL-terminated string that
    // stays valid for the duration of this call. `cstr_to_str` performs the null check and UTF-8
    // validation, and the borrow it returns does not outlive this call.
    match unsafe { crate::cstr_to_str(config) } {
        // A null (or non-UTF-8) argument selects no components — a no-op, as in curl.
        None => crate::CURLcode::CURLE_OK,
        // A recognized/ignored token list: accepted here; routed by the core library. Matches
        // curl's always-`CURLE_OK` result on the supported platforms.
        Some(_config) => crate::CURLcode::CURLE_OK,
    }
}

/// `CURLsslset curl_global_sslset(curl_sslbackend id, const char *name,
/// const curl_ssl_backend ***avail);`
///
/// Select, or query the availability of, the TLS backend. When `avail` is non-null it is set to
/// point at a NUL-terminated array of the available backends — for this single-audited-backend
/// build (rustls, AAP §0.7.3), a one-element list.
///
/// Selection succeeds (`CURLSSLSET_OK`) exactly when the request identifies rustls, either by
/// `id` ([`CURLSSLBACKEND_RUSTLS`](curl_sslbackend::CURLSSLBACKEND_RUSTLS)) or by a
/// case-insensitive `name` match of `"rustls"`; any other request yields
/// `CURLSSLSET_UNKNOWN_BACKEND`. Because there is only one backend, no runtime switch is ever
/// possible, so `CURLSSLSET_TOO_LATE` does not arise.
#[no_mangle]
pub extern "C" fn curl_global_sslset(
    id: curl_sslbackend,
    name: *const c_char,
    avail: *mut *mut *const curl_ssl_backend,
) -> CURLsslset {
    // Publish the availability list first — curl does so unconditionally when `avail` is given,
    // so a caller can still enumerate backends even when the selection itself is unknown.
    if !avail.is_null() {
        // SAFETY: by the C contract a non-null `avail` points to a writable
        // `const curl_ssl_backend **` slot that is valid for the duration of this call. We store
        // into it the address of our process-lifetime, NUL-terminated backend list; that pointee
        // has 'static lifetime, so the caller may read it safely after this call returns.
        unsafe {
            *avail = avail_backends() as *mut *const curl_ssl_backend;
        }
    }

    // Single-backend selection semantics: succeed iff the request names rustls. Compare by the
    // frozen integer id (so curl's `-1` "use the name argument" sentinel simply fails the id
    // test and falls through to the name test) and, failing that, by a case-insensitive name.
    let id_matches = (id as c_int) == (curl_sslbackend::CURLSSLBACKEND_RUSTLS as c_int);

    let name_matches = if name.is_null() {
        false
    } else {
        // SAFETY: `name` is non-null here and, per the C contract, a valid NUL-terminated string
        // valid for this call; `cstr_to_str` UTF-8-validates and borrows only for this call.
        match unsafe { crate::cstr_to_str(name) } {
            Some(requested) => requested.eq_ignore_ascii_case("rustls"),
            None => false,
        }
    };

    if id_matches || name_matches {
        CURLsslset::CURLSSLSET_OK
    } else {
        CURLsslset::CURLSSLSET_UNKNOWN_BACKEND
    }
}

// ===========================================================================
// Phase 2 — Free-standing utilities (7 CURL_EXTERN symbols)
// ===========================================================================

/// Borrow the bytes of a C string as a slice, without a UTF-8 requirement.
///
/// curl's string comparisons operate on raw bytes with ASCII-only case folding, so this avoids
/// the UTF-8 validation that `cstr_to_str` performs and preserves byte-exact semantics.
///
/// # Safety
/// `ptr` must be null, or a valid NUL-terminated C string that stays valid for the returned
/// borrow's lifetime.
unsafe fn cstr_bytes<'a>(ptr: *const c_char) -> Option<&'a [u8]> {
    if ptr.is_null() {
        None
    } else {
        // SAFETY: by the caller's contract `ptr` is a valid NUL-terminated C string that outlives
        // the returned borrow, so `CStr::from_ptr` may safely walk it to the terminator.
        Some(CStr::from_ptr(ptr).to_bytes())
    }
}

/// Borrow `length` bytes at `ptr`, or the NUL-terminated string at `ptr` when `length <= 0`.
///
/// Mirrors curl's escape/unescape length convention (`lib/escape.c`): a positive `length` is an
/// explicit byte count (permitting embedded NULs), while a zero length means "measure with
/// `strlen`". No UTF-8 assumption is made.
///
/// # Safety
/// `ptr` must be non-null and valid for reads of `length` bytes when `length > 0`, or a valid
/// NUL-terminated C string when `length <= 0`; the data must stay valid for the returned borrow.
unsafe fn input_bytes<'a>(ptr: *const c_char, length: c_int) -> &'a [u8] {
    if length > 0 {
        // SAFETY: by the caller's contract `ptr` is valid for reads of `length` bytes and stays
        // valid for the returned borrow.
        std::slice::from_raw_parts(ptr as *const u8, length as usize)
    } else {
        // length <= 0 → measure with `strlen`.
        // SAFETY: by the caller's contract `ptr` is a valid NUL-terminated C string that stays
        // valid for the returned borrow.
        CStr::from_ptr(ptr).to_bytes()
    }
}

/// ASCII case-insensitive comparison of up to `max` bytes (`lib/strequal.c`
/// `Curl_strncasecompare` semantics).
///
/// Compares the two byte slices — each already the NUL-exclusive content of a C string — position
/// by position with ASCII-only case folding, treating "past the end of the slice" as curl's
/// terminating NUL. Returns `true` when `max` matching bytes are consumed, or when both slices
/// terminate at the same position with all preceding bytes equal.
fn ncasecompare(a: &[u8], b: &[u8], max: usize) -> bool {
    let mut i = 0usize;
    while i < max {
        match (a.get(i).copied(), b.get(i).copied()) {
            (Some(x), Some(y)) => {
                if !x.eq_ignore_ascii_case(&y) {
                    return false;
                }
            }
            // Both strings terminated at the same offset with everything equal so far.
            (None, None) => return true,
            // Exactly one string terminated before the other → unequal.
            _ => return false,
        }
        i += 1;
    }
    // Consumed `max` equal bytes without either string terminating first.
    true
}

/// `void curl_free(void *p);`
///
/// Free a buffer previously handed to a C caller by this library — for example the strings
/// returned by [`curl_escape`], [`curl_unescape`], [`curl_getenv`], or, in sibling modules, by
/// `curl_easy_escape` / `curl_url_get` / `curl_maprintf`. Passing null is a no-op.
///
/// This is the exact inverse of the library's owned-string allocator: those buffers are created
/// with [`CString::into_raw`] (via [`str_to_c_owned`](crate::str_to_c_owned) or [`bytes_to_c_owned`]),
/// and here they are reclaimed with [`CString::from_raw`] and dropped. Every module that returns
/// an owned `char *` to C MUST use that same allocator so this reclamation stays symmetric.
#[no_mangle]
pub extern "C" fn curl_free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is non-null and, by this library's allocation contract, was produced by an
    // owned-string allocator that transfers ownership to C via `CString::into_raw` (see the
    // module docs). Reconstructing the `CString` with `from_raw` reclaims that exact allocation,
    // and dropping it frees it exactly once. The caller is contractually required to pass each
    // such pointer to `curl_free` at most once and to never use it afterwards.
    unsafe {
        drop(CString::from_raw(p as *mut c_char));
    }
}

/// `char *curl_getenv(const char *variable);`
///
/// Return a newly allocated copy of the environment variable `variable`'s value, or null when the
/// variable is unset or empty. Matches `lib/getenv.c`, which duplicates the value only when it is
/// both present and non-empty. The caller frees the result with [`curl_free`].
#[no_mangle]
pub extern "C" fn curl_getenv(variable: *const c_char) -> *mut c_char {
    // SAFETY: per the C contract `variable` is null or a valid NUL-terminated string valid for
    // this call; `cstr_to_str` performs the null check and UTF-8 validation and borrows only for
    // the duration of the call.
    let name = match unsafe { crate::cstr_to_str(variable) } {
        Some(name) => name,
        None => return std::ptr::null_mut(),
    };

    // Parity with lib/getenv.c: duplicate only a present, non-empty value; otherwise return null.
    match std::env::var_os(name) {
        Some(value) => match os_string_into_bytes(value) {
            Some(bytes) if !bytes.is_empty() => bytes_to_c_owned(bytes),
            _ => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// `int curl_strequal(const char *s1, const char *s2);`
///
/// Case-insensitive ASCII string comparison. Returns nonzero when the two strings are equal
/// (ignoring ASCII case), zero otherwise. Matching `lib/strequal.c`, two null pointers compare
/// equal while a single null compares unequal.
#[no_mangle]
pub extern "C" fn curl_strequal(s1: *const c_char, s2: *const c_char) -> c_int {
    // SAFETY: per the C contract `s1`/`s2` are each null or valid NUL-terminated C strings valid
    // for this call; `cstr_bytes` upholds that invariant and borrows only for this call.
    let a = unsafe { cstr_bytes(s1) };
    // SAFETY: as above for `s2`.
    let b = unsafe { cstr_bytes(s2) };
    match (a, b) {
        (Some(a), Some(b)) => c_int::from(a.eq_ignore_ascii_case(b)),
        // Both null compare equal (lib/strequal.c).
        (None, None) => 1,
        // Exactly one null compares unequal.
        _ => 0,
    }
}

/// `int curl_strnequal(const char *s1, const char *s2, size_t n);`
///
/// Case-insensitive ASCII comparison of up to `n` bytes. Returns nonzero when the first `n` bytes
/// (or the whole strings, if shorter) are equal ignoring ASCII case, zero otherwise. Matching
/// `lib/strequal.c`, when both pointers are null the result is nonzero only if `n` is positive.
#[no_mangle]
pub extern "C" fn curl_strnequal(s1: *const c_char, s2: *const c_char, n: size_t) -> c_int {
    // SAFETY: per the C contract `s1`/`s2` are each null or valid NUL-terminated C strings valid
    // for this call; `cstr_bytes` upholds that invariant and borrows only for this call.
    let a = unsafe { cstr_bytes(s1) };
    // SAFETY: as above for `s2`.
    let b = unsafe { cstr_bytes(s2) };
    match (a, b) {
        (Some(a), Some(b)) => c_int::from(ncasecompare(a, b, n)),
        // Both null: equal only when a positive length was requested (lib/strequal.c).
        (None, None) => c_int::from(n != 0),
        // Exactly one null compares unequal.
        _ => 0,
    }
}

/// `char *curl_escape(const char *string, int length);`
///
/// URL percent-encode `string`. This is the legacy alias of `curl_easy_escape(NULL, string,
/// length)` (`lib/escape.c`); the easy handle is irrelevant to escaping. `length` is the input
/// byte count, or `0` to measure with `strlen`. Returns a newly allocated encoded string (an
/// allocated empty string for empty input, never null), or null for a null input or a negative
/// length. The caller frees the result with [`curl_free`].
#[no_mangle]
pub extern "C" fn curl_escape(string: *const c_char, length: c_int) -> *mut c_char {
    // curl rejects a null input or a negative length outright.
    if string.is_null() || length < 0 {
        return std::ptr::null_mut();
    }

    // SAFETY: `string` is non-null and, per the C contract, valid for `length` bytes when
    // `length > 0`, or a valid NUL-terminated C string when `length == 0`. `input_bytes` reads
    // exactly that, and the borrow does not outlive this call.
    let input = unsafe { input_bytes(string, length) };

    // The core percent-encoder mirrors `curl_easy_escape`: it encodes an empty input to an empty
    // string (not null) and emits only ASCII (`%XX`, uppercase, plus the unreserved set), so the
    // owned-string allocation below can never contain an interior NUL and thus never fails.
    let encoded = curl_rs_lib::escape::escape(input);
    crate::str_to_c_owned(&encoded)
}

/// `char *curl_unescape(const char *string, int length);`
///
/// URL percent-decode `string`. This is the legacy alias of `curl_easy_unescape(NULL, string,
/// length, NULL)` (`lib/escape.c`); the easy handle and output-length parameters are irrelevant
/// here. `length` is the input byte count, or `0` to measure with `strlen`. Returns a newly
/// allocated decoded string, or null for a null input or a negative length. The caller frees the
/// result with [`curl_free`].
///
/// The decoder runs in curl's permissive `REJECT_NADA` mode (no control-character rejection), so
/// it never errors on well-formed input. Because every buffer handed to C must be reclaimable by
/// [`curl_free`]'s [`CString`]-based allocator, a decoded payload that contains an interior NUL
/// byte (e.g. from a `%00` sequence) cannot be represented as a C string and yields null rather
/// than a buffer the caller could not safely free.
#[no_mangle]
pub extern "C" fn curl_unescape(string: *const c_char, length: c_int) -> *mut c_char {
    // curl requires a non-null input and a non-negative length.
    if string.is_null() || length < 0 {
        return std::ptr::null_mut();
    }

    // SAFETY: `string` is non-null and, per the C contract, valid for `length` bytes when
    // `length > 0`, or a valid NUL-terminated C string when `length == 0`. `input_bytes` reads
    // exactly that, and the borrow does not outlive this call.
    let input = unsafe { input_bytes(string, length) };

    // `reject_ctrl = false` selects REJECT_NADA: control bytes are passed through and the decode
    // never errors. `bytes_to_c_owned` returns null if the decoded output has an interior NUL
    // (documented above), keeping the result safely `curl_free`-able.
    match curl_rs_lib::escape::unescape(input, false) {
        Ok(decoded) => bytes_to_c_owned(decoded),
        Err(_) => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// `curl_getdate` and the RFC/HTTP date parser (port of lib/parsedate.c).
//
// This is a faithful, pure-`std` reimplementation of curl's date parser — no `chrono` (Minimal
// Change Mandate). It handles RFC 822/1123, RFC 850/1036, and ANSI C `asctime()` formats, plus
// the loose variants curl accepts. Only the 64-bit signed `time_t` code path is ported, because
// the supported targets (Linux/macOS on x86_64/aarch64, AAP §0.6.5) all have a 64-bit signed
// `time_t`; the C file's 32-bit / unsigned `time_t` branches are intentionally omitted.
// ---------------------------------------------------------------------------

/// Abbreviated weekday names (`Curl_wkday` in `lib/parsedate.c`), Monday-indexed.
const WKDAY: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
/// Abbreviated month names (`Curl_month`), January-indexed.
const MONTH: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
/// Full weekday names (`weekday` in `lib/parsedate.c`), Monday-indexed.
const WEEKDAY: [&str; 7] = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
];

/// Daylight-savings offset applied to the summer-time zone entries below (`tDAYZONE`).
const TDAYZONE: i32 = -60;

/// The frequently-used time-zone name table (`tz` in `lib/parsedate.c`). Offsets are in minutes
/// (west-positive, as curl stores them); [`checktz`] converts the match to seconds.
///
/// The offset expressions are kept in the exact `N * 60` / `0 + tDAYZONE` / `-1 * 60` form of the
/// C `tz[]` table so the two remain trivially diffable, hence the localized Clippy allow.
#[allow(clippy::identity_op, clippy::neg_multiply)]
static TZ: &[(&str, i32)] = &[
    ("GMT", 0),                // Greenwich Mean
    ("UT", 0),                 // Universal Time
    ("UTC", 0),                // Universal (Coordinated)
    ("WET", 0),                // Western European
    ("BST", 0 + TDAYZONE),     // British Summer
    ("WAT", 60),               // West Africa
    ("AST", 240),              // Atlantic Standard
    ("ADT", 240 + TDAYZONE),   // Atlantic Daylight
    ("EST", 300),              // Eastern Standard
    ("EDT", 300 + TDAYZONE),   // Eastern Daylight
    ("CST", 360),              // Central Standard
    ("CDT", 360 + TDAYZONE),   // Central Daylight
    ("MST", 420),              // Mountain Standard
    ("MDT", 420 + TDAYZONE),   // Mountain Daylight
    ("PST", 480),              // Pacific Standard
    ("PDT", 480 + TDAYZONE),   // Pacific Daylight
    ("YST", 540),              // Yukon Standard
    ("YDT", 540 + TDAYZONE),   // Yukon Daylight
    ("HST", 600),              // Hawaii Standard
    ("HDT", 600 + TDAYZONE),   // Hawaii Daylight
    ("CAT", 600),              // Central Alaska
    ("AHST", 600),             // Alaska-Hawaii Standard
    ("NT", 660),               // Nome
    ("IDLW", 720),             // International Date Line West
    ("CET", -60),              // Central European
    ("MET", -60),              // Middle European
    ("MEWT", -60),             // Middle European Winter
    ("MEST", -60 + TDAYZONE),  // Middle European Summer
    ("CEST", -60 + TDAYZONE),  // Central European Summer
    ("MESZ", -60 + TDAYZONE),  // Middle European Summer
    ("FWT", -60),              // French Winter
    ("FST", -60 + TDAYZONE),   // French Summer
    ("EET", -120),             // Eastern Europe, USSR Zone 1
    ("WAST", -420),            // West Australian Standard
    ("WADT", -420 + TDAYZONE), // West Australian Daylight
    ("CCT", -480),             // China Coast, USSR Zone 7
    ("JST", -540),             // Japan Standard, USSR Zone 8
    ("EAST", -600),            // Eastern Australian Standard
    ("EADT", -600 + TDAYZONE), // Eastern Australian Daylight
    ("GST", -600),             // Guam Standard, USSR Zone 9
    ("NZT", -720),             // New Zealand
    ("NZST", -720),            // New Zealand Standard
    ("NZDT", -720 + TDAYZONE), // New Zealand Daylight
    ("IDLE", -720),            // International Date Line East
    // Military time-zone names (RFC 822), with the corrected signs noted in RFC 1123. "J"
    // (Juliet) is intentionally absent — it denotes the observer's local time.
    ("A", 1 * 60),
    ("B", 2 * 60),
    ("C", 3 * 60),
    ("D", 4 * 60),
    ("E", 5 * 60),
    ("F", 6 * 60),
    ("G", 7 * 60),
    ("H", 8 * 60),
    ("I", 9 * 60),
    ("K", 10 * 60),
    ("L", 11 * 60),
    ("M", 12 * 60),
    ("N", -1 * 60),
    ("O", -2 * 60),
    ("P", -3 * 60),
    ("Q", -4 * 60),
    ("R", -5 * 60),
    ("S", -6 * 60),
    ("T", -7 * 60),
    ("U", -8 * 60),
    ("V", -9 * 60),
    ("W", -10 * 60),
    ("X", -11 * 60),
    ("Y", -12 * 60),
    ("Z", 0), // Zulu, zero meridian (UTC)
];

/// The longest weekday name this parser recognizes ("Wednesday"); tokens this long or longer are
/// rejected. Matches `NAME_LEN` in `lib/parsedate.c`.
const NAME_LEN: usize = 12;

/// What a bare number is next assumed to represent, mirroring `enum assume` in `lib/parsedate.c`.
/// (curl's unused `DATE_TIME` variant is omitted — it is never assigned in the C either.)
enum Assume {
    /// The next bare 1-2 digit number is a day-of-month.
    Mday,
    /// The next bare number is a year.
    Year,
}

/// Return the weekday index (0 = Monday … 6 = Sunday) for `check`, or `-1` if it is not a weekday
/// name. Matches `checkday` in `lib/parsedate.c`.
fn checkday(check: &[u8]) -> i32 {
    let len = check.len();
    // len > 3 -> full names ("Monday"…); len == 3 -> abbreviations ("Mon"…); shorter -> no match.
    let what: &[&str] = match len.cmp(&3) {
        std::cmp::Ordering::Greater => &WEEKDAY,
        std::cmp::Ordering::Equal => &WKDAY,
        std::cmp::Ordering::Less => return -1, // too short
    };
    for (i, name) in what.iter().enumerate() {
        if name.len() == len && ncasecompare(check, name.as_bytes(), len) {
            return i as i32;
        }
    }
    -1
}

/// Return the month index (0 = January … 11 = December) for `check`, or `-1` if it is not a month
/// name. Only 3-letter abbreviations are recognized, matching `checkmonth` in `lib/parsedate.c`.
fn checkmonth(check: &[u8]) -> i32 {
    if check.len() != 3 {
        return -1; // not a month
    }
    for (i, name) in MONTH.iter().enumerate() {
        if ncasecompare(check, name.as_bytes(), 3) {
            return i as i32;
        }
    }
    -1
}

/// Return the time-zone offset from GMT in **seconds** for `check`, or `-1` if it is not a known
/// zone. Matches `checktz` in `lib/parsedate.c`. (A real offset is always a whole number of
/// minutes, so it can never collide with the `-1` sentinel.)
fn checktz(check: &[u8]) -> i32 {
    let len = check.len();
    if len > 4 {
        return -1; // longer than any valid timezone
    }
    for (name, offset) in TZ.iter() {
        if name.len() == len && ncasecompare(check, name.as_bytes(), len) {
            return offset * 60;
        }
    }
    -1
}

/// Convert a broken-down GMT time to seconds since the Unix epoch. A GMT-only analogue of
/// `mktime`, matching `time2epoch` in `lib/parsedate.c`. `mon` must be in `0..=11`.
fn time2epoch(sec: i32, min: i32, hour: i32, mday: i32, mon: i32, year: i32) -> i64 {
    const MONTH_DAYS_CUMULATIVE: [i32; 12] =
        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut leap_days = year - i32::from(mon <= 1);
    leap_days = (leap_days / 4) - (leap_days / 100) + (leap_days / 400) - (1969 / 4) + (1969 / 100)
        - (1969 / 400);
    (((i64::from(year - 1970) * 365
        + i64::from(leap_days)
        + i64::from(MONTH_DAYS_CUMULATIVE[mon as usize])
        + i64::from(mday - 1))
        * 24
        + i64::from(hour))
        * 60
        + i64::from(min))
        * 60
        + i64::from(sec)
}

/// Parse a one- or two-digit decimal number at `start`, returning `(value, index-after)`. The
/// caller guarantees `bytes[start]` is a digit. Matches `oneortwodigit` in `lib/parsedate.c`.
fn oneortwodigit(bytes: &[u8], start: usize) -> (i32, usize) {
    let d0 = i32::from(bytes[start] - b'0');
    if start + 1 < bytes.len() && bytes[start + 1].is_ascii_digit() {
        let d1 = i32::from(bytes[start + 1] - b'0');
        (d0 * 10 + d1, start + 2)
    } else {
        (d0, start + 1)
    }
}

/// Parse an `HH:MM[:SS]` time (single digits allowed) at `start`. Returns
/// `Some((hour, min, sec, index-after))` on a valid match, `None` otherwise. The caller
/// guarantees `bytes[start]` is a digit. Matches `match_time` in `lib/parsedate.c`.
fn match_time(bytes: &[u8], start: usize) -> Option<(i32, i32, i32, usize)> {
    let at = |i: usize| bytes.get(i).copied().unwrap_or(0);
    let (hh, mut p) = oneortwodigit(bytes, start);
    if hh < 24 && at(p) == b':' && at(p + 1).is_ascii_digit() {
        let (mm, np) = oneortwodigit(bytes, p + 1);
        p = np;
        if mm < 60 {
            if at(p) == b':' && at(p + 1).is_ascii_digit() {
                let (ss, np2) = oneortwodigit(bytes, p + 1);
                p = np2;
                if ss <= 60 {
                    return Some((hh, mm, ss, p)); // valid HH:MM:SS
                }
            } else {
                return Some((hh, mm, 0, p)); // valid HH:MM
            }
        }
    }
    None // not a time string
}

/// Parse a run of decimal digits at `start`, returning `(value, index-after)`. Requires at least
/// one digit and fails (returns `None`) if the accumulated value would exceed `max`. Mirrors
/// `curlx_str_number(&p, &val, max)` with base 10 (leading zeros accepted; overflow rejected).
fn str_number(bytes: &[u8], start: usize, max: u64) -> Option<(u64, usize)> {
    let mut pos = start;
    if pos >= bytes.len() || !bytes[pos].is_ascii_digit() {
        return None; // no number
    }
    let mut num: u64 = 0;
    while pos < bytes.len() && bytes[pos].is_ascii_digit() {
        let n = u64::from(bytes[pos] - b'0');
        if num > (max - n) / 10 {
            return None; // overflow
        }
        num = num * 10 + n;
        pos += 1;
    }
    Some((num, pos))
}

/// Parse a date string (as raw bytes) into seconds since the Unix epoch.
///
/// Returns `Some(t)` on a successful parse (`PARSEDATE_OK`), and `None` on any non-success outcome
/// — a malformed string (`PARSEDATE_FAIL`) or a far-future `time_t` overflow (`PARSEDATE_LATER`).
/// This collapsing of the failure outcomes exactly matches [`curl_getdate`], which returns `-1`
/// for every non-`OK` result. Faithful port of `parsedate` in `lib/parsedate.c` (64-bit signed
/// `time_t` path).
fn parsedate(bytes: &[u8]) -> Option<i64> {
    let n = bytes.len();
    let at = |i: usize| -> u8 {
        if i < n {
            bytes[i]
        } else {
            0
        }
    };

    let mut wdaynum: i32 = -1; // day of week, 0-6 (unused beyond de-duplication)
    let mut monnum: i32 = -1; // month, 0-11
    let mut mdaynum: i32 = -1; // day of month, 1-31
    let mut hournum: i32 = -1;
    let mut minnum: i32 = -1;
    let mut secnum: i32 = -1;
    let mut yearnum: i32 = -1;
    let mut tzoff: i32 = -1;
    let mut dignext = Assume::Mday;
    let mut pos: usize = 0;
    let mut part = 0; // at most 6 parts

    while at(pos) != 0 && part < 6 {
        let mut found = false;

        // skip everything that is not a letter or digit
        while at(pos) != 0 && !at(pos).is_ascii_alphanumeric() {
            pos += 1;
        }

        if at(pos).is_ascii_alphabetic() {
            // a name coming up
            let name_start = pos;
            let mut len = 0usize;
            while at(pos).is_ascii_alphabetic() && len < NAME_LEN {
                pos += 1;
                len += 1;
            }
            let token = &bytes[name_start..name_start + len];

            if len != NAME_LEN {
                if wdaynum == -1 {
                    wdaynum = checkday(token);
                    if wdaynum != -1 {
                        found = true;
                    }
                }
                if !found && monnum == -1 {
                    monnum = checkmonth(token);
                    if monnum != -1 {
                        found = true;
                    }
                }
                if !found && tzoff == -1 {
                    // this just must be a time-zone string
                    tzoff = checktz(token);
                    if tzoff != -1 {
                        found = true;
                    }
                }
            }
            if !found {
                return None; // bad string
            }
            // `pos` has already advanced past the name (equivalent to `date += len`).
        } else if at(pos).is_ascii_digit() {
            let tok_start = pos;

            // A time stamp takes precedence when no seconds have been seen yet.
            if secnum == -1 {
                if let Some((h, m, s, end)) = match_time(bytes, tok_start) {
                    hournum = h;
                    minnum = m;
                    secnum = s;
                    pos = end;
                    part += 1;
                    continue;
                }
            }

            // Otherwise a plain number, bounded to 8 digits (max 99_999_999).
            // `?` propagates the `None` (failed conversion) identically to the
            // former explicit `match ... { None => return None }`.
            let (num, p) = str_number(bytes, tok_start, 99_999_999)?;
            let num_digits = p - tok_start;
            let val = num as u32;

            if tzoff == -1
                && num_digits == 4
                && val <= 1400
                && tok_start > 0
                && (at(tok_start - 1) == b'+' || at(tok_start - 1) == b'-')
            {
                // Four digits <= 1400 preceded by '+'/'-': an RFC 822 numeric time zone. The sign
                // is the local-vs-GMT direction, so the stored offset uses the reversed math.
                found = true;
                let off = ((val / 100 * 60 + val % 100) * 60) as i32;
                tzoff = if at(tok_start - 1) == b'+' { -off } else { off };
            } else if num_digits == 8 && yearnum == -1 && monnum == -1 && mdaynum == -1 {
                // 8 digits with no date fields yet: YYYYMMDD.
                found = true;
                yearnum = (val / 10000) as i32;
                monnum = ((val % 10000) / 100) as i32 - 1; // month is 0-11
                mdaynum = (val % 100) as i32;
            }

            if !found && matches!(dignext, Assume::Mday) && mdaynum == -1 {
                if val > 0 && val < 32 {
                    mdaynum = val as i32;
                    found = true;
                }
                dignext = Assume::Year;
            }

            if !found && matches!(dignext, Assume::Year) && yearnum == -1 {
                yearnum = val as i32;
                found = true;
                if yearnum < 100 {
                    if yearnum > 70 {
                        yearnum += 1900;
                    } else {
                        yearnum += 2000;
                    }
                }
                if mdaynum == -1 {
                    dignext = Assume::Mday;
                }
            }

            if !found {
                return None; // failed to convert
            }
            pos = p;
        }

        part += 1;
    }

    if secnum == -1 {
        // no time given, make it midnight
        secnum = 0;
        minnum = 0;
        hournum = 0;
    }

    if mdaynum == -1 || monnum == -1 || yearnum == -1 {
        return None; // lacks vital info, fail
    }

    // The Gregorian calendar was introduced in 1582 (64-bit signed `time_t` path).
    if yearnum < 1583 {
        return None;
    }

    if mdaynum > 31 || monnum > 11 || hournum > 23 || minnum > 59 || secnum > 60 {
        return None; // clearly an illegal date
    }

    let t = time2epoch(secnum, minnum, hournum, mdaynum, monnum, yearnum);

    // Add the offset between the parsed zone and GMT (default GMT when none was given).
    let tzoff = if tzoff == -1 { 0 } else { tzoff };

    // Guard against `time_t` overflow at the far end of time (never reached for real dates on a
    // 64-bit `time_t`, but ported for fidelity — mapped to failure exactly as `curl_getdate` does).
    if tzoff > 0 && t > i64::MAX - i64::from(tzoff) {
        return None; // time_t overflow (PARSEDATE_LATER)
    }

    Some(t + i64::from(tzoff))
}

/// `time_t curl_getdate(const char *p, const time_t *unused);`
///
/// Parse an HTTP/RFC date string `p` into a Unix timestamp (`time_t`). Recognizes the RFC
/// 822/1123, RFC 850/1036, and ANSI C `asctime()` formats plus curl's looser variants. Returns
/// `-1` when the string cannot be parsed. The `unused` argument is a historical relic that curl
/// has always ignored, and is ignored here too.
///
/// As in `lib/parsedate.c`, a valid parse that happens to land exactly on `-1` (one second before
/// the epoch) is nudged to `0` so it is never mistaken for the failure sentinel.
#[no_mangle]
pub extern "C" fn curl_getdate(p: *const c_char, unused: *const time_t) -> time_t {
    // The legacy `unused` argument is ignored (as in curl).
    let _ = unused;

    // The parser is arithmetic-heavy; ensure no panic (e.g. a debug-mode overflow check) can
    // unwind across the FFI boundary. Any such failure collapses to curl's `-1` sentinel.
    let parsed = std::panic::catch_unwind(|| {
        // SAFETY: per the C contract `p` is null or a valid NUL-terminated string that stays
        // valid for the duration of this call; `cstr_bytes` upholds that invariant and the borrow
        // it yields does not outlive this call.
        let bytes = unsafe { cstr_bytes(p) }?;
        parsedate(bytes)
    });

    match parsed {
        Ok(Some(t)) => {
            // Avoid returning -1 for a working scenario (lib/parsedate.c).
            let t = if t == -1 { 0 } else { t };
            t as time_t
        }
        // A parse failure (`Ok(None)`) or a caught panic (`Err(_)`) both map to curl's -1.
        _ => -1,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    // No-op allocator callbacks used to exercise `curl_global_init_mem`'s non-null precondition.
    unsafe extern "C" fn cb_malloc(_size: libc::size_t) -> *mut libc::c_void {
        std::ptr::null_mut()
    }
    unsafe extern "C" fn cb_free(_ptr: *mut libc::c_void) {}
    unsafe extern "C" fn cb_realloc(
        _ptr: *mut libc::c_void,
        _size: libc::size_t,
    ) -> *mut libc::c_void {
        std::ptr::null_mut()
    }
    unsafe extern "C" fn cb_strdup(_s: *const libc::c_char) -> *mut libc::c_char {
        std::ptr::null_mut()
    }
    unsafe extern "C" fn cb_calloc(_n: libc::size_t, _s: libc::size_t) -> *mut libc::c_void {
        std::ptr::null_mut()
    }

    /// The `CURL_GLOBAL_*` flag bits are frozen and must byte-match `include/curl/curl.h`.
    #[test]
    fn global_flag_values_are_frozen() {
        assert_eq!(CURL_GLOBAL_SSL, 1 << 0);
        assert_eq!(CURL_GLOBAL_WIN32, 1 << 1);
        assert_eq!(CURL_GLOBAL_ALL, (1 << 0) | (1 << 1));
        assert_eq!(CURL_GLOBAL_NOTHING, 0);
        assert_eq!(CURL_GLOBAL_DEFAULT, CURL_GLOBAL_ALL);
        assert_eq!(CURL_GLOBAL_ACK_EINTR, 1 << 2);
    }

    /// The `CURLsslset` integer values are frozen ABI.
    #[test]
    fn curlsslset_values_are_frozen() {
        assert_eq!(CURLsslset::CURLSSLSET_OK as i32, 0);
        assert_eq!(CURLsslset::CURLSSLSET_UNKNOWN_BACKEND as i32, 1);
        assert_eq!(CURLsslset::CURLSSLSET_TOO_LATE as i32, 2);
        assert_eq!(CURLsslset::CURLSSLSET_NO_BACKENDS as i32, 3);
    }

    /// The `curl_sslbackend` discriminants are frozen ABI (spot-check the endpoints and rustls).
    #[test]
    fn curl_sslbackend_values_are_frozen() {
        assert_eq!(curl_sslbackend::CURLSSLBACKEND_NONE as i32, 0);
        assert_eq!(curl_sslbackend::CURLSSLBACKEND_OPENSSL as i32, 1);
        assert_eq!(curl_sslbackend::CURLSSLBACKEND_WOLFSSL as i32, 7);
        assert_eq!(curl_sslbackend::CURLSSLBACKEND_MBEDTLS as i32, 11);
        assert_eq!(curl_sslbackend::CURLSSLBACKEND_RUSTLS as i32, 14);
    }

    /// `curl_global_init` is idempotent and always succeeds; `curl_global_cleanup` is safe to call
    /// repeatedly (including before/after init).
    #[test]
    fn global_init_and_cleanup_are_idempotent() {
        assert_eq!(curl_global_init(CURL_GLOBAL_DEFAULT) as i32, 0);
        assert_eq!(curl_global_init(CURL_GLOBAL_ALL) as i32, 0);
        assert_eq!(curl_global_init(CURL_GLOBAL_NOTHING) as i32, 0);
        curl_global_cleanup();
        curl_global_cleanup();
        assert_eq!(curl_global_init(0) as i32, 0);
    }

    /// `curl_global_init_mem` fails when any callback is null and succeeds when all are provided;
    /// the allocators are accepted but never invoked.
    #[test]
    fn global_init_mem_enforces_nonnull_callbacks() {
        // Any null callback -> CURLE_FAILED_INIT.
        assert_eq!(
            curl_global_init_mem(0, None, None, None, None, None) as i32,
            crate::CURLcode::CURLE_FAILED_INIT as i32
        );
        assert_eq!(
            curl_global_init_mem(
                0,
                Some(cb_malloc),
                Some(cb_free),
                Some(cb_realloc),
                Some(cb_strdup),
                None // one missing
            ) as i32,
            crate::CURLcode::CURLE_FAILED_INIT as i32
        );
        // All callbacks provided -> CURLE_OK.
        assert_eq!(
            curl_global_init_mem(
                CURL_GLOBAL_DEFAULT,
                Some(cb_malloc),
                Some(cb_free),
                Some(cb_realloc),
                Some(cb_strdup),
                Some(cb_calloc)
            ) as i32,
            crate::CURLcode::CURLE_OK as i32
        );
    }

    /// `curl_global_trace` accepts null and non-null configs and always reports success.
    #[test]
    fn global_trace_accepts_configs() {
        assert_eq!(curl_global_trace(std::ptr::null()) as i32, 0);
        let cfg = CString::new("all,ids,time").unwrap();
        assert_eq!(curl_global_trace(cfg.as_ptr()) as i32, 0);
    }

    /// `curl_global_sslset` selects the single rustls backend by id and by (case-insensitive)
    /// name, rejects anything else, and publishes the availability list through `avail`.
    #[test]
    fn global_sslset_reflects_single_rustls_backend() {
        // Selection by id.
        assert_eq!(
            curl_global_sslset(
                curl_sslbackend::CURLSSLBACKEND_RUSTLS,
                std::ptr::null(),
                std::ptr::null_mut()
            ),
            CURLsslset::CURLSSLSET_OK
        );

        // Selection by case-insensitive name.
        let name = CString::new("RuStLs").unwrap();
        assert_eq!(
            curl_global_sslset(
                curl_sslbackend::CURLSSLBACKEND_NONE,
                name.as_ptr(),
                std::ptr::null_mut()
            ),
            CURLsslset::CURLSSLSET_OK
        );

        // An unknown backend id with no matching name is rejected.
        let other = CString::new("openssl").unwrap();
        assert_eq!(
            curl_global_sslset(
                curl_sslbackend::CURLSSLBACKEND_OPENSSL,
                other.as_ptr(),
                std::ptr::null_mut()
            ),
            CURLsslset::CURLSSLSET_UNKNOWN_BACKEND
        );

        // The availability list is a one-element (rustls) NUL-terminated array.
        let mut list: *mut *const curl_ssl_backend = std::ptr::null_mut();
        let r = curl_global_sslset(
            curl_sslbackend::CURLSSLBACKEND_RUSTLS,
            std::ptr::null(),
            &mut list,
        );
        assert_eq!(r, CURLsslset::CURLSSLSET_OK);
        assert!(!list.is_null());
        // SAFETY: `list` was populated by the call above to point at the static, NUL-terminated
        // backend array; reading its first two slots is in-bounds.
        unsafe {
            let first = *list;
            assert!(!first.is_null());
            let backend = &*first;
            assert_eq!(backend.id, curl_sslbackend::CURLSSLBACKEND_RUSTLS);
            assert_eq!(CStr::from_ptr(backend.name).to_str().unwrap(), "rustls");
            let second = *list.add(1);
            assert!(second.is_null());
        }
    }

    /// `curl_free` is null-safe and reclaims a library-owned string without corruption.
    #[test]
    fn free_is_null_safe_and_symmetric() {
        curl_free(std::ptr::null_mut()); // no-op
        let owned = crate::str_to_c_owned("some owned string");
        assert!(!owned.is_null());
        curl_free(owned as *mut libc::c_void); // reclaimed via CString::from_raw
    }

    /// `curl_getenv` returns a present, non-empty value and null for missing/empty/invalid input.
    #[test]
    fn getenv_matches_c_semantics() {
        std::env::set_var("CURL_RS_GLOBAL_TEST_VAR", "value-123");
        let name = CString::new("CURL_RS_GLOBAL_TEST_VAR").unwrap();
        let got = curl_getenv(name.as_ptr());
        assert!(!got.is_null());
        // SAFETY: `got` is a library-owned NUL-terminated string valid until freed below.
        let value = unsafe { CStr::from_ptr(got) }.to_str().unwrap().to_owned();
        assert_eq!(value, "value-123");
        curl_free(got as *mut libc::c_void);

        // Empty value -> null (parity with lib/getenv.c).
        std::env::set_var("CURL_RS_GLOBAL_TEST_EMPTY", "");
        let empty = CString::new("CURL_RS_GLOBAL_TEST_EMPTY").unwrap();
        assert!(curl_getenv(empty.as_ptr()).is_null());

        // Missing variable -> null.
        let missing = CString::new("CURL_RS_GLOBAL_TEST_MISSING_XYZ").unwrap();
        assert!(curl_getenv(missing.as_ptr()).is_null());

        // Null argument -> null.
        assert!(curl_getenv(std::ptr::null()).is_null());
    }

    /// `curl_strequal` is a case-insensitive ASCII compare with C null semantics.
    #[test]
    fn strequal_case_insensitive_and_null_semantics() {
        let a = CString::new("Hello").unwrap();
        let b = CString::new("hELLo").unwrap();
        let c = CString::new("world").unwrap();
        assert_ne!(curl_strequal(a.as_ptr(), b.as_ptr()), 0);
        assert_eq!(curl_strequal(a.as_ptr(), c.as_ptr()), 0);
        // Both null compare equal; a single null compares unequal.
        assert_ne!(curl_strequal(std::ptr::null(), std::ptr::null()), 0);
        assert_eq!(curl_strequal(a.as_ptr(), std::ptr::null()), 0);
        assert_eq!(curl_strequal(std::ptr::null(), a.as_ptr()), 0);
    }

    /// `curl_strnequal` compares up to `n` bytes case-insensitively with C null/length semantics.
    #[test]
    fn strnequal_prefix_and_null_semantics() {
        let a = CString::new("Hello").unwrap();
        let b = CString::new("HELLO WORLD").unwrap();
        assert_ne!(curl_strnequal(a.as_ptr(), b.as_ptr(), 5), 0); // first 5 equal
        assert_eq!(curl_strnequal(a.as_ptr(), b.as_ptr(), 6), 0); // 6th differs (end vs ' ')
        assert_ne!(curl_strnequal(a.as_ptr(), b.as_ptr(), 0), 0); // n == 0 -> equal
                                                                  // Both null: equal only when n is positive.
        assert_ne!(curl_strnequal(std::ptr::null(), std::ptr::null(), 3), 0);
        assert_eq!(curl_strnequal(std::ptr::null(), std::ptr::null(), 0), 0);
        // A single null compares unequal.
        assert_eq!(curl_strnequal(a.as_ptr(), std::ptr::null(), 3), 0);
    }

    /// `curl_escape` percent-encodes, handles empty/null/negative input, and round-trips through
    /// `curl_unescape`; both hand back caller-freeable strings.
    #[test]
    fn escape_unescape_roundtrip() {
        // Specific encoding of reserved characters.
        let raw = CString::new("a b/c").unwrap();
        let enc = curl_escape(raw.as_ptr(), 0);
        assert!(!enc.is_null());
        // SAFETY: `enc` is a library-owned NUL-terminated string valid until freed.
        let enc_str = unsafe { CStr::from_ptr(enc) }.to_str().unwrap().to_owned();
        assert_eq!(enc_str, "a%20b%2Fc");
        curl_free(enc as *mut libc::c_void);

        // Full round-trip over a mix of reserved and unreserved characters.
        let original = "Hello, World! /?&=+~-._";
        let cs = CString::new(original).unwrap();
        let enc = curl_escape(cs.as_ptr(), 0);
        assert!(!enc.is_null());
        let dec = curl_unescape(enc, 0);
        assert!(!dec.is_null());
        // SAFETY: `dec` is a library-owned NUL-terminated string valid until freed.
        let dec_str = unsafe { CStr::from_ptr(dec) }.to_str().unwrap().to_owned();
        assert_eq!(dec_str, original);
        curl_free(enc as *mut libc::c_void);
        curl_free(dec as *mut libc::c_void);

        // Empty input escapes to an allocated empty string (not null).
        let empty = CString::new("").unwrap();
        let enc_empty = curl_escape(empty.as_ptr(), 0);
        assert!(!enc_empty.is_null());
        // SAFETY: owned empty string valid until freed.
        assert_eq!(unsafe { CStr::from_ptr(enc_empty) }.to_bytes(), b"");
        curl_free(enc_empty as *mut libc::c_void);

        // Null input or a negative length -> null.
        assert!(curl_escape(std::ptr::null(), 0).is_null());
        assert!(curl_escape(cs.as_ptr(), -1).is_null());
        assert!(curl_unescape(std::ptr::null(), 0).is_null());
        assert!(curl_unescape(cs.as_ptr(), -1).is_null());
    }

    /// `curl_escape` honours an explicit positive length (permitting data past it to be ignored).
    #[test]
    fn escape_respects_explicit_length() {
        let raw = CString::new("ab cd").unwrap();
        // Only encode the first two bytes ("ab").
        let enc = curl_escape(raw.as_ptr(), 2);
        assert!(!enc.is_null());
        // SAFETY: owned NUL-terminated string valid until freed.
        let enc_str = unsafe { CStr::from_ptr(enc) }.to_str().unwrap().to_owned();
        assert_eq!(enc_str, "ab");
        curl_free(enc as *mut libc::c_void);
    }

    /// `curl_getdate` parses the three canonical HTTP date formats to the same instant.
    #[test]
    fn getdate_canonical_formats() {
        const EXPECTED: time_t = 784_111_777; // Sun, 06 Nov 1994 08:49:37 GMT
        let rfc1123 = CString::new("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        let rfc850 = CString::new("Sunday, 06-Nov-94 08:49:37 GMT").unwrap();
        let asctime = CString::new("Sun Nov  6 08:49:37 1994").unwrap();
        assert_eq!(curl_getdate(rfc1123.as_ptr(), std::ptr::null()), EXPECTED);
        assert_eq!(curl_getdate(rfc850.as_ptr(), std::ptr::null()), EXPECTED);
        assert_eq!(curl_getdate(asctime.as_ptr(), std::ptr::null()), EXPECTED);
    }

    /// `curl_getdate` handles the epoch, the -1 nudge, numeric time zones, and failures.
    #[test]
    fn getdate_edge_cases() {
        // Unix epoch.
        let epoch = CString::new("Thu, 01 Jan 1970 00:00:00 GMT").unwrap();
        assert_eq!(curl_getdate(epoch.as_ptr(), std::ptr::null()), 0);

        // One second before the epoch computes to -1, which is nudged to 0.
        let minus_one = CString::new("Wed, 31 Dec 1969 23:59:59 GMT").unwrap();
        assert_eq!(curl_getdate(minus_one.as_ptr(), std::ptr::null()), 0);

        // A numeric time zone matches the equivalent GMT time.
        let with_tz = CString::new("Sat, 11 Sep 2004 21:32:11 +0200").unwrap();
        let as_gmt = CString::new("Sat, 11 Sep 2004 19:32:11 GMT").unwrap();
        assert_eq!(
            curl_getdate(with_tz.as_ptr(), std::ptr::null()),
            curl_getdate(as_gmt.as_ptr(), std::ptr::null())
        );

        // Compact numerical form (YYYYMMDD) with a time.
        let compact = CString::new("20040911 19:32:11 GMT").unwrap();
        assert_eq!(
            curl_getdate(compact.as_ptr(), std::ptr::null()),
            curl_getdate(as_gmt.as_ptr(), std::ptr::null())
        );

        // Unparseable strings and null both yield -1.
        let bad = CString::new("not a date at all").unwrap();
        assert_eq!(curl_getdate(bad.as_ptr(), std::ptr::null()), -1);
        assert_eq!(curl_getdate(std::ptr::null(), std::ptr::null()), -1);

        // A pre-Gregorian year fails on the 64-bit path.
        let ancient = CString::new("Mon, 06 Nov 1500 08:49:37 GMT").unwrap();
        assert_eq!(curl_getdate(ancient.as_ptr(), std::ptr::null()), -1);
    }
}
