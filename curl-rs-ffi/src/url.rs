//! The public `curl_url_*` URL-API C ABI (`curl_url`, `curl_url_cleanup`,
//! `curl_url_dup`, `curl_url_get`, `curl_url_set`, `curl_url_strerror`).
//!
//! This module implements libcurl's **six** exported URL-API symbols
//! (`include/curl/urlapi.h`, all six listed in `lib/libcurl.def`) directly over
//! the safe core URL handle [`curl_rs_lib::url::CurlUrl`] (the memory-safe
//! reimplementation of curl's opaque `struct Curl_URL`). The behavioral and ABI
//! oracle is `lib/urlapi.c` together with the `CURLUcode` / `CURLUPart` /
//! `CURLU_*` declarations of `include/curl/urlapi.h` (Agent Action Plan
//! §0.5.1).
//!
//! | C symbol            | Rust core method                       |
//! |---------------------|----------------------------------------|
//! | `curl_url`          | [`core::url::CurlUrl::new`]             |
//! | `curl_url_cleanup`  | [`Drop`] (via `Box::from_raw`)         |
//! | `curl_url_dup`      | [`core::url::CurlUrl::dup`]             |
//! | `curl_url_get`      | [`core::url::CurlUrl::get`]             |
//! | `curl_url_set`      | [`core::url::CurlUrl::set`]             |
//! | `curl_url_strerror` | [`crate::error_codes::url_strerror`]   |
//!
//! # Opaque handle and memory ownership
//!
//! C sees the URL handle as the opaque `typedef struct Curl_URL CURLU;`
//! ([`crate::types::CURLU`]). The implementation places a heap-allocated
//! [`core::url::CurlUrl`] behind that pointer with [`Box::into_raw`] in
//! [`curl_url`] / [`curl_url_dup`] and reclaims it with [`Box::from_raw`] in
//! [`curl_url_cleanup`], so curl's ownership contract — "anything allocated by
//! Rust is freed by Rust", every handle freed exactly once and never with the C
//! `free` — is upheld by construction (AAP §0.7.1). Dropping the `Box` runs the
//! safe core's deterministic teardown (the `String`/`Vec` fields of `CurlUrl`),
//! the memory-safe replacement for curl's `free_urlhandle`.
//!
//! # The `curl_url_get` heap-string contract
//!
//! `curl_url_get` writes a **newly allocated** C string to `*part` that is
//! **owned by the caller**, who must release it with [`curl_free`] (not the C
//! `free`), exactly as `include/curl/urlapi.h` documents. To satisfy the
//! crate-wide C-heap contract (owned by `global.rs`), the buffer is allocated
//! through [`crate::global::c_strdup_str`] (`libc::malloc` + NUL terminator), so
//! [`curl_free`]'s `libc::free` reclaims it. A `NULL` return from that helper
//! denotes allocation failure and is surfaced to the caller as
//! `CURLUE_OUT_OF_MEMORY`, matching curl's `if(!*part) return
//! CURLUE_OUT_OF_MEMORY;`.
//!
//! [`curl_free`]: crate::global::curl_free
//!
//! # `CURLUPart` mapping
//!
//! The C `CURLUPart` argument is an `int` ([`crate::types::CURLUPart`]). The
//! safe core models the part as the typed, exhaustive
//! [`core::url::CurlUPart`] enum (discriminants `0..=10`, matching
//! `include/curl/urlapi.h`). [`int_to_part`] maps the raw integer to that enum;
//! an out-of-range value yields `None`, which both [`curl_url_get`] and
//! [`curl_url_set`] report as `CURLUE_UNKNOWN_PART` — exactly the result curl's
//! `switch(what) { … default: … }` produces for an unknown part.
//!
//! # `CURLU_*` flags
//!
//! The `unsigned int flags` bitmask (`CURLU_URLENCODE`, `CURLU_URLDECODE`,
//! `CURLU_DEFAULT_PORT`, `CURLU_PUNYCODE`, …) is passed through verbatim to the
//! core's `get` / `set`: the core defines its `CURLU_*` constants with the same
//! bit values as `include/curl/urlapi.h` and inspects them directly, so no
//! per-bit translation is required at this boundary (`c_uint` is `u32` on every
//! target in the matrix).
//!
//! # Memory safety
//!
//! `curl-rs-ffi` is the only crate permitted `unsafe`. Every `unsafe` operation
//! here sits in an explicit `unsafe { … }` block carrying a `// SAFETY:`
//! comment (the crate denies `unsafe_op_in_unsafe_fn`), and every exported
//! `unsafe extern "C"` entry point documents its preconditions under a
//! `# Safety` section. The non-pointer entry points ([`curl_url`],
//! [`curl_url_strerror`]) are ordinary safe `extern "C"` functions.

// Per the crate-wide FFI invariant, the safe async core is reached through the
// `core` alias (AAP prescribes `use curl_rs_lib as core;`). Because that alias
// shadows the standard `core` crate inside this module, every C primitive type
// is taken from `std::ffi` below (never `core::ffi`), mirroring `global.rs` /
// `share.rs`.
use curl_rs_lib as core;

use std::ffi::{c_char, c_uint, CStr};

use crate::error_codes::{result_to_ucode, url_strerror, CURLUcode};
use crate::global::c_strdup_str;
use crate::types::{CURLUPart, CURLU};

// =============================================================================
// CURLUPart selector mapping (include/curl/urlapi.h)
// =============================================================================

/// Map a raw C `CURLUPart` integer to the typed core [`core::url::CurlUPart`].
///
/// The discriminants are fixed by `include/curl/urlapi.h`
/// (`CURLUPART_URL = 0` … `CURLUPART_ZONEID = 10`) and reproduced by the core
/// enum, so this is a direct 1:1 translation. Any value outside `0..=10`
/// returns `None`; both [`curl_url_get`] and [`curl_url_set`] turn that into
/// `CURLUE_UNKNOWN_PART`, matching the `default:` arm of curl's per-part
/// `switch(what)` in `lib/urlapi.c`.
///
/// An explicit `match` (rather than a `transmute`) is used deliberately:
/// [`core::url::CurlUPart`] carries explicit discriminants but no `#[repr(i32)]`
/// attribute, so its in-memory layout is not guaranteed to equal the integer,
/// and transmuting an out-of-range value would be undefined behavior. The
/// `match` is both sound and total.
#[inline]
fn int_to_part(what: CURLUPart) -> Option<core::url::CurlUPart> {
    use core::url::CurlUPart;
    // The integer literals are the `CURLUPART_*` values from
    // `include/curl/urlapi.h`; the compile-time agreement is exercised by the
    // `int_to_part_matches_header` unit test below.
    match what {
        0 => Some(CurlUPart::Url),
        1 => Some(CurlUPart::Scheme),
        2 => Some(CurlUPart::User),
        3 => Some(CurlUPart::Password),
        4 => Some(CurlUPart::Options),
        5 => Some(CurlUPart::Host),
        6 => Some(CurlUPart::Port),
        7 => Some(CurlUPart::Path),
        8 => Some(CurlUPart::Query),
        9 => Some(CurlUPart::Fragment),
        10 => Some(CurlUPart::ZoneId),
        _ => None,
    }
}

// =============================================================================
// Exported symbol 1 / 6 — curl_url
// =============================================================================

/// Create a new URL handle (`curl_url`).
///
/// Allocates a fresh, empty [`core::url::CurlUrl`] on the heap and returns it as
/// an opaque `CURLU *`. The returned handle must eventually be released with
/// [`curl_url_cleanup`]. Strings later returned by [`curl_url_get`] are owned
/// separately by the caller and are **not** freed by `curl_url_cleanup` (they
/// are released with [`curl_free`], matching curl's documented contract).
///
/// [`curl_free`]: crate::global::curl_free
///
/// Unlike the C `curl_url`, which returns `NULL` on an allocation failure, the
/// Rust global allocator aborts the process on out-of-memory, so this
/// constructor is effectively infallible; the `NULL`-return path is retained in
/// the contract only for ABI compatibility and is not reachable in practice.
///
/// This entry point performs no `unsafe` operations and has no preconditions, so
/// it is a safe `extern "C"` function (the `unsafe` keyword on a Rust definition
/// would affect only Rust callers; C callers are unaffected either way).
#[no_mangle]
pub extern "C" fn curl_url() -> *mut CURLU {
    // `Box::new` heap-allocates the core `CurlUrl`; `Box::into_raw` leaks it to a
    // raw pointer whose ownership now rests with the caller until it is handed
    // back to `curl_url_cleanup`. The `*mut CurlUrl -> *mut CURLU` cast is a
    // plain thin-pointer reinterpretation (`CURLU` is an opaque tag type).
    Box::into_raw(Box::new(core::url::CurlUrl::new())) as *mut CURLU
}

// =============================================================================
// Exported symbol 2 / 6 — curl_url_cleanup
// =============================================================================

/// Destroy a URL handle (`curl_url_cleanup`).
///
/// Reclaims the [`core::url::CurlUrl`] behind `handle` and drops it, running the
/// safe core's deterministic teardown of every owned component (the memory-safe
/// equivalent of curl's `free_urlhandle` + `free`). A `NULL` `handle` is a
/// no-op, matching curl's `if(u) { … }` guard.
///
/// As curl documents, this does **not** free strings previously returned by
/// [`curl_url_get`]; those remain owned by the caller and are released with
/// [`curl_free`].
///
/// [`curl_free`]: crate::global::curl_free
///
/// # Safety
///
/// `handle` must be `NULL`, or a valid `CURLU *` previously returned by
/// [`curl_url`] or [`curl_url_dup`] and not yet passed to `curl_url_cleanup`
/// (the allocation is freed here, so a second cleanup of the same handle is a
/// double-free). The handle must not be used after this call returns.
#[no_mangle]
pub unsafe extern "C" fn curl_url_cleanup(handle: *mut CURLU) {
    // C: `if(u) { free_urlhandle(u); curlx_free(u); }` — a NULL handle is a
    // no-op.
    if handle.is_null() {
        return;
    }
    // SAFETY: per the `# Safety` contract `handle` is non-null and was produced
    // by `curl_url` / `curl_url_dup` (`Box::into_raw` of a `core::url::CurlUrl`)
    // and not yet freed, so reclaiming the unique owning `Box` is sound.
    // Dropping it runs the deterministic teardown of every owned field and frees
    // the allocation exactly once.
    drop(unsafe { Box::from_raw(handle as *mut core::url::CurlUrl) });
}

// =============================================================================
// Exported symbol 3 / 6 — curl_url_dup
// =============================================================================

/// Duplicate a URL handle (`curl_url_dup`).
///
/// Returns a new, independent `CURLU *` that is a deep copy of `input`. A `NULL`
/// `input` yields `NULL`. The new handle must also be released with
/// [`curl_url_cleanup`].
///
/// The copy reproduces `lib/urlapi.c`'s `curl_url_dup` exactly: every owned
/// component (scheme, user, password, options, host, port, path, query,
/// fragment, zoneid) plus `portnum` and the query/fragment "present" bits is
/// copied, while the `guessed_scheme` bit is **not** carried over (curl's
/// `curl_url_dup` allocates with `calloc` and never copies it). This is
/// precisely the behavior of the core [`core::url::CurlUrl::dup`] method — which
/// is therefore used here in preference to a plain `Clone`, so a duplicated
/// handle renders its `scheme://` prefix even under `CURLU_NO_GUESS_SCHEME`,
/// matching curl.
///
/// # Safety
///
/// `input` must be `NULL`, or a valid `CURLU *` previously returned by
/// [`curl_url`] or [`curl_url_dup`] and not yet passed to [`curl_url_cleanup`].
/// It is only read (a shared borrow) for the duration of the call and is left
/// untouched; ownership of the returned handle transfers to the caller.
#[no_mangle]
pub unsafe extern "C" fn curl_url_dup(input: *const CURLU) -> *mut CURLU {
    // C: `curl_url_dup(NULL)` is not special-cased in curl (it would crash), but
    // libcurl callers never pass NULL here; we defensively return NULL, which is
    // strictly safer and observationally indistinguishable for valid callers.
    if input.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: per the `# Safety` contract `input` is non-null and points to a
    // live `core::url::CurlUrl` produced by `curl_url` / `curl_url_dup`. We take
    // only a shared (`&`) borrow to call `dup`, which deep-copies the handle; no
    // `&mut` alias can exist for the call duration.
    let dup = unsafe { (*(input as *const core::url::CurlUrl)).dup() };
    // Box + leak the independent copy to a fresh owning raw pointer.
    Box::into_raw(Box::new(dup)) as *mut CURLU
}

// =============================================================================
// Exported symbol 4 / 6 — curl_url_get
// =============================================================================

/// Extract a component of the URL (`curl_url_get`).
///
/// Reads the `what` component from `handle`, applies the `CURLU_*` `flags`
/// (decode/encode, default-port, punycode, …), and writes a **newly allocated**
/// C string to `*part`. The returned string is **owned by the caller** and must
/// be freed with [`curl_free`] (never the C `free`); see the module-level
/// heap-string contract.
///
/// [`curl_free`]: crate::global::curl_free
///
/// All per-component behavior — the missing-component errors
/// (`CURLUE_NO_SCHEME`, `CURLUE_NO_HOST`, `CURLUE_NO_PORT`, `CURLUE_NO_QUERY`,
/// …), the `CURLUPART_PORT` default-port / no-default-port handling, the
/// `CURLUPART_PATH` `"/"` default, the blank-query / blank-fragment
/// `CURLU_GET_EMPTY` rules, the `CURLU_NO_GUESS_SCHEME` scheme suppression, and
/// the URL-decode / URL-encode / punycode transforms — is implemented by the
/// safe core [`core::url::CurlUrl::get`], faithfully mirroring `lib/urlapi.c`.
/// This shim adds only the C-ABI concerns: argument validation, the
/// integer→[`core::url::CurlUPart`] mapping, the caller-owned allocation, and
/// the out-of-memory signal.
///
/// # Return values (mirrors `lib/urlapi.c`)
///
/// * `CURLUE_BAD_HANDLE` — `handle` is `NULL`.
/// * `CURLUE_BAD_PARTPOINTER` — `part` is `NULL`.
/// * `CURLUE_UNKNOWN_PART` — `what` is outside `0..=10`.
/// * `CURLUE_NO_*` — the requested component is absent.
/// * `CURLUE_OUT_OF_MEMORY` — the result string could not be allocated.
/// * other `CURLUE_*` — a flag transform failed (e.g. `CURLUE_URLDECODE`,
///   `CURLUE_BAD_HOSTNAME`, `CURLUE_LACKS_IDN`).
/// * `CURLUE_OK` — success; `*part` holds the new string.
///
/// # Safety
///
/// `handle` must be `NULL`, or a valid `CURLU *` from [`curl_url`] /
/// [`curl_url_dup`] not yet cleaned up. `part` must be `NULL`, or a valid,
/// writable `char **` (the pointed-to `char *` is overwritten — first with
/// `NULL`, then, on success, with the new allocation). The handle is only read
/// (a shared borrow) for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_url_get(
    handle: *const CURLU,
    what: CURLUPart,
    part: *mut *mut c_char,
    flags: c_uint,
) -> CURLUcode {
    // C: `if(!u) return CURLUE_BAD_HANDLE;`
    if handle.is_null() {
        return CURLUcode::CURLUE_BAD_HANDLE;
    }
    // C: `if(!part) return CURLUE_BAD_PARTPOINTER;`
    if part.is_null() {
        return CURLUcode::CURLUE_BAD_PARTPOINTER;
    }

    // C: `*part = NULL;` — clear the out-parameter up front so the caller never
    // observes a stale pointer on any error path.
    // SAFETY: per the `# Safety` contract `part` is a valid, writable `char **`,
    // so writing through it is in bounds and well-aligned.
    unsafe {
        *part = std::ptr::null_mut();
    }

    // Map the C integer to the typed part; an unknown part yields the same
    // `CURLUE_UNKNOWN_PART` curl's `switch` `default:` arm returns.
    let Some(part_tag) = int_to_part(what) else {
        return CURLUcode::CURLUE_UNKNOWN_PART;
    };

    // SAFETY: per the `# Safety` contract `handle` is non-null and points to a
    // live `core::url::CurlUrl` produced by `curl_url` / `curl_url_dup`. A shared
    // (`&`) borrow is sound; no `&mut` alias can exist for the call duration.
    let url: &core::url::CurlUrl = unsafe { &*(handle as *const core::url::CurlUrl) };

    // `c_uint` is `u32` on every target in the matrix, so `flags` is passed
    // through unchanged; the core inspects the identical `CURLU_*` bit values.
    match url.get(part_tag, flags) {
        Ok(value) => {
            // Allocate a caller-owned C string for the component value through
            // the crate-wide heap contract (`libc::malloc`), so the caller frees
            // it with `curl_free`.
            // SAFETY: `c_strdup_str` copies `value`'s bytes into a freshly
            // `libc::malloc`'d, NUL-terminated buffer and transfers ownership to
            // us; it returns NULL only on allocation failure, handled next.
            let allocated = unsafe { c_strdup_str(&value) };
            if allocated.is_null() {
                // C: `if(!*part) return CURLUE_OUT_OF_MEMORY;`
                return CURLUcode::CURLUE_OUT_OF_MEMORY;
            }
            // SAFETY: `part` is a valid, writable `char **` (checked non-null
            // above); store the owning pointer for the caller to reclaim with
            // `curl_free`.
            unsafe {
                *part = allocated;
            }
            CURLUcode::CURLUE_OK
        }
        // Map the typed URL error to its exact `CURLUcode` integer.
        Err(e) => CURLUcode::from(e),
    }
}

// =============================================================================
// Exported symbol 5 / 6 — curl_url_set
// =============================================================================

/// Set (or clear) a component of the URL (`curl_url_set`).
///
/// Sets the `what` component of `handle` to `part`, applying the `CURLU_*`
/// `flags` (`CURLU_URLENCODE`, `CURLU_APPENDQUERY`, `CURLU_NON_SUPPORT_SCHEME`,
/// `CURLU_GUESS_SCHEME`, `CURLU_DEFAULT_SCHEME`, `CURLU_NO_AUTHORITY`,
/// `CURLU_PATH_AS_IS`, `CURLU_ALLOW_SPACE`, `CURLU_PUNYCODE`, `CURLU_PUNY2IDN`,
/// …). The passed-in string is **copied**; passing `NULL` for `part` **clears**
/// that component (curl's "Passing a NULL instead of a part string, clears that
/// part").
///
/// All per-component behavior — scheme validation (known scheme, or
/// syntactically valid under `CURLU_NON_SUPPORT_SCHEME`), the host / IPv6 /
/// zone-id handling, decimal port validation, the path leading-slash rule, the
/// `CURLU_APPENDQUERY` join, and whole-`CURLUPART_URL` absolute-parse /
/// relative-resolve — is implemented by the safe core
/// [`core::url::CurlUrl::set`], faithfully mirroring `lib/urlapi.c`. This shim
/// adds only the C-ABI concerns: argument validation, the
/// integer→[`core::url::CurlUPart`] mapping, and the `NULL`-clears semantics.
///
/// # Return values (mirrors `lib/urlapi.c`)
///
/// * `CURLUE_BAD_HANDLE` — `handle` is `NULL`.
/// * `CURLUE_UNKNOWN_PART` — `what` is outside `0..=10`.
/// * `CURLUE_MALFORMED_INPUT` — input exceeds `CURL_MAX_INPUT_LENGTH`, or (a
///   documented design consequence of the core's UTF-8 component model) the raw
///   bytes are not valid UTF-8. Percent-encoded input is ASCII and is therefore
///   unaffected; only a literal non-UTF-8 byte in the argument triggers this,
///   which curl would reject downstream regardless.
/// * `CURLUE_BAD_SCHEME` / `CURLUE_UNSUPPORTED_SCHEME` / `CURLUE_BAD_PORT_NUMBER`
///   / `CURLUE_BAD_HOSTNAME` / … — a per-component validation failed.
/// * `CURLUE_OK` — success.
///
/// # Safety
///
/// `handle` must be `NULL`, or a valid `CURLU *` from [`curl_url`] /
/// [`curl_url_dup`] not yet cleaned up. `part` must be `NULL`, or a valid,
/// NUL-terminated C string that stays valid for the duration of the call (its
/// contents are copied, so it may be freed by the caller afterwards). The handle
/// is mutated through an exclusive borrow; as with curl, a single handle must
/// not be used concurrently from multiple threads.
#[no_mangle]
pub unsafe extern "C" fn curl_url_set(
    handle: *mut CURLU,
    what: CURLUPart,
    part: *const c_char,
    flags: c_uint,
) -> CURLUcode {
    // C: `if(!u) return CURLUE_BAD_HANDLE;`
    if handle.is_null() {
        return CURLUcode::CURLUE_BAD_HANDLE;
    }

    // Map the C integer to the typed part. curl reaches `CURLUE_UNKNOWN_PART`
    // through both `urlset_clear`'s `default:` arm (NULL `part`) and the main
    // `switch`'s `default:` arm (non-NULL `part`); validating once here yields
    // the same code for every realistic input. (The sole micro-divergence — an
    // unknown part combined with an over-`CURL_MAX_INPUT_LENGTH` string would
    // report `CURLUE_UNKNOWN_PART` here vs. `CURLUE_MALFORMED_INPUT` in C — is
    // an untested pathological corner.)
    let Some(part_tag) = int_to_part(what) else {
        return CURLUcode::CURLUE_UNKNOWN_PART;
    };

    // SAFETY: per the `# Safety` contract `handle` is non-null and points to a
    // live `core::url::CurlUrl` produced by `curl_url` / `curl_url_dup`. The
    // exclusive (`&mut`) borrow is sound: the C URL-API contract is
    // single-threaded per handle (as in curl), so no aliasing borrow exists for
    // the call duration.
    let url: &mut core::url::CurlUrl = unsafe { &mut *(handle as *mut core::url::CurlUrl) };

    // C: `if(!part) return urlset_clear(u, what);` — a NULL value clears the
    // component. The core's `set(_, None, _)` calls its `urlset_clear` and
    // returns `Ok(())`.
    if part.is_null() {
        return result_to_ucode(url.set(part_tag, None, flags));
    }

    // SAFETY: per the `# Safety` contract `part` is a valid, NUL-terminated C
    // string that remains valid for the duration of this call, so borrowing it
    // as a `CStr` is sound.
    let raw = unsafe { CStr::from_ptr(part) };

    // The core models components as UTF-8 `String`s (a documented divergence
    // from curl's raw-byte storage). Percent-encoded input is plain ASCII and
    // converts cleanly; only a literal non-UTF-8 byte fails here, which curl
    // would reject downstream anyway — reported as `CURLUE_MALFORMED_INPUT`.
    let value = match raw.to_str() {
        Ok(s) => s,
        Err(_) => return CURLUcode::CURLUE_MALFORMED_INPUT,
    };

    // Apply the component (the core performs the length check, per-part
    // validation, and flag-driven encoding); collapse the typed result to the
    // exact `CURLUcode`.
    result_to_ucode(url.set(part_tag, Some(value), flags))
}

// =============================================================================
// Exported symbol 6 / 6 — curl_url_strerror
// =============================================================================

/// Return a human-readable string for a `CURLUcode` (`curl_url_strerror`).
///
/// The returned pointer references a `'static`, read-only, NUL-terminated string
/// (sourced from the shared [`url_strerror`] table, byte-for-byte from
/// `lib/strerror.c`'s `curl_url_strerror`) that is **never freed**; the caller
/// must not pass it to `free` / `curl_free`. No allocation is performed,
/// matching curl, which returns string literals. An out-of-range `code` maps to
/// the catch-all `"CURLUcode unknown"` string.
///
/// # Safety
///
/// This function performs no pointer dereferences and is sound for every value
/// of `code`. It is declared `unsafe extern "C"` only to match curl's published
/// FFI surface (mirroring the sibling `curl_share_strerror` /
/// `curl_easy_strerror`); callers must nonetheless treat the returned pointer as
/// borrowed `'static` data and must not free or mutate it.
#[no_mangle]
pub unsafe extern "C" fn curl_url_strerror(code: CURLUcode) -> *const c_char {
    url_strerror(code)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    // `super::*` re-imports the parent's items, including the `core` alias
    // (= `curl_rs_lib`) and the `c_char` / `CStr` C primitives the parent
    // imports. A glob, however, brings `core` in only at glob priority, which is
    // ambiguous against the built-in `core` crate from the extern prelude; an
    // explicit re-import pins `core` to the alias unambiguously (mirrors the
    // sibling `share.rs` test, which roots its core paths at `super::core`).
    use super::core;
    use std::ffi::{c_void, CString};
    use std::ptr;

    // The `CURLUPART_*` selector integers from `include/curl/urlapi.h`, used as
    // the raw `what` argument exactly as a C caller would pass them.
    const PART_URL: CURLUPart = 0;
    const PART_SCHEME: CURLUPart = 1;
    const PART_USER: CURLUPart = 2;
    const PART_PASSWORD: CURLUPart = 3;
    const PART_OPTIONS: CURLUPart = 4;
    const PART_HOST: CURLUPart = 5;
    const PART_PORT: CURLUPart = 6;
    const PART_PATH: CURLUPart = 7;
    const PART_QUERY: CURLUPart = 8;
    const PART_FRAGMENT: CURLUPart = 9;
    const PART_ZONEID: CURLUPart = 10;

    // --- helpers ------------------------------------------------------------

    /// Set a component from a Rust `&str` (test-only convenience).
    ///
    /// Builds an owned `CString` that outlives the call, so the `*const c_char`
    /// handed to `curl_url_set` is never dangling (the value is copied by the
    /// setter). `u` must be a live handle from [`curl_url`].
    fn set_part(u: *mut CURLU, what: CURLUPart, val: &str, flags: c_uint) -> CURLUcode {
        let c = CString::new(val).expect("no interior NUL in test input");
        // SAFETY: `u` is a live handle from `curl_url`; `c.as_ptr()` is a valid,
        // NUL-terminated C string valid for the duration of the call.
        unsafe { curl_url_set(u, what, c.as_ptr(), flags) }
    }

    /// Get a component as an owned Rust `String`, freeing the returned C buffer
    /// with `curl_free` (exercising the full heap-string ownership contract).
    /// Returns the error code on failure. `u` must be a live handle.
    fn get_part(u: *const CURLU, what: CURLUPart, flags: c_uint) -> Result<String, CURLUcode> {
        let mut part: *mut c_char = ptr::null_mut();
        // SAFETY: `u` is a live handle; `&mut part` is a valid, writable
        // `char **` out-parameter.
        let rc = unsafe { curl_url_get(u, what, &mut part, flags) };
        if rc != CURLUcode::CURLUE_OK {
            // On any non-OK result `curl_url_get` leaves `*part` NULL, so there
            // is nothing to free.
            assert!(part.is_null());
            return Err(rc);
        }
        assert!(!part.is_null(), "CURLUE_OK must yield a non-null string");
        // SAFETY: on success `part` is a non-null, NUL-terminated C string this
        // call owns (allocated by `curl_url_get` via the crate heap helper).
        let s = unsafe { CStr::from_ptr(part) }
            .to_str()
            .expect("URL components produced by the core are valid UTF-8")
            .to_owned();
        // SAFETY: `part` was allocated by `curl_url_get` through the crate-wide
        // `libc::malloc` contract, so `curl_free` (`libc::free`) reclaims it
        // exactly once.
        unsafe { crate::global::curl_free(part.cast::<c_void>()) };
        Ok(s)
    }

    // --- lifecycle ----------------------------------------------------------

    #[test]
    fn url_init_returns_nonnull_and_cleanup() {
        let u = curl_url();
        assert!(!u.is_null(), "curl_url must return a non-null handle");
        // SAFETY: `u` is a live handle from `curl_url`, freed exactly once.
        unsafe { curl_url_cleanup(u) };
        // A NULL cleanup is a no-op (must not crash).
        // SAFETY: NULL is an explicitly supported no-op input.
        unsafe { curl_url_cleanup(ptr::null_mut()) };
    }

    #[test]
    fn int_to_part_matches_header() {
        use core::url::CurlUPart;
        assert_eq!(int_to_part(PART_URL), Some(CurlUPart::Url));
        assert_eq!(int_to_part(PART_SCHEME), Some(CurlUPart::Scheme));
        assert_eq!(int_to_part(PART_USER), Some(CurlUPart::User));
        assert_eq!(int_to_part(PART_PASSWORD), Some(CurlUPart::Password));
        assert_eq!(int_to_part(PART_OPTIONS), Some(CurlUPart::Options));
        assert_eq!(int_to_part(PART_HOST), Some(CurlUPart::Host));
        assert_eq!(int_to_part(PART_PORT), Some(CurlUPart::Port));
        assert_eq!(int_to_part(PART_PATH), Some(CurlUPart::Path));
        assert_eq!(int_to_part(PART_QUERY), Some(CurlUPart::Query));
        assert_eq!(int_to_part(PART_FRAGMENT), Some(CurlUPart::Fragment));
        assert_eq!(int_to_part(PART_ZONEID), Some(CurlUPart::ZoneId));
        // Out-of-range values map to None (→ CURLUE_UNKNOWN_PART).
        assert_eq!(int_to_part(11), None);
        assert_eq!(int_to_part(-1), None);
        assert_eq!(int_to_part(99), None);
    }

    // --- set whole URL, then read every component back ----------------------

    #[test]
    fn set_url_then_get_components() {
        let u = curl_url();
        let full = "https://user:pass@example.com:8080/path/to?a=b&c=d#frag";
        assert_eq!(set_part(u, PART_URL, full, 0), CURLUcode::CURLUE_OK);

        assert_eq!(get_part(u, PART_SCHEME, 0).unwrap(), "https");
        assert_eq!(get_part(u, PART_USER, 0).unwrap(), "user");
        assert_eq!(get_part(u, PART_PASSWORD, 0).unwrap(), "pass");
        assert_eq!(get_part(u, PART_HOST, 0).unwrap(), "example.com");
        assert_eq!(get_part(u, PART_PORT, 0).unwrap(), "8080");
        assert_eq!(get_part(u, PART_PATH, 0).unwrap(), "/path/to");
        assert_eq!(get_part(u, PART_QUERY, 0).unwrap(), "a=b&c=d");
        assert_eq!(get_part(u, PART_FRAGMENT, 0).unwrap(), "frag");

        // The whole URL round-trips byte-for-byte.
        assert_eq!(get_part(u, PART_URL, 0).unwrap(), full);

        // SAFETY: live handle, freed once.
        unsafe { curl_url_cleanup(u) };
    }

    // --- argument validation / error codes ----------------------------------

    #[test]
    fn get_argument_validation() {
        // NULL handle → CURLUE_BAD_HANDLE.
        let mut part: *mut c_char = ptr::null_mut();
        // SAFETY: NULL handle is a validated input; `&mut part` is writable.
        let rc = unsafe { curl_url_get(ptr::null(), PART_SCHEME, &mut part, 0) };
        assert_eq!(rc, CURLUcode::CURLUE_BAD_HANDLE);
        assert!(part.is_null());

        let u = curl_url();
        assert_eq!(
            set_part(u, PART_URL, "https://example.com/", 0),
            CURLUcode::CURLUE_OK
        );

        // NULL part pointer → CURLUE_BAD_PARTPOINTER.
        // SAFETY: live handle; NULL out-pointer is a validated input.
        let rc = unsafe { curl_url_get(u, PART_SCHEME, ptr::null_mut(), 0) };
        assert_eq!(rc, CURLUcode::CURLUE_BAD_PARTPOINTER);

        // Out-of-range part → CURLUE_UNKNOWN_PART.
        // SAFETY: live handle; `&mut part` writable.
        let rc = unsafe { curl_url_get(u, 99, &mut part, 0) };
        assert_eq!(rc, CURLUcode::CURLUE_UNKNOWN_PART);
        assert!(part.is_null());

        // Absent component → the matching CURLUE_NO_* code.
        assert_eq!(
            get_part(u, PART_QUERY, 0).unwrap_err(),
            CURLUcode::CURLUE_NO_QUERY
        );
        assert_eq!(
            get_part(u, PART_FRAGMENT, 0).unwrap_err(),
            CURLUcode::CURLUE_NO_FRAGMENT
        );
        assert_eq!(
            get_part(u, PART_USER, 0).unwrap_err(),
            CURLUcode::CURLUE_NO_USER
        );

        // SAFETY: live handle, freed once.
        unsafe { curl_url_cleanup(u) };
    }

    #[test]
    fn set_argument_validation() {
        let scheme = CString::new("https").unwrap();

        // NULL handle → CURLUE_BAD_HANDLE.
        // SAFETY: NULL handle is a validated input; `scheme` outlives the call.
        let rc = unsafe { curl_url_set(ptr::null_mut(), PART_SCHEME, scheme.as_ptr(), 0) };
        assert_eq!(rc, CURLUcode::CURLUE_BAD_HANDLE);

        let u = curl_url();

        // Out-of-range part → CURLUE_UNKNOWN_PART (non-NULL value).
        // SAFETY: live handle; `scheme` outlives the call.
        let rc = unsafe { curl_url_set(u, 99, scheme.as_ptr(), 0) };
        assert_eq!(rc, CURLUcode::CURLUE_UNKNOWN_PART);

        // Out-of-range part → CURLUE_UNKNOWN_PART (NULL value / clear path too).
        // SAFETY: live handle; NULL value is the documented "clear" input.
        let rc = unsafe { curl_url_set(u, 99, ptr::null(), 0) };
        assert_eq!(rc, CURLUcode::CURLUE_UNKNOWN_PART);

        // SAFETY: live handle, freed once.
        unsafe { curl_url_cleanup(u) };
    }

    // --- NULL part clears the component -------------------------------------

    #[test]
    fn set_null_clears_component() {
        let u = curl_url();
        assert_eq!(
            set_part(u, PART_URL, "https://example.com/p?q=1", 0),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(get_part(u, PART_QUERY, 0).unwrap(), "q=1");

        // Clearing the query with a NULL value succeeds and removes it.
        // SAFETY: live handle; NULL value is the documented "clear" input.
        let rc = unsafe { curl_url_set(u, PART_QUERY, ptr::null(), 0) };
        assert_eq!(rc, CURLUcode::CURLUE_OK);
        assert_eq!(
            get_part(u, PART_QUERY, 0).unwrap_err(),
            CURLUcode::CURLUE_NO_QUERY
        );

        // SAFETY: live handle, freed once.
        unsafe { curl_url_cleanup(u) };
    }

    // --- building a URL component-by-component ------------------------------

    #[test]
    fn set_components_then_get_url() {
        let u = curl_url();
        assert_eq!(set_part(u, PART_SCHEME, "https", 0), CURLUcode::CURLUE_OK);
        assert_eq!(
            set_part(u, PART_HOST, "example.com", 0),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(
            set_part(u, PART_PATH, "/index.html", 0),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(set_part(u, PART_OPTIONS, "", 0), CURLUcode::CURLUE_OK);
        assert_eq!(set_part(u, PART_ZONEID, "", 0), CURLUcode::CURLUE_OK);

        assert_eq!(
            get_part(u, PART_URL, 0).unwrap(),
            "https://example.com/index.html"
        );

        // SAFETY: live handle, freed once.
        unsafe { curl_url_cleanup(u) };
    }

    // --- CURLU_* flag pass-through ------------------------------------------

    #[test]
    fn flags_default_port_pass_through() {
        let u = curl_url();
        assert_eq!(set_part(u, PART_SCHEME, "https", 0), CURLUcode::CURLUE_OK);
        assert_eq!(
            set_part(u, PART_HOST, "example.com", 0),
            CURLUcode::CURLUE_OK
        );

        // No explicit port → CURLUE_NO_PORT without the flag …
        assert_eq!(
            get_part(u, PART_PORT, 0).unwrap_err(),
            CURLUcode::CURLUE_NO_PORT
        );
        // … and the scheme default (443) with CURLU_DEFAULT_PORT.
        assert_eq!(
            get_part(u, PART_PORT, core::url::CURLU_DEFAULT_PORT).unwrap(),
            "443"
        );

        // SAFETY: live handle, freed once.
        unsafe { curl_url_cleanup(u) };
    }

    #[test]
    fn flags_urlencode_urldecode_pass_through() {
        let u = curl_url();
        assert_eq!(set_part(u, PART_SCHEME, "https", 0), CURLUcode::CURLUE_OK);
        assert_eq!(
            set_part(u, PART_HOST, "example.com", 0),
            CURLUcode::CURLUE_OK
        );

        // Set a path containing a space with CURLU_URLENCODE → stored encoded.
        assert_eq!(
            set_part(u, PART_PATH, "/a b", core::url::CURLU_URLENCODE),
            CURLUcode::CURLUE_OK
        );
        // Read back raw (encoded) and URL-decoded.
        assert_eq!(get_part(u, PART_PATH, 0).unwrap(), "/a%20b");
        assert_eq!(
            get_part(u, PART_PATH, core::url::CURLU_URLDECODE).unwrap(),
            "/a b"
        );

        // SAFETY: live handle, freed once.
        unsafe { curl_url_cleanup(u) };
    }

    // --- curl_url_dup independence ------------------------------------------

    #[test]
    fn dup_creates_independent_copy() {
        let u = curl_url();
        assert_eq!(
            set_part(u, PART_URL, "https://example.com/a", 0),
            CURLUcode::CURLUE_OK
        );

        // SAFETY: `u` is a live handle; the returned copy is owned by us.
        let u2 = unsafe { curl_url_dup(u) };
        assert!(!u2.is_null());

        // Mutating the original must not affect the duplicate.
        assert_eq!(
            set_part(u, PART_URL, "http://other.test/b", 0),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(get_part(u2, PART_HOST, 0).unwrap(), "example.com");
        assert_eq!(get_part(u, PART_HOST, 0).unwrap(), "other.test");

        // SAFETY: two distinct live handles, each freed once.
        unsafe { curl_url_cleanup(u) };
        unsafe { curl_url_cleanup(u2) };

        // Duplicating NULL yields NULL.
        // SAFETY: NULL is the documented input; returns NULL.
        assert!(unsafe { curl_url_dup(ptr::null()) }.is_null());
    }

    // --- curl_url_strerror --------------------------------------------------

    #[test]
    fn strerror_returns_static_strings() {
        let text = |code: CURLUcode| {
            // SAFETY: `curl_url_strerror` returns a 'static, NUL-terminated,
            // read-only string for every code; we only read it.
            unsafe { CStr::from_ptr(curl_url_strerror(code)) }
                .to_str()
                .expect("strerror strings are valid UTF-8")
        };
        assert_eq!(text(CURLUcode::CURLUE_OK), "No error");
        assert_eq!(
            text(CURLUcode::CURLUE_BAD_HANDLE),
            "An invalid CURLU pointer was passed as argument"
        );
        assert_eq!(
            text(CURLUcode::CURLUE_NO_SCHEME),
            "No scheme part in the URL"
        );
        assert_eq!(
            text(CURLUcode::CURLUE_UNKNOWN_PART),
            "An unknown part ID was passed to a URL API function"
        );
    }
}
