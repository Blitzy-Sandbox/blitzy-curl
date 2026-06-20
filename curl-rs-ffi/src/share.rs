//! The public `curl_share_*` shared-cache C API (`curl_share_init`,
//! `curl_share_setopt`, `curl_share_cleanup`, `curl_share_strerror`).
//!
//! This module implements libcurl's four exported share-interface symbols
//! (`lib/libcurl.def`) directly over the safe, thread-safe core handle
//! [`curl_rs_lib::Share`] (an `Arc<RwLock<SharedData>>`, AAP §0.4.3). The share
//! handle lets several easy handles — possibly on different threads — pool
//! resources such as the cookie jar, the DNS cache, the TLS session cache, the
//! connection pool, the PSL and the HSTS store, exactly as the C
//! `CURLSH`/`curl_share_*` interface does.
//!
//! # Opaque handle and memory ownership
//!
//! C sees the share as the opaque `typedef void CURLSH;` ([`crate::types::CURLSH`]).
//! The implementation places a heap-allocated [`core::Share`](curl_rs_lib::Share)
//! behind that pointer with [`Box::into_raw`] in [`curl_share_init`] and reclaims
//! it with [`Box::from_raw`] in [`curl_share_cleanup`], so the curl ownership
//! contract — "anything allocated by Rust is freed by Rust", every handle freed
//! exactly once, never with the C `free` — is upheld by construction (AAP
//! §0.7.1). Because `Share` wraps an `Arc`, attaching the same handle to several
//! easy handles is a reference-count bump and dropping the last owner frees the
//! shared state deterministically — the safe analogue of C's reference-counted
//! `struct Curl_share`.
//!
//! # `curl_share_setopt` and the C variadic ABI
//!
//! `curl_share_setopt(CURLSH *, CURLSHoption, ...)` is declared C-variadic, but
//! its public call site is the three-argument enforcement macro
//! (`include/curl/curl.h`):
//!
//! ```c
//! #define curl_share_setopt(share, opt, param) \
//!   (curl_share_setopt)(share, opt, param)
//! ```
//!
//! so **exactly one** trailing argument is ever passed. Stable Rust (MSRV 1.75)
//! cannot *define* a C-variadic function (`extern "C" fn(...)` definitions are
//! behind the nightly `c_variadic` feature), so this shim is declared with a
//! single fixed, pointer-width trailing parameter (`arg: usize`). On the SysV
//! AMD64 (x86-64), AArch64 AAPCS64 (Linux/Windows aarch64) and Windows x64
//! calling conventions, a single trailing integer-or-pointer variadic argument
//! occupies the very same general-purpose register slot as a third *named*
//! argument would, so the fixed-parameter shim is ABI-correct for those targets
//! (and for x86-64 macOS). The one calling convention that diverges is Apple's
//! arm64 (`aarch64-apple-darwin`), where the Darwin variant of the AArch64 ABI
//! passes variadic arguments on the stack rather than in registers; closing that
//! one target is a workspace-wide concern shared by every variadic `*_setopt`
//! shim (a single C trampoline behind the build script), not a per-symbol detail
//! of this file. The shim then decodes `arg` according to the `CURLSHoption`
//! selector and dispatches to the typed [`core::Share::setopt`](curl_rs_lib::Share::setopt).
//!
//! # `curl_share_strerror`
//!
//! Returns a `'static`, read-only, NUL-terminated string for a `CURLSHcode`,
//! byte-for-byte identical to `lib/strerror.c`'s `curl_share_strerror`, sourced
//! from the shared [`crate::error_codes::share_strerror_cstr`] table. The string
//! is never heap-allocated and must never be freed — matching curl, which
//! returns string literals (no allocation).
//!
//! # Behavioral oracle
//!
//! The semantics replicate `lib/curl_share.c` (the share interface) and
//! `lib/strerror.c` (the result strings) exactly, including the in-use
//! ("`share->dirty`") guard that rejects both reconfiguration and cleanup with
//! `CURLSHE_IN_USE`, and the lock/unlock callback invocations that
//! `curl_share_cleanup` performs around teardown.
//!
//! # Memory safety
//!
//! `curl-rs-ffi` is the only crate permitted `unsafe`. Every `unsafe` operation
//! here sits in an explicit `unsafe { … }` block carrying a `// SAFETY:`
//! comment (the crate denies `unsafe_op_in_unsafe_fn`), and every exported
//! `unsafe extern "C"` entry point documents its preconditions under a
//! `# Safety` section.

use std::ffi::{c_char, c_int, c_void};
use std::{mem, ptr};

// Per the crate-wide FFI invariant, the safe async core is reached through the
// `core` alias. Standard-library primitives are taken from `std::*` above
// (never `core::*`) because this alias shadows the `core` standard crate within
// this module.
use curl_rs_lib as core;

use crate::error_codes::{result_to_shcode, share_strerror_cstr, CURLSHcode};
use crate::types::{curl_lock_access, curl_lock_data, CURLSHoption, CURL, CURLSH};

// =============================================================================
// CURLSHoption selectors (include/curl/curl.h)
// =============================================================================
//
// The raw integer `CURLSHoption` values `curl_share_setopt` dispatches on. They
// are duplicated here as `match`-pattern constants (a `match` cannot pattern on
// an associated `const fn` call) and are pinned to the core's `ShareOption`
// discriminants by the compile-time guard below, so a future renumbering in
// `curl-rs-lib` fails the build instead of silently mis-dispatching.

/// `CURLSHOPT_SHARE` (1) — begin sharing a `curl_lock_data` data type.
const CURLSHOPT_SHARE: CURLSHoption = 1;
/// `CURLSHOPT_UNSHARE` (2) — stop sharing a `curl_lock_data` data type.
const CURLSHOPT_UNSHARE: CURLSHoption = 2;
/// `CURLSHOPT_LOCKFUNC` (3) — install the `curl_lock_function` callback.
const CURLSHOPT_LOCKFUNC: CURLSHoption = 3;
/// `CURLSHOPT_UNLOCKFUNC` (4) — install the `curl_unlock_function` callback.
const CURLSHOPT_UNLOCKFUNC: CURLSHoption = 4;
/// `CURLSHOPT_USERDATA` (5) — set the `void*` passed to the lock callbacks.
const CURLSHOPT_USERDATA: CURLSHoption = 5;

// Compile-time ABI guard: every selector above MUST equal the core
// `ShareOption` discriminant it dispatches to (which in turn equals the
// `CURLSHoption` value in `include/curl/curl.h`). `as_i32` is a `const fn`, so
// any drift is a hard compile error rather than a silent runtime mismatch.
const _: () = {
    assert!(CURLSHOPT_SHARE == core::share::ShareOption::Share.as_i32());
    assert!(CURLSHOPT_UNSHARE == core::share::ShareOption::Unshare.as_i32());
    assert!(CURLSHOPT_LOCKFUNC == core::share::ShareOption::LockFunc.as_i32());
    assert!(CURLSHOPT_UNLOCKFUNC == core::share::ShareOption::UnlockFunc.as_i32());
    assert!(CURLSHOPT_USERDATA == core::share::ShareOption::UserData.as_i32());
};

// =============================================================================
// Exported symbol 1 / 4 — curl_share_init
// =============================================================================

/// Create a shared-cache handle (`curl_share_init`).
///
/// Allocates a new [`core::Share`](curl_rs_lib::Share) on the heap and returns
/// it as an opaque `CURLSH *`. The fresh handle shares nothing yet (apart from
/// curl's internal `CURL_LOCK_DATA_SHARE` marker, which [`Share::new`] sets just
/// as `curl_share_init` does); sharing of individual resources is enabled with
/// [`curl_share_setopt`]. The returned handle must eventually be released with
/// [`curl_share_cleanup`].
///
/// Unlike the C `curl_share_init`, which returns NULL on an allocation failure,
/// the Rust allocator aborts the process on out-of-memory, so this constructor
/// is effectively infallible; the NULL-return path is retained in the contract
/// only for ABI compatibility and is not reachable in practice.
///
/// This entry point performs no `unsafe` operations and has no preconditions, so
/// it is a safe `extern "C"` function (the `unsafe` keyword on a Rust definition
/// affects only Rust callers; C callers are unaffected either way).
#[no_mangle]
pub extern "C" fn curl_share_init() -> *mut CURLSH {
    // `Box::new` heap-allocates the core `Share`; `Box::into_raw` leaks it to a
    // raw pointer whose ownership now rests with the caller until it is handed
    // back to `curl_share_cleanup`. The `*mut Share -> *mut CURLSH` (== `*mut
    // c_void`) cast is a plain thin-pointer reinterpretation.
    Box::into_raw(Box::new(core::Share::new())) as *mut CURLSH
}

// =============================================================================
// Exported symbol 2 / 4 — curl_share_setopt  (VARIADIC)
//
// As with `curl_easy_setopt`, the public, ABI-exported
// `curl_share_setopt(CURLSH *, CURLSHoption, ...)` symbol is a genuine C-variadic
// trampoline in `csrc/variadic_trampolines.c`; a fixed-arity Rust shim is not
// ABI-equivalent on every target (macOS arm64 stack-passes the first variadic
// argument). The trampoline extracts the single trailing argument with `va_arg`
// and forwards it to this typed Rust implementation, `curlrs_share_setopt_impl`.
// =============================================================================

/// Typed Rust implementation behind the public `curl_share_setopt` C-variadic
/// trampoline (the analog of `lib/curl_share.c`).
///
/// The C trampoline forwards the single trailing
/// `curl_share_setopt(share, option, param)` argument here
/// (guaranteed by the three-argument enforcement macro in
/// `include/curl/curl.h`). `arg` is decoded according to `option`:
///
/// * `CURLSHOPT_SHARE` / `CURLSHOPT_UNSHARE` — `arg` is a `curl_lock_data`
///   integer naming the resource to start / stop sharing (e.g.
///   `CURL_LOCK_DATA_COOKIE`). The low 32 bits hold the value (it is passed as a
///   C `int`).
/// * `CURLSHOPT_LOCKFUNC` / `CURLSHOPT_UNLOCKFUNC` — `arg` is the address of a
///   `curl_lock_function` / `curl_unlock_function` (a NULL/`0` address clears
///   the callback).
/// * `CURLSHOPT_USERDATA` — `arg` is the `void*` user-data pointer handed to the
///   lock callbacks (`0` denotes NULL).
///
/// # Return values (mirrors `lib/curl_share.c`)
///
/// * `CURLSHE_INVALID` — `share` is NULL.
/// * `CURLSHE_IN_USE` — one or more easy handles are currently attached; curl
///   refuses to reconfigure a share that is in use, and this check precedes the
///   option dispatch (so an in-use share reports `CURLSHE_IN_USE` even for an
///   otherwise-unknown option, exactly as the C `share->dirty` guard does).
/// * `CURLSHE_BAD_OPTION` — an unknown option, or a `SHARE`/`UNSHARE` data type
///   that is not shareable.
/// * `CURLSHE_NOT_BUILT_IN` — the requested data type's capability is compiled
///   out of this build.
/// * `CURLSHE_OK` — success.
///
/// # Safety
///
/// `share` must be NULL, or a valid `CURLSH *` previously returned by
/// [`curl_share_init`] and not yet passed to [`curl_share_cleanup`]. For the
/// callback options, `arg` must be NULL/`0` or a valid function pointer of the
/// matching `curl_lock_function` / `curl_unlock_function` type that remains
/// valid for as long as the share may invoke it; for `CURLSHOPT_USERDATA` it
/// must be a pointer valid for the lifetime of those callbacks. The handle's
/// state is internally synchronized, so concurrent calls from multiple threads
/// are sound.
#[no_mangle]
pub unsafe extern "C" fn curlrs_share_setopt_impl(
    share: *mut CURLSH,
    option: CURLSHoption,
    arg: usize,
) -> CURLSHcode {
    // C: `if(!GOOD_SHARE_HANDLE(share)) return CURLSHE_INVALID;`
    if share.is_null() {
        return CURLSHcode::CURLSHE_INVALID;
    }

    // SAFETY: per the `# Safety` contract `share` is non-null and was produced
    // by `curl_share_init` (`Box::into_raw` of a `core::Share`) and not yet
    // freed, so it points to a live, well-aligned `Share`. We take only a shared
    // (`&`) borrow; the `Share`'s interior is `Arc<RwLock<…>>`, so concurrent
    // use from other threads is data-race free and no `&mut` alias can exist.
    let share_ref: &core::Share = unsafe { &*(share as *const core::Share) };

    // C checks `share->dirty` BEFORE the option switch, so an in-use share is
    // rejected with CURLSHE_IN_USE for *every* option — even an unknown one.
    // Replicate that ordering precisely for behavioral parity.
    if share_ref.is_in_use() {
        return CURLSHcode::CURLSHE_IN_USE;
    }

    // Decode the single trailing argument per the option selector and build the
    // typed core request. An unrecognized option maps to CURLSHE_BAD_OPTION,
    // matching curl's `default:` switch arm.
    let setting = match option {
        // The `curl_lock_data` selector is a C `int`; its value lives in the low
        // 32 bits of the promoted argument slot, which `arg as i32` extracts.
        CURLSHOPT_SHARE => core::share::ShareSetting::Share(arg as i32),
        CURLSHOPT_UNSHARE => core::share::ShareSetting::Unshare(arg as i32),
        // A NULL (`0`) callback address clears the callback (curl stores NULL);
        // any other address is the function pointer to install.
        CURLSHOPT_LOCKFUNC => core::share::ShareSetting::LockFunc(addr_to_opt(arg)),
        CURLSHOPT_UNLOCKFUNC => core::share::ShareSetting::UnlockFunc(addr_to_opt(arg)),
        CURLSHOPT_USERDATA => core::share::ShareSetting::UserData(arg),
        _ => return CURLSHcode::CURLSHE_BAD_OPTION,
    };

    // The core re-validates the in-use state and applies the option, returning
    // the typed error that `result_to_shcode` maps to the exact `CURLSHcode`.
    result_to_shcode(share_ref.setopt(setting))
}

/// Maps a raw callback-pointer address to the core's `Option<usize>`
/// representation: a `0` address means "no callback" (curl stores NULL),
/// any other address is the installed function pointer.
#[inline]
fn addr_to_opt(addr: usize) -> Option<usize> {
    if addr == 0 {
        None
    } else {
        Some(addr)
    }
}

// =============================================================================
// Exported symbol 3 / 4 — curl_share_cleanup
// =============================================================================

/// The concrete (non-`Option`) `curl_lock_function` pointer signature
/// (`include/curl/curl.h`), used to reconstruct and invoke the stored lock
/// callback during cleanup.
type LockFn = unsafe extern "C" fn(*mut CURL, curl_lock_data, curl_lock_access, *mut c_void);

/// The concrete (non-`Option`) `curl_unlock_function` pointer signature
/// (`include/curl/curl.h`).
type UnlockFn = unsafe extern "C" fn(*mut CURL, curl_lock_data, *mut c_void);

/// Invoke the application's lock callback for the share's own metadata lock,
/// exactly as `curl_share_cleanup` does:
/// `lockfunc(NULL, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE, clientdata)`.
/// A no-op when no lock callback is registered (`addr` is `None`).
///
/// `addr`, when `Some`, must be the address of a valid `curl_lock_function` the
/// application installed via `curl_share_setopt(CURLSHOPT_LOCKFUNC, …)`.
#[inline]
fn invoke_share_lock(addr: Option<usize>, userdata: *mut c_void) {
    if let Some(addr) = addr {
        // SAFETY: `addr` is the non-null address of a `curl_lock_function` the
        // application registered via `curl_share_setopt(CURLSHOPT_LOCKFUNC, …)`.
        // A function pointer and `usize` are the same width, so transmuting the
        // stored address back to the exact `extern "C"` signature reproduces the
        // original callable with an identical ABI.
        let f: LockFn = unsafe { mem::transmute::<usize, LockFn>(addr) };
        // SAFETY: `f` is invoked with precisely the arguments its published C
        // signature (`curl_lock_function`) requires; the NULL easy-handle and
        // the application-owned `userdata` reference neither the share
        // allocation nor any Rust-owned memory, so the call is sound.
        unsafe {
            f(
                ptr::null_mut(),
                curl_lock_data::CURL_LOCK_DATA_SHARE,
                curl_lock_access::CURL_LOCK_ACCESS_SINGLE,
                userdata,
            );
        }
    }
}

/// Invoke the application's unlock callback for the share's own metadata lock,
/// exactly as `curl_share_cleanup` does:
/// `unlockfunc(NULL, CURL_LOCK_DATA_SHARE, clientdata)`. A no-op when no unlock
/// callback is registered (`addr` is `None`).
///
/// `addr`, when `Some`, must be the address of a valid `curl_unlock_function`
/// the application installed via `curl_share_setopt(CURLSHOPT_UNLOCKFUNC, …)`.
#[inline]
fn invoke_share_unlock(addr: Option<usize>, userdata: *mut c_void) {
    if let Some(addr) = addr {
        // SAFETY: `addr` is the non-null address of a `curl_unlock_function` the
        // application registered via `curl_share_setopt(CURLSHOPT_UNLOCKFUNC,
        // …)`. Transmuting the stored address back to the exact `extern "C"`
        // signature is a same-width pointer round-trip and reproduces the
        // original callable with an identical ABI.
        let f: UnlockFn = unsafe { mem::transmute::<usize, UnlockFn>(addr) };
        // SAFETY: `f` is invoked with exactly the arguments its published C
        // signature (`curl_unlock_function`) requires; the NULL easy-handle and
        // application-owned `userdata` reference no Rust-owned memory.
        unsafe {
            f(
                ptr::null_mut(),
                curl_lock_data::CURL_LOCK_DATA_SHARE,
                userdata,
            );
        }
    }
}

/// Destroy a shared-cache handle (`curl_share_cleanup`).
///
/// Mirrors `lib/curl_share.c` exactly:
///
/// 1. A NULL handle yields `CURLSHE_INVALID`.
/// 2. The registered lock callback (if any) is invoked for the share's own
///    metadata lock: `lockfunc(NULL, CURL_LOCK_DATA_SHARE,
///    CURL_LOCK_ACCESS_SINGLE, userdata)`.
/// 3. If one or more easy handles are still attached (the share is "in use"),
///    the unlock callback (if any) is invoked and `CURLSHE_IN_USE` is returned;
///    the handle is left intact for the caller to retry after detaching.
/// 4. Otherwise the handle is reclaimed and freed (deterministically dropping
///    every shared resource — the safe replacement for curl's explicit
///    cookie/HSTS/session-cache/connection-pool/DNS frees), the unlock callback
///    (if any) is invoked, and `CURLSHE_OK` is returned.
///
/// # Safety
///
/// `share` must be NULL, or a valid `CURLSH *` previously returned by
/// [`curl_share_init`] and not yet passed to `curl_share_cleanup` (it is freed
/// here, so a second cleanup of the same handle is a double-free). Any lock /
/// unlock callbacks previously installed must still be valid to call.
#[no_mangle]
pub unsafe extern "C" fn curl_share_cleanup(share: *mut CURLSH) -> CURLSHcode {
    // C: `if(!GOOD_SHARE_HANDLE(share)) return CURLSHE_INVALID;`
    if share.is_null() {
        return CURLSHcode::CURLSHE_INVALID;
    }

    // Snapshot the callback addresses, the user-data pointer and the in-use
    // state through a shared borrow, then end that borrow before the handle is
    // reclaimed below. (`0` user-data denotes a NULL `void*`, matching curl.)
    let (userdata, lock_fn, unlock_fn, in_use) = {
        // SAFETY: per the `# Safety` contract `share` is non-null and points to
        // a live `core::Share` produced by `curl_share_init`. A shared borrow is
        // sound (interior `Arc<RwLock<…>>`); it is dropped at the end of this
        // block, before any reclamation of the allocation.
        let share_ref: &core::Share = unsafe { &*(share as *const core::Share) };
        (
            share_ref.user_data() as *mut c_void,
            share_ref.lock_function(),
            share_ref.unlock_function(),
            share_ref.is_in_use(),
        )
    };

    // C calls the lock callback first, locking the share's own metadata for the
    // duration of teardown.
    invoke_share_lock(lock_fn, userdata);

    if in_use {
        // C: still dirty — release the metadata lock and refuse to free.
        invoke_share_unlock(unlock_fn, userdata);
        return CURLSHcode::CURLSHE_IN_USE;
    }

    // SAFETY: `share` came from `curl_share_init` (`Box::into_raw` of a
    // `core::Share`) and, per the `# Safety` contract, has not been freed; the
    // shared borrow above has ended, so reclaiming the unique owning `Box` is
    // sound. Dropping it runs the deterministic teardown of every shared
    // resource and frees the allocation exactly once.
    drop(unsafe { Box::from_raw(share as *mut core::Share) });

    // C calls the unlock callback at the very end of a successful cleanup. The
    // callback receives a NULL handle plus the application's own `userdata`
    // (which it owns independently of the now-freed share), so invoking it after
    // the allocation is reclaimed is observationally identical to curl.
    invoke_share_unlock(unlock_fn, userdata);

    CURLSHcode::CURLSHE_OK
}

// =============================================================================
// Exported symbol 4 / 4 — curl_share_strerror
// =============================================================================

/// Return a human-readable string for a `CURLSHcode` (`curl_share_strerror`).
///
/// The returned pointer references a `'static`, read-only, NUL-terminated string
/// (sourced from the shared [`share_strerror_cstr`] table, byte-for-byte from
/// `lib/strerror.c`) that is **never freed**; the caller must not pass it to
/// `free()` / `curl_free`. No allocation is performed, matching curl, which
/// returns string literals.
///
/// The parameter is a plain `c_int`, **not** the closed `CURLSHcode` enum: a C
/// caller may pass any integer, so receiving it as `c_int` (rather than a
/// by-value enum, which would materialize an invalid discriminant — undefined
/// behaviour — for an out-of-range value) keeps the boundary sound. The internal
/// total mapping then falls through to `"CURLSHcode unknown"` for any unmapped
/// integer, exactly as `lib/strerror.c`'s `default` arm does.
///
/// # Safety
///
/// This function performs no pointer dereferences and is sound for every value
/// of `code` (the parameter is a `c_int`, so every C integer is a valid
/// argument; an out-of-range code maps to the catch-all "CURLSHcode unknown"
/// string). It is declared `unsafe extern "C"` only to match curl's published
/// FFI surface (mirroring `curl_easy_strerror`); callers must nonetheless treat
/// the returned pointer as borrowed `'static` data and must not free or mutate
/// it.
#[no_mangle]
pub unsafe extern "C" fn curl_share_strerror(code: c_int) -> *const c_char {
    share_strerror_cstr(code).as_ptr()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    // The public `curl_share_setopt` symbol is now the C-variadic `va_arg`
    // trampoline in `csrc/variadic_trampolines.c`; the typed dispatch logic these
    // tests exercise (including the compile-time signature binding below) lives in
    // the Rust implementation it forwards to. Alias the implementation symbol back
    // to the public name so the test bodies — which already pass exactly one
    // pointer-width trailing argument as `usize` — read unchanged. (The
    // trampoline's pure va_arg extraction is a C-ABI concern verified by the
    // C/`tests/libtest` callers, not reachable from Rust.)
    use super::curlrs_share_setopt_impl as curl_share_setopt;
    // `super::*` re-imports the parent's `core` alias (= `curl_rs_lib`), which
    // shadows the built-in `core` crate; root this import at `super::core` so it
    // is unambiguously the alias rather than the standard `core` crate.
    use super::core::share::LockData;
    use std::ffi::CStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Raw `curl_lock_data` integer value (include/curl/curl.h) used as the
    // trailing `curl_share_setopt(SHARE/UNSHARE, …)` argument in the tests.
    // `CURL_LOCK_DATA_DNS` is shareable in every build (it is not feature-gated,
    // unlike `CURL_LOCK_DATA_COOKIE`), so it exercises the SHARE/UNSHARE path
    // deterministically regardless of the core's enabled feature set.
    const CURL_LOCK_DATA_DNS: usize = 3;

    /// Borrow the core `Share` behind an opaque `CURLSH *` (test-only helper).
    ///
    /// # Safety
    /// `sh` must be a live handle from [`curl_share_init`] not yet cleaned up.
    unsafe fn as_share<'a>(sh: *mut CURLSH) -> &'a core::Share {
        // SAFETY: the caller guarantees `sh` is a live `core::Share` handle.
        unsafe { &*(sh as *const core::Share) }
    }

    // --- lifecycle ----------------------------------------------------------

    #[test]
    fn init_returns_nonnull_and_cleanup_ok() {
        let sh = curl_share_init();
        assert!(
            !sh.is_null(),
            "curl_share_init must return a non-null handle"
        );
        // SAFETY: `sh` is a fresh, live handle from curl_share_init.
        let rc = unsafe { curl_share_cleanup(sh) };
        assert_eq!(rc, CURLSHcode::CURLSHE_OK);
    }

    #[test]
    fn cleanup_null_is_invalid() {
        // SAFETY: NULL is an explicitly handled input (returns CURLSHE_INVALID).
        let rc = unsafe { curl_share_cleanup(ptr::null_mut()) };
        assert_eq!(rc, CURLSHcode::CURLSHE_INVALID);
    }

    #[test]
    fn setopt_null_is_invalid() {
        // SAFETY: NULL handle is explicitly handled before any dereference.
        let rc = unsafe { curl_share_setopt(ptr::null_mut(), CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS) };
        assert_eq!(rc, CURLSHcode::CURLSHE_INVALID);
    }

    // --- CURLSHOPT_SHARE / CURLSHOPT_UNSHARE --------------------------------

    #[test]
    fn setopt_share_dns_ok_and_sets_specifier() {
        let sh = curl_share_init();
        // SAFETY: live handle.
        let rc = unsafe { curl_share_setopt(sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS) };
        assert_eq!(rc, CURLSHcode::CURLSHE_OK);
        // SAFETY: live handle; inspect the core state directly.
        assert!(unsafe { as_share(sh) }.is_sharing(LockData::Dns));
        // SAFETY: live handle.
        assert_eq!(unsafe { curl_share_cleanup(sh) }, CURLSHcode::CURLSHE_OK);
    }

    #[test]
    fn setopt_unshare_clears_specifier() {
        let sh = curl_share_init();
        // SAFETY: live handle throughout.
        unsafe {
            assert_eq!(
                curl_share_setopt(sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS),
                CURLSHcode::CURLSHE_OK
            );
            assert!(as_share(sh).is_sharing(LockData::Dns));
            assert_eq!(
                curl_share_setopt(sh, CURLSHOPT_UNSHARE, CURL_LOCK_DATA_DNS),
                CURLSHcode::CURLSHE_OK
            );
            assert!(!as_share(sh).is_sharing(LockData::Dns));
            assert_eq!(curl_share_cleanup(sh), CURLSHcode::CURLSHE_OK);
        }
    }

    #[test]
    fn setopt_unknown_lock_data_is_bad_option() {
        let sh = curl_share_init();
        // 999 is not a defined curl_lock_data value -> curl's `default:` arm.
        // SAFETY: live handle.
        let rc = unsafe { curl_share_setopt(sh, CURLSHOPT_SHARE, 999) };
        assert_eq!(rc, CURLSHcode::CURLSHE_BAD_OPTION);
        // SAFETY: live handle.
        assert_eq!(unsafe { curl_share_cleanup(sh) }, CURLSHcode::CURLSHE_OK);
    }

    // --- unknown / NONE options ---------------------------------------------

    #[test]
    fn setopt_unknown_option_is_bad_option() {
        let sh = curl_share_init();
        // SAFETY: live handle. 0 is CURLSHOPT_NONE (not settable); 99 is unknown.
        unsafe {
            assert_eq!(
                curl_share_setopt(sh, 0, 0),
                CURLSHcode::CURLSHE_BAD_OPTION,
                "CURLSHOPT_NONE must be rejected"
            );
            assert_eq!(
                curl_share_setopt(sh, 99, 0),
                CURLSHcode::CURLSHE_BAD_OPTION,
                "an unknown option must be rejected"
            );
            assert_eq!(curl_share_cleanup(sh), CURLSHcode::CURLSHE_OK);
        }
    }

    // --- CURLSHOPT_USERDATA / LOCKFUNC --------------------------------------

    #[test]
    fn setopt_userdata_is_stored() {
        let sh = curl_share_init();
        let marker: usize = 0xDEAD_BEEF;
        // SAFETY: live handle.
        let rc = unsafe { curl_share_setopt(sh, CURLSHOPT_USERDATA, marker) };
        assert_eq!(rc, CURLSHcode::CURLSHE_OK);
        // SAFETY: live handle.
        assert_eq!(unsafe { as_share(sh) }.user_data(), marker);
        // No lock callback is set, so cleanup never dereferences `marker`.
        // SAFETY: live handle.
        assert_eq!(unsafe { curl_share_cleanup(sh) }, CURLSHcode::CURLSHE_OK);
    }

    #[test]
    fn setopt_lockfunc_is_stored_and_clearable() {
        let sh = curl_share_init();
        let lock_ptr: LockFn = noop_lock;
        let addr = lock_ptr as usize;
        // SAFETY: live handle; `addr` is the address of a real, valid callback.
        unsafe {
            assert_eq!(
                curl_share_setopt(sh, CURLSHOPT_LOCKFUNC, addr),
                CURLSHcode::CURLSHE_OK
            );
            assert_eq!(as_share(sh).lock_function(), Some(addr));
            // A NULL address clears the callback (curl stores NULL).
            assert_eq!(
                curl_share_setopt(sh, CURLSHOPT_LOCKFUNC, 0),
                CURLSHcode::CURLSHE_OK
            );
            assert_eq!(as_share(sh).lock_function(), None);
            assert_eq!(curl_share_cleanup(sh), CURLSHcode::CURLSHE_OK);
        }
    }

    // --- in-use ("dirty") guard ---------------------------------------------

    #[test]
    fn setopt_and_cleanup_while_in_use() {
        let sh = curl_share_init();
        // Simulate an attached easy handle.
        // SAFETY: live handle.
        unsafe { as_share(sh) }.add_user();

        // SAFETY: live handle.
        unsafe {
            // A known option is rejected with IN_USE while attached.
            assert_eq!(
                curl_share_setopt(sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS),
                CURLSHcode::CURLSHE_IN_USE
            );
            // The dirty check precedes option validation, so an UNKNOWN option
            // also reports IN_USE (not BAD_OPTION) — exact `lib/curl_share.c`
            // ordering parity.
            assert_eq!(curl_share_setopt(sh, 99, 0), CURLSHcode::CURLSHE_IN_USE);
            // Cleanup is likewise refused while in use; the handle is preserved.
            assert_eq!(curl_share_cleanup(sh), CURLSHcode::CURLSHE_IN_USE);

            // Detach and verify reconfiguration / cleanup succeed.
            as_share(sh).remove_user();
            assert_eq!(
                curl_share_setopt(sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS),
                CURLSHcode::CURLSHE_OK
            );
            assert_eq!(curl_share_cleanup(sh), CURLSHcode::CURLSHE_OK);
        }
    }

    // --- curl_share_strerror ------------------------------------------------

    #[test]
    fn strerror_strings_match_oracle() {
        // Byte-for-byte against lib/strerror.c.
        let cases = [
            (CURLSHcode::CURLSHE_OK, "No error"),
            (CURLSHcode::CURLSHE_BAD_OPTION, "Unknown share option"),
            (CURLSHcode::CURLSHE_IN_USE, "Share currently in use"),
            (CURLSHcode::CURLSHE_INVALID, "Invalid share handle"),
            (CURLSHcode::CURLSHE_NOMEM, "Out of memory"),
            (
                CURLSHcode::CURLSHE_NOT_BUILT_IN,
                "Feature not enabled in this library",
            ),
        ];
        for (code, expected) in cases {
            // SAFETY: curl_share_strerror returns a non-null 'static C string.
            let p = unsafe { curl_share_strerror(code as c_int) };
            assert!(!p.is_null());
            // SAFETY: the returned pointer is a valid NUL-terminated 'static str.
            let got = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
            assert_eq!(got, expected, "strerror mismatch for {code:?}");
        }
    }

    /// Issue 2 regression: the exported `curl_share_strerror` takes a `c_int`, so
    /// a C caller may pass any out-of-range integer without invoking undefined
    /// behaviour; every unmapped value returns the catch-all "CURLSHcode unknown"
    /// string (matching `lib/strerror.c`), never NULL and never a crash.
    #[test]
    fn strerror_out_of_range_is_catch_all() {
        for code in [9999, -1, c_int::MIN, c_int::MAX] {
            // SAFETY: returns a non-null 'static NUL-terminated string for any
            // `c_int`; we only read it.
            let p = unsafe { curl_share_strerror(code) };
            assert!(!p.is_null(), "share strerror({code}) returned NULL");
            // SAFETY: the returned pointer is a valid NUL-terminated 'static str.
            let got = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
            assert_eq!(got, "CURLSHcode unknown", "share strerror({code})");
        }
    }

    // --- cleanup invokes the lock/unlock callbacks --------------------------

    static LOCK_CALLS: AtomicUsize = AtomicUsize::new(0);
    static UNLOCK_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn noop_lock(
        _h: *mut CURL,
        _d: curl_lock_data,
        _a: curl_lock_access,
        _u: *mut c_void,
    ) {
    }

    unsafe extern "C" fn counting_lock(
        h: *mut CURL,
        d: curl_lock_data,
        a: curl_lock_access,
        _u: *mut c_void,
    ) {
        assert!(h.is_null());
        assert_eq!(d, curl_lock_data::CURL_LOCK_DATA_SHARE);
        assert_eq!(a, curl_lock_access::CURL_LOCK_ACCESS_SINGLE);
        LOCK_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn counting_unlock(h: *mut CURL, d: curl_lock_data, _u: *mut c_void) {
        assert!(h.is_null());
        assert_eq!(d, curl_lock_data::CURL_LOCK_DATA_SHARE);
        UNLOCK_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn cleanup_invokes_lock_and_unlock_callbacks() {
        LOCK_CALLS.store(0, Ordering::SeqCst);
        UNLOCK_CALLS.store(0, Ordering::SeqCst);

        let sh = curl_share_init();
        let lock_ptr: LockFn = counting_lock;
        let unlock_ptr: UnlockFn = counting_unlock;
        // SAFETY: live handle; addresses are of real, valid callbacks.
        unsafe {
            assert_eq!(
                curl_share_setopt(sh, CURLSHOPT_LOCKFUNC, lock_ptr as usize),
                CURLSHcode::CURLSHE_OK
            );
            assert_eq!(
                curl_share_setopt(sh, CURLSHOPT_UNLOCKFUNC, unlock_ptr as usize),
                CURLSHcode::CURLSHE_OK
            );
            // A successful cleanup invokes the lock callback once at the start
            // and the unlock callback once at the end (lib/curl_share.c).
            assert_eq!(curl_share_cleanup(sh), CURLSHcode::CURLSHE_OK);
        }
        assert_eq!(LOCK_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(UNLOCK_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cleanup_in_use_still_unlocks() {
        // When cleanup is refused (CURLSHE_IN_USE) curl still takes and releases
        // the metadata lock, so both the lock and unlock callbacks fire once per
        // cleanup attempt; the handle itself is preserved for a later retry.
        // Dedicated statics keep this test independent of the success-path test.
        IN_USE_LOCK_CALLS.store(0, Ordering::SeqCst);
        IN_USE_UNLOCK_CALLS.store(0, Ordering::SeqCst);

        let sh = curl_share_init();
        let lock_ptr: LockFn = in_use_lock;
        let unlock_ptr: UnlockFn = in_use_unlock;
        // SAFETY: live handle; real callbacks.
        unsafe {
            curl_share_setopt(sh, CURLSHOPT_LOCKFUNC, lock_ptr as usize);
            curl_share_setopt(sh, CURLSHOPT_UNLOCKFUNC, unlock_ptr as usize);
            as_share(sh).add_user();
            assert_eq!(curl_share_cleanup(sh), CURLSHcode::CURLSHE_IN_USE);
            // Detach and free for real (no leak).
            as_share(sh).remove_user();
            assert_eq!(curl_share_cleanup(sh), CURLSHcode::CURLSHE_OK);
        }
        // Lock fired on both cleanup attempts (2); unlock fired on both (2).
        assert_eq!(IN_USE_LOCK_CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(IN_USE_UNLOCK_CALLS.load(Ordering::SeqCst), 2);
    }

    static IN_USE_LOCK_CALLS: AtomicUsize = AtomicUsize::new(0);
    static IN_USE_UNLOCK_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn in_use_lock(
        _h: *mut CURL,
        _d: curl_lock_data,
        _a: curl_lock_access,
        _u: *mut c_void,
    ) {
        IN_USE_LOCK_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn in_use_unlock(_h: *mut CURL, _d: curl_lock_data, _u: *mut c_void) {
        IN_USE_UNLOCK_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    // --- exported ABI signatures (compile-time) -----------------------------

    #[test]
    fn exported_symbols_have_expected_abi() {
        // Binding each function to its exact C-ABI pointer type proves the
        // signatures match curl's published prototypes at compile time.
        let _init: extern "C" fn() -> *mut CURLSH = curl_share_init;
        let _setopt: unsafe extern "C" fn(*mut CURLSH, CURLSHoption, usize) -> CURLSHcode =
            curl_share_setopt;
        let _cleanup: unsafe extern "C" fn(*mut CURLSH) -> CURLSHcode = curl_share_cleanup;
        let _strerror: unsafe extern "C" fn(c_int) -> *const c_char = curl_share_strerror;
    }
}
