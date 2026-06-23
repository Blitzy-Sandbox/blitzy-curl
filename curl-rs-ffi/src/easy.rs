//! The public `curl_easy_*` easy-handle C API — the drop-in `libcurl`
//! easy-interface ABI (`lib/libcurl.def`).
//!
//! This module implements the thirteen exported easy-interface symbols
//! (`curl_easy_init`, `curl_easy_setopt`, `curl_easy_perform`,
//! `curl_easy_cleanup`, `curl_easy_getinfo`, `curl_easy_duphandle`,
//! `curl_easy_reset`, `curl_easy_recv`, `curl_easy_send`, `curl_easy_upkeep`,
//! `curl_easy_pause`, `curl_easy_ssls_export`, `curl_easy_ssls_import`) directly
//! over the safe async core handle [`curl_rs_lib::Easy`]. It is the heart of the
//! libcurl handle ABI and the canonical sync-over-async bridge point
//! (`curl_easy_perform`, AAP §0.4.4).
//!
//! # Opaque handle and memory ownership
//!
//! C sees the easy handle as the opaque `typedef void CURL;`
//! ([`crate::types::CURL`]). The implementation places a heap-allocated
//! [`core::Easy`](curl_rs_lib::Easy) behind that pointer with [`Box::into_raw`]
//! in [`curl_easy_init`] / [`curl_easy_duphandle`] and reclaims it with
//! [`Box::from_raw`] in [`curl_easy_cleanup`], so the curl ownership contract —
//! "anything allocated by Rust is freed by Rust", every handle freed exactly
//! once, never with the C `free` — is upheld by construction (AAP §0.7.1).
//! Dropping the owning `Box` runs `Easy`'s deterministic teardown (closing
//! connections and freeing buffers), the safe replacement for curl's explicit
//! `Curl_close`.
//!
//! # The two variadic entry points (`setopt` / `getinfo`)
//!
//! `curl_easy_setopt(CURL *, CURLoption, ...)` and
//! `curl_easy_getinfo(CURL *, CURLINFO, ...)` are declared C-variadic, but their
//! public call sites are the three-argument enforcement macros in
//! `include/curl/easy.h`:
//!
//! ```c
//! #define curl_easy_setopt(handle,opt,param) \
//!   curl_easy_setopt(handle,opt,param)
//! #define curl_easy_getinfo(handle,info,arg) \
//!   curl_easy_getinfo(handle,info,arg)
//! ```
//!
//! so **exactly one** trailing argument is ever passed. Stable Rust (MSRV 1.75)
//! cannot *define* a C-variadic function (`extern "C" fn(...)` definitions are
//! behind the nightly `c_variadic` feature), so — exactly like the sibling
//! `curl_share_setopt` / `curl_multi_setopt` shims — these are declared with a
//! single fixed, pointer-width trailing parameter (`arg: usize`). On the SysV
//! AMD64 (x86-64), AArch64 AAPCS64 (Linux aarch64) and x86-64 macOS calling
//! conventions, a single trailing integer-or-pointer variadic argument occupies
//! the very same general-purpose register slot a third *named* argument would,
//! so the fixed-parameter shim is ABI-correct for those targets. The one
//! calling convention that diverges is Apple's arm64 (`aarch64-apple-darwin`),
//! whose Darwin AArch64 variant passes variadic arguments on the stack rather
//! than in registers; closing that one target is a workspace-wide concern shared
//! by every variadic `*_setopt` / `*_getinfo` shim (a single C trampoline behind
//! the build script), **not** a per-symbol detail of this file.
//!
//! The shim then decodes `arg` according to the option/info selector. For
//! `setopt` the `CURLoption`'s type (looked up in the canonical option table,
//! `crate::core::options`) decides whether `arg` is a `long`, a `curl_off_t`, a
//! `char *`, a `struct curl_slist *`, a `struct curl_blob *`, a function
//! pointer, an opaque `void *`, or one of the typed object handles
//! (`CURLSH *` / `CURLU *`); it is marshalled into a typed
//! [`core::OptionValue`](curl_rs_lib::OptionValue) and applied via
//! [`core::Easy::setopt`](curl_rs_lib::Easy::setopt). For `getinfo` the trailing
//! `arg` is a pointer to caller-provided storage, and the
//! [`core::InfoValue`](curl_rs_lib::InfoValue) returned by
//! [`core::Easy::getinfo`](curl_rs_lib::Easy::getinfo) is written through it.
//!
//! # `getinfo` string / slist ownership (AAP §0.7.4, `lib/getinfo.c`)
//!
//! Per curl's contract, `CURLINFO_*` string results are owned by the handle and
//! remain valid only until the next call on it (or cleanup); the caller must not
//! free them. That invariant is satisfied structurally: the returned
//! `*const c_char` borrows an owned `CString`/`String` living inside
//! `core::Easy`. `CURLINFO_*` slist results, by contrast, are a fresh chain the
//! caller owns and must release with `curl_slist_free_all`, matching curl's
//! `CURLINFO_SSL_ENGINES` / `CURLINFO_COOKIELIST`.
//!
//! # Synchronous C ABI over an asynchronous core (AAP §0.4.4)
//!
//! The C API is synchronous; `curl-rs-lib` is asynchronous on Tokio. The
//! blocking entry points drive the async core to completion through the
//! crate-wide [`crate::block_on`] bridge (a thread-local current-thread Tokio
//! runtime). [`curl_easy_perform`] is the canonical example;
//! [`curl_easy_recv`] / [`curl_easy_send`] / [`curl_easy_upkeep`] run their
//! (currently synchronous) core operations inside the same bridge so they
//! execute within a runtime context, exactly as the sibling `curl_ws_recv` /
//! `curl_ws_send` shims do. [`curl_easy_pause`] is a pure handle-state toggle
//! with no I/O and is therefore invoked directly.
//!
//! # Memory safety
//!
//! `curl-rs-ffi` is the only crate permitted `unsafe`. Every `unsafe` operation
//! here sits in an explicit `unsafe { … }` block carrying a `// SAFETY:` comment
//! (the workspace lint policy denies `unsafe_op_in_unsafe_fn`), and every
//! exported `unsafe extern "C"` entry point documents its preconditions under a
//! `# Safety` section.
//!
//! # Behavioral oracle
//!
//! The semantics replicate `lib/easy.c` (lifecycle, `recv`/`send`, `pause`,
//! `reset`, the SSL-session import/export stubs), `lib/setopt.c`
//! (`curl_easy_setopt` option dispatch) and `lib/getinfo.c`
//! (`curl_easy_getinfo` result marshalling) exactly.

use std::ffi::{c_char, c_double, c_int, c_long, c_uchar, c_void, CStr};
use std::{ptr, slice};

use libc::size_t;

// libc's standard-output `FILE*` (the C stdio `stdout` global). The default
// (no-`CURLOPT_WRITEFUNCTION`) body-write path emits through this exact stream,
// so body bytes interleave — in program order — with output from
// `curl_mprintf`/`curl_mfprintf`, which the C printf trampoline (`csrc/mprintf.c`)
// routes through the same single C stdio buffer. Rust's `std::io::stdout()` keeps
// a *separate*, independently-flushed buffer (a `LineWriter`), so mixing the two
// reorders output across `curl_easy_perform` boundaries (oracle test536, where a
// libtest prints the response body via libcurl and a status line via
// `curl_mprintf` after each of two performs). Using the C stream matches C curl's
// default write (`fwrite(ptr, 1, len, stdout)`). Apple targets name it `__stdoutp`.
#[cfg(not(target_vendor = "apple"))]
extern "C" {
    #[link_name = "stdout"]
    static C_STDOUT: *mut libc::FILE;
}
#[cfg(target_vendor = "apple")]
extern "C" {
    #[link_name = "__stdoutp"]
    static C_STDOUT: *mut libc::FILE;
}

// Per the crate-wide FFI invariant, the safe async core is reached through the
// `core` alias. Standard-library primitives are taken from `std::*` above
// (never `core::*`) because this alias shadows the `core` standard crate within
// this module.
use curl_rs_lib as core;

use crate::block_on;
use crate::error_codes::{result_to_code, CURLcode};
use crate::slist;
use crate::types::{
    curl_blob, curl_off_t, curl_slist, curl_socket_t, curl_ssls_export_cb, CURLoption, CURL,
    CURLINFO,
};

// =============================================================================
// CURLPAUSE_* bitmask (include/curl/curl.h)
// =============================================================================
//
// The pause/resume direction bits interpreted by `curl_easy_pause`. They are
// pinned to the core's `easy::CURLPAUSE_*` constants by the compile-time guard
// below so a future renumbering in `curl-rs-lib` fails the build instead of
// silently diverging from the curl header.

/// `CURLPAUSE_RECV` — pause the receiving side of the transfer (`1 << 0`).
pub const CURLPAUSE_RECV: c_int = 1 << 0;
/// `CURLPAUSE_SEND` — pause the sending side of the transfer (`1 << 2`).
pub const CURLPAUSE_SEND: c_int = 1 << 2;
/// `CURLPAUSE_ALL` — pause both directions (`CURLPAUSE_RECV | CURLPAUSE_SEND`).
pub const CURLPAUSE_ALL: c_int = CURLPAUSE_RECV | CURLPAUSE_SEND;
/// `CURLPAUSE_CONT` — resume both directions (clear all pause bits, value `0`).
pub const CURLPAUSE_CONT: c_int = 0;

// Compile-time ABI guard: the FFI pause bits MUST equal the core's, which in
// turn equal the `include/curl/curl.h` values.
const _: () = {
    assert!(CURLPAUSE_RECV == core::easy::CURLPAUSE_RECV);
    assert!(CURLPAUSE_SEND == core::easy::CURLPAUSE_SEND);
    assert!(CURLPAUSE_ALL == core::easy::CURLPAUSE_ALL);
    assert!(CURLPAUSE_CONT == core::easy::CURLPAUSE_CONT);
};

// =============================================================================
// Handle-borrow helpers
// =============================================================================

/// Borrow the [`core::Easy`](curl_rs_lib::Easy) behind an opaque `CURL *` as a
/// shared reference, or [`None`] when `handle` is NULL.
///
/// # Safety
///
/// A non-NULL `handle` must be a live easy handle previously returned by
/// [`curl_easy_init`] / [`curl_easy_duphandle`] and not yet passed to
/// [`curl_easy_cleanup`]. The returned borrow must not outlive the entry point
/// that obtained it, and no `&mut` borrow of the same handle may coexist
/// (guaranteed by curl's one-thread-and-one-active-call-per-handle contract).
#[inline]
unsafe fn easy_ref<'a>(handle: *mut CURL) -> Option<&'a core::Easy> {
    if handle.is_null() {
        None
    } else {
        // SAFETY: per the `# Safety` contract a non-null `handle` came from
        // `curl_easy_init`/`curl_easy_duphandle` (`Box::into_raw` of a
        // `core::Easy`) and is still live, so it points to a well-aligned,
        // initialized `Easy`. A shared borrow is sound for the duration of the
        // call; the caller guarantees no aliasing `&mut` exists.
        Some(unsafe { &*(handle as *const core::Easy) })
    }
}

/// Borrow the [`core::Easy`](curl_rs_lib::Easy) behind an opaque `CURL *` as an
/// exclusive reference, or [`None`] when `handle` is NULL.
///
/// # Safety
///
/// A non-NULL `handle` must be a live easy handle previously returned by
/// [`curl_easy_init`] / [`curl_easy_duphandle`] and not yet passed to
/// [`curl_easy_cleanup`]. The returned `&mut` is the unique reference for the
/// duration of the call (curl's single-thread-per-handle contract guarantees no
/// other reference — shared or exclusive — to the same handle exists).
#[inline]
unsafe fn easy_mut<'a>(handle: *mut CURL) -> Option<&'a mut core::Easy> {
    if handle.is_null() {
        None
    } else {
        // SAFETY: per the `# Safety` contract a non-null `handle` came from
        // `curl_easy_init`/`curl_easy_duphandle` (`Box::into_raw` of a
        // `core::Easy`) and is still live, so it points to a well-aligned,
        // initialized `Easy`. The exclusive borrow is the only live reference to
        // the handle for the duration of the call per curl's usage contract, so
        // no alias exists.
        Some(unsafe { &mut *(handle as *mut core::Easy) })
    }
}

// =============================================================================
// Exported symbol 1 / 13 — curl_easy_init
// =============================================================================

/// Create an easy handle (`curl_easy_init`, `include/curl/easy.h`).
///
/// Allocates a new [`core::Easy`](curl_rs_lib::Easy) on the heap, initialized to
/// curl's documented option defaults, and returns it as an opaque `CURL *`. The
/// returned handle must eventually be released with [`curl_easy_cleanup`].
///
/// Mirroring `lib/easy.c`, this performs the **implicit global initialization**
/// curl does when an application has not already called `curl_global_init`: the
/// reference-counted [`core::global_init`](curl_rs_lib::global_init) is invoked
/// with `CURL_GLOBAL_DEFAULT`. That call is idempotent and effectively
/// infallible (it only installs the process-global crypto provider once); should
/// it ever report failure, this returns `NULL` exactly as curl returns `NULL`
/// when its implicit global init fails.
///
/// This entry point performs no `unsafe` operations and has no preconditions, so
/// it is a safe `extern "C"` function (the `unsafe` keyword on a Rust definition
/// affects only Rust callers; C callers are unaffected either way).
#[no_mangle]
pub extern "C" fn curl_easy_init() -> *mut CURL {
    // curl_easy_init implicitly initializes the library if the application did
    // not. `global_init` is reference-counted and idempotent, so an explicit
    // prior `curl_global_init` simply bumps the counter.
    // `CURL_GLOBAL_DEFAULT` is a `c_long`, which `core::global_init` accepts as
    // its `i64` flags directly on every target in the build matrix (LP64, where
    // `c_long == i64`) — matching the sibling `curl_global_init` shim's
    // convention in `global.rs`.
    if core::global_init(crate::global::CURL_GLOBAL_DEFAULT).is_err() {
        return ptr::null_mut();
    }

    // `Box::new` heap-allocates the core `Easy`; `Box::into_raw` leaks it to a
    // raw pointer whose ownership now rests with the caller until it is handed
    // back to `curl_easy_cleanup`. The `*mut Easy -> *mut CURL` (== `*mut
    // c_void`) cast is a plain thin-pointer reinterpretation.
    Box::into_raw(Box::new(core::Easy::new())) as *mut CURL
}

// =============================================================================
// Exported symbol 2 / 13 — curl_easy_cleanup
// =============================================================================

/// Destroy an easy handle (`curl_easy_cleanup`, `include/curl/easy.h`).
///
/// Reclaims the owning `Box` and drops the [`core::Easy`](curl_rs_lib::Easy),
/// deterministically closing any live connections and freeing every owned buffer
/// — the safe replacement for curl's explicit `Curl_close`. A NULL handle is a
/// no-op, matching `lib/easy.c` (`curl_easy_cleanup` returns immediately when
/// `data` is NULL).
///
/// # Safety
///
/// `handle` must be NULL, or a valid `CURL *` previously returned by
/// [`curl_easy_init`] / [`curl_easy_duphandle`] and not yet passed to
/// `curl_easy_cleanup` (the handle is freed here, so a second cleanup of the
/// same pointer is a double-free).
#[no_mangle]
pub unsafe extern "C" fn curl_easy_cleanup(handle: *mut CURL) {
    if handle.is_null() {
        return;
    }

    // SAFETY: per the `# Safety` contract `handle` is non-null and came from
    // `curl_easy_init`/`curl_easy_duphandle` (`Box::into_raw` of a `core::Easy`)
    // and has not been freed, so reconstructing the unique owning `Box` is sound.
    // Dropping it runs the deterministic teardown and frees the allocation
    // exactly once.
    let easy = unsafe { Box::from_raw(handle as *mut core::Easy) };

    // Drop the handle and then drive the bridge runtime so any detached async
    // teardown tasks the drop signalled run to completion now, while the runtime
    // is healthy. An `sftp://`/`scp://` handle owns a russh SSH session whose
    // run-loop is a detached task; dropping the handle closes its channels but
    // does not run it to exit. Left alive, it would be reaped when the
    // per-thread runtime is torn down at thread exit, where russh's
    // `ChannelCloseOnDrop` re-enters `tokio::spawn` with no runtime context and
    // panics. Draining here reaps those tasks first. See
    // `crate::drop_and_drain`.
    //
    // Issue the deferred FTP `QUIT` for this handle's OWN parked control
    // connection, when the lone-easy reuse mechanism was enabled (a prior
    // `curl_easy_perform` called `enable_self_pool_drain`). This drain runs on
    // the SAME thread-local current-thread runtime that opened the socket — the
    // FFI easy-perform path builds and reuses one runtime per thread — so the
    // `QUIT` exchange completes rather than deadlocking. The
    // `should_drain_own_pool` gate confines this to *self-owned* pools, so a
    // pool injected by the CLI (which runs its own end-of-run `ftp_drain_pool`
    // on its runtime; see `Easy::set_conn_pool`) or by a multi handle (which
    // drains in `curl_multi_cleanup` on the multi's own runtime) is never
    // drained here — closing the old cross-runtime-deadlock hazard that the
    // unconditional skip previously avoided (`tests/data/test539`).
    //
    // For a single-transfer handle this is wire-identical to inline `QUIT`: the
    // same `QUIT` is merely issued at cleanup instead of at transfer end. For
    // two performs on one handle, the first transfer parks the still-valid
    // control connection and the second reuses it (skipping a fresh
    // `USER`/`PASS`), with the single `QUIT` fired here. HTTP/keep-alive pools
    // hold no FTP connection, so the drain just force-closes their sockets,
    // equivalent to the pool's `Drop` teardown.
    if easy.should_drain_own_pool() {
        block_on(easy.drain_own_conn_pool());
    }

    crate::drop_and_drain(easy);
}

// =============================================================================
// Exported symbol 3 / 13 — curl_easy_duphandle
// =============================================================================

/// Clone an easy handle's configuration (`curl_easy_duphandle`,
/// `include/curl/easy.h`).
///
/// Returns a new handle that is a deep copy of the source handle's **options**
/// (curl's `data->set`). Per curl semantics the duplicate does **not** inherit
/// live connections, the in-progress transfer state, the cookie jar contents, or
/// the DNS/session caches — only the configuration is copied — exactly as
/// [`core::Easy::duphandle`](curl_rs_lib::Easy::duphandle) implements. A NULL
/// source yields NULL.
///
/// # Safety
///
/// `handle` must be NULL, or a valid `CURL *` previously returned by
/// [`curl_easy_init`] / [`curl_easy_duphandle`] and not yet cleaned up. The
/// returned handle is independently owned and must itself be released with
/// [`curl_easy_cleanup`].
#[no_mangle]
pub unsafe extern "C" fn curl_easy_duphandle(handle: *mut CURL) -> *mut CURL {
    // SAFETY: `easy_ref` upholds its contract given this function's identical
    // `# Safety` precondition on `handle`; it yields `None` for NULL.
    let src = match unsafe { easy_ref(handle) } {
        Some(e) => e,
        None => return ptr::null_mut(),
    };

    // Deep-copy the configuration into a fresh handle and hand it back as an
    // opaque owning pointer, mirroring `curl_easy_init`'s allocation contract.
    Box::into_raw(Box::new(src.duphandle())) as *mut CURL
}

// =============================================================================
// Exported symbol 4 / 13 — curl_easy_reset
// =============================================================================

/// Reset an easy handle to its initial state (`curl_easy_reset`,
/// `include/curl/easy.h`).
///
/// Restores every option to its default, as if the handle had just been created
/// by [`curl_easy_init`]. Per curl's documented contract (and
/// [`core::Easy::reset`](curl_rs_lib::Easy::reset)) the reset deliberately
/// **keeps** live connections, the Session-ID cache, the DNS cache and the
/// cookie jar. A NULL handle is a no-op (matching `lib/easy.c`).
///
/// # Safety
///
/// `handle` must be NULL, or a valid `CURL *` previously returned by
/// [`curl_easy_init`] / [`curl_easy_duphandle`] and not yet cleaned up.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_reset(handle: *mut CURL) {
    // SAFETY: `easy_mut` upholds its contract given this function's identical
    // `# Safety` precondition on `handle`; it yields `None` for NULL (no-op).
    if let Some(easy) = unsafe { easy_mut(handle) } {
        easy.reset();
    }
}

// =============================================================================
// Exported symbol 5 / 13 — curl_easy_perform  (the canonical block_on bridge)
// =============================================================================

/// Bridges a libcurl consumer's `CURLOPT_WRITEFUNCTION` / `CURLOPT_HEADERFUNCTION`
/// (and their `WRITEDATA` / `HEADERDATA` userdata) to the core's
/// [`WriteCallbacks`](core::transfer::WriteCallbacks) sink, so a transfer driven
/// by [`core::Easy::perform_with`] delivers bytes to the C callbacks.
///
/// Function pointers and userdata are held as integer addresses (`usize`) rather
/// than raw pointers so the bridge is [`Send`] — the core's multi handle runs
/// transfers on a multi-thread runtime that requires it (and a stored address is
/// the same safe representation the core uses for its `CCallback`). The addresses
/// are cast back to the C-ABI function-pointer type at the call site.
///
/// When a function address is `0` (the option was never set) the bridge
/// reproduces curl's default: body bytes are written to `stdout`, and header
/// bytes are silently consumed (curl installs no default header callback).
struct CWriteBridge {
    /// `CURLOPT_WRITEFUNCTION` address, or `0` for curl's default (→ stdout).
    write_fn: usize,
    /// `CURLOPT_WRITEDATA` opaque userdata, passed through to the callback.
    write_data: usize,
    /// `CURLOPT_HEADERFUNCTION` address, or `0` for "no header sink".
    header_fn: usize,
    /// `CURLOPT_HEADERDATA` opaque userdata, passed through to the callback.
    header_data: usize,
}

impl core::transfer::WriteCallbacks for CWriteBridge {
    fn write_body(&mut self, data: &[u8]) -> usize {
        let addr = self.write_fn;
        if addr == 0 {
            // Default `CURLOPT_WRITEFUNCTION`: curl's `fwrite` to the C stdio
            // `stdout` FILE* (`data->set.out` defaults to `stdout`). Emit through
            // the SAME C stream `curl_mprintf`/`curl_mfprintf` use so the two
            // interleave in program order, matching C curl exactly; Rust's
            // `std::io::stdout()` has an independent buffer and would reorder them.
            // `fwrite` with `(size = 1, nmemb = len)` returns the byte count
            // actually written; a short write (< len) is propagated as fewer bytes
            // taken, which the engine maps to `CURLE_WRITE_ERROR` — identical to
            // the previous `Err(_) => 0` behavior.
            // SAFETY: `C_STDOUT` is libc's `stdout` global, a valid `FILE*` for the
            // whole process lifetime. `data` is a valid slice of `data.len()`
            // bytes; `fwrite` reads exactly that many and does not retain the
            // pointer. The returned count is a plain `size_t` (== `usize`).
            return unsafe {
                libc::fwrite(
                    data.as_ptr() as *const libc::c_void,
                    1,
                    data.len(),
                    C_STDOUT,
                )
            };
        }
        // SAFETY: `addr` is a non-zero `curl_write_callback` address previously
        // stored by `curl_easy_setopt(CURLOPT_WRITEFUNCTION, ...)`, so its ABI
        // matches the transmuted signature. `data` is a valid slice; we pass its
        // pointer with curl's `(ptr, size = 1, nmemb = len)` convention and the
        // callback does not retain it. `write_data` is the opaque userdata the
        // caller associated via `CURLOPT_WRITEDATA`. The returned count (or a
        // `CURL_WRITEFUNC_*` sentinel) is forwarded verbatim to the engine.
        let cb: unsafe extern "C" fn(*mut c_char, size_t, size_t, *mut c_void) -> size_t =
            unsafe { std::mem::transmute(addr) };
        // SAFETY: see the preceding comment; the call upholds the C contract.
        unsafe {
            cb(
                data.as_ptr() as *mut c_char,
                1,
                data.len(),
                self.write_data as *mut c_void,
            )
        }
    }

    fn write_header(&mut self, data: &[u8]) -> Option<usize> {
        let addr = self.header_fn;
        if addr == 0 {
            // No `CURLOPT_HEADERFUNCTION`: curl silently consumes header bytes.
            return None;
        }
        // SAFETY: as in `write_body`, `addr` is a non-zero `curl_write_callback`
        // address stored by `curl_easy_setopt(CURLOPT_HEADERFUNCTION, ...)`; the
        // ABI matches, `data` is a valid transient slice, and `header_data` is
        // the caller's `CURLOPT_HEADERDATA` userdata.
        let cb: unsafe extern "C" fn(*mut c_char, size_t, size_t, *mut c_void) -> size_t =
            unsafe { std::mem::transmute(addr) };
        // SAFETY: see the preceding comment; the call upholds the C contract.
        let n = unsafe {
            cb(
                data.as_ptr() as *mut c_char,
                1,
                data.len(),
                self.header_data as *mut c_void,
            )
        };
        Some(n)
    }
}

/// Bridges a libcurl consumer's `CURLOPT_READFUNCTION` (and `READDATA` userdata)
/// to the core's [`ReadCallback`](core::transfer::ReadCallback) source. Stores
/// the address as `usize` for the same [`Send`] reason as [`CWriteBridge`]; a
/// `0` address reproduces curl's default of reading the upload body from stdin.
struct CReadBridge {
    /// `CURLOPT_READFUNCTION` address, or `0` for curl's default (← stdin).
    read_fn: usize,
    /// `CURLOPT_READDATA` opaque userdata, passed through to the callback.
    read_data: usize,
    /// `CURLOPT_TRAILERFUNCTION` address, or `0` for no trailing headers.
    trailer_fn: usize,
    /// `CURLOPT_TRAILERDATA` opaque userdata, passed through to the trailer
    /// callback.
    trailer_data: usize,
    /// `CURLOPT_IOCTLFUNCTION` (deprecated) address, or `0` if unset — the legacy
    /// rewind hook invoked with `CURLIOCMD_RESTARTREAD` before a credentialed
    /// body resend (see [`core::transfer::ReadCallback::rewind`]).
    ioctl_fn: usize,
    /// `CURLOPT_IOCTLDATA` opaque userdata, passed through to the ioctl callback.
    ioctl_data: usize,
    /// The owning `CURL *` handle, passed as the ioctl callback's first argument
    /// (`curlioerr (*)(CURL *, int, void *)`). `0` when not available (the
    /// multi-driven provider path); the `CURLIOCMD_RESTARTREAD` callback ignores
    /// the handle, so a `0` handle is harmless there.
    handle: usize,
}

impl core::transfer::ReadCallback for CReadBridge {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let addr = self.read_fn;
        if addr == 0 {
            // Default `CURLOPT_READFUNCTION` is C's `fread`. curl initializes
            // `set.fread_func_set = fread` and `set.in_set = stdin`
            // (lib/easy.c), so the default reader pulls from the
            // `CURLOPT_READDATA` `FILE*`, falling back to `stdin` when the
            // consumer set no `READDATA`. When `read_data` names a `FILE*`
            // (e.g. `tests/libtest/lib505` / `tests/data/test505`, which set
            // `CURLOPT_READDATA` to an `fopen`ed handle without a custom
            // `READFUNCTION`), read from that stream with `fread` — reading
            // from stdin instead would deliver 0 bytes against a known
            // `CURLOPT_INFILESIZE` and abort the upload with
            // `CURLE_READ_ERROR`.
            if self.read_data != 0 {
                // SAFETY: with the default `fread` read function in effect, the
                // consumer's `CURLOPT_READDATA` is a C `FILE*` (curl's
                // documented contract). `fread` fills up to `buf.len()` bytes
                // (element size 1) and returns the count, short at EOF/error —
                // exactly the byte count this bridge must return.
                return unsafe {
                    libc::fread(
                        buf.as_mut_ptr() as *mut c_void,
                        1,
                        buf.len(),
                        self.read_data as *mut libc::FILE,
                    )
                };
            }
            // No `CURLOPT_READDATA`: curl's default stream is stdin. A read
            // error or EOF yields `0`, signaling end-of-input.
            use std::io::Read;
            return std::io::stdin().read(buf).unwrap_or(0);
        }
        // SAFETY: `addr` is a non-zero `curl_read_callback` address previously
        // stored by `curl_easy_setopt(CURLOPT_READFUNCTION, ...)`, so its ABI
        // matches the transmuted signature. `buf` is a valid mutable slice; we
        // pass it with curl's `(ptr, size = 1, nmemb = len)` convention and the
        // callback fills up to `len` bytes, returning the count (or a
        // `CURL_READFUNC_*` sentinel), forwarded verbatim. `read_data` is the
        // caller's `CURLOPT_READDATA` userdata.
        let cb: unsafe extern "C" fn(*mut c_char, size_t, size_t, *mut c_void) -> size_t =
            unsafe { std::mem::transmute(addr) };
        // SAFETY: see the preceding comment; the call upholds the C contract.
        unsafe {
            cb(
                buf.as_mut_ptr() as *mut c_char,
                1,
                buf.len(),
                self.read_data as *mut c_void,
            )
        }
    }

    /// Bridge `CURLOPT_TRAILERFUNCTION` to the core's chunked-trailer seam.
    ///
    /// Invokes the stored C trailer callback once (curl calls it at end-of-body,
    /// in `add_last_chunk`), collecting the `curl_slist` of `name: value` lines
    /// it builds. Each node's NUL-terminated payload becomes one trailer line;
    /// the engine's chunked encoder writes only the correctly-formatted ones
    /// (those bearing `": "`), exactly as curl's `add_last_chunk` does. The
    /// callback-owned list is freed here with `curl_slist_free_all`, matching
    /// curl's ownership contract.
    fn trailers(&mut self) -> Vec<Vec<u8>> {
        let addr = self.trailer_fn;
        if addr == 0 {
            // No `CURLOPT_TRAILERFUNCTION`: the bare `0\r\n\r\n` last chunk.
            return Vec::new();
        }
        // SAFETY: `addr` is a non-zero `curl_trailer_callback` address previously
        // stored by `curl_easy_setopt(CURLOPT_TRAILERFUNCTION, ...)`, so its ABI
        // matches the transmuted signature.
        let cb: unsafe extern "C" fn(*mut *mut curl_slist, *mut c_void) -> c_int =
            unsafe { std::mem::transmute(addr) };
        let mut list: *mut curl_slist = ptr::null_mut();
        // SAFETY: `&mut list` is a valid `*mut *mut curl_slist` for the callback
        // to write the (heap, `curl_slist_append`-built) chain into; `trailer_data`
        // is the caller's `CURLOPT_TRAILERDATA` userdata, passed through verbatim.
        let rc = unsafe { cb(&mut list, self.trailer_data as *mut c_void) };
        // `CURL_TRAILERFUNC_OK == 0`. Any other value is `CURL_TRAILERFUNC_ABORT`,
        // which curl turns into `CURLE_ABORTED_BY_CALLBACK`. The core read seam
        // has no error channel here, so on abort we free the (possibly partial)
        // list and emit no trailers; the common OK path is fully honored.
        if rc != 0 {
            // SAFETY: `list` is null or a `curl_slist_append` chain; the free
            // accepts null and releases the whole chain.
            unsafe { slist::curl_slist_free_all(list) };
            return Vec::new();
        }
        let mut lines: Vec<Vec<u8>> = Vec::new();
        let mut node = list;
        while !node.is_null() {
            // SAFETY: `node` is a valid `curl_slist` node from the callback's
            // chain; `data` is its owned NUL-terminated string (or null).
            let data = unsafe { (*node).data };
            if !data.is_null() {
                // SAFETY: `data` is a valid NUL-terminated C string owned by the
                // node; copied into an owned `Vec` before the list is freed.
                let bytes = unsafe { CStr::from_ptr(data) }.to_bytes().to_vec();
                lines.push(bytes);
            }
            // SAFETY: `node` is valid; `next` is the next node or null.
            node = unsafe { (*node).next };
        }
        // SAFETY: `list` is the callback-built chain (or null) and is no longer
        // referenced; free it exactly as curl's `add_last_chunk` does.
        unsafe { slist::curl_slist_free_all(list) };
        lines
    }

    /// Bridge the legacy `CURLOPT_IOCTLFUNCTION` rewind hook to the core's
    /// upload-rewind seam (curl's `cr_in_rewind` ioctl fallback).
    ///
    /// Invoked once before a body-bearing request is re-sent on a reactive-auth
    /// resend. curl's client reader (`cr_in_rewind`, `lib/sendf.c`) repositions a
    /// `CURLOPT_READFUNCTION` source by calling the application's
    /// `CURLOPT_IOCTLFUNCTION` with `CURLIOCMD_RESTARTREAD` (the legacy path,
    /// superseded by `CURLOPT_SEEKFUNCTION` but still honored). The engine buffers
    /// the read-callback body and re-sends a buffered clone, so this call exists
    /// only to fire the application callback for its observable side effects
    /// (matching curl's wire/stdout behavior — QA libtest 552). A `0` ioctl
    /// address means no callback is registered, so the rewind is a no-op (the
    /// engine's buffered clone already satisfies the resend); the `CURLIOE_*`
    /// return is not propagated because the buffered re-send cannot fail to
    /// rewind.
    fn rewind(&mut self) {
        let addr = self.ioctl_fn;
        if addr == 0 {
            // No `CURLOPT_IOCTLFUNCTION`: nothing to notify; the engine's
            // buffered body clone is re-sent unchanged.
            return;
        }
        // `CURLIOCMD_RESTARTREAD == 1` (include/curl/curl.h): "restart the read
        // stream from start".
        const CURLIOCMD_RESTARTREAD: c_int = 1;
        // SAFETY: `addr` is a non-zero `curl_ioctl_callback` address previously
        // stored by `curl_easy_setopt(CURLOPT_IOCTLFUNCTION, ...)`, so its ABI
        // (`curlioerr (*)(CURL *, int, void *)`) matches the transmuted signature.
        let cb: unsafe extern "C" fn(*mut CURL, c_int, *mut c_void) -> c_int =
            unsafe { std::mem::transmute(addr) };
        // SAFETY: `self.handle` is the owning `CURL *` (or `0`, which the
        // `RESTARTREAD` command ignores); `self.ioctl_data` is the caller's
        // `CURLOPT_IOCTLDATA` userdata, passed through verbatim. The call upholds
        // the C contract; the `curlioerr` result is intentionally discarded.
        let _ = unsafe {
            cb(
                self.handle as *mut CURL,
                CURLIOCMD_RESTARTREAD,
                self.ioctl_data as *mut c_void,
            )
        };
    }
}

/// Builds the [`CWriteBridge`] / [`CReadBridge`] pair for a transfer the multi
/// handle drives on its own runtime, bridging the consumer's registered C
/// callbacks (`CURLOPT_WRITEFUNCTION` / `HEADERFUNCTION` / `READFUNCTION` and
/// their userdata) to the core's sink/source seam.
///
/// `curl_easy_perform` builds the bridges inline on the calling thread, but a
/// multi-driven transfer runs inside a task spawned on the multi handle's
/// multi-thread runtime ([`curl_multi_perform`](crate::multi::curl_multi_perform)),
/// so the bridge factory must be `Send + Sync` and own no borrow of the handle.
/// The callback function/userdata are stored as integer addresses (`usize`) —
/// the same `Send` representation the bridges use — and rebuilt into fresh
/// bridges per transfer in [`make`](core::transfer::MultiIoProvider::make). This
/// is what makes a multi-driven transfer deliver body bytes to the user's write
/// callback (and honor its abort return) and pull upload bytes from the read
/// callback, instead of falling back to stdout/stdin (QA F11-PERF Issue #6).
///
/// The FFI's [`curl_multi_add_handle`](crate::multi::curl_multi_add_handle)
/// registers one of these on the easy handle (via
/// [`core::Easy::set_multi_io_provider`]) at add time, snapshotting the
/// callbacks configured up to that point — the curl-documented order is
/// `setopt` then `add_handle` then `perform`.
pub(crate) struct CBridgeProvider {
    write_fn: usize,
    write_data: usize,
    header_fn: usize,
    header_data: usize,
    read_fn: usize,
    read_data: usize,
    trailer_fn: usize,
    trailer_data: usize,
    ioctl_fn: usize,
    ioctl_data: usize,
}

impl CBridgeProvider {
    /// Snapshot the easy handle's stored C-callback addresses (the same fields
    /// [`curl_easy_perform`] copies into its inline bridges). Reads only the
    /// `usize` newtypes in `data->set`, so the result borrows nothing.
    pub(crate) fn from_easy(easy: &core::Easy) -> Self {
        Self {
            write_fn: easy.set.fwrite_func.0,
            write_data: easy.set.out.0,
            header_fn: easy.set.fwrite_header.0,
            header_data: easy.set.writeheader.0,
            read_fn: easy.set.fread_func_set.0,
            read_data: easy.set.in_set.0,
            trailer_fn: easy.set.trailer_callback.0,
            trailer_data: easy.set.trailer_data.0,
            ioctl_fn: easy.set.ioctl_func.0,
            ioctl_data: easy.set.ioctl_client.0,
        }
    }
}

impl core::transfer::MultiIoProvider for CBridgeProvider {
    fn make(
        &self,
    ) -> (
        Box<dyn core::transfer::WriteCallbacks>,
        Box<dyn core::transfer::ReadCallback>,
    ) {
        (
            Box::new(CWriteBridge {
                write_fn: self.write_fn,
                write_data: self.write_data,
                header_fn: self.header_fn,
                header_data: self.header_data,
            }),
            Box::new(CReadBridge {
                read_fn: self.read_fn,
                read_data: self.read_data,
                trailer_fn: self.trailer_fn,
                trailer_data: self.trailer_data,
                ioctl_fn: self.ioctl_fn,
                ioctl_data: self.ioctl_data,
                // The multi-driven provider runs on a separate runtime and does
                // not carry the owning `CURL *`; the `CURLIOCMD_RESTARTREAD`
                // callback ignores its handle argument, so `0` is harmless.
                handle: 0,
            }),
        )
    }
}

/// Perform a blocking transfer (`curl_easy_perform`, `include/curl/easy.h`).
///
/// This is the canonical sync-over-async bridge (AAP §0.4.4): it drives the
/// asynchronous [`core::Easy::perform`](curl_rs_lib::Easy::perform) future to
/// completion on the crate's thread-local current-thread Tokio runtime via
/// [`crate::block_on`], honoring the synchronous C contract. The transfer's
/// [`CURLcode`] result is returned. A NULL handle yields
/// `CURLE_BAD_FUNCTION_ARGUMENT`, exactly as `lib/easy.c`'s `easy_perform`
/// returns `CURLE_BAD_FUNCTION_ARGUMENT` when `data` is NULL.
///
/// # Safety
///
/// `handle` must be NULL, or a valid `CURL *` previously returned by
/// [`curl_easy_init`] / [`curl_easy_duphandle`] and not yet cleaned up. Per
/// curl's contract a handle must not be driven concurrently from more than one
/// thread; this call takes an exclusive borrow for its full duration.
///
/// This must not be invoked from within a Tokio runtime context (it is a leaf
/// blocking call and never nests; see [`crate::block_on`]).
#[no_mangle]
pub unsafe extern "C" fn curl_easy_perform(handle: *mut CURL) -> CURLcode {
    // SAFETY: `easy_mut` upholds its contract given this function's identical
    // `# Safety` precondition on `handle`; it yields `None` for NULL.
    let easy = match unsafe { easy_mut(handle) } {
        Some(e) => e,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // Resolve a stored `CURLOPT_CURLU` pointer into an owned URL clone now, at
    // perform time — curl reads the `CURLU` handle here, not at setopt. This is
    // the deferred dereference that implements the store-only contract; a NULL
    // (unset) `uh_ptr` is a no-op.
    // SAFETY: per `curl_easy_perform`'s `# Safety` contract the handle is valid
    // and exclusively borrowed here, and the caller upholds curl's contract that
    // the `CURLU` passed to `CURLOPT_CURLU` remains valid until the transfer.
    unsafe { resolve_curlu(easy) };

    // Materialize a borrowed `CURLOPT_POSTFIELDS` body pointer into owned bytes
    // the safe core can frame (curl reads `data->set.postfields` here, at
    // transfer time, not at setopt). A NULL/unset pointer or the owned
    // `CURLOPT_COPYPOSTFIELDS` path is a no-op.
    // SAFETY: per `curl_easy_perform`'s `# Safety` contract the handle is valid
    // and exclusively borrowed here, and the caller upholds curl's contract that
    // the `CURLOPT_POSTFIELDS` buffer remains valid until the transfer.
    unsafe { resolve_postfields(easy) };

    // Serialize a stored `CURLOPT_HTTPPOST` legacy form chain into an owned
    // `multipart/form-data` body now, at transfer time (curl reads the
    // `curl_httppost *` here, in `Curl_getformdata`, not at setopt). A NULL/unset
    // chain is a no-op; callback (`CURLFORM_STREAM`) parts stream from the
    // handle's `CURLOPT_READFUNCTION`.
    // SAFETY: per `curl_easy_perform`'s `# Safety` contract the handle is valid
    // and exclusively borrowed here, and the caller upholds curl's contract that
    // the `CURLOPT_HTTPPOST` chain (and the read function for callback parts)
    // remains valid until the transfer.
    unsafe { resolve_httppost(easy) };

    // Bridge the consumer's registered C callbacks to the core's sink/source so
    // the transfer routes body/header bytes to `CURLOPT_WRITEFUNCTION` /
    // `HEADERFUNCTION` and pulls upload bytes from `CURLOPT_READFUNCTION`. The
    // stored addresses (`CCallback`/`CDataPtr` are `usize` newtypes) are copied
    // out by value, so the bridges hold no borrow of `easy`. A `0` address means
    // the option was never set and the bridge falls back to curl's default
    // (stdout / stdin), exactly as `Easy::perform` would.
    let mut write_sink = CWriteBridge {
        write_fn: easy.set.fwrite_func.0,
        write_data: easy.set.out.0,
        header_fn: easy.set.fwrite_header.0,
        header_data: easy.set.writeheader.0,
    };
    let mut read_source = CReadBridge {
        read_fn: easy.set.fread_func_set.0,
        read_data: easy.set.in_set.0,
        trailer_fn: easy.set.trailer_callback.0,
        trailer_data: easy.set.trailer_data.0,
        ioctl_fn: easy.set.ioctl_func.0,
        ioctl_data: easy.set.ioctl_client.0,
        // The owning `CURL *` for the legacy ioctl rewind callback's first
        // argument (`curlioerr (*)(CURL *, int, void *)`); available here on the
        // easy path. `easy` reborrows `handle`, so capture the raw address.
        handle: handle as usize,
    };

    // Opt this lone easy handle into deferred-`QUIT`-via-pool-check-in for its
    // OWN connection pool, so a second `curl_easy_perform` on the same handle
    // reuses the still-parked control connection (`tests/data/test539`,
    // `test541`) instead of opening a fresh one. The single deferred `QUIT` is
    // issued by `curl_easy_cleanup` via `drain_own_conn_pool`, on this same
    // thread-local runtime that owns the socket — so it cannot hang. This is
    // gated to self-owned pools (`should_drain_own_pool`), so a handle whose
    // pool was injected by the CLI or a multi handle is never drained here.
    easy.enable_self_pool_drain();

    // Drive the async transfer to completion synchronously. `block_on` runs the
    // future on this thread's current-thread runtime; `result_to_code` collapses
    // the `core::Result<()>` to the exact `CURLcode` the C caller expects.
    result_to_code(block_on(easy.perform_with(&mut write_sink, &mut read_source)))
}

// =============================================================================
// Exported symbol 6 / 13 — curl_easy_setopt  (VARIADIC)
//
// The public, ABI-exported `curl_easy_setopt(CURL *, CURLoption, ...)` symbol is
// a genuine C-variadic trampoline defined in `csrc/variadic_trampolines.c`
// (compiled and whole-archive-linked by `build.rs`). Stable Rust cannot DEFINE a
// C-variadic `extern "C"` function (that needs the nightly-only `c_variadic`
// feature), and a fixed-arity `extern "C" fn(.., arg: usize)` is NOT ABI-
// equivalent to a variadic on every target — notably macOS arm64 passes the
// first variadic argument on the stack while a fixed parameter would occupy a
// register, so a fixed-arity shim would read the wrong slot (AAP §0.7.2 / §0.8.3
// document this C-trampoline exception). The trampoline therefore owns the
// exported `curl_easy_setopt` name, extracts the single trailing argument with
// `va_arg` per the C ABI, and forwards it here. This function is the typed Rust
// implementation it dispatches to; it is named `curlrs_easy_setopt_impl` (the
// non-`curl_` prefix keeps it out of the exported `curl_*` ABI surface) and is
// reached only through the C trampoline.
// =============================================================================

/// Typed Rust implementation behind the public `curl_easy_setopt` C-variadic
/// trampoline (the analog of `lib/setopt.c`, `include/curl/easy.h`).
///
/// The C trampoline (`csrc/variadic_trampolines.c`) extracts the single trailing
/// `curl_easy_setopt(handle, option, param)` argument with `va_arg` and forwards
/// it here as a fixed pointer-width `arg` (the C call carries exactly one trailing
/// argument, guaranteed by the three-argument enforcement macro in
/// `include/curl/easy.h`). `arg` is decoded according to `option`'s value type
/// (recorded in the canonical option table) and applied to the core handle:
///
/// * `CURLOT_LONG` / `CURLOT_VALUES` — `arg` is a C `long`.
/// * `CURLOT_OFF_T` — `arg` is a `curl_off_t`.
/// * `CURLOT_STRING` — `arg` is a `char *` (copied into an owned string; NULL
///   clears the option).
/// * `CURLOT_SLIST` — `arg` is a `struct curl_slist *` (deep-copied; NULL
///   clears the list).
/// * `CURLOT_CBPTR` — `arg` is an opaque `void *` callback-data pointer.
/// * `CURLOT_BLOB` — `arg` is a `struct curl_blob *` (the bytes are copied).
/// * `CURLOT_FUNCTION` — `arg` is a callback function pointer.
/// * `CURLOT_OBJECT` — `arg` is a `void *` object handle: `CURLOPT_SHARE`
///   takes a `CURLSH *`, `CURLOPT_CURLU` a `CURLU *`, `CURLOPT_COPYPOSTFIELDS`
///   the binary POST body (subject to the `CURLOPT_POSTFIELDSIZE` length rule),
///   and every other object option an opaque pointer stored as an address.
///
/// # Return values (mirrors `lib/setopt.c`)
///
/// * `CURLE_BAD_FUNCTION_ARGUMENT` — `handle` is NULL, or `arg` is the wrong
///   shape for `option`.
/// * `CURLE_UNKNOWN_OPTION` — `option` is not a recognized `CURLoption`.
/// * `CURLE_NOT_BUILT_IN` — the option's feature is compiled out of this build.
/// * `CURLE_OK` — success.
///
/// # Safety
///
/// `handle` must be NULL or a valid `CURL *` from [`curl_easy_init`] /
/// [`curl_easy_duphandle`] not yet cleaned up. For pointer-typed options `arg`
/// must be NULL or a valid pointer of the exact type `option` requires
/// (`char *`, `struct curl_slist *`, `struct curl_blob *`, `CURLSH *`,
/// `CURLU *`, a function pointer, or an opaque object pointer), valid for reads
/// for the duration of this call; for `CURLOPT_COPYPOSTFIELDS` the pointed-to
/// region must hold at least `CURLOPT_POSTFIELDSIZE` bytes (or be a
/// NUL-terminated string when the size is unset/`-1`).
#[no_mangle]
pub unsafe extern "C" fn curlrs_easy_setopt_impl(
    handle: *mut CURL,
    option: CURLoption,
    arg: usize,
) -> CURLcode {
    // SAFETY: `easy_mut` upholds its contract given this function's `# Safety`
    // precondition on `handle`. curl rejects a NULL handle with
    // CURLE_BAD_FUNCTION_ARGUMENT (`lib/setopt.c`).
    let easy = match unsafe { easy_mut(handle) } {
        Some(e) => e,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // Resolve the raw option id; an unrecognized option maps to
    // CURLE_UNKNOWN_OPTION, matching curl's `default:` switch arm.
    let opt = match core::CurlOption::from_i32(option) {
        Some(o) => o,
        None => return CURLcode::CURLE_UNKNOWN_OPTION,
    };

    // The CURLOPT_COPYPOSTFIELDS length rule needs the handle's current
    // postfieldsize; read it (a `Copy` i64) before the marshalling borrow so no
    // borrow conflict arises with the `&mut` setopt call below.
    let postfieldsize = easy.set.postfieldsize;

    // SAFETY: `build_option_value` upholds its pointer-validity contract given
    // this function's `# Safety` precondition on `arg`.
    let value = unsafe { build_option_value(opt, arg, postfieldsize) };

    // The typed core setter validates the value shape against the option and
    // returns the `CurlError` that `result_to_code` maps to the exact `CURLcode`
    // (a mismatched shape yields CURLE_BAD_FUNCTION_ARGUMENT).
    result_to_code(easy.setopt(opt, value))
}

/// Marshal the single trailing `curl_easy_setopt` argument into a typed
/// [`core::OptionValue`](curl_rs_lib::OptionValue), classified by the option's
/// value type in the canonical option table.
///
/// `postfieldsize` is the handle's current `CURLOPT_POSTFIELDSIZE[_LARGE]`
/// (default `-1`), used only for the `CURLOPT_COPYPOSTFIELDS` length rule.
///
/// # Safety
///
/// For pointer-typed options `arg` must satisfy the validity contract documented
/// on [`curl_easy_setopt`].
unsafe fn build_option_value(
    opt: core::CurlOption,
    arg: usize,
    postfieldsize: i64,
) -> core::OptionValue {
    use core::options::CurlOptType as T;
    use core::OptionValue as V;

    // `option_by_id` is the canonical inverse lookup; it is always `Some` for an
    // `opt` obtained from `CurlOption::from_i32` (both scan the same table), but
    // the coarse CURLOPTTYPE group is used as a defensive fallback.
    match core::options::option_by_id(opt).map(|e| e.typ) {
        // The trailing arg is a C `long`; reinterpret the pointer-width slot as
        // `c_long` (== `i64` on the LP64 build matrix), the type `OptionValue::Long`
        // stores, preserving the sign of negative long values.
        Some(T::Long) | Some(T::Values) => V::Long(arg as c_long),
        Some(T::OffT) => V::OffT(arg as i64),
        // SAFETY: a STRING option's `arg` is NULL or a valid C string per the
        // `# Safety` contract.
        Some(T::String) => V::Str(unsafe { cstr_to_string(arg) }),
        // SAFETY: an SLIST option's `arg` is NULL or a valid `curl_slist` chain.
        Some(T::Slist) => V::Slist(unsafe { slist_arg_to_core(arg) }),
        Some(T::Cbptr) => V::Ptr(core::setopt::CDataPtr(arg)),
        // SAFETY: a BLOB option's `arg` is NULL or a valid `curl_blob`.
        Some(T::Blob) => V::Blob(unsafe { blob_arg_to_core(arg) }),
        Some(T::Function) => V::Callback(core::setopt::CCallback(arg)),
        // SAFETY: an OBJECT option's `arg` satisfies the per-option contract.
        Some(T::Object) => unsafe { build_object_value(opt, arg, postfieldsize) },
        None => match opt.type_group() {
            core::options::CurloptTypeGroup::Long => V::Long(arg as c_long),
            core::options::CurloptTypeGroup::OffT => V::OffT(arg as i64),
            core::options::CurloptTypeGroup::FunctionPoint => {
                V::Callback(core::setopt::CCallback(arg))
            }
            // SAFETY: classified as a BLOB pointer by its option-number base.
            core::options::CurloptTypeGroup::Blob => V::Blob(unsafe { blob_arg_to_core(arg) }),
            core::options::CurloptTypeGroup::ObjectPoint => V::Ptr(core::setopt::CDataPtr(arg)),
        },
    }
}

/// Marshal a `CURLOT_OBJECT` option's pointer argument. Most object options are
/// opaque `void *` stored as an address; `CURLOPT_SHARE`, `CURLOPT_CURLU` and
/// `CURLOPT_COPYPOSTFIELDS` are the typed exceptions.
///
/// # Safety
///
/// `arg` must satisfy the per-option validity contract documented on
/// [`curl_easy_setopt`].
unsafe fn build_object_value(
    opt: core::CurlOption,
    arg: usize,
    postfieldsize: i64,
) -> core::OptionValue {
    use core::CurlOption as O;
    use core::OptionValue as V;

    match opt {
        // SAFETY: `CURLOPT_SHARE`'s `arg` is NULL or a live `CURLSH *`.
        O::CURLOPT_SHARE => V::Share(unsafe { clone_share(arg) }),
        // `CURLOPT_CURLU` stores the caller's `CURLU *` as an opaque address
        // WITHOUT dereferencing it, honouring curl's store-only contract
        // (`lib/setopt.c`: `s->uh = (CURLU *)ptr;`). The pointer is dereferenced
        // and cloned into the handle only at perform time (see [`resolve_curlu`],
        // invoked by [`curl_easy_perform`] and `curl_multi_add_handle`). This is
        // a plain address store — no `unsafe` — so the dummy pointer that
        // `tests/libtest/lib1521` deliberately passes to verify the contract is
        // accepted without being touched.
        O::CURLOPT_CURLU => V::Ptr(core::setopt::CDataPtr(arg)),
        // SAFETY: `CURLOPT_COPYPOSTFIELDS`'s `arg` is NULL or points to a body of
        // the length implied by `postfieldsize`.
        O::CURLOPT_COPYPOSTFIELDS => V::Bytes(unsafe { copy_postfields(arg, postfieldsize) }),
        // POSTFIELDS, HTTPPOST, MIMEPOST, STDERR, PRIVATE, STREAM_DEPENDS[_E], …:
        // opaque pointers stored as an address (the core interprets them).
        _ => V::Ptr(core::setopt::CDataPtr(arg)),
    }
}

/// Copy a C `char *` into an owned `String` (NULL → `None`).
///
/// Non-UTF-8 bytes are converted lossily, since the core stores string options
/// as `String`; curl's string options are ASCII/UTF-8 in practice.
///
/// # Safety
/// `arg` is `0` (NULL) or a valid NUL-terminated C string readable for the call.
#[inline]
unsafe fn cstr_to_string(arg: usize) -> Option<String> {
    if arg == 0 {
        None
    } else {
        // SAFETY: per the contract `arg` is a valid NUL-terminated C string.
        let cstr = unsafe { CStr::from_ptr(arg as *const c_char) };
        Some(cstr.to_string_lossy().into_owned())
    }
}

/// Deep-copy a `struct curl_slist *` argument into an owned core `SList`
/// (NULL → `None`, which clears the list option).
///
/// # Safety
/// `arg` is `0` (NULL) or a valid `curl_slist` chain readable for the call.
#[inline]
unsafe fn slist_arg_to_core(arg: usize) -> Option<core::SList> {
    if arg == 0 {
        None
    } else {
        // SAFETY: per the contract `arg` points to a valid `curl_slist` chain;
        // `raw_to_core` walks it and deep-copies the node strings without taking
        // ownership of the C nodes.
        Some(unsafe { slist::raw_to_core(arg as *const curl_slist) })
    }
}

/// Copy a `struct curl_blob *` argument into an owned core [`Blob`] (NULL →
/// `None`). The bytes are always copied so the core owns them, regardless of the
/// `CURL_BLOB_COPY` / `CURL_BLOB_NOCOPY` flag (memory safety mandates ownership).
///
/// # Safety
/// `arg` is `0` (NULL) or a valid `curl_blob` whose `data`/`len` describe a
/// readable region for the call.
#[inline]
unsafe fn blob_arg_to_core(arg: usize) -> Option<core::setopt::Blob> {
    if arg == 0 {
        return None;
    }
    // SAFETY: per the contract `arg` points to a valid `curl_blob`.
    let blob = unsafe { &*(arg as *const curl_blob) };
    let bytes = if blob.data.is_null() || blob.len == 0 {
        Vec::new()
    } else {
        // SAFETY: the `curl_blob` contract guarantees `data` points to `len`
        // readable bytes; we copy them into an owned `Vec`. (`size_t` is `usize`,
        // so `blob.len` is passed to `from_raw_parts` without a cast.)
        unsafe { slice::from_raw_parts(blob.data as *const u8, blob.len) }.to_vec()
    };
    Some(core::setopt::Blob {
        data: bytes,
        // `curl_blob.flags` is a `c_uint` (always 32-bit), exactly the core
        // `Blob.flags` `u32` — no cast needed.
        flags: blob.flags,
    })
}

/// Clone the [`core::Share`](curl_rs_lib::Share) behind a `CURLSH *` argument
/// (NULL → `None`, disconnecting any share). `Share` is `Arc`-backed, so the
/// clone is a reference-count bump sharing the same state — curl's attach
/// semantics.
///
/// # Safety
/// `arg` is `0` (NULL) or a live `CURLSH *` from `curl_share_init`.
#[inline]
unsafe fn clone_share(arg: usize) -> Option<core::Share> {
    if arg == 0 {
        None
    } else {
        // SAFETY: per the contract `arg` is a live `core::Share` (`Box::into_raw`
        // of a `Share` by `curl_share_init`); a shared borrow to clone is sound.
        Some(unsafe { &*(arg as *const core::Share) }.clone())
    }
}

/// Resolve a handle's stored `CURLOPT_CURLU` pointer into an owned URL clone,
/// just before a transfer is driven — the deferred dereference that implements
/// curl's store-only `CURLOPT_CURLU` contract.
///
/// `curl_easy_setopt(CURLOPT_CURLU, ptr)` stores `ptr` verbatim in
/// `easy.set.uh_ptr` without touching it (matching `lib/setopt.c`'s
/// `s->uh = (CURLU *)ptr;`), so a dummy pointer that is never performed against
/// (as `tests/libtest/lib1521` passes) cannot crash. curl reads the handle at
/// perform time; this function reproduces that by dereferencing the stored
/// pointer and depositing an owned [`core::url::CurlUrl`] clone into
/// `easy.set.uh`, which the transfer engine then reads (`Easy::pre_perform`).
///
/// A `NULL` (`0`) stored pointer leaves `easy.set.uh` untouched, so a handle
/// configured purely via `CURLOPT_URL` — or driven directly by the core without
/// the FFI — is unaffected. Re-resolving on every perform mirrors curl's
/// read-at-perform behaviour: a caller that mutates its `CURLU` between performs
/// sees the change reflected.
///
/// # Safety
///
/// If `easy.set.uh_ptr` is non-NULL it must be a live `CURLU *` produced by
/// `curl_url` / `curl_url_dup` (a `Box::into_raw` of a [`core::url::CurlUrl`])
/// that has not been cleaned up — i.e. the caller upholds curl's contract that
/// the `CURLU` handle supplied to `CURLOPT_CURLU` stays valid until the transfer
/// is performed. `easy` must be a unique borrow (curl's single-thread-per-handle
/// contract), so writing `easy.set.uh` is sound.
pub(crate) unsafe fn resolve_curlu(easy: &mut core::Easy) {
    let addr = easy.set.uh_ptr.0;
    if addr != 0 {
        // SAFETY: per this function's contract `addr` is a live `CURLU *`
        // (`Box::into_raw` of a `core::url::CurlUrl` by `curl_url`/`curl_url_dup`,
        // not yet cleaned up). A shared borrow to deep-copy is sound, and the
        // caller owns the original; we only clone it.
        let url = unsafe { &*(addr as *const core::url::CurlUrl) }.clone();
        easy.set.uh = Some(url);
    }
}

/// Resolve a handle's borrowed `CURLOPT_POSTFIELDS` body pointer into owned
/// bytes the safe core can frame, just before a transfer is driven — the
/// deferred dereference that mirrors curl reading `data->set.postfields` at
/// transfer time.
///
/// `curl_easy_setopt(CURLOPT_POSTFIELDS, ptr)` stores `ptr` verbatim in
/// `easy.set.postfields` *without copying* — the caller must keep the buffer
/// alive until the transfer (matching `lib/setopt.c`) — and clears the owned
/// `easy.set.copypostfields`. The safe core (`#![forbid(unsafe_code)]`) cannot
/// dereference a raw pointer, so this function deposits an owned copy into
/// `easy.set.copypostfields` (the single in-memory POST body the transfer
/// engine reads), applying curl's `POSTFIELDSIZE`-vs-`strlen` length rule — the
/// very rule the owned `CURLOPT_COPYPOSTFIELDS` path uses.
///
/// `CURLOPT_COPYPOSTFIELDS` already populates `copypostfields` at setopt time
/// and leaves `postfields` NULL, so this is a no-op for it. A NULL/unset
/// `postfields` (for example a read-callback POST that set
/// `CURLOPT_POSTFIELDS, NULL`) is likewise left untouched, preserving the
/// read-callback upload path. Re-resolving on every perform mirrors curl's
/// read-at-perform behaviour: a caller that mutates the pointed-to body between
/// performs sees the change reflected.
///
/// # Safety
///
/// If `easy.set.postfields` is non-NULL it must point to a live body of at
/// least `easy.set.postfieldsize` bytes (or a NUL-terminated C string when
/// `postfieldsize < 0`) that stays valid for this call — curl's contract that
/// the `CURLOPT_POSTFIELDS` buffer remains valid until the transfer is
/// performed. `easy` must be a unique borrow (curl's single-thread-per-handle
/// contract), so writing `easy.set.copypostfields` is sound.
pub(crate) unsafe fn resolve_postfields(easy: &mut core::Easy) {
    if let Some(ptr) = easy.set.postfields {
        if ptr.0 != 0 {
            // SAFETY: per this function's contract `ptr.0` points to a live body
            // honoring the `POSTFIELDSIZE`-vs-`strlen` length rule; the shared
            // `copy_postfields` applies that exact rule and copies the bytes.
            easy.set.copypostfields = unsafe { copy_postfields(ptr.0, easy.set.postfieldsize) };
        }
    }
}

/// Materialize a stored `CURLOPT_HTTPPOST` legacy form chain into an owned
/// `multipart/form-data` body the safe core can frame — the deferred-dereference
/// analog of [`resolve_postfields`] for the legacy `curl_formadd` form API. curl
/// reads the `curl_httppost *` here, at transfer time (its `Curl_getformdata`
/// runs as the request is set up), not at setopt, so this is the perform-time
/// dereference of the address `setopt` stored opaquely. The chain-walk and
/// `multipart/form-data` serialization live in
/// [`crate::mime::httppost_chain_to_body`] (which owns the `curl_httppost`
/// imports and the read-callback bridge); `CURL_HTTPPOST_CALLBACK`
/// (`CURLFORM_STREAM`) parts are streamed from the handle's
/// `CURLOPT_READFUNCTION`. The produced body and its boundary-bearing
/// `Content-Type` are handed to the core via `set_mime_body`, exactly as the CLI
/// `-F` path does, so the request is byte-for-byte curl's. A NULL/unset chain
/// (`httppost.0 == 0`) makes the helper return `None` and is a no-op.
///
/// # Safety
///
/// Per `curl_easy_perform`'s contract the handle is valid and exclusively
/// borrowed here, and the caller upholds curl's contract that the
/// `curl_httppost` chain passed to `CURLOPT_HTTPPOST` (and the read function and
/// its per-part `userp` for any callback parts) remains valid until the transfer.
pub(crate) unsafe fn resolve_httppost(easy: &mut core::Easy) {
    // SAFETY: the stored chain and read-function addresses are valid per this
    // function's contract; the mime helper walks the chain (a no-op for a 0
    // address) and drives any callback parts through the read function.
    if let Some((body, content_type)) = unsafe {
        crate::mime::httppost_chain_to_body(easy.set.httppost.0, easy.set.fread_func_set.0)
    } {
        easy.set_mime_body(body, content_type);
    }
}

/// Apply curl's `CURLOPT_COPYPOSTFIELDS` length rule and copy the body bytes
/// (NULL → `None`). With `postfieldsize < 0` the data is a NUL-terminated string
/// (length via the C string's length); otherwise exactly `postfieldsize` bytes
/// are copied.
///
/// # Safety
/// `arg` is `0` (NULL), or points to either a NUL-terminated C string (when
/// `postfieldsize < 0`) or at least `postfieldsize` readable bytes.
#[inline]
unsafe fn copy_postfields(arg: usize, postfieldsize: i64) -> Option<Vec<u8>> {
    if arg == 0 {
        return None;
    }
    let len = if postfieldsize < 0 {
        // SAFETY: with size < 0 curl treats the data as a NUL-terminated C string,
        // which the caller guarantees `arg` to be.
        unsafe { CStr::from_ptr(arg as *const c_char) }
            .to_bytes()
            .len()
    } else {
        postfieldsize as usize
    };
    if len == 0 {
        return Some(Vec::new());
    }
    // SAFETY: per the contract `arg` points to at least `len` readable bytes.
    Some(unsafe { slice::from_raw_parts(arg as *const u8, len) }.to_vec())
}

// =============================================================================
// Exported symbol 7 / 13 — curl_easy_getinfo  (VARIADIC)
//
// As with `curl_easy_setopt` above, the public, ABI-exported
// `curl_easy_getinfo(CURL *, CURLINFO, ...)` symbol is a genuine C-variadic
// trampoline in `csrc/variadic_trampolines.c`; it extracts the single trailing
// argument with `va_arg` and forwards it to this typed Rust implementation,
// named `curlrs_easy_getinfo_impl`. The trailing `curl_easy_getinfo` argument is
// always an output pointer, so the trampoline reads one pointer-width slot.
// =============================================================================

/// Typed Rust implementation behind the public `curl_easy_getinfo` C-variadic
/// trampoline (the analog of `lib/getinfo.c`, `include/curl/easy.h`).
///
/// The C trampoline forwards the single trailing
/// `curl_easy_getinfo(handle, info, arg)` argument here
/// (guaranteed by the three-argument enforcement macro); `arg` is a pointer to
/// caller-provided storage whose type is fixed by `info`'s `CURLINFO_*` type
/// group: `long*`, `curl_off_t*`, `double*`, `curl_socket_t*`, `const char**`,
/// `struct curl_slist**`, or `void**`. The retrieved value is written through
/// `arg`.
///
/// Ownership of the written results follows curl's contract (AAP §0.7.4): a
/// `CURLINFO_*` string borrows handle-owned storage and stays valid only until
/// the next call on the handle (the caller must not free it); a `CURLINFO_*`
/// slist is a fresh, caller-owned chain that must be released with
/// `curl_slist_free_all`.
///
/// # Return values (mirrors `lib/getinfo.c`)
///
/// * `CURLE_BAD_FUNCTION_ARGUMENT` — `handle` or `arg` is NULL.
/// * `CURLE_UNKNOWN_OPTION` — `info` is not a recognized `CURLINFO`.
/// * `CURLE_OK` — success (the value was written through `arg`).
///
/// # Safety
///
/// `handle` must be NULL or a valid `CURL *` from [`curl_easy_init`] /
/// [`curl_easy_duphandle`] not yet cleaned up. `arg` must be NULL or a valid,
/// well-aligned, writable pointer to storage of the exact type `info` requires.
#[no_mangle]
pub unsafe extern "C" fn curlrs_easy_getinfo_impl(
    handle: *mut CURL,
    info: CURLINFO,
    arg: usize,
) -> CURLcode {
    // SAFETY: `easy_ref` upholds its contract given this function's `# Safety`
    // precondition on `handle`. curl returns CURLE_BAD_FUNCTION_ARGUMENT for a
    // NULL handle (`lib/getinfo.c`).
    let easy = match unsafe { easy_ref(handle) } {
        Some(e) => e,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // An unrecognized info maps to CURLE_UNKNOWN_OPTION (curl's type-dispatch
    // `default:` arm) — checked before the output pointer, since curl never
    // dereferences `arg` for an unknown info.
    let which = match core::CurlInfo::from_raw(info) {
        Some(i) => i,
        None => return CURLcode::CURLE_UNKNOWN_OPTION,
    };

    // Guard the output pointer: curl would dereference it unconditionally
    // (a NULL is undefined behavior in C); we instead reject NULL safely.
    if arg == 0 {
        return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
    }

    match easy.getinfo(which) {
        Ok(value) => {
            // SAFETY: `arg` is non-null and, per the `# Safety` contract, points to
            // caller storage of the type `which`'s group implies, which is exactly
            // the type `write_info_value` writes for that `InfoValue` variant.
            unsafe { write_info_value(value, arg) };
            CURLcode::CURLE_OK
        }
        // On failure nothing is written; map the core error to its `CURLcode`.
        Err(e) => CURLcode::from(e),
    }
}

/// Write a retrieved [`core::InfoValue`](curl_rs_lib::InfoValue) through the
/// caller's `curl_easy_getinfo` output pointer, in the representation curl's
/// `CURLINFO_*` type group requires.
///
/// # Safety
///
/// `arg` must be a non-null, well-aligned pointer to caller storage of the type
/// implied by the info's type group: `long*` for LONG, `curl_off_t*` for OFF_T,
/// `double*` for DOUBLE, `curl_socket_t*` for SOCKET, `const char**` for STRING,
/// `struct curl_slist**` for SLIST, and `void**` for PTR.
unsafe fn write_info_value(value: core::InfoValue<'_>, arg: usize) {
    use core::getinfo::InfoPtr;
    use core::InfoValue as V;

    match value {
        V::Long(v) => {
            // SAFETY: a LONG info's `arg` is a valid, writable `long*`.
            unsafe { *(arg as *mut c_long) = v as c_long };
        }
        V::OffT(v) => {
            // SAFETY: an OFF_T info's `arg` is a valid, writable `curl_off_t*`.
            unsafe { *(arg as *mut curl_off_t) = v };
        }
        V::Double(v) => {
            // SAFETY: a DOUBLE info's `arg` is a valid, writable `double*`.
            unsafe { *(arg as *mut c_double) = v };
        }
        V::Socket(v) => {
            // SAFETY: a SOCKET info's `arg` is a valid, writable `curl_socket_t*`.
            // `CurlSocket` is the wider host type; the cast narrows to the C
            // `curl_socket_t` exactly as curl stores the descriptor.
            unsafe { *(arg as *mut curl_socket_t) = v as curl_socket_t };
        }
        V::Str(s) => {
            let p = match s {
                Some(cstr) => cstr.as_ptr(),
                None => ptr::null(),
            };
            // SAFETY: a STRING info's `arg` is a valid, writable `const char**`.
            // The written pointer (when non-null) borrows handle-owned storage
            // valid until the next call on the handle (curl's contract); the
            // caller must not free it.
            unsafe { *(arg as *mut *const c_char) = p };
        }
        V::Slist(s) => {
            let p = match s {
                Some(list) => slist::core_to_raw(list),
                None => ptr::null_mut(),
            };
            // SAFETY: an SLIST info's `arg` is a valid, writable
            // `struct curl_slist**`. The written chain (when non-null) is freshly
            // built and owned by the caller, who must release it with
            // `curl_slist_free_all`.
            unsafe { *(arg as *mut *mut curl_slist) = p };
        }
        V::Ptr(InfoPtr::Private(addr)) => {
            // SAFETY: CURLINFO_PRIVATE's `arg` is a valid, writable `void**`
            // (curl also accepts `char**`); the stored `CURLOPT_PRIVATE` address
            // is written through unchanged.
            unsafe { *(arg as *mut *mut c_void) = addr as *mut c_void };
        }
        // CURLINFO_CERTINFO / CURLINFO_TLS_SSL_PTR / CURLINFO_TLS_SESSION: the
        // C-visible `struct curl_certinfo` / `struct curl_tlssessioninfo` are not
        // yet defined in `types.rs`, and the safe core does not yet populate the
        // certificate chain or TLS-session info at this layer. The memory-safe,
        // forward-compatible representation of "no info available" is a NULL
        // out-pointer — exactly what curl yields before a TLS handshake has
        // produced any such data. Marshalling the `#[repr(C)]` structs is a
        // dedicated FFI task tracked separately (see this file's completion note).
        V::Ptr(InfoPtr::CertInfo(_)) | V::Ptr(InfoPtr::TlsSession(_)) => {
            // SAFETY: a PTR info's `arg` is a valid, writable `void**`; writing a
            // NULL pointer through it is sound.
            unsafe { *(arg as *mut *mut c_void) = ptr::null_mut() };
        }
    }
}

// =============================================================================
// Exported symbol 8 / 13 — curl_easy_recv
// =============================================================================

/// Receive raw bytes on a `CONNECT_ONLY` connection (`curl_easy_recv`,
/// `include/curl/easy.h`).
///
/// Reads up to `buflen` bytes into `buffer`, storing the number received in
/// `*n`. Like curl this is only meaningful on a connection established with
/// `CURLOPT_CONNECT_ONLY`. The (synchronous) core read runs inside the
/// [`crate::block_on`] bridge so it executes within a Tokio runtime context,
/// mirroring the sibling `curl_ws_recv`. A would-block condition maps to
/// `CURLE_AGAIN`; a NULL handle yields `CURLE_BAD_FUNCTION_ARGUMENT` (matching
/// `lib/easy.c`).
///
/// # Safety
///
/// `handle` must be NULL or a valid, not-cleaned-up `CURL *`. When non-NULL and
/// `buflen > 0`, `buffer` must point to at least `buflen` writable bytes; `n`
/// must be NULL or a valid, writable `size_t*`. All must remain valid for the
/// duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_recv(
    handle: *mut CURL,
    buffer: *mut c_void,
    buflen: size_t,
    n: *mut size_t,
) -> CURLcode {
    // SAFETY: `easy_mut` upholds its contract given this function's `# Safety`
    // precondition; NULL handle → BAD_FUNCTION_ARGUMENT (`lib/easy.c`).
    let easy = match unsafe { easy_mut(handle) } {
        Some(e) => e,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // A writable view over the caller's buffer; an empty/NULL buffer is a
    // zero-length read.
    let dst: &mut [u8] = if buffer.is_null() || buflen == 0 {
        &mut []
    } else {
        // SAFETY: per the `# Safety` contract `buffer` points to `buflen` writable
        // bytes for the duration of the call (`size_t` is `usize`).
        unsafe { slice::from_raw_parts_mut(buffer as *mut u8, buflen) }
    };

    // Drive the core's async raw recv inside the runtime bridge (mirrors
    // `curl_ws_recv`); `block_on` honors curl's synchronous `curl_easy_recv`.
    match block_on(async move { easy.recv(dst).await }) {
        Ok(received) => {
            if !n.is_null() {
                // SAFETY: per the contract `n` is a valid `size_t*` when non-null.
                unsafe { *n = received };
            }
            CURLcode::CURLE_OK
        }
        Err(e) => {
            if !n.is_null() {
                // SAFETY: per the contract `n` is a valid `size_t*` when non-null.
                unsafe { *n = 0 };
            }
            // A would-block maps to CURLE_AGAIN via the `From<CurlError>` impl.
            CURLcode::from(e)
        }
    }
}

// =============================================================================
// Exported symbol 9 / 13 — curl_easy_send
// =============================================================================

/// Send raw bytes on a `CONNECT_ONLY` connection (`curl_easy_send`,
/// `include/curl/easy.h`).
///
/// Writes up to `buflen` bytes from `buffer`, storing the number sent in `*n`.
/// Like curl this is only meaningful on a `CURLOPT_CONNECT_ONLY` connection. The
/// (synchronous) core write runs inside the [`crate::block_on`] bridge, mirroring
/// the sibling `curl_ws_send`. A would-block condition maps to `CURLE_AGAIN`; a
/// NULL handle yields `CURLE_BAD_FUNCTION_ARGUMENT` (matching `lib/easy.c`).
///
/// # Safety
///
/// `handle` must be NULL or a valid, not-cleaned-up `CURL *`. When non-NULL and
/// `buflen > 0`, `buffer` must point to at least `buflen` readable bytes; `n`
/// must be NULL or a valid, writable `size_t*`. All must remain valid for the
/// duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_send(
    handle: *mut CURL,
    buffer: *const c_void,
    buflen: size_t,
    n: *mut size_t,
) -> CURLcode {
    // SAFETY: `easy_mut` upholds its contract given this function's `# Safety`
    // precondition; NULL handle → BAD_FUNCTION_ARGUMENT (`lib/easy.c`).
    let easy = match unsafe { easy_mut(handle) } {
        Some(e) => e,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // A read-only view over the caller's payload; an empty/NULL buffer is a
    // zero-length send.
    let src: &[u8] = if buffer.is_null() || buflen == 0 {
        &[]
    } else {
        // SAFETY: per the `# Safety` contract `buffer` points to `buflen` readable
        // bytes for the duration of the call (`size_t` is `usize`).
        unsafe { slice::from_raw_parts(buffer as *const u8, buflen) }
    };

    // Run the (synchronous) core send inside the runtime bridge.
    match block_on(async move { easy.send(src).await }) {
        Ok(sent) => {
            if !n.is_null() {
                // SAFETY: per the contract `n` is a valid `size_t*` when non-null.
                unsafe { *n = sent };
            }
            CURLcode::CURLE_OK
        }
        Err(e) => {
            if !n.is_null() {
                // SAFETY: per the contract `n` is a valid `size_t*` when non-null.
                unsafe { *n = 0 };
            }
            // A would-block maps to CURLE_AGAIN via the `From<CurlError>` impl.
            CURLcode::from(e)
        }
    }
}

// =============================================================================
// Exported symbol 10 / 13 — curl_easy_upkeep
// =============================================================================

/// Perform connection-pool upkeep (`curl_easy_upkeep`, `include/curl/curl.h`).
///
/// Runs maintenance over the handle's connection cache (curl pings idle
/// connections whose keep-alive interval has elapsed, e.g. via HTTP/2 PING).
/// The (synchronous) core upkeep runs inside the [`crate::block_on`] bridge so
/// any such I/O executes within a Tokio runtime context. With no connections
/// attached this is a successful no-op. A NULL handle yields
/// `CURLE_BAD_FUNCTION_ARGUMENT` (matching `lib/easy.c`).
///
/// # Safety
///
/// `handle` must be NULL or a valid `CURL *` from [`curl_easy_init`] /
/// [`curl_easy_duphandle`] not yet cleaned up.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_upkeep(handle: *mut CURL) -> CURLcode {
    // SAFETY: `easy_ref` upholds its contract given this function's `# Safety`
    // precondition; NULL handle → BAD_FUNCTION_ARGUMENT (`lib/easy.c`).
    let easy = match unsafe { easy_ref(handle) } {
        Some(e) => e,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // Run the (synchronous) core upkeep inside the runtime bridge.
    result_to_code(block_on(async move { easy.upkeep() }))
}

// =============================================================================
// Exported symbol 11 / 13 — curl_easy_pause
// =============================================================================

/// Pause or resume a transfer's directions (`curl_easy_pause`,
/// `include/curl/curl.h`).
///
/// `bitmask` is the `CURLPAUSE_*` set ([`CURLPAUSE_RECV`] / [`CURLPAUSE_SEND`]
/// to pause, [`CURLPAUSE_CONT`] to resume both, [`CURLPAUSE_ALL`] to pause
/// both); bits absent from `bitmask` are cleared. Pausing is a pure handle-state
/// toggle with no network I/O, so it is invoked directly (no runtime bridge).
/// Matching `lib/easy.c`, a NULL handle — or one with no active connection —
/// yields `CURLE_BAD_FUNCTION_ARGUMENT`.
///
/// # Safety
///
/// `handle` must be NULL or a valid `CURL *` from [`curl_easy_init`] /
/// [`curl_easy_duphandle`] not yet cleaned up.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_pause(handle: *mut CURL, bitmask: c_int) -> CURLcode {
    // SAFETY: `easy_mut` upholds its contract given this function's `# Safety`
    // precondition; NULL handle → BAD_FUNCTION_ARGUMENT (`lib/easy.c`).
    let easy = match unsafe { easy_mut(handle) } {
        Some(e) => e,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // The core applies the bitmask and returns BadFunctionArgument when no
    // connection is attached, exactly as curl's `!data->conn` guard does.
    result_to_code(easy.pause(bitmask))
}

// =============================================================================
// Exported symbol 12 / 13 — curl_easy_ssls_import
// =============================================================================

/// Import a TLS session into the SSL session cache (`curl_easy_ssls_import`,
/// `include/curl/curl.h`).
///
/// The SSL-session export/import feature (curl's `USE_SSLS_EXPORT`) is **not
/// built in**: rustls is the workspace's sole TLS backend and exposes no
/// session-ticket import hook, and the `"SSLS-EXPORT"` capability is reported
/// off by `curl_version`. Matching `lib/easy.c`'s `#else` branch, this ignores
/// every argument and returns `CURLE_NOT_BUILT_IN` unconditionally. The exact
/// ABI signature is preserved regardless, so the symbol is present for the
/// `nm`/`objdump` parity gate and for `tests/libtest`.
///
/// # Safety
///
/// Declared `unsafe extern "C"` to match curl's published FFI surface; it
/// dereferences none of its arguments, so any pointer values (including NULL)
/// are accepted.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_ssls_import(
    handle: *mut CURL,
    session_key: *const c_char,
    shmac: *const c_uchar,
    shmac_len: size_t,
    sdata: *const c_uchar,
    sdata_len: size_t,
) -> CURLcode {
    // Feature compiled out — ignore all arguments (no dereference) and report
    // not-built-in, exactly as curl's `#else` branch `(void)`-discards them.
    let _ = (handle, session_key, shmac, shmac_len, sdata, sdata_len);
    CURLcode::CURLE_NOT_BUILT_IN
}

// =============================================================================
// Exported symbol 13 / 13 — curl_easy_ssls_export
// =============================================================================

/// Export the TLS sessions from the SSL session cache (`curl_easy_ssls_export`,
/// `include/curl/curl.h`).
///
/// Not built in for the same reason as [`curl_easy_ssls_import`]: rustls exposes
/// no session-ticket export hook and the `"SSLS-EXPORT"` capability is reported
/// off. Matching `lib/easy.c`'s `#else` branch, this ignores every argument
/// (including the `curl_ssls_export_cb` callback pointer, represented as the
/// nullable `Option<curl_ssls_export_cb>`) and returns `CURLE_NOT_BUILT_IN`
/// unconditionally. The exact ABI signature is preserved for the symbol-parity
/// gate and `tests/libtest`.
///
/// # Safety
///
/// Declared `unsafe extern "C"` to match curl's published FFI surface; it
/// neither dereferences `userptr` nor invokes `export_fn`, so any pointer values
/// (including NULL) are accepted.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_ssls_export(
    handle: *mut CURL,
    export_fn: Option<curl_ssls_export_cb>,
    userptr: *mut c_void,
) -> CURLcode {
    // Feature compiled out — ignore all arguments (the callback is never invoked)
    // and report not-built-in, exactly as curl's `#else` branch does.
    let _ = (handle, export_fn, userptr);
    CURLcode::CURLE_NOT_BUILT_IN
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    // The public `curl_easy_setopt` / `curl_easy_getinfo` symbols are now the
    // C-variadic `va_arg` trampolines in `csrc/variadic_trampolines.c`; the typed
    // marshalling/dispatch logic these tests exercise lives in the Rust
    // implementations the trampolines forward to. Alias the implementation
    // symbols back to the public names so the test bodies below — which already
    // pass exactly one pointer-width trailing argument as `usize`, precisely what
    // the trampoline extracts — read unchanged and continue to validate the
    // dispatch path. (The trampoline's pure va_arg extraction is a C-ABI concern
    // verified by the C/`tests/libtest` callers, not reachable from Rust.)
    use super::curlrs_easy_getinfo_impl as curl_easy_getinfo;
    use super::curlrs_easy_setopt_impl as curl_easy_setopt;
    // `super::*` re-imports the parent's `core` alias (= `curl_rs_lib`), which
    // shadows the built-in `core` crate, along with the parent's `std::ffi::*`
    // primitive imports (`c_char`, `c_long`, `c_double`, `c_void`, `CStr`) and
    // the `curl_off_t` / `curl_socket_t` / `size_t` type aliases. Items rooted at
    // `core::` below are therefore the `curl_rs_lib` alias, never `::core`.
    use std::ffi::CString;

    // --- raw selector helpers ------------------------------------------------
    //
    // The exported shims take the raw C `CURLoption` / `CURLINFO` integer; the
    // idiomatic enums are `#[repr(i32)]`, so `as i32` yields the exact wire value
    // a C caller would pass.

    /// Raw `CURLoption` integer for `opt`.
    fn opt(o: core::CurlOption) -> CURLoption {
        o as CURLoption
    }

    /// Raw `CURLINFO` integer for `info`.
    fn inf(i: core::CurlInfo) -> CURLINFO {
        i as CURLINFO
    }

    /// Borrow the core [`core::Easy`](curl_rs_lib::Easy) behind an opaque
    /// `CURL *` for white-box state assertions (test-only).
    ///
    /// # Safety
    /// `h` must be a live handle from [`curl_easy_init`] / [`curl_easy_duphandle`]
    /// not yet cleaned up.
    unsafe fn as_easy<'a>(h: *mut CURL) -> &'a core::Easy {
        // SAFETY: the caller guarantees `h` is a live `core::Easy` handle.
        unsafe { &*(h as *const core::Easy) }
    }

    // --- lifecycle: init / cleanup -------------------------------------------

    #[test]
    fn init_returns_nonnull_then_cleanup() {
        let h = curl_easy_init();
        assert!(!h.is_null(), "curl_easy_init must return a non-null handle");
        // SAFETY: `h` is a fresh, live handle from curl_easy_init.
        unsafe { curl_easy_cleanup(h) };
    }

    #[test]
    fn init_handles_are_distinct() {
        let a = curl_easy_init();
        let b = curl_easy_init();
        assert!(!a.is_null() && !b.is_null());
        assert_ne!(a, b, "each init must return an independent allocation");
        // SAFETY: both are fresh, live handles, each cleaned up exactly once.
        unsafe {
            curl_easy_cleanup(a);
            curl_easy_cleanup(b);
        }
    }

    #[test]
    fn cleanup_null_is_noop() {
        // SAFETY: NULL is an explicitly handled input (early return, no deref).
        unsafe { curl_easy_cleanup(ptr::null_mut()) };
    }

    // --- lifecycle: reset ----------------------------------------------------

    #[test]
    fn reset_null_is_noop() {
        // SAFETY: NULL is an explicitly handled input (no-op).
        unsafe { curl_easy_reset(ptr::null_mut()) };
    }

    #[test]
    fn reset_restores_option_defaults() {
        let h = curl_easy_init();
        let url = CString::new("https://example.com/").unwrap();
        // SAFETY: live handle; `url` outlives the copying setopt call.
        unsafe {
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_VERBOSE), 1),
                CURLcode::CURLE_OK
            );
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_URL), url.as_ptr() as usize),
                CURLcode::CURLE_OK
            );
            assert!(as_easy(h).set.verbose);
            assert_eq!(as_easy(h).url(), Some("https://example.com/"));

            curl_easy_reset(h);

            // Defaults restored: verbose off, URL cleared.
            assert!(!as_easy(h).set.verbose);
            assert_eq!(as_easy(h).url(), None);

            curl_easy_cleanup(h);
        }
    }

    // --- lifecycle: duphandle ------------------------------------------------

    #[test]
    fn duphandle_null_returns_null() {
        // SAFETY: NULL is explicitly handled (returns NULL).
        let dup = unsafe { curl_easy_duphandle(ptr::null_mut()) };
        assert!(dup.is_null());
    }

    #[test]
    fn duphandle_copies_configuration() {
        let h = curl_easy_init();
        let url = CString::new("https://dup.example/").unwrap();
        // SAFETY: live handles throughout; `url` outlives the copying setopt.
        unsafe {
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_MAXREDIRS), 9),
                CURLcode::CURLE_OK
            );
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_URL), url.as_ptr() as usize),
                CURLcode::CURLE_OK
            );

            let dup = curl_easy_duphandle(h);
            assert!(!dup.is_null(), "duphandle must return a non-null clone");
            assert_ne!(dup, h, "the clone must be an independent allocation");

            // The clone carries the source's configuration.
            assert_eq!(as_easy(dup).url(), Some("https://dup.example/"));
            assert_eq!(as_easy(dup).set.maxredirs, 9);

            // The clone is independent: mutating the source does not affect it.
            curl_easy_reset(h);
            assert_eq!(as_easy(dup).url(), Some("https://dup.example/"));

            curl_easy_cleanup(dup);
            curl_easy_cleanup(h);
        }
    }

    // --- perform -------------------------------------------------------------

    #[test]
    fn perform_null_is_bad_function_argument() {
        // SAFETY: NULL handle is rejected before any dereference.
        let rc = unsafe { curl_easy_perform(ptr::null_mut()) };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn perform_without_url_is_url_malformat() {
        // A fresh handle has no URL: `pre_perform` short-circuits with
        // CURLE_URL_MALFORMAT (no network is attempted). This also exercises the
        // `block_on` bridge end-to-end.
        let h = curl_easy_init();
        // SAFETY: live handle.
        let rc = unsafe { curl_easy_perform(h) };
        assert_eq!(rc, CURLcode::CURLE_URL_MALFORMAT);
        // SAFETY: live handle.
        unsafe { curl_easy_cleanup(h) };
    }

    #[test]
    fn perform_with_url_no_handler_is_unsupported_protocol() {
        // A URL whose scheme has no registered handler reports
        // UNSUPPORTED_PROTOCOL. Every scheme curl recognizes is now driven over
        // the network, so this uses a deliberately bogus scheme (`xyz`) that is
        // absent from the protocol table: `perform_transfer` rejects it
        // immediately — exactly as curl's missing-handler path does — without
        // attempting a real transfer (no network I/O).
        let h = curl_easy_init();
        let url = CString::new("xyz://example.com/").unwrap();
        // SAFETY: live handle; `url` outlives the copying setopt call.
        unsafe {
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_URL), url.as_ptr() as usize),
                CURLcode::CURLE_OK
            );
            let rc = curl_easy_perform(h);
            assert_eq!(rc, CURLcode::CURLE_UNSUPPORTED_PROTOCOL);
            curl_easy_cleanup(h);
        }
    }

    /// A `CURLOPT_WRITEFUNCTION`-shaped C callback that appends the body chunk
    /// (`size * nmemb` bytes — this engine always passes `size == 1`) into the
    /// `Vec<u8>` registered as `CURLOPT_WRITEDATA`, exactly as a C consumer's
    /// `fwrite`-style sink would, and returns the number of bytes taken.
    unsafe extern "C" fn collect_write_cb(
        ptr: *mut c_char,
        size: size_t,
        nmemb: size_t,
        stream: *mut c_void,
    ) -> size_t {
        let len = size * nmemb;
        // SAFETY: the engine passes a valid `(ptr, len)` body chunk via the
        // `(buf, size = 1, nmemb = len)` convention, and `stream` is the live
        // `&mut Vec<u8>` this test registered through `CURLOPT_WRITEDATA`, which
        // outlives the synchronous `curl_easy_perform` call below.
        unsafe {
            let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
            let sink = &mut *(stream as *mut Vec<u8>);
            sink.extend_from_slice(bytes);
        }
        len
    }

    #[test]
    fn perform_file_routes_body_to_c_write_callback() {
        // End-to-end proof that `curl_easy_perform` drives a real transfer
        // (`Easy::perform_with` → `perform_transfer` → the FILE handler) and that
        // the body bytes reach a consumer-registered C `CURLOPT_WRITEFUNCTION`
        // through the `CWriteBridge`/`block_on` bridge. The network-free `file://`
        // handler keeps the test hermetic — the FFI analog of curl-rs-lib's
        // `perform_with_drives_file_download_into_sink`.

        // Build a unique temp path under the system temp dir (curl-rs-ffi has no
        // `tempfile` dev-dependency, so construct one from std primitives).
        let mut path = std::env::temp_dir();
        path.push(format!(
            "curl_rs_ffi_perform_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"bytes via C callback").unwrap();

        let url = CString::new(format!("file://{}", path.display())).unwrap();
        let mut collected: Vec<u8> = Vec::new();

        let h = curl_easy_init();
        // SAFETY: `h` is a live handle; `url` outlives the copying setopt call;
        // `collect_write_cb` is a valid `curl_write_callback`; and `collected`
        // outlives the synchronous `curl_easy_perform` below (the userdata it
        // points at is only touched during the call).
        let rc = unsafe {
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_URL), url.as_ptr() as usize),
                CURLcode::CURLE_OK
            );
            assert_eq!(
                curl_easy_setopt(
                    h,
                    opt(core::CurlOption::CURLOPT_WRITEFUNCTION),
                    collect_write_cb as *const () as usize,
                ),
                CURLcode::CURLE_OK
            );
            assert_eq!(
                curl_easy_setopt(
                    h,
                    opt(core::CurlOption::CURLOPT_WRITEDATA),
                    &mut collected as *mut Vec<u8> as usize,
                ),
                CURLcode::CURLE_OK
            );
            curl_easy_perform(h)
        };

        // The FILE transfer completed and the body reached our C callback.
        assert_eq!(rc, CURLcode::CURLE_OK);
        assert_eq!(collected, b"bytes via C callback");

        // SAFETY: `h` is live and cleaned up exactly once.
        unsafe { curl_easy_cleanup(h) };
        let _ = std::fs::remove_file(&path);
    }

    // --- setopt: error paths -------------------------------------------------

    #[test]
    fn setopt_null_handle_is_bad_function_argument() {
        // SAFETY: NULL handle is rejected before any dereference.
        let rc =
            unsafe { curl_easy_setopt(ptr::null_mut(), opt(core::CurlOption::CURLOPT_VERBOSE), 1) };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn setopt_unknown_option_is_unknown_option() {
        let h = curl_easy_init();
        // 7_000_000 is not a defined CURLoption -> curl's `default:` switch arm.
        // SAFETY: live handle; an unknown option dereferences nothing.
        let rc = unsafe { curl_easy_setopt(h, 7_000_000, 0) };
        assert_eq!(rc, CURLcode::CURLE_UNKNOWN_OPTION);
        // SAFETY: live handle.
        unsafe { curl_easy_cleanup(h) };
    }

    // --- setopt: LONG / VALUES marshalling -----------------------------------

    #[test]
    fn setopt_long_verbose_roundtrips() {
        let h = curl_easy_init();
        // SAFETY: live handle throughout.
        unsafe {
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_VERBOSE), 1),
                CURLcode::CURLE_OK
            );
            assert!(as_easy(h).set.verbose, "VERBOSE=1 must enable verbose");

            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_VERBOSE), 0),
                CURLcode::CURLE_OK
            );
            assert!(!as_easy(h).set.verbose, "VERBOSE=0 must disable verbose");

            curl_easy_cleanup(h);
        }
    }

    #[test]
    fn setopt_long_maxredirs_is_stored() {
        let h = curl_easy_init();
        // SAFETY: live handle.
        unsafe {
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_MAXREDIRS), 7),
                CURLcode::CURLE_OK
            );
            assert_eq!(as_easy(h).set.maxredirs, 7);
            curl_easy_cleanup(h);
        }
    }

    // --- setopt: STRING marshalling ------------------------------------------

    #[test]
    fn setopt_string_url_is_copied() {
        let h = curl_easy_init();
        let url = CString::new("https://example.com/path").unwrap();
        // SAFETY: live handle; `url` outlives the copying call.
        unsafe {
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_URL), url.as_ptr() as usize),
                CURLcode::CURLE_OK
            );
            // The string is copied into owned storage on the handle.
            assert_eq!(as_easy(h).url(), Some("https://example.com/path"));
            curl_easy_cleanup(h);
        }
    }

    #[test]
    fn setopt_string_url_owns_its_copy() {
        // The handle must own its copy: dropping the caller's C string must not
        // dangle the stored option.
        let h = curl_easy_init();
        {
            let url = CString::new("https://transient.example/").unwrap();
            // SAFETY: live handle; `url` is valid for this call.
            unsafe {
                assert_eq!(
                    curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_URL), url.as_ptr() as usize),
                    CURLcode::CURLE_OK
                );
            }
            // `url` is dropped here; the handle must retain an independent copy.
        }
        // SAFETY: live handle.
        unsafe {
            assert_eq!(as_easy(h).url(), Some("https://transient.example/"));
            curl_easy_cleanup(h);
        }
    }

    #[test]
    fn setopt_string_null_clears_option() {
        let h = curl_easy_init();
        let url = CString::new("https://example.com/").unwrap();
        // SAFETY: live handle; `url` outlives its call.
        unsafe {
            curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_URL), url.as_ptr() as usize);
            assert_eq!(as_easy(h).url(), Some("https://example.com/"));
            // A NULL string pointer clears the option (stores None).
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_URL), 0),
                CURLcode::CURLE_OK
            );
            assert_eq!(as_easy(h).url(), None);
            curl_easy_cleanup(h);
        }
    }

    // --- setopt: CBPTR (callback data pointer) -------------------------------

    #[test]
    fn setopt_cbptr_writedata_is_stored() {
        let h = curl_easy_init();
        let marker: usize = 0xCAFE_F00D;
        // SAFETY: live handle; the pointer is stored as an address, never read.
        unsafe {
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_WRITEDATA), marker),
                CURLcode::CURLE_OK
            );
            assert_eq!(as_easy(h).set.out.0, marker);
            curl_easy_cleanup(h);
        }
    }

    // --- setopt: FUNCTION (callback) -----------------------------------------

    /// A dummy `CURLOPT_WRITEFUNCTION`-shaped callback for address-capture tests.
    extern "C" fn dummy_write(
        _ptr: *mut c_char,
        _size: size_t,
        nmemb: size_t,
        _userdata: *mut c_void,
    ) -> size_t {
        nmemb
    }

    #[test]
    fn setopt_function_writefunction_is_stored() {
        let h = curl_easy_init();
        // Cast the function item to a thin pointer first, then to its address
        // (the `function_casts_as_integer` lint forbids the direct fn-to-int
        // cast); this is exactly the address a C caller's function pointer holds.
        let fp = dummy_write as *const () as usize;
        // SAFETY: live handle; the function pointer is stored as an address.
        unsafe {
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_WRITEFUNCTION), fp),
                CURLcode::CURLE_OK
            );
            assert_eq!(as_easy(h).set.fwrite_func.0, fp);
            curl_easy_cleanup(h);
        }
    }

    // --- setopt: OBJECT refinements ------------------------------------------

    #[test]
    fn setopt_object_private_pointer_is_stored() {
        let h = curl_easy_init();
        let marker: usize = 0x0BAD_C0DE;
        // SAFETY: live handle; CURLOPT_PRIVATE stores the address verbatim.
        unsafe {
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_PRIVATE), marker),
                CURLcode::CURLE_OK
            );
            assert_eq!(as_easy(h).set.private_data.0, marker);
            curl_easy_cleanup(h);
        }
    }

    #[test]
    fn setopt_copypostfields_uses_explicit_size() {
        // CURLOPT_COPYPOSTFIELDS copies exactly CURLOPT_POSTFIELDSIZE bytes,
        // including any embedded NUL, when the size is set (>= 0).
        let h = curl_easy_init();
        let body = CString::new("hello").unwrap(); // 5 bytes + NUL
                                                   // SAFETY: live handle; `body` outlives the copying call.
        unsafe {
            assert_eq!(
                curl_easy_setopt(h, opt(core::CurlOption::CURLOPT_POSTFIELDSIZE), 4),
                CURLcode::CURLE_OK
            );
            assert_eq!(
                curl_easy_setopt(
                    h,
                    opt(core::CurlOption::CURLOPT_COPYPOSTFIELDS),
                    body.as_ptr() as usize
                ),
                CURLcode::CURLE_OK
            );
            // Exactly 4 bytes copied ("hell"), per the explicit size.
            assert_eq!(as_easy(h).set.copypostfields.as_deref(), Some(&b"hell"[..]));
            curl_easy_cleanup(h);
        }
    }

    #[test]
    fn setopt_copypostfields_string_when_size_unset() {
        // With CURLOPT_POSTFIELDSIZE unset (default -1) the body is treated as a
        // NUL-terminated C string; its strlen determines the copied length.
        let h = curl_easy_init();
        let body = CString::new("abcdef").unwrap();
        // SAFETY: live handle; `body` outlives the copying call.
        unsafe {
            assert_eq!(
                curl_easy_setopt(
                    h,
                    opt(core::CurlOption::CURLOPT_COPYPOSTFIELDS),
                    body.as_ptr() as usize
                ),
                CURLcode::CURLE_OK
            );
            assert_eq!(
                as_easy(h).set.copypostfields.as_deref(),
                Some(&b"abcdef"[..])
            );
            curl_easy_cleanup(h);
        }
    }

    // --- getinfo: error paths ------------------------------------------------

    #[test]
    fn getinfo_null_handle_is_bad_function_argument() {
        let mut out: c_long = -1;
        // SAFETY: NULL handle is rejected before any dereference of `out`.
        let rc = unsafe {
            curl_easy_getinfo(
                ptr::null_mut(),
                inf(core::CurlInfo::ResponseCode),
                &mut out as *mut c_long as usize,
            )
        };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
        assert_eq!(out, -1, "no value must be written on error");
    }

    #[test]
    fn getinfo_null_arg_is_bad_function_argument() {
        let h = curl_easy_init();
        // SAFETY: live handle; a NULL output pointer is rejected safely (unlike
        // C curl, which would dereference it).
        let rc = unsafe { curl_easy_getinfo(h, inf(core::CurlInfo::ResponseCode), 0) };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
        // SAFETY: live handle.
        unsafe { curl_easy_cleanup(h) };
    }

    #[test]
    fn getinfo_unknown_info_is_unknown_option() {
        let h = curl_easy_init();
        let mut out: c_long = 0;
        // 0x0FF0_0000 is not a defined CURLINFO -> curl's type-dispatch default.
        // SAFETY: live handle; an unknown info dereferences nothing.
        let rc = unsafe { curl_easy_getinfo(h, 0x0FF0_0000, &mut out as *mut c_long as usize) };
        assert_eq!(rc, CURLcode::CURLE_UNKNOWN_OPTION);
        // SAFETY: live handle.
        unsafe { curl_easy_cleanup(h) };
    }

    // --- getinfo: LONG write-through -----------------------------------------

    #[test]
    fn getinfo_long_response_code_writes_value() {
        let h = curl_easy_init();
        let mut code: c_long = -1;
        // SAFETY: live handle; `code` is a valid writable `long*`.
        unsafe {
            let rc = curl_easy_getinfo(
                h,
                inf(core::CurlInfo::ResponseCode),
                &mut code as *mut c_long as usize,
            );
            assert_eq!(rc, CURLcode::CURLE_OK);
            // A fresh handle has performed no transfer: response code is 0.
            assert_eq!(code, 0);
            curl_easy_cleanup(h);
        }
    }

    // --- getinfo: STRING write-through ---------------------------------------

    #[test]
    fn getinfo_string_effective_url_writes_pointer() {
        let h = curl_easy_init();
        let mut p: *const c_char = ptr::null();
        // SAFETY: live handle; `p` is a valid writable `const char**`.
        unsafe {
            let rc = curl_easy_getinfo(
                h,
                inf(core::CurlInfo::EffectiveUrl),
                &mut p as *mut *const c_char as usize,
            );
            assert_eq!(rc, CURLcode::CURLE_OK);
            // Unset effective URL is reported as a non-null, empty C string ""
            // (curl's `s ? s : ""`), owned by the handle.
            assert!(!p.is_null(), "effective URL must be a non-null C string");
            let s = CStr::from_ptr(p).to_str().unwrap();
            assert_eq!(s, "");
            curl_easy_cleanup(h);
        }
    }

    // --- getinfo: PTR write-through ------------------------------------------

    #[test]
    fn getinfo_ptr_private_writes_pointer() {
        // CURLINFO_PRIVATE reads the transfer-info pointer (populated during a
        // transfer); on a fresh handle it is NULL. This exercises the `void**`
        // write-through path deterministically.
        let h = curl_easy_init();
        let mut p: *mut c_void = 0x1 as *mut c_void;
        // SAFETY: live handle; `p` is a valid writable `void**`.
        unsafe {
            let rc = curl_easy_getinfo(
                h,
                inf(core::CurlInfo::Private),
                &mut p as *mut *mut c_void as usize,
            );
            assert_eq!(rc, CURLcode::CURLE_OK);
            assert!(p.is_null(), "unset PRIVATE pointer must be written as NULL");
            curl_easy_cleanup(h);
        }
    }

    // --- recv / send ---------------------------------------------------------

    #[test]
    fn recv_null_handle_is_bad_function_argument() {
        let mut buf = [0u8; 8];
        let mut n: size_t = 99;
        // SAFETY: NULL handle is rejected before any dereference.
        let rc = unsafe {
            curl_easy_recv(
                ptr::null_mut(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut n,
            )
        };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn recv_without_connection_is_unsupported_and_zeroes_n() {
        // No CONNECT_ONLY connection is attached: the core reports
        // UNSUPPORTED_PROTOCOL and the shim writes 0 to `*n`. Also exercises the
        // `block_on` bridge for recv.
        let h = curl_easy_init();
        let mut buf = [0u8; 8];
        let mut n: size_t = 99;
        // SAFETY: live handle; `buf`/`n` are valid for the call.
        unsafe {
            let rc = curl_easy_recv(h, buf.as_mut_ptr() as *mut c_void, buf.len(), &mut n);
            assert_eq!(rc, CURLcode::CURLE_UNSUPPORTED_PROTOCOL);
            assert_eq!(n, 0, "bytes-received must be zeroed on error");
            curl_easy_cleanup(h);
        }
    }

    #[test]
    fn send_null_handle_is_bad_function_argument() {
        let buf = [1u8, 2, 3];
        let mut n: size_t = 99;
        // SAFETY: NULL handle is rejected before any dereference.
        let rc = unsafe {
            curl_easy_send(
                ptr::null_mut(),
                buf.as_ptr() as *const c_void,
                buf.len(),
                &mut n,
            )
        };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn send_without_connection_is_unsupported_and_zeroes_n() {
        let h = curl_easy_init();
        let buf = [1u8, 2, 3];
        let mut n: size_t = 99;
        // SAFETY: live handle; `buf`/`n` are valid for the call.
        unsafe {
            let rc = curl_easy_send(h, buf.as_ptr() as *const c_void, buf.len(), &mut n);
            assert_eq!(rc, CURLcode::CURLE_UNSUPPORTED_PROTOCOL);
            assert_eq!(n, 0, "bytes-sent must be zeroed on error");
            curl_easy_cleanup(h);
        }
    }

    #[test]
    fn recv_tolerates_null_buffer_and_null_n() {
        // A NULL/zero buffer is a zero-length read; a NULL `n` must not be
        // dereferenced. The operation still reports UNSUPPORTED_PROTOCOL (no
        // connection) without faulting.
        let h = curl_easy_init();
        // SAFETY: live handle; NULL buffer and NULL `n` are explicitly tolerated.
        unsafe {
            let rc = curl_easy_recv(h, ptr::null_mut(), 0, ptr::null_mut());
            assert_eq!(rc, CURLcode::CURLE_UNSUPPORTED_PROTOCOL);
            curl_easy_cleanup(h);
        }
    }

    // --- upkeep --------------------------------------------------------------

    #[test]
    fn upkeep_null_handle_is_bad_function_argument() {
        // SAFETY: NULL handle is rejected before any dereference.
        let rc = unsafe { curl_easy_upkeep(ptr::null_mut()) };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn upkeep_without_connections_is_ok() {
        // With no connection cache attached, upkeep is a successful no-op. Also
        // exercises the `block_on` bridge for upkeep.
        let h = curl_easy_init();
        // SAFETY: live handle.
        let rc = unsafe { curl_easy_upkeep(h) };
        assert_eq!(rc, CURLcode::CURLE_OK);
        // SAFETY: live handle.
        unsafe { curl_easy_cleanup(h) };
    }

    // --- pause ---------------------------------------------------------------

    #[test]
    fn pause_null_handle_is_bad_function_argument() {
        // SAFETY: NULL handle is rejected before any dereference.
        let rc = unsafe { curl_easy_pause(ptr::null_mut(), CURLPAUSE_ALL) };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn pause_without_connection_is_bad_function_argument() {
        // Pausing requires an active connection; without one the core returns
        // BAD_FUNCTION_ARGUMENT (curl's `!data->conn` guard).
        let h = curl_easy_init();
        // SAFETY: live handle.
        let rc = unsafe { curl_easy_pause(h, CURLPAUSE_ALL) };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
        // SAFETY: live handle.
        unsafe { curl_easy_cleanup(h) };
    }

    #[test]
    fn pause_bitmask_constants_match_curl() {
        // The CURLPAUSE_* values are part of the public ABI (include/curl/curl.h).
        assert_eq!(CURLPAUSE_RECV, 1 << 0);
        assert_eq!(CURLPAUSE_SEND, 1 << 2);
        assert_eq!(CURLPAUSE_ALL, (1 << 0) | (1 << 2));
        assert_eq!(CURLPAUSE_CONT, 0);
    }

    // --- ssls import / export (feature not built in) -------------------------

    #[test]
    fn ssls_import_is_not_built_in() {
        let h = curl_easy_init();
        let key = CString::new("session-key").unwrap();
        // SAFETY: live handle; the shim dereferences none of its arguments.
        unsafe {
            let rc = curl_easy_ssls_import(h, key.as_ptr(), ptr::null(), 0, ptr::null(), 0);
            assert_eq!(rc, CURLcode::CURLE_NOT_BUILT_IN);
            curl_easy_cleanup(h);
        }
    }

    #[test]
    fn ssls_import_tolerates_null_arguments() {
        let h = curl_easy_init();
        // SAFETY: live handle; all-NULL arguments are explicitly tolerated.
        unsafe {
            let rc = curl_easy_ssls_import(h, ptr::null(), ptr::null(), 0, ptr::null(), 0);
            assert_eq!(rc, CURLcode::CURLE_NOT_BUILT_IN);
            curl_easy_cleanup(h);
        }
    }

    #[test]
    fn ssls_export_is_not_built_in() {
        let h = curl_easy_init();
        // SAFETY: live handle; a NULL callback (`None`) is explicitly tolerated
        // and never invoked.
        unsafe {
            let rc = curl_easy_ssls_export(h, None, ptr::null_mut());
            assert_eq!(rc, CURLcode::CURLE_NOT_BUILT_IN);
            curl_easy_cleanup(h);
        }
    }
}
