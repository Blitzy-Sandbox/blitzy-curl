//! The public `curl_multi_*` / `curl_pushheader_*` multi-interface C API.
//!
//! This module implements libcurl's **24** exported multi-interface symbols
//! (`lib/libcurl.def`; the 24 `CURL_EXTERN` declarations in
//! `include/curl/multi.h`): the 22 `curl_multi_*` functions plus the two
//! `curl_pushheader_*` server-push helpers. Each is a
//! `#[no_mangle] pub extern "C" fn`, so the produced `libcurl` exports exactly
//! the curl 8.x symbol set the `nm`/`objdump` parity gate checks (AAP §0.7.2).
//!
//! The full list (24): `curl_multi_init`, `curl_multi_add_handle`,
//! `curl_multi_remove_handle`, `curl_multi_fdset`, `curl_multi_waitfds`,
//! `curl_multi_wait`, `curl_multi_poll`, `curl_multi_wakeup`,
//! `curl_multi_perform`, `curl_multi_cleanup`, `curl_multi_info_read`,
//! `curl_multi_strerror`, `curl_multi_socket`, `curl_multi_socket_action`,
//! `curl_multi_socket_all`, `curl_multi_timeout`, `curl_multi_setopt`,
//! `curl_multi_assign`, `curl_multi_get_handles`, `curl_multi_get_offt`,
//! `curl_multi_notify_enable`, `curl_multi_notify_disable`,
//! `curl_pushheader_byname`, `curl_pushheader_bynum`.
//!
//! # `curl_multi_socket` is a real symbol *and* a macro
//!
//! In `include/curl/multi.h`, `curl_multi_socket` is BOTH a deprecated exported
//! function AND a backward-compat macro
//! (`#define curl_multi_socket(x,y,z) curl_multi_socket_action(x,y,0,z)`). The
//! curated header keeps the macro; this module nonetheless emits the genuine
//! `#[no_mangle]` symbol so old binaries linked against it still resolve and the
//! parity gate sees 24 symbols (AAP / agent prompt).
//!
//! # Opaque `CURLM` and the easy-handle ownership bridge (Approach D)
//!
//! C sees the multi as the opaque `typedef void CURLM;` ([`crate::types::CURLM`]).
//! Behind that pointer this module places a heap-allocated [`MultiHandle`] — a
//! thin wrapper around the safe async core [`curl_rs_lib::Multi`] plus the small
//! amount of FFI-only bookkeeping the C ABI requires.
//!
//! The core drives transfers as `Arc<tokio::sync::Mutex<Easy>>`
//! ([`SharedEasy`]), but the FFI easy handle (`*mut CURL`, from `easy.rs`) is a
//! `Box<core::Easy>` at a fixed address the caller will eventually free with
//! `curl_easy_cleanup` (`Box::from_raw`). A single `Easy` cannot be *both* a
//! `Box` at a fixed address and inside an `Arc<Mutex>`, so on
//! [`curl_multi_add_handle`] the configured `Easy` is **moved** out of the
//! caller's box (a placeholder `Easy::new()` is left in its place, keeping the
//! `*mut CURL` allocation valid for the eventual `curl_easy_cleanup`) into a
//! [`SharedEasy`] that the core drives. A small registry maps the original
//! `*mut CURL` address to that `SharedEasy`. When the transfer finishes, the
//! real `Easy` is swapped **back** into the caller's box (idempotently, on
//! [`curl_multi_info_read`] and [`curl_multi_remove_handle`]) so a subsequent
//! `curl_easy_getinfo` on the handle reads the real transfer results. This
//! honors curl's contract — the easy handle is owned by the caller, the multi
//! only borrows it, and "anything allocated by Rust is freed by Rust" (AAP
//! §0.7.1) — without any leak or double-free.
//!
//! # Synchronous C contract over an async core (AAP §0.7.4)
//!
//! The core's multi-thread Tokio runtime is owned **inside**
//! [`curl_rs_lib::Multi`] and lazily created on first drive. The core's
//! `perform` / `socket_action` / `poll` / `wait` are already **synchronous**
//! (they manage that runtime internally and return `(CurlMError, running)`), so
//! these shims call them directly and must NOT wrap them in
//! [`crate::block_on`] (the crate-wide current-thread bridge used by the *easy*
//! path) — doing so would nest runtimes. The Tokio runtime is thus a hidden
//! implementation detail behind the same synchronous, callback-driven poll
//! contract, so `curl_multi_socket_action` semantics, `CURLM_CALL_MULTI_PERFORM`
//! signaling, and socket/timer callback timing remain observably identical to C
//! libcurl for external event loops.
//!
//! # Return type
//!
//! Every function returns a [`CURLMcode`] integer (NOT a `CURLcode`):
//! `CURLM_CALL_MULTI_PERFORM = -1`, `CURLM_OK = 0`, then the error codes. The
//! mapping from the core [`curl_rs_lib::error::CurlMError`] is the shared
//! [`crate::error_codes`] table.
//!
//! # Memory safety
//!
//! `curl-rs-ffi` is the only crate permitted `unsafe`. Every `unsafe` operation
//! here sits in an explicit `unsafe { … }` block carrying a `// SAFETY:`
//! comment (the crate denies `unsafe_op_in_unsafe_fn`), and every exported
//! `unsafe extern "C"` entry point documents its preconditions under a
//! `# Safety` section. The behavioral oracle is `lib/multi.c`; the result
//! strings come from `lib/strerror.c`.

#![allow(non_camel_case_types)]

use std::collections::HashSet;
use std::ffi::{c_char, c_int, c_long, c_short, c_uint, c_void};
use std::sync::{Arc, Mutex};
use std::{mem, ptr};

use libc::{fd_set, size_t};

// The safe async core is reached through the `core` alias (mirroring `easy.rs`
// and `share.rs`). NB: this alias shadows the standard `core` crate *within this
// module*, so standard-library items are taken from `std::*` (above), never
// `core::*`.
use curl_rs_lib as core;

// Sub-paths are taken directly from `curl_rs_lib::…` (not via the `core` alias)
// to keep resolution unambiguous. The core's completion message type is aliased
// to `CoreCurlMsg` to avoid confusion with the C `CURLMsg` struct (note the
// different casing) defined in `crate::types`.
use curl_rs_lib::error::CurlMError;
use curl_rs_lib::multi::{
    shared_easy, CurlMInfo, CurlMOption, CurlMsg as CoreCurlMsg, CurlMsgType, CurlSocket,
    MultiOption, NotifyCallback, PushCallback, SharedEasy, SocketCallback, TimerCallback, UserData,
    Waitfd,
};

use crate::error_codes::{multi_strerror, CURLMcode};
use crate::types::{
    curl_off_t, curl_pushheaders, curl_socket_t, curl_waitfd, CURLMinfo_offt, CURLMoption, CURLMsg,
    CURLMsg_data, CURL, CURLM, CURLMSG, CURL_WAIT_POLLIN, CURL_WAIT_POLLOUT,
};

// ===========================================================================
// The opaque CURLM payload — `MultiHandle`
// ===========================================================================

/// Type of the per-handle registry mapping a caller's `*mut CURL` address
/// (stored as `usize` so the value is `Send` for the callback wrappers) to the
/// [`SharedEasy`] the core drives on its behalf.
type Registry = Arc<Mutex<Vec<(usize, SharedEasy)>>>;

/// The concrete object placed behind the opaque `*mut CURLM`.
///
/// Field order is significant: `inner` is declared **first** so that, on drop,
/// the core [`Multi`](curl_rs_lib::Multi) tears down first — aborting its driving
/// tasks and shutting down its runtime — before the `registry` releases its
/// `Arc` clones of the shared easy handles. That ordering guarantees no task is
/// still touching a [`SharedEasy`] when its last `Arc` is released.
struct MultiHandle {
    /// The safe async core multi state machine (drops first; see above).
    inner: core::Multi,
    /// Maps caller `*mut CURL` (as `usize`) to the `SharedEasy` the core drives.
    registry: Registry,
    /// Addresses of easy handles whose real `Easy` has already been swapped back
    /// into the caller's box, so the swap-back is performed at most once.
    restored: HashSet<usize>,
    /// Backing storage for the `CURLMsg` returned by [`curl_multi_info_read`].
    /// The C contract is that the returned pointer is owned by the multi handle
    /// and stays valid until the next `info_read`/`cleanup`; storing it here (a
    /// stable address inside the boxed handle) satisfies that without a per-call
    /// heap allocation the caller would have to free.
    msg_storage: Option<CURLMsg>,
}

impl MultiHandle {
    /// Create an empty multi handle wrapping a fresh [`core::Multi`].
    fn new() -> Self {
        MultiHandle {
            inner: core::Multi::new(),
            registry: Arc::new(Mutex::new(Vec::new())),
            restored: HashSet::new(),
            msg_storage: None,
        }
    }
}

// ===========================================================================
// Internal helpers
// ===========================================================================

/// Reconstitute a `&mut MultiHandle` from a raw `*mut CURLM`, or `None` for NULL.
///
/// # Safety
///
/// `m` must be NULL, or a valid `CURLM *` previously returned by
/// [`curl_multi_init`] and not yet cleaned up. The returned exclusive borrow
/// must not alias any other live borrow of the same handle (curl forbids
/// concurrent use of one multi handle).
unsafe fn multi_handle_ref<'a>(m: *mut CURLM) -> Option<&'a mut MultiHandle> {
    if m.is_null() {
        None
    } else {
        // SAFETY: per the contract `m` is a live `MultiHandle` produced by
        // `curl_multi_init` (`Box::into_raw`), so forming the exclusive borrow is
        // sound for the lifetime the caller upholds.
        Some(unsafe { &mut *(m as *mut MultiHandle) })
    }
}

/// Reverse-lookup the caller `*mut CURL` address registered for `shared`, or `0`
/// if it is not in the registry. Compares by `Arc` identity ([`Arc::ptr_eq`]).
fn ptr_for_shared(registry: &Mutex<Vec<(usize, SharedEasy)>>, shared: &SharedEasy) -> usize {
    let reg = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for (addr, entry) in reg.iter() {
        if Arc::ptr_eq(entry, shared) {
            return *addr;
        }
    }
    0
}

/// Swap the real, finished `Easy` back into the caller's box at `easy_addr`.
///
/// Idempotent (guarded by `restored`): the configured/finished `Easy` lives in
/// the `SharedEasy` while the transfer runs, and a placeholder occupies the
/// caller's box. Once the driving task has released the lock (transfer done),
/// `try_lock` succeeds and the two `Easy` values are swapped, so a subsequent
/// `curl_easy_getinfo`/`curl_easy_cleanup` on the original `*mut CURL` sees the
/// real handle. If the transfer is still running (`try_lock` fails) the swap is
/// deferred to the next call; the placeholder remains valid in the meantime.
fn restore_easy(restored: &mut HashSet<usize>, shared: &SharedEasy, easy_addr: usize) {
    if easy_addr == 0 || restored.contains(&easy_addr) {
        return;
    }
    if let Ok(mut guard) = shared.try_lock() {
        // SAFETY: `easy_addr` is the address of the caller's live `Box<core::Easy>`
        // (the `*mut CURL` from `curl_easy_init`), exclusively accessible under
        // curl's single-thread-per-handle contract; it currently holds the
        // placeholder. `guard` grants exclusive access to the real `Easy` inside
        // the `Arc`. The two are distinct allocations, so swapping their owned
        // `Easy` values is sound and leaves both allocations valid and
        // initialized.
        unsafe {
            let boxed: &mut core::Easy = &mut *(easy_addr as *mut core::Easy);
            mem::swap(&mut *guard, boxed);
        }
        restored.insert(easy_addr);
    }
}

/// Map a raw callback-pointer address to the core's `Option<usize>` form: `0`
/// means "no callback" (clear), any other address is the installed pointer.
#[inline]
fn addr_to_opt(addr: usize) -> Option<usize> {
    if addr == 0 {
        None
    } else {
        Some(addr)
    }
}

// ===========================================================================
// extern "C" callback signatures (for transmuting the installed pointers)
// ===========================================================================

/// Concrete (non-`Option`) `curl_socket_callback` pointer
/// (`include/curl/multi.h`).
type CSocketFn =
    unsafe extern "C" fn(*mut CURL, curl_socket_t, c_int, *mut c_void, *mut c_void) -> c_int;

/// Concrete (non-`Option`) `curl_multi_timer_callback` pointer.
type CTimerFn = unsafe extern "C" fn(*mut CURLM, c_long, *mut c_void) -> c_int;

/// Concrete (non-`Option`) `curl_push_callback` pointer.
type CPushFn =
    unsafe extern "C" fn(*mut CURL, *mut CURL, size_t, *mut curl_pushheaders, *mut c_void) -> c_int;

/// Concrete (non-`Option`) `curl_notify_callback` pointer.
type CNotifyFn = unsafe extern "C" fn(*mut CURLM, c_uint, *mut CURL, *mut c_void);

// ===========================================================================
// Callback wrappers: bridge the core's safe trait objects to the C pointers
// ===========================================================================

/// Wraps a C `curl_socket_callback` as a core [`SocketCallback`]. Holds the
/// installed pointer (as a `usize` address) and a clone of the registry so the
/// core's [`SharedEasy`] can be translated back to the caller's `*mut CURL`.
struct FfiSocketCb {
    func: usize,
    registry: Registry,
}

impl SocketCallback for FfiSocketCb {
    fn on_socket(
        &mut self,
        easy: Option<&SharedEasy>,
        socket: CurlSocket,
        what: i32,
        socket_userp: UserData,
        socketp: UserData,
    ) -> i32 {
        let easy_ptr = match easy {
            Some(e) => ptr_for_shared(&self.registry, e) as *mut CURL,
            None => ptr::null_mut(),
        };
        // SAFETY: `self.func` is the nonzero address of a `curl_socket_callback`
        // the application installed via
        // `curl_multi_setopt(CURLMOPT_SOCKETFUNCTION, …)`. A function pointer and
        // `usize` are the same width, so transmuting the stored address back to
        // the exact `extern "C"` signature reproduces the original callable.
        let f: CSocketFn = unsafe { mem::transmute::<usize, CSocketFn>(self.func) };
        // SAFETY: `f` is invoked with exactly the arguments its published C
        // signature requires; `easy_ptr` is the original caller handle (or NULL),
        // and the two user pointers are application-owned cookies.
        unsafe {
            f(
                easy_ptr,
                socket as curl_socket_t,
                what as c_int,
                socket_userp.0 as *mut c_void,
                socketp.0 as *mut c_void,
            )
        }
    }
}

/// Wraps a C `curl_multi_timer_callback` as a core [`TimerCallback`]. Holds the
/// installed pointer and the stable `*mut CURLM` address (the boxed
/// [`MultiHandle`] never moves) to pass as the callback's `multi` argument.
struct FfiTimerCb {
    func: usize,
    multi_ptr: usize,
}

impl TimerCallback for FfiTimerCb {
    fn on_timer(&mut self, timeout_ms: i64, timer_userp: UserData) -> i32 {
        // SAFETY: `self.func` is the nonzero address of a
        // `curl_multi_timer_callback` installed via
        // `curl_multi_setopt(CURLMOPT_TIMERFUNCTION, …)`; same-width pointer
        // round-trip.
        let f: CTimerFn = unsafe { mem::transmute::<usize, CTimerFn>(self.func) };
        // SAFETY: `multi_ptr` is the stable address of the live `MultiHandle`
        // (boxed by `curl_multi_init`, freed only by `curl_multi_cleanup`);
        // invoked with exactly the C signature's arguments.
        unsafe {
            f(
                self.multi_ptr as *mut CURLM,
                timeout_ms as c_long,
                timer_userp.0 as *mut c_void,
            )
        }
    }
}

/// Wraps a C `curl_push_callback` as a core [`PushCallback`]. The core trait
/// does not (yet) surface `num_headers`/`headers` (HTTP/2 server push is not
/// wired into the core, so this is never invoked); the wrapper still stores the
/// installed pointer so the option round-trips faithfully, and passes `0`/NULL
/// for those C parameters if it is ever called.
struct FfiPushCb {
    func: usize,
    registry: Registry,
}

impl PushCallback for FfiPushCb {
    fn on_push(
        &mut self,
        parent: Option<&SharedEasy>,
        pushed: Option<&SharedEasy>,
        push_userp: UserData,
    ) -> i32 {
        let parent_ptr = match parent {
            Some(e) => ptr_for_shared(&self.registry, e) as *mut CURL,
            None => ptr::null_mut(),
        };
        let pushed_ptr = match pushed {
            Some(e) => ptr_for_shared(&self.registry, e) as *mut CURL,
            None => ptr::null_mut(),
        };
        // SAFETY: `self.func` is the nonzero address of a `curl_push_callback`
        // installed via `curl_multi_setopt(CURLMOPT_PUSHFUNCTION, …)`; same-width
        // pointer round-trip.
        let f: CPushFn = unsafe { mem::transmute::<usize, CPushFn>(self.func) };
        // SAFETY: invoked with the C signature's arguments; the two easy handles
        // are original caller handles (or NULL) and `push_userp` is an
        // application-owned cookie. `0`/NULL are passed for the header count and
        // header object the core does not provide (the call site is unreachable
        // until HTTP/2 push lands).
        unsafe {
            f(
                parent_ptr,
                pushed_ptr,
                0 as size_t,
                ptr::null_mut(),
                push_userp.0 as *mut c_void,
            )
        }
    }
}

/// Wraps a C `curl_notify_callback` as a core [`NotifyCallback`]. Holds the
/// installed pointer, the stable `*mut CURLM` address, and a registry clone to
/// translate the core's [`SharedEasy`] back to the caller's `*mut CURL`.
struct FfiNotifyCb {
    func: usize,
    multi_ptr: usize,
    registry: Registry,
}

impl NotifyCallback for FfiNotifyCb {
    fn on_notify(&mut self, notification: u32, easy: Option<&SharedEasy>, notify_userp: UserData) {
        let easy_ptr = match easy {
            Some(e) => ptr_for_shared(&self.registry, e) as *mut CURL,
            None => ptr::null_mut(),
        };
        // SAFETY: `self.func` is the nonzero address of a `curl_notify_callback`
        // installed via `curl_multi_setopt(CURLMOPT_NOTIFYFUNCTION, …)`;
        // same-width pointer round-trip.
        let f: CNotifyFn = unsafe { mem::transmute::<usize, CNotifyFn>(self.func) };
        // SAFETY: invoked with exactly the C signature's arguments; `multi_ptr`
        // is the live boxed handle's stable address, `easy_ptr` the original
        // caller handle (or NULL), `notify_userp` an application cookie.
        unsafe {
            f(
                self.multi_ptr as *mut CURLM,
                notification as c_uint,
                easy_ptr,
                notify_userp.0 as *mut c_void,
            )
        }
    }
}

// ===========================================================================
// Internal conversion helpers shared by the exported symbols
// ===========================================================================

/// Map the core's [`CurlMsgType`] to the C `CURLMSG` enum (same integer values).
fn msgtype_to_c(t: CurlMsgType) -> CURLMSG {
    match t {
        CurlMsgType::None => CURLMSG::CURLMSG_NONE,
        CurlMsgType::Done => CURLMSG::CURLMSG_DONE,
        CurlMsgType::Last => CURLMSG::CURLMSG_LAST,
    }
}

/// Read the caller's `curl_waitfd` array into a `Vec<Waitfd>` for the core.
///
/// # Safety
///
/// When `n > 0`, `fds` must point to `n` readable [`curl_waitfd`] entries.
unsafe fn collect_extra_fds(fds: *mut curl_waitfd, n: c_uint) -> Vec<Waitfd> {
    if fds.is_null() || n == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        // SAFETY: `i < n` and the caller guarantees `n` valid, readable entries.
        let entry = unsafe { &*fds.add(i) };
        out.push(Waitfd {
            fd: entry.fd as CurlSocket,
            events: entry.events,
            revents: entry.revents,
        });
    }
    out
}

/// Write the per-fd `revents` the core computed back into the caller's array.
///
/// `curl_multi_wait`/`poll` treat `revents` as an output that libcurl always
/// overwrites. The core ([`core::Multi::wait`]/[`poll`](core::Multi::poll)) now
/// polls each application descriptor and records the readiness it observed into
/// the `Waitfd` it was handed; this copies that readiness back to the C
/// `curl_waitfd` array entry-for-entry. `extras` was built from the same array
/// by [`collect_extra_fds`], so the indices line up; `take(n)` is defensive.
///
/// # Safety
///
/// When `n > 0`, `fds` must point to `n` writable [`curl_waitfd`] entries.
unsafe fn write_back_revents(fds: *mut curl_waitfd, n: c_uint, extras: &[Waitfd]) {
    if fds.is_null() || n == 0 {
        return;
    }
    for (i, w) in extras.iter().enumerate().take(n as usize) {
        // SAFETY: `i < n`; the caller guarantees `n` writable entries.
        unsafe {
            (*fds.add(i)).revents = w.revents;
        }
    }
}

// ===========================================================================
// Phase 1 — lifecycle: curl_multi_init / curl_multi_cleanup
// ===========================================================================

/// `curl_multi_init` — create a new multi handle (`include/curl/multi.h:127`).
///
/// Returns an opaque `CURLM *` (a heap-allocated [`MultiHandle`] wrapping a fresh
/// [`core::Multi`]), or NULL on failure. Mirrors `lib/multi.c:curl_multi_init`.
#[no_mangle]
pub extern "C" fn curl_multi_init() -> *mut CURLM {
    // `Box::new` aborts (rather than returning) on allocation failure, so the
    // returned pointer is always valid; NULL is reserved for ABI completeness.
    Box::into_raw(Box::new(MultiHandle::new())) as *mut CURLM
}

/// `curl_multi_cleanup` — free a multi handle (`include/curl/multi.h:230`).
///
/// Reclaims the [`MultiHandle`]: the core (`inner`) drops first — aborting its
/// driving tasks and shutting down its runtime — before the registry releases
/// its `SharedEasy` clones (see [`MultiHandle`] field order). The easy handles
/// are NOT freed here: the caller still owns each `*mut CURL` and must
/// `curl_easy_cleanup` it. Mirrors `lib/multi.c:curl_multi_cleanup`.
///
/// # Safety
///
/// `multi` must be NULL or a `CURLM *` previously returned by
/// [`curl_multi_init`] that has not already been cleaned up, and it must not be
/// used after this call.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_cleanup(multi: *mut CURLM) -> CURLMcode {
    if multi.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE;
    }
    // SAFETY: per the `# Safety` contract `multi` is a live handle from
    // `curl_multi_init` (`Box::into_raw` of a `MultiHandle`) not yet freed, so
    // reconstructing the owning `Box` and dropping it frees the allocation
    // exactly once.
    drop(unsafe { Box::from_raw(multi as *mut MultiHandle) });
    CURLMcode::CURLM_OK
}

// ===========================================================================
// Phase 2 — handle association: add_handle / remove_handle
// ===========================================================================

/// `curl_multi_add_handle` — add an easy handle to the multi stack
/// (`include/curl/multi.h:136`).
///
/// The multi only *borrows* the easy handle; ownership stays with the caller,
/// who must `curl_easy_cleanup` it (after removing it). To bridge the FFI
/// `Box<Easy>` to the core's `Arc<Mutex<Easy>>`, the configured `Easy` is moved
/// out of the caller's box — a placeholder `Easy::new()` is left so the
/// `*mut CURL` allocation stays valid — into a [`SharedEasy`] the core drives,
/// and the original pointer is recorded in the registry (Approach D; see the
/// module docs). A second add of the same handle returns `CURLM_ADDED_ALREADY`.
/// Mirrors `lib/multi.c:curl_multi_add_handle`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`]; `easy` must
/// be NULL or a live `*mut CURL` from `curl_easy_init` that is not concurrently
/// in use (curl's single-thread-per-handle contract).
#[no_mangle]
pub unsafe extern "C" fn curl_multi_add_handle(multi: *mut CURLM, easy: *mut CURL) -> CURLMcode {
    // SAFETY: `multi_handle_ref` upholds its contract under this function's
    // `# Safety` precondition on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return CURLMcode::CURLM_BAD_HANDLE,
    };
    if easy.is_null() {
        return CURLMcode::CURLM_BAD_EASY_HANDLE;
    }
    let easy_addr = easy as usize;

    // Reject a duplicate add up front (curl's CURLM_ADDED_ALREADY). The registry
    // is the authoritative record of which handles this multi currently holds.
    {
        let reg = handle.registry.lock().unwrap_or_else(|p| p.into_inner());
        if reg.iter().any(|(addr, _)| *addr == easy_addr) {
            return CURLMcode::CURLM_ADDED_ALREADY;
        }
    }

    // Move the configured `Easy` out of the caller's box, leaving a placeholder
    // so the `*mut CURL` allocation remains valid for the eventual
    // `curl_easy_cleanup`. The real `Easy` is handed to the core in a
    // `SharedEasy`.
    // SAFETY: `easy` is a live `Box<core::Easy>` (from `curl_easy_init`),
    // exclusively accessible here under curl's single-thread-per-handle
    // contract, so replacing its pointee is sound and leaves a valid `Easy`.
    let mut real = unsafe { mem::replace(&mut *(easy as *mut core::Easy), core::Easy::new()) };

    // Resolve a stored `CURLOPT_CURLU` pointer into an owned URL clone now, before
    // the core takes ownership and drives the transfer (curl reads the `CURLU`
    // handle at perform time). This mirrors the easy interface's resolve in
    // [`crate::easy::curl_easy_perform`] so multi-interface `CURLOPT_CURLU`
    // consumers behave identically; a NULL (unset) `uh_ptr` is a no-op.
    // SAFETY: `real` is the live `Easy` just moved out of the caller's handle and
    // is uniquely owned here; the caller upholds curl's contract that the `CURLU`
    // passed to `CURLOPT_CURLU` stays valid until the transfer is performed.
    unsafe { crate::easy::resolve_curlu(&mut real) };

    // Register a Send + Sync bridge factory so the multi-driven transfer routes
    // body/header bytes to this handle's `CURLOPT_WRITEFUNCTION`/`HEADERFUNCTION`
    // and pulls upload bytes from `CURLOPT_READFUNCTION`, exactly as the easy
    // interface does in [`crate::easy::curl_easy_perform`]. Without this, a
    // multi-driven transfer falls back to the core's default stdout/stdin sink —
    // the user's write callback never fires and its abort (return 0) is ignored
    // (QA F11-PERF Issue #6). The provider snapshots the callbacks configured up
    // to this add (curl's documented `setopt` -> `add_handle` -> `perform`
    // order); it stores only `usize` addresses, so it borrows nothing from
    // `real`. Build it into a local first because the borrow of `real` for
    // `from_easy` must end before the `&mut real` method receiver is taken.
    let provider = crate::easy::CBridgeProvider::from_easy(&real);
    real.set_multi_io_provider(Arc::new(provider));

    let shared = shared_easy(real);

    // Hand a clone to the core; it takes ownership of its clone (enlisting it in
    // its transfer list) on success.
    let code = handle.inner.add_handle(Arc::clone(&shared));

    if matches!(code, CurlMError::RecursiveApiCall) {
        // The core did not enlist the handle (called re-entrantly from a
        // callback). Undo the move so the caller's box holds the real `Easy`
        // again, and register nothing. `restored` does not contain `easy_addr`,
        // so `restore_easy` performs the swap-back; clear it afterwards since the
        // handle is not tracked.
        restore_easy(&mut handle.restored, &shared, easy_addr);
        handle.restored.remove(&easy_addr);
        return CURLMcode::from(code);
    }

    // Enlisted (CURLM_OK, or CURLM_ABORTED_BY_CALLBACK with the handle still in
    // the transfer list). Record the original pointer -> SharedEasy mapping and
    // mark the handle freshly eligible for a future swap-back.
    {
        let mut reg = handle.registry.lock().unwrap_or_else(|p| p.into_inner());
        reg.push((easy_addr, shared));
    }
    handle.restored.remove(&easy_addr);
    CURLMcode::from(code)
}

/// `curl_multi_remove_handle` — remove an easy handle from the multi stack
/// (`include/curl/multi.h:146`).
///
/// Removes the handle from the core (aborting its task if still running), swaps
/// the real `Easy` back into the caller's box (idempotent — it usually already
/// happened in [`curl_multi_info_read`]) so a subsequent
/// `curl_easy_getinfo`/`curl_easy_cleanup` observes the real results, and drops
/// the registry entry. Mirrors `lib/multi.c:curl_multi_remove_handle`.
///
/// # Safety
///
/// Same preconditions as [`curl_multi_add_handle`].
#[no_mangle]
pub unsafe extern "C" fn curl_multi_remove_handle(multi: *mut CURLM, easy: *mut CURL) -> CURLMcode {
    // SAFETY: see `curl_multi_add_handle`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return CURLMcode::CURLM_BAD_HANDLE,
    };
    if easy.is_null() {
        return CURLMcode::CURLM_BAD_EASY_HANDLE;
    }
    let easy_addr = easy as usize;

    // Locate the registered SharedEasy for this handle.
    let shared = {
        let reg = handle.registry.lock().unwrap_or_else(|p| p.into_inner());
        reg.iter()
            .find(|(addr, _)| *addr == easy_addr)
            .map(|(_, s)| Arc::clone(s))
    };
    let shared = match shared {
        Some(s) => s,
        None => return CURLMcode::CURLM_BAD_EASY_HANDLE,
    };

    // Remove from the core first (this aborts any in-flight driving task).
    let code = handle.inner.remove_handle(&shared);

    // Swap the real `Easy` back into the caller's box (idempotent), then drop the
    // registry entry. Done regardless of `code` so FFI bookkeeping stays
    // consistent with the caller's view of the handle.
    restore_easy(&mut handle.restored, &shared, easy_addr);
    {
        let mut reg = handle.registry.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(pos) = reg.iter().position(|(addr, _)| *addr == easy_addr) {
            reg.remove(pos);
        }
    }
    handle.restored.remove(&easy_addr);
    CURLMcode::from(code)
}

// ===========================================================================
// Phase 3 — drive: perform / socket_action / socket / socket_all
// ===========================================================================

/// `curl_multi_perform` — drive all transfers one iteration set
/// (`include/curl/multi.h:217`).
///
/// Calls the core's synchronous `perform` (which advances its internally-owned
/// Tokio runtime) and writes the count of still-running transfers to
/// `*running_handles`. The `CURLM_CALL_MULTI_PERFORM` signal is preserved: the
/// core returns it when more work is immediately available. This shim does NOT
/// use [`crate::block_on`] — the core owns and drives its own runtime, so
/// wrapping it would nest runtimes (AAP §0.7.4). Mirrors
/// `lib/multi.c:curl_multi_perform`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`];
/// `running_handles` must be NULL or point to a writable `int`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_perform(
    multi: *mut CURLM,
    running_handles: *mut c_int,
) -> CURLMcode {
    // SAFETY: contract on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return CURLMcode::CURLM_BAD_HANDLE,
    };
    let (code, running) = handle.inner.perform();
    if !running_handles.is_null() {
        // SAFETY: the caller guarantees a writable `int` when non-NULL.
        unsafe { *running_handles = running as c_int };
    }
    CURLMcode::from(code)
}

/// `curl_multi_socket_action` — drive the transfers tied to one socket
/// (`include/curl/multi.h:320`).
///
/// The modern, event-driven entry point: `s` is the socket that became ready and
/// `ev_bitmask` carries the `CURL_CSELECT_*` events (`0` means a timeout/“check”
/// drive). Advances the core and writes the running-transfer count. Event-loop
/// semantics — callback timing and `CURLM_CALL_MULTI_PERFORM` signaling — are
/// observably identical to C libcurl so external event loops behave the same
/// (AAP §0.7.4). Mirrors `lib/multi.c:curl_multi_socket_action`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`];
/// `running_handles` must be NULL or point to a writable `int`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_socket_action(
    multi: *mut CURLM,
    s: curl_socket_t,
    ev_bitmask: c_int,
    running_handles: *mut c_int,
) -> CURLMcode {
    // SAFETY: contract on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return CURLMcode::CURLM_BAD_HANDLE,
    };
    let (code, running) = handle.inner.socket_action(s as CurlSocket, ev_bitmask);
    if !running_handles.is_null() {
        // SAFETY: the caller guarantees a writable `int` when non-NULL.
        unsafe { *running_handles = running as c_int };
    }
    CURLMcode::from(code)
}

/// `curl_multi_socket` — deprecated predecessor of
/// [`curl_multi_socket_action`] (`include/curl/multi.h:317`).
///
/// In `multi.h` this name is BOTH a backward-compat macro
/// (`#define curl_multi_socket(x,y,z) curl_multi_socket_action(x,y,0,z)`) AND a
/// real exported symbol. This genuine `#[no_mangle]` function exists so binaries
/// linked against the old symbol still resolve and the parity gate counts 24
/// symbols (AAP / agent prompt). It forwards with `ev_bitmask = 0` — exactly
/// what the macro encodes.
///
/// # Safety
///
/// Same preconditions as [`curl_multi_socket_action`].
#[no_mangle]
pub unsafe extern "C" fn curl_multi_socket(
    multi: *mut CURLM,
    s: curl_socket_t,
    running_handles: *mut c_int,
) -> CURLMcode {
    // SAFETY: arguments are forwarded unchanged and the preconditions are
    // identical to `curl_multi_socket_action`.
    unsafe { curl_multi_socket_action(multi, s, 0, running_handles) }
}

/// `curl_multi_socket_all` — deprecated “check every socket” variant
/// (`include/curl/multi.h:325`).
///
/// Drives every transfer, which in this async core is exactly what `perform`
/// does (the per-connection sockets live inside the runtime, so there is no
/// per-socket scan to perform). Modern code uses [`curl_multi_socket_action`]
/// with `CURL_SOCKET_TIMEOUT`. Mirrors `lib/multi.c:curl_multi_socket_all`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`];
/// `running_handles` must be NULL or point to a writable `int`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_socket_all(
    multi: *mut CURLM,
    running_handles: *mut c_int,
) -> CURLMcode {
    // SAFETY: contract on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return CURLMcode::CURLM_BAD_HANDLE,
    };
    let (code, running) = handle.inner.perform();
    if !running_handles.is_null() {
        // SAFETY: the caller guarantees a writable `int` when non-NULL.
        unsafe { *running_handles = running as c_int };
    }
    CURLMcode::from(code)
}

// ===========================================================================
// Phase 4 — poll / wait / wakeup / fdset
// ===========================================================================

/// `curl_multi_fdset` — extract the descriptor sets for `select()`
/// (`include/curl/multi.h:158`).
///
/// Adds the core's externally-registered sockets to the three `fd_set`s and
/// reports the highest descriptor in `*max_fd` (curl does not zero the sets —
/// the caller is expected to `FD_ZERO` first). When no sockets are registered,
/// `*max_fd` is set to `-1` (curl's “nothing to wait on” marker). In this async
/// re-architecture per-connection sockets live inside the Tokio runtime, so only
/// sockets surfaced via the socket-interest mechanism appear here; the
/// recommended drive loop is `perform` + `poll`. Mirrors
/// `lib/multi.c:curl_multi_fdset`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`]. Each non-NULL
/// `*_fd_set` must point to a writable `fd_set`; `max_fd` must be NULL or point
/// to a writable `int`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_fdset(
    multi: *mut CURLM,
    read_fd_set: *mut fd_set,
    write_fd_set: *mut fd_set,
    exc_fd_set: *mut fd_set,
    max_fd: *mut c_int,
) -> CURLMcode {
    // SAFETY: contract on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return CURLMcode::CURLM_BAD_HANDLE,
    };
    let fds = handle.inner.fdset();

    /// Add each non-negative descriptor in `socks` to the libc `fd_set` if the
    /// set pointer is non-NULL.
    ///
    /// # Safety
    ///
    /// When non-NULL, `set` must point to a writable `fd_set`.
    unsafe fn fill(set: *mut fd_set, socks: &[CurlSocket]) {
        if set.is_null() {
            return;
        }
        for &s in socks {
            if s >= 0 {
                // SAFETY: `set` is non-NULL and writable; `s` is a non-negative
                // descriptor produced by the core and so is in range for
                // `fd_set` on the supported targets.
                unsafe { libc::FD_SET(s as c_int, set) };
            }
        }
    }

    // SAFETY: each pointer is validated as non-NULL inside `fill`; the sockets
    // come from the core's own registration.
    unsafe {
        fill(read_fd_set, &fds.read);
        fill(write_fd_set, &fds.write);
        fill(exc_fd_set, &fds.exc);
    }

    if !max_fd.is_null() {
        // SAFETY: the caller guarantees a writable `int` when non-NULL.
        unsafe { *max_fd = fds.max_fd as c_int };
    }
    CURLMcode::CURLM_OK
}

/// `curl_multi_waitfds` — report the descriptors the multi wants to wait on
/// (`include/curl/multi.h:522`).
///
/// Fills up to `size` entries of the caller's `ufds` array (each a
/// [`curl_waitfd`] with `CURL_WAIT_POLL*` event bits) and writes the total
/// number of descriptors to `*fd_count`. When the array is too small but was
/// provided, returns `CURLM_OUT_OF_MEMORY`; a NULL array is only valid as a
/// capacity query (`size == 0` with a non-NULL `fd_count`). Mirrors the
/// argument validation and truncation signalling of
/// `lib/multi.c:curl_multi_waitfds`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`]. When non-NULL,
/// `ufds` must point to at least `size` writable [`curl_waitfd`]s; `fd_count`
/// must be NULL or point to a writable `unsigned int`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_waitfds(
    multi: *mut CURLM,
    ufds: *mut curl_waitfd,
    size: c_uint,
    fd_count: *mut c_uint,
) -> CURLMcode {
    // Argument validation mirrors lib/multi.c: a NULL array is acceptable only as
    // a capacity query — both `size == 0` and a non-NULL `fd_count`.
    if ufds.is_null() && (size != 0 || fd_count.is_null()) {
        return CURLMcode::CURLM_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: contract on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return CURLMcode::CURLM_BAD_HANDLE,
    };

    // Build the flat (fd, events) list the multi cares about, merging the
    // read/write/exc sets (a socket may appear in several). Exceptional interest
    // is folded into read interest, as curl treats it as readability.
    let fds = handle.inner.fdset();
    let mut entries: Vec<(CurlSocket, c_short)> = Vec::new();
    {
        let mut push_ev = |fd: CurlSocket, ev: c_short| {
            if let Some(slot) = entries.iter_mut().find(|(f, _)| *f == fd) {
                slot.1 |= ev;
            } else {
                entries.push((fd, ev));
            }
        };
        for &s in &fds.read {
            push_ev(s, CURL_WAIT_POLLIN);
        }
        for &s in &fds.write {
            push_ev(s, CURL_WAIT_POLLOUT);
        }
        for &s in &fds.exc {
            push_ev(s, CURL_WAIT_POLLIN);
        }
    }

    let need = entries.len() as c_uint;
    let writable = std::cmp::min(need as usize, size as usize);

    if !ufds.is_null() {
        for (i, (fd, events)) in entries.iter().take(writable).enumerate() {
            // SAFETY: `ufds` points to at least `size >= writable` writable
            // entries (caller contract); `i < writable`.
            unsafe {
                let slot = ufds.add(i);
                (*slot).fd = *fd as curl_socket_t;
                (*slot).events = *events;
                (*slot).revents = 0;
            }
        }
    }

    // curl flags truncation (not all descriptors fit) as OUT_OF_MEMORY, but only
    // when an array was actually provided.
    let result = if need as usize != writable && !ufds.is_null() {
        CURLMcode::CURLM_OUT_OF_MEMORY
    } else {
        CURLMcode::CURLM_OK
    };

    if !fd_count.is_null() {
        // SAFETY: the caller guarantees a writable `unsigned int` when non-NULL.
        unsafe { *fd_count = need };
    }
    result
}

/// `curl_multi_wait` — wait for activity on the multi's and the caller's fds
/// (`include/curl/multi.h:172`).
///
/// Waits up to `timeout_ms` for activity on the core's sockets plus any
/// `extra_fds`, returning the number of ready descriptors in `*ret`. Returning
/// immediately when nothing is registered distinguishes `wait` from `poll`. The
/// core's `wait` is synchronous (it drives its own runtime). Mirrors
/// `lib/multi.c:curl_multi_wait`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`]. When
/// `extra_nfds > 0`, `extra_fds` must point to `extra_nfds` readable/writable
/// [`curl_waitfd`]s; `ret` must be NULL or point to a writable `int`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_wait(
    multi: *mut CURLM,
    extra_fds: *mut curl_waitfd,
    extra_nfds: c_uint,
    timeout_ms: c_int,
    ret: *mut c_int,
) -> CURLMcode {
    // SAFETY: contract on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return CURLMcode::CURLM_BAD_HANDLE,
    };
    // SAFETY: the caller guarantees `extra_fds` points to `extra_nfds` entries.
    let mut extras = unsafe { collect_extra_fds(extra_fds, extra_nfds) };
    let (code, ready) = handle.inner.wait(&mut extras, timeout_ms);
    // The core polled each descriptor and recorded its readiness; propagate the
    // per-fd `revents` back to the caller's array (see `write_back_revents`).
    // SAFETY: same array contract as `collect_extra_fds`.
    unsafe { write_back_revents(extra_fds, extra_nfds, &extras) };
    if !ret.is_null() {
        // SAFETY: the caller guarantees a writable `int` when non-NULL.
        unsafe { *ret = ready as c_int };
    }
    CURLMcode::from(code)
}

/// `curl_multi_poll` — like [`curl_multi_wait`] but blocks even with no fds
/// (`include/curl/multi.h:186`).
///
/// Identical to `wait` except that, when there is nothing to wait on, `poll`
/// still blocks for up to `timeout_ms` (and can be interrupted by
/// [`curl_multi_wakeup`]) rather than returning immediately — curl's documented
/// `poll` vs `wait` distinction, which the core preserves. Mirrors
/// `lib/multi.c:curl_multi_poll`.
///
/// # Safety
///
/// Same preconditions as [`curl_multi_wait`].
#[no_mangle]
pub unsafe extern "C" fn curl_multi_poll(
    multi: *mut CURLM,
    extra_fds: *mut curl_waitfd,
    extra_nfds: c_uint,
    timeout_ms: c_int,
    ret: *mut c_int,
) -> CURLMcode {
    // SAFETY: contract on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return CURLMcode::CURLM_BAD_HANDLE,
    };
    // SAFETY: the caller guarantees `extra_fds` points to `extra_nfds` entries.
    let mut extras = unsafe { collect_extra_fds(extra_fds, extra_nfds) };
    let (code, ready) = handle.inner.poll(&mut extras, timeout_ms);
    // The core polled each descriptor and recorded its readiness; propagate the
    // per-fd `revents` back to the caller's array (see `write_back_revents`).
    // SAFETY: same array contract as `collect_extra_fds`.
    unsafe { write_back_revents(extra_fds, extra_nfds, &extras) };
    if !ret.is_null() {
        // SAFETY: the caller guarantees a writable `int` when non-NULL.
        unsafe { *ret = ready as c_int };
    }
    CURLMcode::from(code)
}

/// `curl_multi_wakeup` — wake a concurrent [`curl_multi_poll`]/[`curl_multi_wait`]
/// (`include/curl/multi.h:199`).
///
/// This is the one multi function curl documents as thread-safe: it may be
/// called from another thread while a `poll`/`wait` runs on the same handle.
/// The core's `wakeup` takes `&self` and only signals a thread-safe `Notify`,
/// so it touches none of the `&mut`-guarded state. Mirrors
/// `lib/multi.c:curl_multi_wakeup`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`]. It may be
/// invoked concurrently with a `poll`/`wait` on the same handle from another
/// thread (per curl's contract); this is sound because the only state reached
/// through the shared reference is the core's internal thread-safe notifier.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_wakeup(multi: *mut CURLM) -> CURLMcode {
    if multi.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE;
    }
    // SAFETY: per the `# Safety` contract `multi` is a live `MultiHandle`. We
    // form a shared reference (not `&mut`) precisely because `wakeup(&self)`
    // only notifies a thread-safe `Notify`; curl guarantees this is the only
    // multi entry point usable concurrently with `poll`/`wait`.
    let handle = unsafe { &*(multi as *const MultiHandle) };
    CURLMcode::from(handle.inner.wakeup())
}

// ===========================================================================
// Phase 5 — info / timeout / assign / get_handles
// ===========================================================================

/// `curl_multi_info_read` — read the next status message
/// (`include/curl/multi.h:260`).
///
/// Pops the next completion message (today always `CURLMSG_DONE`) and returns a
/// `CURLMsg *` whose storage is owned by the multi handle and valid until the
/// next `info_read`/`cleanup` (curl's contract) — it lives inside the
/// [`MultiHandle`], not a per-call heap allocation the caller would free. Before
/// returning, the finished handle's real `Easy` is swapped back into the
/// caller's box so a subsequent `curl_easy_getinfo` reads the real results.
/// `*msgs_in_queue` receives the number of messages still queued. Returns NULL
/// when the queue is empty. Mirrors `lib/multi.c:curl_multi_info_read`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`];
/// `msgs_in_queue` must be NULL or point to a writable `int`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_info_read(
    multi: *mut CURLM,
    msgs_in_queue: *mut c_int,
) -> *mut CURLMsg {
    // SAFETY: contract on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return ptr::null_mut(),
    };

    let msg: CoreCurlMsg = match handle.inner.info_read() {
        Some(m) => m,
        None => {
            if !msgs_in_queue.is_null() {
                // SAFETY: writable `int` per contract.
                unsafe { *msgs_in_queue = 0 };
            }
            return ptr::null_mut();
        }
    };

    // Translate the finished SharedEasy back to the caller's `*mut CURL` and swap
    // the real `Easy` back into the caller's box so getinfo/cleanup see real data
    // (idempotent; a later `remove_handle` is then a no-op for the swap).
    let easy_addr = ptr_for_shared(&handle.registry, &msg.easy_handle);
    restore_easy(&mut handle.restored, &msg.easy_handle, easy_addr);

    // Build the C `CURLMsg` into the handle-owned storage (stable address inside
    // the boxed handle), overwriting any message from a previous `info_read`.
    handle.msg_storage = Some(CURLMsg {
        msg: msgtype_to_c(msg.msg),
        easy_handle: easy_addr as *mut CURL,
        data: CURLMsg_data {
            result: msg.result_code(),
        },
    });

    if !msgs_in_queue.is_null() {
        // SAFETY: writable `int` per contract.
        unsafe { *msgs_in_queue = handle.inner.messages_in_queue() as c_int };
    }

    // The stored message lives in the boxed handle, so its address is stable
    // until the next `info_read`/`cleanup` — exactly the documented C lifetime.
    match handle.msg_storage.as_mut() {
        Some(m) => m as *mut CURLMsg,
        None => ptr::null_mut(),
    }
}

/// `curl_multi_timeout` — how long the app may wait before driving again
/// (`include/curl/multi.h:344`).
///
/// Writes the maximum time, in milliseconds, the application should wait before
/// the next `perform`/`socket_action`, or `-1` when no timeout is pending, from
/// the core's timer state. Mirrors `lib/multi.c:curl_multi_timeout`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`];
/// `milliseconds` must be NULL or point to a writable `long`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_timeout(
    multi: *mut CURLM,
    milliseconds: *mut c_long,
) -> CURLMcode {
    // SAFETY: contract on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return CURLMcode::CURLM_BAD_HANDLE,
    };
    let t = handle.inner.timeout();
    if !milliseconds.is_null() {
        // SAFETY: the caller guarantees a writable `long` when non-NULL.
        unsafe { *milliseconds = t as c_long };
    }
    CURLMcode::CURLM_OK
}

/// `curl_multi_assign` — associate a private pointer with a socket
/// (`include/curl/multi.h:441`).
///
/// The `sockp` cookie is handed back to the socket callback for `sockfd` (it is
/// stored opaquely and never dereferenced by this library). Mirrors
/// `lib/multi.c:curl_multi_assign`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`]. `sockp` is an
/// opaque application pointer.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_assign(
    multi: *mut CURLM,
    sockfd: curl_socket_t,
    sockp: *mut c_void,
) -> CURLMcode {
    // SAFETY: contract on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return CURLMcode::CURLM_BAD_HANDLE,
    };
    CURLMcode::from(
        handle
            .inner
            .assign(sockfd as CurlSocket, UserData(sockp as usize)),
    )
}

/// `curl_multi_get_handles` — return the easy handles currently added
/// (`include/curl/multi.h:454`).
///
/// Returns a NULL-terminated, `malloc`-allocated array of the easy handles in
/// the multi (in no particular order). The caller frees the **array** (not the
/// handles) with `curl_free`; allocating via `libc::malloc` keeps that
/// `malloc`/`free` ownership contract consistent with the rest of the crate.
/// Returns NULL on allocation failure. Mirrors
/// `lib/multi.c:curl_multi_get_handles`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`].
#[no_mangle]
pub unsafe extern "C" fn curl_multi_get_handles(multi: *mut CURLM) -> *mut *mut CURL {
    // SAFETY: contract on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return ptr::null_mut(),
    };

    let shared_list = handle.inner.get_handles();
    let count = shared_list.len();
    // One slot per handle plus the NULL terminator.
    let bytes = match count
        .checked_add(1)
        .and_then(|n| n.checked_mul(mem::size_of::<*mut CURL>()))
    {
        Some(b) if b != 0 => b,
        _ => return ptr::null_mut(),
    };

    // SAFETY: `bytes` is a nonzero size computed without overflow; `malloc`
    // returns storage suitably aligned for `*mut CURL` (pointer alignment) or
    // NULL, which we propagate. The caller frees it with `curl_free`.
    let arr = unsafe { libc::malloc(bytes) } as *mut *mut CURL;
    if arr.is_null() {
        return ptr::null_mut();
    }

    for (i, shared) in shared_list.iter().enumerate() {
        let addr = ptr_for_shared(&handle.registry, shared);
        // SAFETY: `i < count`, and `arr` has `count + 1` writable slots.
        unsafe { *arr.add(i) = addr as *mut CURL };
    }
    // SAFETY: index `count` is the final slot of the `count + 1` allocation.
    unsafe { *arr.add(count) = ptr::null_mut() };
    arr
}

// ===========================================================================
// Phase 6 — curl_multi_setopt (variadic) / get_offt / notify enable+disable
// ===========================================================================

/// Typed Rust implementation behind the public `curl_multi_setopt` C-variadic
/// trampoline (`include/curl/multi.h:429`; **variadic** in C as
/// `CURLMoption option, ...`).
///
/// As with [`curl_easy_setopt`](crate::easy), the public, ABI-exported
/// `curl_multi_setopt` symbol is a genuine C-variadic trampoline in
/// `csrc/variadic_trampolines.c`: a fixed-arity `extern "C" fn(.., arg: usize)`
/// is NOT ABI-equivalent to a C-variadic on every target (macOS arm64 passes the
/// first variadic argument on the stack, not in the register a fixed parameter
/// would use), so the trampoline owns the exported name, extracts the single
/// trailing argument with `va_arg`, and forwards it to this implementation
/// (named `curlrs_multi_setopt_impl`; the non-`curl_` prefix keeps it off the
/// exported `curl_*` ABI surface). C passes exactly one value after `option`. The
/// option id is classified via [`CurlMOption::from_raw`] and dispatched to the
/// core's typed [`setopt`](curl_rs_lib::Multi). Function-pointer options install
/// one of the [`FfiSocketCb`]/[`FfiTimerCb`]/[`FfiPushCb`]/[`FfiNotifyCb`]
/// wrappers (or clear it when `arg` is NULL); data options store the cookie;
/// `long` options take the integer. Unknown options return
/// `CURLM_UNKNOWN_OPTION`. Mirrors `lib/multi.c:curl_multi_setopt`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`]. For
/// function-pointer options `arg` must be either NULL or a valid C callback of
/// the matching `curl_*_callback` type; for data options it is an opaque cookie;
/// for `long` options it is the integer value. Exactly one trailing argument
/// must be supplied, as the C prototype requires.
#[no_mangle]
pub unsafe extern "C" fn curlrs_multi_setopt_impl(
    multi: *mut CURLM,
    option: CURLMoption,
    arg: usize,
) -> CURLMcode {
    // SAFETY: contract on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return CURLMcode::CURLM_BAD_HANDLE,
    };

    let opt = match CurlMOption::from_raw(option) {
        Some(o) => o,
        None => return CURLMcode::CURLM_UNKNOWN_OPTION,
    };

    // `multi` is exactly the stable address of the boxed handle, captured for the
    // callbacks that take a `CURLM *` argument (timer/notify).
    let multi_ptr = multi as usize;
    let registry = Arc::clone(&handle.registry);

    // `arg` carries a C `long` for the integer options; reinterpret the raw
    // `usize` bits as a signed `c_long` so a negative value keeps its sign. On
    // the LP64 targets this workspace builds for (x86_64 / aarch64), `c_long` is
    // `i64`, exactly the width the core's integer `MultiOption`s take.
    let as_long: c_long = arg as c_long;

    let mopt = match opt {
        CurlMOption::SocketFunction => MultiOption::SocketFunction(addr_to_opt(arg).map(|f| {
            Box::new(FfiSocketCb {
                func: f,
                registry: Arc::clone(&registry),
            }) as Box<dyn SocketCallback>
        })),
        CurlMOption::SocketData => MultiOption::SocketData(UserData(arg)),
        CurlMOption::TimerFunction => MultiOption::TimerFunction(
            addr_to_opt(arg)
                .map(|f| Box::new(FfiTimerCb { func: f, multi_ptr }) as Box<dyn TimerCallback>),
        ),
        CurlMOption::TimerData => MultiOption::TimerData(UserData(arg)),
        CurlMOption::PushFunction => MultiOption::PushFunction(addr_to_opt(arg).map(|f| {
            Box::new(FfiPushCb {
                func: f,
                registry: Arc::clone(&registry),
            }) as Box<dyn PushCallback>
        })),
        CurlMOption::PushData => MultiOption::PushData(UserData(arg)),
        CurlMOption::NotifyFunction => MultiOption::NotifyFunction(addr_to_opt(arg).map(|f| {
            Box::new(FfiNotifyCb {
                func: f,
                multi_ptr,
                registry: Arc::clone(&registry),
            }) as Box<dyn NotifyCallback>
        })),
        CurlMOption::NotifyData => MultiOption::NotifyData(UserData(arg)),
        CurlMOption::Pipelining => MultiOption::Pipelining(as_long),
        CurlMOption::MaxConnects => MultiOption::MaxConnects(as_long),
        CurlMOption::MaxHostConnections => MultiOption::MaxHostConnections(as_long),
        CurlMOption::MaxTotalConnections => MultiOption::MaxTotalConnections(as_long),
        CurlMOption::MaxConcurrentStreams => MultiOption::MaxConcurrentStreams(as_long),
        CurlMOption::MaxPipelineLength => MultiOption::MaxPipelineLength(as_long),
        CurlMOption::ContentLengthPenaltySize => MultiOption::ContentLengthPenaltySize(as_long),
        CurlMOption::ChunkLengthPenaltySize => MultiOption::ChunkLengthPenaltySize(as_long),
        CurlMOption::PipeliningSiteBl => MultiOption::PipeliningSiteBl,
        CurlMOption::PipeliningServerBl => MultiOption::PipeliningServerBl,
        CurlMOption::NetworkChanged => MultiOption::NetworkChanged(as_long),
    };

    CURLMcode::from(handle.inner.setopt(mopt))
}

/// `curl_multi_get_offt` — read a numeric multi-handle info value
/// (`include/curl/multi.h:483`).
///
/// Writes the selected `CURLMINFO_*` counter (resolved via
/// [`CurlMInfo::from_raw`]) to `*pvalue`. An unrecognized selector returns
/// `CURLM_UNKNOWN_OPTION`. Mirrors `lib/multi.c:curl_multi_get_offt`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`]; `pvalue` must
/// be NULL or point to a writable `curl_off_t`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_get_offt(
    multi: *mut CURLM,
    info: CURLMinfo_offt,
    pvalue: *mut curl_off_t,
) -> CURLMcode {
    // SAFETY: contract on `multi`.
    let handle = match unsafe { multi_handle_ref(multi) } {
        Some(h) => h,
        None => return CURLMcode::CURLM_BAD_HANDLE,
    };
    let sel = match CurlMInfo::from_raw(info) {
        Some(s) => s,
        None => return CURLMcode::CURLM_UNKNOWN_OPTION,
    };
    match handle.inner.get_offt(sel) {
        Ok(v) => {
            if !pvalue.is_null() {
                // SAFETY: the caller guarantees a writable `curl_off_t` when
                // non-NULL.
                unsafe { *pvalue = v as curl_off_t };
            }
            CURLMcode::CURLM_OK
        }
        Err(e) => CURLMcode::from(e),
    }
}

/// `curl_multi_notify_enable` — enable a multi-level notification
/// (`include/curl/multi.h:544`).
///
/// `notification` is a `CURLMNOTIFY_*` id. The core surfaces notifications
/// through the `CURLMOPT_NOTIFYFUNCTION` callback whenever one is installed and
/// does not expose a separate enable/disable toggle, so this validates the
/// handle and acknowledges with `CURLM_OK` (a faithful no-op preserving the
/// exact header signature, as instructed). Mirrors the signature in
/// `include/curl/multi.h`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`].
#[no_mangle]
pub unsafe extern "C" fn curl_multi_notify_enable(
    multi: *mut CURLM,
    _notification: c_uint,
) -> CURLMcode {
    // SAFETY: contract on `multi`.
    match unsafe { multi_handle_ref(multi) } {
        Some(_) => CURLMcode::CURLM_OK,
        None => CURLMcode::CURLM_BAD_HANDLE,
    }
}

/// `curl_multi_notify_disable` — disable a multi-level notification
/// (`include/curl/multi.h:541`).
///
/// The counterpart to [`curl_multi_notify_enable`]; see its docs for why this is
/// a handle-validating no-op returning `CURLM_OK`. Mirrors the signature in
/// `include/curl/multi.h`.
///
/// # Safety
///
/// `multi` must be NULL or a live handle from [`curl_multi_init`].
#[no_mangle]
pub unsafe extern "C" fn curl_multi_notify_disable(
    multi: *mut CURLM,
    _notification: c_uint,
) -> CURLMcode {
    // SAFETY: contract on `multi`.
    match unsafe { multi_handle_ref(multi) } {
        Some(_) => CURLMcode::CURLM_OK,
        None => CURLMcode::CURLM_BAD_HANDLE,
    }
}

// ===========================================================================
// Phase 7 — server-push headers + strerror
// ===========================================================================

/// `curl_pushheader_byname` — look up a pushed-request header by name
/// (`include/curl/multi.h:504`). Used inside a `CURLMOPT_PUSHFUNCTION` callback.
///
/// HTTP/2 server push is not wired into the core, so a `curl_pushheaders` object
/// is never produced and this always returns NULL. The symbol exists for ABI
/// parity (one of the 24 multi-interface exports). Mirrors
/// `lib/http2.c:curl_pushheader_byname`.
///
/// # Safety
///
/// `h` must be NULL or a `curl_pushheaders *` handed to a push callback, and
/// `name` NULL or a valid NUL-terminated C string. In this build the push
/// callback is never invoked, so both are only ever NULL.
#[no_mangle]
pub unsafe extern "C" fn curl_pushheader_byname(
    _h: *mut curl_pushheaders,
    _name: *const c_char,
) -> *mut c_char {
    // No header object can exist: server push is not surfaced by the core.
    ptr::null_mut()
}

/// `curl_pushheader_bynum` — return the Nth pushed-request header
/// (`include/curl/multi.h:502`). Used inside a `CURLMOPT_PUSHFUNCTION` callback.
///
/// As with [`curl_pushheader_byname`], HTTP/2 server push is not wired into the
/// core, so this always returns NULL; the symbol exists for ABI parity. Mirrors
/// `lib/http2.c:curl_pushheader_bynum`.
///
/// # Safety
///
/// `h` must be NULL or a `curl_pushheaders *` handed to a push callback. In this
/// build the push callback is never invoked, so it is only ever NULL.
#[no_mangle]
pub unsafe extern "C" fn curl_pushheader_bynum(
    _h: *mut curl_pushheaders,
    _num: size_t,
) -> *mut c_char {
    // No header object can exist: server push is not surfaced by the core.
    ptr::null_mut()
}

/// `curl_multi_strerror` — human-readable string for a `CURLMcode`
/// (`include/curl/multi.h:272`).
///
/// Returns a pointer to a static, NUL-terminated string (no allocation) for the
/// given code, via the shared [`crate::error_codes::multi_strerror`] table
/// (which covers every `CURLMcode` from `CURLM_CALL_MULTI_PERFORM` (-1) through
/// `CURLM_UNRECOVERABLE_POLL` (12)). The returned pointer is valid for the life
/// of the program and must not be freed. Mirrors
/// `lib/strerror.c:curl_multi_strerror`.
///
/// The parameter is a plain `c_int`, **not** the closed `CURLMcode` enum: a C
/// caller may pass any integer, so receiving it as `c_int` (rather than a
/// by-value enum, which would materialize an invalid discriminant — undefined
/// behaviour — for an out-of-range value) keeps the boundary sound. The internal
/// total mapping falls through to `"Unknown error"` for any unmapped integer,
/// exactly as `lib/strerror.c`'s `default` arm does.
#[no_mangle]
pub extern "C" fn curl_multi_strerror(code: c_int) -> *const c_char {
    multi_strerror(code)
}

// ===========================================================================
// Unit tests
// ===========================================================================
//
// These exercise the FFI surface directly (the `#[no_mangle]` functions are
// callable by their Rust paths in-crate). They cover handle lifecycle, NULL
// argument handling, the placeholder-swap add/remove bridge, the variadic
// `setopt` dispatch, and the message/info getters — all against an idle multi
// (no real transfers), so behavior is fully deterministic.
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    // The public `curl_multi_setopt` symbol is now the C-variadic `va_arg`
    // trampoline in `csrc/variadic_trampolines.c`; the typed dispatch logic these
    // tests exercise lives in the Rust implementation it forwards to. Alias the
    // implementation symbol back to the public name so the test bodies — which
    // already pass exactly one pointer-width trailing argument as `usize` — read
    // unchanged. (The trampoline's pure va_arg extraction is a C-ABI concern
    // verified by the C/`tests/libtest` callers, not reachable from Rust.)
    use super::curlrs_multi_setopt_impl as curl_multi_setopt;

    /// Allocate a fresh easy handle exactly as `curl_easy_init` does, so the
    /// `*mut CURL` is a `Box<core::Easy>` at a stable address.
    fn make_easy() -> *mut CURL {
        Box::into_raw(Box::new(core::Easy::new())) as *mut CURL
    }

    /// Reclaim an easy handle exactly as `curl_easy_cleanup` does.
    ///
    /// # Safety
    /// `easy` must be a live handle from [`make_easy`], freed exactly once.
    unsafe fn free_easy(easy: *mut CURL) {
        // SAFETY: `easy` is a `Box<core::Easy>` from `make_easy`, not yet freed.
        drop(unsafe { Box::from_raw(easy as *mut core::Easy) });
    }

    #[test]
    fn init_cleanup_roundtrip() {
        let m = curl_multi_init();
        assert!(!m.is_null(), "init must return a non-NULL handle");
        // SAFETY: `m` is a live handle from `curl_multi_init`.
        let code = unsafe { curl_multi_cleanup(m) };
        assert_eq!(code, CURLMcode::CURLM_OK);
    }

    #[test]
    fn cleanup_null_is_bad_handle() {
        // SAFETY: NULL is an explicitly handled input.
        let code = unsafe { curl_multi_cleanup(ptr::null_mut()) };
        assert_eq!(code, CURLMcode::CURLM_BAD_HANDLE);
    }

    #[test]
    fn perform_empty_multi_reports_zero_running() {
        let m = curl_multi_init();
        let mut running: c_int = -42;
        // SAFETY: `m` live; `running` is a writable int.
        let code = unsafe { curl_multi_perform(m, &mut running) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        assert_eq!(running, 0);
        // SAFETY: `m` live, freed once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
    }

    #[test]
    fn socket_action_and_deprecated_socket_on_empty() {
        let m = curl_multi_init();
        let mut running: c_int = -1;
        // The modern entrypoint.
        // SAFETY: `m` live; `running` writable.
        let a = unsafe { curl_multi_socket_action(m, 7, 0, &mut running) };
        assert_eq!(a, CURLMcode::CURLM_OK);
        assert_eq!(running, 0);
        // The deprecated real symbol must exist and forward with ev_bitmask = 0.
        running = -1;
        // SAFETY: `m` live; `running` writable.
        let b = unsafe { curl_multi_socket(m, 7, &mut running) };
        assert_eq!(b, CURLMcode::CURLM_OK);
        assert_eq!(running, 0);
        // SAFETY: `m` live; `running` writable.
        let c = unsafe { curl_multi_socket_all(m, &mut running) };
        assert_eq!(c, CURLMcode::CURLM_OK);
        // SAFETY: `m` live, freed once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
    }

    #[test]
    fn info_read_empty_returns_null() {
        let m = curl_multi_init();
        let mut queued: c_int = 99;
        // SAFETY: `m` live; `queued` writable.
        let msg = unsafe { curl_multi_info_read(m, &mut queued) };
        assert!(msg.is_null());
        assert_eq!(queued, 0);
        // SAFETY: `m` live, freed once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
    }

    #[test]
    fn timeout_no_handles_is_minus_one() {
        let m = curl_multi_init();
        let mut ms: c_long = 12345;
        // SAFETY: `m` live; `ms` writable.
        let code = unsafe { curl_multi_timeout(m, &mut ms) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        assert_eq!(ms, -1, "an idle multi reports no pending timeout");
        // SAFETY: `m` live, freed once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
    }

    #[test]
    fn strerror_covers_all_codes() {
        // Every code from CALL_MULTI_PERFORM (-1) to UNRECOVERABLE_POLL (12)
        // must yield a non-NULL, non-empty static string.
        let codes = [
            CURLMcode::CURLM_CALL_MULTI_PERFORM,
            CURLMcode::CURLM_OK,
            CURLMcode::CURLM_BAD_HANDLE,
            CURLMcode::CURLM_BAD_EASY_HANDLE,
            CURLMcode::CURLM_OUT_OF_MEMORY,
            CURLMcode::CURLM_INTERNAL_ERROR,
            CURLMcode::CURLM_BAD_SOCKET,
            CURLMcode::CURLM_UNKNOWN_OPTION,
            CURLMcode::CURLM_ADDED_ALREADY,
            CURLMcode::CURLM_RECURSIVE_API_CALL,
            CURLMcode::CURLM_WAKEUP_FAILURE,
            CURLMcode::CURLM_BAD_FUNCTION_ARGUMENT,
            CURLMcode::CURLM_ABORTED_BY_CALLBACK,
            CURLMcode::CURLM_UNRECOVERABLE_POLL,
        ];
        for code in codes {
            let p = curl_multi_strerror(code as c_int);
            assert!(!p.is_null());
            // SAFETY: `multi_strerror` returns a static NUL-terminated string.
            let s = unsafe { CStr::from_ptr(p) };
            assert!(!s.to_bytes().is_empty(), "{code:?} has an empty string");
        }
    }

    /// Issue 2 regression: the exported `curl_multi_strerror` takes a `c_int`, so
    /// a C caller may pass any out-of-range integer without invoking undefined
    /// behaviour; every unmapped value returns the catch-all "Unknown error"
    /// string (matching `lib/strerror.c`), never NULL and never a crash.
    #[test]
    fn strerror_out_of_range_is_catch_all() {
        for code in [9999, -5, c_int::MIN, c_int::MAX] {
            let p = curl_multi_strerror(code);
            assert!(!p.is_null(), "multi strerror({code}) returned NULL");
            // SAFETY: returns a static NUL-terminated string for any `c_int`.
            let s = unsafe { CStr::from_ptr(p) }.to_bytes();
            assert_eq!(s, b"Unknown error", "multi strerror({code})");
        }
    }

    #[test]
    fn add_null_easy_is_bad_easy_handle() {
        let m = curl_multi_init();
        // SAFETY: `m` live; NULL easy is explicitly handled.
        let code = unsafe { curl_multi_add_handle(m, ptr::null_mut()) };
        assert_eq!(code, CURLMcode::CURLM_BAD_EASY_HANDLE);
        // SAFETY: `m` live, freed once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
    }

    #[test]
    fn add_remove_roundtrip_and_double_add() {
        let m = curl_multi_init();
        let easy = make_easy();

        // SAFETY: `m` and `easy` are live handles.
        let added = unsafe { curl_multi_add_handle(m, easy) };
        assert_eq!(added, CURLMcode::CURLM_OK);

        // A second add of the same handle is rejected.
        // SAFETY: same live handles.
        let again = unsafe { curl_multi_add_handle(m, easy) };
        assert_eq!(again, CURLMcode::CURLM_ADDED_ALREADY);

        // SAFETY: same live handles; the handle was added.
        let removed = unsafe { curl_multi_remove_handle(m, easy) };
        assert_eq!(removed, CURLMcode::CURLM_OK);

        // Removing an unknown handle now fails.
        // SAFETY: `m` live; `easy` no longer registered.
        let removed_again = unsafe { curl_multi_remove_handle(m, easy) };
        assert_eq!(removed_again, CURLMcode::CURLM_BAD_EASY_HANDLE);

        // SAFETY: `m` live, freed once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
        // SAFETY: `easy` was swapped back into its box on removal; free once.
        unsafe { free_easy(easy) };
    }

    #[test]
    fn get_handles_lists_added_then_null_terminates() {
        let m = curl_multi_init();
        let easy = make_easy();
        // SAFETY: live handles.
        assert_eq!(
            // SAFETY: controlled test invocation of `curl_multi_add_handle`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
            unsafe { curl_multi_add_handle(m, easy) },
            CURLMcode::CURLM_OK
        );

        // SAFETY: `m` live.
        let arr = unsafe { curl_multi_get_handles(m) };
        assert!(!arr.is_null());
        // SAFETY: `arr` has at least 2 slots (one handle + NULL terminator).
        unsafe {
            assert_eq!(*arr.add(0), easy, "the added handle is reported");
            assert!((*arr.add(1)).is_null(), "the array is NULL-terminated");
            // The array is malloc'd; the caller frees it (curl_free == libc::free).
            libc::free(arr as *mut c_void);
        }

        // SAFETY: live handles; cleanup order: remove, cleanup multi, free easy.
        unsafe {
            assert_eq!(curl_multi_remove_handle(m, easy), CURLMcode::CURLM_OK);
            assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK);
            free_easy(easy);
        }
    }

    #[test]
    fn setopt_known_and_unknown_options() {
        let m = curl_multi_init();
        // CURLMOPT_MAXCONNECTS (6) is a LONG option.
        // SAFETY: `m` live; LONG option takes the integer in `arg`.
        let ok = unsafe { curl_multi_setopt(m, 6, 10usize) };
        assert_eq!(ok, CURLMcode::CURLM_OK);

        // CURLMOPT_PIPELINING (3) — CURLPIPE_MULTIPLEX bit.
        // SAFETY: `m` live.
        let pipe = unsafe { curl_multi_setopt(m, 3, 2usize) };
        assert_eq!(pipe, CURLMcode::CURLM_OK);

        // An unrecognized option id.
        // SAFETY: `m` live; unknown option is handled.
        let unknown = unsafe { curl_multi_setopt(m, 99_999, 0usize) };
        assert_eq!(unknown, CURLMcode::CURLM_UNKNOWN_OPTION);

        // SAFETY: `m` live, freed once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
    }

    #[test]
    fn setopt_clearing_callbacks_is_ok() {
        let m = curl_multi_init();
        // Installing then clearing the socket/timer callbacks (NULL arg = clear)
        // must both succeed.
        // SAFETY: `m` live; NULL function pointer clears the callback. The option
        // ids are the public `CURLMOPT_*` integers (`CURLOPTTYPE_<kind> +
        // ordinal`), not bare ordinals — passing the bare ordinal would be
        // rejected as CURLM_UNKNOWN_OPTION (QA F11-PERF Issue #2 L1).
        unsafe {
            // CURLMOPT_SOCKETFUNCTION (FUNCTIONPOINT + 1 = 20001) cleared.
            assert_eq!(curl_multi_setopt(m, 20001, 0usize), CURLMcode::CURLM_OK);
            // CURLMOPT_TIMERFUNCTION (FUNCTIONPOINT + 4 = 20004) cleared.
            assert_eq!(curl_multi_setopt(m, 20004, 0usize), CURLMcode::CURLM_OK);
            // CURLMOPT_SOCKETDATA (OBJECTPOINT + 2 = 10002) / CURLMOPT_TIMERDATA
            // (OBJECTPOINT + 5 = 10005).
            assert_eq!(curl_multi_setopt(m, 10002, 0usize), CURLMcode::CURLM_OK);
            assert_eq!(curl_multi_setopt(m, 10005, 0usize), CURLMcode::CURLM_OK);
            assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK);
        }
    }

    #[test]
    fn get_offt_xfers_current_and_unknown() {
        let m = curl_multi_init();
        let mut value: curl_off_t = -7;
        // CURLMINFO_XFERS_CURRENT (1) on an empty multi is 0.
        // SAFETY: `m` live; `value` writable.
        let code = unsafe { curl_multi_get_offt(m, 1, &mut value) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        assert_eq!(value, 0);

        // An unrecognized selector.
        // SAFETY: `m` live; `value` writable.
        let bad = unsafe { curl_multi_get_offt(m, 999, &mut value) };
        assert_eq!(bad, CURLMcode::CURLM_UNKNOWN_OPTION);

        // SAFETY: `m` live, freed once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
    }

    #[test]
    fn assign_socket_and_bad_socket() {
        let m = curl_multi_init();
        // A real descriptor with an opaque cookie.
        // SAFETY: `m` live; `sockp` opaque.
        let ok = unsafe { curl_multi_assign(m, 5, 0x1234 as *mut c_void) };
        assert_eq!(ok, CURLMcode::CURLM_OK);
        // CURL_SOCKET_BAD (-1) is rejected.
        // SAFETY: `m` live.
        let bad = unsafe { curl_multi_assign(m, -1, ptr::null_mut()) };
        assert_eq!(bad, CURLMcode::CURLM_BAD_SOCKET);
        // SAFETY: `m` live, freed once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
    }

    #[test]
    fn waitfds_validation_and_capacity_query() {
        let m = curl_multi_init();

        // A NULL array with size != 0 is a bad argument.
        // SAFETY: `m` live; NULL array handled.
        let bad = unsafe { curl_multi_waitfds(m, ptr::null_mut(), 1, ptr::null_mut()) };
        assert_eq!(bad, CURLMcode::CURLM_BAD_FUNCTION_ARGUMENT);

        // A capacity query (NULL array, size 0, non-NULL count) on an idle multi
        // reports zero descriptors and succeeds.
        let mut count: c_uint = 7;
        // SAFETY: `m` live; `count` writable.
        let q = unsafe { curl_multi_waitfds(m, ptr::null_mut(), 0, &mut count) };
        assert_eq!(q, CURLMcode::CURLM_OK);
        assert_eq!(count, 0);

        // SAFETY: `m` live, freed once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
    }

    #[test]
    fn fdset_empty_sets_max_fd_minus_one() {
        let m = curl_multi_init();
        let mut max_fd: c_int = 123;
        // SAFETY: `m` live; passing NULL fd_sets is allowed (curl skips them);
        // `max_fd` writable.
        let code = unsafe {
            curl_multi_fdset(
                m,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut max_fd,
            )
        };
        assert_eq!(code, CURLMcode::CURLM_OK);
        assert_eq!(max_fd, -1, "an idle multi has no descriptors to wait on");
        // SAFETY: `m` live, freed once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
    }

    #[test]
    fn wait_and_poll_zero_timeout_on_idle() {
        let m = curl_multi_init();
        let mut ready: c_int = -1;
        // `wait` returns immediately when idle.
        // SAFETY: `m` live; no extra fds; `ready` writable.
        let w = unsafe { curl_multi_wait(m, ptr::null_mut(), 0, 0, &mut ready) };
        assert_eq!(w, CURLMcode::CURLM_OK);
        assert_eq!(ready, 0);
        // `poll` with a zero timeout also returns promptly when idle.
        ready = -1;
        // SAFETY: `m` live; no extra fds; `ready` writable.
        let p = unsafe { curl_multi_poll(m, ptr::null_mut(), 0, 0, &mut ready) };
        assert_eq!(p, CURLMcode::CURLM_OK);
        assert_eq!(ready, 0);
        // SAFETY: `m` live, freed once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
    }

    #[test]
    fn wakeup_is_ok() {
        let m = curl_multi_init();
        // SAFETY: `m` live; wakeup only signals a thread-safe notifier.
        let code = unsafe { curl_multi_wakeup(m) };
        assert_eq!(code, CURLMcode::CURLM_OK);
        // SAFETY: `m` live, freed once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
    }

    #[test]
    fn pushheaders_return_null_without_push() {
        // Server push is not wired; both accessors must return NULL.
        // SAFETY: NULL inputs are explicitly handled.
        unsafe {
            assert!(curl_pushheader_byname(ptr::null_mut(), ptr::null()).is_null());
            assert!(curl_pushheader_bynum(ptr::null_mut(), 0).is_null());
        }
    }

    #[test]
    fn notify_enable_disable_are_ok() {
        let m = curl_multi_init();
        // SAFETY: `m` live.
        unsafe {
            assert_eq!(curl_multi_notify_enable(m, 0), CURLMcode::CURLM_OK);
            assert_eq!(curl_multi_notify_disable(m, 0), CURLMcode::CURLM_OK);
            assert_eq!(
                curl_multi_notify_enable(ptr::null_mut(), 0),
                CURLMcode::CURLM_BAD_HANDLE
            );
            assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK);
        }
    }

    /// End-to-end lifecycle across the FFI surface, mirroring how an event loop
    /// drives the multi interface: `init -> add -> get_handles -> (perform /
    /// drain info_read / socket_action / timeout)* -> remove -> cleanup`.
    ///
    /// No URL is configured, so the transfer fails fast and deterministically:
    /// the core's `pre_perform` short-circuits with `CURLE_URL_MALFORMAT`
    /// without any network I/O, so the driving task finishes near-instantly and
    /// a single `CURLMSG_DONE` is delivered for the added handle. The drive loop
    /// is bounded so the test always terminates; once no handles are running the
    /// task is finished, so removal swaps the real easy back into its box and
    /// `free_easy` reclaims it (no leak, no double-free).
    #[test]
    fn full_lifecycle_drive_loop() {
        let m = curl_multi_init();
        assert!(!m.is_null(), "init must return a non-NULL handle");
        let easy = make_easy();

        // Associate the easy handle with the multi.
        // SAFETY: `m` and `easy` are live handles.
        assert_eq!(
            // SAFETY: controlled test invocation of `curl_multi_add_handle`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
            unsafe { curl_multi_add_handle(m, easy) },
            CURLMcode::CURLM_OK
        );

        // While registered, the handle is reported by get_handles.
        // SAFETY: `m` live; the returned array is malloc'd and NULL-terminated.
        unsafe {
            let arr = curl_multi_get_handles(m);
            assert!(!arr.is_null());
            assert_eq!(*arr.add(0), easy, "the added handle is reported");
            assert!((*arr.add(1)).is_null(), "array is NULL-terminated");
            libc::free(arr as *mut c_void);
        }

        // Drive the multi the way an application would. Each iteration performs,
        // then drains every queued completion, validating its shape, and also
        // exercises the event-driven entrypoint and the timer query so the
        // event-loop contract (AAP 0.7.4) is covered at every step.
        let mut saw_done = false;
        let mut running: c_int = -1;
        for _ in 0..400 {
            // SAFETY: `m` live; `running` is writable.
            let code = unsafe { curl_multi_perform(m, &mut running) };
            assert!(
                code == CURLMcode::CURLM_OK || code == CURLMcode::CURLM_CALL_MULTI_PERFORM,
                "perform returns a success-class code, got {code:?}"
            );
            assert!(running >= 0, "running-handle count is never negative");

            // Drain all currently available completion messages.
            loop {
                let mut in_queue: c_int = -1;
                // SAFETY: `m` live; `in_queue` is writable.
                let msg = unsafe { curl_multi_info_read(m, &mut in_queue) };
                if msg.is_null() {
                    assert_eq!(in_queue, 0, "an empty queue must report 0 remaining");
                    break;
                }
                // SAFETY: a non-NULL message points to multi-owned storage that
                // is valid until the next info_read/cleanup.
                unsafe {
                    assert_eq!(
                        (*msg).msg,
                        CURLMSG::CURLMSG_DONE,
                        "the only message kind today is DONE"
                    );
                    assert_eq!(
                        (*msg).easy_handle,
                        easy,
                        "DONE names the exact handle that was added"
                    );
                }
                assert!(in_queue >= 0, "remaining-message count is never negative");
                saw_done = true;
            }

            // The modern event-driven entrypoint plus the timer query must stay
            // well-behaved throughout the drive.
            let mut ran2: c_int = -1;
            // SAFETY: `m` live; CURL_SOCKET_TIMEOUT requests a timeout tick.
            let sa = unsafe {
                curl_multi_socket_action(m, crate::types::CURL_SOCKET_TIMEOUT, 0, &mut ran2)
            };
            assert!(
                sa == CURLMcode::CURLM_OK || sa == CURLMcode::CURLM_CALL_MULTI_PERFORM,
                "socket_action returns a success-class code, got {sa:?}"
            );
            let mut timeout_ms: c_long = -2;
            // SAFETY: `m` live; `timeout_ms` is writable.
            assert_eq!(
                // SAFETY: controlled test invocation of `curl_multi_timeout`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
                unsafe { curl_multi_timeout(m, &mut timeout_ms) },
                CURLMcode::CURLM_OK
            );
            assert!(
                timeout_ms >= -1,
                "timeout is -1 (none) or a non-negative millisecond value"
            );

            if running == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        // The URL-less transfer fails fast, so the loop settles to zero running
        // handles and the single DONE message was observed.
        assert_eq!(running, 0, "the fast-failing transfer must finish");
        assert!(saw_done, "a CURLMSG_DONE must have been delivered");

        // With no task running, removal swaps the real easy back into its box.
        // SAFETY: live handles; the handle was added.
        assert_eq!(
            // SAFETY: controlled test invocation of `curl_multi_remove_handle`: the handle and pointer arguments are valid for this call (NULL only where the bad-argument path is intentionally exercised).
            unsafe { curl_multi_remove_handle(m, easy) },
            CURLMcode::CURLM_OK
        );
        // SAFETY: `m` live, freed exactly once.
        unsafe { assert_eq!(curl_multi_cleanup(m), CURLMcode::CURLM_OK) };
        // SAFETY: the real easy was restored on removal; free exactly once.
        unsafe { free_easy(easy) };
    }
}
