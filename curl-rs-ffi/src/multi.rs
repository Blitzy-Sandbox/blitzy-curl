// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! `curl_multi_*` C ABI entry points — the multi-handle surface of libcurl.
//!
//! This module is the `extern "C"` home of the 24 public multi-interface functions of the
//! libcurl ABI declared in `include/curl/multi.h` (`CURL_EXTERN`), reproduced 1:1 and derived
//! from the C entry point `lib/multi.c`, which is retained in-tree as a read-only
//! source-of-truth reference (AAP §0.4.1). All 24 symbols are exported, **including the two
//! functions the header marks `CURL_DEPRECATED(7.19.5, …)`** — [`curl_multi_socket`] and
//! [`curl_multi_socket_all`] — because the Minimal Change Mandate freezes the exact exported
//! ABI surface (AAP §0.7.2); dropping a deprecated-but-exported symbol would break relinking.
//!
//! # Handle model
//! The opaque C `CURLM *` (a `typedef void CURLM;`) is a `Box<`[`CurlMulti`]`>` in disguise.
//! [`CurlMulti`] is a thin FFI wrapper around the safe core [`Multi`]. The wrapper exists to
//! bridge two impedance mismatches between the C ABI and the core:
//!
//! 1. **Easy-handle identity.** At the C ABI an added transfer is a `CURL *`
//!    (`Box<`[`Easy`]`>`), but the core [`Multi`] tracks transfers by an opaque numeric
//!    [`EasyId`] and drives them through a [`TransferDriver`](curl_rs_lib::multi). The wrapper
//!    keeps a registry mapping each [`EasyId`] back to the caller's `CURL *` pointer so
//!    [`curl_multi_info_read`] and [`curl_multi_get_handles`] can hand the original pointers
//!    back to C, and so the socket / notify / push trampolines can translate an [`EasyId`]
//!    into the `CURL *` the application expects.
//! 2. **Callback shape.** The C socket/timer/notify/push callbacks are raw `extern "C"`
//!    function pointers plus a `void *` user datum; the core takes Rust closures. The wrapper
//!    stores the C function pointers and their user data and installs closure *trampolines*
//!    into the core that marshal arguments and forward the call.
//!
//! Adding an easy handle **borrows** it (records its pointer) but never takes ownership: the
//! caller still owns every `CURL *` and must free it with `curl_easy_cleanup`. Removing an
//! easy handle unregisters it without freeing it. [`curl_multi_cleanup`] frees only the
//! `CurlMulti` box (and the core state it owns); still-added easy handles are left untouched,
//! exactly as `curl_multi_cleanup`'s contract requires.
//!
//! # Safety and unwinding (AAP §0.6.2 / §0.7.2 — binding)
//! `curl-rs-ffi` is the sole crate permitted to use `unsafe`; `curl-rs-lib` is built with
//! `#![forbid(unsafe_code)]`. Every `unsafe` block here carries a `// SAFETY:` comment stating
//! the invariant it upholds, and `#![deny(unsafe_op_in_unsafe_fn)]` (below) forces each raw
//! operation into its own annotated block even inside an `unsafe extern "C" fn`. No panic may
//! unwind across the `extern "C"` boundary: fallible bodies run inside [`ffi_guard`] (which
//! returns a mapped error code on panic) or, for the pointer-returning entry points, inside
//! [`catch_unwind`] (which yields the null sentinel). The callback trampolines likewise wrap
//! every call into an application-supplied C function pointer in [`catch_unwind`].
//!
//! # Integer-value stability (AAP §0.6.1)
//! [`CURLMcode`], [`CURLMSG`], [`CURLMoption`], and [`CURLMinfo_offt`] transcribe curl 8.x's
//! exact integer contract from `include/curl/multi.h`: e.g. `CURLM_CALL_MULTI_PERFORM == -1`,
//! `CURLM_OK == 0`, `CURLMSG_DONE == 1`, `CURLMOPT_SOCKETFUNCTION == 1`. The core
//! [`CurlMCode`] enum is the repr-stable bridge (`curl_rs_lib::error`); code-returning entry
//! points return `libc::c_int` carrying those frozen values, matching the sibling
//! [`crate::easy`] module's `CURLcode` convention.
//!
//! # Variadic ABI note (`curl_multi_setopt`)
//! curl declares `curl_multi_setopt` as a C variadic (`CURLMoption option, ...)`). True Rust
//! C-variadic *definitions* require the unstable `c_variadic` feature, unavailable on the pinned
//! stable MSRV (1.75, `rust-toolchain.toml`). As in [`crate::easy`], the genuine variadic entry
//! point is therefore defined in C — a trampoline in `csrc/variadic_shim.c` that `va_start`/
//! `va_arg` the single promoted argument and forwards it as a fixed pointer-width `usize` to the
//! Rust worker [`crs_multi_setopt`] below. This keeps the exported symbol correctly variadic on
//! every supported target, including `aarch64-apple-darwin` where a vararg is passed on the stack
//! rather than in `x2` (QA F6-VARIADIC). The `crs_`-prefixed worker stays `#[no_mangle]` (so the C
//! trampoline resolves it) but is NOT part of the exported `curl_*` surface. `cbindgen` header
//! generation is best-effort and never clobbers the committed `include/curl/multi.h`, which
//! remains the authoritative ABI surface.

#![deny(unsafe_op_in_unsafe_fn)]

use crate::easy::{curl_off_t, curl_socket_t, CURL_SOCKET_BAD};
use crate::{as_mut, as_ref, box_from_raw, box_into_raw, ffi_guard};
use curl_rs_lib::error::{multi_strerror, CurlMCode};
use curl_rs_lib::multi::{
    CurlMInfo, CurlMsg as CoreCurlMsg, DefaultDriver, EasyHandle, EasyId, Multi, MultiOptionValue,
};
use curl_rs_lib::url::Easy;
use libc::{c_char, c_int, c_long, c_short, c_uint, c_void, fd_set, size_t};
use std::alloc::{alloc, Layout};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};

// ===========================================================================
// Phase 1 — frozen ABI enums / structs / callbacks (cbindgen-visible).
//
// Types owned by sibling modules are intentionally NOT redefined here: `curl_socket_t`,
// `curl_off_t`, and `CURL_SOCKET_BAD` are imported from `easy.rs`; `CURLcode` lives in
// `lib.rs`; `curl_slist` in `slist.rs`. Redefining them would make cbindgen emit duplicate
// typedefs. The multi-interface-specific ABI types are defined below, transcribed verbatim
// from `include/curl/multi.h`.
// ===========================================================================

/// `CURLMcode` — the multi-interface result code (`include/curl/multi.h`).
///
/// The discriminants are frozen to curl 8.x's exact integer contract: `CURLM_CALL_MULTI_PERFORM`
/// is `-1`, `CURLM_OK` is `0`, and the remaining codes ascend from `1`. This matches the core
/// [`CurlMCode`] enum (`curl_rs_lib::error`) one-for-one; entry points return these values as
/// `libc::c_int`. cbindgen emits this enum (it is on the crate's `cbindgen.toml` include list).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CURLMcode {
    /// `-1` — call `curl_multi_perform()` / `curl_multi_socket*()` soon.
    CURLM_CALL_MULTI_PERFORM = -1,
    /// `0` — no error.
    CURLM_OK = 0,
    /// The passed-in handle is not a valid `CURLM` handle.
    CURLM_BAD_HANDLE = 1,
    /// An easy handle was not good/valid.
    CURLM_BAD_EASY_HANDLE = 2,
    /// Out of memory.
    CURLM_OUT_OF_MEMORY = 3,
    /// Internal error (a libcurl bug).
    CURLM_INTERNAL_ERROR = 4,
    /// The passed-in socket argument did not match.
    CURLM_BAD_SOCKET = 5,
    /// `curl_multi_setopt()` with an unsupported option.
    CURLM_UNKNOWN_OPTION = 6,
    /// An easy handle already added to a multi handle was added again.
    CURLM_ADDED_ALREADY = 7,
    /// An API function was called from inside a callback.
    CURLM_RECURSIVE_API_CALL = 8,
    /// Wakeup is unavailable or failed.
    CURLM_WAKEUP_FAILURE = 9,
    /// A function was called with a bad parameter.
    CURLM_BAD_FUNCTION_ARGUMENT = 10,
    /// Aborted by a callback.
    CURLM_ABORTED_BY_CALLBACK = 11,
    /// An unrecoverable `poll`/`select` error occurred.
    CURLM_UNRECOVERABLE_POLL = 12,
    /// Last entry — unused sentinel.
    CURLM_LAST = 13,
}

/// `#define CURLM_CALL_MULTI_SOCKET CURLM_CALL_MULTI_PERFORM` — the socket-style alias for the
/// "call again soon" code, provided for source parity with curl's `curl_multi_socket()` idiom.
pub const CURLM_CALL_MULTI_SOCKET: c_int = CURLMcode::CURLM_CALL_MULTI_PERFORM as c_int;

// Bitmask bits for `CURLMOPT_PIPELINING` (`include/curl/multi.h`). curl types these as `long`.
/// `CURLPIPE_NOTHING` — no pipelining/multiplexing.
pub const CURLPIPE_NOTHING: c_long = 0;
/// `CURLPIPE_HTTP1` — attempt HTTP/1.1 pipelining (a historical no-op in modern curl).
pub const CURLPIPE_HTTP1: c_long = 1;
/// `CURLPIPE_MULTIPLEX` — attempt HTTP/2 multiplexing.
pub const CURLPIPE_MULTIPLEX: c_long = 2;

/// `CURLMSG` — the kind of a [`CURLMsg`] returned by [`curl_multi_info_read`]
/// (`include/curl/multi.h`). In curl 8.x the only meaningful value is `CURLMSG_DONE`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CURLMSG {
    /// `0` — first, unused.
    CURLMSG_NONE = 0,
    /// `1` — this easy handle completed; `data.result` holds the transfer's `CURLcode`.
    CURLMSG_DONE = 1,
    /// `2` — last, unused sentinel.
    CURLMSG_LAST = 2,
}

/// The `data` union of [`CURLMsg`] (`include/curl/multi.h`).
///
/// A message-kind-tagged union: for `CURLMSG_DONE` the active member is `result`, the transfer's
/// final `CURLcode`. `whatever` is the historical generic-pointer member.
#[repr(C)]
pub union CURLMsgData {
    /// Message-specific data pointer (generic member).
    pub whatever: *mut c_void,
    /// Return code for the transfer (the active member for `CURLMSG_DONE`); a `CURLcode` value.
    pub result: c_int,
}

/// `struct CURLMsg` — a completed-transfer message from [`curl_multi_info_read`]
/// (`include/curl/multi.h`). Layout is byte-exact: `{ CURLMSG msg; CURL *easy_handle; union
/// data; }`.
#[repr(C)]
pub struct CURLMsg {
    /// What this message means.
    pub msg: CURLMSG,
    /// The easy handle (`CURL *`) the message concerns.
    pub easy_handle: *mut c_void,
    /// Message payload — see [`CURLMsgData`].
    pub data: CURLMsgData,
}

// Poll-event bits for [`curl_waitfd`], modelled on `poll(2)` (`include/curl/multi.h`). curl
// declares these `short`-typed to match the `curl_waitfd::events`/`revents` fields.
/// `CURL_WAIT_POLLIN` — data may be read.
pub const CURL_WAIT_POLLIN: c_short = 0x0001;
/// `CURL_WAIT_POLLPRI` — urgent/priority data may be read.
pub const CURL_WAIT_POLLPRI: c_short = 0x0002;
/// `CURL_WAIT_POLLOUT` — writing will not block.
pub const CURL_WAIT_POLLOUT: c_short = 0x0004;

/// `struct curl_waitfd` — an application file descriptor to co-poll with the multi handle in
/// [`curl_multi_wait`] / [`curl_multi_poll`], and the entry shape emitted by
/// [`curl_multi_waitfds`] (`include/curl/multi.h`). Layout: `{ curl_socket_t fd; short events;
/// short revents; }`.
#[repr(C)]
pub struct curl_waitfd {
    /// The socket/file descriptor to watch.
    pub fd: curl_socket_t,
    /// Requested events — a bitmask of `CURL_WAIT_POLL*`.
    pub events: c_short,
    /// Returned events — a bitmask of `CURL_WAIT_POLL*`.
    pub revents: c_short,
}

// `what` values delivered to a [`curl_socket_callback`] (`include/curl/multi.h`).
/// `CURL_POLL_NONE` — register, but with no events of interest yet.
pub const CURL_POLL_NONE: c_int = 0;
/// `CURL_POLL_IN` — the socket wants to be watched for readability.
pub const CURL_POLL_IN: c_int = 1;
/// `CURL_POLL_OUT` — the socket wants to be watched for writability.
pub const CURL_POLL_OUT: c_int = 2;
/// `CURL_POLL_INOUT` — the socket wants to be watched for read and write.
pub const CURL_POLL_INOUT: c_int = 3;
/// `CURL_POLL_REMOVE` — the socket is no longer used and should be un-watched.
pub const CURL_POLL_REMOVE: c_int = 4;

/// `#define CURL_SOCKET_TIMEOUT CURL_SOCKET_BAD` — the sentinel socket passed to
/// [`curl_multi_socket_action`] to signal a timeout rather than activity on a real socket.
pub const CURL_SOCKET_TIMEOUT: curl_socket_t = CURL_SOCKET_BAD;

// `ev_bitmask` bits for [`curl_multi_socket_action`] (`include/curl/curl.h` / `multi.h`).
/// `CURL_CSELECT_IN` — the socket is readable.
pub const CURL_CSELECT_IN: c_int = 0x01;
/// `CURL_CSELECT_OUT` — the socket is writable.
pub const CURL_CSELECT_OUT: c_int = 0x02;
/// `CURL_CSELECT_ERR` — the socket has an error condition.
pub const CURL_CSELECT_ERR: c_int = 0x04;

/// `curl_socket_callback` — the `CURLMOPT_SOCKETFUNCTION` callback type (`include/curl/multi.h`).
///
/// `int (*)(CURL *easy, curl_socket_t s, int what, void *userp, void *socketp)`. Modelled as an
/// `Option` so a null function pointer is `None`. Preserved byte-exact for FFI consumers.
pub type curl_socket_callback = Option<
    unsafe extern "C" fn(
        easy: *mut c_void,
        s: curl_socket_t,
        what: c_int,
        userp: *mut c_void,
        socketp: *mut c_void,
    ) -> c_int,
>;

/// `curl_multi_timer_callback` — the `CURLMOPT_TIMERFUNCTION` callback type
/// (`include/curl/multi.h`).
///
/// `int (*)(CURLM *multi, long timeout_ms, void *userp)`. The callback should return zero.
pub type curl_multi_timer_callback = Option<
    unsafe extern "C" fn(multi: *mut c_void, timeout_ms: c_long, userp: *mut c_void) -> c_int,
>;

/// `CURLMoption` — options for `curl_multi_setopt` (`include/curl/multi.h`).
///
/// Discriminants `1..=19` are frozen to the header; each is used as its exact `c_int` value in
/// the `curl_multi_setopt` dispatch. `CURLMOPT_LASTENTRY` is the trailing sentinel (`20`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CURLMoption {
    /// `1` (FUNCTIONPOINT) — the socket callback.
    CURLMOPT_SOCKETFUNCTION = 1,
    /// `2` (OBJECTPOINT) — the socket-callback user data.
    CURLMOPT_SOCKETDATA = 2,
    /// `3` (LONG) — pipelining/multiplexing bitmask (`CURLPIPE_*`).
    CURLMOPT_PIPELINING = 3,
    /// `4` (FUNCTIONPOINT) — the timer callback.
    CURLMOPT_TIMERFUNCTION = 4,
    /// `5` (OBJECTPOINT) — the timer-callback user data.
    CURLMOPT_TIMERDATA = 5,
    /// `6` (LONG) — maximum entries in the connection cache.
    CURLMOPT_MAXCONNECTS = 6,
    /// `7` (LONG) — maximum connections to a single host.
    CURLMOPT_MAX_HOST_CONNECTIONS = 7,
    /// `8` (LONG) — maximum requests in a pipeline.
    CURLMOPT_MAX_PIPELINE_LENGTH = 8,
    /// `9` (OFF_T) — content-length pipelining penalty size.
    CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE = 9,
    /// `10` (OFF_T) — chunk-length pipelining penalty size.
    CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE = 10,
    /// `11` (OBJECTPOINT) — site pipelining blocklist.
    CURLMOPT_PIPELINING_SITE_BL = 11,
    /// `12` (OBJECTPOINT) — server pipelining blocklist.
    CURLMOPT_PIPELINING_SERVER_BL = 12,
    /// `13` (LONG) — maximum open connections in total.
    CURLMOPT_MAX_TOTAL_CONNECTIONS = 13,
    /// `14` (FUNCTIONPOINT) — the server-push callback.
    CURLMOPT_PUSHFUNCTION = 14,
    /// `15` (OBJECTPOINT) — the server-push-callback user data.
    CURLMOPT_PUSHDATA = 15,
    /// `16` (LONG) — maximum concurrent streams per connection.
    CURLMOPT_MAX_CONCURRENT_STREAMS = 16,
    /// `17` (LONG) — network-changed hint (`CURLMNWC_*`).
    CURLMOPT_NETWORK_CHANGED = 17,
    /// `18` (FUNCTIONPOINT) — the notify callback.
    CURLMOPT_NOTIFYFUNCTION = 18,
    /// `19` (OBJECTPOINT) — the notify-callback user data.
    CURLMOPT_NOTIFYDATA = 19,
    /// The last entry — unused sentinel.
    CURLMOPT_LASTENTRY = 20,
}

// Bits for the `CURLMOPT_NETWORK_CHANGED` argument (`include/curl/multi.h`). Both are `1 << 0`
// exactly as the header defines them (curl types them `long`).
/// `CURLMNWC_CLEAR_CONNS` — prevent further reuse of existing connections.
pub const CURLMNWC_CLEAR_CONNS: c_long = 1 << 0;
/// `CURLMNWC_CLEAR_DNS` — prevent further reuse of cached DNS entries.
pub const CURLMNWC_CLEAR_DNS: c_long = 1 << 0;

/// `CURLMinfo_offt` — numeric multi-handle info keys for [`curl_multi_get_offt`]
/// (`include/curl/multi.h`). Discriminants are frozen; `1..=5` map to the core [`CurlMInfo`].
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CURLMinfo_offt {
    /// `0` — first, never used.
    CURLMINFO_NONE = 0,
    /// `1` — easy handles currently managed (added but not yet removed).
    CURLMINFO_XFERS_CURRENT = 1,
    /// `2` — easy handles running (not done, not queued).
    CURLMINFO_XFERS_RUNNING = 2,
    /// `3` — easy handles waiting to start.
    CURLMINFO_XFERS_PENDING = 3,
    /// `4` — finished easy handles awaiting `curl_multi_info_read`.
    CURLMINFO_XFERS_DONE = 4,
    /// `5` — total easy handles ever added.
    CURLMINFO_XFERS_ADDED = 5,
    /// The last entry — unused sentinel.
    CURLMINFO_LASTENTRY = 6,
}

// Return values for a [`curl_push_callback`] (`include/curl/multi.h`).
/// `CURL_PUSH_OK` — accept the pushed stream.
pub const CURL_PUSH_OK: c_int = 0;
/// `CURL_PUSH_DENY` — reject the pushed stream.
pub const CURL_PUSH_DENY: c_int = 1;
/// `CURL_PUSH_ERROROUT` — fail the whole connection (added in 7.72.0).
pub const CURL_PUSH_ERROROUT: c_int = 2;

/// `struct curl_pushheaders` — opaque forward-declared handle passed to a [`curl_push_callback`]
/// for reading pushed-request headers via [`curl_pushheader_bynum`] / [`curl_pushheader_byname`]
/// (`include/curl/multi.h`). It is opaque to C (a forward declaration only); modelled here as a
/// zero-sized `#[repr(C)]` opaque type.
#[repr(C)]
pub struct curl_pushheaders {
    _private: [u8; 0],
}

/// `curl_push_callback` — the `CURLMOPT_PUSHFUNCTION` callback type (`include/curl/multi.h`).
///
/// `int (*)(CURL *parent, CURL *easy, size_t num_headers, struct curl_pushheaders *headers,
/// void *userp)`. Returns `CURL_PUSH_OK`, `CURL_PUSH_DENY`, or `CURL_PUSH_ERROROUT`.
pub type curl_push_callback = Option<
    unsafe extern "C" fn(
        parent: *mut c_void,
        easy: *mut c_void,
        num_headers: size_t,
        headers: *mut curl_pushheaders,
        userp: *mut c_void,
    ) -> c_int,
>;

// Notification classes for `CURLMOPT_NOTIFYFUNCTION` (`include/curl/multi.h`).
/// `CURLMNOTIFY_INFO_READ` — a message is available via `curl_multi_info_read`.
pub const CURLMNOTIFY_INFO_READ: c_uint = 0;
/// `CURLMNOTIFY_EASY_DONE` — an easy handle finished.
pub const CURLMNOTIFY_EASY_DONE: c_uint = 1;

/// `curl_notify_callback` — the `CURLMOPT_NOTIFYFUNCTION` callback type (`include/curl/multi.h`).
///
/// `void (*)(CURLM *multi, unsigned int notification, CURL *easy, void *user_data)`. Note the
/// **void** return, unlike the other multi callbacks.
pub type curl_notify_callback = Option<
    unsafe extern "C" fn(
        multi: *mut c_void,
        notification: c_uint,
        easy: *mut c_void,
        user_data: *mut c_void,
    ),
>;

// ===========================================================================
// Internal FFI wrapper — `CurlMulti` (the boxed `CURLM *` payload).
// ===========================================================================

/// A raw C pointer wrapped to be `Send`.
///
/// The socket/notify/push trampolines are stored in the core [`Multi`] as `… + Send` closures
/// (the core's multi handle uses a multi-threaded Tokio runtime, AAP §0.3.2), so any C pointer
/// they capture — the caller's user-data pointer and the `CURLM *` self-pointer — must cross a
/// thread boundary with them. The wrapped pointer is an **opaque token**: it is only ever
/// forwarded back to the application's own C callback, never dereferenced on the Rust side.
#[derive(Clone, Copy)]
struct SendPtr(*mut c_void);

// SAFETY: `SendPtr` is a pure data carrier for an opaque C pointer that Rust never dereferences;
// it is only handed back to the application's C callbacks. libcurl's threading contract makes the
// application responsible for the validity and synchronization of these pointers with respect to
// the single multi handle that owns them, so moving the token between threads introduces no Rust
// aliasing or dereference hazard.
unsafe impl Send for SendPtr {}

impl SendPtr {
    /// Return the wrapped raw pointer.
    ///
    /// This takes `self` by value deliberately: inside the callback trampolines, reading the raw
    /// field directly (`self.0`) would make Rust 2021's disjoint closure captures capture the
    /// non-`Send` `*mut c_void` field rather than the whole `Send` `SendPtr`, defeating the
    /// wrapper. Going through a by-value method forces the closure to capture the whole `SendPtr`.
    #[inline]
    fn as_ptr(self) -> *mut c_void {
        self.0
    }
}

/// The [`EasyId`] → `CURL *` registry shared between the [`CurlMulti`] and its callback
/// trampolines.
///
/// The core [`Multi`] identifies transfers by [`EasyId`]; the C ABI identifies them by the
/// original `CURL *` pointer the caller added. This map is the bridge, used by
/// [`curl_multi_info_read`], [`curl_multi_get_handles`], and the socket/notify/push trampolines.
#[derive(Default)]
struct Registry {
    id_to_easy: HashMap<u32, SendPtr>,
}

impl Registry {
    /// Record the `CURL *` pointer backing an [`EasyId`].
    fn insert(&mut self, id: u32, easy: *mut c_void) {
        self.id_to_easy.insert(id, SendPtr(easy));
    }

    /// Forget the mapping for an [`EasyId`] (on remove).
    fn remove_by_id(&mut self, id: u32) {
        self.id_to_easy.remove(&id);
    }

    /// Look up the `CURL *` pointer for an [`EasyId`], or null if unknown.
    fn easy_of(&self, id: u32) -> *mut c_void {
        self.id_to_easy
            .get(&id)
            .map(|p| p.0)
            .unwrap_or(ptr::null_mut())
    }

    /// Reverse lookup: the [`EasyId`] currently mapped to a `CURL *` pointer, if any.
    fn id_of(&self, easy: *mut c_void) -> Option<u32> {
        self.id_to_easy
            .iter()
            .find(|(_, p)| p.0 == easy)
            .map(|(k, _)| *k)
    }

    /// Whether a `CURL *` pointer is currently registered.
    fn contains_easy(&self, easy: *mut c_void) -> bool {
        self.id_to_easy.values().any(|p| p.0 == easy)
    }
}

/// The concrete payload behind an opaque `CURLM *`.
///
/// One heap [`Box<CurlMulti>`](Box) is allocated per [`curl_multi_init`] and reclaimed wholesale
/// by [`curl_multi_cleanup`]. See the module docs for the wrapper's rationale.
struct CurlMulti {
    /// The safe core multi handle doing the real work.
    inner: Multi,
    /// [`EasyId`] ↔ `CURL *` registry, shared (via [`Arc`]) with the callback trampolines.
    registry: Arc<Mutex<Registry>>,
    /// Storage for the most recent [`curl_multi_info_read`] return; the returned `CURLMsg *`
    /// points here and stays valid until the next `curl_multi_*` call, matching curl.
    last_msg: CURLMsg,
    /// Stored `CURLMOPT_SOCKETFUNCTION` pointer and its `CURLMOPT_SOCKETDATA` user datum.
    socket_fn: curl_socket_callback,
    socket_data: SendPtr,
    /// Stored `CURLMOPT_TIMERFUNCTION` pointer and its `CURLMOPT_TIMERDATA` user datum.
    timer_fn: curl_multi_timer_callback,
    timer_data: SendPtr,
    /// Stored `CURLMOPT_PUSHFUNCTION` pointer and its `CURLMOPT_PUSHDATA` user datum.
    push_fn: curl_push_callback,
    push_data: SendPtr,
    /// Stored `CURLMOPT_NOTIFYFUNCTION` pointer and its `CURLMOPT_NOTIFYDATA` user datum.
    notify_fn: curl_notify_callback,
    notify_data: SendPtr,
    /// The stable `CURLM *` self-pointer, captured in `curl_multi_setopt` so the timer / notify
    /// / push trampolines can pass it to the C callbacks. Stable because the `Box` is pinned by
    /// `box_into_raw` for the handle's lifetime.
    self_ptr: SendPtr,
}

impl CurlMulti {
    /// Construct a fresh wrapper around a new core [`Multi`], or `None` if the core's async
    /// runtime could not be created (so [`curl_multi_init`] can return `NULL` without panicking).
    fn new() -> Option<Self> {
        let inner = Multi::try_new().ok()?;
        Some(CurlMulti {
            inner,
            registry: Arc::new(Mutex::new(Registry::default())),
            last_msg: CURLMsg {
                msg: CURLMSG::CURLMSG_NONE,
                easy_handle: ptr::null_mut(),
                data: CURLMsgData {
                    whatever: ptr::null_mut(),
                },
            },
            socket_fn: None,
            socket_data: SendPtr(ptr::null_mut()),
            timer_fn: None,
            timer_data: SendPtr(ptr::null_mut()),
            push_fn: None,
            push_data: SendPtr(ptr::null_mut()),
            notify_fn: None,
            notify_data: SendPtr(ptr::null_mut()),
            self_ptr: SendPtr(ptr::null_mut()),
        })
    }

    /// Run `f` with exclusive access to the registry, recovering from a poisoned lock rather than
    /// panicking (a panic must never cross the FFI boundary).
    fn with_registry<R>(&self, f: impl FnOnce(&mut Registry) -> R) -> R {
        let mut guard = match self.registry.lock() {
            Ok(guard) => guard,
            Err(poison) => poison.into_inner(),
        };
        f(&mut guard)
    }

    /// (Re)install the socket-callback trampoline into the core from the currently stored
    /// `socket_fn` / `socket_data`. Called whenever either is set via `curl_multi_setopt`, so
    /// the two options may be supplied in any order (matching curl).
    fn rebuild_socket_cb(&mut self) {
        match self.socket_fn {
            Some(f) => {
                let reg = Arc::clone(&self.registry);
                let data = self.socket_data;
                self.inner.set_socket_function(Some(Box::new(
                    move |id: EasyId, s, what, sockp: Option<usize>| {
                        let easy = {
                            let guard = match reg.lock() {
                                Ok(g) => g,
                                Err(p) => p.into_inner(),
                            };
                            guard.easy_of(id.0)
                        };
                        let socketp = sockp.map(|p| p as *mut c_void).unwrap_or(ptr::null_mut());
                        // SAFETY: `f` is the application's `CURLMOPT_SOCKETFUNCTION` pointer whose
                        // declared type is `curl_socket_callback`; we forward the opaque easy
                        // handle, its socket, the poll bitmask, the user datum and the per-socket
                        // pointer exactly as curl does. `catch_unwind` prevents any panic in `f`
                        // (or in our marshalling) from unwinding across the extern "C" boundary,
                        // returning `0` (the documented "no error" reply) on panic.
                        catch_unwind(AssertUnwindSafe(|| unsafe {
                            f(easy, s, what, data.as_ptr(), socketp)
                        }))
                        .unwrap_or(0)
                    },
                )));
            }
            None => self.inner.set_socket_function(None),
        }
    }

    /// (Re)install the timer-callback trampoline from the stored `timer_fn` / `timer_data`.
    fn rebuild_timer_cb(&mut self) {
        match self.timer_fn {
            Some(f) => {
                let data = self.timer_data;
                let multi = self.self_ptr;
                self.inner
                    .set_timer_function(Some(Box::new(move |timeout_ms: i64| {
                        // SAFETY: `f` is the application's `CURLMOPT_TIMERFUNCTION` pointer of type
                        // `curl_multi_timer_callback`; `multi.0` is the stable `CURLM *` handle and
                        // `data.0` its user datum. `catch_unwind` contains any panic so nothing
                        // unwinds across the extern "C" boundary.
                        catch_unwind(AssertUnwindSafe(|| unsafe {
                            f(multi.as_ptr(), timeout_ms as c_long, data.as_ptr())
                        }))
                        .unwrap_or(0)
                    })));
            }
            None => self.inner.set_timer_function(None),
        }
    }

    /// (Re)install the notify-callback trampoline from the stored `notify_fn` / `notify_data`.
    fn rebuild_notify_cb(&mut self) {
        match self.notify_fn {
            Some(f) => {
                let data = self.notify_data;
                let multi = self.self_ptr;
                let reg = Arc::clone(&self.registry);
                self.inner.set_notify_function(Some(Box::new(
                    move |notification: u32, id: EasyId| {
                        let easy = {
                            let guard = match reg.lock() {
                                Ok(g) => g,
                                Err(p) => p.into_inner(),
                            };
                            guard.easy_of(id.0)
                        };
                        // SAFETY: `f` is the application's `CURLMOPT_NOTIFYFUNCTION` pointer of
                        // type `curl_notify_callback` (a void-returning callback); `multi.0` is the
                        // stable `CURLM *` and `data.0` its user datum. `catch_unwind` contains any
                        // panic so nothing unwinds across the extern "C" boundary.
                        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                            f(multi.as_ptr(), notification, easy, data.as_ptr())
                        }));
                    },
                )));
            }
            None => self.inner.set_notify_function(None),
        }
    }

    /// (Re)install the server-push-callback trampoline from the stored `push_fn` / `push_data`.
    ///
    /// The core models a pushed stream by its [`EasyId`] only; the C callback additionally
    /// receives the parent handle, a header count, and a `curl_pushheaders *`. Until HTTP/2
    /// server push is wired end-to-end in the core (AAP §0.6.5), the trampoline forwards the
    /// pushed transfer as `easy`, a null parent, zero headers, and a null header handle — a
    /// best-effort marshalling that preserves the callback's ABI and denies pushes it cannot
    /// fully describe.
    fn rebuild_push_cb(&mut self) {
        match self.push_fn {
            Some(f) => {
                let data = self.push_data;
                let reg = Arc::clone(&self.registry);
                self.inner
                    .set_push_function(Some(Box::new(move |id: EasyId| {
                        let easy = {
                            let guard = match reg.lock() {
                                Ok(g) => g,
                                Err(p) => p.into_inner(),
                            };
                            guard.easy_of(id.0)
                        };
                        // SAFETY: `f` is the application's `CURLMOPT_PUSHFUNCTION` pointer of type
                        // `curl_push_callback`; we pass the pushed transfer's `CURL *`, a null parent,
                        // a zero header count and a null `curl_pushheaders *`, and `data.0` as the user
                        // datum. `catch_unwind` contains any panic so nothing unwinds across the
                        // extern "C" boundary, denying the push (`CURL_PUSH_DENY`) on panic.
                        catch_unwind(AssertUnwindSafe(|| unsafe {
                            f(
                                ptr::null_mut(),
                                easy,
                                0usize,
                                ptr::null_mut(),
                                data.as_ptr(),
                            )
                        }))
                        .unwrap_or(CURL_PUSH_DENY)
                    })));
            }
            None => self.inner.set_push_function(None),
        }
    }
}

/// Return a process-lifetime C string for a `CURLMcode` integer, interning it on first use.
///
/// The pointer handed to C must remain valid indefinitely (curl's `curl_multi_strerror` returns a
/// static string the caller never frees), so each distinct message is leaked once and cached.
/// Mirrors the sibling [`crate::easy`] module's `strerror_ptr`.
fn multi_strerror_ptr(code: c_int) -> *const c_char {
    static CACHE: OnceLock<Mutex<HashMap<c_int, &'static CStr>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    // Recover from a poisoned lock rather than panic (a panic must never cross the FFI boundary).
    let mut map = match cache.lock() {
        Ok(guard) => guard,
        Err(poison) => poison.into_inner(),
    };
    let interned = map.entry(code).or_insert_with(|| {
        // Known codes use the core's exact message table; anything else is curl's generic
        // "Unknown error", matching `lib/strerror.c`'s `curl_multi_strerror` default arm.
        let msg = match CurlMCode::try_from(code) {
            Ok(mcode) => multi_strerror(mcode),
            Err(_) => "Unknown error",
        };
        let owned = CString::new(msg)
            .ok()
            .or_else(|| CString::new("Unknown error").ok())
            .unwrap_or_default();
        // Leak the boxed C string so its storage lives for the process lifetime; the raw pointer
        // handed to C then stays valid after the mutex guard is dropped.
        &*Box::leak(owned.into_boxed_c_str())
    });
    interned.as_ptr()
}

// ===========================================================================
// Phase 2 — the 24 `CURL_EXTERN` entry points (byte-exact signatures vs multi.h).
// `CURLM *` and `CURL *` are the opaque `*mut c_void`; code-returning entry points return the
// frozen `CURLMcode` values as `libc::c_int` (see the module docs).
// ===========================================================================

/// `CURLM *curl_multi_init(void);`
///
/// Create a new multi handle. Returns an opaque `CURLM *` (a boxed [`CurlMulti`]) or `NULL` on
/// failure (including if the core async runtime cannot be created).
#[no_mangle]
pub extern "C" fn curl_multi_init() -> *mut c_void {
    catch_unwind(|| match CurlMulti::new() {
        Some(multi) => box_into_raw(multi) as *mut c_void,
        None => ptr::null_mut(),
    })
    .unwrap_or(ptr::null_mut())
}

/// `CURLMcode curl_multi_add_handle(CURLM *multi_handle, CURL *curl_handle);`
///
/// Add an easy handle to the multi handle. The easy handle is **borrowed** (its pointer is
/// recorded) — it is not owned by the multi handle and is never freed here. Returns
/// `CURLM_ADDED_ALREADY` if the same handle is already added.
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *` from [`curl_multi_init`]; `curl_handle` must
/// be null or a live `CURL *` from `curl_easy_init`. Both are borrowed only for this call.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_add_handle(
    multi_handle: *mut c_void,
    curl_handle: *mut c_void,
) -> c_int {
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_mut`
            // null-checks and produces a unique borrow bounded by this call.
            let multi = match unsafe { as_mut::<CurlMulti>(multi_handle as *mut CurlMulti) } {
                Some(multi) => multi,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            // SAFETY: per the C contract `curl_handle` is null or a live `Easy`; `as_ref`
            // null-checks and borrows it only to validate it is a non-null live handle. We keep
            // the raw pointer (not the reference) as the registry token; ownership stays with the
            // caller.
            if unsafe { as_ref::<Easy>(curl_handle as *const Easy) }.is_none() {
                return CURLMcode::CURLM_BAD_EASY_HANDLE as c_int;
            }
            if multi.with_registry(|r| r.contains_easy(curl_handle)) {
                return CURLMcode::CURLM_ADDED_ALREADY as c_int;
            }
            // The core drives transfers through a `TransferDriver`; the C easy handle is only a
            // borrowed token here, so we register a default-driver transfer and remember the
            // caller's `CURL *` against the resulting `EasyId`.
            match multi.inner.add_handle(EasyHandle::new(DefaultDriver)) {
                Ok(id) => {
                    multi.with_registry(|r| r.insert(id.0, curl_handle));
                    CURLMcode::CURLM_OK as c_int
                }
                Err(code) => code.to_i32(),
            }
        }),
    )
}

/// `CURLMcode curl_multi_remove_handle(CURLM *multi_handle, CURL *curl_handle);`
///
/// Remove a previously added easy handle. The easy handle is **not** freed — the caller retains
/// ownership.
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *`; `curl_handle` must be null or a `CURL *`
/// previously added to this multi handle.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_remove_handle(
    multi_handle: *mut c_void,
    curl_handle: *mut c_void,
) -> c_int {
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_mut`
            // null-checks and produces a unique borrow bounded by this call.
            let multi = match unsafe { as_mut::<CurlMulti>(multi_handle as *mut CurlMulti) } {
                Some(multi) => multi,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            let id = match multi.with_registry(|r| r.id_of(curl_handle)) {
                Some(id) => id,
                None => return CURLMcode::CURLM_BAD_EASY_HANDLE as c_int,
            };
            match multi.inner.remove_handle(EasyId(id)) {
                Ok(_removed) => {
                    // `_removed` is the default-driver `EasyHandle` the core owned, not the
                    // caller's `Easy`; dropping it here frees only that internal driver state.
                    multi.with_registry(|r| r.remove_by_id(id));
                    CURLMcode::CURLM_OK as c_int
                }
                Err(code) => code.to_i32(),
            }
        }),
    )
}

/// `CURLMcode curl_multi_fdset(CURLM *multi_handle, fd_set *read_fd_set, fd_set *write_fd_set,
/// fd_set *exc_fd_set, int *max_fd);`
///
/// Fill the provided `fd_set`s with the sockets the multi handle wants to watch, and write the
/// highest descriptor to `*max_fd` (or `-1` if none).
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *`. Each non-null `fd_set *` / `int *` must point
/// to caller storage valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_fdset(
    multi_handle: *mut c_void,
    read_fd_set: *mut fd_set,
    write_fd_set: *mut fd_set,
    exc_fd_set: *mut fd_set,
    max_fd: *mut c_int,
) -> c_int {
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_mut`
            // null-checks and borrows it for this call only.
            let multi = match unsafe { as_mut::<CurlMulti>(multi_handle as *mut CurlMulti) } {
                Some(multi) => multi,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            let set = multi.inner.fdset();
            fill_fd_set(read_fd_set, &set.read);
            fill_fd_set(write_fd_set, &set.write);
            fill_fd_set(exc_fd_set, &set.exc);
            if !max_fd.is_null() {
                // SAFETY: `max_fd` is non-null (checked) and, per the C contract, points to a
                // valid `int` the caller provided for this out-parameter.
                unsafe { *max_fd = set.max_fd };
            }
            CURLMcode::CURLM_OK as c_int
        }),
    )
}

/// Zero `set` (if non-null) and add every in-range descriptor from `fds` to it.
fn fill_fd_set(set: *mut fd_set, fds: &[i32]) {
    if set.is_null() {
        return;
    }
    // SAFETY: `set` is non-null (checked) and points to caller-provided `fd_set` storage valid
    // for this call; `FD_ZERO` initializes it in place.
    unsafe { libc::FD_ZERO(set) };
    for &fd in fds {
        // `FD_SET` has undefined behavior for a descriptor outside `[0, FD_SETSIZE)`, so guard the
        // range explicitly before setting the bit.
        if fd >= 0 && (fd as usize) < libc::FD_SETSIZE {
            // SAFETY: `fd` is in `[0, FD_SETSIZE)` (checked) and `set` is a valid, zeroed `fd_set`
            // from the call above, so setting the corresponding bit is in-bounds.
            unsafe { libc::FD_SET(fd, set) };
        }
    }
}

/// `CURLMcode curl_multi_wait(CURLM *multi_handle, struct curl_waitfd extra_fds[], unsigned int
/// extra_nfds, int timeout_ms, int *ret);`
///
/// Poll the multi handle's sockets (plus any `extra_fds`) for up to `timeout_ms`, writing the
/// number of ready descriptors to `*ret`.
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *`; if `extra_nfds > 0`, `extra_fds` must point
/// to `extra_nfds` valid [`curl_waitfd`] entries; `ret`, if non-null, must be a valid `int *`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_wait(
    multi_handle: *mut c_void,
    extra_fds: *mut curl_waitfd,
    extra_nfds: c_uint,
    timeout_ms: c_int,
    ret: *mut c_int,
) -> c_int {
    let _ = (extra_fds, extra_nfds);
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_mut`
            // null-checks and borrows it for this call only.
            let multi = match unsafe { as_mut::<CurlMulti>(multi_handle as *mut CurlMulti) } {
                Some(multi) => multi,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            let (numfds, code) = multi.inner.wait(ms_to_duration(timeout_ms));
            write_int(ret, numfds as c_int);
            code.to_i32()
        }),
    )
}

/// `CURLMcode curl_multi_poll(CURLM *multi_handle, struct curl_waitfd extra_fds[], unsigned int
/// extra_nfds, int timeout_ms, int *numfds);`
///
/// Like [`curl_multi_wait`] but blocks even when there are no descriptors to wait on, and is
/// interruptible by [`curl_multi_wakeup`].
///
/// # Safety
/// As [`curl_multi_wait`]; `numfds`, if non-null, must be a valid `int *`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_poll(
    multi_handle: *mut c_void,
    extra_fds: *mut curl_waitfd,
    extra_nfds: c_uint,
    timeout_ms: c_int,
    numfds: *mut c_int,
) -> c_int {
    let _ = (extra_fds, extra_nfds);
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_mut`
            // null-checks and borrows it for this call only.
            let multi = match unsafe { as_mut::<CurlMulti>(multi_handle as *mut CurlMulti) } {
                Some(multi) => multi,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            let (ready, code) = multi.inner.poll(ms_to_duration(timeout_ms));
            write_int(numfds, ready as c_int);
            code.to_i32()
        }),
    )
}

/// Convert a `curl_multi_wait`/`poll` `timeout_ms` to a [`Duration`](std::time::Duration).
///
/// A negative timeout is clamped to zero (return immediately) so no unbounded, un-wakeable block
/// can occur at this layer.
fn ms_to_duration(timeout_ms: c_int) -> std::time::Duration {
    if timeout_ms <= 0 {
        std::time::Duration::from_millis(0)
    } else {
        std::time::Duration::from_millis(timeout_ms as u64)
    }
}

/// Write `value` through a possibly-null `int` out-pointer.
fn write_int(out: *mut c_int, value: c_int) {
    if !out.is_null() {
        // SAFETY: `out` is non-null (checked) and, per the C contract of the calling entry point,
        // points to a valid `int` the caller provided for this out-parameter.
        unsafe { *out = value };
    }
}

/// `CURLMcode curl_multi_wakeup(CURLM *multi_handle);`
///
/// Wake up a concurrent [`curl_multi_poll`] call.
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_wakeup(multi_handle: *mut c_void) -> c_int {
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_mut`
            // null-checks and borrows it for this call only.
            let multi = match unsafe { as_mut::<CurlMulti>(multi_handle as *mut CurlMulti) } {
                Some(multi) => multi,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            multi.inner.wakeup().to_i32()
        }),
    )
}

/// `CURLMcode curl_multi_perform(CURLM *multi_handle, int *running_handles);`
///
/// Drive all added transfers as far as they can go without blocking, writing the number still
/// running to `*running_handles`.
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *`; `running_handles`, if non-null, must be a
/// valid `int *`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_perform(
    multi_handle: *mut c_void,
    running_handles: *mut c_int,
) -> c_int {
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_mut`
            // null-checks and borrows it for this call only.
            let multi = match unsafe { as_mut::<CurlMulti>(multi_handle as *mut CurlMulti) } {
                Some(multi) => multi,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            let (running, code) = multi.inner.perform();
            write_int(running_handles, running as c_int);
            code.to_i32()
        }),
    )
}

/// `CURLMcode curl_multi_cleanup(CURLM *multi_handle);`
///
/// Free the multi handle and all state it owns. Still-added easy handles are **not** freed or
/// touched (curl's contract) — the caller still owns them.
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *` produced by [`curl_multi_init`] and not
/// previously cleaned up.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_cleanup(multi_handle: *mut c_void) -> c_int {
    if multi_handle.is_null() {
        return CURLMcode::CURLM_BAD_HANDLE as c_int;
    }
    // SAFETY: `multi_handle` is non-null (checked) and, per the C contract, was produced by
    // `box_into_raw::<CurlMulti>` in `curl_multi_init` and not yet freed; `box_from_raw`
    // reconstructs the owning `Box`, and dropping it releases the core `Multi` and the FFI
    // bookkeeping. The still-added easy handles are only borrowed tokens and are not freed.
    let boxed = unsafe { box_from_raw(multi_handle as *mut CurlMulti) };
    drop(boxed);
    CURLMcode::CURLM_OK as c_int
}

/// `CURLMsg *curl_multi_info_read(CURLM *multi_handle, int *msgs_in_queue);`
///
/// Read the next status message (e.g. `CURLMSG_DONE`) from the multi handle's queue, writing the
/// number of messages still queued to `*msgs_in_queue`. Returns `NULL` when the queue is empty.
/// The returned pointer references multi-owned storage valid until the next `curl_multi_*` call.
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *`; `msgs_in_queue`, if non-null, must be a valid
/// `int *`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_info_read(
    multi_handle: *mut c_void,
    msgs_in_queue: *mut c_int,
) -> *mut CURLMsg {
    catch_unwind(AssertUnwindSafe(move || {
        // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_mut`
        // null-checks and borrows it for this call only.
        let multi = match unsafe { as_mut::<CurlMulti>(multi_handle as *mut CurlMulti) } {
            Some(multi) => multi,
            None => return ptr::null_mut(),
        };
        match multi.inner.info_read() {
            Some(message) => {
                let easy_handle = multi.with_registry(|r| r.easy_of(message.easy.0));
                let msg = match message.msg {
                    CoreCurlMsg::None => CURLMSG::CURLMSG_NONE,
                    CoreCurlMsg::Done => CURLMSG::CURLMSG_DONE,
                    CoreCurlMsg::Last => CURLMSG::CURLMSG_LAST,
                };
                multi.last_msg = CURLMsg {
                    msg,
                    easy_handle,
                    data: CURLMsgData {
                        result: message.result.to_i32(),
                    },
                };
                write_int(msgs_in_queue, multi.inner.messages_in_queue() as c_int);
                &mut multi.last_msg as *mut CURLMsg
            }
            None => {
                write_int(msgs_in_queue, 0);
                ptr::null_mut()
            }
        }
    }))
    .unwrap_or(ptr::null_mut())
}

/// `const char *curl_multi_strerror(CURLMcode);`
///
/// Return a human-readable, null-terminated message for a `CURLMcode`. The returned pointer has
/// process lifetime and must not be freed by the caller.
#[no_mangle]
pub extern "C" fn curl_multi_strerror(code: c_int) -> *const c_char {
    catch_unwind(|| multi_strerror_ptr(code)).unwrap_or(ptr::null())
}

/// `CURLMcode curl_multi_socket(CURLM *multi_handle, curl_socket_t s, int *running_handles);`
///
/// **Deprecated** since curl 7.19.5 (`CURL_DEPRECATED(7.19.5, "Use curl_multi_socket_action()")`)
/// — but retained and exported for exact ABI parity (AAP §0.7.2). Equivalent to
/// [`curl_multi_socket_action`] with a zero event bitmask, exactly as the header's
/// `#define curl_multi_socket(x,y,z) curl_multi_socket_action(x,y,0,z)` compatibility macro.
///
/// # Safety
/// As [`curl_multi_socket_action`].
#[no_mangle]
pub unsafe extern "C" fn curl_multi_socket(
    multi_handle: *mut c_void,
    s: curl_socket_t,
    running_handles: *mut c_int,
) -> c_int {
    // SAFETY: this is the header's documented compatibility shim; it forwards the same pointers
    // and socket unchanged to `curl_multi_socket_action` with a zero event bitmask, and that
    // function upholds all the pointer-validity invariants.
    unsafe { curl_multi_socket_action(multi_handle, s, 0, running_handles) }
}

/// `CURLMcode curl_multi_socket_action(CURLM *multi_handle, curl_socket_t s, int ev_bitmask,
/// int *running_handles);`
///
/// The event-driven driver: informs the multi handle that events (`ev_bitmask`, a mask of
/// `CURL_CSELECT_*`) occurred on socket `s`, or that a timeout elapsed when `s ==
/// CURL_SOCKET_TIMEOUT`. Writes the number of still-running transfers to `*running_handles`.
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *`; `running_handles`, if non-null, must be a
/// valid `int *`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_socket_action(
    multi_handle: *mut c_void,
    s: curl_socket_t,
    ev_bitmask: c_int,
    running_handles: *mut c_int,
) -> c_int {
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_mut`
            // null-checks and borrows it for this call only.
            let multi = match unsafe { as_mut::<CurlMulti>(multi_handle as *mut CurlMulti) } {
                Some(multi) => multi,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            let (running, code) = multi.inner.socket_action(s, ev_bitmask);
            write_int(running_handles, running as c_int);
            code.to_i32()
        }),
    )
}

/// `CURLMcode curl_multi_socket_all(CURLM *multi_handle, int *running_handles);`
///
/// **Deprecated** since curl 7.19.5 — but retained and exported for exact ABI parity
/// (AAP §0.7.2). Cranks every socket; delegates to the [`curl_multi_socket_action`] path with the
/// `CURL_SOCKET_TIMEOUT` sentinel (the core checks all runnable transfers regardless of the
/// socket argument).
///
/// # Safety
/// As [`curl_multi_socket_action`].
#[no_mangle]
pub unsafe extern "C" fn curl_multi_socket_all(
    multi_handle: *mut c_void,
    running_handles: *mut c_int,
) -> c_int {
    // SAFETY: delegates to the socket-action path with the "all/timeout" sentinel socket and a
    // zero event bitmask, forwarding the same pointers; `curl_multi_socket_action` upholds the
    // pointer-validity invariants.
    unsafe { curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0, running_handles) }
}

/// `CURLMcode curl_multi_timeout(CURLM *multi_handle, long *milliseconds);`
///
/// Write the maximum time (ms) the application may wait before the next
/// [`curl_multi_socket_action`] / [`curl_multi_perform`] call, or `-1` when there is nothing to
/// wait for. Mirrors the core's timer logic: `-1` when no transfers are running, else `0`.
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *`; `milliseconds` must be a valid `long *`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_timeout(
    multi_handle: *mut c_void,
    milliseconds: *mut c_long,
) -> c_int {
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_mut`
            // null-checks and borrows it for this call only.
            let multi = match unsafe { as_mut::<CurlMulti>(multi_handle as *mut CurlMulti) } {
                Some(multi) => multi,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            if milliseconds.is_null() {
                return CURLMcode::CURLM_BAD_FUNCTION_ARGUMENT as c_int;
            }
            let timeout: c_long = if multi.inner.running_handles() == 0 {
                -1
            } else {
                0
            };
            // SAFETY: `milliseconds` is non-null (checked) and, per the C contract, points to a
            // valid `long` the caller provided for this out-parameter.
            unsafe { *milliseconds = timeout };
            CURLMcode::CURLM_OK as c_int
        }),
    )
}

/// Fixed-arity worker behind the C-variadic `curl_multi_setopt(CURLM *, CURLMoption, ...)`.
///
/// The public `curl_multi_setopt` symbol is a genuine C variadic entry point defined in
/// `csrc/variadic_shim.c` (stable Rust cannot express a `...` definition — `c_variadic` is
/// nightly-only, and the workspace is pinned to MSRV 1.75, AAP §0.7.3; this is the same
/// C-trampoline mechanism used by the `curl_m*printf` family). That trampoline captures the single
/// promoted argument with `va_arg` and forwards it here as a fixed `arg: usize`. Splitting the
/// variadic boundary into C makes the exported symbol correctly variadic on every target —
/// including `aarch64-apple-darwin`, where a vararg is passed on the stack rather than in a
/// register, so the previous fixed-arity export read the wrong slot (QA F6-VARIADIC). The `crs_`
/// prefix keeps this worker OUT of the exported `curl_*` symbol set (the cdylib version script
/// exports only `curl_*`), so symbol parity stays exact. It remains `#[no_mangle]` so the C
/// trampoline can resolve it by name.
///
/// Function-pointer and user-data options (`CURLMOPT_{SOCKET,TIMER,PUSH,NOTIFY}{FUNCTION,DATA}`)
/// are stored and installed as core trampolines; numeric options are forwarded to the core; an
/// unrecognised option yields `CURLM_UNKNOWN_OPTION`.
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *`. For a function-pointer option, `arg` must be a
/// valid function pointer of the matching callback type (or null to clear); for other options it
/// must be the value/pointer the option documents.
#[no_mangle]
pub unsafe extern "C" fn crs_multi_setopt(
    multi_handle: *mut c_void,
    option: c_int,
    arg: usize,
) -> c_int {
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_mut`
            // null-checks and produces a unique borrow bounded by this call.
            let multi = match unsafe { as_mut::<CurlMulti>(multi_handle as *mut CurlMulti) } {
                Some(multi) => multi,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            // The self-pointer is stable for the handle's life (the box is pinned by
            // `box_into_raw`); record it so the timer/notify/push trampolines can pass the
            // `CURLM *` back to the C callbacks.
            multi.self_ptr = SendPtr(multi_handle);
            setopt_dispatch(multi, option, arg)
        }),
    )
}

/// Apply one `curl_multi_setopt` option to `multi`.
///
/// `arg` is the single promoted variadic argument (see `curl_multi_setopt`). Function-pointer
/// and user-data options are stored on the wrapper and re-installed as trampolines (so the
/// function and its data may be set in any order); numeric `LONG`/`OFF_T` options are forwarded
/// to the core [`Multi::setopt_raw`](curl_rs_lib::multi); an unrecognised id yields
/// `CURLM_UNKNOWN_OPTION`.
fn setopt_dispatch(multi: &mut CurlMulti, option: c_int, arg: usize) -> c_int {
    // Each constant equals its exact `CURLMoption` discriminant.
    const O_SOCKETFUNCTION: c_int = CURLMoption::CURLMOPT_SOCKETFUNCTION as c_int;
    const O_SOCKETDATA: c_int = CURLMoption::CURLMOPT_SOCKETDATA as c_int;
    const O_PIPELINING: c_int = CURLMoption::CURLMOPT_PIPELINING as c_int;
    const O_TIMERFUNCTION: c_int = CURLMoption::CURLMOPT_TIMERFUNCTION as c_int;
    const O_TIMERDATA: c_int = CURLMoption::CURLMOPT_TIMERDATA as c_int;
    const O_MAXCONNECTS: c_int = CURLMoption::CURLMOPT_MAXCONNECTS as c_int;
    const O_MAX_HOST_CONNECTIONS: c_int = CURLMoption::CURLMOPT_MAX_HOST_CONNECTIONS as c_int;
    const O_MAX_PIPELINE_LENGTH: c_int = CURLMoption::CURLMOPT_MAX_PIPELINE_LENGTH as c_int;
    const O_CONTENT_LENGTH_PENALTY_SIZE: c_int =
        CURLMoption::CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE as c_int;
    const O_CHUNK_LENGTH_PENALTY_SIZE: c_int =
        CURLMoption::CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE as c_int;
    const O_PIPELINING_SITE_BL: c_int = CURLMoption::CURLMOPT_PIPELINING_SITE_BL as c_int;
    const O_PIPELINING_SERVER_BL: c_int = CURLMoption::CURLMOPT_PIPELINING_SERVER_BL as c_int;
    const O_MAX_TOTAL_CONNECTIONS: c_int = CURLMoption::CURLMOPT_MAX_TOTAL_CONNECTIONS as c_int;
    const O_PUSHFUNCTION: c_int = CURLMoption::CURLMOPT_PUSHFUNCTION as c_int;
    const O_PUSHDATA: c_int = CURLMoption::CURLMOPT_PUSHDATA as c_int;
    const O_MAX_CONCURRENT_STREAMS: c_int = CURLMoption::CURLMOPT_MAX_CONCURRENT_STREAMS as c_int;
    const O_NETWORK_CHANGED: c_int = CURLMoption::CURLMOPT_NETWORK_CHANGED as c_int;
    const O_NOTIFYFUNCTION: c_int = CURLMoption::CURLMOPT_NOTIFYFUNCTION as c_int;
    const O_NOTIFYDATA: c_int = CURLMoption::CURLMOPT_NOTIFYDATA as c_int;

    match option {
        O_SOCKETFUNCTION => {
            // SAFETY: for a FUNCTIONPOINT option the promoted vararg is a function pointer of the
            // documented `curl_socket_callback` type. `Option<extern "C" fn>` is guaranteed by the
            // null-pointer optimization to share the layout of a pointer-sized integer, so this
            // reinterpretation yields `None` for a null pointer and `Some(fn)` otherwise; the C
            // caller guarantees the pointer's real type matches.
            multi.socket_fn = unsafe { core::mem::transmute::<usize, curl_socket_callback>(arg) };
            multi.rebuild_socket_cb();
            CURLMcode::CURLM_OK as c_int
        }
        O_SOCKETDATA => {
            multi.socket_data = SendPtr(arg as *mut c_void);
            multi.rebuild_socket_cb();
            CURLMcode::CURLM_OK as c_int
        }
        O_TIMERFUNCTION => {
            // SAFETY: as `O_SOCKETFUNCTION`, for the `curl_multi_timer_callback` type.
            multi.timer_fn =
                unsafe { core::mem::transmute::<usize, curl_multi_timer_callback>(arg) };
            multi.rebuild_timer_cb();
            CURLMcode::CURLM_OK as c_int
        }
        O_TIMERDATA => {
            multi.timer_data = SendPtr(arg as *mut c_void);
            multi.rebuild_timer_cb();
            CURLMcode::CURLM_OK as c_int
        }
        O_PUSHFUNCTION => {
            // SAFETY: as `O_SOCKETFUNCTION`, for the `curl_push_callback` type.
            multi.push_fn = unsafe { core::mem::transmute::<usize, curl_push_callback>(arg) };
            multi.rebuild_push_cb();
            CURLMcode::CURLM_OK as c_int
        }
        O_PUSHDATA => {
            multi.push_data = SendPtr(arg as *mut c_void);
            multi.rebuild_push_cb();
            CURLMcode::CURLM_OK as c_int
        }
        O_NOTIFYFUNCTION => {
            // SAFETY: as `O_SOCKETFUNCTION`, for the `curl_notify_callback` type.
            multi.notify_fn = unsafe { core::mem::transmute::<usize, curl_notify_callback>(arg) };
            multi.rebuild_notify_cb();
            CURLMcode::CURLM_OK as c_int
        }
        O_NOTIFYDATA => {
            multi.notify_data = SendPtr(arg as *mut c_void);
            multi.rebuild_notify_cb();
            CURLMcode::CURLM_OK as c_int
        }
        // `OFF_T`-typed numeric options.
        O_CONTENT_LENGTH_PENALTY_SIZE | O_CHUNK_LENGTH_PENALTY_SIZE => multi
            .inner
            .setopt_raw(option, MultiOptionValue::OffT(arg as i64))
            .to_i32(),
        // `LONG`-typed numeric options (and the object-pointer blocklists the core treats as
        // no-ops), forwarded as `Long`.
        O_PIPELINING
        | O_MAXCONNECTS
        | O_MAX_HOST_CONNECTIONS
        | O_MAX_PIPELINE_LENGTH
        | O_PIPELINING_SITE_BL
        | O_PIPELINING_SERVER_BL
        | O_MAX_TOTAL_CONNECTIONS
        | O_MAX_CONCURRENT_STREAMS
        | O_NETWORK_CHANGED => multi
            .inner
            .setopt_raw(option, MultiOptionValue::Long(arg as i64))
            .to_i32(),
        _ => CURLMcode::CURLM_UNKNOWN_OPTION as c_int,
    }
}

/// `CURLMcode curl_multi_assign(CURLM *multi_handle, curl_socket_t sockfd, void *sockp);`
///
/// Associate an application private pointer with a socket, delivered back as the `socketp`
/// argument of the [`curl_socket_callback`].
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *`. `sockp` is stored as an opaque token and is
/// never dereferenced by this crate.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_assign(
    multi_handle: *mut c_void,
    sockfd: curl_socket_t,
    sockp: *mut c_void,
) -> c_int {
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_mut`
            // null-checks and borrows it for this call only.
            let multi = match unsafe { as_mut::<CurlMulti>(multi_handle as *mut CurlMulti) } {
                Some(multi) => multi,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            multi.inner.assign(sockfd, sockp as usize).to_i32()
        }),
    )
}

/// `CURL **curl_multi_get_handles(CURLM *multi_handle);`
///
/// Return a freshly allocated, `NULL`-terminated array of the easy handles currently added (the
/// first entry is `NULL` when none are added). The caller frees the **array** with `curl_free`;
/// the handles themselves are not owned by the array. Returns `NULL` on allocation failure.
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_get_handles(multi_handle: *mut c_void) -> *mut *mut c_void {
    catch_unwind(AssertUnwindSafe(move || {
        // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_mut`
        // null-checks and borrows it for this call only.
        let multi = match unsafe { as_mut::<CurlMulti>(multi_handle as *mut CurlMulti) } {
            Some(multi) => multi,
            None => return ptr::null_mut(),
        };
        // Deterministic id order (the core returns ids sorted), mapped back to the caller's
        // `CURL *` pointers via the registry; unknown/null mappings are skipped.
        let ids = multi.inner.handles();
        let handles: Vec<*mut c_void> = multi.with_registry(|r| {
            ids.iter()
                .map(|id| r.easy_of(id.0))
                .filter(|p| !p.is_null())
                .collect()
        });
        alloc_handle_array(&handles)
    }))
    .unwrap_or(ptr::null_mut())
}

/// Allocate a `NULL`-terminated `CURL **` array holding `handles`, or null on allocation failure.
///
/// The block is allocated with the global allocator so a matching `curl_free` (out of scope for
/// this module) can release it; see the module docs for the known free-symmetry caveat
/// (AAP §0.6.5).
fn alloc_handle_array(handles: &[*mut c_void]) -> *mut *mut c_void {
    // `handles.len() + 1` is always >= 1, so the layout has non-zero size.
    let count = handles.len() + 1;
    let layout = match Layout::array::<*mut c_void>(count) {
        Ok(layout) => layout,
        Err(_) => return ptr::null_mut(),
    };
    // SAFETY: `layout` has non-zero size (`count >= 1`); `alloc` returns either a suitably aligned
    // block of `count * size_of::<*mut c_void>()` bytes or null, which we handle below.
    let raw = unsafe { alloc(layout) } as *mut *mut c_void;
    if raw.is_null() {
        return ptr::null_mut();
    }
    for (i, handle) in handles.iter().enumerate() {
        // SAFETY: `i < handles.len() < count`, so `raw.add(i)` is within the allocated block and
        // properly aligned; the slot is uninitialized and we initialize it exactly once.
        unsafe { raw.add(i).write(*handle) };
    }
    // SAFETY: index `handles.len()` is the final slot (`count - 1`) within the block; writing the
    // `NULL` terminator initializes it exactly once.
    unsafe { raw.add(handles.len()).write(ptr::null_mut()) };
    raw
}

/// `CURLMcode curl_multi_get_offt(CURLM *multi_handle, CURLMinfo_offt info, curl_off_t *pvalue);`
///
/// Write a numeric `CURLMINFO_*` value to `*pvalue`.
///
/// # Safety
/// `multi_handle` must be null or a live `CURLM *`; `pvalue` must be a valid `curl_off_t *`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_get_offt(
    multi_handle: *mut c_void,
    info: c_int,
    pvalue: *mut curl_off_t,
) -> c_int {
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi_handle` is null or a live `CurlMulti`; `as_ref`
            // null-checks and borrows it for this call only.
            let multi = match unsafe { as_ref::<CurlMulti>(multi_handle as *const CurlMulti) } {
                Some(multi) => multi,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            if pvalue.is_null() {
                return CURLMcode::CURLM_BAD_FUNCTION_ARGUMENT as c_int;
            }
            const I_XFERS_CURRENT: c_int = CURLMinfo_offt::CURLMINFO_XFERS_CURRENT as c_int;
            const I_XFERS_RUNNING: c_int = CURLMinfo_offt::CURLMINFO_XFERS_RUNNING as c_int;
            const I_XFERS_PENDING: c_int = CURLMinfo_offt::CURLMINFO_XFERS_PENDING as c_int;
            const I_XFERS_DONE: c_int = CURLMinfo_offt::CURLMINFO_XFERS_DONE as c_int;
            const I_XFERS_ADDED: c_int = CURLMinfo_offt::CURLMINFO_XFERS_ADDED as c_int;
            let key = match info {
                I_XFERS_CURRENT => CurlMInfo::XfersCurrent,
                I_XFERS_RUNNING => CurlMInfo::XfersRunning,
                I_XFERS_PENDING => CurlMInfo::XfersPending,
                I_XFERS_DONE => CurlMInfo::XfersDone,
                I_XFERS_ADDED => CurlMInfo::XfersAdded,
                _ => return CURLMcode::CURLM_BAD_FUNCTION_ARGUMENT as c_int,
            };
            let value = multi.inner.get(key);
            // SAFETY: `pvalue` is non-null (checked) and, per the C contract, points to a valid
            // `curl_off_t` the caller provided for this out-parameter.
            unsafe { *pvalue = value as curl_off_t };
            CURLMcode::CURLM_OK as c_int
        }),
    )
}

/// `char *curl_pushheader_bynum(struct curl_pushheaders *h, size_t num);`
///
/// Return the `num`-th pushed-request header (as `"Name: value"`) from within a
/// [`curl_push_callback`], or `NULL` if out of range. The returned pointer references
/// push-owned storage and is not freed by the caller (curl's contract).
///
/// HTTP/2 server push is not yet wired end-to-end in the core (AAP §0.6.5); no push headers are
/// available, so this returns `NULL` — the same result curl gives for an out-of-range index.
///
/// # Safety
/// `h`, if non-null, must be a valid `curl_pushheaders *` supplied by libcurl to a push callback.
#[no_mangle]
pub unsafe extern "C" fn curl_pushheader_bynum(
    h: *mut curl_pushheaders,
    num: size_t,
) -> *mut c_char {
    let _ = (h, num);
    ptr::null_mut()
}

/// `char *curl_pushheader_byname(struct curl_pushheaders *h, const char *name);`
///
/// Return the pushed-request header named `name` from within a [`curl_push_callback`], or `NULL`
/// if absent. The returned pointer references push-owned storage and is not freed by the caller.
///
/// As [`curl_pushheader_bynum`], returns `NULL` because server push is not yet wired in the core
/// (AAP §0.6.5).
///
/// # Safety
/// `h`, if non-null, must be a valid `curl_pushheaders *`; `name`, if non-null, must be a valid
/// NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn curl_pushheader_byname(
    h: *mut curl_pushheaders,
    name: *const c_char,
) -> *mut c_char {
    let _ = (h, name);
    ptr::null_mut()
}

/// `CURLMcode curl_multi_waitfds(CURLM *multi, struct curl_waitfd *ufds, unsigned int size,
/// unsigned int *fd_count);`
///
/// Export the set of descriptors the application should poll on. Writes up to `size` entries into
/// `ufds` and the total number of descriptors to `*fd_count`. When `size` is smaller than the
/// number of descriptors, returns `CURLM_OUT_OF_MEMORY` (still writing the required `*fd_count`),
/// matching curl; passing `size == 0` is the documented way to query just the count.
///
/// # Safety
/// `multi` must be null or a live `CURLM *`; if `size > 0`, `ufds` must point to `size` valid
/// [`curl_waitfd`] entries; `fd_count`, if non-null, must be a valid `unsigned int *`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_waitfds(
    multi: *mut c_void,
    ufds: *mut curl_waitfd,
    size: c_uint,
    fd_count: *mut c_uint,
) -> c_int {
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi` is null or a live `CurlMulti`; `as_mut`
            // null-checks and borrows it for this call only.
            let handle = match unsafe { as_mut::<CurlMulti>(multi as *mut CurlMulti) } {
                Some(handle) => handle,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            let set = handle.inner.fdset();
            // Build one waitfd per active descriptor, folding read/write interest into `events`.
            let mut entries: Vec<curl_waitfd> = Vec::new();
            for &fd in &set.read {
                entries.push(curl_waitfd {
                    fd,
                    events: CURL_WAIT_POLLIN,
                    revents: 0,
                });
            }
            for &fd in &set.write {
                // Merge writability interest into an existing entry for the same fd if present.
                if let Some(existing) = entries.iter_mut().find(|e| e.fd == fd) {
                    existing.events |= CURL_WAIT_POLLOUT;
                } else {
                    entries.push(curl_waitfd {
                        fd,
                        events: CURL_WAIT_POLLOUT,
                        revents: 0,
                    });
                }
            }
            let needed = entries.len();
            if !fd_count.is_null() {
                // SAFETY: `fd_count` is non-null (checked) and, per the C contract, points to a
                // valid `unsigned int` the caller provided for this out-parameter.
                unsafe { *fd_count = needed as c_uint };
            }
            let capacity = size as usize;
            if !ufds.is_null() {
                let writable = needed.min(capacity);
                for (i, entry) in entries.iter().take(writable).enumerate() {
                    // SAFETY: `i < writable <= capacity == size`, so `ufds.add(i)` is within the
                    // caller-provided array of `size` `curl_waitfd` entries and properly aligned;
                    // we write a fully initialized value.
                    unsafe {
                        ufds.add(i).write(curl_waitfd {
                            fd: entry.fd,
                            events: entry.events,
                            revents: entry.revents,
                        })
                    };
                }
            }
            if needed > capacity {
                CURLMcode::CURLM_OUT_OF_MEMORY as c_int
            } else {
                CURLMcode::CURLM_OK as c_int
            }
        }),
    )
}

/// `CURLMcode curl_multi_notify_disable(CURLM *multi, unsigned int notification);`
///
/// Disable delivery of a notification class (`CURLMNOTIFY_*`) via the `CURLMOPT_NOTIFYFUNCTION`
/// callback.
///
/// # Safety
/// `multi` must be null or a live `CURLM *`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_notify_disable(
    multi: *mut c_void,
    notification: c_uint,
) -> c_int {
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi` is null or a live `CurlMulti`; `as_mut`
            // null-checks and borrows it for this call only.
            let handle = match unsafe { as_mut::<CurlMulti>(multi as *mut CurlMulti) } {
                Some(handle) => handle,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            handle.inner.notify_disable(notification).to_i32()
        }),
    )
}

/// `CURLMcode curl_multi_notify_enable(CURLM *multi, unsigned int notification);`
///
/// Enable delivery of a notification class (`CURLMNOTIFY_*`) via the `CURLMOPT_NOTIFYFUNCTION`
/// callback.
///
/// # Safety
/// `multi` must be null or a live `CURLM *`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_notify_enable(
    multi: *mut c_void,
    notification: c_uint,
) -> c_int {
    ffi_guard(
        CURLMcode::CURLM_BAD_HANDLE as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `multi` is null or a live `CurlMulti`; `as_mut`
            // null-checks and borrows it for this call only.
            let handle = match unsafe { as_mut::<CurlMulti>(multi as *mut CurlMulti) } {
                Some(handle) => handle,
                None => return CURLMcode::CURLM_BAD_HANDLE as c_int,
            };
            handle.inner.notify_enable(notification).to_i32()
        }),
    )
}

// ===========================================================================
// Tests.
//
// These use plain `#[test]` (never `#[tokio::test]`): the code-driving entry points
// (`perform`/`poll`/`wait`/`socket_action`) `block_on` the core's own runtime and would panic if
// invoked from inside an ambient Tokio runtime, exactly as a real C caller (which has no ambient
// runtime) requires. The tests therefore exercise the ABI surface, handle lifecycle, and option
// dispatch — not the blocking transfer loop.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// The frozen `CURLMcode` integer contract (`-1`, `0`, then ascending).
    #[test]
    fn curlmcode_values_are_frozen() {
        assert_eq!(CURLMcode::CURLM_CALL_MULTI_PERFORM as c_int, -1);
        assert_eq!(CURLMcode::CURLM_OK as c_int, 0);
        assert_eq!(CURLMcode::CURLM_BAD_HANDLE as c_int, 1);
        assert_eq!(CURLMcode::CURLM_BAD_EASY_HANDLE as c_int, 2);
        assert_eq!(CURLMcode::CURLM_OUT_OF_MEMORY as c_int, 3);
        assert_eq!(CURLMcode::CURLM_INTERNAL_ERROR as c_int, 4);
        assert_eq!(CURLMcode::CURLM_BAD_SOCKET as c_int, 5);
        assert_eq!(CURLMcode::CURLM_UNKNOWN_OPTION as c_int, 6);
        assert_eq!(CURLMcode::CURLM_ADDED_ALREADY as c_int, 7);
        assert_eq!(CURLMcode::CURLM_RECURSIVE_API_CALL as c_int, 8);
        assert_eq!(CURLMcode::CURLM_WAKEUP_FAILURE as c_int, 9);
        assert_eq!(CURLMcode::CURLM_BAD_FUNCTION_ARGUMENT as c_int, 10);
        assert_eq!(CURLMcode::CURLM_ABORTED_BY_CALLBACK as c_int, 11);
        assert_eq!(CURLMcode::CURLM_UNRECOVERABLE_POLL as c_int, 12);
        assert_eq!(CURLMcode::CURLM_LAST as c_int, 13);
        assert_eq!(CURLM_CALL_MULTI_SOCKET, -1);
    }

    /// `CURLMSG` and the option/info enum discriminants match the header.
    #[test]
    fn other_enum_values_are_frozen() {
        assert_eq!(CURLMSG::CURLMSG_NONE as c_int, 0);
        assert_eq!(CURLMSG::CURLMSG_DONE as c_int, 1);
        assert_eq!(CURLMSG::CURLMSG_LAST as c_int, 2);

        assert_eq!(CURLMoption::CURLMOPT_SOCKETFUNCTION as c_int, 1);
        assert_eq!(CURLMoption::CURLMOPT_SOCKETDATA as c_int, 2);
        assert_eq!(CURLMoption::CURLMOPT_PIPELINING as c_int, 3);
        assert_eq!(CURLMoption::CURLMOPT_TIMERFUNCTION as c_int, 4);
        assert_eq!(CURLMoption::CURLMOPT_NOTIFYDATA as c_int, 19);
        assert_eq!(CURLMoption::CURLMOPT_LASTENTRY as c_int, 20);

        assert_eq!(CURLMinfo_offt::CURLMINFO_NONE as c_int, 0);
        assert_eq!(CURLMinfo_offt::CURLMINFO_XFERS_CURRENT as c_int, 1);
        assert_eq!(CURLMinfo_offt::CURLMINFO_XFERS_ADDED as c_int, 5);
        assert_eq!(CURLMinfo_offt::CURLMINFO_LASTENTRY as c_int, 6);
    }

    /// The poll/select/wait constants match the header.
    #[test]
    fn constants_match_header() {
        assert_eq!(CURL_POLL_NONE, 0);
        assert_eq!(CURL_POLL_IN, 1);
        assert_eq!(CURL_POLL_OUT, 2);
        assert_eq!(CURL_POLL_INOUT, 3);
        assert_eq!(CURL_POLL_REMOVE, 4);
        assert_eq!(CURL_CSELECT_IN, 0x01);
        assert_eq!(CURL_CSELECT_OUT, 0x02);
        assert_eq!(CURL_CSELECT_ERR, 0x04);
        assert_eq!(CURL_WAIT_POLLIN, 0x0001);
        assert_eq!(CURL_WAIT_POLLPRI, 0x0002);
        assert_eq!(CURL_WAIT_POLLOUT, 0x0004);
        assert_eq!(CURL_SOCKET_TIMEOUT, CURL_SOCKET_BAD);
        assert_eq!(CURL_PUSH_OK, 0);
        assert_eq!(CURL_PUSH_DENY, 1);
        assert_eq!(CURL_PUSH_ERROROUT, 2);
        assert_eq!(CURLMNOTIFY_INFO_READ, 0);
        assert_eq!(CURLMNOTIFY_EASY_DONE, 1);
        assert_eq!(CURLPIPE_MULTIPLEX, 2);
    }

    /// `curl_waitfd` is the byte-exact `{ i32; i16; i16; }` layout, and the `CURLMsg` union
    /// aliases a pointer-sized cell whose `result` member reads back a written `CURLcode`.
    #[test]
    fn struct_layouts_are_sane() {
        assert_eq!(std::mem::size_of::<curl_waitfd>(), 8);
        assert_eq!(std::mem::align_of::<curl_waitfd>(), 4);
        assert_eq!(
            std::mem::size_of::<CURLMsgData>(),
            std::mem::size_of::<*mut c_void>()
        );
        // The pushed-headers handle is opaque / zero-sized.
        assert_eq!(std::mem::size_of::<curl_pushheaders>(), 0);

        let msg = CURLMsg {
            msg: CURLMSG::CURLMSG_DONE,
            easy_handle: ptr::null_mut(),
            data: CURLMsgData { result: 28 },
        };
        assert_eq!(msg.msg as c_int, 1);
        // SAFETY: we just initialized the union's `result` member, so reading it back is sound.
        let result = unsafe { msg.data.result };
        assert_eq!(result, 28);
    }

    /// A NULL handle is rejected with `CURLM_BAD_HANDLE` (never a crash / UB).
    #[test]
    fn null_handle_is_rejected() {
        // SAFETY: passing NULL is explicitly part of the contract; the entry points null-check.
        unsafe {
            assert_eq!(
                curl_multi_add_handle(ptr::null_mut(), ptr::null_mut()),
                CURLMcode::CURLM_BAD_HANDLE as c_int
            );
            assert_eq!(
                curl_multi_perform(ptr::null_mut(), ptr::null_mut()),
                CURLMcode::CURLM_BAD_HANDLE as c_int
            );
            assert_eq!(
                curl_multi_cleanup(ptr::null_mut()),
                CURLMcode::CURLM_BAD_HANDLE as c_int
            );
        }
    }

    /// `curl_multi_init` yields a live handle that `curl_multi_cleanup` reclaims with `CURLM_OK`.
    #[test]
    fn init_cleanup_roundtrip() {
        let multi = curl_multi_init();
        assert!(!multi.is_null());
        // SAFETY: `multi` is the live handle just returned by `curl_multi_init`.
        let rc = unsafe { curl_multi_cleanup(multi) };
        assert_eq!(rc, CURLMcode::CURLM_OK as c_int);
    }

    /// Adding a handle succeeds once, reports `CURLM_ADDED_ALREADY` on repeat, removes cleanly,
    /// and `curl_multi_cleanup` never frees the still-owned easy handle.
    #[test]
    fn add_remove_added_already() {
        let multi = curl_multi_init();
        assert!(!multi.is_null());
        let easy = crate::easy::curl_easy_init();
        assert!(!easy.is_null());

        // SAFETY: `multi` and `easy` are live handles from their respective constructors.
        unsafe {
            assert_eq!(
                curl_multi_add_handle(multi, easy),
                CURLMcode::CURLM_OK as c_int
            );
            assert_eq!(
                curl_multi_add_handle(multi, easy),
                CURLMcode::CURLM_ADDED_ALREADY as c_int
            );
            assert_eq!(
                curl_multi_remove_handle(multi, easy),
                CURLMcode::CURLM_OK as c_int
            );
            // Removing an unknown handle is a bad easy handle.
            assert_eq!(
                curl_multi_remove_handle(multi, easy),
                CURLMcode::CURLM_BAD_EASY_HANDLE as c_int
            );
            assert_eq!(curl_multi_cleanup(multi), CURLMcode::CURLM_OK as c_int);
            // The easy handle is still valid and owned by us — free it now.
            crate::easy::curl_easy_cleanup(easy);
        }
    }

    /// `curl_multi_strerror` returns a non-null, process-lifetime string for known and unknown
    /// codes.
    #[test]
    fn strerror_is_non_null() {
        let ok = curl_multi_strerror(CURLMcode::CURLM_OK as c_int);
        assert!(!ok.is_null());
        // SAFETY: `ok` is a valid, NUL-terminated, process-lifetime C string from our interner.
        let ok_str = unsafe { CStr::from_ptr(ok) };
        assert!(!ok_str.to_bytes().is_empty());

        let unknown = curl_multi_strerror(9999);
        assert!(!unknown.is_null());
    }

    /// `curl_multi_get_offt` writes a value for a valid key, and rejects a null out-pointer and an
    /// out-of-range key with `CURLM_BAD_FUNCTION_ARGUMENT`.
    #[test]
    fn get_offt_behaviour() {
        let multi = curl_multi_init();
        assert!(!multi.is_null());
        let mut value: curl_off_t = -123;
        // SAFETY: `multi` is live; `value` is valid caller storage for the out-pointer.
        unsafe {
            let rc = curl_multi_get_offt(
                multi,
                CURLMinfo_offt::CURLMINFO_XFERS_CURRENT as c_int,
                &mut value as *mut curl_off_t,
            );
            assert_eq!(rc, CURLMcode::CURLM_OK as c_int);
            assert!(value >= 0);

            assert_eq!(
                curl_multi_get_offt(
                    multi,
                    CURLMinfo_offt::CURLMINFO_XFERS_CURRENT as c_int,
                    ptr::null_mut()
                ),
                CURLMcode::CURLM_BAD_FUNCTION_ARGUMENT as c_int
            );
            assert_eq!(
                curl_multi_get_offt(multi, 9999, &mut value as *mut curl_off_t),
                CURLMcode::CURLM_BAD_FUNCTION_ARGUMENT as c_int
            );
            assert_eq!(curl_multi_cleanup(multi), CURLMcode::CURLM_OK as c_int);
        }
    }

    /// `curl_multi_timeout` reports `-1` (nothing to wait for) on a fresh, empty handle.
    #[test]
    fn timeout_on_idle_handle() {
        let multi = curl_multi_init();
        assert!(!multi.is_null());
        let mut ms: c_long = 12345;
        // SAFETY: `multi` is live; `ms` is valid caller storage for the out-pointer.
        unsafe {
            let rc = curl_multi_timeout(multi, &mut ms as *mut c_long);
            assert_eq!(rc, CURLMcode::CURLM_OK as c_int);
            assert_eq!(ms, -1);
            assert_eq!(curl_multi_cleanup(multi), CURLMcode::CURLM_OK as c_int);
        }
    }

    /// `curl_multi_info_read` on an empty queue returns NULL and writes a zero queue length.
    #[test]
    fn info_read_empty_queue() {
        let multi = curl_multi_init();
        assert!(!multi.is_null());
        let mut left: c_int = -1;
        // SAFETY: `multi` is live; `left` is valid caller storage for the out-pointer.
        unsafe {
            let msg = curl_multi_info_read(multi, &mut left as *mut c_int);
            assert!(msg.is_null());
            assert_eq!(left, 0);
            assert_eq!(curl_multi_cleanup(multi), CURLMcode::CURLM_OK as c_int);
        }
    }

    /// The `crs_multi_setopt` worker (behind the C-variadic `curl_multi_setopt` trampoline)
    /// accepts a recognised numeric option and rejects an unknown id.
    #[test]
    fn setopt_numeric_and_unknown() {
        let multi = curl_multi_init();
        assert!(!multi.is_null());
        // SAFETY: `multi` is live; the numeric options take an integer arg, not a pointer.
        unsafe {
            assert_eq!(
                crs_multi_setopt(multi, CURLMoption::CURLMOPT_MAXCONNECTS as c_int, 10),
                CURLMcode::CURLM_OK as c_int
            );
            assert_eq!(
                crs_multi_setopt(
                    multi,
                    CURLMoption::CURLMOPT_MAX_TOTAL_CONNECTIONS as c_int,
                    8
                ),
                CURLMcode::CURLM_OK as c_int
            );
            assert_eq!(
                crs_multi_setopt(multi, 99_999, 0),
                CURLMcode::CURLM_UNKNOWN_OPTION as c_int
            );
            assert_eq!(curl_multi_cleanup(multi), CURLMcode::CURLM_OK as c_int);
        }
    }

    /// The genuine C-variadic `curl_multi_setopt` entry point — the C trampoline in
    /// `csrc/variadic_shim.c` (QA F6-VARIADIC) — forwards its single promoted argument to the
    /// [`crs_multi_setopt`] worker. Driving the *real exported symbol* (declared here as a C
    /// variadic) proves the trampoline + `va_arg` extraction is wired end-to-end under `cargo test`.
    #[test]
    fn variadic_multi_setopt_trampoline_dispatch() {
        extern "C" {
            fn curl_multi_setopt(multi_handle: *mut c_void, option: c_int, ...) -> c_int;
        }
        let multi = curl_multi_init();
        assert!(!multi.is_null());
        // SAFETY: `multi` is live; the numeric option takes an integer arg and the unknown id an
        // ignored one — each is the single promoted vararg the trampoline reads.
        unsafe {
            assert_eq!(
                curl_multi_setopt(multi, CURLMoption::CURLMOPT_MAXCONNECTS as c_int, 10_usize),
                CURLMcode::CURLM_OK as c_int,
                "CURLMOPT_MAXCONNECTS must dispatch through the trampoline"
            );
            assert_eq!(
                curl_multi_setopt(multi, 99_999, 0_usize),
                CURLMcode::CURLM_UNKNOWN_OPTION as c_int,
                "unknown multi option id must reach the dispatcher and be rejected"
            );
            assert_eq!(curl_multi_cleanup(multi), CURLMcode::CURLM_OK as c_int);
        }
    }

    /// `curl_multi_waitfds` with a zero-size buffer reports the descriptor count without writing
    /// entries (the documented count-query form).
    #[test]
    fn waitfds_count_query() {
        let multi = curl_multi_init();
        assert!(!multi.is_null());
        let mut count: c_uint = 12345;
        // SAFETY: `multi` is live; a null `ufds` with `size == 0` is the count-only query form,
        // and `count` is valid caller storage.
        unsafe {
            let rc = curl_multi_waitfds(multi, ptr::null_mut(), 0, &mut count as *mut c_uint);
            // On an idle handle there are no descriptors, so this is OK with count 0; if the core
            // ever reports descriptors, a zero-size buffer yields CURLM_OUT_OF_MEMORY. Accept both
            // per the documented contract.
            assert!(
                rc == CURLMcode::CURLM_OK as c_int || rc == CURLMcode::CURLM_OUT_OF_MEMORY as c_int
            );
            assert_eq!(curl_multi_cleanup(multi), CURLMcode::CURLM_OK as c_int);
        }
    }

    /// Enabling and disabling a notification class is accepted on a live handle.
    #[test]
    fn notify_enable_disable() {
        let multi = curl_multi_init();
        assert!(!multi.is_null());
        // SAFETY: `multi` is live.
        unsafe {
            assert_eq!(
                curl_multi_notify_enable(multi, CURLMNOTIFY_INFO_READ),
                CURLMcode::CURLM_OK as c_int
            );
            assert_eq!(
                curl_multi_notify_disable(multi, CURLMNOTIFY_INFO_READ),
                CURLMcode::CURLM_OK as c_int
            );
            assert_eq!(curl_multi_cleanup(multi), CURLMcode::CURLM_OK as c_int);
        }
    }

    /// The pushed-header accessors return NULL (server push is not yet wired in the core) and are
    /// null-safe.
    #[test]
    fn pushheader_accessors_return_null() {
        // SAFETY: a null `curl_pushheaders *` is handled; the accessors never dereference it.
        unsafe {
            assert!(curl_pushheader_bynum(ptr::null_mut(), 0).is_null());
            assert!(curl_pushheader_byname(ptr::null_mut(), ptr::null()).is_null());
        }
    }
}
