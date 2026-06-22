// curl-rs — a memory-safe Rust rewrite of curl / libcurl.
//
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// This software is licensed as described in the file COPYING, which you should
// have received as part of this distribution. The terms are also available at
// https://curl.se/docs/copyright.html.
//
// You may opt to use, copy, modify, merge, publish, distribute and/or sell
// copies of the Software, and permit persons to whom the Software is furnished
// to do so, under the terms of the COPYING file.
//
// This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
// KIND, either express or implied.
//
// SPDX-License-Identifier: curl

//! The multi interface — the Rust reimplementation of libcurl's `curl_multi_*`
//! API (`lib/multi.c`, `lib/multiif.h`, `lib/multi_ev.c`).
//!
//! libcurl's *multi* interface drives many transfers concurrently from a single
//! application thread. The opaque C `CURLM` handle is, in this rewrite, backed
//! by the [`Multi`] struct defined here. Where upstream curl hand-rolls a
//! `select`/`poll` state machine ([`lib/multi.c`], ~4000 LoC), this
//! implementation drives the concurrent transfers on a **Tokio multi-thread
//! runtime** (AAP §0.4.4). The runtime is created **lazily on the first
//! [`perform`](Multi::perform) / [`socket_action`](Multi::socket_action)**, never
//! at [`new`](Multi::new), exactly as the design mandate requires.
//!
//! # The contract that must not change (AAP §0.7.4)
//!
//! The multi interface is a hard external API: event-loop integrations (for
//! example `libevent`-based consumers) depend on the precise behavior of
//! [`socket_action`](Multi::socket_action), the `CURLMOPT_SOCKETFUNCTION` /
//! `CURLMOPT_TIMERFUNCTION` callbacks, and the [`CURLM_CALL_MULTI_PERFORM`]
//! (`-1`) signal. The asynchronous Tokio runtime is therefore an *implementation
//! detail* hidden entirely behind the same synchronous, callback-driven contract
//! C consumers already rely on:
//!
//! * The **timer callback** is invoked with curl's exact change-detection timing
//!   (mirroring `Curl_update_timer`): the application is told the next timeout
//!   only when the value actually changes, and a `-1` return from the callback
//!   aborts the multi with [`CurlMError::AbortedByCallback`].
//! * The **socket callback** is invoked with `CURL_POLL_IN` / `CURL_POLL_OUT` /
//!   `CURL_POLL_REMOVE` as a socket's I/O interest changes (mirroring
//!   `lib/multi_ev.c`'s pollset diffing), carrying the per-socket user pointer
//!   registered via [`assign`](Multi::assign).
//! * [`info_read`](Multi::info_read) returns one `CURLMSG_DONE` message per
//!   completed transfer, carrying the easy handle and its [`CurlError`] result,
//!   and maintains the "messages in queue" count.
//!
//! # Synchronous-over-async bridge
//!
//! ```text
//! C caller (sync)  ──▶  curl-rs-ffi  curl_multi_*  shim
//!                           │  (boxes Multi behind CURLM*, block_on)
//!                           ▼
//!                      curl-rs-lib  Multi  ──▶ Tokio multi-thread runtime
//!                           │                    └─ one task per transfer
//!                           ▼                       driving Easy::perform()
//!                      socket / timer callbacks (synchronous, curl-faithful)
//! ```
//!
//! The blocking wait primitives ([`poll`](Multi::poll) / [`wait`](Multi::wait))
//! park the calling thread on the runtime until a transfer makes progress, is
//! interrupted by [`wakeup`](Multi::wakeup), or the timeout elapses — the async
//! machinery never leaks out to the C consumer. Each transfer task drives
//! [`Easy::perform`], which is the shared transfer-advancement core (the seam
//! into [`crate::transfer`]) used by the single-handle `curl_easy_perform` path
//! too, so both interfaces converge on the same engine.
//!
//! # Memory safety (AAP §0.7.1)
//!
//! This module contains **zero** `unsafe` and compiles under the module-root
//! `#![forbid(unsafe_code)]`. There are no raw pointers: the `Box`↔`CURLM*`
//! conversion lives in `curl-rs-ffi`, shared state uses [`Arc`] /
//! [`tokio::sync::Mutex`], and C socket/timer/push/notify function pointers are
//! represented here as opaque, *safe* trait objects ([`SocketCallback`],
//! [`TimerCallback`], [`PushCallback`], [`NotifyCallback`]). The FFI crate
//! supplies the trait implementations that perform the actual `extern "C"`
//! marshaling (the only place an `unsafe` call is made).
//!
//! [`lib/multi.c`]: https://github.com/curl/curl/blob/master/lib/multi.c

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use tokio::runtime::{Builder, Handle, Runtime};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;

use crate::easy::Easy;
use crate::error::{codes, CurlCode, CurlError, CurlMError};

// ===========================================================================
// Shared easy handle
// ===========================================================================

/// A reference-counted, asynchronously lockable easy handle.
///
/// In curl, an easy handle added to a multi handle is *shared*, not copied: the
/// application and the multi both refer to the same `struct Curl_easy`. The
/// memory-safe equivalent is an [`Arc`] over a [`tokio::sync::Mutex`]: the
/// [`Multi`] keeps the `Arc` (using [`Arc::ptr_eq`] for identity), while the
/// per-transfer Tokio task locks the mutex to drive [`Easy::perform`]. The
/// `tokio` mutex (rather than [`std::sync::Mutex`]) is required because the lock
/// is held across the `.await` points of the transfer.
pub type SharedEasy = Arc<AsyncMutex<Easy>>;

/// Wrap an [`Easy`] in the [`SharedEasy`] form the multi interface manages.
///
/// This is a convenience for callers (the FFI crate and tests) so they need not
/// name the concrete `Arc<tokio::sync::Mutex<…>>` type.
#[must_use]
pub fn shared_easy(easy: Easy) -> SharedEasy {
    Arc::new(AsyncMutex::new(easy))
}

/// A socket descriptor, equivalent to curl's `curl_socket_t`.
///
/// On Unix `curl_socket_t` is a C `int`; on Windows it is a `SOCKET` (an
/// unsigned pointer-sized handle). `i64` holds either without loss, so the core
/// stays platform-agnostic; the FFI layer narrows/widens to the platform type.
pub type CurlSocket = i64;

// ===========================================================================
// ABI constants — mirrored verbatim from include/curl/multi.h
// ===========================================================================

/// `CURLM_CALL_MULTI_PERFORM` (`-1`) — the signal asking the caller to invoke
/// [`perform`](Multi::perform) / [`socket_action`](Multi::socket_action) again
/// soon. Sourced from the single canonical definition in [`crate::error`].
pub const CURLM_CALL_MULTI_PERFORM: i32 = codes::multi::CURLM_CALL_MULTI_PERFORM;

/// `CURLM_CALL_MULTI_SOCKET` — an alias of [`CURLM_CALL_MULTI_PERFORM`] kept for
/// source parity with the `curl_multi_socket()` family.
pub const CURLM_CALL_MULTI_SOCKET: i32 = CURLM_CALL_MULTI_PERFORM;

/// `CURL_SOCKET_BAD` — the invalid-socket sentinel (`-1` on Unix).
pub const CURL_SOCKET_BAD: CurlSocket = -1;

/// `CURL_SOCKET_TIMEOUT` — passed to [`socket_action`](Multi::socket_action) to
/// indicate a timeout (rather than activity on a specific socket).
pub const CURL_SOCKET_TIMEOUT: CurlSocket = CURL_SOCKET_BAD;

/// `CURL_POLL_NONE` — the socket needs no monitoring.
pub const CURL_POLL_NONE: i32 = 0;
/// `CURL_POLL_IN` — monitor the socket for readability.
pub const CURL_POLL_IN: i32 = 1;
/// `CURL_POLL_OUT` — monitor the socket for writability.
pub const CURL_POLL_OUT: i32 = 2;
/// `CURL_POLL_INOUT` — monitor the socket for both directions.
pub const CURL_POLL_INOUT: i32 = 3;
/// `CURL_POLL_REMOVE` — stop monitoring the socket entirely.
pub const CURL_POLL_REMOVE: i32 = 4;

/// `CURL_CSELECT_IN` — the `ev_bitmask` bit signalling readable activity.
pub const CURL_CSELECT_IN: i32 = 0x01;
/// `CURL_CSELECT_OUT` — the `ev_bitmask` bit signalling writable activity.
pub const CURL_CSELECT_OUT: i32 = 0x02;
/// `CURL_CSELECT_ERR` — the `ev_bitmask` bit signalling an error condition.
pub const CURL_CSELECT_ERR: i32 = 0x04;

/// `CURLPIPE_NOTHING` — no multiplexing/pipelining.
pub const CURLPIPE_NOTHING: i64 = 0;
/// `CURLPIPE_HTTP1` — (legacy) HTTP/1 pipelining; a no-op in modern curl.
pub const CURLPIPE_HTTP1: i64 = 1;
/// `CURLPIPE_MULTIPLEX` — HTTP/2+ stream multiplexing.
pub const CURLPIPE_MULTIPLEX: i64 = 2;

/// `CURL_WAIT_POLLIN` — [`Waitfd`] event bit: wait for readability.
pub const CURL_WAIT_POLLIN: i16 = 0x0001;
/// `CURL_WAIT_POLLPRI` — [`Waitfd`] event bit: wait for priority data.
pub const CURL_WAIT_POLLPRI: i16 = 0x0002;
/// `CURL_WAIT_POLLOUT` — [`Waitfd`] event bit: wait for writability.
pub const CURL_WAIT_POLLOUT: i16 = 0x0004;

/// `CURLMNWC_CLEAR_CONNS` — `CURLMOPT_NETWORK_CHANGED` bit: drop idle/reused
/// connections.
pub const CURLMNWC_CLEAR_CONNS: i64 = 1 << 0;
/// `CURLMNWC_CLEAR_DNS` — `CURLMOPT_NETWORK_CHANGED` bit: drop cached DNS.
pub const CURLMNWC_CLEAR_DNS: i64 = 1 << 0;

/// `CURL_PUSH_OK` — accept a server-pushed stream.
pub const CURL_PUSH_OK: i32 = 0;
/// `CURL_PUSH_DENY` — refuse a server-pushed stream.
pub const CURL_PUSH_DENY: i32 = 1;
/// `CURL_PUSH_ERROROUT` — fail the whole connection on a pushed stream.
pub const CURL_PUSH_ERROROUT: i32 = 2;

/// `CURLMNOTIFY_INFO_READ` — a message became available for [`info_read`].
///
/// [`info_read`]: Multi::info_read
pub const CURLMNOTIFY_INFO_READ: u32 = 0;
/// `CURLMNOTIFY_EASY_DONE` — an easy handle finished its transfer.
pub const CURLMNOTIFY_EASY_DONE: u32 = 1;

// ===========================================================================
// Opaque user-data pointer
// ===========================================================================

/// An opaque application pointer (`void *`) carried verbatim across the API.
///
/// curl's socket/timer/push/notify callbacks and [`assign`](Multi::assign) carry
/// caller-owned `void *` cookies that libcurl never dereferences — it only
/// stores them and hands them back. To stay free of `unsafe`/raw pointers, the
/// core stores the pointer **as its address** ([`usize`]); the FFI layer casts
/// between this address and the real `*mut c_void` at the boundary (the same
/// safe-newtype pattern `curl-rs-lib` uses for every other C pointer).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct UserData(pub usize);

impl UserData {
    /// The `NULL` cookie (address `0`).
    pub const NULL: UserData = UserData(0);

    /// Returns `true` when the cookie is `NULL`.
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

// ===========================================================================
// Poll descriptors
// ===========================================================================

/// A pollable descriptor, equivalent to C's `struct curl_waitfd`.
///
/// Used by [`poll`](Multi::poll) / [`wait`](Multi::wait) to let the application
/// fold additional descriptors into the multi's own wait set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Waitfd {
    /// The socket descriptor to wait on.
    pub fd: CurlSocket,
    /// Requested events (`CURL_WAIT_POLL*`).
    pub events: i16,
    /// Returned events (filled by the wait; `CURL_WAIT_POLL*`).
    pub revents: i16,
}

/// The descriptor sets reported by [`fdset`](Multi::fdset).
///
/// Mirrors the three `fd_set`s plus `max_fd` filled by `curl_multi_fdset`. In
/// this async re-architecture the per-connection sockets are owned by the Tokio
/// runtime and are not surfaced for external `select()`; the recommended drive
/// loop is [`perform`](Multi::perform) + [`poll`](Multi::poll). `fdset`
/// therefore reports only sockets explicitly registered through the
/// socket-interest mechanism, and `max_fd` is `-1` when there are none — exactly
/// the value curl uses to mean "nothing to wait on".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FdSet {
    /// Sockets to monitor for readability.
    pub read: Vec<CurlSocket>,
    /// Sockets to monitor for writability.
    pub write: Vec<CurlSocket>,
    /// Sockets to monitor for exceptional conditions.
    pub exc: Vec<CurlSocket>,
    /// The highest descriptor in any set, or `-1` if all are empty.
    pub max_fd: i32,
}

// ===========================================================================
// Messages (curl_multi_info_read)
// ===========================================================================

/// The kind of a [`CurlMsg`], equivalent to C's `CURLMSG` enum.
///
/// In practice curl only ever emits [`Done`](CurlMsgType::Done); the `None` and
/// `Last` bookends exist for ABI completeness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlMsgType {
    /// `CURLMSG_NONE` (0) — never used (the leading bookend).
    None = 0,
    /// `CURLMSG_DONE` (1) — the transfer completed; inspect the result.
    Done = 1,
    /// `CURLMSG_LAST` (2) — never used (the trailing bookend).
    Last = 2,
}

impl CurlMsgType {
    /// The raw C `CURLMSG` integer for this kind.
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

/// A completion message, the Rust analog of C's `struct CURLMsg`.
///
/// Returned by [`info_read`](Multi::info_read). C's `CURLMsg` packs a `msg` tag,
/// the `easy_handle`, and a `union { void *whatever; CURLcode result; }`; since
/// the only message is `CURLMSG_DONE`, the payload here is the transfer
/// [`result`](CurlMsg::result) directly.
#[derive(Clone)]
pub struct CurlMsg {
    /// The message kind (always [`CurlMsgType::Done`] today).
    pub msg: CurlMsgType,
    /// The easy handle the message concerns.
    pub easy_handle: SharedEasy,
    /// The transfer result — `Ok(())` on success, otherwise the [`CurlError`].
    pub result: Result<(), CurlError>,
}

impl CurlMsg {
    /// The transfer result as the raw `CURLcode` integer (`CURLE_OK` = `0`).
    ///
    /// This is the value C consumers read from `CURLMsg.data.result`.
    #[must_use]
    pub fn result_code(&self) -> CurlCode {
        match self.result {
            Ok(()) => CurlError::Ok.code(),
            Err(err) => err.code(),
        }
    }

    /// Returns `true` when the transfer completed successfully.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.result.is_ok()
    }
}

impl std::fmt::Debug for CurlMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The easy handle is an opaque shared pointer; print only its address
        // (via Arc) to keep this allocation-free and non-recursive.
        f.debug_struct("CurlMsg")
            .field("msg", &self.msg)
            .field("easy_handle", &Arc::as_ptr(&self.easy_handle))
            .field("result", &self.result)
            .finish()
    }
}

// ===========================================================================
// Option / info selectors (CURLMoption / CURLMinfo_offt)
// ===========================================================================

/// The multi-handle option selectors, equivalent to C's `CURLMoption`.
///
/// The discriminants match `include/curl/multi.h` exactly: each selector is
/// `CURLOPTTYPE_<kind> + ordinal`, where the type bases are
/// `CURLOPTTYPE_LONG = 0`, `CURLOPTTYPE_OBJECTPOINT = 10000`,
/// `CURLOPTTYPE_FUNCTIONPOINT = 20000`, and `CURLOPTTYPE_OFF_T = 30000`
/// (`include/curl/curl.h`). This is the actual integer a C caller passes to
/// `curl_multi_setopt`, so the FFI variadic shim can map a raw tag straight to
/// this enum (via [`from_raw`](CurlMOption::from_raw)) and then build the
/// corresponding [`MultiOption`] payload. Using bare ordinals here would reject
/// every non-`LONG` option as `CURLM_UNKNOWN_OPTION` (only `LONG` options, whose
/// base is `0`, would coincidentally match) — see QA F11-PERF Issue #2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlMOption {
    /// `CURLMOPT_SOCKETFUNCTION` — `CURLOPTTYPE_FUNCTIONPOINT + 1` (20001).
    SocketFunction = 20001,
    /// `CURLMOPT_SOCKETDATA` — `CURLOPTTYPE_OBJECTPOINT + 2` (10002).
    SocketData = 10002,
    /// `CURLMOPT_PIPELINING` — `CURLOPTTYPE_LONG + 3` (3).
    Pipelining = 3,
    /// `CURLMOPT_TIMERFUNCTION` — `CURLOPTTYPE_FUNCTIONPOINT + 4` (20004).
    TimerFunction = 20004,
    /// `CURLMOPT_TIMERDATA` — `CURLOPTTYPE_OBJECTPOINT + 5` (10005).
    TimerData = 10005,
    /// `CURLMOPT_MAXCONNECTS` — `CURLOPTTYPE_LONG + 6` (6).
    MaxConnects = 6,
    /// `CURLMOPT_MAX_HOST_CONNECTIONS` — `CURLOPTTYPE_LONG + 7` (7).
    MaxHostConnections = 7,
    /// `CURLMOPT_MAX_PIPELINE_LENGTH` — `CURLOPTTYPE_LONG + 8` (8); inert.
    MaxPipelineLength = 8,
    /// `CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE` — `CURLOPTTYPE_OFF_T + 9` (30009); inert.
    ContentLengthPenaltySize = 30009,
    /// `CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE` — `CURLOPTTYPE_OFF_T + 10` (30010); inert.
    ChunkLengthPenaltySize = 30010,
    /// `CURLMOPT_PIPELINING_SITE_BL` — `CURLOPTTYPE_OBJECTPOINT + 11` (10011); inert.
    PipeliningSiteBl = 10011,
    /// `CURLMOPT_PIPELINING_SERVER_BL` — `CURLOPTTYPE_OBJECTPOINT + 12` (10012); inert.
    PipeliningServerBl = 10012,
    /// `CURLMOPT_MAX_TOTAL_CONNECTIONS` — `CURLOPTTYPE_LONG + 13` (13).
    MaxTotalConnections = 13,
    /// `CURLMOPT_PUSHFUNCTION` — `CURLOPTTYPE_FUNCTIONPOINT + 14` (20014).
    PushFunction = 20014,
    /// `CURLMOPT_PUSHDATA` — `CURLOPTTYPE_OBJECTPOINT + 15` (10015).
    PushData = 10015,
    /// `CURLMOPT_MAX_CONCURRENT_STREAMS` — `CURLOPTTYPE_LONG + 16` (16).
    MaxConcurrentStreams = 16,
    /// `CURLMOPT_NETWORK_CHANGED` — `CURLOPTTYPE_LONG + 17` (17).
    NetworkChanged = 17,
    /// `CURLMOPT_NOTIFYFUNCTION` — `CURLOPTTYPE_FUNCTIONPOINT + 18` (20018).
    NotifyFunction = 20018,
    /// `CURLMOPT_NOTIFYDATA` — `CURLOPTTYPE_OBJECTPOINT + 19` (10019).
    NotifyData = 10019,
}

impl CurlMOption {
    /// The raw C `CURLMoption` integer for this selector.
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }

    /// Builds a [`CurlMOption`] from a raw `CURLMoption` integer, or `None` for
    /// an unrecognized value.
    #[must_use]
    pub const fn from_raw(value: i32) -> Option<CurlMOption> {
        // Values are the public `CURLMOPT_*` integers (`CURLOPTTYPE_<kind> +
        // ordinal`); see the enum doc. Keep this in lockstep with the variants.
        match value {
            20001 => Some(CurlMOption::SocketFunction),
            10002 => Some(CurlMOption::SocketData),
            3 => Some(CurlMOption::Pipelining),
            20004 => Some(CurlMOption::TimerFunction),
            10005 => Some(CurlMOption::TimerData),
            6 => Some(CurlMOption::MaxConnects),
            7 => Some(CurlMOption::MaxHostConnections),
            8 => Some(CurlMOption::MaxPipelineLength),
            30009 => Some(CurlMOption::ContentLengthPenaltySize),
            30010 => Some(CurlMOption::ChunkLengthPenaltySize),
            10011 => Some(CurlMOption::PipeliningSiteBl),
            10012 => Some(CurlMOption::PipeliningServerBl),
            13 => Some(CurlMOption::MaxTotalConnections),
            20014 => Some(CurlMOption::PushFunction),
            10015 => Some(CurlMOption::PushData),
            16 => Some(CurlMOption::MaxConcurrentStreams),
            17 => Some(CurlMOption::NetworkChanged),
            20018 => Some(CurlMOption::NotifyFunction),
            10019 => Some(CurlMOption::NotifyData),
            _ => None,
        }
    }
}

/// The numeric multi-handle info selectors, equivalent to C's `CURLMinfo_offt`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlMInfo {
    /// `CURLMINFO_NONE` (0) — never used.
    None = 0,
    /// `CURLMINFO_XFERS_CURRENT` (1) — handles currently added.
    XfersCurrent = 1,
    /// `CURLMINFO_XFERS_RUNNING` (2) — handles actively transferring.
    XfersRunning = 2,
    /// `CURLMINFO_XFERS_PENDING` (3) — handles waiting to start.
    XfersPending = 3,
    /// `CURLMINFO_XFERS_DONE` (4) — finished handles awaiting result reads.
    XfersDone = 4,
    /// `CURLMINFO_XFERS_ADDED` (5) — total handles ever added.
    XfersAdded = 5,
}

impl CurlMInfo {
    /// The raw C `CURLMinfo_offt` integer for this selector.
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }

    /// Builds a [`CurlMInfo`] from a raw `CURLMinfo_offt` integer, or `None` for
    /// an unrecognized value.
    #[must_use]
    pub const fn from_raw(value: i32) -> Option<CurlMInfo> {
        match value {
            0 => Some(CurlMInfo::None),
            1 => Some(CurlMInfo::XfersCurrent),
            2 => Some(CurlMInfo::XfersRunning),
            3 => Some(CurlMInfo::XfersPending),
            4 => Some(CurlMInfo::XfersDone),
            5 => Some(CurlMInfo::XfersAdded),
            _ => None,
        }
    }
}


// ===========================================================================
// Callbacks (stored as safe trait objects; FFI does the extern "C" marshaling)
// ===========================================================================

/// The `CURLMOPT_SOCKETFUNCTION` callback (curl's `curl_socket_callback`).
///
/// Invoked when a socket's I/O interest changes so the application can register
/// or unregister it with its own event loop. `what` is one of `CURL_POLL_IN`,
/// `CURL_POLL_OUT`, `CURL_POLL_INOUT`, or `CURL_POLL_REMOVE`. The return value
/// is the callback's status (`0` for success, mirroring C).
///
/// The C signature is `int (*)(CURL *easy, curl_socket_t s, int what, void
/// *userp, void *socketp)`. The raw-pointer marshaling lives in the FFI crate;
/// here the handle is a [`SharedEasy`] and the two cookies are [`UserData`].
pub trait SocketCallback: Send {
    /// Handle a socket-interest change for `socket`.
    fn on_socket(
        &mut self,
        easy: Option<&SharedEasy>,
        socket: CurlSocket,
        what: i32,
        socket_userp: UserData,
        socketp: UserData,
    ) -> i32;
}

/// The `CURLMOPT_TIMERFUNCTION` callback (curl's `curl_multi_timer_callback`).
///
/// Invoked whenever the next-timeout value changes (see `Curl_update_timer`).
/// `timeout_ms` is the maximum time the application should wait before driving
/// the multi again, or `-1` to clear any pending timer. Returning `-1` aborts
/// the multi with [`CurlMError::AbortedByCallback`].
pub trait TimerCallback: Send {
    /// React to a change in the next-timeout value.
    fn on_timer(&mut self, timeout_ms: i64, timer_userp: UserData) -> i32;
}

/// The `CURLMOPT_PUSHFUNCTION` callback (curl's `curl_push_callback`).
///
/// Invoked when a server pushes a new HTTP/2 stream; the callback approves
/// ([`CURL_PUSH_OK`]), denies ([`CURL_PUSH_DENY`]), or errors out
/// ([`CURL_PUSH_ERROROUT`]) the stream. Server push is negotiated in the HTTP/2
/// protocol layer; the callback is stored here so the option round-trips
/// faithfully and is dispatched once that layer is wired in.
pub trait PushCallback: Send {
    /// Approve or deny a pushed stream.
    fn on_push(
        &mut self,
        parent: Option<&SharedEasy>,
        pushed: Option<&SharedEasy>,
        push_userp: UserData,
    ) -> i32;
}

/// The `CURLMOPT_NOTIFYFUNCTION` callback (curl's `curl_notify_callback`).
///
/// Invoked, when enabled, on multi-level notifications — [`CURLMNOTIFY_INFO_READ`]
/// when the first message becomes available and [`CURLMNOTIFY_EASY_DONE`] when an
/// easy handle finishes (mirroring `lib/multi_ntfy.c`).
pub trait NotifyCallback: Send {
    /// Deliver a multi-handle notification.
    fn on_notify(&mut self, notification: u32, easy: Option<&SharedEasy>, notify_userp: UserData);
}

// ===========================================================================
// Typed setopt value (CURLMoption + payload)
// ===========================================================================

/// A typed multi-handle option assignment, the safe analog of one
/// `curl_multi_setopt(handle, OPTION, value)` call.
///
/// The C API is variadic: the FFI shim reads the option tag (a [`CurlMOption`])
/// and its single trailing argument, then builds the matching variant here and
/// calls [`Multi::setopt`]. Each variant name corresponds 1:1 to a `CURLMOPT_*`
/// constant, so the mapping is exhaustive and unambiguous.
pub enum MultiOption {
    /// `CURLMOPT_SOCKETFUNCTION` — install or clear the socket callback.
    SocketFunction(Option<Box<dyn SocketCallback>>),
    /// `CURLMOPT_SOCKETDATA` — the socket callback's user pointer.
    SocketData(UserData),
    /// `CURLMOPT_TIMERFUNCTION` — install or clear the timer callback.
    TimerFunction(Option<Box<dyn TimerCallback>>),
    /// `CURLMOPT_TIMERDATA` — the timer callback's user pointer.
    TimerData(UserData),
    /// `CURLMOPT_PUSHFUNCTION` — install or clear the server-push callback.
    PushFunction(Option<Box<dyn PushCallback>>),
    /// `CURLMOPT_PUSHDATA` — the push callback's user pointer.
    PushData(UserData),
    /// `CURLMOPT_NOTIFYFUNCTION` — install or clear the notify callback.
    NotifyFunction(Option<Box<dyn NotifyCallback>>),
    /// `CURLMOPT_NOTIFYDATA` — the notify callback's user pointer.
    NotifyData(UserData),
    /// `CURLMOPT_PIPELINING` — bitmask; `CURLPIPE_MULTIPLEX` enables HTTP/2+
    /// multiplexing.
    Pipelining(i64),
    /// `CURLMOPT_MAXCONNECTS` — connection-cache size limit.
    MaxConnects(i64),
    /// `CURLMOPT_MAX_HOST_CONNECTIONS` — per-host connection limit.
    MaxHostConnections(i64),
    /// `CURLMOPT_MAX_TOTAL_CONNECTIONS` — total connection limit.
    MaxTotalConnections(i64),
    /// `CURLMOPT_MAX_CONCURRENT_STREAMS` — per-connection stream limit.
    MaxConcurrentStreams(i64),
    /// `CURLMOPT_MAX_PIPELINE_LENGTH` — retained but inert (legacy pipelining).
    MaxPipelineLength(i64),
    /// `CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE` — retained but inert.
    ContentLengthPenaltySize(i64),
    /// `CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE` — retained but inert.
    ChunkLengthPenaltySize(i64),
    /// `CURLMOPT_PIPELINING_SITE_BL` — retained but inert (legacy pipelining).
    PipeliningSiteBl,
    /// `CURLMOPT_PIPELINING_SERVER_BL` — retained but inert (legacy pipelining).
    PipeliningServerBl,
    /// `CURLMOPT_NETWORK_CHANGED` — bitmask; clear connection and/or DNS caches.
    NetworkChanged(i64),
}

impl std::fmt::Debug for MultiOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Callback payloads are opaque trait objects; render the variant name and
        // any plain-data payload, but never attempt to print a `dyn` callback.
        match self {
            MultiOption::SocketFunction(cb) => {
                write!(f, "SocketFunction({})", set_or_clear(cb.is_some()))
            }
            MultiOption::SocketData(u) => write!(f, "SocketData({u:?})"),
            MultiOption::TimerFunction(cb) => {
                write!(f, "TimerFunction({})", set_or_clear(cb.is_some()))
            }
            MultiOption::TimerData(u) => write!(f, "TimerData({u:?})"),
            MultiOption::PushFunction(cb) => {
                write!(f, "PushFunction({})", set_or_clear(cb.is_some()))
            }
            MultiOption::PushData(u) => write!(f, "PushData({u:?})"),
            MultiOption::NotifyFunction(cb) => {
                write!(f, "NotifyFunction({})", set_or_clear(cb.is_some()))
            }
            MultiOption::NotifyData(u) => write!(f, "NotifyData({u:?})"),
            MultiOption::Pipelining(v) => write!(f, "Pipelining({v})"),
            MultiOption::MaxConnects(v) => write!(f, "MaxConnects({v})"),
            MultiOption::MaxHostConnections(v) => write!(f, "MaxHostConnections({v})"),
            MultiOption::MaxTotalConnections(v) => write!(f, "MaxTotalConnections({v})"),
            MultiOption::MaxConcurrentStreams(v) => write!(f, "MaxConcurrentStreams({v})"),
            MultiOption::MaxPipelineLength(v) => write!(f, "MaxPipelineLength({v})"),
            MultiOption::ContentLengthPenaltySize(v) => {
                write!(f, "ContentLengthPenaltySize({v})")
            }
            MultiOption::ChunkLengthPenaltySize(v) => write!(f, "ChunkLengthPenaltySize({v})"),
            MultiOption::PipeliningSiteBl => write!(f, "PipeliningSiteBl"),
            MultiOption::PipeliningServerBl => write!(f, "PipeliningServerBl"),
            MultiOption::NetworkChanged(v) => write!(f, "NetworkChanged({v})"),
        }
    }
}

/// Helper for [`MultiOption`]'s `Debug`: render a callback slot's set/clear state.
fn set_or_clear(is_set: bool) -> &'static str {
    if is_set {
        "set"
    } else {
        "cleared"
    }
}

// ===========================================================================
// Internal per-transfer bookkeeping
// ===========================================================================

/// The lifecycle of one transfer inside a [`Multi`].
///
/// This is the memory-safe distillation of curl's `CURLMstate` progression
/// (`MSTATE_INIT` → … → `MSTATE_COMPLETED` → `MSTATE_MSGSENT`). curl walks a
/// transfer through a dozen fine-grained connect/resolve/protocol states; here
/// the whole connect-and-perform machine is driven *inside* a single Tokio task
/// ([`Easy::perform`]), so the multi only needs to track the four externally
/// observable phases that determine the running/pending/done counts and when a
/// `CURLMSG_DONE` message is queued and read:
///
/// * [`Init`](MultiState::Init) — added but not yet spawned (curl's
///   `MSTATE_INIT`/`MSTATE_PENDING`; counts as *running* and *pending*).
/// * [`Performing`](MultiState::Performing) — a Tokio task is driving the
///   transfer (curl's `MSTATE_CONNECT`…`MSTATE_PERFORMING`; counts as *running*).
/// * [`Completed`](MultiState::Completed) — the task finished and a
///   `CURLMSG_DONE` message has been queued, but the application has not yet read
///   it (curl's `MSTATE_COMPLETED`; counts as *done*, no longer *running*).
/// * [`MsgSent`](MultiState::MsgSent) — the application read the message via
///   [`info_read`](Multi::info_read) (curl's `MSTATE_MSGSENT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MultiState {
    /// Added, not yet spawned — waiting for the next drive.
    Init,
    /// A Tokio task is actively driving the transfer.
    Performing,
    /// Finished; a `CURLMSG_DONE` message is queued and unread.
    Completed,
    /// Finished and the completion message has been delivered to the caller.
    MsgSent,
}

/// One transfer managed by a [`Multi`]: its handle, lifecycle state, and the
/// `JoinHandle` of the Tokio task driving it (when [`Performing`]).
///
/// [`Performing`]: MultiState::Performing
struct ManagedTransfer {
    /// A stable, monotonically assigned id used to correlate a [`Completion`]
    /// arriving on the channel back to this transfer (the easy handle alone is
    /// not used as the key because it may be removed and re-added).
    mid: u64,
    /// The shared easy handle (identity compared with [`Arc::ptr_eq`]).
    easy: SharedEasy,
    /// The transfer's externally observable lifecycle phase.
    state: MultiState,
    /// The driving task's handle while [`Performing`], used to abort the task on
    /// [`remove_handle`](Multi::remove_handle) or [`cleanup`](Multi::cleanup).
    ///
    /// [`Performing`]: MultiState::Performing
    join: Option<JoinHandle<()>>,
}

/// A transfer-completion notice sent from a driving Tokio task back to the
/// [`Multi`] over the internal channel.
///
/// The task cannot touch the `Multi` directly (it lives on another thread), so
/// it reports completion by value: the [`mid`](Completion::mid) identifies the
/// transfer and [`result`](Completion::result) carries its outcome. The `Multi`
/// turns this into a `CURLMSG_DONE` [`CurlMsg`] during reaping.
struct Completion {
    /// The [`ManagedTransfer::mid`] of the transfer that finished.
    mid: u64,
    /// The transfer outcome, propagated verbatim into the `CURLMSG_DONE` message.
    result: Result<(), CurlError>,
}

/// A socket-interest report sent from a driving Tokio task back to the
/// [`Multi`] over the dedicated socket-event channel.
///
/// The async transfer task owns the real I/O on the Tokio reactor and cannot
/// touch the `Multi` directly (it lives on another thread). When the connection
/// layer learns the transfer's socket and its read/write interest
/// (`crate::protocols::http::report_socket_to_observer`), it reports it by value
/// via a [`TaskSocketObserver`]; the `Multi` drains these during reaping and
/// fires `CURLMOPT_SOCKETFUNCTION` on its own thread — the production driver of
/// curl's `lib/multi_ev.c` socket-callback contract (AAP §0.7.4, QA F11-PERF
/// Issue #2 Layer 2). `CURL_POLL_REMOVE` is emitted by the `Multi` itself when
/// the transfer completes or is removed (it owns the per-transfer fd map), not
/// reported by the task.
struct SocketEvent {
    /// The [`ManagedTransfer::mid`] of the reporting transfer, so the `Multi`
    /// records which fds belong to which transfer (for `CURL_POLL_REMOVE`).
    mid: u64,
    /// The transfer's socket descriptor (`curl_socket_t`), or `< 0` if none.
    fd: i64,
    /// The reported I/O interest — a `CURL_POLL_IN`/`OUT`/`INOUT`/`NONE` value.
    what: i32,
}

/// The per-task [`SocketObserver`](crate::transfer::SocketObserver) the
/// [`Multi`] installs on each easy handle before its transfer task runs.
///
/// It is the bridge from the connection layer (which discovers the real socket)
/// back to the `Multi`: each `on_socket` report is forwarded — tagged with the
/// transfer's `mid` — over the socket-event channel. The `Multi` drains the
/// channel on its owning thread and invokes the C socket callback there, so the
/// callback never runs on a Tokio worker thread (matching curl's single-thread
/// multi contract).
struct TaskSocketObserver {
    /// The [`ManagedTransfer::mid`] this observer reports for.
    mid: u64,
    /// The sending half of the `Multi`'s socket-event channel.
    socket_tx: UnboundedSender<SocketEvent>,
}

impl crate::transfer::SocketObserver for TaskSocketObserver {
    fn on_socket(&self, fd: i64, what: i32) {
        // If the receiver is gone (the Multi was dropped) the send fails and the
        // report is simply discarded — there is nothing left to drive.
        let _ = self.socket_tx.send(SocketEvent {
            mid: self.mid,
            fd,
            what,
        });
    }
}

/// The outcome of one blocking wait inside [`poll`](Multi::poll) /
/// [`wait`](Multi::wait): which `select!` arm fired.
enum PollOutcome {
    /// A transfer completion arrived (or the channel closed, carrying `None`).
    Completion(Option<Completion>),
    /// [`wakeup`](Multi::wakeup) interrupted the wait.
    Wakeup,
    /// The timeout elapsed with no other event.
    Timeout,
    /// At least one application-provided descriptor (`extra_fds`) became ready.
    ///
    /// Produced only on Unix targets, where external descriptors are folded into
    /// the wait via [`AsyncFd`](tokio::io::unix::AsyncFd); the per-fd readiness is
    /// returned alongside this outcome and written into the caller's array.
    #[cfg_attr(not(unix), allow(dead_code))]
    ExtraReady,
}

// ===========================================================================
// The multi handle
// ===========================================================================

/// The multi handle — the Rust reimplementation of libcurl's opaque `CURLM`.
///
/// A `Multi` owns a set of [`SharedEasy`] transfers and drives them concurrently
/// on a lazily-created **Tokio multi-thread runtime**. It exposes the same
/// synchronous, callback-driven surface as curl's `curl_multi_*` API — see the
/// [module documentation](self) for how the asynchronous machinery is kept
/// invisible behind that contract.
///
/// # Lifecycle
///
/// * [`Multi::new`] ↔ `curl_multi_init` (no runtime is created yet).
/// * [`add_handle`](Multi::add_handle) / [`remove_handle`](Multi::remove_handle)
///   ↔ `curl_multi_add_handle` / `curl_multi_remove_handle`.
/// * [`perform`](Multi::perform) / [`socket_action`](Multi::socket_action) drive
///   the transfers (and lazily create the runtime on first use).
/// * [`info_read`](Multi::info_read) ↔ `curl_multi_info_read` collects results.
/// * `Drop` ↔ `curl_multi_cleanup` (aborts in-flight tasks, shuts the runtime
///   down without blocking).
///
/// # Concurrency
///
/// All mutating operations take `&mut self`, matching curl's rule that a single
/// multi handle is driven from one thread at a time. The sole exception is
/// [`wakeup`](Multi::wakeup), which — like `curl_multi_wakeup` — is safe to call
/// from another thread because it only signals an [`Arc`]-shared [`Notify`].
pub struct Multi {
    /// All added transfers, in insertion order.
    transfers: Vec<ManagedTransfer>,
    /// The next [`ManagedTransfer::mid`] to assign (monotonic, never reused).
    next_mid: u64,
    /// The total number of transfers ever added (curl's `xfers_total_ever`),
    /// reported by [`CurlMInfo::XfersAdded`].
    total_added: u64,
    /// The queue of completion messages awaiting [`info_read`](Multi::info_read).
    msgs: VecDeque<CurlMsg>,
    /// The Tokio runtime, created lazily on the first drive (AAP §0.4.4). `None`
    /// until then, so [`new`](Multi::new) allocates no threads.
    runtime: Option<Runtime>,
    /// The sending half of the transfer-completion channel, cloned into each
    /// spawned task.
    tx: UnboundedSender<Completion>,
    /// The receiving half, drained during reaping.
    rx: UnboundedReceiver<Completion>,
    /// Completions received while blocking in [`poll`](Multi::poll) but not yet
    /// turned into messages; applied at the next reap.
    pending_completions: VecDeque<Completion>,
    /// The wakeup signal backing [`wakeup`](Multi::wakeup); shared with the
    /// blocking wait so another thread can interrupt it.
    wakeup: Arc<Notify>,
    /// `CURLMOPT_SOCKETFUNCTION` — the socket-interest callback.
    socket_cb: Option<Box<dyn SocketCallback>>,
    /// `CURLMOPT_SOCKETDATA` — the socket callback's user pointer.
    socket_userp: UserData,
    /// `CURLMOPT_TIMERFUNCTION` — the next-timeout callback.
    timer_cb: Option<Box<dyn TimerCallback>>,
    /// `CURLMOPT_TIMERDATA` — the timer callback's user pointer.
    timer_userp: UserData,
    /// `CURLMOPT_PUSHFUNCTION` — the HTTP/2 server-push callback.
    push_cb: Option<Box<dyn PushCallback>>,
    /// `CURLMOPT_PUSHDATA` — the push callback's user pointer.
    push_userp: UserData,
    /// `CURLMOPT_NOTIFYFUNCTION` — the multi notification callback.
    notify_cb: Option<Box<dyn NotifyCallback>>,
    /// `CURLMOPT_NOTIFYDATA` — the notify callback's user pointer.
    notify_userp: UserData,
    /// Whether HTTP/2+ multiplexing is enabled (`CURLMOPT_PIPELINING` &
    /// `CURLPIPE_MULTIPLEX`).
    multiplexing: bool,
    /// `CURLMOPT_MAXCONNECTS` — the connection-cache size hint (`0` = default).
    maxconnects: u32,
    /// `CURLMOPT_MAX_HOST_CONNECTIONS` — per-host limit (`0` = unlimited).
    max_host_connections: usize,
    /// `CURLMOPT_MAX_TOTAL_CONNECTIONS` — overall concurrency limit (`0` =
    /// unlimited). When set, only this many transfers run at once; the rest stay
    /// [`Init`](MultiState::Init) (pending).
    max_total_connections: usize,
    /// `CURLMOPT_MAX_CONCURRENT_STREAMS` — per-connection stream limit.
    max_concurrent_streams: u32,
    /// Per-socket user pointers registered via [`assign`](Multi::assign).
    socket_data: HashMap<CurlSocket, UserData>,
    /// The last I/O interest (`CURL_POLL_*`) reported to the socket callback for
    /// each socket, used to diff changes (mirrors `lib/multi_ev.c`).
    socket_interest: HashMap<CurlSocket, i32>,
    /// The sending half of the socket-interest channel, cloned into each spawned
    /// task's [`TaskSocketObserver`]. See [`SocketEvent`].
    socket_tx: UnboundedSender<SocketEvent>,
    /// The receiving half of the socket-interest channel, drained in
    /// [`drain_socket_events`](Multi::drain_socket_events).
    socket_rx: UnboundedReceiver<SocketEvent>,
    /// The set of socket descriptors currently reported by each running
    /// transfer, keyed by [`ManagedTransfer::mid`]. Used to emit
    /// `CURL_POLL_REMOVE` for every fd of a transfer when it completes or is
    /// removed (curl removes a finished transfer's sockets from the pollset).
    task_sockets: HashMap<u64, Vec<CurlSocket>>,
    /// The last timeout value reported to the timer callback, for the
    /// change-detection in [`update_timer`](Multi::update_timer) (`-1` initially,
    /// meaning "no timer set"; mirrors curl's `last_timeout_ms`).
    last_timeout_ms: i64,
    /// Re-entrancy guard: set while a callback is running so a callback that
    /// re-enters the API is rejected with [`CurlMError::RecursiveApiCall`].
    in_callback: bool,
    /// Set when a callback returned an abort code; the multi is "dead" and the
    /// timer callback is no longer invoked (mirrors curl's `multi->dead`).
    dead: bool,
}

impl Default for Multi {
    fn default() -> Self {
        Self::new()
    }
}

impl Multi {
    /// Create a new multi handle — the equivalent of `curl_multi_init`.
    ///
    /// No Tokio runtime is created here; it is built lazily on the first
    /// [`perform`](Multi::perform) / [`socket_action`](Multi::socket_action) /
    /// blocking wait (AAP §0.4.4). All options take their curl defaults:
    /// multiplexing is enabled, connection limits are unset, and the next-timeout
    /// is `-1` ("no timer").
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = unbounded_channel();
        let (socket_tx, socket_rx) = unbounded_channel();
        Multi {
            transfers: Vec::new(),
            next_mid: 1,
            total_added: 0,
            msgs: VecDeque::new(),
            runtime: None,
            tx,
            rx,
            pending_completions: VecDeque::new(),
            wakeup: Arc::new(Notify::new()),
            socket_cb: None,
            socket_userp: UserData::NULL,
            timer_cb: None,
            timer_userp: UserData::NULL,
            push_cb: None,
            push_userp: UserData::NULL,
            notify_cb: None,
            notify_userp: UserData::NULL,
            // curl enables multiplexing by default (CURLPIPE_MULTIPLEX).
            multiplexing: true,
            maxconnects: 0,
            max_host_connections: 0,
            max_total_connections: 0,
            // curl's documented default cap when unset/out of range.
            max_concurrent_streams: 100,
            socket_data: HashMap::new(),
            socket_interest: HashMap::new(),
            socket_tx,
            socket_rx,
            task_sockets: HashMap::new(),
            last_timeout_ms: -1,
            in_callback: false,
            dead: false,
        }
    }

    /// Whether the Tokio runtime has been created yet.
    ///
    /// Returns `false` for a freshly [`new`](Multi::new)-constructed handle and
    /// `true` after the first drive — the observable proof of the lazy-init
    /// contract (AAP §0.4.4).
    #[must_use]
    pub fn is_runtime_initialized(&self) -> bool {
        self.runtime.is_some()
    }

    /// Return a [`Handle`] to the runtime, creating the multi-thread runtime on
    /// first use (AAP §0.4.4).
    ///
    /// The runtime is built with `enable_all` so spawned transfer tasks have I/O
    /// and timer drivers. A build failure (e.g. the OS refused threads) maps to
    /// [`CurlMError::OutOfMemory`], the closest curl error.
    fn ensure_runtime(&mut self) -> Result<Handle, CurlMError> {
        match &self.runtime {
            Some(rt) => Ok(rt.handle().clone()),
            None => {
                let rt = Builder::new_multi_thread()
                    .enable_all()
                    .thread_name("curl-rs-multi")
                    .build()
                    .map_err(|_| CurlMError::OutOfMemory)?;
                let handle = rt.handle().clone();
                self.runtime = Some(rt);
                Ok(handle)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Handle management
// ---------------------------------------------------------------------------

impl Multi {
    /// Add an easy handle to the multi — the equivalent of
    /// `curl_multi_add_handle`.
    ///
    /// The handle is taken by value (an [`Arc`] clone shares it with the caller).
    /// Adding the *same* handle twice — detected with [`Arc::ptr_eq`] — is
    /// rejected with [`CurlMError::AddedAlready`], exactly as curl rejects a
    /// double-add. On success the next-timeout is recomputed (there is now work
    /// to drive), which may invoke the timer callback; if that callback aborts,
    /// its error is returned.
    pub fn add_handle(&mut self, easy: SharedEasy) -> CurlMError {
        if self.in_callback {
            return CurlMError::RecursiveApiCall;
        }
        if self
            .transfers
            .iter()
            .any(|t| Arc::ptr_eq(&t.easy, &easy))
        {
            return CurlMError::AddedAlready;
        }
        let mid = self.next_mid;
        self.next_mid = self.next_mid.wrapping_add(1);
        self.total_added = self.total_added.wrapping_add(1);
        self.transfers.push(ManagedTransfer {
            mid,
            easy,
            state: MultiState::Init,
            join: None,
        });
        // Adding work changes the timeout from "none" (-1) to "now" (0); report
        // it so an event-loop application schedules an immediate drive.
        self.update_timer()
    }

    /// Remove an easy handle from the multi — the equivalent of
    /// `curl_multi_remove_handle`.
    ///
    /// If the handle is still running its driving task is aborted, and any
    /// queued (unread) `CURLMSG_DONE` message for it is discarded. Removing a
    /// handle that was never added yields [`CurlMError::BadEasyHandle`].
    pub fn remove_handle(&mut self, easy: &SharedEasy) -> CurlMError {
        if self.in_callback {
            return CurlMError::RecursiveApiCall;
        }
        let Some(pos) = self
            .transfers
            .iter()
            .position(|t| Arc::ptr_eq(&t.easy, easy))
        else {
            return CurlMError::BadEasyHandle;
        };
        let mut removed = self.transfers.remove(pos);
        if let Some(join) = removed.join.take() {
            // Stop the driving task; its eventual completion (if any) will be
            // ignored because no transfer with this mid remains.
            join.abort();
        }
        // Tell an event-loop consumer to stop watching this transfer's
        // socket(s) with CURL_POLL_REMOVE before the transfer disappears
        // (curl removes a removed handle's sockets from the pollset). The
        // `removed` transfer is no longer in `self.transfers`, so pass its easy
        // handle directly. Any socket report still queued for this `mid` is
        // harmlessly dropped by the next `drain_socket_events` (its `mid` is
        // gone from `self.transfers`).
        self.clear_task_sockets(removed.mid, Some(&removed.easy));
        // Drop any pending completion message belonging to the removed handle.
        self.msgs
            .retain(|m| !Arc::ptr_eq(&m.easy_handle, easy));
        self.update_timer()
    }

    /// Spawn a Tokio task for every [`Init`](MultiState::Init) transfer, up to
    /// the `CURLMOPT_MAX_TOTAL_CONNECTIONS` limit, creating the runtime on first
    /// use.
    ///
    /// Each task locks the shared easy handle and drives [`Easy::perform`] to
    /// completion, then reports the outcome back over the completion channel.
    /// Transfers left over the limit stay `Init` (curl's *pending* state) and are
    /// spawned by a later drive as running slots free up.
    fn spawn_pending(&mut self) -> CurlMError {
        let handle = match self.ensure_runtime() {
            Ok(handle) => handle,
            Err(err) => return err,
        };
        let limit = self.max_total_connections;
        let mut performing = self
            .transfers
            .iter()
            .filter(|t| matches!(t.state, MultiState::Performing))
            .count();
        for idx in 0..self.transfers.len() {
            if !matches!(self.transfers[idx].state, MultiState::Init) {
                continue;
            }
            if limit > 0 && performing >= limit {
                // Respect the total-connections cap: leave the rest pending.
                break;
            }
            let easy = Arc::clone(&self.transfers[idx].easy);
            let mid = self.transfers[idx].mid;
            let tx = self.tx.clone();
            let socket_tx = self.socket_tx.clone();
            let join = handle.spawn(async move {
                // The transfer engine (shared with curl_easy_perform via
                // Easy::perform → crate::transfer) runs here. The async Mutex is
                // held across the .await because the guard *is* the transfer's
                // exclusive access to its handle for the duration of the run.
                let result = {
                    let mut guard = easy.lock().await;
                    // Install the socket observer so the connection layer reports
                    // this transfer's real fd + interest back to the Multi,
                    // driving CURLMOPT_SOCKETFUNCTION for event-loop consumers
                    // (AAP §0.7.4, QA F11-PERF Issue #2 Layer 2). The observer is
                    // installed under the same lock that guards the run, so it is
                    // in place before any connection is established.
                    guard.set_socket_observer(Arc::new(TaskSocketObserver {
                        mid,
                        socket_tx,
                    }));
                    guard.perform().await
                };
                // If the receiver is gone (the Multi was dropped) the send fails
                // and the result is simply discarded — there is nothing to report
                // to.
                let _ = tx.send(Completion { mid, result });
            });
            self.transfers[idx].join = Some(join);
            self.transfers[idx].state = MultiState::Performing;
            performing += 1;
        }
        CurlMError::Ok
    }

    /// Drain completed transfers — buffered ones first, then the channel — and
    /// turn each into a queued `CURLMSG_DONE` message.
    ///
    /// This never blocks: it applies the [`pending_completions`] received during
    /// a previous blocking wait, then non-blockingly drains the channel via
    /// `try_recv`.
    ///
    /// [`pending_completions`]: Multi::pending_completions
    fn reap_completions(&mut self) {
        // Process socket-interest reports first so a transfer's fd is recorded
        // (and CURLMOPT_SOCKETFUNCTION fired with CURL_POLL_IN/OUT) BEFORE its
        // completion emits the matching CURL_POLL_REMOVE. A task enqueues its
        // socket report (during perform) before its completion, and an unbounded
        // send is immediately visible to `try_recv`; so if a completion is
        // visible here, the socket event that preceded it is too — making the
        // IN-then-REMOVE pairing race-free.
        self.drain_socket_events();
        while let Some(completion) = self.pending_completions.pop_front() {
            self.apply_completion(completion);
        }
        while let Ok(completion) = self.rx.try_recv() {
            self.apply_completion(completion);
        }
    }

    /// Drain the socket-event channel, firing `CURLMOPT_SOCKETFUNCTION` for each
    /// reported interest change on the multi's own thread.
    ///
    /// This is the production path that makes the socket callback fire with a
    /// real fd (QA F11-PERF Issue #2 Layer 2): a spawned transfer's connection
    /// layer reports its socket via the [`TaskSocketObserver`]; here we record
    /// the fd under the transfer's `mid` (so completion/removal can emit
    /// `CURL_POLL_REMOVE`) and call
    /// [`note_socket_interest`](Multi::note_socket_interest), which diffs against
    /// the last interest and invokes the C callback only on a real change —
    /// exactly curl's `lib/multi_ev.c` contract. A report for a transfer no
    /// longer managed (already removed) is dropped: its fds were torn down with
    /// `CURL_POLL_REMOVE` already.
    fn drain_socket_events(&mut self) {
        while let Ok(event) = self.socket_rx.try_recv() {
            if event.fd < 0 {
                continue;
            }
            let Some(pos) = self.transfers.iter().position(|t| t.mid == event.mid) else {
                continue;
            };
            let easy = Arc::clone(&self.transfers[pos].easy);
            // Record the fd for this transfer (scoped so the `task_sockets`
            // borrow is released before `note_socket_interest` takes `&mut self`).
            {
                let fds = self.task_sockets.entry(event.mid).or_default();
                if !fds.contains(&event.fd) {
                    fds.push(event.fd);
                }
            }
            let _ = self.note_socket_interest(event.fd, Some(&easy), event.what);
        }
    }

    /// Emit `CURL_POLL_REMOVE` for every socket a transfer reported, and forget
    /// them. Called when the transfer completes
    /// ([`apply_completion`](Multi::apply_completion)) or is removed
    /// ([`remove_handle`](Multi::remove_handle)) so an event-loop consumer stops
    /// watching the fd — mirroring curl removing a finished transfer's sockets
    /// from the pollset.
    fn clear_task_sockets(&mut self, mid: u64, easy: Option<&SharedEasy>) {
        // `remove` returns the owned Vec, so no `task_sockets` borrow is held
        // across the `clear_socket_interest` calls (which take `&mut self`).
        let Some(fds) = self.task_sockets.remove(&mid) else {
            return;
        };
        for fd in fds {
            let _ = self.clear_socket_interest(fd, easy);
        }
    }

    /// Apply one [`Completion`]: mark its transfer [`Completed`], queue a
    /// `CURLMSG_DONE` message, and fire the relevant notifications.
    ///
    /// A completion whose transfer was removed (no matching `mid`) or already
    /// finished is ignored, so a late task wakeup cannot double-count.
    ///
    /// [`Completed`]: MultiState::Completed
    fn apply_completion(&mut self, completion: Completion) {
        let Some(idx) = self
            .transfers
            .iter()
            .position(|t| t.mid == completion.mid)
        else {
            return;
        };
        if !matches!(
            self.transfers[idx].state,
            MultiState::Init | MultiState::Performing
        ) {
            return;
        }
        self.transfers[idx].state = MultiState::Completed;
        self.transfers[idx].join = None;
        let easy = Arc::clone(&self.transfers[idx].easy);
        // The transfer is done: tell an event-loop consumer to stop watching its
        // socket(s) with CURL_POLL_REMOVE, matching curl's pollset teardown at
        // transfer completion (AAP §0.7.4). No-op when no socket was reported
        // (no observer, or a transfer that never reached connect).
        self.clear_task_sockets(completion.mid, Some(&easy));
        let was_empty = self.msgs.is_empty();
        self.msgs.push_back(CurlMsg {
            msg: CurlMsgType::Done,
            easy_handle: Arc::clone(&easy),
            result: completion.result,
        });
        // Notifications mirror lib/multi_ntfy.c: EASY_DONE for each finished
        // transfer, and INFO_READ when the message queue transitions from empty
        // to non-empty (a message just became readable).
        self.dispatch_notify(CURLMNOTIFY_EASY_DONE, Some(&easy));
        if was_empty {
            self.dispatch_notify(CURLMNOTIFY_INFO_READ, Some(&easy));
        }
    }

    /// Invoke the notify callback (if set) with the re-entrancy guard raised.
    fn dispatch_notify(&mut self, notification: u32, easy: Option<&SharedEasy>) {
        let userp = self.notify_userp;
        let previous = self.in_callback;
        self.in_callback = true;
        if let Some(cb) = self.notify_cb.as_mut() {
            cb.on_notify(notification, easy, userp);
        }
        self.in_callback = previous;
    }
}

// ---------------------------------------------------------------------------
// Driving the transfers (perform / socket_action)
// ---------------------------------------------------------------------------

impl Multi {
    /// Advance all transfers — the equivalent of `curl_multi_perform`.
    ///
    /// Spawns any pending transfers, reaps completed ones into `CURLMSG_DONE`
    /// messages, and returns `(code, running_handles)` where `running_handles`
    /// is the number of transfers still in progress. The application calls
    /// [`perform`](Multi::perform) repeatedly until `running_handles` reaches
    /// zero (then drains results with [`info_read`](Multi::info_read)), exactly
    /// as with curl. Like curl, this is rejected from within a callback with
    /// [`CurlMError::RecursiveApiCall`].
    pub fn perform(&mut self) -> (CurlMError, i32) {
        if self.in_callback {
            return (CurlMError::RecursiveApiCall, self.running_handles());
        }
        let spawn_code = self.spawn_pending();
        if !spawn_code.is_ok() {
            return (spawn_code, self.running_handles());
        }
        self.reap_completions();
        let running = self.running_handles();
        // Report the (possibly changed) next timeout to the application.
        let timer_code = self.update_timer();
        let code = if timer_code.is_ok() {
            CurlMError::Ok
        } else {
            timer_code
        };
        (code, running)
    }

    /// React to activity on a socket (or a timeout) — the equivalent of
    /// `curl_multi_socket_action`, the central event-loop entrypoint.
    ///
    /// `sockfd` is the socket that became ready, or [`CURL_SOCKET_TIMEOUT`] to
    /// signal that a timeout fired; `ev_bitmask` carries `CURL_CSELECT_*` flags.
    /// Following curl's `multi_socket`, the `ev_bitmask` is advisory (the actual
    /// readiness is observed by the transfer's own I/O inside its Tokio task),
    /// and a [`CURL_SOCKET_TIMEOUT`] call forces the timer callback to re-report
    /// even if the timeout value is unchanged (curl clears its last-expiry stamp
    /// here). The transfers are then advanced and the timer callback fired with
    /// curl-equivalent timing, preserving the contract event loops depend on
    /// (AAP §0.7.4).
    pub fn socket_action(&mut self, sockfd: CurlSocket, ev_bitmask: i32) -> (CurlMError, i32) {
        if self.in_callback {
            return (CurlMError::RecursiveApiCall, self.running_handles());
        }
        if sockfd == CURL_SOCKET_TIMEOUT {
            // Force the next update_timer to re-invoke the callback even if the
            // computed timeout is unchanged (mirrors multi_socket resetting the
            // expiry bookkeeping on a timeout run).
            self.last_timeout_ms = i64::MIN;
        } else {
            // Activity on a specific socket. The socket→transfer binding that
            // would re-drive exactly that transfer is established by the
            // connection layer (`conn/`); until then the readiness is handled
            // inside the per-transfer Tokio task, so here we simply acknowledge
            // the descriptor and drive the runnable set.
            let _ = (sockfd, ev_bitmask);
        }
        let spawn_code = self.spawn_pending();
        if !spawn_code.is_ok() {
            return (spawn_code, self.running_handles());
        }
        self.reap_completions();
        let running = self.running_handles();
        let timer_code = self.update_timer();
        let code = if timer_code.is_ok() {
            CurlMError::Ok
        } else {
            timer_code
        };
        (code, running)
    }

    /// Compute the next-timeout value curl would report (milliseconds).
    ///
    /// While any transfer is runnable the multi wants to be driven immediately,
    /// so the timeout is `0`; with nothing to do it is `-1` ("no timer"). This is
    /// the value handed to the timer callback and returned by
    /// [`timeout`](Multi::timeout).
    fn compute_timeout_ms(&self) -> i64 {
        if self
            .transfers
            .iter()
            .any(|t| matches!(t.state, MultiState::Init | MultiState::Performing))
        {
            0
        } else {
            -1
        }
    }

    /// Report the next timeout to the timer callback using curl's
    /// change-detection (`Curl_update_timer`).
    ///
    /// The callback is invoked **only when the value actually changes** versus
    /// the last reported one, so an event loop is not woken needlessly. If no
    /// timer callback is set, or the multi is already dead, nothing happens
    /// (matching curl, which also leaves `last_timeout_ms` untouched in that
    /// case). A `-1` return from the callback marks the multi dead and yields
    /// [`CurlMError::AbortedByCallback`].
    fn update_timer(&mut self) -> CurlMError {
        if self.timer_cb.is_none() || self.dead {
            return CurlMError::Ok;
        }
        let current = self.compute_timeout_ms();
        if current == self.last_timeout_ms {
            return CurlMError::Ok;
        }
        self.last_timeout_ms = current;
        let userp = self.timer_userp;
        let previous = self.in_callback;
        self.in_callback = true;
        let rc = self
            .timer_cb
            .as_mut()
            .map_or(0, |cb| cb.on_timer(current, userp));
        self.in_callback = previous;
        if rc == -1 {
            self.dead = true;
            return CurlMError::AbortedByCallback;
        }
        CurlMError::Ok
    }

    /// Register or update a socket's I/O interest and invoke the socket callback
    /// when it changes (the diffing of `lib/multi_ev.c`).
    ///
    /// `what` is a `CURL_POLL_*` value. A change from the previously reported
    /// interest invokes the `CURLMOPT_SOCKETFUNCTION` callback with the new
    /// interest and the socket's assigned user pointer (see
    /// [`assign`](Multi::assign)). [`CURL_POLL_NONE`] / [`CURL_POLL_REMOVE`] are
    /// treated as a removal (delegated to [`clear_socket_interest`]). This is the
    /// registration entrypoint the connection layer drives once it is wired in;
    /// it is exposed now so the callback contract is complete and testable.
    ///
    /// A nonzero callback return aborts the multi with
    /// [`CurlMError::AbortedByCallback`].
    ///
    /// [`clear_socket_interest`]: Multi::clear_socket_interest
    pub fn note_socket_interest(
        &mut self,
        socket: CurlSocket,
        easy: Option<&SharedEasy>,
        what: i32,
    ) -> CurlMError {
        if what == CURL_POLL_NONE || what == CURL_POLL_REMOVE {
            return self.clear_socket_interest(socket, easy);
        }
        let previous_interest = self
            .socket_interest
            .get(&socket)
            .copied()
            .unwrap_or(CURL_POLL_NONE);
        self.socket_interest.insert(socket, what);
        if what == previous_interest {
            return CurlMError::Ok;
        }
        let socketp = self
            .socket_data
            .get(&socket)
            .copied()
            .unwrap_or(UserData::NULL);
        let userp = self.socket_userp;
        let previous = self.in_callback;
        self.in_callback = true;
        let rc = self
            .socket_cb
            .as_mut()
            .map_or(0, |cb| cb.on_socket(easy, socket, what, userp, socketp));
        self.in_callback = previous;
        if rc != 0 {
            self.dead = true;
            return CurlMError::AbortedByCallback;
        }
        CurlMError::Ok
    }

    /// Stop monitoring a socket, invoking the socket callback with
    /// [`CURL_POLL_REMOVE`] if it was being monitored.
    ///
    /// Mirrors the removal half of `lib/multi_ev.c`'s pollset diffing. A nonzero
    /// callback return aborts the multi with [`CurlMError::AbortedByCallback`].
    pub fn clear_socket_interest(
        &mut self,
        socket: CurlSocket,
        easy: Option<&SharedEasy>,
    ) -> CurlMError {
        if self.socket_interest.remove(&socket).is_none() {
            return CurlMError::Ok;
        }
        let socketp = self
            .socket_data
            .get(&socket)
            .copied()
            .unwrap_or(UserData::NULL);
        let userp = self.socket_userp;
        let previous = self.in_callback;
        self.in_callback = true;
        let rc = self.socket_cb.as_mut().map_or(0, |cb| {
            cb.on_socket(easy, socket, CURL_POLL_REMOVE, userp, socketp)
        });
        self.in_callback = previous;
        if rc != 0 {
            self.dead = true;
            return CurlMError::AbortedByCallback;
        }
        CurlMError::Ok
    }

    /// The number of transfers still running (curl's `Curl_multi_xfers_running`).
    fn running_count(&self) -> usize {
        self.transfers
            .iter()
            .filter(|t| matches!(t.state, MultiState::Init | MultiState::Performing))
            .count()
    }

    /// The running-handle count as the `int` curl returns from
    /// `curl_multi_perform` / `curl_multi_socket_action`.
    #[must_use]
    pub fn running_handles(&self) -> i32 {
        clamp_to_i32(self.running_count())
    }
}

// ---------------------------------------------------------------------------
// Results, options, and introspection
// ---------------------------------------------------------------------------

impl Multi {
    /// Pop the next completion message — the equivalent of
    /// `curl_multi_info_read`.
    ///
    /// Returns the oldest queued `CURLMSG_DONE` [`CurlMsg`] (carrying the easy
    /// handle and its result) or `None` when the queue is empty. Reading a
    /// message advances its transfer to the `MSGSENT` phase, mirroring curl.
    /// Calling this from within a callback returns `None` (curl forbids it).
    /// Use [`messages_in_queue`](Multi::messages_in_queue) for the remaining
    /// count.
    pub fn info_read(&mut self) -> Option<CurlMsg> {
        if self.in_callback {
            return None;
        }
        let message = self.msgs.pop_front()?;
        if let Some(transfer) = self
            .transfers
            .iter_mut()
            .find(|t| Arc::ptr_eq(&t.easy, &message.easy_handle))
        {
            if matches!(transfer.state, MultiState::Completed) {
                transfer.state = MultiState::MsgSent;
            }
        }
        Some(message)
    }

    /// The number of messages still waiting in the queue (the `msgs_in_queue`
    /// out-parameter of `curl_multi_info_read`).
    #[must_use]
    pub fn messages_in_queue(&self) -> usize {
        self.msgs.len()
    }

    /// Associate a user pointer with a socket — the equivalent of
    /// `curl_multi_assign`.
    ///
    /// The pointer is handed back to the socket callback for that socket. A
    /// [`CURL_SOCKET_BAD`] descriptor is rejected with
    /// [`CurlMError::BadSocket`].
    pub fn assign(&mut self, sockfd: CurlSocket, sockp: UserData) -> CurlMError {
        if sockfd == CURL_SOCKET_BAD {
            return CurlMError::BadSocket;
        }
        self.socket_data.insert(sockfd, sockp);
        CurlMError::Ok
    }

    /// Apply one typed option — the equivalent of `curl_multi_setopt`.
    ///
    /// The FFI variadic shim decodes the option tag and its trailing argument
    /// into a [`MultiOption`] and calls this. Semantics follow `lib/multi.c`:
    /// `PIPELINING` enables multiplexing when the `CURLPIPE_MULTIPLEX` bit is
    /// set; the connection-limit options reject negative values with
    /// [`CurlMError::BadFunctionArgument`]; `MAX_CONCURRENT_STREAMS` clamps
    /// out-of-range values to `100`; the legacy pipelining knobs are accepted
    /// but inert. An unrecognized option would be rejected by the FFI decoder
    /// before reaching here.
    pub fn setopt(&mut self, option: MultiOption) -> CurlMError {
        if self.in_callback {
            return CurlMError::RecursiveApiCall;
        }
        match option {
            MultiOption::SocketFunction(cb) => self.socket_cb = cb,
            MultiOption::SocketData(userp) => self.socket_userp = userp,
            MultiOption::TimerFunction(cb) => self.timer_cb = cb,
            MultiOption::TimerData(userp) => self.timer_userp = userp,
            MultiOption::PushFunction(cb) => self.push_cb = cb,
            MultiOption::PushData(userp) => self.push_userp = userp,
            MultiOption::NotifyFunction(cb) => self.notify_cb = cb,
            MultiOption::NotifyData(userp) => self.notify_userp = userp,
            MultiOption::Pipelining(bits) => {
                self.multiplexing = (bits & CURLPIPE_MULTIPLEX) != 0;
            }
            MultiOption::MaxConnects(value) => {
                // curl stores the value when it fits an unsigned int; a negative
                // value is silently ignored (kept at the current setting).
                if let Ok(n) = u32::try_from(value) {
                    self.maxconnects = n;
                }
            }
            MultiOption::MaxHostConnections(value) => {
                let Ok(n) = usize::try_from(value) else {
                    return CurlMError::BadFunctionArgument;
                };
                self.max_host_connections = n;
            }
            MultiOption::MaxTotalConnections(value) => {
                let Ok(n) = usize::try_from(value) else {
                    return CurlMError::BadFunctionArgument;
                };
                self.max_total_connections = n;
            }
            MultiOption::MaxConcurrentStreams(value) => {
                // curl clamps values < 1 or > INT_MAX to the default of 100.
                let clamped = if value < 1 || value > i64::from(i32::MAX) {
                    100
                } else {
                    value
                };
                self.max_concurrent_streams = u32::try_from(clamped).unwrap_or(100);
            }
            // Legacy pipelining knobs: accepted for source parity, no effect.
            MultiOption::MaxPipelineLength(_)
            | MultiOption::ContentLengthPenaltySize(_)
            | MultiOption::ChunkLengthPenaltySize(_)
            | MultiOption::PipeliningSiteBl
            | MultiOption::PipeliningServerBl => {}
            MultiOption::NetworkChanged(bits) => {
                // The connection/DNS caches that honor this land with the conn/
                // and dns/ layers; the request is accepted now (a no-op cache
                // flush) so the option round-trips faithfully.
                let _ = bits;
            }
        }
        CurlMError::Ok
    }

    /// Read a numeric multi property — the equivalent of `curl_multi_get_offt`.
    ///
    /// Maps each [`CurlMInfo`] selector to its count, following
    /// `curl_multi_get_offt`: *current* is the total managed, *running* the
    /// actively driven, *pending* the not-yet-spawned, *done* the finished
    /// (read or unread), and *added* the monotonic total ever added.
    /// [`CurlMInfo::None`] is rejected with [`CurlMError::UnknownOption`].
    pub fn get_offt(&self, info: CurlMInfo) -> Result<i64, CurlMError> {
        let value = match info {
            CurlMInfo::None => return Err(CurlMError::UnknownOption),
            CurlMInfo::XfersCurrent => usize_to_i64(self.transfers.len()),
            CurlMInfo::XfersRunning => usize_to_i64(
                self.transfers
                    .iter()
                    .filter(|t| matches!(t.state, MultiState::Performing))
                    .count(),
            ),
            CurlMInfo::XfersPending => usize_to_i64(
                self.transfers
                    .iter()
                    .filter(|t| matches!(t.state, MultiState::Init))
                    .count(),
            ),
            CurlMInfo::XfersDone => usize_to_i64(
                self.transfers
                    .iter()
                    .filter(|t| {
                        matches!(t.state, MultiState::Completed | MultiState::MsgSent)
                    })
                    .count(),
            ),
            CurlMInfo::XfersAdded => i64::try_from(self.total_added).unwrap_or(i64::MAX),
        };
        Ok(value)
    }

    /// A snapshot of the currently managed easy handles (shared clones).
    ///
    /// Useful to the FFI layer and tests; the returned [`Arc`]s share the same
    /// handles the multi drives.
    #[must_use]
    pub fn get_handles(&self) -> Vec<SharedEasy> {
        self.transfers.iter().map(|t| Arc::clone(&t.easy)).collect()
    }

    /// Whether HTTP/2+ multiplexing is enabled (`CURLMOPT_PIPELINING`).
    #[must_use]
    pub fn multiplexing_enabled(&self) -> bool {
        self.multiplexing
    }

    /// The configured `CURLMOPT_MAXCONNECTS` value (`0` = library default).
    #[must_use]
    pub fn max_connects(&self) -> u32 {
        self.maxconnects
    }

    /// The configured `CURLMOPT_MAX_HOST_CONNECTIONS` value (`0` = unlimited).
    #[must_use]
    pub fn max_host_connections(&self) -> usize {
        self.max_host_connections
    }

    /// The configured `CURLMOPT_MAX_TOTAL_CONNECTIONS` value (`0` = unlimited).
    #[must_use]
    pub fn max_total_connections(&self) -> usize {
        self.max_total_connections
    }

    /// The configured `CURLMOPT_MAX_CONCURRENT_STREAMS` value.
    #[must_use]
    pub fn max_concurrent_streams(&self) -> u32 {
        self.max_concurrent_streams
    }

    /// Whether a `CURLMOPT_SOCKETFUNCTION` callback is set.
    #[must_use]
    pub fn has_socket_callback(&self) -> bool {
        self.socket_cb.is_some()
    }

    /// The `CURLMOPT_SOCKETDATA` user pointer.
    #[must_use]
    pub fn socket_data_ptr(&self) -> UserData {
        self.socket_userp
    }

    /// Whether a `CURLMOPT_TIMERFUNCTION` callback is set.
    #[must_use]
    pub fn has_timer_callback(&self) -> bool {
        self.timer_cb.is_some()
    }

    /// The `CURLMOPT_TIMERDATA` user pointer.
    #[must_use]
    pub fn timer_data_ptr(&self) -> UserData {
        self.timer_userp
    }

    /// Whether a `CURLMOPT_PUSHFUNCTION` callback is set.
    #[must_use]
    pub fn has_push_callback(&self) -> bool {
        self.push_cb.is_some()
    }

    /// The `CURLMOPT_PUSHDATA` user pointer.
    #[must_use]
    pub fn push_data_ptr(&self) -> UserData {
        self.push_userp
    }

    /// Whether a `CURLMOPT_NOTIFYFUNCTION` callback is set.
    #[must_use]
    pub fn has_notify_callback(&self) -> bool {
        self.notify_cb.is_some()
    }

    /// The `CURLMOPT_NOTIFYDATA` user pointer.
    #[must_use]
    pub fn notify_data_ptr(&self) -> UserData {
        self.notify_userp
    }

    /// The user pointer assigned to a socket via [`assign`](Multi::assign), if
    /// any.
    #[must_use]
    pub fn assigned_socket_data(&self, socket: CurlSocket) -> Option<UserData> {
        self.socket_data.get(&socket).copied()
    }

    /// The last I/O interest reported to the socket callback for a socket, if it
    /// is currently monitored.
    #[must_use]
    pub fn socket_interest(&self, socket: CurlSocket) -> Option<i32> {
        self.socket_interest.get(&socket).copied()
    }

    /// Whether the multi has been marked dead by an aborting callback.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.dead
    }
}

// ---------------------------------------------------------------------------
// Waiting (fdset / timeout / poll / wait / wakeup)
// ---------------------------------------------------------------------------

impl Multi {
    /// Report the descriptors to monitor — the equivalent of
    /// `curl_multi_fdset`.
    ///
    /// In this async re-architecture the per-connection sockets are owned by the
    /// Tokio runtime and are not exposed for an external `select()`; the
    /// recommended drive loop is [`perform`](Multi::perform) +
    /// [`poll`](Multi::poll). Accordingly this reports only the sockets
    /// explicitly registered through the socket-interest mechanism, with
    /// `max_fd = -1` when there are none (curl's "nothing to wait on" value).
    #[must_use]
    pub fn fdset(&self) -> FdSet {
        let mut set = FdSet {
            read: Vec::new(),
            write: Vec::new(),
            exc: Vec::new(),
            max_fd: -1,
        };
        for (&socket, &what) in &self.socket_interest {
            if what == CURL_POLL_IN || what == CURL_POLL_INOUT {
                set.read.push(socket);
            }
            if what == CURL_POLL_OUT || what == CURL_POLL_INOUT {
                set.write.push(socket);
            }
            let fd = clamp_to_i32(usize::try_from(socket).unwrap_or(0));
            if fd > set.max_fd {
                set.max_fd = fd;
            }
        }
        set
    }

    /// Report how long the application may wait before driving again — the
    /// equivalent of `curl_multi_timeout`.
    ///
    /// Returns the same value the timer callback would receive: `0` while there
    /// is runnable work, `-1` when idle.
    #[must_use]
    pub fn timeout(&self) -> i64 {
        self.compute_timeout_ms()
    }

    /// Wait for activity, sleeping if idle — the equivalent of
    /// `curl_multi_poll`.
    ///
    /// Blocks the calling thread (driving the runtime) until a transfer makes
    /// progress, one of the application-provided `extra_fds` becomes ready,
    /// [`wakeup`](Multi::wakeup) is called, or `timeout_ms` elapses, then returns
    /// `(code, numfds)` where `numfds` is the number of readiness events
    /// observed. Each ready entry in `extra_fds` has its `revents` filled in,
    /// exactly like `curl_multi_poll`. Unlike [`wait`](Multi::wait), `poll`
    /// sleeps even when there is nothing to wait on (so it can be interrupted by
    /// `wakeup`).
    pub fn poll(&mut self, extra_fds: &mut [Waitfd], timeout_ms: i32) -> (CurlMError, i32) {
        self.poll_core(extra_fds, timeout_ms, true)
    }

    /// Wait for activity, returning immediately if idle — the equivalent of
    /// `curl_multi_wait`.
    ///
    /// Identical to [`poll`](Multi::poll) — including filling each ready entry's
    /// `revents` — except that, like `curl_multi_wait`, it returns at once when
    /// there is nothing to wait on rather than sleeping.
    pub fn wait(&mut self, extra_fds: &mut [Waitfd], timeout_ms: i32) -> (CurlMError, i32) {
        self.poll_core(extra_fds, timeout_ms, false)
    }

    /// Shared implementation of [`poll`](Multi::poll) / [`wait`](Multi::wait).
    ///
    /// On Unix the application-provided `extra_fds` are folded into the wait via
    /// [`AsyncFd`](tokio::io::unix::AsyncFd) (see [`wait_with_extra`]): each ready
    /// descriptor has its `revents` written and is counted into the returned
    /// `numfds`, alongside any internal-socket activity. This stays free of
    /// `unsafe` — the descriptor is registered, not owned, so the caller keeps it.
    fn poll_core(
        &mut self,
        extra_fds: &mut [Waitfd],
        timeout_ms: i32,
        sleep_when_idle: bool,
    ) -> (CurlMError, i32) {
        if self.in_callback {
            return (CurlMError::RecursiveApiCall, 0);
        }
        // First reap anything already finished so readiness is reported without
        // an unnecessary sleep.
        self.reap_completions();
        // Start any just-added (Init) transfers before waiting. curl_multi_poll
        // observes transfers that are already progressing on their sockets; our
        // transfers progress on the Tokio runtime, and a transfer only begins
        // making progress — and can therefore signal completion to wake this
        // wait — once it is spawned. Without this, a poll-before-perform drive
        // loop (e.g. `do { curl_multi_poll(...); curl_multi_perform(...); }`)
        // would wait on a not-yet-started transfer and stall for the entire
        // timeout, once per transfer (QA F11-PERF Issue #2 timing facet). This
        // is idempotent: spawn_pending only starts transfers still in `Init`.
        let spawn_code = self.spawn_pending();
        if !spawn_code.is_ok() {
            return (spawn_code, 0);
        }
        // Reap again: a previously-spawned transfer may have completed while we
        // were setting up, so an already-finished multi need not sleep at all.
        self.reap_completions();
        let running = self.running_count();
        let have_extra = !extra_fds.is_empty();
        // curl_multi_wait returns immediately when there is nothing to wait on;
        // curl_multi_poll instead sleeps (so a wakeup can interrupt it).
        if running == 0 && !have_extra && !sleep_when_idle {
            return (CurlMError::Ok, 0);
        }
        let duration = wait_duration(timeout_ms);
        let handle = match self.ensure_runtime() {
            Ok(handle) => handle,
            Err(err) => return (err, 0),
        };
        let wakeup = Arc::clone(&self.wakeup);
        // Drive the wait on the runtime: race internal completions, wakeup, the
        // external descriptors, and the timeout. `wait_with_extra` fills each
        // ready entry's `revents` and returns how many external fds were ready.
        let (outcome, ext_ready) = {
            let rx = &mut self.rx;
            if tokio::runtime::Handle::try_current().is_ok() {
                // We are already inside a Tokio runtime — e.g. the CLI's
                // `#[tokio::main(flavor = "current_thread")]` runtime driving
                // `-Z/--parallel`. Calling `Handle::block_on` on this thread
                // would panic with "Cannot start a runtime from within a
                // runtime" (QA F11-PERF Issue #1). Drive the wait on a scoped
                // helper thread that is not itself running a runtime; the multi
                // runtime's `Handle` enters its own context there. The future is
                // built and polled entirely on that thread (it never crosses the
                // boundary); only `Send` state is captured by the closure — the
                // `Handle` (Send + Sync), the `&mut [Waitfd]` (Waitfd: Send), the
                // `&mut UnboundedReceiver<Completion>` (Completion: Send) and the
                // `Arc<Notify>` — so the borrow-checked scoped thread is sound
                // and is joined before `poll_core` returns.
                std::thread::scope(|s| {
                    s.spawn(|| handle.block_on(wait_with_extra(extra_fds, wakeup, rx, duration)))
                        .join()
                        .expect("multi poll wait helper thread panicked")
                })
            } else {
                // No ambient runtime (the FFI `curl_multi_poll`/`wait` path):
                // block directly on this thread, as before.
                handle.block_on(wait_with_extra(extra_fds, wakeup, rx, duration))
            }
        };
        // Internal-socket activity surfaces as a completion arriving; add the
        // application descriptors the wait reported ready (already in `revents`).
        let mut numfds = ext_ready;
        if let PollOutcome::Completion(Some(completion)) = outcome {
            self.pending_completions.push_back(completion);
            numfds += 1;
        }
        // Apply the completion we just received (plus any that raced in).
        self.reap_completions();
        (CurlMError::Ok, clamp_to_i32(numfds))
    }

    /// Interrupt a blocking [`poll`](Multi::poll) / [`wait`](Multi::wait) — the
    /// equivalent of `curl_multi_wakeup`.
    ///
    /// This is the one multi function that is safe to call from another thread
    /// (it only signals an [`Arc`]-shared [`Notify`]), exactly as
    /// `curl_multi_wakeup` is the one thread-safe `curl_multi_*` entrypoint. If
    /// no wait is in progress the wakeup is remembered and the next wait returns
    /// at once.
    #[must_use]
    pub fn wakeup(&self) -> CurlMError {
        self.wakeup.notify_one();
        CurlMError::Ok
    }

    /// Abort in-flight transfers and shut the runtime down — the equivalent of
    /// `curl_multi_cleanup`.
    ///
    /// Invoked from `Drop`. Tasks are aborted and the runtime is shut down with
    /// [`Runtime::shutdown_background`] (never a blocking shutdown), so dropping
    /// a `Multi` is safe even from within an async context.
    fn cleanup(&mut self) {
        for transfer in &mut self.transfers {
            if let Some(join) = transfer.join.take() {
                join.abort();
            }
        }
        self.transfers.clear();
        self.msgs.clear();
        self.pending_completions.clear();
        // Forget per-transfer socket tracking. We intentionally do NOT fire the
        // socket callback with CURL_POLL_REMOVE here: cleanup runs from `Drop`,
        // and invoking a user C callback during teardown (when its captured
        // state may already be gone) is unsafe. Live transfers emit
        // CURL_POLL_REMOVE on completion / `remove_handle` before this point.
        self.task_sockets.clear();
        self.socket_interest.clear();
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl Drop for Multi {
    fn drop(&mut self) {
        self.cleanup();
    }
}

impl std::fmt::Debug for Multi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Print only counts and flags — never the opaque easy handles or the
        // non-Debug runtime — to keep this cheap and non-recursive.
        f.debug_struct("Multi")
            .field("transfers", &self.transfers.len())
            .field("running", &self.running_count())
            .field("messages_in_queue", &self.msgs.len())
            .field("runtime_initialized", &self.runtime.is_some())
            .field("multiplexing", &self.multiplexing)
            .field("max_total_connections", &self.max_total_connections)
            .field("last_timeout_ms", &self.last_timeout_ms)
            .field("dead", &self.dead)
            .finish()
    }
}

// ===========================================================================
// Free helpers
// ===========================================================================

/// Saturating `usize` → `i32` (curl's running-handle counts are `int`).
fn clamp_to_i32(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// Saturating `usize` → `i64` (curl's `curl_off_t` info values).
fn usize_to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Translate a curl poll timeout (milliseconds, `< 0` meaning "block") into a
/// bounded [`Duration`].
///
/// A negative timeout is curl's "wait indefinitely"; it is bounded to one second
/// here so a lost wakeup can never hang the library forever — a real wakeup or
/// completion still returns earlier, and the caller's own loop re-enters the
/// wait.
fn wait_duration(timeout_ms: i32) -> Duration {
    if timeout_ms < 0 {
        Duration::from_secs(1)
    } else {
        Duration::from_millis(u64::try_from(timeout_ms).unwrap_or(0))
    }
}

/// A borrowed, **non-owning** wrapper around a raw descriptor for [`AsyncFd`].
///
/// [`AsyncFd`] registers the descriptor with the Tokio reactor but, because
/// `PollFd` has no `Drop`, dropping the `AsyncFd` only *deregisters* the fd — it
/// never closes it. The application that passed the `curl_waitfd` therefore
/// keeps full ownership of its socket, exactly as `curl_multi_wait`/`poll`
/// require. This is what lets the external-fd polling stay inside the
/// `#![forbid(unsafe_code)]` core: no raw-pointer or `close()` handling is
/// needed.
///
/// [`AsyncFd`]: tokio::io::unix::AsyncFd
#[cfg(unix)]
struct PollFd(std::os::fd::RawFd);

#[cfg(unix)]
impl std::os::fd::AsRawFd for PollFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0
    }
}

/// Translate a Tokio [`Ready`] set into curl `CURL_WAIT_POLL*` `revents`, masked
/// to the events the caller actually requested in `want`.
///
/// `read_closed`/`write_closed` (peer hangup) fold into readability/writability
/// because a hung-up descriptor reports as readable/writable to `poll()` — the
/// caller then observes EOF or the error on its next I/O, matching curl. A
/// `CURL_WAIT_POLLPRI` request cannot be distinguished portably from plain
/// readability through [`AsyncFd`] (Tokio's `Interest::PRIORITY` is Linux-only),
/// so it is reported alongside readability only when the caller asked for it.
///
/// [`Ready`]: tokio::io::Ready
#[cfg(unix)]
fn ready_to_revents(ready: tokio::io::Ready, want: i16) -> i16 {
    let mut revents = 0i16;
    if ready.is_readable() || ready.is_read_closed() {
        if want & CURL_WAIT_POLLIN != 0 {
            revents |= CURL_WAIT_POLLIN;
        }
        if want & CURL_WAIT_POLLPRI != 0 {
            revents |= CURL_WAIT_POLLPRI;
        }
    }
    if (ready.is_writable() || ready.is_write_closed()) && want & CURL_WAIT_POLLOUT != 0 {
        revents |= CURL_WAIT_POLLOUT;
    }
    revents
}

/// Drive one blocking wait, folding the application's `extra` descriptors into
/// the runtime's reactor (the Unix implementation).
///
/// Races four sources of readiness on the runtime: a [`wakeup`](Multi::wakeup),
/// an internal transfer completion, any of the `extra` descriptors becoming
/// ready, and the `duration` timeout. Returns the [`PollOutcome`] of the race
/// plus the number of `extra` descriptors found ready; the matching `revents`
/// are written into `extra` in place.
///
/// Descriptors the reactor cannot poll (for example regular files, which `poll()`
/// treats as always ready) are reported ready immediately with the requested I/O
/// bits. A descriptor with no requested events, or a negative fd, is skipped —
/// exactly like `poll()`.
#[cfg(unix)]
async fn wait_with_extra(
    extra: &mut [Waitfd],
    wakeup: Arc<Notify>,
    rx: &mut UnboundedReceiver<Completion>,
    duration: Duration,
) -> (PollOutcome, usize) {
    use futures_util::FutureExt;
    use std::os::fd::RawFd;
    use tokio::io::unix::AsyncFd;
    use tokio::io::Interest;

    const POLL_MASK: i16 = CURL_WAIT_POLLIN | CURL_WAIT_POLLPRI | CURL_WAIT_POLLOUT;

    // Register each application descriptor with the runtime's I/O reactor.
    let mut regs: Vec<(usize, AsyncFd<PollFd>, Interest, i16)> = Vec::new();
    let mut immediate = 0usize;
    for (idx, w) in extra.iter_mut().enumerate() {
        let events = w.events;
        let fd = w.fd;
        // `revents` is a pure output: libcurl always overwrites it.
        w.revents = 0;
        let want_read = events & (CURL_WAIT_POLLIN | CURL_WAIT_POLLPRI) != 0;
        let want_write = events & CURL_WAIT_POLLOUT != 0;
        let interest = match (want_read, want_write) {
            (true, true) => Interest::READABLE | Interest::WRITABLE,
            (true, false) => Interest::READABLE,
            (false, true) => Interest::WRITABLE,
            // Nothing requested for this fd: poll() would simply ignore it.
            (false, false) => continue,
        };
        if fd < 0 {
            // A negative descriptor is ignored, exactly like poll().
            continue;
        }
        match AsyncFd::with_interest(PollFd(fd as RawFd), interest) {
            Ok(afd) => regs.push((idx, afd, interest, events)),
            Err(_) => {
                // Non-pollable descriptors (e.g. regular files) are treated by
                // poll() as always ready; report the requested I/O bits.
                w.revents = events & POLL_MASK;
                immediate += 1;
            }
        }
    }

    // A future that resolves once at least one descriptor is ready — immediately
    // when a non-pollable (always-ready) descriptor is present, and never (so the
    // other arms drive) when there is nothing external to wait on.
    let wait_extra = async {
        if immediate > 0 {
            return;
        }
        if regs.is_empty() {
            std::future::pending::<()>().await;
            return;
        }
        let readiness = regs.iter().map(|(_, afd, interest, _)| {
            let interest = *interest;
            Box::pin(async move {
                let _ = afd.ready(interest).await;
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + '_>>
        });
        let _ = futures_util::future::select_all(readiness).await;
    };

    let outcome = tokio::select! {
        biased;
        () = wakeup.notified() => PollOutcome::Wakeup,
        completion = rx.recv() => PollOutcome::Completion(completion),
        () = wait_extra => PollOutcome::ExtraReady,
        () = tokio::time::sleep(duration) => PollOutcome::Timeout,
    };

    // The reactor turn above cached readiness for every descriptor that is
    // currently ready, so a single non-blocking probe per fd reports them all.
    let mut ext_ready = immediate;
    for (idx, afd, interest, want) in &regs {
        if let Some(result) = afd.ready(*interest).now_or_never() {
            let revents = match result {
                Ok(guard) => ready_to_revents(guard.ready(), *want),
                // A reactor error on the fd surfaces as the requested I/O bits so
                // the caller wakes and observes the condition (matching poll()).
                Err(_) => *want & POLL_MASK,
            };
            if revents != 0 {
                extra[*idx].revents = revents;
                ext_ready += 1;
            }
        }
    }
    (outcome, ext_ready)
}

/// Drive one blocking wait (the non-Unix fallback).
///
/// [`AsyncFd`](tokio::io::unix::AsyncFd) is Unix-only, so on other targets the
/// application descriptors cannot be folded into the reactor: their `revents` are
/// cleared and the wait races only the internal completion, wakeup and timeout
/// sources. (All four CP targets are Unix; this exists for portability.)
#[cfg(not(unix))]
async fn wait_with_extra(
    extra: &mut [Waitfd],
    wakeup: Arc<Notify>,
    rx: &mut UnboundedReceiver<Completion>,
    duration: Duration,
) -> (PollOutcome, usize) {
    for w in extra.iter_mut() {
        w.revents = 0;
    }
    let outcome = tokio::select! {
        biased;
        () = wakeup.notified() => PollOutcome::Wakeup,
        completion = rx.recv() => PollOutcome::Completion(completion),
        () = tokio::time::sleep(duration) => PollOutcome::Timeout,
    };
    (outcome, 0)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Instant;

    // --- test callback recorders ------------------------------------------

    /// A timer callback that records every reported timeout, used to verify
    /// the change-detection timing of [`Multi::update_timer`].
    struct RecordingTimer {
        log: Arc<Mutex<Vec<i64>>>,
        /// Value to return from the callback (`-1` aborts the multi).
        ret: i32,
    }

    impl TimerCallback for RecordingTimer {
        fn on_timer(&mut self, timeout_ms: i64, _userp: UserData) -> i32 {
            self.log.lock().expect("timer log poisoned").push(timeout_ms);
            self.ret
        }
    }

    /// A socket callback that records every `(socket, what, socketp)` it is
    /// invoked with, used to verify pollset diffing and per-socket userdata.
    struct RecordingSocket {
        log: Arc<Mutex<Vec<(CurlSocket, i32, usize)>>>,
        ret: i32,
    }

    impl SocketCallback for RecordingSocket {
        fn on_socket(
            &mut self,
            _easy: Option<&SharedEasy>,
            socket: CurlSocket,
            what: i32,
            _userp: UserData,
            socketp: UserData,
        ) -> i32 {
            self.log
                .lock()
                .expect("socket log poisoned")
                .push((socket, what, socketp.0));
            self.ret
        }
    }

    /// Drive `multi` with `perform` until no handles are running, returning the
    /// number of `CURLMSG_DONE` messages collected. Bounded so a stuck transfer
    /// fails the test rather than hanging.
    fn drive_with_perform(multi: &mut Multi) -> usize {
        let mut iterations = 0;
        loop {
            let (code, running) = multi.perform();
            assert!(
                code.is_ok(),
                "perform returned an error code: {code:?}"
            );
            if running == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
            iterations += 1;
            assert!(iterations < 5000, "perform loop failed to converge");
        }
        let mut done = 0;
        while let Some(message) = multi.info_read() {
            assert_eq!(message.msg, CurlMsgType::Done);
            done += 1;
        }
        done
    }

    // --- constants & enums -------------------------------------------------

    #[test]
    fn call_multi_perform_is_minus_one() {
        // The single most ABI-sensitive multi constant.
        assert_eq!(CURLM_CALL_MULTI_PERFORM, -1);
        assert_eq!(CURLM_CALL_MULTI_SOCKET, -1);
        assert_eq!(CurlMError::CallMultiPerform.code(), -1);
    }

    #[test]
    fn poll_constants_match_header() {
        assert_eq!(CURL_POLL_NONE, 0);
        assert_eq!(CURL_POLL_IN, 1);
        assert_eq!(CURL_POLL_OUT, 2);
        assert_eq!(CURL_POLL_INOUT, 3);
        assert_eq!(CURL_POLL_REMOVE, 4);
        assert_eq!(CURL_SOCKET_BAD, -1);
        assert_eq!(CURL_SOCKET_TIMEOUT, CURL_SOCKET_BAD);
    }

    #[test]
    fn option_enum_round_trips() {
        // The full set of public `CURLMOPT_*` integers (`CURLOPTTYPE_<kind> +
        // ordinal`, see the enum doc). Every one must round-trip exactly, and
        // anything else must be rejected as unknown.
        const ALL: &[i32] = &[
            20001, 10002, 3, 20004, 10005, 6, 7, 8, 30009, 30010, 10011, 10012, 13, 20014, 10015,
            16, 17, 20018, 10019,
        ];
        for &raw in ALL {
            let option = CurlMOption::from_raw(raw)
                .unwrap_or_else(|| panic!("expected a known multi option for {raw}"));
            assert_eq!(option.as_raw(), raw, "round-trip failed for {raw}");
        }
        // Explicit anchors from include/curl/multi.h: function-pointer options
        // live in the FUNCTIONPOINT (20000) band and object-pointer options in
        // the OBJECTPOINT (10000) band — not bare ordinals (QA Issue #2 L1).
        assert_eq!(CurlMOption::SocketFunction.as_raw(), 20001);
        assert_eq!(CurlMOption::TimerFunction.as_raw(), 20004);
        assert_eq!(CurlMOption::from_raw(10019), Some(CurlMOption::NotifyData));
        // Bare ordinals that used to (incorrectly) resolve must now be unknown,
        // except where a LONG option legitimately occupies that integer.
        assert_eq!(CurlMOption::from_raw(1), None);
        assert_eq!(CurlMOption::from_raw(19), None);
        assert_eq!(CurlMOption::from_raw(9999), None);
    }

    #[test]
    fn info_enum_round_trips() {
        for raw in 0..=5 {
            let info = CurlMInfo::from_raw(raw).expect("valid info selector");
            assert_eq!(info.as_raw(), raw);
        }
        assert_eq!(CurlMInfo::from_raw(6), None);
    }

    #[test]
    fn msg_type_raw_values() {
        assert_eq!(CurlMsgType::None.as_raw(), 0);
        assert_eq!(CurlMsgType::Done.as_raw(), 1);
        assert_eq!(CurlMsgType::Last.as_raw(), 2);
    }

    // --- lifecycle & lazy runtime -----------------------------------------

    #[test]
    fn new_does_not_create_runtime() {
        let multi = Multi::new();
        assert!(
            !multi.is_runtime_initialized(),
            "the runtime must be created lazily, not at init (AAP §0.4.4)"
        );
        assert_eq!(multi.running_handles(), 0);
        assert_eq!(multi.messages_in_queue(), 0);
        assert!(multi.multiplexing_enabled(), "multiplexing on by default");
    }

    #[test]
    fn first_perform_creates_runtime() {
        let mut multi = Multi::new();
        let easy = shared_easy(Easy::new());
        assert_eq!(multi.add_handle(Arc::clone(&easy)), CurlMError::Ok);
        assert!(
            !multi.is_runtime_initialized(),
            "add_handle must not create the runtime"
        );
        let _ = multi.perform();
        assert!(
            multi.is_runtime_initialized(),
            "the first perform must create the runtime"
        );
    }

    // --- handle management -------------------------------------------------

    #[test]
    fn double_add_is_rejected() {
        let mut multi = Multi::new();
        let easy = shared_easy(Easy::new());
        assert_eq!(multi.add_handle(Arc::clone(&easy)), CurlMError::Ok);
        assert_eq!(
            multi.add_handle(Arc::clone(&easy)),
            CurlMError::AddedAlready,
            "re-adding the same handle must yield CURLM_ADDED_ALREADY"
        );
    }

    #[test]
    fn remove_unknown_handle_is_rejected() {
        let mut multi = Multi::new();
        let unknown = shared_easy(Easy::new());
        assert_eq!(
            multi.remove_handle(&unknown),
            CurlMError::BadEasyHandle,
            "removing a never-added handle must yield CURLM_BAD_EASY_HANDLE"
        );
    }

    #[test]
    fn remove_known_handle_succeeds() {
        let mut multi = Multi::new();
        let easy = shared_easy(Easy::new());
        assert_eq!(multi.add_handle(Arc::clone(&easy)), CurlMError::Ok);
        assert_eq!(multi.get_offt(CurlMInfo::XfersCurrent), Ok(1));
        assert_eq!(multi.remove_handle(&easy), CurlMError::Ok);
        assert_eq!(multi.get_offt(CurlMInfo::XfersCurrent), Ok(0));
    }

    // --- the two drive paths ----------------------------------------------

    #[test]
    fn perform_drives_two_handles_to_completion() {
        let mut multi = Multi::new();
        let e1 = shared_easy(Easy::new());
        let e2 = shared_easy(Easy::new());
        assert_eq!(multi.add_handle(Arc::clone(&e1)), CurlMError::Ok);
        assert_eq!(multi.add_handle(Arc::clone(&e2)), CurlMError::Ok);
        assert_eq!(multi.get_offt(CurlMInfo::XfersAdded), Ok(2));

        let done = drive_with_perform(&mut multi);
        assert_eq!(done, 2, "both transfers must report a DONE message");
        assert_eq!(multi.running_handles(), 0);
        assert!(multi.info_read().is_none(), "the queue must now be empty");
        // All transfers reached MSGSENT (XfersDone counts completed + msgsent).
        assert_eq!(multi.get_offt(CurlMInfo::XfersDone), Ok(2));
    }

    #[test]
    fn socket_action_drives_to_completion() {
        let mut multi = Multi::new();
        let easy = shared_easy(Easy::new());
        assert_eq!(multi.add_handle(Arc::clone(&easy)), CurlMError::Ok);

        let mut iterations = 0;
        loop {
            let (code, running) = multi.socket_action(CURL_SOCKET_TIMEOUT, 0);
            assert!(code.is_ok(), "socket_action error: {code:?}");
            if running == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
            iterations += 1;
            assert!(iterations < 5000, "socket_action loop did not converge");
        }
        let message = multi.info_read().expect("a DONE message");
        assert_eq!(message.msg, CurlMsgType::Done);
        // The no-URL transfer fails; the message must carry a non-OK result.
        assert!(!message.is_success());
        assert!(multi.info_read().is_none());
    }

    #[test]
    fn info_read_empty_returns_none() {
        let mut multi = Multi::new();
        assert!(multi.info_read().is_none());
        assert_eq!(multi.messages_in_queue(), 0);
    }

    // --- get_offt ----------------------------------------------------------

    #[test]
    fn get_offt_counts_and_rejects_none() {
        let mut multi = Multi::new();
        assert_eq!(
            multi.get_offt(CurlMInfo::None),
            Err(CurlMError::UnknownOption)
        );
        assert_eq!(multi.get_offt(CurlMInfo::XfersCurrent), Ok(0));
        let easy = shared_easy(Easy::new());
        multi.add_handle(Arc::clone(&easy));
        assert_eq!(multi.get_offt(CurlMInfo::XfersCurrent), Ok(1));
        assert_eq!(multi.get_offt(CurlMInfo::XfersPending), Ok(1));
        assert_eq!(multi.get_offt(CurlMInfo::XfersRunning), Ok(0));
        assert_eq!(multi.get_offt(CurlMInfo::XfersAdded), Ok(1));
    }

    // --- setopt ------------------------------------------------------------

    #[test]
    fn setopt_pipelining_controls_multiplexing() {
        let mut multi = Multi::new();
        assert_eq!(
            multi.setopt(MultiOption::Pipelining(CURLPIPE_NOTHING)),
            CurlMError::Ok
        );
        assert!(!multi.multiplexing_enabled());
        assert_eq!(
            multi.setopt(MultiOption::Pipelining(CURLPIPE_MULTIPLEX)),
            CurlMError::Ok
        );
        assert!(multi.multiplexing_enabled());
    }

    #[test]
    fn setopt_connection_limits() {
        let mut multi = Multi::new();
        assert_eq!(
            multi.setopt(MultiOption::MaxTotalConnections(5)),
            CurlMError::Ok
        );
        assert_eq!(multi.max_total_connections(), 5);
        assert_eq!(
            multi.setopt(MultiOption::MaxTotalConnections(-1)),
            CurlMError::BadFunctionArgument,
            "a negative limit must be rejected"
        );
        assert_eq!(
            multi.setopt(MultiOption::MaxHostConnections(-3)),
            CurlMError::BadFunctionArgument
        );
        assert_eq!(
            multi.setopt(MultiOption::MaxHostConnections(7)),
            CurlMError::Ok
        );
        assert_eq!(multi.max_host_connections(), 7);
    }

    #[test]
    fn setopt_max_concurrent_streams_clamps() {
        let mut multi = Multi::new();
        // Out-of-range values clamp to curl's default of 100.
        multi.setopt(MultiOption::MaxConcurrentStreams(0));
        assert_eq!(multi.max_concurrent_streams(), 100);
        multi.setopt(MultiOption::MaxConcurrentStreams(i64::from(i32::MAX) + 1));
        assert_eq!(multi.max_concurrent_streams(), 100);
        // In-range values are stored verbatim.
        multi.setopt(MultiOption::MaxConcurrentStreams(50));
        assert_eq!(multi.max_concurrent_streams(), 50);
    }

    #[test]
    fn setopt_maxconnects_ignores_negative() {
        let mut multi = Multi::new();
        multi.setopt(MultiOption::MaxConnects(10));
        assert_eq!(multi.max_connects(), 10);
        // A negative value is ignored (the previous setting is kept).
        multi.setopt(MultiOption::MaxConnects(-1));
        assert_eq!(multi.max_connects(), 10);
    }

    #[test]
    fn setopt_legacy_options_are_inert_but_ok() {
        let mut multi = Multi::new();
        assert_eq!(
            multi.setopt(MultiOption::MaxPipelineLength(8)),
            CurlMError::Ok
        );
        assert_eq!(
            multi.setopt(MultiOption::ContentLengthPenaltySize(1024)),
            CurlMError::Ok
        );
        assert_eq!(multi.setopt(MultiOption::PipeliningSiteBl), CurlMError::Ok);
        assert_eq!(
            multi.setopt(MultiOption::NetworkChanged(CURLMNWC_CLEAR_CONNS)),
            CurlMError::Ok
        );
    }

    #[test]
    fn setopt_userdata_round_trips() {
        let mut multi = Multi::new();
        multi.setopt(MultiOption::SocketData(UserData(0x55)));
        assert_eq!(multi.socket_data_ptr(), UserData(0x55));
        multi.setopt(MultiOption::TimerData(UserData(0xAA)));
        assert_eq!(multi.timer_data_ptr(), UserData(0xAA));
    }

    // --- assign ------------------------------------------------------------

    #[test]
    fn assign_rejects_bad_socket() {
        let mut multi = Multi::new();
        assert_eq!(
            multi.assign(CURL_SOCKET_BAD, UserData(1)),
            CurlMError::BadSocket
        );
        assert_eq!(multi.assign(4, UserData(0x1234)), CurlMError::Ok);
        assert_eq!(multi.assigned_socket_data(4), Some(UserData(0x1234)));
    }

    // --- timer callback change-detection ----------------------------------

    #[test]
    fn timer_callback_fires_only_on_change() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut multi = Multi::new();
        multi.setopt(MultiOption::TimerFunction(Some(Box::new(RecordingTimer {
            log: Arc::clone(&log),
            ret: 0,
        }))));

        let e1 = shared_easy(Easy::new());
        let e2 = shared_easy(Easy::new());
        // First add: timeout changes -1 -> 0, so the callback fires with 0.
        multi.add_handle(Arc::clone(&e1));
        assert_eq!(*log.lock().unwrap(), vec![0]);
        // Second add: timeout stays 0, so the callback must NOT fire again.
        multi.add_handle(Arc::clone(&e2));
        assert_eq!(*log.lock().unwrap(), vec![0]);

        // Driving to completion: timeout changes 0 -> -1 exactly once at the end.
        drive_with_perform(&mut multi);
        assert_eq!(
            *log.lock().unwrap(),
            vec![0, -1],
            "timer callback must fire only when the value changes"
        );
    }

    #[test]
    fn timer_callback_abort_marks_dead() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut multi = Multi::new();
        multi.setopt(MultiOption::TimerFunction(Some(Box::new(RecordingTimer {
            log: Arc::clone(&log),
            ret: -1,
        }))));
        let easy = shared_easy(Easy::new());
        // add_handle -> update_timer -> callback returns -1 -> abort.
        assert_eq!(
            multi.add_handle(Arc::clone(&easy)),
            CurlMError::AbortedByCallback
        );
        assert!(multi.is_dead());
    }

    // --- socket callback diffing ------------------------------------------

    #[test]
    fn socket_callback_diffs_interest() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut multi = Multi::new();
        multi.setopt(MultiOption::SocketFunction(Some(Box::new(RecordingSocket {
            log: Arc::clone(&log),
            ret: 0,
        }))));
        // Assign a per-socket cookie so we can confirm it reaches the callback.
        multi.assign(5, UserData(0xDEAD));

        // NONE -> IN: fires with CURL_POLL_IN and the assigned cookie.
        assert_eq!(
            multi.note_socket_interest(5, None, CURL_POLL_IN),
            CurlMError::Ok
        );
        // IN -> IN: no change, no callback.
        assert_eq!(
            multi.note_socket_interest(5, None, CURL_POLL_IN),
            CurlMError::Ok
        );
        // IN -> INOUT: change, fires.
        assert_eq!(
            multi.note_socket_interest(5, None, CURL_POLL_INOUT),
            CurlMError::Ok
        );
        // Removal fires with CURL_POLL_REMOVE.
        assert_eq!(multi.clear_socket_interest(5, None), CurlMError::Ok);
        // A different socket with no assigned cookie reports a NULL socketp.
        assert_eq!(
            multi.note_socket_interest(7, None, CURL_POLL_OUT),
            CurlMError::Ok
        );

        let events = log.lock().unwrap().clone();
        assert_eq!(
            events,
            vec![
                (5, CURL_POLL_IN, 0xDEAD),
                (5, CURL_POLL_INOUT, 0xDEAD),
                (5, CURL_POLL_REMOVE, 0xDEAD),
                (7, CURL_POLL_OUT, 0),
            ]
        );
    }

    #[test]
    fn socket_callback_abort_marks_dead() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut multi = Multi::new();
        multi.setopt(MultiOption::SocketFunction(Some(Box::new(RecordingSocket {
            log: Arc::clone(&log),
            ret: 1,
        }))));
        assert_eq!(
            multi.note_socket_interest(3, None, CURL_POLL_IN),
            CurlMError::AbortedByCallback
        );
        assert!(multi.is_dead());
    }

    // --- waiting -----------------------------------------------------------

    #[test]
    fn wait_returns_immediately_when_idle() {
        let mut multi = Multi::new();
        let start = Instant::now();
        let (code, numfds) = multi.wait(&mut [], 1000);
        assert_eq!(code, CurlMError::Ok);
        assert_eq!(numfds, 0);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "wait must not sleep when there is nothing to wait on"
        );
    }

    /// `wait` must actually poll an application-provided descriptor and report
    /// its readiness in `revents` (the CP3 F4 fix). Uses a real connected TCP
    /// pair on loopback so the test stays within the `#![forbid(unsafe_code)]`
    /// core (no `libc::socketpair`).
    #[test]
    #[cfg(unix)]
    fn wait_polls_external_fd_and_reports_revents() {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::AsRawFd;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (mut server, _peer) = listener.accept().expect("accept");
        let fd = client.as_raw_fd() as CurlSocket;

        let mut multi = Multi::new();

        // A freshly connected socket is immediately writable.
        let mut fds = [Waitfd {
            fd,
            events: CURL_WAIT_POLLOUT,
            revents: 0,
        }];
        let (code, numfds) = multi.wait(&mut fds, 2000);
        assert_eq!(code, CurlMError::Ok);
        assert_eq!(numfds, 1, "a connected socket is writable");
        assert_eq!(fds[0].revents & CURL_WAIT_POLLOUT, CURL_WAIT_POLLOUT);

        // With no data pending, the socket is not readable: wait times out and
        // reports nothing ready (it must *not* report a stale/aggregate count).
        let mut fds = [Waitfd {
            fd,
            events: CURL_WAIT_POLLIN,
            revents: 0,
        }];
        let (code, numfds) = multi.wait(&mut fds, 200);
        assert_eq!(code, CurlMError::Ok);
        assert_eq!(numfds, 0, "no data → not readable");
        assert_eq!(fds[0].revents, 0);

        // Send a byte from the peer; the descriptor must now report readable.
        server.write_all(b"x").expect("write");
        let mut fds = [Waitfd {
            fd,
            events: CURL_WAIT_POLLIN,
            revents: 0,
        }];
        let (code, numfds) = multi.wait(&mut fds, 2000);
        assert_eq!(code, CurlMError::Ok);
        assert_eq!(numfds, 1, "the external fd became readable");
        assert_eq!(fds[0].revents & CURL_WAIT_POLLIN, CURL_WAIT_POLLIN);
    }

    /// When several application descriptors are ready at once, `wait` reports
    /// every one of them (both `revents` and the aggregate `numfds`).
    #[test]
    #[cfg(unix)]
    fn wait_reports_every_ready_external_fd() {
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::AsRawFd;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _peer) = listener.accept().expect("accept");

        let mut multi = Multi::new();

        // Both ends of a connected pair are writable simultaneously.
        let mut fds = [
            Waitfd {
                fd: client.as_raw_fd() as CurlSocket,
                events: CURL_WAIT_POLLOUT,
                revents: 0,
            },
            Waitfd {
                fd: server.as_raw_fd() as CurlSocket,
                events: CURL_WAIT_POLLOUT,
                revents: 0,
            },
        ];
        let (code, numfds) = multi.wait(&mut fds, 2000);
        assert_eq!(code, CurlMError::Ok);
        assert_eq!(numfds, 2, "both descriptors are writable");
        assert_eq!(fds[0].revents & CURL_WAIT_POLLOUT, CURL_WAIT_POLLOUT);
        assert_eq!(fds[1].revents & CURL_WAIT_POLLOUT, CURL_WAIT_POLLOUT);
    }

    #[test]
    fn wakeup_interrupts_poll() {
        let mut multi = Multi::new();
        // Pre-arm the wakeup; poll would otherwise sleep when idle.
        assert_eq!(multi.wakeup(), CurlMError::Ok);
        let start = Instant::now();
        let (code, _numfds) = multi.poll(&mut [], 5000);
        assert_eq!(code, CurlMError::Ok);
        assert!(
            start.elapsed() < Duration::from_millis(2000),
            "a pre-armed wakeup must make poll return promptly"
        );
    }

    #[test]
    fn poll_observes_completion() {
        let mut multi = Multi::new();
        let easy = shared_easy(Easy::new());
        multi.add_handle(Arc::clone(&easy));
        // Kick off the transfer.
        let (_code, running) = multi.perform();
        // If still running, poll should block until the completion arrives.
        if running > 0 {
            let (code, _numfds) = multi.poll(&mut [], 5000);
            assert_eq!(code, CurlMError::Ok);
        }
        // Finish draining and confirm we got the DONE message.
        let done = drive_with_perform(&mut multi);
        // `done` counts only messages still queued after the poll-driven reap;
        // across both reaping points exactly one transfer completed.
        assert!(done <= 1);
        assert_eq!(multi.running_handles(), 0);
        assert_eq!(multi.get_offt(CurlMInfo::XfersDone), Ok(1));
    }

    // --- timeout & fdset ---------------------------------------------------

    #[test]
    fn timeout_reflects_work() {
        let mut multi = Multi::new();
        assert_eq!(multi.timeout(), -1, "idle multi reports no timeout");
        let easy = shared_easy(Easy::new());
        multi.add_handle(Arc::clone(&easy));
        assert_eq!(multi.timeout(), 0, "runnable work reports an immediate timeout");
    }

    #[test]
    fn fdset_reports_registered_sockets() {
        let mut multi = Multi::new();
        let set = multi.fdset();
        assert_eq!(set.max_fd, -1, "empty fdset reports max_fd = -1");
        // Register interest directly (no socket callback required for fdset).
        multi.note_socket_interest(6, None, CURL_POLL_IN);
        multi.note_socket_interest(8, None, CURL_POLL_OUT);
        let set = multi.fdset();
        assert!(set.read.contains(&6));
        assert!(set.write.contains(&8));
        assert_eq!(set.max_fd, 8);
    }

    // --- introspection -----------------------------------------------------

    #[test]
    fn get_handles_snapshots_added_transfers() {
        let mut multi = Multi::new();
        let e1 = shared_easy(Easy::new());
        let e2 = shared_easy(Easy::new());
        multi.add_handle(Arc::clone(&e1));
        multi.add_handle(Arc::clone(&e2));
        let handles = multi.get_handles();
        assert_eq!(handles.len(), 2);
        assert!(handles.iter().any(|h| Arc::ptr_eq(h, &e1)));
        assert!(handles.iter().any(|h| Arc::ptr_eq(h, &e2)));
    }

    #[test]
    fn debug_impl_is_concise() {
        let multi = Multi::new();
        let rendered = format!("{multi:?}");
        assert!(rendered.contains("Multi"));
        assert!(rendered.contains("runtime_initialized"));
    }
}

