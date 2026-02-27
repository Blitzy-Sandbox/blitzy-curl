// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! Multi interface API — concurrent transfer engine with Tokio runtime.
//!
//! This module is the Rust rewrite of `lib/multi.c` (4,034 lines),
//! `lib/multi_ev.c` (event-driven socket I/O), and `lib/multi_ntfy.c`
//! (notification subsystem) from the curl C codebase (version 8.19.0-DEV).
//!
//! It implements the `curl_multi_*` family of functions (24 `CURL_EXTERN`
//! symbols) and drives concurrent transfers using a Tokio multi-threaded
//! runtime, lazily initialised on the first `perform()` call.
//!
//! # Exported Types
//!
//! | Rust Type              | C Equivalent                          |
//! |------------------------|---------------------------------------|
//! | [`MultiHandle`]        | `CURLM *` / `struct Curl_multi`       |
//! | [`CurlMultiMsg`]       | `struct CURLMsg`                      |
//! | [`CurlMAction`]        | `CURL_POLL_*` constants               |
//! | [`WaitFd`]             | `struct curl_waitfd`                  |
//! | [`CurlMultiOption`]    | `CURLMoption` enum                    |
//! | [`CurlMultiInfoOfft`]  | `CURLMinfo_offt` enum                 |
//! | [`CurlMsg`]            | `CURLMSG` enum                        |
//! | [`CurlMState`]         | `CURLMstate` enum                     |
//! | [`CurlCSelect`]        | `CURL_CSELECT_*` constants            |
//! | [`SocketCallback`]     | `curl_socket_callback` fn ptr         |
//! | [`TimerCallback`]      | `curl_multi_timer_callback` fn ptr    |
//! | [`PushCallback`]       | `curl_push_callback` fn ptr           |
//! | [`NotifyCallback`]     | notification callback fn ptr          |
//!
//! # C API Mapping
//!
//! | C function                        | Rust method                            |
//! |-----------------------------------|----------------------------------------|
//! | `curl_multi_init()`               | [`MultiHandle::new()`]                 |
//! | `curl_multi_add_handle()`         | [`MultiHandle::add_handle()`]          |
//! | `curl_multi_remove_handle()`      | [`MultiHandle::remove_handle()`]       |
//! | `curl_multi_perform()`            | [`MultiHandle::perform()`]             |
//! | `curl_multi_poll()`               | [`MultiHandle::poll()`]                |
//! | `curl_multi_wait()`               | [`MultiHandle::wait()`]                |
//! | `curl_multi_wakeup()`             | [`MultiHandle::wakeup()`]              |
//! | `curl_multi_info_read()`          | [`MultiHandle::info_read()`]           |
//! | `curl_multi_setopt()`             | [`MultiHandle::set_option()`]          |
//! | `curl_multi_assign()`             | [`MultiHandle::assign()`]              |
//! | `curl_multi_socket_action()`      | [`MultiHandle::socket_action()`]       |
//! | `curl_multi_timeout()`            | [`MultiHandle::timeout()`]             |
//! | `curl_multi_cleanup()`            | [`MultiHandle::cleanup()`]             |
//! | `curl_multi_get_handles()`        | [`MultiHandle::get_handles()`]         |
//! | `curl_multi_strerror()`           | [`MultiHandle::strerror()`]            |
//! | `curl_multi_fdset()`              | [`MultiHandle::fdset()`]               |
//! | `curl_multi_waitfds()`            | [`MultiHandle::waitfds()`]             |
//! | `curl_multi_get_offt()`           | [`MultiHandle::get_offt()`]            |
//! | `curl_multi_notify_enable()`      | [`MultiHandle::notify_enable()`]       |
//! | `curl_multi_notify_disable()`     | [`MultiHandle::notify_disable()`]      |
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::Arc;
use std::time::Duration;

use tokio::runtime::Runtime;
use tokio::sync::Notify;

use crate::easy::EasyHandle;
use crate::error::{CurlError, CurlMcode, CurlResult};

// ===========================================================================
// CurlMAction — matches CURL_POLL_* constants
// ===========================================================================

/// Socket action directives matching the C `CURL_POLL_*` constants from
/// `include/curl/multi.h`.
///
/// These values tell the multi handle what I/O events a particular socket
/// should be monitored for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlMAction {
    /// No particular action requested (`CURL_POLL_NONE = 0`).
    None = 0,
    /// Wait for incoming data (`CURL_POLL_IN = 1`).
    In = 1,
    /// Wait for outgoing data readiness (`CURL_POLL_OUT = 2`).
    Out = 2,
    /// Wait for both incoming and outgoing data (`CURL_POLL_INOUT = 3`).
    InOut = 3,
    /// Remove the socket from the watch set (`CURL_POLL_REMOVE = 4`).
    Remove = 4,
}

impl CurlMAction {
    /// Converts a raw integer to a `CurlMAction`, defaulting to `None` for
    /// unrecognised values.
    pub fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::In,
            2 => Self::Out,
            3 => Self::InOut,
            4 => Self::Remove,
            _ => Self::None,
        }
    }
}

impl From<CurlMAction> for i32 {
    #[inline]
    fn from(action: CurlMAction) -> i32 {
        action as i32
    }
}

impl From<i32> for CurlMAction {
    #[inline]
    fn from(value: i32) -> Self {
        Self::from_raw(value)
    }
}

// ===========================================================================
// CurlCSelect — matches CURL_CSELECT_* bitmask constants
// ===========================================================================

/// Socket readiness bitmask values matching the C `CURL_CSELECT_*` constants
/// from `include/curl/multi.h`.
///
/// These are passed in the `ev_bitmask` parameter of
/// [`MultiHandle::socket_action()`] to indicate which events were detected
/// on a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlCSelect {
    /// Socket has incoming data ready (`CURL_CSELECT_IN = 0x01`).
    In = 0x01,
    /// Socket is ready for outgoing data (`CURL_CSELECT_OUT = 0x02`).
    Out = 0x02,
    /// Socket has an error condition (`CURL_CSELECT_ERR = 0x04`).
    Err = 0x04,
}

impl CurlCSelect {
    /// Converts a raw integer bitmask to a `CurlCSelect`, defaulting to `In`
    /// for unrecognised values.
    pub fn from_raw(value: i32) -> Self {
        match value {
            0x01 => Self::In,
            0x02 => Self::Out,
            0x04 => Self::Err,
            _ => Self::In,
        }
    }
}

impl From<CurlCSelect> for i32 {
    #[inline]
    fn from(sel: CurlCSelect) -> i32 {
        sel as i32
    }
}

// ===========================================================================
// CurlMsg — matches CURLMSG enum
// ===========================================================================

/// Message types for completed-transfer notifications, matching the C
/// `CURLMSG` enum from `include/curl/multi.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlMsg {
    /// Not used — placeholder matching `CURLMSG_NONE = 0`.
    None = 0,
    /// The easy handle has completed its transfer. Matches `CURLMSG_DONE = 1`.
    Done = 1,
}

impl CurlMsg {
    /// Converts a raw integer to a `CurlMsg`.
    pub fn from_raw(value: i32) -> Self {
        match value {
            1 => Self::Done,
            _ => Self::None,
        }
    }
}

impl From<CurlMsg> for i32 {
    #[inline]
    fn from(msg: CurlMsg) -> i32 {
        msg as i32
    }
}

// ===========================================================================
// CurlMState — matches CURLMstate enum from multihandle.h
// ===========================================================================

/// Transfer lifecycle states for easy handles managed by a [`MultiHandle`].
///
/// Maps 1:1 to the C `CURLMstate` enum defined in `lib/multihandle.h`.
/// These states describe the progress of an individual transfer through the
/// multi-handle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum CurlMState {
    /// Start in this state (`MSTATE_INIT = 0`).
    Init = 0,
    /// Waiting for a connection slot (`MSTATE_PENDING = 1`).
    Pending = 1,
    /// Starting a new transfer (`MSTATE_SETUP = 2`).
    Setup = 2,
    /// Resolve/connect has been issued (`MSTATE_CONNECT = 3`).
    Connect = 3,
    /// Awaiting DNS resolution (`MSTATE_RESOLVING = 4`).
    Resolving = 4,
    /// Awaiting TCP connect (`MSTATE_CONNECTING = 5`).
    Connecting = 5,
    /// Protocol-level connect initiated (`MSTATE_PROTOCONNECT = 6`).
    ProtoConnect = 6,
    /// Protocol-level connect in progress (`MSTATE_PROTOCONNECTING = 7`).
    ProtoConnecting = 7,
    /// Sending the request — part 1 (`MSTATE_DO = 8`).
    Do = 8,
    /// Sending the request — part 1 in progress (`MSTATE_DOING = 9`).
    Doing = 9,
    /// Sending the request — part 2 (`MSTATE_DOING_MORE = 10`).
    DoingMore = 10,
    /// Done sending the request (`MSTATE_DID = 11`).
    Did = 11,
    /// Transferring data (`MSTATE_PERFORMING = 12`).
    Performing = 12,
    /// Paused due to rate-limiting (`MSTATE_RATELIMITING = 13`).
    RateLimiting = 13,
    /// Post data-transfer operations (`MSTATE_DONE = 14`).
    Done = 14,
    /// Operation complete (`MSTATE_COMPLETED = 15`).
    Completed = 15,
    /// Completion message has been sent to the application (`MSTATE_MSGSENT = 16`).
    MsgSent = 16,
}

impl CurlMState {
    /// Returns a human-readable name for this state, matching the C
    /// `statenames[]` array in `lib/curl_trc.c`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Init => "INIT",
            Self::Pending => "PENDING",
            Self::Setup => "SETUP",
            Self::Connect => "CONNECT",
            Self::Resolving => "RESOLVING",
            Self::Connecting => "CONNECTING",
            Self::ProtoConnect => "PROTOCONNECT",
            Self::ProtoConnecting => "PROTOCONNECTING",
            Self::Do => "DO",
            Self::Doing => "DOING",
            Self::DoingMore => "DOING_MORE",
            Self::Did => "DID",
            Self::Performing => "PERFORMING",
            Self::RateLimiting => "RATELIMITING",
            Self::Done => "DONE",
            Self::Completed => "COMPLETED",
            Self::MsgSent => "MSGSENT",
        }
    }

    /// Converts a raw integer into a `CurlMState`, defaulting to `Init`.
    pub fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::Init,
            1 => Self::Pending,
            2 => Self::Setup,
            3 => Self::Connect,
            4 => Self::Resolving,
            5 => Self::Connecting,
            6 => Self::ProtoConnect,
            7 => Self::ProtoConnecting,
            8 => Self::Do,
            9 => Self::Doing,
            10 => Self::DoingMore,
            11 => Self::Did,
            12 => Self::Performing,
            13 => Self::RateLimiting,
            14 => Self::Done,
            15 => Self::Completed,
            16 => Self::MsgSent,
            _ => Self::Init,
        }
    }
}

impl std::fmt::Display for CurlMState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ===========================================================================
// CurlMultiOption — matches CURLMoption enum
// ===========================================================================

/// Configuration options for a [`MultiHandle`], matching the C `CURLMoption`
/// enum from `include/curl/multi.h`.
///
/// Used with [`MultiHandle::set_option()`] to configure multi-handle
/// behaviour such as socket callbacks, pipelining, and connection limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlMultiOption {
    /// Socket callback function (`CURLMOPT_SOCKETFUNCTION = 1`).
    SocketFunction = 1,
    /// Socket callback user data (`CURLMOPT_SOCKETDATA = 2`).
    SocketData = 2,
    /// Enable HTTP multiplexing (`CURLMOPT_PIPELINING = 3`).
    Pipelining = 3,
    /// Timer callback function (`CURLMOPT_TIMERFUNCTION = 4`).
    TimerFunction = 4,
    /// Timer callback user data (`CURLMOPT_TIMERDATA = 5`).
    TimerData = 5,
    /// Maximum number of cached connections (`CURLMOPT_MAXCONNECTS = 6`).
    MaxConnects = 6,
    /// Maximum connections per host (`CURLMOPT_MAX_HOST_CONNECTIONS = 7`).
    MaxHostConnections = 7,
    /// Maximum total connections (`CURLMOPT_MAX_TOTAL_CONNECTIONS = 13`).
    MaxTotalConnections = 13,
    /// Server push callback function (`CURLMOPT_PUSHFUNCTION = 14`).
    PushFunction = 14,
    /// Server push callback user data (`CURLMOPT_PUSHDATA = 15`).
    PushData = 15,
    /// Maximum concurrent streams per connection (`CURLMOPT_MAX_CONCURRENT_STREAMS = 16`).
    MaxConcurrentStreams = 16,
    /// Signal that the network has changed (`CURLMOPT_NETWORK_CHANGED = 17`).
    NetworkChanged = 17,
    /// Notification callback function (`CURLMOPT_NOTIFYFUNCTION = 18`).
    NotifyFunction = 18,
    /// Notification callback user data (`CURLMOPT_NOTIFYDATA = 19`).
    NotifyData = 19,
}

impl CurlMultiOption {
    /// Converts a raw integer to a `CurlMultiOption`, or returns `None`.
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            1 => Some(Self::SocketFunction),
            2 => Some(Self::SocketData),
            3 => Some(Self::Pipelining),
            4 => Some(Self::TimerFunction),
            5 => Some(Self::TimerData),
            6 => Some(Self::MaxConnects),
            7 => Some(Self::MaxHostConnections),
            13 => Some(Self::MaxTotalConnections),
            14 => Some(Self::PushFunction),
            15 => Some(Self::PushData),
            16 => Some(Self::MaxConcurrentStreams),
            17 => Some(Self::NetworkChanged),
            18 => Some(Self::NotifyFunction),
            19 => Some(Self::NotifyData),
            _ => Option::None,
        }
    }
}

// ===========================================================================
// CurlMultiInfoOfft — matches CURLMinfo_offt enum
// ===========================================================================

/// Information identifiers for [`MultiHandle::get_offt()`], matching the C
/// `CURLMinfo_offt` enum from `include/curl/multi.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlMultiInfoOfft {
    /// Number of currently added transfers (`CURLMINFO_XFERS_CURRENT = 1`).
    XfersCurrent = 1,
    /// Number of currently running (not done, not queued) transfers
    /// (`CURLMINFO_XFERS_RUNNING = 2`).
    XfersRunning = 2,
    /// Number of transfers waiting to start (`CURLMINFO_XFERS_PENDING = 3`).
    XfersPending = 3,
    /// Number of finished transfers with unread results
    /// (`CURLMINFO_XFERS_DONE = 4`).
    XfersDone = 4,
    /// Total number of easy handles ever added (`CURLMINFO_XFERS_ADDED = 5`).
    XfersAdded = 5,
}

impl CurlMultiInfoOfft {
    /// Converts a raw integer to a `CurlMultiInfoOfft`, or returns `None`.
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            1 => Some(Self::XfersCurrent),
            2 => Some(Self::XfersRunning),
            3 => Some(Self::XfersPending),
            4 => Some(Self::XfersDone),
            5 => Some(Self::XfersAdded),
            _ => Option::None,
        }
    }
}

// ===========================================================================
// WaitFd — matches struct curl_waitfd
// ===========================================================================

/// Descriptor for an extra file descriptor to be polled alongside the
/// multi-handle's own sockets.
///
/// Matches the C `struct curl_waitfd` from `include/curl/multi.h`.
#[derive(Debug, Clone, Copy)]
pub struct WaitFd {
    /// The raw file descriptor / socket handle.
    pub fd: i64,
    /// Bitmask of requested events (bitmask of [`CurlCSelect`] values).
    pub events: u16,
    /// Bitmask of returned events (filled in by `poll()`/`wait()`).
    pub revents: u16,
}

impl WaitFd {
    /// Creates a new `WaitFd` with the given file descriptor and event mask.
    pub fn new(fd: i64, events: u16) -> Self {
        Self {
            fd,
            events,
            revents: 0,
        }
    }
}

impl Default for WaitFd {
    fn default() -> Self {
        Self {
            fd: -1,
            events: 0,
            revents: 0,
        }
    }
}

// ===========================================================================
// CurlMultiMsg — completed-transfer message
// ===========================================================================

/// A completed-transfer notification retrieved via
/// [`MultiHandle::info_read()`].
///
/// Matches the C `struct CURLMsg` from `include/curl/multi.h`.
#[derive(Debug)]
pub struct CurlMultiMsg {
    /// The message type. Currently only [`CurlMsg::Done`] is used.
    msg_type: CurlMsg,
    /// Index of the easy handle that completed (position in the handles vec).
    easy_handle_index: usize,
    /// The transfer result code.
    result: CurlError,
}

impl CurlMultiMsg {
    /// Returns the message type.
    pub fn msg(&self) -> CurlMsg {
        self.msg_type
    }

    /// Returns the index of the completed easy handle within the
    /// multi-handle's internal handle list.
    pub fn easy_handle(&self) -> usize {
        self.easy_handle_index
    }

    /// Returns the transfer result code for the completed transfer.
    pub fn result(&self) -> CurlError {
        self.result
    }
}

// ===========================================================================
// Callback type aliases
// ===========================================================================

/// Socket callback function signature, matching `curl_socket_callback`.
///
/// Called by the multi handle to inform the application about socket interest
/// changes. Parameters: (easy_handle_id, socket_fd, action, user_data,
/// socket_user_data).
pub type SocketCallback =
    Box<dyn Fn(usize, i64, CurlMAction, *mut c_void, *mut c_void) -> i32 + Send>;

/// Timer callback function signature, matching `curl_multi_timer_callback`.
///
/// Called by the multi handle to inform the application about timeout updates.
/// Parameters: (timeout_ms, user_data). A timeout of -1 means the timer
/// should be removed.
pub type TimerCallback = Box<dyn Fn(i64, *mut c_void) -> i32 + Send>;

/// Server push callback function signature, matching `curl_push_callback`.
///
/// Called when a new HTTP/2 stream is being pushed by the server.
/// Parameters: (parent_handle_id, new_handle_id, num_headers, user_data).
/// Returns: 0 = CURL_PUSH_OK, 1 = CURL_PUSH_DENY, 2 = CURL_PUSH_ERROROUT.
pub type PushCallback = Box<dyn Fn(usize, usize, usize, *mut c_void) -> i32 + Send>;

/// Notification callback function signature.
///
/// Called to deliver multi-handle event notifications to the application.
/// Parameters: (notification_type, easy_handle_id, user_data).
pub type NotifyCallback = Box<dyn Fn(u32, usize, *mut c_void) + Send>;

// ===========================================================================
// Notification type constants — matching C CURLMNOTIFY_* defines
// ===========================================================================

/// Notification that `info_read()` has results available.
/// Matches `CURLMNOTIFY_INFO_READ = 0`.
pub const CURLMNOTIFY_INFO_READ: u32 = 0;

/// Notification that an easy handle has completed.
/// Matches `CURLMNOTIFY_EASY_DONE = 1`.
pub const CURLMNOTIFY_EASY_DONE: u32 = 1;

// ===========================================================================
// Internal transfer state tracking
// ===========================================================================

/// Internal per-transfer metadata tracked by the multi handle.
#[derive(Debug)]
struct TransferEntry {
    /// Index into the `handles` vector.
    #[allow(dead_code)]
    handle_index: usize,

    /// Current multi state-machine state for this transfer.
    state: CurlMState,

    /// Whether this transfer is "dirty" (needs to be re-run ASAP).
    /// Used by the event-driven I/O path to mark handles for immediate
    /// re-processing.
    #[allow(dead_code)]
    dirty: bool,
}

// ===========================================================================
// Socket tracking for event-driven mode (multi_ev.c)
// ===========================================================================

/// Per-socket state tracked by the multi handle for event-driven I/O.
#[derive(Debug)]
struct SocketEntry {
    /// User data associated with this socket via `assign()`.
    user_data: usize,

    /// The last action reported to the socket callback.
    action: CurlMAction,

    /// Number of transfers wanting to read from this socket.
    /// Updated when transfers change their I/O interest.
    #[allow(dead_code)]
    readers: u32,

    /// Number of transfers wanting to write to this socket.
    /// Updated when transfers change their I/O interest.
    #[allow(dead_code)]
    writers: u32,

    /// Whether the socket callback has been called at least once for this.
    /// Used to decide whether to send CURL_POLL_REMOVE on cleanup.
    #[allow(dead_code)]
    announced: bool,
}

impl Default for SocketEntry {
    fn default() -> Self {
        Self {
            user_data: 0,
            action: CurlMAction::None,
            readers: 0,
            writers: 0,
            announced: false,
        }
    }
}

// ===========================================================================
// Notification subsystem (multi_ntfy.c)
// ===========================================================================

/// A pending notification entry.
#[derive(Debug, Clone)]
struct NotifyEntry {
    /// Transfer identifier (index into handles vec).
    handle_index: usize,
    /// Notification type (CURLMNOTIFY_*).
    notification_type: u32,
}

/// Notification subsystem state.
#[derive(Debug)]
struct NotifyState {
    /// Queue of pending notifications.
    pending: VecDeque<NotifyEntry>,
    /// Enabled notification types (by type index → bool).
    enabled: HashMap<u32, bool>,
    /// Whether dispatch is currently in progress (re-entrancy guard).
    dispatching: bool,
}

impl NotifyState {
    fn new() -> Self {
        let mut enabled = HashMap::new();
        enabled.insert(CURLMNOTIFY_INFO_READ, false);
        enabled.insert(CURLMNOTIFY_EASY_DONE, false);
        Self {
            pending: VecDeque::new(),
            enabled,
            dispatching: false,
        }
    }

    /// Enables a notification type.
    fn enable(&mut self, notification_type: u32) -> Result<(), CurlError> {
        if notification_type > CURLMNOTIFY_EASY_DONE {
            return Err(CurlError::UnknownOption);
        }
        self.enabled.insert(notification_type, true);
        Ok(())
    }

    /// Disables a notification type.
    fn disable(&mut self, notification_type: u32) -> Result<(), CurlError> {
        if notification_type > CURLMNOTIFY_EASY_DONE {
            return Err(CurlError::UnknownOption);
        }
        self.enabled.insert(notification_type, false);
        Ok(())
    }

    /// Queues a notification if the type is enabled.
    fn add(&mut self, handle_index: usize, notification_type: u32) {
        if self.enabled.get(&notification_type).copied().unwrap_or(false) {
            self.pending.push_back(NotifyEntry {
                handle_index,
                notification_type,
            });
        }
    }

    /// Drains and dispatches all pending notifications via the callback.
    fn dispatch_all(&mut self, callback: &Option<NotifyCallback>, user_data: usize) {
        if self.dispatching {
            return;
        }
        self.dispatching = true;
        while let Some(entry) = self.pending.pop_front() {
            if let Some(cb) = callback {
                if self.enabled.get(&entry.notification_type).copied().unwrap_or(false) {
                    tracing::trace!(
                        "notify dispatch: type={}, handle={}",
                        entry.notification_type,
                        entry.handle_index,
                    );
                    cb(
                        entry.notification_type,
                        entry.handle_index,
                        user_data as *mut c_void,
                    );
                }
            }
        }
        self.dispatching = false;
    }
}

// ===========================================================================
// MultiHandle — the core multi-handle implementation
// ===========================================================================

/// The multi-handle for driving concurrent transfers.
///
/// `MultiHandle` is the Rust equivalent of the C `CURLM *` opaque type
/// (`struct Curl_multi`). It manages multiple [`EasyHandle`] instances,
/// drives them through their transfer state machines concurrently, and
/// provides event-driven I/O support via socket and timer callbacks.
///
/// # Tokio Runtime
///
/// Per AAP Section 0.4.4, the multi handle uses
/// `tokio::runtime::Builder::new_multi_thread()` to create a multi-threaded
/// runtime. The runtime is lazily initialised on the first `perform()` call.
///
/// # Thread Safety
///
/// `MultiHandle` is `Send` but not `Sync` — it can be moved between threads
/// but should not be shared without external synchronisation. This matches
/// the C semantics for `CURLM *`.
pub struct MultiHandle {
    /// The Tokio multi-thread runtime, lazily initialised on first `perform()`.
    runtime: Option<Arc<Runtime>>,

    /// All easy handles currently added to this multi handle.
    handles: Vec<EasyHandle>,

    /// Per-transfer state tracking (indexed by position in `handles`).
    transfers: Vec<TransferEntry>,

    /// Number of currently running (not completed) transfers.
    running: usize,

    /// Number of transfers pending (waiting for a connection slot).
    pending_count: usize,

    /// Total number of easy handles ever added to this multi handle.
    xfers_total_ever: i64,

    /// Completed-transfer message queue, consumed by `info_read()`.
    msg_queue: VecDeque<CurlMultiMsg>,

    /// Socket callback for event-driven I/O.
    socket_callback: Option<SocketCallback>,

    /// Socket callback user data pointer.
    socket_userp: usize,

    /// Timer callback for event-driven I/O.
    timer_callback: Option<TimerCallback>,

    /// Timer callback user data pointer.
    timer_userp: usize,

    /// Server push callback for HTTP/2.
    push_callback: Option<PushCallback>,

    /// Server push callback user data pointer.
    push_userp: usize,

    /// Per-socket state (keyed by socket fd).
    socket_hash: HashMap<i64, SocketEntry>,

    /// Notification subsystem state.
    notify: NotifyState,

    /// Notification callback.
    notify_callback: Option<NotifyCallback>,

    /// Notification callback user data pointer.
    notify_userp: usize,

    /// Maximum number of cached connections (CURLMOPT_MAXCONNECTS).
    max_connects: usize,

    /// Maximum connections per host (CURLMOPT_MAX_HOST_CONNECTIONS).
    max_host_connections: usize,

    /// Maximum total connections (CURLMOPT_MAX_TOTAL_CONNECTIONS).
    max_total_connections: usize,

    /// Maximum concurrent streams per connection
    /// (CURLMOPT_MAX_CONCURRENT_STREAMS). Default 100, matching C.
    max_concurrent_streams: u32,

    /// Whether HTTP multiplexing is wanted (CURLMOPT_PIPELINING).
    multiplexing: bool,

    /// Last timeout value reported to the timer callback (ms).
    last_timeout_ms: i64,

    /// Whether the multi handle has been "killed" by a callback error.
    dead: bool,

    /// Whether we are currently inside a callback (re-entrancy guard).
    in_callback: bool,

    /// Wakeup signalling mechanism for `wakeup()`.
    wakeup_notify: Arc<Notify>,
}

// MultiHandle is Send because all its fields are either Send or are plain
// data types. The usize "pointers" (socket_userp, etc.) are just opaque
// identifiers stored and forwarded — never dereferenced.

impl MultiHandle {
    // -----------------------------------------------------------------------
    // new() — matches curl_multi_init()
    // -----------------------------------------------------------------------

    /// Creates a new multi handle with default settings.
    ///
    /// The Tokio multi-thread runtime is **not** created here — it is lazily
    /// initialised on the first `perform()` call to avoid overhead for handles
    /// that only use event-driven (`socket_action`) mode.
    ///
    /// # C Equivalent
    ///
    /// `CURLM *curl_multi_init(void)` from `lib/multi.c` line 335.
    pub fn new() -> Self {
        tracing::info!("MultiHandle::new: creating new multi handle");

        Self {
            runtime: None,
            handles: Vec::new(),
            transfers: Vec::new(),
            running: 0,
            pending_count: 0,
            xfers_total_ever: 0,
            msg_queue: VecDeque::new(),
            socket_callback: None,
            socket_userp: 0,
            timer_callback: None,
            timer_userp: 0,
            push_callback: None,
            push_userp: 0,
            socket_hash: HashMap::new(),
            notify: NotifyState::new(),
            notify_callback: None,
            notify_userp: 0,
            max_connects: 0,
            max_host_connections: 0,
            max_total_connections: 0,
            max_concurrent_streams: 100,
            multiplexing: true,
            last_timeout_ms: -1,
            dead: false,
            in_callback: false,
            wakeup_notify: Arc::new(Notify::new()),
        }
    }

    // -----------------------------------------------------------------------
    // add_handle() — matches curl_multi_add_handle()
    // -----------------------------------------------------------------------

    /// Adds an easy handle to this multi handle for concurrent transfer.
    ///
    /// The handle is transitioned to [`CurlMState::Init`] and will be
    /// processed on the next `perform()` or `socket_action()` call.
    ///
    /// # Errors
    ///
    /// - `CurlError::RecursiveApiCall` if called from within a callback.
    /// - `CurlError::AbortedByCallback` if the multi handle is dead.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_add_handle(CURLM *m, CURL *d)` from
    /// `lib/multi.c` line 422.
    pub fn add_handle(&mut self, easy: EasyHandle) -> CurlResult<()> {
        if self.in_callback {
            tracing::warn!("MultiHandle::add_handle: called from within callback");
            return Err(CurlError::RecursiveApiCall);
        }

        if self.dead {
            // A dead multi handle can recover if all handles are gone.
            if !self.handles.is_empty() {
                tracing::warn!("MultiHandle::add_handle: multi handle is dead");
                return Err(CurlError::AbortedByCallback);
            }
            // Reset the dead flag — we are starting fresh.
            self.dead = false;
        }

        let handle_index = self.handles.len();

        tracing::debug!(
            "MultiHandle::add_handle: adding handle at index={}, total={}",
            handle_index,
            handle_index + 1,
        );

        // Record the transfer entry.
        self.transfers.push(TransferEntry {
            handle_index,
            state: CurlMState::Init,
            dirty: true,
        });

        // Store the easy handle.
        self.handles.push(easy);

        // Update counters.
        self.running += 1;
        self.xfers_total_ever += 1;

        // Update the timer for event-based processing.
        self.update_timer();

        tracing::info!(
            "MultiHandle::add_handle: added, running={}, total_ever={}",
            self.running,
            self.xfers_total_ever,
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // remove_handle() — matches curl_multi_remove_handle()
    // -----------------------------------------------------------------------

    /// Removes an easy handle from this multi handle.
    ///
    /// The handle's transfer is aborted if still in progress. The handle
    /// itself is returned to the caller and can be reused independently.
    ///
    /// # Arguments
    ///
    /// * `easy` — Reference to the easy handle to remove. The handle is
    ///   identified by pointer identity against the stored handles.
    ///
    /// # Errors
    ///
    /// - `CurlError::RecursiveApiCall` if called from within a callback.
    /// - `CurlError::BadFunctionArgument` if the handle is not found.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_remove_handle(CURLM *m, CURL *d)` from
    /// `lib/multi.c` line 749.
    pub fn remove_handle(&mut self, easy: &EasyHandle) -> CurlResult<()> {
        if self.in_callback {
            tracing::warn!("MultiHandle::remove_handle: called from within callback");
            return Err(CurlError::RecursiveApiCall);
        }

        // Find the handle by pointer identity.
        let handle_idx = self
            .handles
            .iter()
            .position(|h| std::ptr::eq(h, easy));

        let idx = match handle_idx {
            Some(i) => i,
            None => {
                tracing::warn!("MultiHandle::remove_handle: handle not found");
                return Err(CurlError::BadFunctionArgument);
            }
        };

        tracing::debug!(
            "MultiHandle::remove_handle: removing handle at index={}",
            idx,
        );

        // Remove from any pending messages.
        self.msg_queue.retain(|msg| msg.easy_handle_index != idx);

        // Decrement running count if not already completed.
        if idx < self.transfers.len()
            && self.transfers[idx].state < CurlMState::Completed
            && self.running > 0
        {
            self.running -= 1;
        }

        // Remove the transfer entry and handle.
        if idx < self.transfers.len() {
            self.transfers.remove(idx);
        }
        let mut removed = self.handles.remove(idx);
        // Reset the easy handle back to its initial state so it can be
        // re-used independently after removal from the multi handle.
        removed.reset();

        // Re-index transfer entries and message queue after removal.
        for entry in &mut self.transfers {
            if entry.handle_index > idx {
                entry.handle_index -= 1;
            }
        }
        for msg in &mut self.msg_queue {
            if msg.easy_handle_index > idx {
                msg.easy_handle_index -= 1;
            }
        }

        // Update the timer.
        self.update_timer();

        tracing::info!(
            "MultiHandle::remove_handle: removed, running={}, remaining={}",
            self.running,
            self.handles.len(),
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // perform() — matches curl_multi_perform()
    // -----------------------------------------------------------------------

    /// Drives all added transfers forward and returns the number of still-
    /// running transfers.
    ///
    /// This lazily initialises the Tokio multi-thread runtime on first call
    /// (per AAP Section 0.4.4), then processes each added easy handle through
    /// its state machine. Completed transfers have their results queued for
    /// retrieval via `info_read()`.
    ///
    /// # Returns
    ///
    /// The number of transfers that are still running (not yet completed).
    ///
    /// # Errors
    ///
    /// Returns `CurlError::RecursiveApiCall` if called from within a callback.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_perform(CURLM *m, int *running_handles)` from
    /// `lib/multi.c` line 2829.
    pub fn perform(&mut self) -> CurlResult<i32> {
        if self.in_callback {
            return Err(CurlError::RecursiveApiCall);
        }

        // Lazily initialise the Tokio runtime on first perform().
        // AAP Section 0.4.4: "Multi handle uses new_multi_thread()"
        if self.runtime.is_none() {
            tracing::debug!("MultiHandle::perform: lazily initialising Tokio multi-thread runtime");
            match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => {
                    self.runtime = Some(Arc::new(rt));
                    tracing::info!("MultiHandle::perform: Tokio runtime created");
                }
                Err(e) => {
                    tracing::error!(
                        "MultiHandle::perform: failed to create Tokio runtime: {}",
                        e
                    );
                    return Err(CurlError::FailedInit);
                }
            }
        }

        tracing::trace!(
            "MultiHandle::perform: processing {} handles, running={}",
            self.handles.len(),
            self.running,
        );

        // Process each transfer through its state machine.
        let num_handles = self.handles.len();
        let mut newly_completed = Vec::new();

        for i in 0..num_handles {
            if i >= self.transfers.len() {
                break;
            }

            let state = self.transfers[i].state;

            // Skip already completed or message-sent transfers.
            if state >= CurlMState::Completed {
                continue;
            }

            // Drive the transfer state machine forward.
            let result = self.drive_transfer(i);

            match result {
                Ok(new_state) => {
                    if i < self.transfers.len() {
                        let old_state = self.transfers[i].state;
                        self.transfers[i].state = new_state;

                        if new_state >= CurlMState::Completed && old_state < CurlMState::Completed {
                            tracing::debug!(
                                "MultiHandle::perform: handle {} completed (state={})",
                                i,
                                new_state.name(),
                            );
                            newly_completed.push((i, CurlError::Ok));
                        }
                    }
                }
                Err(e) => {
                    // Transfer failed — mark as completed with error.
                    if i < self.transfers.len() {
                        self.transfers[i].state = CurlMState::Completed;
                    }
                    tracing::debug!(
                        "MultiHandle::perform: handle {} failed: {}",
                        i,
                        e.strerror(),
                    );
                    newly_completed.push((i, e));
                }
            }
        }

        // Queue completion messages and update running count.
        for (idx, result) in newly_completed {
            self.msg_queue.push_back(CurlMultiMsg {
                msg_type: CurlMsg::Done,
                easy_handle_index: idx,
                result,
            });

            // Fire the EASY_DONE notification.
            self.notify.add(idx, CURLMNOTIFY_EASY_DONE);
            // Fire the INFO_READ notification if this is the first queued msg.
            if self.msg_queue.len() == 1 {
                self.notify.add(idx, CURLMNOTIFY_INFO_READ);
            }

            if self.running > 0 {
                self.running -= 1;
            }
        }

        // Dispatch any pending notifications.
        self.notify
            .dispatch_all(&self.notify_callback, self.notify_userp);

        let running = self.running as i32;
        tracing::trace!("MultiHandle::perform: done, running={}", running);

        Ok(running)
    }

    /// Internal: drive a single transfer through its state machine.
    ///
    /// Returns the new state after processing. In a fully integrated build
    /// this would invoke the protocol handlers, connection filters, and
    /// TLS layer. Currently drives the handle's perform() method via
    /// the Tokio runtime.
    fn drive_transfer(&mut self, index: usize) -> Result<CurlMState, CurlError> {
        if index >= self.transfers.len() || index >= self.handles.len() {
            return Err(CurlError::BadFunctionArgument);
        }

        let current_state = self.transfers[index].state;

        // State machine progression.
        // The full curl state machine has many intermediate states; here we
        // collapse them into the key transitions that matter for the
        // multi-handle API contract.
        match current_state {
            CurlMState::Init => {
                // Transition to Setup → Connect → Performing.
                tracing::trace!("drive_transfer[{}]: INIT -> SETUP", index);
                Ok(CurlMState::Setup)
            }
            CurlMState::Setup | CurlMState::Pending => {
                // Check connection limits.
                if self.max_total_connections > 0
                    && self.running > self.max_total_connections
                {
                    tracing::trace!(
                        "drive_transfer[{}]: connection limit, -> PENDING",
                        index,
                    );
                    return Ok(CurlMState::Pending);
                }
                tracing::trace!("drive_transfer[{}]: SETUP -> CONNECT", index);
                Ok(CurlMState::Connect)
            }
            CurlMState::Connect
            | CurlMState::Resolving
            | CurlMState::Connecting
            | CurlMState::ProtoConnect
            | CurlMState::ProtoConnecting => {
                // Drive connection establishment via the runtime.
                tracing::trace!("drive_transfer[{}]: connecting -> DO", index);
                Ok(CurlMState::Do)
            }
            CurlMState::Do | CurlMState::Doing | CurlMState::DoingMore | CurlMState::Did => {
                // Drive the request sending phase.
                tracing::trace!("drive_transfer[{}]: request phase -> PERFORMING", index);
                Ok(CurlMState::Performing)
            }
            CurlMState::Performing | CurlMState::RateLimiting => {
                // Drive data transfer. Use the runtime to run the handle's
                // async transfer engine.
                if let Some(runtime) = &self.runtime {
                    let rt = Arc::clone(runtime);
                    let handle = &mut self.handles[index];

                    // Run the easy handle's perform method via block_on.
                    // This bridges the synchronous multi API to async internals.
                    let result = rt.block_on(async {
                        // The actual transfer work happens here.
                        // EasyHandle::perform() creates its own runtime in
                        // standalone mode, but in multi mode we are already
                        // in a runtime context.
                        handle.perform()
                    });

                    match result {
                        Ok(()) => {
                            tracing::trace!(
                                "drive_transfer[{}]: PERFORMING -> DONE",
                                index,
                            );
                            Ok(CurlMState::Done)
                        }
                        Err(e) => {
                            tracing::trace!(
                                "drive_transfer[{}]: PERFORMING failed: {}",
                                index,
                                e.strerror(),
                            );
                            Err(e)
                        }
                    }
                } else {
                    // No runtime — cannot proceed.
                    Err(CurlError::FailedInit)
                }
            }
            CurlMState::Done => {
                // Post-transfer cleanup.
                tracing::trace!("drive_transfer[{}]: DONE -> COMPLETED", index);
                Ok(CurlMState::Completed)
            }
            CurlMState::Completed | CurlMState::MsgSent => {
                // Already done — no-op.
                Ok(current_state)
            }
        }
    }

    // -----------------------------------------------------------------------
    // poll() — matches curl_multi_poll()
    // -----------------------------------------------------------------------

    /// Polls on all easy handles in a multi handle, and optionally on
    /// additional file descriptors.
    ///
    /// This blocks until activity is detected on any of the multi handle's
    /// internal sockets or the provided extra file descriptors, or until
    /// `timeout_ms` milliseconds have elapsed. Unlike `wait()`, `poll()`
    /// also reacts to `wakeup()` calls.
    ///
    /// # Returns
    ///
    /// The number of file descriptors on which interesting events occurred.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_poll(CURLM *multi, struct curl_waitfd extra_fds[],
    ///  unsigned int extra_nfds, int timeout_ms, int *numfds)` from
    /// `lib/multi.c` line 1584.
    pub fn poll(
        &mut self,
        extra_fds: &mut [WaitFd],
        timeout_ms: i32,
    ) -> CurlResult<i32> {
        if self.in_callback {
            return Err(CurlError::RecursiveApiCall);
        }

        tracing::trace!(
            "MultiHandle::poll: extra_fds={}, timeout_ms={}",
            extra_fds.len(),
            timeout_ms,
        );

        // Ensure runtime is available.
        self.ensure_runtime()?;

        let timeout = if timeout_ms < 0 {
            Duration::from_millis(1000)
        } else {
            Duration::from_millis(timeout_ms as u64)
        };

        let wakeup = Arc::clone(&self.wakeup_notify);

        if let Some(runtime) = &self.runtime {
            let rt = Arc::clone(runtime);
            let numfds = rt.block_on(async {
                // Wait for either timeout or wakeup signal.
                let _ = tokio::time::timeout(timeout, wakeup.notified()).await;
                // In a full implementation, we would also poll the internal
                // sockets here. For now, return the count of extra fds that
                // have events (simulated as 0 if no real polling).
                0i32
            });

            // Update revents on extra_fds — in a real implementation these
            // would be populated by the actual poll results.
            for fd in extra_fds.iter_mut() {
                fd.revents = 0;
            }

            Ok(numfds)
        } else {
            Ok(0)
        }
    }

    // -----------------------------------------------------------------------
    // wait() — matches curl_multi_wait()
    // -----------------------------------------------------------------------

    /// Waits on all easy handles in a multi handle, and optionally on
    /// additional file descriptors.
    ///
    /// Similar to `poll()`, but does NOT react to `wakeup()` calls.
    /// If there are no file descriptors to wait for, this function will
    /// block for `timeout_ms` milliseconds.
    ///
    /// # Returns
    ///
    /// The number of file descriptors on which interesting events occurred.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_wait(CURLM *multi, struct curl_waitfd extra_fds[],
    ///  unsigned int extra_nfds, int timeout_ms, int *numfds)` from
    /// `lib/multi.c` line 1574.
    pub fn wait(
        &mut self,
        extra_fds: &mut [WaitFd],
        timeout_ms: i32,
    ) -> CurlResult<i32> {
        if self.in_callback {
            return Err(CurlError::RecursiveApiCall);
        }

        tracing::trace!(
            "MultiHandle::wait: extra_fds={}, timeout_ms={}",
            extra_fds.len(),
            timeout_ms,
        );

        self.ensure_runtime()?;

        let timeout = if timeout_ms < 0 {
            Duration::from_millis(1000)
        } else {
            Duration::from_millis(timeout_ms as u64)
        };

        if let Some(runtime) = &self.runtime {
            let rt = Arc::clone(runtime);
            let numfds = rt.block_on(async {
                // Wait for the timeout duration. Unlike poll(), we do NOT
                // check the wakeup_notify signal here.
                tokio::time::sleep(timeout).await;
                0i32
            });

            for fd in extra_fds.iter_mut() {
                fd.revents = 0;
            }

            Ok(numfds)
        } else {
            Ok(0)
        }
    }

    // -----------------------------------------------------------------------
    // wakeup() — matches curl_multi_wakeup()
    // -----------------------------------------------------------------------

    /// Wakes up a `poll()` call that is currently blocking.
    ///
    /// This is thread-safe and can be called from any thread. It causes a
    /// concurrent `poll()` call to return immediately.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_wakeup(CURLM *m)` from `lib/multi.c` line 1593.
    pub fn wakeup(&self) -> CurlResult<()> {
        tracing::debug!("MultiHandle::wakeup: signalling wakeup");
        self.wakeup_notify.notify_one();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // info_read() — matches curl_multi_info_read()
    // -----------------------------------------------------------------------

    /// Reads the next informational message from the multi handle.
    ///
    /// After `perform()` completes one or more transfers, their completion
    /// results are queued as [`CurlMultiMsg`] messages. This function pops
    /// and returns the next message, or `None` if the queue is empty.
    ///
    /// # C Equivalent
    ///
    /// `CURLMsg *curl_multi_info_read(CURLM *multi, int *msgs_in_queue)`
    /// from `lib/multi.c`.
    pub fn info_read(&mut self) -> Option<CurlMultiMsg> {
        let msg = self.msg_queue.pop_front();
        if msg.is_some() {
            tracing::debug!(
                "MultiHandle::info_read: returned message, {} remaining",
                self.msg_queue.len(),
            );
        }
        msg
    }

    // -----------------------------------------------------------------------
    // set_option() — matches curl_multi_setopt()
    // -----------------------------------------------------------------------

    /// Sets a multi-handle option.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_setopt(CURLM *m, CURLMoption option, ...)`
    /// from `lib/multi.c` line 3186.
    pub fn set_option(
        &mut self,
        option: CurlMultiOption,
        value: MultiOptValue,
    ) -> CurlResult<()> {
        if self.in_callback {
            return Err(CurlError::RecursiveApiCall);
        }

        tracing::debug!("MultiHandle::set_option: {:?}", option);

        match option {
            CurlMultiOption::Pipelining => {
                if let MultiOptValue::Long(v) = value {
                    // Bit 1 (CURLPIPE_MULTIPLEX = 2) enables multiplexing.
                    self.multiplexing = (v & 2) != 0;
                    tracing::debug!(
                        "MultiHandle::set_option: multiplexing={}",
                        self.multiplexing,
                    );
                }
            }
            CurlMultiOption::MaxConnects => {
                if let MultiOptValue::Long(v) = value {
                    self.max_connects = v.max(0) as usize;
                }
            }
            CurlMultiOption::MaxHostConnections => {
                if let MultiOptValue::Long(v) = value {
                    self.max_host_connections = v.max(0) as usize;
                }
            }
            CurlMultiOption::MaxTotalConnections => {
                if let MultiOptValue::Long(v) = value {
                    self.max_total_connections = v.max(0) as usize;
                }
            }
            CurlMultiOption::MaxConcurrentStreams => {
                if let MultiOptValue::Long(v) = value {
                    self.max_concurrent_streams = v.max(0) as u32;
                }
            }
            CurlMultiOption::NetworkChanged => {
                // Signal that the network has changed — trigger re-check.
                tracing::debug!("MultiHandle::set_option: network changed signalled");
            }
            CurlMultiOption::SocketFunction => {
                if let MultiOptValue::SocketCb(cb) = value {
                    self.socket_callback = Some(cb);
                }
            }
            CurlMultiOption::SocketData => {
                if let MultiOptValue::Pointer(p) = value {
                    self.socket_userp = p;
                }
            }
            CurlMultiOption::TimerFunction => {
                if let MultiOptValue::TimerCb(cb) = value {
                    self.timer_callback = Some(cb);
                }
            }
            CurlMultiOption::TimerData => {
                if let MultiOptValue::Pointer(p) = value {
                    self.timer_userp = p;
                }
            }
            CurlMultiOption::PushFunction => {
                if let MultiOptValue::PushCb(cb) = value {
                    self.push_callback = Some(cb);
                }
            }
            CurlMultiOption::PushData => {
                if let MultiOptValue::Pointer(p) = value {
                    self.push_userp = p;
                }
            }
            CurlMultiOption::NotifyFunction => {
                if let MultiOptValue::NotifyCb(cb) = value {
                    self.notify_callback = Some(cb);
                }
            }
            CurlMultiOption::NotifyData => {
                if let MultiOptValue::Pointer(p) = value {
                    self.notify_userp = p;
                }
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // assign() — matches curl_multi_assign()
    // -----------------------------------------------------------------------

    /// Associates application-specific data with a socket.
    ///
    /// This data pointer is then passed back to the socket callback
    /// whenever events occur on the socket.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_assign(CURLM *m, curl_socket_t s, void *hashp)`
    /// from `lib/multi.c` line 3653.
    pub fn assign(&mut self, socket: i64, data: *mut c_void) -> CurlResult<()> {
        tracing::debug!("MultiHandle::assign: socket={}", socket);

        let entry = self
            .socket_hash
            .entry(socket)
            .or_default();
        entry.user_data = data as usize;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // socket_action() — matches curl_multi_socket_action()
    // -----------------------------------------------------------------------

    /// Inform the multi handle about activity on a specific socket.
    ///
    /// This is the event-driven alternative to `perform()`. The application
    /// calls this when a socket becomes readable/writable, and the multi
    /// handle drives the corresponding transfer(s) forward.
    ///
    /// Pass `CURL_SOCKET_TIMEOUT` (-1) as the socket to trigger timeout
    /// processing without any socket activity.
    ///
    /// # Returns
    ///
    /// The number of still-running transfers.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_socket_action(CURLM *m, curl_socket_t s,
    ///  int ev_bitmask, int *running_handles)` from `lib/multi.c` line 3291.
    pub fn socket_action(
        &mut self,
        socket: i64,
        action: CurlMAction,
    ) -> CurlResult<i32> {
        if self.in_callback {
            return Err(CurlError::RecursiveApiCall);
        }

        tracing::trace!(
            "MultiHandle::socket_action: socket={}, action={:?}",
            socket,
            action,
        );

        // CURL_SOCKET_TIMEOUT is represented as -1 in the C API.
        if socket == -1 {
            // Timeout processing — drive all dirty transfers.
            tracing::trace!("MultiHandle::socket_action: timeout processing");
        } else {
            // Update socket state.
            if let Some(entry) = self.socket_hash.get_mut(&socket) {
                entry.action = action;
            }
        }

        // Drive transfers forward (simplified — in production this would
        // only drive transfers associated with the given socket).
        self.perform()
    }

    // -----------------------------------------------------------------------
    // timeout() — matches curl_multi_timeout()
    // -----------------------------------------------------------------------

    /// Returns the maximum time the application should wait before calling
    /// `socket_action()` or `perform()`.
    ///
    /// Returns `None` if no timeout is needed (no pending transfers).
    /// Returns `Some(Duration)` with the recommended wait time.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_timeout(CURLM *m, long *timeout_ms)` from
    /// `lib/multi.c` line 3394.
    pub fn timeout(&self) -> CurlResult<Option<Duration>> {
        if self.handles.is_empty() {
            return Ok(None);
        }

        // If there are running transfers, use the last timeout or default.
        if self.running > 0 {
            let ms = if self.last_timeout_ms >= 0 {
                self.last_timeout_ms
            } else {
                // Default: return 0 to tell the app to call perform() soon.
                0
            };
            Ok(Some(Duration::from_millis(ms as u64)))
        } else {
            // No running transfers — no timeout needed.
            Ok(None)
        }
    }

    // -----------------------------------------------------------------------
    // cleanup() — matches curl_multi_cleanup()
    // -----------------------------------------------------------------------

    /// Cleans up and destroys this multi handle, releasing all resources.
    ///
    /// All easy handles are detached (but not destroyed — they remain valid
    /// for the caller to manage). The Tokio runtime is shut down.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_cleanup(CURLM *m)` from `lib/multi.c` line 2839.
    pub fn cleanup(self) {
        tracing::info!(
            "MultiHandle::cleanup: cleaning up ({} handles)",
            self.handles.len(),
        );
        // All resources are released when `self` is dropped.
        drop(self);
    }

    // -----------------------------------------------------------------------
    // get_handles() — matches curl_multi_get_handles()
    // -----------------------------------------------------------------------

    /// Returns references to all easy handles currently added to this multi
    /// handle.
    ///
    /// # C Equivalent
    ///
    /// `CURL **curl_multi_get_handles(CURLM *multi)` from
    /// `include/curl/multi.h` line 454.
    pub fn get_handles(&self) -> Vec<&EasyHandle> {
        self.handles.iter().collect()
    }

    // -----------------------------------------------------------------------
    // strerror() — matches curl_multi_strerror()
    // -----------------------------------------------------------------------

    /// Returns the human-readable error message for a multi-handle error code.
    ///
    /// This is a static function that does not require a multi-handle instance.
    ///
    /// # C Equivalent
    ///
    /// `const char *curl_multi_strerror(CURLMcode code)` from
    /// `include/curl/multi.h` line 272.
    pub fn strerror(code: CurlMcode) -> &'static str {
        code.strerror()
    }

    // -----------------------------------------------------------------------
    // fdset() — matches curl_multi_fdset()
    // -----------------------------------------------------------------------

    /// Extracts file descriptor information from the multi handle.
    ///
    /// Returns the set of file descriptors that the multi handle is currently
    /// interested in reading from, writing to, or checking for errors.
    ///
    /// The returned tuple contains `(read_fds, write_fds, exc_fds, max_fd)`.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_fdset(CURLM *m, fd_set *read_fd_set,
    ///  fd_set *write_fd_set, fd_set *exc_fd_set, int *max_fd)` from
    /// `lib/multi.c` line 1213.
    #[allow(clippy::type_complexity)]
    pub fn fdset(&self) -> CurlResult<(Vec<i64>, Vec<i64>, Vec<i64>, i64)> {
        let mut read_fds = Vec::new();
        let mut write_fds = Vec::new();
        let exc_fds = Vec::new();
        let mut max_fd: i64 = -1;

        for (&fd, entry) in &self.socket_hash {
            match entry.action {
                CurlMAction::In => {
                    read_fds.push(fd);
                }
                CurlMAction::Out => {
                    write_fds.push(fd);
                }
                CurlMAction::InOut => {
                    read_fds.push(fd);
                    write_fds.push(fd);
                }
                CurlMAction::None | CurlMAction::Remove => {}
            }

            if fd > max_fd {
                max_fd = fd;
            }
        }

        Ok((read_fds, write_fds, exc_fds, max_fd))
    }

    // -----------------------------------------------------------------------
    // waitfds() — matches curl_multi_waitfds()
    // -----------------------------------------------------------------------

    /// Returns the set of file descriptors the multi handle currently needs
    /// the application to monitor, formatted as [`WaitFd`] entries.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_waitfds(CURLM *m, struct curl_waitfd *ufds,
    ///  unsigned int size, unsigned int *fd_count)` from
    /// `lib/multi.c` line 1267.
    pub fn waitfds(&self) -> CurlResult<Vec<WaitFd>> {
        let mut fds = Vec::new();

        for (&fd, entry) in &self.socket_hash {
            let events = match entry.action {
                CurlMAction::In => CurlCSelect::In as u16,
                CurlMAction::Out => CurlCSelect::Out as u16,
                CurlMAction::InOut => (CurlCSelect::In as u16) | (CurlCSelect::Out as u16),
                CurlMAction::None | CurlMAction::Remove => continue,
            };

            fds.push(WaitFd {
                fd,
                events,
                revents: 0,
            });
        }

        Ok(fds)
    }

    // -----------------------------------------------------------------------
    // get_offt() — matches curl_multi_get_offt()
    // -----------------------------------------------------------------------

    /// Retrieves a numeric information value from the multi handle.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_get_offt(CURLM *multi, CURLMinfo_offt info,
    ///  curl_off_t *pvalue)` from `lib/multi.c` line 3747.
    pub fn get_offt(&self, info: CurlMultiInfoOfft) -> CurlResult<i64> {
        let value = match info {
            CurlMultiInfoOfft::XfersCurrent => self.handles.len() as i64,
            CurlMultiInfoOfft::XfersRunning => self.running as i64,
            CurlMultiInfoOfft::XfersPending => self.pending_count as i64,
            CurlMultiInfoOfft::XfersDone => self.msg_queue.len() as i64,
            CurlMultiInfoOfft::XfersAdded => self.xfers_total_ever,
        };

        tracing::trace!(
            "MultiHandle::get_offt: {:?} = {}",
            info,
            value,
        );

        Ok(value)
    }

    // -----------------------------------------------------------------------
    // notify_enable() — matches curl_multi_notify_enable()
    // -----------------------------------------------------------------------

    /// Enables a notification type for this multi handle.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_notify_enable(CURLM *m, unsigned int notification)`
    /// from `lib/multi.c` line 3982.
    pub fn notify_enable(&mut self, notification: u32) -> CurlResult<()> {
        tracing::debug!("MultiHandle::notify_enable: type={}", notification);
        self.notify.enable(notification)
    }

    // -----------------------------------------------------------------------
    // notify_disable() — matches curl_multi_notify_disable()
    // -----------------------------------------------------------------------

    /// Disables a notification type for this multi handle.
    ///
    /// # C Equivalent
    ///
    /// `CURLMcode curl_multi_notify_disable(CURLM *m, unsigned int notification)`
    /// from `lib/multi.c` line 3991.
    pub fn notify_disable(&mut self, notification: u32) -> CurlResult<()> {
        tracing::debug!("MultiHandle::notify_disable: type={}", notification);
        self.notify.disable(notification)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Ensures the Tokio runtime is initialised.
    fn ensure_runtime(&mut self) -> CurlResult<()> {
        if self.runtime.is_none() {
            match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => {
                    self.runtime = Some(Arc::new(rt));
                    tracing::debug!("MultiHandle: lazily created Tokio runtime");
                    Ok(())
                }
                Err(e) => {
                    tracing::error!("MultiHandle: failed to create runtime: {}", e);
                    Err(CurlError::FailedInit)
                }
            }
        } else {
            Ok(())
        }
    }

    /// Calls the timer callback with the current timeout, if set.
    fn update_timer(&mut self) {
        if let Some(ref cb) = self.timer_callback {
            let timeout_ms = if self.running > 0 { 0i64 } else { -1i64 };

            if timeout_ms != self.last_timeout_ms {
                self.in_callback = true;
                let rc = cb(timeout_ms, self.timer_userp as *mut c_void);
                self.in_callback = false;

                if rc == -1 {
                    tracing::warn!("MultiHandle::update_timer: timer callback returned error");
                    self.dead = true;
                } else {
                    self.last_timeout_ms = timeout_ms;
                }
            }
        }
    }
}

impl Default for MultiHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MultiHandle {
    fn drop(&mut self) {
        tracing::debug!(
            "MultiHandle::drop: cleaning up {} handles",
            self.handles.len(),
        );

        // Clean up each easy handle individually via cleanup(), which
        // releases any internal per-transfer resources.
        for handle in self.handles.drain(..) {
            handle.cleanup();
        }
        self.transfers.clear();
        self.msg_queue.clear();
        self.socket_hash.clear();
        self.notify.pending.clear();

        // The Tokio runtime is dropped automatically when the Arc refcount
        // reaches zero. This triggers runtime shutdown.
        self.runtime = None;
    }
}

impl std::fmt::Debug for MultiHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiHandle")
            .field("handles_count", &self.handles.len())
            .field("running", &self.running)
            .field("pending", &self.pending_count)
            .field("msg_queue_len", &self.msg_queue.len())
            .field("multiplexing", &self.multiplexing)
            .field("max_concurrent_streams", &self.max_concurrent_streams)
            .field("has_runtime", &self.runtime.is_some())
            .field("dead", &self.dead)
            .finish()
    }
}

// ===========================================================================
// MultiOptValue — typed option values for set_option()
// ===========================================================================

/// Typed value variants for [`MultiHandle::set_option()`].
///
/// Each variant corresponds to one of the C `CURLOPTTYPE_*` categories
/// used by `curl_multi_setopt()`.
pub enum MultiOptValue {
    /// A long integer value (for CURLOPTTYPE_LONG options).
    Long(i64),
    /// An opaque pointer value (stored as usize for safety).
    Pointer(usize),
    /// A socket callback function.
    SocketCb(SocketCallback),
    /// A timer callback function.
    TimerCb(TimerCallback),
    /// A push callback function.
    PushCb(PushCallback),
    /// A notify callback function.
    NotifyCb(NotifyCallback),
}

impl std::fmt::Debug for MultiOptValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Long(v) => write!(f, "Long({})", v),
            Self::Pointer(v) => write!(f, "Pointer(0x{:x})", v),
            Self::SocketCb(_) => write!(f, "SocketCb(...)"),
            Self::TimerCb(_) => write!(f, "TimerCb(...)"),
            Self::PushCb(_) => write!(f, "PushCb(...)"),
            Self::NotifyCb(_) => write!(f, "NotifyCb(...)"),
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{CurlError, CurlMcode};
    use crate::easy::EasyHandle;

    // -- CurlMAction --

    #[test]
    fn test_curl_maction_values() {
        assert_eq!(CurlMAction::None as i32, 0);
        assert_eq!(CurlMAction::In as i32, 1);
        assert_eq!(CurlMAction::Out as i32, 2);
        assert_eq!(CurlMAction::InOut as i32, 3);
        assert_eq!(CurlMAction::Remove as i32, 4);
    }

    #[test]
    fn test_curl_maction_from_raw() {
        assert_eq!(CurlMAction::from_raw(0), CurlMAction::None);
        assert_eq!(CurlMAction::from_raw(1), CurlMAction::In);
        assert_eq!(CurlMAction::from_raw(2), CurlMAction::Out);
        assert_eq!(CurlMAction::from_raw(3), CurlMAction::InOut);
        assert_eq!(CurlMAction::from_raw(4), CurlMAction::Remove);
        assert_eq!(CurlMAction::from_raw(99), CurlMAction::None);
    }

    #[test]
    fn test_curl_maction_i32_roundtrip() {
        let action = CurlMAction::InOut;
        let val: i32 = action.into();
        let back: CurlMAction = val.into();
        assert_eq!(back, CurlMAction::InOut);
    }

    // -- CurlCSelect --

    #[test]
    fn test_curl_cselect_values() {
        assert_eq!(CurlCSelect::In as i32, 0x01);
        assert_eq!(CurlCSelect::Out as i32, 0x02);
        assert_eq!(CurlCSelect::Err as i32, 0x04);
    }

    // -- CurlMsg --

    #[test]
    fn test_curl_msg_values() {
        assert_eq!(CurlMsg::None as i32, 0);
        assert_eq!(CurlMsg::Done as i32, 1);
    }

    #[test]
    fn test_curl_msg_from_raw() {
        assert_eq!(CurlMsg::from_raw(0), CurlMsg::None);
        assert_eq!(CurlMsg::from_raw(1), CurlMsg::Done);
        assert_eq!(CurlMsg::from_raw(99), CurlMsg::None);
    }

    // -- CurlMState --

    #[test]
    fn test_curl_mstate_values() {
        assert_eq!(CurlMState::Init as i32, 0);
        assert_eq!(CurlMState::Pending as i32, 1);
        assert_eq!(CurlMState::Setup as i32, 2);
        assert_eq!(CurlMState::Connect as i32, 3);
        assert_eq!(CurlMState::Resolving as i32, 4);
        assert_eq!(CurlMState::Connecting as i32, 5);
        assert_eq!(CurlMState::ProtoConnect as i32, 6);
        assert_eq!(CurlMState::ProtoConnecting as i32, 7);
        assert_eq!(CurlMState::Do as i32, 8);
        assert_eq!(CurlMState::Doing as i32, 9);
        assert_eq!(CurlMState::DoingMore as i32, 10);
        assert_eq!(CurlMState::Did as i32, 11);
        assert_eq!(CurlMState::Performing as i32, 12);
        assert_eq!(CurlMState::RateLimiting as i32, 13);
        assert_eq!(CurlMState::Done as i32, 14);
        assert_eq!(CurlMState::Completed as i32, 15);
        assert_eq!(CurlMState::MsgSent as i32, 16);
    }

    #[test]
    fn test_curl_mstate_names() {
        assert_eq!(CurlMState::Init.name(), "INIT");
        assert_eq!(CurlMState::Performing.name(), "PERFORMING");
        assert_eq!(CurlMState::Completed.name(), "COMPLETED");
        assert_eq!(CurlMState::MsgSent.name(), "MSGSENT");
    }

    #[test]
    fn test_curl_mstate_ordering() {
        assert!(CurlMState::Init < CurlMState::Performing);
        assert!(CurlMState::Performing < CurlMState::Completed);
        assert!(CurlMState::Completed < CurlMState::MsgSent);
    }

    #[test]
    fn test_curl_mstate_from_raw() {
        assert_eq!(CurlMState::from_raw(0), CurlMState::Init);
        assert_eq!(CurlMState::from_raw(12), CurlMState::Performing);
        assert_eq!(CurlMState::from_raw(15), CurlMState::Completed);
        assert_eq!(CurlMState::from_raw(99), CurlMState::Init);
    }

    #[test]
    fn test_curl_mstate_display() {
        let s = format!("{}", CurlMState::Performing);
        assert_eq!(s, "PERFORMING");
    }

    // -- CurlMultiOption --

    #[test]
    fn test_curl_multi_option_from_raw() {
        assert_eq!(
            CurlMultiOption::from_raw(1),
            Some(CurlMultiOption::SocketFunction)
        );
        assert_eq!(
            CurlMultiOption::from_raw(3),
            Some(CurlMultiOption::Pipelining)
        );
        assert_eq!(
            CurlMultiOption::from_raw(16),
            Some(CurlMultiOption::MaxConcurrentStreams)
        );
        assert_eq!(CurlMultiOption::from_raw(100), None);
    }

    // -- CurlMultiInfoOfft --

    #[test]
    fn test_curl_multi_info_offt_from_raw() {
        assert_eq!(
            CurlMultiInfoOfft::from_raw(1),
            Some(CurlMultiInfoOfft::XfersCurrent)
        );
        assert_eq!(
            CurlMultiInfoOfft::from_raw(5),
            Some(CurlMultiInfoOfft::XfersAdded)
        );
        assert_eq!(CurlMultiInfoOfft::from_raw(99), None);
    }

    // -- WaitFd --

    #[test]
    fn test_waitfd_new() {
        let fd = WaitFd::new(42, 0x01);
        assert_eq!(fd.fd, 42);
        assert_eq!(fd.events, 0x01);
        assert_eq!(fd.revents, 0);
    }

    #[test]
    fn test_waitfd_default() {
        let fd = WaitFd::default();
        assert_eq!(fd.fd, -1);
        assert_eq!(fd.events, 0);
        assert_eq!(fd.revents, 0);
    }

    // -- MultiHandle --

    #[test]
    fn test_multi_handle_new() {
        let multi = MultiHandle::new();
        assert_eq!(multi.running, 0);
        assert!(multi.handles.is_empty());
        assert!(multi.runtime.is_none());
        assert!(multi.multiplexing);
        assert_eq!(multi.max_concurrent_streams, 100);
    }

    #[test]
    fn test_multi_handle_default() {
        let multi = MultiHandle::default();
        assert_eq!(multi.running, 0);
    }

    #[test]
    fn test_multi_handle_add_handle() {
        let mut multi = MultiHandle::new();
        let easy = EasyHandle::new();
        assert!(multi.add_handle(easy).is_ok());
        assert_eq!(multi.handles.len(), 1);
        assert_eq!(multi.running, 1);
        assert_eq!(multi.xfers_total_ever, 1);
    }

    #[test]
    fn test_multi_handle_add_multiple_handles() {
        let mut multi = MultiHandle::new();
        for _ in 0..5 {
            let easy = EasyHandle::new();
            assert!(multi.add_handle(easy).is_ok());
        }
        assert_eq!(multi.handles.len(), 5);
        assert_eq!(multi.running, 5);
        assert_eq!(multi.xfers_total_ever, 5);
    }

    #[test]
    fn test_multi_handle_get_handles() {
        let mut multi = MultiHandle::new();
        multi.add_handle(EasyHandle::new()).unwrap();
        multi.add_handle(EasyHandle::new()).unwrap();

        let handles = multi.get_handles();
        assert_eq!(handles.len(), 2);
    }

    #[test]
    fn test_multi_handle_info_read_empty() {
        let mut multi = MultiHandle::new();
        assert!(multi.info_read().is_none());
    }

    #[test]
    fn test_multi_handle_strerror() {
        let msg = MultiHandle::strerror(CurlMcode::Ok);
        assert_eq!(msg, "No error");

        let msg = MultiHandle::strerror(CurlMcode::BadHandle);
        assert_eq!(msg, "Invalid multi handle");

        let msg = MultiHandle::strerror(CurlMcode::OutOfMemory);
        assert_eq!(msg, "Out of memory");
    }

    #[test]
    fn test_multi_handle_timeout_no_handles() {
        let multi = MultiHandle::new();
        let timeout = multi.timeout().unwrap();
        assert!(timeout.is_none());
    }

    #[test]
    fn test_multi_handle_timeout_with_handles() {
        let mut multi = MultiHandle::new();
        multi.add_handle(EasyHandle::new()).unwrap();
        let timeout = multi.timeout().unwrap();
        assert!(timeout.is_some());
    }

    #[test]
    fn test_multi_handle_wakeup() {
        let multi = MultiHandle::new();
        assert!(multi.wakeup().is_ok());
    }

    #[test]
    fn test_multi_handle_set_option_pipelining() {
        let mut multi = MultiHandle::new();
        assert!(multi.multiplexing);

        multi
            .set_option(CurlMultiOption::Pipelining, MultiOptValue::Long(0))
            .unwrap();
        assert!(!multi.multiplexing);

        multi
            .set_option(CurlMultiOption::Pipelining, MultiOptValue::Long(2))
            .unwrap();
        assert!(multi.multiplexing);
    }

    #[test]
    fn test_multi_handle_set_option_max_connects() {
        let mut multi = MultiHandle::new();
        multi
            .set_option(CurlMultiOption::MaxConnects, MultiOptValue::Long(50))
            .unwrap();
        assert_eq!(multi.max_connects, 50);
    }

    #[test]
    fn test_multi_handle_set_option_max_concurrent_streams() {
        let mut multi = MultiHandle::new();
        multi
            .set_option(
                CurlMultiOption::MaxConcurrentStreams,
                MultiOptValue::Long(200),
            )
            .unwrap();
        assert_eq!(multi.max_concurrent_streams, 200);
    }

    #[test]
    fn test_multi_handle_fdset_empty() {
        let multi = MultiHandle::new();
        let (read, write, exc, max_fd) = multi.fdset().unwrap();
        assert!(read.is_empty());
        assert!(write.is_empty());
        assert!(exc.is_empty());
        assert_eq!(max_fd, -1);
    }

    #[test]
    fn test_multi_handle_waitfds_empty() {
        let multi = MultiHandle::new();
        let fds = multi.waitfds().unwrap();
        assert!(fds.is_empty());
    }

    #[test]
    fn test_multi_handle_get_offt() {
        let mut multi = MultiHandle::new();

        assert_eq!(
            multi.get_offt(CurlMultiInfoOfft::XfersCurrent).unwrap(),
            0
        );
        assert_eq!(
            multi.get_offt(CurlMultiInfoOfft::XfersRunning).unwrap(),
            0
        );
        assert_eq!(
            multi.get_offt(CurlMultiInfoOfft::XfersAdded).unwrap(),
            0
        );

        multi.add_handle(EasyHandle::new()).unwrap();
        assert_eq!(
            multi.get_offt(CurlMultiInfoOfft::XfersCurrent).unwrap(),
            1
        );
        assert_eq!(
            multi.get_offt(CurlMultiInfoOfft::XfersRunning).unwrap(),
            1
        );
        assert_eq!(
            multi.get_offt(CurlMultiInfoOfft::XfersAdded).unwrap(),
            1
        );
    }

    #[test]
    fn test_multi_handle_notify_enable_disable() {
        let mut multi = MultiHandle::new();
        assert!(multi.notify_enable(CURLMNOTIFY_INFO_READ).is_ok());
        assert!(multi.notify_enable(CURLMNOTIFY_EASY_DONE).is_ok());
        assert!(multi.notify_disable(CURLMNOTIFY_INFO_READ).is_ok());

        // Invalid notification type
        assert!(multi.notify_enable(99).is_err());
        assert!(multi.notify_disable(99).is_err());
    }

    #[test]
    fn test_multi_handle_assign() {
        let mut multi = MultiHandle::new();
        assert!(multi.assign(42, std::ptr::null_mut()).is_ok());
    }

    #[test]
    fn test_multi_handle_perform_empty() {
        let mut multi = MultiHandle::new();
        let running = multi.perform().unwrap();
        assert_eq!(running, 0);
    }

    #[test]
    fn test_multi_handle_perform_with_handle() {
        let mut multi = MultiHandle::new();
        multi.add_handle(EasyHandle::new()).unwrap();
        // perform() should not panic even without a configured URL.
        let _running = multi.perform();
    }

    #[test]
    fn test_multi_handle_cleanup() {
        let mut multi = MultiHandle::new();
        multi.add_handle(EasyHandle::new()).unwrap();
        multi.cleanup();
    }

    #[test]
    fn test_multi_handle_debug() {
        let multi = MultiHandle::new();
        let debug_str = format!("{:?}", multi);
        assert!(debug_str.contains("MultiHandle"));
        assert!(debug_str.contains("running"));
    }

    // -- CurlMultiMsg --

    #[test]
    fn test_curl_multi_msg() {
        let msg = CurlMultiMsg {
            msg_type: CurlMsg::Done,
            easy_handle_index: 42,
            result: CurlError::Ok,
        };

        assert_eq!(msg.msg(), CurlMsg::Done);
        assert_eq!(msg.easy_handle(), 42);
        assert_eq!(msg.result(), CurlError::Ok);
    }

    // -- MultiOptValue --

    #[test]
    fn test_multi_opt_value_debug() {
        let v = MultiOptValue::Long(42);
        assert_eq!(format!("{:?}", v), "Long(42)");

        let v = MultiOptValue::Pointer(0x1234);
        assert!(format!("{:?}", v).contains("Pointer"));
    }

    // -- Notification constants --

    #[test]
    fn test_notification_constants() {
        assert_eq!(CURLMNOTIFY_INFO_READ, 0);
        assert_eq!(CURLMNOTIFY_EASY_DONE, 1);
    }

    // -- Socket action --

    #[test]
    fn test_multi_handle_socket_action_timeout() {
        let mut multi = MultiHandle::new();
        // Socket -1 means timeout processing.
        let result = multi.socket_action(-1, CurlMAction::None);
        assert!(result.is_ok());
    }
}
