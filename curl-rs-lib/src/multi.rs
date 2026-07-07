// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! # `multi` — the multi-interface state machine (`MSTATE`)
//!
//! A language rewrite of curl 8.19.0-DEV's multi interface, fusing three C
//! translation units into one idiomatic-Rust module:
//!
//! * `lib/multi.c`      — the `MSTATE` machine, the `curl_multi_*` API surface,
//!   the per-transfer driver (`multi_runsingle`) and the crank (`multi_perform`).
//! * `lib/multi_ev.c`   — the socket/event bookkeeping that backs
//!   `CURLMOPT_SOCKETFUNCTION` / `CURLMOPT_TIMERFUNCTION`.
//! * `lib/multi_ntfy.c` — the notification queue delivered to
//!   `CURLMOPT_NOTIFYFUNCTION`.
//!
//! The multi interface drives many concurrent easy transfers, each stepped
//! through the identical [`MState`] machine curl uses. Per AAP §0.3.2 the multi
//! handle runs on the Tokio **multi-thread** runtime so independent transfers
//! progress in parallel (contrast the CLI easy path, which uses the
//! current-thread flavor).
//!
//! ## State-name preservation (AAP §0.3.2 / §0.6.3 / §0.7.3)
//!
//! The [`MState`] variant names and their integer order are preserved verbatim
//! from `lib/multihandle.h`, and [`MState::state_name`] returns the exact string
//! curl prints in `--trace` output (the `Curl_trc_mstate_names[]` table from
//! `lib/curl_trc.c`), so trace diagnostics remain byte-identical.
//!
//! ## Frozen ABI values
//!
//! [`CurlMCode`] (re-exported from [`crate::error`]), [`CurlMsg`],
//! [`CurlMOption`], and the `CURL_POLL_*` / `CURL_CSELECT_*` constants keep the
//! exact integer values from `include/curl/multi.h` — a consumer hard-coding
//! `CURLM_CALL_MULTI_PERFORM == -1` or `CURLMOPT_MAXCONNECTS == 6` keeps working.
//!
//! ## The transfer-driver seam
//!
//! curl's `multi_runsingle` calls into the connection layer and the protocol
//! handler vtable (`conn->handler->connect_it` / `do_it` / `done`, the transfer
//! pump) at each state. Those layers (the `conn` subtree and the concrete
//! protocol handlers) are introduced in later checkpoints; this module therefore
//! expresses that vtable as the object-safe [`TransferDriver`] trait, exactly the
//! dependency-inversion curl performs with function pointers. The
//! [`TransferDriver::perform`] hook returns a [`crate::transfer::TransferOutcome`],
//! so the state machine consumes the transfer core's result vocabulary to decide
//! transitions (finish, follow a redirect, or park a paused transfer). A
//! production driver wires the hook onto [`crate::transfer::Transfer`]; the tests
//! in this module drive it with in-process mock transfers.
//!
//! This module contains **zero `unsafe`** (enforced crate-wide by
//! `#![forbid(unsafe_code)]` in `lib.rs`).

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use tokio::runtime::{Builder, Handle, Runtime};
use tokio::sync::Notify;
use tokio::task::JoinSet;

use crate::error::CurlCode;
use crate::request::SingleRequest;
use crate::transfer::TransferOutcome;

/// The multi-interface result code. Re-exported from [`crate::error`] where it
/// is defined once with the frozen `include/curl/multi.h` integer values
/// (`CURLM_CALL_MULTI_PERFORM = -1`, `CURLM_OK = 0`, … `CURLM_UNRECOVERABLE_POLL
/// = 12`), so the multi module and the FFI layer agree on a single definition.
pub use crate::error::CurlMCode;

/// Shorthand for the fallible-future return type of the [`TransferDriver`]
/// hooks. Using a named alias keeps the trait signatures readable and avoids the
/// `clippy::type_complexity` lint on the boxed-future type.
type DriverFuture<'a, T> = BoxFuture<'a, crate::error::Result<T>>;

// ===========================================================================
// Frozen socket / poll / pipelining ABI constants (`include/curl/multi.h`).
// ===========================================================================

/// A platform socket handle, mirroring curl's `curl_socket_t`. On the four
/// supported targets (Linux/macOS, x86_64/aarch64) `curl_socket_t` is a C `int`;
/// we model it as [`i32`] and reserve `-1` as the invalid sentinel.
pub type Socket = i32;

/// `CURL_SOCKET_BAD` — the invalid-socket sentinel (`(curl_socket_t)-1`).
pub const CURL_SOCKET_BAD: Socket = -1;

/// `CURL_SOCKET_TIMEOUT` — passed to [`Multi::socket_action`] to run the timeout
/// machinery rather than a specific socket's readiness. Aliases
/// [`CURL_SOCKET_BAD`], exactly as `include/curl/multi.h` defines it.
pub const CURL_SOCKET_TIMEOUT: Socket = CURL_SOCKET_BAD;

/// `CURL_POLL_NONE` — the socket is registered but currently uninteresting.
pub const CURL_POLL_NONE: i32 = 0;
/// `CURL_POLL_IN` — libcurl wants to read from the socket.
pub const CURL_POLL_IN: i32 = 1;
/// `CURL_POLL_OUT` — libcurl wants to write to the socket.
pub const CURL_POLL_OUT: i32 = 2;
/// `CURL_POLL_INOUT` — libcurl wants both read and write readiness.
pub const CURL_POLL_INOUT: i32 = 3;
/// `CURL_POLL_REMOVE` — the socket is no longer used; drop it from the poll set.
pub const CURL_POLL_REMOVE: i32 = 4;

/// `CURL_CSELECT_IN` — the application reports the socket is readable.
pub const CURL_CSELECT_IN: i32 = 0x01;
/// `CURL_CSELECT_OUT` — the application reports the socket is writable.
pub const CURL_CSELECT_OUT: i32 = 0x02;
/// `CURL_CSELECT_ERR` — the application reports an error on the socket.
pub const CURL_CSELECT_ERR: i32 = 0x04;

/// `CURL_WAIT_POLLIN` — `curl_waitfd` read-readiness request bit.
pub const CURL_WAIT_POLLIN: i16 = 0x0001;
/// `CURL_WAIT_POLLPRI` — `curl_waitfd` priority (out-of-band) request bit.
pub const CURL_WAIT_POLLPRI: i16 = 0x0002;
/// `CURL_WAIT_POLLOUT` — `curl_waitfd` write-readiness request bit.
pub const CURL_WAIT_POLLOUT: i16 = 0x0004;

/// `CURLPIPE_NOTHING` — no multiplexing (`CURLMOPT_PIPELINING`).
pub const CURLPIPE_NOTHING: i64 = 0;
/// `CURLPIPE_HTTP1` — the historical (now no-op) HTTP/1 pipelining bit.
pub const CURLPIPE_HTTP1: i64 = 1;
/// `CURLPIPE_MULTIPLEX` — allow HTTP/2 (and HTTP/3) stream multiplexing.
pub const CURLPIPE_MULTIPLEX: i64 = 2;

/// `CURLMNWC_CLEAR_CONNS` — the `CURLMOPT_NETWORK_CHANGED` bit that prevents
/// further reuse of existing connections (idle ones are closed).
pub const CURLMNWC_CLEAR_CONNS: i64 = 1 << 0;
/// `CURLMNWC_CLEAR_DNS` — the `CURLMOPT_NETWORK_CHANGED` bit that flushes the
/// DNS cache. (Shares the value of [`CURLMNWC_CLEAR_CONNS`], per `multi.h`.)
pub const CURLMNWC_CLEAR_DNS: i64 = 1 << 0;

/// `CURLMNOTIFY_INFO_READ` — notification type: a message became readable via
/// [`Multi::info_read`].
pub const CURLMNOTIFY_INFO_READ: u32 = 0;
/// `CURLMNOTIFY_EASY_DONE` — notification type: an easy handle finished.
pub const CURLMNOTIFY_EASY_DONE: u32 = 1;

// ===========================================================================
// MSTATE — the per-transfer state machine (`lib/multihandle.h` `CURLMstate`).
// ===========================================================================

/// The state of a single transfer inside the multi handle — the exact rewrite
/// of curl's `CURLMstate` enum (`lib/multihandle.h`).
///
/// The variant order and integer discriminants are preserved verbatim: `Init`
/// is `0` and each subsequent variant increments by one through `Msgsent`
/// (`16`), with `Last` (`17`) as the never-a-real-state sentinel curl documents.
/// This ordering matters — curl's `multi_runsingle` performs relational
/// comparisons such as `mstate < MSTATE_DONE`, which [`MState`]'s derived
/// [`Ord`] reproduces.
///
/// [`state_name`](MState::state_name) returns the precise `--trace` string from
/// `Curl_trc_mstate_names[]` (`lib/curl_trc.c`), guaranteeing trace parity.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MState {
    /// `MSTATE_INIT` (0) — transitional start state; a handle never returns here.
    Init = 0,
    /// `MSTATE_PENDING` — no connection available yet; waiting for one.
    Pending,
    /// `MSTATE_SETUP` — set up a new transfer (re-entered on a redirect).
    Setup,
    /// `MSTATE_CONNECT` — resolve/connect has been initiated.
    Connect,
    /// `MSTATE_RESOLVING` — awaiting asynchronous name resolution.
    Resolving,
    /// `MSTATE_CONNECTING` — awaiting the TCP connect to finalize.
    Connecting,
    /// `MSTATE_PROTOCONNECT` — initiate the protocol-specific connect.
    Protoconnect,
    /// `MSTATE_PROTOCONNECTING` — completing the protocol-specific connect phase.
    Protoconnecting,
    /// `MSTATE_DO` — start sending the request (part 1).
    Do,
    /// `MSTATE_DOING` — sending the request (part 1).
    Doing,
    /// `MSTATE_DOING_MORE` — send the request (part 2). Traces as `DOING_MORE`.
    DoingMore,
    /// `MSTATE_DID` — done sending the request.
    Did,
    /// `MSTATE_PERFORMING` — transferring data.
    Performing,
    /// `MSTATE_RATELIMITING` — waiting because `--limit-rate` was exceeded.
    Ratelimiting,
    /// `MSTATE_DONE` — post-transfer operation.
    Done,
    /// `MSTATE_COMPLETED` — the operation is complete.
    Completed,
    /// `MSTATE_MSGSENT` — the completion message has been queued for the app.
    Msgsent,
    /// `MSTATE_LAST` — not a true state; never assigned to a live transfer.
    Last,
}

impl MState {
    /// Returns the state name exactly as curl prints it in `--trace` output,
    /// reproducing `Curl_trc_mstate_names[]` (`lib/curl_trc.c`). The sentinel
    /// [`MState::Last`] yields `"?"`, matching curl's out-of-range fallback in
    /// `Curl_trc_mstate_name`.
    #[must_use]
    pub const fn state_name(self) -> &'static str {
        match self {
            MState::Init => "INIT",
            MState::Pending => "PENDING",
            MState::Setup => "SETUP",
            MState::Connect => "CONNECT",
            MState::Resolving => "RESOLVING",
            MState::Connecting => "CONNECTING",
            MState::Protoconnect => "PROTOCONNECT",
            MState::Protoconnecting => "PROTOCONNECTING",
            MState::Do => "DO",
            MState::Doing => "DOING",
            MState::DoingMore => "DOING_MORE",
            MState::Did => "DID",
            MState::Performing => "PERFORMING",
            MState::Ratelimiting => "RATELIMITING",
            MState::Done => "DONE",
            MState::Completed => "COMPLETED",
            MState::Msgsent => "MSGSENT",
            MState::Last => "?",
        }
    }

    /// Returns the frozen integer discriminant of this state.
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        self as i32
    }

    /// All real states in machine order (`Init` … `Msgsent`), excluding the
    /// [`MState::Last`] sentinel. Used by the trace/state-name parity tests.
    #[must_use]
    pub const fn real_states() -> [MState; 17] {
        [
            MState::Init,
            MState::Pending,
            MState::Setup,
            MState::Connect,
            MState::Resolving,
            MState::Connecting,
            MState::Protoconnect,
            MState::Protoconnecting,
            MState::Do,
            MState::Doing,
            MState::DoingMore,
            MState::Did,
            MState::Performing,
            MState::Ratelimiting,
            MState::Done,
            MState::Completed,
            MState::Msgsent,
        ]
    }
}

impl fmt::Display for MState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.state_name())
    }
}

// ===========================================================================
// EasyId — the identity of a transfer within a multi handle (curl's `mid`).
// ===========================================================================

/// The identity a [`Multi`] assigns to an added [`EasyHandle`], mirroring curl's
/// per-transfer `mid` (`data->mid`). Ids are handed out monotonically starting
/// from `0` and never reused within a multi handle's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EasyId(pub u32);

impl fmt::Display for EasyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ===========================================================================
// CURLMSG / CURLMsg — the completed-transfer message (`include/curl/multi.h`).
// ===========================================================================

/// The kind of message read from the multi handle, mirroring the C `CURLMSG`
/// enum. Integer values are frozen: `None = 0`, `Done = 1`, `Last = 2`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlMsg {
    /// `CURLMSG_NONE` — first, unused.
    None = 0,
    /// `CURLMSG_DONE` — an easy handle completed; the result is meaningful.
    Done = 1,
    /// `CURLMSG_LAST` — last, unused sentinel.
    Last = 2,
}

impl CurlMsg {
    /// Returns the frozen integer value of this message kind.
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        self as i32
    }
}

/// A message extracted from the multi handle via [`Multi::info_read`], the
/// rewrite of the public `struct CURLMsg`. Because the only message curl emits
/// today is `CURLMSG_DONE`, [`result`](Message::result) carries the transfer's
/// final [`CurlCode`] (the C `data.result` union member).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    /// The message kind — always [`CurlMsg::Done`] in curl 8.x.
    pub msg: CurlMsg,
    /// The transfer this message concerns (the C `easy_handle` field, expressed
    /// as the stable [`EasyId`] rather than a raw pointer).
    pub easy: EasyId,
    /// The transfer's final result (the C `data.result` union member), valid
    /// when [`msg`](Message::msg) is [`CurlMsg::Done`].
    pub result: CurlCode,
}

// ===========================================================================
// CURLMoption — the multi-handle option ids (`include/curl/multi.h`).
// ===========================================================================

/// The `curl_multi_setopt` option identifiers, mirroring the C `CURLMoption`
/// enum. Integer values are frozen ABI (`CURLMOPT_SOCKETFUNCTION = 1` …
/// `CURLMOPT_NOTIFYDATA = 19`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlMOption {
    /// `CURLMOPT_SOCKETFUNCTION` (1) — the socket-status callback.
    SocketFunction = 1,
    /// `CURLMOPT_SOCKETDATA` (2) — user pointer for the socket callback.
    SocketData = 2,
    /// `CURLMOPT_PIPELINING` (3) — multiplexing bitmask ([`CURLPIPE_MULTIPLEX`]).
    Pipelining = 3,
    /// `CURLMOPT_TIMERFUNCTION` (4) — the timer callback.
    TimerFunction = 4,
    /// `CURLMOPT_TIMERDATA` (5) — user pointer for the timer callback.
    TimerData = 5,
    /// `CURLMOPT_MAXCONNECTS` (6) — connection-cache size hint.
    MaxConnects = 6,
    /// `CURLMOPT_MAX_HOST_CONNECTIONS` (7) — per-host connection cap.
    MaxHostConnections = 7,
    /// `CURLMOPT_MAX_PIPELINE_LENGTH` (8) — legacy pipelining option (no-op).
    MaxPipelineLength = 8,
    /// `CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE` (9) — legacy pipelining (no-op).
    ContentLengthPenaltySize = 9,
    /// `CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE` (10) — legacy pipelining (no-op).
    ChunkLengthPenaltySize = 10,
    /// `CURLMOPT_PIPELINING_SITE_BL` (11) — legacy pipelining (no-op).
    PipeliningSiteBl = 11,
    /// `CURLMOPT_PIPELINING_SERVER_BL` (12) — legacy pipelining (no-op).
    PipeliningServerBl = 12,
    /// `CURLMOPT_MAX_TOTAL_CONNECTIONS` (13) — overall connection cap.
    MaxTotalConnections = 13,
    /// `CURLMOPT_PUSHFUNCTION` (14) — HTTP/2 server-push callback.
    PushFunction = 14,
    /// `CURLMOPT_PUSHDATA` (15) — user pointer for the push callback.
    PushData = 15,
    /// `CURLMOPT_MAX_CONCURRENT_STREAMS` (16) — HTTP/2 stream limit hint.
    MaxConcurrentStreams = 16,
    /// `CURLMOPT_NETWORK_CHANGED` (17) — react to a network change ([`CURLMNWC_CLEAR_CONNS`]).
    NetworkChanged = 17,
    /// `CURLMOPT_NOTIFYFUNCTION` (18) — the notification callback.
    NotifyFunction = 18,
    /// `CURLMOPT_NOTIFYDATA` (19) — user pointer for the notification callback.
    NotifyData = 19,
}

impl CurlMOption {
    /// Returns the frozen integer value of this option id.
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for CurlMOption {
    /// The rejected integer is returned unchanged on failure so the caller can
    /// surface [`CurlMCode::UnknownOption`].
    type Error = i32;

    fn try_from(value: i32) -> core::result::Result<CurlMOption, i32> {
        let opt = match value {
            1 => CurlMOption::SocketFunction,
            2 => CurlMOption::SocketData,
            3 => CurlMOption::Pipelining,
            4 => CurlMOption::TimerFunction,
            5 => CurlMOption::TimerData,
            6 => CurlMOption::MaxConnects,
            7 => CurlMOption::MaxHostConnections,
            8 => CurlMOption::MaxPipelineLength,
            9 => CurlMOption::ContentLengthPenaltySize,
            10 => CurlMOption::ChunkLengthPenaltySize,
            11 => CurlMOption::PipeliningSiteBl,
            12 => CurlMOption::PipeliningServerBl,
            13 => CurlMOption::MaxTotalConnections,
            14 => CurlMOption::PushFunction,
            15 => CurlMOption::PushData,
            16 => CurlMOption::MaxConcurrentStreams,
            17 => CurlMOption::NetworkChanged,
            18 => CurlMOption::NotifyFunction,
            19 => CurlMOption::NotifyData,
            other => return Err(other),
        };
        Ok(opt)
    }
}

/// A value supplied to [`Multi::setopt`] for the numeric multi options,
/// standing in for C's `va_arg`-typed argument. Callback and pointer options
/// are set through the dedicated typed setters
/// ([`Multi::set_socket_function`], [`Multi::set_timer_function`],
/// [`Multi::set_notify_function`], [`Multi::set_push_function`]) rather than
/// through this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiOptionValue {
    /// A `long`-typed option value (e.g. [`CurlMOption::MaxConnects`]).
    Long(i64),
    /// A `curl_off_t`-typed option value (the legacy penalty-size options).
    OffT(i64),
}

// ===========================================================================
// CURLMinfo_offt — the `curl_multi_get_offt` information ids.
// ===========================================================================

/// The `curl_multi_get_offt` information selectors, mirroring the C
/// `CURLMinfo_offt` enum. Integer values are frozen (`XFERS_CURRENT = 1` …
/// `XFERS_ADDED = 5`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlMInfo {
    /// `CURLMINFO_XFERS_CURRENT` (1) — handles added but not yet removed.
    XfersCurrent = 1,
    /// `CURLMINFO_XFERS_RUNNING` (2) — handles running (not done, not queued).
    XfersRunning = 2,
    /// `CURLMINFO_XFERS_PENDING` (3) — handles waiting to start.
    XfersPending = 3,
    /// `CURLMINFO_XFERS_DONE` (4) — finished handles awaiting `info_read`.
    XfersDone = 4,
    /// `CURLMINFO_XFERS_ADDED` (5) — total handles ever added.
    XfersAdded = 5,
}

// ===========================================================================
// Application callback hook points (Rust-native forms of the C callbacks).
// ===========================================================================

/// The socket-status callback (`CURLMOPT_SOCKETFUNCTION`). Invoked with the
/// transfer, the socket, the desired action ([`CURL_POLL_IN`] /
/// [`CURL_POLL_OUT`] / [`CURL_POLL_INOUT`] / [`CURL_POLL_REMOVE`]), and the
/// per-socket application token previously set with [`Multi::assign`] (curl's
/// `socketp`, `None` when unassigned) whenever the multi handle's interest in a
/// socket changes. Returning non-zero signals an application error, mirroring
/// the C callback's `int` return.
pub type SocketCallback = Box<dyn FnMut(EasyId, Socket, i32, Option<usize>) -> i32 + Send>;

/// The timer callback (`CURLMOPT_TIMERFUNCTION`). Receives the number of
/// milliseconds the application may wait before it must call
/// [`Multi::socket_action`] again; `-1` means "no timeout, delete any timer".
pub type TimerCallback = Box<dyn FnMut(i64) -> i32 + Send>;

/// The notification callback (`CURLMOPT_NOTIFYFUNCTION`). Receives the
/// notification type ([`CURLMNOTIFY_EASY_DONE`]) and the transfer it concerns.
pub type NotifyCallback = Box<dyn FnMut(u32, EasyId) + Send>;

/// The HTTP/2 server-push callback (`CURLMOPT_PUSHFUNCTION`). Receives the
/// parent transfer; a non-zero return declines the pushed stream.
pub type PushCallback = Box<dyn FnMut(EasyId) -> i32 + Send>;

// ===========================================================================
// Transfer-driver seam — the Rust form of curl's `conn->handler` vtable.
// ===========================================================================

/// Outcome of the [`MState::Connect`] step (curl's `state_connect`): where the
/// transfer goes after connection setup is initiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// Asynchronous name resolution started → [`MState::Resolving`].
    Resolving,
    /// A socket connect is in progress → [`MState::Connecting`].
    Connecting,
    /// The connection is ready (e.g. reused from the pool) →
    /// [`MState::Protoconnect`].
    Connected,
    /// No connection is available under the current limits →
    /// [`MState::Pending`].
    Pending,
}

/// Outcome of the [`MState::Resolving`] poll (curl's `state_resolving`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// Name resolution is still in progress → stay in [`MState::Resolving`].
    Resolving,
    /// Resolution finished; a socket connect is now needed →
    /// [`MState::Connecting`].
    Connecting,
    /// Resolution finished and the connection is already usable →
    /// [`MState::Protoconnect`].
    Connected,
}

/// Outcome of a connect-completion poll ([`MState::Connecting`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketConnectOutcome {
    /// The TCP connect is still completing → stay in [`MState::Connecting`].
    Connecting,
    /// The connection is established → [`MState::Protoconnect`].
    Connected,
}

/// Outcome of a protocol-connect step ([`MState::Protoconnect`] /
/// [`MState::Protoconnecting`], curl's `protocol_connect` / `protocol_connecting`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolConnectOutcome {
    /// The protocol handshake needs more round-trips →
    /// [`MState::Protoconnecting`].
    Connecting,
    /// The protocol handshake finished → [`MState::Do`].
    Connected,
}

/// Outcome of a step in the DO family ([`MState::Do`] / [`MState::Doing`] /
/// [`MState::DoingMore`], curl's `state_do` / `protocol_doing` / `multi_do_more`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoOutcome {
    /// Remain in the current DO-family state; more work is pending.
    Stay,
    /// Advance to [`MState::Doing`] (an asynchronous DO started).
    Doing,
    /// Advance to [`MState::DoingMore`] (the second DO phase).
    DoingMore,
    /// Advance to [`MState::Did`] (the DO phase is complete).
    Did,
    /// Skip straight to [`MState::Done`] (there is nothing to transfer).
    Done,
}

/// The result of one [`EasyHandle`] state-machine step, mirroring the control
/// flow of one iteration of curl's `multi_runsingle` inner loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// A transition occurred and more immediate work may be available; the
    /// driver crank should step again (curl's `CURLM_CALL_MULTI_PERFORM`).
    Progress,
    /// The transfer is waiting for an external event. `Some(d)` is a
    /// rate-limit / timer wait of duration `d`; `None` is an unbounded wait
    /// (e.g. a pending connection slot).
    Wait(Option<Duration>),
    /// Every active direction is paused by the application
    /// ([`TransferOutcome::Paused`]); resume on unpause.
    Paused,
    /// The transfer reached [`MState::Completed`] with this final result.
    Completed(CurlCode),
}

/// The protocol/transfer work a single easy transfer performs while the
/// [`Multi`] state machine drives it — the object-safe Rust form of curl's
/// `struct Curl_handler` function-pointer vtable (`connect_it` / `connecting` /
/// `do_it` / `doing` / `done`) plus the transfer pump.
///
/// Every hook has a default implementation modelling the trivial "already
/// ready" path, so a minimal driver need only override the phases it cares
/// about (typically just [`perform`](TransferDriver::perform)). The async hooks
/// return a [`BoxFuture`] rather than using `async fn` in the trait directly:
/// this keeps the trait **object-safe** (so a [`Multi`] can hold
/// `Box<dyn TransferDriver>` and mix protocols on one handle) while remaining
/// compatible with the crate's MSRV of 1.75.
///
/// Implementations must be `Send` (and `'static`) so a transfer can be moved
/// onto a Tokio worker thread for the multi handle's parallel execution.
pub trait TransferDriver: Send {
    /// [`MState::Connect`]: set up and initiate the connection. Defaults to
    /// [`ConnectOutcome::Connected`] (an immediately usable connection).
    fn connect(&mut self) -> DriverFuture<'_, ConnectOutcome> {
        Box::pin(async { Ok(ConnectOutcome::Connected) })
    }

    /// [`MState::Resolving`]: poll asynchronous name resolution. Defaults to
    /// [`ResolveOutcome::Connected`].
    fn resolving(&mut self) -> DriverFuture<'_, ResolveOutcome> {
        Box::pin(async { Ok(ResolveOutcome::Connected) })
    }

    /// [`MState::Connecting`]: poll the socket connect. Defaults to
    /// [`SocketConnectOutcome::Connected`].
    fn connecting(&mut self) -> DriverFuture<'_, SocketConnectOutcome> {
        Box::pin(async { Ok(SocketConnectOutcome::Connected) })
    }

    /// [`MState::Protoconnect`] / [`MState::Protoconnecting`]: run the
    /// protocol-specific handshake. `first` is `true` for the initiating
    /// `PROTOCONNECT` step and `false` for a continuing `PROTOCONNECTING` step.
    /// Defaults to [`ProtocolConnectOutcome::Connected`].
    fn protocol_connect(&mut self, first: bool) -> DriverFuture<'_, ProtocolConnectOutcome> {
        let _ = first;
        Box::pin(async { Ok(ProtocolConnectOutcome::Connected) })
    }

    /// [`MState::Do`]: begin sending the request. Defaults to [`DoOutcome::Did`]
    /// (the request was sent synchronously; proceed toward the transfer).
    fn do_request(&mut self) -> DriverFuture<'_, DoOutcome> {
        Box::pin(async { Ok(DoOutcome::Did) })
    }

    /// [`MState::Doing`]: continue sending the request. Defaults to
    /// [`DoOutcome::Did`].
    fn doing(&mut self) -> DriverFuture<'_, DoOutcome> {
        Box::pin(async { Ok(DoOutcome::Did) })
    }

    /// [`MState::DoingMore`]: run the second DO phase. Defaults to
    /// [`DoOutcome::Did`].
    fn do_more(&mut self) -> DriverFuture<'_, DoOutcome> {
        Box::pin(async { Ok(DoOutcome::Did) })
    }

    /// [`MState::Performing`]: run the transfer pump for this request and report
    /// the [`TransferOutcome`]. This is the hook a production driver wires onto
    /// [`crate::transfer::Transfer::perform`]. Defaults to
    /// [`TransferOutcome::Done`] (an empty, immediately-finished transfer).
    fn perform<'a>(&'a mut self, req: &'a mut SingleRequest) -> DriverFuture<'a, TransferOutcome> {
        let _ = req;
        Box::pin(async { Ok(TransferOutcome::Done) })
    }

    /// [`MState::Done`]: perform the post-transfer operation. `premature` is
    /// `true` when the transfer is being torn down before completing normally
    /// (an error or an abort). Defaults to a no-op success.
    fn done(&mut self, result: CurlCode, premature: bool) -> DriverFuture<'_, ()> {
        let _ = (result, premature);
        Box::pin(async { Ok(()) })
    }

    /// Rate-limit gate consulted around [`MState::Performing`] (curl's
    /// `state_ratelimiting`). Returns `Some(d)` to remain rate-limited for `d`
    /// (moving to [`MState::Ratelimiting`]), or `None` to proceed. The concrete
    /// durations come from the transfer core's rate limiter and progress meter;
    /// the default never rate-limits.
    fn rate_limit(&mut self) -> Option<Duration> {
        None
    }
}

/// A trivial [`TransferDriver`] that accepts every default: it connects
/// immediately, performs an empty transfer, and finishes with [`CurlCode::Ok`].
/// Useful as a placeholder before a protocol handler is attached and as a
/// baseline in tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultDriver;

impl TransferDriver for DefaultDriver {}

// ===========================================================================
// EasyHandle — a single transfer within a multi handle (curl's `Curl_easy`).
// ===========================================================================

/// The default follow-redirect budget applied to a new [`EasyHandle`], guarding
/// the state machine against an unbounded redirect chain when the transfer core
/// reports [`TransferOutcome::NeedNewRequest`]. Mirrors the spirit of curl's
/// `CURLOPT_MAXREDIRS` default used by the CLI.
pub const DEFAULT_MAX_REDIRECTS: u32 = 50;

/// Safety valve bounding a single synchronous driver "burst" ([`Multi::perform`])
/// so a misbehaving driver that never yields cannot spin forever. Far above the
/// worst legitimate case (≈ number of states × redirect budget).
const MAX_BURST_STEPS: usize = 10_000;

/// A single easy transfer as tracked by a [`Multi`] — the rewrite of the
/// per-transfer slice of curl's `struct Curl_easy` that the multi interface
/// drives. It owns the protocol [`TransferDriver`], the per-request state
/// ([`SingleRequest`], curl's `data->req`), its current [`MState`], and the
/// final [`CurlCode`].
///
/// An `EasyHandle` is created standalone, then handed to [`Multi::add_handle`],
/// which assigns it an [`EasyId`]. It is `Send + 'static` so the multi handle
/// can move it onto a Tokio worker thread for parallel execution.
pub struct EasyHandle {
    /// The protocol/transfer work performed at each state.
    driver: Box<dyn TransferDriver>,
    /// Per-request byte counters / keepon bits / buffers (curl's `data->req`).
    req: SingleRequest,
    /// Current position in the [`MState`] machine.
    mstate: MState,
    /// The transfer's result so far (`data->result`).
    result: CurlCode,
    /// Whether an in-flight teardown is premature (an error/abort), passed to
    /// [`TransferDriver::done`].
    premature: bool,
    /// The most recent follow-up URL reported by the transfer core (the last
    /// `Location:`/retry target); informational for callers and tests.
    newurl: Option<String>,
    /// Remaining redirect-follow budget (see [`DEFAULT_MAX_REDIRECTS`]).
    follows_remaining: u32,
    /// Signalled by [`Multi::unpause`] to resume a [`TransferOutcome::Paused`]
    /// transfer while it is being driven to completion.
    unpause: Arc<Notify>,
    /// The id assigned by the owning multi handle, if added.
    mid: Option<EasyId>,
}

impl EasyHandle {
    /// Creates a standalone transfer driven by `driver`, in the initial
    /// [`MState::Init`] state with a fresh [`SingleRequest`].
    #[must_use]
    pub fn new<D: TransferDriver + 'static>(driver: D) -> Self {
        EasyHandle {
            driver: Box::new(driver),
            req: SingleRequest::new(),
            mstate: MState::Init,
            result: CurlCode::Ok,
            premature: false,
            newurl: None,
            follows_remaining: DEFAULT_MAX_REDIRECTS,
            unpause: Arc::new(Notify::new()),
            mid: None,
        }
    }

    /// Replaces the transfer's [`SingleRequest`] (builder style).
    #[must_use]
    pub fn with_request(mut self, req: SingleRequest) -> Self {
        self.req = req;
        self
    }

    /// Sets the follow-redirect budget (builder style).
    #[must_use]
    pub fn with_max_redirects(mut self, max: u32) -> Self {
        self.follows_remaining = max;
        self
    }

    /// The transfer's current [`MState`].
    #[must_use]
    pub fn state(&self) -> MState {
        self.mstate
    }

    /// The transfer's result so far ([`CurlCode::Ok`] until it fails or finishes).
    #[must_use]
    pub fn result(&self) -> CurlCode {
        self.result
    }

    /// The id assigned by the owning [`Multi`], or `None` if not added.
    #[must_use]
    pub fn id(&self) -> Option<EasyId> {
        self.mid
    }

    /// The most recent follow-up URL reported by the transfer core, if any.
    #[must_use]
    pub fn pending_redirect(&self) -> Option<&str> {
        self.newurl.as_deref()
    }

    /// `true` once the transfer has reached [`MState::Msgsent`] (its completion
    /// message has been queued for the application).
    #[must_use]
    pub fn is_msgsent(&self) -> bool {
        self.mstate == MState::Msgsent
    }

    /// Change state, emitting the exact `--trace` transition line curl prints
    /// (`-> [STATENAME]`). A no-op when the state is unchanged, matching curl's
    /// `mstate()` early return.
    fn set_state(&mut self, new: MState) {
        if self.mstate == new {
            return;
        }
        self.mstate = new;
        match self.mid {
            Some(id) => {
                tracing::trace!(target: "curl::multi", mid = id.0, "-> [{}]", new.state_name());
            }
            None => {
                tracing::trace!(target: "curl::multi", "-> [{}]", new.state_name());
            }
        }
    }

    /// Record a hard failure: latch the first error code, mark the teardown
    /// premature, and route to [`MState::Done`] (curl's `multi_posttransfer` +
    /// `multi_done` + `stream_error` path).
    fn fail(&mut self, err: crate::error::Error) -> Step {
        if self.result == CurlCode::Ok {
            self.result = err.code();
        }
        self.premature = true;
        self.set_state(MState::Done);
        Step::Progress
    }

    /// Advance the transfer by one state, the rewrite of a single iteration of
    /// curl's `multi_runsingle` switch. Returns a [`Step`] describing whether to
    /// continue immediately, wait, park (paused), or finish.
    #[allow(clippy::too_many_lines)]
    async fn run_one(&mut self) -> Step {
        match self.mstate {
            MState::Init => {
                // Transitional: init the transfer, then fall through to SETUP.
                self.set_state(MState::Setup);
                Step::Progress
            }
            MState::Pending => {
                // A connection slot is modelled as available at this layer, so a
                // pending transfer immediately re-attempts CONNECT (curl's
                // `process_pending_handles` moving PENDING -> CONNECT).
                self.set_state(MState::Connect);
                Step::Progress
            }
            MState::Setup => {
                self.set_state(MState::Connect);
                Step::Progress
            }
            MState::Connect => match self.driver.connect().await {
                Ok(ConnectOutcome::Resolving) => {
                    self.set_state(MState::Resolving);
                    Step::Progress
                }
                Ok(ConnectOutcome::Connecting) => {
                    self.set_state(MState::Connecting);
                    Step::Progress
                }
                Ok(ConnectOutcome::Connected) => {
                    self.set_state(MState::Protoconnect);
                    Step::Progress
                }
                Ok(ConnectOutcome::Pending) => {
                    self.set_state(MState::Pending);
                    Step::Wait(None)
                }
                Err(e) => self.fail(e),
            },
            MState::Resolving => match self.driver.resolving().await {
                Ok(ResolveOutcome::Resolving) => Step::Wait(None),
                Ok(ResolveOutcome::Connecting) => {
                    self.set_state(MState::Connecting);
                    Step::Progress
                }
                Ok(ResolveOutcome::Connected) => {
                    self.set_state(MState::Protoconnect);
                    Step::Progress
                }
                Err(e) => self.fail(e),
            },
            MState::Connecting => match self.driver.connecting().await {
                Ok(SocketConnectOutcome::Connecting) => Step::Wait(None),
                Ok(SocketConnectOutcome::Connected) => {
                    self.set_state(MState::Protoconnect);
                    Step::Progress
                }
                Err(e) => self.fail(e),
            },
            MState::Protoconnect => match self.driver.protocol_connect(true).await {
                Ok(ProtocolConnectOutcome::Connecting) => {
                    self.set_state(MState::Protoconnecting);
                    Step::Progress
                }
                Ok(ProtocolConnectOutcome::Connected) => {
                    self.set_state(MState::Do);
                    Step::Progress
                }
                Err(e) => self.fail(e),
            },
            MState::Protoconnecting => match self.driver.protocol_connect(false).await {
                Ok(ProtocolConnectOutcome::Connecting) => Step::Wait(None),
                Ok(ProtocolConnectOutcome::Connected) => {
                    self.set_state(MState::Do);
                    Step::Progress
                }
                Err(e) => self.fail(e),
            },
            MState::Do => match self.driver.do_request().await {
                Ok(DoOutcome::Doing) => {
                    self.set_state(MState::Doing);
                    Step::Progress
                }
                Ok(DoOutcome::DoingMore) => {
                    self.set_state(MState::DoingMore);
                    Step::Progress
                }
                Ok(DoOutcome::Did) => {
                    self.set_state(MState::Did);
                    Step::Progress
                }
                Ok(DoOutcome::Done) => {
                    self.set_state(MState::Done);
                    Step::Progress
                }
                Ok(DoOutcome::Stay) => Step::Wait(None),
                Err(e) => self.fail(e),
            },
            MState::Doing => match self.driver.doing().await {
                Ok(DoOutcome::Stay | DoOutcome::Doing) => Step::Wait(None),
                Ok(DoOutcome::DoingMore) => {
                    self.set_state(MState::DoingMore);
                    Step::Progress
                }
                Ok(DoOutcome::Did) => {
                    self.set_state(MState::Did);
                    Step::Progress
                }
                Ok(DoOutcome::Done) => {
                    self.set_state(MState::Done);
                    Step::Progress
                }
                Err(e) => self.fail(e),
            },
            MState::DoingMore => match self.driver.do_more().await {
                Ok(DoOutcome::Stay | DoOutcome::DoingMore) => Step::Wait(None),
                Ok(DoOutcome::Doing) => {
                    self.set_state(MState::Doing);
                    Step::Progress
                }
                Ok(DoOutcome::Did) => {
                    self.set_state(MState::Did);
                    Step::Progress
                }
                Ok(DoOutcome::Done) => {
                    self.set_state(MState::Done);
                    Step::Progress
                }
                Err(e) => self.fail(e),
            },
            MState::Did => {
                // curl goes PERFORMING when a usable socket exists, else DONE.
                // At this layer the transfer pump owns the socket, so we always
                // enter PERFORMING and let the pump report completion.
                self.set_state(MState::Performing);
                Step::Progress
            }
            MState::Performing => {
                // Rate-limit gate (curl's entry into MSTATE_RATELIMITING).
                if let Some(wait) = self.driver.rate_limit() {
                    if wait > Duration::ZERO {
                        self.set_state(MState::Ratelimiting);
                        return Step::Wait(Some(wait));
                    }
                }
                // Split-borrow so the pump can mutate `data->req` while the
                // driver owns the connection halves.
                let outcome = {
                    let EasyHandle { driver, req, .. } = &mut *self;
                    driver.perform(req).await
                };
                match outcome {
                    Ok(TransferOutcome::Done) => {
                        self.set_state(MState::Done);
                        Step::Progress
                    }
                    Ok(TransferOutcome::NeedNewRequest { newurl, follow }) => {
                        if follow && self.follows_remaining > 0 {
                            self.follows_remaining -= 1;
                            self.newurl = Some(newurl);
                            // Re-drive from SETUP for the follow-up request.
                            self.set_state(MState::Setup);
                            Step::Progress
                        } else {
                            self.newurl = Some(newurl);
                            self.set_state(MState::Done);
                            Step::Progress
                        }
                    }
                    Ok(TransferOutcome::Paused) => Step::Paused,
                    Err(e) => self.fail(e),
                }
            }
            MState::Ratelimiting => match self.driver.rate_limit() {
                Some(wait) if wait > Duration::ZERO => Step::Wait(Some(wait)),
                _ => {
                    self.set_state(MState::Performing);
                    Step::Progress
                }
            },
            MState::Done => {
                let premature = self.premature;
                let result = self.result;
                if let Err(e) = self.driver.done(result, premature).await {
                    // A post-transfer error only takes hold if none was latched.
                    if self.result == CurlCode::Ok {
                        self.result = e.code();
                    }
                }
                self.set_state(MState::Completed);
                Step::Progress
            }
            // COMPLETED / MSGSENT / LAST are terminal to the stepper; the owning
            // Multi turns COMPLETED into a queued message and MSGSENT.
            MState::Completed | MState::Msgsent | MState::Last => Step::Completed(self.result),
        }
    }

    /// Drive the transfer as far as it can synchronously go in one crank
    /// ([`Multi::perform`]): step while [`Step::Progress`] is returned, stopping
    /// at the first wait/park/completion. Bounded by [`MAX_BURST_STEPS`].
    async fn drive_burst(&mut self) -> Step {
        for _ in 0..MAX_BURST_STEPS {
            match self.run_one().await {
                Step::Progress => continue,
                other => return other,
            }
        }
        Step::Wait(None)
    }

    /// Drive the transfer to completion, awaiting rate-limit / readiness / paused
    /// events as needed. Used by [`Multi::run`] for concurrent execution on the
    /// multi-thread runtime. Returns the final [`CurlCode`].
    async fn drive(&mut self) -> CurlCode {
        loop {
            match self.run_one().await {
                Step::Progress => {}
                Step::Wait(Some(d)) => {
                    if d > Duration::ZERO {
                        tokio::time::sleep(d).await;
                    } else {
                        tokio::task::yield_now().await;
                    }
                }
                Step::Wait(None) => tokio::task::yield_now().await,
                Step::Paused => self.unpause.notified().await,
                Step::Completed(code) => return code,
            }
        }
    }
}

impl fmt::Debug for EasyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyHandle")
            .field("mid", &self.mid)
            .field("mstate", &self.mstate)
            .field("result", &self.result)
            .field("premature", &self.premature)
            .field("newurl", &self.newurl)
            .field("follows_remaining", &self.follows_remaining)
            .finish_non_exhaustive()
    }
}

// ===========================================================================
// Cross-handle sharing — the `curl_share` model (AAP §0.3.2).
// ===========================================================================

/// A single resolved-name entry in the [`DnsCache`].
#[derive(Debug, Clone)]
struct DnsEntry {
    /// The resolved addresses (string form; the concrete address type lives in
    /// the not-yet-present `dns` module).
    addrs: Vec<String>,
    /// Absolute expiry instant; `None` means the entry never expires (curl's
    /// permanently-cached `--resolve` style entries).
    expires: Option<Instant>,
}

/// A minimal shared DNS cache — the rewrite of the name-cache slice shared
/// across transfers via `curl_share`. Keyed by `(host, port)`.
#[derive(Debug, Default)]
pub struct DnsCache {
    entries: BTreeMap<(String, u16), DnsEntry>,
}

impl DnsCache {
    /// Inserts (or replaces) the resolved addresses for `host:port`. A `ttl` of
    /// `None` caches permanently; otherwise the entry expires after `ttl`.
    pub fn insert(
        &mut self,
        host: impl Into<String>,
        port: u16,
        addrs: Vec<String>,
        ttl: Option<Duration>,
    ) {
        let expires = ttl.map(|d| Instant::now() + d);
        self.entries
            .insert((host.into(), port), DnsEntry { addrs, expires });
    }

    /// Looks up `host:port`, returning a copy of the cached addresses if present
    /// and unexpired. Expired entries are pruned on access.
    #[must_use]
    pub fn lookup(&mut self, host: &str, port: u16) -> Option<Vec<String>> {
        let key = (host.to_owned(), port);
        let expired = match self.entries.get(&key) {
            Some(entry) => entry.expires.is_some_and(|e| Instant::now() >= e),
            None => return None,
        };
        if expired {
            self.entries.remove(&key);
            return None;
        }
        self.entries.get(&key).map(|e| e.addrs.clone())
    }

    /// Empties the cache (curl's `CURLMNWC_CLEAR_DNS`).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// The number of currently cached names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A minimal shared connection-reuse accounting — the rewrite of the
/// connection-pool slice shared across transfers via `curl_share`. The concrete
/// pooled-connection objects live in the not-yet-present `conn` module; this
/// tracks the limits and live count the multi handle enforces
/// ([`CurlMOption::MaxTotalConnections`]).
#[derive(Debug, Default)]
pub struct ConnCache {
    /// Maximum simultaneous connections; `0` means unlimited.
    max: usize,
    /// Connections currently checked out.
    in_use: usize,
    /// Total connections ever created (diagnostic).
    total_created: u64,
}

impl ConnCache {
    /// Creates a cache with the given cap (`0` = unlimited).
    #[must_use]
    pub fn new(max: usize) -> Self {
        ConnCache {
            max,
            in_use: 0,
            total_created: 0,
        }
    }

    /// Attempts to check out a connection slot, honoring the cap. Returns `true`
    /// on success. `false` means the caller should place the transfer in
    /// [`MState::Pending`].
    pub fn try_acquire(&mut self) -> bool {
        if self.max != 0 && self.in_use >= self.max {
            return false;
        }
        self.in_use += 1;
        self.total_created += 1;
        true
    }

    /// Returns a previously acquired slot.
    pub fn release(&mut self) {
        self.in_use = self.in_use.saturating_sub(1);
    }

    /// The number of connections currently in use.
    #[must_use]
    pub fn in_use(&self) -> usize {
        self.in_use
    }

    /// Marks the pool for no further reuse (curl's `CURLMNWC_CLEAR_CONNS`). At
    /// this layer that simply drops the idle count to zero.
    pub fn clear(&mut self) {
        self.in_use = 0;
    }
}

/// The bundle of resources a multi handle shares across its transfers, and that
/// can be shared across multiple multi handles (curl's `CURLSH` sharing). Each
/// resource sits behind its **own** [`Mutex`] so, per AAP §0.3.2, cookie/DNS and
/// connection-cache contention remain independent (fine-grained locking). The
/// [`Clone`] impl shares the underlying [`Arc`]s rather than copying state.
#[derive(Debug, Clone, Default)]
pub struct Shared {
    /// The shared DNS cache, independently locked.
    pub dns: Arc<Mutex<DnsCache>>,
    /// The shared connection accounting, independently locked.
    pub conns: Arc<Mutex<ConnCache>>,
}

impl Shared {
    /// Creates a fresh shared bundle whose connection cache caps at
    /// `max_conns` (`0` = unlimited).
    #[must_use]
    pub fn new(max_conns: usize) -> Self {
        Shared {
            dns: Arc::new(Mutex::new(DnsCache::default())),
            conns: Arc::new(Mutex::new(ConnCache::new(max_conns))),
        }
    }
}

// ===========================================================================
// Socket/event bookkeeping — a rewrite of `lib/multi_ev.c`.
// ===========================================================================

/// Per-socket state tracked for the socket API (`lib/multi_ev.c`'s
/// `mev_sh_entry`): which transfers use the socket, the last action combination
/// reported to the application, and the application's per-socket association
/// from [`Multi::assign`].
#[derive(Debug, Default)]
struct SockEntry {
    /// Transfers currently interested in this socket.
    xfers: BTreeSet<EasyId>,
    /// Per-transfer interest, so the combined action can be recomputed.
    interest: BTreeMap<EasyId, i32>,
    /// The combined [`CURL_POLL_IN`]/[`CURL_POLL_OUT`] last reported to the app.
    action: i32,
    /// The application's opaque per-socket token (`curl_multi_assign`).
    sockp: Option<usize>,
}

impl SockEntry {
    /// Recomputes the combined poll action across all interested transfers.
    fn combined(&self) -> i32 {
        let mut combo = CURL_POLL_NONE;
        for want in self.interest.values() {
            combo |= *want;
        }
        combo
    }
}

/// The socket-to-transfer bookkeeping that backs the socket API, a rewrite of
/// the `mev` hash in `lib/multi_ev.c`. Kept separate from [`Multi`] so its
/// borrow does not conflict with the socket callback during updates.
#[derive(Debug, Default)]
struct SocketBookkeeping {
    entries: BTreeMap<Socket, SockEntry>,
}

/// The read/write/exception socket sets produced by [`Multi::fdset`], the
/// rewrite of `curl_multi_fdset`'s `fd_set` outputs plus `max_fd`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FdSet {
    /// Sockets libcurl wants to read from.
    pub read: Vec<Socket>,
    /// Sockets libcurl wants to write to.
    pub write: Vec<Socket>,
    /// Sockets libcurl wants to watch for errors.
    pub exc: Vec<Socket>,
    /// The highest socket value across all sets, or [`CURL_SOCKET_BAD`] (`-1`)
    /// when no sockets are registered — matching `curl_multi_fdset`'s `*max_fd`.
    pub max_fd: Socket,
}

// ===========================================================================
// Notification queue — a rewrite of `lib/multi_ntfy.c`.
// ===========================================================================

/// The pending-notification queue delivered to [`NotifyCallback`], a rewrite of
/// `struct curl_multi_ntfy` (`lib/multi_ntfy.c`). Types are enabled per
/// [`Multi::notify_enable`]; enqueued events are drained to the callback by
/// [`Multi::dispatch_notifications`].
#[derive(Debug, Default)]
struct Notifications {
    /// Outstanding `(notification_type, transfer)` events, in arrival order.
    queue: VecDeque<(u32, EasyId)>,
    /// The set of enabled notification types (e.g. [`CURLMNOTIFY_EASY_DONE`]).
    enabled: HashSet<u32>,
}

// ===========================================================================
// Multi — the multi handle (curl's `CURLM` / `struct Curl_multi`).
// ===========================================================================

/// Default HTTP/2 concurrent-stream hint, matching curl's setopt clamp target
/// when the requested value is out of range.
const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 100;

/// The multi handle — the rewrite of curl's `struct Curl_multi` (exposed as
/// `CURLM`). It owns the set of added [`EasyHandle`]s, drives them through the
/// [`MState`] machine, queues completion [`Message`]s for [`Multi::info_read`],
/// and hosts the socket/timer/notification hook points.
///
/// Per AAP §0.3.2 the handle owns a Tokio **multi-thread** runtime so
/// [`Multi::run`] can progress independent transfers in parallel. The
/// per-transfer crank [`Multi::perform`] mirrors curl's single-threaded
/// `curl_multi_perform`.
pub struct Multi {
    /// The multi-thread Tokio runtime driving all transfers. Held in an
    /// [`Option`] so [`Drop`] can dispose of it with
    /// [`Runtime::shutdown_background`]: dropping a multi-thread runtime from
    /// within an async context would otherwise panic, which would make the
    /// `*_async` API unusable from inside a Tokio task. It is always `Some`
    /// for the lifetime of the handle and only taken during drop.
    runtime: Option<Runtime>,
    /// Every added transfer, keyed by its assigned [`EasyId`], ordered so the
    /// crank processes transfers deterministically (like curl's mid table).
    xfers: BTreeMap<EasyId, EasyHandle>,
    /// Completion messages awaiting [`Multi::info_read`] (curl's `msglist`).
    msglist: VecDeque<Message>,
    /// The next id to assign (monotonic; never reused).
    next_mid: u32,
    /// Total transfers ever added (curl's `xfers_total_ever`).
    xfers_total_ever: u64,
    /// `CURLMOPT_PIPELINING & CURLPIPE_MULTIPLEX` — whether HTTP/2+ multiplexing
    /// is permitted.
    multiplexing: bool,
    /// `CURLMOPT_MAXCONNECTS` — connection-cache size hint (`0` = auto).
    maxconnects: u32,
    /// `CURLMOPT_MAX_HOST_CONNECTIONS` — per-host connection cap (`0` = none).
    max_host_connections: usize,
    /// `CURLMOPT_MAX_TOTAL_CONNECTIONS` — overall connection cap (`0` = none).
    max_total_connections: usize,
    /// `CURLMOPT_MAX_CONCURRENT_STREAMS` — HTTP/2 stream-limit hint.
    max_concurrent_streams: u32,
    /// `CURLMOPT_SOCKETFUNCTION` hook.
    socket_cb: Option<SocketCallback>,
    /// `CURLMOPT_TIMERFUNCTION` hook.
    timer_cb: Option<TimerCallback>,
    /// `CURLMOPT_NOTIFYFUNCTION` hook.
    notify_cb: Option<NotifyCallback>,
    /// `CURLMOPT_PUSHFUNCTION` hook.
    push_cb: Option<PushCallback>,
    /// Socket-to-transfer bookkeeping for the socket API (`multi_ev`).
    sockets: SocketBookkeeping,
    /// The notification queue and enabled-types set (`multi_ntfy`).
    ntfy: Notifications,
    /// Resources shared across transfers (and shareable across multi handles).
    shared: Shared,
    /// Signalled by [`Multi::wakeup`] to break a blocking [`Multi::poll`] /
    /// [`Multi::wait`] early (curl's `curl_multi_wakeup`).
    wakeup: Arc<Notify>,
    /// The last timeout (in milliseconds, `-1` = none) reported to the timer
    /// callback. curl only fires `CURLMOPT_TIMERFUNCTION` when this changes, so
    /// we cache it to reproduce that de-duplication exactly.
    last_timeout: i64,
    /// Recursive-API-call guard: set while inside an application callback so
    /// re-entrant API calls return [`CurlMCode::RecursiveApiCall`].
    in_callback: bool,
}

impl Multi {
    /// Creates a new multi handle, building the multi-thread Tokio runtime.
    ///
    /// # Panics
    ///
    /// Panics if the Tokio runtime cannot be constructed (e.g. the OS refuses to
    /// spawn worker threads). Use [`Multi::try_new`] to handle that fallibly.
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().expect("failed to build the multi-handle Tokio runtime")
    }

    /// Creates a new multi handle, returning any runtime-construction error
    /// instead of panicking. Mirrors `curl_multi_init` returning `NULL` on
    /// failure.
    ///
    /// # Errors
    ///
    /// Returns the [`std::io::Error`] produced by the Tokio runtime builder.
    pub fn try_new() -> std::io::Result<Self> {
        Self::try_with_shared(Shared::default())
    }

    /// Creates a new multi handle using the given [`Shared`] resource bundle, so
    /// several handles can share a DNS/connection cache (curl's `CURLSH`).
    ///
    /// # Panics
    ///
    /// Panics if the Tokio runtime cannot be constructed.
    #[must_use]
    pub fn with_shared(shared: Shared) -> Self {
        Self::try_with_shared(shared).expect("failed to build the multi-handle Tokio runtime")
    }

    /// Fallible [`Multi::with_shared`].
    ///
    /// # Errors
    ///
    /// Returns the [`std::io::Error`] produced by the Tokio runtime builder.
    pub fn try_with_shared(shared: Shared) -> std::io::Result<Self> {
        let runtime = Builder::new_multi_thread().enable_all().build()?;
        Ok(Multi {
            runtime: Some(runtime),
            xfers: BTreeMap::new(),
            msglist: VecDeque::new(),
            next_mid: 0,
            xfers_total_ever: 0,
            multiplexing: false,
            maxconnects: 0,
            max_host_connections: 0,
            max_total_connections: 0,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            socket_cb: None,
            timer_cb: None,
            notify_cb: None,
            push_cb: None,
            sockets: SocketBookkeeping::default(),
            ntfy: Notifications::default(),
            shared,
            wakeup: Arc::new(Notify::new()),
            last_timeout: i64::MIN,
            in_callback: false,
        })
    }

    /// The [`Shared`] resource bundle backing this handle.
    #[must_use]
    pub fn shared(&self) -> &Shared {
        &self.shared
    }

    // -----------------------------------------------------------------------
    // Handle management (`curl_multi_add_handle` / `curl_multi_remove_handle`).
    // -----------------------------------------------------------------------

    /// Adds an easy transfer, assigning it an [`EasyId`] and placing it in
    /// [`MState::Init`] so the next crank starts it. The rewrite of
    /// `curl_multi_add_handle`.
    ///
    /// # Errors
    ///
    /// * [`CurlMCode::AddedAlready`] — the handle is already in a multi handle.
    /// * [`CurlMCode::RecursiveApiCall`] — called from within a callback.
    /// * [`CurlMCode::OutOfMemory`] — the id space (`u32`) is exhausted.
    pub fn add_handle(&mut self, mut easy: EasyHandle) -> core::result::Result<EasyId, CurlMCode> {
        if self.in_callback {
            return Err(CurlMCode::RecursiveApiCall);
        }
        if easy.mid.is_some() {
            return Err(CurlMCode::AddedAlready);
        }
        let next = self.next_mid.checked_add(1).ok_or(CurlMCode::OutOfMemory)?;
        let id = EasyId(self.next_mid);
        self.next_mid = next;

        // Reset per-run state for a clean (possibly re-added) handle.
        easy.mid = Some(id);
        easy.mstate = MState::Init;
        easy.result = CurlCode::Ok;
        easy.premature = false;
        easy.newurl = None;

        self.xfers.insert(id, easy);
        self.xfers_total_ever += 1;
        tracing::trace!(target: "curl::multi", mid = id.0, "added to multi handle");
        Ok(id)
    }

    /// Removes a transfer, returning ownership of its [`EasyHandle`] so it can be
    /// reused or added elsewhere (curl leaves the easy handle valid after
    /// `curl_multi_remove_handle`). Any queued completion message and socket
    /// registrations for the handle are dropped.
    ///
    /// # Errors
    ///
    /// * [`CurlMCode::BadEasyHandle`] — no transfer with that id is present.
    /// * [`CurlMCode::RecursiveApiCall`] — called from within a callback.
    pub fn remove_handle(&mut self, id: EasyId) -> core::result::Result<EasyHandle, CurlMCode> {
        if self.in_callback {
            return Err(CurlMCode::RecursiveApiCall);
        }
        match self.xfers.remove(&id) {
            Some(mut easy) => {
                easy.mid = None;
                self.msglist.retain(|m| m.easy != id);
                self.forget_transfer_sockets(id);
                tracing::trace!(target: "curl::multi", mid = id.0, "removed from multi handle");
                Ok(easy)
            }
            None => Err(CurlMCode::BadEasyHandle),
        }
    }

    /// Borrows an added transfer by id.
    #[must_use]
    pub fn get_handle(&self, id: EasyId) -> Option<&EasyHandle> {
        self.xfers.get(&id)
    }

    /// The ids of all currently added transfers (curl's `curl_multi_get_handles`).
    #[must_use]
    pub fn handles(&self) -> Vec<EasyId> {
        self.xfers.keys().copied().collect()
    }

    // -----------------------------------------------------------------------
    // Options (`curl_multi_setopt`).
    // -----------------------------------------------------------------------

    /// Sets a numeric multi option, the rewrite of `curl_multi_setopt` for the
    /// `LONG`/`OFF_T` options. Callback and pointer options are configured via
    /// the typed setters ([`Multi::set_socket_function`], etc.).
    ///
    /// Returns [`CurlMCode::Ok`] on success, [`CurlMCode::BadFunctionArgument`]
    /// for an out-of-range value or a callback/pointer option supplied with a
    /// numeric value, and [`CurlMCode::RecursiveApiCall`] if called from within
    /// a callback.
    #[must_use]
    pub fn setopt(&mut self, option: CurlMOption, value: MultiOptionValue) -> CurlMCode {
        if self.in_callback {
            return CurlMCode::RecursiveApiCall;
        }
        let long = match value {
            MultiOptionValue::Long(v) | MultiOptionValue::OffT(v) => v,
        };
        match option {
            CurlMOption::Pipelining => {
                self.multiplexing = (long & CURLPIPE_MULTIPLEX) != 0;
                CurlMCode::Ok
            }
            CurlMOption::MaxConnects => {
                if (0..=i64::from(u32::MAX)).contains(&long) {
                    self.maxconnects = long as u32;
                    CurlMCode::Ok
                } else {
                    CurlMCode::BadFunctionArgument
                }
            }
            CurlMOption::MaxHostConnections => match usize::try_from(long) {
                Ok(v) => {
                    self.max_host_connections = v;
                    CurlMCode::Ok
                }
                Err(_) => CurlMCode::BadFunctionArgument,
            },
            CurlMOption::MaxTotalConnections => match usize::try_from(long) {
                Ok(v) => {
                    self.max_total_connections = v;
                    if let Ok(mut conns) = self.shared.conns.lock() {
                        *conns = ConnCache::new(v);
                    }
                    CurlMCode::Ok
                }
                Err(_) => CurlMCode::BadFunctionArgument,
            },
            CurlMOption::MaxConcurrentStreams => {
                // curl clamps <1 or >INT_MAX to the default of 100.
                self.max_concurrent_streams = if (1..=i64::from(i32::MAX)).contains(&long) {
                    long as u32
                } else {
                    DEFAULT_MAX_CONCURRENT_STREAMS
                };
                CurlMCode::Ok
            }
            CurlMOption::NetworkChanged => {
                if long & CURLMNWC_CLEAR_DNS != 0 {
                    if let Ok(mut dns) = self.shared.dns.lock() {
                        dns.clear();
                    }
                }
                if long & CURLMNWC_CLEAR_CONNS != 0 {
                    if let Ok(mut conns) = self.shared.conns.lock() {
                        conns.clear();
                    }
                }
                CurlMCode::Ok
            }
            // Options formerly used for pipelining are accepted as no-ops,
            // exactly as curl_multi_setopt treats them today.
            CurlMOption::MaxPipelineLength
            | CurlMOption::ContentLengthPenaltySize
            | CurlMOption::ChunkLengthPenaltySize
            | CurlMOption::PipeliningSiteBl
            | CurlMOption::PipeliningServerBl => CurlMCode::Ok,
            // Pointer/data options carry no observable state at this layer.
            CurlMOption::SocketData
            | CurlMOption::TimerData
            | CurlMOption::PushData
            | CurlMOption::NotifyData => CurlMCode::Ok,
            // Function-pointer options must use the typed setters.
            CurlMOption::SocketFunction
            | CurlMOption::TimerFunction
            | CurlMOption::PushFunction
            | CurlMOption::NotifyFunction => CurlMCode::BadFunctionArgument,
        }
    }

    /// Sets an option by its raw integer id, returning [`CurlMCode::UnknownOption`]
    /// for an unrecognized id (the path `curl_multi_setopt` takes for an option
    /// it does not implement). Known ids delegate to [`Multi::setopt`].
    #[must_use]
    pub fn setopt_raw(&mut self, option: i32, value: MultiOptionValue) -> CurlMCode {
        match CurlMOption::try_from(option) {
            Ok(opt) => self.setopt(opt, value),
            Err(_) => CurlMCode::UnknownOption,
        }
    }

    /// Installs (or clears) the `CURLMOPT_SOCKETFUNCTION` hook.
    pub fn set_socket_function(&mut self, cb: Option<SocketCallback>) {
        self.socket_cb = cb;
    }

    /// Installs (or clears) the `CURLMOPT_TIMERFUNCTION` hook.
    pub fn set_timer_function(&mut self, cb: Option<TimerCallback>) {
        self.timer_cb = cb;
    }

    /// Installs (or clears) the `CURLMOPT_NOTIFYFUNCTION` hook.
    pub fn set_notify_function(&mut self, cb: Option<NotifyCallback>) {
        self.notify_cb = cb;
    }

    /// Installs (or clears) the `CURLMOPT_PUSHFUNCTION` hook.
    pub fn set_push_function(&mut self, cb: Option<PushCallback>) {
        self.push_cb = cb;
    }

    /// Enables delivery of a notification type (curl's `curl_multi_notify_enable`).
    ///
    /// Returns [`CurlMCode::UnknownOption`] for an unknown notification type.
    #[must_use]
    pub fn notify_enable(&mut self, notification: u32) -> CurlMCode {
        if notification > CURLMNOTIFY_EASY_DONE {
            return CurlMCode::UnknownOption;
        }
        self.ntfy.enabled.insert(notification);
        CurlMCode::Ok
    }

    /// Disables delivery of a notification type (curl's `curl_multi_notify_disable`).
    ///
    /// Returns [`CurlMCode::UnknownOption`] for an unknown notification type.
    #[must_use]
    pub fn notify_disable(&mut self, notification: u32) -> CurlMCode {
        if notification > CURLMNOTIFY_EASY_DONE {
            return CurlMCode::UnknownOption;
        }
        self.ntfy.enabled.remove(&notification);
        CurlMCode::Ok
    }

    // -----------------------------------------------------------------------
    // Informational queries (`curl_multi_get_offt`).
    // -----------------------------------------------------------------------

    /// The number of transfers currently running (added and not yet moved to
    /// [`MState::Msgsent`]). Mirrors `*running_handles` from `curl_multi_perform`.
    #[must_use]
    pub fn running_handles(&self) -> usize {
        self.xfers
            .values()
            .filter(|h| h.mstate != MState::Msgsent)
            .count()
    }

    /// Returns an informational counter (curl's `curl_multi_get_offt`).
    #[must_use]
    pub fn get(&self, info: CurlMInfo) -> i64 {
        let count_state =
            |state: MState| self.xfers.values().filter(|h| h.mstate == state).count() as i64;
        match info {
            CurlMInfo::XfersCurrent => self.xfers.len() as i64,
            CurlMInfo::XfersRunning => self.running_handles() as i64,
            CurlMInfo::XfersPending => count_state(MState::Pending),
            CurlMInfo::XfersDone => count_state(MState::Msgsent),
            CurlMInfo::XfersAdded => self.xfers_total_ever as i64,
        }
    }

    /// Reads the next completion [`Message`] (curl's `curl_multi_info_read`),
    /// removing it from the queue. Returns `None` when the queue is empty.
    #[must_use]
    pub fn info_read(&mut self) -> Option<Message> {
        if self.in_callback {
            return None;
        }
        self.msglist.pop_front()
    }

    /// The number of completion messages still queued for [`Multi::info_read`]
    /// (the `*msgs_in_queue` out-parameter of `curl_multi_info_read`).
    #[must_use]
    pub fn messages_in_queue(&self) -> usize {
        self.msglist.len()
    }

    /// Associates an application token with a socket (curl's `curl_multi_assign`).
    /// The token is delivered to the socket callback for that socket.
    ///
    /// Returns [`CurlMCode::BadSocket`] for the invalid-socket sentinel.
    #[must_use]
    pub fn assign(&mut self, s: Socket, sockp: usize) -> CurlMCode {
        if s == CURL_SOCKET_BAD {
            return CurlMCode::BadSocket;
        }
        self.sockets.entries.entry(s).or_default().sockp = Some(sockp);
        CurlMCode::Ok
    }

    /// Releases the multi handle (curl's `curl_multi_cleanup`). Consuming the
    /// handle drops its runtime and all remaining transfers; Rust's ownership
    /// model frees every associated resource, so this always succeeds.
    #[must_use]
    pub fn cleanup(self) -> CurlMCode {
        CurlMCode::Ok
    }

    // -----------------------------------------------------------------------
    // Driving transfers (`curl_multi_perform` and a run-to-completion helper).
    // -----------------------------------------------------------------------

    /// A cloned [`Handle`] to the owned runtime, for the blocking (`block_on`)
    /// convenience methods. The runtime is present for the entire lifetime of
    /// the handle (see the `runtime` field), so this never panics in practice.
    fn rt_handle(&self) -> Handle {
        self.runtime
            .as_ref()
            .expect("multi runtime is present until drop")
            .handle()
            .clone()
    }

    /// Cranks every runnable transfer forward by one synchronous burst — the
    /// rewrite of `curl_multi_perform`. Each transfer is stepped through the
    /// [`MState`] machine until it waits on I/O, is paused, or completes;
    /// completed transfers become [`CurlMsg::Done`] messages retrievable via
    /// [`Multi::info_read`].
    ///
    /// Returns `(running_handles, code)`, where `running_handles` is the number
    /// of transfers still active (curl's `*running_handles`). Callers loop
    /// `perform` + [`Multi::poll`] until `running_handles` reaches zero, exactly
    /// as with the C API.
    ///
    /// # Panics
    ///
    /// Panics if called from within an existing Tokio runtime context (it drives
    /// its own runtime via `block_on`). From async code use
    /// [`Multi::perform_async`] instead.
    pub fn perform(&mut self) -> (usize, CurlMCode) {
        let rt = self.rt_handle();
        rt.block_on(self.perform_async())
    }

    /// The `async` core of [`Multi::perform`], usable directly from within a
    /// Tokio context (an application runtime or a `#[tokio::test]`).
    pub async fn perform_async(&mut self) -> (usize, CurlMCode) {
        // Promote transfers parked in PENDING now that capacity is reassessed
        // (curl's `Curl_multi_process_pending_handles`).
        self.process_pending();

        // Snapshot the ids up front: a transfer added by a notification callback
        // (dispatched at the end of this pass) is deferred to the next crank,
        // matching curl's single-sweep `multi_runsingle` behaviour.
        let ids: Vec<EasyId> = self
            .xfers
            .iter()
            .filter(|(_, h)| h.mstate != MState::Msgsent)
            .map(|(id, _)| *id)
            .collect();

        for id in ids {
            // Move the handle out so it can be driven without aliasing `self`.
            let mut handle = match self.xfers.remove(&id) {
                Some(h) => h,
                None => continue,
            };
            match handle.drive_burst().await {
                Step::Completed(result) => self.handle_completed(id, handle, result),
                // Progress / Wait / Paused: still running — put it back.
                _ => {
                    self.xfers.insert(id, handle);
                }
            }
        }

        // Deliver queued notifications and (re)arm the timer callback.
        self.dispatch_notifications();
        self.update_timer();
        (self.running_handles(), CurlMCode::Ok)
    }

    /// Drives every added transfer to completion in parallel on the multi-thread
    /// runtime, returning [`CurlMCode::Ok`]. This is the convenience counterpart
    /// to the classic `perform`/`poll` loop, exploiting the multi-thread runtime
    /// mandated for the multi handle (AAP §0.3.2) so independent transfers run
    /// concurrently. Completion [`Message`]s remain available via
    /// [`Multi::info_read`] afterwards.
    ///
    /// # Panics
    ///
    /// Panics if called from within an existing Tokio runtime context. From
    /// async code use [`Multi::run_async`] instead.
    pub fn run(&mut self) -> CurlMCode {
        let rt = self.rt_handle();
        rt.block_on(self.run_async())
    }

    /// The `async` core of [`Multi::run`], usable directly from within a Tokio
    /// context. Spawns each transfer on its own task and joins them, so a slow
    /// transfer never blocks the others.
    pub async fn run_async(&mut self) -> CurlMCode {
        loop {
            self.process_pending();
            let ids: Vec<EasyId> = self
                .xfers
                .iter()
                .filter(|(_, h)| h.mstate != MState::Msgsent)
                .map(|(id, _)| *id)
                .collect();
            if ids.is_empty() {
                break;
            }

            // Move each runnable transfer onto its own worker task. Every
            // `EasyHandle` is `Send + 'static`, so this needs no `unsafe`.
            let mut set: JoinSet<(EasyId, EasyHandle, CurlCode)> = JoinSet::new();
            for id in ids {
                if let Some(handle) = self.xfers.remove(&id) {
                    set.spawn(async move {
                        let mut handle = handle;
                        let result = handle.drive().await;
                        (id, handle, result)
                    });
                }
            }

            while let Some(joined) = set.join_next().await {
                match joined {
                    Ok((id, handle, result)) => self.handle_completed(id, handle, result),
                    Err(err) => {
                        // A transfer task panicked, taking its handle with it.
                        // curl would treat this as an internal error; we log and
                        // keep draining so the remaining transfers still finish.
                        tracing::error!(target: "curl::multi", "transfer task failed: {err}");
                    }
                }
            }

            self.dispatch_notifications();
        }
        self.update_timer();
        CurlMCode::Ok
    }

    // -----------------------------------------------------------------------
    // Waiting for activity (`curl_multi_poll` / `_wait` / `_wakeup`).
    // -----------------------------------------------------------------------

    /// Waits up to `timeout` for a transfer to need attention — the rewrite of
    /// `curl_multi_poll`. Unlike [`Multi::wait`], a concurrent [`Multi::wakeup`]
    /// breaks the wait early. Returns `(numfds, code)`; `numfds` is `0` at this
    /// layer, which tracks readiness through the async driver rather than raw
    /// `fd_set`s.
    ///
    /// # Panics
    ///
    /// Panics if called from within an existing Tokio runtime context.
    #[must_use]
    pub fn poll(&mut self, timeout: Duration) -> (usize, CurlMCode) {
        self.wait_internal(timeout, true)
    }

    /// Waits up to `timeout` for a transfer to need attention — the rewrite of
    /// `curl_multi_wait`. Identical to [`Multi::poll`] except a concurrent
    /// [`Multi::wakeup`] does **not** cut the wait short.
    ///
    /// # Panics
    ///
    /// Panics if called from within an existing Tokio runtime context.
    #[must_use]
    pub fn wait(&mut self, timeout: Duration) -> (usize, CurlMCode) {
        self.wait_internal(timeout, false)
    }

    /// Shared implementation of [`Multi::poll`]/[`Multi::wait`]. When
    /// `allow_wakeup` is set, a concurrent [`Multi::wakeup`] ends the wait early.
    fn wait_internal(&mut self, timeout: Duration, allow_wakeup: bool) -> (usize, CurlMCode) {
        // Nothing running, or a zero timeout, means "do not block".
        let runnable = self.xfers.values().any(|h| h.mstate != MState::Msgsent);
        if !runnable || timeout.is_zero() {
            return (0, CurlMCode::Ok);
        }

        let rt = self.rt_handle();
        let wakeup = Arc::clone(&self.wakeup);
        rt.block_on(async move {
            if allow_wakeup {
                tokio::select! {
                    () = tokio::time::sleep(timeout) => {}
                    () = wakeup.notified() => {}
                }
            } else {
                tokio::time::sleep(timeout).await;
            }
        });
        (0, CurlMCode::Ok)
    }

    /// Wakes a concurrent [`Multi::poll`] on this handle — the rewrite of
    /// `curl_multi_wakeup`. Cheap and lock-free; the underlying primitive is
    /// [`Sync`], so it may be signalled from any thread holding a reference.
    #[must_use]
    pub fn wakeup(&self) -> CurlMCode {
        self.wakeup.notify_one();
        CurlMCode::Ok
    }

    // -----------------------------------------------------------------------
    // Socket API (`curl_multi_fdset` / `curl_multi_socket_action`) — multi_ev.c.
    // -----------------------------------------------------------------------

    /// Fills read/write/exception socket sets from the current socket
    /// bookkeeping — the rewrite of `curl_multi_fdset`. `max_fd` is the highest
    /// registered socket, or [`CURL_SOCKET_BAD`] when none are registered.
    #[must_use]
    pub fn fdset(&self) -> FdSet {
        let mut set = FdSet {
            read: Vec::new(),
            write: Vec::new(),
            exc: Vec::new(),
            max_fd: CURL_SOCKET_BAD,
        };
        for (sock, entry) in &self.sockets.entries {
            let action = entry.action;
            if action & CURL_POLL_IN != 0 {
                set.read.push(*sock);
            }
            if action & CURL_POLL_OUT != 0 {
                set.write.push(*sock);
            }
            if action != CURL_POLL_NONE && *sock > set.max_fd {
                set.max_fd = *sock;
            }
        }
        set
    }

    /// Reports socket activity and cranks the affected transfers — the rewrite
    /// of `curl_multi_socket_action`. `s` is the socket that saw events (or
    /// [`CURL_SOCKET_TIMEOUT`] for a timer-driven crank) and `ev_bitmask` is the
    /// [`CURL_CSELECT_IN`]/[`CURL_CSELECT_OUT`]/[`CURL_CSELECT_ERR`] combination.
    ///
    /// At this layer transfers track their own readiness through the async
    /// driver, so a socket event simply advances the state machine; the call
    /// therefore behaves like [`Multi::perform`], returning `(running, code)`.
    ///
    /// # Panics
    ///
    /// Panics if called from within an existing Tokio runtime context.
    #[must_use]
    pub fn socket_action(&mut self, s: Socket, ev_bitmask: i32) -> (usize, CurlMCode) {
        let _ = (s, ev_bitmask);
        self.perform()
    }

    /// The `async` core of [`Multi::socket_action`], usable from within a Tokio
    /// context.
    pub async fn socket_action_async(&mut self, s: Socket, ev_bitmask: i32) -> (usize, CurlMCode) {
        let _ = (s, ev_bitmask);
        self.perform_async().await
    }

    /// Records a transfer's interest in a socket and fires the socket callback
    /// when the combined action changes — the rewrite of `lib/multi_ev.c`'s
    /// `mev_sh_entry_update`. `what` is a
    /// [`CURL_POLL_IN`]/[`CURL_POLL_OUT`]/[`CURL_POLL_INOUT`] interest, or
    /// [`CURL_POLL_REMOVE`] to drop the transfer's interest in the socket. The
    /// application callback is invoked only when the combined action for the
    /// socket changes, exactly matching curl's edge-triggered contract.
    pub fn set_socket_interest(&mut self, id: EasyId, s: Socket, what: i32) {
        if s == CURL_SOCKET_BAD {
            return;
        }

        // Update the per-socket entry and derive the value to report.
        let (report, changed, sockp) = {
            let entry = self.sockets.entries.entry(s).or_default();
            if what == CURL_POLL_REMOVE {
                entry.xfers.remove(&id);
                entry.interest.remove(&id);
            } else {
                entry.xfers.insert(id);
                entry.interest.insert(id, what);
            }
            // No transfer wants the socket any more → report REMOVE; otherwise
            // report the (possibly changed) combined poll action.
            let report = if entry.xfers.is_empty() {
                CURL_POLL_REMOVE
            } else {
                entry.combined()
            };
            let changed = entry.action != report;
            entry.action = report;
            (report, changed, entry.sockp)
        };

        if changed {
            self.invoke_socket_cb(id, s, report, sockp);
        }
        // Forget the socket once nobody is interested (after the REMOVE
        // callback has been delivered).
        if report == CURL_POLL_REMOVE {
            self.sockets.entries.remove(&s);
        }
    }

    /// Invokes the registered [`SocketCallback`] with the re-entrancy guard set
    /// so a re-entrant multi API call returns [`CurlMCode::RecursiveApiCall`].
    fn invoke_socket_cb(&mut self, id: EasyId, s: Socket, action: i32, sockp: Option<usize>) {
        if self.socket_cb.is_none() {
            return;
        }
        let prev = self.in_callback;
        self.in_callback = true;
        if let Some(cb) = self.socket_cb.as_mut() {
            let _ = cb(id, s, action, sockp);
        }
        self.in_callback = prev;
    }

    // -----------------------------------------------------------------------
    // Pause/resume and internal state-machine bookkeeping helpers.
    // -----------------------------------------------------------------------

    /// Resumes a transfer previously parked by [`TransferOutcome::Paused`],
    /// signalling its waker so [`Multi::run`]'s driver re-steps it. Mirrors the
    /// wake half of `curl_easy_pause(CURLPAUSE_CONT)` as observed by the multi
    /// loop.
    ///
    /// Returns [`CurlMCode::BadEasyHandle`] if no such transfer is present.
    #[must_use]
    pub fn unpause(&self, id: EasyId) -> CurlMCode {
        match self.xfers.get(&id) {
            Some(handle) => {
                handle.unpause.notify_one();
                CurlMCode::Ok
            }
            None => CurlMCode::BadEasyHandle,
        }
    }

    /// Turns a transfer that reached [`MState::Completed`] into a queued
    /// [`CurlMsg::Done`] message, moves it to [`MState::Msgsent`], drops its
    /// socket registrations, and enqueues the [`CURLMNOTIFY_EASY_DONE`]
    /// notification — the rewrite of curl's completion/message-post path. The
    /// handle is retained (in `Msgsent`) until the application calls
    /// [`Multi::remove_handle`], mirroring the C API.
    fn handle_completed(&mut self, id: EasyId, mut handle: EasyHandle, result: CurlCode) {
        handle.result = result;
        // Post the DONE message before flipping to MSGSENT, matching multi.c.
        self.msglist.push_back(Message {
            msg: CurlMsg::Done,
            easy: id,
            result,
        });
        handle.set_state(MState::Msgsent);
        self.xfers.insert(id, handle);
        self.forget_transfer_sockets(id);
        self.enqueue_notification(CURLMNOTIFY_EASY_DONE, id);
    }

    /// Drops every socket registration for a departing/completed transfer,
    /// recomputing each affected socket's combined action and notifying the
    /// socket callback of removals — the rewrite of `lib/multi_ev.c`'s
    /// per-transfer cleanup.
    fn forget_transfer_sockets(&mut self, id: EasyId) {
        // Collect the sockets this transfer was interested in, then update each.
        let socks: Vec<Socket> = self
            .sockets
            .entries
            .iter()
            .filter(|(_, e)| e.xfers.contains(&id))
            .map(|(s, _)| *s)
            .collect();
        for s in socks {
            self.set_socket_interest(id, s, CURL_POLL_REMOVE);
        }
    }

    /// Enqueues a notification for later delivery by
    /// [`Multi::dispatch_notifications`], but only when a [`NotifyCallback`] is
    /// registered and the type is enabled (curl's `Curl_multi_ntfy`).
    fn enqueue_notification(&mut self, notification: u32, id: EasyId) {
        if self.notify_cb.is_some() && self.ntfy.enabled.contains(&notification) {
            self.ntfy.queue.push_back((notification, id));
        }
    }

    /// Drains the notification queue to the registered [`NotifyCallback`] — the
    /// rewrite of `lib/multi_ntfy.c`'s delivery loop. The queue is drained into a
    /// local buffer first so the callback (run with the re-entrancy guard set)
    /// cannot observe a half-drained queue, and re-entrant multi API calls
    /// return [`CurlMCode::RecursiveApiCall`].
    fn dispatch_notifications(&mut self) {
        if self.notify_cb.is_none() || self.ntfy.queue.is_empty() {
            return;
        }
        let pending: Vec<(u32, EasyId)> = self.ntfy.queue.drain(..).collect();
        let prev = self.in_callback;
        self.in_callback = true;
        if let Some(cb) = self.notify_cb.as_mut() {
            for (notification, id) in pending {
                cb(notification, id);
            }
        }
        self.in_callback = prev;
    }

    /// Recomputes the handle's timeout and reports it to the timer callback when
    /// it changes — the rewrite of `Curl_update_timer`. The timeout is `0` when
    /// any transfer is immediately runnable, or `-1` when the handle is idle. Only
    /// a change from the previously reported value fires `CURLMOPT_TIMERFUNCTION`,
    /// exactly matching curl's de-duplication.
    fn update_timer(&mut self) {
        let timeout_ms: i64 = if self.running_handles() == 0 { -1 } else { 0 };
        if timeout_ms == self.last_timeout {
            return;
        }
        self.last_timeout = timeout_ms;
        if self.timer_cb.is_none() {
            return;
        }
        let prev = self.in_callback;
        self.in_callback = true;
        if let Some(cb) = self.timer_cb.as_mut() {
            let _ = cb(timeout_ms);
        }
        self.in_callback = prev;
    }

    /// Promotes transfers parked in [`MState::Pending`] to [`MState::Connect`] as
    /// connection-cache capacity allows — the rewrite of
    /// `Curl_multi_process_pending_handles`. A promoted transfer begins
    /// connecting on the next crank.
    fn process_pending(&mut self) {
        let pending: Vec<EasyId> = self
            .xfers
            .iter()
            .filter(|(_, h)| h.mstate == MState::Pending)
            .map(|(id, _)| *id)
            .collect();
        for id in pending {
            // Respect the total-connection cap when one is configured.
            if self.max_total_connections > 0 {
                let in_use = self.shared.conns.lock().map_or(0, |c| c.in_use());
                if in_use >= self.max_total_connections {
                    break;
                }
            }
            if let Some(handle) = self.xfers.get_mut(&id) {
                handle.set_state(MState::Connect);
            }
        }
    }
}

impl Default for Multi {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Multi {
    fn drop(&mut self) {
        // Dropping a multi-thread runtime blocks (it joins its worker threads),
        // which panics if it happens inside an async context. `shutdown_background`
        // releases the runtime without blocking, so a `Multi` driven through its
        // `*_async` API can be dropped safely from within a Tokio task.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl fmt::Debug for Multi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Multi")
            .field("xfers", &self.xfers.len())
            .field("running", &self.running_handles())
            .field("messages", &self.msglist.len())
            .field("multiplexing", &self.multiplexing)
            .field("maxconnects", &self.maxconnects)
            .field("max_total_connections", &self.max_total_connections)
            .field("max_concurrent_streams", &self.max_concurrent_streams)
            .finish_non_exhaustive()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test drivers — mock [`TransferDriver`]s exercising each state path.
    // -----------------------------------------------------------------------

    /// Records the sequence of driver hooks invoked so a test can assert the
    /// exact path the [`MState`] machine took.
    #[derive(Clone)]
    struct RecordingDriver {
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl RecordingDriver {
        fn new() -> (Self, Arc<Mutex<Vec<&'static str>>>) {
            let log = Arc::new(Mutex::new(Vec::new()));
            (
                RecordingDriver {
                    log: Arc::clone(&log),
                },
                log,
            )
        }
        fn note(&self, what: &'static str) {
            self.log.lock().expect("recording log lock").push(what);
        }
    }

    impl TransferDriver for RecordingDriver {
        fn connect(&mut self) -> DriverFuture<'_, ConnectOutcome> {
            self.note("connect");
            Box::pin(async { Ok(ConnectOutcome::Connected) })
        }
        fn protocol_connect(&mut self, first: bool) -> DriverFuture<'_, ProtocolConnectOutcome> {
            self.note(if first {
                "protoconnect"
            } else {
                "protoconnecting"
            });
            Box::pin(async { Ok(ProtocolConnectOutcome::Connected) })
        }
        fn do_request(&mut self) -> DriverFuture<'_, DoOutcome> {
            self.note("do");
            Box::pin(async { Ok(DoOutcome::Did) })
        }
        fn perform<'a>(
            &'a mut self,
            _req: &'a mut SingleRequest,
        ) -> DriverFuture<'a, TransferOutcome> {
            self.note("perform");
            Box::pin(async { Ok(TransferOutcome::Done) })
        }
        fn done(&mut self, _result: CurlCode, _premature: bool) -> DriverFuture<'_, ()> {
            self.note("done");
            Box::pin(async { Ok(()) })
        }
    }

    /// Fails at CONNECT with a fixed error code (curl's `stream_error` path).
    struct FailingDriver {
        code: CurlCode,
    }
    impl TransferDriver for FailingDriver {
        fn connect(&mut self) -> DriverFuture<'_, ConnectOutcome> {
            let code = self.code;
            Box::pin(async move { Err(crate::error::Error::from(code)) })
        }
    }

    /// Requests exactly one redirect, then completes.
    struct RedirectDriver {
        performs: u32,
        target: String,
    }
    impl TransferDriver for RedirectDriver {
        fn perform<'a>(
            &'a mut self,
            _req: &'a mut SingleRequest,
        ) -> DriverFuture<'a, TransferOutcome> {
            self.performs += 1;
            let first = self.performs == 1;
            let target = self.target.clone();
            Box::pin(async move {
                if first {
                    Ok(TransferOutcome::NeedNewRequest {
                        newurl: target,
                        follow: true,
                    })
                } else {
                    Ok(TransferOutcome::Done)
                }
            })
        }
    }

    /// Always asks to follow a redirect — used to prove the follow budget stops
    /// an unbounded chain.
    struct AlwaysRedirectDriver {
        target: String,
    }
    impl TransferDriver for AlwaysRedirectDriver {
        fn perform<'a>(
            &'a mut self,
            _req: &'a mut SingleRequest,
        ) -> DriverFuture<'a, TransferOutcome> {
            let target = self.target.clone();
            Box::pin(async move {
                Ok(TransferOutcome::NeedNewRequest {
                    newurl: target,
                    follow: true,
                })
            })
        }
    }

    /// Stays in CONNECTING until the `ready_at`-th poll, modelling a transfer
    /// that must be cranked several times (exercises the perform/poll loop).
    struct SlowConnectDriver {
        attempts: u32,
        ready_at: u32,
    }
    impl TransferDriver for SlowConnectDriver {
        fn connect(&mut self) -> DriverFuture<'_, ConnectOutcome> {
            Box::pin(async { Ok(ConnectOutcome::Connecting) })
        }
        fn connecting(&mut self) -> DriverFuture<'_, SocketConnectOutcome> {
            self.attempts += 1;
            let ready = self.attempts >= self.ready_at;
            Box::pin(async move {
                Ok(if ready {
                    SocketConnectOutcome::Connected
                } else {
                    SocketConnectOutcome::Connecting
                })
            })
        }
    }

    /// Reports [`ConnectOutcome::Pending`] until the `ready_at`-th attempt, then
    /// connects — exercises the PENDING → CONNECT promotion (`process_pending`).
    struct PendingThenConnectDriver {
        tries: u32,
        ready_at: u32,
    }
    impl TransferDriver for PendingThenConnectDriver {
        fn connect(&mut self) -> DriverFuture<'_, ConnectOutcome> {
            self.tries += 1;
            let ready = self.tries >= self.ready_at;
            Box::pin(async move {
                Ok(if ready {
                    ConnectOutcome::Connected
                } else {
                    ConnectOutcome::Pending
                })
            })
        }
    }

    /// Performs after a short async sleep, to exercise genuine concurrency.
    struct SleepyDriver {
        millis: u64,
    }
    impl TransferDriver for SleepyDriver {
        fn perform<'a>(
            &'a mut self,
            _req: &'a mut SingleRequest,
        ) -> DriverFuture<'a, TransferOutcome> {
            let millis = self.millis;
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(millis)).await;
                Ok(TransferOutcome::Done)
            })
        }
    }

    // -----------------------------------------------------------------------
    // MSTATE parity — the `--trace` guard (AAP §0.3.2 / §0.6.3 / §0.7.3).
    // -----------------------------------------------------------------------

    #[test]
    fn mstate_names_and_order_match_curl_8x() {
        // Exactly `Curl_trc_mstate_names[]` from `lib/curl_trc.c`, in order.
        let expected = [
            "INIT",
            "PENDING",
            "SETUP",
            "CONNECT",
            "RESOLVING",
            "CONNECTING",
            "PROTOCONNECT",
            "PROTOCONNECTING",
            "DO",
            "DOING",
            "DOING_MORE",
            "DID",
            "PERFORMING",
            "RATELIMITING",
            "DONE",
            "COMPLETED",
            "MSGSENT",
        ];
        let states = MState::real_states();
        assert_eq!(states.len(), 17, "there are 17 real MSTATE values");
        assert_eq!(expected.len(), 17);
        for (i, st) in states.iter().enumerate() {
            assert_eq!(
                st.state_name(),
                expected[i],
                "state-name mismatch at index {i}"
            );
            assert_eq!(st.to_i32(), i as i32, "discriminant mismatch at index {i}");
        }
        // LAST is the sentinel: value 17, printed as curl's out-of-range "?".
        assert_eq!(MState::Last.to_i32(), 17);
        assert_eq!(MState::Last.state_name(), "?");
    }

    #[test]
    fn mstate_specific_discriminants_and_ordering() {
        assert_eq!(MState::Init.to_i32(), 0);
        assert_eq!(MState::Performing.to_i32(), 12);
        assert_eq!(MState::Done.to_i32(), 14);
        assert_eq!(MState::Completed.to_i32(), 15);
        assert_eq!(MState::Msgsent.to_i32(), 16);
        // Ordering is meaningful: curl compares e.g. `state < MSTATE_COMPLETED`.
        assert!(MState::Init < MState::Done);
        assert!(MState::Performing < MState::Completed);
        assert!(MState::Done < MState::Msgsent);
    }

    // -----------------------------------------------------------------------
    // Frozen ABI integer values (include/curl/multi.h).
    // -----------------------------------------------------------------------

    #[test]
    fn curlmcode_integer_values_match_multi_h() {
        assert_eq!(i32::from(CurlMCode::CallMultiPerform), -1);
        assert_eq!(i32::from(CurlMCode::Ok), 0);
        assert_eq!(i32::from(CurlMCode::BadHandle), 1);
        assert_eq!(i32::from(CurlMCode::BadEasyHandle), 2);
        assert_eq!(i32::from(CurlMCode::OutOfMemory), 3);
        assert_eq!(i32::from(CurlMCode::InternalError), 4);
        assert_eq!(i32::from(CurlMCode::BadSocket), 5);
        assert_eq!(i32::from(CurlMCode::UnknownOption), 6);
        assert_eq!(i32::from(CurlMCode::AddedAlready), 7);
        assert_eq!(i32::from(CurlMCode::RecursiveApiCall), 8);
        assert_eq!(i32::from(CurlMCode::WakeupFailure), 9);
        assert_eq!(i32::from(CurlMCode::BadFunctionArgument), 10);
        assert_eq!(i32::from(CurlMCode::AbortedByCallback), 11);
        assert_eq!(i32::from(CurlMCode::UnrecoverablePoll), 12);
    }

    #[test]
    fn curlmsg_values_match_multi_h() {
        assert_eq!(CurlMsg::None.to_i32(), 0);
        assert_eq!(CurlMsg::Done.to_i32(), 1);
        assert_eq!(CurlMsg::Last.to_i32(), 2);
    }

    #[test]
    fn curlmoption_values_and_try_from_roundtrip() {
        assert_eq!(CurlMOption::SocketFunction.to_i32(), 1);
        assert_eq!(CurlMOption::SocketData.to_i32(), 2);
        assert_eq!(CurlMOption::Pipelining.to_i32(), 3);
        assert_eq!(CurlMOption::TimerFunction.to_i32(), 4);
        assert_eq!(CurlMOption::MaxTotalConnections.to_i32(), 13);
        assert_eq!(CurlMOption::PushFunction.to_i32(), 14);
        assert_eq!(CurlMOption::MaxConcurrentStreams.to_i32(), 16);
        assert_eq!(CurlMOption::NotifyFunction.to_i32(), 18);
        assert_eq!(CurlMOption::NotifyData.to_i32(), 19);
        // Every 1..=19 id round-trips; 0 and 20 are unknown.
        for raw in 1..=19 {
            let opt = CurlMOption::try_from(raw).expect("known option id");
            assert_eq!(opt.to_i32(), raw);
        }
        assert_eq!(CurlMOption::try_from(0), Err(0));
        assert_eq!(CurlMOption::try_from(20), Err(20));
    }

    #[test]
    fn curlminfo_values() {
        assert_eq!(CurlMInfo::XfersCurrent as i32, 1);
        assert_eq!(CurlMInfo::XfersRunning as i32, 2);
        assert_eq!(CurlMInfo::XfersPending as i32, 3);
        assert_eq!(CurlMInfo::XfersDone as i32, 4);
        assert_eq!(CurlMInfo::XfersAdded as i32, 5);
    }

    // -----------------------------------------------------------------------
    // Handle management (`curl_multi_add_handle` / `_remove_handle`).
    // -----------------------------------------------------------------------

    #[test]
    fn add_remove_and_info_counts() {
        let mut multi = Multi::new();
        assert_eq!(multi.running_handles(), 0);
        assert_eq!(multi.get(CurlMInfo::XfersAdded), 0);

        let id = multi
            .add_handle(EasyHandle::new(DefaultDriver))
            .expect("add");
        assert_eq!(id, EasyId(0));
        assert_eq!(multi.running_handles(), 1);
        assert_eq!(multi.get(CurlMInfo::XfersCurrent), 1);
        assert_eq!(multi.get(CurlMInfo::XfersRunning), 1);
        assert_eq!(multi.get(CurlMInfo::XfersAdded), 1);
        assert_eq!(multi.handles(), vec![EasyId(0)]);

        let back = multi.remove_handle(id).expect("remove");
        assert_eq!(back.id(), None, "mid is cleared on removal");
        assert_eq!(multi.running_handles(), 0);
        assert!(matches!(
            multi.remove_handle(id),
            Err(CurlMCode::BadEasyHandle)
        ));
    }

    #[test]
    fn add_handle_with_existing_mid_is_added_already() {
        let mut multi = Multi::new();
        let mut easy = EasyHandle::new(DefaultDriver);
        easy.mid = Some(EasyId(42)); // pretend it already belongs to a multi handle
        assert!(matches!(
            multi.add_handle(easy),
            Err(CurlMCode::AddedAlready)
        ));
    }

    #[test]
    fn empty_handle_queries_are_benign() {
        let mut multi = Multi::new();
        assert!(multi.info_read().is_none());
        assert_eq!(multi.messages_in_queue(), 0);
        assert!(matches!(
            multi.remove_handle(EasyId(123)),
            Err(CurlMCode::BadEasyHandle)
        ));
        assert_eq!(multi.unpause(EasyId(123)), CurlMCode::BadEasyHandle);
        assert!(multi.get_handle(EasyId(123)).is_none());
    }

    // -----------------------------------------------------------------------
    // Options (`curl_multi_setopt`).
    // -----------------------------------------------------------------------

    #[test]
    fn setopt_pipelining_toggles_multiplexing() {
        let mut multi = Multi::new();
        assert!(!multi.multiplexing);
        assert_eq!(
            multi.setopt(
                CurlMOption::Pipelining,
                MultiOptionValue::Long(CURLPIPE_MULTIPLEX)
            ),
            CurlMCode::Ok
        );
        assert!(multi.multiplexing);
        assert_eq!(
            multi.setopt(
                CurlMOption::Pipelining,
                MultiOptionValue::Long(CURLPIPE_NOTHING)
            ),
            CurlMCode::Ok
        );
        assert!(!multi.multiplexing);
    }

    #[test]
    fn setopt_numeric_limits_and_clamping() {
        let mut multi = Multi::new();
        assert_eq!(
            multi.setopt(CurlMOption::MaxConnects, MultiOptionValue::Long(8)),
            CurlMCode::Ok
        );
        assert_eq!(multi.maxconnects, 8);
        assert_eq!(
            multi.setopt(CurlMOption::MaxTotalConnections, MultiOptionValue::Long(4)),
            CurlMCode::Ok
        );
        assert_eq!(multi.max_total_connections, 4);
        // Out-of-range MaxConnects → BadFunctionArgument.
        assert_eq!(
            multi.setopt(CurlMOption::MaxConnects, MultiOptionValue::Long(-1)),
            CurlMCode::BadFunctionArgument
        );
        // Concurrent-streams clamps <1 to the default of 100, accepts in-range.
        assert_eq!(
            multi.setopt(CurlMOption::MaxConcurrentStreams, MultiOptionValue::Long(0)),
            CurlMCode::Ok
        );
        assert_eq!(multi.max_concurrent_streams, 100);
        assert_eq!(
            multi.setopt(
                CurlMOption::MaxConcurrentStreams,
                MultiOptionValue::Long(250)
            ),
            CurlMCode::Ok
        );
        assert_eq!(multi.max_concurrent_streams, 250);
    }

    #[test]
    fn setopt_function_options_and_unknown_ids() {
        let mut multi = Multi::new();
        // Function-pointer options rejected when supplied a numeric value.
        assert_eq!(
            multi.setopt(CurlMOption::SocketFunction, MultiOptionValue::Long(0)),
            CurlMCode::BadFunctionArgument
        );
        // Unknown raw ids report UnknownOption; known ids delegate to setopt.
        assert_eq!(
            multi.setopt_raw(9999, MultiOptionValue::Long(0)),
            CurlMCode::UnknownOption
        );
        assert_eq!(
            multi.setopt_raw(CurlMOption::MaxConnects.to_i32(), MultiOptionValue::Long(3)),
            CurlMCode::Ok
        );
        assert_eq!(multi.maxconnects, 3);
    }

    // -----------------------------------------------------------------------
    // Driving a single transfer (`curl_multi_perform`).
    // -----------------------------------------------------------------------

    #[test]
    fn perform_drives_default_driver_to_done() {
        let mut multi = Multi::new();
        let id = multi.add_handle(EasyHandle::new(DefaultDriver)).unwrap();
        let (running, code) = multi.perform();
        assert_eq!(code, CurlMCode::Ok);
        assert_eq!(running, 0);

        let msg = multi.info_read().expect("a completion message");
        assert_eq!(msg.msg, CurlMsg::Done);
        assert_eq!(msg.easy, id);
        assert_eq!(msg.result, CurlCode::Ok);
        assert!(multi.info_read().is_none());
        // The handle stays in MSGSENT until removed, matching the C API.
        assert!(multi.get_handle(id).unwrap().is_msgsent());
    }

    #[test]
    fn state_machine_visits_expected_phases() {
        let (driver, log) = RecordingDriver::new();
        let mut multi = Multi::new();
        multi.add_handle(EasyHandle::new(driver)).unwrap();
        multi.perform();
        let seen = log.lock().unwrap().clone();
        // CONNECT → PROTOCONNECT → DO → PERFORMING → DONE.
        assert_eq!(seen, ["connect", "protoconnect", "do", "perform", "done"]);
    }

    #[test]
    fn failing_connect_propagates_error_result() {
        let mut multi = Multi::new();
        let id = multi
            .add_handle(EasyHandle::new(FailingDriver {
                code: CurlCode::CouldntConnect,
            }))
            .unwrap();
        multi.perform();
        let msg = multi.info_read().expect("completion");
        assert_eq!(msg.msg, CurlMsg::Done);
        assert_eq!(msg.result, CurlCode::CouldntConnect);
        let h = multi.get_handle(id).unwrap();
        assert_eq!(h.result(), CurlCode::CouldntConnect);
        assert!(h.premature, "a failed transfer tears down prematurely");
        assert!(h.is_msgsent());
    }

    #[test]
    fn redirect_follows_and_decrements_budget() {
        let mut multi = Multi::new();
        let driver = RedirectDriver {
            performs: 0,
            target: "http://example.com/next".to_string(),
        };
        let id = multi
            .add_handle(EasyHandle::new(driver).with_max_redirects(5))
            .unwrap();
        multi.perform();
        let h = multi.get_handle(id).unwrap();
        assert!(h.is_msgsent());
        assert_eq!(h.result(), CurlCode::Ok);
        assert_eq!(h.pending_redirect(), Some("http://example.com/next"));
        assert_eq!(
            h.follows_remaining, 4,
            "one redirect consumed one unit of budget"
        );
        assert_eq!(multi.info_read().unwrap().result, CurlCode::Ok);
    }

    #[test]
    fn redirect_budget_exhaustion_stops_following() {
        let mut multi = Multi::new();
        let driver = AlwaysRedirectDriver {
            target: "http://example.com/loop".to_string(),
        };
        let id = multi
            .add_handle(EasyHandle::new(driver).with_max_redirects(1))
            .unwrap();
        multi.perform();
        let h = multi.get_handle(id).unwrap();
        assert!(h.is_msgsent());
        assert_eq!(h.follows_remaining, 0, "budget is exhausted, chain stops");
        assert_eq!(multi.info_read().unwrap().result, CurlCode::Ok);
    }

    #[test]
    fn slow_connect_requires_multiple_cranks() {
        let mut multi = Multi::new();
        let id = multi
            .add_handle(EasyHandle::new(SlowConnectDriver {
                attempts: 0,
                ready_at: 3,
            }))
            .unwrap();

        // First crank advances to CONNECTING, then waits.
        let (running, _) = multi.perform();
        assert_eq!(running, 1);
        assert_eq!(multi.get_handle(id).unwrap().state(), MState::Connecting);

        // The classic perform/poll loop must drive it to completion.
        let mut cranks = 1;
        loop {
            let (running, code) = multi.perform();
            assert_eq!(code, CurlMCode::Ok);
            cranks += 1;
            if running == 0 {
                break;
            }
            let (_fds, wcode) = multi.wait(Duration::from_millis(1));
            assert_eq!(wcode, CurlMCode::Ok);
            assert!(cranks < 100, "the loop must terminate");
        }
        assert!(multi.get_handle(id).unwrap().is_msgsent());
        assert_eq!(multi.info_read().unwrap().result, CurlCode::Ok);
    }

    #[test]
    fn pending_transfer_is_promoted_and_completes() {
        let mut multi = Multi::new();
        let id = multi
            .add_handle(EasyHandle::new(PendingThenConnectDriver {
                tries: 0,
                ready_at: 2,
            }))
            .unwrap();

        // First crank parks the transfer in PENDING (no slot yet).
        multi.perform();
        assert_eq!(multi.get_handle(id).unwrap().state(), MState::Pending);
        assert_eq!(multi.get(CurlMInfo::XfersPending), 1);

        // Second crank promotes PENDING → CONNECT and runs to completion.
        let (running, _) = multi.perform();
        assert_eq!(running, 0);
        assert!(multi.get_handle(id).unwrap().is_msgsent());
        assert_eq!(multi.info_read().unwrap().result, CurlCode::Ok);
    }

    #[tokio::test]
    async fn perform_async_completes_default_driver() {
        let mut multi = Multi::new();
        let id = multi.add_handle(EasyHandle::new(DefaultDriver)).unwrap();
        let (running, code) = multi.perform_async().await;
        assert_eq!((running, code), (0, CurlMCode::Ok));
        assert_eq!(multi.info_read().unwrap().easy, id);
    }

    // -----------------------------------------------------------------------
    // Concurrency (`Multi::run` / `run_async`) — 2+ transfers in parallel.
    // -----------------------------------------------------------------------

    #[test]
    fn run_completes_multiple_transfers() {
        let mut multi = Multi::new();
        let a = multi.add_handle(EasyHandle::new(DefaultDriver)).unwrap();
        let b = multi.add_handle(EasyHandle::new(DefaultDriver)).unwrap();
        let c = multi.add_handle(EasyHandle::new(DefaultDriver)).unwrap();
        assert_eq!(multi.running_handles(), 3);

        assert_eq!(multi.run(), CurlMCode::Ok);
        assert_eq!(multi.running_handles(), 0);
        assert_eq!(multi.messages_in_queue(), 3);

        let mut done: std::collections::HashSet<EasyId> = std::collections::HashSet::new();
        while let Some(msg) = multi.info_read() {
            assert_eq!(msg.msg, CurlMsg::Done);
            assert_eq!(msg.result, CurlCode::Ok);
            done.insert(msg.easy);
        }
        assert_eq!(done, [a, b, c].into_iter().collect());
        assert_eq!(
            multi.get_handle(a).map(EasyHandle::state),
            Some(MState::Msgsent)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_async_executes_transfers_in_parallel() {
        let mut multi = Multi::new();
        for _ in 0..4 {
            multi
                .add_handle(EasyHandle::new(SleepyDriver { millis: 25 }))
                .unwrap();
        }
        assert_eq!(multi.running_handles(), 4);

        let start = std::time::Instant::now();
        assert_eq!(multi.run_async().await, CurlMCode::Ok);
        let elapsed = start.elapsed();

        assert_eq!(multi.running_handles(), 0);
        assert_eq!(multi.messages_in_queue(), 4);
        // Four 25 ms transfers run concurrently, finishing far under the 100 ms
        // serial worst case.
        assert!(
            elapsed < Duration::from_millis(300),
            "elapsed = {elapsed:?}"
        );
        while let Some(m) = multi.info_read() {
            assert_eq!(m.result, CurlCode::Ok);
        }
    }

    // -----------------------------------------------------------------------
    // Notifications (`lib/multi_ntfy.c`).
    // -----------------------------------------------------------------------

    #[test]
    fn easy_done_notification_is_delivered() {
        let events = Arc::new(Mutex::new(Vec::<(u32, EasyId)>::new()));
        let sink = Arc::clone(&events);
        let mut multi = Multi::new();
        multi.set_notify_function(Some(Box::new(move |kind, id| {
            sink.lock().unwrap().push((kind, id));
        })));
        assert_eq!(multi.notify_enable(CURLMNOTIFY_EASY_DONE), CurlMCode::Ok);

        let id = multi.add_handle(EasyHandle::new(DefaultDriver)).unwrap();
        multi.perform();

        let seen = events.lock().unwrap().clone();
        assert_eq!(seen, vec![(CURLMNOTIFY_EASY_DONE, id)]);
    }

    #[test]
    fn notification_not_delivered_when_disabled() {
        let events = Arc::new(Mutex::new(Vec::<(u32, EasyId)>::new()));
        let sink = Arc::clone(&events);
        let mut multi = Multi::new();
        multi.set_notify_function(Some(Box::new(move |kind, id| {
            sink.lock().unwrap().push((kind, id));
        })));
        // EASY_DONE never enabled → nothing enqueued.
        multi.add_handle(EasyHandle::new(DefaultDriver)).unwrap();
        multi.perform();
        assert!(events.lock().unwrap().is_empty());
    }

    #[test]
    fn notify_enable_rejects_unknown_type() {
        let mut multi = Multi::new();
        assert_eq!(multi.notify_enable(999), CurlMCode::UnknownOption);
        assert_eq!(multi.notify_disable(999), CurlMCode::UnknownOption);
        assert_eq!(multi.notify_enable(CURLMNOTIFY_INFO_READ), CurlMCode::Ok);
        assert_eq!(multi.notify_disable(CURLMNOTIFY_EASY_DONE), CurlMCode::Ok);
    }

    // -----------------------------------------------------------------------
    // Socket API (`curl_multi_fdset` / `_assign`) — multi_ev.c.
    // -----------------------------------------------------------------------

    #[test]
    fn socket_interest_updates_fdset_and_fires_callback() {
        let calls = Arc::new(Mutex::new(
            Vec::<(EasyId, Socket, i32, Option<usize>)>::new(),
        ));
        let sink = Arc::clone(&calls);
        let mut multi = Multi::new();
        multi.set_socket_function(Some(Box::new(move |id, s, what, sockp| {
            sink.lock().unwrap().push((id, s, what, sockp));
            0
        })));

        // Assign a per-socket token, then express INOUT interest.
        assert_eq!(multi.assign(7, 99), CurlMCode::Ok);
        multi.set_socket_interest(EasyId(0), 7, CURL_POLL_INOUT);
        let fds = multi.fdset();
        assert_eq!(fds.read, vec![7]);
        assert_eq!(fds.write, vec![7]);
        assert_eq!(fds.max_fd, 7);

        // Dropping interest removes the socket and reports REMOVE.
        multi.set_socket_interest(EasyId(0), 7, CURL_POLL_REMOVE);
        let fds = multi.fdset();
        assert!(fds.read.is_empty() && fds.write.is_empty());
        assert_eq!(fds.max_fd, CURL_SOCKET_BAD);

        let seen = calls.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![
                (EasyId(0), 7, CURL_POLL_INOUT, Some(99)),
                (EasyId(0), 7, CURL_POLL_REMOVE, Some(99)),
            ]
        );
    }

    #[test]
    fn assign_rejects_bad_socket() {
        let mut multi = Multi::new();
        assert_eq!(multi.assign(CURL_SOCKET_BAD, 1), CurlMCode::BadSocket);
    }

    #[test]
    fn socket_action_cranks_transfers() {
        let mut multi = Multi::new();
        multi.add_handle(EasyHandle::new(DefaultDriver)).unwrap();
        let (running, code) = multi.socket_action(CURL_SOCKET_TIMEOUT, 0);
        assert_eq!(code, CurlMCode::Ok);
        assert_eq!(running, 0);
        assert_eq!(multi.info_read().unwrap().result, CurlCode::Ok);
    }

    // -----------------------------------------------------------------------
    // Poll / wait / wakeup (`curl_multi_poll` / `_wait` / `_wakeup`).
    // -----------------------------------------------------------------------

    #[test]
    fn poll_and_wait_fast_paths() {
        let mut multi = Multi::new();
        // Nothing running → immediate return with zero fds.
        assert_eq!(multi.poll(Duration::from_millis(50)), (0, CurlMCode::Ok));
        assert_eq!(multi.wait(Duration::from_millis(50)), (0, CurlMCode::Ok));
        // Zero timeout returns immediately even with a runnable handle.
        multi
            .add_handle(EasyHandle::new(SlowConnectDriver {
                attempts: 0,
                ready_at: 99,
            }))
            .unwrap();
        multi.perform(); // parks in CONNECTING (runnable)
        assert_eq!(multi.wait(Duration::ZERO), (0, CurlMCode::Ok));
        assert_eq!(multi.wakeup(), CurlMCode::Ok);
    }

    #[test]
    fn wakeup_interrupts_a_blocking_poll() {
        let mut multi = Multi::new();
        multi
            .add_handle(EasyHandle::new(SlowConnectDriver {
                attempts: 0,
                ready_at: u32::MAX,
            }))
            .unwrap();
        multi.perform(); // runnable, parked forever in CONNECTING

        // Signal the wakeup primitive from another thread (test is in-module, so
        // it can clone the private `Arc<Notify>`). This proves poll observes it.
        let waker = Arc::clone(&multi.wakeup);
        let notifier = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            waker.notify_one();
        });

        let start = std::time::Instant::now();
        let (fds, code) = multi.poll(Duration::from_secs(10));
        let elapsed = start.elapsed();
        notifier.join().unwrap();

        assert_eq!((fds, code), (0, CurlMCode::Ok));
        assert!(
            elapsed < Duration::from_secs(5),
            "poll should be woken early, took {elapsed:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Shared caches (`curl_share` model, AAP §0.3.2).
    // -----------------------------------------------------------------------

    #[test]
    fn dns_cache_insert_lookup_and_expiry() {
        let mut dns = DnsCache::default();
        assert!(dns.is_empty());
        dns.insert("example.com", 443, vec!["93.184.216.34".to_string()], None);
        assert_eq!(
            dns.lookup("example.com", 443),
            Some(vec!["93.184.216.34".to_string()])
        );
        assert_eq!(
            dns.lookup("example.com", 80),
            None,
            "port is part of the key"
        );
        assert_eq!(dns.len(), 1);

        // An entry with a tiny TTL is pruned on access once expired.
        dns.insert(
            "stale.example",
            443,
            vec!["10.0.0.1".to_string()],
            Some(Duration::from_millis(1)),
        );
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(dns.lookup("stale.example", 443), None);
    }

    #[test]
    fn conn_cache_enforces_cap() {
        let mut c = ConnCache::new(2);
        assert!(c.try_acquire());
        assert!(c.try_acquire());
        assert!(!c.try_acquire(), "cap of 2 reached");
        assert_eq!(c.in_use(), 2);
        c.release();
        assert_eq!(c.in_use(), 1);
        assert!(c.try_acquire());

        // A cap of 0 means unlimited.
        let mut unlimited = ConnCache::new(0);
        for _ in 0..100 {
            assert!(unlimited.try_acquire());
        }
        unlimited.clear();
        assert_eq!(unlimited.in_use(), 0);
    }

    #[test]
    fn shared_bundle_shares_underlying_state() {
        let shared = Shared::new(4);
        let clone = shared.clone();
        shared
            .dns
            .lock()
            .unwrap()
            .insert("h", 1, vec!["a".to_string()], None);
        // The clone observes the same Arc-shared DNS cache.
        assert_eq!(
            clone.dns.lock().unwrap().lookup("h", 1),
            Some(vec!["a".to_string()])
        );

        // Two multi handles can share one bundle (fine-grained per-type locks).
        let m1 = Multi::with_shared(shared.clone());
        let m2 = Multi::with_shared(shared);
        assert_eq!(m1.shared().dns.lock().unwrap().len(), 1);
        assert_eq!(m2.shared().conns.lock().unwrap().in_use(), 0);
    }

    #[test]
    fn cleanup_consumes_handle() {
        let mut multi = Multi::new();
        multi.add_handle(EasyHandle::new(DefaultDriver)).unwrap();
        assert_eq!(multi.cleanup(), CurlMCode::Ok);
    }
}
