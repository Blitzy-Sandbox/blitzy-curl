//! Socket readiness abstraction — Rust rewrite of `lib/select.c`.
//!
//! This module provides the central polling/select abstraction used throughout
//! the curl-rs library. It replaces C `poll()`/`select()` system calls with
//! Tokio-based async I/O readiness checking via [`tokio::io::unix::AsyncFd`]
//! and [`tokio::io::Interest`].
//!
//! # Key Types
//!
//! * [`CurlSelect`] — Bitflags matching C `CURL_CSELECT_*` constants
//! * [`CurlPoll`] — Poll action constants matching C `CURL_POLL_*` values
//! * [`PollFd`] — Per-fd poll descriptor (mirrors C `struct pollfd`)
//! * [`CurlWaitFd`] — Wait descriptor for `curl_multi_wait` (mirrors C `struct curl_waitfd`)
//! * [`EasyPollset`] — Per-easy-handle socket interest tracking
//! * [`Pollfds`] — Growable collection of [`PollFd`] entries for multi-handle polling
//! * [`Waitfds`] — Fixed-capacity collection of [`CurlWaitFd`] entries
//!
//! # Functions
//!
//! * [`socket_check`] — Async socket readiness check (replaces C `Curl_socket_check`)
//! * [`poll`] — Async poll over a slice of [`PollFd`] (replaces C `Curl_poll`)
//! * [`wait_ms`] — Synchronous blocking sleep (replaces C `curlx_wait_ms`)

use std::os::unix::io::RawFd;
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::io::Ready;
use tokio::time::{sleep, timeout};

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// CurlSelect — bitflags matching CURL_CSELECT_*
// ---------------------------------------------------------------------------

/// Bitflag type representing socket readiness conditions.
///
/// Maps 1:1 to the C `CURL_CSELECT_*` constants defined in `include/curl/multi.h`.
/// Integer values are ABI-stable for FFI compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CurlSelect(u32);

impl CurlSelect {
    /// Socket is readable (`CURL_CSELECT_IN = 0x01`).
    pub const IN: CurlSelect = CurlSelect(0x01);
    /// Socket is writable (`CURL_CSELECT_OUT = 0x02`).
    pub const OUT: CurlSelect = CurlSelect(0x02);
    /// An error condition occurred (`CURL_CSELECT_ERR = 0x04`).
    pub const ERR: CurlSelect = CurlSelect(0x04);
    /// Second read socket is readable (`CURL_CSELECT_IN2 = 0x08`).
    /// This is an internal-only constant (not in the public C header).
    pub const IN2: CurlSelect = CurlSelect(0x08);

    /// Construct an empty (no flags set) value.
    #[inline]
    pub fn empty() -> Self {
        CurlSelect(0)
    }

    /// Check whether this value contains all of the given flags.
    #[inline]
    pub fn contains(self, other: CurlSelect) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Return the raw integer representation.
    #[inline]
    pub fn bits(self) -> u32 {
        self.0
    }
}

impl std::ops::BitOr for CurlSelect {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        CurlSelect(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CurlSelect {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for CurlSelect {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        CurlSelect(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for CurlSelect {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl std::ops::Not for CurlSelect {
    type Output = Self;
    #[inline]
    fn not(self) -> Self {
        CurlSelect(!self.0)
    }
}

impl From<u32> for CurlSelect {
    #[inline]
    fn from(v: u32) -> Self {
        CurlSelect(v)
    }
}

// ---------------------------------------------------------------------------
// CurlPoll — action constants matching CURL_POLL_*
// ---------------------------------------------------------------------------

/// Poll action constants matching C `CURL_POLL_*` values from `include/curl/multi.h`.
///
/// These are used as per-socket action descriptors in the multi interface
/// socket callback and in [`EasyPollset`] action tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurlPoll(u8);

impl CurlPoll {
    /// No activity requested (`CURL_POLL_NONE = 0`).
    pub const NONE: CurlPoll = CurlPoll(0);
    /// Wait for incoming data (`CURL_POLL_IN = 1`).
    pub const IN: CurlPoll = CurlPoll(1);
    /// Wait for outgoing data (`CURL_POLL_OUT = 2`).
    pub const OUT: CurlPoll = CurlPoll(2);
    /// Wait for incoming and outgoing data (`CURL_POLL_INOUT = 3`).
    pub const INOUT: CurlPoll = CurlPoll(3);
    /// Remove socket from polling (`CURL_POLL_REMOVE = 4`).
    pub const REMOVE: CurlPoll = CurlPoll(4);

    /// Return the raw integer representation.
    #[inline]
    pub fn as_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for CurlPoll {
    #[inline]
    fn from(v: u8) -> Self {
        CurlPoll(v)
    }
}

impl std::ops::BitOr for CurlPoll {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        CurlPoll(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for CurlPoll {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        CurlPoll(self.0 & rhs.0)
    }
}

// ---------------------------------------------------------------------------
// CURL_WAIT_POLL* constants for CurlWaitFd events
// ---------------------------------------------------------------------------

/// Readable event flag for [`CurlWaitFd`] (`CURL_WAIT_POLLIN = 0x0001`).
const CURL_WAIT_POLLIN: u16 = 0x0001;
/// Priority event flag for [`CurlWaitFd`] (`CURL_WAIT_POLLPRI = 0x0002`).
#[allow(dead_code)]
const CURL_WAIT_POLLPRI: u16 = 0x0002;
/// Writable event flag for [`CurlWaitFd`] (`CURL_WAIT_POLLOUT = 0x0004`).
const CURL_WAIT_POLLOUT: u16 = 0x0004;

// ---------------------------------------------------------------------------
// POLLIN / POLLOUT constants for PollFd events
// ---------------------------------------------------------------------------

/// Standard poll-in event (readable).
const POLLIN: u16 = 0x0001;
/// Standard poll-out event (writable).
const POLLOUT: u16 = 0x0004;
/// Standard poll error event.
const POLLERR: u16 = 0x0008;
/// Standard poll hangup event.
const POLLHUP: u16 = 0x0010;
/// Standard poll invalid fd event.
const POLLNVAL: u16 = 0x0020;
/// Priority data event.
const POLLPRI: u16 = 0x0002;
/// Normal read band (alias of POLLIN on most systems).
const POLLRDNORM: u16 = 0x0040;
/// Normal write band (alias of POLLOUT on most systems).
const POLLWRNORM: u16 = 0x0100;
/// Priority read band.
const POLLRDBAND: u16 = 0x0080;

// ---------------------------------------------------------------------------
// Sentinel value for invalid / absent sockets
// ---------------------------------------------------------------------------

/// Sentinel value indicating no socket is present (matches C `CURL_SOCKET_BAD`).
const CURL_SOCKET_BAD: RawFd = -1;

// ---------------------------------------------------------------------------
// PollFd — per-fd poll descriptor
// ---------------------------------------------------------------------------

/// Per-file-descriptor poll descriptor, mirroring C `struct pollfd`.
///
/// Used by [`poll`] to track which events to monitor and which events
/// actually occurred on each file descriptor.
#[derive(Debug, Clone, Copy)]
pub struct PollFd {
    /// The raw file descriptor.
    pub fd: RawFd,
    /// Requested events (bitmask of `POLLIN`, `POLLOUT`, etc.).
    pub events: u16,
    /// Returned events filled in by [`poll`].
    pub revents: u16,
}

impl PollFd {
    /// Create a new `PollFd` for the given file descriptor and requested events.
    #[inline]
    pub fn new(fd: RawFd, events: u16) -> Self {
        PollFd {
            fd,
            events,
            revents: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// CurlWaitFd — wait descriptor for curl_multi_wait
// ---------------------------------------------------------------------------

/// Per-fd wait descriptor matching C `struct curl_waitfd` from `include/curl/multi.h`.
///
/// Events use `CURL_WAIT_POLLIN` / `CURL_WAIT_POLLOUT` / `CURL_WAIT_POLLPRI`
/// constants (distinct from the standard POLLIN/POLLOUT values).
#[derive(Debug, Clone, Copy)]
pub struct CurlWaitFd {
    /// The raw file descriptor.
    pub fd: RawFd,
    /// Requested events (bitmask of `CURL_WAIT_POLL*` constants).
    pub events: u16,
    /// Returned events (filled in after waiting).
    pub revents: u16,
}

// ---------------------------------------------------------------------------
// EasyPollset — per-easy-handle socket interest tracking
// ---------------------------------------------------------------------------

/// Default inline capacity for socket tracking (matches C `EZ_POLLSET_DEF_COUNT`).
const EZ_POLLSET_DEF_COUNT: usize = 2;

/// Per-easy-handle pollset tracking which sockets to poll for which actions.
///
/// Replaces C `struct easy_pollset`. Starts with a small inline capacity
/// ([`EZ_POLLSET_DEF_COUNT`] = 2) and grows dynamically when needed.
/// Each entry pairs a socket fd with a [`CurlPoll`] action bitmask.
#[derive(Debug, Clone)]
pub struct EasyPollset {
    /// Socket file descriptors.
    sockets: Vec<RawFd>,
    /// Per-socket action flags (indexed parallel to `sockets`).
    actions: Vec<u8>,
}

impl EasyPollset {
    /// Create a new, empty pollset with default inline capacity.
    pub fn new() -> Self {
        EasyPollset {
            sockets: Vec::with_capacity(EZ_POLLSET_DEF_COUNT),
            actions: Vec::with_capacity(EZ_POLLSET_DEF_COUNT),
        }
    }

    /// Clear all tracked sockets (set count to zero).
    pub fn reset(&mut self) {
        self.sockets.clear();
        self.actions.clear();
    }

    /// Release any heap-allocated resources and reset to empty state.
    pub fn cleanup(&mut self) {
        self.sockets = Vec::with_capacity(EZ_POLLSET_DEF_COUNT);
        self.actions = Vec::with_capacity(EZ_POLLSET_DEF_COUNT);
    }

    /// Move all entries from `other` into `self`, leaving `other` empty.
    ///
    /// This replaces all entries in `self` with those from `other`.
    pub fn move_from(&mut self, other: &mut EasyPollset) {
        self.cleanup();
        std::mem::swap(&mut self.sockets, &mut other.sockets);
        std::mem::swap(&mut self.actions, &mut other.actions);
        other.reset();
    }

    /// Change the poll flags for a socket.
    ///
    /// If the socket is already tracked, `add_flags` are OR-ed in and
    /// `remove_flags` are AND-NOT-ed out. If all flags are cleared the
    /// socket is removed. If the socket is not present and `add_flags`
    /// is non-zero, a new entry is appended.
    ///
    /// Returns `Err(CurlError::BadFunctionArgument)` if `sock` is invalid
    /// (i.e. `CURL_SOCKET_BAD`), or `Err(CurlError::OutOfMemory)` on
    /// allocation failure (not expected with Rust's Vec but preserved for
    /// API parity).
    pub fn change(
        &mut self,
        sock: RawFd,
        add_flags: u8,
        remove_flags: u8,
    ) -> Result<(), CurlError> {
        if sock == CURL_SOCKET_BAD || sock < 0 {
            return Err(CurlError::BadFunctionArgument);
        }

        // Look for existing entry
        for i in 0..self.sockets.len() {
            if self.sockets[i] == sock {
                self.actions[i] &= !remove_flags;
                self.actions[i] |= add_flags;
                // If all flags cleared, remove the entry
                if self.actions[i] == 0 {
                    self.sockets.remove(i);
                    self.actions.remove(i);
                }
                return Ok(());
            }
        }

        // Not present — add new entry if add_flags is non-zero
        if add_flags != 0 {
            self.sockets.push(sock);
            self.actions.push(add_flags);
        }

        Ok(())
    }

    /// Set the poll flags for a socket.
    ///
    /// This is a convenience wrapper around [`change`](Self::change) that sets
    /// the socket to monitor for input and/or output.
    pub fn set(
        &mut self,
        sock: RawFd,
        do_in: bool,
        do_out: bool,
    ) -> Result<(), CurlError> {
        let add_flags = if do_in { CurlPoll::IN.as_u8() } else { 0 }
            | if do_out { CurlPoll::OUT.as_u8() } else { 0 };
        let remove_flags = if !do_in { CurlPoll::IN.as_u8() } else { 0 }
            | if !do_out { CurlPoll::OUT.as_u8() } else { 0 };
        self.change(sock, add_flags, remove_flags)
    }

    /// Poll all tracked sockets for readiness, blocking for at most `timeout`.
    ///
    /// Returns the number of sockets that became ready, or `0` on timeout.
    /// If no sockets are tracked, sleeps for the timeout duration and returns 0.
    pub async fn poll(&self, timeout_dur: Duration) -> Result<i32, CurlError> {
        if self.sockets.is_empty() {
            wait_ms_async(timeout_dur).await;
            return Ok(0);
        }

        let mut pfds: Vec<PollFd> = Vec::with_capacity(self.sockets.len());
        for i in 0..self.sockets.len() {
            let mut events: u16 = 0;
            if self.actions[i] & CurlPoll::IN.as_u8() != 0 {
                events |= POLLIN;
            }
            if self.actions[i] & CurlPoll::OUT.as_u8() != 0 {
                events |= POLLOUT;
            }
            if events != 0 {
                pfds.push(PollFd::new(self.sockets[i], events));
            }
        }

        poll(&mut pfds, timeout_dur).await
    }

    /// Check whether a specific socket has read and/or write interest.
    ///
    /// Returns `(want_read, want_write)`.
    pub fn check(&self, sock: RawFd) -> (bool, bool) {
        for i in 0..self.sockets.len() {
            if self.sockets[i] == sock {
                let want_read = self.actions[i] & CurlPoll::IN.as_u8() != 0;
                let want_write = self.actions[i] & CurlPoll::OUT.as_u8() != 0;
                return (want_read, want_write);
            }
        }
        (false, false)
    }

    /// Returns `true` if the pollset contains the given socket with read interest.
    pub fn want_recv(&self, sock: RawFd) -> bool {
        for i in 0..self.sockets.len() {
            if self.sockets[i] == sock && self.actions[i] & CurlPoll::IN.as_u8() != 0 {
                return true;
            }
        }
        false
    }

    /// Returns `true` if the pollset contains the given socket with write interest.
    pub fn want_send(&self, sock: RawFd) -> bool {
        for i in 0..self.sockets.len() {
            if self.sockets[i] == sock && self.actions[i] & CurlPoll::OUT.as_u8() != 0 {
                return true;
            }
        }
        false
    }

    /// Return the number of tracked sockets.
    #[inline]
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /// Returns `true` if no sockets are tracked.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }

    /// Return a slice of the tracked socket file descriptors.
    #[inline]
    pub fn sockets(&self) -> &[RawFd] {
        &self.sockets
    }

    /// Return a slice of the per-socket action flags.
    #[inline]
    pub fn actions(&self) -> &[u8] {
        &self.actions
    }
}

impl Default for EasyPollset {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Pollfds — growable collection of PollFd entries
// ---------------------------------------------------------------------------

/// Growable collection of [`PollFd`] entries for multi-handle polling.
///
/// Replaces C `struct curl_pollfds`. Supports initialization with a
/// pre-allocated static buffer and dynamic growth.
#[derive(Debug, Clone)]
pub struct Pollfds {
    /// Backing storage for pollfd entries.
    pfds: Vec<PollFd>,
    /// Number of entries currently in use.
    n: usize,
}

impl Pollfds {
    /// Create a new, empty `Pollfds` with the given initial capacity.
    pub fn new(capacity: usize) -> Self {
        Pollfds {
            pfds: Vec::with_capacity(capacity),
            n: 0,
        }
    }

    /// Reset the collection to empty without deallocating.
    pub fn reset(&mut self) {
        self.n = 0;
        self.pfds.clear();
    }

    /// Release resources and reset to empty state.
    pub fn cleanup(&mut self) {
        self.pfds = Vec::new();
        self.n = 0;
    }

    /// Add a single socket with the given events.
    ///
    /// Returns `Err(CurlError::OutOfMemory)` if the internal allocation
    /// would exceed `usize::MAX` entries (preserved for API parity with C).
    pub fn add_sock(&mut self, sock: RawFd, events: i16) -> Result<(), CurlError> {
        if self.n == usize::MAX {
            return Err(CurlError::OutOfMemory);
        }
        self.pfds.push(PollFd::new(sock, events as u16));
        self.n += 1;
        Ok(())
    }

    /// Add all sockets from an [`EasyPollset`], folding duplicate fds.
    ///
    /// For each socket in `ps`, the appropriate `POLLIN`/`POLLOUT` event flags
    /// are computed from the pollset action flags. If the socket is already
    /// present in `self`, its events are OR-ed together.
    pub fn add_ps(&mut self, ps: &EasyPollset) -> Result<(), CurlError> {
        for i in 0..ps.sockets.len() {
            let mut events: u16 = 0;
            if ps.actions[i] & CurlPoll::IN.as_u8() != 0 {
                events |= POLLIN;
            }
            if ps.actions[i] & CurlPoll::OUT.as_u8() != 0 {
                events |= POLLOUT;
            }
            if events != 0 {
                // Attempt to fold into an existing entry
                let sock = ps.sockets[i];
                let mut folded = false;
                for pfd in self.pfds.iter_mut() {
                    if pfd.fd == sock {
                        pfd.events |= events;
                        folded = true;
                        break;
                    }
                }
                if !folded {
                    self.pfds.push(PollFd::new(sock, events));
                    self.n += 1;
                }
            }
        }
        Ok(())
    }

    /// Return a mutable slice of the active entries.
    pub fn as_mut_slice(&mut self) -> &mut [PollFd] {
        &mut self.pfds[..self.n]
    }

    /// Return the number of active entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.n
    }

    /// Returns `true` if no entries are present.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
}

impl Default for Pollfds {
    fn default() -> Self {
        Self::new(8)
    }
}

// ---------------------------------------------------------------------------
// Waitfds — fixed-capacity collection of CurlWaitFd entries
// ---------------------------------------------------------------------------

/// Fixed-capacity collection of [`CurlWaitFd`] entries for `curl_multi_wait`.
///
/// Replaces C `struct Curl_waitfds`. Backed by a pre-allocated `Vec` of
/// fixed `count` capacity; entries are folded by socket fd to avoid duplicates.
#[derive(Debug, Clone)]
pub struct Waitfds {
    /// Backing storage for waitfd entries.
    wfds: Vec<CurlWaitFd>,
    /// Maximum capacity.
    count: usize,
}

impl Waitfds {
    /// Create a new `Waitfds` with the given maximum capacity.
    pub fn new(capacity: usize) -> Self {
        Waitfds {
            wfds: Vec::with_capacity(capacity),
            count: capacity,
        }
    }

    /// Add all sockets from an [`EasyPollset`] into the wait-fd collection.
    ///
    /// Returns the number of additional entries that *would have been* needed
    /// but could not fit (used for capacity estimation by the caller).
    pub fn add_ps(&mut self, ps: &EasyPollset) -> u32 {
        let mut need: u32 = 0;
        for i in 0..ps.sockets.len() {
            let mut events: u16 = 0;
            if ps.actions[i] & CurlPoll::IN.as_u8() != 0 {
                events |= CURL_WAIT_POLLIN;
            }
            if ps.actions[i] & CurlPoll::OUT.as_u8() != 0 {
                events |= CURL_WAIT_POLLOUT;
            }
            if events != 0 {
                need += self.add_sock_internal(ps.sockets[i], events);
            }
        }
        need
    }

    /// Return the number of entries currently in the collection.
    #[inline]
    pub fn len(&self) -> usize {
        self.wfds.len()
    }

    /// Returns `true` if no entries are present.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.wfds.is_empty()
    }

    /// Return a slice of the entries.
    pub fn as_slice(&self) -> &[CurlWaitFd] {
        &self.wfds
    }

    /// Return a mutable slice of the entries.
    pub fn as_mut_slice(&mut self) -> &mut [CurlWaitFd] {
        &mut self.wfds
    }

    /// Internal: add a socket, folding duplicates. Returns 1 if the entry
    /// could not fit (over capacity), 0 otherwise.
    fn add_sock_internal(&mut self, sock: RawFd, events: u16) -> u32 {
        // Try to fold into existing entry
        for wfd in self.wfds.iter_mut() {
            if wfd.fd == sock {
                wfd.events |= events;
                return 0;
            }
        }
        // Not found — add new entry if space permits
        if self.wfds.len() < self.count {
            self.wfds.push(CurlWaitFd {
                fd: sock,
                events,
                revents: 0,
            });
            return 1;
        }
        // Over capacity — report need
        1
    }
}

// ---------------------------------------------------------------------------
// socket_check — async socket readiness check
// ---------------------------------------------------------------------------

/// Asynchronously check socket readiness for reading and/or writing.
///
/// This replaces C `Curl_socket_check` which accepted up to two read sockets
/// and one write socket. If all socket arguments are `None`, the function
/// simply sleeps for the given `timeout` duration (matching C behavior when
/// all fds are `CURL_SOCKET_BAD`).
///
/// # Returns
///
/// A [`CurlSelect`] bitmask indicating which sockets are ready:
/// * `CurlSelect::IN` — `read_fd0` is readable
/// * `CurlSelect::IN2` — `read_fd1` is readable
/// * `CurlSelect::OUT` — `write_fd` is writable
/// * `CurlSelect::ERR` — an error condition occurred
///
/// Returns `CurlSelect::empty()` on timeout.
pub async fn socket_check(
    read_fd0: Option<RawFd>,
    read_fd1: Option<RawFd>,
    write_fd: Option<RawFd>,
    timeout_dur: Duration,
) -> Result<CurlSelect, CurlError> {
    // If no valid sockets, just sleep (matches C behavior)
    if read_fd0.is_none() && read_fd1.is_none() && write_fd.is_none() {
        wait_ms_async(timeout_dur).await;
        return Ok(CurlSelect::empty());
    }

    // Build a pollfd array from the provided sockets
    let mut pfds: Vec<PollFd> = Vec::with_capacity(3);
    let mut read0_idx: Option<usize> = None;
    let mut read1_idx: Option<usize> = None;
    let mut write_idx: Option<usize> = None;

    if let Some(fd) = read_fd0 {
        if fd != CURL_SOCKET_BAD {
            read0_idx = Some(pfds.len());
            pfds.push(PollFd::new(fd, POLLRDNORM | POLLIN | POLLRDBAND | POLLPRI));
        }
    }
    if let Some(fd) = read_fd1 {
        if fd != CURL_SOCKET_BAD {
            read1_idx = Some(pfds.len());
            pfds.push(PollFd::new(fd, POLLRDNORM | POLLIN | POLLRDBAND | POLLPRI));
        }
    }
    if let Some(fd) = write_fd {
        if fd != CURL_SOCKET_BAD {
            write_idx = Some(pfds.len());
            pfds.push(PollFd::new(fd, POLLWRNORM | POLLOUT | POLLPRI));
        }
    }

    if pfds.is_empty() {
        wait_ms_async(timeout_dur).await;
        return Ok(CurlSelect::empty());
    }

    let ready_count = poll(&mut pfds, timeout_dur).await?;
    if ready_count <= 0 {
        return Ok(CurlSelect::empty());
    }

    // Translate revents back to CurlSelect flags
    let mut result = CurlSelect::empty();

    if let Some(idx) = read0_idx {
        let rev = pfds[idx].revents;
        if rev & (POLLRDNORM | POLLIN | POLLERR | POLLHUP) != 0 {
            result |= CurlSelect::IN;
        }
        if rev & (POLLPRI | POLLNVAL) != 0 {
            result |= CurlSelect::ERR;
        }
    }
    if let Some(idx) = read1_idx {
        let rev = pfds[idx].revents;
        if rev & (POLLRDNORM | POLLIN | POLLERR | POLLHUP) != 0 {
            result |= CurlSelect::IN2;
        }
        if rev & (POLLPRI | POLLNVAL) != 0 {
            result |= CurlSelect::ERR;
        }
    }
    if let Some(idx) = write_idx {
        let rev = pfds[idx].revents;
        if rev & (POLLWRNORM | POLLOUT) != 0 {
            result |= CurlSelect::OUT;
        }
        if rev & (POLLERR | POLLHUP | POLLPRI | POLLNVAL) != 0 {
            result |= CurlSelect::ERR;
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// poll — async poll over a slice of PollFd
// ---------------------------------------------------------------------------

/// Asynchronously poll a slice of [`PollFd`] entries for I/O readiness.
///
/// This replaces C `Curl_poll` with Tokio-based async readiness checking.
/// Each fd in the slice is wrapped in a [`tokio::io::unix::AsyncFd`] to
/// monitor for the requested events. The function returns when any fd becomes
/// ready or the timeout expires.
///
/// # Returns
///
/// * On success: the number of entries in `ufds` whose `revents` field is non-zero
/// * On timeout: `0`
/// * On error: `Err(CurlError::UnrecoverablePoll)`
///
/// EINTR from the underlying poll is automatically retried (not exposed to
/// the caller), matching C `Curl_poll` behavior.
pub async fn poll(ufds: &mut [PollFd], timeout_dur: Duration) -> Result<i32, CurlError> {
    // Check if all fds are invalid
    let has_valid = ufds.iter().any(|pfd| pfd.fd != CURL_SOCKET_BAD && pfd.fd >= 0);
    if !has_valid {
        wait_ms_async(timeout_dur).await;
        return Ok(0);
    }

    // Clear all revents
    for pfd in ufds.iter_mut() {
        pfd.revents = 0;
    }

    // Use tokio::io::unix::AsyncFd to monitor each valid fd.
    // We spawn a future for each fd and race them all against the timeout.
    let poll_result = timeout(timeout_dur, poll_all_fds(ufds)).await;

    match poll_result {
        Ok(result) => result,
        Err(_elapsed) => {
            // Timeout — return 0
            Ok(0)
        }
    }
}

/// Internal: poll all file descriptors and return when any becomes ready.
///
/// This function creates an `AsyncFd` for each valid fd, checks readiness
/// for the requested interest (read/write), and fills in `revents`.
/// Returns `Err(CurlError::UnrecoverablePoll)` if no valid fds could be
/// registered with the async reactor.
async fn poll_all_fds(ufds: &mut [PollFd]) -> Result<i32, CurlError> {
    // For each valid fd, compute its Interest and create an AsyncFd guard.
    let mut async_fds: Vec<Option<AsyncFd<FdWrapper>>> = Vec::with_capacity(ufds.len());
    let mut any_registered = false;

    for pfd in ufds.iter() {
        if pfd.fd == CURL_SOCKET_BAD || pfd.fd < 0 || pfd.events == 0 {
            async_fds.push(None);
        } else {
            let interest = events_to_interest(pfd.events);
            match AsyncFd::with_interest(FdWrapper(pfd.fd), interest) {
                Ok(afd) => {
                    async_fds.push(Some(afd));
                    any_registered = true;
                }
                Err(_) => {
                    // If we can't create AsyncFd, mark slot as None (POLLNVAL).
                    async_fds.push(None);
                }
            }
        }
    }

    // If no valid fd could be registered with the async reactor, this is an
    // unrecoverable error condition (matches C Curl_poll returning -1).
    if !any_registered {
        return Err(CurlError::UnrecoverablePoll);
    }

    // Now wait for any fd to become ready.
    // We use a loop that checks each fd's readiness via async_readable / async_writable.
    // We use tokio::select! in a loop, but since the count is dynamic, we use
    // a polling approach with futures_util::future::poll_fn.
    let ready_result = wait_for_any_ready(&async_fds, ufds).await;

    // Drop all AsyncFd wrappers — we do NOT close the fds since we don't own them.
    // The FdWrapper's Drop impl is a no-op (it does not close the fd).
    for a in async_fds.into_iter().flatten() {
        // Forget the AsyncFd to avoid closing the fd we don't own.
        // AsyncFd::into_inner returns the FdWrapper, and FdWrapper doesn't close.
        let _ = a.into_inner();
    }

    ready_result
}

/// Wait for any file descriptor in the set to become ready.
///
/// Fills in `revents` on the corresponding [`PollFd`] entries and returns
/// the count of entries with non-zero revents.
async fn wait_for_any_ready(
    async_fds: &[Option<AsyncFd<FdWrapper>>],
    ufds: &mut [PollFd],
) -> Result<i32, CurlError> {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    // Create a future that polls all fds and resolves when at least one is ready.
    struct PollAllFuture<'a> {
        async_fds: &'a [Option<AsyncFd<FdWrapper>>],
        ufds: &'a mut [PollFd],
    }

    impl<'a> Future for PollAllFuture<'a> {
        type Output = Result<i32, CurlError>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let mut ready_count = 0i32;

            // Poll each fd for readiness
            for (i, afd_opt) in self.async_fds.iter().enumerate() {
                if let Some(afd) = afd_opt {
                    let pfd = &self.ufds[i];
                    let mut revents: u16 = 0;

                    // Check for read readiness
                    if pfd.events & (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI) != 0 {
                        match afd.poll_read_ready(cx) {
                            Poll::Ready(Ok(mut guard)) => {
                                revents |= ready_to_revents(
                                    guard.ready(),
                                    pfd.events,
                                );
                                guard.clear_ready();
                            }
                            Poll::Ready(Err(_)) => {
                                revents |= POLLERR;
                            }
                            Poll::Pending => {}
                        }
                    }

                    // Check for write readiness
                    if pfd.events & (POLLOUT | POLLWRNORM) != 0 {
                        match afd.poll_write_ready(cx) {
                            Poll::Ready(Ok(mut guard)) => {
                                revents |= ready_to_revents(
                                    guard.ready(),
                                    pfd.events,
                                );
                                guard.clear_ready();
                            }
                            Poll::Ready(Err(_)) => {
                                revents |= POLLERR;
                            }
                            Poll::Pending => {}
                        }
                    }

                    if revents != 0 {
                        // We need mutable access to ufds[i].revents. Since we
                        // are iterating async_fds immutably but need ufds mutably,
                        // this is handled via the &mut self.ufds.
                        self.ufds[i].revents = revents;
                        ready_count += 1;
                    }
                } else if self.ufds[i].fd != CURL_SOCKET_BAD && self.ufds[i].fd >= 0
                    && self.ufds[i].events != 0
                {
                    // AsyncFd creation failed — mark POLLNVAL
                    self.ufds[i].revents = POLLNVAL;
                    ready_count += 1;
                }
            }

            if ready_count > 0 {
                // Apply C-compatible fixups: HUP implies IN, ERR implies IN|OUT
                for pfd in self.ufds.iter_mut() {
                    if pfd.revents & POLLHUP != 0 {
                        pfd.revents |= POLLIN;
                    }
                    if pfd.revents & POLLERR != 0 {
                        pfd.revents |= POLLIN | POLLOUT;
                    }
                }
                Poll::Ready(Ok(ready_count))
            } else {
                Poll::Pending
            }
        }
    }

    PollAllFuture { async_fds, ufds }.await
}

// ---------------------------------------------------------------------------
// FdWrapper — non-owning raw fd wrapper for AsyncFd
// ---------------------------------------------------------------------------

/// A non-owning wrapper around a raw file descriptor.
///
/// This allows wrapping an fd in [`AsyncFd`] without taking ownership.
/// The [`Drop`] implementation intentionally does **not** close the fd.
#[derive(Debug)]
struct FdWrapper(RawFd);

impl std::os::unix::io::AsRawFd for FdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

// ---------------------------------------------------------------------------
// wait_ms — synchronous blocking sleep
// ---------------------------------------------------------------------------

/// Synchronously sleep for the given number of milliseconds.
///
/// Replaces C `curlx_wait_ms`. Uses [`std::thread::sleep`] for blocking sleep.
/// A negative `timeout_ms` is treated as zero (immediate return).
/// A zero `timeout_ms` returns immediately.
///
/// This function is intended for non-async contexts (e.g., FFI callers).
pub fn wait_ms(timeout_ms: i64) -> Result<(), CurlError> {
    if timeout_ms <= 0 {
        return Ok(());
    }
    std::thread::sleep(Duration::from_millis(timeout_ms as u64));
    Ok(())
}

/// Convert a [`CurlError`] to a C-compatible return code integer.
///
/// `CurlError::Ok` maps to `0`, all other variants map to their respective
/// `CURLcode` integer discriminants. This helper is used at the FFI boundary
/// to translate Rust `Result` types into C `int` return values.
#[inline]
pub fn error_to_code(err: &CurlError) -> i32 {
    match err {
        CurlError::Ok => 0,
        other => *other as i32,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Async sleep for the given duration. Used when no fds are provided.
async fn wait_ms_async(dur: Duration) {
    if dur.is_zero() {
        return;
    }
    sleep(dur).await;
}

/// Convert a Tokio [`Ready`] value back into poll-style revent flags.
///
/// Used internally to translate readiness results from AsyncFd guards into
/// the `POLLIN`/`POLLOUT` bitmask that callers expect in [`PollFd::revents`].
fn ready_to_revents(ready: Ready, requested_events: u16) -> u16 {
    let mut revents: u16 = 0;
    if ready.is_readable() {
        if requested_events & POLLRDNORM != 0 {
            revents |= POLLRDNORM;
        }
        if requested_events & POLLIN != 0 {
            revents |= POLLIN;
        }
    }
    if ready.is_writable() {
        if requested_events & POLLWRNORM != 0 {
            revents |= POLLWRNORM;
        }
        if requested_events & POLLOUT != 0 {
            revents |= POLLOUT;
        }
    }
    revents
}

/// Convert poll event flags (POLLIN/POLLOUT style) to a Tokio [`Interest`].
fn events_to_interest(events: u16) -> Interest {
    let want_read = events & (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI) != 0;
    let want_write = events & (POLLOUT | POLLWRNORM) != 0;

    match (want_read, want_write) {
        (true, true) => Interest::READABLE | Interest::WRITABLE,
        (true, false) => Interest::READABLE,
        (false, true) => Interest::WRITABLE,
        (false, false) => Interest::READABLE, // fallback, should not happen
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curl_select_constants() {
        assert_eq!(CurlSelect::IN.bits(), 0x01);
        assert_eq!(CurlSelect::OUT.bits(), 0x02);
        assert_eq!(CurlSelect::ERR.bits(), 0x04);
        assert_eq!(CurlSelect::IN2.bits(), 0x08);
        assert_eq!(CurlSelect::empty().bits(), 0);
    }

    #[test]
    fn test_curl_select_contains() {
        let combined = CurlSelect::IN | CurlSelect::OUT;
        assert!(combined.contains(CurlSelect::IN));
        assert!(combined.contains(CurlSelect::OUT));
        assert!(!combined.contains(CurlSelect::ERR));
    }

    #[test]
    fn test_curl_select_bitops() {
        let mut flags = CurlSelect::empty();
        flags |= CurlSelect::IN;
        flags |= CurlSelect::ERR;
        assert_eq!(flags.bits(), 0x05);
        let masked = flags & CurlSelect::IN;
        assert_eq!(masked.bits(), 0x01);
    }

    #[test]
    fn test_curl_poll_constants() {
        assert_eq!(CurlPoll::NONE.as_u8(), 0);
        assert_eq!(CurlPoll::IN.as_u8(), 1);
        assert_eq!(CurlPoll::OUT.as_u8(), 2);
        assert_eq!(CurlPoll::INOUT.as_u8(), 3);
        assert_eq!(CurlPoll::REMOVE.as_u8(), 4);
    }

    #[test]
    fn test_pollfd_new() {
        let pfd = PollFd::new(5, POLLIN | POLLOUT);
        assert_eq!(pfd.fd, 5);
        assert_eq!(pfd.events, POLLIN | POLLOUT);
        assert_eq!(pfd.revents, 0);
    }

    #[test]
    fn test_easy_pollset_new_empty() {
        let ps = EasyPollset::new();
        assert!(ps.is_empty());
        assert_eq!(ps.len(), 0);
    }

    #[test]
    fn test_easy_pollset_set_and_check() {
        let mut ps = EasyPollset::new();
        ps.set(10, true, false).unwrap();
        assert_eq!(ps.len(), 1);
        let (r, w) = ps.check(10);
        assert!(r);
        assert!(!w);
        assert!(ps.want_recv(10));
        assert!(!ps.want_send(10));
    }

    #[test]
    fn test_easy_pollset_change_add_remove() {
        let mut ps = EasyPollset::new();
        // Add IN for socket 10
        ps.change(10, CurlPoll::IN.as_u8(), 0).unwrap();
        assert_eq!(ps.len(), 1);
        assert!(ps.want_recv(10));

        // Add OUT for socket 10
        ps.change(10, CurlPoll::OUT.as_u8(), 0).unwrap();
        assert_eq!(ps.len(), 1);
        assert!(ps.want_recv(10));
        assert!(ps.want_send(10));

        // Remove IN for socket 10
        ps.change(10, 0, CurlPoll::IN.as_u8()).unwrap();
        assert!(ps.want_send(10));
        assert!(!ps.want_recv(10));

        // Remove OUT — socket should be removed entirely
        ps.change(10, 0, CurlPoll::OUT.as_u8()).unwrap();
        assert!(ps.is_empty());
    }

    #[test]
    fn test_easy_pollset_bad_socket() {
        let mut ps = EasyPollset::new();
        let result = ps.change(CURL_SOCKET_BAD, CurlPoll::IN.as_u8(), 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_easy_pollset_reset() {
        let mut ps = EasyPollset::new();
        ps.set(10, true, true).unwrap();
        ps.set(20, false, true).unwrap();
        assert_eq!(ps.len(), 2);
        ps.reset();
        assert!(ps.is_empty());
    }

    #[test]
    fn test_easy_pollset_cleanup() {
        let mut ps = EasyPollset::new();
        ps.set(10, true, true).unwrap();
        ps.cleanup();
        assert!(ps.is_empty());
    }

    #[test]
    fn test_easy_pollset_move_from() {
        let mut ps1 = EasyPollset::new();
        ps1.set(10, true, false).unwrap();
        ps1.set(20, false, true).unwrap();
        let mut ps2 = EasyPollset::new();
        ps2.move_from(&mut ps1);
        assert!(ps1.is_empty());
        assert_eq!(ps2.len(), 2);
        assert!(ps2.want_recv(10));
        assert!(ps2.want_send(20));
    }

    #[test]
    fn test_easy_pollset_sockets_actions() {
        let mut ps = EasyPollset::new();
        ps.set(5, true, true).unwrap();
        ps.set(10, true, false).unwrap();
        assert_eq!(ps.sockets(), &[5, 10]);
        assert_eq!(ps.actions().len(), 2);
    }

    #[test]
    fn test_pollfds_new_and_add() {
        let mut pfds = Pollfds::new(4);
        assert!(pfds.is_empty());
        pfds.add_sock(5, POLLIN as i16).unwrap();
        assert_eq!(pfds.len(), 1);
        pfds.add_sock(10, POLLOUT as i16).unwrap();
        assert_eq!(pfds.len(), 2);
    }

    #[test]
    fn test_pollfds_reset() {
        let mut pfds = Pollfds::new(4);
        pfds.add_sock(5, POLLIN as i16).unwrap();
        pfds.reset();
        assert!(pfds.is_empty());
    }

    #[test]
    fn test_pollfds_cleanup() {
        let mut pfds = Pollfds::new(4);
        pfds.add_sock(5, POLLIN as i16).unwrap();
        pfds.cleanup();
        assert!(pfds.is_empty());
    }

    #[test]
    fn test_pollfds_add_ps_folding() {
        let mut ps = EasyPollset::new();
        ps.change(5, CurlPoll::IN.as_u8() | CurlPoll::OUT.as_u8(), 0)
            .unwrap();
        let mut pfds = Pollfds::new(4);
        pfds.add_ps(&ps).unwrap();
        assert_eq!(pfds.len(), 1);
        // Add same pollset again — should fold
        pfds.add_ps(&ps).unwrap();
        assert_eq!(pfds.len(), 1);
    }

    #[test]
    fn test_waitfds_new_and_add_ps() {
        let mut ps = EasyPollset::new();
        ps.change(5, CurlPoll::IN.as_u8(), 0).unwrap();
        ps.change(10, CurlPoll::OUT.as_u8(), 0).unwrap();
        let mut wfds = Waitfds::new(10);
        let need = wfds.add_ps(&ps);
        assert_eq!(wfds.len(), 2);
        assert!(need > 0); // Each new entry reports need=1
    }

    #[test]
    fn test_waitfds_capacity_limit() {
        let mut ps = EasyPollset::new();
        ps.change(5, CurlPoll::IN.as_u8(), 0).unwrap();
        ps.change(10, CurlPoll::OUT.as_u8(), 0).unwrap();
        ps.change(15, CurlPoll::IN.as_u8(), 0).unwrap();
        let mut wfds = Waitfds::new(2);
        let need = wfds.add_ps(&ps);
        // Only 2 fit, 1 overflows
        assert_eq!(wfds.len(), 2);
        assert!(need >= 1);
    }

    #[test]
    fn test_wait_ms_zero() {
        let result = wait_ms(0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_wait_ms_negative() {
        let result = wait_ms(-100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_wait_ms_positive() {
        let start = std::time::Instant::now();
        let result = wait_ms(10);
        let elapsed = start.elapsed();
        assert!(result.is_ok());
        assert!(elapsed >= Duration::from_millis(5));
    }

    #[test]
    fn test_events_to_interest_read_only() {
        let interest = events_to_interest(POLLIN);
        assert_eq!(interest, Interest::READABLE);
    }

    #[test]
    fn test_events_to_interest_write_only() {
        let interest = events_to_interest(POLLOUT);
        assert_eq!(interest, Interest::WRITABLE);
    }

    #[test]
    fn test_events_to_interest_read_write() {
        let interest = events_to_interest(POLLIN | POLLOUT);
        assert_eq!(interest, Interest::READABLE | Interest::WRITABLE);
    }

    #[test]
    fn test_curl_select_from_u32() {
        let cs = CurlSelect::from(0x03);
        assert!(cs.contains(CurlSelect::IN));
        assert!(cs.contains(CurlSelect::OUT));
        assert!(!cs.contains(CurlSelect::ERR));
    }

    #[test]
    fn test_curl_poll_from_u8() {
        let cp = CurlPoll::from(3);
        assert_eq!(cp, CurlPoll::INOUT);
    }

    #[test]
    fn test_curl_poll_bitops() {
        let combined = CurlPoll::IN | CurlPoll::OUT;
        assert_eq!(combined, CurlPoll::INOUT);
        let masked = combined & CurlPoll::IN;
        assert_eq!(masked, CurlPoll::IN);
    }

    #[tokio::test]
    async fn test_socket_check_no_fds() {
        let result = socket_check(None, None, None, Duration::from_millis(10)).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CurlSelect::empty());
    }

    #[tokio::test]
    async fn test_poll_no_valid_fds() {
        let mut pfds = vec![PollFd::new(CURL_SOCKET_BAD, POLLIN)];
        let result = poll(&mut pfds, Duration::from_millis(10)).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_easy_pollset_poll_empty() {
        let ps = EasyPollset::new();
        let result = ps.poll(Duration::from_millis(10)).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }
}
