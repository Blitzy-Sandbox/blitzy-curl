// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! Per-transfer request state — the idiomatic-Rust rewrite of curl's
//! `lib/request.c` and the `struct SingleRequest` declared in `lib/request.h`.
//!
//! # Responsibility
//!
//! [`SingleRequest`] owns the state that is specific to a *single* request on an
//! easy transfer. In curl this data used to live on the `connectdata` struct but
//! was moved onto the easy handle (`Curl_easy`) because one connection may now be
//! shared between different easy handles. This struct only keeps the state that
//! is interesting for *this* request and is cleared between requests (for example
//! across a redirect or an authentication-negotiation retry).
//!
//! Concretely, this module tracks:
//!
//! * the read/write **`keepon`** bitset (`KEEP_RECV` / `KEEP_SEND` and their
//!   `HOLD` / `PAUSE` variants) that drives whether the transfer wants to send
//!   or receive;
//! * buffered download/upload **bookkeeping** — the byte counters
//!   ([`SingleRequest::bytecount`], [`SingleRequest::writebytecount`], the header
//!   counters) and the outgoing **send buffer** (a [`bytes::BytesMut`] replacing
//!   curl's `dynbuf`/`bufq`);
//! * the **header → body** phase flag and the many per-request status bits;
//! * the **client-writer / client-reader** attachment points — the pipeline
//!   handles are *held* here, while the actual writer chain (download →
//!   content-decode → header parse → output) and reader chain are *driven* by
//!   `transfer.rs` / `content_encoding.rs`;
//! * `pause` / `unpause` support matching `curl_easy_pause` semantics through
//!   the `KEEP_*_PAUSE` bits.
//!
//! # Ownership model
//!
//! Memory management is expressed entirely through Rust ownership: the send
//! buffer is a [`BytesMut`], strings are owned [`String`]s, and the writer/reader
//! stacks are boxed trait objects. This module is written in 100% safe Rust and
//! performs no manual `malloc`/`free`/`realloc`.
//!
//! # Division of labour with `transfer.rs`
//!
//! curl's `Curl_req_send` / `req_flush` / `xfer_send` helpers interleave *state*
//! (buffer bookkeeping, counters, the `keepon` bits) with *I/O* (writing bytes to
//! the connection, reading from the client reader, updating progress). In this
//! rewrite the I/O half is owned by `transfer.rs`, which holds the connection and
//! calls into the state helpers exposed here. Everything in this module is
//! therefore pure state manipulation and buffer management; nothing here performs
//! network I/O.

use crate::error::Result;
use bytes::BytesMut;
use std::time::Instant;

// ---------------------------------------------------------------------------
// `keepon` bitset
// ---------------------------------------------------------------------------
//
// These flags mirror the historical `KEEP_*` `#define`s from curl's
// `lib/urldata.h`. They classify, per direction, whether the transfer may read
// or write, and whether that direction is temporarily *held* (buffer full, flow
// controlled) or *paused* (by an application `curl_easy_pause` call). The
// numeric values are transcribed verbatim from curl so that `--trace`
// diagnostics and any bit-level reasoning remain identical.

/// No receive/send activity is pending (`KEEP_NONE`).
pub const KEEP_NONE: u32 = 0;
/// There is, or may be, data to read (`KEEP_RECV`, `1 << 0`).
pub const KEEP_RECV: u32 = 1 << 0;
/// There is, or may be, data to write (`KEEP_SEND`, `1 << 1`).
pub const KEEP_SEND: u32 = 1 << 1;
/// Receiving is *held*: no reading should be done right now, but there might
/// still be data to read (`KEEP_RECV_HOLD`, `1 << 2`).
pub const KEEP_RECV_HOLD: u32 = 1 << 2;
/// Sending is *held*: no writing should be done right now, but there might
/// still be data to write (`KEEP_SEND_HOLD`, `1 << 3`).
pub const KEEP_SEND_HOLD: u32 = 1 << 3;
/// Receiving is *paused* by the application (`KEEP_RECV_PAUSE`, `1 << 4`).
pub const KEEP_RECV_PAUSE: u32 = 1 << 4;
/// Sending is *paused* by the application (`KEEP_SEND_PAUSE`, `1 << 5`).
pub const KEEP_SEND_PAUSE: u32 = 1 << 5;
/// The transfer should attempt sending at timer (or other) events
/// (`KEEP_SEND_TIMED`, `1 << 6`). Used, for example, for HTTP
/// `Expect: 100-continue` waiting: a transfer waiting on the timer removes
/// [`KEEP_SEND`] to suppress `POLLOUT`s and adds `KEEP_SEND_TIMED` so it retries
/// sending when the "readwrite" loop is entered.
pub const KEEP_SEND_TIMED: u32 = 1 << 6;

/// The set of all receive-direction bits (`KEEP_RECVBITS`): plain, hold and
/// pause. A transfer "wants to receive" iff *only* the plain [`KEEP_RECV`] bit
/// is set within this mask.
pub const KEEP_RECVBITS: u32 = KEEP_RECV | KEEP_RECV_HOLD | KEEP_RECV_PAUSE;
/// The set of all send-direction bits (`KEEP_SENDBITS`): plain, hold and pause.
/// A transfer "wants to send" iff *only* the plain [`KEEP_SEND`] bit is set
/// within this mask.
pub const KEEP_SENDBITS: u32 = KEEP_SEND | KEEP_SEND_HOLD | KEEP_SEND_PAUSE;

// ---------------------------------------------------------------------------
// `CURLPAUSE_*` action bits (public API surface of `curl_easy_pause`)
// ---------------------------------------------------------------------------
//
// These mirror the `CURLPAUSE_*` `#define`s in `include/curl/curl.h` and are the
// bitmask accepted by [`SingleRequest::pause`], exactly as `curl_easy_pause`
// accepts them.

/// Pause receiving (`CURLPAUSE_RECV`, `1 << 0`).
pub const CURLPAUSE_RECV: i32 = 1 << 0;
/// Resume receiving — the "continue" complement of [`CURLPAUSE_RECV`]
/// (`CURLPAUSE_RECV_CONT`, `0`).
pub const CURLPAUSE_RECV_CONT: i32 = 0;
/// Pause sending (`CURLPAUSE_SEND`, `1 << 2`).
pub const CURLPAUSE_SEND: i32 = 1 << 2;
/// Resume sending — the "continue" complement of [`CURLPAUSE_SEND`]
/// (`CURLPAUSE_SEND_CONT`, `0`).
pub const CURLPAUSE_SEND_CONT: i32 = 0;
/// Pause both directions (`CURLPAUSE_ALL`).
pub const CURLPAUSE_ALL: i32 = CURLPAUSE_RECV | CURLPAUSE_SEND;
/// Resume both directions (`CURLPAUSE_CONT`).
pub const CURLPAUSE_CONT: i32 = CURLPAUSE_RECV_CONT | CURLPAUSE_SEND_CONT;

/// The classification bitmask for a client-writer invocation.
///
/// This mirrors curl's `CLIENTWRITE_*` `#define`s from `lib/sendf.h`. When
/// `transfer.rs` drives the writer chain it tags each chunk of received data
/// with the kind of content it represents (body, header, status line, a `1xx`
/// interim response, a trailer, and so on). The flags may be OR-combined, just
/// like the C `int type` bitmask.
///
/// The two flag names that cannot be spelled as Rust identifiers are renamed:
/// `CLIENTWRITE_1XX` becomes [`ClientWriteType::HTTP1XX`] and `CLIENTWRITE_0LEN`
/// becomes [`ClientWriteType::ZERO_LEN`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientWriteType(u32);

impl ClientWriteType {
    /// No classification bits set.
    pub const NONE: Self = Self(0);
    /// Non-meta information — response BODY (`CLIENTWRITE_BODY`, `1 << 0`).
    pub const BODY: Self = Self(1 << 0);
    /// Meta information that is not an HTTP header (`CLIENTWRITE_INFO`,
    /// `1 << 1`).
    pub const INFO: Self = Self(1 << 1);
    /// Meta information that is an HTTP header (`CLIENTWRITE_HEADER`,
    /// `1 << 2`).
    pub const HEADER: Self = Self(1 << 2);
    /// A special status header — the response status line
    /// (`CLIENTWRITE_STATUS`, `1 << 3`).
    pub const STATUS: Self = Self(1 << 3);
    /// A `CONNECT`-related header (`CLIENTWRITE_CONNECT`, `1 << 4`).
    pub const CONNECT: Self = Self(1 << 4);
    /// A `1xx` interim-response header (`CLIENTWRITE_1XX`, `1 << 5`).
    pub const HTTP1XX: Self = Self(1 << 5);
    /// A trailer header (`CLIENTWRITE_TRAILER`, `1 << 6`).
    pub const TRAILER: Self = Self(1 << 6);
    /// End of the download transfer stream (`CLIENTWRITE_EOS`, `1 << 7`).
    pub const EOS: Self = Self(1 << 7);
    /// Write even zero-length buffers (`CLIENTWRITE_0LEN`, `1 << 8`).
    pub const ZERO_LEN: Self = Self(1 << 8);

    /// Returns the raw bit pattern.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Builds a [`ClientWriteType`] from a raw bit pattern.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns `true` iff **all** bits set in `other` are also set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns `true` iff **any** bit set in `other` is also set in `self`.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Returns `true` iff no classification bit is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for ClientWriteType {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for ClientWriteType {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// The outcome of a single [`ClientReader::read`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientRead {
    /// Number of bytes written into the caller's buffer.
    pub nread: usize,
    /// `true` iff the end of the upload stream has been reached; no further
    /// bytes will ever be produced by this reader.
    pub eos: bool,
}

/// The head of the **client-writer** stack.
///
/// In curl the writer stack (`struct Curl_cwriter`) handles transfer- and
/// content-encodings, protocol checks, and pausing driven by client callbacks.
/// [`SingleRequest`] merely *holds* the head of this stack; the concrete chain
/// is built and driven by `transfer.rs` / `content_encoding.rs`, which implement
/// this trait. Keeping the trait here defines the attachment-point contract
/// without this module depending on the transfer or content-encoding layers.
///
/// Implementors are required to be [`Debug`](core::fmt::Debug) (so that the
/// owning [`SingleRequest`] stays `Debug`-printable for `--trace` diagnostics)
/// and [`Send`] (so a transfer may move across threads on the multi-handle's
/// multi-threaded runtime).
pub trait ClientWriter: core::fmt::Debug + Send {
    /// Push `buf`, classified by `wtype`, through the writer chain toward the
    /// application (or output file). Implementations preserve curl's header →
    /// body phase ordering.
    fn write(&mut self, wtype: ClientWriteType, buf: &[u8]) -> Result<()>;

    /// Returns `true` iff this writer chain is currently paused by a client
    /// write callback. Defaults to `false`.
    fn is_paused(&self) -> bool {
        false
    }
}

/// The head of the **client-reader** stack.
///
/// In curl the reader stack (`struct Curl_creader`) supplies upload data,
/// applying transfer-encodings and honouring client read callbacks and pausing.
/// [`SingleRequest`] holds the head of this stack; `transfer.rs` drives it to
/// fill the outgoing [`SingleRequest::sendbuf`].
///
/// Like [`ClientWriter`], implementors are required to be
/// [`Debug`](core::fmt::Debug) and [`Send`].
pub trait ClientReader: core::fmt::Debug + Send {
    /// Read up to `buf.len()` bytes of upload data into `buf`, reporting how
    /// many bytes were produced and whether the end of stream was reached.
    fn read(&mut self, buf: &mut [u8]) -> Result<ClientRead>;

    /// Total number of upload bytes if known ahead of time (for example from a
    /// `Content-Length`), or `None` for a streaming/unknown-length upload.
    /// Defaults to `None`.
    fn total_length(&self) -> Option<u64> {
        None
    }

    /// Returns `true` iff this reader chain is currently paused. Defaults to
    /// `false`.
    fn is_paused(&self) -> bool {
        false
    }
}

/// HTTP `Expect: 100-continue` negotiation state (`enum expect100` in
/// `lib/request.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Expect100 {
    /// Enough waiting — just send the body now (`EXP100_SEND_DATA`).
    #[default]
    SendData,
    /// Waiting for the `100 Continue` header (`EXP100_AWAITING_CONTINUE`).
    AwaitingContinue,
    /// Still sending the request but will wait for the `100` header once done
    /// (`EXP100_SENDING_REQUEST`).
    SendingRequest,
    /// Used on `417 Expectation Failed` (`EXP100_FAILED`).
    Failed,
}

/// HTTP `101 Switching Protocols` upgrade state (`enum upgrade101` in
/// `lib/request.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Upgrade101 {
    /// Default state — no upgrade requested (`UPGR101_NONE`).
    #[default]
    None,
    /// Upgrade to WebSocket requested (`UPGR101_WS`).
    Ws,
    /// Upgrade to HTTP/2 requested (`UPGR101_H2`).
    H2,
    /// A `101` response has been received (`UPGR101_RECEIVED`).
    Received,
}

/// Request-specific state for a single transfer on an easy handle.
///
/// This is the Rust counterpart of curl's `struct SingleRequest`
/// (`lib/request.h`). Fields are public because — exactly as in curl, where the
/// transfer loop reads and writes `data->req.*` directly — the higher layers
/// (`transfer.rs`, the protocol handlers) manipulate these members in place. The
/// non-trivial state transitions (lifecycle resets, the `keepon` bits, pausing,
/// and send-buffer bookkeeping) are additionally wrapped in methods so callers
/// can reproduce curl's semantics without re-deriving the bit math.
///
/// A fresh value (from [`SingleRequest::new`] or [`Default`]) is the equivalent
/// of curl's `Curl_req_init`, i.e. a zeroed struct. Note that a zeroed struct
/// has [`size`](Self::size) and [`maxdownload`](Self::maxdownload) equal to `0`,
/// **not** `-1`; the `-1` "unknown/unlimited" sentinels are only established by
/// [`hard_reset`](Self::hard_reset), matching curl's `Curl_req_hard_reset`.
#[derive(Debug, Default)]
pub struct SingleRequest {
    // -- byte counters and sizes (curl_off_t / i64) ----------------------
    /// Expected size of the download in bytes, or `-1` if unknown at this point
    /// (curl `size`).
    pub size: i64,
    /// Maximum amount of data to fetch, in bytes; `-1` means unlimited (curl
    /// `maxdownload`).
    pub maxdownload: i64,
    /// Total number of body bytes read for this request (curl `bytecount`).
    pub bytecount: i64,
    /// Total number of body bytes written (uploaded) for this request (curl
    /// `writebytecount`).
    pub writebytecount: i64,
    /// Resume offset read from a `Content-Range:` header (curl `offset`).
    pub offset: i64,

    // -- timing ----------------------------------------------------------
    /// The instant the transfer started, or `None` for the zeroed
    /// (`{0, 0}`) time curl uses before a start (curl `start`, a `curltime`).
    pub start: Option<Instant>,
    /// The document's modification time as a Unix timestamp, or `0` if unknown
    /// (curl `timeofdoc`, a `time_t`).
    pub timeofdoc: i64,

    // -- header counters -------------------------------------------------
    /// Number of received server-header bytes (not counting `CONNECT` headers)
    /// (curl `headerbytecount`).
    pub headerbytecount: u32,
    /// Number of all received header bytes (server + `CONNECT`) (curl
    /// `allheadercount`).
    pub allheadercount: u32,
    /// Bytes that do **not** count when checking whether anything was
    /// transferred at the end of a connection. Used so that a lone `100` reply
    /// (with no following final response) yields a `CURLE_GOT_NOTHING` rather
    /// than looking like a successful transfer (curl `deductheadercount`).
    pub deductheadercount: u32,
    /// Counts header lines, to better track the first one (curl `headerline`).
    pub headerline: i32,

    // -- HTTP status / versions -----------------------------------------
    /// The numeric code from the `HTTP/1.? XXX` or `RTSP/1.? XXX` status line
    /// (curl `httpcode`).
    pub httpcode: i32,
    /// HTTP version used in the request: `9`, `10`, `11`, `20`, `30`, … (curl
    /// `httpversion_sent`).
    pub httpversion_sent: u8,
    /// HTTP version seen in the response (curl `httpversion`).
    pub httpversion: u8,
    /// `101`-upgrade negotiation state (curl `upgr101`).
    pub upgr101: Upgrade101,

    // -- keepon bitset ---------------------------------------------------
    /// The receive/send `keepon` bitset — a combination of the `KEEP_*`
    /// constants. Prefer the [`want_send`](Self::want_send),
    /// [`want_recv`](Self::want_recv), [`pause`](Self::pause) and hold helpers
    /// over manipulating the bits directly (curl `keepon`).
    pub keepon: u32,

    // -- client writer / reader attachment points ------------------------
    /// Head of the client-writer stack. Held here, driven by `transfer.rs` /
    /// `content_encoding.rs` (curl `writer_stack`).
    pub writer_stack: Option<Box<dyn ClientWriter>>,
    /// Head of the client-reader stack. Held here, driven by `transfer.rs`
    /// (curl `reader_stack`).
    pub reader_stack: Option<Box<dyn ClientReader>>,

    // -- outgoing send buffer -------------------------------------------
    /// Data that still needs to be sent to the server. Replaces curl's
    /// `dynbuf`/`bufq` `sendbuf` with a [`BytesMut`]; header bytes are always at
    /// the front (see [`sendbuf_hds_len`](Self::sendbuf_hds_len)).
    pub sendbuf: BytesMut,
    /// Number of header bytes currently buffered at the front of
    /// [`sendbuf`](Self::sendbuf) (curl `sendbuf_hds_len`).
    pub sendbuf_hds_len: usize,

    // -- redirect / location ---------------------------------------------
    /// An owned copy of the `Location:` header value, if any (curl `location`).
    pub location: Option<String>,
    /// The new URL to use for a redirect or retry, if any (curl `newurl`).
    pub newurl: Option<String>,

    // -- cookies ---------------------------------------------------------
    /// Number of `Set-Cookie:` headers seen for this request. Corresponds to
    /// curl's `setcookies`, which is compiled in only when cookie support is
    /// enabled; it is kept unconditionally here for a stable struct shape.
    pub setcookies: u8,

    // -- status bits (curl `BIT(...)` members) ---------------------------
    /// Incoming data is (still) HTTP header data — the header phase (curl
    /// `header`). Clearing this marks the header → body transition.
    pub header: bool,
    /// `true` iff header parsing is wanted for this request. Corresponds to
    /// curl's historical `getheader` request flag; retained because the file
    /// specification lists it as a phase flag.
    pub getheader: bool,
    /// The request is done: no more send/recv should happen. This can become
    /// `true` before [`upload_done`](Self::upload_done) or
    /// [`download_done`](Self::download_done) (curl `done`).
    pub done: bool,
    /// A `Content-Range:` header was found (curl `content_range`).
    pub content_range: bool,
    /// The download has completed (curl `download_done`).
    pub download_done: bool,
    /// End-of-stream has been written to the client (curl `eos_written`).
    pub eos_written: bool,
    /// End-of-stream has been read from the client reader (curl `eos_read`).
    pub eos_read: bool,
    /// End-of-stream has been sent to the server (curl `eos_sent`).
    pub eos_sent: bool,
    /// The reader needs a rewind at the next start (curl `rewind_read`).
    pub rewind_read: bool,
    /// All request data has been sent (curl `upload_done`).
    pub upload_done: bool,
    /// The upload was aborted; also implies [`upload_done`](Self::upload_done)
    /// is `true` (curl `upload_aborted`).
    pub upload_aborted: bool,
    /// A response body is being read but is deliberately ignored (curl
    /// `ignorebody`).
    pub ignorebody: bool,
    /// The HTTP response status is between `100` and `199`, or is `204` or
    /// `304`, so it carries no body (curl `http_bodyless`).
    pub http_bodyless: bool,
    /// This is a chunked transfer-encoding download (curl `chunk`).
    pub chunk: bool,
    /// The response carried a `Trailer:` header field (curl `resp_trailer`).
    pub resp_trailer: bool,
    /// Ignore the `Content-Length` of the response (curl `ignore_cl`).
    pub ignore_cl: bool,
    /// Chunked transfer-encoding is being applied on upload (curl
    /// `upload_chunky`).
    pub upload_chunky: bool,
    /// The response has no body (curl `no_body`).
    pub no_body: bool,
    /// The authentication phase has started: a request with an auth header is
    /// being created, but it is not the final request of the negotiation (curl
    /// `authneg`).
    pub authneg: bool,
    /// The [`sendbuf`](Self::sendbuf) has been initialised (curl `sendbuf_init`).
    pub sendbuf_init: bool,
    /// Ending the request will shut down the connection (curl `shutdown`).
    pub shutdown: bool,
    /// Errors during shutdown will not fail the request (curl
    /// `shutdown_err_ignore`).
    pub shutdown_err_ignore: bool,
    /// Client reads have started (curl `reader_started`).
    pub reader_started: bool,
}

impl SingleRequest {
    // =====================================================================
    // Lifecycle — mirrors Curl_req_init / _start / _soft_reset / _done /
    // _hard_reset / _free from lib/request.c
    // =====================================================================

    /// Creates a fresh, zeroed request state.
    ///
    /// This is the constructor form of curl's `Curl_req_init`: every counter is
    /// `0`, every flag is `false`, the `keepon` bitset is [`KEEP_NONE`], and the
    /// send buffer is empty and uninitialised. As in curl, [`size`](Self::size)
    /// and [`maxdownload`](Self::maxdownload) are `0` here — the `-1` sentinels
    /// are only set by [`hard_reset`](Self::hard_reset).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Re-initialises an existing request to the zeroed state in place.
    ///
    /// This is the in-place form of curl's `Curl_req_init` (which `memset`s the
    /// struct to zero). Any attached writer/reader stacks and buffered send data
    /// are dropped.
    pub fn init(&mut self) {
        *self = Self::default();
    }

    /// Records the transfer start time and performs a [`soft_reset`].
    ///
    /// Mirrors `Curl_req_start`: curl stamps `req->start` with the current
    /// progress time and then soft-resets. `now` is the caller-supplied start
    /// instant (curl reads it from the progress subsystem); `upload_buffer_size`
    /// is the configured upload buffer size used to size the send buffer.
    ///
    /// [`soft_reset`]: Self::soft_reset
    pub fn start(&mut self, now: Instant, upload_buffer_size: usize) -> Result<()> {
        self.start = Some(now);
        self.soft_reset(upload_buffer_size)
    }

    /// Resets the per-request members for a follow-up request while keeping the
    /// overall start time (for total-duration calculations).
    ///
    /// Mirrors `Curl_req_soft_reset`: it clears the completion/EOS flags, the
    /// body and header byte counters, the header phase flag and the negotiated
    /// HTTP versions, then ensures the send buffer is initialised (or reset)
    /// with the requested capacity. It does **not** touch [`size`](Self::size),
    /// [`maxdownload`](Self::maxdownload), [`keepon`](Self::keepon),
    /// [`newurl`](Self::newurl) or the attached writer/reader stacks — those are
    /// managed by the transfer layer, which (re)starts the client reader/writer
    /// separately.
    pub fn soft_reset(&mut self, upload_buffer_size: usize) -> Result<()> {
        self.done = false;
        self.upload_done = false;
        self.upload_aborted = false;
        self.download_done = false;
        self.eos_written = false;
        self.eos_read = false;
        self.eos_sent = false;
        self.ignorebody = false;
        self.shutdown = false;
        self.bytecount = 0;
        self.writebytecount = 0;
        self.header = false;
        self.headerline = 0;
        self.headerbytecount = 0;
        self.allheadercount = 0;
        self.deductheadercount = 0;
        self.httpversion_sent = 0;
        self.httpversion = 0;
        self.sendbuf_hds_len = 0;

        // The client reader/writer restart (curl's `Curl_client_start`) is driven
        // by `transfer.rs`, which owns the concrete stacks; there is nothing to
        // fail here. Size (or re-size) the send buffer, mirroring the
        // `sendbuf_init` / chunk-size handling in `Curl_req_soft_reset`.
        if !self.sendbuf_init {
            self.sendbuf = BytesMut::with_capacity(upload_buffer_size);
            self.sendbuf_init = true;
        } else {
            self.sendbuf.clear();
            let cap = self.sendbuf.capacity();
            if cap < upload_buffer_size {
                self.sendbuf.reserve(upload_buffer_size - cap);
            }
        }

        Ok(())
    }

    /// Marks the request as done, resetting the client pipeline.
    ///
    /// Mirrors `Curl_req_done`. In curl, when the request was **not** aborted
    /// the remaining buffered send data is flushed first; that flush is network
    /// I/O and is performed by `transfer.rs` *before* calling this method, so
    /// here we only reset the client writer/reader stacks (curl's
    /// `Curl_client_reset`). The DoH teardown that curl also performs lives in
    /// the DNS layer and is out of scope for this module.
    pub fn done(&mut self, aborted: bool) -> Result<()> {
        // `aborted` gates the (external) pre-flush in curl; retained for parity.
        let _ = aborted;
        self.reset_client();
        Ok(())
    }

    /// Hard-resets the request to a virgin state based on transfer settings.
    ///
    /// Mirrors `Curl_req_hard_reset`. Unlike [`init`](Self::init), this cannot
    /// simply zero the struct because some state must be preserved (notably the
    /// initialised send buffer and, per curl, fields such as `done`,
    /// `resp_trailer`, the negotiated HTTP versions and `sendbuf_init`, which are
    /// intentionally left untouched). `opt_no_body` is the transfer's configured
    /// "no body" setting (curl's `data->set.opt_no_body`), which seeds
    /// [`no_body`](Self::no_body).
    ///
    /// This clears the redirect [`newurl`](Self::newurl)/[`location`](Self::location),
    /// resets the client pipeline, empties the send buffer, and restores the
    /// counters, sizes and status bits to their virgin values — including the
    /// `-1` sentinels for [`size`](Self::size) and [`maxdownload`](Self::maxdownload).
    pub fn hard_reset(&mut self, opt_no_body: bool) {
        // Free the redirect URL and reset the client pipeline first.
        self.newurl = None;
        self.reset_client();
        if self.sendbuf_init {
            self.sendbuf.clear();
        }

        // Cannot memset: we keep the send buffer and a few sticky flags.
        self.size = -1;
        self.maxdownload = -1;
        self.bytecount = 0;
        self.writebytecount = 0;
        self.start = None;
        self.headerbytecount = 0;
        self.allheadercount = 0;
        self.deductheadercount = 0;
        self.headerline = 0;
        self.offset = 0;
        self.httpcode = 0;
        self.keepon = KEEP_NONE;
        self.upgr101 = Upgrade101::None;
        self.sendbuf_hds_len = 0;
        self.timeofdoc = 0;
        self.location = None;
        self.newurl = None;
        self.setcookies = 0;
        self.header = false;
        self.content_range = false;
        self.download_done = false;
        self.eos_written = false;
        self.eos_read = false;
        self.eos_sent = false;
        self.rewind_read = false;
        self.upload_done = false;
        self.upload_aborted = false;
        self.ignorebody = false;
        self.http_bodyless = false;
        self.chunk = false;
        self.ignore_cl = false;
        self.upload_chunky = false;
        self.no_body = opt_no_body;
        self.authneg = false;
        self.shutdown = false;
        // curl also unblocks the download/upload rate limiters here; rate
        // limiting lives in `ratelimit.rs` and is out of scope for this module.
    }

    /// Frees the request state; it must not be used afterwards.
    ///
    /// Mirrors `Curl_req_free`. Rust drops the owned buffer, strings and boxed
    /// stacks automatically, so this method exists for API parity and to make
    /// the teardown explicit and idempotent: it clears the redirect URL, empties
    /// and de-initialises the send buffer, and tears down the client pipeline
    /// (curl's `Curl_client_cleanup`).
    pub fn free(&mut self) {
        self.newurl = None;
        if self.sendbuf_init {
            self.sendbuf.clear();
            self.sendbuf = BytesMut::new();
            self.sendbuf_init = false;
        }
        self.sendbuf_hds_len = 0;
        self.reset_client();
    }

    /// Resets the client writer/reader pipeline (curl's `Curl_client_reset`).
    ///
    /// Drops both attached stacks and clears [`reader_started`](Self::reader_started).
    fn reset_client(&mut self) {
        self.writer_stack = None;
        self.reader_stack = None;
        self.reader_started = false;
    }
}

impl SingleRequest {
    // =====================================================================
    // Send-buffer helpers — mirror the sendbuf handling in lib/request.c
    // (Curl_req_send / req_send_buffer_add / req_send_buffer_flush /
    // Curl_req_sendbuf_empty). The `bufq`/`dynbuf` is replaced by `BytesMut`.
    // =====================================================================

    /// Queues the fully-formed request head (headers, no body) for sending and
    /// records the HTTP version used.
    ///
    /// This is the buffering half of curl's `Curl_req_send`: it stamps
    /// [`httpversion_sent`](Self::httpversion_sent) and appends `header_bytes` to
    /// the send buffer as header bytes. The actual flush to the socket — and the
    /// direct-send fast path and body pull that `Curl_req_send` performs via
    /// `Curl_req_send_more` — are network I/O owned by `transfer.rs`, which
    /// drives them using [`sendbuf_peek`](Self::sendbuf_peek) /
    /// [`sendbuf_consume`](Self::sendbuf_consume) and the attached
    /// [`reader_stack`](Self::reader_stack).
    pub fn queue_request(&mut self, header_bytes: &[u8], httpversion: u8) -> Result<()> {
        self.httpversion_sent = httpversion;
        let len = header_bytes.len();
        self.send_buffer_add(header_bytes, len)
    }

    /// Appends `buf` to the send buffer, of which the leading `hds_len` bytes are
    /// header bytes.
    ///
    /// Mirrors `req_send_buffer_add`. Because header bytes are always written at
    /// the front, `hds_len` is added to [`sendbuf_hds_len`](Self::sendbuf_hds_len).
    /// With a [`BytesMut`] the append cannot fail (an allocation failure aborts,
    /// as it does everywhere in safe Rust), so this always returns `Ok`; the
    /// fallible signature is kept for parity with curl's `CURLcode`-returning
    /// helper. `hds_len` is clamped to `buf.len()` defensively.
    pub fn send_buffer_add(&mut self, buf: &[u8], hds_len: usize) -> Result<()> {
        if !self.sendbuf_init {
            // Match soft_reset's lazy initialisation so a direct add before an
            // explicit reset still lands in a valid buffer.
            self.sendbuf = BytesMut::new();
            self.sendbuf_init = true;
        }
        self.sendbuf.extend_from_slice(buf);
        self.sendbuf_hds_len += hds_len.min(buf.len());
        Ok(())
    }

    /// Returns `true` iff there are no buffered request bytes yet to send.
    ///
    /// Mirrors `Curl_req_sendbuf_empty`: a request whose buffer has never been
    /// initialised counts as empty, as does one whose buffer holds no bytes.
    #[must_use]
    pub fn sendbuf_empty(&self) -> bool {
        !self.sendbuf_init || self.sendbuf.is_empty()
    }

    /// Returns the number of bytes currently buffered for sending.
    #[must_use]
    pub fn sendbuf_len(&self) -> usize {
        self.sendbuf.len()
    }

    /// Borrows the buffered send bytes without consuming them (curl's
    /// `Curl_bufq_peek`). The header bytes, if any, occupy the first
    /// [`sendbuf_hds_len`](Self::sendbuf_hds_len) bytes of the returned slice.
    #[must_use]
    pub fn sendbuf_peek(&self) -> &[u8] {
        &self.sendbuf[..]
    }

    /// Consumes (drops) up to `n` bytes from the front of the send buffer after
    /// they have been written to the socket, and returns how many bytes were
    /// actually consumed.
    ///
    /// Mirrors the `Curl_bufq_skip` + header-length bookkeeping in
    /// `req_send_buffer_flush`: since header bytes sit at the front,
    /// [`sendbuf_hds_len`](Self::sendbuf_hds_len) is reduced by however many of
    /// the consumed bytes were header bytes. `n` is clamped to the buffered
    /// length.
    pub fn sendbuf_consume(&mut self, n: usize) -> usize {
        let take = n.min(self.sendbuf.len());
        let hds_consumed = take.min(self.sendbuf_hds_len);
        self.sendbuf_hds_len -= hds_consumed;
        let _ = self.sendbuf.split_to(take);
        take
    }
}

impl SingleRequest {
    // =====================================================================
    // keepon predicates and direction control — mirror the CURL_WANT_SEND /
    // CURL_WANT_RECV macros and the keepon manipulations in lib/request.c
    // =====================================================================

    /// Returns `true` iff the transfer wants to send: the send direction is
    /// active and is neither *held* nor *paused*.
    ///
    /// This is curl's `CURL_WANT_SEND` macro: it holds exactly when only the
    /// plain [`KEEP_SEND`] bit is set within [`KEEP_SENDBITS`]. The transfer
    /// layer layers the additional "not done / not rate-limited / has buffered
    /// data" conditions of the evolved `Curl_req_want_send` on top of this
    /// bit-level predicate.
    #[must_use]
    pub fn want_send(&self) -> bool {
        (self.keepon & KEEP_SENDBITS) == KEEP_SEND
    }

    /// Returns `true` iff the transfer wants to receive: the receive direction
    /// is active and is neither *held* nor *paused*.
    ///
    /// This is curl's `CURL_WANT_RECV` macro: it holds exactly when only the
    /// plain [`KEEP_RECV`] bit is set within [`KEEP_RECVBITS`].
    #[must_use]
    pub fn want_recv(&self) -> bool {
        (self.keepon & KEEP_RECVBITS) == KEEP_RECV
    }

    /// Returns `true` iff the request has sent all its data.
    ///
    /// Mirrors `Curl_req_done_sending`: the upload is done and the transfer no
    /// longer [wants to send](Self::want_send).
    #[must_use]
    pub fn done_sending(&self) -> bool {
        self.upload_done && !self.want_send()
    }

    /// Enables or disables the plain [`KEEP_RECV`] bit.
    pub fn set_recv(&mut self, on: bool) {
        if on {
            self.keepon |= KEEP_RECV;
        } else {
            self.keepon &= !KEEP_RECV;
        }
    }

    /// Enables or disables the plain [`KEEP_SEND`] bit.
    pub fn set_send(&mut self, on: bool) {
        if on {
            self.keepon |= KEEP_SEND;
        } else {
            self.keepon &= !KEEP_SEND;
        }
    }

    /// Sets or clears the receive *hold* bit ([`KEEP_RECV_HOLD`]). A held
    /// direction has, or may still have, data pending but must not be serviced
    /// right now (for example while a buffer downstream is full).
    pub fn hold_recv(&mut self, hold: bool) {
        if hold {
            self.keepon |= KEEP_RECV_HOLD;
        } else {
            self.keepon &= !KEEP_RECV_HOLD;
        }
    }

    /// Sets or clears the send *hold* bit ([`KEEP_SEND_HOLD`]).
    pub fn hold_send(&mut self, hold: bool) {
        if hold {
            self.keepon |= KEEP_SEND_HOLD;
        } else {
            self.keepon &= !KEEP_SEND_HOLD;
        }
    }

    /// Returns `true` iff the receive direction is currently held.
    #[must_use]
    pub fn is_recv_hold(&self) -> bool {
        (self.keepon & KEEP_RECV_HOLD) != 0
    }

    /// Returns `true` iff the send direction is currently held.
    #[must_use]
    pub fn is_send_hold(&self) -> bool {
        (self.keepon & KEEP_SEND_HOLD) != 0
    }

    // =====================================================================
    // pause / unpause — mirror curl_easy_pause's keepon manipulation
    // =====================================================================

    /// Applies a `curl_easy_pause`-style action to the pause bits.
    ///
    /// `action` is a bitmask of the `CURLPAUSE_*` constants
    /// ([`CURLPAUSE_RECV`], [`CURLPAUSE_SEND`], [`CURLPAUSE_ALL`],
    /// [`CURLPAUSE_CONT`]). Reproduces curl's logic exactly: both pause bits are
    /// cleared first, then [`KEEP_RECV_PAUSE`] and/or [`KEEP_SEND_PAUSE`] are set
    /// according to the requested directions. Passing [`CURLPAUSE_CONT`] (i.e.
    /// `0`) therefore unpauses both directions.
    pub fn pause(&mut self, action: i32) {
        let mut newstate = self.keepon & !(KEEP_RECV_PAUSE | KEEP_SEND_PAUSE);
        if (action & CURLPAUSE_RECV) != 0 {
            newstate |= KEEP_RECV_PAUSE;
        }
        if (action & CURLPAUSE_SEND) != 0 {
            newstate |= KEEP_SEND_PAUSE;
        }
        self.keepon = newstate;
    }

    /// Unpauses both directions — equivalent to `pause(CURLPAUSE_CONT)`.
    pub fn unpause(&mut self) {
        self.pause(CURLPAUSE_CONT);
    }

    /// Returns `true` iff the receive direction is currently paused
    /// ([`KEEP_RECV_PAUSE`] is set).
    #[must_use]
    pub fn is_recv_paused(&self) -> bool {
        (self.keepon & KEEP_RECV_PAUSE) != 0
    }

    /// Returns `true` iff the send direction is currently paused
    /// ([`KEEP_SEND_PAUSE`] is set).
    #[must_use]
    pub fn is_send_paused(&self) -> bool {
        (self.keepon & KEEP_SEND_PAUSE) != 0
    }

    // =====================================================================
    // Upload completion / abort — mirror req_set_upload_done,
    // Curl_req_abort_sending, Curl_req_stop_send_recv from lib/request.c
    // =====================================================================

    /// Marks the upload as completely sent.
    ///
    /// This is the state half of curl's `req_set_upload_done` /
    /// `Curl_req_set_upload_done`: it sets [`upload_done`](Self::upload_done) and
    /// clears the [`KEEP_SEND`] bit. The progress timestamp, client-reader
    /// completion callback and send-side close that curl also performs are
    /// network/side-effecting operations owned by `transfer.rs`.
    pub fn set_upload_done(&mut self) -> Result<()> {
        self.upload_done = true;
        self.keepon &= !KEEP_SEND;
        Ok(())
    }

    /// Stops sending any further request data, discarding whatever is still
    /// buffered.
    ///
    /// Mirrors `Curl_req_abort_sending`: if the upload was not already done, the
    /// send buffer is cleared, [`upload_aborted`](Self::upload_aborted) is set,
    /// the [`KEEP_SEND`] bit is cleared and the upload is marked done via
    /// [`set_upload_done`](Self::set_upload_done).
    pub fn abort_sending(&mut self) -> Result<()> {
        if !self.upload_done {
            if self.sendbuf_init {
                self.sendbuf.clear();
            }
            self.upload_aborted = true;
            self.keepon &= !KEEP_SEND;
            return self.set_upload_done();
        }
        Ok(())
    }

    /// Stops both sending and receiving further request data.
    ///
    /// Mirrors `Curl_req_stop_send_recv`: if sending is still active it is
    /// aborted first, then the plain [`KEEP_RECV`] and [`KEEP_SEND`] bits are
    /// cleared. The receive *pause*/*hold* bits are deliberately left in place —
    /// the transfer may still be paused on receive-side client writes.
    pub fn stop_send_recv(&mut self) -> Result<()> {
        let mut result = Ok(());
        if (self.keepon & KEEP_SEND) != 0 {
            result = self.abort_sending();
        }
        self.keepon &= !(KEEP_RECV | KEEP_SEND);
        result
    }
}

impl SingleRequest {
    // =====================================================================
    // Client writer / reader attachment points
    //
    // request.rs *holds* the heads of the writer and reader stacks; the concrete
    // chains are built and driven by transfer.rs / content_encoding.rs. These
    // accessors let the transfer layer attach, borrow, and detach the stacks.
    // =====================================================================

    /// Attaches (or replaces) the client-writer stack head.
    pub fn set_writer_stack(&mut self, writer: Box<dyn ClientWriter>) {
        self.writer_stack = Some(writer);
    }

    /// Detaches and returns the client-writer stack head, if any.
    pub fn take_writer_stack(&mut self) -> Option<Box<dyn ClientWriter>> {
        self.writer_stack.take()
    }

    /// Borrows the client-writer stack head mutably so the transfer layer can
    /// drive it.
    pub fn writer_stack_mut(&mut self) -> Option<&mut (dyn ClientWriter + 'static)> {
        self.writer_stack.as_deref_mut()
    }

    /// Returns `true` iff a client-writer stack is attached.
    #[must_use]
    pub fn has_writer_stack(&self) -> bool {
        self.writer_stack.is_some()
    }

    /// Attaches (or replaces) the client-reader stack head.
    pub fn set_reader_stack(&mut self, reader: Box<dyn ClientReader>) {
        self.reader_stack = Some(reader);
    }

    /// Detaches and returns the client-reader stack head, if any.
    pub fn take_reader_stack(&mut self) -> Option<Box<dyn ClientReader>> {
        self.reader_stack.take()
    }

    /// Borrows the client-reader stack head mutably so the transfer layer can
    /// drive it.
    pub fn reader_stack_mut(&mut self) -> Option<&mut (dyn ClientReader + 'static)> {
        self.reader_stack.as_deref_mut()
    }

    /// Returns `true` iff a client-reader stack is attached.
    #[must_use]
    pub fn has_reader_stack(&self) -> bool {
        self.reader_stack.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal in-test client writer that records every chunk it is handed.
    #[derive(Debug)]
    struct MockWriter {
        written: Vec<(u32, Vec<u8>)>,
        paused: bool,
    }

    impl MockWriter {
        fn new() -> Self {
            Self {
                written: Vec::new(),
                paused: false,
            }
        }
    }

    impl ClientWriter for MockWriter {
        fn write(&mut self, wtype: ClientWriteType, buf: &[u8]) -> Result<()> {
            self.written.push((wtype.bits(), buf.to_vec()));
            Ok(())
        }

        fn is_paused(&self) -> bool {
            self.paused
        }
    }

    /// Minimal in-test client reader that yields a fixed byte string.
    #[derive(Debug)]
    struct MockReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl MockReader {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                pos: 0,
            }
        }
    }

    impl ClientReader for MockReader {
        fn read(&mut self, buf: &mut [u8]) -> Result<ClientRead> {
            let remaining = self.data.len() - self.pos;
            let n = remaining.min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(ClientRead {
                nread: n,
                eos: self.pos >= self.data.len(),
            })
        }

        fn total_length(&self) -> Option<u64> {
            Some(self.data.len() as u64)
        }
    }

    #[test]
    fn new_is_zeroed_like_curl_req_init() {
        let req = SingleRequest::new();
        // memset(0) semantics: counters and sizes are 0 (NOT -1), all flags false.
        assert_eq!(req.size, 0);
        assert_eq!(req.maxdownload, 0);
        assert_eq!(req.bytecount, 0);
        assert_eq!(req.writebytecount, 0);
        assert_eq!(req.keepon, KEEP_NONE);
        assert!(req.start.is_none());
        assert!(!req.sendbuf_init);
        assert!(req.sendbuf_empty());
        assert!(!req.header);
        assert!(!req.done);
        assert_eq!(req.upgr101, Upgrade101::None);
        assert!(!req.has_writer_stack());
        assert!(!req.has_reader_stack());
    }

    #[test]
    fn init_resets_in_place() {
        let mut req = SingleRequest::new();
        req.bytecount = 123;
        req.keepon = KEEP_RECV | KEEP_SEND;
        req.set_writer_stack(Box::new(MockWriter::new()));
        req.init();
        assert_eq!(req.bytecount, 0);
        assert_eq!(req.keepon, KEEP_NONE);
        assert!(!req.has_writer_stack());
    }

    #[test]
    fn start_then_soft_reset_leaves_counters_consistent() {
        let mut req = SingleRequest::new();
        req.start(Instant::now(), 4096).unwrap();
        assert!(req.start.is_some());
        assert!(req.sendbuf_init);
        assert_eq!(req.bytecount, 0);
        assert_eq!(req.writebytecount, 0);
        assert_eq!(req.headerbytecount, 0);
        assert_eq!(req.allheadercount, 0);
        assert_eq!(req.deductheadercount, 0);
        assert!(req.sendbuf_empty());
        assert!(!req.done);
        assert!(!req.upload_done);
        assert!(!req.download_done);
    }

    #[test]
    fn lifecycle_init_start_done_counters_consistent() {
        let mut req = SingleRequest::new();
        req.start(Instant::now(), 1024).unwrap();

        // Simulate an in-flight transfer updating counters and pipeline state.
        req.bytecount = 500;
        req.writebytecount = 200;
        req.headerbytecount = 80;
        req.allheadercount = 80;
        req.keepon = KEEP_RECV | KEEP_SEND;
        req.set_writer_stack(Box::new(MockWriter::new()));
        req.set_reader_stack(Box::new(MockReader::new(b"body")));
        req.reader_started = true;

        // Completing the request resets the client pipeline but does NOT zero the
        // accumulated counters (curl's Curl_req_done behaviour).
        req.done(false).unwrap();
        assert!(!req.has_writer_stack());
        assert!(!req.has_reader_stack());
        assert!(!req.reader_started);
        assert_eq!(req.bytecount, 500);
        assert_eq!(req.writebytecount, 200);
    }

    #[test]
    fn soft_reset_preserves_session_state_but_clears_body_counters() {
        // This models a redirect/auth follow-up: body counters and the header
        // phase are cleared, while session state (size, maxdownload, keepon,
        // newurl) is preserved.
        let mut req = SingleRequest::new();
        req.start(Instant::now(), 512).unwrap();
        req.size = 9999;
        req.maxdownload = 8888;
        req.keepon = KEEP_RECV;
        req.newurl = Some("https://example.com/next".to_string());
        req.bytecount = 4242;
        req.writebytecount = 111;
        req.headerbytecount = 64;
        req.header = true;
        req.httpversion = 11;

        req.soft_reset(512).unwrap();

        // Body/header counters and phase cleared:
        assert_eq!(req.bytecount, 0);
        assert_eq!(req.writebytecount, 0);
        assert_eq!(req.headerbytecount, 0);
        assert!(!req.header);
        assert_eq!(req.httpversion, 0);
        // Session state preserved:
        assert_eq!(req.size, 9999);
        assert_eq!(req.maxdownload, 8888);
        assert_eq!(req.keepon, KEEP_RECV);
        assert_eq!(req.newurl.as_deref(), Some("https://example.com/next"));
    }

    #[test]
    fn hard_reset_restores_virgin_sentinels_and_clears_body_counters() {
        let mut req = SingleRequest::new();
        req.start(Instant::now(), 256).unwrap();
        req.size = 500;
        req.maxdownload = 400;
        req.bytecount = 4242;
        req.writebytecount = 111;
        req.offset = 77;
        req.keepon = KEEP_RECV | KEEP_SEND;
        req.newurl = Some("https://redir".to_string());
        req.location = Some("https://redir".to_string());
        req.upgr101 = Upgrade101::H2;
        // Sticky flags curl deliberately preserves across a hard reset:
        req.done = true;
        req.resp_trailer = true;
        req.httpversion = 20;

        req.hard_reset(true);

        // Virgin sentinels and cleared counters:
        assert_eq!(req.size, -1);
        assert_eq!(req.maxdownload, -1);
        assert_eq!(req.bytecount, 0);
        assert_eq!(req.writebytecount, 0);
        assert_eq!(req.offset, 0);
        assert_eq!(req.keepon, KEEP_NONE);
        assert!(req.newurl.is_none());
        assert!(req.location.is_none());
        assert!(req.start.is_none());
        assert_eq!(req.upgr101, Upgrade101::None);
        // opt_no_body seeded from the argument:
        assert!(req.no_body);
        // Buffer stays initialised (curl keeps sendbuf across a hard reset):
        assert!(req.sendbuf_init);
        // Sticky state preserved exactly as curl does:
        assert!(req.done);
        assert!(req.resp_trailer);
        assert_eq!(req.httpversion, 20);
    }

    #[test]
    fn keepon_send_recv_and_hold_transitions() {
        let mut req = SingleRequest::new();

        req.set_send(true);
        assert!(req.want_send());
        assert!(!req.want_recv());

        // A HOLD suppresses "want" without dropping the plain bit.
        req.hold_send(true);
        assert!(req.is_send_hold());
        assert!(!req.want_send());
        assert_eq!(req.keepon & KEEP_SEND, KEEP_SEND);

        req.hold_send(false);
        assert!(!req.is_send_hold());
        assert!(req.want_send());

        req.set_recv(true);
        assert!(req.want_recv());
        req.hold_recv(true);
        assert!(!req.want_recv());
        assert!(req.is_recv_hold());
        req.hold_recv(false);
        assert!(req.want_recv());

        req.set_send(false);
        assert!(!req.want_send());
    }

    #[test]
    fn pause_matches_curl_easy_pause_semantics() {
        let mut req = SingleRequest::new();
        req.set_send(true);
        req.set_recv(true);
        assert!(req.want_send());
        assert!(req.want_recv());

        // Pausing send sets the SEND_PAUSE bit and suppresses want_send only.
        req.pause(CURLPAUSE_SEND);
        assert!(req.is_send_paused());
        assert!(!req.is_recv_paused());
        assert!(!req.want_send());
        assert!(req.want_recv());
        // The plain KEEP_SEND bit is retained under a pause.
        assert_eq!(req.keepon & KEEP_SEND, KEEP_SEND);

        // pause() replaces (does not accumulate): pausing RECV clears SEND_PAUSE.
        req.pause(CURLPAUSE_RECV);
        assert!(req.is_recv_paused());
        assert!(!req.is_send_paused());
        assert!(req.want_send());
        assert!(!req.want_recv());

        // Pause both.
        req.pause(CURLPAUSE_ALL);
        assert!(req.is_recv_paused());
        assert!(req.is_send_paused());

        // Unpause clears both pause bits (CURLPAUSE_CONT == 0).
        req.unpause();
        assert!(!req.is_recv_paused());
        assert!(!req.is_send_paused());
        assert!(req.want_send());
        assert!(req.want_recv());
    }

    #[test]
    fn send_buffer_add_peek_consume_and_hds_bookkeeping() {
        let mut req = SingleRequest::new();
        // queue_request buffers the request head as all-header bytes.
        req.queue_request(b"GET / HTTP/1.1\r\n\r\n", 11).unwrap();
        assert_eq!(req.httpversion_sent, 11);
        assert!(!req.sendbuf_empty());
        let head_len = b"GET / HTTP/1.1\r\n\r\n".len();
        assert_eq!(req.sendbuf_len(), head_len);
        assert_eq!(req.sendbuf_hds_len, head_len);

        // Appending body bytes (hds_len = 0) does not grow the header count.
        req.send_buffer_add(b"payload", 0).unwrap();
        assert_eq!(req.sendbuf_len(), head_len + 7);
        assert_eq!(req.sendbuf_hds_len, head_len);
        assert_eq!(req.sendbuf_peek().len(), head_len + 7);

        // Consume half of the header bytes: header count drops by that much.
        let consumed = req.sendbuf_consume(5);
        assert_eq!(consumed, 5);
        assert_eq!(req.sendbuf_hds_len, head_len - 5);
        assert_eq!(req.sendbuf_len(), head_len + 7 - 5);

        // Consume past the remaining header into the body: header count hits 0.
        let rest_of_header = head_len - 5;
        let consumed = req.sendbuf_consume(rest_of_header + 2);
        assert_eq!(consumed, rest_of_header + 2);
        assert_eq!(req.sendbuf_hds_len, 0);

        // Consume everything (clamped) leaves an empty buffer.
        let left = req.sendbuf_len();
        let consumed = req.sendbuf_consume(left + 100);
        assert_eq!(consumed, left);
        assert!(req.sendbuf.is_empty());
        assert!(req.sendbuf_empty());
    }

    #[test]
    fn set_upload_done_clears_keep_send() {
        let mut req = SingleRequest::new();
        req.set_send(true);
        assert!(req.want_send());
        req.set_upload_done().unwrap();
        assert!(req.upload_done);
        assert_eq!(req.keepon & KEEP_SEND, 0);
        assert!(req.done_sending());
    }

    #[test]
    fn abort_sending_clears_buffer_and_marks_done() {
        let mut req = SingleRequest::new();
        req.set_send(true);
        req.send_buffer_add(b"unsent body", 0).unwrap();
        assert!(!req.sendbuf_empty());

        req.abort_sending().unwrap();
        assert!(req.upload_aborted);
        assert!(req.upload_done);
        assert_eq!(req.keepon & KEEP_SEND, 0);
        assert!(req.sendbuf_empty());

        // Calling abort again on an already-done upload is a harmless no-op that
        // does not flip upload_aborted off.
        req.upload_aborted = false;
        req.abort_sending().unwrap();
        assert!(!req.upload_aborted);
    }

    #[test]
    fn stop_send_recv_aborts_send_and_preserves_recv_pause() {
        let mut req = SingleRequest::new();
        req.set_send(true);
        req.set_recv(true);
        req.pause(CURLPAUSE_RECV); // pause receive-side client writes
        req.send_buffer_add(b"pending", 0).unwrap();

        req.stop_send_recv().unwrap();

        // Sending was aborted:
        assert!(req.upload_aborted);
        assert!(req.upload_done);
        assert!(req.sendbuf_empty());
        // Plain RECV and SEND bits cleared:
        assert_eq!(req.keepon & KEEP_RECV, 0);
        assert_eq!(req.keepon & KEEP_SEND, 0);
        // But the receive PAUSE bit is deliberately kept.
        assert!(req.is_recv_paused());
    }

    #[test]
    fn client_writer_attachment_point_round_trip() {
        let mut req = SingleRequest::new();
        assert!(!req.has_writer_stack());
        req.set_writer_stack(Box::new(MockWriter::new()));
        assert!(req.has_writer_stack());

        // Drive the writer via the mutable borrow.
        {
            let writer = req.writer_stack_mut().expect("writer attached");
            writer
                .write(ClientWriteType::HEADER, b"HTTP/1.1 200 OK\r\n")
                .unwrap();
            writer.write(ClientWriteType::BODY, b"hello").unwrap();
            assert!(!writer.is_paused());
        }

        // Detach and inspect what was written.
        let taken = req.take_writer_stack().expect("writer present");
        // Downcast is not needed; just confirm detachment cleared the slot.
        drop(taken);
        assert!(!req.has_writer_stack());
    }

    #[test]
    fn client_reader_attachment_point_drives_reads() {
        let mut req = SingleRequest::new();
        req.set_reader_stack(Box::new(MockReader::new(b"abcdef")));
        assert!(req.has_reader_stack());

        let mut buf = [0u8; 4];
        let reader = req.reader_stack_mut().expect("reader attached");
        assert_eq!(reader.total_length(), Some(6));
        let r1 = reader.read(&mut buf).unwrap();
        assert_eq!(r1.nread, 4);
        assert!(!r1.eos);
        assert_eq!(&buf[..4], b"abcd");
        let r2 = reader.read(&mut buf).unwrap();
        assert_eq!(r2.nread, 2);
        assert!(r2.eos);
        assert_eq!(&buf[..2], b"ef");

        assert!(req.take_reader_stack().is_some());
        assert!(!req.has_reader_stack());
    }

    #[test]
    fn free_releases_buffer_and_handles() {
        let mut req = SingleRequest::new();
        req.start(Instant::now(), 128).unwrap();
        req.send_buffer_add(b"data", 4).unwrap();
        req.set_writer_stack(Box::new(MockWriter::new()));
        req.set_reader_stack(Box::new(MockReader::new(b"x")));
        req.newurl = Some("https://x".to_string());

        req.free();

        assert!(req.sendbuf_empty());
        assert!(!req.sendbuf_init);
        assert_eq!(req.sendbuf_hds_len, 0);
        assert!(req.newurl.is_none());
        assert!(!req.has_writer_stack());
        assert!(!req.has_reader_stack());
    }

    #[test]
    fn client_write_type_bitops() {
        let combo = ClientWriteType::BODY | ClientWriteType::HEADER;
        assert!(combo.contains(ClientWriteType::BODY));
        assert!(combo.contains(ClientWriteType::HEADER));
        assert!(!combo.contains(ClientWriteType::STATUS));
        assert!(combo.intersects(ClientWriteType::HEADER));
        assert!(!combo.intersects(ClientWriteType::EOS));
        assert!(!combo.is_empty());
        assert!(ClientWriteType::NONE.is_empty());
        assert_eq!(ClientWriteType::default(), ClientWriteType::NONE);

        // Verify the raw bit values match curl's CLIENTWRITE_* defines.
        assert_eq!(ClientWriteType::BODY.bits(), 1 << 0);
        assert_eq!(ClientWriteType::INFO.bits(), 1 << 1);
        assert_eq!(ClientWriteType::HEADER.bits(), 1 << 2);
        assert_eq!(ClientWriteType::STATUS.bits(), 1 << 3);
        assert_eq!(ClientWriteType::CONNECT.bits(), 1 << 4);
        assert_eq!(ClientWriteType::HTTP1XX.bits(), 1 << 5);
        assert_eq!(ClientWriteType::TRAILER.bits(), 1 << 6);
        assert_eq!(ClientWriteType::EOS.bits(), 1 << 7);
        assert_eq!(ClientWriteType::ZERO_LEN.bits(), 1 << 8);

        let mut acc = ClientWriteType::NONE;
        acc |= ClientWriteType::BODY;
        acc |= ClientWriteType::EOS;
        assert_eq!(acc, ClientWriteType::BODY | ClientWriteType::EOS);
        assert_eq!(ClientWriteType::from_bits(acc.bits()), acc);
    }

    #[test]
    fn keep_bit_values_match_curl() {
        // The frozen historical KEEP_* values from lib/urldata.h.
        assert_eq!(KEEP_NONE, 0);
        assert_eq!(KEEP_RECV, 1 << 0);
        assert_eq!(KEEP_SEND, 1 << 1);
        assert_eq!(KEEP_RECV_HOLD, 1 << 2);
        assert_eq!(KEEP_SEND_HOLD, 1 << 3);
        assert_eq!(KEEP_RECV_PAUSE, 1 << 4);
        assert_eq!(KEEP_SEND_PAUSE, 1 << 5);
        assert_eq!(KEEP_SEND_TIMED, 1 << 6);
        assert_eq!(KEEP_RECVBITS, KEEP_RECV | KEEP_RECV_HOLD | KEEP_RECV_PAUSE);
        assert_eq!(KEEP_SENDBITS, KEEP_SEND | KEEP_SEND_HOLD | KEEP_SEND_PAUSE);
        // CURLPAUSE_* values from include/curl/curl.h.
        assert_eq!(CURLPAUSE_RECV, 1 << 0);
        assert_eq!(CURLPAUSE_SEND, 1 << 2);
        assert_eq!(CURLPAUSE_ALL, CURLPAUSE_RECV | CURLPAUSE_SEND);
        assert_eq!(CURLPAUSE_CONT, 0);
    }

    #[test]
    fn expect100_and_upgrade101_defaults() {
        assert_eq!(Expect100::default(), Expect100::SendData);
        assert_eq!(Upgrade101::default(), Upgrade101::None);
    }
}
