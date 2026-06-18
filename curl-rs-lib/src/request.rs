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

//! Per-transfer request state — the Rust replacement for libcurl's
//! `struct SingleRequest` and the `Curl_req_*` lifecycle functions
//! (`lib/request.c`, `lib/request.h`).
//!
//! A [`Request`] holds the mutable bookkeeping for exactly **one** in-flight
//! request/response on a transfer: the byte counters the progress meter reads,
//! the header/body phase flags the HTTP parser toggles, the upload/download
//! "done" state, the keep-going [`KeepOn`] flags that drive the event loop, and
//! the staged outgoing bytes waiting to be written to the wire. The async
//! transfer loop in [`crate::transfer`] owns one `Request` per attempt and
//! mutates it as it pumps the request; [`crate::progress`] reads its counters
//! and [`crate::protocols::http`] reads/sets its header-phase flags.
//!
//! # Relationship to the C original
//!
//! This is a *behavioral* re-implementation, not a line-by-line transliteration
//! of `lib/request.c`. The mapping is:
//!
//! | C (`lib/request.c` / `request.h`)        | Rust (`Request`)                         |
//! |------------------------------------------|------------------------------------------|
//! | `Curl_req_init`                          | [`Request::new`] / [`Request::default`]  |
//! | `Curl_req_start`                         | [`Request::start`]                       |
//! | `Curl_req_soft_reset`                    | [`Request::soft_reset`]                  |
//! | `Curl_req_hard_reset`                    | [`Request::hard_reset`]                  |
//! | `Curl_req_done`                          | [`Request::done`]                        |
//! | `Curl_req_free`                          | automatic `Drop` (see below)             |
//! | `req_send_buffer_add` (in `Curl_req_send`)| [`Request::stage_send`]                 |
//! | `req_send_buffer_flush`                  | [`Request::consume_sent`]                |
//! | `req_set_upload_done`                    | [`Request::set_upload_done`]             |
//! | `Curl_req_abort_sending`                 | [`Request::abort_sending`]               |
//! | `Curl_req_stop_send_recv`                | [`Request::stop_send_recv`]              |
//! | `Curl_req_want_send` / `_want_recv`      | [`Request::wants_send`] / [`wants_recv`] |
//! | `Curl_req_done_sending`                  | [`Request::done_sending`]                |
//! | `Curl_req_sendbuf_empty`                 | [`Request::sendbuf_empty`]               |
//! | `int keepon` bitmask (`KEEP_RECV`/`KEEP_SEND`) | typed [`KeepOn`] flags              |
//! | `struct bufq sendbuf` + `sendbuf_hds_len`| private [`bytes::BytesMut`] + counter    |
//!
//! The two reset levels are the heart of connection reuse, so their
//! field-survival semantics mirror `lib/request.c` exactly (see
//! [`Request::soft_reset`] and [`Request::hard_reset`]).
//!
//! ## Drop replaces `Curl_req_free`
//!
//! `Curl_req_free` manually `free()`s `newurl` and the `sendbuf` and tears down
//! the client reader/writer. In Rust every owned resource a `Request` holds (the
//! [`String`] fields and the [`bytes::BytesMut`] send buffer) is released
//! automatically by its own `Drop` when the `Request` is dropped, so no explicit
//! destructor is needed. That automatic, leak-free cleanup *is* the memory-safety
//! win of the migration (AAP §0.7.1), which is why this module deliberately
//! provides no hand-written `Drop` impl.
//!
//! # Scope
//!
//! This struct is **generic per-request bookkeeping** and contains no
//! protocol-specific logic: the actual socket I/O is performed by
//! [`crate::conn`]/the filter chain, client read/write callbacks live in the
//! transfer engine, and protocol parsing lives in `crate::protocols`. Only the
//! staged send bytes and the counters live here.
//!
//! # Memory safety
//!
//! This module performs no raw-pointer or manual buffer arithmetic: outgoing
//! bytes live in a [`bytes::BytesMut`] and are consumed through the safe
//! [`bytes::Buf`] cursor. It contains **zero** `unsafe` and compiles under the
//! module-level `#![forbid(unsafe_code)]` declared below (which is consistent
//! with the crate-root `#![forbid(unsafe_code)]`).

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use bytes::{Buf, BytesMut};

use crate::error::{CurlError, Result};

/// Typed model of libcurl's `int keepon` bitmask
/// (`KEEP_RECV` / `KEEP_SEND`, `lib/urldata.h`).
///
/// In curl, `keepon` is an `int` OR-ed from `KEEP_RECV (1 << 0)` ("there is or
/// may be data to read") and `KEEP_SEND (1 << 1)` ("there is or may be data to
/// write"). The older `KEEP_*_PAUSE` / `KEEP_*_HOLD` bits no longer exist in the
/// 8.19.0-DEV baseline — pausing is handled by the rate limiter — so the whole
/// space is exactly these two independent flags. Modelling them as named
/// booleans (rather than a raw bitmask) makes the event-loop predicates
/// self-documenting and impossible to get wrong with the wrong constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeepOn {
    /// `KEEP_RECV` — the transfer wants to (or may) receive more data.
    pub recv: bool,
    /// `KEEP_SEND` — the transfer wants to (or may) send more data.
    pub send: bool,
}

impl KeepOn {
    /// All flags cleared (`KEEP_NONE`, i.e. `keepon == 0`).
    pub const NONE: KeepOn = KeepOn {
        recv: false,
        send: false,
    };

    /// Construct from explicit `recv`/`send` flags.
    #[must_use]
    pub const fn new(recv: bool, send: bool) -> Self {
        Self { recv, send }
    }

    /// `true` when neither direction is active (`keepon == KEEP_NONE`).
    #[must_use]
    pub const fn is_clear(&self) -> bool {
        !self.recv && !self.send
    }
}

/// State of an HTTP `101 Switching Protocols` upgrade for this request,
/// mirroring C's `enum upgrade101` (`lib/request.h`).
///
/// The field exists on the per-request struct in curl; it is carried here as
/// plain state (no protocol logic) so the transfer engine and the HTTP module
/// can track upgrade negotiation without reaching into protocol internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Upgrade101 {
    /// `UPGR101_NONE` — default state, no upgrade requested.
    #[default]
    None,
    /// `UPGR101_WS` — upgrade to WebSocket requested.
    Ws,
    /// `UPGR101_H2` — upgrade to HTTP/2 requested.
    H2,
    /// `UPGR101_RECEIVED` — a `101` response has been received.
    Received,
}

/// Per-request state for a single in-flight request/response on a transfer.
///
/// This mirrors the meaningful members of C's `struct SingleRequest`. Most
/// fields are `pub` because this is a shared state record that the transfer loop
/// mutates directly and that [`crate::progress`] / `crate::protocols` read; the
/// send buffer and its header-prefix length are the only private members,
/// guarded behind methods so the invariant `sendbuf_hds_len <= sendbuf.len()`
/// can never be violated by a caller.
///
/// Construct with [`Request::new`], begin a request attempt with
/// [`Request::start`], and reset between attempts with [`Request::soft_reset`]
/// (follow-up on a reused connection) or [`Request::hard_reset`] (virgin state
/// for a brand-new transfer).
#[derive(Debug)]
pub struct Request {
    // ---- sizes -------------------------------------------------------------
    /// Expected size of the response body in bytes (`SingleRequest::size`).
    ///
    /// `None` is curl's `-1` ("unknown at this point"); `Some(n)` is a known
    /// content length of `n` bytes.
    pub size: Option<i64>,

    /// Maximum number of body bytes to fetch (`SingleRequest::maxdownload`).
    ///
    /// `None` is curl's `-1` ("unlimited"); `Some(n)` caps the download at `n`
    /// bytes (used for ranged requests).
    pub maxdownload: Option<i64>,

    /// Possible resume offset read from a `Content-Range:` header
    /// (`SingleRequest::offset`).
    pub offset: i64,

    // ---- byte / line counters ---------------------------------------------
    /// Total number of body bytes read for this request
    /// (`SingleRequest::bytecount`).
    pub bytecount: u64,

    /// Number of body bytes written/uploaded for this request
    /// (`SingleRequest::writebytecount`). Incremented by [`Request::consume_sent`]
    /// for the non-header portion of each flushed chunk.
    pub writebytecount: u64,

    /// Received server header bytes, excluding `CONNECT` headers
    /// (`SingleRequest::headerbytecount`).
    pub headerbytecount: u64,

    /// All received header bytes, including `CONNECT` headers
    /// (`SingleRequest::allheadercount`).
    pub allheadercount: u64,

    /// Header bytes that must *not* count when checking whether anything was
    /// transferred at end-of-connection (`SingleRequest::deductheadercount`);
    /// used so a lone `100` reply yields `CURLE_GOT_NOTHING`.
    pub deductheadercount: u64,

    /// Counts header lines, to better track the first (status) line
    /// (`SingleRequest::headerline`).
    pub headerline: u32,

    // ---- status / version --------------------------------------------------
    /// HTTP/RTSP status code parsed from the `HTTP/1.x XXX` line
    /// (`SingleRequest::httpcode`); `0` until parsed.
    pub httpcode: i32,

    /// Version sent in the request (`9`, `10`, `11`, `20`, `30`)
    /// (`SingleRequest::httpversion_sent`).
    pub httpversion_sent: u8,

    /// Version seen in the response (`SingleRequest::httpversion`).
    pub httpversion: u8,

    /// HTTP `101` upgrade state (`SingleRequest::upgr101`).
    pub upgr101: Upgrade101,

    // ---- timing ------------------------------------------------------------
    /// When this request attempt started (`SingleRequest::start`). Preserved
    /// across [`Request::soft_reset`] so overall duration spans follow-ups, and
    /// reset by [`Request::start`] / [`Request::hard_reset`].
    pub start: Instant,

    /// Most recent time observed by the transfer engine; the progress code reads
    /// this together with [`start`](Self::start) to compute elapsed time. Update
    /// via [`Request::update_now`].
    pub now: Instant,

    /// Document modification time (`SingleRequest::timeofdoc`), as seconds since
    /// the Unix epoch; `0` when unknown.
    pub timeofdoc: i64,

    // ---- redirect / location strings --------------------------------------
    /// Owned copy of the `Location:` header value (`SingleRequest::location`).
    pub location: Option<String>,

    /// New URL to use for a redirect or retry (`SingleRequest::newurl`).
    pub newurl: Option<String>,

    /// Count of cookies set by the response (`SingleRequest::setcookies`).
    pub setcookies: u8,

    // ---- event-loop state --------------------------------------------------
    /// Read/write "keep going" flags (`SingleRequest::keepon`).
    pub keepon: KeepOn,

    // ---- send buffer (private — invariant-guarded) ------------------------
    /// Outgoing bytes staged for the wire (C `struct bufq sendbuf`). Private so
    /// the `sendbuf_hds_len <= sendbuf.len()` invariant is upheld by the methods.
    sendbuf: BytesMut,

    /// Number of leading header bytes currently staged in `sendbuf`
    /// (`SingleRequest::sendbuf_hds_len`). Always `<= sendbuf.len()`.
    sendbuf_hds_len: usize,

    // ---- phase / state flags (C `BIT(...)` members) -----------------------
    /// Incoming data is still HTTP header (`BIT(header)`).
    pub header: bool,
    /// Request is done; no more send/recv should happen (`BIT(done)`). May be
    /// `true` before `upload_done`/`download_done`.
    pub done: bool,
    /// A `Content-Range:` header was seen (`BIT(content_range)`).
    pub content_range: bool,
    /// The download is complete (`BIT(download_done)`).
    pub download_done: bool,
    /// End-of-stream has been written to the client (`BIT(eos_written)`).
    pub eos_written: bool,
    /// End-of-stream has been read from the client (`BIT(eos_read)`).
    pub eos_read: bool,
    /// End-of-stream has been sent to the server (`BIT(eos_sent)`).
    pub eos_sent: bool,
    /// The reader needs a rewind at the next start (`BIT(rewind_read)`).
    pub rewind_read: bool,
    /// All request data has been sent (`BIT(upload_done)`).
    pub upload_done: bool,
    /// The upload was aborted; implies `upload_done` (`BIT(upload_aborted)`).
    pub upload_aborted: bool,
    /// A response body is being read but ignored (`BIT(ignorebody)`).
    pub ignorebody: bool,
    /// Response status is `1xx`, `204`, or `304` — no body (`BIT(http_bodyless)`).
    pub http_bodyless: bool,
    /// This is a chunked transfer-encoding download (`BIT(chunk)`).
    pub chunk: bool,
    /// The response carried a `Trailer:` header field (`BIT(resp_trailer)`).
    pub resp_trailer: bool,
    /// Ignore the `Content-Length` (`BIT(ignore_cl)`).
    pub ignore_cl: bool,
    /// Doing chunked transfer-encoding on upload (`BIT(upload_chunky)`).
    pub upload_chunky: bool,
    /// The response has no body (`BIT(no_body)`); seeded from the easy handle's
    /// "no body" option by [`Request::hard_reset`].
    pub no_body: bool,
    /// The auth phase has started: this request carries an auth header but is not
    /// the final request in the negotiation (`BIT(authneg)`).
    pub authneg: bool,
    /// Finishing this request will shut down the connection (`BIT(shutdown)`).
    pub shutdown: bool,
    /// Errors during shutdown must not fail the request (`BIT(shutdown_err_ignore)`).
    pub shutdown_err_ignore: bool,
    /// Client reads have started (`BIT(reader_started)`).
    pub reader_started: bool,
}

impl Request {
    /// Create a freshly initialized request (≙ `Curl_req_init`).
    ///
    /// `Curl_req_init` `memset`s the struct to all-zero. We reproduce that
    /// zeroed state with idiomatic defaults: every counter is `0`, every flag is
    /// `false`, [`keepon`](Self::keepon) is [`KeepOn::NONE`], the send buffer is
    /// empty, and [`size`](Self::size)/[`maxdownload`](Self::maxdownload) are
    /// `None` (curl's `-1`, "unknown"/"unlimited"). The two timing instants are
    /// seeded with [`Instant::now`]; the precise per-request start is then set by
    /// [`Request::start`]. (`Instant` has no representable "zero", so the C
    /// `{0, 0}` start is modelled as "captured at construction and overwritten on
    /// start" — `start` is always called before the timing is observed.)
    #[must_use]
    pub fn new() -> Self {
        let t = Instant::now();
        Request {
            size: None,
            maxdownload: None,
            offset: 0,
            bytecount: 0,
            writebytecount: 0,
            headerbytecount: 0,
            allheadercount: 0,
            deductheadercount: 0,
            headerline: 0,
            httpcode: 0,
            httpversion_sent: 0,
            httpversion: 0,
            upgr101: Upgrade101::None,
            start: t,
            now: t,
            timeofdoc: 0,
            location: None,
            newurl: None,
            setcookies: 0,
            keepon: KeepOn::NONE,
            sendbuf: BytesMut::new(),
            sendbuf_hds_len: 0,
            header: false,
            done: false,
            content_range: false,
            download_done: false,
            eos_written: false,
            eos_read: false,
            eos_sent: false,
            rewind_read: false,
            upload_done: false,
            upload_aborted: false,
            ignorebody: false,
            http_bodyless: false,
            chunk: false,
            resp_trailer: false,
            ignore_cl: false,
            upload_chunky: false,
            no_body: false,
            authneg: false,
            shutdown: false,
            shutdown_err_ignore: false,
            reader_started: false,
        }
    }

    /// Begin a request attempt at time `now` (≙ `Curl_req_start`).
    ///
    /// Records the start time and then performs a [`soft_reset`](Self::soft_reset).
    /// `now` is supplied by the caller (the transfer engine's cached "now",
    /// equivalent to curl's `Curl_pgrs_now`) so the whole engine shares one clock.
    pub fn start(&mut self, now: Instant) {
        self.start = now;
        self.now = now;
        self.soft_reset();
    }

    /// Reset for a follow-up request on a (possibly reused) connection
    /// (≙ `Curl_req_soft_reset`).
    ///
    /// This clears the per-attempt state but **preserves** the transfer-level
    /// configuration needed to continue across a redirect/retry. Matching
    /// `lib/request.c` exactly:
    ///
    /// * **Cleared:** `done`, `upload_done`, `upload_aborted`, `download_done`,
    ///   `eos_written`, `eos_read`, `eos_sent`, `ignorebody`, `shutdown`,
    ///   `header`.
    /// * **Zeroed:** `bytecount`, `writebytecount`, `headerline`,
    ///   `headerbytecount`, `allheadercount`, `deductheadercount`,
    ///   `httpversion_sent`, `httpversion`, `sendbuf_hds_len`; the send buffer is
    ///   emptied.
    /// * **Preserved:** `size`, `maxdownload`, `offset`, `httpcode`, `keepon`,
    ///   `upgr101`, `timeofdoc`, `location`, `newurl`, `setcookies`,
    ///   `content_range`, `rewind_read`, `http_bodyless`, `chunk`,
    ///   `resp_trailer`, `ignore_cl`, `upload_chunky`, `no_body`, `authneg`,
    ///   `shutdown_err_ignore`, `reader_started`, and — crucially — `start`/`now`
    ///   so overall duration keeps counting across the follow-up.
    pub fn soft_reset(&mut self) {
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
        self.sendbuf.clear();
    }

    /// Hard-reset to the virgin state for a brand-new transfer, seeding
    /// `no_body` from the easy handle's "no body" option
    /// (≙ `Curl_req_hard_reset`, where `no_body == data->set.opt_no_body`).
    ///
    /// Unlike [`soft_reset`](Self::soft_reset), this returns transfer-level state
    /// to defaults. Matching `lib/request.c` exactly:
    ///
    /// * **Reset:** `newurl`/`location` to `None` (the previous strings are
    ///   dropped — the safe replacement for curl's manual `free`/`= NULL`),
    ///   the send buffer is emptied, `size`/`maxdownload` to `None` (`-1`),
    ///   `bytecount`, `writebytecount`, `headerbytecount`, `allheadercount`,
    ///   `deductheadercount`, `headerline`, `offset`, `httpcode` to `0`,
    ///   `keepon` to [`KeepOn::NONE`], `upgr101` to [`Upgrade101::None`],
    ///   `sendbuf_hds_len`/`timeofdoc`/`setcookies` to `0`, the timing to "now",
    ///   and the flags `header`, `content_range`, `download_done`, `eos_written`,
    ///   `eos_read`, `eos_sent`, `rewind_read`, `upload_done`, `upload_aborted`,
    ///   `ignorebody`, `http_bodyless`, `chunk`, `ignore_cl`, `upload_chunky`,
    ///   `authneg`, `shutdown` to `false`; `no_body` to the supplied option.
    /// * **NOT touched** (deliberately preserved, exactly as the C does):
    ///   `done`, `httpversion_sent`, `httpversion`, `resp_trailer`,
    ///   `shutdown_err_ignore`, `reader_started`.
    pub fn hard_reset(&mut self, no_body: bool) {
        let t = Instant::now();
        // Curl_safefree(newurl) / location = NULL — the old owned strings are
        // released safely by replacing them with None.
        self.newurl = None;
        self.location = None;
        // Curl_bufq_reset(&req->sendbuf)
        self.sendbuf.clear();
        self.sendbuf_hds_len = 0;

        self.size = None; // -1
        self.maxdownload = None; // -1
        self.bytecount = 0;
        self.writebytecount = 0;
        self.start = t; // C: start = {0, 0}; the timer is reset
        self.now = t;
        self.headerbytecount = 0;
        self.allheadercount = 0;
        self.deductheadercount = 0;
        self.headerline = 0;
        self.offset = 0;
        self.httpcode = 0;
        self.keepon = KeepOn::NONE;
        self.upgr101 = Upgrade101::None;
        self.timeofdoc = 0;
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
        self.no_body = no_body; // data->set.opt_no_body
        self.authneg = false;
        self.shutdown = false;
        // Intentionally NOT reset (matches Curl_req_hard_reset):
        //   done, httpversion_sent, httpversion, resp_trailer,
        //   shutdown_err_ignore, reader_started.
    }
}

impl Default for Request {
    /// Equivalent to [`Request::new`]; provided so the type satisfies the
    /// standard `Default` contract (and Clippy's `new_without_default`).
    fn default() -> Self {
        Self::new()
    }
}

/// Send-buffer staging and flush accounting.
///
/// These methods are the safe analogue of `req_send_buffer_add` /
/// `req_send_buffer_flush` (and the buffering half of `Curl_req_send` /
/// `Curl_req_send_more`) in `lib/request.c`. They only *stage* bytes and track
/// how much has been flushed — the actual socket write is performed by
/// [`crate::conn`]/the filter chain, which writes the slice returned by
/// [`sendbuf`](Request::sendbuf) and then reports progress via
/// [`consume_sent`](Request::consume_sent).
impl Request {
    /// Stage `data` for sending, of which the first `hds_len` bytes are request
    /// header bytes (≙ `req_send_buffer_add`).
    ///
    /// `hds_len` accumulates into [`sendbuf_hds_len`](Request::sendbuf_hds_len);
    /// header bytes are tracked separately because they do not count toward
    /// upload progress (see [`consume_sent`](Request::consume_sent)). `hds_len`
    /// must not exceed `data.len()`.
    pub fn stage_send(&mut self, data: &[u8], hds_len: usize) {
        debug_assert!(
            hds_len <= data.len(),
            "stage_send: hds_len ({hds_len}) exceeds chunk length ({})",
            data.len()
        );
        self.sendbuf.extend_from_slice(data);
        self.sendbuf_hds_len = self.sendbuf_hds_len.saturating_add(hds_len);
    }

    /// The bytes currently staged for sending, for the connection layer to write
    /// to the wire (≙ peeking the C `sendbuf`).
    #[must_use]
    pub fn sendbuf(&self) -> &[u8] {
        &self.sendbuf[..]
    }

    /// Number of bytes currently staged for sending (≙ `Curl_bufq_len`).
    #[must_use]
    pub fn sendbuf_len(&self) -> usize {
        self.sendbuf.len()
    }

    /// `true` when no bytes are staged for sending (≙ `Curl_req_sendbuf_empty`).
    ///
    /// In C this is `!sendbuf_init || Curl_bufq_is_empty(&sendbuf)`; an
    /// always-ready [`bytes::BytesMut`] needs no separate "initialized" flag, so
    /// an empty buffer is simply empty.
    #[must_use]
    pub fn sendbuf_empty(&self) -> bool {
        self.sendbuf.is_empty()
    }

    /// Number of leading header bytes still staged in the send buffer
    /// (`SingleRequest::sendbuf_hds_len`). Always `<= `[`sendbuf_len`](Request::sendbuf_len).
    #[must_use]
    pub fn sendbuf_hds_len(&self) -> usize {
        self.sendbuf_hds_len
    }

    /// Number of staged-but-unflushed bytes still waiting to be sent.
    ///
    /// This is the modern equivalent of curl's historical
    /// `SingleRequest::upload_present` ("bytes left in the buffer to send"),
    /// which in the 8.19.0-DEV `bufq`-based design is simply the current send
    /// buffer length.
    #[must_use]
    pub fn upload_present(&self) -> usize {
        self.sendbuf.len()
    }

    /// Record that `n` staged bytes were written to the wire
    /// (≙ the accounting in `req_send_buffer_flush`).
    ///
    /// Of the `n` flushed bytes, the leading header bytes (up to
    /// [`sendbuf_hds_len`](Request::sendbuf_hds_len)) do **not** count as upload
    /// progress; the remaining body bytes advance
    /// [`writebytecount`](Request::writebytecount), exactly as `xfer_send`
    /// increments `writebytecount` by `body_len` in `lib/request.c`. The
    /// consumed bytes are then dropped from the front of the buffer.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if `n` exceeds the number of
    /// staged bytes — the buffer is left untouched in that case.
    pub fn consume_sent(&mut self, n: usize) -> Result<()> {
        if n > self.sendbuf.len() {
            return Err(CurlError::BadFunctionArgument);
        }
        let hds = self.sendbuf_hds_len.min(n);
        let body = n - hds;
        self.sendbuf_hds_len -= hds;
        self.writebytecount = self.writebytecount.saturating_add(body as u64);
        // Drop the flushed prefix via the safe `Buf` cursor — no pointer math.
        self.sendbuf.advance(n);
        Ok(())
    }

    /// Mark the upload as fully sent (≙ `req_set_upload_done`).
    ///
    /// Sets [`upload_done`](Request::upload_done) and clears the
    /// [`KeepOn::send`] flag (`keepon &= ~KEEP_SEND`). If the upload was aborted,
    /// any staged bytes are discarded — they will never be sent. (curl
    /// additionally stamps the post-transfer timer and tears down the client
    /// reader here; those are driven by the transfer engine, not this struct.)
    pub fn set_upload_done(&mut self) {
        self.upload_done = true;
        self.keepon.send = false;
        if self.upload_aborted {
            self.sendbuf.clear();
            self.sendbuf_hds_len = 0;
        }
    }

    /// Abort sending: discard staged bytes and finish the upload as aborted
    /// (≙ `Curl_req_abort_sending`).
    ///
    /// No-op if the upload is already done. Otherwise clears the send buffer,
    /// sets [`upload_aborted`](Request::upload_aborted), clears [`KeepOn::send`],
    /// and finalizes via [`set_upload_done`](Request::set_upload_done).
    pub fn abort_sending(&mut self) {
        if !self.upload_done {
            self.sendbuf.clear();
            self.sendbuf_hds_len = 0;
            self.upload_aborted = true;
            self.keepon.send = false;
            self.set_upload_done();
        }
    }

    /// Stop both sending and receiving for this request
    /// (≙ `Curl_req_stop_send_recv`).
    ///
    /// Aborts an in-progress upload (if [`KeepOn::send`] is set) and then clears
    /// both keep-going flags so the event loop stops driving the transfer.
    pub fn stop_send_recv(&mut self) {
        if self.keepon.send {
            self.abort_sending();
        }
        self.keepon.send = false;
        self.keepon.recv = false;
    }

    /// Mark this request finished (≙ `Curl_req_done`).
    ///
    /// In curl, `Curl_req_done` flushes the remaining staged bytes when the
    /// request is *not* aborted (that flush is performed by the caller/connection
    /// layer before this is called) and then tears down the client reader/writer
    /// and any DoH state — none of which touch this struct's own bookkeeping. The
    /// only state we own is the [`done`](Request::done) flag, which makes
    /// [`wants_send`](Request::wants_send)/[`wants_recv`](Request::wants_recv)
    /// both report `false`.
    ///
    /// When `premature` is `true` (the request was aborted/errored), any
    /// staged-but-unsent bytes are dropped so they can never leak onto a reused
    /// connection.
    pub fn done(&mut self, premature: bool) {
        if premature {
            self.sendbuf.clear();
            self.sendbuf_hds_len = 0;
        }
        self.done = true;
    }
}

/// Event-loop predicates and small derived queries.
impl Request {
    /// `true` if the request wants to send (≙ `Curl_req_want_send`).
    ///
    /// Mirrors curl: not [`done`](Request::done), the upload direction is not
    /// rate-limit blocked, and either [`KeepOn::send`] is set, the send buffer is
    /// non-empty, or the connection has pending bytes to flush. The
    /// `upload_blocked` (curl's `Curl_rlimit_is_blocked` on the upload limiter)
    /// and `xfer_needs_flush` (curl's `Curl_xfer_needs_flush`) inputs are owned
    /// by the rate limiter and connection layer respectively, so the transfer
    /// engine supplies them.
    #[must_use]
    pub fn wants_send(&self, upload_blocked: bool, xfer_needs_flush: bool) -> bool {
        !self.done
            && !upload_blocked
            && (self.keepon.send || !self.sendbuf_empty() || xfer_needs_flush)
    }

    /// `true` if the request wants to receive (≙ `Curl_req_want_recv`).
    ///
    /// Mirrors curl: not [`done`](Request::done), the download direction is not
    /// rate-limit blocked, and [`KeepOn::recv`] is set. `download_blocked` is
    /// curl's `Curl_rlimit_is_blocked` on the download limiter, supplied by the
    /// transfer engine.
    #[must_use]
    pub fn wants_recv(&self, download_blocked: bool) -> bool {
        !self.done && !download_blocked && self.keepon.recv
    }

    /// `true` once the request has sent all data (≙ `Curl_req_done_sending`):
    /// [`upload_done`](Request::upload_done) and no longer
    /// [`wants_send`](Request::wants_send).
    #[must_use]
    pub fn done_sending(&self, upload_blocked: bool, xfer_needs_flush: bool) -> bool {
        self.upload_done && !self.wants_send(upload_blocked, xfer_needs_flush)
    }

    /// `true` if the response content length is known (i.e.
    /// [`size`](Request::size) is `Some`, curl's `size != -1`).
    #[must_use]
    pub fn content_length_known(&self) -> bool {
        self.size.is_some()
    }

    /// Time elapsed for this request attempt, from [`start`](Request::start) to
    /// the last observed [`now`](Request::now). Saturates at zero rather than
    /// panicking if the clock has not advanced.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.now.saturating_duration_since(self.start)
    }

    /// Update the engine's observed "current time" used by [`elapsed`](Request::elapsed)
    /// and by the progress meter.
    pub fn update_now(&mut self, now: Instant) {
        self.now = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_zeroed_virgin_state() {
        let r = Request::new();
        assert_eq!(r.size, None);
        assert_eq!(r.maxdownload, None);
        assert_eq!(r.offset, 0);
        assert_eq!(r.bytecount, 0);
        assert_eq!(r.writebytecount, 0);
        assert_eq!(r.headerbytecount, 0);
        assert_eq!(r.allheadercount, 0);
        assert_eq!(r.deductheadercount, 0);
        assert_eq!(r.headerline, 0);
        assert_eq!(r.httpcode, 0);
        assert_eq!(r.httpversion_sent, 0);
        assert_eq!(r.httpversion, 0);
        assert_eq!(r.upgr101, Upgrade101::None);
        assert_eq!(r.timeofdoc, 0);
        assert_eq!(r.location, None);
        assert_eq!(r.newurl, None);
        assert_eq!(r.setcookies, 0);
        assert_eq!(r.keepon, KeepOn::NONE);
        assert!(r.keepon.is_clear());
        assert!(r.sendbuf_empty());
        assert_eq!(r.sendbuf_len(), 0);
        assert_eq!(r.sendbuf_hds_len(), 0);
        // Every phase flag starts false.
        assert!(!r.header);
        assert!(!r.done);
        assert!(!r.content_range);
        assert!(!r.download_done);
        assert!(!r.eos_written);
        assert!(!r.eos_read);
        assert!(!r.eos_sent);
        assert!(!r.rewind_read);
        assert!(!r.upload_done);
        assert!(!r.upload_aborted);
        assert!(!r.ignorebody);
        assert!(!r.http_bodyless);
        assert!(!r.chunk);
        assert!(!r.resp_trailer);
        assert!(!r.ignore_cl);
        assert!(!r.upload_chunky);
        assert!(!r.no_body);
        assert!(!r.authneg);
        assert!(!r.shutdown);
        assert!(!r.shutdown_err_ignore);
        assert!(!r.reader_started);
        assert!(!r.content_length_known());
    }

    #[test]
    fn default_matches_new_shape() {
        let d = Request::default();
        assert_eq!(d.size, None);
        assert!(d.sendbuf_empty());
        assert!(d.keepon.is_clear());
        assert!(!d.done);
    }

    #[test]
    fn start_sets_timing_and_soft_resets() {
        let mut r = Request::new();
        r.done = true;
        r.bytecount = 99;
        let now = Instant::now();
        r.start(now);
        assert_eq!(r.start, now);
        assert_eq!(r.now, now);
        // soft_reset side effects:
        assert!(!r.done);
        assert_eq!(r.bytecount, 0);
    }

    /// The crux of connection reuse: a follow-up (`soft_reset`) keeps the
    /// transfer-level config while clearing per-attempt state.
    #[test]
    fn soft_reset_clears_attempt_state_but_preserves_config() {
        let mut r = Request::new();
        // Transfer-level config that must survive a follow-up.
        r.size = Some(1234);
        r.maxdownload = Some(500);
        r.offset = 10;
        r.httpcode = 200;
        r.keepon = KeepOn::new(true, true);
        r.upgr101 = Upgrade101::H2;
        r.timeofdoc = 42;
        r.location = Some("http://a/".to_string());
        r.newurl = Some("http://b/".to_string());
        r.setcookies = 3;
        r.content_range = true;
        r.rewind_read = true;
        r.http_bodyless = true;
        r.chunk = true;
        r.resp_trailer = true;
        r.ignore_cl = true;
        r.upload_chunky = true;
        r.no_body = true;
        r.authneg = true;
        r.shutdown_err_ignore = true;
        r.reader_started = true;
        let start = Instant::now();
        r.start = start;
        r.now = start;
        // Per-attempt state that must be cleared.
        r.done = true;
        r.upload_done = true;
        r.upload_aborted = true;
        r.download_done = true;
        r.eos_written = true;
        r.eos_read = true;
        r.eos_sent = true;
        r.ignorebody = true;
        r.shutdown = true;
        r.header = true;
        r.bytecount = 7;
        r.writebytecount = 9;
        r.headerline = 5;
        r.headerbytecount = 11;
        r.allheadercount = 13;
        r.deductheadercount = 2;
        r.httpversion_sent = 11;
        r.httpversion = 11;
        r.stage_send(b"leftover", 0);

        r.soft_reset();

        // Cleared:
        assert!(!r.done);
        assert!(!r.upload_done);
        assert!(!r.upload_aborted);
        assert!(!r.download_done);
        assert!(!r.eos_written);
        assert!(!r.eos_read);
        assert!(!r.eos_sent);
        assert!(!r.ignorebody);
        assert!(!r.shutdown);
        assert!(!r.header);
        assert_eq!(r.bytecount, 0);
        assert_eq!(r.writebytecount, 0);
        assert_eq!(r.headerline, 0);
        assert_eq!(r.headerbytecount, 0);
        assert_eq!(r.allheadercount, 0);
        assert_eq!(r.deductheadercount, 0);
        assert_eq!(r.httpversion_sent, 0);
        assert_eq!(r.httpversion, 0);
        assert!(r.sendbuf_empty());
        // Preserved:
        assert_eq!(r.size, Some(1234));
        assert_eq!(r.maxdownload, Some(500));
        assert_eq!(r.offset, 10);
        assert_eq!(r.httpcode, 200);
        assert_eq!(r.keepon, KeepOn::new(true, true));
        assert_eq!(r.upgr101, Upgrade101::H2);
        assert_eq!(r.timeofdoc, 42);
        assert_eq!(r.location.as_deref(), Some("http://a/"));
        assert_eq!(r.newurl.as_deref(), Some("http://b/"));
        assert_eq!(r.setcookies, 3);
        assert!(r.content_range);
        assert!(r.rewind_read);
        assert!(r.http_bodyless);
        assert!(r.chunk);
        assert!(r.resp_trailer);
        assert!(r.ignore_cl);
        assert!(r.upload_chunky);
        assert!(r.no_body);
        assert!(r.authneg);
        assert!(r.shutdown_err_ignore);
        assert!(r.reader_started);
        assert_eq!(r.start, start, "soft_reset must preserve start time");
    }

    /// `hard_reset` is the mirror image of `soft_reset`: it clears the
    /// transfer-level config but deliberately keeps `done`, the HTTP versions,
    /// `resp_trailer`, `shutdown_err_ignore`, and `reader_started`.
    #[test]
    fn hard_reset_returns_virgin_state_with_documented_survivors() {
        let mut r = Request::new();
        // Config that hard_reset must wipe.
        r.size = Some(1234);
        r.maxdownload = Some(500);
        r.offset = 10;
        r.httpcode = 200;
        r.keepon = KeepOn::new(true, true);
        r.upgr101 = Upgrade101::Received;
        r.timeofdoc = 42;
        r.location = Some("http://a/".to_string());
        r.newurl = Some("http://b/".to_string());
        r.setcookies = 3;
        r.content_range = true;
        r.download_done = true;
        r.eos_read = true;
        r.upload_done = true;
        r.upload_aborted = true;
        r.ignorebody = true;
        r.http_bodyless = true;
        r.chunk = true;
        r.ignore_cl = true;
        r.upload_chunky = true;
        r.authneg = true;
        r.shutdown = true;
        r.bytecount = 7;
        r.writebytecount = 9;
        r.stage_send(b"abc", 1);
        // Fields hard_reset must NOT touch.
        r.done = true;
        r.httpversion_sent = 11;
        r.httpversion = 20;
        r.resp_trailer = true;
        r.shutdown_err_ignore = true;
        r.reader_started = true;

        r.hard_reset(true);

        // Wiped to virgin state:
        assert_eq!(r.size, None);
        assert_eq!(r.maxdownload, None);
        assert_eq!(r.offset, 0);
        assert_eq!(r.httpcode, 0);
        assert_eq!(r.keepon, KeepOn::NONE);
        assert_eq!(r.upgr101, Upgrade101::None);
        assert_eq!(r.timeofdoc, 0);
        assert_eq!(r.location, None);
        assert_eq!(r.newurl, None);
        assert_eq!(r.setcookies, 0);
        assert!(!r.content_range);
        assert!(!r.download_done);
        assert!(!r.eos_read);
        assert!(!r.upload_done);
        assert!(!r.upload_aborted);
        assert!(!r.ignorebody);
        assert!(!r.http_bodyless);
        assert!(!r.chunk);
        assert!(!r.ignore_cl);
        assert!(!r.upload_chunky);
        assert!(!r.authneg);
        assert!(!r.shutdown);
        assert_eq!(r.bytecount, 0);
        assert_eq!(r.writebytecount, 0);
        assert!(r.sendbuf_empty());
        assert_eq!(r.sendbuf_hds_len(), 0);
        // `no_body` is seeded from the supplied option.
        assert!(r.no_body);
        // Deliberately preserved (matches Curl_req_hard_reset):
        assert!(r.done, "hard_reset must NOT clear `done`");
        assert_eq!(r.httpversion_sent, 11, "hard_reset must NOT clear version");
        assert_eq!(r.httpversion, 20, "hard_reset must NOT clear version");
        assert!(r.resp_trailer, "hard_reset must NOT clear resp_trailer");
        assert!(r.shutdown_err_ignore);
        assert!(r.reader_started);
    }

    /// Directly contrast the two resets on `done`/`httpversion` — the asymmetry
    /// that makes reuse and redirects behave like curl.
    #[test]
    fn reset_asymmetry_done_and_version() {
        let mut soft = Request::new();
        soft.done = true;
        soft.httpversion = 11;
        soft.soft_reset();
        assert!(!soft.done, "soft_reset clears done");
        assert_eq!(soft.httpversion, 0, "soft_reset zeroes httpversion");

        let mut hard = Request::new();
        hard.done = true;
        hard.httpversion = 11;
        hard.hard_reset(false);
        assert!(hard.done, "hard_reset preserves done");
        assert_eq!(hard.httpversion, 11, "hard_reset preserves httpversion");
    }

    #[test]
    fn hard_reset_seeds_no_body_from_option() {
        let mut r = Request::new();
        r.no_body = true;
        r.hard_reset(false);
        assert!(!r.no_body);
        r.no_body = false;
        r.hard_reset(true);
        assert!(r.no_body);
    }

    #[test]
    fn stage_send_tracks_bytes_and_header_prefix() {
        let mut r = Request::new();
        r.stage_send(b"GET / HTTP/1.1\r\n\r\n", 18);
        assert_eq!(r.sendbuf_len(), 18);
        assert_eq!(r.sendbuf_hds_len(), 18);
        assert_eq!(r.upload_present(), 18);
        assert!(!r.sendbuf_empty());
        // Append a body chunk (no header bytes).
        r.stage_send(b"hello", 0);
        assert_eq!(r.sendbuf_len(), 23);
        assert_eq!(r.sendbuf_hds_len(), 18);
        assert_eq!(r.sendbuf(), b"GET / HTTP/1.1\r\n\r\nhello");
    }

    /// Mirrors `req_send_buffer_flush`: header bytes never count toward
    /// `writebytecount`; body bytes do, even when a flush straddles the
    /// header/body boundary.
    #[test]
    fn consume_sent_counts_only_body_bytes() {
        let mut r = Request::new();
        r.stage_send(b"HEADERSbody", 7); // 7 header bytes + 4 body bytes

        // Flush part of the header.
        r.consume_sent(3).unwrap();
        assert_eq!(r.writebytecount, 0);
        assert_eq!(r.sendbuf_hds_len(), 4);
        assert_eq!(r.sendbuf(), b"DERSbody");

        // Flush across the header/body boundary: 4 header + 2 body.
        r.consume_sent(6).unwrap();
        assert_eq!(r.writebytecount, 2);
        assert_eq!(r.sendbuf_hds_len(), 0);
        assert_eq!(r.sendbuf(), b"dy");

        // Flush the rest (pure body).
        r.consume_sent(2).unwrap();
        assert_eq!(r.writebytecount, 4);
        assert!(r.sendbuf_empty());
    }

    #[test]
    fn consume_sent_rejects_overrun_without_mutating() {
        let mut r = Request::new();
        r.stage_send(b"abc", 1);
        let err = r.consume_sent(4).unwrap_err();
        assert_eq!(err, CurlError::BadFunctionArgument);
        // Untouched on error.
        assert_eq!(r.sendbuf_len(), 3);
        assert_eq!(r.sendbuf_hds_len(), 1);
        assert_eq!(r.writebytecount, 0);
    }

    #[test]
    fn set_upload_done_clears_send_keepon() {
        let mut r = Request::new();
        r.keepon = KeepOn::new(true, true);
        r.set_upload_done();
        assert!(r.upload_done);
        assert!(!r.keepon.send, "KEEP_SEND cleared");
        assert!(r.keepon.recv, "KEEP_RECV untouched");
    }

    #[test]
    fn set_upload_done_discards_buffer_when_aborted() {
        let mut r = Request::new();
        r.stage_send(b"pending", 0);
        r.upload_aborted = true;
        r.set_upload_done();
        assert!(r.upload_done);
        assert!(r.sendbuf_empty(), "aborted upload drops staged bytes");
    }

    #[test]
    fn abort_sending_finalizes_as_aborted() {
        let mut r = Request::new();
        r.keepon = KeepOn::new(true, true);
        r.stage_send(b"pending", 0);
        r.abort_sending();
        assert!(r.upload_aborted);
        assert!(r.upload_done);
        assert!(!r.keepon.send);
        assert!(r.sendbuf_empty());

        // No-op once the upload is already done.
        let mut r2 = Request::new();
        r2.upload_done = true;
        r2.abort_sending();
        assert!(!r2.upload_aborted);
    }

    #[test]
    fn stop_send_recv_clears_both_directions() {
        let mut r = Request::new();
        r.keepon = KeepOn::new(true, true);
        r.stage_send(b"x", 0);
        r.stop_send_recv();
        assert!(r.keepon.is_clear());
        assert!(r.upload_aborted, "an in-flight upload is aborted");
        assert!(r.sendbuf_empty());

        // When not sending, just clears recv/send.
        let mut r2 = Request::new();
        r2.keepon = KeepOn::new(true, false);
        r2.stop_send_recv();
        assert!(r2.keepon.is_clear());
        assert!(!r2.upload_aborted);
    }

    #[test]
    fn done_marks_done_and_drops_buffer_when_premature() {
        let mut r = Request::new();
        r.stage_send(b"unsent", 0);
        r.done(true);
        assert!(r.done);
        assert!(r.sendbuf_empty(), "premature done drops staged bytes");

        let mut r2 = Request::new();
        r2.stage_send(b"keep", 0);
        r2.done(false);
        assert!(r2.done);
        assert_eq!(r2.sendbuf_len(), 4, "graceful done leaves the buffer alone");
    }

    #[test]
    fn wants_send_predicate() {
        let mut r = Request::new();
        // Nothing to send.
        assert!(!r.wants_send(false, false));
        // KEEP_SEND set.
        r.keepon.send = true;
        assert!(r.wants_send(false, false));
        // Rate-limit blocked.
        assert!(!r.wants_send(true, false));
        // done short-circuits.
        r.done = true;
        assert!(!r.wants_send(false, false));
        r.done = false;
        r.keepon.send = false;
        // Non-empty send buffer.
        r.stage_send(b"data", 0);
        assert!(r.wants_send(false, false));
        r.consume_sent(4).unwrap();
        assert!(!r.wants_send(false, false));
        // Connection has a pending flush.
        assert!(r.wants_send(false, true));
    }

    #[test]
    fn wants_recv_predicate() {
        let mut r = Request::new();
        assert!(!r.wants_recv(false));
        r.keepon.recv = true;
        assert!(r.wants_recv(false));
        assert!(!r.wants_recv(true), "download rate-limit blocked");
        r.done = true;
        assert!(!r.wants_recv(false));
    }

    #[test]
    fn done_sending_predicate() {
        let mut r = Request::new();
        // Not done uploading.
        assert!(!r.done_sending(false, false));
        // Uploaded and idle.
        r.upload_done = true;
        assert!(r.done_sending(false, false));
        // Uploaded but still has buffered bytes -> still wants to send.
        r.stage_send(b"x", 0);
        assert!(!r.done_sending(false, false));
    }

    #[test]
    fn content_length_known_tracks_size() {
        let mut r = Request::new();
        assert!(!r.content_length_known());
        r.size = Some(0);
        assert!(
            r.content_length_known(),
            "Some(0) is a known (empty) length"
        );
        r.size = Some(42);
        assert!(r.content_length_known());
        r.size = None;
        assert!(!r.content_length_known());
    }

    #[test]
    fn elapsed_and_update_now() {
        let mut r = Request::new();
        let t0 = Instant::now();
        r.start(t0);
        assert_eq!(r.elapsed(), Duration::ZERO);
        let later = t0 + Duration::from_millis(250);
        r.update_now(later);
        assert_eq!(r.elapsed(), Duration::from_millis(250));
    }

    #[test]
    fn keepon_and_upgrade_helpers() {
        assert!(KeepOn::NONE.is_clear());
        assert_eq!(KeepOn::default(), KeepOn::NONE);
        let k = KeepOn::new(true, false);
        assert!(k.recv && !k.send && !k.is_clear());
        assert_eq!(Upgrade101::default(), Upgrade101::None);
    }
}
