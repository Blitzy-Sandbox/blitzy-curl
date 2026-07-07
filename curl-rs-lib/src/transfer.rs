// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! Async read/write transfer loop — the idiomatic-Rust rewrite of curl's
//! `lib/transfer.c` (the send/receive pump) and `lib/sendf.c` (the client
//! writer/reader indirection), with the write-side machinery from
//! `lib/cw-out.c` / `lib/cw-pause.c` folded into the download writer.
//!
//! # Responsibility
//!
//! This module is the heart of a single transfer: it moves bytes between the
//! connection (the connection filter chain) and the client read/write
//! callbacks. Concretely it reproduces:
//!
//! * the **receive path** (`Curl_sendrecv` → `sendrecv_dl` → `Curl_xfer_write_resp`
//!   → the client-writer chain in `sendf.c`): pull bytes from the connection,
//!   run them through the writer chain (raw trace → content-decode → the
//!   download stage that counts bytes and enforces `maxdownload` / `max_filesize`
//!   / `Content-Range` → the client body write callback), update the byte
//!   counters and [`Progress`], and honour `maxdownload` / range / `ignorebody`;
//! * the **send path** (`sendrecv_ul` → `Curl_req_send_more` → `req_flush` →
//!   `xfer_send`, and `sendf.c`'s `Curl_client_read`): pull upload data from the
//!   client reader (or upload buffer), buffer it into the request send buffer,
//!   flush it through the connection honouring short writes and `Expect:
//!   100-continue`, and report `CURLE_SEND_ERROR` on failure;
//! * the **`keepon` bit management** (`KEEP_RECV` / `KEEP_SEND` and the
//!   `HOLD`/`PAUSE` variants) that decides, per direction, whether the transfer
//!   wants to read or write, driving `curl_easy_pause` semantics and
//!   half-closed transfers;
//! * `Expect: 100-continue` handling, the `CURLOPT_LOW_SPEED_LIMIT` /
//!   `CURLOPT_LOW_SPEED_TIME` abort, the `CURLOPT_MAX_RECV_SPEED_LARGE` /
//!   `CURLOPT_MAX_SEND_SPEED_LARGE` rate limit (which enters
//!   `MSTATE_RATELIMITING`), and the hard transfer-timeout that maps to
//!   [`CurlCode::OperationTimedout`] (integer value `28`);
//! * the **redirect / resume plumbing** — surfacing the "need another request"
//!   outcome ([`TransferOutcome::NeedNewRequest`]) with the `newurl` and whether
//!   it is a `Location:` follow, plus the `Curl_retry_request` connection-retry
//!   decision, and `CURLOPT_RESUME_FROM` range restart.
//!
//! # Async model (Tokio)
//!
//! The pump is fully asynchronous on Tokio and performs no blocking I/O. The
//! connection is abstracted behind the [`RecvStream`] and [`SendStream`] traits
//! (the two halves of curl's connection filter chain), which the connection
//! layer implements in a later checkpoint; keeping the two directions as
//! separate halves lets [`Transfer::perform`] `select!` on read *and* write
//! readiness at the same time — the async equivalent of curl's per-direction
//! `poll()` in the multi handle — without ever blocking one direction on the
//! other.
//!
//! Byte processing itself (the `cw_download` size/counter logic, the `keepon`
//! transitions, upload buffering) is kept **synchronous** and side-effect free
//! with respect to I/O, exactly as in curl where `sendrecv_dl` reads a
//! non-blocking chunk and then processes it. Only the transport `recv`/`send`
//! calls `.await`. This keeps the observable behaviour — byte counts, wire
//! bytes, error codes, `--trace` vocabulary — identical to curl 8.x while
//! expressing all memory management through Rust ownership.
//!
//! # Memory safety
//!
//! This module is 100% safe Rust. The crate root (`lib.rs`) applies a
//! crate-wide attribute forbidding the low-level memory-escape keyword, so the
//! compiler rejects any such block outright; all memory management here is
//! expressed purely through Rust ownership and borrowing. The AAP names
//! `transfer.rs` among the files that must never reach for that keyword, and
//! the CI token audit over this file accordingly finds nothing.

use std::future::Future;
use std::time::{Duration, Instant};

use tracing::{debug, info, trace};

use crate::content_encoding::Unencoder;
use crate::error::{CurlCode, Error, Result};
use crate::progress::{Progress, Timer};
use crate::ratelimit::{MSpeedCheck, RateLimiter};
use crate::request::{ClientRead, ClientWriteType, Expect100, SingleRequest, KEEP_RECV, KEEP_SEND};

// ===========================================================================
// Constants transcribed from lib/transfer.c / lib/request.c
// ===========================================================================

/// Maximum number of non-blocking receive iterations serviced for one transfer
/// before yielding, mirroring the `maxloops = 10` cap in `sendrecv_dl`
/// (`lib/transfer.c`). It bounds the CPU spent draining a readable connection
/// in a single pump pass; it does not affect the bytes delivered.
pub const MAX_DL_LOOPS: u32 = 10;

/// Maximum number of automatic fresh-connection retries for a request that got
/// no data on a reused connection, transcribed from `CONN_MAX_RETRIES` in
/// `Curl_retry_request` (`lib/transfer.c`).
pub const CONN_MAX_RETRIES: u32 = 5;

/// Default client-side receive/send buffer size in bytes (`CURL_MAX_WRITE_SIZE`
/// / the `CURLOPT_BUFFERSIZE` default). curl reads at most this many body bytes
/// into one buffer before writing them to the client.
pub const DEFAULT_BUFFER_SIZE: usize = 16_384;

/// Default `Expect: 100-continue` wait, one second, matching curl's
/// `EXPIRE_100_TIMEOUT` (`lib/http.c`): after this long without a `100 Continue`
/// (or final) response, curl sends the request body regardless.
pub const DEFAULT_EXPECT_100_TIMEOUT: Duration = Duration::from_secs(1);

/// Sleeps until the given [`std::time::Instant`], bridging to Tokio's timer.
///
/// Used by [`Transfer::perform`] to wait out the `Expect: 100-continue` timer
/// without busy-looping. Converting through [`tokio::time::Instant::from_std`]
/// keeps the wait on Tokio's clock, which tests can pause and advance
/// deterministically.
async fn sleep_until_instant(deadline: Instant) {
    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
}

// ===========================================================================
// Connection filter chain — the transport halves
// ===========================================================================
//
// curl's transfer loop talks to the connection through `Curl_xfer_recv` /
// `Curl_xfer_send`, which forward into the connection filter chain
// (`lib/cfilters.c`). That chain is implemented in the `conn` module in a later
// checkpoint; to keep this module self-contained (and unit-testable against
// in-process mocks) the read and write ends are abstracted here as two traits.
// Splitting the connection into independent halves is what lets `perform`
// `select!` on both directions concurrently, the async analogue of curl polling
// a socket for `POLLIN | POLLOUT` at once.

/// The read half of the connection filter chain — the source of downloaded
/// bytes. Rewrite of the receive side of `Curl_xfer_recv` / `Curl_conn_recv`.
///
/// Implementors are [`Send`] so a transfer can run on the multi handle's
/// multi-threaded runtime.
pub trait RecvStream: Send {
    /// Await inbound readiness and receive up to `buf.len()` bytes into `buf`,
    /// returning the number of bytes read. A return of `Ok(0)` means the end of
    /// the stream has been reached (EOF / EOS) — the definitive
    /// end-of-response signal, exactly as a zero-length receive is in curl.
    ///
    /// This is the one call that may suspend; it corresponds to a non-blocking
    /// `Curl_xfer_recv` plus the multi handle's readiness wait collapsed into a
    /// single `.await`.
    fn recv(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize>> + Send;

    /// Returns `true` if the connection still has buffered inbound data that can
    /// be read without waiting for the socket (curl's `Curl_conn_data_pending`).
    /// Used only to decide whether the transfer should be re-serviced promptly;
    /// defaults to `false`.
    fn data_pending(&self) -> bool {
        false
    }

    /// Returns `true` for a multiplexed connection (HTTP/2, HTTP/3), where EOF
    /// detection is inherent and the receive amount need not be restricted to
    /// the known body size (curl's `Curl_conn_is_multiplex`). Defaults to
    /// `false`.
    fn is_multiplex(&self) -> bool {
        false
    }

    /// Returns `true` if the server signalled that the connection will close
    /// after this response (`conn->bits.close`). When the download is complete
    /// and this is set, an in-flight upload is aborted. Defaults to `false`.
    fn wants_close(&self) -> bool {
        false
    }

    /// Await inbound readiness *without consuming* any bytes — the equivalent of
    /// the multi handle waiting for `POLLIN` on the connection socket before
    /// calling the receive path. [`perform`](Transfer::perform) races this
    /// against [`SendStream::writable`] so it services whichever direction the
    /// connection is ready for, never blocking a ready send behind a not-yet
    /// readable receive.
    ///
    /// The default implementation resolves immediately, which is correct for
    /// in-memory transports and mock servers whose [`recv`](RecvStream::recv)
    /// never blocks; socket-backed filters override it to await real readability.
    fn readable(&mut self) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
}

/// The write half of the connection filter chain — the sink for uploaded bytes.
/// Rewrite of the send side of `Curl_xfer_send` / `Curl_conn_send`.
pub trait SendStream: Send {
    /// Send up to `buf.len()` bytes, returning how many were accepted. A short
    /// write (fewer than `buf.len()`) is normal and simply means the transfer
    /// must retry the remainder later — the caller keeps the unsent tail
    /// buffered, exactly as `req_send_buffer_flush` does. `eos` is `true` on the
    /// final send of the upload so the transport can finish the stream.
    ///
    /// Following curl's `Curl_xfer_send`, a would-block condition is reported as
    /// `Ok(0)` (curl maps `CURLE_AGAIN` to "0 written"), never as an error.
    fn send(&mut self, buf: &[u8], eos: bool) -> impl Future<Output = Result<usize>> + Send;

    /// Returns `true` if the transport has buffered outbound data still to be
    /// flushed to the socket (curl's `Curl_xfer_needs_flush`). Defaults to
    /// `false`.
    fn needs_flush(&self) -> bool {
        false
    }

    /// Flush any transport-buffered outbound data (curl's `Curl_xfer_flush`).
    /// Defaults to a no-op.
    fn flush(&mut self) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }

    /// Shut down the send direction after the upload has been fully sent
    /// (curl's `Curl_xfer_send_close` / send-side `Curl_conn_shutdown`).
    /// Defaults to a no-op.
    fn shutdown(&mut self) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }

    /// Await outbound readiness *without sending* any bytes — the equivalent of
    /// the multi handle waiting for `POLLOUT` on the connection socket before
    /// calling the send path. [`perform`](Transfer::perform) races this against
    /// [`RecvStream::readable`].
    ///
    /// The default implementation resolves immediately, which is correct for
    /// in-memory transports and mock servers whose [`send`](SendStream::send)
    /// never blocks; socket-backed filters override it to await real writability.
    fn writable(&mut self) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
}

// ===========================================================================
// Transfer configuration — the subset of `data->set` the transfer core reads
// ===========================================================================

/// The `CURLOPT_TIMECONDITION` comparison, transcribed from
/// `curl_TimeCond` in `include/curl/curl.h` and evaluated by
/// [`meets_timecondition`] (curl's `Curl_meets_timecondition`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeCondition {
    /// No time condition — the document is always considered to match
    /// (`CURL_TIMECOND_NONE`).
    #[default]
    None,
    /// Transfer only if the document is newer than the given time
    /// (`CURL_TIMECOND_IFMODSINCE`).
    IfModSince,
    /// Transfer only if the document is *not* newer than the given time
    /// (`CURL_TIMECOND_IFUNMODSINCE`).
    IfUnmodSince,
}

/// The transfer-relevant options, the rewrite of the `data->set` fields that
/// `lib/transfer.c` / `lib/sendf.c` consult. Only the members the transfer pump
/// actually needs are modelled here (Minimal Change Mandate — no speculative
/// configuration): sizes, speed limits, the hard timeout, verbosity, and the
/// two behaviour flags the download/upload paths branch on.
#[derive(Debug, Clone)]
pub struct TransferConfig {
    /// Receive/send buffer size in bytes (`CURLOPT_BUFFERSIZE`). Also caps the
    /// per-read amount, mirroring the `data->set.buffer_size` clamp in
    /// `Curl_xfer_recv`. Must be non-zero; a zero is normalised to
    /// [`DEFAULT_BUFFER_SIZE`] by [`TransferConfig::buffer_size`].
    pub buffer_size: usize,

    /// Maximum download size in bytes (`CURLOPT_MAXFILESIZE_LARGE`); `0` means
    /// unlimited. Enforced by the download writer, yielding
    /// [`CurlCode::FilesizeExceeded`] when exceeded.
    pub max_filesize: i64,

    /// Low-speed floor in bytes/second (`CURLOPT_LOW_SPEED_LIMIT`); `0` disables
    /// the check. Paired with [`low_speed_time`](Self::low_speed_time).
    pub low_speed_limit: i64,

    /// Duration in seconds the transfer may stay below
    /// [`low_speed_limit`](Self::low_speed_limit) before it is aborted with
    /// [`CurlCode::OperationTimedout`] (`CURLOPT_LOW_SPEED_TIME`); `0` disables.
    pub low_speed_time: u32,

    /// Maximum receive rate in bytes/second (`CURLOPT_MAX_RECV_SPEED_LARGE`);
    /// `0` means unlimited.
    pub max_recv_speed: i64,

    /// Maximum send rate in bytes/second (`CURLOPT_MAX_SEND_SPEED_LARGE`); `0`
    /// means unlimited.
    pub max_send_speed: i64,

    /// Hard overall transfer timeout (`CURLOPT_TIMEOUT` / `_MS`); `None` means
    /// no timeout. On expiry the transfer fails with
    /// [`CurlCode::OperationTimedout`].
    pub timeout: Option<Duration>,

    /// How long to wait for a `100 Continue` before sending the request body
    /// anyway (curl's fixed one-second `EXPIRE_100_TIMEOUT`). Defaults to
    /// [`DEFAULT_EXPECT_100_TIMEOUT`].
    pub expect_100_timeout: Duration,

    /// `CURLOPT_RESUME_FROM_LARGE` — the byte offset a download/upload resumes
    /// from; `0` means start from the beginning.
    pub resume_from: i64,

    /// `CURLOPT_VERBOSE` — when set, raw body bytes are traced as
    /// `CURLINFO_DATA_IN` / `CURLINFO_DATA_OUT` events, matching curl's
    /// `cw_raw_write` / `xfer_send` `Curl_debug` calls.
    pub verbose: bool,

    /// `CURLOPT_SUPPRESS_CONNECT_HEADERS` — when set, headers written with the
    /// `CONNECT` classification are dropped instead of forwarded to the client
    /// (curl's check in `cw_download_write`).
    pub suppress_connect_headers: bool,

    /// `CURLOPT_FOLLOWLOCATION` — whether the caller wants redirects followed
    /// automatically. The transfer core does not itself perform the redirect;
    /// it merely reports a pending `newurl` and stamps this flag into
    /// [`TransferOutcome::NeedNewRequest`] so `multi.rs` / `url.rs` can decide
    /// whether to issue the follow-up request.
    pub follow_location: bool,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            buffer_size: DEFAULT_BUFFER_SIZE,
            max_filesize: 0,
            low_speed_limit: 0,
            low_speed_time: 0,
            max_recv_speed: 0,
            max_send_speed: 0,
            timeout: None,
            expect_100_timeout: DEFAULT_EXPECT_100_TIMEOUT,
            resume_from: 0,
            verbose: false,
            suppress_connect_headers: false,
            follow_location: false,
        }
    }
}

impl TransferConfig {
    /// Returns the effective buffer size, normalising a zero to
    /// [`DEFAULT_BUFFER_SIZE`] so the receive path never allocates an empty
    /// buffer (curl clamps `buffer_size` to a positive value at setopt time).
    #[must_use]
    pub fn buffer_size(&self) -> usize {
        if self.buffer_size == 0 {
            DEFAULT_BUFFER_SIZE
        } else {
            self.buffer_size
        }
    }
}

// ===========================================================================
// Loop outcomes
// ===========================================================================

/// The result of driving a transfer to completion with [`Transfer::perform`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferOutcome {
    /// The request finished: there is nothing more to send or receive and no
    /// follow-up request is required. Corresponds to `data->req.done` becoming
    /// true with no `newurl` pending.
    Done,
    /// The transfer needs another request. This surfaces curl's `k->newurl`
    /// (set by a `Location:` redirect or an authentication-negotiation retry) to
    /// the caller (`multi.rs` / `url.rs`), which decides whether to actually
    /// follow it.
    NeedNewRequest {
        /// The URL for the next request (owned copy of `k->newurl`).
        newurl: String,
        /// `true` when the new URL came from a `Location:` header follow, as
        /// opposed to a same-URL retry (curl's `follow` distinction).
        follow: bool,
    },
    /// The transfer made no progress because every active direction is paused
    /// by the application (`curl_easy_pause`). The caller re-drives the transfer
    /// after unpausing (curl leaves such a handle idle in the multi handle until
    /// `curl_easy_pause` re-arms it). This is never returned once at least one
    /// direction can proceed.
    Paused,
}

/// The decision produced by [`Transfer::retry_request`], the rewrite of
/// `Curl_retry_request` (`lib/transfer.c`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryDecision {
    /// Do not retry; proceed with the response as received.
    NoRetry,
    /// Retry the request on a fresh connection using this URL. The caller closes
    /// the current connection and rewinds the client reader.
    Retry {
        /// The URL to reissue the request against (a duplicate of the current
        /// request URL).
        url: String,
    },
}

/// Inputs to [`retry_request`], gathered from the connection and request state
/// that `Curl_retry_request` inspects. Passed explicitly because the connection
/// type lives in the (not-yet-present) `conn` module.
#[derive(Debug, Clone, Copy)]
pub struct RetryContext {
    /// The connection this request ran on was reused from the pool
    /// (`conn->bits.reuse`).
    pub reused_connection: bool,
    /// The request was rejected on an HTTP/2 stream that is safe to reissue
    /// (`data->state.refused_stream`).
    pub refused_stream: bool,
    /// The protocol family is HTTP (or RTSP), which may return a response even
    /// for uploads and so is always retry-eligible on a reused connection
    /// (curl's `PROTO_FAMILY_HTTP | CURLPROTO_RTSP` test).
    pub is_http: bool,
    /// This is an upload (`data->state.upload`).
    pub uploading: bool,
    /// The request expected no response body (`data->req.no_body`).
    pub no_body: bool,
    /// Total response body bytes received so far (`data->req.bytecount`). A
    /// retry is only considered when this plus [`headerbytecount`](Self::headerbytecount)
    /// is zero — i.e. the reused connection produced nothing.
    pub bytecount: i64,
    /// Total response header bytes received so far (`data->req.headerbytecount`).
    pub headerbytecount: i64,
    /// Whether the request had already completed (`data->req.done`); a reused
    /// connection that produced no body but *did* finish is not retried unless
    /// the protocol is HTTP.
    pub done: bool,
}

// ===========================================================================
// The transfer driver
// ===========================================================================

/// The async send/receive pump for a single transfer.
///
/// A `Transfer` owns the two halves of the connection filter chain
/// ([`RecvStream`] / [`SendStream`]), the [`TransferConfig`], and the optional
/// `Content-Encoding` decoder. The per-request byte counters, `keepon` bits,
/// send buffer, and client writer/reader stacks live on the caller's
/// [`SingleRequest`]; the metering lives on the caller's [`Progress`] and the
/// pacing on the caller's [`RateLimiter`]. The pump methods therefore take
/// `&mut SingleRequest`, `&mut Progress`, and `&mut RateLimiter` — mirroring
/// curl, where the transfer loop reads and writes `data->req.*`,
/// `data->progress.*`, and the per-direction rate limiters directly.
///
/// # Type parameters
///
/// * `R` — the connection read half ([`RecvStream`]).
/// * `W` — the connection write half ([`SendStream`]).
///
/// Static dispatch over the halves keeps the async `recv`/`send` futures
/// nameable and `Send` (no `dyn` and no `async-trait` allocation), and lets
/// [`perform`](Self::perform) hold a read future and a write future
/// simultaneously without aliasing.
#[derive(Debug)]
pub struct Transfer<R, W> {
    /// Connection read half — the download byte source.
    recv_half: R,
    /// Connection write half — the upload byte sink.
    send_half: W,
    /// Transfer options (sizes, speed caps, timeout, flags).
    config: TransferConfig,
    /// The `Content-Encoding` decoder chain applied to received body bytes
    /// before they are counted and written to the client. `None` means the body
    /// is passed through unchanged (curl's `identity`). Rewrite of the content
    /// unencoding writer stage, driven via [`crate::content_encoding`].
    decoder: Option<Unencoder>,
    /// `Expect: 100-continue` negotiation state (curl's `data->state.expect100header`
    /// / `k->exp100`). While [`Expect100::AwaitingContinue`] the request body is
    /// held back until a `100` (or final) response arrives or the expect-100
    /// timer fires.
    expect100: Expect100,
    /// Deadline for the `Expect: 100-continue` wait, set when the state becomes
    /// [`Expect100::AwaitingContinue`]. `None` when not awaiting.
    expect100_deadline: Option<Instant>,
    /// `started_response`: set once the first non-informational, non-`CONNECT`
    /// response byte (header or body) is seen, at which point
    /// [`Timer::StartTransfer`] is recorded — the rewrite of the
    /// `cw_download_ctx.started_response` bit.
    started_response: bool,
    /// `started_body`: set once the first real body byte is seen, at which point
    /// the download rate limiter is armed — the rewrite of the
    /// `cw_download_ctx.started_body` bit.
    started_body: bool,
    /// Set when the download writer detected excess body bytes or a "no body
    /// wanted but body arrived" condition and the connection must be closed
    /// (curl's `connclose` / `streamclose`). Surfaced via
    /// [`should_close`](Self::should_close).
    close_requested: bool,
    /// Reusable receive buffer (curl borrows a shared `xfer_buf` per pump pass).
    /// Sized to [`TransferConfig::buffer_size`] on first use and reused across
    /// receive iterations to avoid per-read allocation.
    dl_buf: Vec<u8>,
    /// Reusable scratch buffer for pulling upload bytes from the client reader
    /// before they are appended to the request send buffer.
    ul_buf: Vec<u8>,
    /// Whether the per-direction rate limiters have been armed for this transfer
    /// (curl arms them lazily on the first body byte / first client read); guards
    /// [`configure_rate_limits`](Self::configure_rate_limits) against re-arming.
    rate_limits_armed: bool,
}

impl<R, W> Transfer<R, W>
where
    R: RecvStream,
    W: SendStream,
{
    /// Creates a transfer pump over the given connection halves and options.
    pub fn new(recv_half: R, send_half: W, config: TransferConfig) -> Self {
        Self {
            recv_half,
            send_half,
            config,
            decoder: None,
            expect100: Expect100::SendData,
            expect100_deadline: None,
            started_response: false,
            started_body: false,
            close_requested: false,
            dl_buf: Vec::new(),
            ul_buf: Vec::new(),
            rate_limits_armed: false,
        }
    }

    /// Borrows the transfer configuration.
    #[must_use]
    pub fn config(&self) -> &TransferConfig {
        &self.config
    }

    /// Borrows the connection read half.
    #[must_use]
    pub fn recv_half(&self) -> &R {
        &self.recv_half
    }

    /// Borrows the connection write half.
    #[must_use]
    pub fn send_half(&self) -> &W {
        &self.send_half
    }

    /// Consumes the transfer and returns the two connection halves, so the
    /// connection can be returned to the pool for reuse.
    pub fn into_halves(self) -> (R, W) {
        (self.recv_half, self.send_half)
    }

    /// Returns `true` if the download writer requested that the connection be
    /// closed (curl's `conn->bits.close`), for example because excess body bytes
    /// were seen or a body arrived when none was wanted.
    #[must_use]
    pub fn should_close(&self) -> bool {
        self.close_requested
    }

    // -- content-encoding -------------------------------------------------

    /// Installs the `Content-Encoding` decoder chain for the response body from
    /// a header value such as `"gzip"` or `"deflate, gzip"`.
    ///
    /// Mirrors how curl adds the unencoding writer when it parses the
    /// `Content-Encoding` / `Transfer-Encoding` header: the list is parsed
    /// outermost-first and decoded bytes are what the download stage counts and
    /// writes to the client. Returns [`CurlCode::BadContentEncoding`] via
    /// [`crate::content_encoding`] if an encoding is unsupported.
    pub fn set_content_encoding(&mut self, encodings: &str) -> Result<()> {
        self.decoder = Some(Unencoder::from_content_encoding(encodings)?);
        Ok(())
    }

    /// Clears any installed content-encoding decoder, restoring identity
    /// pass-through.
    pub fn clear_content_encoding(&mut self) {
        self.decoder = None;
    }

    /// Returns `true` if a non-identity content-encoding decoder is installed
    /// (curl's `Curl_cwriter_is_content_decoding`).
    #[must_use]
    pub fn is_content_decoding(&self) -> bool {
        self.decoder.as_ref().is_some_and(|d| !d.is_empty())
    }

    // -- expect-100 -------------------------------------------------------

    /// Returns the current `Expect: 100-continue` state.
    #[must_use]
    pub fn expect100(&self) -> Expect100 {
        self.expect100
    }

    /// Arms the `Expect: 100-continue` wait: the request body is held back and
    /// the expect-100 timer starts from `now`. Called by the HTTP layer after it
    /// sends request headers that carry `Expect: 100-continue`.
    pub fn begin_expect_100(&mut self, now: Instant) {
        self.expect100 = Expect100::AwaitingContinue;
        self.expect100_deadline = Some(now + self.config.expect_100_timeout);
        trace!("Expect: 100-continue, awaiting response before sending body");
    }

    /// Records that a `100 Continue` (or the final response) was received, so
    /// the request body may now be sent (curl's transition to
    /// `EXP100_SEND_DATA`).
    pub fn continue_received(&mut self) {
        self.expect100 = Expect100::SendData;
        self.expect100_deadline = None;
    }

    /// Marks the `Expect: 100-continue` negotiation as failed — used on a `417
    /// Expectation Failed` (curl's `EXP100_FAILED`), after which the body is not
    /// sent on this request.
    pub fn expect_100_failed(&mut self) {
        self.expect100 = Expect100::Failed;
        self.expect100_deadline = None;
    }

    /// Returns `true` if the request body must currently be withheld pending the
    /// `Expect: 100-continue` outcome, evaluated as of `now`.
    ///
    /// While [`Expect100::AwaitingContinue`], the body is held until either the
    /// interim response arrives (the HTTP layer calls
    /// [`continue_received`](Self::continue_received)) or the expect-100 timer
    /// expires — in which case curl sends the body regardless
    /// (`EXPIRE_100_TIMEOUT`), so this method performs that timer-fired
    /// transition itself and returns `false`. [`Expect100::Failed`] (a `417`)
    /// keeps the body held permanently; the send path turns that into an
    /// immediate end-of-stream so the request completes without a body.
    fn body_blocked_on_expect_100(&mut self, now: Instant) -> bool {
        match self.expect100 {
            Expect100::AwaitingContinue => {
                if let Some(deadline) = self.expect100_deadline {
                    if now >= deadline {
                        trace!("Expect: 100-continue timeout, sending body now");
                        self.continue_received();
                        return false;
                    }
                }
                true
            }
            Expect100::Failed => true,
            Expect100::SendData | Expect100::SendingRequest => false,
        }
    }

    // -- transfer setup (xfer_setup_* from lib/transfer.c) ----------------

    /// Configures the request's `keepon` bits and download size for a transfer
    /// that both sends and receives on the connection — the rewrite of
    /// `Curl_xfer_setup_sendrecv` / the shared `xfer_setup`.
    ///
    /// `recv_size` is the expected download size (`-1` if unknown); `has_header`
    /// indicates the protocol produces response headers (curl's
    /// `conn->scheme->run->write_resp_hd`), which keeps the transfer in the
    /// header phase. When either headers or a body are wanted, `KEEP_RECV` and
    /// `KEEP_SEND` are set as requested.
    pub fn xfer_setup_sendrecv(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        recv_size: i64,
        has_header: bool,
    ) {
        self.xfer_setup(req, progress, true, true, recv_size, has_header);
    }

    /// Configures the request for a send-only transfer (`Curl_xfer_setup_send`).
    pub fn xfer_setup_send(&mut self, req: &mut SingleRequest, progress: &mut Progress) {
        self.xfer_setup(req, progress, true, false, -1, false);
    }

    /// Configures the request for a receive-only transfer
    /// (`Curl_xfer_setup_recv`).
    pub fn xfer_setup_recv(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        recv_size: i64,
        has_header: bool,
    ) {
        self.xfer_setup(req, progress, false, true, recv_size, has_header);
    }

    /// Configures a transfer that neither sends nor receives
    /// (`Curl_xfer_setup_nop`), leaving all `keepon` bits clear.
    pub fn xfer_setup_nop(&mut self, req: &mut SingleRequest, progress: &mut Progress) {
        self.xfer_setup(req, progress, false, false, -1, false);
    }

    /// The shared setup routine (`xfer_setup` in `lib/transfer.c`): records the
    /// expected size and header phase, resets the shutdown flags, publishes the
    /// download size to [`Progress`], and sets the `keepon` bits for the
    /// directions in use.
    fn xfer_setup(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        do_send: bool,
        do_recv: bool,
        recv_size: i64,
        has_header: bool,
    ) {
        req.size = if do_recv { recv_size } else { -1 };
        req.header = has_header;
        // By default we do not shut the connection down at the end of the transfer.
        req.shutdown = false;
        req.shutdown_err_ignore = false;

        // If we already know the (non-header) body size, publish it so the
        // progress meter can show a percentage. Mirrors xfer_setup's
        // `if(!k->header && (recv_size > 0)) Curl_pgrsSetDownloadSize(...)`.
        if !has_header && recv_size > 0 {
            progress.pgrs_set_download_size(recv_size);
        }

        // We want header and/or body: arm the requested directions. When neither
        // headers nor a body are wanted (a pure NOP / HEAD with no header sink)
        // no keepon bit is set and the transfer completes immediately.
        if has_header || !req.no_body {
            if do_recv {
                req.keepon |= KEEP_RECV;
            }
            if do_send {
                req.keepon |= KEEP_SEND;
            }
        }

        trace!(
            recv = do_recv,
            send = do_send,
            size = recv_size,
            "xfer_setup"
        );
    }

    /// Marks that ending the request should shut the connection down, and
    /// whether shutdown errors are ignorable (curl's `Curl_xfer_set_shutdown`).
    pub fn xfer_set_shutdown(&self, req: &mut SingleRequest, shutdown: bool, ignore_errors: bool) {
        req.shutdown = shutdown;
        req.shutdown_err_ignore = ignore_errors;
    }
}

// ===========================================================================
// Client-writer path — the download body sink (sendf.c cw_download_write +
// Curl_client_write, and transfer.c Curl_xfer_write_resp)
// ===========================================================================

/// Computes how many more bytes may be written before reaching `limit`
/// (`get_max_body_write_len` in `lib/sendf.c`). `limit == -1` means unlimited
/// and returns [`usize::MAX`]; otherwise the remaining allowance `limit -
/// bytecount` is clamped to `[0, usize::MAX]`.
fn max_body_write_len(limit: i64, bytecount: i64) -> usize {
    if limit < 0 {
        usize::MAX
    } else {
        let remaining = limit.saturating_sub(bytecount);
        if remaining <= 0 {
            0
        } else {
            usize::try_from(remaining).unwrap_or(usize::MAX)
        }
    }
}

impl<R, W> Transfer<R, W>
where
    R: RecvStream,
    W: SendStream,
{
    /// Writes `buf`, classified by `wtype`, toward the client — the rewrite of
    /// `Curl_client_write` together with the `cw_download_write` stage that sees
    /// the real (content-decoded) body bytes.
    ///
    /// For a **body** write this: (optionally) traces the raw bytes when verbose
    /// (curl's `cw_raw_write`); content-decodes them via the installed
    /// [`Unencoder`]; enforces `no_body`, `maxdownload`, the `Content-Range`
    /// end-of-response check, and `max_filesize`; forwards the permitted bytes to
    /// the client-writer stack held on [`SingleRequest`]; and updates
    /// [`SingleRequest::bytecount`] and the download [`Progress`] counter. For a
    /// **header / info** write it forwards the bytes unchanged (dropping
    /// `CONNECT` headers when [`TransferConfig::suppress_connect_headers`] is
    /// set).
    ///
    /// # Errors
    ///
    /// * [`CurlCode::WriteError`] if the client write callback fails.
    /// * [`CurlCode::PartialFile`] if the response ends short of the announced
    ///   size.
    /// * [`CurlCode::FilesizeExceeded`] if `max_filesize` is exceeded.
    /// * [`CurlCode::WeirdServerReply`] if a body arrives when none was wanted
    ///   and no headers were received.
    pub fn client_write(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        wtype: ClientWriteType,
        buf: &[u8],
    ) -> Result<()> {
        let is_info = wtype.intersects(ClientWriteType::INFO);
        let is_connect = wtype.contains(ClientWriteType::CONNECT);
        let is_eos = wtype.contains(ClientWriteType::EOS);

        // The first non-informational, non-CONNECT byte marks the start of the
        // response — record TIMER_STARTTRANSFER exactly once (cw_download_write).
        if !self.started_response && !is_info && !is_connect {
            progress.pgrs_time(Timer::StartTransfer);
            self.started_response = true;
        }

        // Non-body classifications (header / info / status / connect / trailer)
        // are forwarded verbatim to the client-writer stack, with the one
        // exception curl makes: CONNECT headers are dropped when the application
        // asked to suppress them.
        if !wtype.contains(ClientWriteType::BODY) {
            if is_connect && self.config.suppress_connect_headers {
                return Ok(());
            }
            if self.config.verbose && wtype.contains(ClientWriteType::HEADER) {
                trace!(len = buf.len(), "<= Recv header");
            }
            let writer = req.writer_stack_mut().ok_or(Error::Write)?;
            let result = writer.write(wtype, buf);
            trace!(
                type_bits = wtype.bits(),
                len = buf.len(),
                "client_write header"
            );
            return result;
        }

        // -- BODY --------------------------------------------------------
        // Trace the raw (still-encoded) body bytes first, mirroring cw_raw_write
        // in the CURL_CW_RAW phase which sees data before content-decoding.
        if self.config.verbose && !req.ignorebody {
            trace!(len = buf.len(), "<= Recv data (raw)");
        }

        // Content-decode the raw body bytes. When no decoder is installed the
        // bytes pass through unchanged (curl's identity encoding). On EOS the
        // decoder is flushed so any buffered tail is emitted.
        let decoded: std::borrow::Cow<'_, [u8]> = match self.decoder.as_mut() {
            Some(dec) => {
                let mut out: Vec<u8> = dec.write(buf)?.to_vec();
                if is_eos {
                    out.extend_from_slice(&dec.finish()?);
                }
                std::borrow::Cow::Owned(out)
            }
            None => std::borrow::Cow::Borrowed(buf),
        };
        let nbytes = decoded.len();

        // Mark the first real body byte; the caller arms the download rate
        // limiter on this transition (cw_download_write's started_body).
        if !self.started_body && !is_info && !is_connect {
            self.started_body = true;
        }

        // A body arrived although the caller wanted none: bail out. If any
        // headers were received this is fine (e.g. a HEAD-like exchange),
        // otherwise the server reply is malformed.
        if req.no_body && nbytes > 0 {
            self.close_requested = true; // streamclose "ignoring body"
            req.download_done = true;
            trace!(len = nbytes, "download_write body, did not want a BODY");
            if req.allheadercount > 0 {
                return Ok(());
            }
            return Err(Error::with_context(
                CurlCode::WeirdServerReply,
                "Server returned a body although none was requested",
            ));
        }

        // Snapshot the scalar request state the size math needs, so the
        // subsequent mutable borrow of the writer stack does not alias it.
        let bytecount = req.bytecount;
        let maxdownload = req.maxdownload;
        let size = req.size;
        let no_body = req.no_body;
        let ignorebody = req.ignorebody;

        // Determine how many of the decoded bytes we are allowed to write; any
        // remainder is "excess" and triggers a connection close.
        let mut nwrite = nbytes;
        let mut excess_len = 0usize;
        let mut mark_download_done = false;

        if maxdownload != -1 {
            let wmax = max_body_write_len(maxdownload, bytecount);
            if nwrite > wmax {
                excess_len = nbytes - wmax;
                nwrite = wmax;
            }
            if nwrite == wmax {
                mark_download_done = true;
            }
            if is_eos && !no_body && size > bytecount {
                let missing = size - bytecount;
                debug!(missing, "end of response with bytes missing");
                return Err(Error::with_context(
                    CurlCode::PartialFile,
                    format!("end of response with {missing} bytes missing"),
                ));
            }
        }

        // Cap by CURLOPT_MAXFILESIZE (0 == unlimited). The excess beyond the cap
        // is reported as CURLE_FILESIZE_EXCEEDED after the permitted bytes are
        // written.
        if self.config.max_filesize != 0 && !ignorebody {
            let wmax = max_body_write_len(self.config.max_filesize, bytecount);
            if nwrite > wmax {
                nwrite = wmax;
            }
        }

        // Forward the permitted body bytes (plus a bare EOS) to the client-writer
        // stack. The writer's borrow of `req` is confined to this block so the
        // counter updates below can mutate other `req` fields.
        if !ignorebody && (nwrite > 0 || is_eos) {
            let writer = req.writer_stack_mut().ok_or(Error::Write)?;
            writer.write(wtype, &decoded[..nwrite])?;
            trace!(
                type_bits = wtype.bits(),
                len = nwrite,
                "download_write body"
            );
        }

        // Update the download byte counter and progress meter with the bytes
        // actually written (cw_download_write's bytecount / Curl_pgrs_download_inc).
        if nwrite > 0 {
            req.bytecount = req.bytecount.saturating_add(nwrite as i64);
            progress.pgrs_download_inc(nwrite as u64);
        }
        if mark_download_done {
            req.download_done = true;
        }

        if excess_len > 0 {
            if !ignorebody {
                info!(
                    excess = excess_len,
                    size,
                    maxdownload,
                    bytecount = req.bytecount,
                    "Excess found writing body"
                );
                // connclose(conn, "excess found in a read")
                self.close_requested = true;
            }
        } else if nwrite < nbytes && !ignorebody {
            debug!(
                max_filesize = self.config.max_filesize,
                bytecount = req.bytecount,
                "Exceeded the maximum allowed file size"
            );
            return Err(Error::with_context(
                CurlCode::FilesizeExceeded,
                format!(
                    "Maximum file size exceeded ({}) with {} bytes",
                    self.config.max_filesize, req.bytecount
                ),
            ));
        }

        Ok(())
    }

    /// Writes received response body bytes to the client — the rewrite of
    /// `Curl_xfer_write_resp` (default, no protocol `write_resp` hook).
    ///
    /// Bytes (and/or a terminal EOS) are pushed through [`client_write`] as a
    /// `BODY` classification. When the EOS is written the request is marked
    /// [`SingleRequest::eos_written`] and [`SingleRequest::download_done`], since
    /// writing the EOS definitively completes the download.
    ///
    /// [`client_write`]: Self::client_write
    pub fn write_resp(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        buf: &[u8],
        is_eos: bool,
    ) -> Result<()> {
        if !buf.is_empty() || is_eos {
            let mut wtype = ClientWriteType::BODY;
            if is_eos {
                wtype |= ClientWriteType::EOS;
            }
            self.client_write(req, progress, wtype, buf)?;
        }

        if is_eos {
            req.eos_written = true;
            req.download_done = true;
        }
        trace!(len = buf.len(), eos = is_eos, "xfer_write_resp");
        Ok(())
    }

    /// Writes received response *header* bytes to the client — the rewrite of
    /// `Curl_xfer_write_resp_hd` (default path). Header bytes are forwarded with
    /// the `HEADER` classification and are never content-decoded or size-capped.
    pub fn write_resp_hd(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        buf: &[u8],
        is_eos: bool,
    ) -> Result<()> {
        let mut wtype = ClientWriteType::HEADER;
        if is_eos {
            wtype |= ClientWriteType::EOS;
        }
        self.client_write(req, progress, wtype, buf)
    }
}

// ===========================================================================
// Receive path — the download pump (transfer.c sendrecv_dl + xfer_recv_resp)
// ===========================================================================

impl<R, W> Transfer<R, W>
where
    R: RecvStream,
    W: SendStream,
{
    /// Arms the per-direction rate limiters and the low-speed guard from the
    /// transfer configuration, exactly once per transfer.
    ///
    /// curl arms the download/upload rate limiters lazily (`Curl_rlimit_start`
    /// on the first body byte / first client read) and copies
    /// `CURLOPT_LOW_SPEED_LIMIT` / `CURLOPT_LOW_SPEED_TIME` onto the progress
    /// state at transfer start. We fold both into a single idempotent setup call
    /// that [`perform`](Self::perform) invokes before the first pump pass.
    ///
    /// # Errors
    ///
    /// Propagates [`CurlCode::BadFunctionArgument`] from the rate limiter if a
    /// configured speed cap is negative (curl rejects negative caps at
    /// `curl_easy_setopt` time; we mirror that check here).
    ///
    /// [`CurlCode::BadFunctionArgument`]: crate::error::CurlCode::BadFunctionArgument
    fn configure_rate_limits(
        &mut self,
        req: &SingleRequest,
        progress: &mut Progress,
        rate: &mut RateLimiter,
        now: Instant,
    ) -> Result<()> {
        if self.rate_limits_armed {
            return Ok(());
        }
        // Download cap (CURLOPT_MAX_RECV_SPEED_LARGE): configure the bucket and
        // tune its step from the expected total size (req.size, -1 if unknown).
        if self.config.max_recv_speed > 0 {
            rate.set_max_recv_speed(self.config.max_recv_speed, now)?;
            rate.start_recv(now, req.size);
        }
        // Upload cap (CURLOPT_MAX_SEND_SPEED_LARGE): curl passes -1 as the total.
        if self.config.max_send_speed > 0 {
            rate.set_max_send_speed(self.config.max_send_speed, now)?;
            rate.start_send(now);
        }
        // Low-speed abort guard (CURLOPT_LOW_SPEED_LIMIT / _TIME) lives on the
        // progress meter, which owns the speed measurement and the abort clock.
        if self.config.low_speed_limit > 0 {
            progress.set_low_speed_limit(self.config.low_speed_limit);
            progress.set_low_speed_time(self.config.low_speed_time);
        }
        self.rate_limits_armed = true;
        Ok(())
    }

    /// Pumps received bytes from the connection read half into the client-writer
    /// chain — the rewrite of `sendrecv_dl` together with `xfer_recv_resp` from
    /// `lib/transfer.c`.
    ///
    /// One call performs up to [`MAX_DL_LOOPS`] awaited reads, draining the
    /// connection while it reports more buffered data ([`RecvStream::data_pending`]).
    /// Each read is capped by the download rate-limit budget and, for a single
    /// (non-multiplexed) stream past the header phase with a known size, by the
    /// bytes still outstanding (`size - bytecount`). Received bytes are fed
    /// through [`write_resp`](Self::write_resp) (content-decode, size checks,
    /// client callback, counters, progress). A zero-length read is end-of-response
    /// and stops the receive/send halves; when the response body is fully
    /// received (or the stream reaches EOS) the [`KEEP_RECV`] bit is cleared. If
    /// reading finishes while sending is still active on a connection set to
    /// close (or multiplexed), the upload is abandoned as curl does.
    ///
    /// `now` is the shared transfer timestamp (curl's `Curl_pgrs_now`), threaded
    /// so rate-limit accounting is deterministic under a mock clock in tests.
    ///
    /// # Errors
    ///
    /// * transport read errors ([`CurlCode::RecvError`] and lower-level I/O),
    /// * any error surfaced by the client-writer chain
    ///   ([`CurlCode::WriteError`], [`CurlCode::BadContentEncoding`],
    ///   [`CurlCode::PartialFile`], [`CurlCode::FilesizeExceeded`],
    ///   [`CurlCode::WeirdServerReply`]).
    pub async fn sendrecv_dl(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        rate: &mut RateLimiter,
        now: Instant,
    ) -> Result<()> {
        let bufsize = self.config.buffer_size();
        // Reuse the receive scratch buffer across passes; grow it to the
        // configured size on first use. Moved out of `self` so the awaited read
        // (which borrows `self.recv_half`) and the subsequent `&mut self`
        // processing do not alias.
        let mut buf = std::mem::take(&mut self.dl_buf);
        if buf.len() < bufsize {
            buf.resize(bufsize, 0);
        }

        let mut loops: u32 = 0;
        let result = loop {
            loops += 1;

            // -- Determine how much to read this iteration -----------------
            let mut bytestoread = bufsize;

            // Rate-limit pacing: with the download cap armed and no budget
            // available, stop reading now. `perform` will observe the same
            // limiter via `check()` and sleep before the next pass.
            if rate.recv_active() {
                let avail = rate.recv_avail(now);
                if avail <= 0 {
                    break Ok(());
                }
                let avail = usize::try_from(avail).unwrap_or(usize::MAX);
                if avail < bytestoread {
                    bytestoread = avail;
                }
            }

            // Cap by the remaining announced body size, but only for a single
            // (non-multiplexed) stream once past the header phase with a known
            // size — curl's `xfer_recv_resp` clamps `blen` to `size - bytecount`
            // so it never reads into the next response on a reused connection.
            if !self.recv_half.is_multiplex() && !req.header && req.size != -1 {
                let remaining = req.size.saturating_sub(req.bytecount);
                if remaining <= 0 {
                    // Everything announced has already been received.
                    break Ok(());
                }
                let remaining = usize::try_from(remaining).unwrap_or(usize::MAX);
                if remaining < bytestoread {
                    bytestoread = remaining;
                }
            }
            if bytestoread == 0 {
                break Ok(());
            }

            // -- Perform the awaited read ---------------------------------
            let nread = match self.recv_half.recv(&mut buf[..bytestoread]).await {
                Ok(n) => n,
                Err(e) => break Err(e),
            };
            let is_eos = nread == 0;

            // Account the freshly received bytes against the download bucket.
            if nread > 0 && rate.recv_active() {
                rate.drain_recv(nread, now);
            }

            // A zero-length read is end-of-response: stop both halves (curl's
            // `Curl_req_stop_send_recv`). If the terminal EOS was already
            // written to the client we are completely done reading.
            if is_eos {
                if let Err(e) = req.stop_send_recv() {
                    break Err(e);
                }
                if req.eos_written {
                    break Ok(());
                }
            }

            // Feed the bytes (and/or the terminal EOS) through the client-writer
            // chain: content-decode → size checks → client callback → counters.
            if let Err(e) = self.write_resp(req, progress, &buf[..nread], is_eos) {
                break Err(e);
            }
            if req.done {
                break Ok(());
            }

            // Body fully received on a single stream, or the stream reached its
            // end: stop selecting on readable by clearing KEEP_RECV.
            if (!self.recv_half.is_multiplex() && req.download_done) || is_eos {
                req.keepon &= !KEEP_RECV;
                break Ok(());
            }

            // Otherwise keep draining only while the connection reports more
            // buffered data and the per-pass loop budget is not exhausted
            // (curl's `maxloops` guard against starving other transfers).
            if !self.recv_half.data_pending() || loops >= MAX_DL_LOOPS {
                break Ok(());
            }
        };

        // Always return the scratch buffer to `self` for reuse next pass.
        self.dl_buf = buf;
        result?;

        // Reading finished while the upload is still active and the connection
        // is set to close (or is multiplexed): curl abandons the send side.
        if (req.keepon & (KEEP_RECV | KEEP_SEND)) == KEEP_SEND
            && (self.recv_half.wants_close() || self.recv_half.is_multiplex())
        {
            info!("we are done reading and this is set to close, stop send");
            req.abort_sending()?;
        }
        Ok(())
    }
}

// ===========================================================================
// Send path — the upload pump (request.c Curl_req_send_more / req_flush /
// xfer_send / req_set_upload_done, and sendf.c Curl_client_read)
// ===========================================================================

impl<R, W> Transfer<R, W>
where
    R: RecvStream,
    W: SendStream,
{
    /// Pulls up to `blen` bytes from the client reader stack into the internal
    /// upload scratch buffer — the rewrite of `Curl_client_read` from
    /// `lib/sendf.c`.
    ///
    /// The read is paced by the upload rate limiter: when the send cap is armed
    /// and no budget is available this returns `nread == 0, eos == false`
    /// (curl's `ul_avail <= 0` fast path) so the caller retries later; otherwise
    /// the request length is clamped to the available budget. On the first call
    /// the reader is marked started (curl arms the upload limiter lazily here;
    /// [`configure_rate_limits`](Self::configure_rate_limits) has already armed
    /// it from the configured cap). When no reader stack is installed there is
    /// no request body, so an immediate end-of-stream is reported.
    ///
    /// The bytes read are left in `self.ul_buf[..nread]` for the caller to append
    /// to the request send buffer; the returned [`ClientRead`] carries the count
    /// and the end-of-stream flag.
    ///
    /// # Errors
    ///
    /// Propagates any error from the client reader ([`CurlCode::ReadError`],
    /// [`CurlCode::AbortedByCallback`], and the like).
    ///
    /// [`CurlCode::ReadError`]: crate::error::CurlCode::ReadError
    /// [`CurlCode::AbortedByCallback`]: crate::error::CurlCode::AbortedByCallback
    fn client_read(
        &mut self,
        req: &mut SingleRequest,
        rate: &mut RateLimiter,
        now: Instant,
        mut blen: usize,
    ) -> Result<ClientRead> {
        // Lazy reader start (curl's `!reader_started` branch). The upload rate
        // limiter is armed once via `configure_rate_limits`; here we only flip
        // the state flag protocol code may observe.
        if !req.reader_started {
            req.reader_started = true;
        }
        if blen == 0 {
            trace!(len = 0usize, nread = 0usize, eos = false, "client_read");
            return Ok(ClientRead {
                nread: 0,
                eos: false,
            });
        }

        // Upload rate-limit pacing: no budget → read nothing this pass.
        if rate.send_active() {
            let avail = rate.send_avail(now);
            if avail <= 0 {
                trace!(len = blen, nread = 0usize, eos = false, "client_read");
                return Ok(ClientRead {
                    nread: 0,
                    eos: false,
                });
            }
            let avail = usize::try_from(avail).unwrap_or(usize::MAX);
            if avail < blen {
                blen = avail;
            }
        }

        // Ensure the scratch buffer can hold the (possibly clamped) request.
        if self.ul_buf.len() < blen {
            self.ul_buf.resize(blen, 0);
        }

        // No reader installed → no request body → immediate EOS (mirrors the
        // "nothing to upload" outcome; curl would have installed an fread reader
        // whose first read reports EOS for an empty body).
        let Some(reader) = req.reader_stack_mut() else {
            trace!(len = blen, nread = 0usize, eos = true, "client_read");
            return Ok(ClientRead {
                nread: 0,
                eos: true,
            });
        };

        let cread = reader.read(&mut self.ul_buf[..blen])?;
        trace!(
            len = blen,
            nread = cread.nread,
            eos = cread.eos,
            "client_read"
        );
        Ok(cread)
    }

    /// Sends one buffer's worth of queued request bytes from the send buffer —
    /// the rewrite of `xfer_send` from `lib/request.c` for a single write.
    ///
    /// The body portion (everything after the leading `sendbuf_hds_len` header
    /// bytes) is capped by `CURLOPT_MAX_SEND_SPEED_LARGE`; headers never count
    /// toward the cap. The terminal end-of-stream flag is asserted only when the
    /// whole remaining buffer is being sent and the client reader has already
    /// signalled EOS. After a successful write the consumed bytes are dropped
    /// from the send buffer, [`SingleRequest::writebytecount`] and the upload
    /// [`Progress`] counter are advanced by the *body* bytes sent, the upload
    /// rate bucket is drained, and [`SingleRequest::eos_sent`] is set once the
    /// EOS write completes.
    ///
    /// Returns the number of bytes written (`0` when the send buffer is empty or
    /// the write would block).
    ///
    /// # Errors
    ///
    /// Propagates transport send errors ([`CurlCode::SendError`] and lower-level
    /// I/O).
    ///
    /// [`CurlCode::SendError`]: crate::error::CurlCode::SendError
    async fn xfer_send_from_sendbuf(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        rate: &mut RateLimiter,
        now: Instant,
    ) -> Result<usize> {
        if req.sendbuf_empty() {
            return Ok(0);
        }

        let pending_len = req.sendbuf_len();
        let hds_remaining = req.sendbuf_hds_len.min(pending_len);

        // Cap the body by the maximum send speed (headers are exempt). This is
        // the static per-write cap; the token-bucket pacing lives in
        // `client_read`, which throttles how fast the buffer is refilled.
        let mut blen = pending_len;
        if self.config.max_send_speed > 0 {
            let body_bytes = pending_len - hds_remaining;
            let cap = usize::try_from(self.config.max_send_speed).unwrap_or(usize::MAX);
            if body_bytes > cap {
                blen = hds_remaining + cap;
            }
        }

        // EOS is sent with the final chunk: the reader has reported EOS and this
        // write covers the entire remaining buffer.
        let eos = req.eos_read && blen == pending_len;
        if eos {
            debug!("sending last upload chunk of {blen} bytes");
        }

        // Copy the bytes to be sent into the owned upload scratch buffer so the
        // borrow of `req.sendbuf` is released before the awaited send (which
        // needs `&mut self.send_half`, a disjoint field).
        self.ul_buf.clear();
        self.ul_buf.extend_from_slice(&req.sendbuf_peek()[..blen]);
        let hdr_in_write = hds_remaining.min(blen);

        let nwritten = self.send_half.send(&self.ul_buf[..blen], eos).await?;

        // Drop the written bytes from the front of the send buffer (this also
        // decrements `sendbuf_hds_len` by the header bytes consumed).
        let _ = req.sendbuf_consume(nwritten);

        if eos && blen == nwritten {
            req.eos_sent = true;
        }
        if nwritten > 0 {
            let hdr_sent = hdr_in_write.min(nwritten);
            let body_sent = nwritten - hdr_sent;
            if hdr_sent > 0 {
                trace!(len = hdr_sent, "=> Send header");
            }
            if body_sent > 0 {
                trace!(len = body_sent, "=> Send data");
                req.writebytecount = req.writebytecount.saturating_add(body_sent as i64);
                progress.pgrs_upload_inc(body_sent as u64);
                if rate.send_active() {
                    rate.drain_send(body_sent, now);
                }
            }
        }
        Ok(nwritten)
    }

    /// Flushes the request send buffer to the connection — the rewrite of
    /// `req_send_buffer_flush` from `lib/request.c`.
    ///
    /// Repeatedly sends via [`xfer_send_from_sendbuf`](Self::xfer_send_from_sendbuf)
    /// until the buffer is drained or a write is short (a would-block or a
    /// speed-limit cap), exactly as curl's flush loop leaves on `nwritten < blen`.
    ///
    /// # Errors
    ///
    /// Propagates transport send errors from the underlying writes.
    async fn flush_sendbuf(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        rate: &mut RateLimiter,
        now: Instant,
    ) -> Result<()> {
        while !req.sendbuf_empty() {
            let blen_before = req.sendbuf_len();
            let nwritten = self
                .xfer_send_from_sendbuf(req, progress, rate, now)
                .await?;
            // Short write: network blocking or the max-send-speed cap kicked in.
            // Leave the remainder for a later pass (curl's `nwritten < blen`).
            if nwritten < blen_before {
                break;
            }
        }
        Ok(())
    }

    /// Marks the upload complete — the rewrite of `req_set_upload_done` from
    /// `lib/request.c`.
    ///
    /// Sets [`SingleRequest::upload_done`] and clears [`KEEP_SEND`] (via
    /// [`SingleRequest::set_upload_done`]), records [`Timer::PostTransfer`], and
    /// emits the same completion diagnostics curl does — distinguishing an
    /// aborted upload, a completed upload with a known byte count, and the "no
    /// bytes / fine" cases (with the message keyed on whether the client reader
    /// advertised a total length).
    ///
    /// # Errors
    ///
    /// Propagates any error from [`SingleRequest::set_upload_done`].
    fn req_set_upload_done(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
    ) -> Result<()> {
        req.set_upload_done()?;
        progress.pgrs_time(Timer::PostTransfer);

        if req.upload_aborted {
            if req.writebytecount != 0 {
                info!(
                    "abort upload after having sent {} bytes",
                    req.writebytecount
                );
            } else {
                info!("abort upload");
            }
        } else if req.writebytecount != 0 {
            info!("upload completely sent off: {} bytes", req.writebytecount);
        } else if !req.download_done {
            let has_total = req
                .reader_stack_mut()
                .and_then(|r| r.total_length())
                .is_some();
            if has_total {
                info!("We are completely uploaded and fine");
            } else {
                info!("Request completely sent off");
            }
        }
        Ok(())
    }

    /// Flushes buffered request data and finalizes the upload — the rewrite of
    /// `req_flush` from `lib/request.c`.
    ///
    /// Drains the send buffer; if bytes remain the write would block and the
    /// method returns so the caller retries on the next pass (curl's
    /// `CURLE_AGAIN` folded to `CURLE_OK` by `Curl_req_send_more`). When the
    /// buffer is empty but the transport still has pending data it is flushed.
    /// Once the client reader has signalled EOS a zero-length end-of-stream
    /// marker is written, and when both EOS is read and sent the upload is
    /// finalized (running the optional send-direction shutdown first).
    ///
    /// # Errors
    ///
    /// Propagates transport send/shutdown errors and any error from
    /// [`req_set_upload_done`](Self::req_set_upload_done). A shutdown error is
    /// suppressed when [`SingleRequest::shutdown_err_ignore`] is set, matching
    /// curl's "broken server" tolerance.
    async fn req_flush(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        rate: &mut RateLimiter,
        now: Instant,
    ) -> Result<()> {
        if !req.sendbuf_empty() {
            self.flush_sendbuf(req, progress, rate, now).await?;
            if !req.sendbuf_empty() {
                debug!("Curl_req_flush(len={}) -> EAGAIN", req.sendbuf_len());
                // Would block; the remaining bytes are retried on the next pass.
                return Ok(());
            }
        } else if self.send_half.needs_flush() {
            debug!("Curl_req_flush(), xfer send_pending");
            self.send_half.flush().await?;
        }

        // Send the zero-length end-of-stream marker once the reader is done.
        if req.eos_read && !req.eos_sent {
            let nwritten = self.send_half.send(&[], true).await?;
            if nwritten == 0 {
                req.eos_sent = true;
            }
        }

        // Both directions of EOS reached: finalize the upload (with an optional
        // send-side shutdown handshake first).
        if !req.upload_done && req.eos_read && req.eos_sent {
            if req.shutdown {
                match self.send_half.shutdown().await {
                    Ok(()) => {}
                    Err(e) => {
                        if req.shutdown_err_ignore {
                            info!(
                                "Shutdown send direction error: {}. Broken server? Proceeding as if everything is ok.",
                                e.code_i32()
                            );
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
            self.req_set_upload_done(req, progress)?;
        }
        Ok(())
    }

    /// Pumps request bytes toward the connection write half — the rewrite of
    /// `Curl_req_send_more` from `lib/request.c`.
    ///
    /// First, if the upload is neither aborted nor finished nor paused and the
    /// send buffer has room, more body bytes are pulled from the client reader
    /// (via [`client_read`](Self::client_read)) and appended to the send buffer,
    /// setting [`SingleRequest::eos_read`] when the reader reports end-of-stream.
    /// Then the buffer is flushed and the upload finalized via
    /// [`req_flush`](Self::req_flush).
    ///
    /// `now` is the shared transfer timestamp, threaded for deterministic
    /// rate-limit accounting under a mock clock in tests.
    ///
    /// # Errors
    ///
    /// Propagates client-reader errors, transport send errors, and upload
    /// finalization errors.
    pub async fn sendrecv_ul(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        rate: &mut RateLimiter,
        now: Instant,
    ) -> Result<()> {
        // Expect: 100-continue rejected by the server (417): no body is sent, so
        // signal end-of-stream and let the buffered head flush to completion.
        if self.expect100 == Expect100::Failed && !req.eos_read {
            req.eos_read = true;
        }

        // Refill the send buffer from the client while there is room, the client
        // still has data to give, and the body is not being held pending an
        // `Expect: 100-continue` decision (curl's `Curl_req_send_more` head).
        if !req.upload_aborted
            && !req.eos_read
            && !req.is_send_paused()
            && !self.body_blocked_on_expect_100(now)
        {
            let bufsize = self.config.buffer_size();
            let buffered = req.sendbuf_len();
            if buffered < bufsize {
                let room = bufsize - buffered;
                let cread = self.client_read(req, rate, now, room)?;
                if cread.nread > 0 {
                    // Body bytes carry no header prefix (hds_len == 0); the
                    // request head was queued separately by the protocol layer.
                    req.send_buffer_add(&self.ul_buf[..cread.nread], 0)?;
                }
                if cread.eos {
                    req.eos_read = true;
                }
            }
        }

        // Flush whatever is buffered and finalize the upload when complete.
        self.req_flush(req, progress, rate, now).await
    }
}

// ===========================================================================
// Top-level pump — the rewrite of transfer.c Curl_sendrecv and the readiness
// loop the multi handle drives around it (multi_runsingle PERFORMING state)
// ===========================================================================

impl<R, W> Transfer<R, W>
where
    R: RecvStream,
    W: SendStream,
{
    /// Returns `true` when the whole transfer is blocked and must not be pumped
    /// — the rewrite of `Curl_xfer_is_blocked` from `lib/transfer.c`.
    ///
    /// A direction counts as blocked when its rate limiter is in the *blocked*
    /// state, which in curl doubles as the `curl_easy_pause` state
    /// (`Curl_xfer_pause_recv`/`_send` toggle `Curl_rlimit_block`). The transfer
    /// is blocked when every *active* direction is blocked.
    fn xfer_is_blocked(&self, req: &SingleRequest, rate: &RateLimiter) -> bool {
        let want_send = (req.keepon & KEEP_SEND) != 0;
        let want_recv = (req.keepon & KEEP_RECV) != 0;
        if !want_send {
            want_recv && rate.recv_is_blocked()
        } else if !want_recv {
            want_send && rate.send_is_blocked()
        } else {
            rate.recv_is_blocked() && rate.send_is_blocked()
        }
    }

    /// Returns `true` when the transfer wants to receive — the rewrite of the
    /// evolved `Curl_req_want_recv` from `lib/request.c`: not done, the receive
    /// bucket is not blocked, and the [`KEEP_RECV`] bit is set.
    fn req_want_recv(&self, req: &SingleRequest, rate: &RateLimiter) -> bool {
        !req.done && !rate.recv_is_blocked() && (req.keepon & KEEP_RECV) != 0
    }

    /// Returns `true` when the transfer wants to send — the rewrite of the
    /// evolved `Curl_req_want_send` from `lib/request.c`: not done, the send
    /// bucket is not blocked, and either [`KEEP_SEND`] is set, the send buffer
    /// is non-empty, or the transport still has data to flush.
    fn req_want_send(&self, req: &SingleRequest, rate: &RateLimiter) -> bool {
        !req.done
            && !rate.send_is_blocked()
            && ((req.keepon & KEEP_SEND) != 0
                || !req.sendbuf_empty()
                || self.send_half.needs_flush())
    }

    /// Runs the post-pump checks that close out one `Curl_sendrecv` pass: the
    /// low-speed / callback abort check, the hard-timeout check, the partial-file
    /// check, the done determination, and the progress update — the tail of
    /// `Curl_sendrecv` from `lib/transfer.c`.
    ///
    /// # Errors
    ///
    /// * [`CurlCode::AbortedByCallback`] if the progress callback aborted.
    /// * [`CurlCode::OperationTimedout`] on either the low-speed breach (from the
    ///   progress speed check) or the hard `CURLOPT_TIMEOUT` expiry.
    /// * [`CurlCode::PartialFile`] if the transfer ended short of the announced
    ///   size with no follow-up URL pending.
    ///
    /// [`CurlCode::AbortedByCallback`]: crate::error::CurlCode::AbortedByCallback
    fn post_transfer_checks(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        start: Instant,
        now: Instant,
    ) -> Result<()> {
        // Low-speed / callback abort (Curl_pgrsCheck). Propagates AbortedByCallback
        // or the low-speed OperationTimedout.
        progress.pgrs_check_at(now)?;

        if req.keepon != 0 {
            // Hard overall timeout (Curl_timeleft_ms < 0). Measured from the
            // single-transfer start; the message mirrors curl byte-for-byte and
            // branches on whether the total size is known.
            if let Some(timeout) = self.config.timeout {
                let origin = req.start.unwrap_or(start);
                let elapsed = now.saturating_duration_since(origin);
                if elapsed >= timeout {
                    let ms = i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX);
                    return Err(if req.size != -1 {
                        Error::with_context(
                            CurlCode::OperationTimedout,
                            format!(
                                "Operation timed out after {ms} milliseconds with {} out of {} bytes received",
                                req.bytecount, req.size
                            ),
                        )
                    } else {
                        Error::with_context(
                            CurlCode::OperationTimedout,
                            format!(
                                "Operation timed out after {ms} milliseconds with {} bytes received",
                                req.bytecount
                            ),
                        )
                    });
                }
            }
        } else {
            // The transfer has finished pumping: verify we received the whole
            // announced body (partial-file check).
            if !req.no_body && req.size != -1 && req.bytecount != req.size && req.newurl.is_none() {
                let missing = req.size - req.bytecount;
                return Err(Error::with_context(
                    CurlCode::PartialFile,
                    format!("transfer closed with {missing} bytes remaining to read"),
                ));
            }
        }

        // Nothing more to send or receive → the request is done.
        if (req.keepon & (KEEP_RECV | KEEP_SEND)) == 0 {
            req.done = true;
        }

        // Progress update (Curl_pgrsUpdate); propagates AbortedByCallback.
        progress.pgrs_update_at(now)?;
        Ok(())
    }

    /// Performs one full send/receive pass — the faithful rewrite of
    /// `Curl_sendrecv` from `lib/transfer.c`.
    ///
    /// If the transfer is [blocked](Self::xfer_is_blocked) the pass is a no-op.
    /// Otherwise it services the receive direction (when [`KEEP_RECV`] is set),
    /// then the send direction (when it [wants to send](Self::req_want_send)),
    /// then runs the [post-pump checks](Self::post_transfer_checks).
    ///
    /// Note that the receive step awaits inbound bytes: call this only when the
    /// connection is known to be readable (as [`perform`](Self::perform) does
    /// via [`RecvStream::readable`]) or when blocking on the receive is
    /// acceptable. `now` is the shared transfer timestamp.
    ///
    /// # Errors
    ///
    /// Propagates every error from the receive path, the send path, and the
    /// post-pump checks.
    pub async fn sendrecv(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        rate: &mut RateLimiter,
        now: Instant,
    ) -> Result<()> {
        if self.xfer_is_blocked(req, rate) {
            return Ok(());
        }

        if (req.keepon & KEEP_RECV) != 0 {
            self.sendrecv_dl(req, progress, rate, now).await?;
            if req.done {
                return Ok(());
            }
        }

        if self.req_want_send(req, rate) && !req.done_sending() {
            self.sendrecv_ul(req, progress, rate, now).await?;
        }

        self.post_transfer_checks(req, progress, req.start.unwrap_or(now), now)
    }

    /// Drives the transfer to completion, servicing whichever direction the
    /// connection is ready for, and returns the resulting [`TransferOutcome`].
    ///
    /// This is the async analogue of the multi handle's `PERFORMING` loop around
    /// `Curl_sendrecv`. Each iteration:
    ///
    /// 1. returns [`TransferOutcome::Paused`] if the transfer is fully
    ///    [blocked](Self::xfer_is_blocked) (paused via `curl_easy_pause`) so the
    ///    caller can resume it later;
    /// 2. consults the [`RateLimiter`]; on [`MSpeedCheck::RateLimited`] it sleeps
    ///    for the prescribed interval (entering curl's `MSTATE_RATELIMITING`
    ///    rather than busy-looping) and retries;
    /// 3. races [`RecvStream::readable`] against [`SendStream::writable`] and
    ///    pumps the ready direction, then runs the
    ///    [post-pump checks](Self::post_transfer_checks).
    ///
    /// The loop ends when the request is done, when it becomes paused, or when a
    /// follow-up request is required (a `newurl` was set — a redirect or
    /// resume), which is surfaced as [`TransferOutcome::NeedNewRequest`] with the
    /// [`follow`](TransferConfig::follow_location) flag copied from the config.
    ///
    /// # Errors
    ///
    /// Propagates every error surfaced by the pump and the post-pump checks
    /// (write, read, send, receive, timeout, partial-file, content-encoding, …).
    pub async fn perform(
        &mut self,
        req: &mut SingleRequest,
        progress: &mut Progress,
        rate: &mut RateLimiter,
    ) -> Result<TransferOutcome> {
        let start = Progress::now();
        // Arm rate limiters and the low-speed guard from the configuration.
        self.configure_rate_limits(req, progress, rate, start)?;

        loop {
            // (1) A follow-up request was requested by the response handling
            // (redirect / resume): surface it before doing more I/O.
            if let Some(newurl) = req.newurl.take() {
                progress.pgrs_done_at(Progress::now())?;
                return Ok(TransferOutcome::NeedNewRequest {
                    newurl,
                    follow: self.config.follow_location,
                });
            }

            if req.done {
                break;
            }

            let now = Progress::now();

            // (2) Fully blocked (both active directions paused): hand control
            // back so the caller can `curl_easy_pause`-resume us later.
            if self.xfer_is_blocked(req, rate) {
                return Ok(TransferOutcome::Paused);
            }

            // (3) Rate-limit gate: sleep rather than busy-loop when throttled.
            match rate.check(now) {
                MSpeedCheck::RateLimited { wait } => {
                    if wait > Duration::ZERO {
                        tokio::time::sleep(wait).await;
                    } else {
                        tokio::task::yield_now().await;
                    }
                    continue;
                }
                MSpeedCheck::Proceed { .. } => {}
            }

            // Expect: 100-continue — while the body is held awaiting the interim
            // response, only already-buffered head / flush bytes may go out; the
            // body itself is not offered to the send side. This also performs the
            // timer-fired release when the expect-100 deadline passes.
            let body_held = self.body_blocked_on_expect_100(now);
            let expect_100_deadline = if body_held {
                self.expect100_deadline
            } else {
                None
            };

            let do_recv = self.req_want_recv(req, rate);
            let do_send = self.req_want_send(req, rate)
                && !(body_held && req.sendbuf_empty() && !self.send_half.needs_flush());

            // (4) Nothing wants to run right now.
            if !do_recv && !do_send {
                // The body is held awaiting `100 Continue`: wait for the
                // expect-100 timer to fire (then loop to release the body),
                // rather than spinning or declaring the transfer done.
                if let Some(deadline) = expect_100_deadline {
                    sleep_until_instant(deadline).await;
                    continue;
                }
                if (req.keepon & (KEEP_RECV | KEEP_SEND)) != 0 {
                    return Ok(TransferOutcome::Paused);
                }
                req.done = true;
                break;
            }

            // (5) Await readiness of the direction(s) we can service, then pump
            // exactly the ready one — never blocking a ready send behind an
            // unready receive (or vice versa).
            if do_recv && do_send {
                tokio::select! {
                    biased;
                    r = self.recv_half.readable() => {
                        r?;
                        self.sendrecv_dl(req, progress, rate, now).await?;
                    }
                    w = self.send_half.writable() => {
                        w?;
                        if !req.done_sending() {
                            self.sendrecv_ul(req, progress, rate, now).await?;
                        }
                    }
                }
            } else if do_recv {
                // While awaiting `100 Continue`, race the read against the
                // expect-100 timer so the body is released on timeout even if the
                // interim response never arrives.
                if let Some(deadline) = expect_100_deadline {
                    tokio::select! {
                        biased;
                        r = self.recv_half.readable() => {
                            r?;
                            self.sendrecv_dl(req, progress, rate, now).await?;
                        }
                        () = sleep_until_instant(deadline) => {
                            self.continue_received();
                        }
                    }
                } else {
                    self.recv_half.readable().await?;
                    self.sendrecv_dl(req, progress, rate, now).await?;
                }
            } else {
                self.send_half.writable().await?;
                if !req.done_sending() {
                    self.sendrecv_ul(req, progress, rate, now).await?;
                }
            }

            // (6) Post-pump checks: abort/timeout/partial-file/done + progress.
            let now_after = Progress::now();
            self.post_transfer_checks(req, progress, start, now_after)?;
        }

        // Final progress update and outcome classification.
        progress.pgrs_done_at(Progress::now())?;
        if let Some(newurl) = req.newurl.take() {
            return Ok(TransferOutcome::NeedNewRequest {
                newurl,
                follow: self.config.follow_location,
            });
        }
        Ok(TransferOutcome::Done)
    }
}

// ===========================================================================
// Retry and time-condition helpers (transfer.c Curl_retry_request /
// Curl_meets_timecondition)
// ===========================================================================

/// Decides whether a request should be retried on a fresh connection — the
/// rewrite of `Curl_retry_request` from `lib/transfer.c`.
///
/// A retry is warranted when a *reused* connection produced no bytes at all
/// (header + body counters are zero) and either a body was expected or the
/// protocol is HTTP (which can always be retried), or when a refused HTTP/2
/// stream produced no bytes. The caller owns the retry counter (curl's
/// `data->state.retrycount`): it is bumped on each retry and, once
/// [`CONN_MAX_RETRIES`] is exceeded, the transfer fails with
/// [`CurlCode::SendError`] and the counter is reset.
///
/// On a refused-stream retry the caller should additionally clear its
/// `refused_stream` flag, exactly as curl does inline.
///
/// # Errors
///
/// Returns [`CurlCode::SendError`] once the retry budget is exhausted, matching
/// curl's `failf(... "Connection died, tried %d times before giving up")`.
///
/// [`CurlCode::SendError`]: crate::error::CurlCode::SendError
pub fn retry_request(
    ctx: &RetryContext,
    url: &str,
    retry_count: &mut u32,
) -> Result<RetryDecision> {
    // Uploads cannot be blindly retried unless the protocol is HTTP (or RTSP),
    // because for other protocols a partial upload has side effects.
    if ctx.uploading && !ctx.is_http {
        return Ok(RetryDecision::NoRetry);
    }

    let no_bytes = ctx.bytecount + ctx.headerbytecount == 0;
    let mut retry = false;

    if ctx.reused_connection && no_bytes && ((!ctx.no_body && !ctx.done) || ctx.is_http) {
        // No data on a reused connection: the peer likely closed a kept-alive
        // connection we then tried to use. Safe to retry on a fresh connect.
        retry = true;
    } else if ctx.refused_stream && no_bytes {
        info!("REFUSED_STREAM, retrying a fresh connect");
        retry = true;
    }

    if !retry {
        return Ok(RetryDecision::NoRetry);
    }

    // curl uses a post-increment: it checks the current count against the cap,
    // then increments. Exhaustion resets the counter and fails the transfer.
    let current = *retry_count;
    *retry_count += 1;
    if current >= CONN_MAX_RETRIES {
        *retry_count = 0;
        debug!("Connection died, tried {CONN_MAX_RETRIES} times before giving up");
        return Err(Error::with_context(
            CurlCode::SendError,
            format!("Connection died, tried {CONN_MAX_RETRIES} times before giving up"),
        ));
    }
    info!(
        "Connection died, retrying a fresh connect (retry count: {})",
        *retry_count
    );
    Ok(RetryDecision::Retry {
        url: url.to_string(),
    })
}

/// Evaluates `CURLOPT_TIMECONDITION` against a document timestamp — the rewrite
/// of `Curl_meets_timecondition` from `lib/transfer.c`.
///
/// Returns `true` when the transfer should proceed. A `timeofdoc` or `timevalue`
/// of `0` disables the check (always proceeds). For [`TimeCondition::IfModSince`]
/// the transfer proceeds only when the document is strictly newer than
/// `timevalue`; for [`TimeCondition::IfUnmodSince`] only when it is strictly
/// older. When the condition is *not* met the corresponding curl diagnostic is
/// emitted and `false` is returned; the caller should then set its
/// `info.timecond` flag (curl's `data->info.timecond = TRUE`).
#[must_use]
pub fn meets_timecondition(timeofdoc: i64, timevalue: i64, cond: TimeCondition) -> bool {
    if timeofdoc == 0 || timevalue == 0 {
        return true;
    }
    match cond {
        // IfModSince is curl's default branch.
        TimeCondition::None | TimeCondition::IfModSince => {
            if timeofdoc <= timevalue {
                info!("The requested document is not new enough");
                return false;
            }
        }
        TimeCondition::IfUnmodSince => {
            if timeofdoc >= timevalue {
                info!("The requested document is not old enough");
                return false;
            }
        }
    }
    true
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::{
        ClientRead, ClientReader, ClientWriteType, ClientWriter, CURLPAUSE_RECV, KEEP_RECV,
        KEEP_SEND,
    };
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // Mock connection halves and client stacks
    // -----------------------------------------------------------------------

    /// A [`RecvStream`] that yields a fixed sequence of byte chunks and then
    /// reports EOF (`Ok(0)`) forever. `recv` performs no real I/O, so the
    /// returned future never actually suspends.
    #[derive(Debug)]
    struct MockRecv {
        chunks: VecDeque<Vec<u8>>,
        multiplex: bool,
        close: bool,
    }

    impl MockRecv {
        fn new(chunks: Vec<&[u8]>) -> Self {
            Self {
                chunks: chunks.into_iter().map(<[u8]>::to_vec).collect(),
                multiplex: false,
                close: false,
            }
        }
    }

    impl RecvStream for MockRecv {
        fn recv(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize>> + Send {
            // Compute the result synchronously (no borrow of `self` or `buf`
            // is held across the returned future).
            let out: Result<usize> = match self.chunks.pop_front() {
                None => Ok(0),
                Some(chunk) => {
                    let n = chunk.len().min(buf.len());
                    buf[..n].copy_from_slice(&chunk[..n]);
                    if n < chunk.len() {
                        self.chunks.push_front(chunk[n..].to_vec());
                    }
                    Ok(n)
                }
            };
            async move { out }
        }

        fn data_pending(&self) -> bool {
            !self.chunks.is_empty()
        }

        fn is_multiplex(&self) -> bool {
            self.multiplex
        }

        fn wants_close(&self) -> bool {
            self.close
        }
    }

    /// A [`SendStream`] that accumulates everything written to it. When
    /// `max_per_send` is set, each `send` accepts at most that many bytes,
    /// exercising the short-write path.
    #[derive(Debug, Default)]
    struct MockSend {
        sent: Vec<u8>,
        eos_seen: bool,
        max_per_send: Option<usize>,
    }

    impl SendStream for MockSend {
        fn send(&mut self, buf: &[u8], eos: bool) -> impl Future<Output = Result<usize>> + Send {
            let n = match self.max_per_send {
                Some(m) => buf.len().min(m),
                None => buf.len(),
            };
            self.sent.extend_from_slice(&buf[..n]);
            if eos && n == buf.len() {
                self.eos_seen = true;
            }
            async move { Ok(n) }
        }
    }

    /// Shared, inspectable capture of what a [`MockWriter`] received.
    #[derive(Debug, Default)]
    struct WriterCapture {
        body: Vec<u8>,
        headers: Vec<u8>,
        eos: bool,
        writes: usize,
    }

    /// A [`ClientWriter`] that records body and header bytes into a shared
    /// [`WriterCapture`] so the test can inspect them after the writer has been
    /// moved onto the [`SingleRequest`]. `fail` forces a `CURLE_WRITE_ERROR`.
    #[derive(Debug, Clone)]
    struct MockWriter {
        cap: Arc<Mutex<WriterCapture>>,
        fail: bool,
    }

    impl MockWriter {
        fn new() -> (Self, Arc<Mutex<WriterCapture>>) {
            let cap = Arc::new(Mutex::new(WriterCapture::default()));
            (
                Self {
                    cap: Arc::clone(&cap),
                    fail: false,
                },
                cap,
            )
        }

        fn failing() -> Self {
            Self {
                cap: Arc::new(Mutex::new(WriterCapture::default())),
                fail: true,
            }
        }
    }

    impl ClientWriter for MockWriter {
        fn write(&mut self, wtype: ClientWriteType, buf: &[u8]) -> Result<()> {
            if self.fail {
                return Err(Error::Write);
            }
            let mut cap = self.cap.lock().unwrap();
            cap.writes += 1;
            if wtype.contains(ClientWriteType::BODY) {
                cap.body.extend_from_slice(buf);
            } else if wtype.contains(ClientWriteType::HEADER) {
                cap.headers.extend_from_slice(buf);
            }
            if wtype.contains(ClientWriteType::EOS) {
                cap.eos = true;
            }
            Ok(())
        }
    }

    /// A [`ClientReader`] that hands out a fixed body, reporting EOS on the read
    /// that drains the last byte.
    #[derive(Debug)]
    struct MockReader {
        data: Vec<u8>,
        pos: usize,
        total: Option<u64>,
    }

    impl MockReader {
        fn new(data: &[u8], total: Option<u64>) -> Self {
            Self {
                data: data.to_vec(),
                pos: 0,
                total,
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
            self.total
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// A request initialised the way the protocol layer would leave it before a
    /// transfer: `-1` size/`maxdownload` sentinels and a started clock.
    fn fresh_req() -> SingleRequest {
        let mut req = SingleRequest::new();
        req.init();
        req.hard_reset(false);
        req.start(Instant::now(), DEFAULT_BUFFER_SIZE).unwrap();
        req
    }

    fn progress() -> Progress {
        Progress::new()
    }

    fn rate() -> RateLimiter {
        RateLimiter::new(Instant::now())
    }

    // =======================================================================
    // Pure helper functions
    // =======================================================================

    #[test]
    fn max_body_write_len_unlimited_and_clamped() {
        assert_eq!(max_body_write_len(-1, 0), usize::MAX);
        assert_eq!(max_body_write_len(-1, 1_000), usize::MAX);
        assert_eq!(max_body_write_len(100, 0), 100);
        assert_eq!(max_body_write_len(100, 60), 40);
        assert_eq!(max_body_write_len(100, 100), 0);
        assert_eq!(max_body_write_len(100, 250), 0);
    }

    #[test]
    fn meets_timecondition_disabled_when_zero() {
        assert!(meets_timecondition(0, 123, TimeCondition::IfModSince));
        assert!(meets_timecondition(123, 0, TimeCondition::IfModSince));
    }

    #[test]
    fn meets_timecondition_if_modified_since() {
        // Document newer than the reference → proceed.
        assert!(meets_timecondition(200, 100, TimeCondition::IfModSince));
        // Document not newer → skip.
        assert!(!meets_timecondition(100, 100, TimeCondition::IfModSince));
        assert!(!meets_timecondition(50, 100, TimeCondition::IfModSince));
        // The default variant behaves like IfModSince (curl's `default:` label).
        assert!(!meets_timecondition(50, 100, TimeCondition::None));
    }

    #[test]
    fn meets_timecondition_if_unmodified_since() {
        // Document older than the reference → proceed.
        assert!(meets_timecondition(50, 100, TimeCondition::IfUnmodSince));
        // Document not older → skip.
        assert!(!meets_timecondition(100, 100, TimeCondition::IfUnmodSince));
        assert!(!meets_timecondition(200, 100, TimeCondition::IfUnmodSince));
    }

    #[test]
    fn retry_request_reused_http_no_bytes_retries() {
        let ctx = RetryContext {
            reused_connection: true,
            refused_stream: false,
            is_http: true,
            uploading: false,
            no_body: false,
            bytecount: 0,
            headerbytecount: 0,
            done: false,
        };
        let mut count = 0;
        match retry_request(&ctx, "http://example.com/", &mut count).unwrap() {
            RetryDecision::Retry { url } => assert_eq!(url, "http://example.com/"),
            RetryDecision::NoRetry => panic!("expected a retry"),
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn retry_request_no_retry_when_bytes_received() {
        let ctx = RetryContext {
            reused_connection: true,
            refused_stream: false,
            is_http: true,
            uploading: false,
            no_body: false,
            bytecount: 10,
            headerbytecount: 0,
            done: false,
        };
        let mut count = 0;
        assert!(matches!(
            retry_request(&ctx, "http://x/", &mut count).unwrap(),
            RetryDecision::NoRetry
        ));
    }

    #[test]
    fn retry_request_upload_non_http_never_retries() {
        let ctx = RetryContext {
            reused_connection: true,
            refused_stream: false,
            is_http: false,
            uploading: true,
            no_body: false,
            bytecount: 0,
            headerbytecount: 0,
            done: false,
        };
        let mut count = 0;
        assert!(matches!(
            retry_request(&ctx, "ftp://x/", &mut count).unwrap(),
            RetryDecision::NoRetry
        ));
    }

    #[test]
    fn retry_request_refused_stream_retries() {
        let ctx = RetryContext {
            reused_connection: false,
            refused_stream: true,
            is_http: true,
            uploading: false,
            no_body: false,
            bytecount: 0,
            headerbytecount: 0,
            done: false,
        };
        let mut count = 0;
        assert!(matches!(
            retry_request(&ctx, "http://x/", &mut count).unwrap(),
            RetryDecision::Retry { .. }
        ));
    }

    #[test]
    fn retry_request_exhausts_budget_with_send_error() {
        let ctx = RetryContext {
            reused_connection: true,
            refused_stream: false,
            is_http: true,
            uploading: false,
            no_body: false,
            bytecount: 0,
            headerbytecount: 0,
            done: false,
        };
        // Five retries are allowed (counts 0..=4); the sixth attempt gives up.
        let mut count = 0;
        for expected in 1..=CONN_MAX_RETRIES {
            match retry_request(&ctx, "http://x/", &mut count).unwrap() {
                RetryDecision::Retry { .. } => assert_eq!(count, expected),
                RetryDecision::NoRetry => panic!("expected a retry"),
            }
        }
        // Now count == CONN_MAX_RETRIES → give up with CURLE_SEND_ERROR.
        let err = retry_request(&ctx, "http://x/", &mut count).unwrap_err();
        assert_eq!(err.code(), CurlCode::SendError);
        assert_eq!(count, 0, "counter is reset on give-up");
    }

    // =======================================================================
    // Client-writer path (client_write / write_resp)
    // =======================================================================

    fn transfer_with(
        recv: MockRecv,
        send: MockSend,
        config: TransferConfig,
    ) -> Transfer<MockRecv, MockSend> {
        Transfer::new(recv, send, config)
    }

    #[test]
    fn client_write_plain_body_counts_and_forwards() {
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let mut req = fresh_req();
        let mut pg = progress();
        let (writer, cap) = MockWriter::new();
        req.set_writer_stack(Box::new(writer));

        xfer.client_write(&mut req, &mut pg, ClientWriteType::BODY, b"hello world")
            .unwrap();

        let cap = cap.lock().unwrap();
        assert_eq!(cap.body, b"hello world");
        assert_eq!(req.bytecount, 11);
        assert!(!req.download_done);
    }

    #[test]
    fn write_resp_eos_marks_download_done() {
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let mut req = fresh_req();
        let mut pg = progress();
        let (writer, cap) = MockWriter::new();
        req.set_writer_stack(Box::new(writer));

        xfer.write_resp(&mut req, &mut pg, b"body", true).unwrap();

        let cap = cap.lock().unwrap();
        assert_eq!(cap.body, b"body");
        assert!(cap.eos);
        assert!(req.eos_written);
        assert!(req.download_done);
    }

    #[test]
    fn client_write_propagates_writer_error() {
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let mut req = fresh_req();
        let mut pg = progress();
        req.set_writer_stack(Box::new(MockWriter::failing()));

        let err = xfer
            .client_write(&mut req, &mut pg, ClientWriteType::BODY, b"x")
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::WriteError);
    }

    #[test]
    fn client_write_maxfilesize_exceeded() {
        let config = TransferConfig {
            max_filesize: 4,
            ..TransferConfig::default()
        };
        let mut xfer = transfer_with(MockRecv::new(vec![]), MockSend::default(), config);
        let mut req = fresh_req();
        let mut pg = progress();
        let (writer, cap) = MockWriter::new();
        req.set_writer_stack(Box::new(writer));

        let err = xfer
            .client_write(&mut req, &mut pg, ClientWriteType::BODY, b"toolong")
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::FilesizeExceeded);
        // Only the permitted prefix reached the client.
        assert_eq!(cap.lock().unwrap().body, b"tool");
    }

    #[test]
    fn client_write_maxdownload_excess_closes_connection() {
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let mut req = fresh_req();
        req.maxdownload = 4; // only four body bytes are wanted
        let mut pg = progress();
        let (writer, cap) = MockWriter::new();
        req.set_writer_stack(Box::new(writer));

        xfer.client_write(&mut req, &mut pg, ClientWriteType::BODY, b"abcdefgh")
            .unwrap();

        assert_eq!(req.bytecount, 4);
        assert!(req.download_done);
        assert!(xfer.should_close(), "excess body must request a close");
        assert_eq!(cap.lock().unwrap().body, b"abcd");
    }

    #[test]
    fn client_write_no_body_without_headers_is_weird_reply() {
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let mut req = fresh_req();
        req.no_body = true;
        req.allheadercount = 0;
        let mut pg = progress();

        let err = xfer
            .client_write(&mut req, &mut pg, ClientWriteType::BODY, b"unexpected")
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::WeirdServerReply);
        assert!(req.download_done);
    }

    #[test]
    fn client_write_no_body_with_headers_is_ok() {
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let mut req = fresh_req();
        req.no_body = true;
        req.allheadercount = 3; // headers were received (HEAD-like exchange)
        let mut pg = progress();

        xfer.client_write(&mut req, &mut pg, ClientWriteType::BODY, b"body")
            .unwrap();
        assert!(req.download_done);
        assert!(xfer.should_close());
    }

    #[test]
    fn client_write_content_decode_counts_decoded_bytes() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"decoded content").unwrap();
        let gz = enc.finish().unwrap();

        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        xfer.set_content_encoding("gzip").unwrap();
        assert!(xfer.is_content_decoding());

        let mut req = fresh_req();
        let mut pg = progress();
        let (writer, cap) = MockWriter::new();
        req.set_writer_stack(Box::new(writer));

        // Feed the whole gzip blob with EOS so the decoder flushes.
        xfer.write_resp(&mut req, &mut pg, &gz, true).unwrap();

        assert_eq!(cap.lock().unwrap().body, b"decoded content");
        // bytecount reflects the DECODED length, not the compressed input.
        assert_eq!(req.bytecount, "decoded content".len() as i64);
    }

    // =======================================================================
    // xfer_setup / keepon / blocked predicates
    // =======================================================================

    #[test]
    fn xfer_setup_recv_sets_keep_recv_and_size() {
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let mut req = fresh_req();
        let mut pg = progress();
        xfer.xfer_setup_recv(&mut req, &mut pg, 1234, false);
        assert_eq!(req.keepon & KEEP_RECV, KEEP_RECV);
        assert_eq!(req.keepon & KEEP_SEND, 0);
        assert_eq!(req.size, 1234);
        assert!(!req.header);
    }

    #[test]
    fn xfer_is_blocked_reflects_rate_block() {
        let xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let mut req = fresh_req();
        req.keepon = KEEP_RECV;
        let mut rl = rate();
        assert!(!xfer.xfer_is_blocked(&req, &rl));
        rl.block_recv(true, Instant::now());
        assert!(xfer.xfer_is_blocked(&req, &rl));
    }

    #[test]
    fn pause_recv_clears_want_recv() {
        let req_paused = {
            let mut req = fresh_req();
            req.keepon = KEEP_RECV;
            req.pause(CURLPAUSE_RECV);
            req
        };
        // With the receive-pause bit set, the bit-level want_recv is false.
        assert!(!req_paused.want_recv());
    }

    // =======================================================================
    // post_transfer_checks: timeout & partial-file
    // =======================================================================

    #[test]
    fn post_transfer_checks_hard_timeout_with_size() {
        let config = TransferConfig {
            timeout: Some(Duration::from_millis(10)),
            ..TransferConfig::default()
        };
        let mut xfer = transfer_with(MockRecv::new(vec![]), MockSend::default(), config);
        let mut req = fresh_req();
        req.keepon = KEEP_RECV; // still active → the timeout branch runs
        req.size = 100;
        req.bytecount = 10;
        let mut pg = progress();

        let start = Instant::now();
        req.start = Some(start);
        let now = start + Duration::from_secs(1);

        let err = xfer
            .post_transfer_checks(&mut req, &mut pg, start, now)
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::OperationTimedout);
        // The contextual `failf`-style text is the Display output; `message()`
        // is the static `strerror` description ("Timeout was reached").
        let text = err.to_string();
        assert!(
            text.contains("10 out of 100 bytes received"),
            "message was: {text}"
        );
    }

    #[test]
    fn post_transfer_checks_partial_file() {
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let mut req = fresh_req();
        req.keepon = 0; // finished pumping
        req.no_body = false;
        req.size = 100;
        req.bytecount = 40;
        let mut pg = progress();
        let now = Instant::now();

        let err = xfer
            .post_transfer_checks(&mut req, &mut pg, now, now)
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::PartialFile);
        assert!(err.to_string().contains("60 bytes remaining"));
    }

    #[test]
    fn post_transfer_checks_marks_done_when_idle() {
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let mut req = fresh_req();
        req.keepon = 0;
        req.no_body = true; // no partial-file check
        let mut pg = progress();
        let now = Instant::now();
        xfer.post_transfer_checks(&mut req, &mut pg, now, now)
            .unwrap();
        assert!(req.done);
    }

    // =======================================================================
    // Receive path (sendrecv_dl) and full download via perform
    // =======================================================================

    #[tokio::test]
    async fn perform_download_plain() {
        let recv = MockRecv::new(vec![b"hello world"]);
        let mut xfer = transfer_with(recv, MockSend::default(), TransferConfig::default());
        let mut req = fresh_req();
        let mut pg = progress();
        let mut rl = rate();
        let (writer, cap) = MockWriter::new();
        req.set_writer_stack(Box::new(writer));
        xfer.xfer_setup_recv(&mut req, &mut pg, -1, false);

        let outcome = xfer.perform(&mut req, &mut pg, &mut rl).await.unwrap();

        assert_eq!(outcome, TransferOutcome::Done);
        let cap = cap.lock().unwrap();
        assert_eq!(cap.body, b"hello world");
        assert!(cap.eos);
        assert_eq!(req.bytecount, 11);
        assert!(req.download_done);
        assert_eq!(req.keepon & KEEP_RECV, 0);
    }

    #[tokio::test]
    async fn perform_download_chunked() {
        let recv = MockRecv::new(vec![b"hel", b"lo ", b"world!"]);
        let mut xfer = transfer_with(recv, MockSend::default(), TransferConfig::default());
        let mut req = fresh_req();
        let mut pg = progress();
        let mut rl = rate();
        let (writer, cap) = MockWriter::new();
        req.set_writer_stack(Box::new(writer));
        xfer.xfer_setup_recv(&mut req, &mut pg, -1, false);

        let outcome = xfer.perform(&mut req, &mut pg, &mut rl).await.unwrap();
        assert_eq!(outcome, TransferOutcome::Done);
        assert_eq!(cap.lock().unwrap().body, b"hello world!");
        assert_eq!(req.bytecount, 12);
    }

    #[tokio::test]
    async fn perform_download_known_size_exact() {
        let recv = MockRecv::new(vec![b"0123456789"]);
        let mut xfer = transfer_with(recv, MockSend::default(), TransferConfig::default());
        let mut req = fresh_req();
        req.maxdownload = 10;
        let mut pg = progress();
        let mut rl = rate();
        let (writer, cap) = MockWriter::new();
        req.set_writer_stack(Box::new(writer));
        // Known content length of 10 bytes.
        xfer.xfer_setup_recv(&mut req, &mut pg, 10, false);

        let outcome = xfer.perform(&mut req, &mut pg, &mut rl).await.unwrap();
        assert_eq!(outcome, TransferOutcome::Done);
        assert_eq!(cap.lock().unwrap().body, b"0123456789");
        assert_eq!(req.bytecount, 10);
        assert!(req.download_done);
    }

    #[tokio::test]
    async fn perform_download_partial_file_errors() {
        // Server announces 20 bytes but delivers only 5 then closes.
        let recv = MockRecv::new(vec![b"short"]);
        let mut xfer = transfer_with(recv, MockSend::default(), TransferConfig::default());
        let mut req = fresh_req();
        let mut pg = progress();
        let mut rl = rate();
        let (writer, _cap) = MockWriter::new();
        req.set_writer_stack(Box::new(writer));
        req.size = 20; // known size larger than what arrives
        req.keepon = KEEP_RECV;
        req.header = false;

        let err = xfer.perform(&mut req, &mut pg, &mut rl).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::PartialFile);
    }

    #[tokio::test]
    async fn sendrecv_dl_rate_limited_reads_nothing_when_no_budget() {
        let recv = MockRecv::new(vec![b"data-should-not-be-read"]);
        let config = TransferConfig {
            max_recv_speed: 1_000,
            ..TransferConfig::default()
        };
        let mut xfer = transfer_with(recv, MockSend::default(), config);
        let mut req = fresh_req();
        let mut pg = progress();
        let mut rl = rate();
        let (writer, cap) = MockWriter::new();
        req.set_writer_stack(Box::new(writer));
        xfer.xfer_setup_recv(&mut req, &mut pg, -1, false);

        let now = Instant::now();
        // Arm the download limiter and drain its whole budget so nothing is
        // available on the next read.
        xfer.configure_rate_limits(&req, &mut pg, &mut rl, now)
            .unwrap();
        rl.drain_recv(1_000, now);
        assert!(rl.recv_avail(now) <= 0);

        xfer.sendrecv_dl(&mut req, &mut pg, &mut rl, now)
            .await
            .unwrap();
        // No budget → the chunk is untouched and nothing reached the client.
        assert!(cap.lock().unwrap().body.is_empty());
        assert_eq!(req.bytecount, 0);
        assert!(xfer.recv_half().data_pending());
    }

    // =======================================================================
    // Send path (client_read / xfer_send / sendrecv_ul) and full upload
    // =======================================================================

    #[tokio::test]
    async fn perform_upload_plain() {
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let mut req = fresh_req();
        let mut pg = progress();
        let mut rl = rate();
        req.set_reader_stack(Box::new(MockReader::new(b"payload", Some(7))));
        xfer.xfer_setup_send(&mut req, &mut pg);

        let outcome = xfer.perform(&mut req, &mut pg, &mut rl).await.unwrap();
        assert_eq!(outcome, TransferOutcome::Done);
        assert_eq!(xfer.send_half().sent, b"payload");
        assert!(xfer.send_half().eos_seen);
        assert_eq!(req.writebytecount, 7);
        assert!(req.upload_done);
        assert!(req.eos_sent);
        assert_eq!(req.keepon & KEEP_SEND, 0);
    }

    #[tokio::test]
    async fn perform_upload_counts_body_not_headers() {
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let mut req = fresh_req();
        let mut pg = progress();
        let mut rl = rate();
        // Queue a request head, then attach the body reader.
        let head = b"PUT /x HTTP/1.1\r\n\r\n";
        req.queue_request(head, 1).unwrap();
        req.set_reader_stack(Box::new(MockReader::new(b"BODYDATA", Some(8))));
        xfer.xfer_setup_send(&mut req, &mut pg);

        let outcome = xfer.perform(&mut req, &mut pg, &mut rl).await.unwrap();
        assert_eq!(outcome, TransferOutcome::Done);

        let mut expected = head.to_vec();
        expected.extend_from_slice(b"BODYDATA");
        assert_eq!(xfer.send_half().sent, expected);
        // Only the 8 body bytes count toward writebytecount; headers are exempt.
        assert_eq!(req.writebytecount, 8);
    }

    #[tokio::test]
    async fn perform_upload_short_writes_reassemble() {
        // Force 3-byte-at-a-time sends to exercise the short-write flush loop.
        let send = MockSend {
            max_per_send: Some(3),
            ..MockSend::default()
        };
        let mut xfer = transfer_with(MockRecv::new(vec![]), send, TransferConfig::default());
        let mut req = fresh_req();
        let mut pg = progress();
        let mut rl = rate();
        req.set_reader_stack(Box::new(MockReader::new(b"abcdefghij", Some(10))));
        xfer.xfer_setup_send(&mut req, &mut pg);

        let outcome = xfer.perform(&mut req, &mut pg, &mut rl).await.unwrap();
        assert_eq!(outcome, TransferOutcome::Done);
        assert_eq!(xfer.send_half().sent, b"abcdefghij");
        assert_eq!(req.writebytecount, 10);
        assert!(req.upload_done);
    }

    #[test]
    fn expect_100_holds_then_releases_on_timeout() {
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let now = Instant::now();
        xfer.begin_expect_100(now);
        assert_eq!(xfer.expect100(), Expect100::AwaitingContinue);
        // Before the deadline: the body is held.
        assert!(xfer.body_blocked_on_expect_100(now));
        // After the deadline: curl sends the body anyway, releasing the hold.
        let past = now + DEFAULT_EXPECT_100_TIMEOUT + Duration::from_millis(1);
        assert!(!xfer.body_blocked_on_expect_100(past));
        assert_eq!(xfer.expect100(), Expect100::SendData);
    }

    #[test]
    fn expect_100_continue_received_unblocks() {
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig::default(),
        );
        let now = Instant::now();
        xfer.begin_expect_100(now);
        assert!(xfer.body_blocked_on_expect_100(now));
        xfer.continue_received();
        assert_eq!(xfer.expect100(), Expect100::SendData);
        assert!(!xfer.body_blocked_on_expect_100(now));
    }

    #[tokio::test]
    async fn perform_reports_redirect_newurl() {
        // A response handler sets `newurl`; perform surfaces it for the caller.
        let mut xfer = transfer_with(
            MockRecv::new(vec![]),
            MockSend::default(),
            TransferConfig {
                follow_location: true,
                ..TransferConfig::default()
            },
        );
        let mut req = fresh_req();
        let mut pg = progress();
        let mut rl = rate();
        req.keepon = 0; // nothing to pump; a redirect was already discovered
        req.done = false;
        req.newurl = Some("https://example.com/next".to_string());

        let outcome = xfer.perform(&mut req, &mut pg, &mut rl).await.unwrap();
        match outcome {
            TransferOutcome::NeedNewRequest { newurl, follow } => {
                assert_eq!(newurl, "https://example.com/next");
                assert!(follow);
            }
            other => panic!("expected NeedNewRequest, got {other:?}"),
        }
    }
}
