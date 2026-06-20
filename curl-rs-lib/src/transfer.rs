//! The asynchronous transfer engine — the loop that drives a single transfer
//! through its lifecycle and moves bytes between the protocol layer and the
//! client callbacks.
//!
//! This module is the Rust reimplementation of curl's transfer engine, the
//! behavioral oracle for which is `lib/transfer.c` (the read/write loop,
//! pre/post-transfer setup, retry logic, speed-limit checks), `lib/sendf.c`
//! (the client-write pipeline `Curl_client_write` and the send/receive
//! helpers), and `lib/cw-out.c` (the terminal client-writer stage that
//! delivers header/body bytes to the user callbacks with pause buffering). The
//! HTTP redirect rewriting that `lib/transfer.c` historically owned now lives in
//! `lib/http.c` (`Curl_http_follow`) in curl 8.19.0-DEV; its behavior is
//! reproduced here in [`follow`] because redirect handling is intrinsic to
//! driving a transfer to completion and the rules require byte-for-byte parity
//! (AAP §0.8.2).
//!
//! # Chosen model — type-state lifecycle over an async state-machine driver
//!
//! The transfer lifecycle is modelled with the **type-state pattern**
//! ([`Transfer<S>`] with the marker states [`Configured`] → [`Connected`] →
//! [`Transferring`] → [`Complete`]). Each transition consumes `self` and returns
//! the next state, so an out-of-order transition (e.g. streaming a body before
//! connecting) is a *compile error* rather than a runtime check — exactly the
//! compile-time safety the AAP (§0.4.3) asks for. The states wrap one owned
//! [`TransferData`] record (the per-transfer state the loop advances), so the
//! type parameter adds safety without duplicating data or fighting the borrow
//! checker.
//!
//! Within the [`Transferring`] state the actual byte pumping is an async
//! state-machine driver ([`drive_transfer`]) that consumes a stream of
//! [`ResponseEvent`]s from the protocol and feeds them through the
//! [`ClientWriter`] chain. A pure type-state encoding of *every* micro-step of
//! the byte loop would fight Rust's async borrow model (each `await` would have
//! to thread the owned state through a future), so the inner loop is a
//! conventional async driver while the coarse lifecycle keeps its type-state
//! guarantees. This hybrid is the sweet spot the AAP describes: type-state where
//! it buys compile-time safety, an async driver where it would otherwise fight
//! the borrow model.
//!
//! # Dependency inversion (why this module defines its own collaborator traits)
//!
//! The engine ties together connections (`crate::conn`), protocol handlers
//! (`crate::protocols`) and the easy handle (`crate::easy`). Those modules are
//! authored in later migration steps (AAP §0.8.4) and are *not* in this file's
//! dependency set. Rather than depend on types that do not yet exist, the engine
//! **defines the contracts it needs** as local traits — [`Connection`],
//! [`ProtocolExchange`] and [`TransferHandle`] — and depends only on the
//! concrete, already-available subsystems it owns the integration of:
//! [`crate::error`], [`crate::request`], [`crate::progress`],
//! [`crate::content_encoding`], [`crate::ratelimit`] and [`crate::url`]. The
//! connection/protocol/handle types implement these traits, so the wiring is
//! dependency-inverted: the engine names *what* it requires and the leaf modules
//! provide *how*. This keeps the engine compilable and exhaustively
//! unit-testable in isolation (the tests at the bottom of this file drive the
//! whole loop with in-memory mock implementations).
//!
//! # Synchronous C ABI over the async core
//!
//! Every entry point here is `async`; nothing in this module blocks. The
//! synchronous libcurl C contract (`curl_easy_perform`) is honored by
//! `curl-rs-ffi` calling `block_on` on [`run`] / [`Transfer`] — the bridge lives
//! at the FFI edge, never here (AAP §0.4.4 / §0.8.3).
//!
//! # Memory safety
//!
//! This module contains **zero `unsafe`** (AAP §0.7.1 / §0.8.2). All buffer and
//! pointer handling is expressed with [`Vec`], [`bytes::BytesMut`] and safe
//! slice operations.

use std::collections::VecDeque;
use std::marker::PhantomData;
use std::time::{Duration, Instant};

use bytes::BytesMut;

use crate::content_encoding::UnencodingStack;
use crate::error::{CurlError, CurlUError, Result};
use crate::progress::{
    Progress, ProgressCallbackRef, Timer, TimerData, CURL_PROGRESSFUNC_CONTINUE,
};
use crate::ratelimit::{Direction, RateLimit};
use crate::request::Request;
use crate::url::{
    CurlUPart, CurlUrl, CURLU_ALLOW_SPACE, CURLU_DEFAULT_PORT, CURLU_NON_SUPPORT_SCHEME,
    CURLU_PATH_AS_IS, CURLU_URLENCODE,
};

// ===========================================================================
// Constants & sentinels (verbatim from the curl 8.x public/internal headers)
// ===========================================================================

/// Largest chunk handed to the body write callback in a single call
/// (`CURL_MAX_WRITE_SIZE`, `include/curl/curl.h`). Body output is split into
/// pieces no larger than this; header output is delivered as-is (no chunking),
/// matching `cw-out.c`.
pub const CURL_MAX_WRITE_SIZE: usize = 16384;

/// Sentinel a write callback returns to *pause* the transfer
/// (`CURL_WRITEFUNC_PAUSE`, `include/curl/curl.h`). The data is treated as not
/// written; the receive side is paused and the buffered bytes are replayed on
/// unpause.
pub const CURL_WRITEFUNC_PAUSE: usize = 0x1000_0001;

/// Sentinel a write callback returns to *fail* the transfer
/// (`CURL_WRITEFUNC_ERROR`, `include/curl/curl.h`). Yields
/// [`CurlError::WriteError`].
///
/// This is the literal 32-bit all-ones value curl defines; it is deliberately
/// **not** `usize::MAX`, so on 64-bit targets a callback must return exactly
/// `0xFFFF_FFFF` (not `(size_t)-1`) to signal an error — identical to C.
pub const CURL_WRITEFUNC_ERROR: usize = 0xFFFF_FFFF;

/// Sentinel a read callback returns to *abort* the transfer
/// (`CURL_READFUNC_ABORT`, `include/curl/curl.h`). Yields
/// [`CurlError::AbortedByCallback`].
pub const CURL_READFUNC_ABORT: usize = 0x1000_0000;

/// Sentinel a read callback returns to *pause* the upload
/// (`CURL_READFUNC_PAUSE`, `include/curl/curl.h`).
pub const CURL_READFUNC_PAUSE: usize = 0x1000_0001;

/// Upper bound on bytes buffered while a transfer is paused
/// (`DYN_PAUSE_BUFFER`, `lib/curlx/dynbuf.h` — 64 MiB). Exceeding it fails the
/// transfer with [`CurlError::TooLarge`], reproducing curl's
/// decompression/pause-bomb guard.
pub const DYN_PAUSE_BUFFER: usize = 64 * 1024 * 1024;

/// Maximum number of fresh-connect retries for a request that produced no data
/// on a reused connection (`CONN_MAX_RETRIES`, `lib/transfer.c`).
pub const CONN_MAX_RETRIES: u32 = 5;

// ===========================================================================
// Client-write routing flags (`CLIENTWRITE_*`, lib/sendf.h)
// ===========================================================================

/// The `CLIENTWRITE_*` routing flags carried by a [`ClientWriter::write`] call,
/// modelled as a small bitset newtype (the C code uses a raw `int` bitmask).
///
/// The flags select the "stream" the bytes belong to (body vs. the various
/// header/meta kinds) and signal end-of-stream / zero-length writes. They match
/// `lib/sendf.h` bit-for-bit so a protocol handler ported from C can pass the
/// same flag set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientWriteType(u16);

impl ClientWriteType {
    /// `CLIENTWRITE_BODY` — non-meta response body bytes.
    pub const BODY: ClientWriteType = ClientWriteType(1 << 0);
    /// `CLIENTWRITE_INFO` — meta information that is *not* a header.
    pub const INFO: ClientWriteType = ClientWriteType(1 << 1);
    /// `CLIENTWRITE_HEADER` — a response header line.
    pub const HEADER: ClientWriteType = ClientWriteType(1 << 2);
    /// `CLIENTWRITE_STATUS` — the status line (a special header).
    pub const STATUS: ClientWriteType = ClientWriteType(1 << 3);
    /// `CLIENTWRITE_CONNECT` — a `CONNECT`-tunnel-related header.
    pub const CONNECT: ClientWriteType = ClientWriteType(1 << 4);
    /// `CLIENTWRITE_1XX` — a `1xx` informational-response header.
    pub const INFO_1XX: ClientWriteType = ClientWriteType(1 << 5);
    /// `CLIENTWRITE_TRAILER` — a trailer header (after a chunked body).
    pub const TRAILER: ClientWriteType = ClientWriteType(1 << 6);
    /// `CLIENTWRITE_EOS` — end of the download stream.
    pub const EOS: ClientWriteType = ClientWriteType(1 << 7);
    /// `CLIENTWRITE_0LEN` — deliver even a zero-length write to the callback.
    pub const ZERO_LEN: ClientWriteType = ClientWriteType(1 << 8);

    /// The empty flag set.
    pub const NONE: ClientWriteType = ClientWriteType(0);

    /// `true` if every bit in `other` is also set in `self`.
    #[must_use]
    pub const fn contains(self, other: ClientWriteType) -> bool {
        (self.0 & other.0) == other.0
    }

    /// `true` if any bit in `other` is set in `self`.
    #[must_use]
    pub const fn intersects(self, other: ClientWriteType) -> bool {
        (self.0 & other.0) != 0
    }

    /// The union of two flag sets.
    #[must_use]
    pub const fn union(self, other: ClientWriteType) -> ClientWriteType {
        ClientWriteType(self.0 | other.0)
    }

    /// `true` if no flags are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The raw bit pattern (for diagnostics / FFI parity).
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// `true` if these flags denote body bytes (the only stream that is
    /// content-decoded), i.e. [`ClientWriteType::BODY`] is set.
    #[must_use]
    pub const fn is_body(self) -> bool {
        self.contains(ClientWriteType::BODY)
    }

    /// `true` if these flags denote any header/meta stream — anything that is
    /// not body: [`HEADER`](Self::HEADER), [`INFO`](Self::INFO),
    /// [`STATUS`](Self::STATUS), [`CONNECT`](Self::CONNECT),
    /// [`INFO_1XX`](Self::INFO_1XX) or [`TRAILER`](Self::TRAILER).
    #[must_use]
    pub const fn is_header(self) -> bool {
        self.intersects(
            ClientWriteType::HEADER
                .union(ClientWriteType::INFO)
                .union(ClientWriteType::STATUS)
                .union(ClientWriteType::CONNECT)
                .union(ClientWriteType::INFO_1XX)
                .union(ClientWriteType::TRAILER),
        )
    }
}

impl std::ops::BitOr for ClientWriteType {
    type Output = ClientWriteType;
    fn bitor(self, rhs: ClientWriteType) -> ClientWriteType {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for ClientWriteType {
    fn bitor_assign(&mut self, rhs: ClientWriteType) {
        self.0 |= rhs.0;
    }
}

// ===========================================================================
// Client-writer chain (lib/sendf.c `Curl_client_write` + lib/cw-out.c)
// ===========================================================================
//
// Response bytes flow through an ordered pipeline before reaching the user:
//
//   protocol → [content-decoding] → header/body split → [pause buffering] →
//   CURLOPT_WRITEFUNCTION / CURLOPT_HEADERFUNCTION
//
// * Content decoding ([`UnencodingStack`]) transforms **body** bytes only;
//   header/meta bytes pass through untouched (curl's content-decode writer
//   ignores non-`CLIENTWRITE_BODY` data). This is `crate::content_encoding`.
// * The terminal stage ([`CwOut`]) is the Rust port of `lib/cw-out.c`: it splits
//   delivery into a *body* stream and a *header* stream, chunks the body to
//   `CURL_MAX_WRITE_SIZE`, delivers headers verbatim (no chunking), and — when a
//   write callback returns [`CURL_WRITEFUNC_PAUSE`] — buffers subsequent data in
//   an ordered chain (capped at [`DYN_PAUSE_BUFFER`]) that is *replayed in
//   arrival order* once the transfer is unpaused.
// * After any callback error the stage *latches* into an errored state and never
//   invokes a client callback again (curl issue #13337).

/// The user-supplied output callbacks (`CURLOPT_WRITEFUNCTION` and
/// `CURLOPT_HEADERFUNCTION`).
///
/// Both methods use curl's callback return convention: the count of bytes taken,
/// or one of the sentinels [`CURL_WRITEFUNC_PAUSE`] / [`CURL_WRITEFUNC_ERROR`].
/// Returning any value other than the supplied length (and not a sentinel) is a
/// short write and fails the transfer with [`CurlError::WriteError`], matching
/// `cw_out_cb_write` in `lib/cw-out.c`.
///
/// The [`Send`] supertrait lets a transfer that uses a sink be spawned on the
/// multi handle's multi-thread Tokio runtime (`curl_multi_perform`); a front-end
/// that bridges raw C callbacks holds the function/userdata as integer addresses
/// (which are `Send`) and casts them back at the call site.
pub trait WriteCallbacks: Send {
    /// Deliver body bytes (`CURLOPT_WRITEFUNCTION`, default writes to the chosen
    /// output / stdout). A body sink is always considered present.
    fn write_body(&mut self, data: &[u8]) -> usize;

    /// Deliver a header/meta chunk (`CURLOPT_HEADERFUNCTION`). Returns `None`
    /// when no header sink is configured — curl then *silently consumes* the
    /// header bytes (`cw_get_writefunc` yields a `NULL` callback). Returns
    /// `Some(n)` otherwise, with the same convention as [`Self::write_body`].
    fn write_header(&mut self, data: &[u8]) -> Option<usize>;
}

/// The kind of an output buffer node / a single delivery to [`CwOut`], mirroring
/// `cw_out_type` in `lib/cw-out.c`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CwOutType {
    /// Ordinary body bytes (`CW_OUT_BODY`).
    Body,
    /// A *zero-length* body delivery that must still reach the callback once
    /// (`CW_OUT_BODY_0LEN`) — e.g. an empty `200 OK` body with `CLIENTWRITE_0LEN`.
    Body0Len,
    /// Header / meta bytes (`CW_OUT_HDS`).
    Hds,
}

/// One node in the pause-buffer chain (`struct cw_out_buf`): a run of buffered
/// bytes of a single [`CwOutType`].
#[derive(Debug)]
struct PauseBuf {
    kind: CwOutType,
    data: BytesMut,
}

/// The outcome of a single client-callback invocation, capturing the three
/// non-error cases of `cw_out_cb_write`.
enum CbOutcome {
    /// The callback consumed all `n` offered bytes.
    Written(usize),
    /// The callback requested a pause; the offered bytes are *not* consumed and
    /// must be buffered for replay.
    Paused,
    /// No callback is configured (headers only) — consume the bytes silently.
    NoSink,
}

/// The terminal client-writer stage — the Rust port of `lib/cw-out.c`.
///
/// Holds the pause state, the errored latch, the ordered pause-buffer chain
/// (`bufs`, front = oldest so replay is FIFO), and the running buffered byte
/// count enforced against [`DYN_PAUSE_BUFFER`].
#[derive(Debug)]
struct CwOut {
    /// `true` while a write callback has requested a pause; no callback is
    /// invoked while paused — data is appended to `bufs` instead.
    paused: bool,
    /// Sticky error latch (`ctx->errored`): once set, every further write fails
    /// with [`CurlError::WriteError`] and no callback is ever called again.
    errored: bool,
    /// The ordered buffer chain; `front` is the oldest buffered run.
    bufs: VecDeque<PauseBuf>,
    /// Sum of `data.len()` across `bufs`, checked against [`DYN_PAUSE_BUFFER`].
    buffered_len: usize,
    /// `CURLOPT_HEADER`: when set, header bytes are *also* delivered on the body
    /// stream (matches `data->set.include_header` in `cw_out_write`).
    include_header: bool,
    /// `false` for `PROTOPT_NONETWORK` protocols (FILE://) that cannot pause; a
    /// pause request then becomes [`CurlError::WriteError`].
    can_pause: bool,
    /// Preferred minimum write size (`cw_get_writefunc`'s `min_write`). curl
    /// 8.x uses `0` for both body and headers (deliver as data arrives), so the
    /// `flush_all`-gated early-break never fires; kept for structural parity.
    min_write: usize,
}

impl CwOut {
    fn new(include_header: bool, can_pause: bool) -> Self {
        CwOut {
            paused: false,
            errored: false,
            bufs: VecDeque::new(),
            buffered_len: 0,
            include_header,
            can_pause,
            min_write: 0,
        }
    }

    /// The type of the newest buffered run (C: `ctx->buf->type`, the head of the
    /// prepend list — here the back of the FIFO deque).
    fn newest_type(&self) -> Option<CwOutType> {
        self.bufs.back().map(|b| b.kind)
    }

    /// `cw_out_write`: route a delivery to the body and/or header stream.
    fn do_client_write(
        &mut self,
        wtype: ClientWriteType,
        buf: &[u8],
        callbacks: &mut dyn WriteCallbacks,
    ) -> Result<()> {
        if self.errored {
            return Err(CurlError::WriteError);
        }
        let flush_all = wtype.contains(ClientWriteType::EOS);

        // Body stream: real body bytes, or header bytes when CURLOPT_HEADER is on.
        if wtype.contains(ClientWriteType::BODY)
            || (wtype.contains(ClientWriteType::HEADER) && self.include_header)
        {
            let otype = if buf.is_empty() && wtype.contains(ClientWriteType::ZERO_LEN) {
                CwOutType::Body0Len
            } else {
                CwOutType::Body
            };
            self.do_write(otype, flush_all, buf, callbacks)?;
        }

        // Header stream: anything tagged HEADER or INFO.
        if wtype.intersects(ClientWriteType::HEADER.union(ClientWriteType::INFO)) {
            self.do_write(CwOutType::Hds, flush_all, buf, callbacks)?;
        }

        Ok(())
    }

    /// `cw_out_do_write`: flush-on-type-change, then append+flush or direct-write
    /// with remainder buffering. On *any* error the stage latches errored and
    /// frees its buffers.
    fn do_write(
        &mut self,
        otype: CwOutType,
        flush_all: bool,
        buf: &[u8],
        callbacks: &mut dyn WriteCallbacks,
    ) -> Result<()> {
        let result = self.do_write_inner(otype, flush_all, buf, callbacks);
        if result.is_err() {
            // issue #13337: never invoke client callbacks again after an error.
            self.errored = true;
            self.bufs.clear();
            self.buffered_len = 0;
        }
        result
    }

    fn do_write_inner(
        &mut self,
        otype: CwOutType,
        flush_all: bool,
        buf: &[u8],
        callbacks: &mut dyn WriteCallbacks,
    ) -> Result<()> {
        // If we have buffered data of a *different* type, flush all of it first
        // so the streams stay correctly ordered.
        if let Some(newest) = self.newest_type() {
            if newest != otype {
                self.flush_chain(true, callbacks)?;
            }
        }

        if !self.bufs.is_empty() {
            // Still buffered (either same-type, or a pause survived the flush):
            // append and try to flush the whole chain.
            self.append(otype, buf)?;
            self.flush_chain(flush_all, callbacks)?;
        } else {
            // Nothing buffered: attempt a direct write, buffer any remainder.
            let consumed = self.ptr_flush(otype, flush_all, buf, callbacks)?;
            if consumed < buf.len() {
                self.append(otype, &buf[consumed..])?;
            }
        }
        Ok(())
    }

    /// `cw_out_append`: enforce the pause-buffer cap and append `buf` to the
    /// newest run, starting a fresh run on type change or for every header run
    /// (so headers replay exactly as they arrived).
    fn append(&mut self, otype: CwOutType, buf: &[u8]) -> Result<()> {
        if self.buffered_len + buf.len() > DYN_PAUSE_BUFFER {
            // "pause buffer not large enough -> CURLE_TOO_LARGE"
            return Err(CurlError::TooLarge);
        }
        let need_new = match self.bufs.back() {
            None => true,
            Some(b) => b.kind != otype || otype == CwOutType::Hds,
        };
        if need_new {
            self.bufs.push_back(PauseBuf {
                kind: otype,
                data: BytesMut::new(),
            });
        }
        let back = self
            .bufs
            .back_mut()
            .expect("a buffer run exists after the optional push_back");
        back.data.extend_from_slice(buf);
        self.buffered_len += buf.len();
        Ok(())
    }

    /// `cw_out_flush_chain`: flush buffered runs oldest-first until the chain is
    /// empty or a callback pauses again. A no-op while paused.
    fn flush_chain(&mut self, flush_all: bool, callbacks: &mut dyn WriteCallbacks) -> Result<()> {
        if self.paused {
            return Ok(());
        }
        while let Some(mut front) = self.bufs.pop_front() {
            // Drop empty non-0LEN runs (can arise after a partial flush).
            if front.data.is_empty() && front.kind != CwOutType::Body0Len {
                continue;
            }
            let total = front.data.len();
            let consumed = self.ptr_flush(front.kind, flush_all, &front.data, callbacks)?;
            if consumed >= total {
                // Whole run delivered.
                self.buffered_len -= total;
                if self.paused {
                    break;
                }
            } else {
                // Partial delivery only happens on a fresh pause: keep the
                // unconsumed tail at the front and stop.
                self.buffered_len -= consumed;
                let _ = front.data.split_to(consumed);
                self.bufs.push_front(front);
                break;
            }
        }
        Ok(())
    }

    /// `cw_out_ptr_flush` + `cw_get_writefunc`: deliver `buf` of the given kind to
    /// the appropriate callback, chunking the body to [`CURL_MAX_WRITE_SIZE`] and
    /// writing headers whole. Returns the number of bytes consumed (`< buf.len()`
    /// only when a pause interrupted delivery).
    fn ptr_flush(
        &mut self,
        kind: CwOutType,
        flush_all: bool,
        buf: &[u8],
        callbacks: &mut dyn WriteCallbacks,
    ) -> Result<usize> {
        if self.errored {
            return Err(CurlError::WriteError);
        }

        // A zero-length body delivery is a single empty callback call.
        if kind == CwOutType::Body0Len {
            match self.cb_write_body(&[], callbacks)? {
                CbOutcome::Paused => {}
                CbOutcome::Written(_) | CbOutcome::NoSink => {}
            }
            return Ok(0);
        }

        // Body chunks to CURL_MAX_WRITE_SIZE; headers are written whole.
        let max_write = match kind {
            CwOutType::Body => CURL_MAX_WRITE_SIZE,
            CwOutType::Hds => 0, // 0 == "no chunking, write as-is"
            CwOutType::Body0Len => unreachable!("handled above"),
        };
        let min_write = self.min_write;

        let mut consumed = 0usize;
        let mut rest = buf;
        while !rest.is_empty() && !self.paused {
            // curl: `if (!flush_all && blen < min_write) break;`. min_write is 0
            // in curl 8.x so this never fires; preserved for structural parity.
            if !flush_all && min_write != 0 && rest.len() < min_write {
                break;
            }
            let wlen = if max_write > 0 {
                rest.len().min(max_write)
            } else {
                rest.len()
            };
            let chunk = &rest[..wlen];
            let outcome = match kind {
                CwOutType::Hds => self.cb_write_header(chunk, callbacks)?,
                _ => self.cb_write_body(chunk, callbacks)?,
            };
            match outcome {
                CbOutcome::Written(n) => {
                    consumed += n;
                    rest = &rest[n..];
                }
                CbOutcome::NoSink => {
                    // Only headers can lack a sink; consume the whole chunk.
                    consumed += chunk.len();
                    rest = &rest[chunk.len()..];
                }
                CbOutcome::Paused => break,
            }
        }
        Ok(consumed)
    }

    /// `cw_out_cb_write` for the body callback. Translates curl's all-or-nothing
    /// return convention into a [`CbOutcome`].
    fn cb_write_body(
        &mut self,
        buf: &[u8],
        callbacks: &mut dyn WriteCallbacks,
    ) -> Result<CbOutcome> {
        let n = callbacks.write_body(buf);
        if n == CURL_WRITEFUNC_PAUSE {
            if !self.can_pause {
                // "Write callback asked for PAUSE when not supported"
                return Err(CurlError::WriteError);
            }
            self.paused = true;
            Ok(CbOutcome::Paused)
        } else if n == CURL_WRITEFUNC_ERROR || n != buf.len() {
            // Two curl conditions collapse to the same CURLE_WRITE_ERROR:
            // an explicit CURL_WRITEFUNC_ERROR ("client returned ERROR on
            // write of N bytes") and a short write ("Failure writing output
            // to destination, passed N returned M").
            Err(CurlError::WriteError)
        } else {
            Ok(CbOutcome::Written(n))
        }
    }

    /// `cw_out_cb_write` for the header callback (`None` ⇒ no sink ⇒ silent).
    fn cb_write_header(
        &mut self,
        buf: &[u8],
        callbacks: &mut dyn WriteCallbacks,
    ) -> Result<CbOutcome> {
        match callbacks.write_header(buf) {
            None => Ok(CbOutcome::NoSink),
            Some(n) => {
                if n == CURL_WRITEFUNC_PAUSE {
                    if !self.can_pause {
                        return Err(CurlError::WriteError);
                    }
                    self.paused = true;
                    Ok(CbOutcome::Paused)
                } else if n == CURL_WRITEFUNC_ERROR || n != buf.len() {
                    // CURL_WRITEFUNC_ERROR or a short write — both are
                    // CURLE_WRITE_ERROR (see cb_write_body).
                    Err(CurlError::WriteError)
                } else {
                    Ok(CbOutcome::Written(n))
                }
            }
        }
    }
}

/// The full client-writer chain: content decoding followed by the [`CwOut`]
/// delivery stage. This is the Rust equivalent of entering curl's client-writer
/// chain via `Curl_client_write`.
///
/// # Example
///
/// ```
/// use curl_rs_lib::transfer::{ClientWriteType, ClientWriter, WriteCallbacks};
///
/// struct Collect {
///     body: Vec<u8>,
///     headers: Vec<u8>,
/// }
/// impl WriteCallbacks for Collect {
///     fn write_body(&mut self, data: &[u8]) -> usize {
///         self.body.extend_from_slice(data);
///         data.len()
///     }
///     fn write_header(&mut self, data: &[u8]) -> Option<usize> {
///         self.headers.extend_from_slice(data);
///         Some(data.len())
///     }
/// }
///
/// let mut cb = Collect { body: Vec::new(), headers: Vec::new() };
/// let mut w = ClientWriter::new();
/// w.write(ClientWriteType::HEADER, b"HTTP/1.1 200 OK\r\n", &mut cb).unwrap();
/// w.write(ClientWriteType::BODY | ClientWriteType::EOS, b"hello", &mut cb).unwrap();
/// assert_eq!(cb.body, b"hello");
/// assert_eq!(cb.headers, b"HTTP/1.1 200 OK\r\n");
/// ```
pub struct ClientWriter {
    /// The content-decoding stack (`Content-Encoding` / `Transfer-Encoding`
    /// decompression). Empty ⇒ body bytes pass through unchanged.
    decoder: UnencodingStack,
    /// The terminal output / pause-buffering stage.
    out: CwOut,
    /// Set once an end-of-stream body write has flushed the decoder, so the
    /// decoder is finalized at most once.
    eos_seen: bool,
}

impl std::fmt::Debug for ClientWriter {
    // `UnencodingStack` is not `Debug`; report its depth instead of its guts.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientWriter")
            .field("decoder_stack_len", &self.decoder.len())
            .field("out", &self.out)
            .field("eos_seen", &self.eos_seen)
            .finish()
    }
}

impl ClientWriter {
    /// A writer with no content decoding, `CURLOPT_HEADER` off, and pausing
    /// allowed (the common network-protocol case).
    #[must_use]
    pub fn new() -> Self {
        ClientWriter {
            decoder: UnencodingStack::new(),
            out: CwOut::new(false, true),
            eos_seen: false,
        }
    }

    /// A writer with explicit options.
    ///
    /// * `include_header` — `CURLOPT_HEADER`: also deliver headers on the body
    ///   stream.
    /// * `can_pause` — `false` for `PROTOPT_NONETWORK` protocols (FILE://) that
    ///   cannot honor a pause request.
    #[must_use]
    pub fn with_options(include_header: bool, can_pause: bool) -> Self {
        ClientWriter {
            decoder: UnencodingStack::new(),
            out: CwOut::new(include_header, can_pause),
            eos_seen: false,
        }
    }

    /// Build a writer whose body stream is decoded according to `enclist` (the
    /// value of a `Content-Encoding`/`Transfer-Encoding` header, e.g.
    /// `"gzip"`), mirroring curl's construction of the content-decode writers.
    ///
    /// When `decoding_enabled` is `false` the encodings are recognized but left
    /// undecoded (curl's behavior when `CURLOPT_HTTP_CONTENT_DECODING` is off):
    /// the raw bytes pass straight through.
    pub fn with_content_encoding(
        enclist: &str,
        decoding_enabled: bool,
        include_header: bool,
        can_pause: bool,
    ) -> Result<Self> {
        Ok(ClientWriter {
            decoder: UnencodingStack::from_content_encoding(enclist, decoding_enabled)?,
            out: CwOut::new(include_header, can_pause),
            eos_seen: false,
        })
    }

    /// Deliver a chunk of response data through the chain (`Curl_client_write`).
    ///
    /// `wtype` selects the stream(s) and carries the end-of-stream / zero-length
    /// signals; `buf` is the raw protocol payload (decoded here if it is body
    /// data and a content encoding is active). When `wtype` carries
    /// [`ClientWriteType::EOS`] on a body write, the content decoder is flushed
    /// exactly once so trailing decompressed bytes are delivered.
    pub fn write(
        &mut self,
        wtype: ClientWriteType,
        buf: &[u8],
        callbacks: &mut dyn WriteCallbacks,
    ) -> Result<()> {
        if self.out.errored {
            return Err(CurlError::WriteError);
        }
        let is_body = wtype.is_body();

        // Disjoint borrows: the decoder transforms bytes; `out` delivers them.
        let ClientWriter {
            decoder,
            out,
            eos_seen,
        } = self;

        // Stage 1+2: content-decode (body only; headers/meta pass through) and
        // hand each produced chunk to the cw-out delivery stage carrying the
        // original routing flags — exactly as curl's chain threads `type`
        // unchanged from one writer to the next.
        {
            let mut sink = |decoded: &[u8]| out.do_client_write(wtype, decoded, &mut *callbacks);
            decoder.write(is_body, buf, &mut sink)?;
        }

        // End-of-stream: flush the decoder's residual decompressed output once.
        if is_body && wtype.contains(ClientWriteType::EOS) && !*eos_seen {
            *eos_seen = true;
            let mut sink = |decoded: &[u8]| out.do_client_write(wtype, decoded, &mut *callbacks);
            decoder.finish(&mut sink)?;
        }

        Ok(())
    }

    /// (Re)configure the body content-decoding stack once the response's
    /// `Content-Encoding` is known (curl installs the content-decode writers
    /// after parsing the headers, before any body arrives). Replacing the
    /// decoder is only valid before body bytes have been written.
    pub fn set_content_encoding(&mut self, enclist: &str, decoding_enabled: bool) -> Result<()> {
        self.decoder = UnencodingStack::from_content_encoding(enclist, decoding_enabled)?;
        Ok(())
    }

    /// Clear the pause and replay the buffered chain in arrival order
    /// (`curl_easy_pause` with `CURLPAUSE_CONT` on the receive side). If a
    /// callback pauses again mid-replay the remaining bytes stay buffered.
    pub fn unpause(&mut self, callbacks: &mut dyn WriteCallbacks) -> Result<()> {
        if self.out.errored {
            return Err(CurlError::WriteError);
        }
        self.out.paused = false;
        self.out.flush_chain(true, callbacks)
    }

    /// `true` while a write callback has paused the receive side.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.out.paused
    }

    /// `true` once a callback error has latched the writer (no further callbacks
    /// will be invoked).
    #[must_use]
    pub fn is_errored(&self) -> bool {
        self.out.errored
    }

    /// The number of bytes currently held in the pause buffer.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.out.buffered_len
    }
}

impl Default for ClientWriter {
    fn default() -> Self {
        ClientWriter::new()
    }
}

// ===========================================================================
// Read / upload pump (lib/sendf.c `cr_in_read` — the default client reader)
// ===========================================================================

/// The user-supplied upload source (`CURLOPT_READFUNCTION`).
///
/// The [`Send`] supertrait lets a transfer that uses a source be spawned on the
/// multi handle's multi-thread Tokio runtime (see [`WriteCallbacks`]).
pub trait ReadCallback: Send {
    /// Fill `buf` with up to `buf.len()` bytes of upload data and return the
    /// count, `0` to signal end-of-input, or one of the sentinels
    /// [`CURL_READFUNC_ABORT`] / [`CURL_READFUNC_PAUSE`]. Returning more than
    /// `buf.len()` is a fault and fails the transfer with
    /// [`CurlError::ReadError`] ("read function returned funny value").
    fn read(&mut self, buf: &mut [u8]) -> usize;
}

/// The result of pulling one block of upload data through [`UploadReader::read`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadStep {
    /// `n` bytes were placed at the front of the caller's buffer.
    Data(usize),
    /// End of the upload stream — the source is exhausted.
    Eof,
    /// The source requested a pause ([`CURL_READFUNC_PAUSE`]); no bytes were
    /// produced and the send side must stop until unpaused.
    Paused,
}

/// The default client reader — the Rust port of `cr_in_read` in `lib/sendf.c`.
///
/// It pulls upload bytes from a [`ReadCallback`], honoring an optional total
/// length (`CURLOPT_INFILESIZE[_LARGE]`), the abort/pause sentinels, the
/// "callback returned a too-large value" guard, and the early-EOF check (a
/// source that ends before the announced length fails the transfer). Once it
/// errors it returns that same error forever (curl's sticky-error contract).
#[derive(Debug)]
pub struct UploadReader {
    /// The announced upload size, if known (`CURLOPT_INFILESIZE`); `None` is an
    /// open-ended stream that ends when the callback returns `0`.
    total_len: Option<u64>,
    /// Bytes pulled from the source so far.
    read_len: u64,
    /// Set once the source has signalled end-of-input.
    seen_eos: bool,
    /// Sticky error: once set, every subsequent [`Self::read`] returns it.
    errored: Option<CurlError>,
    /// `true` for the duration after the source requested a pause; reset at the
    /// start of the next read attempt.
    is_paused: bool,
    /// `false` for `PROTOPT_NONETWORK` protocols (FILE://) that cannot pause; a
    /// pause request then becomes [`CurlError::ReadError`].
    can_pause: bool,
    /// `true` once the callback has been invoked at least once (curl uses this
    /// to decide whether a rewind is required on retry).
    has_used_cb: bool,
}

impl UploadReader {
    /// Create a reader for an upload of `total_len` bytes (`None` = unknown /
    /// open-ended). `can_pause` is `false` only for FILE://.
    #[must_use]
    pub fn new(total_len: Option<u64>, can_pause: bool) -> Self {
        UploadReader {
            total_len,
            read_len: 0,
            seen_eos: false,
            errored: None,
            is_paused: false,
            can_pause,
            has_used_cb: false,
        }
    }

    /// `true` if the most recent read paused the upload.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.is_paused
    }

    /// `true` once the source has reported end-of-input.
    #[must_use]
    pub fn seen_eos(&self) -> bool {
        self.seen_eos
    }

    /// Total bytes pulled from the source so far.
    #[must_use]
    pub fn read_len(&self) -> u64 {
        self.read_len
    }

    /// `true` once the read callback has been invoked at least once.
    #[must_use]
    pub fn has_used_cb(&self) -> bool {
        self.has_used_cb
    }

    /// Pull the next block of upload data into `buf`, returning a [`ReadStep`].
    ///
    /// Mirrors `cr_in_read`: clamps the request to the remaining announced
    /// length, calls the source, then maps `0`/`ABORT`/`PAUSE`/over-long returns
    /// exactly as curl does.
    pub fn read(&mut self, buf: &mut [u8], cb: &mut dyn ReadCallback) -> Result<ReadStep> {
        self.is_paused = false;

        // Sticky error: return the same error forever (CurlError is Copy).
        if let Some(err) = self.errored {
            return Err(err);
        }
        if self.seen_eos {
            return Ok(ReadStep::Eof);
        }

        // Respect the announced length: never ask for more than remains.
        let mut blen = buf.len();
        if let Some(total) = self.total_len {
            let remaining = total.saturating_sub(self.read_len);
            let cap = usize::try_from(remaining).unwrap_or(usize::MAX);
            blen = blen.min(cap);
        }

        let mut nread = 0usize;
        if blen > 0 {
            nread = cb.read(&mut buf[..blen]);
            self.has_used_cb = true;
        }

        if nread == 0 {
            // End of input. If a length was announced and we are short, it is an
            // error ("client read function EOF fail").
            if let Some(total) = self.total_len {
                if self.read_len < total {
                    return Err(CurlError::ReadError);
                }
            }
            self.seen_eos = true;
            return Ok(ReadStep::Eof);
        }
        if nread == CURL_READFUNC_ABORT {
            // "operation aborted by callback"
            self.errored = Some(CurlError::AbortedByCallback);
            return Err(CurlError::AbortedByCallback);
        }
        if nread == CURL_READFUNC_PAUSE {
            if !self.can_pause {
                // "Read callback asked for PAUSE when not supported"
                return Err(CurlError::ReadError);
            }
            self.is_paused = true;
            return Ok(ReadStep::Paused);
        }
        if nread > blen {
            // "read function returned funny value"
            self.errored = Some(CurlError::ReadError);
            return Err(CurlError::ReadError);
        }

        self.read_len += nread as u64;
        if let Some(total) = self.total_len {
            self.seen_eos = self.read_len >= total;
        }
        Ok(ReadStep::Data(nread))
    }
}

// ===========================================================================
// Redirect handling (lib/http.c `Curl_http_follow` + `http_switch_to_get`)
// ===========================================================================
//
// Redirect handling demands byte-for-byte behavioral parity (AAP §0.8.2): the
// `maxredirs` cap, the 301/302/303 → GET method rewrites with their
// `CURLOPT_POSTREDIR` overrides, auto-referer derivation, credential clearing on
// host/scheme/port change, and the exact URL-resolution flags per follow type.
// The logic is expressed as pure functions over explicit option/state inputs so
// it is exhaustively unit-testable without a live connection; the driver applies
// the returned [`FollowOutcome`] to the handle (request rewind, URL adoption).

/// curl's `followtype` — the reason a follow is happening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowType {
    /// We are *not* following but want to compute the would-be target URL
    /// (e.g. `CURLOPT_FOLLOWLOCATION` is off, or the cap was hit).
    Fake,
    /// A retry of the same logical request (e.g. connection re-use failed); the
    /// "redirect" target is the same URL.
    Retry,
    /// A genuine `3xx` (or `401`/`407` auth) redirect.
    Redir,
}

/// The HTTP request method, matching curl's `Curl_HttpReq` enum (the only
/// methods the redirect rewrite logic distinguishes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// `GET` (also covers `HEAD`-via-`GET` once `CURLOPT_NOBODY` is applied).
    Get,
    /// `POST` with a raw body.
    Post,
    /// `POST` built from an `application/x-www-form-urlencoded` form.
    PostForm,
    /// `POST` built from a multipart MIME structure.
    PostMime,
    /// `PUT`.
    Put,
    /// `HEAD`.
    Head,
}

impl HttpMethod {
    /// `true` for the three POST flavors curl groups together when deciding
    /// whether a 301/302/303 must downgrade to `GET`.
    #[must_use]
    pub fn is_post_family(self) -> bool {
        matches!(
            self,
            HttpMethod::Post | HttpMethod::PostForm | HttpMethod::PostMime
        )
    }
}

/// `CURLOPT_POSTREDIR` flags: keep the original method (instead of switching to
/// `GET`) on the respective redirect status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PostRedir {
    /// Keep `POST` on a `301 Moved Permanently`.
    pub post301: bool,
    /// Keep `POST` on a `302 Found`.
    pub post302: bool,
    /// Keep `POST` on a `303 See Other`.
    pub post303: bool,
}

/// Redirect-relevant options, drawn from the easy handle's `set` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectConfig {
    /// `CURLOPT_MAXREDIRS`; `-1` means unlimited.
    pub maxredirs: i64,
    /// `CURLOPT_POSTREDIR` flags.
    pub post_redir: PostRedir,
    /// `CURLOPT_AUTOREFERER`: set `Referer:` to the previous URL on each follow.
    pub auto_referer: bool,
    /// `CURLOPT_PATH_AS_IS`: do not squash `..`/`.` path segments.
    pub path_as_is: bool,
    /// `CURLOPT_UNRESTRICTED_AUTH`: keep credentials across host/port/scheme.
    pub allow_auth_to_other_hosts: bool,
}

impl Default for RedirectConfig {
    fn default() -> Self {
        RedirectConfig {
            maxredirs: -1,
            post_redir: PostRedir::default(),
            auto_referer: false,
            path_as_is: false,
            allow_auth_to_other_hosts: false,
        }
    }
}

/// Mutable redirect bookkeeping advanced across follows (curl's `data->state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirectState {
    /// Number of redirects followed so far (`state.followlocation`).
    pub followlocation: i64,
    /// Number of real requests issued (`state.requests`).
    pub requests: i64,
    /// Whether a custom port from the original URL may still be used
    /// (`state.allow_port`); cleared once an absolute redirect is followed.
    pub allow_port: bool,
}

impl Default for RedirectState {
    fn default() -> Self {
        RedirectState {
            followlocation: 0,
            requests: 0,
            allow_port: true,
        }
    }
}

/// Connection facts needed to decide whether credentials must be cleared on a
/// redirect (curl reads these from `data->info`/`data->set`).
#[derive(Debug, Clone, Copy)]
pub struct RedirectAuthContext<'a> {
    /// `CURLOPT_UNRESTRICTED_AUTH`: when `true`, credentials are never cleared.
    pub allow_auth_to_other_hosts: bool,
    /// `CURLOPT_PORT` (`None`/`0` = not set); used only when `allow_port`.
    pub use_port: Option<u16>,
    /// The current connection's remote port (`info.conn_remote_port`).
    pub conn_remote_port: i32,
    /// The current connection's scheme, e.g. `"https"` (`info.conn_scheme`).
    pub conn_scheme: &'a str,
}

/// The result of [`follow`] when a redirect is genuinely taken.
#[derive(Debug, Clone)]
pub struct FollowResult {
    /// The resolved absolute target URL handle to adopt as the new current URL.
    pub url: CurlUrl,
    /// The resolved target URL as a string (curl's `state.url`).
    pub url_str: String,
    /// The method to use for the next request after applying the rewrite rules.
    pub method: HttpMethod,
    /// `true` if the method was downgraded to `GET` (affects how a failed upload
    /// rewind is handled: only a non-switch failure aborts the follow).
    pub switched_to_get: bool,
    /// `true` if a custom port must not be carried to the next request.
    pub disallow_port: bool,
    /// The computed auto-referer (`CURLOPT_AUTOREFERER`), if enabled.
    pub referer: Option<String>,
    /// `true` if stored credentials must be cleared before the next request
    /// (redirect crosses to a different port or scheme).
    pub clear_auth: bool,
}

/// The outcome of [`follow`].
///
/// The [`Follow`](FollowOutcome::Follow) payload is boxed because
/// [`FollowResult`] (which owns a [`CurlUrl`] plus several strings) is an order
/// of magnitude larger than the other variants; boxing keeps the enum compact
/// for the common non-follow outcomes.
#[derive(Debug, Clone)]
pub enum FollowOutcome {
    /// Issue another request against [`FollowResult::url`].
    Follow(Box<FollowResult>),
    /// Following is disabled: record the would-be target but do not follow.
    Fake {
        /// The URL we *would* have redirected to (curl's `info.wouldredirect`).
        would_redirect: String,
    },
    /// The `maxredirs` cap was reached — the transfer must fail with
    /// [`CurlError::TooManyRedirects`].
    TooManyRedirects {
        /// The URL we *would* have redirected to, recorded before failing.
        would_redirect: String,
    },
}

/// Map a URL-API error to the `CURLcode` curl uses (`Curl_uc_to_curlcode` in
/// `lib/url.c`): out-of-memory and the two "scheme"/"user" cases keep their
/// dedicated codes; everything else collapses to `CURLE_URL_MALFORMAT`.
#[must_use]
pub fn uc_to_curlcode(uc: CurlUError) -> CurlError {
    match uc {
        CurlUError::OutOfMemory => CurlError::OutOfMemory,
        CurlUError::UnsupportedScheme => CurlError::UnsupportedProtocol,
        CurlUError::UserNotAllowed => CurlError::LoginDenied,
        _ => CurlError::UrlMalformat,
    }
}

/// Decide the request method for the next hop given the redirect `status` and
/// the current `method`, applying curl's `http_switch_to_get` rules and the
/// `CURLOPT_POSTREDIR` overrides. Returns `(new_method, switched_to_get)`.
///
/// * `301`/`302`: a POST-family method becomes `GET` unless the matching
///   `post301`/`post302` override is set.
/// * `303`: any non-`GET` method becomes `GET`, except a POST-family method when
///   `post303` is set.
/// * all other codes (incl. `300`, `304`, `305`, `306`, `307`, `401`, `407`):
///   the method is unchanged.
#[must_use]
pub fn redirect_method(status: i32, method: HttpMethod, pr: &PostRedir) -> (HttpMethod, bool) {
    match status {
        301 => {
            if method.is_post_family() && !pr.post301 {
                (HttpMethod::Get, true)
            } else {
                (method, false)
            }
        }
        302 => {
            if method.is_post_family() && !pr.post302 {
                (HttpMethod::Get, true)
            } else {
                (method, false)
            }
        }
        303 => {
            // Switch to GET for any non-GET method, unless it is a POST kept by
            // CURLOPT_POSTREDIR(post303).
            if method != HttpMethod::Get && (!method.is_post_family() || !pr.post303) {
                (HttpMethod::Get, true)
            } else {
                (method, false)
            }
        }
        _ => (method, false),
    }
}

/// `Curl_is_absolute_url(url, NULL, 0, FALSE)`: a URL is absolute when it starts
/// with `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` followed by `':'`
/// (RFC 3986 §3.1), within `MAX_SCHEME_LEN`.
fn is_absolute_url(url: &str) -> bool {
    const MAX_SCHEME_LEN: usize = 40;
    let b = url.as_bytes();
    if b.is_empty() || !b[0].is_ascii_alphabetic() {
        return false;
    }
    let mut i = 1usize;
    while i < MAX_SCHEME_LEN && i < b.len() {
        let c = b[i];
        if c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.' {
            i += 1;
        } else {
            break;
        }
    }
    i < b.len() && b[i] == b':'
}

/// Build the auto-referer for the next request: the current URL with its
/// fragment and credentials stripped (`Curl_http_follow`'s auto-referer block).
fn build_referer(base: &CurlUrl) -> Result<String> {
    let mut u = base.dup();
    u.set(CurlUPart::Fragment, None, 0)
        .map_err(uc_to_curlcode)?;
    u.set(CurlUPart::User, None, 0).map_err(uc_to_curlcode)?;
    u.set(CurlUPart::Password, None, 0)
        .map_err(uc_to_curlcode)?;
    u.get(CurlUPart::Url, 0).map_err(uc_to_curlcode)
}

/// Decide whether stored credentials must be cleared because the redirect
/// crosses to a different port or scheme (the auth-clearing block of
/// `Curl_http_follow`). Returns `false` immediately when
/// `CURLOPT_UNRESTRICTED_AUTH` is set.
fn should_clear_auth(
    resolved: &CurlUrl,
    ctx: &RedirectAuthContext<'_>,
    allow_port: bool,
) -> Result<bool> {
    if ctx.allow_auth_to_other_hosts {
        return Ok(false);
    }

    // Determine the redirect target's effective port.
    let port: i32 = match ctx.use_port.filter(|&p| p != 0 && allow_port) {
        Some(p) => i32::from(p),
        None => {
            let portnum = resolved
                .get(CurlUPart::Port, CURLU_DEFAULT_PORT)
                .map_err(uc_to_curlcode)?;
            portnum.parse::<i32>().unwrap_or(0)
        }
    };

    if port != ctx.conn_remote_port {
        return Ok(true);
    }

    // Same port: a scheme change also clears auth. curl compares protocol bits;
    // comparing the scheme name case-insensitively is equivalent for the
    // distinct schemes that matter (e.g. http vs https).
    let scheme = resolved.get(CurlUPart::Scheme, 0).map_err(uc_to_curlcode)?;
    Ok(!scheme.eq_ignore_ascii_case(ctx.conn_scheme))
}

/// The incoming-redirect inputs to [`follow`], grouped into one value so the
/// function's policy/state/auth parameters stay readable (and under clippy's
/// argument-count threshold). All fields are cheap (shared refs / `Copy`
/// scalars), so this is itself `Copy`.
#[derive(Debug, Clone, Copy)]
pub struct FollowRequest<'a> {
    /// The current URL handle (curl's `state.uh`) the `Location` resolves
    /// against.
    pub base: &'a CurlUrl,
    /// The raw `Location` header value to follow.
    pub newurl: &'a str,
    /// Why the follow is happening (genuine redirect, retry, or fake compute).
    pub ftype: FollowType,
    /// The response status code driving the method-rewrite rules.
    pub status: i32,
    /// The current request method (before any rewrite).
    pub method: HttpMethod,
}

/// Resolve the `Location` against the current URL and decide how to follow it —
/// the Rust port of `Curl_http_follow`.
///
/// `req` bundles the current URL, the raw `Location`, the follow type, the
/// response status and the current method. `cfg`/`state` carry the redirect
/// options and mutable bookkeeping (both advanced in place), and `auth_ctx`
/// supplies the connection facts for credential clearing.
///
/// The caller is responsible for the request rewind (`crate::request`
/// soft-reset) and for adopting [`FollowResult::url`]; on a `GET` downgrade a
/// failed rewind is tolerated, otherwise it must abort the follow.
pub fn follow(
    req: &FollowRequest<'_>,
    cfg: &RedirectConfig,
    state: &mut RedirectState,
    auth_ctx: &RedirectAuthContext<'_>,
) -> Result<FollowOutcome> {
    let FollowRequest {
        base,
        newurl,
        ftype,
        status,
        method,
    } = *req;
    let mut ftype = ftype;
    let mut reached_max = false;
    let mut referer = None;

    if ftype != FollowType::Fake {
        state.requests += 1;
    }

    if ftype == FollowType::Redir {
        if cfg.maxredirs != -1 && state.followlocation >= cfg.maxredirs {
            reached_max = true;
            // Switch to FAKE so we still compute (and record) the target URL.
            ftype = FollowType::Fake;
        } else {
            state.followlocation += 1;
            if cfg.auto_referer {
                referer = Some(build_referer(base)?);
            }
        }
    }

    // An absolute redirect that is not a 401/407 auth reload must not carry a
    // custom port to the next request.
    let disallow_port =
        ftype != FollowType::Retry && status != 401 && status != 407 && is_absolute_url(newurl);

    // URL-resolution flags differ by follow type (note: FAKE uses ONLY
    // NON_SUPPORT_SCHEME — not ALLOW_SPACE — matching curl's flag precedence).
    let path_as_is = if cfg.path_as_is { CURLU_PATH_AS_IS } else { 0 };
    let flags = match ftype {
        FollowType::Fake => CURLU_NON_SUPPORT_SCHEME,
        FollowType::Redir => CURLU_URLENCODE | CURLU_ALLOW_SPACE | path_as_is,
        FollowType::Retry => CURLU_ALLOW_SPACE | path_as_is,
    };

    // Resolve. On a parse failure: OOM (or any non-FAKE failure) is fatal;
    // a FAKE non-OOM failure falls back to duplicating the target verbatim.
    let resolved = match base.resolve(newurl, flags) {
        Ok(u) => Some(u),
        Err(uc) => {
            if matches!(uc, CurlUError::OutOfMemory) || ftype != FollowType::Fake {
                return Err(uc_to_curlcode(uc));
            }
            None
        }
    };

    let (resolved_url, follow_url_str) = match resolved {
        Some(u) => {
            let s = u.get(CurlUPart::Url, 0).map_err(uc_to_curlcode)?;
            (Some(u), s)
        }
        None => (None, newurl.to_string()),
    };

    // Credential clearing is computed only for a real follow with a parsed URL.
    let mut clear_auth = false;
    if ftype != FollowType::Fake {
        if let Some(ref u) = resolved_url {
            clear_auth = should_clear_auth(u, auth_ctx, state.allow_port)?;
        }
    }

    if ftype == FollowType::Fake {
        if reached_max {
            return Ok(FollowOutcome::TooManyRedirects {
                would_redirect: follow_url_str,
            });
        }
        return Ok(FollowOutcome::Fake {
            would_redirect: follow_url_str,
        });
    }

    if disallow_port {
        state.allow_port = false;
    }

    let (new_method, switched_to_get) = redirect_method(status, method, &cfg.post_redir);

    Ok(FollowOutcome::Follow(Box::new(FollowResult {
        url: resolved_url.expect("a non-FAKE follow always has a resolved URL"),
        url_str: follow_url_str,
        method: new_method,
        switched_to_get,
        disallow_port,
        referer,
        clear_auth,
    })))
}

// ===========================================================================
// Speed / time limits and retry (lib/transfer.c)
// ===========================================================================

/// The transfer-level limits checked on every drive iteration (`Curl_sendrecv`
/// / `Curl_pgrsCheck`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransferLimits {
    /// The absolute deadline derived from `CURLOPT_TIMEOUT[_MS]`; `None` ⇒ no
    /// overall timeout.
    pub deadline: Option<Instant>,
    /// `CURLOPT_LOW_SPEED_LIMIT` in bytes/second; `0` disables the check.
    pub low_speed_limit: i64,
    /// `CURLOPT_LOW_SPEED_TIME` in seconds — how long the rate may stay below
    /// `low_speed_limit` before the transfer is aborted.
    pub low_speed_time: u32,
}

/// Time remaining until `deadline` (`Curl_timeleft`). `None` ⇒ no deadline;
/// `Some(Duration::ZERO)` ⇒ the deadline has arrived or passed.
#[must_use]
pub fn time_left(deadline: Option<Instant>, now: Instant) -> Option<Duration> {
    deadline.map(|d| d.saturating_duration_since(now))
}

/// Whether the overall deadline has elapsed (curl's `Curl_timeleft_ms() < 0`).
/// A deadline exactly equal to `now` is *not* yet timed out, matching curl's
/// strict "less than zero" test.
#[must_use]
pub fn is_timed_out(deadline: Option<Instant>, now: Instant) -> bool {
    match deadline {
        Some(d) => now > d,
        None => false,
    }
}

/// The end-of-transfer short-read check (`Curl_sendrecv`'s `CURLE_PARTIAL_FILE`
/// branch): when a body is expected, its size is known, the redirect chain is
/// over (`!newurl`), and fewer bytes than announced were received, the transfer
/// closed prematurely.
///
/// `size` follows curl's convention: `None` or a negative value means "size
/// unknown" and disables the check.
pub fn check_partial_file(
    no_body: bool,
    size: Option<i64>,
    bytecount: u64,
    has_newurl: bool,
) -> Result<()> {
    if no_body || has_newurl {
        return Ok(());
    }
    if let Some(sz) = size {
        if sz >= 0 && bytecount != sz as u64 {
            return Err(CurlError::PartialFile);
        }
    }
    Ok(())
}

/// The delay an active rate limit (`CURLOPT_MAX_RECV/SEND_SPEED_LARGE`) demands
/// before the next I/O in direction `dir`, given the bytes transferred so far.
/// `Duration::ZERO` means "proceed now". The driver awaits this on a Tokio timer
/// — the asynchronous equivalent of curl's `Curl_pgrsLimitWaitTime` throttling.
#[must_use]
pub fn rate_limit_delay(
    limit: &mut RateLimit,
    dir: Direction,
    transferred: u64,
    now: Instant,
) -> Duration {
    limit.wait_time(dir, transferred, now)
}

/// Inputs to [`retry_request`], gathered from the connection, request and
/// transfer state (`Curl_retry_request` in `lib/transfer.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryConfig {
    /// `state.upload`: this is an upload transfer.
    pub upload: bool,
    /// The connection's protocol is in the HTTP family (`PROTO_FAMILY_HTTP`).
    pub is_http_family: bool,
    /// The connection's protocol is RTSP (`CURLPROTO_RTSP`); together with
    /// `is_http_family` it gates whether an *upload* may be retried.
    pub is_rtsp: bool,
    /// `rtspreq == RTSPREQ_RECEIVE`; such RTSP requests are never retried.
    pub rtsp_receive: bool,
    /// `conn->bits.reuse`: the connection was taken from the pool.
    pub conn_reuse: bool,
    /// `bytecount + headerbytecount == 0`: nothing at all was received yet.
    pub data_counters_zero: bool,
    /// `req.no_body`: no response body is expected.
    pub no_body: bool,
    /// `req.done`: the request already completed.
    pub done: bool,
    /// `state.refused_stream`: an HTTP/2 `REFUSED_STREAM` was seen.
    pub refused_stream: bool,
}

/// The decision returned by [`retry_request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Re-issue the same request on a fresh connection. The caller must close
    /// and re-open the connection, mark it as a retry, and rewind the upload
    /// reader (curl always sets the rewind flag on a retry).
    Retry,
    /// Do not retry; proceed with the result as-is.
    NoRetry,
}

/// Decide whether a request that produced no data should be retried on a fresh
/// connection — the Rust port of `Curl_retry_request`.
///
/// `retrycount` is the transfer's running retry counter (curl's
/// `state.retrycount`); it is advanced in place. Exceeding [`CONN_MAX_RETRIES`]
/// fails the transfer with [`CurlError::SendError`] ("Connection died, tried 5
/// times before giving up") and resets the counter.
pub fn retry_request(cfg: &RetryConfig, retrycount: &mut u32) -> Result<RetryDecision> {
    // Uploads can only be retried for HTTP/RTSP (where a response still comes
    // back); other upload protocols never retry here.
    if cfg.upload && !(cfg.is_http_family || cfg.is_rtsp) {
        return Ok(RetryDecision::NoRetry);
    }

    let reuse_retry = cfg.conn_reuse
        && cfg.data_counters_zero
        && ((!cfg.no_body && !cfg.done) || cfg.is_http_family)
        && !cfg.rtsp_receive;

    let retry = if reuse_retry {
        true
    } else {
        // A refused HTTP/2 stream is safe to replay only if nothing was read.
        cfg.refused_stream && cfg.data_counters_zero
    };

    if retry {
        // curl: `if (retrycount++ >= CONN_MAX_RETRIES) { reset; fail }`.
        if *retrycount >= CONN_MAX_RETRIES {
            *retrycount = 0;
            return Err(CurlError::SendError);
        }
        *retrycount += 1;
        return Ok(RetryDecision::Retry);
    }
    Ok(RetryDecision::NoRetry)
}

// ===========================================================================
// Progress driving + post-transfer info recording (lib/transfer.c + progress.c)
// ===========================================================================

/// The post-transfer info the engine records for `curl_easy_getinfo` — the
/// subset of curl's `data->info` that the transfer loop fills in. Owned by the
/// handle (the FFI/`getinfo` layer reads it); kept here so the engine can
/// populate it without depending on the not-yet-authored `crate::getinfo`.
#[derive(Debug, Clone)]
pub struct TransferInfo {
    /// `CURLINFO_RESPONSE_CODE` — the last response status code.
    pub response_code: i64,
    /// The negotiated HTTP version (`CURLINFO_HTTP_VERSION`), curl's `httpversion`.
    pub http_version: u8,
    /// `CURLINFO_REDIRECT_COUNT` — number of redirects followed.
    pub redirect_count: i64,
    /// `CURLINFO_REDIRECT_URL` — the target a final un-followed redirect points
    /// to (curl's `info.wouldredirect`).
    pub redirect_url: Option<String>,
    /// `CURLINFO_EFFECTIVE_URL` — the URL of the last request actually made.
    pub effective_url: Option<String>,
    /// `CURLINFO_SIZE_DOWNLOAD_T` — bytes downloaded.
    pub size_download: i64,
    /// `CURLINFO_SIZE_UPLOAD_T` — bytes uploaded.
    pub size_upload: i64,
    /// `CURLINFO_SPEED_DOWNLOAD_T` — average download speed (bytes/s).
    pub speed_download: i64,
    /// `CURLINFO_SPEED_UPLOAD_T` — average upload speed (bytes/s).
    pub speed_upload: i64,
    /// `CURLINFO_TOTAL_TIME[_T]`.
    pub total_time: TimerData,
    /// `CURLINFO_NAMELOOKUP_TIME[_T]`.
    pub namelookup_time: TimerData,
    /// `CURLINFO_CONNECT_TIME[_T]`.
    pub connect_time: TimerData,
    /// `CURLINFO_APPCONNECT_TIME[_T]`.
    pub appconnect_time: TimerData,
    /// `CURLINFO_PRETRANSFER_TIME[_T]`.
    pub pretransfer_time: TimerData,
    /// `CURLINFO_STARTTRANSFER_TIME[_T]`.
    pub starttransfer_time: TimerData,
    /// `CURLINFO_REDIRECT_TIME[_T]`.
    pub redirect_time: TimerData,
}

impl TransferInfo {
    /// A fresh, all-zero info store.
    #[must_use]
    pub fn new() -> Self {
        TransferInfo {
            response_code: 0,
            http_version: 0,
            redirect_count: 0,
            redirect_url: None,
            effective_url: None,
            size_download: 0,
            size_upload: 0,
            speed_download: 0,
            speed_upload: 0,
            total_time: TimerData::zero(),
            namelookup_time: TimerData::zero(),
            connect_time: TimerData::zero(),
            appconnect_time: TimerData::zero(),
            pretransfer_time: TimerData::zero(),
            starttransfer_time: TimerData::zero(),
            redirect_time: TimerData::zero(),
        }
    }

    /// Snapshot the size, speed and timing milestones from `progress` into this
    /// store — the post-transfer `data->info` recording done at the end of a
    /// transfer (`Curl_pgrsUpdate` feeds these from `data->progress`).
    pub fn record_progress(&mut self, progress: &Progress) {
        self.size_download = progress.download_size();
        self.size_upload = progress.upload_size();
        self.speed_download = progress.download_speed();
        self.speed_upload = progress.upload_speed();
        self.total_time = progress.total_time();
        self.namelookup_time = progress.namelookup_time();
        self.connect_time = progress.connect_time();
        self.appconnect_time = progress.appconnect_time();
        self.pretransfer_time = progress.pretransfer_time();
        self.starttransfer_time = progress.starttransfer_time();
        self.redirect_time = progress.redirect_time();
    }
}

impl Default for TransferInfo {
    fn default() -> Self {
        TransferInfo::new()
    }
}

/// Record a redirect milestone and reset the per-hop transfer sizes — the exact
/// tail of `Curl_http_follow` (`Curl_pgrsTime(TIMER_REDIRECT)` followed by
/// `Curl_pgrsResetTransferSizes`). Call this when a follow is accepted, before
/// re-driving the transfer for the next hop.
pub fn mark_redirect(progress: &mut Progress, now: Instant) {
    progress.time(Timer::Redirect, now);
    progress.reset_transfer_sizes();
}

/// Drive one progress tick: update the meter / invoke the user progress callback
/// and enforce the low-speed limit — curl's `Curl_pgrsUpdate` + `Curl_pgrsCheck`
/// performed once per drive iteration.
///
/// Returns whether the progress meter should be drawn (curl's `showprogress`).
///
/// # Errors
///
/// Propagates [`CurlError::AbortedByCallback`] when the user callback aborts and
/// [`CurlError::OperationTimedout`] when the low-speed limit has been violated
/// for longer than [`TransferLimits::low_speed_time`].
pub fn progress_tick(
    progress: &mut Progress,
    now: Instant,
    req_done: bool,
    paused: bool,
    limits: &TransferLimits,
    cb: Option<ProgressCallbackRef<'_>>,
) -> Result<bool> {
    progress.check(
        now,
        req_done,
        paused,
        limits.low_speed_limit,
        limits.low_speed_time,
        cb,
    )
}

// ===========================================================================
// Messaging — Curl_infof / Curl_failf (lib/curl_trc.c) + last-error storage
// ===========================================================================

/// The per-handle diagnostic sink: curl's verbose info channel (`Curl_infof`)
/// and the failure-message latch (`Curl_failf` → `CURLOPT_ERRORBUFFER` /
/// `data->state.errorbuf`).
///
/// curl's `Curl_failf` captures the **first** failure message into the user's
/// error buffer and latches `data->state.errorbuf`, so subsequent `failf` calls
/// for the same transfer do *not* overwrite it; when verbose it additionally
/// emits the line on the trace channel. `Curl_infof` only emits — and only when
/// verbose — and never touches the error buffer. `Curl_reset_fail` clears the
/// latch. This struct reproduces exactly those three behaviors:
///
/// * the captured first failure string is the value `curl-rs-ffi` copies into
///   `CURLOPT_ERRORBUFFER` and that `crate::getinfo` surfaces, and it is
///   captured regardless of verbosity (curl captures whenever an error buffer is
///   set, independent of `CURLOPT_VERBOSE`);
/// * the verbose trace channel maps to the [`tracing`] crate (the engine's
///   logging substrate, AAP §0.6.1) — `infof` at `debug` level and `failf` at
///   `warn` level, both on the `curl::text` target (curl's `CURLINFO_TEXT`).
///
/// curl requires that `failf`/`infof` messages contain no `\n`/`\r`; that
/// invariant is asserted in debug builds.
#[derive(Debug, Default, Clone)]
pub struct ErrorBuffer {
    /// `CURLOPT_VERBOSE`: whether messages are emitted on the trace channel.
    verbose: bool,
    /// The captured first failure message (without a trailing newline), if any.
    error: Option<String>,
    /// Whether the first failure has been latched (curl's `state.errorbuf`).
    latched: bool,
}

impl ErrorBuffer {
    /// A fresh, non-verbose sink with no captured error.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A sink with the given verbosity (`CURLOPT_VERBOSE`).
    #[must_use]
    pub fn with_verbose(verbose: bool) -> Self {
        Self {
            verbose,
            error: None,
            latched: false,
        }
    }

    /// Set verbose mode (`CURLOPT_VERBOSE`).
    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    /// Whether verbose tracing is enabled.
    #[must_use]
    pub fn is_verbose(&self) -> bool {
        self.verbose
    }

    /// Emit an informational message (`Curl_infof`): written on the verbose
    /// trace channel only, never captured into the error buffer. The message
    /// must not contain a newline (curl's invariant).
    ///
    /// Callers pass [`std::fmt::Arguments`] (via [`format_args!`]) so the message
    /// is formatted lazily — nothing is allocated when not verbose, matching
    /// curl's early-out.
    pub fn infof(&self, args: std::fmt::Arguments<'_>) {
        if self.verbose {
            let msg = args.to_string();
            debug_assert!(
                !msg.contains('\n') && !msg.contains('\r'),
                "infof message must not contain CR/LF"
            );
            tracing::debug!(target: "curl::text", "{msg}");
        }
    }

    /// Record a failure message (`Curl_failf`): the **first** message latches
    /// into the captured error (later calls do not overwrite, matching
    /// `data->state.errorbuf`); when verbose it is also emitted on the trace
    /// channel. The message must not contain a newline.
    ///
    /// The capture happens regardless of verbosity, mirroring curl, which writes
    /// into `CURLOPT_ERRORBUFFER` whenever one is set.
    pub fn failf(&mut self, args: std::fmt::Arguments<'_>) {
        let msg = args.to_string();
        debug_assert!(
            !msg.contains('\n') && !msg.contains('\r'),
            "failf message must not contain CR/LF"
        );
        if self.verbose {
            tracing::warn!(target: "curl::text", "{msg}");
        }
        if !self.latched {
            self.error = Some(msg);
            self.latched = true;
        }
    }

    /// Clear the captured failure latch (`Curl_reset_fail`), so the next
    /// [`failf`](Self::failf) will capture afresh.
    pub fn reset(&mut self) {
        self.error = None;
        self.latched = false;
    }

    /// The captured failure message, if any — the `CURLOPT_ERRORBUFFER` value.
    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Whether a failure message has been latched.
    #[must_use]
    pub fn has_error(&self) -> bool {
        self.latched
    }
}

/// Emit curl's "operation timed out" failure (`lib/transfer.c`), byte-for-byte:
/// with a known body size the message reports `… with N out of M bytes
/// received`, otherwise `… with N bytes received`.
pub fn emit_timeout(errbuf: &mut ErrorBuffer, elapsed_ms: i64, bytecount: u64, size: Option<i64>) {
    match size {
        Some(sz) => errbuf.failf(format_args!(
            "Operation timed out after {elapsed_ms} milliseconds with {bytecount} out of {sz} bytes received"
        )),
        None => errbuf.failf(format_args!(
            "Operation timed out after {elapsed_ms} milliseconds with {bytecount} bytes received"
        )),
    }
}

/// Emit curl's partial-transfer failure (`lib/transfer.c`): `transfer closed
/// with R bytes remaining to read`, where `R = size - bytecount`.
pub fn emit_partial_file(errbuf: &mut ErrorBuffer, remaining: i64) {
    errbuf.failf(format_args!(
        "transfer closed with {remaining} bytes remaining to read"
    ));
}

/// Emit curl's exhausted-retry failure (`lib/transfer.c` `Curl_retry_request`):
/// `Connection died, tried 5 times before giving up` (the literal
/// [`CONN_MAX_RETRIES`], not the running counter).
pub fn emit_retry_exhausted(errbuf: &mut ErrorBuffer) {
    errbuf.failf(format_args!(
        "Connection died, tried {CONN_MAX_RETRIES} times before giving up"
    ));
}

/// Emit curl's "retrying a fresh connect" info line (`lib/transfer.c`): used
/// when a reused connection died and the request is being replayed.
pub fn emit_retry_fresh_connect(errbuf: &ErrorBuffer, retrycount: u32) {
    errbuf.infof(format_args!(
        "Connection died, retrying a fresh connect (retry count: {retrycount})"
    ));
}

/// Emit curl's `REFUSED_STREAM` info line (`lib/transfer.c`): an HTTP/2 refused
/// stream is being replayed on a fresh connect.
pub fn emit_refused_stream_retry(errbuf: &ErrorBuffer) {
    errbuf.infof(format_args!("REFUSED_STREAM, retrying a fresh connect"));
}

/// Emit curl's too-many-redirects failure (`lib/http.c` `Curl_http_follow`):
/// `Maximum (N) redirects followed`, where `N` is `CURLOPT_MAXREDIRS`.
pub fn emit_too_many_redirects(errbuf: &mut ErrorBuffer, maxredirs: i64) {
    errbuf.failf(format_args!("Maximum ({maxredirs}) redirects followed"));
}

// ===========================================================================
// Collaborator contracts (dependency inversion — see the module docs)
// ===========================================================================

/// A byte-level transport — the contract the connection layer (`crate::conn`,
/// authored in a later migration step) provides to the engine. Defined here so
/// the engine depends on *what* it needs, not on a not-yet-existing module.
///
/// This is the low-level analog of curl's connection-filter chain: a duplex
/// stream of bytes. Protocol handlers are built on top of it (see
/// [`ProtocolExchange`]).
#[allow(async_fn_in_trait)]
pub trait Connection {
    /// Read up to `buf.len()` bytes from the connection; `Ok(0)` means the peer
    /// closed the stream.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Write `data` to the connection, returning the number of bytes accepted.
    async fn send(&mut self, data: &[u8]) -> Result<usize>;
}

/// One event produced by a protocol handler as it drives a response, abstracting
/// over HTTP/1.1, HTTP/2, HTTP/3 and the non-HTTP protocols (curl's
/// `Curl_xfer_write_resp` delivers the analogous header/body stream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseEvent {
    /// The response status / first line is available (HTTP status code, or a
    /// protocol-specific status mapped to one).
    Status(i32),
    /// A single header line (raw bytes, including any trailing CRLF) to be
    /// delivered on the header stream.
    Header(Vec<u8>),
    /// All headers have been received.
    HeadersComplete {
        /// The announced body length (`Content-Length`), if known.
        content_length: Option<i64>,
        /// The `Content-Encoding`/`Transfer-Encoding` value to decode the body
        /// with, if any.
        content_encoding: Option<String>,
    },
    /// A chunk of (still-encoded) response body.
    Body(Vec<u8>),
    /// The response is complete — no more events follow.
    End,
}

/// A protocol exchange — the contract a protocol handler (`crate::protocols`,
/// authored later) implements so the engine can drive it. The engine pulls
/// [`ResponseEvent`]s and pushes request-body bytes, staying oblivious to the
/// specific protocol.
#[allow(async_fn_in_trait)]
pub trait ProtocolExchange {
    /// Produce the next response event. Returning [`ResponseEvent::End`] (or any
    /// later call after it) signals completion.
    async fn next_event(&mut self) -> Result<ResponseEvent>;

    /// Send a chunk of request body, returning the number of bytes accepted
    /// (which may be fewer than offered for flow-controlled protocols).
    async fn send_body(&mut self, data: &[u8]) -> Result<usize>;
}

/// The disjoint set of mutable borrows the byte-loop driver operates on, bundled
/// into one value so a [`TransferHandle`] can hand them over without tripping the
/// borrow checker (one `&mut self` projection yields all of them at once).
pub struct TransferParts<'a, P: ProtocolExchange> {
    /// The protocol handler being driven.
    pub exchange: &'a mut P,
    /// The per-request state object the loop advances (`crate::request`).
    pub request: &'a mut Request,
    /// The progress meter / accounting (`crate::progress`).
    pub progress: &'a mut Progress,
    /// The client-writer chain delivering body/header bytes to the user.
    pub writer: &'a mut ClientWriter,
    /// The user's body/header output callbacks.
    pub write_cb: &'a mut dyn WriteCallbacks,
    /// The active speed/time limits.
    pub limits: &'a TransferLimits,
    /// The diagnostic sink (`Curl_infof`/`Curl_failf` + the error-buffer latch).
    pub errbuf: &'a mut ErrorBuffer,
}

// ===========================================================================
// The async byte-loop driver (lib/transfer.c `Curl_sendrecv` / `Curl_readwrite`)
// ===========================================================================

/// Drive a single transfer's response to completion: pull [`ResponseEvent`]s
/// from the protocol, route header/body bytes through the [`ClientWriter`] chain,
/// advance the request counters and progress meter, enforce the overall timeout
/// and (optionally) the download rate limit, and finalize with the short-read
/// (`CURLE_PARTIAL_FILE`) check.
///
/// This is the asynchronous reimagining of curl's `Curl_sendrecv`/`Curl_readwrite`
/// loop: instead of `select`/`poll` over sockets it awaits protocol events, but
/// the per-iteration bookkeeping (timeout, progress, low-speed abort, body
/// delivery, end-of-stream flush) is preserved.
///
/// `progress_cb` is the optional `CURLOPT_XFERINFOFUNCTION` adapter; `rate_limit`
/// applies `CURLOPT_MAX_RECV_SPEED_LARGE` throttling via a Tokio timer.
///
/// # Errors
///
/// Surfaces any [`CurlError`] from the protocol, the client-writer chain
/// (`WriteError`/`TooLarge`), the progress checks (`AbortedByCallback`,
/// `OperationTimedout`), or the final short-read check (`PartialFile`).
pub async fn drive_transfer<P: ProtocolExchange>(
    parts: TransferParts<'_, P>,
    mut progress_cb: Option<&mut dyn FnMut(i64, i64, i64, i64) -> i32>,
    mut rate_limit: Option<&mut RateLimit>,
) -> Result<()> {
    let TransferParts {
        exchange,
        request,
        progress,
        writer,
        write_cb,
        limits,
        errbuf,
    } = parts;

    // The wall-clock start of this single transfer, for the timeout message's
    // elapsed-milliseconds figure (curl reads `progress.t_startsingle`).
    let started = Instant::now();

    loop {
        let now = Instant::now();
        // Overall transfer timeout (CURLOPT_TIMEOUT). curl emits a precise
        // failure line naming the elapsed time and how much was received.
        if is_timed_out(limits.deadline, now) {
            let elapsed_ms = now.saturating_duration_since(started).as_millis() as i64;
            emit_timeout(errbuf, elapsed_ms, request.bytecount, request.size);
            return Err(CurlError::OperationTimedout);
        }

        match exchange.next_event().await? {
            ResponseEvent::Status(code) => {
                request.httpcode = code;
            }
            ResponseEvent::Header(line) => {
                request.headerbytecount += line.len() as u64;
                writer.write(ClientWriteType::HEADER, &line, write_cb)?;
            }
            ResponseEvent::HeadersComplete {
                content_length,
                content_encoding,
            } => {
                request.size = content_length;
                if let Some(sz) = content_length {
                    progress.set_download_size(sz);
                }
                if let Some(enc) = content_encoding {
                    writer.set_content_encoding(&enc, true)?;
                }
                // Headers are finished; subsequent writes are body bytes.
                request.header = false;
            }
            ResponseEvent::Body(chunk) => {
                request.bytecount += chunk.len() as u64;
                progress.set_download_counter(request.bytecount as i64);
                writer.write(ClientWriteType::BODY, &chunk, write_cb)?;

                // Advance the progress accounting and enforce the low-speed
                // abort (Curl_pgrsUpdate + Curl_pgrsCheck). The user progress
                // callback is invoked separately just below.
                progress.check(
                    now,
                    false,
                    writer.is_paused(),
                    limits.low_speed_limit,
                    limits.low_speed_time,
                    None,
                )?;

                // CURLOPT_XFERINFOFUNCTION: invoke the user callback with the
                // current byte counts. A return other than 0 /
                // CURL_PROGRESSFUNC_CONTINUE aborts the transfer (matching
                // Progress::dispatch's contract).
                if let Some(f) = progress_cb.as_deref_mut() {
                    let dltotal = request.size.unwrap_or(0).max(0);
                    let dlnow = request.bytecount as i64;
                    let ulnow = request.writebytecount as i64;
                    let r = f(dltotal, dlnow, 0, ulnow);
                    if r != CURL_PROGRESSFUNC_CONTINUE && r != 0 {
                        return Err(CurlError::AbortedByCallback);
                    }
                }

                // Apply the receive rate cap, if any (Tokio timer).
                if let Some(rl) = rate_limit.as_deref_mut() {
                    let delay = rl.wait_time(Direction::Download, request.bytecount, now);
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                }
            }
            ResponseEvent::End => {
                // Deliver end-of-stream: flush the content decoder and the
                // terminal (possibly zero-length) body callback.
                writer.write(
                    ClientWriteType::BODY
                        .union(ClientWriteType::EOS)
                        .union(ClientWriteType::ZERO_LEN),
                    &[],
                    write_cb,
                )?;
                request.eos_written = true;
                break;
            }
        }
    }

    // End-of-transfer general check: a known-size body that arrived short (and
    // is not about to be re-requested via a redirect) is a partial transfer.
    if let Err(e) = check_partial_file(
        request.no_body,
        request.size,
        request.bytecount,
        request.newurl.is_some(),
    ) {
        if e == CurlError::PartialFile {
            // size is known here (check_partial_file only returns PartialFile
            // when size is a concrete non-negative value).
            let remaining = request.size.unwrap_or(0) - request.bytecount as i64;
            emit_partial_file(errbuf, remaining);
        }
        return Err(e);
    }
    request.done = true;

    Ok(())
}

// ===========================================================================
// Type-state transfer lifecycle (Configured → Connected → Transferring →
// Complete), per AAP §0.4.3
// ===========================================================================

/// Type-state marker: the transfer is configured but not yet connected.
#[derive(Debug)]
pub struct Configured;
/// Type-state marker: the connection is established, ready to begin.
#[derive(Debug)]
pub struct Connected;
/// Type-state marker: bytes are being moved.
#[derive(Debug)]
pub struct Transferring;
/// Type-state marker: the transfer has finished and info is recorded.
#[derive(Debug)]
pub struct Complete;

/// The owned per-transfer state advanced through the lifecycle. Held inside
/// [`Transfer`] so the type-state parameter adds compile-time ordering safety
/// without duplicating data.
#[derive(Debug)]
struct TransferData {
    request: Request,
    progress: Progress,
    info: TransferInfo,
    limits: TransferLimits,
    #[allow(dead_code)] // consumed by the handle's redirect handling via follow()
    redirect_cfg: RedirectConfig,
    redirect_state: RedirectState,
    #[allow(dead_code)] // consumed by the handle's retry handling via retry_request()
    retrycount: u32,
    /// The diagnostic sink (`Curl_infof`/`Curl_failf` + error-buffer latch).
    errbuf: ErrorBuffer,
}

/// A single transfer modelled with the **type-state pattern**: each lifecycle
/// stage is a distinct `Transfer<State>` type, and transitions consume `self`
/// and return the next stage. Driving a body before connecting, or reading info
/// before completion, is therefore a *compile error* rather than a runtime check.
///
/// # Example
///
/// ```ignore
/// let t = Transfer::new(request, limits, redirect_cfg, Instant::now())
///     .connect(Instant::now())
///     .begin_transfer(Instant::now());
/// let done = t.drive(&mut exchange, &mut writer, &mut cb, None).await?;
/// let info = done.into_info();
/// ```
pub struct Transfer<S> {
    data: TransferData,
    _state: PhantomData<S>,
}

impl Transfer<Configured> {
    /// Create a freshly configured transfer. `now` seeds the progress clock.
    #[must_use]
    pub fn new(
        request: Request,
        limits: TransferLimits,
        redirect_cfg: RedirectConfig,
        now: Instant,
    ) -> Self {
        Transfer {
            data: TransferData {
                request,
                progress: Progress::new(now),
                info: TransferInfo::new(),
                limits,
                redirect_cfg,
                redirect_state: RedirectState::default(),
                retrycount: 0,
                errbuf: ErrorBuffer::new(),
            },
            _state: PhantomData,
        }
    }

    /// Enable or disable verbose diagnostics (`CURLOPT_VERBOSE`) for this
    /// transfer's [`ErrorBuffer`]. Returns `self` for builder-style chaining.
    #[must_use]
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.data.errbuf.set_verbose(verbose);
        self
    }

    /// Transition to [`Connected`], performing curl's pre-transfer setup
    /// (`Curl_pretransfer`): mark the single-request start time and reset the
    /// per-hop transfer sizes.
    #[must_use]
    pub fn connect(mut self, now: Instant) -> Transfer<Connected> {
        self.data.progress.start_now(now);
        self.data.progress.reset_transfer_sizes();
        self.data.request.start(now);
        Transfer {
            data: self.data,
            _state: PhantomData,
        }
    }
}

impl Transfer<Connected> {
    /// Transition to [`Transferring`], recording the pre-transfer timing
    /// milestone (`Curl_pgrsTime(TIMER_PRETRANSFER)`).
    #[must_use]
    pub fn begin_transfer(mut self, now: Instant) -> Transfer<Transferring> {
        self.data.progress.time(Timer::PreTransfer, now);
        Transfer {
            data: self.data,
            _state: PhantomData,
        }
    }
}

impl Transfer<Transferring> {
    /// Drive the transfer to completion over `exchange`, delivering output
    /// through `writer`/`write_cb` and optionally invoking the `progress_cb`
    /// (`CURLOPT_XFERINFOFUNCTION`). On success, the post-transfer info is
    /// recorded and the transfer moves to [`Complete`].
    pub async fn drive<P: ProtocolExchange>(
        mut self,
        exchange: &mut P,
        writer: &mut ClientWriter,
        write_cb: &mut dyn WriteCallbacks,
        progress_cb: Option<&mut dyn FnMut(i64, i64, i64, i64) -> i32>,
    ) -> Result<Transfer<Complete>> {
        // TransferLimits is Copy; take a local copy so the immutable borrow does
        // not collide with the mutable field borrows below.
        let limits = self.data.limits;
        let parts = TransferParts {
            exchange,
            request: &mut self.data.request,
            progress: &mut self.data.progress,
            writer,
            write_cb,
            limits: &limits,
            errbuf: &mut self.data.errbuf,
        };
        drive_transfer(parts, progress_cb, None).await?;

        // Record the post-transfer info store (Curl_pgrsUpdate → data->info).
        self.data.info.record_progress(&self.data.progress);
        self.data.info.response_code = i64::from(self.data.request.httpcode);
        self.data.info.http_version = self.data.request.httpversion;
        self.data.info.redirect_count = self.data.redirect_state.followlocation;
        if self.data.info.effective_url.is_none() {
            self.data.info.redirect_url = self.data.request.newurl.clone();
        }

        Ok(Transfer {
            data: self.data,
            _state: PhantomData,
        })
    }

    /// The progress meter, for callers that drive throttling/metering directly.
    pub fn progress(&mut self) -> &mut Progress {
        &mut self.data.progress
    }
}

impl Transfer<Complete> {
    /// The recorded post-transfer info (`curl_easy_getinfo` source).
    #[must_use]
    pub fn info(&self) -> &TransferInfo {
        &self.data.info
    }

    /// Consume the completed transfer, yielding the recorded info store.
    #[must_use]
    pub fn into_info(self) -> TransferInfo {
        self.data.info
    }

    /// The final per-request state.
    #[must_use]
    pub fn request(&self) -> &Request {
        &self.data.request
    }

    /// The captured failure message, if the transfer recorded one
    /// (`CURLOPT_ERRORBUFFER`). Present even on a successful completion if a
    /// non-fatal `failf` ran earlier.
    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.data.errbuf.last_error()
    }
}

// ===========================================================================
// Handle integration entrypoint (lib/easy.c `curl_easy_perform`, lib/multi.c)
// ===========================================================================

/// The easy-handle contract the engine drives. Implemented by `crate::easy`'s
/// handle (authored later); defined here so [`run`] — shared by `Easy::perform`
/// and `Multi`'s per-handle advancement — does not depend on a not-yet-existing
/// type.
pub trait TransferHandle {
    /// The protocol handler type this handle drives.
    type Exchange: ProtocolExchange;

    /// Project the disjoint mutable borrows the driver needs from the handle in
    /// a single call (so they are provably non-overlapping).
    fn parts(&mut self) -> TransferParts<'_, Self::Exchange>;
}

/// Drive one transfer for `handle` to completion — the single entrypoint shared
/// by the synchronous `curl_easy_perform` path (via the FFI `block_on` bridge)
/// and by the multi interface's per-handle advancement.
///
/// # Errors
///
/// Propagates any [`CurlError`] from [`drive_transfer`].
pub async fn run<H: TransferHandle>(handle: &mut H) -> Result<()> {
    let parts = handle.parts();
    drive_transfer(parts, None, None).await
}

// ===========================================================================
// Tests
// ===========================================================================
//
// The engine is exercised in isolation with in-memory mock implementations of
// the collaborator traits ([`WriteCallbacks`], [`ReadCallback`],
// [`ProtocolExchange`], [`TransferHandle`]). The suite targets the coverage gate
// (AAP §0.8.1, ≥80% on the transfer engine) and the behavioral-parity
// requirements (AAP §0.8.2) for the client-writer chain, the upload reader, the
// redirect rewrite rules, the speed/time limits, the retry decision, progress
// recording, the diagnostic messages, and the type-state driver.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    // -----------------------------------------------------------------------
    // Mock client-write callbacks (CURLOPT_WRITEFUNCTION / HEADERFUNCTION)
    // -----------------------------------------------------------------------

    /// A scriptable [`WriteCallbacks`] sink that records delivered body/header
    /// bytes and can inject curl's callback sentinels at chosen call indices.
    struct CollectCb {
        body: Vec<u8>,
        headers: Vec<u8>,
        body_calls: usize,
        header_calls: usize,
        /// The length passed to each *accepted* body call (for chunking checks).
        body_chunk_lens: Vec<usize>,
        /// 1-based body-call indices that return [`CURL_WRITEFUNC_PAUSE`].
        pause_body_calls: Vec<usize>,
        /// 1-based body-call index that returns [`CURL_WRITEFUNC_ERROR`].
        error_on_body_call: Option<usize>,
        /// 1-based body-call index that returns a short (len-1) write.
        short_on_body_call: Option<usize>,
        /// `false` ⇒ `write_header` returns `None` (no header sink).
        header_sink: bool,
        /// 1-based header-call indices that return [`CURL_WRITEFUNC_PAUSE`].
        pause_header_calls: Vec<usize>,
    }

    impl CollectCb {
        fn new() -> Self {
            CollectCb {
                body: Vec::new(),
                headers: Vec::new(),
                body_calls: 0,
                header_calls: 0,
                body_chunk_lens: Vec::new(),
                pause_body_calls: Vec::new(),
                error_on_body_call: None,
                short_on_body_call: None,
                header_sink: true,
                pause_header_calls: Vec::new(),
            }
        }
    }

    impl WriteCallbacks for CollectCb {
        fn write_body(&mut self, data: &[u8]) -> usize {
            self.body_calls += 1;
            let c = self.body_calls;
            if self.error_on_body_call == Some(c) {
                return CURL_WRITEFUNC_ERROR;
            }
            if self.pause_body_calls.contains(&c) {
                return CURL_WRITEFUNC_PAUSE;
            }
            if self.short_on_body_call == Some(c) && !data.is_empty() {
                return data.len() - 1;
            }
            self.body.extend_from_slice(data);
            self.body_chunk_lens.push(data.len());
            data.len()
        }

        fn write_header(&mut self, data: &[u8]) -> Option<usize> {
            if !self.header_sink {
                return None;
            }
            self.header_calls += 1;
            let c = self.header_calls;
            if self.pause_header_calls.contains(&c) {
                return Some(CURL_WRITEFUNC_PAUSE);
            }
            self.headers.extend_from_slice(data);
            Some(data.len())
        }
    }

    // -----------------------------------------------------------------------
    // Mock read source (CURLOPT_READFUNCTION)
    // -----------------------------------------------------------------------

    /// One scripted action a [`VecReader`] performs on a `read` call.
    enum ReadAction {
        Bytes(Vec<u8>),
        Eof,
        Abort,
        Pause,
        /// Return a value larger than the supplied buffer ("funny value").
        Funny,
    }

    /// A scriptable [`ReadCallback`] yielding a queue of [`ReadAction`]s.
    struct VecReader {
        actions: VecDeque<ReadAction>,
    }

    impl VecReader {
        fn new(actions: Vec<ReadAction>) -> Self {
            VecReader {
                actions: actions.into(),
            }
        }
    }

    impl ReadCallback for VecReader {
        fn read(&mut self, buf: &mut [u8]) -> usize {
            match self.actions.pop_front() {
                None | Some(ReadAction::Eof) => 0,
                Some(ReadAction::Abort) => CURL_READFUNC_ABORT,
                Some(ReadAction::Pause) => CURL_READFUNC_PAUSE,
                Some(ReadAction::Funny) => buf.len() + 100,
                Some(ReadAction::Bytes(b)) => {
                    let n = b.len().min(buf.len());
                    buf[..n].copy_from_slice(&b[..n]);
                    n
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Mock protocol exchange + handle (ProtocolExchange / TransferHandle)
    // -----------------------------------------------------------------------

    /// A [`ProtocolExchange`] that replays a scripted sequence of
    /// [`ResponseEvent`]s and records any request body pushed to it.
    struct MockExchange {
        events: VecDeque<ResponseEvent>,
        sent: Vec<u8>,
    }

    impl MockExchange {
        fn new(events: Vec<ResponseEvent>) -> Self {
            MockExchange {
                events: events.into(),
                sent: Vec::new(),
            }
        }
    }

    impl ProtocolExchange for MockExchange {
        async fn next_event(&mut self) -> Result<ResponseEvent> {
            Ok(self.events.pop_front().unwrap_or(ResponseEvent::End))
        }

        async fn send_body(&mut self, data: &[u8]) -> Result<usize> {
            self.sent.extend_from_slice(data);
            Ok(data.len())
        }
    }

    /// A full [`TransferHandle`] bundling all the collaborators, used to exercise
    /// the [`run`] entrypoint end-to-end.
    struct MockHandle {
        exchange: MockExchange,
        request: Request,
        progress: Progress,
        writer: ClientWriter,
        cb: CollectCb,
        limits: TransferLimits,
        errbuf: ErrorBuffer,
    }

    impl MockHandle {
        fn new(events: Vec<ResponseEvent>) -> Self {
            MockHandle {
                exchange: MockExchange::new(events),
                request: Request::new(),
                progress: Progress::new(Instant::now()),
                writer: ClientWriter::new(),
                cb: CollectCb::new(),
                limits: TransferLimits::default(),
                errbuf: ErrorBuffer::new(),
            }
        }
    }

    impl TransferHandle for MockHandle {
        type Exchange = MockExchange;
        fn parts(&mut self) -> TransferParts<'_, MockExchange> {
            TransferParts {
                exchange: &mut self.exchange,
                request: &mut self.request,
                progress: &mut self.progress,
                writer: &mut self.writer,
                write_cb: &mut self.cb,
                limits: &self.limits,
                errbuf: &mut self.errbuf,
            }
        }
    }

    /// Helper: gzip-compress `plain` so content-decoding can be exercised.
    fn gzip(plain: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(plain).unwrap();
        enc.finish().unwrap()
    }

    // -----------------------------------------------------------------------
    // Client-writer chain (cw-out.c parity)
    // -----------------------------------------------------------------------

    #[test]
    fn cw_body_single_chunk_under_max_write() {
        let mut cb = CollectCb::new();
        let mut w = ClientWriter::new();
        w.write(ClientWriteType::BODY, b"hello world", &mut cb)
            .unwrap();
        assert_eq!(cb.body, b"hello world");
        assert_eq!(cb.body_calls, 1);
        assert!(!w.is_paused());
        assert!(!w.is_errored());
    }

    #[test]
    fn cw_body_chunked_to_max_write_size() {
        // A body larger than CURL_MAX_WRITE_SIZE is split into pieces no larger
        // than that (cw_out_ptr_flush's max_write loop).
        let total = CURL_MAX_WRITE_SIZE * 2 + 123;
        let data = vec![0xABu8; total];
        let mut cb = CollectCb::new();
        let mut w = ClientWriter::new();
        w.write(ClientWriteType::BODY, &data, &mut cb).unwrap();
        assert_eq!(cb.body.len(), total);
        assert_eq!(cb.body, data);
        // Three pieces: 16384 + 16384 + 123.
        assert_eq!(
            cb.body_chunk_lens,
            vec![CURL_MAX_WRITE_SIZE, CURL_MAX_WRITE_SIZE, 123]
        );
        assert!(cb.body_chunk_lens.iter().all(|&n| n <= CURL_MAX_WRITE_SIZE));
    }

    #[test]
    fn cw_header_delivered_verbatim_no_chunking() {
        // Headers are not chunked even if larger than CURL_MAX_WRITE_SIZE.
        let line = vec![b'h'; CURL_MAX_WRITE_SIZE + 500];
        let mut cb = CollectCb::new();
        let mut w = ClientWriter::new();
        w.write(ClientWriteType::HEADER, &line, &mut cb).unwrap();
        assert_eq!(cb.headers.len(), line.len());
        assert_eq!(cb.header_calls, 1, "header delivered in a single call");
        // Body stream untouched.
        assert!(cb.body.is_empty());
    }

    #[test]
    fn cw_header_no_sink_consumed_silently() {
        let mut cb = CollectCb::new();
        cb.header_sink = false; // write_header returns None
        let mut w = ClientWriter::new();
        // No error despite there being no header sink.
        w.write(ClientWriteType::HEADER, b"X-Test: 1\r\n", &mut cb)
            .unwrap();
        assert!(cb.headers.is_empty());
        assert!(!w.is_errored());
    }

    #[test]
    fn cw_zero_len_eos_delivers_single_empty_body_call() {
        let mut cb = CollectCb::new();
        let mut w = ClientWriter::new();
        w.write(
            ClientWriteType::BODY
                .union(ClientWriteType::EOS)
                .union(ClientWriteType::ZERO_LEN),
            &[],
            &mut cb,
        )
        .unwrap();
        // curl's BODY_0LEN path issues exactly one zero-length callback.
        assert_eq!(cb.body_calls, 1);
        assert_eq!(cb.body_chunk_lens, vec![0]);
        assert!(cb.body.is_empty());
    }

    #[test]
    fn cw_pause_then_unpause_replays_in_arrival_order() {
        let mut cb = CollectCb::new();
        // The first body callback pauses; later replays accept.
        cb.pause_body_calls = vec![1];
        let mut w = ClientWriter::new();

        // First write pauses and buffers.
        w.write(ClientWriteType::BODY, b"AAA", &mut cb).unwrap();
        assert!(w.is_paused());
        assert_eq!(cb.body, b""); // nothing delivered yet
        assert_eq!(w.buffered_len(), 3);

        // A second write while paused is appended to the buffer.
        w.write(ClientWriteType::BODY, b"BBB", &mut cb).unwrap();
        assert!(w.is_paused());
        assert_eq!(w.buffered_len(), 6);

        // Unpause replays the buffered chain in arrival order (FIFO).
        w.unpause(&mut cb).unwrap();
        assert!(!w.is_paused());
        assert_eq!(cb.body, b"AAABBB");
        assert_eq!(w.buffered_len(), 0);
    }

    #[test]
    fn cw_repause_during_replay_keeps_remainder_buffered() {
        let mut cb = CollectCb::new();
        // Call 1 pauses (buffer AAA), then on unpause call 2 pauses again so the
        // remainder stays buffered; call 3 finally accepts everything.
        cb.pause_body_calls = vec![1, 2];
        let mut w = ClientWriter::new();

        w.write(ClientWriteType::BODY, b"AAA", &mut cb).unwrap();
        w.write(ClientWriteType::BODY, b"BBB", &mut cb).unwrap();
        assert_eq!(w.buffered_len(), 6);

        // First unpause: call 2 pauses again → nothing delivered, still buffered.
        w.unpause(&mut cb).unwrap();
        assert!(w.is_paused());
        assert_eq!(cb.body, b"");
        assert_eq!(w.buffered_len(), 6);

        // Second unpause: call 3 accepts → full replay in order.
        w.unpause(&mut cb).unwrap();
        assert!(!w.is_paused());
        assert_eq!(cb.body, b"AAABBB");
        assert_eq!(w.buffered_len(), 0);
    }

    #[test]
    fn cw_error_latches_and_suppresses_further_callbacks() {
        let mut cb = CollectCb::new();
        cb.error_on_body_call = Some(1);
        let mut w = ClientWriter::new();

        let err = w
            .write(ClientWriteType::BODY, b"data", &mut cb)
            .unwrap_err();
        assert_eq!(err, CurlError::WriteError);
        assert!(w.is_errored());

        // A subsequent write returns WriteError without invoking the callback.
        let calls_before = cb.body_calls;
        let err2 = w
            .write(ClientWriteType::BODY, b"more", &mut cb)
            .unwrap_err();
        assert_eq!(err2, CurlError::WriteError);
        assert_eq!(
            cb.body_calls, calls_before,
            "no further callbacks after latch"
        );
    }

    #[test]
    fn cw_short_write_is_write_error() {
        let mut cb = CollectCb::new();
        cb.short_on_body_call = Some(1);
        let mut w = ClientWriter::new();
        let err = w
            .write(ClientWriteType::BODY, b"abcdef", &mut cb)
            .unwrap_err();
        assert_eq!(err, CurlError::WriteError);
        assert!(w.is_errored());
    }

    #[test]
    fn cw_pause_buffer_cap_is_too_large() {
        // A writer that cannot pause but is asked to is a write error; but the
        // 64 MiB cap is about exceeding DYN_PAUSE_BUFFER while buffering. Drive
        // it by pausing then feeding more than the cap.
        let mut cb = CollectCb::new();
        cb.pause_body_calls = vec![1];
        let mut w = ClientWriter::new();
        w.write(ClientWriteType::BODY, b"x", &mut cb).unwrap();
        assert!(w.is_paused());
        // Feed a chunk that pushes the buffer over DYN_PAUSE_BUFFER.
        let huge = vec![0u8; DYN_PAUSE_BUFFER + 1];
        let err = w.write(ClientWriteType::BODY, &huge, &mut cb).unwrap_err();
        assert_eq!(err, CurlError::TooLarge);
    }

    #[test]
    fn cw_pause_when_not_supported_is_write_error() {
        let mut cb = CollectCb::new();
        cb.pause_body_calls = vec![1];
        // can_pause = false (PROTOPT_NONETWORK, e.g. FILE://).
        let mut w = ClientWriter::with_options(false, false);
        let err = w.write(ClientWriteType::BODY, b"x", &mut cb).unwrap_err();
        assert_eq!(err, CurlError::WriteError);
    }

    #[test]
    fn cw_gzip_body_is_decoded() {
        let plain = b"The quick brown fox jumps over the lazy dog. ".repeat(50);
        let compressed = gzip(&plain);
        assert!(compressed != plain);

        let mut cb = CollectCb::new();
        let mut w = ClientWriter::with_content_encoding("gzip", true, false, true).unwrap();
        // Feed the gzip stream, then EOS to flush the decoder.
        w.write(ClientWriteType::BODY, &compressed, &mut cb)
            .unwrap();
        w.write(
            ClientWriteType::BODY.union(ClientWriteType::EOS),
            &[],
            &mut cb,
        )
        .unwrap();
        assert_eq!(cb.body, plain);
    }

    #[test]
    fn cw_gzip_passthrough_when_decoding_disabled() {
        let plain = b"hello hello hello".to_vec();
        let compressed = gzip(&plain);
        let mut cb = CollectCb::new();
        // decoding_enabled = false → raw (still-compressed) bytes pass through.
        let mut w = ClientWriter::with_content_encoding("gzip", false, false, true).unwrap();
        w.write(ClientWriteType::BODY, &compressed, &mut cb)
            .unwrap();
        w.write(
            ClientWriteType::BODY.union(ClientWriteType::EOS),
            &[],
            &mut cb,
        )
        .unwrap();
        assert_eq!(cb.body, compressed);
    }

    #[test]
    fn cw_include_header_routes_headers_to_body_stream() {
        // CURLOPT_HEADER: headers are also delivered on the body stream.
        let mut cb = CollectCb::new();
        let mut w = ClientWriter::with_options(true, true);
        w.write(ClientWriteType::HEADER, b"X-A: 1\r\n", &mut cb)
            .unwrap();
        assert_eq!(cb.body, b"X-A: 1\r\n");
    }

    #[test]
    fn cw_default_constructs() {
        let w = ClientWriter::default();
        assert!(!w.is_paused());
        assert!(!w.is_errored());
        assert_eq!(w.buffered_len(), 0);
    }

    // -----------------------------------------------------------------------
    // Upload reader (cr_in_read parity)
    // -----------------------------------------------------------------------

    #[test]
    fn read_returns_data() {
        let mut r = UploadReader::new(None, true);
        let mut src = VecReader::new(vec![ReadAction::Bytes(b"hello".to_vec())]);
        let mut buf = [0u8; 16];
        let step = r.read(&mut buf, &mut src).unwrap();
        assert_eq!(step, ReadStep::Data(5));
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(r.read_len(), 5);
        assert!(r.has_used_cb());
    }

    #[test]
    fn read_eof_unknown_total_is_ok() {
        let mut r = UploadReader::new(None, true);
        let mut src = VecReader::new(vec![ReadAction::Eof]);
        let mut buf = [0u8; 16];
        assert_eq!(r.read(&mut buf, &mut src).unwrap(), ReadStep::Eof);
        assert!(r.seen_eos());
        // A read after EOF stays EOF.
        assert_eq!(r.read(&mut buf, &mut src).unwrap(), ReadStep::Eof);
    }

    #[test]
    fn read_short_eof_with_known_total_is_error() {
        // Announced 10 bytes but source ends after 4 → "client read EOF fail".
        let mut r = UploadReader::new(Some(10), true);
        let mut src = VecReader::new(vec![ReadAction::Bytes(b"abcd".to_vec()), ReadAction::Eof]);
        let mut buf = [0u8; 16];
        assert_eq!(r.read(&mut buf, &mut src).unwrap(), ReadStep::Data(4));
        let err = r.read(&mut buf, &mut src).unwrap_err();
        assert_eq!(err, CurlError::ReadError);
    }

    #[test]
    fn read_known_total_completes_cleanly() {
        let mut r = UploadReader::new(Some(4), true);
        let mut src = VecReader::new(vec![ReadAction::Bytes(b"abcd".to_vec())]);
        let mut buf = [0u8; 16];
        assert_eq!(r.read(&mut buf, &mut src).unwrap(), ReadStep::Data(4));
        // Reached the announced total: marked EOS without another callback.
        assert!(r.seen_eos());
        assert_eq!(r.read(&mut buf, &mut src).unwrap(), ReadStep::Eof);
    }

    #[test]
    fn read_pause() {
        let mut r = UploadReader::new(None, true);
        let mut src = VecReader::new(vec![ReadAction::Pause]);
        let mut buf = [0u8; 16];
        assert_eq!(r.read(&mut buf, &mut src).unwrap(), ReadStep::Paused);
        assert!(r.is_paused());
    }

    #[test]
    fn read_pause_when_unsupported_is_error() {
        let mut r = UploadReader::new(None, false); // can_pause = false
        let mut src = VecReader::new(vec![ReadAction::Pause]);
        let mut buf = [0u8; 16];
        let err = r.read(&mut buf, &mut src).unwrap_err();
        assert_eq!(err, CurlError::ReadError);
    }

    #[test]
    fn read_abort_is_sticky() {
        let mut r = UploadReader::new(None, true);
        let mut src = VecReader::new(vec![ReadAction::Abort]);
        let mut buf = [0u8; 16];
        let err = r.read(&mut buf, &mut src).unwrap_err();
        assert_eq!(err, CurlError::AbortedByCallback);
        // Sticky: the same error is returned again even with fresh actions.
        let mut src2 = VecReader::new(vec![ReadAction::Bytes(b"x".to_vec())]);
        let err2 = r.read(&mut buf, &mut src2).unwrap_err();
        assert_eq!(err2, CurlError::AbortedByCallback);
    }

    #[test]
    fn read_funny_value_is_error() {
        let mut r = UploadReader::new(None, true);
        let mut src = VecReader::new(vec![ReadAction::Funny]);
        let mut buf = [0u8; 8];
        let err = r.read(&mut buf, &mut src).unwrap_err();
        assert_eq!(err, CurlError::ReadError);
    }

    #[test]
    fn read_clamps_request_to_remaining_total() {
        // total=3 but buffer is 16: the callback must be asked for at most 3.
        struct Probe {
            seen: usize,
        }
        impl ReadCallback for Probe {
            fn read(&mut self, buf: &mut [u8]) -> usize {
                self.seen = buf.len();
                // Fill what was asked.
                for b in buf.iter_mut() {
                    *b = b'z';
                }
                buf.len()
            }
        }
        let mut r = UploadReader::new(Some(3), true);
        let mut p = Probe { seen: 0 };
        let mut buf = [0u8; 16];
        let step = r.read(&mut buf, &mut p).unwrap();
        assert_eq!(p.seen, 3, "request clamped to remaining announced length");
        assert_eq!(step, ReadStep::Data(3));
    }

    // -----------------------------------------------------------------------
    // Redirect handling (Curl_http_follow parity)
    // -----------------------------------------------------------------------

    fn url(s: &str) -> CurlUrl {
        let mut u = CurlUrl::new();
        u.set(CurlUPart::Url, Some(s), 0).unwrap();
        u
    }

    fn auth_keep() -> RedirectAuthContext<'static> {
        // allow_auth_to_other_hosts = true ⇒ credentials are never cleared.
        RedirectAuthContext {
            allow_auth_to_other_hosts: true,
            use_port: None,
            conn_remote_port: 0,
            conn_scheme: "http",
        }
    }

    #[test]
    fn redirect_method_301_post_becomes_get() {
        let (m, switched) = redirect_method(301, HttpMethod::Post, &PostRedir::default());
        assert_eq!(m, HttpMethod::Get);
        assert!(switched);
    }

    #[test]
    fn redirect_method_301_post_kept_with_post301() {
        let pr = PostRedir {
            post301: true,
            ..PostRedir::default()
        };
        let (m, switched) = redirect_method(301, HttpMethod::Post, &pr);
        assert_eq!(m, HttpMethod::Post);
        assert!(!switched);
    }

    #[test]
    fn redirect_method_302_post_becomes_get_or_kept() {
        let (m, s) = redirect_method(302, HttpMethod::PostForm, &PostRedir::default());
        assert_eq!(m, HttpMethod::Get);
        assert!(s);
        let pr = PostRedir {
            post302: true,
            ..PostRedir::default()
        };
        let (m2, s2) = redirect_method(302, HttpMethod::PostForm, &pr);
        assert_eq!(m2, HttpMethod::PostForm);
        assert!(!s2);
    }

    #[test]
    fn redirect_method_303_non_get_becomes_get() {
        // 303 turns any non-GET into GET (here PUT, which is not POST-family).
        let (m, s) = redirect_method(303, HttpMethod::Put, &PostRedir::default());
        assert_eq!(m, HttpMethod::Get);
        assert!(s);
    }

    #[test]
    fn redirect_method_303_post_kept_with_post303() {
        let pr = PostRedir {
            post303: true,
            ..PostRedir::default()
        };
        let (m, s) = redirect_method(303, HttpMethod::Post, &pr);
        assert_eq!(m, HttpMethod::Post);
        assert!(!s);
    }

    #[test]
    fn redirect_method_307_unchanged() {
        let (m, s) = redirect_method(307, HttpMethod::Post, &PostRedir::default());
        assert_eq!(m, HttpMethod::Post);
        assert!(!s);
    }

    #[test]
    fn redirect_method_other_codes_unchanged() {
        for code in [300, 304, 305, 306, 308, 401, 407] {
            let (m, s) = redirect_method(code, HttpMethod::Post, &PostRedir::default());
            assert_eq!(m, HttpMethod::Post, "code {code} must keep method");
            assert!(!s);
        }
    }

    #[test]
    fn redirect_method_get_stays_get_on_303() {
        let (m, s) = redirect_method(303, HttpMethod::Get, &PostRedir::default());
        assert_eq!(m, HttpMethod::Get);
        assert!(!s);
    }

    #[test]
    fn uc_to_curlcode_mapping() {
        assert_eq!(
            uc_to_curlcode(CurlUError::OutOfMemory),
            CurlError::OutOfMemory
        );
        assert_eq!(
            uc_to_curlcode(CurlUError::UnsupportedScheme),
            CurlError::UnsupportedProtocol
        );
        assert_eq!(
            uc_to_curlcode(CurlUError::UserNotAllowed),
            CurlError::LoginDenied
        );
        // Anything else collapses to URL_MALFORMAT.
        assert_eq!(
            uc_to_curlcode(CurlUError::BadHandle),
            CurlError::UrlMalformat
        );
    }

    #[test]
    fn is_absolute_url_cases() {
        assert!(is_absolute_url("http://example.com"));
        assert!(is_absolute_url("https://x"));
        assert!(is_absolute_url("ftp://x"));
        assert!(is_absolute_url("a+b-c.d://x"));
        assert!(!is_absolute_url("/relative/path"));
        assert!(!is_absolute_url("//host/path"));
        assert!(!is_absolute_url("1http://x")); // must start with ALPHA
        assert!(!is_absolute_url(""));
        assert!(!is_absolute_url("noscheme"));
    }

    #[test]
    fn follow_relative_redirect_resolves_and_advances() {
        let base = url("http://example.com/a/b");
        let mut state = RedirectState::default();
        let cfg = RedirectConfig::default();
        let req = FollowRequest {
            base: &base,
            newurl: "/c/d",
            ftype: FollowType::Redir,
            status: 302,
            method: HttpMethod::Post,
        };
        let out = follow(&req, &cfg, &mut state, &auth_keep()).unwrap();
        match out {
            FollowOutcome::Follow(r) => {
                assert_eq!(r.url_str, "http://example.com/c/d");
                assert_eq!(r.method, HttpMethod::Get); // 302 POST→GET
                assert!(r.switched_to_get);
                assert!(!r.disallow_port); // relative URL ⇒ no port lock
            }
            other => panic!("expected Follow, got {other:?}"),
        }
        assert_eq!(state.followlocation, 1);
        assert_eq!(state.requests, 1);
    }

    #[test]
    fn follow_absolute_redirect_disallows_port() {
        let base = url("http://example.com/a");
        let mut state = RedirectState::default();
        let cfg = RedirectConfig::default();
        let req = FollowRequest {
            base: &base,
            newurl: "https://other.test:8443/x",
            ftype: FollowType::Redir,
            status: 302,
            method: HttpMethod::Get,
        };
        let out = follow(&req, &cfg, &mut state, &auth_keep()).unwrap();
        match out {
            FollowOutcome::Follow(r) => {
                assert!(r.disallow_port);
            }
            other => panic!("expected Follow, got {other:?}"),
        }
        assert!(!state.allow_port, "absolute redirect locks the port off");
    }

    #[test]
    fn follow_maxredirs_reached_is_too_many() {
        let base = url("http://example.com/a");
        let mut state = RedirectState {
            followlocation: 2,
            ..RedirectState::default()
        };
        let cfg = RedirectConfig {
            maxredirs: 2,
            ..RedirectConfig::default()
        };
        let req = FollowRequest {
            base: &base,
            newurl: "/again",
            ftype: FollowType::Redir,
            status: 302,
            method: HttpMethod::Get,
        };
        let out = follow(&req, &cfg, &mut state, &auth_keep()).unwrap();
        match out {
            FollowOutcome::TooManyRedirects { would_redirect } => {
                assert_eq!(would_redirect, "http://example.com/again");
            }
            other => panic!("expected TooManyRedirects, got {other:?}"),
        }
    }

    #[test]
    fn follow_fake_records_would_redirect() {
        let base = url("http://example.com/a");
        let mut state = RedirectState::default();
        let cfg = RedirectConfig::default();
        let req = FollowRequest {
            base: &base,
            newurl: "/next",
            ftype: FollowType::Fake,
            status: 302,
            method: HttpMethod::Get,
        };
        let out = follow(&req, &cfg, &mut state, &auth_keep()).unwrap();
        match out {
            FollowOutcome::Fake { would_redirect } => {
                assert_eq!(would_redirect, "http://example.com/next");
            }
            other => panic!("expected Fake, got {other:?}"),
        }
        // Fake does not count as a real request.
        assert_eq!(state.requests, 0);
    }

    #[test]
    fn follow_auto_referer_strips_fragment() {
        let base = url("http://user:pass@example.com/a#frag");
        let mut state = RedirectState::default();
        let cfg = RedirectConfig {
            auto_referer: true,
            ..RedirectConfig::default()
        };
        let req = FollowRequest {
            base: &base,
            newurl: "/b",
            ftype: FollowType::Redir,
            status: 302,
            method: HttpMethod::Get,
        };
        let out = follow(&req, &cfg, &mut state, &auth_keep()).unwrap();
        match out {
            FollowOutcome::Follow(r) => {
                let referer = r.referer.expect("auto-referer set");
                assert!(!referer.contains('#'), "fragment stripped: {referer}");
                assert!(!referer.contains("user"), "credentials stripped: {referer}");
            }
            other => panic!("expected Follow, got {other:?}"),
        }
    }

    #[test]
    fn follow_retry_keeps_same_method() {
        let base = url("http://example.com/a");
        let mut state = RedirectState::default();
        let cfg = RedirectConfig::default();
        let req = FollowRequest {
            base: &base,
            newurl: "http://example.com/a",
            ftype: FollowType::Retry,
            status: 0,
            method: HttpMethod::Post,
        };
        let out = follow(&req, &cfg, &mut state, &auth_keep()).unwrap();
        match out {
            FollowOutcome::Follow(r) => {
                assert_eq!(r.method, HttpMethod::Post);
                assert!(!r.disallow_port, "retry never disallows port");
            }
            other => panic!("expected Follow, got {other:?}"),
        }
    }

    #[test]
    fn follow_clear_auth_on_port_change() {
        let base = url("http://example.com/a");
        let mut state = RedirectState::default();
        let cfg = RedirectConfig::default();
        let ctx = RedirectAuthContext {
            allow_auth_to_other_hosts: false,
            use_port: None,
            conn_remote_port: 80,
            conn_scheme: "http",
        };
        let req = FollowRequest {
            base: &base,
            newurl: "http://example.com:8080/b",
            ftype: FollowType::Redir,
            status: 302,
            method: HttpMethod::Get,
        };
        let out = follow(&req, &cfg, &mut state, &ctx).unwrap();
        match out {
            FollowOutcome::Follow(r) => assert!(r.clear_auth, "port change clears auth"),
            other => panic!("expected Follow, got {other:?}"),
        }
    }

    #[test]
    fn follow_clear_auth_on_scheme_change_same_port() {
        let base = url("https://example.com/a");
        let mut state = RedirectState::default();
        let cfg = RedirectConfig::default();
        // conn is https on port 443; redirect to http but pinned to port 443 →
        // ports equal, scheme differs → clear.
        let ctx = RedirectAuthContext {
            allow_auth_to_other_hosts: false,
            use_port: None,
            conn_remote_port: 443,
            conn_scheme: "https",
        };
        let req = FollowRequest {
            base: &base,
            newurl: "http://example.com:443/b",
            ftype: FollowType::Redir,
            status: 302,
            method: HttpMethod::Get,
        };
        let out = follow(&req, &cfg, &mut state, &ctx).unwrap();
        match out {
            FollowOutcome::Follow(r) => assert!(r.clear_auth, "scheme change clears auth"),
            other => panic!("expected Follow, got {other:?}"),
        }
    }

    #[test]
    fn follow_unrestricted_auth_keeps_credentials() {
        let base = url("http://example.com/a");
        let mut state = RedirectState::default();
        let cfg = RedirectConfig {
            allow_auth_to_other_hosts: true,
            ..RedirectConfig::default()
        };
        let ctx = RedirectAuthContext {
            allow_auth_to_other_hosts: true,
            use_port: None,
            conn_remote_port: 80,
            conn_scheme: "http",
        };
        let req = FollowRequest {
            base: &base,
            newurl: "http://other.test:9999/b",
            ftype: FollowType::Redir,
            status: 302,
            method: HttpMethod::Get,
        };
        let out = follow(&req, &cfg, &mut state, &ctx).unwrap();
        match out {
            FollowOutcome::Follow(r) => assert!(!r.clear_auth),
            other => panic!("expected Follow, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Speed / time limits
    // -----------------------------------------------------------------------

    #[test]
    fn time_left_variants() {
        let now = Instant::now();
        assert_eq!(time_left(None, now), None);
        let future = now + Duration::from_secs(5);
        let tl = time_left(Some(future), now).unwrap();
        assert!(tl > Duration::from_secs(4) && tl <= Duration::from_secs(5));
        // A past deadline saturates to ZERO (not negative).
        let past = now - Duration::from_secs(5);
        assert_eq!(time_left(Some(past), now), Some(Duration::ZERO));
    }

    #[test]
    fn is_timed_out_semantics() {
        let now = Instant::now();
        assert!(!is_timed_out(None, now));
        assert!(!is_timed_out(Some(now + Duration::from_secs(1)), now));
        // Exactly-now is NOT timed out (curl's strict "< 0").
        assert!(!is_timed_out(Some(now), now));
        assert!(is_timed_out(Some(now - Duration::from_millis(1)), now));
    }

    #[test]
    fn check_partial_file_variants() {
        // Short read with a known size and no pending redirect → PartialFile.
        assert_eq!(
            check_partial_file(false, Some(100), 40, false),
            Err(CurlError::PartialFile)
        );
        // Exact size → OK.
        assert!(check_partial_file(false, Some(100), 100, false).is_ok());
        // no_body → check skipped.
        assert!(check_partial_file(true, Some(100), 40, false).is_ok());
        // Pending redirect (newurl) → check skipped.
        assert!(check_partial_file(false, Some(100), 40, true).is_ok());
        // Unknown size (None) → check skipped.
        assert!(check_partial_file(false, None, 40, false).is_ok());
        // Negative size (curl's -1 "unknown") → check skipped.
        assert!(check_partial_file(false, Some(-1), 40, false).is_ok());
    }

    #[test]
    fn rate_limit_delay_unlimited_is_zero_limited_is_nonzero() {
        let now = Instant::now();
        let mut rl = RateLimit::new(now);
        // No cap configured → always ZERO.
        assert_eq!(
            rate_limit_delay(&mut rl, Direction::Download, 1_000_000, now),
            Duration::ZERO
        );
        // A tight cap with a large instantaneous transfer owes a wait.
        rl.set_recv_limit(100).unwrap();
        let d = rate_limit_delay(&mut rl, Direction::Download, 10_000, now);
        assert!(d > Duration::ZERO, "an over-cap burst must owe a wait");
    }

    // -----------------------------------------------------------------------
    // Retry decision (Curl_retry_request parity)
    // -----------------------------------------------------------------------

    fn retry_cfg() -> RetryConfig {
        RetryConfig {
            upload: false,
            is_http_family: true,
            is_rtsp: false,
            rtsp_receive: false,
            conn_reuse: true,
            data_counters_zero: true,
            no_body: false,
            done: false,
            refused_stream: false,
        }
    }

    #[test]
    fn retry_reused_connection_with_no_data() {
        let cfg = retry_cfg();
        let mut count = 0u32;
        assert_eq!(
            retry_request(&cfg, &mut count).unwrap(),
            RetryDecision::Retry
        );
        assert_eq!(count, 1);
    }

    #[test]
    fn retry_refused_stream() {
        let cfg = RetryConfig {
            conn_reuse: false,
            refused_stream: true,
            ..retry_cfg()
        };
        let mut count = 0u32;
        assert_eq!(
            retry_request(&cfg, &mut count).unwrap(),
            RetryDecision::Retry
        );
    }

    #[test]
    fn retry_upload_non_http_never_retries() {
        let cfg = RetryConfig {
            upload: true,
            is_http_family: false,
            is_rtsp: false,
            ..retry_cfg()
        };
        let mut count = 0u32;
        assert_eq!(
            retry_request(&cfg, &mut count).unwrap(),
            RetryDecision::NoRetry
        );
        assert_eq!(count, 0);
    }

    #[test]
    fn retry_no_conditions_means_no_retry() {
        let cfg = RetryConfig {
            conn_reuse: false,
            refused_stream: false,
            ..retry_cfg()
        };
        let mut count = 0u32;
        assert_eq!(
            retry_request(&cfg, &mut count).unwrap(),
            RetryDecision::NoRetry
        );
    }

    #[test]
    fn retry_exhausted_after_max_is_send_error() {
        let cfg = retry_cfg();
        let mut count = CONN_MAX_RETRIES; // already at the cap
        let err = retry_request(&cfg, &mut count).unwrap_err();
        assert_eq!(err, CurlError::SendError);
        assert_eq!(count, 0, "counter resets on giving up");
    }

    #[test]
    fn retry_counts_up_to_the_cap() {
        let cfg = retry_cfg();
        let mut count = 0u32;
        for expected in 1..=CONN_MAX_RETRIES {
            assert_eq!(
                retry_request(&cfg, &mut count).unwrap(),
                RetryDecision::Retry
            );
            assert_eq!(count, expected);
        }
        // The next attempt exceeds the cap.
        assert_eq!(
            retry_request(&cfg, &mut count).unwrap_err(),
            CurlError::SendError
        );
    }

    // -----------------------------------------------------------------------
    // Progress + info recording
    // -----------------------------------------------------------------------

    #[test]
    fn transfer_info_default_is_zeroed() {
        let info = TransferInfo::default();
        assert_eq!(info.response_code, 0);
        assert_eq!(info.size_download, 0);
        assert!(info.effective_url.is_none());
        assert!(!info.total_time.is_set());
    }

    #[test]
    fn transfer_info_records_progress_counters() {
        let now = Instant::now();
        let mut p = Progress::new(now);
        p.set_download_counter(1234);
        p.set_upload_counter(56);
        let mut info = TransferInfo::new();
        info.record_progress(&p);
        assert_eq!(info.size_download, 1234);
        assert_eq!(info.size_upload, 56);
    }

    #[test]
    fn mark_redirect_records_timer_and_resets_sizes() {
        let now = Instant::now();
        let mut p = Progress::new(now);
        p.set_download_size(999);
        // mark_redirect stamps TIMER_REDIRECT and resets the per-hop sizes.
        mark_redirect(&mut p, now + Duration::from_millis(1));
        assert!(p.redirect_time().is_set());
    }

    #[test]
    fn progress_tick_runs_without_limits() {
        let now = Instant::now();
        let mut p = Progress::new(now);
        let limits = TransferLimits::default();
        // No low-speed limit, not done, not paused → no abort.
        let res = progress_tick(&mut p, now, false, false, &limits, None);
        assert!(res.is_ok());
    }

    // -----------------------------------------------------------------------
    // Messaging (Curl_infof / Curl_failf parity)
    // -----------------------------------------------------------------------

    #[test]
    fn errorbuffer_failf_latches_first_message() {
        let mut eb = ErrorBuffer::new();
        eb.failf(format_args!("first error"));
        eb.failf(format_args!("second error"));
        // The first message wins (curl's state.errorbuf latch).
        assert_eq!(eb.last_error(), Some("first error"));
        assert!(eb.has_error());
    }

    #[test]
    fn errorbuffer_reset_clears_latch() {
        let mut eb = ErrorBuffer::new();
        eb.failf(format_args!("boom"));
        eb.reset();
        assert_eq!(eb.last_error(), None);
        assert!(!eb.has_error());
        // After reset, the next failf captures afresh.
        eb.failf(format_args!("again"));
        assert_eq!(eb.last_error(), Some("again"));
    }

    #[test]
    fn errorbuffer_infof_never_captures() {
        let eb = ErrorBuffer::with_verbose(true);
        eb.infof(format_args!("just info"));
        assert_eq!(eb.last_error(), None);
        assert!(!eb.has_error());
    }

    #[test]
    fn errorbuffer_verbose_flag() {
        let mut eb = ErrorBuffer::new();
        assert!(!eb.is_verbose());
        eb.set_verbose(true);
        assert!(eb.is_verbose());
        // Capture is independent of verbosity.
        let mut quiet = ErrorBuffer::with_verbose(false);
        quiet.failf(format_args!("captured even when quiet"));
        assert_eq!(quiet.last_error(), Some("captured even when quiet"));
    }

    #[test]
    fn emit_timeout_messages_match_curl() {
        let mut eb = ErrorBuffer::new();
        emit_timeout(&mut eb, 5000, 40, Some(100));
        assert_eq!(
            eb.last_error(),
            Some("Operation timed out after 5000 milliseconds with 40 out of 100 bytes received")
        );
        let mut eb2 = ErrorBuffer::new();
        emit_timeout(&mut eb2, 5000, 40, None);
        assert_eq!(
            eb2.last_error(),
            Some("Operation timed out after 5000 milliseconds with 40 bytes received")
        );
    }

    #[test]
    fn emit_partial_file_message_matches_curl() {
        let mut eb = ErrorBuffer::new();
        emit_partial_file(&mut eb, 60);
        assert_eq!(
            eb.last_error(),
            Some("transfer closed with 60 bytes remaining to read")
        );
    }

    #[test]
    fn emit_retry_exhausted_message_matches_curl() {
        let mut eb = ErrorBuffer::new();
        emit_retry_exhausted(&mut eb);
        assert_eq!(
            eb.last_error(),
            Some("Connection died, tried 5 times before giving up")
        );
    }

    #[test]
    fn emit_too_many_redirects_message_matches_curl() {
        let mut eb = ErrorBuffer::new();
        emit_too_many_redirects(&mut eb, 50);
        assert_eq!(eb.last_error(), Some("Maximum (50) redirects followed"));
    }

    #[test]
    fn emit_info_helpers_do_not_capture() {
        // The info-level emitters never touch the error buffer.
        let eb = ErrorBuffer::with_verbose(true);
        emit_refused_stream_retry(&eb);
        emit_retry_fresh_connect(&eb, 2);
        assert_eq!(eb.last_error(), None);
    }

    // -----------------------------------------------------------------------
    // The async byte-loop driver + type-state lifecycle
    // -----------------------------------------------------------------------

    /// Build a [`TransferParts`] over caller-owned collaborators and run the
    /// driver — a small harness shared by the driver tests.
    async fn drive(
        events: Vec<ResponseEvent>,
        limits: TransferLimits,
        writer: &mut ClientWriter,
        cb: &mut CollectCb,
        request: &mut Request,
        errbuf: &mut ErrorBuffer,
    ) -> Result<()> {
        let mut exchange = MockExchange::new(events);
        let mut progress = Progress::new(Instant::now());
        let parts = TransferParts {
            exchange: &mut exchange,
            request,
            progress: &mut progress,
            writer,
            write_cb: cb,
            limits: &limits,
            errbuf,
        };
        drive_transfer(parts, None, None).await
    }

    #[tokio::test]
    async fn drive_simple_transfer_delivers_body_and_headers() {
        let mut writer = ClientWriter::new();
        let mut cb = CollectCb::new();
        let mut request = Request::new();
        let mut errbuf = ErrorBuffer::new();
        drive(
            vec![
                ResponseEvent::Status(200),
                ResponseEvent::Header(b"Content-Type: text/plain\r\n".to_vec()),
                ResponseEvent::HeadersComplete {
                    content_length: None,
                    content_encoding: None,
                },
                ResponseEvent::Body(b"hello".to_vec()),
                ResponseEvent::End,
            ],
            TransferLimits::default(),
            &mut writer,
            &mut cb,
            &mut request,
            &mut errbuf,
        )
        .await
        .unwrap();

        assert_eq!(cb.body, b"hello");
        assert_eq!(cb.headers, b"Content-Type: text/plain\r\n");
        assert_eq!(request.bytecount, 5);
        assert_eq!(request.httpcode, 200);
        assert!(request.done);
        assert!(request.eos_written);
    }

    #[tokio::test]
    async fn drive_partial_file_when_body_short() {
        let mut writer = ClientWriter::new();
        let mut cb = CollectCb::new();
        let mut request = Request::new();
        let mut errbuf = ErrorBuffer::new();
        let err = drive(
            vec![
                ResponseEvent::Status(200),
                ResponseEvent::HeadersComplete {
                    content_length: Some(100),
                    content_encoding: None,
                },
                ResponseEvent::Body(b"hello".to_vec()), // 5 of 100
                ResponseEvent::End,
            ],
            TransferLimits::default(),
            &mut writer,
            &mut cb,
            &mut request,
            &mut errbuf,
        )
        .await
        .unwrap_err();

        assert_eq!(err, CurlError::PartialFile);
        assert_eq!(
            errbuf.last_error(),
            Some("transfer closed with 95 bytes remaining to read")
        );
    }

    #[tokio::test]
    async fn drive_decodes_gzip_body_via_headers() {
        let plain = b"The quick brown fox. ".repeat(40);
        let compressed = gzip(&plain);

        let mut writer = ClientWriter::new();
        let mut cb = CollectCb::new();
        let mut request = Request::new();
        let mut errbuf = ErrorBuffer::new();
        drive(
            vec![
                ResponseEvent::Status(200),
                ResponseEvent::HeadersComplete {
                    content_length: None,
                    content_encoding: Some("gzip".to_string()),
                },
                ResponseEvent::Body(compressed),
                ResponseEvent::End,
            ],
            TransferLimits::default(),
            &mut writer,
            &mut cb,
            &mut request,
            &mut errbuf,
        )
        .await
        .unwrap();

        assert_eq!(cb.body, plain);
    }

    #[tokio::test]
    async fn drive_timeout_emits_message() {
        let mut writer = ClientWriter::new();
        let mut cb = CollectCb::new();
        let mut request = Request::new();
        let mut errbuf = ErrorBuffer::new();
        let limits = TransferLimits {
            deadline: Some(Instant::now() - Duration::from_secs(1)),
            ..TransferLimits::default()
        };
        let err = drive(
            vec![ResponseEvent::Body(b"x".to_vec()), ResponseEvent::End],
            limits,
            &mut writer,
            &mut cb,
            &mut request,
            &mut errbuf,
        )
        .await
        .unwrap_err();

        assert_eq!(err, CurlError::OperationTimedout);
        assert!(errbuf
            .last_error()
            .unwrap()
            .starts_with("Operation timed out after"));
    }

    #[tokio::test]
    async fn drive_invokes_progress_callback() {
        let calls = std::cell::Cell::new(0u32);
        let mut cbfn = |_dltotal: i64, _dlnow: i64, _ultotal: i64, _ulnow: i64| -> i32 {
            calls.set(calls.get() + 1);
            0
        };

        let mut exchange = MockExchange::new(vec![
            ResponseEvent::Status(200),
            ResponseEvent::HeadersComplete {
                content_length: None,
                content_encoding: None,
            },
            ResponseEvent::Body(b"abc".to_vec()),
            ResponseEvent::End,
        ]);
        let mut request = Request::new();
        let mut progress = Progress::new(Instant::now());
        let mut writer = ClientWriter::new();
        let mut cb = CollectCb::new();
        let limits = TransferLimits::default();
        let mut errbuf = ErrorBuffer::new();
        let parts = TransferParts {
            exchange: &mut exchange,
            request: &mut request,
            progress: &mut progress,
            writer: &mut writer,
            write_cb: &mut cb,
            limits: &limits,
            errbuf: &mut errbuf,
        };
        drive_transfer(parts, Some(&mut cbfn), None).await.unwrap();
        assert!(calls.get() >= 1, "progress callback invoked at least once");
    }

    #[tokio::test]
    async fn drive_progress_callback_abort() {
        // A callback return that is neither 0 nor CURL_PROGRESSFUNC_CONTINUE
        // aborts the transfer.
        let mut cbfn = |_: i64, _: i64, _: i64, _: i64| -> i32 { 1 };

        let mut exchange = MockExchange::new(vec![
            ResponseEvent::HeadersComplete {
                content_length: None,
                content_encoding: None,
            },
            ResponseEvent::Body(b"abc".to_vec()),
            ResponseEvent::End,
        ]);
        let mut request = Request::new();
        let mut progress = Progress::new(Instant::now());
        let mut writer = ClientWriter::new();
        let mut cb = CollectCb::new();
        let limits = TransferLimits::default();
        let mut errbuf = ErrorBuffer::new();
        let parts = TransferParts {
            exchange: &mut exchange,
            request: &mut request,
            progress: &mut progress,
            writer: &mut writer,
            write_cb: &mut cb,
            limits: &limits,
            errbuf: &mut errbuf,
        };
        let err = drive_transfer(parts, Some(&mut cbfn), None)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::AbortedByCallback);
    }

    #[tokio::test]
    async fn type_state_full_lifecycle_records_info() {
        let now = Instant::now();
        let t = Transfer::new(
            Request::new(),
            TransferLimits::default(),
            RedirectConfig::default(),
            now,
        )
        .with_verbose(false)
        .connect(now)
        .begin_transfer(now);

        let mut exchange = MockExchange::new(vec![
            ResponseEvent::Status(206),
            ResponseEvent::HeadersComplete {
                content_length: None,
                content_encoding: None,
            },
            ResponseEvent::Body(b"hi".to_vec()),
            ResponseEvent::End,
        ]);
        let mut writer = ClientWriter::new();
        let mut cb = CollectCb::new();

        let done = t
            .drive(&mut exchange, &mut writer, &mut cb, None)
            .await
            .unwrap();

        assert_eq!(done.info().response_code, 206);
        assert_eq!(done.request().bytecount, 2);
        assert_eq!(cb.body, b"hi");
        let info = done.into_info();
        assert_eq!(info.size_download, 2);
    }

    #[tokio::test]
    async fn run_via_transfer_handle() {
        let mut handle = MockHandle::new(vec![
            ResponseEvent::Status(200),
            ResponseEvent::HeadersComplete {
                content_length: None,
                content_encoding: None,
            },
            ResponseEvent::Body(b"xyz".to_vec()),
            ResponseEvent::End,
        ]);
        run(&mut handle).await.unwrap();
        assert_eq!(handle.cb.body, b"xyz");
        assert_eq!(handle.request.bytecount, 3);
        assert!(handle.request.done);
    }

    #[tokio::test]
    async fn drive_write_error_propagates() {
        // A write callback that errors fails the transfer with WriteError.
        let mut writer = ClientWriter::new();
        let mut cb = CollectCb::new();
        cb.error_on_body_call = Some(1);
        let mut request = Request::new();
        let mut errbuf = ErrorBuffer::new();
        let err = drive(
            vec![
                ResponseEvent::HeadersComplete {
                    content_length: None,
                    content_encoding: None,
                },
                ResponseEvent::Body(b"data".to_vec()),
                ResponseEvent::End,
            ],
            TransferLimits::default(),
            &mut writer,
            &mut cb,
            &mut request,
            &mut errbuf,
        )
        .await
        .unwrap_err();
        assert_eq!(err, CurlError::WriteError);
    }

    // -----------------------------------------------------------------------
    // Public API surface: flag helpers, Debug, accessors, header pause, upload
    // -----------------------------------------------------------------------

    #[test]
    fn client_write_type_flag_helpers() {
        let bh = ClientWriteType::BODY | ClientWriteType::HEADER;
        assert!(bh.contains(ClientWriteType::BODY));
        assert!(bh.contains(ClientWriteType::HEADER));
        assert!(bh.intersects(ClientWriteType::BODY));
        assert!(!bh.intersects(ClientWriteType::TRAILER));
        assert!(bh.is_body());
        assert!(bh.is_header());
        assert!(!bh.is_empty());
        assert!(ClientWriteType::NONE.is_empty());
        assert_eq!(ClientWriteType::BODY.bits(), 1);
        // Status/Info/Connect/1xx/Trailer all count as "header" (meta) streams.
        assert!(ClientWriteType::STATUS.is_header());
        assert!(ClientWriteType::INFO_1XX.is_header());
        assert!(!ClientWriteType::BODY.is_header());

        // BitOrAssign accumulates flags.
        let mut t = ClientWriteType::BODY;
        t |= ClientWriteType::EOS;
        assert!(t.contains(ClientWriteType::EOS));
        assert!(t.is_body());
    }

    #[test]
    fn client_writer_debug_is_informative() {
        let w = ClientWriter::new();
        let s = format!("{w:?}");
        assert!(s.contains("ClientWriter"));
        assert!(s.contains("eos_seen"));
    }

    #[test]
    fn http_method_is_post_family() {
        assert!(HttpMethod::Post.is_post_family());
        assert!(HttpMethod::PostForm.is_post_family());
        assert!(HttpMethod::PostMime.is_post_family());
        assert!(!HttpMethod::Get.is_post_family());
        assert!(!HttpMethod::Put.is_post_family());
        assert!(!HttpMethod::Head.is_post_family());
    }

    #[test]
    fn header_callback_pause_then_unpause() {
        // A header callback can pause too; the chain buffers and replays it.
        let mut cb = CollectCb::new();
        cb.pause_header_calls = vec![1];
        let mut w = ClientWriter::new();
        w.write(ClientWriteType::HEADER, b"X-A: 1\r\n", &mut cb)
            .unwrap();
        assert!(w.is_paused());
        assert_eq!(cb.headers, b"");
        w.unpause(&mut cb).unwrap();
        assert!(!w.is_paused());
        assert_eq!(cb.headers, b"X-A: 1\r\n");
    }

    #[tokio::test]
    async fn transferring_progress_accessor_and_complete_last_error() {
        let now = Instant::now();
        let mut t = Transfer::new(
            Request::new(),
            TransferLimits::default(),
            RedirectConfig::default(),
            now,
        )
        .connect(now)
        .begin_transfer(now);
        // The progress accessor is reachable in the Transferring state.
        let _ = t.progress();

        let mut exchange = MockExchange::new(vec![
            ResponseEvent::Status(200),
            ResponseEvent::HeadersComplete {
                content_length: None,
                content_encoding: None,
            },
            ResponseEvent::Body(b"z".to_vec()),
            ResponseEvent::End,
        ]);
        let mut writer = ClientWriter::new();
        let mut cb = CollectCb::new();
        let done = t
            .drive(&mut exchange, &mut writer, &mut cb, None)
            .await
            .unwrap();
        // A clean transfer recorded no failure.
        assert_eq!(done.last_error(), None);
    }

    #[tokio::test]
    async fn exchange_send_body_records_upload() {
        // The ProtocolExchange upload-push contract: send_body reports the bytes
        // accepted and the mock records them.
        let mut exchange = MockExchange::new(vec![ResponseEvent::End]);
        let n = exchange.send_body(b"upload").await.unwrap();
        assert_eq!(n, 6);
        assert_eq!(exchange.sent, b"upload");
    }
}
