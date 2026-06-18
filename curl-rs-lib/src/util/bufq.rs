// Chunked byte-queue (`bufq`) and borrowed/owned buffer reference (`bufref`).
//
// SPDX-License-Identifier: curl
//
// This file is a memory-safe Rust reimplementation of two curl utilities:
//   * the chunked byte queue `lib/bufq.c` / `lib/bufq.h`, and
//   * the buffer reference `lib/bufref.c` / `lib/bufref.h`.
// The original C sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).
// This Rust port preserves the *observable behavior* and the public API *names*
// of those utilities; it is a behavioral translation, not a line-by-line one.

//! Backpressure-friendly buffering primitives for the connection-filter chain.
//!
//! This module folds **two** curl utilities into a single safe Rust module
//! (the planned workspace layout has no separate `bufref.rs`):
//!
//! * [`BufQ`] — the safe replacement for curl's chunked byte queue
//!   (`lib/bufq.c` / `lib/bufq.h`). A FIFO queue of fixed-size byte chunks used
//!   by the connection-filter chain (`conn/`) and the protocol read/write paths
//!   to buffer data while honoring readiness/backpressure.
//! * [`BufRef`] — the safe replacement for curl's `bufref` (`lib/bufref.c` /
//!   `lib/bufref.h`), a reference to an owned or borrowed byte buffer. curl's C
//!   `bufref` carries an explicit destructor function pointer; in Rust that
//!   ownership collapses onto [`bytes::Bytes`] and deterministic [`Drop`], so no
//!   destructor field is needed.
//!
//! # The `CURLE_AGAIN` readiness contract (observable — preserve exactly)
//!
//! The single most important behavior to reproduce is the
//! [`CURLE_AGAIN`](crate::error::CurlError::Again) signaling, because the
//! connection-filter chain relies on it to detect readiness:
//!
//! * Writing to a **full** queue that cannot accept *any* bytes returns
//!   `Err(`[`CurlError::Again`](crate::error::CurlError::Again)`)`.
//! * Reading from an **empty** queue returns
//!   `Err(`[`CurlError::Again`](crate::error::CurlError::Again)`)`.
//! * A partial write (some but not all bytes accepted) returns `Ok(n)` with the
//!   number of bytes buffered, exactly as curl returns a short count.
//!
//! # Why chunks are a `VecDeque<Chunk>` and not a bare `VecDeque<BytesMut>`
//!
//! curl's C queue threads fixed-size `struct buf_chunk` nodes (each with a fixed
//! capacity `dlen`, a read offset `r_offset`, and a write offset `w_offset`)
//! through head/tail pointers, with a hand-rolled `spare` free-list and an
//! optional shared `bufc_pool`. The Agent Action Plan (AAP §0.7.1) forbids the
//! raw-pointer manipulation that design requires, so this port stores chunks in
//! a [`std::collections::VecDeque`].
//!
//! A *bare* `VecDeque<BytesMut>` cannot, on its own, reproduce one subtle but
//! **observable** property of curl's chunk: a chunk that has been fully written
//! (`w_offset == dlen`) is considered *full* and refuses further writes **even
//! after some bytes have been read from it** — its write space is only
//! reclaimed once the chunk drains completely (then `r_offset`/`w_offset` reset
//! to 0). A naive `BytesMut::advance` model would instead reclaim write space on
//! every read, which changes when the queue reports "full" and therefore when
//! `CURLE_AGAIN` is signaled. To preserve the contract faithfully, each chunk is
//! a thin [`Chunk`] newtype wrapping a [`bytes::BytesMut`] plus a read cursor and
//! a fixed capacity. This still satisfies the AAP mandate — chunks are backed by
//! `BytesMut` held in a `VecDeque`, with no raw pointers and no manual free-list.
//!
//! # Spare chunks and the pool are non-observable
//!
//! curl keeps drained chunks on a `spare` free-list (or returns them to a shared
//! `bufc_pool`) to avoid reallocating. That recycling is purely an allocation
//! optimization and is **not** observable through the public API. This port
//! keeps a small per-queue [`Vec`] of spare chunks for the same reason, and the
//! pool ([`BufcPool`]) collapses to per-queue reuse. `BUFQ_OPT_NO_SPARES`
//! disables recycling (chunks are dropped as soon as they drain), matching curl.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` and is compiled under the module-local
//! `#![forbid(unsafe_code)]` below (consistent with the crate-wide rule). All
//! chunk storage is safe `BytesMut`/`Bytes`; there are no raw pointers.

#![forbid(unsafe_code)]

use std::collections::VecDeque;

use bytes::{Bytes, BytesMut};

use crate::error::{CurlError, Result};

// =============================================================================
// Queue options — bit values MUST match `lib/bufq.h` exactly.
// =============================================================================

/// Default behavior: the `max_chunks` limit is *hard*. Attempts to write more
/// bytes than `max_chunks * chunk_size` are refused with
/// [`CurlError::Again`](crate::error::CurlError::Again).
///
/// Mirrors `BUFQ_OPT_NONE` (`0`) from `lib/bufq.h`.
pub const BUFQ_OPT_NONE: u32 = 0;

/// Make `max_chunks` a *soft* limit: the queue still reports
/// [`is_full`](BufQ::is_full)`() == true` once `max_chunks` are in use, but it
/// will keep accepting writes beyond that limit (allocating extra chunks). This
/// is for situations where writes should preferably never fail except on memory
/// exhaustion.
///
/// Mirrors `BUFQ_OPT_SOFT_LIMIT` (`1 << 0`) from `lib/bufq.h`.
pub const BUFQ_OPT_SOFT_LIMIT: u32 = 1 << 0;

/// Do not retain spare chunks: a chunk is freed immediately when it drains
/// empty, instead of being kept on the spare free-list for reuse.
///
/// Mirrors `BUFQ_OPT_NO_SPARES` (`1 << 1`) from `lib/bufq.h`.
pub const BUFQ_OPT_NO_SPARES: u32 = 1 << 1;

// =============================================================================
// Chunk — a single fixed-capacity byte buffer with read/write cursors.
//
// Faithful analog of curl's `struct buf_chunk`:
//   * `cap`          == C `dlen`     (fixed allocation size)
//   * `buf.len()`    == C `w_offset` (one past the last written byte)
//   * `r_offset`     == C `r_offset` (first unread byte)
// Readable bytes are `buf[r_offset .. buf.len()]`. Writable space is
// `cap - buf.len()` and is NOT reclaimed by reads until the chunk drains
// completely, at which point both cursors reset to 0 (see `read_into`/`skip`).
// =============================================================================

/// A single fixed-capacity byte chunk backing [`BufQ`].
///
/// This is a private implementation detail; callers interact only with
/// [`BufQ`]. It exists (rather than using a bare [`bytes::BytesMut`]) to
/// preserve curl's chunk semantics — see the module-level documentation.
#[derive(Debug)]
struct Chunk {
    /// Backing storage. Its length is curl's `w_offset` (bytes written so far);
    /// it never exceeds [`cap`](Chunk::cap).
    buf: BytesMut,
    /// Read cursor — index of the first unread byte (curl's `r_offset`).
    r_offset: usize,
    /// Fixed capacity of this chunk (curl's `dlen`); equal to the queue's
    /// `chunk_size`.
    cap: usize,
}

impl Chunk {
    /// Create a fresh, empty chunk that can hold up to `cap` bytes.
    fn new(cap: usize) -> Self {
        Chunk {
            // Pre-reserve the full capacity so writes never reallocate.
            buf: BytesMut::with_capacity(cap),
            r_offset: 0,
            cap,
        }
    }

    /// Reset the chunk to empty, keeping its allocation for reuse
    /// (curl's `chunk_reset`).
    fn reset(&mut self) {
        self.buf.clear();
        self.r_offset = 0;
    }

    /// `true` when there are no unread bytes (curl's `chunk_is_empty`:
    /// `r_offset >= w_offset`).
    fn is_empty(&self) -> bool {
        self.r_offset >= self.buf.len()
    }

    /// `true` when the chunk has been written to capacity (curl's
    /// `chunk_is_full`: `w_offset >= dlen`). Note this is independent of how much
    /// has been read.
    fn is_full(&self) -> bool {
        self.buf.len() >= self.cap
    }

    /// Number of unread (readable) bytes (curl's `chunk_len`:
    /// `w_offset - r_offset`).
    fn readable_len(&self) -> usize {
        self.buf.len() - self.r_offset
    }

    /// Append up to `cap - w_offset` bytes from `data`, returning the number of
    /// bytes copied (curl's `chunk_append`). Returns `0` when the chunk is full.
    fn append(&mut self, data: &[u8]) -> usize {
        let writable = self.cap - self.buf.len();
        if writable == 0 {
            return 0;
        }
        let n = writable.min(data.len());
        self.buf.extend_from_slice(&data[..n]);
        n
    }

    /// Copy unread bytes into `out`, returning the number copied (curl's
    /// `chunk_read`). If the entire readable region fits in `out`, the chunk is
    /// drained and reset (cursors back to 0); otherwise the read cursor advances.
    fn read_into(&mut self, out: &mut [u8]) -> usize {
        let avail = self.readable_len();
        if avail == 0 {
            return 0;
        }
        let n = avail.min(out.len());
        let start = self.r_offset;
        out[..n].copy_from_slice(&self.buf[start..start + n]);
        if n == avail {
            // Fully drained: reset cursors (curl sets r_offset = w_offset = 0).
            self.reset();
        } else {
            self.r_offset += n;
        }
        n
    }

    /// Discard up to `amount` unread bytes, returning the number discarded
    /// (curl's `chunk_skip`). Drains-and-resets the chunk if everything readable
    /// is skipped.
    fn skip(&mut self, amount: usize) -> usize {
        let avail = self.readable_len();
        if avail == 0 {
            return 0;
        }
        let n = avail.min(amount);
        self.r_offset += n;
        if self.r_offset == self.buf.len() {
            self.reset();
        }
        n
    }

    /// Borrow the full unread region (curl's `chunk_peek`).
    fn readable(&self) -> &[u8] {
        &self.buf[self.r_offset..]
    }

    /// Borrow the unread region starting `offset` bytes in (curl's
    /// `chunk_peek_at`). `offset` must be `<= readable_len()`.
    fn readable_at(&self, offset: usize) -> &[u8] {
        &self.buf[self.r_offset + offset..]
    }

    /// Read once from `reader` into this chunk's free space, advancing the write
    /// offset by the amount produced (curl's `chunk_slurpn`).
    ///
    /// `max_len == 0` means "no caller-imposed limit besides the chunk's free
    /// space". Returns the number of bytes read (`0` signals reader EOF). The
    /// chunk is only grown by the amount actually produced; on reader error the
    /// chunk is left exactly as it was.
    fn slurpn<R>(&mut self, max_len: usize, reader: &mut R) -> Result<usize>
    where
        R: FnMut(&mut [u8]) -> Result<usize>,
    {
        let w = self.buf.len();
        let free = self.cap - w;
        if free == 0 {
            // Caller guarantees a non-full tail, but stay faithful to curl which
            // returns CURLE_AGAIN here.
            return Err(CurlError::Again);
        }
        let want = if max_len != 0 && free > max_len {
            max_len
        } else {
            free
        };
        // Expose a writable window of `want` zero-filled bytes for the reader.
        self.buf.resize(w + want, 0);
        match reader(&mut self.buf[w..w + want]) {
            Ok(n) => {
                // Defensively clamp: a misbehaving reader must not desync `w_offset`.
                let n = n.min(want);
                self.buf.truncate(w + n);
                Ok(n)
            }
            Err(e) => {
                // Restore the chunk; curl only advances `w_offset` on success.
                self.buf.truncate(w);
                Err(e)
            }
        }
    }
}

// =============================================================================
// BufcPool — a chunk pool descriptor.
//
// curl's `struct bufc_pool` is a free-list of same-size chunks shared by many
// `bufq` instances to avoid reallocation. Sharing is purely an allocation
// optimization and is NOT observable through the queue API, so this port models
// the pool as a lightweight descriptor (chunk size + spare cap); a queue built
// from a pool simply uses the pool's `chunk_size` and bounds its own spare list
// by the pool's `spare_max`. See the module-level documentation.
// =============================================================================

/// A descriptor for chunk pooling (analog of curl's `struct bufc_pool`).
///
/// Pool *sharing* across queues collapses to per-queue chunk reuse in this safe
/// port; the descriptor carries the chunk size and the maximum number of spare
/// chunks to retain. Construct one with [`BufcPool::new`] (or the curl-named
/// [`BufcPool::Curl_bufcp_init`]) and build a queue from it with
/// [`BufQ::from_pool`] / [`BufQ::Curl_bufq_initp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufcPool {
    /// Size of every chunk provided by this pool (curl's `chunk_size`).
    chunk_size: usize,
    /// Maximum number of spare chunks to retain for reuse (curl's `spare_max`).
    spare_max: usize,
}

impl BufcPool {
    /// Create a pool descriptor for chunks of `chunk_size` bytes, retaining up
    /// to `spare_max` spare chunks. Both values are clamped to at least 1 to
    /// avoid degenerate queues (curl asserts both are `> 0`).
    pub fn new(chunk_size: usize, spare_max: usize) -> Self {
        debug_assert!(chunk_size > 0, "chunk_size must be > 0");
        debug_assert!(spare_max > 0, "spare_max must be > 0");
        BufcPool {
            chunk_size: chunk_size.max(1),
            spare_max: spare_max.max(1),
        }
    }
}

#[allow(non_snake_case)]
impl BufcPool {
    /// curl-named constructor — see [`BufcPool::new`] (curl's `Curl_bufcp_init`).
    pub fn Curl_bufcp_init(chunk_size: usize, spare_max: usize) -> Self {
        BufcPool::new(chunk_size, spare_max)
    }

    /// curl-named teardown (curl's `Curl_bufcp_free`). A no-op in Rust: the
    /// descriptor owns no heap resources, and any queue's spare chunks are freed
    /// by [`Drop`] when the queue is dropped. Provided for call-site parity.
    pub fn Curl_bufcp_free(&mut self) {}
}

// =============================================================================
// BufQ — the chunked byte queue.
// =============================================================================

/// A FIFO queue of fixed-size byte chunks — the safe replacement for curl's
/// `struct bufq` (`lib/bufq.c`).
///
/// Bytes are written to the tail and read from the head. The queue can hold up
/// to `max_chunks * chunk_size` bytes by default; see [`BUFQ_OPT_SOFT_LIMIT`]
/// and [`BUFQ_OPT_NO_SPARES`] for option semantics.
///
/// Construct with [`BufQ::new`] / [`BufQ::new_with_opts`] / [`BufQ::from_pool`]
/// (or the curl-named [`BufQ::Curl_bufq_init`] / [`Curl_bufq_init2`](BufQ::Curl_bufq_init2)
/// / [`Curl_bufq_initp`](BufQ::Curl_bufq_initp)).
#[derive(Debug)]
pub struct BufQ {
    /// Active chunks, ordered head (oldest, read side) to tail (newest, write
    /// side). Backed by `BytesMut` per the AAP mandate.
    chunks: VecDeque<Chunk>,
    /// Recycled empty chunks kept for reuse (curl's `spare` free-list / pool).
    /// Non-observable allocation optimization.
    spare: Vec<Chunk>,
    /// Fixed size of every chunk (curl's `chunk_size`).
    chunk_size: usize,
    /// Maximum number of chunks before the queue reports full (curl's
    /// `max_chunks`).
    max_chunks: usize,
    /// Upper bound on retained spare chunks. Equals `max_chunks` for a plain
    /// queue (the natural bound) or the pool's `spare_max` for a pooled queue.
    max_spare: usize,
    /// Option bit-flags (`BUFQ_OPT_*`).
    opts: u32,
}

impl BufQ {
    /// Create a queue holding up to `max_chunks` chunks of `chunk_size` bytes
    /// each, with default options (hard limit, spares retained). Equivalent to
    /// curl's `Curl_bufq_init`.
    ///
    /// `chunk_size` and `max_chunks` are clamped to at least 1 (curl asserts
    /// both are `> 0`).
    pub fn new(chunk_size: usize, max_chunks: usize) -> Self {
        Self::new_with_opts(chunk_size, max_chunks, BUFQ_OPT_NONE)
    }

    /// Create a queue with the given option flags (`BUFQ_OPT_*`). Equivalent to
    /// curl's `Curl_bufq_init2`.
    pub fn new_with_opts(chunk_size: usize, max_chunks: usize, opts: u32) -> Self {
        debug_assert!(chunk_size > 0, "chunk_size must be > 0");
        debug_assert!(max_chunks > 0, "max_chunks must be > 0");
        let max_chunks = max_chunks.max(1);
        BufQ {
            chunks: VecDeque::new(),
            spare: Vec::new(),
            chunk_size: chunk_size.max(1),
            max_chunks,
            // A plain queue's spare list is naturally bounded by max_chunks.
            max_spare: max_chunks,
            opts,
        }
    }

    /// Create a queue that draws chunks from `pool` (using the pool's
    /// `chunk_size` and bounding retained spares by the pool's `spare_max`).
    /// Equivalent to curl's `Curl_bufq_initp`.
    pub fn from_pool(pool: &BufcPool, max_chunks: usize, opts: u32) -> Self {
        debug_assert!(max_chunks > 0, "max_chunks must be > 0");
        BufQ {
            chunks: VecDeque::new(),
            spare: Vec::new(),
            chunk_size: pool.chunk_size,
            max_chunks: max_chunks.max(1),
            max_spare: pool.spare_max,
            opts,
        }
    }

    // ---- private helpers ----------------------------------------------------

    /// Total number of chunks the queue currently owns — active plus spare
    /// (curl's `chunk_count`, which counts `head + spare`).
    fn chunk_count(&self) -> usize {
        self.chunks.len() + self.spare.len()
    }

    /// Obtain a chunk to write into, reusing a spare if available, otherwise
    /// allocating a new one — unless that would exceed the hard `max_chunks`
    /// limit (curl's `get_spare`). Returns `None` only when the hard limit is
    /// reached and `BUFQ_OPT_SOFT_LIMIT` is not set.
    ///
    /// Note: curl can also fail here on `malloc` failure (`CURLE_OUT_OF_MEMORY`).
    /// Rust allocation is infallible (it aborts on OOM), so the only `None` case
    /// is the hard-limit case — which is exactly the `CURLE_AGAIN` condition.
    fn get_spare(&mut self) -> Option<Chunk> {
        if let Some(mut chunk) = self.spare.pop() {
            chunk.reset();
            return Some(chunk);
        }
        // No spare available. With the spare list empty, `chunk_count()` equals
        // the number of active chunks, matching curl's check at this point.
        if self.chunk_count() >= self.max_chunks && (self.opts & BUFQ_OPT_SOFT_LIMIT) == 0 {
            return None;
        }
        Some(Chunk::new(self.chunk_size))
    }

    /// Ensure the tail chunk has room to write, allocating/recycling a new tail
    /// if the current one is full (curl's `get_non_full_tail`). Returns `false`
    /// when no chunk could be obtained (hard limit reached).
    fn ensure_writable_tail(&mut self) -> bool {
        if let Some(tail) = self.chunks.back() {
            if !tail.is_full() {
                return true;
            }
        }
        match self.get_spare() {
            Some(chunk) => {
                self.chunks.push_back(chunk);
                true
            }
            None => false,
        }
    }

    /// Remove drained (empty) chunks from the head, recycling them to the spare
    /// list or freeing them per the options (curl's `prune_head`).
    fn prune_head(&mut self) {
        while self.chunks.front().is_some_and(Chunk::is_empty) {
            let chunk = self
                .chunks
                .pop_front()
                .expect("front exists per loop condition");
            // Reproduce curl's `chunk_count` value at the decision point: in C the
            // chunk is detached from the head list but not yet freed/spared, so it
            // is still counted. We have already popped it, hence the `+ 1`.
            let chunk_count = self.chunks.len() + 1 + self.spare.len();
            let no_spares = (self.opts & BUFQ_OPT_NO_SPARES) != 0;
            if no_spares || chunk_count > self.max_chunks || self.spare.len() >= self.max_spare {
                // Free the chunk (drop its allocation).
                drop(chunk);
            } else {
                let mut chunk = chunk;
                chunk.reset();
                self.spare.push(chunk);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// BufQ — idiomatic Rust API (the primary implementation). The curl-named
// methods further below delegate to these.
// -----------------------------------------------------------------------------

impl BufQ {
    /// Total number of readable bytes currently queued (curl's `Curl_bufq_len`).
    pub fn len(&self) -> usize {
        self.chunks.iter().map(Chunk::readable_len).sum()
    }

    /// `true` when there are no readable bytes (curl's `Curl_bufq_is_empty`).
    ///
    /// Mirrors curl exactly by inspecting the head chunk: drained head chunks
    /// are pruned eagerly by [`read`](BufQ::read)/[`skip`](BufQ::skip), so a
    /// non-empty queue always has a non-empty head.
    pub fn is_empty(&self) -> bool {
        match self.chunks.front() {
            None => true,
            Some(head) => head.is_empty(),
        }
    }

    /// `true` when the queue has no space left (curl's `Curl_bufq_is_full`).
    ///
    /// Under [`BUFQ_OPT_SOFT_LIMIT`] this still reports `true` once `max_chunks`
    /// are in use even though further writes are accepted.
    pub fn is_full(&self) -> bool {
        // No tail (empty queue) or a spare available => not full.
        if self.chunks.is_empty() || !self.spare.is_empty() {
            return false;
        }
        let count = self.chunk_count();
        if count < self.max_chunks {
            return false;
        }
        if count > self.max_chunks {
            return true;
        }
        // Exactly at the limit with no spare: full iff the tail chunk is full.
        self.chunks.back().is_some_and(Chunk::is_full)
    }

    /// Append `data` to the tail of the queue, copying as many bytes as there is
    /// room for and returning that count (curl's `Curl_bufq_write`).
    ///
    /// Returns `Err(`[`CurlError::Again`](crate::error::CurlError::Again)`)` only
    /// when the queue is full and **no** bytes could be written. A partial write
    /// returns `Ok(n)` with `0 < n < data.len()`.
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        let mut written = 0usize;
        let mut rest = data;
        while !rest.is_empty() {
            if !self.ensure_writable_tail() {
                // Hard limit reached and soft-limit not set: cannot grow.
                break;
            }
            let tail = self
                .chunks
                .back_mut()
                .expect("tail exists after ensure_writable_tail");
            let n = tail.append(rest);
            if n == 0 {
                break;
            }
            written += n;
            rest = &rest[n..];
        }
        if written == 0 && !rest.is_empty() {
            Err(CurlError::Again)
        } else {
            Ok(written)
        }
    }

    /// Copy up to `out.len()` bytes from the head of the queue into `out`,
    /// consuming them, and return the count (curl's `Curl_bufq_read`).
    ///
    /// Returns `Err(`[`CurlError::Again`](crate::error::CurlError::Again)`)` when
    /// the queue is empty.
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        let mut nread = 0usize;
        let mut dst = out;
        while !dst.is_empty() {
            // Scope the head borrow so `prune_head` can take `&mut self` after.
            let n = match self.chunks.front_mut() {
                Some(front) => front.read_into(dst),
                None => break,
            };
            if n > 0 {
                nread += n;
                dst = &mut dst[n..];
            }
            // Drop drained head chunks (and, when n == 0, the empty head that
            // produced no bytes — guaranteeing forward progress).
            self.prune_head();
        }
        if nread == 0 {
            Err(CurlError::Again)
        } else {
            Ok(nread)
        }
    }

    /// Borrow the readable bytes of the first non-empty chunk without consuming
    /// them (curl's `Curl_bufq_peek`). Returns `None` when the queue is empty.
    ///
    /// Repeated calls return the same slice until the queue is modified (e.g. by
    /// [`skip`](BufQ::skip) or [`read`](BufQ::read)).
    pub fn peek(&self) -> Option<&[u8]> {
        // curl prunes a leading empty head before peeking; an immutable peek
        // cannot recycle, so it simply skips any transient leading-empty chunks
        // and returns the first chunk that has data. The returned slice is
        // identical to what curl would return after pruning.
        for chunk in &self.chunks {
            if !chunk.is_empty() {
                return Some(chunk.readable());
            }
        }
        None
    }

    /// Borrow up to a contiguous run of readable bytes starting `offset` bytes
    /// into the queue (curl's `Curl_bufq_peek_at`). Returns `None` when `offset`
    /// is at or beyond the readable length.
    ///
    /// The returned slice never spans a chunk boundary: it runs from `offset` to
    /// the end of the chunk that contains `offset`.
    pub fn peek_at(&self, offset: usize) -> Option<&[u8]> {
        let mut offset = offset;
        for chunk in &self.chunks {
            let clen = chunk.readable_len();
            // Faithful to curl: stop at the first empty chunk encountered.
            if clen == 0 {
                break;
            }
            if offset >= clen {
                offset -= clen;
                continue;
            }
            return Some(chunk.readable_at(offset));
        }
        None
    }

    /// Discard up to `amount` bytes from the head of the queue (curl's
    /// `Curl_bufq_skip`). Skipping more than is buffered empties the queue.
    pub fn skip(&mut self, amount: usize) {
        let mut amount = amount;
        while amount > 0 && !self.chunks.is_empty() {
            let n = match self.chunks.front_mut() {
                Some(front) => front.skip(amount),
                None => break,
            };
            amount -= n;
            self.prune_head();
        }
    }

    /// Empty the queue, keeping allocated chunks for reuse (curl's
    /// `Curl_bufq_reset`). All active chunks move to the spare list.
    pub fn reset(&mut self) {
        while let Some(mut chunk) = self.chunks.pop_front() {
            chunk.reset();
            self.spare.push(chunk);
        }
    }

    /// Empty the queue and release all chunk allocations, active and spare
    /// (curl's `Curl_bufq_free`).
    ///
    /// In Rust this is rarely needed explicitly — dropping the [`BufQ`] frees
    /// everything — but it is provided for parity and to reclaim memory eagerly.
    pub fn clear(&mut self) {
        self.chunks.clear();
        self.spare.clear();
    }
}

// -----------------------------------------------------------------------------
// BufQ — callback-driven I/O (idiomatic). Writers/readers are synchronous
// closures, faithful to curl's `Curl_bufq_writer`/`Curl_bufq_reader` function
// pointers (which are themselves synchronous and use `CURLE_AGAIN` to signal
// "would block"). An async caller drives these from within its async context,
// supplying a closure over a non-blocking I/O step that returns
// `Err(CurlError::Again)` when the underlying transport would block.
// -----------------------------------------------------------------------------

impl BufQ {
    /// Drain the queue into `writer`, passing each chunk's readable slice in
    /// turn and skipping the bytes the writer accepts (curl's `Curl_bufq_pass`).
    ///
    /// `writer` returns the number of bytes it consumed, or
    /// `Err(`[`CurlError::Again`](crate::error::CurlError::Again)`)` to signal it
    /// would block. Returns the total number of bytes passed:
    ///
    /// * If the writer blocks (or accepts `0`) **after** some bytes were already
    ///   passed, this returns `Ok(total)` — the partial progress is reported as
    ///   success, matching curl.
    /// * If the writer blocks (or accepts `0`) on the **very first** chunk, this
    ///   returns `Err(CurlError::Again)`.
    /// * Any other writer error is propagated.
    pub fn pass<W>(&mut self, mut writer: W) -> Result<usize>
    where
        W: FnMut(&[u8]) -> Result<usize>,
    {
        let mut passed = 0usize;
        loop {
            // Scope the peek borrow so we can `skip` (which needs `&mut self`)
            // once the writer has consumed the slice.
            let n = {
                let slice = match self.peek() {
                    Some(slice) => slice,
                    None => break,
                };
                match writer(slice) {
                    Ok(0) => {
                        if passed == 0 {
                            return Err(CurlError::Again);
                        }
                        break;
                    }
                    Ok(n) => n,
                    Err(CurlError::Again) => {
                        if passed > 0 {
                            break;
                        }
                        return Err(CurlError::Again);
                    }
                    Err(e) => return Err(e),
                }
            };
            passed += n;
            self.skip(n);
        }
        Ok(passed)
    }

    /// Write `data`, flushing the queue to `writer` to make room when it is full
    /// (curl's `Curl_bufq_write_pass`).
    ///
    /// This buffers as much of `data` as fits; when the queue is full it first
    /// drains via [`pass`](BufQ::pass) and then continues buffering. Returns the
    /// number of bytes of `data` that were buffered. Semantics for blocking and
    /// partial progress match curl: a block after partial progress yields
    /// `Ok(total)`, a block before any progress yields `Err(CurlError::Again)`,
    /// and real writer errors propagate.
    pub fn write_pass<W>(&mut self, data: &[u8], mut writer: W) -> Result<usize>
    where
        W: FnMut(&[u8]) -> Result<usize>,
    {
        let mut written = 0usize;
        let mut rest = data;
        while !rest.is_empty() {
            if self.is_full() {
                // Try to make room. `&mut writer` is itself `FnMut`.
                match self.pass(&mut writer) {
                    Ok(_) => {}
                    Err(CurlError::Again) => break, // would block, queue stays full
                    Err(e) => return Err(e),
                }
            }
            match self.write(rest) {
                Ok(0) => break, // edge case: nothing written though room expected
                Ok(n) => {
                    rest = &rest[n..];
                    written += n;
                }
                Err(CurlError::Again) => {
                    return if written > 0 {
                        Ok(written)
                    } else {
                        Err(CurlError::Again)
                    };
                }
                Err(e) => return Err(e),
            }
        }
        if written == 0 && !rest.is_empty() {
            Err(CurlError::Again)
        } else {
            Ok(written)
        }
    }

    /// Read **once** from `reader`, appending up to `max_len` bytes (or, when
    /// `max_len == 0`, up to the tail chunk's free space) to the queue (curl's
    /// `Curl_bufq_sipn`).
    ///
    /// Returns the number of bytes read (`0` signals reader EOF), or
    /// `Err(`[`CurlError::Again`](crate::error::CurlError::Again)`)` when the
    /// queue is full and cannot grow.
    pub fn sipn<R>(&mut self, max_len: usize, mut reader: R) -> Result<usize>
    where
        R: FnMut(&mut [u8]) -> Result<usize>,
    {
        if !self.ensure_writable_tail() {
            // Full (curl would also distinguish CURLE_OUT_OF_MEMORY, which cannot
            // occur with Rust's infallible allocation).
            return Err(CurlError::Again);
        }
        let tail = self.chunks.back_mut().expect("tail exists");
        tail.slurpn(max_len, &mut reader)
    }

    /// Repeatedly read from `reader`, appending to the queue until the reader
    /// blocks, reaches EOF, or returns a short read, or the queue fills (curl's
    /// `Curl_bufq_slurp`).
    ///
    /// Returns the total number of bytes read. A block after partial progress
    /// yields `Ok(total)`; a block before any progress yields
    /// `Err(CurlError::Again)`; reader errors propagate.
    pub fn slurp<R>(&mut self, reader: R) -> Result<usize>
    where
        R: FnMut(&mut [u8]) -> Result<usize>,
    {
        self.slurp_n(0, reader)
    }

    /// Shared implementation of [`slurp`](BufQ::slurp) with an optional overall
    /// byte limit (curl's internal `bufq_slurpn`). `max_len == 0` means no limit
    /// beyond the queue's capacity.
    fn slurp_n<R>(&mut self, max_len: usize, mut reader: R) -> Result<usize>
    where
        R: FnMut(&mut [u8]) -> Result<usize>,
    {
        let mut max_len = max_len;
        let mut nread = 0usize;
        loop {
            match self.sipn(max_len, &mut reader) {
                Ok(0) => break, // reader EOF
                Ok(n) => {
                    nread += n;
                    if max_len != 0 {
                        max_len -= n;
                        if max_len == 0 {
                            break;
                        }
                    }
                    // A short read (tail not filled) means the reader gave us less
                    // than we asked for; stop slurping (curl does the same).
                    if self.chunks.back().is_some_and(|c| !c.is_full()) {
                        break;
                    }
                }
                Err(CurlError::Again) => {
                    if nread == 0 {
                        return Err(CurlError::Again);
                    }
                    break; // blocked after partial progress -> report success
                }
                Err(e) => return Err(e),
            }
        }
        Ok(nread)
    }
}

// -----------------------------------------------------------------------------
// BufQ — curl-named API surface.
//
// These keep curl's original `Curl_bufq_*` names and semantics to ease porting
// of C call sites. They delegate to the idiomatic methods above. The block is
// annotated `#[allow(non_snake_case)]` because the names intentionally preserve
// curl's mixed-case identifiers (matching the convention used elsewhere in this
// crate, e.g. the `Curl_llist_*` wrappers).
// -----------------------------------------------------------------------------

#[allow(non_snake_case)]
impl BufQ {
    /// curl's `Curl_bufq_init` — see [`BufQ::new`].
    pub fn Curl_bufq_init(chunk_size: usize, max_chunks: usize) -> Self {
        BufQ::new(chunk_size, max_chunks)
    }

    /// curl's `Curl_bufq_init2` — see [`BufQ::new_with_opts`].
    pub fn Curl_bufq_init2(chunk_size: usize, max_chunks: usize, opts: u32) -> Self {
        BufQ::new_with_opts(chunk_size, max_chunks, opts)
    }

    /// curl's `Curl_bufq_initp` — see [`BufQ::from_pool`].
    pub fn Curl_bufq_initp(pool: &BufcPool, max_chunks: usize, opts: u32) -> Self {
        BufQ::from_pool(pool, max_chunks, opts)
    }

    /// curl's `Curl_bufq_len` — see [`BufQ::len`].
    pub fn Curl_bufq_len(&self) -> usize {
        self.len()
    }

    /// curl's `Curl_bufq_is_empty` — see [`BufQ::is_empty`].
    pub fn Curl_bufq_is_empty(&self) -> bool {
        self.is_empty()
    }

    /// curl's `Curl_bufq_is_full` — see [`BufQ::is_full`].
    pub fn Curl_bufq_is_full(&self) -> bool {
        self.is_full()
    }

    /// curl's `Curl_bufq_write` — see [`BufQ::write`].
    pub fn Curl_bufq_write(&mut self, data: &[u8]) -> Result<usize> {
        self.write(data)
    }

    /// curl's `Curl_bufq_cwrite` (the `char*` variant). Identical to
    /// [`Curl_bufq_write`](BufQ::Curl_bufq_write) here, since Rust represents
    /// both `char*` and `uint8_t*` buffers as `&[u8]`. Provided for call-site
    /// parity.
    pub fn Curl_bufq_cwrite(&mut self, data: &[u8]) -> Result<usize> {
        self.write(data)
    }

    /// curl's `Curl_bufq_read` — see [`BufQ::read`].
    pub fn Curl_bufq_read(&mut self, out: &mut [u8]) -> Result<usize> {
        self.read(out)
    }

    /// curl's `Curl_bufq_cread` (the `char*` variant). Identical to
    /// [`Curl_bufq_read`](BufQ::Curl_bufq_read) here; see
    /// [`Curl_bufq_cwrite`](BufQ::Curl_bufq_cwrite).
    pub fn Curl_bufq_cread(&mut self, out: &mut [u8]) -> Result<usize> {
        self.read(out)
    }

    /// curl's `Curl_bufq_peek` — see [`BufQ::peek`].
    pub fn Curl_bufq_peek(&self) -> Option<&[u8]> {
        self.peek()
    }

    /// curl's `Curl_bufq_peek_at` — see [`BufQ::peek_at`].
    pub fn Curl_bufq_peek_at(&self, offset: usize) -> Option<&[u8]> {
        self.peek_at(offset)
    }

    /// curl's `Curl_bufq_skip` — see [`BufQ::skip`].
    pub fn Curl_bufq_skip(&mut self, amount: usize) {
        self.skip(amount);
    }

    /// curl's `Curl_bufq_reset` — see [`BufQ::reset`].
    pub fn Curl_bufq_reset(&mut self) {
        self.reset();
    }

    /// curl's `Curl_bufq_free` — see [`BufQ::clear`].
    pub fn Curl_bufq_free(&mut self) {
        self.clear();
    }

    /// curl's `Curl_bufq_pass` — see [`BufQ::pass`].
    pub fn Curl_bufq_pass<W>(&mut self, writer: W) -> Result<usize>
    where
        W: FnMut(&[u8]) -> Result<usize>,
    {
        self.pass(writer)
    }

    /// curl's `Curl_bufq_write_pass` — see [`BufQ::write_pass`].
    pub fn Curl_bufq_write_pass<W>(&mut self, data: &[u8], writer: W) -> Result<usize>
    where
        W: FnMut(&[u8]) -> Result<usize>,
    {
        self.write_pass(data, writer)
    }

    /// curl's `Curl_bufq_sipn` — see [`BufQ::sipn`].
    pub fn Curl_bufq_sipn<R>(&mut self, max_len: usize, reader: R) -> Result<usize>
    where
        R: FnMut(&mut [u8]) -> Result<usize>,
    {
        self.sipn(max_len, reader)
    }

    /// curl's `Curl_bufq_slurp` — see [`BufQ::slurp`].
    pub fn Curl_bufq_slurp<R>(&mut self, reader: R) -> Result<usize>
    where
        R: FnMut(&mut [u8]) -> Result<usize>,
    {
        self.slurp(reader)
    }
}

// =============================================================================
// BufRef — a reference to an owned or borrowed byte buffer (folded-in bufref).
//
// curl's `struct bufref` carries `{ dtor, ptr, len }` where `dtor` is a function
// pointer that frees `ptr`. In safe Rust the buffer is simply owned by a
// `bytes::Bytes`; ownership transfer and the destructor collapse onto `Bytes`
// move semantics and deterministic `Drop`, so there is no `dtor` field. The C
// `len` field is preserved as the *logical* length, which is independent of the
// backing buffer's physical length (notably after `memdup0`, which appends a NUL
// terminator that is excluded from `len`).
// =============================================================================

/// A reference to an owned or borrowed byte buffer — the safe replacement for
/// curl's `struct bufref` (`lib/bufref.c`).
///
/// The buffer is held in a [`bytes::Bytes`]; dropping or replacing the
/// [`BufRef`] frees it (curl's destructor mechanism). [`memdup0`](BufRef::memdup0)
/// makes a NUL-terminated owned copy for C-string compatibility, while
/// [`len`](BufRef::len) reports the logical length **excluding** that terminator.
#[derive(Debug, Clone, Default)]
pub struct BufRef {
    /// Backing buffer. May be longer than [`len`](BufRef::len) — e.g. after
    /// [`memdup0`](BufRef::memdup0) it carries a trailing NUL byte.
    data: Bytes,
    /// Logical length in bytes (curl's `len`); always `<= data.len()`.
    len: usize,
}

impl BufRef {
    /// Create an empty buffer reference (curl's `Curl_bufref_init`).
    pub fn new() -> Self {
        BufRef {
            data: Bytes::new(),
            len: 0,
        }
    }

    /// `true` when the reference holds no data.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The logical length in bytes (curl's `Curl_bufref_len`).
    pub fn len(&self) -> usize {
        self.len
    }

    /// Borrow the referenced data as a byte slice of [`len`](BufRef::len) bytes
    /// (the safe analog of curl's `Curl_bufref_uptr`/`Curl_bufref_ptr`).
    ///
    /// Any trailing NUL added by [`memdup0`](BufRef::memdup0) is **not** included
    /// in the returned slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Replace the referenced buffer with `data`, taking ownership (curl's
    /// `Curl_bufref_set`). The previous buffer is dropped. The logical length is
    /// set to the new buffer's length.
    pub fn set(&mut self, data: impl Into<Bytes>) {
        let data = data.into();
        self.len = data.len();
        self.data = data;
    }

    /// Copy `src` into a freshly owned, NUL-terminated buffer (curl's
    /// `Curl_bufref_memdup0`). The stored [`len`](BufRef::len) equals `src.len()`
    /// (the NUL is excluded), but the backing buffer carries the terminator so
    /// the data can be handed to C as a C string.
    pub fn memdup0(&mut self, src: &[u8]) {
        let mut owned = Vec::with_capacity(src.len() + 1);
        owned.extend_from_slice(src);
        owned.push(0);
        self.data = Bytes::from(owned);
        self.len = src.len();
    }

    /// Return an independent, NUL-terminated copy of the referenced data (curl's
    /// `Curl_bufref_dup` macro, which `strdup`s the buffer). The returned vector
    /// is `len + 1` bytes: the logical data followed by a `0` terminator.
    pub fn dup(&self) -> Vec<u8> {
        let mut copy = Vec::with_capacity(self.len + 1);
        copy.extend_from_slice(self.as_slice());
        copy.push(0);
        copy
    }

    /// Release the referenced buffer and reset to empty (curl's
    /// `Curl_bufref_free`). The buffer's memory is reclaimed by dropping it.
    pub fn clear(&mut self) {
        self.data = Bytes::new();
        self.len = 0;
    }
}

#[allow(non_snake_case)]
impl BufRef {
    /// curl's `Curl_bufref_init` — see [`BufRef::new`].
    pub fn Curl_bufref_init() -> Self {
        BufRef::new()
    }

    /// curl's `Curl_bufref_set` — see [`BufRef::set`].
    pub fn Curl_bufref_set(&mut self, data: impl Into<Bytes>) {
        self.set(data);
    }

    /// curl's `Curl_bufref_ptr` (the `const char*` accessor) — see
    /// [`BufRef::as_slice`]. Returns the logical `len`-byte slice.
    pub fn Curl_bufref_ptr(&self) -> &[u8] {
        self.as_slice()
    }

    /// curl's `Curl_bufref_uptr` (the `const unsigned char*` accessor). Identical
    /// to [`Curl_bufref_ptr`](BufRef::Curl_bufref_ptr) in Rust, where both map to
    /// `&[u8]`.
    pub fn Curl_bufref_uptr(&self) -> &[u8] {
        self.as_slice()
    }

    /// curl's `Curl_bufref_len` — see [`BufRef::len`].
    pub fn Curl_bufref_len(&self) -> usize {
        self.len()
    }

    /// curl's `Curl_bufref_memdup0` — see [`BufRef::memdup0`].
    pub fn Curl_bufref_memdup0(&mut self, src: &[u8]) {
        self.memdup0(src);
    }

    /// curl's `Curl_bufref_dup` — see [`BufRef::dup`].
    pub fn Curl_bufref_dup(&self) -> Vec<u8> {
        self.dup()
    }

    /// curl's `Curl_bufref_free` — see [`BufRef::clear`].
    pub fn Curl_bufref_free(&mut self) {
        self.clear();
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- option bit values ---------------------------------------------------

    #[test]
    fn option_bit_values_match_curl() {
        assert_eq!(BUFQ_OPT_NONE, 0);
        assert_eq!(BUFQ_OPT_SOFT_LIMIT, 1);
        assert_eq!(BUFQ_OPT_NO_SPARES, 2);
    }

    // ---- write/read round-trips ---------------------------------------------

    #[test]
    fn write_read_roundtrip_within_one_chunk() {
        let mut q = BufQ::new(16, 4);
        assert_eq!(q.write(b"hello").unwrap(), 5);
        assert_eq!(q.len(), 5);
        assert!(!q.is_empty());
        let mut out = [0u8; 8];
        assert_eq!(q.read(&mut out).unwrap(), 5);
        assert_eq!(&out[..5], b"hello");
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn write_read_roundtrip_across_chunk_boundaries() {
        // chunk_size 4, so "HelloWorld!" (11 bytes) spans 3 chunks (4 + 4 + 3).
        let mut q = BufQ::new(4, 8);
        let msg = b"HelloWorld!";
        assert_eq!(q.write(msg).unwrap(), msg.len());
        assert_eq!(q.len(), msg.len());
        // Read it all back in one buffer.
        let mut out = vec![0u8; 32];
        let n = q.read(&mut out).unwrap();
        assert_eq!(n, msg.len());
        assert_eq!(&out[..n], msg);
        assert!(q.is_empty());
    }

    #[test]
    fn read_in_small_increments_across_chunks() {
        let mut q = BufQ::new(4, 8);
        q.write(b"abcdefghij").unwrap(); // 10 bytes over 3 chunks
        let mut collected = Vec::new();
        let mut out = [0u8; 3];
        loop {
            match q.read(&mut out) {
                Ok(n) => collected.extend_from_slice(&out[..n]),
                Err(CurlError::Again) => break,
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        assert_eq!(collected, b"abcdefghij");
    }

    // ---- empty / full CURLE_AGAIN signaling ---------------------------------

    #[test]
    fn empty_read_returns_again() {
        let mut q = BufQ::new(8, 2);
        let mut out = [0u8; 4];
        assert_eq!(q.read(&mut out), Err(CurlError::Again));
    }

    #[test]
    fn full_write_returns_again() {
        // Hard limit: capacity is 2 * 4 = 8 bytes.
        let mut q = BufQ::new(4, 2);
        assert_eq!(q.write(b"01234567").unwrap(), 8);
        assert!(q.is_full());
        // Now completely full; another write writes nothing -> AGAIN.
        assert_eq!(q.write(b"x"), Err(CurlError::Again));
    }

    #[test]
    fn write_returns_short_count_when_partially_full() {
        let mut q = BufQ::new(4, 2); // capacity 8
        assert_eq!(q.write(b"012345").unwrap(), 6); // 6 of 8 used
                                                    // Try to write 5 more; only 2 fit -> short count, not AGAIN.
        assert_eq!(q.write(b"ABCDE").unwrap(), 2);
        assert!(q.is_full());
        assert_eq!(q.write(b"Z"), Err(CurlError::Again));
    }

    // ---- the key non-reclaiming chunk semantic ------------------------------

    #[test]
    fn partial_read_does_not_make_full_chunk_writable() {
        // A single chunk that is full stays full even after a partial read.
        let mut q = BufQ::new(4, 1);
        assert_eq!(q.write(b"abcd").unwrap(), 4);
        assert!(q.is_full());
        let mut out = [0u8; 2];
        assert_eq!(q.read(&mut out).unwrap(), 2);
        assert_eq!(&out, b"ab");
        // Tail chunk is still full (write offset reached capacity); cannot grow.
        assert!(q.is_full());
        assert_eq!(q.write(b"x"), Err(CurlError::Again));
        // Drain the rest; the chunk is then recycled and writable again.
        assert_eq!(q.read(&mut out).unwrap(), 2);
        assert_eq!(&out, b"cd");
        assert!(q.is_empty());
        assert_eq!(q.write(b"wxyz").unwrap(), 4);
    }

    // ---- peek / peek_at / skip / len ----------------------------------------

    #[test]
    fn peek_returns_head_without_consuming() {
        let mut q = BufQ::new(4, 4);
        q.write(b"abcdef").unwrap(); // 4 in chunk 1, 2 in chunk 2
                                     // peek returns only the first chunk's readable slice.
        assert_eq!(q.peek(), Some(&b"abcd"[..]));
        // Repeated peek is stable.
        assert_eq!(q.peek(), Some(&b"abcd"[..]));
        assert_eq!(q.len(), 6);
    }

    #[test]
    fn peek_at_walks_offsets() {
        let mut q = BufQ::new(4, 4);
        q.write(b"abcdefgh").unwrap(); // chunk1="abcd", chunk2="efgh"
        assert_eq!(q.peek_at(0), Some(&b"abcd"[..]));
        assert_eq!(q.peek_at(2), Some(&b"cd"[..]));
        // Offset lands in the second chunk.
        assert_eq!(q.peek_at(4), Some(&b"efgh"[..]));
        assert_eq!(q.peek_at(6), Some(&b"gh"[..]));
        // Offset at/after the end -> None.
        assert_eq!(q.peek_at(8), None);
        assert_eq!(q.peek_at(100), None);
    }

    #[test]
    fn skip_discards_from_head() {
        let mut q = BufQ::new(4, 4);
        q.write(b"abcdefgh").unwrap();
        q.skip(3); // drop "abc"
        assert_eq!(q.len(), 5);
        assert_eq!(q.peek(), Some(&b"d"[..])); // remainder of chunk 1
                                               // Skipping more than buffered empties the queue.
        q.skip(100);
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.peek(), None);
    }

    #[test]
    fn is_empty_and_is_full_transitions() {
        let mut q = BufQ::new(4, 2); // capacity 8
        assert!(q.is_empty());
        assert!(!q.is_full());
        q.write(b"0123").unwrap();
        assert!(!q.is_empty());
        assert!(!q.is_full()); // one chunk used of two
        q.write(b"4567").unwrap();
        assert!(q.is_full()); // both chunks full
        let mut out = [0u8; 8];
        assert_eq!(q.read(&mut out).unwrap(), 8);
        assert!(q.is_empty());
        assert!(!q.is_full());
    }

    // ---- spare / no-spares behavior -----------------------------------------

    #[test]
    fn default_retains_spare_chunk_after_drain() {
        let mut q = BufQ::new(4, 4);
        q.write(b"abcd").unwrap();
        assert!(q.spare.is_empty());
        let mut out = [0u8; 4];
        q.read(&mut out).unwrap();
        // Drained chunk is recycled to the spare list (allocation optimization).
        assert_eq!(q.spare.len(), 1);
        assert!(q.chunks.is_empty());
    }

    #[test]
    fn no_spares_frees_chunks_immediately() {
        let mut q = BufQ::new_with_opts(4, 4, BUFQ_OPT_NO_SPARES);
        q.write(b"abcdefgh").unwrap(); // two chunks
        let mut out = [0u8; 8];
        q.read(&mut out).unwrap();
        // With NO_SPARES, drained chunks are dropped, not retained.
        assert!(q.spare.is_empty());
        assert!(q.chunks.is_empty());
    }

    #[test]
    fn reset_keeps_spares_but_empties_queue() {
        let mut q = BufQ::new(4, 4);
        q.write(b"abcdefgh").unwrap(); // two active chunks
        q.reset();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert!(q.chunks.is_empty());
        assert_eq!(q.spare.len(), 2); // both kept for reuse
    }

    #[test]
    fn clear_frees_active_and_spare() {
        let mut q = BufQ::new(4, 4);
        q.write(b"abcd").unwrap();
        let mut out = [0u8; 4];
        q.read(&mut out).unwrap(); // moves a chunk to spare
        assert_eq!(q.spare.len(), 1);
        q.clear();
        assert!(q.chunks.is_empty());
        assert!(q.spare.is_empty());
        assert!(q.is_empty());
    }

    // ---- soft limit ---------------------------------------------------------

    #[test]
    fn soft_limit_allows_transient_overflow_but_reports_full() {
        let mut q = BufQ::new_with_opts(4, 2, BUFQ_OPT_SOFT_LIMIT); // soft cap 8
        assert_eq!(q.write(b"01234567").unwrap(), 8);
        assert!(q.is_full()); // reports full at the soft limit
                              // ...yet still accepts more, allocating a third chunk.
        assert_eq!(q.write(b"89AB").unwrap(), 4);
        assert_eq!(q.len(), 12); // exceeded max_chunks * chunk_size
        assert!(q.is_full());
        assert_eq!(q.chunks.len(), 3);
        // Everything can still be read back in order.
        let mut out = vec![0u8; 16];
        let n = q.read(&mut out).unwrap();
        assert_eq!(&out[..n], b"0123456789AB");
    }

    // ---- pass / write_pass --------------------------------------------------

    #[test]
    fn pass_drains_entire_queue_to_sink() {
        let mut q = BufQ::new(4, 8);
        q.write(b"HelloWorld!").unwrap();
        let mut sink: Vec<u8> = Vec::new();
        let passed = q
            .pass(|buf| {
                sink.extend_from_slice(buf);
                Ok(buf.len())
            })
            .unwrap();
        assert_eq!(passed, 11);
        assert_eq!(sink, b"HelloWorld!");
        assert!(q.is_empty());
    }

    #[test]
    fn pass_blocking_on_first_chunk_returns_again() {
        let mut q = BufQ::new(4, 8);
        q.write(b"abcd").unwrap();
        let res = q.pass(|_buf| Err(CurlError::Again));
        assert_eq!(res, Err(CurlError::Again));
        // Nothing was consumed.
        assert_eq!(q.len(), 4);
    }

    #[test]
    fn pass_blocking_after_progress_reports_success() {
        let mut q = BufQ::new(4, 8);
        q.write(b"abcdefgh").unwrap(); // two chunks
        let mut calls = 0;
        let mut sink = Vec::new();
        let passed = q
            .pass(|buf| {
                calls += 1;
                if calls == 1 {
                    sink.extend_from_slice(buf);
                    Ok(buf.len())
                } else {
                    Err(CurlError::Again) // block on the second chunk
                }
            })
            .unwrap();
        assert_eq!(passed, 4);
        assert_eq!(sink, b"abcd");
        // The un-passed remainder stays queued.
        assert_eq!(q.len(), 4);
        assert_eq!(q.peek(), Some(&b"efgh"[..]));
    }

    #[test]
    fn write_pass_flushes_when_full_then_buffers() {
        // Tiny queue (capacity 8) but we write 12 bytes; the sink drains overflow.
        let mut q = BufQ::new(4, 2);
        let mut sink: Vec<u8> = Vec::new();
        let written = q
            .write_pass(b"0123456789AB", |buf| {
                sink.extend_from_slice(buf);
                Ok(buf.len())
            })
            .unwrap();
        assert_eq!(written, 12);
        // Drain whatever remains buffered and append to the sink to verify order.
        q.pass(|buf| {
            sink.extend_from_slice(buf);
            Ok(buf.len())
        })
        .unwrap();
        assert_eq!(sink, b"0123456789AB");
    }

    // ---- slurp / sipn -------------------------------------------------------

    #[test]
    fn slurp_fills_queue_from_source_until_eof() {
        let data = b"abcdefghij".to_vec();
        let mut pos = 0usize;
        let mut q = BufQ::new(4, 8);
        let total = q
            .slurp(|out| {
                if pos >= data.len() {
                    return Ok(0); // EOF
                }
                let n = (data.len() - pos).min(out.len());
                out[..n].copy_from_slice(&data[pos..pos + n]);
                pos += n;
                Ok(n)
            })
            .unwrap();
        assert_eq!(total, data.len());
        assert_eq!(q.len(), data.len());
        let mut out = vec![0u8; 32];
        let n = q.read(&mut out).unwrap();
        assert_eq!(&out[..n], &data[..]);
    }

    #[test]
    fn sipn_reads_once_up_to_max_len() {
        let mut q = BufQ::new(16, 4);
        let src = b"abcdefgh";
        let mut pos = 0usize;
        // max_len = 3 caps this single read at 3 bytes even though more is free.
        let n = q
            .sipn(3, |out| {
                let n = (src.len() - pos).min(out.len());
                out[..n].copy_from_slice(&src[pos..pos + n]);
                pos += n;
                Ok(n)
            })
            .unwrap();
        assert_eq!(n, 3);
        assert_eq!(q.len(), 3);
        assert_eq!(q.peek(), Some(&b"abc"[..]));
    }

    #[test]
    fn slurp_blocking_on_first_read_returns_again() {
        let mut q = BufQ::new(4, 4);
        let res = q.slurp(|_out| Err(CurlError::Again));
        assert_eq!(res, Err(CurlError::Again));
        assert!(q.is_empty());
    }

    #[test]
    fn sipn_on_full_queue_returns_again() {
        let mut q = BufQ::new(4, 1);
        q.write(b"abcd").unwrap(); // full
        let res = q.sipn(0, |_out| Ok(0));
        assert_eq!(res, Err(CurlError::Again));
    }

    // ---- curl-named API surface ---------------------------------------------

    #[test]
    fn curl_named_wrappers_delegate() {
        let mut q = BufQ::Curl_bufq_init(8, 2);
        assert!(q.Curl_bufq_is_empty());
        assert_eq!(q.Curl_bufq_write(b"hi").unwrap(), 2);
        assert_eq!(q.Curl_bufq_cwrite(b"!").unwrap(), 1);
        assert_eq!(q.Curl_bufq_len(), 3);
        assert!(!q.Curl_bufq_is_full());
        assert_eq!(q.Curl_bufq_peek(), Some(&b"hi!"[..]));
        let mut out = [0u8; 8];
        assert_eq!(q.Curl_bufq_read(&mut out).unwrap(), 3);
        assert_eq!(&out[..3], b"hi!");
        q.Curl_bufq_reset();
        q.Curl_bufq_free();
        assert!(q.Curl_bufq_is_empty());
    }

    #[test]
    fn curl_named_init2_and_pool() {
        let mut q = BufQ::Curl_bufq_init2(4, 2, BUFQ_OPT_SOFT_LIMIT);
        assert_eq!(q.Curl_bufq_write(b"0123456789").unwrap(), 10); // soft overflow
        assert!(q.Curl_bufq_is_full());

        let pool = BufcPool::Curl_bufcp_init(8, 4);
        let mut pq = BufQ::Curl_bufq_initp(&pool, 3, BUFQ_OPT_NONE);
        assert_eq!(pq.chunk_size, 8);
        assert_eq!(pq.max_spare, 4);
        assert_eq!(pq.Curl_bufq_write(b"pooled").unwrap(), 6);
    }

    // ---- BufRef -------------------------------------------------------------

    #[test]
    fn bufref_default_and_new_are_empty() {
        let a = BufRef::new();
        assert!(a.is_empty());
        assert_eq!(a.len(), 0);
        assert_eq!(a.as_slice(), b"");
        let b = BufRef::default();
        assert!(b.is_empty());
    }

    #[test]
    fn bufref_set_len_and_slice() {
        let mut br = BufRef::new();
        br.set(Bytes::from_static(b"reference"));
        assert_eq!(br.len(), 9);
        assert_eq!(br.as_slice(), b"reference");
        // set replaces the previous buffer.
        br.set(b"new".to_vec());
        assert_eq!(br.len(), 3);
        assert_eq!(br.as_slice(), b"new");
    }

    #[test]
    fn bufref_memdup0_is_nul_terminated_and_len_excludes_nul() {
        let mut br = BufRef::new();
        br.memdup0(b"hello");
        // Logical length excludes the terminator.
        assert_eq!(br.len(), 5);
        assert_eq!(br.as_slice(), b"hello");
        // The backing buffer carries the NUL terminator for C-string use.
        assert_eq!(br.data.len(), 6);
        assert_eq!(br.data[br.len], 0);
    }

    #[test]
    fn bufref_memdup0_empty_input() {
        let mut br = BufRef::new();
        br.memdup0(b"");
        assert_eq!(br.len(), 0);
        assert!(br.is_empty());
        // Still NUL-terminated underneath.
        assert_eq!(br.data.len(), 1);
        assert_eq!(br.data[0], 0);
    }

    #[test]
    fn bufref_dup_is_nul_terminated_copy() {
        let mut br = BufRef::new();
        br.set(b"abc".to_vec());
        let dup = br.dup();
        assert_eq!(dup, b"abc\0");
    }

    #[test]
    fn bufref_free_resets_to_empty() {
        let mut br = BufRef::new();
        br.memdup0(b"data");
        assert!(!br.is_empty());
        br.clear();
        assert!(br.is_empty());
        assert_eq!(br.len(), 0);
        assert_eq!(br.as_slice(), b"");
    }

    #[test]
    fn bufref_curl_named_wrappers() {
        let mut br = BufRef::Curl_bufref_init();
        assert_eq!(br.Curl_bufref_len(), 0);
        br.Curl_bufref_memdup0(b"world");
        assert_eq!(br.Curl_bufref_len(), 5);
        assert_eq!(br.Curl_bufref_ptr(), b"world");
        assert_eq!(br.Curl_bufref_uptr(), b"world");
        assert_eq!(br.Curl_bufref_dup(), b"world\0");
        br.Curl_bufref_set(Bytes::from_static(b"x"));
        assert_eq!(br.Curl_bufref_uptr(), b"x");
        br.Curl_bufref_free();
        assert_eq!(br.Curl_bufref_len(), 0);
    }
}
