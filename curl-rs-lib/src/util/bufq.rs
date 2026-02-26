//! Buffer queue and buffer reference abstractions.
//!
//! This module is a Rust rewrite of `lib/bufq.c` (619 lines) and `lib/bufref.c`
//! (138 lines) from curl 8.19.0-DEV. It provides:
//!
//! - [`BufQ`] — A chunk-based FIFO buffer queue supporting streaming
//!   read/write/peek/skip/pass/slurp operations with configurable chunk
//!   pooling and soft limits.
//! - [`BufQOpts`] — Bitflag options controlling queue behavior (spare chunk
//!   pooling, soft/hard chunk limits).
//! - [`BufRef`] — A borrowed-or-owned buffer reference, replacing the C
//!   `struct bufref` with Rust enum ownership semantics.
//!
//! The chunk-based design preserves the same performance characteristics as
//! the C version (amortized O(1) enqueue/dequeue, bounded memory per chunk)
//! while eliminating all manual `malloc`/`free` management via Rust's
//! ownership, `Drop`, and `Vec` growth semantics.
//!
//! # Zero Unsafe
//!
//! This module contains zero `unsafe` blocks. All memory management is
//! handled by Rust's standard library containers (`VecDeque`, `Vec`).

use std::collections::VecDeque;
use std::io::{self, Read, Write};

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// BufQOpts — buffer queue option flags
// ---------------------------------------------------------------------------

/// Options controlling [`BufQ`] behaviour.
///
/// These flags correspond to the C `BUFQ_OPT_*` constants. Combine with
/// the `|` (bitor) operator.
///
/// # Examples
///
/// ```ignore
/// let opts = BufQOpts::SOFT_LIMIT | BufQOpts::NO_SPARES;
/// assert!(opts.contains(BufQOpts::SOFT_LIMIT));
/// assert!(opts.contains(BufQOpts::NO_SPARES));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufQOpts(u32);

impl BufQOpts {
    /// No special options — hard chunk limit, keep spare chunks for reuse.
    pub const NONE: Self = Self(0);

    /// Do not keep spare chunks for reuse. Freed chunks are dropped
    /// immediately rather than being retained in the spare pool. This
    /// reduces peak memory but may increase allocation frequency for
    /// bursty streaming patterns.
    pub const NO_SPARES: Self = Self(0x01);

    /// Soft chunk limit. When set, the queue allows allocation of new
    /// chunks beyond `max_chunks`, but [`BufQ::is_full`] still returns
    /// `true` once `max_chunks` is reached. Without this flag, writes
    /// to a full queue return [`CurlError::Again`].
    pub const SOFT_LIMIT: Self = Self(0x02);

    /// Returns the empty (no-flags-set) value, equivalent to [`Self::NONE`].
    #[inline]
    pub fn empty() -> Self {
        Self::NONE
    }

    /// Returns `true` if all flags in `other` are present in `self`.
    #[inline]
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for BufQOpts {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for BufQOpts {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl Default for BufQOpts {
    #[inline]
    fn default() -> Self {
        Self::NONE
    }
}

// ---------------------------------------------------------------------------
// Internal: Chunk — a fixed-capacity byte buffer with read/write cursors
// ---------------------------------------------------------------------------

/// A single buffer chunk with independent read and write cursors.
///
/// Data is written starting at `w_offset` and read starting at `r_offset`.
/// When `r_offset == w_offset`, the chunk is empty. When
/// `w_offset == data.len()`, the chunk is full. Once fully read, both
/// offsets are reset to zero so the chunk can be recycled via the spare pool.
struct Chunk {
    /// Pre-allocated byte buffer of capacity `chunk_size`.
    data: Vec<u8>,
    /// Index of the next unread byte.
    r_offset: usize,
    /// Index of the first unwritten byte (one past the last written byte).
    w_offset: usize,
}

impl Chunk {
    /// Allocates a new chunk with the given capacity, zero-initialized.
    fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
            r_offset: 0,
            w_offset: 0,
        }
    }

    /// Wraps an existing buffer as a fresh (empty) chunk, resetting cursors.
    /// The underlying buffer contents are irrelevant because `r_offset` and
    /// `w_offset` are both zero, so no stale data is ever exposed.
    fn from_buf(buf: Vec<u8>) -> Self {
        Self {
            data: buf,
            r_offset: 0,
            w_offset: 0,
        }
    }

    /// Returns `true` if no readable data remains (`r_offset >= w_offset`).
    #[inline]
    fn is_empty_data(&self) -> bool {
        self.r_offset >= self.w_offset
    }

    /// Returns `true` if the write cursor has reached the buffer capacity.
    #[inline]
    fn is_full(&self) -> bool {
        self.w_offset >= self.data.len()
    }

    /// Number of readable bytes in this chunk.
    #[inline]
    fn available(&self) -> usize {
        self.w_offset.saturating_sub(self.r_offset)
    }

    /// Number of writable bytes remaining before the chunk is full.
    #[inline]
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.w_offset)
    }

    /// Appends as much of `src` as fits into the remaining capacity.
    /// Returns the number of bytes actually written.
    fn append(&mut self, src: &[u8]) -> usize {
        let space = self.remaining();
        if space == 0 || src.is_empty() {
            return 0;
        }
        let n = std::cmp::min(space, src.len());
        self.data[self.w_offset..self.w_offset + n].copy_from_slice(&src[..n]);
        self.w_offset += n;
        n
    }

    /// Reads up to `dst.len()` bytes from the chunk into `dst`.
    /// Returns the number of bytes actually read.
    ///
    /// When all available data in this chunk is consumed, the cursors reset
    /// to zero so the chunk is flagged as empty for recycling.
    fn read_data(&mut self, dst: &mut [u8]) -> usize {
        let avail = self.available();
        if avail == 0 || dst.is_empty() {
            return 0;
        }
        if avail <= dst.len() {
            // Consume all available data and reset cursors.
            dst[..avail].copy_from_slice(&self.data[self.r_offset..self.w_offset]);
            self.r_offset = 0;
            self.w_offset = 0;
            avail
        } else {
            // Partial read — consume only what fits.
            let n = dst.len();
            dst.copy_from_slice(&self.data[self.r_offset..self.r_offset + n]);
            self.r_offset += n;
            n
        }
    }

    /// Copies up to `dst.len()` bytes into `dst` **without** advancing
    /// the read cursor.
    fn peek_data(&self, dst: &mut [u8]) -> usize {
        let avail = self.available();
        if avail == 0 || dst.is_empty() {
            return 0;
        }
        let n = std::cmp::min(avail, dst.len());
        dst[..n].copy_from_slice(&self.data[self.r_offset..self.r_offset + n]);
        n
    }

    /// Discards up to `amount` bytes by advancing the read cursor.
    /// Resets cursors when fully drained. Returns the number of bytes
    /// actually skipped.
    fn skip_data(&mut self, amount: usize) -> usize {
        let avail = self.available();
        if avail == 0 {
            return 0;
        }
        let n = std::cmp::min(avail, amount);
        self.r_offset += n;
        if self.r_offset >= self.w_offset {
            self.r_offset = 0;
            self.w_offset = 0;
        }
        n
    }

    /// Consumes the chunk and returns the underlying buffer for reuse in
    /// the spare pool.
    fn into_buf(self) -> Vec<u8> {
        self.data
    }
}

// ---------------------------------------------------------------------------
// BufQ — chunk-based FIFO buffer queue
// ---------------------------------------------------------------------------

/// A FIFO buffer queue composed of fixed-size byte chunks.
///
/// `BufQ` provides an efficient streaming buffer for network I/O:
///
/// - **Write path:** Data is appended to the tail chunk. When the tail is
///   full, a new chunk is allocated (from the spare pool or fresh).
/// - **Read path:** Data is consumed from the head chunk. When the head is
///   exhausted, it is either returned to the spare pool or dropped.
/// - **Spare pool:** Exhausted chunks are recycled to avoid repeated
///   allocation, unless [`BufQOpts::NO_SPARES`] is set.
/// - **Soft limit:** With [`BufQOpts::SOFT_LIMIT`], writes may exceed
///   `max_chunks`, but [`is_full`](Self::is_full) still returns `true` at
///   the configured limit.
///
/// # Performance
///
/// All operations are O(1) amortized per byte, matching the C `struct bufq`.
pub struct BufQ {
    /// Active chunks in FIFO order. Head = read side, back = write side.
    chunks: VecDeque<Chunk>,
    /// Spare chunk buffers available for reuse (reset `Vec<u8>` instances).
    spares: Vec<Vec<u8>>,
    /// Default allocation size (in bytes) per chunk.
    chunk_size: usize,
    /// Soft or hard limit on total chunk count (active + spare).
    max_chunks: usize,
    /// Total number of chunks currently tracked (active + spare).
    /// Mirrors the C `chunk_count` field semantics exactly.
    chunk_count: usize,
    /// Option flags controlling queue behaviour.
    opts: BufQOpts,
}

impl BufQ {
    /// Creates a new buffer queue with default options (hard limit, keep
    /// spare chunks for reuse).
    ///
    /// # Parameters
    ///
    /// * `chunk_size` — Capacity in bytes of each chunk. Must be > 0.
    /// * `max_chunks` — Maximum number of tracked chunks. Must be > 0.
    ///
    /// # Panics
    ///
    /// Panics in debug mode if `chunk_size` or `max_chunks` is zero.
    pub fn new(chunk_size: usize, max_chunks: usize) -> Self {
        Self::with_opts(chunk_size, max_chunks, BufQOpts::NONE)
    }

    /// Creates a new buffer queue with the specified option flags.
    ///
    /// See [`BufQOpts`] for available flags.
    pub fn with_opts(chunk_size: usize, max_chunks: usize, opts: BufQOpts) -> Self {
        debug_assert!(chunk_size > 0, "chunk_size must be positive");
        debug_assert!(max_chunks > 0, "max_chunks must be positive");
        Self {
            chunks: VecDeque::new(),
            spares: Vec::new(),
            chunk_size,
            max_chunks,
            chunk_count: 0,
            opts,
        }
    }

    // -- Internal helpers --------------------------------------------------

    /// Attempts to obtain a fresh chunk from the spare pool or by new
    /// allocation. Returns `None` if the hard limit is reached and
    /// [`BufQOpts::SOFT_LIMIT`] is not set.
    fn allocate_chunk(&mut self) -> Option<Chunk> {
        // 1. Try reusing a spare buffer (no new allocation).
        if let Some(buf) = self.spares.pop() {
            return Some(Chunk::from_buf(buf));
        }
        // 2. Check hard chunk limit.
        if self.chunk_count >= self.max_chunks
            && !self.opts.contains(BufQOpts::SOFT_LIMIT)
        {
            return None;
        }
        // 3. Allocate a brand-new chunk and track it.
        self.chunk_count += 1;
        Some(Chunk::new(self.chunk_size))
    }

    /// Ensures the back of the deque contains a non-full chunk by either
    /// confirming the current tail has space or allocating a new chunk.
    /// Returns `true` if a writable tail exists afterwards.
    fn ensure_non_full_tail(&mut self) -> bool {
        if self.chunks.back().is_some_and(|c| !c.is_full()) {
            return true;
        }
        if let Some(chunk) = self.allocate_chunk() {
            self.chunks.push_back(chunk);
            true
        } else {
            false
        }
    }

    /// Removes exhausted (empty) chunks from the head of the queue.
    /// Chunks are either recycled into the spare pool or dropped depending
    /// on `NO_SPARES` and the current chunk count vs. `max_chunks`.
    fn prune_head(&mut self) {
        loop {
            let should_prune = self
                .chunks
                .front()
                .is_some_and(|c| c.is_empty_data());
            if !should_prune {
                break;
            }
            let chunk = self.chunks.pop_front().unwrap();
            // Over the soft-limit or no-spares mode → release the buffer.
            if self.chunk_count > self.max_chunks
                || self.opts.contains(BufQOpts::NO_SPARES)
            {
                drop(chunk);
                self.chunk_count -= 1;
            } else {
                // Recycle into the spare pool.
                self.spares.push(chunk.into_buf());
            }
        }
    }

    /// Returns a slice view of the first non-empty chunk's readable data,
    /// or `None` if the queue is empty.
    fn peek_front_slice(&self) -> Option<&[u8]> {
        for chunk in &self.chunks {
            if !chunk.is_empty_data() {
                return Some(&chunk.data[chunk.r_offset..chunk.w_offset]);
            }
        }
        None
    }

    // -- Write operations --------------------------------------------------

    /// Appends `data` to the tail of the queue.
    ///
    /// Fills the current tail chunk first, then allocates new chunks as
    /// needed, respecting the configured limits.
    ///
    /// # Returns
    ///
    /// * `Ok(n)` — `n` bytes were written (may be less than `data.len()`
    ///   when the queue reaches its limit with soft-limit enabled).
    /// * `Err(CurlError::Again)` — The queue is at its hard limit and no
    ///   bytes could be written.
    /// * `Err(CurlError::OutOfMemory)` — Allocation failed despite being
    ///   within the configured limits.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, CurlError> {
        if data.is_empty() {
            return Ok(0);
        }
        let mut written: usize = 0;
        let mut remaining = data;

        while !remaining.is_empty() {
            if !self.ensure_non_full_tail() {
                // Could not obtain a writable chunk.
                if self.chunk_count < self.max_chunks
                    || self.opts.contains(BufQOpts::SOFT_LIMIT)
                {
                    // Expected to allocate but failed → memory error.
                    return Err(CurlError::OutOfMemory);
                }
                // Hard limit reached — stop writing.
                break;
            }
            let tail = self.chunks.back_mut().unwrap();
            let n = tail.append(remaining);
            if n == 0 {
                break;
            }
            written += n;
            remaining = &remaining[n..];
        }

        if written == 0 && !data.is_empty() {
            Err(CurlError::Again)
        } else {
            Ok(written)
        }
    }

    /// Enqueues a pre-filled buffer as a new chunk, taking ownership.
    ///
    /// This is a Rust-specific optimisation that avoids copying when the
    /// caller already owns a `Vec<u8>`. The buffer is appended as-is and
    /// its entire contents are immediately readable.
    pub fn append(&mut self, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let len = data.len();
        let chunk = Chunk {
            data,
            r_offset: 0,
            w_offset: len,
        };
        self.chunks.push_back(chunk);
        self.chunk_count += 1;
    }

    // -- Read operations ---------------------------------------------------

    /// Dequeues up to `buf.len()` bytes from the head of the queue.
    ///
    /// Reads from the head chunk, pruning exhausted chunks as it goes.
    ///
    /// # Returns
    ///
    /// * `Ok(n)` — `n` bytes were read into `buf`.
    /// * `Err(CurlError::Again)` — The queue is empty.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, CurlError> {
        let mut total: usize = 0;

        loop {
            if total >= buf.len() || self.chunks.is_empty() {
                break;
            }
            let n = {
                let front = match self.chunks.front_mut() {
                    Some(f) => f,
                    None => break,
                };
                front.read_data(&mut buf[total..])
            };
            if n > 0 {
                total += n;
            }
            self.prune_head();
        }

        if total == 0 {
            Err(CurlError::Again)
        } else {
            Ok(total)
        }
    }

    /// Peeks at the data at the head of the queue **without** consuming it.
    ///
    /// Copies up to `buf.len()` bytes into `buf` from the first non-empty
    /// chunk. Returns the number of bytes copied. Returns 0 if the queue
    /// is empty.
    pub fn peek(&self, buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        for chunk in &self.chunks {
            if !chunk.is_empty_data() {
                return chunk.peek_data(buf);
            }
        }
        0
    }

    /// Discards up to `n` bytes from the head of the queue.
    ///
    /// Returns the number of bytes actually skipped. Requesting more than
    /// [`len`](Self::len) simply empties the queue.
    pub fn skip(&mut self, mut n: usize) -> usize {
        let mut skipped: usize = 0;
        while n > 0 {
            let s = {
                match self.chunks.front_mut() {
                    Some(front) => front.skip_data(n),
                    None => break,
                }
            };
            if s > 0 {
                skipped += s;
                n -= s;
            }
            self.prune_head();
            // If nothing was skipped and the head was empty, prune removed
            // it. Continue to try the next chunk.
            if s == 0 && self.chunks.is_empty() {
                break;
            }
        }
        skipped
    }

    // -- Query operations --------------------------------------------------

    /// Returns `true` if the queue contains no readable data.
    pub fn is_empty(&self) -> bool {
        !self.chunks.iter().any(|c| !c.is_empty_data())
    }

    /// Returns the total number of readable bytes across all chunks.
    pub fn len(&self) -> usize {
        self.chunks.iter().map(|c| c.available()).sum()
    }

    /// Returns `true` if the queue is at or over its chunk limit and the
    /// tail chunk (if any) is full.
    ///
    /// With [`BufQOpts::SOFT_LIMIT`], the queue reports full at the
    /// configured limit but still accepts writes (they allocate beyond
    /// the limit).
    pub fn is_full(&self) -> bool {
        // If we have spare buffers, we can obtain another chunk without
        // exceeding the allocation count.
        if !self.spares.is_empty() {
            return false;
        }
        // If below the limit, we can always allocate more.
        if self.chunk_count < self.max_chunks {
            return false;
        }
        // Over the limit (e.g., after soft-limit writes).
        if self.chunk_count > self.max_chunks {
            return true;
        }
        // Exactly at the limit with no spares — check if tail is full.
        self.chunks.back().is_some_and(|c| c.is_full())
    }

    // -- Advanced / streaming operations -----------------------------------

    /// Reads data from `reader` into the queue until the reader blocks,
    /// returns EOF, or the queue is full.
    ///
    /// # Returns
    ///
    /// * `Ok(n)` — `n` bytes were read from `reader` into the queue.
    /// * `Err(CurlError::Again)` — The queue is full (no bytes read) or
    ///   the reader returned `WouldBlock` with no bytes read.
    /// * `Err(CurlError::OutOfMemory)` — Chunk allocation failed despite
    ///   being within limits.
    pub fn slurp<R: Read>(&mut self, reader: &mut R) -> Result<usize, CurlError> {
        let mut total: usize = 0;

        loop {
            // Ensure we have a writable tail chunk.
            if !self.ensure_non_full_tail() {
                if total == 0 {
                    if self.chunk_count < self.max_chunks {
                        return Err(CurlError::OutOfMemory);
                    }
                    return Err(CurlError::Again);
                }
                break;
            }

            // Read directly into the tail chunk's free space.
            let n = {
                let tail = self.chunks.back_mut().unwrap();
                let space = &mut tail.data[tail.w_offset..];
                if space.is_empty() {
                    // Tail unexpectedly full — retry with a new chunk.
                    continue;
                }
                match reader.read(space) {
                    Ok(0) => {
                        // EOF from reader.
                        break;
                    }
                    Ok(n) => {
                        tail.w_offset += n;
                        n
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if total == 0 {
                            return Err(CurlError::Again);
                        }
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {
                        // Retry on EINTR.
                        continue;
                    }
                    Err(_) => {
                        // Other I/O errors — stop reading.
                        if total == 0 {
                            return Err(CurlError::Again);
                        }
                        break;
                    }
                }
            };

            total += n;

            // If the tail chunk was NOT filled, the reader likely has no
            // more data immediately available. Break to avoid a blocking
            // call on the next iteration (matches C `bufq_slurpn` behaviour).
            if self.chunks.back().map_or(true, |c| !c.is_full()) {
                break;
            }
        }

        Ok(total)
    }

    /// Writes all queued data to `writer`.
    ///
    /// Peeks at head chunks and writes them to `writer`, skipping consumed
    /// bytes as the writer accepts them.
    ///
    /// # Returns
    ///
    /// * `Ok(n)` — `n` bytes were written to `writer`.
    /// * `Err(CurlError::Again)` — The writer blocked immediately with no
    ///   bytes written, or the queue was empty.
    pub fn pass<W: Write>(&mut self, writer: &mut W) -> Result<usize, CurlError> {
        let mut total: usize = 0;

        loop {
            // Peek at the front chunk's readable data.
            let write_result = {
                let front = match self.peek_front_slice() {
                    Some(s) if !s.is_empty() => s,
                    _ => break,
                };
                writer.write(front)
            };
            // The immutable borrow from peek_front_slice is now released,
            // allowing mutable access for skip below.

            match write_result {
                Ok(0) => {
                    // Writer cannot accept more data.
                    if total == 0 {
                        return Err(CurlError::Again);
                    }
                    break;
                }
                Ok(n) => {
                    total += n;
                    self.skip(n);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if total == 0 {
                        return Err(CurlError::Again);
                    }
                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(_) => {
                    if total == 0 {
                        return Err(CurlError::Again);
                    }
                    break;
                }
            }
        }

        Ok(total)
    }

    /// Extracts up to `max` bytes from the head of the queue into a new
    /// `Vec<u8>`, consuming the data.
    ///
    /// This is a Rust-idiomatic drain operation. Returns an empty `Vec` if
    /// the queue is empty or `max` is zero.
    pub fn sipn(&mut self, max: usize) -> Vec<u8> {
        if max == 0 {
            return Vec::new();
        }
        let available = self.len();
        let to_extract = std::cmp::min(max, available);
        let mut result = Vec::with_capacity(to_extract);
        let mut remaining = to_extract;

        while remaining > 0 {
            let n = {
                let front = match self.chunks.front_mut() {
                    Some(c) if !c.is_empty_data() => c,
                    _ => break,
                };
                let avail = front.available();
                let n = std::cmp::min(avail, remaining);
                result.extend_from_slice(
                    &front.data[front.r_offset..front.r_offset + n],
                );
                front.r_offset += n;
                if front.r_offset >= front.w_offset {
                    front.r_offset = 0;
                    front.w_offset = 0;
                }
                n
            };
            remaining -= n;
            self.prune_head();
        }

        result
    }

    /// Clears all data from the queue. Chunks are moved to the spare pool
    /// (unless [`BufQOpts::NO_SPARES`] is set) so that subsequent writes
    /// can reuse them without fresh allocation.
    pub fn reset(&mut self) {
        while let Some(chunk) = self.chunks.pop_front() {
            if self.opts.contains(BufQOpts::NO_SPARES) {
                drop(chunk);
                self.chunk_count -= 1;
            } else {
                self.spares.push(chunk.into_buf());
            }
        }
    }
}

impl Drop for BufQ {
    fn drop(&mut self) {
        // Explicitly clear both containers. The Vec<u8> buffers in both
        // `chunks` and `spares` are dropped automatically by Rust.
        self.chunks.clear();
        self.spares.clear();
    }
}

impl std::fmt::Debug for BufQ {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufQ")
            .field("active_chunks", &self.chunks.len())
            .field("spare_chunks", &self.spares.len())
            .field("chunk_size", &self.chunk_size)
            .field("max_chunks", &self.max_chunks)
            .field("chunk_count", &self.chunk_count)
            .field("total_bytes", &self.len())
            .field("opts", &self.opts)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// BufRef — borrowed or owned buffer reference
// ---------------------------------------------------------------------------

/// A buffer reference that can hold either a borrowed slice or an owned
/// `Vec<u8>`.
///
/// This replaces the C `struct bufref` which stored a `const unsigned char *`
/// pointer, a length, and an optional destructor function pointer. In Rust,
/// the enum discriminant replaces the destructor: `Borrowed` references are
/// never freed, `Owned` values are dropped when the `BufRef` goes out of
/// scope or is reassigned.
///
/// # Lifetime
///
/// The `'a` lifetime applies only to the `Borrowed` variant. For purely
/// owned buffers, use `BufRef<'static>` or construct with
/// [`set_buf`](Self::set_buf).
#[derive(Debug, Clone)]
pub enum BufRef<'a> {
    /// No data.
    Empty,
    /// Borrowed reference to an external byte slice.
    Borrowed(&'a [u8]),
    /// Owned byte buffer.
    Owned(Vec<u8>),
}

impl<'a> BufRef<'a> {
    /// Creates an empty buffer reference.
    #[inline]
    pub fn new() -> Self {
        BufRef::Empty
    }

    /// Sets this reference to borrow `data`. Any previously held owned
    /// data is dropped.
    ///
    /// Corresponds to the C `Curl_bufref_set()` with a non-NULL pointer and
    /// no destructor.
    #[inline]
    pub fn set_ptr(&mut self, data: &'a [u8]) {
        *self = BufRef::Borrowed(data);
    }

    /// Sets this reference to own `data`. Any previously held data
    /// (borrowed or owned) is released.
    ///
    /// Corresponds to the C `Curl_bufref_set()` with a destructor that
    /// frees the buffer.
    #[inline]
    pub fn set_buf(&mut self, data: Vec<u8>) {
        *self = BufRef::Owned(data);
    }

    /// Returns a read-only slice of the referenced data. Returns an empty
    /// slice if the reference is empty.
    ///
    /// Corresponds to the C `Curl_bufref_ptr()` / `Curl_bufref_uptr()`.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            BufRef::Empty => &[],
            BufRef::Borrowed(s) => s,
            BufRef::Owned(v) => v.as_slice(),
        }
    }

    /// Returns the length of the referenced data in bytes.
    ///
    /// Corresponds to the C `Curl_bufref_len()`.
    #[inline]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns `true` if the reference holds no data (length is zero).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a> Default for BufRef<'a> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- BufQOpts tests ----------------------------------------------------

    #[test]
    fn bufq_opts_none_is_default() {
        assert_eq!(BufQOpts::empty(), BufQOpts::NONE);
        assert_eq!(BufQOpts::default(), BufQOpts::NONE);
    }

    #[test]
    fn bufq_opts_contains() {
        let combined = BufQOpts::NO_SPARES | BufQOpts::SOFT_LIMIT;
        assert!(combined.contains(BufQOpts::NO_SPARES));
        assert!(combined.contains(BufQOpts::SOFT_LIMIT));
        assert!(!BufQOpts::NONE.contains(BufQOpts::NO_SPARES));
    }

    // -- BufQ basic write/read round-trip ----------------------------------

    #[test]
    fn write_read_round_trip() {
        let mut q = BufQ::new(64, 4);
        let data = b"hello, buffer queue!";
        let written = q.write(data).unwrap();
        assert_eq!(written, data.len());
        assert!(!q.is_empty());
        assert_eq!(q.len(), data.len());

        let mut out = vec![0u8; 64];
        let read = q.read(&mut out).unwrap();
        assert_eq!(read, data.len());
        assert_eq!(&out[..read], data);
        assert!(q.is_empty());
    }

    #[test]
    fn write_multi_chunk() {
        // 16-byte chunks, 4 max → 64 byte capacity.
        let mut q = BufQ::new(16, 4);
        let data = vec![0xABu8; 48]; // Needs 3 chunks.
        let written = q.write(&data).unwrap();
        assert_eq!(written, 48);
        assert_eq!(q.len(), 48);

        let mut out = vec![0u8; 48];
        let read = q.read(&mut out).unwrap();
        assert_eq!(read, 48);
        assert_eq!(out, data);
    }

    #[test]
    fn write_respects_hard_limit() {
        let mut q = BufQ::new(8, 2); // 16 bytes max.
        let data = vec![0xFFu8; 16];
        let written = q.write(&data).unwrap();
        assert_eq!(written, 16);
        assert!(q.is_full());

        // Next write should return Again.
        let err = q.write(&[0x01]).unwrap_err();
        assert_eq!(err, CurlError::Again);
    }

    #[test]
    fn write_soft_limit_allows_overflow() {
        let mut q = BufQ::with_opts(8, 2, BufQOpts::SOFT_LIMIT);
        let data = vec![0xAAu8; 24]; // Exceeds 2*8 = 16 byte limit.
        let written = q.write(&data).unwrap();
        assert_eq!(written, 24);
        assert!(q.is_full());
        assert_eq!(q.len(), 24);
    }

    // -- Peek / skip -------------------------------------------------------

    #[test]
    fn peek_does_not_consume() {
        let mut q = BufQ::new(64, 4);
        q.write(b"peekaboo").unwrap();

        let mut buf = [0u8; 4];
        let peeked = q.peek(&mut buf);
        assert_eq!(peeked, 4);
        assert_eq!(&buf, b"peek");
        // Data should still be fully present.
        assert_eq!(q.len(), 8);

        // Read the full data.
        let mut out = [0u8; 8];
        let n = q.read(&mut out).unwrap();
        assert_eq!(n, 8);
        assert_eq!(&out, b"peekaboo");
    }

    #[test]
    fn skip_discards_correct_amount() {
        let mut q = BufQ::new(64, 4);
        q.write(b"abcdefgh").unwrap();

        let skipped = q.skip(3);
        assert_eq!(skipped, 3);
        assert_eq!(q.len(), 5);

        let mut out = [0u8; 5];
        let n = q.read(&mut out).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&out, b"defgh");
    }

    #[test]
    fn skip_beyond_len() {
        let mut q = BufQ::new(64, 4);
        q.write(b"short").unwrap();
        let skipped = q.skip(100);
        assert_eq!(skipped, 5);
        assert!(q.is_empty());
    }

    // -- Append (owned buffer) ---------------------------------------------

    #[test]
    fn append_owned_buffer() {
        let mut q = BufQ::new(32, 4);
        let data = vec![1u8, 2, 3, 4, 5];
        q.append(data.clone());
        assert_eq!(q.len(), 5);

        let mut out = [0u8; 5];
        let n = q.read(&mut out).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&out, &[1, 2, 3, 4, 5]);
    }

    // -- sipn (drain) ------------------------------------------------------

    #[test]
    fn sipn_extracts_bytes() {
        let mut q = BufQ::new(64, 4);
        q.write(b"hello world").unwrap();

        let extracted = q.sipn(5);
        assert_eq!(extracted, b"hello");
        assert_eq!(q.len(), 6); // " world" remains.

        let rest = q.sipn(100);
        assert_eq!(rest, b" world");
        assert!(q.is_empty());
    }

    #[test]
    fn sipn_zero_returns_empty() {
        let mut q = BufQ::new(64, 4);
        q.write(b"data").unwrap();
        let v = q.sipn(0);
        assert!(v.is_empty());
        assert_eq!(q.len(), 4); // Unchanged.
    }

    // -- Reset -------------------------------------------------------------

    #[test]
    fn reset_clears_data() {
        let mut q = BufQ::new(32, 4);
        q.write(b"some data here").unwrap();
        assert!(!q.is_empty());
        q.reset();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn reset_keeps_spares_for_reuse() {
        let mut q = BufQ::new(16, 4);
        q.write(&[0u8; 32]).unwrap(); // 2 chunks.
        assert_eq!(q.chunk_count, 2);
        q.reset();
        // Chunks should now be in spare pool.
        assert!(q.is_empty());
        assert_eq!(q.chunk_count, 2); // Still tracked as spares.

        // Writing again should reuse the spare chunks.
        q.write(&[1u8; 16]).unwrap();
        assert_eq!(q.chunk_count, 2); // No new allocation.
    }

    #[test]
    fn reset_no_spares_drops_chunks() {
        let mut q = BufQ::with_opts(16, 4, BufQOpts::NO_SPARES);
        q.write(&[0u8; 32]).unwrap();
        assert_eq!(q.chunk_count, 2);
        q.reset();
        assert!(q.is_empty());
        assert_eq!(q.chunk_count, 0); // Chunks were dropped.
    }

    // -- is_full / is_empty ------------------------------------------------

    #[test]
    fn is_full_hard_limit() {
        let mut q = BufQ::new(8, 2);
        assert!(!q.is_full());
        q.write(&[0u8; 16]).unwrap();
        assert!(q.is_full());
    }

    #[test]
    fn is_empty_on_new_queue() {
        let q = BufQ::new(64, 4);
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    // -- slurp / pass with std::io readers/writers -------------------------

    #[test]
    fn slurp_from_reader() {
        let input = b"read me into the queue";
        let mut cursor = std::io::Cursor::new(input.as_slice());
        let mut q = BufQ::new(64, 4);

        let n = q.slurp(&mut cursor).unwrap();
        assert_eq!(n, input.len());
        assert_eq!(q.len(), input.len());

        let mut out = vec![0u8; 64];
        let read = q.read(&mut out).unwrap();
        assert_eq!(&out[..read], input.as_slice());
    }

    #[test]
    fn pass_to_writer() {
        let mut q = BufQ::new(64, 4);
        q.write(b"pass this along").unwrap();

        let mut output = Vec::new();
        let n = q.pass(&mut output).unwrap();
        assert_eq!(n, 15);
        assert_eq!(&output, b"pass this along");
        assert!(q.is_empty());
    }

    #[test]
    fn slurp_pass_round_trip() {
        let original = b"round trip through slurp and pass";
        let mut cursor = std::io::Cursor::new(original.as_slice());
        let mut q = BufQ::new(16, 8);

        let slurped = q.slurp(&mut cursor).unwrap();
        assert_eq!(slurped, original.len());

        let mut output = Vec::new();
        let passed = q.pass(&mut output).unwrap();
        assert_eq!(passed, original.len());
        assert_eq!(&output, original.as_slice());
    }

    // -- Empty queue error semantics ---------------------------------------

    #[test]
    fn read_empty_returns_again() {
        let mut q = BufQ::new(64, 4);
        let mut buf = [0u8; 8];
        let err = q.read(&mut buf).unwrap_err();
        assert_eq!(err, CurlError::Again);
    }

    #[test]
    fn peek_empty_returns_zero() {
        let q = BufQ::new(64, 4);
        let mut buf = [0u8; 8];
        assert_eq!(q.peek(&mut buf), 0);
    }

    // -- BufRef tests ------------------------------------------------------

    #[test]
    fn bufref_new_is_empty() {
        let r = BufRef::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert_eq!(r.as_slice(), &[]);
    }

    #[test]
    fn bufref_set_ptr_borrowed() {
        let data = [1u8, 2, 3, 4];
        let mut r = BufRef::new();
        r.set_ptr(&data);
        assert!(!r.is_empty());
        assert_eq!(r.len(), 4);
        assert_eq!(r.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn bufref_set_buf_owned() {
        let mut r = BufRef::new();
        r.set_buf(vec![10, 20, 30]);
        assert_eq!(r.len(), 3);
        assert_eq!(r.as_slice(), &[10, 20, 30]);
    }

    #[test]
    fn bufref_reassignment_drops_old() {
        let mut r = BufRef::new();
        r.set_buf(vec![1, 2, 3]);
        assert_eq!(r.len(), 3);
        // Reassign to borrowed — owned vec is dropped.
        let external = [4u8, 5];
        r.set_ptr(&external);
        assert_eq!(r.len(), 2);
        assert_eq!(r.as_slice(), &[4, 5]);
    }

    #[test]
    fn bufref_default_is_empty() {
        let r: BufRef<'_> = Default::default();
        assert!(r.is_empty());
    }

    // -- Spare pool recycling ----------------------------------------------

    #[test]
    fn spare_pool_recycles_chunks() {
        let mut q = BufQ::new(16, 4);
        // Write 2 chunks worth of data.
        q.write(&[0xAA; 32]).unwrap();
        assert_eq!(q.chunk_count, 2);

        // Read it all — chunks should move to spare pool.
        let mut buf = [0u8; 32];
        q.read(&mut buf).unwrap();
        assert!(q.is_empty());
        // chunk_count should still be 2 (now as spares).
        assert_eq!(q.chunk_count, 2);

        // Write again — should reuse spare chunks.
        q.write(&[0xBB; 16]).unwrap();
        assert_eq!(q.chunk_count, 2); // No new allocations.
    }

    #[test]
    fn no_spares_drops_exhausted_chunks() {
        let mut q = BufQ::with_opts(16, 4, BufQOpts::NO_SPARES);
        q.write(&[0xCC; 32]).unwrap();
        assert_eq!(q.chunk_count, 2);

        let mut buf = [0u8; 32];
        q.read(&mut buf).unwrap();
        assert!(q.is_empty());
        // With NO_SPARES, chunks are dropped when exhausted.
        assert_eq!(q.chunk_count, 0);
    }

    // -- Multi-chunk read spanning chunks ----------------------------------

    #[test]
    fn read_spans_multiple_chunks() {
        let mut q = BufQ::new(8, 8);
        // Write 3 chunks: "aaaaaaaa", "bbbbbbbb", "cccccccc" (8 bytes each).
        q.write(&[b'a'; 8]).unwrap();
        q.write(&[b'b'; 8]).unwrap();
        q.write(&[b'c'; 8]).unwrap();
        assert_eq!(q.len(), 24);

        // Read 12 bytes, spanning the first chunk and half the second.
        let mut out = [0u8; 12];
        let n = q.read(&mut out).unwrap();
        assert_eq!(n, 12);
        assert_eq!(&out[..8], &[b'a'; 8]);
        assert_eq!(&out[8..12], &[b'b'; 4]);

        // Remaining should be 12 bytes.
        assert_eq!(q.len(), 12);
    }

    // -- Debug format ------------------------------------------------------

    #[test]
    fn debug_format() {
        let q = BufQ::new(32, 4);
        let debug_str = format!("{:?}", q);
        assert!(debug_str.contains("BufQ"));
        assert!(debug_str.contains("active_chunks"));
        assert!(debug_str.contains("chunk_size"));
    }
}
