//! Formatted send / debug output — Rust replacement for C `lib/sendf.c`.
//!
//! Implements the layered client-side reader/writer stack that manages:
//! - **Writer chain**: filters that post-process downloaded data before
//!   delivering it to the caller (verbose tracing → progress tracking →
//!   pause buffering → transport sink).
//! - **Reader chain**: filters that pre-process upload data from the caller
//!   before handing it to the transport layer (user callback → newline
//!   conversion → protocol framing → transport).
//!
//! # C Correspondence
//!
//! | Rust                          | C                                |
//! |-------------------------------|----------------------------------|
//! | `ClientWriter` trait          | `struct Curl_cwtype`             |
//! | `ClientWriteFlags`            | `CLIENTWRITE_*` bitflags         |
//! | `WriterPhase`                 | `Curl_cwriter_phase`             |
//! | `WriterChain`                 | `struct Curl_cwriter` linked list |
//! | `ClientReader` trait          | `struct Curl_crtype`             |
//! | `ReaderPhase`                 | `Curl_creader_phase`             |
//! | `ReaderControl`               | `Curl_creader_cntrl`             |
//! | `ReaderChain`                 | `struct Curl_creader` linked list |
//! | `client_write()`              | `Curl_client_write()`            |
//! | `client_read()`               | `Curl_client_read()`             |
//! | `client_cleanup()`            | `Curl_client_cleanup()`          |
//! | `client_reset()`              | `Curl_client_reset()`            |
//! | `client_start()`              | `Curl_client_start()`            |
//!
//! # Design Notes
//!
//! In the C implementation, writers and readers form singly-linked lists
//! traversed via function-pointer vtables. In Rust, each layer implements
//! the [`ClientWriter`] or [`ClientReader`] trait, and the chains are stored
//! as `Vec<Box<dyn …>>` ordered by phase. The chains compose naturally
//! with Rust ownership: each layer borrows the next layer to forward data.
//!
//! # Zero Unsafe
//!
//! This module contains zero `unsafe` blocks. All memory management is
//! handled by Rust's standard library containers.

use std::cmp;
use std::fmt;

use crate::error::CurlError;
use crate::ratelimit::RateLimiter;
use crate::util::bufq::{BufQ, BufQOpts};
use crate::util::dynbuf::DynBuf;

// ---------------------------------------------------------------------------
// ClientWriteFlags
// ---------------------------------------------------------------------------

/// Bitflag indicating what kind of data is being written, matching the C
/// `CLIENTWRITE_*` flags defined in `lib/sendf.h`.
///
/// # C Constants
///
/// | Rust              | C                        | Bit  |
/// |-------------------|--------------------------|------|
/// | `BODY`            | `CLIENTWRITE_BODY`       | 1<<0 |
/// | `INFO`            | `CLIENTWRITE_INFO`       | 1<<1 |
/// | `HEADER`          | `CLIENTWRITE_HEADER`     | 1<<2 |
/// | `STATUS`          | `CLIENTWRITE_STATUS`     | 1<<3 |
/// | `CONNECT`         | `CLIENTWRITE_CONNECT`    | 1<<4 |
/// | `ONEX`            | `CLIENTWRITE_1XX`        | 1<<5 |
/// | `TRAILER`         | `CLIENTWRITE_TRAILER`    | 1<<6 |
/// | `EOS`             | `CLIENTWRITE_EOS`        | 1<<7 |
/// | `ZEROLEN`         | `CLIENTWRITE_0LEN`       | 1<<8 |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientWriteFlags(u32);

impl ClientWriteFlags {
    /// Response body data.
    pub const BODY: Self = Self(1 << 0);
    /// Informational text (verbose output, not headers).
    pub const INFO: Self = Self(1 << 1);
    /// Response header line.
    pub const HEADER: Self = Self(1 << 2);
    /// HTTP status line (special header).
    pub const STATUS: Self = Self(1 << 3);
    /// Data from a CONNECT tunnel.
    pub const CONNECT: Self = Self(1 << 4);
    /// One-shot 1xx response header.
    pub const ONEX: Self = Self(1 << 5);
    /// Trailing header.
    pub const TRAILER: Self = Self(1 << 6);
    /// End-of-stream marker.
    pub const EOS: Self = Self(1 << 7);
    /// Zero-length write (flush/signal only).
    pub const ZEROLEN: Self = Self(1 << 8);

    /// Create an empty (no-flags) value.
    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Test whether `self` contains all bits in `other`.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Convenience: is this body data?
    #[inline]
    pub const fn is_body(self) -> bool {
        (self.0 & Self::BODY.0) != 0
    }

    /// Convenience: is this a header line?
    #[inline]
    pub const fn is_header(self) -> bool {
        (self.0 & Self::HEADER.0) != 0
    }

    /// Convenience: is this the end-of-stream marker?
    #[inline]
    pub const fn is_eos(self) -> bool {
        (self.0 & Self::EOS.0) != 0
    }
}

impl std::ops::BitOr for ClientWriteFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for ClientWriteFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for ClientWriteFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl fmt::Display for ClientWriteFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut maybe = |flag: ClientWriteFlags, name: &str| -> fmt::Result {
            if self.contains(flag) {
                if !first {
                    write!(f, "|")?;
                }
                write!(f, "{name}")?;
                first = false;
            }
            Ok(())
        };
        maybe(Self::BODY, "BODY")?;
        maybe(Self::INFO, "INFO")?;
        maybe(Self::HEADER, "HEADER")?;
        maybe(Self::STATUS, "STATUS")?;
        maybe(Self::CONNECT, "CONNECT")?;
        maybe(Self::ONEX, "ONEX")?;
        maybe(Self::TRAILER, "TRAILER")?;
        maybe(Self::EOS, "EOS")?;
        maybe(Self::ZEROLEN, "ZEROLEN")?;
        if first {
            write!(f, "(none)")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WriterPhase / ReaderPhase
// ---------------------------------------------------------------------------

/// Ordering key for the writer chain. Writers are sorted by phase so that
/// earlier phases (closer to the wire) run before later phases (closer to
/// the application).
///
/// Matches C `Curl_cwriter_phase`:
/// - `CURL_CW_RAW` = 0
/// - `CURL_CW_TRANSFER_DECODE` = 1
/// - `CURL_CW_PROTOCOL` = 2
/// - `CURL_CW_CONTENT_DECODE` = 3
/// - `CURL_CW_CLIENT` = 4
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WriterPhase {
    /// Raw tracing / verbose output — first in the chain.
    Raw = 0,
    /// Transfer-level decoding (e.g. chunked encoding removal).
    TransferDecode = 1,
    /// Protocol-specific processing (download progress, size enforcement).
    Protocol = 2,
    /// Content-level decoding (e.g. gzip, brotli, zstd decompression).
    ContentDecode = 3,
    /// Final client delivery — terminal writer.
    Client = 4,
}

impl fmt::Display for WriterPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Raw => write!(f, "Raw"),
            Self::TransferDecode => write!(f, "TransferDecode"),
            Self::Protocol => write!(f, "Protocol"),
            Self::ContentDecode => write!(f, "ContentDecode"),
            Self::Client => write!(f, "Client"),
        }
    }
}

/// Ordering key for the reader chain. Readers are sorted by phase so that
/// the client source is read first, then protocol framing, then transport
/// encoding is applied.
///
/// Matches C `Curl_creader_phase`:
/// - `CURL_CR_NET` = 0
/// - `CURL_CR_TRANSFER_ENCODE` = 1
/// - `CURL_CR_PROTOCOL` = 2
/// - `CURL_CR_CONTENT_ENCODE` = 3
/// - `CURL_CR_CLIENT` = 4
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReaderPhase {
    /// Network-facing (transport) layer.
    Net = 0,
    /// Transfer-level encoding (e.g. chunked encoding addition).
    TransferEncode = 1,
    /// Protocol-specific processing.
    Protocol = 2,
    /// Content-level encoding (e.g. line conversion for ASCII mode).
    ContentEncode = 3,
    /// Client-facing (application) layer — the data source.
    Client = 4,
}

impl fmt::Display for ReaderPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Net => write!(f, "Net"),
            Self::TransferEncode => write!(f, "TransferEncode"),
            Self::Protocol => write!(f, "Protocol"),
            Self::ContentEncode => write!(f, "ContentEncode"),
            Self::Client => write!(f, "Client"),
        }
    }
}

/// Commands that can be issued to the reader chain, matching
/// C `Curl_creader_cntrl`:
/// - `CURL_CRCNTRL_REWIND`
/// - `CURL_CRCNTRL_UNPAUSE`
/// - `CURL_CRCNTRL_CLEAR_EOS`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderControl {
    /// Rewind all readers to the beginning for a retry request.
    Rewind,
    /// Resume a paused reader.
    Unpause,
    /// Clear the end-of-stream flag (allow further reads).
    ClearEos,
}

// ---------------------------------------------------------------------------
// ClientWriter trait
// ---------------------------------------------------------------------------

/// A single layer in the writer (download) pipeline.
///
/// Implementations process downloaded data and (typically) forward it to the
/// next writer in the chain. This replaces the C `struct Curl_cwtype` vtable.
pub trait ClientWriter: fmt::Debug {
    /// The name of this writer, used for diagnostics and lookup.
    fn name(&self) -> &str;

    /// The phase this writer belongs to. Determines ordering in the chain.
    fn phase(&self) -> WriterPhase;

    /// Process `data` with the given `flags`. Returns the number of bytes
    /// consumed from `data`.
    ///
    /// Returns [`CurlError::WriteError`] if the write chain fails,
    /// [`CurlError::FileSizeExceeded`] if max body size is exceeded,
    /// or [`CurlError::Again`] if currently paused.
    fn write(&mut self, data: &[u8], flags: ClientWriteFlags) -> Result<usize, CurlError>;

    /// Notify this writer that no more data will be sent. Release resources.
    fn close(&mut self) -> Result<(), CurlError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ClientReader trait
// ---------------------------------------------------------------------------

/// A single layer in the reader (upload) pipeline.
///
/// Implementations produce upload data and (typically) pull it from the next
/// reader in the chain. This replaces the C `struct Curl_crtype` vtable.
pub trait ClientReader: fmt::Debug {
    /// The name of this reader, used for diagnostics and lookup.
    fn name(&self) -> &str;

    /// The phase this reader belongs to.
    fn phase(&self) -> ReaderPhase;

    /// Read up to `buf.len()` bytes. Returns `(bytes_read, eos)` where
    /// `eos` is `true` when no more data will follow.
    ///
    /// Returns [`CurlError::ReadError`] on read failures,
    /// [`CurlError::AbortedByCallback`] when a user callback aborts,
    /// or [`CurlError::Again`] when paused.
    fn read(&mut self, buf: &mut [u8]) -> Result<(usize, bool), CurlError>;

    /// Whether the reader needs to rewind before a retry request.
    fn needs_rewind(&self) -> bool {
        false
    }

    /// Total content length, if known. Returns `None` when indeterminate
    /// (e.g. chunked encoding, line conversion changes length).
    fn total_length(&self) -> Option<u64> {
        None
    }

    /// Attempt to resume reading from the given byte offset.
    /// Returns `0` if no resume offset is applicable.
    fn resume_from(&self) -> u64 {
        0
    }

    /// Handle a control command (rewind, unpause, clear-eos).
    fn control(&mut self, _cmd: ReaderControl) -> Result<(), CurlError> {
        Ok(())
    }

    /// Whether this reader is currently paused.
    fn is_paused(&self) -> bool {
        false
    }

    /// Whether this reader has delivered all data.
    fn done(&self) -> bool {
        false
    }

    /// Shut down this reader, releasing resources.
    fn close(&mut self) -> Result<(), CurlError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WriterChain
// ---------------------------------------------------------------------------

/// An ordered collection of [`ClientWriter`] layers forming the download
/// pipeline.
///
/// Writers are sorted by [`WriterPhase`] — lower phase values run first.
/// The `write()` entry point forwards data through the chain from the lowest
/// (wire-side) phase to the highest (application-side) phase.
///
/// This replaces the C `writer_stack` singly-linked list of `Curl_cwriter`
/// nodes.
pub struct WriterChain {
    /// Writers in phase order (ascending: Raw → Client).
    writers: Vec<Box<dyn ClientWriter>>,
    /// Whether the entire chain is in a paused state.
    paused: bool,
}

impl fmt::Debug for WriterChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriterChain")
            .field("count", &self.writers.len())
            .field("paused", &self.paused)
            .finish()
    }
}

impl WriterChain {
    /// Create an empty writer chain.
    pub fn new() -> Self {
        Self {
            writers: Vec::new(),
            paused: false,
        }
    }

    /// Add a writer to the chain, inserted in phase order.
    ///
    /// If multiple writers share a phase, the most recently added one
    /// comes first within that phase (matching C `Curl_cwriter_add` which
    /// inserts as first in its phase).
    pub fn add(&mut self, writer: Box<dyn ClientWriter>) {
        let phase = writer.phase();
        // Find the insertion point: skip writers with lower phases.
        let pos = self
            .writers
            .iter()
            .position(|w| w.phase() >= phase)
            .unwrap_or(self.writers.len());
        self.writers.insert(pos, writer);
    }

    /// Number of writers in the chain.
    pub fn count(&self) -> usize {
        self.writers.len()
    }

    /// Look up a writer by name (e.g. `"raw"`, `"download"`, `"pause"`).
    pub fn get_by_name(&self, name: &str) -> Option<&dyn ClientWriter> {
        self.writers
            .iter()
            .find(|w| w.name() == name)
            .map(|w| w.as_ref())
    }

    /// Whether the chain is currently in a paused state.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Check whether any writer in the chain performs content decoding.
    pub fn is_content_decoding(&self) -> bool {
        self.writers
            .iter()
            .any(|w| w.phase() == WriterPhase::ContentDecode)
    }

    /// Resume the chain from a paused state.
    pub fn unpause(&mut self) {
        self.paused = false;
        tracing::debug!("writer chain unpaused");
    }

    /// Write `data` through the chain. Each writer processes the data in
    /// phase order.
    ///
    /// When the chain is paused and the data is not an EOS marker, returns
    /// [`CurlError::Again`].
    pub fn write(
        &mut self,
        data: &[u8],
        flags: ClientWriteFlags,
    ) -> Result<usize, CurlError> {
        if self.paused && !flags.is_eos() {
            tracing::trace!("writer chain paused, buffering data");
            return Err(CurlError::Again);
        }

        if self.writers.is_empty() {
            if data.is_empty() || flags.is_eos() {
                return Ok(0);
            }
            tracing::warn!("writer chain is empty, returning write error");
            return Err(CurlError::WriteError);
        }

        // Forward data through all writers in phase order.
        // Each writer independently processes the full buffer.
        let mut last_written = data.len();
        for writer in &mut self.writers {
            last_written = writer.write(data, flags)?;
        }

        tracing::trace!(
            flags = %flags,
            len = data.len(),
            written = last_written,
            "writer chain complete"
        );

        Ok(last_written)
    }

    /// Reset the chain for reuse (clear paused state, keep writers).
    pub fn reset(&mut self) {
        self.paused = false;
    }

    /// Tear down the chain, closing and dropping all writers.
    pub fn cleanup(&mut self) {
        for w in &mut self.writers {
            let _ = w.close();
        }
        self.writers.clear();
        self.paused = false;
    }
}

impl Default for WriterChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ReaderChain
// ---------------------------------------------------------------------------

/// An ordered collection of [`ClientReader`] layers forming the upload
/// pipeline.
///
/// Readers are sorted by [`ReaderPhase`] — the client source (highest phase)
/// is read by the network-facing reader (lowest phase) through the chain.
///
/// This replaces the C `reader_stack` singly-linked list of `Curl_creader`
/// nodes.
pub struct ReaderChain {
    /// Readers in phase order (ascending: Net → Client).
    readers: Vec<Box<dyn ClientReader>>,
    /// Whether the chain is paused.
    paused: bool,
    /// Whether end-of-stream has been reached.
    eos: bool,
    /// Whether a rewind has been requested for the next start.
    rewind_requested: bool,
    /// Whether the reader chain has been started (for rate limiter init).
    started: bool,
}

impl fmt::Debug for ReaderChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReaderChain")
            .field("count", &self.readers.len())
            .field("paused", &self.paused)
            .field("eos", &self.eos)
            .field("rewind_requested", &self.rewind_requested)
            .finish()
    }
}

impl ReaderChain {
    /// Create an empty reader chain.
    pub fn new() -> Self {
        Self {
            readers: Vec::new(),
            paused: false,
            eos: false,
            rewind_requested: false,
            started: false,
        }
    }

    /// Add a reader, inserted in phase order.
    ///
    /// If multiple readers share a phase, the most recently added one
    /// comes first within that phase (matching C `Curl_creader_add`).
    pub fn add(&mut self, reader: Box<dyn ClientReader>) {
        let phase = reader.phase();
        let pos = self
            .readers
            .iter()
            .position(|r| r.phase() >= phase)
            .unwrap_or(self.readers.len());
        self.readers.insert(pos, reader);
    }

    /// Replace the entire reader list.
    pub fn set(&mut self, readers: Vec<Box<dyn ClientReader>>) {
        self.readers = readers;
        self.readers.sort_by_key(|r| r.phase() as u8);
    }

    /// Install a [`FreadReader`] as the client-phase reader, replacing any
    /// existing client-phase reader.
    pub fn set_fread(&mut self, reader: FreadReader) {
        self.readers.retain(|r| r.phase() != ReaderPhase::Client);
        self.add(Box::new(reader));
        tracing::debug!("installed fread reader");
    }

    /// Install a [`NullReader`] (EOF-only) as the client-phase reader.
    pub fn set_null(&mut self) {
        self.readers.retain(|r| r.phase() != ReaderPhase::Client);
        self.add(Box::new(NullReader::new()));
        tracing::debug!("installed null reader");
    }

    /// Install a [`StaticBufReader`] as the client-phase reader.
    pub fn set_buf(&mut self, data: Vec<u8>) {
        self.readers.retain(|r| r.phase() != ReaderPhase::Client);
        let len = data.len();
        self.add(Box::new(StaticBufReader::new(data)));
        tracing::debug!(len, "installed static buf reader");
    }

    /// Read from the chain. Data flows from the highest phase (client) down
    /// to the lowest phase (network). The last reader in the chain (highest
    /// phase) is the data source; intermediate readers transform the data.
    ///
    /// Returns `(bytes_read, eos)`.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<(usize, bool), CurlError> {
        if self.paused {
            tracing::trace!("reader chain is paused");
            return Err(CurlError::Again);
        }
        if self.eos {
            return Ok((0, true));
        }

        // Read from the highest-phase (last) reader — this is the data source.
        // In a full pipeline, intermediate readers would wrap data from the
        // next-higher-phase reader. Our chain stores them in ascending order,
        // so the client reader is last.
        if let Some(reader) = self.readers.last_mut() {
            let (n, eos) = reader.read(buf)?;
            if eos {
                self.eos = true;
            }
            tracing::trace!(
                len = buf.len(),
                nread = n,
                eos,
                "reader chain read"
            );
            Ok((n, eos))
        } else {
            // Empty chain — no data source.
            tracing::warn!("reader chain is empty, returning read error");
            Err(CurlError::ReadError)
        }
    }

    /// Whether any reader needs rewind before a retry.
    pub fn needs_rewind(&self) -> bool {
        self.readers.iter().any(|r| r.needs_rewind())
    }

    /// Whether the chain will rewind on the next start.
    pub fn will_rewind(&self) -> bool {
        self.rewind_requested
    }

    /// Request a rewind for the next client_start call.
    pub fn set_rewind(&mut self) -> Result<(), CurlError> {
        self.rewind_requested = true;
        self.eos = false;
        tracing::debug!("reader rewind requested");
        Ok(())
    }

    /// Total content length, if known by the top-of-chain reader.
    /// Returns `None` if indeterminate (e.g. encoding changes length).
    pub fn total_length(&self) -> Option<u64> {
        // First reader in the chain (network-facing) determines the total
        // length for the transport. If there are encoding readers, they may
        // change the length. Check the first reader.
        if let Some(reader) = self.readers.first() {
            reader.total_length()
        } else {
            None
        }
    }

    /// Client-provided content length (from the client-phase reader).
    pub fn client_length(&self) -> Option<u64> {
        // The client-phase reader is the last one in the chain.
        self.readers
            .iter()
            .rev()
            .find(|r| r.phase() == ReaderPhase::Client)
            .and_then(|r| r.total_length())
    }

    /// Resume offset from the client-phase reader.
    pub fn resume_from(&self) -> u64 {
        self.readers
            .iter()
            .rev()
            .find(|r| r.phase() == ReaderPhase::Client)
            .map_or(0, |r| r.resume_from())
    }

    /// Resume all paused readers in the chain.
    pub fn unpause(&mut self) -> Result<(), CurlError> {
        self.paused = false;
        for r in &mut self.readers {
            r.control(ReaderControl::Unpause)?;
            tracing::trace!(reader = r.name(), "unpaused reader");
        }
        Ok(())
    }

    /// Whether the chain is paused.
    pub fn is_paused(&self) -> bool {
        self.paused || self.readers.iter().any(|r| r.is_paused())
    }

    /// Clear the end-of-stream flag (for retries after rewind).
    pub fn clear_eos(&mut self) {
        self.eos = false;
        for r in &mut self.readers {
            let _ = r.control(ReaderControl::ClearEos);
        }
    }

    /// Whether all data has been delivered.
    pub fn done(&self) -> bool {
        self.eos
    }

    /// Reset the chain for reuse (clear state, keep readers).
    pub fn reset(&mut self) {
        self.paused = false;
        self.eos = false;
        self.started = false;
    }

    /// Tear down, closing and dropping all readers.
    pub fn cleanup(&mut self) {
        for r in &mut self.readers {
            let _ = r.close();
        }
        self.readers.clear();
        self.paused = false;
        self.eos = false;
        self.rewind_requested = false;
        self.started = false;
    }
}

impl Default for ReaderChain {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Concrete Writers
// ===========================================================================

/// **Raw writer** — first layer in the download chain (phase `Raw`).
///
/// Performs verbose tracing via the `tracing` crate and passes data through
/// unmodified. Replaces C `cw_raw` writer that calls
/// `Curl_debug(CURLINFO_DATA_IN, …)` for body data tracing.
#[derive(Debug)]
pub struct RawWriter {
    /// Total body bytes traced through this writer.
    bytes_written: u64,
}

impl RawWriter {
    /// Create a new raw tracing writer.
    pub fn new() -> Self {
        Self { bytes_written: 0 }
    }
}

impl ClientWriter for RawWriter {
    fn name(&self) -> &str {
        "raw"
    }

    fn phase(&self) -> WriterPhase {
        WriterPhase::Raw
    }

    fn write(&mut self, data: &[u8], flags: ClientWriteFlags) -> Result<usize, CurlError> {
        // Trace body data for verbose output, matching C cw_raw_write.
        if flags.is_body() {
            tracing::debug!(
                writer = "raw",
                len = data.len(),
                flags = %flags,
                total = self.bytes_written,
                "raw body data"
            );
        }
        self.bytes_written += data.len() as u64;
        Ok(data.len())
    }
}

impl Default for RawWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// **Download writer** — tracks progress, enforces max-size, distinguishes
/// body vs. header data. Operates at phase `Protocol`.
///
/// Replaces the C `cw_download` writer at `CURL_CW_PROTOCOL` phase that:
/// 1. Records TIMER_STARTTRANSFER on first non-info/connect data
/// 2. Starts the download rate limiter on first body data
/// 3. Enforces `max_filesize` and `maxdownload` limits
/// 4. Tracks `bytecount` for progress reporting
/// 5. Detects excess data beyond Content-Length
#[derive(Debug)]
pub struct DownloadWriter {
    /// Total body bytes received so far (matches C `data->req.bytecount`).
    body_bytes: u64,
    /// Maximum allowed download body size (0 = unlimited).
    /// Corresponds to `data->req.maxdownload`.
    max_download: u64,
    /// Maximum allowed file size (0 = unlimited).
    /// Corresponds to `data->set.max_filesize`.
    max_filesize: u64,
    /// Expected total body size (-1 = unknown).
    /// Corresponds to `data->req.size`.
    expected_size: i64,
    /// Whether body data should be suppressed (`data->req.no_body`).
    no_body: bool,
    /// Whether the response has started (non-info, non-connect data seen).
    started_response: bool,
    /// Whether body transfer has started.
    started_body: bool,
    /// Whether the download is complete.
    download_done: bool,
    /// Whether we have received headers (for WeirdServerReply detection).
    has_headers: bool,
}

impl DownloadWriter {
    /// Create a new download writer with default (unlimited) settings.
    pub fn new() -> Self {
        Self {
            body_bytes: 0,
            max_download: 0,
            max_filesize: 0,
            expected_size: -1,
            no_body: false,
            started_response: false,
            started_body: false,
            download_done: false,
            has_headers: false,
        }
    }

    /// Set the maximum download body size, matching `data->req.maxdownload`.
    pub fn set_max_download(&mut self, max: u64) {
        self.max_download = max;
    }

    /// Set the maximum file size, matching `CURLOPT_MAXFILESIZE_LARGE`.
    pub fn set_max_filesize(&mut self, max: u64) {
        self.max_filesize = max;
    }

    /// Set the expected total body size, matching `data->req.size`.
    pub fn set_expected_size(&mut self, size: i64) {
        self.expected_size = size;
    }

    /// Set the no-body flag (HEAD request).
    pub fn set_no_body(&mut self, no_body: bool) {
        self.no_body = no_body;
    }

    /// Mark that headers have been received.
    pub fn set_has_headers(&mut self, has: bool) {
        self.has_headers = has;
    }

    /// Whether the download is complete.
    pub fn is_download_done(&self) -> bool {
        self.download_done
    }

    /// Returns the number of body bytes counted so far.
    pub fn body_bytes(&self) -> u64 {
        self.body_bytes
    }

    /// Helper: compute maximum write length given a limit.
    fn max_body_write_len(&self, limit: u64) -> usize {
        if limit > 0 {
            let remaining = limit.saturating_sub(self.body_bytes);
            if remaining > usize::MAX as u64 {
                usize::MAX
            } else {
                remaining as usize
            }
        } else {
            usize::MAX
        }
    }
}

impl ClientWriter for DownloadWriter {
    fn name(&self) -> &str {
        "download"
    }

    fn phase(&self) -> WriterPhase {
        // Matches C cw_download at CURL_CW_PROTOCOL.
        WriterPhase::Protocol
    }

    fn write(&mut self, data: &[u8], flags: ClientWriteFlags) -> Result<usize, CurlError> {
        let is_connect = flags.contains(ClientWriteFlags::CONNECT);
        let is_info = flags.contains(ClientWriteFlags::INFO);

        // Record TIMER_STARTTRANSFER on first non-info/connect data.
        if !self.started_response && !is_info && !is_connect {
            self.started_response = true;
            tracing::debug!("download: response transfer started");
        }

        // Non-body data (headers, info) passes through directly.
        if !flags.is_body() {
            tracing::trace!(
                writer = "download",
                len = data.len(),
                flags = %flags,
                "download_write header/info"
            );
            return Ok(data.len());
        }

        // Start rate limiter on first body data.
        if !self.started_body && !is_info && !is_connect {
            self.started_body = true;
            tracing::debug!("download: body transfer started");
        }

        // Handle no_body: body arrives but we don't want it.
        if self.no_body && !data.is_empty() {
            tracing::info!(
                len = data.len(),
                "download: body received but no_body is set"
            );
            self.download_done = true;
            if self.has_headers {
                return Ok(data.len());
            }
            return Err(CurlError::WeirdServerReply);
        }

        // Enforce max_download limit.
        let mut nwrite = data.len();
        let mut excess_len: usize = 0;

        if self.max_download > 0 {
            let wmax = self.max_body_write_len(self.max_download);
            if nwrite > wmax {
                excess_len = nwrite - wmax;
                nwrite = wmax;
            }
            if nwrite == wmax {
                self.download_done = true;
            }
            // Check for premature EOF with EOS flag.
            if flags.is_eos()
                && !self.no_body
                && self.expected_size >= 0
                && (self.expected_size as u64) > self.body_bytes
            {
                tracing::warn!(
                    missing = (self.expected_size as u64) - self.body_bytes,
                    "end of response with bytes missing"
                );
                return Err(CurlError::PartialFile);
            }
        }

        // Enforce max_filesize limit.
        if self.max_filesize > 0 {
            let wmax = self.max_body_write_len(self.max_filesize);
            if nwrite > wmax {
                nwrite = wmax;
            }
        }

        // Update byte counter.
        self.body_bytes += nwrite as u64;

        // Check for excess or file size exceeded.
        if excess_len > 0 {
            tracing::info!(
                excess = excess_len,
                total = self.body_bytes,
                "download: excess data beyond Content-Length"
            );
        } else if nwrite < data.len() {
            // max_filesize was exceeded.
            tracing::warn!(
                max = self.max_filesize,
                total = self.body_bytes,
                "download: max file size exceeded"
            );
            return Err(CurlError::FileSizeExceeded);
        }

        tracing::trace!(
            writer = "download",
            len = data.len(),
            nwrite,
            total = self.body_bytes,
            flags = %flags,
            "download_write body"
        );

        Ok(nwrite)
    }
}

impl Default for DownloadWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// **Pause writer** — buffers data when the transfer is paused (phase
/// `Protocol`).
///
/// When unpaused, the buffered data can be flushed to the next writer.
/// Replaces the C `cw-pause` writer using [`DynBuf`] for buffering.
#[derive(Debug)]
pub struct PauseWriter {
    /// Buffer for data accumulated while paused.
    buffer: DynBuf,
    /// Current pause state.
    paused: bool,
}

impl PauseWriter {
    /// Create a new pause-aware writer.
    pub fn new() -> Self {
        Self {
            buffer: DynBuf::new(),
            paused: false,
        }
    }

    /// Pause buffering — subsequent writes accumulate in the internal buffer.
    pub fn pause(&mut self) {
        self.paused = true;
        tracing::debug!("pause writer: paused");
    }

    /// Unpause — caller should flush buffered data.
    pub fn unpause(&mut self) {
        self.paused = false;
        tracing::debug!("pause writer: unpaused");
    }

    /// Access the buffered data (for flushing after unpause).
    pub fn buffered(&self) -> &[u8] {
        self.buffer.as_bytes()
    }

    /// Whether any data is buffered.
    pub fn has_buffered(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// Clear the internal buffer after flushing.
    pub fn clear_buffer(&mut self) {
        self.buffer.reset();
    }
}

impl ClientWriter for PauseWriter {
    fn name(&self) -> &str {
        "pause"
    }

    fn phase(&self) -> WriterPhase {
        // Matches C cw-pause at CURL_CW_PROTOCOL.
        WriterPhase::Protocol
    }

    fn write(&mut self, data: &[u8], flags: ClientWriteFlags) -> Result<usize, CurlError> {
        if self.paused && !flags.is_eos() {
            // Buffer the data for later flushing using DynBuf.
            // Map allocation failures to OutOfMemory — matches C behavior
            // where cw_pause_write returns CURLE_OUT_OF_MEMORY on buf failure.
            self.buffer.add(data).map_err(|_| {
                tracing::warn!(
                    writer = "pause",
                    len = data.len(),
                    "pause buffer allocation failed"
                );
                CurlError::OutOfMemory
            })?;
            tracing::trace!(
                writer = "pause",
                buffered = self.buffer.len(),
                "paused — buffering"
            );
            return Ok(data.len());
        }
        // Not paused — data passes through.
        Ok(data.len())
    }

    fn close(&mut self) -> Result<(), CurlError> {
        // Free the buffer completely on close.
        self.buffer.free();
        Ok(())
    }
}

impl Default for PauseWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// **Out writer** — transport sink (terminal layer, phase `Client`).
///
/// This is the final layer in the default writer chain. In a full
/// implementation, it invokes the user's `WRITEFUNCTION` callback. Here it
/// serves as the terminal layer that counts bytes delivered to the application.
///
/// Replaces the C `Curl_cwt_out` writer at `CURL_CW_CLIENT`.
#[derive(Debug)]
pub struct OutWriter {
    /// Total bytes delivered to the application.
    bytes_out: u64,
    /// Whether this writer is paused (application returned CURL_WRITEFUNC_PAUSE).
    paused: bool,
}

impl OutWriter {
    /// Create a new output-sink writer.
    pub fn new() -> Self {
        Self {
            bytes_out: 0,
            paused: false,
        }
    }

    /// Whether this writer is paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Total bytes delivered.
    pub fn bytes_out(&self) -> u64 {
        self.bytes_out
    }
}

impl ClientWriter for OutWriter {
    fn name(&self) -> &str {
        "out"
    }

    fn phase(&self) -> WriterPhase {
        // Matches C Curl_cwt_out at CURL_CW_CLIENT.
        WriterPhase::Client
    }

    fn write(&mut self, data: &[u8], flags: ClientWriteFlags) -> Result<usize, CurlError> {
        if self.paused && !flags.is_eos() {
            return Err(CurlError::Again);
        }
        self.bytes_out += data.len() as u64;
        tracing::trace!(
            writer = "out",
            len = data.len(),
            total = self.bytes_out,
            flags = %flags,
            "out_write"
        );
        Ok(data.len())
    }
}

impl Default for OutWriter {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Concrete Readers
// ===========================================================================

/// **Fread reader** — bridges to a user-supplied read callback (phase
/// `Client`).
///
/// In a full implementation, the callback would be a boxed closure matching
/// `CURLOPT_READFUNCTION`. This version reads from a `Vec<u8>` buffer that
/// simulates the callback's return data. The reader supports:
/// - EOF detection (returns `(0, true)` when exhausted)
/// - Abort simulation (returns [`CurlError::AbortedByCallback`])
/// - Pause state tracking
/// - Rewind via [`ReaderControl::Rewind`]
/// - Total length reporting
///
/// Replaces the C `cr_in` reader.
#[derive(Debug)]
pub struct FreadReader {
    /// Data to read from (simulates callback output).
    data: Vec<u8>,
    /// Current read position.
    pos: usize,
    /// Whether the reader is paused.
    paused: bool,
    /// Whether any data has been read (for needs_rewind).
    has_read: bool,
    /// Whether the reader has seen EOF.
    seen_eos: bool,
    /// Sticky error state — once errored, always returns this error.
    error_result: Option<CurlError>,
}

impl FreadReader {
    /// Create a new fread reader from a data buffer.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            pos: 0,
            paused: false,
            has_read: false,
            seen_eos: false,
            error_result: None,
        }
    }
}

impl ClientReader for FreadReader {
    fn name(&self) -> &str {
        "fread"
    }

    fn phase(&self) -> ReaderPhase {
        ReaderPhase::Client
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<(usize, bool), CurlError> {
        // Once errored, always return the same error (matching C cr_in_read).
        if let Some(err) = self.error_result {
            return Err(err);
        }
        // If paused, return Again.
        if self.paused {
            tracing::trace!("fread reader: paused, returning Again");
            return Err(CurlError::Again);
        }
        // If already at EOF, return immediately.
        if self.seen_eos {
            return Ok((0, true));
        }

        let remaining = &self.data[self.pos..];
        if remaining.is_empty() {
            self.seen_eos = true;
            tracing::trace!("fread reader: EOF reached");
            return Ok((0, true));
        }

        let n = cmp::min(buf.len(), remaining.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        self.has_read = true;

        let eos = self.pos >= self.data.len();
        if eos {
            self.seen_eos = true;
        }

        tracing::trace!(
            reader = "fread",
            requested = buf.len(),
            nread = n,
            total_read = self.pos,
            total_len = self.data.len(),
            eos,
            "fread_read"
        );

        Ok((n, eos))
    }

    fn needs_rewind(&self) -> bool {
        self.has_read
    }

    fn total_length(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }

    fn control(&mut self, cmd: ReaderControl) -> Result<(), CurlError> {
        match cmd {
            ReaderControl::Rewind => {
                if self.has_read {
                    tracing::debug!("fread reader: rewinding");
                }
                self.pos = 0;
                self.paused = false;
                self.seen_eos = false;
                self.error_result = None;
                // Note: has_read intentionally NOT reset — it tracks whether
                // the callback was ever used, for needs_rewind purposes after
                // a rewind. But we reset it here since the rewind succeeded.
                self.has_read = false;
            }
            ReaderControl::Unpause => {
                self.paused = false;
            }
            ReaderControl::ClearEos => {
                self.seen_eos = false;
            }
        }
        Ok(())
    }

    fn is_paused(&self) -> bool {
        self.paused
    }

    fn done(&self) -> bool {
        self.seen_eos
    }
}

/// **Line-conversion reader** — converts LF → CRLF for ASCII-mode FTP
/// (phase `ContentEncode`).
///
/// Uses a [`BufQ`] for intermediate buffering so that converted output can
/// exceed the input length without re-allocation per read. Faithfully
/// replicates the C `cr_lc` reader behavior including `prev_cr` tracking
/// to avoid double-converting existing CRLF sequences.
#[derive(Debug)]
pub struct LineCvtReader {
    /// The inner reader (next in chain — higher phase provides data).
    inner: Box<dyn ClientReader>,
    /// Conversion buffer.
    buf: BufQ,
    /// Whether the inner reader has returned EOF.
    read_eos: bool,
    /// Whether we have returned EOF to our caller.
    eos: bool,
    /// Whether the previous byte was a CR (to avoid \r\n → \r\r\n).
    prev_cr: bool,
}

impl LineCvtReader {
    /// Wrap an existing reader, inserting CRLF conversion.
    ///
    /// Uses a 16 KB chunk with soft limit, matching C `cr_lc_init`.
    pub fn new(inner: Box<dyn ClientReader>) -> Self {
        Self {
            inner,
            // 16 KB chunk, 1 max chunk, soft limit — matches C cr_lc_ctx.
            buf: BufQ::with_opts(16 * 1024, 1, BufQOpts::SOFT_LIMIT),
            read_eos: false,
            eos: false,
            prev_cr: false,
        }
    }
}

impl ClientReader for LineCvtReader {
    fn name(&self) -> &str {
        "linecvt"
    }

    fn phase(&self) -> ReaderPhase {
        // Matches C cr_lc at CURL_CR_CONTENT_ENCODE.
        ReaderPhase::ContentEncode
    }

    fn read(&mut self, output: &mut [u8]) -> Result<(usize, bool), CurlError> {
        if self.eos {
            return Ok((0, true));
        }

        // If conversion buffer is empty, read from inner and convert.
        if self.buf.is_empty() {
            if self.read_eos {
                self.eos = true;
                return Ok((0, true));
            }

            // Read from the inner reader into a temp buffer.
            let mut tmp = vec![0u8; output.len().max(4096)];
            let (nread, eos) = self.inner.read(&mut tmp)?;
            self.read_eos = eos;

            if nread == 0 {
                if self.read_eos {
                    self.eos = true;
                }
                return Ok((0, self.eos));
            }

            // Check if there are any bare LFs to convert.
            let has_lf = tmp[..nread].contains(&b'\n');
            if !has_lf {
                // Nothing to convert — pass through directly.
                let n = cmp::min(nread, output.len());
                output[..n].copy_from_slice(&tmp[..n]);
                if self.read_eos {
                    self.eos = true;
                }
                // Update prev_cr tracking.
                if n > 0 {
                    self.prev_cr = tmp[n - 1] == b'\r';
                }
                tracing::trace!(
                    reader = "linecvt",
                    nread = n,
                    eos = self.eos,
                    "passthrough (no LF)"
                );
                return Ok((n, self.eos));
            }

            // Convert LF → CRLF, respecting prev_cr to avoid \r\n → \r\r\n.
            // This matches the C cr_lc_read algorithm exactly.
            let input = &tmp[..nread];
            let mut start: usize = 0;
            for i in 0..nread {
                // If this byte is not LF, or if previous byte was CR
                // (meaning this is already a CRLF pair), skip it.
                if input[i] != b'\n' || self.prev_cr {
                    self.prev_cr = input[i] == b'\r';
                    continue;
                }
                self.prev_cr = false;

                // Write bytes before this LF.
                if i > start {
                    let _ = self.buf.write(&input[start..i]);
                }
                // Write CRLF replacement.
                let _ = self.buf.write(b"\r\n");
                start = i + 1;
            }
            // Write any leftover bytes after the last conversion.
            if start < nread {
                let _ = self.buf.write(&input[start..nread]);
            }
        }

        // Read from the conversion buffer.
        match self.buf.read(output) {
            Ok(n) => {
                let eos_now = self.read_eos && self.buf.is_empty();
                if eos_now {
                    self.eos = true;
                }
                tracing::trace!(
                    reader = "linecvt",
                    nread = n,
                    eos = eos_now,
                    "linecvt_read"
                );
                Ok((n, eos_now))
            }
            Err(CurlError::Again) => {
                // Buffer empty (shouldn't happen after conversion, but handle it).
                if self.read_eos {
                    self.eos = true;
                    Ok((0, true))
                } else {
                    Ok((0, false))
                }
            }
            Err(e) => Err(e),
        }
    }

    fn needs_rewind(&self) -> bool {
        self.inner.needs_rewind()
    }

    fn total_length(&self) -> Option<u64> {
        // Line conversion changes the length — indeterminate.
        None
    }

    fn control(&mut self, cmd: ReaderControl) -> Result<(), CurlError> {
        if cmd == ReaderControl::Rewind {
            self.buf.reset();
            self.eos = false;
            self.read_eos = false;
            self.prev_cr = false;
        }
        self.inner.control(cmd)
    }

    fn is_paused(&self) -> bool {
        self.inner.is_paused()
    }

    fn done(&self) -> bool {
        self.eos
    }
}

/// **Null reader** — produces immediate EOF (phase `Client`). Used when
/// no upload data is needed (e.g. GET requests).
///
/// Replaces the C `cr_null` reader.
#[derive(Debug, Clone, Copy)]
pub struct NullReader;

impl NullReader {
    /// Create a new null reader.
    pub fn new() -> Self {
        NullReader
    }
}

impl ClientReader for NullReader {
    fn name(&self) -> &str {
        "null"
    }

    fn phase(&self) -> ReaderPhase {
        ReaderPhase::Client
    }

    fn read(&mut self, _buf: &mut [u8]) -> Result<(usize, bool), CurlError> {
        Ok((0, true))
    }

    fn total_length(&self) -> Option<u64> {
        Some(0)
    }

    fn done(&self) -> bool {
        true
    }
}

impl Default for NullReader {
    fn default() -> Self {
        Self::new()
    }
}

/// **Static-buffer reader** — reads from an in-memory `Vec<u8>` (phase
/// `Client`).
///
/// Supports rewind and resume-from. Replaces the C `cr_buf` reader.
#[derive(Debug)]
pub struct StaticBufReader {
    /// Owned data buffer.
    data: Vec<u8>,
    /// Current read position.
    pos: usize,
}

impl StaticBufReader {
    /// Create a static-buffer reader from owned data.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }
}

impl ClientReader for StaticBufReader {
    fn name(&self) -> &str {
        "static_buf"
    }

    fn phase(&self) -> ReaderPhase {
        ReaderPhase::Client
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<(usize, bool), CurlError> {
        let remaining = &self.data[self.pos..];
        if remaining.is_empty() {
            tracing::trace!(reader = "static_buf", "EOF");
            return Ok((0, true));
        }
        let n = cmp::min(buf.len(), remaining.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        let eos = self.pos >= self.data.len();
        tracing::trace!(
            reader = "static_buf",
            nread = n,
            pos = self.pos,
            total = self.data.len(),
            eos,
            "static_buf_read"
        );
        Ok((n, eos))
    }

    fn needs_rewind(&self) -> bool {
        self.pos > 0
    }

    fn total_length(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }

    fn control(&mut self, cmd: ReaderControl) -> Result<(), CurlError> {
        match cmd {
            ReaderControl::Rewind => {
                tracing::debug!("static_buf reader: rewinding");
                self.pos = 0;
            }
            ReaderControl::Unpause | ReaderControl::ClearEos => {}
        }
        Ok(())
    }

    fn done(&self) -> bool {
        self.pos >= self.data.len()
    }
}

// ===========================================================================
// Top-level entry points
// ===========================================================================

/// Write `data` through a [`WriterChain`].
///
/// Convenience function matching C `Curl_client_write()`. Validates that
/// the write type flags are sensible before forwarding to the chain.
pub fn client_write(
    chain: &mut WriterChain,
    data: &[u8],
    flags: ClientWriteFlags,
) -> Result<(), CurlError> {
    // Validate flag combinations (matching C DEBUGASSERT checks):
    // Must have at least one of BODY|HEADER|INFO.
    debug_assert!(
        flags.is_body() || flags.is_header() || flags.contains(ClientWriteFlags::INFO),
        "client_write: must specify BODY, HEADER, or INFO"
    );

    chain.write(data, flags)?;
    tracing::trace!(
        flags = %flags,
        len = data.len(),
        "client_write complete"
    );
    Ok(())
}

/// Read up to `buf.len()` bytes from a [`ReaderChain`], with optional
/// rate limiting.
///
/// Convenience function matching C `Curl_client_read()`. When a rate limiter
/// is provided and active, the read size is capped to the available bandwidth
/// window.
///
/// Returns `(bytes_read, eos)`.
pub fn client_read(
    chain: &mut ReaderChain,
    buf: &mut [u8],
) -> Result<(usize, bool), CurlError> {
    client_read_with_limiter(chain, buf, None)
}

/// Read with optional rate limiting. This is the full implementation
/// matching C `Curl_client_read()` which integrates with the upload
/// rate limiter.
pub fn client_read_with_limiter(
    chain: &mut ReaderChain,
    buf: &mut [u8],
    mut limiter: Option<&mut RateLimiter>,
) -> Result<(usize, bool), CurlError> {
    if buf.is_empty() {
        return Ok((0, false));
    }

    // Initialize rate limiter on first read.
    if !chain.started {
        if let Some(ref mut rl) = limiter {
            rl.start(-1);
        }
        chain.started = true;
    }

    // Apply rate limiting: cap the read buffer size.
    let effective_len = if let Some(ref mut rl) = limiter {
        if rl.is_active() {
            let avail = rl.available();
            if avail <= 0 {
                // No bandwidth available — return empty without error.
                tracing::trace!("client_read: rate limited, no bandwidth available");
                return Ok((0, false));
            }
            cmp::min(buf.len(), avail as usize)
        } else {
            buf.len()
        }
    } else {
        buf.len()
    };

    let (nread, eos) = chain.read(&mut buf[..effective_len])?;

    tracing::trace!(
        requested = buf.len(),
        effective = effective_len,
        nread,
        eos,
        "client_read complete"
    );

    Ok((nread, eos))
}

/// Clean up a writer and reader chain pair, releasing all resources.
///
/// Matches C `Curl_client_cleanup()`.
pub fn client_cleanup(writers: &mut WriterChain, readers: &mut ReaderChain) {
    readers.cleanup();
    writers.cleanup();
    tracing::trace!("client_cleanup: writer and reader chains torn down");
}

/// Reset a writer and reader chain pair for reuse.
///
/// If a rewind has been requested on the reader chain, the readers are
/// preserved for rewinding. Otherwise, readers are reset.
///
/// Matches C `Curl_client_reset()`.
pub fn client_reset(writers: &mut WriterChain, readers: &mut ReaderChain) {
    if readers.will_rewind() {
        tracing::debug!("client_reset: will rewind reader, preserving readers");
    } else {
        tracing::trace!("client_reset: clearing readers");
        readers.reset();
    }
    writers.reset();
}

/// Prepare chains for a new transfer. If a rewind was requested, issue
/// the rewind control to all readers before resetting.
///
/// Matches C `Curl_client_start()`.
pub fn client_start(
    writers: &mut WriterChain,
    readers: &mut ReaderChain,
) -> Result<(), CurlError> {
    if readers.rewind_requested {
        tracing::debug!("client_start: rewinding readers");
        for r in &mut readers.readers {
            r.control(ReaderControl::Rewind).map_err(|e| {
                tracing::warn!(reader = r.name(), error = %e, "rewind failed");
                CurlError::SendFailRewind
            })?;
        }
        readers.rewind_requested = false;
        readers.reset();
    }
    writers.reset();
    readers.started = false;
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- ClientWriteFlags ---------------------------------------------------

    #[test]
    fn write_flags_empty() {
        let f = ClientWriteFlags::empty();
        assert!(!f.is_body());
        assert!(!f.is_header());
        assert!(!f.is_eos());
    }

    #[test]
    fn write_flags_body() {
        let f = ClientWriteFlags::BODY;
        assert!(f.is_body());
        assert!(!f.is_header());
    }

    #[test]
    fn write_flags_combine() {
        let f = ClientWriteFlags::BODY | ClientWriteFlags::EOS;
        assert!(f.is_body());
        assert!(f.is_eos());
        assert!(!f.is_header());
    }

    #[test]
    fn write_flags_contains() {
        let f = ClientWriteFlags::HEADER | ClientWriteFlags::STATUS;
        assert!(f.contains(ClientWriteFlags::HEADER));
        assert!(f.contains(ClientWriteFlags::STATUS));
        assert!(!f.contains(ClientWriteFlags::BODY));
    }

    #[test]
    fn write_flags_display() {
        let f = ClientWriteFlags::BODY | ClientWriteFlags::EOS;
        let s = f.to_string();
        assert!(s.contains("BODY"));
        assert!(s.contains("EOS"));
    }

    #[test]
    fn write_flags_display_empty() {
        let s = ClientWriteFlags::empty().to_string();
        assert_eq!(s, "(none)");
    }

    #[test]
    fn write_flags_all_constants() {
        // Verify each constant has a unique non-zero value.
        let flags = [
            ClientWriteFlags::BODY,
            ClientWriteFlags::INFO,
            ClientWriteFlags::HEADER,
            ClientWriteFlags::STATUS,
            ClientWriteFlags::CONNECT,
            ClientWriteFlags::ONEX,
            ClientWriteFlags::TRAILER,
            ClientWriteFlags::EOS,
            ClientWriteFlags::ZEROLEN,
        ];
        for (i, a) in flags.iter().enumerate() {
            assert_ne!(a.0, 0);
            for b in &flags[i + 1..] {
                assert_ne!(a.0, b.0, "duplicate flag value");
            }
        }
    }

    // -- WriterPhase / ReaderPhase ------------------------------------------

    #[test]
    fn writer_phase_ordering() {
        assert!((WriterPhase::Raw as u8) < (WriterPhase::TransferDecode as u8));
        assert!((WriterPhase::TransferDecode as u8) < (WriterPhase::Protocol as u8));
        assert!((WriterPhase::Protocol as u8) < (WriterPhase::ContentDecode as u8));
        assert!((WriterPhase::ContentDecode as u8) < (WriterPhase::Client as u8));
    }

    #[test]
    fn reader_phase_ordering() {
        assert!((ReaderPhase::Net as u8) < (ReaderPhase::TransferEncode as u8));
        assert!((ReaderPhase::TransferEncode as u8) < (ReaderPhase::Protocol as u8));
        assert!((ReaderPhase::Protocol as u8) < (ReaderPhase::ContentEncode as u8));
        assert!((ReaderPhase::ContentEncode as u8) < (ReaderPhase::Client as u8));
    }

    #[test]
    fn writer_phase_display() {
        assert_eq!(WriterPhase::Raw.to_string(), "Raw");
        assert_eq!(WriterPhase::TransferDecode.to_string(), "TransferDecode");
        assert_eq!(WriterPhase::Protocol.to_string(), "Protocol");
        assert_eq!(WriterPhase::ContentDecode.to_string(), "ContentDecode");
        assert_eq!(WriterPhase::Client.to_string(), "Client");
    }

    #[test]
    fn reader_phase_display() {
        assert_eq!(ReaderPhase::Net.to_string(), "Net");
        assert_eq!(ReaderPhase::TransferEncode.to_string(), "TransferEncode");
        assert_eq!(ReaderPhase::Protocol.to_string(), "Protocol");
        assert_eq!(ReaderPhase::ContentEncode.to_string(), "ContentEncode");
        assert_eq!(ReaderPhase::Client.to_string(), "Client");
    }

    // -- WriterChain --------------------------------------------------------

    #[test]
    fn writer_chain_empty() {
        let chain = WriterChain::new();
        assert_eq!(chain.count(), 0);
        assert!(!chain.is_paused());
        assert!(!chain.is_content_decoding());
    }

    #[test]
    fn writer_chain_add_and_count() {
        let mut chain = WriterChain::new();
        chain.add(Box::new(RawWriter::new()));
        chain.add(Box::new(OutWriter::new()));
        assert_eq!(chain.count(), 2);
    }

    #[test]
    fn writer_chain_phase_ordering() {
        let mut chain = WriterChain::new();
        // Add in reverse order — should be sorted by phase.
        chain.add(Box::new(OutWriter::new())); // Client
        chain.add(Box::new(RawWriter::new())); // Raw
        chain.add(Box::new(DownloadWriter::new())); // Protocol

        assert_eq!(chain.writers[0].phase(), WriterPhase::Raw);
        assert_eq!(chain.writers[1].phase(), WriterPhase::Protocol);
        assert_eq!(chain.writers[2].phase(), WriterPhase::Client);
    }

    #[test]
    fn writer_chain_write_through() {
        let mut chain = WriterChain::new();
        chain.add(Box::new(RawWriter::new()));
        chain.add(Box::new(OutWriter::new()));
        let n = chain.write(b"hello", ClientWriteFlags::BODY).unwrap();
        assert_eq!(n, 5);
    }

    #[test]
    fn writer_chain_empty_write_error() {
        let mut chain = WriterChain::new();
        let err = chain.write(b"hello", ClientWriteFlags::BODY);
        assert!(matches!(err, Err(CurlError::WriteError)));
    }

    #[test]
    fn writer_chain_paused_returns_again() {
        let mut chain = WriterChain::new();
        chain.add(Box::new(RawWriter::new()));
        chain.paused = true;
        let err = chain.write(b"hello", ClientWriteFlags::BODY);
        assert!(matches!(err, Err(CurlError::Again)));
    }

    #[test]
    fn writer_chain_get_by_name() {
        let mut chain = WriterChain::new();
        chain.add(Box::new(RawWriter::new()));
        chain.add(Box::new(OutWriter::new()));
        assert!(chain.get_by_name("raw").is_some());
        assert!(chain.get_by_name("out").is_some());
        assert!(chain.get_by_name("nonexistent").is_none());
    }

    #[test]
    fn writer_chain_cleanup() {
        let mut chain = WriterChain::new();
        chain.add(Box::new(RawWriter::new()));
        chain.cleanup();
        assert_eq!(chain.count(), 0);
    }

    // -- ReaderChain --------------------------------------------------------

    #[test]
    fn reader_chain_empty() {
        let chain = ReaderChain::new();
        assert!(!chain.is_paused());
        assert!(!chain.done());
    }

    #[test]
    fn reader_chain_empty_read_error() {
        let mut chain = ReaderChain::new();
        let mut buf = [0u8; 64];
        let err = chain.read(&mut buf);
        assert!(matches!(err, Err(CurlError::ReadError)));
    }

    #[test]
    fn reader_chain_null_reader() {
        let mut chain = ReaderChain::new();
        chain.set_null();
        let mut buf = [0u8; 64];
        let (n, eos) = chain.read(&mut buf).unwrap();
        assert_eq!(n, 0);
        assert!(eos);
    }

    #[test]
    fn reader_chain_static_buf() {
        let mut chain = ReaderChain::new();
        chain.set_buf(b"hello world".to_vec());
        let mut buf = [0u8; 64];
        let (n, eos) = chain.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello world");
        assert!(eos);
    }

    #[test]
    fn reader_chain_fread() {
        let mut chain = ReaderChain::new();
        chain.set_fread(FreadReader::new(b"test data".to_vec()));
        let mut buf = [0u8; 4];
        let (n1, eos1) = chain.read(&mut buf).unwrap();
        assert_eq!(n1, 4);
        assert!(!eos1);
        let (n2, eos2) = chain.read(&mut buf).unwrap();
        assert_eq!(n2, 4);
        assert!(!eos2);
        let (n3, eos3) = chain.read(&mut buf).unwrap();
        assert_eq!(n3, 1);
        assert!(eos3);
    }

    #[test]
    fn reader_chain_rewind() {
        let mut chain = ReaderChain::new();
        chain.set_buf(b"abc".to_vec());
        let mut buf = [0u8; 64];
        let _ = chain.read(&mut buf).unwrap();
        assert!(chain.done());
        chain.set_rewind().unwrap();
        assert!(!chain.done());
    }

    #[test]
    fn reader_chain_cleanup() {
        let mut chain = ReaderChain::new();
        chain.set_null();
        chain.cleanup();
        assert_eq!(chain.readers.len(), 0);
    }

    #[test]
    fn reader_chain_total_and_client_length() {
        let mut chain = ReaderChain::new();
        chain.set_buf(b"12345".to_vec());
        // Client length comes from the client-phase reader.
        assert_eq!(chain.client_length(), Some(5));
    }

    // -- Concrete writers ---------------------------------------------------

    #[test]
    fn raw_writer_counts_bytes() {
        let mut w = RawWriter::new();
        w.write(b"hello", ClientWriteFlags::BODY).unwrap();
        assert_eq!(w.bytes_written, 5);
    }

    #[test]
    fn raw_writer_phase() {
        let w = RawWriter::new();
        assert_eq!(w.phase(), WriterPhase::Raw);
    }

    #[test]
    fn download_writer_phase() {
        let w = DownloadWriter::new();
        assert_eq!(w.phase(), WriterPhase::Protocol);
    }

    #[test]
    fn download_writer_tracks_body() {
        let mut w = DownloadWriter::new();
        w.write(b"data", ClientWriteFlags::BODY).unwrap();
        assert_eq!(w.body_bytes(), 4);
        assert!(w.started_body);
    }

    #[test]
    fn download_writer_headers_pass_through() {
        let mut w = DownloadWriter::new();
        let n = w.write(b"HTTP/1.1 200 OK\r\n", ClientWriteFlags::HEADER).unwrap();
        assert_eq!(n, 17);
        assert_eq!(w.body_bytes(), 0);
    }

    #[test]
    fn download_writer_max_filesize() {
        let mut w = DownloadWriter::new();
        w.set_max_filesize(5);
        w.write(b"abc", ClientWriteFlags::BODY).unwrap();
        let err = w.write(b"defgh", ClientWriteFlags::BODY);
        assert!(matches!(err, Err(CurlError::FileSizeExceeded)));
    }

    #[test]
    fn download_writer_max_download() {
        let mut w = DownloadWriter::new();
        w.set_max_download(5);
        let n = w.write(b"abcdefgh", ClientWriteFlags::BODY).unwrap();
        assert_eq!(n, 5);
        assert!(w.is_download_done());
    }

    #[test]
    fn download_writer_no_body() {
        let mut w = DownloadWriter::new();
        w.set_no_body(true);
        w.set_has_headers(true);
        // Body arrives but no_body is set — should succeed because headers exist.
        let n = w.write(b"body data", ClientWriteFlags::BODY).unwrap();
        assert_eq!(n, 9);
        assert!(w.is_download_done());
    }

    #[test]
    fn download_writer_no_body_no_headers() {
        let mut w = DownloadWriter::new();
        w.set_no_body(true);
        // No headers received — should return WeirdServerReply.
        let err = w.write(b"body data", ClientWriteFlags::BODY);
        assert!(matches!(err, Err(CurlError::WeirdServerReply)));
    }

    #[test]
    fn download_writer_partial_file() {
        let mut w = DownloadWriter::new();
        w.set_max_download(100);
        w.set_expected_size(50);
        // EOS with bytes missing.
        let err = w.write(b"small", ClientWriteFlags::BODY | ClientWriteFlags::EOS);
        assert!(matches!(err, Err(CurlError::PartialFile)));
    }

    #[test]
    fn pause_writer_buffers() {
        let mut w = PauseWriter::new();
        w.pause();
        w.write(b"hello", ClientWriteFlags::BODY).unwrap();
        assert_eq!(w.buffered(), b"hello");
        assert!(w.has_buffered());
        w.unpause();
        w.clear_buffer();
        assert!(!w.has_buffered());
        assert!(w.buffered().is_empty());
    }

    #[test]
    fn pause_writer_close_frees() {
        let mut w = PauseWriter::new();
        w.pause();
        w.write(b"data", ClientWriteFlags::BODY).unwrap();
        w.close().unwrap();
        assert!(w.buffered().is_empty());
    }

    #[test]
    fn out_writer_counts() {
        let mut w = OutWriter::new();
        w.write(b"xyz", ClientWriteFlags::BODY).unwrap();
        assert_eq!(w.bytes_out(), 3);
    }

    #[test]
    fn out_writer_phase() {
        let w = OutWriter::new();
        assert_eq!(w.phase(), WriterPhase::Client);
    }

    // -- Concrete readers ---------------------------------------------------

    #[test]
    fn null_reader_immediate_eof() {
        let mut r = NullReader::new();
        let mut buf = [0u8; 32];
        let (n, eos) = r.read(&mut buf).unwrap();
        assert_eq!(n, 0);
        assert!(eos);
        assert!(r.done());
        assert_eq!(r.total_length(), Some(0));
    }

    #[test]
    fn static_buf_reader_full_read() {
        let mut r = StaticBufReader::new(b"hello".to_vec());
        assert_eq!(r.total_length(), Some(5));
        let mut buf = [0u8; 64];
        let (n, eos) = r.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert!(eos);
        assert!(r.done());
    }

    #[test]
    fn static_buf_reader_partial_read() {
        let mut r = StaticBufReader::new(b"abcde".to_vec());
        let mut buf = [0u8; 3];
        let (n, eos) = r.read(&mut buf).unwrap();
        assert_eq!(n, 3);
        assert!(!eos);
        let (n2, eos2) = r.read(&mut buf).unwrap();
        assert_eq!(n2, 2);
        assert!(eos2);
    }

    #[test]
    fn static_buf_reader_rewind() {
        let mut r = StaticBufReader::new(b"ab".to_vec());
        let mut buf = [0u8; 64];
        let _ = r.read(&mut buf).unwrap();
        assert!(r.done());
        assert!(r.needs_rewind());
        r.control(ReaderControl::Rewind).unwrap();
        assert!(!r.done());
        let (n, eos) = r.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ab");
        assert!(eos);
    }

    #[test]
    fn fread_reader_basic() {
        let mut r = FreadReader::new(b"hello".to_vec());
        assert_eq!(r.total_length(), Some(5));
        let mut buf = [0u8; 64];
        let (n, eos) = r.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert!(eos);
        assert!(r.done());
    }

    #[test]
    fn fread_reader_rewind() {
        let mut r = FreadReader::new(b"test".to_vec());
        let mut buf = [0u8; 2];
        r.read(&mut buf).unwrap();
        assert!(r.needs_rewind());
        r.control(ReaderControl::Rewind).unwrap();
        assert!(!r.needs_rewind());
        let (n, _) = r.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"te");
    }

    #[test]
    fn fread_reader_pause() {
        let mut r = FreadReader::new(b"data".to_vec());
        r.paused = true;
        let mut buf = [0u8; 4];
        let err = r.read(&mut buf);
        assert!(matches!(err, Err(CurlError::Again)));
        r.control(ReaderControl::Unpause).unwrap();
        assert!(!r.is_paused());
    }

    // -- Line conversion reader ---------------------------------------------

    #[test]
    fn linecvt_converts_bare_lf() {
        let inner = Box::new(StaticBufReader::new(b"a\nb\n".to_vec()));
        let mut reader = LineCvtReader::new(inner);
        let mut buf = [0u8; 64];
        let (n, _) = reader.read(&mut buf).unwrap();
        let output = &buf[..n];
        // Bare \n should become \r\n.
        assert!(
            output.windows(2).any(|w| w == b"\r\n"),
            "expected CRLF in output, got: {:?}",
            std::str::from_utf8(output)
        );
    }

    #[test]
    fn linecvt_preserves_existing_crlf() {
        let inner = Box::new(StaticBufReader::new(b"a\r\nb\r\n".to_vec()));
        let mut reader = LineCvtReader::new(inner);
        let mut buf = [0u8; 64];
        let (n, _) = reader.read(&mut buf).unwrap();
        let output = &buf[..n];
        // Existing \r\n should NOT become \r\r\n.
        assert!(
            !output.windows(3).any(|w| w == b"\r\r\n"),
            "double-converted CRLF found: {:?}",
            std::str::from_utf8(output)
        );
    }

    #[test]
    fn linecvt_phase_is_content_encode() {
        let inner = Box::new(StaticBufReader::new(Vec::new()));
        let reader = LineCvtReader::new(inner);
        assert_eq!(reader.phase(), ReaderPhase::ContentEncode);
    }

    #[test]
    fn linecvt_total_length_is_none() {
        let inner = Box::new(StaticBufReader::new(b"test".to_vec()));
        let reader = LineCvtReader::new(inner);
        // Line conversion changes the output length — indeterminate.
        assert_eq!(reader.total_length(), None);
    }

    // -- Top-level functions ------------------------------------------------

    #[test]
    fn client_write_through_chain() {
        let mut wc = WriterChain::new();
        wc.add(Box::new(RawWriter::new()));
        wc.add(Box::new(OutWriter::new()));
        client_write(&mut wc, b"data", ClientWriteFlags::BODY).unwrap();
    }

    #[test]
    fn client_read_from_chain() {
        let mut rc = ReaderChain::new();
        rc.set_buf(b"data".to_vec());
        let mut buf = [0u8; 64];
        let (n, eos) = client_read(&mut rc, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"data");
        assert!(eos);
    }

    #[test]
    fn client_start_with_rewind() {
        let mut wc = WriterChain::new();
        let mut rc = ReaderChain::new();
        wc.add(Box::new(RawWriter::new()));
        rc.set_buf(b"abc".to_vec());

        // Read all data.
        let mut buf = [0u8; 64];
        let _ = rc.read(&mut buf).unwrap();
        assert!(rc.done());

        // Request rewind and start.
        rc.set_rewind().unwrap();
        client_start(&mut wc, &mut rc).unwrap();

        // After start with rewind, the reader should be reset.
        assert!(!rc.done());
    }

    #[test]
    fn client_start_reset_cleanup() {
        let mut wc = WriterChain::new();
        let mut rc = ReaderChain::new();
        wc.add(Box::new(RawWriter::new()));
        rc.set_null();
        client_start(&mut wc, &mut rc).unwrap();
        client_reset(&mut wc, &mut rc);
        client_cleanup(&mut wc, &mut rc);
        assert_eq!(wc.count(), 0);
    }

    // -- Rate limiter integration -------------------------------------------

    #[test]
    fn client_read_with_rate_limiter() {
        let mut rc = ReaderChain::new();
        rc.set_buf(b"hello world".to_vec());

        let mut limiter = RateLimiter::new(5, 0).unwrap(); // 5 bytes/sec
        limiter.start(-1);

        let mut buf = [0u8; 64];
        let (n, _) = client_read_with_limiter(&mut rc, &mut buf, Some(&mut limiter)).unwrap();
        // Should have read some bytes (limiter starts with tokens = rate).
        assert!(n > 0);
    }

    // -- Default chains -----------------------------------------------------

    #[test]
    fn default_writer_chain_order() {
        let mut chain = WriterChain::new();
        chain.add(Box::new(OutWriter::new()));
        chain.add(Box::new(PauseWriter::new()));
        chain.add(Box::new(DownloadWriter::new()));
        chain.add(Box::new(RawWriter::new()));

        // Verify phase ordering: Raw < Protocol < Protocol < Client.
        assert_eq!(chain.writers[0].name(), "raw");
        // PauseWriter and DownloadWriter are both Protocol — insertion order.
        assert_eq!(chain.writers[1].name(), "download");
        assert_eq!(chain.writers[2].name(), "pause");
        assert_eq!(chain.writers[3].name(), "out");
    }
}
