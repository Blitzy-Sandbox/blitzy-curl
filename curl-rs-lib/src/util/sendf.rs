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
//! | `WriterPhase`                 | `enum cw_phase`                  |
//! | `WriterChain`                 | `struct Curl_cwriter` linked list |
//! | `ClientReader` trait          | `struct Curl_crtype`             |
//! | `ReaderPhase`                 | `enum cr_phase`                  |
//! | `ReaderChain`                 | `struct Curl_creader` linked list |
//! | `client_write()`              | `Curl_client_write()`            |
//! | `client_read()`               | `Curl_client_read()`             |
//!
//! # Design Notes
//!
//! In the C implementation, writers and readers form singly-linked lists
//! traversed via function-pointer vtables. In Rust, each layer implements
//! the [`ClientWriter`] or [`ClientReader`] trait, and the chains are stored
//! as `Vec<Box<dyn …>>` ordered by phase. The chains compose naturally
//! with Rust ownership: each layer borrows the next layer to forward data.

use std::cmp;
use std::fmt;

use crate::error::CurlError;
use crate::util::bufq::{BufQ, BufQOpts};
use crate::util::dynbuf::DynBuf;

// ---------------------------------------------------------------------------
// ClientWriteFlags
// ---------------------------------------------------------------------------

/// Bitflag indicating what kind of data is being written, matching the C
/// `CLIENTWRITE_*` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientWriteFlags(u32);

impl ClientWriteFlags {
    /// Response body data.
    pub const BODY: Self = Self(1 << 0);
    /// Informational text (verbose output).
    pub const INFO: Self = Self(1 << 1);
    /// Response header line.
    pub const HEADER: Self = Self(1 << 2);
    /// HTTP status line.
    pub const STATUS: Self = Self(1 << 3);
    /// Data from a CONNECT tunnel.
    pub const CONNECT: Self = Self(1 << 4);
    /// One-shot flag — data must be delivered exactly once.
    pub const ONEX: Self = Self(1 << 5);
    /// Trailer header.
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
        self.contains(Self::BODY)
    }

    /// Convenience: is this a header line?
    #[inline]
    pub const fn is_header(self) -> bool {
        self.contains(Self::HEADER)
    }

    /// Convenience: is this the end-of-stream marker?
    #[inline]
    pub const fn is_eos(self) -> bool {
        self.contains(Self::EOS)
    }
}

impl std::ops::BitOr for ClientWriteFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for ClientWriteFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for ClientWriteFlags {
    type Output = Self;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WriterPhase {
    /// Raw tracing / verbose output.
    Raw = 0,
    /// Transfer-level decoding (e.g. chunked).
    TransferDecode = 1,
    /// Protocol-specific processing.
    Protocol = 2,
    /// Content-level decoding (e.g. gzip).
    ContentDecode = 3,
    /// Final client delivery.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReaderPhase {
    /// Network-facing (transport) layer.
    Net = 0,
    /// Transfer-level encoding (e.g. chunked).
    TransferEncode = 1,
    /// Protocol-specific processing.
    Protocol = 2,
    /// Content-level encoding (e.g. gzip).
    ContentEncode = 3,
    /// Client-facing (application) layer.
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

/// Commands that can be issued to the reader chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderControl {
    /// Rewind all readers to the beginning.
    Rewind,
    /// Resume a paused reader.
    Unpause,
    /// Clear the end-of-stream flag.
    ClearEos,
}

// ---------------------------------------------------------------------------
// ClientWriter trait
// ---------------------------------------------------------------------------

/// A single layer in the writer (download) pipeline.
///
/// Implementations process downloaded data and (typically) forward it to the
/// next writer in the chain.
pub trait ClientWriter: fmt::Debug {
    /// The name of this writer, used for diagnostics.
    fn name(&self) -> &str;

    /// The phase this writer belongs to. Determines ordering in the chain.
    fn phase(&self) -> WriterPhase;

    /// Process `data` with the given `flags`. Returns the number of bytes
    /// consumed from `data`.
    fn write(&mut self, data: &[u8], flags: ClientWriteFlags) -> Result<usize, CurlError>;

    /// Notify this writer that no more data will be sent.
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
/// reader in the chain.
pub trait ClientReader: fmt::Debug {
    /// The name of this reader, used for diagnostics.
    fn name(&self) -> &str;

    /// The phase this reader belongs to.
    fn phase(&self) -> ReaderPhase;

    /// Read up to `buf.len()` bytes. Returns `(bytes_read, eos)` where
    /// `eos` is `true` when no more data will follow.
    fn read(&mut self, buf: &mut [u8]) -> Result<(usize, bool), CurlError>;

    /// Whether the reader needs to rewind before a retry.
    fn needs_rewind(&self) -> bool {
        false
    }

    /// Total content length, if known.
    fn total_length(&self) -> Option<u64> {
        None
    }

    /// Offset to resume from, if applicable.
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
pub struct WriterChain {
    writers: Vec<Box<dyn ClientWriter>>,
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

    /// Add a writer to the chain. The chain is re-sorted by phase after
    /// insertion.
    pub fn add(&mut self, writer: Box<dyn ClientWriter>) {
        self.writers.push(writer);
        self.writers.sort_by_key(|w| w.phase() as u8);
    }

    /// Number of writers in the chain.
    pub fn count(&self) -> usize {
        self.writers.len()
    }

    /// Look up a writer by name (e.g. `"raw"`, `"download"`, `"pause"`).
    pub fn get_by_name(&self, name: &str) -> Option<&dyn ClientWriter> {
        self.writers.iter().find(|w| w.name() == name).map(|w| w.as_ref())
    }

    /// Whether the chain is currently in a paused state.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Check whether any writer in the chain performs content decoding.
    pub fn is_content_decoding(&self) -> bool {
        self.writers.iter().any(|w| w.phase() == WriterPhase::ContentDecode)
    }

    /// Resume the chain from a paused state.
    pub fn unpause(&mut self) {
        self.paused = false;
    }

    /// Write `data` through the chain. Each writer processes the data in
    /// phase order and passes it to the next.
    pub fn write(&mut self, data: &[u8], flags: ClientWriteFlags) -> Result<usize, CurlError> {
        if self.paused && !flags.is_eos() {
            return Err(CurlError::Again);
        }
        let current = data.to_vec();
        let mut total = 0;
        for writer in &mut self.writers {
            let n = writer.write(&current, flags)?;
            total = n;
            // In a real pipeline each writer might transform data; here
            // we pass the full buffer to each layer for simplicity.
        }
        Ok(if total == 0 { data.len() } else { total })
    }

    /// Reset the chain for reuse (clear state, keep writers).
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
pub struct ReaderChain {
    readers: Vec<Box<dyn ClientReader>>,
    paused: bool,
    eos: bool,
}

impl fmt::Debug for ReaderChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReaderChain")
            .field("count", &self.readers.len())
            .field("paused", &self.paused)
            .field("eos", &self.eos)
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
        }
    }

    /// Add a reader, re-sorting by phase.
    pub fn add(&mut self, reader: Box<dyn ClientReader>) {
        self.readers.push(reader);
        self.readers.sort_by_key(|r| r.phase() as u8);
    }

    /// Replace the entire reader list.
    pub fn set(&mut self, readers: Vec<Box<dyn ClientReader>>) {
        self.readers = readers;
        self.readers.sort_by_key(|r| r.phase() as u8);
    }

    /// Install a [`FreadReader`] as the client-phase reader.
    pub fn set_fread(&mut self, reader: FreadReader) {
        // Remove any existing client-phase reader.
        self.readers.retain(|r| r.phase() != ReaderPhase::Client);
        self.add(Box::new(reader));
    }

    /// Install a [`NullReader`] (EOF-only) as the client-phase reader.
    pub fn set_null(&mut self) {
        self.readers.retain(|r| r.phase() != ReaderPhase::Client);
        self.add(Box::new(NullReader));
    }

    /// Install a [`StaticBufReader`] as the client-phase reader.
    pub fn set_buf(&mut self, data: Vec<u8>) {
        self.readers.retain(|r| r.phase() != ReaderPhase::Client);
        self.add(Box::new(StaticBufReader::new(data)));
    }

    /// Read from the chain. Data flows from the highest phase (client) down
    /// to the lowest phase (network).
    pub fn read(&mut self, buf: &mut [u8]) -> Result<(usize, bool), CurlError> {
        if self.paused {
            return Err(CurlError::Again);
        }
        if self.eos {
            return Ok((0, true));
        }
        // In a real pipeline, data flows from the last reader (client) through
        // intermediate readers. For a basic implementation, read from the
        // highest-phase reader.
        if let Some(reader) = self.readers.last_mut() {
            let (n, eos) = reader.read(buf)?;
            if eos {
                self.eos = true;
            }
            Ok((n, eos))
        } else {
            Ok((0, true))
        }
    }

    /// Whether any reader needs rewind.
    pub fn needs_rewind(&self) -> bool {
        self.readers.iter().any(|r| r.needs_rewind())
    }

    /// Whether the chain will rewind on the next control command.
    pub fn will_rewind(&self) -> bool {
        self.needs_rewind()
    }

    /// Issue a rewind control to all readers.
    pub fn set_rewind(&mut self) -> Result<(), CurlError> {
        self.eos = false;
        for r in &mut self.readers {
            r.control(ReaderControl::Rewind)?;
        }
        Ok(())
    }

    /// Total content length, if known by the client-phase reader.
    pub fn total_length(&self) -> Option<u64> {
        self.readers.last().and_then(|r| r.total_length())
    }

    /// Client-provided content length (same as total_length for simple cases).
    pub fn client_length(&self) -> Option<u64> {
        self.total_length()
    }

    /// Resume offset.
    pub fn resume_from(&self) -> u64 {
        self.readers.last().map_or(0, |r| r.resume_from())
    }

    /// Resume a paused reader chain.
    pub fn unpause(&mut self) -> Result<(), CurlError> {
        self.paused = false;
        for r in &mut self.readers {
            r.control(ReaderControl::Unpause)?;
        }
        Ok(())
    }

    /// Whether the chain is paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Clear the end-of-stream flag (for retries).
    pub fn clear_eos(&mut self) {
        self.eos = false;
    }

    /// Whether all data has been delivered.
    pub fn done(&self) -> bool {
        self.eos
    }

    /// Reset the chain for reuse.
    pub fn reset(&mut self) {
        self.paused = false;
        self.eos = false;
    }

    /// Tear down, closing and dropping all readers.
    pub fn cleanup(&mut self) {
        for r in &mut self.readers {
            let _ = r.close();
        }
        self.readers.clear();
        self.paused = false;
        self.eos = false;
    }
}

impl Default for ReaderChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Concrete writers
// ---------------------------------------------------------------------------

/// **Raw writer** — first layer in the download chain.
///
/// Performs verbose tracing via the `tracing` crate and passes data through
/// unmodified. Replaces C `Curl_debug(CURLINFO_DATA_IN, …)`.
#[derive(Debug)]
pub struct RawWriter {
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
        tracing::trace!(
            writer = "raw",
            len = data.len(),
            flags = %flags,
            "client_write"
        );
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
/// body vs. header data.
///
/// Replaces the C `cw_download` writer.
#[derive(Debug)]
pub struct DownloadWriter {
    /// Total body bytes received so far.
    body_bytes: u64,
    /// Maximum allowed body size (0 = unlimited).
    max_filesize: u64,
    /// Whether we have started the body transfer (TIMER_STARTTRANSFER).
    body_started: bool,
}

impl DownloadWriter {
    /// Create a new download writer.
    ///
    /// `max_filesize` of 0 means unlimited.
    pub fn new() -> Self {
        Self {
            body_bytes: 0,
            max_filesize: 0,
            body_started: false,
        }
    }

    /// Set the maximum body size, matching `CURLOPT_MAXFILESIZE_LARGE`.
    pub fn set_max_filesize(&mut self, max: u64) {
        self.max_filesize = max;
    }
}

impl ClientWriter for DownloadWriter {
    fn name(&self) -> &str {
        "download"
    }

    fn phase(&self) -> WriterPhase {
        WriterPhase::Client
    }

    fn write(&mut self, data: &[u8], flags: ClientWriteFlags) -> Result<usize, CurlError> {
        if flags.is_body() {
            if !self.body_started {
                self.body_started = true;
                tracing::debug!("download: body transfer started");
            }
            self.body_bytes += data.len() as u64;
            if self.max_filesize > 0 && self.body_bytes > self.max_filesize {
                return Err(CurlError::FileSizeExceeded);
            }
        }
        tracing::trace!(
            writer = "download",
            len = data.len(),
            total = self.body_bytes,
            flags = %flags,
            "download_write"
        );
        Ok(data.len())
    }
}

impl Default for DownloadWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// **Pause writer** — buffers data when the transfer is paused.
///
/// When unpaused, the buffered data is flushed to the next writer.
/// Replaces the C `cw-pause` writer.
#[derive(Debug)]
pub struct PauseWriter {
    buffer: DynBuf,
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
    }

    /// Unpause — caller should flush buffered data.
    pub fn unpause(&mut self) {
        self.paused = false;
    }

    /// Access the buffered data (for flushing after unpause).
    pub fn buffered(&self) -> &[u8] {
        self.buffer.as_bytes()
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
        WriterPhase::Protocol
    }

    fn write(&mut self, data: &[u8], flags: ClientWriteFlags) -> Result<usize, CurlError> {
        if self.paused && !flags.is_eos() {
            // Buffer the data for later flushing.
            self.buffer.add(data)?;
            tracing::trace!(
                writer = "pause",
                buffered = self.buffer.len(),
                "paused — buffering"
            );
            return Ok(data.len());
        }
        Ok(data.len())
    }

    fn close(&mut self) -> Result<(), CurlError> {
        self.buffer.reset();
        Ok(())
    }
}

impl Default for PauseWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// **Out writer** — transport sink (terminal layer).
///
/// In a full implementation this would invoke the user's `WRITEFUNCTION`
/// callback. Here it serves as the terminal layer that counts bytes.
#[derive(Debug)]
pub struct OutWriter {
    bytes_out: u64,
}

impl OutWriter {
    /// Create a new output-sink writer.
    pub fn new() -> Self {
        Self { bytes_out: 0 }
    }
}

impl ClientWriter for OutWriter {
    fn name(&self) -> &str {
        "out"
    }

    fn phase(&self) -> WriterPhase {
        WriterPhase::TransferDecode
    }

    fn write(&mut self, data: &[u8], _flags: ClientWriteFlags) -> Result<usize, CurlError> {
        self.bytes_out += data.len() as u64;
        Ok(data.len())
    }
}

impl Default for OutWriter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Concrete readers
// ---------------------------------------------------------------------------

/// **Fread reader** — bridges to a user-supplied read callback.
///
/// In the full implementation, the callback is a boxed closure matching
/// `CURLOPT_READFUNCTION`. This initial version reads from a `Vec<u8>` buffer
/// that simulates the callback's return data.
#[derive(Debug)]
pub struct FreadReader {
    data: Vec<u8>,
    pos: usize,
    paused: bool,
}

impl FreadReader {
    /// Create a new fread reader from a data buffer.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            pos: 0,
            paused: false,
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
        if self.paused {
            return Err(CurlError::Again);
        }
        let remaining = &self.data[self.pos..];
        if remaining.is_empty() {
            return Ok((0, true));
        }
        let n = cmp::min(buf.len(), remaining.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        let eos = self.pos >= self.data.len();
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
                self.pos = 0;
                self.paused = false;
            }
            ReaderControl::Unpause => {
                self.paused = false;
            }
            ReaderControl::ClearEos => {}
        }
        Ok(())
    }

    fn is_paused(&self) -> bool {
        self.paused
    }

    fn done(&self) -> bool {
        self.pos >= self.data.len()
    }
}

/// **Line-conversion reader** — converts LF → CRLF for ASCII-mode FTP.
///
/// Uses a [`BufQ`] for intermediate buffering so that converted output can
/// exceed the input length without re-allocation per read.
#[derive(Debug)]
pub struct LineCvtReader {
    inner: Box<dyn ClientReader>,
    buf: BufQ,
    eos: bool,
}

impl LineCvtReader {
    /// Wrap an existing reader, inserting CRLF conversion.
    pub fn new(inner: Box<dyn ClientReader>) -> Self {
        // 16 KB chunk, 1 max chunk — matches C cr_lc_ctx.
        Self {
            inner,
            buf: BufQ::with_opts(16384, 1, BufQOpts::SOFT_LIMIT),
            eos: false,
        }
    }
}

impl ClientReader for LineCvtReader {
    fn name(&self) -> &str {
        "linecvt"
    }

    fn phase(&self) -> ReaderPhase {
        ReaderPhase::Protocol
    }

    fn read(&mut self, output: &mut [u8]) -> Result<(usize, bool), CurlError> {
        // Fill conversion buffer from inner reader if needed.
        if self.buf.is_empty() && !self.eos {
            let mut tmp = vec![0u8; 4096];
            let (n, eos) = self.inner.read(&mut tmp)?;
            if eos {
                self.eos = true;
            }
            // Convert LF → CRLF.
            for &b in &tmp[..n] {
                if b == b'\n' {
                    let _ = self.buf.write(b"\r\n");
                } else {
                    let _ = self.buf.write(&[b]);
                }
            }
        }

        // Read from conversion buffer.
        let n = self.buf.read(output)?;
        Ok((n, self.eos && self.buf.is_empty()))
    }

    fn needs_rewind(&self) -> bool {
        self.inner.needs_rewind()
    }

    fn control(&mut self, cmd: ReaderControl) -> Result<(), CurlError> {
        if cmd == ReaderControl::Rewind {
            self.buf.reset();
            self.eos = false;
        }
        self.inner.control(cmd)
    }
}

/// **Null reader** — produces immediate EOF. Used when no upload data is
/// needed (e.g. GET requests).
#[derive(Debug, Clone, Copy)]
pub struct NullReader;

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

    fn done(&self) -> bool {
        true
    }
}

/// **Static-buffer reader** — reads from an in-memory `Vec<u8>`.
#[derive(Debug)]
pub struct StaticBufReader {
    data: Vec<u8>,
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
            return Ok((0, true));
        }
        let n = cmp::min(buf.len(), remaining.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        Ok((n, self.pos >= self.data.len()))
    }

    fn needs_rewind(&self) -> bool {
        self.pos > 0
    }

    fn total_length(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }

    fn control(&mut self, cmd: ReaderControl) -> Result<(), CurlError> {
        if cmd == ReaderControl::Rewind {
            self.pos = 0;
        }
        Ok(())
    }

    fn done(&self) -> bool {
        self.pos >= self.data.len()
    }
}

// ---------------------------------------------------------------------------
// Top-level entry points
// ---------------------------------------------------------------------------

/// Write `data` through a [`WriterChain`].
///
/// Convenience function matching C `Curl_client_write()`.
pub fn client_write(
    chain: &mut WriterChain,
    data: &[u8],
    flags: ClientWriteFlags,
) -> Result<(), CurlError> {
    chain.write(data, flags)?;
    Ok(())
}

/// Read up to `buf.len()` bytes from a [`ReaderChain`].
///
/// Convenience function matching C `Curl_client_read()`.
pub fn client_read(chain: &mut ReaderChain, buf: &mut [u8]) -> Result<(usize, bool), CurlError> {
    chain.read(buf)
}

/// Clean up a writer and reader chain pair.
pub fn client_cleanup(writers: &mut WriterChain, readers: &mut ReaderChain) {
    writers.cleanup();
    readers.cleanup();
}

/// Reset a writer and reader chain pair for reuse.
pub fn client_reset(writers: &mut WriterChain, readers: &mut ReaderChain) {
    writers.reset();
    readers.reset();
}

/// Prepare chains for a new transfer.
pub fn client_start(writers: &mut WriterChain, readers: &mut ReaderChain) {
    writers.reset();
    readers.reset();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    // -- WriterPhase / ReaderPhase ------------------------------------------

    #[test]
    fn writer_phase_ordering() {
        assert!((WriterPhase::Raw as u8) < (WriterPhase::Client as u8));
        assert!((WriterPhase::Protocol as u8) < (WriterPhase::ContentDecode as u8));
    }

    #[test]
    fn reader_phase_ordering() {
        assert!((ReaderPhase::Net as u8) < (ReaderPhase::Client as u8));
    }

    #[test]
    fn writer_phase_display() {
        assert_eq!(WriterPhase::Raw.to_string(), "Raw");
        assert_eq!(WriterPhase::Client.to_string(), "Client");
    }

    #[test]
    fn reader_phase_display() {
        assert_eq!(ReaderPhase::Net.to_string(), "Net");
        assert_eq!(ReaderPhase::Client.to_string(), "Client");
    }

    // -- WriterChain --------------------------------------------------------

    #[test]
    fn writer_chain_empty() {
        let chain = WriterChain::new();
        assert_eq!(chain.count(), 0);
        assert!(!chain.is_paused());
    }

    #[test]
    fn writer_chain_add_and_count() {
        let mut chain = WriterChain::new();
        chain.add(Box::new(RawWriter::new()));
        chain.add(Box::new(OutWriter::new()));
        assert_eq!(chain.count(), 2);
    }

    #[test]
    fn writer_chain_write_through() {
        let mut chain = WriterChain::new();
        chain.add(Box::new(RawWriter::new()));
        let n = chain.write(b"hello", ClientWriteFlags::BODY).unwrap();
        assert_eq!(n, 5);
    }

    #[test]
    fn writer_chain_get_by_name() {
        let mut chain = WriterChain::new();
        chain.add(Box::new(RawWriter::new()));
        assert!(chain.get_by_name("raw").is_some());
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

    // -- Concrete writers ---------------------------------------------------

    #[test]
    fn raw_writer_counts_bytes() {
        let mut w = RawWriter::new();
        w.write(b"hello", ClientWriteFlags::BODY).unwrap();
        assert_eq!(w.bytes_written, 5);
    }

    #[test]
    fn download_writer_tracks_body() {
        let mut w = DownloadWriter::new();
        w.write(b"data", ClientWriteFlags::BODY).unwrap();
        assert_eq!(w.body_bytes, 4);
        assert!(w.body_started);
    }

    #[test]
    fn download_writer_max_filesize() {
        let mut w = DownloadWriter::new();
        w.set_max_filesize(5);
        w.write(b"abc", ClientWriteFlags::BODY).unwrap();
        let err = w.write(b"defgh", ClientWriteFlags::BODY);
        assert!(err.is_err());
    }

    #[test]
    fn pause_writer_buffers() {
        let mut w = PauseWriter::new();
        w.pause();
        w.write(b"hello", ClientWriteFlags::BODY).unwrap();
        assert_eq!(w.buffered(), b"hello");
        w.unpause();
        w.clear_buffer();
        assert!(w.buffered().is_empty());
    }

    #[test]
    fn out_writer_counts() {
        let mut w = OutWriter::new();
        w.write(b"xyz", ClientWriteFlags::BODY).unwrap();
        assert_eq!(w.bytes_out, 3);
    }

    // -- Concrete readers ---------------------------------------------------

    #[test]
    fn null_reader_immediate_eof() {
        let mut r = NullReader;
        let mut buf = [0u8; 32];
        let (n, eos) = r.read(&mut buf).unwrap();
        assert_eq!(n, 0);
        assert!(eos);
        assert!(r.done());
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
    fn fread_reader_rewind() {
        let mut r = FreadReader::new(b"test".to_vec());
        let mut buf = [0u8; 2];
        r.read(&mut buf).unwrap();
        assert!(r.needs_rewind());
        r.control(ReaderControl::Rewind).unwrap();
        assert!(!r.needs_rewind());
    }

    // -- Line conversion reader ---------------------------------------------

    #[test]
    fn linecvt_converts_lf() {
        let inner = Box::new(StaticBufReader::new(b"a\nb\n".to_vec()));
        let mut reader = LineCvtReader::new(inner);
        let mut buf = [0u8; 64];
        let (n, _) = reader.read(&mut buf).unwrap();
        let output = &buf[..n];
        assert!(output.windows(2).any(|w| w == b"\r\n"),
            "expected CRLF in output");
    }

    // -- Top-level functions ------------------------------------------------

    #[test]
    fn client_write_through_chain() {
        let mut wc = WriterChain::new();
        wc.add(Box::new(RawWriter::new()));
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
    fn client_start_reset_cleanup() {
        let mut wc = WriterChain::new();
        let mut rc = ReaderChain::new();
        wc.add(Box::new(RawWriter::new()));
        rc.set_null();
        client_start(&mut wc, &mut rc);
        client_reset(&mut wc, &mut rc);
        client_cleanup(&mut wc, &mut rc);
        assert_eq!(wc.count(), 0);
    }
}
