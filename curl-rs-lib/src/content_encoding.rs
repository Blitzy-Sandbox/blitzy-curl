//! Content encoding/decoding support for HTTP response bodies.
//!
//! This module provides streaming decompression for HTTP `Content-Encoding` and
//! `Transfer-Encoding` values. It is the Rust equivalent of `lib/content_encoding.c`
//! from curl 8.19.0-DEV, replacing C zlib, brotli, and zstd integrations with
//! their pure-Rust counterparts (`flate2`, `brotli`, `zstd`).
//!
//! # Supported Encodings
//!
//! | Encoding  | Crate   | Feature Flag | Always Available |
//! |-----------|---------|-------------|------------------|
//! | gzip      | flate2  | —           | Yes              |
//! | x-gzip    | flate2  | —           | Yes (alias)      |
//! | deflate   | flate2  | —           | Yes              |
//! | br        | brotli  | `brotli`    | No               |
//! | zstd      | zstd    | `zstd`      | No               |
//! | identity  | —       | —           | Yes              |
//!
//! # Architecture
//!
//! All decoders implement the [`ContentDecoder`] trait, which provides an
//! incremental streaming interface:
//!
//! - [`ContentDecoder::decode`] — feed a chunk of compressed data, receive
//!   decompressed output.
//! - [`ContentDecoder::finish`] — signal end-of-stream and flush remaining
//!   buffered output.
//!
//! Multiple decoders can be stacked via [`DecoderChain`] to handle responses
//! with multiple `Content-Encoding` layers (e.g., `gzip, deflate`).

use std::io::{Cursor, Read};

// `io` module used by feature-gated decoder error types.
#[cfg(any(feature = "brotli", feature = "zstd"))]
use std::io;

use flate2::bufread::DeflateDecoder as Flate2RawDeflateDecoder;
use flate2::bufread::GzDecoder as Flate2GzDecoder;
use flate2::{Decompress, FlushDecompress, Status};

use crate::error::{CurlError, CurlResult};

// ---------------------------------------------------------------------------
// Constants — matching lib/content_encoding.c
// ---------------------------------------------------------------------------

/// Maximum number of chained compression steps allowed.
///
/// Corresponds to `MAX_ENCODE_STACK` in `lib/content_encoding.c`.
/// Prevents denial-of-service via deeply nested encodings.
pub const MAX_ENCODE_STACK: usize = 5;

/// Internal buffer size for decompressed data (16 KiB).
///
/// Corresponds to `DECOMPRESS_BUFFER_SIZE` in `lib/content_encoding.c`.
pub const DECOMPRESS_BUFFER_SIZE: usize = 16384;

/// Maximum decompressed output size for zstd bulk decompression (256 MiB).
/// Safety limit to prevent decompression bombs.
#[cfg(feature = "zstd")]
const MAX_DECOMPRESS_SIZE: usize = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// ContentDecoder trait
// ---------------------------------------------------------------------------

/// Trait for incremental content decoders.
///
/// Each decoder processes compressed input in streaming fashion, producing
/// decompressed output one chunk at a time. Implementations must handle partial
/// input — callers may invoke [`decode`](ContentDecoder::decode) multiple times
/// with successive fragments of the compressed stream.
pub trait ContentDecoder: Send {
    /// Decode a chunk of compressed input.
    ///
    /// Returns the decompressed bytes produced from `input`. The returned
    /// vector may be empty if the decoder needs more data before it can
    /// produce output.
    ///
    /// # Errors
    ///
    /// - [`CurlError::BadContentEncoding`] — the input is malformed or
    ///   contains an unsupported format.
    /// - [`CurlError::WriteError`] — a decompression stream error occurred.
    /// - [`CurlError::OutOfMemory`] — allocation failure during decompression.
    fn decode(&mut self, input: &[u8]) -> CurlResult<Vec<u8>>;

    /// Signal end-of-stream and flush any buffered output.
    ///
    /// After calling `finish`, the decoder should not be reused. Any remaining
    /// internal state is flushed and returned.
    ///
    /// # Errors
    ///
    /// Same error variants as [`decode`](ContentDecoder::decode).
    fn finish(&mut self) -> CurlResult<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// Gzip header parsing helpers (RFC 1952)
// ---------------------------------------------------------------------------

/// Gzip magic number bytes.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
/// Gzip flag: extra field present.
const GZIP_FEXTRA: u8 = 0x04;
/// Gzip flag: original filename present.
const GZIP_FNAME: u8 = 0x08;
/// Gzip flag: comment present.
const GZIP_FCOMMENT: u8 = 0x10;
/// Gzip flag: header CRC16 present.
const GZIP_FHCRC: u8 = 0x02;
/// Gzip trailer size: CRC32 (4 bytes) + ISIZE (4 bytes).
const GZIP_TRAILER_SIZE: usize = 8;
/// Minimum gzip header size (mandatory fields only).
const GZIP_MIN_HEADER: usize = 10;

/// Attempts to parse a gzip header from `data`.
///
/// Returns `Ok(Some(header_length))` if a complete header is found,
/// `Ok(None)` if more data is needed, or `Err` if the data is malformed.
fn parse_gzip_header(data: &[u8]) -> Result<Option<usize>, CurlError> {
    if data.len() < GZIP_MIN_HEADER {
        return Ok(None);
    }

    // Validate magic number.
    if data[0] != GZIP_MAGIC[0] || data[1] != GZIP_MAGIC[1] {
        return Err(CurlError::BadContentEncoding);
    }

    // Compression method must be deflate (8).
    if data[2] != 8 {
        return Err(CurlError::BadContentEncoding);
    }

    let flags = data[3];
    let mut pos = GZIP_MIN_HEADER;

    // FEXTRA: 2-byte length followed by extra data.
    if flags & GZIP_FEXTRA != 0 {
        if data.len() < pos + 2 {
            return Ok(None);
        }
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + xlen;
        if data.len() < pos {
            return Ok(None);
        }
    }

    // FNAME: null-terminated original filename.
    if flags & GZIP_FNAME != 0 {
        loop {
            if pos >= data.len() {
                return Ok(None);
            }
            if data[pos] == 0 {
                pos += 1;
                break;
            }
            pos += 1;
        }
    }

    // FCOMMENT: null-terminated comment.
    if flags & GZIP_FCOMMENT != 0 {
        loop {
            if pos >= data.len() {
                return Ok(None);
            }
            if data[pos] == 0 {
                pos += 1;
                break;
            }
            pos += 1;
        }
    }

    // FHCRC: 2-byte header CRC16.
    if flags & GZIP_FHCRC != 0 {
        pos += 2;
        if data.len() < pos {
            return Ok(None);
        }
    }

    Ok(Some(pos))
}

// ---------------------------------------------------------------------------
// GzipDecoder
// ---------------------------------------------------------------------------

/// Internal state machine for gzip decompression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GzipState {
    /// Accumulating bytes until the gzip header is fully parsed.
    ParsingHeader,
    /// Decompressing the raw deflate payload via `flate2::Decompress`.
    Inflating,
    /// Consuming the 8-byte gzip trailer (CRC32 + ISIZE).
    ReadingTrailer,
    /// Stream decompression is complete.
    Done,
}

/// Gzip content decoder using the `flate2` crate.
///
/// Handles both `Content-Encoding: gzip` and `Content-Encoding: x-gzip`.
/// Uses `flate2::Decompress` in raw-deflate mode with manual gzip framing,
/// providing true streaming decompression that matches the C `inflate_stream()`
/// loop with `inflateInit2(z, MAX_WBITS+32)`.
pub struct GzipDecoder {
    /// Buffer for partial header/trailer data.
    pending: Vec<u8>,
    /// Raw deflate decompressor (created after header parsing).
    decompressor: Decompress,
    /// Current state in the gzip state machine.
    state: GzipState,
    /// Number of trailer bytes still to consume after stream end.
    trailer_remaining: usize,
}

impl Default for GzipDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl GzipDecoder {
    /// Creates a new gzip decoder.
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            // Raw deflate mode — gzip header is parsed manually.
            decompressor: Decompress::new(false),
            state: GzipState::ParsingHeader,
            trailer_remaining: GZIP_TRAILER_SIZE,
        }
    }

    /// Decompress raw deflate data incrementally using `Decompress::decompress`.
    ///
    /// Returns `(decompressed_output, bytes_consumed_from_input)`.
    fn inflate_data(&mut self, input: &[u8]) -> CurlResult<(Vec<u8>, usize)> {
        let mut output = Vec::new();
        let mut buf = [0u8; DECOMPRESS_BUFFER_SIZE];
        let mut consumed_total = 0usize;
        let mut remaining = input;

        loop {
            if remaining.is_empty() && self.state == GzipState::Inflating {
                // No more input to process right now.
                break;
            }
            if remaining.is_empty() {
                break;
            }

            let before_in = self.decompressor.total_in();
            let before_out = self.decompressor.total_out();

            let status = self
                .decompressor
                .decompress(remaining, &mut buf, FlushDecompress::Sync)
                .map_err(|_| CurlError::BadContentEncoding)?;

            let consumed = (self.decompressor.total_in() - before_in) as usize;
            let produced = (self.decompressor.total_out() - before_out) as usize;

            if produced > 0 {
                output.extend_from_slice(&buf[..produced]);
            }

            consumed_total += consumed;
            remaining = &remaining[consumed..];

            match status {
                Status::Ok => {
                    // Continue decompressing — more data may be buffered internally.
                    if consumed == 0 && produced == 0 {
                        break; // No progress — avoid infinite loop.
                    }
                }
                Status::StreamEnd => {
                    self.state = GzipState::ReadingTrailer;
                    break;
                }
                Status::BufError => {
                    // Output buffer full or no input available.
                    if consumed == 0 && produced == 0 {
                        break;
                    }
                    // If we produced output, continue to drain any remaining.
                }
            }
        }

        Ok((output, consumed_total))
    }

    /// Consume trailer bytes from the given slice.
    ///
    /// Returns the number of bytes consumed as trailer.
    fn consume_trailer(&mut self, data: &[u8]) -> CurlResult<usize> {
        let to_consume = data.len().min(self.trailer_remaining);
        self.trailer_remaining -= to_consume;
        if self.trailer_remaining == 0 {
            self.state = GzipState::Done;
        }
        Ok(to_consume)
    }
}

impl ContentDecoder for GzipDecoder {
    fn decode(&mut self, input: &[u8]) -> CurlResult<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }

        match self.state {
            GzipState::Done => Err(CurlError::WriteError),

            GzipState::ParsingHeader => {
                self.pending.extend_from_slice(input);

                match parse_gzip_header(&self.pending)? {
                    Some(header_len) => {
                        // Header parsed — extract payload bytes after header.
                        let payload: Vec<u8> = self.pending[header_len..].to_vec();
                        self.pending.clear();
                        self.state = GzipState::Inflating;

                        if payload.is_empty() {
                            return Ok(Vec::new());
                        }

                        let (output, consumed) = self.inflate_data(&payload)?;

                        // If stream ended, handle trailer bytes from remaining input.
                        if self.state == GzipState::ReadingTrailer {
                            let after_inflate = &payload[consumed..];
                            self.consume_trailer(after_inflate)?;
                        }

                        Ok(output)
                    }
                    None => {
                        // Need more data for header.
                        Ok(Vec::new())
                    }
                }
            }

            GzipState::Inflating => {
                let (output, consumed) = self.inflate_data(input)?;

                // If stream ended, handle trailer from remaining input.
                if self.state == GzipState::ReadingTrailer {
                    let after_inflate = &input[consumed..];
                    self.consume_trailer(after_inflate)?;
                }

                Ok(output)
            }

            GzipState::ReadingTrailer => {
                self.consume_trailer(input)?;
                Ok(Vec::new())
            }
        }
    }

    fn finish(&mut self) -> CurlResult<Vec<u8>> {
        match self.state {
            GzipState::Done => Ok(Vec::new()),
            GzipState::ParsingHeader => {
                if self.pending.is_empty() {
                    // No data was ever received — not an error.
                    Ok(Vec::new())
                } else {
                    // Incomplete gzip header.
                    Err(CurlError::BadContentEncoding)
                }
            }
            GzipState::Inflating => {
                // Flush any remaining data in the decompressor.
                let mut output = Vec::new();
                let mut buf = [0u8; DECOMPRESS_BUFFER_SIZE];
                loop {
                    let before_out = self.decompressor.total_out();
                    let status = self
                        .decompressor
                        .decompress(&[], &mut buf, FlushDecompress::Finish)
                        .map_err(|_| CurlError::BadContentEncoding)?;
                    let produced =
                        (self.decompressor.total_out() - before_out) as usize;
                    if produced > 0 {
                        output.extend_from_slice(&buf[..produced]);
                    }
                    match status {
                        Status::StreamEnd => {
                            self.state = GzipState::Done;
                            break;
                        }
                        Status::Ok | Status::BufError => {
                            if produced == 0 {
                                self.state = GzipState::Done;
                                break;
                            }
                        }
                    }
                }
                Ok(output)
            }
            GzipState::ReadingTrailer => {
                // Trailer was incomplete but we accept this on finish.
                self.state = GzipState::Done;
                Ok(Vec::new())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DeflateDecoder
// ---------------------------------------------------------------------------

/// Internal state for deflate decompression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeflateState {
    /// Initial state — will try zlib format first.
    Init,
    /// Actively inflating data.
    Inflating,
    /// Stream decompression is complete.
    Done,
}

/// Raw deflate / zlib content decoder using the `flate2` crate.
///
/// Handles `Content-Encoding: deflate`. Per the HTTP specification, "deflate"
/// uses zlib-wrapped data (RFC 1950), but many servers send raw deflate (RFC
/// 1951) without the zlib header. This decoder initially attempts zlib-wrapped
/// decompression and automatically falls back to raw deflate on error, matching
/// the C `inflate_stream()` fallback behavior on `Z_DATA_ERROR`.
pub struct DeflateDecoder {
    /// Zlib or raw deflate decompressor.
    decompressor: Decompress,
    /// Current decompression state.
    state: DeflateState,
    /// Whether we have fallen back to raw deflate mode.
    raw_mode: bool,
    /// Saved initial input bytes for fallback retry.
    initial_input: Vec<u8>,
}

impl Default for DeflateDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DeflateDecoder {
    /// Creates a new deflate decoder.
    pub fn new() -> Self {
        Self {
            // Start with zlib format (expects 2-byte zlib header + checksum).
            decompressor: Decompress::new(true),
            state: DeflateState::Init,
            raw_mode: false,
            initial_input: Vec::new(),
        }
    }

    /// Run the decompression loop over the given input data.
    ///
    /// Returns `(decompressed_output, stream_ended)`.
    fn inflate_chunk(&mut self, input: &[u8]) -> CurlResult<(Vec<u8>, bool)> {
        let mut output = Vec::new();
        let mut buf = [0u8; DECOMPRESS_BUFFER_SIZE];
        let mut remaining = input;
        let mut stream_end = false;

        while !remaining.is_empty() {
            let before_in = self.decompressor.total_in();
            let before_out = self.decompressor.total_out();

            let result = self
                .decompressor
                .decompress(remaining, &mut buf, FlushDecompress::None);

            match result {
                Ok(status) => {
                    let consumed =
                        (self.decompressor.total_in() - before_in) as usize;
                    let produced =
                        (self.decompressor.total_out() - before_out) as usize;

                    if produced > 0 {
                        output.extend_from_slice(&buf[..produced]);
                    }

                    remaining = &remaining[consumed..];

                    match status {
                        Status::Ok => {
                            if consumed == 0 && produced == 0 {
                                break; // No progress — need more input.
                            }
                        }
                        Status::StreamEnd => {
                            stream_end = true;
                            break;
                        }
                        Status::BufError => {
                            break; // Output buffer full or no input.
                        }
                    }
                }
                Err(_) => {
                    return Err(CurlError::BadContentEncoding);
                }
            }
        }

        Ok((output, stream_end))
    }
}

impl ContentDecoder for DeflateDecoder {
    fn decode(&mut self, input: &[u8]) -> CurlResult<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }

        match self.state {
            DeflateState::Done => Err(CurlError::WriteError),

            DeflateState::Init => {
                // Save initial input for potential raw-deflate fallback.
                if !self.raw_mode {
                    self.initial_input.extend_from_slice(input);
                }
                self.state = DeflateState::Inflating;

                match self.inflate_chunk(input) {
                    Ok((output, stream_end)) => {
                        if stream_end {
                            self.state = DeflateState::Done;
                        }
                        // Successful — clear saved input, no fallback needed.
                        self.initial_input.clear();
                        Ok(output)
                    }
                    Err(CurlError::BadContentEncoding) if !self.raw_mode => {
                        // Fallback: some servers send raw deflate without the
                        // zlib header. Retry with raw deflate mode.
                        self.raw_mode = true;
                        self.decompressor = Decompress::new(false);
                        self.state = DeflateState::Inflating;
                        let saved = std::mem::take(&mut self.initial_input);
                        let (output, stream_end) = self.inflate_chunk(&saved)?;
                        if stream_end {
                            self.state = DeflateState::Done;
                        }
                        Ok(output)
                    }
                    Err(e) => Err(e),
                }
            }

            DeflateState::Inflating => {
                let (output, stream_end) = self.inflate_chunk(input)?;
                if stream_end {
                    self.state = DeflateState::Done;
                }
                Ok(output)
            }
        }
    }

    fn finish(&mut self) -> CurlResult<Vec<u8>> {
        if self.state == DeflateState::Done {
            return Ok(Vec::new());
        }

        // Use bufread::DeflateDecoder for final flush via Read interface.
        // This ensures we drain any trailing compressed data properly.
        let mut output = Vec::new();
        let mut buf = [0u8; DECOMPRESS_BUFFER_SIZE];
        loop {
            let before_out = self.decompressor.total_out();
            let result = self
                .decompressor
                .decompress(&[], &mut buf, FlushDecompress::Finish);
            match result {
                Ok(status) => {
                    let produced =
                        (self.decompressor.total_out() - before_out) as usize;
                    if produced > 0 {
                        output.extend_from_slice(&buf[..produced]);
                    }
                    match status {
                        Status::StreamEnd => {
                            self.state = DeflateState::Done;
                            break;
                        }
                        Status::Ok | Status::BufError => {
                            if produced == 0 {
                                self.state = DeflateState::Done;
                                break;
                            }
                        }
                    }
                }
                Err(_) => {
                    self.state = DeflateState::Done;
                    break;
                }
            }
        }
        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// BrotliDecoder (feature-gated)
// ---------------------------------------------------------------------------

/// Brotli content decoder using the `brotli` crate.
///
/// Handles `Content-Encoding: br`. Feature-gated behind the `brotli` Cargo
/// feature flag (enabled by default). Accumulates compressed data and attempts
/// decompression on each [`decode`](ContentDecoder::decode) call; if the stream
/// is incomplete, output is deferred until sufficient data arrives or
/// [`finish`](ContentDecoder::finish) is called.
#[cfg(feature = "brotli")]
pub struct BrotliDecoder {
    /// Accumulated compressed input.
    accumulated: Vec<u8>,
    /// Whether decompression has completed successfully.
    finished: bool,
}

#[cfg(feature = "brotli")]
impl Default for BrotliDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "brotli")]
impl BrotliDecoder {
    /// Creates a new brotli decoder.
    pub fn new() -> Self {
        Self {
            accumulated: Vec::new(),
            finished: false,
        }
    }

    /// Attempt to decompress all accumulated data.
    ///
    /// Uses `brotli::BrotliDecompress` for single-shot decompression, falling
    /// back to `brotli::Decompressor` streaming reader if needed.
    fn try_decompress(&self) -> Result<Vec<u8>, io::Error> {
        let mut input = Cursor::new(&self.accumulated[..]);
        let mut output: Vec<u8> = Vec::new();

        // Use BrotliDecompress for complete stream decompression.
        // This reads from input (impl Read via Cursor) and writes to
        // output (impl Write via Vec<u8>).
        match brotli::BrotliDecompress(&mut input, &mut output) {
            Ok(_) => Ok(output),
            Err(e) => {
                // Fall back to streaming Decompressor for partial reads.
                let mut input2 = Cursor::new(&self.accumulated[..]);
                let mut decompressor =
                    brotli::Decompressor::new(&mut input2, DECOMPRESS_BUFFER_SIZE);
                let mut output2 = Vec::new();
                let mut buf = [0u8; DECOMPRESS_BUFFER_SIZE];
                loop {
                    match decompressor.read(&mut buf) {
                        Ok(0) => return Ok(output2),
                        Ok(n) => output2.extend_from_slice(&buf[..n]),
                        Err(_) => return Err(e),
                    }
                }
            }
        }
    }
}

#[cfg(feature = "brotli")]
impl ContentDecoder for BrotliDecoder {
    fn decode(&mut self, input: &[u8]) -> CurlResult<Vec<u8>> {
        if self.finished {
            if !input.is_empty() {
                return Err(CurlError::WriteError);
            }
            return Ok(Vec::new());
        }

        self.accumulated.extend_from_slice(input);

        // Attempt full decompression of accumulated data.
        // If the brotli stream is complete within accumulated data, output
        // is returned immediately. Otherwise, we wait for more data.
        match self.try_decompress() {
            Ok(output) => {
                self.accumulated.clear();
                self.finished = true;
                Ok(output)
            }
            Err(_) => {
                // Incomplete stream — accumulate more data.
                Ok(Vec::new())
            }
        }
    }

    fn finish(&mut self) -> CurlResult<Vec<u8>> {
        if self.finished || self.accumulated.is_empty() {
            return Ok(Vec::new());
        }

        match self.try_decompress() {
            Ok(output) => {
                self.accumulated.clear();
                self.finished = true;
                Ok(output)
            }
            Err(_) => {
                self.finished = true;
                Err(CurlError::BadContentEncoding)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ZstdDecoder (feature-gated)
// ---------------------------------------------------------------------------

/// Zstandard content decoder using the `zstd` crate.
///
/// Handles `Content-Encoding: zstd`. Feature-gated behind the `zstd` Cargo
/// feature flag (enabled by default). Accumulates compressed data and attempts
/// decompression on each [`decode`](ContentDecoder::decode) call using the
/// `zstd::bulk::Decompressor` for fast single-frame decompression, with a
/// fallback to `zstd::stream::read::Decoder` for streaming multi-frame support.
#[cfg(feature = "zstd")]
pub struct ZstdDecoder {
    /// Accumulated compressed input.
    accumulated: Vec<u8>,
    /// Whether decompression has completed successfully.
    finished: bool,
}

#[cfg(feature = "zstd")]
impl Default for ZstdDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "zstd")]
impl ZstdDecoder {
    /// Creates a new zstd decoder.
    pub fn new() -> Self {
        Self {
            accumulated: Vec::new(),
            finished: false,
        }
    }

    /// Attempt to decompress all accumulated data.
    ///
    /// Tries `zstd::bulk::Decompressor` first (faster for complete single
    /// frames), then falls back to `zstd::stream::read::Decoder` for
    /// multi-frame or streaming decompression.
    fn try_decompress(&self) -> Result<Vec<u8>, io::Error> {
        // Fast path: bulk decompressor for complete frames.
        if let Ok(mut bulk) = zstd::bulk::Decompressor::new() {
            if let Ok(output) =
                bulk.decompress(&self.accumulated, MAX_DECOMPRESS_SIZE)
            {
                return Ok(output);
            }
        }

        // Fallback: streaming decoder for multi-frame or partial data.
        let cursor = Cursor::new(&self.accumulated[..]);
        let mut decoder = zstd::stream::read::Decoder::new(cursor)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut output = Vec::new();
        let mut buf = [0u8; DECOMPRESS_BUFFER_SIZE];
        loop {
            match decoder.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&buf[..n]),
                Err(e) => return Err(e),
            }
        }
        Ok(output)
    }
}

#[cfg(feature = "zstd")]
impl ContentDecoder for ZstdDecoder {
    fn decode(&mut self, input: &[u8]) -> CurlResult<Vec<u8>> {
        if self.finished {
            if !input.is_empty() {
                return Err(CurlError::WriteError);
            }
            return Ok(Vec::new());
        }

        self.accumulated.extend_from_slice(input);

        // Attempt full decompression of accumulated data.
        match self.try_decompress() {
            Ok(output) => {
                self.accumulated.clear();
                self.finished = true;
                Ok(output)
            }
            Err(_) => {
                // Incomplete frame — accumulate more data.
                Ok(Vec::new())
            }
        }
    }

    fn finish(&mut self) -> CurlResult<Vec<u8>> {
        if self.finished || self.accumulated.is_empty() {
            return Ok(Vec::new());
        }

        match self.try_decompress() {
            Ok(output) => {
                self.accumulated.clear();
                self.finished = true;
                Ok(output)
            }
            Err(_) => {
                self.finished = true;
                Err(CurlError::BadContentEncoding)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IdentityDecoder
// ---------------------------------------------------------------------------

/// Identity (pass-through) content decoder.
///
/// Returns input data unchanged. Used when `Content-Encoding: identity` or
/// `Content-Encoding: none` is specified, matching the C code's
/// `identity_encoding` handler.
pub struct IdentityDecoder {
    /// Private field to prevent external construction without `new()`.
    _private: (),
}

impl Default for IdentityDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityDecoder {
    /// Creates a new identity decoder.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl ContentDecoder for IdentityDecoder {
    #[inline]
    fn decode(&mut self, input: &[u8]) -> CurlResult<Vec<u8>> {
        Ok(input.to_vec())
    }

    #[inline]
    fn finish(&mut self) -> CurlResult<Vec<u8>> {
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// DecoderChain
// ---------------------------------------------------------------------------

/// A chain of content decoders applied in sequence.
///
/// When multiple `Content-Encoding` values are present (e.g., `gzip, deflate`),
/// decoders are stacked so that each decoder's output feeds the next. The
/// maximum chain depth is [`MAX_ENCODE_STACK`], matching the C code's
/// `MAX_ENCODE_STACK` limit.
///
/// # Example
///
/// ```ignore
/// use curl_rs_lib::content_encoding::{DecoderChain, create_decoder};
///
/// let mut chain = DecoderChain::new();
/// chain.push(create_decoder("gzip")?)?;
/// let output = chain.decode(compressed_data)?;
/// let final_output = chain.finish()?;
/// ```
pub struct DecoderChain {
    /// Ordered list of decoders. Index 0 receives raw input; the last
    /// decoder produces final output.
    decoders: Vec<Box<dyn ContentDecoder>>,
}

impl Default for DecoderChain {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderChain {
    /// Creates a new empty decoder chain.
    pub fn new() -> Self {
        Self {
            decoders: Vec::new(),
        }
    }

    /// Pushes a decoder onto the end of the chain.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadContentEncoding`] if the chain would exceed
    /// [`MAX_ENCODE_STACK`] decoders, preventing denial-of-service via deeply
    /// nested encodings.
    pub fn push(
        &mut self,
        decoder: Box<dyn ContentDecoder>,
    ) -> CurlResult<()> {
        if self.decoders.len() >= MAX_ENCODE_STACK {
            return Err(CurlError::BadContentEncoding);
        }
        self.decoders.push(decoder);
        Ok(())
    }

    /// Decode input data through the entire decoder chain.
    ///
    /// Data flows from the first decoder to the last; each decoder's output
    /// becomes the next decoder's input.
    pub fn decode(&mut self, input: &[u8]) -> CurlResult<Vec<u8>> {
        let mut data = input.to_vec();
        for decoder in &mut self.decoders {
            data = decoder.decode(&data)?;
        }
        Ok(data)
    }

    /// Finish all decoders in the chain and flush remaining output.
    ///
    /// Each decoder is finished in order; the flushed output from decoder N
    /// is fed through decoders N+1..end before decoder N+1 is itself finished.
    pub fn finish(&mut self) -> CurlResult<Vec<u8>> {
        let mut carry = Vec::new();
        for decoder in &mut self.decoders {
            // Feed any output from the previous decoder's finish through this one.
            if !carry.is_empty() {
                let intermediate = decoder.decode(&carry)?;
                carry = intermediate;
            }
            // Finish this decoder and append its flushed output.
            let flushed = decoder.finish()?;
            carry.extend(flushed);
        }
        Ok(carry)
    }
}

// ---------------------------------------------------------------------------
// Factory functions
// ---------------------------------------------------------------------------

/// Creates a decoder for the given content-encoding name.
///
/// Recognized encoding names (case-insensitive):
/// - `"gzip"`, `"x-gzip"` → [`GzipDecoder`]
/// - `"deflate"` → [`DeflateDecoder`]
/// - `"br"` → [`BrotliDecoder`] (requires `brotli` feature)
/// - `"zstd"` → [`ZstdDecoder`] (requires `zstd` feature)
/// - `"identity"`, `"none"` → [`IdentityDecoder`]
///
/// # Errors
///
/// - [`CurlError::BadContentEncoding`] for unrecognized encoding names.
/// - [`CurlError::NotBuiltIn`] if the encoding is recognized but the
///   corresponding Cargo feature is disabled.
pub fn create_decoder(
    encoding: &str,
) -> CurlResult<Box<dyn ContentDecoder>> {
    let encoding = encoding.trim();

    match encoding.to_ascii_lowercase().as_str() {
        "gzip" | "x-gzip" => Ok(Box::new(GzipDecoder::new())),

        "deflate" => Ok(Box::new(DeflateDecoder::new())),

        "br" => {
            #[cfg(feature = "brotli")]
            {
                Ok(Box::new(BrotliDecoder::new()))
            }
            #[cfg(not(feature = "brotli"))]
            {
                Err(CurlError::NotBuiltIn)
            }
        }

        "zstd" => {
            #[cfg(feature = "zstd")]
            {
                Ok(Box::new(ZstdDecoder::new()))
            }
            #[cfg(not(feature = "zstd"))]
            {
                Err(CurlError::NotBuiltIn)
            }
        }

        "identity" | "none" => Ok(Box::new(IdentityDecoder::new())),

        _ => Err(CurlError::BadContentEncoding),
    }
}

/// Returns a comma-separated list of supported content encodings.
///
/// The returned string is suitable for use as the value of the
/// `Accept-Encoding` HTTP request header. The output matches the format
/// produced by curl 8.x's `Curl_get_content_encodings()`, listing all
/// non-identity encodings supported by the current build.
///
/// # Examples
///
/// With all features enabled: `"deflate, gzip, br, zstd"`
///
/// With only default (no brotli/zstd): `"deflate, gzip"`
pub fn supported_encodings() -> String {
    // Mutable when feature flags add additional encodings at runtime.
    #[allow(unused_mut)]
    let mut encodings: Vec<&str> = vec!["deflate", "gzip"];

    #[cfg(feature = "brotli")]
    encodings.push("br");

    #[cfg(feature = "zstd")]
    encodings.push("zstd");

    encodings.join(", ")
}

// ---------------------------------------------------------------------------
// Helper: complete decompression via bufread adapters
// ---------------------------------------------------------------------------

/// Decompress a complete gzip-compressed byte slice using `flate2::bufread::GzDecoder`.
///
/// This is a convenience function for single-shot decompression of complete
/// gzip streams. For streaming decompression, use [`GzipDecoder`] instead.
#[allow(dead_code)]
fn decompress_gzip_complete(data: &[u8]) -> CurlResult<Vec<u8>> {
    let cursor = Cursor::new(data);
    let mut decoder = Flate2GzDecoder::new(cursor);
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .map_err(|_| CurlError::BadContentEncoding)?;
    Ok(output)
}

/// Decompress a complete raw-deflate byte slice using
/// `flate2::bufread::DeflateDecoder`.
///
/// This is a convenience function for single-shot decompression of complete
/// deflate streams. For streaming decompression, use [`DeflateDecoder`] instead.
#[allow(dead_code)]
fn decompress_deflate_complete(data: &[u8]) -> CurlResult<Vec<u8>> {
    let cursor = Cursor::new(data);
    let mut decoder = Flate2RawDeflateDecoder::new(cursor);
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .map_err(|_| CurlError::BadContentEncoding)?;
    Ok(output)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper: gzip-compress a byte slice ---------------------------------

    fn gzip_compress(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    // -- Helper: deflate-compress a byte slice ------------------------------

    fn deflate_compress(data: &[u8]) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    // -- GzipDecoder --------------------------------------------------------

    #[test]
    fn gzip_decode_small_payload() {
        let original = b"Hello, gzip world!";
        let compressed = gzip_compress(original);

        let mut decoder = GzipDecoder::new();
        let mut output = decoder.decode(&compressed).unwrap();
        output.extend(decoder.finish().unwrap());
        assert_eq!(output, original);
    }

    #[test]
    fn gzip_decode_empty_payload() {
        let compressed = gzip_compress(b"");

        let mut decoder = GzipDecoder::new();
        let mut output = decoder.decode(&compressed).unwrap();
        output.extend(decoder.finish().unwrap());
        assert!(output.is_empty());
    }

    #[test]
    fn gzip_decode_chunked_input() {
        let original = b"The quick brown fox jumps over the lazy dog";
        let compressed = gzip_compress(original);

        let mut decoder = GzipDecoder::new();
        let mut output = Vec::new();
        // Feed in small chunks to exercise the streaming logic.
        for chunk in compressed.chunks(4) {
            output.extend(decoder.decode(chunk).unwrap());
        }
        output.extend(decoder.finish().unwrap());
        assert_eq!(output, original);
    }

    #[test]
    fn gzip_decode_invalid_data() {
        let mut decoder = GzipDecoder::new();
        // Provide >= 10 bytes so the header parser can inspect the magic
        // number (first two bytes). 0x00 0x01 is not the gzip magic 0x1f 0x8b,
        // so `parse_gzip_header` should return `BadContentEncoding`.
        let result = decoder.decode(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a");
        assert!(result.is_err());
    }

    // -- DeflateDecoder -----------------------------------------------------

    #[test]
    fn deflate_decode_small_payload() {
        let original = b"Hello, deflate world!";
        let compressed = deflate_compress(original);

        let mut decoder = DeflateDecoder::new();
        let mut output = decoder.decode(&compressed).unwrap();
        output.extend(decoder.finish().unwrap());
        assert_eq!(output, original);
    }

    #[test]
    fn deflate_decode_empty_payload() {
        let compressed = deflate_compress(b"");

        let mut decoder = DeflateDecoder::new();
        let mut output = decoder.decode(&compressed).unwrap();
        output.extend(decoder.finish().unwrap());
        assert!(output.is_empty());
    }

    // -- IdentityDecoder ----------------------------------------------------

    #[test]
    fn identity_decode_passthrough() {
        let data = b"pass through unchanged";
        let mut decoder = IdentityDecoder::new();
        let output = decoder.decode(data).unwrap();
        assert_eq!(output, data);
    }

    #[test]
    fn identity_finish_empty() {
        let mut decoder = IdentityDecoder::new();
        let trailing = decoder.finish().unwrap();
        assert!(trailing.is_empty());
    }

    // -- DecoderChain -------------------------------------------------------

    #[test]
    fn decoder_chain_single_gzip() {
        let original = b"chain test data";
        let compressed = gzip_compress(original);

        let mut chain = DecoderChain::new();
        chain.push(Box::new(GzipDecoder::new())).unwrap();

        let mut output = chain.decode(&compressed).unwrap();
        output.extend(chain.finish().unwrap());
        assert_eq!(output, original);
    }

    #[test]
    fn decoder_chain_max_stack_exceeded() {
        let mut chain = DecoderChain::new();
        for _ in 0..MAX_ENCODE_STACK {
            chain
                .push(Box::new(IdentityDecoder::new()))
                .unwrap();
        }
        // Adding one more should fail.
        let result = chain.push(Box::new(IdentityDecoder::new()));
        assert!(result.is_err());
    }

    #[test]
    fn decoder_chain_empty_decode() {
        let mut chain = DecoderChain::new();
        let output = chain.decode(b"no decoders").unwrap();
        assert_eq!(output, b"no decoders");
    }

    // -- create_decoder -----------------------------------------------------

    #[test]
    fn create_decoder_gzip() {
        let decoder = create_decoder("gzip");
        assert!(decoder.is_ok());
    }

    #[test]
    fn create_decoder_deflate() {
        let decoder = create_decoder("deflate");
        assert!(decoder.is_ok());
    }

    #[test]
    fn create_decoder_identity() {
        let decoder = create_decoder("identity");
        assert!(decoder.is_ok());
    }

    #[test]
    fn create_decoder_none() {
        let decoder = create_decoder("none");
        assert!(decoder.is_ok());
    }

    #[test]
    fn create_decoder_x_gzip() {
        let decoder = create_decoder("x-gzip");
        assert!(decoder.is_ok());
    }

    #[test]
    fn create_decoder_unknown() {
        let decoder = create_decoder("unknown-encoding");
        assert!(decoder.is_err());
    }

    // -- supported_encodings ------------------------------------------------

    #[test]
    fn supported_encodings_contains_gzip() {
        let s = supported_encodings();
        assert!(s.contains("gzip"), "missing gzip in: {s}");
    }

    #[test]
    fn supported_encodings_contains_deflate() {
        let s = supported_encodings();
        assert!(s.contains("deflate"), "missing deflate in: {s}");
    }

    // -- decompress_gzip_complete helper ------------------------------------

    #[test]
    fn decompress_gzip_complete_works() {
        let original = b"complete decompress";
        let compressed = gzip_compress(original);
        let output = decompress_gzip_complete(&compressed).unwrap();
        assert_eq!(output, original);
    }

    // -- Constants ----------------------------------------------------------

    #[test]
    fn max_encode_stack_value() {
        assert_eq!(MAX_ENCODE_STACK, 5);
    }

    #[test]
    fn decompress_buffer_size_value() {
        assert_eq!(DECOMPRESS_BUFFER_SIZE, 16384);
    }
}
