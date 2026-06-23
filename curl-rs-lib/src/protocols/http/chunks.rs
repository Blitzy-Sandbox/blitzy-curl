//! HTTP/1.1 chunked Transfer-Encoding codec — a byte-exact decoder and encoder.
//!
//! This module is the memory-safe Rust reimplementation of curl's
//! `lib/http_chunks.c`. That C translation unit is the behavioral and wire-format
//! oracle: the chunk-size hex line, the optional chunk extensions, the `CRLF`
//! separators, the trailer headers, and the terminating `0\r\n\r\n` last chunk
//! are all reproduced **byte-for-byte** (AAP §0.6 G6, §0.8.2) so that curl 8.x
//! regression-suite traffic is decoded and generated identically.
//!
//! Two complementary halves live here, each a faithful port:
//!
//! * The **decoder** ([`Chunker`]) is the port of `Curl_chunker` /
//!   `httpchunk_readwrite`. It is a resumable state machine that consumes
//!   network-sized fragments of a chunked response body and emits the decoded
//!   body bytes (and any trailer headers) to a caller-supplied sink. Because curl
//!   receives data in arbitrarily sized pieces, the machine preserves all state
//!   across calls — feeding the same byte stream one byte at a time produces the
//!   identical output to feeding it in one shot.
//! * The **encoder** ([`ChunkedEncoder`]) is the port of the `chunked_reader` /
//!   `cr_chunked_*` reader. It frames an upload body into
//!   `<hex-size>\r\n<data>\r\n` chunks followed by the terminating chunk and
//!   optional trailer headers, using lowercase hexadecimal sizes exactly as
//!   curl's `"%zx"` formatting does.
//!
//! # Where this fits
//!
//! The decoder is one stage of the client-writer chain owned by
//! [`crate::transfer`]: response bytes flow `protocol → chunked-decode →
//! content-decode → header/body split → write callbacks`. To stay decoupled from
//! the (separately authored) engine handle, this module is a **pure codec**: it
//! never touches a socket and never logs. Decoded output is routed through a
//! caller-supplied closure that receives the bytes plus the
//! [`ClientWriteType`] routing flags (`BODY` for chunk data,
//! `HEADER | TRAILER` for trailer lines), exactly mirroring the
//! `CLIENTWRITE_BODY` and `CLIENTWRITE_HEADER | CLIENTWRITE_TRAILER` deliveries
//! the C code performs through `Curl_client_write`. The transfer chain and
//! `h1.rs` decide *when* the codec is applied; this module only decides *how*.
//!
//! `h1.rs` runs HTTP/1.1 over the `hyper` crate, which performs standard chunked
//! framing on the common path. This codec is nonetheless required for: the
//! transfer writer/reader chain integration with curl's exact `CHUNKE_*` →
//! `CURLcode` error parity, trailer capture delivered as header+trailer to the
//! client, the `--raw` / transfer-decoding-off path (`http_te_skip`), and
//! request-body chunk generation honoring curl's `CURL_CHUNKED_MINLEN` /
//! `CURL_CHUNKED_MAXLEN` sizing.
//!
//! # Memory safety
//!
//! Pure safe Rust: zero `unsafe`, no raw pointers, no manual buffer arithmetic
//! beyond bounds-checked slice indexing. The `protocols` subtree root
//! (`protocols/mod.rs`) carries `#![forbid(unsafe_code)]`, which propagates into
//! this module, so it is intentionally **not** re-declared here.

use crate::error::{CurlError, Result};
use crate::transfer::ClientWriteType;
use crate::util::bufq::{BufQ, BUFQ_OPT_SOFT_LIMIT};
use crate::util::dynbuf::{DynBuf, DYN_H1_TRAILER};
use crate::util::strparse::{curlx_hexval, Str};

// ===========================================================================
// Constants — exact mirrors of the `#define`s in `lib/http_chunks.{c,h}`.
// ===========================================================================

/// The longest hexadecimal chunk-size we accept, in digits.
///
/// C: `#define CHUNK_MAXNUM_LEN (SIZEOF_CURL_OFF_T * 2)` in `http_chunks.h`.
/// With a 64-bit `curl_off_t` this is `8 * 2 = 16` digits — enough to express
/// any `curl_off_t` value. A hexadecimal chunk-size longer than this is rejected
/// with [`ChunkCode::TooLongHex`].
pub const CHUNK_MAXNUM_LEN: usize = 16;

/// The smallest request-body chunk the encoder will try to generate.
///
/// C: `#define CURL_CHUNKED_MINLEN 1024`. When the downstream upload buffer is
/// smaller than this, the encoder reads into a scratch buffer of this size so it
/// still produces a decently sized chunk rather than many tiny ones.
pub const CURL_CHUNKED_MINLEN: usize = 1024;

/// The largest request-body chunk the encoder will generate.
///
/// C: `#define CURL_CHUNKED_MAXLEN (64 * 1024)`. Also the chunk size of the
/// encoder's internal soft-limited [`BufQ`].
pub const CURL_CHUNKED_MAXLEN: usize = 64 * 1024;

/// Upper bound applied when parsing a chunk-size, equal to C's `CURL_OFF_T_MAX`.
///
/// curl bounds `curlx_str_hex` with `CURL_OFF_T_MAX` (the maximum signed 64-bit
/// `curl_off_t`); a chunk-size that overflows this is rejected as an illegal hex
/// sequence, matching the C behavior for an over-long numeric value.
const CHUNK_SIZE_MAX: u64 = i64::MAX as u64;

/// Per-chunk framing overhead the encoder deducts from a large read so the
/// framed chunk still fits the caller's buffer: up to 8 hex digits plus two
/// `CRLF` pairs. C: `blen -= (8 + 2 + 2)` in `add_chunk`.
const CHUNK_FRAME_OVERHEAD: usize = 8 + 2 + 2;

// ===========================================================================
// Decoder state machine (C `ChunkyState` / `struct Curl_chunker`)
// ===========================================================================

/// The decoder's position in the chunked grammar — the Rust port of C's
/// `ChunkyState` enum (`http_chunks.h`).
///
/// The variants and their transitions mirror the C state machine exactly; see
/// [`Chunker::read_write`] for the per-state logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkState {
    /// Buffer hexadecimal digits of the chunk-size until a non-hex byte; then
    /// parse the size and move to [`ChunkState::Lf`]. C: `CHUNK_HEX`.
    Hex,
    /// Wait for the `LF` that ends the chunk-size line, ignoring (consuming) any
    /// chunk-extension bytes and a `CR` along the way. C: `CHUNK_LF`.
    Lf,
    /// Copy out `datasize` bytes of chunk data. C: `CHUNK_DATA`.
    Data,
    /// Consume the `CRLF` that follows a chunk's data before the next size.
    /// C: `CHUNK_POSTLF`.
    PostLf,
    /// Accumulate a trailer header line, or detect the terminating empty line.
    /// C: `CHUNK_TRAILER`.
    Trailer,
    /// A trailer line's `CR` was seen; the next byte must be its `LF`.
    /// C: `CHUNK_TRAILER_CR`.
    TrailerCr,
    /// After a trailer line's `CRLF`: either another trailer header follows or
    /// the final `CRLF` terminates the message. C: `CHUNK_TRAILER_POSTCR`.
    TrailerPostCr,
    /// The final `LF` is expected here; on success any trailing buffer bytes are
    /// recorded as leftover (pipelined) data. C: `CHUNK_STOP`.
    Stop,
    /// Every chunk has been successfully de-chunked. C: `CHUNK_DONE`.
    Done,
    /// A malformed or improperly terminated chunk was seen. C: `CHUNK_FAILED`.
    Failed,
}

/// The chunked-decoder error classification — the Rust port of C's `CHUNKcode`
/// enum (`http_chunks.h`), preserving the exact set and their human-readable
/// strings (see [`ChunkCode::strerror`]).
///
/// These classify *why* decoding failed; the public API surfaces failures as the
/// matching [`CurlError`] (and therefore the matching `CURLcode` integer at the
/// FFI boundary). The last classification is retained on the [`Chunker`] so the
/// transfer layer can build curl's exact `failf` message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkCode {
    /// No error. C: `CHUNKE_OK`.
    Ok,
    /// The chunk-size had more than [`CHUNK_MAXNUM_LEN`] hex digits.
    /// C: `CHUNKE_TOO_LONG_HEX`.
    TooLongHex,
    /// A chunk-size byte was not a hex digit where one was required, or the size
    /// failed to parse. C: `CHUNKE_ILLEGAL_HEX`.
    IllegalHex,
    /// A `CRLF` framing byte was missing or wrong. C: `CHUNKE_BAD_CHUNK`.
    BadChunk,
    /// A bad content-encoding was encountered. C: `CHUNKE_BAD_ENCODING`.
    BadEncoding,
    /// Allocation failed while buffering a trailer. C: `CHUNKE_OUT_OF_MEMORY`.
    OutOfMemory,
    /// A downstream writer (the client-write callback / next writer) returned an
    /// error; the originating [`CurlError`] is propagated as-is.
    /// C: `CHUNKE_PASSTHRU_ERROR`.
    PassthruError,
}

impl ChunkCode {
    /// The human-readable description of this code, byte-for-byte identical to
    /// curl's `Curl_chunked_strerror` (`lib/http_chunks.c`). Used by the transfer
    /// layer to compose the `"<reason> in chunked-encoding"` `failf` message.
    #[must_use]
    pub const fn strerror(self) -> &'static str {
        match self {
            // C's `Curl_chunked_strerror` returns "OK" from the `default:` arm,
            // which also covers `CHUNKE_OK`.
            ChunkCode::Ok => "OK",
            ChunkCode::TooLongHex => "Too long hexadecimal number",
            ChunkCode::IllegalHex => "Illegal or missing hexadecimal sequence",
            ChunkCode::BadChunk => "Malformed encoding found",
            ChunkCode::PassthruError => "Error writing data to client",
            ChunkCode::BadEncoding => "Bad content-encoding found",
            ChunkCode::OutOfMemory => "Out of memory",
        }
    }
}

/// The resumable chunked-decode state — the Rust port of C's `struct
/// Curl_chunker`.
///
/// One `Chunker` decodes a single chunked response body across as many
/// [`read_write`](Chunker::read_write) calls as the network delivers. All
/// progress lives in these fields, so the machine can be driven one byte at a
/// time with no change in output.
#[derive(Debug)]
pub struct Chunker {
    /// Bytes still expected in the current chunk's data. After the terminal
    /// chunk this is repurposed to hold the count of leftover (pipelined) bytes
    /// trailing the message — see [`ChunkState::Stop`]. C: `curl_off_t datasize`.
    datasize: u64,
    /// The current grammar position. C: `ChunkyState state`.
    state: ChunkState,
    /// The most recent failure classification. C: `CHUNKcode last_code`.
    last_code: ChunkCode,
    /// Accumulator for the trailer header line currently being read, capped at
    /// [`DYN_H1_TRAILER`]. C: `struct dynbuf trailer`.
    trailer: DynBuf,
    /// The chunk-size hex digits buffered so far (valid for `0..hexindex`).
    /// C: `char hexbuffer[CHUNK_MAXNUM_LEN + 1]` — the C buffer reserves one
    /// extra byte for a NUL terminator; this port parses a slice and needs no
    /// terminator, so it is exactly [`CHUNK_MAXNUM_LEN`] bytes wide.
    hexbuffer: [u8; CHUNK_MAXNUM_LEN],
    /// Number of valid bytes in [`Self::hexbuffer`]. C: `unsigned char hexindex`.
    hexindex: u8,
    /// When set, response body data is decoded for length accounting but never
    /// written to the client (e.g. a `HEAD` response). C: `BIT(ignore_body)`.
    ignore_body: bool,
}

impl Chunker {
    /// Create and initialize a chunked decoder, mirroring `Curl_httpchunk_init`.
    ///
    /// `ignore_body` requests that decoded body data be accounted for but never
    /// emitted to the client sink (trailer headers are still emitted). The
    /// machine starts in [`ChunkState::Hex`] with an empty trailer buffer.
    #[must_use]
    pub fn new(ignore_body: bool) -> Self {
        Chunker {
            datasize: 0,
            state: ChunkState::Hex,
            last_code: ChunkCode::Ok,
            trailer: DynBuf::new(DYN_H1_TRAILER),
            hexbuffer: [0u8; CHUNK_MAXNUM_LEN],
            hexindex: 0,
            ignore_body,
        }
    }

    /// Re-initialize an existing decoder for a fresh chunked body, mirroring
    /// `Curl_httpchunk_init` applied to an already-constructed `Curl_chunker`.
    ///
    /// Equivalent to assigning [`Chunker::new`]; the trailer buffer is reset.
    pub fn init(&mut self, ignore_body: bool) {
        self.hexindex = 0;
        self.state = ChunkState::Hex;
        self.last_code = ChunkCode::Ok;
        self.trailer.curlx_dyn_reset();
        self.ignore_body = ignore_body;
    }

    /// Reset the decoder between chunks within the same body, mirroring
    /// `Curl_httpchunk_reset`.
    ///
    /// Used by the [`ChunkState::PostLf`] transition once a chunk's trailing
    /// `CRLF` has been consumed: the machine returns to [`ChunkState::Hex`] to
    /// read the next chunk-size. `ignore_body` is preserved across the reset.
    pub fn reset(&mut self, ignore_body: bool) {
        self.hexindex = 0;
        self.state = ChunkState::Hex;
        self.last_code = ChunkCode::Ok;
        self.trailer.curlx_dyn_reset();
        self.ignore_body = ignore_body;
    }

    /// `true` once the terminal chunk has been fully decoded, mirroring
    /// `Curl_httpchunk_is_done` (`state == CHUNK_DONE`).
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.state == ChunkState::Done
    }

    /// The current decoder state. Primarily useful for the writer wrapper and
    /// tests to observe progress and detect completion.
    #[must_use]
    pub fn state(&self) -> ChunkState {
        self.state
    }

    /// The most recent failure classification (C `ch->last_code`), used to build
    /// the exact `failf` message after [`Chunker::read_write`] returns an error.
    #[must_use]
    pub fn last_code(&self) -> ChunkCode {
        self.last_code
    }

    /// In [`ChunkState::Done`] this is the number of leftover (pipelined) bytes
    /// that trailed the final chunk in the last buffer; otherwise it is the
    /// number of bytes still expected in the in-progress chunk. Mirrors the dual
    /// use of C's `ch->datasize`.
    #[must_use]
    pub fn datasize(&self) -> u64 {
        self.datasize
    }

    /// Decode a fragment of a chunked body, the Rust port of C's
    /// `httpchunk_readwrite` (and therefore of `Curl_httpchunk_read`, which is
    /// simply that function with a `NULL` next writer — here both the "next
    /// writer" and the direct client write collapse to the single `sink`).
    ///
    /// `input` is the next run of received bytes; the decoder consumes as much as
    /// it can and returns the number of bytes consumed. Any unconsumed tail is
    /// data that follows a completed message (pipelined bytes) — see
    /// [`Chunker::datasize`].
    ///
    /// `sink` receives decoded output: chunk data tagged [`ClientWriteType::BODY`]
    /// and trailer header lines tagged `HEADER | TRAILER`. It mirrors curl's
    /// `Curl_client_write`; returning an error from it fails decoding with
    /// [`ChunkCode::PassthruError`] and the sink's own [`CurlError`] is
    /// propagated unchanged.
    ///
    /// `te_skip` selects curl's transfer-decoding-off behavior
    /// (`data->set.http_te_skip`, i.e. `--raw`): the *original* bytes are passed
    /// straight through to the client as `BODY` (once, up front) and the state
    /// machine then runs purely for length accounting, emitting neither decoded
    /// body nor trailers. With `te_skip` false the decoder emits the decoded body
    /// (unless [`Chunker::new`] was given `ignore_body`) and the trailers.
    ///
    /// # Errors
    ///
    /// - [`CurlError::RecvError`] for a malformed chunk
    ///   ([`ChunkCode::TooLongHex`] / [`ChunkCode::IllegalHex`] /
    ///   [`ChunkCode::BadChunk`]).
    /// - [`CurlError::OutOfMemory`] if buffering a trailer line fails.
    /// - The sink's own error (classified [`ChunkCode::PassthruError`]).
    pub fn read_write(
        &mut self,
        te_skip: bool,
        input: &[u8],
        sink: &mut dyn FnMut(&[u8], ClientWriteType) -> Result<()>,
    ) -> Result<usize> {
        // Terminal states make no further progress (C checks these first, before
        // touching the buffer). `*pconsumed` starts at 0.
        if self.state == ChunkState::Done {
            return Ok(0);
        }
        if self.state == ChunkState::Failed {
            return Err(CurlError::RecvError);
        }

        // `--raw` / transfer-decoding-off: the still-chunked bytes are written to
        // the client verbatim, but we keep running the state machine to compute
        // the content length. (C: the up-front `Curl_client_write` of the whole
        // buffer, gated on `http_te_skip && !ignore_body`.)
        if te_skip && !self.ignore_body {
            if let Err(e) = sink(input, ClientWriteType::BODY) {
                self.state = ChunkState::Failed;
                self.last_code = ChunkCode::PassthruError;
                return Err(e);
            }
        }

        let total = input.len();
        // `pos` is the running consumed count (C's `*pconsumed`); the "current
        // byte" is `input[pos]` (C's `*buf`) and the remaining length is
        // `total - pos` (C's `blen`).
        let mut pos = 0usize;

        while pos < total {
            let b = input[pos];
            match self.state {
                ChunkState::Hex => {
                    if curlx_hexval(b).is_some() {
                        if self.hexindex as usize >= CHUNK_MAXNUM_LEN {
                            // Longer than we can represent — C: CHUNKE_TOO_LONG_HEX.
                            self.state = ChunkState::Failed;
                            self.last_code = ChunkCode::TooLongHex;
                            return Err(CurlError::RecvError);
                        }
                        self.hexbuffer[self.hexindex as usize] = b;
                        self.hexindex += 1;
                        pos += 1;
                    } else if self.hexindex == 0 {
                        // Junk where a hex digit was required — C: CHUNKE_ILLEGAL_HEX.
                        self.state = ChunkState::Failed;
                        self.last_code = ChunkCode::IllegalHex;
                        return Err(CurlError::RecvError);
                    } else {
                        // Parse the accumulated digits, bounded by CURL_OFF_T_MAX.
                        let mut cursor = Str::from_bytes(&self.hexbuffer[..self.hexindex as usize]);
                        let mut size: u64 = 0;
                        if cursor.curlx_str_hex(&mut size, CHUNK_SIZE_MAX).is_err() {
                            self.state = ChunkState::Failed;
                            self.last_code = ChunkCode::IllegalHex;
                            return Err(CurlError::RecvError);
                        }
                        self.datasize = size;
                        // Wait for the CRLF; the non-hex byte is *not* consumed
                        // here — it is processed by the `Lf` state.
                        self.state = ChunkState::Lf;
                    }
                }

                ChunkState::Lf => {
                    // Consume every byte up to and including the LF; this is also
                    // how chunk extensions and a preceding CR are skipped.
                    if b == 0x0a {
                        self.state = if self.datasize == 0 {
                            ChunkState::Trailer
                        } else {
                            ChunkState::Data
                        };
                    }
                    pos += 1;
                }

                ChunkState::Data => {
                    // Emit the smaller of "what we have" and "what remains in the
                    // chunk". `remaining` is a usize, so the clamped `piece` fits.
                    let remaining = total - pos;
                    let piece = if self.datasize < remaining as u64 {
                        // datasize < remaining (a usize) ⇒ fits losslessly.
                        self.datasize as usize
                    } else {
                        remaining
                    };

                    if !te_skip && !self.ignore_body {
                        if let Err(e) = sink(&input[pos..pos + piece], ClientWriteType::BODY) {
                            self.state = ChunkState::Failed;
                            self.last_code = ChunkCode::PassthruError;
                            return Err(e);
                        }
                    }

                    pos += piece;
                    self.datasize -= piece as u64;
                    if self.datasize == 0 {
                        // Expect the trailing CRLF after the chunk data.
                        self.state = ChunkState::PostLf;
                    }
                }

                ChunkState::PostLf => {
                    if b == 0x0a {
                        // End of this chunk's CRLF — go read the next chunk-size.
                        let ignore = self.ignore_body;
                        self.reset(ignore);
                    } else if b != 0x0d {
                        self.state = ChunkState::Failed;
                        self.last_code = ChunkCode::BadChunk;
                        return Err(CurlError::RecvError);
                    }
                    pos += 1;
                }

                ChunkState::Trailer => {
                    if b == 0x0d || b == 0x0a {
                        if self.trailer.curlx_dyn_len() > 0 {
                            // A complete trailer line was collected: terminate it
                            // with CRLF and deliver it as a header+trailer.
                            if self.trailer.curlx_dyn_addn(b"\x0d\x0a").is_err() {
                                self.state = ChunkState::Failed;
                                self.last_code = ChunkCode::OutOfMemory;
                                return Err(CurlError::OutOfMemory);
                            }
                            if !te_skip {
                                let kind = ClientWriteType::HEADER.union(ClientWriteType::TRAILER);
                                if let Err(e) = sink(self.trailer.curlx_dyn_ptr(), kind) {
                                    self.state = ChunkState::Failed;
                                    self.last_code = ChunkCode::PassthruError;
                                    return Err(e);
                                }
                            }
                            self.trailer.curlx_dyn_reset();
                            self.state = ChunkState::TrailerCr;
                            if b == 0x0a {
                                // Already sitting on the LF — let TrailerCr consume
                                // it; do not advance the pointer.
                                continue;
                            }
                            // Fall through to advance past the CR (b == 0x0d).
                        } else {
                            // Zero-length trailer ⇒ this is the final CRLF pair.
                            self.state = ChunkState::TrailerPostCr;
                            // Do not advance the pointer.
                            continue;
                        }
                    } else if self.trailer.curlx_dyn_addn(&[b]).is_err() {
                        self.state = ChunkState::Failed;
                        self.last_code = ChunkCode::OutOfMemory;
                        return Err(CurlError::OutOfMemory);
                    }
                    pos += 1;
                }

                ChunkState::TrailerCr => {
                    if b == 0x0a {
                        self.state = ChunkState::TrailerPostCr;
                        pos += 1;
                    } else {
                        self.state = ChunkState::Failed;
                        self.last_code = ChunkCode::BadChunk;
                        return Err(CurlError::RecvError);
                    }
                }

                ChunkState::TrailerPostCr => {
                    // A CR is expected here (then an LF). Anything else is another
                    // trailer header line.
                    if b != 0x0d && b != 0x0a {
                        self.state = ChunkState::Trailer;
                        // Do not advance: reprocess this byte as trailer content.
                        continue;
                    }
                    if b == 0x0d {
                        // Skip the CR; the LF is consumed by the Stop state.
                        pos += 1;
                    }
                    self.state = ChunkState::Stop;
                }

                ChunkState::Stop => {
                    if b == 0x0a {
                        // Consume the final LF, then record any trailing bytes as
                        // leftover (pipelined) data even though there are no more
                        // chunks to read.
                        pos += 1;
                        self.datasize = (total - pos) as u64;
                        self.state = ChunkState::Done;
                        return Ok(pos);
                    }
                    self.state = ChunkState::Failed;
                    self.last_code = ChunkCode::BadChunk;
                    return Err(CurlError::RecvError);
                }

                ChunkState::Done => return Ok(pos),
                ChunkState::Failed => return Err(CurlError::RecvError),
            }
        }

        Ok(pos)
    }
}

// ===========================================================================
// Writer-chain wrapper (C `chunked_writer` / `cw_chunked_write`)
// ===========================================================================

/// The result of delivering a body write through [`ChunkedUnencoder::write_body`],
/// capturing the post-decode bookkeeping that C's `cw_chunked_write` performs on
/// the easy handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkWrite {
    /// Bytes of `input` consumed by the decoder.
    pub consumed: usize,
    /// `true` once the terminal chunk has been decoded (C sets
    /// `data->req.download_done = TRUE`); the caller should treat the download as
    /// complete.
    pub download_done: bool,
    /// Bytes of `input` that trailed the completed message (pipelined data). C
    /// logs these as `"Leftovers after chunking: %zu bytes"`.
    pub leftover: usize,
}

/// The HTTP chunked Transfer-Encoding **decoder** as a client-writer-chain stage
/// — the Rust port of C's `struct chunked_writer` and its `cw_chunked_*`
/// callbacks (`Curl_httpchunk_unencoder`).
///
/// [`crate::transfer`] installs this stage when a response carries
/// `Transfer-Encoding: chunked`. The chain delivers only body writes here (header
/// and meta writes bypass the decoder), so [`Self::write_body`] is the analogue
/// of `cw_chunked_write`'s `CLIENTWRITE_BODY` path.
#[derive(Debug)]
pub struct ChunkedUnencoder {
    ch: Chunker,
}

impl Default for ChunkedUnencoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkedUnencoder {
    /// Create the decoder stage, mirroring `cw_chunked_init` (which initializes
    /// the chunker with `ignore_body = FALSE`; whether body bytes ultimately
    /// reach the client is decided by the downstream chain, not here).
    #[must_use]
    pub fn new() -> Self {
        ChunkedUnencoder {
            ch: Chunker::new(false),
        }
    }

    /// `true` once the chunked stream has been fully decoded
    /// (`ctx->ch.state == CHUNK_DONE`).
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.ch.is_done()
    }

    /// The classification of the most recent decode failure, for composing the
    /// `failf` message (see [`Self::failf_message`]).
    #[must_use]
    pub fn last_code(&self) -> ChunkCode {
        self.ch.last_code()
    }

    /// Borrow the underlying [`Chunker`] (e.g. to read [`Chunker::datasize`] for
    /// leftover accounting or [`Chunker::state`] in tests).
    #[must_use]
    pub fn chunker(&self) -> &Chunker {
        &self.ch
    }

    /// Decode a body write, the Rust port of the `CLIENTWRITE_BODY` path of
    /// `cw_chunked_write`.
    ///
    /// Call this only for body deliveries; the transfer chain passes
    /// non-body writes around the decoder unchanged (C's early
    /// `if(!(type & CLIENTWRITE_BODY))` return). `sink` receives decoded body and
    /// trailer output exactly as for [`Chunker::read_write`].
    ///
    /// * `te_skip` — curl's `data->set.http_te_skip` (`--raw`).
    /// * `no_body` — curl's `data->req.no_body` (a `HEAD`-style request with no
    ///   response body), which suppresses the truncated-stream error at EOS.
    /// * `is_eos` — the write carries [`ClientWriteType::EOS`] (the connection's
    ///   end of stream).
    ///
    /// On success returns a [`ChunkWrite`] describing completion and any leftover
    /// bytes. On failure returns the decoder's error; call [`Self::failf_message`]
    /// afterwards to obtain curl's exact log line.
    ///
    /// # Errors
    ///
    /// - The decode errors from [`Chunker::read_write`]
    ///   ([`CurlError::RecvError`] / [`CurlError::OutOfMemory`] / a sink error).
    /// - [`CurlError::PartialFile`] when the stream ends (`is_eos`) before the
    ///   terminal chunk and a body was expected (`!no_body`) — C's
    ///   `"transfer closed with outstanding read data remaining"`.
    pub fn write_body(
        &mut self,
        te_skip: bool,
        no_body: bool,
        is_eos: bool,
        input: &[u8],
        sink: &mut dyn FnMut(&[u8], ClientWriteType) -> Result<()>,
    ) -> Result<ChunkWrite> {
        let consumed = self.ch.read_write(te_skip, input, sink)?;

        if self.ch.state() == ChunkState::Done {
            // Chunks read successfully — the download is complete. The bytes that
            // trailed the final chunk (C's `blen -= consumed`) are leftover.
            let leftover = input.len() - consumed;
            return Ok(ChunkWrite {
                consumed,
                download_done: true,
                leftover,
            });
        }

        if is_eos && !no_body {
            // The peer closed mid-stream with body still outstanding.
            return Err(CurlError::PartialFile);
        }

        Ok(ChunkWrite {
            consumed,
            download_done: false,
            leftover: 0,
        })
    }

    /// The exact `failf` message text curl emits for the most recent decode
    /// failure, mirroring the two branches of `cw_chunked_write`:
    ///
    /// * a downstream-writer error ([`ChunkCode::PassthruError`]) →
    ///   `"Failed reading the chunked-encoded stream"`;
    /// * any other classification → `"<reason> in chunked-encoding"`, where
    ///   `<reason>` is [`ChunkCode::strerror`].
    ///
    /// Call after [`Self::write_body`] returns `Err`. The codec itself never
    /// logs; the transfer layer feeds this string to its error buffer.
    #[must_use]
    pub fn failf_message(&self) -> String {
        if self.ch.last_code() == ChunkCode::PassthruError {
            "Failed reading the chunked-encoded stream".to_string()
        } else {
            format!("{} in chunked-encoding", self.ch.last_code().strerror())
        }
    }
}

// ===========================================================================
// Request-body encoder (C `chunked_reader` / `cr_chunked_*`)
// ===========================================================================

/// `true` if `line` is a correctly formatted trailer header — it contains a
/// `:` immediately followed by a space, mirroring curl's `add_last_chunk`
/// validation (`strchr(tr->data, ':')` and `*(ptr + 1) == ' '`). Malformatted
/// trailers are skipped (curl logs `"Malformatted trailing header, skipping
/// trailer"`).
fn is_valid_trailer(line: &[u8]) -> bool {
    match line.iter().position(|&c| c == b':') {
        Some(idx) => line.get(idx + 1) == Some(&b' '),
        None => false,
    }
}

/// The HTTP chunked Transfer-Encoding **encoder** — the Rust port of C's
/// `struct chunked_reader` and its `cr_chunked_*` callbacks
/// (`Curl_httpchunk_encoder`).
///
/// It wraps an upload body into chunked Transfer-Encoding on demand: each block
/// read from the source becomes a `<hex-size>\r\n<data>\r\n` chunk buffered in an
/// internal soft-limited [`BufQ`], and once the source signals end-of-input the
/// terminating `0\r\n` + optional trailer headers + final `\r\n` are appended
/// exactly once.
///
/// The source is supplied per [`Self::read`] call as a closure returning
/// `(bytes_read, end_of_stream)`, mirroring curl's `Curl_creader_read` against
/// the next reader in the upload chain. Trailers (curl's `trailer_callback`
/// result) are wired in via [`Self::set_trailers`]; the abort case
/// (`CURL_TRAILERFUNC_ABORT` → `CURLE_ABORTED_BY_CALLBACK`) is handled by the
/// caller that invokes the user callback, which simply omits the trailers here.
#[derive(Debug)]
pub struct ChunkedEncoder {
    /// Buffered framed output, sized like C's
    /// `Curl_bufq_init2(&chunkbuf, CURL_CHUNKED_MAXLEN, 2, BUFQ_OPT_SOFT_LIMIT)`.
    chunkbuf: BufQ,
    /// Reusable read scratch (curl reuses the caller's buffer; we keep a small
    /// owned buffer to avoid per-read allocation while staying borrow-clean).
    scratch: Vec<u8>,
    /// Set once the source has reported end-of-input. C: `BIT(read_eos)`.
    read_eos: bool,
    /// Set once the terminating chunk has been drained to the caller.
    /// C: `BIT(eos)`.
    eos: bool,
    /// Trailer header lines to append after the terminal `0\r\n`, or `None` when
    /// no `trailer_callback` is configured (then the last chunk is the bare
    /// `0\r\n\r\n`). C: `data->set.trailer_callback` / its returned `curl_slist`.
    trailers: Option<Vec<Vec<u8>>>,
}

impl Default for ChunkedEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkedEncoder {
    /// Create a chunked request-body encoder, mirroring `cr_chunked_init`.
    #[must_use]
    pub fn new() -> Self {
        ChunkedEncoder {
            chunkbuf: BufQ::new_with_opts(CURL_CHUNKED_MAXLEN, 2, BUFQ_OPT_SOFT_LIMIT),
            scratch: Vec::new(),
            read_eos: false,
            eos: false,
            trailers: None,
        }
    }

    /// Provide the trailer header lines to emit in the terminal chunk (the result
    /// of curl's `CURLOPT_TRAILERFUNCTION`). Each entry is a raw header line such
    /// as `b"X-Checksum: abc123"`; lines without a `": "` are skipped, matching
    /// curl. Setting trailers switches the terminal chunk from the bare
    /// `0\r\n\r\n` to `0\r\n` + lines + `\r\n` (an empty list still yields the
    /// same `0\r\n\r\n` bytes).
    pub fn set_trailers(&mut self, trailers: Vec<Vec<u8>>) {
        self.trailers = Some(trailers);
    }

    /// `true` once the encoder has delivered the terminal chunk (no further
    /// output remains). C: `ctx->eos`.
    #[must_use]
    pub fn is_eos(&self) -> bool {
        self.eos
    }

    /// Pull the next block of encoded request body into `out`, returning the
    /// number of bytes written and whether the encoded stream has ended. The
    /// Rust port of `cr_chunked_read`.
    ///
    /// `source` is called to obtain raw body bytes when the internal buffer needs
    /// refilling; it fills the provided slice and returns
    /// `(bytes_read, end_of_stream)`, mirroring `Curl_creader_read` against the
    /// next reader. A `(0, false)` result is a pause (no bytes available yet);
    /// `(_, true)` reports that the source is exhausted, after which the terminal
    /// chunk is appended.
    ///
    /// # Errors
    ///
    /// Propagates a source error, or a buffer write error (the soft-limited
    /// [`BufQ`] does not fail on capacity).
    pub fn read<R>(&mut self, out: &mut [u8], source: &mut R) -> Result<(usize, bool)>
    where
        R: FnMut(&mut [u8]) -> Result<(usize, bool)>,
    {
        if self.eos {
            return Ok((0, true));
        }

        // Refill: while the source has more and the buffer has drained, frame the
        // next block (which also appends the terminal chunk once the source ends).
        if !self.read_eos && self.chunkbuf.Curl_bufq_is_empty() {
            self.add_chunk(out.len(), source)?;
        }

        if !self.chunkbuf.Curl_bufq_is_empty() {
            let n = self.chunkbuf.Curl_bufq_cread(out)?;
            if self.read_eos && self.chunkbuf.Curl_bufq_is_empty() {
                // Drained the last buffered bytes after the source ended.
                self.eos = true;
                return Ok((n, true));
            }
            return Ok((n, false));
        }

        // No buffered output and the source produced none (a pause): no bytes,
        // not yet end-of-stream.
        Ok((0, self.eos))
    }

    /// Read one block from `source` and frame it into [`Self::chunkbuf`], the
    /// Rust port of `add_chunk`. Appends the terminal chunk once the source has
    /// reported end-of-input.
    fn add_chunk<R>(&mut self, out_len: usize, source: &mut R) -> Result<()>
    where
        R: FnMut(&mut [u8]) -> Result<(usize, bool)>,
    {
        // Mirror C's read sizing: cap to MAXLEN; for a small downstream buffer
        // read up to MINLEN so we still make a decent chunk, otherwise read up to
        // (cap - framing overhead) so the framed chunk fits when drained back.
        let cap = out_len.min(CURL_CHUNKED_MAXLEN);
        let read_len = if cap < CURL_CHUNKED_MINLEN {
            CURL_CHUNKED_MINLEN
        } else {
            cap - CHUNK_FRAME_OVERHEAD
        };
        if self.scratch.len() < read_len {
            self.scratch.resize(read_len, 0);
        }

        let (nread, eos) = source(&mut self.scratch[..read_len])?;
        if eos {
            self.read_eos = true;
        }

        // Defend against a source that reports more than the slice can hold.
        let framed = nread.min(read_len);
        if framed > 0 {
            // Lowercase hex, no leading zeros — identical to curl's `"%zx\r\n"`.
            let hd = format!("{:x}\r\n", framed);
            self.chunkbuf.Curl_bufq_cwrite(hd.as_bytes())?;
            // Disjoint field borrows: `chunkbuf` (mut) and `scratch` (shared).
            self.chunkbuf.Curl_bufq_cwrite(&self.scratch[..framed])?;
            self.chunkbuf.Curl_bufq_cwrite(b"\r\n")?;
        }

        if self.read_eos {
            self.add_last_chunk()?;
        }
        Ok(())
    }

    /// Append the terminal chunk (and any trailers), the Rust port of
    /// `add_last_chunk`. The tail is assembled in a local buffer and written in
    /// one go; because the [`BufQ`] is a FIFO byte queue, this yields the exact
    /// same drained byte stream as curl's sequential `Curl_bufq_cwrite` calls.
    fn add_last_chunk(&mut self) -> Result<()> {
        let mut tail: Vec<u8> = Vec::new();
        match &self.trailers {
            // No trailer callback: the bare last chunk.
            None => tail.extend_from_slice(b"0\r\n\r\n"),
            // Trailer callback present: `0\r\n`, then each valid trailer line,
            // then the closing `\r\n`. An empty list collapses to `0\r\n\r\n`.
            Some(trailers) => {
                tail.extend_from_slice(b"0\r\n");
                for tr in trailers {
                    if is_valid_trailer(tr) {
                        tail.extend_from_slice(tr);
                        tail.extend_from_slice(b"\r\n");
                    }
                }
                tail.extend_from_slice(b"\r\n");
            }
        }
        self.chunkbuf.Curl_bufq_cwrite(&tail)?;
        Ok(())
    }
}

/// One-shot chunked encoding of an in-memory body — a convenience built on the
/// same framing rules as [`ChunkedEncoder`].
///
/// `data` is split into chunks no larger than [`CURL_CHUNKED_MAXLEN`], each
/// framed as `<hex-size>\r\n<data>\r\n` (lowercase hex, no leading zeros); an
/// empty `data` produces no data chunks. The terminal chunk follows: with
/// `trailers = None` it is the bare `0\r\n\r\n`; with `Some(lines)` it is `0\r\n`
/// + each correctly formatted (`": "`-bearing) trailer line + `\r\n`.
///
/// This is primarily for callers that already hold the whole body (and for
/// round-trip testing); streaming uploads use [`ChunkedEncoder::read`].
#[must_use]
pub fn encode_chunked(data: &[u8], trailers: Option<&[&[u8]]>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    // Data chunks (respect the MAXLEN sizing; empty input emits none).
    append_data_chunks(&mut out, data);
    // Terminal chunk (with optional trailers).
    append_terminal_chunk(&mut out, trailers);
    out
}

/// Frame a sequence of upload **blocks** as chunked transfer-encoding, emitting
/// **one chunk per block** (each block split only when it exceeds
/// [`CURL_CHUNKED_MAXLEN`]) followed by a single terminal chunk.
///
/// This preserves the read-callback boundaries on the wire: curl frames each
/// `CURLOPT_READFUNCTION` return (one `Curl_creader_read`) as its own chunk, so
/// a callback that returns `"one"`, `"two"`, `"three"`, `"four"` produces four
/// distinct chunks — not one coalesced chunk. The buffered chunked upload path
/// (a chunked body that must be resent across an auth challenge or a redirect,
/// or whose size is unknown) collects those per-read blocks and frames them here
/// so the emitted wire matches curl byte-for-byte (G6). An empty block list
/// emits only the terminal `0\r\n\r\n`; empty blocks are never framed as data
/// chunks (a zero-length chunk *is* the terminator).
#[must_use]
pub fn encode_chunked_blocks(blocks: &[Vec<u8>], trailers: Option<&[&[u8]]>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for block in blocks {
        append_data_chunks(&mut out, block);
    }
    append_terminal_chunk(&mut out, trailers);
    out
}

/// Append the data-chunk framing for `data` (`<hex-size>\r\n<data>\r\n` per
/// piece, split at [`CURL_CHUNKED_MAXLEN`]); empty input appends nothing, so a
/// zero-length read is never framed as a (body-terminating) zero-size chunk.
fn append_data_chunks(out: &mut Vec<u8>, data: &[u8]) {
    for piece in data.chunks(CURL_CHUNKED_MAXLEN) {
        out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        out.extend_from_slice(piece);
        out.extend_from_slice(b"\r\n");
    }
}

/// Append the terminal chunk: the bare `0\r\n\r\n` for `trailers = None`, or
/// `0\r\n` + each valid trailer line + the closing `\r\n` otherwise.
fn append_terminal_chunk(out: &mut Vec<u8>, trailers: Option<&[&[u8]]>) {
    match trailers {
        None => out.extend_from_slice(b"0\r\n\r\n"),
        Some(lines) => {
            out.extend_from_slice(b"0\r\n");
            for line in lines {
                if is_valid_trailer(line) {
                    out.extend_from_slice(line);
                    out.extend_from_slice(b"\r\n");
                }
            }
            out.extend_from_slice(b"\r\n");
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Captures decoder output, separating body bytes from trailer header lines
    /// and recording the routing flags of every sink call.
    #[derive(Default)]
    struct Collected {
        /// Concatenation of every `BODY` write.
        body: Vec<u8>,
        /// Each trailer (`HEADER | TRAILER`) write, kept whole.
        trailers: Vec<Vec<u8>>,
        /// `(len, flag-bits)` of every sink call, for routing assertions.
        writes: Vec<(usize, u16)>,
    }

    /// Build a sink closure that records into `c`. The returned closure borrows
    /// `c` for its lifetime, so scope it in a block before reading `c` back.
    fn record_into(c: &mut Collected) -> impl FnMut(&[u8], ClientWriteType) -> Result<()> + '_ {
        move |data: &[u8], kind: ClientWriteType| {
            c.writes.push((data.len(), kind.bits()));
            if kind.contains(ClientWriteType::BODY) {
                c.body.extend_from_slice(data);
            }
            if kind.contains(ClientWriteType::TRAILER) {
                c.trailers.push(data.to_vec());
            }
            Ok(())
        }
    }

    /// Decode `input` in a single call against a fresh-ish `ch`.
    fn drive_oneshot(ch: &mut Chunker, te_skip: bool, input: &[u8]) -> (Result<usize>, Collected) {
        let mut c = Collected::default();
        let res = {
            let mut sink = record_into(&mut c);
            ch.read_write(te_skip, input, &mut sink)
        };
        (res, c)
    }

    /// Decode `input` one byte per call, proving the state machine is resumable.
    /// Returns the aggregated output, the terminal state, and any error.
    fn drive_byte_by_byte(
        ignore_body: bool,
        te_skip: bool,
        input: &[u8],
    ) -> (Result<()>, Collected, ChunkState) {
        let mut ch = Chunker::new(ignore_body);
        let mut c = Collected::default();
        for i in 0..input.len() {
            if matches!(ch.state(), ChunkState::Done | ChunkState::Failed) {
                break;
            }
            let r = {
                let mut sink = record_into(&mut c);
                ch.read_write(te_skip, &input[i..i + 1], &mut sink)
            };
            if let Err(e) = r {
                return (Err(e), c, ch.state());
            }
        }
        (Ok(()), c, ch.state())
    }

    /// A pull source over an in-memory buffer, mirroring `Curl_creader_read`:
    /// fills the slice and reports `(bytes_read, end_of_stream)`.
    fn mem_source(data: &[u8]) -> impl FnMut(&mut [u8]) -> Result<(usize, bool)> + '_ {
        let mut pos = 0usize;
        move |buf: &mut [u8]| {
            let n = (data.len() - pos).min(buf.len());
            buf[..n].copy_from_slice(&data[pos..pos + n]);
            pos += n;
            Ok((n, pos >= data.len()))
        }
    }

    // ---- decoder: happy paths ------------------------------------------------

    #[test]
    fn single_chunk_decode() {
        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, b"5\r\nhello\r\n0\r\n\r\n");
        assert_eq!(res.unwrap(), 15);
        assert_eq!(c.body, b"hello");
        assert!(c.trailers.is_empty());
        assert!(ch.is_done());
        assert_eq!(ch.datasize(), 0, "no leftover bytes");
    }

    #[test]
    fn terminating_last_chunk_marks_done() {
        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, b"0\r\n\r\n");
        assert_eq!(res.unwrap(), 5);
        assert!(c.body.is_empty());
        assert!(ch.is_done());
        assert_eq!(ch.state(), ChunkState::Done);
    }

    #[test]
    fn multi_chunk_decode() {
        // Two data chunks then the terminator.
        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, b"3\r\nabc\r\n5\r\ndefgh\r\n0\r\n\r\n");
        assert!(res.is_ok());
        assert_eq!(c.body, b"abcdefgh");
        assert!(ch.is_done());
    }

    #[test]
    fn data_containing_crlf_is_not_misframed() {
        // The classic Wikipedia example: a chunk whose data embeds CRLF pairs.
        // Those bytes are pure data (`datasize` controls the copy), never framing.
        let stream = b"4\r\nWiki\r\n5\r\npedia\r\ne\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n";
        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, stream);
        assert!(res.is_ok());
        assert_eq!(c.body, b"Wikipedia in\r\n\r\nchunks.");
        assert!(ch.is_done());
    }

    #[test]
    fn resumable_byte_by_byte_matches_oneshot() {
        // The decoder must yield identical output whether fed whole or one byte
        // at a time (curl receives data in network-sized pieces).
        let stream =
            b"4\r\nWiki\r\n5\r\npedia\r\ne\r\n in\r\n\r\nchunks.\r\n0\r\nX-A: 1\r\nX-B: 2\r\n\r\n";

        let mut ch = Chunker::new(false);
        let (res1, c1) = drive_oneshot(&mut ch, false, stream);
        assert!(res1.is_ok());
        assert!(ch.is_done());

        let (res2, c2, state2) = drive_byte_by_byte(false, false, stream);
        assert!(res2.is_ok());
        assert_eq!(state2, ChunkState::Done);

        assert_eq!(c1.body, c2.body, "body identical across granularities");
        assert_eq!(
            c1.trailers, c2.trailers,
            "trailers identical across granularities"
        );
        assert_eq!(c1.body, b"Wikipedia in\r\n\r\nchunks.");
        assert_eq!(
            c2.trailers,
            vec![b"X-A: 1\r\n".to_vec(), b"X-B: 2\r\n".to_vec()]
        );
    }

    #[test]
    fn chunk_extension_after_size_is_ignored() {
        // A chunk-extension (`;name=value`) follows the size on the same line and
        // is consumed without affecting the decoded body.
        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, b"5;foo=bar\r\nhello\r\n0;final\r\n\r\n");
        assert!(res.is_ok());
        assert_eq!(c.body, b"hello");
        assert!(ch.is_done());
    }

    // ---- decoder: trailers ---------------------------------------------------

    #[test]
    fn single_trailer_written_as_header_and_trailer() {
        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(
            &mut ch,
            false,
            b"5\r\nhello\r\n0\r\nX-Trailer: value\r\n\r\n",
        );
        assert!(res.is_ok());
        assert_eq!(c.body, b"hello");
        assert_eq!(c.trailers, vec![b"X-Trailer: value\r\n".to_vec()]);

        // Routing: the trailer carries HEADER and TRAILER; body carries BODY.
        let header = ClientWriteType::HEADER.bits();
        let trailer = ClientWriteType::TRAILER.bits();
        let body = ClientWriteType::BODY.bits();
        assert!(
            c.writes
                .iter()
                .any(|&(_, b)| (b & trailer) != 0 && (b & header) != 0),
            "a trailer write must carry HEADER | TRAILER"
        );
        assert!(
            c.writes.iter().any(|&(_, b)| (b & body) != 0),
            "a body write must carry BODY"
        );
        // The body write must NOT be tagged as a trailer, and vice versa.
        assert!(
            c.writes
                .iter()
                .all(|&(_, b)| ((b & body) == 0) || ((b & trailer) == 0)),
            "body and trailer routing must be disjoint"
        );
    }

    #[test]
    fn multiple_trailers_each_delivered() {
        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, b"0\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n");
        assert!(res.is_ok());
        assert_eq!(
            c.trailers,
            vec![
                b"A: 1\r\n".to_vec(),
                b"B: 2\r\n".to_vec(),
                b"C: 3\r\n".to_vec(),
            ]
        );
        assert!(ch.is_done());
    }

    // ---- decoder: error parity (exact CURLcode integers) ---------------------

    #[test]
    fn illegal_hex_is_recv_error() {
        // First byte is not a hex digit (hexindex == 0) → CHUNKE_ILLEGAL_HEX.
        let mut ch = Chunker::new(false);
        let (res, _c) = drive_oneshot(&mut ch, false, b"X\r\nhello\r\n");
        let err = res.unwrap_err();
        assert_eq!(err, CurlError::RecvError);
        assert_eq!(err.code(), 56, "CURLE_RECV_ERROR");
        assert_eq!(ch.last_code(), ChunkCode::IllegalHex);
        assert_eq!(ch.state(), ChunkState::Failed);
    }

    #[test]
    fn hex_overflow_is_recv_error() {
        // 16 `f`s = 0xffff_ffff_ffff_ffff > CURL_OFF_T_MAX (i64::MAX): the size
        // parse overflows and is rejected as an illegal hex sequence.
        let mut ch = Chunker::new(false);
        let (res, _c) = drive_oneshot(&mut ch, false, b"ffffffffffffffff\r\n");
        let err = res.unwrap_err();
        assert_eq!(err, CurlError::RecvError);
        assert_eq!(ch.last_code(), ChunkCode::IllegalHex);
    }

    #[test]
    fn too_long_hex_is_recv_error() {
        // 17 hex digits exceeds CHUNK_MAXNUM_LEN (16) → CHUNKE_TOO_LONG_HEX.
        let mut ch = Chunker::new(false);
        let (res, _c) = drive_oneshot(&mut ch, false, b"00000000000000000\r\n");
        let err = res.unwrap_err();
        assert_eq!(err, CurlError::RecvError);
        assert_eq!(err.code(), 56);
        assert_eq!(ch.last_code(), ChunkCode::TooLongHex);
        assert_eq!(ch.state(), ChunkState::Failed);
    }

    #[test]
    fn bad_chunk_framing_is_recv_error() {
        // After a chunk's data the trailing CRLF is mandatory; a stray byte where
        // the CR/LF should be is CHUNKE_BAD_CHUNK.
        let mut ch = Chunker::new(false);
        let (res, _c) = drive_oneshot(&mut ch, false, b"5\r\nhelloXX");
        let err = res.unwrap_err();
        assert_eq!(err, CurlError::RecvError);
        assert_eq!(ch.last_code(), ChunkCode::BadChunk);
        assert_eq!(ch.state(), ChunkState::Failed);
    }

    #[test]
    fn overlong_trailer_is_out_of_memory() {
        // A trailer line longer than the trailer dynbuf cap (DYN_H1_TRAILER)
        // fails the append, which curl maps to CHUNKE_OUT_OF_MEMORY regardless of
        // the underlying allocator error.
        let mut input = Vec::new();
        input.extend_from_slice(b"0\r\n");
        input.extend_from_slice(&vec![b'a'; DYN_H1_TRAILER + 16]);

        let mut ch = Chunker::new(false);
        let (res, _c) = drive_oneshot(&mut ch, false, &input);
        let err = res.unwrap_err();
        assert_eq!(err, CurlError::OutOfMemory);
        assert_eq!(err.code(), 27, "CURLE_OUT_OF_MEMORY");
        assert_eq!(ch.last_code(), ChunkCode::OutOfMemory);
    }

    #[test]
    fn terminal_failed_state_keeps_returning_recv_error() {
        // Once failed, further input makes no progress (terminal state).
        let mut ch = Chunker::new(false);
        let (res, _c) = drive_oneshot(&mut ch, false, b"X");
        assert!(res.is_err());
        assert_eq!(ch.state(), ChunkState::Failed);
        let (res2, _c2) = drive_oneshot(&mut ch, false, b"anything");
        assert_eq!(res2.unwrap_err(), CurlError::RecvError);
    }

    #[test]
    fn passthru_error_propagates_underlying_error() {
        // A failing sink fails decoding with CHUNKE_PASSTHRU_ERROR and the sink's
        // own error is propagated unchanged.
        let mut ch = Chunker::new(false);
        let mut sink = |_: &[u8], _: ClientWriteType| -> Result<()> { Err(CurlError::WriteError) };
        let res = ch.read_write(false, b"5\r\nhello\r\n", &mut sink);
        assert_eq!(res.unwrap_err(), CurlError::WriteError);
        assert_eq!(ch.last_code(), ChunkCode::PassthruError);
        assert_eq!(ch.state(), ChunkState::Failed);
    }

    // ---- decoder: leftover / pipelined data ----------------------------------

    #[test]
    fn leftover_pipelined_data_recorded() {
        // Bytes after the terminal chunk are not consumed; their count is recorded
        // in `datasize` (curl's `ch->datasize = blen` in CHUNK_STOP).
        let mut ch = Chunker::new(false);
        let input = b"5\r\nhello\r\n0\r\n\r\nLEFTOVER";
        let (res, c) = drive_oneshot(&mut ch, false, input);
        let consumed = res.unwrap();
        assert_eq!(c.body, b"hello");
        assert!(ch.is_done());
        assert_eq!(consumed, input.len() - b"LEFTOVER".len());
        assert_eq!(ch.datasize(), b"LEFTOVER".len() as u64);
    }

    // ---- writer wrapper (ChunkedUnencoder / cw_chunked_write) -----------------

    #[test]
    fn writer_reports_done_and_leftover() {
        let mut dec = ChunkedUnencoder::new();
        let input = b"3\r\nabc\r\n0\r\n\r\nPIPE";
        let mut c = Collected::default();
        let cw = {
            let mut sink = record_into(&mut c);
            dec.write_body(false, false, false, input, &mut sink)
                .unwrap()
        };
        assert!(cw.download_done);
        assert_eq!(cw.leftover, b"PIPE".len());
        assert_eq!(cw.consumed, input.len() - b"PIPE".len());
        assert_eq!(c.body, b"abc");
        assert!(dec.is_done());
    }

    #[test]
    fn writer_truncated_stream_with_eos_is_partial_file() {
        // A chunk claims 0xa (10) bytes, but only 4 arrive and then the stream
        // ends — curl's "transfer closed with outstanding read data remaining".
        let mut dec = ChunkedUnencoder::new();
        let mut c = Collected::default();
        let res = {
            let mut sink = record_into(&mut c);
            dec.write_body(false, false, true, b"a\r\nhell", &mut sink)
        };
        let err = res.unwrap_err();
        assert_eq!(err, CurlError::PartialFile);
        assert_eq!(err.code(), 18, "CURLE_PARTIAL_FILE");
        assert_eq!(c.body, b"hell");
    }

    #[test]
    fn writer_truncated_stream_with_no_body_is_not_an_error() {
        // With `no_body` (e.g. a HEAD response), an early EOS is not a failure.
        let mut dec = ChunkedUnencoder::new();
        let mut c = Collected::default();
        let cw = {
            let mut sink = record_into(&mut c);
            dec.write_body(false, true, true, b"a\r\nhell", &mut sink)
                .unwrap()
        };
        assert!(!cw.download_done);
    }

    #[test]
    fn failf_message_passthru_vs_malformed() {
        // Passthru (downstream-writer) error → fixed message.
        let mut dec = ChunkedUnencoder::new();
        {
            let mut sink =
                |_: &[u8], _: ClientWriteType| -> Result<()> { Err(CurlError::WriteError) };
            let _ = dec.write_body(false, false, false, b"5\r\nhello\r\n", &mut sink);
        }
        assert_eq!(dec.last_code(), ChunkCode::PassthruError);
        assert_eq!(
            dec.failf_message(),
            "Failed reading the chunked-encoded stream"
        );

        // Any other classification → "<reason> in chunked-encoding".
        let mut dec2 = ChunkedUnencoder::new();
        {
            let mut sink = |_: &[u8], _: ClientWriteType| -> Result<()> { Ok(()) };
            let _ = dec2.write_body(false, false, false, b"Z\r\n", &mut sink);
        }
        assert_eq!(dec2.last_code(), ChunkCode::IllegalHex);
        assert_eq!(
            dec2.failf_message(),
            "Illegal or missing hexadecimal sequence in chunked-encoding"
        );
    }

    // ---- decoder: --raw / ignore-body modes ----------------------------------

    #[test]
    fn te_skip_passes_original_bytes_through() {
        // With transfer-decoding off, the *still-chunked* bytes are written
        // verbatim (once, up front) and the machine only accounts for length.
        let input = b"5\r\nhello\r\n0\r\n\r\n";
        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, true, input);
        assert!(res.is_ok());
        assert_eq!(c.body, input, "original bytes passed through unchanged");
        assert!(c.trailers.is_empty(), "no decoded trailers in te-skip mode");
        assert!(ch.is_done());
    }

    #[test]
    fn ignore_body_suppresses_body_but_keeps_trailers() {
        // `ignore_body` accounts for body length but never emits it; trailers are
        // still delivered (they are gated only on te-skip in curl).
        let input = b"5\r\nhello\r\n0\r\nT: v\r\n\r\n";
        let mut ch = Chunker::new(true);
        let (res, c) = drive_oneshot(&mut ch, false, input);
        assert!(res.is_ok());
        assert!(c.body.is_empty(), "body suppressed");
        assert_eq!(
            c.trailers,
            vec![b"T: v\r\n".to_vec()],
            "trailers still flow"
        );
        assert!(ch.is_done());
    }

    // ---- strerror parity -----------------------------------------------------

    #[test]
    fn strerror_strings_match_curl() {
        assert_eq!(ChunkCode::Ok.strerror(), "OK");
        assert_eq!(
            ChunkCode::TooLongHex.strerror(),
            "Too long hexadecimal number"
        );
        assert_eq!(
            ChunkCode::IllegalHex.strerror(),
            "Illegal or missing hexadecimal sequence"
        );
        assert_eq!(ChunkCode::BadChunk.strerror(), "Malformed encoding found");
        assert_eq!(
            ChunkCode::PassthruError.strerror(),
            "Error writing data to client"
        );
        assert_eq!(
            ChunkCode::BadEncoding.strerror(),
            "Bad content-encoding found"
        );
        assert_eq!(ChunkCode::OutOfMemory.strerror(), "Out of memory");
    }

    // ---- encoder -------------------------------------------------------------

    #[test]
    fn encoder_wire_format_and_lowercase_hex() {
        // 19 bytes → size line "13" (lowercase hex), exact framing.
        assert_eq!(
            encode_chunked(b"The quick brown fox", None),
            b"13\r\nThe quick brown fox\r\n0\r\n\r\n"
        );
        // 26 bytes → "1a" proves the hex letters are lowercase.
        assert_eq!(
            encode_chunked(b"abcdefghijklmnopqrstuvwxyz", None),
            b"1a\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\n\r\n"
        );
    }

    #[test]
    fn encoder_empty_body_is_bare_last_chunk() {
        assert_eq!(encode_chunked(b"", None), b"0\r\n\r\n");
    }

    #[test]
    fn encode_blocks_frames_each_read_as_its_own_chunk() {
        // The exact `tests/data/test565` upload: a read callback returning
        // "one", "two", "three", "and a final longer crap: four" must produce
        // FOUR distinct chunks (not one coalesced chunk), then the terminal.
        let blocks: Vec<Vec<u8>> = vec![
            b"one".to_vec(),
            b"two".to_vec(),
            b"three".to_vec(),
            b"and a final longer crap: four".to_vec(),
        ];
        assert_eq!(
            encode_chunked_blocks(&blocks, None),
            b"3\r\none\r\n3\r\ntwo\r\n5\r\nthree\r\n1d\r\nand a final longer crap: four\r\n0\r\n\r\n"
                .to_vec()
        );
    }

    #[test]
    fn encode_blocks_empty_list_is_bare_terminal() {
        // The auth-negotiation probe (suppressed body) frames to the lone
        // terminal chunk — byte-for-byte the `test565` probe body.
        assert_eq!(encode_chunked_blocks(&[], None), b"0\r\n\r\n".to_vec());
    }

    #[test]
    fn encode_blocks_skips_empty_blocks() {
        // A zero-length block is never framed as a (body-terminating) zero-size
        // data chunk; only the final terminal carries size 0.
        let blocks: Vec<Vec<u8>> = vec![b"ab".to_vec(), Vec::new(), b"cd".to_vec()];
        assert_eq!(
            encode_chunked_blocks(&blocks, None),
            b"2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n".to_vec()
        );
    }

    #[test]
    fn encode_blocks_single_block_matches_flat_encode() {
        // A one-element block list is identical to encoding the flat buffer.
        let one = vec![b"data".to_vec()];
        assert_eq!(
            encode_chunked_blocks(&one, None),
            encode_chunked(b"data", None)
        );
    }

    #[test]
    fn encoder_decoder_roundtrip() {
        let original = b"The quick brown fox jumps over the lazy dog.";
        let encoded = encode_chunked(original, None);
        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, &encoded);
        assert!(res.is_ok());
        assert_eq!(c.body, original, "encode→decode is byte-for-byte identity");
        assert!(ch.is_done());
    }

    #[test]
    fn encoder_roundtrip_large_body_multiple_chunks() {
        // Larger than CURL_CHUNKED_MAXLEN forces multiple data chunks.
        let original: Vec<u8> = (0..CURL_CHUNKED_MAXLEN + 100)
            .map(|i| (i % 251) as u8)
            .collect();
        let encoded = encode_chunked(&original, None);
        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, &encoded);
        assert!(res.is_ok());
        assert_eq!(c.body, original);
        assert!(ch.is_done());
    }

    #[test]
    fn encoder_trailers_valid_and_malformed() {
        // Lines without ":" + space are skipped (curl logs and continues).
        let encoded = encode_chunked(
            b"x",
            Some(&[
                b"A: 1".as_slice(),
                b"NoColonHere".as_slice(),
                b"B: 2".as_slice(),
                b"C:nospace".as_slice(),
            ]),
        );
        assert_eq!(encoded, b"1\r\nx\r\n0\r\nA: 1\r\nB: 2\r\n\r\n");

        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, &encoded);
        assert!(res.is_ok());
        assert_eq!(c.body, b"x");
        assert_eq!(c.trailers, vec![b"A: 1\r\n".to_vec(), b"B: 2\r\n".to_vec()]);
    }

    #[test]
    fn streaming_encoder_matches_decode() {
        // Drive the pull-based ChunkedEncoder into a small output buffer (forcing
        // multiple reads) and confirm the result decodes back to the source.
        let body = b"streamed body content spanning several reads";
        let mut enc = ChunkedEncoder::new();
        let mut src = mem_source(body);
        let mut encoded = Vec::new();
        let mut out = [0u8; 8];
        loop {
            let (n, eos) = enc.read(&mut out, &mut src).unwrap();
            encoded.extend_from_slice(&out[..n]);
            if eos {
                break;
            }
            assert!(n > 0, "non-eos read must make progress for this source");
        }
        assert!(enc.is_eos());

        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, &encoded);
        assert!(res.is_ok());
        assert_eq!(c.body, body);
        assert!(ch.is_done());
    }

    #[test]
    fn streaming_encoder_with_trailers() {
        let body = b"payload";
        let mut enc = ChunkedEncoder::new();
        enc.set_trailers(vec![b"X-Sum: abc".to_vec()]);
        let mut src = mem_source(body);
        let mut encoded = Vec::new();
        let mut out = [0u8; 16];
        loop {
            let (n, eos) = enc.read(&mut out, &mut src).unwrap();
            encoded.extend_from_slice(&out[..n]);
            if eos {
                break;
            }
            assert!(n > 0);
        }

        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, &encoded);
        assert!(res.is_ok());
        assert_eq!(c.body, body);
        assert_eq!(c.trailers, vec![b"X-Sum: abc\r\n".to_vec()]);
    }

    #[test]
    fn streaming_encoder_empty_body() {
        // A source that is immediately at end-of-stream yields just the last
        // chunk: the first read frames the terminator and reports eos.
        let mut enc = ChunkedEncoder::new();
        let mut src = mem_source(b"");
        let mut encoded = Vec::new();
        let mut out = [0u8; 32];
        let mut saw_eos = false;
        while !saw_eos {
            let (n, eos) = enc.read(&mut out, &mut src).unwrap();
            encoded.extend_from_slice(&out[..n]);
            saw_eos = eos;
        }
        assert_eq!(encoded, b"0\r\n\r\n");
    }

    // ---- trailer validation helper ------------------------------------------

    #[test]
    fn trailer_validation_rules() {
        assert!(is_valid_trailer(b"Name: value"));
        assert!(is_valid_trailer(b"X:  two-spaces-ok"));
        assert!(!is_valid_trailer(b"NoColon"));
        assert!(!is_valid_trailer(b"NoSpace:value"));
        assert!(!is_valid_trailer(b"TrailingColon:"));
        assert!(!is_valid_trailer(b""));
    }

    // ---- additional coverage: public API, error branches, edge cases --------

    #[test]
    fn init_reinitializes_a_used_chunker() {
        // Drive a decoder to failure, then `init` must restore a fresh machine.
        let mut ch = Chunker::new(false);
        {
            let mut sink = |_: &[u8], _: ClientWriteType| -> Result<()> { Ok(()) };
            let _ = ch.read_write(false, b"Z\r\n", &mut sink);
        }
        assert_eq!(ch.state(), ChunkState::Failed);

        ch.init(true);
        assert_eq!(ch.state(), ChunkState::Hex);
        assert_eq!(ch.last_code(), ChunkCode::Ok);
        assert!(!ch.is_done());

        // `init(true)` set ignore_body, so a fresh decode suppresses the body.
        let (res, c) = drive_oneshot(&mut ch, false, b"5\r\nhello\r\n0\r\n\r\n");
        assert!(res.is_ok());
        assert!(c.body.is_empty());
        assert!(ch.is_done());
    }

    #[test]
    fn read_write_after_done_makes_no_progress() {
        // The terminal Done state returns 0 consumed without touching the input.
        let mut ch = Chunker::new(false);
        let (res, _c) = drive_oneshot(&mut ch, false, b"0\r\n\r\n");
        assert!(res.is_ok());
        assert!(ch.is_done());

        let (res2, c2) = drive_oneshot(&mut ch, false, b"more bytes");
        assert_eq!(res2.unwrap(), 0);
        assert!(c2.body.is_empty());
        assert!(ch.is_done());
    }

    #[test]
    fn te_skip_sink_error_is_passthru() {
        // In te-skip mode the up-front verbatim write can fail; that is a
        // passthru error and the underlying error propagates.
        let mut ch = Chunker::new(false);
        let mut sink = |_: &[u8], _: ClientWriteType| -> Result<()> { Err(CurlError::WriteError) };
        let res = ch.read_write(true, b"5\r\nhello\r\n", &mut sink);
        assert_eq!(res.unwrap_err(), CurlError::WriteError);
        assert_eq!(ch.last_code(), ChunkCode::PassthruError);
        assert_eq!(ch.state(), ChunkState::Failed);
    }

    #[test]
    fn trailer_write_sink_error_is_passthru() {
        // A sink that rejects the trailer delivery fails decoding as a passthru
        // error (the underlying error is propagated unchanged).
        let mut ch = Chunker::new(false);
        let mut sink = |_: &[u8], kind: ClientWriteType| -> Result<()> {
            if kind.contains(ClientWriteType::TRAILER) {
                Err(CurlError::WriteError)
            } else {
                Ok(())
            }
        };
        let res = ch.read_write(false, b"0\r\nX: y\r\n\r\n", &mut sink);
        assert_eq!(res.unwrap_err(), CurlError::WriteError);
        assert_eq!(ch.last_code(), ChunkCode::PassthruError);
        assert_eq!(ch.state(), ChunkState::Failed);
    }

    #[test]
    fn trailer_line_terminated_by_bare_lf() {
        // A trailer line ended by a bare LF (no CR) is still captured and
        // delivered with the decoder-normalized CRLF terminator.
        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, b"0\r\nX: y\n\n");
        assert!(res.is_ok());
        assert_eq!(c.trailers, vec![b"X: y\r\n".to_vec()]);
        assert!(ch.is_done());
    }

    #[test]
    fn trailer_cr_without_lf_is_bad_chunk() {
        // After a trailer line's CR, a byte other than LF is malformed framing.
        let mut ch = Chunker::new(false);
        let mut sink = |_: &[u8], _: ClientWriteType| -> Result<()> { Ok(()) };
        let res = ch.read_write(false, b"0\r\nX: y\rZ", &mut sink);
        assert_eq!(res.unwrap_err(), CurlError::RecvError);
        assert_eq!(ch.last_code(), ChunkCode::BadChunk);
        assert_eq!(ch.state(), ChunkState::Failed);
    }

    #[test]
    fn stop_state_without_final_lf_is_bad_chunk() {
        // The terminating sequence must end in LF; a stray byte where the final
        // LF is expected is a bad chunk.
        let mut ch = Chunker::new(false);
        let mut sink = |_: &[u8], _: ClientWriteType| -> Result<()> { Ok(()) };
        let res = ch.read_write(false, b"0\r\n\rZ", &mut sink);
        assert_eq!(res.unwrap_err(), CurlError::RecvError);
        assert_eq!(ch.last_code(), ChunkCode::BadChunk);
        assert_eq!(ch.state(), ChunkState::Failed);
    }

    #[test]
    fn crlf_append_overflow_is_out_of_memory() {
        // A trailer line that fits within the dynbuf cap on its own but overflows
        // when the decoder appends its own CRLF terminator still maps to OOM.
        // `DYN_H1_TRAILER - 1` content bytes fit, but + CRLF exceeds the cap
        // regardless of the buffer's reserved-NUL accounting.
        let mut input = Vec::new();
        input.extend_from_slice(b"0\r\n");
        input.extend_from_slice(&vec![b'a'; DYN_H1_TRAILER - 1]);
        input.push(b'\r'); // line end → triggers the CRLF append

        let mut ch = Chunker::new(false);
        let (res, _c) = drive_oneshot(&mut ch, false, &input);
        let err = res.unwrap_err();
        assert_eq!(err, CurlError::OutOfMemory);
        assert_eq!(err.code(), 27);
        assert_eq!(ch.last_code(), ChunkCode::OutOfMemory);
    }

    #[test]
    fn public_defaults_and_accessors() {
        // The `Default` impls construct fresh codecs.
        let dec = ChunkedUnencoder::default();
        assert!(!dec.is_done());
        assert_eq!(dec.last_code(), ChunkCode::Ok);
        // The `chunker()` accessor exposes the underlying decoder.
        assert_eq!(dec.chunker().state(), ChunkState::Hex);
        assert_eq!(dec.chunker().datasize(), 0);

        let enc = ChunkedEncoder::default();
        assert!(!enc.is_eos());
    }

    #[test]
    fn streaming_encoder_read_after_eos_is_idempotent() {
        let mut enc = ChunkedEncoder::new();
        let mut src = mem_source(b"hi");
        let mut out = [0u8; 64];
        let mut saw_eos = false;
        while !saw_eos {
            let (_n, eos) = enc.read(&mut out, &mut src).unwrap();
            saw_eos = eos;
        }
        assert!(enc.is_eos());
        // A further read after eos yields nothing and stays at eos.
        let (n, eos) = enc.read(&mut out, &mut src).unwrap();
        assert_eq!(n, 0);
        assert!(eos);
    }

    #[test]
    fn streaming_encoder_handles_source_pause() {
        // A source that returns `(0, false)` is a pause: the read yields no bytes
        // and is not yet at end-of-stream.
        let payload: &[u8] = b"data";
        let mut paused_once = false;
        let mut pos = 0usize;
        let mut src = |buf: &mut [u8]| -> Result<(usize, bool)> {
            if !paused_once {
                paused_once = true;
                return Ok((0, false)); // pause
            }
            let n = (payload.len() - pos).min(buf.len());
            buf[..n].copy_from_slice(&payload[pos..pos + n]);
            pos += n;
            Ok((n, pos >= payload.len()))
        };

        let mut enc = ChunkedEncoder::new();
        let mut out = [0u8; 64];

        // First read: source pauses → no bytes, not eos.
        let (n0, eos0) = enc.read(&mut out, &mut src).unwrap();
        assert_eq!(n0, 0);
        assert!(!eos0);

        // Subsequent reads frame the body and terminator.
        let mut encoded = Vec::new();
        let mut saw_eos = false;
        while !saw_eos {
            let (n, eos) = enc.read(&mut out, &mut src).unwrap();
            encoded.extend_from_slice(&out[..n]);
            saw_eos = eos;
        }

        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, &encoded);
        assert!(res.is_ok());
        assert_eq!(c.body, payload);
    }

    #[test]
    fn streaming_encoder_large_output_buffer() {
        // An output buffer >= CURL_CHUNKED_MINLEN exercises the
        // `(cap - framing overhead)` read-sizing branch.
        let body: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let mut enc = ChunkedEncoder::new();
        let mut src = mem_source(&body);
        let mut out = vec![0u8; 8192];
        let mut encoded = Vec::new();
        let mut saw_eos = false;
        while !saw_eos {
            let (n, eos) = enc.read(&mut out, &mut src).unwrap();
            encoded.extend_from_slice(&out[..n]);
            saw_eos = eos;
        }

        let mut ch = Chunker::new(false);
        let (res, c) = drive_oneshot(&mut ch, false, &encoded);
        assert!(res.is_ok());
        assert_eq!(c.body, body);
    }

    #[test]
    fn byte_by_byte_surfaces_errors() {
        // The resumable driver must also surface a decode error mid-stream
        // (here an illegal hex digit on the very first byte).
        let (res, _c, state) = drive_byte_by_byte(false, false, b"Z\r\n");
        assert_eq!(res.unwrap_err(), CurlError::RecvError);
        assert_eq!(state, ChunkState::Failed);
    }
}
