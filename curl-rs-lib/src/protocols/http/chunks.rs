// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP/1.1 chunked Transfer-Encoding codec (← `lib/http_chunks.c` + `lib/http_chunks.h`).
//!
//! This module is a faithful, memory-safe Rust port of curl 8.19.0-DEV's chunked
//! transfer-encoding implementation. It provides both halves of the codec:
//!
//! * **Decoder / "unencoder"** — [`Chunker`] and the [`ChunkedWriter`] write-pipeline
//!   stage de-chunk a `Transfer-Encoding: chunked` *response* body, writing the
//!   reassembled body bytes (and broadcasting any trailer headers) to a downstream
//!   [`ChunkWrite`] sink. This ports `httpchunk_readwrite`, `Curl_httpchunk_read`,
//!   `Curl_httpchunk_is_done`, and the `Curl_cwtype Curl_httpchunk_unencoder` glue.
//! * **Encoder / "reader"** — [`ChunkedEncoder`] frames a *request* body into chunks
//!   (`<hex-size>\r\n<data>\r\n` … terminated by `0\r\n\r\n` plus optional trailers).
//!   This ports the `Curl_crtype Curl_httpchunk_encoder` reader-pipeline stage and
//!   `Curl_httpchunk_add_reader`.
//!
//! ## Byte-for-byte parity
//!
//! Framing is byte-for-byte identical to curl 8.x: CRLF handling, chunk-extension
//! tolerance, trailer processing, and the hexadecimal chunk-size grammar all follow the
//! reference `http_chunks.c` state machine exactly. The state names in [`ChunkyState`]
//! and the error codes in [`CHUNKcode`] are preserved verbatim so that `--trace`
//! diagnostics and error strings remain identical (AAP §0.3.2, §0.6.3).
//!
//! The decoder deliberately compares against the raw ASCII byte values `0x0d` / `0x0a`
//! rather than the Rust escapes `'\r'` / `'\n'`, matching the upstream C comment that
//! this "always uses ASCII hex values to accommodate non-ASCII hosts".
//!
//! ## Memory safety
//!
//! This module is written entirely in safe Rust and performs no raw-pointer, FFI, or
//! otherwise memory-hazardous operations. The crate root enforces safe Rust crate-wide via
//! a `forbid`-level lint, so any attempt to bypass the borrow checker is a hard compile
//! error; a CI audit additionally asserts the corresponding keyword never appears under
//! `curl-rs-lib/src/` (AAP §0.6.2, §0.7.2). All buffering uses the [`bytes`] crate; curl's
//! manual `dynbuf`/`bufq` allocations are replaced by owned [`BytesMut`] whose `Drop`
//! supplants `Curl_httpchunk_free` / `Curl_bufq_free`.

use crate::error::{CurlCode, Error, Result};
use bytes::{Bytes, BytesMut};

// This module is a child of the HTTP family root `crate::protocols::http` (declared there
// as `pub mod chunks;`), so that structural dependency is satisfied without an explicit
// `use`. Trailer lines produced by the decoder are modeled as raw header bytes (see
// [`ChunkWrite::write_trailer`]) rather than reusing the parent's header machinery, keeping
// this codec self-contained and independently testable.

/// The longest hexadecimal chunk-size we accept, in digits.
///
/// Ported from `http_chunks.h`'s `CHUNK_MAXNUM_LEN (SIZEOF_CURL_OFF_T * 2)`. Neither
/// RFC 2616 nor RFC 9112 defines a maximum chunk size; curl caps it at the number of hex
/// digits that fit a 64-bit `curl_off_t` — 16 digits. A size longer than this is rejected
/// with [`CHUNKcode::TooLongHex`].
pub const CHUNK_MAXNUM_LEN: usize = 16;

/// Upper bound on `curl_off_t` (`CURL_OFF_T_MAX`), i.e. `i64::MAX`.
///
/// curl parses the chunk size with this ceiling (`curlx_str_hex(..., CURL_OFF_T_MAX)`);
/// a value exceeding it is an overflow and is reported as [`CHUNKcode::IllegalHex`],
/// exactly as the reference does. Although [`Chunker::datasize`] is stored as `u64`, the
/// parser rejects anything above this bound to preserve parity.
const CURL_OFF_T_MAX: u64 = i64::MAX as u64;

/// Minimum chunk payload the encoder will emit for a small upstream read
/// (`CURL_CHUNKED_MINLEN` in `http_chunks.c`). Small reads are coalesced into a chunk of
/// at least this size.
pub const CURL_CHUNKED_MINLEN: usize = 1024;

/// Maximum chunk payload the encoder buffers per round (`CURL_CHUNKED_MAXLEN`).
pub const CURL_CHUNKED_MAXLEN: usize = 64 * 1024;

// ===========================================================================
// PHASE 1 — state and error enums (names preserved for --trace / strerror parity)
// ===========================================================================

/// The decoder state machine (← `ChunkyState` in `http_chunks.h`).
///
/// Every state and its exact meaning is preserved from the reference so that the
/// de-chunking behavior — and any `--trace` output naming these states — stays identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkyState {
    /// `CHUNK_HEX`: buffer hexadecimal digits until a non-hex byte is seen, then move to
    /// [`Lf`](ChunkyState::Lf).
    Hex,
    /// `CHUNK_LF`: wait for the LF that ends the chunk-size line; ignore everything else
    /// (this is where chunk-extensions after the size are silently consumed).
    Lf,
    /// `CHUNK_DATA`: consume `datasize` payload bytes, then move to
    /// [`PostLf`](ChunkyState::PostLf).
    Data,
    /// `CHUNK_POSTLF`: expect the trailing CRLF after a chunk's data. A missing CR is
    /// tolerated; on the LF we loop back to [`Hex`](ChunkyState::Hex).
    PostLf,
    /// `CHUNK_STOP`: out of the game. The `datasize` field then records how many trailing
    /// bytes in the input were **not** part of the chunked stream.
    Stop,
    /// `CHUNK_TRAILER`: optional trailer headers may appear here, unless the next line is
    /// an immediate CRLF (which terminates the stream).
    Trailer,
    /// `CHUNK_TRAILER_CR`: a trailer CR has been seen; the next byte must be LF.
    TrailerCr,
    /// `CHUNK_TRAILER_POSTCR`: an LF must follow. An empty trailer means the stream is
    /// finished; otherwise the completed trailer line is broadcast and we return to
    /// [`Trailer`](ChunkyState::Trailer).
    TrailerPostCr,
    /// `CHUNK_DONE`: everything has been successfully de-chunked.
    Done,
    /// `CHUNK_FAILED`: a bad or incorrectly terminated chunk was seen.
    Failed,
}

/// Chunked-decoding error categories (← `CHUNKcode` in `http_chunks.h`).
///
/// The integer discriminants are preserved verbatim (`CHUNKE_OK == 0`,
/// `CHUNKE_TOO_LONG_HEX == 1`, …) so the ordering never drifts. This enum mirrors curl's
/// `ch->last_code`: it records **which category** of chunk error occurred, for the
/// human-readable [`CHUNKcode::strerror`] text.
///
/// [`PassthruError`](CHUNKcode::PassthruError) is a sentinel: it means "the real error is
/// the wrapped [`Error`] returned by the sink". Unlike the other categories it does not
/// map to a fixed message; the propagated [`Error`] carries the true [`CurlCode`]. This is
/// exactly curl's `CHUNKE_PASSTHRU_ERROR`, where `last_code` is the sentinel and the
/// function's return value is the genuine `CURLcode`.
#[allow(non_camel_case_types)] // Name preserved verbatim from the C `CHUNKcode` typedef.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CHUNKcode {
    /// `CHUNKE_OK` — no error.
    Ok = 0,
    /// `CHUNKE_TOO_LONG_HEX` — chunk-size hex ran longer than [`CHUNK_MAXNUM_LEN`].
    TooLongHex = 1,
    /// `CHUNKE_ILLEGAL_HEX` — a non-hex byte where a hex digit was required, a missing
    /// hex sequence, or a chunk size that overflows `curl_off_t`.
    IllegalHex,
    /// `CHUNKE_BAD_CHUNK` — malformed / incorrectly terminated chunk framing.
    BadChunk,
    /// `CHUNKE_BAD_ENCODING` — bad content-encoding found (kept for parity of numbering).
    BadEncoding,
    /// `CHUNKE_OUT_OF_MEMORY` — allocation failure. Retained for numbering parity; the
    /// safe-Rust port uses [`BytesMut`], whose growth aborts rather than returning this,
    /// so it is never produced here.
    OutOfMemory,
    /// `CHUNKE_PASSTHRU_ERROR` — propagate the wrapped [`Error`] (real `CURLcode`).
    PassthruError,
}

impl CHUNKcode {
    /// The diagnostic string for this error (← `Curl_chunked_strerror`).
    ///
    /// The exact text is preserved so that stderr messages remain byte-stable for
    /// downstream log scrapers (AAP §0.7.3). The [`Ok`](CHUNKcode::Ok) /
    /// [`PassthruError`](CHUNKcode::PassthruError) mappings match the reference `switch`
    /// (whose `default` returns `"OK"`).
    #[must_use]
    pub fn strerror(self) -> &'static str {
        match self {
            CHUNKcode::TooLongHex => "Too long hexadecimal number",
            CHUNKcode::IllegalHex => "Illegal or missing hexadecimal sequence",
            CHUNKcode::BadChunk => "Malformed encoding found",
            CHUNKcode::PassthruError => "Error writing data to client",
            CHUNKcode::BadEncoding => "Bad content-encoding found",
            CHUNKcode::OutOfMemory => "Out of memory",
            // `CHUNKE_OK` and any future value fall through to the reference `default`.
            CHUNKcode::Ok => "OK",
        }
    }

    /// The frozen integer value of this code (the `CHUNKE_*` enum value).
    #[must_use]
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

// ===========================================================================
// Downstream sink abstraction (← curl's `Curl_client_write` / `Curl_cwriter_write`)
// ===========================================================================

/// A downstream sink for the de-chunking decoder, modeling curl's client-write targets.
///
/// The reference calls `Curl_client_write` (or the next `Curl_cwriter`) with different
/// `CLIENTWRITE_*` type flags depending on what is being emitted; this trait splits those
/// destinations into explicit methods:
///
/// * [`write_body`](ChunkWrite::write_body) — reassembled response **body** bytes
///   (`CLIENTWRITE_BODY`).
/// * [`write_trailer`](ChunkWrite::write_trailer) — a completed **trailer** header line,
///   including its terminating CRLF (`CLIENTWRITE_HEADER | CLIENTWRITE_TRAILER`).
/// * [`write_passthrough`](ChunkWrite::write_passthrough) — non-body writes that flow
///   through the stage unchanged (e.g. response headers reaching the chunked stage before
///   the body).
///
/// Only [`write_body`](ChunkWrite::write_body) is required; the other two default to a
/// no-op so a caller that only wants the decoded body can implement a single method (or use
/// the closure-based [`Chunker::read`]).
pub trait ChunkWrite {
    /// Receive decoded response body bytes.
    fn write_body(&mut self, buf: &[u8]) -> Result<()>;

    /// Receive one completed trailer header line (content + CRLF). Defaults to discarding.
    fn write_trailer(&mut self, buf: &[u8]) -> Result<()> {
        let _ = buf;
        Ok(())
    }

    /// Receive non-body pass-through bytes. Defaults to discarding.
    fn write_passthrough(&mut self, buf: &[u8]) -> Result<()> {
        let _ = buf;
        Ok(())
    }
}

/// Adapts a plain `FnMut(&[u8]) -> Result<()>` body closure into a [`ChunkWrite`] sink,
/// used by [`Chunker::read`]. Trailer and pass-through writes are discarded (the low-level
/// [`Chunker::read`] contract emits body bytes only; trailer broadcasting is available via
/// [`Chunker::read_with`] and [`ChunkedWriter`]).
struct BodyClosureSink<'a, F: FnMut(&[u8]) -> Result<()>> {
    body: &'a mut F,
}

impl<F: FnMut(&[u8]) -> Result<()>> ChunkWrite for BodyClosureSink<'_, F> {
    fn write_body(&mut self, buf: &[u8]) -> Result<()> {
        (self.body)(buf)
    }
}

/// Returns `true` for an ASCII hexadecimal digit (`0-9`, `a-f`, `A-F`), matching curl's
/// `ISXDIGIT` classification used in the `CHUNK_HEX` state.
#[inline]
fn is_xdigit(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// Parses an all-hex-digit slice into a chunk size (← `curlx_str_hex(..., CURL_OFF_T_MAX)`).
///
/// `digits` is guaranteed by the caller to contain only ASCII hex digits and to be
/// non-empty. Returns `None` if the value overflows [`CURL_OFF_T_MAX`] (`i64::MAX`), which
/// the reference reports as [`CHUNKcode::IllegalHex`].
fn parse_chunk_hex(digits: &[u8]) -> Option<u64> {
    let mut num: u64 = 0;
    for &d in digits {
        let n = if d.is_ascii_digit() {
            u64::from(d - b'0')
        } else if (b'a'..=b'f').contains(&d) {
            u64::from(d - b'a' + 10)
        } else if (b'A'..=b'F').contains(&d) {
            u64::from(d - b'A' + 10)
        } else {
            // Unreachable: the caller only buffers `is_xdigit` bytes.
            return None;
        };
        // Overflow guard mirroring the reference's per-digit `num > (max - n)/base` check:
        // reject any value that would exceed CURL_OFF_T_MAX.
        num = num.checked_mul(16)?.checked_add(n)?;
        if num > CURL_OFF_T_MAX {
            return None;
        }
    }
    Some(num)
}

// ===========================================================================
// PHASE 2 — the chunked-decoder state struct (← `struct Curl_chunker`)
// ===========================================================================

/// The chunked-transfer decoder state (← `struct Curl_chunker`).
///
/// Holds the running de-chunk state across successive [`read`](Chunker::read) calls. Field
/// names track the reference struct; `struct dynbuf trailer` becomes an owned [`BytesMut`]
/// and `Curl_httpchunk_free` is subsumed by its `Drop`.
#[derive(Debug)]
pub struct Chunker {
    /// Bytes remaining in the current chunk. After the stream completes
    /// ([`ChunkyState::Done`]) this instead records the count of trailing input bytes that
    /// were not part of the chunked body (← `curl_off_t datasize`).
    pub datasize: u64,
    /// The current decoder state (← `ChunkyState state`).
    pub state: ChunkyState,
    /// The category of the most recent error (← `CHUNKcode last_code`).
    pub last_code: CHUNKcode,
    /// Accumulates the bytes of the trailer line currently being read (← `struct dynbuf
    /// trailer`, initialized with `DYN_H1_TRAILER`).
    trailer: BytesMut,
    /// Number of hex digits buffered so far in [`Self::hexbuffer`] (← `unsigned char
    /// hexindex`).
    hexindex: u8,
    /// Buffer for the chunk-size hex digits; `+1` for the reference's NUL terminator
    /// (← `char hexbuffer[CHUNK_MAXNUM_LEN + 1]`).
    hexbuffer: [u8; CHUNK_MAXNUM_LEN + 1],
    /// When set, decoded body data is never written out — the stream is still parsed to
    /// compute length (← `BIT(ignore_body)`).
    ignore_body: bool,
}

impl Chunker {
    /// Creates a fresh decoder (← `Curl_httpchunk_init`).
    ///
    /// `ignore_body` requests that decoded body bytes be parsed but never written to the
    /// sink (used when the caller only needs the content length).
    #[must_use]
    pub fn new(ignore_body: bool) -> Self {
        Chunker {
            datasize: 0,
            state: ChunkyState::Hex, // we get hex first!
            last_code: CHUNKcode::Ok,
            trailer: BytesMut::new(),
            hexindex: 0,
            hexbuffer: [0u8; CHUNK_MAXNUM_LEN + 1],
            ignore_body,
        }
    }

    /// Resets the decoder to its initial state (← `Curl_httpchunk_reset`).
    ///
    /// Clears the hex buffer, trailer buffer, and last error, returning to
    /// [`ChunkyState::Hex`]; `ignore_body` is re-applied (the reference passes the current
    /// value when looping between chunks).
    pub fn reset(&mut self, ignore_body: bool) {
        self.hexindex = 0;
        self.state = ChunkyState::Hex;
        self.last_code = CHUNKcode::Ok;
        self.datasize = 0;
        self.trailer.clear();
        self.ignore_body = ignore_body;
    }

    /// Returns `true` once the stream has been fully de-chunked (← `Curl_httpchunk_is_done`,
    /// `ch->state == CHUNK_DONE`).
    ///
    /// Note: this checks [`ChunkyState::Done`] only, matching the reference. [`Stop`] is a
    /// transient state that still awaits the final LF, so an input buffer that ends exactly
    /// at [`Stop`] is **not** done — reporting done there would diverge from curl.
    ///
    /// [`Stop`]: ChunkyState::Stop
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.state == ChunkyState::Done
    }
}

impl Default for Chunker {
    /// A decoder that writes body data (`ignore_body == false`).
    fn default() -> Self {
        Chunker::new(false)
    }
}

// ===========================================================================
// PHASE 3 — the decoder core (← `httpchunk_readwrite` / `Curl_httpchunk_read`)
// ===========================================================================

impl Chunker {
    /// De-chunks `ch_in`, writing decoded **body** bytes to the `out` closure, and returns
    /// the number of input bytes consumed (← `Curl_httpchunk_read`).
    ///
    /// This is the low-level, body-only entry point matching curl's
    /// `Curl_httpchunk_read(..., buf, blen, pconsumed)` (which calls
    /// `httpchunk_readwrite` with a `NULL` writer). Trailer headers found in the stream are
    /// parsed and consumed exactly as the reference does, but are **not** delivered here;
    /// use [`Chunker::read_with`] (or [`ChunkedWriter`]) to also receive trailer lines.
    ///
    /// On success the returned count is how many bytes of `ch_in` were consumed; the
    /// remaining `ch_in[consumed..]` (if any) are leftovers after the stream terminated. On
    /// a framing error the [`Chunker`] transitions to [`ChunkyState::Failed`], records the
    /// category in [`Chunker::last_code`], and returns the corresponding [`Error`].
    pub fn read(
        &mut self,
        ch_in: &[u8],
        out: &mut impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<usize> {
        let mut sink = BodyClosureSink { body: out };
        self.read_with(ch_in, &mut sink)
    }

    /// De-chunks `ch_in` into a full [`ChunkWrite`] `sink`, returning bytes consumed.
    ///
    /// This is the complete port of `httpchunk_readwrite`. Body bytes go to
    /// [`ChunkWrite::write_body`] (unless [`ignore_body`](Chunker::new) is set) and each
    /// completed trailer line — content plus its terminating CRLF — is broadcast via
    /// [`ChunkWrite::write_trailer`], mirroring curl's `CLIENTWRITE_HEADER |
    /// CLIENTWRITE_TRAILER` client write.
    ///
    /// The loop compares bytes against the raw ASCII values `0x0d`/`0x0a` (never `'\r'`/
    /// `'\n'`), preserving the reference's non-ASCII-host behavior.
    ///
    /// Note on `http_te_skip`: curl has an option that, when set, forwards the still-encoded
    /// bytes to the client while decoding continues purely to compute the content length.
    /// That option is not part of `struct Curl_chunker` and is off in a default transfer;
    /// this port therefore implements the default path (`http_te_skip == false`), gating
    /// body writes on `!ignore_body` alone.
    pub fn read_with<S: ChunkWrite + ?Sized>(
        &mut self,
        ch_in: &[u8],
        sink: &mut S,
    ) -> Result<usize> {
        let mut consumed: usize = 0;

        // First handle terminal states that cannot progress (reference does this before the
        // loop). DONE returns OK having consumed nothing; FAILED returns a recv error.
        match self.state {
            ChunkyState::Done => return Ok(0),
            ChunkyState::Failed => return Err(Error::Recv),
            _ => {}
        }

        let total = ch_in.len();
        let mut idx: usize = 0;

        while idx < total {
            let b = ch_in[idx];
            match self.state {
                ChunkyState::Hex => {
                    if is_xdigit(b) {
                        if self.hexindex as usize >= CHUNK_MAXNUM_LEN {
                            // Longer than we support.
                            self.state = ChunkyState::Failed;
                            self.last_code = CHUNKcode::TooLongHex;
                            return Err(Error::with_context(
                                CurlCode::RecvError,
                                format!("chunk hex-length longer than {CHUNK_MAXNUM_LEN}"),
                            ));
                        }
                        self.hexbuffer[self.hexindex as usize] = b;
                        self.hexindex += 1;
                        idx += 1;
                        consumed += 1;
                    } else {
                        if self.hexindex == 0 {
                            // Junk where a hex digit was expected.
                            self.state = ChunkyState::Failed;
                            self.last_code = CHUNKcode::IllegalHex;
                            return Err(Error::with_context(
                                CurlCode::RecvError,
                                format!("chunk hex-length char not a hex digit: 0x{b:x}"),
                            ));
                        }
                        // NUL-terminate the collected digits (parity with the C buffer) and
                        // parse them; overflow beyond CURL_OFF_T_MAX is an illegal size.
                        let n = self.hexindex as usize;
                        self.hexbuffer[n] = 0;
                        match parse_chunk_hex(&self.hexbuffer[..n]) {
                            Some(v) => self.datasize = v,
                            None => {
                                let shown = String::from_utf8_lossy(&self.hexbuffer[..n]);
                                self.state = ChunkyState::Failed;
                                self.last_code = CHUNKcode::IllegalHex;
                                return Err(Error::with_context(
                                    CurlCode::RecvError,
                                    format!("invalid chunk size: '{shown}'"),
                                ));
                            }
                        }
                        // Now wait for the CRLF; buf/blen are left unmodified (no consume).
                        self.state = ChunkyState::Lf;
                    }
                }

                ChunkyState::Lf => {
                    // Waiting for the LF after the chunk size.
                    if b == 0x0a {
                        if self.datasize == 0 {
                            // Last chunk — look for trailers next.
                            self.state = ChunkyState::Trailer;
                        } else {
                            self.state = ChunkyState::Data;
                        }
                    }
                    idx += 1;
                    consumed += 1;
                }

                ChunkyState::Data => {
                    // Take the smaller of "bytes we still owe this chunk" and "bytes on hand".
                    let remaining = total - idx;
                    let piece = if self.datasize < remaining as u64 {
                        self.datasize as usize
                    } else {
                        remaining
                    };

                    if !self.ignore_body {
                        if let Err(e) = sink.write_body(&ch_in[idx..idx + piece]) {
                            self.state = ChunkyState::Failed;
                            self.last_code = CHUNKcode::PassthruError;
                            return Err(e);
                        }
                    }

                    consumed += piece;
                    self.datasize -= piece as u64;
                    idx += piece;

                    if self.datasize == 0 {
                        // End of this chunk's data; expect the trailing CRLF.
                        self.state = ChunkyState::PostLf;
                    }
                }

                ChunkyState::PostLf => {
                    if b == 0x0a {
                        // The final byte before we loop back to hex and start over.
                        let ignore_body = self.ignore_body;
                        self.reset(ignore_body);
                    } else if b != 0x0d {
                        // Anything other than the tolerated CR is malformed.
                        self.state = ChunkyState::Failed;
                        self.last_code = CHUNKcode::BadChunk;
                        return Err(Error::Recv);
                    }
                    idx += 1;
                    consumed += 1;
                }

                ChunkyState::Trailer => {
                    if b == 0x0d || b == 0x0a {
                        if !self.trailer.is_empty() {
                            // End of a non-empty trailer line: append CRLF, broadcast the
                            // whole line, then reset the buffer for the next trailer.
                            self.trailer.extend_from_slice(&[0x0d, 0x0a]);
                            let line = self.trailer.split();
                            if let Err(e) = sink.write_trailer(&line) {
                                self.state = ChunkyState::Failed;
                                self.last_code = CHUNKcode::PassthruError;
                                return Err(e);
                            }
                            self.state = ChunkyState::TrailerCr;
                            if b == 0x0a {
                                // Already sitting on the LF — let TRAILER_CR consume it.
                                continue;
                            }
                            // Otherwise this was the CR: fall through to consume it below.
                        } else {
                            // No trailer content: we are on the final CRLF pair. Do not
                            // advance — reprocess this byte in TRAILER_POSTCR.
                            self.state = ChunkyState::TrailerPostCr;
                            continue;
                        }
                    } else {
                        // Ordinary trailer content byte.
                        self.trailer.extend_from_slice(&[b]);
                    }
                    idx += 1;
                    consumed += 1;
                }

                ChunkyState::TrailerCr => {
                    if b == 0x0a {
                        self.state = ChunkyState::TrailerPostCr;
                        idx += 1;
                        consumed += 1;
                    } else {
                        self.state = ChunkyState::Failed;
                        self.last_code = CHUNKcode::BadChunk;
                        return Err(Error::Recv);
                    }
                }

                ChunkyState::TrailerPostCr => {
                    // We enter expecting a CR (then LF); a non-CR/LF byte instead means yet
                    // another trailer header follows.
                    if b != 0x0d && b != 0x0a {
                        self.state = ChunkyState::Trailer;
                        continue; // do not advance the pointer
                    }
                    if b == 0x0d {
                        // Skip the CR.
                        idx += 1;
                        consumed += 1;
                    }
                    // Now wait for the final LF (an LF here is reprocessed in STOP).
                    self.state = ChunkyState::Stop;
                }

                ChunkyState::Stop => {
                    if b == 0x0a {
                        idx += 1;
                        consumed += 1;
                        // Record how many trailing bytes remain unconsumed after the stream.
                        self.datasize = (total - idx) as u64;
                        self.state = ChunkyState::Done;
                        return Ok(consumed);
                    }
                    self.state = ChunkyState::Failed;
                    self.last_code = CHUNKcode::BadChunk;
                    return Err(Error::Recv);
                }

                ChunkyState::Done => return Ok(consumed),
                ChunkyState::Failed => return Err(Error::Recv),
            }
        }

        Ok(consumed)
    }
}

// ===========================================================================
// PHASE 3 (cont.) — the write-pipeline stage (← `Curl_cwtype Curl_httpchunk_unencoder`)
// ===========================================================================

/// The chunked Transfer-Encoding decode stage of the client write pipeline
/// (← `struct chunked_writer` + `Curl_httpchunk_unencoder`).
///
/// Wraps a [`Chunker`] and reproduces `cw_chunked_init` / `cw_chunked_write` /
/// `cw_chunked_close`. Non-body writes pass straight through to the downstream sink; body
/// writes are de-chunked. When the stream completes, [`download_done`](Self::download_done)
/// is set (← `data->req.download_done = TRUE`).
#[derive(Debug)]
pub struct ChunkedWriter {
    chunker: Chunker,
    /// Set once the chunked stream is fully decoded (← `data->req.download_done`).
    pub download_done: bool,
}

impl ChunkedWriter {
    /// Creates the decode stage (← `cw_chunked_init`), which initializes its [`Chunker`]
    /// with `ignore_body == false`.
    #[must_use]
    pub fn new() -> Self {
        ChunkedWriter {
            chunker: Chunker::new(false),
            download_done: false,
        }
    }

    /// Processes one pipeline write (← `cw_chunked_write`).
    ///
    /// * `is_body`   — whether the write carries body bytes (`type & CLIENTWRITE_BODY`).
    /// * `is_eos`    — whether this is the end of the stream (`type & CLIENTWRITE_EOS`).
    /// * `no_body`   — the request expects no body (`data->req.no_body`).
    /// * `buf`       — the bytes for this write.
    /// * `sink`      — downstream [`ChunkWrite`] destination.
    ///
    /// Non-body writes are forwarded verbatim via [`ChunkWrite::write_passthrough`]. Body
    /// writes are de-chunked through the [`Chunker`]; on completion `download_done` is set,
    /// and if the stream ends prematurely (EOS while still expecting body) a
    /// [`Error::PartialFile`] is returned, matching `CURLE_PARTIAL_FILE`.
    pub fn write<S: ChunkWrite + ?Sized>(
        &mut self,
        is_body: bool,
        is_eos: bool,
        no_body: bool,
        buf: &[u8],
        sink: &mut S,
    ) -> Result<()> {
        if !is_body {
            // Not body data — forward through the stage unchanged.
            return sink.write_passthrough(buf);
        }

        let consumed = match self.chunker.read_with(buf, sink) {
            Ok(c) => c,
            Err(e) => {
                // Reference: on error, `failf` a message then return the result code.
                // A pass-through error already carries the genuine CURLcode, so propagate
                // it as-is; otherwise wrap with curl's "<reason> in chunked-encoding" text.
                if self.chunker.last_code == CHUNKcode::PassthruError {
                    return Err(e);
                }
                return Err(Error::with_context(
                    e.code(),
                    format!("{} in chunked-encoding", self.chunker.last_code.strerror()),
                ));
            }
        };

        let leftover = buf.len() - consumed;
        if self.chunker.state == ChunkyState::Done {
            // Chunks read successfully: the download is complete. `leftover` counts any
            // bytes after the terminating chunk (curl logs these as "Leftovers after
            // chunking"); it is also available via `self.chunker.datasize`.
            self.download_done = true;
            let _ = leftover;
        } else if is_eos && !no_body {
            // Stream closed with data still outstanding.
            return Err(Error::PartialFile);
        }

        Ok(())
    }

    /// Tears down the stage (← `cw_chunked_close`).
    ///
    /// The reference calls `Curl_httpchunk_free` to release the trailer `dynbuf`; here the
    /// [`Chunker`]'s [`BytesMut`] is freed automatically by `Drop`, so this is a no-op kept
    /// for API symmetry.
    pub fn close(&mut self) {}

    /// Returns `true` once the underlying [`Chunker`] has finished (← `state == CHUNK_DONE`).
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.chunker.is_done()
    }
}

impl Default for ChunkedWriter {
    fn default() -> Self {
        ChunkedWriter::new()
    }
}

// ===========================================================================
// PHASE 4 — the request-body encoder (← `Curl_crtype Curl_httpchunk_encoder`)
// ===========================================================================

/// The chunked Transfer-Encoding **encoder** for request bodies
/// (← `struct chunked_reader` + `Curl_httpchunk_encoder`).
///
/// Frames upstream request-body bytes into HTTP/1.1 chunks. Each non-empty run of data is
/// emitted as `<hex-size>\r\n<data>\r\n`, and the stream is terminated with the last chunk
/// `0\r\n\r\n` (or `0\r\n<trailer>\r\n…\r\n` when request trailers are supplied). Framing is
/// byte-for-byte identical to curl's `add_chunk` / `add_last_chunk`.
///
/// Two usage styles are provided:
///
/// * **Push** — call [`push`](Self::push) with each run of body bytes then [`finish`](Self::finish)
///   once, and drain the framed output with [`take`](Self::take) or [`drain`](Self::drain).
/// * **Pull** — call [`read`](Self::read) with a source closure; it pulls from the source,
///   frames the data (honoring the [`CURL_CHUNKED_MINLEN`]/[`CURL_CHUNKED_MAXLEN`] buffer
///   preferences), and copies framed bytes into the caller's buffer — mirroring
///   `cr_chunked_read`.
#[derive(Debug)]
pub struct ChunkedEncoder {
    /// Framed output awaiting delivery (← `struct bufq chunkbuf`).
    chunkbuf: BytesMut,
    /// Set once the upstream source has signaled end-of-stream and the last chunk has been
    /// emitted (← `BIT(read_eos)`).
    read_eos: bool,
    /// Set once every framed byte has been delivered to the caller (← `BIT(eos)`).
    eos: bool,
    /// Request trailer header lines (`"Name: value"`) to append after the last chunk. Curl
    /// obtains these from `data->set.trailer_callback`; here they are supplied up front.
    trailers: Vec<String>,
}

impl ChunkedEncoder {
    /// Creates a new encoder with no request trailers (← `cr_chunked_init`).
    #[must_use]
    pub fn new() -> Self {
        ChunkedEncoder {
            chunkbuf: BytesMut::new(),
            read_eos: false,
            eos: false,
            trailers: Vec::new(),
        }
    }

    /// Creates an encoder that appends the given request trailer lines after the last chunk.
    ///
    /// Each entry should be a full `"Name: value"` header line (no CRLF). Malformed entries
    /// — those lacking a `':'` followed by a space — are skipped when framed, matching the
    /// reference's per-trailer validation in `add_last_chunk`.
    #[must_use]
    pub fn with_trailers(trailers: Vec<String>) -> Self {
        ChunkedEncoder {
            chunkbuf: BytesMut::new(),
            read_eos: false,
            eos: false,
            trailers,
        }
    }

    /// Frames one run of body bytes into the output buffer (← the `if(nread)` block of
    /// `add_chunk`).
    ///
    /// Emits `<hex-size>\r\n<data>\r\n`. An empty `data` emits nothing, exactly as the
    /// reference only wraps a chunk when it actually read bytes.
    pub fn push(&mut self, data: &[u8]) {
        if !data.is_empty() {
            // Chunk-size line: lowercase hex, no leading zeros (← `curl_msnprintf("%zx\r\n")`).
            let header = format!("{:x}\r\n", data.len());
            self.chunkbuf.extend_from_slice(header.as_bytes());
            self.chunkbuf.extend_from_slice(data);
            self.chunkbuf.extend_from_slice(b"\r\n");
        }
    }

    /// Appends the terminating last chunk (← `add_last_chunk`).
    ///
    /// With no trailers this writes `0\r\n\r\n`. With trailers it writes `0\r\n`, then each
    /// correctly formatted trailer line followed by CRLF, then a final CRLF. Idempotent:
    /// once the last chunk has been emitted, further calls do nothing.
    pub fn finish(&mut self) {
        if self.read_eos {
            return;
        }
        if self.trailers.is_empty() {
            self.chunkbuf.extend_from_slice(b"0\r\n\r\n");
        } else {
            self.chunkbuf.extend_from_slice(b"0\r\n");
            for tr in &self.trailers {
                // Only emit correctly formatted trailers: a ':' followed by a space.
                if let Some(pos) = tr.find(':') {
                    if tr.as_bytes().get(pos + 1) == Some(&b' ') {
                        self.chunkbuf.extend_from_slice(tr.as_bytes());
                        self.chunkbuf.extend_from_slice(b"\r\n");
                    }
                }
            }
            self.chunkbuf.extend_from_slice(b"\r\n");
        }
        self.read_eos = true;
    }

    /// Copies up to `buf.len()` framed bytes into `buf`, returning how many were copied
    /// (← `Curl_bufq_cread`). Consumed bytes are removed from the internal buffer.
    pub fn drain(&mut self, buf: &mut [u8]) -> usize {
        let n = self.chunkbuf.len().min(buf.len());
        buf[..n].copy_from_slice(&self.chunkbuf[..n]);
        let _ = self.chunkbuf.split_to(n);
        n
    }

    /// Takes and returns all currently framed output, leaving the internal buffer empty.
    /// Convenient for the push style and for tests.
    #[must_use]
    pub fn take(&mut self) -> Bytes {
        self.chunkbuf.split().freeze()
    }

    /// Pulls body bytes from `src` and delivers framed chunk bytes into `buf`
    /// (← `cr_chunked_read` + `add_chunk`), returning `(n_written, eos)`.
    ///
    /// `src` fills the slice it is given and returns `(n_read, source_eos)`. When the buffer
    /// is empty and the source is not yet exhausted, a fresh chunk is pulled and framed,
    /// respecting the [`CURL_CHUNKED_MINLEN`]/[`CURL_CHUNKED_MAXLEN`] preferences (small
    /// reads are coalesced to at least `MINLEN`; large reads reserve room for the framing
    /// overhead). `eos` becomes `true` once the last chunk has been fully delivered.
    pub fn read(
        &mut self,
        src: &mut impl FnMut(&mut [u8]) -> Result<(usize, bool)>,
        buf: &mut [u8],
    ) -> Result<(usize, bool)> {
        let mut n_written = 0usize;
        let mut eos_out = self.eos;

        if !self.eos {
            if !self.read_eos && self.chunkbuf.is_empty() {
                self.add_chunk(src, buf.len())?;
            }
            if !self.chunkbuf.is_empty() {
                n_written = self.drain(buf);
                if self.read_eos && self.chunkbuf.is_empty() {
                    // No more data and everything has been read out — done.
                    self.eos = true;
                    eos_out = true;
                }
                return Ok((n_written, eos_out));
            }
        }
        // Either already done, or the source produced nothing this round (paused).
        Ok((n_written, eos_out))
    }

    /// Pulls one read from `src` and frames it into the output buffer (← `add_chunk`).
    ///
    /// `caller_blen` is the caller's target buffer size, used (as in the reference) to size
    /// the pull so a framed chunk fits back into that buffer.
    fn add_chunk(
        &mut self,
        src: &mut impl FnMut(&mut [u8]) -> Result<(usize, bool)>,
        caller_blen: usize,
    ) -> Result<()> {
        // Respect our buffer preference (← `blen = CURLMIN(blen, CURL_CHUNKED_MAXLEN)`).
        let mut want = caller_blen.min(CURL_CHUNKED_MAXLEN);
        if want < CURL_CHUNKED_MINLEN {
            // Small read: make a chunk of decent size.
            want = CURL_CHUNKED_MINLEN;
        } else {
            // Larger read: leave room so the framed chunk fits back (8 hex + 2 * CRLF).
            want -= 8 + 2 + 2;
        }

        let mut tmp = vec![0u8; want];
        let (nread, source_eos) = src(&mut tmp)?;

        if nread > 0 {
            // Wrap the bytes we actually read.
            self.push(&tmp[..nread]);
        }
        if source_eos {
            // Emit the terminating last chunk (+ trailers).
            self.finish();
        }
        Ok(())
    }

    /// The unknown/streaming total length (← `cr_chunked_total_length`, which returns `-1`).
    ///
    /// The chunked encoder's output length depends on its input, so no total is known.
    #[must_use]
    pub fn total_length(&self) -> Option<u64> {
        None
    }
}

impl Default for ChunkedEncoder {
    fn default() -> Self {
        ChunkedEncoder::new()
    }
}

/// Constructs a chunked Transfer-Encoding request-body encoder
/// (← `Curl_httpchunk_add_reader`).
///
/// In curl this creates a `Curl_creader` for `Curl_httpchunk_encoder` and pushes it onto
/// the transfer's reader stack. The reader-stack wiring belongs to the transfer layer; this
/// function provides the encoder itself, ready to frame a request body.
#[must_use]
pub fn add_reader() -> ChunkedEncoder {
    ChunkedEncoder::new()
}

// ===========================================================================
// Tests — the curl 8.x chunked framing behavior is the oracle.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`ChunkWrite`] sink that records body bytes, trailer lines, and pass-through bytes
    /// so tests can assert on exactly what the decoder emitted.
    #[derive(Default)]
    struct Capture {
        body: Vec<u8>,
        trailers: Vec<Vec<u8>>,
        passthrough: Vec<u8>,
    }

    impl ChunkWrite for Capture {
        fn write_body(&mut self, buf: &[u8]) -> Result<()> {
            self.body.extend_from_slice(buf);
            Ok(())
        }
        fn write_trailer(&mut self, buf: &[u8]) -> Result<()> {
            self.trailers.push(buf.to_vec());
            Ok(())
        }
        fn write_passthrough(&mut self, buf: &[u8]) -> Result<()> {
            self.passthrough.extend_from_slice(buf);
            Ok(())
        }
    }

    /// Decode `input` in one shot, returning the decoded body bytes.
    fn decode_body(input: &[u8]) -> (Vec<u8>, usize, Chunker) {
        let mut ch = Chunker::new(false);
        let mut out = Vec::new();
        let consumed = ch
            .read(input, &mut |b: &[u8]| {
                out.extend_from_slice(b);
                Ok(())
            })
            .expect("decode should succeed");
        (out, consumed, ch)
    }

    #[test]
    fn constants_match_reference() {
        // CHUNK_MAXNUM_LEN == SIZEOF_CURL_OFF_T * 2 for 64-bit.
        assert_eq!(CHUNK_MAXNUM_LEN, 16);
        assert_eq!(CURL_CHUNKED_MINLEN, 1024);
        assert_eq!(CURL_CHUNKED_MAXLEN, 64 * 1024);
        assert_eq!(CURL_OFF_T_MAX, i64::MAX as u64);
    }

    #[test]
    fn chunkcode_integer_order_preserved() {
        // Discriminants transcribed verbatim from the C `CHUNKcode` enum.
        assert_eq!(CHUNKcode::Ok.as_i32(), 0);
        assert_eq!(CHUNKcode::TooLongHex.as_i32(), 1);
        assert_eq!(CHUNKcode::IllegalHex.as_i32(), 2);
        assert_eq!(CHUNKcode::BadChunk.as_i32(), 3);
        assert_eq!(CHUNKcode::BadEncoding.as_i32(), 4);
        assert_eq!(CHUNKcode::OutOfMemory.as_i32(), 5);
        assert_eq!(CHUNKcode::PassthruError.as_i32(), 6);
    }

    #[test]
    fn chunkcode_strerror_text_preserved() {
        // Exact strings from `Curl_chunked_strerror`.
        assert_eq!(CHUNKcode::Ok.strerror(), "OK");
        assert_eq!(
            CHUNKcode::TooLongHex.strerror(),
            "Too long hexadecimal number"
        );
        assert_eq!(
            CHUNKcode::IllegalHex.strerror(),
            "Illegal or missing hexadecimal sequence"
        );
        assert_eq!(CHUNKcode::BadChunk.strerror(), "Malformed encoding found");
        assert_eq!(
            CHUNKcode::PassthruError.strerror(),
            "Error writing data to client"
        );
        assert_eq!(
            CHUNKcode::BadEncoding.strerror(),
            "Bad content-encoding found"
        );
        assert_eq!(CHUNKcode::OutOfMemory.strerror(), "Out of memory");
    }

    #[test]
    fn decode_single_chunk() {
        let (body, consumed, ch) = decode_body(b"5\r\nhello\r\n0\r\n\r\n");
        assert_eq!(body, b"hello");
        assert_eq!(consumed, b"5\r\nhello\r\n0\r\n\r\n".len());
        assert_eq!(ch.state, ChunkyState::Done);
        assert!(ch.is_done());
        assert_eq!(ch.datasize, 0); // no leftover bytes
    }

    #[test]
    fn decode_multi_chunk() {
        // Two data chunks then the terminator.
        let input = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (body, consumed, ch) = decode_body(input);
        assert_eq!(body, b"hello world");
        assert_eq!(consumed, input.len());
        assert!(ch.is_done());
    }

    #[test]
    fn decode_reports_leftover_bytes() {
        // Bytes trailing the terminating chunk are reported via `datasize`, not consumed
        // into the body.
        let input = b"5\r\nhello\r\n0\r\n\r\nEXTRA";
        let (body, consumed, ch) = decode_body(input);
        assert_eq!(body, b"hello");
        assert!(ch.is_done());
        assert_eq!(ch.datasize, b"EXTRA".len() as u64);
        // Consumed stops right after the final LF of the terminator.
        assert_eq!(consumed, input.len() - b"EXTRA".len());
    }

    #[test]
    fn decode_chunk_extension_after_size_is_ignored() {
        // A chunk-extension after the size (";ext=1") is consumed and ignored in CHUNK_LF.
        let input = b"5;ext=1\r\nhello\r\n0\r\n\r\n";
        let (body, _consumed, ch) = decode_body(input);
        assert_eq!(body, b"hello");
        assert!(ch.is_done());
    }

    #[test]
    fn decode_uppercase_and_multidigit_hex_size() {
        // "1F" == 31 bytes; uppercase hex must be accepted.
        let payload = vec![b'x'; 0x1f];
        let mut input = Vec::new();
        input.extend_from_slice(b"1F\r\n");
        input.extend_from_slice(&payload);
        input.extend_from_slice(b"\r\n0\r\n\r\n");
        let (body, _consumed, ch) = decode_body(&input);
        assert_eq!(body, payload);
        assert!(ch.is_done());
    }

    #[test]
    fn decode_trailer_headers_are_broadcast() {
        // Two trailer headers, then the empty line terminates the stream.
        let input = b"5\r\nhello\r\n0\r\nX-A: 1\r\nX-B: 2\r\n\r\n";
        let mut ch = Chunker::new(false);
        let mut cap = Capture::default();
        let consumed = ch.read_with(input, &mut cap).expect("decode ok");
        assert_eq!(cap.body, b"hello");
        assert_eq!(consumed, input.len());
        assert!(ch.is_done());
        // Each trailer line is broadcast with its terminating CRLF appended.
        assert_eq!(cap.trailers.len(), 2);
        assert_eq!(cap.trailers[0], b"X-A: 1\r\n");
        assert_eq!(cap.trailers[1], b"X-B: 2\r\n");
    }

    #[test]
    fn decode_empty_trailer_terminates_cleanly() {
        // "0\r\n\r\n": immediate CRLF after the last chunk means no trailers.
        let input = b"0\r\n\r\n";
        let mut ch = Chunker::new(false);
        let mut cap = Capture::default();
        ch.read_with(input, &mut cap).expect("decode ok");
        assert!(ch.is_done());
        assert!(cap.body.is_empty());
        assert!(cap.trailers.is_empty());
    }

    #[test]
    fn decode_tolerates_missing_cr_before_lf_in_postlf() {
        // After a chunk's data, curl tolerates a bare LF (missing CR) before the next size.
        let input = b"5\r\nhello\n0\r\n\r\n"; // note: "hello\n" not "hello\r\n"
        let (body, _consumed, ch) = decode_body(input);
        assert_eq!(body, b"hello");
        assert!(ch.is_done());
    }

    #[test]
    fn decode_trailer_line_ending_in_bare_lf() {
        // A trailer line terminated by a bare LF (no CR) must still be handled.
        let input = b"0\r\nX-A: 1\n\r\n";
        let mut ch = Chunker::new(false);
        let mut cap = Capture::default();
        ch.read_with(input, &mut cap).expect("decode ok");
        assert!(ch.is_done());
        assert_eq!(cap.trailers.len(), 1);
        assert_eq!(cap.trailers[0], b"X-A: 1\r\n");
    }

    #[test]
    fn decode_oversized_hex_is_rejected() {
        // 17 hex digits exceeds CHUNK_MAXNUM_LEN (16) → CHUNKE_TOO_LONG_HEX.
        let input = b"00000000000000000\r\n"; // 17 zeros
        let mut ch = Chunker::new(false);
        let err = ch
            .read(input, &mut |_b: &[u8]| Ok(()))
            .expect_err("must reject oversized hex");
        assert_eq!(err.code(), CurlCode::RecvError);
        assert_eq!(ch.state, ChunkyState::Failed);
        assert_eq!(ch.last_code, CHUNKcode::TooLongHex);
    }

    #[test]
    fn decode_hex_overflow_is_illegal() {
        // 16 digits but value > CURL_OFF_T_MAX (i64::MAX) → CHUNKE_ILLEGAL_HEX.
        let input = b"8000000000000000\r\n"; // = i64::MAX + 1
        let mut ch = Chunker::new(false);
        let err = ch
            .read(input, &mut |_b: &[u8]| Ok(()))
            .expect_err("must reject overflowing size");
        assert_eq!(err.code(), CurlCode::RecvError);
        assert_eq!(ch.last_code, CHUNKcode::IllegalHex);
    }

    #[test]
    fn decode_max_offt_size_is_accepted() {
        // Exactly i64::MAX must parse (boundary), then we can stop at the data state.
        let input = b"7fffffffffffffff\r\n";
        let mut ch = Chunker::new(false);
        // Only the size line is present; decoding consumes it and waits for data.
        ch.read(input, &mut |_b: &[u8]| Ok(())).expect("size ok");
        assert_eq!(ch.datasize, i64::MAX as u64);
        assert_eq!(ch.state, ChunkyState::Data);
    }

    #[test]
    fn decode_illegal_hex_char_is_rejected() {
        // A non-hex byte where a hex digit is required, with nothing buffered yet.
        let input = b"Z\r\n";
        let mut ch = Chunker::new(false);
        let err = ch
            .read(input, &mut |_b: &[u8]| Ok(()))
            .expect_err("must reject junk");
        assert_eq!(err.code(), CurlCode::RecvError);
        assert_eq!(ch.last_code, CHUNKcode::IllegalHex);
        assert_eq!(ch.state, ChunkyState::Failed);
    }

    #[test]
    fn decode_ignore_body_parses_but_suppresses_output() {
        let input = b"5\r\nhello\r\n0\r\n\r\n";
        let mut ch = Chunker::new(true); // ignore_body = true
        let mut wrote = 0usize;
        ch.read(input, &mut |b: &[u8]| {
            wrote += b.len();
            Ok(())
        })
        .expect("decode ok");
        assert_eq!(wrote, 0); // body suppressed
        assert!(ch.is_done()); // stream still fully parsed
    }

    #[test]
    fn decode_incremental_across_call_boundaries() {
        // Feed the stream one byte at a time using the realistic streaming pattern: append a
        // byte to a pending buffer, decode the whole pending buffer, then drop the consumed
        // prefix and keep the unconsumed tail. State must persist across calls and the body
        // must reassemble identically to a single-shot decode. This exercises the states
        // that consume zero bytes on a transition (e.g. HEX→LF, TRAILER→TRAILER_POSTCR).
        let input = b"3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n";
        let mut ch = Chunker::new(false);
        let mut body = Vec::new();
        let mut pending: Vec<u8> = Vec::new();
        for &byte in input.iter() {
            pending.push(byte);
            let consumed = ch
                .read(&pending, &mut |b: &[u8]| {
                    body.extend_from_slice(b);
                    Ok(())
                })
                .expect("decode ok");
            pending.drain(0..consumed);
            if ch.is_done() {
                break;
            }
        }
        assert_eq!(body, b"abcdef");
        assert!(ch.is_done());
        assert!(pending.is_empty(), "no bytes should be left unconsumed");
    }

    #[test]
    fn decode_terminal_states_are_stable() {
        // Once DONE, further reads consume nothing and stay DONE.
        let (_body, _consumed, mut ch) = decode_body(b"1\r\nx\r\n0\r\n\r\n");
        assert!(ch.is_done());
        let n = ch
            .read(b"garbage", &mut |_b: &[u8]| Ok(()))
            .expect("done ok");
        assert_eq!(n, 0);
        assert!(ch.is_done());

        // Once FAILED, reads return a recv error.
        let mut failed = Chunker::new(false);
        let _ = failed.read(b"Z", &mut |_b: &[u8]| Ok(()));
        assert_eq!(failed.state, ChunkyState::Failed);
        let err = failed
            .read(b"x", &mut |_b: &[u8]| Ok(()))
            .expect_err("failed stays failed");
        assert_eq!(err.code(), CurlCode::RecvError);
    }

    #[test]
    fn writer_passes_through_non_body_and_decodes_body() {
        let mut w = ChunkedWriter::new();
        let mut cap = Capture::default();

        // A non-body (header) write flows through unchanged.
        w.write(false, false, false, b"Header: v\r\n", &mut cap)
            .expect("header ok");
        assert_eq!(cap.passthrough, b"Header: v\r\n");
        assert!(!w.download_done);

        // The body write is de-chunked, and completion sets download_done.
        w.write(true, false, false, b"5\r\nhello\r\n0\r\n\r\n", &mut cap)
            .expect("body ok");
        assert_eq!(cap.body, b"hello");
        assert!(w.is_done());
        assert!(w.download_done);
        w.close();
    }

    #[test]
    fn writer_premature_eos_is_partial_file() {
        let mut w = ChunkedWriter::new();
        let mut cap = Capture::default();
        // A partial stream with EOS set and a body expected → CURLE_PARTIAL_FILE.
        let err = w
            .write(true, true, false, b"5\r\nhel", &mut cap)
            .expect_err("premature eos");
        assert_eq!(err.code(), CurlCode::PartialFile);
    }

    #[test]
    fn writer_error_message_mentions_chunked_encoding() {
        let mut w = ChunkedWriter::new();
        let mut cap = Capture::default();
        let err = w
            .write(true, false, false, b"Z\r\n", &mut cap)
            .expect_err("bad hex");
        assert_eq!(err.code(), CurlCode::RecvError);
        // Reference wraps as "<reason> in chunked-encoding".
        assert!(err.to_string().contains("in chunked-encoding"));
    }

    #[test]
    fn encode_byte_exact_framing() {
        // Single push + finish yields exactly the reference framing.
        let mut enc = ChunkedEncoder::new();
        enc.push(b"hello");
        enc.finish();
        assert_eq!(&enc.take()[..], b"5\r\nhello\r\n0\r\n\r\n");
    }

    #[test]
    fn encode_multi_push_framing() {
        let mut enc = ChunkedEncoder::new();
        enc.push(b"hello");
        enc.push(b" world"); // 6 bytes → "6\r\n world\r\n"
        enc.finish();
        assert_eq!(&enc.take()[..], b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    }

    #[test]
    fn encode_empty_push_emits_nothing() {
        let mut enc = ChunkedEncoder::new();
        enc.push(b""); // no chunk emitted for empty data
        enc.finish();
        assert_eq!(&enc.take()[..], b"0\r\n\r\n");
    }

    #[test]
    fn encode_hex_size_uses_lowercase() {
        // 255 bytes → size line "ff\r\n" (lowercase, no leading zeros).
        let data = vec![b'a'; 255];
        let mut enc = ChunkedEncoder::new();
        enc.push(&data);
        enc.finish();
        let out = enc.take();
        assert!(out.starts_with(b"ff\r\n"));
        assert!(out.ends_with(b"\r\n0\r\n\r\n"));
    }

    #[test]
    fn encode_with_trailers_frames_last_chunk() {
        let mut enc =
            ChunkedEncoder::with_trailers(vec!["X-A: 1".to_string(), "X-B: 2".to_string()]);
        enc.push(b"hi");
        enc.finish();
        assert_eq!(&enc.take()[..], b"2\r\nhi\r\n0\r\nX-A: 1\r\nX-B: 2\r\n\r\n");
    }

    #[test]
    fn encode_skips_malformed_trailers() {
        // "BadTrailer" has no ':' + space, so it is skipped; the valid one is kept.
        let mut enc = ChunkedEncoder::with_trailers(vec![
            "BadTrailer".to_string(),
            "X-Ok: yes".to_string(),
            "NoSpace:x".to_string(),
        ]);
        enc.finish();
        assert_eq!(&enc.take()[..], b"0\r\nX-Ok: yes\r\n\r\n");
    }

    #[test]
    fn encode_finish_is_idempotent() {
        let mut enc = ChunkedEncoder::new();
        enc.push(b"x");
        enc.finish();
        enc.finish(); // second call must not append a second terminator
        assert_eq!(&enc.take()[..], b"1\r\nx\r\n0\r\n\r\n");
    }

    #[test]
    fn encode_total_length_is_unknown() {
        let enc = ChunkedEncoder::new();
        assert_eq!(enc.total_length(), None);
    }

    #[test]
    fn add_reader_returns_fresh_encoder() {
        let mut enc = add_reader();
        enc.push(b"z");
        enc.finish();
        assert_eq!(&enc.take()[..], b"1\r\nz\r\n0\r\n\r\n");
    }

    #[test]
    fn encode_pull_read_frames_from_source() {
        // A source that yields "abcdef" once, then EOF.
        let mut enc = ChunkedEncoder::new();
        let payload = b"abcdef";
        let mut yielded = false;
        let mut src = |dst: &mut [u8]| -> Result<(usize, bool)> {
            if yielded {
                return Ok((0, true)); // EOF
            }
            let n = payload.len().min(dst.len());
            dst[..n].copy_from_slice(&payload[..n]);
            yielded = true;
            Ok((n, true)) // data + EOF in one shot
        };

        let mut framed = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let (n, eos) = enc.read(&mut src, &mut buf).expect("pull ok");
            framed.extend_from_slice(&buf[..n]);
            if eos {
                break;
            }
        }
        assert_eq!(framed, b"6\r\nabcdef\r\n0\r\n\r\n");
    }

    #[test]
    fn round_trip_encode_then_decode_is_identity() {
        // The core parity property: encode arbitrary data, decode it back, get the original.
        for payload in [
            &b""[..],
            &b"a"[..],
            &b"hello world"[..],
            &vec![0u8; 5000][..],
            &(0u8..=255).collect::<Vec<u8>>()[..],
        ] {
            let mut enc = ChunkedEncoder::new();
            enc.push(payload);
            enc.finish();
            let framed = enc.take();

            let (decoded, _consumed, ch) = decode_body(&framed);
            assert!(
                ch.is_done(),
                "stream should complete for len {}",
                payload.len()
            );
            assert_eq!(
                decoded,
                payload,
                "round-trip mismatch for len {}",
                payload.len()
            );
        }
    }

    #[test]
    fn round_trip_multi_chunk_encode_then_decode() {
        let mut enc = ChunkedEncoder::new();
        enc.push(b"first ");
        enc.push(b"second ");
        enc.push(b"third");
        enc.finish();
        let framed = enc.take();
        let (decoded, _consumed, ch) = decode_body(&framed);
        assert!(ch.is_done());
        assert_eq!(decoded, b"first second third");
    }
}
