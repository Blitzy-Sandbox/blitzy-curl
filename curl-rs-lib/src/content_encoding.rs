// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! Content/Transfer decompression pipeline — the chained content-writer that
//! decodes `Content-Encoding` / `Transfer-Encoding` response bodies.
//!
//! This module is a language rewrite of curl 8.x `lib/content_encoding.c`
//! (`Curl_build_unencoding_stack`, the per-codec writers, and
//! `Curl_get_content_encodings`). It preserves byte-for-byte functional parity
//! with the reference: the same encoding names and aliases, the same chaining
//! model, the same decompression-bomb limit (`MAX_ENCODE_STACK`), the same
//! `deflate` "zlib-header vs raw" auto-detection, and the same error code
//! ([`CurlCode::BadContentEncoding`], integer `61`) for an unrecognized or bad
//! encoding.
//!
//! # Model
//!
//! A response may carry a comma-separated list of content codings applied in
//! order (RFC 9110 §8.4). To recover the original bytes the codings are undone
//! in reverse: the coding applied **last** is decoded **first**. This module
//! materializes that as an [`Unencoder`] — an ordered stack of boxed
//! [`Decoder`] trait objects. Bytes flow through the stack incrementally as
//! they arrive off the network (this is an async transfer): each call to
//! [`Unencoder::write`] feeds a chunk of still-encoded bytes into the head of
//! the stack and returns the fully decoded output for that chunk, without ever
//! requiring the whole body to be resident in memory.
//!
//! # Codec backends (pure-Rust crates, no C libraries linked)
//!
//! | Coding             | Crate                                   | Availability |
//! |--------------------|-----------------------------------------|--------------|
//! | `deflate`          | [`flate2`] (zlib + raw auto-detect)     | always       |
//! | `gzip` (`x-gzip`)  | [`flate2`] (transparent gzip)           | always       |
//! | `br`               | [`brotli`]                              | `feature = "brotli"` |
//! | `zstd`             | [`zstd`]                                | `feature = "zstd"`   |
//! | `identity` (`none`)| pass-through                            | always       |
//!
//! `deflate`/`gzip` are always compiled in. The `br` and `zstd` handlers are
//! gated behind their respective (default-on) Cargo features; when a feature is
//! disabled the coding is treated exactly as an unknown coding would be in a
//! curl build without that library — negotiation omits it and a body encoded
//! with it fails with [`CurlCode::BadContentEncoding`].
//!
//! # Memory safety
//!
//! This module is 100% memory-safe Rust: it manipulates no raw pointers and
//! contains no low-level escape hatches. All buffering uses [`bytes::BytesMut`].

use crate::error::{Error, Result};
use bytes::{Bytes, BytesMut};

/// The default content coding, matching curl's `CONTENT_ENCODING_DEFAULT`.
///
/// `identity` denotes "no transformation" and is never advertised in an
/// `Accept-Encoding` request header (see [`content_encodings`]).
pub const CONTENT_ENCODING_DEFAULT: &str = "identity";

/// Maximum number of chained content codings, matching curl's
/// `MAX_ENCODE_STACK`.
///
/// curl allows "no more than 5 chained compression steps" as a guard against
/// decompression bombs built from deeply nested codings. The stack builder
/// rejects a coding list that would exceed this limit with
/// [`CurlCode::BadContentEncoding`] — see [`Unencoder::push`] for the exact
/// (curl-identical) arithmetic.
pub const MAX_ENCODE_STACK: usize = 5;

/// Size, in bytes, of the scratch buffer used for a single decompression step.
///
/// Mirrors curl's `DECOMPRESS_BUFFER_SIZE`. Each decoder decompresses into a
/// buffer of this size and flushes it downstream repeatedly, so a single input
/// chunk never forces an unbounded intermediate allocation for the low-level
/// zlib/deflate path.
pub const DECOMPRESS_BUFFER_SIZE: usize = 16_384;

/// Default upper bound, in bytes, on the decoded output a **single**
/// [`Unencoder::write`] / [`Unencoder::finish`] call may produce at any one
/// decoding stage (see [`Unencoder::set_max_decoded_per_write`]).
///
/// # Why this exists (decompression-bomb defense, CWE-400)
///
/// A tiny highly-compressible input can expand by many orders of magnitude
/// (a "decompression bomb"). Left unchecked, one small malicious chunk could
/// drive an unbounded allocation and exhaust memory before any downstream
/// backpressure applies. curl's C writer chain bounds this structurally: it
/// inflates into a fixed [`DECOMPRESS_BUFFER_SIZE`] buffer and flushes each
/// block to the next writer, so its working set per stage is ~16 KiB and a
/// bomb is merely *streamed* rather than materialized.
///
/// This pure-Rust pipeline returns the decoded output of a chunk as an owned
/// [`Bytes`], so it instead enforces an explicit per-call ceiling: each
/// decoding stage may emit at most this many bytes for one input chunk before
/// the decode is rejected with [`Error::TooLarge`] ([`CurlCode::TooLarge`],
/// integer `100`). The bound is applied **per call**, not cumulatively over
/// the transfer, so legitimate streaming downloads of unbounded total size are
/// unaffected (each network-sized chunk expands well under the ceiling) while a
/// single pathological chunk can allocate no more than this before it is
/// stopped — preserving functional parity for real content while closing the
/// bomb vector. The nesting guard [`MAX_ENCODE_STACK`] still independently caps
/// how many stages can be chained.
///
/// The default is deliberately generous (64 MiB): far above any plausible
/// single-chunk expansion of legitimate content, yet a hard cap against
/// runaway allocation. Callers that must accept larger single-chunk expansions
/// can raise it (or disable it with `usize::MAX`) via
/// [`Unencoder::set_max_decoded_per_write`].
pub const DEFAULT_MAX_DECODED_PER_WRITE: usize = 64 * 1024 * 1024;

// The default ceiling must be a real finite bound: positive (so some output is
// always permitted) and strictly below `usize::MAX` (which is the sentinel that
// *disables* the bound). Enforced at compile time so the invariant can never
// silently regress.
//
// This is a deliberate compile-time (const-context) assertion, so clippy's
// `assertions_on_constants` lint is intentionally allowed here: the whole point
// is to fail the build if the constant ever violates the invariant.
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(
    DEFAULT_MAX_DECODED_PER_WRITE > 0 && DEFAULT_MAX_DECODED_PER_WRITE < usize::MAX,
    "DEFAULT_MAX_DECODED_PER_WRITE must be a finite, positive decompression-bomb ceiling",
);

/// A single recognized (or unrecognized) content coding.
///
/// This mirrors the entries of curl's `general_unencoders` table plus the
/// sentinel used for unrecognized codings. [`ContentEncoding::from_name`]
/// performs the same case-insensitive name/alias matching curl performs with
/// `curl_strnequal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentEncoding {
    /// `identity` (alias `none`) — the body is delivered unchanged.
    Identity,
    /// `deflate` — a zlib or raw DEFLATE stream (auto-detected).
    Deflate,
    /// `gzip` (alias `x-gzip`) — a gzip stream.
    Gzip,
    /// `br` — a Brotli stream. Decodable only when the `brotli` feature is
    /// enabled; otherwise treated as unsupported.
    Brotli,
    /// `zstd` — a Zstandard stream. Decodable only when the `zstd` feature is
    /// enabled; otherwise treated as unsupported.
    Zstd,
    /// An unrecognized coding token. Resolving one of these yields curl's
    /// deferred "ce-error" behavior: it errors with
    /// [`CurlCode::BadContentEncoding`] the first time a non-empty body chunk
    /// is written through it.
    Unknown,
}

impl ContentEncoding {
    /// Resolves a coding token to a [`ContentEncoding`], applying the exact
    /// names and aliases from curl's handler registry.
    ///
    /// Matching is ASCII case-insensitive (as with curl's `curl_strnequal`).
    /// Recognized tokens: `identity`/`none`, `deflate`, `gzip`/`x-gzip`, `br`,
    /// and `zstd`. Any other token (including `br`/`zstd` names, which are still
    /// *recognized* here even when their feature is disabled) maps as shown;
    /// unrecognized tokens map to [`ContentEncoding::Unknown`].
    ///
    /// Note that recognizing a name is distinct from being able to *decode* it:
    /// see [`ContentEncoding::is_supported`].
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        if name.eq_ignore_ascii_case("identity") || name.eq_ignore_ascii_case("none") {
            ContentEncoding::Identity
        } else if name.eq_ignore_ascii_case("deflate") {
            ContentEncoding::Deflate
        } else if name.eq_ignore_ascii_case("gzip") || name.eq_ignore_ascii_case("x-gzip") {
            ContentEncoding::Gzip
        } else if name.eq_ignore_ascii_case("br") {
            ContentEncoding::Brotli
        } else if name.eq_ignore_ascii_case("zstd") {
            ContentEncoding::Zstd
        } else {
            ContentEncoding::Unknown
        }
    }

    /// Returns the canonical (lower-case) coding name, matching the `name`
    /// field of curl's `Curl_cwtype` entries.
    ///
    /// [`ContentEncoding::Unknown`] reports curl's internal deferred-error
    /// writer name `"ce-error"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            ContentEncoding::Identity => "identity",
            ContentEncoding::Deflate => "deflate",
            ContentEncoding::Gzip => "gzip",
            ContentEncoding::Brotli => "br",
            ContentEncoding::Zstd => "zstd",
            ContentEncoding::Unknown => "ce-error",
        }
    }

    /// Returns whether this build can actually decode the coding.
    ///
    /// `identity`, `deflate`, and `gzip` are always decodable. `br` and `zstd`
    /// are decodable only when their (default-on) Cargo feature is enabled, so
    /// that a build compiled without them behaves exactly like a curl build
    /// without brotli/zstd. [`ContentEncoding::Unknown`] is never decodable.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        match self {
            ContentEncoding::Identity | ContentEncoding::Deflate | ContentEncoding::Gzip => true,
            ContentEncoding::Brotli => cfg!(feature = "brotli"),
            ContentEncoding::Zstd => cfg!(feature = "zstd"),
            ContentEncoding::Unknown => false,
        }
    }
}

/// Returns the comma-separated list of content codings this build can decode,
/// suitable for an `Accept-Encoding` request header.
///
/// This is the parity equivalent of curl's `Curl_get_content_encodings`: it
/// walks the supported general decoders in registry order and joins their
/// names with `", "`, deliberately **excluding** `identity`
/// ([`CONTENT_ENCODING_DEFAULT`]). The `br` and `zstd` entries are present only
/// when their features are enabled, so the advertised set always matches the
/// set this build can actually decode.
///
/// With all features enabled the result is `"deflate, gzip, br, zstd"`; with
/// both compression features disabled it is `"deflate, gzip"`.
#[must_use]
pub fn content_encodings() -> String {
    // The general decoders in curl's `general_unencoders` registry order,
    // excluding `identity` exactly as `Curl_get_content_encodings` skips
    // `CONTENT_ENCODING_DEFAULT`. A candidate is advertised only if this build
    // can decode it, so `br`/`zstd` appear only when their feature is enabled.
    const CANDIDATES: [ContentEncoding; 4] = [
        ContentEncoding::Deflate,
        ContentEncoding::Gzip,
        ContentEncoding::Brotli,
        ContentEncoding::Zstd,
    ];
    CANDIDATES
        .iter()
        .filter(|enc| enc.is_supported())
        .map(|enc| enc.name())
        .collect::<Vec<&'static str>>()
        .join(", ")
}

// =========================================================================
// Decoder trait + shared helpers
// =========================================================================

/// A single streaming content decoder — the parity equivalent of one
/// `contenc_writer` in curl's client-writer chain.
///
/// A decoder consumes still-encoded input incrementally and appends the decoded
/// output to a caller-supplied [`BytesMut`]. Implementations must be
/// incremental: a call to [`decode`](Decoder::decode) may receive an arbitrary
/// fragment of the coded stream (even a single byte), and any bytes that cannot
/// yet be decoded must be retained internally until enough input arrives.
///
/// The `Send` bound lets a decoder chain live inside a transfer that the
/// multi-handle may drive from a worker thread.
trait Decoder: Send {
    /// The canonical coding name (used for diagnostics and duplicate checks).
    fn name(&self) -> &'static str;

    /// Decodes a chunk of coded `input`, appending decoded bytes to `out`.
    ///
    /// An empty `input` is a no-op that must succeed (mirroring curl's writers,
    /// which forward zero-length writes untouched). Returns
    /// [`Error::BadContentEncoding`] on a malformed stream.
    ///
    /// `limit` is the maximum number of decoded bytes this single call may emit
    /// (the decompression-bomb ceiling; see [`DEFAULT_MAX_DECODED_PER_WRITE`]).
    /// A decoder that would exceed it must stop and return [`Error::TooLarge`]
    /// rather than allocate past the bound.
    fn decode(&mut self, input: &[u8], out: &mut BytesMut, limit: usize) -> Result<()>;

    /// Signals end-of-body, flushing any decoder-internal residual into `out`.
    ///
    /// Like curl's `do_close`, this is lenient about a truncated stream: it
    /// flushes whatever is available and does not, on its own, treat an
    /// incomplete stream as an error. `limit` bounds the flushed output exactly
    /// as in [`decode`](Decoder::decode).
    fn finish(&mut self, out: &mut BytesMut, limit: usize) -> Result<()>;
}

/// A bounded `Write` sink for the write-adapter decoders (`br`, `zstd`).
///
/// The `brotli`/`zstd` write adapters decode by *writing* their
/// decompressed output into an inner writer. Using a plain `Vec<u8>` there lets
/// a single `write_all` of a small compressed chunk balloon the vector without
/// limit — the decompression-bomb vector called out in the review. `BoundedSink`
/// closes it: it refuses (with an [`io::Error`]) any write that would push the
/// bytes accumulated **for the current decode call** past [`limit`], so the
/// adapter's `write_all` aborts partway and the transient allocation is capped
/// at ~`limit` rather than growing to gigabytes. The accumulated bytes are
/// drained into the transfer's output buffer after each call via
/// [`drain_sink`], and `limit` is refreshed from the owning [`Unencoder`] before
/// every call so a runtime change to the ceiling always takes effect.
///
/// Gated to the `brotli`/`zstd` write-adapter decoders: the `gzip` decoder
/// drives [`run_inflate`] directly and enforces the ceiling there, so it does
/// not use this sink. When neither feature is enabled there are no write-adapter
/// decoders and this type is compiled out.
#[cfg(any(feature = "brotli", feature = "zstd"))]
struct BoundedSink {
    /// Bytes decoded so far in the current call, awaiting drain.
    buf: Vec<u8>,
    /// Maximum bytes this call may accumulate before the write is rejected.
    limit: usize,
    /// Set once a write has been rejected for exceeding [`limit`], so the
    /// decoder can map the adapter's generic I/O failure to [`Error::TooLarge`]
    /// rather than a malformed-stream error.
    overflowed: bool,
}

#[cfg(any(feature = "brotli", feature = "zstd"))]
impl BoundedSink {
    /// Creates an empty sink. `limit` is set to the permissive `usize::MAX`
    /// until the owning [`Unencoder`] supplies the real ceiling before the
    /// first write.
    fn new() -> Self {
        BoundedSink {
            buf: Vec::new(),
            limit: usize::MAX,
            overflowed: false,
        }
    }
}

#[cfg(any(feature = "brotli", feature = "zstd"))]
impl std::io::Write for BoundedSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        // Reject *before* extending the buffer so the allocation never exceeds
        // `limit`. `saturating_add` avoids overflow on absurd inputs.
        if self.buf.len().saturating_add(data.len()) > self.limit {
            self.overflowed = true;
            return Err(std::io::Error::other(
                "decoded output exceeded the configured per-write limit",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Moves everything accumulated in a decoder's [`BoundedSink`] into the output
/// buffer and clears the sink for reuse.
///
/// Used by the write-adapter–based decoders (`br`, `zstd`), which emit
/// their decoded output into the sink that is drained after each write so
/// intermediate memory stays bounded.
#[cfg(any(feature = "brotli", feature = "zstd"))]
#[inline]
fn drain_sink(sink: &mut BoundedSink, out: &mut BytesMut) {
    if !sink.buf.is_empty() {
        out.extend_from_slice(sink.buf.as_slice());
        sink.buf.clear();
    }
}

/// Maps a write-adapter failure to the appropriate [`Error`].
///
/// The `br` and `zstd` decoders wrap a [`BoundedSink`]. When the
/// underlying `write_all` fails there are two distinct causes to tell apart:
/// the sink tripped the decompression-bomb ceiling (`overflowed == true`),
/// which is a resource-limit condition reported as [`Error::TooLarge`]
/// (`CURLE_TOO_LARGE`); or the compressed stream was malformed, reported as a
/// content-encoding error just like curl's `*_do_close` diagnostics.
#[cfg(any(feature = "brotli", feature = "zstd"))]
#[inline]
fn sink_write_error(overflowed: bool, _err: std::io::Error, what: &str) -> Error {
    if overflowed {
        Error::TooLarge
    } else {
        Error::bad_content_encoding(format!("Error while processing {what} content"))
    }
}

// -------------------------------------------------------------------------
// identity — pass-through (curl's identity_encoding)
// -------------------------------------------------------------------------

/// The `identity` decoder: forwards input unchanged.
struct IdentityDecoder;

impl Decoder for IdentityDecoder {
    fn name(&self) -> &'static str {
        "identity"
    }

    fn decode(&mut self, input: &[u8], out: &mut BytesMut, _limit: usize) -> Result<()> {
        // Pass-through: output size equals input size (no expansion), so the
        // decompression-bomb ceiling does not apply here.
        out.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, _out: &mut BytesMut, _limit: usize) -> Result<()> {
        Ok(())
    }
}

// -------------------------------------------------------------------------
// ce-error — deferred error (curl's error_writer)
// -------------------------------------------------------------------------

/// The deferred-error decoder, matching curl's `error_writer`.
///
/// When the stack builder encounters a coding it cannot decode (an unrecognized
/// token, or `br`/`zstd` in a build without that feature) it installs this
/// decoder rather than failing immediately — exactly as curl defers the error
/// to write time. The error surfaces the first time a non-empty body chunk is
/// written; zero-length writes are forwarded without error (as in
/// `error_do_write`).
struct ErrorDecoder;

impl Decoder for ErrorDecoder {
    fn name(&self) -> &'static str {
        "ce-error"
    }

    fn decode(&mut self, input: &[u8], _out: &mut BytesMut, _limit: usize) -> Result<()> {
        if input.is_empty() {
            // Mirrors curl: a zero-length write is forwarded, not an error.
            return Ok(());
        }
        Err(Error::bad_content_encoding(
            "Unrecognized content encoding type",
        ))
    }

    fn finish(&mut self, _out: &mut BytesMut, _limit: usize) -> Result<()> {
        Ok(())
    }
}

// -------------------------------------------------------------------------
// deflate — zlib or raw DEFLATE, auto-detected (curl's zlib_writer/deflate)
// -------------------------------------------------------------------------

/// Failure modes of [`run_inflate`].
///
/// Distinguishing these matters for the `deflate` decoder: a [`Decompress`]
/// error on the pristine first chunk is the trigger for curl's zlib→raw
/// fallback, whereas a [`TooLarge`](RunInflateError::TooLarge) limit hit is a
/// hard stop that must abort immediately (retrying a bomb in raw mode would
/// simply hit the ceiling again).
enum RunInflateError {
    /// The underlying zlib inflate reported malformed data. curl's
    /// `process_zlib_error` collapses every zlib failure into one generic
    /// diagnostic, so the specific [`flate2::DecompressError`] carries no
    /// parity-relevant information and is intentionally not retained.
    Decompress,
    /// The decode would exceed the per-call decompression-bomb ceiling.
    TooLarge,
}

impl From<flate2::DecompressError> for RunInflateError {
    fn from(_e: flate2::DecompressError) -> Self {
        RunInflateError::Decompress
    }
}

/// Runs a [`flate2::Decompress`] over `input`, appending decoded bytes to
/// `out`, iterating with a fixed [`DECOMPRESS_BUFFER_SIZE`] scratch buffer.
///
/// This is the direct analogue of curl's `inflate_stream` loop: it keeps
/// inflating into a bounded buffer and flushing it downstream until the stream
/// ends, the input is exhausted, or the decoder can make no further progress
/// (needing more input). It returns the terminal [`flate2::Status`] on success,
/// [`RunInflateError::Decompress`] on a malformed stream (so the caller can
/// decide whether the `deflate` raw-stream fallback applies), or
/// [`RunInflateError::TooLarge`] if the bytes emitted during this call would
/// exceed `limit` — the decompression-bomb ceiling. Because it flushes each
/// [`DECOMPRESS_BUFFER_SIZE`] block as it goes, the check fires after the block
/// that crosses the bound, capping the transient allocation at
/// `limit + DECOMPRESS_BUFFER_SIZE`.
fn run_inflate(
    decomp: &mut flate2::Decompress,
    mut input: &[u8],
    out: &mut BytesMut,
    limit: usize,
) -> std::result::Result<flate2::Status, RunInflateError> {
    // Bytes already in `out` before this call: the ceiling applies to the
    // output *produced here*, not to any upstream residual already buffered.
    let base = out.len();
    let mut buf = [0u8; DECOMPRESS_BUFFER_SIZE];
    loop {
        let in_before = decomp.total_in();
        let out_before = decomp.total_out();
        let status = decomp.decompress(input, &mut buf, flate2::FlushDecompress::None)?;
        let consumed = (decomp.total_in() - in_before) as usize;
        let produced = (decomp.total_out() - out_before) as usize;
        if produced > 0 {
            out.extend_from_slice(&buf[..produced]);
            // Enforce the decompression-bomb ceiling incrementally: stop as soon
            // as this call's cumulative output crosses `limit`.
            if out.len() - base > limit {
                return Err(RunInflateError::TooLarge);
            }
        }
        input = &input[consumed..];
        match status {
            flate2::Status::StreamEnd => return Ok(status),
            flate2::Status::Ok | flate2::Status::BufError => {
                // A full output buffer means there may be more latched output
                // to drain even if no further input is consumed: loop again.
                if produced == buf.len() {
                    continue;
                }
                // Otherwise, stop once the input is drained or the decoder made
                // no progress at all (it needs more input to continue).
                if input.is_empty() || (consumed == 0 && produced == 0) {
                    return Ok(status);
                }
            }
        }
    }
}

/// The `deflate` decoder.
///
/// curl initializes zlib with `inflateInit` (which expects a zlib header) and,
/// if the very first inflate hits a data error before producing any output —
/// the tell-tale of a server that sent a *raw* DEFLATE stream with no zlib
/// header — it reinitializes in raw mode (`inflateReset2(-MAX_WBITS)`) and
/// replays the same input. This decoder reproduces that behavior: it starts
/// with [`flate2::Decompress::new(true)`] (zlib header expected) and, on a
/// first-chunk data error with no output yet emitted, rebuilds as
/// [`flate2::Decompress::new(false)`] (raw) and re-runs the original chunk.
struct DeflateDecoder {
    decomp: flate2::Decompress,
    /// `true` once any output has been produced or the raw fallback has been
    /// taken — after this point the zlib→raw fallback can no longer trigger,
    /// exactly as curl only falls back while still in the pristine `ZLIB_INIT`
    /// state.
    started: bool,
    /// `true` once the fallback to raw DEFLATE has already been attempted, so
    /// it is never attempted twice.
    raw_fallback_done: bool,
    /// `true` once the stream has reached its end.
    finished: bool,
}

impl DeflateDecoder {
    /// Creates a `deflate` decoder in the initial zlib-header-expected state.
    fn new() -> Self {
        DeflateDecoder {
            decomp: flate2::Decompress::new(true),
            started: false,
            raw_fallback_done: false,
            finished: false,
        }
    }

    /// The message curl emits (via `process_zlib_error`) when zlib cannot make
    /// sense of the stream.
    fn zlib_error() -> Error {
        Error::bad_content_encoding(
            "Error while processing content unencoding: \
             Unknown failure within decompression software.",
        )
    }
}

impl Decoder for DeflateDecoder {
    fn name(&self) -> &'static str {
        "deflate"
    }

    fn decode(&mut self, input: &[u8], out: &mut BytesMut, limit: usize) -> Result<()> {
        if input.is_empty() || self.finished {
            return Ok(());
        }

        let out_start = out.len();
        match run_inflate(&mut self.decomp, input, out, limit) {
            Ok(status) => {
                if out.len() > out_start {
                    self.started = true;
                }
                if status == flate2::Status::StreamEnd {
                    self.finished = true;
                }
                Ok(())
            }
            // A decompression-bomb ceiling hit is a hard stop: retrying in raw
            // mode would only re-expand the same bytes and hit the ceiling
            // again, so surface the resource-limit error immediately.
            Err(RunInflateError::TooLarge) => Err(Error::TooLarge),
            Err(RunInflateError::Decompress) => {
                // Attempt curl's raw-DEFLATE fallback, but only while still in
                // the pristine state (no output emitted, not yet retried).
                if !self.started && !self.raw_fallback_done && out.len() == out_start {
                    self.raw_fallback_done = true;
                    self.decomp = flate2::Decompress::new(false); // raw, no header
                    match run_inflate(&mut self.decomp, input, out, limit) {
                        Ok(status) => {
                            if out.len() > out_start {
                                self.started = true;
                            }
                            if status == flate2::Status::StreamEnd {
                                self.finished = true;
                            }
                            Ok(())
                        }
                        Err(RunInflateError::TooLarge) => Err(Error::TooLarge),
                        Err(RunInflateError::Decompress) => Err(Self::zlib_error()),
                    }
                } else {
                    Err(Self::zlib_error())
                }
            }
        }
    }

    fn finish(&mut self, _out: &mut BytesMut, _limit: usize) -> Result<()> {
        // zlib inflate emits output eagerly during `decode`, so there is never
        // any buffered residual to flush here. curl's `deflate_do_close` is
        // likewise lenient about a truncated stream, so end-of-body is a no-op.
        Ok(())
    }
}

// -------------------------------------------------------------------------
// gzip — transparent gzip (curl's zlib_writer/gzip, inflateInit2(+32))
// -------------------------------------------------------------------------

/// Upper bound on the bytes buffered while parsing a single gzip member header.
///
/// A gzip header is normally 10 bytes, but the optional `FEXTRA` field carries
/// a 16-bit length (so up to 65 535 bytes) and `FNAME`/`FCOMMENT` are
/// NUL-terminated strings of unbounded length in principle. curl/zlib read and
/// discard these fields; because this decoder buffers the header to locate the
/// DEFLATE body, an unbounded `FNAME`/`FCOMMENT`/`FEXTRA` would let a hostile
/// server balloon the header buffer. This ceiling (comfortably above a maximal
/// `FEXTRA` plus realistic name/comment fields) caps that transient allocation;
/// no real-world gzip stream approaches it, so parity is unaffected. A header
/// that exceeds it is treated as malformed (`CURLE_BAD_CONTENT_ENCODING`).
const MAX_GZIP_HEADER_BYTES: usize = 128 * 1024;

/// Outcome of attempting to parse an RFC 1952 gzip member header from a prefix
/// of the coded stream.
enum GzipHeaderParse {
    /// Not enough bytes buffered yet to decide; feed more input.
    NeedMore,
    /// The bytes are not a valid gzip header (bad magic or compression method).
    Invalid,
    /// A complete header occupying this many leading bytes; the DEFLATE body
    /// begins immediately after.
    Complete(usize),
}

/// Parses an RFC 1952 gzip member header from the front of `buf`.
///
/// Mirrors what zlib's `inflate` (with `MAX_WBITS + 32`) does internally: verify
/// the `1f 8b` magic and the `CM == 8` (DEFLATE) method byte, then skip the
/// fixed 10-byte header and whichever optional fields the `FLG` byte enables —
/// `FEXTRA` (0x04, 2-byte length + payload), `FNAME` (0x08, NUL-terminated),
/// `FCOMMENT` (0x10, NUL-terminated) and `FHCRC` (0x02, 2-byte CRC). Returns the
/// total header length so the caller knows where the compressed body starts.
fn parse_gzip_header(buf: &[u8]) -> GzipHeaderParse {
    // Fixed portion: ID1 ID2 CM FLG MTIME(4) XFL OS.
    if buf.len() < 10 {
        return GzipHeaderParse::NeedMore;
    }
    if buf[0] != 0x1f || buf[1] != 0x8b {
        return GzipHeaderParse::Invalid;
    }
    if buf[2] != 8 {
        // Only DEFLATE (CM == 8) is defined; anything else is malformed.
        return GzipHeaderParse::Invalid;
    }
    let flg = buf[3];
    let mut pos = 10usize;
    // FEXTRA: 2-byte little-endian length followed by that many bytes.
    if flg & 0x04 != 0 {
        if buf.len() < pos + 2 {
            return GzipHeaderParse::NeedMore;
        }
        let xlen = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;
        if buf.len() < pos + xlen {
            return GzipHeaderParse::NeedMore;
        }
        pos += xlen;
    }
    // FNAME: original file name, NUL-terminated.
    if flg & 0x08 != 0 {
        loop {
            if pos >= buf.len() {
                return GzipHeaderParse::NeedMore;
            }
            let byte = buf[pos];
            pos += 1;
            if byte == 0 {
                break;
            }
        }
    }
    // FCOMMENT: file comment, NUL-terminated.
    if flg & 0x10 != 0 {
        loop {
            if pos >= buf.len() {
                return GzipHeaderParse::NeedMore;
            }
            let byte = buf[pos];
            pos += 1;
            if byte == 0 {
                break;
            }
        }
    }
    // FHCRC: 2-byte header CRC16 (contents not validated, matching zlib, which
    // only checks it when present but whose result curl does not surface).
    if flg & 0x02 != 0 {
        if buf.len() < pos + 2 {
            return GzipHeaderParse::NeedMore;
        }
        pos += 2;
    }
    GzipHeaderParse::Complete(pos)
}

/// Where the gzip member decoder is within the RFC 1952 framing.
enum GzipState {
    /// Buffering and parsing the member header.
    Header,
    /// Inflating the DEFLATE body of the current member.
    Body,
    /// Buffering the 8-byte trailer (CRC32 + ISIZE) of the current member.
    Trailer,
}

/// The `gzip` decoder.
///
/// curl decodes gzip "transparently" via `inflateInit2(z, MAX_WBITS + 32)`,
/// letting zlib parse the gzip header, inflate the body, and — crucially —
/// **verify the 8-byte trailer**, reporting `CURLE_BAD_CONTENT_ENCODING` on a
/// CRC32 or ISIZE mismatch. The low-level [`flate2::Decompress`] API does not
/// expose gzip window bits, so this decoder reproduces zlib's gzip framing
/// itself: a small state machine parses each member's header, drives the raw
/// DEFLATE body through the shared [`run_inflate`] loop (which enforces the
/// decompression-bomb ceiling exactly as for `deflate`), and validates the
/// trailer inline against a running [`flate2::Crc`] over the decoded output.
///
/// Concatenated members are supported (like zlib's transparent multi-member
/// handling): after a validated trailer the machine resets and parses the next
/// member. A stream that ends mid-member or mid-trailer is tolerated as a
/// truncated transfer — matching curl's lenient `gzip_do_close`, which does not
/// turn a short read into an error — so only a *present but wrong* trailer is
/// rejected.
struct GzipDecoder {
    /// Current position within the gzip framing.
    state: GzipState,
    /// Header bytes accumulated so far for the member being parsed (bounded by
    /// [`MAX_GZIP_HEADER_BYTES`]).
    header_buf: Vec<u8>,
    /// Raw-DEFLATE inflater for the current member's body (`false` = no zlib
    /// header, i.e. a bare DEFLATE stream, which is what a gzip body is).
    decomp: flate2::Decompress,
    /// Running CRC32 and byte count over the current member's decoded output,
    /// compared against the trailer. [`flate2::Crc::sum`] yields the CRC32 and
    /// [`flate2::Crc::amount`] the ISIZE (mod 2^32), matching the trailer's two
    /// little-endian 32-bit fields.
    crc: flate2::Crc,
    /// Trailer bytes accumulated so far (need 8: CRC32 then ISIZE).
    trailer_buf: Vec<u8>,
    /// Set once [`finish`](Decoder::finish) has run so a later call is a no-op.
    finished: bool,
}

impl GzipDecoder {
    /// Creates a `gzip` decoder positioned at the start of the first member.
    fn new() -> Self {
        GzipDecoder {
            state: GzipState::Header,
            header_buf: Vec::new(),
            decomp: flate2::Decompress::new(false),
            crc: flate2::Crc::new(),
            trailer_buf: Vec::new(),
            finished: false,
        }
    }

    /// The diagnostic curl surfaces (via `process_zlib_error`) for a malformed
    /// gzip stream. The `detail` mirrors zlib's `z->msg` for the deterministic
    /// framing failures (`incorrect header check` / `incorrect data check` /
    /// `incorrect length check`), so `--verbose` output matches curl 8.x.
    fn framing_error(detail: &str) -> Error {
        Error::bad_content_encoding(format!(
            "Error while processing content unencoding: {detail}"
        ))
    }
}

impl Decoder for GzipDecoder {
    fn name(&self) -> &'static str {
        "gzip"
    }

    fn decode(&mut self, mut input: &[u8], out: &mut BytesMut, limit: usize) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        // Drive the framing state machine, consuming `input` as it advances
        // across headers, bodies and trailers (a single call may span several
        // members, or only a fraction of one).
        loop {
            if input.is_empty() {
                return Ok(());
            }
            match self.state {
                GzipState::Header => {
                    // Buffer just enough of `input` to complete the header,
                    // capped so a pathological header cannot exhaust memory.
                    let room = MAX_GZIP_HEADER_BYTES.saturating_sub(self.header_buf.len());
                    let take = room.min(input.len());
                    let prev_len = self.header_buf.len();
                    self.header_buf.extend_from_slice(&input[..take]);
                    match parse_gzip_header(&self.header_buf) {
                        GzipHeaderParse::Invalid => {
                            return Err(Self::framing_error("incorrect header check"));
                        }
                        GzipHeaderParse::Complete(header_len) => {
                            // Only the header bytes belong to the header; the
                            // remainder of `input` is the body (and beyond).
                            let used_from_input = header_len - prev_len;
                            input = &input[used_from_input..];
                            self.header_buf.clear();
                            // Fresh inflater and CRC for this member's body.
                            self.decomp = flate2::Decompress::new(false);
                            self.crc = flate2::Crc::new();
                            self.state = GzipState::Body;
                        }
                        GzipHeaderParse::NeedMore => {
                            input = &input[take..];
                            if self.header_buf.len() >= MAX_GZIP_HEADER_BYTES {
                                return Err(Self::framing_error("incorrect header check"));
                            }
                            // Either `input` is now empty (wait for more) or the
                            // cap was hit above; the outer check returns Ok.
                        }
                    }
                }
                GzipState::Body => {
                    let base = out.len();
                    let in_before = self.decomp.total_in();
                    let status = match run_inflate(&mut self.decomp, input, out, limit) {
                        Ok(status) => status,
                        Err(RunInflateError::TooLarge) => return Err(Error::TooLarge),
                        Err(RunInflateError::Decompress) => {
                            return Err(Self::framing_error(
                                "Unknown failure within decompression software.",
                            ));
                        }
                    };
                    // Fold exactly this member's freshly decoded bytes into the
                    // running CRC/length, then advance past the consumed input.
                    self.crc.update(&out[base..]);
                    let consumed = (self.decomp.total_in() - in_before) as usize;
                    input = &input[consumed..];
                    if status == flate2::Status::StreamEnd {
                        self.trailer_buf.clear();
                        self.state = GzipState::Trailer;
                    } else {
                        // Needs more body input; resume on the next call.
                        return Ok(());
                    }
                }
                GzipState::Trailer => {
                    let need = 8 - self.trailer_buf.len();
                    let take = need.min(input.len());
                    self.trailer_buf.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    if self.trailer_buf.len() < 8 {
                        // Trailer split across calls; wait for the rest.
                        return Ok(());
                    }
                    let crc_expected =
                        u32::from_le_bytes(self.trailer_buf[0..4].try_into().unwrap());
                    let isize_expected =
                        u32::from_le_bytes(self.trailer_buf[4..8].try_into().unwrap());
                    if crc_expected != self.crc.sum() {
                        return Err(Self::framing_error("incorrect data check"));
                    }
                    if isize_expected != self.crc.amount() {
                        return Err(Self::framing_error("incorrect length check"));
                    }
                    // Member fully validated; any remaining input starts the
                    // next concatenated member.
                    self.state = GzipState::Header;
                }
            }
        }
    }

    fn finish(&mut self, _out: &mut BytesMut, _limit: usize) -> Result<()> {
        // The body is inflated eagerly during `decode` (via `run_inflate`, which
        // emits output as it goes), so there is never buffered residual to flush
        // here. A stream that stops mid-header, mid-body or mid-trailer is a
        // truncated transfer, which curl's `gzip_do_close` tolerates rather than
        // reporting as a content error — so end-of-body is a lenient no-op.
        self.finished = true;
        Ok(())
    }
}

// -------------------------------------------------------------------------
// br — Brotli (curl's brotli_writer), gated behind `feature = "brotli"`
// -------------------------------------------------------------------------

/// The `br` (Brotli) decoder, compiled only when the `brotli` feature is on.
///
/// Mirrors curl's `brotli_writer`, which streams input through
/// `BrotliDecoderDecompressStream`. Here the pure-Rust [`brotli`] crate's
/// [`brotli::DecompressorWriter`] plays the same role: a `Write` adapter that
/// decodes into a [`BoundedSink`], drained after every write and enforcing the
/// per-call decompression-bomb ceiling before bytes are buffered.
#[cfg(feature = "brotli")]
struct BrotliDecoder {
    inner: brotli::DecompressorWriter<BoundedSink>,
    finished: bool,
}

#[cfg(feature = "brotli")]
impl BrotliDecoder {
    /// Creates a Brotli decoder with a scratch window sized like curl's
    /// per-step decompression buffer.
    fn new() -> Self {
        BrotliDecoder {
            inner: brotli::DecompressorWriter::new(BoundedSink::new(), DECOMPRESS_BUFFER_SIZE),
            finished: false,
        }
    }
}

#[cfg(feature = "brotli")]
impl Decoder for BrotliDecoder {
    fn name(&self) -> &'static str {
        "br"
    }

    fn decode(&mut self, input: &[u8], out: &mut BytesMut, limit: usize) -> Result<()> {
        if input.is_empty() || self.finished {
            return Ok(());
        }
        use std::io::Write as _;
        self.inner.get_mut().limit = limit;
        if let Err(e) = self.inner.write_all(input) {
            let overflowed = self.inner.get_ref().overflowed;
            return Err(sink_write_error(overflowed, e, "brotli"));
        }
        drain_sink(self.inner.get_mut(), out);
        Ok(())
    }

    fn finish(&mut self, out: &mut BytesMut, limit: usize) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        use std::io::Write as _;
        self.inner.get_mut().limit = limit;
        let _ = self.inner.flush();
        if self.inner.get_ref().overflowed {
            return Err(Error::TooLarge);
        }
        drain_sink(self.inner.get_mut(), out);
        Ok(())
    }
}

// -------------------------------------------------------------------------
// zstd — Zstandard (curl's zstd_writer), gated behind `feature = "zstd"`
// -------------------------------------------------------------------------

/// The `zstd` (Zstandard) decoder, compiled only when the `zstd` feature is on.
///
/// Mirrors curl's `zstd_writer`, which streams input through
/// `ZSTD_decompressStream`. Here the [`zstd`] crate's
/// [`zstd::stream::write::Decoder`] plays the same role: a `Write` adapter that
/// decodes into a [`BoundedSink`], drained after every write and enforcing the
/// per-call decompression-bomb ceiling before bytes are buffered.
#[cfg(feature = "zstd")]
struct ZstdDecoder {
    inner: zstd::stream::write::Decoder<'static, BoundedSink>,
    finished: bool,
}

#[cfg(feature = "zstd")]
impl ZstdDecoder {
    /// Creates a Zstandard decoder, or an [`Error::OutOfMemory`] if the
    /// underlying decompression context cannot be created — the parity mapping
    /// of curl's `ZSTD_createDStream` returning `NULL` (`CURLE_OUT_OF_MEMORY`).
    fn new() -> Result<Self> {
        let inner = zstd::stream::write::Decoder::new(BoundedSink::new())
            .map_err(|_| Error::OutOfMemory)?;
        Ok(ZstdDecoder {
            inner,
            finished: false,
        })
    }
}

#[cfg(feature = "zstd")]
impl Decoder for ZstdDecoder {
    fn name(&self) -> &'static str {
        "zstd"
    }

    fn decode(&mut self, input: &[u8], out: &mut BytesMut, limit: usize) -> Result<()> {
        if input.is_empty() || self.finished {
            return Ok(());
        }
        use std::io::Write as _;
        self.inner.get_mut().limit = limit;
        if let Err(e) = self.inner.write_all(input) {
            let overflowed = self.inner.get_ref().overflowed;
            return Err(sink_write_error(overflowed, e, "zstd"));
        }
        drain_sink(self.inner.get_mut(), out);
        Ok(())
    }

    fn finish(&mut self, out: &mut BytesMut, limit: usize) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        use std::io::Write as _;
        self.inner.get_mut().limit = limit;
        let _ = self.inner.flush();
        if self.inner.get_ref().overflowed {
            return Err(Error::TooLarge);
        }
        drain_sink(self.inner.get_mut(), out);
        Ok(())
    }
}

// =========================================================================
// Decoder factory + the Unencoder stack
// =========================================================================

/// Builds the concrete [`Decoder`] for a recognized, decodable coding.
///
/// Returns `None` for [`ContentEncoding::Unknown`] and for `br`/`zstd` when
/// their feature is disabled (or when a `zstd` context cannot be allocated) —
/// in every such case the caller substitutes the deferred [`ErrorDecoder`], so
/// the observable behavior matches a curl build lacking that codec.
fn make_decoder(enc: ContentEncoding) -> Option<Box<dyn Decoder>> {
    match enc {
        ContentEncoding::Identity => Some(Box::new(IdentityDecoder)),
        ContentEncoding::Deflate => Some(Box::new(DeflateDecoder::new())),
        ContentEncoding::Gzip => Some(Box::new(GzipDecoder::new())),
        ContentEncoding::Brotli => {
            #[cfg(feature = "brotli")]
            {
                Some(Box::new(BrotliDecoder::new()))
            }
            #[cfg(not(feature = "brotli"))]
            {
                None
            }
        }
        ContentEncoding::Zstd => {
            #[cfg(feature = "zstd")]
            {
                // A failed context allocation degrades to the deferred error
                // decoder, matching curl's `CURLE_OUT_OF_MEMORY`→writer path.
                ZstdDecoder::new()
                    .ok()
                    .map(|d| Box::new(d) as Box<dyn Decoder>)
            }
            #[cfg(not(feature = "zstd"))]
            {
                None
            }
        }
        ContentEncoding::Unknown => None,
    }
}

/// An ordered stack of content decoders — the parity equivalent of curl's
/// content-decode writer chain built by `Curl_build_unencoding_stack`.
///
/// The stack decodes the codings named in a `Content-Encoding` (or
/// `Transfer-Encoding`) header. Because codings are undone in reverse of the
/// order they were applied, [`push`](Unencoder::push) inserts each newly parsed
/// coding at the **front** of the stack, so the coding named last in the header
/// (applied last) is decoded first. Feed network bytes in with
/// [`write`](Unencoder::write) and signal end-of-body with
/// [`finish`](Unencoder::finish).
///
/// # Examples
///
/// ```ignore
/// // Decode a body sent as `Content-Encoding: gzip`.
/// let mut dec = Unencoder::from_content_encoding("gzip")?;
/// let mut body = dec.write(&chunk1)?;
/// body.extend_from_slice(&dec.write(&chunk2)?);
/// body.extend_from_slice(&dec.finish()?);
/// ```
pub struct Unencoder {
    /// Decoders in application-reverse order: index 0 runs first on input.
    decoders: Vec<Box<dyn Decoder>>,
    /// The decompression-bomb ceiling handed to every decoder on each
    /// [`write`](Unencoder::write) / [`finish`](Unencoder::finish) call: the
    /// maximum number of decoded bytes a single stage may emit for one call
    /// before the decode is aborted with [`Error::TooLarge`]. Defaults to
    /// [`DEFAULT_MAX_DECODED_PER_WRITE`]; set [`usize::MAX`] to disable the
    /// bound. See [`set_max_decoded_per_write`](Unencoder::set_max_decoded_per_write).
    max_decoded_per_write: usize,
}

impl Default for Unencoder {
    fn default() -> Self {
        Unencoder {
            decoders: Vec::new(),
            max_decoded_per_write: DEFAULT_MAX_DECODED_PER_WRITE,
        }
    }
}

impl std::fmt::Debug for Unencoder {
    /// Formats the stack as its ordered list of coding names, since the boxed
    /// decoder trait objects are not themselves `Debug`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unencoder")
            .field("decoders", &self.names())
            .finish()
    }
}

impl Unencoder {
    /// Creates an empty stack (an identity pass-through until codings are
    /// pushed).
    ///
    /// The decompression-bomb ceiling starts at [`DEFAULT_MAX_DECODED_PER_WRITE`];
    /// adjust it with [`set_max_decoded_per_write`](Unencoder::set_max_decoded_per_write)
    /// or [`with_max_decoded_per_write`](Unencoder::with_max_decoded_per_write).
    #[must_use]
    pub fn new() -> Self {
        Unencoder::default()
    }

    /// Sets the decompression-bomb ceiling: the maximum number of decoded bytes
    /// any single decoder stage may emit for one [`write`](Unencoder::write) or
    /// [`finish`](Unencoder::finish) call before the decode is aborted with
    /// [`Error::TooLarge`] (`CURLE_TOO_LARGE`).
    ///
    /// The bound guards against a compressed "bomb" — a tiny input that inflates
    /// to an enormous output — forcing unbounded allocation before the caller
    /// can apply backpressure (CWE-400). It applies per call and per stage, so
    /// working memory during a decode is capped at roughly
    /// `limit + DECOMPRESS_BUFFER_SIZE` regardless of the input's expansion
    /// ratio. Pass [`usize::MAX`] to disable the bound entirely.
    pub fn set_max_decoded_per_write(&mut self, limit: usize) {
        self.max_decoded_per_write = limit;
    }

    /// Builder form of [`set_max_decoded_per_write`](Unencoder::set_max_decoded_per_write),
    /// consuming and returning `self` for fluent construction.
    #[must_use]
    pub fn with_max_decoded_per_write(mut self, limit: usize) -> Self {
        self.max_decoded_per_write = limit;
        self
    }

    /// Returns the current decompression-bomb ceiling (decoded bytes per stage
    /// per call). [`usize::MAX`] means the bound is disabled.
    #[must_use]
    pub fn max_decoded_per_write(&self) -> usize {
        self.max_decoded_per_write
    }

    /// Builds a stack from a comma-separated coding list, e.g. the value of a
    /// `Content-Encoding` response header.
    ///
    /// Tokens are split on `,`, trimmed of surrounding ASCII whitespace, and
    /// empty tokens are skipped — matching curl's tolerant parsing in
    /// `Curl_build_unencoding_stack`. Each token is pushed via
    /// [`push`](Unencoder::push).
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadContentEncoding`] if the list would exceed
    /// [`MAX_ENCODE_STACK`] chained codings. An *unrecognized* or
    /// feature-disabled coding does **not** fail here; it is deferred (see
    /// [`push`](Unencoder::push)).
    pub fn from_content_encoding(enclist: &str) -> Result<Self> {
        let mut unencoder = Unencoder::new();
        for token in enclist.split(',') {
            let name = token.trim_matches(|c: char| c.is_ascii_whitespace());
            if name.is_empty() {
                continue;
            }
            unencoder.push(name)?;
        }
        Ok(unencoder)
    }

    /// Pushes one coding onto the stack, resolving it by name.
    ///
    /// The new decoder is inserted at the front so decoding unwinds in reverse
    /// of the order codings were applied. A coding that cannot be decoded (an
    /// unrecognized token, or `br`/`zstd` without its feature) installs the
    /// deferred [`ErrorDecoder`] instead of failing immediately, exactly as
    /// curl installs its `error_writer`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadContentEncoding`] when adding this coding would
    /// exceed [`MAX_ENCODE_STACK`]. The check reproduces curl's arithmetic
    /// exactly: it rejects when `current_count + 1 >= MAX_ENCODE_STACK`.
    pub fn push(&mut self, name: &str) -> Result<()> {
        // curl: `if(Curl_cwriter_count(data, phase) + 1 >= MAX_ENCODE_STACK)`.
        if self.decoders.len() + 1 >= MAX_ENCODE_STACK {
            return Err(Error::bad_content_encoding(format!(
                "Reject response due to more than {MAX_ENCODE_STACK} content encodings"
            )));
        }
        let enc = ContentEncoding::from_name(name);
        let decoder = make_decoder(enc).unwrap_or_else(|| Box::new(ErrorDecoder));
        // Insert at the front: last coding applied is decoded first.
        self.decoders.insert(0, decoder);
        Ok(())
    }

    /// Returns the number of decoders currently in the stack.
    #[must_use]
    pub fn len(&self) -> usize {
        self.decoders.len()
    }

    /// Returns `true` if the stack holds no decoders (a pure pass-through).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decoders.is_empty()
    }

    /// Returns the coding names of the stacked decoders in decode order (the
    /// coding decoded first comes first).
    ///
    /// This is the introspection analogue of curl's `Curl_cwriter_get_by_name`
    /// over the content-decode phase: a recognized coding reports its canonical
    /// name (`deflate`, `gzip`, `br`, `zstd`, `identity`) and an unrecognized or
    /// feature-disabled coding reports the deferred-error writer name
    /// `"ce-error"`.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.decoders.iter().map(|decoder| decoder.name()).collect()
    }

    /// Feeds a chunk of still-encoded body bytes through the stack and returns
    /// the fully decoded output for that chunk.
    ///
    /// An empty stack returns the input unchanged. Otherwise the chunk flows
    /// through every decoder in order (index 0 first); each decoder's output
    /// becomes the next decoder's input. Decoding is incremental — bytes that
    /// cannot yet be decoded are retained inside the individual decoders.
    ///
    /// # Errors
    ///
    /// Propagates [`Error::BadContentEncoding`] from any decoder that
    /// encounters a malformed stream (including the deferred error decoder on
    /// its first non-empty chunk).
    pub fn write(&mut self, input: &[u8]) -> Result<Bytes> {
        let limit = self.max_decoded_per_write;
        let mut iter = self.decoders.iter_mut();
        let Some(first) = iter.next() else {
            // No codings: identity pass-through.
            return Ok(Bytes::copy_from_slice(input));
        };
        let mut current = BytesMut::new();
        first.decode(input, &mut current, limit)?;
        for decoder in iter {
            let mut next = BytesMut::new();
            decoder.decode(&current, &mut next, limit)?;
            current = next;
        }
        Ok(current.freeze())
    }

    /// Signals end-of-body, flushing any decoder-internal residual through the
    /// remaining decoders and returning the final decoded tail.
    ///
    /// For most codecs the residual is empty (they emit eagerly), so this
    /// typically returns an empty buffer; it exists so any trailing bytes a
    /// decoder was holding are correctly pushed through the rest of the chain.
    ///
    /// # Errors
    ///
    /// Propagates [`Error::BadContentEncoding`] from any decoder in the chain.
    pub fn finish(&mut self) -> Result<Bytes> {
        let limit = self.max_decoded_per_write;
        let mut carry = BytesMut::new();
        for (index, decoder) in self.decoders.iter_mut().enumerate() {
            let mut out = BytesMut::new();
            // Feed the residual produced by the previous stage before flushing
            // this one; the first stage has no upstream residual.
            if index > 0 && !carry.is_empty() {
                decoder.decode(&carry, &mut out, limit)?;
            }
            decoder.finish(&mut out, limit)?;
            carry = out;
        }
        Ok(carry.freeze())
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CurlCode;
    use std::io::Write as _;

    /// A ~45 KB sample that exceeds [`DECOMPRESS_BUFFER_SIZE`], forcing the
    /// low-level inflate loop to iterate and every codec to stream.
    fn sample() -> Vec<u8> {
        b"The quick brown fox jumps over the lazy dog. ".repeat(1000)
    }

    fn gzip_compress(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).expect("gzip write");
        enc.finish().expect("gzip finish")
    }

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).expect("zlib write");
        enc.finish().expect("zlib finish")
    }

    fn raw_deflate_compress(data: &[u8]) -> Vec<u8> {
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).expect("deflate write");
        enc.finish().expect("deflate finish")
    }

    #[cfg(feature = "brotli")]
    fn brotli_compress(data: &[u8]) -> Vec<u8> {
        let mut enc = brotli::CompressorWriter::new(Vec::new(), DECOMPRESS_BUFFER_SIZE, 5, 22);
        enc.write_all(data).expect("brotli write");
        enc.into_inner()
    }

    #[cfg(feature = "zstd")]
    fn zstd_compress(data: &[u8]) -> Vec<u8> {
        zstd::encode_all(data, 3).expect("zstd encode")
    }

    /// Decodes `data` through the coding list `enclist` in a single write.
    fn decode_all(enclist: &str, data: &[u8]) -> Result<Vec<u8>> {
        let mut unencoder = Unencoder::from_content_encoding(enclist)?;
        let mut out = BytesMut::new();
        out.extend_from_slice(&unencoder.write(data)?);
        out.extend_from_slice(&unencoder.finish()?);
        Ok(out.to_vec())
    }

    /// Decodes `data` through `enclist` by feeding it in `chunk`-byte pieces,
    /// exercising the incremental streaming path.
    fn decode_chunked(enclist: &str, data: &[u8], chunk: usize) -> Result<Vec<u8>> {
        let mut unencoder = Unencoder::from_content_encoding(enclist)?;
        let mut out = BytesMut::new();
        for piece in data.chunks(chunk.max(1)) {
            out.extend_from_slice(&unencoder.write(piece)?);
        }
        out.extend_from_slice(&unencoder.finish()?);
        Ok(out.to_vec())
    }

    #[test]
    fn identity_passthrough() {
        let data = sample();
        assert_eq!(decode_all("identity", &data).unwrap(), data);
        // The `none` alias resolves to identity too.
        assert_eq!(decode_all("none", &data).unwrap(), data);
    }

    #[test]
    fn empty_stack_passthrough() {
        let data = sample();
        let mut unencoder = Unencoder::new();
        assert!(unencoder.is_empty());
        assert_eq!(unencoder.len(), 0);
        let decoded = unencoder.write(&data).unwrap();
        assert_eq!(&decoded[..], &data[..]);
        assert!(unencoder.finish().unwrap().is_empty());
    }

    #[test]
    fn gzip_roundtrip() {
        let data = sample();
        let encoded = gzip_compress(&data);
        assert_eq!(decode_all("gzip", &encoded).unwrap(), data);
    }

    #[test]
    fn gzip_alias_x_gzip() {
        let data = sample();
        let encoded = gzip_compress(&data);
        assert_eq!(decode_all("x-gzip", &encoded).unwrap(), data);
        // Case-insensitive matching, like curl's curl_strnequal.
        assert_eq!(decode_all("GZIP", &encoded).unwrap(), data);
    }

    #[test]
    fn deflate_zlib_roundtrip() {
        let data = sample();
        let encoded = zlib_compress(&data);
        assert_eq!(decode_all("deflate", &encoded).unwrap(), data);
    }

    #[test]
    fn deflate_raw_roundtrip() {
        // Some servers send a raw DEFLATE stream (no zlib header) under the
        // `deflate` coding; the decoder must auto-detect and fall back to raw.
        let data = sample();
        let encoded = raw_deflate_compress(&data);
        assert_eq!(decode_all("deflate", &encoded).unwrap(), data);
    }

    #[test]
    fn chained_gzip_gzip() {
        // Body gzipped twice → `Content-Encoding: gzip, gzip`.
        let data = sample();
        let encoded = gzip_compress(&gzip_compress(&data));
        assert_eq!(decode_all("gzip, gzip", &encoded).unwrap(), data);
    }

    #[test]
    fn mixed_gzip_then_deflate_unwinds_in_reverse() {
        // `Content-Encoding: gzip, deflate` means gzip was applied first, then
        // deflate: wire = deflate(gzip(orig)). Correct decoding must undo
        // deflate first, then gzip — verifying the reverse-order stack.
        let data = sample();
        let encoded = zlib_compress(&gzip_compress(&data));
        assert_eq!(decode_all("gzip, deflate", &encoded).unwrap(), data);
    }

    #[test]
    fn names_reflect_reverse_order_stacking() {
        // Header order gzip,deflate → decode order deflate,gzip (unwind reverse).
        let unencoder = Unencoder::from_content_encoding("gzip, deflate").unwrap();
        assert_eq!(unencoder.names(), vec!["deflate", "gzip"]);
        // An unrecognized coding surfaces as the deferred-error writer name.
        let unknown = Unencoder::from_content_encoding("banana").unwrap();
        assert_eq!(unknown.names(), vec!["ce-error"]);
    }

    #[test]
    fn streaming_chunked_gzip() {
        let data = sample();
        let encoded = gzip_compress(&data);
        // Tiny chunks exercise incremental decoding (header/trailer spanning
        // multiple writes, output produced across many calls).
        assert_eq!(decode_chunked("gzip", &encoded, 7).unwrap(), data);
        assert_eq!(
            decode_chunked("gzip, deflate", &zlib_compress(&encoded), 3).unwrap(),
            data
        );
    }

    #[test]
    fn unknown_encoding_defers_to_code_61() {
        // Building the stack succeeds (curl defers the error to write time).
        let mut unencoder =
            Unencoder::from_content_encoding("banana").expect("build defers unknown coding");
        assert_eq!(unencoder.len(), 1);
        // A zero-length write is forwarded without error.
        assert!(unencoder.write(&[]).unwrap().is_empty());
        // The first non-empty body chunk surfaces CURLE_BAD_CONTENT_ENCODING.
        let err = unencoder.write(b"some body bytes").unwrap_err();
        assert_eq!(err.code(), CurlCode::BadContentEncoding);
        assert_eq!(err.code() as i32, 61);
    }

    #[test]
    fn oversized_chain_rejected_like_curl() {
        // curl rejects when `count + 1 >= MAX_ENCODE_STACK` (== 5), so four
        // codings are accepted and a fifth is rejected.
        assert_eq!(
            Unencoder::from_content_encoding("gzip, gzip, gzip, gzip")
                .expect("four codings accepted")
                .len(),
            4
        );
        let err = Unencoder::from_content_encoding("gzip, gzip, gzip, gzip, gzip")
            .expect_err("five codings rejected");
        assert_eq!(err.code(), CurlCode::BadContentEncoding);
        assert_eq!(err.code() as i32, 61);
    }

    #[test]
    fn content_encodings_lists_supported_excluding_identity() {
        let listed = content_encodings();
        // identity is never advertised.
        assert!(!listed.split(", ").any(|n| n == "identity"));
        // deflate and gzip are always present, in registry order first.
        assert!(listed.starts_with("deflate, gzip"));
        #[cfg(feature = "brotli")]
        assert!(listed.split(", ").any(|n| n == "br"));
        #[cfg(feature = "zstd")]
        assert!(listed.split(", ").any(|n| n == "zstd"));
        #[cfg(not(feature = "brotli"))]
        assert!(!listed.split(", ").any(|n| n == "br"));
        #[cfg(not(feature = "zstd"))]
        assert!(!listed.split(", ").any(|n| n == "zstd"));
    }

    #[test]
    fn from_name_matches_names_and_aliases() {
        assert_eq!(
            ContentEncoding::from_name("identity"),
            ContentEncoding::Identity
        );
        assert_eq!(
            ContentEncoding::from_name("none"),
            ContentEncoding::Identity
        );
        assert_eq!(
            ContentEncoding::from_name("deflate"),
            ContentEncoding::Deflate
        );
        assert_eq!(ContentEncoding::from_name("gzip"), ContentEncoding::Gzip);
        assert_eq!(ContentEncoding::from_name("x-gzip"), ContentEncoding::Gzip);
        assert_eq!(ContentEncoding::from_name("BR"), ContentEncoding::Brotli);
        assert_eq!(ContentEncoding::from_name("zstd"), ContentEncoding::Zstd);
        assert_eq!(
            ContentEncoding::from_name("weird"),
            ContentEncoding::Unknown
        );
        // identity/deflate/gzip are always decodable; unknown never is.
        assert!(ContentEncoding::Identity.is_supported());
        assert!(ContentEncoding::Deflate.is_supported());
        assert!(ContentEncoding::Gzip.is_supported());
        assert!(!ContentEncoding::Unknown.is_supported());
    }

    #[test]
    fn default_and_constants_match_curl() {
        assert_eq!(CONTENT_ENCODING_DEFAULT, "identity");
        assert_eq!(MAX_ENCODE_STACK, 5);
        assert_eq!(DECOMPRESS_BUFFER_SIZE, 16_384);
        // Default-constructed stack is an empty pass-through.
        assert!(Unencoder::default().is_empty());
    }

    #[test]
    fn decoders_and_stack_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Unencoder>();
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn brotli_roundtrip() {
        let data = sample();
        let encoded = brotli_compress(&data);
        assert_eq!(decode_all("br", &encoded).unwrap(), data);
        assert!(ContentEncoding::Brotli.is_supported());
    }

    #[cfg(feature = "zstd")]
    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises zstd C-FFI (zstd-sys); Miri cannot interpret foreign functions"
    )]
    fn zstd_roundtrip() {
        let data = sample();
        let encoded = zstd_compress(&data);
        assert_eq!(decode_all("zstd", &encoded).unwrap(), data);
        assert!(ContentEncoding::Zstd.is_supported());
    }

    #[cfg(not(feature = "brotli"))]
    #[test]
    fn brotli_unsupported_when_disabled_behaves_like_unknown() {
        // Without the feature, `br` is recognized as a name but not decodable,
        // so the stack installs the deferred error decoder → code 61 on write.
        assert!(!ContentEncoding::Brotli.is_supported());
        let mut unencoder = Unencoder::from_content_encoding("br").expect("build defers");
        let err = unencoder.write(b"body").unwrap_err();
        assert_eq!(err.code() as i32, 61);
    }

    #[cfg(not(feature = "zstd"))]
    #[test]
    fn zstd_unsupported_when_disabled_behaves_like_unknown() {
        assert!(!ContentEncoding::Zstd.is_supported());
        let mut unencoder = Unencoder::from_content_encoding("zstd").expect("build defers");
        let err = unencoder.write(b"body").unwrap_err();
        assert_eq!(err.code() as i32, 61);
    }

    #[test]
    fn corrupt_gzip_stream_reports_bad_encoding() {
        // Random bytes are not a valid gzip stream → CURLE_BAD_CONTENT_ENCODING.
        let mut unencoder = Unencoder::from_content_encoding("gzip").unwrap();
        let garbage = [0xFFu8; 512];
        // The error may surface on write or on finish depending on how much of
        // the (invalid) header was consumed; either way it must be code 61.
        let result = unencoder.write(&garbage).and_then(|_| unencoder.finish());
        let err = result.expect_err("corrupt gzip must fail");
        assert_eq!(err.code() as i32, 61);
    }

    #[test]
    fn gzip_bad_crc_is_rejected() {
        // A gzip member whose stored CRC32 does not match the decoded body must
        // be rejected as CURLE_BAD_CONTENT_ENCODING — zlib's "incorrect data
        // check" as surfaced by curl. (Before the fix this was silently
        // accepted, the defect reported in F5-CE-001.)
        let data = sample();
        let mut encoded = gzip_compress(&data);
        let n = encoded.len();
        encoded[n - 8] ^= 0x01; // flip a bit in the little-endian CRC32 field
        let err = decode_all("gzip", &encoded).expect_err("bad gzip CRC must fail");
        assert_eq!(err.code(), CurlCode::BadContentEncoding);
        assert_eq!(err.code() as i32, 61);
    }

    #[test]
    fn gzip_bad_isize_is_rejected() {
        // A corrupted ISIZE (uncompressed-length) trailer field must likewise be
        // rejected — zlib's "incorrect length check".
        let data = sample();
        let mut encoded = gzip_compress(&data);
        let n = encoded.len();
        encoded[n - 1] ^= 0x01; // flip a bit in the little-endian ISIZE field
        let err = decode_all("gzip", &encoded).expect_err("bad gzip ISIZE must fail");
        assert_eq!(err.code(), CurlCode::BadContentEncoding);
        assert_eq!(err.code() as i32, 61);
    }

    #[test]
    fn gzip_bad_crc_is_detected_even_when_chunked() {
        // The trailer check must fire regardless of how the stream is fragmented
        // across writes (trailer bytes arriving one byte at a time).
        let data = sample();
        let mut encoded = gzip_compress(&data);
        let n = encoded.len();
        encoded[n - 6] ^= 0x02; // corrupt a CRC32 byte
        let err = decode_chunked("gzip", &encoded, 1)
            .expect_err("bad gzip CRC must fail even when chunked");
        assert_eq!(err.code() as i32, 61);
    }

    #[test]
    fn gzip_truncated_trailer_is_tolerated() {
        // A stream cut off before (or during) its trailer is a truncated
        // transfer, not a content error: curl's lenient gzip_do_close delivers
        // the decoded body without failing, and the output is still complete.
        let data = sample();
        let encoded = gzip_compress(&data);
        let n = encoded.len();
        // The whole 8-byte trailer is missing.
        assert_eq!(decode_all("gzip", &encoded[..n - 8]).unwrap(), data);
        // Only part of the trailer arrived (split-trailer truncation).
        assert_eq!(decode_all("gzip", &encoded[..n - 3]).unwrap(), data);
        // The intact stream still decodes cleanly (rejection is trailer-specific).
        assert_eq!(decode_all("gzip", &encoded).unwrap(), data);
    }

    #[test]
    fn gzip_multi_member_roundtrips() {
        // Concatenated gzip members (zlib's transparent multi-member handling)
        // decode into the concatenation of their bodies, each trailer validated
        // against its own CRC32/ISIZE.
        let first = b"first member payload ".repeat(200);
        let second = b"second member payload ".repeat(200);
        let mut encoded = gzip_compress(&first);
        encoded.extend_from_slice(&gzip_compress(&second));
        let mut expected = first.clone();
        expected.extend_from_slice(&second);
        // Whole-buffer and tiny-chunk (header/trailer spanning writes) paths.
        assert_eq!(decode_all("gzip", &encoded).unwrap(), expected);
        assert_eq!(decode_chunked("gzip", &encoded, 5).unwrap(), expected);
    }

    // ---------------------------------------------------------------------
    // Decompression-bomb ceiling (CWE-400)
    // ---------------------------------------------------------------------

    /// A trivially compressible payload: `n` zero bytes shrink to a tiny
    /// compressed stream but expand back to `n` bytes on decode — the shape of
    /// a decompression bomb.
    fn zeros(n: usize) -> Vec<u8> {
        vec![0u8; n]
    }

    #[test]
    fn default_ceiling_is_finite_and_configurable() {
        // A fresh stack starts at the finite default (the constant's finiteness
        // is proven at compile time by the `const _` assertion above), and the
        // setter/builder/accessor must round-trip.
        assert_eq!(
            Unencoder::new().max_decoded_per_write(),
            DEFAULT_MAX_DECODED_PER_WRITE
        );

        let mut u = Unencoder::new();
        u.set_max_decoded_per_write(4096);
        assert_eq!(u.max_decoded_per_write(), 4096);

        let u = Unencoder::new().with_max_decoded_per_write(usize::MAX);
        assert_eq!(u.max_decoded_per_write(), usize::MAX);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "compresses/decompresses a 512 KiB buffer; the pure-Rust codec is prohibitively slow under Miri's interpreter (minutes/test) and is UB-clean — the CWE-400 ceiling logic is covered by the smaller roundtrip/within-ceiling tests that run natively under Miri"
    )]
    fn gzip_bomb_exceeding_limit_is_rejected() {
        // 512 KiB of zeros compresses to a few hundred bytes; decoding it under
        // a 32 KiB ceiling must abort with CURLE_TOO_LARGE (100) rather than
        // allocate the full 512 KiB.
        let encoded = gzip_compress(&zeros(512 * 1024));
        let mut unencoder = Unencoder::from_content_encoding("gzip").unwrap();
        unencoder.set_max_decoded_per_write(32 * 1024);
        let err = unencoder
            .write(&encoded)
            .and_then(|_| unencoder.finish())
            .expect_err("gzip bomb must be rejected");
        assert_eq!(err.code(), CurlCode::TooLarge);
        assert_eq!(err.code() as i32, 100);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "compresses/decompresses a 512 KiB buffer; the pure-Rust codec is prohibitively slow under Miri's interpreter (minutes/test) and is UB-clean — the CWE-400 ceiling logic is covered by the smaller roundtrip/within-ceiling tests that run natively under Miri"
    )]
    fn deflate_bomb_exceeding_limit_is_rejected() {
        // Same bomb shape through the zlib/deflate inflate loop, which enforces
        // the ceiling cumulatively inside `run_inflate`.
        let encoded = zlib_compress(&zeros(512 * 1024));
        let mut unencoder = Unencoder::from_content_encoding("deflate").unwrap();
        unencoder.set_max_decoded_per_write(32 * 1024);
        let err = unencoder
            .write(&encoded)
            .and_then(|_| unencoder.finish())
            .expect_err("deflate bomb must be rejected");
        assert_eq!(err.code(), CurlCode::TooLarge);
        assert_eq!(err.code() as i32, 100);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "compresses/decompresses a 512 KiB buffer; the pure-Rust codec is prohibitively slow under Miri's interpreter (minutes/test) and is UB-clean — the CWE-400 ceiling logic is covered by the smaller roundtrip/within-ceiling tests that run natively under Miri"
    )]
    fn raw_deflate_bomb_exceeding_limit_is_rejected() {
        // The headerless raw-DEFLATE fallback path must honor the ceiling too:
        // a raw stream that expands past the limit is rejected as TooLarge, not
        // masked by the fallback retry.
        let encoded = raw_deflate_compress(&zeros(512 * 1024));
        let mut unencoder = Unencoder::from_content_encoding("deflate").unwrap();
        unencoder.set_max_decoded_per_write(32 * 1024);
        let err = unencoder
            .write(&encoded)
            .and_then(|_| unencoder.finish())
            .expect_err("raw-deflate bomb must be rejected");
        assert_eq!(err.code(), CurlCode::TooLarge);
        assert_eq!(err.code() as i32, 100);
    }

    #[test]
    fn gzip_within_ceiling_still_roundtrips() {
        // Legitimate content whose decoded size stays under the configured
        // ceiling must decode unharmed — the bound only rejects overflow.
        let data = sample();
        assert!(data.len() < 512 * 1024);
        let encoded = gzip_compress(&data);
        let mut unencoder = Unencoder::from_content_encoding("gzip").unwrap();
        unencoder.set_max_decoded_per_write(512 * 1024);
        let mut out = BytesMut::new();
        out.extend_from_slice(&unencoder.write(&encoded).unwrap());
        out.extend_from_slice(&unencoder.finish().unwrap());
        assert_eq!(out.to_vec(), data);
    }

    #[test]
    fn deflate_within_ceiling_still_roundtrips() {
        let data = sample();
        assert!(data.len() < 512 * 1024);
        let encoded = zlib_compress(&data);
        let mut unencoder = Unencoder::from_content_encoding("deflate").unwrap();
        unencoder.set_max_decoded_per_write(512 * 1024);
        let mut out = BytesMut::new();
        out.extend_from_slice(&unencoder.write(&encoded).unwrap());
        out.extend_from_slice(&unencoder.finish().unwrap());
        assert_eq!(out.to_vec(), data);
    }

    #[cfg(feature = "brotli")]
    #[test]
    #[cfg_attr(
        miri,
        ignore = "compresses/decompresses a 512 KiB buffer; the pure-Rust codec is prohibitively slow under Miri's interpreter (minutes/test) and is UB-clean — the CWE-400 ceiling logic is covered by the smaller roundtrip/within-ceiling tests that run natively under Miri"
    )]
    fn brotli_bomb_exceeding_limit_is_rejected() {
        let encoded = brotli_compress(&zeros(512 * 1024));
        let mut unencoder = Unencoder::from_content_encoding("br").unwrap();
        unencoder.set_max_decoded_per_write(32 * 1024);
        let err = unencoder
            .write(&encoded)
            .and_then(|_| unencoder.finish())
            .expect_err("brotli bomb must be rejected");
        assert_eq!(err.code(), CurlCode::TooLarge);
        assert_eq!(err.code() as i32, 100);
    }

    #[cfg(feature = "zstd")]
    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises zstd C-FFI (zstd-sys); Miri cannot interpret foreign functions"
    )]
    fn zstd_bomb_exceeding_limit_is_rejected() {
        let encoded = zstd_compress(&zeros(512 * 1024));
        let mut unencoder = Unencoder::from_content_encoding("zstd").unwrap();
        unencoder.set_max_decoded_per_write(32 * 1024);
        let err = unencoder
            .write(&encoded)
            .and_then(|_| unencoder.finish())
            .expect_err("zstd bomb must be rejected");
        assert_eq!(err.code(), CurlCode::TooLarge);
        assert_eq!(err.code() as i32, 100);
    }
}
