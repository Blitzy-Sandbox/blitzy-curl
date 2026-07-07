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
    fn decode(&mut self, input: &[u8], out: &mut BytesMut) -> Result<()>;

    /// Signals end-of-body, flushing any decoder-internal residual into `out`.
    ///
    /// Like curl's `do_close`, this is lenient about a truncated stream: it
    /// flushes whatever is available and does not, on its own, treat an
    /// incomplete stream as an error.
    fn finish(&mut self, out: &mut BytesMut) -> Result<()>;
}

/// Moves everything accumulated in a decoder's `Vec` sink into the output
/// buffer and clears the sink for reuse.
///
/// Used by the write-adapter–based decoders (`gzip`, `br`, `zstd`), which emit
/// their decoded output into an owned `Vec<u8>` that is drained after each
/// write so intermediate memory stays bounded.
#[inline]
fn drain_sink(sink: &mut Vec<u8>, out: &mut BytesMut) {
    if !sink.is_empty() {
        out.extend_from_slice(sink.as_slice());
        sink.clear();
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

    fn decode(&mut self, input: &[u8], out: &mut BytesMut) -> Result<()> {
        out.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, _out: &mut BytesMut) -> Result<()> {
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

    fn decode(&mut self, input: &[u8], _out: &mut BytesMut) -> Result<()> {
        if input.is_empty() {
            // Mirrors curl: a zero-length write is forwarded, not an error.
            return Ok(());
        }
        Err(Error::bad_content_encoding(
            "Unrecognized content encoding type",
        ))
    }

    fn finish(&mut self, _out: &mut BytesMut) -> Result<()> {
        Ok(())
    }
}

// -------------------------------------------------------------------------
// deflate — zlib or raw DEFLATE, auto-detected (curl's zlib_writer/deflate)
// -------------------------------------------------------------------------

/// Runs a [`flate2::Decompress`] over `input`, appending decoded bytes to
/// `out`, iterating with a fixed [`DECOMPRESS_BUFFER_SIZE`] scratch buffer.
///
/// This is the direct analogue of curl's `inflate_stream` loop: it keeps
/// inflating into a bounded buffer and flushing it downstream until the stream
/// ends, the input is exhausted, or the decoder can make no further progress
/// (needing more input). It returns the terminal [`flate2::Status`] on success,
/// or the underlying [`flate2::DecompressError`] on a malformed stream so the
/// caller can decide whether the `deflate` raw-stream fallback applies.
fn run_inflate(
    decomp: &mut flate2::Decompress,
    mut input: &[u8],
    out: &mut BytesMut,
) -> std::result::Result<flate2::Status, flate2::DecompressError> {
    let mut buf = [0u8; DECOMPRESS_BUFFER_SIZE];
    loop {
        let in_before = decomp.total_in();
        let out_before = decomp.total_out();
        let status = decomp.decompress(input, &mut buf, flate2::FlushDecompress::None)?;
        let consumed = (decomp.total_in() - in_before) as usize;
        let produced = (decomp.total_out() - out_before) as usize;
        if produced > 0 {
            out.extend_from_slice(&buf[..produced]);
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

    fn decode(&mut self, input: &[u8], out: &mut BytesMut) -> Result<()> {
        if input.is_empty() || self.finished {
            return Ok(());
        }

        let out_start = out.len();
        match run_inflate(&mut self.decomp, input, out) {
            Ok(status) => {
                if out.len() > out_start {
                    self.started = true;
                }
                if status == flate2::Status::StreamEnd {
                    self.finished = true;
                }
                Ok(())
            }
            Err(_) => {
                // Attempt curl's raw-DEFLATE fallback, but only while still in
                // the pristine state (no output emitted, not yet retried).
                if !self.started && !self.raw_fallback_done && out.len() == out_start {
                    self.raw_fallback_done = true;
                    self.decomp = flate2::Decompress::new(false); // raw, no header
                    match run_inflate(&mut self.decomp, input, out) {
                        Ok(status) => {
                            if out.len() > out_start {
                                self.started = true;
                            }
                            if status == flate2::Status::StreamEnd {
                                self.finished = true;
                            }
                            Ok(())
                        }
                        Err(_) => Err(Self::zlib_error()),
                    }
                } else {
                    Err(Self::zlib_error())
                }
            }
        }
    }

    fn finish(&mut self, _out: &mut BytesMut) -> Result<()> {
        // zlib inflate emits output eagerly during `decode`, so there is never
        // any buffered residual to flush here. curl's `deflate_do_close` is
        // likewise lenient about a truncated stream, so end-of-body is a no-op.
        Ok(())
    }
}

// -------------------------------------------------------------------------
// gzip — transparent gzip (curl's zlib_writer/gzip, inflateInit2(+32))
// -------------------------------------------------------------------------

/// The `gzip` decoder.
///
/// curl decodes gzip "transparently" via `inflateInit2(z, MAX_WBITS + 32)`,
/// letting zlib parse the gzip header, member, and trailer. The low-level
/// [`flate2::Decompress`] API does not expose gzip window bits, so this decoder
/// uses [`flate2::write::MultiGzDecoder`] — a `Write` adapter that decodes gzip
/// (tolerating concatenated members) into an owned `Vec<u8>` sink, which is
/// drained into the output buffer after every write to keep memory bounded.
struct GzipDecoder {
    inner: flate2::write::MultiGzDecoder<Vec<u8>>,
    finished: bool,
}

impl GzipDecoder {
    /// Creates a `gzip` decoder writing into a fresh, empty sink.
    fn new() -> Self {
        GzipDecoder {
            inner: flate2::write::MultiGzDecoder::new(Vec::new()),
            finished: false,
        }
    }
}

impl Decoder for GzipDecoder {
    fn name(&self) -> &'static str {
        "gzip"
    }

    fn decode(&mut self, input: &[u8], out: &mut BytesMut) -> Result<()> {
        if input.is_empty() || self.finished {
            return Ok(());
        }
        use std::io::Write as _;
        self.inner
            .write_all(input)
            .map_err(|_| Error::bad_content_encoding("Error while processing gzip content"))?;
        drain_sink(self.inner.get_mut(), out);
        Ok(())
    }

    fn finish(&mut self, out: &mut BytesMut) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        use std::io::Write as _;
        // Flush any bytes the adapter still holds, then drain the sink. Flush
        // failures on a truncated stream are ignored to match curl's lenient
        // `gzip_do_close`.
        let _ = self.inner.flush();
        drain_sink(self.inner.get_mut(), out);
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
/// decodes into an owned `Vec<u8>` sink, drained after every write.
#[cfg(feature = "brotli")]
struct BrotliDecoder {
    inner: brotli::DecompressorWriter<Vec<u8>>,
    finished: bool,
}

#[cfg(feature = "brotli")]
impl BrotliDecoder {
    /// Creates a Brotli decoder with a scratch window sized like curl's
    /// per-step decompression buffer.
    fn new() -> Self {
        BrotliDecoder {
            inner: brotli::DecompressorWriter::new(Vec::new(), DECOMPRESS_BUFFER_SIZE),
            finished: false,
        }
    }
}

#[cfg(feature = "brotli")]
impl Decoder for BrotliDecoder {
    fn name(&self) -> &'static str {
        "br"
    }

    fn decode(&mut self, input: &[u8], out: &mut BytesMut) -> Result<()> {
        if input.is_empty() || self.finished {
            return Ok(());
        }
        use std::io::Write as _;
        self.inner
            .write_all(input)
            .map_err(|_| Error::bad_content_encoding("Error while processing brotli content"))?;
        drain_sink(self.inner.get_mut(), out);
        Ok(())
    }

    fn finish(&mut self, out: &mut BytesMut) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        use std::io::Write as _;
        let _ = self.inner.flush();
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
/// decodes into an owned `Vec<u8>` sink, drained after every write.
#[cfg(feature = "zstd")]
struct ZstdDecoder {
    inner: zstd::stream::write::Decoder<'static, Vec<u8>>,
    finished: bool,
}

#[cfg(feature = "zstd")]
impl ZstdDecoder {
    /// Creates a Zstandard decoder, or an [`Error::OutOfMemory`] if the
    /// underlying decompression context cannot be created — the parity mapping
    /// of curl's `ZSTD_createDStream` returning `NULL` (`CURLE_OUT_OF_MEMORY`).
    fn new() -> Result<Self> {
        let inner =
            zstd::stream::write::Decoder::new(Vec::new()).map_err(|_| Error::OutOfMemory)?;
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

    fn decode(&mut self, input: &[u8], out: &mut BytesMut) -> Result<()> {
        if input.is_empty() || self.finished {
            return Ok(());
        }
        use std::io::Write as _;
        self.inner
            .write_all(input)
            .map_err(|_| Error::bad_content_encoding("Error while processing zstd content"))?;
        drain_sink(self.inner.get_mut(), out);
        Ok(())
    }

    fn finish(&mut self, out: &mut BytesMut) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        use std::io::Write as _;
        let _ = self.inner.flush();
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
#[derive(Default)]
pub struct Unencoder {
    /// Decoders in application-reverse order: index 0 runs first on input.
    decoders: Vec<Box<dyn Decoder>>,
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
    #[must_use]
    pub fn new() -> Self {
        Unencoder {
            decoders: Vec::new(),
        }
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
        let mut iter = self.decoders.iter_mut();
        let Some(first) = iter.next() else {
            // No codings: identity pass-through.
            return Ok(Bytes::copy_from_slice(input));
        };
        let mut current = BytesMut::new();
        first.decode(input, &mut current)?;
        for decoder in iter {
            let mut next = BytesMut::new();
            decoder.decode(&current, &mut next)?;
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
        let mut carry = BytesMut::new();
        for (index, decoder) in self.decoders.iter_mut().enumerate() {
            let mut out = BytesMut::new();
            // Feed the residual produced by the previous stage before flushing
            // this one; the first stage has no upstream residual.
            if index > 0 && !carry.is_empty() {
                decoder.decode(&carry, &mut out)?;
            }
            decoder.finish(&mut out)?;
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
}
