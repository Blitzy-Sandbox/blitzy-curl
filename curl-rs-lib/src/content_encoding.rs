// HTTP content-encoding (decompression) writer chain for the curl-rs workspace.
//
// SPDX-License-Identifier: curl
//
// This file is a memory-safe Rust reimplementation of curl's content-encoding
// subsystem (`lib/content_encoding.c` / `lib/content_encoding.h`). The original
// C sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).
// This Rust port preserves the observable behavior (the decoded byte stream and
// the `Accept-Encoding` request header) of that subsystem; it is a behavioral
// translation, not a line-by-line transliteration.
#![forbid(unsafe_code)]
//! Streaming HTTP content-decoding chain — the safe replacement for curl's
//! content-encoding writers (`lib/content_encoding.c`).
//!
//! # What this module does
//!
//! When an HTTP response carries a `Content-Encoding` (or, for the chunked
//! pass-through, `Transfer-Encoding`) header, the body on the wire is one or
//! more *compressed* encodings of the data the application asked for. curl
//! removes those encodings with a **chain of streaming writers**: each writer
//! consumes the bytes produced by the previous one, decompresses incrementally,
//! and hands the result to the next writer — the final link being the client
//! write callback in [`crate::transfer`].
//!
//! This module provides:
//!
//! * [`Unencoder`] — the streaming-decoder trait, analogous to curl's
//!   `Curl_cwtype` writer vtable (`init`/`write`/`close`). A decoder is fed
//!   compressed bytes and emits decompressed bytes to a *sink* callback that
//!   represents the next writer in the chain.
//! * [`ContentEncoding`] — the recognized encoding tokens (`gzip`, `deflate`,
//!   `br`, `zstd`, `identity`, `chunked`) plus the unknown/unsupported case,
//!   with curl's name and alias handling (`x-gzip`, `none`).
//! * [`UnencodingStack`] — the ordered chain of decoders built from a
//!   `Content-Encoding` header value, mirroring `Curl_build_unencoding_stack`:
//!   the comma-separated list is parsed left-to-right and the decoders are
//!   stacked in **reverse** so the *last*-listed encoding is undone *first*
//!   (RFC 9110 §8.4 — codings are listed in the order applied).
//! * [`supported_content_encodings`] and [`accept_encoding_header`] — the
//!   builders for the `Accept-Encoding` request header, mirroring
//!   `Curl_get_content_encodings` and the `CURLOPT_ACCEPT_ENCODING` semantics.
//!
//! # Pure-Rust, zero-`unsafe` backends
//!
//! curl's C implementation wraps the `zlib`, `brotli`, and `zstd` **C**
//! libraries. This port wraps their pure-Rust equivalents instead — `flate2`
//! (with the `miniz_oxide`/`rust_backend`, no C linkage), `brotli`, and
//! `zstd` — so the whole module compiles under `#![forbid(unsafe_code)]`
//! (AAP §0.7.1) and links no C TLS/compression code (AAP §0.6.2).
//!
//! The `br` (Brotli) and `zstd` decoders are gated behind the `brotli` and
//! `zstd` Cargo features exactly as curl gates `USE_BROTLI` / `USE_ZSTD`. A
//! `--no-default-features` build omits them, and [`supported_content_encodings`]
//! correspondingly omits the tokens, so `curl --version` /
//! `curl-config --features` capability reporting stays in lock-step with the
//! build (AAP §0.7.3).
//!
//! # Streaming and bomb resistance
//!
//! Decompression is **incremental**: bytes are decoded as they arrive (partial
//! input across reads is handled) and flushed onward in bounded chunks, never
//! by buffering the whole body. This both fits the asynchronous transfer loop
//! and bounds working memory. curl additionally limits a response to at most
//! [`MAX_ENCODE_STACK`]-1 chained encodings as its decompression-bomb guard;
//! [`UnencodingStack`] reproduces that limit and the matching
//! [`CURLE_BAD_CONTENT_ENCODING`](crate::error::CurlError::BadContentEncoding)
//! rejection.

use std::io::Write;

use crate::error::{CurlError, Result};

// ---------------------------------------------------------------------------
// Constants — mirrored from lib/content_encoding.c
// ---------------------------------------------------------------------------

/// Maximum number of "chained" decompression steps curl tolerates in a single
/// decoding phase (`#define MAX_ENCODE_STACK 5` in `lib/content_encoding.c`).
///
/// This is curl's decompression-bomb guard: a response advertising more than
/// `MAX_ENCODE_STACK - 1` stacked content encodings is rejected with
/// [`CurlError::BadContentEncoding`] before any decoder is created. See
/// [`UnencodingStack::from_content_encoding`].
pub const MAX_ENCODE_STACK: usize = 5;

/// Size of the fixed scratch buffer used to flush decompressed output to the
/// next writer (`#define DECOMPRESS_BUFFER_SIZE 16384`).
///
/// Decoders emit at most this many bytes per flush iteration, which bounds the
/// transient memory held while decompressing — even for a highly compressible
/// (potentially adversarial) input — exactly as curl's 16 KiB buffer does.
pub const DECOMPRESS_BUFFER_SIZE: usize = 16384;

/// The default/no-op content coding (`#define CONTENT_ENCODING_DEFAULT
/// "identity"`). It is excluded from the advertised `Accept-Encoding` list.
pub const CONTENT_ENCODING_DEFAULT: &str = "identity";

// ---------------------------------------------------------------------------
// ContentEncoding — the recognized coding tokens
// ---------------------------------------------------------------------------

/// A content (or transfer) coding token recognized by the decoding chain.
///
/// Mirrors the `Curl_cwtype` table in `lib/content_encoding.c`: the canonical
/// name plus curl's accepted aliases (`x-gzip` for `gzip`, `none` for
/// `identity`). [`from_token`](ContentEncoding::from_token) performs the same
/// case-insensitive matching curl does with `curl_strnequal`.
///
/// The [`Brotli`](ContentEncoding::Brotli) and [`Zstd`](ContentEncoding::Zstd)
/// variants exist only when the corresponding Cargo feature is enabled; when a
/// feature is disabled, its token parses to [`Unknown`](ContentEncoding::Unknown)
/// — exactly as a curl build compiled without `USE_BROTLI` / `USE_ZSTD` treats
/// an unsupported coding (deferred [`CurlError::BadContentEncoding`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentEncoding {
    /// `identity` (alias `none`) — no transformation; a pass-through decoder.
    Identity,
    /// `deflate` — zlib-wrapped DEFLATE, with curl's raw-DEFLATE fallback when
    /// the zlib header is absent.
    Deflate,
    /// `gzip` (alias `x-gzip`) — gzip-framed DEFLATE.
    Gzip,
    /// `br` — Brotli. Present only with the `brotli` feature.
    #[cfg(feature = "brotli")]
    Brotli,
    /// `zstd` — Zstandard. Present only with the `zstd` feature.
    #[cfg(feature = "zstd")]
    Zstd,
    /// `chunked` — the HTTP chunked transfer coding. At the content-decoding
    /// layer this is a pass-through; the actual chunk de-framing is performed
    /// upstream by `crate::protocols::http` before content decoding runs.
    Chunked,
    /// An unrecognized or unsupported coding. Building a stack that contains one
    /// defers a [`CurlError::BadContentEncoding`] until body data is written,
    /// matching curl's `error_writer` ("ce-error").
    Unknown,
}

impl ContentEncoding {
    /// Maps a single coding token to a [`ContentEncoding`].
    ///
    /// Leading/trailing ASCII whitespace is trimmed and the comparison is
    /// case-insensitive (per RFC 9110 §8.4.1 and curl's `curl_strnequal`).
    /// Unknown tokens — including `br`/`zstd` when their feature is disabled —
    /// map to [`Unknown`](ContentEncoding::Unknown).
    #[must_use]
    pub fn from_token(token: &str) -> ContentEncoding {
        let t = token.trim_matches(|c: char| c == ' ' || c == '\t');
        if t.eq_ignore_ascii_case("identity") || t.eq_ignore_ascii_case("none") {
            ContentEncoding::Identity
        } else if t.eq_ignore_ascii_case("deflate") {
            ContentEncoding::Deflate
        } else if t.eq_ignore_ascii_case("gzip") || t.eq_ignore_ascii_case("x-gzip") {
            ContentEncoding::Gzip
        } else if t.eq_ignore_ascii_case("br") {
            #[cfg(feature = "brotli")]
            {
                ContentEncoding::Brotli
            }
            #[cfg(not(feature = "brotli"))]
            {
                ContentEncoding::Unknown
            }
        } else if t.eq_ignore_ascii_case("zstd") {
            #[cfg(feature = "zstd")]
            {
                ContentEncoding::Zstd
            }
            #[cfg(not(feature = "zstd"))]
            {
                ContentEncoding::Unknown
            }
        } else if t.eq_ignore_ascii_case("chunked") {
            ContentEncoding::Chunked
        } else {
            ContentEncoding::Unknown
        }
    }

    /// Returns the canonical curl name for this coding.
    ///
    /// [`Unknown`](ContentEncoding::Unknown) reports `"ce-error"`, the name of
    /// curl's deferred-error writer.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ContentEncoding::Identity => "identity",
            ContentEncoding::Deflate => "deflate",
            ContentEncoding::Gzip => "gzip",
            #[cfg(feature = "brotli")]
            ContentEncoding::Brotli => "br",
            #[cfg(feature = "zstd")]
            ContentEncoding::Zstd => "zstd",
            ContentEncoding::Chunked => "chunked",
            ContentEncoding::Unknown => "ce-error",
        }
    }

    /// Constructs the streaming decoder that undoes this coding.
    ///
    /// [`Identity`](ContentEncoding::Identity) and
    /// [`Chunked`](ContentEncoding::Chunked) yield a pass-through;
    /// [`Unknown`](ContentEncoding::Unknown) yields the deferred-error decoder.
    #[must_use]
    fn make_decoder(self) -> Box<dyn Unencoder> {
        match self {
            ContentEncoding::Identity | ContentEncoding::Chunked => Box::new(IdentityUnencoder),
            ContentEncoding::Deflate => Box::new(DeflateUnencoder::new()),
            ContentEncoding::Gzip => Box::new(GzipUnencoder::new()),
            #[cfg(feature = "brotli")]
            ContentEncoding::Brotli => Box::new(BrotliUnencoder::new()),
            #[cfg(feature = "zstd")]
            ContentEncoding::Zstd => Box::new(ZstdUnencoder::new()),
            ContentEncoding::Unknown => Box::new(DeferredErrorUnencoder),
        }
    }
}

// ---------------------------------------------------------------------------
// Unencoder — the streaming-decoder trait (curl's Curl_cwtype vtable)
// ---------------------------------------------------------------------------

/// A streaming content decoder — one link in the unencoding chain.
///
/// This is the safe analog of curl's `Curl_cwtype` writer: an implementor is
/// fed compressed bytes through [`write`](Unencoder::write) and emits the
/// decompressed bytes by invoking the `sink` callback (which represents the
/// *next* writer in the chain — ultimately the client write callback in
/// [`crate::transfer`]). [`finish`](Unencoder::finish) flushes any buffered
/// tail of the stream at end-of-body, analogous to curl's `close` step.
///
/// # Contract
///
/// * Implementations decode **incrementally** and MUST NOT buffer the whole
///   body; output is flushed to `sink` in bounded pieces (see
///   [`DECOMPRESS_BUFFER_SIZE`]).
/// * A malformed compressed stream is reported as
///   [`CurlError::BadContentEncoding`].
/// * Errors returned by `sink` (e.g. a client write failure) are propagated
///   unchanged.
/// * After the underlying stream signals completion, subsequent
///   [`write`](Unencoder::write) calls are accepted and ignored (trailing bytes
///   past a self-terminating stream are tolerated, as in curl).
pub trait Unencoder {
    /// The canonical curl name of this decoder (for tracing/introspection).
    fn name(&self) -> &'static str;

    /// Feeds `data` (compressed bytes) into the decoder, forwarding every
    /// decompressed byte produced to `sink` in order.
    fn write(&mut self, data: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>;

    /// Flushes any remaining decompressed output at end-of-stream, forwarding it
    /// to `sink`. Called once after the final [`write`](Unencoder::write).
    fn finish(&mut self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Identity — pass-through (curl identity_encoding / Curl_cwriter_def_*)
// ---------------------------------------------------------------------------

/// Pass-through decoder: forwards input verbatim. Backs both `identity`/`none`
/// and the content-layer `chunked` pass-through.
struct IdentityUnencoder;

impl Unencoder for IdentityUnencoder {
    fn name(&self) -> &'static str {
        "identity"
    }

    fn write(&mut self, data: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        sink(data)
    }

    fn finish(&mut self, _sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Deferred error — curl's error_writer ("ce-error")
// ---------------------------------------------------------------------------

/// Decoder for an unrecognized coding. It mirrors curl's `error_writer`: the
/// error is *deferred* until body bytes actually flow, so a response that
/// advertises an unsupported `Content-Encoding` but carries no body (e.g. a
/// `HEAD` reply) does not fail. Any body byte yields
/// [`CurlError::BadContentEncoding`].
struct DeferredErrorUnencoder;

impl Unencoder for DeferredErrorUnencoder {
    fn name(&self) -> &'static str {
        "ce-error"
    }

    fn write(&mut self, data: &[u8], _sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        // Empty writes carry no body and are tolerated; the stack only routes
        // non-empty body bytes to the chain, so any data here is a real body.
        if data.is_empty() {
            return Ok(());
        }
        Err(CurlError::BadContentEncoding)
    }

    fn finish(&mut self, _sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Deflate — zlib-wrapped DEFLATE with curl's raw-DEFLATE fallback
// ---------------------------------------------------------------------------

/// `deflate` decoder built on flate2's low-level [`flate2::Decompress`]
/// (`miniz_oxide`, pure Rust).
///
/// curl first tries a zlib-wrapped stream and, if the zlib header turns out to
/// be absent, transparently falls back to raw DEFLATE (`inflateReset2` with
/// negative window bits). Some servers emit raw DEFLATE while still labeling it
/// `deflate`, so this fallback is required for parity.
///
/// This implementation reproduces curl's *decision* deterministically: it
/// inspects the first two bytes and checks the RFC 1950 zlib header invariants
/// (`CM == 8`, `CINFO <= 7`, and the 16-bit `CMF*256+FLG` being a multiple of
/// 31) — exactly the conditions zlib itself uses to accept or reject the
/// header. A valid header selects zlib mode; otherwise raw DEFLATE is used.
/// Real raw-DEFLATE block headers reliably fail the check (their compression
/// method nibble is not 8), so the outcome is byte-identical to curl's
/// try-then-reset behavior while also being robust when the first two bytes
/// arrive in separate reads.
struct DeflateUnencoder {
    /// `None` until the zlib-vs-raw decision has been made.
    decomp: Option<flate2::Decompress>,
    /// Holds the single byte seen so far when the first read delivered only one
    /// byte (we need two to decide). Never grows beyond one byte.
    pending: Vec<u8>,
    /// Reusable 16 KiB output buffer.
    out: Vec<u8>,
    /// Set once the inflate stream reports its end.
    done: bool,
}

impl DeflateUnencoder {
    fn new() -> Self {
        DeflateUnencoder {
            decomp: None,
            pending: Vec::new(),
            out: vec![0u8; DECOMPRESS_BUFFER_SIZE],
            done: false,
        }
    }

    /// Chooses zlib (`true`) vs raw DEFLATE (`false`) from the first two bytes,
    /// applying zlib's header-acceptance test.
    fn decide(b0: u8, b1: u8) -> flate2::Decompress {
        let cm = b0 & 0x0f;
        let cinfo = b0 >> 4;
        // zlib FCHECK: the 16-bit `CMF*256 + FLG` value must be a multiple of
        // 31. `u16::is_multiple_of` expresses this, but it was stabilized in
        // Rust 1.87 — above this crate's MSRV of 1.75 (AAP §0.8.1) — so the
        // explicit modulo is retained deliberately.
        #[allow(clippy::manual_is_multiple_of)]
        let fcheck_ok = (((b0 as u16) << 8) | b1 as u16) % 31 == 0;
        let zlib_header = cm == 8 && cinfo <= 7 && fcheck_ok;
        flate2::Decompress::new(zlib_header)
    }

    /// Drives the inflate loop over `input`, flushing each 16 KiB of output to
    /// `sink`. Requires `self.decomp` to be initialized.
    fn run(&mut self, input: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let decomp = match self.decomp.as_mut() {
            Some(d) => d,
            None => return Ok(()),
        };
        let mut pos = 0usize;
        loop {
            let before_in = decomp.total_in();
            let before_out = decomp.total_out();
            let status = decomp
                .decompress(&input[pos..], &mut self.out, flate2::FlushDecompress::None)
                .map_err(|_| CurlError::BadContentEncoding)?;
            let consumed = (decomp.total_in() - before_in) as usize;
            let produced = (decomp.total_out() - before_out) as usize;
            if produced > 0 {
                sink(&self.out[..produced])?;
            }
            pos += consumed;
            match status {
                flate2::Status::StreamEnd => {
                    self.done = true;
                    break;
                }
                flate2::Status::Ok => {
                    // No forward progress means we need more input; stop until
                    // the next write() (or finish()).
                    if consumed == 0 && produced == 0 {
                        break;
                    }
                }
                flate2::Status::BufError => break,
            }
        }
        Ok(())
    }
}

impl Unencoder for DeflateUnencoder {
    fn name(&self) -> &'static str {
        "deflate"
    }

    fn write(&mut self, data: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if self.done {
            return Ok(());
        }
        if self.decomp.is_some() {
            return self.run(data, sink);
        }
        // Still deciding zlib vs raw: we need two bytes.
        if self.pending.is_empty() {
            if data.len() >= 2 {
                self.decomp = Some(Self::decide(data[0], data[1]));
                return self.run(data, sink);
            }
            // Fewer than two bytes available: stash and wait for more.
            self.pending.extend_from_slice(data);
            return Ok(());
        }
        // We already have one stashed byte; combine with the new data.
        if self.pending.len() + data.len() < 2 {
            self.pending.extend_from_slice(data);
            return Ok(());
        }
        let mut combined = std::mem::take(&mut self.pending);
        combined.extend_from_slice(data);
        self.decomp = Some(Self::decide(combined[0], combined[1]));
        self.run(&combined, sink)
    }

    fn finish(&mut self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if self.done || self.decomp.is_none() {
            // Either the stream ended cleanly, or it was too short to even pick
            // a mode (empty or single-byte body). curl's close step likewise
            // produces no further output and no error in these cases.
            return Ok(());
        }
        // Defensive final drain: flush any latched output the inflate state may
        // still hold. Normal streams have already been fully drained by write().
        self.run(&[], sink)
    }
}

/// Drains the decompressed bytes a write-based decoder has accumulated in its
/// inner [`Vec`] sink, forwarding them to `sink` and reusing the buffer's
/// capacity. Shared by the gzip/brotli/zstd decoders.
fn drain_inner(inner: &mut Vec<u8>, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    if inner.is_empty() {
        return Ok(());
    }
    sink(inner.as_slice())?;
    inner.clear();
    Ok(())
}

// ---------------------------------------------------------------------------
// Gzip — flate2 write::GzDecoder (gzip framing + DEFLATE, pure Rust)
// ---------------------------------------------------------------------------

/// `gzip` decoder built on [`flate2::write::GzDecoder`].
///
/// The write-based decoder parses the gzip header/trailer and decompresses the
/// DEFLATE body, writing the result into an inner [`Vec`] that is drained to the
/// chain's `sink` after each fed slice. This mirrors curl's transparent-gzip
/// mode (`inflateInit2(MAX_WBITS + 32)`). The low-level
/// [`flate2::Decompress::new_gzip`] constructor is unavailable with the
/// pure-Rust backend, so the backend-agnostic `write::GzDecoder` is used.
struct GzipUnencoder {
    dec: flate2::write::GzDecoder<Vec<u8>>,
    done: bool,
}

impl GzipUnencoder {
    fn new() -> Self {
        GzipUnencoder {
            dec: flate2::write::GzDecoder::new(Vec::new()),
            done: false,
        }
    }
}

impl Unencoder for GzipUnencoder {
    fn name(&self) -> &'static str {
        "gzip"
    }

    fn write(&mut self, data: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if self.done || data.is_empty() {
            return Ok(());
        }
        // Feed in bounded slices, draining decompressed output after each so the
        // transient buffer stays small even for highly compressible input.
        for slice in data.chunks(DECOMPRESS_BUFFER_SIZE) {
            self.dec
                .write_all(slice)
                .map_err(|_| CurlError::BadContentEncoding)?;
            drain_inner(self.dec.get_mut(), sink)?;
        }
        Ok(())
    }

    fn finish(&mut self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        self.dec
            .try_finish()
            .map_err(|_| CurlError::BadContentEncoding)?;
        drain_inner(self.dec.get_mut(), sink)
    }
}

// ---------------------------------------------------------------------------
// Brotli — brotli::DecompressorWriter (pure Rust, feature-gated)
// ---------------------------------------------------------------------------

/// `br` (Brotli) decoder built on [`brotli::DecompressorWriter`]. Present only
/// with the `brotli` feature, mirroring curl's `USE_BROTLI` gate.
#[cfg(feature = "brotli")]
struct BrotliUnencoder {
    dec: brotli::DecompressorWriter<Vec<u8>>,
    done: bool,
}

#[cfg(feature = "brotli")]
impl BrotliUnencoder {
    fn new() -> Self {
        BrotliUnencoder {
            dec: brotli::DecompressorWriter::new(Vec::new(), DECOMPRESS_BUFFER_SIZE),
            done: false,
        }
    }
}

#[cfg(feature = "brotli")]
impl Unencoder for BrotliUnencoder {
    fn name(&self) -> &'static str {
        "br"
    }

    fn write(&mut self, data: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if self.done || data.is_empty() {
            return Ok(());
        }
        for slice in data.chunks(DECOMPRESS_BUFFER_SIZE) {
            self.dec
                .write_all(slice)
                .map_err(|_| CurlError::BadContentEncoding)?;
            drain_inner(self.dec.get_mut(), sink)?;
        }
        Ok(())
    }

    fn finish(&mut self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        self.dec
            .close()
            .map_err(|_| CurlError::BadContentEncoding)?;
        drain_inner(self.dec.get_mut(), sink)
    }
}

// ---------------------------------------------------------------------------
// Zstd — zstd::stream::write::Decoder (pure Rust, feature-gated)
// ---------------------------------------------------------------------------

/// `zstd` (Zstandard) decoder built on [`zstd::stream::write::Decoder`]. Present
/// only with the `zstd` feature, mirroring curl's `USE_ZSTD` gate.
///
/// The underlying decoder is created lazily on first use so that the (alloc-only)
/// failure path can be surfaced as [`CurlError::OutOfMemory`], matching curl's
/// `ZSTD_createDStream` handling.
#[cfg(feature = "zstd")]
struct ZstdUnencoder {
    dec: Option<zstd::stream::write::Decoder<'static, Vec<u8>>>,
    done: bool,
}

#[cfg(feature = "zstd")]
impl ZstdUnencoder {
    fn new() -> Self {
        ZstdUnencoder {
            dec: None,
            done: false,
        }
    }

    fn decoder(&mut self) -> Result<&mut zstd::stream::write::Decoder<'static, Vec<u8>>> {
        if self.dec.is_none() {
            let d = zstd::stream::write::Decoder::new(Vec::new())
                .map_err(|_| CurlError::OutOfMemory)?;
            self.dec = Some(d);
        }
        Ok(self.dec.as_mut().expect("zstd decoder initialized above"))
    }
}

#[cfg(feature = "zstd")]
impl Unencoder for ZstdUnencoder {
    fn name(&self) -> &'static str {
        "zstd"
    }

    fn write(&mut self, data: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if self.done || data.is_empty() {
            return Ok(());
        }
        for slice in data.chunks(DECOMPRESS_BUFFER_SIZE) {
            {
                let dec = self.decoder()?;
                dec.write_all(slice)
                    .map_err(|_| CurlError::BadContentEncoding)?;
            }
            // Borrow again only to drain, keeping the mutable borrows disjoint.
            if let Some(dec) = self.dec.as_mut() {
                drain_inner(dec.get_mut(), sink)?;
            }
        }
        Ok(())
    }

    fn finish(&mut self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        if let Some(dec) = self.dec.as_mut() {
            dec.flush().map_err(|_| CurlError::BadContentEncoding)?;
            drain_inner(dec.get_mut(), sink)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Chain driving — equivalent to curl's writer->next forwarding
// ---------------------------------------------------------------------------

/// Pushes `input` through the writer chain `writers` (where `writers[0]` is the
/// first decoder to touch the wire bytes), forwarding the final decompressed
/// output to `client`.
///
/// Each decoder's output is fed into the remaining decoders by recursively
/// driving the tail of the slice — the safe analog of curl's
/// `Curl_cwriter_write(data, writer->next, …)`.
fn drive(
    writers: &mut [Box<dyn Unencoder>],
    input: &[u8],
    client: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    if let Some((head, tail)) = writers.split_first_mut() {
        head.write(input, &mut |decoded: &[u8]| drive(tail, decoded, client))
    } else {
        client(input)
    }
}

/// Flushes the writer chain at end-of-stream: each decoder is finished in order,
/// its trailing output routed through the decoders that follow it before they
/// themselves are finished.
fn finish_chain(
    writers: &mut [Box<dyn Unencoder>],
    client: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    if let Some((head, tail)) = writers.split_first_mut() {
        head.finish(&mut |decoded: &[u8]| drive(tail, decoded, client))?;
        finish_chain(tail, client)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// UnencodingStack — the built decoder chain (Curl_build_unencoding_stack)
// ---------------------------------------------------------------------------

/// An ordered chain of content decoders built from a `Content-Encoding` header.
///
/// This is the safe analog of curl's per-request writer stack for the
/// content-decode phase. [`from_content_encoding`](UnencodingStack::from_content_encoding)
/// reproduces `Curl_build_unencoding_stack`:
///
/// * The comma-separated coding list is parsed left-to-right; each decoder is
///   **prepended** so the chain runs in reverse order (the last-listed coding is
///   undone first), matching curl's "insert first in phase" insertion and RFC
///   9110 §8.4 semantics.
/// * At most [`MAX_ENCODE_STACK`]`- 1` decoders are allowed; a longer list is
///   rejected with [`CurlError::BadContentEncoding`] (curl's bomb guard).
/// * An unrecognized coding becomes a deferred-error decoder that fails on the
///   first body byte.
/// * When content decoding is disabled (curl's `CURLOPT_HTTP_CONTENT_DECODING`
///   off / `http_ce_skip`), the stack is left empty so the still-encoded bytes
///   pass through unchanged.
///
/// Drive it with [`write`](UnencodingStack::write) per received body chunk and
/// [`finish`](UnencodingStack::finish) once at end-of-body.
pub struct UnencodingStack {
    /// `writers[0]` processes wire bytes first.
    writers: Vec<Box<dyn Unencoder>>,
    /// The codings, parallel to `writers` (same first-runs order).
    encodings: Vec<ContentEncoding>,
}

impl UnencodingStack {
    /// Creates an empty stack — a transparent pass-through that performs no
    /// decoding (the state used when no `Content-Encoding` applies or when
    /// content decoding is disabled).
    #[must_use]
    pub fn new() -> Self {
        UnencodingStack {
            writers: Vec::new(),
            encodings: Vec::new(),
        }
    }

    /// Builds the decoding chain from a `Content-Encoding` header value.
    ///
    /// `enclist` is the raw header value (e.g. `"gzip, deflate"`).
    /// `decoding_enabled` reflects `CURLOPT_HTTP_CONTENT_DECODING`: when `false`
    /// the returned stack is empty (raw pass-through), exactly as curl skips
    /// building the stack when `http_ce_skip` is set.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadContentEncoding`] if the list specifies more than
    /// [`MAX_ENCODE_STACK`]`- 1` codings (curl's decompression-bomb guard).
    /// Unrecognized codings do **not** fail here; they install a deferred-error
    /// decoder that fails only when body bytes are written.
    pub fn from_content_encoding(enclist: &str, decoding_enabled: bool) -> Result<UnencodingStack> {
        let mut stack = UnencodingStack::new();
        if !decoding_enabled {
            // Content decoding disabled: leave the body untouched.
            return Ok(stack);
        }

        for token in enclist.split(',') {
            let trimmed = token.trim_matches(|c: char| c == ' ' || c == '\t');
            if trimmed.is_empty() {
                // Empty element (e.g. a trailing/standalone comma) — skip, as
                // curl's parser advances past blanks and commas.
                continue;
            }

            // Bomb guard: reject before creating the decoder, matching curl's
            // `Curl_cwriter_count(...) + 1 >= MAX_ENCODE_STACK` check.
            if stack.writers.len() + 1 >= MAX_ENCODE_STACK {
                return Err(CurlError::BadContentEncoding);
            }

            let enc = ContentEncoding::from_token(trimmed);
            // Prepend: the decoder for the last-listed coding ends up first in
            // the chain, so wire bytes are decoded in reverse list order.
            stack.writers.insert(0, enc.make_decoder());
            stack.encodings.insert(0, enc);
        }

        Ok(stack)
    }

    /// Returns the number of decoders in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.writers.len()
    }

    /// Returns `true` if the chain performs no decoding (pass-through).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.writers.is_empty()
    }

    /// Returns the chain's codings in the order they run (the decoder for the
    /// last-listed `Content-Encoding` coding is first).
    #[must_use]
    pub fn encodings(&self) -> &[ContentEncoding] {
        &self.encodings
    }

    /// Feeds one received chunk through the chain.
    ///
    /// `is_body` reflects curl's `CLIENTWRITE_BODY` flag: only body bytes are
    /// decoded. Non-body data (header/meta writes) and empty writes bypass the
    /// decoders and are forwarded to `sink` unchanged — exactly as each curl
    /// writer forwards non-`CLIENTWRITE_BODY` / zero-length writes straight to
    /// `writer->next`.
    pub fn write(
        &mut self,
        is_body: bool,
        data: &[u8],
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        if !is_body || data.is_empty() {
            return sink(data);
        }
        drive(&mut self.writers, data, sink)
    }

    /// Flushes the chain at end-of-body, emitting any decoder's buffered tail to
    /// `sink`. Call once after the final [`write`](UnencodingStack::write).
    pub fn finish(&mut self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        finish_chain(&mut self.writers, sink)
    }
}

impl Default for UnencodingStack {
    fn default() -> Self {
        UnencodingStack::new()
    }
}

// ---------------------------------------------------------------------------
// Accept-Encoding builders (Curl_get_content_encodings / CURLOPT_ACCEPT_ENCODING)
// ---------------------------------------------------------------------------

/// Returns the comma-separated list of content codings this build can decode,
/// in curl's advertised order: `deflate, gzip`, then `br` (if the `brotli`
/// feature is on), then `zstd` (if the `zstd` feature is on).
///
/// This is the safe analog of `Curl_get_content_encodings`: it enumerates the
/// general decoders and omits the [`CONTENT_ENCODING_DEFAULT`] (`identity`)
/// coding. It is the value libcurl sends for `Accept-Encoding` when
/// `CURLOPT_ACCEPT_ENCODING` is set to the empty string ("all I support").
///
/// The order and membership are wire-observable and feature-coupled, so they
/// stay in lock-step with `curl --version` capability reporting (AAP §0.7.3).
#[must_use]
pub fn supported_content_encodings() -> String {
    // `deflate` and `gzip` are always available (flate2 is non-optional); `br`
    // and `zstd` are appended only when their Cargo feature is enabled. The
    // `mut` is used only when at least one of those features is on, hence the
    // allow for the `--no-default-features` build where both are compiled out.
    #[allow(unused_mut)]
    let mut names: Vec<&'static str> = vec!["deflate", "gzip"];
    #[cfg(feature = "brotli")]
    names.push("br");
    #[cfg(feature = "zstd")]
    names.push("zstd");
    names.join(", ")
}

/// Computes the value of the `Accept-Encoding` request header, reproducing
/// `CURLOPT_ACCEPT_ENCODING` semantics:
///
/// * `None` — the option was never set: no `Accept-Encoding` header is sent and
///   no automatic decoding is requested. Returns `None`.
/// * `Some("")` — the empty string means "advertise everything I can decode":
///   returns [`supported_content_encodings`].
/// * `Some(value)` — an explicit value is sent **verbatim** (curl does not
///   validate or reorder it); returns it unchanged.
///
/// The returned [`String`] is the header *value* only (without the
/// `Accept-Encoding:` field name).
#[must_use]
pub fn accept_encoding_header(requested: Option<&str>) -> Option<String> {
    match requested {
        None => None,
        Some("") => Some(supported_content_encodings()),
        Some(s) => Some(s.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Representative, compressible payload large enough to force several 16 KiB
    /// flush iterations through the decoders.
    fn sample() -> Vec<u8> {
        b"The quick brown fox jumps over the lazy dog. 0123456789\n".repeat(4096)
    }

    // ---- encoder helpers (produce the compressed test vectors) -------------

    fn enc_gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn enc_zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn enc_raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[cfg(feature = "brotli")]
    fn enc_brotli(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, DECOMPRESS_BUFFER_SIZE, 5, 22);
            w.write_all(data).unwrap();
        }
        out
    }

    #[cfg(feature = "zstd")]
    fn enc_zstd(data: &[u8]) -> Vec<u8> {
        zstd::encode_all(data, 3).unwrap()
    }

    /// Decodes `chunks` (fed as successive body writes) through the chain built
    /// from `enclist`, returning the concatenated decoded output.
    fn decode_chunks(enclist: &str, decoding_enabled: bool, chunks: &[&[u8]]) -> Result<Vec<u8>> {
        let mut stack = UnencodingStack::from_content_encoding(enclist, decoding_enabled)?;
        let mut out = Vec::new();
        for c in chunks {
            stack.write(true, c, &mut |d| {
                out.extend_from_slice(d);
                Ok(())
            })?;
        }
        stack.finish(&mut |d| {
            out.extend_from_slice(d);
            Ok(())
        })?;
        Ok(out)
    }

    /// Decodes `comp` in a single body write.
    fn decode_all(enclist: &str, comp: &[u8]) -> Result<Vec<u8>> {
        decode_chunks(enclist, true, &[comp])
    }

    /// Decodes `comp` one byte at a time, exercising partial-input streaming.
    fn decode_byte_by_byte(enclist: &str, comp: &[u8]) -> Result<Vec<u8>> {
        let chunks: Vec<&[u8]> = comp.chunks(1).collect();
        decode_chunks(enclist, true, &chunks)
    }

    // ---- token / name parsing ---------------------------------------------

    #[test]
    fn from_token_recognizes_names_and_aliases() {
        assert_eq!(
            ContentEncoding::from_token("identity"),
            ContentEncoding::Identity
        );
        assert_eq!(
            ContentEncoding::from_token("none"),
            ContentEncoding::Identity
        );
        assert_eq!(
            ContentEncoding::from_token("deflate"),
            ContentEncoding::Deflate
        );
        assert_eq!(ContentEncoding::from_token("gzip"), ContentEncoding::Gzip);
        assert_eq!(ContentEncoding::from_token("x-gzip"), ContentEncoding::Gzip);
        assert_eq!(
            ContentEncoding::from_token("chunked"),
            ContentEncoding::Chunked
        );
        // Case-insensitive and whitespace-trimmed.
        assert_eq!(
            ContentEncoding::from_token("  GZip "),
            ContentEncoding::Gzip
        );
        assert_eq!(
            ContentEncoding::from_token("DEFLATE"),
            ContentEncoding::Deflate
        );
        // Genuinely unknown.
        assert_eq!(
            ContentEncoding::from_token("snappy"),
            ContentEncoding::Unknown
        );
    }

    #[test]
    fn from_token_brotli_zstd_track_features() {
        #[cfg(feature = "brotli")]
        assert_eq!(ContentEncoding::from_token("br"), ContentEncoding::Brotli);
        #[cfg(not(feature = "brotli"))]
        assert_eq!(ContentEncoding::from_token("br"), ContentEncoding::Unknown);

        #[cfg(feature = "zstd")]
        assert_eq!(ContentEncoding::from_token("zstd"), ContentEncoding::Zstd);
        #[cfg(not(feature = "zstd"))]
        assert_eq!(
            ContentEncoding::from_token("zstd"),
            ContentEncoding::Unknown
        );
    }

    // ---- single-coding round trips ----------------------------------------

    #[test]
    fn gzip_round_trip() {
        let data = sample();
        let comp = enc_gzip(&data);
        assert!(comp.len() < data.len());
        assert_eq!(decode_all("gzip", &comp).unwrap(), data);
        // Alias and partial feeding.
        assert_eq!(decode_all("x-gzip", &comp).unwrap(), data);
        assert_eq!(decode_byte_by_byte("gzip", &comp).unwrap(), data);
    }

    #[test]
    fn deflate_zlib_round_trip() {
        let data = sample();
        let comp = enc_zlib(&data);
        assert_eq!(decode_all("deflate", &comp).unwrap(), data);
        assert_eq!(decode_byte_by_byte("deflate", &comp).unwrap(), data);
    }

    #[test]
    fn deflate_raw_round_trip_uses_fallback() {
        // Raw DEFLATE (no zlib header) must still decode under "deflate".
        let data = sample();
        let comp = enc_raw_deflate(&data);
        assert_eq!(decode_all("deflate", &comp).unwrap(), data);
        // The zlib-vs-raw decision must also be correct when the first two
        // bytes arrive in separate reads.
        assert_eq!(decode_byte_by_byte("deflate", &comp).unwrap(), data);
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn brotli_round_trip() {
        let data = sample();
        let comp = enc_brotli(&data);
        assert_eq!(decode_all("br", &comp).unwrap(), data);
        assert_eq!(decode_byte_by_byte("br", &comp).unwrap(), data);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn zstd_round_trip() {
        let data = sample();
        let comp = enc_zstd(&data);
        assert_eq!(decode_all("zstd", &comp).unwrap(), data);
        assert_eq!(decode_byte_by_byte("zstd", &comp).unwrap(), data);
    }

    #[test]
    fn identity_is_pass_through() {
        let data = b"plain body, unchanged".to_vec();
        assert_eq!(decode_all("identity", &data).unwrap(), data);
        assert_eq!(decode_all("none", &data).unwrap(), data);
    }

    // ---- chaining / ordering ----------------------------------------------

    #[test]
    fn chained_gzip_then_deflate_decodes_in_reverse() {
        // Content-Encoding: gzip, deflate  =>  codings applied gzip first, then
        // deflate. The wire bytes are deflate(gzip(data)); decoding must undo
        // deflate first, then gzip.
        let data = sample();
        let wire = enc_raw_deflate(&enc_gzip(&data));
        assert_eq!(decode_all("gzip, deflate", &wire).unwrap(), data);
        // Order of the decoders in the built stack: deflate runs first.
        let stack = UnencodingStack::from_content_encoding("gzip, deflate", true).unwrap();
        assert_eq!(
            stack.encodings(),
            &[ContentEncoding::Deflate, ContentEncoding::Gzip]
        );
        assert_eq!(stack.len(), 2);
    }

    #[test]
    fn chained_with_identity_layer() {
        // "identity, gzip" => gzip applied (identity is a no-op layer).
        let data = sample();
        let wire = enc_gzip(&data);
        assert_eq!(decode_all("identity, gzip", &wire).unwrap(), data);
    }

    // ---- decompression-bomb / stack-depth guard ---------------------------

    #[test]
    fn rejects_more_than_max_encodings() {
        // MAX_ENCODE_STACK - 1 (== 4) codings is the most that is accepted.
        let four = "gzip, gzip, gzip, gzip";
        assert!(UnencodingStack::from_content_encoding(four, true).is_ok());
        let five = "gzip, gzip, gzip, gzip, gzip";
        // `UnencodingStack` is intentionally neither `Debug` nor `PartialEq`
        // (it owns `Box<dyn Unencoder>` trait objects), so assert the error
        // variant by matching rather than comparing the whole `Result`.
        match UnencodingStack::from_content_encoding(five, true) {
            Err(e) => assert_eq!(e, CurlError::BadContentEncoding),
            Ok(_) => panic!("expected BadContentEncoding for 5 content encodings"),
        }
    }

    // ---- unknown encoding: deferred error ----------------------------------

    #[test]
    fn unknown_encoding_defers_error_until_body() {
        // Building the stack succeeds (the error is deferred).
        let mut stack = UnencodingStack::from_content_encoding("made-up", true).unwrap();
        assert_eq!(stack.encodings(), &[ContentEncoding::Unknown]);

        // A non-body write and an empty body write do NOT trigger the error.
        let mut out = Vec::new();
        stack
            .write(false, b"X-Header: v", &mut |d| {
                out.extend_from_slice(d);
                Ok(())
            })
            .unwrap();
        stack.write(true, b"", &mut |_d| Ok(())).unwrap();
        assert_eq!(out, b"X-Header: v");

        // The first real body byte yields CURLE_BAD_CONTENT_ENCODING.
        let err = stack.write(true, b"body", &mut |_d| Ok(())).unwrap_err();
        assert_eq!(err, CurlError::BadContentEncoding);
    }

    #[test]
    fn unknown_encoding_without_body_is_ok() {
        // No body at all (e.g. HEAD): build + finish must not error.
        let mut stack = UnencodingStack::from_content_encoding("made-up", true).unwrap();
        assert!(stack.finish(&mut |_d| Ok(())).is_ok());
    }

    // ---- content-decoding disabled: raw pass-through -----------------------

    #[test]
    fn disabled_decoding_passes_raw() {
        let data = sample();
        let comp = enc_gzip(&data);
        // decoding_enabled = false => empty stack, raw bytes pass through.
        let stack = UnencodingStack::from_content_encoding("gzip", false).unwrap();
        assert!(stack.is_empty());
        assert_eq!(decode_chunks("gzip", false, &[&comp]).unwrap(), comp);
    }

    #[test]
    fn non_body_writes_bypass_decoders() {
        // Even with an active gzip decoder, non-body data is forwarded verbatim.
        let mut stack = UnencodingStack::from_content_encoding("gzip", true).unwrap();
        let mut out = Vec::new();
        stack
            .write(false, b"HTTP/1.1 200 OK\r\n", &mut |d| {
                out.extend_from_slice(d);
                Ok(())
            })
            .unwrap();
        assert_eq!(out, b"HTTP/1.1 200 OK\r\n");
    }

    // ---- malformed input errors -------------------------------------------

    #[test]
    fn malformed_gzip_errors() {
        let garbage = vec![b'x'; 64];
        assert_eq!(
            decode_all("gzip", &garbage),
            Err(CurlError::BadContentEncoding)
        );
    }

    #[test]
    fn empty_content_encoding_value_is_pass_through() {
        // An empty / blank header value yields an empty (pass-through) stack.
        let stack = UnencodingStack::from_content_encoding("", true).unwrap();
        assert!(stack.is_empty());
        let stack2 = UnencodingStack::from_content_encoding("  ,  ", true).unwrap();
        assert!(stack2.is_empty());
        let data = b"unencoded".to_vec();
        assert_eq!(decode_all("", &data).unwrap(), data);
    }

    // ---- Accept-Encoding builders -----------------------------------------

    #[test]
    fn supported_content_encodings_order() {
        let s = supported_content_encodings();
        // deflate and gzip are always present, in this order, first.
        assert!(s.starts_with("deflate, gzip"), "got: {s}");

        #[cfg(feature = "brotli")]
        assert!(s.contains("br"), "br missing: {s}");
        #[cfg(not(feature = "brotli"))]
        assert!(!s.contains("br"), "br present unexpectedly: {s}");

        #[cfg(feature = "zstd")]
        assert!(s.contains("zstd"), "zstd missing: {s}");
        #[cfg(not(feature = "zstd"))]
        assert!(!s.contains("zstd"), "zstd present unexpectedly: {s}");

        // identity must never be advertised.
        assert!(!s.split(", ").any(|t| t == "identity"));
    }

    #[test]
    fn accept_encoding_header_semantics() {
        // Unset: no header.
        assert_eq!(accept_encoding_header(None), None);
        // Empty string: advertise everything supported.
        assert_eq!(
            accept_encoding_header(Some("")),
            Some(supported_content_encodings())
        );
        // Explicit value: sent verbatim.
        assert_eq!(
            accept_encoding_header(Some("gzip")),
            Some("gzip".to_string())
        );
        assert_eq!(
            accept_encoding_header(Some("gzip;q=1.0, identity;q=0")),
            Some("gzip;q=1.0, identity;q=0".to_string())
        );
    }

    // ---- sink error propagation -------------------------------------------

    #[test]
    fn sink_errors_propagate() {
        let data = sample();
        let comp = enc_gzip(&data);
        let mut stack = UnencodingStack::from_content_encoding("gzip", true).unwrap();
        let err = stack
            .write(true, &comp, &mut |_d| Err(CurlError::WriteError))
            .unwrap_err();
        assert_eq!(err, CurlError::WriteError);
    }
}
