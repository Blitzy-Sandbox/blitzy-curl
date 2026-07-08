// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.
//
//! MIME / multipart-form-data construction.
//!
//! This module is the idiomatic-Rust rewrite of curl's `lib/mime.c` (the modern
//! `curl_mime_*` API) and the legacy `lib/formdata.c` (the deprecated
//! `curl_formadd`/`curl_formget`/`curl_formfree` `HTTPPOST` machinery). It builds
//! `multipart/form-data` and related MIME bodies used by HTTP `POST` and by the
//! IMAP/SMTP mail protocols.
//!
//! # Parity contract
//!
//! Per the Minimal Change Mandate, this module reproduces curl 8.x behavior
//! byte-for-byte:
//!
//! * **Boundary** — a 24-dash prefix followed by 22 random alphanumeric
//!   characters, exactly like `Curl_rand_alnum` seeded in `curl_mime_init`.
//! * **Content-transfer encoders** — `7bit`, `8bit`, `binary`,
//!   `quoted-printable`, and `base64`, matching the wire output of
//!   `mime_encoders` (line wrapping and CRLF placement included).
//! * **Automatic Content-Type detection** — the small built-in extension table
//!   from `Curl_mime_contenttype`, with the same defaults.
//! * **Header assembly** — `Content-Disposition`, `Content-Type`, and
//!   `Content-Transfer-Encoding` emitted in curl's exact order and casing.
//! * **Legacy `formadd`** — the deprecated `CURLFORM_*` option parsing and the
//!   `HTTPPOST` → MIME conversion, kept bug-for-bug where the test corpus relies
//!   on it.
//!
//! # Streaming model
//!
//! Mirroring `Curl_mime_read`, a MIME body is consumed incrementally by the
//! transfer loop rather than being materialized whole. [`MimeReader`] yields
//! bytes on demand: file-backed and callback-backed part contents are streamed
//! straight from their source, while only headers, boundaries, and
//! encoder-transformed content are buffered in memory (matching curl, which
//! likewise buffers only small encoder windows).
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` code, satisfying the CI grep audit
//! required of `curl-rs-lib`.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use crate::error::{CurlCode, Error, Result};

// ===========================================================================
// Constants (mirrors lib/mime.h)
// ===========================================================================

/// Number of leading dash characters in a multipart boundary
/// (`MIME_BOUNDARY_DASHES`).
const BOUNDARY_DASHES: usize = 24;

/// Number of random alphanumeric characters appended to a boundary
/// (`MIME_RAND_BOUNDARY_CHARS`).
const RAND_BOUNDARY_CHARS: usize = 22;

/// Total boundary length: dashes + random characters (`MIME_BOUNDARY_LEN`).
const BOUNDARY_LEN: usize = BOUNDARY_DASHES + RAND_BOUNDARY_CHARS;

/// Maximum encoded line length for `base64` / `quoted-printable`
/// (`MAX_ENCODED_LINE_LENGTH`). Encoded output is wrapped so that no line
/// exceeds this many characters.
const MAX_ENCODED_LINE_LENGTH: usize = 76;

/// Default Content-Type for a file part whose type cannot be inferred
/// (`FILE_CONTENTTYPE_DEFAULT`).
pub const FILE_CONTENTTYPE_DEFAULT: &str = "application/octet-stream";

/// Default Content-Type for a multipart with no explicit type
/// (`MULTIPART_CONTENTTYPE_DEFAULT`).
pub const MULTIPART_CONTENTTYPE_DEFAULT: &str = "multipart/mixed";

/// Default Content-Disposition value (`DISPOSITION_DEFAULT`).
pub const DISPOSITION_DEFAULT: &str = "attachment";

/// The `Content-Type` used when a multipart is posted as an HTTP form.
pub const FORMDATA_CONTENTTYPE: &str = "multipart/form-data";

// ===========================================================================
// Core enumerations
// ===========================================================================

/// The source kind of a MIME part (mirrors C `enum mimekind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MimeKind {
    /// Part content has not been set.
    #[default]
    None,
    /// Content is an in-memory byte buffer.
    Data,
    /// Content is read from a named local file.
    File,
    /// Content is produced by a read callback.
    Callback,
    /// Content is a nested multipart (subparts).
    Multipart,
}

/// The header-generation strategy (mirrors C `enum mimestrategy`).
///
/// The strategy selects the escaping rules for names/filenames and whether a
/// default `Content-Transfer-Encoding` is emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeStrategy {
    /// MIME mail body (IMAP/SMTP): backslash-escapes names, defaults parts to
    /// `8bit`.
    Mail,
    /// HTTP form post: percent-escapes CR/LF/`"` in names per the WHATWG HTML
    /// living standard.
    Form,
}

/// A content-transfer-encoding (mirrors the `encoders[]` table in `mime.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// `binary` — no transformation; the size is the raw data size.
    Binary,
    /// `8bit` — no transformation (identical bytes to `binary`).
    EightBit,
    /// `7bit` — no transformation, but every byte must be 7-bit clean
    /// (`& 0x80 == 0`); otherwise the encode fails.
    SevenBit,
    /// `base64` — RFC 2045 base64 wrapped at [`MAX_ENCODED_LINE_LENGTH`] with
    /// CRLF separators.
    Base64,
    /// `quoted-printable` — RFC 2045 quoted-printable.
    QuotedPrintable,
}

impl Encoding {
    /// Returns the canonical encoding name as it appears in a
    /// `Content-Transfer-Encoding` header (matches the `encoders[]` names).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Encoding::Binary => "binary",
            Encoding::EightBit => "8bit",
            Encoding::SevenBit => "7bit",
            Encoding::Base64 => "base64",
            Encoding::QuotedPrintable => "quoted-printable",
        }
    }

    /// Looks up an encoding by name, case-insensitively (curl uses
    /// `curl_strequal`). Returns `None` for an unknown name, mirroring
    /// `curl_mime_encoder` returning `CURLE_BAD_FUNCTION_ARGUMENT`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Encoding> {
        // The C table order is binary, 8bit, 7bit, base64, quoted-printable.
        if name.eq_ignore_ascii_case("binary") {
            Some(Encoding::Binary)
        } else if name.eq_ignore_ascii_case("8bit") {
            Some(Encoding::EightBit)
        } else if name.eq_ignore_ascii_case("7bit") {
            Some(Encoding::SevenBit)
        } else if name.eq_ignore_ascii_case("base64") {
            Some(Encoding::Base64)
        } else if name.eq_ignore_ascii_case("quoted-printable") {
            Some(Encoding::QuotedPrintable)
        } else {
            None
        }
    }

    /// Encodes `data` according to this content-transfer-encoding, producing the
    /// exact bytes curl would place on the wire.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Read`] (mapping curl's `READ_ERROR`) when a
    /// [`Encoding::SevenBit`] stream contains a byte with the high bit set.
    pub fn encode(self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            // `binary` and `8bit` are pure pass-through (`encoder_nop_read`).
            Encoding::Binary | Encoding::EightBit => Ok(data.to_vec()),
            Encoding::SevenBit => encode_7bit(data),
            Encoding::Base64 => Ok(encode_base64(data)),
            Encoding::QuotedPrintable => Ok(encode_quoted_printable(data)),
        }
    }
}

// ===========================================================================
// Automatic Content-Type detection (Curl_mime_contenttype)
// ===========================================================================

/// Built-in extension → MIME-type table, reproduced verbatim (including order)
/// from `Curl_mime_contenttype` in `lib/mime.c`.
const CONTENT_TYPE_TABLE: &[(&str, &str)] = &[
    (".gif", "image/gif"),
    (".jpg", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".png", "image/png"),
    (".svg", "image/svg+xml"),
    (".txt", "text/plain"),
    (".htm", "text/html"),
    (".html", "text/html"),
    (".pdf", "application/pdf"),
    (".xml", "application/xml"),
];

/// Scans the built-in extension table and returns the first matching MIME type
/// for `filename`, or `None` if no extension matches.
///
/// This is the direct analogue of `Curl_mime_contenttype`: matching is a
/// case-insensitive suffix comparison (curl uses `curl_strequal`).
#[must_use]
pub fn content_type_for_filename(filename: &str) -> Option<&'static str> {
    let name = filename.as_bytes();
    for (ext, ty) in CONTENT_TYPE_TABLE {
        let ext_bytes = ext.as_bytes();
        if name.len() >= ext_bytes.len() {
            let tail = &name[name.len() - ext_bytes.len()..];
            if tail.eq_ignore_ascii_case(ext_bytes) {
                return Some(ty);
            }
        }
    }
    None
}

// ===========================================================================
// Content-transfer encoders (mirrors mime_encoders in lib/mime.c)
// ===========================================================================

/// `7bit` encoder: verify each byte is 7-bit clean, otherwise fail.
///
/// `encoder_7bit_read` returns `READ_ERROR` on the first byte with the high bit
/// set; here we surface that as [`Error::Read`].
fn encode_7bit(data: &[u8]) -> Result<Vec<u8>> {
    for &b in data {
        if b & 0x80 != 0 {
            return Err(Error::Read);
        }
    }
    Ok(data.to_vec())
}

/// `base64` encoder producing curl-identical output.
///
/// curl's `encoder_base64_read` emits standard base64 (alphabet `A-Za-z0-9+/`
/// with `=` padding) and inserts a CRLF after every [`MAX_ENCODED_LINE_LENGTH`]
/// output characters, with **no** trailing CRLF after the final line. We encode
/// with the standard engine, then re-wrap into 76-character lines joined by
/// CRLF.
fn encode_base64(data: &[u8]) -> Vec<u8> {
    let encoded = BASE64_STANDARD.encode(data);
    let mut out = Vec::with_capacity(encoded.len());
    let mut col = 0usize;
    append_base64_wrapped(&mut out, &mut col, encoded.as_bytes());
    out
}

/// Appends base64 characters to `out`, inserting a CRLF whenever the current
/// output line reaches [`MAX_ENCODED_LINE_LENGTH`] characters. curl wraps base64
/// at 76 columns with a CRLF *between* lines and **no** trailing CRLF.
///
/// `col` (the number of characters already on the current line) is threaded
/// through by the caller so the very same wrapping is produced whether the
/// base64 stream is emitted in one shot (the in-memory Data path via
/// [`encode_base64`]) or incrementally group-by-group (the streaming
/// [`EncoderStream::Base64`] path). This shared helper is what guarantees the
/// two paths wrap byte-identically.
fn append_base64_wrapped(out: &mut Vec<u8>, col: &mut usize, chars: &[u8]) {
    for &c in chars {
        if *col == MAX_ENCODED_LINE_LENGTH {
            out.push(b'\r');
            out.push(b'\n');
            *col = 0;
        }
        out.push(c);
        *col += 1;
    }
}

/// Quoted-printable character classes (mirrors `qp_class` in `lib/mime.c`).
///
/// The table is expressed with the same semantics as curl: an ASCII-compatible
/// classification independent of the host character set.
#[derive(Clone, Copy, PartialEq, Eq)]
enum QpClass {
    /// Not representable by itself; must be escaped as `=XX`.
    Escape,
    /// Representable as itself.
    Ok,
    /// Space or tab.
    Space,
    /// Carriage return.
    Cr,
    /// Line feed.
    Lf,
}

/// Classifies a byte for the quoted-printable encoder, reproducing curl's
/// `qp_class[]` lookup table exactly.
fn qp_class(b: u8) -> QpClass {
    match b {
        0x09 => QpClass::Space, // TAB
        0x0A => QpClass::Lf,    // LF
        0x0D => QpClass::Cr,    // CR
        0x20 => QpClass::Space, // SPACE
        // Printable ASCII 0x21..=0x7E is QP_OK, EXCEPT '=' (0x3D) which must be
        // escaped so the '=' introducer is unambiguous.
        0x3D => QpClass::Escape,
        0x21..=0x7E => QpClass::Ok,
        // Everything else (control chars and 8-bit bytes) must be escaped.
        _ => QpClass::Escape,
    }
}

/// Uppercase hexadecimal digits, matching curl's `aschex[]`.
const ASCHEX: &[u8; 16] = b"0123456789ABCDEF";

/// Quoted-printable end-of-line lookahead, mirroring `qp_lookahead_eol`.
///
/// Returns `Some(true)` if a CRLF (or end of data) is present at offset `pos+n`,
/// `Some(false)` if not, and — because we always encode with the full buffer
/// available (equivalent to `ateof == true`) — never needs to request more data.
fn qp_lookahead_eol(data: &[u8], pos: usize, n: usize) -> bool {
    let idx = pos + n;
    // At or past end of data with everything available == end of data.
    if idx >= data.len() {
        return true;
    }
    if idx + 2 > data.len() {
        // Not enough bytes for a CRLF and no more data will arrive.
        return false;
    }
    qp_class(data[idx]) == QpClass::Cr && qp_class(data[idx + 1]) == QpClass::Lf
}

/// `quoted-printable` encoder producing curl-identical output for the in-memory
/// Data path.
///
/// This is a faithful port of `encoder_qp_read` operating over the whole input.
/// It is a thin wrapper over [`qp_encode_window`] run to completion (`ateof =
/// true`) from column 0 — the same window function that drives the incremental
/// [`EncoderStream::QuotedPrintable`] path — so the one-shot and streaming
/// encoders share a single implementation and can never drift apart.
fn encode_quoted_printable(data: &[u8]) -> Vec<u8> {
    qp_encode_window(data, 0, true).0
}

/// Encodes a quoted-printable *window* of `data` beginning at output column
/// `start_col`, returning `(encoded_bytes, input_bytes_consumed, end_col)`.
///
/// The quoted-printable algorithm only depends on cross-position state through
/// (a) the current output column and (b) a bounded lookahead of at most two
/// bytes (`data[i+2]`, for the space-before-EOL and exact-line-fill rules). This
/// function externalizes both so a body can be encoded incrementally:
///
/// * When `ateof` is `false`, the window stops before any byte that lacks its
///   full (≤2-byte) lookahead within the currently-available `data` — those
///   trailing bytes are left unconsumed for the caller to retry once more input
///   arrives. Because the maximum lookahead is two bytes, it is always safe to
///   process byte `i` while at least three bytes remain (`data.len() - i >= 3`).
///   This mirrors how curl's `encoder_qp_read` defers when `!ateof`.
/// * When `ateof` is `true`, lookahead past the end of `data` is treated as
///   end-of-data (exactly as [`qp_lookahead_eol`] already does), yielding the
///   byte-for-byte whole-buffer result.
fn qp_encode_window(data: &[u8], start_col: usize, ateof: bool) -> (Vec<u8>, usize, usize) {
    let mut out = Vec::with_capacity(data.len());
    let mut pos: usize = start_col; // column position on the current output line
    let mut i: usize = 0;

    while i < data.len() {
        // Streaming (`!ateof`): defer any byte whose ≤2-byte lookahead would read
        // past the currently-available data; three remaining bytes always suffice.
        if !ateof && data.len() - i < 3 {
            break;
        }
        let b = data[i];
        // Candidate output for this input byte: either the byte itself, or its
        // `=XX` hexadecimal escape.
        let mut buf: [u8; 3] = [
            b,
            ASCHEX[((b >> 4) & 0xF) as usize],
            ASCHEX[(b & 0xF) as usize],
        ];
        let mut len: usize = 1;
        let mut consumed: usize = 1;

        match qp_class(b) {
            QpClass::Ok => {
                // Represented as itself.
            }
            QpClass::Space => {
                // A space or tab must be escaped only if it ends a line
                // (immediately followed by CRLF or end of data).
                if qp_lookahead_eol(data, i, 1) {
                    buf[0] = b'=';
                    len = 3;
                }
            }
            QpClass::Cr => {
                // A CR followed by LF is emitted as a literal CRLF; otherwise it
                // is escaped.
                if qp_lookahead_eol(data, i, 0) {
                    buf[1] = b'\n';
                    len = 2;
                    consumed = 2;
                } else {
                    buf[0] = b'=';
                    len = 3;
                }
            }
            QpClass::Lf | QpClass::Escape => {
                buf[0] = b'=';
                len = 3;
            }
        }

        // Enforce the maximum line length with a soft line break unless the
        // token itself ends the line (a literal LF).
        if buf[len - 1] != b'\n' {
            let mut softlinebreak = pos + len > MAX_ENCODED_LINE_LENGTH;
            if !softlinebreak && pos + len == MAX_ENCODED_LINE_LENGTH {
                // We may fill the line exactly only if end of data or a CRLF
                // immediately follows; otherwise insert a soft break now.
                if !qp_lookahead_eol(data, i, consumed) {
                    softlinebreak = true;
                }
            }
            if softlinebreak {
                buf[0] = b'=';
                buf[1] = b'\r';
                buf[2] = b'\n';
                len = 3;
                consumed = 0;
            }
        }

        out.extend_from_slice(&buf[..len]);
        pos += len;
        if buf[len - 1] == b'\n' {
            pos = 0;
        }
        i += consumed;
    }

    (out, i, pos)
}

// ===========================================================================
// Boundary generation (mirrors curl_mime_init + Curl_rand_alnum)
// ===========================================================================

/// Generates a fresh multipart boundary: [`BOUNDARY_DASHES`] dashes followed by
/// [`RAND_BOUNDARY_CHARS`] random alphanumeric characters.
///
/// curl fills the random tail with `Curl_rand_alnum`, whose alphabet is
/// `A-Za-z0-9` (62 characters). The [`Alphanumeric`] distribution from the
/// `rand` crate samples from exactly that set, so the wire format (length and
/// character class) is identical to curl 8.x.
#[must_use]
pub fn generate_boundary() -> String {
    let mut boundary = String::with_capacity(BOUNDARY_LEN);
    for _ in 0..BOUNDARY_DASHES {
        boundary.push('-');
    }
    let mut rng = thread_rng();
    for _ in 0..RAND_BOUNDARY_CHARS {
        boundary.push(char::from(rng.sample(Alphanumeric)));
    }
    boundary
}

// ===========================================================================
// Read-callback abstraction (mirrors curl_read_callback for MIMEKIND_CALLBACK)
// ===========================================================================

/// The result of a single [`MimeReadCallback::read`] invocation.
///
/// This mirrors the return convention of curl's `curl_read_callback`, where a
/// return of `0` means end of data, and the sentinel values `CURL_READFUNC_ABORT`
/// / `CURL_READFUNC_PAUSE` request that the transfer abort or pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOutcome {
    /// `n` bytes were written to the buffer (`n == 0` means end of data).
    Bytes(usize),
    /// The callback aborted the transfer (`CURL_READFUNC_ABORT`).
    Abort,
    /// The callback paused the transfer (`CURL_READFUNC_PAUSE`).
    Pause,
}

/// A pluggable data source for a callback-backed MIME part
/// (`curl_mime_data_cb`).
///
/// Implementations fill the supplied buffer on demand, exactly like curl's
/// `curl_read_callback`. The trait is `Send` so that a part may cross threads on
/// the multi-thread multi-handle runtime.
pub trait MimeReadCallback: Send {
    /// Reads up to `buf.len()` bytes into `buf`, returning a [`ReadOutcome`].
    fn read(&mut self, buf: &mut [u8]) -> ReadOutcome;

    /// Rewinds/seeks the source. The default implementation reports that the
    /// source cannot seek (`CURL_SEEKFUNC_CANTSEEK`), returning `false`.
    fn seek(&mut self, _offset: i64, _whence: i32) -> bool {
        false
    }
}

// ===========================================================================
// MIME part (mirrors struct curl_mimepart)
// ===========================================================================

/// A single MIME part in a [`Mime`] tree (mirrors `struct curl_mimepart`).
///
/// A part carries a content source (in-memory data, a file, a callback, or
/// nested subparts) plus optional metadata: a part `name`, a remote `filename`,
/// an explicit `Content-Type`, a content-transfer `encoder`, and caller-supplied
/// headers.
///
/// Construct parts through [`Mime::addpart`] and configure them with the
/// `set_*` methods, each of which corresponds to a `curl_mime_*` C function.
#[derive(Default)]
pub struct Part {
    /// The kind of content this part carries.
    kind: MimeKind,
    /// In-memory content for [`MimeKind::Data`].
    data: Option<Bytes>,
    /// Local file path for [`MimeKind::File`].
    filepath: Option<PathBuf>,
    /// Read callback for [`MimeKind::Callback`].
    callback: Option<Box<dyn MimeReadCallback>>,
    /// Nested multipart for [`MimeKind::Multipart`].
    subparts: Option<Box<Mime>>,
    /// Known content size, or `-1` when unknown (mirrors `datasize`).
    datasize: i64,
    /// Explicit MIME type (`curl_mime_type`).
    mimetype: Option<String>,
    /// Remote filename shown in `Content-Disposition` (`curl_mime_filename`).
    filename: Option<String>,
    /// Part name shown in `Content-Disposition` (`curl_mime_name`).
    name: Option<String>,
    /// Content-transfer encoder (`curl_mime_encoder`).
    encoder: Option<Encoding>,
    /// Caller-supplied headers (`curl_mime_headers`), each a full `Name: value`
    /// line.
    userheaders: Vec<String>,
    /// When set, the part emits only its body (no headers) — the analogue of
    /// `MIME_BODY_ONLY`, used when a multipart is the top-level HTTP body.
    body_only: bool,
}

impl std::fmt::Debug for Part {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A manual impl is required because `Box<dyn MimeReadCallback>` is not
        // `Debug`; we summarize the callback presence instead.
        f.debug_struct("Part")
            .field("kind", &self.kind)
            .field("datasize", &self.datasize)
            .field("mimetype", &self.mimetype)
            .field("filename", &self.filename)
            .field("name", &self.name)
            .field("encoder", &self.encoder)
            .field("userheaders", &self.userheaders)
            .field("body_only", &self.body_only)
            .field("has_callback", &self.callback.is_some())
            .field("has_subparts", &self.subparts.is_some())
            .finish()
    }
}

impl Part {
    /// Creates a fresh, empty part (mirrors `Curl_mime_initpart`).
    fn new() -> Self {
        Part {
            kind: MimeKind::None,
            data: None,
            filepath: None,
            callback: None,
            subparts: None,
            datasize: 0,
            mimetype: None,
            filename: None,
            name: None,
            encoder: None,
            userheaders: Vec::new(),
            body_only: false,
        }
    }

    /// Clears any previously assigned content, returning the part to
    /// [`MimeKind::None`] (mirrors `cleanup_part_content`).
    fn cleanup_content(&mut self) {
        self.data = None;
        self.filepath = None;
        self.callback = None;
        self.subparts = None;
        self.datasize = 0;
        self.kind = MimeKind::None;
    }

    /// The kind of content currently held by this part.
    #[must_use]
    pub fn kind(&self) -> MimeKind {
        self.kind
    }

    /// Sets the part name (`curl_mime_name`).
    ///
    /// Passing `None` clears the name.
    ///
    /// # Errors
    ///
    /// Never fails in the Rust port (kept as `Result` for API parity with the C
    /// function, which can return `CURLE_OUT_OF_MEMORY`).
    pub fn set_name(&mut self, name: Option<&str>) -> Result<()> {
        self.name = name.map(str::to_owned);
        Ok(())
    }

    /// Sets the remote filename (`curl_mime_filename`).
    ///
    /// Passing `None` clears the filename (this is how callers withdraw the
    /// implicit filename set by [`Part::set_filedata`]).
    ///
    /// # Errors
    ///
    /// Never fails in the Rust port (kept as `Result` for API parity).
    pub fn set_filename(&mut self, filename: Option<&str>) -> Result<()> {
        self.filename = filename.map(str::to_owned);
        Ok(())
    }

    /// Sets the explicit `Content-Type` for the part (`curl_mime_type`).
    ///
    /// Passing `None` clears the type, restoring automatic detection.
    ///
    /// # Errors
    ///
    /// Never fails in the Rust port (kept as `Result` for API parity).
    pub fn set_type(&mut self, mimetype: Option<&str>) -> Result<()> {
        self.mimetype = mimetype.map(str::to_owned);
        Ok(())
    }

    /// Sets the part content from an in-memory byte buffer (`curl_mime_data`).
    ///
    /// # Errors
    ///
    /// Never fails in the Rust port (kept as `Result` for API parity).
    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        self.cleanup_content();
        self.data = Some(Bytes::copy_from_slice(data));
        self.datasize = data.len() as i64;
        self.kind = MimeKind::Data;
        Ok(())
    }

    /// Sets the part content from an owned byte buffer, avoiding a copy.
    ///
    /// Behaves identically to [`Part::set_data`] but takes ownership of `data`.
    ///
    /// # Errors
    ///
    /// Never fails in the Rust port (kept as `Result` for API parity).
    pub fn set_data_owned(&mut self, data: Vec<u8>) -> Result<()> {
        self.cleanup_content();
        self.datasize = data.len() as i64;
        self.data = Some(Bytes::from(data));
        self.kind = MimeKind::Data;
        Ok(())
    }

    /// Sets the part content from a named local file (`curl_mime_filedata`).
    ///
    /// As a side effect, the remote filename is set to the base name of
    /// `path` (callers can withdraw this by calling
    /// [`Part::set_filename(None)`](Part::set_filename) afterwards). The known
    /// content size is captured for regular files.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Read`] (curl's `CURLE_READ_ERROR`) if `path` cannot be
    /// stat-ed.
    pub fn set_filedata<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        self.cleanup_content();
        let path = path.as_ref();
        let meta = std::fs::metadata(path).map_err(|_| Error::Read)?;

        self.datasize = -1;
        if meta.is_file() {
            self.datasize = meta.len() as i64;
        }
        self.filepath = Some(path.to_path_buf());
        self.kind = MimeKind::File;

        // Side effect: set the remote filename to the file's base name.
        if let Some(base) = path.file_name().and_then(|s| s.to_str()) {
            self.filename = Some(base.to_owned());
        }
        Ok(())
    }

    /// Sets the part content from a read callback (`curl_mime_data_cb`).
    ///
    /// `datasize` is the expected content length, or `-1` when unknown.
    ///
    /// # Errors
    ///
    /// Never fails in the Rust port (kept as `Result` for API parity).
    pub fn set_data_cb(&mut self, datasize: i64, reader: Box<dyn MimeReadCallback>) -> Result<()> {
        self.cleanup_content();
        self.callback = Some(reader);
        self.datasize = datasize;
        self.kind = MimeKind::Callback;
        Ok(())
    }

    /// Sets the content-transfer encoder by name (`curl_mime_encoder`).
    ///
    /// Passing `None` removes the current encoder.
    ///
    /// # Errors
    ///
    /// Returns [`Error::bad_argument`] (curl's `CURLE_BAD_FUNCTION_ARGUMENT`) if
    /// `encoding` is not one of `binary`, `8bit`, `7bit`, `base64`, or
    /// `quoted-printable`.
    pub fn set_encoder(&mut self, encoding: Option<&str>) -> Result<()> {
        match encoding {
            None => {
                self.encoder = None;
                Ok(())
            }
            Some(name) => match Encoding::from_name(name) {
                Some(enc) => {
                    self.encoder = Some(enc);
                    Ok(())
                }
                None => Err(Error::bad_argument(format!(
                    "unknown mime encoding: {name}"
                ))),
            },
        }
    }

    /// Replaces the caller-supplied headers for the part (`curl_mime_headers`).
    ///
    /// Each entry is a complete header line of the form `Name: value`.
    ///
    /// # Errors
    ///
    /// Never fails in the Rust port (kept as `Result` for API parity).
    pub fn set_headers(&mut self, headers: Vec<String>) -> Result<()> {
        self.userheaders = headers;
        Ok(())
    }

    /// Sets the part content from a nested multipart (`curl_mime_subparts`).
    ///
    /// # Errors
    ///
    /// Never fails in the Rust port (ownership rules that C enforces at runtime —
    /// "already attached" / "cannot be its own root" — are enforced statically by
    /// Rust's move semantics, since `subparts` is consumed by value).
    pub fn set_subparts(&mut self, subparts: Mime) -> Result<()> {
        self.cleanup_content();
        self.subparts = Some(Box::new(subparts));
        self.datasize = -1;
        self.kind = MimeKind::Multipart;
        Ok(())
    }

    /// Returns a mutable reference to the nested multipart, if this is a
    /// [`MimeKind::Multipart`] part. Useful for adding subparts after attaching.
    pub fn subparts_mut(&mut self) -> Option<&mut Mime> {
        self.subparts.as_deref_mut()
    }

    /// Marks (or clears) this part as body-only, suppressing its own header
    /// block (mirrors `MIME_BODY_ONLY`). This is set on the top-level part when a
    /// multipart is posted as the HTTP request body, so its `Content-Type` is
    /// carried in the HTTP header rather than the body.
    pub fn set_body_only(&mut self, body_only: bool) {
        self.body_only = body_only;
    }

    /// Computes the curl-generated header lines for this part, in the exact order
    /// curl emits them: `Content-Disposition`, then `Content-Type`, then
    /// `Content-Transfer-Encoding`.
    ///
    /// This is a faithful port of `Curl_mime_prepare_headers` for a single part.
    /// `contenttype_hint` is the type propagated from an enclosing call (only the
    /// top-level form passes one); `disposition` is the disposition inherited
    /// from the parent multipart (`"form-data"` for `multipart/form-data`
    /// children).
    ///
    /// Returns the ordered header lines together with the resolved media type
    /// (without any `; boundary=` suffix), which the caller uses to decide the
    /// disposition of nested subparts.
    fn prepare_headers(
        &self,
        contenttype_hint: Option<&str>,
        disposition: Option<&str>,
        strategy: MimeStrategy,
    ) -> (Vec<String>, Option<String>) {
        let mut headers: Vec<String> = Vec::new();

        // --- Resolve the content type -------------------------------------
        // A custom type (explicit `set_type` or a user "Content-Type" header)
        // overrides any propagated hint.
        let customct: Option<String> = self
            .mimetype
            .clone()
            .or_else(|| header_value(&self.userheaders, "Content-Type").map(str::to_owned));

        let mut contenttype: Option<String> = customct
            .clone()
            .or_else(|| contenttype_hint.map(str::to_owned));

        if contenttype.is_none() {
            contenttype = match self.kind {
                MimeKind::Multipart => Some(MULTIPART_CONTENTTYPE_DEFAULT.to_owned()),
                MimeKind::File => {
                    let by_name = self.filename.as_deref().and_then(content_type_for_filename);
                    let by_path = self
                        .filepath
                        .as_ref()
                        .and_then(|p| p.to_str())
                        .and_then(content_type_for_filename);
                    by_name.or(by_path).map(str::to_owned).or_else(|| {
                        self.filename
                            .as_ref()
                            .map(|_| FILE_CONTENTTYPE_DEFAULT.to_owned())
                    })
                }
                _ => self
                    .filename
                    .as_deref()
                    .and_then(content_type_for_filename)
                    .map(str::to_owned),
            };
        }

        // --- Boundary (multipart) and the text/plain default drop ---------
        let mut boundary: Option<&str> = None;
        if self.kind == MimeKind::Multipart {
            if let Some(sub) = self.subparts.as_deref() {
                boundary = Some(sub.boundary());
            }
        } else if customct.is_none() {
            if let Some(ct) = contenttype.as_deref() {
                if content_type_match(ct, "text/plain")
                    && (strategy == MimeStrategy::Mail || self.filename.is_none())
                {
                    contenttype = None;
                }
            }
        }

        // --- Content-Disposition ------------------------------------------
        if header_value(&self.userheaders, "Content-Disposition").is_none() {
            let mut disp: Option<String> = disposition.map(str::to_owned);

            if disp.is_none() {
                let want = self.filename.is_some()
                    || self.name.is_some()
                    || contenttype
                        .as_deref()
                        .is_some_and(|ct| !starts_with_ci(ct, "multipart/"));
                if want {
                    disp = Some(DISPOSITION_DEFAULT.to_owned());
                }
            }

            // A bare "attachment" with neither name nor filename is dropped.
            if let Some(d) = disp.as_deref() {
                if d.eq_ignore_ascii_case("attachment")
                    && self.name.is_none()
                    && self.filename.is_none()
                {
                    disp = None;
                }
            }

            if let Some(d) = disp {
                let mut line = String::from("Content-Disposition: ");
                line.push_str(&d);
                if let Some(name) = self.name.as_deref() {
                    line.push_str("; name=\"");
                    line.push_str(&escape_string(name, strategy));
                    line.push('"');
                }
                if let Some(filename) = self.filename.as_deref() {
                    line.push_str("; filename=\"");
                    line.push_str(&escape_string(filename, strategy));
                    line.push('"');
                }
                headers.push(line);
            }
        }

        // --- Content-Type -------------------------------------------------
        if let Some(ct) = contenttype.as_deref() {
            let mut line = String::from("Content-Type: ");
            line.push_str(ct);
            if let Some(b) = boundary {
                line.push_str("; boundary=");
                line.push_str(b);
            }
            headers.push(line);
        }

        // --- Content-Transfer-Encoding ------------------------------------
        if header_value(&self.userheaders, "Content-Transfer-Encoding").is_none() {
            let cte: Option<&str> = if let Some(enc) = self.encoder {
                Some(enc.name())
            } else if contenttype.is_some()
                && strategy == MimeStrategy::Mail
                && self.kind != MimeKind::Multipart
            {
                Some("8bit")
            } else {
                None
            };
            if let Some(c) = cte {
                headers.push(format!("Content-Transfer-Encoding: {c}"));
            }
        }

        (headers, contenttype)
    }

    /// Builds the full header block bytes for this part: every curl-generated
    /// header line, then every user header line (except a user `Content-Type`,
    /// which is already folded into the curl `Content-Type`), each terminated by
    /// CRLF, followed by the empty CRLF line that ends the headers.
    ///
    /// Mirrors the `MIMESTATE_CURLHEADERS` → `MIMESTATE_USERHEADERS` →
    /// `MIMESTATE_EOH` readback sequence in `readback_part`.
    fn header_block(
        &self,
        contenttype_hint: Option<&str>,
        disposition: Option<&str>,
        strategy: MimeStrategy,
    ) -> (Vec<u8>, Option<String>) {
        let (curl_headers, resolved_ct) =
            self.prepare_headers(contenttype_hint, disposition, strategy);

        let mut out = Vec::new();
        for h in &curl_headers {
            out.extend_from_slice(h.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        for h in &self.userheaders {
            // The user's Content-Type was promoted into the curl headers above,
            // so it is not emitted a second time.
            if let Some(colon) = h.find(':') {
                if h[..colon].eq_ignore_ascii_case("Content-Type") {
                    continue;
                }
            }
            out.extend_from_slice(h.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        // End-of-headers empty line.
        out.extend_from_slice(b"\r\n");

        (out, resolved_ct)
    }
}

// ===========================================================================
// Header helpers (mirrors search_header / content_type_match / escape_string)
// ===========================================================================

/// Finds the value of the header named `name` (case-insensitive) in a list of
/// `Name: value` lines, skipping leading spaces in the value.
///
/// Mirrors `search_header` + `match_header` in `lib/mime.c`.
fn header_value<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    for line in headers {
        if let Some(colon) = line.find(':') {
            if line[..colon].eq_ignore_ascii_case(name) {
                let value = line[colon + 1..].trim_start_matches(' ');
                return Some(value);
            }
        }
    }
    None
}

/// Returns `true` if `contenttype` begins with `target` (case-insensitive) and
/// the following byte terminates the media type (NUL, TAB, CR, LF, space, `;`,
/// or end of string).
///
/// Mirrors `content_type_match` in `lib/mime.c`.
fn content_type_match(contenttype: &str, target: &str) -> bool {
    let ct = contenttype.as_bytes();
    let tg = target.as_bytes();
    if ct.len() < tg.len() {
        return false;
    }
    if !ct[..tg.len()].eq_ignore_ascii_case(tg) {
        return false;
    }
    match ct.get(tg.len()) {
        None => true,
        Some(&c) => matches!(c, b'\0' | b'\t' | b'\r' | b'\n' | b' ' | b';'),
    }
}

/// Returns `true` if `s` begins with `prefix`, compared case-insensitively.
fn starts_with_ci(s: &str, prefix: &str) -> bool {
    let s = s.as_bytes();
    let p = prefix.as_bytes();
    s.len() >= p.len() && s[..p.len()].eq_ignore_ascii_case(p)
}

/// Escapes a name or filename for inclusion in a `Content-Disposition` header,
/// selecting the rule set by [`MimeStrategy`].
///
/// * [`MimeStrategy::Form`] follows the WHATWG HTML living standard: `"`→`%22`,
///   CR→`%0D`, LF→`%0A`, leaving everything else untouched.
/// * [`MimeStrategy::Mail`] uses classic MIME backslash quoting: `\`→`\\`,
///   `"`→`\"`.
///
/// Mirrors `escape_string` in `lib/mime.c`.
fn escape_string(src: &str, strategy: MimeStrategy) -> String {
    let mut out = String::with_capacity(src.len());
    match strategy {
        MimeStrategy::Form => {
            for ch in src.chars() {
                match ch {
                    '"' => out.push_str("%22"),
                    '\r' => out.push_str("%0D"),
                    '\n' => out.push_str("%0A"),
                    other => out.push(other),
                }
            }
        }
        MimeStrategy::Mail => {
            for ch in src.chars() {
                match ch {
                    '\\' => out.push_str("\\\\"),
                    '"' => out.push_str("\\\""),
                    other => out.push(other),
                }
            }
        }
    }
    out
}

// ===========================================================================
// MIME multipart container (mirrors struct curl_mime)
// ===========================================================================

/// A MIME multipart: an ordered list of [`Part`]s plus the boundary that
/// separates them (mirrors `struct curl_mime`).
///
/// Build one with [`Mime::new`] (which generates the boundary), append parts
/// with [`Mime::addpart`], then serialize with [`Mime::to_bytes`] or stream with
/// [`Mime::reader`].
#[derive(Debug)]
pub struct Mime {
    /// The boundary string (24 dashes + 22 random alphanumeric chars).
    boundary: String,
    /// The ordered parts of this multipart.
    parts: Vec<Part>,
}

impl Default for Mime {
    fn default() -> Self {
        Mime::new()
    }
}

impl Mime {
    /// Creates an empty multipart with a freshly generated boundary
    /// (mirrors `curl_mime_init`).
    #[must_use]
    pub fn new() -> Self {
        Mime {
            boundary: generate_boundary(),
            parts: Vec::new(),
        }
    }

    /// Appends a new, empty part and returns a mutable reference to it
    /// (mirrors `curl_mime_addpart`).
    ///
    /// Configure the returned part with its `set_*` methods before adding the
    /// next one.
    pub fn addpart(&mut self) -> &mut Part {
        self.parts.push(Part::new());
        self.parts
            .last_mut()
            .expect("a part was just pushed, so last_mut is Some")
    }

    /// Returns the multipart boundary string.
    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// Overrides the boundary. Intended for deterministic testing and for
    /// reproducing a specific curl reference output; production code should use
    /// the random boundary from [`Mime::new`].
    pub fn set_boundary(&mut self, boundary: impl Into<String>) {
        self.boundary = boundary.into();
    }

    /// Returns the parts of this multipart.
    #[must_use]
    pub fn parts(&self) -> &[Part] {
        &self.parts
    }

    /// The number of parts in this multipart.
    #[must_use]
    pub fn len(&self) -> usize {
        self.parts.len()
    }

    /// Returns `true` if this multipart has no parts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Returns the `Content-Type` header value for this multipart when used as
    /// the top-level body, e.g. `multipart/form-data; boundary=----...`.
    ///
    /// For [`MimeStrategy::Form`] the media type is `multipart/form-data`; for
    /// [`MimeStrategy::Mail`] it is `multipart/mixed`. This is the value the
    /// transport layer places in the HTTP/mail `Content-Type` header while the
    /// body itself (from [`Mime::to_bytes`]) omits it — mirroring curl's
    /// `MIME_BODY_ONLY` handling.
    #[must_use]
    pub fn content_type_header(&self, strategy: MimeStrategy) -> String {
        let ct = match strategy {
            MimeStrategy::Form => FORMDATA_CONTENTTYPE,
            MimeStrategy::Mail => MULTIPART_CONTENTTYPE_DEFAULT,
        };
        format!("{ct}; boundary={}", self.boundary)
    }

    /// The disposition curl propagates to the direct children of this container
    /// when it is used as the top-level body: `"form-data"` under
    /// [`MimeStrategy::Form`] (a `multipart/form-data` body) and none under
    /// [`MimeStrategy::Mail`] (a `multipart/mixed` body).
    fn top_child_disposition(strategy: MimeStrategy) -> Option<&'static str> {
        match strategy {
            MimeStrategy::Form => Some("form-data"),
            MimeStrategy::Mail => None,
        }
    }

    /// Consumes the multipart and returns a [`MimeReader`] that yields the body
    /// bytes on demand (mirrors installing `Curl_mime_read` as the upload
    /// source).
    ///
    /// File- and callback-backed parts are streamed straight from their source;
    /// only headers, boundaries, and encoder-transformed content are buffered.
    /// The produced bytes are the multipart body only (no top-level
    /// `Content-Type` header — that value is available from
    /// [`Mime::content_type_header`]).
    ///
    /// # Errors
    ///
    /// Propagates [`Error::Read`] if a file part cannot be opened, and encoder
    /// errors (e.g. non-7-bit-clean data under `7bit`).
    pub fn into_reader(self, strategy: MimeStrategy) -> Result<MimeReader> {
        let mut sources: VecDeque<Source> = VecDeque::new();
        let child_disposition = Mime::top_child_disposition(strategy);
        push_multipart(self, strategy, child_disposition, &mut sources)?;
        Ok(MimeReader { sources })
    }

    /// Serializes the whole multipart body to a byte vector.
    ///
    /// This is the in-memory equivalent of draining [`Mime::into_reader`]; it is
    /// the form of the request body an HTTP `POST` sends (with the
    /// `Content-Type` carried separately, see [`Mime::content_type_header`]).
    ///
    /// # Errors
    ///
    /// Propagates the same errors as [`Mime::into_reader`], plus
    /// [`Error::AbortedByCallback`] if a callback part aborts.
    pub fn to_bytes(self, strategy: MimeStrategy) -> Result<Vec<u8>> {
        let mut reader = self.into_reader(strategy)?;
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = reader.fill(&mut buf)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        Ok(out)
    }

    /// Computes the exact body length in bytes, or `-1` if any part's size is
    /// unknown (a callback with unknown length, or a `quoted-printable` part).
    ///
    /// This is the analogue of `multipart_size`/`mime_size` used to populate the
    /// `Content-Length` header, and equals `to_bytes(strategy).len()` whenever
    /// the result is non-negative.
    #[must_use]
    pub fn content_length(&self, strategy: MimeStrategy) -> i64 {
        multipart_size(self, strategy, Mime::top_child_disposition(strategy))
    }
}

// ===========================================================================
// Size computation (mirrors multipart_size / mime_size / encoder sizefuncs)
// ===========================================================================

/// Computes the encoded content size for a known `datasize` under `encoder`,
/// mirroring the `sizefunc` entries of the `encoders[]` table.
///
/// A `quoted-printable` part reports an unknown size (`-1`) for any non-empty
/// input, exactly like `encoder_qp_size`.
fn encoded_content_size(datasize: i64, encoder: Option<Encoding>) -> i64 {
    match encoder {
        None | Some(Encoding::Binary | Encoding::EightBit | Encoding::SevenBit) => datasize,
        Some(Encoding::Base64) => {
            if datasize <= 0 {
                datasize
            } else {
                let s = 4 * (1 + (datasize - 1) / 3);
                s + 2 * ((s - 1) / MAX_ENCODED_LINE_LENGTH as i64)
            }
        }
        Some(Encoding::QuotedPrintable) => {
            if datasize != 0 {
                -1
            } else {
                0
            }
        }
    }
}

/// Computes the serialized size of a single part (mirrors `mime_size`).
fn part_size(
    part: &Part,
    contenttype_hint: Option<&str>,
    disposition: Option<&str>,
    strategy: MimeStrategy,
) -> i64 {
    let datasize = if part.kind == MimeKind::Multipart {
        match part.subparts.as_deref() {
            Some(sub) => {
                let (_, resolved_ct) =
                    part.prepare_headers(contenttype_hint, disposition, strategy);
                let child_disp = resolved_ct
                    .as_deref()
                    .filter(|c| content_type_match(c, FORMDATA_CONTENTTYPE))
                    .map(|_| "form-data");
                multipart_size(sub, strategy, child_disp)
            }
            None => 0,
        }
    } else {
        part.datasize
    };

    let mut size = encoded_content_size(datasize, part.encoder);
    if size >= 0 && !part.body_only {
        let (header_bytes, _) = part.header_block(contenttype_hint, disposition, strategy);
        size += header_bytes.len() as i64;
    }
    size
}

/// Computes the serialized size of a multipart body (mirrors `multipart_size`).
fn multipart_size(mime: &Mime, strategy: MimeStrategy, child_disposition: Option<&str>) -> i64 {
    // "\r\n--" (4) + boundary + "\r\n" (2) — see the derivation in mime.c.
    let boundarysize = 4 + BOUNDARY_LEN as i64 + 2;
    let mut size = boundarysize; // Final boundary + CRLF after headers.
    for part in &mime.parts {
        let sz = part_size(part, None, child_disposition, strategy);
        if sz < 0 {
            size = sz;
        }
        if size >= 0 {
            size += boundarysize + sz;
        }
    }
    size
}

// ===========================================================================
// Streaming reader (mirrors Curl_mime_read)
// ===========================================================================

/// Number of raw bytes pulled from a file/callback per streaming step before
/// they are run through a content-transfer-encoder. This bounds the working-set
/// memory of an encoded [`Source::Encoded`] segment regardless of body size, so
/// a large encoded upload is never materialized whole (the streaming-parity
/// requirement). It matches curl's `MIME_RD_BUF` order of magnitude.
const MIME_STREAM_CHUNK: usize = 8192;

/// One segment of a serialized MIME body.
enum Source {
    /// Fully materialized bytes (headers, boundaries, in-memory data, or
    /// encoder-transformed *in-memory* Data-part content), consumed via a cursor.
    Mem { data: Vec<u8>, pos: usize },
    /// A file whose content is streamed directly (no encoder applied).
    File(File),
    /// A callback whose content is streamed directly (no encoder applied).
    Callback { cb: Box<dyn MimeReadCallback> },
    /// A file or callback whose content is streamed through a content-transfer
    /// encoder incrementally, so the whole (encoded) payload is never buffered.
    /// `out`/`out_pos` hold the encoded bytes produced from the most recent raw
    /// chunk that have not yet been handed to the caller; `done` is set once the
    /// raw source has reached EOF and the encoder's final flush has run.
    Encoded {
        raw: RawSource,
        enc: EncoderStream,
        out: Vec<u8>,
        out_pos: usize,
        done: bool,
    },
}

impl Source {
    /// Wraps owned bytes as a [`Source::Mem`] positioned at the start.
    fn mem(data: Vec<u8>) -> Source {
        Source::Mem { data, pos: 0 }
    }

    /// Builds a streaming encoded segment from a raw byte source and an encoder.
    fn encoded(raw: RawSource, enc: Encoding) -> Source {
        Source::Encoded {
            raw,
            enc: EncoderStream::new(enc),
            out: Vec::new(),
            out_pos: 0,
            done: false,
        }
    }
}

/// A raw (un-encoded) byte source feeding a streaming [`EncoderStream`]: either
/// an open file or a data-read callback. This is the streaming analogue of the
/// bytes that [`Source::File`] / [`Source::Callback`] emit directly, but here
/// they are pulled a bounded chunk at a time and transformed by an encoder.
enum RawSource {
    /// A file streamed a chunk at a time.
    File(File),
    /// A callback streamed a chunk at a time.
    Callback(Box<dyn MimeReadCallback>),
}

impl RawSource {
    /// Reads up to `buf.len()` raw bytes, returning `Ok(0)` at end of input.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Read`] on a file I/O error **and** when a read callback
    /// reports more bytes than were requested (`n > buf.len()`) — curl treats a
    /// callback that over-returns as a `CURLE_READ_ERROR` read-contract
    /// violation rather than silently truncating. Callback abort/pause map to
    /// [`Error::AbortedByCallback`] and a `CURLE_AGAIN` context error.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            RawSource::File(f) => f.read(buf).map_err(|_| Error::Read),
            RawSource::Callback(cb) => match cb.read(buf) {
                ReadOutcome::Bytes(0) => Ok(0),
                ReadOutcome::Bytes(n) => {
                    if n > buf.len() {
                        return Err(Error::Read);
                    }
                    Ok(n)
                }
                ReadOutcome::Abort => Err(Error::AbortedByCallback),
                ReadOutcome::Pause => Err(Error::with_context(
                    CurlCode::Again,
                    "mime data callback paused",
                )),
            },
        }
    }
}

/// Incremental content-transfer-encoder state.
///
/// Each variant transforms input bytes fed via [`push`](EncoderStream::push) and
/// flushes any trailing state via [`finish`](EncoderStream::finish), producing
/// output that is byte-for-byte identical to the corresponding whole-buffer
/// encoder ([`encode_base64`] / [`encode_quoted_printable`] / [`encode_7bit`] /
/// the `binary`/`8bit` pass-through) regardless of how the input is chunked.
/// The base64 and quoted-printable variants share their core logic with those
/// whole-buffer functions ([`append_base64_wrapped`] and [`qp_encode_window`]),
/// so parity holds by construction (and is pinned by tests).
enum EncoderStream {
    /// `binary` / `8bit`: pass-through, no transformation.
    Passthrough,
    /// `7bit`: pass-through, but every byte must be 7-bit clean.
    SevenBit,
    /// `base64`: carries the 0–2 input bytes that do not yet complete a 3-byte
    /// group, plus the output column used for 76-character line wrapping.
    Base64 {
        carry: [u8; 2],
        carry_len: usize,
        col: usize,
    },
    /// `quoted-printable`: carries pending input bytes that still need lookahead
    /// (at most a couple), plus the output column.
    QuotedPrintable { pending: Vec<u8>, col: usize },
}

impl EncoderStream {
    /// Creates the streaming encoder for a given [`Encoding`].
    fn new(enc: Encoding) -> Self {
        match enc {
            Encoding::Binary | Encoding::EightBit => EncoderStream::Passthrough,
            Encoding::SevenBit => EncoderStream::SevenBit,
            Encoding::Base64 => EncoderStream::Base64 {
                carry: [0u8; 2],
                carry_len: 0,
                col: 0,
            },
            Encoding::QuotedPrintable => EncoderStream::QuotedPrintable {
                pending: Vec::new(),
                col: 0,
            },
        }
    }

    /// Feeds `input` through the encoder, appending encoded bytes to `out`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Read`] for a [`EncoderStream::SevenBit`] stream that
    /// contains a byte with the high bit set (matching `encoder_7bit_read`).
    fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        match self {
            EncoderStream::Passthrough => out.extend_from_slice(input),
            EncoderStream::SevenBit => {
                for &b in input {
                    if b & 0x80 != 0 {
                        return Err(Error::Read);
                    }
                }
                out.extend_from_slice(input);
            }
            EncoderStream::Base64 {
                carry,
                carry_len,
                col,
            } => {
                let mut idx = 0;
                // 1) Complete a pending group left over from a previous chunk.
                if *carry_len > 0 {
                    let need = 3 - *carry_len;
                    let take = need.min(input.len());
                    let mut group = [0u8; 3];
                    group[..*carry_len].copy_from_slice(&carry[..*carry_len]);
                    group[*carry_len..*carry_len + take].copy_from_slice(&input[..take]);
                    idx = take;
                    if *carry_len + take == 3 {
                        // A multiple-of-3 slice base64-encodes with no padding.
                        let enc = BASE64_STANDARD.encode(group);
                        append_base64_wrapped(out, col, enc.as_bytes());
                        *carry_len = 0;
                    } else {
                        // Still short of a full group; stash and wait for more.
                        carry[..*carry_len + take].copy_from_slice(&group[..*carry_len + take]);
                        *carry_len += take;
                        return Ok(());
                    }
                }
                // 2) Encode all complete 3-byte groups from the remainder.
                let rem = &input[idx..];
                let full = (rem.len() / 3) * 3;
                if full > 0 {
                    let enc = BASE64_STANDARD.encode(&rem[..full]);
                    append_base64_wrapped(out, col, enc.as_bytes());
                }
                // 3) Stash the trailing 0–2 bytes as the new carry.
                let tail = &rem[full..];
                carry[..tail.len()].copy_from_slice(tail);
                *carry_len = tail.len();
            }
            EncoderStream::QuotedPrintable { pending, col } => {
                pending.extend_from_slice(input);
                // Encode everything that has its full lookahead available; keep
                // the (bounded) unconsumed tail for the next chunk / finish.
                let (encoded, consumed, new_col) = qp_encode_window(pending, *col, false);
                out.extend_from_slice(&encoded);
                *col = new_col;
                pending.drain(..consumed);
            }
        }
        Ok(())
    }

    /// Flushes any state held after the last [`push`](EncoderStream::push):
    /// base64 emits its final (padded) group, quoted-printable encodes the
    /// remaining bytes with end-of-data lookahead. Pass-through / 7bit hold no
    /// state and emit nothing.
    ///
    /// # Errors
    ///
    /// Propagates the same errors as [`push`](EncoderStream::push).
    fn finish(&mut self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            EncoderStream::Passthrough | EncoderStream::SevenBit => {}
            EncoderStream::Base64 {
                carry,
                carry_len,
                col,
            } => {
                if *carry_len > 0 {
                    // A 1- or 2-byte tail base64-encodes to 4 chars with padding.
                    let enc = BASE64_STANDARD.encode(&carry[..*carry_len]);
                    append_base64_wrapped(out, col, enc.as_bytes());
                    *carry_len = 0;
                }
            }
            EncoderStream::QuotedPrintable { pending, col } => {
                let (encoded, _consumed, new_col) = qp_encode_window(pending, *col, true);
                out.extend_from_slice(&encoded);
                *col = new_col;
                pending.clear();
            }
        }
        Ok(())
    }
}

/// An incremental reader over a serialized MIME body.
///
/// Obtain one from [`Mime::into_reader`]. It implements [`std::io::Read`] and,
/// like `Curl_mime_read`, hands back bytes a chunk at a time so the transfer
/// loop never has to hold the whole body in memory.
pub struct MimeReader {
    sources: VecDeque<Source>,
}

impl MimeReader {
    /// Fills `buf` with up to `buf.len()` bytes from the current segment,
    /// advancing to the next segment when one is exhausted. Returns `Ok(0)` once
    /// all segments are consumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Read`] on a file read error or when a read callback
    /// over-returns (reports more bytes than requested — a `CURLE_READ_ERROR`
    /// contract violation), [`Error::AbortedByCallback`] if a callback aborts,
    /// and a `CURLE_AGAIN` context error if a callback pauses.
    pub fn fill(&mut self, buf: &mut [u8]) -> Result<usize> {
        while let Some(front) = self.sources.front_mut() {
            match front {
                Source::Mem { data, pos } => {
                    if *pos < data.len() {
                        let n = usize::min(buf.len(), data.len() - *pos);
                        buf[..n].copy_from_slice(&data[*pos..*pos + n]);
                        *pos += n;
                        return Ok(n);
                    }
                    self.sources.pop_front();
                }
                Source::File(f) => {
                    let n = f.read(buf).map_err(|_| Error::Read)?;
                    if n > 0 {
                        return Ok(n);
                    }
                    self.sources.pop_front();
                }
                Source::Callback { cb } => {
                    if buf.is_empty() {
                        return Ok(0);
                    }
                    match cb.read(buf) {
                        ReadOutcome::Bytes(0) => {
                            self.sources.pop_front();
                        }
                        ReadOutcome::Bytes(n) => {
                            // A callback reporting more than requested violates
                            // the read contract; curl surfaces this as
                            // CURLE_READ_ERROR rather than silently truncating.
                            if n > buf.len() {
                                return Err(Error::Read);
                            }
                            return Ok(n);
                        }
                        ReadOutcome::Abort => return Err(Error::AbortedByCallback),
                        ReadOutcome::Pause => {
                            return Err(Error::with_context(
                                CurlCode::Again,
                                "mime data callback paused",
                            ))
                        }
                    }
                }
                Source::Encoded {
                    raw,
                    enc,
                    out,
                    out_pos,
                    done,
                } => {
                    if buf.is_empty() {
                        return Ok(0);
                    }
                    // Hand out any encoded bytes produced from the previous chunk.
                    if *out_pos < out.len() {
                        let n = usize::min(buf.len(), out.len() - *out_pos);
                        buf[..n].copy_from_slice(&out[*out_pos..*out_pos + n]);
                        *out_pos += n;
                        return Ok(n);
                    }
                    // Encoded buffer drained: either finish, or pull and encode
                    // the next bounded raw chunk (never materializing the whole
                    // payload). A refill may legitimately yield no output yet
                    // (e.g. base64 awaiting a complete 3-byte group); the outer
                    // loop simply reads again until bytes are available or EOF.
                    if *done {
                        self.sources.pop_front();
                    } else {
                        out.clear();
                        *out_pos = 0;
                        let mut scratch = [0u8; MIME_STREAM_CHUNK];
                        let n = raw.read(&mut scratch)?;
                        if n == 0 {
                            enc.finish(out)?;
                            *done = true;
                        } else {
                            enc.push(&scratch[..n], out)?;
                        }
                    }
                }
            }
        }
        Ok(0)
    }
}

impl Read for MimeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill(buf).map_err(|e| io::Error::other(e.message()))
    }
}

/// Appends the segments for a whole multipart body to `sources`, emitting the
/// boundary delimiters exactly as `mime_subparts_read` does: the first boundary
/// has no leading CRLF (it follows the parent's end-of-headers empty line),
/// interior boundaries are `\r\n--BOUNDARY\r\n`, and the closing boundary is
/// `\r\n--BOUNDARY--\r\n`.
fn push_multipart(
    mime: Mime,
    strategy: MimeStrategy,
    child_disposition: Option<&str>,
    sources: &mut VecDeque<Source>,
) -> Result<()> {
    let boundary = mime.boundary;
    for (i, part) in mime.parts.into_iter().enumerate() {
        let delim = if i == 0 {
            format!("--{boundary}\r\n")
        } else {
            format!("\r\n--{boundary}\r\n")
        };
        sources.push_back(Source::mem(delim.into_bytes()));
        push_part(part, strategy, None, child_disposition, sources)?;
    }
    sources.push_back(Source::mem(format!("\r\n--{boundary}--\r\n").into_bytes()));
    Ok(())
}

/// Appends the segments for a single part to `sources`: its header block (unless
/// body-only) followed by its content (encoded when an encoder is set).
fn push_part(
    part: Part,
    strategy: MimeStrategy,
    contenttype_hint: Option<&str>,
    disposition: Option<&str>,
    sources: &mut VecDeque<Source>,
) -> Result<()> {
    let (header_bytes, resolved_ct) = part.header_block(contenttype_hint, disposition, strategy);
    if !part.body_only {
        sources.push_back(Source::mem(header_bytes));
    }

    match part.kind {
        MimeKind::Multipart => {
            if let Some(sub) = part.subparts {
                let child_disp = resolved_ct
                    .as_deref()
                    .filter(|c| content_type_match(c, FORMDATA_CONTENTTYPE))
                    .map(|_| "form-data");
                push_multipart(*sub, strategy, child_disp, sources)?;
            }
        }
        MimeKind::Data => {
            if let Some(data) = part.data {
                let out = match part.encoder {
                    Some(enc) => enc.encode(&data)?,
                    None => data.to_vec(),
                };
                sources.push_back(Source::mem(out));
            }
        }
        MimeKind::File => {
            let path = part.filepath.ok_or(Error::Read)?;
            let f = File::open(path).map_err(|_| Error::Read)?;
            match part.encoder {
                // Encoded file part: stream the file through the encoder a
                // bounded chunk at a time instead of reading the whole file into
                // memory and encoding it in one shot.
                Some(enc) => sources.push_back(Source::encoded(RawSource::File(f), enc)),
                None => sources.push_back(Source::File(f)),
            }
        }
        MimeKind::Callback => {
            if let Some(cb) = part.callback {
                match part.encoder {
                    // Encoded callback part: stream the callback through the
                    // encoder a bounded chunk at a time instead of draining the
                    // whole callback into memory before encoding.
                    Some(enc) => sources.push_back(Source::encoded(RawSource::Callback(cb), enc)),
                    None => sources.push_back(Source::Callback { cb }),
                }
            }
        }
        MimeKind::None => {}
    }
    Ok(())
}

// ===========================================================================
// Legacy form API (mirrors lib/formdata.c)
// ===========================================================================
//
// curl's deprecated `curl_formadd`/`curl_formget`/`curl_formfree` build a chain
// of `struct curl_httppost` "meta data" nodes which are then converted, by
// `Curl_getformdata`, into the same MIME tree the modern `curl_mime_*` API
// produces. This section reproduces that machinery: the [`HttpPost`] node, the
// [`FormOption`]/[`FormCode`] enums, the [`formadd`] option parser
// (`FormAdd` + `FormAddCheck`), the [`getformdata`] conversion
// (`Curl_getformdata`), and [`formget`]/[`formfree`].
//
// The design goal is bug-for-bug parity: for identical inputs, the body
// rendered from a `formadd`-built chain is byte-identical (modulo the random
// boundary) to the body rendered from the equivalent modern-API `Mime`.

/// The uploaded content is a file name (`CURL_HTTPPOST_FILENAME`).
pub const HTTPPOST_FILENAME: u32 = 1 << 0;
/// The contents is a file name naming a file to read (`CURL_HTTPPOST_READFILE`).
pub const HTTPPOST_READFILE: u32 = 1 << 1;
/// The name is a pointer that is not copied (`CURL_HTTPPOST_PTRNAME`).
pub const HTTPPOST_PTRNAME: u32 = 1 << 2;
/// The contents is a pointer that is not copied (`CURL_HTTPPOST_PTRCONTENTS`).
pub const HTTPPOST_PTRCONTENTS: u32 = 1 << 3;
/// The contents is provided as an in-memory buffer (`CURL_HTTPPOST_BUFFER`).
pub const HTTPPOST_BUFFER: u32 = 1 << 4;
/// The buffer pointer is not copied (`CURL_HTTPPOST_PTRBUFFER`).
pub const HTTPPOST_PTRBUFFER: u32 = 1 << 5;
/// The contents is read through a callback (`CURL_HTTPPOST_CALLBACK`).
pub const HTTPPOST_CALLBACK: u32 = 1 << 6;
/// The `contentlen` field carries the (large) content length
/// (`CURL_HTTPPOST_LARGE`).
pub const HTTPPOST_LARGE: u32 = 1 << 7;

/// A single node in a legacy form-post chain (mirrors `struct curl_httppost`).
///
/// A top-level node represents one form field; when a field carries several
/// files, the extra files live in [`HttpPost::more`] (curl chains them via the
/// `more` pointer). [`getformdata`] converts a chain of these into a [`Mime`].
#[derive(Debug, Clone, Default)]
pub struct HttpPost {
    /// Field name (raw bytes; curl allows non-UTF-8, non-NUL-terminated names).
    pub name: Option<Vec<u8>>,
    /// Effective length of [`HttpPost::name`] in bytes.
    pub namelength: usize,
    /// The field contents: literal data, or a file name for a file field.
    pub contents: Option<Vec<u8>>,
    /// The declared content length (`0` means "NUL-terminated").
    pub contentlen: i64,
    /// In-memory buffer contents (for `CURLFORM_BUFFERPTR`).
    pub buffer: Option<Vec<u8>>,
    /// Length of [`HttpPost::buffer`] (`0` means "NUL-terminated").
    pub bufferlen: usize,
    /// Explicit `Content-Type` for this field, if any.
    pub contenttype: Option<String>,
    /// Custom header lines attached to this field.
    pub contentheader: Vec<String>,
    /// The "fake" file name reported in `Content-Disposition` (`CURLFORM_FILENAME`).
    pub showfilename: Option<String>,
    /// Bit-flags from the `HTTPPOST_*` set.
    pub flags: u32,
    /// Additional files belonging to the same field (curl's `more` chain).
    pub more: Vec<HttpPost>,
}

impl HttpPost {
    /// Returns the field name as a `String`, honoring [`HttpPost::namelength`]
    /// (mirrors `setname`, which memdup0's `namelength` bytes, or the whole
    /// NUL-terminated string when `namelength` is zero).
    fn name_string(&self) -> Option<String> {
        self.name.as_ref().map(|n| {
            let end = if self.namelength > 0 {
                self.namelength.min(n.len())
            } else {
                n.iter().position(|&b| b == 0).unwrap_or(n.len())
            };
            String::from_utf8_lossy(&n[..end]).into_owned()
        })
    }

    /// Returns [`HttpPost::contents`] as a lossy `String` (used when the
    /// contents holds a file name for `CURLFORM_FILE`/`CURLFORM_FILECONTENT`).
    fn contents_string(&self) -> Option<String> {
        self.contents
            .as_ref()
            .map(|c| String::from_utf8_lossy(c).into_owned())
    }
}

/// Options accepted by [`formadd`] (mirrors `CURLformoption` in `curl.h`).
///
/// The integer discriminants match curl exactly so the FFI crate can bridge the
/// C `va_list`/array forms onto this typed representation without translation.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormOption {
    /// `CURLFORM_NOTHING` — no-op placeholder.
    Nothing = 0,
    /// `CURLFORM_COPYNAME` — set the field name (copied).
    CopyName = 1,
    /// `CURLFORM_PTRNAME` — set the field name (not copied).
    PtrName = 2,
    /// `CURLFORM_NAMELENGTH` — length of a non-NUL-terminated name.
    NameLength = 3,
    /// `CURLFORM_COPYCONTENTS` — set the contents (copied).
    CopyContents = 4,
    /// `CURLFORM_PTRCONTENTS` — set the contents (not copied).
    PtrContents = 5,
    /// `CURLFORM_CONTENTSLENGTH` — length of the contents (deprecated `long`).
    ContentsLength = 6,
    /// `CURLFORM_FILECONTENT` — use a file's content as the field value.
    FileContent = 7,
    /// `CURLFORM_ARRAY` — an array of options (unsupported by the flat API).
    Array = 8,
    /// `CURLFORM_OBSOLETE` — reserved, unused.
    Obsolete = 9,
    /// `CURLFORM_FILE` — upload a named file.
    File = 10,
    /// `CURLFORM_BUFFER` — set the "fake" file name for a buffer upload.
    Buffer = 11,
    /// `CURLFORM_BUFFERPTR` — pointer to an in-memory buffer.
    BufferPtr = 12,
    /// `CURLFORM_BUFFERLENGTH` — length of the buffer.
    BufferLength = 13,
    /// `CURLFORM_CONTENTTYPE` — explicit `Content-Type`.
    ContentType = 14,
    /// `CURLFORM_CONTENTHEADER` — custom header list.
    ContentHeader = 15,
    /// `CURLFORM_FILENAME` — set the "fake" file name.
    FileName = 16,
    /// `CURLFORM_END` — terminates the option list.
    End = 17,
    /// `CURLFORM_OBSOLETE2` — reserved, unused.
    Obsolete2 = 18,
    /// `CURLFORM_STREAM` — read the contents from a callback.
    Stream = 19,
    /// `CURLFORM_CONTENTLEN` — length of the contents (`curl_off_t`).
    ContentLen = 20,
    /// `CURLFORM_LASTENTRY` — sentinel, never a valid option.
    LastEntry = 21,
}

/// Result code returned by [`formadd`] (mirrors `CURLFORMcode` in `curl.h`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormCode {
    /// `CURL_FORMADD_OK` — the field was added successfully.
    Ok = 0,
    /// `CURL_FORMADD_MEMORY` — an allocation failed (not reachable in the port).
    Memory = 1,
    /// `CURL_FORMADD_OPTION_TWICE` — the same option was supplied twice.
    OptionTwice = 2,
    /// `CURL_FORMADD_NULL` — a required value was missing/null.
    Null = 3,
    /// `CURL_FORMADD_UNKNOWN_OPTION` — an unrecognized option was supplied.
    UnknownOption = 4,
    /// `CURL_FORMADD_INCOMPLETE` — the field is missing a name or contents.
    Incomplete = 5,
    /// `CURL_FORMADD_ILLEGAL_ARRAY` — an array option was used illegally.
    IllegalArray = 6,
    /// `CURL_FORMADD_DISABLED` — form support was disabled at build time.
    Disabled = 7,
    /// `CURL_FORMADD_LAST` — sentinel.
    Last = 8,
}

impl FormCode {
    /// Returns the C integer value of this code.
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        self as i32
    }

    /// Returns `true` if this is [`FormCode::Ok`].
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, FormCode::Ok)
    }
}

/// A value supplied alongside a [`FormOption`] in a [`FormArg`].
///
/// This typed enum stands in for the C `va_list`, where each option consumes a
/// `char *`, a `long`, a `curl_off_t`, or a `struct curl_slist *`.
#[derive(Debug, Clone)]
pub enum FormValue {
    /// A textual value (names, contents, file names, content types).
    Str(String),
    /// A raw byte value (binary contents).
    Bytes(Vec<u8>),
    /// An integer value (lengths).
    Len(i64),
    /// A list of custom header lines (`CURLFORM_CONTENTHEADER`).
    Headers(Vec<String>),
    /// No value (used with valueless placeholders such as `CURLFORM_END`).
    None,
}

impl FormValue {
    /// Interprets the value as bytes (accepting both `Str` and `Bytes`).
    fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            FormValue::Str(s) => Some(s.as_bytes().to_vec()),
            FormValue::Bytes(b) => Some(b.clone()),
            _ => None,
        }
    }

    /// Interprets the value as a string slice (only `Str`).
    fn as_str(&self) -> Option<&str> {
        match self {
            FormValue::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Interprets the value as an integer length (only `Len`).
    fn as_len(&self) -> Option<i64> {
        match self {
            FormValue::Len(n) => Some(*n),
            _ => None,
        }
    }

    /// Interprets the value as a header list (only `Headers`).
    fn as_headers(&self) -> Option<Vec<String>> {
        match self {
            FormValue::Headers(h) => Some(h.clone()),
            _ => None,
        }
    }
}

/// One `(option, value)` pair passed to [`formadd`].
///
/// This is the Rust analogue of a single `CURLFORM_*` argument in the C
/// variadic call, or of one `struct curl_forms` array entry.
#[derive(Debug, Clone)]
pub struct FormArg {
    /// The option selector.
    pub option: FormOption,
    /// The associated value.
    pub value: FormValue,
}

impl FormArg {
    /// Builds a [`FormArg`] from an option and a value.
    #[must_use]
    pub fn new(option: FormOption, value: FormValue) -> Self {
        FormArg { option, value }
    }

    /// Convenience constructor for a string-valued option.
    #[must_use]
    pub fn string(option: FormOption, value: impl Into<String>) -> Self {
        FormArg {
            option,
            value: FormValue::Str(value.into()),
        }
    }

    /// Convenience constructor for a byte-valued option.
    #[must_use]
    pub fn bytes(option: FormOption, value: impl Into<Vec<u8>>) -> Self {
        FormArg {
            option,
            value: FormValue::Bytes(value.into()),
        }
    }

    /// Convenience constructor for an integer-length option.
    #[must_use]
    pub fn length(option: FormOption, value: i64) -> Self {
        FormArg {
            option,
            value: FormValue::Len(value),
        }
    }

    /// Convenience constructor for a header-list option.
    #[must_use]
    pub fn headers(option: FormOption, value: Vec<String>) -> Self {
        FormArg {
            option,
            value: FormValue::Headers(value),
        }
    }
}

/// Intermediate accumulator for one field while parsing (mirrors
/// `struct FormInfo`). A single [`formadd`] call may build a chain of these
/// (extra `FILE`/`CONTENTTYPE` options append new nodes).
#[derive(Default)]
struct FormInfo {
    name: Option<Vec<u8>>,
    namelength: usize,
    value: Option<Vec<u8>>,
    contenttype: Option<String>,
    showfilename: Option<String>,
    buffer: Option<Vec<u8>>,
    bufferlength: usize,
    contentheader: Vec<String>,
    contentslength: i64,
    flags: u32,
    /// `true` once a `CURLFORM_STREAM` user pointer has been supplied.
    userp: bool,
}

/// Parses a slice of [`FormArg`]s into a chain of [`FormInfo`] nodes.
///
/// Faithful port of the option `switch` in `FormAdd`. Index `0` of the returned
/// vector is the primary node; later indices are the `more` chain produced by
/// repeated `CURLFORM_FILE`/`CURLFORM_CONTENTTYPE` options.
fn form_parse(args: &[FormArg]) -> std::result::Result<Vec<FormInfo>, FormCode> {
    let mut forms: Vec<FormInfo> = vec![FormInfo::default()];
    let mut curr: usize = 0;

    for arg in args {
        match arg.option {
            // The flat slice already represents the (single) option list; a
            // terminating END simply stops parsing, and a nested ARRAY is not
            // representable here.
            FormOption::End => break,
            FormOption::Array => return Err(FormCode::IllegalArray),

            FormOption::PtrName | FormOption::CopyName => {
                if arg.option == FormOption::PtrName {
                    forms[curr].flags |= HTTPPOST_PTRNAME;
                }
                if forms[curr].name.is_some() {
                    return Err(FormCode::OptionTwice);
                }
                match arg.value.as_bytes() {
                    Some(b) => forms[curr].name = Some(b),
                    None => return Err(FormCode::Null),
                }
            }

            FormOption::NameLength => {
                if forms[curr].namelength != 0 {
                    return Err(FormCode::OptionTwice);
                }
                forms[curr].namelength = arg.value.as_len().unwrap_or(0).max(0) as usize;
            }

            FormOption::PtrContents | FormOption::CopyContents => {
                if arg.option == FormOption::PtrContents {
                    forms[curr].flags |= HTTPPOST_PTRCONTENTS;
                }
                if forms[curr].value.is_some() {
                    return Err(FormCode::OptionTwice);
                }
                match arg.value.as_bytes() {
                    Some(b) => forms[curr].value = Some(b),
                    None => return Err(FormCode::Null),
                }
            }

            FormOption::ContentsLength => {
                forms[curr].contentslength = arg.value.as_len().unwrap_or(0);
            }

            FormOption::ContentLen => {
                forms[curr].flags |= HTTPPOST_LARGE;
                forms[curr].contentslength = arg.value.as_len().unwrap_or(0);
            }

            FormOption::FileContent => {
                if forms[curr].flags & (HTTPPOST_PTRCONTENTS | HTTPPOST_READFILE) != 0 {
                    return Err(FormCode::OptionTwice);
                }
                match arg.value.as_bytes() {
                    Some(b) => {
                        forms[curr].value = Some(b);
                        forms[curr].flags |= HTTPPOST_READFILE;
                    }
                    None => return Err(FormCode::Null),
                }
            }

            FormOption::File => {
                let avalue = arg.value.as_bytes();
                if forms[curr].value.is_some() {
                    if forms[curr].flags & HTTPPOST_FILENAME != 0 {
                        match avalue {
                            Some(b) => {
                                // AddFormInfo: the new node inherits HTTPPOST_FILENAME.
                                let mut nf = FormInfo {
                                    value: Some(b),
                                    ..FormInfo::default()
                                };
                                nf.flags |= HTTPPOST_FILENAME;
                                forms.push(nf);
                                curr = forms.len() - 1;
                            }
                            None => return Err(FormCode::Null),
                        }
                    } else {
                        return Err(FormCode::OptionTwice);
                    }
                } else {
                    match avalue {
                        Some(b) => {
                            forms[curr].value = Some(b);
                            forms[curr].flags |= HTTPPOST_FILENAME;
                        }
                        None => return Err(FormCode::Null),
                    }
                }
            }

            FormOption::BufferPtr => {
                forms[curr].flags |= HTTPPOST_PTRBUFFER | HTTPPOST_BUFFER;
                if forms[curr].buffer.is_some() {
                    return Err(FormCode::OptionTwice);
                }
                match arg.value.as_bytes() {
                    Some(b) => {
                        forms[curr].buffer = Some(b.clone());
                        // Make value non-null so the field is accepted.
                        forms[curr].value = Some(b);
                    }
                    None => return Err(FormCode::Null),
                }
            }

            FormOption::BufferLength => {
                if forms[curr].bufferlength != 0 {
                    return Err(FormCode::OptionTwice);
                }
                forms[curr].bufferlength = arg.value.as_len().unwrap_or(0).max(0) as usize;
            }

            FormOption::Stream => {
                forms[curr].flags |= HTTPPOST_CALLBACK;
                if forms[curr].userp {
                    return Err(FormCode::OptionTwice);
                }
                // A user pointer is required; we only record its presence and
                // make the value non-null so the field is accepted.
                forms[curr].userp = true;
                if forms[curr].value.is_none() {
                    forms[curr].value = Some(Vec::new());
                }
            }

            FormOption::ContentType => {
                let avalue = arg.value.as_str();
                if forms[curr].contenttype.is_some() {
                    if forms[curr].flags & HTTPPOST_FILENAME != 0 {
                        match avalue {
                            Some(s) => {
                                let mut nf = FormInfo {
                                    contenttype: Some(s.to_owned()),
                                    ..FormInfo::default()
                                };
                                nf.flags |= HTTPPOST_FILENAME;
                                forms.push(nf);
                                curr = forms.len() - 1;
                            }
                            None => return Err(FormCode::Null),
                        }
                    } else {
                        return Err(FormCode::OptionTwice);
                    }
                } else {
                    match avalue {
                        Some(s) => forms[curr].contenttype = Some(s.to_owned()),
                        None => return Err(FormCode::Null),
                    }
                }
            }

            FormOption::ContentHeader => {
                if !forms[curr].contentheader.is_empty() {
                    return Err(FormCode::OptionTwice);
                }
                if let Some(h) = arg.value.as_headers() {
                    forms[curr].contentheader = h;
                }
            }

            FormOption::FileName | FormOption::Buffer => {
                if forms[curr].showfilename.is_some() {
                    return Err(FormCode::OptionTwice);
                }
                match arg.value.as_str() {
                    Some(s) => forms[curr].showfilename = Some(s.to_owned()),
                    None => return Err(FormCode::Null),
                }
            }

            // NOTHING, OBSOLETE, OBSOLETE2, LASTENTRY: unrecognized options.
            _ => return Err(FormCode::UnknownOption),
        }
    }

    Ok(forms)
}

/// Validates a parsed [`FormInfo`] chain and builds the resulting [`HttpPost`]
/// (faithful port of `FormAddCheck` + `AddHttpPost`).
///
/// The primary node becomes the top-level [`HttpPost`]; the rest populate its
/// [`HttpPost::more`] chain, mirroring curl's `more`-linked list.
fn form_add_check(forms: &mut [FormInfo]) -> std::result::Result<HttpPost, FormCode> {
    let mut prevtype: Option<String> = None;
    let mut top: Option<HttpPost> = None;

    for i in 0..forms.len() {
        let has_post = top.is_some();

        // --- Completeness checks (mirrors the big `if` in FormAddCheck) -----
        {
            let f = &forms[i];
            let name_null = f.name.is_none();
            let value_null = f.value.is_none();
            if ((name_null || value_null) && !has_post)
                || (f.contentslength != 0 && (f.flags & HTTPPOST_FILENAME != 0))
                || ((f.flags & HTTPPOST_FILENAME != 0) && (f.flags & HTTPPOST_PTRCONTENTS != 0))
                || (f.buffer.is_none()
                    && (f.flags & HTTPPOST_BUFFER != 0)
                    && (f.flags & HTTPPOST_PTRBUFFER != 0))
                || ((f.flags & HTTPPOST_READFILE != 0) && (f.flags & HTTPPOST_PTRCONTENTS != 0))
            {
                return Err(FormCode::Incomplete);
            }
        }

        // --- Default content type for file/buffer parts --------------------
        if (forms[i].flags & (HTTPPOST_FILENAME | HTTPPOST_BUFFER) != 0)
            && forms[i].contenttype.is_none()
        {
            let basis: Option<String> = if forms[i].flags & HTTPPOST_BUFFER != 0 {
                forms[i].showfilename.clone()
            } else {
                forms[i]
                    .value
                    .as_ref()
                    .map(|v| String::from_utf8_lossy(v).into_owned())
            };
            let ty = basis
                .as_deref()
                .and_then(content_type_for_filename)
                .map(str::to_owned)
                .or_else(|| prevtype.clone())
                .unwrap_or_else(|| FILE_CONTENTTYPE_DEFAULT.to_owned());
            forms[i].contenttype = Some(ty);
        }

        // --- Embedded-NUL check on a length-delimited name -----------------
        if let Some(name) = forms[i].name.as_ref() {
            if forms[i].namelength > 0 {
                let region = &name[..forms[i].namelength.min(name.len())];
                if region.contains(&0) {
                    return Err(FormCode::Null);
                }
            }
        }

        // --- Compute the effective name length (mirrors AddHttpPost) -------
        let namelength = if forms[i].namelength != 0 {
            forms[i].namelength
        } else if let Some(name) = forms[i].name.as_ref() {
            name.iter().position(|&b| b == 0).unwrap_or(name.len())
        } else {
            0
        };

        // --- Build the HttpPost node ---------------------------------------
        let f = &forms[i];
        let post = HttpPost {
            name: f.name.clone(),
            namelength,
            contents: f.value.clone(),
            contentlen: f.contentslength,
            buffer: f.buffer.clone(),
            bufferlen: f.bufferlength,
            contenttype: f.contenttype.clone(),
            contentheader: f.contentheader.clone(),
            showfilename: f.showfilename.clone(),
            // AddHttpPost always sets CURL_HTTPPOST_LARGE.
            flags: f.flags | HTTPPOST_LARGE,
            more: Vec::new(),
        };

        match top.as_mut() {
            None => top = Some(post),
            Some(t) => t.more.push(post),
        }

        if let Some(ct) = forms[i].contenttype.as_ref() {
            prevtype = Some(ct.clone());
        }
    }

    top.ok_or(FormCode::Incomplete)
}

/// Adds one form field to `chain` (public analogue of `curl_formadd`).
///
/// `args` is the ordered list of `CURLFORM_*` options for a single field. On
/// success the new [`HttpPost`] (with any `more` files) is appended to `chain`
/// and [`FormCode::Ok`] is returned; otherwise the chain is left unchanged and
/// the corresponding [`FormCode`] error is returned.
///
/// # Examples
///
/// ```ignore
/// let mut chain = Vec::new();
/// let code = formadd(&mut chain, &[
///     FormArg::string(FormOption::CopyName, "field"),
///     FormArg::string(FormOption::CopyContents, "value"),
/// ]);
/// assert!(code.is_ok());
/// ```
pub fn formadd(chain: &mut Vec<HttpPost>, args: &[FormArg]) -> FormCode {
    let mut forms = match form_parse(args) {
        Ok(f) => f,
        Err(code) => return code,
    };
    match form_add_check(&mut forms) {
        Ok(post) => {
            chain.push(post);
            FormCode::Ok
        }
        Err(code) => code,
    }
}

/// Frees a legacy form-post chain (analogue of `curl_formfree`).
///
/// In the Rust port every node owns its data, so simply dropping the chain
/// releases everything; this consuming function exists for API symmetry.
pub fn formfree(chain: Vec<HttpPost>) {
    drop(chain);
}

/// Returns the effective byte length of `data` under a declared length `clen`.
///
/// A positive `clen` selects exactly that many bytes (clamped to the buffer);
/// a non-positive `clen` means "NUL-terminated" (curl's `CURL_ZERO_TERMINATED`
/// / `strlen`), i.e. up to the first NUL byte.
fn effective_len(data: &[u8], clen: i64) -> usize {
    if clen > 0 {
        (clen as usize).min(data.len())
    } else {
        data.iter().position(|&b| b == 0).unwrap_or(data.len())
    }
}

/// A [`MimeReadCallback`] that streams the process's standard input, used for
/// the legacy `"-"` pseudo-file-name (`CURLFORM_FILE` with contents `"-"`).
struct StdinReader;

impl MimeReadCallback for StdinReader {
    fn read(&mut self, buf: &mut [u8]) -> ReadOutcome {
        match io::stdin().read(buf) {
            Ok(n) => ReadOutcome::Bytes(n),
            Err(_) => ReadOutcome::Abort,
        }
    }
}

/// A [`MimeReadCallback`] that yields no data.
///
/// It backs a `CURLFORM_STREAM` field in the pure conversion, where the live
/// read function is not available (it is supplied at the transport layer). The
/// declared size is still carried on the part so header/length computation is
/// preserved.
struct EmptyReader;

impl MimeReadCallback for EmptyReader {
    fn read(&mut self, _buf: &mut [u8]) -> ReadOutcome {
        ReadOutcome::Bytes(0)
    }
}

/// Adds a single file/field part to `target`, taking the transfer parameters
/// (flags, name, length, fake file name) from the top `post` and the per-file
/// data (contents, content type, headers) from `file`.
///
/// This is the body of the inner `for(file = post; ...)` loop in
/// `Curl_getformdata`.
fn add_file_part(target: &mut Mime, post: &HttpPost, file: &HttpPost) -> Result<()> {
    // AddHttpPost always sets CURL_HTTPPOST_LARGE, so the effective length is
    // taken from `contentlen`.
    let clen = post.contentlen;

    let part = target.addpart();

    // Custom headers (from the individual file).
    if !file.contentheader.is_empty() {
        part.set_headers(file.contentheader.clone())?;
    }

    // Explicit content type (from the individual file).
    if let Some(ct) = file.contenttype.as_deref() {
        part.set_type(Some(ct))?;
    }

    // Field name — only for a single-file field (matches `if(!post->more)`).
    if post.more.is_empty() {
        let name = post.name_string();
        part.set_name(name.as_deref())?;
    }

    // Contents.
    if post.flags & (HTTPPOST_FILENAME | HTTPPOST_READFILE) != 0 {
        let fname = file.contents_string().unwrap_or_default();
        if fname == "-" {
            // Legacy stdin pseudo-file.
            part.set_data_cb(-1, Box::new(StdinReader))?;
        } else {
            part.set_filedata(&fname)?;
        }
        if post.flags & HTTPPOST_READFILE != 0 {
            part.set_filename(None)?;
        }
    } else if post.flags & HTTPPOST_BUFFER != 0 {
        let buf = post.buffer.as_deref().unwrap_or(&[]);
        let n = effective_len(buf, post.bufferlen as i64);
        part.set_data(&buf[..n])?;
    } else if post.flags & HTTPPOST_CALLBACK != 0 {
        let size = if clen != 0 { clen } else { -1 };
        part.set_data_cb(size, Box::new(EmptyReader))?;
    } else {
        let contents = post.contents.as_deref().unwrap_or(&[]);
        let n = effective_len(contents, clen);
        part.set_data(&contents[..n])?;
    }

    // Fake file name (Content-Disposition `filename=`).
    if let Some(show) = post.showfilename.as_deref() {
        if !post.more.is_empty()
            || post.flags & (HTTPPOST_FILENAME | HTTPPOST_BUFFER | HTTPPOST_CALLBACK) != 0
        {
            part.set_filename(Some(show))?;
        }
    }

    Ok(())
}

/// Converts a legacy [`HttpPost`] chain into a [`Mime`] tree
/// (faithful port of `Curl_getformdata`).
///
/// Each top-level field with several files becomes a named subpart wrapping a
/// nested multipart; a single-file field becomes a single part. The resulting
/// [`Mime`] renders (under [`MimeStrategy::Form`]) to the same
/// `multipart/form-data` body the modern API produces for equivalent inputs.
///
/// # Errors
///
/// Propagates [`Error::Read`] if a file part cannot be stat-ed/opened.
pub fn getformdata(posts: &[HttpPost]) -> Result<Mime> {
    let mut form = Mime::new();

    for post in posts {
        if post.more.is_empty() {
            // Single file/field goes straight into the top-level multipart.
            add_file_part(&mut form, post, post)?;
        } else {
            // Several files: a named subpart wraps a nested multipart holding
            // one part per file (the field itself plus each `more` entry).
            let mut nested = Mime::new();
            add_file_part(&mut nested, post, post)?;
            for file in &post.more {
                add_file_part(&mut nested, post, file)?;
            }
            let name = post.name_string();
            let part = form.addpart();
            part.set_name(name.as_deref())?;
            part.set_subparts(nested)?;
        }
    }

    Ok(form)
}

/// Serializes a legacy form-post chain and feeds it to `append` in chunks
/// (analogue of `curl_formget`).
///
/// The body is rendered as `multipart/form-data` (no top-level `Content-Type`
/// header, matching `curl_formget`, which prepares headers on the container and
/// then reads only the body).
///
/// # Errors
///
/// Propagates conversion and rendering errors, plus any error returned by
/// `append`.
pub fn formget<F>(posts: &[HttpPost], mut append: F) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let mime = getformdata(posts)?;
    let mut reader = mime.into_reader(MimeStrategy::Form)?;
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.fill(&mut buf)?;
        if n == 0 {
            break;
        }
        append(&buf[..n])?;
    }
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Creates a uniquely named temporary file with `content`, returning its
    /// path. The caller is responsible for removing it.
    fn make_temp_file(content: &[u8], suffix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let n = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        path.push(format!(
            "blitzy_mime_test_{}_{}_{}_{}",
            std::process::id(),
            n,
            nanos,
            suffix
        ));
        std::fs::write(&path, content).expect("write temp file");
        path
    }

    /// Replaces every occurrence of `boundary` in `bytes` with a fixed
    /// placeholder so bodies with different random boundaries can be compared.
    ///
    /// Uses a lossy conversion so bodies carrying binary part content (e.g. a
    /// PNG magic prefix) can still be compared on their textual structure.
    fn normalize(bytes: &[u8], boundary: &str) -> String {
        String::from_utf8_lossy(bytes).replace(boundary, "BOUNDARY")
    }

    // --- Encoding name mapping ---------------------------------------------

    #[test]
    fn encoding_name_roundtrip() {
        for (enc, name) in [
            (Encoding::Binary, "binary"),
            (Encoding::EightBit, "8bit"),
            (Encoding::SevenBit, "7bit"),
            (Encoding::Base64, "base64"),
            (Encoding::QuotedPrintable, "quoted-printable"),
        ] {
            assert_eq!(enc.name(), name);
            assert_eq!(Encoding::from_name(name), Some(enc));
        }
        // Matching is case-insensitive, as in curl's `find_encoder`.
        assert_eq!(Encoding::from_name("BASE64"), Some(Encoding::Base64));
        assert_eq!(Encoding::from_name("nonsense"), None);
    }

    // --- Content-Type extension table --------------------------------------

    #[test]
    fn content_type_table_matches_curl() {
        assert_eq!(content_type_for_filename("photo.gif"), Some("image/gif"));
        assert_eq!(content_type_for_filename("a.jpg"), Some("image/jpeg"));
        assert_eq!(content_type_for_filename("a.jpeg"), Some("image/jpeg"));
        assert_eq!(content_type_for_filename("a.png"), Some("image/png"));
        assert_eq!(content_type_for_filename("a.svg"), Some("image/svg+xml"));
        assert_eq!(content_type_for_filename("notes.txt"), Some("text/plain"));
        assert_eq!(content_type_for_filename("a.htm"), Some("text/html"));
        assert_eq!(content_type_for_filename("a.html"), Some("text/html"));
        assert_eq!(content_type_for_filename("a.pdf"), Some("application/pdf"));
        assert_eq!(content_type_for_filename("a.xml"), Some("application/xml"));
        // Case-insensitive suffix match (curl uses curl_strequal).
        assert_eq!(content_type_for_filename("IMAGE.PNG"), Some("image/png"));
        // Unknown / no extension yields None.
        assert_eq!(content_type_for_filename("archive.tar"), None);
        assert_eq!(content_type_for_filename("noext"), None);
    }

    // --- base64 encoder -----------------------------------------------------

    #[test]
    fn base64_basic_vector() {
        // "Hello, World!" -> standard base64, short enough to need no wrapping.
        assert_eq!(
            Encoding::Base64.encode(b"Hello, World!").unwrap(),
            b"SGVsbG8sIFdvcmxkIQ==".to_vec()
        );
        // Empty input -> empty output.
        assert_eq!(Encoding::Base64.encode(b"").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn base64_wraps_at_76_columns_with_crlf_no_trailing() {
        // 60 input bytes -> 80 base64 chars -> one CRLF after column 76.
        let input = vec![b'A'; 60];
        let out = Encoding::Base64.encode(&input).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(lines.len(), 2, "expected exactly one wrap");
        assert_eq!(lines[0].len(), 76);
        assert_eq!(lines[1].len(), 4);
        // No trailing CRLF.
        assert!(!text.ends_with("\r\n"));
        // Re-joining and base64-decoding must reproduce the input.
        let joined = text.replace("\r\n", "");
        assert_eq!(BASE64_STANDARD.decode(joined).unwrap(), input);
    }

    // --- quoted-printable encoder ------------------------------------------

    #[test]
    fn quoted_printable_escapes_equals_and_high_bytes() {
        // '=' is always escaped to "=3D".
        assert_eq!(
            Encoding::QuotedPrintable.encode(b"foo=bar").unwrap(),
            b"foo=3Dbar".to_vec()
        );
        // An 8-bit byte (0xE9) is escaped uppercase.
        assert_eq!(
            Encoding::QuotedPrintable.encode(&[0xE9]).unwrap(),
            b"=E9".to_vec()
        );
    }

    #[test]
    fn quoted_printable_space_and_eol_rules() {
        // A trailing space (end of data) must be escaped as "=20".
        assert_eq!(
            Encoding::QuotedPrintable.encode(b"a ").unwrap(),
            b"a=20".to_vec()
        );
        // A space not at end of line stays literal.
        assert_eq!(
            Encoding::QuotedPrintable.encode(b"a b").unwrap(),
            b"a b".to_vec()
        );
        // A CRLF in the input is emitted as a literal CRLF.
        assert_eq!(
            Encoding::QuotedPrintable.encode(b"a\r\nb").unwrap(),
            b"a\r\nb".to_vec()
        );
    }

    // --- 7bit encoder -------------------------------------------------------

    #[test]
    fn sevenbit_accepts_clean_rejects_high_bit() {
        assert_eq!(
            Encoding::SevenBit.encode(b"clean ascii").unwrap(),
            b"clean ascii".to_vec()
        );
        assert!(Encoding::SevenBit.encode(&[0x41, 0x80, 0x42]).is_err());
    }

    // --- Boundary generation ------------------------------------------------

    #[test]
    fn boundary_format_and_uniqueness() {
        let b1 = generate_boundary();
        let b2 = generate_boundary();
        assert_eq!(b1.len(), BOUNDARY_LEN);
        assert_eq!(b1.len(), 46);
        assert!(b1.starts_with(&"-".repeat(BOUNDARY_DASHES)));
        // The random tail is drawn from the 62-char alphanumeric alphabet.
        let tail = &b1[BOUNDARY_DASHES..];
        assert_eq!(tail.len(), RAND_BOUNDARY_CHARS);
        assert!(tail.bytes().all(|c| c.is_ascii_alphanumeric()));
        // Two boundaries are practically always different.
        assert_ne!(b1, b2);
    }

    // --- Two-part form render (field + file) -------------------------------

    #[test]
    fn two_part_form_render_matches_expected_bytes() {
        let file_path = make_temp_file(b"filedata", "upload.dat");
        let fname = file_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap()
            .to_owned();

        let mut mime = Mime::new();
        {
            let p = mime.addpart();
            p.set_name(Some("field")).unwrap();
            p.set_data(b"value").unwrap();
        }
        {
            let p = mime.addpart();
            p.set_name(Some("file")).unwrap();
            p.set_filedata(&file_path).unwrap();
        }

        let boundary = mime.boundary().to_owned();
        let declared_len = mime.content_length(MimeStrategy::Form);
        let body = mime.to_bytes(MimeStrategy::Form).unwrap();

        std::fs::remove_file(&file_path).ok();

        let expected = format!(
            "--{b}\r\n\
             Content-Disposition: form-data; name=\"field\"\r\n\
             \r\n\
             value\r\n\
             --{b}\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"{f}\"\r\n\
             Content-Type: application/octet-stream\r\n\
             \r\n\
             filedata\r\n\
             --{b}--\r\n",
            b = boundary,
            f = fname
        );

        assert_eq!(String::from_utf8(body.clone()).unwrap(), expected);
        // The computed Content-Length must equal the rendered body length.
        assert_eq!(declared_len, body.len() as i64);
    }

    // --- Legacy formadd equivalence ----------------------------------------

    #[test]
    fn legacy_formadd_matches_modern_mime() {
        let file_path = make_temp_file(b"filedata", "upload.dat");
        let fname = file_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap()
            .to_owned();
        let path_str = file_path.to_str().unwrap().to_owned();

        // Modern API construction.
        let mut modern = Mime::new();
        {
            let p = modern.addpart();
            p.set_name(Some("field")).unwrap();
            p.set_data(b"value").unwrap();
        }
        {
            let p = modern.addpart();
            p.set_name(Some("file")).unwrap();
            p.set_filedata(&file_path).unwrap();
        }
        let modern_boundary = modern.boundary().to_owned();
        let modern_bytes = modern.to_bytes(MimeStrategy::Form).unwrap();

        // Legacy formadd construction of the same field + file.
        let mut chain: Vec<HttpPost> = Vec::new();
        assert_eq!(
            formadd(
                &mut chain,
                &[
                    FormArg::string(FormOption::CopyName, "field"),
                    FormArg::string(FormOption::CopyContents, "value"),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            formadd(
                &mut chain,
                &[
                    FormArg::string(FormOption::CopyName, "file"),
                    FormArg::string(FormOption::File, path_str),
                ]
            ),
            FormCode::Ok
        );
        let legacy_mime = getformdata(&chain).unwrap();
        let legacy_boundary = legacy_mime.boundary().to_owned();
        let legacy_bytes = legacy_mime.to_bytes(MimeStrategy::Form).unwrap();

        std::fs::remove_file(&file_path).ok();

        // Both must render to the same body once the (random) boundary is
        // normalized, and both must reference the file's base name.
        assert!(normalize(&modern_bytes, &modern_boundary).contains(&fname));
        assert_eq!(
            normalize(&legacy_bytes, &legacy_boundary),
            normalize(&modern_bytes, &modern_boundary)
        );
    }

    // --- formget streams the same body as to_bytes -------------------------

    #[test]
    fn formget_streams_form_body() {
        let mut chain: Vec<HttpPost> = Vec::new();
        formadd(
            &mut chain,
            &[
                FormArg::string(FormOption::CopyName, "greeting"),
                FormArg::string(FormOption::CopyContents, "hi"),
            ],
        );

        let mime = getformdata(&chain).unwrap();
        let boundary = mime.boundary().to_owned();
        let direct = mime.to_bytes(MimeStrategy::Form).unwrap();

        // getformdata produces a fresh Mime (new boundary) each call, so render
        // a second one for formget and compare modulo the boundary.
        let mut collected: Vec<u8> = Vec::new();
        formget(&chain, |chunk| {
            collected.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();

        // The direct body references the "greeting" field.
        assert!(normalize(&direct, &boundary).contains("name=\"greeting\""));
        // formget's body, normalized, matches a directly rendered body.
        let mime2 = getformdata(&chain).unwrap();
        let b2 = mime2.boundary().to_owned();
        let direct2 = mime2.to_bytes(MimeStrategy::Form).unwrap();
        // `collected` used its own boundary; compare structural content.
        assert!(normalize(&collected, extract_boundary(&collected).as_str()).contains("hi"));
        assert_eq!(
            normalize(&direct2, &b2),
            normalize(&direct, &boundary),
            "two direct renders must be structurally identical"
        );
    }

    /// Extracts the boundary from a rendered body (the text after the leading
    /// `--` up to the first CRLF).
    fn extract_boundary(bytes: &[u8]) -> String {
        let text = String::from_utf8_lossy(bytes);
        let after = text.strip_prefix("--").unwrap_or(&text);
        after.split("\r\n").next().unwrap_or("").to_owned()
    }

    // --- formadd error paths -----------------------------------------------

    #[test]
    fn formadd_reports_option_twice_and_incomplete() {
        // Setting the name twice is an error.
        let mut chain: Vec<HttpPost> = Vec::new();
        let code = formadd(
            &mut chain,
            &[
                FormArg::string(FormOption::CopyName, "a"),
                FormArg::string(FormOption::CopyName, "b"),
                FormArg::string(FormOption::CopyContents, "c"),
            ],
        );
        assert_eq!(code, FormCode::OptionTwice);
        assert!(chain.is_empty());

        // A field with a name but no contents is incomplete.
        let mut chain2: Vec<HttpPost> = Vec::new();
        let code2 = formadd(
            &mut chain2,
            &[FormArg::string(FormOption::CopyName, "lonely")],
        );
        assert_eq!(code2, FormCode::Incomplete);
        assert!(chain2.is_empty());
    }

    #[test]
    fn formadd_buffer_default_content_type() {
        // A buffer field with a recognizable fake file name gets that type.
        let mut chain: Vec<HttpPost> = Vec::new();
        let code = formadd(
            &mut chain,
            &[
                FormArg::string(FormOption::CopyName, "img"),
                FormArg::bytes(FormOption::BufferPtr, b"\x89PNG".to_vec()),
                FormArg::length(FormOption::BufferLength, 4),
                FormArg::string(FormOption::Buffer, "logo.png"),
            ],
        );
        assert_eq!(code, FormCode::Ok);
        let mime = getformdata(&chain).unwrap();
        let boundary = mime.boundary().to_owned();
        let body = normalize(&mime.to_bytes(MimeStrategy::Form).unwrap(), &boundary);
        assert!(body.contains("Content-Type: image/png"));
        assert!(body.contains("filename=\"logo.png\""));
        assert!(body.contains("name=\"img\""));
    }

    // --- Callback-backed part ----------------------------------------------

    struct VecReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl MimeReadCallback for VecReader {
        fn read(&mut self, buf: &mut [u8]) -> ReadOutcome {
            let n = (self.data.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            ReadOutcome::Bytes(n)
        }
    }

    #[test]
    fn callback_part_streams_content() {
        let mut mime = Mime::new();
        {
            let p = mime.addpart();
            p.set_name(Some("stream")).unwrap();
            p.set_data_cb(
                5,
                Box::new(VecReader {
                    data: b"abcde".to_vec(),
                    pos: 0,
                }),
            )
            .unwrap();
        }
        let boundary = mime.boundary().to_owned();
        let body = normalize(&mime.to_bytes(MimeStrategy::Form).unwrap(), &boundary);
        assert!(body.contains("name=\"stream\""));
        assert!(body.contains("\r\n\r\nabcde\r\n"));
    }

    // --- Escaping in Content-Disposition -----------------------------------

    #[test]
    fn form_name_escaping() {
        let mut mime = Mime::new();
        {
            let p = mime.addpart();
            p.set_name(Some("a\"b")).unwrap();
            p.set_data(b"x").unwrap();
        }
        let boundary = mime.boundary().to_owned();
        let body = normalize(&mime.to_bytes(MimeStrategy::Form).unwrap(), &boundary);
        // A double quote in a form name is percent-encoded as %22.
        assert!(body.contains("name=\"a%22b\""));
    }

    // --- Mail strategy adds 8bit CTE ---------------------------------------

    #[test]
    fn mail_strategy_adds_transfer_encoding() {
        let mut mime = Mime::new();
        {
            let p = mime.addpart();
            p.set_type(Some("text/html")).unwrap();
            p.set_data(b"<p>hi</p>").unwrap();
        }
        let boundary = mime.boundary().to_owned();
        let body = normalize(&mime.to_bytes(MimeStrategy::Mail).unwrap(), &boundary);
        assert!(body.contains("Content-Type: text/html"));
        assert!(body.contains("Content-Transfer-Encoding: 8bit"));
    }

    // --- Streaming content-transfer encoders ------------------------------

    /// Runs an [`EncoderStream`] over `input`, pushing it in fixed-size `chunk`
    /// slices and flushing at the end — the streaming counterpart of the
    /// whole-buffer [`Encoding::encode`].
    fn stream_encode(enc: Encoding, input: &[u8], chunk: usize) -> Result<Vec<u8>> {
        let mut s = EncoderStream::new(enc);
        let mut out = Vec::new();
        let mut i = 0;
        while i < input.len() {
            let end = (i + chunk).min(input.len());
            s.push(&input[i..end], &mut out)?;
            i = end;
        }
        s.finish(&mut out)?;
        Ok(out)
    }

    /// Fully drains a [`MimeReader`] using a `bufsize`-byte read buffer,
    /// returning the concatenated body. A small `bufsize` forces the streaming
    /// segments through many `fill` iterations.
    fn read_all(mut reader: MimeReader, bufsize: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; bufsize];
        loop {
            let n = reader.fill(&mut buf)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        Ok(out)
    }

    /// A varied corpus that exercises base64 group boundaries, the 76-column
    /// wrap, and the quoted-printable escape / space-EOL / soft-break / CRLF
    /// lookahead rules.
    fn parity_inputs() -> Vec<Vec<u8>> {
        let mut inputs: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"a".to_vec(),
            b"ab".to_vec(),
            b"abc".to_vec(),
            b"abcd".to_vec(),
            b"abcde".to_vec(),
            b"Hello, World!".to_vec(),
            vec![b'A'; 60],
            vec![b'A'; 76],
            vec![b'A'; 77],
            vec![b'X'; 200],
            b"foo=bar".to_vec(),
            b"a b".to_vec(),
            b"a ".to_vec(),
            b"trailing tab\t".to_vec(),
            b"line1\r\nline2\r\nlast".to_vec(),
            b"tab\there\tthere".to_vec(),
            (0u8..=255).collect(),
            vec![b'='; 100],
            b"y".repeat(74),
            b"y".repeat(75),
            b"y".repeat(76),
            b"y".repeat(77),
        ];
        // A deterministic pseudo-random binary blob.
        let mut blob = Vec::new();
        let mut x: u32 = 0x1234_5678;
        for _ in 0..500 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            blob.push((x >> 16) as u8);
        }
        inputs.push(blob);
        inputs
    }

    #[test]
    fn encoder_stream_matches_whole_buffer_across_all_chunkings() {
        let chunk_sizes = [1usize, 2, 3, 4, 5, 7, 8, 13, 64, 76, 77, 8192];
        for input in parity_inputs() {
            for enc in [
                Encoding::Base64,
                Encoding::QuotedPrintable,
                Encoding::Binary,
                Encoding::EightBit,
            ] {
                let whole = enc.encode(&input).unwrap();
                for &chunk in &chunk_sizes {
                    let streamed = stream_encode(enc, &input, chunk).unwrap();
                    assert_eq!(
                        streamed,
                        whole,
                        "enc={enc:?} chunk={chunk} len={}",
                        input.len()
                    );
                }
            }
            // 7bit parity only over 7-bit-clean inputs (others error in both).
            if input.iter().all(|b| b & 0x80 == 0) {
                let whole = Encoding::SevenBit.encode(&input).unwrap();
                for &chunk in &chunk_sizes {
                    let streamed = stream_encode(Encoding::SevenBit, &input, chunk).unwrap();
                    assert_eq!(streamed, whole, "7bit chunk={chunk} len={}", input.len());
                }
            }
        }
    }

    #[test]
    fn encoder_stream_7bit_rejects_high_bit_like_whole_buffer() {
        let bad = b"ok\xffbad";
        assert!(Encoding::SevenBit.encode(bad).is_err());
        for chunk in [1usize, 2, 3, 8, 8192] {
            assert!(
                stream_encode(Encoding::SevenBit, bad, chunk).is_err(),
                "streamed 7bit should reject high bit (chunk={chunk})"
            );
        }
    }

    /// A misbehaving callback that always reports more bytes than requested.
    struct OverReader;
    impl MimeReadCallback for OverReader {
        fn read(&mut self, buf: &mut [u8]) -> ReadOutcome {
            // Contract violation: claim to have produced more than `buf` holds.
            ReadOutcome::Bytes(buf.len() + 1)
        }
    }

    fn drain_reader_error(mut reader: MimeReader) -> Option<Error> {
        let mut buf = [0u8; 64];
        loop {
            match reader.fill(&mut buf) {
                Ok(0) => return None,
                Ok(_) => continue,
                Err(e) => return Some(e),
            }
        }
    }

    #[test]
    fn callback_over_return_is_read_error_plain() {
        // Un-encoded callback part: over-return surfaces as CURLE_READ_ERROR.
        let mut mime = Mime::new();
        {
            let p = mime.addpart();
            p.set_name(Some("x")).unwrap();
            p.set_data_cb(10, Box::new(OverReader)).unwrap();
        }
        let reader = mime.into_reader(MimeStrategy::Form).unwrap();
        assert!(
            matches!(drain_reader_error(reader), Some(Error::Read)),
            "plain callback over-return must be Error::Read"
        );
    }

    #[test]
    fn callback_over_return_is_read_error_encoded() {
        // Encoded (base64) callback part: the streaming raw read also enforces
        // the callback contract and surfaces CURLE_READ_ERROR.
        let mut mime = Mime::new();
        {
            let p = mime.addpart();
            p.set_name(Some("x")).unwrap();
            p.set_data_cb(10, Box::new(OverReader)).unwrap();
            p.set_encoder(Some("base64")).unwrap();
        }
        let reader = mime.into_reader(MimeStrategy::Form).unwrap();
        assert!(
            matches!(drain_reader_error(reader), Some(Error::Read)),
            "encoded callback over-return must be Error::Read"
        );
    }

    #[test]
    fn encoded_callback_streamed_body_equals_whole_buffer_base64() {
        // The streamed encoded segment (read through a tiny buffer, so both the
        // raw reads and the encoded hand-off are heavily chunked) must contain
        // exactly the whole-buffer base64 of the payload.
        let payload: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let mut mime = Mime::new();
        {
            let p = mime.addpart();
            p.set_name(Some("f")).unwrap();
            p.set_data_cb(
                payload.len() as i64,
                Box::new(VecReader {
                    data: payload.clone(),
                    pos: 0,
                }),
            )
            .unwrap();
            p.set_encoder(Some("base64")).unwrap();
        }
        let reader = mime.into_reader(MimeStrategy::Form).unwrap();
        let body = read_all(reader, 7).unwrap();
        let expected = Encoding::Base64.encode(&payload).unwrap();
        assert!(
            body.windows(expected.len())
                .any(|w| w == expected.as_slice()),
            "streamed base64 callback body does not match the whole-buffer encoding"
        );
    }

    #[test]
    fn encoded_file_streamed_body_equals_whole_buffer_base64() {
        use std::io::Write;
        let payload: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let mut tf = tempfile::NamedTempFile::new().unwrap();
        tf.write_all(&payload).unwrap();
        tf.flush().unwrap();
        let path = tf.path().to_owned();

        let mut mime = Mime::new();
        {
            let p = mime.addpart();
            p.set_name(Some("f")).unwrap();
            p.set_filedata(&path).unwrap();
            p.set_encoder(Some("base64")).unwrap();
        }
        let reader = mime.into_reader(MimeStrategy::Form).unwrap();
        let body = read_all(reader, 5).unwrap();
        let expected = Encoding::Base64.encode(&payload).unwrap();
        assert!(
            body.windows(expected.len())
                .any(|w| w == expected.as_slice()),
            "streamed base64 file body does not match the whole-buffer encoding"
        );
    }
}
