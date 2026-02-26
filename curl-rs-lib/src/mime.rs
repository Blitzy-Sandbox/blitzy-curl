// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
// Rust rewrite of lib/mime.c and lib/formdata.c — MIME multipart builder for
// HTTP form submissions (`multipart/form-data`, `multipart/mixed`).
//
// This module provides the `Mime` and `MimePart` types that implement the
// `curl_mime_*` C API surface in idiomatic Rust.  The design replaces the C
// linked-list-based `curl_mimepart` chain and manual memory management with
// `Vec<MimePart>` and Rust ownership semantics.
//
// Streaming serialisation is achieved via the `encode()` method which returns
// a `Box<dyn Read + Send>` that chains per-part readers — boundaries and
// headers are small and buffered, while file-backed parts stream directly
// from disk without loading the entire payload into memory.
//
// # Zero `unsafe` blocks
//
// This module contains no `unsafe` code.

use std::fmt;
use std::fs;
use std::io::{self, BufReader, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use rand::distributions::Alphanumeric;
use rand::Rng;

use crate::error::{CurlError, CurlResult};
use crate::slist::SList;

// ---------------------------------------------------------------------------
// Constants — matching C lib/mime.h values
// ---------------------------------------------------------------------------

/// Number of leading dashes in a MIME boundary string.
const MIME_BOUNDARY_DASHES: usize = 24;

/// Number of random alphanumeric characters appended after the dashes.
const MIME_RAND_BOUNDARY_CHARS: usize = 22;

/// Maximum line length for encoded content (Base64, Quoted-Printable).
const MAX_ENCODED_LINE_LENGTH: usize = 76;

/// Default Content-Type for file parts when the extension is unknown.
const FILE_CONTENTTYPE_DEFAULT: &str = "application/octet-stream";

/// Default Content-Type for multipart sub-parts.
const MULTIPART_CONTENTTYPE_DEFAULT: &str = "multipart/mixed";

/// Default Content-Disposition value.
const DISPOSITION_DEFAULT: &str = "attachment";

// ---------------------------------------------------------------------------
// MimeEncoder — content-transfer-encoding
// ---------------------------------------------------------------------------

/// Content transfer encoding applied to a MIME part's body during
/// serialisation.
///
/// The variant names map 1:1 to the C `struct mime_encoder` name strings
/// (`"base64"`, `"quoted-printable"`, `"binary"`, `"7bit"`, `"8bit"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MimeEncoder {
    /// Base64 encoding (RFC 4648) with 76-character line wrapping.
    Base64,
    /// Quoted-Printable encoding (RFC 2045).
    QuotedPrintable,
    /// Binary — no encoding, no line-length restriction.
    Binary,
    /// 7-bit — pass-through; high-bit bytes are treated as an error.
    SevenBit,
    /// 8-bit — pass-through; any byte value is acceptable.
    EightBit,
}

impl fmt::Display for MimeEncoder {
    /// Produces the wire-format name used in `Content-Transfer-Encoding`
    /// headers, matching the C encoder name strings.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Base64 => "base64",
            Self::QuotedPrintable => "quoted-printable",
            Self::Binary => "binary",
            Self::SevenBit => "7bit",
            Self::EightBit => "8bit",
        };
        f.write_str(name)
    }
}

impl MimeEncoder {
    /// Parses an encoder name (case-insensitive) into a [`MimeEncoder`]
    /// variant.  Returns `None` for unrecognised names, matching the C
    /// `curl_mime_encoder` behaviour.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "base64" => Some(Self::Base64),
            "quoted-printable" => Some(Self::QuotedPrintable),
            "binary" => Some(Self::Binary),
            "7bit" => Some(Self::SevenBit),
            "8bit" => Some(Self::EightBit),
            _ => None,
        }
    }

    /// Returns the encoded size for a given raw byte count, or `None` when
    /// the encoded size cannot be determined without reading the data
    /// (Quoted-Printable).
    fn encoded_size(&self, raw_size: u64) -> Option<u64> {
        match self {
            Self::Base64 => {
                if raw_size == 0 {
                    return Some(0);
                }
                // Number of Base64 characters (4 per 3-byte group, padding).
                let base64_chars = 4 * raw_size.div_ceil(3);
                // CRLF every MAX_ENCODED_LINE_LENGTH characters.
                let line_breaks = if base64_chars > 0 {
                    2 * ((base64_chars - 1) / MAX_ENCODED_LINE_LENGTH as u64)
                } else {
                    0
                };
                Some(base64_chars + line_breaks)
            }
            Self::QuotedPrintable => {
                // QP encoded size depends on data content; cannot pre-compute.
                if raw_size == 0 {
                    Some(0)
                } else {
                    None
                }
            }
            Self::Binary | Self::EightBit | Self::SevenBit => Some(raw_size),
        }
    }
}

// ---------------------------------------------------------------------------
// MimeData — part data source
// ---------------------------------------------------------------------------

/// Data source for a [`MimePart`].
///
/// Each variant corresponds to a different `curl_mime_*` setter in the C API.
pub enum MimeData {
    /// No data has been set (`curl_mime_data(part, NULL, 0)`).
    None,
    /// In-memory binary data (`curl_mime_data`).
    Bytes(Vec<u8>),
    /// In-memory string data (`curl_mime_data` with string).
    String(String),
    /// File path — data read lazily during serialisation (`curl_mime_filedata`).
    File(PathBuf),
    /// Caller-supplied reader (`curl_mime_data_cb`).
    /// Wrapped in `Mutex<Option<…>>` so that `encode(&self)` can consume the
    /// reader exactly once without requiring `&mut self`.
    Callback(Mutex<Option<Box<dyn Read + Send>>>),
    /// Nested MIME multipart (`curl_mime_subparts`).
    Subparts(Box<Mime>),
}

impl fmt::Debug for MimeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "MimeData::None"),
            Self::Bytes(b) => write!(f, "MimeData::Bytes({} bytes)", b.len()),
            Self::String(s) => f.debug_tuple("MimeData::String").field(s).finish(),
            Self::File(p) => f.debug_tuple("MimeData::File").field(p).finish(),
            Self::Callback(_) => write!(f, "MimeData::Callback(...)"),
            Self::Subparts(m) => f.debug_tuple("MimeData::Subparts").field(m).finish(),
        }
    }
}

// ---------------------------------------------------------------------------
// MimeStrategy (crate-internal)
// ---------------------------------------------------------------------------

/// Header generation strategy, matching C `enum mimestrategy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MimeStrategy {
    /// Email-style MIME (RFC 2045).
    Mail,
    /// HTTP multipart/form-data (RFC 7578 / WHATWG).
    Form,
}

// ---------------------------------------------------------------------------
// MimePart
// ---------------------------------------------------------------------------

/// A single part within a MIME multipart message.
///
/// Constructed via [`Mime::add_part`]; configured through the `set_*` builder
/// methods that mirror the C `curl_mime_*` API.
#[derive(Debug)]
pub struct MimePart {
    /// Field name for `Content-Disposition: …; name="…"`.
    name: Option<String>,
    /// Data source for this part's body.
    data: MimeData,
    /// Filename for `Content-Disposition: …; filename="…"`.
    filename: Option<String>,
    /// Explicit Content-Type (overrides auto-detection).
    content_type: Option<String>,
    /// User-provided custom headers (set via `set_headers`).
    user_headers: SList,
    /// Auto-generated headers (built by `prepare_headers`).
    curl_headers: SList,
    /// Content transfer encoding for this part.
    encoder: Option<MimeEncoder>,
    /// Explicit data size in bytes (`None` = unknown / must stream).
    data_size: Option<u64>,
}

impl MimePart {
    /// Creates a blank part with no data, no name, and no headers.
    fn new() -> Self {
        Self {
            name: None,
            data: MimeData::None,
            filename: None,
            content_type: None,
            user_headers: SList::new(),
            curl_headers: SList::new(),
            encoder: None,
            data_size: None,
        }
    }

    // -- Public setter API (matching curl_mime_* C functions) ---------------

    /// Sets the field name, corresponding to `curl_mime_name`.
    pub fn set_name(&mut self, name: &str) {
        self.name = Some(name.to_owned());
    }

    /// Sets part content from a byte slice, corresponding to `curl_mime_data`.
    pub fn set_data(&mut self, data: &[u8]) {
        self.data_size = Some(data.len() as u64);
        self.data = MimeData::Bytes(data.to_vec());
    }

    /// Sets part content from a string, corresponding to `curl_mime_data`
    /// with `CURL_ZERO_TERMINATED`.
    pub fn set_data_string(&mut self, data: &str) {
        self.data_size = Some(data.len() as u64);
        self.data = MimeData::String(data.to_owned());
    }

    /// Sets part content from a file path, corresponding to
    /// `curl_mime_filedata`.
    ///
    /// The file metadata is read immediately to determine the size.  As a
    /// side-effect the remote filename is set to the path's basename (the C
    /// API does the same).
    pub fn set_file(&mut self, path: &Path) -> CurlResult<()> {
        let metadata = fs::metadata(path).map_err(|_| CurlError::ReadError)?;
        self.data = MimeData::File(path.to_path_buf());
        self.data_size = if metadata.is_file() {
            Some(metadata.len())
        } else {
            Option::None
        };
        // Auto-set filename from basename (matches C curl_mime_filedata).
        if let Some(file_name) = path.file_name() {
            if let Some(name_str) = file_name.to_str() {
                self.filename = Some(name_str.to_owned());
            }
        }
        Ok(())
    }

    /// Sets the remote filename, corresponding to `curl_mime_filename`.
    pub fn set_filename(&mut self, filename: &str) {
        self.filename = Some(filename.to_owned());
    }

    /// Sets the Content-Type, corresponding to `curl_mime_type`.
    pub fn set_type(&mut self, content_type: &str) {
        self.content_type = Some(content_type.to_owned());
    }

    /// Replaces the custom headers for this part, corresponding to
    /// `curl_mime_headers`.
    pub fn set_headers(&mut self, headers: SList) {
        self.user_headers = headers;
    }

    /// Sets the content-transfer-encoding, corresponding to
    /// `curl_mime_encoder`.
    pub fn set_encoder(&mut self, encoder: MimeEncoder) {
        self.encoder = Some(encoder);
    }

    /// Attaches nested MIME sub-parts, corresponding to
    /// `curl_mime_subparts`.
    pub fn set_subparts(&mut self, mime: Mime) -> CurlResult<()> {
        self.data = MimeData::Subparts(Box::new(mime));
        self.data_size = Option::None; // computed from subparts
        Ok(())
    }

    /// Sets part content from a caller-supplied reader, corresponding to
    /// `curl_mime_data_cb`.
    ///
    /// `size` is the expected byte count (`None` for unknown), used for
    /// Content-Length calculation.
    pub fn set_data_callback(
        &mut self,
        reader: Box<dyn Read + Send>,
        size: Option<u64>,
    ) {
        self.data = MimeData::Callback(Mutex::new(Some(reader)));
        self.data_size = size;
    }

    /// Produces a deep copy of this part.
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if the part uses a
    /// callback reader (which cannot be cloned).
    pub fn duplicate(&self) -> CurlResult<MimePart> {
        let data = match &self.data {
            MimeData::None => MimeData::None,
            MimeData::Bytes(b) => MimeData::Bytes(b.clone()),
            MimeData::String(s) => MimeData::String(s.clone()),
            MimeData::File(p) => MimeData::File(p.clone()),
            MimeData::Callback(_) => {
                return Err(CurlError::BadFunctionArgument);
            }
            MimeData::Subparts(m) => MimeData::Subparts(Box::new(m.duplicate()?)),
        };

        Ok(MimePart {
            name: self.name.clone(),
            data,
            filename: self.filename.clone(),
            content_type: self.content_type.clone(),
            user_headers: self.user_headers.duplicate(),
            curl_headers: self.curl_headers.duplicate(),
            encoder: self.encoder,
            data_size: self.data_size,
        })
    }

    // -- Internal helpers --------------------------------------------------

    /// Returns the raw (unencoded) data size, or `None` when unknown.
    fn raw_data_size(&self) -> Option<u64> {
        match &self.data {
            MimeData::None => Some(0),
            MimeData::Bytes(b) => Some(b.len() as u64),
            MimeData::String(s) => Some(s.len() as u64),
            MimeData::File(_) => self.data_size,
            MimeData::Callback(_) => self.data_size,
            MimeData::Subparts(mime) => mime.content_length(),
        }
    }

    /// Returns the encoded body size, or `None` when unknown.
    fn encoded_data_size(&self) -> Option<u64> {
        let raw = self.raw_data_size()?;
        if let Some(enc) = &self.encoder {
            enc.encoded_size(raw)
        } else {
            Some(raw)
        }
    }

    /// Returns the total serialised size of this part (headers + CRLF + body),
    /// or `None` when the body size is unknown.
    fn total_size(&self) -> Option<u64> {
        let body_size = self.encoded_data_size()?;
        let mut header_size: u64 = 0;
        for h in self.curl_headers.iter() {
            header_size += h.len() as u64 + 2; // header + CRLF
        }
        for h in self.user_headers.iter() {
            // Content-Type from user headers is suppressed in favour of the
            // auto-generated one in curl_headers.
            if !header_starts_with_ci(h, "content-type:") {
                header_size += h.len() as u64 + 2;
            }
        }
        header_size += 2; // blank line separating headers from body
        Some(header_size + body_size)
    }

    /// Creates a streaming `Read` for this part's body, applying the
    /// configured encoder.
    fn create_body_reader(&self) -> CurlResult<Box<dyn Read + Send>> {
        let reader: Box<dyn Read + Send> = match &self.data {
            MimeData::None => Box::new(io::empty()),
            MimeData::Bytes(b) => Box::new(Cursor::new(b.clone())),
            MimeData::String(s) => Box::new(Cursor::new(s.as_bytes().to_vec())),
            MimeData::File(path) => {
                let file = fs::File::open(path).map_err(|_| CurlError::ReadError)?;
                Box::new(BufReader::new(file))
            }
            MimeData::Callback(mutex) => {
                let mut guard = mutex.lock().map_err(|_| CurlError::ReadError)?;
                guard.take().ok_or(CurlError::ReadError)?
            }
            MimeData::Subparts(mime) => {
                return mime.encode();
            }
        };
        // Wrap with encoder if one is configured.
        match self.encoder {
            Some(MimeEncoder::Base64) => Ok(Box::new(Base64EncodingReader::new(reader))),
            Some(MimeEncoder::QuotedPrintable) => Ok(Box::new(QPEncodingReader::new(reader))),
            _ => Ok(reader), // Binary / 7bit / 8bit / None pass through.
        }
    }

    /// Serialises all headers for this part into a byte vector (including the
    /// terminating blank line).
    fn serialise_headers(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        for h in self.curl_headers.iter() {
            buf.extend_from_slice(h.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        for h in self.user_headers.iter() {
            if !header_starts_with_ci(h, "content-type:") {
                buf.extend_from_slice(h.as_bytes());
                buf.extend_from_slice(b"\r\n");
            }
        }
        buf.extend_from_slice(b"\r\n"); // end-of-headers blank line
        buf
    }

    /// Builds the auto-generated `curl_headers` for this part.
    ///
    /// This is the Rust equivalent of `Curl_mime_prepare_headers` in the C
    /// code.  `parent_content_type` is the Content-Type of the enclosing
    /// multipart (used for defaulting), `disposition` is the default
    /// Content-Disposition (e.g. `"form-data"` for HTTP forms), and
    /// `strategy` selects the escaping rules (HTTP form vs. mail).
    pub(crate) fn prepare_headers_internal(
        &mut self,
        _parent_content_type: Option<&str>,
        disposition: Option<&str>,
        strategy: MimeStrategy,
    ) -> CurlResult<()> {
        // Clear previously generated headers.
        self.curl_headers = SList::new();

        // --- Determine effective Content-Type ---
        let explicit_ct = self.content_type.clone();
        let user_ct = search_header(&self.user_headers, "Content-Type");
        let mut content_type: Option<String> = explicit_ct.or(user_ct);

        // Auto-detect when no explicit type is set.
        if content_type.is_none() {
            match &self.data {
                MimeData::Subparts(_) => {
                    content_type = Some(MULTIPART_CONTENTTYPE_DEFAULT.to_owned());
                }
                MimeData::File(path) => {
                    let ct = self
                        .filename
                        .as_deref()
                        .and_then(mime_contenttype)
                        .or_else(|| path.to_str().and_then(mime_contenttype));
                    if let Some(detected) = ct {
                        content_type = Some(detected.to_owned());
                    } else if self.filename.is_some() {
                        content_type = Some(FILE_CONTENTTYPE_DEFAULT.to_owned());
                    }
                }
                _ => {
                    if let Some(ct) = self.filename.as_deref().and_then(mime_contenttype) {
                        content_type = Some(ct.to_owned());
                    }
                }
            }
        }

        // For subparts, extract the boundary for the Content-Type header.
        let boundary: Option<String> = if let MimeData::Subparts(mime) = &self.data {
            Some(mime.boundary.clone())
        } else {
            // Suppress auto-detected text/plain in form mode when there is
            // no explicit filename (matches C behaviour).
            if let Some(ref ct) = content_type {
                if self.content_type.is_none()
                    && search_header(&self.user_headers, "Content-Type").is_none()
                    && content_type_match(ct, "text/plain")
                    && strategy != MimeStrategy::Mail
                    && self.filename.is_none()
                {
                    content_type = None;
                }
            }
            None
        };

        // --- Content-Disposition ---
        if !has_header(&self.user_headers, "Content-Disposition") {
            let mut disp: Option<String> = disposition.map(String::from);

            if disp.is_none()
                && (self.filename.is_some()
                    || self.name.is_some()
                    || content_type
                        .as_ref()
                        .is_some_and(|ct| !ct.starts_with("multipart/")))
            {
                disp = Some(DISPOSITION_DEFAULT.to_owned());
            }

            // Skip bare "attachment" when neither name nor filename is present.
            if disp.as_deref() == Some("attachment")
                && self.name.is_none()
                && self.filename.is_none()
            {
                disp = None;
            }

            if let Some(d) = disp {
                let mut header = format!("Content-Disposition: {d}");
                if let Some(ref name) = self.name {
                    let escaped = escape_string(name, strategy);
                    header.push_str(&format!("; name=\"{escaped}\""));
                }
                if let Some(ref fname) = self.filename {
                    let escaped = escape_string(fname, strategy);
                    header.push_str(&format!("; filename=\"{escaped}\""));
                }
                self.curl_headers.append_nodup(header);
            }
        }

        // --- Content-Type ---
        if let Some(ref ct) = content_type {
            let header = if let Some(ref b) = boundary {
                format!("Content-Type: {ct}; boundary={b}")
            } else {
                format!("Content-Type: {ct}")
            };
            self.curl_headers.append_nodup(header);
        }

        // --- Content-Transfer-Encoding ---
        if !has_header(&self.user_headers, "Content-Transfer-Encoding") {
            let cte: Option<String> = if let Some(ref enc) = self.encoder {
                Some(enc.to_string())
            } else if content_type.is_some()
                && strategy == MimeStrategy::Mail
                && !matches!(self.data, MimeData::Subparts(_))
            {
                Some("8bit".to_owned())
            } else {
                None
            };

            if let Some(cte_val) = cte {
                self.curl_headers
                    .append_nodup(format!("Content-Transfer-Encoding: {cte_val}"));
            }
        }

        // --- Recursive sub-part header preparation ---
        if let MimeData::Subparts(ref mut mime) = self.data {
            let sub_disp = if content_type
                .as_deref()
                .is_some_and(|ct| content_type_match(ct, "multipart/form-data"))
            {
                Some("form-data")
            } else {
                None
            };
            for part in &mut mime.parts {
                part.prepare_headers_internal(content_type.as_deref(), sub_disp, strategy)?;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Mime — the top-level multipart container
// ---------------------------------------------------------------------------

/// A MIME multipart container holding zero or more [`MimePart`]s.
///
/// This is the Rust equivalent of `struct curl_mime` in C.  Construct with
/// [`Mime::new()`], add parts with [`Mime::add_part()`], prepare headers
/// with [`Mime::prepare_headers()`], and serialise with [`Mime::encode()`].
#[derive(Debug)]
pub struct Mime {
    /// The ordered list of parts in this multipart message.
    parts: Vec<MimePart>,
    /// The boundary string (24 dashes + 22 random alphanumeric characters).
    boundary: String,
}

impl Mime {
    /// Creates a new, empty MIME multipart structure with a randomly
    /// generated boundary string.
    ///
    /// The boundary format matches the C implementation: 24 leading dashes
    /// followed by 22 random alphanumeric characters (RFC 2046 compliant).
    pub fn new() -> Self {
        Self {
            parts: Vec::new(),
            boundary: generate_boundary(),
        }
    }

    /// Appends a new, blank [`MimePart`] and returns a mutable reference to
    /// it for configuration via the `set_*` builder methods.
    ///
    /// This is the Rust equivalent of `curl_mime_addpart`.
    pub fn add_part(&mut self) -> &mut MimePart {
        self.parts.push(MimePart::new());
        // SAFETY (logic): `push` always succeeds for a `Vec` and the
        // reference is valid for the lifetime of `&mut self`.
        self.parts.last_mut().expect("just pushed a part")
    }

    /// Serialises the multipart message into a streaming reader.
    ///
    /// Returns a `Box<dyn Read + Send>` that produces the complete
    /// multipart body (boundaries, per-part headers, and encoded body
    /// data).  File-backed parts are opened lazily so that large uploads
    /// stream without being buffered entirely in memory.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::ReadError`] if a file-backed part cannot be
    /// opened, or if a callback reader has already been consumed.
    pub fn encode(&self) -> CurlResult<Box<dyn Read + Send>> {
        let mut readers: Vec<Box<dyn Read + Send>> = Vec::new();

        for (i, part) in self.parts.iter().enumerate() {
            // -- Boundary --
            let boundary_bytes = if i == 0 {
                format!("--{}\r\n", self.boundary).into_bytes()
            } else {
                format!("\r\n--{}\r\n", self.boundary).into_bytes()
            };
            readers.push(Box::new(Cursor::new(boundary_bytes)));

            // -- Part headers --
            let header_bytes = part.serialise_headers();
            readers.push(Box::new(Cursor::new(header_bytes)));

            // -- Part body --
            readers.push(part.create_body_reader()?);
        }

        // -- Closing boundary --
        if !self.parts.is_empty() {
            let final_boundary = format!("\r\n--{}--\r\n", self.boundary).into_bytes();
            readers.push(Box::new(Cursor::new(final_boundary)));
        }

        Ok(Box::new(ChainedReader::new(readers)))
    }

    /// Returns the `Content-Type` header value for this multipart,
    /// including the boundary parameter.
    ///
    /// Example: `"multipart/form-data; boundary=------------------------AbCdEfGhIjKlMnOpQrStUv"`
    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    /// Returns a reference to the boundary string.
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// Computes the total byte length of the serialised multipart body, or
    /// `None` when any part has an unknown size (e.g. a callback reader
    /// without an explicit size, or a Quoted-Printable–encoded part).
    ///
    /// The calculation matches the C `multipart_size()` algorithm:
    /// `boundary_size × (N + 1) + Σ part_total_size`.
    pub fn content_length(&self) -> Option<u64> {
        if self.parts.is_empty() {
            return Some(0);
        }
        let boundary_len = self.boundary.len();
        // Each inter-part boundary is: "\r\n--" + boundary + "\r\n"  = 4 + len + 2
        // The first boundary saves 2 bytes ("\r\n" prefix omitted) and the
        // final boundary adds 2 bytes ("--" suffix).  These cancel out, so
        // the uniform boundary_size works for the total.
        let boundary_size: u64 = (4 + boundary_len + 2) as u64;
        let mut size: u64 = boundary_size; // accounts for the final boundary

        for part in &self.parts {
            let part_size = part.total_size()?;
            size = size.checked_add(boundary_size + part_size)?;
        }
        Some(size)
    }

    /// Generates auto-headers (`Content-Disposition`, `Content-Type`,
    /// `Content-Transfer-Encoding`) for every part using the HTTP
    /// `multipart/form-data` strategy.
    ///
    /// This must be called before [`encode()`](Mime::encode) for the
    /// serialised output to contain correct per-part headers.
    pub fn prepare_headers(&mut self) -> CurlResult<()> {
        for part in &mut self.parts {
            part.prepare_headers_internal(None, Some("form-data"), MimeStrategy::Form)?;
        }
        Ok(())
    }

    /// Produces a deep copy of this MIME structure (with a fresh boundary).
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if any part uses a
    /// callback reader.
    pub fn duplicate(&self) -> CurlResult<Mime> {
        let mut new_mime = Mime {
            parts: Vec::with_capacity(self.parts.len()),
            boundary: generate_boundary(),
        };
        for part in &self.parts {
            new_mime.parts.push(part.duplicate()?);
        }
        Ok(new_mime)
    }
}

impl Default for Mime {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// mime_contenttype — file-extension → MIME type lookup
// ---------------------------------------------------------------------------

/// Returns the MIME content-type for the given filename based on its
/// extension, or `None` if the extension is not recognised.
///
/// The lookup table matches the C `Curl_mime_contenttype` function exactly.
pub fn mime_contenttype(filename: &str) -> Option<&'static str> {
    /// (extension, MIME type) pairs — order matches the C source.
    static MAP: &[(&str, &str)] = &[
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

    let lower = filename.to_ascii_lowercase();
    for &(ext, ct) in MAP {
        if lower.ends_with(ext) {
            return Some(ct);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Internal helper functions
// ---------------------------------------------------------------------------

/// Generates a MIME boundary: 24 dashes followed by 22 random alphanumeric
/// characters, matching the C `curl_mime_init` format.
fn generate_boundary() -> String {
    let random_part: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(MIME_RAND_BOUNDARY_CHARS)
        .map(char::from)
        .collect();
    let mut boundary = String::with_capacity(MIME_BOUNDARY_DASHES + MIME_RAND_BOUNDARY_CHARS);
    for _ in 0..MIME_BOUNDARY_DASHES {
        boundary.push('-');
    }
    boundary.push_str(&random_part);
    boundary
}

/// Escapes a header value according to the chosen strategy.
///
/// * **Form** (WHATWG HTML 4.10.21.8): `"` → `%22`, `\r` → `%0D`, `\n` → `%0A`
/// * **Mail** (RFC 2047): `\` → `\\`, `"` → `\"`
fn escape_string(s: &str, strategy: MimeStrategy) -> String {
    let mut result = String::with_capacity(s.len());
    match strategy {
        MimeStrategy::Form => {
            for ch in s.chars() {
                match ch {
                    '"' => result.push_str("%22"),
                    '\r' => result.push_str("%0D"),
                    '\n' => result.push_str("%0A"),
                    _ => result.push(ch),
                }
            }
        }
        MimeStrategy::Mail => {
            for ch in s.chars() {
                match ch {
                    '\\' => result.push_str("\\\\"),
                    '"' => result.push_str("\\\""),
                    _ => result.push(ch),
                }
            }
        }
    }
    result
}

/// Case-insensitive header search: returns the trimmed value after the colon
/// for the first header matching `label`, or `None`.
fn search_header(headers: &SList, label: &str) -> Option<String> {
    let label_len = label.len();
    for h in headers.iter() {
        if h.len() > label_len
            && h.as_bytes()[label_len] == b':'
            && h[..label_len].eq_ignore_ascii_case(label)
        {
            return Some(h[label_len + 1..].trim_start().to_owned());
        }
    }
    None
}

/// Returns `true` if any header in `headers` matches `label` (case-insensitive).
fn has_header(headers: &SList, label: &str) -> bool {
    search_header(headers, label).is_some()
}

/// Case-insensitive prefix check for header lines.
fn header_starts_with_ci(header: &str, prefix: &str) -> bool {
    header.len() >= prefix.len() && header[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Returns `true` if `content_type` starts with `target` (case-insensitive)
/// and is followed by end-of-string or a delimiter (whitespace / `;`).
fn content_type_match(content_type: &str, target: &str) -> bool {
    if content_type.len() < target.len() {
        return false;
    }
    if !content_type[..target.len()].eq_ignore_ascii_case(target) {
        return false;
    }
    if content_type.len() == target.len() {
        return true;
    }
    matches!(
        content_type.as_bytes()[target.len()],
        b'\t' | b'\r' | b'\n' | b' ' | b';'
    )
}

// ---------------------------------------------------------------------------
// ChainedReader — chains multiple readers sequentially
// ---------------------------------------------------------------------------

/// A reader that concatenates a vector of inner readers, reading from each
/// in turn until all are exhausted.  This is the core of the streaming MIME
/// serialisation returned by [`Mime::encode`].
struct ChainedReader {
    readers: Vec<Box<dyn Read + Send>>,
    current: usize,
}

impl ChainedReader {
    fn new(readers: Vec<Box<dyn Read + Send>>) -> Self {
        Self {
            readers,
            current: 0,
        }
    }
}

impl Read for ChainedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.current < self.readers.len() {
            let n = self.readers[self.current].read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            self.current += 1;
        }
        Ok(0) // all readers exhausted
    }
}

// ---------------------------------------------------------------------------
// Base64EncodingReader — streaming Base64 encoder with 76-char line wrap
// ---------------------------------------------------------------------------

/// Wraps an inner reader and produces Base64-encoded output with CRLF line
/// breaks every [`MAX_ENCODED_LINE_LENGTH`] characters (76), matching the C
/// `encoder_base64_read` behaviour.
struct Base64EncodingReader {
    inner: Box<dyn Read + Send>,
    /// Buffered encoded output waiting to be served.
    out_buf: Vec<u8>,
    /// Current read position within `out_buf`.
    out_pos: usize,
    /// Current position on the output line (for line-wrapping).
    line_pos: usize,
    /// `true` once the inner reader is exhausted.
    finished: bool,
}

impl Base64EncodingReader {
    fn new(inner: Box<dyn Read + Send>) -> Self {
        Self {
            inner,
            out_buf: Vec::with_capacity(256),
            out_pos: 0,
            line_pos: 0,
            finished: false,
        }
    }

    /// Reads a chunk from the inner reader, Base64-encodes it, and appends
    /// the encoded bytes (with CRLF line-wrapping) to `self.out_buf`.
    fn fill_buffer(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }

        // Read up to 57 raw bytes → 76 Base64 characters (one full line).
        let mut raw = [0u8; 57];
        let mut total = 0usize;
        while total < raw.len() {
            match self.inner.read(&mut raw[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        if total == 0 {
            self.finished = true;
            return Ok(());
        }

        let encoded = base64::engine::general_purpose::STANDARD.encode(&raw[..total]);
        self.out_buf.clear();
        self.out_pos = 0;

        for &byte in encoded.as_bytes() {
            if self.line_pos >= MAX_ENCODED_LINE_LENGTH {
                self.out_buf.extend_from_slice(b"\r\n");
                self.line_pos = 0;
            }
            self.out_buf.push(byte);
            self.line_pos += 1;
        }

        Ok(())
    }
}

impl Read for Base64EncodingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // Serve bytes from the output buffer first.
            if self.out_pos < self.out_buf.len() {
                let avail = self.out_buf.len() - self.out_pos;
                let n = buf.len().min(avail);
                buf[..n].copy_from_slice(&self.out_buf[self.out_pos..self.out_pos + n]);
                self.out_pos += n;
                return Ok(n);
            }

            if self.finished {
                return Ok(0);
            }

            self.fill_buffer()?;

            if self.out_buf.is_empty() && self.finished {
                return Ok(0);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// QPEncodingReader — streaming Quoted-Printable encoder
// ---------------------------------------------------------------------------

/// Hex digits for QP `=XX` encoding.
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Wraps an inner reader and produces Quoted-Printable–encoded output,
/// matching the C `encoder_qp_read` behaviour.
struct QPEncodingReader {
    inner: Box<dyn Read + Send>,
    out_buf: Vec<u8>,
    out_pos: usize,
    line_pos: usize,
    finished: bool,
}

impl QPEncodingReader {
    fn new(inner: Box<dyn Read + Send>) -> Self {
        Self {
            inner,
            out_buf: Vec::with_capacity(512),
            out_pos: 0,
            line_pos: 0,
            finished: false,
        }
    }

    /// Appends the QP-encoded representation of `byte` (`=XX`) to `out_buf`,
    /// inserting a soft line-break first if necessary.
    fn push_encoded(&mut self, byte: u8) {
        if self.line_pos + 3 > MAX_ENCODED_LINE_LENGTH {
            self.out_buf.extend_from_slice(b"=\r\n");
            self.line_pos = 0;
        }
        self.out_buf.push(b'=');
        self.out_buf.push(HEX_UPPER[(byte >> 4) as usize]);
        self.out_buf.push(HEX_UPPER[(byte & 0x0F) as usize]);
        self.line_pos += 3;
    }

    /// Pushes a literal byte, inserting a soft line-break first if necessary.
    fn push_literal(&mut self, byte: u8) {
        if self.line_pos + 1 >= MAX_ENCODED_LINE_LENGTH {
            self.out_buf.extend_from_slice(b"=\r\n");
            self.line_pos = 0;
        }
        self.out_buf.push(byte);
        self.line_pos += 1;
    }

    /// Reads a chunk from the inner reader and QP-encodes it.
    fn fill_buffer(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }

        let mut raw = [0u8; 1024];
        let mut total = 0usize;
        while total < raw.len() {
            match self.inner.read(&mut raw[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        if total == 0 {
            self.finished = true;
            return Ok(());
        }

        self.out_buf.clear();
        self.out_pos = 0;

        let mut i = 0usize;
        while i < total {
            let byte = raw[i];
            match byte {
                // CRLF — pass through and reset line position.
                b'\r' if i + 1 < total && raw[i + 1] == b'\n' => {
                    self.out_buf.extend_from_slice(b"\r\n");
                    self.line_pos = 0;
                    i += 2;
                }
                // Printable ASCII (except '=' at 0x3D).
                0x21..=0x3C | 0x3E..=0x7E => {
                    self.push_literal(byte);
                    i += 1;
                }
                // Space / Tab — escape if followed by CRLF or at end of chunk.
                b' ' | b'\t' => {
                    let followed_by_crlf = i + 2 < total
                        && raw[i + 1] == b'\r'
                        && raw[i + 2] == b'\n';
                    let at_end = i + 1 >= total;

                    if followed_by_crlf || at_end {
                        self.push_encoded(byte);
                    } else {
                        self.push_literal(byte);
                    }
                    i += 1;
                }
                // Everything else must be encoded.
                _ => {
                    self.push_encoded(byte);
                    i += 1;
                }
            }
        }
        Ok(())
    }
}

impl Read for QPEncodingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.out_pos < self.out_buf.len() {
                let avail = self.out_buf.len() - self.out_pos;
                let n = buf.len().min(avail);
                buf[..n].copy_from_slice(&self.out_buf[self.out_pos..self.out_pos + n]);
                self.out_pos += n;
                return Ok(n);
            }

            if self.finished {
                return Ok(0);
            }

            self.fill_buffer()?;

            if self.out_buf.is_empty() && self.finished {
                return Ok(0);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (compile-time only — exercised by the ad-hoc test file)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_format() {
        let b = generate_boundary();
        assert_eq!(b.len(), MIME_BOUNDARY_DASHES + MIME_RAND_BOUNDARY_CHARS);
        assert!(b.starts_with("------------------------"));
        assert!(b[MIME_BOUNDARY_DASHES..].chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn mime_contenttype_detection() {
        assert_eq!(mime_contenttype("photo.jpg"), Some("image/jpeg"));
        assert_eq!(mime_contenttype("PHOTO.JPG"), Some("image/jpeg"));
        assert_eq!(mime_contenttype("index.html"), Some("text/html"));
        assert_eq!(mime_contenttype("archive.tar.gz"), None);
        assert_eq!(mime_contenttype("doc.pdf"), Some("application/pdf"));
    }

    #[test]
    fn basic_multipart_encode() {
        let mut mime = Mime::new();
        {
            let part = mime.add_part();
            part.set_name("field1");
            part.set_data_string("value1");
        }
        mime.prepare_headers().unwrap();

        let mut reader = mime.encode().unwrap();
        let mut body = String::new();
        reader.read_to_string(&mut body).unwrap();

        // Verify structure.
        assert!(body.starts_with("--"));
        assert!(body.contains("Content-Disposition: form-data; name=\"field1\""));
        assert!(body.contains("value1"));
        assert!(body.contains("--\r\n")); // closing boundary
    }

    #[test]
    fn content_length_matches_encoded() {
        let mut mime = Mime::new();
        {
            let part = mime.add_part();
            part.set_name("f");
            part.set_data_string("hello");
        }
        mime.prepare_headers().unwrap();

        let expected_len = mime.content_length();
        let mut reader = mime.encode().unwrap();
        let mut body = Vec::new();
        reader.read_to_end(&mut body).unwrap();

        assert_eq!(expected_len, Some(body.len() as u64));
    }

    #[test]
    fn duplicate_roundtrip() {
        let mut mime = Mime::new();
        {
            let p = mime.add_part();
            p.set_name("x");
            p.set_data(b"bytes");
        }
        mime.prepare_headers().unwrap();

        let dup = mime.duplicate().unwrap();
        assert_eq!(dup.parts.len(), 1);
    }

    #[test]
    fn encoder_display() {
        assert_eq!(MimeEncoder::Base64.to_string(), "base64");
        assert_eq!(MimeEncoder::QuotedPrintable.to_string(), "quoted-printable");
        assert_eq!(MimeEncoder::Binary.to_string(), "binary");
        assert_eq!(MimeEncoder::SevenBit.to_string(), "7bit");
        assert_eq!(MimeEncoder::EightBit.to_string(), "8bit");
    }

    #[test]
    fn encoder_from_name() {
        assert_eq!(MimeEncoder::from_name("BASE64"), Some(MimeEncoder::Base64));
        assert_eq!(MimeEncoder::from_name("8BIT"), Some(MimeEncoder::EightBit));
        assert_eq!(MimeEncoder::from_name("unknown"), None);
    }

    #[test]
    fn escape_form_strategy() {
        assert_eq!(escape_string("a\"b", MimeStrategy::Form), "a%22b");
        assert_eq!(escape_string("a\rb", MimeStrategy::Form), "a%0Db");
        assert_eq!(escape_string("a\nb", MimeStrategy::Form), "a%0Ab");
    }

    #[test]
    fn escape_mail_strategy() {
        assert_eq!(escape_string("a\"b", MimeStrategy::Mail), "a\\\"b");
        assert_eq!(escape_string("a\\b", MimeStrategy::Mail), "a\\\\b");
    }

    #[test]
    fn base64_encoding_reader() {
        let data = b"Hello, World!";
        let reader = Base64EncodingReader::new(Box::new(Cursor::new(data.to_vec())));
        let mut output = String::new();
        { let mut r = reader; r.read_to_string(&mut output).unwrap(); }
        // Standard Base64 of "Hello, World!" is "SGVsbG8sIFdvcmxkIQ=="
        assert_eq!(output.trim(), "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn qp_encoding_reader() {
        let data = b"Hello World\r\n";
        let reader = QPEncodingReader::new(Box::new(Cursor::new(data.to_vec())));
        let mut output = Vec::new();
        { let mut r = reader; r.read_to_end(&mut output).unwrap(); }
        assert_eq!(&output, b"Hello World\r\n");
    }

    #[test]
    fn qp_encoding_special_chars() {
        let data = b"A=B";
        let reader = QPEncodingReader::new(Box::new(Cursor::new(data.to_vec())));
        let mut output = String::new();
        { let mut r = reader; r.read_to_string(&mut output).unwrap(); }
        assert_eq!(output, "A=3DB");
    }

    #[test]
    fn content_type_header() {
        let mime = Mime::new();
        let ct = mime.content_type();
        assert!(ct.starts_with("multipart/form-data; boundary="));
        assert!(ct.contains(&mime.boundary));
    }

    #[test]
    fn empty_mime_length() {
        let mime = Mime::new();
        assert_eq!(mime.content_length(), Some(0));
    }

    #[test]
    fn multipart_two_parts() {
        let mut mime = Mime::new();
        {
            let p = mime.add_part();
            p.set_name("a");
            p.set_data_string("1");
        }
        {
            let p = mime.add_part();
            p.set_name("b");
            p.set_data_string("2");
        }
        mime.prepare_headers().unwrap();

        let mut reader = mime.encode().unwrap();
        let mut body = String::new();
        reader.read_to_string(&mut body).unwrap();

        // Should contain two boundaries and a closing boundary.
        let boundary = mime.boundary();
        let boundary_count = body.matches(boundary).count();
        assert_eq!(boundary_count, 3); // 2 parts + 1 closing

        assert!(body.contains("name=\"a\""));
        assert!(body.contains("name=\"b\""));
        assert!(body.contains("1"));
        assert!(body.contains("2"));
    }
}
