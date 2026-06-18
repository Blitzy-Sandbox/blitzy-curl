//! MIME multipart bodies and the legacy form API for `curl-rs-lib`.
//!
//! This module is the memory-safe Rust reimplementation of libcurl's MIME
//! subsystem (`lib/mime.c`) **and** the deprecated form API (`lib/formdata.c`).
//! Together they build `multipart/form-data` (and related `multipart/mixed`)
//! request bodies for HTTP `POST` and for mail (SMTP/IMAP), reproducing curl's
//! byte-for-byte wire output wherever that output is deterministic.
//!
//! # What lives here
//!
//! * The modern MIME builder — [`Mime`] (a multipart) and [`MimePart`] (one
//!   part), mirroring `curl_mime_init` / `curl_mime_addpart` and the
//!   `curl_mime_name` / `data` / `filedata` / `type` / `encoder` / `headers` /
//!   `subparts` / `data_cb` setters. Ownership is expressed with Rust's type
//!   system; the part tree is freed deterministically by `Drop` (the analog of
//!   `curl_mime_free`).
//! * The transfer encoders curl supports — [`MimeEncoding`]: `binary`, `8bit`,
//!   `7bit`, `base64` and `quoted-printable`, each reproducing curl's exact
//!   output including base64/QP line wrapping at 76 columns.
//! * Body serialization — [`MimeReader`], a streaming [`std::io::Read`] source
//!   that emits the same header formatting, CRLF handling and boundary
//!   delimiters as curl, streaming large unencoded file parts without buffering
//!   them whole.
//! * The legacy form API — [`HttpPost`] (the `curl_httppost` linked structure),
//!   [`FormSection`] / [`FormData::add`] (the typed analog of the variadic
//!   `curl_formadd`), [`form_get`] (`curl_formget`) and the form → MIME
//!   conversion ([`httppost_to_mime`], the analog of `Curl_getformdata`).
//!   `curl_formfree` is replaced by `Drop`.
//!
//! # ABI and wire parity
//!
//! The serialized bytes produced here are observable on the wire and checked by
//! curl's regression suite (form posts), so the part-header formatting, the
//! transfer encoders and the boundary scheme reproduce curl 8.x exactly. The
//! boundary is 24 `-` characters followed by 22 random alphanumerics (via
//! [`crate::util::rand::rand_alnum`]); only that random tail differs run to run,
//! exactly as in curl, so tests that tolerate the random portion still parse.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` and compiles under the crate-root
//! `#![forbid(unsafe_code)]`. The raw-pointer marshaling that turns a [`Mime`],
//! [`MimePart`] or [`HttpPost`] into the opaque C handles `curl_mime*`,
//! `curl_mimepart*` and `curl_httppost*` lives entirely in `curl-rs-ffi`; here
//! everything is owned Rust data with deterministic destructors.

use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

use crate::error::{CurlError, Result};
use crate::slist::SList;
use crate::util::base64::base64_encode;
use crate::util::rand::rand_alnum;

// =============================================================================
// Constants (mirrors lib/mime.h)
// =============================================================================

/// Number of leading `-` characters in a generated boundary
/// (`MIME_BOUNDARY_DASHES`).
const MIME_BOUNDARY_DASHES: usize = 24;

/// Number of random alphanumeric characters appended to a boundary
/// (`MIME_RAND_BOUNDARY_CHARS`).
const MIME_RAND_BOUNDARY_CHARS: usize = 22;

/// Total stored boundary length: dashes + random tail (`MIME_BOUNDARY_LEN`).
const MIME_BOUNDARY_LEN: usize = MIME_BOUNDARY_DASHES + MIME_RAND_BOUNDARY_CHARS;

/// Maximum encoded line length used by the base64 and quoted-printable encoders
/// (`MAX_ENCODED_LINE_LENGTH`).
const MAX_ENCODED_LINE_LENGTH: usize = 76;

/// Default content type used for a file part whose type cannot be guessed
/// (`FILE_CONTENTTYPE_DEFAULT`).
const FILE_CONTENTTYPE_DEFAULT: &str = "application/octet-stream";

/// Default content type for a multipart that has no explicit type
/// (`MULTIPART_CONTENTTYPE_DEFAULT`).
const MULTIPART_CONTENTTYPE_DEFAULT: &str = "multipart/mixed";

/// Default `Content-Disposition` value (`DISPOSITION_DEFAULT`).
const DISPOSITION_DEFAULT: &str = "attachment";

/// Part flag: the part owns its user headers and must free them
/// (`MIME_USERHEADERS_OWNER`).
const MIME_USERHEADERS_OWNER: u32 = 1 << 0;

/// Part flag: emit only the body, never the part headers (`MIME_BODY_ONLY`).
/// Set on the synthetic top-level part of an HTTP form post so its
/// `Content-Type` header goes into the request rather than the body.
const MIME_BODY_ONLY: u32 = 1 << 1;

// ---- legacy form (curl_httppost) flags (include/curl/curl.h) ---------------

/// `CURL_HTTPPOST_FILENAME` — the contents field is a filename to upload.
pub const CURL_HTTPPOST_FILENAME: u32 = 1 << 0;
/// `CURL_HTTPPOST_READFILE` — read the file named by the contents field.
pub const CURL_HTTPPOST_READFILE: u32 = 1 << 1;
/// `CURL_HTTPPOST_PTRNAME` — the name is a borrowed pointer (not copied).
pub const CURL_HTTPPOST_PTRNAME: u32 = 1 << 2;
/// `CURL_HTTPPOST_PTRCONTENTS` — the contents are a borrowed pointer.
pub const CURL_HTTPPOST_PTRCONTENTS: u32 = 1 << 3;
/// `CURL_HTTPPOST_BUFFER` — upload the part from an in-memory buffer.
pub const CURL_HTTPPOST_BUFFER: u32 = 1 << 4;
/// `CURL_HTTPPOST_PTRBUFFER` — the buffer is a borrowed pointer.
pub const CURL_HTTPPOST_PTRBUFFER: u32 = 1 << 5;
/// `CURL_HTTPPOST_CALLBACK` — read the part contents via the read callback.
pub const CURL_HTTPPOST_CALLBACK: u32 = 1 << 6;
/// `CURL_HTTPPOST_LARGE` — the `contentlen` field carries the content length.
pub const CURL_HTTPPOST_LARGE: u32 = 1 << 7;

/// Sentinel passed to [`MimePart::set_data`] (and friends) meaning "the data is
/// NUL-terminated, measure its length" — the analog of curl's
/// `CURL_ZERO_TERMINATED` (`(size_t)-1`).
pub const CURL_ZERO_TERMINATED: usize = usize::MAX;

// =============================================================================
// Small ASCII helpers (curl assumes ASCII-compatible input on the wire)
// =============================================================================

/// Uppercase hexadecimal digits, matching curl's `aschex` table used by the
/// quoted-printable encoder so escape sequences such as `=0D` use uppercase.
const ASCHEX: &[u8; 16] = b"0123456789ABCDEF";

/// Case-insensitive ASCII byte equality (the behavior of curl's `curl_strequal`
/// for a single byte): folds only `A..=Z` / `a..=z`.
#[inline]
fn ascii_eq_ignore_case(a: u8, b: u8) -> bool {
    a.eq_ignore_ascii_case(&b)
}

/// Case-insensitive ASCII prefix test — true when `hay` begins with `needle`
/// ignoring ASCII case. Mirrors `curl_strnequal(hay, needle, needle.len())`.
fn starts_with_ignore_case(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len()
        && hay[..needle.len()]
            .iter()
            .zip(needle)
            .all(|(&x, &y)| ascii_eq_ignore_case(x, y))
}

/// If `entry` (a raw `Name: value` header line) matches header `name`
/// case-insensitively and is immediately followed by `:`, return the value with
/// leading spaces stripped. Mirrors `match_header()` in `lib/mime.c`.
fn match_header<'a>(entry: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let nb = name.as_bytes();
    if entry.len() > nb.len()
        && entry[nb.len()] == b':'
        && entry[..nb.len()]
            .iter()
            .zip(nb)
            .all(|(&x, &y)| ascii_eq_ignore_case(x, y))
    {
        let mut v = nb.len() + 1;
        // curl skips ONLY spaces (not tabs) after the colon.
        while v < entry.len() && entry[v] == b' ' {
            v += 1;
        }
        Some(&entry[v..])
    } else {
        None
    }
}

/// Search a user-header [`SList`] for the first entry matching `name`, returning
/// its value bytes. Mirrors `search_header()` in `lib/mime.c`.
fn search_header<'a>(list: Option<&'a SList>, name: &str) -> Option<&'a [u8]> {
    let list = list?;
    for entry in list.iter() {
        if let Some(v) = match_header(entry.to_bytes(), name) {
            return Some(v);
        }
    }
    None
}

/// Does `ct` name content type `target`? True when `ct` begins with `target`
/// (case-insensitive) and the following byte terminates the token (end of
/// string, whitespace, CR/LF or `;`). Mirrors `content_type_match()`.
fn content_type_match(ct: &[u8], target: &str) -> bool {
    let tb = target.as_bytes();
    if !starts_with_ignore_case(ct, tb) {
        return false;
    }
    match ct.get(tb.len()) {
        None => true, // end of string == C's '\0'
        Some(&c) => matches!(c, b'\t' | b'\r' | b'\n' | b' ' | b';'),
    }
}

/// Guess a content type from a filename's extension, reproducing curl's
/// `Curl_mime_contenttype()` table. Returns `None` when nothing matches.
fn guess_content_type(filename: Option<&[u8]>) -> Option<&'static str> {
    // (extension, type) pairs in curl's exact order.
    const TABLE: &[(&str, &str)] = &[
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
    let name = filename?;
    for (ext, ty) in TABLE {
        let eb = ext.as_bytes();
        if name.len() >= eb.len()
            && name[name.len() - eb.len()..]
                .iter()
                .zip(eb)
                .all(|(&x, &y)| ascii_eq_ignore_case(x, y))
        {
            return Some(ty);
        }
    }
    None
}

/// Strip any directory components from a path, returning the trailing base name
/// as owned bytes. Mirrors `strippath()` / `curlx_basename()` in `lib/mime.c`:
/// the base name is the substring after the last `/` or `\\`.
fn strip_path(full: &[u8]) -> Vec<u8> {
    let mut start = 0;
    for (i, &b) in full.iter().enumerate() {
        if b == b'/' || b == b'\\' {
            start = i + 1;
        }
    }
    full[start..].to_vec()
}

/// Escape a header parameter value (a part name or filename) for inclusion in a
/// quoted `Content-Disposition` parameter, reproducing curl's `escape_string()`.
///
/// * `backslash == false` (the default HTTP form path): apply the WHATWG HTML
///   form escaping — `"` → `%22`, CR → `%0D`, LF → `%0A`.
/// * `backslash == true` (mail, or HTTP forms with `CURLMIMEOPT_FORMESCAPE`):
///   apply backslash escaping — `\` → `\\`, `"` → `\"`.
fn escape_string(src: &[u8], backslash: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len());
    for &c in src {
        if backslash {
            match c {
                b'\\' => out.extend_from_slice(b"\\\\"),
                b'"' => out.extend_from_slice(b"\\\""),
                _ => out.push(c),
            }
        } else {
            match c {
                b'"' => out.extend_from_slice(b"%22"),
                b'\r' => out.extend_from_slice(b"%0D"),
                b'\n' => out.extend_from_slice(b"%0A"),
                _ => out.push(c),
            }
        }
    }
    out
}

// =============================================================================
// Transfer encoders (mirrors the encoders in lib/mime.c)
// =============================================================================

// Quoted-printable character classes (`qp_class` in lib/mime.c).
const QP_OK: u8 = 1; // representable as itself
const QP_SP: u8 = 2; // space or tab
const QP_CR: u8 = 3; // carriage return
const QP_LF: u8 = 4; // line feed

/// Build curl's quoted-printable classification table at compile time.
///
/// Printable ASCII `0x21..=0x7E` are [`QP_OK`] except `=` (`0x3D`), which must be
/// escaped; space (`0x20`) and tab (`0x09`) are [`QP_SP`]; LF is [`QP_LF`]; CR is
/// [`QP_CR`]; everything else (control bytes, DEL, and all `0x80..=0xFF`) is `0`,
/// meaning "must be escaped".
const fn build_qp_class() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0x21usize;
    while i <= 0x7e {
        t[i] = QP_OK;
        i += 1;
    }
    t[0x3d] = 0; // '=' must always be escaped
    t[0x20] = QP_SP; // space
    t[0x09] = QP_SP; // tab
    t[0x0a] = QP_LF; // LF
    t[0x0d] = QP_CR; // CR
    t
}

/// The quoted-printable classification table.
static QP_CLASS: [u8; 256] = build_qp_class();

/// Does the byte at `n` begin a `CRLF` pair, or is `n` at/after end of data?
///
/// Whole-buffer analog of curl's `qp_lookahead_eol()` with `ateof` always true
/// (we hold all the data): returns `true` for end-of-data or an explicit CRLF,
/// `false` otherwise.
fn qp_at_eol(data: &[u8], n: usize) -> bool {
    if n >= data.len() {
        return true; // end of data
    }
    if n + 2 > data.len() {
        return false; // only one byte left: cannot be CRLF
    }
    data[n] == 0x0d && data[n + 1] == 0x0a
}

/// Content transfer encoding, one of the five encoders curl supports.
///
/// The variant set and names match curl's `encoders[]` table exactly, which is
/// what `curl_mime_encoder()` accepts and what is reported in the
/// `Content-Transfer-Encoding` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MimeEncoding {
    /// `binary` — pass the data through unchanged.
    Binary,
    /// `8bit` — pass the data through unchanged (8-bit clean).
    EightBit,
    /// `7bit` — pass through, but fail if any byte has the high bit set.
    SevenBit,
    /// `base64` — RFC 2045 base64 with 76-column line wrapping.
    Base64,
    /// `quoted-printable` — RFC 2045 quoted-printable with soft line breaks.
    QuotedPrintable,
}

impl MimeEncoding {
    /// The wire name of this encoding, as it appears in
    /// `Content-Transfer-Encoding` and as accepted by `curl_mime_encoder()`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            MimeEncoding::Binary => "binary",
            MimeEncoding::EightBit => "8bit",
            MimeEncoding::SevenBit => "7bit",
            MimeEncoding::Base64 => "base64",
            MimeEncoding::QuotedPrintable => "quoted-printable",
        }
    }

    /// Look up an encoding by its wire name, case-insensitively (curl uses
    /// `curl_strequal`). Returns `None` for an unknown name, which the caller
    /// maps to `CURLE_BAD_FUNCTION_ARGUMENT`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<MimeEncoding> {
        let nb = name.as_bytes();
        for enc in [
            MimeEncoding::Binary,
            MimeEncoding::EightBit,
            MimeEncoding::SevenBit,
            MimeEncoding::Base64,
            MimeEncoding::QuotedPrintable,
        ] {
            let cand = enc.name().as_bytes();
            if cand.len() == nb.len()
                && cand
                    .iter()
                    .zip(nb)
                    .all(|(&x, &y)| ascii_eq_ignore_case(x, y))
            {
                return Some(enc);
            }
        }
        None
    }

    /// Encode `data` with this encoding, producing the exact bytes curl emits.
    ///
    /// `binary` / `8bit` are identity transforms; `7bit` is identity but returns
    /// [`CurlError::ReadError`] (curl's `READ_ERROR`) if any byte has the high
    /// bit set; `base64` and `quoted-printable` reproduce curl's 76-column line
    /// wrapping.
    pub fn encode(self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            MimeEncoding::Binary | MimeEncoding::EightBit => Ok(data.to_vec()),
            MimeEncoding::SevenBit => {
                if data.iter().any(|&b| b & 0x80 != 0) {
                    Err(CurlError::ReadError)
                } else {
                    Ok(data.to_vec())
                }
            }
            MimeEncoding::Base64 => encode_base64(data),
            MimeEncoding::QuotedPrintable => Ok(encode_quoted_printable(data)),
        }
    }

    /// Compute the encoded size for a part whose decoded size is `datasize`
    /// (`-1` meaning unknown), mirroring curl's per-encoder `sizefunc`.
    ///
    /// `binary` / `8bit` / `7bit` preserve the size; `base64` expands it and
    /// accounts for CRLFs; `quoted-printable` is only known to be `0` for empty
    /// input and otherwise `-1` (must be computed by encoding).
    #[must_use]
    pub fn encoded_size(self, datasize: i64) -> i64 {
        match self {
            MimeEncoding::Binary | MimeEncoding::EightBit | MimeEncoding::SevenBit => datasize,
            MimeEncoding::Base64 => {
                if datasize <= 0 {
                    return datasize;
                }
                // Base64 character count (curl: 4 * (1 + (size - 1) / 3)).
                let chars = 4 * (1 + (datasize - 1) / 3);
                // Add the CRLFs inserted at every MAX_ENCODED_LINE_LENGTH.
                chars + 2 * ((chars - 1) / MAX_ENCODED_LINE_LENGTH as i64)
            }
            MimeEncoding::QuotedPrintable => {
                if datasize == 0 {
                    0
                } else {
                    -1
                }
            }
        }
    }
}

/// Encode `data` as base64 with curl's 76-column line wrapping.
///
/// Produces standard RFC 4648 base64 (with `=` padding) and inserts a `CRLF`
/// after every [`MAX_ENCODED_LINE_LENGTH`] characters, with **no** trailing
/// `CRLF` — identical to the stream curl's `encoder_base64_read()` emits, since
/// the line length is a multiple of the 4-character base64 group.
fn encode_base64(data: &[u8]) -> Result<Vec<u8>> {
    let b64 = base64_encode(data)?;
    if b64.is_empty() {
        return Ok(b64);
    }
    // Reserve room for the data plus one CRLF per full line.
    let mut out = Vec::with_capacity(b64.len() + 2 * (b64.len() / MAX_ENCODED_LINE_LENGTH));
    let mut col = 0usize;
    for &b in &b64 {
        if col == MAX_ENCODED_LINE_LENGTH {
            out.push(b'\r');
            out.push(b'\n');
            col = 0;
        }
        out.push(b);
        col += 1;
    }
    Ok(out)
}

/// Encode `data` as quoted-printable, reproducing curl's `encoder_qp_read()`.
///
/// Printable characters pass through; `=` and control bytes become `=XX`
/// (uppercase hex); a space or tab is escaped only when it ends a line; a
/// `CRLF` pair is emitted literally as a hard line break (resetting the column),
/// while a lone CR or LF is escaped. Soft line breaks (`=\r\n`) are inserted so
/// no encoded line exceeds [`MAX_ENCODED_LINE_LENGTH`] columns; on a soft break
/// the pending character is re-emitted on the fresh line.
fn encode_quoted_printable(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut pos = 0usize; // current output column
    let mut i = 0usize;
    while i < data.len() {
        let c = data[i];
        // Default token is the escaped form `=XX`; specific classes override it.
        let mut token = [
            b'=',
            ASCHEX[((c >> 4) & 0xF) as usize],
            ASCHEX[(c & 0xF) as usize],
        ];
        let len: usize;
        let mut consumed = 1usize;

        match QP_CLASS[c as usize] {
            QP_OK => {
                token[0] = c;
                len = 1;
            }
            QP_SP => {
                // Space/tab: escape only if it ends a line (CRLF or EOF next).
                if qp_at_eol(data, i + 1) {
                    len = 3; // "=XX"
                } else {
                    token[0] = c;
                    len = 1;
                }
            }
            QP_CR => {
                if i + 1 < data.len() && data[i + 1] == 0x0a {
                    // Hard line break: emit CRLF literally.
                    token[0] = 0x0d;
                    token[1] = 0x0a;
                    len = 2;
                    consumed = 2;
                } else {
                    len = 3; // escape lone CR as "=0D"
                }
            }
            // QP_LF and class 0 (everything else): escape as "=XX".
            _ => {
                len = 3;
            }
        }

        // Soft line-break handling — skipped for a hard CRLF token (ends in LF).
        if token[len - 1] != 0x0a {
            let mut softbreak = pos + len > MAX_ENCODED_LINE_LENGTH;
            if !softbreak && pos + len == MAX_ENCODED_LINE_LENGTH {
                // A line may reach exactly the max only at end-of-data or before
                // a following CRLF; otherwise insert a soft break.
                if !qp_at_eol(data, i + consumed) {
                    softbreak = true;
                }
            }
            if softbreak {
                out.extend_from_slice(b"=\r\n");
                pos = 0;
                // Do not consume the current byte; re-emit it on the new line.
                continue;
            }
        }

        out.extend_from_slice(&token[..len]);
        pos += len;
        if token[len - 1] == 0x0a {
            pos = 0;
        }
        i += consumed;
    }
    out
}

// =============================================================================
// Part data sources and the streaming reader trait
// =============================================================================

/// Which serialization conventions to apply, mirroring curl's `mimestrategy`.
///
/// The strategy affects parameter escaping and a couple of header defaults:
/// HTTP forms percent-escape disposition parameters and never inject a default
/// transfer encoding, whereas mail uses backslash escaping and defaults a typed,
/// non-multipart part to `Content-Transfer-Encoding: 8bit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeStrategy {
    /// HTTP `multipart/form-data` (the `curl_mime` attached via `CURLOPT_MIMEPOST`
    /// or built from the legacy form API).
    Form,
    /// Mail bodies for SMTP/IMAP.
    Mail,
}

/// A pull-based, streaming source of part content.
///
/// This is the Rust analog of curl's `curl_read_callback` + `curl_seek_callback`
/// pair used by `curl_mime_data_cb`. Implementors yield bytes on demand so the
/// transfer engine can stream a large part without materializing it in memory.
///
/// [`read`](MimeDataReader::read) follows the [`std::io::Read`] contract; a
/// return of `Ok(0)` signals end of data. [`rewind`](MimeDataReader::rewind)
/// corresponds to seeking back to offset 0 for retransmission (for example after
/// an HTTP redirect or auth retry) and defaults to "unsupported".
pub trait MimeDataReader: Send {
    /// Read up to `buf.len()` bytes into `buf`, returning the number read. A
    /// return of `Ok(0)` means end of data.
    ///
    /// # Errors
    ///
    /// Returns any I/O error encountered while producing the content; the
    /// transfer engine maps this onto `CURLE_READ_ERROR`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Seek back to the beginning so the content can be re-read.
    ///
    /// The default implementation reports the source as non-rewindable, which
    /// the engine treats like curl's `CURL_SEEKFUNC_CANTSEEK`.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Unsupported`] when the source cannot rewind.
    fn rewind(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "mime data source cannot rewind",
        ))
    }
}

/// The content source backing a [`MimePart`], the Rust analog of curl's
/// `mimekind` discriminator together with the part's `data`/`arg` union.
enum PartData {
    /// No content has been set yet (`MIMEKIND_NONE`).
    None,
    /// In-memory bytes, copied into the part (`MIMEKIND_DATA`).
    Bytes(Vec<u8>),
    /// A filesystem path to stream from (`MIMEKIND_FILE`).
    File(PathBuf),
    /// A user-supplied streaming reader (`MIMEKIND_CALLBACK`).
    Callback(Box<dyn MimeDataReader>),
    /// Nested multipart content (`MIMEKIND_MULTIPART`).
    Multipart(Box<Mime>),
}

// =============================================================================
// MimePart — a single MIME part (mirrors `struct curl_mimepart`)
// =============================================================================

/// A single MIME part: its content source plus the metadata that determines the
/// part headers curl emits (`Content-Disposition`, `Content-Type`,
/// `Content-Transfer-Encoding`).
///
/// Build a part by calling [`Mime::addpart`] and then the setters below, which
/// mirror `curl_mime_name`, `curl_mime_data`, `curl_mime_filedata`,
/// `curl_mime_type`, `curl_mime_encoder`, `curl_mime_headers`,
/// `curl_mime_filename`, `curl_mime_data_cb` and `curl_mime_subparts`. The part
/// and any nested [`Mime`] are freed deterministically by `Drop`.
pub struct MimePart {
    /// The content source (`kind` + `data`/`arg` in curl).
    data: PartData,
    /// The part name for `Content-Disposition` (`curl_mime_name`).
    name: Option<Vec<u8>>,
    /// The filename for `Content-Disposition` (`curl_mime_filename`, or the
    /// basename derived by `curl_mime_filedata`).
    filename: Option<Vec<u8>>,
    /// An explicit content type (`curl_mime_type`); overrides any guess.
    mimetype: Option<Vec<u8>>,
    /// Caller-supplied custom headers (`curl_mime_headers`).
    userheaders: Option<SList>,
    /// The selected transfer encoder (`curl_mime_encoder`), if any.
    encoder: Option<MimeEncoding>,
    /// Headers generated during [`prepare_headers`](MimePart::prepare_headers).
    curlheaders: Vec<Vec<u8>>,
    /// Bit set of `MIME_*` flags (`MIME_USERHEADERS_OWNER`, `MIME_BODY_ONLY`).
    flags: u32,
    /// Decoded content size, or `-1` when unknown (`datasize`).
    datasize: i64,
}

impl Default for MimePart {
    fn default() -> Self {
        MimePart {
            data: PartData::None,
            name: None,
            filename: None,
            mimetype: None,
            userheaders: None,
            encoder: None,
            curlheaders: Vec::new(),
            flags: 0,
            datasize: 0,
        }
    }
}

impl MimePart {
    /// Create an empty part with no content (the state right after
    /// `curl_mime_addpart`, before any setter is called).
    #[must_use]
    pub fn new() -> MimePart {
        MimePart::default()
    }

    /// Drop any previously configured content source, mirroring curl's
    /// `cleanup_part_content` so that re-setting a part's data replaces it.
    fn cleanup_content(&mut self) {
        self.data = PartData::None;
        self.datasize = 0;
    }

    /// Set (or, with `None`, clear) the part name used in `Content-Disposition`.
    /// Mirrors `curl_mime_name`.
    ///
    /// # Errors
    ///
    /// Never fails; returns `Ok` for symmetry with the fallible setters so calls
    /// can be chained with `?`.
    pub fn set_name(&mut self, name: Option<&[u8]>) -> Result<&mut MimePart> {
        self.name = name.map(<[u8]>::to_vec);
        Ok(self)
    }

    /// Set (or, with `None`, clear) the filename used in `Content-Disposition`.
    /// Mirrors `curl_mime_filename`.
    ///
    /// # Errors
    ///
    /// Never fails; returns `Ok` for chaining symmetry.
    pub fn set_filename(&mut self, filename: Option<&[u8]>) -> Result<&mut MimePart> {
        self.filename = filename.map(<[u8]>::to_vec);
        Ok(self)
    }

    /// Set (or, with `None`, clear) the explicit content type. Mirrors
    /// `curl_mime_type`.
    ///
    /// # Errors
    ///
    /// Never fails; returns `Ok` for chaining symmetry.
    pub fn set_type(&mut self, mimetype: Option<&[u8]>) -> Result<&mut MimePart> {
        self.mimetype = mimetype.map(<[u8]>::to_vec);
        Ok(self)
    }

    /// Select a transfer encoder by name (`binary`, `8bit`, `7bit`, `base64`,
    /// `quoted-printable`), or clear it with `None`. Mirrors `curl_mime_encoder`.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if `encoding` is not one of the
    /// supported encoder names, exactly as curl returns
    /// `CURLE_BAD_FUNCTION_ARGUMENT`.
    pub fn set_encoder(&mut self, encoding: Option<&str>) -> Result<&mut MimePart> {
        match encoding {
            None => {
                self.encoder = None;
                Ok(self)
            }
            Some(name) => match MimeEncoding::from_name(name) {
                Some(enc) => {
                    self.encoder = Some(enc);
                    Ok(self)
                }
                None => Err(CurlError::BadFunctionArgument),
            },
        }
    }

    /// Select a transfer encoder using the typed [`MimeEncoding`] directly — a
    /// convenience over [`set_encoder`](MimePart::set_encoder) for Rust callers.
    ///
    /// # Errors
    ///
    /// Never fails; returns `Ok` for chaining symmetry.
    pub fn set_encoding(&mut self, encoding: MimeEncoding) -> Result<&mut MimePart> {
        self.encoder = Some(encoding);
        Ok(self)
    }

    /// Attach (or, with `None`, clear) caller-supplied custom headers. Mirrors
    /// `curl_mime_headers`; `take_ownership` records whether the FFI layer should
    /// free the original C list (it has no effect on the owned Rust copy).
    ///
    /// # Errors
    ///
    /// Never fails; returns `Ok` for chaining symmetry.
    pub fn set_headers(
        &mut self,
        headers: Option<SList>,
        take_ownership: bool,
    ) -> Result<&mut MimePart> {
        self.userheaders = headers;
        if self.userheaders.is_some() && take_ownership {
            self.flags |= MIME_USERHEADERS_OWNER;
        } else {
            self.flags &= !MIME_USERHEADERS_OWNER;
        }
        Ok(self)
    }

    /// Set the part content to a copy of `data` (`MIMEKIND_DATA`). Mirrors
    /// `curl_mime_data`. An empty slice is a valid zero-length part.
    ///
    /// # Errors
    ///
    /// Never fails; returns `Ok` for chaining symmetry.
    pub fn set_data(&mut self, data: &[u8]) -> Result<&mut MimePart> {
        self.cleanup_content();
        self.datasize = data.len() as i64;
        self.data = PartData::Bytes(data.to_vec());
        Ok(self)
    }

    /// Set the part content by taking ownership of `data` without an extra copy —
    /// a Rust convenience equivalent in effect to [`set_data`](MimePart::set_data).
    ///
    /// # Errors
    ///
    /// Never fails; returns `Ok` for chaining symmetry.
    pub fn set_data_bytes(&mut self, data: Vec<u8>) -> Result<&mut MimePart> {
        self.cleanup_content();
        self.datasize = data.len() as i64;
        self.data = PartData::Bytes(data);
        Ok(self)
    }

    /// Stream the part content from the file at `path` (`MIMEKIND_FILE`), and, if
    /// no filename has been set yet, default the `Content-Disposition` filename to
    /// the path's basename. Mirrors `curl_mime_filedata`.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::ReadError`] (curl's `CURLE_READ_ERROR`) if the file
    /// cannot be stat'd; the path is still recorded so the caller can decide how
    /// to proceed, exactly as curl does.
    pub fn set_filedata(&mut self, path: &str) -> Result<&mut MimePart> {
        self.cleanup_content();
        // Default the disposition filename to the basename if unset.
        if self.filename.is_none() {
            let base = strip_path(path.as_bytes());
            if !base.is_empty() {
                self.filename = Some(base);
            }
        }
        let stat = std::fs::metadata(path);
        self.data = PartData::File(PathBuf::from(path));
        match stat {
            Ok(meta) if meta.is_file() => {
                self.datasize = meta.len() as i64;
                Ok(self)
            }
            _ => {
                // Unknown size; curl returns READ_ERROR but keeps the path.
                self.datasize = -1;
                Err(CurlError::ReadError)
            }
        }
    }

    /// Stream the part content from a user-supplied [`MimeDataReader`]
    /// (`MIMEKIND_CALLBACK`), declaring its size as `datasize` (`-1` if unknown).
    /// Mirrors `curl_mime_data_cb`.
    ///
    /// # Errors
    ///
    /// Never fails; returns `Ok` for chaining symmetry.
    pub fn set_data_cb(
        &mut self,
        datasize: i64,
        reader: Box<dyn MimeDataReader>,
    ) -> Result<&mut MimePart> {
        self.cleanup_content();
        self.datasize = datasize;
        self.data = PartData::Callback(reader);
        Ok(self)
    }

    /// Set (or, with `None`, clear) nested multipart content (`MIMEKIND_MULTIPART`).
    /// Mirrors `curl_mime_subparts`. Ownership transfer makes curl's "subparts
    /// cannot belong to several parts" and cycle checks unnecessary: a [`Mime`]
    /// is moved in, so it can be owned by at most one part and cannot contain
    /// itself.
    ///
    /// # Errors
    ///
    /// Never fails; returns `Ok` for chaining symmetry.
    pub fn set_subparts(&mut self, subparts: Option<Mime>) -> Result<&mut MimePart> {
        self.cleanup_content();
        if let Some(m) = subparts {
            self.data = PartData::Multipart(Box::new(m));
        }
        Ok(self)
    }

    /// True when these user headers are owned by the part (the
    /// `MIME_USERHEADERS_OWNER` flag); consulted by the FFI layer to decide
    /// whether to free the caller's original C list.
    #[must_use]
    pub fn headers_owned(&self) -> bool {
        self.flags & MIME_USERHEADERS_OWNER != 0
    }

    /// Read access to the nested multipart, if this part has subparts.
    #[must_use]
    pub fn subparts(&self) -> Option<&Mime> {
        match &self.data {
            PartData::Multipart(m) => Some(m),
            _ => None,
        }
    }

    /// Mutable access to the nested multipart, if this part has subparts.
    pub fn subparts_mut(&mut self) -> Option<&mut Mime> {
        match &mut self.data {
            PartData::Multipart(m) => Some(m),
            _ => None,
        }
    }
}

// =============================================================================
// Mime — a multipart body (mirrors `struct curl_mime`)
// =============================================================================

/// A MIME multipart body: an ordered list of [`MimePart`]s plus the boundary
/// that separates them. This is the Rust analog of `struct curl_mime` and is
/// created by [`Mime::new`] (`curl_mime_init`).
///
/// Parts are held as `Box<MimePart>` so a part's address is stable even as the
/// list grows — important for the FFI layer, which can hand out a
/// `curl_mimepart *` that remains valid after subsequent `curl_mime_addpart`
/// calls. The whole tree is freed deterministically by `Drop`
/// (`curl_mime_free`).
pub struct Mime {
    /// The 46-byte boundary: [`MIME_BOUNDARY_DASHES`] `-` characters followed by
    /// [`MIME_RAND_BOUNDARY_CHARS`] random alphanumerics. The on-the-wire
    /// delimiter prefixes this with an extra `--`.
    boundary: Vec<u8>,
    // The parts are individually boxed on purpose: the FFI layer hands out a
    // `curl_mimepart *` (the address of a part) that must stay valid across
    // later `curl_mime_addpart` calls. Boxing keeps each part's address stable
    // even when the vector reallocates, so this is not the unnecessary boxing
    // `clippy::vec_box` warns about.
    #[allow(clippy::vec_box)]
    /// The parts, in insertion order.
    parts: Vec<Box<MimePart>>,
}

impl Mime {
    /// Create a new, empty multipart with a freshly generated boundary. Mirrors
    /// `curl_mime_init`.
    ///
    /// # Errors
    ///
    /// Returns an error only if the random number generator backing the boundary
    /// fails (curl returns `NULL` in that case); the FFI layer maps an error to a
    /// `NULL` `curl_mime *`.
    pub fn new() -> Result<Mime> {
        // 24 dashes followed by 22 random alphanumerics (then a NUL we discard).
        let mut boundary = vec![b'-'; MIME_BOUNDARY_LEN];
        let mut tail = [0u8; MIME_RAND_BOUNDARY_CHARS + 1];
        rand_alnum(&mut tail, MIME_RAND_BOUNDARY_CHARS + 1)?;
        boundary[MIME_BOUNDARY_DASHES..].copy_from_slice(&tail[..MIME_RAND_BOUNDARY_CHARS]);
        Ok(Mime {
            boundary,
            parts: Vec::new(),
        })
    }

    /// Construct a multipart with a caller-provided boundary. Intended for
    /// deterministic testing; production code uses [`Mime::new`].
    #[cfg(test)]
    fn with_boundary(boundary: &[u8]) -> Mime {
        Mime {
            boundary: boundary.to_vec(),
            parts: Vec::new(),
        }
    }

    /// Append a new, empty part and return a mutable reference to it for further
    /// configuration. Mirrors `curl_mime_addpart`.
    pub fn addpart(&mut self) -> &mut MimePart {
        self.parts.push(Box::new(MimePart::new()));
        // `&mut Box<MimePart>` coerces to `&mut MimePart` via auto-deref.
        self.parts.last_mut().expect("a part was just pushed")
    }

    /// The 46-byte boundary string (without the leading `--` delimiter prefix),
    /// as used in the `boundary=` parameter of the multipart `Content-Type`.
    #[must_use]
    pub fn boundary_str(&self) -> &[u8] {
        &self.boundary
    }

    /// The number of parts in this multipart.
    #[must_use]
    pub fn len(&self) -> usize {
        self.parts.len()
    }

    /// True when this multipart has no parts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Iterate over the parts in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &MimePart> {
        self.parts.iter().map(AsRef::as_ref)
    }

    /// Iterate mutably over the parts in insertion order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut MimePart> {
        self.parts.iter_mut().map(AsMut::as_mut)
    }

    /// Wrap this multipart in a synthetic top-level [`MimePart`] carrying the
    /// `MIME_BODY_ONLY` flag, exactly as curl's `CURLOPT_MIMEPOST` handling
    /// does. The wrapper's `Content-Type` (with the `boundary=` parameter) is
    /// generated into its [`MimePart::curl_headers`] so the HTTP/mail layer can
    /// lift it into the request headers, while serialization of the wrapper
    /// emits only the multipart body.
    #[must_use]
    pub fn into_top_part(self) -> MimePart {
        let mut top = MimePart::new();
        top.data = PartData::Multipart(Box::new(self));
        top.datasize = -1;
        top.flags |= MIME_BODY_ONLY;
        top
    }
}

// =============================================================================
// Header preparation (mirrors `Curl_mime_prepare_headers`, recursive)
// =============================================================================

impl MimePart {
    /// Generate this part's `Content-Disposition`, `Content-Type` and
    /// `Content-Transfer-Encoding` headers, recursing into any subparts. Mirrors
    /// `Curl_mime_prepare_headers` byte-for-byte.
    ///
    /// `contenttype` is the type inherited from the parent (for the top-level
    /// form part it is `multipart/form-data`); `disposition` is the inherited
    /// disposition (`form-data` for the subparts of a form); `strategy` selects
    /// HTTP-form versus mail conventions; `formescape` corresponds to
    /// `CURLMIMEOPT_FORMESCAPE` and forces backslash escaping on HTTP forms.
    ///
    /// # Errors
    ///
    /// Propagates any error from a recursive call; in practice this is
    /// infallible for in-memory metadata and only the recursion signature can
    /// surface an error.
    pub fn prepare_headers(
        &mut self,
        contenttype: Option<&[u8]>,
        disposition: Option<&[u8]>,
        strategy: MimeStrategy,
        formescape: bool,
    ) -> Result<()> {
        // Discard any headers from a previous preparation.
        self.curlheaders.clear();

        // Determine an explicit (custom) content type: an explicit `type`, else a
        // user-supplied `Content-Type` header. A custom type also suppresses the
        // text/plain dropping below.
        let custom_ct: Option<Vec<u8>> = self.mimetype.clone().or_else(|| {
            search_header(self.userheaders.as_ref(), "Content-Type").map(<[u8]>::to_vec)
        });

        // Effective content type: custom overrides the inherited one.
        let mut ct: Option<Vec<u8>> = custom_ct
            .clone()
            .or_else(|| contenttype.map(<[u8]>::to_vec));

        let is_multipart = matches!(self.data, PartData::Multipart(_));

        // Multipart parts carry the boundary used in their `Content-Type`.
        let boundary: Option<Vec<u8>> = match &self.data {
            PartData::Multipart(m) => Some(m.boundary.clone()),
            _ => None,
        };

        // Derive a content type when none is specified.
        if ct.is_none() {
            match &self.data {
                PartData::Multipart(_) => {
                    ct = Some(MULTIPART_CONTENTTYPE_DEFAULT.as_bytes().to_vec());
                }
                PartData::File(path) => {
                    let path_lossy = path.to_string_lossy();
                    let guess = guess_content_type(self.filename.as_deref())
                        .or_else(|| guess_content_type(Some(path_lossy.as_bytes())));
                    match guess {
                        Some(t) => ct = Some(t.as_bytes().to_vec()),
                        None => {
                            if self.filename.is_some() {
                                ct = Some(FILE_CONTENTTYPE_DEFAULT.as_bytes().to_vec());
                            }
                        }
                    }
                }
                _ => {
                    if let Some(t) = guess_content_type(self.filename.as_deref()) {
                        ct = Some(t.as_bytes().to_vec());
                    }
                }
            }
        }

        // Drop a *derived* text/plain type for mail, or for HTTP parts without a
        // filename (curl avoids a redundant `Content-Type: text/plain`).
        if !is_multipart && custom_ct.is_none() {
            if let Some(c) = &ct {
                if content_type_match(c, "text/plain")
                    && (strategy == MimeStrategy::Mail || self.filename.is_none())
                {
                    ct = None;
                }
            }
        }

        let escape_backslash = strategy == MimeStrategy::Mail || formescape;

        // Content-Disposition — only if the caller did not supply one.
        if search_header(self.userheaders.as_ref(), "Content-Disposition").is_none() {
            let mut disp: Option<Vec<u8>> = disposition.map(<[u8]>::to_vec);
            if disp.is_none()
                && (self.filename.is_some()
                    || self.name.is_some()
                    || ct
                        .as_deref()
                        .is_some_and(|c| !starts_with_ignore_case(c, b"multipart/")))
            {
                disp = Some(DISPOSITION_DEFAULT.as_bytes().to_vec());
            }
            // A bare "attachment" with neither name nor filename adds nothing.
            if let Some(d) = &disp {
                if d.eq_ignore_ascii_case(b"attachment")
                    && self.name.is_none()
                    && self.filename.is_none()
                {
                    disp = None;
                }
            }
            if let Some(d) = &disp {
                let mut line = Vec::with_capacity(48);
                line.extend_from_slice(b"Content-Disposition: ");
                line.extend_from_slice(d);
                if let Some(n) = &self.name {
                    line.extend_from_slice(b"; name=\"");
                    line.extend_from_slice(&escape_string(n, escape_backslash));
                    line.push(b'"');
                }
                if let Some(f) = &self.filename {
                    line.extend_from_slice(b"; filename=\"");
                    line.extend_from_slice(&escape_string(f, escape_backslash));
                    line.push(b'"');
                }
                self.curlheaders.push(line);
            }
        }

        // Content-Type (with the multipart boundary parameter when present).
        if let Some(c) = &ct {
            let mut line = Vec::with_capacity(16 + c.len());
            line.extend_from_slice(b"Content-Type: ");
            line.extend_from_slice(c);
            if let Some(b) = &boundary {
                line.extend_from_slice(b"; boundary=");
                line.extend_from_slice(b);
            }
            self.curlheaders.push(line);
        }

        // Content-Transfer-Encoding — only if the caller did not supply one.
        if search_header(self.userheaders.as_ref(), "Content-Transfer-Encoding").is_none() {
            let cte: Option<&str> = if let Some(enc) = self.encoder {
                Some(enc.name())
            } else if ct.is_some() && strategy == MimeStrategy::Mail && !is_multipart {
                Some("8bit")
            } else {
                None
            };
            if let Some(c) = cte {
                let mut line = Vec::with_capacity(28 + c.len());
                line.extend_from_slice(b"Content-Transfer-Encoding: ");
                line.extend_from_slice(c.as_bytes());
                self.curlheaders.push(line);
            }
        }

        // Recurse into subparts, passing the form-data disposition when this is a
        // `multipart/form-data` container.
        if let PartData::Multipart(m) = &mut self.data {
            let sub_disp: Option<&[u8]> = if ct
                .as_deref()
                .is_some_and(|c| content_type_match(c, "multipart/form-data"))
            {
                Some(b"form-data".as_slice())
            } else {
                None
            };
            for sp in m.iter_mut() {
                sp.prepare_headers(None, sub_disp, strategy, formescape)?;
            }
        }

        Ok(())
    }

    /// The headers generated by [`prepare_headers`](MimePart::prepare_headers),
    /// each without its trailing `CRLF`. For the synthetic top part of an HTTP
    /// form this is where the `Content-Type: multipart/form-data; boundary=...`
    /// request header is found.
    #[must_use]
    pub fn curl_headers(&self) -> &[Vec<u8>] {
        &self.curlheaders
    }
}

// =============================================================================
// Serialization — streaming body reader (mirrors the `readback_*` machinery)
// =============================================================================

/// One contiguous run of the serialized body.
///
/// In-memory runs (part headers, boundary delimiters, encoded content and the
/// content of in-memory or callback parts) are held as [`Segment::Bytes`];
/// unencoded file parts are held as [`Segment::File`] and streamed on demand so
/// a large upload is never buffered in full.
enum Segment {
    /// A buffered run, consumed from `pos` onward.
    Bytes {
        /// The bytes to emit.
        data: Vec<u8>,
        /// How many bytes at the front have already been emitted.
        pos: usize,
    },
    /// A file streamed lazily, emitting at most `remaining` bytes.
    File {
        /// The path to open on first read.
        path: PathBuf,
        /// The open handle, created on first read of this segment.
        file: Option<File>,
        /// Bytes still to emit (`u64::MAX` means "until EOF").
        remaining: u64,
    },
}

impl Segment {
    /// A buffered segment over `data`.
    fn bytes(data: Vec<u8>) -> Segment {
        Segment::Bytes { data, pos: 0 }
    }

    /// A streamed file segment capped at the part's declared size (`datasize`);
    /// a negative `datasize` means stream until end of file.
    fn file(path: PathBuf, datasize: i64) -> Segment {
        let remaining = if datasize < 0 {
            u64::MAX
        } else {
            datasize as u64
        };
        Segment::File {
            path,
            file: None,
            remaining,
        }
    }
}

/// A pull-based [`std::io::Read`] source over a fully prepared MIME tree.
///
/// The byte stream is exactly the one curl's `Curl_mime_read` produces: part
/// headers (curl-generated then user headers, with any user `Content-Type`
/// skipped), the empty line, the encoded or raw content, and the
/// boundary-delimited multipart framing. File parts without a transfer encoder
/// are streamed straight from disk.
pub struct MimeReader {
    /// The ordered runs that make up the body.
    segments: Vec<Segment>,
    /// Index of the segment currently being emitted.
    idx: usize,
}

impl Read for MimeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.idx < self.segments.len() {
            match &mut self.segments[self.idx] {
                Segment::Bytes { data, pos } => {
                    let avail = data.len() - *pos;
                    if avail == 0 {
                        self.idx += 1;
                        continue;
                    }
                    let n = avail.min(buf.len());
                    buf[..n].copy_from_slice(&data[*pos..*pos + n]);
                    *pos += n;
                    if *pos == data.len() {
                        self.idx += 1;
                    }
                    return Ok(n);
                }
                Segment::File {
                    path,
                    file,
                    remaining,
                } => {
                    if *remaining == 0 {
                        self.idx += 1;
                        continue;
                    }
                    if file.is_none() {
                        *file = Some(File::open(&*path)?);
                    }
                    let handle = file.as_mut().expect("file just opened");
                    let cap = (*remaining).min(buf.len() as u64) as usize;
                    let n = handle.read(&mut buf[..cap])?;
                    if n == 0 {
                        // Short file: stop emitting this part.
                        *remaining = 0;
                        self.idx += 1;
                        continue;
                    }
                    *remaining -= n as u64;
                    return Ok(n);
                }
            }
        }
        Ok(0)
    }
}

/// Append the boundary-delimited serialization of `mime` to `segments`,
/// reproducing the exact framing of curl's `mime_subparts_read`.
///
/// With no parts the body is `--<boundary>--\r\n`. Otherwise the first part is
/// preceded by `--<boundary>\r\n` (curl spares the leading CRLF), each later
/// part by `\r\n--<boundary>\r\n`, and the body ends with
/// `\r\n--<boundary>--\r\n`.
fn build_multipart_segments(mime: &mut Mime, segments: &mut Vec<Segment>) -> Result<()> {
    let boundary = mime.boundary.clone();
    if mime.parts.is_empty() {
        let mut d = Vec::with_capacity(MIME_BOUNDARY_LEN + 6);
        d.extend_from_slice(b"--");
        d.extend_from_slice(&boundary);
        d.extend_from_slice(b"--\r\n");
        segments.push(Segment::bytes(d));
        return Ok(());
    }
    for (i, part) in mime.parts.iter_mut().enumerate() {
        let mut d = Vec::with_capacity(MIME_BOUNDARY_LEN + 6);
        if i == 0 {
            d.extend_from_slice(b"--");
        } else {
            d.extend_from_slice(b"\r\n--");
        }
        d.extend_from_slice(&boundary);
        d.extend_from_slice(b"\r\n");
        segments.push(Segment::bytes(d));
        build_part_segments(part, segments)?;
    }
    let mut d = Vec::with_capacity(MIME_BOUNDARY_LEN + 8);
    d.extend_from_slice(b"\r\n--");
    d.extend_from_slice(&boundary);
    d.extend_from_slice(b"--\r\n");
    segments.push(Segment::bytes(d));
    Ok(())
}

/// Append the serialization of a single `part` (headers then content) to
/// `segments`, reproducing curl's `readback_part`. When [`MIME_BODY_ONLY`] is
/// set the headers and the trailing empty line are skipped and only the content
/// is emitted.
fn build_part_segments(part: &mut MimePart, segments: &mut Vec<Segment>) -> Result<()> {
    if part.flags & MIME_BODY_ONLY == 0 {
        let mut hdrs = Vec::new();
        // curl-generated headers, each terminated by CRLF.
        for h in &part.curlheaders {
            hdrs.extend_from_slice(h);
            hdrs.extend_from_slice(b"\r\n");
        }
        // User headers, skipping any Content-Type (already issued by curl).
        if let Some(uh) = &part.userheaders {
            for entry in uh.iter() {
                let bytes = entry.to_bytes();
                if match_header(bytes, "Content-Type").is_some() {
                    continue;
                }
                hdrs.extend_from_slice(bytes);
                hdrs.extend_from_slice(b"\r\n");
            }
        }
        // Empty line terminating the headers.
        hdrs.extend_from_slice(b"\r\n");
        segments.push(Segment::bytes(hdrs));
    }
    build_content_segments(part, segments)
}

/// Append the (possibly encoded) content of `part` to `segments`.
fn build_content_segments(part: &mut MimePart, segments: &mut Vec<Segment>) -> Result<()> {
    let is_multipart = matches!(part.data, PartData::Multipart(_));

    if let Some(enc) = part.encoder {
        // Encoded content must be materialized so the encoder can wrap it.
        let raw = if is_multipart {
            let mut tmp = Vec::new();
            if let PartData::Multipart(m) = &mut part.data {
                build_multipart_segments(m, &mut tmp)?;
            }
            segments_to_bytes(tmp)?
        } else {
            read_leaf_raw(&mut part.data, part.datasize)?
        };
        segments.push(Segment::bytes(enc.encode(&raw)?));
        return Ok(());
    }

    match &mut part.data {
        PartData::None => {}
        PartData::Bytes(b) => segments.push(Segment::bytes(b.clone())),
        PartData::File(path) => segments.push(Segment::file(path.clone(), part.datasize)),
        PartData::Callback(reader) => {
            let mut raw = Vec::new();
            read_reader_to_end(reader.as_mut(), &mut raw)?;
            segments.push(Segment::bytes(raw));
        }
        PartData::Multipart(m) => build_multipart_segments(m, segments)?,
    }
    Ok(())
}

/// Read all of a leaf part's raw content into memory, honoring a non-negative
/// `datasize` cap for file parts (curl stops at the size captured at
/// `curl_mime_filedata` time).
fn read_leaf_raw(data: &mut PartData, datasize: i64) -> Result<Vec<u8>> {
    match data {
        PartData::Bytes(b) => Ok(b.clone()),
        PartData::File(path) => {
            let mut f = File::open(&*path).map_err(|_| CurlError::ReadError)?;
            let mut v = Vec::new();
            if datasize < 0 {
                f.read_to_end(&mut v).map_err(|_| CurlError::ReadError)?;
            } else {
                f.take(datasize as u64)
                    .read_to_end(&mut v)
                    .map_err(|_| CurlError::ReadError)?;
            }
            Ok(v)
        }
        PartData::Callback(reader) => {
            let mut v = Vec::new();
            read_reader_to_end(reader.as_mut(), &mut v)?;
            Ok(v)
        }
        PartData::None | PartData::Multipart(_) => Ok(Vec::new()),
    }
}

/// Drain a [`MimeDataReader`] to end of data, mapping any I/O error onto
/// [`CurlError::ReadError`].
fn read_reader_to_end(reader: &mut dyn MimeDataReader, out: &mut Vec<u8>) -> Result<()> {
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(CurlError::ReadError),
        }
    }
}

/// Flatten a list of segments into a single byte buffer, reading any file
/// segments. Used only for the (degenerate) encoded-multipart case.
fn segments_to_bytes(segs: Vec<Segment>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for s in segs {
        match s {
            Segment::Bytes { data, pos } => out.extend_from_slice(&data[pos..]),
            Segment::File {
                path, remaining, ..
            } => {
                let mut f = File::open(&path).map_err(|_| CurlError::ReadError)?;
                if remaining == u64::MAX {
                    f.read_to_end(&mut out).map_err(|_| CurlError::ReadError)?;
                } else {
                    f.take(remaining)
                        .read_to_end(&mut out)
                        .map_err(|_| CurlError::ReadError)?;
                }
            }
        }
    }
    Ok(out)
}

// ---- size computation (mirrors mime_size / multipart_size / slist_size) ------

/// Sum of `len + 2` (the header text plus its CRLF) over curl-generated headers.
fn curlheaders_size(headers: &[Vec<u8>]) -> i64 {
    headers.iter().map(|h| h.len() as i64 + 2).sum()
}

/// Sum of `len + 2` over user headers, skipping any `Content-Type`.
fn userheaders_size(list: Option<&SList>) -> i64 {
    match list {
        None => 0,
        Some(l) => l
            .iter()
            .filter(|e| match_header(e.to_bytes(), "Content-Type").is_none())
            .map(|e| e.to_bytes().len() as i64 + 2)
            .sum(),
    }
}

/// Compute the serialized size of `mime`, mirroring `multipart_size`. Returns
/// `-1` if any part's size is unknown.
fn multipart_size(mime: &mut Mime) -> i64 {
    // "\r\n--" (4) + boundary + "\r\n" (2): the per-part and final overhead.
    // curl uses `strlen(mime->boundary)` here, so use the actual boundary
    // length rather than the nominal constant (they coincide for the 46-byte
    // boundaries `Mime::new` generates, but the actual length keeps the size
    // correct for any boundary).
    let boundarysize = 4 + mime.boundary.len() as i64 + 2;
    let mut size = boundarysize; // The final boundary / CRLF after headers.
    for part in mime.parts.iter_mut() {
        let sz = mime_size(part);
        if sz < 0 {
            size = sz;
        }
        if size >= 0 {
            size += boundarysize + sz;
        }
    }
    size
}

/// Compute the serialized size of one `part`, mirroring `mime_size`. Returns
/// `-1` when the size cannot be determined (for example an unsized callback or a
/// quoted-printable encoder over non-empty data).
fn mime_size(part: &mut MimePart) -> i64 {
    let base = if let PartData::Multipart(m) = &mut part.data {
        multipart_size(m)
    } else {
        part.datasize
    };
    let mut size = base;
    if let Some(enc) = part.encoder {
        size = enc.encoded_size(size);
    }
    if size >= 0 && part.flags & MIME_BODY_ONLY == 0 {
        size += curlheaders_size(&part.curlheaders);
        size += userheaders_size(part.userheaders.as_ref());
        size += 2; // CRLF after headers.
    }
    size
}

impl MimePart {
    /// Build a streaming [`MimeReader`] over this part's serialized form.
    ///
    /// Call [`prepare_headers`](MimePart::prepare_headers) first so the part
    /// headers are present; this method only assembles the byte runs.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::ReadError`] if a file or callback part cannot be read
    /// while assembling encoded or callback content, or any error surfaced by an
    /// encoder.
    pub fn reader(&mut self) -> Result<MimeReader> {
        let mut segments = Vec::new();
        build_part_segments(self, &mut segments)?;
        Ok(MimeReader { segments, idx: 0 })
    }

    /// Serialize this part fully into a byte buffer — a convenience over
    /// [`reader`](MimePart::reader) for callers (and tests) that want the whole
    /// body at once.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::ReadError`] if streaming a file or callback part
    /// fails, or any encoder error.
    pub fn to_bytes(&mut self) -> Result<Vec<u8>> {
        let mut reader = self.reader()?;
        let mut out = Vec::new();
        reader
            .read_to_end(&mut out)
            .map_err(|_| CurlError::ReadError)?;
        Ok(out)
    }

    /// Compute the exact serialized size of this part (headers plus content,
    /// with the multipart framing for a container), or `-1` if it cannot be
    /// determined. Mirrors `Curl_mime_size`; the result feeds the HTTP
    /// `Content-Length`.
    pub fn compute_size(&mut self) -> i64 {
        mime_size(self)
    }
}

// =============================================================================
// Legacy form API (mirrors lib/formdata.c) — deprecated but required for parity
// =============================================================================

/// Result code for the legacy form builder, mirroring `CURLFORMcode` with the
/// exact integer values from `include/curl/curl.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum FormCode {
    /// `CURL_FORMADD_OK` — success.
    Ok = 0,
    /// `CURL_FORMADD_MEMORY` — allocation failure (not produced in safe Rust).
    Memory = 1,
    /// `CURL_FORMADD_OPTION_TWICE` — an option was supplied twice.
    OptionTwice = 2,
    /// `CURL_FORMADD_NULL` — a required pointer argument was NULL.
    Null = 3,
    /// `CURL_FORMADD_UNKNOWN_OPTION` — an unrecognized option was used.
    UnknownOption = 4,
    /// `CURL_FORMADD_INCOMPLETE` — the section is missing required fields.
    Incomplete = 5,
    /// `CURL_FORMADD_ILLEGAL_ARRAY` — an illegal nested array was used.
    IllegalArray = 6,
    /// `CURL_FORMADD_DISABLED` — the form API was disabled at build time.
    Disabled = 7,
}

impl FormCode {
    /// The integer value, identical to the corresponding `CURLFORMcode`.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// The Rust analog of `struct curl_httppost`: one node in a legacy form post
/// chain. `next` links sibling sections; `more` links the additional files of a
/// single multi-file field. The whole chain is freed deterministically by
/// `Drop`, replacing `curl_formfree`.
///
/// The C struct's `userp`/read-callback pair (used for `CURL_HTTPPOST_CALLBACK`)
/// is represented safely by the [`reader`](HttpPost::reader) field; all other
/// fields mirror `curl_httppost` one-to-one.
#[derive(Default)]
pub struct HttpPost {
    /// Field name.
    pub name: Vec<u8>,
    /// Length of `name` (`namelength`).
    pub namelength: usize,
    /// Allocated contents: the value, a filename, or unused depending on flags.
    pub contents: Option<Vec<u8>>,
    /// Length of `contents` (`contentslength`).
    pub contentslength: i64,
    /// In-memory buffer contents (`CURL_HTTPPOST_BUFFER`).
    pub buffer: Option<Vec<u8>>,
    /// Length of `buffer` (`bufferlength`).
    pub bufferlength: usize,
    /// Explicit `Content-Type`.
    pub contenttype: Option<Vec<u8>>,
    /// Extra per-part headers (`contentheader`).
    pub contentheader: Option<SList>,
    /// Filename to show in `Content-Disposition` (`showfilename`).
    pub showfilename: Option<Vec<u8>>,
    /// Bit set of `CURL_HTTPPOST_*` flags.
    pub flags: u32,
    /// Alternative content length used when `CURL_HTTPPOST_LARGE` is set.
    pub contentlen: i64,
    /// Streaming reader for `CURL_HTTPPOST_CALLBACK` (replaces the C `userp`).
    pub reader: Option<Box<dyn MimeDataReader>>,
    /// Additional files of the same field name (`more`).
    pub more: Option<Box<HttpPost>>,
    /// The next sibling section (`next`).
    pub next: Option<Box<HttpPost>>,
}

impl HttpPost {
    /// An empty node with `CURL_HTTPPOST_LARGE` set (curl's `AddHttpPost`
    /// unconditionally sets this flag).
    fn new_node() -> HttpPost {
        HttpPost {
            flags: CURL_HTTPPOST_LARGE,
            ..HttpPost::default()
        }
    }
}

/// One file in a multi-file [`FormContent::Files`] section.
pub struct FormFile {
    /// The path of the file to upload.
    pub filename: Vec<u8>,
    /// An explicit content type, or `None` to let curl guess from the extension.
    pub contenttype: Option<Vec<u8>>,
}

/// The content of a single [`FormSection`], capturing the meaning of the
/// `CURLFORM_*` content options exactly.
pub enum FormContent {
    /// `CURLFORM_COPYCONTENTS` / `CURLFORM_PTRCONTENTS` — an in-memory value.
    Data(Vec<u8>),
    /// `CURLFORM_FILECONTENT` — read this file's bytes as the value, with no
    /// filename shown in the disposition.
    FileContent(Vec<u8>),
    /// `CURLFORM_FILE` (possibly repeated) — one or more files to upload.
    Files(Vec<FormFile>),
    /// `CURLFORM_BUFFER` + `CURLFORM_BUFFERPTR`/`BUFFERLENGTH` — an in-memory
    /// "file" with a shown filename.
    Buffer {
        /// The filename shown in the `Content-Disposition`.
        filename: Vec<u8>,
        /// The buffer contents.
        data: Vec<u8>,
    },
    /// `CURLFORM_STREAM` (+ `CURLFORM_CONTENTLEN`) — content read on demand.
    Stream {
        /// The declared length, or `-1` if unknown.
        len: i64,
        /// The streaming reader.
        reader: Box<dyn MimeDataReader>,
    },
}

/// A single logical form section — the typed analog of the arguments to one
/// `curl_formadd` call. The FFI layer marshals the variadic `CURLFORM_*`
/// arguments (detecting `OPTION_TWICE` / `NULL` / `UNKNOWN_OPTION` /
/// `ILLEGAL_ARRAY` as it goes) into this structure and then calls
/// [`FormData::add`].
pub struct FormSection {
    /// The field name (`CURLFORM_COPYNAME` / `PTRNAME`, length from
    /// `CURLFORM_NAMELENGTH`).
    pub name: Vec<u8>,
    /// The section content.
    pub content: FormContent,
    /// An explicit content type for single-content sections
    /// (`CURLFORM_CONTENTTYPE`); per-file types live in [`FormFile`].
    pub contenttype: Option<Vec<u8>>,
    /// Extra headers (`CURLFORM_CONTENTHEADER`).
    pub headers: Option<SList>,
    /// Shown filename for buffer/callback sections (`CURLFORM_FILENAME`).
    pub showfilename: Option<Vec<u8>>,
}

/// A reader that yields no data — the safe stand-in for a `CURL_HTTPPOST_CALLBACK`
/// part whose reader was not supplied.
struct EmptyReader;

impl MimeDataReader for EmptyReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

/// A reader that streams from standard input, used for the legacy `"-"`
/// pseudo-filename (curl reads such a part from `stdin`).
struct StdinReader {
    inner: io::Stdin,
}

impl StdinReader {
    fn new() -> StdinReader {
        StdinReader { inner: io::stdin() }
    }
}

impl MimeDataReader for StdinReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

/// Interpret `bytes` using curl's length conventions: a `len` of `0` means
/// "NUL-terminated, use the bytes up to the first NUL"; a negative `len` means
/// "use all bytes"; a positive `len` caps the slice.
fn sized_or_zero_terminated(bytes: &[u8], len: i64) -> Vec<u8> {
    if len == 0 {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        bytes[..end].to_vec()
    } else if len < 0 {
        bytes.to_vec()
    } else {
        let n = (len as usize).min(bytes.len());
        bytes[..n].to_vec()
    }
}

/// Resolve a file/buffer part's content type, mirroring `FormAddCheck`: an
/// explicit type wins; otherwise guess from the filename extension; otherwise
/// fall back to the previous part's type; otherwise
/// [`FILE_CONTENTTYPE_DEFAULT`].
fn resolve_file_contenttype(
    explicit: Option<Vec<u8>>,
    filename: &[u8],
    prevtype: Option<&[u8]>,
) -> Vec<u8> {
    if let Some(t) = explicit {
        return t;
    }
    if let Some(t) = guess_content_type(Some(filename)) {
        return t.as_bytes().to_vec();
    }
    if let Some(p) = prevtype {
        return p.to_vec();
    }
    FILE_CONTENTTYPE_DEFAULT.as_bytes().to_vec()
}

/// Set a MIME part's name honoring an explicit length (`0` means use the whole
/// NUL-free name), mirroring `setname()` in `lib/formdata.c`.
fn set_part_name(part: &mut MimePart, name: &[u8], namelength: usize) -> Result<()> {
    let slice = if namelength == 0 {
        name
    } else {
        &name[..namelength.min(name.len())]
    };
    part.set_name(Some(slice))?;
    Ok(())
}

/// The fully resolved inputs needed to populate one MIME part from a legacy form
/// node, gathered to avoid aliasing the source [`HttpPost`] while building.
struct PartFill {
    contentheader: Option<SList>,
    contenttype: Option<Vec<u8>>,
    name: Option<(Vec<u8>, usize)>,
    flags: u32,
    contentlen: i64,
    contentslength: i64,
    filename: Option<Vec<u8>>,
    buffer: Option<Vec<u8>>,
    bufferlength: usize,
    contents: Option<Vec<u8>>,
    showfilename: Option<Vec<u8>>,
    has_more: bool,
    reader: Option<Box<dyn MimeDataReader>>,
}

/// Populate `part` from a resolved [`PartFill`], reproducing the per-part body of
/// `Curl_getformdata`.
fn apply_fill(part: &mut MimePart, fill: PartFill) -> Result<()> {
    if let Some(h) = fill.contentheader {
        part.set_headers(Some(h), false)?;
    }
    if let Some(ct) = &fill.contenttype {
        part.set_type(Some(ct))?;
    }
    if let Some((nm, nl)) = &fill.name {
        set_part_name(part, nm, *nl)?;
    }

    let clen = if fill.flags & CURL_HTTPPOST_LARGE != 0 {
        fill.contentlen
    } else {
        fill.contentslength
    };

    if fill.flags & (CURL_HTTPPOST_FILENAME | CURL_HTTPPOST_READFILE) != 0 {
        let fname = fill.filename.as_deref().unwrap_or(b"");
        if fname == b"-" {
            part.set_data_cb(-1, Box::new(StdinReader::new()))?;
        } else {
            let s = String::from_utf8_lossy(fname).into_owned();
            part.set_filedata(&s)?;
        }
        if fill.flags & CURL_HTTPPOST_READFILE != 0 {
            part.set_filename(None)?;
        }
    } else if fill.flags & CURL_HTTPPOST_BUFFER != 0 {
        let buf = fill.buffer.unwrap_or_default();
        let n = if fill.bufferlength > 0 {
            fill.bufferlength as i64
        } else {
            0
        };
        part.set_data_bytes(sized_or_zero_terminated(&buf, n))?;
    } else if fill.flags & CURL_HTTPPOST_CALLBACK != 0 {
        let mut c = clen;
        if c == 0 {
            c = -1;
        }
        let reader = fill.reader.unwrap_or_else(|| Box::new(EmptyReader));
        part.set_data_cb(c, reader)?;
    } else {
        let contents = fill.contents.unwrap_or_default();
        let len = if clen == 0 { 0 } else { clen };
        part.set_data_bytes(sized_or_zero_terminated(&contents, len))?;
    }

    // Apply the shown filename where curl would (multi-file, or file/buffer/
    // callback parts).
    if let Some(sf) = &fill.showfilename {
        if fill.has_more
            || fill.flags & (CURL_HTTPPOST_FILENAME | CURL_HTTPPOST_BUFFER | CURL_HTTPPOST_CALLBACK)
                != 0
        {
            part.set_filename(Some(sf))?;
        }
    }
    Ok(())
}

/// Build the [`HttpPost`] node (with a `more` chain for multi-file sections) for
/// one [`FormSection`], reproducing the relevant `FormAdd` / `FormAddCheck`
/// semantics. Returns a [`FormCode`] on validation failure.
fn build_section_node(section: FormSection) -> core::result::Result<Box<HttpPost>, FormCode> {
    let FormSection {
        name,
        content,
        contenttype,
        headers,
        showfilename,
    } = section;
    let namelength = name.len();

    let mut node = HttpPost::new_node();
    node.name = name;
    node.namelength = namelength;
    node.contentheader = headers;

    match content {
        FormContent::Data(bytes) => {
            let len = bytes.len() as i64;
            node.contentslength = len;
            node.contentlen = len;
            node.contents = Some(bytes);
            node.contenttype = contenttype;
        }
        FormContent::FileContent(filename) => {
            node.flags |= CURL_HTTPPOST_READFILE;
            node.contents = Some(filename);
            node.contenttype = contenttype;
        }
        FormContent::Files(files) => {
            if files.is_empty() {
                return Err(FormCode::Incomplete);
            }
            node.flags |= CURL_HTTPPOST_FILENAME;
            node.showfilename = showfilename;

            let f0 = &files[0];
            let explicit0 = f0.contenttype.clone().or(contenttype);
            let ct0 = resolve_file_contenttype(explicit0, &f0.filename, None);
            node.contents = Some(f0.filename.clone());
            node.contenttype = Some(ct0.clone());
            let mut prevtype: Option<Vec<u8>> = Some(ct0);

            // Remaining files become a `more` chain.
            let mut tail = &mut node;
            for f in &files[1..] {
                let mut more = HttpPost::new_node();
                more.flags |= CURL_HTTPPOST_FILENAME;
                let ct = resolve_file_contenttype(
                    f.contenttype.clone(),
                    &f.filename,
                    prevtype.as_deref(),
                );
                prevtype = Some(ct.clone());
                more.contents = Some(f.filename.clone());
                more.contenttype = Some(ct);
                tail.more = Some(Box::new(more));
                tail = tail.more.as_mut().expect("more was just set");
            }
        }
        FormContent::Buffer { filename, data } => {
            node.flags |= CURL_HTTPPOST_BUFFER;
            node.bufferlength = data.len();
            node.buffer = Some(data);
            let ct = resolve_file_contenttype(contenttype, &filename, None);
            node.contenttype = Some(ct);
            node.showfilename = Some(filename);
        }
        FormContent::Stream { len, reader } => {
            node.flags |= CURL_HTTPPOST_CALLBACK;
            node.contentslength = len;
            node.contentlen = len;
            node.reader = Some(reader);
            node.contenttype = contenttype;
            node.showfilename = showfilename;
        }
    }

    Ok(Box::new(node))
}

/// An owning collection of legacy form sections — the safe analog of curl's
/// `curl_httppost *` head pointer driven by `curl_formadd`.
///
/// Build it with [`add`](FormData::add) (the typed analog of `curl_formadd`),
/// serialize it with [`get`](FormData::get) (`curl_formget`), or convert it to a
/// [`Mime`] with [`to_mime`](FormData::to_mime) (`Curl_getformdata`). The whole
/// chain is freed by `Drop`, replacing `curl_formfree`.
#[derive(Default)]
pub struct FormData {
    /// The head of the section chain.
    head: Option<Box<HttpPost>>,
}

impl FormData {
    /// Create an empty form.
    #[must_use]
    pub fn new() -> FormData {
        FormData::default()
    }

    /// True when no sections have been added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Borrow the head [`HttpPost`] node, if any.
    #[must_use]
    pub fn head(&self) -> Option<&HttpPost> {
        self.head.as_deref()
    }

    /// Mutably borrow the head [`HttpPost`] node, if any.
    pub fn head_mut(&mut self) -> Option<&mut HttpPost> {
        self.head.as_deref_mut()
    }

    /// Append a form section, mirroring `curl_formadd`. Returns [`FormCode::Ok`]
    /// on success or a specific code on validation failure.
    pub fn add(&mut self, section: FormSection) -> FormCode {
        match build_section_node(section) {
            Ok(node) => {
                self.append(node);
                FormCode::Ok
            }
            Err(code) => code,
        }
    }

    /// Append a built node to the tail of the chain.
    fn append(&mut self, node: Box<HttpPost>) {
        match &mut self.head {
            None => self.head = Some(node),
            Some(head) => {
                let mut cur = head.as_mut();
                while cur.next.is_some() {
                    cur = cur.next.as_mut().expect("checked is_some").as_mut();
                }
                cur.next = Some(node);
            }
        }
    }

    /// Convert the form to a [`Mime`] multipart, mirroring `Curl_getformdata`.
    ///
    /// # Errors
    ///
    /// Returns an error if a referenced file cannot be stat'd or the boundary
    /// RNG fails.
    pub fn to_mime(&mut self) -> Result<Mime> {
        match &mut self.head {
            None => Mime::new(),
            Some(head) => httppost_to_mime(head),
        }
    }

    /// Serialize the form exactly as `curl_formget` would: the top-level
    /// `Content-Type: multipart/form-data; boundary=...` header, the blank line,
    /// and the multipart body.
    ///
    /// # Errors
    ///
    /// Returns an error if a referenced file cannot be read or the boundary RNG
    /// fails.
    pub fn get(&mut self) -> Result<Vec<u8>> {
        match &mut self.head {
            None => Ok(Vec::new()),
            Some(head) => form_get(head),
        }
    }
}

/// Convert a legacy form chain rooted at `post` into a [`Mime`] multipart,
/// faithfully reproducing `Curl_getformdata`. A section with multiple files
/// becomes a named wrapper part containing a nested multipart.
///
/// # Errors
///
/// Returns an error if a referenced file cannot be stat'd or a boundary cannot
/// be generated.
pub fn httppost_to_mime(post: &mut HttpPost) -> Result<Mime> {
    let mut form = Mime::new()?;
    let mut cur: Option<&mut HttpPost> = Some(post);

    while let Some(sect) = cur {
        let has_more = sect.more.is_some();
        // Snapshot owner-level fields used by every file in the section.
        let o_name = sect.name.clone();
        let o_namelen = sect.namelength;
        let o_flags = sect.flags;
        let o_contentlen = sect.contentlen;
        let o_contentslen = sect.contentslength;
        let o_buffer = sect.buffer.clone();
        let o_contents = sect.contents.clone();
        let o_bufferlength = sect.bufferlength;
        let o_showfilename = sect.showfilename.clone();

        if has_more {
            let wrapper = form.addpart();
            set_part_name(wrapper, &o_name, o_namelen)?;
            let mut sub = Mime::new()?;

            // The section node itself is the first file.
            let first_fill = PartFill {
                contentheader: sect.contentheader.clone(),
                contenttype: sect.contenttype.clone(),
                name: None,
                flags: o_flags,
                contentlen: o_contentlen,
                contentslength: o_contentslen,
                filename: sect.contents.clone(),
                buffer: o_buffer.clone(),
                bufferlength: o_bufferlength,
                contents: o_contents.clone(),
                showfilename: o_showfilename.clone(),
                has_more: true,
                reader: None,
            };
            let p = sub.addpart();
            apply_fill(p, first_fill)?;

            // Then each additional file in the `more` chain.
            let mut f = sect.more.as_deref();
            while let Some(file) = f {
                let fill = PartFill {
                    contentheader: file.contentheader.clone(),
                    contenttype: file.contenttype.clone(),
                    name: None,
                    flags: o_flags,
                    contentlen: o_contentlen,
                    contentslength: o_contentslen,
                    filename: file.contents.clone(),
                    buffer: o_buffer.clone(),
                    bufferlength: o_bufferlength,
                    contents: o_contents.clone(),
                    showfilename: o_showfilename.clone(),
                    has_more: true,
                    reader: None,
                };
                let p = sub.addpart();
                apply_fill(p, fill)?;
                f = file.more.as_deref();
            }

            wrapper.set_subparts(Some(sub))?;
        } else {
            // Single content; move out any callback reader.
            let reader = sect.reader.take();
            let fill = PartFill {
                contentheader: sect.contentheader.clone(),
                contenttype: sect.contenttype.clone(),
                name: Some((o_name, o_namelen)),
                flags: o_flags,
                contentlen: o_contentlen,
                contentslength: o_contentslen,
                filename: sect.contents.clone(),
                buffer: o_buffer,
                bufferlength: o_bufferlength,
                contents: o_contents,
                showfilename: o_showfilename,
                has_more: false,
                reader,
            };
            let p = form.addpart();
            apply_fill(p, fill)?;
        }

        cur = sect.next.as_deref_mut();
    }

    Ok(form)
}

/// Serialize a legacy form chain exactly as `curl_formget` does — including the
/// top-level `Content-Type` header and the separating blank line — by building
/// the MIME tree, preparing its headers with the `multipart/form-data` strategy,
/// and reading it back in full.
///
/// # Errors
///
/// Returns an error if a referenced file cannot be read or a boundary cannot be
/// generated.
pub fn form_get(post: &mut HttpPost) -> Result<Vec<u8>> {
    let mime = httppost_to_mime(post)?;
    // A non-body-only top part: its Content-Type and the blank line are part of
    // the produced bytes (curl_formget serializes the whole part).
    let mut top = MimePart::new();
    top.data = PartData::Multipart(Box::new(mime));
    top.datasize = -1;
    top.prepare_headers(
        Some(b"multipart/form-data"),
        None,
        MimeStrategy::Form,
        false,
    )?;
    top.to_bytes()
}

// =============================================================================
// Tests
//
// These tests assert *byte-for-byte* parity with curl 8.x wire output wherever
// the bytes are deterministic. Random boundaries are pinned via
// `Mime::with_boundary` (or by overwriting `Mime::boundary` after a legacy
// conversion) so the produced bodies can be compared exactly. The remaining
// tests pin down the encoders, the header-preparation rules, the size
// computation invariant, and the legacy form -> MIME conversion.
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // --- helpers -------------------------------------------------------------

    /// Serialize a `Mime` as the HTTP request *body only* (the synthetic top
    /// part is `MIME_BODY_ONLY`, so no top `Content-Type` header is emitted),
    /// exactly as the body of a `multipart/form-data` request would appear.
    fn form_body(mime: Mime) -> Vec<u8> {
        let mut top = mime.into_top_part();
        top.prepare_headers(
            Some(b"multipart/form-data"),
            None,
            MimeStrategy::Form,
            false,
        )
        .expect("prepare_headers is infallible for in-memory metadata");
        top.to_bytes()
            .expect("serialization of in-memory parts succeeds")
    }

    /// Naive substring search used for the structural (non-byte-exact) checks
    /// against bodies whose boundary is random.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Create a fresh, uniquely named temporary directory for file-part tests.
    fn unique_dir() -> std::path::PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut dir = std::env::temp_dir();
        dir.push(format!("curlrs_mime_test_{}_{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// Write `content` to `dir/name` and return the full path as a `String`.
    fn write_file(dir: &std::path::Path, name: &str, content: &[u8]) -> String {
        let mut p = dir.to_path_buf();
        p.push(name);
        std::fs::write(&p, content).expect("write temp file");
        p.to_string_lossy().into_owned()
    }

    // --- escape_string -------------------------------------------------------

    #[test]
    fn escape_string_form_mode() {
        // HTTP form default: " -> %22, CR -> %0D, LF -> %0A; everything else
        // passes through verbatim.
        assert_eq!(escape_string(b"a\"b", false), b"a%22b".to_vec());
        assert_eq!(escape_string(b"a\r\nb", false), b"a%0D%0Ab".to_vec());
        assert_eq!(escape_string(b"plain text", false), b"plain text".to_vec());
    }

    #[test]
    fn escape_string_backslash_mode() {
        // Mail / CURLMIMEOPT_FORMESCAPE: \ -> \\, " -> \"; CR/LF are left alone.
        assert_eq!(escape_string(b"a\"b", true), b"a\\\"b".to_vec());
        assert_eq!(escape_string(b"a\\b", true), b"a\\\\b".to_vec());
        assert_eq!(escape_string(b"a\r\nb", true), b"a\r\nb".to_vec());
    }

    // --- content type guessing ----------------------------------------------

    #[test]
    fn content_type_guessing() {
        assert_eq!(guess_content_type(Some(b"photo.png")), Some("image/png"));
        // Case-insensitive on the extension.
        assert_eq!(guess_content_type(Some(b"PHOTO.JPG")), Some("image/jpeg"));
        assert_eq!(guess_content_type(Some(b"a.jpeg")), Some("image/jpeg"));
        assert_eq!(guess_content_type(Some(b"notes.txt")), Some("text/plain"));
        assert_eq!(guess_content_type(Some(b"page.html")), Some("text/html"));
        assert_eq!(
            guess_content_type(Some(b"doc.pdf")),
            Some("application/pdf")
        );
        assert_eq!(guess_content_type(Some(b"noextension")), None);
        assert_eq!(guess_content_type(None), None);
    }

    // --- encoders ------------------------------------------------------------

    #[test]
    fn encoding_names_roundtrip() {
        for (enc, name) in [
            (MimeEncoding::Binary, "binary"),
            (MimeEncoding::EightBit, "8bit"),
            (MimeEncoding::SevenBit, "7bit"),
            (MimeEncoding::Base64, "base64"),
            (MimeEncoding::QuotedPrintable, "quoted-printable"),
        ] {
            assert_eq!(enc.name(), name);
            assert_eq!(MimeEncoding::from_name(name), Some(enc));
            // Names are matched case-insensitively (curl uses curl_strequal).
            assert_eq!(MimeEncoding::from_name(&name.to_uppercase()), Some(enc));
        }
        assert_eq!(MimeEncoding::from_name("rot13"), None);
    }

    #[test]
    fn encoder_identity_and_7bit() {
        // binary / 8bit are identity transforms, including over high bytes.
        assert_eq!(
            MimeEncoding::Binary.encode(b"\x00\x01\xfe\xff").unwrap(),
            b"\x00\x01\xfe\xff".to_vec()
        );
        assert_eq!(
            MimeEncoding::EightBit.encode(b"\x00\x80\xff").unwrap(),
            b"\x00\x80\xff".to_vec()
        );
        // 7bit is identity for pure ASCII...
        assert_eq!(
            MimeEncoding::SevenBit.encode(b"ok ascii").unwrap(),
            b"ok ascii".to_vec()
        );
        // ...but fails (READ_ERROR) when any byte has the high bit set.
        assert!(matches!(
            MimeEncoding::SevenBit.encode(b"high\x80byte"),
            Err(CurlError::ReadError)
        ));
    }

    #[test]
    fn base64_small_and_wrap() {
        // Short input: standard base64 with padding, no wrapping.
        assert_eq!(
            MimeEncoding::Base64.encode(b"Hello, World!").unwrap(),
            b"SGVsbG8sIFdvcmxkIQ==".to_vec()
        );
        // 60 bytes -> 80 base64 chars -> exactly one wrap (CRLF after 76 chars),
        // and no trailing CRLF.
        let data = vec![b'A'; 60];
        let enc = MimeEncoding::Base64.encode(&data).unwrap();
        assert_eq!(enc.len(), 82);
        assert_eq!(&enc[76..78], b"\r\n");
        assert_ne!(&enc[enc.len() - 2..], b"\r\n");
        // Removing the inserted CRLF yields the unwrapped standard base64.
        let mut unwrapped = enc.clone();
        unwrapped.drain(76..78);
        assert_eq!(unwrapped, base64_encode(&data).unwrap());
    }

    #[test]
    fn base64_encoded_size_matches_encode() {
        // The size function curl uses for Content-Length must agree with the
        // bytes actually produced for every input length, including the
        // wrapping thresholds (57/58 chars, multi-line).
        for n in [0usize, 1, 2, 3, 57, 58, 60, 100, 120, 1000] {
            let data = vec![b'Z'; n];
            let enc = MimeEncoding::Base64.encode(&data).unwrap();
            assert_eq!(
                MimeEncoding::Base64.encoded_size(n as i64),
                enc.len() as i64,
                "base64 size mismatch for n={n}"
            );
        }
    }

    #[test]
    fn quoted_printable_basic_escapes() {
        let qp = |d: &[u8]| MimeEncoding::QuotedPrintable.encode(d).unwrap();
        assert_eq!(qp(b"hello"), b"hello".to_vec());
        assert_eq!(qp(b"a=b"), b"a=3Db".to_vec()); // '=' -> =3D
        assert_eq!(qp(b"\xff"), b"=FF".to_vec()); // high byte -> =FF (uppercase)
        assert_eq!(qp(b"caf\xc3\xa9"), b"caf=C3=A9".to_vec()); // UTF-8 'é'
        assert_eq!(qp(b"end "), b"end=20".to_vec()); // trailing space -> =20
        assert_eq!(qp(b"a b"), b"a b".to_vec()); // interior space kept
        assert_eq!(qp(b"tab\tend"), b"tab\tend".to_vec()); // interior tab kept
        assert_eq!(qp(b"tab\t"), b"tab=09".to_vec()); // trailing tab -> =09
        assert_eq!(qp(b"a\r\nb"), b"a\r\nb".to_vec()); // hard CRLF preserved
        assert_eq!(qp(b"a\rb"), b"a=0Db".to_vec()); // lone CR -> =0D
        assert_eq!(qp(b"a\nb"), b"a=0Ab".to_vec()); // lone LF -> =0A
    }

    #[test]
    fn quoted_printable_soft_line_breaks() {
        // A long run with no natural line breaks must be split with soft breaks
        // so no encoded line exceeds 76 columns, and reconstructing (dropping
        // the "=\r\n" soft breaks) must restore the original bytes.
        let data = vec![b'a'; 200];
        let qp = MimeEncoding::QuotedPrintable.encode(&data).unwrap();
        for line in qp.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            assert!(
                line.len() <= 76,
                "encoded line exceeds 76 columns: {}",
                line.len()
            );
        }
        let mut reconstructed = Vec::new();
        let mut i = 0;
        while i < qp.len() {
            if qp[i] == b'=' && qp.get(i + 1) == Some(&b'\r') && qp.get(i + 2) == Some(&b'\n') {
                i += 3; // skip a soft break
            } else {
                reconstructed.push(qp[i]);
                i += 1;
            }
        }
        assert_eq!(reconstructed, data);
    }

    // --- boundary format -----------------------------------------------------

    #[test]
    fn boundary_has_curl_format() {
        let mime = Mime::new().unwrap();
        let b = mime.boundary_str();
        // 24 dashes + 22 random alphanumerics == 46 bytes.
        assert_eq!(b.len(), MIME_BOUNDARY_LEN);
        assert_eq!(MIME_BOUNDARY_LEN, 46);
        assert!(b[..MIME_BOUNDARY_DASHES].iter().all(|&c| c == b'-'));
        assert!(b[MIME_BOUNDARY_DASHES..]
            .iter()
            .all(u8::is_ascii_alphanumeric));
        // Fresh boundaries are randomized (overwhelmingly unlikely to collide).
        let mime2 = Mime::new().unwrap();
        assert_ne!(mime.boundary_str(), mime2.boundary_str());
    }

    // --- multipart body framing (byte-exact) ---------------------------------

    #[test]
    fn simple_form_field_byte_exact() {
        let mut mime = Mime::with_boundary(b"BOUNDARY");
        mime.addpart()
            .set_name(Some(b"field".as_slice()))
            .unwrap()
            .set_data(b"value")
            .unwrap();
        let body = form_body(mime);
        let expected = [
            b"--BOUNDARY\r\n".as_slice(),
            b"Content-Disposition: form-data; name=\"field\"\r\n",
            b"\r\n",
            b"value",
            b"\r\n--BOUNDARY--\r\n",
        ]
        .concat();
        assert_eq!(body, expected);
    }

    #[test]
    fn two_form_fields_byte_exact() {
        let mut mime = Mime::with_boundary(b"BOUNDARY");
        mime.addpart()
            .set_name(Some(b"a".as_slice()))
            .unwrap()
            .set_data(b"1")
            .unwrap();
        mime.addpart()
            .set_name(Some(b"b".as_slice()))
            .unwrap()
            .set_data(b"2")
            .unwrap();
        let body = form_body(mime);
        let expected = [
            b"--BOUNDARY\r\n".as_slice(),
            b"Content-Disposition: form-data; name=\"a\"\r\n",
            b"\r\n",
            b"1",
            b"\r\n--BOUNDARY\r\n",
            b"Content-Disposition: form-data; name=\"b\"\r\n",
            b"\r\n",
            b"2",
            b"\r\n--BOUNDARY--\r\n",
        ]
        .concat();
        assert_eq!(body, expected);
    }

    #[test]
    fn zero_part_body_byte_exact() {
        // An empty multipart is just the closing delimiter.
        let mime = Mime::with_boundary(b"BOUNDARY");
        let body = form_body(mime);
        assert_eq!(body, b"--BOUNDARY--\r\n".to_vec());
    }

    #[test]
    fn file_upload_part_byte_exact() {
        // A part with name + filename + explicit type emits Content-Disposition
        // then Content-Type, then the raw content.
        let mut mime = Mime::with_boundary(b"BOUNDARY");
        let p = mime.addpart();
        p.set_name(Some(b"upload".as_slice())).unwrap();
        p.set_filename(Some(b"photo.png".as_slice())).unwrap();
        p.set_type(Some(b"image/png".as_slice())).unwrap();
        p.set_data(b"\x89PNG").unwrap();
        let body = form_body(mime);
        let expected = [
            b"--BOUNDARY\r\n".as_slice(),
            b"Content-Disposition: form-data; name=\"upload\"; filename=\"photo.png\"\r\n",
            b"Content-Type: image/png\r\n",
            b"\r\n",
            b"\x89PNG",
            b"\r\n--BOUNDARY--\r\n",
        ]
        .concat();
        assert_eq!(body, expected);
    }

    #[test]
    fn base64_encoded_part_byte_exact() {
        let mut mime = Mime::with_boundary(b"BOUNDARY");
        let p = mime.addpart();
        p.set_name(Some(b"f".as_slice())).unwrap();
        p.set_data(b"Hello, World!").unwrap();
        p.set_encoding(MimeEncoding::Base64).unwrap();
        let body = form_body(mime);
        let expected = [
            b"--BOUNDARY\r\n".as_slice(),
            b"Content-Disposition: form-data; name=\"f\"\r\n",
            b"Content-Transfer-Encoding: base64\r\n",
            b"\r\n",
            b"SGVsbG8sIFdvcmxkIQ==",
            b"\r\n--BOUNDARY--\r\n",
        ]
        .concat();
        assert_eq!(body, expected);
    }

    #[test]
    fn disposition_escapes_quotes_in_form_mode() {
        let mut mime = Mime::with_boundary(b"BOUNDARY");
        mime.addpart()
            .set_name(Some(b"a\"b".as_slice()))
            .unwrap()
            .set_data(b"v")
            .unwrap();
        let body = form_body(mime);
        assert!(contains(&body, b"name=\"a%22b\""));
    }

    // --- header-preparation rules -------------------------------------------

    #[test]
    fn text_plain_dropped_for_mail_with_filename() {
        // For mail, a *derived* text/plain type is suppressed entirely.
        let mut part = MimePart::new();
        part.set_filename(Some(b"notes.txt".as_slice())).unwrap();
        part.set_data(b"hello").unwrap();
        part.prepare_headers(None, None, MimeStrategy::Mail, false)
            .unwrap();
        assert_eq!(
            part.curl_headers().to_vec(),
            vec![b"Content-Disposition: attachment; filename=\"notes.txt\"".to_vec()]
        );
    }

    #[test]
    fn text_plain_kept_for_form_with_filename() {
        // For an HTTP form part that *has* a filename, the derived text/plain is
        // kept (curl only drops it for mail or when there is no filename).
        let mut part = MimePart::new();
        part.set_name(Some(b"f".as_slice())).unwrap();
        part.set_filename(Some(b"notes.txt".as_slice())).unwrap();
        part.set_data(b"hello").unwrap();
        part.prepare_headers(None, Some(b"form-data"), MimeStrategy::Form, false)
            .unwrap();
        assert_eq!(
            part.curl_headers().to_vec(),
            vec![
                b"Content-Disposition: form-data; name=\"f\"; filename=\"notes.txt\"".to_vec(),
                b"Content-Type: text/plain".to_vec(),
            ]
        );
    }

    #[test]
    fn mail_part_defaults_to_8bit_cte() {
        // A typed, non-multipart mail part with no encoder defaults to an 8bit
        // Content-Transfer-Encoding.
        let mut part = MimePart::new();
        part.set_type(Some(b"application/json".as_slice())).unwrap();
        part.set_data(b"{}").unwrap();
        part.prepare_headers(None, None, MimeStrategy::Mail, false)
            .unwrap();
        let hdrs = part.curl_headers().to_vec();
        assert!(hdrs.contains(&b"Content-Type: application/json".to_vec()));
        assert!(hdrs.contains(&b"Content-Transfer-Encoding: 8bit".to_vec()));
    }

    // --- size computation invariant -----------------------------------------

    #[test]
    fn compute_size_matches_serialized_length() {
        let make = || {
            let mut mime = Mime::with_boundary(b"X-BOUNDARY-X");
            mime.addpart()
                .set_name(Some(b"alpha".as_slice()))
                .unwrap()
                .set_data(b"first value")
                .unwrap();
            mime.addpart()
                .set_name(Some(b"beta".as_slice()))
                .unwrap()
                .set_data(b"second")
                .unwrap();
            mime
        };
        let mut sized = make().into_top_part();
        sized
            .prepare_headers(
                Some(b"multipart/form-data"),
                None,
                MimeStrategy::Form,
                false,
            )
            .unwrap();
        let size = sized.compute_size();

        let mut rendered = make().into_top_part();
        rendered
            .prepare_headers(
                Some(b"multipart/form-data"),
                None,
                MimeStrategy::Form,
                false,
            )
            .unwrap();
        let bytes = rendered.to_bytes().unwrap();

        assert!(size >= 0);
        assert_eq!(size as usize, bytes.len());
    }

    #[test]
    fn compute_size_matches_with_base64_encoder() {
        let make = || {
            let mut mime = Mime::with_boundary(b"BB");
            let p = mime.addpart();
            p.set_name(Some(b"data".as_slice())).unwrap();
            p.set_data(&[b'A'; 100]).unwrap();
            p.set_encoding(MimeEncoding::Base64).unwrap();
            mime
        };
        let mut sized = make().into_top_part();
        sized
            .prepare_headers(
                Some(b"multipart/form-data"),
                None,
                MimeStrategy::Form,
                false,
            )
            .unwrap();
        let size = sized.compute_size();

        let mut rendered = make().into_top_part();
        rendered
            .prepare_headers(
                Some(b"multipart/form-data"),
                None,
                MimeStrategy::Form,
                false,
            )
            .unwrap();
        let bytes = rendered.to_bytes().unwrap();

        assert!(size >= 0);
        assert_eq!(size as usize, bytes.len());
    }

    // --- legacy form API -----------------------------------------------------

    #[test]
    fn formcode_values_match_curl() {
        // CURLFORMcode is a 0-based C enum: OK == 0.
        assert_eq!(FormCode::Ok.as_i32(), 0);
        assert_eq!(FormCode::Memory.as_i32(), 1);
        assert_eq!(FormCode::OptionTwice.as_i32(), 2);
        assert_eq!(FormCode::Null.as_i32(), 3);
        assert_eq!(FormCode::UnknownOption.as_i32(), 4);
        assert_eq!(FormCode::Incomplete.as_i32(), 5);
        assert_eq!(FormCode::IllegalArray.as_i32(), 6);
        assert_eq!(FormCode::Disabled.as_i32(), 7);
    }

    #[test]
    fn legacy_form_data_matches_direct_mime() {
        // A legacy CONTENTS field must serialize identically to the equivalent
        // modern MIME part.
        let mut form = FormData::new();
        let code = form.add(FormSection {
            name: b"field".to_vec(),
            content: FormContent::Data(b"value".to_vec()),
            contenttype: None,
            headers: None,
            showfilename: None,
        });
        assert_eq!(code, FormCode::Ok);
        let mut mime = form.to_mime().unwrap();
        mime.boundary = b"BOUNDARY".to_vec();
        let body = form_body(mime);
        let expected = [
            b"--BOUNDARY\r\n".as_slice(),
            b"Content-Disposition: form-data; name=\"field\"\r\n",
            b"\r\n",
            b"value",
            b"\r\n--BOUNDARY--\r\n",
        ]
        .concat();
        assert_eq!(body, expected);
    }

    #[test]
    fn legacy_single_file_byte_exact() {
        let dir = unique_dir();
        let path = write_file(&dir, "leg.txt", b"FILEDATA");

        let mut form = FormData::new();
        let code = form.add(FormSection {
            name: b"document".to_vec(),
            content: FormContent::Files(vec![FormFile {
                filename: path.into_bytes(),
                contenttype: None,
            }]),
            contenttype: None,
            headers: None,
            showfilename: None,
        });
        assert_eq!(code, FormCode::Ok);

        let mut mime = form.to_mime().unwrap();
        mime.boundary = b"BOUNDARY".to_vec();
        let body = form_body(mime);
        let expected = [
            b"--BOUNDARY\r\n".as_slice(),
            b"Content-Disposition: form-data; name=\"document\"; filename=\"leg.txt\"\r\n",
            b"Content-Type: text/plain\r\n",
            b"\r\n",
            b"FILEDATA",
            b"\r\n--BOUNDARY--\r\n",
        ]
        .concat();
        assert_eq!(body, expected);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_multi_file_byte_exact() {
        // A multi-file field becomes a nested multipart/mixed part whose name is
        // on the wrapper and whose files are attachment subparts.
        let dir = unique_dir();
        let p1 = write_file(&dir, "leg1.txt", b"AAA");
        let p2 = write_file(&dir, "leg2.txt", b"BBB");

        let mut form = FormData::new();
        let code = form.add(FormSection {
            name: b"docs".to_vec(),
            content: FormContent::Files(vec![
                FormFile {
                    filename: p1.into_bytes(),
                    contenttype: None,
                },
                FormFile {
                    filename: p2.into_bytes(),
                    contenttype: None,
                },
            ]),
            contenttype: None,
            headers: None,
            showfilename: None,
        });
        assert_eq!(code, FormCode::Ok);

        let mut mime = form.to_mime().unwrap();
        mime.boundary = b"OUTER".to_vec();
        mime.parts[0]
            .subparts_mut()
            .expect("multi-file section is a nested multipart")
            .boundary = b"INNER".to_vec();
        let body = form_body(mime);
        let expected = [
            b"--OUTER\r\n".as_slice(),
            b"Content-Disposition: form-data; name=\"docs\"\r\n",
            b"Content-Type: multipart/mixed; boundary=INNER\r\n",
            b"\r\n",
            b"--INNER\r\n",
            b"Content-Disposition: attachment; filename=\"leg1.txt\"\r\n",
            b"Content-Type: text/plain\r\n",
            b"\r\n",
            b"AAA",
            b"\r\n--INNER\r\n",
            b"Content-Disposition: attachment; filename=\"leg2.txt\"\r\n",
            b"Content-Type: text/plain\r\n",
            b"\r\n",
            b"BBB",
            b"\r\n--INNER--\r\n",
            b"\r\n--OUTER--\r\n",
        ]
        .concat();
        assert_eq!(body, expected);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn form_get_includes_top_content_type_header() {
        // curl_formget emits the top Content-Type header and the blank line, so
        // the random boundary must be checked structurally.
        let mut form = FormData::new();
        form.add(FormSection {
            name: b"k".to_vec(),
            content: FormContent::Data(b"v".to_vec()),
            contenttype: None,
            headers: None,
            showfilename: None,
        });
        let out = form.get().unwrap();

        assert!(out.starts_with(b"Content-Type: multipart/form-data; boundary="));
        let hdr_end = out.windows(2).position(|w| w == b"\r\n").unwrap();
        let prefix = b"Content-Type: multipart/form-data; boundary=";
        let boundary = &out[prefix.len()..hdr_end];
        assert_eq!(boundary.len(), MIME_BOUNDARY_LEN);
        assert!(boundary[..MIME_BOUNDARY_DASHES].iter().all(|&c| c == b'-'));
        // Blank line separates the header from the body, then the delimiter and
        // the field disposition appear.
        assert!(contains(&out, b"\r\n\r\n--"));
        assert!(contains(
            &out,
            b"Content-Disposition: form-data; name=\"k\""
        ));
        assert!(contains(&out, b"\r\nv\r\n"));
    }

    // --- deterministic teardown (Miri leak/UB check) -------------------------

    #[test]
    fn drop_frees_nested_tree() {
        // Build a nested tree (a part owning a subpart multipart) and drop it;
        // Miri validates there is no leak or undefined behavior.
        let mut mime = Mime::new().unwrap();
        let p = mime.addpart();
        p.set_name(Some(b"a".as_slice())).unwrap();
        let mut sub = Mime::new().unwrap();
        sub.addpart()
            .set_name(Some(b"b".as_slice()))
            .unwrap()
            .set_data(b"x")
            .unwrap();
        p.set_subparts(Some(sub)).unwrap();
        drop(mime);
    }
}
