// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_formparse.c (-F multipart/form via curl_mime).

//! # `formparse` — the `-F` / `--form` multipart parser
//!
//! Faithful, idiomatic-Rust rewrite of curl 8.19.0-DEV's `src/tool_formparse.c`
//! (893 lines) and its header `src/tool_formparse.h`. This module implements the
//! CLI side of curl's `multipart/form-data` support: it parses a single
//! `-F`/`--form` (or `--form-string`) command-line argument into the CLI's MIME
//! tree ([`ToolMime`], owned by [`OperationConfig`]), and later translates that
//! tree into a `curl-rs-lib` [`Mime`] object that the transfer layer sends.
//!
//! ## The `-F` mini-language
//!
//! [`formparse`] reproduces curl's exact `name=content` grammar:
//!
//! * `name=content` — a literal data part.
//! * `name=@filename` — a file **upload** part (contents read at transfer time).
//!   Several files may be attached at once: `name=@f1,f2,f3`.
//! * `name=<filename` — the file **contents** used as the field data (not an
//!   upload; no remote filename by default).
//! * `@-` / `<-` — read from standard input.
//! * `name=(` … `name=)` — begin / end a nested multipart group.
//! * Semicolon parameters (terminator-aware, [`get_param_part`]):
//!   `;type=<content-type>` (with optional `;charset=`), `;filename=<name>`,
//!   `;headers=@headerfile` or `;headers="Header: value"`, and
//!   `;encoder=<name>` (`base64`, `quoted-printable`, `8bit`, `7bit`, `binary`).
//! * Double-quoted values honor `\"` and `\\` escapes.
//! * With `--form-string` (`is_literal_data == true`), the value is **always**
//!   literal — `@`, `<`, `(`, and `;` lose their special meaning.
//!
//! Malformed input reproduces curl's exact `warnf` diagnostics and returns the
//! corresponding [`CurlCode`].
//!
//! ## Conversion to libcurl MIME
//!
//! [`tool2curlmime`] walks the parsed [`ToolMime`] tree and builds the equivalent
//! `curl-rs-lib` [`Mime`] object using its safe builder API (the analogue of
//! curl's `curl_mime_*` C functions). The produced object is attached to the easy
//! handle by the setopt/operate layer.
//!
//! ## Safety
//!
//! This module contains **zero** `unsafe` code, satisfying the workspace's unsafe
//! containment policy (AAP §0.7.2).

// The full operation-dispatch wiring that drives `-F` is layered on in a later
// checkpoint (AAP §0.7.3): `main.rs` installs [`form_parser_hook`] as the
// [`crate::args::FormParserHook`], and `operate.rs`/`setopt.rs` call
// [`tool2curlmime`] to materialize the body. Until those call sites exist this
// module has no in-crate caller, so — matching the established convention of the
// sibling CLI modules (`args`, `xattr`, `getpass`, `terminal`) — `dead_code` is
// allowed here to keep the strict CI `-D warnings` gate green.
#![allow(dead_code)]

use std::io::Read;

use curl_rs_lib::mime::{Mime, MimeReadCallback, ReadOutcome};
use curl_rs_lib::{CurlCode, Easy};

use crate::args::{warnf, Diag, OperationConfig, ParameterError, ToolMime, ToolMimeKind};

// ===========================================================================
// Diagnostics
// ===========================================================================
//
// curl's `formparse`/`get_param_part` emit `warnf(...)` messages that reference a
// process-global config for the `--silent` gate. The Rust `-F` parser hook
// (`crate::args::FormParserHook`) receives only `&mut OperationConfig` — the
// `silent`/`showerror` flags live on `GlobalConfig`, which is not threaded in —
// so warnings are emitted with a default [`Diag`]. The *message text* (the
// behavioral-parity contract, AAP §0.7.3) is reproduced verbatim; the `--silent`
// gate is applied at the outer diagnostic layer where a `Diag` is available.

/// Emit a `Warning:`-prefixed diagnostic with curl's exact message text,
/// delegating to [`crate::args::warnf`] (port of `warnf`, `tool_msgs.c`).
#[inline]
fn warn(msg: &str) {
    warnf(Diag::default(), msg);
}

// ===========================================================================
// Character classes (mirror the curl `ISBLANK` / `ISSPACE` / `ISNEWLINE`
// classifiers and the content-type `strcspn` delimiter set)
// ===========================================================================

/// `ISBLANK`: a space or horizontal tab.
#[inline]
fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// `ISSPACE`: space, tab, newline, carriage return, vertical tab, or form feed.
#[inline]
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// `ISNEWLINE`: a carriage return or line feed.
#[inline]
fn is_newline(c: u8) -> bool {
    c == b'\r' || c == b'\n'
}

/// The content-type terminator set used by `strcspn(p, "()<>@,;:\\\"[]?=\r\n ")`
/// in `get_param_part`: a `;type=` value runs up to (but not including) the first
/// of these characters.
#[inline]
fn is_ct_delim(c: u8) -> bool {
    matches!(
        c,
        b'(' | b')'
            | b'<'
            | b'>'
            | b'@'
            | b','
            | b';'
            | b':'
            | b'\\'
            | b'"'
            | b'['
            | b']'
            | b'?'
            | b'='
            | b'\r'
            | b'\n'
            | b' '
    )
}

/// Checked `usize` → `i64` (`curl_off_t`) conversion, the safe analogue of curl's
/// `uztoso` helper (which masked off the sign bit under a `DEBUGASSERT`). A value
/// that cannot be represented saturates at [`i64::MAX`]; in practice CLI form data
/// never approaches that bound.
#[inline]
fn uztoso(uznum: usize) -> i64 {
    i64::try_from(uznum).unwrap_or(i64::MAX)
}

// ===========================================================================
// CLI-side mime-tree constructors (mirror tool_mime_new* in tool_formparse.c)
// ===========================================================================
//
// The C intrusive `parent`/`prev`/`subparts` pointer links are replaced by
// ownership: children live in `ToolMime::subparts` (a `Vec<ToolMime>` in forward
// insertion order). These constructors therefore return a *detached* node; the
// caller splices it into the tree (see the navigation helpers in `formparse`).

/// Create an interior multipart node (`tool_mime_new_parts` → `TOOLMIME_PARTS`).
fn tool_mime_new_parts() -> ToolMime {
    ToolMime {
        kind: ToolMimeKind::Parts,
        ..Default::default()
    }
}

/// Create an inline-data node (`tool_mime_new_data` → `TOOLMIME_DATA`). The data
/// is copied, exactly like curl's `curlx_strdup(mime_data)`.
fn tool_mime_new_data(mime_data: &str) -> ToolMime {
    ToolMime {
        kind: ToolMimeKind::Data,
        data: Some(mime_data.to_string()),
        ..Default::default()
    }
}

/// Create a file-backed node (`tool_mime_new_filedata`).
///
/// For an ordinary path this yields a [`ToolMimeKind::File`] (a remote upload,
/// `isremotefile == true`) or [`ToolMimeKind::FileData`] (file contents inlined as
/// data, `isremotefile == false`) node whose `data` holds the path. The special
/// path `"-"` selects standard input via [`tool_mime_new_stdin`].
///
/// Returns the node paired with a [`CurlCode`] read outcome (`Ok` normally,
/// `ReadError` if buffering stdin failed) — the analogue of curl's `*errcode`
/// out-parameter. Node creation itself never fails in the Rust port (there is no
/// manual allocation to run out of memory on).
fn tool_mime_new_filedata(filename: &str, isremotefile: bool) -> (ToolMime, CurlCode) {
    if filename != "-" {
        // A normal file. The contents are read from `data` at transfer time.
        let kind = if isremotefile {
            ToolMimeKind::File
        } else {
            ToolMimeKind::FileData
        };
        let m = ToolMime {
            kind,
            data: Some(filename.to_string()),
            ..Default::default()
        };
        (m, CurlCode::Ok)
    } else {
        // Standard input.
        tool_mime_new_stdin(isremotefile)
    }
}

/// Create a standard-input node (`tool_mime_new_stdin`).
///
/// curl buffers stdin eagerly unless it is a seekable regular file (which it then
/// reads on demand). Detecting a regular file requires `fstat(0)`, which cannot be
/// done from safe Rust; since this module forbids `unsafe`, stdin is **always**
/// buffered here. Buffering preserves the known content size — important for
/// `Content-Length` parity — and matches curl's non-regular-file branch, which is
/// the common case (`curl -F name=@- < file` / piped input). The captured bytes
/// are stored on the node as a `String`; text form data (the overwhelmingly common
/// case) round-trips exactly, and `size` is set to the stored byte length so the
/// node stays internally consistent.
fn tool_mime_new_stdin(isremotefile: bool) -> (ToolMime, CurlCode) {
    let kind = if isremotefile {
        ToolMimeKind::Stdin
    } else {
        ToolMimeKind::StdinData
    };

    let mut buf: Vec<u8> = Vec::new();
    // Read whatever is available. On error, `read_to_end` still leaves the bytes
    // consumed before the failure in `buf`; curl's `file2memory` behaves the same
    // (returning `PARAM_READ_ERROR` while retaining partial data), and `formparse`
    // decides — based on whether any bytes were read — whether to fail now or defer.
    let outcome = match std::io::stdin().lock().read_to_end(&mut buf) {
        Ok(_) => CurlCode::Ok,
        Err(_) => CurlCode::ReadError,
    };

    let data = String::from_utf8_lossy(&buf).into_owned();
    let size = uztoso(data.len());
    let m = ToolMime {
        kind,
        data: Some(data),
        origin: 0,
        size,
        curpos: 0,
        ..Default::default()
    };
    (m, outcome)
}

// ===========================================================================
// Standard-input read/seek callback (mirror tool_mime_stdin_read/seek)
// ===========================================================================

// POSIX `whence` values. These are stable on every supported target (Linux and
// macOS), so hard-coding them avoids depending on `libc` merely for constants.
const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;
const SEEK_END: i32 = 2;

/// A [`MimeReadCallback`] backing a [`ToolMimeKind::Stdin`] / [`ToolMimeKind::StdinData`]
/// part, reproducing curl's `tool_mime_stdin_read` / `tool_mime_stdin_seek`.
///
/// When `data` is present the reader serves from that in-memory buffer (curl's
/// buffered-stdin path); when it is `None` (the delayed read-error path, where
/// `formparse` set `size == -1`) it reads live from the process's standard input.
struct StdinMimeReader {
    /// Buffered stdin bytes, or `None` to read live from standard input.
    data: Option<Vec<u8>>,
    /// Known byte size, or `-1` when unknown.
    size: i64,
    /// Read origin offset within the underlying stream (unused for buffered data).
    origin: i64,
    /// Current read position.
    curpos: i64,
}

impl MimeReadCallback for StdinMimeReader {
    fn read(&mut self, buf: &mut [u8]) -> ReadOutcome {
        let mut nitems = buf.len();

        // Cap the request to the bytes remaining when the size is known.
        if self.size >= 0 {
            if self.curpos >= self.size {
                return ReadOutcome::Bytes(0); // at EOF
            }
            let bytesleft = self.size - self.curpos;
            if uztoso(nitems) > bytesleft {
                nitems = bytesleft as usize;
            }
        }

        if nitems == 0 {
            return ReadOutcome::Bytes(0);
        }

        if let Some(ref d) = self.data {
            // Serve from the in-memory buffer.
            let start = self.curpos as usize;
            let end = start.saturating_add(nitems).min(d.len());
            let n = end.saturating_sub(start);
            buf[..n].copy_from_slice(&d[start..end]);
            self.curpos += uztoso(n);
            ReadOutcome::Bytes(n)
        } else {
            // Read live from standard input. A read error maps to
            // `CURL_READFUNC_ABORT`, exactly like curl on `ferror(stdin)`.
            match std::io::stdin().lock().read(&mut buf[..nitems]) {
                Ok(n) => {
                    self.curpos += uztoso(n);
                    ReadOutcome::Bytes(n)
                }
                Err(_) => ReadOutcome::Abort,
            }
        }
    }

    fn seek(&mut self, offset: i64, whence: i32) -> bool {
        let mut off = offset;
        match whence {
            SEEK_CUR => off += self.curpos,
            SEEK_END => off += self.size,
            _ => {} // SEEK_SET
        }
        if off < 0 {
            return false; // CURL_SEEKFUNC_CANTSEEK
        }
        if self.data.is_none() {
            // curl would `fseek(stdin, off + origin, SEEK_SET)` here; seeking live
            // standard input is not possible from safe Rust, so report that the
            // source cannot seek (the transfer layer already tolerates this for a
            // callback part). Buffered data — the common case — seeks fine below.
            let _ = self.origin;
            return false;
        }
        self.curpos = off;
        true // CURL_SEEKFUNC_OK
    }
}

// ===========================================================================
// Field-header file reader (mirror read_field_headers)
// ===========================================================================

/// Split `content` into lines on `\n`, excluding the newline byte. A trailing
/// line without a terminating newline is included; trailing CR bytes are left for
/// the caller to trim (matching curl's `my_get_line` + trailing-whitespace strip).
fn split_lines(content: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    for (i, &b) in content.iter().enumerate() {
        if b == b'\n' {
            lines.push(&content[start..i]);
            start = i + 1;
        }
    }
    if start < content.len() {
        lines.push(&content[start..]);
    }
    lines
}

/// Port of `read_field_headers`: read RFC-822-style header lines from `path` and
/// append them to `headers`, honoring `#` comments and leading-space folding.
///
/// A file that cannot be opened produces curl's `Cannot read from ...` warning and
/// leaves `headers` unchanged — curl warns and continues here; only an
/// out-of-memory condition (impossible in the Rust port) was ever a hard error.
fn read_field_headers(path: &str, headers: &mut Vec<String>) {
    let content = match std::fs::read(path) {
        Ok(c) => c,
        Err(e) => {
            warn(&format!("Cannot read from {path}: {e}"));
            return;
        }
    };

    for raw in split_lines(&content) {
        // The comment / folded classification uses the first raw byte, before any
        // trailing-whitespace trimming.
        if raw.first() == Some(&b'#') {
            continue; // comment line
        }
        let folded = raw.first() == Some(&b' '); // continuation of the previous line

        // Trim trailing CRLFs and blanks.
        let mut len = raw.len();
        while len > 0 && (is_newline(raw[len - 1]) || is_blank(raw[len - 1])) {
            len -= 1;
        }
        if len == 0 {
            continue;
        }
        let line = String::from_utf8_lossy(&raw[..len]).into_owned();

        if folded {
            if let Some(last) = headers.last_mut() {
                // Append this continuation — including its leading space — onto the
                // previous header line, exactly like curl's fold handling.
                last.push_str(&line);
                continue;
            }
            // No previous header to fold into: add it as its own line (curl's
            // `else` branch, which reaches `slist_append`).
        }
        headers.push(line);
    }
}

// ===========================================================================
// The `-F` mini-language scanner (mirror get_param_word / get_param_part)
// ===========================================================================

/// Remove trailing `ISBLANK` (space / tab) bytes from a word — the strip curl
/// applies to an *unquoted* [`get_param_word`] result.
fn strip_trailing_blank(mut s: String) -> String {
    while matches!(s.as_bytes().last(), Some(&b) if is_blank(b)) {
        s.pop();
    }
    s
}

/// Remove trailing `ISSPACE` bytes from a word — the strip curl applies to an
/// *unquoted* `;encoder=` value (which uses `ISSPACE`, not `ISBLANK`).
fn strip_trailing_space(mut s: String) -> String {
    while matches!(s.as_bytes().last(), Some(&b) if is_space(b)) {
        s.pop();
    }
    s
}

/// The parameters extracted from one `-F` field segment by [`Cursor::get_param_part`].
struct ParamPart {
    /// The primary data word: the field content, a filename, or the `(` marker.
    data: String,
    /// `;type=` content type (with any `;charset=` continuation), if present.
    mime_type: Option<String>,
    /// `;filename=` override, if present and permitted here.
    filename: Option<String>,
    /// `;encoder=` name, if present and permitted here.
    encoder: Option<String>,
    /// `;headers=` user headers (from `@file` and/or inline `"Header: value"`).
    headers: Vec<String>,
    /// The terminating separator byte: `0` at end of input, otherwise `endchar`.
    sep: u8,
}

/// A byte cursor over the value portion (everything after the first `=`) of a
/// `-F` argument. Parsing is non-mutating — unlike curl, which null-terminates and
/// unescapes the argument buffer in place — so extracted words are returned as
/// owned [`String`]s sliced at ASCII delimiter boundaries.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    /// The byte at the cursor, or `None` at end of input.
    #[inline]
    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// The current separator byte, `0` at end of input (curl's `sep = *p`).
    #[inline]
    fn sep(&self) -> u8 {
        self.buf.get(self.pos).copied().unwrap_or(0)
    }

    /// Advance the cursor past any run of `ISBLANK` bytes.
    #[inline]
    fn skip_blanks(&mut self) {
        while matches!(self.peek(), Some(c) if is_blank(c)) {
            self.pos += 1;
        }
    }

    /// True if the remaining input begins with `prefix` (curl's `checkprefix`).
    fn starts_with(&self, prefix: &str) -> bool {
        self.buf[self.pos..].starts_with(prefix.as_bytes())
    }

    /// Port of `get_param_word`. Reads one word at the cursor, advancing to the
    /// terminator (`;`, `endchar`, or end of input). Returns the word (unescaped
    /// when quoted) and whether it was double-quoted. `endchar == 0` means "no
    /// extra terminator" (curl's `'\0'`).
    fn get_param_word(&mut self, endchar: u8) -> (String, bool) {
        let start = self.pos;
        if self.buf.get(start) == Some(&b'"') {
            // Quoted word: unescape `\"` and `\\`, stop at the closing quote.
            let mut out: Vec<u8> = Vec::new();
            let mut i = start + 1;
            while i < self.buf.len() {
                let c = self.buf[i];
                if c == b'\\' {
                    if let Some(&n) = self.buf.get(i + 1) {
                        if n == b'\\' || n == b'"' {
                            out.push(n); // drop the escaping backslash
                            i += 2;
                            continue;
                        }
                    }
                }
                if c == b'"' {
                    // Closing quote: skip it, then scan (and warn about) trailing data.
                    i += 1;
                    let mut trailing_data = false;
                    while i < self.buf.len() {
                        let t = self.buf[i];
                        if t == b';' || (endchar != 0 && t == endchar) {
                            break;
                        }
                        if !is_space(t) {
                            trailing_data = true;
                        }
                        i += 1;
                    }
                    if trailing_data {
                        warn("Trailing data after quoted form parameter");
                    }
                    self.pos = i;
                    return (String::from_utf8_lossy(&out).into_owned(), true);
                }
                out.push(c);
                i += 1;
            }
            // Unterminated quote: treat as a non-quoted word from `start`, so the
            // leading '"' becomes part of the word (curl resets `ptr = word_begin`).
        }

        let mut i = start;
        while i < self.buf.len() {
            let c = self.buf[i];
            if c == b';' || (endchar != 0 && c == endchar) {
                break;
            }
            i += 1;
        }
        self.pos = i;
        (
            String::from_utf8_lossy(&self.buf[start..i]).into_owned(),
            false,
        )
    }

    /// Finalize the content-type byte range into `mime_type` and clear `endct`,
    /// the analogue of curl's `if(endct) { *endct = '\0'; endct = NULL; }`.
    fn finalize_ct(
        &self,
        type_start: Option<usize>,
        endct: &mut Option<usize>,
        mime_type: &mut Option<String>,
    ) {
        if let Some(e) = endct.take() {
            if let Some(s) = type_start {
                *mime_type = Some(String::from_utf8_lossy(&self.buf[s..e]).into_owned());
            }
        }
    }

    /// Port of `get_param_part`. Parses the data word plus any trailing
    /// `;`-separated parameters (`type=`, `filename=`, `headers=`, `encoder=`),
    /// stopping at `endchar` or end of input. `allow_*` gate which parameters are
    /// permitted in this position; a present-but-disallowed parameter reproduces
    /// curl's `Field ... not allowed here` warning and is dropped.
    fn get_param_part(
        &mut self,
        endchar: u8,
        allow_type: bool,
        allow_filename: bool,
        allow_encoder: bool,
        allow_headers: bool,
    ) -> ParamPart {
        self.skip_blanks();
        let (data_word, data_quoted) = self.get_param_word(endchar);
        let data = if data_quoted {
            data_word
        } else {
            strip_trailing_blank(data_word)
        };

        let mut sep = self.sep();

        // Content-type is tracked as a byte range [type_start, endct) so that a
        // `;charset=` continuation can extend it verbatim, mirroring the way curl
        // grows the type in place.
        let mut type_start: Option<usize> = None;
        let mut endct: Option<usize> = None;
        let mut mime_type: Option<String> = None;
        let mut filename: Option<String> = None;
        let mut encoder: Option<String> = None;
        let mut headers: Vec<String> = Vec::new();

        while sep == b';' {
            // Advance past ';' and any following blanks (curl's
            // `while(p++ && ISBLANK(*p));`).
            self.pos += 1;
            self.skip_blanks();

            if endct.is_none() && self.starts_with("type=") {
                self.pos += 5;
                self.skip_blanks();
                type_start = Some(self.pos);
                while matches!(self.peek(), Some(c) if !is_ct_delim(c)) {
                    self.pos += 1;
                }
                endct = Some(self.pos);
                sep = self.sep();
            } else if self.starts_with("filename=") {
                self.finalize_ct(type_start, &mut endct, &mut mime_type);
                self.pos += 9;
                self.skip_blanks();
                let (w, q) = self.get_param_word(endchar);
                filename = Some(if q { w } else { strip_trailing_blank(w) });
                sep = self.sep();
            } else if self.starts_with("headers=") {
                self.finalize_ct(type_start, &mut endct, &mut mime_type);
                self.pos += 8;
                if matches!(self.peek(), Some(b'@') | Some(b'<')) {
                    // `;headers=@file` / `;headers=<file`: read from a file.
                    // curl's `do { p++; } while(ISBLANK(*p));` skips the marker
                    // then any blanks.
                    self.pos += 1;
                    self.skip_blanks();
                    let (hdrfile, q) = self.get_param_word(endchar);
                    let hdrfile = if q {
                        hdrfile
                    } else {
                        strip_trailing_blank(hdrfile)
                    };
                    sep = self.sep();
                    read_field_headers(&hdrfile, &mut headers);
                } else {
                    // `;headers="Header: value"`: a single inline header.
                    self.skip_blanks();
                    let (hdr, q) = self.get_param_word(endchar);
                    let hdr = if q { hdr } else { strip_trailing_blank(hdr) };
                    sep = self.sep();
                    headers.push(hdr);
                }
            } else if self.starts_with("encoder=") {
                self.finalize_ct(type_start, &mut endct, &mut mime_type);
                self.pos += 8;
                self.skip_blanks();
                let (w, q) = self.get_param_word(endchar);
                // The encoder value strips trailing ISSPACE (not ISBLANK).
                encoder = Some(if q { w } else { strip_trailing_space(w) });
                sep = self.sep();
            } else if endct.is_some() {
                // Continuation of the content type (e.g. `;charset=utf-8`): grow
                // `endct` to the last non-blank byte before the next terminator.
                let mut e = self.pos;
                while let Some(c) = self.peek() {
                    if c == b';' || (endchar != 0 && c == endchar) {
                        break;
                    }
                    if !is_blank(c) {
                        e = self.pos + 1;
                    }
                    self.pos += 1;
                }
                endct = Some(e);
                sep = self.sep();
            } else {
                // Unknown prefix: consume the block and warn if it was non-empty.
                let (unknown, _q) = self.get_param_word(endchar);
                sep = self.sep();
                if !unknown.is_empty() {
                    warn(&format!("skip unknown form field: {unknown}"));
                }
            }
        }

        // Terminate a still-open content type.
        self.finalize_ct(type_start, &mut endct, &mut mime_type);

        // Reproduce curl's "not allowed here" gating for disallowed parameters.
        if !allow_type {
            if let Some(t) = mime_type.take() {
                warn(&format!("Field content type not allowed here: {t}"));
            }
        }
        if !allow_filename {
            if let Some(f) = filename.take() {
                warn(&format!("Field filename not allowed here: {f}"));
            }
        }
        if !allow_encoder {
            if let Some(e) = encoder.take() {
                warn(&format!("Field encoder not allowed here: {e}"));
            }
        }
        if !allow_headers {
            if let Some(h0) = headers.first() {
                warn(&format!("Field headers not allowed here: {h0}"));
                headers.clear();
            }
        }

        ParamPart {
            data,
            mime_type,
            filename,
            encoder,
            headers,
            sep,
        }
    }
}

// ===========================================================================
// Mime-tree navigation
// ===========================================================================
//
// curl threads the "current" node through an intrusive `parent`/`subparts`
// pointer graph. Here the tree is owned (`ToolMime::subparts: Vec<ToolMime>`) and
// the current node is addressed by an index path from the root
// (`OperationConfig::mimecurrent`): an empty path denotes the root, `[i]` its
// `i`-th child, `[i, j]` that child's `j`-th child, and so on.

/// Follow `OperationConfig::mimecurrent` from the root and return a mutable
/// reference to the current multipart node.
///
/// The path is cloned first (it is tiny — one entry per level of `-F name=(`
/// nesting) so the traversal borrows only `mimeroot`, keeping the borrow checker
/// happy while the caller mutates the returned node. The root is expected to have
/// been created by [`formparse`] before any navigation occurs.
fn current_node(config: &mut OperationConfig) -> &mut ToolMime {
    let path = config.mimecurrent.clone();
    let mut node = config
        .mimeroot
        .as_mut()
        .expect("mimeroot must be initialized before navigation");
    for idx in path {
        node = &mut node.subparts[idx];
    }
    node
}

// ===========================================================================
// formparse — the `-F` / `--form` entry point (mirror formparse)
// ===========================================================================

/// Parse one `-F`/`--form` argument (or `--form-string` when
/// `is_literal_data == true`) and splice the resulting part(s) into the MIME tree
/// held by `config` (`config.mimeroot` / `config.mimecurrent`). This is the
/// faithful Rust port of curl's `formparse`.
///
/// The grammar handled is `name=value`, where `value` may be:
///
/// * `(` — begin a nested multipart (the following `-F` fields join it until
///   `name=)` closes it);
/// * `)` (with no `name`) — end the current nested multipart;
/// * `@file[,file2,...]` — one or more file **uploads** (with `@-` reading stdin);
/// * `<file` — the file's **contents** used as the field data (`<-` reads stdin);
/// * anything else — literal inline data;
///
/// each optionally followed by `;`-separated `type=`, `filename=`, `headers=`, and
/// `encoder=` parameters (see [`Cursor::get_param_part`]). With `--form-string` the
/// value is taken verbatim — `(`, `)`, `@`, `<`, and `;` lose all special meaning.
///
/// # Errors
///
/// Returns [`CurlCode::BadFunctionArgument`] for malformed input (a missing `=`,
/// or `)` with no multipart open) and [`CurlCode::ReadError`] when reading standard
/// input fails after data has already been consumed — reproducing curl's exact
/// `warnf` diagnostics in every case. The CLI layer maps any error to
/// `PARAM_BAD_USE` via [`form_parser_hook`], matching `tool_getparam.c`.
pub fn formparse(
    input: &str,
    config: &mut OperationConfig,
    is_literal_data: bool,
) -> Result<(), CurlCode> {
    // Allocate the root multipart node the first time a `-F` field is seen.
    if config.mimeroot.is_none() {
        config.mimeroot = Some(tool_mime_new_parts());
        config.mimecurrent = Vec::new(); // empty path == the root node
    }

    // Split at the first '='. Everything before it (if any) is the field name.
    let eq = match input.find('=') {
        Some(i) => i,
        None => {
            warn("Illegally formatted input field");
            return Err(CurlCode::BadFunctionArgument);
        }
    };
    let name: Option<String> = if eq > 0 {
        Some(input[..eq].to_string())
    } else {
        None
    };
    let value = &input[eq + 1..];
    let vbytes = value.as_bytes();
    let first_byte = vbytes.first().copied();

    // ---- Branch A: `name=(` — start a nested multipart. ----
    if first_byte == Some(b'(') && !is_literal_data {
        let mut cursor = Cursor::new(vbytes);
        // Only `type=` and `headers=` are meaningful on a multipart opener.
        let pp = cursor.get_param_part(0, true, false, false, true);

        let mut part = tool_mime_new_parts();
        part.headers = pp.headers;
        if let Some(t) = pp.mime_type {
            part.mime_type = Some(t);
        }

        let cur = current_node(config);
        cur.subparts.push(part);
        let new_idx = cur.subparts.len() - 1;
        // Descend: the freshly created multipart becomes the current node.
        config.mimecurrent.push(new_idx);

        // The field name is applied to the new multipart.
        if let Some(nm) = name {
            current_node(config).name = Some(nm);
        }
        return Ok(());
    }

    // ---- Branch B: `)` with no name — end the current multipart. ----
    if name.is_none() && value == ")" && !is_literal_data {
        if config.mimecurrent.is_empty() {
            warn("no multipart to terminate");
            return Err(CurlCode::BadFunctionArgument);
        }
        config.mimecurrent.pop(); // ascend to the parent
        return Ok(());
    }

    // ---- Branch C: `@file[,file2,...]` — one or more file uploads. ----
    if first_byte == Some(b'@') && !is_literal_data {
        let mut cursor = Cursor::new(vbytes);
        let mut files: Vec<ToolMime> = Vec::new();
        let mut make_group = false;
        let mut first = true;

        // `do { ... } while(sep)` — always parse at least one filename, then loop
        // while a trailing comma announces another.
        loop {
            // Skip the leading '@' (first pass) or the ',' separator (later passes).
            cursor.pos += 1;
            let pp = cursor.get_param_part(b',', true, true, true, true);
            let sep = pp.sep;

            if first {
                // A comma after the first file means several files share one field,
                // so they must be wrapped in their own multipart group.
                make_group = sep == b',';
                first = false;
            }

            let (mut part, result) = tool_mime_new_filedata(&pp.data, true);
            part.headers = pp.headers;
            if result == CurlCode::ReadError {
                // A stdin read error: if bytes were already consumed, fail now;
                // otherwise defer the failure to the library (size = -1).
                if part.size > 0 {
                    warn("error while reading standard input");
                    return Err(CurlCode::ReadError);
                }
                part.data = None;
                part.size = -1;
            }
            if let Some(f) = pp.filename {
                part.filename = Some(f);
            }
            if let Some(t) = pp.mime_type {
                part.mime_type = Some(t);
            }
            if let Some(e) = pp.encoder {
                part.encoder = Some(e);
            }
            files.push(part);

            if sep == 0 {
                break;
            }
        }

        let cur = current_node(config);
        if make_group {
            // Wrap the files in a multipart group and attach that to the current
            // node; the field name is applied to the group.
            let mut group = tool_mime_new_parts();
            group.subparts = files;
            cur.subparts.push(group);
        } else {
            // A single file attaches directly to the current node.
            cur.subparts.extend(files);
        }
        if let Some(nm) = name {
            if let Some(last) = cur.subparts.last_mut() {
                last.name = Some(nm);
            }
        }
        return Ok(());
    }

    // ---- Branch D: `<file` (file contents), literal, or plain inline data. ----
    let mut cursor = Cursor::new(vbytes);
    let (mut part, pfilename, ptype, pencoder, sep) =
        if first_byte == Some(b'<') && !is_literal_data {
            // `<file` — use the file's contents as the field value (no upload).
            cursor.pos += 1; // skip '<'
            let pp = cursor.get_param_part(0, true, false, true, true);
            let (mut part, result) = tool_mime_new_filedata(&pp.data, false);
            part.headers = pp.headers;
            if result == CurlCode::ReadError {
                if part.size > 0 {
                    warn("error while reading standard input");
                    return Err(CurlCode::ReadError);
                }
                part.data = None;
                part.size = -1;
            }
            (part, None, pp.mime_type, pp.encoder, pp.sep)
        } else if is_literal_data {
            // `--form-string`: the entire value is literal data.
            let part = tool_mime_new_data(value);
            (part, None, None, None, 0u8)
        } else {
            // Plain inline data with optional `;`-parameters.
            let pp = cursor.get_param_part(0, true, true, true, true);
            let mut part = tool_mime_new_data(&pp.data);
            part.headers = pp.headers;
            (part, pp.filename, pp.mime_type, pp.encoder, pp.sep)
        };

    // Apply the parsed parameters (curl's order: filename, type, encoder).
    if let Some(f) = pfilename {
        part.filename = Some(f);
    }
    if let Some(t) = ptype {
        part.mime_type = Some(t);
    }
    if let Some(e) = pencoder {
        part.encoder = Some(e);
    }

    // With `endchar == '\0'` `get_param_part` consumes every `;`-parameter, so
    // `sep` is always 0 here; the warning is reproduced for byte-level fidelity.
    if sep != 0 {
        let rest = String::from_utf8_lossy(&vbytes[cursor.pos..]).into_owned();
        warn(&format!("garbage at end of field specification: {rest}"));
    }

    if let Some(nm) = name {
        part.name = Some(nm);
    }
    current_node(config).subparts.push(part);
    Ok(())
}

// ===========================================================================
// Conversion to a libcurl mime object (mirror tool2curlparts / tool2curlmime)
// ===========================================================================

/// Build a fresh [`StdinMimeReader`] mirroring the bookkeeping stored on a
/// stdin-backed [`ToolMime`] node. The buffered bytes (if any) are copied so the
/// reader owns its data independently of the tree.
fn stdin_reader_for(m: &ToolMime) -> StdinMimeReader {
    StdinMimeReader {
        data: m.data.as_ref().map(|s| s.as_bytes().to_vec()),
        size: m.size,
        origin: m.origin,
        curpos: m.curpos,
    }
}

/// Convert a single [`ToolMime`] node into a new part appended to `mime`, the port
/// of curl's `tool2curlparts` (minus its `prev`-recursion: siblings are already in
/// forward order in [`ToolMime::subparts`], so the caller iterates them directly).
///
/// The libcurl `curl_mime_*` calls become their safe [`Mime`]/`Part` builder
/// equivalents, applied in curl's exact order — content, then filename, type,
/// headers, encoder, and finally name — so the resulting tree is structurally
/// identical to the C output.
fn tool2curlparts(easy: &Easy, m: &ToolMime, mime: &mut Mime) -> Result<(), CurlCode> {
    let part = mime.addpart();
    // Start from the node's own filename; the switch below may substitute it.
    let mut filename: Option<&str> = m.filename.as_deref();

    match m.kind {
        ToolMimeKind::Parts => {
            // Recurse to build the sub-multipart, then attach it.
            let submime = tool2curlmime(easy, m)?;
            part.set_subparts(submime).map_err(|e| e.code())?;
        }
        ToolMimeKind::Data => {
            let data = m.data.as_deref().unwrap_or("");
            part.set_data(data.as_bytes()).map_err(|e| e.code())?;
        }
        ToolMimeKind::File | ToolMimeKind::FileData => {
            let path = m.data.as_deref().unwrap_or("");
            part.set_filedata(path).map_err(|e| e.code())?;
            // `set_filedata` exposes the file's base name as the remote filename.
            // For `<file` (FileData) with no explicit `;filename=`, curl clears it
            // so the contents are sent as anonymous field data.
            if m.kind == ToolMimeKind::FileData && filename.is_none() {
                part.set_filename(None).map_err(|e| e.code())?;
            }
        }
        ToolMimeKind::Stdin => {
            // A stdin upload defaults its remote filename to "-".
            if filename.is_none() {
                filename = Some("-");
            }
            let reader = stdin_reader_for(m);
            part.set_data_cb(m.size, Box::new(reader))
                .map_err(|e| e.code())?;
        }
        ToolMimeKind::StdinData => {
            let reader = stdin_reader_for(m);
            part.set_data_cb(m.size, Box::new(reader))
                .map_err(|e| e.code())?;
        }
        ToolMimeKind::None => {
            // Not reachable in this context (curl's `default:` no-op).
        }
    }

    if let Some(f) = filename {
        part.set_filename(Some(f)).map_err(|e| e.code())?;
    }
    part.set_type(m.mime_type.as_deref())
        .map_err(|e| e.code())?;
    if !m.headers.is_empty() {
        part.set_headers(m.headers.clone()).map_err(|e| e.code())?;
    }
    part.set_encoder(m.encoder.as_deref())
        .map_err(|e| e.code())?;
    part.set_name(m.name.as_deref()).map_err(|e| e.code())?;
    Ok(())
}

/// Convert a [`ToolMime`] multipart node and its children into a `curl-rs-lib`
/// [`Mime`] object, the port of curl's `tool2curlmime`. The `easy` handle is
/// carried for signature parity with the C API (`curl_mime_init(curl)`); the
/// safe [`Mime`] builder needs no handle, so it is otherwise unused.
///
/// # Errors
///
/// Propagates any [`CurlCode`] produced while materializing a part — most
/// commonly [`CurlCode::ReadError`] when a `;filename` source file is missing, or
/// [`CurlCode::BadFunctionArgument`] for an unknown `;encoder=` name.
pub fn tool2curlmime(easy: &Easy, m: &ToolMime) -> Result<Mime, CurlCode> {
    let mut mime = Mime::new();
    for child in &m.subparts {
        tool2curlparts(easy, child, &mut mime)?;
    }
    Ok(mime)
}

// ===========================================================================
// CLI integration adapter
// ===========================================================================

/// Adapter installed as [`crate::args::FormParserHook`] by `main.rs`.
///
/// It bridges [`formparse`]'s [`CurlCode`] result to the CLI's
/// [`ParameterError`] convention: any failure becomes [`ParameterError::BadUse`],
/// exactly as `tool_getparam.c` maps a non-zero `formparse` return to
/// `PARAM_BAD_USE`. The distinct `warnf` diagnostics are emitted inside
/// [`formparse`] before the mapping, so no message detail is lost.
pub fn form_parser_hook(
    input: &str,
    config: &mut OperationConfig,
    is_literal_data: bool,
) -> Result<(), ParameterError> {
    formparse(input, config, is_literal_data).map_err(|_| ParameterError::BadUse)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use curl_rs_lib::mime::{MimeKind, MimeStrategy};
    use std::io::Write;

    /// Parse one `-F` argument into a fresh config and return that config.
    fn parse(input: &str) -> OperationConfig {
        let mut config = OperationConfig::default();
        formparse(input, &mut config, false).expect("formparse should succeed");
        config
    }

    /// The root node's direct children after parsing.
    fn roots(config: &OperationConfig) -> &[ToolMime] {
        &config.mimeroot.as_ref().expect("root created").subparts
    }

    #[test]
    fn plain_data_part() {
        let config = parse("field=hello world");
        let parts = roots(&config);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].kind, ToolMimeKind::Data);
        assert_eq!(parts[0].data.as_deref(), Some("hello world"));
        assert_eq!(parts[0].name.as_deref(), Some("field"));
        assert!(parts[0].mime_type.is_none());
    }

    #[test]
    fn empty_name_is_none() {
        // `=value` has an empty name (curl leaves `name` NULL for `contp == contents`).
        let config = parse("=anonymous");
        let parts = roots(&config);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].name, None);
        assert_eq!(parts[0].data.as_deref(), Some("anonymous"));
    }

    #[test]
    fn type_parameter() {
        let config = parse("f=data;type=text/plain");
        let parts = roots(&config);
        assert_eq!(parts[0].data.as_deref(), Some("data"));
        assert_eq!(parts[0].mime_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn type_charset_continuation() {
        // `;charset=` continues the content type verbatim (semicolon retained).
        let config = parse("f=data;type=text/plain;charset=utf-8");
        let parts = roots(&config);
        assert_eq!(
            parts[0].mime_type.as_deref(),
            Some("text/plain;charset=utf-8")
        );
    }

    #[test]
    fn encoder_parameter() {
        let config = parse("f=data;encoder=base64");
        let parts = roots(&config);
        assert_eq!(parts[0].encoder.as_deref(), Some("base64"));
    }

    #[test]
    fn inline_header_parameter() {
        let config = parse(r#"f=data;headers="X-Custom: value""#);
        let parts = roots(&config);
        assert_eq!(parts[0].headers, vec!["X-Custom: value".to_string()]);
    }

    #[test]
    fn quoted_value_with_escapes() {
        // `\"` -> `"` and `\\` -> `\`.
        let config = parse(r#"f="a\"b\\c""#);
        let parts = roots(&config);
        assert_eq!(parts[0].data.as_deref(), Some("a\"b\\c"));
    }

    #[test]
    fn file_upload_single() {
        let config = parse("f=@/path/to/file.txt");
        let parts = roots(&config);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].kind, ToolMimeKind::File);
        assert_eq!(parts[0].data.as_deref(), Some("/path/to/file.txt"));
        assert_eq!(parts[0].name.as_deref(), Some("f"));
    }

    #[test]
    fn file_upload_with_filename_override() {
        let config = parse(r#"f=@/etc/hosts;filename=fake.txt"#);
        let parts = roots(&config);
        assert_eq!(parts[0].kind, ToolMimeKind::File);
        assert_eq!(parts[0].filename.as_deref(), Some("fake.txt"));
    }

    #[test]
    fn file_content_data() {
        // `<file` uses the file's contents as the field value (kind FileData).
        let config = parse("f=</path/to/file.txt");
        let parts = roots(&config);
        assert_eq!(parts[0].kind, ToolMimeKind::FileData);
        assert_eq!(parts[0].data.as_deref(), Some("/path/to/file.txt"));
    }

    #[test]
    fn multiple_files_form_group() {
        let config = parse("f=@a.txt,b.txt,c.txt");
        let parts = roots(&config);
        // The three files are wrapped in a single multipart group named `f`.
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].kind, ToolMimeKind::Parts);
        assert_eq!(parts[0].name.as_deref(), Some("f"));
        assert_eq!(parts[0].subparts.len(), 3);
        assert_eq!(parts[0].subparts[0].data.as_deref(), Some("a.txt"));
        assert_eq!(parts[0].subparts[1].data.as_deref(), Some("b.txt"));
        assert_eq!(parts[0].subparts[2].data.as_deref(), Some("c.txt"));
    }

    #[test]
    fn form_string_is_literal() {
        // `--form-string`: `@`, `<`, and `;type=` all lose special meaning.
        let mut config = OperationConfig::default();
        formparse("f=@notafile;type=x", &mut config, true).unwrap();
        let parts = roots(&config);
        assert_eq!(parts[0].kind, ToolMimeKind::Data);
        assert_eq!(parts[0].data.as_deref(), Some("@notafile;type=x"));
        assert!(parts[0].mime_type.is_none());
    }

    #[test]
    fn nested_multipart_start_and_end() {
        let mut config = OperationConfig::default();
        formparse("outer=(", &mut config, false).unwrap();
        // We descended into the new multipart.
        assert_eq!(config.mimecurrent, vec![0]);
        formparse("inner=text", &mut config, false).unwrap();
        formparse("=)", &mut config, false).unwrap();
        // Back at the root.
        assert!(config.mimecurrent.is_empty());

        let root = config.mimeroot.as_ref().unwrap();
        assert_eq!(root.subparts.len(), 1);
        let outer = &root.subparts[0];
        assert_eq!(outer.kind, ToolMimeKind::Parts);
        assert_eq!(outer.name.as_deref(), Some("outer"));
        assert_eq!(outer.subparts.len(), 1);
        assert_eq!(outer.subparts[0].data.as_deref(), Some("text"));
        assert_eq!(outer.subparts[0].name.as_deref(), Some("inner"));
    }

    #[test]
    fn multipart_with_type_on_opener() {
        let mut config = OperationConfig::default();
        formparse("files=(;type=multipart/mixed", &mut config, false).unwrap();
        let outer = &config.mimeroot.as_ref().unwrap().subparts[0];
        assert_eq!(outer.kind, ToolMimeKind::Parts);
        assert_eq!(outer.mime_type.as_deref(), Some("multipart/mixed"));
    }

    #[test]
    fn missing_equals_is_error() {
        let mut config = OperationConfig::default();
        let err = formparse("no-equals-here", &mut config, false).unwrap_err();
        assert_eq!(err, CurlCode::BadFunctionArgument);
    }

    #[test]
    fn terminate_without_multipart_is_error() {
        let mut config = OperationConfig::default();
        let err = formparse("=)", &mut config, false).unwrap_err();
        assert_eq!(err, CurlCode::BadFunctionArgument);
    }

    #[test]
    fn headers_from_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "X-First: 1").unwrap();
        writeln!(file, "# a comment line").unwrap();
        writeln!(file, "X-Second: 2").unwrap();
        writeln!(file, " continued").unwrap(); // folded onto X-Second
        let path = file.path().to_str().unwrap().to_string();

        let config = parse(&format!("f=data;headers=@{path}"));
        let parts = roots(&config);
        assert_eq!(
            parts[0].headers,
            vec![
                "X-First: 1".to_string(),
                "X-Second: 2 continued".to_string()
            ]
        );
    }

    #[test]
    fn parser_hook_maps_error_to_bad_use() {
        let mut config = OperationConfig::default();
        let err = form_parser_hook("no-equals", &mut config, false).unwrap_err();
        assert_eq!(err, ParameterError::BadUse);
    }

    #[test]
    fn parser_hook_success() {
        let mut config = OperationConfig::default();
        form_parser_hook("f=hello", &mut config, false).unwrap();
        assert_eq!(roots(&config)[0].data.as_deref(), Some("hello"));
    }

    // ---- tool2curlmime conversion ----

    #[test]
    fn convert_data_part() {
        let config = parse("greeting=hello");
        let easy = Easy::builder().build().unwrap();
        let mime = tool2curlmime(&easy, config.mimeroot.as_ref().unwrap()).unwrap();
        assert_eq!(mime.parts().len(), 1);
        assert_eq!(mime.parts()[0].kind(), MimeKind::Data);

        // The serialized form body carries the name and the data.
        let body = mime.to_bytes(MimeStrategy::Form).unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains(r#"name="greeting""#), "body: {text}");
        assert!(text.contains("hello"), "body: {text}");
    }

    #[test]
    fn convert_file_part() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "file contents").unwrap();
        let path = file.path().to_str().unwrap().to_string();

        let config = parse(&format!("upload=@{path}"));
        let easy = Easy::builder().build().unwrap();
        let mime = tool2curlmime(&easy, config.mimeroot.as_ref().unwrap()).unwrap();
        assert_eq!(mime.parts().len(), 1);
        assert_eq!(mime.parts()[0].kind(), MimeKind::File);
    }

    #[test]
    fn convert_file_content_clears_filename() {
        // `<file` (FileData) with no explicit filename must not expose a filename.
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "abc").unwrap();
        let path = file.path().to_str().unwrap().to_string();

        let config = parse(&format!("data=<{path}"));
        let easy = Easy::builder().build().unwrap();
        let mime = tool2curlmime(&easy, config.mimeroot.as_ref().unwrap()).unwrap();
        assert_eq!(mime.parts()[0].kind(), MimeKind::File);
        let body = mime.to_bytes(MimeStrategy::Form).unwrap();
        let text = String::from_utf8_lossy(&body);
        // Field data, not a file upload: no `filename=` in the disposition.
        assert!(!text.contains("filename="), "body: {text}");
        assert!(text.contains(r#"name="data""#), "body: {text}");
    }

    #[test]
    fn convert_nested_multipart() {
        let mut config = OperationConfig::default();
        formparse("outer=(", &mut config, false).unwrap();
        formparse("inner=text", &mut config, false).unwrap();
        formparse("=)", &mut config, false).unwrap();

        let easy = Easy::builder().build().unwrap();
        let mime = tool2curlmime(&easy, config.mimeroot.as_ref().unwrap()).unwrap();
        assert_eq!(mime.parts().len(), 1);
        assert_eq!(mime.parts()[0].kind(), MimeKind::Multipart);
    }

    #[test]
    fn convert_missing_file_is_error() {
        // A `<file` whose source does not exist surfaces as a read error at
        // conversion time (curl's deferred `curl_mime_filedata`).
        let config = parse("f=</no/such/file/exists/here.xyz");
        let easy = Easy::builder().build().unwrap();
        let err = tool2curlmime(&easy, config.mimeroot.as_ref().unwrap()).unwrap_err();
        assert_eq!(err, CurlCode::ReadError);
    }
}
