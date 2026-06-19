//! `-F`/`--form` (and `--form-string`) MIME parsing for the `curl-rs` CLI.
//!
//! This module is the Rust reimplementation of curl's `src/tool_formparse.c`
//! (and its header `src/tool_formparse.h`). It parses each `-F`/`--form`
//! command-line argument into an intermediate **MIME-part tree** ([`ToolMime`])
//! and then translates that tree into a [`curl_rs_lib::Mime`] object — the exact
//! analogue of the C `curl_mime` tree built by `tool2curlmime`/`tool2curlparts`.
//!
//! # Behavioral parity (AAP §0.8.2)
//!
//! The produced multipart body — part names, filenames, content types,
//! encoders, per-part headers, and **ordering** — must match curl byte-for-byte
//! wherever the behavior is deterministic. To guarantee that, this port
//! reproduces curl's grammar and its metadata-application order exactly:
//!
//! * Grammar helpers `get_param_word` and `get_param_part` mirror the C
//!   token/metadata scanner, including quoted-string escapes, trailing-data
//!   warnings, the `type=`/`filename=`/`encoder=`/`headers=` blocks (with
//!   `headers=@file` continuation folding), and content-type continuation.
//! * `formparse` reproduces the `name=content` split, `(`/`)` multipart
//!   grouping, `@file` uploads (with multi-file grouping into a nested
//!   multipart), `<file`/`<-` data-from-file/stdin, literal data, and the
//!   `--form-string` literal mode that suppresses `@`/`<`/`(`/`)`.
//! * `build_mime`/`build_parts` apply per-part metadata in curl's order —
//!   `filename` → `type` → `headers` → `encoder` → `name` — so the emitted
//!   multipart headers are byte-identical.
//!
//! # Ordering note
//!
//! curl builds the intermediate tree by *prepending* each new sibling onto
//! `parent->subparts` (via the `prev` link) and then *reverses* the list while
//! converting (`tool2curlparts` recurses `m->prev` first). This Rust port
//! instead stores siblings in a `Vec<ToolMime>` pushed in **CLI order** and
//! iterates that vector **forward** during conversion — an equivalent result
//! that is verified against curl's emitted order in the unit tests.
//!
//! # Constraints
//!
//! * No `unsafe` (`#![forbid(unsafe_code)]`).
//! * Depends on `curl_rs_lib` only (never `curl-rs-ffi`).
//! * Uses [`crate::messages::warnf`] for the exact warnings curl prints on
//!   malformed `-F` syntax.

#![forbid(unsafe_code)]
// The CLI is still being assembled file-by-file; some public items here are
// consumed by `setopt.rs`/`operate.rs` which land alongside this file. Mirrors
// the construction-staging convention used elsewhere in the crate.
#![allow(dead_code)]

use std::io::{self, Read};

use curl_rs_lib::{CurlError, Easy, Mime, SList};

use crate::args::ParameterError;
use crate::config::{GlobalConfig, OperationConfig};
use crate::messages::warnf;

// ===========================================================================
// Phase A — Intermediate MIME-part tree
// ===========================================================================

/// Kind of an intermediate MIME node. Mirrors the C `toolmimekind` enum in
/// `src/tool_formparse.h`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ToolMimeKind {
    /// No content yet (a freshly created node). C `TOOLMIME_NONE`.
    #[default]
    None,
    /// A nested multipart group holding `subparts`. C `TOOLMIME_PARTS`.
    Parts,
    /// Literal in-memory data. C `TOOLMIME_DATA`.
    Data,
    /// A file upload (`@file`); the basename is sent as the filename.
    /// C `TOOLMIME_FILE`.
    File,
    /// Data read from a file (`<file`); the filename is *not* sent.
    /// C `TOOLMIME_FILEDATA`.
    FileData,
    /// Live standard input as a file upload (`@-`). C `TOOLMIME_STDIN`.
    Stdin,
    /// Standard input used as data only (`<-`). C `TOOLMIME_STDINDATA`.
    StdinData,
}

/// An intermediate MIME node, the Rust analogue of the C `struct tool_mime`.
///
/// The tree is modeled with owned `Vec<ToolMime>` children stored in CLI order
/// (see the module-level *Ordering note*); there are no raw `parent`/`prev`
/// links. The currently-open multipart group is tracked by the [`open`] flag on
/// `Parts` nodes rather than a separate cursor pointer, so the cursor state
/// persists across successive `-F` arguments inside [`OperationConfig`].
///
/// [`open`]: ToolMime::open
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolMime {
    /// The node kind.
    pub kind: ToolMimeKind,
    /// Child parts (only meaningful for [`ToolMimeKind::Parts`]).
    pub subparts: Vec<ToolMime>,
    /// Literal data bytes (for [`ToolMimeKind::Data`]). Stored as raw bytes to
    /// preserve byte-for-byte parity.
    pub data: Option<Vec<u8>>,
    /// File path for [`ToolMimeKind::File`]/[`ToolMimeKind::FileData`] (the C
    /// `data` field when it holds a filename).
    pub filepath: Option<String>,
    /// Stdin read origin offset (C `origin`). Retained for struct fidelity.
    pub origin: i64,
    /// Stdin data size (C `size`); `-1` means "unknown, determine at build".
    pub size: i64,
    /// Part name (the `name=` of `name=content`). C `name`.
    pub name: Option<String>,
    /// Part content type (`;type=`). C `type`.
    pub content_type: Option<String>,
    /// Part filename (`;filename=`). C `filename`.
    pub filename: Option<String>,
    /// Part transfer encoder (`;encoder=`). C `encoder`.
    pub encoder: Option<String>,
    /// Per-part custom headers (`;headers=`). C `headers` (an slist).
    pub headers: Vec<String>,
    /// Whether this `Parts` group is still open for more content (an opening
    /// `(` not yet matched by `)`). The root group is always open. Multi-file
    /// `@a,b` groups are created already closed.
    pub open: bool,
}

impl ToolMime {
    /// Create an *open* multipart group. Analogue of `tool_mime_new_parts` for
    /// the root and for an explicit `(`.
    #[must_use]
    fn new_parts_open() -> ToolMime {
        ToolMime {
            kind: ToolMimeKind::Parts,
            open: true,
            ..ToolMime::default()
        }
    }

    /// Create a *closed* multipart group (used to bundle the multiple files of a
    /// single `@a,b,c` field). Analogue of `tool_mime_new_parts` whose contents
    /// are complete.
    #[must_use]
    fn new_parts_closed() -> ToolMime {
        ToolMime {
            kind: ToolMimeKind::Parts,
            open: false,
            ..ToolMime::default()
        }
    }

    /// Create a literal data node. Analogue of `tool_mime_new_data`.
    #[must_use]
    fn new_data(data: Vec<u8>) -> ToolMime {
        ToolMime {
            kind: ToolMimeKind::Data,
            data: Some(data),
            ..ToolMime::default()
        }
    }
}

/// Build a file-data node from a path, mirroring `tool_mime_new_filedata`.
///
/// * `path == "-"` selects standard input ([`ToolMimeKind::Stdin`] when
///   `isremotefile`, else [`ToolMimeKind::StdinData`]). curl decides live vs.
///   buffered reading at this point based on whether stdin is a seekable
///   regular file; this port defers all stdin reading to [`build_mime`] (where
///   it buffers stdin and streams it through a callback), which is byte-for-byte
///   equivalent for the produced body and avoids any `unsafe`/`fstat`.
/// * Otherwise it is a normal file ([`ToolMimeKind::File`] when `isremotefile`,
///   else [`ToolMimeKind::FileData`]); the path is recorded and the file is
///   opened later by libcurl, exactly as curl defers it.
#[must_use]
fn make_filedata(path: &str, isremotefile: bool) -> ToolMime {
    if path != "-" {
        ToolMime {
            kind: if isremotefile {
                ToolMimeKind::File
            } else {
                ToolMimeKind::FileData
            },
            filepath: Some(path.to_string()),
            ..ToolMime::default()
        }
    } else {
        ToolMime {
            kind: if isremotefile {
                ToolMimeKind::Stdin
            } else {
                ToolMimeKind::StdinData
            },
            // Actual size/content are determined when the tree is converted.
            size: -1,
            ..ToolMime::default()
        }
    }
}

// ===========================================================================
// Phase B — Grammar (character classes + token scanner)
// ===========================================================================

/// `ISBLANK`: space or tab. Matches curl's `ISBLANK` classification.
#[inline]
fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// `ISSPACE`: blank plus the `0x0a..=0x0d` range (LF, VT, FF, CR). Matches
/// curl's `ISSPACE`. Used (instead of `is_blank`) when trimming `encoder=`.
#[inline]
fn is_space(c: u8) -> bool {
    is_blank(c) || (0x0a..=0x0d).contains(&c)
}

/// A "tspecial" / separator character for an HTTP content type, i.e. the
/// `strcspn` reject set `"()<>@,;:\\\"[]?=\r\n "` used by curl when scanning a
/// `type=` value.
#[inline]
fn is_tspecial(c: u8) -> bool {
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

/// Case-insensitive ASCII prefix test, the analogue of curl's `checkprefix`.
#[inline]
fn checkprefix(prefix: &[u8], s: &[u8]) -> bool {
    s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// The separator byte at `pos`, or `0` for end-of-input (curl reads the NUL
/// terminator, which is `0`).
#[inline]
fn sep_at(input: &[u8], pos: usize) -> u8 {
    if pos < input.len() {
        input[pos]
    } else {
        0
    }
}

/// Strip trailing `ISBLANK` bytes from a word in place.
#[inline]
fn strip_trailing_blanks(word: &mut Vec<u8>) {
    while word.last().is_some_and(|&c| is_blank(c)) {
        word.pop();
    }
}

/// Strip trailing `ISSPACE` bytes from a word in place (used for `encoder=`).
#[inline]
fn strip_trailing_space(word: &mut Vec<u8>) {
    while word.last().is_some_and(|&c| is_space(c)) {
        word.pop();
    }
}

/// Lossy UTF-8 decode of a parsed token into an owned `String`. CLI input is
/// already valid UTF-8 and the token delimiters are all ASCII, so for command
/// line tokens this is an exact, lossless conversion; for bytes read from a
/// header file it degrades gracefully.
#[inline]
fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Extract a token from `input` starting at `*pos`, returning `(token, quoted)`.
///
/// Mirrors curl's `get_param_word`:
/// * A leading `"` begins a quoted token; `\\` and `\"` are unescaped; the
///   closing quote ends the token. After the closing quote, any non-space data
///   before the next `;`/`endchar` triggers a "Trailing data after quoted form
///   parameter" warning. A missing closing quote falls back to non-quoted
///   parsing from the original start.
/// * Otherwise the token runs up to the next `;` or `endchar` (or end of input).
///
/// On return `*pos` points at the terminating `;`/`endchar`/end. The boolean is
/// `true` when the token was read as a quoted string; callers strip trailing
/// blanks only for non-quoted tokens, exactly as curl does.
fn get_param_word(
    global: &GlobalConfig,
    input: &[u8],
    pos: &mut usize,
    endchar: u8,
) -> (Vec<u8>, bool) {
    let len = input.len();
    let start = *pos;

    if start < len && input[start] == b'"' {
        let mut i = start + 1;
        let mut word: Vec<u8> = Vec::new();
        while i < len {
            if input[i] == b'\\' && i + 1 < len && (input[i + 1] == b'\\' || input[i + 1] == b'"') {
                // Escaped backslash or double-quote: keep the escaped char.
                word.push(input[i + 1]);
                i += 2;
                continue;
            }
            if input[i] == b'"' {
                // Closing quote: consume it, then scan trailing data.
                i += 1;
                let mut trailing_data = false;
                while i < len && input[i] != b';' && input[i] != endchar {
                    if !is_space(input[i]) {
                        trailing_data = true;
                    }
                    i += 1;
                }
                if trailing_data {
                    warnf(global, "Trailing data after quoted form parameter");
                }
                *pos = i;
                return (word, true);
            }
            // Ordinary byte (also covers a lone backslash not followed by an
            // escapable char, which curl copies verbatim).
            word.push(input[i]);
            i += 1;
        }
        // End quote missing: fall through and treat as non-quoted from `start`.
    }

    // Non-quoted token: up to ';' or endchar.
    let mut i = start;
    let mut word: Vec<u8> = Vec::new();
    while i < len && input[i] != b';' && input[i] != endchar {
        word.push(input[i]);
        i += 1;
    }
    *pos = i;
    (word, false)
}

/// Parse header lines from the contents of a `headers=@file`, appending each to
/// `headers`. Mirrors curl's `read_field_headers`:
/// * Lines beginning with `#` are comments and skipped.
/// * Lines beginning with a space are continuations folded onto the previous
///   header (the whole line, including its leading space, is appended).
/// * Trailing CR/LF and blanks are trimmed; blank lines are skipped.
fn read_field_headers(content: &[u8], headers: &mut Vec<String>) {
    for raw in content.split(|&b| b == b'\n') {
        if raw.first() == Some(&b'#') {
            // Comment line.
            continue;
        }
        let folded = raw.first() == Some(&b' ');
        // Trim trailing CR/LF and blanks (ISNEWLINE || ISBLANK).
        let mut end = raw.len();
        while end > 0 {
            let c = raw[end - 1];
            if c == b'\n' || c == b'\r' || is_blank(c) {
                end -= 1;
            } else {
                break;
            }
        }
        let line = &raw[..end];
        if line.is_empty() {
            continue;
        }
        if folded {
            if let Some(last) = headers.last_mut() {
                last.push_str(&bytes_to_string(line));
                continue;
            }
            // No previous header to fold onto: treat as a normal header below.
        }
        headers.push(bytes_to_string(line));
    }
}

/// Which metadata blocks a given call to [`get_param_part`] accepts. A field that
/// is parsed but not allowed in the current context produces a "Field ... not
/// allowed here" warning and is discarded — exactly as curl does when the
/// corresponding `p*` out-pointer is `NULL`.
#[derive(Debug, Clone, Copy)]
struct Allowed {
    typ: bool,
    filename: bool,
    encoder: bool,
    headers: bool,
}

/// The result of parsing one `-F` value segment via [`get_param_part`].
#[derive(Debug, Default)]
struct ParamPart {
    /// The main token (data, file path, or `(`), as raw bytes.
    data: Vec<u8>,
    /// `;type=` value (content type), if present and allowed.
    content_type: Option<String>,
    /// `;filename=` value, if present and allowed.
    filename: Option<String>,
    /// `;encoder=` value, if present and allowed.
    encoder: Option<String>,
    /// `;headers=` values, if present and allowed.
    headers: Vec<String>,
    /// The terminating byte (`,`/`;`/`endchar`/`0`) where parsing stopped.
    sep: u8,
}

/// Parse the main token plus any `type=`/`filename=`/`encoder=`/`headers=`
/// metadata blocks. Mirrors curl's `get_param_part`.
///
/// On return `*pos` points at the terminating separator; [`ParamPart::sep`] is
/// that separator byte (`0` at end of input), letting the caller continue an
/// `@a,b,c` file list or detect trailing garbage.
fn get_param_part(
    global: &GlobalConfig,
    input: &[u8],
    pos: &mut usize,
    endchar: u8,
    allowed: Allowed,
) -> Result<ParamPart, ParameterError> {
    let len = input.len();
    let mut type_start: Option<usize> = None;
    let mut ct_end: usize = 0;
    let mut endct_active = false; // C: endct != NULL
    let mut filename: Option<String> = None;
    let mut encoder: Option<String> = None;
    let mut headers: Vec<String> = Vec::new();

    // Skip leading blanks, then read the main word.
    while *pos < len && is_blank(input[*pos]) {
        *pos += 1;
    }
    let (mut data, quoted) = get_param_word(global, input, pos, endchar);
    if !quoted {
        strip_trailing_blanks(&mut data);
    }
    let mut sep = sep_at(input, *pos);

    while sep == b';' {
        // Skip the ';' and any following blanks.
        *pos += 1;
        while *pos < len && is_blank(input[*pos]) {
            *pos += 1;
        }
        let rest = &input[*pos..];

        if !endct_active && checkprefix(b"type=", rest) {
            *pos += 5;
            while *pos < len && is_blank(input[*pos]) {
                *pos += 1;
            }
            let ts = *pos;
            // strcspn(p, "()<>@,;:\\\"[]?=\r\n ")
            while *pos < len && !is_tspecial(input[*pos]) {
                *pos += 1;
            }
            type_start = Some(ts);
            ct_end = *pos;
            endct_active = true;
            sep = sep_at(input, *pos);
        } else if checkprefix(b"filename=", rest) {
            endct_active = false; // C terminates the pending content type.
            *pos += 9;
            while *pos < len && is_blank(input[*pos]) {
                *pos += 1;
            }
            let (mut w, q) = get_param_word(global, input, pos, endchar);
            if !q {
                strip_trailing_blanks(&mut w);
            }
            sep = sep_at(input, *pos);
            filename = Some(bytes_to_string(&w));
        } else if checkprefix(b"headers=", rest) {
            endct_active = false;
            *pos += 8;
            if *pos < len && (input[*pos] == b'@' || input[*pos] == b'<') {
                // Read headers from a file: skip the '@'/'<' and blanks.
                loop {
                    *pos += 1;
                    if !(*pos < len && is_blank(input[*pos])) {
                        break;
                    }
                }
                let (mut w, q) = get_param_word(global, input, pos, endchar);
                if !q {
                    strip_trailing_blanks(&mut w);
                }
                sep = sep_at(input, *pos);
                let hdrfile = bytes_to_string(&w);
                match std::fs::read(&hdrfile) {
                    Ok(bytes) => read_field_headers(&bytes, &mut headers),
                    Err(e) => warnf(global, &format!("Cannot read from {hdrfile}: {e}")),
                }
            } else {
                // Literal header value.
                while *pos < len && is_blank(input[*pos]) {
                    *pos += 1;
                }
                let (mut w, q) = get_param_word(global, input, pos, endchar);
                if !q {
                    strip_trailing_blanks(&mut w);
                }
                sep = sep_at(input, *pos);
                headers.push(bytes_to_string(&w));
            }
        } else if checkprefix(b"encoder=", rest) {
            endct_active = false;
            *pos += 8;
            while *pos < len && is_blank(input[*pos]) {
                *pos += 1;
            }
            let (mut w, q) = get_param_word(global, input, pos, endchar);
            if !q {
                strip_trailing_space(&mut w); // NB: ISSPACE here, not ISBLANK.
            }
            sep = sep_at(input, *pos);
            encoder = Some(bytes_to_string(&w));
        } else if endct_active {
            // Continuation of the content type: extend `ct_end` to just past the
            // last non-blank byte of this block.
            let mut e = *pos;
            while *pos < len && input[*pos] != b';' && input[*pos] != endchar {
                if !is_blank(input[*pos]) {
                    e = *pos + 1;
                }
                *pos += 1;
            }
            ct_end = e;
            sep = sep_at(input, *pos);
        } else {
            // Unknown prefix: consume the block and warn (if non-empty).
            let (w, _q) = get_param_word(global, input, pos, endchar);
            sep = sep_at(input, *pos);
            if !w.is_empty() {
                warnf(
                    global,
                    &format!("skip unknown form field: {}", bytes_to_string(&w)),
                );
            }
        }
    }

    // The content type spans the contiguous range from its first byte through
    // the last extension's end (separators between blocks are included exactly
    // as curl keeps them in the source buffer).
    let content_type = type_start.map(|s| bytes_to_string(&input[s..ct_end]));

    // Route each parsed field to the result, or warn + discard when not allowed.
    let out_type = if allowed.typ {
        content_type
    } else {
        if let Some(t) = &content_type {
            warnf(global, &format!("Field content type not allowed here: {t}"));
        }
        None
    };
    let out_filename = if allowed.filename {
        filename
    } else {
        if let Some(f) = &filename {
            warnf(global, &format!("Field filename not allowed here: {f}"));
        }
        None
    };
    let out_encoder = if allowed.encoder {
        encoder
    } else {
        if let Some(e) = &encoder {
            warnf(global, &format!("Field encoder not allowed here: {e}"));
        }
        None
    };
    let out_headers = if allowed.headers {
        headers
    } else {
        if let Some(h) = headers.first() {
            warnf(global, &format!("Field headers not allowed here: {h}"));
        }
        Vec::new()
    };

    Ok(ParamPart {
        data,
        content_type: out_type,
        filename: out_filename,
        encoder: out_encoder,
        headers: out_headers,
        sep,
    })
}

/// Compute the path (a sequence of `subparts` indices) from `root` to the
/// currently-open multipart group: descend into the last child while it is an
/// *open* `Parts` node. The empty path denotes the root group itself.
///
/// This replaces curl's mutable `mimecurrent` cursor: the "open" state lives in
/// the tree (the [`ToolMime::open`] flag), so it persists across successive
/// `-F` arguments without a separate pointer.
fn current_group_path(root: &ToolMime) -> Vec<usize> {
    let mut path = Vec::new();
    let mut cur = root;
    while let Some(last) = cur.subparts.last() {
        if last.kind == ToolMimeKind::Parts && last.open {
            let idx = cur.subparts.len() - 1;
            path.push(idx);
            cur = &cur.subparts[idx];
        } else {
            break;
        }
    }
    path
}

/// Resolve a path produced by [`current_group_path`] to a mutable reference.
fn group_at_mut<'a>(root: &'a mut ToolMime, path: &[usize]) -> &'a mut ToolMime {
    let mut cur = root;
    for &i in path {
        cur = &mut cur.subparts[i];
    }
    cur
}

/// Parse one `-F`/`--form` (or `--form-string`) argument and fold it into the
/// operation's MIME tree (`config.mimeroot`). Mirrors curl's `formparse`.
///
/// `literal_value` is `true` for `--form-string`, which suppresses the special
/// meaning of a leading `@`/`<`/`(`/`)` and of embedded `;type=` etc.
///
/// # Errors
///
/// Returns [`ParameterError::BadUse`] on malformed input — the same mapping curl
/// applies when `formparse` returns non-zero (`tool_getparam` maps it to
/// `PARAM_BAD_USE`).
pub fn formparse(
    global: &GlobalConfig,
    config: &mut OperationConfig,
    input: &str,
    literal_value: bool,
) -> Result<(), ParameterError> {
    // Allocate the root multipart group on first use.
    if config.mimeroot.is_none() {
        config.mimeroot = Some(ToolMime::new_parts_open());
    }
    let root = config
        .mimeroot
        .as_mut()
        .expect("mimeroot was just initialized");

    // The current open group for this argument (curl's `mimecurrent`).
    let path = current_group_path(root);

    let bytes = input.as_bytes();
    // Scan for the end of the name.
    let Some(eq) = bytes.iter().position(|&b| b == b'=') else {
        warnf(global, "Illegally formatted input field");
        return Err(ParameterError::BadUse);
    };
    // `name` is set only when there is at least one character before '='.
    let name: Option<String> = if eq > 0 {
        Some(input[..eq].to_string())
    } else {
        None
    };
    let content = &bytes[eq + 1..];

    if !content.is_empty() && content[0] == b'(' && !literal_value {
        // ---- Starting a multipart group. ----
        // The leading '(' is read (and discarded) as the main token; only the
        // type and headers are captured.
        let mut pos = 0usize;
        let pp = get_param_part(
            global,
            content,
            &mut pos,
            0,
            Allowed {
                typ: true,
                filename: false,
                encoder: false,
                headers: true,
            },
        )?;
        let group = group_at_mut(root, &path);
        let mut node = ToolMime::new_parts_open();
        node.headers = pp.headers;
        node.content_type = pp.content_type;
        node.name = name;
        group.subparts.push(node);
    } else if name.is_none() && content == b")" && !literal_value {
        // ---- Ending a multipart group. ----
        if path.is_empty() {
            warnf(global, "no multipart to terminate");
            return Err(ParameterError::BadUse);
        }
        group_at_mut(root, &path).open = false;
    } else if !content.is_empty() && content[0] == b'@' && !literal_value {
        // ---- One or more file uploads (`@a,b,c`). ----
        let mut pos = 0usize; // points at '@'
        let mut files: Vec<ToolMime> = Vec::new();
        let mut multi = false;
        let mut first = true;
        loop {
            pos += 1; // skip '@' (first iteration) or ',' (subsequent)
            let pp = get_param_part(
                global,
                content,
                &mut pos,
                b',',
                Allowed {
                    typ: true,
                    filename: true,
                    encoder: true,
                    headers: true,
                },
            )?;
            let sep = pp.sep;
            if first {
                // A trailing comma on the first file means there is more than
                // one file, which must be grouped into a nested multipart.
                multi = sep == b',';
                first = false;
            }
            let mut node = make_filedata(&bytes_to_string(&pp.data), true);
            node.headers = pp.headers;
            node.filename = pp.filename;
            node.content_type = pp.content_type;
            node.encoder = pp.encoder;
            files.push(node);
            if sep == 0 {
                break;
            }
        }
        let group = group_at_mut(root, &path);
        if multi {
            // Multiple files: bundle them in a nested (closed) multipart and put
            // the field name on the group.
            let mut grp = ToolMime::new_parts_closed();
            grp.subparts = files;
            grp.name = name;
            group.subparts.push(grp);
        } else {
            // Exactly one file: the field name goes on the file itself.
            let mut node = files.pop().expect("at least one file part");
            node.name = name;
            group.subparts.push(node);
        }
    } else {
        // ---- `<file`/`<-` data-from-file, or literal data. ----
        let mut content_type: Option<String> = None;
        let mut filename: Option<String> = None;
        let mut encoder: Option<String> = None;
        let mut headers: Vec<String> = Vec::new();
        let mut sep: u8 = 0;
        let mut garbage_from: usize = 0;

        let mut node = if !content.is_empty() && content[0] == b'<' && !literal_value {
            // Data read from a file (filename is not sent).
            let mut pos = 1usize; // skip '<'
            let pp = get_param_part(
                global,
                content,
                &mut pos,
                0,
                Allowed {
                    typ: true,
                    filename: false,
                    encoder: true,
                    headers: true,
                },
            )?;
            sep = pp.sep;
            garbage_from = pos;
            content_type = pp.content_type;
            encoder = pp.encoder;
            headers = pp.headers;
            make_filedata(&bytes_to_string(&pp.data), false)
        } else if literal_value {
            // `--form-string`: the entire content is literal data.
            ToolMime::new_data(content.to_vec())
        } else {
            // Literal data with optional metadata blocks.
            let mut pos = 0usize;
            let pp = get_param_part(
                global,
                content,
                &mut pos,
                0,
                Allowed {
                    typ: true,
                    filename: true,
                    encoder: true,
                    headers: true,
                },
            )?;
            sep = pp.sep;
            garbage_from = pos;
            content_type = pp.content_type;
            filename = pp.filename;
            encoder = pp.encoder;
            headers = pp.headers;
            ToolMime::new_data(pp.data)
        };

        node.headers = headers;
        node.filename = filename;
        node.content_type = content_type;
        node.encoder = encoder;
        node.name = name;

        if sep != 0 {
            let rest = String::from_utf8_lossy(&content[garbage_from..]).into_owned();
            warnf(
                global,
                &format!("garbage at end of field specification: {rest}"),
            );
        }

        group_at_mut(root, &path).subparts.push(node);
    }

    Ok(())
}

// ===========================================================================
// Phase C — Conversion to a `curl_rs_lib` MIME object
// ===========================================================================

/// A [`curl_rs_lib::mime::MimeDataReader`] over an in-memory buffer, used to
/// stream buffered standard input into a MIME part.
///
/// curl streams stdin either live (a seekable regular file) or from a buffer (a
/// pipe). This port always buffers stdin, which yields a byte-identical part
/// body and a known size while supporting the rewind the transfer engine may
/// request on retry — and avoids any `unsafe`/`fstat` to probe seekability.
struct BufStdinReader {
    data: Vec<u8>,
    pos: usize,
}

impl curl_rs_lib::mime::MimeDataReader for BufStdinReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.data.len() - self.pos;
        let n = remaining.min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    fn rewind(&mut self) -> io::Result<()> {
        self.pos = 0;
        Ok(())
    }
}

/// Truncate `data` at the first NUL byte, reproducing curl's use of
/// `CURL_ZERO_TERMINATED` for literal `curl_mime_data` content.
fn zero_terminated(data: &[u8]) -> &[u8] {
    match data.iter().position(|&b| b == 0) {
        Some(i) => &data[..i],
        None => data,
    }
}

/// Recursively add `parts` (in CLI order) to `mime`. Mirrors `tool2curlparts`,
/// including the per-part metadata application order
/// (`filename` → `type` → `headers` → `encoder` → `name`), which is reproduced
/// exactly so the emitted multipart headers are byte-identical to curl's.
fn build_parts(parts: &[ToolMime], mime: &mut Mime) -> Result<(), CurlError> {
    for m in parts {
        // Build a nested group's sub-MIME first, so we do not borrow `mime`
        // mutably while also adding the parent part.
        let submime = if m.kind == ToolMimeKind::Parts {
            let mut sm = Mime::new()?;
            build_parts(&m.subparts, &mut sm)?;
            Some(sm)
        } else {
            None
        };

        let part = mime.addpart();

        // The filename actually applied after content is set. STDIN (`@-`)
        // defaults to "-" when no explicit filename was given.
        let mut effective_filename: Option<&[u8]> = m.filename.as_deref().map(str::as_bytes);

        match m.kind {
            ToolMimeKind::Parts => {
                part.set_subparts(submime)?;
            }
            ToolMimeKind::Data => {
                let bytes = m.data.as_deref().unwrap_or(&[]);
                part.set_data(zero_terminated(bytes))?;
            }
            ToolMimeKind::File | ToolMimeKind::FileData => {
                if let Some(path) = &m.filepath {
                    // curl defers a missing/unreadable file to transfer time;
                    // swallow the stat error here exactly as `tool2curlparts`
                    // maps CURLE_READ_ERROR back to CURLE_OK. The path is still
                    // recorded on the part by `set_filedata`.
                    match part.set_filedata(path) {
                        Ok(_) | Err(CurlError::ReadError) => {}
                        Err(e) => return Err(e),
                    }
                }
                if m.kind == ToolMimeKind::FileData && m.filename.is_none() {
                    // `<file` does not send a filename: clear the basename that
                    // `set_filedata` auto-applied.
                    part.set_filename(None)?;
                }
            }
            ToolMimeKind::Stdin | ToolMimeKind::StdinData => {
                // Buffer all of standard input, then stream it back through the
                // callback with a known length (see `BufStdinReader`).
                let mut buf = Vec::new();
                io::stdin()
                    .read_to_end(&mut buf)
                    .map_err(|_| CurlError::ReadError)?;
                let size = buf.len() as i64;
                part.set_data_cb(size, Box::new(BufStdinReader { data: buf, pos: 0 }))?;
                if m.kind == ToolMimeKind::Stdin && m.filename.is_none() {
                    effective_filename = Some(b"-");
                }
            }
            ToolMimeKind::None => {}
        }

        // Apply metadata in curl's order; calling order matters for
        // byte-identical multipart headers.
        if let Some(fname) = effective_filename {
            part.set_filename(Some(fname))?;
        }
        if let Some(ct) = &m.content_type {
            part.set_type(Some(ct.as_bytes()))?;
        }
        if !m.headers.is_empty() {
            let mut list = SList::new();
            for h in &m.headers {
                list.append(h)?;
            }
            part.set_headers(Some(list), true)?;
        }
        if let Some(enc) = &m.encoder {
            part.set_encoder(Some(enc))?;
        }
        if let Some(name) = &m.name {
            part.set_name(Some(name.as_bytes()))?;
        }
    }
    Ok(())
}

/// Translate the intermediate [`ToolMime`] `root` into a [`curl_rs_lib::Mime`]
/// bound to `easy`. Mirrors `tool2curlmime`: create the MIME object and add the
/// root's children as top-level parts in CLI order.
///
/// `easy` is accepted for API parity with curl (where the `curl_mime` is created
/// from, and tied to, the easy handle); the Rust [`Mime`] owns its parts
/// independently, so the handle is not otherwise consulted here.
///
/// # Errors
///
/// Returns the first [`CurlError`] produced while building the tree (for
/// example, an invalid `;encoder=` name yields [`CurlError::BadFunctionArgument`],
/// matching `curl_mime_encoder`).
pub fn build_mime(easy: &mut Easy, root: &ToolMime) -> Result<Mime, CurlError> {
    // The handle is intentionally unused beyond parity; bind it to silence the
    // unused-variable lint without changing the public signature.
    let _ = easy;
    let mut mime = Mime::new()?;
    build_parts(&root.subparts, &mut mime)?;
    Ok(mime)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A silent `GlobalConfig` (so warning output does not clutter test logs)
    /// paired with a fresh `OperationConfig`.
    fn cfg() -> (GlobalConfig, OperationConfig) {
        let g = GlobalConfig {
            silent: true,
            ..GlobalConfig::default()
        };
        (g, OperationConfig::default())
    }

    const ALL: Allowed = Allowed {
        typ: true,
        filename: true,
        encoder: true,
        headers: true,
    };

    fn root_of(config: &OperationConfig) -> &ToolMime {
        config.mimeroot.as_ref().expect("mimeroot built")
    }

    // ---- name=content splitting ------------------------------------------

    #[test]
    fn name_value_split_makes_named_data_part() {
        let (g, mut c) = cfg();
        formparse(&g, &mut c, "field=value", false).unwrap();
        let root = root_of(&c);
        assert_eq!(root.subparts.len(), 1);
        let p = &root.subparts[0];
        assert_eq!(p.kind, ToolMimeKind::Data);
        assert_eq!(p.name.as_deref(), Some("field"));
        assert_eq!(p.data.as_deref(), Some(b"value".as_ref()));
    }

    #[test]
    fn empty_name_yields_no_name() {
        let (g, mut c) = cfg();
        formparse(&g, &mut c, "=value", false).unwrap();
        let p = &root_of(&c).subparts[0];
        assert_eq!(p.kind, ToolMimeKind::Data);
        assert_eq!(p.name, None);
        assert_eq!(p.data.as_deref(), Some(b"value".as_ref()));
    }

    #[test]
    fn missing_equals_is_bad_use() {
        let (g, mut c) = cfg();
        let err = formparse(&g, &mut c, "noequals", false).unwrap_err();
        assert_eq!(err, ParameterError::BadUse);
    }

    // ---- --form-string literal mode --------------------------------------

    #[test]
    fn form_string_suppresses_special_chars() {
        let (g, mut c) = cfg();
        // With literal_value, a leading '@' must NOT mean "file".
        formparse(&g, &mut c, "field=@notafile;type=x", true).unwrap();
        let p = &root_of(&c).subparts[0];
        assert_eq!(p.kind, ToolMimeKind::Data);
        // The entire content is literal data — including the ';type=x'.
        assert_eq!(p.data.as_deref(), Some(b"@notafile;type=x".as_ref()));
        assert_eq!(p.content_type, None);
        assert_eq!(p.name.as_deref(), Some("field"));
    }

    // ---- @file uploads ----------------------------------------------------

    #[test]
    fn single_file_upload() {
        let (g, mut c) = cfg();
        formparse(&g, &mut c, "f=@file.txt", false).unwrap();
        let p = &root_of(&c).subparts[0];
        assert_eq!(p.kind, ToolMimeKind::File);
        assert_eq!(p.filepath.as_deref(), Some("file.txt"));
        assert_eq!(p.name.as_deref(), Some("f"));
    }

    #[test]
    fn file_upload_with_type_and_filename() {
        let (g, mut c) = cfg();
        formparse(
            &g,
            &mut c,
            "f=@data;type=text/plain;filename=foo.txt",
            false,
        )
        .unwrap();
        let p = &root_of(&c).subparts[0];
        assert_eq!(p.kind, ToolMimeKind::File);
        assert_eq!(p.filepath.as_deref(), Some("data"));
        assert_eq!(p.content_type.as_deref(), Some("text/plain"));
        assert_eq!(p.filename.as_deref(), Some("foo.txt"));
        assert_eq!(p.name.as_deref(), Some("f"));
    }

    #[test]
    fn multi_file_groups_into_nested_multipart() {
        let (g, mut c) = cfg();
        formparse(&g, &mut c, "f=@a.txt,b.txt", false).unwrap();
        let root = root_of(&c);
        assert_eq!(root.subparts.len(), 1);
        let group = &root.subparts[0];
        assert_eq!(group.kind, ToolMimeKind::Parts);
        assert!(!group.open, "multi-file group must be created closed");
        assert_eq!(group.name.as_deref(), Some("f"), "name goes on the group");
        assert_eq!(group.subparts.len(), 2);
        assert_eq!(group.subparts[0].filepath.as_deref(), Some("a.txt"));
        assert_eq!(group.subparts[1].filepath.as_deref(), Some("b.txt"));
        // Individual files carry no field name.
        assert_eq!(group.subparts[0].name, None);
        assert_eq!(group.subparts[1].name, None);
    }

    // ---- ordering ---------------------------------------------------------

    #[test]
    fn parts_preserve_cli_order() {
        let (g, mut c) = cfg();
        formparse(&g, &mut c, "one=1", false).unwrap();
        formparse(&g, &mut c, "two=2", false).unwrap();
        formparse(&g, &mut c, "three=3", false).unwrap();
        let names: Vec<_> = root_of(&c)
            .subparts
            .iter()
            .map(|p| p.name.clone().unwrap())
            .collect();
        assert_eq!(names, vec!["one", "two", "three"]);
    }

    // ---- open/close multipart grouping -----------------------------------

    #[test]
    fn open_then_close_multipart_routes_content() {
        let (g, mut c) = cfg();
        formparse(&g, &mut c, "group=(", false).unwrap(); // open
        formparse(&g, &mut c, "inner=1", false).unwrap(); // into the group
        formparse(&g, &mut c, "=)", false).unwrap(); // close
        formparse(&g, &mut c, "outer=2", false).unwrap(); // back at root

        let root = root_of(&c);
        assert_eq!(root.subparts.len(), 2);
        let grp = &root.subparts[0];
        assert_eq!(grp.kind, ToolMimeKind::Parts);
        assert_eq!(grp.name.as_deref(), Some("group"));
        assert!(!grp.open, "group should be closed after ')'");
        assert_eq!(grp.subparts.len(), 1);
        assert_eq!(grp.subparts[0].name.as_deref(), Some("inner"));
        assert_eq!(root.subparts[1].name.as_deref(), Some("outer"));
    }

    #[test]
    fn close_without_open_is_bad_use() {
        let (g, mut c) = cfg();
        let err = formparse(&g, &mut c, "=)", false).unwrap_err();
        assert_eq!(err, ParameterError::BadUse);
    }

    // ---- stdin node kinds -------------------------------------------------

    #[test]
    fn stdin_kinds_for_at_and_lt() {
        let (g, mut c1) = cfg();
        formparse(&g, &mut c1, "f=@-", false).unwrap();
        assert_eq!(root_of(&c1).subparts[0].kind, ToolMimeKind::Stdin);

        let mut c2 = OperationConfig::default();
        formparse(&g, &mut c2, "f=<-", false).unwrap();
        assert_eq!(root_of(&c2).subparts[0].kind, ToolMimeKind::StdinData);
    }

    #[test]
    fn lt_file_is_filedata() {
        let (g, mut c) = cfg();
        formparse(&g, &mut c, "f=<data.bin", false).unwrap();
        let p = &root_of(&c).subparts[0];
        assert_eq!(p.kind, ToolMimeKind::FileData);
        assert_eq!(p.filepath.as_deref(), Some("data.bin"));
    }

    // ---- get_param_word ---------------------------------------------------

    #[test]
    fn quoted_word_unescapes() {
        let (g, _) = cfg();
        // Raw bytes: "a\"b\\c"  -> a"b\c
        let input = br#""a\"b\\c""#;
        let mut pos = 0;
        let (w, quoted) = get_param_word(&g, input, &mut pos, 0);
        assert!(quoted);
        assert_eq!(w, b"a\"b\\c");
        assert_eq!(pos, input.len());
    }

    #[test]
    fn unquoted_word_stops_at_semicolon() {
        let (g, _) = cfg();
        let input = b"hello;type=x";
        let mut pos = 0;
        let (w, quoted) = get_param_word(&g, input, &mut pos, 0);
        assert!(!quoted);
        assert_eq!(w, b"hello");
        assert_eq!(input[pos], b';');
    }

    #[test]
    fn missing_close_quote_falls_back_to_unquoted() {
        let (g, _) = cfg();
        let input = b"\"unterminated";
        let mut pos = 0;
        let (w, quoted) = get_param_word(&g, input, &mut pos, 0);
        assert!(!quoted);
        assert_eq!(w, b"\"unterminated");
    }

    // ---- get_param_part ---------------------------------------------------

    #[test]
    fn content_type_continuation_is_joined() {
        let (g, _) = cfg();
        let input = b"v;type=text/plain; charset=utf-8";
        let mut pos = 0;
        let pp = get_param_part(&g, input, &mut pos, 0, ALL).unwrap();
        assert_eq!(pp.data, b"v");
        assert_eq!(
            pp.content_type.as_deref(),
            Some("text/plain; charset=utf-8")
        );
    }

    #[test]
    fn encoder_block_parsed() {
        let (g, _) = cfg();
        let input = b"v;encoder=base64";
        let mut pos = 0;
        let pp = get_param_part(&g, input, &mut pos, 0, ALL).unwrap();
        assert_eq!(pp.encoder.as_deref(), Some("base64"));
    }

    #[test]
    fn unknown_field_is_skipped_not_fatal() {
        let (g, _) = cfg();
        let input = b"v;bogus=stuff;type=text/plain";
        let mut pos = 0;
        let pp = get_param_part(&g, input, &mut pos, 0, ALL).unwrap();
        assert_eq!(pp.data, b"v");
        assert_eq!(pp.content_type.as_deref(), Some("text/plain"));
    }

    // ---- per-part headers -------------------------------------------------

    #[test]
    fn literal_header_value() {
        let (g, mut c) = cfg();
        formparse(&g, &mut c, "a=b;headers=X-Foo: bar", false).unwrap();
        let p = &root_of(&c).subparts[0];
        assert_eq!(p.headers, vec!["X-Foo: bar".to_string()]);
    }

    #[test]
    fn headers_from_file_with_folding_and_comment() {
        let (g, mut c) = cfg();
        let path = std::env::temp_dir().join("fp_hdr_parity_test.txt");
        std::fs::write(
            &path,
            b"X-First: one\n continued\n# a comment line\nX-Second: two\n",
        )
        .unwrap();
        let input = format!("a=b;headers=@{}", path.display());
        formparse(&g, &mut c, &input, false).unwrap();
        let p = &root_of(&c).subparts[0];
        assert_eq!(
            p.headers,
            vec![
                "X-First: one continued".to_string(),
                "X-Second: two".to_string()
            ]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_field_headers_unit() {
        let mut headers = Vec::new();
        read_field_headers(b"# comment\nA: 1\n B-folded\nB: 2\n\n", &mut headers);
        assert_eq!(
            headers,
            vec!["A: 1 B-folded".to_string(), "B: 2".to_string()]
        );
    }

    // ---- trailing garbage is non-fatal -----------------------------------

    #[test]
    fn trailing_garbage_does_not_fail() {
        let (g, mut c) = cfg();
        // A space inside type= breaks the type and leaves trailing garbage,
        // which curl warns about but continues past.
        formparse(&g, &mut c, "a=b;type=text/plain junk", false).unwrap();
        let p = &root_of(&c).subparts[0];
        assert_eq!(p.content_type.as_deref(), Some("text/plain"));
    }

    // ---- build_mime (conversion to curl_rs_lib::Mime) --------------------

    #[test]
    fn build_mime_counts_top_level_parts() {
        let (g, mut c) = cfg();
        formparse(&g, &mut c, "a=1", false).unwrap();
        formparse(&g, &mut c, "b=2", false).unwrap();
        formparse(&g, &mut c, "c=3", false).unwrap();
        let mut easy = Easy::new();
        let mime = build_mime(&mut easy, root_of(&c)).unwrap();
        assert_eq!(mime.len(), 3);
    }

    #[test]
    fn build_mime_nests_multifile_group() {
        let (g, mut c) = cfg();
        formparse(&g, &mut c, "f=@a.txt,b.txt", false).unwrap();
        let mut easy = Easy::new();
        let mime = build_mime(&mut easy, root_of(&c)).unwrap();
        assert_eq!(mime.len(), 1);
        let group_part = mime.iter().next().expect("one part");
        let sub = group_part.subparts().expect("nested multipart");
        assert_eq!(sub.len(), 2);
    }

    #[test]
    fn build_mime_rejects_bad_encoder() {
        let mut root = ToolMime::new_parts_open();
        let mut data = ToolMime::new_data(b"x".to_vec());
        data.name = Some("a".to_string());
        data.encoder = Some("definitely-not-an-encoder".to_string());
        root.subparts.push(data);
        let mut easy = Easy::new();
        // `Mime` does not implement `Debug`, so match instead of `unwrap_err`.
        let result = build_mime(&mut easy, &root);
        assert!(matches!(result, Err(CurlError::BadFunctionArgument)));
    }

    #[test]
    fn build_mime_data_with_known_encoder_ok() {
        let mut root = ToolMime::new_parts_open();
        let mut data = ToolMime::new_data(b"hello".to_vec());
        data.name = Some("a".to_string());
        data.encoder = Some("base64".to_string());
        data.content_type = Some("text/plain".to_string());
        root.subparts.push(data);
        let mut easy = Easy::new();
        let mime = build_mime(&mut easy, &root).unwrap();
        assert_eq!(mime.len(), 1);
    }

    // ---- character class helpers -----------------------------------------

    #[test]
    fn ctype_helpers() {
        assert!(is_blank(b' ') && is_blank(b'\t'));
        assert!(!is_blank(b'\n'));
        assert!(is_space(b' ') && is_space(b'\n') && is_space(b'\r'));
        assert!(!is_space(b'x'));
        assert!(is_tspecial(b';') && is_tspecial(b'=') && is_tspecial(b' '));
        assert!(!is_tspecial(b'a'));
        assert!(checkprefix(b"type=", b"TYPE=foo"));
        assert!(!checkprefix(b"type=", b"typ"));
    }

    #[test]
    fn zero_terminated_truncates_at_nul() {
        assert_eq!(zero_terminated(b"ab\0cd"), b"ab");
        assert_eq!(zero_terminated(b"abcd"), b"abcd");
    }
}
