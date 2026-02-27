// -----------------------------------------------------------------------
// curl-rs/src/formparse.rs — Form Data Parsing
//
// Rust rewrite of src/tool_formparse.c and src/tool_formparse.h from
// curl 8.19.0-DEV.  Parses `-F`/`--form` CLI arguments into a MIME tree
// structure (`ToolMime`) and converts it to the library's `Mime` type for
// multipart form uploads.
//
// # Source Mapping
//
// | Rust function            | C origin                                   |
// |--------------------------|---------------------------------------------|
// | `formparse`              | `formparse()` in `tool_formparse.c:714`     |
// | `tool2curlmime`          | `tool2curlmime()` in `tool_formparse.c:321` |
// | `get_param_word`         | `get_param_word()` :342                     |
// | `get_param_part`         | `get_param_part()` :471                     |
// | `read_field_headers`     | `read_field_headers()` :412                 |
// | `create_filedata_node`   | `tool_mime_new_filedata()` :96              |
// | `tool2curlparts`         | `tool2curlparts()` :253                     |
//
// Zero `unsafe` blocks.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{bail, Result};

use crate::config::{GlobalConfig, ToolMime, ToolMimeKind};
use crate::msgs::{errorf, warnf};
use crate::paramhelp::file2memory;
use curl_rs_lib::mime::{Mime, MimeEncoder};
use curl_rs_lib::slist::SList;
use curl_rs_lib::{CurlError, CurlResult, EasyHandle};

// ---------------------------------------------------------------------------
// Internal character classification helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `b` is a blank character (space or horizontal tab).
///
/// Matches the C `ISBLANK()` macro.
#[inline]
fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Returns `true` if `b` is a whitespace character (space, tab, CR, LF,
/// VT, or FF).
///
/// Matches the C `ISSPACE()` macro used for trailing whitespace stripping
/// in the encoder metadata parsing.
#[inline]
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0B | 0x0C)
}

/// Case-insensitive prefix check.
///
/// Matches the C `checkprefix()` function.
#[inline]
fn check_prefix(haystack: &str, prefix: &str) -> bool {
    haystack.len() >= prefix.len()
        && haystack.as_bytes()[..prefix.len()]
            .eq_ignore_ascii_case(prefix.as_bytes())
}

// ---------------------------------------------------------------------------
// get_param_word — token extraction
// ---------------------------------------------------------------------------

/// Process escape sequences (`\\` and `\"`) in a quoted string,
/// returning the unescaped content.
fn unescape_quoted(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next == b'\\' || next == b'"' {
                result.push(next as char);
                i += 2;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

/// Extract a parameter word from the cursor position.
///
/// This is the Rust equivalent of C `get_param_word()` in
/// `tool_formparse.c` line 342.
///
/// Handles both quoted (`"value"`) and unquoted values.  For quoted
/// strings, `\\` and `\"` escape sequences are processed.
///
/// The cursor is advanced past the word to the separator position.
///
/// # Returns
///
/// `(word, separator)` where `separator` is the byte found after the
/// word: `b';'`, `endchar`, or `0` for end-of-string.
fn get_param_word(cursor: &mut &str, endchar: u8, global: &GlobalConfig) -> (String, u8) {
    let bytes = cursor.as_bytes();
    let len = bytes.len();
    let mut pos: usize = 0;

    // --- Quoted string handling ---
    if pos < len && bytes[pos] == b'"' {
        pos += 1;
        let word_start = pos;
        let mut has_escape = false;

        while pos < len {
            if bytes[pos] == b'\\' && pos + 1 < len {
                let next = bytes[pos + 1];
                if next == b'\\' || next == b'"' {
                    has_escape = true;
                    pos += 2;
                    continue;
                }
            }
            if bytes[pos] == b'"' {
                // Found closing quote — build the unescaped word.
                let word_raw = &cursor[word_start..pos];
                let word = if has_escape {
                    unescape_quoted(word_raw)
                } else {
                    word_raw.to_string()
                };

                pos += 1; // skip closing quote

                // Scan for trailing data before the next separator.
                // Matches C: `while(*ptr && *ptr != ';' && *ptr != endchar)`
                let mut trailing_data = false;
                while pos < len
                    && bytes[pos] != b';'
                    && (endchar == 0 || bytes[pos] != endchar)
                {
                    if !is_space(bytes[pos]) {
                        trailing_data = true;
                    }
                    pos += 1;
                }
                if trailing_data {
                    warnf(global, "Trailing data after quoted form parameter");
                }

                let sep = if pos < len { bytes[pos] } else { 0 };
                *cursor = &cursor[pos..];
                return (word, sep);
            }
            pos += 1;
        }
        // End quote is missing — treat as non-quoted.  Reset to beginning.
        // Matches C: `ptr = word_begin;`
        pos = 0;
    }

    // --- Unquoted string: scan until ';', endchar, or end ---
    while pos < len && bytes[pos] != b';' && (endchar == 0 || bytes[pos] != endchar) {
        pos += 1;
    }

    let sep = if pos < len { bytes[pos] } else { 0 };

    // Strip trailing blanks for unquoted words.
    // Matches C: `while(endpos > *pdata && ISBLANK(endpos[-1])) endpos--;`
    let mut word_end = pos;
    while word_end > 0 && is_blank(bytes[word_end - 1]) {
        word_end -= 1;
    }

    let word = cursor[..word_end].to_string();
    *cursor = &cursor[pos..];
    (word, sep)
}

// ---------------------------------------------------------------------------
// read_field_headers — header file reader
// ---------------------------------------------------------------------------

/// Read headers from a file and return them as a `Vec<String>`.
///
/// Matches the C `read_field_headers()` in `tool_formparse.c` line 412.
///
/// - Lines starting with `#` are comments and skipped.
/// - Lines starting with a space are continuation (folded) lines appended
///   to the previous header.
/// - Trailing CR/LF/whitespace is stripped from each line.
/// - Empty lines (after stripping) are skipped.
fn read_field_headers(path: &str, global: &GlobalConfig) -> Result<Vec<String>> {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            warnf(
                global,
                &format!("Cannot read from {}: {}", path, e),
            );
            return Ok(Vec::new());
        }
    };

    let reader = BufReader::new(file);
    let mut headers: Vec<String> = Vec::new();

    for line_result in reader.lines() {
        let raw_line = match line_result {
            Ok(l) => l,
            Err(_) => break,
        };

        // Skip comments.
        if raw_line.starts_with('#') {
            continue;
        }

        let folded = raw_line.starts_with(' ');

        // Trim trailing CRLF and whitespace.
        let trimmed = raw_line.trim_end();
        if trimmed.is_empty() {
            continue;
        }

        if folded && !headers.is_empty() {
            // Continuation line: append to the previous header.
            // Matches C: `curlx_dyn_add(&amend, l->data); curlx_dyn_addn(…)`
            let last = headers.last_mut().unwrap();
            last.push_str(trimmed);
        } else {
            headers.push(trimmed.to_string());
        }
    }

    Ok(headers)
}

// ---------------------------------------------------------------------------
// FormPartMeta + get_param_part — metadata parsing
// ---------------------------------------------------------------------------

/// Metadata extracted from a form part specification.
///
/// Corresponds to the output parameters of C `get_param_part()`.
struct FormPartMeta {
    /// The data token (file path, literal data, or `(`).
    data: String,
    /// Explicit content-type from `;type=…`.
    content_type: Option<String>,
    /// Explicit filename from `;filename=…`.
    filename: Option<String>,
    /// Explicit encoder from `;encoder=…`.
    encoder: Option<String>,
    /// Per-part headers from `;headers=…` or `;headers=@file`.
    headers: Vec<String>,
    /// The terminating separator character (`0` for end).
    separator: u8,
}

/// Parse a complete form part specification including metadata.
///
/// This is the Rust equivalent of C `get_param_part()` in
/// `tool_formparse.c` line 471.
///
/// The cursor is advanced past the entire part specification.
///
/// `allow_*` flags control which metadata fields are accepted.  If a
/// disallowed field is present, a warning is emitted and the value is
/// discarded (matching C behaviour where a `NULL` output pointer
/// suppresses the corresponding metadata).
fn get_param_part(
    endchar: u8,
    cursor: &mut &str,
    allow_type: bool,
    allow_filename: bool,
    allow_encoder: bool,
    allow_headers: bool,
    global: &GlobalConfig,
) -> Result<FormPartMeta> {
    // Skip leading blanks.
    while !cursor.is_empty() && is_blank(cursor.as_bytes()[0]) {
        *cursor = &cursor[1..];
    }

    let (data, mut sep) = get_param_word(cursor, endchar, global);

    let mut content_type: Option<String> = None;
    let mut filename: Option<String> = None;
    let mut encoder: Option<String> = None;
    let mut headers: Vec<String> = Vec::new();

    // `in_ct` tracks whether we are in the middle of accumulating a
    // multi-token content-type (e.g. `text/html; charset=utf-8`).
    let mut in_ct = false;
    let mut ct_buf = String::new();

    // Process `;key=value` metadata blocks.
    while sep == b';' {
        // Advance past `;`.
        if !cursor.is_empty() {
            *cursor = &cursor[1..];
        }
        // Skip blanks after `;`.
        while !cursor.is_empty() && is_blank(cursor.as_bytes()[0]) {
            *cursor = &cursor[1..];
        }

        if !in_ct && check_prefix(cursor, "type=") {
            // --- type= ---
            *cursor = &cursor[5..];
            while !cursor.is_empty() && is_blank(cursor.as_bytes()[0]) {
                *cursor = &cursor[1..];
            }

            // Scan the initial content-type token.
            // Matches C: `tlen = strcspn(p, "()<>@,;:\\\"[]?=\r\n ");`
            let ct_bytes = cursor.as_bytes();
            let mut tlen: usize = 0;
            while tlen < ct_bytes.len() {
                match ct_bytes[tlen] {
                    b'(' | b')' | b'<' | b'>' | b'@' | b',' | b';' | b':'
                    | b'\\' | b'"' | b'[' | b']' | b'?' | b'=' | b'\r'
                    | b'\n' | b' ' => break,
                    _ => tlen += 1,
                }
            }

            ct_buf = cursor[..tlen].to_string();
            in_ct = true;
            *cursor = &cursor[tlen..];
            sep = if !cursor.is_empty() {
                cursor.as_bytes()[0]
            } else {
                0
            };
        } else if check_prefix(cursor, "filename=") {
            // --- filename= ---
            if in_ct {
                content_type = Some(ct_buf.trim_end().to_string());
                ct_buf.clear();
                in_ct = false;
            }
            *cursor = &cursor[9..];
            while !cursor.is_empty() && is_blank(cursor.as_bytes()[0]) {
                *cursor = &cursor[1..];
            }
            let (fname, new_sep) = get_param_word(cursor, endchar, global);
            filename = Some(fname);
            sep = new_sep;
        } else if check_prefix(cursor, "headers=") {
            // --- headers= ---
            if in_ct {
                content_type = Some(ct_buf.trim_end().to_string());
                ct_buf.clear();
                in_ct = false;
            }
            *cursor = &cursor[8..];

            if !cursor.is_empty()
                && (cursor.as_bytes()[0] == b'@' || cursor.as_bytes()[0] == b'<')
            {
                // Read headers from a file.
                *cursor = &cursor[1..];
                while !cursor.is_empty() && is_blank(cursor.as_bytes()[0]) {
                    *cursor = &cursor[1..];
                }
                let (hdrfile, new_sep) = get_param_word(cursor, endchar, global);
                sep = new_sep;

                match read_field_headers(&hdrfile, global) {
                    Ok(hdrs) => headers.extend(hdrs),
                    Err(_) => {
                        errorf(global, "Out of memory for field headers");
                        bail!("Failed to read headers from {}", hdrfile);
                    }
                }
            } else {
                // Inline header value.
                while !cursor.is_empty() && is_blank(cursor.as_bytes()[0]) {
                    *cursor = &cursor[1..];
                }
                let (hdr, new_sep) = get_param_word(cursor, endchar, global);
                sep = new_sep;
                if !hdr.is_empty() {
                    headers.push(hdr);
                }
            }
        } else if check_prefix(cursor, "encoder=") {
            // --- encoder= ---
            if in_ct {
                content_type = Some(ct_buf.trim_end().to_string());
                ct_buf.clear();
                in_ct = false;
            }
            *cursor = &cursor[8..];
            while !cursor.is_empty() && is_blank(cursor.as_bytes()[0]) {
                *cursor = &cursor[1..];
            }
            let (enc, new_sep) = get_param_word(cursor, endchar, global);
            sep = new_sep;
            // Strip trailing spaces (C uses ISSPACE for encoder).
            let trimmed = enc.trim_end().to_string();
            encoder = Some(trimmed);
        } else if in_ct {
            // Continuation of content-type (e.g. `; charset=utf-8`).
            // Matches C: scan until `;` or endchar, tracking last
            // non-blank position as the effective end.
            let start = cursor.as_bytes();
            let mut pos: usize = 0;
            let mut last_nonblank: usize = 0;
            while pos < start.len()
                && start[pos] != b';'
                && (endchar == 0 || start[pos] != endchar)
            {
                if !is_blank(start[pos]) {
                    last_nonblank = pos + 1;
                }
                pos += 1;
            }
            ct_buf.push(';');
            if last_nonblank > 0 {
                ct_buf.push_str(&cursor[..last_nonblank]);
            }
            sep = if pos < start.len() { start[pos] } else { 0 };
            *cursor = &cursor[pos..];
        } else {
            // Unknown prefix — skip to next block.
            let (unknown, new_sep) = get_param_word(cursor, endchar, global);
            sep = new_sep;
            if !unknown.is_empty() {
                warnf(
                    global,
                    &format!("skip unknown form field: {}", unknown),
                );
            }
        }
    }

    // Finalize content-type if still accumulating.
    if in_ct && !ct_buf.is_empty() {
        content_type = Some(ct_buf.trim_end().to_string());
    }

    // Warn about disallowed fields and discard their values.
    if !allow_type {
        if let Some(ref t) = content_type {
            warnf(
                global,
                &format!("Field content type not allowed here: {}", t),
            );
        }
        content_type = None;
    }
    if !allow_filename {
        if let Some(ref f) = filename {
            warnf(
                global,
                &format!("Field filename not allowed here: {}", f),
            );
        }
        filename = None;
    }
    if !allow_encoder {
        if let Some(ref e) = encoder {
            warnf(
                global,
                &format!("Field encoder not allowed here: {}", e),
            );
        }
        encoder = None;
    }
    if !allow_headers && !headers.is_empty() {
        warnf(
            global,
            &format!("Field headers not allowed here: {}", headers[0]),
        );
        headers.clear();
    }

    Ok(FormPartMeta {
        data,
        content_type,
        filename,
        encoder,
        headers,
        separator: sep,
    })
}

// ---------------------------------------------------------------------------
// Tree navigation helper
// ---------------------------------------------------------------------------

/// Navigate to the current MIME container at the specified nesting depth.
///
/// - `depth == 0` → returns the root node itself.
/// - `depth == 1` → returns the last subpart of root (must be a `Parts`
///   node).
/// - `depth == n` → recursively follows the last subpart at each level.
///
/// Returns `None` if the tree structure is invalid at any level.
fn get_current_node_mut(root: &mut ToolMime, depth: usize) -> Option<&mut ToolMime> {
    let mut current = root;
    for _ in 0..depth {
        current = current.subparts.last_mut()?;
    }
    Some(current)
}

// ---------------------------------------------------------------------------
// File/stdin node creation
// ---------------------------------------------------------------------------

/// Create a `ToolMime` node for file data or standard input.
///
/// This is the Rust equivalent of C `tool_mime_new_filedata()` in
/// `tool_formparse.c` line 96.
///
/// - For regular files (not `"-"`): creates a `File` or `FileData` node
///   with the file path stored in `data`.
/// - For stdin (`"-"`): buffers the entire stdin content via
///   [`file2memory`] and stores it in `data`.  The `origin` field is
///   set to `Some("-")` for file-upload semantics (`@-`) to distinguish
///   from data-inclusion semantics (`<-`).
///
/// # Arguments
///
/// * `filename` — The file path, or `"-"` for stdin.
/// * `is_remote_file` — `true` when the file was referenced via `@`
///   (upload semantics), `false` for `<` (content-inclusion semantics).
/// * `global` — Global configuration for diagnostic output.
///
/// # Returns
///
/// `(node, had_read_error)` — the `ToolMime` node and a flag indicating
/// whether a read error occurred during stdin buffering.
fn create_filedata_node(
    filename: &str,
    is_remote_file: bool,
    _global: &GlobalConfig,
) -> Result<(ToolMime, bool)> {
    if filename != "-" {
        // --- Regular file ---
        let kind = if is_remote_file {
            ToolMimeKind::File
        } else {
            ToolMimeKind::FileData
        };
        let mut node = ToolMime::new(kind);
        node.data = Some(filename.to_string());
        Ok((node, false))
    } else {
        // --- Standard input ---
        // Always buffer stdin content to support non-seekable sources
        // (pipes, sockets).  For seekable stdin (regular file redirected),
        // this trades a small efficiency loss for implementation simplicity
        // and zero `unsafe` code.
        match file2memory("-") {
            Ok(bytes) => {
                let content = String::from_utf8(bytes).unwrap_or_else(|e| {
                    String::from_utf8_lossy(e.as_bytes()).into_owned()
                });
                let mut node = ToolMime::new(ToolMimeKind::Stdin);
                node.data = if content.is_empty() {
                    Some(String::new())
                } else {
                    Some(content)
                };
                if is_remote_file {
                    // Mark as file-upload semantics: tool2curlmime will
                    // default the filename to "-" if no explicit override.
                    node.origin = Some("-".to_string());
                }
                Ok((node, false))
            }
            Err(_) => {
                // Read error — create the node but flag the error.
                // The caller decides whether to fail or defer based on
                // whether any data was already read (matching C behaviour).
                let mut node = ToolMime::new(ToolMimeKind::Stdin);
                if is_remote_file {
                    node.origin = Some("-".to_string());
                }
                Ok((node, true))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// formparse — main form parsing entry point
// ---------------------------------------------------------------------------

/// Parse a single `-F`/`--form` argument into the MIME tree.
///
/// This is the Rust equivalent of C `formparse()` in `tool_formparse.c`
/// line 714.
///
/// The function is called once per `-F` argument.  State is maintained
/// across calls via `mimeroot` (the tree root) and `mimecurrent` (the
/// nesting depth, where `0` = root level).
///
/// # Arguments
///
/// * `input` — The raw `-F` argument string (e.g. `"name=value"`,
///   `"file=@path"`, `"=("`).
/// * `mimeroot` — Mutable reference to the root of the MIME tree.
///   `None` on the first call; initialized automatically.
/// * `mimecurrent` — Mutable reference to the current nesting depth.
///   `None` on the first call; set to `Some(0)` after initialization.
/// * `literal_value` — When `true` (from `--form-string`), suppresses
///   special interpretation of `@`, `<`, `(`, `)`, and metadata.
/// * `global` — Global configuration for diagnostic output.
///
/// # Errors
///
/// Returns an error for malformed input, memory allocation failure, or
/// read errors on stdin.
pub fn formparse(
    input: &str,
    mimeroot: &mut Option<ToolMime>,
    mimecurrent: &mut Option<usize>,
    literal_value: bool,
    global: &GlobalConfig,
) -> Result<()> {
    // --- Initialize root if needed ---
    // Matches C: `if(!*mimecurrent) { *mimeroot = tool_mime_new_parts(NULL); }`
    if mimecurrent.is_none() {
        *mimeroot = Some(ToolMime::new(ToolMimeKind::Parts));
        *mimecurrent = Some(0);
    }

    let root = mimeroot
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("MIME root is unexpectedly None"))?;
    let depth = mimecurrent
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("MIME current depth is unexpectedly None"))?;

    // --- Find the '=' separator ---
    let eq_pos = match input.find('=') {
        Some(pos) => pos,
        None => {
            warnf(global, "Illegally formatted input field");
            bail!("Illegally formatted input field");
        }
    };

    // Name is everything before '='; empty prefix means no name.
    let name: Option<String> = if eq_pos > 0 {
        Some(input[..eq_pos].to_string())
    } else {
        None
    };

    // Content starts after '='.
    let content = &input[eq_pos + 1..];
    let mut cursor: &str = content;

    // === Case 1: Starting a multipart group `name=(` ===
    if cursor.starts_with('(') && !literal_value {
        let meta = get_param_part(
            0,     // endchar = '\0' (no additional terminator)
            &mut cursor,
            true,  // allow type
            false, // disallow filename
            false, // disallow encoder
            true,  // allow headers
            global,
        )?;

        let current_node = get_current_node_mut(root, *depth)
            .ok_or_else(|| anyhow::anyhow!("Invalid MIME tree structure at depth {}", *depth))?;

        let mut new_parts = ToolMime::new(ToolMimeKind::Parts);
        new_parts.headers = meta.headers;
        if let Some(ct) = meta.content_type {
            new_parts.content_type = Some(ct);
        }
        if let Some(ref n) = name {
            new_parts.name = Some(n.clone());
        }

        current_node.subparts.push(new_parts);
        *depth += 1;

    // === Case 2: Ending a multipart group `=)` ===
    } else if name.is_none() && cursor == ")" && !literal_value {
        if *depth == 0 {
            warnf(global, "no multipart to terminate");
            bail!("no multipart to terminate");
        }
        *depth -= 1;

    // === Case 3: File upload `name=@filename[,filename2,...]` ===
    } else if cursor.starts_with('@') && !literal_value {
        cursor = &cursor[1..]; // skip '@'

        // Track whether we needed a sub-container for multiple files.
        let mut subparts_created = false;
        let mut use_subcontainer = false;

        loop {
            let meta = get_param_part(
                b',',  // endchar = ',' (comma separates multiple files)
                &mut cursor,
                true, true, true, true, // allow all metadata
                global,
            )?;

            // Determine whether a sub-container is needed (multiple files).
            if !subparts_created {
                if meta.separator == b',' {
                    // More files follow — create a multipart sub-container.
                    let current_node = get_current_node_mut(root, *depth)
                        .ok_or_else(|| anyhow::anyhow!("Invalid MIME tree depth"))?;
                    current_node
                        .subparts
                        .push(ToolMime::new(ToolMimeKind::Parts));
                    use_subcontainer = true;
                }
                subparts_created = true;
            }

            // Build the file part node.
            let (mut node, had_error) =
                create_filedata_node(&meta.data, true, global)?;
            node.headers = meta.headers;

            if had_error {
                // Read error on stdin.  If data is empty, defer the error
                // until libcurl processes the part.  Otherwise, fail now.
                let data_is_empty = node
                    .data
                    .as_ref()
                    .map_or(true, |d| d.is_empty());
                if !data_is_empty {
                    warnf(global, "error while reading standard input");
                    bail!("error while reading standard input");
                }
                // Defer error: clear data and let libcurl handle it.
                node.data = None;
            }

            if let Some(f) = meta.filename {
                node.filename = Some(f);
            }
            if let Some(ct) = meta.content_type {
                node.content_type = Some(ct);
            }
            if let Some(enc) = meta.encoder {
                node.encoder = Some(enc);
            }

            // Insert into the correct container.
            if use_subcontainer {
                let current_node = get_current_node_mut(root, *depth)
                    .ok_or_else(|| anyhow::anyhow!("Invalid MIME tree depth"))?;
                let sub = current_node.subparts.last_mut()
                    .ok_or_else(|| anyhow::anyhow!("Missing subcontainer"))?;
                sub.subparts.push(node);
            } else {
                let current_node = get_current_node_mut(root, *depth)
                    .ok_or_else(|| anyhow::anyhow!("Invalid MIME tree depth"))?;
                current_node.subparts.push(node);
            }

            // Continue to next file if comma-separated.
            if meta.separator != b',' {
                break;
            }
            // Advance past the comma.
            if !cursor.is_empty() && cursor.as_bytes()[0] == b',' {
                cursor = &cursor[1..];
            }
        }

        // Set name on the group (the last top-level child).
        if let Some(ref n) = name {
            let current_node = get_current_node_mut(root, *depth)
                .ok_or_else(|| anyhow::anyhow!("Invalid MIME tree depth"))?;
            if let Some(last) = current_node.subparts.last_mut() {
                last.name = Some(n.clone());
            }
        }

    // === Case 4: File content inclusion or literal data ===
    } else {
        let mut trailing_sep: u8 = 0;
        let part_node: ToolMime;

        if cursor.starts_with('<') && !literal_value {
            // --- File content inclusion `name=<filename` ---
            cursor = &cursor[1..];
            let meta = get_param_part(
                0,     // endchar = '\0'
                &mut cursor,
                true,  // allow type
                false, // disallow filename
                true,  // allow encoder
                true,  // allow headers
                global,
            )?;
            trailing_sep = meta.separator;

            let (mut node, had_error) =
                create_filedata_node(&meta.data, false, global)?;
            node.headers = meta.headers;

            if had_error {
                let data_is_empty = node
                    .data
                    .as_ref()
                    .map_or(true, |d| d.is_empty());
                if !data_is_empty {
                    warnf(global, "error while reading standard input");
                    bail!("error while reading standard input");
                }
                node.data = None;
            }

            if let Some(ct) = meta.content_type {
                node.content_type = Some(ct);
            }
            if let Some(enc) = meta.encoder {
                node.encoder = Some(enc);
            }

            part_node = node;
        } else {
            // --- Literal data `name=value` ---
            if literal_value {
                // In literal mode, the entire content is the data.
                let mut node = ToolMime::new(ToolMimeKind::Data);
                node.data = Some(cursor.to_string());
                part_node = node;
            } else {
                let meta = get_param_part(
                    0,    // endchar = '\0'
                    &mut cursor,
                    true, true, true, true, // allow all metadata
                    global,
                )?;
                trailing_sep = meta.separator;

                let mut node = ToolMime::new(ToolMimeKind::Data);
                node.data = Some(meta.data);
                node.headers = meta.headers;

                if let Some(f) = meta.filename {
                    node.filename = Some(f);
                }
                if let Some(ct) = meta.content_type {
                    node.content_type = Some(ct);
                }
                if let Some(enc) = meta.encoder {
                    node.encoder = Some(enc);
                }

                part_node = node;
            }
        }

        // Insert node and set name.
        let current_node = get_current_node_mut(root, *depth)
            .ok_or_else(|| anyhow::anyhow!("Invalid MIME tree depth"))?;

        let mut final_node = part_node;
        if let Some(ref n) = name {
            final_node.name = Some(n.clone());
        }

        current_node.subparts.push(final_node);

        // Warn about garbage after the field specification.
        if trailing_sep != 0 {
            warnf(
                global,
                &format!("garbage at end of field specification: {}", cursor),
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// tool2curlmime — MIME tree conversion
// ---------------------------------------------------------------------------

/// Recursively convert `ToolMime` child nodes into `Mime` parts.
///
/// This is the Rust equivalent of C `tool2curlparts()` in
/// `tool_formparse.c` line 253.
///
/// The children of `parent` are iterated in forward order (matching
/// the C reverse-linked-list recursion which restores original order).
#[allow(clippy::only_used_in_recursion)]
fn tool2curlparts(
    parent: &ToolMime,
    mime: &mut Mime,
    easy: &EasyHandle,
) -> CurlResult<()> {
    for child in &parent.subparts {
        let part = mime.add_part();

        match child.kind {
            ToolMimeKind::Parts => {
                // Nested multipart container — recurse.
                let mut submime = Mime::new();
                tool2curlparts(child, &mut submime, easy)?;
                part.set_subparts(submime)?;
            }

            ToolMimeKind::Data => {
                // Literal data content.
                if let Some(ref data) = child.data {
                    part.set_data_string(data);
                }
            }

            ToolMimeKind::File => {
                // File upload — set_file auto-sets the filename to the
                // file's basename (matching C `curl_mime_filedata`).
                if let Some(ref data) = child.data {
                    part.set_file(Path::new(data))?;
                }
            }

            ToolMimeKind::FileData => {
                // File content inclusion — include data without setting
                // a filename.  We read the file content and use set_data
                // rather than set_file (which would auto-set filename).
                // This matches the C pattern of calling
                // `curl_mime_filedata` + `curl_mime_filename(part, NULL)`.
                if let Some(ref data) = child.data {
                    let content =
                        fs::read(data).map_err(|_| CurlError::ReadError)?;
                    part.set_data(&content);
                }
            }

            ToolMimeKind::Stdin => {
                // Standard input data.
                if let Some(ref data) = child.data {
                    // Buffered stdin content.
                    part.set_data(data.as_bytes());
                } else {
                    // No buffered content — set up a stdin reader.
                    // This handles the case where buffering was deferred
                    // (e.g. read error detected but size was 0).
                    let stdin_reader =
                        Box::new(std::io::stdin());
                    part.set_data_callback(stdin_reader, None);
                }

                // For file-upload semantics (`@-`), default filename to
                // "-" if no explicit override was provided.
                // Matches C: `case TOOLMIME_STDIN: if(!filename) filename = "-";`
                if child.origin.is_some() && child.filename.is_none() {
                    part.set_filename("-");
                }
            }
        }

        // --- Apply metadata (common to all kinds) ---

        // Explicit filename override.
        if let Some(ref filename) = child.filename {
            part.set_filename(filename);
        }

        // Content-Type.
        if let Some(ref ct) = child.content_type {
            part.set_type(ct);
        }

        // Per-part custom headers.
        if !child.headers.is_empty() {
            let mut slist = SList::new();
            for h in &child.headers {
                slist.append(h);
            }
            part.set_headers(slist);
        }

        // Content-Transfer-Encoding.
        if let Some(ref enc_name) = child.encoder {
            if let Some(enc) = MimeEncoder::from_name(enc_name) {
                part.set_encoder(enc);
            }
        }

        // Part name.
        if let Some(ref name) = child.name {
            part.set_name(name);
        }
    }

    Ok(())
}

/// Convert a `ToolMime` tree into a libcurl-compatible `Mime` structure.
///
/// This is the Rust equivalent of C `tool2curlmime()` in
/// `tool_formparse.c` line 321.
///
/// Creates a new `Mime` instance and recursively populates it from the
/// `ToolMime` tree's subparts.
///
/// # Arguments
///
/// * `root` — The root `ToolMime` node (always `ToolMimeKind::Parts`).
/// * `easy` — The `EasyHandle` associated with this transfer (kept in the
///   signature for API compatibility with the C `tool2curlmime(CURL*, …)`).
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] if MIME structure allocation fails,
/// or [`CurlError::ReadError`] if a file-backed part cannot be read.
pub fn tool2curlmime(root: &ToolMime, easy: &EasyHandle) -> CurlResult<Mime> {
    let mut mime = Mime::new();
    tool2curlparts(root, &mut mime, easy)?;
    Ok(mime)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        GlobalConfig, OperationConfig, TerminalState, ToolMime, ToolMimeKind,
        TraceType, TransferState, PARALLEL_DEFAULT,
    };
    use crate::libinfo::LibCurlInfo;

    /// Helper: create a minimal GlobalConfig for testing.
    ///
    /// This constructs a `GlobalConfig` without calling `globalconf_init()`
    /// (which triggers library initialization), making tests fast and
    /// self-contained.
    fn test_global() -> GlobalConfig {
        GlobalConfig {
            state: TransferState::new(),
            trace_dump: None,
            trace_stream: None,
            libcurl: None,
            ssl_sessions: None,
            variables: Vec::new(),
            configs: vec![OperationConfig::new()],
            current: 0,
            ms_per_transfer: 0,
            tracetype: TraceType::None,
            progressmode: 0,
            parallel_host: 0,
            parallel_max: PARALLEL_DEFAULT,
            verbosity: 0,
            parallel: false,
            parallel_connect: false,
            fail_early: false,
            styled_output: false,
            trace_fopened: false,
            tracetime: false,
            traceids: false,
            showerror: false,
            silent: true, // suppress diagnostic output in tests
            noprogress: false,
            isatty: false,
            trace_set: false,
            libcurl_info: LibCurlInfo::default(),
            term: TerminalState::new(),
            libcurl_version: None,
        }
    }

    #[test]
    fn test_is_blank() {
        assert!(is_blank(b' '));
        assert!(is_blank(b'\t'));
        assert!(!is_blank(b'a'));
        assert!(!is_blank(b'\n'));
    }

    #[test]
    fn test_is_space() {
        assert!(is_space(b' '));
        assert!(is_space(b'\t'));
        assert!(is_space(b'\r'));
        assert!(is_space(b'\n'));
        assert!(!is_space(b'a'));
    }

    #[test]
    fn test_check_prefix() {
        assert!(check_prefix("type=text/html", "type="));
        assert!(check_prefix("Type=text/html", "type="));
        assert!(check_prefix("TYPE=text/html", "type="));
        assert!(!check_prefix("typ=text/html", "type="));
        assert!(!check_prefix("", "type="));
    }

    #[test]
    fn test_unescape_quoted() {
        assert_eq!(unescape_quoted("hello"), "hello");
        assert_eq!(unescape_quoted(r#"he\"llo"#), "he\"llo");
        assert_eq!(unescape_quoted(r"he\\llo"), "he\\llo");
        assert_eq!(unescape_quoted(r#"a\\b\"c"#), "a\\b\"c");
    }

    #[test]
    fn test_get_param_word_unquoted() {
        let global = test_global();
        let input = "hello;world";
        let mut cursor: &str = input;
        let (word, sep) = get_param_word(&mut cursor, 0, &global);
        assert_eq!(word, "hello");
        assert_eq!(sep, b';');
        assert_eq!(cursor, ";world");
    }

    #[test]
    fn test_get_param_word_quoted() {
        let global = test_global();
        let input = r#""hello world";next"#;
        let mut cursor: &str = input;
        let (word, sep) = get_param_word(&mut cursor, 0, &global);
        assert_eq!(word, "hello world");
        assert_eq!(sep, b';');
    }

    #[test]
    fn test_get_param_word_endchar() {
        let global = test_global();
        let input = "file1,file2";
        let mut cursor: &str = input;
        let (word, sep) = get_param_word(&mut cursor, b',', &global);
        assert_eq!(word, "file1");
        assert_eq!(sep, b',');
    }

    #[test]
    fn test_get_param_word_trailing_spaces() {
        let global = test_global();
        let input = "hello   ;next";
        let mut cursor: &str = input;
        let (word, sep) = get_param_word(&mut cursor, 0, &global);
        assert_eq!(word, "hello");
        assert_eq!(sep, b';');
    }

    #[test]
    fn test_formparse_simple_value() {
        let global = test_global();
        let mut root: Option<ToolMime> = None;
        let mut depth: Option<usize> = None;

        formparse("name=value", &mut root, &mut depth, false, &global).unwrap();

        let r = root.as_ref().unwrap();
        assert_eq!(r.kind, ToolMimeKind::Parts);
        assert_eq!(r.subparts.len(), 1);
        assert_eq!(r.subparts[0].name.as_deref(), Some("name"));
        assert_eq!(r.subparts[0].data.as_deref(), Some("value"));
        assert_eq!(r.subparts[0].kind, ToolMimeKind::Data);
    }

    #[test]
    fn test_formparse_literal_value() {
        let global = test_global();
        let mut root: Option<ToolMime> = None;
        let mut depth: Option<usize> = None;

        formparse("name=@notafile", &mut root, &mut depth, true, &global).unwrap();

        let r = root.as_ref().unwrap();
        assert_eq!(r.subparts.len(), 1);
        assert_eq!(r.subparts[0].data.as_deref(), Some("@notafile"));
        assert_eq!(r.subparts[0].kind, ToolMimeKind::Data);
    }

    #[test]
    fn test_formparse_multipart_open_close() {
        let global = test_global();
        let mut root: Option<ToolMime> = None;
        let mut depth: Option<usize> = None;

        // Open a multipart group.
        formparse("group=(", &mut root, &mut depth, false, &global).unwrap();
        assert_eq!(depth, Some(1));

        // Add a value inside the group.
        formparse("inner=data", &mut root, &mut depth, false, &global).unwrap();

        // Close the multipart group.
        formparse("=)", &mut root, &mut depth, false, &global).unwrap();
        assert_eq!(depth, Some(0));

        let r = root.as_ref().unwrap();
        assert_eq!(r.subparts.len(), 1);
        assert_eq!(r.subparts[0].kind, ToolMimeKind::Parts);
        assert_eq!(r.subparts[0].name.as_deref(), Some("group"));
        assert_eq!(r.subparts[0].subparts.len(), 1);
        assert_eq!(r.subparts[0].subparts[0].name.as_deref(), Some("inner"));
        assert_eq!(r.subparts[0].subparts[0].data.as_deref(), Some("data"));
    }

    #[test]
    fn test_formparse_no_name() {
        let global = test_global();
        let mut root: Option<ToolMime> = None;
        let mut depth: Option<usize> = None;

        // Empty name — data part with no name.
        formparse("=somedata", &mut root, &mut depth, false, &global).unwrap();

        let r = root.as_ref().unwrap();
        assert_eq!(r.subparts.len(), 1);
        assert!(r.subparts[0].name.is_none());
        assert_eq!(r.subparts[0].data.as_deref(), Some("somedata"));
    }

    #[test]
    fn test_formparse_no_equals() {
        let global = test_global();
        let mut root: Option<ToolMime> = None;
        let mut depth: Option<usize> = None;

        // Should error — no '=' separator.
        assert!(formparse("badformat", &mut root, &mut depth, false, &global).is_err());
    }

    #[test]
    fn test_formparse_metadata_type() {
        let global = test_global();
        let mut root: Option<ToolMime> = None;
        let mut depth: Option<usize> = None;

        formparse("data=hello;type=text/plain", &mut root, &mut depth, false, &global).unwrap();

        let r = root.as_ref().unwrap();
        assert_eq!(r.subparts[0].content_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn test_formparse_close_without_open() {
        let global = test_global();
        let mut root: Option<ToolMime> = None;
        let mut depth: Option<usize> = None;

        // Should error — closing without opening.
        assert!(formparse("=)", &mut root, &mut depth, false, &global).is_err());
    }

    #[test]
    fn test_get_param_word_empty_input() {
        let global = test_global();
        let input = "";
        let mut cursor: &str = input;
        let (word, sep) = get_param_word(&mut cursor, 0, &global);
        assert_eq!(word, "");
        assert_eq!(sep, 0);
    }

    #[test]
    fn test_get_param_word_only_semicolon() {
        let global = test_global();
        let input = ";rest";
        let mut cursor: &str = input;
        let (word, sep) = get_param_word(&mut cursor, 0, &global);
        assert_eq!(word, "");
        assert_eq!(sep, b';');
    }

    #[test]
    fn test_get_current_node_depth_0() {
        let mut root = ToolMime::new(ToolMimeKind::Parts);
        let node = get_current_node_mut(&mut root, 0);
        assert!(node.is_some());
    }

    #[test]
    fn test_get_current_node_depth_1() {
        let mut root = ToolMime::new(ToolMimeKind::Parts);
        root.subparts.push(ToolMime::new(ToolMimeKind::Parts));
        let node = get_current_node_mut(&mut root, 1);
        assert!(node.is_some());
    }

    #[test]
    fn test_get_current_node_invalid_depth() {
        let mut root = ToolMime::new(ToolMimeKind::Parts);
        // No children — depth 1 should return None.
        let node = get_current_node_mut(&mut root, 1);
        assert!(node.is_none());
    }
}
