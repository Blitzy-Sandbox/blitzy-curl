// curl-rs/src/callbacks/header.rs
//
// Header callback implementation for the curl-rs CLI tool.
//
// This module implements the CURLOPT_HEADERFUNCTION callback that processes
// HTTP response headers during transfers. It is the Rust equivalent of the C
// `src/tool_cb_hdr.c` and `src/tool_cb_hdr.h` files.
//
// Responsibilities:
// - Writing received headers to --dump-header output stream
// - Extracting and saving ETag values (--etag-save)
// - Processing Content-Disposition filenames (-J / --remote-header-name)
// - Rendering styled header output with ANSI bold and OSC 8 hyperlinks
// - Buffering headers when Content-Disposition filename resolution is pending
// - Counting response headers for --write-out variable tracking
//
// SPDX-License-Identifier: curl

use std::env;
use std::io::{self, Seek, SeekFrom, Write};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use url::Url;

use crate::config::{GlobalConfig, OperationConfig};
use crate::libinfo;
use crate::msgs;
use crate::terminal;

// ---------------------------------------------------------------------------
// ANSI Terminal Escape Constants
// ---------------------------------------------------------------------------

/// ANSI escape: enable bold text.
const BOLD: &str = "\x1b[1m";

/// ANSI escape: disable bold text.
/// On Windows only the bold attribute is reset; on Unix all attributes are
/// cleared — matching the C `BOLDOFF` constant in `tool_cb_hdr.c`.
#[cfg(windows)]
const BOLDOFF: &str = "\x1b[22m";
#[cfg(not(windows))]
const BOLDOFF: &str = "\x1b[0m";

/// OSC 8 hyperlink start (followed by URL then [`LINKST`]).
const LINK: &str = "\x1b]8;;";

/// String Terminator for OSC 8 sequences.
const LINKST: &str = "\x1b\\";

/// OSC 8 hyperlink end (empty URL + ST).
const LINKOFF: &str = "\x1b]8;;\x1b\\";

/// Minimum VTE version that supports OSC 8 hyperlinks.
///
/// VTE builds older than this value have broken hyperlink rendering; we skip
/// hyperlink output for those terminals — matching the C
/// `getenv("VTE_VERSION")` guard in `tool_cb_hdr.c`.
const VTE_MIN_VERSION: u32 = 5000;

// ---------------------------------------------------------------------------
// OutputStream — polymorphic output target
// ---------------------------------------------------------------------------

/// Output stream target for header / body / etag writing.
///
/// Wraps the different concrete I/O destinations that the curl-rs CLI writes
/// to: regular files (seekable, truncatable), stdout (write-only), or a null
/// sink that silently discards all output.
pub enum OutputStream {
    /// Regular file handle — supports [`Write`] + [`Seek`] + truncation.
    File(std::fs::File),
    /// Standard output — [`Write`] only, no seeking.
    Stdout(std::io::Stdout),
    /// Null sink — silently discards all written data.
    Null,
}

impl Write for OutputStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            OutputStream::File(f) => f.write(buf),
            OutputStream::Stdout(s) => s.write(buf),
            OutputStream::Null => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            OutputStream::File(f) => f.flush(),
            OutputStream::Stdout(s) => s.flush(),
            OutputStream::Null => Ok(()),
        }
    }
}

impl OutputStream {
    /// Returns `true` if this stream targets a real terminal (TTY).
    ///
    /// Used to decide whether ANSI styling / OSC 8 hyperlinks are safe.
    pub fn is_terminal(&self) -> bool {
        match self {
            OutputStream::Stdout(s) => terminal::is_terminal(s),
            _ => false,
        }
    }

    /// Returns `true` when the stream is the [`Null`](OutputStream::Null)
    /// variant (no actual output configured).
    pub fn is_null(&self) -> bool {
        matches!(self, OutputStream::Null)
    }

    /// Returns `true` when the stream is active (not null).
    pub fn is_active(&self) -> bool {
        !self.is_null()
    }

    /// Rewinds to the beginning **and** truncates the stream to zero length.
    ///
    /// Only succeeds for [`OutputStream::File`]; other variants return an
    /// error because they do not support seeking.
    pub fn truncate_and_rewind(&mut self) -> io::Result<()> {
        match self {
            OutputStream::File(f) => {
                f.seek(SeekFrom::Start(0))?;
                f.set_len(0)?;
                Ok(())
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "stream does not support truncation",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// OutStruct — per-stream output state
// ---------------------------------------------------------------------------

/// Tracks the state of a single output stream (body, headers, or etag).
///
/// This is the Rust equivalent of the C `struct OutStruct` used throughout
/// the curl CLI tool to manage file-based and stdout-based output.
pub struct OutStruct {
    /// The underlying output stream.
    pub stream: OutputStream,
    /// Output filename (user-specified, URL-derived, or Content-Disposition).
    pub filename: Option<String>,
    /// Total bytes written through this stream.
    pub bytes: u64,
    /// Whether the stream has been initialised with the first write.
    pub init: bool,
    /// Whether the stream was opened by us (and should be closed on cleanup).
    pub fopened: bool,
    /// Whether the target is a regular file (not a pipe or device).
    pub s_isreg: bool,
    /// Whether the filename was dynamically allocated.  In Rust this tracks
    /// ownership provenance rather than memory management.
    pub alloc_filename: bool,
    /// Whether the filename came from a Content-Disposition header.
    pub is_cd_filename: bool,
    /// Whether output should be discarded (`--output /dev/null`).
    pub out_null: bool,
}

impl OutStruct {
    /// Creates a new `OutStruct` with null output (no stream, no filename).
    pub fn new_null() -> Self {
        Self {
            stream: OutputStream::Null,
            filename: None,
            bytes: 0,
            init: false,
            fopened: false,
            s_isreg: false,
            alloc_filename: false,
            is_cd_filename: false,
            out_null: true,
        }
    }

    /// Creates a new `OutStruct` targeting stdout.
    pub fn new_stdout() -> Self {
        Self {
            stream: OutputStream::Stdout(io::stdout()),
            filename: None,
            bytes: 0,
            init: false,
            fopened: false,
            s_isreg: false,
            alloc_filename: false,
            is_cd_filename: false,
            out_null: false,
        }
    }

    /// Creates a new `OutStruct` targeting a named file (not yet opened).
    pub fn new_file(filename: String) -> Self {
        Self {
            stream: OutputStream::Null,
            filename: Some(filename),
            bytes: 0,
            init: false,
            fopened: false,
            s_isreg: true,
            alloc_filename: false,
            is_cd_filename: false,
            out_null: false,
        }
    }
}

// ---------------------------------------------------------------------------
// HdrCbData — header callback context
// ---------------------------------------------------------------------------

/// Context structure passed to the header callback function.
///
/// This is the Rust equivalent of the C `struct HdrCbData` defined in
/// `src/tool_cb_hdr.h`.  It aggregates all the state needed by
/// [`tool_header_cb`] to process each received HTTP response header.
pub struct HdrCbData {
    /// Per-transfer operation configuration (shared ownership).
    pub config: Arc<OperationConfig>,
    /// Body output stream state.
    pub outs: OutStruct,
    /// Header dump output stream (`--dump-header`).
    pub heads: OutStruct,
    /// ETag save stream (`--etag-save`).  `None` when `--etag-save` is not
    /// configured.
    pub etag_save: Option<OutStruct>,
    /// Buffered headers awaiting Content-Disposition filename resolution.
    /// Replaces the C `curl_slist *headlist` linked list.
    pub headlist: Vec<String>,
    /// Whether Content-Disposition filename processing is active (`-J`).
    pub honor_cd_filename: bool,

    // -- Additional transfer-level state required by the callback -----------

    /// Effective URL of the current transfer (protocol detection &
    /// Location header resolution).
    pub this_url: String,
    /// Count of received headers that contain a colon separator (for the
    /// `%{num_headers}` write-out variable).
    pub num_headers: u64,
    /// `true` when the most-recently received header was an empty line
    /// (the header/body separator).
    pub was_last_header_empty: bool,
}

impl HdrCbData {
    /// Creates a new `HdrCbData` with default state.
    pub fn new(config: Arc<OperationConfig>) -> Self {
        Self {
            config,
            outs: OutStruct::new_stdout(),
            heads: OutStruct::new_null(),
            etag_save: None,
            headlist: Vec::new(),
            honor_cd_filename: false,
            this_url: String::new(),
            num_headers: 0,
            was_last_header_empty: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Filename Parsing
// ---------------------------------------------------------------------------

/// Extracts and sanitizes a filename from a header value.
///
/// When `is_content_disposition` is `true`, searches for the `filename=`
/// parameter in a Content-Disposition header value.  When `false`, treats the
/// header value as a URL / Location path and extracts the last path segment
/// as a fallback filename.
///
/// Post-processing applied in both modes:
/// - Leading directory path components are stripped (`/` and `\`)
/// - Trailing CR/LF/whitespace is removed
/// - On Windows: reserved device names are prefixed and trailing dots stripped
///
/// Returns `None` if the result is empty after sanitization.
fn parse_filename(header: &str, is_content_disposition: bool) -> Option<String> {
    let raw = if is_content_disposition {
        // Content-Disposition: attachment; filename="foo.txt"
        // Content-Disposition: attachment; filename=foo.txt
        let lower = header.to_ascii_lowercase();
        let pos = lower.find("filename=")?;
        let value_start = pos + "filename=".len();
        let rest = &header[value_start..];

        if let Some(inner) = rest.strip_prefix('"') {
            // Quoted value: content between the opening and closing quotes
            let end_quote = inner.find('"').unwrap_or(inner.len());
            inner[..end_quote].to_string()
        } else {
            // Unquoted value: runs until `;`, CR, LF, space, or tab
            let end = rest
                .find([';', '\r', '\n', ' ', '\t'])
                .unwrap_or(rest.len());
            rest[..end].to_string()
        }
    } else {
        // Location / URL fallback: use the last path component
        let mut value = header.trim();

        // Strip query string
        if let Some(q) = value.find('?') {
            value = &value[..q];
        }
        // Strip fragment identifier
        if let Some(f) = value.find('#') {
            value = &value[..f];
        }
        // Extract basename
        value.rsplit('/').next().unwrap_or(value).to_string()
    };

    // Slide to basename: remove any remaining directory separators.
    // We handle both forward and back slashes for cross-platform safety.
    let mut result = raw;
    if let Some(pos) = result.rfind('/') {
        result = result[pos + 1..].to_string();
    }
    if let Some(pos) = result.rfind('\\') {
        result = result[pos + 1..].to_string();
    }

    // Strip trailing CR / LF / whitespace
    let trimmed = result.trim_end_matches(|c: char| {
        c == '\r' || c == '\n' || c == ' ' || c == '\t'
    });
    result = trimmed.to_string();

    // Platform-specific sanitization for Windows reserved names
    #[cfg(windows)]
    {
        // Strip trailing dots and spaces (Windows filesystem restriction)
        result = result
            .trim_end_matches(|c: char| c == '.' || c == ' ')
            .to_string();

        // Guard against reserved device names (CON, PRN, AUX, NUL, COMn, LPTn)
        let upper = result.to_ascii_uppercase();
        let name_part = upper.split('.').next().unwrap_or(&upper);
        const RESERVED: &[&str] = &[
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
            "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
            "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        if RESERVED.contains(&name_part) {
            result = format!("_{}", result);
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

// ---------------------------------------------------------------------------
// ETag Saving
// ---------------------------------------------------------------------------

/// Extracts and saves an ETag header value to the etag-save stream.
///
/// When the header line begins with `etag:` (case-insensitive), the cleaned
/// value is written to `etag_save` after truncating the stream.  This ensures
/// only the most recent ETag value is stored — matching the C
/// `fseek`+`ftruncate`+`fwrite` pattern in `tool_cb_hdr.c`.
fn save_etag(etag_save: &mut OutStruct, header: &str) -> Result<()> {
    const ETAG_PREFIX: &str = "etag:";

    if header.len() < ETAG_PREFIX.len() {
        return Ok(());
    }

    // Case-insensitive prefix check
    if !header[..ETAG_PREFIX.len()].eq_ignore_ascii_case(ETAG_PREFIX) {
        return Ok(());
    }

    let value = &header[ETAG_PREFIX.len()..];

    // Trim leading blanks
    let value = value.trim_start_matches([' ', '\t']);

    // Trim trailing whitespace / CRLF
    let value = value.trim_end_matches(['\r', '\n', ' ', '\t']);

    if value.is_empty() {
        return Ok(());
    }

    // Truncate and rewind the stream, then write the cleaned ETag value
    etag_save
        .stream
        .truncate_and_rewind()
        .context("failed to truncate etag-save stream")?;

    writeln!(etag_save.stream, "{}", value)
        .context("failed to write etag value")?;

    etag_save
        .stream
        .flush()
        .context("failed to flush etag-save stream")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Terminal Hyperlinks for Location Headers
// ---------------------------------------------------------------------------

/// Renders an OSC 8 terminal hyperlink for a Location redirect header.
///
/// Resolves the `location_value` against `base_url` and, when the resolved
/// scheme is safe (`http` / `https` / `ftp` / `ftps`), emits OSC 8 escape
/// sequences that make the displayed text a clickable hyperlink in supported
/// terminal emulators.
///
/// Returns `true` if the hyperlinked text was written, `false` if the caller
/// should fall back to writing the location as plain text.
fn write_linked_location(
    stream: &mut dyn Write,
    location_value: &str,
    base_url: &str,
    _global: &GlobalConfig,
) -> Result<bool> {
    // Check VTE_VERSION environment variable for terminal compatibility.
    // Outdated VTE builds (< VTE_MIN_VERSION) have broken OSC 8 support.
    if let Ok(vte_str) = env::var("VTE_VERSION") {
        if let Ok(vte_ver) = vte_str.parse::<u32>() {
            if vte_ver > 0 && vte_ver < VTE_MIN_VERSION {
                return Ok(false);
            }
        }
    }

    let location = location_value.trim();
    if location.is_empty() {
        return Ok(false);
    }

    // Resolve the Location value against the effective (base) URL
    let resolved = if let Ok(base) = Url::parse(base_url) {
        match base.join(location) {
            Ok(url) => url,
            Err(_) => {
                // Join failed — try parsing Location as absolute URL
                match Url::parse(location) {
                    Ok(url) => url,
                    Err(_) => return Ok(false),
                }
            }
        }
    } else {
        // Base URL unparseable — try Location as absolute
        match Url::parse(location) {
            Ok(url) => url,
            Err(_) => return Ok(false),
        }
    };

    // Validate the resolved scheme is safe for rendering as a hyperlink
    match resolved.scheme() {
        "http" | "https" | "ftp" | "ftps" => {}
        _ => return Ok(false), // unsafe or unknown scheme — skip
    }

    let resolved_str = resolved.to_string();

    // Emit:  ESC]8;;URL ST  display_text  ESC]8;; ST
    write!(
        stream,
        "{}{}{}{}{}",
        LINK, resolved_str, LINKST, location, LINKOFF
    )
    .context("failed to write hyperlinked location")?;

    Ok(true)
}

// ---------------------------------------------------------------------------
// Output File Creation (local helper)
// ---------------------------------------------------------------------------

/// Creates the output file specified by `outs.filename`.
///
/// This is a local helper that covers the basic case.  The full clobber-mode
/// and directory-creation logic lives in `callbacks/write.rs`
/// (`tool_create_output_file`) which will replace this once that module is
/// available.
fn create_output_file(outs: &mut OutStruct) -> Result<()> {
    if let Some(ref filename) = outs.filename {
        let file = std::fs::File::create(filename)
            .with_context(|| format!("failed to create output file: {}", filename))?;
        outs.stream = OutputStream::File(file);
        Ok(())
    } else {
        Err(anyhow!("no filename set for output"))
    }
}

// ---------------------------------------------------------------------------
// Content-Disposition Processing
// ---------------------------------------------------------------------------

/// Processes Content-Disposition and Location headers for filename extraction.
///
/// When `honor_cd_filename` is `true` (the `-J` / `--remote-header-name`
/// flag), this function:
/// - Extracts filenames from Content-Disposition headers to name the output
///   file, creates the file, and flushes any buffered headers.
/// - Falls back to Location header path segments for 3xx redirects.
/// - Buffers headers when `show_headers` is active (replayed after file
///   creation).
///
/// Returns `Some(byte_count)` when the header was buffered (caller should
/// *not* write it to the output), or `None` for passthrough.
fn content_disposition(
    hdrcbdata: &mut HdrCbData,
    header: &str,
    cb: usize,
    global: &GlobalConfig,
) -> Option<usize> {
    if !hdrcbdata.honor_cd_filename {
        return None;
    }

    let header_lower = header.to_ascii_lowercase();

    // ----- Content-Disposition header ----------------------------------
    if header_lower.starts_with("content-disposition:") {
        let cd_value = &header["content-disposition:".len()..];
        if let Some(filename) = parse_filename(cd_value, true) {
            // Prepend output_dir when configured
            let full_path = prepend_output_dir(&hdrcbdata.config, &filename);

            // Only act if we have not yet opened a body output file
            if !hdrcbdata.outs.fopened && !hdrcbdata.outs.out_null {
                hdrcbdata.outs.filename = Some(full_path.clone());
                hdrcbdata.outs.alloc_filename = true;
                hdrcbdata.outs.is_cd_filename = true;
                hdrcbdata.outs.s_isreg = true;

                // Attempt to create the output file
                match create_output_file(&mut hdrcbdata.outs) {
                    Ok(()) => {
                        hdrcbdata.outs.fopened = true;

                        // Flush buffered headers to the newly-opened stream
                        if hdrcbdata.config.show_headers {
                            let _ = flush_headlist(
                                &mut hdrcbdata.headlist,
                                &mut hdrcbdata.outs.stream,
                            );
                        }
                    }
                    Err(e) => {
                        msgs::warnf(
                            global,
                            &format!(
                                "Failed to create output file '{}': {}",
                                full_path, e
                            ),
                        );
                    }
                }

                // Stop processing after the first Content-Disposition match
                hdrcbdata.honor_cd_filename = false;
            }
        }
    }
    // ----- Location header (3xx fallback filename) ---------------------
    else if header_lower.starts_with("location:") {
        let location_value = header["location:".len()..].trim();
        if let Some(filename) = parse_filename(location_value, false) {
            let full_path = prepend_output_dir(&hdrcbdata.config, &filename);
            // Store as the filename; a later Content-Disposition may override.
            hdrcbdata.outs.filename = Some(full_path);
            hdrcbdata.outs.alloc_filename = true;
            hdrcbdata.outs.is_cd_filename = true;
        }
    }

    // When show_headers is active and we have not yet opened the output
    // file, buffer the header for later replay via tool_write_headers.
    if hdrcbdata.config.show_headers && !hdrcbdata.outs.fopened && !hdrcbdata.outs.out_null {
        hdrcbdata.headlist.push(header.to_string());
        return Some(cb);
    }

    None
}

/// Prepends `config.output_dir` (if set) to the given filename.
fn prepend_output_dir(config: &OperationConfig, filename: &str) -> String {
    if let Some(ref dir) = config.output_dir {
        let mut path = dir.clone();
        if !path.ends_with('/') && !path.ends_with('\\') {
            path.push(std::path::MAIN_SEPARATOR);
        }
        path.push_str(filename);
        path
    } else {
        filename.to_string()
    }
}

// ---------------------------------------------------------------------------
// Styled Header Writing
// ---------------------------------------------------------------------------

/// Writes a single header line with ANSI bold styling for the header name
/// and an optional OSC 8 hyperlink for Location headers.
///
/// If the header contains a colon, everything up to and including the colon
/// is rendered in bold.  For `Location:` headers the value is additionally
/// rendered as a clickable terminal hyperlink when the terminal supports it.
fn write_styled_header(
    stream: &mut OutputStream,
    header: &str,
    this_url: &str,
    global: &GlobalConfig,
) -> Result<()> {
    if let Some(colon_pos) = header.find(':') {
        let name_with_colon = &header[..colon_pos + 1];
        let after_colon = &header[colon_pos + 1..];

        // Emit bold header name (including the colon)
        write!(stream, "{}{}{}", BOLD, name_with_colon, BOLDOFF)
            .context("failed to write styled header name")?;

        // For Location headers, attempt to render the value as a hyperlink
        if name_with_colon.eq_ignore_ascii_case("location:")
            && global.styled_output
        {
            // Decompose the value into: leading whitespace | value | CRLF
            let trimmed_start = after_colon.trim_start();
            let leading_ws_len = after_colon.len() - trimmed_start.len();
            let leading_ws = &after_colon[..leading_ws_len];

            let value_no_crlf = trimmed_start.trim_end_matches(|c: char| {
                c == '\r' || c == '\n'
            });
            let crlf = &trimmed_start[value_no_crlf.len()..];

            // Write the leading whitespace before the (possibly linked) value
            stream
                .write_all(leading_ws.as_bytes())
                .context("failed to write header spacing")?;

            // Try the hyperlinked version; fall back to plain text on failure
            let linked = if !value_no_crlf.is_empty() {
                write_linked_location(
                    stream,
                    value_no_crlf,
                    this_url,
                    global,
                )?
            } else {
                false
            };

            if !linked {
                // Plain text fallback
                stream
                    .write_all(value_no_crlf.as_bytes())
                    .context("failed to write location value")?;
            }

            // Trailing CRLF (or synthesize one if absent)
            if crlf.is_empty() {
                stream.write_all(b"\r\n")?;
            } else {
                stream.write_all(crlf.as_bytes())?;
            }
        } else {
            // Non-Location header (or styling disabled): write as-is
            stream
                .write_all(after_colon.as_bytes())
                .context("failed to write header value")?;
        }
    } else {
        // No colon (status line, empty terminator) — write verbatim
        stream
            .write_all(header.as_bytes())
            .context("failed to write header line")?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal header-list flush helper
// ---------------------------------------------------------------------------

/// Writes all buffered headers from `headlist` to `stream`, then clears the
/// list.  The list is **always** cleared, even if a write fails.
fn flush_headlist(headlist: &mut Vec<String>, stream: &mut dyn Write) -> Result<()> {
    let mut first_err: Option<io::Error> = None;

    for hdr in headlist.iter() {
        if first_err.is_none() {
            if let Err(e) = stream.write_all(hdr.as_bytes()) {
                first_err = Some(e);
            }
        }
    }

    headlist.clear();

    match first_err {
        Some(e) => Err(anyhow::Error::from(e).context("failed to write buffered headers")),
        None => Ok(()),
    }
}

// ===========================================================================
// Public API
// ===========================================================================

/// Flushes all buffered headers from `hdrcbdata.headlist` to `stream`.
///
/// Each stored header string is written verbatim (including any trailing CRLF
/// present in the original data).  The list is always cleared after flushing,
/// regardless of write success.
///
/// This is the Rust equivalent of the C `tool_write_headers()` function.
pub fn tool_write_headers(hdrcbdata: &mut HdrCbData, stream: &mut dyn Write) -> Result<()> {
    flush_headlist(&mut hdrcbdata.headlist, stream)
}

/// Main header callback — processes each received HTTP response header.
///
/// This is the Rust equivalent of the C `tool_header_cb()` function
/// registered via `CURLOPT_HEADERFUNCTION`.  It is called once per header
/// line (including the initial status line and the empty header/body
/// separator).
///
/// # Processing pipeline
///
/// 1. Write the header to the `--dump-header` stream (if configured)
/// 2. Detect the active protocol via [`proto_token`](libinfo::proto_token)
/// 3. For HTTP-like protocols:
///    - Extract and save ETag values (`--etag-save`)
///    - Process Content-Disposition / Location filenames (`-J`)
/// 4. Track header count and empty-header state for `--write-out`
/// 5. Render styled output (bold header names, OSC 8 hyperlinks)
///
/// # Returns
///
/// `Ok(data.len())` on success (all bytes consumed), or an error on I/O
/// failure (equivalent to `CURL_WRITEFUNC_ERROR` in C).
pub fn tool_header_cb(
    data: &[u8],
    hdrcbdata: &mut HdrCbData,
    global: &GlobalConfig,
) -> Result<usize> {
    let cb = data.len();
    if cb == 0 {
        return Ok(0);
    }

    // Convert the raw header bytes to a string.  HTTP headers are
    // ASCII / Latin-1 so lossy conversion is acceptable.
    let header_str = String::from_utf8_lossy(data);

    // ------------------------------------------------------------------
    // 1. Write to --dump-header stream (if configured)
    // ------------------------------------------------------------------
    if hdrcbdata.heads.stream.is_active() {
        hdrcbdata
            .heads
            .stream
            .write_all(data)
            .context("failed to write to --dump-header stream")?;
        hdrcbdata.heads.bytes += cb as u64;
    }

    // ------------------------------------------------------------------
    // 2. Determine the active protocol from the effective URL scheme
    // ------------------------------------------------------------------
    let scheme = extract_scheme(&hdrcbdata.this_url);
    let is_http_like = scheme
        .as_deref()
        .is_some_and(|s| {
            matches!(s, "http" | "https" | "rtsp" | "file")
                && libinfo::proto_token(s).is_some()
        });

    // ------------------------------------------------------------------
    // 3. ETag extraction (--etag-save, HTTP-like only)
    // ------------------------------------------------------------------
    if is_http_like {
        if let Some(ref mut etag_out) = hdrcbdata.etag_save {
            if hdrcbdata.config.etag_save_file.is_some() {
                if let Err(e) = save_etag(etag_out, &header_str) {
                    msgs::warnf(global, &format!("ETag save failed: {}", e));
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 4. Content-Disposition / Location filename processing (-J)
    // ------------------------------------------------------------------
    if is_http_like {
        if let Some(consumed) = content_disposition(hdrcbdata, &header_str, cb, global) {
            // The header was buffered by content_disposition — do not
            // write it to the output stream; return the consumed count.
            return Ok(consumed);
        }
    }

    // ------------------------------------------------------------------
    // 5. Header counting for --write-out %{num_headers}
    // ------------------------------------------------------------------
    let trimmed = header_str.trim_end_matches(['\r', '\n']);
    if trimmed.contains(':') {
        hdrcbdata.num_headers += 1;
    }

    // Detect the empty header/body separator
    hdrcbdata.was_last_header_empty = trimmed.is_empty();

    // ------------------------------------------------------------------
    // 6. Write header to the body output stream (when -i is active)
    // ------------------------------------------------------------------
    if hdrcbdata.config.show_headers {
        // Lazily create the output file on first header write
        if !hdrcbdata.outs.fopened
            && !hdrcbdata.outs.out_null
            && hdrcbdata.outs.filename.is_some()
            && hdrcbdata.outs.stream.is_null()
        {
            match create_output_file(&mut hdrcbdata.outs) {
                Ok(()) => {
                    hdrcbdata.outs.fopened = true;
                }
                Err(e) => {
                    let fname = hdrcbdata
                        .outs
                        .filename
                        .as_deref()
                        .unwrap_or("<unknown>");
                    msgs::warnf(
                        global,
                        &format!("Failed to create output file '{}': {}", fname, e),
                    );
                    return Err(anyhow!("failed to create output file"));
                }
            }
        }

        let use_style = global.styled_output && global.isatty;

        if use_style && !hdrcbdata.was_last_header_empty && trimmed.contains(':') {
            write_styled_header(
                &mut hdrcbdata.outs.stream,
                &header_str,
                &hdrcbdata.this_url,
                global,
            )?;
        } else {
            hdrcbdata
                .outs
                .stream
                .write_all(data)
                .context("failed to write header to output")?;
        }

        hdrcbdata.outs.bytes += cb as u64;
    }

    Ok(cb)
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Extracts the scheme (lowercased) from a URL string, e.g. `"https"` from
/// `"https://example.com/path"`.
fn extract_scheme(url: &str) -> Option<String> {
    url.find("://")
        .map(|pos| url[..pos].to_ascii_lowercase())
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TerminalState, TraceType, TransferState};
    use crate::libinfo::LibCurlInfo;
    use std::io::Write;

    /// Helper: creates a minimal GlobalConfig for testing.
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
            parallel_max: 0,
            verbosity: 0,
            parallel: false,
            parallel_connect: false,
            fail_early: false,
            styled_output: false,
            trace_fopened: false,
            tracetime: false,
            traceids: false,
            showerror: false,
            silent: false,
            noprogress: false,
            isatty: false,
            trace_set: false,
            libcurl_info: LibCurlInfo::default(),
            term: TerminalState::new(),
            libcurl_version: None,
        }
    }

    /// Helper: creates a minimal OperationConfig wrapped in Arc.
    fn test_config() -> Arc<OperationConfig> {
        Arc::new(OperationConfig::new())
    }

    // ----- OutputStream ---------------------------------------------------

    #[test]
    fn output_stream_null_write() {
        let mut s = OutputStream::Null;
        assert_eq!(s.write(b"hello").unwrap(), 5);
        s.flush().unwrap();
    }

    #[test]
    fn output_stream_null_predicates() {
        let s = OutputStream::Null;
        assert!(s.is_null());
        assert!(!s.is_active());
    }

    #[test]
    fn output_stream_file_truncate_rewind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trunc.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"old content\n").unwrap();
        }
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut stream = OutputStream::File(f);
        stream.truncate_and_rewind().unwrap();
        write!(stream, "new").unwrap();
        stream.flush().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn output_stream_null_truncate_fails() {
        let mut s = OutputStream::Null;
        assert!(s.truncate_and_rewind().is_err());
    }

    // ----- OutStruct ------------------------------------------------------

    #[test]
    fn outstruct_new_null() {
        let o = OutStruct::new_null();
        assert!(o.stream.is_null());
        assert!(o.out_null);
        assert_eq!(o.bytes, 0);
    }

    #[test]
    fn outstruct_new_stdout() {
        let o = OutStruct::new_stdout();
        assert!(!o.stream.is_null());
        assert!(!o.out_null);
    }

    #[test]
    fn outstruct_new_file() {
        let o = OutStruct::new_file("output.txt".into());
        assert!(o.stream.is_null());
        assert_eq!(o.filename.as_deref(), Some("output.txt"));
        assert!(o.s_isreg);
    }

    // ----- HdrCbData ------------------------------------------------------

    #[test]
    fn hdrcbdata_defaults() {
        let h = HdrCbData::new(test_config());
        assert!(!h.honor_cd_filename);
        assert!(h.headlist.is_empty());
        assert_eq!(h.num_headers, 0);
        assert!(!h.was_last_header_empty);
        assert!(h.etag_save.is_none());
    }

    // ----- parse_filename -------------------------------------------------

    #[test]
    fn parse_cd_quoted_filename() {
        let hdr = " attachment; filename=\"report.pdf\"";
        assert_eq!(parse_filename(hdr, true), Some("report.pdf".into()));
    }

    #[test]
    fn parse_cd_unquoted_filename() {
        let hdr = " attachment; filename=report.pdf";
        assert_eq!(parse_filename(hdr, true), Some("report.pdf".into()));
    }

    #[test]
    fn parse_cd_filename_with_path() {
        let hdr = " attachment; filename=\"/tmp/data/report.pdf\"";
        assert_eq!(parse_filename(hdr, true), Some("report.pdf".into()));
    }

    #[test]
    fn parse_cd_no_filename_param() {
        let hdr = " inline";
        assert_eq!(parse_filename(hdr, true), None);
    }

    #[test]
    fn parse_cd_empty_filename() {
        let hdr = " attachment; filename=\"\"";
        assert_eq!(parse_filename(hdr, true), None);
    }

    #[test]
    fn parse_location_basename() {
        assert_eq!(
            parse_filename("https://example.com/files/doc.pdf", false),
            Some("doc.pdf".into())
        );
    }

    #[test]
    fn parse_location_strips_query() {
        assert_eq!(
            parse_filename("https://example.com/doc.pdf?v=2", false),
            Some("doc.pdf".into())
        );
    }

    #[test]
    fn parse_location_strips_fragment() {
        assert_eq!(
            parse_filename("https://example.com/doc.pdf#section", false),
            Some("doc.pdf".into())
        );
    }

    #[test]
    fn parse_location_trailing_slash() {
        assert_eq!(
            parse_filename("https://example.com/path/", false),
            None
        );
    }

    #[test]
    fn parse_location_strips_backslash_path() {
        let hdr = " attachment; filename=\"C:\\Users\\me\\doc.pdf\"";
        assert_eq!(parse_filename(hdr, true), Some("doc.pdf".into()));
    }

    // ----- save_etag ------------------------------------------------------

    #[test]
    fn save_etag_extracts_value() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("etag.txt");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        let mut out = OutStruct {
            stream: OutputStream::File(f),
            filename: None,
            bytes: 0,
            init: false,
            fopened: true,
            s_isreg: true,
            alloc_filename: false,
            is_cd_filename: false,
            out_null: false,
        };
        save_etag(&mut out, "ETag: \"abc123\"\r\n").unwrap();
        out.stream.flush().unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "\"abc123\"\n");
    }

    #[test]
    fn save_etag_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("etag2.txt");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        let mut out = OutStruct {
            stream: OutputStream::File(f),
            filename: None,
            bytes: 0,
            init: false,
            fopened: true,
            s_isreg: true,
            alloc_filename: false,
            is_cd_filename: false,
            out_null: false,
        };
        save_etag(&mut out, "etag: first\r\n").unwrap();
        save_etag(&mut out, "etag: second\r\n").unwrap();
        out.stream.flush().unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "second\n");
    }

    #[test]
    fn save_etag_ignores_non_etag() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("etag3.txt");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        let mut out = OutStruct {
            stream: OutputStream::File(f),
            filename: None,
            bytes: 0,
            init: false,
            fopened: true,
            s_isreg: true,
            alloc_filename: false,
            is_cd_filename: false,
            out_null: false,
        };
        save_etag(&mut out, "Content-Type: text/html\r\n").unwrap();
        out.stream.flush().unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "");
    }

    // ----- extract_scheme -------------------------------------------------

    #[test]
    fn extract_scheme_http() {
        assert_eq!(extract_scheme("http://example.com"), Some("http".into()));
    }

    #[test]
    fn extract_scheme_https() {
        assert_eq!(extract_scheme("HTTPS://example.com"), Some("https".into()));
    }

    #[test]
    fn extract_scheme_no_scheme() {
        assert_eq!(extract_scheme("example.com"), None);
    }

    // ----- tool_write_headers ---------------------------------------------

    #[test]
    fn write_headers_empty() {
        let mut h = HdrCbData::new(test_config());
        let mut buf = Vec::new();
        tool_write_headers(&mut h, &mut buf).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn write_headers_flushes_all() {
        let mut h = HdrCbData::new(test_config());
        h.headlist.push("Content-Type: text/html\r\n".into());
        h.headlist.push("Location: /new\r\n".into());
        let mut buf = Vec::new();
        tool_write_headers(&mut h, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Content-Type: text/html\r\n"));
        assert!(s.contains("Location: /new\r\n"));
        assert!(h.headlist.is_empty());
    }

    #[test]
    fn write_headers_clears_on_error() {
        struct Fail;
        impl Write for Fail {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "fail"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut h = HdrCbData::new(test_config());
        h.headlist.push("H: v\r\n".into());
        let _ = tool_write_headers(&mut h, &mut Fail);
        assert!(h.headlist.is_empty());
    }

    // ----- tool_header_cb -------------------------------------------------

    #[test]
    fn header_cb_empty_data() {
        let mut h = HdrCbData::new(test_config());
        let g = test_global();
        assert_eq!(tool_header_cb(b"", &mut h, &g).unwrap(), 0);
    }

    #[test]
    fn header_cb_returns_len() {
        let mut h = HdrCbData::new(test_config());
        h.this_url = "http://ex.com".into();
        let g = test_global();
        let d = b"Content-Type: text/html\r\n";
        assert_eq!(tool_header_cb(d, &mut h, &g).unwrap(), d.len());
    }

    #[test]
    fn header_cb_counts_headers() {
        let mut h = HdrCbData::new(test_config());
        h.this_url = "http://ex.com".into();
        let g = test_global();
        tool_header_cb(b"Content-Type: text/html\r\n", &mut h, &g).unwrap();
        assert_eq!(h.num_headers, 1);
        tool_header_cb(b"X-Custom: val\r\n", &mut h, &g).unwrap();
        assert_eq!(h.num_headers, 2);
        tool_header_cb(b"HTTP/1.1 200 OK\r\n", &mut h, &g).unwrap();
        assert_eq!(h.num_headers, 2);
    }

    #[test]
    fn header_cb_detects_empty() {
        let mut h = HdrCbData::new(test_config());
        h.this_url = "http://ex.com".into();
        let g = test_global();
        tool_header_cb(b"H: v\r\n", &mut h, &g).unwrap();
        assert!(!h.was_last_header_empty);
        tool_header_cb(b"\r\n", &mut h, &g).unwrap();
        assert!(h.was_last_header_empty);
    }

    #[test]
    fn header_cb_dump_header() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("headers.txt");
        let mut h = HdrCbData::new(test_config());
        h.this_url = "http://ex.com".into();
        h.heads.stream = OutputStream::File(std::fs::File::create(&p).unwrap());
        let g = test_global();
        tool_header_cb(b"Content-Type: text/html\r\n", &mut h, &g).unwrap();
        tool_header_cb(b"\r\n", &mut h, &g).unwrap();
        h.heads.stream.flush().unwrap();
        let c = std::fs::read_to_string(&p).unwrap();
        assert!(c.contains("Content-Type: text/html\r\n"));
        // 25 bytes for "Content-Type: text/html\r\n" + 2 bytes for "\r\n"
        assert_eq!(h.heads.bytes, 27);
    }

    #[test]
    fn header_cb_show_headers() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("out.txt");
        let mut cfg = OperationConfig::new();
        cfg.show_headers = true;
        let mut h = HdrCbData::new(Arc::new(cfg));
        h.this_url = "http://ex.com".into();
        h.outs.stream = OutputStream::File(std::fs::File::create(&p).unwrap());
        h.outs.fopened = true;
        let g = test_global(); // styled_output = false
        tool_header_cb(b"Content-Type: text/html\r\n", &mut h, &g).unwrap();
        h.outs.stream.flush().unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "Content-Type: text/html\r\n");
    }

    #[test]
    fn header_cb_etag_save() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("etag.txt");
        let mut cfg = OperationConfig::new();
        cfg.etag_save_file = Some(p.to_string_lossy().into());
        let mut h = HdrCbData::new(Arc::new(cfg));
        h.this_url = "http://ex.com".into();
        h.etag_save = Some(OutStruct {
            stream: OutputStream::File(
                std::fs::OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .open(&p)
                    .unwrap(),
            ),
            filename: Some(p.to_string_lossy().into()),
            bytes: 0,
            init: false,
            fopened: true,
            s_isreg: true,
            alloc_filename: false,
            is_cd_filename: false,
            out_null: false,
        });
        let g = test_global();
        tool_header_cb(b"ETag: \"v1\"\r\n", &mut h, &g).unwrap();
        if let Some(ref mut e) = h.etag_save {
            e.stream.flush().unwrap();
        }
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "\"v1\"\n");
    }

    #[test]
    fn header_cb_cd_buffering() {
        let mut cfg = OperationConfig::new();
        cfg.show_headers = true;
        let mut h = HdrCbData::new(Arc::new(cfg));
        h.this_url = "http://ex.com".into();
        h.honor_cd_filename = true;
        h.outs.out_null = false;
        h.outs.fopened = false;
        h.outs.stream = OutputStream::Null;
        let g = test_global();
        let d = b"X-Test: value\r\n";
        let r = tool_header_cb(d, &mut h, &g).unwrap();
        assert_eq!(r, d.len());
        assert_eq!(h.headlist.len(), 1);
    }

    // ----- write_linked_location ------------------------------------------

    #[test]
    fn linked_location_absolute_url() {
        let g = test_global();
        let mut buf = Vec::new();
        let ok = write_linked_location(
            &mut buf,
            "https://example.com/new",
            "https://example.com/old",
            &g,
        )
        .unwrap();
        assert!(ok);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("https://example.com/new"));
        assert!(s.contains(LINK));
        assert!(s.contains(LINKOFF));
    }

    #[test]
    fn linked_location_relative_url() {
        let g = test_global();
        let mut buf = Vec::new();
        let ok = write_linked_location(
            &mut buf,
            "/newpath",
            "https://example.com/old",
            &g,
        )
        .unwrap();
        assert!(ok);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("https://example.com/newpath"));
    }

    #[test]
    fn linked_location_unsafe_scheme() {
        let g = test_global();
        let mut buf = Vec::new();
        let ok = write_linked_location(
            &mut buf,
            "javascript:alert(1)",
            "https://example.com",
            &g,
        )
        .unwrap();
        assert!(!ok);
        assert!(buf.is_empty());
    }

    #[test]
    fn linked_location_empty() {
        let g = test_global();
        let mut buf = Vec::new();
        let ok = write_linked_location(&mut buf, "", "https://ex.com", &g).unwrap();
        assert!(!ok);
    }

    // ----- prepend_output_dir ---------------------------------------------

    #[test]
    fn prepend_output_dir_none() {
        let cfg = OperationConfig::new();
        assert_eq!(prepend_output_dir(&cfg, "file.txt"), "file.txt");
    }

    #[test]
    fn prepend_output_dir_some() {
        let mut cfg = OperationConfig::new();
        cfg.output_dir = Some("/tmp/out".into());
        let result = prepend_output_dir(&cfg, "file.txt");
        assert!(result.starts_with("/tmp/out"));
        assert!(result.ends_with("file.txt"));
    }
}
