//! `CURLOPT_HEADERFUNCTION` response-header callback and header writing for the
//! `curl-rs` CLI.
//!
//! This module is the memory-safe Rust reimplementation of curl's
//! `src/tool_cb_hdr.c` — the header-data callback `tool_header_cb`, the buffered
//! header flusher `tool_write_headers`, and the private helpers `parse_filename`,
//! `save_etag`, `content_disposition`, and `write_linked_location`. That C file
//! (and `src/tool_cb_hdr.h`) is read as the behavioral oracle and is never
//! modified.
//!
//! # Role in the crate
//!
//! It implements the function libcurl invokes for every received response
//! **header** line. From that single callback curl drives several CLI features:
//!
//! * **`-D` / `--dump-header`** — write the raw header bytes to a file.
//! * **`-J` / `--remote-header-name`** — derive the local output filename from a
//!   `Content-Disposition` (or, as a fallback, a redirect `Location:`) header.
//! * **`--etag-save`** — capture the response `ETag` into a file.
//! * **`-i` / `--include`** (and `--show-headers`) — echo headers to the body
//!   output, with bold header names on a styled tty and an OSC-8 hyperlinked
//!   `Location:` value in VTE terminals.
//!
//! The `OutStruct` per-sink state, the `HdrCbData` callback-linkage state, and
//! the owning `PerTransfer` all live canonically in [`crate::operate`]; this
//! module consumes them. `OutStruct` is reached via the re-export in
//! [`crate::callbacks::write`].
//!
//! # Borrow model (the key design point)
//!
//! curl's C freely aliases the three `OutStruct` sinks (`outs`, `heads`,
//! `etag_save`) and the `OperationConfig` through both `per_transfer` and
//! `HdrCbData` pointers. Safe Rust forbids that aliasing, so this port keeps a
//! **single owner** — the `PerTransfer` (`per`) — and reaches each sink and the
//! config through it, splitting the *disjoint* fields it needs at each call site
//! (e.g. `&per.easy` together with `&mut per.outs`). `HdrCbData` therefore stores
//! only its own state (`headlist` + `honor_cd_filename` + the `config_idx`
//! back-reference); it never duplicates the sinks. `getinfo` results are copied
//! into owned values immediately so the shared `&per.easy` borrow is released
//! before any sink is mutated. No `unsafe`, no `Rc<RefCell<…>>`.
//!
//! # `headlist` semantics (faithful to the oracle)
//!
//! As in `tool_cb_hdr.c`, `hdrcbdata.headlist` is **only** an in-memory hold for
//! the `-J` + show-headers case: while awaiting the `Content-Disposition` header
//! (before the output file name — and hence the file — exists), each header line
//! is buffered and then flushed by [`tool_write_headers`] once the file is
//! created. It is not a general header accumulator. (`crate::callbacks::write`
//! flushes/clears any such buffer ahead of the first body byte with its own
//! inlined copy of this logic, preserving the header→write dependency
//! direction.)
//!
//! # Behavioral parity (AAP §0.7.3, §0.8.2)
//!
//! Every observable artifact of `tool_cb_hdr.c` is reproduced: the exact raw
//! bytes written under `--dump-header`, the `Content-Disposition` / redirect
//! `Location` filename derivation (including the `--output-dir` prefix and the
//! `is_cd_filename` no-clobber marking), the trimmed `ETag` + newline written to
//! a truncated file, the `--write-out` header counting (`num_headers`, reset on
//! each new header block), the bold header echo, and the OSC-8 hyperlinked
//! `Location:`. The `CURL_WRITEFUNC_ERROR` sentinel is taken from
//! [`curl_rs_lib::transfer`].
//!
//! # Out of scope (initial POSIX/macOS port)
//!
//! The Windows-only paths of `tool_cb_hdr.c` are intentionally omitted, matching
//! the AAP's four (non-Windows) targets: the `_WIN32` `BOLDOFF` value
//! (`"\x1b[22m"`), the `sanitize_file_name` step in `parse_filename`, the
//! `utf8seq` incomplete-sequence discard at the top of the callback, and the
//! Windows-console `tool_term_has_bold` probe. On POSIX curl assumes bold is
//! available whenever output is an interactive, styled tty, which is what this
//! port implements; the OSC-8 hyperlink path (curl's `#ifdef LINK`, defined only
//! on non-Windows) is therefore always compiled here.

#![forbid(unsafe_code)]
// The header callback's public entry points (`tool_header_cb`,
// `tool_write_headers`) are wired in by `operate`/`setopt` in a later migration
// step (AAP §0.8.4 step 11/12). `allow(dead_code)` keeps the not-yet-driven
// public functions — and the private helpers reached only through them or the
// unit tests — from tripping the workspace `-D warnings` gate, mirroring the
// construction-order staging already used by the sibling callback modules
// (`write.rs`, `read.rs`, …); it is removed once `operate` registers the
// callback.
#![allow(dead_code)]

use std::io::{self, Seek, SeekFrom, Write};

use curl_rs_lib::transfer::CURL_WRITEFUNC_ERROR;
use curl_rs_lib::url::{CurlUPart, CURLU_NO_DEFAULT_PORT};
use curl_rs_lib::{CurlInfo, InfoValue, Url};

use crate::callbacks::write::create_output_file;
use crate::config::GlobalConfig;
use crate::operate::{HdrCbData, OutStruct, PerTransfer};

// ===========================================================================
// Styling / hyperlink escape sequences (POSIX values; `src/tool_cb_hdr.c:38-51`)
// ===========================================================================

/// Turn on bold (`BOLD`, SGR 1).
const BOLD: &str = "\x1b[1m";
/// Turn off bold. curl uses "all attributes off" (SGR 0) rather than the
/// explicit bold-off (SGR 22) because SGR 22 is not supported everywhere (e.g.
/// the macOS Terminal). (The `_WIN32` build uses `"\x1b[22m"`; out of scope.)
const BOLDOFF: &str = "\x1b[0m";
/// OSC 8 hyperlink introducer (`LINK`).
const LINK: &str = "\x1b]8;;";
/// OSC 8 string terminator (`LINKST`), `ESC \`.
const LINKST: &str = "\x1b\\";
/// OSC 8 hyperlink closer (`LINKOFF`), `LINK LINKST` — an empty-URL hyperlink
/// that ends the clickable region.
const LINKOFF: &str = "\x1b]8;;\x1b\\";

/// Largest header block libcurl will deliver (`CURL_MAX_HTTP_HEADER`,
/// `100 * 1024`, from `include/curl/curl.h`). The core library does not export
/// this constant, so it is defined locally; it is only consulted by the
/// debug-build header-size guard, hence the `#[cfg(debug_assertions)]` gate (a
/// release build must not carry an unused constant under `-D warnings`).
#[cfg(debug_assertions)]
const CURL_MAX_HTTP_HEADER: usize = 100 * 1024;

// ===========================================================================
// Character-class helpers — curl's `lib/curl_ctype.h` macros, byte-exact.
// ===========================================================================

/// `ISBLANK` — a space or a horizontal tab.
fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// `ISSPACE` — space, tab, line feed, vertical tab, form feed, or carriage
/// return. NB: Rust's [`u8::is_ascii_whitespace`] deliberately **excludes**
/// vertical tab (`0x0B`), so the set is enumerated explicitly to match curl.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// curl's `checkprefix(prefix, data)` — a case-insensitive test of whether
/// `data` begins with `prefix`. (curl expands to
/// `curl_strnequal(prefix, data, strlen(prefix))`; for the ASCII, NUL-free
/// prefixes used here a length-guarded `eq_ignore_ascii_case` is exact, and the
/// length guard additionally makes it memory-safe on a short, non-terminated
/// header buffer.)
fn checkprefix(prefix: &[u8], data: &[u8]) -> bool {
    data.len() >= prefix.len() && data[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Faithful port of curl's `curl_strnequal("Location", ptr, namelen)` used to
/// decide whether an echoed header name is `Location` (and thus eligible for the
/// OSC-8 hyperlink). curl's `strnequal` treats NUL as end-of-string, so:
///
/// * `namelen > 8` → the 9th character of `"Location"` is its NUL terminator,
///   which never equals a real header byte → `false`.
/// * `namelen <= 8` → a case-insensitive comparison of the first `namelen`
///   bytes, i.e. a *prefix* match of `"Location"` (curl's quirk: a truncated
///   name such as `"Locat"` matches; preserved here for byte parity).
fn name_is_location(name: &[u8]) -> bool {
    const LOC: &[u8] = b"Location";
    if name.len() > LOC.len() {
        return false;
    }
    LOC[..name.len()].eq_ignore_ascii_case(name)
}

// ===========================================================================
// Output-sink helpers — resolve an `OutStruct` to its concrete writer.
//
// These mirror the private `write_to_sink`/`flush_sink` of
// `crate::callbacks::write` (which does not export them). curl carries a single
// `FILE *stream`; the Rust `OutStruct` models the same destination with an
// `Option<File>` plus a `to_stderr` flag: a held `File` is a regular file;
// otherwise `to_stderr` selects the process stderr; otherwise the destination is
// the process stdout (curl's default `outs->stream = stdout`).
// ===========================================================================

/// Writes the whole `buffer` to the sink described by `outs`, returning the
/// number of bytes accepted — the analogue of `fwrite(buffer, 1, len, stream)`.
///
/// curl detects a short write by comparing `fwrite`'s return against the byte
/// count; this port preserves that *observable* contract: a fully successful
/// [`Write::write_all`] returns `buffer.len()`, and any error returns `0`
/// (`!= buffer.len()`), which the callers map to an aborting return value.
fn write_to_sink(outs: &mut OutStruct, buffer: &[u8]) -> usize {
    let result = if let Some(file) = outs.stream.as_mut() {
        file.write_all(buffer)
    } else if outs.to_stderr {
        io::stderr().write_all(buffer)
    } else {
        io::stdout().write_all(buffer)
    };
    match result {
        Ok(()) => buffer.len(),
        Err(_) => 0,
    }
}

/// Flushes the sink described by `outs` — the analogue of `fflush(stream)`. std
/// retries the underlying `EINTR` internally, matching curl's effective
/// behavior.
fn flush_sink(outs: &mut OutStruct) -> io::Result<()> {
    if let Some(file) = outs.stream.as_mut() {
        file.flush()
    } else if outs.to_stderr {
        io::stderr().flush()
    } else {
        io::stdout().flush()
    }
}

// ===========================================================================
// Buffered-header flush — port of `tool_write_headers`
// (`src/tool_cb_hdr.c:233-249`).
// ===========================================================================

/// Writes the buffered header lines in `hdrcbdata.headlist` to the `outs` sink,
/// then **always** clears the buffer — the Rust port of `tool_write_headers`.
///
/// Returns `true` on a write failure (curl's `rc = 1`, which callers map to
/// [`CURL_WRITEFUNC_ERROR`]) and `false` on success (curl's `rc = 0`). On the
/// first short write the remaining lines are skipped (curl's `goto fail`). As in
/// C the list is consumed regardless of outcome — curl's
/// `curl_slist_free_all(headlist); headlist = NULL;` reached on both the success
/// (`rc = 0`) and failure (`fail:`) paths; here the owning `Vec` is cleared,
/// dropping every line.
///
/// This is `pub` so it is reachable cross-module as the documented header→write
/// boundary export; `crate::callbacks::write` nonetheless inlines its own
/// equivalent (rather than calling here) to keep the dependency direction one-way
/// (header consumes write, not the reverse).
pub fn tool_write_headers(hdrcbdata: &mut HdrCbData, outs: &mut OutStruct) -> bool {
    let mut failed = false;
    for line in &hdrcbdata.headlist {
        // curl compares `strlen(h->data)` against the `fwrite` return; the stored
        // bytes carry no trailing NUL, so the line length is the expectation.
        if write_to_sink(outs, line) != line.len() {
            failed = true; // curl: `goto fail` (rc stays 1)
            break;
        }
    }
    // curl always frees the list and nulls the pointer (the `fail:` label is on
    // both the success and failure paths).
    hdrcbdata.headlist.clear();
    failed
}

// ===========================================================================
// Filename extraction — port of `parse_filename` (`src/tool_cb_hdr.c:150-231`).
// ===========================================================================

/// Derives a local filename from a `Location:` or `Content-Disposition:` header
/// value — the Rust port of `parse_filename`.
///
/// `data` is the raw value bytes (which still include the header line's trailing
/// CR/LF). `stop` distinguishes the two callers:
///
/// * `Some(stop)` — a `Content-Disposition` value. If it opens with a single or
///   double quote, that quote becomes the stop character (and is skipped);
///   otherwise the supplied `stop` (`;`) is used. The value is truncated at the
///   first occurrence of the stop character.
/// * `None` — a `Location` value. The query (`?`) and fragment (`#`) are trimmed
///   off.
///
/// In both cases the result is reduced to its basename (the part after the last
/// `/`, then after the last `\`), trailing `\r`/`\n` are stripped, and the owned
/// `String` is returned. Returns [`None`] only when a path separator leaves an
/// empty trailing component (curl's two `return NULL` cases); an otherwise-empty
/// value yields `Some(String::new())`, exactly as C returns the empty `copy`.
///
/// curl operates on a NUL-terminated copy, so `strchr`/`strrchr` stop at the
/// first embedded NUL; this port models that by treating the bytes up to the
/// first NUL (if any) as the working string. Real headers contain none.
///
/// (The Windows/MSDOS `sanitize_file_name` step is out of scope; see the module
/// docs.) The returned `String` is built with [`String::from_utf8_lossy`]
/// because [`OutStruct::filename`] is a `String`; curl's regression filenames
/// are ASCII, so this is byte-faithful for the test corpus.
fn parse_filename(data: &[u8], stop: Option<u8>) -> Option<String> {
    // curl: `copy = curlx_memdup0(ptr, len)` — a NUL-terminated copy; the C
    // string functions below stop at the first embedded NUL.
    let nul = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let copy = &data[..nul];

    // `start..end` is the live window into `copy` as it is narrowed.
    let mut start = 0usize;
    let mut end = copy.len();

    match stop {
        Some(mut s) => {
            // A `Content-Disposition` value: handle a leading quote, then cut at
            // the (possibly updated) stop character.
            if copy.first() == Some(&b'\'') || copy.first() == Some(&b'"') {
                s = copy[0]; // the opening quote becomes the stop char
                start = 1;
            }
            if let Some(pos) = copy[start..end].iter().position(|&b| b == s) {
                end = start + pos;
            }
        }
        None => {
            // A `Location` value: trim off query and fragment if present.
            if let Some(pos) = copy[start..end].iter().position(|&b| b == b'?') {
                end = start + pos;
            }
            if let Some(pos) = copy[start..end].iter().position(|&b| b == b'#') {
                end = start + pos;
            }
        }
    }

    // Reduce to the basename: the part after the last '/', then after the last
    // '\\'. curl returns NULL when a separator is the final character.
    if let Some(pos) = copy[start..end].iter().rposition(|&b| b == b'/') {
        start = start + pos + 1;
        if start >= end {
            return None;
        }
    }
    if let Some(pos) = copy[start..end].iter().rposition(|&b| b == b'\\') {
        start = start + pos + 1;
        if start >= end {
            return None;
        }
    }

    // Strip a trailing CR then LF (curl truncates at the first of each).
    if let Some(pos) = copy[start..end].iter().position(|&b| b == b'\r') {
        end = start + pos;
    }
    if let Some(pos) = copy[start..end].iter().position(|&b| b == b'\n') {
        end = start + pos;
    }

    Some(String::from_utf8_lossy(&copy[start..end]).into_owned())
}

// ===========================================================================
// ETag capture — port of `save_etag` (`src/tool_cb_hdr.c:254-286`), `--etag-save`.
// ===========================================================================

/// Writes the response `ETag` to the `--etag-save` file — the Rust port of
/// `save_etag`.
///
/// `etag_value` is the header line beyond the `etag:` prefix (curl's `&str[5]`),
/// so its final byte is the line's final byte. curl only acts when that line
/// ends in `'\n'`; it then strips leading `ISBLANK` and trailing `ISSPACE`,
/// truncates the save file, writes the trimmed value followed by a newline, and
/// flushes.
///
/// Returns [`CURL_WRITEFUNC_ERROR`] if truncation fails (curl's `ftruncate` /
/// `fseek` failure path), otherwise `0`. The write/flush errors are ignored,
/// matching curl (which does not check `fwrite` here and casts `fflush` to
/// `void`). The file is truncated to zero **and** repositioned to the start —
/// the union of curl's `HAVE_FTRUNCATE` (`ftruncate(fd, 0)`) and fallback
/// (`fseek(SEEK_SET)`) branches — which is byte-identical to either on the
/// realistic single-write path (a freshly opened file already at offset 0) and
/// reflects the documented intent of replacing any existing ETag value.
fn save_etag(etag_value: &[u8], etag_save: &mut OutStruct) -> usize {
    // curl: `const char *eot = endp - 1; if(*eot == '\n')`.
    if etag_value.last() != Some(&b'\n') {
        return 0;
    }
    let last = etag_value.len() - 1; // index of the trailing '\n'

    // curl: `while(ISBLANK(*etag_h) && (etag_h < eot)) etag_h++;`
    let mut start = 0usize;
    while start < last && is_blank(etag_value[start]) {
        start += 1;
    }
    // curl: `while(ISSPACE(*eot)) eot--;` — drops the trailing whitespace
    // (including the '\n'). curl has no lower bound; the `>= 0` guard here is for
    // memory safety only and cannot change the outcome, because the result test
    // below reproduces curl's `eot >= etag_h` exactly.
    let mut eot: isize = last as isize;
    while eot >= 0 && is_space(etag_value[eot as usize]) {
        eot -= 1;
    }

    // curl: `if(eot >= etag_h) { truncate; fwrite; fputc('\n'); fflush; }`
    if eot >= start as isize {
        let etag = &etag_value[start..=(eot as usize)];
        if let Some(file) = etag_save.stream.as_mut() {
            if file.set_len(0).is_err() {
                return CURL_WRITEFUNC_ERROR;
            }
            if file.seek(SeekFrom::Start(0)).is_err() {
                return CURL_WRITEFUNC_ERROR;
            }
            let _ = file.write_all(etag);
            let _ = file.write_all(b"\n");
            let _ = file.flush();
        }
    }
    0
}

// ===========================================================================
// VTE version parsing — curl's `curlx_str_number` as applied to `VTE_VERSION`.
// ===========================================================================

/// Parses the leading base-10 digits of `VTE_VERSION` into an [`i64`] (curl's
/// `curl_off_t`), the equivalent of `curlx_str_number(&vver, &num,
/// CURL_OFF_T_MAX)`.
///
/// At least one leading digit is required (otherwise curl reports an error,
/// modeled here as [`None`]); parsing stops at the first non-digit; overflow past
/// `i64::MAX` (curl's `CURL_OFF_T_MAX`) yields [`None`]. No sign or leading space
/// is accepted, exactly as curl's parser.
fn parse_vte_version(s: &[u8]) -> Option<i64> {
    let mut value: i64 = 0;
    let mut any = false;
    for &b in s {
        if b.is_ascii_digit() {
            any = true;
            value = value.checked_mul(10)?.checked_add(i64::from(b - b'0'))?;
        } else {
            break;
        }
    }
    if any {
        Some(value)
    } else {
        None
    }
}

// ===========================================================================
// Hyperlinked Location — port of `write_linked_location`
// (`src/tool_cb_hdr.c:63-144`, curl's `#ifdef LINK`).
// ===========================================================================

/// Writes a `Location:` value to `outs`, wrapping it in an OSC-8 hyperlink whose
/// target is the *absolute* redirect URL so even a relative `Location` is
/// clickable in supporting terminals — the Rust port of `write_linked_location`.
///
/// The decision flow matches curl exactly:
///
/// 1. **VTE gate.** If `VTE_VERSION` is set and either unparseable or `<= 4801`
///    (VTE ≤ 0.48.1, which has formatting bugs), fall back to a plain write. If
///    the variable is unset, curl proceeds to linkify (it only suppresses for a
///    *known-old* VTE).
/// 2. Strip leading blanks (counting them) and trailing CR/LF from the value.
/// 3. Resolve the (possibly relative) value against `CURLINFO_EFFECTIVE_URL`
///    using a [`Url`]: set the base, then set the value (curl's two
///    `curl_url_set(CURLUPART_URL)` calls — the second resolves a relative
///    reference), and read back the full URL (`CURLU_NO_DEFAULT_PORT`) and the
///    scheme.
/// 4. If the resolved scheme is `http`/`https`/`ftp`/`ftps`, emit
///    `"<skipped>" LINK <finalurl> LINKST "<value>" LINKOFF` — where `<value>` is
///    the original tail after the skipped leading blanks (still including the
///    trailing CR/LF, exactly as curl's `(int)loclen - space_skipped, loc`).
///    Otherwise (or on any failure above) write the original value verbatim.
fn write_linked_location(easy: &curl_rs_lib::Easy, location: &[u8], outs: &mut OutStruct) {
    // 1. VTE_VERSION gate (curl: `if(vver) { if(str_number(...) || num<=4801)
    //    goto locout; }`). Unset → proceed.
    if let Ok(vver) = std::env::var("VTE_VERSION") {
        match parse_vte_version(vver.as_bytes()) {
            Some(num) if num > 4801 => {}
            _ => {
                write_to_sink(outs, location);
                return;
            }
        }
    }

    // 2. Strip leading blanks (counted) and trailing CR/LF.
    let mut start = 0usize;
    while start < location.len() && is_blank(location[start]) {
        start += 1;
    }
    let space_skipped = start;
    let mut end = location.len();
    while end > start && (location[end - 1] == b'\n' || location[end - 1] == b'\r') {
        end -= 1;
    }
    let stripped = &location[start..end];

    // 3. Resolve against the effective URL. Any failure → plain output
    //    (curl's `goto locout`, which `fwrite`s the original `location`).
    let base = match easy.getinfo(CurlInfo::EffectiveUrl) {
        Ok(InfoValue::Str(Some(c))) => c.to_string_lossy().into_owned(),
        _ => {
            write_to_sink(outs, location);
            return;
        }
    };
    let relative = String::from_utf8_lossy(stripped).into_owned();
    let mut u = Url::new();
    if u.set(CurlUPart::Url, Some(base.as_str()), 0).is_err() {
        write_to_sink(outs, location);
        return;
    }
    if u.set(CurlUPart::Url, Some(relative.as_str()), 0).is_err() {
        write_to_sink(outs, location);
        return;
    }
    let finalurl = match u.get(CurlUPart::Url, CURLU_NO_DEFAULT_PORT) {
        Ok(s) => s,
        Err(_) => {
            write_to_sink(outs, location);
            return;
        }
    };
    let scheme = match u.get(CurlUPart::Scheme, 0) {
        Ok(s) => s,
        Err(_) => {
            write_to_sink(outs, location);
            return;
        }
    };

    // 4. Emit the hyperlink only for "safe" schemes; otherwise plain.
    if matches!(scheme.as_str(), "http" | "https" | "ftp" | "ftps") {
        // curl: curl_mfprintf(stream, "%.*s" LINK "%s" LINKST "%.*s" LINKOFF,
        //   space_skipped, location,   /* the skipped leading blanks */
        //   finalurl,                  /* the resolved absolute URL  */
        //   (int)loclen - space_skipped, loc); /* original tail incl. CR/LF */
        let tail = &location[space_skipped..];
        let mut out = Vec::with_capacity(
            space_skipped
                + LINK.len()
                + finalurl.len()
                + LINKST.len()
                + tail.len()
                + LINKOFF.len(),
        );
        out.extend_from_slice(&location[..space_skipped]);
        out.extend_from_slice(LINK.as_bytes());
        out.extend_from_slice(finalurl.as_bytes());
        out.extend_from_slice(LINKST.as_bytes());
        out.extend_from_slice(tail);
        out.extend_from_slice(LINKOFF.as_bytes());
        write_to_sink(outs, &out);
    } else {
        write_to_sink(outs, location);
    }
}

// ===========================================================================
// Content-Disposition / Location filename — port of `content_disposition`
// (`src/tool_cb_hdr.c:294-419`), the `-J` / `--remote-header-name` engine.
// ===========================================================================

/// Sets the output filename from a `Content-Disposition` filename parameter (or,
/// as a fallback, a redirect `Location:`), the way `-O -J` (and `-J` alone)
/// require — the Rust port of `content_disposition`.
///
/// Operates on the disjoint pieces of `PerTransfer` it needs (`outs`,
/// `hdrcbdata`, the `config_idx`) so it borrows cleanly and is unit-testable
/// without a whole `PerTransfer`. `buffer` is the raw header line, `cb` its
/// length, `response` the HTTP status, and `global` supplies the
/// [`OperationConfig`](crate::config::OperationConfig) at `config_idx` (for
/// `output_dir` and `show_headers`).
///
/// Returns `0` on the ordinary path, `cb` when the line was buffered for later
/// writing (the `-J` + show-headers hold), or [`CURL_WRITEFUNC_ERROR`] on a
/// failure that must abort the transfer.
fn content_disposition(
    buffer: &[u8],
    cb: usize,
    outs: &mut OutStruct,
    hdrcbdata: &mut HdrCbData,
    config_idx: usize,
    global: &GlobalConfig,
    response: i64,
) -> usize {
    // ---- Location: branch (a fallback name from a 3xx redirect) ------------
    // curl: `if((cb > 9) && checkprefix("Location:", str) && (response/100 == 3))`
    if cb > 9 && checkprefix(b"Location:", buffer) && (response / 100 == 3) {
        // p = &str[9]; skip ISBLANK.
        let mut p = 9usize;
        while p < cb && is_blank(buffer[p]) {
            p += 1;
        }
        if p < cb {
            // curl: `parse_filename(p, cb - (p - str), 0)` — value runs to end.
            if let Some(filename) = parse_filename(&buffer[p..cb], None) {
                if outs.stream.is_some() {
                    // curl: indication of problem, get out!
                    return CURL_WRITEFUNC_ERROR;
                }
                outs.filename = Some(apply_output_dir(global, config_idx, filename));
                outs.alloc_filename = true;
                // Mark so an existing file is not clobbered by default.
                outs.is_cd_filename = true;
            }
        }
    }
    // ---- Content-disposition: branch (the authoritative name) ---------------
    // curl: `else if((cb > 20) && checkprefix("Content-disposition:", str))`
    else if cb > 20 && checkprefix(b"Content-disposition:", buffer) {
        let mut p = 20usize;
        loop {
            // Skip to the next parameter token start (curl:
            // `while((p<end) && *p && !ISALPHA(*p)) p++;`).
            while p < cb && buffer[p] != 0 && !buffer[p].is_ascii_alphabetic() {
                p += 1;
            }
            // curl: `if(p > end - 9) break;` — not enough room for "filename=".
            if p + 9 > cb {
                break;
            }
            // curl: `if(memcmp(p, "filename=", 9))` — note: a CASE-SENSITIVE
            // match (the RFC-5987 `filename*=` form is unsupported and skipped).
            if &buffer[p..p + 9] != b"filename=" {
                // No match: advance to the next ';'-separated parameter.
                while p < cb && buffer[p] != 0 && buffer[p] != b';' {
                    p += 1;
                }
                if p < cb && buffer[p] != 0 {
                    continue;
                }
                break;
            }
            p += 9;
            // Skip blanks after '=' (curl: `curlx_str_passblanks(&p)`).
            while p < cb && is_blank(buffer[p]) {
                p += 1;
            }
            // curl: `parse_filename(p, cb - (p - str), ';')`.
            if let Some(filename) = parse_filename(&buffer[p..cb], Some(b';')) {
                if outs.stream.is_some() {
                    return CURL_WRITEFUNC_ERROR;
                }
                outs.filename = Some(apply_output_dir(global, config_idx, filename));
                outs.is_cd_filename = true;
                outs.regular_file = true;
                outs.fopened = false;
                outs.alloc_filename = true;
                hdrcbdata.honor_cd_filename = false; // done now!
                // curl: open the file and flush any buffered headers into it.
                if !create_output_file(outs, &global.operations[config_idx], global) {
                    return CURL_WRITEFUNC_ERROR;
                }
                if tool_write_headers(hdrcbdata, outs) {
                    return CURL_WRITEFUNC_ERROR;
                }
            }
            break;
        }
        // curl: `if(!outs->stream && !tool_create_output_file(...)) return ERR;`
        // In Rust a stdout/stderr sink has `stream == None` with no filename, so
        // a real output file is "pending" only when a filename is set; that is
        // also `create_output_file`'s requirement.
        if outs.stream.is_none() {
            if outs.filename.is_some() {
                if !create_output_file(outs, &global.operations[config_idx], global) {
                    return CURL_WRITEFUNC_ERROR;
                }
            } else {
                // curl would `fopen(NULL)` → fail; mirror with an abort.
                return CURL_WRITEFUNC_ERROR;
            }
        }
        // curl: second `tool_write_headers` — a no-op once the list is cleared.
        if tool_write_headers(hdrcbdata, outs) {
            return CURL_WRITEFUNC_ERROR;
        }
    }

    // ---- Buffer the line while still awaiting Content-Disposition ----------
    // curl: `if(hdrcbdata->honor_cd_filename && hdrcbdata->config->show_headers)`
    if hdrcbdata.honor_cd_filename && global.operations[config_idx].show_headers {
        // The output file does not exist yet, so hold the header line in memory
        // (curl clones it with `curl_maprintf("%.*s", cb, str)` and appends to
        // the slist). Stored as raw bytes; flushed by `tool_write_headers` once
        // the file is created.
        hdrcbdata.headlist.push(buffer.to_vec());
        return cb; // done for now
    }

    0
}

/// Prefixes `filename` with `output_dir + "/"` when `--output-dir` is set,
/// matching curl's `curl_maprintf("%s/%s", config->output_dir, filename)` (and
/// returning the bare filename otherwise).
fn apply_output_dir(global: &GlobalConfig, config_idx: usize, filename: String) -> String {
    match global.operations[config_idx].output_dir.as_deref() {
        Some(dir) => format!("{dir}/{filename}"),
        None => filename,
    }
}

/// Parse the HTTP status code from a status line as it streams through the
/// header callback. Returns `None` for any non-status line. The status line is
/// `HTTP/<version> <code> <reason>`; the second whitespace-separated token is
/// the integer code (`HTTP/1.1 200 OK` → `200`, `HTTP/2 301 ...` → `301`). This
/// is the CLI's stand-in for `CURLINFO_RESPONSE_CODE` during the transfer — the
/// live handle is moved out (see [`tool_header_cb`]) — and mirrors the core's
/// own status-line parser (`parse_status_code`).
fn parse_status_line_code(line: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(line).ok()?;
    let rest = s.strip_prefix("HTTP/")?;
    let mut tokens = rest.split_whitespace();
    let _version = tokens.next()?; // "1.1", "1.0", "2", "3"
    tokens.next()?.parse::<i64>().ok()
}

/// Whether `url`'s scheme is `http` or `https` (case-insensitive). Gates the
/// etag / content-disposition header handling to HTTP(S) transfers — the CLI's
/// stand-in for `getinfo(SCHEME) ∈ {http, https}`, taken from the transfer URL
/// because the live handle is unavailable in the header callback.
fn url_is_http_or_https(url: &str) -> bool {
    let u = url.trim_start();
    match u.find("://") {
        Some(pos) => {
            let scheme = &u[..pos];
            scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
        }
        None => false,
    }
}

// ===========================================================================
// The CURLOPT_HEADERFUNCTION callback — port of `tool_header_cb`
// (`src/tool_cb_hdr.c:426-543`).
// ===========================================================================

/// The header callback libcurl invokes once per received response header line.
/// `buffer` is the raw header bytes (curl's `ptr`, length `size * nmemb` with
/// `size == 1`); `per` is the owning transfer; `global` the CLI configuration.
/// Returns the number of bytes consumed (`cb`), or [`CURL_WRITEFUNC_ERROR`] to
/// abort the transfer.
///
/// This is the public entry point a future transfer integrator registers against
/// `curl_rs_lib`'s safe header-callback surface. The control flow mirrors
/// `tool_header_cb` step for step; the disjoint pieces of `per` are split at each
/// call so the borrow checker is satisfied without `unsafe`.
pub fn tool_header_cb(buffer: &[u8], per: &mut PerTransfer, global: &mut GlobalConfig) -> usize {
    let cb = buffer.len(); // curl: `size * nmemb`
    let config_idx = per.config_idx;

    // curl: `if(!per->config) return CURL_WRITEFUNC_ERROR;`. The safe analogue of
    // a missing config is an out-of-range operation index.
    if config_idx >= global.operations.len() {
        return CURL_WRITEFUNC_ERROR;
    }

    // curl: `#ifdef DEBUGBUILD if(size*nmemb > CURL_MAX_HTTP_HEADER) {...}`.
    #[cfg(debug_assertions)]
    if cb > CURL_MAX_HTTP_HEADER {
        crate::warnf!(global, "Header data exceeds write limit");
        return CURL_WRITEFUNC_ERROR;
    }

    // (The `_WIN32` `utf8seq` incomplete-sequence discard is out of scope.)

    // Snapshot the config fields this callback consults so no borrow of `global`
    // is held across the mutations of `per` below.
    let (headerfile, has_etag_file, has_writeout, show_headers) = {
        let config = &global.operations[config_idx];
        (
            config.headerfile.clone(),
            config.etag_save_file.is_some(),
            config.writeout.is_some(),
            config.show_headers,
        )
    };

    // ---- --dump-header (-D): write raw header bytes to the heads sink -------
    // curl: `if(per->config->headerfile && heads->stream) { ... }`. In curl
    // `heads->stream` is *always* non-NULL once `-D <target>` is given — a file
    // for a path, `stdout` for `-`, `stderr` for `%`. This port cannot store the
    // process std streams in `heads.stream` (an `Option<File>`), so those two
    // targets carry `stream == None` (plus `to_stderr` for `%`); the C guard's
    // `heads->stream` therefore maps to "a `-D` target is configured", i.e.
    // `headerfile.is_some()`. `write_to_sink` then routes to the file, stdout, or
    // stderr exactly as curl's `fwrite(…, heads->stream)` would. (Previously this
    // also required `heads.stream.is_some()`, which silently dropped `-D -` and
    // `-D %` — only the regular-file case wrote anything.)
    if headerfile.is_some() {
        let rc = write_to_sink(&mut per.heads, buffer);
        if rc != cb {
            // curl: `if(rc != nmemb) return rc;` — a short write aborts.
            return rc;
        }
        if flush_sink(&mut per.heads).is_err() {
            let name = headerfile.as_deref().unwrap_or("");
            crate::errorf!(global, "Failed writing headers to {name}");
            return CURL_WRITEFUNC_ERROR;
        }
    }

    // ---- Scheme retained only for the `-i`/`--include` header echo ---------
    // curl's `tool_header_cb` reads getinfo(SCHEME) from the live handle. Here
    // the real easy handle is moved out for the duration of the CLI transfer
    // (`perform_with_cli_io`), so getinfo returns the default (empty) — and the
    // `-i` header echo further below is in any case driven independently by the
    // core's `CURLOPT_HEADER` merge (set from `show_headers` in `setopt`). This
    // value is therefore retained purely to preserve that block's original gate.
    let scheme = match per.easy.getinfo(CurlInfo::Scheme) {
        Ok(InfoValue::Str(Some(c))) => c.to_string_lossy().to_ascii_lowercase(),
        _ => String::new(),
    };

    // ---- Track the response code from the status line ----------------------
    // The CLI cannot read `CURLINFO_RESPONSE_CODE` / `CURLINFO_SCHEME` from the
    // in-flight handle (moved out, as above), so `--etag-save` / `-J` would never
    // fire if gated on getinfo. curl reads the live code via
    // `curl_easy_getinfo(per->curl, CURLINFO_RESPONSE_CODE)` in `tool_header_cb`;
    // we instead parse it from the status line as it streams through this
    // callback. The status line always precedes the `ETag:`/`Content-Disposition:`
    // lines of its block, and the latest status line wins — mirroring getinfo
    // returning the most recent response code across redirect/auth hops.
    if let Some(code) = parse_status_line_code(buffer) {
        per.hdrcbdata.last_response_code = code;
    }

    // ---- Scheme / response gating for --etag-save and -J -------------------
    // curl: only http/https carry a response code, and only 2xx/3xx responses
    // care about etag / content-disposition (`tool_cb_hdr.c`). The scheme is
    // taken from the transfer URL (`per.url`) — equivalent to getinfo(SCHEME) for
    // this http/https gate — and the response code from the status line tracked
    // above, because the live handle is unavailable mid-transfer.
    let http_like = per.url.as_deref().is_some_and(url_is_http_or_https);
    if http_like {
        let response = per.hdrcbdata.last_response_code;
        let class = response / 100;
        if class == 2 || class == 3 {
            if has_etag_file
                && per.etag_save.stream.is_some()
                && checkprefix(b"etag:", buffer)
            {
                // curl: `save_etag(&str[5], end, etag_save)`.
                let rc = save_etag(&buffer[5..], &mut per.etag_save);
                if rc != 0 {
                    return rc;
                }
            } else if per.hdrcbdata.honor_cd_filename {
                let rc = content_disposition(
                    buffer,
                    cb,
                    &mut per.outs,
                    &mut per.hdrcbdata,
                    config_idx,
                    global,
                    response,
                );
                if rc != 0 {
                    return rc;
                }
            }
        }
    }

    // ---- --write-out header counting (%{num_headers}) ----------------------
    // curl: `if(hdrcbdata->config->writeout) { ... }` — no scheme gate.
    if has_writeout {
        if buffer.contains(&b':') {
            // A real header line: reset the count at the start of a new block.
            if per.was_last_header_empty {
                per.num_headers = 0;
            }
            per.was_last_header_empty = false;
            per.num_headers += 1;
        } else if matches!(buffer.first().copied(), Some(b'\r') | Some(b'\n')) {
            // A blank line ends the current header block.
            per.was_last_header_empty = true;
        }
    }

    // ---- Echo headers to the body output (-i / --include) ------------------
    // curl: `if(show_headers && !outs->out_null && scheme in {http,https,rtsp,file})`
    if show_headers
        && !per.outs.out_null
        && matches!(scheme.as_str(), "http" | "https" | "rtsp" | "file")
    {
        // Lazily open the output file if a name is pending (curl: `if(!outs->stream
        // && !tool_create_output_file(...)) return ERROR`). A stdout/stderr sink
        // has no filename and is left to `write_to_sink`.
        if per.outs.stream.is_none()
            && per.outs.filename.is_some()
            && !create_output_file(&mut per.outs, &global.operations[config_idx], global)
        {
            return CURL_WRITEFUNC_ERROR;
        }

        // curl computes the name/value split (and the bold path) only for styled,
        // interactive output; otherwise the whole line is written verbatim. (On
        // POSIX bold is assumed available whenever the tty is styled — curl's
        // `tool_term_has_bold` is a Windows-only probe; see the module docs.)
        let value_pos = if global.isatty && global.styled_output {
            buffer.iter().position(|&b| b == b':')
        } else {
            None
        };

        if let Some(colon) = value_pos {
            let name = &buffer[..colon];
            // curl: curl_mfprintf(stream, BOLD "%.*s" BOLDOFF ":", namelen, ptr).
            let mut styled =
                Vec::with_capacity(BOLD.len() + name.len() + BOLDOFF.len() + 1);
            styled.extend_from_slice(BOLD.as_bytes());
            styled.extend_from_slice(name);
            styled.extend_from_slice(BOLDOFF.as_bytes());
            styled.push(b':');
            write_to_sink(&mut per.outs, &styled);

            // curl: `&value[1]`, length `cb - namelen - 1` — the value after ':'.
            let value_bytes = &buffer[colon + 1..];
            if name_is_location(name) {
                write_linked_location(&per.easy, value_bytes, &mut per.outs);
            } else {
                write_to_sink(&mut per.outs, value_bytes);
            }
        } else {
            // Not styled (or no colon): write the whole line verbatim.
            write_to_sink(&mut per.outs, buffer);
        }
    }

    cb
}

// ===========================================================================
// Unit tests — exercise the parity-critical helpers directly. These cover the
// pure logic (`parse_filename`, the ctype helpers, `parse_vte_version`,
// `name_is_location`) and the file-touching helpers (`save_etag`,
// `tool_write_headers`, `content_disposition`) without needing a live transfer.
// They never touch the process stdout: every sink is a temp file or an in-memory
// buffer.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;
    use tempfile::tempdir;

    // ---- character-class helpers -------------------------------------------

    #[test]
    fn ctype_is_blank_and_is_space() {
        assert!(is_blank(b' '));
        assert!(is_blank(b'\t'));
        assert!(!is_blank(b'\n'));
        assert!(!is_blank(b'a'));

        // ISSPACE includes vertical tab (0x0B), which Rust's
        // `is_ascii_whitespace` deliberately excludes — the reason a custom
        // helper is required.
        for b in [b' ', b'\t', b'\n', 0x0b, 0x0c, b'\r'] {
            assert!(is_space(b), "0x{b:02x} should be ISSPACE");
        }
        assert!(!is_space(b'a'));
        assert!(!0x0b_u8.is_ascii_whitespace()); // documents the divergence
        assert!(is_space(0x0b));
    }

    #[test]
    fn checkprefix_is_case_insensitive_and_length_guarded() {
        assert!(checkprefix(b"Location:", b"location: /x\r\n"));
        assert!(checkprefix(b"Content-disposition:", b"CONTENT-DISPOSITION: x"));
        assert!(checkprefix(b"etag:", b"ETag: \"v\"\r\n"));
        assert!(!checkprefix(b"etag:", b"eta")); // shorter than prefix
        assert!(!checkprefix(b"Location:", b"X-Location: y"));
    }

    #[test]
    fn name_is_location_matches_curl_strnequal() {
        assert!(name_is_location(b"Location"));
        assert!(name_is_location(b"location"));
        assert!(name_is_location(b"LOCATION"));
        // curl quirk: a truncated prefix matches (strnequal stops at `namelen`).
        assert!(name_is_location(b"Locat"));
        assert!(name_is_location(b"")); // zero-length prefix matches
        // Longer than "Location" never matches (the 9th char is curl's NUL).
        assert!(!name_is_location(b"LocationX"));
        assert!(!name_is_location(b"X-Location"));
        assert!(!name_is_location(b"Content-Type"));
    }

    #[test]
    fn parse_vte_version_parses_leading_digits() {
        assert_eq!(parse_vte_version(b"6003"), Some(6003));
        assert_eq!(parse_vte_version(b"4801"), Some(4801));
        assert_eq!(parse_vte_version(b"52.1"), Some(52)); // stops at '.'
        assert_eq!(parse_vte_version(b"0"), Some(0));
        assert_eq!(parse_vte_version(b""), None); // no digits
        assert_eq!(parse_vte_version(b"abc"), None);
        assert_eq!(parse_vte_version(b" 12"), None); // no leading space allowed
        // Overflow past i64::MAX yields None.
        assert_eq!(parse_vte_version(b"99999999999999999999999"), None);
    }

    // ---- parse_filename -----------------------------------------------------

    #[test]
    fn parse_filename_content_disposition_quoted() {
        assert_eq!(
            parse_filename(b"\"report.pdf\";", Some(b';')).as_deref(),
            Some("report.pdf")
        );
        // single quotes work too
        assert_eq!(
            parse_filename(b"'a b.txt'", Some(b';')).as_deref(),
            Some("a b.txt")
        );
    }

    #[test]
    fn parse_filename_content_disposition_unquoted_stops_at_semicolon() {
        assert_eq!(
            parse_filename(b"file.bin;charset=utf-8", Some(b';')).as_deref(),
            Some("file.bin")
        );
    }

    #[test]
    fn parse_filename_location_trims_query_and_fragment_and_path() {
        assert_eq!(
            parse_filename(b"/path/to/file.html?q=1#frag", None).as_deref(),
            Some("file.html")
        );
        assert_eq!(
            parse_filename(b"http://h/a/b/name.bin\r\n", None).as_deref(),
            Some("name.bin")
        );
    }

    #[test]
    fn parse_filename_strips_backslash_component_and_trailing_eol() {
        assert_eq!(
            parse_filename(b"a\\b\\c.dat\r\n", Some(b';')).as_deref(),
            Some("c.dat")
        );
    }

    #[test]
    fn parse_filename_empty_after_separator_is_none() {
        assert_eq!(parse_filename(b"/path/", None), None);
        assert_eq!(parse_filename(b"dir\\", Some(b';')), None);
    }

    #[test]
    fn parse_filename_empty_value_is_empty_string_not_none() {
        // curl returns the (empty) copy, not NULL, for an empty quoted value.
        assert_eq!(parse_filename(b"\"\"", Some(b';')).as_deref(), Some(""));
    }

    // ---- save_etag ----------------------------------------------------------

    /// A read+write temp-file `OutStruct` plus the path, for the file-touching
    /// helpers.
    fn file_outs(dir: &std::path::Path, name: &str) -> (OutStruct, std::path::PathBuf) {
        let path = dir.join(name);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let outs = OutStruct {
            stream: Some(file),
            ..OutStruct::default()
        };
        (outs, path)
    }

    #[test]
    fn save_etag_writes_trimmed_value_and_newline() {
        let dir = tempdir().unwrap();
        let (mut outs, path) = file_outs(dir.path(), "etag");
        // Pre-fill with longer content to prove truncation happens.
        if let Some(f) = outs.stream.as_mut() {
            f.write_all(b"PRE-EXISTING LONG CONTENT").unwrap();
        }
        // value is `&str[5..]`: leading blank + quoted value + CRLF.
        let rc = save_etag(b" \"abc123\"\r\n", &mut outs);
        assert_eq!(rc, 0);
        let contents = fs::read(&path).unwrap();
        assert_eq!(contents, b"\"abc123\"\n");
    }

    #[test]
    fn save_etag_ignores_value_without_trailing_newline() {
        let dir = tempdir().unwrap();
        let (mut outs, path) = file_outs(dir.path(), "etag2");
        let rc = save_etag(b" \"abc\"\r", &mut outs); // ends in '\r', not '\n'
        assert_eq!(rc, 0);
        assert!(fs::read(&path).unwrap().is_empty());
    }

    #[test]
    fn save_etag_all_whitespace_writes_nothing() {
        let dir = tempdir().unwrap();
        let (mut outs, path) = file_outs(dir.path(), "etag3");
        let rc = save_etag(b"   \r\n", &mut outs);
        assert_eq!(rc, 0);
        assert!(fs::read(&path).unwrap().is_empty());
    }

    // ---- response-code / scheme gate helpers --------------------------------

    #[test]
    fn parse_status_line_code_reads_second_token() {
        assert_eq!(parse_status_line_code(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status_line_code(b"HTTP/1.0 301 Moved\r\n"), Some(301));
        assert_eq!(parse_status_line_code(b"HTTP/2 204\r\n"), Some(204));
        assert_eq!(parse_status_line_code(b"HTTP/3 200\r\n"), Some(200));
        // Non-status lines and malformed status lines yield None.
        assert_eq!(parse_status_line_code(b"ETag: W/\"x\"\r\n"), None);
        assert_eq!(parse_status_line_code(b"\r\n"), None);
        assert_eq!(parse_status_line_code(b"HTTP/1.1\r\n"), None); // no code token
        assert_eq!(parse_status_line_code(b"HTTP/1.1 NaN Bad\r\n"), None);
    }

    #[test]
    fn url_is_http_or_https_matches_scheme_case_insensitively() {
        assert!(url_is_http_or_https("http://h/x"));
        assert!(url_is_http_or_https("https://h/x"));
        assert!(url_is_http_or_https("HTTP://h/x"));
        assert!(url_is_http_or_https("HtTpS://h/x"));
        assert!(!url_is_http_or_https("ftp://h/x"));
        assert!(!url_is_http_or_https("file:///x"));
        assert!(!url_is_http_or_https("no-scheme-here"));
        assert!(!url_is_http_or_https(""));
    }

    /// A read+write temp `OutStruct` bound to `path`, used as the `--etag-save`
    /// sink for the `tool_header_cb` integration tests.
    fn etag_sink(path: &std::path::Path) -> OutStruct {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        OutStruct {
            stream: Some(file),
            ..OutStruct::default()
        }
    }

    /// End-to-end: a 2xx response with an `ETag:` header on an http URL must
    /// write the trimmed etag to the `--etag-save` file. Regression test for the
    /// CLI etag-save gate: the live easy handle is moved out during the transfer,
    /// so the gate must derive the scheme from `per.url` and the response code
    /// from the status line (parsed by the callback) rather than from `getinfo`,
    /// which would return the placeholder defaults and skip the save. Mirrors
    /// curl test 339.
    #[test]
    fn tool_header_cb_saves_etag_on_2xx_http() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("etag339");
        let mut global = GlobalConfig::new();
        global.operations[0].etag_save_file = Some(path.to_string_lossy().into_owned());
        let mut per = PerTransfer::new(0);
        per.url = Some("http://127.0.0.1/339".to_string());
        per.etag_save = etag_sink(&path);
        // The status line arrives first, then the ETag header — exactly as the
        // engine streams them to the callback.
        tool_header_cb(b"HTTP/1.1 200 funky chunky!\r\n", &mut per, &mut global);
        tool_header_cb(b"ETag: W/\"asdf\"\r\n", &mut per, &mut global);
        // Close the sink so the bytes are flushed before reading back.
        per.etag_save.stream = None;
        assert_eq!(fs::read(&path).unwrap(), b"W/\"asdf\"\n");
    }

    /// A 3xx (redirect) response that is not followed must still save its etag —
    /// curl saves in 2xx and 3xx alike. Mirrors curl test 473 (etag on a 301).
    #[test]
    fn tool_header_cb_saves_etag_on_3xx_http() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("etag473");
        let mut global = GlobalConfig::new();
        global.operations[0].etag_save_file = Some(path.to_string_lossy().into_owned());
        let mut per = PerTransfer::new(0);
        per.url = Some("http://127.0.0.1/473".to_string());
        per.etag_save = etag_sink(&path);
        tool_header_cb(b"HTTP/1.1 301 funky chunky!\r\n", &mut per, &mut global);
        tool_header_cb(b"ETag: W/\"asdf\"\r\n", &mut per, &mut global);
        per.etag_save.stream = None;
        assert_eq!(fs::read(&path).unwrap(), b"W/\"asdf\"\n");
    }

    /// A 4xx response must NOT save the etag (the gate restricts to 2xx/3xx),
    /// matching curl's `(response/100 != 2) && (response/100 != 3)` skip.
    #[test]
    fn tool_header_cb_skips_etag_on_4xx() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("etag4xx");
        let mut global = GlobalConfig::new();
        global.operations[0].etag_save_file = Some(path.to_string_lossy().into_owned());
        let mut per = PerTransfer::new(0);
        per.url = Some("http://127.0.0.1/x".to_string());
        per.etag_save = etag_sink(&path);
        tool_header_cb(b"HTTP/1.1 404 Not Found\r\n", &mut per, &mut global);
        tool_header_cb(b"ETag: W/\"asdf\"\r\n", &mut per, &mut global);
        per.etag_save.stream = None;
        assert!(fs::read(&path).unwrap().is_empty());
    }

    /// A non-HTTP scheme must NOT save the etag even on a 2xx — the gate is
    /// http/https only (curl's `scheme == proto_http || proto_https`).
    #[test]
    fn tool_header_cb_skips_etag_on_non_http_scheme() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("etagftp");
        let mut global = GlobalConfig::new();
        global.operations[0].etag_save_file = Some(path.to_string_lossy().into_owned());
        let mut per = PerTransfer::new(0);
        per.url = Some("ftp://127.0.0.1/x".to_string());
        per.etag_save = etag_sink(&path);
        tool_header_cb(b"HTTP/1.1 200 OK\r\n", &mut per, &mut global);
        tool_header_cb(b"ETag: W/\"asdf\"\r\n", &mut per, &mut global);
        per.etag_save.stream = None;
        assert!(fs::read(&path).unwrap().is_empty());
    }

    // ---- tool_write_headers -------------------------------------------------

    #[test]
    fn tool_write_headers_flushes_then_always_clears() {
        let dir = tempdir().unwrap();
        let (mut outs, path) = file_outs(dir.path(), "heads");
        let mut hdr = HdrCbData {
            config_idx: 0,
            honor_cd_filename: false,
            headlist: vec![b"H1: a\r\n".to_vec(), b"H2: b\r\n".to_vec()],
            last_response_code: 0,
        };
        let failed = tool_write_headers(&mut hdr, &mut outs);
        assert!(!failed);
        assert!(hdr.headlist.is_empty()); // always cleared
        // Reopen the file to read what was written (the held handle is mid-file).
        let mut buf = Vec::new();
        fs::File::open(&path).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"H1: a\r\nH2: b\r\n");
    }

    #[test]
    fn tool_write_headers_on_empty_list_is_success_noop() {
        let dir = tempdir().unwrap();
        let (mut outs, _path) = file_outs(dir.path(), "heads2");
        let mut hdr = HdrCbData::default();
        assert!(!tool_write_headers(&mut hdr, &mut outs));
        assert!(hdr.headlist.is_empty());
    }

    // ---- content_disposition ------------------------------------------------

    fn global_with_output_dir(dir: &std::path::Path, show_headers: bool) -> GlobalConfig {
        let mut g = GlobalConfig::new();
        g.operations[0].output_dir = Some(dir.to_string_lossy().into_owned());
        g.operations[0].show_headers = show_headers;
        g
    }

    #[test]
    fn content_disposition_sets_filename_and_creates_file() {
        let dir = tempdir().unwrap();
        let global = global_with_output_dir(dir.path(), false);
        let mut outs = OutStruct::default();
        let mut hdr = HdrCbData {
            config_idx: 0,
            honor_cd_filename: true,
            headlist: Vec::new(),
            last_response_code: 0,
        };
        let line = b"Content-Disposition: attachment; filename=\"report.pdf\"\r\n";
        let rc = content_disposition(line, line.len(), &mut outs, &mut hdr, 0, &global, 200);
        assert_eq!(rc, 0);
        let expected = dir.path().join("report.pdf");
        assert_eq!(outs.filename.as_deref(), expected.to_str());
        assert!(outs.is_cd_filename);
        assert!(outs.regular_file);
        assert!(outs.alloc_filename);
        assert!(!hdr.honor_cd_filename); // consumed
        assert!(outs.stream.is_some()); // file was created
        assert!(expected.exists());
    }

    #[test]
    fn content_disposition_location_fallback_on_3xx() {
        let dir = tempdir().unwrap();
        let global = global_with_output_dir(dir.path(), false);
        let mut outs = OutStruct::default();
        let mut hdr = HdrCbData {
            config_idx: 0,
            honor_cd_filename: true,
            headlist: Vec::new(),
            last_response_code: 0,
        };
        let line = b"Location: /downloads/file.zip\r\n";
        let rc = content_disposition(line, line.len(), &mut outs, &mut hdr, 0, &global, 302);
        assert_eq!(rc, 0);
        let expected = dir.path().join("file.zip");
        assert_eq!(outs.filename.as_deref(), expected.to_str());
        assert!(outs.is_cd_filename);
        // The Location branch only records the name; it does not open the file.
        assert!(outs.stream.is_none());
        assert!(hdr.honor_cd_filename); // still awaiting Content-Disposition
    }

    #[test]
    fn content_disposition_location_ignored_on_2xx() {
        // The Location fallback is only for 3xx; a 200 leaves the name unset.
        let dir = tempdir().unwrap();
        let global = global_with_output_dir(dir.path(), false);
        let mut outs = OutStruct::default();
        let mut hdr = HdrCbData {
            config_idx: 0,
            honor_cd_filename: true,
            headlist: Vec::new(),
            last_response_code: 0,
        };
        let line = b"Location: /downloads/file.zip\r\n";
        let rc = content_disposition(line, line.len(), &mut outs, &mut hdr, 0, &global, 200);
        assert_eq!(rc, 0);
        assert!(outs.filename.is_none());
    }

    #[test]
    fn content_disposition_buffers_other_headers_when_showing() {
        // A non-matching header, with honor_cd_filename + show_headers, is held
        // in headlist and the call returns `cb`.
        let dir = tempdir().unwrap();
        let global = global_with_output_dir(dir.path(), true);
        let mut outs = OutStruct::default();
        let mut hdr = HdrCbData {
            config_idx: 0,
            honor_cd_filename: true,
            headlist: Vec::new(),
            last_response_code: 0,
        };
        let line = b"Server: nginx\r\n";
        let rc = content_disposition(line, line.len(), &mut outs, &mut hdr, 0, &global, 200);
        assert_eq!(rc, line.len());
        assert_eq!(hdr.headlist, vec![line.to_vec()]);
        assert!(hdr.honor_cd_filename); // unchanged
        assert!(outs.filename.is_none());
    }

    #[test]
    fn content_disposition_output_dir_prefix_applied() {
        let dir = tempdir().unwrap();
        let global = global_with_output_dir(dir.path(), false);
        let mut outs = OutStruct::default();
        let mut hdr = HdrCbData {
            config_idx: 0,
            honor_cd_filename: true,
            headlist: Vec::new(),
            last_response_code: 0,
        };
        // Unquoted filename, stopping at the trailing CRLF.
        let line = b"Content-Disposition: inline; filename=data.json\r\n";
        let rc = content_disposition(line, line.len(), &mut outs, &mut hdr, 0, &global, 200);
        assert_eq!(rc, 0);
        let expected = dir.path().join("data.json");
        assert_eq!(outs.filename.as_deref(), expected.to_str());
    }

    #[test]
    fn apply_output_dir_with_and_without_dir() {
        let dir = tempdir().unwrap();
        let with = global_with_output_dir(dir.path(), false);
        assert_eq!(
            apply_output_dir(&with, 0, "x.txt".to_string()),
            format!("{}/x.txt", dir.path().to_string_lossy())
        );
        let without = GlobalConfig::new(); // output_dir is None
        assert_eq!(apply_output_dir(&without, 0, "x.txt".to_string()), "x.txt");
    }
}

