// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

//! CURLOPT_HEADERFUNCTION — `-D`/`--dump-header`, `--etag-save`, `-O` from
//! `Content-Disposition`, write-out capture, bold/OSC8 header display.
//!
//! Rust rewrite of curl 8.19.0-DEV's `src/tool_cb_hdr.c`. This is the CLI header
//! callback installed via `CURLOPT_HEADERFUNCTION`/`CURLOPT_HEADERDATA`. It is a
//! faithful, behaviour-preserving port: filename derivation, clobber interplay,
//! and every emitted message match curl 8.x byte-for-byte (AAP §0.7 —
//! behavioural parity is binding).
//!
//! Responsibilities, mirroring the C original:
//! * `--dump-header` (`-D`): stream received header bytes to a side file.
//! * `--etag-save`: capture the `ETag` value of 2xx/3xx HTTP responses.
//! * `-O`/`-J` (`--remote-header-name`): derive the output filename from a
//!   `Content-Disposition` (or, as a fallback, `Location`) header.
//! * `--write-out` header counting (`%{num_headers}`).
//! * Bold header names and OSC 8 hyperlinked `Location:` values on styled TTYs.
//!
//! Platform scope: this crate targets `*-unknown-linux-gnu` and `*-apple-darwin`
//! only, so all `_WIN32`/`MSDOS` branches of the C file (`sanitize_file_name`,
//! `tool_term_has_bold`, the incomplete-UTF-8 discard, and `BOLDOFF="\x1b[22m"`),
//! the `DEBUGBUILD` header-size guard, and the `#ifndef LINK` fallback are dropped
//! — on unix `LINK` (OSC 8) is always defined. The `#ifndef HAVE_FTRUNCATE` seek
//! fallback becomes [`std::fs::File::set_len`].
//!
//! Integration status: like the sibling callbacks (`read`, `seek`, `write`), this
//! module is the CLI-side callback surface. It is fully implemented but not yet
//! wired into the transfer engine, hence the `#[allow(dead_code)]` markers.

use core::ffi::{c_char, c_void};
use std::io::{Seek, SeekFrom, Write};

use curl_rs_ffi::easy::CURL_WRITEFUNC_ERROR;
use curl_rs_lib::urlapi::{CurlUPart, Url, NO_DEFAULT_PORT};

use crate::args::OperationConfig;
use crate::callbacks::write::tool_create_output_file;
use crate::callbacks::{userdata_mut, OutSink, OutStruct};
use crate::operate::{errorf, PerTransfer};

// ANSI / OSC 8 escape sequences (unix values from `tool_cb_hdr.c:42-50`).
/// Turn on bold.
const BOLD: &str = "\x1b[1m";
/// Turn bold off via "all attributes off" (`\x1b[0m`); the explicit bold-off
/// code (21/22) is not honoured everywhere, e.g. the macOS Terminal.
const BOLDOFF: &str = "\x1b[0m";
/// OSC 8 hyperlink introducer.
const LINK: &str = "\x1b]8;;";
/// OSC 8 string terminator (ESC `\`).
const LINKST: &str = "\x1b\\";
/// OSC 8 hyperlink closer: `LINK LINKST`.
const LINKOFF: &str = "\x1b]8;;\x1b\\";

/// Per-transfer state for the header callback.
///
/// Faithful to `tool_cb_hdr.h:43`'s `struct HdrCbData`, minus three pointer
/// fields (`outs`, `heads`, `etag_save`). Those are redundant aliases of the
/// [`PerTransfer`] fields the C `tool_header_cb` actually dereferences
/// (`per->outs` / `per->heads` / `per->etag_save`); reproducing them as Rust
/// references or raw pointers would create needless aliasing/borrow hazards, so
/// the callback reaches those buffers through `per` directly. The retained
/// `config` pointer mirrors C's `hdrcbdata->config` (which, in curl, is the same
/// pointer as `per->config`) and follows the raw-pointer-to-`OperationConfig`
/// precedent set by `write.rs`'s `WriteData`.
#[allow(dead_code)]
pub struct HdrCbData {
    /// The active [`OperationConfig`] (same object as `per`'s config). Held as a
    /// raw pointer to match curl's `hdrcbdata->config` and to avoid tying the
    /// callback context to a borrow of `per`.
    pub config: *mut OperationConfig,
    /// Headers buffered in memory while awaiting a `Content-Disposition` header
    /// (mirrors C's `struct curl_slist *headlist`). Each entry is a full header
    /// line, written out once the destination file is created.
    pub headlist: Vec<String>,
    /// Whether a `Content-Disposition` filename is still being honoured
    /// (`-J`/`--remote-header-name`). Mirrors C's `BIT(honor_cd_filename)`.
    pub honor_cd_filename: bool,
}

impl Default for HdrCbData {
    fn default() -> Self {
        HdrCbData {
            config: core::ptr::null_mut(),
            headlist: Vec::new(),
            honor_cd_filename: false,
        }
    }
}

/// Case-insensitive prefix test, mirroring curl's `checkprefix(prefix, buf)`
/// (`curl_strnequal(prefix, buf, strlen(prefix))`). Returns `false` when `s` is
/// shorter than `prefix` — safer than the C `strncasecmp`, which may read past a
/// short buffer, and behaviourally identical for real (longer) header lines.
#[allow(dead_code)]
fn checkprefix(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// `ISBLANK`: space or tab.
#[allow(dead_code)]
fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// `ISSPACE` (C locale): space, tab, LF, CR, vertical tab, form feed.
#[allow(dead_code)]
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// Case-insensitive equivalent of `curl_strnequal("Location", name, name.len())`.
///
/// Compares `name` against the literal `"Location"` using `strncasecmp`
/// semantics: byte-for-byte case-insensitive comparison bounded by `name.len()`,
/// stopping at the terminating NUL of `"Location"`.
#[allow(dead_code)]
fn is_location_name(name: &[u8]) -> bool {
    const LOC: &[u8] = b"Location";
    for (i, &b) in name.iter().enumerate() {
        // Byte from "Location", or its NUL terminator once we run past the end.
        let a = if i < LOC.len() { LOC[i] } else { 0u8 };
        if a.to_ascii_lowercase() != b.to_ascii_lowercase() {
            return false;
        }
        if a == 0 {
            // Reached "Location"'s NUL and it matched a NUL in `name`; strncasecmp
            // stops comparing here and reports equality so far.
            return true;
        }
    }
    true
}

/// Parse a leading decimal integer, mirroring curl's `curlx_str_number`.
///
/// Consumes ASCII digits from the front of `s`, saturating on overflow. Returns
/// `None` when no digit is present (i.e. the C parser would have failed).
#[allow(dead_code)]
fn parse_leading_number(s: &[u8]) -> Option<i64> {
    let mut i = 0usize;
    let mut num: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        num = num
            .saturating_mul(10)
            .saturating_add(i64::from(s[i] - b'0'));
        i += 1;
    }
    if i == 0 {
        None
    } else {
        Some(num)
    }
}

/// Copy a filename part out of a header value, returning the owned basename.
///
/// Port of C's `parse_filename` (`tool_cb_hdr.c:150-231`). `ptr[..len]` is the
/// value to parse; embedded NULs terminate the working copy (matching
/// `curlx_memdup0`). `stop` selects the mode:
/// * `stop != 0` — a `Content-Disposition` value: honour a leading quote (using
///   it as the terminator) and truncate at the stop character.
/// * `stop == 0` — a `Location` value: strip the query (`?`) then fragment (`#`).
///
/// The path portion is then removed (basename after the last `/` and `\`), and
/// the result is truncated at the first CR/LF. Returns `None` when a trailing
/// path separator leaves an empty basename. The `_WIN32`/`MSDOS`
/// `sanitize_file_name` post-processing is intentionally dropped.
#[allow(dead_code)]
fn parse_filename(ptr: &[u8], len: usize, stop: u8) -> Option<String> {
    // curlx_memdup0(ptr, len): copy `len` bytes; NUL-terminate. Subsequent str*
    // operations treat the first embedded NUL as the end of the string.
    let raw = &ptr[..len.min(ptr.len())];
    let end0 = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let mut work: Vec<u8> = raw[..end0].to_vec();
    let mut stop = stop;

    if stop != 0 {
        // A Content-Disposition: header value.
        let mut start = 0usize;
        if let Some(&first) = work.first() {
            if first == b'\'' || first == b'"' {
                // Store the starting quote as the terminator and skip it.
                stop = first;
                start = 1;
            }
        }
        // Scan for the end letter and stop there.
        if let Some(rel) = work[start..].iter().position(|&b| b == stop) {
            work.truncate(start + rel);
        }
        if start == 1 {
            work.remove(0);
        }
    } else {
        // A Location: header, trim off any query and fragment present.
        if let Some(i) = work.iter().position(|&b| b == b'?') {
            work.truncate(i);
        }
        if let Some(i) = work.iter().position(|&b| b == b'#') {
            work.truncate(i);
        }
    }

    // If the filename contains a path, only use the filename portion.
    if let Some(i) = work.iter().rposition(|&b| b == b'/') {
        if i + 1 >= work.len() {
            return None;
        }
        work.drain(..=i);
    }
    // Likewise for a backslash separator (even on systems that do not treat it as
    // a separator, the path prefix is dropped for convenience).
    if let Some(i) = work.iter().rposition(|&b| b == b'\\') {
        if i + 1 >= work.len() {
            return None;
        }
        work.drain(..=i);
    }
    // Make sure the filename does not end in CR or LF.
    if let Some(i) = work.iter().position(|&b| b == b'\r') {
        work.truncate(i);
    }
    if let Some(i) = work.iter().position(|&b| b == b'\n') {
        work.truncate(i);
    }

    Some(String::from_utf8_lossy(&work).into_owned())
}

/// Flush the buffered headers to `stream`, then clear the buffer.
///
/// Port of C's `tool_write_headers` (`tool_cb_hdr.c:233-249`). Writes each stored
/// header line to `stream`; a short or failed write aborts. The list is **always**
/// cleared afterwards (C frees the slist and NULLs it on both success and
/// failure). Returns `Ok(())` on success and `Err(())` on any write failure —
/// `write.rs` maps the error to `CURL_WRITEFUNC_ERROR`.
#[allow(dead_code)]
pub fn tool_write_headers(hdrcbdata: &mut HdrCbData, stream: &mut OutSink) -> Result<(), ()> {
    let mut result: Result<(), ()> = Ok(());
    for h in &hdrcbdata.headlist {
        let bytes = h.as_bytes();
        match stream.write_all(bytes) {
            Ok(n) if n == bytes.len() => {}
            _ => {
                result = Err(());
                break;
            }
        }
    }
    // Free the buffered headers regardless of success/failure (C: curl_slist_free_all + NULL).
    hdrcbdata.headlist.clear();
    result
}

/// Write the captured ETag value to the `--etag-save` file.
///
/// Port of C's `save_etag` (`tool_cb_hdr.c:254-286`). `etag_h` is the header
/// slice after `"etag:"`, up to and including the terminating LF. The value is
/// only saved when the last byte is `'\n'`; leading `ISBLANK` and trailing
/// `ISSPACE` are trimmed. The destination file is truncated to zero (it may hold
/// a previous value) and rewritten with the trimmed value plus a trailing LF.
///
/// Only a truncate failure is reported as `CURL_WRITEFUNC_ERROR`; curl ignores
/// `fwrite`/`fflush` errors here. A non-regular sink (e.g. stdout) cannot be
/// truncated — curl's `ftruncate` on such a descriptor fails — so that also maps
/// to the write-error signal. Returns `0` on success.
#[allow(dead_code)]
fn save_etag(etag_h: &[u8], etag_save: &mut OutStruct) -> usize {
    let n = etag_h.len();
    // eot = endp - 1 (the header's last byte). Only act when it is a newline.
    if n == 0 || etag_h[n - 1] != b'\n' {
        return 0;
    }
    let eot0 = n - 1; // index of the last byte (the '\n')

    // Trim leading ISBLANK, bounded by the original end (as in C).
    let mut lo = 0usize;
    while lo < eot0 && is_blank(etag_h[lo]) {
        lo += 1;
    }
    // Trim trailing ISSPACE. C decrements without a lower bound but relies on the
    // subsequent `eot >= etag_h` guard; the `hi >= 0` bound is the safe analogue.
    let mut hi: isize = eot0 as isize;
    while hi >= 0 && is_space(etag_h[hi as usize]) {
        hi -= 1;
    }
    if hi < lo as isize {
        // C: `if(eot >= etag_h)` is false — nothing worth saving.
        return 0;
    }
    let value = &etag_h[lo..=(hi as usize)];

    match &mut etag_save.stream {
        OutSink::File(bw) => {
            // Flush buffered bytes before repositioning the descriptor, then
            // truncate. ftruncate leaves the offset intact, so seek to the start
            // (independent of the handle's append open mode) before rewriting.
            let _ = bw.flush();
            let file = bw.get_mut();
            if file.set_len(0).is_err() {
                return CURL_WRITEFUNC_ERROR;
            }
            let _ = file.seek(SeekFrom::Start(0));
            let _ = bw.write_all(value);
            let _ = bw.write_all(b"\n");
            let _ = bw.flush();
        }
        // Truncation is impossible on a non-regular sink; mirror ftruncate failing.
        _ => return CURL_WRITEFUNC_ERROR,
    }
    0
}

/// Join a derived filename with `--output-dir` when set, mirroring C's
/// `curl_maprintf("%s/%s", output_dir, filename)`.
#[allow(dead_code)]
fn join_output_dir(config: &OperationConfig, filename: String) -> String {
    match config.output_dir.as_deref() {
        Some(dir) => format!("{dir}/{filename}"),
        None => filename,
    }
}

/// Build the OSC 8 hyperlink byte sequence for a `Location:` value, or `None`
/// when the plain value should be written instead.
///
/// Pure port of the linkifying logic in C's `write_linked_location`
/// (`tool_cb_hdr.c:63-144`). Returns `None` (→ plain output) when: the
/// `VTE_VERSION` gate rejects (unparsable, or `<= 4801` — VTE ≤ 0.48.1 had
/// formatting bugs), there is no effective base URL, URL parsing/resolution
/// fails, or the resolved scheme is not one of `http`/`https`/`ftp`/`ftps`.
///
/// On success the returned bytes are, matching curl's
/// `"%.*s" LINK "%s" LINKST "%.*s" LINKOFF`:
/// the skipped leading whitespace of the original location, `LINK`, the resolved
/// absolute URL, `LINKST`, the location bytes after the leading whitespace (which
/// deliberately still include any trailing CR/LF, as in curl), then `LINKOFF`.
#[allow(dead_code)]
fn build_linked_location(
    effective_url: Option<&str>,
    location: &[u8],
    loclen: usize,
) -> Option<Vec<u8>> {
    // VTE_VERSION gate: unset -> linkify; set but unparsable or <= 4801 -> plain.
    if let Some(v) = std::env::var_os("VTE_VERSION") {
        let num = parse_leading_number(v.as_encoded_bytes())?;
        if num <= 4801 {
            return None;
        }
    }

    let loclen = loclen.min(location.len());
    let loc_full = &location[..loclen];

    // Strip leading whitespace of the redirect URL.
    let mut lo = 0usize;
    while lo < loc_full.len() && (loc_full[lo] == b' ' || loc_full[lo] == b'\t') {
        lo += 1;
    }
    let space_skipped = lo;
    // Strip the trailing end-of-line characters, normally "\r\n".
    let mut hi = loc_full.len();
    while hi > lo && (loc_full[hi - 1] == b'\n' || loc_full[hi - 1] == b'\r') {
        hi -= 1;
    }
    let stripped = &loc_full[lo..hi];

    // CURLU makes the relative-URL case easy; the effective URL is the base.
    let base = effective_url?;
    let copyloc = String::from_utf8_lossy(stripped);

    let mut u = Url::new();
    // The original URL to use as a base for a relative redirect URL.
    u.set(CurlUPart::Url, Some(base), 0).ok()?;
    // Redirected location; may be absolute or relative (resolved against the base).
    u.set(CurlUPart::Url, Some(copyloc.as_ref()), 0).ok()?;
    let finalurl = u.get(CurlUPart::Url, NO_DEFAULT_PORT).ok()?;
    let scheme = u.get(CurlUPart::Scheme, 0).ok()?;

    if !matches!(scheme.as_str(), "http" | "https" | "ftp" | "ftps") {
        // Not a "safe" URL: do not linkify it.
        return None;
    }

    let mut out =
        Vec::with_capacity(loclen + LINK.len() + finalurl.len() + LINKST.len() + LINKOFF.len());
    out.extend_from_slice(&location[..space_skipped]);
    out.extend_from_slice(LINK.as_bytes());
    out.extend_from_slice(finalurl.as_bytes());
    out.extend_from_slice(LINKST.as_bytes());
    out.extend_from_slice(&location[space_skipped..loclen]);
    out.extend_from_slice(LINKOFF.as_bytes());
    Some(out)
}

/// Emit a `Location:` value, hyperlinked (OSC 8) when possible.
///
/// Port of C's `write_linked_location` (`tool_cb_hdr.c:63-144`). Delegates the
/// (pure) link construction to [`build_linked_location`]; on any failure or
/// unsafe scheme it falls back to writing the plain `location[..loclen]` bytes
/// (C's `locout` label). `effective_url` is the transfer's effective URL — the
/// base for resolving a relative redirect — supplied by the caller instead of a
/// raw `CURL*` to keep this function free of FFI `unsafe`.
#[allow(dead_code)]
fn write_linked_location(
    effective_url: Option<&str>,
    location: &[u8],
    loclen: usize,
    stream: &mut OutSink,
) {
    let loclen = loclen.min(location.len());
    match build_linked_location(effective_url, location, loclen) {
        Some(rendered) => {
            let _ = stream.write_all(&rendered);
        }
        None => {
            // Normal output in case of error or unsafe scheme.
            let _ = stream.write_all(&location[..loclen]);
        }
    }
}

/// Derive the `-O`/`-J` output filename from a `Content-Disposition` (or, as a
/// fallback, `Location`) header, creating the output file once resolved.
///
/// Port of C's `content_disposition` (`tool_cb_hdr.c:294-419`). `str_bytes` is
/// the full header line (`cb` bytes); `response` is the HTTP status. Returns `0`
/// normally, `cb` when a header was buffered for later writing, or
/// `CURL_WRITEFUNC_ERROR` on failure — matching curl exactly.
#[allow(dead_code)]
fn content_disposition(str_bytes: &[u8], cb: usize, per: &mut PerTransfer, response: i64) -> usize {
    let diag = per.diag;
    // SAFETY: `per.hdrcbdata.config` is the OperationConfig installed alongside the
    // header callback (curl's `per->config`, the same pointer as `hdrcbdata->config`);
    // the caller (`tool_header_cb`) has already rejected a null pointer. It points to a
    // live config distinct from `per`, is only read here, and so never aliases the
    // `per` mutations below.
    let config: &OperationConfig = unsafe { &*per.hdrcbdata.config };

    if cb > 9 && checkprefix(str_bytes, b"Location:") && response / 100 == 3 {
        // Get the name off the Location header as a temporary measure in case there is
        // no Content-Disposition.
        let mut p = 9usize;
        while p < cb && is_blank(str_bytes[p]) {
            p += 1;
        }
        if p < cb {
            // as a precaution
            if let Some(filename) = parse_filename(&str_bytes[p..], cb - p, 0) {
                if per.outs.stream.is_open() {
                    // indication of problem, get out!
                    return CURL_WRITEFUNC_ERROR;
                }
                per.outs.filename = Some(join_output_dir(config, filename));
                per.outs.alloc_filename = true;
                // set to avoid clobbering existing files by default
                per.outs.is_cd_filename = true;
            }
        }
    } else if cb > 20 && checkprefix(str_bytes, b"Content-disposition:") {
        // Look for the 'filename=' parameter (encoded filenames (*=) are not supported).
        let mut p = 20usize;
        loop {
            while p < cb && str_bytes[p] != 0 && !str_bytes[p].is_ascii_alphabetic() {
                p += 1;
            }
            if p > cb - 9 {
                break;
            }
            if !str_bytes[p..].starts_with(b"filename=") {
                // No match, find the next parameter.
                while p < cb && str_bytes[p] != 0 && str_bytes[p] != b';' {
                    p += 1;
                }
                if p < cb && str_bytes[p] != 0 {
                    continue;
                }
                break;
            }
            p += 9;
            while p < cb && is_blank(str_bytes[p]) {
                p += 1;
            }
            let len = cb - p;
            if let Some(filename) = parse_filename(&str_bytes[p..], len, b';') {
                if per.outs.stream.is_open() {
                    // indication of problem, get out!
                    return CURL_WRITEFUNC_ERROR;
                }
                per.outs.filename = Some(join_output_dir(config, filename));
                per.outs.is_cd_filename = true;
                per.outs.regular_file = true;
                per.outs.fopened = false;
                per.outs.alloc_filename = true;
                per.hdrcbdata.honor_cd_filename = false; // done now!
                if !tool_create_output_file(diag, &mut per.outs, config) {
                    return CURL_WRITEFUNC_ERROR;
                }
                if tool_write_headers(&mut per.hdrcbdata, &mut per.outs.stream).is_err() {
                    return CURL_WRITEFUNC_ERROR;
                }
            }
            break;
        }
        if !per.outs.stream.is_open() && !tool_create_output_file(diag, &mut per.outs, config) {
            return CURL_WRITEFUNC_ERROR;
        }
        if tool_write_headers(&mut per.hdrcbdata, &mut per.outs.stream).is_err() {
            return CURL_WRITEFUNC_ERROR;
        }
    } // content-disposition handling

    if per.hdrcbdata.honor_cd_filename && config.show_headers {
        // Still awaiting the Content-Disposition header; store this header in memory.
        // (The header is not null-terminated in C; here we take the `cb` bytes as-is.)
        per.hdrcbdata
            .headlist
            .push(String::from_utf8_lossy(&str_bytes[..cb]).into_owned());
        return cb; // done for now
    }

    0 // ok
}

/// Callback for `CURLOPT_HEADERFUNCTION`. `size` is always 1.
///
/// Port of C's `tool_header_cb` (`tool_cb_hdr.c:426-543`). Handles, in order:
/// `--dump-header` (`-D`) side-file writing; ETag capture and
/// `Content-Disposition`/`Location` filename derivation (HTTP 2xx/3xx only);
/// `--write-out` header counting; and bold / OSC 8 header display on styled
/// TTYs. Returns `cb` (= `size * nmemb`) on success, or `CURL_WRITEFUNC_ERROR`
/// (or a short count) on failure — the exact values libcurl expects.
///
/// # Safety
/// `ptr` must point to `size * nmemb` initialised bytes for the duration of the
/// call, and `userdata` must be the `*mut PerTransfer` registered via
/// `CURLOPT_HEADERDATA`, valid and exclusively borrowable (the CLI drives the
/// transfer engine single-threaded).
#[allow(dead_code)]
pub unsafe extern "C" fn tool_header_cb(
    ptr: *mut c_char,
    size: usize,
    nmemb: usize,
    userdata: *mut c_void,
) -> usize {
    // SAFETY: per the CURLOPT_HEADERDATA contract, `userdata` is the live,
    // exclusively-borrowed `*mut PerTransfer` for this transfer.
    let per = match unsafe { userdata_mut::<PerTransfer>(userdata) } {
        Some(p) => p,
        None => return CURL_WRITEFUNC_ERROR,
    };

    let cb = size * nmemb;
    // SAFETY: the header-callback contract guarantees `ptr` addresses `cb` readable bytes.
    let str_bytes: &[u8] = unsafe { core::slice::from_raw_parts(ptr as *const u8, cb) };

    // C: `if(!per->config) return CURL_WRITEFUNC_ERROR;` — a null config pointer means
    // the callback context was never established, so there is nothing to write against.
    if per.hdrcbdata.config.is_null() {
        return CURL_WRITEFUNC_ERROR;
    }
    // SAFETY: non-null (checked above); points to the live OperationConfig driving this
    // transfer, distinct from `per`; read-only here so it never aliases a `per` mutation.
    let config: &OperationConfig = unsafe { &*per.hdrcbdata.config };
    let diag = per.diag;

    // Write header data when curl option --dump-header (-D) is given.
    if config.headerfile.is_some() && per.heads.stream.is_open() {
        match per.heads.stream.write_all(str_bytes) {
            Ok(_) => {}
            // A short/failed write aborts the transfer (C returns the short fwrite count).
            Err(_) => return 0,
        }
        // Flush the stream to send off what we got earlier.
        if per.heads.stream.flush().is_err() {
            let file = config.headerfile.as_deref().unwrap_or_default();
            errorf(diag, &format!("Failed writing headers to {file}"));
            return CURL_WRITEFUNC_ERROR;
        }
    }

    // Connection scheme (CURLINFO_SCHEME, normalised); the library records it lowercase,
    // matching curl's interned protocol tokens.
    let (scheme_is_http, scheme_is_display) = {
        let s = per.easy.info.conn_scheme.as_deref();
        (
            matches!(s, Some("http") | Some("https")),
            matches!(
                s,
                Some("http") | Some("https") | Some("rtsp") | Some("file")
            ),
        )
    };

    if scheme_is_http {
        let response = i64::from(per.easy.info.httpcode);
        // Only care about etag and content-disposition headers in 2xx and 3xx responses.
        if response / 100 == 2 || response / 100 == 3 {
            if config.etag_save_file.is_some()
                && per.etag_save.stream.is_open()
                && checkprefix(str_bytes, b"etag:")
            {
                // Match only a header that starts with "etag" (case insensitive).
                let rc = save_etag(&str_bytes[5..], &mut per.etag_save);
                if rc != 0 {
                    return rc;
                }
            } else if per.hdrcbdata.honor_cd_filename {
                // content_disposition() may return an rc when it buffered a header for later.
                let rc = content_disposition(str_bytes, cb, per, response);
                if rc != 0 {
                    return rc;
                }
            }
        }
    }

    // --write-out header counting (%{num_headers}).
    if config.writeout.is_some() {
        if str_bytes.contains(&b':') {
            if per.was_last_header_empty {
                per.num_headers = 0;
            }
            per.was_last_header_empty = false;
            per.num_headers += 1;
        } else if !str_bytes.is_empty() && (str_bytes[0] == b'\r' || str_bytes[0] == b'\n') {
            per.was_last_header_empty = true;
        }
    }

    // Bold headers (and OSC 8 hyperlinked Location:) for selected protocols only.
    if config.show_headers && !per.outs.out_null && scheme_is_display {
        if !per.outs.stream.is_open() && !tool_create_output_file(diag, &mut per.outs, config) {
            return CURL_WRITEFUNC_ERROR;
        }
        let styled = per.isatty && per.styled_output;
        let colon = if styled {
            str_bytes.iter().position(|&b| b == b':')
        } else {
            None
        };
        if let Some(namelen) = colon {
            // BOLD "%.*s" BOLDOFF ":"
            let _ = per.outs.stream.write_all(BOLD.as_bytes());
            let _ = per.outs.stream.write_all(&str_bytes[..namelen]);
            let _ = per.outs.stream.write_all(BOLDOFF.as_bytes());
            let _ = per.outs.stream.write_all(b":");
            if is_location_name(&str_bytes[..namelen]) {
                // Resolve a (possibly relative) Location against the effective URL and emit
                // it as an OSC 8 hyperlink; fall back to plain text on any failure.
                let effective = per
                    .easy
                    .state
                    .uh
                    .as_ref()
                    .and_then(|u| u.get(CurlUPart::Url, 0).ok());
                write_linked_location(
                    effective.as_deref(),
                    &str_bytes[namelen + 1..cb],
                    cb - namelen - 1,
                    &mut per.outs.stream,
                );
            } else {
                let _ = per.outs.stream.write_all(&str_bytes[namelen + 1..cb]);
            }
        } else {
            // Not "handled", just show it.
            let _ = per.outs.stream.write_all(&str_bytes[..cb]);
        }
    }

    cb
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::BufWriter;
    use std::path::PathBuf;

    /// Build a unique temp path (per process + suffix) for a filesystem test.
    fn tmp_path(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blitzy_adhoc_test_hdr_{}_{}.tmp",
            std::process::id(),
            suffix
        ))
    }

    /// Wrap an existing writable file as an `OutStruct` whose sink is that file.
    fn outstruct_for(path: &std::path::Path) -> OutStruct {
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("open temp file");
        OutStruct {
            stream: OutSink::File(BufWriter::new(f)),
            ..OutStruct::default()
        }
    }

    #[test]
    fn escape_constants_match_curl() {
        assert_eq!(BOLD, "\x1b[1m");
        assert_eq!(BOLDOFF, "\x1b[0m");
        assert_eq!(LINK, "\x1b]8;;");
        assert_eq!(LINKST, "\x1b\\");
        // LINKOFF is exactly LINK followed by LINKST.
        assert_eq!(LINKOFF, format!("{LINK}{LINKST}"));
    }

    #[test]
    fn checkprefix_is_case_insensitive_and_length_safe() {
        assert!(checkprefix(b"Location: x", b"Location:"));
        assert!(checkprefix(b"lOcAtIoN: x", b"Location:"));
        assert!(checkprefix(b"etag: \"v\"\n", b"etag:"));
        assert!(checkprefix(b"ETAG: \"v\"\n", b"etag:"));
        assert!(!checkprefix(b"X-Location: x", b"Location:"));
        // Shorter than the prefix → false (no out-of-bounds read).
        assert!(!checkprefix(b"eta", b"etag:"));
    }

    #[test]
    fn blank_and_space_classes() {
        assert!(is_blank(b' ') && is_blank(b'\t'));
        assert!(!is_blank(b'\n') && !is_blank(b'x'));
        for b in [b' ', b'\t', b'\n', b'\r', 0x0b, 0x0c] {
            assert!(is_space(b), "byte {b:#x} should be ISSPACE");
        }
        assert!(!is_space(b'x'));
    }

    #[test]
    fn location_name_matching() {
        assert!(is_location_name(b"Location"));
        assert!(is_location_name(b"location"));
        assert!(is_location_name(b"LOCATION"));
        assert!(!is_location_name(b"Content-Type"));
        assert!(!is_location_name(b"Locationx"));
        // strncasecmp semantics: a shorter prefix of "Location" still matches.
        assert!(is_location_name(b"Loc"));
    }

    #[test]
    fn leading_number_parsing() {
        assert_eq!(parse_leading_number(b"6003"), Some(6003));
        assert_eq!(parse_leading_number(b"4801trailing"), Some(4801));
        assert_eq!(parse_leading_number(b"0"), Some(0));
        assert_eq!(parse_leading_number(b""), None);
        assert_eq!(parse_leading_number(b"abc"), None);
    }

    #[test]
    fn parse_filename_content_disposition_quoted() {
        // Quoted value: honour the quote as the terminator, strip the quotes.
        assert_eq!(
            parse_filename(b"\"file name.txt\"", 15, b';').as_deref(),
            Some("file name.txt")
        );
    }

    #[test]
    fn parse_filename_content_disposition_unquoted_stop() {
        let s = b"file.txt;charset=utf-8";
        assert_eq!(
            parse_filename(s, s.len(), b';').as_deref(),
            Some("file.txt")
        );
    }

    #[test]
    fn parse_filename_location_trims_query_and_fragment_and_path() {
        let s = b"/path/to/page.html?q=1#frag";
        assert_eq!(parse_filename(s, s.len(), 0).as_deref(), Some("page.html"));
    }

    #[test]
    fn parse_filename_trailing_separator_is_none() {
        let s = b"/path/to/";
        assert_eq!(parse_filename(s, s.len(), 0), None);
    }

    #[test]
    fn parse_filename_backslash_basename_and_crlf_trim() {
        let s = b"a\\b\\c.txt\r\n";
        assert_eq!(parse_filename(s, s.len(), b';').as_deref(), Some("c.txt"));
    }

    #[test]
    fn save_etag_truncates_then_writes_trimmed_value() {
        let path = tmp_path("etag");
        // Pre-populate with stale (longer) content to prove truncation happens.
        fs::write(&path, b"OLD-STALE-ETAG-VALUE-THAT-IS-LONG\n").unwrap();
        {
            let mut outs = outstruct_for(&path);
            // Header tail after "etag:" — leading blanks + trailing CR/LF are trimmed,
            // the surrounding quotes are preserved (curl only trims whitespace).
            let rc = save_etag(b"  \"abc123\"\r\n", &mut outs);
            assert_eq!(rc, 0);
        } // drop closes/flushes the file
        let got = fs::read(&path).unwrap();
        assert_eq!(got, b"\"abc123\"\n");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn save_etag_ignores_line_without_newline() {
        let path = tmp_path("etag_nonl");
        fs::write(&path, b"KEEP-ME\n").unwrap();
        {
            let mut outs = outstruct_for(&path);
            // No trailing '\n' → C does nothing and returns 0.
            let rc = save_etag(b"\"abc\"", &mut outs);
            assert_eq!(rc, 0);
        }
        let got = fs::read(&path).unwrap();
        assert_eq!(got, b"KEEP-ME\n", "file must be untouched");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn save_etag_non_file_sink_reports_error() {
        // A non-regular sink cannot be truncated (mirrors ftruncate failing).
        let mut outs = OutStruct {
            stream: OutSink::Stdout,
            ..OutStruct::default()
        };
        assert_eq!(save_etag(b"\"v\"\n", &mut outs), CURL_WRITEFUNC_ERROR);
    }

    #[test]
    fn tool_write_headers_flushes_all_and_clears_list() {
        let path = tmp_path("hdrs");
        fs::write(&path, b"").unwrap();
        {
            let mut outs = outstruct_for(&path);
            let mut hdr = HdrCbData::default();
            hdr.headlist.push("Header-One: a\r\n".to_string());
            hdr.headlist.push("Header-Two: b\r\n".to_string());
            let res = tool_write_headers(&mut hdr, &mut outs.stream);
            assert!(res.is_ok());
            // The buffer is always drained afterwards.
            assert!(hdr.headlist.is_empty());
        }
        let got = fs::read(&path).unwrap();
        assert_eq!(got, b"Header-One: a\r\nHeader-Two: b\r\n");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn tool_write_headers_empty_list_is_ok() {
        let path = tmp_path("hdrs_empty");
        fs::write(&path, b"").unwrap();
        {
            let mut outs = outstruct_for(&path);
            let mut hdr = HdrCbData::default();
            assert!(tool_write_headers(&mut hdr, &mut outs.stream).is_ok());
            assert!(hdr.headlist.is_empty());
        }
        assert_eq!(fs::read(&path).unwrap(), b"");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn build_linked_location_none_without_effective_url() {
        // With no base URL the link cannot be built regardless of the VTE gate.
        assert_eq!(build_linked_location(None, b"http://x/y", 10), None);
    }

    #[test]
    fn linkification_happy_path_and_unsafe_scheme() {
        // This is the only test that touches VTE_VERSION; save & restore it.
        let saved = std::env::var_os("VTE_VERSION");
        std::env::set_var("VTE_VERSION", "9999"); // > 4801 → linkification enabled

        // Relative redirect resolved against the effective URL, wrapped as OSC 8.
        let base = "http://example.com/path/page";
        let loc = b"  /other\r\n"; // 2 leading spaces, trailing CRLF
        let built =
            build_linked_location(Some(base), loc, loc.len()).expect("http scheme should linkify");
        let mut prefix = Vec::new();
        prefix.extend_from_slice(b"  ");
        prefix.extend_from_slice(LINK.as_bytes());
        assert!(
            built.starts_with(&prefix),
            "must start with skipped ws + LINK"
        );
        assert!(built.ends_with(LINKOFF.as_bytes()), "must end with LINKOFF");
        assert!(
            built.windows(LINKST.len()).any(|w| w == LINKST.as_bytes()),
            "must contain the OSC 8 string terminator"
        );
        // The resolved absolute URL and the original (untrimmed-tail) location appear.
        assert!(contains_sub(&built, b"http://example.com/other"));
        assert!(contains_sub(&built, b"/other\r\n"));

        // A resolved "unsafe" scheme (e.g. file:) must NOT be linkified.
        let unsafe_built = build_linked_location(Some(base), b"file:///etc/hostname", 20);
        assert_eq!(unsafe_built, None);

        // Restore the environment.
        match saved {
            Some(v) => std::env::set_var("VTE_VERSION", v),
            None => std::env::remove_var("VTE_VERSION"),
        }
    }

    /// Substring search over byte slices for the linkification assertions.
    fn contains_sub(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
