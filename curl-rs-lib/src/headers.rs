//! HTTP header handling: the public header API and the internal dynamic
//! header set.
//!
//! This module is the Rust home for two distinct-but-related pieces of curl's
//! header machinery, ported from the behavioural/ABI oracle in `lib/headers.c`
//! and `lib/dynhds.c` (read as a reference, **not** transliterated line by
//! line):
//!
//! * [`DynHds`] — an ordered, growable set of name/value header entries with
//!   case-insensitive name lookup and configurable count/byte caps. This is the
//!   internal container the HTTP and proxy layers use to accumulate request and
//!   response headers (`struct dynhds` in `lib/dynhds.c`). It provides HTTP/1
//!   line parsing and `Name: Value\r\n` serialization helpers.
//!
//! * [`Header`] and [`HeaderCollector`] — the public header API. [`Header`]
//!   mirrors the C `struct curl_header`; [`HeaderCollector`] is the per-handle
//!   store of collected response headers populated during a transfer and read
//!   afterwards by [`HeaderCollector::header`] / [`HeaderCollector::nextheader`]
//!   (the engine-side equivalents of `curl_easy_header()` /
//!   `curl_easy_nextheader()` in `lib/headers.c`). The FFI crate
//!   (`curl-rs-ffi/src/header.rs`) builds the `#[repr(C)] struct curl_header`
//!   it returns to C from this store.
//!
//! # Origin classification
//!
//! Every collected header carries an *origin* bitmask identifying where it came
//! from — a plain server header ([`CURLH_HEADER`]), a trailer
//! ([`CURLH_TRAILER`]), a `CONNECT`-response header ([`CURLH_CONNECT`]), a `1xx`
//! informational header ([`CURLH_1XX`]) or an HTTP/2+ pseudo-header
//! ([`CURLH_PSEUDO`]). The classification reproduced here matches
//! `hds_cw_collect_write()` in `lib/headers.c` exactly so the `tests/data`
//! header-API tests observe identical origins.
//!
//! # Result codes
//!
//! The header-lookup result code [`CurlHError`] (curl's `CURLHcode`) is
//! centralized in [`crate::error`] alongside the other libcurl result-code
//! enums and re-exported here for convenience.
//!
//! # Memory safety
//!
//! This module is pure safe Rust: it contains **zero** `unsafe` and compiles
//! under the crate-wide `#![forbid(unsafe_code)]`. Header strings are owned
//! [`String`]s held by the collector and remain valid until the next lookup or
//! a reset, matching the C contract that a returned `struct curl_header` is
//! valid only until the next call.

#![forbid(unsafe_code)]

use crate::error::{CurlError, Result};

// Re-export the header-API result code so callers can refer to it as
// `crate::headers::CurlHError` as well as `crate::error::CurlHError`.
pub use crate::error::CurlHError;

// ===========================================================================
// Origin classification bits (`include/curl/header.h`)
// ===========================================================================

/// Plain server response header (`CURLH_HEADER`, `1 << 0`).
pub const CURLH_HEADER: u32 = 1 << 0;
/// Trailer header, sent after a chunked body (`CURLH_TRAILER`, `1 << 1`).
pub const CURLH_TRAILER: u32 = 1 << 1;
/// Header from a proxy `CONNECT` response (`CURLH_CONNECT`, `1 << 2`).
pub const CURLH_CONNECT: u32 = 1 << 2;
/// Header from a `1xx` informational response (`CURLH_1XX`, `1 << 3`).
pub const CURLH_1XX: u32 = 1 << 3;
/// HTTP/2+ pseudo-header such as `:status` (`CURLH_PSEUDO`, `1 << 4`).
pub const CURLH_PSEUDO: u32 = 1 << 4;

/// The union of every valid origin bit.
///
/// `curl_easy_header()` rejects any `origin` argument with bits outside this
/// mask (or equal to zero) with [`CurlHError::BadArgument`].
pub const CURLH_ORIGIN_MASK: u32 =
    CURLH_HEADER | CURLH_TRAILER | CURLH_CONNECT | CURLH_1XX | CURLH_PSEUDO;

/// A reserved bit OR'd into the `origin` of every returned [`Header`].
///
/// `copy_header_external()` in `lib/headers.c` deliberately sets a high
/// reserved bit (`1 << 27`) in the `origin` field it hands back, specifically so
/// that applications cannot do exact `==` comparisons against a single
/// `CURLH_*` flag (which would tempt them to depend on the reserved bits staying
/// clear). [`HeaderCollector`] reproduces this so the returned origin is
/// byte-for-byte identical to curl's.
pub const CURLH_RESERVED_BIT: u32 = 1 << 27;

/// Maximum number of response headers collected for a single transfer.
///
/// Mirrors `MAX_HTTP_RESP_HEADER_COUNT` (`lib/http.h`). Pushing beyond this cap
/// fails with [`CurlError::TooLarge`], exactly as curl's
/// `Curl_headers_push()` does.
pub const MAX_HTTP_RESP_HEADER_COUNT: usize = 5000;

// ===========================================================================
// DynHds option flags and common size caps (`lib/dynhds.h`, `lib/curlx/dynbuf.h`)
// ===========================================================================

/// No [`DynHds`] options set (`DYNHDS_OPT_NONE`).
pub const DYNHDS_OPT_NONE: i32 = 0;
/// Lowercase every header name as it is added (`DYNHDS_OPT_LOWERCASE`).
///
/// Used by the HTTP/2 and HTTP/3 layers, where header names are required to be
/// lowercase on the wire.
pub const DYNHDS_OPT_LOWERCASE: i32 = 1 << 0;

/// Default total-bytes cap used for request/response header sets
/// (`DYN_HTTP_REQUEST` = 1 MiB in `lib/curlx/dynbuf.h`).
pub const DYN_HTTP_REQUEST: usize = 1024 * 1024;
/// Total-bytes cap used for proxy `CONNECT` header sets
/// (`DYN_PROXY_CONNECT_HEADERS` = 16 KiB in `lib/curlx/dynbuf.h`).
pub const DYN_PROXY_CONNECT_HEADERS: usize = 16 * 1024;

// ===========================================================================
// Small helpers
// ===========================================================================

/// Returns `true` for an HTTP "blank" byte: space or horizontal tab.
///
/// Equivalent to curl's `ISBLANK()` (it intentionally does **not** treat CR/LF
/// or other whitespace as blank).
#[inline]
const fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// Case-insensitive (ASCII) name comparison, matching curl's `curl_strequal` /
/// `curl_strnequal`.
///
/// curl folds case using ASCII rules only; [`str::eq_ignore_ascii_case`]
/// reproduces that exactly (and, by comparing length first, is equivalent to the
/// `namelen == … && curl_strnequal(…)` pattern in `lib/dynhds.c`).
#[inline]
fn name_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Converts raw header bytes into an owned [`String`].
///
/// curl stores header names and values as raw bytes (`char *`). All headers in
/// the parity test corpus are ASCII/UTF-8; any stray non-UTF-8 byte is replaced
/// using [`String::from_utf8_lossy`] rather than rejected, so collection never
/// fails on otherwise-valid transfers.
#[inline]
fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ===========================================================================
// DynHds — the internal dynamic header set (`lib/dynhds.c`)
// ===========================================================================

/// A single name/value entry in a [`DynHds`] (curl's `struct dynhds_entry`).
///
/// Both `name` and `value` are owned and always valid UTF-8. Lengths are
/// exposed as [`namelen`](DynHdsEntry::namelen) / [`valuelen`](DynHdsEntry::valuelen)
/// to mirror the C struct's `namelen` / `valuelen` fields (which the HTTP/2 and
/// HTTP/3 layers read directly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynHdsEntry {
    name: String,
    value: String,
}

impl DynHdsEntry {
    /// The header name (case is preserved unless [`DYNHDS_OPT_LOWERCASE`] was
    /// set when it was added).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The header value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The header name as raw bytes.
    #[must_use]
    pub fn name_bytes(&self) -> &[u8] {
        self.name.as_bytes()
    }

    /// The header value as raw bytes.
    #[must_use]
    pub fn value_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }

    /// Length in bytes of the name (curl's `namelen`).
    #[must_use]
    pub fn namelen(&self) -> usize {
        self.name.len()
    }

    /// Length in bytes of the value (curl's `valuelen`).
    #[must_use]
    pub fn valuelen(&self) -> usize {
        self.value.len()
    }
}

/// An ordered, growable set of header entries with case-insensitive name
/// lookup (curl's `struct dynhds`).
///
/// Entries are kept in insertion order. Two caps bound the structure, exactly
/// as in `lib/dynhds.c`:
///
/// * `max_entries` — the maximum number of entries; `0` means unlimited.
/// * `max_strs_size` — the maximum total length, in bytes, of all names plus
///   values combined.
///
/// Exceeding either cap on [`add`](DynHds::add) fails with
/// [`CurlError::OutOfMemory`], reproducing curl's behaviour (curl signals the
/// overflow with `CURLE_OUT_OF_MEMORY`).
///
/// This is the container the HTTP/proxy layers (`crate::protocols::http`,
/// `crate::conn`) use to assemble request headers, response trailers and proxy
/// `CONNECT` headers.
#[derive(Debug, Clone)]
pub struct DynHds {
    entries: Vec<DynHdsEntry>,
    /// Maximum number of entries; `0` means unlimited.
    max_entries: usize,
    /// Running total of `namelen + valuelen` across all entries.
    strs_len: usize,
    /// Cap on `strs_len`.
    max_strs_size: usize,
    /// Bitmask of `DYNHDS_OPT_*` options.
    opts: i32,
}

impl DynHds {
    /// Creates a new, empty set with the given caps (curl's `Curl_dynhds_init`).
    ///
    /// `max_entries == 0` means an unlimited number of entries; `max_strs_size`
    /// caps the total bytes of all names and values.
    #[must_use]
    pub fn new(max_entries: usize, max_strs_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
            strs_len: 0,
            max_strs_size,
            opts: DYNHDS_OPT_NONE,
        }
    }

    /// Creates a set with the default request/response caps
    /// (`0` entries unlimited, [`DYN_HTTP_REQUEST`] total bytes).
    #[must_use]
    pub fn with_request_limits() -> Self {
        Self::new(0, DYN_HTTP_REQUEST)
    }

    /// Creates a set with the proxy `CONNECT` caps
    /// (`0` entries unlimited, [`DYN_PROXY_CONNECT_HEADERS`] total bytes).
    #[must_use]
    pub fn with_proxy_connect_limits() -> Self {
        Self::new(0, DYN_PROXY_CONNECT_HEADERS)
    }

    /// Removes all entries, keeping the configured caps and options
    /// (curl's `Curl_dynhds_reset`).
    pub fn reset(&mut self) {
        self.entries.clear();
        self.strs_len = 0;
    }

    /// The number of entries (curl's `Curl_dynhds_count`).
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The running total bytes of all names plus values (curl's `strs_len`).
    #[must_use]
    pub fn total_strs_len(&self) -> usize {
        self.strs_len
    }

    /// The configured entry cap (`0` means unlimited).
    #[must_use]
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// The configured total-bytes cap.
    #[must_use]
    pub fn max_strs_size(&self) -> usize {
        self.max_strs_size
    }

    /// Replaces the active option bitmask (curl's `Curl_dynhds_set_opts`).
    ///
    /// Existing entries are unaffected; the options apply only to subsequent
    /// additions.
    pub fn set_opts(&mut self, opts: i32) {
        self.opts = opts;
    }

    /// The active option bitmask.
    #[must_use]
    pub fn opts(&self) -> i32 {
        self.opts
    }

    /// Returns the `n`-th entry, or `None` if out of range
    /// (curl's `Curl_dynhds_getn`).
    #[must_use]
    pub fn getn(&self, n: usize) -> Option<&DynHdsEntry> {
        self.entries.get(n)
    }

    /// Returns the first entry whose name matches `name` case-insensitively, or
    /// `None` (curl's `Curl_dynhds_get` / `Curl_dynhds_cget`).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&DynHdsEntry> {
        self.entries.iter().find(|e| name_eq(&e.name, name))
    }

    /// Returns `true` if at least one entry has the given name
    /// (case-insensitive; curl's `Curl_dynhds_contains`).
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Returns how many entries have the given name (case-insensitive; curl's
    /// `Curl_dynhds_count_name`).
    #[must_use]
    pub fn count_name(&self, name: &str) -> usize {
        self.entries
            .iter()
            .filter(|e| name_eq(&e.name, name))
            .count()
    }

    /// All entries, in insertion order.
    #[must_use]
    pub fn entries(&self) -> &[DynHdsEntry] {
        &self.entries
    }

    /// Iterates over the entries in insertion order.
    pub fn iter(&self) -> core::slice::Iter<'_, DynHdsEntry> {
        self.entries.iter()
    }

    /// Appends a header, **without** checking for duplicate names
    /// (curl's `Curl_dynhds_add` / `Curl_dynhds_cadd`).
    ///
    /// Returns [`CurlError::OutOfMemory`] if the entry cap or the total-bytes
    /// cap would be exceeded — matching curl, which reports both overflow
    /// conditions as `CURLE_OUT_OF_MEMORY`. If [`DYNHDS_OPT_LOWERCASE`] is set,
    /// the stored name is lowercased.
    pub fn add(&mut self, name: &str, value: &str) -> Result<()> {
        // Entry-count cap: `if(max_entries && hds_len >= max_entries)`.
        if self.max_entries != 0 && self.entries.len() >= self.max_entries {
            return Err(CurlError::OutOfMemory);
        }
        // Total-bytes cap: `if(strs_len + namelen + valuelen > max_strs_size)`.
        let addlen = name.len() + value.len();
        if self.strs_len + addlen > self.max_strs_size {
            return Err(CurlError::OutOfMemory);
        }

        let stored_name = if self.opts & DYNHDS_OPT_LOWERCASE != 0 {
            name.to_ascii_lowercase()
        } else {
            name.to_string()
        };
        self.entries.push(DynHdsEntry {
            name: stored_name,
            value: value.to_string(),
        });
        self.strs_len += addlen;
        Ok(())
    }

    /// Sets a header, replacing any existing entries with the same name and
    /// appending the new entry at the end (curl's `Curl_dynhds_set` /
    /// `Curl_dynhds_cset`).
    pub fn set(&mut self, name: &str, value: &str) -> Result<()> {
        self.remove(name);
        self.add(name, value)
    }

    /// Removes every entry whose name matches `name` case-insensitively,
    /// returning the number removed (curl's `Curl_dynhds_remove` /
    /// `Curl_dynhds_cremove`).
    pub fn remove(&mut self, name: &str) -> usize {
        let mut removed = 0;
        let mut i = 0;
        while i < self.entries.len() {
            if name_eq(&self.entries[i].name, name) {
                let e = self.entries.remove(i);
                self.strs_len -= e.name.len() + e.value.len();
                removed += 1;
            } else {
                i += 1;
            }
        }
        removed
    }

    /// Parses and appends a single HTTP/1 header line (curl's
    /// `Curl_dynhds_h1_cadd_line`).
    ///
    /// See [`add_h1_line_bytes`](DynHds::add_h1_line_bytes) for the parsing
    /// rules.
    pub fn add_h1_line(&mut self, line: &str) -> Result<()> {
        self.add_h1_line_bytes(line.as_bytes())
    }

    /// Parses and appends a single HTTP/1 header line from raw bytes (curl's
    /// `Curl_dynhds_h1_add_line`).
    ///
    /// The line may carry a trailing `CRLF` or `LF`; anything from the first
    /// CR/LF onward is ignored. The name is everything up to the first `:`; the
    /// value is what follows, with leading blanks skipped. An empty line is a
    /// no-op (`Ok`). A line with no `:` is rejected with
    /// [`CurlError::BadFunctionArgument`].
    pub fn add_h1_line_bytes(&mut self, line: &[u8]) -> Result<()> {
        if line.is_empty() {
            return Ok(());
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Err(CurlError::BadFunctionArgument);
        };
        let name = &line[..colon];

        // Value starts after the colon, past any leading blanks.
        let mut vstart = colon + 1;
        while vstart < line.len() && is_blank(line[vstart]) {
            vstart += 1;
        }
        let rest = &line[vstart..];
        // Value ends at the first CR or LF, if any.
        let vend = rest
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .unwrap_or(rest.len());
        let value = &rest[..vend];

        self.add(&bytes_to_string(name), &bytes_to_string(value))
    }

    /// Serializes the set to HTTP/1 format — one `Name: Value\r\n` line per
    /// entry, with no trailing empty line (curl's `Curl_dynhds_h1_dprint`).
    #[must_use]
    pub fn to_h1_string(&self) -> String {
        let mut out = String::new();
        for e in &self.entries {
            out.push_str(&e.name);
            out.push_str(": ");
            out.push_str(&e.value);
            out.push_str("\r\n");
        }
        out
    }
}

impl Default for DynHds {
    /// A set with the default request/response caps (see
    /// [`with_request_limits`](DynHds::with_request_limits)).
    fn default() -> Self {
        Self::with_request_limits()
    }
}

impl<'a> IntoIterator for &'a DynHds {
    type Item = &'a DynHdsEntry;
    type IntoIter = core::slice::Iter<'a, DynHdsEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

// ===========================================================================
// Public header API (`include/curl/header.h`, `lib/headers.c`)
// ===========================================================================

/// A single collected header as returned by the header API — the Rust analog
/// of C's `struct curl_header`.
///
/// Field correspondence with `struct curl_header`:
///
/// * [`name`](Header::name) / [`value`](Header::value) — the header name and
///   value. The name preserves the case as received.
/// * [`amount`](Header::amount) — the number of headers sharing this name
///   within the requested origin mask and request number.
/// * [`index`](Header::index) — the 0-based index of this instance among those
///   `amount` headers.
/// * [`origin`](Header::origin) — the origin bitmask, with the
///   [`CURLH_RESERVED_BIT`] set (exactly as `copy_header_external()` does).
/// * [`anchor`](Header::anchor) — the index of this header within the
///   collector's store; the analog of the opaque `void *anchor` in
///   `struct curl_header`, used to resume iteration in
///   [`nextheader`](HeaderCollector::nextheader).
///
/// [`request`](Header::request) records which request in a redirect/multi-stage
/// sequence produced the header. The C `struct curl_header` does not expose this
/// field; it is included here because it is meaningful internally and is cheap
/// to carry. The FFI layer simply does not copy it into the C struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The header name (case preserved).
    pub name: String,
    /// The header value.
    pub value: String,
    /// Number of headers with this name in the requested origin/request scope.
    pub amount: usize,
    /// 0-based index of this header among the `amount` that share its name.
    pub index: usize,
    /// Origin bitmask with [`CURLH_RESERVED_BIT`] set.
    pub origin: u32,
    /// Request number (0-based) that produced this header.
    pub request: i32,
    /// Store index; the opaque iteration anchor (C's `void *anchor`).
    pub anchor: usize,
}

/// An internal stored header — the Rust analog of C's `struct Curl_header_store`.
///
/// Holds the parsed name/value, the *raw* origin bits (without the reserved bit,
/// which is added only when a [`Header`] is built for return) and the request
/// number active when the header was pushed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HeaderStore {
    name: String,
    value: String,
    /// Raw `CURLH_*` origin bit (no [`CURLH_RESERVED_BIT`]).
    origin: u32,
    request: i32,
}

/// Splits a single header buffer into `(name, value)` — the Rust analog of
/// `namevalue()` in `lib/headers.c`.
///
/// `buf` is the header content with any trailing CR/LF already stripped and
/// leading blanks already removed (as [`HeaderCollector::push`] guarantees). For
/// a pseudo-header ([`CURLH_PSEUDO`]) the buffer must begin with `:`; that colon
/// is part of the stored name and the name terminator is the *next* colon.
///
/// The name is everything up to the delimiting colon (its trailing whitespace,
/// if any, is preserved exactly as curl does); the value is what follows with
/// leading and trailing blanks trimmed. A buffer with no delimiting colon yields
/// [`CurlError::BadFunctionArgument`].
fn namevalue(buf: &[u8], origin: u32) -> Result<(String, String)> {
    // Name starts at the beginning of the buffer.
    let mut i = 0;

    if origin == CURLH_PSEUDO {
        // Pseudo-headers must start with ':'; skip it before scanning for the
        // name-terminating colon.
        if buf.first() != Some(&b':') {
            return Err(CurlError::BadFunctionArgument);
        }
        i = 1;
    }

    // Find the colon that terminates the name.
    while i < buf.len() && buf[i] != b':' {
        i += 1;
    }
    if i >= buf.len() {
        // No colon: not a valid header.
        return Err(CurlError::BadFunctionArgument);
    }
    let name = &buf[..i];
    i += 1; // skip the colon

    // Skip leading blanks of the value.
    while i < buf.len() && is_blank(buf[i]) {
        i += 1;
    }
    let value_start = i;

    // Trim trailing blanks of the value.
    let mut value_end = buf.len();
    while value_end > value_start && is_blank(buf[value_end - 1]) {
        value_end -= 1;
    }
    let value = &buf[value_start..value_end];

    Ok((bytes_to_string(name), bytes_to_string(value)))
}

/// Per-handle store of collected response headers plus the header-API readers.
///
/// During a transfer the header client-writer stage calls [`push`](HeaderCollector::push)
/// for each received header line (the engine-side equivalent of
/// `Curl_headers_push()`); afterwards the application reads headers back with
/// [`header`](HeaderCollector::header) and [`nextheader`](HeaderCollector::nextheader)
/// (the equivalents of `curl_easy_header()` / `curl_easy_nextheader()`).
///
/// Two output slots are kept so that an interleaved
/// `header()` + `nextheader()` usage pattern does not clobber the other's
/// returned reference — matching curl's `data->state.headerout[0]` and
/// `headerout[1]`.
#[derive(Debug, Default)]
pub struct HeaderCollector {
    /// All collected headers, in arrival order (curl's `data->state.httphdrs`).
    stored: Vec<HeaderStore>,
    /// The current request number (curl's `data->state.requests`), starting at
    /// `0` and incremented once per redirect/follow.
    requests: i32,
    /// Store index of the most recently pushed header (curl's
    /// `data->state.prevhead`), used to support obs-fold continuation.
    prevhead: Option<usize>,
    /// Output slots for [`header`](HeaderCollector::header) (slot 0) and
    /// [`nextheader`](HeaderCollector::nextheader) (slot 1).
    headerout: [Option<Header>; 2],
}

impl HeaderCollector {
    /// Creates an empty collector at request `0`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Classifies a header's origin from the client-writer flags, reproducing
    /// the precedence in `hds_cw_collect_write()` (`lib/headers.c`):
    /// `CONNECT` beats `1xx` beats trailer beats a plain header.
    ///
    /// Pseudo-headers ([`CURLH_PSEUDO`]) are pushed directly by the HTTP/2 and
    /// HTTP/3 layers and are not produced by this helper.
    #[must_use]
    pub fn classify(is_connect: bool, is_1xx: bool, is_trailer: bool) -> u32 {
        if is_connect {
            CURLH_CONNECT
        } else if is_1xx {
            CURLH_1XX
        } else if is_trailer {
            CURLH_TRAILER
        } else {
            CURLH_HEADER
        }
    }

    /// The current request number (curl's `data->state.requests`).
    #[must_use]
    pub fn requests(&self) -> i32 {
        self.requests
    }

    /// Sets the current request number.
    pub fn set_requests(&mut self, requests: i32) {
        self.requests = requests;
    }

    /// Advances to the next request (called on each redirect/follow), mirroring
    /// curl incrementing `data->state.requests`.
    pub fn bump_request(&mut self) {
        self.requests += 1;
    }

    /// The number of collected headers.
    #[must_use]
    pub fn count(&self) -> usize {
        self.stored.len()
    }

    /// Returns `true` if no headers have been collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stored.is_empty()
    }

    /// Iterates over every collected header as a `(name, value)` pair in arrival
    /// order.
    ///
    /// This is the simple "all stored response headers" view that the CLI's
    /// `%header{}` / `%{header_json}` write-out consumes — curl walks the same
    /// store via `curl_easy_nextheader(easy, CURLH_HEADER, -1, prev)`. The richer
    /// per-origin / per-request selection (and the C-visible borrowed `Header`)
    /// remains available through [`header`](Self::header) /
    /// [`nextheader`](Self::nextheader); this accessor avoids the output-slot
    /// round-trip when the caller only needs an in-order Rust iteration.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.stored
            .iter()
            .map(|hs| (hs.name.as_str(), hs.value.as_str()))
    }

    /// Name/value of the most recently pushed header, if any (the analog of
    /// reading curl's `data->state.prevhead`).
    #[must_use]
    pub fn prev_header(&self) -> Option<(&str, &str)> {
        let idx = self.prevhead?;
        let hs = self.stored.get(idx)?;
        Some((hs.name.as_str(), hs.value.as_str()))
    }

    /// Appends an obs-fold continuation to the most recently pushed header's
    /// value, returning `true` if a previous header existed.
    ///
    /// curl normally performs the equivalent *unfold* in its HTTP/1 line reader
    /// (`lib/http.c`) before a combined line ever reaches `Curl_headers_push()`;
    /// this helper exposes the same effect for callers that fold after the fact,
    /// using `data->state.prevhead`. Leading blanks of the continuation are
    /// collapsed to a single space, matching curl's "keep only a single
    /// whitespace" unfold rule.
    pub fn fold_into_previous(&mut self, continuation: &[u8]) -> bool {
        let Some(idx) = self.prevhead else {
            return false;
        };
        let Some(hs) = self.stored.get_mut(idx) else {
            return false;
        };
        // Collapse leading blanks of the continuation to a single space.
        let mut start = 0;
        while start < continuation.len() && is_blank(continuation[start]) {
            start += 1;
        }
        // Trim trailing CR/LF and blanks from the continuation.
        let mut end = continuation.len();
        while end > start
            && (is_blank(continuation[end - 1])
                || continuation[end - 1] == b'\r'
                || continuation[end - 1] == b'\n')
        {
            end -= 1;
        }
        hs.value.push(' ');
        hs.value
            .push_str(&bytes_to_string(&continuation[start..end]));
        true
    }

    /// Resets the collector to its just-created state, dropping every collected
    /// header and clearing the output slots (the analog of
    /// `Curl_headers_cleanup()` + `headers_reset()` in `lib/headers.c`).
    ///
    /// The request counter is intentionally left untouched, matching curl, which
    /// manages `data->state.requests` as part of the broader transfer state.
    pub fn reset(&mut self) {
        self.stored.clear();
        self.prevhead = None;
        self.headerout = [None, None];
    }

    /// Stores a single received header line under the given origin — the
    /// engine-side equivalent of `Curl_headers_push()`.
    ///
    /// The line may be `CRLF`, `CR` or `LF` terminated. Behaviour reproduced
    /// from `lib/headers.c`:
    ///
    /// * A line beginning with CR or LF is the body separator and is silently
    ///   ignored (`Ok`).
    /// * Exactly one trailing `\n` then one trailing `\r` are stripped; if the
    ///   line had no CR/LF terminator at all it is rejected with
    ///   [`CurlError::WeirdServerReply`].
    /// * Leading blanks are skipped; a line that is all blanks is rejected with
    ///   [`CurlError::WeirdServerReply`].
    /// * Collecting more than [`MAX_HTTP_RESP_HEADER_COUNT`] headers fails with
    ///   [`CurlError::TooLarge`].
    /// * The remainder is split into name/value by an internal `namevalue`
    ///   parser; a malformed header yields [`CurlError::BadFunctionArgument`].
    ///
    /// On success the header is appended and recorded as the previous header
    /// (for obs-fold continuation).
    pub fn push(&mut self, line: &[u8], origin: u32) -> Result<()> {
        // A line starting with CR or LF is the body separator: ignore it.
        if matches!(line.first(), Some(&b'\r') | Some(&b'\n')) {
            return Ok(());
        }

        let ilen = line.len();
        let mut hlen = ilen;
        // Trim a single trailing '\n', then a single trailing '\r'.
        if hlen > 0 && line[hlen - 1] == b'\n' {
            hlen -= 1;
        }
        if hlen > 0 && line[hlen - 1] == b'\r' {
            hlen -= 1;
        }
        // A header with neither CR nor LF terminator is invalid.
        if hlen == ilen {
            return Err(CurlError::WeirdServerReply);
        }

        let mut buf = &line[..hlen];

        // Skip leading blanks; a header that is only blanks is invalid.
        if matches!(buf.first(), Some(&c) if is_blank(c)) {
            let mut start = 0;
            while start < buf.len() && is_blank(buf[start]) {
                start += 1;
            }
            buf = &buf[start..];
            if buf.is_empty() {
                return Err(CurlError::WeirdServerReply);
            }
        }

        // Enforce the response-header count cap.
        if self.stored.len() >= MAX_HTTP_RESP_HEADER_COUNT {
            return Err(CurlError::TooLarge);
        }

        let (name, value) = namevalue(buf, origin)?;
        self.stored.push(HeaderStore {
            name,
            value,
            origin,
            request: self.requests,
        });
        self.prevhead = Some(self.stored.len() - 1);
        Ok(())
    }

    /// Builds a returnable [`Header`] from the stored entry at `store_idx`,
    /// reproducing `copy_header_external()` (including the reserved origin bit).
    fn build_header(&self, store_idx: usize, index: usize, amount: usize) -> Header {
        let hs = &self.stored[store_idx];
        Header {
            name: hs.name.clone(),
            value: hs.value.clone(),
            amount,
            index,
            origin: hs.origin | CURLH_RESERVED_BIT,
            request: hs.request,
            anchor: store_idx,
        }
    }

    /// Looks up a collected header by name, instance index, origin mask and
    /// request — the equivalent of `curl_easy_header()`.
    ///
    /// `origin` is a bitmask of `CURLH_*` flags; a header matches if any of its
    /// origin bits are set in `origin`. `request` selects which request in a
    /// redirect sequence to read; `-1` means the most recent request.
    ///
    /// On success the returned [`Header`] borrows an internal slot and remains
    /// valid until the next call to `header` (or a [`reset`](Self::reset)).
    ///
    /// # Errors
    ///
    /// * [`CurlHError::BadArgument`] — `origin` has bits outside
    ///   [`CURLH_ORIGIN_MASK`], `origin` is `0`, or `request < -1`.
    /// * [`CurlHError::NoHeaders`] — no headers have been collected.
    /// * [`CurlHError::NoRequest`] — `request` exceeds the highest request seen.
    /// * [`CurlHError::Missing`] — no header with that name in scope.
    /// * [`CurlHError::BadIndex`] — fewer than `index + 1` such headers exist.
    pub fn header(
        &mut self,
        name: &str,
        index: usize,
        origin: u32,
        request: i32,
    ) -> core::result::Result<&Header, CurlHError> {
        // Argument validation, matching the C guard exactly.
        if origin > CURLH_ORIGIN_MASK || origin == 0 || request < -1 {
            return Err(CurlHError::BadArgument);
        }
        if self.stored.is_empty() {
            return Err(CurlHError::NoHeaders);
        }
        if request > self.requests {
            return Err(CurlHError::NoRequest);
        }
        let request = if request == -1 {
            self.requests
        } else {
            request
        };

        // First pass: count matches and remember the last one.
        let mut amount = 0;
        let mut last_pick: Option<usize> = None;
        for (idx, hs) in self.stored.iter().enumerate() {
            if hs.request == request && (hs.origin & origin) != 0 && name_eq(&hs.name, name) {
                amount += 1;
                last_pick = Some(idx);
            }
        }
        if amount == 0 {
            return Err(CurlHError::Missing);
        }
        if index >= amount {
            return Err(CurlHError::BadIndex);
        }

        // Resolve the chosen store index for the requested instance.
        let chosen = if index == amount - 1 {
            // The last (or only) occurrence is exactly what was asked for.
            last_pick.unwrap_or(0)
        } else {
            let mut match_n = 0;
            let mut found: Option<usize> = None;
            for (idx, hs) in self.stored.iter().enumerate() {
                if hs.request == request && (hs.origin & origin) != 0 && name_eq(&hs.name, name) {
                    if match_n == index {
                        found = Some(idx);
                        break;
                    }
                    match_n += 1;
                }
            }
            match found {
                Some(i) => i,
                // Unreachable given the counting pass above, but handled total.
                None => return Err(CurlHError::Missing),
            }
        };

        let hdr = self.build_header(chosen, index, amount);
        self.headerout[0] = Some(hdr);
        Ok(self.headerout[0]
            .as_ref()
            .expect("headerout[0] was just assigned"))
    }

    /// Returns the next collected header in the given origin mask and request,
    /// resuming after `prev` — the equivalent of `curl_easy_nextheader()`.
    ///
    /// Pass `prev = None` to start from the first header; pass the previously
    /// returned header to continue. `request = -1` means the most recent
    /// request. Returns `None` when no further header matches.
    ///
    /// Because the returned reference borrows the collector, callers iterating
    /// in a loop should prefer [`nextheader_from`](Self::nextheader_from), which
    /// takes a plain anchor index and avoids holding a borrow across calls.
    pub fn nextheader(
        &mut self,
        origin: u32,
        request: i32,
        prev: Option<&Header>,
    ) -> Option<&Header> {
        let prev_anchor = prev.map(|p| p.anchor);
        self.nextheader_from(origin, request, prev_anchor)
    }

    /// Anchor-index variant of [`nextheader`](Self::nextheader).
    ///
    /// `prev_anchor` is the [`anchor`](Header::anchor) of the previously returned
    /// header (or `None` to start). This is the borrow-free primitive used by
    /// the FFI layer, which stores the anchor in the C `struct curl_header`.
    pub fn nextheader_from(
        &mut self,
        origin: u32,
        request: i32,
        prev_anchor: Option<usize>,
    ) -> Option<&Header> {
        if request > self.requests {
            return None;
        }
        let request = if request == -1 {
            self.requests
        } else {
            request
        };

        // Start after the previous anchor, or at the head of the list.
        let start = match prev_anchor {
            Some(a) => a + 1,
            None => 0,
        };

        // Advance to the next header matching the origin mask and request.
        let mut pick: Option<usize> = None;
        let mut idx = start;
        while idx < self.stored.len() {
            let hs = &self.stored[idx];
            if (hs.origin & origin) != 0 && hs.request == request {
                pick = Some(idx);
                break;
            }
            idx += 1;
        }
        let pick = pick?;

        // Count occurrences of this name within the mask/request and find the
        // index of the picked entry among them.
        let picked_name = self.stored[pick].name.clone();
        let mut amount = 0;
        let mut index = 0;
        for (i, hs) in self.stored.iter().enumerate() {
            if name_eq(&hs.name, &picked_name) && hs.request == request && (hs.origin & origin) != 0
            {
                amount += 1;
            }
            if i == pick {
                index = amount - 1;
            }
        }

        let hdr = self.build_header(pick, index, amount);
        self.headerout[1] = Some(hdr);
        self.headerout[1].as_ref()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- DynHds -----------------------------------------------------------

    #[test]
    fn dynhds_add_count_and_case_insensitive_get() {
        let mut h = DynHds::new(0, 4096);
        assert!(h.is_empty());
        h.add("Content-Type", "text/html").unwrap();
        h.add("X-Custom", "1").unwrap();
        assert_eq!(h.count(), 2);
        assert!(!h.is_empty());

        // Case-insensitive lookup returns the first match, case preserved.
        let e = h.get("content-TYPE").expect("present");
        assert_eq!(e.name(), "Content-Type");
        assert_eq!(e.value(), "text/html");
        assert_eq!(e.namelen(), "Content-Type".len());
        assert_eq!(e.valuelen(), "text/html".len());
        assert_eq!(e.name_bytes(), b"Content-Type");
        assert_eq!(e.value_bytes(), b"text/html");

        assert!(h.contains("X-CUSTOM"));
        assert!(!h.contains("missing"));
        assert!(h.get("missing").is_none());

        assert_eq!(h.getn(0).unwrap().name(), "Content-Type");
        assert_eq!(h.getn(1).unwrap().name(), "X-Custom");
        assert!(h.getn(2).is_none());
    }

    #[test]
    fn dynhds_does_not_dedup_and_count_name() {
        let mut h = DynHds::new(0, 4096);
        h.add("Set-Cookie", "a=1").unwrap();
        h.add("set-cookie", "b=2").unwrap();
        h.add("Other", "x").unwrap();
        assert_eq!(h.count(), 3);
        assert_eq!(h.count_name("SET-COOKIE"), 2);
        assert_eq!(h.count_name("other"), 1);
        assert_eq!(h.count_name("nope"), 0);
        // get returns the first inserted instance.
        assert_eq!(h.get("set-cookie").unwrap().value(), "a=1");
    }

    #[test]
    fn dynhds_entry_cap_enforced() {
        let mut h = DynHds::new(2, 4096);
        assert_eq!(h.max_entries(), 2);
        h.add("a", "1").unwrap();
        h.add("b", "2").unwrap();
        // Third add exceeds the entry cap.
        assert_eq!(h.add("c", "3"), Err(CurlError::OutOfMemory));
        assert_eq!(h.count(), 2);
    }

    #[test]
    fn dynhds_byte_cap_enforced() {
        // Cap of 10 total bytes of names+values.
        let mut h = DynHds::new(0, 10);
        assert_eq!(h.max_strs_size(), 10);
        // "ab" + "cd" = 4 bytes.
        h.add("ab", "cd").unwrap();
        assert_eq!(h.total_strs_len(), 4);
        // "ef" + "ghij" = 6 bytes -> total 10, allowed (strictly-greater check).
        h.add("ef", "ghij").unwrap();
        assert_eq!(h.total_strs_len(), 10);
        // One more byte overflows.
        assert_eq!(h.add("k", ""), Err(CurlError::OutOfMemory));
    }

    #[test]
    fn dynhds_set_replaces_all_same_name() {
        let mut h = DynHds::new(0, 4096);
        h.add("X", "1").unwrap();
        h.add("Y", "y").unwrap();
        h.add("x", "2").unwrap();
        assert_eq!(h.count_name("x"), 2);
        // set removes all "X" then appends a fresh one at the end.
        h.set("X", "final").unwrap();
        assert_eq!(h.count_name("x"), 1);
        assert_eq!(h.get("x").unwrap().value(), "final");
        // The replacement is appended last.
        assert_eq!(h.getn(h.count() - 1).unwrap().value(), "final");
    }

    #[test]
    fn dynhds_remove_returns_count_and_updates_size() {
        let mut h = DynHds::new(0, 4096);
        h.add("Dup", "11").unwrap();
        h.add("keep", "k").unwrap();
        h.add("dup", "222").unwrap();
        let before = h.total_strs_len();
        let removed = h.remove("DUP");
        assert_eq!(removed, 2);
        assert_eq!(h.count(), 1);
        assert_eq!(h.get("keep").unwrap().value(), "k");
        // Sizes of both "Dup" entries were subtracted.
        assert_eq!(
            before - h.total_strs_len(),
            ("Dup".len() + "11".len()) + ("dup".len() + "222".len())
        );
        assert_eq!(h.remove("absent"), 0);
    }

    #[test]
    fn dynhds_reset_clears_entries_and_size() {
        let mut h = DynHds::new(0, 4096);
        h.add("a", "1").unwrap();
        h.add("b", "2").unwrap();
        h.reset();
        assert!(h.is_empty());
        assert_eq!(h.total_strs_len(), 0);
        // Caps survive a reset.
        assert_eq!(h.max_strs_size(), 4096);
    }

    #[test]
    fn dynhds_lowercase_option() {
        let mut h = DynHds::new(0, 4096);
        h.set_opts(DYNHDS_OPT_LOWERCASE);
        assert_eq!(h.opts(), DYNHDS_OPT_LOWERCASE);
        h.add("Content-Type", "X").unwrap();
        // Name lowercased; value untouched.
        assert_eq!(h.getn(0).unwrap().name(), "content-type");
        assert_eq!(h.getn(0).unwrap().value(), "X");
    }

    #[test]
    fn dynhds_h1_line_parsing() {
        let mut h = DynHds::new(0, 4096);
        // Trailing CRLF stripped; leading value blanks skipped.
        h.add_h1_line("X-Foo:   bar\r\n").unwrap();
        let e = h.get("x-foo").unwrap();
        assert_eq!(e.name(), "X-Foo");
        assert_eq!(e.value(), "bar");

        // LF-only termination and a value containing colons.
        h.add_h1_line("Date: Mon, 01 Jan 2024 00:00:00 GMT\n")
            .unwrap();
        assert_eq!(
            h.get("date").unwrap().value(),
            "Mon, 01 Jan 2024 00:00:00 GMT"
        );

        // Empty line is a no-op.
        let before = h.count();
        h.add_h1_line("").unwrap();
        assert_eq!(h.count(), before);

        // A line without a colon is rejected.
        assert_eq!(
            h.add_h1_line("nocolonhere"),
            Err(CurlError::BadFunctionArgument)
        );
    }

    #[test]
    fn dynhds_to_h1_string_round_trips() {
        let mut h = DynHds::new(0, 4096);
        h.add("Host", "example.com").unwrap();
        h.add("Accept", "*/*").unwrap();
        // One "Name: Value\r\n" line per entry, no trailing blank line.
        assert_eq!(h.to_h1_string(), "Host: example.com\r\nAccept: */*\r\n");
    }

    #[test]
    fn dynhds_iteration() {
        let mut h = DynHds::new(0, 4096);
        h.add("a", "1").unwrap();
        h.add("b", "2").unwrap();
        let via_iter: Vec<&str> = h.iter().map(DynHdsEntry::name).collect();
        let via_into: Vec<&str> = (&h).into_iter().map(DynHdsEntry::name).collect();
        assert_eq!(via_iter, vec!["a", "b"]);
        assert_eq!(via_into, vec!["a", "b"]);
        assert_eq!(h.entries().len(), 2);
    }

    // ---- Header push + classification -------------------------------------

    #[test]
    fn classify_matches_curl_precedence() {
        assert_eq!(HeaderCollector::classify(true, false, false), CURLH_CONNECT);
        // CONNECT beats everything.
        assert_eq!(HeaderCollector::classify(true, true, true), CURLH_CONNECT);
        // 1xx beats trailer.
        assert_eq!(HeaderCollector::classify(false, true, true), CURLH_1XX);
        assert_eq!(HeaderCollector::classify(false, false, true), CURLH_TRAILER);
        assert_eq!(HeaderCollector::classify(false, false, false), CURLH_HEADER);
    }

    #[test]
    fn push_basic_header_and_lookup() {
        let mut c = HeaderCollector::new();
        assert!(c.is_empty());
        c.push(b"Content-Type: text/html\r\n", CURLH_HEADER)
            .unwrap();
        assert_eq!(c.count(), 1);

        let h = c
            .header("content-type", 0, CURLH_HEADER, -1)
            .unwrap()
            .clone();
        assert_eq!(h.name, "Content-Type");
        assert_eq!(h.value, "text/html");
        assert_eq!(h.amount, 1);
        assert_eq!(h.index, 0);
        assert_eq!(h.request, 0);
        // Reserved bit is OR'd in; the low bits are exactly CURLH_HEADER.
        assert_ne!(h.origin & CURLH_RESERVED_BIT, 0);
        assert_eq!(h.origin & CURLH_ORIGIN_MASK, CURLH_HEADER);
    }

    #[test]
    fn push_strips_terminators_and_skips_body_separator() {
        let mut c = HeaderCollector::new();
        // CRLF, LF-only, and CR-only terminators all accepted.
        c.push(b"A: 1\r\n", CURLH_HEADER).unwrap();
        c.push(b"B: 2\n", CURLH_HEADER).unwrap();
        c.push(b"C: 3\r", CURLH_HEADER).unwrap();
        assert_eq!(c.count(), 3);
        assert_eq!(c.header("c", 0, CURLH_HEADER, -1).unwrap().value, "3");

        // A lone CRLF/LF is the body separator: ignored, no error.
        c.push(b"\r\n", CURLH_HEADER).unwrap();
        c.push(b"\n", CURLH_HEADER).unwrap();
        assert_eq!(c.count(), 3);
    }

    #[test]
    fn push_rejects_unterminated_and_blank_only() {
        let mut c = HeaderCollector::new();
        // No CR/LF terminator at all.
        assert_eq!(
            c.push(b"X: 1", CURLH_HEADER),
            Err(CurlError::WeirdServerReply)
        );
        // Only blanks before the terminator.
        assert_eq!(
            c.push(b"    \r\n", CURLH_HEADER),
            Err(CurlError::WeirdServerReply)
        );
        assert!(c.is_empty());
    }

    #[test]
    fn push_rejects_header_without_colon() {
        let mut c = HeaderCollector::new();
        assert_eq!(
            c.push(b"NoColonHeader\r\n", CURLH_HEADER),
            Err(CurlError::BadFunctionArgument)
        );
    }

    #[test]
    fn push_pseudo_header() {
        let mut c = HeaderCollector::new();
        c.push(b":status: 200\r\n", CURLH_PSEUDO).unwrap();
        let h = c.header(":status", 0, CURLH_PSEUDO, -1).unwrap().clone();
        assert_eq!(h.name, ":status");
        assert_eq!(h.value, "200");
        assert_eq!(h.origin & CURLH_ORIGIN_MASK, CURLH_PSEUDO);

        // A pseudo buffer that does not start with ':' is malformed.
        let mut c2 = HeaderCollector::new();
        assert_eq!(
            c2.push(b"status: 200\r\n", CURLH_PSEUDO),
            Err(CurlError::BadFunctionArgument)
        );
    }

    #[test]
    fn push_trims_value_whitespace() {
        let mut c = HeaderCollector::new();
        c.push(b"Spaced:    hello world   \r\n", CURLH_HEADER)
            .unwrap();
        assert_eq!(
            c.header("spaced", 0, CURLH_HEADER, -1).unwrap().value,
            "hello world"
        );
    }

    // ---- header(): amount / index / errors --------------------------------

    #[test]
    fn header_amount_and_index_for_repeated_names() {
        let mut c = HeaderCollector::new();
        c.push(b"Set-Cookie: a=1\r\n", CURLH_HEADER).unwrap();
        c.push(b"X-Other: y\r\n", CURLH_HEADER).unwrap();
        c.push(b"set-cookie: b=2\r\n", CURLH_HEADER).unwrap();
        c.push(b"SET-COOKIE: c=3\r\n", CURLH_HEADER).unwrap();

        let h0 = c.header("set-cookie", 0, CURLH_HEADER, -1).unwrap().clone();
        assert_eq!(h0.amount, 3);
        assert_eq!(h0.index, 0);
        assert_eq!(h0.value, "a=1");

        let h1 = c.header("set-cookie", 1, CURLH_HEADER, -1).unwrap().clone();
        assert_eq!(h1.index, 1);
        assert_eq!(h1.value, "b=2");

        let h2 = c.header("set-cookie", 2, CURLH_HEADER, -1).unwrap().clone();
        assert_eq!(h2.index, 2);
        assert_eq!(h2.value, "c=3");

        // index == amount is out of range.
        assert_eq!(
            c.header("set-cookie", 3, CURLH_HEADER, -1).unwrap_err(),
            CurlHError::BadIndex
        );
    }

    #[test]
    fn header_error_paths() {
        let mut c = HeaderCollector::new();
        // No headers collected yet.
        assert_eq!(
            c.header("any", 0, CURLH_HEADER, -1).unwrap_err(),
            CurlHError::NoHeaders
        );

        c.push(b"A: 1\r\n", CURLH_HEADER).unwrap();

        // origin == 0 -> bad argument.
        assert_eq!(
            c.header("a", 0, 0, -1).unwrap_err(),
            CurlHError::BadArgument
        );
        // origin with bits outside the mask -> bad argument.
        assert_eq!(
            c.header("a", 0, CURLH_RESERVED_BIT, -1).unwrap_err(),
            CurlHError::BadArgument
        );
        // request < -1 -> bad argument.
        assert_eq!(
            c.header("a", 0, CURLH_HEADER, -2).unwrap_err(),
            CurlHError::BadArgument
        );
        // request beyond the highest seen -> no request.
        assert_eq!(
            c.header("a", 0, CURLH_HEADER, 5).unwrap_err(),
            CurlHError::NoRequest
        );
        // A name that does not exist -> missing.
        assert_eq!(
            c.header("nope", 0, CURLH_HEADER, -1).unwrap_err(),
            CurlHError::Missing
        );
        // Wrong origin mask for an existing header -> missing.
        assert_eq!(
            c.header("a", 0, CURLH_TRAILER, -1).unwrap_err(),
            CurlHError::Missing
        );
    }

    #[test]
    fn header_origin_mask_filters() {
        let mut c = HeaderCollector::new();
        c.push(b"Via: 1.1 proxy\r\n", CURLH_CONNECT).unwrap();
        c.push(b"Via: 2.0 edge\r\n", CURLH_HEADER).unwrap();

        // Mask matches both -> amount 2.
        let both = c
            .header("via", 0, CURLH_HEADER | CURLH_CONNECT, -1)
            .unwrap()
            .clone();
        assert_eq!(both.amount, 2);

        // Mask matches only the CONNECT one.
        let only_connect = c.header("via", 0, CURLH_CONNECT, -1).unwrap().clone();
        assert_eq!(only_connect.amount, 1);
        assert_eq!(only_connect.value, "1.1 proxy");
    }

    #[test]
    fn header_request_indexing() {
        let mut c = HeaderCollector::new();
        // Request 0 (initial).
        c.push(b"Stage: first\r\n", CURLH_HEADER).unwrap();
        // Simulate a redirect: advance to request 1.
        c.bump_request();
        assert_eq!(c.requests(), 1);
        c.push(b"Stage: second\r\n", CURLH_HEADER).unwrap();

        assert_eq!(
            c.header("stage", 0, CURLH_HEADER, 0).unwrap().value,
            "first"
        );
        assert_eq!(
            c.header("stage", 0, CURLH_HEADER, 1).unwrap().value,
            "second"
        );
        // -1 selects the most recent request.
        assert_eq!(
            c.header("stage", 0, CURLH_HEADER, -1).unwrap().value,
            "second"
        );
        // Each request scopes amount/index independently.
        assert_eq!(c.header("stage", 0, CURLH_HEADER, 0).unwrap().amount, 1);
    }

    // ---- nextheader -------------------------------------------------------

    #[test]
    fn nextheader_iterates_in_order() {
        let mut c = HeaderCollector::new();
        c.push(b"A: 1\r\n", CURLH_HEADER).unwrap();
        c.push(b"B: 2\r\n", CURLH_HEADER).unwrap();
        c.push(b":status: 200\r\n", CURLH_PSEUDO).unwrap();
        c.push(b"C: 3\r\n", CURLH_HEADER).unwrap();

        // Iterate only the plain headers (pseudo excluded by the mask).
        let mut anchor: Option<usize> = None;
        let mut names = Vec::new();
        while let Some(h) = c.nextheader_from(CURLH_HEADER, -1, anchor) {
            anchor = Some(h.anchor);
            names.push(h.name.clone());
        }
        assert_eq!(names, vec!["A", "B", "C"]);
    }

    #[test]
    fn nextheader_none_matches_first() {
        let mut c = HeaderCollector::new();
        c.push(b"Only: here\r\n", CURLH_HEADER).unwrap();
        // The &Header-taking variant agrees with the anchor variant for the
        // first element.
        let first = c.nextheader(CURLH_HEADER, -1, None).unwrap().clone();
        assert_eq!(first.name, "Only");
        assert_eq!(first.amount, 1);
        assert_eq!(first.index, 0);
        // No further header of this type.
        assert!(c
            .nextheader_from(CURLH_HEADER, -1, Some(first.anchor))
            .is_none());
    }

    #[test]
    fn nextheader_respects_request_and_amount() {
        let mut c = HeaderCollector::new();
        c.push(b"Set-Cookie: a\r\n", CURLH_HEADER).unwrap();
        c.push(b"Set-Cookie: b\r\n", CURLH_HEADER).unwrap();

        let h = c.nextheader_from(CURLH_HEADER, -1, None).unwrap().clone();
        assert_eq!(h.name, "Set-Cookie");
        assert_eq!(h.amount, 2);
        assert_eq!(h.index, 0);

        let h2 = c
            .nextheader_from(CURLH_HEADER, -1, Some(h.anchor))
            .unwrap()
            .clone();
        assert_eq!(h2.index, 1);
        assert_eq!(h2.amount, 2);

        // A request number beyond the highest seen yields nothing.
        assert!(c.nextheader_from(CURLH_HEADER, 9, None).is_none());
    }

    // ---- folding / prevhead ----------------------------------------------

    #[test]
    fn prev_header_and_fold_into_previous() {
        let mut c = HeaderCollector::new();
        assert!(c.prev_header().is_none());
        c.push(b"Folded: start\r\n", CURLH_HEADER).unwrap();
        assert_eq!(c.prev_header(), Some(("Folded", "start")));

        // An obs-fold continuation extends the previous value with one space.
        assert!(c.fold_into_previous(b"   continued\r\n"));
        assert_eq!(c.prev_header(), Some(("Folded", "start continued")));
        assert_eq!(
            c.header("folded", 0, CURLH_HEADER, -1).unwrap().value,
            "start continued"
        );
    }

    #[test]
    fn fold_into_previous_without_previous_is_noop() {
        let mut c = HeaderCollector::new();
        assert!(!c.fold_into_previous(b"orphan"));
    }

    // ---- caps / reset on the collector ------------------------------------

    #[test]
    fn push_enforces_max_header_count() {
        let mut c = HeaderCollector::new();
        for i in 0..MAX_HTTP_RESP_HEADER_COUNT {
            let line = format!("H{i}: v\r\n");
            c.push(line.as_bytes(), CURLH_HEADER).unwrap();
        }
        assert_eq!(c.count(), MAX_HTTP_RESP_HEADER_COUNT);
        // One beyond the cap is rejected.
        assert_eq!(
            c.push(b"Over: flow\r\n", CURLH_HEADER),
            Err(CurlError::TooLarge)
        );
    }

    #[test]
    fn collector_reset_clears_state() {
        let mut c = HeaderCollector::new();
        c.push(b"A: 1\r\n", CURLH_HEADER).unwrap();
        c.bump_request();
        c.reset();
        assert!(c.is_empty());
        assert!(c.prev_header().is_none());
        // Request counter is intentionally preserved across a reset.
        assert_eq!(c.requests(), 1);
        assert_eq!(
            c.header("a", 0, CURLH_HEADER, -1).unwrap_err(),
            CurlHError::NoHeaders
        );
    }

    #[test]
    fn reexported_curlh_error_is_the_same_type() {
        // The re-export and the canonical path refer to the same type.
        let a: CurlHError = crate::error::CurlHError::Missing;
        let b: crate::headers::CurlHError = CurlHError::Missing;
        assert_eq!(a, b);
        assert_eq!(a.code(), 2);
    }
}
