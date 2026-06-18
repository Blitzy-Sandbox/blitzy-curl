//! HTTP Strict Transport Security (HSTS) store — RFC 6797.
//!
//! This is the idiomatic, memory-safe Rust reimplementation of libcurl's HSTS
//! subsystem (`lib/hsts.c` / `lib/hsts.h`). It owns three responsibilities that
//! together let the transfer engine upgrade insecure `http://` requests to
//! `https://` for hosts that have advertised an HSTS policy:
//!
//! 1. **Header parsing** — [`HstsStore::parse`] consumes a
//!    `Strict-Transport-Security` response-header value, honoring the `max-age`
//!    (mandatory) and `includeSubDomains` (optional) directives, with
//!    `max-age=0` deleting a known host. Mirrors C's `Curl_hsts_parse`.
//! 2. **Matching** — [`HstsStore::is_known`] answers "is this host currently an
//!    HSTS host?" using exact-host and `includeSubDomains` superdomain matching
//!    while skipping expired entries. Mirrors C's `Curl_hsts`.
//! 3. **Persistence** — [`HstsStore::load_file`] / [`HstsStore::save`] read and
//!    write curl's documented, line-oriented HSTS cache file
//!    (<https://curl.se/docs/hsts.html>) **byte-for-byte** so the regression
//!    suite's dump comparisons pass unchanged. Mirrors `Curl_hsts_loadfile` /
//!    `Curl_hsts_save`.
//!
//! The C sources are consulted strictly as a **behavioral and file-format
//! oracle** (AAP §0.8.2): parsing rules, subdomain matching, expiry handling,
//! and the persisted layout are reproduced exactly, but the code is expressed
//! with safe Rust collections rather than a hand-rolled linked list. The actual
//! scheme/port rewrite (`http`→`https`, `80`→`443`) is performed by the
//! transfer/URL layer; this module only stores policy and answers queries.
//!
//! # Time handling
//!
//! Unlike the C code — which reads the wall clock internally via `time(NULL)`
//! (overridable by `CURL_TIME` in debug builds) — every time-sensitive entry
//! point here takes an explicit `now` (a Unix timestamp in seconds, UTC). This
//! keeps the module free of ambient global state, makes expiry deterministically
//! testable, and lets the caller inject the same clock the rest of the engine
//! uses. The "never expires" sentinel is [`UNLIMITED_EXPIRY`] (`i64::MAX`),
//! matching curl's `TIME_T_MAX` on 64-bit platforms.
//!
//! # Feature gating
//!
//! The whole module is gated behind the `hsts` Cargo feature (default on),
//! matching curl's `CURL_DISABLE_HSTS` build gate. When the feature is off the
//! module compiles to nothing, `version.rs` omits the `CURL_VERSION_HSTS` bit
//! (`1 << 28`), and the relevant `setopt` calls return `CURLE_NOT_BUILT_IN`.
//!
//! # Memory safety
//!
//! Per the project mandate (AAP §0.7.1) this module contains **zero `unsafe`**
//! and is compiled under `#![forbid(unsafe_code)]`. All host comparisons operate
//! on raw bytes with ASCII-only case folding (parity with curl's
//! `curl_strnequal`), so they never panic on non-UTF-8 input or char
//! boundaries.

#![cfg(feature = "hsts")]
#![forbid(unsafe_code)]

use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Datelike, NaiveDate, Timelike, Utc};

use crate::error::{CurlError, Result};

// ----------------------------------------------------------------------------
// Constants — mirroring the `#define`s in `lib/hsts.c` / `include/curl/curl.h`.
// ----------------------------------------------------------------------------

/// Maximum accepted hostname length, in bytes (`MAX_HSTS_HOSTLEN` in
/// `lib/hsts.c`). Queries longer than this never match; the C lookup rejects
/// them outright.
pub const MAX_HSTS_HOSTLEN: usize = 2048;

/// Maximum length of a single line in the persisted cache file
/// (`MAX_HSTS_LINE`). Retained for parity/documentation; long lines are simply
/// not parsed into entries.
pub const MAX_HSTS_LINE: usize = 4095;

/// Maximum length of the date token in the persisted cache file
/// (`MAX_HSTS_DATELEN`).
pub const MAX_HSTS_DATELEN: usize = 256;

/// The literal token used in the cache file to mean "this entry never expires"
/// (`UNLIMITED` in `lib/hsts.c`).
pub const UNLIMITED: &str = "unlimited";

/// The internal sentinel expiry meaning "never expires".
///
/// curl uses `TIME_T_MAX` for this, which equals [`i64::MAX`] on the 64-bit
/// `time_t` platforms this rewrite targets. An entry whose `expires` equals this
/// value is serialized as the [`UNLIMITED`] token rather than a date.
pub const UNLIMITED_EXPIRY: i64 = i64::MAX;

/// `CURLHSTS_ENABLE` bit for `CURLOPT_HSTS_CTRL` (`include/curl/curl.h`).
///
/// Enables the in-memory HSTS cache. Stored verbatim in [`HstsStore::flags`].
pub const CURLHSTS_ENABLE: u32 = 1 << 0;

/// `CURLHSTS_READONLYFILE` bit for `CURLOPT_HSTS_CTRL` (`include/curl/curl.h`).
///
/// Marks the backing file as read-only: it is loaded on start but never written
/// back by [`HstsStore::save`].
pub const CURLHSTS_READONLYFILE: u32 = 1 << 1;

/// The exact two-line comment banner curl writes at the top of every saved
/// cache file. Reproduced byte-for-byte (including the trailing newline) so the
/// regression suite's file comparisons pass unchanged.
const HSTS_FILE_HEADER: &str = "# Your HSTS cache. https://curl.se/docs/hsts.html\n\
     # This file was generated by libcurl! Edit at your own risk.\n";

/// Process-wide counter used to give each atomic save a unique temporary file
/// name, so concurrent saves to different stores never collide.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

// ----------------------------------------------------------------------------
// HstsEntry
// ----------------------------------------------------------------------------

/// A single HSTS policy entry: one host plus its expiry and subdomain scope.
///
/// Equivalent to C's `struct stsentry`. The host is stored with any trailing
/// dot removed (curl strips it on insert) and with its original case preserved;
/// all matching is ASCII case-insensitive, exactly as in curl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HstsEntry {
    /// The host this policy applies to, e.g. `"example.com"`. Never carries a
    /// leading `.` (the `includeSubDomains` scope is expressed by
    /// [`include_subdomains`](Self::include_subdomains)) and never a trailing
    /// `.` (stripped on insert).
    pub host: String,
    /// Whether the policy also covers every subdomain of [`host`](Self::host).
    pub include_subdomains: bool,
    /// Absolute expiry as a Unix timestamp (seconds, UTC). The value
    /// [`UNLIMITED_EXPIRY`] means the entry never expires.
    pub expires: i64,
}

impl HstsEntry {
    /// Creates an entry. The `host` is stored as given except that a single
    /// trailing dot is stripped (matching curl's `hsts_create`).
    #[must_use]
    pub fn new(host: impl Into<String>, include_subdomains: bool, expires: i64) -> Self {
        let host = host.into();
        let host = match host.strip_suffix('.') {
            Some(stripped) => stripped.to_string(),
            None => host,
        };
        HstsEntry {
            host,
            include_subdomains,
            expires,
        }
    }

    /// Returns `true` if this entry never expires ([`expires`](Self::expires)
    /// equals [`UNLIMITED_EXPIRY`]).
    #[must_use]
    pub fn is_unlimited(&self) -> bool {
        self.expires == UNLIMITED_EXPIRY
    }

    /// Returns `true` if this entry has expired relative to `now`.
    ///
    /// Matches curl's `sts->expires <= now` test: an entry is considered expired
    /// at the exact second it reaches its expiry timestamp.
    #[must_use]
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires <= now
    }

    /// Formats this entry's expiry the way curl writes it to the cache file and
    /// passes it to the write callback's `expire[18]` buffer: either the
    /// [`UNLIMITED`] token or a UTC `YYYYMMDD HH:MM:SS` timestamp.
    #[must_use]
    pub fn expiry_string(&self) -> String {
        if self.expires == UNLIMITED_EXPIRY {
            UNLIMITED.to_string()
        } else {
            // A non-sentinel expiry that nonetheless falls outside the range
            // representable as a calendar date is degenerate; fall back to the
            // unlimited token rather than emitting a malformed line.
            format_expiry(self.expires).unwrap_or_else(|| UNLIMITED.to_string())
        }
    }
}

// ----------------------------------------------------------------------------
// HstsStore
// ----------------------------------------------------------------------------

/// An in-memory HSTS cache with optional file persistence.
///
/// Equivalent to C's `struct hsts`. Entries are held in a [`Vec`] in **insertion
/// order**, which is the order curl's linked list preserves and the order the
/// cache file is written in; an update to an existing host keeps its original
/// position. The store is plain data (`Send + Sync`), so it can be shared across
/// transfers behind an `Arc<Mutex<…>>` by `crate::share`, mirroring curl's
/// reference-counted shared HSTS cache.
///
/// # Examples
///
/// ```ignore
/// use curl_rs_lib::hsts::HstsStore;
///
/// let mut store = HstsStore::new();
/// let now = 1_700_000_000;
/// store.parse("example.com", "max-age=31536000; includeSubDomains", now).unwrap();
/// assert!(store.is_known("example.com", now));
/// assert!(store.is_known("api.example.com", now)); // covered by includeSubDomains
/// ```
#[derive(Debug, Clone, Default)]
pub struct HstsStore {
    /// The policy entries, in insertion order.
    entries: Vec<HstsEntry>,
    /// The backing file path, remembered across handle resets so a later
    /// [`save`](Self::save) with no explicit path can reuse it (mirrors curl
    /// stashing `h->filename` in `hsts_load`).
    filename: Option<PathBuf>,
    /// `CURLHSTS_*` control bits (see [`CURLHSTS_ENABLE`],
    /// [`CURLHSTS_READONLYFILE`]).
    flags: u32,
}

impl HstsStore {
    /// Creates an empty store with no backing file and no flags set.
    ///
    /// Mirrors `Curl_hsts_init`. (Cleanup is automatic: dropping the store frees
    /// all entries and the remembered filename, replacing C's
    /// `Curl_hsts_cleanup`.)
    #[must_use]
    pub fn new() -> Self {
        HstsStore::default()
    }

    /// Creates an empty store that remembers `file` as its backing path.
    #[must_use]
    pub fn with_file(file: impl Into<PathBuf>) -> Self {
        HstsStore {
            entries: Vec::new(),
            filename: Some(file.into()),
            flags: 0,
        }
    }

    // -- accessors -----------------------------------------------------------

    /// Returns the number of stored entries (including any that are expired but
    /// not yet pruned). Mirrors `Curl_llist_count(&h->list)`.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Alias for [`count`](Self::count); returns the number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the store holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a read-only view of all entries in insertion order.
    ///
    /// This is what the FFI/easy layer iterates when driving the
    /// `CURLOPT_HSTSWRITEFUNCTION` callback: for each entry it builds a
    /// `curl_hstsentry` (name = [`HstsEntry::host`], `includeSubDomains`, and
    /// `expire` from [`HstsEntry::expiry_string`]).
    #[must_use]
    pub fn entries(&self) -> &[HstsEntry] {
        &self.entries
    }

    /// Returns the remembered backing-file path, if any.
    #[must_use]
    pub fn filename(&self) -> Option<&Path> {
        self.filename.as_deref()
    }

    /// Sets (or clears) the remembered backing-file path.
    pub fn set_filename(&mut self, file: Option<PathBuf>) {
        self.filename = file;
    }

    /// Removes every entry and forgets the backing file, returning the store to
    /// its freshly-initialized state. Equivalent to `Curl_hsts_cleanup` followed
    /// by re-init; provided for handle reset.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.filename = None;
    }

    // -- flags (CURLOPT_HSTS_CTRL) ------------------------------------------

    /// Returns the raw `CURLHSTS_*` control flags.
    #[must_use]
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Replaces the `CURLHSTS_*` control flags (driven by `CURLOPT_HSTS_CTRL`).
    pub fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    /// Returns `true` if the HSTS cache is enabled ([`CURLHSTS_ENABLE`] set).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.flags & CURLHSTS_ENABLE != 0
    }

    /// Returns `true` if the backing file is marked read-only
    /// ([`CURLHSTS_READONLYFILE`] set), in which case [`save`](Self::save) skips
    /// writing it.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.flags & CURLHSTS_READONLYFILE != 0
    }
}

// ----------------------------------------------------------------------------
// Header parsing
// ----------------------------------------------------------------------------

/// Outcome of parsing a decimal number from the cursor, mirroring the relevant
/// `curlx_str_number` return states that `Curl_hsts_parse` distinguishes.
enum ParsedNum {
    /// A value within `0..=i64::MAX`.
    Value(i64),
    /// The digits overflowed `i64::MAX`; curl caps this to `CURL_OFF_T_MAX`.
    Overflow,
    /// No digit was present where one was required (`STRE_NO_NUM`).
    NoDigit,
}

/// A tiny, bounds-checked byte cursor used to walk a header value exactly the
/// way `Curl_hsts_parse` walks its `const char *p`.
///
/// [`peek`](Self::peek) returns `0` past the end of input, reproducing the C
/// code's reliance on the terminating NUL so the porting of the `do { … }
/// while(*p)` loop is faithful.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    /// True once the cursor has consumed all input (`*p == '\0'` in C).
    fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The current byte, or `0` at/after end of input (NUL emulation).
    fn peek(&self) -> u8 {
        if self.pos < self.buf.len() {
            self.buf[self.pos]
        } else {
            0
        }
    }

    /// Advances the cursor by `n` bytes, saturating at end of input.
    fn advance(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n).min(self.buf.len());
    }

    /// Skips spaces and tabs (`curlx_str_passblanks` / curl's `ISBLANK`).
    fn pass_blanks(&mut self) {
        while self.pos < self.buf.len() {
            let b = self.buf[self.pos];
            if b == b' ' || b == b'\t' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    /// If the next byte equals `byte`, consumes it and returns `true`; otherwise
    /// leaves the cursor untouched and returns `false` (`curlx_str_single`).
    fn eat(&mut self, byte: u8) -> bool {
        if self.pos < self.buf.len() && self.buf[self.pos] == byte {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Returns `true` if the bytes at the cursor case-insensitively match
    /// `needle` (ASCII folding, like `curl_strnequal`). Requires at least
    /// `needle.len()` bytes to remain — a short tail never matches, mirroring
    /// the C comparison stopping at the NUL.
    fn matches_ci(&self, needle: &[u8]) -> bool {
        match self.pos.checked_add(needle.len()) {
            Some(end) if end <= self.buf.len() => {
                self.buf[self.pos..end].eq_ignore_ascii_case(needle)
            }
            _ => false,
        }
    }

    /// Parses a run of ASCII decimal digits, advancing past **all** of them even
    /// on overflow (matching `curlx_str_number`, which consumes the whole run).
    fn parse_number(&mut self) -> ParsedNum {
        let start = self.pos;
        let mut value: i64 = 0;
        let mut overflow = false;
        while self.pos < self.buf.len() && self.buf[self.pos].is_ascii_digit() {
            let digit = i64::from(self.buf[self.pos] - b'0');
            if !overflow {
                match value.checked_mul(10).and_then(|v| v.checked_add(digit)) {
                    Some(v) => value = v,
                    None => overflow = true,
                }
            }
            self.pos += 1;
        }
        if self.pos == start {
            ParsedNum::NoDigit
        } else if overflow {
            ParsedNum::Overflow
        } else {
            ParsedNum::Value(value)
        }
    }

    /// Captures a run of bytes up to (but not including) the next space,
    /// mirroring `curlx_str_word` (which stops only at `' '`, not at a tab).
    ///
    /// Returns the captured slice, or `None` if it is empty or longer than
    /// `max` — the two failure modes (`STRE_SHORT`, `STRE_BIG`) curl folds into
    /// "skip this line". On success the cursor stops at the delimiting space (or
    /// end of input).
    fn parse_word(&mut self, max: usize) -> Option<&'a [u8]> {
        let start = self.pos;
        while self.pos < self.buf.len() && self.buf[self.pos] != b' ' {
            self.pos += 1;
        }
        let len = self.pos - start;
        if len == 0 || len > max {
            return None;
        }
        Some(&self.buf[start..self.pos])
    }

    /// Parses a double-quoted token, mirroring `curlx_str_quotedword`.
    ///
    /// The token must open with `"`; a backslash escapes the following byte
    /// (both the backslash and the escaped byte count toward `max`, exactly as
    /// curl counts raw consumed bytes); the token closes at the next unescaped
    /// `"`. Returns the unescaped contents, or `None` on a missing opening quote
    /// (`STRE_BEGQUOTE`), overflow (`STRE_BIG`), or a missing closing quote
    /// (`STRE_ENDQUOTE`). On success the cursor sits just past the closing `"`.
    fn parse_quotedword(&mut self, max: usize) -> Option<Vec<u8>> {
        if !self.eat(b'"') {
            return None;
        }
        let mut out = Vec::new();
        let mut consumed = 0usize; // raw bytes consumed inside the quotes
        loop {
            if self.at_end() {
                // Reached end of input without a closing quote.
                return None;
            }
            let b = self.peek();
            if b == b'"' {
                self.advance(1);
                return Some(out);
            }
            if b == b'\\' {
                self.advance(1);
                if self.at_end() {
                    return None;
                }
                consumed += 2;
                if consumed > max {
                    return None;
                }
                out.push(self.peek());
                self.advance(1);
            } else {
                consumed += 1;
                if consumed > max {
                    return None;
                }
                out.push(b);
                self.advance(1);
            }
        }
    }

    /// True if the cursor is at a newline byte (`\r` or `\n`) or at end of input.
    ///
    /// curl's `hsts_add` requires `curlx_str_newline` immediately after the
    /// quoted date; because the cache file is read line-by-line (with the
    /// terminator stripped here), end-of-input stands in for that newline.
    fn at_newline_or_end(&self) -> bool {
        if self.at_end() {
            return true;
        }
        let b = self.peek();
        b == b'\n' || b == b'\r'
    }
}

/// Returns the input with a single trailing `.` removed, if present.
///
/// Mirrors curl stripping one trailing dot from both stored and queried hosts
/// (`if(hlen && hostname[hlen - 1] == '.') --hlen;`).
fn strip_trailing_dot(host: &str) -> &str {
    match host.strip_suffix('.') {
        Some(stripped) => stripped,
        None => host,
    }
}

/// Returns `true` if `host` is a numeric IP literal (IPv4 or IPv6), which
/// RFC 6797 excludes from HSTS. Mirrors curl's `Curl_host_is_ipnum`, which calls
/// `inet_pton` for `AF_INET` and `AF_INET6`.
fn is_ip_literal(host: &str) -> bool {
    host.parse::<Ipv4Addr>().is_ok() || host.parse::<Ipv6Addr>().is_ok()
}

/// ASCII case-insensitive byte equality (parity with `curl_strnequal`).
fn bytes_eq_ci(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

impl HstsStore {
    /// Parses a `Strict-Transport-Security` header value for `host`, updating the
    /// store. `now` is the current Unix time (seconds, UTC).
    ///
    /// Mirrors `Curl_hsts_parse` exactly:
    ///
    /// * IP-literal hosts are ignored (RFC 6797), returning `Ok(())`.
    /// * `max-age=<seconds>` is **mandatory** and may appear once; its value may
    ///   be optionally double-quoted. An overflowing value is capped to
    ///   [`UNLIMITED_EXPIRY`]; a missing/invalid value is an error.
    /// * `includeSubDomains` is optional, case-insensitive, and may appear once.
    /// * Directive order is irrelevant; unknown directives are skipped up to the
    ///   next `;`.
    /// * `max-age=0` deletes the host's entry (exact match, no subdomain logic).
    /// * Otherwise the absolute expiry is `now + max-age` (saturating to
    ///   [`UNLIMITED_EXPIRY`] on overflow); an existing entry is updated in
    ///   place, otherwise a new one is appended.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] (curl's
    /// `CURLE_BAD_FUNCTION_ARGUMENT`) for a malformed header: a missing or
    /// duplicated `max-age`, a duplicated `includeSubDomains`, a missing `=`, an
    /// unterminated quote, or a non-numeric `max-age`.
    pub fn parse(&mut self, host: &str, header: &str, now: i64) -> Result<()> {
        // RFC 6797: "explicit IP address identification of all forms is
        // excluded." Ignore such hosts without error.
        if is_ip_literal(host) {
            return Ok(());
        }

        let mut cursor = Cursor::new(header.as_bytes());
        let mut expires: i64 = 0;
        let mut got_max_age = false;
        let mut got_include = false;
        let mut subdomains = false;

        // Faithful port of the C `do { … } while(*p)` directive loop.
        loop {
            cursor.pass_blanks();

            if cursor.matches_ci(b"max-age") {
                if got_max_age {
                    return Err(CurlError::BadFunctionArgument);
                }
                cursor.advance(7);
                cursor.pass_blanks();
                if !cursor.eat(b'=') {
                    return Err(CurlError::BadFunctionArgument);
                }
                cursor.pass_blanks();
                let quoted = cursor.eat(b'"');
                match cursor.parse_number() {
                    ParsedNum::Overflow => expires = UNLIMITED_EXPIRY,
                    ParsedNum::NoDigit => return Err(CurlError::BadFunctionArgument),
                    ParsedNum::Value(value) => expires = value,
                }
                if quoted && !cursor.eat(b'"') {
                    return Err(CurlError::BadFunctionArgument);
                }
                got_max_age = true;
            } else if cursor.matches_ci(b"includesubdomains") {
                if got_include {
                    return Err(CurlError::BadFunctionArgument);
                }
                subdomains = true;
                cursor.advance(17);
                got_include = true;
            } else {
                // Unknown directive: skip to the next ';' (or end of input).
                while !cursor.at_end() && cursor.peek() != b';' {
                    cursor.advance(1);
                }
            }

            cursor.pass_blanks();
            if cursor.peek() == b';' {
                cursor.advance(1);
            }
            if cursor.at_end() {
                break;
            }
        }

        if !got_max_age {
            // max-age is mandatory.
            return Err(CurlError::BadFunctionArgument);
        }

        if expires == 0 {
            // `max-age=0` removes the entry verbatim, with **no** subdomain
            // matching: curl calls `Curl_hsts(h, hostname, hlen, FALSE)` and
            // unlinks whatever exact entry it returns. That lookup also prunes
            // any expired entries it visits, so we reproduce it faithfully via
            // `prune_and_match(.., false)`.
            if let Some(index) = self.prune_and_match(host, now, false) {
                self.entries.remove(index);
            }
            return Ok(());
        }

        // Absolute expiry; saturate to the sentinel on overflow, exactly as
        // curl's `if(CURL_OFF_T_MAX - now < expires)` guard does. `checked_add`
        // returns `None` precisely when `now + expires` would exceed `i64::MAX`.
        let absolute = now.checked_add(expires).unwrap_or(UNLIMITED_EXPIRY);

        // Exact-match lookup (subdomain = FALSE), which also prunes expired
        // entries it passes — mirroring curl's second `Curl_hsts(.., FALSE)`.
        if let Some(index) = self.prune_and_match(host, now, false) {
            // Update the existing entry in place, preserving its list position.
            self.entries[index].expires = absolute;
            self.entries[index].include_subdomains = subdomains;
        } else {
            self.create(host, subdomains, absolute);
        }
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Matching and lookup
// ----------------------------------------------------------------------------

impl HstsStore {
    /// Appends a new entry, mirroring curl's `hsts_create`.
    ///
    /// A single trailing dot is stripped from `host`; if nothing remains the
    /// entry is **not** stored (curl returns `CURLE_OK` without inserting).
    fn create(&mut self, host: &str, include_subdomains: bool, expires: i64) {
        let stripped = strip_trailing_dot(host);
        if stripped.is_empty() {
            return;
        }
        self.entries.push(HstsEntry {
            host: stripped.to_string(),
            include_subdomains,
            expires,
        });
    }

    /// The faithful port of curl's `Curl_hsts`: it prunes expired entries as it
    /// visits them, finds the best `includeSubDomains` superdomain match (the
    /// one with the longest matching tail), and returns immediately on an exact
    /// host match — **without** visiting (or pruning) entries beyond it.
    ///
    /// `host` may carry a trailing dot (it is stripped here, as in curl). The
    /// returned index is valid against `self.entries` **after** pruning. An
    /// exact match takes precedence over any subdomain match.
    ///
    /// When `subdomain` is `false`, only exact matches are considered (this is
    /// how `parse` looks up the entry to update or delete).
    fn prune_and_match(&mut self, host: &str, now: i64, subdomain: bool) -> Option<usize> {
        // Bounds check on the *original* length, exactly as curl does before it
        // strips the trailing dot.
        let hlen_orig = host.len();
        if hlen_orig == 0 || hlen_orig > MAX_HSTS_HOSTLEN {
            return None;
        }
        let stripped = strip_trailing_dot(host);
        let hbytes = stripped.as_bytes();
        let hlen = hbytes.len();

        let mut retained: Vec<HstsEntry> = Vec::with_capacity(self.entries.len());
        let mut best: Option<usize> = None;
        let mut blen: usize = 0;
        let mut exact: Option<usize> = None;

        for entry in std::mem::take(&mut self.entries) {
            // Once curl finds an exact match it `return`s, so every later entry
            // is left untouched (neither matched nor pruned). Preserve them.
            if exact.is_some() {
                retained.push(entry);
                continue;
            }

            // Prune expired entries we actually visit (`sts->expires <= now`).
            if entry.expires <= now {
                continue;
            }

            let ntail = entry.host.len();

            // Longest-tail `includeSubDomains` superdomain match.
            if subdomain && entry.include_subdomains && ntail < hlen {
                let offs = hlen - ntail;
                if hbytes[offs - 1] == b'.'
                    && bytes_eq_ci(&hbytes[offs..], entry.host.as_bytes())
                    && ntail > blen
                {
                    best = Some(retained.len());
                    blen = ntail;
                }
            }

            // Exact match wins immediately.
            if hlen == ntail && bytes_eq_ci(hbytes, entry.host.as_bytes()) {
                exact = Some(retained.len());
            }

            retained.push(entry);
        }

        self.entries = retained;
        exact.or(best)
    }

    /// Removes every expired entry (`expires <= now`), unconditionally.
    ///
    /// This is a convenience for callers (and handle reset) that want to compact
    /// the store without performing a lookup. Note that curl never prunes
    /// wholesale like this — it prunes lazily during [`lookup`](Self::lookup) —
    /// so `parse`/`lookup` deliberately do **not** call this; they rely on the
    /// visit-time pruning inside [`prune_and_match`](Self::prune_and_match) to
    /// stay byte-compatible with curl's persisted output.
    pub fn prune_expired(&mut self, now: i64) {
        self.entries.retain(|entry| entry.expires > now);
    }

    /// Returns `true` if `host` is currently a known HSTS host, i.e. there is a
    /// non-expired entry that matches it exactly or (via `includeSubDomains`) as
    /// a superdomain.
    ///
    /// This is the read-only query the transfer/redirect layer consults before
    /// rewriting an `http://` URL to `https://` (and the default port `80` to
    /// `443`). It corresponds to curl's `Curl_hsts(.., subdomain = TRUE)` but,
    /// being `&self`, performs **no** pruning; expired entries are simply
    /// skipped, so the boolean answer is identical to curl's.
    #[must_use]
    pub fn is_known(&self, host: &str, now: i64) -> bool {
        let hlen_orig = host.len();
        if hlen_orig == 0 || hlen_orig > MAX_HSTS_HOSTLEN {
            return false;
        }
        let stripped = strip_trailing_dot(host);
        let hbytes = stripped.as_bytes();
        let hlen = hbytes.len();

        for entry in &self.entries {
            if entry.expires <= now {
                continue;
            }
            let ntail = entry.host.len();
            if entry.include_subdomains && ntail < hlen {
                let offs = hlen - ntail;
                if hbytes[offs - 1] == b'.' && bytes_eq_ci(&hbytes[offs..], entry.host.as_bytes()) {
                    return true;
                }
            }
            if hlen == ntail && bytes_eq_ci(hbytes, entry.host.as_bytes()) {
                return true;
            }
        }
        false
    }

    /// Looks up `host` with subdomain matching enabled, pruning expired entries
    /// as a side effect, and returns the matched entry (longest-tail superdomain
    /// match, or an exact match which takes precedence).
    ///
    /// This is the mutating counterpart to [`is_known`](Self::is_known) and the
    /// faithful equivalent of curl's `Curl_hsts(.., TRUE)`: callers that want
    /// curl's exact prune-on-lookup behavior (for example before persisting the
    /// cache) use this.
    pub fn lookup(&mut self, host: &str, now: i64) -> Option<&HstsEntry> {
        let index = self.prune_and_match(host, now, true)?;
        self.entries.get(index)
    }
}

// ----------------------------------------------------------------------------
// Date formatting and parsing
// ----------------------------------------------------------------------------

/// Formats a Unix timestamp (seconds, UTC) the way curl serializes an HSTS
/// expiry: `YYYYMMDD HH:MM:SS`, in UTC, with the year **not** zero-padded
/// (curl uses `%d` for the year and `%02d` for the other fields).
///
/// Returns `None` if the timestamp is outside the range chrono can represent as
/// a UTC calendar date (a degenerate input the caller maps to [`UNLIMITED`]).
///
/// Mirrors the `curl_msnprintf(..., "%d%02d%02d %02d:%02d:%02d", ...)` calls in
/// curl's `hsts_out` / `hsts_push`.
fn format_expiry(expires: i64) -> Option<String> {
    let dt: DateTime<Utc> = DateTime::<Utc>::from_timestamp(expires, 0)?;
    // curl uses `%d` for the year (no zero-padding) and `%02d` for the rest.
    // For every representable HSTS expiry the year is four digits, so this
    // matches curl's `hsts_out` byte-for-byte.
    Some(format!(
        "{}{:02}{:02} {:02}:{:02}:{:02}",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    ))
}

/// Parses a date token from a persisted HSTS cache line into a Unix timestamp
/// (seconds, UTC).
///
/// curl loads dates with its general-purpose `Curl_getdate_capped`, but every
/// date it (or the test suite) *writes* uses the canonical `YYYYMMDD HH:MM:SS`
/// UTC form produced by [`format_expiry`]. This parser accepts exactly that
/// canonical form, which is what round-trips through the regression suite's dump
/// comparisons. Whitespace around the token is tolerated.
///
/// Returns `None` if the token is not well-formed (curl's loader treats an
/// unparsable date as `0`, i.e. already-expired; callers map `None` to `0`).
fn parse_hsts_date(token: &str) -> Option<i64> {
    let token = token.trim();
    // Expected layout: 8-digit date, a single space, then HH:MM:SS.
    let (date_part, time_part) = token.split_once(' ')?;
    if date_part.len() != 8 || !date_part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let year: i32 = date_part[0..4].parse().ok()?;
    let month: u32 = date_part[4..6].parse().ok()?;
    let day: u32 = date_part[6..8].parse().ok()?;

    let mut time_iter = time_part.split(':');
    let hour: u32 = time_iter.next()?.parse().ok()?;
    let minute: u32 = time_iter.next()?.parse().ok()?;
    let second: u32 = time_iter.next()?.parse().ok()?;
    if time_iter.next().is_some() {
        // Trailing junk after seconds — reject.
        return None;
    }

    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    let datetime = date.and_hms_opt(hour, minute, second)?;
    Some(datetime.and_utc().timestamp())
}

// ----------------------------------------------------------------------------
// Persistence — loading
// ----------------------------------------------------------------------------

impl HstsStore {
    /// Adds (or merges) a single entry from a known host/expiry/subdomain
    /// triple, mirroring the dedup logic shared by curl's `hsts_add` and
    /// `hsts_pull` (the `CURLOPT_HSTSREADFUNCTION` path).
    ///
    /// * If no entry matches, a new one is created.
    /// * If an entry with the **same** host already exists, only the larger
    ///   expiry is kept (the subdomain flag is left unchanged, exactly as curl
    ///   does).
    /// * If only a superdomain `includeSubDomains` entry matches (a *different*
    ///   host), nothing is added — reproducing curl's quirk where such a line is
    ///   silently dropped.
    ///
    /// `now` drives the same visit-time pruning as a normal lookup.
    pub fn add_entry(&mut self, host: &str, include_subdomains: bool, expires: i64, now: i64) {
        if let Some(index) = self.prune_and_match(host, now, include_subdomains) {
            let stripped = strip_trailing_dot(host);
            if bytes_eq_ci(stripped.as_bytes(), self.entries[index].host.as_bytes()) {
                // Same hostname: keep the largest expiry.
                if expires > self.entries[index].expires {
                    self.entries[index].expires = expires;
                }
            }
            // Otherwise it was a subdomain match for a different host: drop it,
            // exactly as curl's `hsts_add` does.
        } else {
            self.create(host, include_subdomains, expires);
        }
    }

    /// Parses and adds a single persisted cache line, mirroring `hsts_add`.
    ///
    /// The grammar is `WORD SPACE QUOTEDWORD NEWLINE`, where `WORD` is the host
    /// (optionally prefixed with `.` to denote `includeSubDomains`) and
    /// `QUOTEDWORD` is either [`UNLIMITED`] or a `YYYYMMDD HH:MM:SS` UTC date.
    /// Any syntactically malformed line is silently ignored (curl returns
    /// `CURLE_OK` for per-line errors).
    fn add_line(&mut self, line: &str, now: i64) {
        // Strip a trailing CR so Windows-style `\r\n` files parse identically.
        let line = line.strip_suffix('\r').unwrap_or(line);

        let mut cursor = Cursor::new(line.as_bytes());
        cursor.pass_blanks();

        let host_bytes = match cursor.parse_word(MAX_HSTS_HOSTLEN) {
            Some(bytes) => bytes,
            None => return,
        };
        if !cursor.eat(b' ') {
            return;
        }
        let date_bytes = match cursor.parse_quotedword(MAX_HSTS_DATELEN) {
            Some(bytes) => bytes,
            None => return,
        };
        if !cursor.at_newline_or_end() {
            // Trailing junk after the quoted date — reject the whole line.
            return;
        }

        // The host token is guaranteed non-empty by `parse_word`. It is the only
        // place a non-UTF-8 host could enter; cache files are ASCII in practice,
        // and a non-UTF-8 host simply cannot match a (UTF-8) `String` entry, so
        // dropping it is both safe and behaviorally inert.
        let host_token = match std::str::from_utf8(host_bytes) {
            Ok(host) => host,
            Err(_) => return,
        };
        let date_token = match std::str::from_utf8(&date_bytes) {
            Ok(date) => date,
            Err(_) => return,
        };

        // A leading '.' marks an includeSubDomains entry; strip it before store.
        let (host, include_subdomains) = match host_token.strip_prefix('.') {
            Some(rest) => (rest, true),
            None => (host_token, false),
        };
        if host.is_empty() {
            return;
        }

        // "unlimited" → never expires; otherwise parse the canonical date.
        // curl's loader treats an unparsable date as 0 (already expired).
        let expires = if date_token == UNLIMITED {
            UNLIMITED_EXPIRY
        } else {
            parse_hsts_date(date_token).unwrap_or(0)
        };

        self.add_entry(host, include_subdomains, expires, now);
    }

    /// Loads cache entries from an in-memory string (one entry per line),
    /// applying the same per-line skipping rules as curl's `hsts_load`: lines
    /// that are blank (after leading whitespace) or begin with `#` are ignored.
    ///
    /// This is the engine behind [`load_file`](Self::load_file) and is also handy
    /// for tests and for feeding data obtained via the read callback.
    pub fn load_str(&mut self, data: &str, now: i64) {
        for raw in data.split('\n') {
            // Determine the first non-blank byte to apply the comment/blank skip
            // exactly as curl does after its own `curlx_str_passblanks`.
            let trimmed = raw.trim_start_matches([' ', '\t']);
            let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            self.add_line(raw, now);
        }
    }

    /// Loads the HSTS cache from `file`, mirroring `Curl_hsts_loadfile`.
    ///
    /// The path is remembered (so a later [`save`](Self::save) with no explicit
    /// path reuses it) **before** the file is read, exactly as curl stores
    /// `h->filename` first. A missing or unreadable file is **not** an error
    /// (curl ignores it and proceeds with an empty cache); only the path is
    /// retained. Individual malformed lines are skipped.
    ///
    /// # Errors
    ///
    /// Returns an error only for a "serious" I/O failure while reading an
    /// existing, openable file (mapped from [`std::io::Error`] via
    /// [`CurlError`]), matching curl's contract that line-level problems are
    /// ignored but catastrophic ones surface.
    pub fn load_file(&mut self, file: impl AsRef<Path>, now: i64) -> Result<()> {
        let path = file.as_ref();

        // Remember the filename first, surviving an empty/absent file.
        self.filename = Some(path.to_path_buf());

        match std::fs::read(path) {
            Ok(bytes) => {
                // Cache files are ASCII/UTF-8; tolerate invalid bytes by parsing
                // losslessly enough to skip bad lines rather than failing.
                let text = String::from_utf8_lossy(&bytes);
                self.load_str(&text, now);
                Ok(())
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // Missing file: not an error, just an empty cache (curl's
                // `curlx_fopen` returning NULL is silently tolerated).
                Ok(())
            }
            Err(err) => Err(CurlError::from(err)),
        }
    }
}

// ----------------------------------------------------------------------------
// Persistence — saving
// ----------------------------------------------------------------------------

impl HstsStore {
    /// Writes the full cache (the two-line banner followed by one line per
    /// entry, in insertion order) to `writer`, byte-for-byte as curl does.
    ///
    /// Each entry is `[.]host "EXPIRY"\n`, where the leading `.` is present iff
    /// the entry is `includeSubDomains` and `EXPIRY` is either [`UNLIMITED`] or a
    /// UTC `YYYYMMDD HH:MM:SS` timestamp. This is the same output `Curl_hsts_save`
    /// produces and that the regression suite compares.
    ///
    /// # Errors
    ///
    /// Propagates any [`std::io::Error`] from `writer`, mapped to [`CurlError`].
    pub fn save_to_writer<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(HSTS_FILE_HEADER.as_bytes())?;
        for entry in &self.entries {
            let prefix = if entry.include_subdomains { "." } else { "" };
            writeln!(
                writer,
                "{}{} \"{}\"",
                prefix,
                entry.host,
                entry.expiry_string()
            )?;
        }
        Ok(())
    }

    /// Returns the full serialized cache as a `String` (banner + entry lines).
    ///
    /// Convenience over [`save_to_writer`](Self::save_to_writer) for the
    /// `CURLOPT_HSTSWRITEFUNCTION` path and for tests. Writing into a `Vec<u8>`
    /// is infallible, so this never fails.
    #[must_use]
    pub fn dump_string(&self) -> String {
        let mut buf: Vec<u8> = Vec::new();
        // Writing to a Vec cannot fail; the Result is purely formal here.
        let _ = self.save_to_writer(&mut buf);
        // The content is ASCII by construction (hosts that round-trip from the
        // store plus numeric dates), so this conversion never allocates a
        // replacement character in practice.
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Persists the cache to disk, mirroring `Curl_hsts_save`.
    ///
    /// * If `file` is `None`, the remembered [`filename`](Self::filename) is used.
    /// * If the store is marked read-only ([`CURLHSTS_READONLYFILE`]), or there is
    ///   no destination path, saving is **skipped** and `Ok(())` is returned.
    /// * The write is atomic: the data is written to a unique temporary file in
    ///   the same directory, then renamed over the destination. On any failure
    ///   the temporary file is removed.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::WriteError`] (curl's `CURLE_WRITE_ERROR`) if the
    /// temporary file cannot be created, written, or renamed into place.
    pub fn save(&self, file: Option<&Path>) -> Result<()> {
        // Choose the destination: explicit argument, else the remembered path.
        let dest: Option<&Path> = file.or(self.filename.as_deref());

        let dest = match dest {
            Some(path) if !path.as_os_str().is_empty() => path,
            // Read-only or no destination: nothing to write (callback handling
            // lives at the FFI/easy layer, matching curl's `skipsave`).
            _ => return Ok(()),
        };

        if self.is_read_only() {
            return Ok(());
        }

        self.write_atomic(dest)
    }

    /// Writes the serialized cache to `dest` atomically (temp file + rename).
    fn write_atomic(&self, dest: &Path) -> Result<()> {
        // Build a unique sibling temp path: same directory so the rename stays
        // on one filesystem (cross-device renames fail). The process id plus a
        // monotonic counter keeps concurrent saves from colliding.
        let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
        let file_name = dest
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| String::from("hsts"));
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!(".{}.{}.{}.tmp", file_name, std::process::id(), seq);
        let tmp_path: PathBuf = match parent {
            Some(dir) => dir.join(&tmp_name),
            None => PathBuf::from(&tmp_name),
        };

        // Write the serialized cache to the temp file, then atomically rename it
        // over the destination. Any failure maps to CURLE_WRITE_ERROR (curl's
        // `Curl_hsts_save` contract) and removes the temp file best-effort.
        if self.write_temp_file(&tmp_path).is_err() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(CurlError::WriteError);
        }

        if std::fs::rename(&tmp_path, dest).is_err() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(CurlError::WriteError);
        }

        Ok(())
    }

    /// Creates `tmp_path`, writes the full serialized cache into it, and flushes.
    /// All I/O failures collapse to [`CurlError::WriteError`], matching curl's
    /// uniform save-error reporting.
    fn write_temp_file(&self, tmp_path: &Path) -> Result<()> {
        let mut file = std::fs::File::create(tmp_path).map_err(|_| CurlError::WriteError)?;
        self.save_to_writer(&mut file)
            .map_err(|_| CurlError::WriteError)?;
        file.flush().map_err(|_| CurlError::WriteError)?;
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixed clock used by the upstream `unit1660` test:
    /// `CURL_TIME=1548369261` == 2019-01-24 22:34:21 UTC.
    const CURL_TIME: i64 = 1_548_369_261;

    // -- date helpers --------------------------------------------------------

    #[test]
    fn format_expiry_matches_curl() {
        assert_eq!(
            format_expiry(CURL_TIME).as_deref(),
            Some("20190124 22:34:21")
        );
        assert_eq!(
            format_expiry(1_633_063_661).as_deref(),
            Some("20211001 04:47:41")
        );
        assert_eq!(
            format_expiry(1_569_905_261).as_deref(),
            Some("20191001 04:47:41")
        );
        assert_eq!(
            format_expiry(1_579_905_261).as_deref(),
            Some("20200124 22:34:21")
        );
    }

    #[test]
    fn parse_date_matches_curl() {
        assert_eq!(parse_hsts_date("20190124 22:34:21"), Some(CURL_TIME));
        assert_eq!(parse_hsts_date("20211001 04:47:41"), Some(1_633_063_661));
        assert_eq!(parse_hsts_date("20161001 04:47:41"), Some(1_475_297_261));
        // round-trip of the sentinel-adjacent values
        for ts in [CURL_TIME, 1_569_905_261, 1_579_905_261, 1_548_400_797] {
            let s = format_expiry(ts).unwrap();
            assert_eq!(parse_hsts_date(&s), Some(ts), "round-trip failed for {ts}");
        }
    }

    #[test]
    fn parse_date_rejects_malformed() {
        assert_eq!(parse_hsts_date(""), None);
        assert_eq!(parse_hsts_date("unlimited"), None); // handled separately by caller
        assert_eq!(parse_hsts_date("2019012 22:34:21"), None); // 7-digit date
        assert_eq!(parse_hsts_date("20190124 22:34"), None); // missing seconds
        assert_eq!(parse_hsts_date("20191301 00:00:00"), None); // month 13
        assert_eq!(parse_hsts_date("abcdefgh 00:00:00"), None);
    }

    // -- entry --------------------------------------------------------------

    #[test]
    fn entry_strips_trailing_dot() {
        let e = HstsEntry::new("example.com.", false, 100);
        assert_eq!(e.host, "example.com");
    }

    #[test]
    fn entry_expiry_string() {
        assert_eq!(
            HstsEntry::new("h", false, UNLIMITED_EXPIRY).expiry_string(),
            "unlimited"
        );
        assert_eq!(
            HstsEntry::new("h", false, CURL_TIME).expiry_string(),
            "20190124 22:34:21"
        );
    }

    // -- parse: basics -------------------------------------------------------

    #[test]
    fn parse_basic_max_age_then_known() {
        let mut h = HstsStore::new();
        h.parse("example.com", "max-age=31536000", CURL_TIME)
            .unwrap();
        assert!(h.is_known("example.com", CURL_TIME));
        assert_eq!(h.count(), 1);
        let e = &h.entries()[0];
        assert_eq!(e.host, "example.com");
        assert!(!e.include_subdomains);
        assert_eq!(e.expires, CURL_TIME + 31_536_000);
    }

    #[test]
    fn parse_quoted_and_unquoted_equivalent() {
        let mut a = HstsStore::new();
        let mut b = HstsStore::new();
        a.parse("h.example", "max-age=\"100\"", CURL_TIME).unwrap();
        b.parse("h.example", "max-age=100", CURL_TIME).unwrap();
        assert_eq!(a.entries()[0].expires, b.entries()[0].expires);
    }

    #[test]
    fn parse_include_subdomains_case_insensitive_order_independent() {
        let mut h = HstsStore::new();
        h.parse("example.com", "INCLUDESUBDOMAINS; max-age=100", CURL_TIME)
            .unwrap();
        assert!(h.entries()[0].include_subdomains);
        // subdomain is covered, sibling is not
        assert!(h.is_known("api.example.com", CURL_TIME));
        assert!(h.is_known("example.com", CURL_TIME));
        assert!(!h.is_known("notexample.com", CURL_TIME));
    }

    #[test]
    fn parse_max_age_zero_deletes() {
        let mut h = HstsStore::new();
        h.parse("example.com", "max-age=100", CURL_TIME).unwrap();
        assert_eq!(h.count(), 1);
        h.parse("example.com", "max-age=0", CURL_TIME).unwrap();
        assert_eq!(h.count(), 0);
        assert!(!h.is_known("example.com", CURL_TIME));
    }

    #[test]
    fn parse_overflow_caps_to_unlimited() {
        let mut h = HstsStore::new();
        // A max-age that overflows i64 is capped; absolute expiry saturates.
        h.parse("example.com", "max-age=99999999999999999999999", CURL_TIME)
            .unwrap();
        assert_eq!(h.entries()[0].expires, UNLIMITED_EXPIRY);
    }

    #[test]
    fn parse_errors_match_curl() {
        let mut h = HstsStore::new();
        // From unit1660: each of these is CURLE_BAD_FUNCTION_ARGUMENT (43).
        assert_eq!(
            h.parse("x", "max=\"31536\";", CURL_TIME),
            Err(CurlError::BadFunctionArgument)
        );
        assert_eq!(
            h.parse("x", "max-age=\"31536", CURL_TIME),
            Err(CurlError::BadFunctionArgument)
        );
        assert_eq!(
            h.parse("x", "includeSubDomains; ", CURL_TIME),
            Err(CurlError::BadFunctionArgument)
        );
        assert_eq!(
            h.parse(
                "x",
                "max-age=\"21536000\"; includeSubDomains; max-age=\"3\";",
                CURL_TIME
            ),
            Err(CurlError::BadFunctionArgument)
        );
        assert_eq!(
            h.parse(
                "x",
                "max-age=\"21536000\"; includeSubDomains; includeSubDomains;",
                CURL_TIME
            ),
            Err(CurlError::BadFunctionArgument)
        );
        // The error code is exactly 43.
        assert_eq!(CurlError::BadFunctionArgument.code(), 43);
    }

    #[test]
    fn parse_trailing_quote_unquoted_is_ok() {
        // unit1660 input 10: `max-age=31536"` is OK (unquoted; trailing quote
        // is consumed by the unknown-directive skip).
        let mut h = HstsStore::new();
        h.parse("this.example", "max-age=31536\"", CURL_TIME)
            .unwrap();
        assert_eq!(h.entries()[0].expires, CURL_TIME + 31536);
    }

    #[test]
    fn parse_unknown_directive_ignored() {
        let mut h = HstsStore::new();
        h.parse(
            "3.example.com",
            "max-age=\"21536000\"; include; includeSubDomains;",
            CURL_TIME,
        )
        .unwrap();
        assert!(h.entries()[0].include_subdomains);
        assert_eq!(h.entries()[0].expires, CURL_TIME + 21_536_000);
    }

    #[test]
    fn parse_ignores_ip_literals() {
        let mut h = HstsStore::new();
        h.parse("192.168.0.1", "max-age=100", CURL_TIME).unwrap();
        h.parse("::1", "max-age=100", CURL_TIME).unwrap();
        h.parse("2001:db8::1", "max-age=100", CURL_TIME).unwrap();
        assert_eq!(h.count(), 0, "IP-literal hosts must not be stored");
    }

    #[test]
    fn parse_update_keeps_position_and_fields() {
        let mut h = HstsStore::new();
        h.parse("a.example", "max-age=100", CURL_TIME).unwrap();
        h.parse("b.example", "max-age=100", CURL_TIME).unwrap();
        // update a.example
        h.parse("a.example", "max-age=200; includeSubDomains", CURL_TIME)
            .unwrap();
        assert_eq!(h.count(), 2);
        assert_eq!(h.entries()[0].host, "a.example"); // position preserved
        assert_eq!(h.entries()[0].expires, CURL_TIME + 200);
        assert!(h.entries()[0].include_subdomains);
    }

    // -- matching ------------------------------------------------------------

    #[test]
    fn subdomain_matching_rules() {
        let mut h = HstsStore::new();
        h.parse(
            "example.com",
            "max-age=100000; includeSubDomains",
            CURL_TIME,
        )
        .unwrap();
        // a real subdomain matches
        assert!(h.is_known("foo.example.com", CURL_TIME));
        assert!(h.is_known("a.b.example.com", CURL_TIME));
        // a non-dot-boundary near-match does NOT
        assert!(!h.is_known("fooexample.com", CURL_TIME));
        assert!(!h.is_known("foo.xample.com", CURL_TIME));
        // exact still matches
        assert!(h.is_known("example.com", CURL_TIME));
    }

    #[test]
    fn no_subdomain_match_without_flag() {
        let mut h = HstsStore::new();
        h.parse("example.com", "max-age=100000", CURL_TIME).unwrap();
        assert!(h.is_known("example.com", CURL_TIME));
        assert!(!h.is_known("foo.example.com", CURL_TIME));
    }

    #[test]
    fn trailing_dot_is_normalized_in_query() {
        let mut h = HstsStore::new();
        h.parse("example.com", "max-age=100000", CURL_TIME).unwrap();
        assert!(h.is_known("example.com.", CURL_TIME));
    }

    #[test]
    fn case_insensitive_host_matching() {
        let mut h = HstsStore::new();
        h.parse("Example.COM", "max-age=100000", CURL_TIME).unwrap();
        assert!(h.is_known("example.com", CURL_TIME));
        assert!(h.is_known("EXAMPLE.com", CURL_TIME));
    }

    #[test]
    fn oversized_host_never_matches() {
        let mut h = HstsStore::new();
        h.parse("example.com", "max-age=100000", CURL_TIME).unwrap();
        let huge = "a".repeat(MAX_HSTS_HOSTLEN + 1);
        assert!(!h.is_known(&huge, CURL_TIME));
    }

    // -- expiry/pruning ------------------------------------------------------

    #[test]
    fn expired_entries_not_known() {
        let mut h = HstsStore::new();
        h.parse("example.com", "max-age=7", CURL_TIME).unwrap();
        let expiry = CURL_TIME + 7;
        assert!(h.is_known("example.com", expiry - 1));
        // expires <= now means expired (curl's boundary)
        assert!(!h.is_known("example.com", expiry));
        assert!(!h.is_known("example.com", expiry + 1));
    }

    #[test]
    fn lookup_prunes_expired() {
        let mut h = HstsStore::new();
        h.parse("a.example", "max-age=7", CURL_TIME).unwrap();
        h.parse("b.example", "max-age=100000", CURL_TIME).unwrap();
        assert_eq!(h.count(), 2);
        // a lookup at/after a.example's expiry prunes it
        let _ = h.lookup("b.example", CURL_TIME + 7);
        assert_eq!(h.count(), 1);
        assert_eq!(h.entries()[0].host, "b.example");
    }

    #[test]
    fn prune_expired_compacts() {
        let mut h = HstsStore::new();
        h.parse("a.example", "max-age=7", CURL_TIME).unwrap();
        h.parse("b.example", "max-age=100000", CURL_TIME).unwrap();
        h.prune_expired(CURL_TIME + 7);
        assert_eq!(h.count(), 1);
        assert_eq!(h.entries()[0].host, "b.example");
    }

    // -- persistence ---------------------------------------------------------

    const UNIT1660_INPUT: &str = "\
# Your HSTS cache. https://curl.se/docs/hsts.html
# This file was generated by libcurl! Edit at your own risk.
.readfrom.example \"20211001 04:47:41\"
.old.example \"20161001 04:47:41\"
.new.example \"unlimited\"
";

    #[test]
    fn load_str_parses_entries_and_flags() {
        let mut h = HstsStore::new();
        // Load far in the past so nothing is pruned during load.
        h.load_str(UNIT1660_INPUT, 0);
        assert_eq!(h.count(), 3);
        assert_eq!(h.entries()[0].host, "readfrom.example");
        assert!(h.entries()[0].include_subdomains);
        assert_eq!(h.entries()[0].expires, 1_633_063_661);
        assert_eq!(h.entries()[1].host, "old.example");
        assert_eq!(h.entries()[2].host, "new.example");
        assert_eq!(h.entries()[2].expires, UNLIMITED_EXPIRY);
    }

    #[test]
    fn load_dedup_keeps_larger_expiry() {
        let mut h = HstsStore::new();
        let data = "\
example.com \"20190124 22:34:21\"
example.com \"20200124 22:34:21\"
example.com \"20191001 04:47:41\"
";
        h.load_str(data, 0);
        assert_eq!(h.count(), 1);
        // largest of the three expiries
        assert_eq!(h.entries()[0].expires, 1_579_905_261);
    }

    #[test]
    fn load_skips_comments_and_blanks() {
        let mut h = HstsStore::new();
        let data = "# comment\n\n   \nexample.com \"unlimited\"\n";
        h.load_str(data, 0);
        assert_eq!(h.count(), 1);
        assert_eq!(h.entries()[0].host, "example.com");
    }

    #[test]
    fn load_skips_malformed_lines() {
        let mut h = HstsStore::new();
        // missing quote, missing date, trailing junk → all skipped
        let data =
            "bad.example noquote\ngood.example \"unlimited\"\nbad2.example \"unlimited\" junk\n";
        h.load_str(data, 0);
        assert_eq!(h.count(), 1);
        assert_eq!(h.entries()[0].host, "good.example");
    }

    #[test]
    fn save_format_is_byte_exact() {
        let mut h = HstsStore::new();
        h.add_entry("new.example", true, UNLIMITED_EXPIRY, 0);
        h.add_entry("example.com", true, 1_569_905_261, 0);
        h.add_entry("example.org", false, 1_579_905_261, 0);
        let expected = "\
# Your HSTS cache. https://curl.se/docs/hsts.html
# This file was generated by libcurl! Edit at your own risk.
.new.example \"unlimited\"
.example.com \"20191001 04:47:41\"
example.org \"20200124 22:34:21\"
";
        assert_eq!(h.dump_string(), expected);
    }

    #[test]
    fn save_and_load_round_trip_via_file() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "blitzy_hsts_rt_{}_{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hsts.txt");

        let mut h = HstsStore::new();
        h.add_entry("new.example", true, UNLIMITED_EXPIRY, 0);
        h.add_entry("example.com", true, 1_569_905_261, 0);
        h.add_entry("example.org", false, 1_579_905_261, 0);
        h.save(Some(&path)).unwrap();

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk, h.dump_string());

        let mut loaded = HstsStore::new();
        loaded.load_file(&path, 0).unwrap();
        assert_eq!(loaded.count(), 3);
        assert_eq!(loaded.dump_string(), h.dump_string());

        // cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn save_skips_when_read_only() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "blitzy_hsts_ro_{}_{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hsts.txt");

        let mut h = HstsStore::new();
        h.set_flags(CURLHSTS_ENABLE | CURLHSTS_READONLYFILE);
        h.add_entry("example.com", false, UNLIMITED_EXPIRY, 0);
        h.save(Some(&path)).unwrap();
        assert!(!path.exists(), "read-only save must not write a file");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_file_is_ok_and_remembers_path() {
        let mut h = HstsStore::new();
        let path = std::env::temp_dir().join(format!(
            "blitzy_hsts_missing_{}_{}.txt",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        // ensure absent
        let _ = std::fs::remove_file(&path);
        h.load_file(&path, CURL_TIME).unwrap();
        assert_eq!(h.count(), 0);
        assert_eq!(h.filename(), Some(path.as_path()));
    }

    // -- the gold parity vector: full unit1660 reproduction ------------------

    /// Reproduces the exact stdout (and final saved file) of upstream
    /// `tests/unit/unit1660.c` + `tests/data/test1660`, the canonical HSTS
    /// behavioral oracle. Any divergence in parsing, matching, expiry, pruning,
    /// or serialization fails this test.
    #[test]
    fn unit1660_full_reproduction() {
        struct Op {
            host: &'static str,
            chost: Option<&'static str>,
            hdr: Option<&'static str>,
            result_ok: bool,
        }
        // The header table from unit1660.c (result_ok=false means the parse must
        // return CURLE_BAD_FUNCTION_ARGUMENT).
        let ops = [
            Op {
                host: "-",
                chost: Some("readfrom.example"),
                hdr: None,
                result_ok: true,
            },
            Op {
                host: "-",
                chost: Some("old.example"),
                hdr: None,
                result_ok: true,
            },
            Op {
                host: "readfrom.example",
                chost: None,
                hdr: Some("max-age=\"0\""),
                result_ok: true,
            },
            Op {
                host: "example.com",
                chost: None,
                hdr: Some("max-age=\"31536000\"\r\n"),
                result_ok: true,
            },
            Op {
                host: "example.com",
                chost: None,
                hdr: Some("max-age=\"21536000\"\r\n"),
                result_ok: true,
            },
            Op {
                host: "example.com",
                chost: None,
                hdr: Some("max-age=\"21536000\"; \r\n"),
                result_ok: true,
            },
            Op {
                host: "example.com",
                chost: None,
                hdr: Some("max-age=\"21536000\"; includeSubDomains\r\n"),
                result_ok: true,
            },
            Op {
                host: "example.org",
                chost: None,
                hdr: Some("max-age=\"31536000\"\r\n"),
                result_ok: true,
            },
            Op {
                host: "this.example",
                chost: None,
                hdr: Some("max=\"31536\";"),
                result_ok: false,
            },
            Op {
                host: "this.example",
                chost: None,
                hdr: Some("max-age=\"31536"),
                result_ok: false,
            },
            Op {
                host: "this.example",
                chost: None,
                hdr: Some("max-age=31536\""),
                result_ok: true,
            },
            Op {
                host: "this.example",
                chost: None,
                hdr: Some("max-age=0"),
                result_ok: true,
            },
            Op {
                host: "another.example",
                chost: None,
                hdr: Some("includeSubDomains; "),
                result_ok: false,
            },
            Op {
                host: "example.com",
                chost: None,
                hdr: Some("max-age=\"21536000\"; includeSubDomains; max-age=\"3\";"),
                result_ok: false,
            },
            Op {
                host: "2.example.com",
                chost: None,
                hdr: Some("max-age=\"21536000\"; includeSubDomains; includeSubDomains;"),
                result_ok: false,
            },
            Op {
                host: "3.example.com",
                chost: None,
                hdr: Some("max-age=\"21536000\"; include; includeSubDomains;"),
                result_ok: true,
            },
            Op {
                host: "3.example.com",
                chost: None,
                hdr: Some("max-age=\"0\"; includeSubDomains;"),
                result_ok: true,
            },
            Op {
                host: "-",
                chost: Some("foo.example.com"),
                hdr: None,
                result_ok: true,
            },
            Op {
                host: "-",
                chost: Some("foo.xample.com"),
                hdr: None,
                result_ok: true,
            },
            Op {
                host: "example.net",
                chost: Some("forexample.net"),
                hdr: Some("max-age=\"31536000\"\r\n"),
                result_ok: true,
            },
            Op {
                host: "example.net",
                chost: Some("forexample.net"),
                hdr: Some("max-age=\"31536000\"; includeSubDomains\r\n"),
                result_ok: true,
            },
            Op {
                host: "example.net",
                chost: None,
                hdr: Some("max-age=\"0\"; includeSubDomains\r\n"),
                result_ok: true,
            },
            Op {
                host: "expire.example",
                chost: None,
                hdr: Some("max-age=\"7\"\r\n"),
                result_ok: true,
            },
        ];

        fn showsts(out: &mut Vec<String>, store: &mut HstsStore, chost: &str, now: i64) {
            match store.lookup(chost, now) {
                None => out.push(format!("'{chost}' is not HSTS")),
                Some(e) => out.push(format!(
                    "{} [{}]: {}{}",
                    chost,
                    e.host,
                    e.expires,
                    if e.include_subdomains {
                        " includeSubDomains"
                    } else {
                        ""
                    }
                )),
            }
        }

        let mut store = HstsStore::new();
        store.load_str(UNIT1660_INPUT, CURL_TIME);

        let mut out: Vec<String> = Vec::new();
        for (i, op) in ops.iter().enumerate() {
            if let Some(hdr) = op.hdr {
                let result = store.parse(op.host, hdr, CURL_TIME);
                if op.result_ok {
                    assert!(result.is_ok(), "op {i} ({hdr}) expected OK, got {result:?}");
                } else {
                    let err = result.expect_err("expected parse error");
                    out.push(format!("Input {i}: error {}", err.code()));
                    continue;
                }
            }
            let chost = op.chost.unwrap_or(op.host);
            showsts(&mut out, &mut store, chost, CURL_TIME);
        }

        out.push(format!("Number of entries: {}", store.count()));

        // Expiry verification loop: chost "expire.example" lives for 7 seconds.
        let chost = "expire.example";
        for i in 0..10 {
            let now = CURL_TIME + i; // deltatime increments after each lookup
            showsts(&mut out, &mut store, chost, now);
        }

        let expected_stdout = "\
readfrom.example [readfrom.example]: 1633063661 includeSubDomains
'old.example' is not HSTS
'readfrom.example' is not HSTS
example.com [example.com]: 1579905261
example.com [example.com]: 1569905261
example.com [example.com]: 1569905261
example.com [example.com]: 1569905261 includeSubDomains
example.org [example.org]: 1579905261
Input 8: error 43
Input 9: error 43
this.example [this.example]: 1548400797
'this.example' is not HSTS
Input 12: error 43
Input 13: error 43
Input 14: error 43
3.example.com [3.example.com]: 1569905261 includeSubDomains
3.example.com [example.com]: 1569905261 includeSubDomains
foo.example.com [example.com]: 1569905261 includeSubDomains
'foo.xample.com' is not HSTS
'forexample.net' is not HSTS
'forexample.net' is not HSTS
'example.net' is not HSTS
expire.example [expire.example]: 1548369268
Number of entries: 4
expire.example [expire.example]: 1548369268
expire.example [expire.example]: 1548369268
expire.example [expire.example]: 1548369268
expire.example [expire.example]: 1548369268
expire.example [expire.example]: 1548369268
expire.example [expire.example]: 1548369268
expire.example [expire.example]: 1548369268
'expire.example' is not HSTS
'expire.example' is not HSTS
'expire.example' is not HSTS";

        assert_eq!(out.join("\n"), expected_stdout);

        // The final saved cache must match test1660's expected dump exactly.
        let expected_save = "\
# Your HSTS cache. https://curl.se/docs/hsts.html
# This file was generated by libcurl! Edit at your own risk.
.new.example \"unlimited\"
.example.com \"20191001 04:47:41\"
example.org \"20200124 22:34:21\"
";
        assert_eq!(store.dump_string(), expected_save);
    }
}
