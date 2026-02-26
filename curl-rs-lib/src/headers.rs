//! HTTP header storage, iteration, and the `curl_easy_header` API.
//!
//! This module is a Rust rewrite of `lib/headers.c` and `lib/dynhds.c` from
//! the curl C codebase. It provides:
//!
//! - [`Headers`]: Response header storage and lookup (maps to `Curl_header_store`
//!   linked list and the `curl_easy_header`/`curl_easy_nextheader` public API).
//! - [`DynHeaders`]: Dynamic header building for outgoing requests (maps to
//!   `struct dynhds` and the `Curl_dynhds_*` family of functions).
//! - [`Header`]: User-facing header view returned by lookup operations.
//! - [`HeaderOrigin`]: Bitflag-style type for header origin classification.
//! - [`CurlHcode`]: Error codes for the header lookup API.
//! - [`DynHeaderEntry`]: Individual entry in a [`DynHeaders`] collection.
//!
//! # Origin Constants
//!
//! The origin constants match their C counterparts exactly for FFI compatibility:
//!
//! | Rust Constant    | C Constant       | Value    |
//! |------------------|------------------|----------|
//! | [`CURLH_HEADER`] | `CURLH_HEADER`   | `1 << 0` |
//! | [`CURLH_TRAILER`]| `CURLH_TRAILER`  | `1 << 1` |
//! | [`CURLH_CONNECT`]| `CURLH_CONNECT`  | `1 << 2` |
//! | [`CURLH_1XX`]    | `CURLH_1XX`      | `1 << 3` |
//! | [`CURLH_PSEUDO`] | `CURLH_PSEUDO`   | `1 << 4` |

use crate::error::{CurlError, CurlResult};

// ---------------------------------------------------------------------------
// Origin bit constants — MUST match C `CURLH_*` defines in include/curl/header.h
// ---------------------------------------------------------------------------

/// Plain server header origin (`CURLH_HEADER = 1 << 0`).
pub const CURLH_HEADER: u32 = 1 << 0;

/// Trailer header origin (`CURLH_TRAILER = 1 << 1`).
pub const CURLH_TRAILER: u32 = 1 << 1;

/// CONNECT response header origin (`CURLH_CONNECT = 1 << 2`).
pub const CURLH_CONNECT: u32 = 1 << 2;

/// 1xx intermediate response header origin (`CURLH_1XX = 1 << 3`).
pub const CURLH_1XX: u32 = 1 << 3;

/// HTTP/2 or HTTP/3 pseudo-header origin (`CURLH_PSEUDO = 1 << 4`).
pub const CURLH_PSEUDO: u32 = 1 << 4;

/// Bitmask of all valid origin bits (internal).
const CURLH_ALL: u32 = CURLH_HEADER | CURLH_TRAILER | CURLH_CONNECT | CURLH_1XX | CURLH_PSEUDO;

/// Maximum number of response headers stored per easy handle.
/// Matches the C `MAX_HTTP_RESP_HEADER_COUNT` limit in `lib/headers.c`.
const MAX_HTTP_RESP_HEADER_COUNT: usize = 10_000;

// ---------------------------------------------------------------------------
// HeaderOrigin — bitflag-style wrapper
// ---------------------------------------------------------------------------

/// Bitflag-style type identifying the origin of an HTTP header.
///
/// Values match the C `CURLH_*` constants exactly for FFI compatibility.
/// Multiple origins can be combined for filtering (e.g.,
/// `HeaderOrigin::HEADER | HeaderOrigin::TRAILER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeaderOrigin(u32);

impl HeaderOrigin {
    /// Plain server header (value: `1 << 0`).
    pub const HEADER: Self = Self(CURLH_HEADER);

    /// Trailer header (value: `1 << 1`).
    pub const TRAILER: Self = Self(CURLH_TRAILER);

    /// CONNECT response header (value: `1 << 2`).
    pub const CONNECT: Self = Self(CURLH_CONNECT);

    /// 1xx intermediate response header (value: `1 << 3`).
    pub const INTERIM_1XX: Self = Self(CURLH_1XX);

    /// HTTP/2 or HTTP/3 pseudo-header (value: `1 << 4`).
    pub const PSEUDO: Self = Self(CURLH_PSEUDO);

    /// Returns the raw `u32` representation of these origin bits.
    #[inline]
    pub fn as_u32(self) -> u32 {
        self.0
    }

    /// Attempts to construct a [`HeaderOrigin`] from a raw `u32` bitmask.
    ///
    /// Returns `None` if `bits` is zero or contains bits outside the valid
    /// `CURLH_*` range.
    #[inline]
    pub fn from_bits(bits: u32) -> Option<Self> {
        if bits == 0 || (bits & !CURLH_ALL) != 0 {
            None
        } else {
            Some(Self(bits))
        }
    }

    /// Returns `true` if `self` contains all bits present in `other`.
    ///
    /// Returns `false` when `other` has no bits set.
    #[inline]
    pub fn contains(self, other: Self) -> bool {
        other.0 != 0 && (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for HeaderOrigin {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for HeaderOrigin {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for HeaderOrigin {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for HeaderOrigin {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

// ---------------------------------------------------------------------------
// CurlHcode — header API result code
// ---------------------------------------------------------------------------

/// Error codes returned by the header lookup API.
///
/// Maps 1:1 to the C `CURLHcode` enumeration defined in
/// `include/curl/header.h`. Integer discriminants match the C values exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CurlHcode {
    /// Success (`CURLHE_OK = 0`).
    Ok = 0,
    /// Header exists but not at the requested index (`CURLHE_BADINDEX = 1`).
    BadIndex = 1,
    /// No such header exists (`CURLHE_MISSING = 2`).
    Missing = 2,
    /// No headers available yet (`CURLHE_NOHEADERS = 3`).
    NoHeaders = 3,
    /// No request with the given number was used (`CURLHE_NOREQUEST = 4`).
    NoRequest = 4,
    /// Out of memory (`CURLHE_OUT_OF_MEMORY = 5`).
    OutOfMemory = 5,
    /// Bad argument supplied (`CURLHE_BAD_ARGUMENT = 6`).
    BadArgument = 6,
    /// Feature not built in (`CURLHE_NOT_BUILT_IN = 7`).
    NotBuiltIn = 7,
}

impl CurlHcode {
    /// Returns the integer value of this code, matching the C `CURLHcode` enum.
    #[inline]
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

// ---------------------------------------------------------------------------
// Header — user-facing header view
// ---------------------------------------------------------------------------

/// A single HTTP header returned by [`Headers::get()`] or [`Headers::next()`].
///
/// Mirrors the C `struct curl_header` from `include/curl/header.h`.
/// The `anchor` field is a crate-internal position used by [`Headers::next()`]
/// to resume iteration.
#[derive(Debug, Clone)]
pub struct Header {
    /// Header field name (may differ in case from the original).
    name_str: String,
    /// Header field value (trimmed of leading/trailing whitespace).
    value_str: String,
    /// Total count of headers sharing this name in the filtered result set.
    header_amount: usize,
    /// Zero-based index of this header among same-name headers.
    header_index: usize,
    /// Origin classification of this header.
    header_origin: HeaderOrigin,
    /// Internal position in the storage vector, used by [`Headers::next()`].
    pub(crate) anchor: usize,
}

impl Header {
    /// Returns the header field name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name_str
    }

    /// Returns the header field value.
    #[inline]
    pub fn value(&self) -> &str {
        &self.value_str
    }

    /// Returns the total count of headers with this name in the filtered set.
    #[inline]
    pub fn amount(&self) -> usize {
        self.header_amount
    }

    /// Returns the zero-based index of this header among same-name headers.
    #[inline]
    pub fn index(&self) -> usize {
        self.header_index
    }

    /// Returns the origin classification of this header.
    #[inline]
    pub fn origin(&self) -> HeaderOrigin {
        self.header_origin
    }
}

// ---------------------------------------------------------------------------
// DynHeaderEntry — public entry for DynHeaders
// ---------------------------------------------------------------------------

/// A single name-value pair stored in a [`DynHeaders`] collection.
///
/// Mirrors the C `struct dynhds_entry` from `lib/dynhds.h`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynHeaderEntry {
    /// Header field name.
    name_str: String,
    /// Header field value.
    value_str: String,
}

impl DynHeaderEntry {
    /// Returns the header field name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name_str
    }

    /// Returns the header field value.
    #[inline]
    pub fn value(&self) -> &str {
        &self.value_str
    }
}

// ---------------------------------------------------------------------------
// HeaderEntry — private internal storage for Headers
// ---------------------------------------------------------------------------

/// Internal representation of a stored response header.
///
/// Corresponds to the C `struct Curl_header_store` in `lib/headers.h`.
struct HeaderEntry {
    /// Header name (stored as-is from the server response).
    name: String,
    /// Header value (trimmed of surrounding whitespace).
    value: String,
    /// Origin type identifying where this header was received.
    origin: HeaderOrigin,
    /// Request number: 0 for the initial request, incremented for each
    /// redirect or follow-up request on the same handle.
    request: i32,
}

// ---------------------------------------------------------------------------
// Headers — response header collection
// ---------------------------------------------------------------------------

/// Collection of HTTP response headers received during a transfer.
///
/// This is the Rust equivalent of the `struct Curl_llist httphdrs` linked
/// list maintained in the C code's `struct UrlState`. It stores headers
/// in insertion order and supports lookup by name, index, and origin filter
/// via [`get()`](Headers::get) and sequential iteration via
/// [`next()`](Headers::next).
///
/// # Request Tracking
///
/// Curl tracks a "request number" that starts at 0 and increments for each
/// redirect or follow-up request on the same easy handle. Use
/// [`next_request()`](Headers::next_request) to advance the counter before
/// pushing headers for a new request.
pub struct Headers {
    /// Stored header entries in insertion order.
    entries: Vec<HeaderEntry>,
    /// Current request counter (0 for the first request, then 1, 2, …).
    requests: i32,
}

impl Headers {
    /// Creates a new, empty `Headers` collection with request counter at 0.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            requests: 0,
        }
    }

    /// Stores a raw HTTP response header line.
    ///
    /// The header should be in `"Name: Value\r\n"` format. The method trims
    /// trailing CR/LF, parses the name and value, and stores the entry.
    /// Pseudo-headers (`:name`) are supported when `origin` is
    /// [`HeaderOrigin::PSEUDO`].
    ///
    /// Matches the C `Curl_headers_push()` function from `lib/headers.c`.
    ///
    /// # Errors
    ///
    /// - [`CurlError::WeirdServerReply`] if the header line has no CR/LF
    ///   terminator, or is a blank continuation line with no content.
    /// - [`CurlError::BadFunctionArgument`] if the line is malformed (missing
    ///   colon separator, or pseudo-header without leading `:`).
    /// - [`CurlError::TooLarge`] if the maximum header count is exceeded.
    pub fn push(&mut self, header: &str, origin: HeaderOrigin) -> CurlResult<()> {
        if header.is_empty() {
            return Ok(());
        }

        let first_byte = header.as_bytes()[0];

        // Ignore the body separator (blank lines consisting of just CR/LF).
        if first_byte == b'\r' || first_byte == b'\n' {
            return Ok(());
        }

        let orig_len = header.len();
        let mut hdr = header;

        // Trim trailing LF then CR (matching C order: check LF first, then CR).
        if hdr.ends_with('\n') {
            hdr = &hdr[..hdr.len() - 1];
        }
        if hdr.ends_with('\r') {
            hdr = &hdr[..hdr.len() - 1];
        }

        // Neither CR nor LF was found — not a valid header line.
        if hdr.len() == orig_len {
            return Err(CurlError::WeirdServerReply);
        }

        // Handle leading blanks (obsolete line folding / continuation).
        // The C code strips leading blanks and attempts to parse the remainder
        // as a normal "Name: Value" line. It does NOT append to the previous
        // header.
        let bytes = hdr.as_bytes();
        if !bytes.is_empty() && (bytes[0] == b' ' || bytes[0] == b'\t') {
            let trimmed = hdr.trim_start_matches([' ', '\t']);
            if trimmed.is_empty() {
                return Err(CurlError::WeirdServerReply);
            }
            hdr = trimmed;
        }

        // Enforce maximum header count.
        if self.entries.len() >= MAX_HTTP_RESP_HEADER_COUNT {
            return Err(CurlError::TooLarge);
        }

        // Parse the "Name: Value" line.
        let (name, value) = parse_name_value(hdr, origin)?;

        self.entries.push(HeaderEntry {
            name,
            value,
            origin,
            request: self.requests,
        });

        Ok(())
    }

    /// Looks up a header by name, index, origin bitmask, and request number.
    ///
    /// Matches the C `curl_easy_header()` function from `lib/headers.c`.
    ///
    /// # Parameters
    ///
    /// - `name`: Header name (comparison is case-insensitive).
    /// - `name_index`: Zero-based index among headers with this name that
    ///   also match the origin and request filters.
    /// - `origin_mask`: Bitmask of accepted origin types (e.g.,
    ///   `CURLH_HEADER | CURLH_1XX`). Must be non-zero and within the valid
    ///   `CURLH_*` range.
    /// - `request`: Request number (`0` for the first request, `-1` for the
    ///   latest request).
    ///
    /// # Errors
    ///
    /// Returns a [`CurlHcode`] error variant instead of the header when:
    /// - Arguments are invalid ([`BadArgument`](CurlHcode::BadArgument))
    /// - No headers stored yet ([`NoHeaders`](CurlHcode::NoHeaders))
    /// - Requested request number not reached ([`NoRequest`](CurlHcode::NoRequest))
    /// - No header with this name matches ([`Missing`](CurlHcode::Missing))
    /// - Index exceeds the matching count ([`BadIndex`](CurlHcode::BadIndex))
    pub fn get(
        &self,
        name: &str,
        name_index: usize,
        origin_mask: u32,
        request: i32,
    ) -> Result<Header, CurlHcode> {
        // Validate arguments — mirrors the C parameter checks.
        if name.is_empty() || origin_mask == 0 || origin_mask > CURLH_ALL || request < -1 {
            return Err(CurlHcode::BadArgument);
        }

        if self.entries.is_empty() {
            return Err(CurlHcode::NoHeaders);
        }

        let req = if request == -1 { self.requests } else { request };
        if req > self.requests {
            return Err(CurlHcode::NoRequest);
        }

        // First pass: count matching entries and remember the last match
        // position. This mirrors the C two-pass approach.
        let mut amount: usize = 0;
        let mut last_match_pos: Option<usize> = None;
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.name.eq_ignore_ascii_case(name)
                && (entry.origin.as_u32() & origin_mask) != 0
                && entry.request == req
            {
                amount += 1;
                last_match_pos = Some(i);
            }
        }

        if amount == 0 {
            return Err(CurlHcode::Missing);
        }
        if name_index >= amount {
            return Err(CurlHcode::BadIndex);
        }

        // If the caller requests the last occurrence, we already know it.
        let pos = if name_index == amount - 1 {
            // The C code optimizes this case to avoid a second scan.
            last_match_pos.unwrap()
        } else {
            // Second pass: locate the entry at the requested index.
            let mut match_count: usize = 0;
            let mut found = 0usize;
            for (i, entry) in self.entries.iter().enumerate() {
                if entry.name.eq_ignore_ascii_case(name)
                    && (entry.origin.as_u32() & origin_mask) != 0
                    && entry.request == req
                {
                    if match_count == name_index {
                        found = i;
                        break;
                    }
                    match_count += 1;
                }
            }
            found
        };

        let entry = &self.entries[pos];
        Ok(Header {
            name_str: entry.name.clone(),
            value_str: entry.value.clone(),
            header_amount: amount,
            header_index: name_index,
            header_origin: entry.origin,
            anchor: pos,
        })
    }

    /// Returns the next header matching the origin filter and request number,
    /// starting after `prev` (or from the beginning if `prev` is `None`).
    ///
    /// Matches the C `curl_easy_nextheader()` function from `lib/headers.c`.
    ///
    /// # Parameters
    ///
    /// - `origin_mask`: Bitmask of accepted origin types.
    /// - `request`: Request number (`-1` for the latest).
    /// - `prev`: Previous header returned by an earlier call. Pass `None` to
    ///   start from the beginning.
    pub fn next(
        &self,
        origin_mask: u32,
        request: i32,
        prev: Option<&Header>,
    ) -> Option<Header> {
        let req = if request == -1 { self.requests } else { request };
        if req > self.requests {
            return None;
        }

        // Determine the starting position: after the previous header's
        // anchor, or from the very beginning.
        let start = match prev {
            Some(h) => {
                if h.anchor >= self.entries.len() {
                    return None;
                }
                h.anchor + 1
            }
            None => 0,
        };

        // Find the next entry matching the origin and request filters.
        let mut pick_pos: Option<usize> = None;
        for i in start..self.entries.len() {
            let entry = &self.entries[i];
            if (entry.origin.as_u32() & origin_mask) != 0 && entry.request == req {
                pick_pos = Some(i);
                break;
            }
        }

        let pos = pick_pos?;
        let entry = &self.entries[pos];

        // Count total occurrences of this name (matching origin and request)
        // and determine the index of the picked entry. This mirrors the C
        // code's counting loop in `curl_easy_nextheader`.
        let mut amount: usize = 0;
        let mut index: usize = 0;
        for (i, e) in self.entries.iter().enumerate() {
            if e.name.eq_ignore_ascii_case(&entry.name)
                && (e.origin.as_u32() & origin_mask) != 0
                && e.request == req
            {
                if i == pos {
                    index = amount;
                }
                amount += 1;
            }
        }

        Some(Header {
            name_str: entry.name.clone(),
            value_str: entry.value.clone(),
            header_amount: amount,
            header_index: index,
            header_origin: entry.origin,
            anchor: pos,
        })
    }

    /// Removes all stored headers and resets the request counter to 0.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.requests = 0;
    }

    /// Returns the number of stored header entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no headers are stored.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over all stored headers as [`Header`] values.
    ///
    /// Each yielded [`Header`] has its `amount` and `index` computed relative
    /// to **all** stored entries (unfiltered by origin or request).
    pub fn iter(&self) -> HeadersIter<'_> {
        HeadersIter {
            headers: self,
            pos: 0,
        }
    }

    /// Increments the internal request counter.
    ///
    /// Call this when following a redirect or starting a new request on the
    /// same handle. Subsequent [`push()`](Headers::push) calls will associate
    /// headers with the new request number.
    pub fn next_request(&mut self) {
        self.requests += 1;
    }

    /// Returns the current request number (0 for the first request).
    #[inline]
    pub fn current_request(&self) -> i32 {
        self.requests
    }
}

impl Default for Headers {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HeadersIter — iterator over Headers
// ---------------------------------------------------------------------------

/// Iterator over all headers in a [`Headers`] collection.
///
/// Yields owned [`Header`] values with `amount` and `index` computed across
/// **all** stored entries (no origin or request filtering).
pub struct HeadersIter<'a> {
    headers: &'a Headers,
    pos: usize,
}

impl<'a> Iterator for HeadersIter<'a> {
    type Item = Header;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.headers.entries.len() {
            return None;
        }

        let pos = self.pos;
        self.pos += 1;

        let entry = &self.headers.entries[pos];

        // Compute the total count (amount) and position (index) among
        // all entries sharing this name.
        let mut amount: usize = 0;
        let mut index: usize = 0;
        for (i, e) in self.headers.entries.iter().enumerate() {
            if e.name.eq_ignore_ascii_case(&entry.name) {
                if i == pos {
                    index = amount;
                }
                amount += 1;
            }
        }

        Some(Header {
            name_str: entry.name.clone(),
            value_str: entry.value.clone(),
            header_amount: amount,
            header_index: index,
            header_origin: entry.origin,
            anchor: pos,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.headers.entries.len().saturating_sub(self.pos);
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for HeadersIter<'a> {}

// ---------------------------------------------------------------------------
// DynHeaders — dynamic header collection for outgoing requests
// ---------------------------------------------------------------------------

/// Dynamic HTTP header collection for building outgoing request headers.
///
/// This is the Rust equivalent of the C `struct dynhds` from `lib/dynhds.h`.
/// It supports adding, replacing, removing, and serialising header entries
/// with optional capacity limits and name lowercasing.
///
/// # Capacity Limits
///
/// Two independent limits can be configured:
/// - **`max_entries`**: Maximum number of header entries (0 = unlimited).
/// - **`max_strs_size`**: Maximum total byte length of all stored name and
///   value strings combined.
///
/// Both limits are checked by [`add()`](DynHeaders::add). Exceeding either
/// limit returns [`CurlError::OutOfMemory`], matching the C implementation.
pub struct DynHeaders {
    /// Stored entries in insertion order.
    entries: Vec<DynHeaderEntry>,
    /// Maximum number of entries allowed (0 = unlimited).
    max_entries: usize,
    /// Maximum total byte length of all name + value strings.
    max_strs_size: usize,
    /// Current total byte length of all name + value strings.
    strs_len: usize,
    /// When `true`, names are lowercased on [`add()`](DynHeaders::add).
    /// Corresponds to the C `DYNHDS_OPT_LOWERCASE` option.
    lowercase: bool,
}

impl DynHeaders {
    /// Creates a new, empty `DynHeaders` with no capacity limits.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_entries: 0,
            max_strs_size: usize::MAX,
            strs_len: 0,
            lowercase: false,
        }
    }

    /// Creates a new, empty `DynHeaders` with the specified capacity limits.
    ///
    /// # Parameters
    ///
    /// - `max_entries`: Maximum number of entries (0 = unlimited).
    /// - `max_strs_size`: Maximum total byte length of all name + value
    ///   strings. Must be > 0.
    pub fn with_limits(max_entries: usize, max_strs_size: usize) -> Self {
        debug_assert!(max_strs_size > 0, "max_strs_size must be > 0");
        Self {
            entries: Vec::new(),
            max_entries,
            max_strs_size: if max_strs_size == 0 { 1 } else { max_strs_size },
            strs_len: 0,
            lowercase: false,
        }
    }

    /// Returns the number of stored entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no entries are stored.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes all entries and resets the string length counter.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.strs_len = 0;
    }

    /// Returns a reference to the first entry matching `name`
    /// (case-insensitive), or `None` if no match is found.
    ///
    /// Matches the C `Curl_dynhds_cget()` function.
    pub fn get(&self, name: &str) -> Option<&DynHeaderEntry> {
        self.entries
            .iter()
            .find(|e| e.name_str.eq_ignore_ascii_case(name))
    }

    /// Returns a reference to the entry at position `index`, or `None` if
    /// the index is out of bounds.
    ///
    /// Matches the C `Curl_dynhds_getn()` function.
    #[inline]
    pub fn get_at(&self, index: usize) -> Option<&DynHeaderEntry> {
        self.entries.get(index)
    }

    /// Returns `true` if at least one entry with the given `name` exists
    /// (case-insensitive comparison).
    ///
    /// Matches the C `Curl_dynhds_ccontains()` function.
    #[inline]
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Appends a new header entry. Does **not** check for duplicate names.
    ///
    /// If the `lowercase` option is enabled (via [`set_lowercase`](DynHeaders::set_lowercase)),
    /// the stored name is converted to ASCII lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::OutOfMemory`] when either:
    /// - The entry limit would be exceeded.
    /// - The total string size limit would be exceeded.
    pub fn add(&mut self, name: &str, value: &str) -> CurlResult<()> {
        // Check entry count limit.
        if self.max_entries > 0 && self.entries.len() >= self.max_entries {
            return Err(CurlError::OutOfMemory);
        }

        // Check string size limit (safe against overflow).
        let new_strs = name.len().saturating_add(value.len());
        if self.strs_len.checked_add(new_strs).map_or(true, |total| total > self.max_strs_size) {
            return Err(CurlError::OutOfMemory);
        }

        let stored_name = if self.lowercase {
            name.to_ascii_lowercase()
        } else {
            name.to_owned()
        };

        self.entries.push(DynHeaderEntry {
            name_str: stored_name,
            value_str: value.to_owned(),
        });
        self.strs_len += new_strs;

        Ok(())
    }

    /// Parses an HTTP/1.1 formatted header line (`"Name: Value\r\n"`) and
    /// appends the resulting entry.
    ///
    /// Leading whitespace after the colon is stripped. Trailing `\r` and `\n`
    /// are stripped from the value. An empty or blank line is silently ignored.
    ///
    /// Matches the C `Curl_dynhds_h1_add_line()` / `Curl_dynhds_h1_cadd_line()`
    /// functions from `lib/dynhds.c`.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if no colon separator is
    /// found. Propagates [`CurlError::OutOfMemory`] from [`add()`](DynHeaders::add).
    pub fn add_line(&mut self, line: &str) -> CurlResult<()> {
        if line.is_empty() {
            return Ok(());
        }

        // Find the colon separator.
        let colon_pos = match line.find(':') {
            Some(pos) => pos,
            None => return Err(CurlError::BadFunctionArgument),
        };

        let name = &line[..colon_pos];
        let after_colon = &line[colon_pos + 1..];

        // Skip leading blanks (space / tab) after the colon.
        let trimmed = after_colon.trim_start_matches([' ', '\t']);

        // Truncate the value at the first CR or LF (if any).
        let value = match trimmed.find(['\r', '\n']) {
            Some(pos) => &trimmed[..pos],
            None => trimmed,
        };

        self.add(name, value)
    }

    /// Replaces all entries with the given `name` with a single new entry
    /// carrying the supplied `value`. The new entry is appended at the end.
    ///
    /// Matches the C `Curl_dynhds_cset()` / `Curl_dynhds_set()` functions.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`add()`](DynHeaders::add).
    pub fn set(&mut self, name: &str, value: &str) -> CurlResult<()> {
        self.remove(name);
        self.add(name, value)
    }

    /// Removes all entries whose name matches `name` (case-insensitive).
    ///
    /// Returns the number of entries removed. Matches the C
    /// `Curl_dynhds_cremove()` function.
    pub fn remove(&mut self, name: &str) -> usize {
        let mut removed = 0usize;
        let mut freed_strs = 0usize;
        self.entries.retain(|e| {
            if e.name_str.eq_ignore_ascii_case(name) {
                removed += 1;
                freed_strs += e.name_str.len() + e.value_str.len();
                false
            } else {
                true
            }
        });
        self.strs_len = self.strs_len.saturating_sub(freed_strs);
        removed
    }

    /// Enables or disables automatic ASCII lowercasing of header names on
    /// future [`add()`](DynHeaders::add) calls. Existing entries are **not**
    /// modified.
    ///
    /// Corresponds to the C `DYNHDS_OPT_LOWERCASE` option set via
    /// `Curl_dynhds_set_opts()`.
    #[inline]
    pub fn set_lowercase(&mut self, enabled: bool) {
        self.lowercase = enabled;
    }

    /// Serialises all stored headers into HTTP/1.1 wire format.
    ///
    /// Each header is formatted as `Name: Value\r\n`. No trailing blank line
    /// is appended (matching the C `Curl_dynhds_h1_dprint()` behaviour).
    ///
    /// Returns the formatted string.
    pub fn h1_serialize(&self) -> String {
        if self.entries.is_empty() {
            return String::new();
        }

        // Pre-allocate: each entry contributes name + ": " + value + "\r\n".
        let capacity = self.strs_len + self.entries.len() * 4;
        let mut buf = String::with_capacity(capacity);

        for entry in &self.entries {
            buf.push_str(&entry.name_str);
            buf.push_str(": ");
            buf.push_str(&entry.value_str);
            buf.push_str("\r\n");
        }

        buf
    }

    /// Returns an iterator over references to the stored [`DynHeaderEntry`]
    /// items in insertion order.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, DynHeaderEntry> {
        self.entries.iter()
    }
}

impl Default for DynHeaders {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IntoIterator implementations
// ---------------------------------------------------------------------------

impl<'a> IntoIterator for &'a Headers {
    type Item = Header;
    type IntoIter = HeadersIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a DynHeaders {
    type Item = &'a DynHeaderEntry;
    type IntoIter = std::slice::Iter<'a, DynHeaderEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parses a `"Name: Value"` header string into separate name and value
/// components.
///
/// For pseudo-headers (when `origin` is [`HeaderOrigin::PSEUDO`]), the
/// leading `:` is part of the name and the separator colon follows the
/// pseudo-header name (e.g., `:status: 200`).
///
/// Matches the C `namevalue()` static function in `lib/headers.c`.
fn parse_name_value(line: &str, origin: HeaderOrigin) -> CurlResult<(String, String)> {
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        return Err(CurlError::BadFunctionArgument);
    }

    // For pseudo-headers the name starts with ':'. The separator colon is
    // the *second* colon in the line.
    let search_start = if origin == HeaderOrigin::PSEUDO {
        if bytes[0] != b':' {
            return Err(CurlError::BadFunctionArgument);
        }
        1 // skip the leading ':' when scanning for the separator
    } else {
        0
    };

    // Locate the colon separator.
    let colon_pos = match bytes[search_start..].iter().position(|&b| b == b':') {
        Some(p) => search_start + p,
        None => return Err(CurlError::BadFunctionArgument),
    };

    let name = &line[..colon_pos];
    let after_colon = &line[colon_pos + 1..];

    // Strip leading whitespace from the value (space / tab).
    let value = after_colon.trim_start_matches([' ', '\t']);
    // Strip trailing whitespace from the value.
    let value = value.trim_end_matches([' ', '\t']);

    Ok((name.to_owned(), value.to_owned()))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- HeaderOrigin tests --

    #[test]
    fn header_origin_constants_match_c() {
        assert_eq!(CURLH_HEADER, 1);
        assert_eq!(CURLH_TRAILER, 2);
        assert_eq!(CURLH_CONNECT, 4);
        assert_eq!(CURLH_1XX, 8);
        assert_eq!(CURLH_PSEUDO, 16);

        assert_eq!(HeaderOrigin::HEADER.as_u32(), CURLH_HEADER);
        assert_eq!(HeaderOrigin::TRAILER.as_u32(), CURLH_TRAILER);
        assert_eq!(HeaderOrigin::CONNECT.as_u32(), CURLH_CONNECT);
        assert_eq!(HeaderOrigin::INTERIM_1XX.as_u32(), CURLH_1XX);
        assert_eq!(HeaderOrigin::PSEUDO.as_u32(), CURLH_PSEUDO);
    }

    #[test]
    fn header_origin_from_bits() {
        assert!(HeaderOrigin::from_bits(0).is_none());
        assert!(HeaderOrigin::from_bits(1 << 5).is_none());
        assert!(HeaderOrigin::from_bits(CURLH_ALL + 1).is_none());

        let ho = HeaderOrigin::from_bits(CURLH_HEADER | CURLH_TRAILER).unwrap();
        assert_eq!(ho.as_u32(), 3);
    }

    #[test]
    fn header_origin_contains() {
        let combined = HeaderOrigin::HEADER | HeaderOrigin::TRAILER;
        assert!(combined.contains(HeaderOrigin::HEADER));
        assert!(combined.contains(HeaderOrigin::TRAILER));
        assert!(!combined.contains(HeaderOrigin::CONNECT));
        // contains with zero-bits other always returns false.
        assert!(!combined.contains(HeaderOrigin(0)));
    }

    // -- CurlHcode tests --

    #[test]
    fn curl_hcode_values() {
        assert_eq!(CurlHcode::Ok.as_i32(), 0);
        assert_eq!(CurlHcode::BadIndex.as_i32(), 1);
        assert_eq!(CurlHcode::Missing.as_i32(), 2);
        assert_eq!(CurlHcode::NoHeaders.as_i32(), 3);
        assert_eq!(CurlHcode::NoRequest.as_i32(), 4);
        assert_eq!(CurlHcode::OutOfMemory.as_i32(), 5);
        assert_eq!(CurlHcode::BadArgument.as_i32(), 6);
        assert_eq!(CurlHcode::NotBuiltIn.as_i32(), 7);
    }

    // -- Headers tests --

    #[test]
    fn headers_push_basic() {
        let mut hdrs = Headers::new();
        hdrs.push("Content-Type: text/html\r\n", HeaderOrigin::HEADER)
            .unwrap();
        assert_eq!(hdrs.len(), 1);
        assert!(!hdrs.is_empty());
    }

    #[test]
    fn headers_push_ignores_blank_lines() {
        let mut hdrs = Headers::new();
        hdrs.push("\r\n", HeaderOrigin::HEADER).unwrap();
        hdrs.push("\n", HeaderOrigin::HEADER).unwrap();
        assert_eq!(hdrs.len(), 0);
    }

    #[test]
    fn headers_push_rejects_no_crlf() {
        let mut hdrs = Headers::new();
        let result = hdrs.push("Content-Type: text/html", HeaderOrigin::HEADER);
        assert_eq!(result.unwrap_err(), CurlError::WeirdServerReply);
    }

    #[test]
    fn headers_push_rejects_no_colon() {
        let mut hdrs = Headers::new();
        let result = hdrs.push("BadHeader\r\n", HeaderOrigin::HEADER);
        assert_eq!(result.unwrap_err(), CurlError::BadFunctionArgument);
    }

    #[test]
    fn headers_push_pseudo_header() {
        let mut hdrs = Headers::new();
        hdrs.push(":status: 200\r\n", HeaderOrigin::PSEUDO).unwrap();
        assert_eq!(hdrs.len(), 1);

        let h = hdrs
            .get(":status", 0, CURLH_PSEUDO, 0)
            .unwrap();
        assert_eq!(h.name(), ":status");
        assert_eq!(h.value(), "200");
    }

    #[test]
    fn headers_get_case_insensitive() {
        let mut hdrs = Headers::new();
        hdrs.push("Content-Type: text/html\r\n", HeaderOrigin::HEADER)
            .unwrap();

        let h = hdrs.get("content-type", 0, CURLH_HEADER, 0).unwrap();
        assert_eq!(h.name(), "Content-Type");
        assert_eq!(h.value(), "text/html");
        assert_eq!(h.amount(), 1);
        assert_eq!(h.index(), 0);
        assert_eq!(h.origin(), HeaderOrigin::HEADER);
    }

    #[test]
    fn headers_get_multiple_same_name() {
        let mut hdrs = Headers::new();
        hdrs.push("Set-Cookie: a=1\r\n", HeaderOrigin::HEADER).unwrap();
        hdrs.push("Set-Cookie: b=2\r\n", HeaderOrigin::HEADER).unwrap();
        hdrs.push("Set-Cookie: c=3\r\n", HeaderOrigin::HEADER).unwrap();

        let h0 = hdrs.get("set-cookie", 0, CURLH_HEADER, 0).unwrap();
        assert_eq!(h0.value(), "a=1");
        assert_eq!(h0.amount(), 3);
        assert_eq!(h0.index(), 0);

        let h1 = hdrs.get("set-cookie", 1, CURLH_HEADER, 0).unwrap();
        assert_eq!(h1.value(), "b=2");
        assert_eq!(h1.amount(), 3);
        assert_eq!(h1.index(), 1);

        let h2 = hdrs.get("set-cookie", 2, CURLH_HEADER, 0).unwrap();
        assert_eq!(h2.value(), "c=3");
        assert_eq!(h2.amount(), 3);
        assert_eq!(h2.index(), 2);

        // Out-of-range index.
        assert_eq!(
            hdrs.get("set-cookie", 3, CURLH_HEADER, 0).unwrap_err(),
            CurlHcode::BadIndex
        );
    }

    #[test]
    fn headers_get_missing() {
        let mut hdrs = Headers::new();
        hdrs.push("Host: example.com\r\n", HeaderOrigin::HEADER)
            .unwrap();
        assert_eq!(
            hdrs.get("X-Missing", 0, CURLH_HEADER, 0).unwrap_err(),
            CurlHcode::Missing
        );
    }

    #[test]
    fn headers_get_no_headers() {
        let hdrs = Headers::new();
        assert_eq!(
            hdrs.get("Host", 0, CURLH_HEADER, 0).unwrap_err(),
            CurlHcode::NoHeaders
        );
    }

    #[test]
    fn headers_get_bad_argument() {
        let mut hdrs = Headers::new();
        hdrs.push("Host: example.com\r\n", HeaderOrigin::HEADER)
            .unwrap();

        // Empty name.
        assert_eq!(
            hdrs.get("", 0, CURLH_HEADER, 0).unwrap_err(),
            CurlHcode::BadArgument
        );
        // Zero origin.
        assert_eq!(
            hdrs.get("Host", 0, 0, 0).unwrap_err(),
            CurlHcode::BadArgument
        );
        // Request < -1.
        assert_eq!(
            hdrs.get("Host", 0, CURLH_HEADER, -2).unwrap_err(),
            CurlHcode::BadArgument
        );
    }

    #[test]
    fn headers_get_with_request_tracking() {
        let mut hdrs = Headers::new();
        hdrs.push("Host: example.com\r\n", HeaderOrigin::HEADER)
            .unwrap();
        hdrs.next_request();
        hdrs.push("Host: redirected.com\r\n", HeaderOrigin::HEADER)
            .unwrap();

        // Request 0.
        let h0 = hdrs.get("Host", 0, CURLH_HEADER, 0).unwrap();
        assert_eq!(h0.value(), "example.com");

        // Request 1.
        let h1 = hdrs.get("Host", 0, CURLH_HEADER, 1).unwrap();
        assert_eq!(h1.value(), "redirected.com");

        // Request -1 (latest = 1).
        let hl = hdrs.get("Host", 0, CURLH_HEADER, -1).unwrap();
        assert_eq!(hl.value(), "redirected.com");

        // Request 2 does not exist.
        assert_eq!(
            hdrs.get("Host", 0, CURLH_HEADER, 2).unwrap_err(),
            CurlHcode::NoRequest
        );
    }

    #[test]
    fn headers_get_origin_filter() {
        let mut hdrs = Headers::new();
        hdrs.push("Via: proxy\r\n", HeaderOrigin::CONNECT).unwrap();
        hdrs.push("Content-Length: 42\r\n", HeaderOrigin::HEADER)
            .unwrap();

        // Only HEADER origin — should not find "Via".
        assert_eq!(
            hdrs.get("Via", 0, CURLH_HEADER, 0).unwrap_err(),
            CurlHcode::Missing
        );

        // CONNECT origin — should find "Via".
        let h = hdrs.get("Via", 0, CURLH_CONNECT, 0).unwrap();
        assert_eq!(h.value(), "proxy");

        // Combined mask.
        let h = hdrs
            .get("Via", 0, CURLH_HEADER | CURLH_CONNECT, 0)
            .unwrap();
        assert_eq!(h.value(), "proxy");
    }

    #[test]
    fn headers_next_iteration() {
        let mut hdrs = Headers::new();
        hdrs.push("A: 1\r\n", HeaderOrigin::HEADER).unwrap();
        hdrs.push("B: 2\r\n", HeaderOrigin::HEADER).unwrap();
        hdrs.push("C: 3\r\n", HeaderOrigin::HEADER).unwrap();

        let h1 = hdrs.next(CURLH_HEADER, 0, None).unwrap();
        assert_eq!(h1.name(), "A");

        let h2 = hdrs.next(CURLH_HEADER, 0, Some(&h1)).unwrap();
        assert_eq!(h2.name(), "B");

        let h3 = hdrs.next(CURLH_HEADER, 0, Some(&h2)).unwrap();
        assert_eq!(h3.name(), "C");

        assert!(hdrs.next(CURLH_HEADER, 0, Some(&h3)).is_none());
    }

    #[test]
    fn headers_next_with_origin_filter() {
        let mut hdrs = Headers::new();
        hdrs.push("A: 1\r\n", HeaderOrigin::HEADER).unwrap();
        hdrs.push("B: 2\r\n", HeaderOrigin::CONNECT).unwrap();
        hdrs.push("C: 3\r\n", HeaderOrigin::HEADER).unwrap();

        // Only HEADER origin — should skip "B".
        let h1 = hdrs.next(CURLH_HEADER, 0, None).unwrap();
        assert_eq!(h1.name(), "A");

        let h2 = hdrs.next(CURLH_HEADER, 0, Some(&h1)).unwrap();
        assert_eq!(h2.name(), "C");

        assert!(hdrs.next(CURLH_HEADER, 0, Some(&h2)).is_none());
    }

    #[test]
    fn headers_iter() {
        let mut hdrs = Headers::new();
        hdrs.push("A: 1\r\n", HeaderOrigin::HEADER).unwrap();
        hdrs.push("B: 2\r\n", HeaderOrigin::HEADER).unwrap();
        hdrs.push("A: 3\r\n", HeaderOrigin::HEADER).unwrap();

        let collected: Vec<Header> = hdrs.iter().collect();
        assert_eq!(collected.len(), 3);

        // First "A".
        assert_eq!(collected[0].name(), "A");
        assert_eq!(collected[0].value(), "1");
        assert_eq!(collected[0].amount(), 2);
        assert_eq!(collected[0].index(), 0);

        // "B".
        assert_eq!(collected[1].name(), "B");
        assert_eq!(collected[1].amount(), 1);
        assert_eq!(collected[1].index(), 0);

        // Second "A".
        assert_eq!(collected[2].name(), "A");
        assert_eq!(collected[2].value(), "3");
        assert_eq!(collected[2].amount(), 2);
        assert_eq!(collected[2].index(), 1);
    }

    #[test]
    fn headers_clear() {
        let mut hdrs = Headers::new();
        hdrs.push("X: 1\r\n", HeaderOrigin::HEADER).unwrap();
        hdrs.next_request();
        hdrs.push("Y: 2\r\n", HeaderOrigin::HEADER).unwrap();
        assert_eq!(hdrs.len(), 2);
        assert_eq!(hdrs.current_request(), 1);

        hdrs.clear();
        assert_eq!(hdrs.len(), 0);
        assert!(hdrs.is_empty());
        assert_eq!(hdrs.current_request(), 0);
    }

    #[test]
    fn headers_push_too_large() {
        let mut hdrs = Headers::new();
        for i in 0..MAX_HTTP_RESP_HEADER_COUNT {
            hdrs.push(
                &format!("X-Hdr-{}: value\r\n", i),
                HeaderOrigin::HEADER,
            )
            .unwrap();
        }
        let result = hdrs.push("X-Overflow: boom\r\n", HeaderOrigin::HEADER);
        assert_eq!(result.unwrap_err(), CurlError::TooLarge);
    }

    #[test]
    fn headers_push_trims_value_whitespace() {
        let mut hdrs = Headers::new();
        hdrs.push("X-Pad:   spaced   \r\n", HeaderOrigin::HEADER)
            .unwrap();
        let h = hdrs.get("X-Pad", 0, CURLH_HEADER, 0).unwrap();
        assert_eq!(h.value(), "spaced");
    }

    // -- DynHeaders tests --

    #[test]
    fn dynhdrs_add_and_get() {
        let mut dh = DynHeaders::new();
        dh.add("Content-Type", "application/json").unwrap();
        assert_eq!(dh.len(), 1);
        assert!(!dh.is_empty());

        let entry = dh.get("content-type").unwrap();
        assert_eq!(entry.name(), "Content-Type");
        assert_eq!(entry.value(), "application/json");
    }

    #[test]
    fn dynhdrs_get_at() {
        let mut dh = DynHeaders::new();
        dh.add("A", "1").unwrap();
        dh.add("B", "2").unwrap();

        assert_eq!(dh.get_at(0).unwrap().name(), "A");
        assert_eq!(dh.get_at(1).unwrap().name(), "B");
        assert!(dh.get_at(2).is_none());
    }

    #[test]
    fn dynhdrs_contains() {
        let mut dh = DynHeaders::new();
        dh.add("Host", "example.com").unwrap();
        assert!(dh.contains("host"));
        assert!(dh.contains("HOST"));
        assert!(!dh.contains("Accept"));
    }

    #[test]
    fn dynhdrs_set_replaces() {
        let mut dh = DynHeaders::new();
        dh.add("Host", "one.com").unwrap();
        dh.add("Host", "two.com").unwrap();
        assert_eq!(dh.len(), 2);

        dh.set("Host", "three.com").unwrap();
        assert_eq!(dh.len(), 1);
        assert_eq!(dh.get("Host").unwrap().value(), "three.com");
    }

    #[test]
    fn dynhdrs_remove() {
        let mut dh = DynHeaders::new();
        dh.add("A", "1").unwrap();
        dh.add("B", "2").unwrap();
        dh.add("A", "3").unwrap();

        let removed = dh.remove("a");
        assert_eq!(removed, 2);
        assert_eq!(dh.len(), 1);
        assert_eq!(dh.get_at(0).unwrap().name(), "B");
    }

    #[test]
    fn dynhdrs_remove_nonexistent() {
        let mut dh = DynHeaders::new();
        dh.add("A", "1").unwrap();
        assert_eq!(dh.remove("Z"), 0);
        assert_eq!(dh.len(), 1);
    }

    #[test]
    fn dynhdrs_add_line() {
        let mut dh = DynHeaders::new();
        dh.add_line("Content-Type: text/html\r\n").unwrap();
        assert_eq!(dh.len(), 1);
        assert_eq!(dh.get("Content-Type").unwrap().value(), "text/html");
    }

    #[test]
    fn dynhdrs_add_line_no_colon() {
        let mut dh = DynHeaders::new();
        let result = dh.add_line("BadHeader\r\n");
        assert_eq!(result.unwrap_err(), CurlError::BadFunctionArgument);
    }

    #[test]
    fn dynhdrs_add_line_empty() {
        let mut dh = DynHeaders::new();
        dh.add_line("").unwrap();
        assert_eq!(dh.len(), 0);
    }

    #[test]
    fn dynhdrs_add_line_strips_crlf() {
        let mut dh = DynHeaders::new();
        dh.add_line("X: val\r\n").unwrap();
        assert_eq!(dh.get("X").unwrap().value(), "val");

        dh.add_line("Y: val2\n").unwrap();
        assert_eq!(dh.get("Y").unwrap().value(), "val2");
    }

    #[test]
    fn dynhdrs_set_lowercase() {
        let mut dh = DynHeaders::new();
        dh.set_lowercase(true);
        dh.add("Content-Type", "text/html").unwrap();
        assert_eq!(dh.get_at(0).unwrap().name(), "content-type");
    }

    #[test]
    fn dynhdrs_h1_serialize() {
        let mut dh = DynHeaders::new();
        dh.add("Host", "example.com").unwrap();
        dh.add("Accept", "*/*").unwrap();

        let wire = dh.h1_serialize();
        assert_eq!(wire, "Host: example.com\r\nAccept: */*\r\n");
    }

    #[test]
    fn dynhdrs_h1_serialize_empty() {
        let dh = DynHeaders::new();
        assert_eq!(dh.h1_serialize(), "");
    }

    #[test]
    fn dynhdrs_with_limits_entries() {
        let mut dh = DynHeaders::with_limits(2, 1024);
        dh.add("A", "1").unwrap();
        dh.add("B", "2").unwrap();
        let result = dh.add("C", "3");
        assert_eq!(result.unwrap_err(), CurlError::OutOfMemory);
    }

    #[test]
    fn dynhdrs_with_limits_strs_size() {
        let mut dh = DynHeaders::with_limits(0, 10);
        dh.add("ABCDE", "12345").unwrap(); // 5 + 5 = 10 = exactly at limit
        let result = dh.add("X", "Y"); // would be 12 > 10
        assert_eq!(result.unwrap_err(), CurlError::OutOfMemory);
    }

    #[test]
    fn dynhdrs_clear() {
        let mut dh = DynHeaders::new();
        dh.add("A", "1").unwrap();
        dh.add("B", "2").unwrap();
        dh.clear();
        assert!(dh.is_empty());
        assert_eq!(dh.len(), 0);
    }

    #[test]
    fn dynhdrs_iter() {
        let mut dh = DynHeaders::new();
        dh.add("A", "1").unwrap();
        dh.add("B", "2").unwrap();

        let names: Vec<&str> = dh.iter().map(|e| e.name()).collect();
        assert_eq!(names, vec!["A", "B"]);
    }

    #[test]
    fn default_impls() {
        let hdrs = Headers::default();
        assert!(hdrs.is_empty());
        let dh = DynHeaders::default();
        assert!(dh.is_empty());
    }
}
