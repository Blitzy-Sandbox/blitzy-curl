//! Dynamic growable byte buffer — Rust replacement for C `lib/curlx/dynbuf.c`.
//!
//! [`DynBuf`] is one of the most heavily used utilities in the curl codebase.
//! Every protocol handler, authentication module, and connection filter builds
//! protocol messages, accumulates response data, or constructs headers using
//! dynamic buffers.
//!
//! # C Correspondence
//!
//! | Rust                      | C                                       |
//! |---------------------------|-----------------------------------------|
//! | `DynBuf::new()`           | `curlx_dyn_init(s, DEFAULT_MAX_SIZE)`   |
//! | `DynBuf::with_max(n)`     | `curlx_dyn_init(s, n)`                  |
//! | `DynBuf::add(data)`       | `curlx_dyn_addn(s, data, len)`          |
//! | `DynBuf::add_str(s)`      | `curlx_dyn_add(s, str)`                 |
//! | `DynBuf::add_fmt(args)`   | `curlx_dyn_addf(s, fmt, ...)`           |
//! | `DynBuf::add_byte(b)`     | single-byte append                      |
//! | `DynBuf::as_bytes()`      | `curlx_dyn_ptr(s)` (data view)          |
//! | `DynBuf::as_cstr()`       | `curlx_dyn_ptr(s)` (NUL-terminated)     |
//! | `DynBuf::len()`           | `curlx_dyn_len(s)`                      |
//! | `DynBuf::reset()`         | `curlx_dyn_reset(s)`                    |
//! | `DynBuf::free()`          | `curlx_dyn_free(s)`                     |
//! | `DynBuf::take()`          | `curlx_dyn_take(s, &len)`               |
//! | `DynBuf::truncate(n)`     | `curlx_dyn_setlen(s, n)`                |
//!
//! # Design Notes
//!
//! Internally, `DynBuf` maintains a trailing NUL byte (`0x00`) in the backing
//! [`Vec<u8>`] whenever data is present, matching the C implementation that
//! always stores a NUL terminator at `bufr[leng]`. The NUL byte is **not**
//! counted by [`DynBuf::len()`] and is **not** visible from
//! [`DynBuf::as_bytes()`]. It is only accessible via [`DynBuf::as_cstr()`],
//! which returns the full NUL-terminated slice.
//!
//! On error (size ceiling exceeded or allocation failure), the buffer is
//! **freed** (deallocated), matching the C `dyn_nappend` / `curlx_dyn_free`
//! error semantics.

use std::borrow::Cow;
use std::fmt;
use std::io;

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum first allocation size in bytes.
///
/// Matches the C `#define MIN_FIRST_ALLOC 32` constant. The first [`add()`]
/// call on an empty [`DynBuf`] reserves at least this many bytes even if the
/// appended data is smaller, amortising future small appends.
///
/// [`add()`]: DynBuf::add
const MIN_FIRST_ALLOC: usize = 32;

/// Default maximum data size (10 MiB).
///
/// Each [`DynBuf`] instance enforces a ceiling on the data length to prevent
/// unbounded memory growth on malicious or malformed input. This default is
/// appropriate for general-purpose use; callers that need a different ceiling
/// should use [`DynBuf::with_max()`].
pub const DEFAULT_MAX_SIZE: usize = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// DynBuf
// ---------------------------------------------------------------------------

/// A dynamic growable byte buffer with a configurable size ceiling.
///
/// See the [module-level documentation](self) for design notes and C
/// correspondence.
#[derive(Clone)]
pub struct DynBuf {
    /// Byte storage.
    ///
    /// **Invariant:** When `inner` is non-empty the last byte is always
    /// `0x00` (the NUL terminator). The "data length" is therefore
    /// `inner.len() - 1` when non-empty and `0` when empty.
    inner: Vec<u8>,

    /// Maximum allowed *data* length (exclusive of the trailing NUL).
    max_size: usize,
}

// --- Construction ----------------------------------------------------------

impl DynBuf {
    /// Creates an empty `DynBuf` with the [`DEFAULT_MAX_SIZE`] ceiling.
    ///
    /// No heap allocation occurs until the first append operation, matching
    /// the lazy-allocation strategy of the C `curlx_dyn_init`.
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Vec::new(),
            max_size: DEFAULT_MAX_SIZE,
        }
    }

    /// Creates an empty `DynBuf` with a custom maximum data size.
    ///
    /// `max_size` is the largest number of data bytes (excluding the internal
    /// NUL terminator) that the buffer will accept. Appending beyond this
    /// limit returns [`CurlError::TooLarge`].
    #[inline]
    pub fn with_max(max_size: usize) -> Self {
        Self {
            inner: Vec::new(),
            max_size,
        }
    }

    /// Takes ownership of an existing `Vec<u8>`, applying the
    /// [`DEFAULT_MAX_SIZE`] ceiling.
    ///
    /// The contents of `v` are treated as the data payload. A trailing NUL
    /// byte is appended automatically so that the internal invariant is
    /// maintained. If `v` is empty, no allocation occurs.
    pub fn from_vec(mut v: Vec<u8>) -> Self {
        // Maintain the NUL-terminator invariant for non-empty data.
        if !v.is_empty() {
            v.push(0);
        }
        Self {
            inner: v,
            max_size: DEFAULT_MAX_SIZE,
        }
    }
}

// --- Append Operations -----------------------------------------------------

impl DynBuf {
    /// Appends a byte slice to the buffer.
    ///
    /// Returns [`CurlError::TooLarge`] if the resulting data length would
    /// exceed `max_size`. On error the buffer is **freed** (matching C
    /// `dyn_nappend` behaviour that calls `curlx_dyn_free` before returning
    /// an error code).
    ///
    /// Returns [`CurlError::OutOfMemory`] if the underlying allocation fails.
    pub fn add(&mut self, data: &[u8]) -> Result<(), CurlError> {
        if data.is_empty() {
            return Ok(());
        }

        let current_data_len = self.len();

        // Guard against usize overflow.
        let new_data_len = match current_data_len.checked_add(data.len()) {
            Some(n) => n,
            None => {
                self.free();
                return Err(CurlError::TooLarge);
            }
        };

        // Enforce the size ceiling.
        if new_data_len > self.max_size {
            self.free();
            return Err(CurlError::TooLarge);
        }

        if self.inner.is_empty() {
            // --- First allocation: honour MIN_FIRST_ALLOC. ---
            let needed = new_data_len + 1; // +1 for the NUL terminator
            let cap = if MIN_FIRST_ALLOC > self.max_size.saturating_add(1) {
                // max_size is smaller than MIN_FIRST_ALLOC — cap at max_size.
                self.max_size.saturating_add(1)
            } else if needed < MIN_FIRST_ALLOC {
                MIN_FIRST_ALLOC
            } else {
                needed
            };

            self.inner.try_reserve(cap).map_err(|_| {
                // Cannot free() here — inner is already empty.
                CurlError::OutOfMemory
            })?;
        } else {
            // --- Subsequent allocation: Vec doubles capacity on its own. ---
            // `try_reserve(data.len())` on the pre-pop Vec guarantees:
            //   capacity >= (current_data_len + 1) + data.len()
            //             = new_data_len + 1   ✓
            self.inner.try_reserve(data.len()).map_err(|_| {
                self.free();
                CurlError::OutOfMemory
            })?;

            // Remove the trailing NUL before extending.
            self.inner.pop();
        }

        // Append the new data and restore the NUL terminator.
        self.inner.extend_from_slice(data);
        self.inner.push(0);

        Ok(())
    }

    /// Appends a UTF-8 string to the buffer.
    ///
    /// This is a convenience wrapper around [`add()`](Self::add).
    #[inline]
    pub fn add_str(&mut self, s: &str) -> Result<(), CurlError> {
        self.add(s.as_bytes())
    }

    /// Appends formatted output to the buffer (matches C `curlx_dyn_addf`).
    ///
    /// Formatting is performed directly into the buffer without allocating an
    /// intermediate `String`. Use with the [`format_args!()`] macro:
    ///
    /// ```ignore
    /// buf.add_fmt(format_args!("Content-Length: {}\r\n", length))?;
    /// ```
    pub fn add_fmt(&mut self, args: fmt::Arguments<'_>) -> Result<(), CurlError> {
        // Use a helper adapter that captures the real `CurlError` rather
        // than losing it through `fmt::Error`.
        struct Adapter<'a> {
            buf: &'a mut DynBuf,
            err: Option<CurlError>,
        }

        impl<'a> fmt::Write for Adapter<'a> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                match self.buf.add_str(s) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        self.err = Some(e);
                        Err(fmt::Error)
                    }
                }
            }
        }

        let mut adapter = Adapter {
            buf: self,
            err: None,
        };
        match fmt::Write::write_fmt(&mut adapter, args) {
            Ok(()) => Ok(()),
            Err(_) => Err(adapter.err.unwrap_or(CurlError::OutOfMemory)),
        }
    }

    /// Appends a single byte to the buffer.
    #[inline]
    pub fn add_byte(&mut self, byte: u8) -> Result<(), CurlError> {
        self.add(&[byte])
    }
}

// --- Content Access --------------------------------------------------------

impl DynBuf {
    /// Returns the data as a byte slice (**without** the trailing NUL).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        let data_len = self.len();
        if data_len == 0 {
            &[]
        } else {
            // SAFETY invariant: inner.len() >= 1 (contains at least the NUL),
            // so data_len = inner.len() - 1 is a valid slice end index.
            &self.inner[..data_len]
        }
    }

    /// Returns the data as a UTF-8 string, or `None` if the content is not
    /// valid UTF-8.
    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()).ok()
    }

    /// Returns the data as a UTF-8 string, replacing invalid sequences with
    /// the Unicode replacement character (U+FFFD).
    #[inline]
    pub fn as_str_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.as_bytes())
    }

    /// Returns the number of data bytes in the buffer.
    ///
    /// The trailing NUL terminator is **not** counted, matching C
    /// `curlx_dyn_len` semantics.
    #[inline]
    pub fn len(&self) -> usize {
        // When inner is non-empty the last byte is always the NUL terminator,
        // so the data length is `inner.len() - 1`.
        if self.inner.is_empty() {
            0
        } else {
            self.inner.len() - 1
        }
    }

    /// Returns `true` if the buffer contains no data bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the current heap-allocated capacity in bytes (including the
    /// space reserved for the trailing NUL).
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}

// --- Modification Operations -----------------------------------------------

impl DynBuf {
    /// Clears all data but **retains** the allocated memory for reuse.
    ///
    /// After `reset()`, [`len()`](Self::len) returns `0` and
    /// [`capacity()`](Self::capacity) is unchanged. This matches C
    /// `curlx_dyn_reset`.
    pub fn reset(&mut self) {
        if !self.inner.is_empty() {
            // Keep exactly one byte (the NUL) to preserve the allocation.
            self.inner.truncate(1);
            self.inner[0] = 0;
        }
    }

    /// Clears all data **and** deallocates the backing memory.
    ///
    /// After `free()`, both [`len()`](Self::len) and
    /// [`capacity()`](Self::capacity) return `0`. This matches C
    /// `curlx_dyn_free`.
    pub fn free(&mut self) {
        self.inner = Vec::new();
    }

    /// Truncates the data to `len` bytes, keeping the first `len` bytes and
    /// discarding the rest.
    ///
    /// If `len >= self.len()` this is a no-op. The trailing NUL terminator is
    /// maintained automatically. This matches C `curlx_dyn_setlen` semantics
    /// (which returns [`CurlError::BadFunctionArgument`] when the requested
    /// length exceeds the current length — in Rust we silently no-op for
    /// ergonomics, consistent with [`Vec::truncate`]).
    pub fn truncate(&mut self, len: usize) {
        let current = self.len();
        if len < current {
            if len == 0 {
                self.reset();
            } else {
                // Keep data[0..len] plus the NUL terminator.
                self.inner.truncate(len + 1);
                self.inner[len] = 0;
            }
        }
    }

    /// Takes ownership of the inner `Vec<u8>` (data bytes only, **without**
    /// the trailing NUL), leaving `self` empty and deallocated.
    ///
    /// This matches C `curlx_dyn_take` which transfers buffer ownership to
    /// the caller and resets the dynbuf.
    pub fn take(&mut self) -> Vec<u8> {
        let mut v = std::mem::take(&mut self.inner);
        // Remove the trailing NUL so the caller receives only data bytes.
        if !v.is_empty() {
            v.pop();
        }
        v
    }

    /// Releases excess allocated capacity, shrinking the backing allocation
    /// to fit the current data length plus the NUL terminator.
    pub fn shrink_to_fit(&mut self) {
        self.inner.shrink_to_fit();
    }
}

// --- NUL-Terminated Access (FFI support) -----------------------------------

impl DynBuf {
    /// Returns the data as a byte slice **with** a guaranteed trailing NUL
    /// byte (`0x00`).
    ///
    /// When the buffer is empty a static `&[0u8]` is returned so that the
    /// caller always receives a valid NUL-terminated slice. This matches C
    /// `curlx_dyn_ptr` which always returns a NUL-terminated pointer (or
    /// `NULL` for an uninitialised buffer).
    #[inline]
    pub fn as_cstr(&self) -> &[u8] {
        if self.inner.is_empty() {
            // Return a static NUL-terminated empty slice.
            &[0u8]
        } else {
            &self.inner[..]
        }
    }
}

// --- Trait Implementations -------------------------------------------------

impl Default for DynBuf {
    /// Creates an empty [`DynBuf`] with the default ceiling, identical to
    /// [`DynBuf::new()`].
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DynBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynBuf")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .field("max_size", &self.max_size)
            .field("data", &self.as_str_lossy())
            .finish()
    }
}

/// Allows using [`DynBuf`] as an [`io::Write`] target, enabling binary I/O
/// operations such as `write_all` and `write_fmt`.
///
/// Errors from the underlying [`DynBuf::add`] call are mapped to
/// [`io::Error`] with [`io::ErrorKind::Other`].
impl io::Write for DynBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.add(buf).map_err(io::Error::other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // No additional buffering beyond the inner Vec.
        Ok(())
    }
}

/// Allows using [`DynBuf`] as a [`fmt::Write`] target, enabling the
/// `write!` and `writeln!` macros for string formatting.
impl fmt::Write for DynBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.add_str(s).map_err(|_| fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Construction ------------------------------------------------------

    #[test]
    fn new_creates_empty_buffer() {
        let buf = DynBuf::new();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.as_bytes(), &[]);
        assert_eq!(buf.capacity(), 0);
    }

    #[test]
    fn with_max_sets_ceiling() {
        let buf = DynBuf::with_max(100);
        assert!(buf.is_empty());
        assert_eq!(buf.max_size, 100);
    }

    #[test]
    fn from_vec_takes_ownership() {
        let buf = DynBuf::from_vec(vec![65, 66, 67]);
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.as_bytes(), b"ABC");
        assert_eq!(buf.as_str(), Some("ABC"));
    }

    #[test]
    fn from_vec_empty() {
        let buf = DynBuf::from_vec(Vec::new());
        assert!(buf.is_empty());
        assert_eq!(buf.as_bytes(), &[]);
    }

    // --- Append Operations -------------------------------------------------

    #[test]
    fn add_bytes_grows_buffer() {
        let mut buf = DynBuf::new();
        buf.add(b"hello").unwrap();
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_bytes(), b"hello");

        buf.add(b" world").unwrap();
        assert_eq!(buf.len(), 11);
        assert_eq!(buf.as_bytes(), b"hello world");
    }

    #[test]
    fn add_empty_slice_is_noop() {
        let mut buf = DynBuf::new();
        buf.add(b"").unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn add_str_appends_utf8() {
        let mut buf = DynBuf::new();
        buf.add_str("hello ").unwrap();
        buf.add_str("世界").unwrap();
        assert_eq!(buf.as_str(), Some("hello 世界"));
    }

    #[test]
    fn add_byte_appends_single() {
        let mut buf = DynBuf::new();
        buf.add_byte(b'A').unwrap();
        buf.add_byte(b'B').unwrap();
        assert_eq!(buf.as_bytes(), b"AB");
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn add_fmt_formats_directly() {
        let mut buf = DynBuf::new();
        buf.add_fmt(format_args!("n={}, s={}", 42, "ok")).unwrap();
        assert_eq!(buf.as_str(), Some("n=42, s=ok"));
    }

    // --- Max Size Enforcement ----------------------------------------------

    #[test]
    fn add_exceeding_max_size_returns_too_large() {
        let mut buf = DynBuf::with_max(10);
        buf.add(b"12345").unwrap();
        let err = buf.add(b"678901").unwrap_err();
        assert_eq!(err, CurlError::TooLarge);
        // Buffer is freed on error (C behaviour).
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), 0);
    }

    #[test]
    fn add_exactly_at_max_size_succeeds() {
        let mut buf = DynBuf::with_max(5);
        buf.add(b"12345").unwrap();
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn add_fmt_exceeding_max_returns_too_large() {
        let mut buf = DynBuf::with_max(5);
        let err = buf.add_fmt(format_args!("hello world")).unwrap_err();
        assert_eq!(err, CurlError::TooLarge);
    }

    #[test]
    fn add_str_exceeding_max_returns_too_large() {
        let mut buf = DynBuf::with_max(3);
        let err = buf.add_str("abcdef").unwrap_err();
        assert_eq!(err, CurlError::TooLarge);
        assert!(buf.is_empty());
    }

    #[test]
    fn add_byte_exceeding_max_returns_too_large() {
        let mut buf = DynBuf::with_max(2);
        buf.add_byte(b'A').unwrap();
        buf.add_byte(b'B').unwrap();
        let err = buf.add_byte(b'C').unwrap_err();
        assert_eq!(err, CurlError::TooLarge);
    }

    // --- Content Access ----------------------------------------------------

    #[test]
    fn as_bytes_on_empty() {
        let buf = DynBuf::new();
        assert_eq!(buf.as_bytes(), &[]);
    }

    #[test]
    fn as_str_returns_none_for_invalid_utf8() {
        let mut buf = DynBuf::new();
        buf.add(&[0xFF, 0xFE]).unwrap();
        assert!(buf.as_str().is_none());
    }

    #[test]
    fn as_str_lossy_replaces_invalid() {
        let mut buf = DynBuf::new();
        buf.add(b"ok").unwrap();
        buf.add(&[0xFF]).unwrap();
        let s = buf.as_str_lossy();
        assert!(s.contains("ok"));
        assert!(s.contains('\u{FFFD}'));
    }

    #[test]
    fn len_and_is_empty() {
        let mut buf = DynBuf::new();
        assert!(buf.is_empty());
        buf.add(b"x").unwrap();
        assert!(!buf.is_empty());
        assert_eq!(buf.len(), 1);
    }

    // --- Modification Operations -------------------------------------------

    #[test]
    fn reset_clears_data_keeps_capacity() {
        let mut buf = DynBuf::new();
        buf.add(b"some data here").unwrap();
        let cap_before = buf.capacity();
        buf.reset();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.as_bytes(), &[]);
        // Capacity should be preserved.
        assert!(buf.capacity() > 0);
        assert_eq!(buf.capacity(), cap_before);
    }

    #[test]
    fn reset_on_empty_is_noop() {
        let mut buf = DynBuf::new();
        buf.reset();
        assert!(buf.is_empty());
    }

    #[test]
    fn free_clears_and_deallocates() {
        let mut buf = DynBuf::new();
        buf.add(b"data").unwrap();
        buf.free();
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), 0);
    }

    #[test]
    fn truncate_shortens_data() {
        let mut buf = DynBuf::new();
        buf.add(b"abcdef").unwrap();
        buf.truncate(3);
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.as_bytes(), b"abc");
    }

    #[test]
    fn truncate_to_zero_resets() {
        let mut buf = DynBuf::new();
        buf.add(b"abcdef").unwrap();
        buf.truncate(0);
        assert!(buf.is_empty());
        assert!(buf.capacity() > 0); // allocation kept
    }

    #[test]
    fn truncate_beyond_len_is_noop() {
        let mut buf = DynBuf::new();
        buf.add(b"abc").unwrap();
        buf.truncate(100);
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.as_bytes(), b"abc");
    }

    #[test]
    fn take_transfers_ownership() {
        let mut buf = DynBuf::new();
        buf.add(b"hello").unwrap();
        let v = buf.take();
        assert_eq!(v, b"hello");
        // DynBuf is now empty.
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), 0);
    }

    #[test]
    fn take_on_empty() {
        let mut buf = DynBuf::new();
        let v = buf.take();
        assert!(v.is_empty());
    }

    #[test]
    fn shrink_to_fit_reduces_capacity() {
        let mut buf = DynBuf::new();
        // Add a lot of data then truncate to provoke excess capacity.
        buf.add(&[b'X'; 1000]).unwrap();
        buf.truncate(5);
        let cap_before = buf.capacity();
        buf.shrink_to_fit();
        assert!(buf.capacity() <= cap_before);
        assert_eq!(buf.len(), 5);
    }

    // --- NUL-Terminated Access ---------------------------------------------

    #[test]
    fn as_cstr_on_empty() {
        let buf = DynBuf::new();
        let cstr = buf.as_cstr();
        assert_eq!(cstr, &[0u8]);
        assert_eq!(cstr.last(), Some(&0u8));
    }

    #[test]
    fn as_cstr_on_data() {
        let mut buf = DynBuf::new();
        buf.add(b"abc").unwrap();
        let cstr = buf.as_cstr();
        assert_eq!(cstr, &[b'a', b'b', b'c', 0]);
        assert_eq!(cstr.last(), Some(&0u8));
    }

    #[test]
    fn as_cstr_after_reset() {
        let mut buf = DynBuf::new();
        buf.add(b"abc").unwrap();
        buf.reset();
        let cstr = buf.as_cstr();
        // After reset inner is [0], so as_cstr returns [0].
        assert_eq!(cstr, &[0u8]);
    }

    // --- Write Trait Implementations ---------------------------------------

    #[test]
    fn io_write_trait() {
        use std::io::Write;
        let mut buf = DynBuf::new();
        write!(buf, "test {}", 123).unwrap();
        assert_eq!(buf.as_str(), Some("test 123"));
    }

    #[test]
    fn fmt_write_trait() {
        use std::fmt::Write;
        let mut buf = DynBuf::new();
        write!(buf, "fmt {}", 456).unwrap();
        assert_eq!(buf.as_str(), Some("fmt 456"));
    }

    #[test]
    fn io_write_respects_max_size() {
        use std::io::Write;
        let mut buf = DynBuf::with_max(4);
        let result = buf.write_all(b"too long");
        assert!(result.is_err());
    }

    // --- Growth Strategy ---------------------------------------------------

    #[test]
    fn first_alloc_uses_min_first_alloc() {
        let mut buf = DynBuf::new();
        buf.add(b"x").unwrap();
        // First allocation should be at least MIN_FIRST_ALLOC.
        assert!(buf.capacity() >= MIN_FIRST_ALLOC);
    }

    #[test]
    fn first_alloc_with_small_max() {
        let mut buf = DynBuf::with_max(8);
        buf.add(b"hi").unwrap();
        // Capacity should not exceed max_size + 1 (NUL).
        assert!(buf.capacity() <= buf.max_size + 1 + 16); // allow allocator overhead
    }

    #[test]
    fn multiple_appends_grow_correctly() {
        let mut buf = DynBuf::new();
        for i in 0..100 {
            buf.add_fmt(format_args!("line {}\n", i)).unwrap();
        }
        assert!(buf.len() > 400);
        // All lines should be present.
        let s = buf.as_str().unwrap();
        assert!(s.contains("line 0\n"));
        assert!(s.contains("line 99\n"));
    }

    // --- Reuse after Error -------------------------------------------------

    #[test]
    fn reuse_after_too_large_error() {
        let mut buf = DynBuf::with_max(5);
        buf.add(b"12345").unwrap();
        let _ = buf.add(b"6"); // fails with TooLarge, buffer freed
        assert!(buf.is_empty());
        // Buffer should be reusable.
        buf.add(b"abc").unwrap();
        assert_eq!(buf.as_bytes(), b"abc");
    }

    #[test]
    fn reuse_after_free() {
        let mut buf = DynBuf::new();
        buf.add(b"first").unwrap();
        buf.free();
        buf.add(b"second").unwrap();
        assert_eq!(buf.as_bytes(), b"second");
    }

    // --- Edge Cases --------------------------------------------------------

    #[test]
    fn max_size_zero_rejects_all() {
        let mut buf = DynBuf::with_max(0);
        let err = buf.add(b"a").unwrap_err();
        assert_eq!(err, CurlError::TooLarge);
    }

    #[test]
    fn max_size_one_allows_single_byte() {
        let mut buf = DynBuf::with_max(1);
        buf.add_byte(b'X').unwrap();
        assert_eq!(buf.len(), 1);
        let err = buf.add_byte(b'Y').unwrap_err();
        assert_eq!(err, CurlError::TooLarge);
    }

    #[test]
    fn clone_produces_independent_copy() {
        let mut buf = DynBuf::new();
        buf.add(b"original").unwrap();
        let mut cloned = buf.clone();
        cloned.add(b" extra").unwrap();
        assert_eq!(buf.as_bytes(), b"original");
        assert_eq!(cloned.as_bytes(), b"original extra");
    }

    #[test]
    fn debug_format() {
        let mut buf = DynBuf::new();
        buf.add(b"test").unwrap();
        let dbg = format!("{:?}", buf);
        assert!(dbg.contains("DynBuf"));
        assert!(dbg.contains("test"));
    }

    #[test]
    fn default_is_new() {
        let buf: DynBuf = Default::default();
        assert!(buf.is_empty());
        assert_eq!(buf.max_size, DEFAULT_MAX_SIZE);
    }

    // --- NUL Invariant Consistency -----------------------------------------

    #[test]
    fn nul_invariant_after_operations() {
        let mut buf = DynBuf::new();

        // Empty: no NUL in inner.
        assert!(buf.inner.is_empty());

        // After add: trailing NUL present.
        buf.add(b"abc").unwrap();
        assert_eq!(buf.inner.last(), Some(&0u8));
        assert_eq!(buf.inner.len(), 4); // 3 data + 1 NUL

        // After reset: single NUL.
        buf.reset();
        assert_eq!(buf.inner, vec![0u8]);

        // After add post-reset: NUL maintained.
        buf.add(b"xy").unwrap();
        assert_eq!(buf.inner.last(), Some(&0u8));
        assert_eq!(buf.inner.len(), 3); // 2 data + 1 NUL

        // After truncate: NUL maintained.
        buf.truncate(1);
        assert_eq!(buf.inner, vec![b'x', 0u8]);

        // After free: empty.
        buf.free();
        assert!(buf.inner.is_empty());
    }
}
