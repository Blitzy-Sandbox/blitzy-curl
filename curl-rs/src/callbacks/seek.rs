// curl-rs/src/callbacks/seek.rs
//
// Seek callback for repositioning the upload input stream during transfer
// retry and resume scenarios.
//
// This is the Rust rewrite of `src/tool_cb_see.c` and `src/tool_cb_see.h`
// from curl 8.19.0-DEV.  The C implementation provides a
// `CURLOPT_SEEKFUNCTION` callback that libcurl invokes when it needs to
// rewind or reposition the upload data source (e.g., after a redirect
// during a POST, or when retrying a failed upload).
//
// ## Key Simplification vs. C
//
// The C source contains a chunked-seeking code path activated on 32-bit
// platforms where `sizeof(off_t) < sizeof(curl_off_t)`:
//
// ```c
// #define OUR_MAX_SEEK_L  2147483646   /* (2^31 - 2) */
// while (offset > OUR_MAX_SEEK_L) {
//     lseek(fd, OUR_MAX_SEEK_L, SEEK_CUR);
//     offset -= OUR_MAX_SEEK_L;
// }
// lseek(fd, (off_t)offset, whence);
// ```
//
// This entire loop is **unnecessary in Rust** because:
// - `std::io::Seek::seek()` always uses `u64`/`i64` natively
// - Rust's standard library dispatches to `lseek64` / `_lseeki64` on
//   platforms that require it
// - There is no `off_t` truncation risk in safe Rust
//
// The Rust implementation achieves identical functional behavior on all
// platforms with a single `input.seek(pos)` call.
//
// ## Return Code ABI Contract
//
// The integer return codes are part of the libcurl C ABI and **MUST**
// match exactly:
//
// | Constant               | Value | Meaning                            |
// |------------------------|-------|------------------------------------|
// | CURL_SEEKFUNC_OK       |   0   | Seek succeeded                     |
// | CURL_SEEKFUNC_FAIL     |   1   | Hard failure — abort transfer      |
// | CURL_SEEKFUNC_CANTSEEK |   2   | Seek not possible — try fallback   |
//
// SPDX-License-Identifier: curl

use std::io::{Seek, SeekFrom};

// ---------------------------------------------------------------------------
// SeekResult — typed representation of CURL_SEEKFUNC_* return codes
// ---------------------------------------------------------------------------

/// Result codes returned by the seek callback, corresponding 1:1 to the
/// `CURL_SEEKFUNC_*` constants from the libcurl C API.
///
/// The integer discriminant values are part of the ABI contract between
/// the CLI tool and the underlying transfer engine and **must not** be
/// changed.
///
/// # Variants
///
/// * `Ok` (0) — The seek completed successfully.  The transfer engine
///   may proceed with data at the new stream position.
///
/// * `Fail` (1) — A hard, unrecoverable failure occurred.  The transfer
///   engine should abort the current transfer immediately.
///
/// * `CantSeek` (2) — The stream does not support seeking (e.g., a pipe
///   or network socket).  The transfer engine will fall back to an
///   alternative strategy such as re-reading and discarding bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SeekResult {
    /// Seek succeeded — corresponds to `CURL_SEEKFUNC_OK` (0).
    Ok = 0,

    /// Hard failure — corresponds to `CURL_SEEKFUNC_FAIL` (1).
    Fail = 1,

    /// Seek not possible — corresponds to `CURL_SEEKFUNC_CANTSEEK` (2).
    CantSeek = 2,
}

impl SeekResult {
    /// Convert the enum variant to its integer representation.
    ///
    /// The returned value matches the `CURL_SEEKFUNC_*` C constants:
    /// `Ok` → 0, `Fail` → 1, `CantSeek` → 2.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs::callbacks::seek::SeekResult;
    /// assert_eq!(SeekResult::Ok.as_i32(), 0);
    /// assert_eq!(SeekResult::Fail.as_i32(), 1);
    /// assert_eq!(SeekResult::CantSeek.as_i32(), 2);
    /// ```
    #[inline]
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Attempt to create a `SeekResult` from its integer representation.
    ///
    /// Returns `Some(variant)` for valid values (0, 1, 2) and `None` for
    /// anything else.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs::callbacks::seek::SeekResult;
    /// assert_eq!(SeekResult::from_i32(0), Some(SeekResult::Ok));
    /// assert_eq!(SeekResult::from_i32(1), Some(SeekResult::Fail));
    /// assert_eq!(SeekResult::from_i32(2), Some(SeekResult::CantSeek));
    /// assert_eq!(SeekResult::from_i32(99), None);
    /// ```
    #[inline]
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(SeekResult::Ok),
            1 => Some(SeekResult::Fail),
            2 => Some(SeekResult::CantSeek),
            _ => None,
        }
    }
}

impl std::fmt::Display for SeekResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeekResult::Ok => write!(f, "CURL_SEEKFUNC_OK(0)"),
            SeekResult::Fail => write!(f, "CURL_SEEKFUNC_FAIL(1)"),
            SeekResult::CantSeek => write!(f, "CURL_SEEKFUNC_CANTSEEK(2)"),
        }
    }
}

// ---------------------------------------------------------------------------
// whence_to_seekfrom — C whence integer → Rust SeekFrom conversion
// ---------------------------------------------------------------------------

/// Maps a C-style `whence` integer and `offset` to a Rust [`SeekFrom`] value.
///
/// The C `lseek()` family uses integer constants for the seek origin:
///
/// | Constant  | Value | Rust Equivalent          |
/// |-----------|-------|--------------------------|
/// | SEEK_SET  |   0   | `SeekFrom::Start(n)`     |
/// | SEEK_CUR  |   1   | `SeekFrom::Current(n)`   |
/// | SEEK_END  |   2   | `SeekFrom::End(n)`       |
///
/// # Arguments
///
/// * `whence` — The seek origin as a C-style integer (0, 1, or 2).
/// * `offset` — The byte offset for the seek operation.
///
/// # Returns
///
/// * `Some(SeekFrom)` — Successfully mapped to a valid `SeekFrom`.
/// * `None` — Either `whence` is not a valid origin constant, or
///   `offset` is negative when `whence` is `SEEK_SET` (which requires
///   a non-negative position).
///
/// # Examples
///
/// ```
/// # use std::io::SeekFrom;
/// # use curl_rs::callbacks::seek::whence_to_seekfrom;
/// assert_eq!(whence_to_seekfrom(0, 100), Some(SeekFrom::Start(100)));
/// assert_eq!(whence_to_seekfrom(1, -50), Some(SeekFrom::Current(-50)));
/// assert_eq!(whence_to_seekfrom(2, -10), Some(SeekFrom::End(-10)));
/// assert_eq!(whence_to_seekfrom(0, -1), None);   // negative SEEK_SET
/// assert_eq!(whence_to_seekfrom(99, 0), None);   // invalid whence
/// ```
pub fn whence_to_seekfrom(whence: i32, offset: i64) -> Option<SeekFrom> {
    match whence {
        // SEEK_SET (0): Position the stream at an absolute byte offset.
        // The offset must be non-negative because `SeekFrom::Start` takes
        // a `u64` — negative values are physically meaningless for an
        // absolute position.
        0 => {
            if offset < 0 {
                None
            } else {
                Some(SeekFrom::Start(offset as u64))
            }
        }
        // SEEK_CUR (1): Position relative to the current stream location.
        // Negative offsets move backward; positive offsets move forward.
        1 => Some(SeekFrom::Current(offset)),
        // SEEK_END (2): Position relative to the end of the stream.
        // Typically negative (positioning before EOF) or zero (at EOF).
        2 => Some(SeekFrom::End(offset)),
        // Any other value is not a valid C seek origin.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// tool_seek_cb — core seek callback (typed Rust API)
// ---------------------------------------------------------------------------

/// Seek callback for repositioning the upload input stream.
///
/// This is the Rust equivalent of `tool_seek_cb()` from
/// `src/tool_cb_see.c`.  It repositions the input stream used for
/// upload data during transfer retry and resume scenarios.
///
/// The function accepts a pre-computed [`SeekFrom`] value (the typed
/// Rust equivalent of the C `(offset, whence)` pair).  For callers
/// that have raw C-style integer parameters, use [`make_seek_callback`]
/// which handles the conversion automatically.
///
/// # Type Parameter
///
/// The `S: Seek + ?Sized` bound allows this function to work with both
/// concrete types (`std::fs::File`) and trait objects (`dyn Seek`),
/// enabling use from both monomorphized call sites and the dynamic
/// closure returned by [`make_seek_callback`].
///
/// # Arguments
///
/// * `input` — A mutable reference to any seekable stream (typically
///   a `std::fs::File` for file-based uploads).
/// * `offset` — The raw byte offset value.  This is provided for
///   informational/logging purposes; the actual seek position
///   is fully encoded in `seek_pos`.
/// * `seek_pos` — A [`SeekFrom`] that encodes both the origin and the
///   offset for the seek operation.
///
/// # Returns
///
/// * [`SeekResult::Ok`] — Seek succeeded.
/// * [`SeekResult::CantSeek`] — Seek failed.  This matches the C
///   implementation's behavior of returning `CURL_SEEKFUNC_CANTSEEK`
///   (not `CURL_SEEKFUNC_FAIL`) when `lseek()` returns -1.
///
/// # Error Handling
///
/// All `std::io::Error` variants from the `seek()` call are mapped to
/// `SeekResult::CantSeek`.  This matches the original C behavior where
/// `lseek()` failure (returning -1) always produces
/// `CURL_SEEKFUNC_CANTSEEK`, allowing libcurl to fall back to
/// alternative strategies rather than hard-aborting the transfer.
///
/// # Panics
///
/// This function **never panics**.  All error paths are handled
/// gracefully through the `SeekResult` return value.
pub fn tool_seek_cb<S: Seek + ?Sized>(
    input: &mut S,
    _offset: i64,
    seek_pos: SeekFrom,
) -> SeekResult {
    // Perform the seek operation.
    //
    // In Rust, `Seek::seek()` uses `u64`/`i64` internally on all
    // platforms.  The standard library transparently calls `lseek64` or
    // `_lseeki64` where needed, so the C chunked-seeking loop
    // (OUR_MAX_SEEK_L = 2,147,483,646) is entirely unnecessary.
    //
    // A single `seek()` call achieves identical behavior on both 32-bit
    // and 64-bit platforms.
    match input.seek(seek_pos) {
        // Seek completed successfully — stream is now positioned at the
        // requested location.
        Result::Ok(_new_position) => SeekResult::Ok,

        // Seek failed — return CantSeek to signal that the stream cannot
        // be repositioned.  This matches the C behavior:
        //
        //   if(lseek(per->infd, seekerr, ...) == -1)
        //       return CURL_SEEKFUNC_CANTSEEK;
        //
        // By returning CantSeek (not Fail), we allow the transfer engine
        // to attempt fallback strategies such as re-reading the stream
        // from the beginning and discarding bytes up to the desired
        // offset.
        Result::Err(_io_error) => SeekResult::CantSeek,
    }
}

// ---------------------------------------------------------------------------
// make_seek_callback — factory for C-ABI-compatible callback closure
// ---------------------------------------------------------------------------

/// Creates a seek callback closure that bridges C-style integer
/// parameters to the typed Rust [`tool_seek_cb`] function.
///
/// The returned closure accepts the same parameter shapes as the C
/// `CURLOPT_SEEKFUNCTION` callback signature:
///
/// ```c
/// int seek_func(void *userdata, curl_off_t offset, int whence);
/// ```
///
/// mapped to Rust as:
///
/// ```text
/// Fn(&mut dyn Seek, i64, i32) -> i32
/// ```
///
/// # Return Value
///
/// The closure returns an `i32` matching the `CURL_SEEKFUNC_*` integer
/// constants:
/// - `0` — `CURL_SEEKFUNC_OK`
/// - `1` — `CURL_SEEKFUNC_FAIL`
/// - `2` — `CURL_SEEKFUNC_CANTSEEK`
///
/// # Parameter Mapping
///
/// | Closure Param | C Equivalent    | Description                     |
/// |---------------|------------------|---------------------------------|
/// | `&mut dyn Seek` | `void *userdata` | Input stream (seekable)       |
/// | `i64`         | `curl_off_t`     | Byte offset for the seek        |
/// | `i32`         | `int whence`     | Seek origin (0=SET, 1=CUR, 2=END) |
///
/// # Error Handling
///
/// - Invalid `whence` values (not 0, 1, or 2) → returns
///   `CURL_SEEKFUNC_FAIL` (1).
/// - Negative offset with `SEEK_SET` → returns `CURL_SEEKFUNC_FAIL` (1).
/// - I/O errors during seek → returns `CURL_SEEKFUNC_CANTSEEK` (2).
///
/// # Examples
///
/// ```no_run
/// use std::fs::File;
/// use std::io::Seek;
/// use curl_rs::callbacks::seek::make_seek_callback;
///
/// let seek_cb = make_seek_callback();
/// let mut file = File::open("upload.dat").unwrap();
/// // Seek to absolute position 1024 (SEEK_SET = 0)
/// let result = seek_cb(&mut file, 1024, 0);
/// assert_eq!(result, 0); // CURL_SEEKFUNC_OK
/// ```
pub fn make_seek_callback() -> impl Fn(&mut dyn Seek, i64, i32) -> i32 {
    move |input: &mut dyn Seek, offset: i64, whence: i32| -> i32 {
        // Convert the C-style (whence, offset) pair into a typed SeekFrom.
        // If the conversion fails (invalid whence or negative SEEK_SET
        // offset), return CURL_SEEKFUNC_FAIL immediately.
        let seek_pos = match whence_to_seekfrom(whence, offset) {
            Some(pos) => pos,
            None => return SeekResult::Fail.as_i32(),
        };

        // Delegate to the typed seek callback and convert the result
        // back to an integer for the C-ABI boundary.
        tool_seek_cb(input, offset, seek_pos).as_i32()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Seek, SeekFrom};

    // -- SeekResult tests --------------------------------------------------

    #[test]
    fn seek_result_integer_values_match_curl_constants() {
        // CURL_SEEKFUNC_OK = 0
        assert_eq!(SeekResult::Ok.as_i32(), 0);
        // CURL_SEEKFUNC_FAIL = 1
        assert_eq!(SeekResult::Fail.as_i32(), 1);
        // CURL_SEEKFUNC_CANTSEEK = 2
        assert_eq!(SeekResult::CantSeek.as_i32(), 2);
    }

    #[test]
    fn seek_result_from_i32_valid_values() {
        assert_eq!(SeekResult::from_i32(0), Some(SeekResult::Ok));
        assert_eq!(SeekResult::from_i32(1), Some(SeekResult::Fail));
        assert_eq!(SeekResult::from_i32(2), Some(SeekResult::CantSeek));
    }

    #[test]
    fn seek_result_from_i32_invalid_values() {
        assert_eq!(SeekResult::from_i32(-1), None);
        assert_eq!(SeekResult::from_i32(3), None);
        assert_eq!(SeekResult::from_i32(99), None);
        assert_eq!(SeekResult::from_i32(i32::MIN), None);
        assert_eq!(SeekResult::from_i32(i32::MAX), None);
    }

    #[test]
    fn seek_result_display_formatting() {
        assert_eq!(format!("{}", SeekResult::Ok), "CURL_SEEKFUNC_OK(0)");
        assert_eq!(format!("{}", SeekResult::Fail), "CURL_SEEKFUNC_FAIL(1)");
        assert_eq!(
            format!("{}", SeekResult::CantSeek),
            "CURL_SEEKFUNC_CANTSEEK(2)"
        );
    }

    #[test]
    fn seek_result_equality_and_copy() {
        let a = SeekResult::Ok;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_eq!(a, SeekResult::Ok);
        assert_ne!(a, SeekResult::Fail);
    }

    // -- whence_to_seekfrom tests ------------------------------------------

    #[test]
    fn whence_seek_set_positive_offset() {
        assert_eq!(
            whence_to_seekfrom(0, 0),
            Some(SeekFrom::Start(0))
        );
        assert_eq!(
            whence_to_seekfrom(0, 100),
            Some(SeekFrom::Start(100))
        );
        assert_eq!(
            whence_to_seekfrom(0, i64::MAX),
            Some(SeekFrom::Start(i64::MAX as u64))
        );
    }

    #[test]
    fn whence_seek_set_negative_offset_returns_none() {
        assert_eq!(whence_to_seekfrom(0, -1), None);
        assert_eq!(whence_to_seekfrom(0, -100), None);
        assert_eq!(whence_to_seekfrom(0, i64::MIN), None);
    }

    #[test]
    fn whence_seek_cur() {
        assert_eq!(
            whence_to_seekfrom(1, 0),
            Some(SeekFrom::Current(0))
        );
        assert_eq!(
            whence_to_seekfrom(1, 50),
            Some(SeekFrom::Current(50))
        );
        assert_eq!(
            whence_to_seekfrom(1, -50),
            Some(SeekFrom::Current(-50))
        );
    }

    #[test]
    fn whence_seek_end() {
        assert_eq!(
            whence_to_seekfrom(2, 0),
            Some(SeekFrom::End(0))
        );
        assert_eq!(
            whence_to_seekfrom(2, -10),
            Some(SeekFrom::End(-10))
        );
        assert_eq!(
            whence_to_seekfrom(2, 10),
            Some(SeekFrom::End(10))
        );
    }

    #[test]
    fn whence_invalid_values_return_none() {
        assert_eq!(whence_to_seekfrom(-1, 0), None);
        assert_eq!(whence_to_seekfrom(3, 0), None);
        assert_eq!(whence_to_seekfrom(99, 0), None);
        assert_eq!(whence_to_seekfrom(i32::MAX, 0), None);
        assert_eq!(whence_to_seekfrom(i32::MIN, 0), None);
    }

    // -- tool_seek_cb tests ------------------------------------------------

    #[test]
    fn tool_seek_cb_seek_set_success() {
        let data = vec![0u8; 1024];
        let mut cursor = Cursor::new(data);

        let result = tool_seek_cb(&mut cursor, 512, SeekFrom::Start(512));
        assert_eq!(result, SeekResult::Ok);
        assert_eq!(cursor.position(), 512);
    }

    #[test]
    fn tool_seek_cb_seek_set_beginning() {
        let data = vec![0u8; 256];
        let mut cursor = Cursor::new(data);

        // Move to position 100 first
        cursor.seek(SeekFrom::Start(100)).unwrap();
        assert_eq!(cursor.position(), 100);

        // Seek back to beginning
        let result = tool_seek_cb(&mut cursor, 0, SeekFrom::Start(0));
        assert_eq!(result, SeekResult::Ok);
        assert_eq!(cursor.position(), 0);
    }

    #[test]
    fn tool_seek_cb_seek_cur_forward() {
        let data = vec![0u8; 256];
        let mut cursor = Cursor::new(data);

        cursor.seek(SeekFrom::Start(50)).unwrap();
        let result = tool_seek_cb(&mut cursor, 25, SeekFrom::Current(25));
        assert_eq!(result, SeekResult::Ok);
        assert_eq!(cursor.position(), 75);
    }

    #[test]
    fn tool_seek_cb_seek_cur_backward() {
        let data = vec![0u8; 256];
        let mut cursor = Cursor::new(data);

        cursor.seek(SeekFrom::Start(100)).unwrap();
        let result = tool_seek_cb(&mut cursor, -30, SeekFrom::Current(-30));
        assert_eq!(result, SeekResult::Ok);
        assert_eq!(cursor.position(), 70);
    }

    #[test]
    fn tool_seek_cb_seek_end() {
        let data = vec![0u8; 256];
        let mut cursor = Cursor::new(data);

        let result = tool_seek_cb(&mut cursor, 0, SeekFrom::End(0));
        assert_eq!(result, SeekResult::Ok);
        assert_eq!(cursor.position(), 256);
    }

    #[test]
    fn tool_seek_cb_seek_end_negative_offset() {
        let data = vec![0u8; 256];
        let mut cursor = Cursor::new(data);

        let result = tool_seek_cb(&mut cursor, -10, SeekFrom::End(-10));
        assert_eq!(result, SeekResult::Ok);
        assert_eq!(cursor.position(), 246);
    }

    #[test]
    fn tool_seek_cb_large_offset() {
        // Verify that large offsets (>2GB) work without chunking.
        // This is the key improvement over the C implementation.
        let data = vec![0u8; 16];
        let mut cursor = Cursor::new(data);

        // Cursor allows seeking past the end, so this should succeed
        let large_offset: i64 = 3_000_000_000; // ~3 GB — beyond 32-bit off_t
        let result = tool_seek_cb(
            &mut cursor,
            large_offset,
            SeekFrom::Start(large_offset as u64),
        );
        assert_eq!(result, SeekResult::Ok);
        assert_eq!(cursor.position(), large_offset as u64);
    }

    #[test]
    fn tool_seek_cb_with_dyn_seek() {
        // Verify that tool_seek_cb works with trait objects (dyn Seek)
        // since make_seek_callback uses &mut dyn Seek.
        let data = vec![0u8; 100];
        let mut cursor = Cursor::new(data);
        let seekable: &mut dyn Seek = &mut cursor;

        let result = tool_seek_cb(seekable, 42, SeekFrom::Start(42));
        assert_eq!(result, SeekResult::Ok);
    }

    // -- make_seek_callback tests ------------------------------------------

    #[test]
    fn make_seek_callback_seek_set() {
        let cb = make_seek_callback();
        let data = vec![0u8; 256];
        let mut cursor = Cursor::new(data);

        // SEEK_SET = 0, offset = 100
        let result = cb(&mut cursor, 100, 0);
        assert_eq!(result, 0); // CURL_SEEKFUNC_OK
        assert_eq!(cursor.position(), 100);
    }

    #[test]
    fn make_seek_callback_seek_cur() {
        let cb = make_seek_callback();
        let data = vec![0u8; 256];
        let mut cursor = Cursor::new(data);

        // Position at 50
        cursor.seek(SeekFrom::Start(50)).unwrap();

        // SEEK_CUR = 1, offset = 25
        let result = cb(&mut cursor, 25, 1);
        assert_eq!(result, 0); // CURL_SEEKFUNC_OK
        assert_eq!(cursor.position(), 75);
    }

    #[test]
    fn make_seek_callback_seek_end() {
        let cb = make_seek_callback();
        let data = vec![0u8; 256];
        let mut cursor = Cursor::new(data);

        // SEEK_END = 2, offset = -10
        let result = cb(&mut cursor, -10, 2);
        assert_eq!(result, 0); // CURL_SEEKFUNC_OK
        assert_eq!(cursor.position(), 246);
    }

    #[test]
    fn make_seek_callback_invalid_whence_returns_fail() {
        let cb = make_seek_callback();
        let data = vec![0u8; 256];
        let mut cursor = Cursor::new(data);

        // Invalid whence = 99
        let result = cb(&mut cursor, 0, 99);
        assert_eq!(result, 1); // CURL_SEEKFUNC_FAIL
    }

    #[test]
    fn make_seek_callback_negative_seek_set_returns_fail() {
        let cb = make_seek_callback();
        let data = vec![0u8; 256];
        let mut cursor = Cursor::new(data);

        // SEEK_SET with negative offset
        let result = cb(&mut cursor, -10, 0);
        assert_eq!(result, 1); // CURL_SEEKFUNC_FAIL
    }

    #[test]
    fn make_seek_callback_large_offset_succeeds() {
        let cb = make_seek_callback();
        let data = vec![0u8; 16];
        let mut cursor = Cursor::new(data);

        // Large offset beyond 2GB (the C chunked-seek boundary)
        let large: i64 = 5_000_000_000;
        let result = cb(&mut cursor, large, 0); // SEEK_SET
        assert_eq!(result, 0); // CURL_SEEKFUNC_OK
        assert_eq!(cursor.position(), large as u64);
    }

    // -- Seek failure simulation -------------------------------------------

    /// A mock stream that always fails on seek, simulating a non-seekable
    /// input (e.g., a pipe or stdin).
    struct NonSeekableStream;

    impl std::io::Read for NonSeekableStream {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Seek for NonSeekableStream {
        fn seek(&mut self, _pos: SeekFrom) -> std::io::Result<u64> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "stream is not seekable",
            ))
        }
    }

    #[test]
    fn tool_seek_cb_non_seekable_returns_cantseek() {
        let mut stream = NonSeekableStream;
        let result = tool_seek_cb(&mut stream, 0, SeekFrom::Start(0));
        assert_eq!(result, SeekResult::CantSeek);
    }

    #[test]
    fn make_seek_callback_non_seekable_returns_cantseek() {
        let cb = make_seek_callback();
        let mut stream = NonSeekableStream;

        // SEEK_SET = 0, offset = 0
        let result = cb(&mut stream, 0, 0);
        assert_eq!(result, 2); // CURL_SEEKFUNC_CANTSEEK
    }

    #[test]
    fn make_seek_callback_non_seekable_seek_cur() {
        let cb = make_seek_callback();
        let mut stream = NonSeekableStream;

        // SEEK_CUR = 1, offset = 50
        let result = cb(&mut stream, 50, 1);
        assert_eq!(result, 2); // CURL_SEEKFUNC_CANTSEEK
    }
}
