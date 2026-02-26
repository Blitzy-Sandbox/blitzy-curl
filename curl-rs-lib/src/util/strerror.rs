//! Error message string utilities — portable OS error lookup and formatting.
//!
//! This module is the Rust replacement for the OS-error and formatting portions
//! of C `lib/strerror.c` (676 lines). The primary CURLcode/CURLMcode/CURLSHcode
//! → string mappings live in [`crate::error`]; this module provides:
//!
//! * [`strerror()`] — portable OS error message lookup via `std::io::Error`
//! * [`socket_strerror()`] — socket-specific error messages (Winsock on Windows)
//! * [`format_error()`] — combines a [`CurlError`] message with OS context
//! * [`connect_strerror()`] — formatted connection error with OS + detail strings
//!
//! # Behavioral Compatibility
//!
//! Error message strings produced by these functions match the formatting
//! patterns of curl 8.x for test-suite compatibility. In particular:
//!
//! * Trailing CR/LF characters are stripped from OS error messages (Windows
//!   `FormatMessage` appends `\r\n`).
//! * The "description - details" pattern used by C `Curl_strerror` is
//!   preserved in [`connect_strerror()`] and [`format_error()`].
//! * A zero `errno` always produces `"No error"`.

use crate::error::CurlError;
use std::io;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns a human-readable description for the given OS error number.
///
/// This function replaces the internal C `Curl_strerror()` helper that called
/// the POSIX `strerror_r()` (or `strerror_s()` on Windows). The Rust
/// implementation uses [`std::io::Error::from_raw_os_error()`] which is
/// thread-safe and handles both POSIX errno values and Windows system error
/// codes, including the Winsock range (10000+).
///
/// Trailing carriage-return (`\r`) and line-feed (`\n`) characters are
/// stripped to match the C implementation's behavior of trimming
/// `FormatMessage` output on Windows.
///
/// # Arguments
///
/// * `errno` — The OS error number. On POSIX systems this is an `errno`
///   value; on Windows it may be a system error code or Winsock error code.
///
/// # Returns
///
/// A `String` containing the human-readable error description. Returns
/// `"No error"` when `errno` is zero.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::strerror::strerror;
///
/// let msg = strerror(0);
/// assert_eq!(msg, "No error");
///
/// // Non-zero errno produces a platform-specific message.
/// let msg = strerror(2); // ENOENT on most POSIX systems
/// assert!(!msg.is_empty());
/// ```
pub fn strerror(errno: i32) -> String {
    if errno == 0 {
        return String::from("No error");
    }
    let msg = io::Error::from_raw_os_error(errno).to_string();
    trim_trailing_crlf(&msg)
}

/// Returns a human-readable description for the given socket error number.
///
/// On Unix-like platforms, socket errors share the same error code space as
/// regular OS errors, so this function delegates directly to [`strerror()`].
///
/// On Windows, Winsock error codes occupy a distinct range (typically 10000+),
/// but [`std::io::Error::from_raw_os_error()`] handles them correctly by
/// calling `FormatMessageW` under the hood, so the same delegation applies.
///
/// # Arguments
///
/// * `sockerr` — The socket error number (e.g., `ECONNREFUSED`, or
///   `WSAECONNREFUSED` on Windows).
///
/// # Returns
///
/// A `String` containing the human-readable socket error description.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::strerror::socket_strerror;
///
/// let msg = socket_strerror(0);
/// assert_eq!(msg, "No error");
/// ```
pub fn socket_strerror(sockerr: i32) -> String {
    // std::io::Error::from_raw_os_error correctly handles both POSIX errno
    // values and Winsock error codes on Windows, so a single path suffices.
    strerror(sockerr)
}

/// Produces a formatted error string combining a [`CurlError`] message with
/// optional OS-level error context.
///
/// This function calls [`CurlError::strerror()`] to obtain the curl-specific
/// error description, then appends the OS error message (if an `os_errno` is
/// provided and non-zero) using the curl 8.x `"<curl msg> - <os msg>"` format.
///
/// When `os_errno` is `None` or zero, only the curl error description is
/// returned (no trailing separator or empty OS message).
///
/// # Arguments
///
/// * `code` — Reference to the [`CurlError`] variant describing the
///   curl-level failure.
/// * `os_errno` — Optional OS error number providing additional context.
///   Pass `None` or `Some(0)` when there is no OS-level error to report.
///
/// # Returns
///
/// A formatted error string matching curl 8.x output patterns.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::error::CurlError;
/// use curl_rs_lib::util::strerror::format_error;
///
/// // Without OS context — just the curl message.
/// let msg = format_error(&CurlError::CouldntConnect, None);
/// assert_eq!(msg, "Could not connect to server");
///
/// // With OS context — curl message + OS message.
/// let msg = format_error(&CurlError::CouldntConnect, Some(111)); // ECONNREFUSED on Linux
/// assert!(msg.starts_with("Could not connect to server - "));
/// ```
pub fn format_error(code: &CurlError, os_errno: Option<i32>) -> String {
    let curl_msg = code.strerror();

    match os_errno {
        Some(errno) if errno != 0 => {
            let os_msg = strerror(errno);
            format!("{} - {}", curl_msg, os_msg)
        }
        _ => curl_msg.to_string(),
    }
}

/// Produces a formatted connection error string combining the OS error
/// message with a curl-specific detail string.
///
/// This function mirrors the C `Curl_strerror` formatting pattern:
/// `"<OS error description> - <detail>"`. When `detail` is empty, only the
/// OS error message is returned without a trailing separator.
///
/// # Arguments
///
/// * `errno` — The OS error number from the failed connection attempt.
/// * `detail` — Additional context string describing what curl was
///   attempting (e.g., the target hostname/port or connection phase).
///
/// # Returns
///
/// A formatted error string suitable for user-facing error output.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::strerror::connect_strerror;
///
/// // With detail context.
/// let msg = connect_strerror(111, "connect to 127.0.0.1 port 8080");
/// assert!(msg.contains(" - connect to 127.0.0.1 port 8080"));
///
/// // Without detail — just the OS error.
/// let msg = connect_strerror(111, "");
/// assert!(!msg.contains(" - "));
/// ```
pub fn connect_strerror(errno: i32, detail: &str) -> String {
    let os_msg = strerror(errno);

    if detail.is_empty() {
        os_msg
    } else {
        format!("{} - {}", os_msg, detail)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Strips trailing carriage-return and line-feed characters from an error
/// message string.
///
/// On Windows, `FormatMessageW` appends `"\r\n"` to error descriptions.
/// The C curl implementation trims these characters, and we do the same for
/// behavioral parity.
fn trim_trailing_crlf(s: &str) -> String {
    s.trim_end_matches(['\r', '\n']).to_string()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CurlError;

    #[test]
    fn strerror_zero_returns_no_error() {
        assert_eq!(strerror(0), "No error");
    }

    #[test]
    fn strerror_nonzero_returns_nonempty_string() {
        // ENOENT (2) is "No such file or directory" on most POSIX systems.
        let msg = strerror(2);
        assert!(!msg.is_empty(), "strerror(2) should not be empty");
        // Ensure no trailing newlines.
        assert!(
            !msg.ends_with('\n') && !msg.ends_with('\r'),
            "strerror output should not end with CR/LF"
        );
    }

    #[test]
    fn socket_strerror_delegates_to_strerror() {
        assert_eq!(socket_strerror(0), "No error");
        // Non-zero should produce the same result as strerror.
        assert_eq!(socket_strerror(2), strerror(2));
    }

    #[test]
    fn format_error_without_os_errno() {
        let msg = format_error(&CurlError::CouldntConnect, None);
        assert_eq!(msg, "Could not connect to server");
    }

    #[test]
    fn format_error_with_zero_os_errno() {
        let msg = format_error(&CurlError::CouldntConnect, Some(0));
        assert_eq!(msg, "Could not connect to server");
    }

    #[test]
    fn format_error_with_nonzero_os_errno() {
        let msg = format_error(&CurlError::CouldntConnect, Some(2));
        // Should contain the curl message, a separator, and an OS message.
        assert!(msg.starts_with("Could not connect to server - "));
        assert!(msg.len() > "Could not connect to server - ".len());
    }

    #[test]
    fn format_error_ok_variant() {
        let msg = format_error(&CurlError::Ok, None);
        assert_eq!(msg, "No error");
    }

    #[test]
    fn connect_strerror_with_detail() {
        let msg = connect_strerror(2, "connect to 127.0.0.1 port 8080");
        assert!(msg.contains(" - connect to 127.0.0.1 port 8080"));
    }

    #[test]
    fn connect_strerror_empty_detail() {
        let msg = connect_strerror(2, "");
        assert!(!msg.contains(" - "));
        assert!(!msg.is_empty());
    }

    #[test]
    fn connect_strerror_zero_errno_with_detail() {
        let msg = connect_strerror(0, "something");
        assert_eq!(msg, "No error - something");
    }

    #[test]
    fn trim_trailing_crlf_strips_correctly() {
        assert_eq!(trim_trailing_crlf("hello\r\n"), "hello");
        assert_eq!(trim_trailing_crlf("hello\n"), "hello");
        assert_eq!(trim_trailing_crlf("hello\r"), "hello");
        assert_eq!(trim_trailing_crlf("hello"), "hello");
        assert_eq!(trim_trailing_crlf(""), "");
        assert_eq!(trim_trailing_crlf("\r\n"), "");
        assert_eq!(trim_trailing_crlf("msg\r\n\r\n"), "msg");
    }

    #[test]
    fn all_curl_error_variants_produce_nonempty_format() {
        // Verify that format_error produces a non-empty string for
        // representative error codes.
        let codes = [
            CurlError::Ok,
            CurlError::UnsupportedProtocol,
            CurlError::CouldntConnect,
            CurlError::OperationTimedOut,
            CurlError::SslConnectError,
            CurlError::Http3,
            CurlError::EchRequired,
        ];
        for code in &codes {
            let msg = format_error(code, None);
            assert!(
                !msg.is_empty(),
                "format_error for {:?} should not be empty",
                code
            );
        }
    }
}
