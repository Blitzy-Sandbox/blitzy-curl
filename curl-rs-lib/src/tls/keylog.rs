//! SSLKEYLOGFILE support via the rustls `KeyLog` trait.
//!
//! This module provides centralized TLS key logging for debugging purposes,
//! enabling tools like Wireshark to decrypt captured TLS traffic. When the
//! `SSLKEYLOGFILE` environment variable is set, key material is written in
//! the standard NSS key log format:
//!
//! ```text
//! {label} {hex(client_random)} {hex(secret)}\n
//! ```
//!
//! # Architecture
//!
//! - [`KeyLogger`] is a thread-safe struct wrapping a `Mutex<Option<BufWriter<File>>>`.
//! - A process-wide singleton is accessible via [`global_keylogger()`] using `OnceLock`.
//! - [`init_keylogger()`] creates an `Arc<dyn rustls::KeyLog>` for attachment to
//!   `rustls::ClientConfig::key_log`.
//! - The `rustls::KeyLog` trait is implemented directly on `KeyLogger`, so rustls
//!   calls [`KeyLogger::log()`] during TLS handshakes to emit key log entries.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks. Thread safety is provided
//! by `std::sync::Mutex`.
//!
//! # C Source Correspondence
//!
//! Replaces `lib/vtls/keylog.c` (148 lines) and `lib/vtls/keylog.h` (69 lines)
//! from curl 8.19.0-DEV.

use std::env;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex, OnceLock};

// Internal import: CurlError for consistency with other TLS module files.
// The schema specifies this import with members_accessed=[] — it is imported
// for module-level consistency and potential future Result-based API usage.
#[allow(unused_imports)]
use crate::error::CurlError;

// ---------------------------------------------------------------------------
// Constants — matching C `lib/vtls/keylog.h` exactly
// ---------------------------------------------------------------------------

/// Maximum length of a TLS key log label string.
///
/// Corresponds to `sizeof("CLIENT_HANDSHAKE_TRAFFIC_SECRET") - 1` in C,
/// which equals 31 bytes. This covers all standard TLS 1.2 and TLS 1.3
/// key log labels defined by the NSS key log format specification.
pub const KEYLOG_LABEL_MAXLEN: usize = 31;

/// Size of the TLS client random value in bytes.
///
/// The client random is always exactly 32 bytes in TLS 1.2 and TLS 1.3
/// handshakes, as defined by RFC 5246 §7.4.1.2 and RFC 8446 §4.1.2.
pub const CLIENT_RANDOM_SIZE: usize = 32;

/// Maximum secret length in bytes.
///
/// TLS 1.2 master secret is always 48 bytes. TLS 1.3 secrets depend on the
/// cipher suite's hash function: SHA-256 produces 32-byte secrets and
/// SHA-384 produces 48-byte secrets. This constant covers both cases.
pub const SECRET_MAXLEN: usize = 48;

/// Internal maximum line length for formatted key log output.
///
/// Matches the C implementation's 256-byte stack buffer used in
/// `Curl_tls_keylog_write_line()`. A complete NSS key log line must fit
/// within this limit: label (31) + space (1) + hex client_random (64) +
/// space (1) + hex secret (96) + newline (1) + NUL (1) = 195 max.
const MAX_LINE_LEN: usize = 256;

// ---------------------------------------------------------------------------
// KeyLogger — thread-safe TLS key logger
// ---------------------------------------------------------------------------

/// Internal mutable state for the key logger.
///
/// Holds an optional buffered file writer. When `file` is `None`, key
/// logging is inactive.
struct KeyLoggerInner {
    /// Buffered writer for the SSLKEYLOGFILE output file.
    ///
    /// `BufWriter` provides buffered I/O, replacing the C `setvbuf()` call
    /// with `_IOLBF` (line-buffered, 4 KB buffer). Each write is explicitly
    /// flushed after completion to ensure immediate visibility for debugging.
    file: Option<BufWriter<File>>,
}

/// Thread-safe TLS key logger for SSLKEYLOGFILE support.
///
/// This struct manages the lifecycle of the key log file and provides
/// methods matching the C API surface:
///
/// | Rust method                | C function                      |
/// |----------------------------|---------------------------------|
/// | [`open()`](Self::open)     | `Curl_tls_keylog_open()`        |
/// | [`close()`](Self::close)   | `Curl_tls_keylog_close()`       |
/// | [`enabled()`](Self::enabled) | `Curl_tls_keylog_enabled()`   |
/// | [`write_line()`](Self::write_line) | `Curl_tls_keylog_write_line()` |
/// | [`write()`](Self::write)   | `Curl_tls_keylog_write()`       |
///
/// Additionally, `KeyLogger` implements `rustls::KeyLog`, allowing it to
/// be passed directly to `rustls::ClientConfig::key_log` as
/// `Arc<dyn rustls::KeyLog>`.
pub struct KeyLogger {
    /// Mutex-protected inner state. The mutex ensures thread-safe access
    /// from multiple TLS connections that may be handshaking concurrently.
    inner: Mutex<KeyLoggerInner>,
}

// Custom Debug implementation because BufWriter<File> does not implement
// Debug in a useful way, and the rustls::KeyLog trait requires Debug.
impl fmt::Debug for KeyLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let active = match self.inner.lock() {
            Ok(inner) => inner.file.is_some(),
            Err(_) => false,
        };
        f.debug_struct("KeyLogger")
            .field("active", &active)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

/// Process-wide `KeyLogger` singleton, lazily initialized via `OnceLock`.
///
/// Replaces the C global `static FILE *keylog_file_fp` with a safe,
/// thread-safe Rust equivalent. `OnceLock` is stable since Rust 1.70,
/// well within the MSRV 1.75 requirement.
static GLOBAL_KEYLOGGER: OnceLock<KeyLogger> = OnceLock::new();

/// Returns a reference to the process-wide [`KeyLogger`] singleton.
///
/// The singleton is lazily initialized on first access with no file open.
/// Call [`KeyLogger::open()`] on the returned reference to activate key
/// logging based on the `SSLKEYLOGFILE` environment variable.
///
/// # Example
///
/// ```ignore
/// use curl_rs_lib::tls::keylog::global_keylogger;
///
/// let logger = global_keylogger();
/// logger.open();
/// if logger.enabled() {
///     logger.write_line("# TLS key log initialized");
/// }
/// ```
pub fn global_keylogger() -> &'static KeyLogger {
    GLOBAL_KEYLOGGER.get_or_init(|| KeyLogger {
        inner: Mutex::new(KeyLoggerInner { file: None }),
    })
}

// ---------------------------------------------------------------------------
// KeyLogger implementation
// ---------------------------------------------------------------------------

impl KeyLogger {
    /// Creates a new `KeyLogger` with the given file writer already open.
    ///
    /// Used internally by [`init_keylogger()`] to construct a logger that
    /// is immediately ready for use.
    fn with_file(writer: BufWriter<File>) -> Self {
        Self {
            inner: Mutex::new(KeyLoggerInner {
                file: Some(writer),
            }),
        }
    }

    /// Opens the TLS key log file based on the `SSLKEYLOGFILE` environment
    /// variable.
    ///
    /// If the variable is not set or is empty, or if the file cannot be
    /// opened, key logging remains inactive — no error is raised. This
    /// matches the C behavior where `Curl_tls_keylog_open()` silently
    /// returns when `curl_getenv("SSLKEYLOGFILE")` is `NULL`.
    ///
    /// The file is opened in **append mode** so that multiple processes or
    /// successive runs accumulate entries rather than overwriting.
    ///
    /// Corresponds to C `Curl_tls_keylog_open()` (keylog.c lines 40–62).
    pub fn open(&self) {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(_poisoned) => return, // Poisoned mutex — cannot proceed safely.
        };

        // Already open — idempotent, matching C `if(!keylog_file_fp)` guard.
        if inner.file.is_some() {
            return;
        }

        // Read SSLKEYLOGFILE environment variable (replaces C `curl_getenv`).
        let path = match env::var("SSLKEYLOGFILE") {
            Ok(p) if !p.is_empty() => p,
            _ => return, // Not set or empty — no key logging.
        };

        // Open in create + append mode (replaces C `FOPEN_APPENDTEXT`).
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => {
                // BufWriter provides buffered I/O with an 8 KB default buffer,
                // replacing the C `setvbuf(fp, NULL, _IOLBF, 4096)` call.
                // Each write is explicitly flushed for immediate visibility.
                inner.file = Some(BufWriter::new(file));
            }
            Err(_) => {
                // Silently ignore open failure — matches C behavior where
                // keylog_file_fp remains NULL on failure.
            }
        }
    }

    /// Closes the TLS key log file, flushing any buffered data.
    ///
    /// After this call, [`enabled()`](Self::enabled) returns `false` and
    /// all write operations become no-ops. It is safe to call `close()`
    /// multiple times.
    ///
    /// Corresponds to C `Curl_tls_keylog_close()` (keylog.c lines 64–70).
    pub fn close(&self) {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(_poisoned) => return,
        };

        // Flush before dropping to ensure all buffered data reaches disk.
        if let Some(ref mut writer) = inner.file {
            let _ = writer.flush();
        }
        // Drop the file handle by setting to None.
        inner.file = None;
    }

    /// Returns `true` if key logging is currently active (file is open).
    ///
    /// Corresponds to C `Curl_tls_keylog_enabled()` (keylog.c lines 72–75).
    pub fn enabled(&self) -> bool {
        match self.inner.lock() {
            Ok(inner) => inner.file.is_some(),
            Err(_poisoned) => false,
        }
    }

    /// Writes a preformatted line to the key log file.
    ///
    /// The line must be between 1 and 254 characters (inclusive). A trailing
    /// newline is appended if not already present. Returns `true` on success,
    /// `false` if key logging is inactive, the line is invalid, or a write
    /// error occurs.
    ///
    /// Corresponds to C `Curl_tls_keylog_write_line()` (keylog.c lines 77–103).
    ///
    /// # Validation rules (matching C exactly)
    ///
    /// - Line must not be empty (`linelen == 0` check).
    /// - Line length must be ≤ 254 to fit within the 256-byte buffer with
    ///   room for a newline and NUL terminator (`linelen > sizeof(buf) - 2`).
    pub fn write_line(&self, line: &str) -> bool {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(_poisoned) => return false,
        };

        let writer = match inner.file {
            Some(ref mut w) => w,
            None => return false, // Key logging not active.
        };

        let len = line.len();

        // Validate line length: must be 1..=254 (matching C `linelen == 0 ||
        // linelen > sizeof(buf) - 2` where sizeof(buf) == 256).
        if len == 0 || len > MAX_LINE_LEN - 2 {
            return false;
        }

        // Write the line content.
        if writer.write_all(line.as_bytes()).is_err() {
            return false;
        }

        // Ensure newline termination (matching C lines 94–96:
        // `if(line[linelen - 1] != '\n') { buf[linelen++] = '\n'; }`).
        if !line.ends_with('\n') && writer.write_all(b"\n").is_err() {
            return false;
        }

        // Flush for immediate visibility, matching the intent of the C
        // line-buffered (`_IOLBF`) and unbuffered (`_IONBF`) modes.
        let _ = writer.flush();
        true
    }

    /// Writes a structured TLS key log entry in NSS format.
    ///
    /// Formats and writes a line of the form:
    /// ```text
    /// {label} {hex(client_random)} {hex(secret)}\n
    /// ```
    ///
    /// Returns `true` on success, `false` if key logging is inactive,
    /// parameters are invalid, or a write error occurs.
    ///
    /// Corresponds to C `Curl_tls_keylog_write()` (keylog.c lines 105–145).
    ///
    /// # Parameters
    ///
    /// - `label`: The key log label (e.g., `"CLIENT_RANDOM"`,
    ///   `"CLIENT_HANDSHAKE_TRAFFIC_SECRET"`). Must be ≤ 31 bytes.
    /// - `client_random`: The 32-byte client random value from the TLS
    ///   handshake.
    /// - `secret`: The secret value (1–48 bytes).
    pub fn write(
        &self,
        label: &str,
        client_random: &[u8; CLIENT_RANDOM_SIZE],
        secret: &[u8],
    ) -> bool {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(_poisoned) => return false,
        };

        let writer = match inner.file {
            Some(ref mut w) => w,
            None => return false,
        };

        // Validate label length (matching C line 118:
        // `pos > KEYLOG_LABEL_MAXLEN`).
        if label.len() > KEYLOG_LABEL_MAXLEN {
            return false;
        }

        // Validate secret bounds (matching C line 118:
        // `!secretlen || secretlen > SECRET_MAXLEN`).
        if secret.is_empty() || secret.len() > SECRET_MAXLEN {
            return false;
        }

        // Build NSS key log format line:
        // "{label} {hex_client_random} {hex_secret}\n"
        //
        // Using write!() with {:02x} for lowercase hex formatting,
        // replacing C's `Curl_hexbyte()` manual hex conversion.

        // Write label.
        if write!(writer, "{} ", label).is_err() {
            return false;
        }

        // Write client random as lowercase hex (32 bytes → 64 hex chars).
        for byte in client_random {
            if write!(writer, "{:02x}", byte).is_err() {
                return false;
            }
        }

        // Separator between client_random and secret.
        if write!(writer, " ").is_err() {
            return false;
        }

        // Write secret as lowercase hex.
        for byte in secret {
            if write!(writer, "{:02x}", byte).is_err() {
                return false;
            }
        }

        // Trailing newline.
        if writeln!(writer).is_err() {
            return false;
        }

        // Flush for immediate visibility.
        let _ = writer.flush();
        true
    }
}

// ---------------------------------------------------------------------------
// rustls::KeyLog trait implementation
// ---------------------------------------------------------------------------

impl rustls::KeyLog for KeyLogger {
    /// Called by rustls during TLS handshakes to log key material.
    ///
    /// Formats the provided label, client random, and secret as an NSS key
    /// log line and writes it to the SSLKEYLOGFILE. Silently does nothing
    /// if key logging is not active or if the mutex is poisoned.
    ///
    /// This implementation is intentionally infallible — errors during
    /// writing are silently ignored to avoid disrupting the TLS handshake.
    /// This matches the C implementation's use of `fputs()` with no error
    /// checking on the return value.
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(_poisoned) => return,
        };

        let writer = match inner.file {
            Some(ref mut w) => w,
            None => return,
        };

        // Format: "{label} {hex_client_random} {hex_secret}\n"
        //
        // Note: rustls may provide client_random of varying length (not
        // necessarily CLIENT_RANDOM_SIZE). We encode whatever is provided
        // as hex, matching the NSS key log format specification.
        let _ = write!(writer, "{} ", label);

        for b in client_random {
            let _ = write!(writer, "{:02x}", b);
        }

        let _ = write!(writer, " ");

        for b in secret {
            let _ = write!(writer, "{:02x}", b);
        }

        let _ = writeln!(writer);
        let _ = writer.flush();
    }
}

// ---------------------------------------------------------------------------
// Initialization helper for rustls integration
// ---------------------------------------------------------------------------

/// Creates a [`KeyLogger`] suitable for use with `rustls::ClientConfig::key_log`.
///
/// Checks the `SSLKEYLOGFILE` environment variable. If it is set and the
/// file can be opened, returns `Some(Arc<dyn rustls::KeyLog>)` containing
/// a fully initialized `KeyLogger`. If the variable is not set or the file
/// cannot be opened, returns `None`.
///
/// This function creates a **new** `KeyLogger` instance (not the global
/// singleton) so that each `rustls::ClientConfig` can own its own
/// `Arc<dyn rustls::KeyLog>` reference. The underlying file is opened in
/// append mode so multiple loggers write to the same file safely.
///
/// # Usage
///
/// ```ignore
/// use curl_rs_lib::tls::keylog::init_keylogger;
///
/// let mut config = rustls::ClientConfig::builder()
///     .with_root_certificates(root_store)
///     .with_no_client_auth();
///
/// if let Some(key_log) = init_keylogger() {
///     config.key_log = key_log;
/// }
/// ```
///
/// Corresponds to the combination of C `Curl_tls_keylog_open()` and the
/// rustls backend's integration point in `rustls.c`.
pub fn init_keylogger() -> Option<Arc<dyn rustls::KeyLog>> {
    // Read SSLKEYLOGFILE environment variable.
    let path = match env::var("SSLKEYLOGFILE") {
        Ok(p) if !p.is_empty() => p,
        _ => return None, // Not set or empty — no key logging.
    };

    // Open file in create + append mode.
    let file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(_) => return None, // Cannot open — no key logging.
    };

    // Wrap in BufWriter for buffered I/O and construct the logger.
    let logger = KeyLogger::with_file(BufWriter::new(file));
    Some(Arc::new(logger))
}
