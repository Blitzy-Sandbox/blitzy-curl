//! `SSLKEYLOGFILE` TLS key-log writer in the NSS Key Log Format.
//!
//! This module is the memory-safe Rust reimplementation of libcurl's TLS
//! key-logging facility (`lib/vtls/keylog.c` and `lib/vtls/keylog.h`, used here
//! as a behavioral oracle, not transliterated line-by-line). When the
//! well-known `SSLKEYLOGFILE` environment variable names a writable file, the
//! TLS layer appends each negotiated secret to it in the *NSS Key Log Format*,
//! which packet-analysis tools such as Wireshark consume to decrypt captured
//! traffic.
//!
//! # Scope and environment passthrough
//!
//! `SSLKEYLOGFILE` is the **only** environment variable this module reads, and
//! it introduces **no new** runtime secret or configuration knob — it honors the
//! pre-existing, industry-standard variable exactly as upstream curl does (see
//! the Agent Action Plan §0.8.3, "environment passthrough only"; `SSL_CERT_FILE`
//! and `HOME` are similarly honored elsewhere).
//!
//! # NSS Key Log Format
//!
//! Every entry is a single line of the form
//!
//! ```text
//! <label> <client_random as 64 lowercase hex chars> <secret as lowercase hex>\n
//! ```
//!
//! with exactly one ASCII space between the three fields, lowercase hexadecimal
//! (two characters per byte), and a trailing line feed. The `client_random` is
//! always 32 bytes and therefore always renders as exactly 64 hex characters.
//! This is byte-for-byte the format that `rustls` itself emits, so the live and
//! the explicit-parity paths below produce wire-identical output.
//!
//! # C API → Rust mapping
//!
//! curl exposes the key log through a file-scoped `static FILE *` plus five free
//! functions. That global, manually managed handle is exactly the C idiom this
//! rewrite replaces with ownership, so the state is encapsulated in the [`KeyLog`]
//! type and the mapping is:
//!
//! | curl (`keylog.c`)             | Rust (this module)                                  |
//! |-------------------------------|-----------------------------------------------------|
//! | `Curl_tls_keylog_open()`      | [`KeyLog::from_env`] / [`KeyLog::open_path`]        |
//! | `Curl_tls_keylog_close()`     | `Drop` for [`KeyLog`] (deterministic, automatic)   |
//! | `Curl_tls_keylog_enabled()`   | [`KeyLog::is_enabled`]                              |
//! | `Curl_tls_keylog_write(...)`  | [`KeyLog::write_secret`]                            |
//! | `Curl_tls_keylog_write_line()`| [`KeyLog::write_line`]                              |
//!
//! # Implementation strategy (two equivalent paths)
//!
//! The public surface that [`crate::tls::config`] consumes is [`key_log`], which
//! returns an `Arc<dyn rustls::KeyLog>` ready to assign to
//! `rustls::ClientConfig.key_log` (mirroring curl's `init_config_builder_keylog`
//! in `lib/vtls/rustls.c`, which calls `Curl_tls_keylog_open()` and then
//! registers the log callback).
//!
//! * **Primary (live) path — [`key_log`]:** when `SSLKEYLOGFILE` is present it
//!   returns [`rustls::KeyLogFile`], whose own implementation reads the same
//!   variable, formats the same NSS lines, and writes them atomically under a
//!   lock. This is the simplest, idiomatic, zero-maintenance choice and is
//!   wire-identical to curl. When the variable is absent it returns
//!   [`rustls::NoKeyLog`] so that `will_log()` is `false` and there is no
//!   per-secret overhead.
//! * **Explicit-parity path — [`KeyLog`] + [`key_log_explicit`]:** a fully
//!   independent implementation that reproduces curl's validation, byte layout,
//!   buffering, and single-locked-write thread-safety. It is kept present,
//!   documented, and unit-tested so the parity with curl is auditable and so the
//!   workspace retains control over buffering and validation should `rustls`'
//!   default ever diverge. [`key_log_explicit`] is a drop-in replacement for
//!   [`key_log`].
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` (it compiles cleanly under the
//! crate-root `#![forbid(unsafe_code)]`) and relies only on `std::{env, fs, io,
//! sync}` and the safe `rustls` trait surface.

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

// `rustls::KeyLog` (the trait) is intentionally NOT imported by name: the
// explicit-parity type below is also called `KeyLog`, so the trait is always
// referred to by its fully-qualified path `rustls::KeyLog` to avoid the name
// clash. Only the two concrete helper types are imported.
use rustls::{KeyLogFile, NoKeyLog};

/// Longest NSS key-log label, in bytes, excluding the C string's NUL.
///
/// Equal to `"CLIENT_HANDSHAKE_TRAFFIC_SECRET".len()`, matching curl's
/// `#define KEYLOG_LABEL_MAXLEN (sizeof("CLIENT_HANDSHAKE_TRAFFIC_SECRET") - 1)`
/// in `lib/vtls/keylog.h`. Labels longer than this are rejected.
pub const KEYLOG_LABEL_MAXLEN: usize = 31;

/// Size, in bytes, of the TLS `client_random`, which is always 32 bytes and
/// therefore renders as exactly 64 hexadecimal characters. Matches curl's
/// `#define CLIENT_RANDOM_SIZE 32`.
pub const CLIENT_RANDOM_SIZE: usize = 32;

/// Largest TLS secret, in bytes.
///
/// The TLS 1.2 master secret is always 48 bytes; in TLS 1.3 the secret size is
/// the cipher suite hash length (32 bytes for SHA-256, 48 for SHA-384). Matches
/// curl's `#define SECRET_MAXLEN 48`. Secrets must be in `1..=SECRET_MAXLEN`.
pub const SECRET_MAXLEN: usize = 48;

/// Maximum length, in bytes, of a raw key-log line accepted by
/// [`KeyLog::write_line`], excluding the terminating line feed.
///
/// curl formats into a fixed 256-byte stack buffer and rejects any input whose
/// length exceeds `sizeof(buf) - 2` so that the line plus a line feed plus the
/// terminating NUL still fit; that bound is `256 - 2 = 254`.
pub const KEYLOG_LINE_MAXLEN: usize = 254;

/// Name of the environment variable that, when present, enables key logging.
const SSLKEYLOGFILE_ENV: &str = "SSLKEYLOGFILE";

/// Lowercase hexadecimal alphabet used throughout the NSS key-log format.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Returns `true` iff the `SSLKEYLOGFILE` environment variable is present.
///
/// Only presence is checked (mirroring curl, which acts whenever the variable
/// is set); an unreadable or empty path is handled gracefully downstream by the
/// open call, which simply leaves logging disabled.
fn sslkeylogfile_present() -> bool {
    env::var_os(SSLKEYLOGFILE_ENV).is_some()
}

/// Opens `path` for appending, creating it if it does not exist.
///
/// This mirrors curl's `curlx_fopen(name, FOPEN_APPENDTEXT)`: existing contents
/// are preserved and new entries are appended.
fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().append(true).create(true).open(path)
}

/// Appends each byte of `bytes` to `out` as two lowercase ASCII hex digits.
///
/// This is the byte-oriented counterpart of [`to_hex`], used on the hot path so
/// the whole NSS line can be assembled in a single allocation and written with
/// one call.
fn push_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    out.reserve(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_DIGITS[(b >> 4) as usize]);
        out.push(HEX_DIGITS[(b & 0x0f) as usize]);
    }
}

/// Encodes `bytes` as a lowercase hexadecimal string (two characters per byte).
///
/// This is the public, allocation-returning hex encoder used by the explicit
/// parity path and its tests. It is the safe analogue of curl's `Curl_hexbyte`
/// applied across a slice and never panics for any input.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(HEX_DIGITS[(b >> 4) as usize]));
        s.push(char::from(HEX_DIGITS[(b & 0x0f) as usize]));
    }
    s
}

/// Formats one NSS key-log entry, applying every validation curl applies.
///
/// Returns the complete line (including the trailing `\n`) as bytes, or [`None`]
/// if any field is out of range — in which case nothing is written and no
/// malformed line is ever produced. The validation reproduces
/// `Curl_tls_keylog_write`:
///
/// * `label` must be at most [`KEYLOG_LABEL_MAXLEN`] bytes,
/// * `client_random` must be exactly [`CLIENT_RANDOM_SIZE`] bytes (curl's
///   `DEBUGASSERT(client_random_len == CLIENT_RANDOM_SIZE)`), and
/// * `secret` length must be in `1..=`[`SECRET_MAXLEN`].
fn format_keylog_line(label: &str, client_random: &[u8], secret: &[u8]) -> Option<Vec<u8>> {
    if label.len() > KEYLOG_LABEL_MAXLEN {
        return None;
    }
    if client_random.len() != CLIENT_RANDOM_SIZE {
        return None;
    }
    let secret_len = secret.len();
    if secret_len == 0 || secret_len > SECRET_MAXLEN {
        return None;
    }

    // Pre-size the buffer to the exact final length:
    //   label + ' ' + 2*client_random + ' ' + 2*secret + '\n'
    let mut line =
        Vec::with_capacity(label.len() + 1 + (2 * CLIENT_RANDOM_SIZE) + 1 + (2 * secret_len) + 1);
    line.extend_from_slice(label.as_bytes());
    line.push(b' ');
    push_hex(&mut line, client_random);
    line.push(b' ');
    push_hex(&mut line, secret);
    line.push(b'\n');
    Some(line)
}

/// Returns the key logger that `rustls` should use for new TLS configurations.
///
/// This is the **primary, live** path and the stable public surface consumed by
/// [`crate::tls::config`]:
///
/// * If `SSLKEYLOGFILE` is set, it returns an `Arc<rustls::KeyLogFile>`, which
///   reads that variable and writes NSS-format entries itself — byte-identical
///   to curl and fully thread-safe.
/// * Otherwise it returns an `Arc<rustls::NoKeyLog>`, whose `will_log()` is
///   `false`, so `rustls` never even derives the secrets for logging.
///
/// Assign the result directly: `config.key_log = keylog::key_log();`.
///
/// The decision is taken once, when this function is called (typically while
/// building a `ClientConfig`); changing `SSLKEYLOGFILE` afterwards does not
/// affect already-built configurations, which matches curl's
/// open-once semantics.
#[must_use]
pub fn key_log() -> Arc<dyn rustls::KeyLog> {
    if sslkeylogfile_present() {
        Arc::new(KeyLogFile::new())
    } else {
        Arc::new(NoKeyLog)
    }
}

/// Like [`key_log`], but backed by the explicit-parity [`KeyLog`] implementation
/// in this module instead of `rustls::KeyLogFile`.
///
/// Both produce wire-identical output. This variant exists so the workspace can
/// switch to the audited, curl-faithful writer — retaining direct control over
/// validation and buffering — without changing the call site, should
/// `rustls::KeyLogFile`'s behavior ever need to be overridden. When
/// `SSLKEYLOGFILE` is unset it returns [`rustls::NoKeyLog`], exactly like
/// [`key_log`].
#[must_use]
pub fn key_log_explicit() -> Arc<dyn rustls::KeyLog> {
    if sslkeylogfile_present() {
        Arc::new(KeyLog::from_env())
    } else {
        Arc::new(NoKeyLog)
    }
}

/// An explicit, curl-faithful `SSLKEYLOGFILE` writer implementing
/// [`rustls::KeyLog`].
///
/// This is the auditable parity counterpart to [`rustls::KeyLogFile`]. It owns
/// the open log file (replacing curl's file-scoped `static FILE *`), so closing
/// is deterministic and automatic via `Drop` — there is no global state and no
/// manual `close`. The file lives behind a [`Mutex`] so that a single shared
/// configuration can be used concurrently by many connections: each entry is
/// formatted up front and emitted with one locked [`write_all`](Write::write_all),
/// reproducing the thread-safety curl obtains from a single `fputs`.
///
/// A [`BufWriter`] is flushed after every entry to mirror curl's line-buffered
/// (`_IOLBF`) mode, so each secret reaches disk promptly while still benefiting
/// from buffered writes.
///
/// `Debug` is derived and is safe: the struct holds only the file handle, never
/// any secret material.
#[derive(Debug)]
pub struct KeyLog {
    /// The open log file, or `None` when logging is disabled. `None` is the
    /// faithful analogue of curl's `keylog_file_fp == NULL`.
    file: Mutex<Option<BufWriter<File>>>,
}

impl KeyLog {
    /// Creates a key logger from the `SSLKEYLOGFILE` environment variable.
    ///
    /// This is the parity analogue of `Curl_tls_keylog_open()`: if the variable
    /// is set and the named file can be opened for appending, logging is
    /// enabled; otherwise it is silently disabled (curl likewise leaves its
    /// handle `NULL` on any failure). Opening errors are intentionally swallowed
    /// here because key logging is a best-effort diagnostic and must never break
    /// a transfer. Use [`KeyLog::open_path`] when an explicit error is wanted.
    #[must_use]
    pub fn from_env() -> Self {
        let file = env::var_os(SSLKEYLOGFILE_ENV)
            .and_then(|path| open_append(Path::new(&path)).ok())
            .map(BufWriter::new);
        Self {
            file: Mutex::new(file),
        }
    }

    /// Opens `path` for appending and returns an enabled key logger, or a
    /// [`CurlError`](crate::error::CurlError) if the file cannot be opened.
    ///
    /// Unlike [`from_env`](KeyLog::from_env) this ignores the environment and
    /// surfaces I/O failures: the underlying [`std::io::Error`] is converted into
    /// the closest `CURLcode`-bearing [`CurlError`](crate::error::CurlError)
    /// through the crate's existing `From` implementation (for example a missing
    /// directory becomes `CURLE_READ_ERROR`). It is provided for callers and
    /// tests that need a deterministic, env-independent logger.
    ///
    /// # Errors
    ///
    /// Returns the converted I/O error if `path` cannot be opened or created for
    /// appending.
    pub fn open_path<P: AsRef<Path>>(path: P) -> crate::error::Result<Self> {
        let file = open_append(path.as_ref())?;
        Ok(Self {
            file: Mutex::new(Some(BufWriter::new(file))),
        })
    }

    /// Returns a logger that is permanently disabled (no file).
    ///
    /// Equivalent in effect to [`rustls::NoKeyLog`]: [`will_log`](rustls::KeyLog::will_log)
    /// is `false` and [`write_secret`](KeyLog::write_secret) is a no-op. Useful
    /// for tests and for representing the "feature off" state explicitly.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            file: Mutex::new(None),
        }
    }

    /// Returns `true` iff the log file is open, mirroring
    /// `Curl_tls_keylog_enabled()`.
    ///
    /// A poisoned lock (a panic in another thread while logging) is tolerated by
    /// inspecting the recovered state, so a diagnostic facility never propagates
    /// a panic.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        match self.file.lock() {
            Ok(guard) => guard.is_some(),
            Err(poisoned) => poisoned.into_inner().is_some(),
        }
    }

    /// Appends one NSS key-log entry, mirroring `Curl_tls_keylog_write`.
    ///
    /// `label`, `client_random`, and `secret` are validated exactly as curl does
    /// (see [`format_keylog_line`]); if any field is out of range, or if logging
    /// is disabled, nothing is written and `false` is returned — a malformed
    /// line is never emitted. Returns `true` only when a complete, valid line was
    /// written.
    pub fn write_secret(&self, label: &str, client_random: &[u8], secret: &[u8]) -> bool {
        match format_keylog_line(label, client_random, secret) {
            Some(line) => self.write_raw(&line),
            None => false,
        }
    }

    /// Appends a raw key-log `line`, ensuring it is terminated by a single line
    /// feed; mirrors `Curl_tls_keylog_write_line`.
    ///
    /// Rejects (returns `false`, writing nothing) an empty line, a line longer
    /// than [`KEYLOG_LINE_MAXLEN`] bytes, or any write attempt while logging is
    /// disabled. If `line` does not already end in `\n`, exactly one is appended.
    pub fn write_line(&self, line: &str) -> bool {
        let bytes = line.as_bytes();
        let len = bytes.len();
        if len == 0 || len > KEYLOG_LINE_MAXLEN {
            return false;
        }
        if bytes[len - 1] == b'\n' {
            self.write_raw(bytes)
        } else {
            let mut buf = Vec::with_capacity(len + 1);
            buf.extend_from_slice(bytes);
            buf.push(b'\n');
            self.write_raw(&buf)
        }
    }

    /// Writes `bytes` to the log file under the lock as a single operation, then
    /// flushes to mirror curl's line buffering.
    ///
    /// Returns `false` when logging is disabled or the write fails. Write errors
    /// are swallowed (beyond the boolean result) because key logging must never
    /// abort a transfer — the same stance as curl, which ignores the `fputs`
    /// return value. A poisoned lock is recovered rather than propagated.
    fn write_raw(&self, bytes: &[u8]) -> bool {
        let mut guard = match self.file.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match guard.as_mut() {
            Some(writer) => {
                if writer.write_all(bytes).is_ok() {
                    // Flush per line to match curl's `_IOLBF` line buffering, so
                    // captured secrets are available promptly.
                    let _ = writer.flush();
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }
}

impl rustls::KeyLog for KeyLog {
    /// Logging is active exactly when the file is open. Returning `false` when
    /// disabled lets `rustls` skip deriving secrets entirely.
    fn will_log(&self, _label: &str) -> bool {
        self.is_enabled()
    }

    /// Emits one secret. Any validation or I/O failure is silently ignored — as
    /// in curl — so that a diagnostic write can never disrupt the TLS session.
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let _ = self.write_secret(label, client_random, secret);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // The crate-internal `KeyLog` struct shares its name with the `rustls::KeyLog`
    // trait, so the trait is imported under an alias to exercise its methods on
    // concrete instances without a name clash.
    use rustls::KeyLog as RustlsKeyLog;

    /// Serializes the few tests that mutate the process-global `SSLKEYLOGFILE`
    /// variable so they cannot race each other when the test harness runs
    /// functions on multiple threads. Poisoning is recovered rather than
    /// propagated so one failing test does not cascade.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// A 32-byte `client_random` with distinct bytes `0x00..=0x1f`, so its hex
    /// rendering is non-trivial and order-sensitive.
    fn sample_client_random() -> [u8; CLIENT_RANDOM_SIZE] {
        core::array::from_fn(|i| i as u8)
    }

    // --- (a) constants ------------------------------------------------------

    #[test]
    fn constants_match_curl_header() {
        assert_eq!(KEYLOG_LABEL_MAXLEN, 31);
        // The label maximum is defined in curl as the length of the longest
        // NSS label, so pin it to that exact string.
        assert_eq!(KEYLOG_LABEL_MAXLEN, "CLIENT_HANDSHAKE_TRAFFIC_SECRET".len());
        assert_eq!(CLIENT_RANDOM_SIZE, 32);
        assert_eq!(SECRET_MAXLEN, 48);
        // 256-byte stack buffer minus a line feed and a NUL.
        assert_eq!(KEYLOG_LINE_MAXLEN, 254);
    }

    // --- (b) hex encoder + NSS line formatter -------------------------------

    #[test]
    fn to_hex_is_lowercase_and_two_chars_per_byte() {
        assert_eq!(to_hex(&[]), "");
        assert_eq!(to_hex(&[0x00]), "00");
        assert_eq!(to_hex(&[0x0f]), "0f");
        assert_eq!(to_hex(&[0xa0]), "a0");
        assert_eq!(to_hex(&[0xff]), "ff");
        assert_eq!(
            to_hex(&[0x00, 0x0f, 0xa0, 0xff, 0xde, 0xad]),
            "000fa0ffdead"
        );
        // No uppercase digit ever appears.
        let rendered = to_hex(&(0u8..=255).collect::<Vec<u8>>());
        assert!(rendered
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
        assert_eq!(rendered.len(), 256 * 2);
    }

    #[test]
    fn format_line_is_byte_exact_nss() {
        let label = "CLIENT_RANDOM";
        let cr = sample_client_random();
        let secret = [0xde, 0xad, 0xbe, 0xef];

        let line = format_keylog_line(label, &cr, &secret).expect("valid inputs");
        let expected = format!("CLIENT_RANDOM {} deadbeef\n", to_hex(&cr));
        assert_eq!(line, expected.as_bytes());

        // Structural guarantees of the NSS format.
        let text = std::str::from_utf8(&line).expect("ascii line");
        assert!(text.ends_with('\n'), "must end with a single line feed");
        assert_eq!(text.matches(' ').count(), 2, "exactly two field separators");
        let body = text.trim_end_matches('\n');
        let fields: Vec<&str> = body.split(' ').collect();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0], "CLIENT_RANDOM");
        // client_random always renders as exactly 64 hex characters.
        assert_eq!(fields[1].len(), 64);
        assert_eq!(fields[2], "deadbeef");
    }

    #[test]
    fn format_line_rejects_out_of_range_fields() {
        let cr = sample_client_random();
        // Label exactly at the maximum is accepted; one over is rejected.
        assert!(format_keylog_line(&"x".repeat(KEYLOG_LABEL_MAXLEN), &cr, &[0x01]).is_some());
        assert!(format_keylog_line(&"x".repeat(KEYLOG_LABEL_MAXLEN + 1), &cr, &[0x01]).is_none());
        // Secret length boundaries: empty and >48 rejected, 48 accepted.
        assert!(format_keylog_line("L", &cr, &[]).is_none());
        assert!(format_keylog_line("L", &cr, &[0u8; SECRET_MAXLEN]).is_some());
        assert!(format_keylog_line("L", &cr, &[0u8; SECRET_MAXLEN + 1]).is_none());
        // client_random must be exactly 32 bytes.
        assert!(format_keylog_line("L", &[0u8; CLIENT_RANDOM_SIZE - 1], &[0x01]).is_none());
        assert!(format_keylog_line("L", &[0u8; CLIENT_RANDOM_SIZE + 1], &[0x01]).is_none());
    }

    // --- explicit KeyLog: writing the correct content -----------------------

    #[test]
    fn open_path_writes_exact_nss_line() {
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        let kl = KeyLog::open_path(tmp.path()).expect("open temp keylog");
        assert!(kl.is_enabled());

        let cr = sample_client_random();
        assert!(kl.write_secret("CLIENT_RANDOM", &cr, &[0xde, 0xad, 0xbe, 0xef]));
        drop(kl); // ensure the buffer is fully released before reading

        let contents = std::fs::read_to_string(tmp.path()).expect("read back");
        assert_eq!(
            contents,
            format!("CLIENT_RANDOM {} deadbeef\n", to_hex(&cr))
        );
    }

    #[test]
    fn open_path_errors_on_unwritable_path() {
        // A path whose parent directory does not exist cannot be created; the
        // I/O error must surface as a CurlError (not a panic).
        let result = KeyLog::open_path("/this/directory/should/not/exist/keylog.log");
        assert!(result.is_err());
    }

    // --- (d) explicit log() rejects invalid input safely --------------------

    #[test]
    fn write_secret_rejects_invalid_without_writing() {
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        let kl = KeyLog::open_path(tmp.path()).expect("open temp keylog");
        let cr = sample_client_random();

        // Over-long label, over-long secret, empty secret, wrong cr length all
        // return false and must NOT write a (malformed) line or panic.
        assert!(!kl.write_secret(&"x".repeat(KEYLOG_LABEL_MAXLEN + 1), &cr, &[0xab]));
        assert!(!kl.write_secret("L", &cr, &[0u8; SECRET_MAXLEN + 1]));
        assert!(!kl.write_secret("L", &cr, &[]));
        assert!(!kl.write_secret("L", &[0u8; 10], &[0xab]));
        // The trait entry point must equally tolerate bad input silently.
        RustlsKeyLog::log(&kl, &"x".repeat(KEYLOG_LABEL_MAXLEN + 1), &cr, &[0xab]);
        drop(kl);

        let contents = std::fs::read(tmp.path()).expect("read back");
        assert!(
            contents.is_empty(),
            "no malformed line should ever be written"
        );
    }

    #[test]
    fn write_line_enforces_bounds_and_newline() {
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        let kl = KeyLog::open_path(tmp.path()).expect("open temp keylog");

        // Empty and over-long (255 > 254) are rejected, writing nothing.
        assert!(!kl.write_line(""));
        assert!(!kl.write_line(&"a".repeat(KEYLOG_LINE_MAXLEN + 1)));

        // Exactly 254 bytes is accepted and a single newline is appended.
        let max_line = "b".repeat(KEYLOG_LINE_MAXLEN);
        assert!(kl.write_line(&max_line));
        // A line already ending in '\n' is written verbatim (no doubled LF).
        assert!(kl.write_line("already\n"));
        drop(kl);

        let contents = std::fs::read_to_string(tmp.path()).expect("read back");
        assert_eq!(contents, format!("{max_line}\nalready\n"));
    }

    #[test]
    fn disabled_logger_is_inert() {
        let kl = KeyLog::disabled();
        assert!(!kl.is_enabled());
        assert!(!RustlsKeyLog::will_log(&kl, "CLIENT_RANDOM"));

        let cr = sample_client_random();
        assert!(!kl.write_secret("CLIENT_RANDOM", &cr, &[0xab]));
        assert!(!kl.write_line("anything"));
        // log() on a disabled logger must be a no-op and must not panic.
        RustlsKeyLog::log(&kl, "CLIENT_RANDOM", &cr, &[0xab]);
    }

    // --- (c) key_log()/key_log_explicit() env-driven selection --------------

    #[test]
    fn key_log_is_disabled_when_env_unset() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var(SSLKEYLOGFILE_ENV);

        // NoKeyLog: will_log must be false so rustls skips secret derivation.
        assert!(!key_log().will_log("CLIENT_RANDOM"));
        assert!(!key_log_explicit().will_log("CLIENT_RANDOM"));
    }

    #[test]
    fn key_log_is_enabled_when_env_set() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        env::set_var(SSLKEYLOGFILE_ENV, tmp.path());

        // Primary path is backed by rustls::KeyLogFile, whose will_log is true.
        assert!(key_log().will_log("CLIENT_RANDOM"));

        env::remove_var(SSLKEYLOGFILE_ENV);
    }

    #[test]
    fn key_log_explicit_writes_when_env_set() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        env::set_var(SSLKEYLOGFILE_ENV, tmp.path());

        let logger = key_log_explicit();
        assert!(logger.will_log("CLIENT_RANDOM"));
        let cr = sample_client_random();
        logger.log("CLIENT_RANDOM", &cr, &[0xde, 0xad, 0xbe, 0xef]);

        env::remove_var(SSLKEYLOGFILE_ENV);

        let contents = std::fs::read_to_string(tmp.path()).expect("read back");
        assert_eq!(
            contents,
            format!("CLIENT_RANDOM {} deadbeef\n", to_hex(&cr))
        );
    }

    // --- thread-safety surface ---------------------------------------------

    #[test]
    fn key_log_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KeyLog>();
        assert_send_sync::<Arc<dyn rustls::KeyLog>>();
    }
}
