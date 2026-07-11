// SPDX-License-Identifier: curl

//! `SSLKEYLOGFILE` support — TLS secret logging in the NSS Key Log Format.
//!
//! This module is a faithful Rust port of curl's `lib/vtls/keylog.c` (and its
//! declaration-only companion `lib/vtls/keylog.h`). It reproduces curl's
//! behavior for the well-known `SSLKEYLOGFILE` debugging facility: when that
//! environment variable names a file, the TLS stack appends the per-session
//! secrets to it so that a packet capture (e.g. in Wireshark) can be
//! decrypted after the fact.
//!
//! # NSS Key Log Format
//!
//! Each logged secret is one text line of the form
//!
//! ```text
//! <LABEL> <hex(client_random)> <hex(secret)>\n
//! ```
//!
//! where the two hex fields are lowercase, two hex digits per byte, and the
//! three fields are separated by single ASCII spaces. `LABEL` is one of the
//! NSS labels chosen by the TLS implementation (for example `CLIENT_RANDOM`
//! for a TLS 1.2 master secret, or `CLIENT_HANDSHAKE_TRAFFIC_SECRET` /
//! `SERVER_TRAFFIC_SECRET_0` and friends for TLS 1.3). Wireshark parses this
//! format strictly, so the byte layout produced here — label, one space,
//! lowercase-hex client random, one space, lowercase-hex secret, one trailing
//! line feed — is kept byte-identical to curl's `Curl_tls_keylog_write`.
//!
//! # Integration with `rustls`
//!
//! In the C tree each TLS backend called the `Curl_tls_keylog_*` functions
//! directly. In this rewrite `rustls` is the single TLS backend, and it drives
//! key logging through its [`rustls::KeyLog`] trait. This module therefore
//! exposes [`KeyLogFile`], an implementation of that trait, together with the
//! [`key_log`] constructor that `tls::config` installs on the
//! `rustls::ClientConfig::key_log` field. Exactly as in curl, no key-logging
//! machinery is active unless the user opts in by setting `SSLKEYLOGFILE`:
//! [`KeyLogFile::will_log`] returns `false` when the variable is unset, so
//! `rustls` skips the work entirely.
//!
//! # Security
//!
//! The secrets written here are **extremely** sensitive: anyone with the log
//! file and a matching packet capture can decrypt the corresponding TLS
//! sessions, past and future. Nothing is ever written unless the user
//! explicitly requests it via `SSLKEYLOGFILE`, mirroring curl's opt-in policy.
//!
//! # Implementation notes
//!
//! * Writes are plain, best-effort synchronous file appends (curl used
//!   buffered `fputs`); this module therefore uses [`std::fs`] / [`std::io`]
//!   and never spawns a task. Logging must never disrupt a transfer, so every
//!   failure — a missing or unopenable file, an I/O error, even a poisoned
//!   lock —
//!   is silently ignored, matching curl's callers which discard the returned
//!   `bool`.
//! * The open file handle is a process-global initialized once from the
//!   environment (the idiomatic equivalent of curl's `static FILE
//!   *keylog_file_fp`), guarded by a [`std::sync::Mutex`] so concurrent
//!   connections may append safely.
//! * The module is written wholly in safe Rust so the crate-wide safety audit
//!   (`grep` over `curl-rs-lib/src/`) stays green.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

/// Maximum accepted length of an NSS key-log *label*, in bytes.
///
/// Mirrors curl's `KEYLOG_LABEL_MAXLEN`, defined as
/// `sizeof("CLIENT_HANDSHAKE_TRAFFIC_SECRET") - 1` — the longest label curl
/// emits (31 bytes). Computed the same way here so the value stays in lockstep
/// with the reference definition.
const KEYLOG_LABEL_MAXLEN: usize = "CLIENT_HANDSHAKE_TRAFFIC_SECRET".len();

/// Size, in bytes, of the TLS client random (mirrors curl's
/// `CLIENT_RANDOM_SIZE`). `rustls` always hands us exactly this many bytes for
/// the `client_random` argument of [`rustls::KeyLog::log`].
const CLIENT_RANDOM_SIZE: usize = 32;

/// Maximum accepted length of a logged secret, in bytes (curl's
/// `SECRET_MAXLEN`).
///
/// The TLS 1.2 master secret is always 48 bytes. In TLS 1.3 the secret size
/// follows the cipher suite's hash function — 32 bytes for SHA-256 and 48 for
/// SHA-384 — so 48 is the upper bound in every case.
const SECRET_MAXLEN: usize = 48;

/// Maximum accepted length, in bytes, of a raw line handed to [`write_line`]
/// *before* the trailing line feed is appended.
///
/// curl's `Curl_tls_keylog_write_line` used a 256-byte stack buffer and
/// reserved two bytes for the appended line feed and the C NUL terminator,
/// rejecting any line longer than `sizeof(buf) - 2`. Rust writes UTF-8 bytes
/// directly and stores no NUL terminator, so the equivalent cap that still
/// fits the historical buffer once the line feed is appended is 255. This is a
/// pure sanity bound: a well-formed NSS line never exceeds 195 bytes
/// (`31 + 1 + 2*32 + 1 + 2*48 + 1`), so it never triggers in practice.
const MAX_LINE_LEN: usize = 255;

/// Format a single NSS key-log line from its constituent parts.
///
/// This is the Rust counterpart of curl's `Curl_tls_keylog_write`: it performs
/// the same sanity checks and produces the same bytes. It returns [`None`]
/// (and logs nothing) when any check fails, exactly like curl returning
/// `FALSE`:
///
/// * the `label` is longer than [`KEYLOG_LABEL_MAXLEN`] bytes,
/// * the `secret` is empty, or
/// * the `secret` is longer than [`SECRET_MAXLEN`] bytes.
///
/// On success the returned string is
/// `"<label> <hex(client_random)> <hex(secret)>\n"`, where each hex field uses
/// lowercase, two digits per byte (matching curl's `Curl_hexbyte`), fields are
/// separated by single spaces, and the line ends with exactly one line feed.
///
/// The `client_random` slice is written verbatim as `rustls` supplies it
/// (always [`CLIENT_RANDOM_SIZE`] bytes); its length is not otherwise
/// constrained, matching curl's fixed-size `client_random[32]` parameter.
fn format_keylog_line(label: &str, client_random: &[u8], secret: &[u8]) -> Option<String> {
    // Sanity checks, identical to curl's guard in `Curl_tls_keylog_write`.
    // "Should never happen" in normal operation, but we validate anyway and
    // simply decline to log rather than emit a malformed line.
    if label.len() > KEYLOG_LABEL_MAXLEN || secret.is_empty() || secret.len() > SECRET_MAXLEN {
        return None;
    }

    // Reserve the worst-case capacity up front, mirroring the fixed-size
    // `line[]` array curl declared. Using every size constant here also keeps
    // them all genuinely referenced.
    let mut line = String::with_capacity(
        KEYLOG_LABEL_MAXLEN + 1 + 2 * CLIENT_RANDOM_SIZE + 1 + 2 * SECRET_MAXLEN + 1,
    );

    line.push_str(label);
    line.push(' ');
    // Client random, lowercase hex. Writing into a `String` via `fmt::Write`
    // is infallible, so the `Result` is deliberately discarded.
    for &byte in client_random {
        let _ = write!(line, "{byte:02x}");
    }
    line.push(' ');
    // Secret, lowercase hex.
    for &byte in secret {
        let _ = write!(line, "{byte:02x}");
    }
    line.push('\n');

    Some(line)
}

/// Open (creating if necessary) the key-log file at `path` in append mode.
///
/// Best-effort: any I/O failure yields [`None`] so that logging simply stays
/// disabled rather than surfacing an error, matching curl's behavior when
/// `curlx_fopen` fails. Append mode (`O_APPEND` on Unix) is what preserves any
/// existing contents and makes each write land at the end of the file.
fn open_keylog_at(path: &Path) -> Option<Mutex<File>> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
        .map(Mutex::new)
}

/// Read `SSLKEYLOGFILE` from the environment and open the named file.
///
/// Returns [`None`] when the variable is unset (or not valid Unicode) or when
/// the file cannot be opened — in every such case key logging is disabled,
/// exactly as in curl's `Curl_tls_keylog_open`.
fn open_keylog_from_env() -> Option<Mutex<File>> {
    let path = std::env::var("SSLKEYLOGFILE").ok()?;
    open_keylog_at(Path::new(&path))
}

/// Return the process-global key-log file handle, opening it once on first use.
///
/// This is the idiomatic equivalent of curl's `static FILE *keylog_file_fp`
/// combined with the idempotent `Curl_tls_keylog_open`: the environment is read
/// and the file opened exactly once for the lifetime of the process. If
/// `SSLKEYLOGFILE` is unset (or the file cannot be opened) the stored value is
/// [`None`] and every subsequent lookup is a cheap no-op.
fn keylog_file() -> Option<&'static Mutex<File>> {
    static KEYLOG_FILE: OnceLock<Option<Mutex<File>>> = OnceLock::new();
    KEYLOG_FILE.get_or_init(open_keylog_from_env).as_ref()
}

/// Return `true` iff key logging is active (i.e. `SSLKEYLOGFILE` named a file
/// that was opened successfully).
///
/// Mirrors curl's `Curl_tls_keylog_enabled`. The first call lazily performs the
/// one-time open described on [`keylog_file`].
pub fn is_enabled() -> bool {
    keylog_file().is_some()
}

/// Append `line` to `file`, ensuring it is terminated by a single line feed.
///
/// This is the shared mechanism behind both [`write_line`] and
/// [`KeyLogFile::log`], factored out so it can be exercised against an
/// arbitrary file in tests. It applies curl's `Curl_tls_keylog_write_line`
/// validation (reject empty or oversized lines), then performs a single
/// best-effort `write_all` of the fully terminated line so the append is one
/// atomic operation under `O_APPEND`. All failures — validation, lock
/// poisoning, or I/O — are silently ignored; logging never disrupts a transfer.
fn append_line(file: &Mutex<File>, line: &str) {
    let len = line.len();
    if len == 0 || len > MAX_LINE_LEN {
        // Empty line, or too big to be a valid key-log entry.
        return;
    }

    // Recover from a poisoned lock instead of panicking: a previous writer
    // panicking must not turn best-effort logging into a hard failure.
    let mut guard = match file.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    if line.as_bytes().last() == Some(&b'\n') {
        // Already newline-terminated: write it as-is in one call.
        let _ = guard.write_all(line.as_bytes());
    } else {
        // Assemble the terminated line first so the append is a single write.
        let mut buf = String::with_capacity(len + 1);
        buf.push_str(line);
        buf.push('\n');
        let _ = guard.write_all(buf.as_bytes());
    }
}

/// Append a pre-formatted line to the `SSLKEYLOGFILE`, terminating it with a
/// line feed if necessary.
///
/// Mirrors curl's `Curl_tls_keylog_write_line`. Empty lines and lines longer
/// than [`MAX_LINE_LEN`] bytes are rejected; everything else is written
/// best-effort. When key logging is disabled this is a no-op.
pub fn write_line(line: &str) {
    if let Some(file) = keylog_file() {
        append_line(file, line);
    }
}

/// A [`rustls::KeyLog`] implementation that appends secrets to the file named
/// by `SSLKEYLOGFILE`, in the NSS Key Log Format.
///
/// This is a zero-sized handle: the actual file lives in a process-global (see
/// [`keylog_file`]), matching curl's single shared `keylog_file_fp`. Install it
/// on a `rustls::ClientConfig` via [`key_log`].
///
/// Note: `rustls` also ships its own `rustls::KeyLogFile`; this type is a
/// distinct, curl-faithful implementation kept here so the exact environment
/// variable, label handling, and byte format match curl 8.x and stay unit
/// testable.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyLogFile;

impl rustls::KeyLog for KeyLogFile {
    /// Format the secret as an NSS key-log line and append it, best-effort.
    ///
    /// `rustls` passes the NSS `label`, the 32-byte `client_random`, and the
    /// `secret`; these are forwarded to [`format_keylog_line`] exactly as
    /// curl's `cr_keylog_log_cb` forwarded them to `Curl_tls_keylog_write`.
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if let Some(line) = format_keylog_line(label, client_random, secret) {
            write_line(&line);
        }
    }

    /// Report whether logging is active, letting `rustls` skip deriving and
    /// passing secrets when it is not. Equivalent to gating each call on curl's
    /// `Curl_tls_keylog_enabled`.
    fn will_log(&self, _label: &str) -> bool {
        is_enabled()
    }
}

/// Construct the key logger to install on `rustls::ClientConfig::key_log`.
///
/// `tls::config` calls this (only when `SSLKEYLOGFILE` is set) to wire curl's
/// key-logging behavior into `rustls`. Even if installed unconditionally the
/// logger is inert while `SSLKEYLOGFILE` is unset, because
/// [`KeyLogFile::will_log`] returns `false` and [`KeyLogFile::log`] finds no
/// open file — so no secrets are ever written unless the user opts in.
pub fn key_log() -> Arc<dyn rustls::KeyLog> {
    Arc::new(KeyLogFile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::KeyLog as _;
    use std::sync::Mutex as StdMutex;

    /// Serializes every test that reads or mutates the `SSLKEYLOGFILE`
    /// environment variable or touches the process-global key-log handle, so
    /// they never race on shared process state. Tests that only exercise the
    /// pure helpers ([`format_keylog_line`], [`append_line`], [`open_keylog_at`])
    /// need not take this lock.
    static ENV_GUARD: StdMutex<()> = StdMutex::new(());

    /// Run `body` while holding [`ENV_GUARD`], recovering from a poisoned lock
    /// so one failing test does not cascade into the others.
    fn with_env_lock<T>(body: impl FnOnce() -> T) -> T {
        let guard = ENV_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result = body();
        drop(guard);
        result
    }

    // ---- `format_keylog_line` : byte-exact NSS formatting ----

    #[test]
    fn format_line_matches_curl_byte_for_byte() {
        // The canonical example from the file's spec: a 32-byte client random
        // of 0xAB and a two-byte secret 0x01 0x02.
        let client_random = [0xABu8; 32];
        let secret = [0x01u8, 0x02u8];
        let line = format_keylog_line("CLIENT_RANDOM", &client_random, &secret)
            .expect("valid inputs must format");

        let expected = format!("CLIENT_RANDOM {} 0102\n", "ab".repeat(32));
        assert_eq!(line, expected);

        // Single-space separators and exactly one trailing newline.
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1);
        assert_eq!(line.matches(' ').count(), 2);

        // The label keeps its original (upper) case; only the hex fields that
        // follow it are lowercase.
        let hex_fields = &line["CLIENT_RANDOM ".len()..];
        assert_eq!(hex_fields, hex_fields.to_ascii_lowercase());
    }

    #[test]
    fn format_line_hex_is_lowercase_and_zero_padded() {
        // 0x00 -> "00", 0x0f -> "0f", 0xa0 -> "a0", 0xff -> "ff".
        let line = format_keylog_line("CLIENT_RANDOM", &[0x00, 0x0f], &[0xa0, 0xff])
            .expect("valid inputs must format");
        assert_eq!(line, "CLIENT_RANDOM 000f a0ff\n");
    }

    #[test]
    fn format_line_rejects_overlong_label() {
        // 32 bytes > KEYLOG_LABEL_MAXLEN (31).
        let too_long = "X".repeat(KEYLOG_LABEL_MAXLEN + 1);
        assert!(format_keylog_line(&too_long, &[0u8; 32], &[0x01]).is_none());
    }

    #[test]
    fn format_line_accepts_max_length_label() {
        // Exactly 31 bytes is allowed (boundary).
        let max_label = "X".repeat(KEYLOG_LABEL_MAXLEN);
        assert_eq!(max_label.len(), 31);
        assert!(format_keylog_line(&max_label, &[0u8; 32], &[0x01]).is_some());
    }

    #[test]
    fn format_line_rejects_empty_secret() {
        assert!(format_keylog_line("CLIENT_RANDOM", &[0u8; 32], &[]).is_none());
    }

    #[test]
    fn format_line_secret_length_boundaries() {
        // 48 bytes is the maximum accepted secret; 49 is rejected.
        assert!(format_keylog_line("CLIENT_RANDOM", &[0u8; 32], &[0x01; SECRET_MAXLEN]).is_some());
        assert!(
            format_keylog_line("CLIENT_RANDOM", &[0u8; 32], &[0x01; SECRET_MAXLEN + 1]).is_none()
        );
    }

    // ---- `append_line` : append semantics against a real file ----

    #[test]
    fn append_line_writes_and_terminates() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("keylog.txt");
        let file = open_keylog_at(&path).expect("open keylog file");

        // A line without a trailing newline gets exactly one appended.
        append_line(&file, "CLIENT_RANDOM aa bb");
        drop(file);

        let contents = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(contents, "CLIENT_RANDOM aa bb\n");
    }

    #[test]
    fn append_line_second_write_appends_without_truncating() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("keylog.txt");

        {
            let file = open_keylog_at(&path).expect("open keylog file");
            append_line(&file, "LINE_ONE 11 22");
            append_line(&file, "LINE_TWO 33 44");
        }
        // Re-open the same path (append mode) and add a third line: this proves
        // opening does not truncate an existing file.
        {
            let file = open_keylog_at(&path).expect("re-open keylog file");
            append_line(&file, "LINE_THREE 55 66");
        }

        let contents = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(
            contents,
            "LINE_ONE 11 22\nLINE_TWO 33 44\nLINE_THREE 55 66\n"
        );
    }

    #[test]
    fn append_line_does_not_double_existing_newline() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("keylog.txt");
        let file = open_keylog_at(&path).expect("open keylog file");

        // The output of `format_keylog_line` already ends in '\n'; feeding it
        // back must not add a second newline.
        let formatted = format_keylog_line("CLIENT_RANDOM", &[0x01u8; 32], &[0xaa, 0xbb])
            .expect("valid inputs must format");
        append_line(&file, &formatted);
        drop(file);

        let contents = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(contents, formatted);
        assert!(contents.ends_with('\n'));
        assert_eq!(contents.matches('\n').count(), 1);
    }

    #[test]
    fn append_line_rejects_empty_and_oversized() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("keylog.txt");
        let file = open_keylog_at(&path).expect("open keylog file");

        // Empty line: nothing written.
        append_line(&file, "");
        // Oversized line (> MAX_LINE_LEN): nothing written.
        let oversized = "x".repeat(MAX_LINE_LEN + 1);
        append_line(&file, &oversized);
        drop(file);

        let contents = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(contents, "", "rejected lines must not be written");
    }

    // ---- environment-driven open (serialized) ----

    #[test]
    fn open_from_env_reads_sslkeylogfile_and_appends() {
        with_env_lock(|| {
            let original = std::env::var_os("SSLKEYLOGFILE");
            let dir = tempfile::tempdir().expect("temp dir");
            let path = dir.path().join("env_keylog.txt");

            // With the variable set to a temp file, the env-driven open
            // succeeds and writes land in that file (and a second write
            // appends).
            std::env::set_var("SSLKEYLOGFILE", &path);
            let opened = open_keylog_from_env();
            assert!(opened.is_some(), "env-named keylog file must open");
            let file = opened.expect("some handle");
            append_line(&file, "CLIENT_RANDOM aa bb");
            append_line(&file, "CLIENT_RANDOM cc dd");
            drop(file);

            let contents = std::fs::read_to_string(&path).expect("read back");
            assert_eq!(contents, "CLIENT_RANDOM aa bb\nCLIENT_RANDOM cc dd\n");

            // With the variable unset, the env-driven open yields nothing.
            std::env::remove_var("SSLKEYLOGFILE");
            assert!(open_keylog_from_env().is_none());

            // Restore the caller's environment.
            match original {
                Some(value) => std::env::set_var("SSLKEYLOGFILE", value),
                None => std::env::remove_var("SSLKEYLOGFILE"),
            }
        });
    }

    // ---- disabled state (memoized global; only touched with env unset) ----

    #[test]
    fn disabled_when_sslkeylogfile_unset() {
        with_env_lock(|| {
            let original = std::env::var_os("SSLKEYLOGFILE");
            std::env::remove_var("SSLKEYLOGFILE");

            // The non-memoized source of truth reports disabled...
            assert!(open_keylog_from_env().is_none());

            // ...as do the public predicates that consult the process-global
            // handle (initialized here, with the variable unset, to `None`).
            assert!(!is_enabled());
            assert!(!KeyLogFile.will_log("CLIENT_RANDOM"));
            assert!(!key_log().will_log("CLIENT_HANDSHAKE_TRAFFIC_SECRET"));

            // Logging while disabled is a silent no-op and must never panic.
            KeyLogFile.log("CLIENT_RANDOM", &[0u8; 32], &[0x01, 0x02]);
            write_line("CLIENT_RANDOM deadbeef 0102");

            match original {
                Some(value) => std::env::set_var("SSLKEYLOGFILE", value),
                None => std::env::remove_var("SSLKEYLOGFILE"),
            }
        });
    }

    // ---- trait object wiring ----

    #[test]
    fn key_log_returns_usable_trait_object() {
        // `will_log`/`is_enabled` consult the process-global handle, so this
        // test is serialized with the other global/env tests and runs with the
        // variable unset (keeping the global's one-time init deterministic).
        with_env_lock(|| {
            let original = std::env::var_os("SSLKEYLOGFILE");
            std::env::remove_var("SSLKEYLOGFILE");

            // The constructor yields an `Arc<dyn rustls::KeyLog>` (what
            // `ClientConfig::key_log` expects) whose `will_log` tracks
            // `is_enabled()`.
            let logger: Arc<dyn rustls::KeyLog> = key_log();
            assert_eq!(logger.will_log("CLIENT_RANDOM"), is_enabled());

            match original {
                Some(value) => std::env::set_var("SSLKEYLOGFILE", value),
                None => std::env::remove_var("SSLKEYLOGFILE"),
            }
        });
    }
}
