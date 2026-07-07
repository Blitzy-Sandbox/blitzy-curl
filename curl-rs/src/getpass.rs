// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_getpass.c (interactive no-echo password prompt).

//! Interactive, no-echo password prompt.
//!
//! This module is the Rust rewrite of curl 8.19.0-DEV's `src/tool_getpass.c`. It exposes a
//! single entry point, [`getpass_r`], which prints a prompt to the terminal, reads a line of
//! input **without echoing keystrokes**, and returns the entered secret with its trailing
//! end-of-line byte removed.
//!
//! # Behavior parity with curl
//!
//! The implementation mirrors the POSIX `termios` branch of curl's `getpass_r` (the
//! `HAVE_TERMIOS_H` path guarded by `#ifndef DONE`) exactly:
//!
//! 1. The controlling terminal is opened read-only via `/dev/tty`; if that cannot be opened
//!    (for example when the process has no controlling terminal) the read falls back to
//!    standard input — identical to curl's `curlx_open("/dev/tty", O_RDONLY)` with its
//!    `STDIN_FILENO` fallback.
//! 2. The current terminal attributes are saved with `tcgetattr`.
//! 3. A copy with the `ECHO` bit cleared from `c_lflag` is installed with
//!    `tcsetattr(.., TCSANOW, ..)`, disabling local echo while preserving canonical
//!    (line-buffered) input.
//! 4. The prompt is written to standard error (curl writes to `tool_stderr`).
//! 5. A single read of up to `buflen` bytes is performed and the final byte — the terminating
//!    newline produced by the user's <kbd>Enter</kbd> — is dropped, reproducing curl's
//!    `buffer[--nread] = '\0'`.
//! 6. The original terminal attributes are restored with `tcsetattr(.., TCSAFLUSH, ..)`. This
//!    restoration is performed by an RAII guard ([`EchoGuard`]) so it happens on **every** exit
//!    path, including early returns, errors, and unwinding — the terminal is never left with
//!    echo disabled.
//! 7. A trailing newline is emitted to standard error, because the user's <kbd>Enter</kbd>
//!    keystroke was suppressed along with the rest of the echo.
//!
//! # Platform scope
//!
//! Only the POSIX `termios` behavior is ported. curl's `__VMS`, `_WIN32` (`_getch` /
//! `SetConsoleMode`) and NetWare branches are intentionally out of scope: the Rust rewrite
//! targets Linux and macOS only (AAP §0.6.5).
//!
//! # `unsafe` policy
//!
//! Per AAP §0.6.2 / §0.7.2, `unsafe` outside the FFI crate is permitted only for narrow
//! OS-integration primitives that genuinely require it. Here it is confined to the `libc`
//! `termios` calls (`tcgetattr` / `tcsetattr`) and the preparation of the `termios`
//! out-parameter they write into; every `unsafe` block carries a `// SAFETY:` comment stating
//! the invariant it upholds. Reading the secret itself uses safe [`std::io`].

// The public entry point of this module (`getpass_r`) is consumed by the argument- and
// operation-handling layer (`args.rs` / `operate.rs`) when a required password is not supplied
// on the command line — for example `-u user:` with an empty password, `--proxy-user`, or an
// SSH key passphrase. Those callers are wired up in a later build-order checkpoint (AAP
// §0.7.3); until then this module has no in-crate caller, so `dead_code` is allowed to keep the
// foundation build warning-free. The allowance becomes a harmless no-op once the callers land,
// at which point every item below is reachable. This mirrors the convention already used by the
// sibling FFI crate.
#![allow(dead_code)]

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};

/// RAII guard that disables terminal echo and restores the original attributes on drop.
///
/// Constructing the guard via [`EchoGuard::disable`] saves the terminal's current attributes and
/// installs a copy with the `ECHO` flag cleared. When the guard is dropped — whether the
/// enclosing scope returns normally, returns early, or unwinds due to a panic — the saved
/// attributes are reinstalled. This guarantees the terminal is never left with echo disabled,
/// matching curl's paired `ttyecho(FALSE, fd)` / `ttyecho(TRUE, fd)` calls while being robust
/// against every early-exit path.
struct EchoGuard {
    /// The terminal file descriptor whose attributes were modified. Borrowed, never owned: the
    /// descriptor belongs to the caller's [`File`] (or is `STDIN_FILENO`) and outlives the
    /// guard, so the guard must not — and does not — close it.
    fd: RawFd,
    /// The terminal attributes captured before echo was disabled; restored verbatim on drop.
    original: libc::termios,
}

impl EchoGuard {
    /// Disable local echo on `fd`, returning a guard that restores the previous attributes on
    /// drop.
    ///
    /// Returns `None` when `fd` does not refer to a terminal (for example when standard input is
    /// a pipe or a regular file): there is then nothing to disable and nothing to restore. This
    /// matches curl, whose `tcgetattr`/`tcsetattr` calls fail harmlessly on a non-terminal
    /// descriptor.
    fn disable(fd: RawFd) -> Option<Self> {
        // A `termios` to receive the current attributes. `libc::termios` is a plain-old-data C
        // struct, so an all-zero bit pattern is a valid, inert initial value; it is fully
        // overwritten by `tcgetattr` below before any field is read.
        //
        // SAFETY: `libc::termios` is a `Copy` POD aggregate of integer/array fields with no
        // validity invariant that an all-zero bit pattern could violate; no field is read until
        // `tcgetattr` populates the struct.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };

        // SAFETY: `fd` is an open file descriptor (from an owned `File` for `/dev/tty`, or the
        // process's standard input) that stays valid for the duration of this call. `tcgetattr`
        // only writes the current terminal attributes into `original` and retains no reference
        // to it. A non-zero return means `fd` is not a terminal.
        let rc = unsafe { libc::tcgetattr(fd, &mut original) };
        if rc != 0 {
            // Not a terminal (e.g. piped stdin): nothing to disable, nothing to restore.
            return None;
        }

        // Clear only the ECHO bit, leaving canonical mode and every other flag intact — the
        // direct analogue of curl's `noecho.c_lflag &= ~(tcflag_t)ECHO;`. `libc::ECHO` is itself
        // a `tcflag_t`, so no cast is needed.
        let mut noecho = original;
        noecho.c_lflag &= !libc::ECHO;

        // SAFETY: `fd` is the same valid terminal descriptor; `noecho` is a fully initialized
        // `termios` (a copy of the successfully read attributes with one bit cleared) that
        // `tcsetattr` only reads from. `TCSANOW` applies the change immediately, matching curl.
        let rc = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &noecho) };
        if rc != 0 {
            // Could not modify the terminal; report "not disabled" so that no restoration is
            // attempted against attributes we never actually changed.
            return None;
        }

        Some(EchoGuard { fd, original })
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        // Restore the saved attributes. The return value is deliberately ignored: as in curl's
        // `ttyecho(TRUE, fd)`, a failed restore is not actionable here, and `drop` must never
        // panic (it may run while the stack is unwinding).
        //
        // SAFETY: `self.original` was fully populated by a successful `tcgetattr` in `disable`
        // (the guard is only constructed on that success); `self.fd` is still open because the
        // owning `File` — or `STDIN_FILENO` — outlives this guard; `tcsetattr` only reads from
        // `self.original`. `TCSAFLUSH` flushes pending input and applies the change, matching
        // curl's restore path.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original);
        }
    }
}

/// Trim the terminating end-of-line byte from a freshly read secret.
///
/// This is the pure, side-effect-free core of the read path, factored out so it can be unit
/// tested without a live terminal. It reproduces curl's post-read handling exactly:
///
/// * When nothing was read (`nread == 0`, i.e. end-of-file), the result is empty — curl's
///   `buffer[0] = '\0'`.
/// * Otherwise the **final** byte is dropped unconditionally — curl's `buffer[--nread] = '\0'`.
///   In canonical mode that byte is the newline from the user's <kbd>Enter</kbd>; if the buffer
///   filled before a newline arrived (or input ended without one) curl still drops the last
///   byte, and that exact behavior is preserved here for byte-for-byte parity.
///
/// The bytes are interpreted as UTF-8 with lossy replacement of any invalid sequences, since the
/// public API yields a [`String`]; well-formed passwords round-trip unchanged.
fn finalize_secret(buf: &[u8], nread: usize) -> String {
    if nread == 0 {
        String::new()
    } else {
        // `nread >= 1` here (the `== 0` case returned above), so `nread - 1` cannot underflow.
        String::from_utf8_lossy(&buf[..nread - 1]).into_owned()
    }
}

/// Perform the single, bounded read of the secret from `reader` and trim its trailing byte.
///
/// A lone `read` of at most `buflen` bytes is issued — matching curl's solitary
/// `read(fd, buffer, buflen)`. On success the bytes are handed to [`finalize_secret`]; on a
/// genuine I/O error `None` is returned so the caller can abort, mirroring curl's documented
/// "returning NULL will abort the continued operation" contract.
///
/// The reader is generic so the exact same logic serves both the `/dev/tty` file and the
/// standard-input fallback, and so it can be exercised directly in unit tests.
fn read_secret_from<R: Read>(mut reader: R, buflen: usize) -> Option<String> {
    let mut buf = vec![0u8; buflen];
    match reader.read(&mut buf) {
        Ok(nread) => Some(finalize_secret(&buf, nread)),
        Err(_) => None,
    }
}

/// Read the secret from the controlling terminal, falling back to standard input.
///
/// `tty` is `Some` when `/dev/tty` was opened (read directly from that file) and `None` when the
/// read must fall back to standard input — the descriptor-selection half of curl's
/// `curlx_open("/dev/tty", O_RDONLY)` / `STDIN_FILENO` logic.
fn read_secret(tty: Option<&mut File>, buflen: usize) -> Option<String> {
    match tty {
        Some(file) => read_secret_from(file, buflen),
        None => read_secret_from(io::stdin(), buflen),
    }
}

/// Prompt on the terminal and read a password without echoing it.
///
/// Prints `prompt` to standard error, reads a single line of input (up to `buflen` bytes) from
/// the controlling terminal with echo disabled, and returns the entered secret with its trailing
/// newline removed.
///
/// # Parameters
///
/// * `prompt` — the text shown to the user before input (written to standard error, as curl
///   writes to `tool_stderr`).
/// * `buflen` — the maximum number of bytes to read, mirroring the size of the fixed buffer
///   curl's C signature receives. Input longer than `buflen` is truncated exactly as curl
///   truncates it.
///
/// # Returns
///
/// * `Some(secret)` — the entered password, possibly empty if the user pressed <kbd>Enter</kbd>
///   immediately or input reached end-of-file. On the POSIX terminal path this is the normal
///   outcome, mirroring curl's `getpass_r`, which always returns its buffer here.
/// * `None` — a genuine I/O error occurred while reading; callers treat this as an abort, the
///   analogue of curl's `NULL`-return contract. (curl's POSIX path never actually fails here; a
///   read error is non-deterministic and therefore outside the deterministic parity contract.)
///
/// Terminal echo is always restored before this function returns (via [`EchoGuard`]), even if an
/// error occurs or the stack unwinds.
pub fn getpass_r(prompt: &str, buflen: usize) -> Option<String> {
    // Open the controlling terminal read-only, matching curl's
    // `curlx_open("/dev/tty", O_RDONLY)`. If it cannot be opened, `tty` is `None` and the read
    // falls back to standard input (curl's `STDIN_FILENO` fallback). The `File` owns the
    // descriptor and closes it on drop, so — unlike curl — no explicit close is required, and the
    // standard-input descriptor is never owned and therefore never closed.
    let mut tty: Option<File> = File::open("/dev/tty").ok();
    let fd: RawFd = tty
        .as_ref()
        .map_or(libc::STDIN_FILENO, |file| file.as_raw_fd());

    // Disable echo for the duration of the prompt. The guard restores the original terminal
    // attributes when it drops at the end of this function — after the trailing newline is
    // written below — reproducing curl's ordering: disable echo, prompt, read, newline, re-enable
    // echo. If `fd` is not a terminal the guard is `None` and no attributes are changed or
    // restored.
    let _echo_guard = EchoGuard::disable(fd);

    // The prompt goes to standard error, matching curl's `fputs(prompt, tool_stderr)`. Write
    // errors are ignored just as curl ignores the `fputs` return value.
    let mut stderr = io::stderr();
    let _ = stderr.write_all(prompt.as_bytes());
    let _ = stderr.flush();

    // Read the secret from the terminal (or standard input) with echo suppressed.
    let secret = read_secret(tty.as_mut(), buflen);

    // Emit a trailing newline: on `termios` platforms curl always does this because the user's
    // <kbd>Enter</kbd> was not echoed. Written before the guard drops so the observable sequence
    // matches curl (newline, then echo restored).
    let _ = stderr.write_all(b"\n");
    let _ = stderr.flush();

    secret
    // Drop order (reverse of declaration): `stderr`, then `_echo_guard` (restores the terminal
    // while `fd` is still open), then `tty` (closes `/dev/tty`). The standard-input descriptor is
    // never owned and thus never closed.
}

#[cfg(test)]
mod tests {
    use super::{finalize_secret, read_secret_from, EchoGuard};
    use std::fs::File;
    use std::io::{self, Read};
    use std::os::unix::io::AsRawFd;

    #[test]
    fn finalize_strips_trailing_newline() {
        // The common case: a line terminated by the user's Enter key.
        assert_eq!(finalize_secret(b"secret\n", 7), "secret");
    }

    #[test]
    fn finalize_drops_final_byte_when_no_newline() {
        // curl unconditionally drops the last byte via `buffer[--nread] = '\0'`, even when the
        // buffer fills before a newline is seen. Parity requires the same behavior here.
        assert_eq!(finalize_secret(b"abcde", 5), "abcd");
    }

    #[test]
    fn finalize_empty_on_eof() {
        // Nothing read (end-of-file) yields an empty secret — curl's `buffer[0] = '\0'`. The
        // buffer contents are irrelevant when `nread == 0`.
        assert_eq!(finalize_secret(b"", 0), "");
        assert_eq!(finalize_secret(&[0u8; 8], 0), "");
    }

    #[test]
    fn finalize_bare_newline_is_empty_password() {
        // Pressing Enter with no other input: the single newline is stripped, leaving "".
        assert_eq!(finalize_secret(b"\n", 1), "");
    }

    #[test]
    fn finalize_replaces_invalid_utf8() {
        // Invalid UTF-8 bytes are replaced with U+FFFD; the trailing newline is still dropped.
        assert_eq!(finalize_secret(b"a\xFFb\n", 4), "a\u{FFFD}b");
    }

    #[test]
    fn finalize_preserves_interior_bytes() {
        // Only the final byte is removed; embedded spaces and punctuation survive intact.
        assert_eq!(finalize_secret(b"p@ss w0rd!\n", 11), "p@ss w0rd!");
    }

    #[test]
    fn read_secret_from_slice_strips_newline() {
        // The generic read core reads from a byte slice (a stand-in for the terminal fd) and
        // drops the trailing newline, exercising the read + finalize wiring end to end.
        assert_eq!(
            read_secret_from(&b"hunter2\n"[..], 64).as_deref(),
            Some("hunter2")
        );
    }

    #[test]
    fn read_secret_from_truncates_to_buflen() {
        // A `buflen` smaller than the input truncates the read, then the last read byte is
        // dropped — precisely curl's behavior when the fixed buffer fills before the newline.
        assert_eq!(
            read_secret_from(&b"longpassword\n"[..], 5).as_deref(),
            Some("long")
        );
    }

    #[test]
    fn read_secret_from_eof_is_empty() {
        // An immediate EOF (empty input) yields an empty secret rather than `None`.
        assert_eq!(read_secret_from(&b""[..], 32).as_deref(), Some(""));
    }

    #[test]
    fn read_secret_from_propagates_io_error_as_none() {
        // A genuine read error must surface as `None` so the caller can abort — the Rust
        // counterpart of curl's `NULL`-return contract.
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("simulated read failure"))
            }
        }
        assert_eq!(read_secret_from(FailingReader, 16), None);
    }

    #[test]
    fn echo_guard_returns_none_on_non_terminal() {
        // `/dev/null` is a character device but not a terminal, so `tcgetattr` fails and
        // `disable` must return `None` without panicking. This exercises the `unsafe` `tcgetattr`
        // path and confirms the graceful non-terminal fallback.
        let devnull = File::open("/dev/null").expect("open /dev/null");
        let guard = EchoGuard::disable(devnull.as_raw_fd());
        assert!(
            guard.is_none(),
            "echo must not be reported as disabled on a non-terminal fd"
        );
    }

    #[test]
    fn echo_guard_drop_on_non_terminal_is_noop() {
        // Dropping the `None` result of a non-terminal `disable` must be a harmless no-op (there
        // is no guard to run), so no terminal call is made and nothing panics.
        let devnull = File::open("/dev/null").expect("open /dev/null");
        let guard = EchoGuard::disable(devnull.as_raw_fd());
        drop(guard); // must not panic or touch the terminal
    }
}
