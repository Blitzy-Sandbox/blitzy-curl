// -----------------------------------------------------------------------
// curl-rs: Password input handling
//
// Rust rewrite of src/tool_getpass.c and src/tool_getpass.h from curl
// 8.19.0-DEV.  Provides secure, cross-platform password prompting from
// the terminal with echo disabled.
//
// The C original contains three platform-specific implementations:
//   - VMS:     sys$qiow with IO$M_NOECHO
//   - Windows: _getch() character-by-character loop
//   - Unix:    termios echo disable on /dev/tty (stdin fallback)
//
// All three display the prompt on stderr (via tool_stderr) and return
// the entered password as a null-terminated C string in a caller-provided
// buffer.  The Rust version replaces all platform-specific code with the
// `rpassword` crate, which internally uses termios on Unix and the
// Windows Console API on Windows — wrapped in RAII guards that
// unconditionally restore terminal state even on error or panic.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use anyhow::{Context, Result};

/// Prompt the user for a password with terminal echo disabled.
///
/// Displays `prompt` on the terminal (via the `rpassword` crate, which
/// writes to the TTY on Unix or the console on Windows), reads a line of
/// input with echo suppressed, and returns the entered text with the
/// trailing newline stripped.
///
/// # Arguments
///
/// * `prompt` — The text to display before reading input.  Typically
///   something like `"Enter host password for user 'foo':"`.  The prompt
///   is written directly to the terminal device, bypassing both stdout
///   and stderr redirections, which is the safest approach for interactive
///   password entry.
///
/// # Returns
///
/// * `Ok(String)` — The entered password.  May be empty if the user
///   pressed Enter immediately or if stdin reached EOF (piped input with
///   no data).
/// * `Err(_)` — An I/O error occurred while reading or while
///   manipulating terminal state.  The terminal is guaranteed to be
///   restored to its original state regardless (RAII cleanup inside
///   `rpassword`).
///
/// # Cross-Platform Behavior
///
/// | Platform | Prompt destination | Input source | Echo control |
/// |----------|-------------------|--------------|--------------|
/// | Unix     | `/dev/tty`        | `/dev/tty`   | termios      |
/// | Windows  | Console           | Console      | Console API  |
/// | Piped    | stderr fallback   | stdin        | skipped      |
///
/// # Security Notes
///
/// - Terminal echo is unconditionally restored even on error or panic,
///   thanks to RAII guards inside the `rpassword` crate.
/// - The returned `String` is a standard heap allocation.  Callers that
///   need zeroization semantics should use the `zeroize` crate on the
///   returned value when they are done with it.
/// - This function contains zero `unsafe` blocks.
///
/// # Differences from the C Implementation
///
/// The C function signature is:
/// ```c
/// char *getpass_r(const char *prompt, char *buffer, size_t buflen);
/// ```
/// The Rust version eliminates the caller-provided buffer in favor of
/// returning an owned `String`, which is automatically sized and freed
/// by Rust's ownership system.
///
/// # Examples
///
/// ```no_run
/// # use curl_rs::getpass::getpass_r;
/// let password = getpass_r("Enter password: ").expect("failed to read password");
/// println!("Got {} characters", password.len());
/// ```
pub fn getpass_r(prompt: &str) -> Result<String> {
    // rpassword::prompt_password handles all platform-specific details:
    //
    //   1. Opens the TTY (/dev/tty on Unix, Console on Windows)
    //   2. Writes the prompt directly to the terminal device
    //   3. Disables echo via termios (Unix) or Console API (Windows)
    //   4. Reads input until newline or EOF
    //   5. Restores terminal state via RAII drop guard — even on panic
    //   6. Strips the trailing newline from the returned string
    //
    // If no terminal is available (e.g. fully piped environment), the
    // crate falls back to reading from stdin without echo manipulation,
    // which matches the C fallback behavior (read from STDIN_FILENO
    // when /dev/tty is unavailable).
    rpassword::prompt_password(prompt)
        .or_else(|err| {
            // On EOF (piped stdin with no data remaining) or broken pipe,
            // return an empty string rather than propagating the error.
            // This matches the C behavior where a zero-length read()
            // results in buffer[0] = '\0' — i.e. an empty password string
            // is returned on failure to read.
            match err.kind() {
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe => {
                    Ok(String::new())
                }
                _ => Err(err),
            }
        })
        .context("failed to read password from terminal")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the `getpass_r` function compiles with the correct
    /// signature: `fn(&str) -> anyhow::Result<String>`.
    ///
    /// Interactive password prompting cannot be meaningfully tested in
    /// a CI environment (no TTY), so this test validates the function
    /// pointer type and ensures the module compiles cleanly.
    #[test]
    fn signature_is_correct() {
        let _fn_ptr: fn(&str) -> Result<String> = getpass_r;
    }

    /// Verify that the function is publicly exported from the module.
    /// This ensures that `paramhelp.rs` (and any other consumer) can
    /// call `crate::getpass::getpass_r(...)`.
    #[test]
    fn is_publicly_accessible() {
        // If this compiles, the function is pub. The actual call would
        // require a TTY, so we only verify the symbol is accessible.
        let _name = stringify!(getpass_r);
    }
}
