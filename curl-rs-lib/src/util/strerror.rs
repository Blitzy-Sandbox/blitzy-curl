// SPDX-License-Identifier: curl
//
// Memory-safe Rust port of curl's OS/system error-string helper.
//
// This module is the idiomatic, `unsafe`-free Rust reimplementation of
// libcurl's `lib/curlx/strerr.c` / `lib/curlx/strerr.h` — specifically the
// thread-safe `curlx_strerror(int err, char *buf, size_t buflen)` routine that
// turns a raw operating-system error number into a human-readable message. The
// C sources are consulted only as a behavioral oracle; nothing is
// transliterated line-by-line.

//! OS / system error-number → string helpers.
//!
//! This is the Rust successor to libcurl's `lib/curlx/strerr.c`
//! (`curlx_strerror`). Its sole job is to turn a raw **operating-system error
//! number** — `errno` on POSIX, or a `GetLastError` / `WSAGetLastError` code on
//! Windows — into a human-readable string, exactly as the C helper does for
//! socket and syscall failure reporting.
//!
//! # Scope boundary (read this first)
//!
//! curl has *two* distinct families of "strerror" functions, and this module
//! owns **only one** of them:
//!
//! * **OS / system error numbers → string** — `curlx_strerror` in
//!   `lib/curlx/strerr.c`. **This module implements this one.**
//! * **libcurl result codes → string** — `curl_easy_strerror`,
//!   `curl_multi_strerror`, `curl_share_strerror` and `curl_url_strerror` in
//!   `lib/strerror.c`, which map `CURLcode` / `CURLMcode` / `CURLSHcode` /
//!   `CURLUcode` values to their canonical descriptions. **Those are owned by
//!   `crate::error`** — they back the `Display` implementations of `CurlError`
//!   and its sibling result-code enums — and MUST NOT be re-implemented here.
//!
//! Keeping the split clean means the ABI-significant result-code text lives in
//! exactly one place (`crate::error`) with no duplication. The Windows SSPI
//! variant (`Curl_sspi_strerror` in `lib/strerror.c`) is out of scope for the
//! `rustls`-only build and is intentionally not ported.
//!
//! # Memory safety
//!
//! The C implementation hand-rolls a thread-safe `strerror_r` /
//! `FormatMessageA` wrapper with manual `errno` / `GetLastError`
//! save-and-restore and fixed-size caller buffers. The Rust standard library
//! already provides exactly this — thread-safe, cross-platform OS-error
//! formatting — through [`std::io::Error`], with **no `unsafe`** and no manual
//! FFI. This module is therefore a thin, safe wrapper over the standard library
//! and compiles under the module-level `#![forbid(unsafe_code)]` declared below
//! (consistent with the crate-wide guarantee at the `curl-rs-lib` crate root).
//!
//! # Behavioral parity notes
//!
//! * **Owned `String` instead of a caller buffer.** The C signature writes into
//!   a `char *buf` and returns it; the idiomatic Rust form returns an owned
//!   [`String`]. A buffer-shaped variant, [`curlx_strerror_into`], is provided
//!   for ported call sites that want to mirror the C "fill my buffer" shape.
//! * **Message text.** [`std::io::Error`] renders recognized code messages
//!   through the same platform facilities that curl uses, but Rust appends an
//!   implementation-specific `" (os error N)"` suffix. The wrapper removes that
//!   suffix and preserves curl's `"Unknown error N"` fallback shape for
//!   unrecognized codes so user-visible diagnostics stay byte-compatible with
//!   the C helper wherever the underlying platform wording is the same.
//! * **No range checking.** Like the C helper, no validation is performed on
//!   `err`; out-of-range or negative values produce the standard-library
//!   fallback string rather than panicking.
//! * **`errno` preservation.** The C code explicitly saves and restores `errno`
//!   so that reporting an error never clobbers it. The Rust helpers preserve
//!   this property for free: [`curlx_strerror`] formats a value supplied by the
//!   caller and never reads the live `errno`, while [`last_os_error`] reads it
//!   exactly once without mutating it.

#![forbid(unsafe_code)]
// The OS-string helpers are parity shims consumed by ported call sites (socket
// and syscall error reporting in `conn`, `dns`, the protocol engines, ...).
// During the staged C→Rust migration not every caller exists yet, and whether a
// given helper is reachable depends on how the surrounding `util` module is
// wired, so `dead_code` is allowed here to keep `clippy -D warnings` green
// regardless. The small surface is intentionally complete so any ported call
// site can reference the exact upstream name.
#![allow(dead_code)]

/// Formats an operating-system error number into an owned, human-readable
/// [`String`].
///
/// This is the Rust analogue of libcurl's `curlx_strerror(int err, char *buf,
/// size_t buflen)` from `lib/curlx/strerr.c`, returning an owned [`String`]
/// instead of writing into a caller-supplied buffer. `err` is interpreted as a
/// platform error number — `errno` on POSIX, or a `GetLastError` /
/// `WSAGetLastError` code on Windows — and is formatted through
/// [`std::io::Error::from_raw_os_error`], which delegates to the platform's
/// thread-safe message lookup (`strerror_r` / `FormatMessage`).
///
/// Recognized codes yield the platform message with Rust's trailing
/// `" (os error N)"` suffix removed; unrecognized codes yield curl's non-empty
/// `"Unknown error N"` fallback. The function never panics and performs no
/// range checking on `err`, matching the C helper's documented contract. For
/// example, on POSIX systems `curlx_strerror(2)` (`ENOENT`) returns
/// `"No such file or directory"`.
#[inline]
#[must_use]
pub fn curlx_strerror(err: i32) -> String {
    format_raw_os_error(err)
}

/// Formats a raw OS error code using the standard library and normalizes the
/// wording to curl's `curlx_strerror` shape.
#[inline]
fn format_raw_os_error(err: i32) -> String {
    normalize_os_error_message(err, std::io::Error::from_raw_os_error(err).to_string())
}

/// Removes Rust-specific adornments from the platform error text.
///
/// The C helper copies the platform message directly, falls back to
/// `"Unknown error N"` when the platform cannot render the code, and strips any
/// trailing CR/LF from Windows messages. `std::io::Error` can append
/// `" (os error N)"`; removing that suffix restores curl-compatible
/// diagnostics without introducing any unsafe `strerror_r`/`FormatMessage`
/// calls.
#[inline]
fn normalize_os_error_message(err: i32, message: String) -> String {
    let message = message.trim_end_matches(['\r', '\n']);
    let suffix = format!(" (os error {err})");
    message.strip_suffix(&suffix).unwrap_or(message).to_owned()
}

/// Buffer-shaped parity variant of [`curlx_strerror`].
///
/// Mirrors the C `curlx_strerror(err, buf, buflen)` "fill the caller's buffer"
/// shape for ported call sites that reuse a scratch [`String`]: `buf` is
/// cleared and then overwritten with the formatted message, so any previous
/// contents are discarded. Provided purely for porting convenience; new Rust
/// code should prefer [`curlx_strerror`].
#[inline]
pub fn curlx_strerror_into(err: i32, buf: &mut String) {
    buf.clear();
    buf.push_str(&curlx_strerror(err));
}

/// Formats the calling thread's *current* last OS error into an owned
/// [`String`].
///
/// Wraps [`std::io::Error::last_os_error`], which reads the platform's live
/// error indicator (`errno` on POSIX, `GetLastError` on Windows). This mirrors
/// curl call sites that report the most recent failure straight from
/// `SOCKERRNO` / `errno` without first capturing the numeric code. The read is
/// non-mutating, so it does not disturb the value for subsequent inspection.
#[inline]
#[must_use]
pub fn last_os_error() -> String {
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(err) => normalize_os_error_message(err, error.to_string()),
        None => error.to_string().trim_end_matches(['\r', '\n']).to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code must produce a non-empty diagnostic string.
    #[test]
    fn known_code_is_non_empty() {
        assert!(!curlx_strerror(2).is_empty());
    }

    /// `2` is `ENOENT` on POSIX. Assert a recognizable substring rather than an
    /// exact, locale-/platform-dependent string so the test stays portable.
    #[cfg(unix)]
    #[test]
    fn enoent_message_is_recognizable() {
        let msg = curlx_strerror(2);
        assert!(
            msg.contains("No such file or directory"),
            "unexpected ENOENT rendering: {msg:?}"
        );
        assert!(
            !msg.contains("os error 2"),
            "Rust-specific OS suffix must be stripped: {msg:?}"
        );
    }

    /// An out-of-range / unrecognized code must still yield a non-empty
    /// fallback matching curl's `"Unknown error N"` shape.
    #[test]
    fn unknown_code_has_non_empty_fallback() {
        let msg = curlx_strerror(999_999);
        assert_eq!(msg, "Unknown error 999999");
    }

    /// Parity with the C helper: no range checking, no panic on negative input.
    #[test]
    fn negative_code_does_not_panic() {
        let msg = curlx_strerror(-1);
        assert!(!msg.is_empty());
        assert!(
            !msg.contains("os error -1"),
            "Rust-specific OS suffix must be stripped: {msg:?}"
        );
    }

    /// The buffer variant must clear stale content and then match the
    /// owned-`String` form exactly.
    #[test]
    fn into_variant_matches_and_clears() {
        let mut buf = String::from("stale contents that must be cleared");
        curlx_strerror_into(2, &mut buf);
        assert_eq!(buf, curlx_strerror(2));
        assert!(!buf.contains("stale"));
        assert!(!buf.is_empty());
    }

    /// Reading the live OS error always renders to a non-empty diagnostic
    /// string, whatever the current `errno` value happens to be.
    #[test]
    fn last_os_error_is_non_empty() {
        assert!(!last_os_error().is_empty());
    }
}
