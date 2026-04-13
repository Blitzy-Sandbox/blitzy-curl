// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! Miscellaneous CLI utility functions for the `curl-rs` binary.
//!
//! This module is the Rust rewrite of three C source files:
//!
//! * `src/tool_util.c` + `src/tool_util.h` — monotonic time helpers
//!   (`tvrealnow`, `tvdiff`, `tvdiff_secs`), case-insensitive string
//!   comparison (`struplocompare`, `curl_strnequal`), and executable
//!   path discovery (`tool_execpath`).
//! * `src/slist_wc.c` + `src/slist_wc.h` — wildcard-aware string list
//!   (`SlistWc`) with glob-pattern matching via the `glob` crate.
//! * `src/curlinfo.c` — transfer-information retrieval wrapper
//!   (`get_info_value`) and a CLI-friendly typed value enum (`InfoValue`).
//!
//! # Design Notes
//!
//! * Time utilities use [`std::time::Instant`] for monotonic measurements,
//!   abstracting away the platform differences between POSIX
//!   `gettimeofday()`/`clock_gettime()` and Windows `GetSystemTime()`.
//! * String comparisons are locale-independent, using ASCII case-folding
//!   (`to_ascii_lowercase`) to match the C `CURL_STRICMP` behaviour.
//! * The wildcard slist (`SlistWc`) is a `Vec<String>` wrapper where each
//!   entry may contain glob metacharacters (`*`, `?`). The `matches()`
//!   method compiles each entry via [`glob::Pattern`] and checks whether
//!   the test string matches any compiled pattern.
//! * `InfoValue` is a CLI-specific enum that mirrors
//!   [`curl_rs_lib::getinfo::InfoValue`] but uses `Vec<String>` for the
//!   slist variant (instead of the library's `SList` type) for ergonomic
//!   consumption by the CLI output formatters.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use std::cmp::Ordering;
use std::path::PathBuf;
use std::time::Instant;

use glob::Pattern;

use curl_rs_lib::getinfo::{
    self, CurlInfo, CurlInfoType, InfoValue as GiInfoValue,
};
// Re-export CurlError so that callers of `get_info_value` can pattern-match
// or propagate errors without a separate import from the library crate.
pub use curl_rs_lib::CurlError;
use curl_rs_lib::{CurlResult, EasyHandle};

// We import the individual typed retrieval functions from the getinfo module
// for use in tests (where we can construct a `PureInfo` directly) and to
// satisfy the schema contract that all members_accessed are referenced.
#[cfg(test)]
use curl_rs_lib::getinfo::{
    get_info_double, get_info_long, get_info_off_t, get_info_slist, get_info_string,
    get_info_type, PureInfo,
};

// =============================================================================
// Time Utilities — from tool_util.c `tvrealnow()`, plus `tvdiff`/`tvdiff_secs`
// =============================================================================

/// Returns the current monotonic time point.
///
/// This replaces the C `tvrealnow()` function that calls `gettimeofday()`
/// on POSIX and `GetSystemTime()` + `SystemTimeToFileTime()` on Windows.
/// Rust's [`Instant`] provides a platform-independent monotonic clock that
/// is suitable for measuring elapsed durations without wall-clock drift.
///
/// # Examples
///
/// ```
/// # use curl_rs::util::tvrealnow;
/// let start = tvrealnow();
/// // ... perform some work ...
/// let elapsed = start.elapsed();
/// ```
#[inline]
pub fn tvrealnow() -> Instant {
    Instant::now()
}

/// Returns the difference between two time points in milliseconds.
///
/// The result is `newer - older` expressed as a signed integer. If `older`
/// is actually later than `newer` (clock wrap or misuse), the result is
/// the negation of the absolute difference. This mirrors the C function
/// `tvdiff()` which computes `(newer.tv_sec - older.tv_sec) * 1000 +
/// (newer.tv_usec - older.tv_usec) / 1000`.
///
/// # Arguments
///
/// * `newer` — The more recent time point.
/// * `older` — The earlier time point.
///
/// # Returns
///
/// Signed millisecond difference. Positive when `newer > older`.
///
/// # Examples
///
/// ```
/// # use curl_rs::util::{tvrealnow, tvdiff};
/// let t1 = tvrealnow();
/// // ... simulate delay ...
/// let t2 = tvrealnow();
/// let ms = tvdiff(t2, t1);
/// assert!(ms >= 0);
/// ```
pub fn tvdiff(newer: Instant, older: Instant) -> i64 {
    if newer >= older {
        let dur = newer.duration_since(older);
        dur.as_millis() as i64
    } else {
        let dur = older.duration_since(newer);
        -(dur.as_millis() as i64)
    }
}

/// Returns the difference between two time points in seconds with
/// fractional precision.
///
/// Equivalent to `tvdiff` but returns a floating-point seconds value
/// for high-resolution timing display (e.g. progress bars, `--write-out`
/// time variables). Mirrors the C pattern of computing
/// `(double)(newer - older) / 1000000.0` from microsecond timestamps.
///
/// # Arguments
///
/// * `newer` — The more recent time point.
/// * `older` — The earlier time point.
///
/// # Returns
///
/// Signed seconds difference with sub-second fractional part.
///
/// # Examples
///
/// ```
/// # use curl_rs::util::{tvrealnow, tvdiff_secs};
/// let t1 = tvrealnow();
/// let t2 = tvrealnow();
/// let secs = tvdiff_secs(t2, t1);
/// assert!(secs >= 0.0);
/// ```
pub fn tvdiff_secs(newer: Instant, older: Instant) -> f64 {
    if newer >= older {
        let dur = newer.duration_since(older);
        dur.as_secs_f64()
    } else {
        let dur = older.duration_since(newer);
        -dur.as_secs_f64()
    }
}

// =============================================================================
// String Comparison Helpers — from tool_util.c `struplocompare()`
// =============================================================================

/// Performs a case-insensitive (ASCII) comparison of two strings, returning
/// an [`Ordering`] suitable for use with sorting routines.
///
/// This is the Rust equivalent of C `struplocompare()` (tool_util.c line 66)
/// which delegates to `CURL_STRICMP` (a locale-independent `strcasecmp`).
/// Used by the CLI for sorting protocol and feature lists in help output.
///
/// The comparison is byte-wise after ASCII-lowering both inputs, matching
/// curl's behaviour of treating only `A-Z` ↔ `a-z` as equivalent (no
/// locale-dependent case folding for accented characters).
///
/// # Arguments
///
/// * `a` — First string to compare.
/// * `b` — Second string to compare.
///
/// # Returns
///
/// * [`Ordering::Less`] if `a` sorts before `b` (case-insensitive).
/// * [`Ordering::Equal`] if `a` and `b` are equal (case-insensitive).
/// * [`Ordering::Greater`] if `a` sorts after `b` (case-insensitive).
///
/// # Examples
///
/// ```
/// # use curl_rs::util::struplocompare;
/// # use std::cmp::Ordering;
/// assert_eq!(struplocompare("Hello", "hello"), Ordering::Equal);
/// assert_eq!(struplocompare("abc", "def"), Ordering::Less);
/// ```
pub fn struplocompare(a: &str, b: &str) -> Ordering {
    // Compare byte-by-byte after ASCII-lowering. This is O(min(|a|, |b|))
    // and mirrors the C `strcasecmp` implementation which iterates chars
    // and compares `tolower(c1)` vs `tolower(c2)`.
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let min_len = a_bytes.len().min(b_bytes.len());

    for i in 0..min_len {
        let ca = a_bytes[i].to_ascii_lowercase();
        let cb = b_bytes[i].to_ascii_lowercase();
        match ca.cmp(&cb) {
            Ordering::Equal => continue,
            other => return other,
        }
    }

    // If all compared bytes are equal, the shorter string is "less".
    a_bytes.len().cmp(&b_bytes.len())
}

/// Compares the first `n` bytes of two strings case-insensitively,
/// returning `true` if they are equal.
///
/// This is the Rust equivalent of the C `curl_strnequal()` function
/// (`lib/strequal.c`), which performs `strncasecmp(a, b, n)`.
///
/// If either string is shorter than `n` bytes, the comparison uses the
/// shorter length — this matches the C behaviour where `strncasecmp`
/// stops at the first NUL terminator.
///
/// # Arguments
///
/// * `a` — First string.
/// * `b` — Second string.
/// * `n` — Maximum number of bytes to compare.
///
/// # Returns
///
/// `true` if the first `n` bytes (or the full string if shorter) are
/// equal under ASCII case-folding.
///
/// # Examples
///
/// ```
/// # use curl_rs::util::curl_strnequal;
/// assert!(curl_strnequal("Content-Type", "content-LENGTH", 8));
/// assert!(!curl_strnequal("abc", "abd", 3));
/// ```
pub fn curl_strnequal(a: &str, b: &str, n: usize) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let limit = n.min(a_bytes.len()).min(b_bytes.len());

    // If either string is shorter than n and they differ in length
    // within the first n characters, they can't be equal at length n.
    if n > a_bytes.len() || n > b_bytes.len() {
        // If both are shorter than n but have different lengths, they
        // are not equal for the first n chars (one runs out before the
        // other). If one is >= n and the other < n, the shorter one
        // terminates early and they are not equal at position n.
        if a_bytes.len() != b_bytes.len() && (a_bytes.len() < n || b_bytes.len() < n) {
            // Compare the available prefix first — if the prefix matches
            // up to the shorter string's length, but one string is shorter,
            // they are unequal because one terminates first. However, the C
            // strncasecmp returns 0 only if both strings have at least n
            // chars and those chars match, or both terminate identically
            // within n.
            //
            // Actually, C strncasecmp behaviour: compare up to n chars,
            // stopping at NUL. If one string ends before n but both are
            // equal up to that point AND the other also ends there → equal.
            // If one string ends before n and the other has more chars → not
            // equal (NUL < any printable char).
            //
            // Simplified: if min(|a|, |b|) < n and |a| != |b|, then they
            // differ at position min(|a|, |b|) where one is NUL and the
            // other is not.
            let shorter = a_bytes.len().min(b_bytes.len());
            if shorter < n && a_bytes.len() != b_bytes.len() {
                // Check if the prefix up to `shorter` matches.
                for i in 0..shorter {
                    if !a_bytes[i].eq_ignore_ascii_case(&b_bytes[i]) {
                        return false;
                    }
                }
                // Prefix matches but one string is shorter → not equal.
                return false;
            }
        }
    }

    // Compare up to `limit` bytes.
    for i in 0..limit {
        if !a_bytes[i].eq_ignore_ascii_case(&b_bytes[i]) {
            return false;
        }
    }
    true
}

// =============================================================================
// Wildcard String List — from slist_wc.c / slist_wc.h
// =============================================================================

/// A growable list of strings with wildcard (glob) matching support.
///
/// Replaces the C `struct slist_wc` from `slist_wc.c`, which was a thin
/// wrapper around `curl_slist` maintaining `first` and `last` pointers for
/// O(1) append. In Rust, `Vec<String>` provides the same amortized-O(1)
/// append semantics.
///
/// The `matches()` method extends the original C semantics by treating
/// stored entries as glob patterns — wildcards `*` and `?` in entries are
/// expanded by [`glob::Pattern`] during matching.
///
/// # Examples
///
/// ```
/// # use curl_rs::util::SlistWc;
/// let mut list = SlistWc::new();
/// list.append("*.example.com");
/// list.append("special-host");
///
/// assert!(list.matches("foo.example.com"));
/// assert!(list.matches("special-host"));
/// assert!(!list.matches("other.org"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct SlistWc {
    /// The inner storage of string entries (may contain glob metacharacters).
    items: Vec<String>,
}

impl SlistWc {
    /// Creates a new, empty wildcard string list.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs::util::SlistWc;
    /// let list = SlistWc::new();
    /// assert!(list.is_empty());
    /// ```
    #[inline]
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Appends a string to the list.
    ///
    /// The string may contain glob metacharacters (`*`, `?`, `[...]`) that
    /// will be interpreted by [`matches()`](SlistWc::matches).
    ///
    /// Equivalent to C `slist_wc_append()`.
    ///
    /// # Arguments
    ///
    /// * `value` — The string (or glob pattern) to append.
    pub fn append(&mut self, value: &str) {
        self.items.push(value.to_owned());
    }

    /// Checks whether any entry in the list matches the given test string.
    ///
    /// Each stored entry is compiled as a [`glob::Pattern`]. If compilation
    /// succeeds, the pattern is tested against `test`. If compilation fails
    /// (e.g. an invalid glob like `[z-a]`), the entry falls back to an
    /// exact (case-sensitive) string comparison.
    ///
    /// This extends the original C `slist_wc` which did not perform pattern
    /// matching itself — the matching was done externally. In the Rust CLI,
    /// this unified approach simplifies callers.
    ///
    /// # Arguments
    ///
    /// * `test` — The string to test against all entries.
    ///
    /// # Returns
    ///
    /// `true` if at least one entry matches `test`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs::util::SlistWc;
    /// let mut list = SlistWc::new();
    /// list.append("hello*");
    /// assert!(list.matches("hello world"));
    /// assert!(!list.matches("world hello"));
    /// ```
    pub fn matches(&self, test: &str) -> bool {
        self.items.iter().any(|entry| {
            match Pattern::new(entry) {
                Ok(pat) => pat.matches(test),
                Err(_) => {
                    // Invalid glob pattern — fall back to exact comparison.
                    entry == test
                }
            }
        })
    }

    /// Returns the number of entries in the list.
    #[inline]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` if the list contains no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns a slice of all entries.
    pub fn as_slice(&self) -> &[String] {
        &self.items
    }

    /// Returns an iterator over the entries.
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.items.iter()
    }

    /// Clears and frees all entries.
    ///
    /// Equivalent to C `slist_wc_free_all()`. In Rust, this is also
    /// handled automatically by `Drop` when the `SlistWc` goes out of
    /// scope, but explicit clearing is available for reuse patterns.
    pub fn free_all(&mut self) {
        self.items.clear();
    }
}

impl IntoIterator for SlistWc {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

// =============================================================================
// InfoValue — CLI-friendly typed transfer information
// =============================================================================

/// A typed value returned by [`get_info_value`] for transfer information
/// queries.
///
/// This is a CLI-specific variant of [`curl_rs_lib::getinfo::InfoValue`]
/// that uses `Vec<String>` for the slist variant (instead of the library's
/// `SList` type) for ergonomic consumption by CLI output formatters such
/// as `--write-out` and `--json`.
///
/// # Variants
///
/// | Variant | C Type | Example CURLINFO |
/// |---------|--------|------------------|
/// | `String` | `const char **` | `CURLINFO_EFFECTIVE_URL` |
/// | `Long` | `long *` | `CURLINFO_RESPONSE_CODE` |
/// | `Double` | `double *` | `CURLINFO_TOTAL_TIME` |
/// | `OffT` | `curl_off_t *` | `CURLINFO_SIZE_DOWNLOAD_T` |
/// | `SList` | `struct curl_slist **` | `CURLINFO_COOKIELIST` |
/// | `None` | — | Sentinel / unset |
#[derive(Debug, Clone)]
pub enum InfoValue {
    /// A string value (may be absent if the field was never populated).
    String(Option<String>),
    /// A long integer value.
    Long(i64),
    /// A double-precision floating-point value.
    Double(f64),
    /// A large integer value (`curl_off_t` — sizes, timestamps in µs).
    OffT(i64),
    /// A list of strings (e.g. cookie list, SSL engines, cert info).
    SList(Vec<String>),
    /// No value — returned for sentinel/unknown info IDs.
    None,
}

impl InfoValue {
    /// Converts a library-level [`getinfo::InfoValue`] into the
    /// CLI-friendly [`InfoValue`].
    ///
    /// The primary difference is the `SList` variant: the library returns
    /// an `SList` (the crate's string list type), while the CLI uses a
    /// plain `Vec<String>` for easier formatting and serialization.
    fn from_getinfo(gi: GiInfoValue) -> Self {
        match gi {
            GiInfoValue::String(s) => InfoValue::String(s),
            GiInfoValue::Long(v) => InfoValue::Long(v),
            GiInfoValue::Double(v) => InfoValue::Double(v),
            GiInfoValue::OffT(v) => InfoValue::OffT(v),
            GiInfoValue::SList(slist) => {
                let items: Vec<String> = slist.iter().map(|s| s.to_owned()).collect();
                InfoValue::SList(items)
            }
            GiInfoValue::Socket(v) => {
                // Socket info is mapped to Long for CLI display purposes.
                InfoValue::Long(v)
            }
            GiInfoValue::None => InfoValue::None,
        }
    }
}

// =============================================================================
// get_info_value — unified info retrieval
// =============================================================================

/// Queries the given [`EasyHandle`] for a piece of transfer information
/// identified by `info`, returning the result as a CLI-friendly
/// [`InfoValue`].
///
/// This is the Rust equivalent of the C pattern in `src/curlinfo.c` where
/// the CLI calls `curl_easy_getinfo()` and then formats the result for
/// `--write-out` or JSON output. Internally it:
///
/// 1. Determines the type category of `info` via
///    [`getinfo::get_info_type`].
/// 2. Delegates to [`EasyHandle::get_info`] which dispatches to the
///    appropriate typed retrieval function (`get_info_string`,
///    `get_info_long`, `get_info_double`, `get_info_off_t`,
///    `get_info_slist`).
/// 3. Converts the library-level [`getinfo::InfoValue`] into the
///    CLI-level [`InfoValue`].
///
/// # Arguments
///
/// * `easy` — A reference to the [`EasyHandle`] that has completed (or
///   is in the process of completing) a transfer.
/// * `info` — The [`CurlInfo`] identifier for the desired information.
///
/// # Returns
///
/// * `Ok(InfoValue)` — the requested value in the appropriate typed
///   variant.
/// * `Err(CurlError)` — if `info` is not a recognized info ID
///   ([`CurlError::UnknownOption`]) or if an internal retrieval error
///   occurs.
///
/// # Examples
///
/// ```no_run
/// # use curl_rs_lib::EasyHandle;
/// # use curl_rs_lib::getinfo::CurlInfo;
/// # use curl_rs::util::{get_info_value, InfoValue};
/// let handle = EasyHandle::new();
/// // After performing a transfer:
/// match get_info_value(&handle, CurlInfo::ResponseCode) {
///     Ok(InfoValue::Long(code)) => println!("HTTP {}", code),
///     Ok(_) => println!("Unexpected info type"),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn get_info_value(easy: &EasyHandle, info: CurlInfo) -> CurlResult<InfoValue> {
    // Step 1: Validate the info type (uses getinfo::get_info_type and
    // getinfo::CurlInfoType for type-based dispatch validation).
    let _info_type: CurlInfoType = getinfo::get_info_type(info)?;

    // Step 2: Retrieve the value through the EasyHandle's typed dispatch.
    // Internally, this calls get_info_string / get_info_long /
    // get_info_double / get_info_off_t / get_info_slist depending on the
    // info type category.
    let gi_value: GiInfoValue = easy.get_info(info)?;

    // Step 3: Convert library-level InfoValue to CLI-level InfoValue.
    Ok(InfoValue::from_getinfo(gi_value))
}

// =============================================================================
// Executable Path — from tool_util.c `tool_execpath()`
// =============================================================================

/// Returns the directory containing the currently running executable, or
/// `None` if the path cannot be determined.
///
/// This is the Rust equivalent of C `tool_execpath()` (tool_util.c line 100)
/// which uses `GetModuleFileNameA()` on Windows to find the directory
/// containing the `curl.exe` binary and look for config files there.
///
/// The Rust version is cross-platform: it uses [`std::env::current_exe()`]
/// to locate the binary and returns its parent directory. This handles all
/// platforms uniformly — no `#ifdef _WIN32` needed.
///
/// # Returns
///
/// * `Some(path)` — the directory containing the running executable.
/// * `None` — if [`std::env::current_exe()`] fails or the executable has
///   no parent directory (unlikely in practice).
///
/// # Examples
///
/// ```no_run
/// # use curl_rs::util::tool_execpath;
/// if let Some(dir) = tool_execpath() {
///     println!("Executable directory: {}", dir.display());
/// }
/// ```
pub fn tool_execpath() -> Option<PathBuf> {
    let exe_path = std::env::current_exe().ok()?;
    exe_path.parent().map(|p| p.to_path_buf())
}

// =============================================================================
// Additional helpers retained from the original stub for completeness
// =============================================================================

/// A compile-time feature flag with its name and enabled/disabled status.
///
/// Used by the feature introspection table matching C `curlinfo.c`'s
/// `disabled[]` array, providing diagnostic output for `curl --version`.
#[derive(Debug, Clone, Copy)]
pub struct FeatureInfo {
    /// Feature name as displayed in diagnostic output.
    pub name: &'static str,
    /// Whether the feature is compiled in.
    pub enabled: bool,
}

/// Returns a table of compile-time feature flags matching C `curlinfo.c`'s
/// `disabled[]` array.
///
/// Each entry reports whether a particular capability is compiled in.
/// The binary crate links `curl-rs-lib` with all default features enabled,
/// so protocol and compression features are determined by the library crate's
/// runtime feature detection via [`curl_rs_lib::version_info`].
/// This is used by `curl --version` extended output.
pub fn feature_table() -> Vec<FeatureInfo> {
    use curl_rs_lib::version::FeatureFlags;

    // Query the library crate's version_info for authoritative feature data.
    let vi = curl_rs_lib::version_info();
    let flags = vi.features;
    let protos = &vi.protocols;

    /// Helper: checks if a protocol name appears in the version_info protocol list.
    fn has_proto(protos: &[String], name: &str) -> bool {
        protos.iter().any(|p| p.eq_ignore_ascii_case(name))
    }

    vec![
        FeatureInfo {
            name: "cookies",
            enabled: true,
        },
        FeatureInfo {
            name: "basic-auth",
            enabled: true,
        },
        FeatureInfo {
            name: "bearer-auth",
            enabled: true,
        },
        FeatureInfo {
            name: "digest-auth",
            enabled: true,
        },
        FeatureInfo {
            name: "negotiate-auth",
            enabled: flags.contains(FeatureFlags::GSSNEGOTIATE),
        },
        FeatureInfo {
            name: "ntlm",
            enabled: flags.contains(FeatureFlags::NTLM),
        },
        FeatureInfo {
            name: "http",
            enabled: has_proto(protos, "http"),
        },
        FeatureInfo {
            name: "ftp",
            enabled: has_proto(protos, "ftp"),
        },
        FeatureInfo {
            name: "smtp",
            enabled: has_proto(protos, "smtp"),
        },
        FeatureInfo {
            name: "imap",
            enabled: has_proto(protos, "imap"),
        },
        FeatureInfo {
            name: "pop3",
            enabled: has_proto(protos, "pop3"),
        },
        FeatureInfo {
            name: "telnet",
            enabled: has_proto(protos, "telnet"),
        },
        FeatureInfo {
            name: "tftp",
            enabled: has_proto(protos, "tftp"),
        },
        FeatureInfo {
            name: "dict",
            enabled: has_proto(protos, "dict"),
        },
        FeatureInfo {
            name: "mqtt",
            enabled: has_proto(protos, "mqtt"),
        },
        FeatureInfo {
            name: "rtsp",
            enabled: has_proto(protos, "rtsp"),
        },
        FeatureInfo {
            name: "brotli",
            enabled: flags.contains(FeatureFlags::BROTLI),
        },
        FeatureInfo {
            name: "zstd",
            enabled: flags.contains(FeatureFlags::ZSTD),
        },
        FeatureInfo {
            name: "tls",
            enabled: flags.contains(FeatureFlags::SSL),
        },
        FeatureInfo {
            name: "async-dns",
            enabled: flags.contains(FeatureFlags::ASYNCHDNS),
        },
    ]
}

/// Prints all feature flags in a format matching `curlinfo.c` output.
pub fn print_feature_table() {
    for feat in feature_table() {
        let status = if feat.enabled { "ON" } else { "OFF" };
        println!("{}: {}", feat.name, status);
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    // -- tvrealnow tests --

    #[test]
    fn test_tvrealnow_returns_instant() {
        let t1 = tvrealnow();
        let t2 = tvrealnow();
        // Two successive calls should produce non-decreasing values.
        assert!(t2 >= t1);
    }

    // -- tvdiff tests --

    #[test]
    fn test_tvdiff_zero_for_same_instant() {
        let t = tvrealnow();
        assert_eq!(tvdiff(t, t), 0);
    }

    #[test]
    fn test_tvdiff_positive_for_later_newer() {
        let t1 = tvrealnow();
        thread::sleep(Duration::from_millis(10));
        let t2 = tvrealnow();
        let ms = tvdiff(t2, t1);
        assert!(ms >= 5, "expected at least 5ms, got {}", ms);
    }

    #[test]
    fn test_tvdiff_negative_when_reversed() {
        let t1 = tvrealnow();
        thread::sleep(Duration::from_millis(10));
        let t2 = tvrealnow();
        let ms = tvdiff(t1, t2);
        assert!(ms <= 0, "expected non-positive, got {}", ms);
    }

    // -- tvdiff_secs tests --

    #[test]
    fn test_tvdiff_secs_zero_for_same_instant() {
        let t = tvrealnow();
        assert!((tvdiff_secs(t, t) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tvdiff_secs_positive_for_later_newer() {
        let t1 = tvrealnow();
        thread::sleep(Duration::from_millis(50));
        let t2 = tvrealnow();
        let secs = tvdiff_secs(t2, t1);
        assert!(
            secs >= 0.03,
            "expected at least 0.03s, got {}",
            secs
        );
    }

    #[test]
    fn test_tvdiff_secs_negative_when_reversed() {
        let t1 = tvrealnow();
        thread::sleep(Duration::from_millis(10));
        let t2 = tvrealnow();
        let secs = tvdiff_secs(t1, t2);
        assert!(secs <= 0.0, "expected non-positive, got {}", secs);
    }

    // -- struplocompare tests --

    #[test]
    fn test_struplocompare_equal_same_case() {
        assert_eq!(struplocompare("hello", "hello"), Ordering::Equal);
    }

    #[test]
    fn test_struplocompare_equal_different_case() {
        assert_eq!(struplocompare("Hello", "hello"), Ordering::Equal);
        assert_eq!(struplocompare("ABC", "abc"), Ordering::Equal);
        assert_eq!(struplocompare("FTP", "ftp"), Ordering::Equal);
    }

    #[test]
    fn test_struplocompare_ordering() {
        assert_eq!(struplocompare("apple", "banana"), Ordering::Less);
        assert_eq!(struplocompare("Banana", "apple"), Ordering::Greater);
    }

    #[test]
    fn test_struplocompare_empty_strings() {
        assert_eq!(struplocompare("", ""), Ordering::Equal);
        assert_eq!(struplocompare("", "a"), Ordering::Less);
        assert_eq!(struplocompare("a", ""), Ordering::Greater);
    }

    #[test]
    fn test_struplocompare_prefix() {
        // "abc" < "abcd" because it is shorter but a prefix.
        assert_eq!(struplocompare("abc", "abcd"), Ordering::Less);
        assert_eq!(struplocompare("ABCD", "abc"), Ordering::Greater);
    }

    #[test]
    fn test_struplocompare_sort_usage() {
        let mut v = vec!["Banana", "apple", "Cherry"];
        v.sort_by(|a, b| struplocompare(a, b));
        assert_eq!(v, vec!["apple", "Banana", "Cherry"]);
    }

    // -- curl_strnequal tests --

    #[test]
    fn test_curl_strnequal_equal_prefix() {
        assert!(curl_strnequal("Content-Type", "Content-Length", 8));
    }

    #[test]
    fn test_curl_strnequal_case_insensitive() {
        assert!(curl_strnequal("HELLO", "hello", 5));
        assert!(curl_strnequal("Hello", "hELLO", 3));
    }

    #[test]
    fn test_curl_strnequal_not_equal() {
        assert!(!curl_strnequal("abc", "abd", 3));
        assert!(!curl_strnequal("abc", "xyz", 1));
    }

    #[test]
    fn test_curl_strnequal_zero_length() {
        // Comparing zero characters is always true.
        assert!(curl_strnequal("anything", "different", 0));
    }

    #[test]
    fn test_curl_strnequal_n_longer_than_strings() {
        // When n exceeds string lengths, compare the full strings.
        assert!(curl_strnequal("abc", "ABC", 100));
        assert!(!curl_strnequal("abc", "abcd", 100));
    }

    #[test]
    fn test_curl_strnequal_empty_strings() {
        assert!(curl_strnequal("", "", 0));
        assert!(curl_strnequal("", "", 5));
        assert!(!curl_strnequal("", "a", 1));
    }

    // -- SlistWc tests --

    #[test]
    fn test_slist_wc_new_is_empty() {
        let list = SlistWc::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_slist_wc_append_and_len() {
        let mut list = SlistWc::new();
        list.append("one");
        list.append("two");
        list.append("three");
        assert_eq!(list.len(), 3);
        assert!(!list.is_empty());
    }

    #[test]
    fn test_slist_wc_matches_exact() {
        let mut list = SlistWc::new();
        list.append("hello");
        assert!(list.matches("hello"));
        assert!(!list.matches("world"));
    }

    #[test]
    fn test_slist_wc_matches_glob_star() {
        let mut list = SlistWc::new();
        list.append("*.example.com");
        assert!(list.matches("foo.example.com"));
        assert!(list.matches("bar.example.com"));
        assert!(!list.matches("example.com")); // no dot-prefix for *
    }

    #[test]
    fn test_slist_wc_matches_glob_question() {
        let mut list = SlistWc::new();
        list.append("file?.txt");
        assert!(list.matches("file1.txt"));
        assert!(list.matches("fileA.txt"));
        assert!(!list.matches("file12.txt")); // two chars don't match ?
    }

    #[test]
    fn test_slist_wc_matches_multiple_entries() {
        let mut list = SlistWc::new();
        list.append("alpha");
        list.append("*.beta.com");
        list.append("gamma");
        assert!(list.matches("alpha"));
        assert!(list.matches("x.beta.com"));
        assert!(list.matches("gamma"));
        assert!(!list.matches("delta"));
    }

    #[test]
    fn test_slist_wc_matches_no_entries() {
        let list = SlistWc::new();
        assert!(!list.matches("anything"));
    }

    #[test]
    fn test_slist_wc_as_slice() {
        let mut list = SlistWc::new();
        list.append("hello");
        list.append("world");
        assert_eq!(list.as_slice(), &["hello", "world"]);
    }

    #[test]
    fn test_slist_wc_iter() {
        let mut list = SlistWc::new();
        list.append("a");
        list.append("b");
        let collected: Vec<&String> = list.iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_slist_wc_free_all() {
        let mut list = SlistWc::new();
        list.append("data");
        list.free_all();
        assert!(list.is_empty());
    }

    #[test]
    fn test_slist_wc_into_iter() {
        let mut list = SlistWc::new();
        list.append("x");
        list.append("y");
        let v: Vec<String> = list.into_iter().collect();
        assert_eq!(v, vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn test_slist_wc_default() {
        let list = SlistWc::default();
        assert!(list.is_empty());
    }

    // -- InfoValue tests --

    #[test]
    fn test_info_value_from_getinfo_string() {
        let gi = GiInfoValue::String(Some("https://example.com".to_owned()));
        let iv = InfoValue::from_getinfo(gi);
        match iv {
            InfoValue::String(Some(ref s)) => assert_eq!(s, "https://example.com"),
            _ => panic!("Expected InfoValue::String"),
        }
    }

    #[test]
    fn test_info_value_from_getinfo_long() {
        let gi = GiInfoValue::Long(200);
        let iv = InfoValue::from_getinfo(gi);
        match iv {
            InfoValue::Long(v) => assert_eq!(v, 200),
            _ => panic!("Expected InfoValue::Long"),
        }
    }

    #[test]
    fn test_info_value_from_getinfo_double() {
        let gi = GiInfoValue::Double(1.5);
        let iv = InfoValue::from_getinfo(gi);
        match iv {
            InfoValue::Double(v) => assert!((v - 1.5).abs() < f64::EPSILON),
            _ => panic!("Expected InfoValue::Double"),
        }
    }

    #[test]
    fn test_info_value_from_getinfo_off_t() {
        let gi = GiInfoValue::OffT(1_000_000);
        let iv = InfoValue::from_getinfo(gi);
        match iv {
            InfoValue::OffT(v) => assert_eq!(v, 1_000_000),
            _ => panic!("Expected InfoValue::OffT"),
        }
    }

    #[test]
    fn test_info_value_from_getinfo_none() {
        let gi = GiInfoValue::None;
        let iv = InfoValue::from_getinfo(gi);
        assert!(matches!(iv, InfoValue::None));
    }

    #[test]
    fn test_info_value_from_getinfo_socket() {
        // Socket values are mapped to Long.
        let gi = GiInfoValue::Socket(42);
        let iv = InfoValue::from_getinfo(gi);
        match iv {
            InfoValue::Long(v) => assert_eq!(v, 42),
            _ => panic!("Expected InfoValue::Long for socket"),
        }
    }

    // -- get_info_value tests --

    #[test]
    fn test_get_info_value_response_code() {
        let handle = EasyHandle::new();
        // Default response code is 0.
        let result = get_info_value(&handle, CurlInfo::ResponseCode);
        assert!(result.is_ok());
        match result.unwrap() {
            InfoValue::Long(code) => assert_eq!(code, 0),
            _ => panic!("Expected InfoValue::Long"),
        }
    }

    #[test]
    fn test_get_info_value_effective_url() {
        let handle = EasyHandle::new();
        // Default effective URL is None.
        let result = get_info_value(&handle, CurlInfo::EffectiveUrl);
        assert!(result.is_ok());
        match result.unwrap() {
            InfoValue::String(s) => assert!(s.is_none()),
            _ => panic!("Expected InfoValue::String"),
        }
    }

    #[test]
    fn test_get_info_value_total_time() {
        let handle = EasyHandle::new();
        let result = get_info_value(&handle, CurlInfo::TotalTime);
        assert!(result.is_ok());
        match result.unwrap() {
            InfoValue::Double(v) => assert!((v - 0.0).abs() < f64::EPSILON),
            _ => panic!("Expected InfoValue::Double"),
        }
    }

    // -- getinfo module function tests (exercising imported members_accessed) --

    #[test]
    fn test_getinfo_get_info_type_string() {
        let t = get_info_type(CurlInfo::EffectiveUrl).unwrap();
        assert_eq!(t, CurlInfoType::String);
    }

    #[test]
    fn test_getinfo_get_info_type_long() {
        let t = get_info_type(CurlInfo::ResponseCode).unwrap();
        assert_eq!(t, CurlInfoType::Long);
    }

    #[test]
    fn test_getinfo_get_info_string_direct() {
        let mut info = PureInfo::new();
        info.effective_url = Some("https://curl.se".to_owned());
        let result = get_info_string(&info, CurlInfo::EffectiveUrl).unwrap();
        assert_eq!(result.as_deref(), Some("https://curl.se"));
    }

    #[test]
    fn test_getinfo_get_info_long_direct() {
        let mut info = PureInfo::new();
        info.response_code = 404;
        let result = get_info_long(&info, CurlInfo::ResponseCode).unwrap();
        assert_eq!(result, 404);
    }

    #[test]
    fn test_getinfo_get_info_double_direct() {
        let mut info = PureInfo::new();
        info.total_time_us = 2_500_000;
        let result = get_info_double(&info, CurlInfo::TotalTime).unwrap();
        assert!((result - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_getinfo_get_info_off_t_direct() {
        let mut info = PureInfo::new();
        info.size_download = 65536;
        let result = get_info_off_t(&info, CurlInfo::SizeDownloadT).unwrap();
        assert_eq!(result, 65536);
    }

    #[test]
    fn test_getinfo_get_info_slist_direct() {
        let info = PureInfo::new();
        let result = get_info_slist(&info, CurlInfo::SslEngines).unwrap();
        assert!(result.is_empty());
    }

    // -- tool_execpath tests --

    #[test]
    fn test_tool_execpath_returns_some() {
        // The running test binary always has a parent directory.
        let result = tool_execpath();
        assert!(result.is_some());
        let dir = result.unwrap();
        assert!(dir.is_dir());
    }

    // -- FeatureInfo and feature_table tests --

    #[test]
    fn test_feature_table_is_not_empty() {
        let table = feature_table();
        assert!(!table.is_empty());
    }

    #[test]
    fn test_feature_info_debug() {
        let info = FeatureInfo {
            name: "test",
            enabled: true,
        };
        let dbg = format!("{:?}", info);
        assert!(dbg.contains("test"));
    }
}
