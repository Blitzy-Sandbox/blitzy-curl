// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! CLI utility functions for the `curl-rs` binary.
//!
//! This module is the Rust rewrite of three C source files:
//!
//! * `src/tool_util.c` — real-time clock, case-insensitive comparison,
//!   file truncation, and executable path helpers
//! * `src/slist_wc.c` — wildcard-aware string list wrapper around
//!   `curl_slist_append`
//! * `src/curlinfo.c` — compile-time feature introspection table used
//!   by `curl --version` and diagnostic output
//!
//! # Design Notes
//!
//! * Real-time clock is provided by [`std::time::SystemTime`]; platform
//!   differences (Windows `FILETIME`, POSIX `gettimeofday`) are abstracted
//!   away by the standard library.
//! * The wildcard slist (`slist_wc`) is replaced by a simple `Vec<String>`
//!   wrapper — Rust's `Vec` already provides the append and free semantics.
//! * Feature introspection is built from Cargo feature flags rather than
//!   `#ifdef` preprocessor tests.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Real-time clock — from tool_util.c `tvrealnow()`
// ---------------------------------------------------------------------------

/// Returns the current wall-clock time as a `(seconds, microseconds)` pair
/// since the Unix epoch.
///
/// Equivalent to C `tvrealnow()` which calls `gettimeofday()` on POSIX
/// and `GetSystemTime()` + `SystemTimeToFileTime()` on Windows.
pub fn tv_real_now() -> (i64, i64) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => (dur.as_secs() as i64, dur.subsec_micros() as i64),
        Err(_) => (0, 0),
    }
}

/// Returns the current wall-clock time as a [`Duration`] since the Unix epoch.
///
/// Convenience wrapper over [`tv_real_now`] for callers that prefer a
/// `Duration` value.
pub fn real_now_duration() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

// ---------------------------------------------------------------------------
// Case-insensitive comparison — from tool_util.c `struplocompare()`
// ---------------------------------------------------------------------------

/// Case-insensitive comparison of two optional string references.
///
/// Returns `Ordering::Equal` when both are `None`.
/// A `None` value compares as less than any `Some` value.
///
/// Equivalent to C `struplocompare()` which accepts NULL pointers.
pub fn str_uplo_compare(p1: Option<&str>, p2: Option<&str>) -> Ordering {
    match (p1, p2) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(a), Some(b)) => a
            .chars()
            .flat_map(char::to_uppercase)
            .cmp(b.chars().flat_map(char::to_uppercase)),
    }
}

/// Sort-callback adapter for [`str_uplo_compare`].
///
/// Equivalent to C `struplocompare4sort()` used as a `qsort` callback.
pub fn str_uplo_compare_for_sort(a: &str, b: &str) -> Ordering {
    str_uplo_compare(Some(a), Some(b))
}

// ---------------------------------------------------------------------------
// Executable path helper — from tool_util.c `tool_execpath()`
// ---------------------------------------------------------------------------

/// Finds a file in the same directory as the running executable.
///
/// Returns the full path if the file exists, or `None` otherwise.
/// Equivalent to C `tool_execpath()` which uses `GetModuleFileName` on
/// Windows and is unavailable on other platforms (this Rust version is
/// cross-platform).
pub fn exec_path(filename: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join(filename);
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// File truncation — from tool_util.c `tool_ftruncate64()`
// ---------------------------------------------------------------------------

/// Truncates a file at the given path to the specified length in bytes.
///
/// Equivalent to C `tool_ftruncate64()` which calls `_get_osfhandle` +
/// `SetEndOfFile` on Windows and `ftruncate` on POSIX.
pub fn truncate_file(path: &Path, len: u64) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.set_len(len)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SListWc — wildcard-aware string list from slist_wc.c
// ---------------------------------------------------------------------------

/// A growable list of strings, replacing C `struct slist_wc`.
///
/// In the original C code, `slist_wc` is a thin wrapper around
/// `curl_slist` that maintains both `first` and `last` pointers for
/// O(1) append. In Rust, `Vec<String>` provides the same semantics.
#[derive(Debug, Clone, Default)]
pub struct SListWc {
    /// The inner storage of string entries.
    items: Vec<String>,
}

impl SListWc {
    /// Creates a new empty wildcard string list.
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Appends `data` to the list.
    ///
    /// Equivalent to C `slist_wc_append()`.
    pub fn append(&mut self, data: impl Into<String>) {
        self.items.push(data.into());
    }

    /// Returns the number of entries in the list.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` if the list is empty.
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
    /// Equivalent to C `slist_wc_free_all()`.
    pub fn free_all(&mut self) {
        self.items.clear();
    }
}

impl IntoIterator for SListWc {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

// ---------------------------------------------------------------------------
// Feature introspection table — from curlinfo.c
// ---------------------------------------------------------------------------

/// A compile-time feature flag with its name and enabled/disabled status.
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
            // Cookies are always enabled in the Rust build (no CURL_DISABLE_COOKIES).
            enabled: true,
        },
        FeatureInfo {
            name: "basic-auth",
            enabled: true, // Always enabled in curl-rs
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

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tv_real_now_returns_positive_seconds() {
        let (secs, usecs) = tv_real_now();
        assert!(secs > 0, "seconds since epoch should be positive");
        assert!(usecs >= 0, "microseconds should be non-negative");
        assert!(usecs < 1_000_000, "microseconds should be < 1 million");
    }

    #[test]
    fn test_real_now_duration_is_positive() {
        let dur = real_now_duration();
        assert!(dur.as_secs() > 0);
    }

    #[test]
    fn test_str_uplo_compare_both_none() {
        assert_eq!(str_uplo_compare(None, None), Ordering::Equal);
    }

    #[test]
    fn test_str_uplo_compare_none_vs_some() {
        assert_eq!(str_uplo_compare(None, Some("a")), Ordering::Less);
        assert_eq!(str_uplo_compare(Some("a"), None), Ordering::Greater);
    }

    #[test]
    fn test_str_uplo_compare_case_insensitive() {
        assert_eq!(
            str_uplo_compare(Some("Hello"), Some("hello")),
            Ordering::Equal
        );
        assert_eq!(
            str_uplo_compare(Some("ABC"), Some("abc")),
            Ordering::Equal
        );
    }

    #[test]
    fn test_str_uplo_compare_ordering() {
        assert_eq!(
            str_uplo_compare(Some("apple"), Some("banana")),
            Ordering::Less
        );
        assert_eq!(
            str_uplo_compare(Some("Banana"), Some("apple")),
            Ordering::Greater
        );
    }

    #[test]
    fn test_str_uplo_compare_for_sort() {
        let mut v = vec!["Banana", "apple", "Cherry"];
        v.sort_by(|a, b| str_uplo_compare_for_sort(a, b));
        assert_eq!(v, vec!["apple", "Banana", "Cherry"]);
    }

    #[test]
    fn test_exec_path_nonexistent_file() {
        assert!(exec_path("definitely_does_not_exist_12345.txt").is_none());
    }

    #[test]
    fn test_truncate_file_nonexistent() {
        let result = truncate_file(Path::new("/tmp/no_such_file_test_42"), 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_slist_wc_new_is_empty() {
        let list = SListWc::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_slist_wc_append_and_len() {
        let mut list = SListWc::new();
        list.append("one");
        list.append("two");
        list.append("three");
        assert_eq!(list.len(), 3);
        assert!(!list.is_empty());
    }

    #[test]
    fn test_slist_wc_as_slice() {
        let mut list = SListWc::new();
        list.append("hello");
        list.append("world");
        assert_eq!(list.as_slice(), &["hello", "world"]);
    }

    #[test]
    fn test_slist_wc_iter() {
        let mut list = SListWc::new();
        list.append("a");
        list.append("b");
        let collected: Vec<&String> = list.iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_slist_wc_free_all() {
        let mut list = SListWc::new();
        list.append("data");
        list.free_all();
        assert!(list.is_empty());
    }

    #[test]
    fn test_slist_wc_into_iter() {
        let mut list = SListWc::new();
        list.append("x");
        list.append("y");
        let v: Vec<String> = list.into_iter().collect();
        assert_eq!(v, vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn test_slist_wc_default() {
        let list = SListWc::default();
        assert!(list.is_empty());
    }

    #[test]
    fn test_feature_table_is_not_empty() {
        let table = feature_table();
        assert!(!table.is_empty());
        // TLS is always enabled
        let tls = table.iter().find(|f| f.name == "tls").unwrap();
        assert!(tls.enabled);
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
