//! File timestamp management for the `-R`/`--remote-time` option.
//!
//! Provides functions to set and retrieve file modification times as Unix
//! timestamps (seconds since 1970-01-01 00:00:00 UTC). This module is the
//! Rust equivalent of the C `src/tool_filetime.c` and `src/tool_filetime.h`
//! files from curl 8.x.
//!
//! # Behavioral parity with curl 8.x
//!
//! - Timestamps are always UTC — no daylight-saving-time adjustment is applied.
//!   The C implementation on Windows bypasses `stat()`/`utime()` to avoid DST
//!   mangling; this Rust implementation uses [`std::fs::File::set_times`] which
//!   operates on UTC timestamps natively.
//! - Both the access time and the modification time are set to the same value,
//!   matching the C `setfiletime()` behavior.
//! - Negative timestamps (dates before the Unix epoch 1970-01-01) are supported,
//!   matching the C implementation's handling of pre-epoch dates.

use std::fs::{self, FileTimes};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};

/// Sets the modification time of the file at `path` to the given Unix timestamp.
///
/// Both the access time and the modification time are set to the specified
/// `timestamp`, matching the curl 8.x `setfiletime()` behavior where both
/// `utimes`/`utime` fields (Unix) or both FILETIME fields (Windows) are set
/// identically.
///
/// # Arguments
///
/// * `path` — Path to the file whose timestamps should be updated. The file
///   must already exist.
/// * `timestamp` — Unix timestamp in seconds (UTC). Negative values represent
///   dates before the Unix epoch (1970-01-01). The caller is responsible for
///   ensuring the timestamp is within the platform-representable range; values
///   outside that range will produce an error rather than being silently capped.
///
/// # Errors
///
/// Returns an error if:
/// - The file at `path` cannot be opened (missing, permission denied, etc.)
/// - The timestamp cannot be converted to a [`SystemTime`] (e.g., the absolute
///   value is so large it overflows the platform's time representation)
/// - The operating system rejects the [`File::set_times`](std::fs::File::set_times)
///   call (e.g., filesystem does not support setting timestamps)
///
/// # Example
///
/// ```no_run
/// # use anyhow::Result;
/// # fn example() -> Result<()> {
/// // Set modification time to 2021-01-01 00:00:00 UTC
/// curl_rs::filetime::set_filetime("/tmp/output.html", 1_609_459_200)?;
/// # Ok(())
/// # }
/// ```
pub fn set_filetime(path: &str, timestamp: i64) -> Result<()> {
    let system_time = unix_timestamp_to_system_time(timestamp)
        .with_context(|| format!("invalid timestamp {} for file '{}'", timestamp, path))?;

    // Open the file with write access so that set_times() succeeds on all
    // platforms.  On Windows the underlying SetFileTime call requires the
    // FILE_WRITE_ATTRIBUTES permission, which is included in GENERIC_WRITE
    // requested by OpenOptions::write(true).  On Unix, futimens works with
    // any open descriptor when the caller owns the file or has appropriate
    // permissions.
    //
    // Importantly, write(true) without truncate(true) does NOT truncate the
    // file contents — only the timestamps are modified.
    let file = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("failed to open '{}' for setting file time", path))?;

    // Set both access and modification time to the same value, matching the
    // curl 8.x C implementation which sets utimes[0] == utimes[1] on Unix
    // and passes the same FILETIME for both lpLastAccessTime and
    // lpLastWriteTime on Windows.
    let times = FileTimes::new()
        .set_accessed(system_time)
        .set_modified(system_time);

    file.set_times(times).with_context(|| {
        format!(
            "failed to set file time {} on '{}'",
            timestamp, path
        )
    })?;

    Ok(())
}

/// Retrieves the modification time of the file at `path` as a Unix timestamp.
///
/// # Arguments
///
/// * `path` — Path to the file whose modification time should be read.
///
/// # Returns
///
/// The file's modification time as seconds since the Unix epoch (1970-01-01
/// 00:00:00 UTC). For files modified before the epoch, the returned value is
/// negative.
///
/// # Errors
///
/// Returns an error if:
/// - The file metadata cannot be read (file not found, permission denied)
/// - The modification time is not available on the current platform
/// - The timestamp magnitude exceeds [`i64`] range (practically impossible on
///   current hardware but guarded for correctness)
///
/// # Example
///
/// ```no_run
/// # use anyhow::Result;
/// # fn example() -> Result<()> {
/// let ts = curl_rs::filetime::get_filetime("/tmp/output.html")?;
/// println!("Last modified: {} seconds since epoch", ts);
/// # Ok(())
/// # }
/// ```
pub fn get_filetime(path: &str) -> Result<i64> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to get metadata for '{}'", path))?;

    let modified = metadata
        .modified()
        .with_context(|| format!("failed to get modification time for '{}'", path))?;

    system_time_to_unix_timestamp(modified)
        .with_context(|| format!("failed to convert modification time for '{}'", path))
}

// ---------------------------------------------------------------------------
// Internal helpers — Unix-timestamp ↔ SystemTime conversion
// ---------------------------------------------------------------------------

/// Converts a Unix timestamp (seconds since epoch, possibly negative) to a
/// [`SystemTime`] value.
///
/// Positive timestamps are computed as `UNIX_EPOCH + seconds`. Negative
/// timestamps (pre-1970 dates) are computed as `UNIX_EPOCH - |seconds|` using
/// [`i64::unsigned_abs`] to safely handle the full `i64` range without
/// overflow.
fn unix_timestamp_to_system_time(timestamp: i64) -> Result<SystemTime> {
    if timestamp >= 0 {
        // Post-epoch: straightforward addition.
        Ok(UNIX_EPOCH + Duration::from_secs(timestamp as u64))
    } else {
        // Pre-epoch: subtract the absolute value of the (negative) timestamp
        // from the Unix epoch.  `unsigned_abs()` is used instead of negation
        // to avoid overflow when `timestamp == i64::MIN`.
        let abs_secs = timestamp.unsigned_abs();
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(abs_secs))
            .ok_or_else(|| {
                anyhow!(
                    "timestamp {} is too far before the Unix epoch to represent as SystemTime",
                    timestamp
                )
            })
    }
}

/// Converts a [`SystemTime`] to a Unix timestamp (seconds since epoch).
///
/// For times at or after the Unix epoch the result is non-negative. For times
/// before the epoch the result is negative.
fn system_time_to_unix_timestamp(time: SystemTime) -> Result<i64> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            // At or after epoch — return non-negative seconds.
            let secs = duration.as_secs();
            i64::try_from(secs).map_err(|_| {
                anyhow!(
                    "file modification time {} seconds after epoch exceeds i64 range",
                    secs
                )
            })
        }
        Err(err) => {
            // Before epoch — `SystemTimeError::duration()` gives the positive
            // distance from `UNIX_EPOCH`, which we negate.
            let duration = err.duration();
            let secs = duration.as_secs();
            let positive = i64::try_from(secs).map_err(|_| {
                anyhow!(
                    "file modification time {} seconds before epoch exceeds i64 range",
                    secs
                )
            })?;
            Ok(-positive)
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    // -- Conversion helper tests ------------------------------------------

    #[test]
    fn unix_to_systemtime_zero() {
        let st = unix_timestamp_to_system_time(0).unwrap();
        assert_eq!(st, UNIX_EPOCH);
    }

    #[test]
    fn unix_to_systemtime_positive() {
        let ts: i64 = 1_700_000_000; // 2023-11-14T22:13:20 UTC
        let st = unix_timestamp_to_system_time(ts).unwrap();
        let expected = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(st, expected);
    }

    #[test]
    fn unix_to_systemtime_negative() {
        let ts: i64 = -86_400; // 1969-12-31T00:00:00 UTC
        let st = unix_timestamp_to_system_time(ts).unwrap();
        let expected = UNIX_EPOCH.checked_sub(Duration::from_secs(86_400)).unwrap();
        assert_eq!(st, expected);
    }

    #[test]
    fn systemtime_to_unix_epoch() {
        let ts = system_time_to_unix_timestamp(UNIX_EPOCH).unwrap();
        assert_eq!(ts, 0);
    }

    #[test]
    fn systemtime_to_unix_positive() {
        let st = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let ts = system_time_to_unix_timestamp(st).unwrap();
        assert_eq!(ts, 1_700_000_000);
    }

    #[test]
    fn roundtrip_positive_timestamp() {
        let original: i64 = 1_609_459_200; // 2021-01-01T00:00:00 UTC
        let st = unix_timestamp_to_system_time(original).unwrap();
        let back = system_time_to_unix_timestamp(st).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn roundtrip_zero_timestamp() {
        let original: i64 = 0;
        let st = unix_timestamp_to_system_time(original).unwrap();
        let back = system_time_to_unix_timestamp(st).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn roundtrip_large_positive_timestamp() {
        // Year 2100 — 4102444800
        let original: i64 = 4_102_444_800;
        let st = unix_timestamp_to_system_time(original).unwrap();
        let back = system_time_to_unix_timestamp(st).unwrap();
        assert_eq!(original, back);
    }

    // -- File operation tests ---------------------------------------------

    #[test]
    fn set_and_get_filetime_roundtrip() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("test_file.txt");
        {
            let mut f = File::create(&file_path).expect("failed to create test file");
            f.write_all(b"test content").expect("failed to write");
        }
        let path_str = file_path.to_str().expect("non-UTF-8 path");

        // Set a known timestamp (2021-01-01 00:00:00 UTC)
        let target_ts: i64 = 1_609_459_200;
        set_filetime(path_str, target_ts).expect("set_filetime failed");

        // Read it back and verify
        let read_ts = get_filetime(path_str).expect("get_filetime failed");
        assert_eq!(read_ts, target_ts);
    }

    #[test]
    fn set_filetime_recent_timestamp() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("recent.txt");
        {
            let mut f = File::create(&file_path).expect("failed to create test file");
            f.write_all(b"recent").expect("failed to write");
        }
        let path_str = file_path.to_str().expect("non-UTF-8 path");

        // 2024-06-15 12:00:00 UTC = 1718452800
        let target_ts: i64 = 1_718_452_800;
        set_filetime(path_str, target_ts).expect("set_filetime failed");

        let read_ts = get_filetime(path_str).expect("get_filetime failed");
        assert_eq!(read_ts, target_ts);
    }

    #[test]
    fn get_filetime_nonexistent_file() {
        let result = get_filetime("/nonexistent/path/that/does/not/exist.txt");
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("failed to get metadata"),
            "unexpected error message: {}",
            err_msg
        );
    }

    #[test]
    fn set_filetime_nonexistent_file() {
        let result = set_filetime("/nonexistent/path/that/does/not/exist.txt", 1_000_000);
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("failed to open"),
            "unexpected error message: {}",
            err_msg
        );
    }

    #[test]
    fn set_filetime_epoch_zero() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("epoch_zero.txt");
        {
            let mut f = File::create(&file_path).expect("failed to create test file");
            f.write_all(b"epoch").expect("failed to write");
        }
        let path_str = file_path.to_str().expect("non-UTF-8 path");

        set_filetime(path_str, 0).expect("set_filetime failed for epoch zero");

        let read_ts = get_filetime(path_str).expect("get_filetime failed");
        assert_eq!(read_ts, 0);
    }

    #[test]
    fn set_filetime_one_second_after_epoch() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("one_sec.txt");
        {
            let mut f = File::create(&file_path).expect("failed to create test file");
            f.write_all(b"one").expect("failed to write");
        }
        let path_str = file_path.to_str().expect("non-UTF-8 path");

        set_filetime(path_str, 1).expect("set_filetime failed");

        let read_ts = get_filetime(path_str).expect("get_filetime failed");
        assert_eq!(read_ts, 1);
    }
}
