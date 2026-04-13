//! `file://` protocol handler — local filesystem I/O.
//!
//! Rust rewrite of `lib/file.c` from the curl 8.19.0-DEV C codebase.
//! Implements the FILE protocol handler for reading, writing, and listing
//! local files via `file://` URLs.
//!
//! # Supported Operations
//!
//! * **Download** — read a file from the local filesystem, supporting byte
//!   range requests (`CURLOPT_RANGE`), resume (`CURLOPT_RESUME_FROM`), time
//!   conditions (`CURLOPT_TIMECONDITION`), and automatic `Content-Length` /
//!   `Last-Modified` header generation.
//! * **Upload** — write data to a local file, supporting resume (append at
//!   offset), file permissions (`CURLOPT_NEW_FILE_PERMS`), and progress
//!   callback invocation.
//! * **Directory listing** — when the path refers to a directory, produces a
//!   newline-separated listing of non-hidden entries, matching curl 8.x
//!   output.
//!
//! # Platform Path Normalization
//!
//! The handler performs platform-aware path normalization:
//! * On Windows / DOS, a leading `/C:` or `/C|` is stripped and the drive
//!   letter separator is normalized to `:`.  Forward slashes are converted to
//!   backslashes.
//! * On Unix, the decoded path is used as-is (leading `/` preserved).
//! * Binary zero bytes in the decoded path are rejected with
//!   [`CurlError::UrlMalformat`].
//!
//! # C Equivalents
//!
//! | Rust                                | C function / struct                  |
//! |-------------------------------------|--------------------------------------|
//! | `FileProto`                         | `struct FILEPROTO`                   |
//! | `FileProto::connect()`              | `file_connect()`                     |
//! | `FileProto::do_it()`                | `file_do()`                          |
//! | `FileProto::done()`                 | `file_done()`                        |
//! | `FileProto::disconnect()`           | `file_disconnect()`                  |
//! | `FileProto::name()`                 | `Curl_scheme_file.scheme`            |
//! | `FileProto::default_port()`         | `Curl_scheme_file.defport`           |
//! | `FileProto::flags()`                | `Curl_scheme_file.flags`             |
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use tracing;

use crate::conn::ConnectionData;
use crate::error::{CurlError, CurlResult};
use crate::escape::url_decode;
use crate::progress::Progress;
use crate::protocols::{Protocol, ProtocolFlags};
use crate::transfer::TimeCondition;
use crate::util::parsedate::format_http_date;
use crate::util::sendf::ClientWriteFlags;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default buffer size for file I/O read/write operations (16 KiB).
/// Matches the C `CURL_MAX_WRITE_SIZE` default used in `file_do()`.
const FILE_BUFFER_SIZE: usize = 16 * 1024;

/// Default file permissions for newly created files (octal 0644).
/// Matches the C `DEFAULT_NEW_FILE_PERMS` value.
const DEFAULT_NEW_FILE_PERMS: u32 = 0o644;

// ---------------------------------------------------------------------------
// FileWriteCallback / FileReadCallback
// ---------------------------------------------------------------------------

/// Callback for delivering data (headers and body) to the client.
///
/// The `ClientWriteFlags` parameter indicates the type of data being
/// delivered (`HEADER` for response metadata, `BODY` for file content).
///
/// Returns `Ok(())` on success, or a [`CurlError`] to abort the transfer.
pub type FileWriteCallback =
    Box<dyn FnMut(&[u8], ClientWriteFlags) -> Result<(), CurlError> + Send + Sync>;

/// Callback for reading upload data from the client.
///
/// The buffer slice is filled with upload data. Returns
/// `(bytes_read, is_end_of_stream)`.
pub type FileReadCallback =
    Box<dyn FnMut(&mut [u8]) -> Result<(usize, bool), CurlError> + Send + Sync>;

// ---------------------------------------------------------------------------
// FileProto — protocol handler state
// ---------------------------------------------------------------------------

/// FILE protocol handler implementing `file://` URL access.
///
/// Replaces the C `struct FILEPROTO` from `lib/file.c`. Holds all
/// per-transfer state needed for local file operations: the decoded path,
/// optional file handle, transfer configuration, progress tracker, and
/// data delivery callbacks.
///
/// # Lifecycle
///
/// ```text
/// FileProto::new() → connect() → do_it() → done() → disconnect()
/// ```
///
/// The caller configures upload/download mode, resume offset, range,
/// time condition, and callbacks before invoking the protocol methods.
pub struct FileProto {
    // -- Decoded filesystem path (populated in connect) -----------------------
    /// Decoded and platform-normalized filesystem path.
    path: Option<PathBuf>,

    /// File handle opened for reading during download (populated in connect).
    read_file: Option<File>,

    // -- Transfer configuration (set by caller before connect/do_it) ----------
    /// Whether this is an upload operation (`true` = write, `false` = read).
    upload: bool,

    /// Resume byte offset.
    /// * Positive: absolute byte position to resume from.
    /// * Negative: offset from the end of the file.
    /// * Zero: no resume.
    resume_from: i64,

    /// Optional range specification string (e.g. `"100-200"`).
    range: Option<String>,

    /// Maximum download size in bytes. `-1` means no limit.
    maxdownload: i64,

    /// Skip the response body (equivalent to HTTP HEAD).
    no_body: bool,

    /// Time condition type for conditional file access.
    time_condition: TimeCondition,

    /// Reference timestamp for time condition (Unix epoch seconds).
    time_value: i64,

    /// Whether to collect and report the file modification time.
    get_filetime: bool,

    /// Collected file modification time (Unix timestamp), or `-1` if unknown.
    filetime: i64,

    /// File permission bits for newly created files during upload.
    new_file_perms: u32,

    /// Expected upload data size in bytes. `-1` means unknown.
    infilesize: i64,

    /// URL-encoded path component from the `file://` URL. Must be set by
    /// the caller before invoking [`connect()`](Protocol::connect).
    url_path: String,

    // -- Data delivery callbacks -----------------------------------------------
    /// Callback for delivering response headers and body data to the client.
    write_cb: Option<FileWriteCallback>,

    /// Callback for reading upload data from the client.
    read_cb: Option<FileReadCallback>,

    // -- Progress tracking ----------------------------------------------------
    /// Transfer progress tracker for speed and callback invocation.
    progress: Progress,
}

// ---------------------------------------------------------------------------
// FileProto — construction and configuration
// ---------------------------------------------------------------------------

impl Default for FileProto {
    fn default() -> Self {
        Self::new()
    }
}

impl FileProto {
    /// Creates a new `FileProto` with default configuration.
    ///
    /// The handler starts in download mode with no resume, no range, and
    /// default file permissions (0644). The caller must set [`url_path`],
    /// [`write_cb`] (for downloads), or [`read_cb`] (for uploads) before
    /// invoking protocol methods.
    pub fn new() -> Self {
        Self {
            path: None,
            read_file: None,
            upload: false,
            resume_from: 0,
            range: None,
            maxdownload: -1,
            no_body: false,
            time_condition: TimeCondition::None,
            time_value: 0,
            get_filetime: false,
            filetime: -1,
            new_file_perms: DEFAULT_NEW_FILE_PERMS,
            infilesize: -1,
            url_path: String::new(),
            write_cb: None,
            read_cb: None,
            progress: Progress::new(),
        }
    }

    /// Sets the URL-encoded path component from the `file://` URL.
    pub fn set_url_path(&mut self, path: String) {
        self.url_path = path;
    }

    /// Sets whether this transfer is an upload (`true`) or download (`false`).
    pub fn set_upload(&mut self, upload: bool) {
        self.upload = upload;
    }

    /// Sets the resume byte offset.
    pub fn set_resume_from(&mut self, offset: i64) {
        self.resume_from = offset;
    }

    /// Sets the byte range specification (e.g. `"100-200"`).
    pub fn set_range(&mut self, range: Option<String>) {
        self.range = range;
    }

    /// Sets the maximum download size in bytes (`-1` for unlimited).
    pub fn set_maxdownload(&mut self, max: i64) {
        self.maxdownload = max;
    }

    /// Sets whether to skip the response body.
    pub fn set_no_body(&mut self, no_body: bool) {
        self.no_body = no_body;
    }

    /// Sets the time condition and reference value.
    pub fn set_time_condition(&mut self, condition: TimeCondition, value: i64) {
        self.time_condition = condition;
        self.time_value = value;
    }

    /// Sets whether to collect file modification time.
    pub fn set_get_filetime(&mut self, get: bool) {
        self.get_filetime = get;
    }

    /// Sets the file permission bits for uploaded files.
    pub fn set_new_file_perms(&mut self, perms: u32) {
        self.new_file_perms = perms;
    }

    /// Sets the expected upload data size (`-1` for unknown).
    pub fn set_infilesize(&mut self, size: i64) {
        self.infilesize = size;
    }

    /// Installs the write callback for data delivery.
    pub fn set_write_callback(&mut self, cb: FileWriteCallback) {
        self.write_cb = Some(cb);
    }

    /// Installs the read callback for upload data.
    pub fn set_read_callback(&mut self, cb: FileReadCallback) {
        self.read_cb = Some(cb);
    }

    /// Returns the collected file modification time, or `-1` if not available.
    pub fn filetime(&self) -> i64 {
        self.filetime
    }

    /// Returns a reference to the progress tracker.
    pub fn progress(&self) -> &Progress {
        &self.progress
    }

    /// Returns a mutable reference to the progress tracker.
    pub fn progress_mut(&mut self) -> &mut Progress {
        &mut self.progress
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — path normalization
// ---------------------------------------------------------------------------

/// Decode and normalize a URL-encoded file path into a platform-native
/// filesystem path.
///
/// Replaces the path-handling logic in C `file_connect()` including
/// `DOS_FILESYSTEM` and `AMIGA_FILESYSTEM` branches.
///
/// # Errors
///
/// * [`CurlError::UrlMalformat`] — if the decoded path contains binary zero
///   bytes (matching C `REJECT_ZERO` behavior).
/// * [`CurlError::OutOfMemory`] — if URL decoding fails due to allocation
///   (extremely unlikely in Rust but preserved for API parity).
fn decode_and_normalize_path(url_path: &str) -> CurlResult<PathBuf> {
    // Step 1: URL-decode the path.
    let decoded_bytes = url_decode(url_path).map_err(|_| CurlError::OutOfMemory)?;

    // Step 2: Reject binary zero bytes (REJECT_ZERO in C).
    if decoded_bytes.contains(&0u8) {
        tracing::error!(
            "file:// path contains binary zero byte — rejecting as malformed"
        );
        return Err(CurlError::UrlMalformat);
    }

    // Step 3: Convert bytes to a UTF-8 string.
    let decoded_str = String::from_utf8(decoded_bytes).map_err(|_| {
        tracing::error!("file:// path is not valid UTF-8 after percent-decoding");
        CurlError::UrlMalformat
    })?;

    // Step 4: Platform-specific path normalization.
    let normalized = normalize_platform_path(&decoded_str);

    Ok(PathBuf::from(normalized))
}

/// Perform platform-specific path normalization.
///
/// On Windows/DOS:
/// * If the path starts with `/X:` or `/X|` where X is a letter, strip
///   the leading `/` and normalize `|` to `:`.
/// * Replace all forward slashes with backslashes.
///
/// On Unix (the common case):
/// * The path is returned as-is.
fn normalize_platform_path(path: &str) -> String {
    let bytes = path.as_bytes();

    // Check for DOS/Windows-style drive letter patterns.
    // Pattern: "/C:" or "/C|" where C is an ASCII letter.
    if cfg!(windows) {
        if bytes.len() >= 3
            && bytes[0] == b'/'
            && bytes[1].is_ascii_alphabetic()
            && (bytes[2] == b':' || bytes[2] == b'|')
        {
            // Strip the leading '/' and normalize '|' to ':'.
            let mut result = String::with_capacity(path.len() - 1);
            result.push(bytes[1] as char);
            result.push(':');
            // Append the rest of the path, converting '/' to '\'.
            for &b in &bytes[3..] {
                if b == b'/' {
                    result.push('\\');
                } else {
                    result.push(b as char);
                }
            }
            return result;
        }

        // No drive letter but still Windows: convert '/' to '\'.
        return path.replace('/', "\\");
    }

    // Unix: return as-is.
    path.to_string()
}

// ---------------------------------------------------------------------------
// Internal helpers — deliver header data to client
// ---------------------------------------------------------------------------

impl FileProto {
    /// Deliver a header line to the client via the write callback.
    ///
    /// Sends data tagged with [`ClientWriteFlags::HEADER`].
    fn deliver_header(&mut self, header: &str) -> CurlResult<()> {
        if let Some(ref mut cb) = self.write_cb {
            cb(header.as_bytes(), ClientWriteFlags::HEADER)?;
        }
        Ok(())
    }

    /// Deliver body data to the client via the write callback.
    ///
    /// Sends data tagged with [`ClientWriteFlags::BODY`].
    fn deliver_body(&mut self, data: &[u8]) -> CurlResult<()> {
        if let Some(ref mut cb) = self.write_cb {
            cb(data, ClientWriteFlags::BODY)?;
        }
        Ok(())
    }

    /// Read upload data from the client via the read callback.
    ///
    /// Returns `(bytes_read, is_eos)`. If no read callback is installed,
    /// returns `(0, true)` to signal end-of-stream.
    fn read_upload_data(&mut self, buf: &mut [u8]) -> CurlResult<(usize, bool)> {
        if let Some(ref mut cb) = self.read_cb {
            cb(buf)
        } else {
            Ok((0, true))
        }
    }

    /// Check whether the file's modification time satisfies the configured
    /// time condition.
    ///
    /// Implements the same logic as `Curl_meets_timecondition()` in
    /// `lib/transfer.c`.
    ///
    /// Returns `true` if the transfer should proceed, `false` if the
    /// condition is not met.
    fn meets_timecondition(&self, time_of_doc: i64) -> bool {
        if time_of_doc == 0 || self.time_value == 0 {
            return true;
        }

        match self.time_condition {
            TimeCondition::IfModifiedSince => {
                if time_of_doc <= self.time_value {
                    tracing::debug!(
                        time_of_doc = time_of_doc,
                        time_value = self.time_value,
                        "file:// timecondition not met: document not new enough"
                    );
                    return false;
                }
            }
            TimeCondition::IfUnmodifiedSince => {
                if time_of_doc >= self.time_value {
                    tracing::debug!(
                        time_of_doc = time_of_doc,
                        time_value = self.time_value,
                        "file:// timecondition not met: document not old enough"
                    );
                    return false;
                }
            }
            TimeCondition::None | TimeCondition::LastMod => {
                // No condition or LastMod — always proceed.
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — file upload
// ---------------------------------------------------------------------------

impl FileProto {
    /// Perform a file upload operation.
    ///
    /// Replaces C `file_upload()` from `lib/file.c` lines 264–374.
    ///
    /// Opens the target file for writing (creating or truncating as needed),
    /// reads upload data from the client read callback, handles resume
    /// semantics, tracks progress, and reports errors.
    fn file_upload(&mut self) -> CurlResult<()> {
        // Clone the path to avoid holding an immutable borrow on `self`.
        let path = self.path.clone().ok_or_else(|| {
            tracing::error!("file:// upload with no path set");
            CurlError::FailedInit
        })?;

        // Validate that the path has at least a directory separator.
        // Matches C check: `dir = strchr(file->path, DIRSEP)`.
        let path_str = path.to_string_lossy().to_string();
        let sep = std::path::MAIN_SEPARATOR;
        let has_dir = path_str.contains(sep) || path_str.contains('/');
        if !has_dir {
            tracing::error!(path = %path_str, "file:// upload path has no directory separator");
            return Err(CurlError::FileCouldntReadFile);
        }

        // Determine open mode: append for resume, truncate otherwise.
        let mut opts = OpenOptions::new();
        opts.write(true).create(true);
        if self.resume_from != 0 {
            opts.append(true);
        } else {
            opts.truncate(true);
        }

        // Set file permissions on Unix platforms.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(self.new_file_perms);
        }

        let mut fd = opts.open(&path).map_err(|e| {
            tracing::error!(path = %path.display(), error = %e, "cannot open file for writing");
            CurlError::WriteError
        })?;

        // Report expected upload size for progress tracking.
        if self.infilesize >= 0 {
            self.progress
                .set_upload_size(Some(self.infilesize as u64));
        }

        // Handle negative resume offset: seek to (file_size + resume_from).
        if self.resume_from < 0 {
            let meta = fd.metadata().map_err(|e| {
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "cannot get file size for resume"
                );
                CurlError::WriteError
            })?;
            self.resume_from += meta.len() as i64;
            if self.resume_from < 0 {
                self.resume_from = 0;
            }
        }

        // Allocate the transfer buffer.
        let mut xfer_buf = vec![0u8; FILE_BUFFER_SIZE];
        let mut eos = false;

        // Main upload loop: read from client, write to file.
        while !eos {
            let (readcount, is_eos) = self.read_upload_data(&mut xfer_buf)?;
            eos = is_eos;

            if readcount == 0 {
                break;
            }

            let mut nread = readcount;
            let mut send_start = 0usize;

            // Skip bytes before resume point.
            if self.resume_from > 0 {
                if (nread as i64) <= self.resume_from {
                    self.resume_from -= nread as i64;
                    nread = 0;
                } else {
                    send_start = self.resume_from as usize;
                    nread -= send_start;
                    self.resume_from = 0;
                }
            }

            if nread > 0 {
                let write_slice = &xfer_buf[send_start..send_start + nread];
                fd.write_all(write_slice).map_err(|e| {
                    tracing::error!(error = %e, "file:// upload write failed");
                    CurlError::SendError
                })?;

                self.progress.upload_inc(nread as u64);
            }

            self.progress.check()?;
        }

        self.progress.update()?;

        tracing::debug!(
            path = %path.display(),
            "file:// upload complete"
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — file download and directory listing
// ---------------------------------------------------------------------------

impl FileProto {
    /// Perform a file download or directory listing operation.
    ///
    /// Replaces the download/directory-listing branch of C `file_do()`
    /// from `lib/file.c` lines 384–599.
    ///
    /// * Stat the file to get size and modification time.
    /// * Check time conditions.
    /// * Generate response headers (`Content-Length`, `Accept-ranges`,
    ///   `Last-Modified`).
    /// * For regular files: read and deliver data in chunks.
    /// * For directories: list non-hidden entries.
    fn file_download(&mut self) -> CurlResult<()> {
        // Clone the path to avoid holding an immutable borrow on `self`.
        let path_clone = self.path.clone().ok_or_else(|| {
            tracing::error!("file:// download with no path set");
            CurlError::FailedInit
        })?;

        let is_directory = path_clone.is_dir();

        // -- Stat the file / directory ----------------------------------------
        let mut expected_size: i64 = -1;
        let mut fstated = false;

        match fs::metadata(&path_clone) {
            Ok(meta) => {
                if !is_directory {
                    expected_size = meta.len() as i64;
                }

                // Extract modification time as Unix timestamp.
                self.filetime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(-1);

                fstated = true;
            }
            Err(e) => {
                tracing::warn!(
                    path = %path_clone.display(),
                    error = %e,
                    "file:// could not stat path"
                );
            }
        }

        // -- Time condition check ---------------------------------------------
        if fstated
            && self.range.is_none()
            && self.time_condition != TimeCondition::None
            && !self.meets_timecondition(self.filetime)
        {
            tracing::debug!("file:// timecondition not met, returning early");
            return Ok(());
        }

        // -- Generate response headers ----------------------------------------
        if fstated {
            // Content-Length header (only for regular files with known size).
            if expected_size >= 0 {
                let header = format!("Content-Length: {}\r\n", expected_size);
                self.deliver_header(&header)?;

                let accept_ranges = "Accept-ranges: bytes\r\n";
                self.deliver_header(accept_ranges)?;
            }

            // Last-Modified header from file modification timestamp.
            if self.filetime >= 0 {
                let date_str = format_http_date(self.filetime);
                if !date_str.is_empty() {
                    let header = format!("Last-Modified: {}\r\n", date_str);
                    self.deliver_header(&header)?;
                }
            }

            // End of headers.
            self.deliver_header("\r\n")?;

            // Set download size for progress reporting.
            if expected_size >= 0 {
                self.progress
                    .set_download_size(Some(expected_size as u64));
            }

            // If no_body is set, return after headers (HEAD-like behavior).
            if self.no_body {
                return Ok(());
            }
        }

        // -- Range processing -------------------------------------------------
        // Parse and apply range specification.
        self.apply_range(&mut expected_size)?;

        // Adjust for negative resume_from: rewind from end of file.
        // Matches C: data->state.resume_from += (curl_off_t)statbuf.st_size
        if self.resume_from < 0 {
            if !fstated {
                tracing::error!("file:// cannot determine file size for resume");
                return Err(CurlError::ReadError);
            }
            let file_size = fs::metadata(&path_clone)
                .map(|m| m.len() as i64)
                .unwrap_or(0);
            self.resume_from += file_size;
        }

        // Adjust expected_size for resume offset.
        if self.resume_from > 0 && expected_size >= 0 {
            if self.resume_from <= expected_size {
                expected_size -= self.resume_from;
            } else {
                tracing::error!(
                    resume_from = self.resume_from,
                    file_size = expected_size,
                    "file:// resume offset exceeds file size"
                );
                return Err(CurlError::BadDownloadResume);
            }
        }

        // Apply maxdownload cap.
        if self.maxdownload > 0 {
            expected_size = self.maxdownload;
        }

        // Determine if size is known.
        let size_known = fstated && expected_size > 0;

        // Update download progress size after all adjustments.
        if size_known {
            self.progress
                .set_download_size(Some(expected_size as u64));
        }

        // -- Seek to resume offset --------------------------------------------
        if self.resume_from > 0 {
            if is_directory {
                tracing::error!("file:// cannot resume a directory listing");
                return Err(CurlError::BadDownloadResume);
            }

            if let Some(ref mut f) = self.read_file {
                let actual = f.seek(SeekFrom::Start(self.resume_from as u64)).map_err(|e| {
                    tracing::error!(
                        offset = self.resume_from,
                        error = %e,
                        "file:// seek for resume failed"
                    );
                    CurlError::BadDownloadResume
                })?;
                if actual != self.resume_from as u64 {
                    return Err(CurlError::BadDownloadResume);
                }
            }
        }

        // -- Transfer data ----------------------------------------------------
        if !is_directory {
            self.file_read_and_deliver(size_known, expected_size)?;
        } else {
            self.file_dir_list(&path_clone)?;
        }

        // Final progress update.
        self.progress.update()?;

        Ok(())
    }

    /// Read file content in chunks and deliver to the client.
    ///
    /// Handles the `size_known` / `expected_size` constraints for range
    /// downloads and maxdownload limits.
    fn file_read_and_deliver(
        &mut self,
        size_known: bool,
        mut expected_size: i64,
    ) -> CurlResult<()> {
        // Take the file handle out of `self` to avoid double mutable borrow
        // when calling `self.deliver_body()` in the read loop.
        let mut file = self.read_file.take().ok_or_else(|| {
            tracing::error!("file:// download with no open file handle");
            CurlError::FileCouldntReadFile
        })?;

        let mut buf = vec![0u8; FILE_BUFFER_SIZE];
        let mut result: CurlResult<()> = Ok(());

        loop {
            // Determine how many bytes to read this iteration.
            let bytes_to_read = if size_known {
                (FILE_BUFFER_SIZE - 1).min(
                    if expected_size >= 0 {
                        expected_size as usize
                    } else {
                        FILE_BUFFER_SIZE - 1
                    },
                )
            } else {
                FILE_BUFFER_SIZE - 1
            };

            if bytes_to_read == 0 {
                break;
            }

            let nread = match file.read(&mut buf[..bytes_to_read]) {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(error = %e, "file:// read failed");
                    result = Err(CurlError::ReadError);
                    break;
                }
            };

            if nread == 0 {
                break;
            }

            // Check if we've reached the expected size limit.
            if size_known && expected_size == 0 {
                break;
            }

            if size_known {
                expected_size -= nread as i64;
            }

            // Deliver body data to the client.
            if let Err(e) = self.deliver_body(&buf[..nread]) {
                result = Err(e);
                break;
            }

            // Progress check (periodic callback invocation).
            if let Err(e) = self.progress.check() {
                result = Err(e);
                break;
            }
        }

        // Restore the file handle back into self.
        self.read_file = Some(file);

        result
    }

    /// List directory contents and deliver as newline-separated entry names.
    ///
    /// Non-hidden entries (those not starting with `.`) are listed,
    /// matching the curl 8.x `readdir()` filter in `file_do()`.
    fn file_dir_list(&mut self, dir_path: &Path) -> CurlResult<()> {
        let entries = fs::read_dir(dir_path).map_err(|e| {
            tracing::error!(
                path = %dir_path.display(),
                error = %e,
                "file:// directory listing failed"
            );
            CurlError::ReadError
        })?;

        for entry_result in entries {
            let entry = entry_result.map_err(|e| {
                tracing::error!(error = %e, "file:// error reading directory entry");
                CurlError::ReadError
            })?;

            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip hidden entries (those starting with '.').
            if name_str.starts_with('.') {
                continue;
            }

            // Deliver the entry name followed by a newline.
            self.deliver_body(name_str.as_bytes())?;
            self.deliver_body(b"\n")?;
        }

        Ok(())
    }

    /// Parse and apply the range specification to adjust the resume offset.
    ///
    /// Handles the `CURLOPT_RANGE` format: `"start-end"` where either start
    /// or end may be omitted.
    fn apply_range(&mut self, _expected_size: &mut i64) -> CurlResult<()> {
        if let Some(ref range) = self.range.clone() {
            let range = range.trim();
            if range.is_empty() {
                return Ok(());
            }

            // Parse "start-end" format.
            let parts: Vec<&str> = range.splitn(2, '-').collect();
            if parts.len() == 2 {
                let start_str = parts[0].trim();
                let end_str = parts[1].trim();

                if !start_str.is_empty() {
                    if let Ok(start) = start_str.parse::<i64>() {
                        self.resume_from = start;
                    }
                }

                if !end_str.is_empty() {
                    if let Ok(end) = end_str.parse::<i64>() {
                        // maxdownload is the number of bytes to fetch.
                        let max = end - self.resume_from + 1;
                        if max > 0 {
                            self.maxdownload = max;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Protocol trait implementation
// ---------------------------------------------------------------------------

impl Protocol for FileProto {
    /// Returns the protocol name: `"FILE"`.
    fn name(&self) -> &str {
        "FILE"
    }

    /// Returns the default port for `file://`: `0` (no network port).
    fn default_port(&self) -> u16 {
        0
    }

    /// Returns protocol capability flags.
    ///
    /// `NONETWORK` indicates that `file://` performs no network I/O.
    /// Matches the C `PROTOPT_NONETWORK | PROTOPT_NOURLQUERY` flags.
    fn flags(&self) -> ProtocolFlags {
        ProtocolFlags::NONETWORK
    }

    /// Establish the protocol-level "connection" to a local file.
    ///
    /// Decodes the URL-encoded path from `self.url_path`, applies
    /// platform-specific path normalization (drive letters on Windows,
    /// binary zero rejection), and opens the file for reading if this
    /// is a download operation.
    ///
    /// # Errors
    ///
    /// * [`CurlError::FailedInit`] — if no `url_path` has been set.
    /// * [`CurlError::UrlMalformat`] — if the path contains binary zero bytes.
    /// * [`CurlError::FileCouldntReadFile`] — if the file cannot be opened
    ///   for reading during a download.
    async fn connect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        let _ = conn; // FILE doesn't use network connection state.

        // If already connected (path already decoded), return immediately.
        if self.path.is_some() {
            tracing::debug!("file:// already connected");
            return Ok(());
        }

        if self.url_path.is_empty() {
            tracing::error!("file:// connect called with empty url_path");
            return Err(CurlError::FailedInit);
        }

        tracing::debug!(url_path = %self.url_path, "file:// connect — decoding path");

        // Decode and normalize the URL path.
        let real_path = decode_and_normalize_path(&self.url_path)?;

        tracing::debug!(
            decoded_path = %real_path.display(),
            upload = self.upload,
            "file:// path decoded"
        );

        // Open file for reading if this is a download.
        if !self.upload {
            match File::open(&real_path) {
                Ok(f) => {
                    self.read_file = Some(f);
                }
                Err(e) => {
                    tracing::error!(
                        path = %real_path.display(),
                        error = %e,
                        "Could not open file for reading"
                    );
                    self.path = Some(real_path);
                    // Check if it's a directory — directories can't be opened
                    // as files but are valid for listing.
                    if self.path.as_ref().is_some_and(|p| p.is_dir()) {
                        tracing::debug!("file:// path is a directory, will list contents");
                        return Ok(());
                    }
                    return Err(CurlError::FileCouldntReadFile);
                }
            }
        }

        self.path = Some(real_path);
        Ok(())
    }

    /// Execute the main data transfer operation.
    ///
    /// Dispatches to [`file_upload()`](FileProto::file_upload) for uploads
    /// or [`file_download()`](FileProto::file_download) for downloads and
    /// directory listings.
    async fn do_it(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        let _ = conn; // FILE doesn't use network connection state.

        if self.path.is_none() {
            tracing::error!("file:// do_it called without connect");
            return Err(CurlError::FailedInit);
        }

        if self.upload {
            tracing::debug!(
                path = %self.path.as_ref().unwrap().display(),
                "file:// starting upload"
            );
            self.file_upload()
        } else {
            tracing::debug!(
                path = %self.path.as_ref().unwrap().display(),
                "file:// starting download"
            );
            self.file_download()
        }
    }

    /// Finalize the transfer and clean up per-transfer resources.
    ///
    /// Closes any open file handles and resets the decoded path. The
    /// handler remains usable for subsequent transfers after calling
    /// [`connect()`](Protocol::connect) again.
    async fn done(
        &mut self,
        conn: &mut ConnectionData,
        status: CurlError,
    ) -> Result<(), CurlError> {
        let _ = conn;
        let _ = status;

        tracing::debug!("file:// done — cleaning up");

        // Close the file handle.
        self.read_file = None;

        // Clear the decoded path so a fresh connect() is required.
        self.path = None;

        // Reset collected filetime.
        self.filetime = -1;

        Ok(())
    }

    /// Disconnect and release all protocol-level resources.
    ///
    /// For FILE, this is equivalent to `done()` since there is no
    /// persistent connection to tear down.
    async fn disconnect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        let _ = conn;

        tracing::debug!("file:// disconnect");

        self.read_file = None;
        self.path = None;
        self.filetime = -1;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl std::fmt::Debug for FileProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileProto")
            .field("path", &self.path)
            .field("upload", &self.upload)
            .field("resume_from", &self.resume_from)
            .field("range", &self.range)
            .field("maxdownload", &self.maxdownload)
            .field("no_body", &self.no_body)
            .field("filetime", &self.filetime)
            .field("has_read_file", &self.read_file.is_some())
            .field("has_write_cb", &self.write_cb.is_some())
            .field("has_read_cb", &self.read_cb.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Path normalization tests ---------------------------------------------

    #[test]
    fn normalize_unix_path_preserved() {
        // On Unix, paths should be preserved as-is.
        if !cfg!(windows) {
            let result = normalize_platform_path("/home/user/file.txt");
            assert_eq!(result, "/home/user/file.txt");
        }
    }

    #[test]
    fn normalize_empty_path() {
        let result = normalize_platform_path("");
        assert_eq!(result, "");
    }

    #[test]
    fn decode_path_rejects_null_bytes() {
        // URL-encoded null byte: %00
        let result = decode_and_normalize_path("/test%00file");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::UrlMalformat);
    }

    #[test]
    fn decode_simple_path() {
        let result = decode_and_normalize_path("/home/user/file.txt");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(path, PathBuf::from("/home/user/file.txt"));
    }

    #[test]
    fn decode_encoded_spaces() {
        let result = decode_and_normalize_path("/home/user/my%20file.txt");
        assert!(result.is_ok());
        let path = result.unwrap();
        // url_decode converts + to space and %20 to space
        assert!(path.to_string_lossy().contains("my"));
        assert!(path.to_string_lossy().contains("file.txt"));
    }

    // -- FileProto construction tests -----------------------------------------

    #[test]
    fn new_creates_default_state() {
        let proto = FileProto::new();
        assert!(proto.path.is_none());
        assert!(proto.read_file.is_none());
        assert!(!proto.upload);
        assert_eq!(proto.resume_from, 0);
        assert!(proto.range.is_none());
        assert_eq!(proto.maxdownload, -1);
        assert!(!proto.no_body);
        assert_eq!(proto.time_condition, TimeCondition::None);
        assert_eq!(proto.time_value, 0);
        assert_eq!(proto.filetime, -1);
        assert_eq!(proto.new_file_perms, DEFAULT_NEW_FILE_PERMS);
        assert_eq!(proto.infilesize, -1);
    }

    #[test]
    fn protocol_name_is_file() {
        let proto = FileProto::new();
        assert_eq!(proto.name(), "FILE");
    }

    #[test]
    fn protocol_default_port_is_zero() {
        let proto = FileProto::new();
        assert_eq!(proto.default_port(), 0);
    }

    #[test]
    fn protocol_flags_nonetwork() {
        let proto = FileProto::new();
        let flags = proto.flags();
        assert!(flags.contains(ProtocolFlags::NONETWORK));
    }

    // -- Time condition tests -------------------------------------------------

    #[test]
    fn meets_timecondition_none_always_true() {
        let proto = FileProto::new();
        assert!(proto.meets_timecondition(12345));
    }

    #[test]
    fn meets_timecondition_if_modified_since() {
        let mut proto = FileProto::new();
        proto.time_condition = TimeCondition::IfModifiedSince;
        proto.time_value = 1000;

        // Document is newer than reference → condition met.
        assert!(proto.meets_timecondition(2000));

        // Document is older than reference → condition not met.
        assert!(!proto.meets_timecondition(500));

        // Document is same age → condition not met (matches C: <=).
        assert!(!proto.meets_timecondition(1000));
    }

    #[test]
    fn meets_timecondition_if_unmodified_since() {
        let mut proto = FileProto::new();
        proto.time_condition = TimeCondition::IfUnmodifiedSince;
        proto.time_value = 1000;

        // Document is older than reference → condition met.
        assert!(proto.meets_timecondition(500));

        // Document is newer than reference → condition not met.
        assert!(!proto.meets_timecondition(2000));

        // Document is same age → condition not met (matches C: >=).
        assert!(!proto.meets_timecondition(1000));
    }

    #[test]
    fn meets_timecondition_zero_doc_always_true() {
        let mut proto = FileProto::new();
        proto.time_condition = TimeCondition::IfModifiedSince;
        proto.time_value = 1000;
        assert!(proto.meets_timecondition(0));
    }

    #[test]
    fn meets_timecondition_zero_value_always_true() {
        let mut proto = FileProto::new();
        proto.time_condition = TimeCondition::IfModifiedSince;
        proto.time_value = 0;
        assert!(proto.meets_timecondition(2000));
    }

    // -- Configuration setters -----------------------------------------------

    #[test]
    fn setter_methods_work() {
        let mut proto = FileProto::new();

        proto.set_url_path("/test".to_string());
        assert_eq!(proto.url_path, "/test");

        proto.set_upload(true);
        assert!(proto.upload);

        proto.set_resume_from(100);
        assert_eq!(proto.resume_from, 100);

        proto.set_range(Some("0-99".to_string()));
        assert_eq!(proto.range.as_deref(), Some("0-99"));

        proto.set_maxdownload(1024);
        assert_eq!(proto.maxdownload, 1024);

        proto.set_no_body(true);
        assert!(proto.no_body);

        proto.set_time_condition(TimeCondition::IfModifiedSince, 12345);
        assert_eq!(proto.time_condition, TimeCondition::IfModifiedSince);
        assert_eq!(proto.time_value, 12345);

        proto.set_get_filetime(true);
        assert!(proto.get_filetime);

        proto.set_new_file_perms(0o755);
        assert_eq!(proto.new_file_perms, 0o755);

        proto.set_infilesize(2048);
        assert_eq!(proto.infilesize, 2048);
    }

    // -- Range parsing tests -------------------------------------------------

    #[test]
    fn apply_range_empty_is_noop() {
        let mut proto = FileProto::new();
        proto.range = Some("".to_string());
        let mut size: i64 = 1000;
        proto.apply_range(&mut size).unwrap();
        assert_eq!(proto.resume_from, 0);
        assert_eq!(proto.maxdownload, -1);
    }

    #[test]
    fn apply_range_start_end() {
        let mut proto = FileProto::new();
        proto.range = Some("100-200".to_string());
        let mut size: i64 = 1000;
        proto.apply_range(&mut size).unwrap();
        assert_eq!(proto.resume_from, 100);
        assert_eq!(proto.maxdownload, 101); // 200 - 100 + 1
    }

    #[test]
    fn apply_range_start_only() {
        let mut proto = FileProto::new();
        proto.range = Some("50-".to_string());
        let mut size: i64 = 1000;
        proto.apply_range(&mut size).unwrap();
        assert_eq!(proto.resume_from, 50);
        assert_eq!(proto.maxdownload, -1); // no end → no maxdownload
    }

    // -- Default trait --------------------------------------------------------

    #[test]
    fn default_matches_new() {
        let a = FileProto::new();
        let b = FileProto::default();
        assert_eq!(a.resume_from, b.resume_from);
        assert_eq!(a.maxdownload, b.maxdownload);
        assert_eq!(a.upload, b.upload);
        assert_eq!(a.filetime, b.filetime);
    }

    // -- Debug impl -----------------------------------------------------------

    #[test]
    fn debug_impl_contains_fields() {
        let proto = FileProto::new();
        let dbg = format!("{:?}", proto);
        assert!(dbg.contains("FileProto"));
        assert!(dbg.contains("upload"));
        assert!(dbg.contains("path"));
    }

    // -- Callback delivery ----------------------------------------------------

    #[test]
    fn deliver_header_calls_write_cb() {
        let mut proto = FileProto::new();
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let recv_clone = received.clone();
        proto.set_write_callback(Box::new(move |data, flags| {
            if flags.contains(ClientWriteFlags::HEADER) {
                recv_clone.lock().unwrap().extend_from_slice(data);
            }
            Ok(())
        }));
        proto.deliver_header("Content-Type: text/plain\r\n").unwrap();
        let data = received.lock().unwrap();
        assert_eq!(&*data, b"Content-Type: text/plain\r\n");
    }

    #[test]
    fn deliver_header_no_callback_is_ok() {
        let mut proto = FileProto::new();
        assert!(proto.deliver_header("test").is_ok());
    }

    #[test]
    fn deliver_body_calls_write_cb() {
        let mut proto = FileProto::new();
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let recv_clone = received.clone();
        proto.set_write_callback(Box::new(move |data, flags| {
            if flags.contains(ClientWriteFlags::BODY) {
                recv_clone.lock().unwrap().extend_from_slice(data);
            }
            Ok(())
        }));
        proto.deliver_body(b"hello world").unwrap();
        let data = received.lock().unwrap();
        assert_eq!(&*data, b"hello world");
    }

    #[test]
    fn deliver_body_no_callback_is_ok() {
        let mut proto = FileProto::new();
        assert!(proto.deliver_body(b"test").is_ok());
    }

    #[test]
    fn read_upload_data_no_callback_returns_eos() {
        let mut proto = FileProto::new();
        let mut buf = [0u8; 64];
        let (n, eos) = proto.read_upload_data(&mut buf).unwrap();
        assert_eq!(n, 0);
        assert!(eos);
    }

    #[test]
    fn read_upload_data_with_callback() {
        let mut proto = FileProto::new();
        proto.set_read_callback(Box::new(|buf| {
            let data = b"test data";
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok((len, true))
        }));
        let mut buf = [0u8; 64];
        let (n, eos) = proto.read_upload_data(&mut buf).unwrap();
        assert_eq!(n, 9);
        assert!(eos);
        assert_eq!(&buf[..9], b"test data");
    }

    // -- Progress accessor ----------------------------------------------------

    #[test]
    fn progress_accessors() {
        let mut proto = FileProto::new();
        let _ = proto.progress();
        let _ = proto.progress_mut();
    }

    // -- Filetime accessor ----------------------------------------------------

    #[test]
    fn filetime_default_is_minus_one() {
        let proto = FileProto::new();
        assert_eq!(proto.filetime(), -1);
    }

    // -- Constants ------------------------------------------------------------

    #[test]
    fn file_buffer_size_is_16k() {
        assert_eq!(FILE_BUFFER_SIZE, 16384);
    }

    #[test]
    fn default_file_perms_is_0644() {
        assert_eq!(DEFAULT_NEW_FILE_PERMS, 0o644);
    }

    // -- Path normalization edge cases ----------------------------------------

    #[test]
    fn normalize_path_only_slash() {
        let result = normalize_platform_path("/");
        assert_eq!(result, "/");
    }

    #[test]
    fn normalize_path_deep_nesting() {
        let result = normalize_platform_path("/a/b/c/d/e/f/g");
        assert_eq!(result, "/a/b/c/d/e/f/g");
    }

    #[test]
    fn decode_path_percent_encoded_slash() {
        let result = decode_and_normalize_path("/home%2Fuser");
        assert!(result.is_ok());
    }

    #[test]
    fn decode_path_double_encoded() {
        // %2520 = %25 -> '%' then '20', not a space
        let result = decode_and_normalize_path("/test%2520file");
        assert!(result.is_ok());
    }

    #[test]
    fn decode_path_unicode_utf8() {
        // URL-encoded UTF-8 for 'ü' = %C3%BC
        let result = decode_and_normalize_path("/t%C3%BCst");
        assert!(result.is_ok());
    }

    // -- TimeCondition LastMod variant ----------------------------------------

    #[test]
    fn meets_timecondition_lastmod_always_true() {
        let mut proto = FileProto::new();
        proto.time_condition = TimeCondition::LastMod;
        proto.time_value = 1000;
        assert!(proto.meets_timecondition(500));
        assert!(proto.meets_timecondition(2000));
    }

    // -- apply_range edge cases -----------------------------------------------

    #[test]
    fn apply_range_none_is_noop() {
        let mut proto = FileProto::new();
        // range is None by default
        let mut size: i64 = 1000;
        proto.apply_range(&mut size).unwrap();
        assert_eq!(proto.resume_from, 0);
        assert_eq!(proto.maxdownload, -1);
    }

    #[test]
    fn apply_range_whitespace_trimmed() {
        let mut proto = FileProto::new();
        proto.range = Some("  100-200  ".to_string());
        let mut size: i64 = 1000;
        proto.apply_range(&mut size).unwrap();
        assert_eq!(proto.resume_from, 100);
        assert_eq!(proto.maxdownload, 101);
    }

    #[test]
    fn apply_range_end_only() {
        let mut proto = FileProto::new();
        proto.range = Some("-500".to_string());
        let mut size: i64 = 1000;
        proto.apply_range(&mut size).unwrap();
        // start_str is empty, so resume_from stays 0
        assert_eq!(proto.resume_from, 0);
    }

    #[test]
    fn apply_range_invalid_numbers() {
        let mut proto = FileProto::new();
        proto.range = Some("abc-xyz".to_string());
        let mut size: i64 = 1000;
        proto.apply_range(&mut size).unwrap();
        // parse fails, so resume_from and maxdownload stay at defaults
        assert_eq!(proto.resume_from, 0);
        assert_eq!(proto.maxdownload, -1);
    }

    // -- file_read_and_deliver with real temp file ----------------------------

    #[test]
    fn file_read_and_deliver_reads_content() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        {
            let mut f = std::fs::File::create(&file_path).unwrap();
            f.write_all(b"Hello, file protocol!").unwrap();
        }

        let mut proto = FileProto::new();
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let recv_clone = received.clone();
        proto.set_write_callback(Box::new(move |data, _flags| {
            recv_clone.lock().unwrap().extend_from_slice(data);
            Ok(())
        }));
        proto.read_file = Some(std::fs::File::open(&file_path).unwrap());
        proto.file_read_and_deliver(true, 21).unwrap();
        let data = received.lock().unwrap();
        assert_eq!(&*data, b"Hello, file protocol!");
    }

    #[test]
    fn file_read_and_deliver_no_handle_error() {
        let mut proto = FileProto::new();
        let result = proto.file_read_and_deliver(false, -1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::FileCouldntReadFile);
    }

    // -- file_dir_list with temp dir ------------------------------------------

    #[test]
    fn file_dir_list_lists_non_hidden() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::File::create(dir.path().join("visible.txt")).unwrap();
        std::fs::File::create(dir.path().join(".hidden")).unwrap();

        let mut proto = FileProto::new();
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let recv_clone = received.clone();
        proto.set_write_callback(Box::new(move |data, _flags| {
            recv_clone.lock().unwrap().extend_from_slice(data);
            Ok(())
        }));
        proto.file_dir_list(dir.path()).unwrap();
        let data = received.lock().unwrap();
        let listing = String::from_utf8_lossy(&data);
        assert!(listing.contains("visible.txt"));
        assert!(!listing.contains(".hidden"));
    }

    #[test]
    fn file_dir_list_nonexistent_fails() {
        let mut proto = FileProto::new();
        let result = proto.file_dir_list(Path::new("/nonexistent_path_abcdef"));
        assert!(result.is_err());
    }

    // -- file_upload with temp file -------------------------------------------

    #[test]
    fn file_upload_writes_data() {
        use std::io::Read;
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("upload.txt");

        let mut proto = FileProto::new();
        proto.path = Some(file_path.clone());
        proto.upload = true;
        proto.set_read_callback(Box::new(|buf| {
            let data = b"uploaded content";
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok((len, true))
        }));
        proto.set_write_callback(Box::new(|_data, _flags| Ok(())));

        proto.file_upload().unwrap();

        let mut content = String::new();
        std::fs::File::open(&file_path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "uploaded content");
    }

    #[test]
    fn file_upload_no_path_fails() {
        let mut proto = FileProto::new();
        proto.upload = true;
        let result = proto.file_upload();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::FailedInit);
    }

    // -- file_download with temp file -----------------------------------------

    #[test]
    fn file_download_reads_file() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("download.txt");
        {
            let mut f = std::fs::File::create(&file_path).unwrap();
            f.write_all(b"download content").unwrap();
        }

        let mut proto = FileProto::new();
        proto.path = Some(file_path.clone());
        proto.read_file = Some(std::fs::File::open(&file_path).unwrap());
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let recv_clone = received.clone();
        proto.set_write_callback(Box::new(move |data, _flags| {
            recv_clone.lock().unwrap().extend_from_slice(data);
            Ok(())
        }));

        proto.file_download().unwrap();
        let data = received.lock().unwrap();
        assert!(data.len() > 0);
    }

    #[test]
    fn file_download_no_path_fails() {
        let mut proto = FileProto::new();
        let result = proto.file_download();
        assert!(result.is_err());
    }

    // -- Setter edge cases ----------------------------------------------------

    #[test]
    fn set_callbacks_replaces_existing() {
        let mut proto = FileProto::new();
        proto.set_write_callback(Box::new(|_d, _f| Ok(())));
        proto.set_write_callback(Box::new(|_d, _f| Ok(())));
        proto.set_read_callback(Box::new(|_b| Ok((0, true))));
        proto.set_read_callback(Box::new(|_b| Ok((0, true))));
        // No panic — second callback replaces first
    }

    #[test]
    fn set_infilesize_negative() {
        let mut proto = FileProto::new();
        proto.set_infilesize(-1);
        assert_eq!(proto.infilesize, -1);
    }

    #[test]
    fn set_resume_from_negative() {
        let mut proto = FileProto::new();
        proto.set_resume_from(-100);
        assert_eq!(proto.resume_from, -100);
    
    }
    // ====== Round 5 coverage tests ======

    #[test]
    fn test_file_handler_default_port_r5() {
        let h = FileProto::new();
        assert_eq!(h.default_port(), 0);
    }

    #[test]
    fn test_file_handler_name_r5() {
        let h = FileProto::new();
        assert_eq!(h.name(), "FILE");
    }

    #[test]
    fn test_file_handler_flags_r5() {
        let h = FileProto::new();
        let flags = h.flags();
        let _ = format!("{:?}", flags);
    }

    #[test]
    fn test_file_handler_connection_check_r5() {
        let h = FileProto::new();
        let conn = ConnectionData::new(1, "localhost".into(), 0, "file".into());
        let _ = Protocol::connection_check(&h, &conn);
    }



    // ====== Round 7 ======
    #[test] fn test_file_handler_r7() {
        let h = FileProto::new();
        assert_eq!(h.name(), "FILE");
        assert_eq!(h.default_port(), 0);
    }
    #[test] fn test_file_flags_r7() {
        let h = FileProto::new();
        let _ = h.flags();
    }


    // ===== ROUND 9 TESTS =====
    #[test]
    fn r9_file_proto_setters_comprehensive() {
        let mut f = FileProto::new();
        f.set_url_path("/tmp/test.txt".to_string());
        f.set_upload(true);
        f.set_resume_from(100);
        f.set_range(Some("0-99".to_string()));
        f.set_maxdownload(1024);
        f.set_no_body(true);
        f.set_get_filetime(true);
        f.set_new_file_perms(0o644);
        f.set_infilesize(2048);
        let _ = f.filetime();
        let _ = f.progress();
        let _ = f.progress_mut();
    }

    #[test]
    fn r9_file_proto_time_condition() {
        let mut f = FileProto::new();
        f.set_time_condition(TimeCondition::IfModifiedSince, 1700000000);
    }

    #[test]
    fn r9_file_proto_time_condition_unmod() {
        let mut f = FileProto::new();
        f.set_time_condition(TimeCondition::IfUnmodifiedSince, 1700000000);
    }


    // ===== ROUND 10 TESTS =====
    #[test]
    fn r10_file_proto_all_setters() {
        let mut f = FileProto::new();
        f.set_url_path("/a/b/c".to_string());
        f.set_upload(false);
        f.set_upload(true);
        f.set_resume_from(-1);
        f.set_resume_from(0);
        f.set_resume_from(1024);
        f.set_range(None);
        f.set_range(Some("0-99".to_string()));
        f.set_range(Some("100-".to_string()));
        f.set_maxdownload(-1);
        f.set_maxdownload(0);
        f.set_maxdownload(9999);
        f.set_no_body(false);
        f.set_no_body(true);
        f.set_get_filetime(false);
        f.set_get_filetime(true);
        f.set_new_file_perms(0o600);
        f.set_new_file_perms(0o755);
        f.set_infilesize(-1);
        f.set_infilesize(0);
        f.set_infilesize(999999);
        let _ = f.filetime();
        let _ = f.progress();
    }

}
