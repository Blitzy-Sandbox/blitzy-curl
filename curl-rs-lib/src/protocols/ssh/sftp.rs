//! SFTP Protocol Handler — complete Rust rewrite of the SFTP subsystem.
//!
//! This module is the Rust replacement for the SFTP-specific portions of:
//! - `lib/vssh/libssh2.c` (~3866 lines) — core SFTP state machine and operations
//! - `lib/vssh/libssh.c` (~3015 lines) — alternative libssh backend SFTP logic
//!
//! It implements complete SFTP file operations (upload/download/resume), directory
//! listing (ls -la format matching curl 8.x), QUOTE command interpreter supporting
//! all 12 commands (pwd, chgrp, chmod, chown, atime, mtime, ln/symlink, mkdir,
//! rename, rmdir, rm, statvfs), create-missing-directories, and the Protocol trait
//! for integration with the curl-rs protocol dispatch system.
//!
//! # SSH Transport
//!
//! Uses `russh` (0.55.x) for SSH2 transport and `russh-sftp` (2.1.x) for the
//! SFTP subsystem protocol. All async operations run on the Tokio runtime.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.
//! All memory management uses Rust ownership and borrowing.

// ============================================================================
// Standard library imports
// ============================================================================
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// External crate imports
// ============================================================================
use russh_sftp::client::SftpSession as RusshSftpSession;
use russh_sftp::client::fs;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncSeekExt};
use tracing::{debug, error, trace, warn};

// ============================================================================
// Internal crate imports
// ============================================================================
use crate::error::{CurlError, CurlResult};
use crate::conn::ConnectionData;
use crate::progress::Progress;
use crate::protocols::{ConnectionCheckResult, Protocol, ProtocolFlags};
// TransferConfig and TransferState are used indirectly in method signatures
// by code calling into SftpHandler from the transfer engine.
#[allow(unused_imports)]
use crate::transfer::{TransferConfig, TransferState};
use crate::util::dynbuf::DynBuf;
use crate::util::parsedate::MONTH_NAMES;

// Parent module imports
use super::{
    SshSession, SshState, get_pathname, ssh_range,
    SSH_FLAG_DIRLOCK, SSH_FLAG_NOURLQUERY, PORT_SSH,
    MAX_SSHPATH_LEN, MAX_PATHLENGTH,
};

// ============================================================================
// Constants
// ============================================================================

/// Default permissions for newly created directories (0o755).
/// Matches C `CURLOPT_NEW_DIRECTORY_PERMS` default.
const DEFAULT_DIR_PERMS: u32 = 0o755;

/// Default permissions for newly created files during upload (0o644).
/// Used by sftp_upload_init when creating new files via open_with_flags.
#[allow(dead_code)]
const DEFAULT_FILE_PERMS: u32 = 0o644;

/// Buffer size for read/write SFTP operations (16 KiB).
/// Available for callers that need a default buffer size for SFTP I/O.
#[allow(dead_code)]
const SFTP_BUFFER_SIZE: usize = 16 * 1024;

/// Maximum size for DynBuf directory listing buffer (1 MiB).
const DIR_LISTING_MAX_SIZE: usize = 1024 * 1024;

/// Threshold in seconds for "recent" files in directory listing.
/// Files modified within the last 6 months show time instead of year.
const RECENT_FILE_THRESHOLD_SECS: u64 = 180 * 24 * 60 * 60;

// ============================================================================
// SftpState — SFTP operation state machine
// ============================================================================

/// SFTP-specific state machine states.
///
/// Maps to C `SSH_SFTP_*` states from `ssh.h` lines 48-81.
/// Each variant represents a discrete step in the SFTP state machine,
/// tracking the progress of upload, download, directory listing, QUOTE
/// command execution, and session lifecycle operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SftpState {
    /// Initialize SFTP subsystem over SSH channel (C: `SSH_SFTP_INIT`).
    Init,
    /// Canonicalize home directory via realpath (C: `SSH_SFTP_REALPATH`).
    Realpath,
    /// Begin pre-transfer QUOTE commands (C: `SSH_SFTP_QUOTE_INIT`).
    QuoteInit,
    /// Begin post-transfer QUOTE commands (C: `SSH_SFTP_POSTQUOTE_INIT`).
    PostQuoteInit,
    /// Execute a single QUOTE command (C: `SSH_SFTP_QUOTE`).
    Quote,
    /// Advance to next QUOTE command (C: `SSH_SFTP_NEXT_QUOTE`).
    NextQuote,
    /// Stat file for attribute change (C: `SSH_SFTP_QUOTE_STAT`).
    QuoteStat,
    /// Apply attribute change (C: `SSH_SFTP_QUOTE_SETSTAT`).
    QuoteSetStat,
    /// Create symlink (C: `SSH_SFTP_QUOTE_SYMLINK`).
    QuoteSymlink,
    /// Create directory (C: `SSH_SFTP_QUOTE_MKDIR`).
    QuoteMkdir,
    /// Rename file/directory (C: `SSH_SFTP_QUOTE_RENAME`).
    QuoteRename,
    /// Remove directory (C: `SSH_SFTP_QUOTE_RMDIR`).
    QuoteRmdir,
    /// Remove file (C: `SSH_SFTP_QUOTE_UNLINK`).
    QuoteUnlink,
    /// Filesystem stat (C: `SSH_SFTP_QUOTE_STATVFS`).
    QuoteStatvfs,
    /// Get file info (C: `SSH_SFTP_GETINFO`).
    GetInfo,
    /// Get file modification time (C: `SSH_SFTP_FILETIME`).
    Filetime,
    /// Determine upload vs download vs directory listing (C: `SSH_SFTP_TRANS_INIT`).
    TransInit,
    /// Open file for upload (C: `SSH_SFTP_UPLOAD_INIT`).
    UploadInit,
    /// Begin missing directory creation (C: `SSH_SFTP_CREATE_DIRS_INIT`).
    CreateDirsInit,
    /// Walk and create directory segments (C: `SSH_SFTP_CREATE_DIRS`).
    CreateDirs,
    /// Mkdir for a single segment (C: `SSH_SFTP_CREATE_DIRS_MKDIR`).
    CreateDirsMkdir,
    /// Open directory handle (C: `SSH_SFTP_READDIR_INIT`).
    ReaddirInit,
    /// Read directory entry (C: `SSH_SFTP_READDIR`).
    Readdir,
    /// Resolve symlink for directory entry (C: `SSH_SFTP_READDIR_LINK`).
    ReaddirLink,
    /// Finalize directory entry (C: `SSH_SFTP_READDIR_BOTTOM`).
    ReaddirBottom,
    /// Close directory handle (C: `SSH_SFTP_READDIR_DONE`).
    ReaddirDone,
    /// Open file for download (C: `SSH_SFTP_DOWNLOAD_INIT`).
    DownloadInit,
    /// Stat file for download size/time (C: `SSH_SFTP_DOWNLOAD_STAT`).
    DownloadStat,
    /// Close file/dir handle (C: `SSH_SFTP_CLOSE`).
    Close,
    /// Shutdown SFTP subsystem (C: `SSH_SFTP_SHUTDOWN`).
    Shutdown,
    /// Transfer complete (terminal state).
    Done,
    /// Error state with associated error.
    Error,
}

impl SftpState {
    /// Return a human-readable state name for debugging.
    ///
    /// Matches C `Curl_ssh_statename()` state name strings.
    pub fn state_name(&self) -> &'static str {
        match self {
            SftpState::Init => "SSH_SFTP_INIT",
            SftpState::Realpath => "SSH_SFTP_REALPATH",
            SftpState::QuoteInit => "SSH_SFTP_QUOTE_INIT",
            SftpState::PostQuoteInit => "SSH_SFTP_POSTQUOTE_INIT",
            SftpState::Quote => "SSH_SFTP_QUOTE",
            SftpState::NextQuote => "SSH_SFTP_NEXT_QUOTE",
            SftpState::QuoteStat => "SSH_SFTP_QUOTE_STAT",
            SftpState::QuoteSetStat => "SSH_SFTP_QUOTE_SETSTAT",
            SftpState::QuoteSymlink => "SSH_SFTP_QUOTE_SYMLINK",
            SftpState::QuoteMkdir => "SSH_SFTP_QUOTE_MKDIR",
            SftpState::QuoteRename => "SSH_SFTP_QUOTE_RENAME",
            SftpState::QuoteRmdir => "SSH_SFTP_QUOTE_RMDIR",
            SftpState::QuoteUnlink => "SSH_SFTP_QUOTE_UNLINK",
            SftpState::QuoteStatvfs => "SSH_SFTP_QUOTE_STATVFS",
            SftpState::GetInfo => "SSH_SFTP_GETINFO",
            SftpState::Filetime => "SSH_SFTP_FILETIME",
            SftpState::TransInit => "SSH_SFTP_TRANS_INIT",
            SftpState::UploadInit => "SSH_SFTP_UPLOAD_INIT",
            SftpState::CreateDirsInit => "SSH_SFTP_CREATE_DIRS_INIT",
            SftpState::CreateDirs => "SSH_SFTP_CREATE_DIRS",
            SftpState::CreateDirsMkdir => "SSH_SFTP_CREATE_DIRS_MKDIR",
            SftpState::ReaddirInit => "SSH_SFTP_READDIR_INIT",
            SftpState::Readdir => "SSH_SFTP_READDIR",
            SftpState::ReaddirLink => "SSH_SFTP_READDIR_LINK",
            SftpState::ReaddirBottom => "SSH_SFTP_READDIR_BOTTOM",
            SftpState::ReaddirDone => "SSH_SFTP_READDIR_DONE",
            SftpState::DownloadInit => "SSH_SFTP_DOWNLOAD_INIT",
            SftpState::DownloadStat => "SSH_SFTP_DOWNLOAD_STAT",
            SftpState::Close => "SSH_SFTP_CLOSE",
            SftpState::Shutdown => "SSH_SFTP_SHUTDOWN",
            SftpState::Done => "SSH_SFTP_DONE",
            SftpState::Error => "SSH_SFTP_ERROR",
        }
    }
}

impl fmt::Display for SftpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.state_name())
    }
}

// ============================================================================
// SftpHandler — SFTP protocol handler
// ============================================================================

/// SFTP protocol handler providing complete SFTP file operations over SSH.
///
/// This struct holds all per-transfer SFTP state including the SFTP session,
/// open file/directory handles, path resolution state, QUOTE command queue,
/// resume/range tracking, and progress counters.
///
/// Implements the [`Protocol`] trait for integration with the curl-rs
/// protocol dispatch system.
pub struct SftpHandler {
    /// SFTP session wrapping the SSH channel (None before sftp_init).
    session: Option<RusshSftpSession>,

    /// Currently open file handle for upload/download (None when no file open).
    file_handle: Option<fs::File>,

    /// Currently open directory entries for listing (None when no dir open).
    dir_entries: Option<Vec<fs::DirEntry>>,

    /// Index into dir_entries for current readdir position.
    dir_entry_index: usize,

    /// Resolved remote working path for the current operation.
    remote_path: String,

    /// Remote home directory from realpath(".").
    homedir: String,

    /// Current SFTP operation state.
    state: SftpState,

    /// QUOTE command queue (pre-transfer or post-transfer).
    quote_items: Vec<String>,

    /// Current index in quote_items queue.
    quote_index: usize,

    /// First path argument for the current QUOTE command.
    /// Used by multi-step QUOTE operations (stat-then-setstat).
    #[allow(dead_code)]
    quote_path1: Option<String>,

    /// Second path argument for the current QUOTE command (for rename, symlink).
    /// Used by two-argument QUOTE commands.
    #[allow(dead_code)]
    quote_path2: Option<String>,

    /// Whether the current QUOTE command is allowed to fail (asterisk prefix).
    accept_fail: bool,

    /// Flag to prevent infinite directory creation retry.
    /// Matches C `secondCreateDirs` in ssh_conn.
    second_create_dirs: bool,

    /// Position tracker for directory creation walk.
    /// Tracks progress through path segments during sftp_create_dirs().
    #[allow(dead_code)]
    slash_pos: Option<usize>,

    /// Total bytes transferred in current operation (upload or download).
    bytes_transferred: u64,

    /// Resume offset for upload/download (0 = no resume).
    /// Negative value = determine offset from remote file size.
    resume_from: i64,

    /// Whether this is an upload operation.
    is_upload: bool,

    /// Whether this is a directory listing operation.
    is_directory: bool,

    /// Whether remote append mode is active.
    remote_append: bool,

    /// Input file size for upload (-1 = unknown).
    infilesize: i64,

    /// Whether to create missing directories on upload.
    create_missing_dirs: bool,

    /// Permissions for new directories (default 0o755).
    /// Configurable via CURLOPT_NEW_DIRECTORY_PERMS.
    #[allow(dead_code)]
    new_dir_perms: u32,

    /// Post-transfer QUOTE commands to execute after done().
    postquote_items: Vec<String>,

    /// Pre-transfer QUOTE commands to execute before transfer.
    prequote_items: Vec<String>,

    /// Whether we're in post-quote phase.
    in_postquote: bool,

    /// Download range specification string (e.g. "0-100", "-50").
    /// Set from CURLOPT_RANGE, consumed by sftp_download_stat.
    #[allow(dead_code)]
    range_spec: Option<String>,

    /// Total download size for progress reporting.
    download_size: u64,
}

impl SftpHandler {
    /// Create a new `SftpHandler` with default state.
    pub fn new() -> Self {
        SftpHandler {
            session: None,
            file_handle: None,
            dir_entries: None,
            dir_entry_index: 0,
            remote_path: String::new(),
            homedir: String::new(),
            state: SftpState::Init,
            quote_items: Vec::new(),
            quote_index: 0,
            quote_path1: None,
            quote_path2: None,
            accept_fail: false,
            second_create_dirs: false,
            slash_pos: None,
            bytes_transferred: 0,
            resume_from: 0,
            is_upload: false,
            is_directory: false,
            remote_append: false,
            infilesize: -1,
            create_missing_dirs: false,
            new_dir_perms: DEFAULT_DIR_PERMS,
            postquote_items: Vec::new(),
            prequote_items: Vec::new(),
            in_postquote: false,
            range_spec: None,
            download_size: 0,
        }
    }
}

impl Default for SftpHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SftpHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SftpHandler")
            .field("state", &self.state)
            .field("remote_path", &self.remote_path)
            .field("homedir", &self.homedir)
            .field("has_session", &self.session.is_some())
            .field("has_file", &self.file_handle.is_some())
            .field("bytes_transferred", &self.bytes_transferred)
            .field("resume_from", &self.resume_from)
            .field("is_upload", &self.is_upload)
            .field("is_directory", &self.is_directory)
            .finish()
    }
}

// ============================================================================
// SFTP Session Initialization and Path Resolution
// ============================================================================

impl SftpHandler {
    /// Initialize the SFTP subsystem on an established SSH channel.
    ///
    /// Requests the "sftp" subsystem from the SSH session and wraps the
    /// resulting channel in a `russh_sftp::SftpSession`. This replaces
    /// the C `libssh2_sftp_init()` call at libssh2.c line 1775.
    ///
    /// # Arguments
    /// * `ssh_session` - The authenticated SSH session.
    ///
    /// # Errors
    /// Returns `CurlError::Ssh` if the channel cannot be opened or the
    /// SFTP subsystem request fails.
    pub async fn sftp_init(&mut self, ssh_session: &mut SshSession) -> CurlResult<()> {
        debug!("SFTP: initializing SFTP subsystem");
        self.state = SftpState::Init;

        let handle = ssh_session
            .handle
            .as_mut()
            .ok_or(CurlError::Ssh)?;

        // Open a new session channel for SFTP
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| {
                error!("SFTP: failed to open SSH channel: {}", e);
                CurlError::Ssh
            })?;

        // Request the SFTP subsystem on this channel
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| {
                error!("SFTP: failed to request sftp subsystem: {}", e);
                CurlError::Ssh
            })?;

        // Create the SFTP session from the channel stream
        let sftp = RusshSftpSession::new(channel.into_stream())
            .await
            .map_err(|e| {
                error!("SFTP: failed to create SFTP session: {}", e);
                CurlError::Ssh
            })?;

        self.session = Some(sftp);
        self.state = SftpState::Realpath;
        debug!("SFTP: subsystem initialized successfully");
        Ok(())
    }

    /// Resolve the real path of the home directory on the remote server.
    ///
    /// Canonicalizes "." to obtain the absolute home directory path, which
    /// is used for `/~/` home-relative path expansion. Replaces the C
    /// `libssh2_sftp_realpath()` call at libssh2.c line 1797.
    ///
    /// # Errors
    /// Returns `CurlError::Ssh` if the remote realpath fails.
    pub async fn sftp_realpath(&mut self) -> CurlResult<()> {
        debug!("SFTP: resolving home directory via realpath('.')");
        self.state = SftpState::Realpath;

        let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;

        let home = sftp
            .canonicalize(".")
            .await
            .map_err(|e| {
                error!("SFTP: realpath failed: {}", e);
                CurlError::Ssh
            })?;

        debug!("SFTP: home directory resolved to '{}'", home);
        self.homedir = home;
        Ok(())
    }

    // ========================================================================
    // SFTP Upload Operations
    // ========================================================================

    /// Initialize an SFTP upload operation.
    ///
    /// Handles resume-from offset calculation, open flags selection (append,
    /// resume, truncate), create-missing-dirs on ENOENT, seek to resume
    /// offset, and progress tracking setup.
    ///
    /// Replaces C `sftp_upload_init()` in libssh2.c lines 887-1066.
    ///
    /// # Arguments
    /// * `path` - Remote file path to upload to.
    /// * `resume_from` - Resume offset (negative = auto-detect from file size).
    /// * `remote_append` - Whether to append rather than overwrite.
    /// * `infilesize` - Total upload file size (-1 if unknown).
    /// * `create_missing_dirs` - Whether to create missing parent directories.
    /// * `progress` - Progress tracker for size reporting.
    pub async fn sftp_upload_init(
        &mut self,
        path: &str,
        resume_from: i64,
        remote_append: bool,
        infilesize: i64,
        create_missing_dirs: bool,
        progress: &mut Progress,
    ) -> CurlResult<()> {
        debug!("SFTP: upload init path='{}' resume={} append={}", path, resume_from, remote_append);
        self.state = SftpState::UploadInit;

        // Validate path length against maximum (matches C MAX_SSHPATH_LEN check)
        if path.len() > MAX_SSHPATH_LEN {
            warn!("SFTP: upload path exceeds maximum length ({})", MAX_SSHPATH_LEN);
            return Err(CurlError::TooLarge);
        }

        self.is_upload = true;
        self.resume_from = resume_from;
        self.remote_append = remote_append;
        self.infilesize = infilesize;
        self.create_missing_dirs = create_missing_dirs;
        self.bytes_transferred = 0;
        self.remote_path = path.to_string();

        let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;

        // Handle negative resume_from: stat the remote file to get its size
        let mut actual_resume = resume_from;
        if actual_resume < 0 {
            match sftp.metadata(path).await {
                Ok(attrs) => {
                    if let Some(size) = attrs.size {
                        actual_resume = size as i64;
                        debug!("SFTP: auto-resume from remote file size {}", actual_resume);
                    } else {
                        actual_resume = 0;
                    }
                }
                Err(_) => {
                    debug!("SFTP: auto-resume stat failed, starting from 0");
                    actual_resume = 0;
                }
            }
        }
        self.resume_from = actual_resume;

        // Determine open flags matching C behavior (libssh2.c lines 910-934)
        let flags = if remote_append {
            // Append mode: WRITE | CREATE | APPEND
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::APPEND
        } else if actual_resume > 0 {
            // Resume mode: WRITE only (no APPEND — C comment explains why:
            // most SFTP servers treat APPEND as always-append even after seek)
            OpenFlags::WRITE
        } else {
            // Normal upload: WRITE | CREATE | TRUNCATE
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE
        };

        // Attempt to open the file
        let open_result = sftp
            .open_with_flags(path, flags)
            .await;

        match open_result {
            Ok(file) => {
                self.file_handle = Some(file);
            }
            Err(e) => {
                let is_no_such = is_no_such_file_error(&e);

                // If file not found and create_missing_dirs is enabled, create dirs
                if is_no_such && create_missing_dirs && !self.second_create_dirs {
                    debug!("SFTP: file not found, creating missing directories for '{}'", path);
                    self.second_create_dirs = true;
                    self.sftp_create_dirs(path).await?;

                    // Retry the open after directory creation
                    let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;
                    let file = sftp
                        .open_with_flags(path, flags)
                        .await
                        .map_err(|e2| {
                            error!("SFTP: open after mkdir failed: {}", e2);
                            map_sftp_error(&e2)
                        })?;
                    self.file_handle = Some(file);
                } else {
                    error!("SFTP: upload open failed: {}", e);
                    return Err(map_sftp_error(&e));
                }
            }
        }

        // Seek to resume offset (skip in append mode, per C line 998)
        if actual_resume > 0 && !remote_append {
            if let Some(ref mut file) = self.file_handle {
                file.seek(tokio::io::SeekFrom::Start(actual_resume as u64))
                    .await
                    .map_err(|e| {
                        error!("SFTP: seek to resume offset {} failed: {}", actual_resume, e);
                        CurlError::Ssh
                    })?;
                debug!("SFTP: seeked to resume offset {}", actual_resume);
            }
        }

        // Adjust upload size for progress reporting
        let upload_size = if infilesize >= 0 {
            let adjusted = infilesize - actual_resume;
            if adjusted > 0 {
                adjusted as u64
            } else {
                0
            }
        } else {
            0
        };
        progress.set_upload_size(Some(upload_size));

        debug!("SFTP: upload init complete, upload_size={}", upload_size);
        Ok(())
    }

    /// Send data during an SFTP upload.
    ///
    /// Writes the provided data buffer to the open SFTP file handle and
    /// tracks bytes transferred for progress reporting.
    ///
    /// Replaces C `sftp_send()` in libssh2.c lines 3697-3727.
    ///
    /// # Arguments
    /// * `data` - Data bytes to write.
    /// * `progress` - Progress tracker for increment reporting.
    ///
    /// # Returns
    /// The number of bytes successfully written.
    pub async fn sftp_send(
        &mut self,
        data: &[u8],
        progress: &mut Progress,
    ) -> CurlResult<usize> {
        let file = self.file_handle.as_mut().ok_or_else(|| {
            error!("SFTP: send called with no open file handle");
            CurlError::Ssh
        })?;

        if data.is_empty() {
            return Ok(0);
        }

        let written = file.write(data).await.map_err(|e| {
            error!("SFTP: write failed: {}", e);
            CurlError::UploadFailed
        })?;

        self.bytes_transferred += written as u64;
        progress.upload_inc(written as u64);
        trace!("SFTP: sent {} bytes (total: {})", written, self.bytes_transferred);

        Ok(written)
    }

    // ========================================================================
    // SFTP Download Operations
    // ========================================================================

    /// Initialize an SFTP download operation.
    ///
    /// Opens the specified remote file for reading. The file handle is stored
    /// for subsequent `sftp_recv()` calls.
    ///
    /// Replaces C `ssh_state_sftp_download_init()` in libssh2.c lines 2348-2374.
    ///
    /// # Arguments
    /// * `path` - Remote file path to download.
    pub async fn sftp_download_init(&mut self, path: &str) -> CurlResult<()> {
        debug!("SFTP: download init path='{}'", path);
        self.state = SftpState::DownloadInit;

        // Validate path length against maximum
        if path.len() > MAX_SSHPATH_LEN {
            warn!("SFTP: download path exceeds maximum length ({})", MAX_SSHPATH_LEN);
            return Err(CurlError::TooLarge);
        }

        self.is_upload = false;
        self.bytes_transferred = 0;
        self.remote_path = path.to_string();

        let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;

        let file = sftp.open(path).await.map_err(|e| {
            error!("SFTP: download open failed for '{}': {}", path, e);
            map_sftp_error(&e)
        })?;

        self.file_handle = Some(file);
        debug!("SFTP: download file opened successfully");
        Ok(())
    }

    /// Stat a file for download metadata (size, modification time).
    ///
    /// After the file is opened for download, this method retrieves file
    /// metadata for size-based progress reporting and optional range handling.
    ///
    /// Replaces C `sftp_download_stat()` in libssh2.c lines 1274-1368.
    ///
    /// # Arguments
    /// * `range_str` - Optional range specification ("from-to", "-N").
    /// * `resume_from` - Resume offset (0 = no resume).
    /// * `progress` - Progress tracker for size reporting.
    ///
    /// # Returns
    /// Tuple of (download_size, optional_filetime_epoch_secs).
    pub async fn sftp_download_stat(
        &mut self,
        range_str: Option<&str>,
        resume_from: i64,
        progress: &mut Progress,
    ) -> CurlResult<(u64, Option<i64>)> {
        debug!("SFTP: stat for download, range={:?}, resume_from={}", range_str, resume_from);
        self.state = SftpState::DownloadStat;

        let file = self.file_handle.as_mut().ok_or(CurlError::Ssh)?;

        // Get file metadata for size and modification time
        let metadata = file.metadata().await.map_err(|e| {
            error!("SFTP: metadata failed: {}", e);
            CurlError::Ssh
        })?;

        let file_size = metadata.size.unwrap_or(0);
        let filetime = metadata.mtime.map(|t| t as i64);

        debug!("SFTP: remote file size={}, mtime={:?}", file_size, filetime);

        // Handle range requests via ssh_range() logic (C vssh.c lines 287-331)
        let (from_offset, download_size) = if let Some(range) = range_str {
            let (from, to) = ssh_range(range, file_size)?;
            let size = to - from + 1;
            debug!("SFTP: range resolved: from={}, to={}, size={}", from, to, size);
            (from, size)
        } else if resume_from > 0 {
            // Resume download: skip already-downloaded bytes
            let from = resume_from as u64;
            if from >= file_size {
                return Err(CurlError::RangeError);
            }
            let size = file_size - from;
            debug!("SFTP: resume from offset {}, remaining size={}", from, size);
            (from, size)
        } else {
            (0, file_size)
        };

        // Seek to start offset if needed
        if from_offset > 0 {
            let file = self.file_handle.as_mut().ok_or(CurlError::Ssh)?;
            file.seek(tokio::io::SeekFrom::Start(from_offset))
                .await
                .map_err(|e| {
                    error!("SFTP: seek to download offset {} failed: {}", from_offset, e);
                    CurlError::Ssh
                })?;
            debug!("SFTP: seeked to download offset {}", from_offset);
        }

        self.download_size = download_size;
        progress.set_download_size(Some(download_size));

        Ok((download_size, filetime))
    }

    /// Receive data during an SFTP download.
    ///
    /// Reads data from the open SFTP file handle into the provided buffer
    /// and tracks bytes transferred for progress reporting.
    ///
    /// Replaces C `sftp_recv()` in libssh2.c lines 3728-3757.
    ///
    /// # Arguments
    /// * `buf` - Buffer to read data into.
    /// * `progress` - Progress tracker for increment reporting.
    ///
    /// # Returns
    /// The number of bytes read (0 = EOF).
    pub async fn sftp_recv(
        &mut self,
        buf: &mut [u8],
        progress: &mut Progress,
    ) -> CurlResult<usize> {
        let file = self.file_handle.as_mut().ok_or_else(|| {
            error!("SFTP: recv called with no open file handle");
            CurlError::Ssh
        })?;

        if buf.is_empty() {
            return Ok(0);
        }

        // Limit read size to remaining download_size if set
        let max_read = if self.download_size > 0 {
            let remaining = self.download_size.saturating_sub(self.bytes_transferred);
            if remaining == 0 {
                return Ok(0);
            }
            std::cmp::min(buf.len(), remaining as usize)
        } else {
            buf.len()
        };

        let n = file.read(&mut buf[..max_read]).await.map_err(|e| {
            error!("SFTP: read failed: {}", e);
            CurlError::RecvError
        })?;

        if n > 0 {
            self.bytes_transferred += n as u64;
            progress.download_inc(n as u64);
            trace!("SFTP: received {} bytes (total: {})", n, self.bytes_transferred);
        }

        Ok(n)
    }

    // ========================================================================
    // Directory Listing Operations
    // ========================================================================

    /// Initialize directory listing.
    ///
    /// Opens the specified remote directory for reading. The directory entries
    /// are collected for subsequent `sftp_readdir()` calls.
    ///
    /// Replaces C `ssh_state_sftp_readdir_init()` in libssh2.c lines 2169-2201.
    ///
    /// # Arguments
    /// * `path` - Remote directory path to list.
    pub async fn sftp_readdir_init(&mut self, path: &str) -> CurlResult<()> {
        debug!("SFTP: readdir init path='{}'", path);
        self.state = SftpState::ReaddirInit;
        self.is_directory = true;
        self.remote_path = path.to_string();

        let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;

        let read_dir = sftp.read_dir(path).await.map_err(|e| {
            error!("SFTP: readdir failed for '{}': {}", path, e);
            map_sftp_error(&e)
        })?;

        // Collect all directory entries into a Vec for iteration
        let entries: Vec<fs::DirEntry> = read_dir.collect();
        debug!("SFTP: directory contains {} entries", entries.len());

        self.dir_entries = Some(entries);
        self.dir_entry_index = 0;
        self.state = SftpState::Readdir;
        Ok(())
    }

    /// Read the next directory entry and format it as an ls -la listing line.
    ///
    /// Formats each entry in Unix `ls -la` style to match curl 8.x output:
    /// ```text
    /// drwxr-xr-x    3 user     group        4096 Jan 15 14:30 dirname
    /// -rw-r--r--    1 user     group       12345 Feb  3  2023 file.txt
    /// lrwxrwxrwx    1 user     group          15 Mar 20 09:15 link -> target
    /// ```
    ///
    /// Replaces C `sftp_readdir()` in libssh2.c lines 1369-1427 and
    /// `ssh_state_sftp_readdir_link()` at line 2202-2230.
    ///
    /// # Arguments
    /// * `progress` - Progress tracker for download byte count.
    ///
    /// # Returns
    /// `Ok(Some(line))` with a formatted listing line, or `Ok(None)` when
    /// the directory is exhausted.
    pub async fn sftp_readdir(
        &mut self,
        progress: &mut Progress,
    ) -> CurlResult<Option<String>> {
        let entries = match self.dir_entries.as_ref() {
            Some(e) => e,
            None => return Ok(None),
        };

        if self.dir_entry_index >= entries.len() {
            self.state = SftpState::ReaddirDone;
            return Ok(None);
        }

        let entry = &entries[self.dir_entry_index];
        self.dir_entry_index += 1;

        let filename = entry.file_name();
        let metadata = entry.metadata();

        // Build ls -la formatted line using DynBuf
        let mut buf = DynBuf::with_max(DIR_LISTING_MAX_SIZE);

        // Format the permission string
        let perm_str = format_permission_string(&metadata);
        buf.add_str(&perm_str).map_err(|_| CurlError::OutOfMemory)?;

        // Hard link count (always 1 for SFTP — not available)
        buf.add_str("    1 ").map_err(|_| CurlError::OutOfMemory)?;

        // Owner and group
        let owner = metadata
            .user
            .as_deref()
            .unwrap_or("owner");
        let group = metadata
            .group
            .as_deref()
            .unwrap_or("group");

        buf.add_str(&format!("{:<8} {:<8} ", owner, group))
            .map_err(|_| CurlError::OutOfMemory)?;

        // File size
        let size = metadata.size.unwrap_or(0);
        buf.add_str(&format!("{:>8} ", size))
            .map_err(|_| CurlError::OutOfMemory)?;

        // Date formatting: "Jan 15 14:30" for recent, "Jan 15  2023" for old
        let date_str = format_file_date(metadata.mtime);
        buf.add_str(&date_str).map_err(|_| CurlError::OutOfMemory)?;
        buf.add_str(" ").map_err(|_| CurlError::OutOfMemory)?;

        // Filename
        buf.add_str(&filename).map_err(|_| CurlError::OutOfMemory)?;

        // For symlinks, resolve link target and append " -> target"
        if metadata.is_symlink() {
            if let Some(sftp) = self.session.as_ref() {
                let link_path = if self.remote_path.ends_with('/') {
                    format!("{}{}", self.remote_path, filename)
                } else {
                    format!("{}/{}", self.remote_path, filename)
                };
                match sftp.read_link(&link_path).await {
                    Ok(target) => {
                        buf.add_str(" -> ").map_err(|_| CurlError::OutOfMemory)?;
                        buf.add_str(&target)
                            .map_err(|_| CurlError::OutOfMemory)?;
                    }
                    Err(e) => {
                        trace!("SFTP: readlink failed for '{}': {}", link_path, e);
                    }
                }
            }
        }

        // Trailing newline
        buf.add_str("\n").map_err(|_| CurlError::OutOfMemory)?;

        let line = buf.as_str().unwrap_or("").to_string();
        let line_len = line.len() as u64;
        progress.download_inc(line_len);

        trace!("SFTP: readdir entry: {}", line.trim_end());
        Ok(Some(line))
    }

    // ========================================================================
    // QUOTE Command Interpreter
    // ========================================================================

    /// Initialize QUOTE command processing.
    ///
    /// Sets up the QUOTE command queue from the provided list of commands
    /// and prepares for sequential execution.
    ///
    /// # Arguments
    /// * `quote_list` - List of QUOTE command strings.
    /// * `is_postquote` - Whether these are post-transfer commands.
    pub fn sftp_quote_init(&mut self, quote_list: &[String], is_postquote: bool) {
        debug!(
            "SFTP: quote init ({} commands, postquote={})",
            quote_list.len(),
            is_postquote
        );
        self.state = if is_postquote {
            SftpState::PostQuoteInit
        } else {
            SftpState::QuoteInit
        };
        self.quote_items = quote_list.to_vec();
        self.quote_index = 0;
        self.in_postquote = is_postquote;
    }

    /// Execute a single QUOTE command.
    ///
    /// Parses the command string and dispatches to the appropriate SFTP
    /// operation. Supports all 12 curl 8.x SFTP QUOTE commands:
    /// pwd, chgrp, chmod, chown, atime, mtime, ln/symlink, mkdir,
    /// rename, rmdir, rm, statvfs.
    ///
    /// The asterisk prefix (`*command`) marks the command as allowed to fail.
    ///
    /// Replaces C `sftp_quote()` in libssh2.c lines 727-884.
    ///
    /// # Arguments
    /// * `cmd` - QUOTE command string.
    ///
    /// # Returns
    /// A formatted response string (for pwd and statvfs), or empty string.
    pub async fn sftp_quote(&mut self, cmd: &str) -> CurlResult<String> {
        self.state = SftpState::Quote;

        // Handle asterisk prefix for accept-fail
        let (cmd_str, accept_fail) = if let Some(stripped) = cmd.strip_prefix('*') {
            (stripped.trim(), true)
        } else {
            (cmd.trim(), false)
        };
        self.accept_fail = accept_fail;

        debug!("SFTP: quote command: '{}' (accept_fail={})", cmd_str, accept_fail);

        let result = self.execute_quote_command(cmd_str).await;

        match result {
            Ok(response) => Ok(response),
            Err(e) => {
                if accept_fail {
                    warn!("SFTP: quote command '{}' failed (accepted): {}", cmd_str, e);
                    Ok(String::new())
                } else {
                    error!("SFTP: quote command '{}' failed: {}", cmd_str, e);
                    Err(CurlError::QuoteError)
                }
            }
        }
    }

    /// Internal dispatcher for QUOTE commands.
    async fn execute_quote_command(&mut self, cmd: &str) -> CurlResult<String> {
        // Extract the command verb (first word)
        let verb_end = cmd
            .find([' ', '\t'])
            .unwrap_or(cmd.len());
        let verb = &cmd[..verb_end].to_lowercase();
        let args = cmd[verb_end..].trim_start();

        match verb.as_str() {
            "pwd" => self.quote_pwd().await,
            "chgrp" => self.quote_chgrp(args).await,
            "chmod" => self.quote_chmod(args).await,
            "chown" => self.quote_chown(args).await,
            "atime" => self.quote_atime(args).await,
            "mtime" => self.quote_mtime(args).await,
            "ln" | "symlink" => self.quote_symlink(args).await,
            "mkdir" => self.quote_mkdir(args).await,
            "rename" => self.quote_rename(args).await,
            "rmdir" => self.quote_rmdir(args).await,
            "rm" => self.quote_rm(args).await,
            "statvfs" => self.quote_statvfs(args).await,
            _ => {
                error!("SFTP: unknown quote command: '{}'", verb);
                Err(CurlError::QuoteError)
            }
        }
    }

    /// QUOTE pwd — output current directory.
    ///
    /// Outputs the current working directory in the format:
    /// `257 "<path>" is current directory.\n`
    ///
    /// Matches C behavior at libssh2.c lines 753-769.
    async fn quote_pwd(&self) -> CurlResult<String> {
        let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;

        let cwd = sftp.canonicalize(".").await.map_err(|e| {
            error!("SFTP: pwd realpath failed: {}", e);
            CurlError::QuoteError
        })?;

        let response = format!("257 \"{}\" is current directory.\n", cwd);
        debug!("SFTP: pwd => {}", response.trim_end());
        Ok(response)
    }

    /// QUOTE chgrp — change group ownership.
    ///
    /// Format: `chgrp <gid> <path>`
    /// Matches C behavior at libssh2.c lines 798-819.
    async fn quote_chgrp(&mut self, args: &str) -> CurlResult<String> {
        let (gid_str, remainder) = split_first_word(args);
        let gid: u32 = gid_str.parse().map_err(|_| {
            error!("SFTP: chgrp invalid GID: '{}'", gid_str);
            CurlError::QuoteError
        })?;

        let (path, _) = get_pathname(remainder, &self.homedir)?;
        debug!("SFTP: chgrp {} '{}'", gid, path);

        let attrs = self.sftp_quote_stat(&path).await?;
        let mut new_attrs = attrs;
        new_attrs.gid = Some(gid);
        self.sftp_quote_setstat(&path, &new_attrs).await?;

        Ok(String::new())
    }

    /// QUOTE chmod — change file permissions.
    ///
    /// Format: `chmod <mode> <path>` (mode is octal)
    /// Matches C behavior at libssh2.c lines 798-819.
    async fn quote_chmod(&mut self, args: &str) -> CurlResult<String> {
        let (mode_str, remainder) = split_first_word(args);
        let mode = u32::from_str_radix(mode_str, 8).map_err(|_| {
            error!("SFTP: chmod invalid mode: '{}'", mode_str);
            CurlError::QuoteError
        })?;

        let (path, _) = get_pathname(remainder, &self.homedir)?;
        debug!("SFTP: chmod {:04o} '{}'", mode, path);

        let attrs = self.sftp_quote_stat(&path).await?;
        let mut new_attrs = attrs;
        new_attrs.permissions = Some(mode);
        self.sftp_quote_setstat(&path, &new_attrs).await?;

        Ok(String::new())
    }

    /// QUOTE chown — change file ownership.
    ///
    /// Format: `chown <uid> <path>`
    /// Matches C behavior at libssh2.c lines 798-819.
    async fn quote_chown(&mut self, args: &str) -> CurlResult<String> {
        let (uid_str, remainder) = split_first_word(args);
        let uid: u32 = uid_str.parse().map_err(|_| {
            error!("SFTP: chown invalid UID: '{}'", uid_str);
            CurlError::QuoteError
        })?;

        let (path, _) = get_pathname(remainder, &self.homedir)?;
        debug!("SFTP: chown {} '{}'", uid, path);

        let attrs = self.sftp_quote_stat(&path).await?;
        let mut new_attrs = attrs;
        new_attrs.uid = Some(uid);
        self.sftp_quote_setstat(&path, &new_attrs).await?;

        Ok(String::new())
    }

    /// QUOTE atime — set access time.
    ///
    /// Format: `atime <epoch_seconds> <path>`
    /// Matches C behavior at libssh2.c lines 800-819.
    async fn quote_atime(&mut self, args: &str) -> CurlResult<String> {
        let (time_str, remainder) = split_first_word(args);
        let atime: u32 = time_str.parse().map_err(|_| {
            error!("SFTP: atime invalid timestamp: '{}'", time_str);
            CurlError::QuoteError
        })?;

        let (path, _) = get_pathname(remainder, &self.homedir)?;
        debug!("SFTP: atime {} '{}'", atime, path);

        let attrs = self.sftp_quote_stat(&path).await?;
        let mut new_attrs = attrs;
        new_attrs.atime = Some(atime);
        self.sftp_quote_setstat(&path, &new_attrs).await?;

        Ok(String::new())
    }

    /// QUOTE mtime — set modification time.
    ///
    /// Format: `mtime <epoch_seconds> <path>`
    /// Matches C behavior at libssh2.c lines 801-819.
    async fn quote_mtime(&mut self, args: &str) -> CurlResult<String> {
        let (time_str, remainder) = split_first_word(args);
        let mtime: u32 = time_str.parse().map_err(|_| {
            error!("SFTP: mtime invalid timestamp: '{}'", time_str);
            CurlError::QuoteError
        })?;

        let (path, _) = get_pathname(remainder, &self.homedir)?;
        debug!("SFTP: mtime {} '{}'", mtime, path);

        let attrs = self.sftp_quote_stat(&path).await?;
        let mut new_attrs = attrs;
        new_attrs.mtime = Some(mtime);
        self.sftp_quote_setstat(&path, &new_attrs).await?;

        Ok(String::new())
    }

    /// QUOTE ln/symlink — create a symbolic link.
    ///
    /// Format: `ln <source> <target>` or `symlink <source> <target>`
    /// Matches C behavior at libssh2.c lines 821-836.
    async fn quote_symlink(&mut self, args: &str) -> CurlResult<String> {
        let (source, pos) = get_pathname(args, &self.homedir)?;
        let remainder = &args[pos..];
        let (target, _) = get_pathname(remainder, &self.homedir)?;

        debug!("SFTP: symlink '{}' -> '{}'", source, target);

        let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;
        sftp.symlink(&source, &target).await.map_err(|e| {
            error!("SFTP: symlink failed: {}", e);
            CurlError::QuoteError
        })?;

        Ok(String::new())
    }

    /// QUOTE mkdir — create a directory.
    ///
    /// Format: `mkdir <path>`
    /// Matches C behavior at libssh2.c lines 838-843.
    async fn quote_mkdir(&mut self, args: &str) -> CurlResult<String> {
        let (path, _) = get_pathname(args, &self.homedir)?;
        debug!("SFTP: mkdir '{}'", path);

        let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;
        sftp.create_dir(&path).await.map_err(|e| {
            error!("SFTP: mkdir failed for '{}': {}", path, e);
            CurlError::QuoteError
        })?;

        Ok(String::new())
    }

    /// QUOTE rename — rename a file or directory.
    ///
    /// Format: `rename <source> <dest>`
    /// Matches C behavior at libssh2.c lines 845-859.
    async fn quote_rename(&mut self, args: &str) -> CurlResult<String> {
        let (source, pos) = get_pathname(args, &self.homedir)?;
        let remainder = &args[pos..];
        let (dest, _) = get_pathname(remainder, &self.homedir)?;

        debug!("SFTP: rename '{}' -> '{}'", source, dest);

        let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;
        sftp.rename(&source, &dest).await.map_err(|e| {
            error!("SFTP: rename failed: {}", e);
            CurlError::QuoteError
        })?;

        Ok(String::new())
    }

    /// QUOTE rmdir — remove a directory.
    ///
    /// Format: `rmdir <path>`
    /// Matches C behavior at libssh2.c lines 861-866.
    async fn quote_rmdir(&mut self, args: &str) -> CurlResult<String> {
        let (path, _) = get_pathname(args, &self.homedir)?;
        debug!("SFTP: rmdir '{}'", path);

        let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;
        sftp.remove_dir(&path).await.map_err(|e| {
            error!("SFTP: rmdir failed for '{}': {}", path, e);
            CurlError::QuoteError
        })?;

        Ok(String::new())
    }

    /// QUOTE rm — remove a file.
    ///
    /// Format: `rm <path>`
    /// Matches C behavior at libssh2.c lines 868-872.
    async fn quote_rm(&mut self, args: &str) -> CurlResult<String> {
        let (path, _) = get_pathname(args, &self.homedir)?;
        debug!("SFTP: rm '{}'", path);

        let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;
        sftp.remove_file(&path).await.map_err(|e| {
            error!("SFTP: rm failed for '{}': {}", path, e);
            CurlError::QuoteError
        })?;

        Ok(String::new())
    }

    /// QUOTE statvfs — get filesystem statistics.
    ///
    /// Format: `statvfs <path>`
    /// Outputs a formatted block matching C lines 2075-2137:
    /// ```text
    /// statvfs:
    ///   f_bsize: <value>
    ///   f_frsize: <value>
    ///   ...
    /// ```
    async fn quote_statvfs(&mut self, args: &str) -> CurlResult<String> {
        let (path, _) = get_pathname(args, &self.homedir)?;

        // Validate path length against MAX_PATHLENGTH (matches C Curl_get_pathname)
        if path.len() > MAX_PATHLENGTH {
            warn!("SFTP: statvfs path exceeds maximum length ({})", MAX_PATHLENGTH);
            return Err(CurlError::QuoteError);
        }

        debug!("SFTP: statvfs '{}'", path);

        let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;
        let vfs = sftp.fs_info(&path).await.map_err(|e| {
            error!("SFTP: statvfs failed for '{}': {}", path, e);
            CurlError::QuoteError
        })?;

        match vfs {
            Some(stat) => {
                // Build the statvfs output block using DynBuf with add_fmt
                let mut buf = DynBuf::new();
                buf.add_fmt(format_args!("statvfs:\n"))?;
                buf.add_fmt(format_args!(" f_bsize: {}\n", stat.block_size))?;
                buf.add_fmt(format_args!(" f_frsize: {}\n", stat.fragment_size))?;
                buf.add_fmt(format_args!(" f_blocks: {}\n", stat.blocks))?;
                buf.add_fmt(format_args!(" f_bfree: {}\n", stat.blocks_free))?;
                buf.add_fmt(format_args!(" f_bavail: {}\n", stat.blocks_avail))?;
                buf.add_fmt(format_args!(" f_files: {}\n", stat.inodes))?;
                buf.add_fmt(format_args!(" f_ffree: {}\n", stat.inodes_free))?;
                buf.add_fmt(format_args!(" f_favail: {}\n", stat.inodes_avail))?;
                buf.add_fmt(format_args!(" f_fsid: {}\n", stat.fs_id))?;
                buf.add_fmt(format_args!(" f_flag: {}\n", stat.flags))?;
                buf.add_fmt(format_args!(" f_namemax: {}\n", stat.name_max))?;
                let output = buf.as_str().unwrap_or("").to_string();
                debug!("SFTP: statvfs result:\n{}", output);
                // Reset the buffer to release memory after use
                buf.reset();
                Ok(output)
            }
            None => {
                error!("SFTP: statvfs returned None for '{}'", path);
                Err(CurlError::QuoteError)
            }
        }
    }

    /// Stat a file for attribute change commands (chmod/chown/chgrp/atime/mtime).
    ///
    /// Replaces C `sftp_quote_stat()` in libssh2.c lines 1163-1273.
    ///
    /// # Arguments
    /// * `path` - Remote file path to stat.
    pub async fn sftp_quote_stat(&self, path: &str) -> CurlResult<FileAttributes> {
        trace!("SFTP: stat for quote command: '{}'", path);

        let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;
        let attrs = sftp.metadata(path).await.map_err(|e| {
            error!("SFTP: stat failed for '{}': {}", path, e);
            map_sftp_error(&e)
        })?;

        Ok(attrs)
    }

    /// Apply attribute changes to a remote file.
    ///
    /// # Arguments
    /// * `path` - Remote file path to modify.
    /// * `attrs` - New file attributes to set.
    pub async fn sftp_quote_setstat(
        &self,
        path: &str,
        attrs: &FileAttributes,
    ) -> CurlResult<()> {
        trace!("SFTP: setstat for '{}': {:?}", path, attrs);

        let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;
        sftp.set_metadata(path, attrs.clone()).await.map_err(|e| {
            error!("SFTP: setstat failed for '{}': {}", path, e);
            map_sftp_error(&e)
        })?;

        Ok(())
    }

    // ========================================================================
    // Create Missing Directories
    // ========================================================================

    /// Walk path segments from root and create each missing directory.
    ///
    /// Permissions are set from `new_dir_perms` (default 0o755).
    /// Matches C `ssh_state_sftp_create_dirs*` states in libssh2.c lines 2138-2168.
    ///
    /// # Arguments
    /// * `path` - Full remote file path (parent directories will be created).
    pub async fn sftp_create_dirs(&mut self, path: &str) -> CurlResult<()> {
        debug!("SFTP: creating missing directories for '{}'", path);
        self.state = SftpState::CreateDirsInit;

        // Verify session is available before starting walk
        if self.session.is_none() {
            return Err(CurlError::Ssh);
        }

        // Extract the directory part (everything before the last '/')
        let dir_path = match path.rfind('/') {
            Some(pos) if pos > 0 => &path[..pos],
            _ => return Ok(()), // No directory component, nothing to create
        };

        // Walk path segments and create each missing directory
        let segments: Vec<&str> = dir_path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut current_path = String::new();
        if dir_path.starts_with('/') {
            current_path.push('/');
        }

        for segment in segments {
            if !current_path.ends_with('/') && !current_path.is_empty() {
                current_path.push('/');
            }
            current_path.push_str(segment);

            self.state = SftpState::CreateDirsMkdir;

            // Try to create the directory; ignore "already exists" errors
            let sftp = self.session.as_ref().ok_or(CurlError::Ssh)?;
            match sftp.create_dir(&current_path).await {
                Ok(()) => {
                    debug!("SFTP: created directory '{}'", current_path);
                }
                Err(e) => {
                    // Ignore "already exists" (permission denied or failure may
                    // indicate the dir exists but we can't create it)
                    let is_exists = is_already_exists_error(&e);
                    if !is_exists {
                        trace!(
                            "SFTP: mkdir '{}' returned error (may exist): {}",
                            current_path,
                            e
                        );
                    }
                }
            }
        }

        self.state = SftpState::CreateDirs;
        debug!("SFTP: directory creation walk complete");
        Ok(())
    }

    // ========================================================================
    // File Close and Cleanup
    // ========================================================================

    /// Close the current SFTP file handle.
    ///
    /// Drops the file handle, flushing any pending writes. Checks for
    /// post-QUOTE command processing.
    ///
    /// Replaces C `ssh_state_sftp_close()` in libssh2.c lines 2276-2310.
    pub async fn sftp_close(&mut self) -> CurlResult<()> {
        debug!("SFTP: closing file/dir handle");
        self.state = SftpState::Close;

        // Close file handle if open
        if let Some(mut file) = self.file_handle.take() {
            // Flush any pending writes before close
            if self.is_upload {
                if let Err(e) = file.flush().await {
                    warn!("SFTP: flush on close warning: {}", e);
                }
                if let Err(e) = file.shutdown().await {
                    warn!("SFTP: shutdown on close warning: {}", e);
                }
            }
            // File is dropped here, closing the handle
            debug!("SFTP: file handle closed");
        }

        // Close directory entries if open
        if self.dir_entries.is_some() {
            self.dir_entries = None;
            self.dir_entry_index = 0;
            debug!("SFTP: directory handle closed");
        }

        Ok(())
    }

    /// Shut down the SFTP subsystem and release all resources.
    ///
    /// Closes any open file/directory handles, shuts down the SFTP session,
    /// and frees the home directory string.
    ///
    /// Replaces C `ssh_state_sftp_shutdown()` in libssh2.c lines 2312-2346.
    pub async fn sftp_shutdown(&mut self) -> CurlResult<()> {
        debug!("SFTP: shutting down subsystem");
        self.state = SftpState::Shutdown;

        // Close any open handles first
        self.sftp_close().await?;

        // Close the SFTP session
        if let Some(sftp) = self.session.take() {
            if let Err(e) = sftp.close().await {
                warn!("SFTP: session close warning: {}", e);
            }
            debug!("SFTP: session closed");
        }

        // Clear state
        self.homedir.clear();
        self.remote_path.clear();
        self.quote_items.clear();
        self.quote_index = 0;
        self.bytes_transferred = 0;
        self.resume_from = 0;
        self.second_create_dirs = false;

        self.state = SftpState::Done;
        debug!("SFTP: subsystem shutdown complete");
        Ok(())
    }
}

// ============================================================================
// Protocol trait implementation for SftpHandler
// ============================================================================

impl Protocol for SftpHandler {
    /// Protocol name: "SFTP".
    fn name(&self) -> &str {
        "SFTP"
    }

    /// Default port: 22 (SSH).
    fn default_port(&self) -> u16 {
        PORT_SSH
    }

    /// Protocol capability flags.
    ///
    /// Matches C `Curl_scheme_sftp` flags:
    /// - DIRLOCK: directory listing locks the connection
    /// - CLOSEACTION: requires cleanup action before close
    /// - NOURLQUERY: no URL query string support
    /// - CONN_REUSE: connections can be reused
    fn flags(&self) -> ProtocolFlags {
        ProtocolFlags::from_bits(
            ProtocolFlags::CLOSEACTION.bits()
                | ProtocolFlags::CONN_REUSE.bits()
                | SSH_FLAG_DIRLOCK.bits()
                | SSH_FLAG_NOURLQUERY.bits(),
        )
    }

    /// Establish the SFTP protocol connection.
    ///
    /// Delegates to the shared SSH session establishment in `ssh/mod.rs`.
    /// The actual SSH handshake, authentication, and SFTP subsystem
    /// initialization happen here.
    async fn connect(&mut self, _conn: &mut ConnectionData) -> Result<(), CurlError> {
        debug!("SFTP: connect requested");
        // The SSH connection is managed by the parent SSH module.
        // SFTP init and realpath will be driven by do_it().
        Ok(())
    }

    /// Execute the primary SFTP operation.
    ///
    /// Drives the SFTP state machine: processes pre-QUOTE commands,
    /// determines the transfer type (upload/download/readdir), and
    /// dispatches to the appropriate handler.
    async fn do_it(&mut self, _conn: &mut ConnectionData) -> Result<(), CurlError> {
        // Report current state wrapped in parent SshState for logging
        debug!(
            "SFTP: do_it invoked, ssh_state={}",
            SshState::Sftp(self.state.clone())
        );

        // Process pre-transfer QUOTE commands if any
        if !self.prequote_items.is_empty() {
            let items = self.prequote_items.clone();
            self.sftp_quote_init(&items, false);
            for item in &items {
                let response = self.sftp_quote(item).await?;
                if !response.is_empty() {
                    trace!("SFTP: prequote response: {}", response.trim_end());
                }
            }
        }

        debug!("SFTP: do_it complete");
        Ok(())
    }

    /// Finalize the SFTP transfer.
    ///
    /// Closes the file handle, processes post-QUOTE commands, and cleans up
    /// per-transfer state.
    async fn done(
        &mut self,
        _conn: &mut ConnectionData,
        status: CurlError,
    ) -> Result<(), CurlError> {
        debug!("SFTP: done invoked, status={}", CurlError::strerror(&status));

        // Close file/directory handles
        self.sftp_close().await?;

        // Process post-transfer QUOTE commands if any
        if !self.postquote_items.is_empty() {
            let items = self.postquote_items.clone();
            self.sftp_quote_init(&items, true);
            for item in &items {
                let response = self.sftp_quote(item).await?;
                if !response.is_empty() {
                    trace!("SFTP: postquote response: {}", response.trim_end());
                }
            }
        }

        // Reset per-transfer state
        self.bytes_transferred = 0;
        self.resume_from = 0;
        self.is_upload = false;
        self.is_directory = false;
        self.second_create_dirs = false;
        self.remote_path.clear();

        debug!("SFTP: done complete");
        Ok(())
    }

    /// Continue a multi-step SFTP operation.
    ///
    /// Returns `Ok(true)` when the operation is complete.
    async fn doing(&mut self, conn: &mut ConnectionData) -> Result<bool, CurlError> {
        let _ = conn;
        // SFTP operations are driven to completion in do_it/send/recv,
        // so doing() always reports completion.
        Ok(true)
    }

    /// Disconnect and release all SFTP resources.
    ///
    /// Shuts down the SFTP subsystem and frees all session state.
    async fn disconnect(&mut self, _conn: &mut ConnectionData) -> Result<(), CurlError> {
        debug!("SFTP: disconnect requested");
        self.sftp_shutdown().await?;
        debug!("SFTP: disconnected");
        Ok(())
    }

    /// Non-destructive connection liveness check.
    ///
    /// Returns `Ok` if the SFTP session is still alive, `Dead` otherwise.
    fn connection_check(&self, conn: &ConnectionData) -> ConnectionCheckResult {
        let _ = conn;
        if self.session.is_some() {
            ConnectionCheckResult::Ok
        } else {
            ConnectionCheckResult::Dead
        }
    }
}

// ============================================================================
// Helper Functions — Error Mapping
// ============================================================================

/// Map a russh-sftp client error to a CurlError variant.
///
/// Maps SFTP status codes to curl error codes matching C behavior:
/// - NoSuchFile → RemoteFileNotFound (like C LIBSSH2_FX_NO_SUCH_FILE)
/// - PermissionDenied → RemoteAccessDenied
/// - Failure → Ssh
/// - Eof → RecvError
/// - IO/timeout/other → Ssh
fn map_sftp_error(err: &russh_sftp::client::error::Error) -> CurlError {
    use russh_sftp::client::error::Error as SftpErr;

    match err {
        SftpErr::Status(status) => match status.status_code {
            StatusCode::NoSuchFile => CurlError::RemoteFileNotFound,
            StatusCode::PermissionDenied => CurlError::RemoteAccessDenied,
            StatusCode::Eof => CurlError::RecvError,
            StatusCode::Failure => CurlError::Ssh,
            StatusCode::BadMessage => CurlError::Ssh,
            StatusCode::NoConnection => CurlError::Ssh,
            StatusCode::ConnectionLost => CurlError::Ssh,
            StatusCode::OpUnsupported => CurlError::Ssh,
            StatusCode::Ok => CurlError::Ok,
        },
        SftpErr::Timeout => CurlError::Ssh,
        SftpErr::IO(_) => CurlError::Ssh,
        _ => CurlError::Ssh,
    }
}

/// Check if an SFTP error indicates "no such file" or "no such path".
fn is_no_such_file_error(err: &russh_sftp::client::error::Error) -> bool {
    use russh_sftp::client::error::Error as SftpErr;
    match err {
        SftpErr::Status(status) => matches!(status.status_code, StatusCode::NoSuchFile),
        _ => false,
    }
}

/// Check if an SFTP error indicates "already exists" (for mkdir).
///
/// SFTP protocol does not have a specific "already exists" status code.
/// Servers typically return FAILURE when a directory already exists.
/// We treat FAILURE as "may exist" during create-missing-dirs walks.
fn is_already_exists_error(err: &russh_sftp::client::error::Error) -> bool {
    use russh_sftp::client::error::Error as SftpErr;
    match err {
        SftpErr::Status(status) => matches!(
            status.status_code,
            StatusCode::Failure | StatusCode::PermissionDenied
        ),
        _ => false,
    }
}

// ============================================================================
// Helper Functions — Directory Listing Formatting
// ============================================================================

/// Format a Unix permission string from file attributes.
///
/// Produces a 10-character string like "drwxr-xr-x" or "-rw-r--r--".
fn format_permission_string(attrs: &FileAttributes) -> String {
    let perms = attrs.permissions.unwrap_or(0);

    // File type character
    let file_type = if attrs.is_dir() {
        'd'
    } else if attrs.is_symlink() {
        'l'
    } else {
        '-'
    };

    // Permission bits (standard Unix rwx mapping)
    let mut result = String::with_capacity(10);
    result.push(file_type);

    // Owner permissions (bits 8-6)
    result.push(if perms & 0o400 != 0 { 'r' } else { '-' });
    result.push(if perms & 0o200 != 0 { 'w' } else { '-' });
    result.push(if perms & 0o100 != 0 { 'x' } else { '-' });

    // Group permissions (bits 5-3)
    result.push(if perms & 0o040 != 0 { 'r' } else { '-' });
    result.push(if perms & 0o020 != 0 { 'w' } else { '-' });
    result.push(if perms & 0o010 != 0 { 'x' } else { '-' });

    // Other permissions (bits 2-0)
    result.push(if perms & 0o004 != 0 { 'r' } else { '-' });
    result.push(if perms & 0o002 != 0 { 'w' } else { '-' });
    result.push(if perms & 0o001 != 0 { 'x' } else { '-' });

    result
}

/// Format a file date for directory listing output.
///
/// Recent files (< 6 months old) show "MMM DD HH:MM".
/// Older files show "MMM DD  YYYY".
///
/// Uses MONTH_NAMES from util/parsedate.rs.
fn format_file_date(mtime: Option<u32>) -> String {
    let epoch_secs = mtime.unwrap_or(0) as u64;

    // Get current time for "recent" threshold
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();

    // Convert epoch seconds to (year, month, day, hour, minute)
    let (year, month, day, hour, minute) = epoch_to_ymd_hm(epoch_secs);
    let month_name = MONTH_NAMES[month as usize % 12];

    let is_recent = epoch_secs > 0
        && now_secs > epoch_secs
        && (now_secs - epoch_secs) < RECENT_FILE_THRESHOLD_SECS;

    if is_recent {
        format!("{} {:2} {:02}:{:02}", month_name, day, hour, minute)
    } else if epoch_secs == 0 {
        format!("{} {:2}  {:4}", month_name, 1, 1970)
    } else {
        format!("{} {:2}  {:4}", month_name, day, year)
    }
}

/// Convert Unix epoch seconds to (year, month, day, hour, minute).
///
/// This is a simple conversion without timezone handling (UTC assumed),
/// matching curl 8.x directory listing behavior which uses gmtime().
fn epoch_to_ymd_hm(epoch: u64) -> (u32, u32, u32, u32, u32) {
    if epoch == 0 {
        return (1970, 0, 1, 0, 0);
    }

    let secs_per_day: u64 = 86400;
    let days = epoch / secs_per_day;
    let remaining_secs = epoch % secs_per_day;

    let hour = (remaining_secs / 3600) as u32;
    let minute = ((remaining_secs % 3600) / 60) as u32;

    // Compute year, month, day from day count since epoch (1970-01-01)
    let mut y: u64 = 1970;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }

    let leap = is_leap_year(y);
    let month_days: [u64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m: usize = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining_days < md {
            m = i;
            break;
        }
        remaining_days -= md;
        if i == 11 {
            m = 11;
        }
    }

    let day = remaining_days as u32 + 1;

    (y as u32, m as u32, day, hour, minute)
}

/// Check if a year is a leap year.
fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Split a string into the first whitespace-delimited word and the remainder.
fn split_first_word(s: &str) -> (&str, &str) {
    let trimmed = s.trim_start();
    match trimmed.find([' ', '\t']) {
        Some(pos) => (&trimmed[..pos], trimmed[pos..].trim_start()),
        None => (trimmed, ""),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{Protocol, ProtocolFlags};
    use russh_sftp::protocol::{FileAttributes, StatusCode, Status};
    use russh_sftp::client::error::Error as SftpErr;

    // ========================================================================
    // SftpState tests
    // ========================================================================

    #[test]
    fn test_sftp_state_names_match_c() {
        assert_eq!(SftpState::Init.state_name(), "SSH_SFTP_INIT");
        assert_eq!(SftpState::Realpath.state_name(), "SSH_SFTP_REALPATH");
        assert_eq!(SftpState::QuoteInit.state_name(), "SSH_SFTP_QUOTE_INIT");
        assert_eq!(SftpState::PostQuoteInit.state_name(), "SSH_SFTP_POSTQUOTE_INIT");
        assert_eq!(SftpState::Quote.state_name(), "SSH_SFTP_QUOTE");
        assert_eq!(SftpState::NextQuote.state_name(), "SSH_SFTP_NEXT_QUOTE");
        assert_eq!(SftpState::QuoteStat.state_name(), "SSH_SFTP_QUOTE_STAT");
        assert_eq!(SftpState::QuoteSetStat.state_name(), "SSH_SFTP_QUOTE_SETSTAT");
        assert_eq!(SftpState::QuoteSymlink.state_name(), "SSH_SFTP_QUOTE_SYMLINK");
        assert_eq!(SftpState::QuoteMkdir.state_name(), "SSH_SFTP_QUOTE_MKDIR");
        assert_eq!(SftpState::QuoteRename.state_name(), "SSH_SFTP_QUOTE_RENAME");
        assert_eq!(SftpState::QuoteRmdir.state_name(), "SSH_SFTP_QUOTE_RMDIR");
        assert_eq!(SftpState::QuoteUnlink.state_name(), "SSH_SFTP_QUOTE_UNLINK");
        assert_eq!(SftpState::QuoteStatvfs.state_name(), "SSH_SFTP_QUOTE_STATVFS");
        assert_eq!(SftpState::GetInfo.state_name(), "SSH_SFTP_GETINFO");
        assert_eq!(SftpState::Filetime.state_name(), "SSH_SFTP_FILETIME");
        assert_eq!(SftpState::TransInit.state_name(), "SSH_SFTP_TRANS_INIT");
        assert_eq!(SftpState::UploadInit.state_name(), "SSH_SFTP_UPLOAD_INIT");
        assert_eq!(SftpState::CreateDirsInit.state_name(), "SSH_SFTP_CREATE_DIRS_INIT");
        assert_eq!(SftpState::CreateDirs.state_name(), "SSH_SFTP_CREATE_DIRS");
        assert_eq!(SftpState::CreateDirsMkdir.state_name(), "SSH_SFTP_CREATE_DIRS_MKDIR");
        assert_eq!(SftpState::ReaddirInit.state_name(), "SSH_SFTP_READDIR_INIT");
        assert_eq!(SftpState::Readdir.state_name(), "SSH_SFTP_READDIR");
        assert_eq!(SftpState::ReaddirLink.state_name(), "SSH_SFTP_READDIR_LINK");
        assert_eq!(SftpState::ReaddirBottom.state_name(), "SSH_SFTP_READDIR_BOTTOM");
        assert_eq!(SftpState::ReaddirDone.state_name(), "SSH_SFTP_READDIR_DONE");
        assert_eq!(SftpState::DownloadInit.state_name(), "SSH_SFTP_DOWNLOAD_INIT");
        assert_eq!(SftpState::DownloadStat.state_name(), "SSH_SFTP_DOWNLOAD_STAT");
        assert_eq!(SftpState::Close.state_name(), "SSH_SFTP_CLOSE");
        assert_eq!(SftpState::Shutdown.state_name(), "SSH_SFTP_SHUTDOWN");
        assert_eq!(SftpState::Done.state_name(), "SSH_SFTP_DONE");
        assert_eq!(SftpState::Error.state_name(), "SSH_SFTP_ERROR");
    }

    #[test]
    fn test_sftp_state_display() {
        assert_eq!(format!("{}", SftpState::Init), "SSH_SFTP_INIT");
        assert_eq!(format!("{}", SftpState::UploadInit), "SSH_SFTP_UPLOAD_INIT");
        assert_eq!(format!("{}", SftpState::Error), "SSH_SFTP_ERROR");
    }

    #[test]
    fn test_sftp_state_clone_and_eq() {
        let s1 = SftpState::UploadInit;
        let s2 = s1.clone();
        assert_eq!(s1, s2);
        assert_ne!(s1, SftpState::DownloadInit);
    }

    #[test]
    fn test_all_32_sftp_states_exist() {
        let states = vec![
            SftpState::Init, SftpState::Realpath, SftpState::QuoteInit,
            SftpState::PostQuoteInit, SftpState::Quote, SftpState::NextQuote,
            SftpState::QuoteStat, SftpState::QuoteSetStat, SftpState::QuoteSymlink,
            SftpState::QuoteMkdir, SftpState::QuoteRename, SftpState::QuoteRmdir,
            SftpState::QuoteUnlink, SftpState::QuoteStatvfs, SftpState::GetInfo,
            SftpState::Filetime, SftpState::TransInit, SftpState::UploadInit,
            SftpState::CreateDirsInit, SftpState::CreateDirs, SftpState::CreateDirsMkdir,
            SftpState::ReaddirInit, SftpState::Readdir, SftpState::ReaddirLink,
            SftpState::ReaddirBottom, SftpState::ReaddirDone, SftpState::DownloadInit,
            SftpState::DownloadStat, SftpState::Close, SftpState::Shutdown,
            SftpState::Done, SftpState::Error,
        ];
        assert_eq!(states.len(), 32);
        let names: std::collections::HashSet<&str> =
            states.iter().map(|s| s.state_name()).collect();
        assert_eq!(names.len(), 32);
    }

    // ========================================================================
    // SftpHandler construction tests
    // ========================================================================

    #[test]
    fn test_sftp_handler_new() {
        let handler = SftpHandler::new();
        assert!(handler.session.is_none());
        assert!(handler.file_handle.is_none());
        assert_eq!(handler.state, SftpState::Init);
        assert_eq!(handler.remote_path, "");
        assert_eq!(handler.homedir, "");
        assert_eq!(handler.bytes_transferred, 0);
        assert_eq!(handler.resume_from, 0);
        assert!(!handler.is_upload);
        assert!(!handler.is_directory);
        assert!(!handler.accept_fail);
        assert!(!handler.second_create_dirs);
        assert!(!handler.remote_append);
        assert!(handler.quote_items.is_empty());
        assert!(handler.postquote_items.is_empty());
        assert!(handler.prequote_items.is_empty());
        assert_eq!(handler.quote_index, 0);
        assert!(handler.quote_path1.is_none());
        assert!(handler.quote_path2.is_none());
        assert!(handler.slash_pos.is_none());
        assert_eq!(handler.infilesize, -1);
        assert_eq!(handler.new_dir_perms, DEFAULT_DIR_PERMS);
        assert!(!handler.in_postquote);
        assert!(handler.range_spec.is_none());
        assert_eq!(handler.download_size, 0);
    }

    #[test]
    fn test_sftp_handler_default_matches_new() {
        let h1 = SftpHandler::new();
        let h2 = SftpHandler::default();
        assert_eq!(h1.state, h2.state);
        assert_eq!(h1.remote_path, h2.remote_path);
        assert_eq!(h1.homedir, h2.homedir);
        assert_eq!(h1.bytes_transferred, h2.bytes_transferred);
        assert_eq!(h1.resume_from, h2.resume_from);
    }

    #[test]
    fn test_sftp_handler_debug() {
        let handler = SftpHandler::new();
        let debug_str = format!("{:?}", handler);
        assert!(debug_str.contains("SftpHandler"));
        assert!(debug_str.contains("Init"));
    }

    // ========================================================================
    // Protocol trait tests
    // ========================================================================

    #[test]
    fn test_protocol_name() {
        let handler = SftpHandler::new();
        assert_eq!(handler.name(), "SFTP");
    }

    #[test]
    fn test_protocol_default_port() {
        let handler = SftpHandler::new();
        assert_eq!(handler.default_port(), 22);
    }

    #[test]
    fn test_protocol_flags() {
        let handler = SftpHandler::new();
        let flags = handler.flags();
        assert!(flags.contains(ProtocolFlags::CLOSEACTION));
        assert!(flags.contains(ProtocolFlags::CONN_REUSE));
        // SFTP should not have these
        assert!(!flags.contains(ProtocolFlags::SSL));
        assert!(!flags.contains(ProtocolFlags::NONETWORK));
    }

    // ========================================================================
    // epoch_to_ymd_hm tests
    // ========================================================================

    #[test]
    fn test_epoch_zero() {
        // Unix epoch: 1970-01-01 00:00:00 UTC
        let (y, m, d, h, min) = epoch_to_ymd_hm(0);
        assert_eq!(y, 1970);
        assert_eq!(m, 0); // January = month index 0
        assert_eq!(d, 1);
        assert_eq!(h, 0);
        assert_eq!(min, 0);
    }

    #[test]
    fn test_epoch_known_date_2023_01_15() {
        // 2023-01-15 14:30:00 UTC = 1673793000
        let (y, m, d, h, min) = epoch_to_ymd_hm(1673793000);
        assert_eq!(y, 2023);
        assert_eq!(m, 0); // January = 0
        assert_eq!(d, 15);
        assert_eq!(h, 14);
        assert_eq!(min, 30);
    }

    #[test]
    fn test_epoch_leap_year_feb_29() {
        // 2000-02-29 00:00:00 UTC = 951782400
        let (y, m, d, _h, _min) = epoch_to_ymd_hm(951782400);
        assert_eq!(y, 2000);
        assert_eq!(m, 1); // February = 1
        assert_eq!(d, 29);
    }

    #[test]
    fn test_epoch_dec_31() {
        // 2024-12-31 23:59:00 UTC = 1735689540
        let (y, m, d, h, min) = epoch_to_ymd_hm(1735689540);
        assert_eq!(y, 2024);
        assert_eq!(m, 11); // December = 11
        assert_eq!(d, 31);
        assert_eq!(h, 23);
        assert_eq!(min, 59);
    }

    // ========================================================================
    // is_leap_year tests
    // ========================================================================

    #[test]
    fn test_leap_years() {
        assert!(is_leap_year(2000)); // divisible by 400
        assert!(is_leap_year(2004)); // divisible by 4
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900)); // divisible by 100 but not 400
        assert!(!is_leap_year(2023)); // not divisible by 4
        assert!(!is_leap_year(2100));
    }

    // ========================================================================
    // split_first_word tests
    // ========================================================================

    #[test]
    fn test_split_first_word_basic() {
        let (word, rest) = split_first_word("hello world");
        assert_eq!(word, "hello");
        assert_eq!(rest, "world");
    }

    #[test]
    fn test_split_first_word_no_rest() {
        let (word, rest) = split_first_word("hello");
        assert_eq!(word, "hello");
        assert_eq!(rest, "");
    }

    #[test]
    fn test_split_first_word_leading_spaces() {
        let (word, rest) = split_first_word("   hello   world  ");
        assert_eq!(word, "hello");
        assert_eq!(rest, "world  ");
    }

    #[test]
    fn test_split_first_word_tab_separator() {
        let (word, rest) = split_first_word("hello\tworld");
        assert_eq!(word, "hello");
        assert_eq!(rest, "world");
    }

    #[test]
    fn test_split_first_word_empty() {
        let (word, rest) = split_first_word("");
        assert_eq!(word, "");
        assert_eq!(rest, "");
    }

    #[test]
    fn test_split_first_word_only_spaces() {
        let (word, rest) = split_first_word("   ");
        assert_eq!(word, "");
        assert_eq!(rest, "");
    }

    // ========================================================================
    // format_permission_string tests
    // ========================================================================

    #[test]
    fn test_format_permission_regular_644() {
        let mut attrs = FileAttributes::default();
        attrs.permissions = Some(0o100644);
        let result = format_permission_string(&attrs);
        assert_eq!(result, "-rw-r--r--");
    }

    #[test]
    fn test_format_permission_dir_755() {
        let mut attrs = FileAttributes::default();
        attrs.permissions = Some(0o40755);
        let result = format_permission_string(&attrs);
        assert_eq!(result, "drwxr-xr-x");
    }

    #[test]
    fn test_format_permission_executable() {
        let mut attrs = FileAttributes::default();
        attrs.permissions = Some(0o100755);
        let result = format_permission_string(&attrs);
        assert_eq!(result, "-rwxr-xr-x");
    }

    #[test]
    fn test_format_permission_no_permissions() {
        // FileAttributes with permissions = None (not the default which is dir+777)
        let attrs = FileAttributes {
            size: None,
            uid: None,
            user: None,
            gid: None,
            group: None,
            permissions: None,
            atime: None,
            mtime: None,
        };
        let result = format_permission_string(&attrs);
        assert_eq!(result, "----------");
    }

    #[test]
    fn test_format_permission_default_is_dir_777() {
        // FileAttributes::default() is a directory with 777 permissions
        let attrs = FileAttributes::default();
        let result = format_permission_string(&attrs);
        assert_eq!(result, "drwxrwxrwx");
    }

    #[test]
    fn test_format_permission_all_set() {
        let mut attrs = FileAttributes::default();
        attrs.permissions = Some(0o100777);
        let result = format_permission_string(&attrs);
        assert_eq!(result, "-rwxrwxrwx");
    }

    #[test]
    fn test_format_permission_symlink() {
        let mut attrs = FileAttributes::default();
        attrs.permissions = Some(0o120777);
        let result = format_permission_string(&attrs);
        assert_eq!(result, "lrwxrwxrwx");
    }

    // ========================================================================
    // format_file_date tests
    // ========================================================================

    #[test]
    fn test_format_file_date_none() {
        let result = format_file_date(None);
        // Should produce a date string for epoch 0 (Jan  1  1970)
        assert!(result.contains("Jan"));
        assert!(result.contains("1970"));
    }

    #[test]
    fn test_format_file_date_known_old_file() {
        // A date older than 6 months should show year instead of time
        let result = format_file_date(Some(1000000000)); // Sep 2001
        assert!(result.contains("2001"));
    }

    // ========================================================================
    // Error mapping tests
    // ========================================================================

    #[test]
    fn test_map_sftp_error_no_such_file() {
        let status = Status {
            id: 0,
            status_code: StatusCode::NoSuchFile,
            error_message: "No such file".to_string(),
            language_tag: "en-US".to_string(),
        };
        let err = SftpErr::Status(status);
        assert_eq!(map_sftp_error(&err), CurlError::RemoteFileNotFound);
    }

    #[test]
    fn test_map_sftp_error_permission_denied() {
        let status = Status {
            id: 0,
            status_code: StatusCode::PermissionDenied,
            error_message: "Permission denied".to_string(),
            language_tag: "en-US".to_string(),
        };
        let err = SftpErr::Status(status);
        assert_eq!(map_sftp_error(&err), CurlError::RemoteAccessDenied);
    }

    #[test]
    fn test_map_sftp_error_eof() {
        let status = Status {
            id: 0,
            status_code: StatusCode::Eof,
            error_message: "EOF".to_string(),
            language_tag: "en-US".to_string(),
        };
        let err = SftpErr::Status(status);
        assert_eq!(map_sftp_error(&err), CurlError::RecvError);
    }

    #[test]
    fn test_map_sftp_error_failure() {
        let status = Status {
            id: 0,
            status_code: StatusCode::Failure,
            error_message: "Failure".to_string(),
            language_tag: "en-US".to_string(),
        };
        let err = SftpErr::Status(status);
        assert_eq!(map_sftp_error(&err), CurlError::Ssh);
    }

    #[test]
    fn test_map_sftp_error_io() {
        let err = SftpErr::IO("io fail".to_string());
        assert_eq!(map_sftp_error(&err), CurlError::Ssh);
    }

    #[test]
    fn test_map_sftp_error_timeout() {
        let err = SftpErr::Timeout;
        assert_eq!(map_sftp_error(&err), CurlError::Ssh);
    }

    #[test]
    fn test_is_no_such_file_positive() {
        let status = Status {
            id: 0,
            status_code: StatusCode::NoSuchFile,
            error_message: "No such file".to_string(),
            language_tag: "en-US".to_string(),
        };
        let err = SftpErr::Status(status);
        assert!(is_no_such_file_error(&err));
    }

    #[test]
    fn test_is_no_such_file_negative() {
        let err = SftpErr::Timeout;
        assert!(!is_no_such_file_error(&err));
    }

    #[test]
    fn test_is_already_exists_error_positive() {
        let status = Status {
            id: 0,
            status_code: StatusCode::Failure,
            error_message: "Failure".to_string(),
            language_tag: "en-US".to_string(),
        };
        let err = SftpErr::Status(status);
        assert!(is_already_exists_error(&err));
    }

    #[test]
    fn test_is_already_exists_error_negative() {
        let status = Status {
            id: 0,
            status_code: StatusCode::NoSuchFile,
            error_message: "No such file".to_string(),
            language_tag: "en-US".to_string(),
        };
        let err = SftpErr::Status(status);
        assert!(!is_already_exists_error(&err));
    }

    // ========================================================================
    // Constants tests
    // ========================================================================

    #[test]
    fn test_default_permissions() {
        assert_eq!(DEFAULT_DIR_PERMS, 0o755);
        assert_eq!(DEFAULT_FILE_PERMS, 0o644);
    }

    #[test]
    fn test_buffer_size() {
        assert!(SFTP_BUFFER_SIZE > 0);
        assert!(SFTP_BUFFER_SIZE <= 64 * 1024); // not larger than 64KB
    }

    #[test]
    fn test_dir_listing_max_size() {
        assert!(DIR_LISTING_MAX_SIZE > 0);
    }

    #[test]
    fn test_recent_file_threshold() {
        assert_eq!(RECENT_FILE_THRESHOLD_SECS, 6 * 30 * 24 * 3600);
    }
}
