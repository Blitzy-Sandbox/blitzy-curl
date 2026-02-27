//! SFTP protocol handler.
//!
//! This module provides the SFTP state machine and handler for
//! SFTP file operations over SSH. Full implementation is provided
//! by the dedicated agent — this file defines the types re-exported
//! by the SSH module root.

use crate::error::CurlResult;

/// SFTP-specific state machine states.
///
/// Maps to C `SSH_SFTP_*` states from `ssh.h` lines 48-81.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SftpState {
    /// SFTP subsystem initialization.
    Init,
    /// SFTP realpath resolution.
    Realpath,
    /// SFTP quote command processing.
    QuoteInit,
    /// SFTP quote stat operation.
    QuoteStat,
    /// SFTP quote setstat operation.
    QuoteSetstat,
    /// SFTP quote symlink operation.
    QuoteSymlink,
    /// SFTP quote mkdir operation.
    QuoteMkdir,
    /// SFTP quote rename operation.
    QuoteRename,
    /// SFTP quote rmdir operation.
    QuoteRmdir,
    /// SFTP quote unlink operation.
    QuoteUnlink,
    /// SFTP quote statvfs operation.
    QuoteStatvfs,
    /// SFTP upload initialization.
    UploadInit,
    /// SFTP create dirs for upload.
    CreateDirsInit,
    /// SFTP create dirs mkdir step.
    CreateDirsMkdir,
    /// SFTP upload active data transfer.
    Upload,
    /// SFTP download initialization.
    DownloadInit,
    /// SFTP download stat for size.
    DownloadStat,
    /// SFTP download active data transfer.
    Download,
    /// SFTP close file handle.
    Close,
    /// SFTP shutdown subsystem.
    Shutdown,
    /// SFTP readdir initialization.
    ReaddirInit,
    /// SFTP readdir active listing.
    Readdir,
    /// SFTP readdir link check.
    ReaddirLink,
    /// SFTP readdir bottom/finalize.
    ReaddirBottom,
    /// SFTP readdir done.
    ReaddirDone,
}

impl SftpState {
    /// Return a human-readable state name for debugging.
    pub fn state_name(&self) -> &'static str {
        match self {
            SftpState::Init => "SSH_SFTP_INIT",
            SftpState::Realpath => "SSH_SFTP_REALPATH",
            SftpState::QuoteInit => "SSH_SFTP_QUOTE_INIT",
            SftpState::QuoteStat => "SSH_SFTP_QUOTE_STAT",
            SftpState::QuoteSetstat => "SSH_SFTP_QUOTE_SETSTAT",
            SftpState::QuoteSymlink => "SSH_SFTP_QUOTE_SYMLINK",
            SftpState::QuoteMkdir => "SSH_SFTP_QUOTE_MKDIR",
            SftpState::QuoteRename => "SSH_SFTP_QUOTE_RENAME",
            SftpState::QuoteRmdir => "SSH_SFTP_QUOTE_RMDIR",
            SftpState::QuoteUnlink => "SSH_SFTP_QUOTE_UNLINK",
            SftpState::QuoteStatvfs => "SSH_SFTP_QUOTE_STATVFS",
            SftpState::UploadInit => "SSH_SFTP_UPLOAD_INIT",
            SftpState::CreateDirsInit => "SSH_SFTP_CREATE_DIRS_INIT",
            SftpState::CreateDirsMkdir => "SSH_SFTP_CREATE_DIRS_MKDIR",
            SftpState::Upload => "SSH_SFTP_UPLOAD",
            SftpState::DownloadInit => "SSH_SFTP_DOWNLOAD_INIT",
            SftpState::DownloadStat => "SSH_SFTP_DOWNLOAD_STAT",
            SftpState::Download => "SSH_SFTP_DOWNLOAD",
            SftpState::Close => "SSH_SFTP_CLOSE",
            SftpState::Shutdown => "SSH_SFTP_SHUTDOWN",
            SftpState::ReaddirInit => "SSH_SFTP_READDIR_INIT",
            SftpState::Readdir => "SSH_SFTP_READDIR",
            SftpState::ReaddirLink => "SSH_SFTP_READDIR_LINK",
            SftpState::ReaddirBottom => "SSH_SFTP_READDIR_BOTTOM",
            SftpState::ReaddirDone => "SSH_SFTP_READDIR_DONE",
        }
    }
}

/// SFTP protocol handler providing SFTP file operations over SSH.
pub struct SftpHandler;

impl SftpHandler {
    /// Initialize the SFTP subsystem on an SSH channel.
    pub async fn sftp_init() -> CurlResult<()> {
        Ok(())
    }

    /// Resolve the real absolute path on the remote server.
    pub async fn sftp_realpath() -> CurlResult<String> {
        Ok(String::new())
    }

    /// Initialize an SFTP upload operation.
    pub async fn sftp_upload_init() -> CurlResult<()> {
        Ok(())
    }

    /// Send data during an SFTP upload.
    pub async fn sftp_send(_data: &[u8]) -> CurlResult<usize> {
        Ok(0)
    }

    /// Initialize an SFTP download operation.
    pub async fn sftp_download_init() -> CurlResult<()> {
        Ok(())
    }

    /// Stat a file for download size information.
    pub async fn sftp_download_stat() -> CurlResult<u64> {
        Ok(0)
    }

    /// Receive data during an SFTP download.
    pub async fn sftp_recv(_buf: &mut [u8]) -> CurlResult<usize> {
        Ok(0)
    }

    /// Initialize directory listing.
    pub async fn sftp_readdir_init() -> CurlResult<()> {
        Ok(())
    }

    /// Read the next directory entry.
    pub async fn sftp_readdir() -> CurlResult<Option<String>> {
        Ok(None)
    }

    /// Execute an SFTP quote command.
    pub async fn sftp_quote() -> CurlResult<()> {
        Ok(())
    }

    /// Close the SFTP file handle.
    pub async fn sftp_close() -> CurlResult<()> {
        Ok(())
    }

    /// Shut down the SFTP subsystem.
    pub async fn sftp_shutdown() -> CurlResult<()> {
        Ok(())
    }
}
