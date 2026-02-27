//! SCP protocol handler.
//!
//! This module provides the SCP state machine and handler for
//! SCP file transfer operations over SSH. Full implementation is
//! provided by the dedicated agent — this file defines the types
//! re-exported by the SSH module root.

use crate::error::CurlResult;

/// SCP-specific state machine states.
///
/// Maps to C `SSH_SCP_*` states from `ssh.h` lines 83-95.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScpState {
    /// SCP transfer initialization.
    TransInit,
    /// SCP upload initialization.
    UploadInit,
    /// SCP download initialization.
    DownloadInit,
    /// SCP download active data transfer.
    Download,
    /// SCP download complete.
    Done,
    /// SCP send EOF.
    SendEof,
    /// SCP wait for EOF acknowledgment.
    WaitEof,
    /// SCP wait for close.
    WaitClose,
    /// SCP channel free/cleanup.
    ChannelFree,
}

impl ScpState {
    /// Return a human-readable state name for debugging.
    pub fn state_name(&self) -> &'static str {
        match self {
            ScpState::TransInit => "SSH_SCP_TRANS_INIT",
            ScpState::UploadInit => "SSH_SCP_UPLOAD_INIT",
            ScpState::DownloadInit => "SSH_SCP_DOWNLOAD_INIT",
            ScpState::Download => "SSH_SCP_DOWNLOAD",
            ScpState::Done => "SSH_SCP_DONE",
            ScpState::SendEof => "SSH_SCP_SEND_EOF",
            ScpState::WaitEof => "SSH_SCP_WAIT_EOF",
            ScpState::WaitClose => "SSH_SCP_WAIT_CLOSE",
            ScpState::ChannelFree => "SSH_SCP_CHANNEL_FREE",
        }
    }
}

/// SCP protocol handler providing SCP file transfer over SSH.
pub struct ScpHandler;

impl ScpHandler {
    /// Initialize an SCP upload operation.
    pub async fn scp_upload_init() -> CurlResult<()> {
        Ok(())
    }

    /// Send data during an SCP upload.
    pub async fn scp_send(_data: &[u8]) -> CurlResult<usize> {
        Ok(0)
    }

    /// Initialize an SCP download operation.
    pub async fn scp_download_init() -> CurlResult<()> {
        Ok(())
    }

    /// Receive data during an SCP download.
    pub async fn scp_recv(_buf: &mut [u8]) -> CurlResult<usize> {
        Ok(0)
    }

    /// Parse an SCP header line (T-line or C-line).
    pub fn parse_scp_header(_header: &str) -> CurlResult<(u64, String)> {
        Ok((0, String::new()))
    }

    /// Format an SCP header for upload.
    pub fn format_scp_header(_size: u64, _mode: u32, _name: &str) -> String {
        String::new()
    }
}
