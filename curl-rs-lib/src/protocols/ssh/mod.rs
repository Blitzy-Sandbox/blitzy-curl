//! SSH Module Root and Shared Infrastructure
//!
//! This module provides the foundational SSH protocol types, session management,
//! authentication flows, known-host verification, state machine, and utility
//! functions shared by the SFTP and SCP protocol handlers.
//!
//! Replaces the following C source files from curl 8.19.0-DEV:
//! - `lib/vssh/ssh.h` (265 lines) — SSH state machine and type definitions
//! - `lib/vssh/vssh.c` (364 lines) — Shared SSH utility functions
//! - `lib/vssh/vssh.h` (42 lines) — Shared SSH function declarations
//! - Shared auth/connect/session logic from `lib/vssh/libssh2.c`

pub mod sftp;
pub mod scp;

// ============================================================================
// Standard library imports
// ============================================================================
use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// ============================================================================
// External crate imports
// ============================================================================
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use sha2::{Sha256, Digest};
use md5::Md5;
use tracing::{debug, error, info, trace, warn};
use russh::client::{self, Handle, KeyboardInteractiveAuthResponse};
use russh::keys as ssh_keys;
use russh::{Disconnect, MethodKind, MethodSet};

// ============================================================================
// Internal crate imports
// ============================================================================
use crate::error::{CurlError, CurlResult};
use crate::escape::url_decode;
use crate::protocols::{Scheme, ProtocolFlags};
use crate::conn::ConnectionData;
use crate::util::dynbuf::DynBuf;

// ============================================================================
// Re-exports from submodules
// ============================================================================
pub use self::sftp::{SftpHandler, SftpState};
pub use self::scp::{ScpHandler, ScpState};

// ============================================================================
// Constants
// ============================================================================

/// Default SSH port (matches C `PORT_SSH`)
pub const PORT_SSH: u16 = 22;

/// Maximum path length for SSH working path operations.
/// From C `MAX_SSHPATH_LEN` in `vssh.c` line 127.
pub const MAX_SSHPATH_LEN: usize = 100_000;

/// Maximum path length for QUOTE command arguments.
/// From C `MAX_PATHLENGTH` in `vssh.c` line 200.
pub const MAX_PATHLENGTH: usize = 65_535;

/// Protocol flag: Directory lock (matches C `PROTOPT_DIRLOCK`).
/// Uses bit 13, available in `ProtocolFlags`.
const SSH_FLAG_DIRLOCK: ProtocolFlags = ProtocolFlags::from_bits(1 << 13);

/// Protocol flag: No URL query (matches C `PROTOPT_NOURLQUERY`).
/// Uses bit 14, available in `ProtocolFlags`.
const SSH_FLAG_NOURLQUERY: ProtocolFlags = ProtocolFlags::from_bits(1 << 14);

/// SSH library version string for identification.
const SSH_VERSION_STRING: &str = "russh/0.55";

// ============================================================================
// SshProtocol — Protocol discriminator
// ============================================================================

/// Discriminator for SSH protocol variants (SFTP vs SCP).
///
/// Used by shared path resolution functions to apply protocol-specific
/// behavior for `/~/` home-relative path rewriting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshProtocol {
    /// SFTP protocol — `/~/` is replaced with homedir prefix.
    Sftp,
    /// SCP protocol — `/~/` prefix is stripped (home-relative).
    Scp,
}

impl fmt::Display for SshProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SshProtocol::Sftp => write!(f, "SFTP"),
            SshProtocol::Scp => write!(f, "SCP"),
        }
    }
}

// ============================================================================
// SshState — SSH session state machine
// ============================================================================

/// SSH session state machine states.
///
/// Maps 1:1 to the C `sshstate` enum in `lib/vssh/ssh.h` (lines 29-121).
/// Authentication and session lifecycle states are defined directly here;
/// SFTP and SCP operational states are delegated to their respective
/// `SftpState` and `ScpState` enums via wrapping variants.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SshState {
    /// No state set (C: `SSH_NO_STATE = -1`)
    #[default]
    NoState,
    /// Stopped / idle (C: `SSH_STOP = 0`)
    Stop,
    /// Initialization (C: `SSH_INIT`)
    Init,
    /// Session startup / handshake (C: `SSH_S_STARTUP`)
    Startup,
    /// Host key verification (C: `SSH_HOSTKEY`)
    Hostkey,
    /// Authentication method list discovery (C: `SSH_AUTHLIST`)
    AuthList,
    /// Public key auth initialization (C: `SSH_AUTH_PKEY_INIT`)
    AuthPkeyInit,
    /// Public key auth attempt (C: `SSH_AUTH_PKEY`)
    AuthPkey,
    /// Password auth initialization (C: `SSH_AUTH_PASS_INIT`)
    AuthPassInit,
    /// Password auth attempt (C: `SSH_AUTH_PASS`)
    AuthPass,
    /// SSH agent initialization (C: `SSH_AUTH_AGENT_INIT`)
    AuthAgentInit,
    /// SSH agent identity listing (C: `SSH_AUTH_AGENT_LIST`)
    AuthAgentList,
    /// SSH agent auth attempt (C: `SSH_AUTH_AGENT`)
    AuthAgent,
    /// Host-based auth initialization (C: `SSH_AUTH_HOST_INIT`)
    AuthHostInit,
    /// Host-based auth attempt (C: `SSH_AUTH_HOST`)
    AuthHost,
    /// Keyboard-interactive auth initialization (C: `SSH_AUTH_KEY_INIT`)
    AuthKeyInit,
    /// Keyboard-interactive auth attempt (C: `SSH_AUTH_KEY`)
    AuthKey,
    /// GSSAPI auth attempt (C: `SSH_AUTH_GSSAPI`)
    AuthGssapi,
    /// Authentication complete (C: `SSH_AUTH_DONE`)
    AuthDone,
    /// SFTP operational state (wraps `SftpState` from `sftp.rs`)
    Sftp(SftpState),
    /// SCP operational state (wraps `ScpState` from `scp.rs`)
    Scp(ScpState),
    /// Session disconnect initiated (C: `SSH_SESSION_DISCONNECT`)
    SessionDisconnect,
    /// Session freed (C: `SSH_SESSION_FREE`)
    SessionFree,
    /// Quit state (C: `SSH_QUIT`)
    Quit,
}

impl fmt::Display for SshState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ssh_state_name(self))
    }
}

// ============================================================================
// SshAuthMethod — Authentication method bitflags
// ============================================================================

/// Bitflags type representing SSH authentication methods.
///
/// Maps to the server's `authlist` string of comma-separated method names
/// and the client's allowed method configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SshAuthMethod(u32);

impl SshAuthMethod {
    /// Public key authentication.
    pub const PUBLICKEY: SshAuthMethod = SshAuthMethod(1 << 0);
    /// Password authentication.
    pub const PASSWORD: SshAuthMethod = SshAuthMethod(1 << 1);
    /// Host-based authentication.
    pub const HOST: SshAuthMethod = SshAuthMethod(1 << 2);
    /// Keyboard-interactive authentication.
    pub const KEYBOARD_INTERACTIVE: SshAuthMethod = SshAuthMethod(1 << 3);
    /// GSSAPI / Kerberos authentication.
    pub const GSSAPI: SshAuthMethod = SshAuthMethod(1 << 4);
    /// SSH agent forwarding.
    pub const AGENT: SshAuthMethod = SshAuthMethod(1 << 5);

    /// Returns an empty set of auth methods.
    pub const fn empty() -> Self {
        SshAuthMethod(0)
    }

    /// Returns a set containing all known auth methods.
    pub const fn all() -> Self {
        SshAuthMethod(
            Self::PUBLICKEY.0
                | Self::PASSWORD.0
                | Self::HOST.0
                | Self::KEYBOARD_INTERACTIVE.0
                | Self::GSSAPI.0
                | Self::AGENT.0,
        )
    }

    /// Returns true if `self` contains all bits in `other`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns true if no bits are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for SshAuthMethod {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        SshAuthMethod(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for SshAuthMethod {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for SshAuthMethod {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        SshAuthMethod(self.0 & rhs.0)
    }
}

// ============================================================================
// SshAuthConfig — Authentication configuration
// ============================================================================

/// SSH authentication configuration.
///
/// Carries all user-provided credentials and verification settings for
/// establishing an SSH session. Maps to fields from `struct ssh_conn`
/// in C `lib/vssh/ssh.h` and CURLOPT_SSH_* options.
#[derive(Debug, Clone)]
pub struct SshAuthConfig {
    /// SSH username (from URL userinfo or CURLOPT_USERPWD).
    pub username: String,
    /// Password for password authentication.
    pub password: Option<String>,
    /// Path to private key file (CURLOPT_SSH_PRIVATE_KEYFILE).
    pub private_key_file: Option<PathBuf>,
    /// Path to public key file (CURLOPT_SSH_PUBLIC_KEYFILE).
    pub public_key_file: Option<PathBuf>,
    /// Passphrase for encrypted private key (CURLOPT_KEYPASSWD).
    pub passphrase: Option<String>,
    /// Path to known_hosts file (CURLOPT_SSH_KNOWNHOSTS).
    pub known_hosts_file: Option<PathBuf>,
    /// Expected SHA-256 fingerprint of server host key (base64-encoded).
    pub host_public_key_sha256: Option<String>,
    /// Expected MD5 fingerprint of server host key (hex, 32 chars).
    pub host_public_key_md5: Option<String>,
    /// Bitmask of allowed authentication methods.
    pub allowed_methods: SshAuthMethod,
    /// Whether to use SSH agent for authentication.
    pub ssh_agent: bool,
}

impl Default for SshAuthConfig {
    fn default() -> Self {
        SshAuthConfig {
            username: String::new(),
            password: None,
            private_key_file: None,
            public_key_file: None,
            passphrase: None,
            known_hosts_file: None,
            host_public_key_sha256: None,
            host_public_key_md5: None,
            allowed_methods: SshAuthMethod::all(),
            ssh_agent: true,
        }
    }
}

// ============================================================================
// SshError — SSH-specific error type
// ============================================================================

/// SSH-specific error variants mapped to CurlError codes at the API boundary.
#[derive(Debug)]
pub enum SshError {
    /// All authentication methods exhausted (CURLE_LOGIN_DENIED = 67).
    AuthFailed,
    /// Known-hosts verification found a key mismatch (CURLE_PEER_FAILED_VERIFICATION = 60).
    HostKeyMismatch,
    /// Host key not in known_hosts and not accepted (CURLE_PEER_FAILED_VERIFICATION = 60).
    HostKeyUnknown,
    /// SSH channel open failed (CURLE_SSH = 79).
    ChannelFailed,
    /// Subsystem request failed (CURLE_SSH = 79).
    SubsystemFailed,
    /// SSH connection was lost (CURLE_SSH = 79).
    ConnectionLost,
    /// SSH operation timed out (CURLE_SSH = 79).
    Timeout,
    /// Wrapped russh transport error.
    Transport(russh::Error),
    /// Wrapped russh-keys error.
    Keys(ssh_keys::Error),
    /// Agent authentication error.
    AgentAuth(String),
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SshError::AuthFailed => write!(f, "SSH authentication failed"),
            SshError::HostKeyMismatch => write!(f, "SSH host key mismatch"),
            SshError::HostKeyUnknown => write!(f, "SSH host key unknown"),
            SshError::ChannelFailed => write!(f, "SSH channel open failed"),
            SshError::SubsystemFailed => write!(f, "SSH subsystem request failed"),
            SshError::ConnectionLost => write!(f, "SSH connection lost"),
            SshError::Timeout => write!(f, "SSH operation timed out"),
            SshError::Transport(e) => write!(f, "SSH transport error: {}", e),
            SshError::Keys(e) => write!(f, "SSH key error: {}", e),
            SshError::AgentAuth(msg) => write!(f, "SSH agent auth error: {}", msg),
        }
    }
}

impl std::error::Error for SshError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SshError::Transport(e) => Some(e),
            SshError::Keys(e) => Some(e),
            _ => None,
        }
    }
}

impl From<russh::Error> for SshError {
    fn from(err: russh::Error) -> Self {
        match err {
            russh::Error::Disconnect => SshError::ConnectionLost,
            _ => SshError::Transport(err),
        }
    }
}

impl From<ssh_keys::Error> for SshError {
    fn from(err: ssh_keys::Error) -> Self {
        SshError::Keys(err)
    }
}

impl From<russh::AgentAuthError> for SshError {
    fn from(err: russh::AgentAuthError) -> Self {
        SshError::AgentAuth(format!("{}", err))
    }
}

impl From<SshError> for CurlError {
    fn from(err: SshError) -> Self {
        match err {
            SshError::AuthFailed => {
                warn!("SSH: {}", err);
                CurlError::LoginDenied
            }
            SshError::HostKeyMismatch | SshError::HostKeyUnknown => {
                warn!("SSH: {}", err);
                CurlError::PeerFailedVerification
            }
            _ => {
                error!("SSH: {}", err);
                CurlError::Ssh
            }
        }
    }
}

// ============================================================================
// Fingerprint computation helpers
// ============================================================================

/// Compute SHA-256 fingerprint of SSH public key bytes (base64-encoded).
fn compute_sha256_fingerprint(key_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, key_bytes);
    let result = hasher.finalize();
    BASE64_STANDARD.encode(result)
}

/// Compute MD5 fingerprint of SSH public key bytes (hex with colons).
fn compute_md5_fingerprint(key_bytes: &[u8]) -> String {
    let mut hasher = Md5::new();
    Digest::update(&mut hasher, key_bytes);
    let result = hasher.finalize();
    result
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Extract raw SSH wire-format bytes from a public key.
fn get_public_key_bytes(key: &ssh_keys::PublicKey) -> Result<Vec<u8>, SshError> {
    let openssh = key.to_openssh().map_err(|_| SshError::ChannelFailed)?;
    let parts: Vec<&str> = openssh.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(SshError::ChannelFailed);
    }
    BASE64_STANDARD
        .decode(parts[1])
        .map_err(|_| SshError::ChannelFailed)
}

// ============================================================================
// Known-hosts file verification
// ============================================================================

/// Check a server key against a known_hosts file using russh_keys.
fn check_known_hosts_file(
    key: &ssh_keys::PublicKey,
    hostname: &str,
    port: u16,
    path: &Path,
) -> Result<bool, SshError> {
    match ssh_keys::known_hosts::check_known_hosts_path(hostname, port, key, path) {
        Ok(true) => {
            debug!("SSH host key verified via known_hosts for {}:{}", hostname, port);
            Ok(true)
        }
        Ok(false) => {
            warn!("SSH host key mismatch in known_hosts for {}:{}", hostname, port);
            Err(SshError::HostKeyMismatch)
        }
        Err(e) => {
            let err_str = format!("{}", e);
            if err_str.contains("not found") || err_str.contains("NoHomeDir") {
                debug!("Host not in known_hosts for {}:{}: {}", hostname, port, e);
                Err(SshError::HostKeyUnknown)
            } else {
                warn!("Known-hosts check failed for {}:{}: {}", hostname, port, e);
                Err(SshError::HostKeyMismatch)
            }
        }
    }
}

// ============================================================================
// SshClientHandler — russh Handler implementation
// ============================================================================

/// SSH client handler implementing the `russh::client::Handler` trait.
///
/// Handles host key verification and SSH banner display during the
/// SSH handshake phase.
pub struct SshClientHandler {
    known_hosts_file: Option<PathBuf>,
    host_public_key_sha256: Option<String>,
    host_public_key_md5: Option<String>,
    hostname: String,
    port: u16,
}

impl SshClientHandler {
    /// Create a new SSH client handler with verification configuration.
    pub fn new(
        known_hosts_file: Option<PathBuf>,
        host_public_key_sha256: Option<String>,
        host_public_key_md5: Option<String>,
        hostname: String,
        port: u16,
    ) -> Self {
        SshClientHandler {
            known_hosts_file,
            host_public_key_sha256,
            host_public_key_md5,
            hostname,
            port,
        }
    }

    /// Synchronous host key verification.
    ///
    /// Checks in order (matching C `ssh_state_hostkey()` in libssh2.c):
    /// 1. SHA-256 fingerprint if configured
    /// 2. MD5 fingerprint if configured
    /// 3. Known-hosts file if configured
    /// 4. Accept by default if no checks configured
    fn verify_key_sync(&self, key: &ssh_keys::PublicKey) -> Result<bool, SshError> {
        let key_bytes = get_public_key_bytes(key)?;

        // 1. Check SHA-256 fingerprint
        if let Some(ref expected_sha256) = self.host_public_key_sha256 {
            let computed = compute_sha256_fingerprint(&key_bytes);
            if computed != *expected_sha256 {
                warn!(
                    "SSH host key SHA-256 mismatch for {}:{} (expected: {}, got: {})",
                    self.hostname, self.port, expected_sha256, computed
                );
                return Err(SshError::HostKeyMismatch);
            }
            debug!("SSH host key SHA-256 verified for {}:{}", self.hostname, self.port);
            return Ok(true);
        }

        // 2. Check MD5 fingerprint
        if let Some(ref expected_md5) = self.host_public_key_md5 {
            let computed = compute_md5_fingerprint(&key_bytes);
            let expected_clean = expected_md5.replace(':', "").to_lowercase();
            let computed_clean = computed.replace(':', "").to_lowercase();
            if expected_clean != computed_clean {
                warn!(
                    "SSH host key MD5 mismatch for {}:{} (expected: {}, got: {})",
                    self.hostname, self.port, expected_md5, computed
                );
                return Err(SshError::HostKeyMismatch);
            }
            debug!("SSH host key MD5 verified for {}:{}", self.hostname, self.port);
            return Ok(true);
        }

        // 3. Check known_hosts file
        if let Some(ref kh_path) = self.known_hosts_file {
            return check_known_hosts_file(key, &self.hostname, self.port, kh_path);
        }

        // 4. No verification configured — accept by default (curl 8.x behavior)
        debug!(
            "No SSH host key verification configured, accepting for {}:{}",
            self.hostname, self.port
        );
        Ok(true)
    }

    /// Public wrapper for host key verification.
    pub fn check_server_key_sync(&self, key: &ssh_keys::PublicKey) -> Result<bool, SshError> {
        self.verify_key_sync(key)
    }

    /// Log an SSH server authentication banner.
    pub fn auth_banner_log(&self, banner: &str) {
        info!(target: "ssh", "SSH banner from {}:{}: {}", self.hostname, self.port, banner.trim());
    }
}

impl client::Handler for SshClientHandler {
    type Error = SshError;

    fn check_server_key(
        &mut self,
        server_public_key: &ssh_keys::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let result = self.verify_key_sync(server_public_key);
        std::future::ready(result)
    }

    fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut client::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        self.auth_banner_log(banner);
        std::future::ready(Ok(()))
    }
}

// ============================================================================
// SshSession — SSH session state
// ============================================================================

/// SSH session state wrapping the russh client handle.
pub struct SshSession {
    /// russh client handle. `None` before `ssh_connect()`.
    pub handle: Option<Handle<SshClientHandler>>,
    /// Current state machine position.
    pub state: SshState,
    /// Whether authentication completed successfully.
    pub authed: bool,
    /// Remote home directory.
    pub homedir: String,
    /// Authentication methods offered by the server.
    pub server_auth_methods: SshAuthMethod,
    /// Server host key fingerprint (SHA-256 bytes).
    pub fingerprint: Option<Vec<u8>>,
}

impl SshSession {
    /// Create a new unconnected SSH session.
    pub fn new() -> Self {
        SshSession {
            handle: None,
            state: SshState::NoState,
            authed: false,
            homedir: String::new(),
            server_auth_methods: SshAuthMethod::empty(),
            fingerprint: None,
        }
    }

    /// Get a mutable reference to the session handle.
    fn handle_mut(&mut self) -> Result<&mut Handle<SshClientHandler>, SshError> {
        self.handle.as_mut().ok_or(SshError::ConnectionLost)
    }
}

impl Default for SshSession {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SshSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshSession")
            .field("state", &self.state)
            .field("authed", &self.authed)
            .field("homedir", &self.homedir)
            .field("server_auth_methods", &self.server_auth_methods)
            .field("has_handle", &self.handle.is_some())
            .finish()
    }
}

// ============================================================================
// verify_host_key — Public host key verification API
// ============================================================================

/// Verify an SSH server host key against configured expectations.
///
/// Checks are performed in order (matching C `ssh_state_hostkey()`):
/// 1. SHA-256 fingerprint if `host_public_key_sha256` is set
/// 2. MD5 fingerprint if `host_public_key_md5` is set
/// 3. Known-hosts file if `known_hosts_file` is set
/// 4. Accept by default if no checks are configured
///
/// # Returns
/// - `Ok(true)` if the key is accepted
/// - `Err(SshError::HostKeyMismatch)` if key doesn't match
/// - `Err(SshError::HostKeyUnknown)` if host not in known_hosts
pub fn verify_host_key(
    key: &ssh_keys::PublicKey,
    hostname: &str,
    port: u16,
    config: &SshAuthConfig,
) -> Result<bool, SshError> {
    let key_bytes = get_public_key_bytes(key)?;

    // SHA-256 fingerprint check
    if let Some(ref expected_sha256) = config.host_public_key_sha256 {
        let computed = compute_sha256_fingerprint(&key_bytes);
        if computed != *expected_sha256 {
            return Err(SshError::HostKeyMismatch);
        }
        return Ok(true);
    }

    // MD5 fingerprint check
    if let Some(ref expected_md5) = config.host_public_key_md5 {
        let computed = compute_md5_fingerprint(&key_bytes);
        let expected_clean = expected_md5.replace(':', "").to_lowercase();
        let computed_clean = computed.replace(':', "").to_lowercase();
        if expected_clean != computed_clean {
            return Err(SshError::HostKeyMismatch);
        }
        return Ok(true);
    }

    // Known-hosts file check
    if let Some(ref kh_path) = config.known_hosts_file {
        return check_known_hosts_file(key, hostname, port, kh_path);
    }

    // No verification configured — accept (curl 8.x default)
    Ok(true)
}

// ============================================================================
// Authentication flow
// ============================================================================

/// Convert russh `MethodSet` to our `SshAuthMethod` bitflags.
fn method_set_to_auth_method(methods: &MethodSet) -> SshAuthMethod {
    let mut result = SshAuthMethod::empty();
    for kind in methods.iter() {
        match kind {
            MethodKind::PublicKey => result |= SshAuthMethod::PUBLICKEY,
            MethodKind::Password => result |= SshAuthMethod::PASSWORD,
            MethodKind::HostBased => result |= SshAuthMethod::HOST,
            MethodKind::KeyboardInteractive => result |= SshAuthMethod::KEYBOARD_INTERACTIVE,
            _ => {}
        }
    }
    result
}

/// Discover SSH key file paths, matching C behavior in libssh2.c lines 1068-1120.
///
/// Priority:
/// 1. If `config.private_key_file` is set, use that directly
/// 2. Try `~/.ssh/id_rsa`
/// 3. Try `~/.ssh/id_dsa`
/// 4. Try `id_rsa` in current working directory
fn discover_key_files(config: &SshAuthConfig) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    // User-specified key file takes priority
    if let Some(ref key_path) = config.private_key_file {
        candidates.push(key_path.clone());
        return candidates;
    }

    // Try standard locations
    if let Some(home) = home_dir() {
        let ssh_dir = home.join(".ssh");
        let id_rsa = ssh_dir.join("id_rsa");
        if id_rsa.exists() {
            candidates.push(id_rsa);
        }
        let id_dsa = ssh_dir.join("id_dsa");
        if id_dsa.exists() {
            candidates.push(id_dsa);
        }
        let id_ecdsa = ssh_dir.join("id_ecdsa");
        if id_ecdsa.exists() {
            candidates.push(id_ecdsa);
        }
        let id_ed25519 = ssh_dir.join("id_ed25519");
        if id_ed25519.exists() {
            candidates.push(id_ed25519);
        }
    }

    // Fallback: current directory
    let cwd_rsa = PathBuf::from("id_rsa");
    if cwd_rsa.exists() {
        candidates.push(cwd_rsa);
    }

    candidates
}

/// Get the user's home directory.
fn home_dir() -> Option<PathBuf> {
    env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .or({
            #[cfg(unix)]
            {
                // Fallback to /etc/passwd entry if HOME not set
                None
            }
            #[cfg(not(unix))]
            {
                None
            }
        })
}

/// Attempt public key authentication using key files.
///
/// Tries each discovered key file in order. Matches C
/// `ssh_state_auth_pkey_init()` and `ssh_state_auth_pkey()` in libssh2.c.
async fn try_pubkey_auth(
    session: &mut SshSession,
    config: &SshAuthConfig,
) -> Result<bool, SshError> {
    let key_files = discover_key_files(config);
    if key_files.is_empty() {
        debug!("No SSH key files found for public key authentication");
        return Ok(false);
    }

    for key_path in &key_files {
        trace!("Trying SSH public key auth with: {}", key_path.display());
        let passphrase = config.passphrase.as_deref();

        // Load the private key from file
        let key = match ssh_keys::load_secret_key(key_path, passphrase) {
            Ok(k) => k,
            Err(e) => {
                debug!("Failed to load key {}: {}", key_path.display(), e);
                continue;
            }
        };

        // Determine best hash algorithm for RSA keys
        let hash_alg = match session.handle_mut()?.best_supported_rsa_hash().await {
            Ok(Some(alg)) => alg,    // Some(Option<HashAlg>)
            Ok(None) | Err(_) => None,
        };

        let key_with_hash = ssh_keys::key::PrivateKeyWithHashAlg::new(
            Arc::new(key),
            hash_alg,
        );

        let result = session
            .handle_mut()?
            .authenticate_publickey(config.username.clone(), key_with_hash)
            .await;

        match result {
            Ok(ref auth) if auth.success() => {
                info!("SSH public key auth succeeded with {}", key_path.display());
                session.authed = true;
                return Ok(true);
            }
            Ok(russh::client::AuthResult::Failure { remaining_methods, .. }) => {
                debug!(
                    "SSH public key auth failed with {}, remaining: {:?}",
                    key_path.display(),
                    remaining_methods
                );
                session.server_auth_methods = method_set_to_auth_method(&remaining_methods);
            }
            Err(e) => {
                debug!("SSH public key auth error with {}: {}", key_path.display(), e);
            }
            _ => {}
        }
    }

    Ok(false)
}

/// Attempt SSH agent authentication.
///
/// Connects to the SSH agent, lists identities, and tries each one.
/// Matches C `ssh_state_auth_agent_*` states in libssh2.c.
#[cfg(unix)]
async fn try_agent_auth(
    session: &mut SshSession,
    config: &SshAuthConfig,
) -> Result<bool, SshError> {
    use ssh_keys::agent::client::AgentClient;

    // Connect to SSH agent
    let mut agent = match AgentClient::connect_env().await {
        Ok(a) => a,
        Err(e) => {
            debug!("Failed to connect to SSH agent: {}", e);
            return Ok(false);
        }
    };

    // Get available identities
    let identities = match agent.request_identities().await {
        Ok(ids) => ids,
        Err(e) => {
            debug!("Failed to list SSH agent identities: {}", e);
            return Ok(false);
        }
    };

    if identities.is_empty() {
        debug!("SSH agent has no identities");
        return Ok(false);
    }

    debug!("SSH agent has {} identities, trying each", identities.len());

    for identity in &identities {
        trace!("Trying SSH agent identity: {:?}", identity.algorithm());

        // authenticate_publickey_with takes ssh_key::PublicKey, Option<HashAlg>, &mut Signer
        let result = session
            .handle_mut()?
            .authenticate_publickey_with(
                config.username.clone(),
                identity.clone(),
                None,
                &mut agent,
            )
            .await;

        match result {
            Ok(russh::client::AuthResult::Success) => {
                info!("SSH agent auth succeeded");
                session.authed = true;
                return Ok(true);
            }
            Ok(russh::client::AuthResult::Failure { remaining_methods, .. }) => {
                session.server_auth_methods = method_set_to_auth_method(&remaining_methods);
                debug!("SSH agent identity rejected, trying next");
            }
            Err(e) => {
                debug!("SSH agent auth error: {}", e);
            }
        }
    }

    Ok(false)
}

/// Agent auth stub for non-Unix platforms.
#[cfg(not(unix))]
async fn try_agent_auth(
    _session: &mut SshSession,
    _config: &SshAuthConfig,
) -> Result<bool, SshError> {
    debug!("SSH agent auth not available on this platform");
    Ok(false)
}

/// Attempt password authentication.
///
/// Matches C `ssh_state_auth_pass_init()` and `ssh_state_auth_pass()` in libssh2.c.
async fn try_password_auth(
    session: &mut SshSession,
    config: &SshAuthConfig,
) -> Result<bool, SshError> {
    let password = match config.password {
        Some(ref p) => p.clone(),
        None => return Ok(false),
    };

    trace!("Trying SSH password authentication");

    let result = session
        .handle_mut()?
        .authenticate_password(config.username.clone(), password)
        .await?;

    if result.success() {
        info!("SSH password auth succeeded");
        session.authed = true;
        Ok(true)
    } else {
        debug!("SSH password auth failed");
        Ok(false)
    }
}

/// Attempt keyboard-interactive authentication using password as response.
///
/// Matches C `ssh_state_auth_key_init()` and `ssh_state_auth_key()`.
async fn try_keyboard_interactive_auth(
    session: &mut SshSession,
    config: &SshAuthConfig,
) -> Result<bool, SshError> {
    let password = match config.password {
        Some(ref p) => p.clone(),
        None => return Ok(false),
    };

    trace!("Trying SSH keyboard-interactive authentication");

    // Start keyboard-interactive auth
    let response = match session
        .handle_mut()?
        .authenticate_keyboard_interactive_start(config.username.clone(), None::<String>)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            debug!("SSH keyboard-interactive start failed: {}", e);
            return Ok(false);
        }
    };

    // Handle the response
    match response {
        KeyboardInteractiveAuthResponse::Success => {
            info!("SSH keyboard-interactive auth succeeded (no prompts)");
            session.authed = true;
            Ok(true)
        }
        KeyboardInteractiveAuthResponse::Failure { .. } => {
            debug!("SSH keyboard-interactive auth rejected immediately");
            Ok(false)
        }
        KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
            // Respond with the password for each prompt
            let responses: Vec<String> = prompts.iter().map(|_| password.clone()).collect();
            let result = session
                .handle_mut()?
                .authenticate_keyboard_interactive_respond(responses)
                .await;

            match result {
                Ok(KeyboardInteractiveAuthResponse::Success) => {
                    info!("SSH keyboard-interactive auth succeeded");
                    session.authed = true;
                    Ok(true)
                }
                Ok(KeyboardInteractiveAuthResponse::Failure { .. }) => {
                    debug!("SSH keyboard-interactive auth failed");
                    Ok(false)
                }
                Ok(KeyboardInteractiveAuthResponse::InfoRequest { .. }) => {
                    // Multiple rounds of prompts — respond with empty for subsequent
                    debug!("SSH keyboard-interactive auth requested additional info (unsupported)");
                    Ok(false)
                }
                Err(e) => {
                    debug!("SSH keyboard-interactive respond error: {}", e);
                    Ok(false)
                }
            }
        }
    }
}

/// Perform the full SSH authentication flow.
///
/// Attempts authentication methods in curl 8.x priority order:
/// 1. Public key (from file)
/// 2. SSH agent
/// 3. Password
/// 4. Keyboard-interactive
/// 5. GSSAPI (not supported by russh — logged and skipped)
///
/// Matches the full auth chain from C libssh2.c lines 1571-1750.
pub async fn authenticate(
    session: &mut SshSession,
    config: &SshAuthConfig,
) -> Result<(), SshError> {
    set_ssh_state(session, SshState::AuthList);

    // Probe server for available auth methods via none auth
    let probe_result = session
        .handle_mut()?
        .authenticate_none(config.username.clone())
        .await?;

    match probe_result {
        russh::client::AuthResult::Success => {
            info!("SSH none auth accepted (server allows anonymous access)");
            session.authed = true;
            set_ssh_state(session, SshState::AuthDone);
            return Ok(());
        }
        russh::client::AuthResult::Failure { remaining_methods, .. } => {
            session.server_auth_methods = method_set_to_auth_method(&remaining_methods);
            debug!("SSH server auth methods: {:?}", session.server_auth_methods);
        }
    }

    // 1. Public key authentication
    if session.server_auth_methods.contains(SshAuthMethod::PUBLICKEY)
        && config.allowed_methods.contains(SshAuthMethod::PUBLICKEY)
    {
        set_ssh_state(session, SshState::AuthPkeyInit);
        if try_pubkey_auth(session, config).await? {
            set_ssh_state(session, SshState::AuthDone);
            return Ok(());
        }
    }

    // 2. SSH agent authentication
    if config.ssh_agent && config.allowed_methods.contains(SshAuthMethod::AGENT) {
        set_ssh_state(session, SshState::AuthAgentInit);
        if try_agent_auth(session, config).await? {
            set_ssh_state(session, SshState::AuthDone);
            return Ok(());
        }
    }

    // 3. Password authentication
    if session.server_auth_methods.contains(SshAuthMethod::PASSWORD)
        && config.allowed_methods.contains(SshAuthMethod::PASSWORD)
    {
        set_ssh_state(session, SshState::AuthPassInit);
        if try_password_auth(session, config).await? {
            set_ssh_state(session, SshState::AuthDone);
            return Ok(());
        }
    }

    // 4. Keyboard-interactive authentication
    if session
        .server_auth_methods
        .contains(SshAuthMethod::KEYBOARD_INTERACTIVE)
        && config
            .allowed_methods
            .contains(SshAuthMethod::KEYBOARD_INTERACTIVE)
    {
        set_ssh_state(session, SshState::AuthKeyInit);
        if try_keyboard_interactive_auth(session, config).await? {
            set_ssh_state(session, SshState::AuthDone);
            return Ok(());
        }
    }

    // 5. GSSAPI authentication — not supported by russh
    if config.allowed_methods.contains(SshAuthMethod::GSSAPI) {
        debug!("SSH GSSAPI auth requested but not supported by russh");
    }

    // All methods exhausted
    error!("SSH authentication failed — all methods exhausted");
    Err(SshError::AuthFailed)
}

// ============================================================================
// SSH session lifecycle
// ============================================================================

/// Establish a complete SSH connection: TCP connect, handshake,
/// host key verification, and authentication.
///
/// This is the high-level entry point that orchestrates the full SSH
/// connection flow. Replaces C `ssh_setup_connection()` + `ssh_connect()`
/// in libssh2.c.
pub async fn ssh_connect(
    session: &mut SshSession,
    host: &str,
    port: u16,
    config: &SshAuthConfig,
) -> CurlResult<()> {
    set_ssh_state(session, SshState::Init);
    info!("SSH connecting to {}:{}", host, port);

    // Create the handler with verification config
    let handler = SshClientHandler::new(
        config.known_hosts_file.clone(),
        config.host_public_key_sha256.clone(),
        config.host_public_key_md5.clone(),
        host.to_string(),
        port,
    );

    // Create default SSH client configuration
    let ssh_config = Arc::new(client::Config::default());

    // Perform TCP connect + SSH handshake (includes host key verification
    // via the Handler callback)
    set_ssh_state(session, SshState::Startup);
    let handle = client::connect(ssh_config, (host, port), handler)
        .await
        .map_err(CurlError::from)?;

    session.handle = Some(handle);
    set_ssh_state(session, SshState::Hostkey);

    // Perform authentication
    authenticate(session, config)
        .await
        .map_err(CurlError::from)?;

    info!("SSH connection established to {}:{}", host, port);
    Ok(())
}

/// Disconnect an SSH session gracefully.
///
/// Sends SSH disconnect and drops the handle. Replaces C
/// `ssh_state_session_disconnect()` + `ssh_state_session_free()`
/// in libssh2.c lines 2376-2470.
pub async fn ssh_disconnect(session: &mut SshSession) -> CurlResult<()> {
    set_ssh_state(session, SshState::SessionDisconnect);
    debug!("SSH disconnecting");

    if let Some(ref handle) = session.handle {
        let _ = handle
            .disconnect(Disconnect::ByApplication, "curl-rs disconnect", "en")
            .await;
    }

    set_ssh_state(session, SshState::SessionFree);
    session.handle = None;
    session.authed = false;
    session.state = SshState::Stop;

    debug!("SSH session freed");
    Ok(())
}

/// Return the SSH library version string.
///
/// Replaces C `Curl_ssh_version()` in libssh2.c.
pub fn ssh_version() -> &'static str {
    SSH_VERSION_STRING
}

// ============================================================================
// Path utilities — from vssh.c
// ============================================================================

/// Compute the working path for SSH operations.
///
/// URL-decodes the path and applies `/~/` home-relative rewriting:
/// - For SCP: strips `/~/` prefix (home-relative → relative path)
/// - For SFTP: replaces `/~/` with `homedir/` prefix
///
/// Matches C `Curl_getworkingpath()` in `vssh.c` lines 128-196.
///
/// # Arguments
/// - `url_path`: The URL-encoded path from the request URL
/// - `homedir`: The remote home directory
/// - `protocol`: SFTP or SCP, determines `/~/` rewriting behavior
///
/// # Errors
/// - `CurlError::OutOfMemory` if path exceeds `MAX_SSHPATH_LEN`
/// - `CurlError::UrlMalformat` if path contains null bytes
pub fn get_working_path(
    url_path: &str,
    homedir: &str,
    protocol: SshProtocol,
) -> CurlResult<String> {
    // URL-decode the path
    let decoded_bytes = url_decode(url_path)?;

    // Reject null bytes (matches C REJECT_ZERO flag)
    if decoded_bytes.contains(&0) {
        return Err(CurlError::UrlMalformat);
    }

    let decoded = String::from_utf8(decoded_bytes).map_err(|_| CurlError::UrlMalformat)?;

    // Check max path length
    if decoded.len() > MAX_SSHPATH_LEN {
        return Err(CurlError::OutOfMemory);
    }

    match protocol {
        SshProtocol::Scp => {
            // For SCP: strip /~/ prefix for home-relative paths
            if let Some(remainder) = decoded.strip_prefix("/~/") {
                // Strip leading /~/ — remainder is relative to home
                Ok(remainder.to_string())
            } else if decoded == "/~" {
                // Just home directory
                Ok(String::new())
            } else if let Some(stripped) = decoded.strip_prefix('/') {
                // Absolute path — strip leading / for relative
                Ok(stripped.to_string())
            } else {
                Ok(decoded)
            }
        }
        SshProtocol::Sftp => {
            // For SFTP: replace /~/ with homedir prefix
            if let Some(remainder) = decoded.strip_prefix("/~/") {
                let mut result = DynBuf::with_max(MAX_SSHPATH_LEN);
                result
                    .add_str(homedir)
                    .map_err(|_| CurlError::OutOfMemory)?;
                if !homedir.ends_with('/') && !remainder.is_empty() {
                    result.add_str("/").map_err(|_| CurlError::OutOfMemory)?;
                }
                result
                    .add_str(remainder)
                    .map_err(|_| CurlError::OutOfMemory)?;
                let path = std::str::from_utf8(result.as_bytes())
                    .map_err(|_| CurlError::UrlMalformat)?
                    .to_string();
                Ok(path)
            } else if decoded == "/~" {
                // Just the home directory
                let mut result = DynBuf::with_max(MAX_SSHPATH_LEN);
                result
                    .add_str(homedir)
                    .map_err(|_| CurlError::OutOfMemory)?;
                result.add_str("/").map_err(|_| CurlError::OutOfMemory)?;
                let path = std::str::from_utf8(result.as_bytes())
                    .map_err(|_| CurlError::UrlMalformat)?
                    .to_string();
                Ok(path)
            } else {
                // Absolute path — use as-is
                Ok(decoded)
            }
        }
    }
}

/// Parse a pathname argument from an SSH QUOTE command string.
///
/// Handles quoted strings (single/double quotes) with escape sequences,
/// unquoted words, and `/~/` home-directory expansion.
///
/// Matches C `Curl_get_pathname()` in `vssh.c` lines 200-285.
///
/// # Arguments
/// - `input`: The command argument string to parse
/// - `homedir`: Home directory for `/~/` expansion
///
/// # Returns
/// A tuple of (parsed_path, bytes_consumed) on success.
///
/// # Errors
/// - `CurlError::QuoteError` for malformed paths or unterminated quotes
/// - `CurlError::TooLarge` if path exceeds `MAX_PATHLENGTH`
pub fn get_pathname(input: &str, homedir: &str) -> CurlResult<(String, usize)> {
    let bytes = input.as_bytes();
    let len = bytes.len();

    // Skip leading whitespace
    let mut pos = 0;
    while pos < len && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
        pos += 1;
    }

    if pos >= len {
        return Err(CurlError::QuoteError);
    }

    let _start_pos = pos;

    match bytes[pos] {
        // Double-quoted string
        b'"' => {
            pos += 1; // skip opening quote
            let mut result = DynBuf::with_max(MAX_PATHLENGTH);
            while pos < len {
                if bytes[pos] == b'\\' && pos + 1 < len {
                    // Escape sequences: \\ -> \, \" -> "
                    let next = bytes[pos + 1];
                    if next == b'\\' || next == b'"' {
                        result.add(&[next]).map_err(|_| CurlError::TooLarge)?;
                        pos += 2;
                        continue;
                    }
                }
                if bytes[pos] == b'"' {
                    // Closing quote found
                    pos += 1;
                    let path = std::str::from_utf8(result.as_bytes())
                        .map_err(|_| CurlError::QuoteError)?
                        .to_string();
                    if path.len() > MAX_PATHLENGTH {
                        return Err(CurlError::TooLarge);
                    }
                    return Ok((path, pos));
                }
                result
                    .add(&[bytes[pos]])
                    .map_err(|_| CurlError::TooLarge)?;
                pos += 1;
            }
            // Unterminated double quote
            Err(CurlError::QuoteError)
        }
        // Single-quoted string
        b'\'' => {
            pos += 1; // skip opening quote
            let mut result = DynBuf::with_max(MAX_PATHLENGTH);
            while pos < len {
                if bytes[pos] == b'\\' && pos + 1 < len {
                    // Escape sequences: \\ -> \, \' -> '
                    let next = bytes[pos + 1];
                    if next == b'\\' || next == b'\'' {
                        result.add(&[next]).map_err(|_| CurlError::TooLarge)?;
                        pos += 2;
                        continue;
                    }
                }
                if bytes[pos] == b'\'' {
                    // Closing quote found
                    pos += 1;
                    let path = std::str::from_utf8(result.as_bytes())
                        .map_err(|_| CurlError::QuoteError)?
                        .to_string();
                    if path.len() > MAX_PATHLENGTH {
                        return Err(CurlError::TooLarge);
                    }
                    return Ok((path, pos));
                }
                result
                    .add(&[bytes[pos]])
                    .map_err(|_| CurlError::TooLarge)?;
                pos += 1;
            }
            // Unterminated single quote
            Err(CurlError::QuoteError)
        }
        // Unquoted word
        _ => {
            let word_start = pos;
            while pos < len && bytes[pos] != b' ' && bytes[pos] != b'\t' {
                pos += 1;
            }
            let word = std::str::from_utf8(&bytes[word_start..pos])
                .map_err(|_| CurlError::QuoteError)?;

            if word.len() > MAX_PATHLENGTH {
                return Err(CurlError::TooLarge);
            }

            // Apply /~/ home-directory expansion for unquoted paths
            let expanded = if let Some(remainder) = word.strip_prefix("/~/") {
                let mut buf = String::with_capacity(homedir.len() + 1 + remainder.len());
                buf.push_str(homedir);
                if !homedir.ends_with('/') && !remainder.is_empty() {
                    buf.push('/');
                }
                buf.push_str(remainder);
                buf
            } else if word == "/~" {
                let mut buf = String::with_capacity(homedir.len() + 1);
                buf.push_str(homedir);
                buf.push('/');
                buf
            } else {
                word.to_string()
            };

            if expanded.len() > MAX_PATHLENGTH {
                return Err(CurlError::TooLarge);
            }

            Ok((expanded, pos))
        }
    }
}

/// Parse a byte range for partial SSH transfers.
///
/// Supported formats:
/// - `"from-to"` — download bytes from `from` to `to` inclusive
/// - `"from-"` — download from `from` to end of file
/// - `"-N"` — download the last `N` bytes
///
/// Matches C `Curl_ssh_range()` in `vssh.c` lines 287-331.
///
/// # Arguments
/// - `range_str`: The range specification string
/// - `total_size`: Total file size for clamping and last-N computation
///
/// # Returns
/// A tuple of (from, to) byte offsets (inclusive), or error.
pub fn ssh_range(range_str: &str, total_size: u64) -> CurlResult<(u64, u64)> {
    let trimmed = range_str.trim();
    if trimmed.is_empty() {
        return Err(CurlError::RangeError);
    }

    if let Some(stripped) = trimmed.strip_prefix('-') {
        // "-N" format: last N bytes
        let n: u64 = stripped.parse().map_err(|_| CurlError::RangeError)?;
        if n == 0 || n > total_size {
            return Err(CurlError::RangeError);
        }
        let from = total_size - n;
        let to = total_size - 1;
        return Ok((from, to));
    }

    if let Some(dash_pos) = trimmed.find('-') {
        let from_str = &trimmed[..dash_pos];
        let to_str = &trimmed[dash_pos + 1..];

        let from: u64 = from_str.parse().map_err(|_| CurlError::RangeError)?;

        if to_str.is_empty() {
            // "from-" format: from to end
            if from >= total_size {
                return Err(CurlError::RangeError);
            }
            return Ok((from, total_size - 1));
        }

        // "from-to" format
        let mut to: u64 = to_str.parse().map_err(|_| CurlError::RangeError)?;

        // Clamp to to file size
        if to >= total_size {
            to = total_size - 1;
        }

        if from > to || from >= total_size {
            return Err(CurlError::RangeError);
        }

        return Ok((from, to));
    }

    Err(CurlError::RangeError)
}

// ============================================================================
// Scheme descriptors — matching C Curl_scheme_sftp and Curl_scheme_scp
// ============================================================================

/// SFTP protocol scheme descriptor.
///
/// Matches C `Curl_scheme_sftp` in `vssh.c` lines 338-350:
/// - name: "SFTP"
/// - default_port: 22
/// - flags: DIRLOCK | CLOSEACTION | NOURLQUERY | CONN_REUSE
/// - uses_tls: false
pub const SFTP_SCHEME: Scheme = Scheme {
    name: "SFTP",
    default_port: PORT_SSH,
    flags: ProtocolFlags::from_bits(
        ProtocolFlags::CLOSEACTION.bits()
            | ProtocolFlags::CONN_REUSE.bits()
            | SSH_FLAG_DIRLOCK.bits()
            | SSH_FLAG_NOURLQUERY.bits(),
    ),
    uses_tls: false,
};

/// SCP protocol scheme descriptor.
///
/// Matches C `Curl_scheme_scp` in `vssh.c` lines 353-365:
/// - name: "SCP"
/// - default_port: 22
/// - flags: DIRLOCK | CLOSEACTION | NOURLQUERY | CONN_REUSE
/// - uses_tls: false
pub const SCP_SCHEME: Scheme = Scheme {
    name: "SCP",
    default_port: PORT_SSH,
    flags: ProtocolFlags::from_bits(
        ProtocolFlags::CLOSEACTION.bits()
            | ProtocolFlags::CONN_REUSE.bits()
            | SSH_FLAG_DIRLOCK.bits()
            | SSH_FLAG_NOURLQUERY.bits(),
    ),
    uses_tls: false,
};

// ============================================================================
// State machine debug helpers
// ============================================================================

/// Return a human-readable name for an SSH state.
///
/// Matches C `Curl_ssh_statename()` in `vssh.c` lines 29-100.
pub fn ssh_state_name(state: &SshState) -> &'static str {
    match state {
        SshState::NoState => "SSH_NO_STATE",
        SshState::Stop => "SSH_STOP",
        SshState::Init => "SSH_INIT",
        SshState::Startup => "SSH_S_STARTUP",
        SshState::Hostkey => "SSH_HOSTKEY",
        SshState::AuthList => "SSH_AUTHLIST",
        SshState::AuthPkeyInit => "SSH_AUTH_PKEY_INIT",
        SshState::AuthPkey => "SSH_AUTH_PKEY",
        SshState::AuthPassInit => "SSH_AUTH_PASS_INIT",
        SshState::AuthPass => "SSH_AUTH_PASS",
        SshState::AuthAgentInit => "SSH_AUTH_AGENT_INIT",
        SshState::AuthAgentList => "SSH_AUTH_AGENT_LIST",
        SshState::AuthAgent => "SSH_AUTH_AGENT",
        SshState::AuthHostInit => "SSH_AUTH_HOST_INIT",
        SshState::AuthHost => "SSH_AUTH_HOST",
        SshState::AuthKeyInit => "SSH_AUTH_KEY_INIT",
        SshState::AuthKey => "SSH_AUTH_KEY",
        SshState::AuthGssapi => "SSH_AUTH_GSSAPI",
        SshState::AuthDone => "SSH_AUTH_DONE",
        SshState::Sftp(sftp_state) => sftp_state.state_name(),
        SshState::Scp(scp_state) => scp_state.state_name(),
        SshState::SessionDisconnect => "SSH_SESSION_DISCONNECT",
        SshState::SessionFree => "SSH_SESSION_FREE",
        SshState::Quit => "SSH_QUIT",
    }
}

/// Set the SSH session state with debug logging.
///
/// Logs the state transition and updates `session.state`.
/// Matches C `Curl_ssh_set_state()` in `vssh.c` lines 102-125.
pub fn set_ssh_state(session: &mut SshSession, new_state: SshState) {
    if session.state != new_state {
        trace!(
            "SSH state: {} -> {}",
            ssh_state_name(&session.state),
            ssh_state_name(&new_state)
        );
        session.state = new_state;
    }
}

// ============================================================================
// Module-level suppression of unused import warnings during incremental build.
// The following items are used by submodules and external callers:
// - ConnectionData: used by sftp.rs and scp.rs for Protocol trait
// - DynBuf: used in get_working_path and get_pathname
// - url_decode: used in get_working_path
// ============================================================================
#[allow(unused)]
fn _ensure_imports_used() {
    let _ = std::mem::size_of::<ConnectionData>();
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SshProtocol tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssh_protocol_display_sftp() {
        assert_eq!(format!("{}", SshProtocol::Sftp), "SFTP");
    }

    #[test]
    fn test_ssh_protocol_display_scp() {
        assert_eq!(format!("{}", SshProtocol::Scp), "SCP");
    }

    // -----------------------------------------------------------------------
    // SshState tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssh_state_default_is_no_state() {
        assert_eq!(SshState::default(), SshState::NoState);
    }

    #[test]
    fn test_ssh_state_equality() {
        assert_eq!(SshState::Init, SshState::Init);
        assert_ne!(SshState::Init, SshState::Stop);
    }

    #[test]
    fn test_ssh_state_name_no_state() {
        assert_eq!(ssh_state_name(&SshState::NoState), "SSH_NO_STATE");
    }

    #[test]
    fn test_ssh_state_name_stop() {
        assert_eq!(ssh_state_name(&SshState::Stop), "SSH_STOP");
    }

    #[test]
    fn test_ssh_state_name_auth_variants() {
        assert_eq!(ssh_state_name(&SshState::AuthList), "SSH_AUTHLIST");
        assert_eq!(ssh_state_name(&SshState::AuthPkeyInit), "SSH_AUTH_PKEY_INIT");
        assert_eq!(ssh_state_name(&SshState::AuthPkey), "SSH_AUTH_PKEY");
        assert_eq!(ssh_state_name(&SshState::AuthPassInit), "SSH_AUTH_PASS_INIT");
        assert_eq!(ssh_state_name(&SshState::AuthPass), "SSH_AUTH_PASS");
        assert_eq!(ssh_state_name(&SshState::AuthDone), "SSH_AUTH_DONE");
    }

    #[test]
    fn test_ssh_state_name_lifecycle() {
        assert_eq!(ssh_state_name(&SshState::Init), "SSH_INIT");
        assert_eq!(ssh_state_name(&SshState::Startup), "SSH_S_STARTUP");
        assert_eq!(ssh_state_name(&SshState::Hostkey), "SSH_HOSTKEY");
        assert_eq!(ssh_state_name(&SshState::SessionDisconnect), "SSH_SESSION_DISCONNECT");
        assert_eq!(ssh_state_name(&SshState::SessionFree), "SSH_SESSION_FREE");
        assert_eq!(ssh_state_name(&SshState::Quit), "SSH_QUIT");
    }

    // -----------------------------------------------------------------------
    // SshAuthMethod tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssh_auth_method_empty() {
        let m = SshAuthMethod::empty();
        assert!(m.is_empty());
        assert!(!m.contains(SshAuthMethod::PUBLICKEY));
    }

    #[test]
    fn test_ssh_auth_method_all_contains_every_method() {
        let all = SshAuthMethod::all();
        assert!(all.contains(SshAuthMethod::PUBLICKEY));
        assert!(all.contains(SshAuthMethod::PASSWORD));
        assert!(all.contains(SshAuthMethod::HOST));
        assert!(all.contains(SshAuthMethod::KEYBOARD_INTERACTIVE));
        assert!(all.contains(SshAuthMethod::GSSAPI));
        assert!(all.contains(SshAuthMethod::AGENT));
        assert!(!all.is_empty());
    }

    #[test]
    fn test_ssh_auth_method_bitor() {
        let m = SshAuthMethod::PUBLICKEY | SshAuthMethod::PASSWORD;
        assert!(m.contains(SshAuthMethod::PUBLICKEY));
        assert!(m.contains(SshAuthMethod::PASSWORD));
        assert!(!m.contains(SshAuthMethod::GSSAPI));
    }

    #[test]
    fn test_ssh_auth_method_bitor_assign() {
        let mut m = SshAuthMethod::PUBLICKEY;
        m |= SshAuthMethod::AGENT;
        assert!(m.contains(SshAuthMethod::PUBLICKEY));
        assert!(m.contains(SshAuthMethod::AGENT));
    }

    #[test]
    fn test_ssh_auth_method_bitand() {
        let a = SshAuthMethod::PUBLICKEY | SshAuthMethod::PASSWORD;
        let b = SshAuthMethod::PASSWORD | SshAuthMethod::GSSAPI;
        let c = a & b;
        assert!(c.contains(SshAuthMethod::PASSWORD));
        assert!(!c.contains(SshAuthMethod::PUBLICKEY));
        assert!(!c.contains(SshAuthMethod::GSSAPI));
    }

    // -----------------------------------------------------------------------
    // SshAuthConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssh_auth_config_default() {
        let cfg = SshAuthConfig::default();
        assert!(cfg.username.is_empty());
        assert!(cfg.password.is_none());
        assert!(cfg.private_key_file.is_none());
        assert!(cfg.public_key_file.is_none());
        assert!(cfg.passphrase.is_none());
        assert!(cfg.known_hosts_file.is_none());
        assert!(cfg.host_public_key_sha256.is_none());
        assert!(cfg.host_public_key_md5.is_none());
        assert_eq!(cfg.allowed_methods, SshAuthMethod::all());
        assert!(cfg.ssh_agent);
    }

    // -----------------------------------------------------------------------
    // SshError tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssh_error_display() {
        let e = SshError::AuthFailed;
        let msg = format!("{}", e);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_ssh_error_into_curl_error() {
        let ce: CurlError = SshError::AuthFailed.into();
        assert!(matches!(ce, CurlError::LoginDenied));

        let ce2: CurlError = SshError::HostKeyMismatch.into();
        assert!(matches!(ce2, CurlError::PeerFailedVerification));

        let ce3: CurlError = SshError::ChannelFailed.into();
        assert!(matches!(ce3, CurlError::Ssh));
    }

    // -----------------------------------------------------------------------
    // SshSession tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssh_session_new() {
        let s = SshSession::new();
        assert!(s.handle.is_none());
        assert_eq!(s.state, SshState::NoState);
        assert!(!s.authed);
        assert!(s.homedir.is_empty());
        assert!(s.server_auth_methods.is_empty());
        assert!(s.fingerprint.is_none());
    }

    #[test]
    fn test_ssh_session_default_equals_new() {
        let s1 = SshSession::new();
        let s2 = SshSession::default();
        assert_eq!(s1.state, s2.state);
        assert_eq!(s1.authed, s2.authed);
        assert_eq!(s1.homedir, s2.homedir);
    }

    // -----------------------------------------------------------------------
    // set_ssh_state tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_set_ssh_state_changes_state() {
        let mut session = SshSession::new();
        assert_eq!(session.state, SshState::NoState);
        set_ssh_state(&mut session, SshState::Init);
        assert_eq!(session.state, SshState::Init);
    }

    #[test]
    fn test_set_ssh_state_same_state_is_noop() {
        let mut session = SshSession::new();
        set_ssh_state(&mut session, SshState::Init);
        set_ssh_state(&mut session, SshState::Init);
        assert_eq!(session.state, SshState::Init);
    }

    // -----------------------------------------------------------------------
    // ssh_version tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssh_version_is_not_empty() {
        let v = ssh_version();
        assert!(!v.is_empty());
        assert!(v.contains("russh"));
    }

    // -----------------------------------------------------------------------
    // get_working_path tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_working_path_sftp_home_relative() {
        let result = get_working_path("/~/Documents", "/home/user", SshProtocol::Sftp).unwrap();
        assert_eq!(result, "/home/user/Documents");
    }

    #[test]
    fn test_get_working_path_sftp_just_home() {
        let result = get_working_path("/~", "/home/user", SshProtocol::Sftp).unwrap();
        assert_eq!(result, "/home/user/");
    }

    #[test]
    fn test_get_working_path_sftp_absolute() {
        let result = get_working_path("/var/log/syslog", "/home/user", SshProtocol::Sftp).unwrap();
        assert_eq!(result, "/var/log/syslog");
    }

    #[test]
    fn test_get_working_path_scp_home_relative() {
        let result = get_working_path("/~/file.txt", "/home/user", SshProtocol::Scp).unwrap();
        assert_eq!(result, "file.txt");
    }

    #[test]
    fn test_get_working_path_scp_just_home() {
        let result = get_working_path("/~", "/home/user", SshProtocol::Scp).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_get_working_path_scp_absolute() {
        let result = get_working_path("/etc/hosts", "/home/user", SshProtocol::Scp).unwrap();
        assert_eq!(result, "etc/hosts");
    }

    #[test]
    fn test_get_working_path_rejects_null_bytes() {
        let result = get_working_path("/path%00evil", "/home/user", SshProtocol::Sftp);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // get_pathname tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_pathname_simple_word() {
        let (path, consumed) = get_pathname("myfile.txt rest", "/home").unwrap();
        assert_eq!(path, "myfile.txt");
        assert_eq!(consumed, 10);
    }

    #[test]
    fn test_get_pathname_quoted_string() {
        let (path, consumed) = get_pathname("\"my file.txt\" rest", "/home").unwrap();
        assert_eq!(path, "my file.txt");
        assert!(consumed > 0);
    }

    #[test]
    fn test_get_pathname_empty_input_fails() {
        let result = get_pathname("", "/home");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_pathname_whitespace_only_fails() {
        let result = get_pathname("   ", "/home");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // ssh_range tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssh_range_from_to() {
        let (from, to) = ssh_range("10-20", 100).unwrap();
        assert_eq!(from, 10);
        assert_eq!(to, 20);
    }

    #[test]
    fn test_ssh_range_from_end() {
        let (from, to) = ssh_range("50-", 100).unwrap();
        assert_eq!(from, 50);
        assert_eq!(to, 99);
    }

    #[test]
    fn test_ssh_range_last_n() {
        let (from, to) = ssh_range("-10", 100).unwrap();
        assert_eq!(from, 90);
        assert_eq!(to, 99);
    }

    #[test]
    fn test_ssh_range_to_clamped_to_file_size() {
        let (from, to) = ssh_range("0-999", 50).unwrap();
        assert_eq!(from, 0);
        assert_eq!(to, 49);
    }

    #[test]
    fn test_ssh_range_empty_is_error() {
        assert!(ssh_range("", 100).is_err());
    }

    #[test]
    fn test_ssh_range_last_n_exceeds_size_is_error() {
        assert!(ssh_range("-200", 100).is_err());
    }

    #[test]
    fn test_ssh_range_from_exceeds_size_is_error() {
        assert!(ssh_range("100-", 100).is_err());
    }

    #[test]
    fn test_ssh_range_inverted_is_error() {
        assert!(ssh_range("50-10", 100).is_err());
    }

    // -----------------------------------------------------------------------
    // Scheme constants tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sftp_scheme_constants() {
        assert_eq!(SFTP_SCHEME.name, "SFTP");
        assert_eq!(SFTP_SCHEME.default_port, 22);
    }

    #[test]
    fn test_scp_scheme_constants() {
        assert_eq!(SCP_SCHEME.name, "SCP");
        assert_eq!(SCP_SCHEME.default_port, 22);
    }

    #[test]
    fn test_port_ssh_constant() {
        assert_eq!(PORT_SSH, 22);
    }
}
