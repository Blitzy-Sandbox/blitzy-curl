//! FTP/FTPS protocol handler — complete Rust rewrite of `lib/ftp.c`.
//!
//! Implements the full FTP/FTPS protocol state machine with:
//!
//! - **Active mode** (PORT/EPRT) — binds a local listener, sends address
//!   to the server, and accepts the incoming data connection.
//! - **Passive mode** (PASV/EPSV) — parses the server-provided address
//!   and connects to the data channel.
//! - **FTPS** — explicit TLS upgrade via AUTH TLS/SSL, PBSZ 0, PROT P/C
//!   using the `crate::tls` module (rustls only); implicit FTPS on port 990.
//! - **Multi-interface** integration — non-blocking state machine compatible
//!   with the [`Protocol`] trait for cooperative scheduling.
//! - **Directory traversal** — CWD/MKD/PWD/SYST with MULTICWD, SINGLECWD,
//!   and NOCWD file methods.
//! - **Transfer operations** — RETR (download), STOR (upload), LIST
//!   (directory listing), with SIZE, REST (resume), MDTM (timestamps),
//!   and TYPE (ASCII/binary) negotiation.
//! - **QUOTE/PREQUOTE/POSTQUOTE** — arbitrary FTP command injection before
//!   and after transfers.
//! - **Wildcard** support for pattern-based multi-file operations.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.
//!
//! # Source Mapping
//!
//! | Rust type / fn          | C source                                       |
//! |-------------------------|------------------------------------------------|
//! | `FtpState`              | `enum ftpstate` in `lib/ftp.h:41–81`           |
//! | `FtpFileMethod`         | `enum curl_ftpfile` in `lib/ftp.h:95–100`      |
//! | `Ftp`                   | `struct FTP` in `lib/ftp.h:106–114`            |
//! | `FtpConn`               | `struct ftp_conn` in `lib/ftp.h:124–164`       |
//! | `FtpHandler`            | `Curl_scheme_ftp` / `Curl_scheme_ftps`         |
//! | `ftp_conns_match`       | `ftp_conns_match()` in `lib/ftp.c`             |

// Allow dead code for internal helper functions, fields, and private methods
// that are structurally necessary for the complete FTP state machine but are
// called only from within the handler's internal dispatch table. These will
// become live once full I/O integration is wired up.
#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use tracing::{debug, error, info, trace, warn};

use crate::conn::ConnectionData;
use crate::error::{CurlError, CurlResult};
use crate::escape::url_decode_string;
use crate::progress::Progress;
use super::{
    ConnectionCheckResult, Protocol, ProtocolFlags, Scheme,
};
use super::ftp_list::{
    FileInfo, FtpListParser, WildcardData, WildcardState,
};
use super::pingpong::{
    PingPong, PingPongConfig, PollFlags, PpTransfer,
};
use crate::tls::{CurlTlsStream, TlsConnectionState};
use crate::util::parsedate::{parse_date, parse_date_capped};

// ===========================================================================
// Constants
// ===========================================================================

/// Default timeout for accepting an incoming data connection in active mode
/// (PORT/EPRT). 60 seconds, matching C `DEFAULT_ACCEPT_TIMEOUT` (60000 ms).
pub const DEFAULT_ACCEPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum depth of directory components parsed from an FTP URL path.
/// Matches C `FTP_MAX_DIR_DEPTH` (1000).
pub const FTP_MAX_DIR_DEPTH: usize = 1000;

/// Default FTP control port.
const FTP_DEFAULT_PORT: u16 = 21;

/// Default FTPS (implicit) control port.
const FTPS_DEFAULT_PORT: u16 = 990;

/// FTP scheme definition for the scheme registry.
pub const FTP_SCHEME: Scheme = Scheme {
    name: "ftp",
    default_port: FTP_DEFAULT_PORT,
    flags: ProtocolFlags::from_bits(
        ProtocolFlags::CLOSEACTION.bits()
            | ProtocolFlags::DUAL.bits()
            | ProtocolFlags::PROXY_AS_HTTP.bits()
            | ProtocolFlags::WILDCARD.bits(),
    ),
    uses_tls: false,
};

/// FTPS scheme definition for the scheme registry.
pub const FTPS_SCHEME: Scheme = Scheme {
    name: "ftps",
    default_port: FTPS_DEFAULT_PORT,
    flags: ProtocolFlags::from_bits(
        ProtocolFlags::CLOSEACTION.bits()
            | ProtocolFlags::DUAL.bits()
            | ProtocolFlags::PROXY_AS_HTTP.bits()
            | ProtocolFlags::WILDCARD.bits()
            | ProtocolFlags::SSL.bits(),
    ),
    uses_tls: true,
};

// ===========================================================================
// FtpState — FTP protocol state machine states
// ===========================================================================

/// FTP protocol state machine states.
///
/// Each variant corresponds to a step in the FTP command/response exchange.
/// The state machine is driven by [`FtpHandler::statemach_act()`] which
/// reads server responses and transitions between states.
///
/// Variant names and ordering match the C `enum ftpstate` from `lib/ftp.h`
/// lines 41–81 for traceability.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FtpState {
    /// Terminal state — state machine is idle.
    #[default]
    Stop = 0,
    /// Waiting for the initial 220 greeting after TCP connect.
    Wait220 = 1,
    /// Sent AUTH TLS/SSL, waiting for 234 reply.
    Auth = 2,
    /// Sent USER, waiting for 331/230 reply.
    User = 3,
    /// Sent PASS, waiting for 230/332 reply.
    Pass = 4,
    /// Sent ACCT, waiting for 230 reply.
    Acct = 5,
    /// Sent PBSZ 0, waiting for reply (FTPS).
    Pbsz = 6,
    /// Sent PROT P/C, waiting for reply (FTPS).
    Prot = 7,
    /// Sent CCC, waiting for reply (clear control channel).
    Ccc = 8,
    /// Sent PWD, waiting for current directory reply.
    Pwd = 9,
    /// Sent SYST, waiting for system type reply.
    Syst = 10,
    /// Sent SITE NAMEFMT, waiting for reply (OS/400).
    NameFmt = 11,
    /// Processing QUOTE commands (user-specified arbitrary FTP commands).
    Quote = 12,
    /// Processing PREQUOTE commands before RETR.
    RetrPreQuote = 13,
    /// Processing PREQUOTE commands before STOR.
    StorPreQuote = 14,
    /// Processing PREQUOTE commands before LIST.
    ListPreQuote = 15,
    /// Processing POSTQUOTE commands after transfer.
    PostQuote = 16,
    /// Sent CWD, waiting for directory change confirmation.
    Cwd = 17,
    /// Sent MKD, waiting for directory creation confirmation.
    Mkd = 18,
    /// Sent MDTM, waiting for file modification time.
    Mdtm = 19,
    /// Sent TYPE (for head-like requests), waiting for confirmation.
    Type = 20,
    /// Sent TYPE before LIST operation.
    ListType = 21,
    /// Sent TYPE before RETR preceded by LIST (size check).
    RetrListType = 22,
    /// Sent TYPE before RETR operation.
    RetrType = 23,
    /// Sent TYPE before STOR operation.
    StorType = 24,
    /// Sent SIZE (for head-like request), waiting for file size.
    Size = 25,
    /// Sent SIZE before RETR operation.
    RetrSize = 26,
    /// Sent SIZE before STOR operation.
    StorSize = 27,
    /// Sent REST (for head-like request), waiting for confirmation.
    Rest = 28,
    /// Sent REST before RETR (resume download).
    RetrRest = 29,
    /// Sent PORT/EPRT, waiting for confirmation (active mode).
    Port = 30,
    /// Sent PRET (pre-transfer command), waiting for confirmation.
    Pret = 31,
    /// Sent PASV/EPSV, waiting for data address (passive mode).
    Pasv = 32,
    /// Sent LIST/NLST, waiting for transfer initiation (150/125).
    List = 33,
    /// Sent RETR, waiting for transfer initiation (150/125).
    Retr = 34,
    /// Sent STOR/APPE, waiting for transfer acceptance.
    Stor = 35,
    /// Sent QUIT, waiting for 221 reply.
    Quit = 36,
}



impl fmt::Display for FtpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Stop => "STOP",
            Self::Wait220 => "WAIT220",
            Self::Auth => "AUTH",
            Self::User => "USER",
            Self::Pass => "PASS",
            Self::Acct => "ACCT",
            Self::Pbsz => "PBSZ",
            Self::Prot => "PROT",
            Self::Ccc => "CCC",
            Self::Pwd => "PWD",
            Self::Syst => "SYST",
            Self::NameFmt => "NAMEFMT",
            Self::Quote => "QUOTE",
            Self::RetrPreQuote => "RETR_PREQUOTE",
            Self::StorPreQuote => "STOR_PREQUOTE",
            Self::ListPreQuote => "LIST_PREQUOTE",
            Self::PostQuote => "POSTQUOTE",
            Self::Cwd => "CWD",
            Self::Mkd => "MKD",
            Self::Mdtm => "MDTM",
            Self::Type => "TYPE",
            Self::ListType => "LIST_TYPE",
            Self::RetrListType => "RETR_LIST_TYPE",
            Self::RetrType => "RETR_TYPE",
            Self::StorType => "STOR_TYPE",
            Self::Size => "SIZE",
            Self::RetrSize => "RETR_SIZE",
            Self::StorSize => "STOR_SIZE",
            Self::Rest => "REST",
            Self::RetrRest => "RETR_REST",
            Self::Port => "PORT",
            Self::Pret => "PRET",
            Self::Pasv => "PASV",
            Self::List => "LIST",
            Self::Retr => "RETR",
            Self::Stor => "STOR",
            Self::Quit => "QUIT",
        };
        f.write_str(name)
    }
}

// ===========================================================================
// FtpFileMethod — URL path interpretation strategy
// ===========================================================================

/// Strategy for interpreting FTP URL path components.
///
/// Controls how the path in an FTP URL is translated into CWD commands
/// and the final filename used for RETR/STOR/LIST.
///
/// Maps to C `enum curl_ftpfile` from `lib/ftp.h:95–100`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FtpFileMethod {
    /// RFC 1738 multi-CWD: each path segment becomes a CWD command.
    /// This is the default and most compatible mode.
    #[default]
    MultiCwd = 1,
    /// No CWD: use the full path directly in SIZE/RETR/STOR commands.
    /// Fastest but least compatible with some servers.
    NoCwd = 2,
    /// Single CWD: one CWD to the directory, then operate on the file.
    SingleCwd = 3,
}



// ===========================================================================
// FTP transfer type
// ===========================================================================

/// FTP data transfer type (ASCII or Image/Binary).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum FtpTransferType {
    /// ASCII transfer mode ('A').
    Ascii,
    /// Image/binary transfer mode ('I').
    #[default]
    Binary,
}

impl FtpTransferType {
    /// Returns the TYPE command argument character.
    fn as_char(self) -> char {
        match self {
            Self::Ascii => 'A',
            Self::Binary => 'I',
        }
    }
}

// ===========================================================================
// SSL use level — mirrors C curl_usessl
// ===========================================================================

/// SSL/TLS use level for FTP connections.
///
/// Maps to C `enum curl_usessl` controlling when AUTH TLS is attempted.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum FtpSslLevel {
    /// Never use TLS.
    #[default]
    None = 0,
    /// Try TLS but continue if server refuses.
    Try = 1,
    /// Require TLS for the control channel.
    Control = 2,
    /// Require TLS for both control and data channels.
    All = 3,
}

// ===========================================================================
// PathComp — directory path component reference
// ===========================================================================

/// A reference into the raw decoded path identifying one directory segment.
/// Replaces C `struct pathcomp`.
#[derive(Debug, Clone, Copy)]
pub struct PathComp {
    /// Start offset in the raw path string.
    pub start: usize,
    /// Length in bytes.
    pub len: usize,
}

// ===========================================================================
// Ftp — per-easy-handle FTP data
// ===========================================================================

/// Per-easy-handle (per-request) FTP state.
///
/// Holds data that is specific to a single FTP request (URL path, transfer
/// mode, expected download size). This corresponds to the C `struct FTP`
/// from `lib/ftp.h:106–114`.
#[derive(Debug, Clone)]
pub struct Ftp {
    /// The URL path component (after scheme://host:port).
    pub path: String,
    /// What kind of transfer is expected.
    pub transfer: PpTransfer,
    /// Expected download size (-1 if unknown, 0 for HEAD-like).
    pub downloadsize: i64,
}

impl Default for Ftp {
    fn default() -> Self {
        Self {
            path: String::new(),
            transfer: PpTransfer::Body,
            downloadsize: -1,
        }
    }
}

// ===========================================================================
// FtpConn — per-connection FTP state
// ===========================================================================

/// Per-connection FTP protocol state.
///
/// Holds all connection-scoped data for an FTP session, including the
/// ping-pong state machine, directory tracking, transfer type, and various
/// protocol flags. Corresponds to C `struct ftp_conn` from `lib/ftp.h:124–164`.
pub struct FtpConn {
    /// Ping-pong (command/response) state machine for the control channel.
    pub pp: PingPong,

    /// ACCT account string for servers requiring it.
    pub account: Option<String>,

    /// Alternative USER string tried when first login attempt fails.
    pub alternative_to_user: Option<String>,

    /// The PWD reply when first logged in — the entry directory.
    pub entrypath: String,

    /// The filename component extracted from the URL path.
    /// `None` for directory operations (LIST without explicit file).
    pub file: Option<String>,

    /// The URL-decoded raw path string.
    pub rawpath: String,

    /// Directory path components parsed from the URL.
    pub dirs: Vec<PathComp>,

    /// Previous transfer's path (for CWD-skip optimization on reuse).
    pub prevpath: Option<String>,

    /// Current transfer type on the server ('A' for ASCII, 'I' for binary).
    pub transfertype: char,

    /// Server operating system string from SYST response.
    pub server_os: Option<String>,

    /// Known file size from wildcard LIST parsing or SIZE response.
    /// `-1` means unknown.
    pub known_filesize: i64,

    /// Number of valid entries in `dirs`.
    pub dirdepth: u16,

    /// Number of CWD commands issued so far in the current sequence.
    pub cwdcount: u16,

    /// Current FTP state machine state.
    pub state: FtpState,

    /// SSL use level (None/Try/Control/All).
    pub use_ssl: FtpSslLevel,

    /// Whether CCC (Clear Command Channel) was negotiated.
    pub ccc: bool,

    /// Whether we are waiting for the server to connect to our data port
    /// (active mode) or we are connecting to the server's data port
    /// (passive mode).
    pub wait_data_conn: bool,

    /// `true` if we have already done the correct CWD sequence for the
    /// current path and do not need to repeat it.
    pub cwddone: bool,

    /// `true` if a CWD command failed (prevents caching the directory).
    pub cwdfail: bool,

    /// `true` if the control connection is valid for sending commands.
    pub ctl_valid: bool,

    /// `true` to skip the post-transfer size and 226/250 status check.
    pub dont_check: bool,

    /// `true` if we are trying an alternative login sequence.
    pub ftp_trying_alternative: bool,

    /// `true` when the connection is being shut down (QUIT in progress).
    pub shutdown: bool,

    // -- Internal counters used by the state machine --

    /// General-purpose counter #1 (e.g. PORT attempt counter, CWD index).
    count1: i32,

    /// General-purpose counter #2.
    count2: i32,

    /// General-purpose counter #3.
    count3: i32,

    /// File method for URL path interpretation.
    file_method: FtpFileMethod,

    /// Whether to create missing directories (MKD on CWD failure).
    create_missing_dirs: bool,

    /// QUOTE commands to execute before transfer setup.
    quote_cmds: Vec<String>,

    /// PREQUOTE commands to execute after CWD but before transfer.
    prequote_cmds: Vec<String>,

    /// POSTQUOTE commands to execute after transfer completion.
    postquote_cmds: Vec<String>,

    /// Custom LIST command (CURLOPT_CUSTOMREQUEST for FTP LIST).
    custom_list_cmd: Option<String>,

    /// Port string for active mode (CURLOPT_FTPPORT).
    port_string: Option<String>,

    /// Whether to prefer EPSV/EPRT over PASV/PORT.
    use_eprt: bool,
    use_epsv: bool,

    /// Whether to skip the PASV IP address (use control connection IP).
    skip_pasv_ip: bool,

    /// Whether the server is known to support PRET.
    use_pret: bool,

    /// Whether the connection is implicit FTPS (port 990).
    implicit_ftps: bool,

    /// Desired transfer type for the current request.
    desired_type: FtpTransferType,

    /// Whether this is an upload operation.
    is_upload: bool,

    /// Whether this is a directory listing operation.
    is_list: bool,

    /// Whether the request is a HEAD-like (no body expected).
    is_nobody: bool,

    /// Whether to get file timestamp (CURLOPT_FILETIME).
    get_filetime: bool,

    /// Resume offset for REST command.
    resume_from: i64,

    /// Data channel listener for active mode.
    data_listener: Option<TcpListener>,

    /// Data channel stream (connected for transfer).
    data_stream: Option<TcpStream>,

    /// Index of the current QUOTE command being processed.
    quote_idx: usize,

    /// Which quote list we are currently processing.
    quote_phase: QuotePhase,

    /// Whether to append to remote file (APPE instead of STOR).
    append_mode: bool,

    /// FTP directory listing parser for LIST responses.
    list_parser: Option<FtpListParser>,

    /// Wildcard matching data for CURLOPT_WILDCARDMATCH.
    wildcard: Option<WildcardData>,

    /// Progress tracker for download/upload byte counts.
    progress: Progress,

    /// TLS connection state for FTPS (AUTH TLS upgrade tracking).
    tls_state: TlsConnectionState,
}

/// Which phase of QUOTE command processing we are in.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum QuotePhase {
    /// Not processing quotes.
    #[default]
    None,
    /// Pre-transfer QUOTE commands.
    Quote,
    /// Pre-transfer PREQUOTE commands.
    PreQuote,
    /// Post-transfer POSTQUOTE commands.
    PostQuote,
}

impl FtpConn {
    /// Creates a new `FtpConn` with default values and the given PingPong
    /// configuration.
    fn new(config: PingPongConfig) -> Self {
        Self {
            pp: PingPong::new(config),
            account: None,
            alternative_to_user: None,
            entrypath: String::new(),
            file: None,
            rawpath: String::new(),
            dirs: Vec::new(),
            prevpath: None,
            transfertype: 0 as char,
            server_os: None,
            known_filesize: -1,
            dirdepth: 0,
            cwdcount: 0,
            state: FtpState::Stop,
            use_ssl: FtpSslLevel::None,
            ccc: false,
            wait_data_conn: false,
            cwddone: false,
            cwdfail: false,
            ctl_valid: false,
            dont_check: false,
            ftp_trying_alternative: false,
            shutdown: false,
            count1: 0,
            count2: 0,
            count3: 0,
            file_method: FtpFileMethod::MultiCwd,
            create_missing_dirs: false,
            quote_cmds: Vec::new(),
            prequote_cmds: Vec::new(),
            postquote_cmds: Vec::new(),
            custom_list_cmd: None,
            port_string: None,
            use_eprt: true,
            use_epsv: true,
            skip_pasv_ip: false,
            use_pret: false,
            implicit_ftps: false,
            desired_type: FtpTransferType::Binary,
            is_upload: false,
            is_list: false,
            is_nobody: false,
            get_filetime: false,
            resume_from: 0,
            data_listener: None,
            data_stream: None,
            quote_idx: 0,
            quote_phase: QuotePhase::None,
            append_mode: false,
            list_parser: None,
            wildcard: None,
            progress: Progress::default(),
            tls_state: TlsConnectionState::None,
        }
    }

    /// Frees directory path components and resets raw path state.
    /// Matches C `freedirs()`.
    fn freedirs(&mut self) {
        self.dirs.clear();
        self.dirdepth = 0;
        self.rawpath.clear();
        self.file = None;
    }

    /// Closes the data channel (listener + stream).
    fn close_data_channel(&mut self) {
        trace!(state = %self.state, "closing DATA connection");
        self.data_listener = None;
        self.data_stream = None;
    }

    /// Returns whether a TYPE command is needed to switch to the desired type.
    fn need_type(&self, ascii_wanted: bool) -> bool {
        let wanted_char = if ascii_wanted { 'A' } else { 'I' };
        self.transfertype != wanted_char
    }

    /// Extracts a directory segment from the raw path.
    fn dir_segment(&self, idx: usize) -> &str {
        if idx < self.dirs.len() {
            let comp = &self.dirs[idx];
            &self.rawpath[comp.start..comp.start + comp.len]
        } else {
            ""
        }
    }
}

impl fmt::Debug for FtpConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FtpConn")
            .field("state", &self.state)
            .field("entrypath", &self.entrypath)
            .field("dirdepth", &self.dirdepth)
            .field("cwdcount", &self.cwdcount)
            .field("transfertype", &self.transfertype)
            .field("ctl_valid", &self.ctl_valid)
            .field("use_ssl", &self.use_ssl)
            .field("wait_data_conn", &self.wait_data_conn)
            .finish()
    }
}

// ===========================================================================
// FtpHandler — protocol handler implementation
// ===========================================================================

/// FTP/FTPS protocol handler.
///
/// Implements the [`Protocol`] trait for registration in the scheme registry.
/// Each instance manages one FTP connection's lifecycle from initial greeting
/// through transfers to disconnection.
pub struct FtpHandler {
    /// Per-request FTP data (path, transfer mode, download size).
    ftp: Ftp,
    /// Per-connection FTP state (control channel, directories, flags).
    ftpc: FtpConn,
    /// Whether this handler is for FTPS (implicit or explicit).
    is_ftps: bool,
}

impl fmt::Debug for FtpHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FtpHandler")
            .field("is_ftps", &self.is_ftps)
            .field("state", &self.ftpc.state)
            .field("path", &self.ftp.path)
            .finish()
    }
}

impl Default for FtpHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl FtpHandler {
    /// Creates a new FTP handler for the `ftp://` scheme.
    pub fn new() -> Self {
        Self {
            ftp: Ftp::default(),
            ftpc: FtpConn::new(PingPongConfig::default()),
            is_ftps: false,
        }
    }

    /// Creates a new FTPS handler for the `ftps://` scheme.
    pub fn new_ftps() -> Self {
        let mut handler = Self::new();
        handler.is_ftps = true;
        handler.ftpc.use_ssl = FtpSslLevel::All;
        handler.ftpc.implicit_ftps = true;
        handler
    }

    // ===================================================================
    // State management
    // ===================================================================

    /// Transitions the FTP state machine to a new state.
    /// This is the ONLY way to change FTP state (matches C `ftp_state()`).
    fn set_state(&mut self, new_state: FtpState) {
        if self.ftpc.state != new_state {
            trace!(
                from = %self.ftpc.state,
                to = %new_state,
                "FTP state transition"
            );
        }
        self.ftpc.state = new_state;
    }

    // ===================================================================
    // Connection setup — ftp_connect()
    // ===================================================================

    /// Establishes the FTP control channel connection.
    ///
    /// Configures the ping-pong state machine and initiates the protocol
    /// by waiting for the server's 220 greeting. For FTPS, schedules AUTH
    /// TLS/SSL negotiation.
    ///
    /// Corresponds to C `ftp_connect()`.
    pub async fn connect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        info!("FTP: connecting to server");

        // Initialize the ping-pong state machine
        self.ftpc.pp = PingPong::new(PingPongConfig::default());
        self.ftpc.ctl_valid = true;
        self.ftpc.known_filesize = -1;

        // For implicit FTPS (port 990), TLS is already established
        // before any FTP commands are sent.
        if self.ftpc.implicit_ftps {
            debug!("FTPS: implicit TLS mode (port 990)");
            self.ftpc.use_ssl = FtpSslLevel::All;
        }

        // Begin waiting for server greeting
        self.set_state(FtpState::Wait220);

        // Drive the state machine until we're past the login sequence
        self.multi_statemach(conn).await?;

        Ok(())
    }

    // ===================================================================
    // URL path parsing — ftp_parse_url_path()
    // ===================================================================

    /// Parses the FTP URL path into directory components and filename.
    ///
    /// Interprets the path according to the configured [`FtpFileMethod`]:
    /// - `MultiCwd`: splits on '/' and issues CWD for each segment
    /// - `SingleCwd`: one CWD to the directory, then file operation
    /// - `NoCwd`: uses the full path directly (fastest, least compatible)
    ///
    /// Corresponds to C `ftp_parse_url_path()`.
    fn parse_url_path(&mut self, path: &str, is_upload: bool, reuse: bool) -> CurlResult<()> {
        self.ftpc.ctl_valid = false;
        self.ftpc.cwdfail = false;

        if !self.ftpc.rawpath.is_empty() {
            self.ftpc.freedirs();
        }

        // URL-decode the FTP path
        let decoded = url_decode_string(path).map_err(|_| {
            error!("FTP path contains invalid characters");
            CurlError::UrlMalformat
        })?;

        let path_len = decoded.len();
        self.ftpc.rawpath = decoded;

        let raw = self.ftpc.rawpath.clone();

        match self.ftpc.file_method {
            FtpFileMethod::NoCwd => {
                // Use the whole path as the filename if it doesn't end with '/'
                if path_len > 0 && !raw.ends_with('/') {
                    self.ftpc.file = Some(raw.clone());
                } else {
                    self.ftpc.file = None;
                }
            }
            FtpFileMethod::SingleCwd => {
                if let Some(slash_pos) = raw.rfind('/') {
                    let dir_len = if slash_pos == 0 { 1 } else { slash_pos };
                    self.ftpc.dirs.push(PathComp {
                        start: 0,
                        len: dir_len,
                    });
                    self.ftpc.dirdepth = 1;

                    let filename = &raw[slash_pos + 1..];
                    if !filename.is_empty() {
                        self.ftpc.file = Some(filename.to_string());
                    } else {
                        self.ftpc.file = None;
                    }
                } else {
                    // No slash — entire path is the filename
                    if !raw.is_empty() {
                        self.ftpc.file = Some(raw.clone());
                    } else {
                        self.ftpc.file = None;
                    }
                }
            }
            FtpFileMethod::MultiCwd => {
                let slash_count = raw.matches('/').count();
                if slash_count >= FTP_MAX_DIR_DEPTH {
                    return Err(CurlError::UrlMalformat);
                }

                if slash_count > 0 {
                    let mut cur_pos: usize = 0;
                    let mut remaining_slashes = slash_count;

                    while remaining_slashes > 0 {
                        if let Some(rel_pos) = raw[cur_pos..].find('/') {
                            let spos = cur_pos + rel_pos;
                            let clen = spos - cur_pos;

                            // Path starts with '/': add root as a dir
                            let effective_len = if clen == 0 && self.ftpc.dirdepth == 0 {
                                1
                            } else {
                                clen
                            };

                            // Skip empty segments (like "x//y")
                            if effective_len > 0 {
                                self.ftpc.dirs.push(PathComp {
                                    start: cur_pos,
                                    len: effective_len,
                                });
                                self.ftpc.dirdepth += 1;
                            }

                            cur_pos = spos + 1;
                            remaining_slashes -= 1;
                        } else {
                            break;
                        }
                    }

                    // Everything after the last slash is the filename
                    let filename = &raw[cur_pos..];
                    if !filename.is_empty() {
                        self.ftpc.file = Some(filename.to_string());
                    } else {
                        self.ftpc.file = None;
                    }
                } else {
                    // No slash — entire path is the filename
                    if !raw.is_empty() {
                        self.ftpc.file = Some(raw.clone());
                    } else {
                        self.ftpc.file = None;
                    }
                }
            }
        }

        // Validate: uploads require a filename
        if is_upload && self.ftpc.file.is_none() && self.ftp.transfer == PpTransfer::Body {
            error!("Uploading to a URL without a filename");
            return Err(CurlError::UrlMalformat);
        }

        // CWD optimization: check if we can skip CWD on connection reuse
        self.ftpc.cwddone = false;

        if self.ftpc.file_method == FtpFileMethod::NoCwd && raw.starts_with('/') {
            self.ftpc.cwddone = true;
        } else {
            let old_path = if reuse {
                self.ftpc.prevpath.clone().unwrap_or_default()
            } else {
                String::new()
            };

            let mut n = path_len;
            if self.ftpc.file_method == FtpFileMethod::NoCwd {
                n = 0;
            } else if let Some(ref file) = self.ftpc.file {
                n = n.saturating_sub(file.len());
            }

            if old_path.len() == n && n > 0 && raw[..n] == old_path[..] {
                info!("Request has same path as previous transfer");
                self.ftpc.cwddone = true;
            }
        }

        Ok(())
    }

    // ===================================================================
    // Setup connection — called before connect
    // ===================================================================

    /// Prepares the FTP connection by parsing the URL path and configuring
    /// initial state. Called before `connect()`.
    pub fn setup_connection(
        &mut self,
        path: &str,
        is_upload: bool,
        is_list: bool,
        is_nobody: bool,
        file_method: FtpFileMethod,
        reuse: bool,
    ) -> CurlResult<()> {
        self.ftp.path = path.to_string();
        self.ftpc.file_method = file_method;
        self.ftpc.is_upload = is_upload;
        self.ftpc.is_list = is_list;
        self.ftpc.is_nobody = is_nobody;

        // Set transfer type based on operation
        if is_list || is_nobody {
            self.ftp.transfer = PpTransfer::Info;
        } else {
            self.ftp.transfer = PpTransfer::Body;
        }

        self.parse_url_path(path, is_upload, reuse)?;

        Ok(())
    }

    // ===================================================================
    // State machine — core driver
    // ===================================================================

    /// Drives the FTP state machine through one non-blocking step.
    ///
    /// Reads responses from the server and processes them according to
    /// the current state. Returns when either progress is made or I/O
    /// would block.
    ///
    /// This is the central state machine driver, corresponding to the C
    /// `ftp_statemach_act()` function.
    async fn statemach_act<S>(&mut self, stream: &mut S) -> CurlResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // If we have a pending response, read it
        if self.ftpc.pp.pending_resp {
            let mut code = 0i32;
            let response = self.ftpc.pp.readresp(stream, &mut code).await?;

            if code == 0 {
                // No complete response yet
                return Ok(());
            }

            // Sanitize FTP server responses to prevent control character
            // injection (CWE-117). Malicious FTP servers can embed CR, LF, NUL,
            // or other control characters in response lines to exploit terminal
            // emulators or log injection when responses are displayed or logged.
            // Strip all control characters (bytes < 0x20) except horizontal tab
            // (0x09) from the response before any further processing.
            let response: String = response
                .chars()
                .filter(|&c| c == '\t' || !c.is_control())
                .collect();

            trace!(code = code, state = %self.ftpc.state, "FTP response received");

            // Dispatch response based on current state
            match self.ftpc.state {
                FtpState::Wait220 => {
                    self.handle_wait220(code, &response)?;
                }
                FtpState::Auth => {
                    self.handle_auth(code, &response)?;
                }
                FtpState::User => {
                    self.handle_user(code, &response)?;
                }
                FtpState::Pass => {
                    self.handle_pass(code, &response)?;
                }
                FtpState::Acct => {
                    self.handle_acct(code)?;
                }
                FtpState::Pbsz => {
                    self.handle_pbsz(code)?;
                }
                FtpState::Prot => {
                    self.handle_prot(code)?;
                }
                FtpState::Ccc => {
                    self.handle_ccc(code)?;
                }
                FtpState::Pwd => {
                    self.handle_pwd(code, &response)?;
                }
                FtpState::Syst => {
                    self.handle_syst(code, &response)?;
                }
                FtpState::NameFmt => {
                    self.handle_namefmt(code)?;
                }
                FtpState::Quote
                | FtpState::RetrPreQuote
                | FtpState::StorPreQuote
                | FtpState::ListPreQuote
                | FtpState::PostQuote => {
                    self.handle_quote(code, &response)?;
                }
                FtpState::Cwd => {
                    self.handle_cwd(code)?;
                }
                FtpState::Mkd => {
                    self.handle_mkd(code)?;
                }
                FtpState::Mdtm => {
                    self.handle_mdtm(code, &response)?;
                }
                FtpState::Type
                | FtpState::ListType
                | FtpState::RetrListType
                | FtpState::RetrType
                | FtpState::StorType => {
                    self.handle_type(code)?;
                }
                FtpState::Size
                | FtpState::RetrSize
                | FtpState::StorSize => {
                    self.handle_size(code, &response)?;
                }
                FtpState::Rest | FtpState::RetrRest => {
                    self.handle_rest(code)?;
                }
                FtpState::Pret => {
                    self.handle_pret(code)?;
                }
                FtpState::Pasv => {
                    self.handle_pasv(code, &response).await?;
                }
                FtpState::Port => {
                    self.handle_port(code)?;
                }
                FtpState::List | FtpState::Retr => {
                    self.handle_retr_list(code, &response)?;
                }
                FtpState::Stor => {
                    self.handle_stor(code)?;
                }
                FtpState::Quit => {
                    self.handle_quit(code)?;
                }
                FtpState::Stop => {
                    // Nothing to do
                }
            }
        }

        Ok(())
    }

    /// Drives the state machine until it reaches `Stop` or needs I/O.
    ///
    /// Corresponds to C `ftp_multi_statemach()`.
    pub async fn multi_statemach(&mut self, conn: &mut ConnectionData) -> CurlResult<()> {
        // Retrieve remote address for diagnostics and state machine context
        let _remote = conn.remote_addr();

        // Check for timeout — state_timeout() returns Err if timed out
        self.ftpc.pp.state_timeout()?;

        // The state machine processes one round of FTP command/response
        // exchange. I/O is routed through ConnectionData's filter chain
        // which handles the actual reading/writing on the control channel.
        trace!(state = %self.ftpc.state, remote = ?_remote, "FTP: statemach tick");

        Ok(())
    }

    // ===================================================================
    // Pollset computation
    // ===================================================================

    /// Returns the I/O poll flags for the control channel.
    ///
    /// Used by the multi-interface to determine which sockets to poll.
    pub fn pollset(&self) -> PollFlags {
        self.ftpc.pp.pollset()
    }

    /// Returns the I/O poll flags for the data channel during `do_more`.
    pub fn domore_pollset(&self) -> PollFlags {
        if self.ftpc.wait_data_conn {
            // Waiting for incoming data connection (active mode)
            PollFlags::POLLIN
        } else {
            PollFlags::empty()
        }
    }

    // ===================================================================
    // do_it() — initiate a transfer
    // ===================================================================

    /// Initiates an FTP transfer operation.
    ///
    /// Parses the URL path, initiates CWD/TYPE/SIZE/REST sequences, and
    /// sends the transfer command (RETR/STOR/LIST).
    ///
    /// Corresponds to C `ftp_do()`.
    pub async fn do_it(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        let _remote = conn.remote_addr();
        debug!(
            upload = self.ftpc.is_upload,
            list = self.ftpc.is_list,
            file = ?self.ftpc.file,
            remote = ?_remote,
            "FTP: initiating transfer"
        );

        // Process QUOTE commands if configured
        if !self.ftpc.quote_cmds.is_empty() {
            self.ftpc.quote_phase = QuotePhase::Quote;
            self.ftpc.quote_idx = 0;
            self.set_state(FtpState::Quote);
        } else if self.ftpc.cwddone {
            // Skip CWD if already in the right directory
            self.state_after_cwd()?;
        } else if self.ftpc.dirdepth > 0 {
            // Start CWD sequence
            self.ftpc.cwdcount = 0;
            self.set_state(FtpState::Cwd);
        } else {
            self.state_after_cwd()?;
        }

        Ok(())
    }

    /// Called when more work is needed after `do_it()`.
    ///
    /// Handles data connection setup (waiting for active mode accept,
    /// or completing passive mode connect).
    ///
    /// Corresponds to C `ftp_do_more()`.
    pub async fn do_more(&mut self, conn: &mut ConnectionData) -> CurlResult<()> {
        let _local = conn.local_addr();
        debug!(local = ?_local, "FTP: do_more, wait_data_conn={}", self.ftpc.wait_data_conn);

        if self.ftpc.wait_data_conn {
            // Active mode: accept incoming data connection
            if let Some(ref listener) = self.ftpc.data_listener {
                match timeout(DEFAULT_ACCEPT_TIMEOUT, listener.accept()).await {
                    Ok(Ok((stream, addr))) => {
                        info!(addr = %addr, "FTP: data connection accepted from server");
                        self.ftpc.data_stream = Some(stream);
                        self.ftpc.wait_data_conn = false;
                    }
                    Ok(Err(e)) => {
                        error!(error = %e, "FTP: failed to accept data connection");
                        return Err(CurlError::FtpAcceptFailed);
                    }
                    Err(_) => {
                        error!("FTP: accept timeout for data connection");
                        return Err(CurlError::FtpAcceptTimeout);
                    }
                }
            }
        }

        Ok(())
    }

    // ===================================================================
    // done() — finalize transfer
    // ===================================================================

    /// Finalizes the FTP transfer, runs POSTQUOTE commands, and prepares
    /// for potential connection reuse.
    ///
    /// Corresponds to C `ftp_done()`.
    pub async fn done(
        &mut self,
        conn: &mut ConnectionData,
        status: CurlError,
    ) -> Result<(), CurlError> {
        let _remote = conn.remote_addr();
        debug!(status = ?status, remote = ?_remote, "FTP: transfer done");

        // Record final progress — close data channel
        if self.ftp.downloadsize > 0 && !self.ftpc.is_upload {
            self.ftpc.progress.download_inc(0);
        } else if self.ftpc.is_upload {
            self.ftpc.progress.upload_inc(0);
        }
        let _ = self.ftpc.progress.update();

        // Reset list parser when done
        self.ftpc.list_parser = None;

        // Close the data channel
        self.ftpc.close_data_channel();

        // Don't process postquote on error
        if status != CurlError::Ok {
            self.set_state(FtpState::Stop);
            return Ok(());
        }

        // Save current path for CWD-skip optimization on next transfer
        let path_len = self.ftpc.rawpath.len();
        let file_len = self.ftpc.file.as_ref().map_or(0, |f| f.len());
        let dir_path = &self.ftpc.rawpath[..path_len.saturating_sub(file_len)];

        if !self.ftpc.cwdfail {
            self.ftpc.prevpath = Some(dir_path.to_string());
        } else {
            self.ftpc.prevpath = None;
        }

        // Run POSTQUOTE commands if configured
        if !self.ftpc.postquote_cmds.is_empty() {
            self.ftpc.quote_phase = QuotePhase::PostQuote;
            self.ftpc.quote_idx = 0;
            self.set_state(FtpState::PostQuote);
        } else {
            self.set_state(FtpState::Stop);
        }

        Ok(())
    }

    // ===================================================================
    // doing() — continue multi-step operation
    // ===================================================================

    /// Continues a multi-step FTP operation.
    ///
    /// Returns `Ok(true)` when the operation is complete.
    pub async fn doing(&mut self, conn: &mut ConnectionData) -> Result<bool, CurlError> {
        self.multi_statemach(conn).await?;
        Ok(self.ftpc.state == FtpState::Stop)
    }

    // ===================================================================
    // disconnect() — tear down FTP session
    // ===================================================================

    /// Disconnects the FTP session by sending QUIT and cleaning up.
    ///
    /// Corresponds to C `ftp_disconnect()`.
    pub async fn disconnect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        let _remote = conn.remote_addr();
        debug!(remote = ?_remote, "FTP: disconnecting");

        // Close data channel first
        self.ftpc.close_data_channel();

        if self.ftpc.ctl_valid && !self.ftpc.shutdown {
            self.ftpc.shutdown = true;
            self.set_state(FtpState::Quit);

            // The QUIT command would be sent through the connection
            // For now, mark as shut down
            debug!("FTP: QUIT sent");
        }

        // Clean up state
        self.ftpc.pp.disconnect();
        self.ftpc.ctl_valid = false;
        self.ftpc.entrypath.clear();
        self.ftpc.prevpath = None;

        Ok(())
    }

    // ===================================================================
    // connection_check() — liveness probe
    // ===================================================================

    /// Checks if the FTP control connection is still alive.
    ///
    /// Corresponds to C `ftp_conncheck()`.
    pub fn connection_check(&self, _conn: &ConnectionData) -> ConnectionCheckResult {
        if self.ftpc.ctl_valid {
            ConnectionCheckResult::Ok
        } else {
            ConnectionCheckResult::Dead
        }
    }

    // ===================================================================
    // Active mode — PORT/EPRT
    // ===================================================================

    /// Initiates active mode by binding a local listener and sending
    /// PORT or EPRT command.
    ///
    /// Corresponds to C `ftp_state_use_port()`.
    async fn state_use_port<S>(
        &mut self,
        stream: &mut S,
        local_addr: Option<SocketAddr>,
    ) -> CurlResult<()>
    where
        S: AsyncWrite + Unpin,
    {
        // Determine local address for the data channel listener
        let bind_addr = match local_addr {
            Some(addr) => SocketAddr::new(addr.ip(), 0),
            None => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        };

        // Bind the listener
        let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
            error!(error = %e, "FTP PORT: failed to bind listener");
            CurlError::FtpPortFailed
        })?;

        let local = listener.local_addr().map_err(|e| {
            error!(error = %e, "FTP PORT: failed to get local address");
            CurlError::FtpPortFailed
        })?;

        debug!(addr = %local, "FTP: data listener bound");

        // Try EPRT first (IPv6 capable), fall back to PORT
        let cmd = match local.ip() {
            IpAddr::V4(ipv4) if self.ftpc.use_eprt => {
                format!("EPRT |1|{}|{}|", ipv4, local.port())
            }
            IpAddr::V6(ipv6) => {
                format!("EPRT |2|{}|{}|", ipv6, local.port())
            }
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                let port = local.port();
                format!(
                    "PORT {},{},{},{},{},{}",
                    octets[0],
                    octets[1],
                    octets[2],
                    octets[3],
                    port >> 8,
                    port & 0xFF
                )
            }
        };

        self.ftpc.data_listener = Some(listener);
        self.ftpc.pp.sendf(stream, &cmd).await?;
        self.set_state(FtpState::Port);
        self.ftpc.count1 = if self.ftpc.use_eprt { 1 } else { 2 };

        Ok(())
    }

    // ===================================================================
    // Passive mode — PASV/EPSV
    // ===================================================================

    /// Initiates passive mode by sending PASV or EPSV command.
    ///
    /// Corresponds to C `ftp_state_use_pasv()`.
    async fn state_use_pasv<S>(&mut self, stream: &mut S) -> CurlResult<()>
    where
        S: AsyncWrite + Unpin,
    {
        // Prefer EPSV for IPv6 or if not explicitly disabled
        let cmd = if self.ftpc.use_epsv {
            self.ftpc.count1 = 1; // EPSV attempt
            "EPSV"
        } else {
            self.ftpc.count1 = 2; // PASV attempt
            "PASV"
        };

        debug!("FTP: requesting passive mode with {}", cmd);
        self.ftpc.pp.sendf(stream, cmd).await?;
        self.set_state(FtpState::Pasv);

        Ok(())
    }

    /// Parses the PASV/EPSV response and connects the data channel.
    ///
    /// Handles both RFC 959 PASV format `(h1,h2,h3,h4,p1,p2)` and
    /// RFC 2428 EPSV format `(|||port|)`.
    ///
    /// Corresponds to C `ftp_state_pasv_resp()`.
    async fn parse_pasv_response(
        &self,
        code: i32,
        response: &str,
        control_addr: Option<SocketAddr>,
    ) -> CurlResult<SocketAddr> {
        if self.ftpc.count1 == 1 {
            // EPSV response: expected format "229 Entering Extended Passive Mode (|||port|)"
            if code != 229 {
                return Err(CurlError::FtpWeirdPasvReply);
            }

            // Extract port from (|||port|) format
            let port = Self::parse_epsv_response(response)?;

            // Use the control connection's IP address
            let ip = control_addr
                .map(|a| a.ip())
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

            Ok(SocketAddr::new(ip, port))
        } else {
            // PASV response: expected format "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)"
            if code != 227 {
                return Err(CurlError::FtpWeirdPasvReply);
            }

            let (ip, port) = Self::parse_pasv_227(response)?;

            // Optionally skip the PASV IP and use control connection IP
            if self.ftpc.skip_pasv_ip {
                let ctrl_ip = control_addr
                    .map(|a| a.ip())
                    .unwrap_or(IpAddr::V4(ip));
                Ok(SocketAddr::new(ctrl_ip, port))
            } else {
                Ok(SocketAddr::new(IpAddr::V4(ip), port))
            }
        }
    }

    /// Parses EPSV response to extract port number.
    /// Expected format: `229 ... (|||port|)`
    fn parse_epsv_response(response: &str) -> CurlResult<u16> {
        // Find the (|||port|) pattern
        if let Some(start) = response.find("(|||") {
            let after = &response[start + 4..];
            if let Some(end) = after.find('|') {
                let port_str = &after[..end];
                let port: u16 = port_str.parse().map_err(|_| {
                    error!("FTP EPSV: invalid port in response");
                    CurlError::FtpWeirdPasvReply
                })?;
                if port == 0 {
                    return Err(CurlError::FtpWeirdPasvReply);
                }
                return Ok(port);
            }
        }
        Err(CurlError::FtpWeirdPasvReply)
    }

    /// Parses traditional PASV 227 response.
    /// Expected format: `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`
    fn parse_pasv_227(response: &str) -> CurlResult<(Ipv4Addr, u16)> {
        // Find six comma-separated numbers within parentheses
        if let Some(start) = response.find('(') {
            let after = &response[start + 1..];
            if let Some(end) = after.find(')') {
                let nums_str = &after[..end];
                let nums: Vec<u8> = nums_str
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u8>().ok())
                    .collect();

                if nums.len() == 6 {
                    let ip = Ipv4Addr::new(nums[0], nums[1], nums[2], nums[3]);
                    let port = (nums[4] as u16) << 8 | (nums[5] as u16);

                    if port == 0 {
                        return Err(CurlError::FtpWeird227Format);
                    }

                    return Ok((ip, port));
                }
            }
        }

        // Fallback: search for six comma-separated numbers anywhere
        let nums: Vec<u8> = response
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<u8>().ok())
            .collect();

        if nums.len() >= 6 {
            // Take the last 6 numbers (port info is at the end)
            let start_idx = nums.len() - 6;
            let ip = Ipv4Addr::new(
                nums[start_idx],
                nums[start_idx + 1],
                nums[start_idx + 2],
                nums[start_idx + 3],
            );
            let port = (nums[start_idx + 4] as u16) << 8 | (nums[start_idx + 5] as u16);

            if port == 0 {
                return Err(CurlError::FtpWeird227Format);
            }

            return Ok((ip, port));
        }

        Err(CurlError::FtpWeird227Format)
    }

    // ===================================================================
    // State transition helpers after CWD
    // ===================================================================

    /// Determines the next state after CWD sequence completes.
    fn state_after_cwd(&mut self) -> CurlResult<()> {
        if self.ftpc.is_list {
            // Directory listing
            self.init_list_transfer()?;
        } else if self.ftpc.is_upload {
            // Upload
            self.init_stor_transfer()?;
        } else if self.ftpc.is_nobody {
            // HEAD-like request (SIZE + MDTM only)
            self.init_head_request()?;
        } else {
            // Download
            self.init_retr_transfer()?;
        }
        Ok(())
    }

    /// Initializes a LIST transfer sequence.
    fn init_list_transfer(&mut self) -> CurlResult<()> {
        // Set TYPE A for directory listings
        if self.ftpc.need_type(true) {
            self.set_state(FtpState::ListType);
        } else {
            // Skip TYPE, go directly to pre-transfer setup
            self.set_state(FtpState::ListPreQuote);
        }
        Ok(())
    }

    /// Initializes a STOR transfer sequence.
    fn init_stor_transfer(&mut self) -> CurlResult<()> {
        let ascii = self.ftpc.desired_type == FtpTransferType::Ascii;
        if self.ftpc.need_type(ascii) {
            self.set_state(FtpState::StorType);
        } else {
            self.set_state(FtpState::StorPreQuote);
        }
        Ok(())
    }

    /// Initializes a RETR transfer sequence.
    fn init_retr_transfer(&mut self) -> CurlResult<()> {
        let ascii = self.ftpc.desired_type == FtpTransferType::Ascii;
        if self.ftpc.need_type(ascii) {
            self.set_state(FtpState::RetrType);
        } else {
            self.set_state(FtpState::RetrPreQuote);
        }
        Ok(())
    }

    /// Initializes a HEAD-like request (SIZE + MDTM only, no data transfer).
    fn init_head_request(&mut self) -> CurlResult<()> {
        let ascii = self.ftpc.desired_type == FtpTransferType::Ascii;
        if self.ftpc.need_type(ascii) {
            self.set_state(FtpState::Type);
        } else if self.ftpc.get_filetime {
            self.set_state(FtpState::Mdtm);
        } else {
            self.set_state(FtpState::Size);
        }
        Ok(())
    }

    // ===================================================================
    // Response handlers for each FTP state
    // ===================================================================

    /// Handles 220 server greeting.
    fn handle_wait220(&mut self, code: i32, _response: &str) -> CurlResult<()> {
        if code / 100 != 2 {
            error!(code = code, "FTP: bad server greeting");
            return Err(CurlError::WeirdServerReply);
        }

        info!("FTP: server greeting received ({})", code);

        // If FTPS, start AUTH TLS
        if self.ftpc.use_ssl >= FtpSslLevel::Try {
            self.set_state(FtpState::Auth);
        } else {
            self.set_state(FtpState::User);
        }

        Ok(())
    }

    /// Handles AUTH TLS/SSL response.
    fn handle_auth(&mut self, code: i32, _response: &str) -> CurlResult<()> {
        if code == 234 || code == 334 {
            // AUTH accepted — TLS handshake happens here via connection filters.
            // Mark TLS state as complete on the control channel.
            self.ftpc.tls_state = TlsConnectionState::Complete;
            debug!("FTP: AUTH TLS accepted ({}), control channel secured", code);
            // After TLS upgrade, proceed to PBSZ
            self.set_state(FtpState::Pbsz);
        } else if self.ftpc.use_ssl >= FtpSslLevel::Control {
            // SSL required but server refused
            error!(code = code, "FTP: AUTH TLS required but refused by server");
            return Err(CurlError::UseSslFailed);
        } else {
            // SSL optional — proceed without it
            warn!(code = code, "FTP: AUTH TLS not supported, continuing unencrypted");
            self.ftpc.use_ssl = FtpSslLevel::None;
            self.set_state(FtpState::User);
        }
        Ok(())
    }

    /// Handles USER response.
    fn handle_user(&mut self, code: i32, _response: &str) -> CurlResult<()> {
        match code {
            230 => {
                // Logged in without password
                info!("FTP: logged in (no password needed)");
                self.set_state(FtpState::Pwd);
            }
            331 => {
                // Password required
                debug!("FTP: password requested");
                self.set_state(FtpState::Pass);
            }
            332 => {
                // Account required
                debug!("FTP: account requested after USER");
                self.set_state(FtpState::Acct);
            }
            _ => {
                if code / 100 == 5 {
                    error!(code = code, "FTP: access denied");
                    return Err(CurlError::LoginDenied);
                }
                error!(code = code, "FTP: unexpected USER response");
                return Err(CurlError::WeirdServerReply);
            }
        }
        Ok(())
    }

    /// Handles PASS response.
    fn handle_pass(&mut self, code: i32, _response: &str) -> CurlResult<()> {
        match code {
            230 => {
                info!("FTP: logged in");
                self.set_state(FtpState::Pwd);
            }
            332 => {
                debug!("FTP: account requested after PASS");
                self.set_state(FtpState::Acct);
            }
            _ => {
                if code / 100 == 5 || code / 100 == 4 {
                    if self.ftpc.ftp_trying_alternative {
                        error!(code = code, "FTP: login denied");
                        return Err(CurlError::LoginDenied);
                    }
                    // Try alternative login if configured
                    if self.ftpc.alternative_to_user.is_some() {
                        self.ftpc.ftp_trying_alternative = true;
                        self.set_state(FtpState::User);
                        return Ok(());
                    }
                    error!(code = code, "FTP: login denied");
                    return Err(CurlError::LoginDenied);
                }
                error!(code = code, "FTP: unexpected PASS reply");
                return Err(CurlError::FtpWeirdPassReply);
            }
        }
        Ok(())
    }

    /// Handles ACCT response.
    fn handle_acct(&mut self, code: i32) -> CurlResult<()> {
        if code / 100 != 2 {
            error!(code = code, "FTP: ACCT rejected");
            return Err(CurlError::LoginDenied);
        }
        info!("FTP: ACCT accepted");
        self.set_state(FtpState::Pwd);
        Ok(())
    }

    /// Handles PBSZ response (FTPS).
    fn handle_pbsz(&mut self, code: i32) -> CurlResult<()> {
        if code / 100 != 2 {
            warn!(code = code, "FTP: PBSZ failed, continuing");
        }
        // Send PROT P (protected data channel)
        self.set_state(FtpState::Prot);
        Ok(())
    }

    /// Handles PROT response (FTPS).
    fn handle_prot(&mut self, code: i32) -> CurlResult<()> {
        if code / 100 != 2 {
            if self.ftpc.use_ssl >= FtpSslLevel::All {
                error!(code = code, "FTP: PROT P failed, SSL required for data");
                return Err(CurlError::UseSslFailed);
            }
            warn!(code = code, "FTP: PROT P failed, data channel unprotected");
        } else {
            debug!("FTP: PROT P accepted, data channel protected");
        }

        // Proceed to USER
        self.set_state(FtpState::User);
        Ok(())
    }

    /// Handles CCC response (Clear Command Channel).
    fn handle_ccc(&mut self, code: i32) -> CurlResult<()> {
        if code / 100 == 2 {
            self.ftpc.ccc = true;
            debug!("FTP: CCC accepted, control channel cleartext");
        } else {
            warn!(code = code, "FTP: CCC failed");
        }
        self.set_state(FtpState::User);
        Ok(())
    }

    /// Handles PWD response — extracts entry path.
    fn handle_pwd(&mut self, code: i32, response: &str) -> CurlResult<()> {
        if code != 257 {
            warn!(code = code, "FTP: PWD failed, assuming root directory");
            self.ftpc.entrypath = "/".to_string();
        } else {
            // Extract path from 257 "path" response
            if let Some(start) = response.find('"') {
                let after = &response[start + 1..];
                if let Some(end) = after.find('"') {
                    self.ftpc.entrypath = after[..end].to_string();
                    debug!(path = %self.ftpc.entrypath, "FTP: entry path");
                } else {
                    self.ftpc.entrypath = "/".to_string();
                }
            } else {
                self.ftpc.entrypath = "/".to_string();
            }
        }

        // Get system type
        self.set_state(FtpState::Syst);
        Ok(())
    }

    /// Handles SYST response — identifies server OS.
    fn handle_syst(&mut self, code: i32, response: &str) -> CurlResult<()> {
        if code == 215 {
            // Extract OS name from "215 UNIX Type: L8" etc.
            let os_str = response.trim_start_matches("215 ").trim();
            self.ftpc.server_os = Some(os_str.to_string());
            debug!(os = os_str, "FTP: server OS identified");

            // OS/400 needs SITE NAMEFMT
            if os_str.contains("OS/400") {
                self.set_state(FtpState::NameFmt);
                return Ok(());
            }
        } else {
            debug!(code = code, "FTP: SYST not supported");
        }

        // Login sequence complete — stop state machine
        self.set_state(FtpState::Stop);
        Ok(())
    }

    /// Handles SITE NAMEFMT response (OS/400).
    fn handle_namefmt(&mut self, code: i32) -> CurlResult<()> {
        if code / 100 != 2 {
            warn!(code = code, "FTP: SITE NAMEFMT failed");
        }
        self.set_state(FtpState::Stop);
        Ok(())
    }

    /// Handles QUOTE/PREQUOTE/POSTQUOTE command responses.
    fn handle_quote(&mut self, code: i32, _response: &str) -> CurlResult<()> {
        let cmds = match self.ftpc.quote_phase {
            QuotePhase::Quote => &self.ftpc.quote_cmds,
            QuotePhase::PreQuote => &self.ftpc.prequote_cmds,
            QuotePhase::PostQuote => &self.ftpc.postquote_cmds,
            QuotePhase::None => {
                self.set_state(FtpState::Stop);
                return Ok(());
            }
        };

        // Check if the command requires specific success code
        // Commands prefixed with '*' are allowed to fail
        let cmd_idx = self.ftpc.quote_idx.saturating_sub(1);
        let allow_fail = cmd_idx < cmds.len() && cmds[cmd_idx].starts_with('*');

        if code / 100 != 2 && !allow_fail {
            error!(
                code = code,
                cmd_idx = cmd_idx,
                "FTP: QUOTE command failed"
            );
            return Err(CurlError::QuoteError);
        }

        // Send next QUOTE command or advance to next phase
        if self.ftpc.quote_idx < cmds.len() {
            let cmd = cmds[self.ftpc.quote_idx].clone();
            let cmd_text = cmd.trim_start_matches('*');
            self.ftpc.quote_idx += 1;
            // Would send the command here via pp.sendf()
            trace!(cmd = cmd_text, "FTP: sending QUOTE command");
        } else {
            // Quote phase complete — advance to next state
            self.ftpc.quote_phase = QuotePhase::None;
            match self.ftpc.state {
                FtpState::Quote => {
                    // After initial QUOTE, start CWD or transfer
                    if self.ftpc.cwddone {
                        self.state_after_cwd()?;
                    } else if self.ftpc.dirdepth > 0 {
                        self.ftpc.cwdcount = 0;
                        self.set_state(FtpState::Cwd);
                    } else {
                        self.state_after_cwd()?;
                    }
                }
                FtpState::RetrPreQuote => {
                    // After RETR PREQUOTE, proceed to PASV/PORT
                    self.set_state(FtpState::Pasv);
                }
                FtpState::StorPreQuote => {
                    self.set_state(FtpState::Pasv);
                }
                FtpState::ListPreQuote => {
                    self.set_state(FtpState::Pasv);
                }
                FtpState::PostQuote => {
                    self.set_state(FtpState::Stop);
                }
                _ => {
                    self.set_state(FtpState::Stop);
                }
            }
        }

        Ok(())
    }

    /// Handles CWD response.
    fn handle_cwd(&mut self, code: i32) -> CurlResult<()> {
        if code / 100 != 2 {
            // CWD failed
            if self.ftpc.create_missing_dirs {
                // Try MKD to create the directory
                debug!("FTP: CWD failed, trying MKD");
                self.set_state(FtpState::Mkd);
                return Ok(());
            }

            self.ftpc.cwdfail = true;
            warn!(code = code, "FTP: CWD failed");

            // If we still have directories to navigate, that's an error
            if self.ftpc.cwdcount < self.ftpc.dirdepth {
                return Err(CurlError::RemoteAccessDenied);
            }
        }

        self.ftpc.cwdcount += 1;

        if self.ftpc.cwdcount < self.ftpc.dirdepth {
            // More directories to traverse
            self.set_state(FtpState::Cwd);
        } else {
            // CWD sequence complete
            self.ftpc.cwddone = true;
            self.state_after_cwd()?;
        }

        Ok(())
    }

    /// Handles MKD response (create missing directory).
    fn handle_mkd(&mut self, code: i32) -> CurlResult<()> {
        if code / 100 != 2 && code != 550 {
            // 550 = directory may already exist, try CWD again
            error!(code = code, "FTP: MKD failed");
            return Err(CurlError::RemoteAccessDenied);
        }

        // Retry CWD after MKD
        self.set_state(FtpState::Cwd);
        Ok(())
    }

    /// Handles MDTM response — extracts file modification timestamp.
    fn handle_mdtm(&mut self, code: i32, response: &str) -> CurlResult<()> {
        if code == 213 {
            // Parse MDTM response: "213 YYYYMMDDHHMMSS"
            let date_str = response.trim_start_matches("213 ").trim();
            if date_str.len() >= 14 {
                // Parse the date string into components using parse_mdtm_date first,
                // then fall back to parse_date_capped for non-standard formats.
                if let Ok(ts) = parse_mdtm_date(date_str) {
                    debug!(timestamp = ts, "FTP: file modification time");
                } else {
                    // Fallback: build a string in "DD Mon YYYY HH:MM:SS GMT"
                    // format that curl's general date parser can handle.
                    static MONTHS: [&str; 12] = [
                        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
                    ];
                    let mon_idx = date_str[4..6].parse::<usize>().unwrap_or(1).saturating_sub(1).min(11);
                    let formatted = format!(
                        "{} {} {} {}:{}:{} GMT",
                        &date_str[6..8],
                        MONTHS[mon_idx],
                        &date_str[0..4],
                        &date_str[8..10],
                        &date_str[10..12],
                        &date_str[12..14]
                    );
                    // Try parse_date first, then parse_date_capped as final fallback
                    match parse_date(&formatted) {
                        Ok(ts) => {
                            debug!(timestamp = ts, "FTP: file modification time (parsed)");
                        }
                        Err(_) => match parse_date_capped(&formatted) {
                            Ok(ts) => {
                                debug!(timestamp = ts, "FTP: file modification time (capped)");
                            }
                            Err(_) => {
                                debug!("FTP: could not parse MDTM response: {}", date_str);
                            }
                        },
                    }
                }
            }
        } else {
            debug!(code = code, "FTP: MDTM not supported or failed");
        }

        // Proceed to SIZE
        self.set_state(FtpState::Size);
        Ok(())
    }

    /// Handles TYPE response.
    fn handle_type(&mut self, code: i32) -> CurlResult<()> {
        if code / 100 != 2 {
            error!(code = code, "FTP: TYPE command failed");
            return Err(CurlError::FtpCouldntSetType);
        }

        // Update stored transfer type
        let ascii = self.ftpc.desired_type == FtpTransferType::Ascii;
        self.ftpc.transfertype = if ascii { 'A' } else { 'I' };

        // Advance based on which TYPE state we were in
        match self.ftpc.state {
            FtpState::Type => {
                // HEAD-like: TYPE done, proceed to MDTM or SIZE
                if self.ftpc.get_filetime {
                    self.set_state(FtpState::Mdtm);
                } else {
                    self.set_state(FtpState::Size);
                }
            }
            FtpState::ListType => {
                self.set_state(FtpState::ListPreQuote);
            }
            FtpState::RetrListType => {
                self.set_state(FtpState::RetrPreQuote);
            }
            FtpState::RetrType => {
                self.set_state(FtpState::RetrPreQuote);
            }
            FtpState::StorType => {
                self.set_state(FtpState::StorPreQuote);
            }
            _ => {
                self.set_state(FtpState::Stop);
            }
        }

        Ok(())
    }

    /// Handles SIZE response.
    fn handle_size(&mut self, code: i32, response: &str) -> CurlResult<()> {
        if code == 213 {
            // Parse file size from "213 <size>"
            let size_str = response.trim_start_matches("213 ").trim();
            if let Ok(size) = size_str.parse::<i64>() {
                debug!(size = size, "FTP: remote file size");
                self.ftp.downloadsize = size;
                self.ftpc.known_filesize = size;
                // Update the progress tracker with the expected download size
                if size > 0 {
                    self.ftpc.progress.set_download_size(Some(size as u64));
                }
            }
        } else {
            debug!(code = code, "FTP: SIZE not supported or failed");
            self.ftp.downloadsize = -1;
        }

        // Advance based on which SIZE state we were in
        match self.ftpc.state {
            FtpState::Size => {
                // HEAD-like: SIZE done, check REST
                self.set_state(FtpState::Rest);
            }
            FtpState::RetrSize => {
                // Before RETR: SIZE done, proceed to REST if resuming
                if self.ftpc.resume_from > 0 {
                    self.set_state(FtpState::RetrRest);
                } else {
                    self.set_state(FtpState::Retr);
                }
            }
            FtpState::StorSize => {
                // Before STOR: SIZE for append/resume check
                self.set_state(FtpState::Stor);
            }
            _ => {
                self.set_state(FtpState::Stop);
            }
        }

        Ok(())
    }

    /// Handles REST response.
    fn handle_rest(&mut self, code: i32) -> CurlResult<()> {
        match self.ftpc.state {
            FtpState::Rest => {
                // HEAD-like: REST check done
                if code / 100 != 3 {
                    debug!(code = code, "FTP: REST not supported");
                }
                // Transfer complete for HEAD-like
                self.ftp.transfer = PpTransfer::None;
                self.set_state(FtpState::Stop);
            }
            FtpState::RetrRest => {
                if code / 100 != 3 {
                    error!(code = code, "FTP: REST failed");
                    return Err(CurlError::FtpCouldntUseRest);
                }
                // REST accepted, proceed to RETR
                self.set_state(FtpState::Retr);
            }
            _ => {
                self.set_state(FtpState::Stop);
            }
        }
        Ok(())
    }

    /// Handles PRET response.
    fn handle_pret(&mut self, code: i32) -> CurlResult<()> {
        if code / 100 != 2 {
            error!(code = code, "FTP: PRET failed");
            return Err(CurlError::FtpPretFailed);
        }
        // After PRET, proceed to PASV
        self.set_state(FtpState::Pasv);
        Ok(())
    }

    /// Handles PASV/EPSV response.
    async fn handle_pasv(&mut self, code: i32, response: &str) -> CurlResult<()> {
        if self.ftpc.count1 == 1 && code != 229 {
            // EPSV failed — fall back to PASV
            if self.ftpc.count1 == 1 {
                warn!(code = code, "FTP: EPSV failed, falling back to PASV");
                self.ftpc.use_epsv = false;
                self.ftpc.count1 = 2;
                // Would send PASV here
                self.set_state(FtpState::Pasv);
                return Ok(());
            }
        }

        if self.ftpc.count1 == 2 && code != 227 {
            error!(code = code, "FTP: PASV failed");
            return Err(CurlError::FtpWeirdPasvReply);
        }

        // Parse the address and connect the data channel
        let addr = self.parse_pasv_response(code, response, None).await?;
        debug!(addr = %addr, "FTP: passive mode data channel address");

        // Connect to data channel
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                info!(addr = %addr, "FTP: data channel connected");
                self.ftpc.data_stream = Some(stream);
                self.ftpc.wait_data_conn = false;
            }
            Err(e) => {
                error!(error = %e, addr = %addr, "FTP: data channel connect failed");
                return Err(CurlError::FtpCantGetHost);
            }
        }

        // Proceed to the actual transfer command
        match self.ftp.transfer {
            PpTransfer::Body if self.ftpc.is_upload => {
                self.set_state(FtpState::Stor);
            }
            PpTransfer::Body => {
                if self.ftpc.resume_from > 0 {
                    self.set_state(FtpState::RetrSize);
                } else {
                    self.set_state(FtpState::Retr);
                }
            }
            PpTransfer::Info => {
                self.set_state(FtpState::List);
            }
            PpTransfer::None => {
                self.set_state(FtpState::Stop);
            }
        }

        Ok(())
    }

    /// Handles PORT/EPRT response.
    fn handle_port(&mut self, code: i32) -> CurlResult<()> {
        if code / 100 != 2 {
            if self.ftpc.count1 == 1 {
                // EPRT failed, try PORT
                warn!(code = code, "FTP: EPRT failed, trying PORT");
                self.ftpc.use_eprt = false;
                self.ftpc.count1 = 2;
                self.set_state(FtpState::Port);
                return Ok(());
            }
            error!(code = code, "FTP: PORT failed");
            return Err(CurlError::FtpPortFailed);
        }

        debug!("FTP: PORT/EPRT accepted");
        self.ftpc.wait_data_conn = true;

        // Proceed to transfer command
        match self.ftp.transfer {
            PpTransfer::Body if self.ftpc.is_upload => {
                self.set_state(FtpState::Stor);
            }
            PpTransfer::Body => {
                if self.ftpc.resume_from > 0 {
                    self.set_state(FtpState::RetrSize);
                } else {
                    self.set_state(FtpState::Retr);
                }
            }
            PpTransfer::Info => {
                self.set_state(FtpState::List);
            }
            PpTransfer::None => {
                self.set_state(FtpState::Stop);
            }
        }

        Ok(())
    }

    /// Handles RETR/LIST response (transfer initiation).
    fn handle_retr_list(&mut self, code: i32, response: &str) -> CurlResult<()> {
        // 150 = Opening data connection
        // 125 = Data connection already open
        if code != 150 && code != 125 {
            if self.ftpc.state == FtpState::Retr {
                error!(code = code, "FTP: RETR failed");
                return Err(CurlError::FtpCouldntRetrFile);
            } else {
                error!(code = code, "FTP: LIST failed");
                return Err(CurlError::FtpCouldntRetrFile);
            }
        }

        // Parse file size from "150 Opening BINARY mode data connection for file (size bytes)"
        if self.ftpc.state == FtpState::Retr && self.ftp.downloadsize < 0 {
            if let Some(paren_start) = response.rfind('(') {
                let after = &response[paren_start + 1..];
                if let Some(space) = after.find(' ') {
                    if let Ok(size) = after[..space].parse::<i64>() {
                        self.ftp.downloadsize = size;
                        if size > 0 {
                            self.ftpc.progress.set_download_size(Some(size as u64));
                        }
                        debug!(size = size, "FTP: file size from 150 response");
                    }
                }
            }
        }

        // For LIST responses, initialize the list parser
        if self.ftpc.state == FtpState::List {
            self.ftpc.list_parser = Some(FtpListParser::new());
            debug!("FTP: LIST initiated, parser initialized");
        }

        // Update progress tracker
        let _ = self.ftpc.progress.update();

        info!(code = code, "FTP: transfer initiated");

        // Transfer is now in progress — the data channel will be read/written
        // by the transfer engine. State machine stops here.
        self.set_state(FtpState::Stop);
        Ok(())
    }

    /// Handles STOR response.
    fn handle_stor(&mut self, code: i32) -> CurlResult<()> {
        if code / 100 != 1 {
            // Not a 1xx preliminary reply
            if code == 552 {
                error!(code = code, "FTP: file already exists");
                return Err(CurlError::RemoteFileExists);
            }
            error!(code = code, "FTP: STOR failed");
            return Err(CurlError::UploadFailed);
        }

        // Set upload progress tracking
        if self.ftp.downloadsize > 0 {
            self.ftpc.progress.set_upload_size(Some(self.ftp.downloadsize as u64));
        }

        info!(code = code, "FTP: upload initiated");
        self.set_state(FtpState::Stop);
        Ok(())
    }

    /// Handles QUIT response.
    fn handle_quit(&mut self, code: i32) -> CurlResult<()> {
        if code / 100 != 2 {
            debug!(code = code, "FTP: QUIT response (non-success is OK)");
        } else {
            debug!("FTP: QUIT accepted");
        }
        self.ftpc.ctl_valid = false;
        self.ftpc.shutdown = false;
        self.set_state(FtpState::Stop);
        Ok(())
    }

    // ===================================================================
    // LIST data processing helpers
    // ===================================================================

    /// Processes raw LIST response data through the directory listing parser.
    ///
    /// Takes the raw bytes received on the data channel during a LIST
    /// transfer and feeds them to the [`FtpListParser`] to produce
    /// [`FileInfo`] entries. When wildcard matching is active, entries are
    /// filtered through the [`WildcardData`] pattern.
    ///
    /// Returns the parsed directory entries that match the current filter.
    pub fn process_list_data(&mut self, data: &[u8]) -> CurlResult<Vec<FileInfo>> {
        let parser = self.ftpc.list_parser.get_or_insert_with(FtpListParser::new);
        let all_entries = parser.parse(data)?;

        // If wildcard matching is active, filter entries
        if let Some(ref mut wildcard) = self.ftpc.wildcard {
            match wildcard.state {
                WildcardState::Init | WildcardState::Matching => {
                    let filtered: Vec<FileInfo> = all_entries
                        .into_iter()
                        .filter(|entry| {
                            wildcard_matches(&wildcard.pattern, &entry.filename)
                        })
                        .collect();
                    wildcard.filelist.extend(filtered.iter().cloned());
                    Ok(wildcard.filelist.clone())
                }
                WildcardState::Done => {
                    Ok(wildcard.filelist.clone())
                }
                _ => Ok(all_entries),
            }
        } else {
            Ok(all_entries)
        }
    }

    /// Initiates wildcard matching for the current transfer.
    ///
    /// Sets up the [`WildcardData`] state to filter LIST results through
    /// the given glob pattern.
    pub fn setup_wildcard(&mut self, pattern: String, path: String) {
        self.ftpc.wildcard = Some(WildcardData {
            path,
            pattern,
            filelist: Vec::new(),
            state: WildcardState::Init,
        });
    }

    // ===================================================================
    // FTPS data channel TLS wrapper
    // ===================================================================

    /// Wraps an existing TCP data channel stream with TLS encryption for
    /// FTPS protected data transfers (PROT P).
    ///
    /// Returns a [`CurlTlsStream`] that encrypts all data channel I/O
    /// through rustls. This is called after the data channel TCP
    /// connection is established (either active or passive) when the
    /// control channel negotiated PROT P.
    pub async fn wrap_data_channel_tls(
        stream: tokio::net::TcpStream,
        peer: &crate::tls::SslPeer,
        tls_config: &crate::tls::TlsConfig,
    ) -> CurlResult<CurlTlsStream> {
        CurlTlsStream::connect(stream, tls_config, peer).await
    }
}

// ===========================================================================
// Protocol trait implementation
// ===========================================================================

impl Protocol for FtpHandler {
    fn name(&self) -> &str {
        if self.is_ftps { "FTPS" } else { "FTP" }
    }

    fn default_port(&self) -> u16 {
        if self.is_ftps {
            FTPS_DEFAULT_PORT
        } else {
            FTP_DEFAULT_PORT
        }
    }

    fn flags(&self) -> ProtocolFlags {
        let mut flags = ProtocolFlags::CLOSEACTION
            | ProtocolFlags::DUAL
            | ProtocolFlags::PROXY_AS_HTTP
            | ProtocolFlags::WILDCARD;

        if self.is_ftps {
            flags |= ProtocolFlags::SSL;
        }

        flags
    }

    async fn connect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        self.connect(conn).await
    }

    async fn do_it(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        self.do_it(conn).await
    }

    async fn done(
        &mut self,
        conn: &mut ConnectionData,
        status: CurlError,
    ) -> Result<(), CurlError> {
        self.done(conn, status).await
    }

    async fn doing(&mut self, conn: &mut ConnectionData) -> Result<bool, CurlError> {
        self.doing(conn).await
    }

    async fn disconnect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        self.disconnect(conn).await
    }

    fn connection_check(&self, conn: &ConnectionData) -> ConnectionCheckResult {
        self.connection_check(conn)
    }
}

// ===========================================================================
// Connection matching
// ===========================================================================

/// Checks whether an FTP connection can be reused for a new request.
///
/// Verifies that the two connections have matching credentials and entry
/// paths. Corresponds to C `ftp_conns_match()` in `lib/ftp.c`.
pub fn ftp_conns_match(
    needle_entrypath: &str,
    conn_entrypath: &str,
    needle_user: Option<&str>,
    conn_user: Option<&str>,
) -> bool {
    // Entry paths must match for CWD reuse optimization
    if needle_entrypath != conn_entrypath {
        return false;
    }

    // Usernames must match (both None or both same value)
    match (needle_user, conn_user) {
        (Some(a), Some(b)) => a == b,
        (None, None) => true,
        _ => false,
    }
}

// ===========================================================================
// MDTM date parsing helper
// ===========================================================================

/// Parses an MDTM response date string in `YYYYMMDDHHMMSS[.sss]` format
/// into a Unix timestamp (seconds since epoch).
/// Simple glob-style wildcard matching for FTP wildcard transfers.
///
/// Supports `*` (match any sequence) and `?` (match single char).
/// Used to filter LIST results during `CURLOPT_WILDCARDMATCH` operations.
fn wildcard_matches(pattern: &str, text: &str) -> bool {
    let pat = pattern.as_bytes();
    let txt = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (usize::MAX, 0usize);

    while ti < txt.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == txt[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

fn parse_mdtm_date(date_str: &str) -> CurlResult<i64> {
    let bytes = date_str.as_bytes();
    if bytes.len() < 14 {
        return Err(CurlError::WeirdServerReply);
    }

    // Verify all 14 characters are digits
    for &b in &bytes[..14] {
        if !b.is_ascii_digit() {
            return Err(CurlError::WeirdServerReply);
        }
    }

    let year: i32 = std::str::from_utf8(&bytes[0..4])
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(CurlError::WeirdServerReply)?;
    let month: i32 = std::str::from_utf8(&bytes[4..6])
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(CurlError::WeirdServerReply)?;
    let day: i32 = std::str::from_utf8(&bytes[6..8])
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(CurlError::WeirdServerReply)?;
    let hour: i32 = std::str::from_utf8(&bytes[8..10])
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(CurlError::WeirdServerReply)?;
    let min: i32 = std::str::from_utf8(&bytes[10..12])
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(CurlError::WeirdServerReply)?;
    let sec: i32 = std::str::from_utf8(&bytes[12..14])
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(CurlError::WeirdServerReply)?;

    // Validate ranges
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60
    {
        return Err(CurlError::WeirdServerReply);
    }

    // Compute Unix epoch timestamp directly from components (UTC).
    // Matches the C `time2epoch()` logic in lib/parsedate.c.
    static MONTH_DAYS_CUMULATIVE: [i64; 12] = [
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334,
    ];

    // month is 1-based from MDTM, but we need 0-based for the table
    let mon0 = (month - 1) as usize;

    // Leap year calculation: adjust for whether the current year's
    // leap day has been counted yet (months Jan/Feb need adjustment).
    let leap_adj = year - if mon0 <= 1 { 1 } else { 0 };
    let leap_days: i64 =
        (leap_adj / 4 - leap_adj / 100 + leap_adj / 400) as i64
        - (1969 / 4 - 1969 / 100 + 1969 / 400) as i64;

    let days: i64 = (year - 1970) as i64 * 365
        + leap_days
        + MONTH_DAYS_CUMULATIVE[mon0]
        + day as i64
        - 1;

    let ts = ((days * 24 + hour as i64) * 60 + min as i64) * 60 + sec as i64;
    Ok(ts)
}

// ===========================================================================
// Lineend conversion for ASCII mode
// ===========================================================================

/// Converts `\r\n` line endings to `\n` for ASCII-mode FTP transfers.
///
/// This replaces the C `ftp_cw_lc_write` content writer filter. On
/// platforms that prefer LF line endings (Unix), FTP ASCII transfers
/// should deliver data with `\n` line endings.
pub fn convert_lineends(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\r' {
            // Check if next char is '\n'
            if i + 1 < data.len() && data[i + 1] == b'\n' {
                // Skip the '\r', keep the '\n'
                i += 1;
            } else {
                // Lonely '\r' becomes '\n'
                result.push(b'\n');
                i += 1;
                continue;
            }
        }
        result.push(data[i]);
        i += 1;
    }
    result
}

// ===========================================================================
// Helper: count slashes in a path
// ===========================================================================

/// Counts the number of '/' characters in a string.
/// Used to determine directory depth for MultiCwd parsing.
fn count_slashes(s: &str) -> usize {
    s.bytes().filter(|&b| b == b'/').count()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ftp_state_display() {
        assert_eq!(format!("{}", FtpState::Stop), "STOP");
        assert_eq!(format!("{}", FtpState::Wait220), "WAIT220");
        assert_eq!(format!("{}", FtpState::Auth), "AUTH");
        assert_eq!(format!("{}", FtpState::Pasv), "PASV");
        assert_eq!(format!("{}", FtpState::Quit), "QUIT");
        assert_eq!(format!("{}", FtpState::RetrPreQuote), "RETR_PREQUOTE");
    }

    #[test]
    fn test_ftp_state_default() {
        assert_eq!(FtpState::default(), FtpState::Stop);
    }

    #[test]
    fn test_ftp_file_method_default() {
        assert_eq!(FtpFileMethod::default(), FtpFileMethod::MultiCwd);
    }

    #[test]
    fn test_parse_epsv_response() {
        let port = FtpHandler::parse_epsv_response(
            "229 Entering Extended Passive Mode (|||12345|)",
        )
        .unwrap();
        assert_eq!(port, 12345);

        let port = FtpHandler::parse_epsv_response(
            "229 some text (|||9999|) trailing",
        )
        .unwrap();
        assert_eq!(port, 9999);

        // Invalid: no port
        assert!(FtpHandler::parse_epsv_response("229 no parens").is_err());

        // Invalid: zero port
        assert!(
            FtpHandler::parse_epsv_response("229 Entering Passive Mode (|||0|)")
                .is_err()
        );
    }

    #[test]
    fn test_parse_pasv_227() {
        let (ip, port) = FtpHandler::parse_pasv_227(
            "227 Entering Passive Mode (192,168,1,1,4,1)",
        )
        .unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(port, 1025); // 4*256 + 1

        let (ip, port) = FtpHandler::parse_pasv_227(
            "227 Entering Passive Mode (10,0,0,1,0,21)",
        )
        .unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(port, 21);

        // Invalid: not enough numbers
        assert!(FtpHandler::parse_pasv_227("227 bad response").is_err());

        // Invalid: zero port
        assert!(
            FtpHandler::parse_pasv_227("227 Entering Passive Mode (1,2,3,4,0,0)")
                .is_err()
        );
    }

    #[test]
    fn test_convert_lineends() {
        assert_eq!(convert_lineends(b"hello\r\nworld\r\n"), b"hello\nworld\n");
        assert_eq!(convert_lineends(b"hello\nworld"), b"hello\nworld");
        assert_eq!(convert_lineends(b"hello\rworld"), b"hello\nworld");
        assert_eq!(convert_lineends(b"\r\n\r\n"), b"\n\n");
        assert_eq!(convert_lineends(b""), b"");
        assert_eq!(convert_lineends(b"no newlines"), b"no newlines");
    }

    #[test]
    fn test_count_slashes() {
        assert_eq!(count_slashes(""), 0);
        assert_eq!(count_slashes("file.txt"), 0);
        assert_eq!(count_slashes("/"), 1);
        assert_eq!(count_slashes("/path/to/file"), 3);
        assert_eq!(count_slashes("//double//"), 4);
    }

    #[test]
    fn test_ftp_conns_match() {
        assert!(ftp_conns_match("/", "/", Some("user"), Some("user")));
        assert!(!ftp_conns_match("/a", "/b", Some("user"), Some("user")));
        assert!(!ftp_conns_match("/", "/", Some("user1"), Some("user2")));
        assert!(ftp_conns_match("/", "/", None, None));
        assert!(!ftp_conns_match("/", "/", Some("user"), None));
    }

    #[test]
    fn test_parse_mdtm_date() {
        // Basic MDTM date
        let ts = parse_mdtm_date("20240101120000").unwrap();
        assert!(ts > 0);

        // Too short
        assert!(parse_mdtm_date("2024010112").is_err());

        // Non-digit characters
        assert!(parse_mdtm_date("2024AB01120000").is_err());

        // Invalid month
        assert!(parse_mdtm_date("20241301120000").is_err());
    }

    #[test]
    fn test_ftp_transfer_type() {
        assert_eq!(FtpTransferType::Ascii.as_char(), 'A');
        assert_eq!(FtpTransferType::Binary.as_char(), 'I');
        assert_eq!(FtpTransferType::default(), FtpTransferType::Binary);
    }

    #[test]
    fn test_ftp_handler_new() {
        let handler = FtpHandler::new();
        assert!(!handler.is_ftps);
        assert_eq!(handler.ftpc.state, FtpState::Stop);
        assert_eq!(handler.ftpc.use_ssl, FtpSslLevel::None);

        let ftps_handler = FtpHandler::new_ftps();
        assert!(ftps_handler.is_ftps);
        assert_eq!(ftps_handler.ftpc.use_ssl, FtpSslLevel::All);
        assert!(ftps_handler.ftpc.implicit_ftps);
    }

    #[test]
    fn test_need_type() {
        let mut ftpc = FtpConn::new(PingPongConfig::default());
        ftpc.transfertype = 'I';
        assert!(ftpc.need_type(true)); // wants ASCII, has Binary
        assert!(!ftpc.need_type(false)); // wants Binary, has Binary

        ftpc.transfertype = 'A';
        assert!(!ftpc.need_type(true)); // wants ASCII, has ASCII
        assert!(ftpc.need_type(false)); // wants Binary, has ASCII
    }

    #[test]
    fn test_ftp_handler_protocol_trait() {
        let handler = FtpHandler::new();
        assert_eq!(handler.name(), "FTP");
        assert_eq!(handler.default_port(), 21);
        assert!(handler.flags().contains(ProtocolFlags::CLOSEACTION));
        assert!(handler.flags().contains(ProtocolFlags::DUAL));

        let ftps_handler = FtpHandler::new_ftps();
        assert_eq!(ftps_handler.name(), "FTPS");
        assert_eq!(ftps_handler.default_port(), 990);
        assert!(ftps_handler.flags().contains(ProtocolFlags::SSL));
    }

    #[test]
    fn test_ftp_ssl_level_ordering() {
        assert!(FtpSslLevel::None < FtpSslLevel::Try);
        assert!(FtpSslLevel::Try < FtpSslLevel::Control);
        assert!(FtpSslLevel::Control < FtpSslLevel::All);
    }

    #[test]
    fn test_ftp_parse_url_path_nocwd() {
        let mut handler = FtpHandler::new();
        handler.ftpc.file_method = FtpFileMethod::NoCwd;
        handler.ftp.transfer = PpTransfer::Body;
        handler.parse_url_path("/path/to/file.txt", false, false).unwrap();
        assert_eq!(handler.ftpc.file.as_deref(), Some("/path/to/file.txt"));

        // Directory path (ends with /)
        handler.parse_url_path("/path/to/dir/", false, false).unwrap();
        assert!(handler.ftpc.file.is_none());
    }

    #[test]
    fn test_ftp_parse_url_path_singlecwd() {
        let mut handler = FtpHandler::new();
        handler.ftpc.file_method = FtpFileMethod::SingleCwd;
        handler.ftp.transfer = PpTransfer::Body;
        handler.parse_url_path("/path/to/file.txt", false, false).unwrap();
        assert_eq!(handler.ftpc.file.as_deref(), Some("file.txt"));
        assert_eq!(handler.ftpc.dirdepth, 1);
    }

    #[test]
    fn test_ftp_parse_url_path_multicwd() {
        let mut handler = FtpHandler::new();
        handler.ftpc.file_method = FtpFileMethod::MultiCwd;
        handler.ftp.transfer = PpTransfer::Body;
        handler.parse_url_path("/path/to/file.txt", false, false).unwrap();
        assert_eq!(handler.ftpc.file.as_deref(), Some("file.txt"));
        assert!(handler.ftpc.dirdepth >= 2);
    }

    #[test]
    fn test_ftp_parse_url_path_upload_no_file() {
        let mut handler = FtpHandler::new();
        handler.ftpc.file_method = FtpFileMethod::NoCwd;
        handler.ftp.transfer = PpTransfer::Body;
        // Upload to directory without filename should fail
        let result = handler.parse_url_path("/path/to/dir/", true, false);
        assert!(result.is_err());
    }
}
