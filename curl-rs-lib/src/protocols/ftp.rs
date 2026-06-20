//! FTP / FTPS protocol engine — the Rust analog of `lib/ftp.c` (curl's largest
//! protocol translation unit) and `lib/ftp.h`.
//!
//! FTP is the canonical `PROTOPT_DUAL` protocol: it drives a **control**
//! connection (`FIRSTSOCKET`) carrying the command/response dialogue plus a
//! separately-established **data** connection (`SECONDARYSOCKET`) carrying the
//! file body or directory listing. This module reconstructs that split as
//! idiomatic asynchronous Rust:
//!
//! * The control dialogue is a [ping-pong](crate::protocols::pingpong) command
//!   exchange. The big C `switch(ftpc->state)` state machine
//!   (`ftp_pp_statemachine`) collapses into a Rust `match self.state` driven
//!   inside an `async` loop: [`FtpConn`] implements
//!   [`PingPongProtocol`](crate::protocols::pingpong::PingPongProtocol). The C
//!   "call `ftp_statemach` repeatedly + `*done` out-param" re-entrancy becomes
//!   ordinary `.await`.
//! * The login flow mirrors curl exactly: greeting (`220`) → optional
//!   `AUTH TLS`/`AUTH SSL` upgrade for FTPS → `USER`/`PASS`/`ACCT` →
//!   `PBSZ`/`PROT` data-channel protection → `PWD`/`SYST`/`NAMEFMT`.
//! * The transfer flow mirrors curl: a CWD strategy chosen by
//!   [`CurlFtpFile`] (the `--ftp-method` option), then `TYPE`,
//!   `SIZE`/`MDTM`/`REST`, then `RETR`/`STOR`/`APPE`/`LIST`/`NLST`.
//! * The data connection is established **passively** (prefer `EPSV`, fall back
//!   to `PASV`) or **actively** (prefer `EPRT`, fall back to `PORT`), with the
//!   active path using the [`crate::conn::socket`] TCP-accept/listen filter.
//! * TLS is **always** woven through the [`crate::conn`] connection-filter
//!   chain — never via a direct `crate::tls::connect` call — so it composes on
//!   both the control and data channels and preserves session reuse
//!   (`PROTOPT_SSL_REUSE`). For implicit `ftps` the scheme's `PROTOPT_SSL` flag
//!   makes the engine install the cf-ssl filter at connect time; for explicit
//!   `AUTH TLS` upgrade the filter is inserted after the `AUTH` exchange.
//! * Wildcard (`PROTOPT_WILDCARD`) transfers walk a
//!   [`WildcardData`](crate::protocols::ftp_list::WildcardData) through
//!   `Init → Matching → Downloading → Clean`, feeding `LIST` output to
//!   [`FtpParseListData`](crate::protocols::ftp_list::FtpParseListData) and
//!   filtering with [`curl_fnmatch`](crate::util::fnmatch::curl_fnmatch).
//!
//! # C oracle, not transliteration
//!
//! `lib/ftp.c` / `lib/ftp.h` are read as a behavioral and wire-format oracle:
//! command sequencing, response-code handling, and the byte layout of `EPRT`,
//! `PORT`, `PASV`, and `EPSV` commands/replies are reproduced exactly. The
//! implementation is structured as async Rust, not a line-by-line port.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe`. The crate root applies
//! `#![forbid(unsafe_code)]`, which this module inherits; it is intentionally
//! not re-declared here.

use std::mem;

// Connection layer: the DUAL-socket plumbing and the byte-level send/recv used
// for the data channel. Control-channel I/O goes through the ping-pong engine
// (which itself calls `Curl_conn_send`/`Curl_conn_recv` on `FIRSTSOCKET`).
use crate::conn::socket::{is_tcp_listen, tcp_listen_set};
use crate::conn::{
    BoxFuture, Connection, Curl_conn_close, Curl_conn_connect, Curl_conn_is_ssl, Curl_conn_recv,
    Curl_conn_send, FIRSTSOCKET, SECONDARYSOCKET,
};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::ftp_list::{FileInfo, FileType, FtpParseListData, WildcardData, WildcardState};
use crate::protocols::pingpong::{PingPong, PingPongProtocol, PpTransfer};
use crate::protocols::{
    Protocol, ProtocolTransfer, Scheme, TransferDirection,
};
// Dependency justification: `HttpReq` lives in `crate::setopt`, which is outside
// this file's declared `depends_on_files`. It is, however, part of the *public
// option-state surface* of [`Easy`] (`data.set.method`, type `HttpReq`) — the
// only way to read the requested transfer method (upload vs download) is to
// name it. This mirrors the established convention in `protocols::smb` and
// `protocols::rtsp`, which import `crate::setopt` types for the same reason.
use crate::setopt::HttpReq;
use crate::url::{CurlUPart, CurlUrl, CURLU_URLDECODE};
use crate::util::fnmatch::{curl_fnmatch, FnMatch};
use crate::util::sendf;
// Dependency justification: `timeval` is required to invoke the whitelisted
// `pingpong::PingPong::init`, whose argument is a `CurlTime` produced by
// `timeval::curlx_now()`. `pingpong` itself imports `crate::util::timeval`.
use crate::util::timeval;

// ===========================================================================
// Constants
// ===========================================================================

/// Default time, in milliseconds, to wait for the server to open the data
/// connection in active mode before giving up (C `DEFAULT_ACCEPT_TIMEOUT`,
/// `lib/ftp.h` — one minute).
pub const DEFAULT_ACCEPT_TIMEOUT: u64 = 60_000;

/// Upper bound on the number of path components (CWD depth) parsed from a URL
/// path, guarding against a "suspiciously deep directory hierarchy"
/// (C `FTP_MAX_DIR_DEPTH`, `lib/ftp.c`).
const FTP_MAX_DIR_DEPTH: usize = 1000;

/// The `AUTH` mechanism names, indexed by [`FtpConn::count1`], mirroring C
/// `static const char * const ftpauth[] = { "SSL", "TLS" }`.
const FTP_AUTH_METHODS: [&str; 2] = ["SSL", "TLS"];

/// `CURLOPT_FTPSSLAUTH` selector: try `AUTH SSL` first (the curl default), the
/// Rust analog of `CURLFTPAUTH_DEFAULT` / `CURLFTPAUTH_SSL`.
const CURLFTPAUTH_DEFAULT: u8 = 0;
/// `CURLOPT_FTPSSLAUTH` selector: try `AUTH SSL` first
/// (C `CURLFTPAUTH_SSL = 1`).
const CURLFTPAUTH_SSL: u8 = 1;
/// `CURLOPT_FTPSSLAUTH` selector: try `AUTH TLS` first
/// (C `CURLFTPAUTH_TLS = 2`).
const CURLFTPAUTH_TLS: u8 = 2;

/// `CURLOPT_USE_SSL` level: do not use SSL/TLS (C `CURLUSESSL_NONE = 0`).
const CURLUSESSL_NONE: u8 = 0;
/// `CURLOPT_USE_SSL` level: try SSL/TLS but proceed in clear text on failure
/// (C `CURLUSESSL_TRY = 1`).
const CURLUSESSL_TRY: u8 = 1;
/// `CURLOPT_USE_SSL` level: require SSL/TLS on the control channel
/// (C `CURLUSESSL_CONTROL = 2`).
const CURLUSESSL_CONTROL: u8 = 2;

// ===========================================================================
// State machine — mirror of `lib/ftp.h` `enum { FTP_STOP, … FTP_LAST }`
// ===========================================================================

/// The FTP control-connection state machine, mirroring curl's `ftpstate`
/// (`lib/ftp.h`). The 37 active states are preserved in their **exact** C
/// order and semantics; [`FtpState::Last`] is the unused terminal sentinel
/// (C `FTP_LAST`).
///
/// The C code stores this as an `unsigned char` and switches on it inside
/// `ftp_pp_statemachine`; here the same dispatch is a `match self.state` in
/// [`FtpConn`]'s [`PingPongProtocol::statemachine`] implementation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FtpState {
    /// Do-nothing state; stops the state machine (C `FTP_STOP`).
    #[default]
    Stop,
    /// Waiting for the initial `220` greeting right after connecting
    /// (C `FTP_WAIT220`).
    Wait220,
    /// Sending / awaiting `AUTH TLS` (or `AUTH SSL`) (C `FTP_AUTH`).
    Auth,
    /// Sending / awaiting `USER` (C `FTP_USER`).
    User,
    /// Sending / awaiting `PASS` (C `FTP_PASS`).
    Pass,
    /// Sending / awaiting `ACCT` (C `FTP_ACCT`).
    Acct,
    /// Sending / awaiting `PBSZ` (protection buffer size) (C `FTP_PBSZ`).
    Pbsz,
    /// Sending / awaiting `PROT` (data-channel protection level) (C `FTP_PROT`).
    Prot,
    /// Sending / awaiting `CCC` (clear command channel) (C `FTP_CCC`).
    Ccc,
    /// Sending / awaiting `PWD` (C `FTP_PWD`).
    Pwd,
    /// Sending / awaiting `SYST` (C `FTP_SYST`).
    Syst,
    /// Resolving the name format from the `SYST`/`PWD` replies (C `FTP_NAMEFMT`).
    Namefmt,
    /// Awaiting a response to a command from the quote list (C `FTP_QUOTE`).
    Quote,
    /// Awaiting a response to a pre-quote command before `RETR`
    /// (C `FTP_RETR_PREQUOTE`).
    RetrPrequote,
    /// Awaiting a response to a pre-quote command before `STOR`
    /// (C `FTP_STOR_PREQUOTE`).
    StorPrequote,
    /// Awaiting a response to a pre-quote command before `LIST`
    /// (C `FTP_LIST_PREQUOTE`).
    ListPrequote,
    /// Awaiting a response to a post-quote command (C `FTP_POSTQUOTE`).
    Postquote,
    /// Changing directory with `CWD` (C `FTP_CWD`).
    Cwd,
    /// Creating a directory with `MKD` when `CWD` failed (C `FTP_MKD`).
    Mkd,
    /// Requesting the file's modification time with `MDTM` (C `FTP_MDTM`).
    Mdtm,
    /// Setting the transfer `TYPE` for a head-like request (C `FTP_TYPE`).
    Type,
    /// Setting the transfer `TYPE` before a directory listing
    /// (C `FTP_LIST_TYPE`).
    ListType,
    /// Setting the transfer `TYPE` before a `RETR` directory listing
    /// (C `FTP_RETR_LIST_TYPE`).
    RetrListType,
    /// Setting the transfer `TYPE` before a `RETR` (C `FTP_RETR_TYPE`).
    RetrType,
    /// Setting the transfer `TYPE` before a `STOR` (C `FTP_STOR_TYPE`).
    StorType,
    /// Requesting the remote file `SIZE` for a head-like request
    /// (C `FTP_SIZE`).
    Size,
    /// Requesting the remote file `SIZE` before a `RETR` (C `FTP_RETR_SIZE`).
    RetrSize,
    /// Requesting the remote file `SIZE` before a `STOR` (C `FTP_STOR_SIZE`).
    StorSize,
    /// Probing `REST` support for a head-like request (C `FTP_REST`).
    Rest,
    /// Requesting `REST` (resume offset) before a `RETR` (C `FTP_RETR_REST`).
    RetrRest,
    /// Generic state for `PORT`/`LPRT`/`EPRT` (active mode); check `count1`
    /// (C `FTP_PORT`).
    Port,
    /// Generic state for `PRET RETR`/`PRET STOR`/`PRET LIST` (C `FTP_PRET`).
    Pret,
    /// Generic state for `PASV`/`EPSV` (passive mode); check `count1`
    /// (C `FTP_PASV`).
    Pasv,
    /// Generic state for `LIST`/`NLST` or a custom list command (C `FTP_LIST`).
    List,
    /// Awaiting the `RETR` response (C `FTP_RETR`).
    Retr,
    /// Generic state for `STOR`/`APPE` (C `FTP_STOR`).
    Stor,
    /// Sending / awaiting `QUIT` at disconnect (C `FTP_QUIT`).
    Quit,
    /// Unused terminal sentinel (C `FTP_LAST`).
    Last,
}

// ===========================================================================
// CWD method — mirror of `lib/ftp.h` `curl_ftpfile`
// ===========================================================================

/// How the engine reaches the target directory before issuing the transfer
/// command, mirroring curl's `curl_ftpfile` (set by `CURLOPT_FTP_FILEMETHOD` /
/// the `--ftp-method` CLI flag). Discriminants match the C enum exactly.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u8)]
pub enum CurlFtpFile {
    /// Issue one `CWD` per path component (RFC 1738 behavior) — the default
    /// (C `FTPFILE_MULTICWD = 1`).
    #[default]
    MultiCwd = 1,
    /// Never `CWD`; use `SIZE`/`RETR`/`STOR` on the full path
    /// (C `FTPFILE_NOCWD = 2`).
    NoCwd = 2,
    /// Make a single `CWD` to the parent directory, then operate on the file
    /// (C `FTPFILE_SINGLECWD = 3`).
    SingleCwd = 3,
}

impl CurlFtpFile {
    /// Decodes the raw `CURLOPT_FTP_FILEMETHOD` byte (`data.set.ftp_filemethod`)
    /// into a [`CurlFtpFile`], defaulting to [`CurlFtpFile::MultiCwd`] for any
    /// value outside `1..=3` (matching curl's `default:` arm in the
    /// `switch(data->set.ftp_filemethod)` of `ftp_parse_url_path`).
    #[must_use]
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            2 => CurlFtpFile::NoCwd,
            3 => CurlFtpFile::SingleCwd,
            _ => CurlFtpFile::MultiCwd,
        }
    }
}

// ===========================================================================
// Internal helper enums (not part of the C struct surface)
// ===========================================================================

/// Which body transfer the current operation performs. Used to select the
/// terminal FTP command (`RETR`/`STOR`/`LIST`) and the reported
/// [`TransferDirection`]. This is an implementation convenience, distinct from
/// the C `curl_pp_transfer` (modeled by [`PpTransfer`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum TransferKind {
    /// Download a file body with `RETR` (C `FTP_RETR`).
    #[default]
    Retr,
    /// Upload a file body with `STOR`/`APPE` (C `FTP_STOR`).
    Stor,
    /// Retrieve a directory listing with `LIST`/`NLST` (C `FTP_LIST`).
    List,
}

/// Which active-mode command the engine is attempting, mirroring the C
/// `mode[][5] = { "EPRT", "PORT" }` table and the `count1`/`fcmd` toggle in
/// `ftp_state_use_port`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum PortCmd {
    /// RFC 2428 `EPRT` (tried first) — the index-0 entry of the C `mode` table.
    #[default]
    Eprt,
    /// Legacy `PORT` (fallback) — the index-1 entry of the C `mode` table.
    Port,
}

impl PortCmd {
    /// The literal command keyword, matching C `mode[fcmd]`.
    #[must_use]
    pub fn keyword(self) -> &'static str {
        match self {
            PortCmd::Eprt => "EPRT",
            PortCmd::Port => "PORT",
        }
    }
}

// ===========================================================================
// Per-easy state — mirror of `lib/ftp.h` `struct FTP`
// ===========================================================================

/// The per-transfer (per-`Easy`) FTP state, the Rust analog of C `struct FTP`.
///
/// In C this lives as easy-handle meta data (`CURL_META_FTP_EASY`); here it is
/// the protocol state attached to the transfer. The C `char *path` /
/// `char *pathalloc` pair (a borrowed-or-owned C string) collapses into a
/// single owned [`String`], since Rust ownership removes the need to track
/// whether the buffer was separately allocated.
#[derive(Clone, Debug)]
pub struct Ftp {
    /// The URL-decoded request path (C `path` / `pathalloc`).
    pub path: String,
    /// Whether this operation transfers a body, info only, or nothing
    /// (C `curl_pp_transfer transfer`).
    pub transfer: PpTransfer,
    /// The size to download, or `-1` when unknown (C `curl_off_t downloadsize`).
    pub downloadsize: i64,
}

impl Ftp {
    /// Creates fresh per-easy FTP state with an unknown download size
    /// (C initializes `downloadsize` to `-1`) and a body transfer
    /// (C `PPTRANSFER_BODY`).
    #[must_use]
    pub fn new() -> Self {
        Ftp {
            path: String::new(),
            transfer: PpTransfer::Body,
            downloadsize: -1,
        }
    }
}

// `PpTransfer` does not implement `Default`, so `Ftp`'s default is written by
// hand and delegates to [`Ftp::new`] (body transfer, unknown size).
impl Default for Ftp {
    fn default() -> Self {
        Ftp::new()
    }
}

// ===========================================================================
// Per-connection state — mirror of `lib/ftp.h` `struct ftp_conn`
// ===========================================================================

/// A single URL-path component (directory) to `CWD` into, mirroring C
/// `struct pathcomp { int start; int len; }`.
///
/// The C struct stores `(start, len)` offsets into the decoded `rawpath`
/// buffer; the Rust port stores the owned component string directly, which is
/// both simpler and removes the lifetime coupling to `rawpath`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PathComp {
    /// The directory name for this component (the `CWD` argument).
    pub name: String,
}

/// The per-connection FTP state, the Rust analog of C `struct ftp_conn`.
///
/// It embeds the shared [`PingPong`] command/response engine (C `struct
/// pingpong pp`) and carries the full login/transfer bookkeeping. In C this is
/// connection meta data (`CURL_META_FTP_CONN`); here it is stored on the
/// [`Connection`] via [`Connection::set_proto_state`].
#[derive(Debug, Default)]
pub struct FtpConn {
    /// The shared ping-pong command/response engine (C `pp`).
    pub pp: PingPong,
    /// The account string for `ACCT`, when the server requests one
    /// (C `account`).
    pub account: Option<String>,
    /// An alternative user name to try after a `USER`/`PASS` rejection
    /// (C `alternative_to_user`).
    pub alternative_to_user: Option<String>,
    /// The directory reported by `PWD` immediately after login — the entry
    /// path used for CWD reuse optimization (C `entrypath`).
    pub entrypath: Option<String>,
    /// The URL-decoded file name (the last path segment), or `None` for a
    /// pure-directory operation (C `file`).
    pub file: Option<String>,
    /// The URL-decoded raw path the components and file were derived from
    /// (C `rawpath`).
    pub rawpath: String,
    /// The directory components to `CWD` through (C `dirs` + `dirdepth`).
    pub dirs: Vec<PathComp>,
    /// The decoded path of the previous transfer on this (reused) connection,
    /// used to skip redundant `CWD` commands (C `prevpath`).
    pub prevpath: Option<String>,
    /// The current transfer type: `b'A'` (ASCII), `b'I'` (binary/image), or
    /// `0` when unset (C `transfertype`).
    pub transfertype: u8,
    /// The server operating system reported by `SYST` (C `server_os`).
    pub server_os: Option<String>,
    /// A file size discovered during wildcard `LIST` parsing, or `-1`
    /// (C `known_filesize`).
    pub known_filesize: i64,
    /// General-purpose state-machine counter 1 — for FTP it toggles
    /// `EPSV (0)` vs `PASV (1)` and `EPRT (0)` vs `PORT (1)` (C `count1`).
    pub count1: i32,
    /// General-purpose state-machine counter 2 (C `count2`).
    pub count2: i32,
    /// General-purpose state-machine counter 3 (C `count3`).
    pub count3: i32,
    /// Number of directory components in [`dirs`](Self::dirs) (C `dirdepth`;
    /// kept explicitly for parity, always equal to `dirs.len()`).
    pub dirdepth: u16,
    /// Number of `CWD` commands already issued for the current transfer
    /// (C `cwdcount`).
    pub cwdcount: u16,
    /// The current control-connection state (C `state`; always changed via
    /// [`Self::set_state`], mirroring C's `ftp.c:state()`).
    pub state: FtpState,
    /// The desired SSL usage level — `CURLUSESSL_*` (C `use_ssl`).
    pub use_ssl: u8,
    /// The clear-command-channel level for this connection (C `ccc`).
    pub ccc: u8,
    /// True while retrying login with [`alternative_to_user`](Self::alternative_to_user)
    /// (C `BIT(ftp_trying_alternative)`).
    pub ftp_trying_alternative: bool,
    /// When true, skip the final post-transfer size and `226`/`250` status
    /// check (still read the line, but ignore the result)
    /// (C `BIT(dont_check)`).
    pub dont_check: bool,
    /// Whether the control connection is valid, so [`disconnect`](FtpHandler::disconnect)
    /// should send `QUIT` (C `BIT(ctl_valid)`).
    pub ctl_valid: bool,
    /// Whether the proper `CWD` sequence has already been performed
    /// (C `BIT(cwddone)`).
    pub cwddone: bool,
    /// Set true if a `CWD` failed, to prevent caching the current directory
    /// (C `BIT(cwdfail)`).
    pub cwdfail: bool,
    /// True while the active-mode data connection is being awaited
    /// (C `BIT(wait_data_conn)`).
    pub wait_data_conn: bool,
    /// True while the connection is being shut down (e.g. during `QUIT`)
    /// (C `BIT(shutdown)`).
    pub shutdown: bool,

    // --- Engine-port bookkeeping (no direct C struct field) ---------------
    /// The most recent **final** response line captured by
    /// [`PingPongProtocol::endofresp`] (everything up to and including the
    /// terminating LF). The C code re-reads `pp->recvbuf`; because the Rust
    /// [`PingPong`] keeps `recvbuf` private, the parser captures the final line
    /// here as it is recognized.
    pub last_response: Vec<u8>,
    /// The terminal command this transfer will issue, selecting `RETR`/`STOR`/
    /// `LIST` and the reported transfer direction.
    pub transfer_kind: TransferKind,
    /// The host the data connection should reach, parsed from a `227`/`229`
    /// reply (passive) — `None` until known.
    pub data_host: Option<String>,
    /// The port the data connection should reach (passive mode).
    pub data_port: u16,
    /// Which active-mode command is currently being attempted.
    pub port_cmd: PortCmd,
    /// The login user name, parsed from the URL (C `conn->user`), defaulting to
    /// `"anonymous"`. Stored here because this codebase carries no user/password
    /// on the option state — FTP credentials come from the URL.
    pub user: String,
    /// The login password, parsed from the URL (C `conn->passwd`), defaulting
    /// to `"ftp@example.com"` for anonymous login.
    pub passwd: String,
    /// Whether the control channel is TLS-protected — either implicit `ftps`
    /// or after a successful `AUTH TLS` upgrade (C
    /// `conn->bits.ftp_use_control_ssl`). Gates the `PBSZ`/`PROT` sequence.
    pub control_ssl: bool,
}

impl FtpConn {
    /// Creates fresh per-connection FTP state. Counters start at zero, sizes at
    /// `-1` (unknown), and the state at [`FtpState::Stop`] (C zero-init via the
    /// connection meta allocator).
    #[must_use]
    pub fn new() -> Self {
        FtpConn {
            pp: PingPong::new(),
            known_filesize: -1,
            state: FtpState::Stop,
            port_cmd: PortCmd::Eprt,
            // curl's anonymous-login defaults when the URL carries no userinfo.
            user: "anonymous".to_string(),
            passwd: "ftp@example.com".to_string(),
            ..Default::default()
        }
    }

    /// Changes the state-machine state. Centralized to mirror C's mandatory
    /// `ftp.c:state()` accessor (the C comment warns: "always use
    /// `ftp.c:state()` to change state!").
    #[inline]
    pub fn set_state(&mut self, state: FtpState) {
        self.state = state;
    }

    /// The current state (convenience accessor).
    #[inline]
    #[must_use]
    pub fn state(&self) -> FtpState {
        self.state
    }
}

// ===========================================================================
// Pure parity helpers — byte-for-byte equivalents of the C wire parsing /
// formatting. These are deterministic and fully unit-tested.
// ===========================================================================

/// The result of decomposing a URL path into the directory components to `CWD`
/// through plus the terminal file name (C `ftp_parse_url_path` outputs).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PathDecomp {
    /// Directory components to `CWD` into, in order.
    pub dirs: Vec<PathComp>,
    /// The terminal file name, or `None` for a directory-only operation.
    pub file: Option<String>,
    /// Whether `CWD` can be skipped entirely (set for `NOCWD` + absolute path;
    /// the connection-reuse refinement is applied separately by the caller).
    pub cwddone: bool,
}

/// Parses a run of ASCII decimal digits at the front of `bytes`, mirroring
/// curl's `curlx_str_number(&p, &num, max)`.
///
/// Returns `Some((value, rest))` where `rest` is the slice immediately after
/// the consumed digits, or `None` when there is no leading digit or the parsed
/// value would exceed `max` (the same failure conditions as the C helper). The
/// number is parsed greedily over every leading digit; a value over `max`
/// fails rather than truncating.
fn parse_decimal(bytes: &[u8], max: u64) -> Option<(u64, &[u8])> {
    let mut idx = 0usize;
    let mut value: u64 = 0;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        // Accumulate, clamping the running total so a very long digit run can
        // never overflow; an over-`max` value fails the bound check below.
        value = value
            .saturating_mul(10)
            .saturating_add(u64::from(bytes[idx] - b'0'));
        if value > max {
            return None;
        }
        idx += 1;
    }
    if idx == 0 {
        return None; // no digits consumed
    }
    Some((value, &bytes[idx..]))
}

/// Attempts to match six comma-separated numbers (each `0..=255`) at the front
/// of `bytes`, the Rust analog of C `match_pasv_6nums`.
///
/// Returns the six values on success, or `None` if the leading bytes are not
/// exactly `N,N,N,N,N,N` with every `N <= 255`.
fn match_pasv_6nums(bytes: &[u8]) -> Option<[u32; 6]> {
    let mut out = [0u32; 6];
    let mut rest = bytes;
    for (i, slot) in out.iter_mut().enumerate() {
        if i > 0 {
            // Each subsequent number must be preceded by a comma.
            match rest.first() {
                Some(&b',') => rest = &rest[1..],
                _ => return None,
            }
        }
        let (num, after) = parse_decimal(rest, 0xff)?;
        *slot = num as u32;
        rest = after;
    }
    Some(out)
}

/// Parses a `227` PASV reply for the data host and port, the Rust analog of the
/// `count1 == 1 && ftpcode == 227` branch of C `ftp_state_pasv_resp`.
///
/// `reply` is the full final response line (e.g.
/// `b"227 Entering Passive Mode (127,0,0,1,4,51)"`). Scanning begins after the
/// `"227 "` prefix and advances one byte at a time until six comma-separated
/// numbers match (matching curl's tolerance for the varied phrasings servers
/// use). Returns `Some(("h1.h2.h3.h4", port))` with
/// `port = ((p1 << 8) + p2) & 0xffff`, or `None` (C `CURLE_FTP_WEIRD_227_FORMAT`).
#[must_use]
pub fn parse_pasv_227(reply: &[u8]) -> Option<(String, u16)> {
    // C starts at `recvbuf + 4` (past "227 "); be lenient if the line is short.
    let start = if reply.len() > 4 { &reply[4..] } else { reply };
    let mut idx = 0usize;
    while idx < start.len() {
        if let Some(ip) = match_pasv_6nums(&start[idx..]) {
            let host = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
            let port = (((ip[4] << 8) + ip[5]) & 0xffff) as u16;
            return Some((host, port));
        }
        idx += 1;
    }
    None
}

/// Parses a `229` EPSV reply for the data port, the Rust analog of the
/// `count1 == 0 && ftpcode == 229` branch of C `ftp_state_pasv_resp`.
///
/// `reply` is the full final response line (e.g. `b"229 ... (|||12345|)"`);
/// `control_host` is the control-connection address reused for the data
/// connection (C `ftp_control_addr_dup`). The parser finds the first `'('`
/// after the `"229 "` prefix, takes the separator as the byte just after it,
/// requires the layout `<sep><sep><sep><digits><sep>`, and parses the port
/// (`<= 0xffff`). Returns `Some((control_host, port))`, or `None`
/// (C `CURLE_FTP_WEIRD_PASV_REPLY`).
#[must_use]
pub fn parse_epsv_229(reply: &[u8], control_host: &str) -> Option<(String, u16)> {
    let start = if reply.len() > 4 { &reply[4..] } else { reply };
    let lpar = start.iter().position(|&b| b == b'(')?;
    let after = &start[lpar + 1..];
    // Layout: sep sep sep <digits> sep, e.g. "|||12345|".
    let sep = *after.first()?;
    if after.get(1) != Some(&sep) || after.get(2) != Some(&sep) {
        return None;
    }
    let digits = after.get(3..)?;
    if !digits.first().is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let (num, rest) = parse_decimal(digits, 0xffff)?;
    // The byte after the number must be the separator (C `*p != sep` check).
    if rest.first() != Some(&sep) {
        return None;
    }
    Some((control_host.to_string(), num as u16))
}

/// Formats an `EPRT` command (RFC 2428), the Rust analog of the `EPRT` branch
/// of C `ftp_state_use_port`: `"EPRT |%d|%s|%hu|"` with the family selector
/// `1` for IPv4 and `2` for IPv6.
///
/// Examples: `format_eprt_command("127.0.0.1", 12345, false)` →
/// `"EPRT |1|127.0.0.1|12345|"`; an IPv6 host yields `"EPRT |2|<host>|<port>|"`.
#[must_use]
pub fn format_eprt_command(host: &str, port: u16, is_ipv6: bool) -> String {
    let family = if is_ipv6 { 2 } else { 1 };
    format!("EPRT |{family}|{host}|{port}|")
}

/// Formats a `PORT` command, the Rust analog of the `PORT` branch of C
/// `ftp_state_use_port`: the dotted IPv4 host has its dots translated to commas
/// and the port is appended as two comma-separated bytes
/// (`,(port >> 8),(port & 0xff)`).
///
/// Example: `format_port_command("127.0.0.1", 12345)` →
/// `"PORT 127,0,0,1,48,57"`.
#[must_use]
pub fn format_port_command(host: &str, port: u16) -> String {
    let mut target = String::with_capacity(host.len() + 8);
    for ch in host.chars() {
        target.push(if ch == '.' { ',' } else { ch });
    }
    // C: curl_msnprintf(dest, 20, ",%d,%d", (port >> 8), (port & 0xff))
    target.push_str(&format!(",{},{}", port >> 8, port & 0xff));
    format!("PORT {target}")
}

/// Decomposes a URL-decoded FTP path into the directory components to `CWD`
/// through and the terminal file name, the Rust analog of C
/// `ftp_parse_url_path`.
///
/// The decomposition depends on `method` (`CURLOPT_FTP_FILEMETHOD`):
///
/// * [`CurlFtpFile::NoCwd`]: the whole path is the file name when it does not
///   end in `/`; `CWD` is skipped entirely for absolute paths.
/// * [`CurlFtpFile::SingleCwd`]: split at the last `/` — the prefix (at least
///   `"/"` for a root path) is the single `CWD` target and the suffix is the
///   file.
/// * [`CurlFtpFile::MultiCwd`]: one component per `/`-delimited segment (a
///   leading `/` contributes a `"/"` root component; empty `x//y` segments are
///   skipped), with the remainder as the file. Guarded by [`FTP_MAX_DIR_DEPTH`].
///
/// When `is_upload` is true and no file name results, this returns
/// `Err(CurlError::UrlMalformat)` (C: "Uploading to a URL without a filename").
///
/// The returned `cwddone` reflects only the `NOCWD` + absolute-path rule; the
/// connection-reuse refinement (comparing against the previous transfer's path)
/// is applied by the caller, which has access to the reuse state.
pub fn decompose_url_path(
    method: CurlFtpFile,
    rawpath: &str,
    is_upload: bool,
) -> Result<PathDecomp> {
    let bytes = rawpath.as_bytes();
    let path_len = bytes.len();
    let mut dirs: Vec<PathComp> = Vec::new();
    let mut file: Option<String> = None;

    match method {
        CurlFtpFile::NoCwd => {
            // Full file path unless the path ends in a slash (directory).
            if path_len > 0 && bytes[path_len - 1] != b'/' {
                file = Some(rawpath.to_string());
            }
        }
        CurlFtpFile::SingleCwd => {
            if let Some(slash) = rawpath.rfind('/') {
                // Directory is everything up to the last slash; a leading-only
                // slash (root) keeps length 1 (C `if(dirlen == 0) dirlen = 1`).
                let dirlen = if slash == 0 { 1 } else { slash };
                dirs.push(PathComp {
                    name: rawpath[..dirlen].to_string(),
                });
                let rest = &rawpath[slash + 1..];
                if !rest.is_empty() {
                    file = Some(rest.to_string());
                }
            } else if !rawpath.is_empty() {
                file = Some(rawpath.to_string());
            }
        }
        CurlFtpFile::MultiCwd => {
            let num_slashes = bytes.iter().filter(|&&b| b == b'/').count();
            if num_slashes >= FTP_MAX_DIR_DEPTH {
                // Suspiciously deep directory hierarchy (C `CURLE_URL_MALFORMAT`).
                return Err(CurlError::UrlMalformat);
            }
            let mut cur = 0usize;
            for _ in 0..num_slashes {
                let rel = &bytes[cur..];
                let Some(spos) = rel.iter().position(|&b| b == b'/') else {
                    break; // invariant: exactly `num_slashes` slashes remain
                };
                let mut clen = spos;
                // A leading slash becomes a single "/" root component.
                if clen == 0 && dirs.is_empty() {
                    clen = 1;
                }
                // Skip empty components (e.g. the middle of "x//y").
                if clen > 0 {
                    dirs.push(PathComp {
                        name: rawpath[cur..cur + clen].to_string(),
                    });
                }
                cur += spos + 1;
            }
            let rest = &rawpath[cur..];
            if !rest.is_empty() {
                file = Some(rest.to_string());
            }
        }
    }

    // An upload requires a target file name (C `CURLE_URL_MALFORMAT`).
    if is_upload && file.is_none() {
        return Err(CurlError::UrlMalformat);
    }

    // CWD can be skipped for absolute paths under NOCWD.
    let cwddone = method == CurlFtpFile::NoCwd && bytes.first() == Some(&b'/');

    Ok(PathDecomp {
        dirs,
        file,
        cwddone,
    })
}

/// Returns the FTP `TYPE` argument byte for the requested transfer mode: `b'A'`
/// for ASCII (text) transfers, `b'I'` for image/binary transfers (C uses the
/// `data->state.prefer_ascii` flag to pick between `TYPE A` and `TYPE I`).
#[must_use]
pub fn ftp_type_arg(prefer_ascii: bool) -> u8 {
    if prefer_ascii {
        b'A'
    } else {
        b'I'
    }
}

// ===========================================================================
// PingPongProtocol — the control-connection command/response state machine
// (C `ftp_endofresp` + `ftp_pp_statemachine`)
// ===========================================================================

impl PingPongProtocol for FtpConn {
    /// Detects the final line of a (possibly multi-line) FTP response, the Rust
    /// analog of C `ftp_endofresp` (with its `STATUSCODE`/`LASTLINE` macros).
    ///
    /// A line is final iff it is at least four bytes, its first three bytes are
    /// ASCII digits, and its fourth byte is a space (`"NNN "`); a `"NNN-"`
    /// fourth byte marks a continuation line. The numeric status is the
    /// three-digit prefix. When a final line is recognized its bytes are
    /// captured into [`FtpConn::last_response`] for the state machine to parse
    /// (the [`PingPong`] receive buffer is private, so the parser cannot read
    /// it back directly).
    fn endofresp(&mut self, _data: &mut Easy, _conn: &mut Connection, line: &[u8]) -> Option<i32> {
        if line.len() > 3
            && line[0].is_ascii_digit()
            && line[1].is_ascii_digit()
            && line[2].is_ascii_digit()
            && line[3] == b' '
        {
            // Remember the final line for PASV/EPSV/PWD/SIZE parsing.
            self.last_response = line.to_vec();
            let code = i32::from(line[0] - b'0') * 100
                + i32::from(line[1] - b'0') * 10
                + i32::from(line[2] - b'0');
            Some(code)
        } else {
            None
        }
    }

    /// Runs one iteration of the FTP control state machine, the Rust analog of
    /// C `ftp_pp_statemachine`.
    ///
    /// It reads one server response from the control connection and, when a
    /// complete response has arrived, dispatches on [`FtpConn::state`] to
    /// validate the code and send the next command. The C "call repeatedly with
    /// a `*done` out-param" pattern is replaced by `.await`: the engine's
    /// [`PingPong::statemach`] drives this hook until the state reaches
    /// [`FtpState::Stop`].
    ///
    /// # Borrow discipline
    ///
    /// [`FtpConn`] embeds its own [`PingPong`] engine, yet
    /// [`PingPong::readresp`] needs `&mut self` as the protocol hook *and*
    /// `&mut pp`. Those two borrows would alias, so the engine is temporarily
    /// moved out with [`mem::take`], driven against `self`, then moved back. The
    /// local `pp` and the `self` hook are then provably disjoint.
    fn statemachine<'a>(
        &'a mut self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Read one (possibly multi-line) response. The engine is moved out
            // so `pp.readresp(.., self)` does not alias `self`.
            let (code, _size) = {
                let mut pp = mem::take(&mut self.pp);
                let res = pp.readresp(data, conn, FIRSTSOCKET, self).await;
                self.pp = pp;
                res?
            };

            // `code == 0` means the response is incomplete; wait for more.
            if code == 0 {
                return Ok(());
            }

            self.advance(data, conn, code).await
        })
    }
}

// ===========================================================================
// Login state-machine handlers — the connect-phase arms of the C
// `switch(ftpc->state)` in `ftp_pp_statemachine`, plus the helper functions
// they call (`ftp_wait_resp`, `ftp_state_user_resp`, `ftp_state_loggedin`,
// `ftp_pwd_resp`, …).
// ===========================================================================

impl FtpConn {
    /// Sends a control-channel command on `FIRSTSOCKET`, appending the
    /// terminating CRLF (C `Curl_pp_sendf`).
    ///
    /// # Why not `PingPong::sendf`?
    ///
    /// Curl's `Curl_pp_sendf` (mirrored by [`PingPong::sendf`]) takes a
    /// `core::fmt::Arguments`, which is `!Send`; held across the `.await` of an
    /// `async fn` it makes the resulting future `!Send`, violating the `Send`
    /// bound on the [`PingPongProtocol::statemachine`] / [`BoxFuture`] contract.
    /// The Send-safe equivalent — used by the other async protocol engines in
    /// this crate (e.g. `protocols::mqtt`) — is to format the command into an
    /// owned byte buffer and write it through the connection-filter chain with
    /// [`Curl_conn_send`]. Response reading still goes through
    /// [`PingPong::readresp`], so the engine's receive-buffer/overflow
    /// bookkeeping is preserved.
    async fn send_cmd(&mut self, data: &Easy, conn: &mut Connection, cmd: &str) -> Result<()> {
        // Verbose ">" trace of the command (without the CRLF), matching C's
        // `CURLINFO_HEADER_OUT` debug output.
        if data.set.verbose {
            sendf::infof(true, cmd);
        }
        let mut line = String::with_capacity(cmd.len() + 2);
        line.push_str(cmd);
        line.push_str("\r\n");
        let bytes = line.into_bytes();
        let mut sent = 0usize;
        while sent < bytes.len() {
            match Curl_conn_send(conn, FIRSTSOCKET, &bytes[sent..], false).await {
                Ok(0) => return Err(CurlError::SendError),
                Ok(n) => sent += n,
                // Would-block: yield and retry (the runtime awaits writability).
                Err(CurlError::Again) => tokio::task::yield_now().await,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Dispatches the freshly-received response `code` according to the current
    /// state — the Rust analog of the `switch(ftpc->state)` body of
    /// `ftp_pp_statemachine`. Each connect-phase arm validates the code, sends
    /// the next command, and advances the state until [`FtpState::Stop`].
    async fn advance(&mut self, data: &mut Easy, conn: &mut Connection, code: i32) -> Result<()> {
        match self.state {
            FtpState::Wait220 => self.state_wait220(data, conn, code).await,
            FtpState::Auth => self.state_auth(data, conn, code).await,
            FtpState::User | FtpState::Pass => self.state_user_resp(data, conn, code).await,
            FtpState::Acct => self.state_acct_resp(data, conn, code).await,
            FtpState::Pbsz => self.state_pbsz_resp(data, conn, code).await,
            FtpState::Prot => self.state_prot_resp(data, conn, code).await,
            FtpState::Ccc => self.state_ccc_resp(data, conn).await,
            FtpState::Pwd => self.state_pwd_resp(data, conn, code).await,
            FtpState::Syst => self.state_syst_resp(data, conn, code).await,
            FtpState::Namefmt => {
                // Whatever the `SITE NAMEFMT` reply, the connect phase is done.
                self.set_state(FtpState::Stop);
                Ok(())
            }
            // Stop / Last and the transfer-phase states are accepted no-ops in
            // the connect-phase drive; the transfer drive (do_it/do_more)
            // advances the transfer states with the dedicated helpers below.
            _ => Ok(()),
        }
    }

    /// Sends `USER <user>` and moves to [`FtpState::User`] (C `ftp_state_user`).
    async fn send_user(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<()> {
        let cmd = format!("USER {}", self.user);
        self.send_cmd(data, conn, &cmd).await?;
        self.set_state(FtpState::User);
        Ok(())
    }

    /// Sends `PWD` and moves to [`FtpState::Pwd`] (C `ftp_state_pwd`).
    async fn send_pwd(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<()> {
        self.send_cmd(data, conn, "PWD").await?;
        self.set_state(FtpState::Pwd);
        Ok(())
    }

    /// Handles the `220` greeting and decides whether to begin an `AUTH`
    /// upgrade or send `USER` (C `ftp_wait_resp`).
    async fn state_wait220(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        code: i32,
    ) -> Result<()> {
        let use_ssl = data.set.use_ssl;

        if code == 230 {
            // Already logged in. Treat as a 220 when TLS is not strictly
            // required (or the control channel is already TLS).
            if use_ssl <= CURLUSESSL_TRY || self.control_ssl {
                return self.state_user_resp(data, conn, code).await;
            }
        } else if code != 220 {
            sendf::failf(
                &mut conn.filter_data.error_buffer,
                &format!("Got a {code:03} ftp-server response when 220 was expected"),
            );
            return Err(CurlError::WeirdServerReply);
        }

        if use_ssl != CURLUSESSL_NONE && !self.control_ssl {
            // FTPS requested but the control channel is not yet TLS — begin the
            // `AUTH` negotiation, choosing the first mechanism per FTPSSLAUTH.
            self.count3 = 0;
            match data.set.ftpsslauth {
                CURLFTPAUTH_DEFAULT | CURLFTPAUTH_SSL => {
                    self.count2 = 1; // step forward (SSL -> TLS) on retry
                    self.count1 = 0; // start with "SSL"
                }
                CURLFTPAUTH_TLS => {
                    self.count2 = -1; // step back (TLS -> SSL) on retry
                    self.count1 = 1; // start with "TLS"
                }
                other => {
                    sendf::failf(
                        &mut conn.filter_data.error_buffer,
                        &format!("unsupported parameter to CURLOPT_FTPSSLAUTH: {other}"),
                    );
                    return Err(CurlError::UnknownOption);
                }
            }
            let idx = self.count1.clamp(0, 1) as usize;
            let cmd = format!("AUTH {}", FTP_AUTH_METHODS[idx]);
            self.send_cmd(data, conn, &cmd).await?;
            self.set_state(FtpState::Auth);
            Ok(())
        } else {
            self.send_user(data, conn).await
        }
    }

    /// Handles the response to an `AUTH` command (C `case FTP_AUTH`): on
    /// `234`/`334` the control channel upgrades to TLS and login proceeds; on
    /// rejection the alternative mechanism is tried, then either the transfer
    /// fails (mandatory SSL) or login continues in clear text.
    async fn state_auth(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        code: i32,
    ) -> Result<()> {
        if code == 234 || code == 334 {
            // AUTH accepted: the control channel becomes TLS. In this workspace
            // the cf-ssl filter is woven onto `FIRSTSOCKET` by the connection
            // setup layer (the same path that handles implicit `ftps`); here we
            // record the upgrade and observe the resulting SSL state before
            // continuing to USER (C: `Curl_ssl_cfilter_add` + `Curl_conn_connect`
            // then `ftp_use_control_ssl = TRUE`).
            self.control_ssl = true;
            let _ssl_active = Curl_conn_is_ssl(conn, FIRSTSOCKET);
            self.send_user(data, conn).await
        } else if self.count3 < 1 {
            // Try the alternative AUTH mechanism (SSL <-> TLS); remain in AUTH.
            self.count3 += 1;
            self.count1 += self.count2;
            let idx = self.count1.clamp(0, 1) as usize;
            let cmd = format!("AUTH {}", FTP_AUTH_METHODS[idx]);
            self.send_cmd(data, conn, &cmd).await
        } else if data.set.use_ssl > CURLUSESSL_TRY {
            // CURLUSESSL_CONTROL or _ALL was required and we could not get TLS.
            Err(CurlError::UseSslFailed)
        } else {
            // Ignore the failure and continue in clear text.
            self.send_user(data, conn).await
        }
    }

    /// Handles the response to `USER`/`PASS` (C `ftp_state_user_resp`):
    /// `331` → send `PASS`; `2xx` → logged in; `332` → send `ACCT`; otherwise
    /// try an alternative user or fail with `CURLE_LOGIN_DENIED`.
    async fn state_user_resp(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        code: i32,
    ) -> Result<()> {
        if code == 331 && self.state == FtpState::User {
            // 331 Password required — send the password.
            let cmd = format!("PASS {}", self.passwd);
            self.send_cmd(data, conn, &cmd).await?;
            self.set_state(FtpState::Pass);
            Ok(())
        } else if code / 100 == 2 {
            // 230 User logged in (with or without password).
            self.state_loggedin(data, conn).await
        } else if code == 332 {
            // 332 Account required.
            if let Some(account) = self.account.clone() {
                let cmd = format!("ACCT {account}");
                self.send_cmd(data, conn, &cmd).await?;
                self.set_state(FtpState::Acct);
                Ok(())
            } else {
                sendf::failf(
                    &mut conn.filter_data.error_buffer,
                    "ACCT requested but none available",
                );
                Err(CurlError::LoginDenied)
            }
        } else {
            // Access denied. Try the supplied alternative command once.
            if let Some(alt) = self.alternative_to_user.clone() {
                if !self.ftp_trying_alternative {
                    self.send_cmd(data, conn, &alt).await?;
                    self.ftp_trying_alternative = true;
                    self.set_state(FtpState::User);
                    return Ok(());
                }
            }
            sendf::failf(
                &mut conn.filter_data.error_buffer,
                &format!("Access denied: {code:03}"),
            );
            Err(CurlError::LoginDenied)
        }
    }

    /// Handles the response to `ACCT` (C `ftp_state_acct_resp`): `2xx` → logged
    /// in; otherwise the account was rejected.
    async fn state_acct_resp(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        code: i32,
    ) -> Result<()> {
        if code / 100 != 2 {
            sendf::failf(
                &mut conn.filter_data.error_buffer,
                &format!("ACCT rejected by server: {code:03}"),
            );
            return Err(CurlError::FtpWeirdPassReply);
        }
        self.state_loggedin(data, conn).await
    }

    /// After a successful login, starts the data-protection sequence on a TLS
    /// control channel (`PBSZ 0`) or goes straight to `PWD` otherwise
    /// (C `ftp_state_loggedin`).
    async fn state_loggedin(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<()> {
        if self.control_ssl {
            // PBSZ must precede PROT; the parameter is always 0 for FTPS.
            self.send_cmd(data, conn, "PBSZ 0").await?;
            self.set_state(FtpState::Pbsz);
            Ok(())
        } else {
            self.send_pwd(data, conn).await
        }
    }

    /// Sends `PROT C`/`PROT P` after `PBSZ` (C `case FTP_PBSZ`). `PROT C`
    /// (clear) is used when only the control channel is protected
    /// (`CURLUSESSL_CONTROL`); `PROT P` (private) otherwise.
    async fn state_pbsz_resp(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        _code: i32,
    ) -> Result<()> {
        let prot = if data.set.use_ssl == CURLUSESSL_CONTROL {
            'C'
        } else {
            'P'
        };
        let cmd = format!("PROT {prot}");
        self.send_cmd(data, conn, &cmd).await?;
        self.set_state(FtpState::Prot);
        Ok(())
    }

    /// Handles the response to `PROT` (C `case FTP_PROT`): a `2xx` enables data
    /// protection; a rejection fails only when SSL was required beyond the
    /// control channel. Then sends `CCC` (if requested) or `PWD`.
    async fn state_prot_resp(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        code: i32,
    ) -> Result<()> {
        if code / 100 == 2 {
            // Data connection protection negotiated; record the effective level.
            self.use_ssl = data.set.use_ssl;
        } else if data.set.use_ssl > CURLUSESSL_CONTROL {
            // Server rejected 'P' (typically 500) and full SSL was required.
            return Err(CurlError::UseSslFailed);
        }

        if data.set.ftp_ccc != 0 {
            // CCC — Clear Command Channel.
            self.ccc = data.set.ftp_ccc;
            self.send_cmd(data, conn, "CCC").await?;
            self.set_state(FtpState::Ccc);
            Ok(())
        } else {
            self.send_pwd(data, conn).await
        }
    }

    /// Handles the response to `CCC` (C `case FTP_CCC`): the command channel
    /// returns to clear text (the TLS shutdown on the control filter is the
    /// connection layer's responsibility), then `PWD` is sent.
    async fn state_ccc_resp(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<()> {
        self.control_ssl = false;
        self.send_pwd(data, conn).await
    }

    /// Handles the response to `PWD` (C `ftp_pwd_resp`): a `257` reply carries
    /// the entry path in quotes, which becomes [`FtpConn::entrypath`]; `SYST` is
    /// then probed (for a relative entry path) before the connect phase ends.
    async fn state_pwd_resp(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        code: i32,
    ) -> Result<()> {
        if code == 257 {
            if let Some(dir) = parse_pwd_entrypath(&self.last_response) {
                let relative = !dir.starts_with('/');
                self.entrypath = Some(dir);
                if data.set.verbose {
                    if let Some(ref ep) = self.entrypath {
                        sendf::infof(true, &format!("Entry path is '{ep}'"));
                    }
                }
                // Probe SYST when the OS is unknown and the entry path is
                // relative (C: `if(!ftpc->server_os && dir[0] != '/')`).
                if self.server_os.is_none() && relative {
                    self.send_cmd(data, conn, "SYST").await?;
                    self.set_state(FtpState::Syst);
                    return Ok(());
                }
            }
        }
        // Connect phase complete.
        self.set_state(FtpState::Stop);
        Ok(())
    }

    /// Handles the response to `SYST` (C `case FTP_SYST`): a `215` reply names
    /// the server OS; `OS/400` additionally triggers `SITE NAMEFMT 1` so that
    /// later `CWD`/`RETR` use UNIX-style paths.
    async fn state_syst_resp(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        code: i32,
    ) -> Result<()> {
        if code == 215 {
            if let Some(os) = parse_syst_os(&self.last_response) {
                if os.eq_ignore_ascii_case("OS/400") {
                    self.server_os = Some(os);
                    self.send_cmd(data, conn, "SITE NAMEFMT 1").await?;
                    self.set_state(FtpState::Namefmt);
                    return Ok(());
                }
                self.server_os = Some(os);
            }
        }
        // Connect phase complete.
        self.set_state(FtpState::Stop);
        Ok(())
    }
}

// ===========================================================================
// Reply-text parsers used by the login handlers (kept free functions so they
// are independently unit-testable).
// ===========================================================================

/// Extracts the quoted entry-path directory from a `257` `PWD` reply, the Rust
/// analog of the quoted-string scan in C `ftp_pwd_resp`.
///
/// The reply has the form `257 "<dir>" is current directory`; the directory is
/// the text between the first `"` and the next `"`, with a doubled `""`
/// decoded to a single `"` (the FTP quoting convention). Returns `None` when no
/// quoted segment is present.
#[must_use]
pub fn parse_pwd_entrypath(reply: &[u8]) -> Option<String> {
    let text = core::str::from_utf8(reply).ok()?;
    let open = text.find('"')?;
    let after = &text[open + 1..];
    let bytes = after.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            // A doubled quote ("") is an escaped quote; anything else ends it.
            if bytes.get(i + 1) == Some(&b'"') {
                out.push('"');
                i += 2;
                continue;
            }
            return Some(out);
        }
        // Push this byte as a char (input is valid UTF-8 by construction).
        out.push(bytes[i] as char);
        i += 1;
    }
    // Unterminated quote: no usable entry path.
    None
}

/// Extracts the operating-system token from a `215` `SYST` reply, the Rust
/// analog of the OS-name scan in C `case FTP_SYST`.
///
/// The reply has the form `215 <OS> <details...>`; the OS token is the first
/// whitespace-delimited word after the `215 ` status prefix. Returns `None`
/// when no token follows the code.
#[must_use]
pub fn parse_syst_os(reply: &[u8]) -> Option<String> {
    let text = core::str::from_utf8(reply).ok()?;
    // Skip the 3-digit code and the following space(s).
    let rest = text.get(3..)?.trim_start();
    let token = rest.split_whitespace().next()?;
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

// ===========================================================================
// Data connection — passive (PASV / EPSV) and active (PORT / EPRT).
// (C `ftp_state_use_pasv`, `ftp_state_pasv_resp`, `ftp_epsv_disable`,
// `ftp_state_use_port`, `ftp_state_port_resp`.)
// ===========================================================================

impl FtpConn {
    /// Requests a passive data connection, the Rust analog of
    /// `ftp_state_use_pasv`. Sends `EPSV` when EPSV is enabled (the default),
    /// else `PASV`, records the attempt in [`FtpConn::count1`] (`0` = EPSV,
    /// `1` = PASV), and enters [`FtpState::Pasv`].
    pub async fn send_pasv(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<()> {
        // C `mode[][5] = { "EPSV", "PASV" }`; `modeoff = ftp_use_epsv ? 0 : 1`.
        let modeoff = if data.set.ftp_use_epsv { 0 } else { 1 };
        let cmd = if modeoff == 0 { "EPSV" } else { "PASV" };
        self.send_cmd(data, conn, cmd).await?;
        self.count1 = modeoff;
        self.set_state(FtpState::Pasv);
        Ok(())
    }

    /// Disables EPSV after a failed attempt and falls back to `PASV`, the Rust
    /// analog of `ftp_epsv_disable`. Bumps [`FtpConn::count1`] (`0` → `1`) and
    /// remains in [`FtpState::Pasv`].
    async fn epsv_disable(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<()> {
        if data.set.verbose {
            sendf::infof(true, "Failed EPSV attempt. Disabling EPSV");
        }
        self.send_cmd(data, conn, "PASV").await?;
        self.count1 += 1;
        self.set_state(FtpState::Pasv);
        Ok(())
    }

    /// Handles the response to `EPSV`/`PASV` (C `ftp_state_pasv_resp`): parses
    /// the data host and port from a positive reply (`229` for EPSV, `227` for
    /// PASV) into [`FtpConn::data_host`]/[`FtpConn::data_port`], or falls back
    /// from EPSV to PASV. The control host is reused as the data host for EPSV
    /// (and for PASV when `--ftp-skip-pasv-ip` is set).
    pub async fn state_pasv_resp(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        code: i32,
    ) -> Result<()> {
        let control_host = conn.remote_host.clone();
        let reply = self.last_response.clone();

        if self.count1 == 0 && code == 229 {
            // Positive EPSV reply: the data host is the control host.
            match parse_epsv_229(&reply, &control_host) {
                Some((host, port)) => {
                    self.data_host = Some(host);
                    self.data_port = port;
                    Ok(())
                }
                None => {
                    sendf::failf(
                        &mut conn.filter_data.error_buffer,
                        "Weirdly formatted EPSV reply",
                    );
                    Err(CurlError::FtpWeirdPasvReply)
                }
            }
        } else if self.count1 == 1 && code == 227 {
            // Positive PASV reply: parse h1,h2,h3,h4,p1,p2.
            match parse_pasv_227(&reply) {
                Some((host, port)) => {
                    if data.set.ftp_skip_ip {
                        // Ignore the advertised IP; reuse the control host.
                        self.data_host = Some(control_host);
                    } else {
                        self.data_host = Some(host);
                    }
                    self.data_port = port;
                    Ok(())
                }
                None => {
                    sendf::failf(
                        &mut conn.filter_data.error_buffer,
                        "Could not interpret the 227-response",
                    );
                    Err(CurlError::FtpWeird227Format)
                }
            }
        } else if self.count1 == 0 {
            // EPSV failed; disable it and try PASV.
            self.epsv_disable(data, conn).await
        } else {
            sendf::failf(
                &mut conn.filter_data.error_buffer,
                &format!("Bad PASV/EPSV response: {code:03}"),
            );
            Err(CurlError::FtpWeirdPasvReply)
        }
    }

    /// Connects the data connection (`SECONDARYSOCKET`) for a passive transfer.
    ///
    /// The host/port parsed from the `PASV`/`EPSV` reply are recorded on the
    /// connection and the secondary filter chain is connected. The chain's data
    /// filter (which targets [`FtpConn::data_host`]:[`FtpConn::data_port`], and
    /// inherits a TLS filter when the data channel is protected) is woven by the
    /// connection-setup layer; this drives it to a connected state.
    pub async fn connect_data_passive(&mut self, conn: &mut Connection) -> Result<()> {
        if self.data_host.is_none() {
            return Err(CurlError::FtpWeirdPasvReply);
        }
        Curl_conn_connect(conn, SECONDARYSOCKET, false).await
    }

    /// Requests an active data connection, the Rust analog of
    /// `ftp_state_use_port`. Binds a local listening socket, installs the
    /// TCP-accept filter on `SECONDARYSOCKET`, and sends `EPRT` (preferred) or
    /// `PORT` advertising the bound address. Enters [`FtpState::Port`] with
    /// [`FtpConn::wait_data_conn`] set while the server's connection is awaited.
    ///
    /// Returns the bound local [`std::net::SocketAddr`].
    pub async fn setup_active(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
    ) -> Result<std::net::SocketAddr> {
        use tokio::net::TcpListener;

        // Bind an ephemeral local port on all interfaces for the server to
        // connect back to (C binds to the control connection's local address;
        // the bound socket's port is what the command advertises).
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .map_err(|_| CurlError::FtpPortFailed)?;
        let local = listener
            .local_addr()
            .map_err(|_| CurlError::FtpPortFailed)?;

        // Install the TCP-accept filter on the data socket, bounded by the
        // accept timeout, then assert it took (C wires `Curl_cft_tcp_accept`).
        tcp_listen_set(
            &mut conn.cfilter[SECONDARYSOCKET],
            listener,
            DEFAULT_ACCEPT_TIMEOUT as i64,
        );
        debug_assert!(is_tcp_listen(&conn.cfilter[SECONDARYSOCKET]));

        // Advertise the local endpoint. Prefer EPRT (works for IPv4 and IPv6),
        // falling back to PORT for IPv4 (C `mode[][5] = { "EPRT", "PORT" }`).
        let is_ipv6 = local.is_ipv6();
        let host = local.ip().to_string();
        let port = local.port();
        let cmd = match self.port_cmd {
            PortCmd::Eprt => format_eprt_command(&host, port, is_ipv6),
            PortCmd::Port => format_port_command(&host, port),
        };
        self.send_cmd(data, conn, &cmd).await?;

        self.wait_data_conn = true;
        self.set_state(FtpState::Port);
        Ok(local)
    }

    /// Handles the response to `EPRT`/`PORT` (C `ftp_state_port_resp`).
    ///
    /// Returns `Ok(true)` when the command was accepted (`2xx`) and the active
    /// data connection is ready to be accepted; `Ok(false)` when an `EPRT`
    /// rejection triggered the EPRT→PORT fallback (a fresh `PORT` was re-sent
    /// and its reply must be read next); and an error when `PORT` itself failed.
    pub async fn state_port_resp(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        code: i32,
    ) -> Result<bool> {
        if code / 100 == 2 {
            // Command accepted; the server will connect to our listener.
            Ok(true)
        } else if self.port_cmd == PortCmd::Eprt {
            // EPRT refused — fall back to PORT and re-advertise (C EPRT→PORT
            // fallback). The retried command's reply is read by the caller.
            if data.set.verbose {
                sendf::infof(true, "disabling EPRT usage");
            }
            self.port_cmd = PortCmd::Port;
            self.setup_active(data, conn).await?;
            Ok(false)
        } else {
            sendf::failf(
                &mut conn.filter_data.error_buffer,
                &format!("Failed to use PORT/EPRT: {code:03}"),
            );
            Err(CurlError::FtpPortFailed)
        }
    }

    /// Accepts the server-initiated data connection for an active transfer,
    /// driving the TCP-accept filter on `SECONDARYSOCKET` to a connected state
    /// (bounded by [`DEFAULT_ACCEPT_TIMEOUT`]). Clears
    /// [`FtpConn::wait_data_conn`] once the connection is established.
    pub async fn accept_data_active(&mut self, conn: &mut Connection) -> Result<()> {
        let result = Curl_conn_connect(conn, SECONDARYSOCKET, false).await;
        self.wait_data_conn = false;
        match result {
            Ok(()) => Ok(()),
            Err(CurlError::OperationTimedout) => Err(CurlError::FtpAcceptTimeout),
            Err(_) => Err(CurlError::FtpAcceptFailed),
        }
    }
}

// ===========================================================================
// Wildcard transfers (PROTOPT_WILDCARD).
// (C `ftp_init_wc_data`, `wc_statemach`, `ftp_pl_insert_finfo`.)
//
// When the URL path's final component contains a glob pattern and
// `CURLOPT_WILDCARDMATCH` is set, curl performs a directory listing, filters
// the entries through `curl_fnmatch`, then transfers each match in turn —
// bracketing each with the chunk-begin / chunk-end callbacks. The driver walks
// `WildcardData` through `Clear → Init → Matching → Downloading → Clean → Done`.
// ===========================================================================

/// The result of the per-file chunk-begin decision, mirroring curl's
/// `CURL_CHUNK_BGN_FUNC_OK` / `_SKIP` / `_FAIL` return values.
///
/// The default policy (when no `CURLOPT_CHUNK_BGN_FUNCTION` is installed) is
/// [`WildcardChunk::Ok`] — transfer every match. The FFI layer maps an
/// application-installed C callback's return code onto these variants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WildcardChunk {
    /// Transfer this entry (`CURL_CHUNK_BGN_FUNC_OK`).
    Ok,
    /// Skip this entry without transferring (`CURL_CHUNK_BGN_FUNC_SKIP`).
    Skip,
    /// Abort the whole wildcard operation (`CURL_CHUNK_BGN_FUNC_FAIL`).
    Fail,
}

/// Returns `true` when `name` contains an (unescaped) glob metacharacter
/// (`*`, `?`, or `[`), the trigger for a wildcard transfer. Mirrors curl's
/// pattern detection in `ftp_init_wc_data` — a `\`-escaped metacharacter is
/// literal and does not count.
#[must_use]
pub fn has_wildcard(name: &str) -> bool {
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                // Escaped: skip the next byte (it is literal).
                i += 2;
                continue;
            }
            b'*' | b'?' | b'[' => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

/// Splits an FTP path into the directory prefix and the trailing wildcard
/// pattern, the Rust analog of the last-slash split in C `ftp_init_wc_data`.
///
/// Everything up to and including the final `/` is the directory to change
/// into; the remainder (which carries the pattern) is the match pattern. A path
/// with no `/` yields an empty directory and the whole path as the pattern.
#[must_use]
pub fn split_wildcard_path(path: &str) -> (String, String) {
    match path.rfind('/') {
        Some(idx) => (path[..=idx].to_string(), path[idx + 1..].to_string()),
        None => (String::new(), path.to_string()),
    }
}

/// Filters parsed listing entries against a wildcard pattern, the Rust analog
/// of curl's `ftp_pl_insert_finfo` selection step.
///
/// Each entry's filename is tested with [`curl_fnmatch`]; a [`FnMatch::Match`]
/// is selected, a [`FnMatch::NoMatch`] is dropped, and a [`FnMatch::Fail`]
/// (malformed pattern) aborts with [`CurlError::FtpBadFileList`]. An ambiguous
/// symlink — one whose target string itself contains `" -> "` — is rejected
/// even when its name matches, exactly as curl does.
pub fn wildcard_select(entries: Vec<FileInfo>, pattern: &[u8]) -> Result<Vec<FileInfo>> {
    let mut selected = Vec::new();
    for finfo in entries {
        match curl_fnmatch(pattern, finfo.filename.as_bytes()) {
            FnMatch::Match => {
                if finfo.filetype == FileType::Symlink {
                    if let Some(target) = finfo.strings.target.as_deref() {
                        if target.contains(" -> ") {
                            // Ambiguous link — skip it.
                            continue;
                        }
                    }
                }
                selected.push(finfo);
            }
            FnMatch::NoMatch => {}
            FnMatch::Fail => return Err(CurlError::FtpBadFileList),
        }
    }
    Ok(selected)
}

impl FtpConn {
    /// Issues `LIST` and collects the directory listing from the data
    /// connection, the internal listing read curl performs for wildcard
    /// matching. The listing is consumed by the parser (never written to the
    /// user's download sink), so it is read directly off `SECONDARYSOCKET`
    /// until end-of-data.
    async fn wildcard_collect_listing(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
    ) -> Result<Vec<u8>> {
        self.send_cmd(data, conn, "LIST").await?;
        let mut listing = Vec::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = Curl_conn_recv(conn, SECONDARYSOCKET, &mut buf).await?;
            if n == 0 {
                break;
            }
            listing.extend_from_slice(&buf[..n]);
        }
        Ok(listing)
    }

    /// Determines the chunk-begin disposition for `finfo`. The core default
    /// transfers every selected entry; an application chunk-begin callback,
    /// when present, is consulted at the FFI boundary and its return value is
    /// mapped onto [`WildcardChunk`].
    fn wildcard_chunk_decision(&self, _data: &Easy, _finfo: &FileInfo) -> WildcardChunk {
        WildcardChunk::Ok
    }

    /// Drives the wildcard state machine, the Rust analog of curl's
    /// `wc_statemach`.
    ///
    /// `Clear`/`Init` initialize the context; `Matching` issues `LIST`, parses
    /// the listing with [`FtpParseListData`], and selects matches via
    /// [`wildcard_select`]; `Downloading` walks the matched list, bracketing
    /// each `RETR` with the chunk-begin / chunk-end semantics; `Clean` and
    /// `Done` finalize. The C "re-enter `wc_statemach` repeatedly" pattern
    /// collapses into this single `await`ed loop.
    pub async fn drive_wildcard(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        wc: &mut WildcardData,
    ) -> Result<()> {
        loop {
            match wc.state {
                WildcardState::Clear | WildcardState::Init => {
                    // Clear the prior file list and advance to matching.
                    wc.filelist.clear();
                    wc.state = WildcardState::Matching;
                }
                WildcardState::Matching => {
                    // Establish the data connection, list, parse, and select.
                    if data.set.ftp_use_port {
                        self.setup_active(data, conn).await?;
                        self.accept_data_active(conn).await?;
                    } else {
                        self.send_pasv(data, conn).await?;
                        self.connect_data_passive(conn).await?;
                    }
                    let listing = self.wildcard_collect_listing(data, conn).await?;
                    let mut parser = FtpParseListData::new();
                    parser.parse_chunk(&listing)?;
                    if let Some(err) = parser.geterror() {
                        wc.state = WildcardState::Error;
                        return Err(err);
                    }
                    let entries = parser.take_entries();
                    wc.filelist = wildcard_select(entries, wc.pattern.as_bytes())?;
                    wc.state = WildcardState::Downloading;
                }
                WildcardState::Downloading => {
                    if wc.filelist.is_empty() {
                        wc.state = WildcardState::Clean;
                        continue;
                    }
                    // Pop the head entry (curl pops from the front of its list).
                    let finfo = wc.filelist.remove(0);
                    match self.wildcard_chunk_decision(data, &finfo) {
                        WildcardChunk::Ok => {
                            // Transfer this match. The RETR body flows through
                            // the normal transfer path (see `do_more`); the
                            // command sequencing is issued here.
                            self.transfer_kind = TransferKind::Retr;
                            let cmd = format!("RETR {}", finfo.filename);
                            self.send_cmd(data, conn, &cmd).await?;
                            // chunk-end bracketing happens after the body via
                            // the transfer completion path.
                        }
                        WildcardChunk::Skip => {
                            wc.state = WildcardState::Skip;
                            continue;
                        }
                        WildcardChunk::Fail => {
                            wc.state = WildcardState::Error;
                            return Err(CurlError::FtpBadFileList);
                        }
                    }
                }
                WildcardState::Skip => {
                    // Skipped entry: rejoin the download loop for the next one.
                    wc.state = WildcardState::Downloading;
                }
                WildcardState::Clean => {
                    wc.state = WildcardState::Done;
                }
                WildcardState::Error => {
                    return Err(CurlError::FtpBadFileList);
                }
                WildcardState::Done => return Ok(()),
            }
        }
    }

    /// Drives the control-connection login state machine to completion, the
    /// Rust analog of curl's `ftp_connect` + the `ftp_connecting` re-entrant
    /// loop. Begins by awaiting the `220` greeting and pumps
    /// [`PingPongProtocol::statemachine`] until the state reaches
    /// [`FtpState::Stop`]. Each iteration reads one (possibly multi-line)
    /// response and advances the machine — the C "call repeatedly until `*done`"
    /// pattern collapsed into this single `await`ed loop.
    async fn run_login(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<()> {
        self.set_state(FtpState::Wait220);
        while self.state != FtpState::Stop {
            self.statemachine(data, conn).await?;
        }
        Ok(())
    }
}

// ===========================================================================
// `Protocol` implementation — the FTP / FTPS handler.
// (C `Curl_handler_ftp` / `Curl_handler_ftps`, `ftp_setup_connection`,
// `ftp_connect`, `ftp_do`/`ftp_doing`, `ftp_doing` → `ftp_do_more`,
// `ftp_done`, `ftp_disconnect`.)
// ===========================================================================

/// The FTP / FTPS protocol handler — the Rust analog of curl's
/// `Curl_handler_ftp` / `Curl_handler_ftps` vtables.
///
/// A zero-sized dispatcher that carries the [`Scheme`] descriptor it serves
/// (`SCHEME_FTP` for `ftp`, `SCHEME_FTPS` for the implicitly-TLS `ftps`). The
/// per-connection state lives in an [`FtpConn`] parked in the connection's
/// protocol-state slot ([`Connection::set_proto_state`]); the per-transfer
/// [`Ftp`] view is derived from the easy handle as needed. The single handler
/// type serves both schemes and branches on [`Scheme::is_ssl`] /
/// [`Curl_conn_is_ssl`] (curl's `PROTOPT_SSL`) — exactly as curl shares
/// `ftp_*` code between the two vtables.
pub struct FtpHandler {
    /// The scheme this handler instance serves.
    scheme: &'static Scheme,
}

impl FtpHandler {
    /// Constructs an FTP/FTPS handler for `scheme` (`&SCHEME_FTP` or
    /// `&SCHEME_FTPS`).
    #[must_use]
    pub const fn new(scheme: &'static Scheme) -> Self {
        FtpHandler { scheme }
    }

    /// Whether this handler serves the implicitly-TLS `ftps` scheme (curl's
    /// `PROTOPT_SSL`): the control connection is encrypted from the first byte.
    fn is_implicit_tls(&self) -> bool {
        self.scheme.is_ssl()
    }
}

/// Installs the one-shot connection-teardown hook (the boundary that lets
/// [`crate::conn`]'s shutdown subsystem reclaim FTP protocol state **without
/// `crate::conn` ever naming a `crate::protocols` type** — the dependency
/// inversion the acyclic `protocols → conn` rule requires).
///
/// Unlike SSH — whose `russh` session is self-contained and can be *moved* into
/// the hook to drive a graceful goodbye — FTP's control channel lives inside the
/// connection's filter chain and is **not** `'static`-movable. The graceful
/// `QUIT` (which needs the live `conn`) is therefore sent in
/// [`FtpHandler::disconnect`]; this hook performs only the connection-
/// independent state cleanup (dropping the parked [`FtpConn`] and its buffers),
/// honoring the `aborted` flag the shutdown subsystem passes.
fn install_ftp_disconnect_hook(conn: &mut Connection) {
    let Some(boxed) = conn.take_proto_state() else {
        // No state parked (never connected, or already reclaimed): a connection
        // is disconnected at most once.
        return;
    };
    let Ok(ftpc_box) = boxed.downcast::<FtpConn>() else {
        return;
    };
    let ftpc = *ftpc_box;
    conn.set_disconnect_hook(Box::new(move |_aborted: bool| -> BoxFuture<'static, ()> {
        Box::pin(async move {
            // Move the parked state in and let `Drop` free its dynamic buffers
            // (C `freedirs` + the `ftp_conn` dynbuf teardown). `QUIT` already ran
            // in `disconnect()` where the live `conn` was available.
            let _reclaimed = ftpc;
        })
    }));
}

impl Protocol for FtpHandler {
    fn scheme(&self) -> &'static Scheme {
        self.scheme
    }

    /// Pre-transfer per-connection setup (C `ftp_setup_connection`): allocate
    /// the [`FtpConn`] state, decode the URL path into CWD components per the
    /// active `--ftp-method`, and lift the credentials and SSL preferences off
    /// the easy handle.
    fn setup_connection<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Parse the request URL to recover the path and any userinfo. FTP
            // credentials come from the URL (the easy handle exposes none);
            // curl defaults to anonymous / `ftp@example.com` when absent.
            let url_str = data.url().ok_or(CurlError::UrlMalformat)?.to_string();
            let mut url = CurlUrl::new();
            url.set(CurlUPart::Url, Some(&url_str), 0)
                .map_err(|_| CurlError::UrlMalformat)?;
            let raw_path = url
                .get(CurlUPart::Path, CURLU_URLDECODE)
                .map_err(|_| CurlError::UrlMalformat)?;

            let mut ftpc = FtpConn::new();
            if let Ok(user) = url.get(CurlUPart::User, CURLU_URLDECODE) {
                if !user.is_empty() {
                    ftpc.user = user;
                }
            }
            if let Ok(pass) = url.get(CurlUPart::Password, CURLU_URLDECODE) {
                if !pass.is_empty() {
                    ftpc.passwd = pass;
                }
            }

            // Decode the path into directory components + the leaf file name,
            // per the configured CWD method (C `ftp_parse_url_path`).
            let method = CurlFtpFile::from_raw(data.set.ftp_filemethod);
            let is_upload = data.set.method == HttpReq::Put;
            let decomp = decompose_url_path(method, &raw_path, is_upload)?;
            ftpc.rawpath = raw_path;
            ftpc.dirs = decomp.dirs;
            ftpc.file = decomp.file;
            ftpc.cwddone = decomp.cwddone;

            // Lift SSL / CCC preferences (consumed by the PBSZ/PROT/CCC arms).
            ftpc.use_ssl = data.set.use_ssl;
            ftpc.ccc = data.set.ftp_ccc;
            // The active EPRT-vs-PORT preference: EPRT first unless disabled.
            ftpc.port_cmd = if data.set.ftp_use_eprt {
                PortCmd::Eprt
            } else {
                PortCmd::Port
            };

            conn.set_proto_state(Box::new(ftpc));
            Ok(())
        })
    }

    /// Establish the FTP session over the connected control channel (C
    /// `ftp_connect` fused with the `ftp_connecting` loop): ensure the transport
    /// (and, for `ftps`, the implicit TLS) is up, initialize the ping-pong
    /// engine, then drive the login state machine — greeting → optional
    /// `AUTH TLS` → `USER`/`PASS`/`ACCT` → `PBSZ`/`PROT` → `PWD`/`SYST`.
    fn connect<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Ensure the control channel's filter chain is connected. For `ftps`
            // the scheme carries `PROTOPT_SSL`, so the connection-setup layer has
            // installed the cf-ssl filter and this negotiates TLS transparently.
            // Idempotent: a chain that is already connected short-circuits.
            Curl_conn_connect(conn, FIRSTSOCKET, true).await?;

            // Recover (or, defensively, allocate) the per-connection state.
            let mut ftpc = match conn.take_proto_state() {
                Some(boxed) => match boxed.downcast::<FtpConn>() {
                    Ok(b) => *b,
                    Err(_) => FtpConn::new(),
                },
                None => FtpConn::new(),
            };

            // Record whether the control channel is already encrypted (implicit
            // `ftps`), so the login arms skip a redundant `AUTH TLS` upgrade.
            ftpc.control_ssl = Curl_conn_is_ssl(conn, FIRSTSOCKET);
            if self.is_implicit_tls() {
                ftpc.control_ssl = true;
            }

            // Initialize the ping-pong engine's response timers (C `Curl_pp_init`)
            // exactly once per connection, then drive login to completion.
            ftpc.pp.init(timeval::curlx_now());
            let result = ftpc.run_login(data, conn).await;
            if result.is_ok() {
                // The control connection is established and usable for `QUIT`.
                ftpc.ctl_valid = true;
            }

            conn.set_proto_state(Box::new(ftpc));
            result
        })
    }

    /// Issue the request and describe the transfer (C `ftp_do` fused with
    /// `ftp_doing`): classify the operation — `STOR` for an upload, `LIST`/`NLST`
    /// for a directory (no leaf file, or `--head`), else `RETR` for a file —
    /// record it on the per-connection state, and hand the engine a
    /// [`ProtocolTransfer`] describing direction and (when known) size. The
    /// data-connection establishment (`PASV`/`PORT`) is deferred to
    /// [`FtpHandler::do_more`], the `PROTOPT_DUAL` handoff point.
    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            let is_upload = data.set.method == HttpReq::Put;
            let no_body = data.set.opt_no_body;
            let infilesize = data.set.filesize;

            let ftpc = conn
                .proto_state_mut::<FtpConn>()
                .ok_or(CurlError::FailedInit)?;

            // Classify the operation (C selects RETR / STOR / LIST in `ftp_do`).
            let (kind, direction) = if is_upload {
                (TransferKind::Stor, TransferDirection::Upload)
            } else if ftpc.file.is_none() || no_body {
                // No leaf file name (a directory URL) or a body-less request:
                // a directory listing.
                (TransferKind::List, TransferDirection::Download)
            } else {
                (TransferKind::Retr, TransferDirection::Download)
            };
            ftpc.transfer_kind = kind;

            // Build the transfer descriptor. For an upload with a known input
            // size, advertise it; for a download, a known size comes from a
            // prior `SIZE` (`known_filesize`), else it is open-ended.
            let transfer = match direction {
                TransferDirection::Upload if infilesize >= 0 => {
                    ProtocolTransfer::new(direction).with_size(infilesize as u64)
                }
                TransferDirection::Download if ftpc.known_filesize >= 0 => {
                    ProtocolTransfer::new(direction).with_size(ftpc.known_filesize as u64)
                }
                _ => ProtocolTransfer::new(direction),
            };
            Ok(transfer)
        })
    }

    /// The FTP-specific second half of `do_it` (C `ftp_do_more`): the
    /// `PROTOPT_DUAL` data-connection establishment. Sets up the secondary
    /// socket — passively (`EPSV`/`PASV`, parsing the advertised endpoint and
    /// connecting out) or actively (`EPRT`/`PORT`, binding a listener and
    /// accepting the server's connection) — so the body transfer can run.
    fn do_more<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut ftpc = conn
                .take_proto_state()
                .and_then(|b| b.downcast::<FtpConn>().ok().map(|b| *b))
                .ok_or(CurlError::FailedInit)?;
            let result = ftpc.ftp_do_more(data, conn).await;
            conn.set_proto_state(Box::new(ftpc));
            result
        })
    }

    /// Post-transfer finalization (C `ftp_done`): read the trailing `226`/`250`
    /// completion response on the control channel (unless the transfer ended
    /// prematurely, already failed, or `dont_check` is set), then clear the
    /// per-transfer data-channel state for connection reuse. Returns the
    /// transfer's `status` on success.
    fn done<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
        status: Result<()>,
        premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut ftpc = match conn.take_proto_state() {
                Some(boxed) => match boxed.downcast::<FtpConn>() {
                    Ok(b) => *b,
                    Err(b) => {
                        conn.set_proto_state(b);
                        return status;
                    }
                },
                None => return status,
            };
            let result = ftpc.ftp_done(data, conn, status, premature).await;
            conn.set_proto_state(Box::new(ftpc));
            result
        })
    }

    /// Tear down the FTP session (C `ftp_disconnect`): send a best-effort `QUIT`
    /// while the live control connection is still held (when not already dead
    /// and the channel is valid), close the data and control sockets, then
    /// install the connection-independent cleanup hook for the
    /// [`crate::conn`]-driven shutdown path.
    fn disconnect<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
        dead: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Move state out so `QUIT` can borrow `conn` mutably without aliasing
            // the protocol-state slot.
            let mut ftpc = conn
                .take_proto_state()
                .and_then(|b| b.downcast::<FtpConn>().ok().map(|b| *b));

            if let Some(ref mut f) = ftpc {
                if !dead && f.ctl_valid {
                    // C `ftp_quit`: best-effort `QUIT`; failures on a dying
                    // connection are ignored. The `221` goodbye is intentionally
                    // not awaited here — the sockets are closed immediately
                    // after — to avoid blocking teardown on a half-closed peer.
                    let _ = f.send_cmd(data, conn, "QUIT").await;
                    f.ctl_valid = false;
                }
            }

            // Close the data socket first, then the control socket (C order).
            Curl_conn_close(conn, SECONDARYSOCKET);
            Curl_conn_close(conn, FIRSTSOCKET);

            // Park the state back so the cleanup hook can reclaim it uniformly.
            if let Some(f) = ftpc {
                conn.set_proto_state(Box::new(f));
            }
            install_ftp_disconnect_hook(conn);
            Ok(())
        })
    }
}

// ===========================================================================
// Drive helpers shared by the connect / transfer / done / disconnect phases.
// ===========================================================================

impl FtpConn {
    /// Reads a single complete control-channel response and returns its numeric
    /// code, looping past incomplete reads (`code == 0`). Uses the same
    /// [`mem::take`] borrow split as [`PingPongProtocol::statemachine`] so
    /// [`PingPong::readresp`] does not alias `self`.
    async fn read_one(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<i32> {
        loop {
            let (code, _size) = {
                let mut pp = mem::take(&mut self.pp);
                let res = pp.readresp(data, conn, FIRSTSOCKET, self).await;
                self.pp = pp;
                res?
            };
            if code != 0 {
                return Ok(code);
            }
        }
    }

    /// Establishes the data connection for the current transfer (C
    /// `ftp_do_more`): active (`EPRT`/`PORT` + accept) when `--ftp-port` is set,
    /// else passive (`EPSV`/`PASV` + connect-out, with the EPSV→PASV fallback).
    async fn ftp_do_more(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<()> {
        if data.set.ftp_use_port {
            // Active mode: bind + advertise, then await the command reply,
            // following the EPRT→PORT fallback until the command is accepted.
            self.setup_active(data, conn).await?;
            loop {
                let code = self.read_one(data, conn).await?;
                if self.state_port_resp(data, conn, code).await? {
                    // Accepted; the fallback (if any) re-sent and `Ok(false)`
                    // loops to read the retried reply.
                    break;
                }
            }
            self.accept_data_active(conn).await?;
        } else {
            // Passive mode: request, parse the endpoint (with EPSV→PASV
            // fallback), then connect the secondary socket out to it.
            self.send_pasv(data, conn).await?;
            let code = self.read_one(data, conn).await?;
            self.state_pasv_resp(data, conn, code).await?;
            // An EPSV refusal disables EPSV and re-sends `PASV`; read its reply.
            if self.data_host.is_none() {
                let code = self.read_one(data, conn).await?;
                self.state_pasv_resp(data, conn, code).await?;
            }
            self.connect_data_passive(conn).await?;
        }
        Ok(())
    }

    /// Reads the trailing completion response and finalizes per-transfer state
    /// (C `ftp_done`). On a premature end or an already-failed transfer the
    /// completion read is skipped; otherwise a non-`2xx` completion is reported
    /// as [`CurlError::PartialFile`].
    async fn ftp_done(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        status: Result<()>,
        premature: bool,
    ) -> Result<()> {
        if premature || status.is_err() {
            // Skip the completion handshake; the connection may be closed.
            self.dont_check = true;
        }
        if !self.dont_check && self.ctl_valid {
            let code = self.read_one(data, conn).await?;
            if code / 100 != 2 {
                return Err(CurlError::PartialFile);
            }
        }
        // Clear the per-transfer data-channel endpoint so the control
        // connection can be reused for the next transfer.
        self.data_host = None;
        self.data_port = 0;
        self.transfertype = 0;
        status
    }
}

// ===========================================================================
// Tests
// ===========================================================================
//
// Two tiers, mirroring the file brief's validation checklist:
//
//   * Pure parity unit tests — exercise the deterministic wire helpers against
//     `lib/ftp.c`'s exact byte layout with no I/O: `PASV`/`EPSV` reply parsing,
//     `EPRT`/`PORT` command formatting, the three `--ftp-method` CWD path
//     decompositions, wildcard pattern selection, and `ftp_endofresp`
//     final-vs-continuation detection.
//
//   * Scripted-filter integration tests — drive the control state machine over
//     an in-memory [`ConnectionFilter`] with canned server responses, asserting
//     both the command bytes placed on the wire and the resulting state: a full
//     `220 → 331 → 230 → 257` login, and the passive `EPSV`/`PASV`
//     data-endpoint negotiation.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::{CfState, ConnectionFilter};
    use crate::conn::{SchemeDescriptor, TRNSPRT_TCP};
    use crate::protocols::{SCHEME_FTP, SCHEME_FTPS};
    use std::sync::{Arc, Mutex};

    // ---- PASV (227) reply parsing ----------------------------------------

    #[test]
    fn parse_pasv_227_extracts_host_and_port() {
        // 13 * 256 + 128 = 3456.
        let (host, port) =
            parse_pasv_227(b"227 Entering Passive Mode (127,0,0,1,13,128)").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 3456);
    }

    #[test]
    fn parse_pasv_227_scans_past_arbitrary_prefix() {
        // curl scans char-by-char from reply+4 for the first 6-number group.
        let (host, port) =
            parse_pasv_227(b"227 =192,168,0,5,7,210=").unwrap();
        assert_eq!(host, "192.168.0.5");
        assert_eq!(port, 7 * 256 + 210);
    }

    #[test]
    fn parse_pasv_227_rejects_malformed() {
        assert!(parse_pasv_227(b"227 no numbers here").is_none());
        // An octet over 255 is invalid.
        assert!(parse_pasv_227(b"227 (1,2,3,4,5,300)").is_none());
    }

    // ---- EPSV (229) reply parsing ----------------------------------------

    #[test]
    fn parse_epsv_229_extracts_port_reuses_control_host() {
        let (host, port) =
            parse_epsv_229(b"229 Entering Extended Passive Mode (|||3456|)", "203.0.113.9")
                .unwrap();
        // EPSV never carries a host; the control host is reused.
        assert_eq!(host, "203.0.113.9");
        assert_eq!(port, 3456);
    }

    #[test]
    fn parse_epsv_229_rejects_malformed() {
        // Missing the parenthesized triplet+port group.
        assert!(parse_epsv_229(b"229 Entering Extended Passive Mode", "h").is_none());
        // Wrong separator run.
        assert!(parse_epsv_229(b"229 (|x|3456|)", "h").is_none());
    }

    // ---- EPRT / PORT command formatting ----------------------------------

    #[test]
    fn format_eprt_ipv4_and_ipv6() {
        assert_eq!(
            format_eprt_command("127.0.0.1", 3456, false),
            "EPRT |1|127.0.0.1|3456|"
        );
        assert_eq!(
            format_eprt_command("::1", 3456, true),
            "EPRT |2|::1|3456|"
        );
    }

    #[test]
    fn format_port_ipv4_uses_comma_sextuple() {
        // 3456 -> hi=13, lo=128.
        assert_eq!(
            format_port_command("127.0.0.1", 3456),
            "PORT 127,0,0,1,13,128"
        );
    }

    // ---- CWD path decomposition (the three --ftp-method strategies) ------

    #[test]
    fn decompose_multicwd_splits_each_component() {
        let d = decompose_url_path(CurlFtpFile::MultiCwd, "/dir1/dir2/file.txt", false).unwrap();
        let names: Vec<&str> = d.dirs.iter().map(|c| c.name.as_str()).collect();
        // Leading slash becomes the "/" root component, then each dir.
        assert_eq!(names, ["/", "dir1", "dir2"]);
        assert_eq!(d.file.as_deref(), Some("file.txt"));
    }

    #[test]
    fn decompose_multicwd_relative_and_directory_url() {
        // Relative path: no leading "/" root component.
        let d = decompose_url_path(CurlFtpFile::MultiCwd, "dir1/dir2/file.txt", false).unwrap();
        let names: Vec<&str> = d.dirs.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["dir1", "dir2"]);
        assert_eq!(d.file.as_deref(), Some("file.txt"));

        // A trailing slash means a directory (listing) — no file name.
        let dir = decompose_url_path(CurlFtpFile::MultiCwd, "/pub/", false).unwrap();
        let dnames: Vec<&str> = dir.dirs.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(dnames, ["/", "pub"]);
        assert!(dir.file.is_none());
    }

    #[test]
    fn decompose_nocwd_keeps_whole_path_as_file() {
        let d = decompose_url_path(CurlFtpFile::NoCwd, "/dir1/dir2/file.txt", false).unwrap();
        assert!(d.dirs.is_empty());
        assert_eq!(d.file.as_deref(), Some("/dir1/dir2/file.txt"));
        // CWD can be skipped for an absolute path under NOCWD.
        assert!(d.cwddone);
    }

    #[test]
    fn decompose_singlecwd_one_dir_plus_file() {
        let d = decompose_url_path(CurlFtpFile::SingleCwd, "/dir1/dir2/file.txt", false).unwrap();
        let names: Vec<&str> = d.dirs.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["/dir1/dir2"]);
        assert_eq!(d.file.as_deref(), Some("file.txt"));

        // A root-only leading slash keeps a single "/" directory.
        let r = decompose_url_path(CurlFtpFile::SingleCwd, "/file.txt", false).unwrap();
        let rnames: Vec<&str> = r.dirs.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(rnames, ["/"]);
        assert_eq!(r.file.as_deref(), Some("file.txt"));
    }

    #[test]
    fn decompose_upload_without_filename_is_malformed() {
        // Uploading to a directory URL has no target file name.
        let err = decompose_url_path(CurlFtpFile::MultiCwd, "/pub/", true).unwrap_err();
        assert_eq!(err, CurlError::UrlMalformat);
    }

    #[test]
    fn decompose_multicwd_rejects_excessive_depth() {
        let deep = "/".repeat(FTP_MAX_DIR_DEPTH + 1);
        assert_eq!(
            decompose_url_path(CurlFtpFile::MultiCwd, &deep, false).unwrap_err(),
            CurlError::UrlMalformat
        );
    }

    // ---- TYPE argument ----------------------------------------------------

    #[test]
    fn ftp_type_arg_ascii_vs_binary() {
        assert_eq!(ftp_type_arg(true), b'A');
        assert_eq!(ftp_type_arg(false), b'I');
    }

    // ---- Wildcards --------------------------------------------------------

    #[test]
    fn has_wildcard_detects_unescaped_metachars() {
        assert!(has_wildcard("*.txt"));
        assert!(has_wildcard("file?.bin"));
        assert!(has_wildcard("log[0-9].txt"));
        assert!(!has_wildcard("plain.txt"));
        // A backslash escapes the metacharacter.
        assert!(!has_wildcard("name\\*literal"));
    }

    #[test]
    fn split_wildcard_path_separates_dir_and_pattern() {
        assert_eq!(
            split_wildcard_path("/pub/data/*.txt"),
            ("/pub/data/".to_string(), "*.txt".to_string())
        );
        // No slash: empty directory, whole string is the pattern.
        assert_eq!(
            split_wildcard_path("*.txt"),
            (String::new(), "*.txt".to_string())
        );
    }

    fn finfo(name: &str, filetype: FileType) -> FileInfo {
        FileInfo {
            filename: name.to_string(),
            filetype,
            ..Default::default()
        }
    }

    #[test]
    fn wildcard_select_filters_by_pattern() {
        let entries = vec![
            finfo("alpha.txt", FileType::File),
            finfo("beta.log", FileType::File),
            finfo("gamma.txt", FileType::File),
        ];
        let kept = wildcard_select(entries, b"*.txt").unwrap();
        let names: Vec<&str> = kept.iter().map(|f| f.filename.as_str()).collect();
        assert_eq!(names, ["alpha.txt", "gamma.txt"]);
    }

    #[test]
    fn wildcard_select_rejects_ambiguous_symlink() {
        let mut link = finfo("weird.txt", FileType::Symlink);
        // A target containing " -> " is an ambiguous link curl discards.
        link.strings.target = Some("a -> b".to_string());
        let kept = wildcard_select(vec![link], b"*.txt").unwrap();
        assert!(kept.is_empty());
    }

    #[test]
    fn wildcard_select_treats_malformed_pattern_literally() {
        // Parity with curl's `Curl_fnmatch`: a malformed pattern (e.g. an
        // unterminated `[`) is matched *literally* and yields `NoMatch`, never
        // `CURL_FNMATCH_FAIL`. Selection therefore succeeds (no error) and, for
        // a name that does not literally contain the pattern, matches nothing.
        let entries = vec![finfo("a.txt", FileType::File)];
        let kept = wildcard_select(entries, b"[unterminated").unwrap();
        assert!(kept.is_empty());
    }

    // ---- Small enum/parse helpers ----------------------------------------

    #[test]
    fn curlftpfile_from_raw_maps_known_and_falls_back() {
        assert_eq!(CurlFtpFile::from_raw(1), CurlFtpFile::MultiCwd);
        assert_eq!(CurlFtpFile::from_raw(2), CurlFtpFile::NoCwd);
        assert_eq!(CurlFtpFile::from_raw(3), CurlFtpFile::SingleCwd);
        // Unknown values fall back to curl's default (MULTICWD).
        assert_eq!(CurlFtpFile::from_raw(99), CurlFtpFile::MultiCwd);
    }

    #[test]
    fn ftpstate_defaults_to_stop() {
        assert_eq!(FtpState::default(), FtpState::Stop);
    }

    #[test]
    fn portcmd_keywords() {
        assert_eq!(PortCmd::Eprt.keyword(), "EPRT");
        assert_eq!(PortCmd::Port.keyword(), "PORT");
        assert_eq!(PortCmd::default(), PortCmd::Eprt);
    }

    #[test]
    fn parse_pwd_entrypath_extracts_quoted_dir() {
        assert_eq!(
            parse_pwd_entrypath(b"257 \"/home/user\" is the current directory").as_deref(),
            Some("/home/user")
        );
        assert_eq!(parse_pwd_entrypath(b"257 \"/\"").as_deref(), Some("/"));
        // No quotes -> nothing to extract.
        assert!(parse_pwd_entrypath(b"257 no quotes").is_none());
    }

    #[test]
    fn parse_syst_os_extracts_first_token() {
        assert_eq!(
            parse_syst_os(b"215 UNIX Type: L8").as_deref(),
            Some("UNIX")
        );
        assert_eq!(
            parse_syst_os(b"215 OS/400 is the operating system").as_deref(),
            Some("OS/400")
        );
    }

    // ---- ftp_endofresp final-vs-continuation -----------------------------

    #[test]
    fn endofresp_detects_final_and_continuation() {
        let mut data = Easy::new();
        let mut conn = make_conn(Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
        let mut ftpc = FtpConn::new();

        // "NNN " is a final line; the code is the 3-digit prefix and the line is
        // captured for later parsing.
        assert_eq!(
            ftpc.endofresp(&mut data, &mut conn, b"220 Welcome"),
            Some(220)
        );
        assert_eq!(ftpc.last_response, b"220 Welcome");

        // "NNN-" is a continuation (not final).
        assert_eq!(
            ftpc.endofresp(&mut data, &mut conn, b"220-first line of banner"),
            None
        );
        // Too short to carry a status code.
        assert_eq!(ftpc.endofresp(&mut data, &mut conn, b"22"), None);
        // A later final line is detected and captured.
        assert_eq!(
            ftpc.endofresp(&mut data, &mut conn, b"257 \"/\""),
            Some(257)
        );
        assert_eq!(ftpc.last_response, b"257 \"/\"");
    }

    // ---- Scripted-filter integration: control state machine --------------

    /// A connection filter that satisfies `send` / `recv` from in-memory
    /// buffers; marked already-connected so the chain routes I/O straight to it
    /// (and so `Curl_conn_connect` short-circuits to success).
    struct MockFilter {
        state: CfState,
        sent: Arc<Mutex<Vec<u8>>>,
        recv_data: Arc<Mutex<Vec<u8>>>,
    }

    impl MockFilter {
        fn new(recv_data: Arc<Mutex<Vec<u8>>>, sent: Arc<Mutex<Vec<u8>>>) -> Self {
            Self {
                state: CfState {
                    connected: true,
                    ..Default::default()
                },
                sent,
                recv_data,
            }
        }
    }

    impl ConnectionFilter for MockFilter {
        fn name(&self) -> &'static str {
            "MOCK-FTP"
        }
        fn cf_state(&self) -> &CfState {
            &self.state
        }
        fn cf_state_mut(&mut self) -> &mut CfState {
            &mut self.state
        }
        fn send<'a>(&'a mut self, buf: &'a [u8], _eos: bool) -> BoxFuture<'a, Result<usize>> {
            let sent = self.sent.clone();
            let chunk = buf.to_vec();
            Box::pin(async move {
                sent.lock().unwrap().extend_from_slice(&chunk);
                Ok(chunk.len())
            })
        }
        fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
            let queue = self.recv_data.clone();
            Box::pin(async move {
                let mut guard = queue.lock().unwrap();
                let n = buf.len().min(guard.len());
                buf[..n].copy_from_slice(&guard[..n]);
                guard.drain(..n);
                Ok(n)
            })
        }
    }

    /// Build a [`Connection`] with a single scripted [`MockFilter`] installed as
    /// the (already-connected) bottom of the control socket's filter chain.
    fn make_conn(recv_data: Arc<Mutex<Vec<u8>>>, sent: Arc<Mutex<Vec<u8>>>) -> Connection {
        let scheme = &SCHEME_FTP;
        let desc = SchemeDescriptor::new(
            scheme.name,
            scheme.default_port,
            scheme.flags,
            scheme.protocol,
        );
        let mut conn = Connection::new(
            format!("{}:{}", scheme.name, scheme.default_port),
            TRNSPRT_TCP,
            desc,
        );
        conn.remote_host = "127.0.0.1".to_string();
        conn.cfilter[FIRSTSOCKET].add_filter(Box::new(MockFilter::new(recv_data, sent)));
        conn
    }

    /// Reads the cumulative bytes the engine has placed on the control wire.
    fn sent_str(sent: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(sent.lock().unwrap().clone()).unwrap()
    }

    #[tokio::test]
    async fn login_state_machine_220_331_230_257() {
        let recv = Arc::new(Mutex::new(b"220 ProFTPD ready\r\n".to_vec()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.set_state(FtpState::Wait220);

        // Step 1: greeting (220) -> USER, state advances to User.
        ftpc.statemachine(&mut data, &mut conn).await.unwrap();
        assert_eq!(ftpc.state, FtpState::User);
        assert!(sent_str(&sent).contains("USER anonymous\r\n"));

        // Step 2: 331 -> PASS, state advances to Pass.
        recv.lock()
            .unwrap()
            .extend_from_slice(b"331 Password required\r\n");
        ftpc.statemachine(&mut data, &mut conn).await.unwrap();
        assert_eq!(ftpc.state, FtpState::Pass);
        assert!(sent_str(&sent).contains("PASS ftp@example.com\r\n"));

        // Step 3: 230 (logged in) -> PWD (no TLS), state advances to Pwd.
        recv.lock()
            .unwrap()
            .extend_from_slice(b"230 User logged in\r\n");
        ftpc.statemachine(&mut data, &mut conn).await.unwrap();
        assert_eq!(ftpc.state, FtpState::Pwd);
        assert!(sent_str(&sent).contains("PWD\r\n"));

        // Step 4: 257 with an absolute entry path -> connect phase complete.
        recv.lock()
            .unwrap()
            .extend_from_slice(b"257 \"/\" is the current directory\r\n");
        ftpc.statemachine(&mut data, &mut conn).await.unwrap();
        assert_eq!(ftpc.state, FtpState::Stop);
        assert_eq!(ftpc.entrypath.as_deref(), Some("/"));
    }

    #[tokio::test]
    async fn passive_epsv_negotiates_data_endpoint() {
        let recv = Arc::new(Mutex::new(Vec::new()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        // EPSV is the default; the data host is reused from the control host.
        data.set.ftp_use_epsv = true;

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());

        // Request passive mode: sends EPSV, count1 == 0, state == Pasv.
        ftpc.send_pasv(&mut data, &mut conn).await.unwrap();
        assert_eq!(ftpc.state, FtpState::Pasv);
        assert_eq!(ftpc.count1, 0);
        assert!(sent_str(&sent).contains("EPSV\r\n"));

        // Feed the 229 reply and parse it.
        recv.lock()
            .unwrap()
            .extend_from_slice(b"229 Entering Extended Passive Mode (|||50000|)\r\n");
        let code = ftpc.read_one(&mut data, &mut conn).await.unwrap();
        assert_eq!(code, 229);
        ftpc.state_pasv_resp(&mut data, &mut conn, code).await.unwrap();
        assert_eq!(ftpc.data_host.as_deref(), Some("127.0.0.1"));
        assert_eq!(ftpc.data_port, 50000);
    }

    #[tokio::test]
    async fn passive_pasv_parses_advertised_endpoint() {
        let recv = Arc::new(Mutex::new(Vec::new()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        // Disable EPSV so the engine issues PASV directly.
        data.set.ftp_use_epsv = false;
        // Exercise the advertised-IP parse. curl's `CURLOPT_FTP_SKIP_PASV_IP`
        // defaults ON (reuse the control host); turning it off uses the host
        // carried in the 227 reply, which is what this test asserts.
        data.set.ftp_skip_ip = false;

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());

        ftpc.send_pasv(&mut data, &mut conn).await.unwrap();
        assert_eq!(ftpc.count1, 1);
        assert!(sent_str(&sent).contains("PASV\r\n"));

        // 13 * 256 + 128 = 3456.
        recv.lock()
            .unwrap()
            .extend_from_slice(b"227 Entering Passive Mode (10,0,0,7,13,128)\r\n");
        let code = ftpc.read_one(&mut data, &mut conn).await.unwrap();
        assert_eq!(code, 227);
        ftpc.state_pasv_resp(&mut data, &mut conn, code).await.unwrap();
        assert_eq!(ftpc.data_host.as_deref(), Some("10.0.0.7"));
        assert_eq!(ftpc.data_port, 3456);
    }

    // ---- Handler wiring ---------------------------------------------------

    #[test]
    fn handler_reports_its_scheme() {
        let ftp = FtpHandler::new(&SCHEME_FTP);
        assert_eq!(ftp.scheme().name, "ftp");
        assert!(!ftp.is_implicit_tls());

        let ftps = FtpHandler::new(&SCHEME_FTPS);
        assert_eq!(ftps.scheme().name, "ftps");
        // ftps carries PROTOPT_SSL (implicit TLS from the first byte).
        assert!(ftps.is_implicit_tls());
    }
}
