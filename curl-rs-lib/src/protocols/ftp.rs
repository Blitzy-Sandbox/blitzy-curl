//! FTP / FTPS protocol handler — a faithful, idiomatic-Rust port of curl's
//! FTP client (`lib/ftp.c`, `lib/ftp.h`).
//!
//! FTP is the canonical **dual-connection** protocol: a persistent *control*
//! channel carries the line-based command/response dialogue (the "ping-pong"),
//! while each transfer opens a *separate* *data* channel — the connection's
//! [`SECONDARYSOCKET`] — for the file bytes or directory listing. It is also
//! the archetypal ping-pong protocol, so the command/response plumbing is
//! shared with IMAP/POP3/SMTP through [`crate::protocols::pingpong`].
//!
//! ```text
//! control:  220 ─► AUTH TLS ─► USER ─► PASS ─► [PBSZ/PROT] ─► PWD ─► SYST
//!                                                                      │
//!                                        (per transfer) CWD… ─► TYPE ─►│
//!                              MDTM/SIZE/REST ─► PASV|PORT ─► RETR|STOR|LIST
//!                                                                      │
//! data:     ───────────────────── file bytes / directory listing ─────┘
//! ```
//!
//! # State-machine fidelity (`--trace` ABI)
//!
//! The [`FtpState`] enum reproduces curl's `ftpstate` (`lib/ftp.h`) **variant
//! for variant, in order**, and [`FtpConn::state`] logs every transition with
//! the exact `ftp_state_names[]` string curl uses (`STOP`, `WAIT220`, `AUTH`,
//! …). The state names are a diagnostic contract: `--trace` output must stay
//! byte-identical to curl 8.x, so no state may be renamed, reordered, or
//! collapsed.
//!
//! # Minimal Change Mandate
//!
//! This module reproduces curl's FTP behavior **exactly** — active (`PORT`/
//! `EPRT`) and passive (`PASV`/`EPSV`) data connections, ASCII/binary `TYPE`,
//! `REST` resume, `MLSD`/`LIST`/`NLST` listings, multi-`CWD` traversal,
//! wildcard download, the `QUOTE`/`PREQUOTE`/`POSTQUOTE` command hooks, and
//! FTPS control- and data-channel protection. It adds nothing curl lacks.
//!
//! # FTPS
//!
//! `ftps://` (implicit, default port 990) wraps the control channel in TLS
//! *before* the greeting; `ftp://` with `AUTH TLS`/`AUTH SSL` (explicit)
//! upgrades an already-open control channel. In both cases the TLS layer is
//! established by the connection filter chain (`crate::conn` / [`crate::tls`]),
//! exactly as curl calls `Curl_ssl_cfilter_add` + `Curl_conn_connect`; this
//! handler then speaks plain FTP over the secure channel. `PBSZ 0` + `PROT P`
//! protect the data channel (with TLS session reuse from the control channel,
//! curl's `PROTOPT_SSL_REUSE`); `PROT C` leaves it clear; the optional `CCC`
//! command reverts the control channel to clear-text after login.
//!
//! # Zero `unsafe`
//!
//! Every byte of this module is safe Rust — the crate sets
//! `#![forbid(unsafe_code)]`. All parsing uses safe slice operations and the
//! standard integer/`str` conversions.

use std::mem;
use std::time::Instant;

use crate::conn::{ConnControl, Connection, FIRSTSOCKET, SECONDARYSOCKET};
use crate::error::{CurlCode, Error, Result};
use crate::pp_sendf;
use crate::protocols::ftp_list::{FileInfo, FileType, FtpListParser, CURLFINFOFLAG_KNOWN_SIZE};
use crate::protocols::pingpong::{PingPong, PingPongProtocol, PpTransfer};
use crate::protocols::{Pollset, ProtoFuture, Protocol, TransferCtx};

// ===========================================================================
// FTP state machine — a variant-for-variant rewrite of curl's `ftpstate`
// (`lib/ftp.h` L41-81).
//
// The discriminants are 0-based and follow the C enum order exactly, so
// `FtpState as u8` matches the `unsigned char` stored in `struct ftp_conn`.
// `FTP_LAST` is curl's "never used" sentinel, retained for parity.
// ===========================================================================

/// The FTP control-channel state (← `enum ftpstate`, `lib/ftp.h`).
///
/// Every variant maps one-to-one onto a `FTP_*` C enumerator, in declaration
/// order, and its [`FtpState::as_str`] name is the exact string curl logs in
/// `--trace` output (`ftp_state_names[]`). These names are frozen diagnostic
/// ABI — see the module docs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FtpState {
    /// `FTP_STOP` — do nothing; stops the state machine.
    Stop = 0,
    /// `FTP_WAIT220` — waiting for the initial `220` greeting after connect.
    Wait220,
    /// `FTP_AUTH` — awaiting the response to `AUTH SSL`/`AUTH TLS`.
    Auth,
    /// `FTP_USER` — awaiting the response to `USER`.
    User,
    /// `FTP_PASS` — awaiting the response to `PASS`.
    Pass,
    /// `FTP_ACCT` — awaiting the response to `ACCT`.
    Acct,
    /// `FTP_PBSZ` — awaiting the response to `PBSZ 0` (FTPS).
    Pbsz,
    /// `FTP_PROT` — awaiting the response to `PROT C`/`PROT P` (FTPS).
    Prot,
    /// `FTP_CCC` — awaiting the response to `CCC` (clear command channel).
    Ccc,
    /// `FTP_PWD` — awaiting the response to `PWD` (learn the entry path).
    Pwd,
    /// `FTP_SYST` — awaiting the response to `SYST` (server OS).
    Syst,
    /// `FTP_NAMEFMT` — awaiting the response to `SITE NAMEFMT 1` (OS/400).
    Namefmt,
    /// `FTP_QUOTE` — awaiting a response to a `CURLOPT_QUOTE` command.
    Quote,
    /// `FTP_RETR_PREQUOTE` — a `CURLOPT_PREQUOTE` command before `RETR`.
    RetrPrequote,
    /// `FTP_STOR_PREQUOTE` — a `CURLOPT_PREQUOTE` command before `STOR`.
    StorPrequote,
    /// `FTP_LIST_PREQUOTE` — a `CURLOPT_PREQUOTE` command before `LIST`.
    ListPrequote,
    /// `FTP_POSTQUOTE` — a `CURLOPT_POSTQUOTE` command after the transfer.
    Postquote,
    /// `FTP_CWD` — change directory.
    Cwd,
    /// `FTP_MKD` — create a directory that did not exist.
    Mkd,
    /// `FTP_MDTM` — obtain the file's modification time.
    Mdtm,
    /// `FTP_TYPE` — set the transfer type for a head-like request.
    Type,
    /// `FTP_LIST_TYPE` — set the transfer type before a directory listing.
    ListType,
    /// `FTP_RETR_LIST_TYPE` — set the type before a wildcard-listing `RETR`.
    RetrListType,
    /// `FTP_RETR_TYPE` — set the type before a `RETR`.
    RetrType,
    /// `FTP_STOR_TYPE` — set the type before a `STOR`.
    StorType,
    /// `FTP_SIZE` — get the remote file size for a head-like request.
    Size,
    /// `FTP_RETR_SIZE` — get the remote file size for `RETR`.
    RetrSize,
    /// `FTP_STOR_SIZE` — get the size for `STOR` (resume).
    StorSize,
    /// `FTP_REST` — probe `REST` support for a head-like request.
    Rest,
    /// `FTP_RETR_REST` — request "resume" via `REST` for `RETR`.
    RetrRest,
    /// `FTP_PORT` — generic state for `PORT`/`EPRT` (active mode); see `count1`.
    Port,
    /// `FTP_PRET` — generic state for `PRET RETR`/`STOR`/`LIST` (drftpd).
    Pret,
    /// `FTP_PASV` — generic state for `PASV`/`EPSV` (passive mode); see `count1`.
    Pasv,
    /// `FTP_LIST` — generic state for `LIST`/`NLST`/`MLSD`/custom list.
    List,
    /// `FTP_RETR` — awaiting the `RETR` response.
    Retr,
    /// `FTP_STOR` — generic state for `STOR`/`APPE`.
    Stor,
    /// `FTP_QUIT` — awaiting the `QUIT` response.
    Quit,
    /// `FTP_LAST` — curl's "never used" sentinel (kept for parity).
    Last,
}

/// The trace names curl logs for each state (← `ftp_state_names[]`,
/// `lib/ftp.c`). Indexed by `FtpState as usize`; there is no entry for
/// [`FtpState::Last`] (curl's array stops at `QUIT`), matching curl exactly.
const FTP_STATE_NAMES: [&str; 37] = [
    "STOP",
    "WAIT220",
    "AUTH",
    "USER",
    "PASS",
    "ACCT",
    "PBSZ",
    "PROT",
    "CCC",
    "PWD",
    "SYST",
    "NAMEFMT",
    "QUOTE",
    "RETR_PREQUOTE",
    "STOR_PREQUOTE",
    "LIST_PREQUOTE",
    "POSTQUOTE",
    "CWD",
    "MKD",
    "MDTM",
    "TYPE",
    "LIST_TYPE",
    "RETR_LIST_TYPE",
    "RETR_TYPE",
    "STOR_TYPE",
    "SIZE",
    "RETR_SIZE",
    "STOR_SIZE",
    "REST",
    "RETR_REST",
    "PORT",
    "PRET",
    "PASV",
    "LIST",
    "RETR",
    "STOR",
    "QUIT",
];

impl Default for FtpState {
    /// A freshly-created connection starts in [`FtpState::Stop`], matching the
    /// zero-initialized `state` field of `struct ftp_conn` (`FTP_STOP == 0`).
    fn default() -> Self {
        FtpState::Stop
    }
}

impl FtpState {
    /// Returns the exact `--trace` name curl logs for this state
    /// (← `ftp_state_names[state]`, `FTP_CSTATE`).
    ///
    /// [`FtpState::Last`] has no name in curl's array; it returns `"???"`,
    /// mirroring the `FTP_CSTATE` fallback for an out-of-range state.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        let idx = self as usize;
        if idx < FTP_STATE_NAMES.len() {
            FTP_STATE_NAMES[idx]
        } else {
            "???"
        }
    }
}

// ===========================================================================
// FTP-wide constants (← `lib/ftp.h`, `lib/ftp.c`).
// ===========================================================================

/// The deepest directory hierarchy `ftp_parse_url_path` will accept before
/// declaring the URL malformed (← `FTP_MAX_DIR_DEPTH`, `lib/ftp.c`).
const FTP_MAX_DIR_DEPTH: usize = 1000;

/// How long to wait for the server to open the active-mode data connection,
/// in milliseconds (← `DEFAULT_ACCEPT_TIMEOUT`, `lib/ftp.h`, one minute).
pub const DEFAULT_ACCEPT_TIMEOUT: u64 = 60_000;

/// The mechanism tokens tried for explicit FTPS, in order (← `ftpauth[]`,
/// `lib/ftp.c`): `AUTH SSL` then `AUTH TLS`.
const FTPAUTH: [&str; 2] = ["SSL", "TLS"];

/// The passive-mode commands, indexed by `count1` (← `mode[]` in
/// `ftp_state_use_pasv`): `EPSV` (0) then `PASV` (1).
const PASV_MODE: [&str; 2] = ["EPSV", "PASV"];

/// The active-mode commands, indexed by the `fcmd` counter (← `mode[]` in
/// `ftp_state_use_port`): `EPRT` then `PORT`.
const PORT_MODE: [&str; 2] = ["EPRT", "PORT"];

/// How curl maps a URL path onto FTP directory navigation
/// (← `curl_ftpfile`, `lib/ftp.h`). The discriminants are frozen (they are
/// the `CURLOPT_FTP_FILEMETHOD` values).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u8)]
pub enum CurlFtpFile {
    /// `FTPFILE_MULTICWD` — one `CWD` per path component (RFC 1738 default).
    #[default]
    Multicwd = 1,
    /// `FTPFILE_NOCWD` — no `CWD`; use `SIZE`/`RETR`/`STOR` on the full path.
    Nocwd = 2,
    /// `FTPFILE_SINGLECWD` — a single `CWD`, then operate on the file.
    Singlecwd = 3,
}

/// The `curl_usessl` levels controlling FTPS negotiation (← `include/curl/curl.h`).
/// Stored as the frozen integer values in [`FtpConn::use_ssl`].
pub mod usessl {
    /// `CURLUSESSL_NONE` — do not attempt TLS.
    pub const NONE: u8 = 0;
    /// `CURLUSESSL_TRY` — try TLS, but continue in clear text on failure.
    pub const TRY: u8 = 1;
    /// `CURLUSESSL_CONTROL` — require TLS on the control channel.
    pub const CONTROL: u8 = 2;
    /// `CURLUSESSL_ALL` — require TLS on both control and data channels.
    pub const ALL: u8 = 3;
}

/// `CURLFTPSSL_CCC_ACTIVE` — send our own close-notify when clearing the
/// command channel (← `include/curl/curl.h`); the default (`PASSIVE`) waits
/// for the server's alert only.
const CURLFTPSSL_CCC_ACTIVE: u8 = 2;

/// The `curl_ftpauth` order for explicit FTPS negotiation
/// (← `include/curl/curl.h`); selects which of `AUTH SSL`/`AUTH TLS` is tried
/// first. Stored as the frozen integer values in [`FtpParams::ftpsslauth`].
pub mod ftpsslauth {
    /// `CURLFTPAUTH_DEFAULT` — let curl decide (`SSL` first, same as `SSL`).
    pub const DEFAULT: u8 = 0;
    /// `CURLFTPAUTH_SSL` — try `AUTH SSL` first, then `AUTH TLS`.
    pub const SSL: u8 = 1;
    /// `CURLFTPAUTH_TLS` — try `AUTH TLS` first, then `AUTH SSL`.
    pub const TLS: u8 = 2;
}

/// The `CURL_TIMECOND_*` values controlling a time-conditional transfer
/// (← `include/curl/curl.h`), consumed by [`FtpConn::state_mdtm_resp`].
pub mod timecond {
    /// `CURL_TIMECOND_NONE` — no time condition.
    pub const NONE: u8 = 0;
    /// `CURL_TIMECOND_IFMODSINCE` — transfer only if newer than the value.
    pub const IFMODSINCE: u8 = 1;
    /// `CURL_TIMECOND_IFUNMODSINCE` — transfer only if older than the value.
    pub const IFUNMODSINCE: u8 = 2;
}

// ===========================================================================
// Per-transfer options (← the `data->set` / `data->state` fields `ftp.c`
// reads). curl fetches these from the easy handle throughout the state
// machine; this port snapshots the FTP-relevant subset into `FtpParams` so the
// transition logic ports verbatim without an easy-handle reference. This is
// the exact analogue of `struct FTP` (the transfer-scoped state, [`Ftp`]) plus
// the option fields curl reads from `data->set`/`data->state`; both are held
// on [`FtpConn`] for the duration of a transfer, mirroring how
// `ftp_pp_statemachine` fetches `struct FTP` and reads `data->set` at entry.
// ===========================================================================

/// The FTP-relevant subset of the easy-handle options/state the state machine
/// reads (← `data->set.*` / `data->state.*` in `lib/ftp.c`).
///
/// Every field mirrors the C member it stands in for; the defaults reproduce a
/// freshly-`curl_easy_init`ed handle (MULTICWD, passive mode, binary, no
/// resume, no time condition).
#[derive(Debug, Clone, Default)]
pub struct FtpParams {
    /// How to map the URL path onto directory navigation
    /// (← `data->set.ftp_filemethod`).
    pub filemethod: CurlFtpFile,
    /// `--ftp-create-dirs` level: `0` off, `1` one level, `2` recursive
    /// (← `data->set.ftp_create_missing_dirs`).
    pub create_missing_dirs: u8,
    /// Use active mode (`PORT`/`EPRT`) instead of passive
    /// (← `data->set.ftp_use_port`).
    pub use_port: bool,
    /// The `--ftp-port` argument, if any (← `data->set.str[STRING_FTPPORT]`).
    pub ftpport: Option<String>,
    /// Send `PRET` before `PASV` (drftpd) (← `data->set.ftp_use_pret`).
    pub use_pret: bool,
    /// Ignore the server-provided IP in a `227` reply, reuse the control host
    /// (← `data->set.ftp_skip_ip`).
    pub skip_ip: bool,
    /// Prefer ASCII (`TYPE A`) transfers (← `data->state.prefer_ascii`).
    pub prefer_ascii: bool,
    /// Directory-listing (`NLST`) mode (← `data->state.list_only`).
    pub list_only: bool,
    /// This is an upload (`STOR`/`APPE`) (← `data->state.upload`).
    pub upload: bool,
    /// Ignore the reported content length, for growing files
    /// (← `data->set.ignorecl`, `CURLOPT_IGNORE_CONTENT_LENGTH`).
    pub ignorecl: bool,
    /// Append rather than overwrite on upload (← `data->set.remote_append`).
    pub remote_append: bool,
    /// The resume offset for `RETR`/`STOR` (← `data->state.resume_from`).
    pub resume_from: i64,
    /// The known upload size, or `-1` (← `data->state.infilesize`).
    pub infilesize: i64,
    /// The maximum file size to accept, or `0` for no limit
    /// (← `data->set.max_filesize`).
    pub max_filesize: i64,
    /// Retrieve the remote modification time (← `data->set.get_filetime`).
    pub get_filetime: bool,
    /// The `CURL_TIMECOND_*` selector, or `0` (← `data->set.timecondition`);
    /// see [`timecond`].
    pub timecondition: u8,
    /// The reference time for the time condition (← `data->set.timevalue`).
    pub timevalue: i64,
    /// Do CRLF line-ending conversion on upload (← `data->set.crlf`).
    pub crlf: bool,
    /// A custom list/transfer command (← `data->set.str[STRING_CUSTOMREQUEST]`).
    pub customrequest: Option<String>,
    /// Which `AUTH` mechanism to try first for explicit FTPS
    /// (← `data->set.ftpsslauth`); see [`ftpsslauth`].
    pub ftpsslauth: u8,
    /// `CURLOPT_QUOTE` commands, sent before the transfer (← `data->set.quote`).
    pub quote: Vec<String>,
    /// `CURLOPT_PREQUOTE` commands, sent after `CWD`/`TYPE`
    /// (← `data->set.prequote`).
    pub prequote: Vec<String>,
    /// `CURLOPT_POSTQUOTE` commands, sent after the transfer
    /// (← `data->set.postquote`).
    pub postquote: Vec<String>,
    /// Resolve wildcards in the path (← `data->state.wildcardmatch`).
    pub wildcardmatch: bool,
    /// A "head"-like request that wants no body (← `data->req.no_body`).
    pub no_body: bool,
}

// ===========================================================================
// Connection-liveness bits (← `CONNCHECK_*` / `CONNRESULT_*`, `lib/urldata.h`).
//
// No such constants exist elsewhere in this crate yet, so they are defined
// here for signature parity with curl's `connection_check` vtable slot. curl's
// FTP handler installs no `connection_check` (the slot is `ZERO_NULL`), so
// [`FtpHandler::connection_check`] returns [`CONNRESULT_NONE`]; the constants
// document the contract the multi layer expects.
// ===========================================================================

/// `CONNCHECK_ISDEAD` — ask whether the connection is dead.
pub const CONNCHECK_ISDEAD: u32 = 1 << 0;
/// `CONNCHECK_KEEPALIVE` — ask the handler to send a keep-alive probe.
pub const CONNCHECK_KEEPALIVE: u32 = 1 << 1;
/// `CONNRESULT_NONE` — no result bits (the connection is considered alive).
pub const CONNRESULT_NONE: u32 = 0;
/// `CONNRESULT_DEAD` — the connection was found dead.
pub const CONNRESULT_DEAD: u32 = 1 << 0;

// ===========================================================================
// Per-transfer state (← `struct FTP`, `lib/ftp.h` L106-114).
// ===========================================================================

/// The transfer-scoped FTP state (← `struct FTP`).
///
/// curl keeps this on the easy handle (not the connection) because a single
/// connection may be reused across easy handles: the path and the
/// download-size belong to *this* transfer, whereas login state, the entry
/// path, and the negotiated data address belong to the [`FtpConn`].
#[derive(Debug, Clone)]
pub struct Ftp {
    /// The (URL-encoded) path being transferred (← `FTP.path`). curl points
    /// this at the URL's path field or at [`pathalloc`](Self::pathalloc)
    /// during a wildcard transfer; here it is always an owned copy.
    pub path: String,
    /// The owned path allocated for a wildcard transfer, if any
    /// (← `FTP.pathalloc`). When `Some`, [`path`](Self::path) is a copy of it.
    pub pathalloc: Option<String>,
    /// Whether to transfer a body, only info/headers, or nothing
    /// (← `FTP.transfer`).
    pub transfer: PpTransfer,
    /// The number of bytes to download for this transfer (← `FTP.downloadsize`).
    pub downloadsize: i64,
}

impl Ftp {
    /// Creates a fresh per-transfer state (← the zeroed `struct FTP` set up by
    /// `ftp_setup_connection`): a body transfer with an unset path.
    #[must_use]
    pub fn new() -> Self {
        Ftp {
            path: String::new(),
            pathalloc: None,
            transfer: PpTransfer::Body,
            downloadsize: 0,
        }
    }
}

impl Default for Ftp {
    /// A default per-transfer state is a fresh body transfer ([`Ftp::new`]).
    /// (`PpTransfer` has no `Default`, so this cannot be derived.)
    fn default() -> Self {
        Ftp::new()
    }
}

// ===========================================================================
// Path components (← `struct pathcomp`, `lib/ftp.h` L117-120).
//
// curl stores each directory component as a `{start,len}` slice into the
// url-decoded `rawpath`. This port stores owned component strings in
// [`FtpConn::dirs`] instead (safe Rust owns its slices), which is behaviorally
// identical; `PathComp` is retained for documentation/ABI parity.
// ===========================================================================

/// One directory component's `{start, len}` span within the raw path
/// (← `struct pathcomp`). Retained for parity; the live representation is the
/// owned [`FtpConn::dirs`] vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PathComp {
    /// Start column within the url-decoded raw path (← `pathcomp.start`).
    pub start: usize,
    /// Length in bytes (← `pathcomp.len`).
    pub len: usize,
}

// ===========================================================================
// Wildcard-download state (← `enum wildcard_states` / `struct WildcardData` +
// `struct ftp_wc`, `lib/urldata.h` + `lib/ftp.c` L3776-4007).
//
// curl keeps the wildcard machine on the easy handle's `data->wildcard`; this
// port co-locates it on [`FtpConn`] for the duration of a wildcard transfer,
// exactly as it co-locates [`Ftp`]/[`FtpParams`]. The FTP-specific `struct
// ftp_wc` (the parser + the write-function backup) folds into the same struct.
// ===========================================================================

/// The wildcard-download state (← `enum wildcard_states`, `CURLWC_*`).
///
/// Drives a `LIST` of the directory, matches each returned entry against the
/// glob pattern taken from the URL's last path component, and `RETR`s the
/// matches one at a time. The names map onto curl's `CURLWC_INIT`,
/// `CURLWC_MATCHING`, `CURLWC_DOWNLOADING`, `CURLWC_SKIP`, `CURLWC_CLEAN`,
/// `CURLWC_DONE`, and `CURLWC_ERROR`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum WildcardState {
    /// `CURLWC_INIT` — parse the pattern and kick off the directory listing.
    #[default]
    Init,
    /// `CURLWC_MATCHING` — the `LIST` response has been parsed into the file
    /// list; restore the normal write path and check for matches.
    Matching,
    /// `CURLWC_DOWNLOADING` — transferring the matched files in turn.
    Downloading,
    /// `CURLWC_SKIP` — skip the current entry (a non-file, or a user skip).
    Skip,
    /// `CURLWC_CLEAN` — the last file is done; surface any parse error.
    Clean,
    /// `CURLWC_DONE` — all matches transferred successfully.
    Done,
    /// `CURLWC_ERROR` — the listing or its parse failed.
    Error,
}

/// Per-transfer wildcard state (← `struct WildcardData` + the FTP-specific
/// `struct ftp_wc`).
///
/// Holds the glob pattern extracted from the URL, the base directory the
/// matches live under, the [`FtpListParser`] fed by the `LIST` data, the queue
/// of matched files awaiting `RETR`, and the sticky parse error (curl's
/// `Curl_ftp_parselist_geterror`). The write-function backup curl keeps in
/// `ftp_wc.backup` is not needed here: the parser is fed explicitly through
/// [`FtpConn::wc_parse_feed`] rather than by swapping the easy handle's write
/// callback.
#[derive(Default)]
pub struct FtpWildcard {
    /// The current wildcard state (← `WildcardData.state`).
    pub state: WildcardState,
    /// The trailing glob pattern from the URL (← `WildcardData.pattern`).
    pub pattern: Option<String>,
    /// The base directory the matched files live under (← `WildcardData.path`).
    pub path: String,
    /// The directory-listing parser (← `ftp_wc.parser`).
    pub parser: FtpListParser,
    /// The queue of matched files still to transfer (← `WildcardData.filelist`).
    pub filelist: std::collections::VecDeque<FileInfo>,
    /// The sticky `LIST`-parse error, if any (← `Curl_ftp_parselist_geterror`).
    pub parse_error: Option<CurlCode>,
}

impl std::fmt::Debug for FtpWildcard {
    /// [`FtpListParser`] has no `Debug`, so this is hand-written and reports the
    /// queue length rather than the parser internals.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FtpWildcard")
            .field("state", &self.state)
            .field("pattern", &self.pattern)
            .field("path", &self.path)
            .field("filelist_len", &self.filelist.len())
            .field("parse_error", &self.parse_error)
            .finish_non_exhaustive()
    }
}

// ===========================================================================
// Per-connection state (← `struct ftp_conn`, `lib/ftp.h` L124-164).
// ===========================================================================

/// The connection-scoped FTP state (← `struct ftp_conn`).
///
/// This owns the control-channel [`PingPong`] engine and every fact that
/// persists across transfers on the same connection: the login/entry path, the
/// negotiated data address, the general-purpose state-machine counters, and the
/// current [`FtpState`]. The general-purpose `count1`/`count2`/`count3` fields
/// keep curl's exact roles so the transition logic ports verbatim.
#[derive(Default)]
pub struct FtpConn {
    /// The control-channel command/response engine (← `ftp_conn.pp`).
    ///
    /// Owned here exactly as curl embeds `struct pingpong pp`. Because the
    /// [`PingPongProtocol`] engine methods take `pp` and the protocol object as
    /// *separate* borrows, the driver ([`FtpConn::statemach`]) temporarily
    /// [`mem::take`]s this field out before calling into the engine and puts it
    /// back afterward; the engine methods therefore never touch `self.pp`.
    pub pp: PingPong,
    /// The `ACCT` account string, if any (← `ftp_conn.account`).
    pub account: Option<String>,
    /// The `CURLOPT_FTP_ALTERNATIVE_TO_USER` fallback login
    /// (← `ftp_conn.alternative_to_user`).
    pub alternative_to_user: Option<String>,
    /// The working directory reported by `PWD` at login (← `ftp_conn.entrypath`).
    pub entrypath: Option<String>,
    /// The url-decoded filename for this transfer, if any (← `ftp_conn.file`).
    pub file: Option<String>,
    /// The url-decoded full path for this transfer (← `ftp_conn.rawpath`).
    pub rawpath: String,
    /// The url-decoded directory components to `CWD` through, in order
    /// (← `ftp_conn.dirs`, stored as owned strings instead of `{start,len}`).
    pub dirs: Vec<String>,
    /// The previous transfer's url-decoded path, for reuse detection
    /// (← `ftp_conn.prevpath`).
    pub prevpath: Option<String>,
    /// The current transfer type: `b'A'` (ASCII), `b'I'` (binary), or `0`
    /// (unset) (← `ftp_conn.transfertype`).
    pub transfertype: u8,
    /// The server operating system reported by `SYST` (← `ftp_conn.server_os`).
    pub server_os: Option<String>,
    /// The wildcard-listed file size, or `-1` if unknown
    /// (← `ftp_conn.known_filesize`).
    pub known_filesize: i64,
    /// General-purpose state-machine counter #1 (← `ftp_conn.count1`).
    pub count1: i32,
    /// General-purpose state-machine counter #2 (← `ftp_conn.count2`).
    pub count2: i32,
    /// General-purpose state-machine counter #3 (← `ftp_conn.count3`).
    pub count3: i32,
    /// Number of directory components in [`dirs`](Self::dirs)
    /// (← `ftp_conn.dirdepth`).
    pub dirdepth: u16,
    /// Number of `CWD` commands issued so far (← `ftp_conn.cwdcount`).
    pub cwdcount: u16,
    /// The current control-channel state (← `ftp_conn.state`); change only via
    /// [`FtpConn::state`].
    state: FtpState,
    /// The `curl_usessl` level for this connection (← `ftp_conn.use_ssl`); see
    /// [`usessl`].
    pub use_ssl: u8,
    /// The `CURLOPT_FTP_SSL_CCC` level for this connection (← `ftp_conn.ccc`).
    pub ccc: u8,
    /// Whether the alternative-to-user login is currently being tried
    /// (← `ftp_conn.ftp_trying_alternative`).
    pub ftp_trying_alternative: bool,
    /// Suppress the final post-transfer size / `226`/`250` status check
    /// (← `ftp_conn.dont_check`).
    pub dont_check: bool,
    /// Whether the control connection is still usable for `QUIT`
    /// (← `ftp_conn.ctl_valid`).
    pub ctl_valid: bool,
    /// Whether the correct `CWD` sequence has already been performed
    /// (← `ftp_conn.cwddone`).
    pub cwddone: bool,
    /// Whether a `CWD` failed (so the path must not be cached)
    /// (← `ftp_conn.cwdfail`).
    pub cwdfail: bool,
    /// Whether the data connection is being awaited (← `ftp_conn.wait_data_conn`).
    pub wait_data_conn: bool,
    /// Whether the connection is being shut down (`QUIT`) (← `ftp_conn.shutdown`).
    pub shutdown: bool,

    // --- in-flight transfer context ---------------------------------------
    // curl fetches `struct FTP` (the transfer-scoped state) and reads
    // `data->set`/`data->state` at the top of every `ftp_pp_statemachine`
    // call. Because the [`PingPongProtocol::statemachine`] hook receives only
    // `self`/`pp`/`conn` (no easy handle), this port co-locates both here for
    // the duration of a transfer. They are reset per transfer by
    // [`FtpConn::begin_transfer`], mirroring curl's per-call meta fetch.
    /// The transfer-scoped state for the transfer in flight (← `struct FTP`).
    pub ftp: Ftp,
    /// The easy-handle option/state snapshot for the transfer in flight
    /// (← the `data->set`/`data->state` fields `ftp.c` reads).
    pub params: FtpParams,
    /// The remote modification time parsed from `MDTM`, in seconds since the
    /// epoch, or `0` if unknown (← `data->info.filetime`).
    pub filetime: i64,
    /// Whether the time condition was met such that no transfer happens
    /// (← `data->info.timecond`).
    pub timecond: bool,
    /// The size the transfer layer should expect for a download, or `-1`
    /// (← `data->req.size`); set by [`FtpConn::state_get_resp`]/`state_size_resp`.
    pub req_size: i64,
    /// The maximum number of bytes to download, or `-1` for unlimited
    /// (← `data->req.maxdownload`); set from a byte range.
    pub req_maxdownload: i64,
    /// Set by [`FtpConn::initiate_transfer`] once a data transfer has been set
    /// up, to signal that the control channel must be read for the final
    /// `226`/`250` transfer-complete reply in [`FtpConn::done_engine`].
    ///
    /// This is the faithful port of `ftp_initiate_transfer`'s
    /// `ftpc->pp.pending_resp = TRUE` (`lib/ftp.c` L569): curl re-arms the
    /// ping-pong "response pending" flag there because [`PingPong::readresp`]
    /// clears it after every completed read and no command is sent between the
    /// `150`/`125` reply and the trailing `226`. Since the [`PingPong`]
    /// dependency exposes no public setter for that flag, this connection-scoped
    /// bool carries the exact same gate.
    pub pending_final_resp: bool,
    /// The wildcard-download machine for a `CURLOPT_WILDCARDMATCH` transfer
    /// (← `data->wildcard` + `ftp_wc`). Idle ([`WildcardState::Init`], empty)
    /// unless [`FtpParams::wildcardmatch`] is set; driven by
    /// [`FtpConn::wc_statemach`].
    pub wildcard: FtpWildcard,
}

impl std::fmt::Debug for FtpConn {
    /// A [`PingPong`] has no `Debug`, so this is written by hand and omits the
    /// `pp` engine (showing only the FTP-specific state), exactly as
    /// `smb.rs`/other engines skip their non-`Debug` transport fields.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FtpConn")
            .field("state", &self.state)
            .field("entrypath", &self.entrypath)
            .field("file", &self.file)
            .field("rawpath", &self.rawpath)
            .field("dirs", &self.dirs)
            .field("dirdepth", &self.dirdepth)
            .field("cwdcount", &self.cwdcount)
            .field("transfertype", &self.transfertype)
            .field("count1", &self.count1)
            .field("count2", &self.count2)
            .field("count3", &self.count3)
            .field("use_ssl", &self.use_ssl)
            .field("ccc", &self.ccc)
            .field("known_filesize", &self.known_filesize)
            .field("cwddone", &self.cwddone)
            .field("ctl_valid", &self.ctl_valid)
            .field("wait_data_conn", &self.wait_data_conn)
            .finish_non_exhaustive()
    }
}

impl FtpConn {
    /// Creates a fresh per-connection state (← the zeroed `struct ftp_conn`
    /// allocated by `ftp_setup_connection`).
    ///
    /// Mirrors `ftp_setup_connection`'s explicit initialization:
    /// `known_filesize` starts at `-1` (unknown) and everything else is zero /
    /// empty / [`FtpState::Stop`].
    #[must_use]
    pub fn new() -> Self {
        FtpConn {
            pp: PingPong::new(),
            known_filesize: -1,
            req_size: -1,
            req_maxdownload: -1,
            ..Default::default()
        }
    }

    /// Reset the per-transfer context for a new transfer on this connection
    /// (← curl re-fetching `struct FTP` + reading `data->set`/`data->state` at
    /// the start of each DO). Installs the transfer-scoped [`Ftp`] and the
    /// [`FtpParams`] option snapshot and clears the per-transfer result fields;
    /// connection-scoped login/entry-path state is preserved for reuse.
    pub fn begin_transfer(&mut self, ftp: Ftp, params: FtpParams) {
        self.ftp = ftp;
        self.params = params;
        self.filetime = 0;
        self.timecond = false;
        self.req_size = -1;
        self.req_maxdownload = -1;
        self.count1 = 0;
        self.count2 = 0;
        self.count3 = 0;
        self.pending_final_resp = false;
    }

    /// Returns the current control-channel state (← `ftp_conn.state`).
    #[must_use]
    pub fn state(&self) -> FtpState {
        self.state
    }

    /// Transition to `newstate`, logging `[old] -> [new]` exactly as curl's
    /// `ftp_state_low` does via `CURL_TRC_FTP` (← `lib/ftp.c`).
    ///
    /// The trace line is emitted **only when the state actually changes**,
    /// byte-for-byte matching curl's `if(ftpc->state != newstate)` guard, so
    /// `--trace` output stays identical. This is the single permitted way to
    /// change the state, mirroring curl's "always use ftp.c:state()" rule.
    pub fn set_state(&mut self, newstate: FtpState) {
        if self.state != newstate {
            tracing::trace!(
                target: "curl::ftp",
                "[{}] -> [{}]",
                self.state.as_str(),
                newstate.as_str()
            );
        }
        self.state = newstate;
    }

    /// Frees the directory list (← `freedirs`, `lib/ftp.c`).
    ///
    /// Clears the owned components, the raw path, and resets `dirdepth`; the
    /// filename slice (owned here) is dropped too, matching curl clearing
    /// `ftpc->file`.
    pub fn freedirs(&mut self) {
        self.dirs.clear();
        self.dirdepth = 0;
        self.rawpath.clear();
        self.file = None;
    }

    /// Returns `true` if a `TYPE` command must be sent to switch the transfer
    /// mode (← `ftp_need_type`, `lib/ftp.c`): the current `transfertype` does
    /// not already match the desired ASCII/binary mode.
    #[must_use]
    pub fn need_type(&self, ascii_wanted: bool) -> bool {
        self.transfertype != if ascii_wanted { b'A' } else { b'I' }
    }

    /// Parse the URL path into directory components and a filename
    /// (← `ftp_parse_url_path`, `lib/ftp.c` L205-343).
    ///
    /// `path` is the raw (URL-encoded) path; it is url-decoded (rejecting
    /// control characters, curl's `REJECT_CTRL`) into [`rawpath`](Self::rawpath)
    /// and then split according to `filemethod`:
    ///
    /// * [`CurlFtpFile::Nocwd`] — the whole path is the file (unless it ends in
    ///   `/`); no `CWD` components.
    /// * [`CurlFtpFile::Singlecwd`] — everything before the last `/` is a single
    ///   directory; the rest is the file.
    /// * [`CurlFtpFile::Multicwd`] — split on every `/`, skipping empty
    ///   components (`x//y`), with a leading `/` kept as the first component.
    ///
    /// `upload`, `reuse`, and `transfer` mirror the easy-handle/connection state
    /// curl reads to (a) reject an upload URL that lacks a filename and (b)
    /// decide whether the current directory already matches
    /// [`prevpath`](Self::prevpath) (setting [`cwddone`](Self::cwddone)).
    ///
    /// # Errors
    ///
    /// * [`CurlCode::UrlMalformat`] — control characters in the path, a
    ///   directory hierarchy deeper than [`FTP_MAX_DIR_DEPTH`], or an upload
    ///   without a filename.
    pub fn parse_url_path(
        &mut self,
        path: &str,
        filemethod: CurlFtpFile,
        upload: bool,
        reuse: bool,
        transfer: PpTransfer,
    ) -> Result<()> {
        // `ftpc->ctl_valid = FALSE; ftpc->cwdfail = FALSE;`
        self.ctl_valid = false;
        self.cwdfail = false;

        if !self.rawpath.is_empty() || !self.dirs.is_empty() {
            self.freedirs();
        }

        // `Curl_urldecode(..., REJECT_CTRL)`.
        let raw = urldecode_reject_ctrl(path.as_bytes())?;
        self.rawpath = String::from_utf8_lossy(&raw).into_owned();
        let raw_path = self.rawpath.clone();
        let path_len = raw_path.len();

        let mut file_name: Option<String> = None;
        self.dirs.clear();
        self.dirdepth = 0;

        match filemethod {
            CurlFtpFile::Nocwd => {
                // Full file path unless it ends with '/'.
                if path_len > 0 && !raw_path.ends_with('/') {
                    file_name = Some(raw_path.clone());
                }
            }
            CurlFtpFile::Singlecwd => {
                if let Some(slash) = raw_path.rfind('/') {
                    // Directory before the last slash (min length 1 for "/…").
                    let dirlen = if slash == 0 { 1 } else { slash };
                    self.dirs.push(raw_path[..dirlen].to_string());
                    self.dirdepth = 1;
                    file_name = Some(raw_path[slash + 1..].to_string());
                } else {
                    file_name = Some(raw_path.clone());
                }
            }
            CurlFtpFile::Multicwd => {
                let dir_alloc = numof_slashes(&raw_path);
                if dir_alloc >= FTP_MAX_DIR_DEPTH {
                    return Err(Error::with_context(
                        CurlCode::UrlMalformat,
                        "FTP directory hierarchy too deep",
                    ));
                }
                let bytes = raw_path.as_bytes();
                let mut cur = 0usize;
                for _ in 0..dir_alloc {
                    // Next component runs up to the next '/'.
                    let rel = bytes[cur..]
                        .iter()
                        .position(|&b| b == b'/')
                        .expect("numof_slashes guarantees a '/'");
                    let spos = cur + rel;
                    let mut clen = spos - cur;
                    // A leading slash becomes a directory of its own ("/").
                    if clen == 0 && self.dirdepth == 0 {
                        clen += 1;
                    }
                    // Skip empty components ("x//y").
                    if clen != 0 {
                        self.dirs.push(raw_path[cur..cur + clen].to_string());
                        self.dirdepth += 1;
                    }
                    cur = spos + 1;
                }
                // The remainder is the filename (or empty).
                file_name = Some(raw_path[cur..].to_string());
            }
        }

        // `if(fileName && *fileName) ftpc->file = fileName; else NULL;`
        self.file = match file_name {
            Some(f) if !f.is_empty() => Some(f),
            _ => None,
        };

        // An upload needs a filename.
        if upload && self.file.is_none() && transfer == PpTransfer::Body {
            return Err(Error::with_context(
                CurlCode::UrlMalformat,
                "Uploading to a URL without a filename",
            ));
        }

        // Decide whether the CWD sequence can be skipped.
        self.cwddone = false;
        if filemethod == CurlFtpFile::Nocwd && raw_path.starts_with('/') {
            // Absolute path with NOCWD: no CWD needed.
            self.cwddone = true;
        } else {
            // A freshly created connection already sits in the entry path; a
            // reused one may already be in the right directory.
            let old_path: &str = if reuse {
                self.prevpath.as_deref().unwrap_or("")
            } else {
                ""
            };
            let mut n = path_len;
            if filemethod == CurlFtpFile::Nocwd {
                n = 0; // CWD to entry for relative paths
            } else if let Some(f) = &self.file {
                n -= f.len();
            }
            if old_path.len() == n
                && raw_path.len() >= n
                && raw_path.as_bytes()[..n] == old_path.as_bytes()[..n]
            {
                self.cwddone = true;
            }
        }

        Ok(())
    }
}

// ===========================================================================
// Free helper functions (← the file-scope helpers in `lib/ftp.c`).
// ===========================================================================

/// Counts the `/` bytes in `s` (← `numof_slashes`, `lib/ftp.c`), i.e. the
/// number of directory components to allocate for a MULTICWD split.
fn numof_slashes(s: &str) -> usize {
    s.bytes().filter(|&b| b == b'/').count()
}

/// url-decode `input`, rejecting control characters (← `Curl_urldecode` with
/// the `REJECT_CTRL` flag). `%XX` escapes are decoded; a decoded byte `<= 0x1f`
/// or `== 0x7f` is rejected, exactly as curl does for FTP paths.
///
/// # Errors
///
/// [`CurlCode::UrlMalformat`] for a malformed `%`-escape or a control byte.
fn urldecode_reject_ctrl(input: &[u8]) -> Result<Vec<u8>> {
    let malformed =
        || Error::with_context(CurlCode::UrlMalformat, "path contains control characters");
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        let decoded = if b == b'%' {
            // Need two hex digits.
            if i + 2 >= input.len() {
                return Err(malformed());
            }
            let hi = (input[i + 1] as char).to_digit(16).ok_or_else(malformed)?;
            let lo = (input[i + 2] as char).to_digit(16).ok_or_else(malformed)?;
            i += 3;
            (hi * 16 + lo) as u8
        } else {
            i += 1;
            b
        };
        // REJECT_CTRL: control characters are not allowed in the decoded path.
        if decoded < 0x20 || decoded == 0x7f {
            return Err(malformed());
        }
        out.push(decoded);
    }
    Ok(out)
}

/// The result of scanning a URL path for the FTP `;type=<code>` suffix
/// (← the effect of `type_url_check`, `lib/ftp.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TypeUrl {
    /// Prefer ASCII transfers (`;type=a`), i.e. set `data->state.prefer_ascii`.
    pub prefer_ascii: bool,
    /// List-only mode (`;type=d`), i.e. set `data->state.list_only`.
    pub list_only: bool,
}

/// Strip and interpret an FTP `;type=<typecode>` URL suffix
/// (← `type_url_check`, `lib/ftp.c` L4226-4253).
///
/// If `path` ends with `;type=A`/`;type=D`/`;type=I` (case-insensitive on the
/// code), the suffix is removed from `path` and the corresponding preference is
/// returned: `A` → ASCII, `D` → directory/list-only, `I` (or anything else) →
/// binary. When there is no such suffix the path is left unchanged and a binary
/// (all-`false`) result is returned.
#[must_use]
pub fn type_url_check(path: &mut String) -> TypeUrl {
    let mut out = TypeUrl::default();
    let bytes = path.as_bytes();
    let len = bytes.len();
    // curl: `(len >= 7) && !memcmp(&path[len-7], ";type=", 6)` — the suffix is
    // ";type=" (6 bytes) plus one code byte.
    if len >= 7 && &bytes[len - 7..len - 1] == b";type=" {
        let command = bytes[len - 1].to_ascii_uppercase();
        path.truncate(len - 7); // cut the suffix off
        match command {
            b'A' => out.prefer_ascii = true,
            b'D' => out.list_only = true,
            // 'I' and any other code: binary (ASCII off).
            _ => {}
        }
    }
    out
}

/// Parse the six comma-separated `0..=255` numbers of a classic `227` PASV
/// reply (← `match_pasv_6nums`, `lib/ftp.c`). Returns the array on success.
fn match_pasv_6nums(p: &[u8]) -> Option<[u32; 6]> {
    let mut array = [0u32; 6];
    let mut idx = 0usize; // position within `p`
    for (i, slot) in array.iter_mut().enumerate() {
        if i > 0 {
            // Each number after the first must be comma-separated.
            if idx >= p.len() || p[idx] != b',' {
                return None;
            }
            idx += 1;
        }
        // Parse a decimal number, capped at 0xff (curl's max).
        let start = idx;
        let mut num: u32 = 0;
        while idx < p.len() && p[idx].is_ascii_digit() {
            num = num * 10 + u32::from(p[idx] - b'0');
            if num > 0xff {
                return None;
            }
            idx += 1;
        }
        if idx == start {
            return None; // no digits
        }
        *slot = num;
    }
    Some(array)
}

/// Whether `line`'s first three bytes are ASCII digits (← the `STATUSCODE`
/// macro, `lib/ftp.c`): `ISDIGIT(line[0]) && ISDIGIT(line[1]) && ISDIGIT(line[2])`.
fn is_statuscode(line: &[u8]) -> bool {
    line.len() >= 3
        && line[0].is_ascii_digit()
        && line[1].is_ascii_digit()
        && line[2].is_ascii_digit()
}

// ===========================================================================
// PingPongProtocol — the control-channel command/response engine
// (← `ftp_endofresp` + `ftp_pp_statemachine`, `lib/ftp.c`).
// ===========================================================================

impl PingPongProtocol for FtpConn {
    /// Decide whether `line` completes an FTP response and, if so, parse its
    /// numeric status into `code` (← `ftp_endofresp`, `lib/ftp.c` L575-588).
    ///
    /// An FTP reply is either a single line `NNN text` or a multi-line block
    /// whose first line is `NNN-text` and whose terminator repeats the *same*
    /// three digits followed by a **space** (`NNN text`). curl's rule is
    /// therefore purely local to the latest line: a line is the last one iff it
    /// is at least four bytes, its first three bytes are digits
    /// (`STATUSCODE`), and its fourth byte is a space (`LASTLINE`). Intermediate
    /// `NNN-` (or free-text continuation) lines return `false`, so the engine
    /// keeps scanning. This reproduces the exact byte test, including the
    /// "continuation until a matching `NNN<space>`" behavior.
    fn endofresp(&mut self, line: &[u8], code: &mut i32) -> bool {
        // `(len > 3) && LASTLINE(line) && !curlx_str_number(&line, &status, 999)`
        if line.len() > 3 && is_statuscode(line) && line[3] == b' ' {
            // The three status digits, value 0..=999 (curl's `str_number` cap).
            let status = i32::from(line[0] - b'0') * 100
                + i32::from(line[1] - b'0') * 10
                + i32::from(line[2] - b'0');
            *code = status;
            return true;
        }
        false
    }

    /// Advance the FTP control-channel state machine by one server response
    /// (← `ftp_pp_statemachine`, `lib/ftp.c` L3047-3365).
    ///
    /// Mirrors curl's entry sequence exactly: if a command is still queued,
    /// flush it and return; otherwise read the next response
    /// ([`PingPong::readresp`]). A `421` ("service not available, closing
    /// control connection") at any point forces [`FtpState::Stop`] and
    /// [`CurlCode::OperationTimedout`] (← `ftp_readresp`). When no complete
    /// response has arrived yet (`ftpcode == 0`) it returns `Ok(())` so the pump
    /// polls again; once a full response is in hand it is dispatched through the
    /// big `switch(ftpc->state)` in [`FtpConn::dispatch`].
    ///
    /// The `pp` engine arrives as a borrow **separate** from `self` — the driver
    /// ([`FtpConn::statemach`]) [`mem::take`]s [`FtpConn::pp`] out first — so
    /// `self.pp` must never be touched here; all control-channel I/O goes
    /// through the `pp` parameter, exactly as curl passes `pp` and `data`/`conn`
    /// as distinct arguments.
    fn statemachine<'a>(
        &'a mut self,
        pp: &'a mut PingPong,
        conn: &'a mut Connection,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            // `if(pp->sendleft) return Curl_pp_flushsend(data, pp);`
            if pp.needs_flush() {
                return pp.flushsend(conn, Instant::now()).await;
            }

            // `ftp_readresp(data, ftpc, FIRSTSOCKET, pp, &ftpcode, &nread)`.
            let mut ftpcode = 0i32;
            let mut nread = 0usize;
            pp.readresp(self, conn, FIRSTSOCKET, &mut ftpcode, &mut nread)
                .await?;

            // `if(code == 421) { ... FTP_STOP; return CURLE_OPERATION_TIMEDOUT; }`
            if ftpcode == 421 {
                self.set_state(FtpState::Stop);
                return Err(Error::with_context(
                    CurlCode::OperationTimedout,
                    "We got a 421 - timeout",
                ));
            }

            // `if(result || !ftpcode) return result;`
            if ftpcode == 0 {
                return Ok(());
            }

            // "we have now received a full FTP server response" → switch(state).
            self.dispatch(pp, conn, ftpcode).await
        })
    }
}

/// Parse the entry-path out of a `257` `PWD`/`MKD` reply
/// (← the double-quote scan in `ftp_pwd_resp`, `lib/ftp.c` L2909-2950).
///
/// The reply looks like `257<sp>[junk]"<directory>"<sp><commentary>`; the
/// directory name may embed a literal `"` encoded as `""` ("quote-doubling",
/// RFC 959). Returns the decoded directory, or `None` if no properly
/// closed, non-empty quoted string is present (curl's `entry_extracted`
/// remaining false).
fn parse_pwd_entrypath(line: &[u8]) -> Option<String> {
    // `ptr = recvbuf + 4` — skip the three status digits plus one separator.
    if line.len() < 4 {
        return None;
    }
    let mut i = 4;
    // "scan for the first double-quote for non-standard responses".
    while i < line.len() && line[i] != b'\n' && line[i] != b'"' {
        i += 1;
    }
    if i >= line.len() || line[i] != b'"' {
        return None;
    }
    i += 1; // step past the opening quote
    let mut out = Vec::new();
    let mut closed = false;
    while i < line.len() {
        if line[i] == b'"' {
            if i + 1 < line.len() && line[i + 1] == b'"' {
                // "quote-doubling": a literal double-quote in the name.
                out.push(b'"');
                i += 2;
            } else {
                // end of path
                closed = true;
                break;
            }
        } else {
            out.push(line[i]);
            i += 1;
        }
    }
    // `if(curlx_dyn_len(&out)) entry_extracted = TRUE;` on the closing quote.
    if closed && !out.is_empty() {
        Some(String::from_utf8_lossy(&out).into_owned())
    } else {
        None
    }
}

// ===========================================================================
// PHASE 4a — greeting & login control-channel handlers
// (← `ftp_wait_resp`, `ftp_state_user`, `ftp_state_user_resp`,
//    `ftp_state_acct_resp`, `ftp_state_loggedin`, `ftp_state_pwd`,
//    `ftp_pwd_resp`, and the `FTP_AUTH` switch arm, `lib/ftp.c`).
// ===========================================================================

impl FtpConn {
    /// `FTP_WAIT220`: the server greeting (← `ftp_wait_resp`, L3000-3045).
    ///
    /// A `230` means the server logged us in before we sent anything; unless
    /// FTPS is requested it is treated exactly like a `220`. Any other
    /// non-`220` greeting is [`CurlCode::WeirdServerReply`]. When FTPS
    /// (`use_ssl`) is requested and the control channel is not yet TLS, an
    /// `AUTH SSL`/`AUTH TLS` sequence is started (order set by
    /// [`FtpParams::ftpsslauth`]); otherwise login proceeds with `USER`.
    fn wait_resp(&mut self, pp: &mut PingPong, conn: &mut Connection, ftpcode: i32) -> Result<()> {
        if ftpcode == 230 {
            // Already logged in — accept as 220 unless TLS must come first.
            if self.use_ssl <= usessl::TRY || conn.bits.ftp_use_control_ssl {
                return self.user_resp(pp, conn, ftpcode);
            }
        } else if ftpcode != 220 {
            return Err(Error::with_context(
                CurlCode::WeirdServerReply,
                format!("Got a {ftpcode:03} ftp-server response when 220 was expected"),
            ));
        }

        if self.use_ssl != usessl::NONE && !conn.bits.ftp_use_control_ssl {
            // FTPS requested but control channel is still plaintext: negotiate.
            self.count3 = 0;
            match self.params.ftpsslauth {
                ftpsslauth::DEFAULT | ftpsslauth::SSL => {
                    self.count2 = 1; // add one to get next
                    self.count1 = 0;
                }
                ftpsslauth::TLS => {
                    self.count2 = -1; // subtract one to get next
                    self.count1 = 1;
                }
                other => {
                    return Err(Error::with_context(
                        CurlCode::UnknownOption,
                        format!("unsupported parameter to CURLOPT_FTPSSLAUTH: {other}"),
                    ));
                }
            }
            pp_sendf!(pp, "AUTH {}", FTPAUTH[self.count1 as usize])?;
            self.set_state(FtpState::Auth);
            Ok(())
        } else {
            self.state_user(pp, conn)
        }
    }

    /// `FTP_AUTH` response (← the `case FTP_AUTH` arm, L3073-3118).
    ///
    /// On `234`/`334` the server accepted the mechanism: the control-channel
    /// TLS filter is installed and connected (blocking, mirroring curl), data
    /// protection is reset to clear-text, control protection is marked on, and
    /// login continues. Otherwise the next mechanism is tried
    /// (`count1 += count2`), and once exhausted the failure is fatal
    /// ([`CurlCode::UseSslFailed`]) unless `use_ssl <= TRY`.
    async fn auth_resp(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        ftpcode: i32,
    ) -> Result<()> {
        // "Forbid pipelining in response." (← `if(pp->overflow)`): reject any
        // bytes received past this AUTH response.
        if pp.moredata() {
            return Err(Error::from(CurlCode::WeirdServerReply));
        }

        if ftpcode == 234 || ftpcode == 334 {
            // Bring up TLS on the control channel (blocking, as in curl).
            //
            // ← `Curl_ssl_cfilter_add(data, conn, FIRSTSOCKET)`: splice a TLS
            //   filter onto the head of the (already-connected, plaintext)
            //   control chain, then drive the blocking connect below so the
            //   AUTH TLS handshake actually runs. Setting `ftp_use_control_ssl`
            //   alone would leave the channel in the clear — the filter is what
            //   performs the upgrade. Guarded on `is_ssl` so an implicit-FTPS
            //   chain that already carries TLS is not double-wrapped.
            if !conn.is_ssl(FIRSTSOCKET) {
                crate::conn::connect::ssl_cfilter_add(conn, FIRSTSOCKET)?;
            }
            match conn.connect(FIRSTSOCKET, true).await {
                Ok(_) => {
                    conn.bits.ftp_use_data_ssl = false; // clear-text data
                    conn.bits.ftp_use_control_ssl = true; // SSL on control
                    self.state_user(pp, conn)
                }
                Err(_) => Err(Error::from(CurlCode::UseSslFailed)),
            }
        } else if self.count3 < 1 {
            self.count3 += 1;
            self.count1 += self.count2; // get next attempt
            pp_sendf!(pp, "AUTH {}", FTPAUTH[self.count1 as usize])?;
            Ok(()) // remain in this same state
        } else if self.use_ssl > usessl::TRY {
            // CURLUSESSL_CONTROL or CURLUSESSL_ALL is set: hard failure.
            Err(Error::from(CurlCode::UseSslFailed))
        } else {
            // Ignore the failure and continue in the clear.
            self.state_user(pp, conn)
        }
    }

    /// Send `USER` (← `ftp_state_user`, L640-655).
    fn state_user(&mut self, pp: &mut PingPong, conn: &mut Connection) -> Result<()> {
        let user = conn.user.clone().unwrap_or_default();
        pp_sendf!(pp, "USER {}", user)?;
        self.ftp_trying_alternative = false;
        self.set_state(FtpState::User);
        Ok(())
    }

    /// `FTP_USER`/`FTP_PASS` response (← `ftp_state_user_resp`, L2831-2884).
    fn user_resp(&mut self, pp: &mut PingPong, conn: &mut Connection, ftpcode: i32) -> Result<()> {
        if ftpcode == 331 && self.state == FtpState::User {
            // 331 Password required — send it.
            let passwd = conn.passwd.clone().unwrap_or_default();
            pp_sendf!(pp, "PASS {}", passwd)?;
            self.set_state(FtpState::Pass);
            Ok(())
        } else if ftpcode / 100 == 2 {
            // 230 logged in.
            self.state_loggedin(pp, conn)
        } else if ftpcode == 332 {
            if let Some(account) = self.account.clone() {
                pp_sendf!(pp, "ACCT {}", account)?;
                self.set_state(FtpState::Acct);
                Ok(())
            } else {
                Err(Error::with_context(
                    CurlCode::LoginDenied,
                    "ACCT requested but none available",
                ))
            }
        } else if let Some(alt) = self.alternative_to_user.clone() {
            if !self.ftp_trying_alternative {
                // USER failed: try the supplied alternative command.
                pp_sendf!(pp, "{}", alt)?;
                self.ftp_trying_alternative = true;
                self.set_state(FtpState::User);
                return Ok(());
            }
            Err(Error::with_context(
                CurlCode::LoginDenied,
                format!("Access denied: {ftpcode:03}"),
            ))
        } else {
            Err(Error::with_context(
                CurlCode::LoginDenied,
                format!("Access denied: {ftpcode:03}"),
            ))
        }
    }

    /// `FTP_ACCT` response (← `ftp_state_acct_resp`, L2887-2900).
    fn acct_resp(&mut self, pp: &mut PingPong, conn: &mut Connection, ftpcode: i32) -> Result<()> {
        if ftpcode != 230 {
            Err(Error::with_context(
                CurlCode::FtpWeirdPassReply,
                format!("ACCT rejected by server: {ftpcode:03}"),
            ))
        } else {
            self.state_loggedin(pp, conn)
        }
    }

    /// Post-login step (← `ftp_state_loggedin`, L2800-2828).
    ///
    /// For FTPS with an encrypted control channel this issues `PBSZ 0` to enter
    /// the protection-buffer-size negotiation; otherwise it goes straight to
    /// `PWD` to learn the entry path.
    fn state_loggedin(&mut self, pp: &mut PingPong, conn: &mut Connection) -> Result<()> {
        if conn.bits.ftp_use_control_ssl {
            // "In case we are using SSL on the control connection first, then
            //  send PBSZ 0."
            pp_sendf!(pp, "PBSZ {}", 0)?;
            self.set_state(FtpState::Pbsz);
            Ok(())
        } else {
            self.state_pwd(pp)
        }
    }

    /// Send `PWD` (← `ftp_state_pwd`, L657-664).
    fn state_pwd(&mut self, pp: &mut PingPong) -> Result<()> {
        pp_sendf!(pp, "{}", "PWD")?;
        self.set_state(FtpState::Pwd);
        Ok(())
    }

    /// Dispatch a complete FTP server response through the `switch(ftpc->state)`
    /// (← the body of `ftp_pp_statemachine`, `lib/ftp.c` L3068-3362).
    ///
    /// Every arm reproduces the corresponding curl transition exactly; the
    /// inline arms (`PBSZ`, `PROT`, `CCC`, `SYST`, `NAMEFMT`, the quote group,
    /// `PRET`) match the C code that lives directly in the switch, while the
    /// larger handlers delegate to the `*_resp`/`state_*` methods.
    async fn dispatch(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        ftpcode: i32,
    ) -> Result<()> {
        let state = self.state;
        match state {
            FtpState::Wait220 => self.wait_resp(pp, conn, ftpcode),

            FtpState::Auth => self.auth_resp(pp, conn, ftpcode).await,

            FtpState::User | FtpState::Pass => self.user_resp(pp, conn, ftpcode),

            FtpState::Acct => self.acct_resp(pp, conn, ftpcode),

            FtpState::Pbsz => {
                // `PROT C|P` — clear or private data protection.
                let level = if self.use_ssl == usessl::CONTROL {
                    'C'
                } else {
                    'P'
                };
                pp_sendf!(pp, "PROT {}", level)?;
                self.set_state(FtpState::Prot);
                Ok(())
            }

            FtpState::Prot => {
                if ftpcode / 100 == 2 {
                    // Data-connection protection enabled (unless CONTROL-only).
                    conn.bits.ftp_use_data_ssl = self.use_ssl != usessl::CONTROL;
                } else if self.use_ssl > usessl::CONTROL {
                    // Server rejected 'P' and we require it.
                    return Err(Error::from(CurlCode::UseSslFailed));
                }
                if self.ccc != 0 {
                    // CCC — Clear Command Channel.
                    pp_sendf!(pp, "{}", "CCC")?;
                    self.set_state(FtpState::Ccc);
                    Ok(())
                } else {
                    self.state_pwd(pp)
                }
            }

            FtpState::Ccc => {
                // `if(ftpcode < 500)` curl tears down the control-channel TLS
                // filter with a (blocking) `Curl_ssl_cfilter_remove(FIRSTSOCKET,
                // send_shutdown)`. The `send_shutdown` argument is TRUE only for
                // an ACTIVE CCC level — we initiate the TLS close-notify — and
                // FALSE for PASSIVE, where we only receive the peer's. The
                // connection filter layer owns the actual filter removal; the
                // direction is computed here exactly as curl does (and consumed
                // by that teardown once wired), after which the control channel
                // is plaintext again and we learn the entry path.
                if ftpcode < 500 {
                    let _send_shutdown = self.ccc == CURLFTPSSL_CCC_ACTIVE;
                    conn.bits.ftp_use_control_ssl = false;
                }
                self.state_pwd(pp)
            }

            FtpState::Pwd => self.pwd_resp(pp, ftpcode),

            FtpState::Syst => {
                if ftpcode == 215 {
                    let os = parse_syst_os(pp.response_line());
                    if let Some(os) = os {
                        if os.eq_ignore_ascii_case("OS/400") {
                            // Force OS/400 name format 1.
                            pp_sendf!(pp, "{}", "SITE NAMEFMT 1")?;
                            self.server_os = Some(os);
                            self.set_state(FtpState::Namefmt);
                            return Ok(());
                        }
                        self.server_os = Some(os);
                    }
                }
                // Nothing special (or unidentified OS): CONNECT phase done.
                self.set_state(FtpState::Stop);
                Ok(())
            }

            FtpState::Namefmt => {
                if ftpcode == 250 {
                    // Name-format change successful: reload initial path.
                    return self.state_pwd(pp);
                }
                self.set_state(FtpState::Stop);
                Ok(())
            }

            FtpState::Quote
            | FtpState::Postquote
            | FtpState::RetrPrequote
            | FtpState::StorPrequote
            | FtpState::ListPrequote => {
                if ftpcode >= 400 && self.count2 == 0 {
                    // Failure response, and this command was not allowed to fail.
                    return Err(Error::with_context(
                        CurlCode::QuoteError,
                        format!("QUOT command failed with {ftpcode:03}"),
                    ));
                }
                self.state_quote(pp, conn, false, state)
            }

            FtpState::Cwd => self.cwd_resp(pp, conn, ftpcode),

            FtpState::Mkd => self.mkd_resp(pp, conn, ftpcode),

            FtpState::Mdtm => self.mdtm_resp(pp, conn, ftpcode),

            FtpState::Type
            | FtpState::ListType
            | FtpState::RetrType
            | FtpState::StorType
            | FtpState::RetrListType => self.type_resp(pp, conn, ftpcode, state),

            FtpState::Size | FtpState::RetrSize | FtpState::StorSize => {
                self.size_resp(pp, conn, ftpcode, state)
            }

            FtpState::Rest | FtpState::RetrRest => self.rest_resp(pp, conn, ftpcode, state),

            FtpState::Pret => {
                if ftpcode != 200 {
                    // The one standard OK code.
                    return Err(Error::with_context(
                        CurlCode::FtpPretFailed,
                        format!("PRET command not accepted: {ftpcode:03}"),
                    ));
                }
                self.state_use_pasv(pp, conn)
            }

            FtpState::Pasv => self.pasv_resp(pp, conn, ftpcode),

            FtpState::Port => self.port_resp(pp, conn, ftpcode),

            FtpState::List | FtpState::Retr => self.get_resp(pp, conn, ftpcode, state).await,

            FtpState::Stor => self.stor_resp(pp, conn, ftpcode).await,

            // FTP_QUIT and any unexpected state: internal error → STOP.
            _ => {
                self.set_state(FtpState::Stop);
                Ok(())
            }
        }
    }

    /// `FTP_PWD` response (← `ftp_pwd_resp`, L2902-2996).
    ///
    /// Parses the quoted entry path from a `257` reply into
    /// [`entrypath`](Self::entrypath). For a non-absolute path on a server
    /// whose OS is not yet known, a `SYST` probe is issued first (OS/400 name
    /// syntax quirk) and the state moves to `FTP_SYST`; otherwise the CONNECT
    /// phase is complete (`FTP_STOP`).
    fn pwd_resp(&mut self, pp: &mut PingPong, ftpcode: i32) -> Result<()> {
        if ftpcode == 257 {
            if let Some(dir) = parse_pwd_entrypath(pp.response_line()) {
                let needs_syst = self.server_os.is_none() && !dir.starts_with('/');
                if needs_syst {
                    pp_sendf!(pp, "{}", "SYST")?;
                }
                self.entrypath = Some(dir);
                if needs_syst {
                    self.set_state(FtpState::Syst);
                    return Ok(());
                }
            }
            // else: could not get the path — fall through, connect phase done.
        }
        self.set_state(FtpState::Stop); // done with CONNECT phase
        Ok(())
    }
}

/// Extract the server OS token from a `215` `SYST` reply
/// (← the `case FTP_SYST` parse, `lib/ftp.c` L3182-3216).
///
/// The reply is `215<sp><OS-name><sp><commentary>`; leading spaces after the
/// code are skipped and the first whitespace-delimited token is returned.
fn parse_syst_os(line: &[u8]) -> Option<String> {
    if line.len() < 4 {
        return None;
    }
    let mut i = 4; // skip "215" + separator
    while i < line.len() && line[i] == b' ' {
        i += 1;
    }
    let start = i;
    while i < line.len() && line[i] != b' ' && line[i] != b'\r' && line[i] != b'\n' && line[i] != 0
    {
        i += 1;
    }
    Some(String::from_utf8_lossy(&line[start..i]).into_owned())
}

/// Parse an FTP `MDTM` `213` timestamp `YYYYMMDDHHMMSS[.sss]`
/// (← `ftp_213_date` + `twodigit`, `lib/ftp.c` L2331-2378).
///
/// Requires at least 14 digits and validates the component ranges exactly as
/// curl does (`month <= 12`, `day <= 31`, `hour <= 23`, `minute <= 59`,
/// `second <= 60`). Returns `(year, month, day, hour, minute, second)`.
fn ftp_213_date(resp: &[u8]) -> Option<(i32, i32, i32, i32, i32, i32)> {
    // `if(strlen(resp) < 14) return FALSE;`
    if resp.len() < 14 || !resp[..14].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let d = |a: usize, b: usize| -> i32 {
        resp[a..b]
            .iter()
            .fold(0i32, |acc, &c| acc * 10 + i32::from(c - b'0'))
    };
    let year = d(0, 4);
    let month = d(4, 6);
    let day = d(6, 8);
    let hour = d(8, 10);
    let minute = d(10, 12);
    let second = d(12, 14);

    // "Check for valid ranges."
    if month > 12 || day > 31 || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((year, month, day, hour, minute, second))
}

/// Convert a UTC calendar date-time to a Unix timestamp (seconds since the
/// 1970 epoch) using Howard Hinnant's `days_from_civil` algorithm — a
/// dependency-free stand-in for curl's `Curl_getdate_capped` when reformatting
/// an `MDTM` reply into a comparable `time_t`.
fn civil_to_epoch(year: i32, month: i32, day: i32, hour: i32, minute: i32, second: i32) -> i64 {
    let y = i64::from(if month <= 2 { year - 1 } else { year });
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second)
}

// ===========================================================================
// PHASE 4b — directory traversal, MDTM, and TYPE handlers
// (← `ftp_state_cwd`, the `FTP_CWD`/`FTP_MKD` arms, `ftp_state_mdtm`,
//    `ftp_state_mdtm_resp`, `ftp_state_type`, `ftp_nb_type`,
//    `ftp_state_type_resp`, `lib/ftp.c`).
// ===========================================================================

impl FtpConn {
    /// Begin the CWD sequence after login (← `ftp_state_cwd`, L823-868).
    fn state_cwd(&mut self, pp: &mut PingPong, conn: &mut Connection) -> Result<()> {
        if self.cwddone {
            return self.state_mdtm(pp, conn);
        }
        self.count2 = 0; // count2 counts failed CWDs

        let abs_path = self.dirdepth > 0 && self.rawpath.starts_with('/');
        if conn.bits.reuse && self.entrypath.is_some() && !abs_path {
            // Reused connection: return to the login directory first.
            self.cwdcount = 0;
            let entry = self.entrypath.clone().unwrap_or_default();
            pp_sendf!(pp, "CWD {}", entry)?;
            self.set_state(FtpState::Cwd);
            Ok(())
        } else if self.dirdepth > 0 {
            self.cwdcount = 1;
            pp_sendf!(pp, "CWD {}", self.dirs[0])?;
            self.set_state(FtpState::Cwd);
            Ok(())
        } else {
            // No CWD necessary.
            self.state_mdtm(pp, conn)
        }
    }

    /// `FTP_CWD` response (← the `case FTP_CWD` arm, L3251-3291).
    fn cwd_resp(&mut self, pp: &mut PingPong, conn: &mut Connection, ftpcode: i32) -> Result<()> {
        if ftpcode / 100 != 2 {
            if self.params.create_missing_dirs != 0 && self.cwdcount > 0 && self.count2 == 0 {
                // Try creating the directory.
                self.count2 += 1; // prevent CWD-MKD loops
                self.count3 = if self.params.create_missing_dirs == 2 {
                    1
                } else {
                    0
                };
                let idx = self.cwdcount as usize - 1;
                pp_sendf!(pp, "MKD {}", self.dirs[idx])?;
                self.set_state(FtpState::Mkd);
                Ok(())
            } else {
                self.cwdfail = true; // do not remember this path
                Err(Error::with_context(
                    CurlCode::RemoteAccessDenied,
                    "Server denied you to change to the given directory",
                ))
            }
        } else {
            // Success.
            self.count2 = 0;
            if self.cwdcount >= self.dirdepth {
                self.state_mdtm(pp, conn)
            } else {
                self.cwdcount += 1;
                let idx = self.cwdcount as usize - 1;
                pp_sendf!(pp, "CWD {}", self.dirs[idx])?;
                Ok(())
            }
        }
    }

    /// `FTP_MKD` response (← the `case FTP_MKD` arm, L3293-3306).
    fn mkd_resp(&mut self, pp: &mut PingPong, _conn: &mut Connection, ftpcode: i32) -> Result<()> {
        // `if((ftpcode / 100 != 2) && !ftpc->count3--)`
        let allow = self.count3 > 0;
        self.count3 -= 1;
        if ftpcode / 100 != 2 && !allow {
            return Err(Error::with_context(
                CurlCode::RemoteAccessDenied,
                format!("Failed to MKD dir: {ftpcode:03}"),
            ));
        }
        self.set_state(FtpState::Cwd);
        let idx = self.cwdcount as usize - 1;
        pp_sendf!(pp, "CWD {}", self.dirs[idx])?;
        Ok(())
    }

    /// Send `MDTM` for the file's modification time, if requested
    /// (← `ftp_state_mdtm`, L1516-1536).
    fn state_mdtm(&mut self, pp: &mut PingPong, conn: &mut Connection) -> Result<()> {
        if (self.params.get_filetime || self.params.timecondition != timecond::NONE)
            && self.file.is_some()
        {
            let file = self.file.clone().unwrap_or_default();
            pp_sendf!(pp, "MDTM {}", file)?;
            self.set_state(FtpState::Mdtm);
            Ok(())
        } else {
            self.state_type(pp, conn)
        }
    }

    /// `FTP_MDTM` response (← `ftp_state_mdtm_resp`, L2406-2518).
    fn mdtm_resp(&mut self, pp: &mut PingPong, conn: &mut Connection, ftpcode: i32) -> Result<()> {
        match ftpcode {
            213 => {
                // `resp = recvbuf + 4`
                let line = pp.response_line();
                if line.len() > 4 {
                    if let Some((y, mo, d, h, mi, s)) = ftp_213_date(&line[4..]) {
                        self.filetime = civil_to_epoch(y, mo, d, h, mi, s);
                    }
                }
            }
            550 => { /* file does not exist or permission problem: continue */ }
            _ => { /* unsupported MDTM reply format */ }
        }

        // Time-condition evaluation.
        if self.params.timecondition != timecond::NONE
            && self.filetime > 0
            && self.params.timevalue > 0
        {
            let skip = match self.params.timecondition {
                timecond::IFUNMODSINCE => self.filetime > self.params.timevalue,
                // IFMODSINCE (and default).
                _ => self.filetime <= self.params.timevalue,
            };
            if skip {
                self.ftp.transfer = PpTransfer::None; // do not transfer data
                self.timecond = true;
                self.set_state(FtpState::Stop);
                return Ok(());
            }
        }

        self.state_type(pp, conn)
    }

    /// Decide whether a `TYPE`/`SIZE` probe is needed for a NOBODY request
    /// (← `ftp_state_type`, L1483-1512).
    fn state_type(&mut self, pp: &mut PingPong, conn: &mut Connection) -> Result<()> {
        if self.params.no_body && self.file.is_some() && self.need_type(self.params.prefer_ascii) {
            // Only file information wanted → INFO transfer, set TYPE then SIZE.
            self.ftp.transfer = PpTransfer::Info;
            let ascii = self.params.prefer_ascii;
            self.nb_type(pp, conn, ascii, FtpState::Type)
        } else {
            self.state_size(pp, conn)
        }
    }

    /// Send `TYPE A`/`TYPE I` only when the current transfer type differs
    /// (← `ftp_nb_type`, `lib/ftp.c`).
    fn nb_type(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        ascii: bool,
        newstate: FtpState,
    ) -> Result<()> {
        let want = if ascii { b'A' } else { b'I' };
        if self.transfertype == want {
            // Already in this type: fabricate the 200 and advance.
            self.set_state(newstate);
            return self.type_resp(pp, conn, 200, newstate);
        }
        pp_sendf!(pp, "TYPE {}", want as char)?;
        self.set_state(newstate);
        self.transfertype = want;
        Ok(())
    }

    /// `FTP_TYPE`/`FTP_*_TYPE` response (← `ftp_state_type_resp`, L2520-2551).
    ///
    /// A non-2xx reply is [`CurlCode::FtpCouldntSetType`]; a `2xx` other than
    /// `200` is accepted with a note. The `instate` selects the follow-on:
    /// `TYPE`→`SIZE`, `LIST_TYPE`→`LIST`, `RETR_TYPE`→retr-prequote,
    /// `STOR_TYPE`→stor-prequote, `RETR_LIST_TYPE`→list-prequote.
    fn type_resp(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        ftpcode: i32,
        instate: FtpState,
    ) -> Result<()> {
        if ftpcode / 100 != 2 {
            return Err(Error::with_context(
                CurlCode::FtpCouldntSetType,
                "Could not set desired mode",
            ));
        }
        // A 2xx other than 200 is tolerated.
        match instate {
            FtpState::Type => self.state_size(pp, conn),
            FtpState::ListType => self.state_list(pp, conn),
            FtpState::RetrType => self.state_quote(pp, conn, true, FtpState::RetrPrequote),
            FtpState::StorType => self.state_quote(pp, conn, true, FtpState::StorPrequote),
            FtpState::RetrListType => self.state_quote(pp, conn, true, FtpState::ListPrequote),
            _ => Ok(()),
        }
    }
}

/// The active-mode command preference order (← the C `ftpport` enum,
/// `lib/ftp.c` L870-874): try `EPRT` first, then `PORT`, then give up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FtpPort {
    /// `EPRT` — RFC 2428 extended `PORT`, works for IPv4 and IPv6.
    Eprt,
    /// `PORT` — the classic RFC 959 IPv4-only command.
    Port,
    /// `DONE` — sentinel: no command left to try.
    Done,
}

/// Scan an FTP `SIZE` `213` reply for the trailing decimal byte count
/// (← the digit back-scan in `ftp_state_size_resp`, `lib/ftp.c` L2564-2581).
///
/// Servers may prepend arbitrary text, so curl locates the terminating `\r`
/// and walks backwards over the trailing digit run, then parses it. Returns
/// `-1` when no number can be recovered ("size remains unknown").
fn parse_size_213(line: &[u8]) -> i64 {
    let len = line.len();
    if len <= 4 {
        return -1;
    }
    let start = 4usize; // `start = &buf[4]`
                        // `fdigit = memchr(start, '\r', len - 4)`
    let cr_rel = line[start..].iter().position(|&b| b == b'\r');
    let mut fdigit: usize = match cr_rel {
        Some(rel) => {
            let cr = start + rel;
            if cr == 0 {
                return -1;
            }
            let mut fd = cr - 1; // `fdigit--`
            if line[fd] == b'\n' {
                if fd == 0 {
                    return -1;
                }
                fd -= 1; // `if(*fdigit == '\n') fdigit--`
            }
            // `while(ISDIGIT(fdigit[-1]) && (fdigit > start)) fdigit--`
            while fd > start && line[fd - 1].is_ascii_digit() {
                fd -= 1;
            }
            fd
        }
        None => start,
    };
    // `curlx_str_number(&fdigit, &filesize, CURL_OFF_T_MAX)` — parse the run.
    let mut val: i64 = 0;
    let mut any = false;
    while fdigit < len && line[fdigit].is_ascii_digit() {
        val = val
            .saturating_mul(10)
            .saturating_add(i64::from(line[fdigit] - b'0'));
        fdigit += 1;
        any = true;
    }
    if any {
        val
    } else {
        -1
    }
}

// ===========================================================================
// PHASE 4c — SIZE / REST / RETR / STOR / LIST / QUOTE and transfer prep
// (← `ftp_state_size`, `ftp_state_size_resp`, `ftp_state_rest`,
//    `ftp_state_rest_resp`, `ftp_state_retr`, `ftp_state_ul_setup`,
//    `ftp_state_list`, `ftp_state_prepare_transfer`, `ftp_state_quote`,
//    `lib/ftp.c`).
// ===========================================================================

impl FtpConn {
    /// Send `SIZE` for a NOBODY/INFO request, else fall through to `REST`
    /// (← `ftp_state_size`, L1381-1399).
    fn state_size(&mut self, pp: &mut PingPong, conn: &mut Connection) -> Result<()> {
        if self.ftp.transfer == PpTransfer::Info && self.file.is_some() {
            let file = self.file.clone().unwrap_or_default();
            pp_sendf!(pp, "SIZE {}", file)?;
            self.set_state(FtpState::Size);
            Ok(())
        } else {
            self.state_rest(pp, conn)
        }
    }

    /// `FTP_SIZE`/`FTP_RETR_SIZE`/`FTP_STOR_SIZE` response
    /// (← `ftp_state_size_resp`, L2553-2615).
    fn size_resp(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        ftpcode: i32,
        instate: FtpState,
    ) -> Result<()> {
        let mut filesize: i64 = -1;
        if ftpcode == 213 {
            filesize = parse_size_213(pp.response_line());
        } else if ftpcode == 550 && instate != FtpState::StorSize {
            // Allow a SIZE failure for (resumed) uploads while probing.
            return Err(Error::with_context(
                CurlCode::RemoteFileNotFound,
                "The file does not exist",
            ));
        }

        match instate {
            FtpState::Size => {
                // (Content-Length header + progress download size are emitted
                //  by the transfer/client-write layer.)
                self.state_rest(pp, conn)
            }
            FtpState::RetrSize => self.state_retr(pp, conn, filesize),
            FtpState::StorSize => {
                self.params.resume_from = filesize;
                self.state_ul_setup(pp, conn, true)
            }
            _ => Ok(()),
        }
    }

    /// Probe `REST 0` for a HEAD-like request, else prepare the transfer
    /// (← `ftp_state_rest`, L1360-1379).
    fn state_rest(&mut self, pp: &mut PingPong, conn: &mut Connection) -> Result<()> {
        if self.ftp.transfer != PpTransfer::Body && self.file.is_some() {
            pp_sendf!(pp, "REST {}", 0)?;
            self.set_state(FtpState::Rest);
            Ok(())
        } else {
            self.state_prepare_transfer(pp, conn)
        }
    }

    /// `FTP_REST`/`FTP_RETR_REST` response (← `ftp_state_rest_resp`, L2617-2651).
    fn rest_resp(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        ftpcode: i32,
        instate: FtpState,
    ) -> Result<()> {
        match instate {
            FtpState::RetrRest => {
                if ftpcode != 350 {
                    Err(Error::with_context(
                        CurlCode::FtpCouldntUseRest,
                        "Could not use REST",
                    ))
                } else {
                    let file = self.file.clone().unwrap_or_default();
                    pp_sendf!(pp, "RETR {}", file)?;
                    self.set_state(FtpState::Retr);
                    Ok(())
                }
            }
            // FTP_REST (and default): a 350 means range is supported.
            _ => {
                // (The `Accept-ranges: bytes` header is emitted by the
                //  client-write layer on a 350.)
                let _ = ftpcode;
                self.state_prepare_transfer(pp, conn)
            }
        }
    }

    /// Issue `RETR` (with optional `REST` resume) for a download
    /// (← `ftp_state_retr`, L1638-1719).
    fn state_retr(
        &mut self,
        pp: &mut PingPong,
        _conn: &mut Connection,
        filesize: i64,
    ) -> Result<()> {
        if self.params.max_filesize != 0 && filesize > self.params.max_filesize {
            return Err(Error::with_context(
                CurlCode::FilesizeExceeded,
                "Maximum file size exceeded",
            ));
        }
        self.ftp.downloadsize = filesize;

        if self.params.resume_from != 0 {
            if filesize == -1 {
                // Server does not support SIZE — proceed and let the server
                // close the connection when done.
            } else if self.params.resume_from < 0 {
                // Download the last abs(resume_from) bytes.
                if filesize < -self.params.resume_from {
                    return Err(Error::with_context(
                        CurlCode::BadDownloadResume,
                        "Offset was beyond file size",
                    ));
                }
                self.ftp.downloadsize = -self.params.resume_from;
                self.params.resume_from = filesize - self.ftp.downloadsize;
            } else {
                if filesize < self.params.resume_from {
                    return Err(Error::with_context(
                        CurlCode::BadDownloadResume,
                        "Offset was beyond file size",
                    ));
                }
                self.ftp.downloadsize = filesize - self.params.resume_from;
            }

            if self.ftp.downloadsize == 0 {
                // No data to transfer — already completely downloaded.
                self.ftp.transfer = PpTransfer::None;
                self.set_state(FtpState::Stop);
                return Ok(());
            }

            pp_sendf!(pp, "REST {}", self.params.resume_from)?;
            self.set_state(FtpState::RetrRest);
            Ok(())
        } else {
            let file = self.file.clone().unwrap_or_default();
            pp_sendf!(pp, "RETR {}", file)?;
            self.set_state(FtpState::Retr);
            Ok(())
        }
    }

    /// Set up an upload: `STOR`/`APPE`, with `SIZE`-based resume probing
    /// (← `ftp_state_ul_setup`, L1539-1636).
    ///
    /// The actual input-stream seek/skip for a resumed upload is performed by
    /// the data-transfer layer (which owns the read source); here we reproduce
    /// the command decisions: probe `SIZE` when the resume offset is unknown,
    /// switch to `APPE`, decrement the remaining upload size, and short-circuit
    /// when the file is already fully uploaded.
    fn state_ul_setup(
        &mut self,
        pp: &mut PingPong,
        _conn: &mut Connection,
        sizechecked: bool,
    ) -> Result<()> {
        let mut append = self.params.remote_append;
        let resume = self.params.resume_from;

        if (resume != 0 && !sizechecked) || (resume > 0 && sizechecked) {
            if resume < 0 {
                // Unknown offset: ask the server for the current size first.
                let file = self.file.clone().unwrap_or_default();
                pp_sendf!(pp, "SIZE {}", file)?;
                self.set_state(FtpState::StorSize);
                return Ok(());
            }
            append = true;
            if self.params.infilesize > 0 {
                self.params.infilesize -= resume;
                if self.params.infilesize <= 0 {
                    // Already completely uploaded — nothing to transfer.
                    self.ftp.transfer = PpTransfer::None;
                    self.set_state(FtpState::Stop);
                    return Ok(());
                }
            }
        }

        let file = self.file.clone().unwrap_or_default();
        if append {
            pp_sendf!(pp, "APPE {}", file)?;
        } else {
            pp_sendf!(pp, "STOR {}", file)?;
        }
        self.set_state(FtpState::Stor);
        Ok(())
    }

    /// Issue `LIST`/`NLST`/custom (← `ftp_state_list`, L1401-1457).
    ///
    /// For `FTPFILE_NOCWD` the directory portion of the raw path is passed as
    /// an argument; otherwise the command is sent bare (the CWD sequence has
    /// already positioned the server).
    fn state_list(&mut self, pp: &mut PingPong, _conn: &mut Connection) -> Result<()> {
        let mut arg: Option<String> = None;
        if self.params.filemethod == CurlFtpFile::Nocwd && !self.ftp.path.is_empty() {
            if let Some(pos) = self.rawpath.rfind('/') {
                // Keep the directory part; a leading "/" stays as "/".
                let n = if pos == 0 { 1 } else { pos };
                arg = Some(self.rawpath[..n].to_string());
            }
        }
        let base = if let Some(cmd) = &self.params.customrequest {
            cmd.clone()
        } else if self.params.list_only {
            "NLST".to_string()
        } else {
            "LIST".to_string()
        };
        match arg {
            Some(a) => pp_sendf!(pp, "{} {}", base, a)?,
            None => pp_sendf!(pp, "{}", base)?,
        }
        self.set_state(FtpState::List);
        Ok(())
    }

    /// Start the data phase with `PORT`/`PASV`/`PRET` (←
    /// `ftp_state_prepare_transfer`, L1319-1358).
    fn state_prepare_transfer(&mut self, pp: &mut PingPong, conn: &mut Connection) -> Result<()> {
        if self.ftp.transfer != PpTransfer::Body {
            // A non-body request may still run pre-quote jobs.
            self.set_state(FtpState::RetrPrequote);
            self.state_quote(pp, conn, true, FtpState::RetrPrequote)
        } else if self.params.use_port {
            self.state_use_port(pp, conn, FtpPort::Eprt)
        } else if self.params.use_pret {
            // PRET prepares distributed-FTP (drftpd) servers for the PASV.
            if self.file.is_none() {
                let sub = if let Some(cmd) = &self.params.customrequest {
                    cmd.clone()
                } else if self.params.list_only {
                    "NLST".to_string()
                } else {
                    "LIST".to_string()
                };
                pp_sendf!(pp, "PRET {}", sub)?;
            } else if self.params.upload {
                let file = self.file.clone().unwrap_or_default();
                pp_sendf!(pp, "PRET STOR {}", file)?;
            } else {
                let file = self.file.clone().unwrap_or_default();
                pp_sendf!(pp, "PRET RETR {}", file)?;
            }
            self.set_state(FtpState::Pret);
            Ok(())
        } else {
            self.state_use_pasv(pp, conn)
        }
    }

    /// Iterate the QUOTE/PREQUOTE/POSTQUOTE command lists (← `ftp_state_quote`,
    /// L1721-1836).
    ///
    /// `count1` walks the selected list; `count2` records whether the current
    /// command (prefixed `*`) is allowed to fail. When the list is exhausted the
    /// `instate` decides the continuation: `QUOTE`→CWD, `RETR_PREQUOTE`→size or
    /// retr, `STOR_PREQUOTE`→upload setup, `POSTQUOTE`→done, `LIST_PREQUOTE`→
    /// `LIST` (after switching to `FTP_LIST_TYPE`).
    fn state_quote(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        init: bool,
        instate: FtpState,
    ) -> Result<()> {
        if init {
            self.count1 = 0;
        } else {
            self.count1 += 1;
        }
        let idx = self.count1 as usize;

        // Fetch the count1'th command from the relevant list (cloned to avoid
        // holding a borrow of `self.params` across the mutable sends below).
        let cmd_opt = match instate {
            FtpState::RetrPrequote | FtpState::StorPrequote | FtpState::ListPrequote => {
                self.params.prequote.get(idx).cloned()
            }
            FtpState::Postquote => self.params.postquote.get(idx).cloned(),
            // FTP_QUOTE (and default).
            _ => self.params.quote.get(idx).cloned(),
        };

        let mut quote = false;
        if let Some(mut cmd) = cmd_opt {
            if cmd.starts_with('*') {
                cmd.remove(0);
                self.count2 = 1; // allowed to fail
            } else {
                self.count2 = 0; // failure cancels the operation
            }
            pp_sendf!(pp, "{}", cmd)?;
            self.set_state(instate);
            quote = true;
        }

        if quote {
            return Ok(());
        }

        // No more quotes to send — continue with the protocol flow.
        match instate {
            FtpState::RetrPrequote => {
                if self.ftp.transfer != PpTransfer::Body {
                    self.set_state(FtpState::Stop);
                    Ok(())
                } else if self.known_filesize != -1 {
                    let ks = self.known_filesize;
                    self.state_retr(pp, conn, ks)
                } else if self.params.ignorecl || self.params.prefer_ascii {
                    // Unknown size download (growing files / ASCII mode).
                    let file = self.file.clone().unwrap_or_default();
                    pp_sendf!(pp, "RETR {}", file)?;
                    self.set_state(FtpState::Retr);
                    Ok(())
                } else {
                    let file = self.file.clone().unwrap_or_default();
                    pp_sendf!(pp, "SIZE {}", file)?;
                    self.set_state(FtpState::RetrSize);
                    Ok(())
                }
            }
            FtpState::StorPrequote => self.state_ul_setup(pp, conn, false),
            FtpState::Postquote => Ok(()),
            FtpState::ListPrequote => {
                self.set_state(FtpState::ListType);
                self.state_list(pp, conn)
            }
            // FTP_QUOTE (and default).
            _ => self.state_cwd(pp, conn),
        }
    }
}

/// Parse a positive EPSV `229` reply `Entering Extended Passive Mode (|||port|)`
/// (← the EPSV branch of `ftp_state_pasv_resp`, `lib/ftp.c` L1929-1957).
///
/// Locates the `(`, reads the repeated separator (`|||`), then the decimal
/// port (capped at `0xffff`) terminated by the same separator. Returns the
/// port, or `None` for a malformed reply.
fn parse_epsv_229(s: &[u8]) -> Option<u16> {
    // `ptr = strchr(str, '(')`
    let lp = s.iter().position(|&b| b == b'(')?;
    let p = &s[lp + 1..];
    // Need at least sep,sep,sep,digit.
    if p.len() < 4 {
        return None;
    }
    let sep = p[0];
    // `if((ptr[1] == sep) && (ptr[2] == sep) && ISDIGIT(ptr[3]))`
    if p[1] != sep || p[2] != sep || !p[3].is_ascii_digit() {
        return None;
    }
    // `curlx_str_number(&p, &num, 0xffff)` then `*p != sep` check.
    let mut val: u32 = 0;
    let mut i = 3;
    let mut any = false;
    while i < p.len() && p[i].is_ascii_digit() {
        val = val * 10 + u32::from(p[i] - b'0');
        if val > 0xffff {
            return None;
        }
        i += 1;
        any = true;
    }
    if !any || i >= p.len() || p[i] != sep {
        return None;
    }
    Some(val as u16)
}

/// Scan a `227` PASV reply for the first `a,b,c,d,p1,p2` sextet anywhere in the
/// text (← the `while(*str) { if(match_pasv_6nums(...)) break; str++; }` scan in
/// `ftp_state_pasv_resp`, `lib/ftp.c` L1972-1976).
fn scan_pasv_227(s: &[u8]) -> Option<[u32; 6]> {
    for i in 0..s.len() {
        if let Some(ip) = match_pasv_6nums(&s[i..]) {
            return Some(ip);
        }
    }
    None
}

/// Scan a `150`/`125` reply for a `"<n> bytes"` size token
/// (← the size-in-reply parse in `ftp_state_get_resp`, `lib/ftp.c` L2735-2749).
fn parse_get_size(line: &[u8]) -> Option<i64> {
    // `if(len >= 7)` — "1 bytes" is the shortest match.
    if line.len() < 7 {
        return None;
    }
    for i in 0..=line.len() - 7 {
        let c = &line[i..];
        // `curlx_str_number(&c, &what, MAX)`
        let mut val: i64 = 0;
        let mut j = 0;
        while j < c.len() && c[j].is_ascii_digit() {
            val = val
                .saturating_mul(10)
                .saturating_add(i64::from(c[j] - b'0'));
            j += 1;
        }
        if j == 0 {
            continue; // no number here
        }
        // `!curlx_str_single(&c, ' ')` — exactly one space, then "bytes".
        if j < c.len() && c[j] == b' ' && c[j + 1..].starts_with(b"bytes") {
            return Some(val);
        }
    }
    None
}

// ===========================================================================
// PHASE 4d — data-channel setup (PASV/EPSV, PORT/EPRT) and RETR/STOR/LIST
// responses (← `ftp_state_use_pasv`, `ftp_state_pasv_resp`, `ftp_epsv_disable`,
//    `ftp_control_addr_dup`, `ftp_state_use_port`, `ftp_state_port_resp`,
//    `ftp_state_get_resp`, `ftp_state_stor_resp`, `lib/ftp.c`).
// ===========================================================================

impl FtpConn {
    /// The control-connection host reused for the data connection
    /// (← `ftp_control_addr_dup`, L1871-1896).
    ///
    /// curl returns the resolved remote IP of the control channel; this port
    /// reuses the connection's host name (the connection layer resolves it for
    /// the data channel). Empty means the peer address is unavailable
    /// ([`CurlCode::FtpCantGetHost`]).
    fn control_addr(&self, conn: &Connection) -> Result<String> {
        let name = conn.host.name.clone();
        if name.is_empty() {
            Err(Error::with_context(
                CurlCode::FtpCantGetHost,
                "unable to get peername of DATA connection",
            ))
        } else {
            Ok(name)
        }
    }

    /// Send `EPSV`/`PASV` for passive mode (← `ftp_state_use_pasv`, L1272-1310).
    fn state_use_pasv(&mut self, pp: &mut PingPong, conn: &mut Connection) -> Result<()> {
        // "We cannot disable EPSV when doing IPv6": force EPSV on for IPv6.
        if !conn.bits.ftp_use_epsv && conn.bits.ipv6 {
            conn.bits.ftp_use_epsv = true;
        }
        let modeoff = if conn.bits.ftp_use_epsv { 0 } else { 1 };
        pp_sendf!(pp, "{}", PASV_MODE[modeoff])?;
        self.count1 = modeoff as i32;
        self.set_state(FtpState::Pasv);
        Ok(())
    }

    /// Fall back from `EPSV` to `PASV` after an EPSV failure
    /// (← `ftp_epsv_disable`, L1840-1869).
    ///
    /// With IPv6 there is no PASV fallback, so this is a hard
    /// [`CurlCode::WeirdServerReply`]; otherwise EPSV is disabled, the secondary
    /// socket is closed, and `PASV` is issued (staying in `FTP_PASV`).
    fn epsv_disable(&mut self, pp: &mut PingPong, conn: &mut Connection) -> Result<()> {
        if conn.bits.ipv6 {
            return Err(Error::with_context(
                CurlCode::WeirdServerReply,
                "Failed EPSV attempt, exiting",
            ));
        }
        conn.bits.ftp_use_epsv = false;
        conn.close(SECONDARYSOCKET);
        pp_sendf!(pp, "{}", "PASV")?;
        self.count1 += 1;
        self.set_state(FtpState::Pasv);
        Ok(())
    }

    /// `FTP_PASV` response (← `ftp_state_pasv_resp`, L1916-2106).
    ///
    /// Parses the negotiated data endpoint from a `229` (EPSV) or `227` (PASV)
    /// reply into [`Connection::secondaryhostname`]/[`Connection::secondary_port`]
    /// and flags [`ConnectBits::do_more`] so the data connection is established
    /// during the DO-MORE phase (`FTP_STOP`). A `count1 == 0` non-positive reply
    /// falls back to PASV via [`epsv_disable`](Self::epsv_disable).
    fn pasv_resp(&mut self, pp: &mut PingPong, conn: &mut Connection, ftpcode: i32) -> Result<()> {
        // `str = recvbuf + 4` — own the bytes so we may send commands below.
        let line = pp.response_line().to_vec();
        let s: &[u8] = if line.len() > 4 { &line[4..] } else { &[] };

        // Definite assignment: every path either assigns both or diverges.
        let newhost: String;
        let newport: u16;

        if self.count1 == 0 && ftpcode == 229 {
            match parse_epsv_229(s) {
                Some(port) => {
                    newport = port;
                    newhost = self.control_addr(conn)?;
                }
                None => {
                    return Err(Error::with_context(
                        CurlCode::FtpWeirdPasvReply,
                        "Weirdly formatted EPSV reply",
                    ));
                }
            }
        } else if self.count1 == 1 && ftpcode == 227 {
            match scan_pasv_227(s) {
                Some(ip) => {
                    if self.params.skip_ip {
                        // Reuse the control host instead of the advertised IP.
                        newhost = self.control_addr(conn)?;
                    } else {
                        newhost = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                    }
                    newport = (((ip[4] << 8) + ip[5]) & 0xffff) as u16;
                }
                None => {
                    return Err(Error::with_context(
                        CurlCode::FtpWeird227Format,
                        "Could not interpret the 227-response",
                    ));
                }
            }
        } else if self.count1 == 0 {
            // EPSV failed, move on to PASV.
            return self.epsv_disable(pp, conn);
        } else {
            return Err(Error::with_context(
                CurlCode::FtpWeirdPasvReply,
                format!("Bad PASV/EPSV response: {ftpcode:03}"),
            ));
        }

        // Direct connection: record the data endpoint; the connection layer
        // establishes SECONDARYSOCKET during DO-MORE (SSL mode is driven by
        // `conn.bits.ftp_use_data_ssl`, set during PROT negotiation).
        conn.secondaryhostname = Some(newhost);
        conn.secondary_port = newport;
        conn.bits.do_more = true;
        self.set_state(FtpState::Stop); // this phase is completed
        Ok(())
    }

    /// Send `EPRT`/`PORT` for active mode (← `ftp_state_use_port`, L876-1270).
    ///
    /// The socket bind/listen is owned by the connection layer, which publishes
    /// the local listen endpoint via
    /// [`Connection::secondaryhostname`]/[`Connection::secondary_port`]; this
    /// method reproduces curl's command selection (EPRT unless disabled or IPv4
    /// with EPRT off; PORT is IPv4-only) and the exact `EPRT |af|host|port|` /
    /// `PORT h,h,h,h,p1,p2` wire formats.
    fn state_use_port(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        fcmd: FtpPort,
    ) -> Result<()> {
        // "We cannot disable EPRT when doing IPv6": force EPRT on for IPv6.
        if !conn.bits.ftp_use_eprt && conn.bits.ipv6 {
            conn.bits.ftp_use_eprt = true;
        }
        let is_ipv6 = conn.bits.ipv6;
        let port = conn.secondary_port;
        let host = match conn.secondaryhostname.clone() {
            Some(h) if !h.is_empty() && port != 0 => h,
            _ => {
                // No bound data listener published: cannot set up active mode.
                self.set_state(FtpState::Stop);
                return Err(Error::with_context(
                    CurlCode::FtpPortFailed,
                    "Failed to set up the active data listen socket",
                ));
            }
        };

        let mut cmd = fcmd;
        loop {
            match cmd {
                FtpPort::Done => {
                    self.set_state(FtpState::Stop);
                    return Err(Error::with_context(
                        CurlCode::FtpPortFailed,
                        "Failed to do PORT",
                    ));
                }
                FtpPort::Eprt => {
                    if !conn.bits.ftp_use_eprt {
                        cmd = FtpPort::Port; // disabled: go to next
                        continue;
                    }
                    // `EPRT |1|132.235.1.2|6275|` / `EPRT |2|1080::.:417A|5282|`
                    // curl: `Curl_pp_sendf("%s |%d|%s|%hu|", mode[fcmd], ..)`.
                    let af = if is_ipv6 { 2 } else { 1 };
                    pp_sendf!(pp, "{} |{}|{}|{}|", PORT_MODE[0], af, host, port)?;
                    self.count1 = 0; // fcmd = EPRT
                    self.set_state(FtpState::Port);
                    conn.bits.do_more = false;
                    return Ok(());
                }
                FtpPort::Port => {
                    if is_ipv6 {
                        cmd = FtpPort::Done; // PORT is IPv4-only
                        continue;
                    }
                    // Translate `x.x.x.x` to `x,x,x,x` then append the port pair.
                    // curl: `Curl_pp_sendf("%s %s", mode[fcmd], target)`.
                    let dotted = host.replace('.', ",");
                    let p_hi = (port >> 8) & 0xff;
                    let p_lo = port & 0xff;
                    pp_sendf!(pp, "{} {},{},{}", PORT_MODE[1], dotted, p_hi, p_lo)?;
                    self.count1 = 1; // fcmd = PORT
                    self.set_state(FtpState::Port);
                    conn.bits.do_more = false;
                    return Ok(());
                }
            }
        }
    }

    /// `FTP_PORT` response (← `ftp_state_port_resp`, L2320-2355).
    ///
    /// A failure retries the next command (`EPRT`→`PORT`→give up with
    /// [`CurlCode::FtpPortFailed`]); success ends the DO phase (`FTP_STOP`) and
    /// requests the DO-MORE phase to accept the inbound data connection.
    fn port_resp(&mut self, pp: &mut PingPong, conn: &mut Connection, ftpcode: i32) -> Result<()> {
        let fcmd = if self.count1 == 0 {
            FtpPort::Eprt
        } else {
            FtpPort::Port
        };
        if ftpcode / 100 != 2 {
            if fcmd == FtpPort::Eprt {
                conn.bits.ftp_use_eprt = false;
            }
            let next = match fcmd {
                FtpPort::Eprt => FtpPort::Port,
                _ => FtpPort::Done,
            };
            if next == FtpPort::Done {
                return Err(Error::with_context(
                    CurlCode::FtpPortFailed,
                    "Failed to do PORT",
                ));
            }
            self.state_use_port(pp, conn, next)
        } else {
            // Active data stream: end of DO phase; DO-MORE accepts the peer.
            self.set_state(FtpState::Stop);
            conn.bits.do_more = true;
            Ok(())
        }
    }

    /// `FTP_LIST`/`FTP_RETR` response (← `ftp_state_get_resp`, `lib/ftp.c`
    /// L2686-2797).
    ///
    /// On `150`/`125` the expected transfer size is parsed from the reply (with
    /// curl's exact ASCII-mode and `maxdownload` caveats); in active mode the
    /// data connection is accepted (deferring to
    /// [`check_ctrl_on_data_wait`](Self::check_ctrl_on_data_wait) if the peer
    /// has not connected back yet), then the transfer is initiated
    /// ([`initiate_transfer`](Self::initiate_transfer)). A `450` on `LIST` means
    /// an empty listing (transfer becomes [`PpTransfer::None`], no error). Other
    /// codes map to [`CurlCode::RemoteFileNotFound`] (`RETR` `550`) or
    /// [`CurlCode::FtpCouldntRetrFile`].
    ///
    /// Async because it establishes the data connection inline exactly as
    /// `ftp_state_get_resp` calls `ftp_initiate_transfer`; `pp` is the live
    /// borrow from the running state machine (see [`FtpConn::pp`]).
    async fn get_resp(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        ftpcode: i32,
        instate: FtpState,
    ) -> Result<()> {
        if ftpcode == 150 || ftpcode == 125 {
            self.req_size = -1; // default unknown size

            // Parse "<n> bytes" out of the reply, except for LIST or where the
            // number would only mislead (ASCII mode / ignore-content-length /
            // an already-known download size).
            if instate != FtpState::List
                && !self.params.prefer_ascii
                && !self.params.ignorecl
                && self.ftp.downloadsize < 1
            {
                if let Some(sz) = parse_get_size(pp.response_line()) {
                    self.req_size = sz;
                }
            } else if self.ftp.downloadsize > -1 {
                self.req_size = self.ftp.downloadsize;
            }

            if self.req_size > self.req_maxdownload && self.req_maxdownload > 0 {
                self.req_size = self.req_maxdownload;
            } else if instate != FtpState::List && self.params.prefer_ascii {
                self.req_size = -1; // servers understate ASCII-mode sizes
            }

            // Active mode: the server connects back to us. Accept it now; if it
            // is not here yet, wait and watch the control channel.
            if self.params.use_port {
                let connected = conn.connect(SECONDARYSOCKET, false).await?;
                if !connected {
                    tracing::info!("Data conn was not available immediately");
                    self.set_state(FtpState::Stop);
                    self.wait_data_conn = true;
                    return self.check_ctrl_on_data_wait(pp, conn).await;
                }
                self.wait_data_conn = false;
            }
            self.initiate_transfer(conn).await?;
            Ok(())
        } else if instate == FtpState::List && ftpcode == 450 {
            // No matching files in the directory listing.
            self.ftp.transfer = PpTransfer::None;
            self.set_state(FtpState::Stop);
            Ok(())
        } else if instate == FtpState::Retr && ftpcode == 550 {
            Err(Error::with_context(
                CurlCode::RemoteFileNotFound,
                format!("RETR response: {ftpcode:03}"),
            ))
        } else {
            Err(Error::with_context(
                CurlCode::FtpCouldntRetrFile,
                format!("RETR response: {ftpcode:03}"),
            ))
        }
    }

    /// `FTP_STOR` response (← `ftp_state_stor_resp`, `lib/ftp.c` L2653-2683).
    ///
    /// A `>= 400` reply is [`CurlCode::UploadFailed`]. Otherwise, in active mode
    /// the inbound data connection is accepted (waiting via
    /// [`check_ctrl_on_data_wait`](Self::check_ctrl_on_data_wait) if not yet
    /// available), then the upload is initiated
    /// ([`initiate_transfer`](Self::initiate_transfer)).
    async fn stor_resp(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        ftpcode: i32,
    ) -> Result<()> {
        if ftpcode >= 400 {
            self.set_state(FtpState::Stop);
            return Err(Error::with_context(
                CurlCode::UploadFailed,
                format!("Failed FTP upload: {ftpcode:03}"),
            ));
        }

        // "PORT means we are now awaiting the server to connect to us."
        if self.params.use_port {
            self.set_state(FtpState::Stop); // no longer in STOR state
            let connected = conn.connect(SECONDARYSOCKET, false).await?;
            if !connected {
                tracing::info!("Data conn was not available immediately");
                self.wait_data_conn = true;
                return self.check_ctrl_on_data_wait(pp, conn).await;
            }
            self.wait_data_conn = false;
        }
        self.initiate_transfer(conn).await?;
        Ok(())
    }
}

// ===========================================================================
// PHASE 5 — dual-connection orchestration and the data transfer (the DO /
// DO_MORE split). These engine methods drive the control-channel ping-pong
// (through the borrow-split driver [`FtpConn::drive`]) and set up the
// secondary (data) connection, mirroring `ftp_do_more`, `ftp_initiate_transfer`,
// `ftp_check_ctrl_on_data_wait`, `ftp_perform`, `ftp_regular_transfer`,
// `ftp_dophase_done`, `ftp_do`, `ftp_done`, `ftp_connect`, and `ftp_disconnect`
// (`lib/ftp.c`).
//
// The actual byte copy over the data channel is intentionally NOT here: curl's
// `ftp.c` does not move payload bytes either — `ftp_initiate_transfer` calls
// `Curl_xfer_setup_recv`/`Curl_xfer_setup_send` and the generic transfer engine
// (`lib/transfer.c` → `crate::transfer`) pumps the bytes. `crate::transfer` is
// not a dependency of this module (it depends on `protocols`, not the reverse),
// so this handler's data-phase role is purely control: establish the data
// connection, issue the right commands, set the transfer direction/size, and
// read the trailing `226`.
// ===========================================================================

impl FtpConn {
    /// Close and discard the secondary (data) connection
    /// (← `close_secondarysocket`, `lib/ftp.c` L351-358).
    fn close_secondary(&self, conn: &mut Connection) {
        tracing::trace!(state = self.state.as_str(), "closing DATA connection");
        conn.close(SECONDARYSOCKET);
    }

    /// Drive the control-channel state machine by one iteration, returning
    /// whether it has reached [`FtpState::Stop`] (← `ftp_statemach` /
    /// `ftp_multi_statemach`, `lib/ftp.c` L3368-3372, plus the borrow-split
    /// `mem::take` dance described on [`FtpConn::pp`]).
    ///
    /// [`PingPong::statemach`] needs `pp` and the protocol object (`self`) as
    /// two *separate* borrows, so [`FtpConn::pp`] is moved out, driven, and put
    /// back. `block`/`disconnecting` map to curl's `Curl_pp_statemach`
    /// arguments; `done` is `state == FTP_STOP`.
    async fn drive(
        &mut self,
        conn: &mut Connection,
        block: bool,
        disconnecting: bool,
    ) -> Result<bool> {
        let mut pp = mem::take(&mut self.pp);
        // curl derives `xfer_timeleft` from the easy handle's overall timeout;
        // the response-window bound lives inside `pp` (armed by `pp.init`), so a
        // sentinel "no transfer-level limit" is faithful for the engine. The
        // real per-transfer budget is supplied when the driver wires this in.
        let result = pp
            .statemach(self, conn, block, disconnecting, Instant::now(), i64::MAX)
            .await;
        self.pp = pp;
        result?;
        Ok(self.state == FtpState::Stop)
    }

    /// Read exactly one control-channel response through the supplied `pp`,
    /// returning its numeric code (← a single `getftpresponse` call, `lib/ftp.c`).
    ///
    /// Takes `pp` explicitly (rather than [`mem::take`]ing [`FtpConn::pp`])
    /// because it may be called from *within* the running state machine — e.g.
    /// [`get_resp`](Self::get_resp) → [`check_ctrl_on_data_wait`](Self::check_ctrl_on_data_wait)
    /// — where [`FtpConn::pp`] has already been moved out into the live `pp`.
    /// Callers that hold [`FtpConn::pp`] intact (e.g. [`done_engine`](Self::done_engine))
    /// pass a `mem::take`n copy and restore it afterward.
    async fn read_resp_via(&mut self, pp: &mut PingPong, conn: &mut Connection) -> Result<i32> {
        let mut code = 0i32;
        let mut nread = 0usize;
        pp.readresp(self, conn, FIRSTSOCKET, &mut code, &mut nread)
            .await?;
        Ok(code)
    }

    /// Set up the data transfer once the data connection is (or is being)
    /// established (← `ftp_initiate_transfer`, `lib/ftp.c` L542-573).
    ///
    /// Ensures `SECONDARYSOCKET` is fully connected (blocking, as curl passes
    /// `TRUE`), then records the transfer direction/size for the generic
    /// transfer engine and arms [`pending_final_resp`](Self::pending_final_resp)
    /// (curl's `pp.pending_resp = TRUE`). The state returns to [`FtpState::Stop`]
    /// because the DO/DO-MORE control dialogue is finished; payload movement is
    /// the transfer engine's job. Returns `false` when the connection is not
    /// ready yet (curl's `if(result || !connected) return`).
    async fn initiate_transfer(&mut self, conn: &mut Connection) -> Result<bool> {
        tracing::trace!("ftp_initiate_transfer()");
        let connected = conn.connect(SECONDARYSOCKET, true).await?;
        if !connected {
            return Ok(false);
        }
        // `data->state.upload` selects Curl_xfer_setup_send vs _recv. The
        // direction is already in `params.upload`; `req_size` (download) was set
        // by `get_resp`. Nothing else to compute here without the easy handle.
        self.pending_final_resp = true; // expect the server's transfer-complete reply
        self.set_state(FtpState::Stop);
        Ok(true)
    }

    /// While waiting for the server to open the data connection (active mode),
    /// notice an early/negative control-channel reply
    /// (← `ftp_check_ctrl_on_data_wait`, `lib/ftp.c` L458-532).
    ///
    /// A cached response whose first digit is `> '3'` means the data connection
    /// could not be established ([`CurlCode::FtpAcceptFailed`]). A stray `226`
    /// arriving before any data activity is the benign "final message early"
    /// race and is left in place ([`Ok`]). Any other response with class `> 3`
    /// is [`CurlCode::FtpAcceptFailed`]; otherwise it is a
    /// [`CurlCode::WeirdServerReply`].
    ///
    /// Takes the live `pp` (see [`read_resp_via`](Self::read_resp_via)) because
    /// it runs from inside the state machine via [`get_resp`](Self::get_resp) /
    /// [`stor_resp`](Self::stor_resp).
    async fn check_ctrl_on_data_wait(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
    ) -> Result<()> {
        // "First check whether there is a cached response from server."
        let cached = pp.response_line().to_vec();
        if !cached.is_empty() {
            let c = cached[0];
            if !c.is_ascii_digit() || c > b'3' {
                tracing::info!("There is negative response in cache while serv connect");
                let _ = self.read_resp_via(pp, conn).await;
                return Err(Error::with_context(
                    CurlCode::FtpAcceptFailed,
                    "Data connection could not be established",
                ));
            }
        }

        // "see if the connection request is already here" — is there control
        // data pending on FIRSTSOCKET (curl's overflow || SOCKET_READABLE)?
        let response = pp.moredata() || conn.data_pending(FIRSTSOCKET);
        if !response {
            return Ok(());
        }

        tracing::info!("Ctrl conn has data while waiting for data conn");
        // Special case: a `226` that arrived before the data connection saw any
        // traffic — leave it queued and use it as a trigger to read the data
        // socket (curl peeks the buffered line without consuming it).
        if pp.moredata() {
            let line = pp.response_line();
            if line.len() > 3 && is_statuscode(line) && line[3] == b' ' {
                let status = i32::from(line[0] - b'0') * 100
                    + i32::from(line[1] - b'0') * 10
                    + i32::from(line[2] - b'0');
                if status == 226 {
                    tracing::info!("Got 226 before data activity");
                    return Ok(());
                }
            }
        }

        let ftpcode = self.read_resp_via(pp, conn).await?;
        tracing::info!(ftpcode, "FTP code");
        if ftpcode / 100 > 3 {
            return Err(Error::with_context(
                CurlCode::FtpAcceptFailed,
                "Data connection could not be established",
            ));
        }
        Err(Error::with_context(
            CurlCode::WeirdServerReply,
            "Weird server reply while waiting for data connection",
        ))
    }

    /// Call [`epsv_disable`](Self::epsv_disable) from a context that holds
    /// [`FtpConn::pp`] intact, wrapping it in the [`mem::take`] borrow-split.
    fn epsv_disable_owned(&mut self, conn: &mut Connection) -> Result<()> {
        let mut pp = mem::take(&mut self.pp);
        let r = self.epsv_disable(&mut pp, conn);
        self.pp = pp;
        r
    }

    /// Choose and send the `TYPE` for a download's data phase, then continue the
    /// state machine (← the download branch of `ftp_do_more`, `lib/ftp.c`
    /// L2233-2271): plain `LIST` (directory), `RETR` with a pre-quote listing,
    /// or an ordinary `RETR`. Holds [`FtpConn::pp`] intact, so it uses the
    /// [`mem::take`] split around [`nb_type`](Self::nb_type).
    fn begin_download_type(&mut self, conn: &mut Connection) -> Result<()> {
        let mut pp = mem::take(&mut self.pp);
        let r = (|| {
            if (self.params.list_only || self.file.is_none()) && self.params.prequote.is_empty() {
                // A directory listing: LIST needs ASCII mode first, but only for
                // a real body transfer; otherwise just fall through.
                if self.ftp.transfer == PpTransfer::Body {
                    return self.nb_type(&mut pp, conn, true, FtpState::ListType);
                }
                Ok(())
            } else if !self.params.prequote.is_empty() && self.file.is_none() {
                self.nb_type(&mut pp, conn, true, FtpState::RetrListType)
            } else {
                let ascii = self.params.prefer_ascii;
                self.nb_type(&mut pp, conn, ascii, FtpState::RetrType)
            }
        })();
        self.pp = pp;
        r
    }

    /// The DO-MORE phase — establish the data connection and drive the transfer
    /// commands (← `ftp_do_more`, `lib/ftp.c` L2133-2290).
    ///
    /// Returns curl's `*completep`: `0` = stay (not complete yet), `1` = the DO
    /// phase is complete, `-1` = go back to DOING (an `EPSV` data connect failed
    /// and PASV is being retried).
    pub async fn do_more_engine(&mut self, conn: &mut Connection) -> Result<i32> {
        // If the secondary connection has been set up, try to connect it. This
        // may not complete now (active mode awaits the server; a TLS filter
        // awaits more FTP commands).
        if conn.is_setup(SECONDARYSOCKET) {
            let is_eptr = self.params.use_port; // active mode ⇒ we listen
            match conn.connect(SECONDARYSOCKET, false).await {
                Err(e) => {
                    // An EPSV connect failure with EPSV still selected retries
                    // with PASV (go back to DOING).
                    if !is_eptr && self.count1 == 0 {
                        self.epsv_disable_owned(conn)?;
                        return Ok(-1);
                    }
                    return Err(e);
                }
                Ok(connected) => {
                    if !connected && !is_eptr && !conn.is_ip_connected(SECONDARYSOCKET) {
                        return Ok(0); // stay; poll again later
                    }
                }
            }
        }

        if self.state != FtpState::Stop {
            // Already mid-dialogue: run the next queued kickstart command. One
            // step per call, exactly as curl's `ftp_multi_statemach`; the caller
            // ([`run_do_more`](Self::run_do_more) / the multi DO_MORE state)
            // re-enters until `*completep != 0`.
            let complete = self.drive(conn, true, false).await?;
            if !self.wait_data_conn {
                return Ok(i32::from(complete));
            }
            // Reached the end of the FSM but still awaiting the data connection,
            // so we are not actually complete (curl overrides `*completep = 0`).
        }

        // `ftp->transfer <= PPTRANSFER_INFO`: a transfer (or a SIZE-needing
        // INFO request) is about to take place.
        if matches!(self.ftp.transfer, PpTransfer::Body | PpTransfer::Info) {
            if self.wait_data_conn {
                let serv_conned = conn.connect(SECONDARYSOCKET, false).await?;
                if serv_conned {
                    // The data connection is established.
                    self.wait_data_conn = false;
                    self.initiate_transfer(conn).await?;
                    // Complete once the server has connected back to us.
                    return Ok(1);
                }
                let mut pp = mem::take(&mut self.pp);
                let r = self.check_ctrl_on_data_wait(&mut pp, conn).await;
                self.pp = pp;
                r?;
                return Ok(0);
            } else if self.params.upload {
                // Upload: TYPE (if needed) then STOR.
                let mut pp = mem::take(&mut self.pp);
                let ascii = self.params.prefer_ascii;
                let r = self.nb_type(&mut pp, conn, ascii, FtpState::StorType);
                self.pp = pp;
                r?;
                let complete = self.drive(conn, true, false).await?;
                // nb_type may have skipped `TYPE` and sent `STOR` directly; if
                // the FSM completed but we still await the data connection the
                // transfer has not actually been initiated yet.
                return Ok(if self.wait_data_conn {
                    0
                } else {
                    i32::from(complete)
                });
            } else {
                // Download.
                self.ftp.downloadsize = -1; // unknown as of yet

                // Curl_range applies any byte range: without the range parser
                // here, the maxdownload value is already in place; reproduce the
                // "do not check for successful transfer" side effect.
                if self.req_maxdownload >= 0 {
                    self.dont_check = true;
                }

                self.begin_download_type(conn)?;
                let complete = self.drive(conn, true, false).await?;
                return Ok(i32::from(complete));
            }
        }

        // No data to transfer.
        if !self.wait_data_conn {
            tracing::trace!(state = self.state.as_str(), "DO-MORE phase ends");
            return Ok(1);
        }
        Ok(0)
    }

    /// Re-enter [`do_more_engine`](Self::do_more_engine) until it reports a
    /// definitive result, mirroring the multi layer's `DO_MORE` state loop.
    ///
    /// `do_more_engine` advances the data-phase one control step per call
    /// (`ftp_do_more` calls `ftp_multi_statemach` once); the multi loop re-enters
    /// it when the socket is ready. This helper reproduces that re-entry for the
    /// blocking / test driver: it loops while the returned `*completep` is `0`
    /// (stay), returns `Ok(())` on `1` (complete), and re-runs the DOING phase
    /// via [`do_engine`](Self::do_engine) on `-1` (an `EPSV` connect failed and
    /// `PASV` is being retried), exactly as curl's multi state machine does.
    pub async fn run_do_more(&mut self, conn: &mut Connection) -> Result<()> {
        loop {
            match self.do_more_engine(conn).await? {
                0 => continue,      // stay: re-enter (each call awaits progress)
                1 => return Ok(()), // the DO-MORE phase is complete
                _ => {
                    // -1: EPSV failed, PASV substituted — go back to DOING and
                    // re-run the transfer commands, then resume DO-MORE.
                    self.regular_transfer(conn).await?;
                }
            }
        }
    }

    /// Drive the control state machine to [`FtpState::Stop`] with blocking reads
    /// (← `ftp_block_statemach`, `lib/ftp.c` L3376-3390).
    ///
    /// This is the "run to completion" primitive used by the blocking-flavored
    /// entry points ([`run_connect`](Self::run_connect), [`perform`](Self::perform),
    /// [`quit`](Self::quit)); it loops [`PingPong::statemach`] with `block =
    /// true` (each step awaits socket readiness) until the FSM settles at
    /// `FTP_STOP`. `disconnecting` is forwarded so a stalled socket surfaces as
    /// [`CurlCode::OperationTimedout`] during teardown.
    async fn block_statemach(&mut self, conn: &mut Connection, disconnecting: bool) -> Result<()> {
        while self.state != FtpState::Stop {
            let mut pp = mem::take(&mut self.pp);
            let r = pp
                .statemach(self, conn, true, disconnecting, Instant::now(), i64::MAX)
                .await;
            self.pp = pp;
            r?;
        }
        Ok(())
    }

    /// The connect phase: greeting → login → `PWD`/`SYST` (← `ftp_connect`,
    /// `lib/ftp.c` L3400-3431).
    ///
    /// Installs the ping-pong engine (this object), brings the control channel's
    /// TLS up first for implicit FTPS (`ftps://`, curl's `Curl_conn_is_ssl`
    /// blocking connect + `ftp_use_control_ssl = TRUE`), arms the response timer
    /// ([`PingPong::init`]), starts at [`FtpState::Wait220`], and drives the
    /// login dialogue to completion. Returns whether the connect phase is done
    /// (`state == FTP_STOP`), matching curl's `*done`.
    pub async fn run_connect(&mut self, conn: &mut Connection) -> Result<bool> {
        // `if(Curl_conn_is_ssl(conn, FIRSTSOCKET))` — implicit FTPS: the control
        // channel must be TLS *before* the greeting (BLOCKING connect).
        if conn.is_ssl(FIRSTSOCKET) {
            let connected = conn.connect(FIRSTSOCKET, true).await?;
            if !connected {
                return Ok(false);
            }
            conn.bits.ftp_use_control_ssl = true;
        }

        // `Curl_pp_init(pp, ...)` — once per transfer.
        self.pp.init(Instant::now());

        // "When we connect, we start in the state where we await the 220."
        self.set_state(FtpState::Wait220);

        self.block_statemach(conn, false).await?;
        Ok(self.state == FtpState::Stop)
    }

    /// The DO-phase control dialogue (← `ftp_perform`, `lib/ftp.c` L3734-3773).
    ///
    /// Issues the first `QUOTE` command and drives the state machine through
    /// `CWD`/`MDTM`/`TYPE`/`SIZE`/`REST` and `PASV`/`PORT` up to the point where
    /// the data connection is set up (the FSM parks at [`FtpState::Stop`] with
    /// `do_more` requested). Returns `connected` = whether the secondary data
    /// connection is already established (it usually is not — active mode must
    /// still `accept`, passive mode connects during DO-MORE), matching curl's
    /// `*connected`.
    async fn perform(&mut self, conn: &mut Connection) -> Result<bool> {
        tracing::trace!(state = self.state.as_str(), "DO phase starts");

        // `if(data->req.no_body) ftp->transfer = PPTRANSFER_INFO;`
        if self.params.no_body {
            self.ftp.transfer = PpTransfer::Info;
        }

        // "start the first command in the DO phase" — ftp_state_quote(TRUE, QUOTE).
        {
            let mut pp = mem::take(&mut self.pp);
            let r = self.state_quote(&mut pp, conn, true, FtpState::Quote);
            self.pp = pp;
            r?;
        }

        self.block_statemach(conn, false).await?;

        let connected = conn.is_connected(SECONDARYSOCKET);
        if connected {
            tracing::info!(state = self.state.as_str(), "[DATA] connection established");
        } else {
            tracing::trace!(state = self.state.as_str(), "[DATA] awaiting connect");
        }
        Ok(connected)
    }

    /// Called when the DO phase has completed (← `ftp_dophase_done`, `lib/ftp.c`
    /// L2293-2318).
    ///
    /// When the data connection is already up, kick the DO-MORE machine once
    /// (closing the secondary socket on error). Otherwise, for a body transfer,
    /// request DO-MORE (`conn.bits.do_more = TRUE`) so the multi layer will call
    /// [`run_do_more`](Self::run_do_more); a non-body request needs no data phase
    /// (curl's `Curl_xfer_setup_nop`). Marks the control channel valid.
    async fn dophase_done(&mut self, conn: &mut Connection, connected: bool) -> Result<()> {
        if connected {
            if let Err(e) = self.do_more_engine(conn).await {
                self.close_secondary(conn);
                return Err(e);
            }
        }

        if self.ftp.transfer != PpTransfer::Body {
            // No data to transfer (← Curl_xfer_setup_nop; handled by the
            // transfer layer, which owns the byte pump).
        } else if !connected {
            // We did not connect now, so make the multi layer call do_more.
            conn.bits.do_more = true;
        }

        self.ctl_valid = true; // seems good
        Ok(())
    }

    /// Perform all pre-transfer commands and set up the transfer (←
    /// `ftp_regular_transfer`, `lib/ftp.c` L4021-4053).
    ///
    /// Resets the expected size, marks the control channel valid, runs
    /// [`perform`](Self::perform), and finishes the DO phase via
    /// [`dophase_done`](Self::dophase_done). On error the directory list is freed
    /// (curl's `freedirs`). Returns `dophase_done` (always `true` in this
    /// blocking model, where [`perform`](Self::perform) drives to `FTP_STOP`).
    async fn regular_transfer(&mut self, conn: &mut Connection) -> Result<bool> {
        self.req_size = -1; // unknown at this point
        self.ctl_valid = true; // starts good

        match self.perform(conn).await {
            Ok(connected) => {
                self.dophase_done(conn, connected).await?;
                Ok(true)
            }
            Err(e) => {
                self.freedirs();
                Err(e)
            }
        }
    }

    /// The DO function: decode the path and run the transfer (← `ftp_do`,
    /// `lib/ftp.c` L4064-4112).
    ///
    /// Clears `wait_data_conn`, then either drives the wildcard state machine
    /// (`CURLOPT_WILDCARDMATCH`) or parses the URL path, and finally runs
    /// [`regular_transfer`](Self::regular_transfer). Returns `done` (the
    /// dophase-done flag); a wildcard `SKIP`/`DONE` short-circuits with `done =
    /// false` so the regular transfer is not run (curl returns `CURLE_OK` with
    /// `*done` still `FALSE`).
    pub async fn do_engine(&mut self, conn: &mut Connection) -> Result<bool> {
        self.wait_data_conn = false; // default to no such wait

        if self.params.wildcardmatch {
            self.wc_statemach(conn)?;
            if matches!(
                self.wildcard.state,
                WildcardState::Skip | WildcardState::Done
            ) {
                // Do not call regular_transfer.
                return Ok(false);
            }
        } else {
            let path = self.ftp.path.clone();
            let filemethod = self.params.filemethod;
            let upload = self.params.upload;
            let reuse = conn.bits.reuse;
            let transfer = self.ftp.transfer;
            self.parse_url_path(&path, filemethod, upload, reuse, transfer)?;
        }

        self.regular_transfer(conn).await
    }

    /// The DOING multi callback: advance the DO-phase state machine (←
    /// `ftp_doing`, `lib/ftp.c` L4181-4200).
    ///
    /// Runs one control step; when the FSM has settled it finalizes the DO phase
    /// via [`dophase_done`](Self::dophase_done) with `connected = false` (the
    /// data connection is completed later, in DO-MORE). Returns `dophase_done`.
    pub async fn doing_engine(&mut self, conn: &mut Connection) -> Result<bool> {
        let done = self.drive(conn, true, false).await?;
        if done {
            self.dophase_done(conn, false).await?;
        }
        Ok(done)
    }
}

// ===========================================================================
// PHASE 5 — DONE / QUIT / disconnect and the blocking QUOTE sender
// (← `ftp_done`, `ftp_sendquote`, `ftp_quit`, `ftp_disconnect`, `lib/ftp.c`).
// ===========================================================================

impl FtpConn {
    /// Send a list of raw `QUOTE` commands, blocking for each response (←
    /// `ftp_sendquote`, `lib/ftp.c` L3442-3486).
    ///
    /// A command prefixed with `*` is allowed to fail (curl's `acceptfail`): its
    /// `>= 400` response is ignored. Any other command that draws a `>= 400`
    /// reply is [`CurlCode::QuoteError`]. Used for `POSTQUOTE` from
    /// [`done_engine`](Self::done_engine).
    async fn sendquote(&mut self, conn: &mut Connection, quote: &[String]) -> Result<()> {
        let mut pp = mem::take(&mut self.pp);
        let r = self.sendquote_inner(&mut pp, conn, quote).await;
        self.pp = pp;
        r
    }

    /// The body of [`sendquote`](Self::sendquote), operating on the taken-out
    /// [`PingPong`]. Each command is queued, flushed onto the wire, and its
    /// response read synchronously (curl's `Curl_pp_sendf` + `getftpresponse`).
    async fn sendquote_inner(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        quote: &[String],
    ) -> Result<()> {
        for cmd in quote {
            if cmd.is_empty() {
                continue;
            }
            // A leading '*' marks the command as allowed-to-fail and is stripped.
            let (cmd_str, acceptfail) = match cmd.strip_prefix('*') {
                Some(rest) => (rest, true),
                None => (cmd.as_str(), false),
            };

            pp_sendf!(pp, "{}", cmd_str)?;
            // Flush the queued command onto the wire before reading (the state
            // machine defers the flush to its next entry; here we send inline).
            while pp.needs_flush() {
                pp.flushsend(conn, Instant::now()).await?;
            }
            let ftpcode = self.read_resp_via(pp, conn).await?;

            if !acceptfail && ftpcode >= 400 {
                return Err(Error::with_context(
                    CurlCode::QuoteError,
                    format!("QUOT string not accepted: {cmd_str}"),
                ));
            }
        }
        Ok(())
    }

    /// The DONE function: finalize a completed (or aborted) transfer (←
    /// `ftp_done`, `lib/ftp.c` L3497-3694).
    ///
    /// `status` is the transfer result (`Ok` = `CURLE_OK`); `premature` marks an
    /// early abort. `bytecount`/`writebytecount` are the actual downloaded /
    /// uploaded byte totals the transfer layer owns (curl's
    /// `data->req.bytecount` / `data->req.writebytecount`), passed in because
    /// they live outside this handler; they default to `0` in unit tests that do
    /// not exercise the partial-file checks.
    ///
    /// This reproduces curl's DONE logic faithfully: the status→connection-health
    /// classification, wildcard cleanup, `prevpath` remembering for reuse, the
    /// `ABOR` on a checked-out partial download, the trailing `226`/`250`/`552`
    /// status read (gated by [`pending_final_resp`](Self::pending_final_resp)),
    /// the upload/download partial-file checks, and the `POSTQUOTE` send.
    pub async fn done_engine(
        &mut self,
        conn: &mut Connection,
        status: Result<()>,
        premature: bool,
        bytecount: i64,
        writebytecount: i64,
    ) -> Result<()> {
        let status_code = status.as_ref().err().map(Error::code);

        // These errors do not, by themselves, wedge the control connection.
        let benign = matches!(
            status_code,
            None | Some(
                CurlCode::BadDownloadResume
                    | CurlCode::FtpWeirdPasvReply
                    | CurlCode::FtpPortFailed
                    | CurlCode::FtpAcceptFailed
                    | CurlCode::FtpAcceptTimeout
                    | CurlCode::FtpCouldntSetType
                    | CurlCode::FtpCouldntRetrFile
                    | CurlCode::PartialFile
                    | CurlCode::UploadFailed
                    | CurlCode::RemoteAccessDenied
                    | CurlCode::FilesizeExceeded
                    | CurlCode::RemoteFileNotFound
                    | CurlCode::WriteError
            )
        );

        let mut result: Result<()> = Ok(());
        if benign && !premature {
            // The connection stays alive; nothing to do (curl's `break`).
        } else {
            // Default: the control connection is wedged and must not be reused.
            self.ctl_valid = false;
            self.cwdfail = true; // do not remember the current path
            conn.conn_control(ConnControl::Connection); // connclose
            if let Err(e) = status {
                result = Err(e);
            }
        }

        // Wildcard: run the per-file chunk-end hook and reset for the next entry.
        if self.params.wildcardmatch {
            if self.file.is_some() {
                // curl calls data->set.chunk_end here; the callback is owned by
                // the CLI layer, so this port only performs the state reset.
                self.freedirs();
            }
            self.known_filesize = -1;
        }

        // Remember the working directory for connection reuse (curl's else-branch
        // runs only when the connection was not wedged).
        if result.is_err() {
            self.ctl_valid = false;
            conn.conn_control(ConnControl::Connection);
            self.prevpath = None; // no path remembering
        } else if !self.rawpath.is_empty() {
            if self.params.filemethod == CurlFtpFile::Nocwd && self.rawpath.starts_with('/') {
                // Full path => no CWDs happened => keep the existing prevpath.
            } else if !self.cwdfail {
                let mut path_len = self.rawpath.len();
                if self.params.filemethod == CurlFtpFile::Nocwd {
                    // Relative path => working directory is the FTP home.
                    path_len = 0;
                } else {
                    path_len -= self.file.as_ref().map_or(0, String::len);
                }
                self.prevpath = Some(self.rawpath[..path_len].to_string());
            } else {
                self.prevpath = None; // no path
            }
            if let Some(p) = &self.prevpath {
                tracing::info!("Remembering we are in directory \"{p}\"");
            }
        }

        // Shut down the data connection to inform the server we are done.
        if conn.is_setup(SECONDARYSOCKET) {
            if result.is_ok() && self.dont_check && self.req_maxdownload > 0 {
                // Partial download completed: abort the rest.
                let mut pp = mem::take(&mut self.pp);
                let sent = pp_sendf!(pp, "{}", "ABOR");
                self.pp = pp;
                if let Err(e) = sent {
                    self.ctl_valid = false;
                    conn.conn_control(ConnControl::Connection);
                    result = Err(e);
                }
            }
            self.close_secondary(conn);
        }

        // Read the server's transfer-complete reply, unless we already errored.
        if result.is_ok()
            && self.ftp.transfer == PpTransfer::Body
            && self.ctl_valid
            && self.pending_final_resp
            && !premature
        {
            let mut pp = mem::take(&mut self.pp);
            let read = self.read_resp_via(&mut pp, conn).await;
            self.pp = pp;
            let ftpcode = read?;

            if self.dont_check && self.req_maxdownload > 0 {
                // We just sent ABOR; there is no reliable way to check it, so the
                // connection must be closed now.
                tracing::info!("partial download completed, closing connection");
                conn.conn_control(ConnControl::Connection);
                return Ok(());
            }

            if !self.dont_check {
                match ftpcode {
                    // 226 Transfer complete; 250 file action OK, completed.
                    226 | 250 => {}
                    552 => {
                        result = Err(Error::with_context(
                            CurlCode::RemoteDiskFull,
                            "Exceeded storage allocation",
                        ));
                    }
                    other => {
                        result = Err(Error::with_context(
                            CurlCode::PartialFile,
                            format!("server did not report OK, got {other}"),
                        ));
                    }
                }
            }
        }

        // Partial-file sanity checks against the transfer layer's byte counts.
        if result.is_err() || premature {
            // The status already showed an error — no use checking further.
        } else if self.params.upload {
            if self.ftp.transfer == PpTransfer::Body && self.params.infilesize != -1 {
                let no_conversion = !self.params.crlf && !self.params.prefer_ascii;
                let unaligned = if no_conversion {
                    self.params.infilesize != writebytecount
                } else {
                    self.params.infilesize > writebytecount
                };
                if unaligned {
                    result = Err(Error::with_context(
                        CurlCode::PartialFile,
                        format!(
                            "Uploaded unaligned file size ({writebytecount} out of {} bytes)",
                            self.params.infilesize
                        ),
                    ));
                }
            }
        } else if self.req_size != -1
            && self.req_size != bytecount
            && self.req_maxdownload != bytecount
        {
            result = Err(Error::with_context(
                CurlCode::PartialFile,
                format!("Received only partial file: {bytecount} bytes"),
            ));
        } else if !self.dont_check && bytecount == 0 && self.req_size > 0 {
            result = Err(Error::with_context(
                CurlCode::FtpCouldntRetrFile,
                "No data was received",
            ));
        }

        // Clear these for the next transfer on this connection.
        self.ftp.transfer = PpTransfer::Body;
        self.dont_check = false;

        // Send any post-transfer QUOTE strings.
        if status_code.is_none()
            && result.is_ok()
            && !premature
            && !self.params.postquote.is_empty()
        {
            let postquote = self.params.postquote.clone();
            result = self.sendquote(conn, &postquote).await;
        }

        tracing::trace!(state = self.state.as_str(), "done");
        result
    }

    /// Send `QUIT` and wait for the server's response (← `ftp_quit`, `lib/ftp.c`
    /// L4124-4147).
    ///
    /// Only issued when the control channel is still valid ([`ctl_valid`](Self::ctl_valid));
    /// a send failure marks the channel bad and requests connection closure. On
    /// success the FSM parks at [`FtpState::Quit`] and is driven to `FTP_STOP`
    /// with blocking reads (curl's `ftp_block_statemach`).
    async fn quit(&mut self, conn: &mut Connection) -> Result<()> {
        if !self.ctl_valid {
            return Ok(());
        }

        tracing::trace!("sending QUIT to close session");
        let mut pp = mem::take(&mut self.pp);
        let sent = pp_sendf!(pp, "{}", "QUIT");
        self.pp = pp;

        if let Err(e) = sent {
            self.ctl_valid = false; // mark control connection as bad
            conn.conn_control(ConnControl::Connection); // mark for closure
            self.set_state(FtpState::Stop);
            return Err(e);
        }

        self.set_state(FtpState::Quit);
        self.block_statemach(conn, true).await
    }

    /// Disconnect from the FTP server (← `ftp_disconnect`, `lib/ftp.c`
    /// L4156-4178). BLOCKING.
    ///
    /// Sets the shutdown flag; if the connection is dead or has unflushed control
    /// bytes the channel is marked invalid so [`quit`](Self::quit) will skip the
    /// `QUIT` handshake. Errors from `QUIT` are ignored, exactly as curl does.
    pub async fn disconnect_engine(&mut self, conn: &mut Connection, dead: bool) -> Result<()> {
        self.shutdown = true;
        if dead || self.pp.needs_flush() {
            self.ctl_valid = false;
        }
        // Ignore errors on the QUIT (the connection is going away regardless).
        let _ = self.quit(conn).await;
        Ok(())
    }
}

// ===========================================================================
// Wildcard glob matching (← `Curl_fnmatch`, `lib/curl_fnmatch.c`).
//
// The `LIST` parser ([`crate::protocols::ftp_list`]) deliberately does not
// filter by pattern; the wildcard machine here matches each listed filename
// against the URL's trailing glob using this `fnmatch`. It supports `*`, `?`,
// `[set]` (ranges `a-z`, negation `[!..]`/`[^..]`, POSIX classes
// `[[:alpha:]]`), and `\` escapes, mirroring curl's matcher.
// ===========================================================================

/// Whether byte `ch` belongs to POSIX character class `class` (the name between
/// `[:` and `:]`), matching C's `is*()` classifications used by curl's fnmatch.
fn posix_class_match(class: &[u8], ch: u8) -> bool {
    match class {
        b"alpha" => ch.is_ascii_alphabetic(),
        b"digit" => ch.is_ascii_digit(),
        b"alnum" => ch.is_ascii_alphanumeric(),
        // C `isspace`: space, tab, newline, vertical tab, form feed, return.
        b"space" => matches!(ch, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'),
        b"upper" => ch.is_ascii_uppercase(),
        b"lower" => ch.is_ascii_lowercase(),
        b"print" => ch.is_ascii_graphic() || ch == b' ',
        b"blank" => ch == b' ' || ch == b'\t',
        b"cntrl" => ch.is_ascii_control(),
        b"graph" => ch.is_ascii_graphic(),
        b"punct" => ch.is_ascii_punctuation(),
        b"xdigit" => ch.is_ascii_hexdigit(),
        _ => false,
    }
}

/// Find the terminating `:]` of a POSIX class starting at `from` (just past the
/// opening `[:`); returns the index of the `:` in `:]`, or `None` if absent.
fn find_posix_class_end(pattern: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < pattern.len() {
        if pattern[i] == b':' && pattern[i + 1] == b']' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Test byte `ch` against the `[...]` set beginning at `start` (the `[`).
///
/// Returns `Some((matched, next))` where `matched` accounts for a leading `!`/
/// `^` negation and `next` is the index just past the closing `]`; returns
/// `None` when the set has no closing `]` (a malformed pattern, which the caller
/// then treats as a literal `[`).
fn fnmatch_setcharset(pattern: &[u8], start: usize, ch: u8) -> Option<(bool, usize)> {
    let mut i = start + 1;
    let mut negate = false;
    if i < pattern.len() && (pattern[i] == b'!' || pattern[i] == b'^') {
        negate = true;
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    while i < pattern.len() {
        let c = pattern[i];
        // A `]` other than as the very first member closes the set.
        if c == b']' && !first {
            return Some((matched ^ negate, i + 1));
        }
        first = false;

        // POSIX class `[:name:]`.
        if c == b'[' && i + 1 < pattern.len() && pattern[i + 1] == b':' {
            if let Some(colon) = find_posix_class_end(pattern, i + 2) {
                if posix_class_match(&pattern[i + 2..colon], ch) {
                    matched = true;
                }
                i = colon + 2; // skip past ":]"
                continue;
            }
        }

        // Escaped literal inside the set.
        if c == b'\\' && i + 1 < pattern.len() {
            if ch == pattern[i + 1] {
                matched = true;
            }
            i += 2;
            continue;
        }

        // Range `a-z` (a `-` followed by a non-`]` upper bound).
        if i + 2 < pattern.len() && pattern[i + 1] == b'-' && pattern[i + 2] != b']' {
            if c <= ch && ch <= pattern[i + 2] {
                matched = true;
            }
            i += 3;
            continue;
        }

        // Plain literal member.
        if ch == c {
            matched = true;
        }
        i += 1;
    }
    None // no closing ']'
}

/// Match `string` against shell wildcard `pattern` (← `Curl_fnmatch`).
///
/// Returns `true` only on a full match. Uses classic backtracking for `*`
/// (recording the last star position and retrying longer matches on mismatch),
/// with `?`, `[set]`, and `\`-escape handling inline.
fn fnmatch(pattern: &[u8], string: &[u8]) -> bool {
    let (plen, slen) = (pattern.len(), string.len());
    let (mut p, mut s) = (0usize, 0usize);
    let mut star_p: Option<usize> = None;
    let mut star_s = 0usize;

    while s < slen {
        let mut advanced = false;
        if p < plen {
            match pattern[p] {
                b'?' => {
                    p += 1;
                    s += 1;
                    advanced = true;
                }
                b'*' => {
                    star_p = Some(p);
                    star_s = s;
                    p += 1;
                    advanced = true;
                }
                b'[' => {
                    if let Some((m, next_p)) = fnmatch_setcharset(pattern, p, string[s]) {
                        if m {
                            p = next_p;
                            s += 1;
                            advanced = true;
                        }
                        // A well-formed set that did not match falls through to
                        // the `*` backtrack below.
                    } else if string[s] == b'[' {
                        // Malformed set: treat the '[' as a literal.
                        p += 1;
                        s += 1;
                        advanced = true;
                    }
                }
                b'\\' => {
                    let lit = if p + 1 < plen { pattern[p + 1] } else { b'\\' };
                    if string[s] == lit {
                        p += 2;
                        s += 1;
                        advanced = true;
                    }
                }
                c => {
                    if string[s] == c {
                        p += 1;
                        s += 1;
                        advanced = true;
                    }
                }
            }
        }
        if advanced {
            continue;
        }
        // Mismatch (or pattern exhausted): backtrack to the last '*' if any.
        match star_p {
            Some(sp) => {
                p = sp + 1;
                star_s += 1;
                s = star_s;
            }
            None => return false,
        }
    }

    // Any remaining pattern must be all '*' to match the empty suffix.
    while p < plen && pattern[p] == b'*' {
        p += 1;
    }
    p == plen
}

// ===========================================================================
// Wildcard-download state machine (← `init_wc_data`, `wc_statemach`, and the
// `Curl_ftp_parselist` write function, `lib/ftp.c` L3784-4007).
// ===========================================================================

impl FtpConn {
    /// Initialize the wildcard machine from the URL path (← `init_wc_data`,
    /// `lib/ftp.c` L3784-3876).
    ///
    /// Splits [`Ftp::path`] at the last `/`: the trailing component becomes the
    /// glob [`pattern`](FtpWildcard::pattern) and the leading part the base
    /// [`path`](FtpWildcard::path). A path ending in `/` (or empty) is a plain
    /// listing — the state goes straight to [`WildcardState::Clean`]. Wildcard
    /// transfers force `MULTICWD` (curl asserts `NOCWD` is unsupported here).
    fn init_wc_data(&mut self, conn: &mut Connection) -> Result<()> {
        let path = self.ftp.path.clone();
        let reuse = conn.bits.reuse;

        if let Some(pos) = path.rfind('/') {
            let after = &path[pos + 1..];
            if after.is_empty() {
                // Trailing slash: only a listing is requested.
                self.wildcard.state = WildcardState::Clean;
                let (fm, up, tr) = (
                    self.params.filemethod,
                    self.params.upload,
                    self.ftp.transfer,
                );
                return self.parse_url_path(&path, fm, up, reuse, tr);
            }
            self.wildcard.pattern = Some(after.to_string());
            // Cut the file off the path (curl's `last_slash[0] = '\0'`), keeping
            // the trailing slash.
            self.ftp.path = path[..=pos].to_string();
        } else if !path.is_empty() {
            // Only a wildcard pattern, no directory.
            self.wildcard.pattern = Some(path.clone());
            self.ftp.path = String::new();
        } else {
            // Nothing at all: only a listing.
            self.wildcard.state = WildcardState::Clean;
            let (fm, up, tr) = (
                self.params.filemethod,
                self.params.upload,
                self.ftp.transfer,
            );
            return self.parse_url_path("", fm, up, reuse, tr);
        }

        // Fresh parser / file list for this wildcard operation.
        self.wildcard.parser = FtpListParser::new();
        self.wildcard.parse_error = None;
        self.wildcard.filelist.clear();

        // The wildcard machine does not support NOCWD; fall back to MULTICWD.
        if self.params.filemethod == CurlFtpFile::Nocwd {
            self.params.filemethod = CurlFtpFile::Multicwd;
        }

        let parse_path = self.ftp.path.clone();
        let (fm, up, tr) = (
            self.params.filemethod,
            self.params.upload,
            self.ftp.transfer,
        );
        self.parse_url_path(&parse_path, fm, up, reuse, tr)?;

        // `wildcard->path = strdup(ftp->path)` — the base every match hangs off.
        self.wildcard.path = self.ftp.path.clone();
        tracing::info!("Wildcard - Parsing started");
        Ok(())
    }

    /// Feed a chunk of `LIST` response bytes to the wildcard parser (← the
    /// `Curl_ftp_parselist` write function installed by `init_wc_data`).
    ///
    /// Every complete record the parser recognizes is matched against the glob
    /// [`pattern`](FtpWildcard::pattern) via [`fnmatch`]; matches are queued in
    /// [`filelist`](FtpWildcard::filelist) for later `RETR`. A parse failure is
    /// recorded as the sticky [`parse_error`](FtpWildcard::parse_error) (curl's
    /// `Curl_ftp_parselist_geterror`).
    ///
    /// The transfer layer calls this with the data-channel bytes of the
    /// `MATCHING`-phase `LIST`; it is the explicit analogue of curl swapping the
    /// easy handle's write callback to the parser.
    pub fn wc_parse_feed(&mut self, buf: &[u8]) -> Result<()> {
        if let Some(code) = self.wildcard.parse_error {
            return Err(Error::from(code));
        }

        // Borrow-split: take the parser out so the `on_file` closure can borrow
        // the sibling `filelist` field mutably without aliasing the parser.
        let mut parser = mem::take(&mut self.wildcard.parser);
        let res = {
            let pattern: Vec<u8> = self
                .wildcard
                .pattern
                .as_deref()
                .unwrap_or("")
                .as_bytes()
                .to_vec();
            let filelist = &mut self.wildcard.filelist;
            let mut on_file = |finfo: FileInfo| -> Result<()> {
                if fnmatch(&pattern, finfo.filename.as_bytes()) {
                    filelist.push_back(finfo);
                }
                Ok(())
            };
            parser.parse(buf, &mut on_file)
        };
        self.wildcard.parser = parser;

        if let Err(e) = res {
            self.wildcard.parse_error = Some(e.code());
            return Err(e);
        }
        Ok(())
    }

    /// Finalize the wildcard `LIST` parse once all data-channel bytes are in
    /// (← `Curl_ftp_parselist` end-of-stream). Drops any partial final line and
    /// records a sticky error if one surfaces.
    pub fn wc_parse_end(&mut self) -> Result<()> {
        if let Some(code) = self.wildcard.parse_error {
            return Err(Error::from(code));
        }
        if let Err(e) = self.wildcard.parser.end() {
            self.wildcard.parse_error = Some(e.code());
            return Err(e);
        }
        Ok(())
    }

    /// Drive the wildcard state machine (← `wc_statemach`, `lib/ftp.c`
    /// L3878-4007).
    ///
    /// Not `async`: it performs no I/O (the `LIST` bytes are delivered
    /// separately via [`wc_parse_feed`](Self::wc_parse_feed)). It parks in
    /// [`WildcardState::Matching`] after `INIT` (so the caller can run the
    /// listing transfer), then on the next entry picks the first matched file,
    /// rewrites [`Ftp::path`], re-parses it, and pops the queue — one file per
    /// call — until the queue drains via [`WildcardState::Clean`] to
    /// [`WildcardState::Done`]. The per-file `chunk_bgn`/`chunk_end` callbacks
    /// live in the CLI layer, so this port performs the state transitions
    /// without invoking them.
    fn wc_statemach(&mut self, conn: &mut Connection) -> Result<()> {
        loop {
            match self.wildcard.state {
                WildcardState::Init => {
                    let result = self.init_wc_data(conn);
                    if self.wildcard.state == WildcardState::Clean {
                        // Only a listing was requested.
                        return result;
                    }
                    self.wildcard.state = if result.is_err() {
                        WildcardState::Error
                    } else {
                        WildcardState::Matching
                    };
                    return result;
                }

                WildcardState::Matching => {
                    // The LIST response has been parsed (the caller fed it via
                    // `wc_parse_feed`); the normal write path is already in
                    // effect in this port.
                    self.wildcard.state = WildcardState::Downloading;

                    if self.wildcard.parse_error.is_some() {
                        // A parse error is surfaced at CLEAN.
                        self.wildcard.state = WildcardState::Clean;
                        continue;
                    }
                    if self.wildcard.filelist.is_empty() {
                        // No file matched the pattern.
                        self.wildcard.state = WildcardState::Clean;
                        return Err(Error::from(CurlCode::RemoteFileNotFound));
                    }
                    continue;
                }

                WildcardState::Downloading => {
                    // Take the first matched file.
                    let finfo = self
                        .wildcard
                        .filelist
                        .front()
                        .cloned()
                        .expect("filelist is non-empty in DOWNLOADING");

                    // Swap ftp->path to "<base><filename>".
                    let tmp_path = format!("{}{}", self.wildcard.path, finfo.filename);
                    self.ftp.pathalloc = Some(tmp_path.clone());
                    self.ftp.path = tmp_path;

                    tracing::info!("Wildcard - START of \"{}\"", finfo.filename);
                    // (data->set.chunk_bgn is a CLI-owned callback; skipped here.)

                    if finfo.filetype != FileType::File {
                        // Only regular files are transferred; skip the rest.
                        self.wildcard.state = WildcardState::Skip;
                        continue;
                    }

                    if finfo.flags & CURLFINFOFLAG_KNOWN_SIZE != 0 {
                        self.known_filesize = finfo.size.unwrap_or(0) as i64;
                    }

                    let parse_path = self.ftp.path.clone();
                    let (fm, up, reuse, tr) = (
                        self.params.filemethod,
                        self.params.upload,
                        conn.bits.reuse,
                        self.ftp.transfer,
                    );
                    self.parse_url_path(&parse_path, fm, up, reuse, tr)?;

                    // Done with this file's info.
                    self.wildcard.filelist.pop_front();

                    if self.wildcard.filelist.is_empty() {
                        // Last file: after its transfer, do_engine is entered once
                        // more and CLEAN skips a further transfer.
                        self.wildcard.state = WildcardState::Clean;
                    }
                    return Ok(());
                }

                WildcardState::Skip => {
                    // (data->set.chunk_end is a CLI-owned callback; skipped here.)
                    self.wildcard.filelist.pop_front();
                    self.wildcard.state = if self.wildcard.filelist.is_empty() {
                        WildcardState::Clean
                    } else {
                        WildcardState::Downloading
                    };
                    continue;
                }

                WildcardState::Clean => {
                    let result = match self.wildcard.parse_error {
                        Some(code) => Err(Error::from(code)),
                        None => Ok(()),
                    };
                    self.wildcard.state = if result.is_err() {
                        WildcardState::Error
                    } else {
                        WildcardState::Done
                    };
                    return result;
                }

                WildcardState::Done | WildcardState::Error => {
                    // The parser (curl's ftpwc) is dropped by Rust ownership when
                    // the FtpConn/wildcard is torn down; nothing to free here.
                    return Ok(());
                }
            }
        }
    }
}

// ===========================================================================
// Pollset contributions (← `ftp_pollset` / `ftp_domore_pollset`, `lib/ftp.c`
// L768-801).
//
// These engine methods carry curl's exact socket-interest logic; the thin
// [`FtpHandler`] trait methods delegate here once the driver exposes the live
// [`FtpConn`] + [`Connection`] through [`TransferCtx`] (deferred, matching the
// sibling `smb`/`dict` handlers).
// ===========================================================================

impl FtpConn {
    /// Contribute control-channel socket readiness for the "protocol connect"
    /// and "doing" phases (← `ftp_pollset`, `lib/ftp.c` L768-773).
    ///
    /// Delegates to the ping-pong pollset ([`PingPong::pollset`], curl's
    /// `Curl_pp_pollset`): write interest while there are buffered command bytes
    /// to flush, read interest while awaiting the response.
    ///
    /// `pub` (like the sibling engine entry points [`run_connect`](Self::run_connect)
    /// / [`do_engine`](Self::do_engine)): the driver calls it once it exposes the
    /// live [`FtpConn`] + [`Connection`] through [`TransferCtx`].
    pub fn proto_pollset_engine(&self, conn: &Connection, ps: &mut Pollset) {
        self.pp.pollset(conn, ps);
    }

    /// Contribute socket readiness for the DO_MORE phase (← `ftp_domore_pollset`,
    /// `lib/ftp.c` L776-801).
    ///
    /// In [`FtpState::Stop`] the control channel is idle and we are waiting on
    /// the secondary (data) connection, so we request read interest on the
    /// primary socket. An *unconnected* secondary contributes its own socket via
    /// its filter chain's `adjust_pollset`, so it is deliberately not added
    /// here. Otherwise ordinary control-channel commands are in flight and we
    /// delegate to the ping-pong pollset.
    ///
    /// `pub` (like the sibling engine entry points [`run_do_more`](Self::run_do_more)
    /// / [`done_engine`](Self::done_engine)): the driver calls it during DO_MORE
    /// once it exposes the live [`FtpConn`] + [`Connection`] through [`TransferCtx`].
    pub fn domore_pollset_engine(&self, conn: &Connection, ps: &mut Pollset) {
        tracing::trace!(state = self.state.as_str(), "ftp_domore_pollset()");
        if self.state == FtpState::Stop {
            if let Some(fd) = conn.get_first_socket() {
                ps.add_in(fd);
            }
        } else {
            self.pp.pollset(conn, ps);
        }
    }
}

// ===========================================================================
// FtpHandler — the URL-scheme behavior vtable (← `struct Curl_protocol
// Curl_protocol_ftp`, `lib/ftp.c` L4323-4340).
//
// A zero-sized singleton shared by both `ftp` and `ftps` (curl shares the
// `ftp_*` functions across `Curl_protocol_ftp` and `Curl_protocol_ftps`; the
// schemes differ only in `PROTOPT_*` flags and default port, never behavior).
// ===========================================================================

/// The FTP/FTPS protocol behavior (← `Curl_protocol_ftp`).
///
/// Each C vtable slot maps to an engine method on [`FtpConn`] that carries the
/// real, unit-tested logic; the thin trait methods below hold curl's exact
/// ctx-independent behavior and defer the ctx-dependent phases to the engine
/// once the driver ([`crate::transfer`] / [`crate::multi`]) exposes the live
/// [`FtpConn`] + [`Connection`] through [`TransferCtx`] (deferred exactly as in
/// the sibling `smb`/`dict` handlers — `TransferCtx` is `#[non_exhaustive]`
/// precisely because it grows as those driver modules land):
///
/// | curl vtable slot   | engine realization                                          |
/// |--------------------|-------------------------------------------------------------|
/// | `setup_connection` | [`FtpConn::begin_transfer`] + `type_url_check` + field init |
/// | `do_it`            | [`FtpConn::do_engine`] (← `ftp_do`) — returns `*done=FALSE` |
/// | `done`             | [`FtpConn::done_engine`] (← `ftp_done`)                     |
/// | `do_more`          | [`FtpConn::run_do_more`] (← `ftp_do_more`)                  |
/// | `connect_it`       | [`FtpConn::run_connect`] (← `ftp_connect`)                  |
/// | `connecting`       | [`FtpConn::doing_engine`]-style single step (← `ftp_multi_statemach`) |
/// | `doing`            | [`FtpConn::doing_engine`] (← `ftp_doing`)                   |
/// | `proto_pollset`    | [`FtpConn::proto_pollset_engine`] (← `ftp_pollset`)         |
/// | `doing_pollset`    | [`FtpConn::proto_pollset_engine`] (← `ftp_pollset`)         |
/// | `domore_pollset`   | [`FtpConn::domore_pollset_engine`] (← `ftp_domore_pollset`) |
/// | `disconnect`       | [`FtpConn::disconnect_engine`] (← `ftp_disconnect`)         |
/// | `connection_check` | `ZERO_NULL` → default `CONNRESULT_NONE`                     |
/// | `write_resp` / `write_resp_hd` / `attach` / `follow` / `perform_pollset` | `ZERO_NULL` → default |
#[derive(Debug, Clone, Copy, Default)]
pub struct FtpHandler;

impl Protocol for FtpHandler {
    /// **Required "DO" phase** (← `ftp_do`, `lib/ftp.c` L4064-4112). FTP never
    /// completes the DO phase synchronously: it establishes the data connection
    /// (PASV/PORT) and hands the transfer to the DO_MORE / DOING phases. `ftp_do`
    /// leaves `*done = FALSE`, so this returns `Ok(false)` — "continue via
    /// [`doing`](Protocol::doing) / [`do_more`](Protocol::do_more)". The real
    /// work lives in [`FtpConn::do_engine`].
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(async { Ok(false) })
    }

    /// Transport-level connect step (← `ftp_connect`, `lib/ftp.c` L3392-3431).
    /// `ftp_connect` initializes the ping-pong control channel and enters
    /// `FTP_WAIT220`; the greeting → login → PWD/SYST exchange runs in
    /// `connecting` ([`FtpConn::run_connect`] drives it to completion). The
    /// protocol connect is thus never complete here; returning `Ok(false)`
    /// continues via [`connecting`](Protocol::connecting).
    fn connect<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(async { Ok(false) })
    }

    /// Optional second half of the DO phase (← `ftp_do_more`, `lib/ftp.c`
    /// L2130-2295). FTP is the archetypal `PROTOPT_DUAL` protocol: after
    /// PASV/PORT in the DO phase, the data connection is established and the
    /// transfer performed here. The `i32` mirrors curl's `*completep`
    /// out-parameter (`0` = not yet complete). The real work lives in
    /// [`FtpConn::run_do_more`] / [`FtpConn::do_more_engine`]; until the driver
    /// wires the live engine through [`TransferCtx`], this reports `0`
    /// ("not complete"), matching curl's initial `*completep = 0`.
    fn do_more<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, i32> {
        let _ = ctx;
        Box::pin(async { Ok(0) })
    }

    /// **Required** teardown of a completed (or, if `premature`, aborted)
    /// transfer (← `ftp_done`, `lib/ftp.c` L3475-3694). The real logic —
    /// benign-status classification, wildcard cleanup, `prevpath` remembering,
    /// the `ABOR` on a partial download, the final `226`/`250`/`552` read, the
    /// upload/download partial-file checks, and `POSTQUOTE` — lives in
    /// [`FtpConn::done_engine`], which needs the transfer's byte counts and the
    /// live [`Connection`]. Until the driver exposes those through
    /// [`TransferCtx`], the thin handler is a no-op that defers to the engine.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, status, premature);
        Box::pin(async { Ok(()) })
    }

    /// Protocol-dependent disconnection (← `ftp_disconnect`, `lib/ftp.c`
    /// L4156-4178): mark shutdown, send `QUIT`, and drain the response. The real
    /// logic lives in [`FtpConn::disconnect_engine`] (which needs the live
    /// [`Connection`]); until the driver exposes it through [`TransferCtx`] this
    /// defers. `dead_connection` skips the graceful `QUIT` chatter.
    fn disconnect<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        dead_connection: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, dead_connection);
        Box::pin(async { Ok(()) })
    }
}

/// The single, shared FTP/FTPS handler instance (← the `&Curl_protocol_ftp`
/// vtable pointer). Both [`SCHEME_FTP`](crate::protocols::SCHEME_FTP) and
/// [`SCHEME_FTPS`](crate::protocols::SCHEME_FTPS) reference this static; the
/// schemes differ only in their `PROTOPT_*` flags (FTPS adds `PROTOPT_SSL`) and
/// default port (21 vs 990), never in behavior — exactly as curl shares the
/// `ftp_*` functions across `Curl_protocol_ftp` and `Curl_protocol_ftps`.
pub static HANDLER: FtpHandler = FtpHandler;

// ===========================================================================
// Tests. These exercise the byte-exact response parsers, the `FtpState`
// diagnostic-name mapping, the URL-path splitting, the wildcard `fnmatch`, the
// data-channel (PASV/EPSV, PORT/EPRT) command formatting and reply parsing, the
// control-channel error mappings, and a full login→PWD→SYST handshake driven
// through the ping-pong engine over an in-memory mock connection filter (no
// external daemon), mirroring the sibling `smb`/`pingpong` test harnesses.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::{CfFuture, FilterCtx, QueryCtx, QueryOut};
    use crate::conn::{CfQuery, CfType, ConnectionFilter, FilterChain, Scheme, Transport};
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // In-memory mock connection filter (canned bytes on recv, capture on send),
    // a leaf terminating the chain exactly like the `pingpong` test harness.
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct MockIo {
        /// Bytes handed to `recv`, consumed from the front (server → client).
        to_deliver: Vec<u8>,
        /// Bytes accepted by `send`, retained for assertion (client → server).
        captured: Vec<u8>,
    }

    struct MockFilter {
        io: Arc<Mutex<MockIo>>,
        fd: i32,
    }

    impl ConnectionFilter for MockFilter {
        fn name(&self) -> &'static str {
            "MOCK"
        }
        fn cf_type(&self) -> CfType {
            CfType::IP_CONNECT
        }
        fn send<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a [u8],
            _eos: bool,
        ) -> CfFuture<'a, Result<usize>> {
            let io = Arc::clone(&self.io);
            let data = buf.to_vec();
            Box::pin(async move {
                io.lock().unwrap().captured.extend_from_slice(&data);
                Ok(data.len())
            })
        }
        fn recv<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a mut [u8],
        ) -> CfFuture<'a, Result<usize>> {
            let io = Arc::clone(&self.io);
            Box::pin(async move {
                let mut g = io.lock().unwrap();
                let n = g.to_deliver.len().min(buf.len());
                buf[..n].copy_from_slice(&g.to_deliver[..n]);
                g.to_deliver.drain(..n);
                Ok(n)
            })
        }
        fn data_pending(&self, _cx: &QueryCtx<'_>) -> bool {
            !self.io.lock().unwrap().to_deliver.is_empty()
        }
        fn query(&self, _cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
            match query {
                CfQuery::Socket => {
                    *out = QueryOut::Socket(self.fd);
                    Ok(())
                }
                CfQuery::Transport => {
                    *out = QueryOut::Transport(Transport::Tcp);
                    Ok(())
                }
                _ => Err(Error::Code(CurlCode::UnknownOption)),
            }
        }
    }

    /// A network connection whose primary chain is the given mock filter, with
    /// the credentials FTP login needs.
    fn conn_with(io: Arc<Mutex<MockIo>>, fd: i32) -> Connection {
        let mut conn = Connection::new(Scheme::new("ftp", 21), "example.com", 21);
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(MockFilter { io, fd }));
        conn.cfilter[FIRSTSOCKET] = Some(chain);
        conn.user = Some("u".into());
        conn.passwd = Some("p".into());
        conn
    }

    /// A freshly-initialised standalone ping-pong engine (response window armed).
    fn init_pp() -> PingPong {
        let mut pp = PingPong::new();
        pp.init(Instant::now());
        pp
    }

    /// A fresh per-connection FTP state with a per-transfer context installed.
    fn fresh_ftpc() -> FtpConn {
        let mut c = FtpConn::new();
        c.begin_transfer(Ftp::default(), FtpParams::default());
        c
    }

    /// The commands captured by the mock server, as a UTF-8 string.
    fn captured(io: &Arc<Mutex<MockIo>>) -> String {
        String::from_utf8(io.lock().unwrap().captured.clone()).unwrap()
    }

    /// Feed `bytes` to the mock and read exactly one response into `pp` (via the
    /// real [`PingPong::readresp`] path, populating [`PingPong::response_line`]),
    /// returning the parsed status code.
    async fn feed_one(
        pp: &mut PingPong,
        ftpc: &mut FtpConn,
        conn: &mut Connection,
        io: &Arc<Mutex<MockIo>>,
        bytes: &[u8],
    ) -> i32 {
        io.lock().unwrap().to_deliver.extend_from_slice(bytes);
        let mut code = 0i32;
        let mut nread = 0usize;
        pp.readresp(ftpc, conn, FIRSTSOCKET, &mut code, &mut nread)
            .await
            .unwrap();
        code
    }

    // -----------------------------------------------------------------------
    // FtpState diagnostic-name mapping (← ftp_state_names[], --trace ABI).
    // -----------------------------------------------------------------------

    #[test]
    fn state_names_match_curl_verbatim() {
        // The 37 named states plus the unnamed FTP_LAST sentinel.
        assert_eq!(FTP_STATE_NAMES.len(), 37);
        assert_eq!(FtpState::Stop.as_str(), "STOP");
        assert_eq!(FtpState::Wait220.as_str(), "WAIT220");
        assert_eq!(FtpState::Auth.as_str(), "AUTH");
        assert_eq!(FtpState::User.as_str(), "USER");
        assert_eq!(FtpState::Pass.as_str(), "PASS");
        assert_eq!(FtpState::Pbsz.as_str(), "PBSZ");
        assert_eq!(FtpState::Prot.as_str(), "PROT");
        assert_eq!(FtpState::Ccc.as_str(), "CCC");
        assert_eq!(FtpState::Pwd.as_str(), "PWD");
        assert_eq!(FtpState::Syst.as_str(), "SYST");
        assert_eq!(FtpState::Namefmt.as_str(), "NAMEFMT");
        assert_eq!(FtpState::RetrPrequote.as_str(), "RETR_PREQUOTE");
        assert_eq!(FtpState::StorPrequote.as_str(), "STOR_PREQUOTE");
        assert_eq!(FtpState::ListPrequote.as_str(), "LIST_PREQUOTE");
        assert_eq!(FtpState::Postquote.as_str(), "POSTQUOTE");
        assert_eq!(FtpState::Cwd.as_str(), "CWD");
        assert_eq!(FtpState::Mdtm.as_str(), "MDTM");
        assert_eq!(FtpState::RetrListType.as_str(), "RETR_LIST_TYPE");
        assert_eq!(FtpState::RetrSize.as_str(), "RETR_SIZE");
        assert_eq!(FtpState::StorSize.as_str(), "STOR_SIZE");
        assert_eq!(FtpState::RetrRest.as_str(), "RETR_REST");
        assert_eq!(FtpState::Port.as_str(), "PORT");
        assert_eq!(FtpState::Pret.as_str(), "PRET");
        assert_eq!(FtpState::Pasv.as_str(), "PASV");
        assert_eq!(FtpState::Retr.as_str(), "RETR");
        assert_eq!(FtpState::Stor.as_str(), "STOR");
        assert_eq!(FtpState::Quit.as_str(), "QUIT");
        // FTP_LAST sentinel has no name in curl's array.
        assert_eq!(FtpState::Last.as_str(), "???");
    }

    #[test]
    fn state_default_is_stop() {
        assert_eq!(FtpState::default(), FtpState::Stop);
    }

    // -----------------------------------------------------------------------
    // endofresp (← ftp_endofresp): single line vs. multi-line NNN-/NNN<sp>.
    // -----------------------------------------------------------------------

    #[test]
    fn endofresp_single_line_sets_code() {
        let mut ftpc = fresh_ftpc();
        let mut code = 0;
        assert!(ftpc.endofresp(b"220 Welcome\r\n", &mut code));
        assert_eq!(code, 220);
    }

    #[test]
    fn endofresp_multiline_intermediate_then_terminator() {
        let mut ftpc = fresh_ftpc();
        let mut code = -1;
        // First line of a multi-line block: `NNN-` is NOT the end.
        assert!(!ftpc.endofresp(b"220-first line\r\n", &mut code));
        assert_eq!(code, -1, "code must remain unset on a continuation line");
        // A free-text continuation line is also not the end.
        assert!(!ftpc.endofresp(b"  more banner text\r\n", &mut code));
        // Terminator repeats the code with a SPACE: this ends the response.
        assert!(ftpc.endofresp(b"220 last line\r\n", &mut code));
        assert_eq!(code, 220);
    }

    #[test]
    fn endofresp_hyphen_after_code_is_not_terminal() {
        let mut ftpc = fresh_ftpc();
        let mut code = 0;
        // `250-` (hyphen, not space) is a continuation, not a terminator.
        assert!(!ftpc.endofresp(b"250-directory listing\r\n", &mut code));
    }

    #[test]
    fn endofresp_too_short_or_nondigit_is_false() {
        let mut ftpc = fresh_ftpc();
        let mut code = 0;
        assert!(!ftpc.endofresp(b"22 \r\n", &mut code)); // fewer than 3 digits
        assert!(!ftpc.endofresp(b"abc def\r\n", &mut code)); // non-digit
        assert!(!ftpc.endofresp(b"20 x\r\n", &mut code)); // len>3 but not 3 digits
    }

    // -----------------------------------------------------------------------
    // is_statuscode (← the STATUSCODE macro).
    // -----------------------------------------------------------------------

    #[test]
    fn is_statuscode_requires_three_leading_digits() {
        assert!(is_statuscode(b"220 x"));
        assert!(is_statuscode(b"500"));
        assert!(!is_statuscode(b"2 x"));
        assert!(!is_statuscode(b"a20"));
        assert!(!is_statuscode(b"2a0"));
    }

    // -----------------------------------------------------------------------
    // URL-path splitting (← ftp_parse_url_path): MULTICWD / SINGLECWD / NOCWD.
    // -----------------------------------------------------------------------

    #[test]
    fn parse_url_path_multicwd_splits_every_component() {
        let mut ftpc = fresh_ftpc();
        ftpc.parse_url_path(
            "a/b/c",
            CurlFtpFile::Multicwd,
            false,
            false,
            PpTransfer::Body,
        )
        .unwrap();
        assert_eq!(ftpc.dirs, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(ftpc.dirdepth, 2);
        assert_eq!(ftpc.file.as_deref(), Some("c"));
    }

    #[test]
    fn parse_url_path_multicwd_leading_slash_is_its_own_dir() {
        let mut ftpc = fresh_ftpc();
        ftpc.parse_url_path(
            "/a/file",
            CurlFtpFile::Multicwd,
            false,
            false,
            PpTransfer::Body,
        )
        .unwrap();
        // The leading '/' becomes a directory component of its own.
        assert_eq!(ftpc.dirs, vec!["/".to_string(), "a".to_string()]);
        assert_eq!(ftpc.file.as_deref(), Some("file"));
    }

    #[test]
    fn parse_url_path_singlecwd_single_dir() {
        let mut ftpc = fresh_ftpc();
        ftpc.parse_url_path(
            "a/b/c",
            CurlFtpFile::Singlecwd,
            false,
            false,
            PpTransfer::Body,
        )
        .unwrap();
        assert_eq!(ftpc.dirs, vec!["a/b".to_string()]);
        assert_eq!(ftpc.dirdepth, 1);
        assert_eq!(ftpc.file.as_deref(), Some("c"));
    }

    #[test]
    fn parse_url_path_nocwd_absolute_marks_cwddone() {
        let mut ftpc = fresh_ftpc();
        ftpc.parse_url_path(
            "/dir/file.txt",
            CurlFtpFile::Nocwd,
            false,
            false,
            PpTransfer::Body,
        )
        .unwrap();
        // NOCWD + absolute path: no CWD sequence is needed.
        assert!(ftpc.cwddone);
        assert_eq!(ftpc.file.as_deref(), Some("/dir/file.txt"));
    }

    #[test]
    fn parse_url_path_trailing_slash_has_no_file() {
        let mut ftpc = fresh_ftpc();
        ftpc.parse_url_path(
            "a/b/",
            CurlFtpFile::Multicwd,
            false,
            false,
            PpTransfer::Body,
        )
        .unwrap();
        assert_eq!(ftpc.file, None);
    }

    #[test]
    fn parse_url_path_upload_without_filename_is_malformed() {
        let mut ftpc = fresh_ftpc();
        let err = ftpc
            .parse_url_path("a/b/", CurlFtpFile::Multicwd, true, false, PpTransfer::Body)
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    // -----------------------------------------------------------------------
    // type_url_check (← type_url_check): ;type=a / ;type=d / ;type=i.
    // -----------------------------------------------------------------------

    #[test]
    fn type_url_check_ascii_directory_binary_none() {
        let mut p = String::from("file.txt;type=a");
        let t = type_url_check(&mut p);
        assert!(t.prefer_ascii && !t.list_only);
        assert_eq!(p, "file.txt");

        let mut p = String::from("dir/;type=d");
        let t = type_url_check(&mut p);
        assert!(t.list_only && !t.prefer_ascii);
        assert_eq!(p, "dir/");

        let mut p = String::from("blob;type=i");
        let t = type_url_check(&mut p);
        assert!(!t.prefer_ascii && !t.list_only);
        assert_eq!(p, "blob");

        // Case-insensitive on the type code.
        let mut p = String::from("f;type=A");
        assert!(type_url_check(&mut p).prefer_ascii);

        // No suffix: unchanged, binary.
        let mut p = String::from("plain");
        let t = type_url_check(&mut p);
        assert!(!t.prefer_ascii && !t.list_only);
        assert_eq!(p, "plain");
    }

    #[test]
    fn numof_slashes_counts_separators() {
        assert_eq!(numof_slashes("a/b/c"), 2);
        assert_eq!(numof_slashes("/a/b/"), 3);
        assert_eq!(numof_slashes("nofile"), 0);
    }

    // -----------------------------------------------------------------------
    // PASV / EPSV reply parsing (← match_pasv_6nums / scan_pasv_227 /
    // parse_epsv_229).
    // -----------------------------------------------------------------------

    #[test]
    fn scan_pasv_227_extracts_sextet() {
        // Text after the "227 " code (the caller passes line[4..]).
        let ip = scan_pasv_227(b"Entering Passive Mode (192,168,0,1,4,1).").unwrap();
        assert_eq!(ip, [192, 168, 0, 1, 4, 1]);
        // The port is (p1<<8)+p2 = 4*256 + 1 = 1025.
        let port = (((ip[4] << 8) + ip[5]) & 0xffff) as u16;
        assert_eq!(port, 1025);
    }

    #[test]
    fn match_pasv_6nums_rejects_out_of_range() {
        // 256 exceeds the 0xff cap curl enforces per octet.
        assert!(match_pasv_6nums(b"1,2,3,256,4,1").is_none());
        assert!(match_pasv_6nums(b"1,2,3,4,5").is_none()); // too few
        assert_eq!(
            match_pasv_6nums(b"10,0,0,1,200,80").unwrap(),
            [10, 0, 0, 1, 200, 80]
        );
    }

    #[test]
    fn parse_epsv_229_extracts_port() {
        // RFC 2428 EPSV reply body (after "229 "): (|||port|).
        let port = parse_epsv_229(b"Entering Extended Passive Mode (|||6446|)").unwrap();
        assert_eq!(port, 6446);
    }

    #[test]
    fn parse_epsv_229_rejects_bad_delimiters() {
        assert!(parse_epsv_229(b"nonsense without parens").is_none());
        assert!(parse_epsv_229(b"(|x|6446|)").is_none()); // inconsistent separators
    }

    // -----------------------------------------------------------------------
    // SIZE (213) and 150/125 in-reply size parsing.
    // -----------------------------------------------------------------------

    #[test]
    fn parse_size_213_reads_trailing_number() {
        assert_eq!(parse_size_213(b"213 1024\r\n"), 1024);
        assert_eq!(parse_size_213(b"213 999999"), 999_999);
        assert_eq!(parse_size_213(b"213 "), -1); // no digits
    }

    #[test]
    fn parse_get_size_finds_bytes_token() {
        assert_eq!(
            parse_get_size(b"150 Opening data connection for x (4096 bytes)"),
            Some(4096)
        );
        assert_eq!(parse_get_size(b"150 no size here"), None);
    }

    // -----------------------------------------------------------------------
    // PWD (257) entry-path and SYST (215) OS parsing.
    // -----------------------------------------------------------------------

    #[test]
    fn parse_pwd_entrypath_simple_and_quote_doubling() {
        assert_eq!(
            parse_pwd_entrypath(b"257 \"/home/user\" is the current directory"),
            Some("/home/user".to_string())
        );
        // RFC 959 quote-doubling: "" encodes a literal double quote.
        assert_eq!(
            parse_pwd_entrypath(b"257 \"a\"\"b\" is current"),
            Some("a\"b".to_string())
        );
        // No closing quote → None.
        assert_eq!(parse_pwd_entrypath(b"257 no quotes here"), None);
    }

    #[test]
    fn parse_syst_os_first_token() {
        assert_eq!(
            parse_syst_os(b"215 UNIX Type: L8"),
            Some("UNIX".to_string())
        );
        assert_eq!(
            parse_syst_os(b"215 Windows_NT version 10"),
            Some("Windows_NT".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // MDTM date parsing (← ftp_213_date + civil_to_epoch).
    // -----------------------------------------------------------------------

    #[test]
    fn ftp_213_date_parses_fields() {
        assert_eq!(
            ftp_213_date(b"19980615123456"),
            Some((1998, 6, 15, 12, 34, 56))
        );
        assert!(ftp_213_date(b"1998").is_none()); // too short
        assert!(ftp_213_date(b"19981315000000").is_none()); // month 13 invalid
    }

    #[test]
    fn civil_to_epoch_known_anchors() {
        assert_eq!(civil_to_epoch(1970, 1, 1, 0, 0, 0), 0);
        assert_eq!(civil_to_epoch(2000, 1, 1, 0, 0, 0), 946_684_800);
        // 1998-06-15 12:34:56 UTC.
        assert_eq!(civil_to_epoch(1998, 6, 15, 12, 34, 56), 897_914_096);
    }

    // -----------------------------------------------------------------------
    // Wildcard glob matcher (← Curl_fnmatch): literals, *, ?, [set], ranges,
    // negation, POSIX classes, and escapes.
    // -----------------------------------------------------------------------

    #[test]
    fn fnmatch_literal_and_question_mark() {
        assert!(fnmatch(b"file.txt", b"file.txt"));
        assert!(!fnmatch(b"file.txt", b"file.dat"));
        assert!(fnmatch(b"fi?e", b"file"));
        assert!(!fnmatch(b"fi?e", b"fille")); // '?' is exactly one char
    }

    #[test]
    fn fnmatch_star_backtracking() {
        assert!(fnmatch(b"*", b"anything"));
        assert!(fnmatch(b"*.txt", b"report.txt"));
        assert!(fnmatch(b"a*b*c", b"axxbyyc"));
        assert!(fnmatch(b"*.txt", b".txt")); // star matches empty
        assert!(!fnmatch(b"*.txt", b"file.txtx"));
        assert!(fnmatch(b"file*", b"file"));
    }

    #[test]
    fn fnmatch_charset_ranges_and_negation() {
        assert!(fnmatch(b"file[0-9].log", b"file7.log"));
        assert!(!fnmatch(b"file[0-9].log", b"filex.log"));
        assert!(fnmatch(b"[abc]", b"b"));
        assert!(!fnmatch(b"[abc]", b"d"));
        // Negated set.
        assert!(fnmatch(b"[!0-9]", b"a"));
        assert!(!fnmatch(b"[!0-9]", b"5"));
        assert!(fnmatch(b"[^x]", b"y"));
    }

    #[test]
    fn fnmatch_posix_class() {
        assert!(fnmatch(b"[[:digit:]]", b"5"));
        assert!(!fnmatch(b"[[:digit:]]", b"a"));
        assert!(fnmatch(b"[[:alpha:]]*", b"abc123"));
        assert!(fnmatch(b"[[:upper:]]", b"Q"));
        assert!(!fnmatch(b"[[:upper:]]", b"q"));
    }

    #[test]
    fn fnmatch_escape_and_malformed_bracket() {
        // Escaped metacharacters match literally.
        assert!(fnmatch(b"a\\*b", b"a*b"));
        assert!(!fnmatch(b"a\\*b", b"axb"));
        // A '[' with no closing ']' is treated as a literal '['.
        assert!(fnmatch(b"a[b", b"a[b"));
    }

    // -----------------------------------------------------------------------
    // Control-channel response handlers driven with a live pp + mock conn.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn user_resp_331_sends_pass() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 7);
        let mut pp = init_pp();
        let mut ftpc = fresh_ftpc();
        ftpc.set_state(FtpState::User);

        ftpc.user_resp(&mut pp, &mut conn, 331).unwrap();
        assert_eq!(ftpc.state(), FtpState::Pass);

        // Flush the queued command to the mock and confirm it is `PASS p`.
        pp.flushsend(&mut conn, Instant::now()).await.unwrap();
        assert_eq!(captured(&io), "PASS p\r\n");
    }

    #[tokio::test]
    async fn user_resp_230_logs_in_and_sends_pwd() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 7);
        let mut pp = init_pp();
        let mut ftpc = fresh_ftpc();
        ftpc.set_state(FtpState::User);

        // 230 = already logged in; with no TLS this goes straight to PWD.
        ftpc.user_resp(&mut pp, &mut conn, 230).unwrap();
        assert_eq!(ftpc.state(), FtpState::Pwd);
        pp.flushsend(&mut conn, Instant::now()).await.unwrap();
        assert_eq!(captured(&io), "PWD\r\n");
    }

    #[test]
    fn user_resp_530_is_login_denied() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 7);
        let mut pp = init_pp();
        let mut ftpc = fresh_ftpc();
        ftpc.set_state(FtpState::Pass);
        let err = ftpc.user_resp(&mut pp, &mut conn, 530).unwrap_err();
        assert_eq!(err.code(), CurlCode::LoginDenied);
    }

    // -----------------------------------------------------------------------
    // PASV (227) / EPSV (229) reply handling sets the data endpoint.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pasv_resp_227_sets_secondary_endpoint() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 7);
        let mut pp = init_pp();
        let mut ftpc = fresh_ftpc();
        // count1 == 1 selects the PASV (227) branch.
        ftpc.count1 = 1;
        ftpc.set_state(FtpState::Pasv);

        let code = feed_one(
            &mut pp,
            &mut ftpc,
            &mut conn,
            &io,
            b"227 Entering Passive Mode (192,168,0,1,4,1).\r\n",
        )
        .await;
        assert_eq!(code, 227);

        ftpc.pasv_resp(&mut pp, &mut conn, code).unwrap();
        assert_eq!(conn.secondaryhostname.as_deref(), Some("192.168.0.1"));
        assert_eq!(conn.secondary_port, 1025); // (4<<8)+1
        assert!(conn.bits.do_more);
        assert_eq!(ftpc.state(), FtpState::Stop);
    }

    #[tokio::test]
    async fn pasv_resp_229_epsv_uses_control_host() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 7);
        let mut pp = init_pp();
        let mut ftpc = fresh_ftpc();
        // count1 == 0 selects the EPSV (229) branch.
        ftpc.count1 = 0;
        ftpc.set_state(FtpState::Pasv);

        let code = feed_one(
            &mut pp,
            &mut ftpc,
            &mut conn,
            &io,
            b"229 Entering Extended Passive Mode (|||6446|)\r\n",
        )
        .await;
        assert_eq!(code, 229);

        ftpc.pasv_resp(&mut pp, &mut conn, code).unwrap();
        // EPSV reuses the control connection host (control_addr → conn.host.name).
        assert_eq!(conn.secondaryhostname.as_deref(), Some("example.com"));
        assert_eq!(conn.secondary_port, 6446);
    }

    #[tokio::test]
    async fn pasv_resp_227_bad_format_is_weird_227() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 7);
        let mut pp = init_pp();
        let mut ftpc = fresh_ftpc();
        ftpc.count1 = 1;
        ftpc.set_state(FtpState::Pasv);

        let code = feed_one(
            &mut pp,
            &mut ftpc,
            &mut conn,
            &io,
            b"227 no numbers here\r\n",
        )
        .await;
        let err = ftpc.pasv_resp(&mut pp, &mut conn, code).unwrap_err();
        assert_eq!(err.code(), CurlCode::FtpWeird227Format);
    }

    // -----------------------------------------------------------------------
    // Active mode: EPRT / PORT command formatting (← ftp_state_use_port).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn state_use_port_formats_eprt() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 7);
        conn.secondaryhostname = Some("192.168.0.5".into());
        conn.secondary_port = 20000;
        conn.bits.ftp_use_eprt = true;
        let mut pp = init_pp();
        let mut ftpc = fresh_ftpc();

        ftpc.state_use_port(&mut pp, &mut conn, FtpPort::Eprt)
            .unwrap();
        assert_eq!(ftpc.state(), FtpState::Port);
        pp.flushsend(&mut conn, Instant::now()).await.unwrap();
        // IPv4 → address family 1.
        assert_eq!(captured(&io), "EPRT |1|192.168.0.5|20000|\r\n");
    }

    #[tokio::test]
    async fn state_use_port_falls_back_to_port() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 7);
        conn.secondaryhostname = Some("192.168.0.5".into());
        conn.secondary_port = 20000;
        conn.bits.ftp_use_eprt = false; // EPRT disabled → PORT
        conn.bits.ipv6 = false;
        let mut pp = init_pp();
        let mut ftpc = fresh_ftpc();

        ftpc.state_use_port(&mut pp, &mut conn, FtpPort::Eprt)
            .unwrap();
        pp.flushsend(&mut conn, Instant::now()).await.unwrap();
        // 20000 = 78*256 + 32 → "PORT h,h,h,h,78,32".
        assert_eq!(captured(&io), "PORT 192,168,0,5,78,32\r\n");
    }

    // -----------------------------------------------------------------------
    // SIZE error mapping (← ftp_state_size_resp): 550 for a download probe.
    // -----------------------------------------------------------------------

    #[test]
    fn size_resp_550_download_is_remote_file_not_found() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 7);
        let mut pp = init_pp();
        let mut ftpc = fresh_ftpc();
        let err = ftpc
            .size_resp(&mut pp, &mut conn, 550, FtpState::RetrSize)
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::RemoteFileNotFound);
    }

    // -----------------------------------------------------------------------
    // PRET failure mapping (← the FTP_PRET arm): non-200 → CURLE_FTP_PRET_FAILED.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pret_failure_maps_to_pret_failed() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 7);
        let mut pp = init_pp();
        let mut ftpc = fresh_ftpc();
        ftpc.set_state(FtpState::Pret);
        let err = ftpc.dispatch(&mut pp, &mut conn, 500).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::FtpPretFailed);
    }

    // -----------------------------------------------------------------------
    // Wildcard: wc_parse_feed drives FtpListParser and fnmatch-filters names.
    // -----------------------------------------------------------------------

    #[test]
    fn wc_parse_feed_filters_by_pattern() {
        let mut ftpc = fresh_ftpc();
        ftpc.wildcard.pattern = Some("*.txt".to_string());

        // A small Unix listing: two .txt files and one .dat.
        let listing = b"-rw-r--r-- 1 u g 5 Jan 1 2020 file1.txt\r\n\
                        -rw-r--r-- 1 u g 5 Jan 1 2020 file2.dat\r\n\
                        -rw-r--r-- 1 u g 5 Jan 1 2020 notes.txt\r\n";
        ftpc.wc_parse_feed(listing).unwrap();
        ftpc.wc_parse_end().unwrap();

        let names: Vec<String> = ftpc
            .wildcard
            .filelist
            .iter()
            .map(|f| f.filename.clone())
            .collect();
        assert_eq!(
            names,
            vec!["file1.txt".to_string(), "notes.txt".to_string()]
        );
    }

    // -----------------------------------------------------------------------
    // Full connect handshake driven through the ping-pong engine over the mock:
    // greeting → USER → PASS → PWD → SYST → FTP_STOP (← ftp_connect).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn run_connect_full_login_pwd_syst() {
        // A non-absolute PWD path triggers the SYST probe (OS/400 name quirk).
        let responses = b"220 Welcome\r\n\
                          331 Password required\r\n\
                          230 Logged in\r\n\
                          257 \"pub\" is the current directory\r\n\
                          215 UNIX Type: L8\r\n";
        let io = Arc::new(Mutex::new(MockIo {
            to_deliver: responses.to_vec(),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io), 9);
        let mut ftpc = fresh_ftpc();

        let connected = ftpc.run_connect(&mut conn).await.unwrap();
        assert!(connected, "connect should complete (FTP_STOP)");
        assert_eq!(ftpc.entrypath.as_deref(), Some("pub"));
        assert_eq!(ftpc.server_os.as_deref(), Some("UNIX"));

        let cmds = captured(&io);
        assert!(cmds.contains("USER u\r\n"), "cmds were: {cmds:?}");
        assert!(cmds.contains("PASS p\r\n"), "cmds were: {cmds:?}");
        assert!(cmds.contains("PWD\r\n"), "cmds were: {cmds:?}");
        assert!(cmds.contains("SYST\r\n"), "cmds were: {cmds:?}");
    }

    #[tokio::test]
    async fn run_connect_weird_greeting_is_error() {
        let io = Arc::new(Mutex::new(MockIo {
            to_deliver: b"500 go away\r\n".to_vec(),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io), 9);
        let mut ftpc = fresh_ftpc();
        let err = ftpc.run_connect(&mut conn).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::WeirdServerReply);
    }

    #[tokio::test]
    async fn run_connect_421_is_timeout() {
        // A 421 at greeting forces FTP_STOP with CURLE_OPERATION_TIMEDOUT.
        let io = Arc::new(Mutex::new(MockIo {
            to_deliver: b"421 Service not available\r\n".to_vec(),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io), 9);
        let mut ftpc = fresh_ftpc();
        let err = ftpc.run_connect(&mut conn).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::OperationTimedout);
    }

    // -----------------------------------------------------------------------
    // Handler registration: FTP/FTPS share one behavior vtable.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn handler_do_it_and_connect_defer_to_phases() {
        let mut ctx = TransferCtx::new();
        // ftp_do leaves *done = FALSE (continue via doing/do_more).
        assert!(!HANDLER.do_it(&mut ctx).await.unwrap());
        // ftp_connect defers the greeting/login to `connecting`.
        assert!(!HANDLER.connect(&mut ctx).await.unwrap());
        // do_more starts "not complete".
        assert_eq!(HANDLER.do_more(&mut ctx).await.unwrap(), 0);
    }

    #[test]
    fn domore_pollset_waits_on_primary_when_stopped() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let conn = conn_with(Arc::clone(&io), 11);
        let ftpc = fresh_ftpc(); // state defaults to FTP_STOP
        let mut ps = Pollset::default();
        ftpc.domore_pollset_engine(&conn, &mut ps);
        // In FTP_STOP we watch the primary socket for the data-connection event.
        assert_eq!(ps.action_of(11), crate::protocols::CURL_POLL_IN);
    }

    // =======================================================================
    // F4-FTP-001: explicit FTPS `AUTH TLS` control-channel upgrade (RFC 4217).
    //
    // Regression coverage for the real defect: `auth_resp` used to flip
    // `ftp_use_control_ssl` to true on a `234` *without ever installing a TLS
    // filter*, so the "encrypted" control channel actually stayed in the clear
    // and `is_ssl(FIRSTSOCKET)` remained false. The fix splices a genuine
    // `rustls` filter via `ssl_cfilter_add` and performs a blocking handshake.
    //
    // This test drives the real login FSM (220 -> AUTH TLS -> 234 -> handshake
    // -> USER/PASS/PBSZ 0/PROT P/PWD) against an in-process server whose control
    // socket is a real `tokio_rustls` acceptor using an ephemeral `rcgen`
    // certificate that the client trusts as a private CA (validation stays ON).
    // If the handshake did not actually occur, the acceptor would never see a
    // ClientHello and the post-`234` dialogue could not complete — so a green
    // result is proof the control channel is genuinely encrypted end to end.
    // =======================================================================
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Installs the process-default aws-lc-rs crypto provider (idempotent).
    fn ftps_ensure_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    /// An ephemeral self-signed `localhost` server config plus its certificate
    /// in PEM, so the client can trust it as a private CA (cert validation on).
    fn ftps_make_server_config() -> (Arc<rustls::ServerConfig>, Vec<u8>) {
        ftps_ensure_provider();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed generation");
        let ca_pem = certified.cert.pem().into_bytes();
        let cert_der = certified.cert.der().clone();
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
        );
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config builds");
        (Arc::new(cfg), ca_pem)
    }

    /// Reads one CRLF-terminated line, byte-by-byte, so no bytes past the line
    /// (e.g. a following TLS ClientHello on the plaintext leg) are consumed.
    /// Returns the line without its trailing CRLF, or `None` at EOF.
    async fn ftps_read_crlf_line<R>(r: &mut R) -> Option<String>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match r.read(&mut byte).await {
                Ok(0) | Err(_) => {
                    return if line.is_empty() {
                        None
                    } else {
                        Some(String::from_utf8_lossy(&line).into_owned())
                    };
                }
                Ok(_) => {
                    line.push(byte[0]);
                    if line.ends_with(b"\r\n") {
                        line.truncate(line.len() - 2);
                        return Some(String::from_utf8_lossy(&line).into_owned());
                    }
                }
            }
        }
    }

    /// The control-channel transport leaf: bridges the FTP filter chain to one
    /// half of an in-memory duplex whose other half is owned by the in-process
    /// FTPS server. The SSL filter added by `ssl_cfilter_add` sits *above* this
    /// leaf and drives its ciphertext through it via `send_next`/`recv_next` —
    /// exactly as the real socket filter sits beneath TLS in production.
    struct FtpsBridgeLeaf {
        stream: tokio::io::DuplexStream,
        fd: i32,
    }

    impl ConnectionFilter for FtpsBridgeLeaf {
        fn name(&self) -> &'static str {
            "FTPS-BRIDGE-TEST"
        }
        fn cf_type(&self) -> CfType {
            CfType::IP_CONNECT
        }
        fn connect<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            _blocking: bool,
        ) -> CfFuture<'a, Result<bool>> {
            // The in-memory duplex needs no dial — connected on creation.
            Box::pin(async { Ok(true) })
        }
        fn send<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a [u8],
            _eos: bool,
        ) -> CfFuture<'a, Result<usize>> {
            Box::pin(async move { self.stream.write(buf).await.map_err(|_| Error::Send) })
        }
        fn recv<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a mut [u8],
        ) -> CfFuture<'a, Result<usize>> {
            Box::pin(async move { self.stream.read(buf).await.map_err(|_| Error::Recv) })
        }
        fn data_pending(&self, _cx: &QueryCtx<'_>) -> bool {
            false
        }
        fn query(&self, _cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
            match query {
                CfQuery::Socket => {
                    *out = QueryOut::Socket(self.fd);
                    Ok(())
                }
                CfQuery::Transport => {
                    *out = QueryOut::Transport(Transport::Tcp);
                    Ok(())
                }
                _ => Err(Error::Code(CurlCode::UnknownOption)),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg_attr(
        miri,
        ignore = "drives a real rustls handshake (rcgen-issued cert + tokio_rustls TlsAcceptor), \
                  which invokes the ring/aws-lc-rs C crypto backend; Miri cannot interpret foreign \
                  functions. The FTPS control-channel logic is UB-clean; this matches the C-FFI \
                  test-guard pattern used throughout the TLS/QUIC suites (AAP §0.6.4)."
    )]
    async fn ftps_auth_tls_upgrades_control_channel() {
        let (server_cfg, ca_pem) = ftps_make_server_config();
        let (client_half, mut server_half) = tokio::io::duplex(64 * 1024);

        // In-process FTPS server: plaintext 220 + AUTH-TLS handshake, then the
        // encrypted login dialogue. Returns every command line it received
        // (index 0 is the plaintext `AUTH TLS`; the rest arrive over TLS).
        let server = tokio::spawn(async move {
            let mut commands: Vec<String> = Vec::new();

            server_half
                .write_all(b"220 blitzy FTPS server ready\r\n")
                .await
                .expect("write 220");
            server_half.flush().await.expect("flush 220");

            // Exactly one plaintext command — must be `AUTH TLS`.
            let auth = ftps_read_crlf_line(&mut server_half)
                .await
                .expect("AUTH command line");
            commands.push(auth);
            server_half
                .write_all(b"234 AUTH TLS OK; initializing TLS\r\n")
                .await
                .expect("write 234");
            server_half.flush().await.expect("flush 234");

            // The control channel goes TLS from here (the client hand-shakes).
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            let mut tls = acceptor
                .accept(server_half)
                .await
                .expect("server TLS accept (client must have hand-shaken)");

            // Encrypted login dialogue.
            let user = ftps_read_crlf_line(&mut tls).await.expect("USER");
            commands.push(user);
            tls.write_all(b"331 Password required\r\n")
                .await
                .expect("331");
            tls.flush().await.expect("flush 331");

            let pass = ftps_read_crlf_line(&mut tls).await.expect("PASS");
            commands.push(pass);
            tls.write_all(b"230 User logged in\r\n").await.expect("230");
            tls.flush().await.expect("flush 230");

            let pbsz = ftps_read_crlf_line(&mut tls).await.expect("PBSZ");
            commands.push(pbsz);
            tls.write_all(b"200 PBSZ=0\r\n").await.expect("200 pbsz");
            tls.flush().await.expect("flush pbsz");

            let prot = ftps_read_crlf_line(&mut tls).await.expect("PROT");
            commands.push(prot);
            tls.write_all(b"200 Protection level set to Private\r\n")
                .await
                .expect("200 prot");
            tls.flush().await.expect("flush prot");

            // Absolute path -> the FSM skips SYST and parks at FTP_STOP.
            let pwd = ftps_read_crlf_line(&mut tls).await.expect("PWD");
            commands.push(pwd);
            tls.write_all(b"257 \"/\" is the current directory\r\n")
                .await
                .expect("257");
            tls.flush().await.expect("flush 257");

            commands
        });

        // Client: a plaintext control chain whose single leaf is the duplex
        // bridge; the login FSM must upgrade it to TLS on the 234.
        let mut conn = Connection::new(Scheme::new("ftp", 21), "localhost", 21);
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(FtpsBridgeLeaf {
            stream: client_half,
            fd: 42,
        }));
        conn.cfilter[FIRSTSOCKET] = Some(chain);
        conn.user = Some("u".into());
        conn.passwd = Some("p".into());
        // Trust the server's ephemeral cert as a private CA (validation ON).
        conn.ssl_config = Arc::new(
            crate::tls::TlsConfig::default()
                .with_webpki_roots(false)
                .with_ca_info_blob(ca_pem),
        );

        // Explicit FTPS: CURLUSESSL_ALL + CURLFTPAUTH_TLS.
        let mut ftpc = FtpConn::new();
        ftpc.begin_transfer(
            Ftp::default(),
            FtpParams {
                ftpsslauth: ftpsslauth::TLS,
                ..FtpParams::default()
            },
        );
        ftpc.use_ssl = usessl::ALL;

        let done = ftpc
            .run_connect(&mut conn)
            .await
            .expect("FTPS AUTH TLS connect must succeed");
        assert!(done, "connect phase should reach FTP_STOP");

        // The control channel is genuinely TLS now (the fix's whole point).
        assert!(
            conn.is_ssl(FIRSTSOCKET),
            "control channel must be upgraded to TLS after AUTH TLS + 234"
        );
        assert!(
            conn.bits.ftp_use_control_ssl,
            "ftp_use_control_ssl must be set after the upgrade"
        );
        assert!(
            conn.bits.ftp_use_data_ssl,
            "PROT P must enable data-channel protection under CURLUSESSL_ALL"
        );

        let commands = server.await.expect("server task joins");
        assert_eq!(
            commands.first().map(String::as_str),
            Some("AUTH TLS"),
            "first (plaintext) control command must be AUTH TLS"
        );
        assert!(
            commands.iter().any(|c| c == "USER u"),
            "USER must be sent over the upgraded channel; got {commands:?}"
        );
        assert!(
            commands.iter().any(|c| c == "PASS p"),
            "PASS must be sent over the upgraded channel; got {commands:?}"
        );
        assert!(
            commands.iter().any(|c| c == "PBSZ 0"),
            "PBSZ 0 must be sent over TLS; got {commands:?}"
        );
        assert!(
            commands.iter().any(|c| c == "PROT P"),
            "PROT P must be sent over TLS; got {commands:?}"
        );
    }
}
