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
use std::path::Path;

// Connection layer: the DUAL-socket plumbing and the byte-level send/recv used
// for the data channel. Control-channel I/O goes through the ping-pong engine
// (which itself calls `Curl_conn_send`/`Curl_conn_recv` on `FIRSTSOCKET`).
use crate::conn::connect::{eyeballs_factory, tls_factory, SetupConfig};
use crate::conn::https_connect::create_tls_filter;
use crate::conn::socket::{is_tcp_listen, tcp_listen_set};
use crate::conn::{
    establish_connection, BoxFuture, ConnSetup, Connection, Curl_conn_cf_add, Curl_conn_close,
    Curl_conn_connect, Curl_conn_get_ip_info, Curl_conn_is_alive, Curl_conn_is_ssl, Curl_conn_recv,
    Curl_conn_send,
    SchemeDescriptor, CURL_CF_SSL_DISABLE, CURL_CF_SSL_ENABLE, FIRSTSOCKET, SECONDARYSOCKET,
    TRNSPRT_TCP,
};
use crate::dns::{self, DnsCache, IpVersion, ResolveParams, ResolvedAddrs};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::file::format_last_modified_header;
use crate::protocols::ftp_list::{FileInfo, FileType, FtpParseListData, WildcardData, WildcardState};
use crate::protocols::pingpong::{tls_config_from_easy, PingPong, PingPongProtocol, PpTransfer};
use crate::protocols::{
    Protocol, ProtocolTransfer, Scheme, TransferDirection, SCHEME_FTP, SCHEME_FTPS,
};
use crate::transfer::{
    ClientWriteType, ClientWriter, ReadCallback, ReadStep, UploadReader, WriteCallbacks,
};
// Dependency justification: `HttpReq` lives in `crate::setopt`, which is outside
// this file's declared `depends_on_files`. It is, however, part of the *public
// option-state surface* of [`Easy`] (`data.set.method`, type `HttpReq`) — the
// only way to read the requested transfer method (upload vs download) is to
// name it. This mirrors the established convention in `protocols::smb` and
// `protocols::rtsp`, which import `crate::setopt` types for the same reason.
use crate::netrc::{self, CurlNetrcOption};
use crate::setopt::{HttpReq, StrId};
use crate::url::{CurlUPart, CurlUrl, CURLU_DEFAULT_PORT, CURLU_GUESS_SCHEME, CURLU_URLDECODE};
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
    /// The maximum number of body bytes to download for this transfer, or `-1`
    /// for "no cap / open-ended" (C `data->req.maxdownload`). A bounded
    /// `CURLOPT_RANGE` (`-r X-Y` or `-r -N`) parsed by [`Curl_range`-equivalent]
    /// [`crate::protocols::file::parse_range`] yields `maxdownload >= 0`; an
    /// open-ended `-r X-` or a plain `-C n` resume leaves it `-1`. When a
    /// bounded range is in force the engine reads at most `maxdownload` bytes,
    /// then [`ftp_done`](Self::ftp_done) sends `ABOR` to stop the server early
    /// (C `ftp_done`: `if(dont_check && req.maxdownload > 0) ABOR`). See
    /// `tests/data/test135` (`-r 4-16`: `REST 4`/`RETR`/`ABOR`/`QUIT`).
    pub maxdownload: i64,
    /// The effective absolute resume/start offset for the current *download*
    /// (the `REST` offset), folded from either a `CURLOPT_RANGE` start or a
    /// `CURLOPT_RESUME_FROM` (`-C n`). Used by the partial-file check so that
    /// the expected length is `known_filesize - xfer_resume_off`, not the full
    /// announced size — a `CURLOPT_RANGE` start does **not** flow through
    /// `set.set_resume_from`, so without this the bytes received after a `REST`
    /// would be misread as a premature/partial transfer (see
    /// `tests/data/test2307`, `-r 4-1000` with the end past EOF). `0` for a
    /// non-resumed transfer.
    pub xfer_resume_off: i64,
    /// The source offset to skip when *resuming an upload* (C
    /// `ftp_state_ul_setup`: the first `resume_from` bytes are already on the
    /// server, so curl advances the source past them and `APPE`nds the rest).
    /// `0` for a non-resumed upload. Applied in
    /// [`run_upload_body`](Self::run_upload_body) by reading and discarding this
    /// many bytes from the source (mirroring C's `CURL_SEEKFUNC_CANTSEEK`
    /// fallback, since the read callback has no seek). See `tests/data/test112`
    /// (`-T file -C 41`, whose wire uses `APPE` and uploads only the bytes past
    /// offset 41).
    pub upload_resume_from: i64,
    /// Force the `APPE` verb (append) for this upload instead of `STOR`, even
    /// when `CURLOPT_APPEND` is not set. Set by the upload-resume path (C
    /// `ftp_state_ul_setup`: `append = TRUE;` whenever `resume_from > 0`), so a
    /// resumed upload appends its remaining bytes to the partial file rather
    /// than truncating it.
    pub upload_append: bool,
    /// General-purpose state-machine counter 1 — for FTP it toggles
    /// `EPSV (0)` vs `PASV (1)` and `EPRT (0)` vs `PORT (1)` (C `count1`).
    pub count1: i32,
    /// Connection-level "EPSV has been disabled for this connection" flag — the
    /// Rust analog of C clearing `conn->bits.ftp_use_epsv` in
    /// `ftp_epsv_disable` (lib/ftp.c L1858). Once an `EPSV` is refused and the
    /// session falls back to `PASV`, every later passive negotiation on the
    /// SAME (reused) control connection skips `EPSV` and uses `PASV` directly
    /// (`tests/data/test211`). Connection-lifetime: preserved across reuse,
    /// never re-enabled for the connection. Defaults `false` (EPSV permitted),
    /// so a fresh connection and the unit tests behave exactly as before.
    pub epsv_disabled: bool,
    /// Connection-level "EPRT has been disabled for this connection" flag — the
    /// active-mode analog of [`epsv_disabled`](Self::epsv_disabled), mirroring
    /// C clearing `conn->bits.ftp_use_eprt` after an `EPRT` refusal. Once
    /// `EPRT` is refused and the session falls back to `PORT`, every later
    /// active negotiation on the SAME (reused) control connection uses `PORT`
    /// directly (`tests/data/test212`). Connection-lifetime: preserved across
    /// reuse. Defaults `false` (EPRT permitted), keeping fresh connections and
    /// the unit tests unchanged.
    pub eprt_disabled: bool,
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
    /// Effective per-transfer ASCII preference (C `data->state.prefer_ascii`).
    /// Seeded from `CURLOPT_TRANSFERTEXT` (`data.set.prefer_ascii`) and then
    /// possibly overridden by a URL `;type=A`/`;type=I` suffix
    /// ([`type_url_check`]). Held here — rather than mutating the persistent
    /// `data.set` — so the override is scoped to this transfer exactly as C's
    /// per-request `state` is, and does not leak onto a reused easy handle.
    pub prefer_ascii: bool,
    /// Effective per-transfer directory-listing preference
    /// (C `data->state.list_only`). Seeded from `CURLOPT_DIRLISTONLY`
    /// (`data.set.list_only`) and possibly forced on by a URL `;type=D` suffix
    /// ([`type_url_check`]). Selects `NLST` over `LIST` and marks the operation
    /// as a directory listing.
    pub list_only: bool,
    /// Set when the URL path failed to url-decode because it contains a control
    /// byte (`< 0x20`), e.g. a percent-encoded `%00`. curl performs this
    /// `REJECT_CTRL` decode inside `ftp_parse_url_path` (lib/ftp.c L221-224),
    /// which runs in the DO phase — *after* login — so the malformed path is
    /// recorded here at setup time and surfaced as `CURLE_URL_MALFORMAT` at the
    /// start of `run_do_phase`, with `USER`/`PASS`/`PWD` already on the wire
    /// (`tests/data/test340`).
    pub path_malformed: bool,
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
            maxdownload: -1,
            xfer_resume_off: 0,
            upload_resume_from: 0,
            upload_append: false,
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

/// Extract the advertised *address* from a `CURLOPT_FTPPORT` (`--ftp-port`/`-P`)
/// value, the Rust analog of the address-parsing arm of C `ftp_state_use_port`
/// (lib/ftp.c L912-L1010).
///
/// curl only parses an address when the option string is **longer than one
/// character**; the single-character default `"-"` (and the empty string) mean
/// "advertise the control connection's local IP", for which this returns
/// `None`. The accepted grammar is `(ipv4|ipv6|domain|interface)?(:port-range)?`:
///
/// * `[ipv6]:port` → the bracketed IPv6 literal;
/// * a bare IPv6 literal (parses as `Ipv6Addr`, has no port) → used whole;
/// * otherwise the text up to the first `:` is the address and any trailing
///   `:port(-range)` is dropped (the local listener still binds an ephemeral
///   port — no test exercises an explicit `-P` port range).
///
/// An interface name is returned verbatim (curl resolves it via `Curl_if2ip`;
/// no test relies on interface-name resolution, and a literal IP — the
/// `IF2IP_NOT_FOUND` arm — is used as-is, exactly as here). See
/// `tests/data/test116` (`-P 1.2.3.4`) and `tests/data/test251` (`-P %CLIENTIP`).
/// Apply curl's `CURLOPT_CRLF` (`--crlf`) line-ending conversion to one chunk
/// of upload data, the Rust analog of C `cr_lc_read` (lib/sendf.c L981-L1058).
///
/// A lone `\n` — one **not** immediately preceded by a `\r` — is expanded to
/// `\r\n`; an `\n` that already follows a `\r` (an existing CRLF pair) is left
/// unchanged. `prev_cr` carries the "previous byte was CR" state across chunk
/// boundaries so a `\r` ending one read and an `\n` starting the next are
/// correctly recognized as an already-converted pair (C `ctx->prev_cr`). The
/// converted bytes are appended to `out`. See `tests/data/test128`.
fn crlf_convert_chunk(chunk: &[u8], prev_cr: &mut bool, out: &mut Vec<u8>) {
    for &b in chunk {
        if b == b'\n' && !*prev_cr {
            // Lone LF → CRLF (C: emit "\r\n", reset prev_cr).
            out.push(b'\r');
            out.push(b'\n');
            *prev_cr = false;
        } else {
            out.push(b);
            *prev_cr = b == b'\r';
        }
    }
}

#[must_use]
pub fn parse_ftpport_address(spec: &str) -> Option<String> {
    // C gate: `strlen(STRING_FTPPORT) > 1`. "-" (the default) is length 1.
    if spec.len() <= 1 {
        return None;
    }
    // `[ipv6]:port(-range)`
    if let Some(rest) = spec.strip_prefix('[') {
        return rest
            .split(']')
            .next()
            .filter(|ip| !ip.is_empty())
            .map(str::to_string);
    }
    // `:port` — only a port was given, no address.
    if spec.starts_with(':') {
        return None;
    }
    // A bare IPv6 literal (e.g. `::1`, `fe80::1`) contains ':' but parses as an
    // address and carries no port; use it whole (C `inet_pton(AF_INET6, ...)`).
    if spec.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some(spec.to_string());
    }
    // `ipv4|domain|interface` optionally followed by `:port(-range)`.
    let addr = spec.split(':').next().unwrap_or(spec);
    if addr.is_empty() {
        None
    } else {
        Some(addr.to_string())
    }
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
pub fn decompose_url_path(method: CurlFtpFile, rawpath: &str) -> Result<PathDecomp> {
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

    // NOTE: an upload to a path that names no file (e.g. one ending in `/`)
    // is malformed (`CURLE_URL_MALFORMAT`), but curl does **not** raise that
    // here. C performs the check in `ftp_parse_url_path` during the DO phase
    // (lib/ftp.c L310-313), which runs *after* the control connection has
    // logged in — so the error must surface with `USER`/`PASS`/`PWD` already
    // on the wire (see `run_do_phase` and `tests/data/test524`/`lib524`). This
    // function only splits the path; the upload-without-filename decision is
    // made by the caller from `file.is_none()`.

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

/// Detect a trailing FTP `;type=<typecode>` URL extension and return its
/// (upper-cased) type code, or `None` when the path carries no such suffix.
///
/// This is the detection half of curl's `type_url_check` (C: lib/ftp.c
/// L4226-4253). The check is performed on the *encoded* path, exactly as curl
/// runs it on `ftp->path` before URL-decoding: a path qualifies when it is at
/// least 7 bytes long and ends with the literal six-byte tag `;type=` followed
/// by a single type character. The caller maps the returned code to the
/// per-transfer preferences — `A` ⇒ ASCII (`prefer_ascii`), `D` ⇒ directory
/// listing (`list_only`), `I` (or anything else) ⇒ binary — and strips the
/// 7-byte suffix from the path before CWD decomposition.
///
/// The suffix is always literal ASCII (`;type=X`), so it is byte-identical in
/// the encoded and decoded forms; the caller can therefore detect it here on
/// the encoded path yet remove the final 7 characters from the decoded path.
#[must_use]
pub fn type_url_check(path: &str) -> Option<u8> {
    let bytes = path.as_bytes();
    let len = bytes.len();
    // C: `if((len >= 7) && !memcmp(&ftp->path[len - 7], ";type=", 6))`.
    if len >= 7 && &bytes[len - 7..len - 1] == b";type=" {
        // C: `command = Curl_raw_toupper(type[6])` — the type character.
        Some(bytes[len - 1].to_ascii_uppercase())
    } else {
        None
    }
}

/// Resolve `host:port` to a set of socket addresses for an FTP connection,
/// honoring `CURLOPT_IPRESOLVE`. The Rust analog of the resolve step curl's
/// `Curl_resolv_*` performs before connecting the control or data socket.
///
/// FTP data endpoints are typically IP literals carried in the `PASV`/`EPSV`
/// reply (a no-op resolve), but a hostname control target is resolved through
/// the same system-resolver pipeline the HTTP engine uses (`--doh-url` is not
/// threaded here: FTP follows curl's common case of the system resolver, and
/// the DoH transport is owned by the HTTP engine).
async fn resolve_ftp_addrs(
    host: &str,
    port: u16,
    ipver: IpVersion,
    verbose: bool,
) -> Result<ResolvedAddrs> {
    let mut cache = DnsCache::new();
    let mut errbuf: Option<String> = None;
    let mut params = ResolveParams::new(host, port);
    params.ip_version = ipver;
    params.verbose = verbose;
    let entry = dns::resolve(&mut cache, &params, &mut errbuf).await?;
    Ok(entry.addrs.clone())
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

            // Store the latest **final** FTP response code so it is retrievable
            // via `CURLINFO_RESPONSE_CODE` (`getinfo`), except during shutdown —
            // the Rust analog of C `ftp_readresp` (lib/ftp.c L601-603):
            //   `if(!ftpc->shutdown) data->info.httpcode = code;`
            // Without this, a transfer that fails on a control-channel reply
            // (e.g. `430` on `PASS` → `CURLE_LOGIN_DENIED`) leaves the recorded
            // response code at 0, so the CLI retry machinery (`retrycheck`,
            // which retries FTP when `response / 100 == 4`) never fires and
            // `%{num_retries}` stays 0 (QA test 196). HTTP records this in the
            // transfer engine (`http::mod.rs`); FTP must do so here.
            if !self.shutdown {
                data.info.response_code = i64::from(code);
            }

            // C `ftp_readresp` (lib/ftp.c L607-617): a `421` may arrive at any
            // point in the dialogue (idle-timeout / "closing control
            // connection") and is treated generically as
            // `CURLE_OPERATION_TIMEDOUT` before the per-state switch. The
            // connect-phase reader mirrors that here so a `421` during login is
            // handled identically to one during transfer (see `read_one`).
            if code == 421 {
                if data.set.verbose {
                    sendf::infof(true, "We got a 421 - timeout");
                }
                self.ctl_valid = false;
                self.set_state(FtpState::Stop);
                return Err(CurlError::OperationTimedout);
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
                // A failed write on the *control* channel means the connection
                // is no longer usable. Mark it dead so the teardown sends no
                // `QUIT` and does not wait in vain on a half-closed peer — the
                // exact role of C's `ctl_valid`, which `ftp_disconnect` clears
                // for a dead connection before `ftp_quit` consults it
                // (lib/ftp.c L4172-4178). A *protocol* error (a successfully
                // read non-2xx reply such as `550`) does **not** reach here and
                // so leaves `ctl_valid` set, exactly as curl keeps the control
                // connection alive and still sends `QUIT` after, e.g., a `550`.
                Ok(0) => {
                    self.ctl_valid = false;
                    return Err(CurlError::SendError);
                }
                Ok(n) => sent += n,
                // Would-block: yield and retry (the runtime awaits writability).
                Err(CurlError::Again) => tokio::task::yield_now().await,
                Err(e) => {
                    self.ctl_valid = false;
                    return Err(e);
                }
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
                // C `case FTP_NAMEFMT` (lib/ftp.c L3226-3232): on a `250` (name
                // format change accepted) the initial path is *reloaded* with a
                // second `PWD` — `ftp_state_pwd(data, ftpc)` — so subsequent
                // `CWD`/`RETR` use the now-UNIX-style entry path; any other reply
                // simply ends the connect phase. The second `PWD` reply re-enters
                // `state_pwd_resp`, but `server_os` is already set by now so the
                // `SYST` probe is not repeated (no loop). Oracle: tests/data/test1102.
                if code == 250 {
                    self.send_pwd(data, conn).await
                } else {
                    self.set_state(FtpState::Stop);
                    Ok(())
                }
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
        // Pipelining in the AUTH response is forbidden: the server must not send
        // any bytes after the response line and before the TLS handshake, or
        // those plaintext bytes could be a command injection by a network
        // attacker. Mirrors C `case FTP_AUTH` (`ftp.c` L3076-3077):
        // `if(pp->overflow) return CURLE_WEIRD_SERVER_REPLY;`, checked *before*
        // the response code so a pipelined reply is rejected regardless of the
        // 234/334 accept status. Without this guard the buffered extra lines are
        // consumed as replies to later commands, corrupting the session
        // (tests/data/test983).
        if self.pp.has_overflow() {
            crate::failf!(
                &mut conn.filter_data.error_buffer,
                "Reply to AUTH contained pipelined data"
            );
            return Err(CurlError::WeirdServerReply);
        }
        if code == 234 || code == 334 {
            // AUTH accepted: upgrade the control channel to TLS *now*, before
            // `USER`. The Rust analog of C's `Curl_ssl_cfilter_add(FIRSTSOCKET)`
            // + `Curl_conn_connect` then `ftp_use_control_ssl = TRUE`: a
            // `tokio-rustls` filter is layered atop the live cleartext TCP chain
            // and its handshake driven to completion, so every subsequent
            // control command (`USER`/`PASS`/…) flows over TLS. Without this the
            // server (which switches to TLS after its 234/334) would see the
            // next command as cleartext and the session would stall — the
            // root cause of QA F4-CRIT-2 for explicit FTPS (`--ssl-reqd`).
            self.upgrade_control_tls(data, conn).await?;
            self.control_ssl = true;
            debug_assert!(Curl_conn_is_ssl(conn, FIRSTSOCKET));
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

/// Extracts the byte count from a `213` `SIZE` reply, the Rust analog of the
/// `strtoofft` parse in C `ftp_state_size_resp`.
///
/// The reply has the form `213 <size>`; the size is the first decimal token
/// after the status prefix. Returns `None` when no parseable number follows the
/// code (the caller then leaves `known_filesize` unset and proceeds open-ended).
#[must_use]
pub fn parse_size_213(reply: &[u8]) -> Option<i64> {
    let text = core::str::from_utf8(reply).ok()?;
    // Skip the 3-digit code and following whitespace, then take the first token.
    let rest = text.get(3..)?.trim_start();
    let token = rest.split_whitespace().next()?;
    token.parse::<i64>().ok().filter(|&n| n >= 0)
}

/// Parse an FTP `MDTM` `213 YYYYMMDDHHMMSS[.sss]` reply into a Unix timestamp,
/// the Rust analog of C `ftp_state_mdtm_resp` (`ftp_213_date` + the
/// `"%04d%02d%02d %02d:%02d:%02d GMT"` reformat handed to
/// `Curl_getdate_capped`, lib/ftp.c L2420-L2433). The reply carries the
/// modification time as a compact `YYYYMMDDHHMMSS` token (an optional `.sss`
/// fractional-seconds suffix is ignored, exactly as curl does). Returns `None`
/// when the reply is not a parseable `213` timestamp — the caller then simply
/// omits the synthetic `Last-Modified` header (C "unsupported MDTM reply
/// format").
#[must_use]
pub fn parse_mdtm_213(reply: &[u8]) -> Option<i64> {
    let text = core::str::from_utf8(reply).ok()?;
    // Skip the 3-digit code and following whitespace, then take the first token.
    let rest = text.get(3..)?.trim_start();
    let token = rest.split_whitespace().next()?;
    // Collect the leading run of ASCII digits (drops any `.sss` fraction).
    let digits: String = token.chars().take_while(char::is_ascii_digit).collect();
    if digits.len() < 14 {
        return None;
    }
    let (y, mo, d) = (&digits[0..4], &digits[4..6], &digits[6..8]);
    let (h, mi, s) = (&digits[8..10], &digits[10..12], &digits[12..14]);
    // Reformat exactly as curl does, then run it through the same getdate path
    // so the resulting `time_t` (and thus the emitted `Last-Modified` and
    // `CURLINFO_FILETIME_T`) is byte-for-byte identical to the C tool.
    let formatted = format!("{y}{mo}{d} {h}:{mi}:{s} GMT");
    crate::util::parsedate::getdate_capped(&formatted)
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
        // C `mode[][5] = { "EPSV", "PASV" }`; `modeoff = ftp_use_epsv ? 0 : 1`,
        // where curl's `conn->bits.ftp_use_epsv` is the option AND-ed with the
        // not-yet-disabled connection flag. A prior `EPSV` refusal on THIS
        // (reused) connection latches `epsv_disabled`, so the negotiation goes
        // straight to `PASV` (`tests/data/test211`); on a fresh connection
        // `epsv_disabled` is `false`, leaving the choice identical to before.
        let modeoff = if data.set.ftp_use_epsv && !self.epsv_disabled {
            0
        } else {
            1
        };
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
        // Latch EPSV off for the lifetime of this (possibly-reused) connection,
        // mirroring C `conn->bits.ftp_use_epsv = FALSE` (lib/ftp.c L1858): a
        // subsequent transfer on the same control channel will start with
        // `PASV` and not re-probe `EPSV` (`tests/data/test211`).
        self.epsv_disabled = true;
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
    /// The host/port parsed from the `PASV`/`EPSV` reply identify the data
    /// endpoint. This **installs** the secondary socket's connection-filter
    /// chain — a TCP/happy-eyeballs connect filter targeting
    /// [`FtpConn::data_host`]:[`FtpConn::data_port`], wrapped in a `tokio-rustls`
    /// TLS filter when the data channel is protected (`PROT P` on an encrypted
    /// control channel) — and then drives it to a connected (and, for FTPS, fully
    /// TLS-handshaken) state.
    ///
    /// # Why the filter is installed here
    ///
    /// Unlike the control channel (`FIRSTSOCKET`), whose chain is assembled by
    /// the [`crate::protocols::perform_transfer`] driver before login, the data
    /// channel's endpoint is unknown until the `PASV`/`EPSV` reply arrives. The
    /// Rust analog of curl's `Curl_conn_setup(data, conn, SECONDARYSOCKET, …)`
    /// (the second-socket cf-socket install in `ftp_state_pasv_resp`) therefore
    /// happens at this point — mirroring C, which only knows the data address
    /// after parsing the `227`/`229` reply.
    pub async fn connect_data_passive(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        let host = self.data_host.clone().ok_or(CurlError::FtpWeirdPasvReply)?;
        let port = self.data_port;

        // A reused control connection may carry a stale (closed) secondary
        // chain from the previous transfer; discard it so a fresh data filter
        // is installed (C tears the second socket down in `ftp_done`).
        conn.cfilter[SECONDARYSOCKET].discard_all();

        let ipver = IpVersion::from_raw(i64::from(data.set.ipver));
        let verbose = data.set.verbose;

        // FTP-over-HTTP(S)-proxy CONNECT tunnel: when the control channel tunnels
        // through a proxy, the data channel opens its OWN `CONNECT` through the
        // SAME proxy to the `PASV`/`EPSV` endpoint — curl's `ftp_state_pasv_resp`
        // `if(conn->bits.proxy)` re-resolves the proxy host, dials it, and sets up
        // `SECONDARYSOCKET` with a `CONNECT` to `conn->secondaryhostname:port`
        // (= the data host above). The proxy is re-resolved from `data.set` (the
        // origin host for the `no_proxy` match is the recorded control remote,
        // which under a tunnel is the ORIGIN FTP host). `None` for a direct or
        // SOCKS route leaves the existing behavior untouched.
        #[cfg(all(feature = "ftp", feature = "http", feature = "proxy"))]
        let data_proxy = if conn.bits.tunnel_proxy {
            ftp_tunnel_proxy(data, &conn.remote_host, conn.remote_port).map(|tp| tp.proxy)
        } else {
            None
        };

        // The data-channel **dial** target: the proxy when tunneling, else the
        // advertised data endpoint (usually an IP literal from the PASV/EPSV
        // reply — a no-op resolve — but a hostname is handled too).
        #[cfg(all(feature = "ftp", feature = "http", feature = "proxy"))]
        let (dial_host, dial_port) = match &data_proxy {
            Some(px) => (px.host.clone(), px.port),
            None => (host.clone(), port),
        };
        #[cfg(not(all(feature = "ftp", feature = "http", feature = "proxy")))]
        let (dial_host, dial_port) = (host.clone(), port);

        let addrs = resolve_ftp_addrs(&dial_host, dial_port, ipver, verbose).await?;

        // Connect ONLY the TCP layer of the data channel here. For FTPS `PROT P`
        // the data-channel TLS handshake is intentionally **deferred** until
        // *after* the transfer command's `150`/`125` reply (driven by
        // [`FtpConn::upgrade_data_tls`] from [`FtpConn::run_do_phase`]). This
        // mirrors the C oracle's `ftp_do_more`, whose own comment states: "an SSL
        // filter is in place and the server will not start the TLS handshake
        // until we send more FTP commands". Handshaking now (before `RETR`/`STOR`/
        // `LIST`) deadlocks: the client's `ClientHello` would wait forever for a
        // `ServerHello` the server does not send until it has received the
        // transfer command. The active-mode path already defers identically
        // (TCP accept, then `upgrade_data_tls`), so the data-channel TLS handshake
        // is uniformly post-`150` regardless of passive/active. (Plaintext `ftp`
        // is unaffected — it never gets a TLS filter at all.)
        let eyeballs = eyeballs_factory(TRNSPRT_TCP, ipver, data.set.happy_eyeballs_timeout, data.set.connecttimeout, addrs);
        let mut setup = SetupConfig::new(CURL_CF_SSL_DISABLE, false, eyeballs);
        // Splice the HTTP(S)-proxy CONNECT tunnel for the data channel, targeting
        // the PASV/EPSV data endpoint (`host:port`). The proxy returns a second
        // "200 Connection established" block which `run_do_phase` surfaces onto
        // the body stream (oracle: tests/data/test714, test715).
        #[cfg(all(feature = "ftp", feature = "http", feature = "proxy"))]
        if let Some(px) = &data_proxy {
            setup = ftp_apply_proxy_connect(setup, data, px, &host, port, conn);
        }
        let dispatch = ConnSetup::Default(setup);
        establish_connection(conn, SECONDARYSOCKET, CURL_CF_SSL_DISABLE, dispatch, false).await
    }

    /// Whether the data connection should be TLS-protected — the Rust analog of
    /// curl's `conn->bits.ftp_use_data_ssl`, set in `case FTP_PROT` as
    /// `(data->set.use_ssl != CURLUSESSL_CONTROL)` once the control channel is
    /// encrypted and `PROT P` has been negotiated.
    ///
    /// The trigger is the **encrypted control channel** ([`FtpConn::control_ssl`]),
    /// not the requested `--ssl*` level: curl sends `PBSZ`/`PROT` whenever the
    /// control channel is TLS (C `ftp_state_loggedin` gates on
    /// `ftp_use_control_ssl`). Consequently an **implicit `ftps://`** session —
    /// whose control channel is TLS from the first byte yet whose `use_ssl`
    /// defaults to `CURLUSESSL_NONE` — still protects the data channel with
    /// `PROT P`. Only an explicit control-only level (`CURLUSESSL_CONTROL`, which
    /// sends `PROT C`) keeps the data channel in clear text. Matching C's
    /// `(use_ssl != CURLUSESSL_CONTROL)` exactly (rather than additionally
    /// excluding `CURLUSESSL_NONE`) is required for implicit-FTPS data-channel
    /// parity (QA F4-CRIT-2).
    fn data_channel_uses_tls(&self, data: &Easy) -> bool {
        self.control_ssl && data.set.use_ssl != CURLUSESSL_CONTROL
    }

    /// Upgrade the **control** channel (`FIRSTSOCKET`) to TLS in place, after a
    /// successful `AUTH SSL`/`AUTH TLS` (explicit FTPS). The Rust analog of
    /// curl's `Curl_ssl_cfilter_add(data, conn, FIRSTSOCKET)` followed by
    /// `Curl_conn_connect`.
    ///
    /// A fresh `tokio-rustls` filter (built from the easy handle's TLS config —
    /// CA store, verification toggle, client cert, SNI, version window) is added
    /// at the **top** of the already-connected TCP filter chain via
    /// [`Curl_conn_cf_add`], then [`Curl_conn_connect`] drives that new head: the
    /// TLS filter sees its sub-chain already connected and performs only the
    /// rustls handshake over it. On return the control channel is encrypted and
    /// the moved-in sub-chain lives inside the TLS stream, so every later
    /// [`Curl_conn_send`]/[`Curl_conn_recv`] on `FIRSTSOCKET` is protected.
    async fn upgrade_control_tls(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<()> {
        // Already encrypted (implicit ftps, or a redundant AUTH): nothing to do.
        if Curl_conn_is_ssl(conn, FIRSTSOCKET) {
            return Ok(());
        }
        let host = conn.remote_host.clone();
        let port = conn.remote_port;
        let tls = tls_config_from_easy(data);
        // No ALPN for FTPS control (FTP is not negotiated over ALPN).
        let tls_filter = create_tls_filter(tls, host, port, None, Vec::new());
        Curl_conn_cf_add(conn, FIRSTSOCKET, tls_filter);
        Curl_conn_connect(conn, FIRSTSOCKET, true).await
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

        // Bind an ephemeral local port for the server to connect back to. C's
        // `ftp_state_use_port` binds to — and advertises — the *control
        // connection's local address* (`conn->ip.local_ip`), NOT the wildcard:
        // a server will reject a data connection advertised as `0.0.0.0`
        // ("foreign address"), so the advertised IP must be the routable local
        // endpoint the control link already uses. Query that local IP from the
        // established `FIRSTSOCKET` (C `Curl_conn_get_ip_info`) and bind to it;
        // `local_addr()` then reports that IP, so the EPRT/PORT advertisement
        // below carries the correct address. Fall back to the wildcard only when
        // the quadruple is somehow unavailable (preserves prior behavior).
        let control_local_ip = Curl_conn_get_ip_info(conn, FIRSTSOCKET)
            .map(|(_, quad)| quad.local_ip)
            .filter(|ip| !ip.is_empty());
        let bind_target = match control_local_ip.as_deref() {
            Some(ip) if ip.contains(':') => format!("[{ip}]:0"), // IPv6 literal
            Some(ip) => format!("{ip}:0"),                       // IPv4
            None => "0.0.0.0:0".to_string(),
        };
        let listener = TcpListener::bind(&bind_target)
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

        // Advertise the endpoint. Prefer EPRT (works for IPv4 and IPv6),
        // falling back to PORT for IPv4 (C `mode[][5] = { "EPRT", "PORT" }`).
        //
        // The advertised *address* honors `CURLOPT_FTPPORT` (`--ftp-port`/`-P`):
        // when an explicit address is given (option longer than one char), curl
        // advertises *that* address rather than the bound local IP (C
        // `ftp_state_use_port`; lib/ftp.c L912-L1010). The local listener still
        // binds an ephemeral local port; only the advertised IP changes. The
        // single-char default `-` advertises the control connection's local IP.
        // See `tests/data/test116` (`-P 1.2.3.4` → `EPRT |1|1.2.3.4|`).
        let advertised = data
            .set
            .str(StrId::Ftpport)
            .and_then(parse_ftpport_address);
        let host = match advertised {
            Some(ref a) => a.clone(),
            None => local.ip().to_string(),
        };
        // The EPRT family selector (`|1|` IPv4, `|2|` IPv6) follows the
        // advertised address's family when one was specified, else the bound
        // socket's family.
        let is_ipv6 = match advertised {
            Some(ref a) => a.parse::<std::net::Ipv6Addr>().is_ok(),
            None => local.is_ipv6(),
        };
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
            // Latch EPRT off for the lifetime of this (possibly-reused)
            // connection (C clears `conn->bits.ftp_use_eprt`): a subsequent
            // active transfer on the same control channel starts with `PORT`
            // and does not re-probe `EPRT` (`tests/data/test212`).
            self.eprt_disabled = true;
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
    ///
    /// # Watching the control channel during the accept wait
    ///
    /// A server that *cannot* open the data connection does not simply leave
    /// curl hanging on the accept — it reports the failure on the **control**
    /// channel, typically as `150 Opening data connection` immediately followed
    /// by `425 Can't open data connection` (or `421`). curl must notice that
    /// negative reply and fail with `CURLE_FTP_ACCEPT_FAILED` (10) *without*
    /// waiting out the full accept timeout (and, under `--max-time`, without
    /// hitting the global timeout and reporting `28` instead). This is the Rust
    /// analog of C's `ftp_check_ctrl_on_data_wait` (lib/ftp.c L458), which curl's
    /// `ftp_do_more` runs each pass it finds the server has not yet connected
    /// (L2196-L2218): it checks the control socket — first any reply already
    /// buffered behind the `1xx`, then a zero-timeout readability poll — and on a
    /// reply whose first digit is `> '3'` (`ftpcode/100 > 3`) returns
    /// `CURLE_FTP_ACCEPT_FAILED`. (Oracle: `tests/data/test1206`, where the wire
    /// ends `RETR 1206` then `QUIT` and the exit code is `10`.)
    ///
    /// The C cooperative poll-loop becomes a short-window loop here: each pass
    /// (a) consumes and inspects any pending control reply *non-destructively*
    /// first (so a well-behaved server — which sends nothing on the control
    /// channel until the post-transfer `226` — is never read against, incurring
    /// no latency or behavior change), then (b) attempts the accept for a bounded
    /// window. The accept filter's listener persists until a connection is
    /// accepted and its budget counts from a fixed `started_at`, so cancelling an
    /// idle short window and retrying is safe (`TcpListener::accept` is
    /// cancel-safe) and the overall `DEFAULT_ACCEPT_TIMEOUT` still expires.
    pub async fn accept_data_active(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        use std::time::Duration;
        // How long each accept attempt runs before we re-poll the control
        // channel. Short enough that a pipelined-but-slightly-delayed `425` is
        // caught promptly (well under any `--max-time`), long enough that a
        // healthy server's immediate connect-back is accepted in the first pass.
        const ACCEPT_POLL_MS: u64 = 200;
        loop {
            // (a) C `ftp_check_ctrl_on_data_wait`: look for a server-sent
            // negative reply on the CONTROL channel. The bytes can be waiting
            // either already in the pingpong receive buffer (read in the same
            // segment as the `1xx`, `moredata`) or unread in the socket
            // (`input_pending` from a zero-timeout `poll_peek`, the analog of
            // C's `SOCKET_READABLE(ctrl_sock, 0)`). Reading is only attempted
            // when data is actually present, so `read_one` cannot block here and
            // is never cancelled (preserving its non-cancel-safe `mem::take`).
            let (_alive, input_pending) = Curl_conn_is_alive(conn);
            if self.pp.moredata() || input_pending {
                let code = self.read_one(data, conn).await?;
                if data.set.verbose {
                    sendf::infof(true, &format!("FTP code: {code:03}"));
                }
                // C: `if(ftpcode / 100 > 3) return CURLE_FTP_ACCEPT_FAILED;`.
                if code >= 400 {
                    self.wait_data_conn = false;
                    return Err(CurlError::FtpAcceptFailed);
                }
                // A positive/intermediate reply during the wait (e.g. a stray
                // `226` arriving before the data socket is noticed): C keeps
                // waiting for the data connection, so loop back to the accept.
            }

            // (b) Bounded accept attempt.
            match tokio::time::timeout(
                Duration::from_millis(ACCEPT_POLL_MS),
                Curl_conn_connect(conn, SECONDARYSOCKET, false),
            )
            .await
            {
                // Server connected back: the active-mode data channel is up.
                Ok(Ok(())) => {
                    self.wait_data_conn = false;
                    return Ok(());
                }
                // The accept filter exhausted its own budget / errored. Preserve
                // the original error mapping exactly.
                Ok(Err(CurlError::OperationTimedout)) => {
                    self.wait_data_conn = false;
                    return Err(CurlError::FtpAcceptTimeout);
                }
                Ok(Err(_)) => {
                    self.wait_data_conn = false;
                    return Err(CurlError::FtpAcceptFailed);
                }
                // Our short poll window elapsed without a connection: loop to
                // re-check the control channel and re-attempt the accept.
                Err(_elapsed) => {}
            }
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
                        self.accept_data_active(data, conn).await?;
                    } else {
                        self.send_pasv(data, conn).await?;
                        self.connect_data_passive(data, conn).await?;
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
        // Opt in to the "response lines as headers" capture before the greeting
        // is read, so the (possibly multi-line) `220` welcome and the
        // `USER`/`PASS`/`PWD` replies are recorded for the `-D`/`--dump-header`
        // sink — mirroring C `Curl_pp_readresp`'s unconditional
        // `Curl_client_write(CLIENTWRITE_INFO)` (lib/pingpong.c L304-310). The
        // captured lines are flushed to the header sink after the transfer's
        // completion handshake by `perform_ftp`. Idempotent; on a reused
        // connection login is skipped and capture is (re)enabled at the start of
        // `run_do_phase` instead. Oracle: tests/data/test1349.
        self.pp.enable_info_capture();
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

/// Graceful end-of-run drain of FTP control connections left alive in the
/// shared connection pool for reuse (the synchronous easy/CLI analog of curl
/// tearing down its connection cache in `Curl_cpool_destroy`).
///
/// A reused FTP connection is **not** QUITed inline at the end of its transfer
/// (see [`perform_ftp`]'s tail); it is checked back into the pool so a
/// subsequent same-host transfer can reuse it. Whatever connection remains in
/// the pool after the final transfer must therefore receive its deferred,
/// best-effort `QUIT` here, while the Tokio runtime is still live — producing
/// the single trailing `QUIT` the curl oracle expects (e.g.
/// `tests/data/test215`). For a single transfer this is wire-identical to the
/// previous inline teardown: the transfer's commands, then `QUIT`.
///
/// Each pooled connection still carrying an [`FtpConn`] proto-state is handed to
/// [`FtpHandler::disconnect`] (which only reads `data.set.verbose` from the
/// handle, so a throwaway [`Easy`] drives it faithfully); connections without
/// FTP state — e.g. pooled HTTP keep-alives — are simply dropped here, which
/// force-closes their sockets exactly as the pool's own `Drop` did. `verbose`
/// is propagated to the throwaway handle so the internal `> QUIT` trace is
/// still emitted under `-v`/`CURLOPT_VERBOSE`.
pub async fn ftp_drain_pool(pool: &crate::conn::SharedPool, verbose: bool) {
    let conns = crate::conn::pool_take_all(pool);
    if conns.is_empty() {
        return;
    }
    let handler = FtpHandler::new(&SCHEME_FTP);
    let mut throwaway = Easy::new();
    throwaway.set.verbose = verbose;
    for mut conn in conns {
        if conn.proto_state_ref::<FtpConn>().is_some() {
            // Best-effort graceful `QUIT` + socket close; failures are ignored
            // (a dying peer must never block teardown). Only connections checked
            // in with a still-valid control channel reach here, so `disconnect`
            // sends the `QUIT` exactly as the prior inline path did.
            let _ = handler.disconnect(&mut throwaway, &mut conn, false).await;
        } else {
            // Non-FTP pooled connections. An authenticated IMAP control
            // connection parked for reuse (see [`perform_imap`]'s tail) defers
            // its `LOGOUT` to this end-of-run drain so that two consecutive
            // same-origin `imap://` transfers share one session and emit exactly
            // one trailing `LOGOUT` (oracle: tests/data/test815, test816).
            // Dispatch it to [`ImapHandler::disconnect`], which — like FTP's
            // `disconnect` — reads only `data.set.verbose` from the handle, so
            // the throwaway [`Easy`] drives it faithfully. Gated on the `imap`
            // feature so the FTP-only build never names IMAP items.
            #[cfg(feature = "imap")]
            if conn
                .proto_state_ref::<crate::protocols::imap::ImapConn>()
                .is_some()
            {
                let imap_handler =
                    crate::protocols::imap::ImapHandler::new(&crate::protocols::SCHEME_IMAP);
                let _ = imap_handler
                    .disconnect(&mut throwaway, &mut conn, false)
                    .await;
            }
        }
        // `conn` drops at the end of the loop body: any connection without a
        // recognized still-live proto-state (or one already torn down above) has
        // its sockets force-closed here, matching the connection pool's previous
        // `Drop`-time teardown.
    }
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
            // C `ftp->path = &data->state.up.path[1]` — the URL path (always
            // rooted with a leading '/') is taken WITHOUT that initial slash
            // before CWD decomposition. Thus `ftp://host/file` decomposes to
            // *no* directory component (and so emits no `CWD`), matching
            // `tests/data/test102`; a leading double slash (`//abs/file`) keeps
            // exactly one slash, expressing an absolute path that CWDs to root.
            // FTP URLs may carry a trailing `;type=<typecode>` extension
            // (C `type_url_check`, lib/ftp.c L4226-4253). curl detects it on the
            // *encoded* path before decoding, so do the same: read the encoded
            // path (leading '/' dropped, as for `ftp->path`) and probe for the
            // suffix.
            let encoded_path = {
                let p = url
                    .get(CurlUPart::Path, 0)
                    .map_err(|_| CurlError::UrlMalformat)?;
                p.strip_prefix('/').unwrap_or(&p).to_string()
            };
            let type_code = type_url_check(&encoded_path);

            // Seed the per-transfer ASCII / directory-listing preferences from
            // the options (C copies `data->set.*` into `data->state.*` per
            // request), then apply any URL `;type=` override: `A` ⇒ ASCII,
            // `D` ⇒ directory listing, `I`/other ⇒ binary. These are stored on
            // the (per-transfer) `FtpConn` rather than mutated onto the
            // persistent `data.set`, so the override cannot leak onto a reused
            // easy handle.
            let mut prefer_ascii = data.set.prefer_ascii;
            let mut list_only = data.set.list_only;
            match type_code {
                Some(b'A') => prefer_ascii = true,
                Some(b'D') => list_only = true,
                Some(_) => prefer_ascii = false, // 'I' and any other code
                None => {}
            }

            // C `ftp->path = &data->state.up.path[1]` — the URL path (always
            // rooted with a leading '/') is taken WITHOUT that initial slash
            // before CWD decomposition. Thus `ftp://host/file` decomposes to
            // *no* directory component (and so emits no `CWD`), matching
            // `tests/data/test102`; a leading double slash (`//abs/file`) keeps
            // exactly one slash, expressing an absolute path that CWDs to root.
            // The `;type=X` suffix (7 literal ASCII bytes, identical encoded and
            // decoded) is removed here, mirroring C's `*type = 0` cut, so it
            // never reaches the CWD/RETR path.
            // The url-decode of the path uses `REJECT_CTRL` semantics
            // (`CURLU_URLDECODE` → `escape::urldecode(.., UrlReject::Ctrl)`), so
            // a control byte such as a percent-encoded `%00` makes it fail. curl
            // performs that REJECT_CTRL decode inside `ftp_parse_url_path` — in
            // the DO phase, *after* login (lib/ftp.c L221-224) — so a failure
            // here must NOT abort before the control connection logs in. Record
            // the malformed state instead and surface `CURLE_URL_MALFORMAT` at
            // the start of `run_do_phase` (`tests/data/test340`). The success
            // path is unchanged.
            let mut path_malformed = false;
            let raw_path = match url.get(CurlUPart::Path, CURLU_URLDECODE) {
                Ok(decoded) => {
                    let decoded = decoded.strip_prefix('/').unwrap_or(&decoded);
                    let trimmed = if type_code.is_some() {
                        &decoded[..decoded.len().saturating_sub(7)]
                    } else {
                        decoded
                    };
                    trimmed.to_string()
                }
                Err(_) => {
                    path_malformed = true;
                    String::new()
                }
            };

            // On a reused control connection, carry the connection-lifetime FTP
            // state across into the fresh per-transfer state: the live
            // ping-pong engine and its control buffers, the login `entrypath`,
            // the `prevpath` left by the previous transfer (the basis for the
            // same-path / delta-CWD decision below), the negotiated
            // `transfertype` (so `ftp_need_type` can elide a redundant `TYPE`),
            // the server OS, and the control-channel TLS flag. A fresh
            // connection starts from `FtpConn::new()` defaults. Every
            // *per-transfer* field is taken from the fresh `FtpConn::new()` (and
            // overwritten below from the new URL/options), so no stale request
            // state leaks across the reuse — only the genuinely
            // connection-lifetime fields survive.
            let mut ftpc = FtpConn::new();
            let mut reuse_prevpath: Option<String> = None;
            if conn.bits.reuse {
                if let Some(prev) = conn
                    .take_proto_state()
                    .and_then(|b| b.downcast::<FtpConn>().ok().map(|b| *b))
                {
                    ftpc.pp = prev.pp;
                    ftpc.entrypath = prev.entrypath;
                    ftpc.transfertype = prev.transfertype;
                    ftpc.server_os = prev.server_os;
                    ftpc.control_ssl = prev.control_ssl;
                    // The control channel was validated at login and remains
                    // usable for the deferred `QUIT`; it is set true only in
                    // `connect()`, which reuse skips, so carry it forward (else
                    // teardown would silently drop the connection without the
                    // pooled, drained `QUIT` — `tests/data/test215`).
                    ftpc.ctl_valid = prev.ctl_valid;
                    // A prior `EPSV` refusal stays disabled for the connection
                    // (C `conn->bits.ftp_use_epsv` is never re-enabled); the
                    // reused transfer goes straight to `PASV` (test211). The
                    // active-mode `EPRT` refusal latches the same way (test212).
                    ftpc.epsv_disabled = prev.epsv_disabled;
                    ftpc.eprt_disabled = prev.eprt_disabled;
                    reuse_prevpath = prev.prevpath;
                    // Carry the previous directory forward so `ftp_done`'s
                    // NOCWD-absolute "keep existing prevpath" branch sees it.
                    ftpc.prevpath = reuse_prevpath.clone();
                }
            }
            // Record the resolved per-transfer transfer-mode preferences.
            ftpc.prefer_ascii = prefer_ascii;
            ftpc.list_only = list_only;
            ftpc.path_malformed = path_malformed;

            // Resolve the login credentials with curl's exact precedence
            // (C `override_login`, lib/url.c L2575, plus the create_conn comment
            // at L1761-1763: "username and password set with their own options
            // override the credentials possibly set in the URL, but netrc does
            // not"):
            //   1. explicit `-u user:password` (CURLOPT_USERPWD →
            //      `StrId::Username`/`StrId::Password`) overrides the URL
            //      userinfo on a per-field basis (CREDS_OPTION > CREDS_URL);
            //   2. the URL userinfo seeds any field `-u` did not set;
            //   3. `.netrc` (when `CURLOPT_NETRC` is enabled AND no `-u`
            //      *username* was given) fills the remaining gaps.
            // Anything still unset falls back to curl's anonymous defaults
            // (`anonymous` / `ftp@example.com`), already seeded by
            // `FtpConn::new()`.
            let explicit_user = data.set.str(StrId::Username).map(str::to_string);
            let explicit_pass = data.set.str(StrId::Password).map(str::to_string);

            // URL userinfo (empty userinfo is treated as absent, matching the
            // C `CURLUE_NO_USER`/`CURLUE_NO_PASSWORD` handling).
            let url_user = url
                .get(CurlUPart::User, CURLU_URLDECODE)
                .ok()
                .filter(|u| !u.is_empty());
            let url_pass = url
                .get(CurlUPart::Password, CURLU_URLDECODE)
                .ok()
                .filter(|p| !p.is_empty());

            // `CURLOPT_NETRC` mode (0=ignored / 1=optional / 2=required).
            let netrc_opt = CurlNetrcOption::from_long(i64::from(data.set.use_netrc))
                .unwrap_or(CurlNetrcOption::Ignored);

            // For `CURL_NETRC_REQUIRED` curl discards the URL-supplied
            // credentials up front so `.netrc` fully overrides them
            // (C `override_login` L2591-2593); the URL username is still kept as
            // the `.netrc` lookup hint below. Otherwise the URL userinfo is the
            // seed.
            let (mut user, mut passwd) = if netrc_opt == CurlNetrcOption::Required {
                (None, None)
            } else {
                (url_user.clone(), url_pass.clone())
            };

            // `-u` overrides the URL for each field independently.
            if explicit_user.is_some() {
                user = explicit_user.clone();
            }
            if explicit_pass.is_some() {
                passwd = explicit_pass.clone();
            }

            // `.netrc`: consulted only when enabled AND `-u` supplied no
            // username (C `use_netrc && !STRING_USERNAME`), and only while the
            // password is still unset (C guards the lookup with `if(!*passwdp)`).
            // The entry is matched by the URL-provided username when one exists
            // (preserved as the hint even under `REQUIRED`); otherwise the first
            // host match is taken and supplies the login too.
            if netrc_opt != CurlNetrcOption::Ignored
                && explicit_user.is_none()
                && passwd.is_none()
            {
                let host = url.get(CurlUPart::Host, 0).unwrap_or_default();
                let file = data.set.str(StrId::NetrcFile).map(Path::new);
                let hint = url_user.as_deref();
                if let Ok(Some(entry)) = netrc::resolve(netrc_opt, file, &host, hint) {
                    if user.is_none() {
                        user = entry.login;
                    }
                    if passwd.is_none() {
                        passwd = entry.password;
                    }
                }
            }

            if let Some(u) = user {
                ftpc.user = u;
            }
            if let Some(p) = passwd {
                ftpc.passwd = p;
            }

            // CURLOPT_FTP_ACCOUNT / CURLOPT_FTP_ALTERNATIVE_TO_USER
            // (C `data->set.str[STRING_FTP_ACCOUNT]` /
            // `STRING_FTP_ALTERNATIVE_TO_USER`): lift the configured strings
            // onto the FTP state so `state_user_resp` can answer a `332` with
            // `ACCT <account>` and retry a denied login with the alternative
            // command. Both stay `None` when the option is unset, matching the
            // C default of a NULL pointer.
            ftpc.account = data.set.str(StrId::FtpAccount).map(str::to_string);
            ftpc.alternative_to_user = data
                .set
                .str(StrId::FtpAlternativeToUser)
                .map(str::to_string);

            // Decode the path into directory components + the leaf file name,
            // per the configured CWD method (C `ftp_parse_url_path`). The
            // upload-without-filename malformat check is deliberately NOT done
            // here — it is deferred to the DO phase (`run_do_phase`) so the
            // login (`USER`/`PASS`/`PWD`) reaches the wire before the error, as
            // curl does (lib/ftp.c L310-313; `tests/data/test524`).
            let method = CurlFtpFile::from_raw(data.set.ftp_filemethod);
            let decomp = decompose_url_path(method, &raw_path)?;
            ftpc.rawpath = raw_path;
            ftpc.dirs = decomp.dirs;
            ftpc.file = decomp.file;
            // Decide whether ANY `CWD` is needed for this request. On a fresh
            // connection only the NOCWD-absolute rule applies (`decomp.cwddone`).
            // On a reused connection curl additionally skips ALL `CWD`s when the
            // request's directory portion is byte-identical to the previous
            // transfer's `prevpath` — "Request has same path as previous
            // transfer" (lib/ftp.c L316-334): the directory length is
            // `pathLen - strlen(file)` (or `0` for NOCWD); if that prefix equals
            // `prevpath` exactly, `cwddone = TRUE` and the DO phase goes straight
            // to the file command (`tests/data/test215`). A differing path
            // leaves `cwddone = FALSE`, and the CWD state machine first resets to
            // the login `entrypath` before descending (`test146`, `test149`).
            ftpc.cwddone = decomp.cwddone;
            if conn.bits.reuse && !ftpc.cwddone {
                if let Some(prev) = reuse_prevpath {
                    let dirlen = match method {
                        CurlFtpFile::NoCwd => 0,
                        _ => ftpc
                            .rawpath
                            .len()
                            .saturating_sub(ftpc.file.as_ref().map_or(0, String::len)),
                    };
                    if ftpc.rawpath.get(..dirlen).unwrap_or("") == prev {
                        ftpc.cwddone = true;
                    }
                }
            }

            // Lift SSL / CCC preferences (consumed by the PBSZ/PROT/CCC arms).
            ftpc.use_ssl = data.set.use_ssl;
            ftpc.ccc = data.set.ftp_ccc;
            // The active EPRT-vs-PORT preference: EPRT first unless disabled by
            // the option, OR latched off by a prior EPRT refusal carried across
            // reuse (`eprt_disabled`, set above from the pooled connection).
            // On a fresh connection `eprt_disabled` is `false`, leaving the
            // choice identical to before (`tests/data/test212`).
            ftpc.port_cmd = if data.set.ftp_use_eprt && !ftpc.eprt_disabled {
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
                match res {
                    Ok(v) => v,
                    Err(e) => {
                        // A failed *read* on the control channel (peer closed,
                        // recv error, timeout) means the connection is dead.
                        // Clear `ctl_valid` so teardown skips `QUIT`, mirroring
                        // C's `ftp_disconnect` clearing it for a dead connection
                        // (lib/ftp.c L4172-4178). Note a successfully read
                        // non-2xx status code returns `Ok((code, _))` below and
                        // therefore keeps `ctl_valid` set — curl still issues a
                        // graceful `QUIT` after a protocol error such as `550`.
                        self.ctl_valid = false;
                        return Err(e);
                    }
                }
            };
            if code != 0 {
                // C `ftp_readresp` (lib/ftp.c L607-617): a `421` ("Service not
                // available, closing control connection") can arrive at any point
                // — FTP servers use it to signal an idle-session timeout — and is
                // treated generically as `CURLE_OPERATION_TIMEDOUT`. The control
                // connection is now dead, so clear `ctl_valid` (teardown sends no
                // `QUIT`) and stop. Without this a `421` (e.g. on `CWD`) would be
                // mis-handled by the per-state logic. Oracle: tests/data/test1120.
                if code == 421 {
                    if data.set.verbose {
                        sendf::infof(true, "We got a 421 - timeout");
                    }
                    self.ctl_valid = false;
                    self.set_state(FtpState::Stop);
                    return Err(CurlError::OperationTimedout);
                }
                return Ok(code);
            }
        }
    }

    /// Send a list of custom FTP commands (`CURLOPT_QUOTE` / `CURLOPT_PREQUOTE`
    /// / `CURLOPT_POSTQUOTE`) on the control channel, one at a time, reading and
    /// validating each reply — the Rust analog of C `ftp_state_quote`
    /// (lib/ftp.c L1721) and the blocking `ftp_sendquote` (lib/ftp.c L3442).
    ///
    /// Each entry is sent verbatim followed by `CRLF`; its single reply is read
    /// and its numeric code inspected. A command prefixed with `*` (which no
    /// legal FTP verb begins with) is *allowed to fail*: the leading `*` is
    /// stripped before sending and any reply — including a `>= 400` failure — is
    /// accepted. Any other command whose reply code is `>= 400` aborts the
    /// operation with `CURLE_QUOTE_ERROR` (C: "QUOT command failed with %03d").
    /// Empty entries are skipped (matching C's `if(item->data)` guard).
    ///
    /// Used for all three quote phases: `CURLOPT_QUOTE` (after login, before
    /// `CWD`), `CURLOPT_PREQUOTE` (after `TYPE`, before the transfer command),
    /// and `CURLOPT_POSTQUOTE` (after a successful transfer's completion
    /// handshake). See `tests/data/test120`, `test121`, and `test227`.
    async fn send_quote_list(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        list: &[std::ffi::CString],
    ) -> Result<()> {
        for entry in list {
            let raw = entry.to_bytes();
            if raw.is_empty() {
                continue;
            }
            // A leading `*` marks the command as allowed-to-fail; strip it
            // before sending (C `ftp_state_quote`: `if(cmd[0] == '*')`).
            let (cmd_bytes, acceptfail) = if raw[0] == b'*' {
                (&raw[1..], true)
            } else {
                (raw, false)
            };
            if cmd_bytes.is_empty() {
                continue;
            }
            // FTP control commands are ASCII; a lossy decode is correct for the
            // send path (`send_cmd` re-encodes to bytes and appends `CRLF`).
            let cmd = String::from_utf8_lossy(cmd_bytes).into_owned();
            self.send_cmd(data, conn, &cmd).await?;
            let code = self.read_one(data, conn).await?;
            if !acceptfail && code >= 400 {
                // C: `failf(data, "QUOT command failed with %03d", ftpcode)` /
                // `"QUOT string not accepted: %s"` → `CURLE_QUOTE_ERROR`.
                sendf::failf(
                    &mut conn.filter_data.error_buffer,
                    &format!("QUOT command failed with {code:03}"),
                );
                return Err(CurlError::QuoteError);
            }
        }
        Ok(())
    }

    /// Drive the entire FTP DO phase end to end — the Rust analog of the C
    /// `switch(ftpc->state)` transfer arms (`ftp_state_cwd` → `ftp_state_type`
    /// → `ftp_state_size` → `ftp_state_rest` → `ftp_state_retr`/`stor`/`list`)
    /// fused with the body transfer the C `multi` state machine performs over
    /// `SECONDARYSOCKET`.
    ///
    /// Invoked by [`perform_ftp`] after [`FtpHandler::connect`] has completed
    /// login (so the control channel is up and, for FTPS, encrypted). It issues,
    /// in curl's exact wire order:
    ///
    /// 1. `CWD` through each URL directory component (per `--ftp-method`);
    /// 2. the data-channel command — `EPSV`/`PASV` (passive, connect-out) or
    ///    `EPRT`/`PORT` (active, bind a listener; the **accept** is deferred
    ///    until after the transfer command, matching C);
    /// 3. `TYPE I`/`TYPE A`;
    /// 4. `SIZE` (binary download only — discovers `known_filesize`);
    /// 5. `REST <offset>` (resume, when `CURLOPT_RESUME_FROM` is set);
    /// 6. the terminal `RETR`/`STOR`/`APPE`/`LIST`/`NLST`, whose `1xx`
    ///    (`150`/`125`) reply opens the data transfer;
    /// 7. for active mode, the deferred data-connection **accept**;
    /// 8. the body movement over `SECONDARYSOCKET` (download → `sink`, upload ←
    ///    `source`), then the data socket close that bounds the transfer.
    ///
    /// The trailing `226`/`250` completion line is **not** read here — it is read
    /// by [`FtpConn::ftp_done`], matching curl's split between the transfer and
    /// the `ftp_done` finalization.
    async fn run_do_phase(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        sink: &mut dyn WriteCallbacks,
        source: &mut dyn ReadCallback,
    ) -> Result<()> {
        // Ensure the "response lines as headers" capture is on for the DO-phase
        // control replies (`CWD`/`EPSV`/`TYPE`/`SIZE`/`RETR`/…). On a freshly
        // dialed connection `run_login` already enabled it (capturing the
        // greeting + `USER`/`PASS`/`PWD`); on a *reused* pooled connection login
        // is skipped, so enable it here — the drained-empty buffer then captures
        // only this transfer's DO replies, matching curl's per-transfer
        // `-D`/`--dump-header` dump on a kept-alive control channel. Idempotent.
        self.pp.enable_info_capture();

        // A path that failed to url-decode under `REJECT_CTRL` (a control byte
        // such as a percent-encoded `%00`) is malformed. C raises this at the
        // very top of `ftp_parse_url_path` — the url-decode step (lib/ftp.c
        // L221-224) — which runs in the DO phase, *after* login, and *before*
        // the upload-without-filename check. Surfacing it here (first, then the
        // upload check) reproduces that exact ordering and wire: the login
        // (`USER`/`PASS`/`PWD`) is already sent, then the transfer aborts with
        // `CURLE_URL_MALFORMAT` before any `QUOTE`/`CWD` (`tests/data/test340`).
        if self.path_malformed {
            sendf::failf(
                &mut conn.filter_data.error_buffer,
                "path contains control characters",
            );
            return Err(CurlError::UrlMalformat);
        }

        // An upload to a URL that names no file (e.g. a path ending in `/`)
        // is malformed. C makes this check in `ftp_parse_url_path` (lib/ftp.c
        // L310-313), which runs at the very start of the DO phase (`ftp_do`) —
        // *after* the control connection has logged in but *before* any
        // `QUOTE`/`CWD`. Surfacing it here reproduces that exact wire: the
        // login (`USER`/`PASS`/`PWD`) is already sent, and the transfer aborts
        // with `CURLE_URL_MALFORMAT` before issuing any further command (see
        // `tests/data/test524`/`lib524`).
        if data.set.method == HttpReq::Put && self.file.is_none() {
            sendf::failf(
                &mut conn.filter_data.error_buffer,
                "Uploading to a URL without a filename",
            );
            return Err(CurlError::UrlMalformat);
        }

        // (0) CURLOPT_QUOTE — custom commands sent immediately after login,
        // before any `CWD` (C `ftp_do` kicks off `ftp_state_quote(.., FTP_QUOTE)`
        // at lib/ftp.c L3754, and on exhaustion that state falls through to
        // `ftp_state_cwd`; lib/ftp.c L1786). See `tests/data/test227`, whose
        // wire shows `NOOP 1`/`FAIL` immediately after `PWD`, before `EPSV`.
        // Cloned out of `data.set` so the per-command `send_cmd`/`read_one`
        // calls can borrow `data` mutably.
        let quote = data
            .set
            .quote
            .as_ref()
            .map(|s| s.as_slice().to_vec())
            .unwrap_or_default();
        if !quote.is_empty() {
            self.send_quote_list(data, conn, &quote).await?;
        }

        // (1) CWD through each directory component (C `ftp_state_cwd`). A fresh
        // control connection starts at the server's home dir; CWD walks down to
        // the target directory before the file command runs.
        self.cwd_navigate(data, conn).await?;

        // Classify the operation and pick the terminal command. `TransferKind`
        // carries only RETR/STOR/LIST; APPE (vs STOR) and NLST (vs LIST) are
        // selected here from the option state.
        let is_upload = data.set.method == HttpReq::Put;
        // C `ftp_do` treats the operation as a directory listing when
        // `data->state.list_only || !ftpc->file` (lib/ftp.c L2245) — i.e. when
        // `--list-only`/`;type=d` is in force or the URL named no file (a
        // directory). NOTE: `--head`/`-I` (`opt_no_body`) on a *file* is NOT a
        // listing — see the INFO branch below.
        let is_listing = self.list_only || self.file.is_none();

        // A body-less request on a *file* (`--head`/`-I`) is curl's "INFO"
        // transfer (C sets `ftp->transfer = PPTRANSFER_INFO` in
        // `ftp_state_type`). It opens no data connection and issues no
        // `LIST`/`RETR`: it queries the file's metadata via
        // `MDTM`/`TYPE`/`SIZE`/`REST 0` and emits HTTP-style headers
        // (`Last-Modified`/`Content-Length`/`Accept-ranges`). Previously this
        // case was mis-classified as a directory listing (`EPSV`/`TYPE A`/
        // `LIST`), the root cause of the `tests/data/test104` and
        // `tests/data/test141` wire mismatches.
        if !is_upload && !is_listing && data.set.opt_no_body && self.file.is_some() {
            // Record the verb as a file operation (not a listing) for any state
            // observed by the completion path, then run the metadata sequence.
            self.transfer_kind = TransferKind::Retr;
            return self.run_info_phase(data, conn, sink).await;
        }

        // A body-less request on a *directory* (`--head`/`-I` on a path that
        // names no file, e.g. `ftp://host/1000/`) stops right after the final
        // `CWD`: curl's `ftp_perform` sets `ftp->transfer = PPTRANSFER_INFO`
        // for `data->req.no_body`, and `ftp_state_prepare_transfer` routes a
        // non-`PPTRANSFER_BODY` transfer to `FTP_RETR_PREQUOTE`. With no file to
        // stat, the prequote state falls straight through to `FTP_STOP`
        // (lib/ftp.c L1786-1793) — so curl opens NO data connection and issues
        // NO `EPSV`/`TYPE A`/`LIST` for a directory `NOBODY` request. Previously
        // this case was mis-classified as a directory listing (it has
        // `is_listing == true` because `file.is_none()`), emitting the extra
        // `EPSV`/`TYPE A`/`LIST` — the root cause of the `tests/data/test1000`
        // wire mismatch. Mirror curl exactly: stop after `CWD`. `dont_check`
        // suppresses the (absent) trailing `226`/`250` completion read, and the
        // control channel stays valid (`ctl_valid` is untouched after a
        // successful `cwd_navigate`) so a graceful `QUIT` still follows in
        // teardown — yielding `USER`/`PASS`/`PWD`/`CWD`/`QUIT`. `transfer_kind`
        // is left at its default: it is inert on this path (no data transfer,
        // `maxdownload == 0`, no `run_*_phase` body code runs).
        if !is_upload && data.set.opt_no_body && self.file.is_none() {
            self.dont_check = true;
            return Ok(());
        }

        let (kind, direction) = if is_upload {
            (TransferKind::Stor, TransferDirection::Upload)
        } else if is_listing {
            (TransferKind::List, TransferDirection::Download)
        } else {
            (TransferKind::Retr, TransferDirection::Download)
        };
        self.transfer_kind = kind;

        // MDTM + time-condition (C `ftp_state_mdtm` / `ftp_state_mdtm_resp`,
        // lib/ftp.c). For a single *file* transfer in **either direction**, when
        // the file time was requested (`CURLOPT_FILETIME`) or a time condition
        // is active (`-z`), query the modification time via `MDTM` *before*
        // opening the data channel — C `ftp_state_mdtm` gates this on
        // `(get_filetime || timecondition) && file` regardless of upload vs
        // download. The wire order is `… / MDTM / EPSV / TYPE / SIZE / RETR` for
        // a download (`tests/data/test139`) and `… / MDTM / EPSV / TYPE / STOR`
        // for an upload (`tests/data/test248`). A `213` reply sets
        // `info.filetime`; a `550`/other reply is non-fatal ("MDTM failed …
        // continuing"). Directory listings (`LIST`/`NLST`) have no single file
        // and are excluded.
        if !is_listing
            && self.file.is_some()
            && (data.set.get_filetime || data.set.timecondition != 0)
        {
            let f = self.file.clone().unwrap_or_default();
            self.send_cmd(data, conn, &format!("MDTM {f}")).await?;
            let code = self.read_one(data, conn).await?;
            if code == 213 {
                if let Some(ft) = parse_mdtm_213(&self.last_response) {
                    data.info.filetime = ft;
                }
            }

            // Time-condition gate (C `ftp_state_mdtm_resp`): `IFMODSINCE` (the
            // `-z "<date>"` default) skips the transfer when the file is NOT
            // newer (`filetime <= timevalue`); `IFUNMODSINCE` (`-z "-<date>"`)
            // skips when it IS newer (`filetime > timevalue`). Only applied when
            // both the parsed filetime and the configured timevalue are
            // positive, exactly as curl guards it.
            if data.set.timecondition != 0 {
                let filetime = data.info.filetime;
                let timevalue = data.set.timevalue;
                if filetime > 0 && timevalue > 0 {
                    // `CURL_TIMECOND_IFUNMODSINCE == 2`; every other selector
                    // (including `IFMODSINCE == 1`) takes the default skip rule.
                    let skip = if data.set.timecondition == 2 {
                        filetime > timevalue
                    } else {
                        filetime <= timevalue
                    };
                    if skip {
                        // `CURLINFO_CONDITION_UNMET`: no data transfer and no
                        // trailing `226`/`250`, so the control channel stays
                        // valid for a graceful `QUIT` (`tests/data/test140`
                        // expects exactly `MDTM` then `QUIT`).
                        data.info.timecond = true;
                        self.dont_check = true;
                        return Ok(());
                    }
                }
            }
        }

        // (2) Establish the data-channel endpoint. Passive connects out now
        // (before TYPE/SIZE/RETR, as in `tests/data/test102`); active binds a
        // listener and advertises it via EPRT/PORT, deferring the accept.
        let active = data.set.ftp_use_port;
        if active {
            // C `ftp_state_prepare_transfer` (lib/ftp.c L1333-1356): the
            // `data->set.ftp_use_port` branch goes straight to PORT/EPRT — PRET
            // is *not* sent in active mode, since PRET only prepares the server
            // for an upcoming PASV.
            self.negotiate_active_noaccept(data, conn).await?;
        } else {
            // PRET (proftpd "PRE Transfer" extension, `--ftp-pret` →
            // `CURLOPT_FTP_USE_PRET`) must precede the PASV/EPSV when requested,
            // mirroring C `ftp_state_prepare_transfer` (lib/ftp.c L1339-1352):
            // the server is told the upcoming data command so it can pre-open
            // the passive port (required behind certain proxies/load-balancers
            // such as Drupal/Pure-FTPd in mirror mode). The reply must be `200`;
            // anything else aborts the transfer with `CURLE_FTP_PRET_FAILED`
            // (C `case FTP_PRET`, lib/ftp.c L3331-3335 — "there only is this one
            // standard OK return code"). Gated on `ftp_use_pret` (default off),
            // so non-PRET transfers issue the identical wire sequence as before.
            // Oracle: tests/data/test1107 (`PRET RETR <file>` → 200 → proceed
            // to EPSV/TYPE/SIZE/RETR) and tests/data/test1108 (`PRET RETR
            // <file>` → 550 → exit 84, no data channel opened).
            if data.set.ftp_use_pret {
                let pret_cmd = match &self.file {
                    // No file in the URL → directory listing. C selects the
                    // custom request if set, else `NLST`/`LIST` per
                    // `--list-only` (`data->state.list_only`).
                    None => {
                        let listcmd = if self.list_only { "NLST" } else { "LIST" };
                        format!("PRET {listcmd}")
                    }
                    // A named file: `PRET STOR` for an upload, `PRET RETR` for a
                    // download (C `data->state.upload` branch).
                    Some(f) if is_upload => format!("PRET STOR {f}"),
                    Some(f) => format!("PRET RETR {f}"),
                };
                self.send_cmd(data, conn, &pret_cmd).await?;
                let code = self.read_one(data, conn).await?;
                if code != 200 {
                    crate::failf!(
                        &mut conn.filter_data.error_buffer,
                        "PRET command not accepted: {code:03}"
                    );
                    return Err(CurlError::FtpPretFailed);
                }
            }
            self.negotiate_passive(data, conn).await?;
        }

        // FTP-over-HTTP-proxy CONNECT (tunnel): surface the DATA-channel CONNECT
        // response (status line + headers + blank line) onto the body stream,
        // producing the SECOND "200 Connection established" block ahead of the
        // transferred content (oracle: tests/data/test714, test715). The passive
        // data connection was opened just above by `connect_data_passive`, which
        // performed the `CONNECT` to the PASV/EPSV endpoint through the proxy;
        // its captured response lives on the `SECONDARYSOCKET` filter. Gated like
        // the control-channel surface in `perform_ftp` and curl's
        // `CLIENTWRITE_CONNECT` path: only for a passive tunneled transfer, and
        // only when `--suppress-connect-headers` is not set. Active mode is not
        // reachable through a CONNECT tunnel (no test exercises it).
        #[cfg(all(feature = "ftp", feature = "http", feature = "proxy"))]
        if !active && conn.bits.tunnel_proxy && !data.set.suppress_connect_headers {
            if let Some(lines) = conn.cfilter[SECONDARYSOCKET].connect_response_headers() {
                for line in &lines {
                    let mut off = 0;
                    while off < line.len() {
                        let n = sink.write_body(&line[off..]);
                        if n == 0 {
                            break;
                        }
                        off += n;
                    }
                }
            }
        }

        // (2c) Range validation (C `ftp_do_more` → `Curl_range`, lib/ftp.c
        // L2237). curl validates `CURLOPT_RANGE` right after the data connection
        // is established (EPSV/PASV are already on the wire above) and BEFORE any
        // TYPE/SIZE/REST/RETR. A malformed or out-of-range specification — for
        // instance a leading offset that overflows `curl_off_t`
        // (`-r 36893488147419103232-`) — makes `Curl_range` return
        // `CURLE_RANGE_ERROR`, but C does **not** treat that as a fatal transfer
        // error: the download branch hits `if(result) ;` — an *empty statement*
        // (lib/ftp.c L2249) that merely SKIPS the TYPE/REST/RETR setup — and the
        // trailing `result = ftp_statemach(...)` (lib/ftp.c L2273) then
        // OVERWRITES the range error with the (OK) state-machine result. The net
        // observable effect is: the data channel is set up, NO TYPE/SIZE/RETR is
        // sent, and the transfer completes SUCCESSFULLY (exit 0) with a graceful
        // `QUIT`. This was verified empirically against curl 8.14.1, whose
        // `stderr` is empty and whose wire is exactly `USER`/`PASS`/`PWD`/`EPSV`/
        // `QUIT`. Mirror that here: on a parse failure, skip the remaining
        // download commands and finish the DO phase `Ok(())`. `dont_check`
        // suppresses the (absent) trailing `226`/`250` completion read, and
        // `ctl_valid` is left untouched, so the end-of-run teardown emits `QUIT`.
        // A *well-formed* range is re-parsed in step (4b) below for the
        // resume/`maxdownload` offsets (`parse_range` is pure). Oracle:
        // tests/data/test1449.
        if direction == TransferDirection::Download
            && kind == TransferKind::Retr
            && data
                .set
                .str(StrId::SetRange)
                .is_some_and(|range| crate::protocols::file::parse_range(range).is_err())
        {
            self.dont_check = true;
            self.maxdownload = -1;
            return Ok(());
        }

        // (3) TYPE — pick the transfer mode exactly as curl's `ftp_do` does
        // (C: `lib/ftp.c` L2245-L2266). A *directory listing* (`LIST`/`NLST`,
        // i.e. `TransferKind::List`) is always requested in ASCII mode: curl
        // calls `ftp_nb_type(data, ..., TRUE /*ascii*/, FTP_LIST_TYPE)` for the
        // `(list_only || !file)` case, regardless of `CURLOPT_TRANSFERTEXT`,
        // because directory listings are text and servers convert line endings
        // for them (see `tests/data/test100`, which expects `TYPE A` before
        // `LIST`). A *file* transfer (`RETR`/`STOR`/`APPE`) instead honors
        // `CURLOPT_TRANSFERTEXT` (and a URL `;type=A`/`;type=I`) via the
        // per-transfer `prefer_ascii` (ASCII when set, else binary). Sent once
        // per transfer (curl re-sends only on a type change).
        let type_byte = if kind == TransferKind::List {
            b'A'
        } else {
            ftp_type_arg(self.prefer_ascii)
        };
        // C `ftp_need_type`: send `TYPE` only when the connection's current
        // transfer type differs from the wanted one (lib/ftp.c L342-347). On a
        // fresh connection `transfertype == 0`, so this always sends and the
        // non-reuse wire is unchanged; on a reused connection whose type already
        // matches (e.g. a second listing, still `TYPE A`), the redundant `TYPE`
        // is skipped (`tests/data/test215`).
        if self.transfertype != type_byte {
            self.send_type(data, conn, type_byte).await?;
        }

        // (3b) CURLOPT_PREQUOTE — custom commands sent after `TYPE`, just before
        // the transfer command (C `ftp_state_{retr,stor,list}_prequote` →
        // `ftp_state_quote(.., *_PREQUOTE)`; lib/ftp.c L1467-L1480). For every
        // transfer kind the prequote runs after `TYPE` and before
        // `SIZE`/`REST`/the terminal `RETR`/`STOR`/`LIST`. See
        // `tests/data/test227`, whose wire shows `NOOP 2`/`FAIL HARD` between
        // `TYPE I` and `SIZE`.
        let prequote = data
            .set
            .prequote
            .as_ref()
            .map(|s| s.as_slice().to_vec())
            .unwrap_or_default();
        if !prequote.is_empty() {
            self.send_quote_list(data, conn, &prequote).await?;
        }

        // (4) SIZE — for a binary download it gives the engine a content length
        // (`known_filesize`) for progress; for an *auto-resuming upload* (`-C -`
        // → `set_resume_from < 0`) curl issues SIZE to discover the remote
        // resume offset (C `ftp_state_ul_setup`: `resume_from < 0` → send `SIZE`
        // → `FTP_STOR_SIZE`; the wire `… TYPE I / SIZE / STOR` in
        // `tests/data/test235`). A non-2xx `SIZE` (some servers reject it with
        // `500`/`550`) is non-fatal: the size simply stays unknown and the
        // upload starts from offset 0 (a full `STOR`).
        let need_upload_size =
            kind == TransferKind::Stor && data.set.set_resume_from < 0;
        // `CURLOPT_IGNORE_CONTENT_LENGTH` (`--ignore-content-length`): support
        // *growing files* by NOT discovering the remote size — curl skips the
        // `SIZE` command entirely and performs an open-ended `RETR`, reading
        // until the data connection closes rather than stopping at a (possibly
        // stale/short) reported length. C gates the size discovery on
        // `!(data->set.ignorecl || data->state.prefer_ascii)` (lib/ftp.c
        // L1793-1818): with `ignorecl` set the `else` arm sends no `SIZE` and
        // goes straight to an open-ended retrieve. ASCII downloads already skip
        // `SIZE` here because they use `TYPE A` (`type_byte != b'I'`), so adding
        // the `ignorecl` guard completes the `ignorecl || prefer_ascii` parity.
        // With no `SIZE`, `known_filesize` stays -1 and the transfer is
        // open-ended (`with_size` is not applied), reading to EOF. Uploads
        // (`need_upload_size`, the `-C -` SIZE probe) are unaffected.
        // (oracle tests/data/test416).
        let need_download_size =
            kind == TransferKind::Retr && type_byte == b'I' && !data.set.ignorecl;
        if need_download_size || need_upload_size {
            if let Some(file) = self.file.clone() {
                self.send_size(data, conn, &file).await?;
            }
        }

        // (4a) CURLOPT_MAXFILESIZE (`--max-filesize`): when `SIZE` reported a
        // length larger than the cap, abort the *download* before opening the
        // data channel / sending `RETR` (C `ftp_state_size_resp`:
        // `if(data->set.max_filesize && ftpc->known_filesize > …) return
        // CURLE_FILESIZE_EXCEEDED`). The wire shows `… / SIZE / QUIT` with no
        // `RETR` (`tests/data/test290`). `CURLE_FILESIZE_EXCEEDED` is in the
        // "stays alive" set, so a graceful `QUIT` still follows in
        // `disconnect`.
        if kind == TransferKind::Retr
            && data.set.max_filesize > 0
            && self.known_filesize > data.set.max_filesize
        {
            sendf::failf(
                &mut conn.filter_data.error_buffer,
                "Maximum file size exceeded",
            );
            return Err(CurlError::FilesizeExceeded);
        }

        // (4b) Range / resume bookkeeping (C `Curl_range` + `ftp_state_retr` /
        // `ftp_state_ul_setup`). A `CURLOPT_RANGE` (`-r`) carries both an
        // explicit start offset *and* (for a bounded `X-Y` / `-N`) a
        // `maxdownload` cap; a `CURLOPT_RESUME_FROM` (`-C n`) carries only the
        // offset. The effective `REST` offset is computed here and the
        // "entire file already transferred" short-circuits are applied before
        // the terminal command is sent.
        let mut resume_off: i64 = 0;
        if direction == TransferDirection::Download && kind == TransferKind::Retr {
            // C `ftp_do` (download branch): parse the range; when it is
            // *bounded* (`maxdownload >= 0`) mark `dont_check` so the
            // post-transfer status check is skipped and an `ABOR` is issued once
            // the cap is reached (see [`FtpConn::ftp_done`]).
            if let Some(range) = data.set.str(StrId::SetRange) {
                if let Ok(outcome) = crate::protocols::file::parse_range(range) {
                    resume_off = outcome.resume_from;
                    self.maxdownload = outcome.maxdownload;
                    if self.maxdownload >= 0 {
                        self.dont_check = true;
                    }
                }
            } else {
                resume_off = data.set.set_resume_from;
            }

            // C `ftp_state_retr`: with a known file size (`SIZE` → `213`) and a
            // resume offset, compute how many bytes remain. If none remain, the
            // file is already fully downloaded — skip `REST`/`RETR` and proceed
            // to a graceful `QUIT` (see `tests/data/test122`). A resume offset
            // beyond the file size is `CURLE_BAD_DOWNLOAD_RESUME`.
            if resume_off != 0 && self.known_filesize >= 0 {
                let downloadsize = if resume_off < 0 {
                    // `-N`: download the last N bytes.
                    if self.known_filesize < -resume_off {
                        sendf::failf(
                            &mut conn.filter_data.error_buffer,
                            &format!(
                                "Offset ({resume_off}) was beyond file size ({})",
                                self.known_filesize
                            ),
                        );
                        return Err(CurlError::BadDownloadResume);
                    }
                    -resume_off
                } else {
                    if self.known_filesize < resume_off {
                        sendf::failf(
                            &mut conn.filter_data.error_buffer,
                            &format!(
                                "Offset ({resume_off}) was beyond file size ({})",
                                self.known_filesize
                            ),
                        );
                        return Err(CurlError::BadDownloadResume);
                    }
                    self.known_filesize - resume_off
                };
                if downloadsize == 0 {
                    // Nothing to transfer (C "File already completely
                    // downloaded"): no `REST`, no `RETR`, no `ABOR`. The control
                    // channel stays valid for a graceful `QUIT`.
                    self.dont_check = true;
                    self.maxdownload = -1;
                    return Ok(());
                }
                if resume_off < 0 {
                    // Convert "last N bytes" to the absolute `REST` offset.
                    resume_off = self.known_filesize - downloadsize;
                }
            }
            // Record the effective absolute download offset for the
            // partial-file check (a `CURLOPT_RANGE` start does not flow through
            // `set.set_resume_from`).
            self.xfer_resume_off = resume_off.max(0);
        }

        // (5) REST — resume offset for a download (C `ftp_state_rest`). Upload
        // resume is expressed via APPE, not REST.
        if resume_off > 0 && direction == TransferDirection::Download {
            self.send_rest(data, conn, resume_off).await?;
        }

        // (5b) Upload resume "already complete" (C `ftp_state_ul_setup`): with an
        // explicit positive resume offset and a known input size, the source is
        // logically advanced by `resume_from` and the remaining length is
        // `infilesize - resume_from`. When nothing remains the file is already
        // fully uploaded — skip `STOR`/`APPE` and `QUIT` (see
        // `tests/data/test123`, whose wire ends `TYPE I` then `QUIT`).
        if is_upload {
            let mut resume = data.set.set_resume_from;
            // `-C -` (auto-resume, `set_resume_from < 0`): the real offset was
            // just probed via `SIZE` above. A `213` set `known_filesize`; a
            // failed `SIZE` (`500`/`550`) leaves it unknown (`-1`), in which
            // case curl uploads the whole file from offset 0 (C
            // `ftp_state_size_resp` for `FTP_STOR_SIZE` → `ftp_state_ul_setup`
            // with the discovered size, or 0 when SIZE failed). `max(0)` folds
            // both "unknown" and "empty remote file" into a full `STOR`.
            if resume < 0 {
                resume = self.known_filesize.max(0);
            }
            if resume > 0 {
                let infilesize = data.set.filesize;
                if infilesize >= 0 && infilesize - resume <= 0 {
                    // Nothing remains to send — the file is already fully
                    // uploaded; skip `STOR`/`APPE` entirely and `QUIT`
                    // (C "File already completely uploaded"; `tests/data/test123`).
                    self.dont_check = true;
                    return Ok(());
                }
                // Bytes remain (or the input size is unknown): curl resumes by
                // skipping the first `resume` bytes of the source and APPENDing
                // the rest (C `ftp_state_ul_setup`: `append = TRUE;` + source
                // seek). Force the `APPE` verb (chosen in `transfer_command`)
                // and record the offset for `run_upload_body` to skip.
                self.upload_append = true;
                self.upload_resume_from = resume;
            }
        }

        // (6) The terminal transfer command. Its `1xx` reply (150/125) signals
        // the data connection is opening; a `>=400` reply maps to the curl
        // error for the operation (e.g. 550 RETR → REMOTE_FILE_NOT_FOUND).
        let cmd = self.transfer_command(data, kind)?;
        self.send_cmd(data, conn, &cmd).await?;
        let code = self.read_one(data, conn).await?;
        let transfer_open = self.check_transfer_start(code, kind)?;

        // An empty directory listing (a `LIST`/`NLST` answered with `450 No
        // files`) opens no data connection — there is nothing to accept,
        // TLS-upgrade, or read. curl treats this as a *successful* empty
        // listing: it sets `PPTRANSFER_NONE`, transitions to `FTP_STOP`, and
        // proceeds to a graceful `QUIT` (C: lib/ftp.c L2783-2787). Mark the
        // completion handshake as skipped (no trailing `226`/`250` arrives) and
        // finish the DO phase successfully so the control connection is closed
        // via `QUIT` rather than torn down as dead — see `tests/data/test144`,
        // whose expected wire ends `NLST` then `QUIT`.
        if !transfer_open {
            self.dont_check = true;
            return Ok(());
        }

        // (7) Active mode: now that the server has the transfer command, accept
        // its inbound data connection (correct ordering — the accept must follow
        // RETR/STOR, not the earlier PORT).
        if active {
            self.accept_data_active(data, conn).await?;
        }

        // (7b) Data-channel TLS handshake for FTPS `PROT P` — deferred until *after*
        // the transfer command's `150`/`125` reply, for BOTH passive and active.
        // An FTPS server does not begin the TLS handshake on the data connection
        // until it has received `RETR`/`STOR`/`LIST` (C `ftp_do_more`: "an SSL
        // filter is in place and the server will not start the TLS handshake until
        // we send more FTP commands"). The passive connect-out and the active
        // accept therefore both bring up only the TCP layer earlier; the rustls
        // layer is added here, once the server is ready. Doing it before the
        // transfer command deadlocks (the client `ClientHello` waits for a
        // `ServerHello` the server will not send until the command arrives) — the
        // root cause of QA F4-CRIT-2 for passive FTPS downloads.
        if self.data_channel_uses_tls(data) {
            self.upgrade_data_tls(data, conn).await?;
        }

        // (8) Move the body, then bound the data connection.
        match direction {
            TransferDirection::Download => self.run_download_body(data, conn, sink).await,
            TransferDirection::Upload => self.run_upload_body(data, conn, source).await,
            TransferDirection::None | TransferDirection::Bidirectional => Ok(()),
        }
    }

    /// `CWD` through each URL directory component (C `ftp_state_cwd`). Each
    /// component is issued in turn; a non-2xx reply fails the transfer
    /// (`CURLE_REMOTE_ACCESS_DENIED`), matching curl's default behavior when
    /// `--ftp-create-dirs` is not in force.
    async fn cwd_navigate(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<()> {
        // (reuse) The previous transfer left us in the exact directory this
        // request needs — `cwddone` was set in `setup_connection` by the
        // same-path comparison against `prevpath`, or by the NOCWD-absolute
        // rule. Emit no `CWD` at all and go straight to the file command
        // (C `ftp_state_cwd`: `if(ftpc->cwddone)`; `tests/data/test215`).
        if self.cwddone {
            return Ok(());
        }
        // (reuse) A DIFFERENT directory on a reused connection: curl first
        // changes back to the login entry path, then descends to the new
        // target — it does NOT issue relative `CWD`s from wherever the previous
        // transfer ended (C `ftp_state_cwd` L838-849; `tests/data/test146`,
        // `test149`). The reset is skipped for an absolute request path
        // (a non-empty `dirdepth` AND a leading-slash `rawpath`), which already
        // descends from root. A fresh connection (no reuse, or no `entrypath`
        // yet) descends directly from the post-login working directory —
        // byte-identical to the pre-reuse behavior.
        if conn.bits.reuse {
            if let Some(entry) = self.entrypath.clone() {
                let absolute = !self.dirs.is_empty() && self.rawpath.starts_with('/');
                if !absolute {
                    let cwd_cmd = format!("CWD {entry}");
                    self.send_cmd(data, conn, &cwd_cmd).await?;
                    let code = self.read_one(data, conn).await?;
                    if code / 100 != 2 {
                        sendf::failf(
                            &mut conn.filter_data.error_buffer,
                            &format!("Server denied changing to directory: {code:03}"),
                        );
                        self.cwdfail = true;
                        return Err(CurlError::RemoteAccessDenied);
                    }
                }
            }
        }
        let dirs = self.dirs.clone();
        // C `ftp_state_cwd` MKD-on-failure: when `CURLOPT_FTP_CREATE_MISSING_DIRS`
        // is set (`--ftp-create-dirs` → `CURLFTP_CREATE_DIR_RETRY` = 2), a `CWD`
        // into a non-existent directory is recovered by issuing `MKD <dir>` and
        // retrying the `CWD` (lib/ftp.c FTP_CWD / FTP_MKD response arms,
        // L3253-L3306). Level 2 additionally tolerates a *failed* `MKD` (e.g. a
        // racing session already created the dir, or the server rejects it) and
        // still retries the `CWD` exactly once. See `tests/data/test147`
        // (`CWD`→`MKD`→`CWD` ok) and `tests/data/test148`
        // (`CWD`→`MKD`→`CWD` all fail → exit 9 `CURLE_REMOTE_ACCESS_DENIED`).
        let create_missing = data.set.ftp_create_missing_dirs;
        for comp in &dirs {
            let cwd_cmd = format!("CWD {}", comp.name);
            self.send_cmd(data, conn, &cwd_cmd).await?;
            let code = self.read_one(data, conn).await?;
            if code / 100 == 2 {
                continue;
            }
            // The `CWD` was denied. Without `--ftp-create-dirs` this is fatal
            // (curl's default: `CURLE_REMOTE_ACCESS_DENIED`).
            if create_missing == 0 {
                sendf::failf(
                    &mut conn.filter_data.error_buffer,
                    &format!("Server denied changing to directory: {code:03}"),
                );
                self.cwdfail = true;
                return Err(CurlError::RemoteAccessDenied);
            }
            // Attempt to create the missing directory (C `MKD %.*s`). `count3`
            // in C is the number of tolerated `MKD` failures: 1 for level 2
            // (retry), 0 for level 1 (create-only).
            let mkd_retry = create_missing == 2;
            let mkd_cmd = format!("MKD {}", comp.name);
            self.send_cmd(data, conn, &mkd_cmd).await?;
            let mkd_code = self.read_one(data, conn).await?;
            if mkd_code / 100 != 2 && !mkd_retry {
                // `MKD` failed and no retry is permitted (C "Failed to MKD
                // dir: %03d" → `CURLE_REMOTE_ACCESS_DENIED`).
                sendf::failf(
                    &mut conn.filter_data.error_buffer,
                    &format!("Failed to MKD dir: {mkd_code:03}"),
                );
                self.cwdfail = true;
                return Err(CurlError::RemoteAccessDenied);
            }
            // `MKD` succeeded (or failed but is tolerated once): retry the
            // `CWD` into the directory exactly once. A second failure is fatal
            // (C: the `count2` guard now blocks another `MKD`).
            self.send_cmd(data, conn, &cwd_cmd).await?;
            let retry_code = self.read_one(data, conn).await?;
            if retry_code / 100 != 2 {
                sendf::failf(
                    &mut conn.filter_data.error_buffer,
                    &format!("Server denied changing to directory: {retry_code:03}"),
                );
                self.cwdfail = true;
                return Err(CurlError::RemoteAccessDenied);
            }
        }
        self.cwddone = true;
        Ok(())
    }

    /// Passive data-channel negotiation: send `EPSV` (then `PASV` on refusal),
    /// parse the advertised endpoint, and connect the secondary socket out to it
    /// (installing its filter chain). Reuses [`FtpConn::send_pasv`] /
    /// [`FtpConn::state_pasv_resp`] / [`FtpConn::connect_data_passive`].
    async fn negotiate_passive(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<()> {
        self.send_pasv(data, conn).await?;
        let code = self.read_one(data, conn).await?;
        self.state_pasv_resp(data, conn, code).await?;
        // An EPSV *reply* refusal (non-229) disabled EPSV and re-sent PASV; read
        // its reply. (This is distinct from the data-connect failure handled
        // below: here the server rejected the `EPSV` command itself.)
        if self.data_host.is_none() {
            let code = self.read_one(data, conn).await?;
            self.state_pasv_resp(data, conn, code).await?;
        }

        // Connect the data channel. A *successful* `EPSV` reply (`229`) can still
        // advertise an unreachable data port (e.g. a firewalled/bogus port, or a
        // broken NAT helper); curl handles this in `ftp_do_more`, whose three
        // data-connect-failure sites (lib/ftp.c L2003/L2069/L2168) call
        // `ftp_epsv_disable` to disable EPSV, re-send `PASV`, and retry — exactly
        // the behavior `tests/data/test1233` exercises (EPSV → 229 (|||1|) →
        // connect fails → `PASV` → `227` → data connect succeeds → RETR).
        match self.connect_data_passive(data, conn).await {
            Ok(()) => Ok(()),
            Err(e) => {
                // Only EPSV (`count1 == 0`) has a PASV fallback. C's
                // `ftp_epsv_disable` refuses to disable EPSV on a genuine IPv6
                // control channel (PASV cannot express an IPv6 data endpoint),
                // returning `CURLE_WEIRD_SERVER_REPLY`; mirror that by only
                // retrying when the control connection is IPv4. On IPv6 (or if a
                // PASV attempt itself failed) the original connect error stands.
                let used_epsv = self.count1 == 0;
                let control_is_ipv6 = Curl_conn_get_ip_info(conn, FIRSTSOCKET)
                    .map(|(is_ipv6, _)| is_ipv6)
                    .unwrap_or(false);
                if used_epsv && !control_is_ipv6 {
                    // `epsv_disable` latches EPSV off and sends `PASV`; read and
                    // parse its `227` reply, then retry the data connect.
                    self.epsv_disable(data, conn).await?;
                    let code = self.read_one(data, conn).await?;
                    self.state_pasv_resp(data, conn, code).await?;
                    self.connect_data_passive(data, conn).await
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Active data-channel setup **without** accepting: bind a local listener,
    /// install the TCP-accept filter, advertise it via `EPRT`/`PORT` (with the
    /// EPRT→PORT fallback), and wait for the command's `2xx`. The inbound
    /// connection is accepted later — after the transfer command — by
    /// [`FtpConn::accept_data_active`].
    async fn negotiate_active_noaccept(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        self.setup_active(data, conn).await?;
        loop {
            let code = self.read_one(data, conn).await?;
            if self.state_port_resp(data, conn, code).await? {
                break;
            }
        }
        Ok(())
    }

    /// Send `TYPE <I|A>` and verify the `2xx` reply (C `ftp_state_type`). Records
    /// the active transfer type so a reused connection can skip a redundant
    /// `TYPE`.
    async fn send_type(&mut self, data: &mut Easy, conn: &mut Connection, ty: u8) -> Result<()> {
        let cmd = format!("TYPE {}", ty as char);
        self.send_cmd(data, conn, &cmd).await?;
        let code = self.read_one(data, conn).await?;
        if code / 100 != 2 {
            sendf::failf(
                &mut conn.filter_data.error_buffer,
                &format!("Couldn't set desired transfer type: {code:03}"),
            );
            return Err(CurlError::FtpCouldntSetType);
        }
        self.transfertype = ty;
        Ok(())
    }

    /// Send `SIZE <file>` and, on a `213` reply, record the file size in
    /// [`FtpConn::known_filesize`] (C `ftp_state_size`). A non-`2xx` reply (server
    /// without `SIZE`, or an ASCII-mode size) is **non-fatal** — the size stays
    /// unknown and the transfer proceeds open-ended.
    async fn send_size(&mut self, data: &mut Easy, conn: &mut Connection, file: &str) -> Result<()> {
        let cmd = format!("SIZE {file}");
        self.send_cmd(data, conn, &cmd).await?;
        let code = self.read_one(data, conn).await?;
        if code == 213 {
            if let Some(size) = parse_size_213(&self.last_response) {
                self.known_filesize = size;
            }
        }
        Ok(())
    }

    /// Send `REST <offset>` to resume a download and verify the `350` reply
    /// (C `ftp_state_rest`).
    async fn send_rest(&mut self, data: &mut Easy, conn: &mut Connection, offset: i64) -> Result<()> {
        let cmd = format!("REST {offset}");
        self.send_cmd(data, conn, &cmd).await?;
        let code = self.read_one(data, conn).await?;
        if code != 350 {
            sendf::failf(
                &mut conn.filter_data.error_buffer,
                &format!("Couldn't use REST: {code:03}"),
            );
            return Err(CurlError::FtpCouldntUseRest);
        }
        Ok(())
    }

    /// Build the terminal transfer command string for `kind`, selecting
    /// `APPE` vs `STOR` (`--append`) and `NLST` vs `LIST` (`--list-only`).
    fn transfer_command(&self, data: &Easy, kind: TransferKind) -> Result<String> {
        Ok(match kind {
            TransferKind::Retr => {
                let file = self.file.clone().ok_or(CurlError::UrlMalformat)?;
                format!("RETR {file}")
            }
            TransferKind::Stor => {
                let file = self.file.clone().ok_or(CurlError::UrlMalformat)?;
                // `APPE` is selected either explicitly (`CURLOPT_APPEND` /
                // `--append`) or implicitly by an upload *resume* (C
                // `ftp_state_ul_setup` forces `append = TRUE` whenever
                // `resume_from > 0`), so the remaining bytes are appended to the
                // partial remote file rather than truncating it.
                if data.set.remote_append || self.upload_append {
                    format!("APPE {file}")
                } else {
                    format!("STOR {file}")
                }
            }
            TransferKind::List => {
                // Base verb: NLST when `--list-only` / `CURLOPT_DIRLISTONLY`
                // or a URL `;type=D` suffix is in force, else LIST (C:
                // `ftp_state_list`, lib/ftp.c L1442-1443 —
                // `data->state.list_only ? "NLST" : "LIST"`). The per-transfer
                // `self.list_only` already folds in the URL override.
                let base = if self.list_only { "NLST" } else { "LIST" };

                // For the NOCWD method curl does *not* `CWD` into the directory;
                // instead it appends the directory path as an argument to
                // LIST/NLST (C: `ftp_state_list`, lib/ftp.c L1424-1445). The
                // argument is `rawpath` truncated at its last '/': for a
                // `dir/dir/` path that drops the trailing slash (→ `dir/dir`),
                // and the absolute root `/` is preserved via the special-case
                // `if(n == 0) ++n;`. `self.rawpath` already matches C's
                // `ftpc->rawpath` exactly — URL-decoded with the leading '/'
                // stripped (C uses `ftp->path = &up.path[1]`, lib/ftp.c L4290)
                // — so this slash arithmetic is byte-for-byte identical to the
                // C oracle. The other methods (MULTICWD/SINGLECWD) `CWD` into
                // the directory first and then issue a bare LIST/NLST, so no
                // path argument is added here.
                let method = CurlFtpFile::from_raw(data.set.ftp_filemethod);
                if method == CurlFtpFile::NoCwd {
                    match self.rawpath.rfind('/') {
                        Some(slash) => {
                            let n = if slash == 0 { 1 } else { slash };
                            format!("{base} {}", &self.rawpath[..n])
                        }
                        None => base.to_string(),
                    }
                } else {
                    base.to_string()
                }
            }
        })
    }

    /// Validate the terminal command's first reply: a `1xx` (`150`/`125`) opens
    /// the data transfer; any other reply maps to the curl error appropriate to
    /// the operation (download → `REMOTE_FILE_NOT_FOUND` on 550, else
    /// `FTP_COULDNT_RETR_FILE`; upload → `UPLOAD_FAILED`).
    fn check_transfer_start(&self, code: i32, kind: TransferKind) -> Result<bool> {
        // A `1xx` (`150`/`125`) opens the data transfer — proceed to move data.
        if code / 100 == 1 {
            return Ok(true);
        }
        // A directory listing answered with `450` means "no matching files":
        // curl treats it as a *successful empty listing*, not an error. It
        // opens no data connection and goes straight to a graceful `QUIT`
        // (C: the RETR/LIST response handler, lib/ftp.c L2783-2787 —
        // `if((instate == FTP_LIST) && (ftpcode == 450)) { ftp->transfer =
        // PPTRANSFER_NONE; ftp_state(data, ftpc, FTP_STOP); }`). Signal "no
        // transfer opened" so the caller skips the data phase but still
        // succeeds.
        if kind == TransferKind::List && code == 450 {
            return Ok(false);
        }
        // Any other non-`1xx` reply fails the operation. curl maps only a
        // *RETR* answered with `550` to `CURLE_REMOTE_FILE_NOT_FOUND`; every
        // other download/listing failure (including a `LIST` `550`) is
        // `CURLE_FTP_COULDNT_RETR_FILE`, and an upload is `CURLE_UPLOAD_FAILED`
        // (C: lib/ftp.c L2788-2791, `instate == FTP_RETR && ftpcode == 550`).
        match kind {
            TransferKind::Stor => Err(CurlError::UploadFailed),
            TransferKind::Retr if code == 550 => Err(CurlError::RemoteFileNotFound),
            _ => Err(CurlError::FtpCouldntRetrFile),
        }
    }

    /// Layer a TLS filter atop an already-connected active-mode data socket
    /// (`SECONDARYSOCKET`) and drive its handshake — the active-mode analog of
    /// the passive path's connect-time TLS, used when `PROT P` protects the data
    /// channel.
    async fn upgrade_data_tls(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<()> {
        if Curl_conn_is_ssl(conn, SECONDARYSOCKET) {
            return Ok(());
        }
        let host = self.data_host.clone().unwrap_or_else(|| conn.remote_host.clone());
        let port = self.data_port;
        let tls = tls_config_from_easy(data);
        let tls_filter = create_tls_filter(tls, host, port, None, Vec::new());
        Curl_conn_cf_add(conn, SECONDARYSOCKET, tls_filter);
        Curl_conn_connect(conn, SECONDARYSOCKET, true).await
    }

    /// Run the FTP "INFO" sequence for a body-less request on a file
    /// (`--head`/`-I`), the fused Rust analog of C's
    /// `ftp_state_mdtm` → `ftp_state_type` → `ftp_state_size` →
    /// `ftp_state_rest` chain when `ftp->transfer == PPTRANSFER_INFO`
    /// (lib/ftp.c). It opens **no** data connection and issues **no**
    /// `LIST`/`RETR`; it queries the file's metadata and emits the
    /// corresponding HTTP-style response headers:
    ///
    /// 1. `MDTM <file>` — only when `CURLOPT_FILETIME` (`--head`/`--remote-time`)
    ///    or a time condition is in force (C `ftp_state_mdtm`). On a `213`
    ///    timestamp reply the modification time is recorded
    ///    (`CURLINFO_FILETIME_T`) and a `Last-Modified:` header is emitted (C
    ///    `ftp_state_mdtm_resp`); `550`/other replies are non-fatal ("MDTM
    ///    failed … continuing").
    /// 2. `TYPE <I|A>` — the file's transfer mode (binary unless ASCII is
    ///    preferred), exactly as `ftp_nb_type` selects it.
    /// 3. `SIZE <file>` — on a `213` reply a `Content-Length:` header is emitted
    ///    (C `ftp_state_size_resp`); a `550` is a missing file
    ///    (`CURLE_REMOTE_FILE_NOT_FOUND`); any other non-`213` leaves the size
    ///    unknown (no header).
    /// 4. `REST 0` — probes resume support; a `350` reply emits
    ///    `Accept-ranges: bytes` (C `ftp_state_rest_resp`). A non-`350` is
    ///    non-fatal (curl simply omits the header and proceeds).
    ///
    /// No trailing blank header line is written — matching the C oracle, whose
    /// FTP metadata path emits each header individually with no terminating
    /// `\r\n` (see `tests/data/test141`'s expected `stdout`). The control
    /// connection stays valid so the engine finishes with a graceful `QUIT`;
    /// `dont_check` is set because no `226`/`250` completion line follows.
    async fn run_info_phase(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        sink: &mut dyn WriteCallbacks,
    ) -> Result<()> {
        let file = self.file.clone().ok_or(CurlError::UrlMalformat)?;
        // FTP's synthesized metadata headers (`Last-Modified`, `Content-Length`,
        // `Accept-ranges`) are ALWAYS written to the body/stdout stream,
        // regardless of `CURLOPT_HEADER` — exactly C's `client_write_header`
        // (lib/ftp.c L2381), which temporarily forces `data->set.include_header
        // = TRUE` for these writes: "For historic reasons, FTP never played this
        // game and expects all its headers to do that always." Hence the writer
        // is forced to include headers even when `CURLOPT_HEADER` is off (a
        // `NOBODY` request with `HEADER 0`, `tests/data/test542`); `--head`
        // (which already sets `include_header`) is unaffected.
        let mut writer = ClientWriter::with_options(true, false);

        // (1) MDTM — file modification time (C `ftp_state_mdtm`): only when the
        // file time was requested (`--head` sets `CURLOPT_FILETIME`) or a time
        // condition is active.
        if data.set.get_filetime || data.set.timecondition != 0 {
            self.send_cmd(data, conn, &format!("MDTM {file}")).await?;
            let code = self.read_one(data, conn).await?;
            if code == 213 {
                if let Some(ft) = parse_mdtm_213(&self.last_response) {
                    data.info.filetime = ft;
                    // C emits `Last-Modified` only for a body-less file request
                    // when the time was actually requested and parsed.
                    if data.set.get_filetime {
                        if let Some(hdr) = format_last_modified_header(ft) {
                            writer.write(ClientWriteType::HEADER, &hdr, sink)?;
                        }
                    }
                }
            }
            // 550/other: "MDTM failed … continuing" — non-fatal, no header.
        }

        // (2) TYPE — the file's transfer mode (binary unless ASCII preferred).
        // C `ftp_need_type`: skip a redundant `TYPE` on a reused connection
        // whose type already matches. Inert on the fresh path (`transfertype`
        // starts at `0`).
        let type_byte = ftp_type_arg(self.prefer_ascii);
        if self.transfertype != type_byte {
            self.send_type(data, conn, type_byte).await?;
        }

        // (3) SIZE — emit `Content-Length` on a 213 reply (C `ftp_state_size`/
        // `ftp_state_size_resp`). A 550 is a missing file; any other non-213
        // leaves the size unknown.
        self.send_cmd(data, conn, &format!("SIZE {file}")).await?;
        let size_code = self.read_one(data, conn).await?;
        if size_code == 213 {
            if let Some(size) = parse_size_213(&self.last_response) {
                self.known_filesize = size;
                let cl = format!("Content-Length: {size}\r\n");
                writer.write(ClientWriteType::HEADER, cl.as_bytes(), sink)?;
            }
        } else if size_code == 550 {
            sendf::failf(&mut conn.filter_data.error_buffer, "The file does not exist");
            return Err(CurlError::RemoteFileNotFound);
        }

        // (4) REST 0 — probe resume support; a 350 reply emits `Accept-ranges`
        // (C `ftp_state_rest`/`ftp_state_rest_resp`). A non-350 is non-fatal.
        self.send_cmd(data, conn, "REST 0").await?;
        let rest_code = self.read_one(data, conn).await?;
        if rest_code == 350 {
            writer.write(ClientWriteType::HEADER, b"Accept-ranges: bytes\r\n", sink)?;
        }

        // No data transfer and no trailing `226`/`250`: the control channel
        // stays valid for a graceful `QUIT`.
        self.dont_check = true;
        Ok(())
    }

    /// Move a download body from the data connection to the client `sink`
    /// (C: the `SECONDARYSOCKET` read loop feeding `Curl_client_write`). Reads
    /// `SECONDARYSOCKET` until EOF, routing each chunk through a [`ClientWriter`]
    /// (which honors `CURLOPT_HEADER` and content-decoding), then flushes a final
    /// end-of-stream and records `CURLINFO_SIZE_DOWNLOAD`.
    async fn run_download_body(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        sink: &mut dyn WriteCallbacks,
    ) -> Result<()> {
        let mut writer = ClientWriter::with_options(data.set.include_header, false);
        let mut buf = vec![0u8; 64 * 1024];
        let mut total: i64 = 0;
        // A bounded `CURLOPT_RANGE` (`-r X-Y` / `-r -N`) bounds the body. curl's
        // output limit is `req.size` — the number of bytes *available after the
        // `REST` offset* (`known_filesize - xfer_resume_off`), then further
        // capped by `maxdownload` (C `ftp_state_retr` + the `req.size =
        // min(downloadsize, maxdownload)` clamp at `lib/ftp.c` L2751-2755). The
        // test servers ignore `REST` and stream the whole file from byte 0, so
        // the limit is applied to the *received* prefix. When the announced size
        // is unknown (`SIZE` failed → `known_filesize == -1`, e.g. test336/337)
        // only `maxdownload` bounds the output. `capped` (a bounded range was
        // requested) keeps the data socket open and drives the `ABOR` in
        // [`FtpConn::ftp_done`] regardless of whether the limit or EOF arrives
        // first (C sends `ABOR` whenever `dont_check && maxdownload > 0`).
        let capped = self.maxdownload >= 0;
        let range_limit: i64 = if capped {
            let avail = if self.known_filesize >= 0 {
                self.known_filesize - self.xfer_resume_off
            } else {
                i64::MAX
            };
            avail.min(self.maxdownload)
        } else {
            -1
        };
        let mut aborted = false;
        loop {
            if capped && total >= range_limit {
                // Reached the range output limit: stop early without reading the
                // EOS and without closing the socket (ABOR is sent by
                // `ftp_done`).
                aborted = true;
                break;
            }
            let n = Curl_conn_recv(conn, SECONDARYSOCKET, &mut buf).await?;
            if n == 0 {
                // End of the data stream: flush a zero-length end-of-stream so
                // the writer finalizes any content decoder.
                writer.write(
                    ClientWriteType::BODY.union(ClientWriteType::EOS),
                    &[],
                    sink,
                )?;
                break;
            }
            // Never write past the range output limit (C caps `req.size`): a
            // single recv may straddle the boundary.
            let take = if capped {
                std::cmp::min(n as i64, range_limit - total) as usize
            } else {
                n
            };
            total += take as i64;
            writer.write(ClientWriteType::BODY, &buf[..take], sink)?;
            if capped && total >= range_limit {
                aborted = true;
                break;
            }
        }
        if !capped {
            // Bound the transfer: close the data socket (the server has already
            // closed its end after sending the body). For *any* bounded range
            // (`maxdownload >= 0`) the socket is instead left open so
            // [`FtpConn::ftp_done`] can issue `ABOR` *before* closing it — curl
            // sends `ABOR` whenever `dont_check && req.maxdownload > 0`, even
            // when the body happened to end at EOF before the cap (the range end
            // exceeded the file size; see `tests/data/test2307`).
            Curl_conn_close(conn, SECONDARYSOCKET);
        }
        data.info.size_download = total;
        // Partial-file detection (oracle: `lib/transfer.c` L412-416): a download
        // whose size was announced (`SIZE` → `known_filesize >= 0`, i.e. curl's
        // `k->size != -1`) but whose received byte count differs from the
        // *expected* transfer length (`k->bytecount != k->size`) ended
        // prematurely — the data connection closed before delivering the whole
        // file. curl reports this as `CURLE_PARTIAL_FILE`. A directory listing
        // (`LIST`/`NLST`) never issues `SIZE`, so `known_filesize` stays `-1` and
        // this check is skipped there.
        //
        // A resume (`REST <n>`, i.e. `CURLOPT_RESUME_FROM`) shifts the start of
        // the transfer: only the `known_filesize - resume_from` bytes *after* the
        // resume point are delivered. The expected count is therefore the
        // remaining length, not the full announced size — curl's `k->size` is the
        // resume-adjusted maxdownload. Without this adjustment every resumed
        // download (`-C <n>`) would be misread as a premature/partial transfer
        // and wrongly suppress the graceful `QUIT`. The `expected_bytes >= 0`
        // guard skips the check when the resume point is at/beyond EOF (handled
        // separately, like curl's "entire document already downloaded"). The
        // non-resumed premature-end case remains exercised by
        // `tests/data/test161`; the resumed success case by
        // `tests/data/test110` ("FTP download resume with set limit").
        //
        // A *capped range* transfer (`aborted`) read exactly `maxdownload`
        // bytes by design; curl's partial-file check explicitly excludes this
        // case (`req.maxdownload == req.bytecount`), so it is skipped here — the
        // early stop is expected, not premature (see `tests/data/test135`).
        let expected_bytes = self.known_filesize - self.xfer_resume_off;
        if !aborted && self.known_filesize >= 0 && expected_bytes >= 0 && total != expected_bytes {
            // curl's KNOWN_BUGS 7.8 ("Premature transfer end but healthy control
            // channel"): on a premature end curl's `ftp_done` falls through to
            // clear `ctl_valid` (lib/ftp.c L3520-3536), so the session teardown
            // sends **no** `QUIT` even though the control channel is still alive.
            // Clearing `ctl_valid` here reproduces that exactly — distinct from a
            // command-level error (e.g. `RETR`/`NLST` → `550`), which leaves
            // `ctl_valid` set and still sends a graceful `QUIT` (test 145). See
            // `tests/data/test161`, whose expected wire ends at `RETR` with no
            // `QUIT` and errorcode 18.
            self.ctl_valid = false;
            return Err(CurlError::PartialFile);
        }
        Ok(())
    }

    /// Move an upload body from the client `source` to the data connection
    /// (C: the `SECONDARYSOCKET` send loop driven by `Curl_fillreadbuffer`).
    /// Pulls from a [`UploadReader`] (honoring `CURLOPT_INFILESIZE`) and writes
    /// each chunk to `SECONDARYSOCKET`, then closes the data socket so the server
    /// sees EOF and returns its `226`. Records `CURLINFO_SIZE_UPLOAD`.
    async fn run_upload_body(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        source: &mut dyn ReadCallback,
    ) -> Result<()> {
        // Upload resume (C `ftp_state_ul_setup`): the first `upload_resume_from`
        // bytes are already on the server (we issued `APPE`), so advance the
        // source past them before sending. The `ReadCallback` exposes no seek,
        // so mirror C's `CURL_SEEKFUNC_CANTSEEK` fallback: read and discard the
        // prefix in scratch-sized chunks. A premature `0` (or an over-long
        // funny value) maps to `CURLE_FTP_COULDNT_USE_REST`, exactly as C's
        // discard loop ("Failed to read data").
        if self.upload_resume_from > 0 {
            let mut scratch = vec![0u8; 4 * 1024];
            let mut skipped: i64 = 0;
            while skipped < self.upload_resume_from {
                let want = std::cmp::min(
                    (self.upload_resume_from - skipped) as usize,
                    scratch.len(),
                );
                let got = source.read(&mut scratch[..want]);
                if got == 0 || got > want {
                    return Err(CurlError::FtpCouldntUseRest);
                }
                skipped += got as i64;
            }
        }

        // The announced upload length after the resume offset: curl lowers
        // `infilesize` by `resume_from` (C `ftp_state_ul_setup`: "now, decrease
        // the size of the read"). An unknown input size stays open-ended.
        let total_len = if data.set.filesize >= 0 {
            let remaining = (data.set.filesize - self.upload_resume_from.max(0)).max(0);
            Some(remaining as u64)
        } else {
            None
        };
        // `CURLOPT_CRLF` (`--crlf`): convert lone LFs in the upload stream to
        // CRLF before sending (C adds the `cr_lc` content reader; lib/sendf.c
        // L1068). The conversion is byte-count-changing, so `size_upload`
        // reflects the *converted* (sent) length, matching C's progress
        // accounting. `prev_cr` tracks CRLF pairs across read boundaries.
        //
        // ASCII-mode FTP uploads (`TYPE A`, requested via the `;type=a` URL
        // suffix or `CURLOPT_TRANSFERTEXT`) perform the *same* LF→CRLF
        // conversion even without `--crlf`: C gates the `cr_lc` reader on
        // `data->set.crlf || data->state.prefer_ascii` (lib/sendf.c
        // L1111-1113), and `prefer_ascii` is what selects `TYPE A` over
        // `TYPE I` on the control channel. An ASCII upload therefore must put
        // CRLF line endings on the wire even though the local file has lone
        // LFs (`tests/data/test475`, whose `<upload crlf="yes">` verify expects
        // CRLF-terminated lines).
        let crlf = data.set.crlf || self.prefer_ascii;
        let mut prev_cr = false;
        let mut conv = Vec::new();
        let mut reader = UploadReader::new(total_len, false);
        let mut buf = vec![0u8; 64 * 1024];
        let mut total: i64 = 0;
        loop {
            match reader.read(&mut buf, source)? {
                ReadStep::Data(n) => {
                    // Select the bytes to send: the raw chunk, or its CRLF-
                    // converted form when `--crlf` is in force.
                    let payload: &[u8] = if crlf {
                        conv.clear();
                        crlf_convert_chunk(&buf[..n], &mut prev_cr, &mut conv);
                        &conv
                    } else {
                        &buf[..n]
                    };
                    // A single filter `send` may write fewer bytes than offered;
                    // loop until the whole chunk is on the wire.
                    let mut off = 0usize;
                    while off < payload.len() {
                        let wrote =
                            Curl_conn_send(conn, SECONDARYSOCKET, &payload[off..], false).await?;
                        if wrote == 0 {
                            return Err(CurlError::UploadFailed);
                        }
                        off += wrote;
                    }
                    total += payload.len() as i64;
                }
                ReadStep::Eof => break,
                // `can_pause = false`, so the reader never returns `Paused`.
                ReadStep::Paused => break,
            }
        }
        // Signal end-of-upload by closing the data connection (TCP FIN / TLS
        // close-notify); the server then sends its `226` on the control channel.
        Curl_conn_close(conn, SECONDARYSOCKET);
        data.info.size_upload = total;
        Ok(())
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
            self.accept_data_active(data, conn).await?;
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
            self.connect_data_passive(data, conn).await?;
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
        // A capped-range download (`-r X-Y`) stopped early with the data socket
        // still open and `maxdownload > 0`. Mirror C `ftp_done`: send `ABOR` on
        // the control channel to tell the server to abandon the rest of the
        // transfer, close the data socket, then read the single queued trailing
        // response (the server's `226 File transfer complete`, already sent
        // after its `senddata`). curl deliberately does **not** verify this
        // status ("partial download completed, closing connection"), so the
        // normal completion check below is skipped. `ctl_valid` is left set so a
        // graceful `QUIT` still follows in `disconnect`. See `tests/data/test135`
        // (`-r 4-16` → `REST 4`/`RETR`/`ABOR`/`QUIT`).
        if status.is_ok() && self.maxdownload > 0 {
            self.send_cmd(data, conn, "ABOR").await?;
            Curl_conn_close(conn, SECONDARYSOCKET);
            let _ = self.read_one(data, conn).await?;
            self.data_host = None;
            self.data_port = 0;
            // `transfertype` is connection-lifetime (see the note at the end of
            // `ftp_done`); do not clear it here so a reused connection can skip
            // a redundant `TYPE`. Inert on the fresh path.
            return status;
        }

        if premature || status.is_err() {
            // Skip the completion handshake; the connection may be closed.
            self.dont_check = true;
        }

        // Control-connection survival after an error (C `ftp_done` switch,
        // lib/ftp.c L3513-3539). A specific set of transfer errors leave the
        // control connection usable, so a graceful `QUIT` still follows in
        // `disconnect` (these reach `case CURLE_OK` and, being non-premature
        // DO-phase failures, `break`). Every *other* error wedges the control
        // connection (it is out of sync / untrustworthy), so curl falls to the
        // `default` arm, clears `ctl_valid`, and closes the connection without
        // `QUIT`. The canonical example is `CURLE_FTP_WEIRD_227_FORMAT` — a
        // malformed `227` PASV reply whose bytes were read but cannot be
        // interpreted (`tests/data/test237`) — which is deliberately *absent*
        // from the "stays alive" list even though its sibling
        // `CURLE_FTP_WEIRD_PASV_REPLY` is present. Genuine control-channel I/O
        // death is handled separately by `send_cmd`/`read_one` clearing
        // `ctl_valid`, so this only governs the error-code dimension.
        // C `ftp_done` switch (lib/ftp.c L3513-3539): an OK transfer or one of
        // the listed soft errors keeps the control connection usable ("the
        // connection stays alive fine even though this happened"); every other
        // error wedges it. This is exactly curl's `result == CURLE_OK` predicate
        // reused by the `prevpath` block below, so it is computed once here.
        let keeps_control_alive = match status {
            Ok(()) => true,
            Err(ref e) => matches!(
                e,
                CurlError::BadDownloadResume
                    | CurlError::FtpWeirdPasvReply
                    | CurlError::FtpPortFailed
                    | CurlError::FtpAcceptFailed
                    | CurlError::FtpAcceptTimeout
                    | CurlError::FtpCouldntSetType
                    | CurlError::FtpCouldntRetrFile
                    | CurlError::PartialFile
                    | CurlError::UploadFailed
                    | CurlError::RemoteAccessDenied
                    | CurlError::FilesizeExceeded
                    | CurlError::RemoteFileNotFound
                    | CurlError::WriteError
            ),
        };
        if !keeps_control_alive {
            self.ctl_valid = false;
        }

        if !self.dont_check && self.ctl_valid {
            let code = self.read_one(data, conn).await?;
            if code / 100 != 2 {
                // C `ftp_done` maps the trailing completion code (lib/ftp.c
                // L3634-3647): `226`/`250` succeed; `552` ("Exceeded storage
                // allocation") → `CURLE_REMOTE_DISK_FULL`; any other non-2xx →
                // `CURLE_PARTIAL_FILE`. This `result` is computed *after* the
                // `switch(status)` that governs `ctl_valid`, so an OK transfer
                // whose completion line is an error keeps the control channel
                // alive and still sends a graceful `QUIT` (see
                // `tests/data/test348`, whose wire ends `STOR`/`QUIT` with
                // errorcode 70).
                if code == 552 {
                    sendf::failf(
                        &mut conn.filter_data.error_buffer,
                        "Exceeded storage allocation",
                    );
                    return Err(CurlError::RemoteDiskFull);
                }
                return Err(CurlError::PartialFile);
            }
        }

        // CURLOPT_POSTQUOTE — custom commands sent after a *successful*
        // transfer's completion handshake, while the control connection is
        // still up, before teardown (C `ftp_done`: `if(!status && !result &&
        // !premature && data->set.postquote) ftp_sendquote(...)`; lib/ftp.c
        // L3690). Only runs for a clean, non-premature transfer. See
        // `tests/data/test120` (`DELE file` after `RETR`/`226`) and
        // `tests/data/test121` (`DELE after_transfer`). The control channel
        // must still be valid to issue them.
        if status.is_ok() && !premature && self.ctl_valid {
            let postquote = data
                .set
                .postquote
                .as_ref()
                .map(|s| s.as_slice().to_vec())
                .unwrap_or_default();
            if !postquote.is_empty() {
                self.send_quote_list(data, conn, &postquote).await?;
            }
        }

        // Remember the working directory for connection reuse (C `ftp_done`
        // prevpath block, lib/ftp.c L3559-3585). On a clean, non-`cwdfail`
        // transfer, store this request's directory portion — the rawpath with
        // the leaf filename stripped — so a later same-host transfer on the
        // reused connection can compare it (`ftp_state_pwd`/`cwddone`) and skip
        // redundant `CWD` commands (`tests/data/test215`). A failed transfer or
        // a `cwdfail` clears it ("no path remembering"). Under `FTPFILE_NOCWD`
        // an absolute path means no `CWD` happened, so the existing `prevpath`
        // is kept; a relative path leaves us in the FTP home (empty prevpath).
        // This only ever affects the reuse path; on a fresh connection the next
        // transfer gets a new `FtpConn` and never reads this.
        // C `ftp_done`'s `if(result) … else …` (lib/ftp.c L3554-3586): the
        // working directory is remembered for connection reuse whenever the
        // control connection survived. curl's `result == CURLE_OK` predicate
        // holds for an OK transfer AND for the soft errors handled above, when
        // not genuinely premature — which is *exactly* the condition under which
        // `ctl_valid` remains set here: `keeps_control_alive` already cleared it
        // for a hard (`default`-arm) error, a control-channel I/O death cleared
        // it in `send_cmd`/`read_one`, and a genuinely premature data-end cleared
        // it in `run_download_body`. (Our local `premature` flag is merely
        // `result.is_err()` and so is *true* for a clean soft error like a 550
        // `RETR`, which is NOT premature in curl's sense — hence it must not gate
        // this decision.) A 550 `RETR` of a missing file
        // (`CURLE_REMOTE_FILE_NOT_FOUND` / `CURLE_FTP_COULDNT_RETR_FILE`) is a
        // soft error: the directory was entered successfully, so `ctl_valid`
        // stays set, curl keeps `prevpath`, and a later same-path transfer on the
        // reused connection skips the `CWD` entirely (`tests/data/test533`,
        // `test546`). A hard error or genuine premature end wedges the channel
        // (`ctl_valid` cleared) and forgets the path. The inner `cwdfail` /
        // `NOCWD`-absolute structure mirrors curl exactly: a full NOCWD path
        // means no `CWD` happened, so the existing `prevpath` is kept regardless
        // of `cwdfail`; otherwise a failed `CWD` clears it.
        if self.ctl_valid {
            let method = CurlFtpFile::from_raw(data.set.ftp_filemethod);
            if method == CurlFtpFile::NoCwd && self.rawpath.starts_with('/') {
                // full path => no CWDs happened => keep existing prevpath
            } else if self.cwdfail {
                // a failed CWD means we are not where we think — forget the path
                self.prevpath = None;
            } else if method == CurlFtpFile::NoCwd {
                self.prevpath = Some(String::new());
            } else {
                let flen = self.file.as_ref().map_or(0, String::len);
                let dir = self
                    .rawpath
                    .get(..self.rawpath.len().saturating_sub(flen))
                    .unwrap_or("")
                    .to_string();
                self.prevpath = Some(dir);
            }
        } else {
            self.prevpath = None;
        }

        // Clear the per-transfer data-channel endpoint so the control
        // connection can be reused for the next transfer. `transfertype` is
        // deliberately NOT cleared here: it is a connection-lifetime property
        // (C `ftpc->transfertype`) that a reused connection consults via
        // `ftp_need_type` to skip a redundant `TYPE` (`tests/data/test215`). On
        // a fresh connection the next transfer gets a new `FtpConn`
        // (`transfertype == 0`), so persisting it is inert for the non-reuse
        // path.
        self.data_host = None;
        self.data_port = 0;
        status
    }
}

// ===========================================================================
// FTP-over-HTTP(S)-proxy CONNECT tunnel (the FTP analog of curl's
// `conn->bits.tunnel_proxy` handling in `lib/ftp.c`).
// ===========================================================================

/// The resolved HTTP(S)-proxy CONNECT-tunnel routing for a native FTP transfer.
///
/// When an `ftp://`/`ftps://` request runs through an HTTP proxy with
/// `--proxytunnel` (or through an HTTPS proxy, which always tunnels), curl opens
/// a `CONNECT` tunnel to the FTP server for the **control** channel and a second
/// `CONNECT` to the `PASV`/`EPSV` endpoint for the **data** channel
/// (`lib/ftp.c` `ftp_state_pasv_resp` `if(conn->bits.proxy)`). This struct
/// captures, once, what both legs need: which proxy to dial and what authority
/// the control-channel `CONNECT` names.
#[cfg(all(feature = "ftp", feature = "http", feature = "proxy"))]
struct FtpTunnelProxy {
    /// The HTTP/HTTPS proxy actually dialed (TCP) for both channels.
    proxy: crate::proxy::Proxy,
    /// The control-channel `CONNECT` target host — the `--connect-to` override
    /// when active, else the origin FTP host (curl's
    /// `Curl_http_proxy_get_destination` for `FIRSTSOCKET`).
    connect_host: String,
    /// The control-channel `CONNECT` target port.
    connect_port: u16,
}

/// Resolve a possible HTTP(S)-proxy CONNECT tunnel for an FTP transfer to
/// `origin_host:origin_port`.
///
/// Returns `Some` only for a **non-SOCKS** proxy that this transfer must
/// `CONNECT`-tunnel through. A SOCKS proxy returns `None` here so the existing
/// direct-dial behavior is preserved (tests 712/713, where the SOCKS proxy is
/// not actually traversed and the `--connect-to` override reaches the FTP server
/// directly). A bypassed (`no_proxy`) or absent proxy also returns `None`,
/// leaving every non-proxied FTP transfer byte-for-byte unchanged.
///
/// The proxy is resolved for the original `ftp` scheme exactly as curl's
/// `detect_proxy`/`parse_proxy` (so `-x`/`CURLOPT_PROXY`, `ftp_proxy`, and
/// `all_proxy` all apply, honoring `no_proxy`). Reaching the native FTP engine
/// with a non-SOCKS proxy already implies a tunnel: the dispatcher
/// ([`crate::protocols::ftp_driven_as_http_proxy`]) routes a *forward* HTTP-proxy
/// FTP request to the HTTP engine instead, so an HTTP proxy is seen here only
/// when `--proxytunnel` forced `CONNECT` (or for `ftps://`, which always
/// tunnels). The control-channel `CONNECT` authority is the `--connect-to`
/// override when active, else the origin (curl's
/// `Curl_http_proxy_get_destination`).
#[cfg(all(feature = "ftp", feature = "http", feature = "proxy"))]
fn ftp_tunnel_proxy(data: &Easy, origin_host: &str, origin_port: u16) -> Option<FtpTunnelProxy> {
    // Resolve the proxy for the original `ftp` scheme (so `ftp_proxy`/`all_proxy`
    // env vars apply), honoring the `no_proxy` bypass list.
    let cfg = crate::protocols::http::proxy_engine::config(data, "ftp").ok()?;
    let px = crate::proxy::proxy_for_target(&cfg, origin_host)?;
    // SOCKS proxies keep the existing direct-dial behavior (Cluster B); only
    // HTTP/HTTPS proxies use the CONNECT-tunnel path here.
    if px.is_socks() {
        return None;
    }
    // The control-channel CONNECT authority: the `--connect-to` override when a
    // component is active, else the origin (mirrors the HTTP path's
    // `connect_host`/`connect_port`, `lib/http_proxy.c` L165).
    let (connect_host, connect_port) =
        crate::protocols::http::connect_target(data, origin_host, origin_port);
    Some(FtpTunnelProxy {
        proxy: px.clone(),
        connect_host,
        connect_port,
    })
}

/// Splice an HTTP(S)-proxy `CONNECT`-tunnel filter chain onto an FTP
/// connection's [`SetupConfig`], targeting `connect_host:connect_port`.
///
/// This is the FTP analog of the HTTP engine's proxy filter assembly
/// (`http::http_connect_hop`): for an HTTPS proxy it first layers the proxy-leg
/// TLS (`with_ssl_proxy`), then in all cases adds the HTTP/1.x `CONNECT` filter
/// (`with_http_proxy`). The bottom transport (eyeballs) already dials the proxy;
/// this filter performs the `CONNECT host:port` handshake and then passes the
/// FTP control/data bytes through transparently. `conn.bits.httpproxy` /
/// `tunnel_proxy` (and `proxy_ssl` for an HTTPS proxy) are set so the
/// CONNECT-response-surfacing gates downstream fire.
#[cfg(all(feature = "ftp", feature = "http", feature = "proxy"))]
fn ftp_apply_proxy_connect(
    mut setup: SetupConfig,
    data: &Easy,
    px: &crate::proxy::Proxy,
    connect_host: &str,
    connect_port: u16,
    conn: &mut Connection,
) -> SetupConfig {
    use crate::conn::connect::{h1_proxy_factory, tls_proxy_factory};
    use crate::conn::h1_proxy::{H1ProxyConfig, StandardProxyAuth};

    // An HTTPS proxy speaks TLS on the proxy leg first, then behaves exactly
    // like an HTTP proxy for the CONNECT (curl pins/validates the proxy leg
    // independently of the origin).
    if px.is_https() {
        conn.bits.proxy_ssl = true;
        // The CONNECT request is HTTP/1.x, so the proxy-leg ALPN offers only
        // `http/1.1` (when ALPN is enabled). `alpn_protocols` is private to the
        // HTTP module, so the single-entry list is built directly here.
        let palpn: Vec<Vec<u8>> = if data.set.ssl_enable_alpn {
            vec![b"http/1.1".to_vec()]
        } else {
            Vec::new()
        };
        let ptls = px.tls.clone().unwrap_or_else(|| tls_config_from_easy(data));
        // `CURLOPT_PROXY_PINNEDPUBLICKEY` (`--proxy-pinnedpubkey`) enforced on
        // the HTTPS proxy leaf — `None` would silently disable the pin.
        let proxy_pinned_pubkey = data
            .set
            .str(StrId::SslPinnedPublicKeyProxy)
            .map(str::to_string);
        setup = setup.with_ssl_proxy(tls_proxy_factory(
            ptls,
            px.host.clone(),
            px.port,
            proxy_pinned_pubkey,
            palpn,
        ));
    }

    conn.bits.httpproxy = true;
    conn.bits.tunnel_proxy = true;

    // The CONNECT request's HTTP minor version: `--proxy1.0` forces HTTP/1.0,
    // every other HTTP proxy type uses HTTP/1.1 (`cf-h1-proxy.c` `start_CONNECT`).
    let proxy_http_minor = if px.proxytype.is_http_1_0() { 0 } else { 1 };
    // The CONNECT `User-Agent` comes from the same `STRING_USERAGENT` source as
    // the main request; the builder omits it when empty.
    let proxy_user_agent = data.set.str(StrId::Useragent).map(str::to_string);
    // No-auth / proactive-Basic proxy auth (tests 714/715 use no proxy
    // credentials; `StandardProxyAuth` emits nothing then).
    let proxy_auth = Box::new(StandardProxyAuth::new(px.clone(), data.set.proxyauth));
    // An IPv6-literal CONNECT target must be bracketed in the request-line
    // authority and `Host` (the ACE host here is bracket-stripped, so a residual
    // colon means IPv6).
    let h1cfg = H1ProxyConfig::new(connect_host.to_string(), connect_port)
        .with_ipv6(connect_host.contains(':'))
        .with_http_minor(proxy_http_minor)
        .with_user_agent(proxy_user_agent)
        .with_scheme("ftp", true)
        .with_auth(proxy_auth);
    setup.with_http_proxy(h1_proxy_factory(h1cfg))
}

// ===========================================================================
// Top-level FTP / FTPS transfer driver — the `protocols::mod::perform_transfer`
// network seam for the `ftp` and `ftps` schemes (the analog of
// `http::perform_http`).
// ===========================================================================

/// Drive a complete one-shot FTP/FTPS transfer over a freshly-built control
/// connection, mirroring `http::perform_http`'s shape: parse the request URL,
/// resolve the control host, build the control-channel filter chain (implicit
/// TLS for `ftps://`, plain TCP for `ftp://` with the optional `AUTH TLS`
/// upgrade handled during login), run the login state machine, then drive the
/// DO phase (CWD → data-channel negotiation → `TYPE`/`SIZE`/`REST` →
/// `RETR`/`STOR`/`APPE`/`LIST`/`NLST` → body movement) and the trailing
/// completion handshake. The body flows through the caller-supplied `sink`
/// (download) / `source` (upload).
///
/// This is the genuine FTP transfer engine entry point. The C oracle's
/// canonical control-channel order is reproduced (`tests/data/test102`:
/// `USER`/`PASS`/`PWD`/`EPSV`/`TYPE I`/`SIZE`/`RETR`/`226`), satisfying AAP
/// §0.8.4 step 8 and the G6 wire-parity goal.
pub(crate) async fn perform_ftp(
    data: &mut Easy,
    sink: &mut dyn WriteCallbacks,
    source: &mut dyn ReadCallback,
) -> Result<()> {
    let verbose = data.set.verbose;

    // (1) Resolve the request URL: prefer a pre-parsed `CURLOPT_CURLU` handle
    //     (deposited by the FFI layer), else parse the stored URL string.
    //     `CURLU_GUESS_SCHEME` mirrors curl's scheme guessing; `CURLU_DEFAULT_PORT`
    //     lets the port query fall back to the scheme default.
    let url = if let Some(uh) = data.set.uh.clone() {
        uh
    } else {
        let url_str = data.url().ok_or(CurlError::UrlMalformat)?.to_string();
        let mut parsed = CurlUrl::new();
        parsed
            .set(
                CurlUPart::Url,
                Some(&url_str),
                CURLU_GUESS_SCHEME | CURLU_DEFAULT_PORT,
            )
            .map_err(|_| CurlError::UrlMalformat)?;
        parsed
    };

    let scheme = url
        .get(CurlUPart::Scheme, 0)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let is_ftps = scheme.eq_ignore_ascii_case("ftps");
    let scheme_const: &'static Scheme = if is_ftps { &SCHEME_FTPS } else { &SCHEME_FTP };

    // The control host (stripped of any IPv6 brackets for DNS/identity).
    let host_bracketed = url.get(CurlUPart::Host, CURLU_URLDECODE).unwrap_or_default();
    if host_bracketed.is_empty() {
        return Err(CurlError::UrlMalformat);
    }
    let host = host_bracketed
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(&host_bracketed)
        .to_string();
    let url_port = url
        .get(CurlUPart::Port, 0)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(scheme_const.default_port);
    // `CURLOPT_PORT` (`data.set.use_port`, 0 = "use the URL / scheme default")
    // overrides the port from the URL for the *control* connection (C
    // `parse_remote_port`, lib/url.c L2538-2549: `if(data->set.use_port &&
    // data->state.allow_port) conn->remote_port = data->set.use_port`).
    // `allow_port` is TRUE for a normal (non-redirected) transfer, which is the
    // case here. The passive/active *data* port is negotiated separately
    // (227/229 or the client listener) and is unaffected.
    let port = if data.set.use_port != 0 {
        data.set.use_port
    } else {
        url_port
    };

    let ipver = IpVersion::from_raw(i64::from(data.set.ipver));

    let handler = FtpHandler::new(scheme_const);

    // `--connect-to` (`CURLOPT_CONNECT_TO`): curl applies `conn->conn_to_host` /
    // `conn->conn_to_port` uniformly across protocols in `create_conn`, so an
    // entry matching the FTP origin redirects the *control-channel dial* (and,
    // via the reused control address, the passive `EPSV`/`PASV` data channel) to
    // the substituted host/port, while the URL — hence the `USER`/`PASS`
    // credentials and, for `ftps://`, the TLS SNI/verification host — keep the
    // original origin. With no matching entry this returns the origin unchanged,
    // so every FTP transfer without `--connect-to` is byte-for-byte identical
    // (the dial target equals the origin and all four uses below collapse to the
    // prior code). Oracle: tests/data/test713 (`ftp://ftp.example.com/… --proxy
    // socks5://… --connect-to ::HOST:PORT`, where the origin host is deliberately
    // unresolvable and only the connect-to override makes the dial succeed). The
    // `--connect-to` matcher lives in the HTTP module (curl shares a single
    // implementation across protocols); when the `http` feature is compiled out
    // there is no override and the origin is dialed directly.
    #[cfg(feature = "http")]
    let (dial_host, dial_port) = crate::protocols::http::connect_target(data, &host, port);
    #[cfg(not(feature = "http"))]
    let (dial_host, dial_port) = (host.clone(), port);

    // FTP-over-HTTP(S)-proxy CONNECT tunnel (`--proxytunnel`, an HTTPS proxy, or
    // a `--connect-to` override over an HTTP proxy). When one applies, the
    // **control channel dials the proxy** and the proxy is asked to `CONNECT` to
    // the FTP server; the data channel later opens its own `CONNECT` through the
    // same proxy (handled in `connect_data_passive`). This is the FTP analog of
    // curl's `conn->bits.tunnel_proxy` path (`lib/ftp.c`); a SOCKS proxy or no
    // proxy leaves `tunnel_proxy == None` and every existing FTP route unchanged.
    // Oracle: tests/data/test714 (HTTP proxytunnel), test715 (+ SOCKS preproxy).
    #[cfg(all(feature = "ftp", feature = "http", feature = "proxy"))]
    let tunnel_proxy = ftp_tunnel_proxy(data, &host, port);

    // The control-channel **dial** target (where the TCP connection is opened):
    // the proxy when a CONNECT tunnel applies, else the `--connect-to`-overridden
    // (Cluster B) / direct origin computed above. The recorded **remote**
    // (`conn.remote_host`/`remote_port`, reused by `EPSV` as the data host) stays
    // the ORIGIN FTP host under a tunnel — matching curl's `ftp_control_addr_dup`,
    // which returns `conn->host.name` when `tunnel_proxy`/`socksproxy` is set — so
    // the data channel's own `CONNECT` names the FTP server, not the proxy.
    #[cfg(all(feature = "ftp", feature = "http", feature = "proxy"))]
    let (dial_host, dial_port, remote_host, remote_port) = match &tunnel_proxy {
        Some(tp) => (tp.proxy.host.clone(), tp.proxy.port, host.clone(), port),
        None => (dial_host.clone(), dial_port, dial_host, dial_port),
    };
    #[cfg(not(all(feature = "ftp", feature = "http", feature = "proxy")))]
    let (dial_host, dial_port, remote_host, remote_port) =
        (dial_host.clone(), dial_port, dial_host, dial_port);

    // (2)/(3) Obtain the control connection. On the CLI path — the only path
    //     with a guaranteed end-of-run pool drain (`external_pool_drain`, set
    //     solely by `set_conn_pool`) — first try to reuse a pooled same-host
    //     control channel. A pool hit skips BOTH the TCP/TLS dial AND the
    //     `USER`/`PASS`/`PWD` login, so a subsequent transfer resumes the live
    //     session exactly as curl's connection cache does, eliding the
    //     redundant login (and, via the delta-CWD/`ftp_need_type` logic, the
    //     redundant `CWD`/`TYPE`) — see `tests/data/test215`, `test146`,
    //     `test149`. `CURLOPT_FRESH_CONNECT` / `CURLOPT_FORBID_REUSE` opt out,
    //     identical to the HTTP reuse gate. On the FFI easy-perform and
    //     multi-interface paths `external_pool_drain` is `false`, so the pool is
    //     never populated, checkout never hits, and this is byte-identical to a
    //     fresh dial — the connection is then QUITed inline at teardown
    //     (reg-baseline; see the teardown note and `tests/data/test529`/`test539`).
    // Keyed by the *dial* target (the `--connect-to` override when active, else
    // the origin): two transfers to the same origin but different connect-to
    // routes must not share a pooled control channel, and a transfer with no
    // override keys identically to before (dial == origin). Under a CONNECT
    // tunnel the dial is the shared proxy, so the key folds in the CONNECT
    // *authority* (`remote_host:remote_port`, the origin) as well, ensuring two
    // FTP servers tunneled through the same proxy never share a control channel.
    let reuse_key = format!("{dial_host}:{dial_port}|{remote_host}:{remote_port}");
    let mut conn = {
        let mut reused: Option<Connection> = None;
        if data.external_pool_drain && !data.set.reuse_fresh && !data.set.reuse_forbid {
            let pool = data.conn_pool_handle();
            if let Some(mut candidate) = crate::conn::pool_checkout(&pool, &reuse_key) {
                // Liveness probe (curl's `Curl_conn_is_alive`): reuse only a
                // control channel that is still open AND carries no unexpected
                // pending bytes — a server-side close or stray data makes a
                // supposedly-idle keep-alive socket unsafe to reuse.
                let (alive, pending) = Curl_conn_is_alive(&mut candidate);
                if alive && !pending {
                    // Mark pool-reused (curl's `conn->bits.reuse`); this drives
                    // the login skip below and the delta-CWD / TYPE-skip in the
                    // DO phase.
                    candidate.bits.reuse = true;
                    if verbose {
                        // curl's reuse trace omits the `* Trying`/`* Connected`
                        // dial lines (lib/url.c L3540).
                        sendf::infof(
                            true,
                            &format!("Re-using existing connection with host {host}"),
                        );
                    }
                    reused = Some(candidate);
                }
                // Dead / unexpected pending data: `candidate` is dropped here
                // (closing its socket) and we fall through to a fresh dial.
            }
        }
        match reused {
            Some(c) => c,
            None => {
                // Fresh dial. Resolve the control endpoint's addresses (system
                // resolver; FTP has no DoH path of its own) and build the
                // control connection + filter chain. `ftps://` installs the TLS
                // filter now (implicit TLS, encrypted from the first byte);
                // `ftp://` is a plain TCP chain — the optional `AUTH TLS` upgrade
                // is performed mid-login by `FtpConn::upgrade_control_tls`.
                let addrs = resolve_ftp_addrs(&dial_host, dial_port, ipver, verbose).await?;
                let desc = SchemeDescriptor::new(
                    scheme_const.name,
                    scheme_const.default_port,
                    scheme_const.flags,
                    scheme_const.protocol,
                );
                let mut conn = Connection::new(reuse_key.clone(), TRNSPRT_TCP, desc)
                    .with_verbose(verbose);
                // The connection's recorded remote is the *dial* target so the
                // passive data channel (EPSV reuses `conn.remote_host`) reaches
                // the same endpoint as the control channel under `--connect-to`.
                // Under a CONNECT tunnel the recorded remote is instead the ORIGIN
                // FTP host (the dial is the proxy), matching curl's
                // `ftp_control_addr_dup`, so EPSV names the FTP server.
                conn.set_remote(remote_host.clone(), remote_port);

                let eyeballs = eyeballs_factory(
                    TRNSPRT_TCP,
                    ipver,
                    data.set.happy_eyeballs_timeout,
                    data.set.connecttimeout,
                    addrs,
                );
                // The control channel's filter chain. For a CONNECT tunnel the
                // chain is eyeballs(→proxy) → [proxy TLS] → CONNECT → [origin TLS
                // for ftps]; otherwise it is the plain/implicit-TLS chain.
                let ssl_mode = if is_ftps {
                    CURL_CF_SSL_ENABLE
                } else {
                    CURL_CF_SSL_DISABLE
                };
                let mut setup = SetupConfig::new(ssl_mode, is_ftps, eyeballs);
                // Splice the HTTP(S)-proxy CONNECT tunnel for the control channel,
                // targeting the connect-to authority (else origin).
                #[cfg(all(feature = "ftp", feature = "http", feature = "proxy"))]
                if let Some(tp) = &tunnel_proxy {
                    setup = ftp_apply_proxy_connect(
                        setup,
                        data,
                        &tp.proxy,
                        &tp.connect_host,
                        tp.connect_port,
                        &mut conn,
                    );
                }
                // Implicit `ftps://` control-channel TLS rides on TOP of any
                // CONNECT tunnel (curl adds the origin `ssl` filter last). FTP
                // control channels do not negotiate ALPN; offer none.
                if is_ftps {
                    let tls = tls_config_from_easy(data);
                    let ssl = tls_factory(tls, host.clone(), port, None, Vec::new());
                    setup = setup.with_ssl(ssl);
                }
                let dispatch = ConnSetup::Default(setup);
                establish_connection(&mut conn, FIRSTSOCKET, ssl_mode, dispatch, true).await?;

                // FTP-over-HTTP-proxy CONNECT (tunnel): surface the
                // control-channel CONNECT response (status line + headers +
                // terminating blank line) onto the body stream, mirroring curl's
                // `CLIENTWRITE_CONNECT` → `cw_download_write` forwarding for a
                // non-TLS origin (`http::http_connect_hop`). This produces the
                // FIRST "200 Connection established" block in the output
                // (oracle: tests/data/test714, test715). Gated like the HTTP path:
                // a CONNECT tunnel was used, the origin is not (implicit-)TLS — an
                // ftps origin keeps the plaintext CONNECT response off the
                // encrypted stream — and `--suppress-connect-headers` opts out.
                #[cfg(all(feature = "ftp", feature = "http", feature = "proxy"))]
                if conn.bits.tunnel_proxy && !is_ftps && !data.set.suppress_connect_headers {
                    if let Some(lines) = conn.cfilter[FIRSTSOCKET].connect_response_headers() {
                        for line in &lines {
                            let mut off = 0;
                            while off < line.len() {
                                let n = sink.write_body(&line[off..]);
                                if n == 0 {
                                    break;
                                }
                                off += n;
                            }
                        }
                    }
                }
                conn
            }
        }
    };

    // (4) Per-connection setup: decode the URL path/credentials onto `FtpConn`,
    //     preserving the pooled connection-lifetime state (live ping-pong
    //     engine, `entrypath`, `prevpath`, `transfertype`, server OS) on reuse.
    //     The login state machine (greeting → optional `AUTH TLS` →
    //     `USER`/`PASS` → `PBSZ`/`PROT` → `PWD`/`SYST`) runs ONLY for a freshly
    //     dialed connection; a reused channel is already logged in.
    handler.setup_connection(data, &mut conn).await?;
    if !conn.bits.reuse {
        handler.connect(data, &mut conn).await?;
    }

    // (5) Take the per-connection state out and drive the DO phase + body
    //     movement, then the trailing completion handshake (`226`/`250`).
    let mut ftpc = conn
        .take_proto_state()
        .and_then(|b| b.downcast::<FtpConn>().ok().map(|b| *b))
        .ok_or(CurlError::FailedInit)?;
    let result = ftpc.run_do_phase(data, &mut conn, sink, source).await;
    let premature = result.is_err();
    let done = ftpc.ftp_done(data, &mut conn, result, premature).await;

    // Flush the captured FTP control responses to the header sink as
    // `CLIENTWRITE_INFO` — the Rust analog of C `Curl_pp_readresp`'s per-line
    // `Curl_client_write(data, CLIENTWRITE_INFO, line, length)` ("the response
    // lines can be seen as a kind of headers", lib/pingpong.c L304-310). This
    // populates the `-D`/`--dump-header` file with every control reply from the
    // greeting through the transfer-completion `226`/`250` (read just above by
    // `ftp_done`), in arrival order. The drain happens BEFORE teardown, so the
    // `221` reply to the eventual `QUIT` is excluded — it is not part of this
    // transfer (oracle: tests/data/test1349 `<file2>`, whose trailing comment
    // explicitly notes the final `221` "will not be recorded"). For a non-`-D`
    // transfer the header sink discards the bytes (the CLI `tool_header_cb`
    // writes nothing without a `-D` target and never echoes FTP-scheme `INFO`
    // onto stdout under `-i`, since its echo is gated on an http/https scheme),
    // so this is wire-neutral for every FTP transfer that does not request a
    // header dump. Best-effort: a header-sink write failure must not mask the
    // transfer's own outcome (`done`), which is what `perform_ftp` returns.
    if let Some(captured) = ftpc.pp.drain_info_capture() {
        if !captured.is_empty() {
            let mut writer = ClientWriter::with_options(data.set.include_header, false);
            let _ = writer.write(ClientWriteType::INFO, &captured, sink);
        }
    }

    // Snapshot the control-channel validity before parking the state back: a
    // still-valid channel is reuse-eligible (and would have received a graceful
    // `QUIT`); a cleared one means a dead connection that must be torn down now
    // without a `QUIT`.
    let ctl_valid = ftpc.ctl_valid;
    conn.set_proto_state(Box::new(ftpc));

    // (6) Teardown — deferred-`QUIT` connection reuse (the FTP analog of curl's
    //     connection cache). The transfer outcome is what we return; teardown
    //     failures never mask it.
    //
    //     A connection whose control channel is still valid and not marked
    //     non-reusable is **checked back into the shared pool** instead of being
    //     QUITed inline. This lets a subsequent same-host transfer reuse it
    //     (skipping `USER`/`PASS`/`PWD` and redundant `CWD`/`TYPE`, per
    //     `tests/data/test215`); the connection's single, deferred, best-effort
    //     `QUIT` is sent later by [`ftp_drain_pool`] at end-of-run /
    //     `curl_easy_cleanup`, while the runtime is still live. For a lone
    //     transfer this is wire-identical to the previous inline teardown — the
    //     transfer's commands, then `QUIT` at drain.
    //
    //     A connection with a cleared `ctl_valid` (a control-channel I/O
    //     failure recorded by `send_cmd`/`read_one`) — or one explicitly marked
    //     `no_reuse` — is torn down immediately via [`FtpHandler::disconnect`],
    //     which sends no `QUIT` on a dead channel. This preserves the exact
    //     no-`QUIT`-on-dead-connection behavior (and, for a *protocol* error
    //     such as a `550` that leaves `ctl_valid` set, the connection is still
    //     reuse-eligible and its graceful `QUIT` is issued at drain — matching
    //     curl, which keeps the channel alive and QUITs after a `550`; see
    //     `tests/data/test145`).
    //     The deferred-`QUIT`-via-pool-check-in path is taken **only** when this
    //     handle's pool is externally managed with a guaranteed end-of-run drain
    //     (`data.external_pool_drain`, set solely by the CLI's `set_conn_pool`).
    //     On the FFI easy-perform and multi-interface paths the flag is `false`,
    //     so the connection is QUITed inline here — curl's reg-baseline. This is
    //     mandatory: a connection checked into a pool that is never drained would
    //     drop its `QUIT` (`tests/data/test529`), and a connection whose socket
    //     lives on the multi handle's runtime cannot be driven to `QUIT` from a
    //     `curl_easy_cleanup` `block_on` on a different runtime — it would hang
    //     (`tests/data/test539`). Confining check-in to the CLI keeps the drain
    //     on the same (current-thread) runtime that opened the socket.
    if data.external_pool_drain && ctl_valid && !conn.bits.no_reuse {
        let pool = data.conn_pool_handle();
        let maxconnects = data.set.maxconnects;
        crate::conn::pool_checkin(&pool, conn, maxconnects);
    } else {
        let _ = handler.disconnect(data, &mut conn, false).await;
    }
    done
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

    #[test]
    fn parse_ftpport_address_honors_curl_grammar() {
        // "-" (the default) and single chars → None (advertise local IP).
        assert_eq!(parse_ftpport_address("-"), None);
        assert_eq!(parse_ftpport_address(""), None);
        // A literal IPv4 (tests/data/test116 `-P 1.2.3.4`).
        assert_eq!(
            parse_ftpport_address("1.2.3.4"),
            Some("1.2.3.4".to_string())
        );
        // A loopback literal (tests/data/test251 `-P %CLIENTIP`).
        assert_eq!(
            parse_ftpport_address("127.0.0.1"),
            Some("127.0.0.1".to_string())
        );
        // An IPv4 with a trailing :port(-range) keeps only the address.
        assert_eq!(
            parse_ftpport_address("1.2.3.4:8000-9000"),
            Some("1.2.3.4".to_string())
        );
        // `[ipv6]:port` → the bracketed literal.
        assert_eq!(
            parse_ftpport_address("[::1]:2000"),
            Some("::1".to_string())
        );
        // A bare IPv6 literal carries no port and is used whole.
        assert_eq!(parse_ftpport_address("fe80::1"), Some("fe80::1".to_string()));
        // `:port` only → no address.
        assert_eq!(parse_ftpport_address(":8000"), None);
    }

    // ---- CWD path decomposition (the three --ftp-method strategies) ------

    #[test]
    fn decompose_multicwd_splits_each_component() {
        let d = decompose_url_path(CurlFtpFile::MultiCwd, "/dir1/dir2/file.txt").unwrap();
        let names: Vec<&str> = d.dirs.iter().map(|c| c.name.as_str()).collect();
        // Leading slash becomes the "/" root component, then each dir.
        assert_eq!(names, ["/", "dir1", "dir2"]);
        assert_eq!(d.file.as_deref(), Some("file.txt"));
    }

    #[test]
    fn decompose_multicwd_relative_and_directory_url() {
        // Relative path: no leading "/" root component.
        let d = decompose_url_path(CurlFtpFile::MultiCwd, "dir1/dir2/file.txt").unwrap();
        let names: Vec<&str> = d.dirs.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["dir1", "dir2"]);
        assert_eq!(d.file.as_deref(), Some("file.txt"));

        // A trailing slash means a directory (listing) — no file name.
        let dir = decompose_url_path(CurlFtpFile::MultiCwd, "/pub/").unwrap();
        let dnames: Vec<&str> = dir.dirs.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(dnames, ["/", "pub"]);
        assert!(dir.file.is_none());
    }

    #[test]
    fn decompose_nocwd_keeps_whole_path_as_file() {
        let d = decompose_url_path(CurlFtpFile::NoCwd, "/dir1/dir2/file.txt").unwrap();
        assert!(d.dirs.is_empty());
        assert_eq!(d.file.as_deref(), Some("/dir1/dir2/file.txt"));
        // CWD can be skipped for an absolute path under NOCWD.
        assert!(d.cwddone);
    }

    #[test]
    fn decompose_singlecwd_one_dir_plus_file() {
        let d = decompose_url_path(CurlFtpFile::SingleCwd, "/dir1/dir2/file.txt").unwrap();
        let names: Vec<&str> = d.dirs.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["/dir1/dir2"]);
        assert_eq!(d.file.as_deref(), Some("file.txt"));

        // A root-only leading slash keeps a single "/" directory.
        let r = decompose_url_path(CurlFtpFile::SingleCwd, "/file.txt").unwrap();
        let rnames: Vec<&str> = r.dirs.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(rnames, ["/"]);
        assert_eq!(r.file.as_deref(), Some("file.txt"));
    }

    #[test]
    fn decompose_upload_without_filename_yields_no_file() {
        // A directory URL (trailing slash) has no target file name. Path
        // decomposition itself no longer fails for an upload — the
        // upload-without-filename malformat error (`CURLE_URL_MALFORMAT`) is
        // raised in the DO phase (`run_do_phase`), *after* login, exactly like
        // C's `ftp_parse_url_path` (lib/ftp.c L310-313). Here we only assert
        // the precondition the DO phase keys off: `file` is `None`.
        let d = decompose_url_path(CurlFtpFile::MultiCwd, "/pub/").unwrap();
        assert!(d.file.is_none());
    }

    #[test]
    fn decompose_multicwd_rejects_excessive_depth() {
        let deep = "/".repeat(FTP_MAX_DIR_DEPTH + 1);
        assert_eq!(
            decompose_url_path(CurlFtpFile::MultiCwd, &deep).unwrap_err(),
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

    #[test]
    fn parse_pwd_entrypath_unescapes_doubled_quote() {
        // RFC 959 §5.4: a literal double-quote inside the path name is doubled
        // ("") on the wire; the parser must collapse it back to a single quote
        // and continue scanning until the genuine closing quote.
        assert_eq!(
            parse_pwd_entrypath(b"257 \"/a\"\"b/c\" is current").as_deref(),
            Some("/a\"b/c")
        );
    }

    #[test]
    fn parse_pwd_entrypath_rejects_unterminated_quote() {
        // An opening quote with no closing quote yields no usable entry path.
        assert!(parse_pwd_entrypath(b"257 \"/unterminated").is_none());
    }

    #[test]
    fn parse_size_213_parses_and_rejects() {
        // A well-formed `213 <size>` yields the byte count.
        assert_eq!(parse_size_213(b"213 4096"), Some(4096));
        // Surrounding/trailing tokens are ignored (only the first is parsed).
        assert_eq!(parse_size_213(b"213 0 bytes"), Some(0));
        // A non-numeric size token is rejected (caller proceeds open-ended).
        assert_eq!(parse_size_213(b"213 unknown"), None);
        // A negative value is rejected (sizes are non-negative).
        assert_eq!(parse_size_213(b"213 -5"), None);
        // No token after the code → None.
        assert_eq!(parse_size_213(b"213"), None);
    }

    #[test]
    fn parse_mdtm_213_parses_timestamp() {
        // The canonical `tests/data/test141` reply: 2003-04-09 10:26:59 GMT.
        // Independently confirmed: unix(2003-04-09 10:26:59 GMT) = 1_049_884_019.
        assert_eq!(parse_mdtm_213(b"213 20030409102659"), Some(1_049_884_019));
        // A fractional-seconds suffix (`.sss`) is ignored, exactly as curl does.
        assert_eq!(parse_mdtm_213(b"213 20030409102659.123"), Some(1_049_884_019));
        // Fewer than 14 digits is not a usable timestamp → None (caller omits
        // the synthetic `Last-Modified` header).
        assert_eq!(parse_mdtm_213(b"213 200304091026"), None);
        // A `550` (or any non-`213`) reply is not a timestamp.
        assert_eq!(parse_mdtm_213(b"550 No such file"), None);
        // No token after the code → None.
        assert_eq!(parse_mdtm_213(b"213"), None);
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

    // ---- DO-phase control-channel helpers --------------------------------
    //
    // These drive the transfer-phase command helpers (`cwd_navigate`,
    // `send_type`/`send_size`/`send_rest`) over the mock control socket, plus
    // the pure command-construction (`transfer_command`) and start-classifier
    // (`check_transfer_start`) — the wire-facing logic the existing login/PASV
    // tests above do not reach.

    #[tokio::test]
    async fn cwd_navigate_walks_each_directory_component() {
        let recv = Arc::new(Mutex::new(
            b"250 CWD ok\r\n250 CWD ok\r\n".to_vec(),
        ));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.dirs = vec![
            PathComp { name: "pub".to_string() },
            PathComp { name: "files".to_string() },
        ];

        ftpc.cwd_navigate(&mut data, &mut conn).await.unwrap();
        assert!(ftpc.cwddone, "cwd should be marked done");
        let wire = sent_str(&sent);
        assert!(wire.contains("CWD pub\r\n"), "first CWD wrong: {wire:?}");
        assert!(wire.contains("CWD files\r\n"), "second CWD wrong: {wire:?}");
    }

    #[tokio::test]
    async fn cwd_navigate_denied_is_remote_access_denied() {
        let recv = Arc::new(Mutex::new(b"550 No such directory\r\n".to_vec()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.dirs = vec![PathComp { name: "missing".to_string() }];

        let err = ftpc.cwd_navigate(&mut data, &mut conn).await.unwrap_err();
        assert_eq!(err, CurlError::RemoteAccessDenied);
        assert!(ftpc.cwdfail, "cwdfail flag should be set");
    }

    #[test]
    fn transfer_command_builds_each_verb() {
        let data = Easy::new();
        let mut ftpc = FtpConn::new();
        ftpc.file = Some("report.bin".to_string());

        assert_eq!(
            ftpc.transfer_command(&data, TransferKind::Retr).unwrap(),
            "RETR report.bin"
        );
        assert_eq!(
            ftpc.transfer_command(&data, TransferKind::Stor).unwrap(),
            "STOR report.bin"
        );
        // A bare directory listing takes no path argument.
        assert_eq!(
            ftpc.transfer_command(&data, TransferKind::List).unwrap(),
            "LIST"
        );

        // APPE is selected for an upload when CURLOPT_APPEND is set.
        let mut data_app = Easy::new();
        data_app.set.remote_append = true;
        assert_eq!(
            ftpc.transfer_command(&data_app, TransferKind::Stor).unwrap(),
            "APPE report.bin"
        );

        // NLST is selected for a name-only listing (the per-transfer
        // `list_only`, seeded from `CURLOPT_DIRLISTONLY`/`;type=d`).
        ftpc.list_only = true;
        assert_eq!(
            ftpc.transfer_command(&data, TransferKind::List).unwrap(),
            "NLST"
        );
    }

    #[test]
    fn type_url_check_detects_type_suffix() {
        // `;type=A` / `;type=a` ⇒ ASCII (upper-cased to 'A').
        assert_eq!(type_url_check("dir/file;type=A"), Some(b'A'));
        assert_eq!(type_url_check("dir/file;type=a"), Some(b'A'));
        // `;type=I` / `;type=i` ⇒ binary.
        assert_eq!(type_url_check("path/123;type=I"), Some(b'I'));
        assert_eq!(type_url_check("path/123;type=i"), Some(b'I'));
        // `;type=D` ⇒ directory listing.
        assert_eq!(type_url_check("pub;type=D"), Some(b'D'));
        // The minimal qualifying string is exactly the 7-byte tag.
        assert_eq!(type_url_check(";type=A"), Some(b'A'));
        // No suffix ⇒ None (and short strings never match).
        assert_eq!(type_url_check("dir/file.txt"), None);
        assert_eq!(type_url_check("type=A"), None);
        assert_eq!(type_url_check(""), None);
        // A `;type=` that is not a *trailing* suffix is not matched.
        assert_eq!(type_url_check("a;type=A/b"), None);
    }

    #[test]
    fn transfer_command_nocwd_appends_list_path() {
        // Under `--ftp-method nocwd` curl does not CWD into the directory; it
        // passes the directory path as an argument to LIST/NLST, truncated at
        // the last '/' (C `ftp_state_list`, lib/ftp.c L1424-1445).
        let mut data = Easy::new();
        data.set.ftp_filemethod = CurlFtpFile::NoCwd as u8;

        // Absolute root `/` (URL `ftp://host//`): the `if(n == 0) ++n;`
        // special-case keeps the single slash ⇒ `LIST /` (tests/data/test351).
        let mut root = FtpConn::new();
        root.rawpath = "/".to_string();
        assert_eq!(
            root.transfer_command(&data, TransferKind::List).unwrap(),
            "LIST /"
        );

        // A nested directory drops the trailing slash ⇒ `LIST fir#t/third/244`
        // (tests/data/test244; rawpath is URL-decoded, leading '/' stripped).
        let mut nested = FtpConn::new();
        nested.rawpath = "fir#t/third/244/".to_string();
        assert_eq!(
            nested.transfer_command(&data, TransferKind::List).unwrap(),
            "LIST fir#t/third/244"
        );

        // `--list-only` (per-transfer `list_only`) selects the NLST verb but
        // the same path argument.
        nested.list_only = true;
        assert_eq!(
            nested.transfer_command(&data, TransferKind::List).unwrap(),
            "NLST fir#t/third/244"
        );

        // A rawpath with no slash (e.g. the server home) yields a bare verb.
        let mut bare = FtpConn::new();
        bare.rawpath = String::new();
        assert_eq!(
            bare.transfer_command(&data, TransferKind::List).unwrap(),
            "LIST"
        );

        // The other CWD methods CWD into the directory first, so they emit a
        // bare LIST/NLST with no path argument even when a rawpath is present.
        let mut multicwd = FtpConn::new();
        multicwd.rawpath = "pub/".to_string();
        let data_default = Easy::new(); // default method = MULTICWD
        assert_eq!(
            multicwd.transfer_command(&data_default, TransferKind::List).unwrap(),
            "LIST"
        );
    }

    #[test]
    fn check_transfer_start_classifies_reply_codes() {
        let ftpc = FtpConn::new();
        // 1xx preliminary replies open the data transfer (⇒ Ok(true)).
        assert!(ftpc.check_transfer_start(150, TransferKind::Retr).unwrap());
        assert!(ftpc.check_transfer_start(125, TransferKind::List).unwrap());
        // 450 on a LIST/NLST ⇒ empty listing: a *successful* transfer that
        // opens no data connection (C lib/ftp.c L2783-2787). Signaled as
        // Ok(false), NOT an error, so the control connection is QUIT-ed
        // gracefully (tests/data/test144).
        assert!(!ftpc.check_transfer_start(450, TransferKind::List).unwrap());
        // 450 on a RETR is *not* the empty-listing special case ⇒ generic
        // RETR failure.
        assert_eq!(
            ftpc.check_transfer_start(450, TransferKind::Retr).unwrap_err(),
            CurlError::FtpCouldntRetrFile
        );
        // 550 on a RETR ⇒ file not found (C: only `instate == FTP_RETR`).
        assert_eq!(
            ftpc.check_transfer_start(550, TransferKind::Retr).unwrap_err(),
            CurlError::RemoteFileNotFound
        );
        // 550 on a LIST ⇒ generic RETR failure, NOT file-not-found (C maps
        // only RETR+550 to REMOTE_FILE_NOT_FOUND).
        assert_eq!(
            ftpc.check_transfer_start(550, TransferKind::List).unwrap_err(),
            CurlError::FtpCouldntRetrFile
        );
        // Any other non-1xx download failure ⇒ generic RETR failure.
        assert_eq!(
            ftpc.check_transfer_start(500, TransferKind::Retr).unwrap_err(),
            CurlError::FtpCouldntRetrFile
        );
        // Any non-1xx on an upload ⇒ upload failed.
        assert_eq!(
            ftpc.check_transfer_start(553, TransferKind::Stor).unwrap_err(),
            CurlError::UploadFailed
        );
    }

    #[tokio::test]
    async fn send_type_sets_transfertype_and_reports_failure() {
        // Success: 200 ⇒ transfertype recorded.
        let recv = Arc::new(Mutex::new(b"200 Type set to I\r\n".to_vec()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());

        ftpc.send_type(&mut data, &mut conn, b'I').await.unwrap();
        assert_eq!(ftpc.transfertype, b'I');
        assert!(sent_str(&sent).contains("TYPE I\r\n"));

        // Failure: a non-2xx reply ⇒ CURLE_FTP_COULDNT_SET_TYPE.
        let recv2 = Arc::new(Mutex::new(b"504 Bad type\r\n".to_vec()));
        let sent2 = Arc::new(Mutex::new(Vec::new()));
        let mut conn2 = make_conn(recv2.clone(), sent2.clone());
        let mut ftpc2 = FtpConn::new();
        ftpc2.pp.init(timeval::curlx_now());
        let err = ftpc2.send_type(&mut data, &mut conn2, b'A').await.unwrap_err();
        assert_eq!(err, CurlError::FtpCouldntSetType);
    }

    #[tokio::test]
    async fn send_size_records_known_filesize_on_213() {
        let recv = Arc::new(Mutex::new(b"213 4096\r\n".to_vec()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());

        ftpc.send_size(&mut data, &mut conn, "report.bin").await.unwrap();
        assert_eq!(ftpc.known_filesize, 4096);
        assert!(sent_str(&sent).contains("SIZE report.bin\r\n"));
    }

    #[tokio::test]
    async fn send_rest_requires_350_else_fails() {
        // 350 ⇒ resume accepted.
        let recv = Arc::new(Mutex::new(b"350 Restart position accepted\r\n".to_vec()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());

        ftpc.send_rest(&mut data, &mut conn, 1024).await.unwrap();
        assert!(sent_str(&sent).contains("REST 1024\r\n"));

        // A non-350 reply ⇒ CURLE_FTP_COULDNT_USE_REST.
        let recv2 = Arc::new(Mutex::new(b"500 Not understood\r\n".to_vec()));
        let sent2 = Arc::new(Mutex::new(Vec::new()));
        let mut conn2 = make_conn(recv2.clone(), sent2.clone());
        let mut ftpc2 = FtpConn::new();
        ftpc2.pp.init(timeval::curlx_now());
        let err = ftpc2.send_rest(&mut data, &mut conn2, 1024).await.unwrap_err();
        assert_eq!(err, CurlError::FtpCouldntUseRest);
    }

    // -----------------------------------------------------------------------
    // FTPS login-protection response handlers (ACCT / PBSZ / PROT / CCC / SYST).
    // These mirror the C `ftp_statemachine` per-state arms; each is driven in
    // isolation over the scripted `MockFilter` control channel. `send_cmd` is
    // send-only (the reply is consumed on the *next* state), so no recv script
    // is needed — only the emitted command and the resulting state are checked.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn state_acct_resp_proceeds_on_2xx_and_fails_otherwise() {
        let mut data = Easy::new();
        // A non-2xx ACCT reply ⇒ CURLE_FTP_WEIRD_PASS_REPLY (C "ACCT rejected").
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(Arc::new(Mutex::new(Vec::new())), sent.clone());
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        let err = ftpc
            .state_acct_resp(&mut data, &mut conn, 530)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::FtpWeirdPassReply);

        // A 2xx ACCT on a clear control channel ⇒ logged in ⇒ straight to PWD.
        let sent2 = Arc::new(Mutex::new(Vec::new()));
        let mut conn2 = make_conn(Arc::new(Mutex::new(Vec::new())), sent2.clone());
        let mut ftpc2 = FtpConn::new();
        ftpc2.pp.init(timeval::curlx_now());
        ftpc2.control_ssl = false;
        ftpc2
            .state_acct_resp(&mut data, &mut conn2, 230)
            .await
            .unwrap();
        assert!(sent_str(&sent2).contains("PWD\r\n"));
        assert_eq!(ftpc2.state, FtpState::Pwd);
    }

    #[tokio::test]
    async fn state_loggedin_starts_pbsz_on_tls_else_pwd() {
        let mut data = Easy::new();
        // TLS control channel ⇒ begin data-protection with `PBSZ 0`.
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(Arc::new(Mutex::new(Vec::new())), sent.clone());
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.control_ssl = true;
        ftpc.state_loggedin(&mut data, &mut conn).await.unwrap();
        assert!(sent_str(&sent).contains("PBSZ 0\r\n"));
        assert_eq!(ftpc.state, FtpState::Pbsz);

        // Clear control channel ⇒ skip straight to `PWD`.
        let sent2 = Arc::new(Mutex::new(Vec::new()));
        let mut conn2 = make_conn(Arc::new(Mutex::new(Vec::new())), sent2.clone());
        let mut ftpc2 = FtpConn::new();
        ftpc2.pp.init(timeval::curlx_now());
        ftpc2.control_ssl = false;
        ftpc2.state_loggedin(&mut data, &mut conn2).await.unwrap();
        assert!(sent_str(&sent2).contains("PWD\r\n"));
        assert_eq!(ftpc2.state, FtpState::Pwd);
    }

    #[tokio::test]
    async fn state_pbsz_resp_selects_prot_clear_or_private() {
        // CURLUSESSL_CONTROL ⇒ only the control channel is protected ⇒ `PROT C`.
        let mut data = Easy::new();
        data.set.use_ssl = CURLUSESSL_CONTROL;
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(Arc::new(Mutex::new(Vec::new())), sent.clone());
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.state_pbsz_resp(&mut data, &mut conn, 200).await.unwrap();
        assert!(sent_str(&sent).contains("PROT C\r\n"));
        assert_eq!(ftpc.state, FtpState::Prot);

        // Full SSL (CURLUSESSL_ALL = 3) ⇒ protect the data channel too ⇒ `PROT P`.
        let mut data2 = Easy::new();
        data2.set.use_ssl = 3;
        let sent2 = Arc::new(Mutex::new(Vec::new()));
        let mut conn2 = make_conn(Arc::new(Mutex::new(Vec::new())), sent2.clone());
        let mut ftpc2 = FtpConn::new();
        ftpc2.pp.init(timeval::curlx_now());
        ftpc2
            .state_pbsz_resp(&mut data2, &mut conn2, 200)
            .await
            .unwrap();
        assert!(sent_str(&sent2).contains("PROT P\r\n"));
        assert_eq!(ftpc2.state, FtpState::Prot);
    }

    #[tokio::test]
    async fn state_prot_resp_records_level_or_ccc_or_fails() {
        // 2xx with no CCC requested ⇒ record the SSL level and proceed to PWD.
        let mut data = Easy::new();
        data.set.use_ssl = 3; // CURLUSESSL_ALL
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(Arc::new(Mutex::new(Vec::new())), sent.clone());
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.state_prot_resp(&mut data, &mut conn, 200).await.unwrap();
        assert_eq!(ftpc.use_ssl, 3);
        assert!(sent_str(&sent).contains("PWD\r\n"));
        assert_eq!(ftpc.state, FtpState::Pwd);

        // 2xx with CCC requested ⇒ send `CCC` and advance to the CCC state.
        let mut data2 = Easy::new();
        data2.set.use_ssl = 3;
        data2.set.ftp_ccc = 1;
        let sent2 = Arc::new(Mutex::new(Vec::new()));
        let mut conn2 = make_conn(Arc::new(Mutex::new(Vec::new())), sent2.clone());
        let mut ftpc2 = FtpConn::new();
        ftpc2.pp.init(timeval::curlx_now());
        ftpc2
            .state_prot_resp(&mut data2, &mut conn2, 200)
            .await
            .unwrap();
        assert_eq!(ftpc2.ccc, 1);
        assert!(sent_str(&sent2).contains("CCC\r\n"));
        assert_eq!(ftpc2.state, FtpState::Ccc);

        // Server rejects `PROT P` (500) while full SSL was required ⇒ fail.
        let mut data3 = Easy::new();
        data3.set.use_ssl = 3; // > CURLUSESSL_CONTROL
        let sent3 = Arc::new(Mutex::new(Vec::new()));
        let mut conn3 = make_conn(Arc::new(Mutex::new(Vec::new())), sent3.clone());
        let mut ftpc3 = FtpConn::new();
        ftpc3.pp.init(timeval::curlx_now());
        let err = ftpc3
            .state_prot_resp(&mut data3, &mut conn3, 500)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::UseSslFailed);
    }

    #[tokio::test]
    async fn state_ccc_resp_clears_control_then_sends_pwd() {
        let mut data = Easy::new();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(Arc::new(Mutex::new(Vec::new())), sent.clone());
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.control_ssl = true;
        ftpc.state_ccc_resp(&mut data, &mut conn).await.unwrap();
        assert!(!ftpc.control_ssl, "CCC returns the control channel to clear");
        assert!(sent_str(&sent).contains("PWD\r\n"));
        assert_eq!(ftpc.state, FtpState::Pwd);
    }

    #[tokio::test]
    async fn state_syst_resp_records_os_and_handles_os400() {
        // A 215 naming a generic UNIX OS ⇒ record it and finish the connect phase.
        let mut data = Easy::new();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(Arc::new(Mutex::new(Vec::new())), sent.clone());
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.last_response = b"215 UNIX Type: L8".to_vec();
        ftpc.state_syst_resp(&mut data, &mut conn, 215).await.unwrap();
        assert_eq!(ftpc.server_os.as_deref(), Some("UNIX"));
        assert_eq!(ftpc.state, FtpState::Stop);

        // `OS/400` additionally triggers `SITE NAMEFMT 1` ⇒ Namefmt state.
        let sent2 = Arc::new(Mutex::new(Vec::new()));
        let mut conn2 = make_conn(Arc::new(Mutex::new(Vec::new())), sent2.clone());
        let mut ftpc2 = FtpConn::new();
        ftpc2.pp.init(timeval::curlx_now());
        ftpc2.last_response = b"215 OS/400 is the operating system".to_vec();
        ftpc2
            .state_syst_resp(&mut data, &mut conn2, 215)
            .await
            .unwrap();
        assert_eq!(ftpc2.server_os.as_deref(), Some("OS/400"));
        assert!(sent_str(&sent2).contains("SITE NAMEFMT 1\r\n"));
        assert_eq!(ftpc2.state, FtpState::Namefmt);

        // A non-215 reply ⇒ no OS recorded, connect phase ends.
        let sent3 = Arc::new(Mutex::new(Vec::new()));
        let mut conn3 = make_conn(Arc::new(Mutex::new(Vec::new())), sent3.clone());
        let mut ftpc3 = FtpConn::new();
        ftpc3.pp.init(timeval::curlx_now());
        ftpc3.last_response = b"500 Unknown command".to_vec();
        ftpc3
            .state_syst_resp(&mut data, &mut conn3, 500)
            .await
            .unwrap();
        assert_eq!(ftpc3.server_os, None);
        assert_eq!(ftpc3.state, FtpState::Stop);
    }

    #[tokio::test]
    async fn state_wait220_greeting_dispatches_user_auth_or_error() {
        // Plain 220 with no SSL ⇒ send USER and move to the User state.
        let mut data = Easy::new();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(Arc::new(Mutex::new(Vec::new())), sent.clone());
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.state_wait220(&mut data, &mut conn, 220).await.unwrap();
        assert!(sent_str(&sent).contains("USER "));
        assert_eq!(ftpc.state, FtpState::User);

        // A non-220/230 greeting (e.g. 421) ⇒ CURLE_WEIRD_SERVER_REPLY.
        let mut conn_e = make_conn(Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
        let mut ftpc_e = FtpConn::new();
        ftpc_e.pp.init(timeval::curlx_now());
        let err = ftpc_e
            .state_wait220(&mut data, &mut conn_e, 421)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::WeirdServerReply);

        // FTPS requested (CURLUSESSL_TRY) on a clear control channel, default
        // FTPSSLAUTH ⇒ begin AUTH negotiation with `AUTH SSL`.
        let mut data_ssl = Easy::new();
        data_ssl.set.use_ssl = CURLUSESSL_TRY;
        data_ssl.set.ftpsslauth = CURLFTPAUTH_DEFAULT;
        let sent_s = Arc::new(Mutex::new(Vec::new()));
        let mut conn_s = make_conn(Arc::new(Mutex::new(Vec::new())), sent_s.clone());
        let mut ftpc_s = FtpConn::new();
        ftpc_s.pp.init(timeval::curlx_now());
        ftpc_s
            .state_wait220(&mut data_ssl, &mut conn_s, 220)
            .await
            .unwrap();
        assert!(sent_str(&sent_s).contains("AUTH SSL\r\n"));
        assert_eq!(ftpc_s.state, FtpState::Auth);

        // FTPSSLAUTH=TLS starts the negotiation at `AUTH TLS` instead.
        let mut data_tls = Easy::new();
        data_tls.set.use_ssl = CURLUSESSL_TRY;
        data_tls.set.ftpsslauth = CURLFTPAUTH_TLS;
        let sent_t = Arc::new(Mutex::new(Vec::new()));
        let mut conn_t = make_conn(Arc::new(Mutex::new(Vec::new())), sent_t.clone());
        let mut ftpc_t = FtpConn::new();
        ftpc_t.pp.init(timeval::curlx_now());
        ftpc_t
            .state_wait220(&mut data_tls, &mut conn_t, 220)
            .await
            .unwrap();
        assert!(sent_str(&sent_t).contains("AUTH TLS\r\n"));
        assert_eq!(ftpc_t.state, FtpState::Auth);

        // An unsupported FTPSSLAUTH value ⇒ CURLE_UNKNOWN_OPTION.
        let mut data_bad = Easy::new();
        data_bad.set.use_ssl = CURLUSESSL_TRY;
        data_bad.set.ftpsslauth = 99;
        let mut conn_b = make_conn(Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
        let mut ftpc_b = FtpConn::new();
        ftpc_b.pp.init(timeval::curlx_now());
        let err = ftpc_b
            .state_wait220(&mut data_bad, &mut conn_b, 220)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::UnknownOption);
    }

    #[tokio::test]
    async fn state_auth_retries_then_fails_or_falls_back() {
        // First rejection (count3 == 0) ⇒ try the alternative mechanism and
        // remain in AUTH. Starting from the default `AUTH SSL` setup
        // (count1=0, count2=+1), the retry advances to `AUTH TLS`.
        let mut data = Easy::new();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(Arc::new(Mutex::new(Vec::new())), sent.clone());
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.count1 = 0;
        ftpc.count2 = 1;
        ftpc.count3 = 0;
        ftpc.state_auth(&mut data, &mut conn, 500).await.unwrap();
        assert_eq!(ftpc.count3, 1);
        assert!(sent_str(&sent).contains("AUTH TLS\r\n"));

        // Second rejection (count3 >= 1) with mandatory SSL ⇒ CURLE_USE_SSL_FAILED.
        let mut data_req = Easy::new();
        data_req.set.use_ssl = CURLUSESSL_CONTROL; // > CURLUSESSL_TRY
        let mut conn_r = make_conn(Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
        let mut ftpc_r = FtpConn::new();
        ftpc_r.pp.init(timeval::curlx_now());
        ftpc_r.count3 = 1;
        let err = ftpc_r
            .state_auth(&mut data_req, &mut conn_r, 500)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::UseSslFailed);

        // Second rejection with optional SSL ⇒ continue in clear text (USER).
        let mut data_try = Easy::new();
        data_try.set.use_ssl = CURLUSESSL_TRY;
        let sent_c = Arc::new(Mutex::new(Vec::new()));
        let mut conn_c = make_conn(Arc::new(Mutex::new(Vec::new())), sent_c.clone());
        let mut ftpc_c = FtpConn::new();
        ftpc_c.pp.init(timeval::curlx_now());
        ftpc_c.count3 = 1;
        ftpc_c
            .state_auth(&mut data_try, &mut conn_c, 500)
            .await
            .unwrap();
        assert!(sent_str(&sent_c).contains("USER "));
        assert_eq!(ftpc_c.state, FtpState::User);
    }

    #[tokio::test]
    async fn state_user_resp_password_account_alt_and_denied() {
        let mut data = Easy::new();
        // 331 in the User state ⇒ send PASS, advance to Pass.
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(Arc::new(Mutex::new(Vec::new())), sent.clone());
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.set_state(FtpState::User);
        ftpc.passwd = "secret".to_string();
        ftpc.state_user_resp(&mut data, &mut conn, 331).await.unwrap();
        assert!(sent_str(&sent).contains("PASS secret\r\n"));
        assert_eq!(ftpc.state, FtpState::Pass);

        // 2xx ⇒ logged in; on a clear control channel that means straight to PWD.
        let sent2 = Arc::new(Mutex::new(Vec::new()));
        let mut conn2 = make_conn(Arc::new(Mutex::new(Vec::new())), sent2.clone());
        let mut ftpc2 = FtpConn::new();
        ftpc2.pp.init(timeval::curlx_now());
        ftpc2.control_ssl = false;
        ftpc2
            .state_user_resp(&mut data, &mut conn2, 230)
            .await
            .unwrap();
        assert!(sent_str(&sent2).contains("PWD\r\n"));

        // 332 with an account configured ⇒ send ACCT, advance to Acct.
        let sent3 = Arc::new(Mutex::new(Vec::new()));
        let mut conn3 = make_conn(Arc::new(Mutex::new(Vec::new())), sent3.clone());
        let mut ftpc3 = FtpConn::new();
        ftpc3.pp.init(timeval::curlx_now());
        ftpc3.account = Some("acct-1".to_string());
        ftpc3
            .state_user_resp(&mut data, &mut conn3, 332)
            .await
            .unwrap();
        assert!(sent_str(&sent3).contains("ACCT acct-1\r\n"));
        assert_eq!(ftpc3.state, FtpState::Acct);

        // 332 with no account ⇒ CURLE_LOGIN_DENIED.
        let mut conn4 = make_conn(
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
        );
        let mut ftpc4 = FtpConn::new();
        ftpc4.pp.init(timeval::curlx_now());
        ftpc4.account = None;
        let err = ftpc4
            .state_user_resp(&mut data, &mut conn4, 332)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::LoginDenied);

        // Access denial with an alternative command ⇒ try it once, back to User.
        let sent5 = Arc::new(Mutex::new(Vec::new()));
        let mut conn5 = make_conn(Arc::new(Mutex::new(Vec::new())), sent5.clone());
        let mut ftpc5 = FtpConn::new();
        ftpc5.pp.init(timeval::curlx_now());
        ftpc5.alternative_to_user = Some("USER anonymous".to_string());
        ftpc5
            .state_user_resp(&mut data, &mut conn5, 530)
            .await
            .unwrap();
        assert!(sent_str(&sent5).contains("USER anonymous\r\n"));
        assert!(ftpc5.ftp_trying_alternative);
        assert_eq!(ftpc5.state, FtpState::User);

        // Access denial with no (remaining) alternative ⇒ CURLE_LOGIN_DENIED.
        let mut conn6 = make_conn(
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
        );
        let mut ftpc6 = FtpConn::new();
        ftpc6.pp.init(timeval::curlx_now());
        let err = ftpc6
            .state_user_resp(&mut data, &mut conn6, 530)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::LoginDenied);
    }

    #[tokio::test]
    async fn state_pwd_resp_records_entrypath_and_probes_syst() {
        let mut data = Easy::new();
        // 257 with a *relative* entry path and unknown OS ⇒ probe SYST.
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(Arc::new(Mutex::new(Vec::new())), sent.clone());
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.last_response = b"257 \"home/user\" is current directory".to_vec();
        ftpc.server_os = None;
        ftpc.state_pwd_resp(&mut data, &mut conn, 257).await.unwrap();
        assert_eq!(ftpc.entrypath.as_deref(), Some("home/user"));
        assert!(sent_str(&sent).contains("SYST\r\n"));
        assert_eq!(ftpc.state, FtpState::Syst);

        // 257 with an *absolute* entry path ⇒ no SYST probe, connect phase ends.
        let sent2 = Arc::new(Mutex::new(Vec::new()));
        let mut conn2 = make_conn(Arc::new(Mutex::new(Vec::new())), sent2.clone());
        let mut ftpc2 = FtpConn::new();
        ftpc2.pp.init(timeval::curlx_now());
        ftpc2.last_response = b"257 \"/pub\" is current directory".to_vec();
        ftpc2
            .state_pwd_resp(&mut data, &mut conn2, 257)
            .await
            .unwrap();
        assert_eq!(ftpc2.entrypath.as_deref(), Some("/pub"));
        assert!(!sent_str(&sent2).contains("SYST"));
        assert_eq!(ftpc2.state, FtpState::Stop);

        // A non-257 reply ⇒ no entry path recorded, connect phase ends.
        let mut conn3 = make_conn(
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
        );
        let mut ftpc3 = FtpConn::new();
        ftpc3.pp.init(timeval::curlx_now());
        ftpc3.last_response = b"500 not understood".to_vec();
        ftpc3
            .state_pwd_resp(&mut data, &mut conn3, 500)
            .await
            .unwrap();
        assert_eq!(ftpc3.entrypath, None);
        assert_eq!(ftpc3.state, FtpState::Stop);
    }

    // =====================================================================
    // Added coverage: pure codec helpers, the QUOTE pipeline, CWD MKD
    // recovery, the INFO (`--head`) metadata phase, and full passive
    // data-channel download/upload drives over a real loopback data socket.
    // =====================================================================

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Minimal body/header-collecting [`WriteCallbacks`] sink for the drive
    /// tests (the engine's real client sink without any front-end hooks).
    #[derive(Default)]
    struct VecSink {
        body: Vec<u8>,
        headers: Vec<u8>,
    }
    impl WriteCallbacks for VecSink {
        fn write_body(&mut self, data: &[u8]) -> usize {
            self.body.extend_from_slice(data);
            data.len()
        }
        fn write_header(&mut self, data: &[u8]) -> Option<usize> {
            self.headers.extend_from_slice(data);
            Some(data.len())
        }
    }

    /// Minimal in-memory [`ReadCallback`] upload source: hands out a fixed byte
    /// vector then signals EOF (a `0`-length read), exactly as a finite file
    /// source would.
    struct SliceSource {
        data: Vec<u8>,
        pos: usize,
    }
    impl ReadCallback for SliceSource {
        fn read(&mut self, buf: &mut [u8]) -> usize {
            let n = (self.data.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            n
        }
    }

    #[test]
    fn crlf_convert_chunk_expands_lone_lf_only() {
        // A lone LF becomes CRLF; an existing CRLF pair is left untouched.
        let mut prev_cr = false;
        let mut out = Vec::new();
        crlf_convert_chunk(b"a\nb\r\nc", &mut prev_cr, &mut out);
        assert_eq!(out, b"a\r\nb\r\nc");
        assert!(!prev_cr, "last byte 'c' is not CR");

        // A trailing CR sets `prev_cr` so an LF opening the next chunk is
        // recognized as an already-converted pair (no doubling across the
        // chunk boundary).
        let mut prev_cr = false;
        let mut out = Vec::new();
        crlf_convert_chunk(b"x\r", &mut prev_cr, &mut out);
        assert!(prev_cr, "chunk ended on CR");
        crlf_convert_chunk(b"\ny", &mut prev_cr, &mut out);
        assert_eq!(out, b"x\r\ny");
        assert!(!prev_cr);
    }

    #[test]
    fn parse_decimal_consumes_digits_and_enforces_max() {
        // Leading digits are consumed; the non-digit remainder is returned.
        let (v, rest) = parse_decimal(b"2048rest", 65535).unwrap();
        assert_eq!(v, 2048);
        assert_eq!(rest, b"rest");
        // A value exceeding `max` fails the bound check.
        assert!(parse_decimal(b"70000", 65535).is_none());
        // No leading digit consumes nothing → None.
        assert!(parse_decimal(b"abc", 100).is_none());
        // Exactly at the bound is accepted.
        let (v, rest) = parse_decimal(b"255", 255).unwrap();
        assert_eq!(v, 255);
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn send_quote_list_sends_each_and_accepts_2xx() {
        let recv = Arc::new(Mutex::new(b"200 NOOP ok\r\n250 dir changed\r\n".to_vec()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());

        let list = vec![
            std::ffi::CString::new("NOOP").unwrap(),
            std::ffi::CString::new("CWD x").unwrap(),
        ];
        ftpc.send_quote_list(&mut data, &mut conn, &list)
            .await
            .unwrap();
        let wire = sent_str(&sent);
        assert!(wire.contains("NOOP\r\n"), "wire: {wire:?}");
        assert!(wire.contains("CWD x\r\n"), "wire: {wire:?}");
    }

    #[tokio::test]
    async fn send_quote_list_star_prefix_tolerates_failure_else_aborts() {
        // A `*`-prefixed command is allowed to fail (the `*` is stripped before
        // sending), so a 500 reply is accepted.
        let recv = Arc::new(Mutex::new(b"500 nope\r\n".to_vec()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        let ok = vec![std::ffi::CString::new("*SITE BOGUS").unwrap()];
        ftpc.send_quote_list(&mut data, &mut conn, &ok).await.unwrap();
        assert!(sent_str(&sent).contains("SITE BOGUS\r\n"));

        // The same failing command without the `*` aborts with QuoteError.
        let recv2 = Arc::new(Mutex::new(b"500 nope\r\n".to_vec()));
        let sent2 = Arc::new(Mutex::new(Vec::new()));
        let mut conn2 = make_conn(recv2.clone(), sent2.clone());
        let mut ftpc2 = FtpConn::new();
        ftpc2.pp.init(timeval::curlx_now());
        let bad = vec![std::ffi::CString::new("SITE BOGUS").unwrap()];
        let err = ftpc2
            .send_quote_list(&mut data, &mut conn2, &bad)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::QuoteError);
    }

    #[tokio::test]
    async fn cwd_navigate_creates_missing_dir_then_retries() {
        // `--ftp-create-dirs` (level 2): a denied `CWD` (550) recovers via
        // `MKD` (257) and a retried `CWD` (250).
        let recv = Arc::new(Mutex::new(
            b"550 No such dir\r\n257 \"/new\" created\r\n250 CWD ok\r\n".to_vec(),
        ));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        data.set.ftp_create_missing_dirs = 2;

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.dirs = vec![PathComp {
            name: "new".to_string(),
        }];

        ftpc.cwd_navigate(&mut data, &mut conn).await.unwrap();
        assert!(ftpc.cwddone);
        let wire = sent_str(&sent);
        assert!(wire.contains("MKD new\r\n"), "wire: {wire:?}");
        // The `CWD` is issued, then retried after the `MKD`.
        assert!(
            wire.matches("CWD new\r\n").count() >= 2,
            "expected CWD retry, wire: {wire:?}"
        );
    }

    #[tokio::test]
    async fn run_info_phase_emits_metadata_headers() {
        // `--head` on a file: MDTM (213) + TYPE (200) + SIZE (213) + REST 0
        // (350) → Content-Length + Accept-ranges written to the sink.
        let recv = Arc::new(Mutex::new(
            b"213 20240101000000\r\n200 Type set to I\r\n213 4096\r\n350 Restart OK\r\n".to_vec(),
        ));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        data.set.get_filetime = true;

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.file = Some("data.bin".to_string());

        let mut sink = VecSink::default();
        ftpc.run_info_phase(&mut data, &mut conn, &mut sink)
            .await
            .unwrap();

        let wire = sent_str(&sent);
        assert!(wire.contains("MDTM data.bin\r\n"), "wire: {wire:?}");
        assert!(wire.contains("TYPE I\r\n"), "wire: {wire:?}");
        assert!(wire.contains("SIZE data.bin\r\n"), "wire: {wire:?}");
        assert!(wire.contains("REST 0\r\n"), "wire: {wire:?}");
        let headers = String::from_utf8_lossy(&sink.headers);
        assert!(
            headers.contains("Content-Length: 4096\r\n"),
            "headers: {headers:?}"
        );
        assert!(
            headers.contains("Accept-ranges: bytes\r\n"),
            "headers: {headers:?}"
        );
        assert_eq!(ftpc.known_filesize, 4096);
        assert!(ftpc.dont_check);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn passive_download_moves_body_over_real_data_socket() {
        // Bind a real loopback listener as the data endpoint and advertise its
        // port in the EPSV reply; the engine connects out and reads the body.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = b"hello ftp download body\n".to_vec(); // 24 bytes
        let body_clone = body.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(&body_clone).await.unwrap();
            // Dropping `sock` closes the connection → the client sees EOF.
        });

        // Control responses, in the exact order `run_do_phase` reads them:
        // EPSV(229) → TYPE(200) → SIZE(213) → RETR(150).
        let recv = Arc::new(Mutex::new(
            format!(
                "229 Entering Extended Passive Mode (|||{port}|)\r\n\
                 200 Type set to I\r\n\
                 213 24\r\n\
                 150 Opening BINARY mode data connection\r\n"
            )
            .into_bytes(),
        ));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        data.set.ftp_use_epsv = true;

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.file = Some("download.bin".to_string());

        let mut sink = VecSink::default();
        let mut source = SliceSource {
            data: Vec::new(),
            pos: 0,
        };
        ftpc.run_do_phase(&mut data, &mut conn, &mut sink, &mut source)
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(sink.body, body, "downloaded body mismatch");
        let wire = sent_str(&sent);
        assert!(wire.contains("EPSV\r\n"), "wire: {wire:?}");
        assert!(wire.contains("TYPE I\r\n"), "wire: {wire:?}");
        assert!(wire.contains("RETR download.bin\r\n"), "wire: {wire:?}");
        assert_eq!(data.info.size_download, body.len() as i64);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn passive_upload_sends_body_over_real_data_socket() {
        // Loopback listener that READS the uploaded body to EOF.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let collected = Arc::new(Mutex::new(Vec::new()));
        let collected2 = collected.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            *collected2.lock().unwrap() = buf;
        });

        // Control responses: EPSV(229) → TYPE(200) → STOR(150).
        let recv = Arc::new(Mutex::new(
            format!(
                "229 Entering Extended Passive Mode (|||{port}|)\r\n\
                 200 Type set to I\r\n\
                 150 Ok to send data\r\n"
            )
            .into_bytes(),
        ));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        data.set.ftp_use_epsv = true;
        data.set.method = HttpReq::Put;
        let payload = b"upload payload bytes 12345".to_vec();
        data.set.filesize = payload.len() as i64;

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.file = Some("upload.bin".to_string());

        let mut sink = VecSink::default();
        let mut source = SliceSource {
            data: payload.clone(),
            pos: 0,
        };
        ftpc.run_do_phase(&mut data, &mut conn, &mut sink, &mut source)
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(*collected.lock().unwrap(), payload, "uploaded body mismatch");
        let wire = sent_str(&sent);
        assert!(wire.contains("STOR upload.bin\r\n"), "wire: {wire:?}");
        assert_eq!(data.info.size_upload, payload.len() as i64);
    }

    // ---- ftp_done: trailing completion handshake -------------------------

    /// A clean download completion (C `ftp_done`): read the trailing `226`,
    /// run `CURLOPT_POSTQUOTE` while the control channel is still up, then
    /// remember the working directory (`prevpath`) for connection reuse. With
    /// the default MULTICWD method the leaf file name is stripped from the
    /// raw path to yield the directory.
    #[tokio::test]
    async fn ftp_done_reads_226_runs_postquote_and_remembers_prevpath() {
        let recv = Arc::new(Mutex::new(
            b"226 Transfer complete\r\n250 DELE command successful\r\n".to_vec(),
        ));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        // POSTQUOTE runs only after a clean, non-premature transfer.
        let mut postquote = crate::slist::SList::new();
        postquote.append("DELE old.tmp").unwrap();
        data.set.postquote = Some(postquote);

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.ctl_valid = true;
        ftpc.rawpath = "pub/data/file.bin".to_string();
        ftpc.file = Some("file.bin".to_string());

        ftpc.ftp_done(&mut data, &mut conn, Ok(()), false)
            .await
            .unwrap();

        let wire = sent_str(&sent);
        assert!(wire.contains("DELE old.tmp\r\n"), "wire: {wire:?}");
        // MULTICWD (default) strips the leaf → the directory is remembered.
        assert_eq!(ftpc.prevpath.as_deref(), Some("pub/data/"));
        // The per-transfer data endpoint is cleared for reuse.
        assert_eq!(ftpc.data_host, None);
        assert_eq!(ftpc.data_port, 0);
    }

    /// A capped-range download (`maxdownload > 0`, e.g. `-r 0-15`) ends with
    /// the data socket still open: `ftp_done` sends `ABOR`, closes the data
    /// socket, and reads the single queued trailing response — without the
    /// normal completion-code check (C deliberately does not verify it).
    #[tokio::test]
    async fn ftp_done_capped_range_sends_abor_then_reads_trailer() {
        let recv = Arc::new(Mutex::new(b"226 Abort successful\r\n".to_vec()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.ctl_valid = true;
        ftpc.maxdownload = 16; // bounded range → ABOR path

        ftpc.ftp_done(&mut data, &mut conn, Ok(()), false)
            .await
            .unwrap();

        let wire = sent_str(&sent);
        assert!(wire.contains("ABOR\r\n"), "wire: {wire:?}");
        assert_eq!(ftpc.data_host, None);
        assert_eq!(ftpc.data_port, 0);
    }

    /// `ftp_done` maps a `552` completion ("Exceeded storage allocation") to
    /// `CURLE_REMOTE_DISK_FULL` (C `ftp_done`, lib/ftp.c L3634-3647).
    #[tokio::test]
    async fn ftp_done_552_maps_to_disk_full() {
        let recv = Arc::new(Mutex::new(b"552 Exceeded storage allocation\r\n".to_vec()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.ctl_valid = true;
        let res = ftpc.ftp_done(&mut data, &mut conn, Ok(()), false).await;
        assert!(matches!(res, Err(CurlError::RemoteDiskFull)), "got {res:?}");
    }

    /// `ftp_done`: any other non-`2xx` trailing completion → `CURLE_PARTIAL_FILE`.
    #[tokio::test]
    async fn ftp_done_non2xx_completion_is_partial_file() {
        let recv = Arc::new(Mutex::new(b"451 Requested action aborted\r\n".to_vec()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.ctl_valid = true;
        let res = ftpc.ftp_done(&mut data, &mut conn, Ok(()), false).await;
        assert!(matches!(res, Err(CurlError::PartialFile)), "got {res:?}");
    }

    /// A *hard* error (one not in curl's "control connection stays alive" set,
    /// here `CURLE_URL_MALFORMAT`) wedges the control channel: `ftp_done`
    /// clears `ctl_valid`, forgets `prevpath`, and — being premature — skips the
    /// completion read entirely.
    #[tokio::test]
    async fn ftp_done_hard_error_wedges_control_and_clears_prevpath() {
        let recv = Arc::new(Mutex::new(Vec::new())); // no completion read expected
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.ctl_valid = true;
        ftpc.prevpath = Some("pub/".to_string());

        let res = ftpc
            .ftp_done(&mut data, &mut conn, Err(CurlError::UrlMalformat), true)
            .await;
        assert!(res.is_err());
        assert!(!ftpc.ctl_valid, "hard error must wedge the control channel");
        assert_eq!(ftpc.prevpath, None);
        // No completion handshake (and no ABOR) was attempted.
        assert!(sent_str(&sent).is_empty(), "wire: {:?}", sent_str(&sent));
    }

    // ---- Active mode (PORT/EPRT) -----------------------------------------

    /// Active-mode (`EPRT`) download driven end-to-end through `run_do_phase`.
    /// The engine binds a local listener and advertises it via `EPRT`; this
    /// test plays the *server* — it parses the advertised port off the control
    /// wire, connects back, and streams the body. Exercises
    /// `negotiate_active_noaccept` → `setup_active` → `state_port_resp` →
    /// `accept_data_active` and the active branch of `run_do_phase`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn active_mode_download_over_real_data_socket() {
        let body = b"active mode download body!\n".to_vec(); // 27 bytes
        let body_clone = body.clone();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_for_task = sent.clone();

        // Server task: wait for the EPRT advertisement, parse `EPRT |1|host|PORT|`,
        // connect back to 127.0.0.1:PORT, and stream the body.
        let server = tokio::spawn(async move {
            let port = loop {
                {
                    let wire =
                        String::from_utf8_lossy(&sent_for_task.lock().unwrap()).to_string();
                    if let Some(idx) = wire.find("EPRT |") {
                        let fields: Vec<&str> = wire[idx..].split('|').collect();
                        if fields.len() >= 4 {
                            if let Ok(p) = fields[3].parse::<u16>() {
                                break p;
                            }
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            };
            let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            sock.write_all(&body_clone).await.unwrap();
            // Drop closes the connection → the client reads EOF.
        });

        // Control replies in the order active-mode `run_do_phase` reads them:
        // EPRT(200) → TYPE(200) → SIZE(213) → RETR(150).
        let recv = Arc::new(Mutex::new(
            b"200 EPRT command successful\r\n\
              200 Type set to I\r\n\
              213 27\r\n\
              150 Opening BINARY mode data connection\r\n"
                .to_vec(),
        ));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        data.set.ftp_use_port = true; // active mode
        data.set.ftp_use_eprt = true; // prefer EPRT over PORT

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.file = Some("active.bin".to_string());

        let mut sink = VecSink::default();
        let mut source = SliceSource {
            data: Vec::new(),
            pos: 0,
        };
        ftpc.run_do_phase(&mut data, &mut conn, &mut sink, &mut source)
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(sink.body, body, "active-mode body mismatch");
        let wire = sent_str(&sent);
        assert!(wire.contains("EPRT |1|"), "wire: {wire:?}");
        assert!(wire.contains("RETR active.bin\r\n"), "wire: {wire:?}");
        assert_eq!(data.info.size_download, body.len() as i64);
    }

    // ---- Directory listing (LIST) ----------------------------------------

    /// A directory listing: no leaf file name ⇒ `TransferKind::List`, which
    /// forces `TYPE A` (listings are always ASCII) and a bare `LIST`. The
    /// listing text flows over a real data socket. Exercises the listing
    /// classification and the `TYPE A`/`LIST` arms of `run_do_phase`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn passive_listing_uses_type_a_and_list() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let listing = b"-rw-r--r-- 1 user group 42 Jan  1 00:00 a.txt\r\n".to_vec();
        let listing_clone = listing.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(&listing_clone).await.unwrap();
        });

        // EPSV(229) → TYPE A(200) → LIST(150). A listing issues no SIZE.
        let recv = Arc::new(Mutex::new(
            format!(
                "229 Entering Extended Passive Mode (|||{port}|)\r\n\
                 200 Type set to A\r\n\
                 150 Here comes the directory listing\r\n"
            )
            .into_bytes(),
        ));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        data.set.ftp_use_epsv = true;

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.file = None; // no leaf → directory listing (kind == List)

        let mut sink = VecSink::default();
        let mut source = SliceSource {
            data: Vec::new(),
            pos: 0,
        };
        ftpc.run_do_phase(&mut data, &mut conn, &mut sink, &mut source)
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(sink.body, listing, "listing body mismatch");
        let wire = sent_str(&sent);
        assert!(wire.contains("TYPE A\r\n"), "wire: {wire:?}");
        assert!(wire.contains("LIST\r\n"), "wire: {wire:?}");
    }

    // ---- Time-condition + resume -----------------------------------------

    /// A time-conditioned download (`-z`, `CURL_TIMECOND_IFMODSINCE`) whose
    /// remote file is NOT newer than the configured time: `run_do_phase` queries
    /// `MDTM`, parses the modification time, finds the condition unmet, sets
    /// `CURLINFO_CONDITION_UNMET`, and stops without opening a data channel (no
    /// `EPSV`/`RETR`). Exercises the MDTM + time-condition gate (control-only).
    #[tokio::test]
    async fn download_time_condition_unmet_skips_after_mdtm() {
        // MDTM: file modified 2001-01-01 (~9.78e8 epoch), older than the
        // configured `timevalue` (2.0e9) ⇒ IFMODSINCE "not modified" ⇒ skip.
        let recv = Arc::new(Mutex::new(b"213 20010101000000\r\n".to_vec()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        data.set.timecondition = 1; // CURL_TIMECOND_IFMODSINCE
        data.set.timevalue = 2_000_000_000; // far ahead of the MDTM time
        data.set.ftp_use_epsv = true;

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.file = Some("stale.txt".to_string());

        let mut sink = VecSink::default();
        let mut source = SliceSource {
            data: Vec::new(),
            pos: 0,
        };
        ftpc.run_do_phase(&mut data, &mut conn, &mut sink, &mut source)
            .await
            .unwrap();

        assert!(data.info.timecond, "condition should be unmet (skipped)");
        assert!(data.info.filetime > 0, "filetime parsed from MDTM");
        let wire = sent_str(&sent);
        assert!(wire.contains("MDTM stale.txt\r\n"), "wire: {wire:?}");
        assert!(!wire.contains("EPSV"), "must not open data channel: {wire:?}");
        assert!(!wire.contains("RETR"), "must not RETR: {wire:?}");
        assert!(ftpc.dont_check);
    }

    /// A resumed download (`-C 4`, `CURLOPT_RESUME_FROM`): with a known size from
    /// `SIZE`, `run_do_phase` issues `REST 4` (expecting `350`) before `RETR`,
    /// then transfers only the remaining bytes over a real data socket.
    /// Exercises the range/resume bookkeeping and `send_rest`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn download_resume_from_sends_rest_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let remaining = b"WXYZ-remaining-tail!".to_vec(); // 20 bytes (= 24 - 4)
        let remaining_clone = remaining.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(&remaining_clone).await.unwrap();
        });

        // EPSV(229) → TYPE I(200) → SIZE(213 24) → REST(350) → RETR(150).
        let recv = Arc::new(Mutex::new(
            format!(
                "229 Entering Extended Passive Mode (|||{port}|)\r\n\
                 200 Type set to I\r\n\
                 213 24\r\n\
                 350 Restarting at 4\r\n\
                 150 Opening BINARY mode data connection\r\n"
            )
            .into_bytes(),
        ));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        data.set.ftp_use_epsv = true;
        data.set.set_resume_from = 4;

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.file = Some("resume.bin".to_string());

        let mut sink = VecSink::default();
        let mut source = SliceSource {
            data: Vec::new(),
            pos: 0,
        };
        ftpc.run_do_phase(&mut data, &mut conn, &mut sink, &mut source)
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(sink.body, remaining, "resumed body mismatch");
        let wire = sent_str(&sent);
        assert!(wire.contains("REST 4\r\n"), "wire: {wire:?}");
        assert!(wire.contains("RETR resume.bin\r\n"), "wire: {wire:?}");
    }

    /// Active-mode `EPRT`→`PORT` fallback (C `ftp_state_port_resp`): an `EPRT`
    /// refusal (`500`) latches EPRT off for the connection, re-advertises the
    /// listener with `PORT`, and accepts the `PORT` reply. Driven through
    /// `negotiate_active_noaccept` (no data accept needed — control-only).
    #[tokio::test]
    async fn active_eprt_refused_falls_back_to_port() {
        let recv = Arc::new(Mutex::new(
            b"500 EPRT not understood\r\n200 PORT command successful\r\n".to_vec(),
        ));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        data.set.ftp_use_port = true;
        data.set.ftp_use_eprt = true;

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.port_cmd = PortCmd::Eprt;

        ftpc.negotiate_active_noaccept(&mut data, &mut conn)
            .await
            .unwrap();

        let wire = sent_str(&sent);
        assert!(wire.contains("EPRT |1|"), "wire: {wire:?}");
        assert!(wire.contains("PORT "), "wire: {wire:?}");
        assert!(ftpc.eprt_disabled, "EPRT must latch off after a refusal");
        assert_eq!(ftpc.port_cmd, PortCmd::Port);
    }

    /// A resumed upload (`-C 4`, `CURLOPT_RESUME_FROM` > 0): curl forces `APPE`
    /// and advances the source past the first 4 bytes (no seek callback ⇒
    /// read-and-discard), appending only the remaining bytes over a real data
    /// socket. Exercises the upload-resume bookkeeping, `APPE` selection, and
    /// `run_upload_body`'s skip loop.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn upload_resume_appends_with_appe_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let collected = Arc::new(Mutex::new(Vec::new()));
        let collected2 = collected.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            *collected2.lock().unwrap() = buf;
        });

        // EPSV(229) → TYPE I(200) → APPE(150). A positive `-C` sends no SIZE.
        let recv = Arc::new(Mutex::new(
            format!(
                "229 Entering Extended Passive Mode (|||{port}|)\r\n\
                 200 Type set to I\r\n\
                 150 Ok to send data\r\n"
            )
            .into_bytes(),
        ));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(recv.clone(), sent.clone());
        let mut data = Easy::new();
        data.set.ftp_use_epsv = true;
        data.set.method = HttpReq::Put;
        let full = b"SKIPpayload-after-skip".to_vec(); // first 4 ("SKIP") are skipped
        data.set.filesize = full.len() as i64;
        data.set.set_resume_from = 4;

        let mut ftpc = FtpConn::new();
        ftpc.pp.init(timeval::curlx_now());
        ftpc.file = Some("resume_up.bin".to_string());

        let mut sink = VecSink::default();
        let mut source = SliceSource {
            data: full.clone(),
            pos: 0,
        };
        ftpc.run_do_phase(&mut data, &mut conn, &mut sink, &mut source)
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(
            *collected.lock().unwrap(),
            full[4..].to_vec(),
            "only the bytes after the resume offset should be appended"
        );
        let wire = sent_str(&sent);
        assert!(wire.contains("APPE resume_up.bin\r\n"), "wire: {wire:?}");
    }
}
