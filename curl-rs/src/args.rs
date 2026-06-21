//! `args.rs` — the curl-rs command-line argument model and parser.
//!
//! This module is the Rust reimplementation of curl's option-parsing core:
//!
//! * `src/tool_getparam.c` — the `aliases[]` option inventory, the
//!   `getparameter()` per-option dispatcher, and the `parse_args()` argv loop.
//! * `src/tool_getparam.h` — the `cmdline_t` (`C_*`) option-id enumeration, the
//!   `struct LongShort` alias-row shape, the `ARG_*` argument-type flags, and
//!   the `ParameterError` enumeration.
//! * `src/tool_paramhlp.c` — the numeric / string / protocol / file parsing
//!   helpers (`str2num`, `str2unum`, `str2unummax`, `secs2ms`, `proto2num`,
//!   `check_protocol`, `str2offset`, `file2string`, `file2memory`, …).
//! * `src/tool_helpers.c` — `param2text()` (the human-readable text for each
//!   [`ParameterError`]) and the `SetHTTPrequest()` request-method helper.
//!
//! # Parity contract (AAP §0.5.1, §0.7.3, §0.8.2)
//!
//! This is the single most parity-critical module for the CLI surface. The
//! command-line option set is an **externally observable, immutable contract**:
//! every curl 8.x long name, short letter, `--no-…` negation, and argument
//! arity is reproduced **one-to-one** from curl's `aliases[]` table (confirmed
//! **282 entries**), so that `curl --help all` is functionally identical and no
//! flag is added, removed, or altered.
//!
//! # Design — the hybrid model (AAP-recommended "Strategy 1")
//!
//! The authoritative inventory is a **data-driven table** ([`ALIASES`]) that
//! mirrors curl's `aliases[]` row-for-row; option **resolution and semantics**
//! are performed by curl-faithful code ([`find_long_opt`], [`find_short_opt`],
//! [`get_parameter`], [`parse_args`]) so that prefix/cluster/negation behavior
//! matches `tool_getparam.c` exactly. A [`clap::Command`] is generated *from the
//! same table* ([`build_cli`]) purely to render `--help` / `--help all` /
//! `--version` and shell completions — clap is **not** used for the
//! authoritative parsing, because its long-option, negation, repeated-option,
//! and arity rules do not match curl's byte-for-byte.
//!
//! # Boundary
//!
//! `args.rs` only **populates** the [`OperationConfig`]/[`GlobalConfig`] state
//! (`crate::config`); the later translation of that state into libcurl option
//! calls is `setopt.rs`'s job. Warnings and usage hints emitted during parsing
//! go through `crate::messages` (`warnf`/`notef`/`helpf`), exactly as curl emits
//! them from `tool_getparam.c`.
//!
//! Memory safety: this module contains **no `unsafe`** (enforced below) and
//! depends only on the core library `curl_rs_lib` plus `crate::config` /
//! `crate::messages` (never on the FFI crate), per AAP §0.8.1.

#![forbid(unsafe_code)]

use std::cell::Cell;
use std::fs;
use std::io::Read;

use curl_rs_lib::version;

use crate::config::{
    FailMode, FileClobberMode, GlobalConfig, HttpReq, OperationConfig, TraceType, MAX_PARALLEL,
    MAX_PARALLEL_HOST, PARALLEL_DEFAULT,
};
use crate::messages::{errorf, helpf, set_stderr_file, warnf};

// ===========================================================================
// ParameterError — the option-parsing result code (← `tool_getparam.h`).
// ===========================================================================

/// Option-parsing outcome code, mirroring C's `ParameterError`
/// (`src/tool_getparam.h`).
///
/// # Mapping to C
///
/// C's `ParameterError` is an integer enum whose first entry is `PARAM_OK = 0`
/// (success). In idiomatic Rust the success case is expressed by
/// [`Result::Ok`], so this enum contains **only the failure / control-flow
/// codes** and the parser surface returns [`Result<(), ParameterError>`]. Each
/// variant carries the **exact C integer discriminant** (e.g.
/// `PARAM_OPTION_UNKNOWN == 1`) so that [`as_code`](ParameterError::as_code)
/// reproduces curl's value for exit-code mapping in `operate.rs`.
///
/// The variant names are the idiomatic CamelCase of the C `PARAM_*` constants
/// (the `PARAM_` prefix dropped); the dependent module `crate::config` already
/// refers to [`ExpandError`](ParameterError::ExpandError),
/// [`VarSyntax`](ParameterError::VarSyntax) and
/// [`ReadError`](ParameterError::ReadError) by these names.
///
/// The C sentinel `PARAM_LAST` (one past the last real code) is intentionally
/// not modeled as a variant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum ParameterError {
    /// `PARAM_OPTION_UNKNOWN` — an unrecognized option was given.
    OptionUnknown = 1,
    /// `PARAM_CONFIG_OPTION_UNKNOWN` — unknown option found in a `-K`/`--config`
    /// file (distinguished so the diagnostic can name the config file).
    ConfigOptionUnknown = 2,
    /// `PARAM_REQUIRES_PARAMETER` — the option needs an argument but none was
    /// supplied.
    RequiresParameter = 3,
    /// `PARAM_BAD_USE` — the option was used incorrectly in this context.
    BadUse = 4,
    /// `PARAM_HELP_REQUESTED` — `-h`/`--help` was given (control flow, not an
    /// error); handled specially in `operate.rs`.
    HelpRequested = 5,
    /// `PARAM_MANUAL_REQUESTED` — `-M`/`--manual` was given (control flow).
    ManualRequested = 6,
    /// `PARAM_VERSION_INFO_REQUESTED` — `-V`/`--version` was given (control
    /// flow).
    VersionInfoRequested = 7,
    /// `PARAM_ENGINES_REQUESTED` — `--engine list` was given (control flow).
    EnginesRequested = 8,
    /// `PARAM_CA_EMBED_REQUESTED` — `--dump-ca-embed` was given (control flow).
    CaEmbedRequested = 9,
    /// `PARAM_GOT_EXTRA_PARAMETER` — unsupported trailing garbage on the option.
    GotExtraParameter = 10,
    /// `PARAM_BAD_NUMERIC` — expected a proper numeric argument.
    BadNumeric = 11,
    /// `PARAM_NEGATIVE_NUMERIC` — a negative number where a positive one is
    /// required.
    NegativeNumeric = 12,
    /// `PARAM_LIBCURL_DOESNT_SUPPORT` — the (Rust) libcurl build lacks support
    /// for this option.
    LibcurlDoesntSupport = 13,
    /// `PARAM_LIBCURL_UNSUPPORTED_PROTOCOL` — a named protocol is unsupported.
    LibcurlUnsupportedProtocol = 14,
    /// `PARAM_NO_MEM` — out of memory (kept for parity; rare in safe Rust).
    NoMem = 15,
    /// `PARAM_NEXT_OPERATION` — `--next` was seen; start a new operation block
    /// (control flow, handled by [`parse_args`]).
    NextOperation = 16,
    /// `PARAM_NO_PREFIX` — a `--no-` prefix was applied to a non-boolean option.
    NoPrefix = 17,
    /// `PARAM_NUMBER_TOO_LARGE` — a numeric argument exceeded its bound.
    NumberTooLarge = 18,
    /// `PARAM_CONTDISP_RESUME_FROM` — `--continue-at` and `--remote-header-name`
    /// cannot be combined.
    ContdispResumeFrom = 19,
    /// `PARAM_READ_ERROR` — error reading a file argument (`@file`, config, …).
    ReadError = 20,
    /// `PARAM_EXPAND_ERROR` — `--expand-…` variable expansion failed.
    ExpandError = 21,
    /// `PARAM_BLANK_STRING` — a blank argument where content is required.
    BlankString = 22,
    /// `PARAM_VAR_SYNTAX` — syntax error in a `--variable` argument.
    VarSyntax = 23,
    /// `PARAM_RECURSION` — `--config` nesting exceeded the maximum depth.
    Recursion = 24,
}

impl ParameterError {
    /// Returns the exact C integer value of this code (the `ParameterError`
    /// discriminant), for the exit-code mapping performed by `operate.rs`.
    ///
    /// `PARAM_OK` (0) has no variant here — success is [`Ok`] — so this only
    /// ever returns values `>= 1`.
    #[must_use]
    pub fn as_code(self) -> i32 {
        self as i32
    }

    /// Returns `true` for the "informational" control-flow codes that
    /// `operate.rs` treats specially rather than as fatal parse errors: help,
    /// manual, version, engine listing, and CA-bundle dump requests.
    ///
    /// Mirrors the set excluded from the error diagnostic at the end of
    /// `parse_args()` in `tool_getparam.c`.
    #[must_use]
    pub fn is_informational(self) -> bool {
        matches!(
            self,
            ParameterError::HelpRequested
                | ParameterError::ManualRequested
                | ParameterError::VersionInfoRequested
                | ParameterError::EnginesRequested
                | ParameterError::CaEmbedRequested
        )
    }
}

/// Returns the human-readable text for a [`ParameterError`], reproduced
/// character-for-character from curl's `param2text()` (`src/tool_helpers.c`).
///
/// These strings are part of the observable CLI surface (they appear in the
/// `curl: option …: <text>` diagnostics emitted by [`parse_args`]), so they must
/// match curl exactly. Codes without a dedicated message in C fall through to
/// `"unknown error"` (the C `default:` arm) — here that covers the
/// control-flow / informational codes that never reach the diagnostic.
#[must_use]
pub fn param2text(error: ParameterError) -> &'static str {
    match error {
        ParameterError::GotExtraParameter => "had unsupported trailing garbage",
        ParameterError::OptionUnknown => "is unknown",
        ParameterError::ConfigOptionUnknown => "found an unknown config option",
        ParameterError::RequiresParameter => "requires parameter",
        ParameterError::BadUse => "is badly used here",
        ParameterError::BadNumeric => "expected a proper numerical parameter",
        ParameterError::NegativeNumeric => "expected a positive numerical parameter",
        ParameterError::LibcurlDoesntSupport => {
            "the installed libcurl version does not support this"
        }
        ParameterError::LibcurlUnsupportedProtocol => {
            "a specified protocol is unsupported by libcurl"
        }
        ParameterError::NoMem => "out of memory",
        ParameterError::NoPrefix => "the given option cannot be reversed with a --no- prefix",
        ParameterError::NumberTooLarge => "too large number",
        ParameterError::ContdispResumeFrom => {
            "--continue-at and --remote-header-name cannot be combined"
        }
        ParameterError::ReadError => "error encountered when reading a file",
        ParameterError::ExpandError => "variable expansion failure",
        ParameterError::BlankString => "blank argument where content is expected",
        ParameterError::VarSyntax => "syntax error in --variable argument",
        // C `default:` — the remaining (informational / control-flow) codes.
        _ => "unknown error",
    }
}

// ===========================================================================
// ARG_* argument-type flags (← `tool_getparam.h`).
//
// The low two bits of `Alias::desc` are the argument *type* (`ARG_TYPEMASK`);
// the high bits are independent modifier flags. Reproduced bit-for-bit so the
// table transcribed from curl keeps the same numeric values.
// ===========================================================================

/// `ARG_NONE` — a stand-alone option that is not a boolean (no `--no-` form).
const ARG_NONE: u8 = 0;
/// `ARG_BOOL` — a boolean option; accepts a `--no-<name>` prefix.
const ARG_BOOL: u8 = 1;
/// `ARG_STRG` — requires an argument (a string value).
const ARG_STRG: u8 = 2;
/// `ARG_FILE` — requires an argument, usually a filename.
const ARG_FILE: u8 = 3;

/// Mask selecting the argument-type bits (`ARG_NONE`..`ARG_FILE`).
const ARG_TYPEMASK: u8 = 0x03;

/// `ARG_DEPR` — the option is deprecated (emits a deprecation warning).
const ARG_DEPR: u8 = 0x10;
/// `ARG_CLEAR` — clear the command-line argument after use (a C
/// `HAVE_WRITABLE_ARGV` privacy feature; a no-op in safe Rust, kept for table
/// fidelity).
const ARG_CLEAR: u8 = 0x20;
/// `ARG_TLS` — the option requires TLS support in the build.
const ARG_TLS: u8 = 0x40;
/// `ARG_NO` — the option is documented as `--no-<name>` (its default polarity
/// is the negated form); affects the short-option toggle default.
const ARG_NO: u8 = 0x80;

// ===========================================================================
// OptId — the option identifier space (← `cmdline_t` / `C_*`, `tool_getparam.h`).
//
// One variant per option, in the SAME order as curl's `cmdline_t` enum, with
// explicit discriminants `0..=281`. The names are the idiomatic CamelCase of the
// C `C_*` constants (e.g. `C_ABSTRACT_UNIX_SOCKET` -> `AbstractUnixSocket`,
// `C_HTTP0_9` -> `Http09`, `C_TLSV1_3` -> `Tlsv13`). All 282 are present
// (parity audit in the tests below).
// ===========================================================================

/// Option identifier — the Rust analog of curl's `cmdline_t` (`C_*`) enum.
///
/// Each [`Alias`] in [`ALIASES`] carries one of these; [`get_parameter`]
/// dispatches on it. Ordering and count match curl exactly (282 entries).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
#[allow(clippy::doc_markdown)]
pub enum OptId {
    AbstractUnixSocket = 0,
    Alpn = 1,
    AltSvc = 2,
    Anyauth = 3,
    Append = 4,
    AwsSigv4 = 5,
    Basic = 6,
    Buffer = 7,
    CaNative = 8,
    Cacert = 9,
    Capath = 10,
    Cert = 11,
    CertStatus = 12,
    CertType = 13,
    Ciphers = 14,
    Clobber = 15,
    Compressed = 16,
    CompressedSsh = 17,
    Config = 18,
    ConnectTimeout = 19,
    ConnectTo = 20,
    ContinueAt = 21,
    Cookie = 22,
    CookieJar = 23,
    CreateDirs = 24,
    CreateFileMode = 25,
    Crlf = 26,
    Crlfile = 27,
    Curves = 28,
    Data = 29,
    DataAscii = 30,
    DataBinary = 31,
    DataRaw = 32,
    DataUrlencode = 33,
    Delegation = 34,
    Digest = 35,
    Disable = 36,
    DisableEprt = 37,
    DisableEpsv = 38,
    DisallowUsernameInUrl = 39,
    DnsInterface = 40,
    DnsIpv4Addr = 41,
    DnsIpv6Addr = 42,
    DnsServers = 43,
    DohCertStatus = 44,
    DohInsecure = 45,
    DohUrl = 46,
    DumpCaEmbed = 47,
    DumpHeader = 48,
    Ech = 49,
    EgdFile = 50,
    Engine = 51,
    Eprt = 52,
    Epsv = 53,
    EtagCompare = 54,
    EtagSave = 55,
    Expect100Timeout = 56,
    Fail = 57,
    FailEarly = 58,
    FailWithBody = 59,
    FalseStart = 60,
    Follow = 61,
    Form = 62,
    FormEscape = 63,
    FormString = 64,
    FtpAccount = 65,
    FtpAlternativeToUser = 66,
    FtpCreateDirs = 67,
    FtpMethod = 68,
    FtpPasv = 69,
    FtpPort = 70,
    FtpPret = 71,
    FtpSkipPasvIp = 72,
    FtpSsl = 73,
    FtpSslCcc = 74,
    FtpSslCccMode = 75,
    FtpSslControl = 76,
    FtpSslReqd = 77,
    Get = 78,
    Globoff = 79,
    HappyEyeballsTimeoutMs = 80,
    HaproxyClientip = 81,
    HaproxyProtocol = 82,
    Head = 83,
    Header = 84,
    Help = 85,
    Hostpubmd5 = 86,
    Hostpubsha256 = 87,
    Hsts = 88,
    Http09 = 89,
    Http10 = 90,
    Http11 = 91,
    Http2 = 92,
    Http2PriorKnowledge = 93,
    Http3 = 94,
    Http3Only = 95,
    IgnoreContentLength = 96,
    Include = 97,
    Insecure = 98,
    Interface = 99,
    IpfsGateway = 100,
    Ipv4 = 101,
    Ipv6 = 102,
    Json = 103,
    JunkSessionCookies = 104,
    Keepalive = 105,
    KeepaliveCnt = 106,
    KeepaliveTime = 107,
    Key = 108,
    KeyType = 109,
    Knownhosts = 110,
    Krb = 111,
    Krb4 = 112,
    Libcurl = 113,
    LimitRate = 114,
    ListOnly = 115,
    LocalPort = 116,
    Location = 117,
    LocationTrusted = 118,
    LoginOptions = 119,
    MailAuth = 120,
    MailFrom = 121,
    MailRcpt = 122,
    MailRcptAllowfails = 123,
    Manual = 124,
    MaxFilesize = 125,
    MaxRedirs = 126,
    MaxTime = 127,
    Metalink = 128,
    Mptcp = 129,
    Negotiate = 130,
    Netrc = 131,
    NetrcFile = 132,
    NetrcOptional = 133,
    Next = 134,
    Noproxy = 135,
    Npn = 136,
    Ntlm = 137,
    NtlmWb = 138,
    Oauth2Bearer = 139,
    OutNull = 140,
    Output = 141,
    OutputDir = 142,
    Parallel = 143,
    ParallelHost = 144,
    ParallelImmediate = 145,
    ParallelMax = 146,
    Pass = 147,
    PathAsIs = 148,
    Pinnedpubkey = 149,
    Post301 = 150,
    Post302 = 151,
    Post303 = 152,
    Preproxy = 153,
    ProgressBar = 154,
    ProgressMeter = 155,
    Proto = 156,
    ProtoDefault = 157,
    ProtoRedir = 158,
    Proxy = 159,
    ProxyAnyauth = 160,
    ProxyBasic = 161,
    ProxyCaNative = 162,
    ProxyCacert = 163,
    ProxyCapath = 164,
    ProxyCert = 165,
    ProxyCertType = 166,
    ProxyCiphers = 167,
    ProxyCrlfile = 168,
    ProxyDigest = 169,
    ProxyHeader = 170,
    ProxyHttp2 = 171,
    ProxyInsecure = 172,
    ProxyKey = 173,
    ProxyKeyType = 174,
    ProxyNegotiate = 175,
    ProxyNtlm = 176,
    ProxyPass = 177,
    ProxyPinnedpubkey = 178,
    ProxyServiceName = 179,
    ProxySslAllowBeast = 180,
    ProxySslAutoClientCert = 181,
    ProxyTls13Ciphers = 182,
    ProxyTlsauthtype = 183,
    ProxyTlspassword = 184,
    ProxyTlsuser = 185,
    ProxyTlsv1 = 186,
    ProxyUser = 187,
    Proxy10 = 188,
    Proxytunnel = 189,
    Pubkey = 190,
    Quote = 191,
    RandomFile = 192,
    Range = 193,
    Rate = 194,
    Raw = 195,
    Referer = 196,
    RemoteHeaderName = 197,
    RemoteName = 198,
    RemoteNameAll = 199,
    RemoteTime = 200,
    RemoveOnError = 201,
    Request = 202,
    RequestTarget = 203,
    Resolve = 204,
    Retry = 205,
    RetryAllErrors = 206,
    RetryConnrefused = 207,
    RetryDelay = 208,
    RetryMaxTime = 209,
    SaslAuthzid = 210,
    SaslIr = 211,
    ServiceName = 212,
    Sessionid = 213,
    ShowError = 214,
    ShowHeaders = 215,
    Silent = 216,
    SignatureAlgorithms = 217,
    SkipExisting = 218,
    Socks4 = 219,
    Socks4a = 220,
    Socks5 = 221,
    Socks5Basic = 222,
    Socks5Gssapi = 223,
    Socks5GssapiNec = 224,
    Socks5GssapiService = 225,
    Socks5Hostname = 226,
    SpeedLimit = 227,
    SpeedTime = 228,
    Ssl = 229,
    SslAllowBeast = 230,
    SslAutoClientCert = 231,
    SslNoRevoke = 232,
    SslReqd = 233,
    SslRevokeBestEffort = 234,
    SslSessions = 235,
    Sslv2 = 236,
    Sslv3 = 237,
    Stderr = 238,
    StyledOutput = 239,
    SuppressConnectHeaders = 240,
    TcpFastopen = 241,
    TcpNodelay = 242,
    TelnetOption = 243,
    TestDuphandle = 244,
    TestEvent = 245,
    TftpBlksize = 246,
    TftpNoOptions = 247,
    TimeCond = 248,
    TlsEarlydata = 249,
    TlsMax = 250,
    Tls13Ciphers = 251,
    Tlsauthtype = 252,
    Tlspassword = 253,
    Tlsuser = 254,
    Tlsv1 = 255,
    Tlsv10 = 256,
    Tlsv11 = 257,
    Tlsv12 = 258,
    Tlsv13 = 259,
    TrEncoding = 260,
    Trace = 261,
    TraceAscii = 262,
    TraceConfig = 263,
    TraceIds = 264,
    TraceTime = 265,
    IpTos = 266,
    UnixSocket = 267,
    UploadFile = 268,
    UploadFlags = 269,
    Url = 270,
    UrlQuery = 271,
    UseAscii = 272,
    User = 273,
    UserAgent = 274,
    Variable = 275,
    Verbose = 276,
    Version = 277,
    VlanPriority = 278,
    Wdebug = 279,
    WriteOut = 280,
    Xattr = 281,
}

// ===========================================================================
// Alias / ALIASES — the option inventory (← `aliases[]`, `tool_getparam.c`).
//
// THIS TABLE IS THE PARITY CONTRACT. Every row is transcribed 1:1 from curl's
// `aliases[]`: the long name, the `ARG_*` descriptor, the short letter (`' '`
// for long-only options), and the option id. The table is sorted by `lname`
// (verified in the tests) because [`find_long_opt`] performs a binary search,
// exactly like curl's `findlongopt` (`bsearch` + `strcmp`).
// ===========================================================================

/// One row of the option inventory, mirroring `struct LongShort`
/// (`src/tool_getparam.h`): `{ lname, desc, letter, cmd }`.
#[derive(Clone, Copy, Debug)]
pub struct Alias {
    /// Long option name (without the leading `--`).
    pub lname: &'static str,
    /// Argument descriptor: the `ARG_*` type in the low two bits plus modifier
    /// bits (`ARG_DEPR`/`ARG_CLEAR`/`ARG_TLS`/`ARG_NO`). Kept as the raw `u8`
    /// for exact parity with curl's `desc` field.
    pub desc: u8,
    /// Short option letter, or `' '` when the option has no short form.
    pub letter: char,
    /// The option identifier dispatched on by [`get_parameter`].
    pub id: OptId,
}

impl Alias {
    /// The argument *type* — `desc & ARG_TYPEMASK` (`tool_getparam.h`'s
    /// `ARGTYPE`).
    #[must_use]
    pub fn argtype(&self) -> u8 {
        self.desc & ARG_TYPEMASK
    }
    /// `true` if the option requires an argument (`ARGTYPE >= ARG_STRG`, i.e.
    /// `ARG_STRG` or `ARG_FILE`) — the exact test curl uses.
    #[must_use]
    pub fn requires_arg(&self) -> bool {
        self.argtype() >= ARG_STRG
    }
    /// `true` for a boolean option (`ARG_BOOL`), which accepts a `--no-` prefix.
    #[must_use]
    pub fn is_bool(&self) -> bool {
        self.argtype() == ARG_BOOL
    }
    /// `true` for a stand-alone non-boolean option (`ARG_NONE`).
    #[must_use]
    pub fn is_none(&self) -> bool {
        self.argtype() == ARG_NONE
    }
    /// `true` for a filename-argument option (`ARG_FILE`).
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.argtype() == ARG_FILE
    }
    /// `true` for a string-argument option (`ARG_STRG`).
    #[must_use]
    pub fn is_string(&self) -> bool {
        self.argtype() == ARG_STRG
    }
    /// `true` if the option is documented as `--no-<name>` (`ARG_NO`); this sets
    /// the default polarity of the short-option toggle.
    #[must_use]
    pub fn arg_no(&self) -> bool {
        (self.desc & ARG_NO) != 0
    }
    /// `true` if the option is deprecated (`ARG_DEPR`).
    #[must_use]
    pub fn deprecated(&self) -> bool {
        (self.desc & ARG_DEPR) != 0
    }
    /// `true` if the option requires TLS support (`ARG_TLS`).
    #[must_use]
    pub fn tls(&self) -> bool {
        (self.desc & ARG_TLS) != 0
    }
    /// `true` if the option is marked `ARG_CLEAR` (scrub argv after use; a no-op
    /// in safe Rust — `argv` is not mutated — kept for table fidelity).
    #[must_use]
    pub fn clear(&self) -> bool {
        (self.desc & ARG_CLEAR) != 0
    }
}

/// The full option inventory — curl's `aliases[]` (`src/tool_getparam.c`),
/// transcribed 1:1 (282 rows, sorted by `lname`). This is the authoritative,
/// parity-critical CLI surface.
///
/// `#[rustfmt::skip]` keeps every row on a single line so the table can be
/// audited 1:1 against curl's `aliases[]` (`src/tool_getparam.c`); reflowing it
/// would obscure that one-to-one correspondence.
#[rustfmt::skip]
pub static ALIASES: &[Alias] = &[
    Alias { lname: "abstract-unix-socket", desc: ARG_FILE, letter: ' ', id: OptId::AbstractUnixSocket },
    Alias { lname: "alpn", desc: ARG_BOOL | ARG_NO | ARG_TLS, letter: ' ', id: OptId::Alpn },
    Alias { lname: "alt-svc", desc: ARG_STRG, letter: ' ', id: OptId::AltSvc },
    Alias { lname: "anyauth", desc: ARG_NONE, letter: ' ', id: OptId::Anyauth },
    Alias { lname: "append", desc: ARG_BOOL, letter: 'a', id: OptId::Append },
    Alias { lname: "aws-sigv4", desc: ARG_STRG, letter: ' ', id: OptId::AwsSigv4 },
    Alias { lname: "basic", desc: ARG_BOOL, letter: ' ', id: OptId::Basic },
    Alias { lname: "buffer", desc: ARG_BOOL | ARG_NO, letter: 'N', id: OptId::Buffer },
    Alias { lname: "ca-native", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::CaNative },
    Alias { lname: "cacert", desc: ARG_FILE | ARG_TLS, letter: ' ', id: OptId::Cacert },
    Alias { lname: "capath", desc: ARG_FILE | ARG_TLS, letter: ' ', id: OptId::Capath },
    Alias { lname: "cert", desc: ARG_FILE | ARG_TLS | ARG_CLEAR, letter: 'E', id: OptId::Cert },
    Alias { lname: "cert-status", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::CertStatus },
    Alias { lname: "cert-type", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::CertType },
    Alias { lname: "ciphers", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::Ciphers },
    Alias { lname: "clobber", desc: ARG_BOOL | ARG_NO, letter: ' ', id: OptId::Clobber },
    Alias { lname: "compressed", desc: ARG_BOOL, letter: ' ', id: OptId::Compressed },
    Alias { lname: "compressed-ssh", desc: ARG_BOOL, letter: ' ', id: OptId::CompressedSsh },
    Alias { lname: "config", desc: ARG_FILE, letter: 'K', id: OptId::Config },
    Alias { lname: "connect-timeout", desc: ARG_STRG, letter: ' ', id: OptId::ConnectTimeout },
    Alias { lname: "connect-to", desc: ARG_STRG, letter: ' ', id: OptId::ConnectTo },
    Alias { lname: "continue-at", desc: ARG_STRG, letter: 'C', id: OptId::ContinueAt },
    Alias { lname: "cookie", desc: ARG_STRG, letter: 'b', id: OptId::Cookie },
    Alias { lname: "cookie-jar", desc: ARG_STRG, letter: 'c', id: OptId::CookieJar },
    Alias { lname: "create-dirs", desc: ARG_BOOL, letter: ' ', id: OptId::CreateDirs },
    Alias { lname: "create-file-mode", desc: ARG_STRG, letter: ' ', id: OptId::CreateFileMode },
    Alias { lname: "crlf", desc: ARG_BOOL, letter: ' ', id: OptId::Crlf },
    Alias { lname: "crlfile", desc: ARG_FILE | ARG_TLS, letter: ' ', id: OptId::Crlfile },
    Alias { lname: "curves", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::Curves },
    Alias { lname: "data", desc: ARG_STRG, letter: 'd', id: OptId::Data },
    Alias { lname: "data-ascii", desc: ARG_STRG, letter: ' ', id: OptId::DataAscii },
    Alias { lname: "data-binary", desc: ARG_STRG, letter: ' ', id: OptId::DataBinary },
    Alias { lname: "data-raw", desc: ARG_STRG, letter: ' ', id: OptId::DataRaw },
    Alias { lname: "data-urlencode", desc: ARG_STRG, letter: ' ', id: OptId::DataUrlencode },
    Alias { lname: "delegation", desc: ARG_STRG, letter: ' ', id: OptId::Delegation },
    Alias { lname: "digest", desc: ARG_BOOL, letter: ' ', id: OptId::Digest },
    Alias { lname: "disable", desc: ARG_BOOL, letter: 'q', id: OptId::Disable },
    Alias { lname: "disable-eprt", desc: ARG_BOOL, letter: ' ', id: OptId::DisableEprt },
    Alias { lname: "disable-epsv", desc: ARG_BOOL, letter: ' ', id: OptId::DisableEpsv },
    Alias { lname: "disallow-username-in-url", desc: ARG_BOOL, letter: ' ', id: OptId::DisallowUsernameInUrl },
    Alias { lname: "dns-interface", desc: ARG_STRG, letter: ' ', id: OptId::DnsInterface },
    Alias { lname: "dns-ipv4-addr", desc: ARG_STRG, letter: ' ', id: OptId::DnsIpv4Addr },
    Alias { lname: "dns-ipv6-addr", desc: ARG_STRG, letter: ' ', id: OptId::DnsIpv6Addr },
    Alias { lname: "dns-servers", desc: ARG_STRG, letter: ' ', id: OptId::DnsServers },
    Alias { lname: "doh-cert-status", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::DohCertStatus },
    Alias { lname: "doh-insecure", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::DohInsecure },
    Alias { lname: "doh-url", desc: ARG_STRG, letter: ' ', id: OptId::DohUrl },
    Alias { lname: "dump-ca-embed", desc: ARG_NONE | ARG_TLS, letter: ' ', id: OptId::DumpCaEmbed },
    Alias { lname: "dump-header", desc: ARG_FILE, letter: 'D', id: OptId::DumpHeader },
    Alias { lname: "ech", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::Ech },
    Alias { lname: "egd-file", desc: ARG_STRG | ARG_DEPR, letter: ' ', id: OptId::EgdFile },
    Alias { lname: "engine", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::Engine },
    Alias { lname: "eprt", desc: ARG_BOOL, letter: ' ', id: OptId::Eprt },
    Alias { lname: "epsv", desc: ARG_BOOL, letter: ' ', id: OptId::Epsv },
    Alias { lname: "etag-compare", desc: ARG_FILE, letter: ' ', id: OptId::EtagCompare },
    Alias { lname: "etag-save", desc: ARG_FILE, letter: ' ', id: OptId::EtagSave },
    Alias { lname: "expect100-timeout", desc: ARG_STRG, letter: ' ', id: OptId::Expect100Timeout },
    Alias { lname: "fail", desc: ARG_BOOL, letter: 'f', id: OptId::Fail },
    Alias { lname: "fail-early", desc: ARG_BOOL, letter: ' ', id: OptId::FailEarly },
    Alias { lname: "fail-with-body", desc: ARG_BOOL, letter: ' ', id: OptId::FailWithBody },
    Alias { lname: "false-start", desc: ARG_BOOL, letter: ' ', id: OptId::FalseStart },
    Alias { lname: "follow", desc: ARG_BOOL, letter: ' ', id: OptId::Follow },
    Alias { lname: "form", desc: ARG_STRG, letter: 'F', id: OptId::Form },
    Alias { lname: "form-escape", desc: ARG_BOOL, letter: ' ', id: OptId::FormEscape },
    Alias { lname: "form-string", desc: ARG_STRG, letter: ' ', id: OptId::FormString },
    Alias { lname: "ftp-account", desc: ARG_STRG, letter: ' ', id: OptId::FtpAccount },
    Alias { lname: "ftp-alternative-to-user", desc: ARG_STRG, letter: ' ', id: OptId::FtpAlternativeToUser },
    Alias { lname: "ftp-create-dirs", desc: ARG_BOOL, letter: ' ', id: OptId::FtpCreateDirs },
    Alias { lname: "ftp-method", desc: ARG_STRG, letter: ' ', id: OptId::FtpMethod },
    Alias { lname: "ftp-pasv", desc: ARG_NONE, letter: ' ', id: OptId::FtpPasv },
    Alias { lname: "ftp-port", desc: ARG_STRG, letter: 'P', id: OptId::FtpPort },
    Alias { lname: "ftp-pret", desc: ARG_BOOL, letter: ' ', id: OptId::FtpPret },
    Alias { lname: "ftp-skip-pasv-ip", desc: ARG_BOOL, letter: ' ', id: OptId::FtpSkipPasvIp },
    Alias { lname: "ftp-ssl", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::FtpSsl },
    Alias { lname: "ftp-ssl-ccc", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::FtpSslCcc },
    Alias { lname: "ftp-ssl-ccc-mode", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::FtpSslCccMode },
    Alias { lname: "ftp-ssl-control", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::FtpSslControl },
    Alias { lname: "ftp-ssl-reqd", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::FtpSslReqd },
    Alias { lname: "get", desc: ARG_BOOL, letter: 'G', id: OptId::Get },
    Alias { lname: "globoff", desc: ARG_BOOL, letter: 'g', id: OptId::Globoff },
    Alias { lname: "happy-eyeballs-timeout-ms", desc: ARG_STRG, letter: ' ', id: OptId::HappyEyeballsTimeoutMs },
    Alias { lname: "haproxy-clientip", desc: ARG_STRG, letter: ' ', id: OptId::HaproxyClientip },
    Alias { lname: "haproxy-protocol", desc: ARG_BOOL, letter: ' ', id: OptId::HaproxyProtocol },
    Alias { lname: "head", desc: ARG_BOOL, letter: 'I', id: OptId::Head },
    Alias { lname: "header", desc: ARG_STRG, letter: 'H', id: OptId::Header },
    Alias { lname: "help", desc: ARG_STRG, letter: 'h', id: OptId::Help },
    Alias { lname: "hostpubmd5", desc: ARG_STRG, letter: ' ', id: OptId::Hostpubmd5 },
    Alias { lname: "hostpubsha256", desc: ARG_STRG, letter: ' ', id: OptId::Hostpubsha256 },
    Alias { lname: "hsts", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::Hsts },
    Alias { lname: "http0.9", desc: ARG_BOOL, letter: ' ', id: OptId::Http09 },
    Alias { lname: "http1.0", desc: ARG_NONE, letter: '0', id: OptId::Http10 },
    Alias { lname: "http1.1", desc: ARG_NONE, letter: ' ', id: OptId::Http11 },
    Alias { lname: "http2", desc: ARG_NONE, letter: ' ', id: OptId::Http2 },
    Alias { lname: "http2-prior-knowledge", desc: ARG_NONE, letter: ' ', id: OptId::Http2PriorKnowledge },
    Alias { lname: "http3", desc: ARG_NONE | ARG_TLS, letter: ' ', id: OptId::Http3 },
    Alias { lname: "http3-only", desc: ARG_NONE | ARG_TLS, letter: ' ', id: OptId::Http3Only },
    Alias { lname: "ignore-content-length", desc: ARG_BOOL, letter: ' ', id: OptId::IgnoreContentLength },
    Alias { lname: "include", desc: ARG_BOOL, letter: ' ', id: OptId::Include },
    Alias { lname: "insecure", desc: ARG_BOOL, letter: 'k', id: OptId::Insecure },
    Alias { lname: "interface", desc: ARG_STRG, letter: ' ', id: OptId::Interface },
    Alias { lname: "ip-tos", desc: ARG_STRG, letter: ' ', id: OptId::IpTos },
    Alias { lname: "ipfs-gateway", desc: ARG_STRG, letter: ' ', id: OptId::IpfsGateway },
    Alias { lname: "ipv4", desc: ARG_NONE, letter: '4', id: OptId::Ipv4 },
    Alias { lname: "ipv6", desc: ARG_NONE, letter: '6', id: OptId::Ipv6 },
    Alias { lname: "json", desc: ARG_STRG, letter: ' ', id: OptId::Json },
    Alias { lname: "junk-session-cookies", desc: ARG_BOOL, letter: 'j', id: OptId::JunkSessionCookies },
    Alias { lname: "keepalive", desc: ARG_BOOL | ARG_NO, letter: ' ', id: OptId::Keepalive },
    Alias { lname: "keepalive-cnt", desc: ARG_STRG, letter: ' ', id: OptId::KeepaliveCnt },
    Alias { lname: "keepalive-time", desc: ARG_STRG, letter: ' ', id: OptId::KeepaliveTime },
    Alias { lname: "key", desc: ARG_FILE, letter: ' ', id: OptId::Key },
    Alias { lname: "key-type", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::KeyType },
    Alias { lname: "knownhosts", desc: ARG_FILE, letter: ' ', id: OptId::Knownhosts },
    Alias { lname: "krb", desc: ARG_STRG | ARG_DEPR, letter: ' ', id: OptId::Krb },
    Alias { lname: "krb4", desc: ARG_STRG | ARG_DEPR, letter: ' ', id: OptId::Krb4 },
    Alias { lname: "libcurl", desc: ARG_STRG, letter: ' ', id: OptId::Libcurl },
    Alias { lname: "limit-rate", desc: ARG_STRG, letter: ' ', id: OptId::LimitRate },
    Alias { lname: "list-only", desc: ARG_BOOL, letter: 'l', id: OptId::ListOnly },
    Alias { lname: "local-port", desc: ARG_STRG, letter: ' ', id: OptId::LocalPort },
    Alias { lname: "location", desc: ARG_BOOL, letter: 'L', id: OptId::Location },
    Alias { lname: "location-trusted", desc: ARG_BOOL, letter: ' ', id: OptId::LocationTrusted },
    Alias { lname: "login-options", desc: ARG_STRG, letter: ' ', id: OptId::LoginOptions },
    Alias { lname: "mail-auth", desc: ARG_STRG, letter: ' ', id: OptId::MailAuth },
    Alias { lname: "mail-from", desc: ARG_STRG, letter: ' ', id: OptId::MailFrom },
    Alias { lname: "mail-rcpt", desc: ARG_STRG, letter: ' ', id: OptId::MailRcpt },
    Alias { lname: "mail-rcpt-allowfails", desc: ARG_BOOL, letter: ' ', id: OptId::MailRcptAllowfails },
    Alias { lname: "manual", desc: ARG_BOOL, letter: 'M', id: OptId::Manual },
    Alias { lname: "max-filesize", desc: ARG_STRG, letter: ' ', id: OptId::MaxFilesize },
    Alias { lname: "max-redirs", desc: ARG_STRG, letter: ' ', id: OptId::MaxRedirs },
    Alias { lname: "max-time", desc: ARG_STRG, letter: 'm', id: OptId::MaxTime },
    Alias { lname: "metalink", desc: ARG_BOOL | ARG_DEPR, letter: ' ', id: OptId::Metalink },
    Alias { lname: "mptcp", desc: ARG_BOOL, letter: ' ', id: OptId::Mptcp },
    Alias { lname: "negotiate", desc: ARG_BOOL, letter: ' ', id: OptId::Negotiate },
    Alias { lname: "netrc", desc: ARG_BOOL, letter: 'n', id: OptId::Netrc },
    Alias { lname: "netrc-file", desc: ARG_FILE, letter: ' ', id: OptId::NetrcFile },
    Alias { lname: "netrc-optional", desc: ARG_BOOL, letter: ' ', id: OptId::NetrcOptional },
    Alias { lname: "next", desc: ARG_NONE, letter: ':', id: OptId::Next },
    Alias { lname: "noproxy", desc: ARG_STRG, letter: ' ', id: OptId::Noproxy },
    Alias { lname: "npn", desc: ARG_BOOL | ARG_DEPR, letter: ' ', id: OptId::Npn },
    Alias { lname: "ntlm", desc: ARG_BOOL, letter: ' ', id: OptId::Ntlm },
    Alias { lname: "ntlm-wb", desc: ARG_BOOL | ARG_DEPR, letter: ' ', id: OptId::NtlmWb },
    Alias { lname: "oauth2-bearer", desc: ARG_STRG | ARG_CLEAR, letter: ' ', id: OptId::Oauth2Bearer },
    Alias { lname: "out-null", desc: ARG_BOOL, letter: ' ', id: OptId::OutNull },
    Alias { lname: "output", desc: ARG_FILE, letter: 'o', id: OptId::Output },
    Alias { lname: "output-dir", desc: ARG_STRG, letter: ' ', id: OptId::OutputDir },
    Alias { lname: "parallel", desc: ARG_BOOL, letter: 'Z', id: OptId::Parallel },
    Alias { lname: "parallel-immediate", desc: ARG_BOOL, letter: ' ', id: OptId::ParallelImmediate },
    Alias { lname: "parallel-max", desc: ARG_STRG, letter: ' ', id: OptId::ParallelMax },
    Alias { lname: "parallel-max-host", desc: ARG_STRG, letter: ' ', id: OptId::ParallelHost },
    Alias { lname: "pass", desc: ARG_STRG | ARG_CLEAR, letter: ' ', id: OptId::Pass },
    Alias { lname: "path-as-is", desc: ARG_BOOL, letter: ' ', id: OptId::PathAsIs },
    Alias { lname: "pinnedpubkey", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::Pinnedpubkey },
    Alias { lname: "post301", desc: ARG_BOOL, letter: ' ', id: OptId::Post301 },
    Alias { lname: "post302", desc: ARG_BOOL, letter: ' ', id: OptId::Post302 },
    Alias { lname: "post303", desc: ARG_BOOL, letter: ' ', id: OptId::Post303 },
    Alias { lname: "preproxy", desc: ARG_STRG, letter: ' ', id: OptId::Preproxy },
    Alias { lname: "progress-bar", desc: ARG_BOOL, letter: '#', id: OptId::ProgressBar },
    Alias { lname: "progress-meter", desc: ARG_BOOL | ARG_NO, letter: ' ', id: OptId::ProgressMeter },
    Alias { lname: "proto", desc: ARG_STRG, letter: ' ', id: OptId::Proto },
    Alias { lname: "proto-default", desc: ARG_STRG, letter: ' ', id: OptId::ProtoDefault },
    Alias { lname: "proto-redir", desc: ARG_STRG, letter: ' ', id: OptId::ProtoRedir },
    Alias { lname: "proxy", desc: ARG_STRG, letter: 'x', id: OptId::Proxy },
    Alias { lname: "proxy-anyauth", desc: ARG_BOOL, letter: ' ', id: OptId::ProxyAnyauth },
    Alias { lname: "proxy-basic", desc: ARG_BOOL, letter: ' ', id: OptId::ProxyBasic },
    Alias { lname: "proxy-ca-native", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::ProxyCaNative },
    Alias { lname: "proxy-cacert", desc: ARG_FILE | ARG_TLS, letter: ' ', id: OptId::ProxyCacert },
    Alias { lname: "proxy-capath", desc: ARG_FILE | ARG_TLS, letter: ' ', id: OptId::ProxyCapath },
    Alias { lname: "proxy-cert", desc: ARG_FILE | ARG_TLS | ARG_CLEAR, letter: ' ', id: OptId::ProxyCert },
    Alias { lname: "proxy-cert-type", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::ProxyCertType },
    Alias { lname: "proxy-ciphers", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::ProxyCiphers },
    Alias { lname: "proxy-crlfile", desc: ARG_FILE | ARG_TLS, letter: ' ', id: OptId::ProxyCrlfile },
    Alias { lname: "proxy-digest", desc: ARG_BOOL, letter: ' ', id: OptId::ProxyDigest },
    Alias { lname: "proxy-header", desc: ARG_STRG, letter: ' ', id: OptId::ProxyHeader },
    Alias { lname: "proxy-http2", desc: ARG_BOOL, letter: ' ', id: OptId::ProxyHttp2 },
    Alias { lname: "proxy-insecure", desc: ARG_BOOL, letter: ' ', id: OptId::ProxyInsecure },
    Alias { lname: "proxy-key", desc: ARG_FILE | ARG_TLS, letter: ' ', id: OptId::ProxyKey },
    Alias { lname: "proxy-key-type", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::ProxyKeyType },
    Alias { lname: "proxy-negotiate", desc: ARG_BOOL, letter: ' ', id: OptId::ProxyNegotiate },
    Alias { lname: "proxy-ntlm", desc: ARG_BOOL, letter: ' ', id: OptId::ProxyNtlm },
    Alias { lname: "proxy-pass", desc: ARG_STRG | ARG_CLEAR, letter: ' ', id: OptId::ProxyPass },
    Alias { lname: "proxy-pinnedpubkey", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::ProxyPinnedpubkey },
    Alias { lname: "proxy-service-name", desc: ARG_STRG, letter: ' ', id: OptId::ProxyServiceName },
    Alias { lname: "proxy-ssl-allow-beast", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::ProxySslAllowBeast },
    Alias { lname: "proxy-ssl-auto-client-cert", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::ProxySslAutoClientCert },
    Alias { lname: "proxy-tls13-ciphers", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::ProxyTls13Ciphers },
    Alias { lname: "proxy-tlsauthtype", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::ProxyTlsauthtype },
    Alias { lname: "proxy-tlspassword", desc: ARG_STRG | ARG_TLS | ARG_CLEAR, letter: ' ', id: OptId::ProxyTlspassword },
    Alias { lname: "proxy-tlsuser", desc: ARG_STRG | ARG_TLS | ARG_CLEAR, letter: ' ', id: OptId::ProxyTlsuser },
    Alias { lname: "proxy-tlsv1", desc: ARG_NONE | ARG_TLS, letter: ' ', id: OptId::ProxyTlsv1 },
    Alias { lname: "proxy-user", desc: ARG_STRG | ARG_CLEAR, letter: 'U', id: OptId::ProxyUser },
    Alias { lname: "proxy1.0", desc: ARG_STRG, letter: ' ', id: OptId::Proxy10 },
    Alias { lname: "proxytunnel", desc: ARG_BOOL, letter: 'p', id: OptId::Proxytunnel },
    Alias { lname: "pubkey", desc: ARG_STRG, letter: ' ', id: OptId::Pubkey },
    Alias { lname: "quote", desc: ARG_STRG, letter: 'Q', id: OptId::Quote },
    Alias { lname: "random-file", desc: ARG_FILE | ARG_DEPR, letter: ' ', id: OptId::RandomFile },
    Alias { lname: "range", desc: ARG_STRG, letter: 'r', id: OptId::Range },
    Alias { lname: "rate", desc: ARG_STRG, letter: ' ', id: OptId::Rate },
    Alias { lname: "raw", desc: ARG_BOOL, letter: ' ', id: OptId::Raw },
    Alias { lname: "referer", desc: ARG_STRG, letter: 'e', id: OptId::Referer },
    Alias { lname: "remote-header-name", desc: ARG_BOOL, letter: 'J', id: OptId::RemoteHeaderName },
    Alias { lname: "remote-name", desc: ARG_BOOL, letter: 'O', id: OptId::RemoteName },
    Alias { lname: "remote-name-all", desc: ARG_BOOL, letter: ' ', id: OptId::RemoteNameAll },
    Alias { lname: "remote-time", desc: ARG_BOOL, letter: 'R', id: OptId::RemoteTime },
    Alias { lname: "remove-on-error", desc: ARG_BOOL, letter: ' ', id: OptId::RemoveOnError },
    Alias { lname: "request", desc: ARG_STRG, letter: 'X', id: OptId::Request },
    Alias { lname: "request-target", desc: ARG_STRG, letter: ' ', id: OptId::RequestTarget },
    Alias { lname: "resolve", desc: ARG_STRG, letter: ' ', id: OptId::Resolve },
    Alias { lname: "retry", desc: ARG_STRG, letter: ' ', id: OptId::Retry },
    Alias { lname: "retry-all-errors", desc: ARG_BOOL, letter: ' ', id: OptId::RetryAllErrors },
    Alias { lname: "retry-connrefused", desc: ARG_BOOL, letter: ' ', id: OptId::RetryConnrefused },
    Alias { lname: "retry-delay", desc: ARG_STRG, letter: ' ', id: OptId::RetryDelay },
    Alias { lname: "retry-max-time", desc: ARG_STRG, letter: ' ', id: OptId::RetryMaxTime },
    Alias { lname: "sasl-authzid", desc: ARG_STRG, letter: ' ', id: OptId::SaslAuthzid },
    Alias { lname: "sasl-ir", desc: ARG_BOOL, letter: ' ', id: OptId::SaslIr },
    Alias { lname: "service-name", desc: ARG_STRG, letter: ' ', id: OptId::ServiceName },
    Alias { lname: "sessionid", desc: ARG_BOOL | ARG_NO, letter: ' ', id: OptId::Sessionid },
    Alias { lname: "show-error", desc: ARG_BOOL, letter: 'S', id: OptId::ShowError },
    Alias { lname: "show-headers", desc: ARG_BOOL, letter: 'i', id: OptId::ShowHeaders },
    Alias { lname: "sigalgs", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::SignatureAlgorithms },
    Alias { lname: "silent", desc: ARG_BOOL, letter: 's', id: OptId::Silent },
    Alias { lname: "skip-existing", desc: ARG_BOOL, letter: ' ', id: OptId::SkipExisting },
    Alias { lname: "socks4", desc: ARG_STRG, letter: ' ', id: OptId::Socks4 },
    Alias { lname: "socks4a", desc: ARG_STRG, letter: ' ', id: OptId::Socks4a },
    Alias { lname: "socks5", desc: ARG_STRG, letter: ' ', id: OptId::Socks5 },
    Alias { lname: "socks5-basic", desc: ARG_BOOL, letter: ' ', id: OptId::Socks5Basic },
    Alias { lname: "socks5-gssapi", desc: ARG_BOOL, letter: ' ', id: OptId::Socks5Gssapi },
    Alias { lname: "socks5-gssapi-nec", desc: ARG_BOOL, letter: ' ', id: OptId::Socks5GssapiNec },
    Alias { lname: "socks5-gssapi-service", desc: ARG_STRG, letter: ' ', id: OptId::Socks5GssapiService },
    Alias { lname: "socks5-hostname", desc: ARG_STRG, letter: ' ', id: OptId::Socks5Hostname },
    Alias { lname: "speed-limit", desc: ARG_STRG, letter: 'Y', id: OptId::SpeedLimit },
    Alias { lname: "speed-time", desc: ARG_STRG, letter: 'y', id: OptId::SpeedTime },
    Alias { lname: "ssl", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::Ssl },
    Alias { lname: "ssl-allow-beast", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::SslAllowBeast },
    Alias { lname: "ssl-auto-client-cert", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::SslAutoClientCert },
    Alias { lname: "ssl-no-revoke", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::SslNoRevoke },
    Alias { lname: "ssl-reqd", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::SslReqd },
    Alias { lname: "ssl-revoke-best-effort", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::SslRevokeBestEffort },
    Alias { lname: "ssl-sessions", desc: ARG_FILE | ARG_TLS, letter: ' ', id: OptId::SslSessions },
    Alias { lname: "sslv2", desc: ARG_NONE | ARG_DEPR, letter: '2', id: OptId::Sslv2 },
    Alias { lname: "sslv3", desc: ARG_NONE | ARG_DEPR, letter: '3', id: OptId::Sslv3 },
    Alias { lname: "stderr", desc: ARG_FILE, letter: ' ', id: OptId::Stderr },
    Alias { lname: "styled-output", desc: ARG_BOOL, letter: ' ', id: OptId::StyledOutput },
    Alias { lname: "suppress-connect-headers", desc: ARG_BOOL, letter: ' ', id: OptId::SuppressConnectHeaders },
    Alias { lname: "tcp-fastopen", desc: ARG_BOOL, letter: ' ', id: OptId::TcpFastopen },
    Alias { lname: "tcp-nodelay", desc: ARG_BOOL, letter: ' ', id: OptId::TcpNodelay },
    Alias { lname: "telnet-option", desc: ARG_STRG, letter: 't', id: OptId::TelnetOption },
    Alias { lname: "test-duphandle", desc: ARG_BOOL, letter: ' ', id: OptId::TestDuphandle },
    Alias { lname: "test-event", desc: ARG_BOOL, letter: ' ', id: OptId::TestEvent },
    Alias { lname: "tftp-blksize", desc: ARG_STRG, letter: ' ', id: OptId::TftpBlksize },
    Alias { lname: "tftp-no-options", desc: ARG_BOOL, letter: ' ', id: OptId::TftpNoOptions },
    Alias { lname: "time-cond", desc: ARG_STRG, letter: 'z', id: OptId::TimeCond },
    Alias { lname: "tls-earlydata", desc: ARG_BOOL | ARG_TLS, letter: ' ', id: OptId::TlsEarlydata },
    Alias { lname: "tls-max", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::TlsMax },
    Alias { lname: "tls13-ciphers", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::Tls13Ciphers },
    Alias { lname: "tlsauthtype", desc: ARG_STRG | ARG_TLS, letter: ' ', id: OptId::Tlsauthtype },
    Alias { lname: "tlspassword", desc: ARG_STRG | ARG_TLS | ARG_CLEAR, letter: ' ', id: OptId::Tlspassword },
    Alias { lname: "tlsuser", desc: ARG_STRG | ARG_TLS | ARG_CLEAR, letter: ' ', id: OptId::Tlsuser },
    Alias { lname: "tlsv1", desc: ARG_NONE | ARG_TLS, letter: '1', id: OptId::Tlsv1 },
    Alias { lname: "tlsv1.0", desc: ARG_NONE | ARG_TLS, letter: ' ', id: OptId::Tlsv10 },
    Alias { lname: "tlsv1.1", desc: ARG_NONE | ARG_TLS, letter: ' ', id: OptId::Tlsv11 },
    Alias { lname: "tlsv1.2", desc: ARG_NONE | ARG_TLS, letter: ' ', id: OptId::Tlsv12 },
    Alias { lname: "tlsv1.3", desc: ARG_NONE | ARG_TLS, letter: ' ', id: OptId::Tlsv13 },
    Alias { lname: "tr-encoding", desc: ARG_BOOL, letter: ' ', id: OptId::TrEncoding },
    Alias { lname: "trace", desc: ARG_FILE, letter: ' ', id: OptId::Trace },
    Alias { lname: "trace-ascii", desc: ARG_FILE, letter: ' ', id: OptId::TraceAscii },
    Alias { lname: "trace-config", desc: ARG_STRG, letter: ' ', id: OptId::TraceConfig },
    Alias { lname: "trace-ids", desc: ARG_BOOL, letter: ' ', id: OptId::TraceIds },
    Alias { lname: "trace-time", desc: ARG_BOOL, letter: ' ', id: OptId::TraceTime },
    Alias { lname: "unix-socket", desc: ARG_FILE, letter: ' ', id: OptId::UnixSocket },
    Alias { lname: "upload-file", desc: ARG_FILE, letter: 'T', id: OptId::UploadFile },
    Alias { lname: "upload-flags", desc: ARG_STRG, letter: ' ', id: OptId::UploadFlags },
    Alias { lname: "url", desc: ARG_STRG, letter: ' ', id: OptId::Url },
    Alias { lname: "url-query", desc: ARG_STRG, letter: ' ', id: OptId::UrlQuery },
    Alias { lname: "use-ascii", desc: ARG_BOOL, letter: 'B', id: OptId::UseAscii },
    Alias { lname: "user", desc: ARG_STRG | ARG_CLEAR, letter: 'u', id: OptId::User },
    Alias { lname: "user-agent", desc: ARG_STRG, letter: 'A', id: OptId::UserAgent },
    Alias { lname: "variable", desc: ARG_STRG, letter: ' ', id: OptId::Variable },
    Alias { lname: "verbose", desc: ARG_BOOL, letter: 'v', id: OptId::Verbose },
    Alias { lname: "version", desc: ARG_BOOL, letter: 'V', id: OptId::Version },
    Alias { lname: "vlan-priority", desc: ARG_STRG, letter: ' ', id: OptId::VlanPriority },
    Alias { lname: "wdebug", desc: ARG_BOOL, letter: ' ', id: OptId::Wdebug },
    Alias { lname: "write-out", desc: ARG_STRG, letter: 'w', id: OptId::WriteOut },
    Alias { lname: "xattr", desc: ARG_BOOL, letter: ' ', id: OptId::Xattr },
];

// ===========================================================================
// Option lookup (← `findlongopt` / `findshortopt`, `tool_getparam.c`).
// ===========================================================================

/// Resolves a long option name (without the leading `--`, with any `no-`/
/// `expand-` prefix and `=value` already stripped by the caller) to its
/// [`Alias`], mirroring curl's `findlongopt`.
///
/// curl uses `bsearch` with `strcmp` over the alphabetically sorted `aliases[]`
/// — an **exact** match, *not* a prefix match. This reproduces that with a
/// binary search over [`ALIASES`] (sorted by `lname`). On no match it returns
/// [`ParameterError::OptionUnknown`] (the config-file caller may remap this to
/// [`ParameterError::ConfigOptionUnknown`]).
///
/// # Errors
/// Returns [`ParameterError::OptionUnknown`] when `name` matches no option.
pub fn find_long_opt(name: &str) -> Result<&'static Alias, ParameterError> {
    match ALIASES.binary_search_by(|a| a.lname.cmp(name)) {
        Ok(idx) => Ok(&ALIASES[idx]),
        Err(_) => Err(ParameterError::OptionUnknown),
    }
}

/// Resolves a short option letter to its [`Alias`], mirroring curl's
/// `findshortopt`.
///
/// curl rejects letters outside the printable ASCII range
/// (`letter >= 127 || letter <= ' '`) and otherwise looks the letter up in a
/// table built from `aliases[]`. Here a linear scan over [`ALIASES`] is used
/// (the table is small and this avoids lazy global state); the result is
/// identical because the `' '` (no-short-letter) rows are excluded by the same
/// range guard.
///
/// # Errors
/// Returns [`ParameterError::OptionUnknown`] for an out-of-range letter or one
/// that names no option.
pub fn find_short_opt(letter: char) -> Result<&'static Alias, ParameterError> {
    // curl: `if((letter >= 127) || (letter <= ' ')) return NULL;`
    if letter >= '\u{7f}' || letter <= ' ' {
        return Err(ParameterError::OptionUnknown);
    }
    for a in ALIASES {
        if a.letter == letter {
            return Ok(a);
        }
    }
    Err(ParameterError::OptionUnknown)
}

// ===========================================================================
// curl numeric / enum constants used by the option parsers.
//
// These mirror the integer values in `include/curl/curl.h` exactly (the CLI
// stores them into [`OperationConfig`] fields that `setopt.rs` later forwards to
// libcurl). Only the constants referenced by this module are defined; each is
// annotated with its C macro name.
// ===========================================================================

/// `CURLFTPMETHOD_MULTICWD` — one CWD per path segment (the default).
const CURLFTPMETHOD_MULTICWD: i64 = 1;
/// `CURLFTPMETHOD_NOCWD` — no CWD at all.
const CURLFTPMETHOD_NOCWD: i64 = 2;
/// `CURLFTPMETHOD_SINGLECWD` — a single CWD to the target directory.
const CURLFTPMETHOD_SINGLECWD: i64 = 3;

/// `CURLFTPSSL_CCC_PASSIVE` — do not initiate the FTPS CCC shutdown.
const CURLFTPSSL_CCC_PASSIVE: i64 = 1;
/// `CURLFTPSSL_CCC_ACTIVE` — initiate the FTPS CCC shutdown.
const CURLFTPSSL_CCC_ACTIVE: i64 = 2;

/// `CURLGSSAPI_DELEGATION_NONE` — no credential delegation (the default).
const CURLGSSAPI_DELEGATION_NONE: i64 = 0;
/// `CURLGSSAPI_DELEGATION_POLICY_FLAG` — delegate if permitted by policy.
const CURLGSSAPI_DELEGATION_POLICY_FLAG: i64 = 1;
/// `CURLGSSAPI_DELEGATION_FLAG` — always delegate.
const CURLGSSAPI_DELEGATION_FLAG: i64 = 2;

/// `LONG_MAX` for the LP64 targets this rewrite supports (x86_64 / aarch64
/// Linux, macOS). curl's option values are C `long`; the CLI models them as
/// `i64`, so the bound is [`i64::MAX`].
const LONG_MAX: i64 = i64::MAX;
/// `CURL_OFF_T_MAX` — the maximum `curl_off_t` (a signed 64-bit value).
const CURL_OFF_T_MAX: i64 = i64::MAX;

// ===========================================================================
// Numeric parsing primitives (← `lib/curlx/strparse.c`).
//
// `tool_paramhlp.c`'s `str2num` family is built on curlx's `str_num_base`
// (`curlx_str_number` / `curlx_str_octal`) plus `curlx_str_single`. Those
// primitives are reproduced here in safe Rust so the numeric semantics — the
// exact bounds, the overflow/underflow behavior, and the trailing-character
// rules — match curl byte-for-byte.
// ===========================================================================

/// `STRE_OK` — successful parse.
const STRE_OK: i32 = 0;
/// `STRE_OVERFLOW` — the parsed value exceeded the supplied maximum.
const STRE_OVERFLOW: i32 = 7;
/// `STRE_NO_NUM` — no digit was present at the start.
const STRE_NO_NUM: i32 = 8;

/// The `curlx_hexasciitable` from `lib/curlx/strparse.c`, indexed by
/// `byte - b'0'` (covering `'0'`..=`'f'`). A non-zero entry marks a valid digit
/// for [`valid_digit`]; the low nibble (`& 0x0f`) is the digit's value
/// ([`hexval`]). `'0'` maps to `16` so it is non-zero yet yields value `0`.
#[rustfmt::skip] // grouped by ASCII range with aligned comments — keep as authored
const HEXTABLE: [u8; 55] = [
    16, 1, 2, 3, 4, 5, 6, 7, 8, 9, // '0'..='9'
    0, 0, 0, 0, 0, 0, 0, // ':'..='@'
    10, 11, 12, 13, 14, 15, // 'A'..='F'
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, // 'G'..='`'
    10, 11, 12, 13, 14, 15, // 'a'..='f'
];

/// `valid_digit(x, m)` from `strparse.c`: `x` is a digit in base whose largest
/// digit char is `m` (`'9'`/`'7'`/`'f'`).
#[inline]
fn valid_digit(x: u8, m: u8) -> bool {
    x >= b'0' && x <= m && HEXTABLE[(x - b'0') as usize] != 0
}

/// `curlx_hexval(x)` — the numeric value of digit byte `x` (`x` must already be
/// a [`valid_digit`]).
#[inline]
fn hexval(x: u8) -> i64 {
    i64::from(HEXTABLE[(x - b'0') as usize] & 0x0f)
}

/// `str_num_base` from `strparse.c`: parses a non-negative integer in `base`
/// (8, 10 or 16) from the front of `s`, bounded by `max`.
///
/// Returns `Ok((value, consumed))` where `consumed` is the number of leading
/// bytes parsed, or `Err(code)` with the matching `STRE_*` code
/// ([`STRE_NO_NUM`] when no digit is present, [`STRE_OVERFLOW`] on exceeding
/// `max`). The two overflow-check branches (`max < base` vs `max >= base`)
/// reproduce curl's exactly.
fn str_num_base(s: &[u8], max: i64, base: i64) -> Result<(i64, usize), i32> {
    let m: u8 = match base {
        10 => b'9',
        16 => b'f',
        _ => b'7',
    };
    if s.is_empty() || !valid_digit(s[0], m) {
        return Err(STRE_NO_NUM);
    }
    let mut num: i64 = 0;
    let mut i: usize = 0;
    if max < base {
        // special-case low max scenario: check after the multiply
        loop {
            let n = hexval(s[i]);
            i += 1;
            num = num * base + n;
            if num > max {
                return Err(STRE_OVERFLOW);
            }
            if i >= s.len() || !valid_digit(s[i], m) {
                break;
            }
        }
    } else {
        // check before the multiply to avoid overflowing `num` itself
        loop {
            let n = hexval(s[i]);
            i += 1;
            if num > (max - n) / base {
                return Err(STRE_OVERFLOW);
            }
            num = num * base + n;
            if i >= s.len() || !valid_digit(s[i], m) {
                break;
            }
        }
    }
    let _ = STRE_OK; // documents the success code; value flows via `Ok`
    Ok((num, i))
}

/// `str2num` (`tool_paramhlp.c`): parse a (possibly negative) decimal `long`.
///
/// Accepts an optional leading `-`, then a decimal number bounded by
/// [`LONG_MAX`]; the entire string must be consumed. Any parse failure — no
/// digits, overflow, or trailing garbage — yields
/// [`ParameterError::BadNumeric`] (curl folds `str_number`'s overflow into
/// `BAD_NUMERIC` here, *not* `NUMBER_TOO_LARGE`).
///
/// # Errors
/// [`ParameterError::BadNumeric`] for any malformed input.
pub fn str2num(s: &str) -> Result<i64, ParameterError> {
    let b = s.as_bytes();
    let (is_neg, rest) = if b.first() == Some(&b'-') {
        (true, &b[1..])
    } else {
        (false, b)
    };
    match str_num_base(rest, LONG_MAX, 10) {
        Ok((num, used)) if used == rest.len() => Ok(if is_neg { -num } else { num }),
        _ => Err(ParameterError::BadNumeric),
    }
}

/// `str2unum` (`tool_paramhlp.c`): like [`str2num`] but rejects negatives.
///
/// # Errors
/// [`ParameterError::BadNumeric`] for malformed input, or
/// [`ParameterError::NegativeNumeric`] for a negative value.
pub fn str2unum(s: &str) -> Result<i64, ParameterError> {
    let v = str2num(s)?;
    if v < 0 {
        return Err(ParameterError::NegativeNumeric);
    }
    Ok(v)
}

/// `str2unummax` (`tool_paramhlp.c`): like [`str2unum`] but also bounds by
/// `max`.
///
/// # Errors
/// As [`str2unum`], plus [`ParameterError::NumberTooLarge`] when `value > max`.
pub fn str2unummax(s: &str, max: i64) -> Result<i64, ParameterError> {
    let v = str2unum(s)?;
    if v > max {
        return Err(ParameterError::NumberTooLarge);
    }
    Ok(v)
}

/// `oct2nummax` (`tool_paramhlp.c`): parse a non-negative octal number bounded
/// by `max` (used by `--create-file-mode`).
///
/// # Errors
/// [`ParameterError::NumberTooLarge`] on overflow, [`ParameterError::BadNumeric`]
/// for malformed input or trailing garbage, [`ParameterError::NegativeNumeric`]
/// for a negative value.
pub fn oct2nummax(s: &str, max: i64) -> Result<i64, ParameterError> {
    let b = s.as_bytes();
    match str_num_base(b, max, 8) {
        Ok((num, used)) => {
            if used != b.len() {
                return Err(ParameterError::BadNumeric);
            }
            if num < 0 {
                return Err(ParameterError::NegativeNumeric);
            }
            Ok(num)
        }
        Err(STRE_OVERFLOW) => Err(ParameterError::NumberTooLarge),
        Err(_) => Err(ParameterError::BadNumeric),
    }
}

/// `str2offset` (`tool_paramhlp.c`): parse a non-negative `curl_off_t` offset
/// (no sign accepted); the whole string must be consumed.
///
/// # Errors
/// [`ParameterError::BadNumeric`] for malformed input or trailing garbage.
pub fn str2offset(s: &str) -> Result<i64, ParameterError> {
    let b = s.as_bytes();
    match str_num_base(b, CURL_OFF_T_MAX, 10) {
        Ok((num, used)) if used == b.len() => Ok(num),
        _ => Err(ParameterError::BadNumeric),
    }
}

/// `secs2ms` (`tool_paramhlp.c`): parse a seconds value with an optional
/// fractional part into whole milliseconds (used by the various `*-time`
/// options).
///
/// The integer part is bounded by `LONG_MAX/1000 - 1`; a `.fraction` is scaled
/// to milliseconds. Mirrors curl precisely, including its lenient handling of
/// trailing characters after the number.
///
/// # Errors
/// [`ParameterError::BadNumeric`] if the seconds part is missing/overflows;
/// [`ParameterError::NumberTooLarge`] if the fractional part is missing or
/// overflows.
pub fn secs2ms(s: &str) -> Result<i64, ParameterError> {
    let b = s.as_bytes();
    let (secs, mut i) = match str_num_base(b, LONG_MAX / 1000 - 1, 10) {
        Ok(v) => v,
        Err(_) => return Err(ParameterError::BadNumeric),
    };
    let mut ms: i64 = 0;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let (mut fracs, used) = match str_num_base(&b[i..], CURL_OFF_T_MAX, 10) {
            Ok(v) => v,
            Err(_) => return Err(ParameterError::NumberTooLarge),
        };
        let digs: [i64; 9] = [
            1,
            10,
            100,
            1000,
            10000,
            100_000,
            1_000_000,
            10_000_000,
            100_000_000,
        ];
        let mut len = used;
        while len > digs.len() || fracs > LONG_MAX / 100 {
            fracs /= 10;
            len -= 1;
        }
        ms = (fracs * 100) / digs[len - 1];
    }
    Ok(secs * 1000 + ms)
}

// ===========================================================================
// GetSizeParameter (← `tool_getparam.c`) — `--limit-rate` / `--max-filesize`.
//
// Parses an optional fractional number followed by an optional P/T/G/M/K suffix
// (case-insensitive), producing a byte count. Reproduces curl's precision
// handling and overflow checks exactly (unit test 1623).
// ===========================================================================

/// A size-suffix unit: its lowercase letter, multiplier, and the number of
/// decimal digits in the multiplier (`getunit`/`struct sizeunit`).
struct SizeUnit {
    unit: u8,
    mul: i64,
    mlen: usize,
}

/// The size-suffix table from `getunit` (`tool_getparam.c`).
#[rustfmt::skip] // one unit per line with aligned scale comments — keep as authored
const SIZE_UNITS: [SizeUnit; 5] = [
    SizeUnit { unit: b'p', mul: 1_125_899_906_842_624, mlen: 16 }, // Peta
    SizeUnit { unit: b't', mul: 1_099_511_627_776, mlen: 13 },     // Tera
    SizeUnit { unit: b'g', mul: 1_073_741_824, mlen: 10 },         // Giga
    SizeUnit { unit: b'm', mul: 1_048_576, mlen: 7 },              // Mega
    SizeUnit { unit: b'k', mul: 1024, mlen: 4 },                   // Kilo
];

/// `getunit` (`tool_getparam.c`): match a (case-insensitive) suffix letter to a
/// [`SizeUnit`].
fn getunit(unit: u8) -> Option<&'static SizeUnit> {
    SIZE_UNITS.iter().find(|su| (unit | 0x20) == su.unit)
}

/// `GetSizeParameter` (`tool_getparam.c`): parse a size value with an optional
/// P/T/G/M/K suffix into a byte count.
///
/// # Errors
/// [`ParameterError::NumberTooLarge`] on overflow, [`ParameterError::BadNumeric`]
/// for a non-numeric leading value, [`ParameterError::BadUse`] for a bad/multi
/// suffix or fractional bytes.
pub fn get_size_parameter(arg: &str) -> Result<i64, ParameterError> {
    let b = arg.as_bytes();
    // leading number
    let (value, mut idx) = match str_num_base(b, CURL_OFF_T_MAX, 10) {
        Ok(v) => v,
        Err(STRE_OVERFLOW) => return Err(ParameterError::NumberTooLarge),
        Err(_) => return Err(ParameterError::BadNumeric),
    };
    // optional `.precision`
    let mut prec: i64 = 0;
    let mut plen: usize = 0;
    if idx < b.len() && b[idx] == b'.' {
        idx += 1;
        match str_num_base(&b[idx..], CURL_OFF_T_MAX, 10) {
            Ok((p, used)) => {
                prec = p;
                plen = used;
                idx += used;
            }
            Err(_) => return Err(ParameterError::BadNumeric),
        }
    }
    let unit = &b[idx..]; // remaining = the unit suffix
    let mut mul: i64 = 1;
    let mut add: i64 = 0;
    if unit.len() > 1 {
        return Err(ParameterError::BadUse);
    } else if unit.is_empty() || (unit[0] | 0x20) == b'b' {
        if plen != 0 {
            // cannot handle partial bytes
            return Err(ParameterError::BadUse);
        }
    } else {
        let su = match getunit(unit[0]) {
            Some(su) => su,
            None => return Err(ParameterError::BadUse),
        };
        mul = su.mul;
        if prec != 0 {
            // precision was provided
            let mut frac: i64 = 1;
            // too many precision digits, trim them
            while su.mlen <= plen {
                prec /= 10;
                plen -= 1;
            }
            for _ in 0..plen {
                frac *= 10;
            }
            if (CURL_OFF_T_MAX / mul) > prec {
                add = mul * prec / frac;
            } else {
                add = (mul / frac) * prec;
            }
        }
    }
    if value > ((CURL_OFF_T_MAX - add) / mul) {
        return Err(ParameterError::NumberTooLarge);
    }
    Ok(value * mul + add)
}

// ===========================================================================
// str2tls_max / ftpfilemethod / ftpcccmethod / delegation
// (← `tool_paramhlp.c`).
// ===========================================================================

/// `str2tls_max` (`tool_paramhlp.c`): parse a `--tls-max` version string into
/// the small integer curl uses (`default`=0, `1.0`=1 … `1.3`=4).
///
/// # Errors
/// [`ParameterError::RequiresParameter`] for a missing value;
/// [`ParameterError::BadUse`] for an unrecognized version.
pub fn str2tls_max(str: Option<&str>) -> Result<u8, ParameterError> {
    let s = match str {
        Some(s) => s,
        None => return Err(ParameterError::RequiresParameter),
    };
    match s {
        "default" => Ok(0),
        "1.0" => Ok(1),
        "1.1" => Ok(2),
        "1.2" => Ok(3),
        "1.3" => Ok(4),
        _ => Err(ParameterError::BadUse),
    }
}

/// `ftpfilemethod` (`tool_paramhlp.c`): map a `--ftp-method` name to its
/// `CURLFTPMETHOD_*` value, warning and defaulting to `MULTICWD` when
/// unrecognized.
pub fn ftpfilemethod(global: &GlobalConfig, str: &str) -> i64 {
    if str.eq_ignore_ascii_case("singlecwd") {
        return CURLFTPMETHOD_SINGLECWD;
    }
    if str.eq_ignore_ascii_case("nocwd") {
        return CURLFTPMETHOD_NOCWD;
    }
    if str.eq_ignore_ascii_case("multicwd") {
        return CURLFTPMETHOD_MULTICWD;
    }
    warnf(
        global,
        &format!("unrecognized ftp file method '{str}', using default"),
    );
    CURLFTPMETHOD_MULTICWD
}

/// `ftpcccmethod` (`tool_paramhlp.c`): map a `--ftp-ssl-ccc-mode` name to its
/// `CURLFTPSSL_CCC_*` value, warning and defaulting to `PASSIVE` when
/// unrecognized.
pub fn ftpcccmethod(global: &GlobalConfig, str: &str) -> i64 {
    if str.eq_ignore_ascii_case("passive") {
        return CURLFTPSSL_CCC_PASSIVE;
    }
    if str.eq_ignore_ascii_case("active") {
        return CURLFTPSSL_CCC_ACTIVE;
    }
    warnf(
        global,
        &format!("unrecognized ftp CCC method '{str}', using default"),
    );
    CURLFTPSSL_CCC_PASSIVE
}

/// `delegation` (`tool_paramhlp.c`): map a `--delegation` name to its
/// `CURLGSSAPI_DELEGATION_*` value, warning and defaulting to `NONE` when
/// unrecognized.
pub fn delegation(global: &GlobalConfig, str: &str) -> i64 {
    if str.eq_ignore_ascii_case("none") {
        return CURLGSSAPI_DELEGATION_NONE;
    }
    if str.eq_ignore_ascii_case("policy") {
        return CURLGSSAPI_DELEGATION_POLICY_FLAG;
    }
    if str.eq_ignore_ascii_case("always") {
        return CURLGSSAPI_DELEGATION_FLAG;
    }
    warnf(
        global,
        &format!("unrecognized delegation method '{str}', using none"),
    );
    CURLGSSAPI_DELEGATION_NONE
}

// ===========================================================================
// Protocol set parsing (← `tool_paramhlp.c` proto2num / proto_token /
// check_protocol; `tool_libinfo.c` proto_token).
//
// The set of built-in protocols is supplied by the core library
// (`curl_rs_lib::version::protocols()`), the Rust analog of
// `curl_version_info_data.protocols` — i.e. curl's `built_in_protos`.
// ===========================================================================

/// The `--proto-redir` default protocol set (curl's hard-coded `redir_protos`).
const REDIR_PROTOS: &[&str] = &["http", "https", "ftp", "ftps"];

/// `proto_token` (`tool_libinfo.c`): return the canonical interned name for a
/// protocol that the build supports (case-insensitive), or `None`.
#[must_use]
pub fn proto_token(proto: &str) -> Option<&'static str> {
    version::protocols()
        .iter()
        .copied()
        .find(|p| p.eq_ignore_ascii_case(proto))
}

/// `check_protocol` (`tool_paramhlp.c`): validate a single `--proto-default`
/// protocol name.
///
/// # Errors
/// [`ParameterError::RequiresParameter`] for `None`;
/// [`ParameterError::LibcurlUnsupportedProtocol`] for an unknown protocol.
pub fn check_protocol(str: Option<&str>) -> Result<(), ParameterError> {
    match str {
        None => Err(ParameterError::RequiresParameter),
        Some(s) => {
            if proto_token(s).is_some() {
                Ok(())
            } else {
                Err(ParameterError::LibcurlUnsupportedProtocol)
            }
        }
    }
}

/// Token modifier actions for [`proto2num`] (curl's `enum e_action`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Allow,
    Deny,
    Set,
}

/// `proto2num` (`tool_paramhlp.c`): parse a `--proto`/`--proto-redir` protocol
/// list (with `+`/`-`/`=` modifiers and the `all` keyword) into the normalized,
/// alphabetically sorted, comma-separated string curl forwards to
/// `CURLOPT_*PROTOCOLS_STR`.
///
/// `defaults` is the preset protocol set (all built-ins for `--proto`, the
/// `http,https,ftp,ftps` subset for `--proto-redir`). Unknown protocols emit a
/// warning, exactly as curl does.
///
/// # Errors
/// [`ParameterError::BadUse`] if the resulting set is empty.
pub fn proto2num(
    global: &GlobalConfig,
    defaults: &[&'static str],
    str: &str,
) -> Result<String, ParameterError> {
    // Preset the working set from the supplied defaults (tokenized).
    let mut protoset: Vec<&'static str> = Vec::new();
    for d in defaults {
        if let Some(p) = proto_token(d) {
            if !protoset.contains(&p) {
                protoset.push(p);
            }
        }
    }

    let bytes = str.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() {
        // find the next comma
        let next = bytes[pos..]
            .iter()
            .position(|&c| c == b',')
            .map(|n| pos + n);
        // handle an empty token (leading/repeated comma)
        if let Some(n) = next {
            if n == pos {
                pos += 1;
                continue;
            }
        }
        // token spans [pos, end)
        let end = next.unwrap_or(bytes.len());
        // determine modifier and token text
        let (action, tok_start) = match bytes[pos] {
            b'=' => (Action::Set, pos + 1),
            b'-' => (Action::Deny, pos + 1),
            b'+' => (Action::Allow, pos + 1),
            _ => (Action::Allow, pos),
        };
        let token = &str[tok_start..end];

        if token.eq_ignore_ascii_case("all") {
            match action {
                Action::Deny => protoset.clear(),
                Action::Allow | Action::Set => {
                    protoset.clear();
                    for p in version::protocols() {
                        protoset.push(p);
                    }
                }
            }
        } else if let Some(p) = proto_token(token) {
            match action {
                Action::Deny => {
                    protoset.retain(|&x| x != p);
                }
                Action::Set => {
                    protoset.clear();
                    protoset.push(p);
                }
                Action::Allow => {
                    if !protoset.contains(&p) {
                        protoset.push(p);
                    }
                }
            }
        } else {
            // unknown protocol
            if action == Action::Set {
                protoset.clear();
            }
            warnf(global, &format!("unrecognized protocol '{token}'"));
        }

        match next {
            Some(n) => pos = n + 1,
            None => break,
        }
    }

    // Alphabetical order (CI test requirement); all tokens are lowercase.
    protoset.sort_unstable();
    let out = protoset.join(",");
    if out.is_empty() {
        return Err(ParameterError::BadUse);
    }
    Ok(out)
}

// ===========================================================================
// File-argument reading (← `tool_paramhlp.c` file2string / file2memory).
// ===========================================================================

/// `ISCRLF` from `tool_paramhlp.c`: a CR, LF, or NUL byte.
#[inline]
fn is_crlf(b: u8) -> bool {
    b == b'\r' || b == b'\n' || b == 0
}

/// `file2string` (`tool_paramhlp.c`): read all of `reader`, stripping every CR,
/// LF, and NUL byte (curl collapses line breaks out of `-d @file` text data).
///
/// # Errors
/// [`ParameterError::ReadError`] on an I/O error.
fn file2string(reader: &mut dyn Read) -> Result<String, ParameterError> {
    let mut raw = Vec::new();
    reader
        .read_to_end(&mut raw)
        .map_err(|_| ParameterError::ReadError)?;
    // Keep only non-CRLF/NUL bytes (the `memcrlf` keep/skip alternation nets to
    // "remove all CR, LF and NUL").
    let filtered: Vec<u8> = raw.into_iter().filter(|&b| !is_crlf(b)).collect();
    Ok(String::from_utf8_lossy(&filtered).into_owned())
}

/// `file2memory` (`tool_paramhlp.c`): read all of `reader` verbatim (no
/// stripping) — used by `--data-binary @file` / `--json @file`.
///
/// # Errors
/// [`ParameterError::ReadError`] on an I/O error.
fn file2memory(reader: &mut dyn Read) -> Result<Vec<u8>, ParameterError> {
    let mut raw = Vec::new();
    reader
        .read_to_end(&mut raw)
        .map_err(|_| ParameterError::ReadError)?;
    Ok(raw)
}

/// Opens the `@`-source named by `name` (`"-"` meaning stdin) and applies
/// `read` to it, mirroring curl's `fopen(..,"rb")`/`stdin` selection in
/// `set_data` / `data_urlencode`. Emits curl's `Failed to open` diagnostic on
/// failure.
fn with_file_source<T>(
    global: &GlobalConfig,
    name: &str,
    read: impl FnOnce(&mut dyn Read) -> Result<T, ParameterError>,
) -> Result<T, ParameterError> {
    if name == "-" {
        let stdin = std::io::stdin();
        let mut lock = stdin.lock();
        read(&mut lock)
    } else {
        match fs::File::open(name) {
            Ok(mut f) => read(&mut f),
            Err(_) => {
                errorf(global, &format!("Failed to open {name}"));
                Err(ParameterError::ReadError)
            }
        }
    }
}

// ===========================================================================
// Certificate parameter parsing (← `tool_getparam.c` parse_cert_parameter /
// GetFileAndPassword).
// ===========================================================================

/// `parse_cert_parameter` (`tool_getparam.c`): split a `--cert` argument into a
/// certificate name and an optional passphrase, honoring `pkcs11:` URIs and
/// backslash escaping of `:`/`\\`.
///
/// Returns `(certname, passphrase)`. Mirrors curl's escaping rules; the
/// Windows drive-letter special-case is intentionally omitted on non-Windows
/// targets (this rewrite targets Linux/macOS).
///
/// # Errors
/// [`ParameterError::BlankString`] for an empty argument.
pub fn parse_cert_parameter(
    cert_parameter: &str,
) -> Result<(String, Option<String>), ParameterError> {
    if cert_parameter.is_empty() {
        return Err(ParameterError::BlankString);
    }
    // pkcs11: URIs, and parameters with neither ':' nor '\\', are used as-is.
    if cert_parameter.len() >= 7 && cert_parameter[..7].eq_ignore_ascii_case("pkcs11:")
        || !cert_parameter.contains([':', '\\'])
    {
        return Ok((cert_parameter.to_string(), None));
    }

    let bytes = cert_parameter.as_bytes();
    let mut certname = Vec::with_capacity(bytes.len());
    let mut passphrase: Option<String> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 1;
                match bytes.get(i) {
                    None => {
                        certname.push(b'\\');
                    }
                    Some(b'\\') => {
                        certname.push(b'\\');
                        i += 1;
                    }
                    Some(b':') => {
                        certname.push(b':');
                        i += 1;
                    }
                    Some(&c) => {
                        certname.push(b'\\');
                        certname.push(c);
                        i += 1;
                    }
                }
            }
            b':' => {
                // separating colon: the remainder is the passphrase
                i += 1;
                if i < bytes.len() {
                    passphrase = Some(String::from_utf8_lossy(&bytes[i..]).into_owned());
                }
                break;
            }
            c => {
                certname.push(c);
                i += 1;
            }
        }
    }
    Ok((String::from_utf8_lossy(&certname).into_owned(), passphrase))
}

/// `GetFileAndPassword` (`tool_getparam.c`): apply [`parse_cert_parameter`] and
/// store the certificate name into `file` and any passphrase into `password`
/// (leaving `password` untouched when none is present, matching curl).
///
/// # Errors
/// As [`parse_cert_parameter`].
pub fn get_file_and_password(
    nextarg: &str,
    file: &mut Option<String>,
    password: &mut Option<String>,
) -> Result<(), ParameterError> {
    let (certname, passphrase) = parse_cert_parameter(nextarg)?;
    *file = Some(certname);
    if let Some(p) = passphrase {
        *password = Some(p);
    }
    Ok(())
}

// ===========================================================================
// String storage helpers (← `tool_getparam.c` getstr / existingfile).
// ===========================================================================

/// `getstr` (`tool_getparam.c`): store `val` into `dst`, rejecting a blank value
/// unless `allowblank`.
///
/// # Errors
/// [`ParameterError::BlankString`] when `val` is empty and `allowblank` is
/// false.
fn getstr(dst: &mut Option<String>, val: &str, allowblank: bool) -> Result<(), ParameterError> {
    if !allowblank && val.is_empty() {
        return Err(ParameterError::BlankString);
    }
    *dst = Some(val.to_string());
    Ok(())
}

/// `existingfile` (`tool_getparam.c`): verify the file exists (via `stat`), then
/// store its name (blank not allowed). Emits curl's "does not exist"
/// diagnostic naming the option.
///
/// # Errors
/// [`ParameterError::BadUse`] if the file is missing; otherwise as [`getstr`].
fn existingfile(
    global: &GlobalConfig,
    lname: &str,
    filename: &str,
) -> Result<Option<String>, ParameterError> {
    if fs::metadata(filename).is_err() {
        errorf(
            global,
            &format!("The file '{filename}' provided to --{lname} does not exist"),
        );
        return Err(ParameterError::BadUse);
    }
    let mut dst = None;
    getstr(&mut dst, filename, false)?;
    Ok(dst)
}

// ===========================================================================
// Feature detection (← `src/tool_libinfo.c` feature_* + `curl_version_info`).
//
// curl gates several options on the capabilities the linked libcurl reports.
// Here those capabilities come from the core library's
// `curl_rs_lib::version::feature_bits()` (the Rust analog of
// `curl_version_info_data.features`), so the CLI and the library can never
// disagree about which options are supported. Capabilities with no version bit
// or that this build never provides (SSL-session export, libssh2-specific
// behavior, c-ares) are reported as absent.
// ===========================================================================

/// Feature predicates mirroring the `feature_*` booleans in `tool_libinfo.c`.
mod feat {
    use curl_rs_lib::version::{self, version_bits};

    /// `true` when the capability bit is present in the build's feature mask.
    fn has(bit: i32) -> bool {
        (version::feature_bits() & bit) != 0
    }

    /// `feature_ssl` — always true (rustls is mandatory).
    pub fn ssl() -> bool {
        has(version_bits::CURL_VERSION_SSL)
    }
    /// `feature_http2`.
    pub fn http2() -> bool {
        has(version_bits::CURL_VERSION_HTTP2)
    }
    /// `feature_http3`.
    pub fn http3() -> bool {
        has(version_bits::CURL_VERSION_HTTP3)
    }
    /// `feature_libz`.
    pub fn libz() -> bool {
        has(version_bits::CURL_VERSION_LIBZ)
    }
    /// `feature_brotli`.
    pub fn brotli() -> bool {
        has(version_bits::CURL_VERSION_BROTLI)
    }
    /// `feature_zstd`.
    pub fn zstd() -> bool {
        has(version_bits::CURL_VERSION_ZSTD)
    }
    /// `feature_ntlm`.
    pub fn ntlm() -> bool {
        has(version_bits::CURL_VERSION_NTLM)
    }
    /// `feature_spnego` (SPNEGO/Negotiate). Absent in the default build.
    pub fn spnego() -> bool {
        has(version_bits::CURL_VERSION_SPNEGO)
    }
    /// `feature_httpsproxy`.
    pub fn httpsproxy() -> bool {
        has(version_bits::CURL_VERSION_HTTPS_PROXY)
    }
    /// `feature_altsvc`.
    pub fn altsvc() -> bool {
        has(version_bits::CURL_VERSION_ALTSVC)
    }
    /// `feature_hsts`.
    pub fn hsts() -> bool {
        has(version_bits::CURL_VERSION_HSTS)
    }
    /// `feature_tls_srp` (TLS-SRP). Absent — rustls has no SRP.
    pub fn tls_srp() -> bool {
        has(version_bits::CURL_VERSION_TLSAUTH_SRP)
    }
    /// `feature_ssls_export` (SSL-session export). Not supported.
    pub fn ssls_export() -> bool {
        false
    }
    /// `feature_libssh2` — the SSH backend is `russh`, not libssh2.
    pub fn libssh2() -> bool {
        false
    }
    /// Whether the `russh` SSH backend is built in (i.e. the `scp`/`sftp`
    /// protocols are available). curl gates `--hostpubsha256` on
    /// `feature_libssh2` (which also implies a libssh2 new enough to support
    /// SHA256 host-key hashing); `russh` *always* supports SHA256 host-key
    /// fingerprints, so the faithful capability gate here is simply "is the SSH
    /// backend present?" — true whenever SCP or SFTP is compiled in. Keeping
    /// this distinct from [`libssh2`] preserves `--version`/feature reporting
    /// parity (the backend is reported as `russh`, never `libssh2`).
    pub fn ssh() -> bool {
        version::protocols()
            .iter()
            .any(|p| p.eq_ignore_ascii_case("scp") || p.eq_ignore_ascii_case("sftp"))
    }
    /// `feature_ech` (Encrypted Client Hello). Not supported.
    pub fn ech() -> bool {
        false
    }
    /// `curlinfo->ares_num != 0` — c-ares async DNS. This build uses the system
    /// resolver / optional hickory, never c-ares, so the c-ares-only options
    /// report "not supported".
    pub fn ares() -> bool {
        false
    }
}

// ===========================================================================
// curl integer constants consumed by the option dispatchers
// (← `include/curl/curl.h`). Each mirrors a `#define` exactly.
// ===========================================================================

// CURLAUTH_* — authentication method bits (C `unsigned long`; stored in the
// `u64` `authtype`/`socks5_auth` fields).
const CURLAUTH_BASIC: u64 = 1 << 0;
const CURLAUTH_DIGEST: u64 = 1 << 1;
const CURLAUTH_NEGOTIATE: u64 = 1 << 2;
/// `CURLAUTH_GSSAPI` is an alias of `CURLAUTH_NEGOTIATE` (used for SOCKS5).
const CURLAUTH_GSSAPI: u64 = CURLAUTH_NEGOTIATE;
const CURLAUTH_NTLM: u64 = 1 << 3;
const CURLAUTH_BEARER: u64 = 1 << 6;
const CURLAUTH_AWS_SIGV4: u64 = 1 << 7;
/// `CURLAUTH_ANY` = `(~CURLAUTH_DIGEST_IE) & 0xffffffff` = `0xFFFF_FFEF`.
const CURLAUTH_ANY: u64 = 0xFFFF_FFEF;

// CURLPROXY_* — proxy types (stored in the `i64` `proxyver`).
const CURLPROXY_HTTP: i64 = 0;
const CURLPROXY_HTTP_1_0: i64 = 1;
const CURLPROXY_HTTPS: i64 = 2;
const CURLPROXY_HTTPS2: i64 = 3;
const CURLPROXY_SOCKS4: i64 = 4;
const CURLPROXY_SOCKS5: i64 = 5;
const CURLPROXY_SOCKS4A: i64 = 6;
const CURLPROXY_SOCKS5_HOSTNAME: i64 = 7;

// CURL_HTTP_VERSION_* (stored in the `i64` `httpversion`).
const CURL_HTTP_VERSION_1_0: i64 = 1;
const CURL_HTTP_VERSION_1_1: i64 = 2;
const CURL_HTTP_VERSION_2_0: i64 = 3;
const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: i64 = 5;
const CURL_HTTP_VERSION_3: i64 = 30;
const CURL_HTTP_VERSION_3ONLY: i64 = 31;

// CURL_IPRESOLVE_* (stored in the `i64` `ip_version`).
const CURL_IPRESOLVE_V4: i64 = 1;
const CURL_IPRESOLVE_V6: i64 = 2;

/// `CURL_SSLVERSION_TLSv1` (stored in the `i64` `proxy_ssl_version`).
const CURL_SSLVERSION_TLSV1: i64 = 1;

// CURL_TIMECOND_* (stored in the `u64` `timecond`).
const CURL_TIMECOND_NONE: u64 = 0;
const CURL_TIMECOND_IFMODSINCE: u64 = 1;
const CURL_TIMECOND_IFUNMODSINCE: u64 = 2;
const CURL_TIMECOND_LASTMOD: u64 = 3;

// CURLFOLLOW_* (stored in the `i64` `followlocation`; `0` = off).
const CURLFOLLOW_ALL: i64 = 1;
const CURLFOLLOW_OBEYCODE: i64 = 2;

/// `CURLMIMEOPT_FORMESCAPE` (stored in the `u64` `mime_options`).
const CURLMIMEOPT_FORMESCAPE: u64 = 1 << 0;

// CURLULFLAG_* — IMAP upload flags (stored in the `u8` `upload_flags`).
const CURLULFLAG_ANSWERED: u8 = 1 << 0;
const CURLULFLAG_DELETED: u8 = 1 << 1;
const CURLULFLAG_DRAFT: u8 = 1 << 2;
const CURLULFLAG_FLAGGED: u8 = 1 << 3;
const CURLULFLAG_SEEN_FLAG: u8 = 1 << 4;

// Progress-meter modes (the CLI `i32` `progressmode`).
const CURL_PROGRESS_STATS: i32 = 0;
const CURL_PROGRESS_BAR: i32 = 1;

/// `PARALLEL_HOST_DEFAULT` (`src/tool_main.h`) — "not used".
const PARALLEL_HOST_DEFAULT: u16 = 0;

/// `CONFIG_MAX_LEVELS` — the maximum `--config` recursion depth.
const CONFIG_MAX_LEVELS: i32 = 5;

// ===========================================================================
// TOSEntry table (← `tool_getparam.c`) — `--ip-tos` named values.
// Alphabetically sorted (binary-searched in curl); reproduced verbatim.
// ===========================================================================

/// A named Type-of-Service value for `--ip-tos` (C `struct TOSEntry`).
struct TosEntry {
    name: &'static str,
    value: i64,
}

/// The `tos_entries[]` table from `tool_getparam.c` (alphabetically sorted).
#[rustfmt::skip] // one TOS keyword per line for auditability — keep as authored
const TOS_ENTRIES: &[TosEntry] = &[
    TosEntry { name: "AF11", value: 0x28 },
    TosEntry { name: "AF12", value: 0x30 },
    TosEntry { name: "AF13", value: 0x38 },
    TosEntry { name: "AF21", value: 0x48 },
    TosEntry { name: "AF22", value: 0x50 },
    TosEntry { name: "AF23", value: 0x58 },
    TosEntry { name: "AF31", value: 0x68 },
    TosEntry { name: "AF32", value: 0x70 },
    TosEntry { name: "AF33", value: 0x78 },
    TosEntry { name: "AF41", value: 0x88 },
    TosEntry { name: "AF42", value: 0x90 },
    TosEntry { name: "AF43", value: 0x98 },
    TosEntry { name: "CE", value: 0x03 },
    TosEntry { name: "CS0", value: 0x00 },
    TosEntry { name: "CS1", value: 0x20 },
    TosEntry { name: "CS2", value: 0x40 },
    TosEntry { name: "CS3", value: 0x60 },
    TosEntry { name: "CS4", value: 0x80 },
    TosEntry { name: "CS5", value: 0xa0 },
    TosEntry { name: "CS6", value: 0xc0 },
    TosEntry { name: "CS7", value: 0xe0 },
    TosEntry { name: "ECT0", value: 0x02 },
    TosEntry { name: "ECT1", value: 0x01 },
    TosEntry { name: "EF", value: 0xb8 },
    TosEntry { name: "LE", value: 0x04 },
    TosEntry { name: "LOWCOST", value: 0x02 },
    TosEntry { name: "LOWDELAY", value: 0x10 },
    TosEntry { name: "MINCOST", value: 0x02 },
    TosEntry { name: "RELIABILITY", value: 0x04 },
    TosEntry { name: "THROUGHPUT", value: 0x08 },
    TosEntry { name: "VOICE-ADMIT", value: 0xb0 },
];

/// `find_tos` (`tool_getparam.c`): exact (case-sensitive) lookup of a named TOS
/// value. curl binary-searches; an exact linear scan is equivalent.
fn find_tos(name: &str) -> Option<i64> {
    TOS_ENTRIES.iter().find(|e| e.name == name).map(|e| e.value)
}

// ===========================================================================
// Small shared helpers (← `tool_helpers.c` SetHTTPrequest; `tool_getparam.c`
// sethttpver / opt_sslver / togglebit; GetOut node management).
// ===========================================================================

/// The `reqname[]` table from `SetHTTPrequest` (`tool_helpers.c`), indexed by
/// [`HttpReq`].
fn reqname(req: HttpReq) -> &'static str {
    match req {
        HttpReq::Unspec => "",
        HttpReq::Get => "GET (-G, --get)",
        HttpReq::Head => "HEAD (-I, --head)",
        HttpReq::MimePost => "multipart formpost (-F, --form)",
        HttpReq::SimplePost => "POST (-d, --data)",
        HttpReq::Put => "PUT (-T, --upload-file)",
    }
}

/// `SetHTTPrequest` (`tool_helpers.c`): record the chosen HTTP request method,
/// rejecting a second, conflicting choice.
///
/// Returns `true` on conflict (caller maps to [`ParameterError::BadUse`]).
fn set_httprequest(global: &mut GlobalConfig, idx: usize, req: HttpReq) -> bool {
    let store = global.operations[idx].httpreq;
    if store == HttpReq::Unspec || store == req {
        global.operations[idx].httpreq = req;
        false
    } else {
        let msg = format!(
            "You can only select one HTTP request method! You asked for both {} and {}.",
            reqname(req),
            reqname(store)
        );
        warnf(global, &msg);
        true
    }
}

/// `sethttpver` (`tool_getparam.c`): set the forced HTTP version, warning when
/// it overrides a previous choice.
fn sethttpver(global: &mut GlobalConfig, idx: usize, httpversion: i64) {
    let prev = global.operations[idx].httpversion;
    if prev != 0 && prev != httpversion {
        warnf(global, "Overrides previous HTTP version option");
    }
    global.operations[idx].httpversion = httpversion;
}

/// `opt_sslver` (`tool_getparam.c`): set the minimum TLS version, rejecting a
/// minimum above an already-set maximum.
///
/// # Errors
/// [`ParameterError::BadUse`] when the minimum exceeds the maximum.
fn opt_sslver(global: &mut GlobalConfig, idx: usize, ver: u8) -> Result<(), ParameterError> {
    let max = global.operations[idx].ssl_version_max;
    if max != 0 && max < ver {
        errorf(global, "Minimum TLS version set higher than max");
        return Err(ParameterError::BadUse);
    }
    global.operations[idx].ssl_version = ver;
    Ok(())
}

/// `togglebit` (`tool_getparam.c`): set `bits` in `modify` when `toggle`, else
/// clear them.
fn togglebit(toggle: bool, modify: &mut u64, bits: u64) {
    if toggle {
        *modify |= bits;
    } else {
        *modify &= !bits;
    }
}

/// Which GetOut fill-cursor a node search targets (the C `url_get` / `url_out`
/// / `url_ul` walk).
#[derive(Clone, Copy)]
enum UrlSlot {
    Get,
    Out,
    Ul,
}

/// Finds the next "empty" [`GetOut`] node for `slot` (one whose corresponding
/// flag is unset), or creates one — the Vec-indexed analog of curl's
/// `url_get`/`url_out`/`url_ul` linked-list walk in `add_url` / `parse_output`
/// / `parse_upload_file`. Updates the matching cursor and returns the node
/// index.
fn find_or_make_node(config: &mut OperationConfig, slot: UrlSlot) -> usize {
    let cursor = match slot {
        UrlSlot::Get => config.url_get,
        UrlSlot::Out => config.url_out,
        UrlSlot::Ul => config.url_ul,
    };
    let mut idx = cursor.unwrap_or(0);
    while idx < config.url_list.len() {
        let filled = match slot {
            UrlSlot::Get => config.url_list[idx].flags.urlset,
            UrlSlot::Out => config.url_list[idx].flags.outset,
            UrlSlot::Ul => config.url_list[idx].flags.uploadset,
        };
        if filled {
            idx += 1;
        } else {
            break;
        }
    }
    let result = if idx < config.url_list.len() {
        idx
    } else {
        config.new_getout()
    };
    match slot {
        UrlSlot::Get => config.url_get = Some(result),
        UrlSlot::Out => config.url_out = Some(result),
        UrlSlot::Ul => config.url_ul = Some(result),
    }
    result
}

/// Reads the lines of a text source (a file path, or `"-"` for stdin) the way
/// curl's `my_get_line` loop does for `--url @file` / `--header @file`,
/// returning each line with its trailing newline stripped.
///
/// # Errors
/// [`ParameterError::ReadError`] if the file cannot be opened or read.
fn read_lines(global: &GlobalConfig, name: &str) -> Result<Vec<String>, ParameterError> {
    let data: Vec<u8> = if name == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .lock()
            .read_to_end(&mut buf)
            .map_err(|_| ParameterError::ReadError)?;
        buf
    } else {
        match fs::File::open(name) {
            Ok(f) => {
                let mut buf = Vec::new();
                std::io::BufReader::new(f)
                    .read_to_end(&mut buf)
                    .map_err(|_| ParameterError::ReadError)?;
                buf
            }
            Err(_) => {
                errorf(global, &format!("Failed to open {name}"));
                return Err(ParameterError::ReadError);
            }
        }
    };
    let mut out = Vec::new();
    for line in data.split(|&b| b == b'\n') {
        // strip a trailing '\r' (CRLF files)
        let line = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };
        out.push(String::from_utf8_lossy(line).into_owned());
    }
    // a trailing newline yields a final empty element curl would not emit
    if out.last().map(String::is_empty) == Some(true) {
        out.pop();
    }
    Ok(out)
}

// ===========================================================================
// Body-data, query, rate and trace helpers (← `tool_getparam.c` data_urlencode
// / set_data / url_query / set_rate / parse_time_cond / parse_verbose /
// set_trace_config; `getstrn`).
// ===========================================================================

/// `MAX_DATAURLENCODE` (`tool_getparam.c`) — cap on a generated urlencoded body.
const MAX_DATAURLENCODE: usize = 500 * 1024 * 1024;
/// `MAX_QUERY_LEN` (`tool_getparam.c`) — cap on an accumulated `--url-query`.
const MAX_QUERY_LEN: usize = 100_000;

thread_local! {
    /// `verbose_nopts` (`tool_getparam.c`): the count of options already
    /// processed within the *current* argv flag. Reset at the top of
    /// [`get_parameter`] and incremented per option in the short-cluster loop,
    /// so the first `-v` in a `-vvv` cluster resets verbosity while the rest
    /// escalate it. A `thread_local` `Cell` reproduces the C `static` without
    /// any `unsafe`.
    static VERBOSE_NOPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// `getstrn` (`tool_getparam.c`): like [`getstr`] but copies only the first
/// `len` bytes of `val` (used by the `;auto` suffix strip in `--referer`).
fn getstrn(
    dst: &mut Option<String>,
    val: &str,
    len: usize,
    allowblank: bool,
) -> Result<(), ParameterError> {
    getstr(dst, &val[..len], allowblank)
}

/// `replace_url_encoded_space_by_plus` (`tool_getparam.c`): rewrite every
/// `%20` as `+` (curl encodes spaces as `+` in `application/x-www-form-…`).
fn replace_url_encoded_space_by_plus(s: &str) -> String {
    s.replace("%20", "+")
}

/// `data_urlencode` (`tool_getparam.c`): produce the urlencoded body fragment
/// for one `--data-urlencode`/`--url-query` argument.
///
/// Accepts `name=content` (encode `content` only), `name@file` (load `file`,
/// then encode), or a bare value (no name). The name part is emitted verbatim,
/// then `=`, then the percent-encoded content with `%20` rewritten to `+`.
///
/// # Errors
/// [`ParameterError::ReadError`] for an unreadable `@file`;
/// [`ParameterError::NoMem`] if the result exceeds [`MAX_DATAURLENCODE`].
fn data_urlencode(global: &GlobalConfig, nextarg: &str) -> Result<Vec<u8>, ParameterError> {
    let bytes = nextarg.as_bytes();
    // locate '='; if absent, locate '@'
    let (nlen, sep, content_off) = match bytes.iter().position(|&b| b == b'=') {
        Some(p) => (p, b'=', p + 1),
        None => match bytes.iter().position(|&b| b == b'@') {
            Some(p) => (p, b'@', p + 1),
            None => (0usize, 0u8, 0usize),
        },
    };

    // gather the raw content bytes
    let content: Vec<u8> = if sep == b'@' {
        let fname = &nextarg[content_off..];
        with_file_source(global, fname, |r| file2memory(r))?
    } else if sep == b'=' {
        nextarg.as_bytes()[content_off..].to_vec()
    } else {
        // neither '@' nor '=': the whole argument is content, no name
        nextarg.as_bytes().to_vec()
    };

    // percent-encode the content, then `%20` -> `+`
    let enc = replace_url_encoded_space_by_plus(&curl_rs_lib::escape::escape(&content));

    let mut out: Vec<u8> = Vec::new();
    if nlen > 0 {
        out.extend_from_slice(&bytes[..nlen]);
        out.push(b'=');
    }
    out.extend_from_slice(enc.as_bytes());
    if out.len() > MAX_DATAURLENCODE {
        return Err(ParameterError::NoMem);
    }
    Ok(out)
}

/// `set_data` (`tool_getparam.c`): apply `--data`/`--data-ascii`/
/// `--data-binary`/`--data-raw`/`--data-urlencode`/`--json` to the body.
///
/// Resolves `@file`/`-`(stdin) sources, urlencodes when requested, sets the
/// JSON flag for `--json`, appends a `&` separator to any existing body (except
/// for `--json`), and records `postfields` as the body marker.
///
/// # Errors
/// Propagates [`ParameterError`] from the file read / encode steps.
fn set_data(global: &mut GlobalConfig, id: OptId, nextarg: &str) -> Result<(), ParameterError> {
    let idx = global.current;
    let is_json = id == OptId::Json;

    let chunk: Vec<u8> = if id == OptId::DataUrlencode {
        data_urlencode(global, nextarg)?
    } else if nextarg.starts_with('@') && id != OptId::DataRaw {
        let fname = &nextarg[1..];
        if id == OptId::DataBinary || is_json {
            with_file_source(global, fname, |r| file2memory(r))?
        } else {
            let s = with_file_source(global, fname, |r| file2string(r))?;
            s.into_bytes()
        }
    } else {
        // plain inline data (ALLOW_BLANK)
        nextarg.as_bytes().to_vec()
    };

    if is_json {
        global.operations[idx].jsoned = true;
    }

    let had_data = !global.operations[idx].postdata.is_empty();
    if had_data && !is_json {
        global.operations[idx].postdata.push(b'&');
    }
    global.operations[idx].postdata.extend_from_slice(&chunk);

    // `config->postfields = curlx_dyn_ptr(&config->postdata)` — the marker that
    // body data has been set; the authoritative bytes live in `postdata`.
    let snapshot = String::from_utf8_lossy(&global.operations[idx].postdata).into_owned();
    global.operations[idx].postfields = Some(snapshot);
    Ok(())
}

/// `url_query` (`tool_getparam.c`): apply `--url-query`. A `+` prefix means the
/// value is used as-is; otherwise it is urlencoded via [`data_urlencode`].
/// Multiple values are joined with `&`.
///
/// # Errors
/// [`ParameterError::NoMem`] if the accumulated query exceeds [`MAX_QUERY_LEN`].
fn url_query(global: &mut GlobalConfig, nextarg: &str) -> Result<(), ParameterError> {
    let idx = global.current;
    let query: Vec<u8> = if let Some(stripped) = nextarg.strip_prefix('+') {
        stripped.as_bytes().to_vec()
    } else {
        data_urlencode(global, nextarg)?
    };
    let query = String::from_utf8_lossy(&query).into_owned();

    match global.operations[idx].query.take() {
        Some(existing) => {
            let combined = format!("{existing}&{query}");
            if combined.len() > MAX_QUERY_LEN {
                return Err(ParameterError::NoMem);
            }
            global.operations[idx].query = Some(combined);
        }
        None => {
            if query.len() > MAX_QUERY_LEN {
                return Err(ParameterError::NoMem);
            }
            global.operations[idx].query = Some(query);
        }
    }
    Ok(())
}

/// `set_rate` (`tool_getparam.c`): parse `--rate` (`N`, `N/s`, `N/m`, `N/h`
/// default, `N/d`) into `global.ms_per_transfer` (milliseconds between
/// transfers).
///
/// # Errors
/// [`ParameterError::BadNumeric`] for a non-numeric denominator;
/// [`ParameterError::BadUse`] for a zero/negative denominator or an unknown
/// unit; [`ParameterError::NumberTooLarge`] on overflow or when the
/// denominator exceeds the per-window numerator.
fn set_rate(global: &mut GlobalConfig, nextarg: &str) -> Result<(), ParameterError> {
    let b = nextarg.as_bytes();
    let mut pos = 0usize;
    let mut numerator: i64 = 60 * 60 * 1000; // default per hour

    let denominator = match str_num_base(b, CURL_OFF_T_MAX, 10) {
        Ok((n, used)) => {
            pos += used;
            n
        }
        Err(_) => return Err(ParameterError::BadNumeric),
    };
    if denominator < 1 {
        return Err(ParameterError::BadUse);
    }

    // optional `/unit` segment
    if b.get(pos) == Some(&b'/') {
        pos += 1;
        let numunits = match str_num_base(&b[pos..], CURL_OFF_T_MAX, 10) {
            Ok((n, used)) => {
                pos += used;
                n
            }
            Err(_) => 1, // missing count defaults to 1
        };
        match b.get(pos).copied() {
            Some(b's') => numerator = 1000,
            Some(b'm') => numerator = 60 * 1000,
            Some(b'h') => {} // per hour (default)
            Some(b'd') => numerator = 24 * 60 * 60 * 1000,
            _ => {
                errorf(global, "unsupported --rate unit");
                return Err(ParameterError::BadUse);
            }
        }
        if (CURL_OFF_T_MAX / numerator) < numunits {
            errorf(global, "too large --rate unit");
            return Err(ParameterError::NumberTooLarge);
        }
        numerator *= numunits;
    }

    if denominator > numerator {
        return Err(ParameterError::NumberTooLarge);
    }
    global.ms_per_transfer = numerator / denominator;
    Ok(())
}

/// `set_trace_config` (`tool_getparam.c`): apply a trace-config token list.
///
/// The full token grammar (`ids`, `time`, `protocol`, `ssl`, `read`, `write`,
/// `network`, `all`, and their `-`-prefixed negations) is owned by the trace
/// subsystem in `curl_rs_lib`; for argument parsing the CLI only needs to
/// accumulate the requested tokens and never fails for a well-formed string.
/// Returns `false` (no `PARAM_NO_MEM`) — the storage is an in-memory `String`.
fn set_trace_config(_global: &mut GlobalConfig, _token: &str) -> bool {
    false
}

/// `parse_verbose` (`tool_getparam.c`): the `-v`/`--verbose` super-boolean
/// (`-vvv` escalates). `--no-verbose` resets to silence; each repeated `-v`
/// within one flag raises the verbosity tier and selects the matching trace
/// configuration.
///
/// # Errors
/// [`ParameterError::NoMem`] is never produced here (kept for signature parity
/// with curl's `set_trace_config` failure path).
fn parse_verbose(global: &mut GlobalConfig, toggle: bool) -> Result<(), ParameterError> {
    if !toggle {
        global.verbosity = 0;
        set_trace_config(global, "-all");
        global.tracetype = TraceType::None;
        return Ok(());
    }
    let first = VERBOSE_NOPTS.with(Cell::get) == 0;
    if first {
        // first `-v` in an argument resets to base verbosity
        global.verbosity = 0;
        if !global.trace_set {
            set_trace_config(global, "-all");
        }
    }
    match global.verbosity {
        0 => {
            global.verbosity = 1;
            global.trace_dump = Some("%".to_string());
            if global.tracetype != TraceType::None && global.tracetype != TraceType::Plain {
                warnf(global, "-v, --verbose overrides an earlier trace option");
            }
            global.tracetype = TraceType::Plain;
        }
        1 => {
            global.verbosity = 2;
            set_trace_config(global, "ids,time,protocol");
        }
        2 => {
            global.verbosity = 3;
            global.tracetype = TraceType::Ascii;
            set_trace_config(global, "ssl,read,write");
        }
        3 => {
            global.verbosity = 4;
            set_trace_config(global, "network");
        }
        _ => {}
    }
    Ok(())
}

/// `parse_writeout` (`tool_getparam.c`): apply `--write-out`. A `@file`/`@-`
/// source reads the format string from a file/stdin (with CR/LF stripped);
/// otherwise the literal value is used.
///
/// # Errors
/// [`ParameterError::ReadError`] for an unreadable `@file`.
fn parse_writeout(global: &mut GlobalConfig, nextarg: &str) -> Result<(), ParameterError> {
    let idx = global.current;
    if let Some(rest) = nextarg.strip_prefix('@') {
        let (fname, contents) = if rest == "-" {
            (
                "<stdin>".to_string(),
                file2string(&mut std::io::stdin().lock())?,
            )
        } else {
            let s = match fs::File::open(rest) {
                Ok(mut f) => file2string(&mut f)?,
                Err(_) => {
                    errorf(global, &format!("Failed to open {rest}"));
                    return Err(ParameterError::ReadError);
                }
            };
            (rest.to_string(), s)
        };
        if contents.is_empty() {
            warnf(global, &format!("Failed to read {fname}"));
            global.operations[idx].writeout = None;
        } else {
            global.operations[idx].writeout = Some(contents);
        }
        Ok(())
    } else {
        getstr(&mut global.operations[idx].writeout, nextarg, true)
    }
}

/// `parse_time_cond` (`tool_getparam.c`): apply `-z`/`--time-cond`. A leading
/// `+`/`-`/`=` selects if-modified-since / if-unmodified-since / last-modified;
/// the remainder is a date (or, if it fails to parse, the mtime of a named
/// file). An unparseable date disables the condition with a warning.
fn parse_time_cond(global: &mut GlobalConfig, nextarg: &str) -> Result<(), ParameterError> {
    let idx = global.current;
    let (timecond, datestr) = match nextarg.as_bytes().first() {
        Some(b'+') => (CURL_TIMECOND_IFMODSINCE, &nextarg[1..]),
        Some(b'-') => (CURL_TIMECOND_IFUNMODSINCE, &nextarg[1..]),
        Some(b'=') => (CURL_TIMECOND_LASTMOD, &nextarg[1..]),
        _ => (CURL_TIMECOND_IFMODSINCE, nextarg),
    };
    global.operations[idx].timecond = timecond;

    let mut condtime = curl_rs_lib::util::parsedate::curl_getdate(datestr);
    if condtime == -1 {
        // not a valid date — try the file's modification time
        match fs::metadata(datestr).and_then(|m| m.modified()) {
            Ok(mtime) => {
                condtime = mtime
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
            }
            Err(_) => {
                global.operations[idx].timecond = CURL_TIMECOND_NONE;
                warnf(
                    global,
                    "Illegal date format for -z, --time-cond (and not a filename). \
                     Disabling time condition. See curl_getdate(3) for valid date syntax.",
                );
                return Ok(());
            }
        }
    }
    global.operations[idx].condtime = condtime;
    Ok(())
}

// ===========================================================================
// URL / output / upload node helpers and list appenders
// (← `tool_getparam.c` add_url / parse_url / parse_output / parse_remote_name /
// parse_upload_file / parse_quote / parse_header / parse_range /
// parse_localport / parse_continue_at / parse_ech / parse_upload_flags;
// `add2list`).
// ===========================================================================

/// `add2list` (`tool_getparam.c`): append `s` to a slist-backed option. The C
/// `curl_slist_append` cannot fail meaningfully here, so this never errors.
fn add2list(list: &mut Vec<String>, s: &str) {
    list.push(s.to_string());
}

/// `add_url` (`tool_getparam.c`): record a URL into the next free GetOut node.
/// `remote_noglob` marks the node `--remote-name`+`--globoff` (used when URLs
/// are read from a file). Enforces curl's "etag options work on a single URL"
/// rule once more than one URL is present.
///
/// # Errors
/// [`ParameterError::BadUse`] when a second URL is added alongside an etag
/// option.
fn add_url(
    global: &mut GlobalConfig,
    thisurl: &str,
    remote_noglob: bool,
) -> Result<(), ParameterError> {
    let idx = global.current;
    let node = find_or_make_node(&mut global.operations[idx], UrlSlot::Get);
    getstr(
        &mut global.operations[idx].url_list[node].url,
        thisurl,
        false,
    )?;
    global.operations[idx].url_list[node].flags.urlset = true;
    if remote_noglob {
        global.operations[idx].url_list[node].flags.useremote = true;
        global.operations[idx].url_list[node].flags.noglob = true;
    }
    global.operations[idx].num_urls += 1;
    if global.operations[idx].num_urls > 1
        && (global.operations[idx].etag_save_file.is_some()
            || global.operations[idx].etag_compare_file.is_some())
    {
        errorf(global, "The etag options only work on a single URL");
        return Err(ParameterError::BadUse);
    }
    Ok(())
}

/// `parse_url` (`tool_getparam.c`): apply a bare URL argument or, for `@file`
/// (`@-` = stdin), read one URL per line, each treated as `--remote-name`.
///
/// # Errors
/// [`ParameterError::ReadError`] for an unreadable `@file`; propagates
/// [`add_url`] errors.
fn parse_url(global: &mut GlobalConfig, nextarg: &str) -> Result<(), ParameterError> {
    if let Some(src) = nextarg.strip_prefix('@') {
        let lines = read_lines(global, src)?;
        for line in &lines {
            add_url(global, line, true)?;
        }
        Ok(())
    } else {
        add_url(global, nextarg, false)
    }
}

/// `parse_output` (`tool_getparam.c`): apply `-o`/`--output`. `Some(name)` sets
/// the output file; `None` (the `--output null`/`-O` discard form) records a
/// null sink. Clears `useremote` and marks the node `outset`.
fn parse_output(global: &mut GlobalConfig, nextarg: Option<&str>) -> Result<(), ParameterError> {
    let idx = global.current;
    let node = find_or_make_node(&mut global.operations[idx], UrlSlot::Out);
    if let Some(name) = nextarg {
        getstr(
            &mut global.operations[idx].url_list[node].outfile,
            name,
            false,
        )?;
    } else {
        global.operations[idx].url_list[node].outfile = None;
    }
    global.operations[idx].url_list[node].flags.useremote = false;
    global.operations[idx].url_list[node].flags.outset = true;
    global.operations[idx].url_list[node].flags.out_null = nextarg.is_none();
    Ok(())
}

/// `parse_remote_name` (`tool_getparam.c`): apply `-O`/`--remote-name` (and its
/// `--no-remote-name`). When toggled off without `--remote-name-all`, nothing
/// happens; otherwise the next free output node is marked `useremote`.
fn parse_remote_name(global: &mut GlobalConfig, toggle: bool) -> Result<(), ParameterError> {
    let idx = global.current;
    if !toggle && !global.operations[idx].remote_name_all {
        return Ok(());
    }
    let node = find_or_make_node(&mut global.operations[idx], UrlSlot::Out);
    global.operations[idx].url_list[node].outfile = None;
    global.operations[idx].url_list[node].flags.useremote = toggle;
    global.operations[idx].url_list[node].flags.outset = true;
    global.operations[idx].url_list[node].flags.out_null = false;
    Ok(())
}

/// `parse_upload_file` (`tool_getparam.c`): apply `-T`/`--upload-file`. An empty
/// argument disables upload for the node; otherwise the filename (`-` = stdin)
/// is recorded.
///
/// # Errors
/// [`ParameterError::BlankString`] is never produced (the empty case is
/// handled before [`getstr`]).
fn parse_upload_file(global: &mut GlobalConfig, nextarg: &str) -> Result<(), ParameterError> {
    let idx = global.current;
    let node = find_or_make_node(&mut global.operations[idx], UrlSlot::Ul);
    global.operations[idx].url_list[node].flags.uploadset = true;
    if nextarg.is_empty() {
        global.operations[idx].url_list[node].flags.noupload = true;
        Ok(())
    } else {
        getstr(
            &mut global.operations[idx].url_list[node].infile,
            nextarg,
            false,
        )
    }
}

/// `parse_localport` (`tool_getparam.c`): apply `--local-port` (`PORT` or
/// `LOW-HIGH`). Parses the (optional) range and stores the base port plus the
/// count of ports to try.
///
/// # Errors
/// [`ParameterError::BadUse`] for malformed input or an empty/zero range (curl
/// folds every numeric failure here into `BAD_USE`).
fn parse_localport(global: &mut GlobalConfig, nextarg: &str) -> Result<(), ParameterError> {
    let idx = global.current;
    let b = nextarg.as_bytes();
    let mut p = 0usize;
    while p < b.len() && b[p].is_ascii_digit() {
        p += 1;
    }
    let plen = p;
    let mut pp: Option<&str> = None;
    if p < b.len() {
        let mut q = p;
        if b.get(q) == Some(&b' ') || b.get(q) == Some(&b'\t') {
            q += 1;
        }
        if b.get(q) != Some(&b'-') {
            return Err(ParameterError::BadUse);
        }
        q += 1;
        if b.get(q) == Some(&b' ') || b.get(q) == Some(&b'\t') {
            q += 1;
        }
        pp = Some(&nextarg[q..]);
    }
    let buffer = &nextarg[..plen];
    global.operations[idx].localport =
        str2unummax(buffer, 65535).map_err(|_| ParameterError::BadUse)?;
    match pp {
        None => global.operations[idx].localportrange = 1,
        Some(pp) => {
            let range = str2unummax(pp, 65535).map_err(|_| ParameterError::BadUse)?;
            let adjusted = range - (global.operations[idx].localport - 1);
            if adjusted < 1 {
                return Err(ParameterError::BadUse);
            }
            global.operations[idx].localportrange = adjusted;
        }
    }
    Ok(())
}

/// `parse_continue_at` (`tool_getparam.c`): apply `-C`/`--continue-at`. `-`
/// means "resume from the current output size"; otherwise a byte offset is
/// parsed. Rejects combinations with `--range`/`--remove-on-error`/
/// `--no-clobber`.
///
/// # Errors
/// [`ParameterError::BadUse`] for the mutually-exclusive combinations;
/// propagates [`str2offset`] errors for a malformed offset.
fn parse_continue_at(global: &mut GlobalConfig, nextarg: &str) -> Result<(), ParameterError> {
    let idx = global.current;
    if global.operations[idx].range.is_some() {
        errorf(global, "--continue-at is mutually exclusive with --range");
        return Err(ParameterError::BadUse);
    }
    if global.operations[idx].rm_partial {
        errorf(
            global,
            "--continue-at is mutually exclusive with --remove-on-error",
        );
        return Err(ParameterError::BadUse);
    }
    if global.operations[idx].file_clobber_mode == FileClobberMode::Never {
        errorf(
            global,
            "--continue-at is mutually exclusive with --no-clobber",
        );
        return Err(ParameterError::BadUse);
    }
    let mut err = Ok(());
    if nextarg != "-" {
        match str2offset(nextarg) {
            Ok(v) => global.operations[idx].resume_from = v,
            Err(e) => err = Err(e),
        }
        global.operations[idx].resume_from_current = false;
    } else {
        global.operations[idx].resume_from_current = true;
        global.operations[idx].resume_from = 0;
    }
    global.operations[idx].use_resume = true;
    err
}

/// `parse_ech` (`tool_getparam.c`): apply `--ech`. Accepts a keyword, a
/// `pn:<public-name>`, or an `ecl:<config>` (optionally `ecl:@file`/`ecl:@-`).
///
/// # Errors
/// [`ParameterError::LibcurlDoesntSupport`] when ECH is unavailable (always, in
/// this build); [`ParameterError::BadUse`] for an unreadable `ecl:@file`.
fn parse_ech(global: &mut GlobalConfig, nextarg: &str) -> Result<(), ParameterError> {
    let idx = global.current;
    if !feat::ech() {
        return Err(ParameterError::LibcurlDoesntSupport);
    }
    let ci = |a: &str, n: usize| nextarg.get(..n).is_some_and(|s| s.eq_ignore_ascii_case(a));
    if nextarg.len() > 4 && ci("pn:", 3) {
        getstr(&mut global.operations[idx].ech_public, nextarg, false)
    } else if nextarg.len() > 5 && ci("ecl:", 4) {
        if nextarg.as_bytes().get(4) != Some(&b'@') {
            getstr(&mut global.operations[idx].ech_config, nextarg, false)
        } else {
            // indirect: `ecl:@filename` or `ecl:@-` for stdin
            let src = &nextarg[5..];
            let body = if src == "-" {
                file2string(&mut std::io::stdin().lock())?
            } else {
                match fs::File::open(src) {
                    Ok(mut f) => file2string(&mut f)?,
                    Err(_) => {
                        warnf(
                            global,
                            &format!(
                                "Could not read file \"{src}\" specified for \"--ech ecl:\" option"
                            ),
                        );
                        return Err(ParameterError::BadUse);
                    }
                }
            };
            global.operations[idx].ech_config = Some(format!("ecl:{body}"));
            Ok(())
        }
    } else {
        getstr(&mut global.operations[idx].ech, nextarg, false)
    }
}

/// `parse_header` (`tool_getparam.c`): apply `-H`/`--header` or
/// `--proxy-header`. An `@file` (`@-` = stdin) source reads one header per
/// line; otherwise the literal header is appended (with curl's
/// "does not look like a header" warning when it lacks `:`/`;`).
///
/// # Errors
/// [`ParameterError::ReadError`] for an unreadable `@file`.
fn parse_header(global: &mut GlobalConfig, id: OptId, nextarg: &str) -> Result<(), ParameterError> {
    let idx = global.current;
    let is_proxy = id == OptId::ProxyHeader;
    if let Some(src) = nextarg.strip_prefix('@') {
        let lines = read_lines(global, src)?;
        for line in &lines {
            if is_proxy {
                add2list(&mut global.operations[idx].proxyheaders, line);
            } else {
                add2list(&mut global.operations[idx].headers, line);
            }
        }
        Ok(())
    } else {
        if !nextarg.contains(':') && !nextarg.contains(';') {
            let kind = if is_proxy { "proxy" } else { "HTTP" };
            let msg =
                format!("The provided {kind} header '{nextarg}' does not look like a header?");
            warnf(global, &msg);
        }
        if is_proxy {
            add2list(&mut global.operations[idx].proxyheaders, nextarg);
        } else {
            add2list(&mut global.operations[idx].headers, nextarg);
        }
        Ok(())
    }
}

/// `parse_quote` (`tool_getparam.c`): apply `-Q`/`--quote`. A `-` prefix routes
/// the command to `postquote` (after transfer), a `+` prefix to `prequote`
/// (just before transfer); otherwise it is a pre-transfer `quote`.
fn parse_quote(global: &mut GlobalConfig, nextarg: &str) -> Result<(), ParameterError> {
    let idx = global.current;
    match nextarg.as_bytes().first() {
        Some(b'-') => add2list(&mut global.operations[idx].postquote, &nextarg[1..]),
        Some(b'+') => add2list(&mut global.operations[idx].prequote, &nextarg[1..]),
        _ => add2list(&mut global.operations[idx].quote, nextarg),
    }
    Ok(())
}

/// `parse_range` (`tool_getparam.c`): apply `-r`/`--range`. A dash-less numeric
/// range is rejected by curl with a warning and an appended `-`; otherwise the
/// raw range string is validated (digits/`-`/`,`) and stored.
///
/// # Errors
/// [`ParameterError::BadUse`] when `--continue-at` is already set.
fn parse_range(global: &mut GlobalConfig, nextarg: &str) -> Result<(), ParameterError> {
    let idx = global.current;
    if global.operations[idx].use_resume {
        errorf(global, "--continue-at is mutually exclusive with --range");
        return Err(ParameterError::BadUse);
    }
    let b = nextarg.as_bytes();
    // "number with no trailing dash" => curl appends a dash for the user
    let dashless_value = match str_num_base(b, CURL_OFF_T_MAX, 10) {
        Ok((value, used)) if b.get(used) != Some(&b'-') => Some(value),
        _ => None,
    };
    if let Some(value) = dashless_value {
        warnf(
            global,
            "A specified range MUST include at least one dash (-). Appending one for you",
        );
        global.operations[idx].range = Some(format!("{value}-"));
        Ok(())
    } else {
        for &c in nextarg.as_bytes() {
            if !c.is_ascii_digit() && c != b'-' && c != b',' {
                warnf(
                    global,
                    "Invalid character is found in given range. A specified range MUST have \
                     only digits in 'start'-'stop'. The server's response to this request \
                     is uncertain.",
                );
                break;
            }
        }
        getstr(&mut global.operations[idx].range, nextarg, false)
    }
}

/// One entry of curl's `flag_table` for `--upload-flags` (`tool_getparam.c`).
struct FlagMap {
    name: &'static str,
    flag: u8,
}

/// The `flag_table[]` from `tool_getparam.c` (IMAP upload flags).
#[rustfmt::skip] // one upload-flag per line for auditability — keep as authored
const FLAG_TABLE: &[FlagMap] = &[
    FlagMap { name: "answered", flag: CURLULFLAG_ANSWERED },
    FlagMap { name: "deleted", flag: CURLULFLAG_DELETED },
    FlagMap { name: "draft", flag: CURLULFLAG_DRAFT },
    FlagMap { name: "flagged", flag: CURLULFLAG_FLAGGED },
    FlagMap { name: "seen", flag: CURLULFLAG_SEEN_FLAG },
];

/// `parse_upload_flags` (`tool_getparam.c`): apply `--upload-flags` — a
/// comma-separated list of IMAP flag names, each optionally `-`-negated to
/// clear rather than set the corresponding bit.
///
/// # Errors
/// [`ParameterError::OptionUnknown`] for an unrecognized flag name.
fn parse_upload_flags(global: &mut GlobalConfig, flag: &str) -> Result<(), ParameterError> {
    let idx = global.current;
    for token in flag.split(',') {
        let (negate, name) = match token.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, token),
        };
        match FLAG_TABLE.iter().find(|m| m.name == name) {
            Some(m) => {
                if negate {
                    global.operations[idx].upload_flags &= !m.flag;
                } else {
                    global.operations[idx].upload_flags |= m.flag;
                }
            }
            None => return Err(ParameterError::OptionUnknown),
        }
    }
    Ok(())
}

// ===========================================================================
// opt_depr / opt_none / opt_bool (← `tool_getparam.c`).
// ===========================================================================

/// `opt_depr` (`tool_getparam.c`): warn that a deprecated option no longer does
/// anything. Used both for `ARG_DEPR` rows (intercepted in [`get_parameter`])
/// and for `--false-start`.
fn opt_depr(global: &GlobalConfig, lname: &str) {
    warnf(
        global,
        &format!("--{lname} is deprecated and has no function anymore"),
    );
}

/// `opt_none` (`tool_getparam.c`): apply an `ARG_NONE` option (one that never
/// negates and takes no value). Several entries return a `*_REQUESTED` /
/// `NEXT_OPERATION` sentinel that the caller turns into control flow.
///
/// # Errors
/// The sentinel [`ParameterError`]s (`CaEmbedRequested`, `NextOperation`),
/// [`ParameterError::LibcurlDoesntSupport`] for unavailable HTTP versions, and
/// propagated [`opt_sslver`] errors.
fn opt_none(global: &mut GlobalConfig, id: OptId) -> Result<(), ParameterError> {
    let idx = global.current;
    match id {
        OptId::Anyauth => global.operations[idx].authtype = CURLAUTH_ANY,
        OptId::DumpCaEmbed => return Err(ParameterError::CaEmbedRequested),
        OptId::FtpPasv => global.operations[idx].ftpport = None,
        OptId::Http10 => sethttpver(global, idx, CURL_HTTP_VERSION_1_0),
        OptId::Http11 => sethttpver(global, idx, CURL_HTTP_VERSION_1_1),
        OptId::Http2 => {
            if !feat::http2() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            sethttpver(global, idx, CURL_HTTP_VERSION_2_0);
        }
        OptId::Http2PriorKnowledge => {
            if !feat::http2() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            sethttpver(global, idx, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
        }
        OptId::Http3 => {
            if !feat::http3() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            sethttpver(global, idx, CURL_HTTP_VERSION_3);
        }
        OptId::Http3Only => {
            if !feat::http3() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            sethttpver(global, idx, CURL_HTTP_VERSION_3ONLY);
        }
        OptId::Tlsv1 | OptId::Tlsv10 => opt_sslver(global, idx, 1)?,
        OptId::Tlsv11 => opt_sslver(global, idx, 2)?,
        OptId::Tlsv12 => opt_sslver(global, idx, 3)?,
        OptId::Tlsv13 => opt_sslver(global, idx, 4)?,
        OptId::Ipv4 => global.operations[idx].ip_version = CURL_IPRESOLVE_V4,
        OptId::Ipv6 => global.operations[idx].ip_version = CURL_IPRESOLVE_V6,
        OptId::Next => return Err(ParameterError::NextOperation),
        OptId::ProxyTlsv1 => global.operations[idx].proxy_ssl_version = CURL_SSLVERSION_TLSV1,
        // Any other id reaching opt_none is a table/dispatch mismatch.
        _ => {}
    }
    Ok(())
}

/// `opt_bool` (`tool_getparam.c`): apply an `ARG_BOOL`/`ARG_NO` option. `toggle`
/// is the resolved polarity (`--no-…` and `ARG_NO` defaults already applied by
/// the caller). Some entries delegate to a `parse_*` helper or return a
/// `*_REQUESTED` sentinel.
///
/// # Errors
/// [`ParameterError::LibcurlDoesntSupport`] for unavailable capabilities,
/// [`ParameterError::BadUse`] for mutually-exclusive combinations, the
/// `*_REQUESTED` sentinels, and [`ParameterError::OptionUnknown`] for an id that
/// is not a boolean option.
fn opt_bool(global: &mut GlobalConfig, id: OptId, toggle: bool) -> Result<(), ParameterError> {
    let idx = global.current;
    match id {
        OptId::Alpn => global.operations[idx].noalpn = !toggle,
        OptId::DisableEpsv => global.operations[idx].disable_epsv = toggle,
        OptId::DisallowUsernameInUrl => {
            global.operations[idx].disallow_username_in_url = toggle;
        }
        OptId::Epsv => global.operations[idx].disable_epsv = !toggle,
        OptId::Compressed => {
            if toggle && !(feat::libz() || feat::brotli() || feat::zstd()) {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            global.operations[idx].encoding = toggle;
        }
        OptId::TrEncoding => global.operations[idx].tr_encoding = toggle,
        OptId::Digest => togglebit(
            toggle,
            &mut global.operations[idx].authtype,
            CURLAUTH_DIGEST,
        ),
        OptId::FtpCreateDirs => global.operations[idx].ftp_create_dirs = toggle,
        OptId::CreateDirs => global.operations[idx].create_dirs = toggle,
        OptId::ProxyNtlm => {
            if !feat::ntlm() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            global.operations[idx].proxyntlm = toggle;
        }
        OptId::Crlf => global.operations[idx].crlf = toggle,
        OptId::HaproxyProtocol => global.operations[idx].haproxy_protocol = toggle,
        OptId::Negotiate => {
            if !feat::spnego() && toggle {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            togglebit(
                toggle,
                &mut global.operations[idx].authtype,
                CURLAUTH_NEGOTIATE,
            );
        }
        OptId::Ntlm => {
            if !feat::ntlm() && toggle {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            togglebit(toggle, &mut global.operations[idx].authtype, CURLAUTH_NTLM);
        }
        OptId::OutNull => return parse_output(global, None),
        OptId::Basic => togglebit(toggle, &mut global.operations[idx].authtype, CURLAUTH_BASIC),
        OptId::Wdebug => {} // `--wdebug` (USE_WATT32): no analog on this target
        OptId::DisableEprt => global.operations[idx].disable_eprt = toggle,
        OptId::Eprt => global.operations[idx].disable_eprt = !toggle,
        OptId::Xattr => global.operations[idx].xattr = toggle,
        OptId::FtpSsl | OptId::Ssl => {
            global.operations[idx].ftp_ssl = toggle;
            if global.operations[idx].ftp_ssl {
                let lname = if id == OptId::FtpSsl {
                    "ftp-ssl"
                } else {
                    "ssl"
                };
                warnf(
                    global,
                    &format!("--{lname} is an insecure option, consider --ssl-reqd instead"),
                );
            }
        }
        OptId::FtpSslCcc => {
            global.operations[idx].ftp_ssl_ccc = toggle;
            if global.operations[idx].ftp_ssl_ccc_mode == 0 {
                global.operations[idx].ftp_ssl_ccc_mode = CURLFTPSSL_CCC_PASSIVE;
            }
        }
        OptId::TcpNodelay => global.operations[idx].tcp_nodelay = toggle,
        OptId::ProxyDigest => global.operations[idx].proxydigest = toggle,
        OptId::ProxyBasic => global.operations[idx].proxybasic = toggle,
        OptId::RetryConnrefused => global.operations[idx].retry_connrefused = toggle,
        OptId::RetryAllErrors => global.operations[idx].retry_all_errors = toggle,
        OptId::ProxyNegotiate => {
            if !feat::spnego() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            global.operations[idx].proxynegotiate = toggle;
        }
        OptId::FormEscape => togglebit(
            toggle,
            &mut global.operations[idx].mime_options,
            CURLMIMEOPT_FORMESCAPE,
        ),
        OptId::ProxyAnyauth => global.operations[idx].proxyanyauth = toggle,
        OptId::TraceTime => global.tracetime = toggle,
        OptId::IgnoreContentLength => global.operations[idx].ignorecl = toggle,
        OptId::FtpSkipPasvIp => global.operations[idx].ftp_skip_ip = toggle,
        OptId::FtpSslReqd | OptId::SslReqd => global.operations[idx].ftp_ssl_reqd = toggle,
        OptId::Sessionid => global.operations[idx].disable_sessionid = !toggle,
        OptId::FtpSslControl => global.operations[idx].ftp_ssl_control = toggle,
        OptId::Raw => global.operations[idx].raw = toggle,
        OptId::Keepalive => global.operations[idx].nokeepalive = !toggle,
        OptId::Post301 => global.operations[idx].post301 = toggle,
        OptId::Post302 => global.operations[idx].post302 = toggle,
        OptId::Post303 => global.operations[idx].post303 = toggle,
        OptId::Socks5GssapiNec => global.operations[idx].socks5_gssapi_nec = toggle,
        OptId::FtpPret => global.operations[idx].ftp_pret = toggle,
        OptId::SaslIr => global.operations[idx].sasl_ir = toggle,
        OptId::TestDuphandle => global.test_duphandle = toggle,
        OptId::TestEvent => global.test_event_based = toggle,
        OptId::PathAsIs => global.operations[idx].path_as_is = toggle,
        OptId::TftpNoOptions => global.operations[idx].tftp_no_options = toggle,
        OptId::TlsEarlydata => global.operations[idx].ssl_allow_earlydata = toggle,
        OptId::SuppressConnectHeaders => global.operations[idx].suppress_connect_headers = toggle,
        OptId::CompressedSsh => global.operations[idx].ssh_compression = toggle,
        OptId::TraceIds => global.traceids = toggle,
        OptId::ProgressMeter => global.noprogress = !toggle,
        OptId::ProgressBar => {
            global.progressmode = if toggle {
                CURL_PROGRESS_BAR
            } else {
                CURL_PROGRESS_STATS
            };
        }
        OptId::Http09 => global.operations[idx].http09_allowed = toggle,
        OptId::ProxyHttp2 => {
            if !feat::httpsproxy() || !feat::http2() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            global.operations[idx].proxyver = if toggle {
                CURLPROXY_HTTPS2
            } else {
                CURLPROXY_HTTPS
            };
        }
        OptId::Append => global.operations[idx].ftp_append = toggle,
        OptId::UseAscii => global.operations[idx].use_ascii = toggle,
        OptId::CaNative => global.operations[idx].native_ca_store = toggle,
        OptId::ProxyCaNative => global.operations[idx].proxy_native_ca_store = toggle,
        OptId::SslAllowBeast => global.operations[idx].ssl_allow_beast = toggle,
        OptId::SslAutoClientCert => global.operations[idx].ssl_auto_client_cert = toggle,
        OptId::ProxySslAutoClientCert => {
            global.operations[idx].proxy_ssl_auto_client_cert = toggle;
        }
        OptId::CertStatus => global.operations[idx].verifystatus = toggle,
        OptId::DohCertStatus => global.operations[idx].doh_verifystatus = toggle,
        OptId::FalseStart => opt_depr(global, "false-start"),
        OptId::SslNoRevoke => global.operations[idx].ssl_no_revoke = toggle,
        OptId::SslRevokeBestEffort => global.operations[idx].ssl_revoke_best_effort = toggle,
        OptId::TcpFastopen => global.operations[idx].tcp_fastopen = toggle,
        OptId::ProxySslAllowBeast => global.operations[idx].proxy_ssl_allow_beast = toggle,
        OptId::ProxyInsecure => global.operations[idx].proxy_insecure_ok = toggle,
        OptId::Socks5Basic => {
            togglebit(
                toggle,
                &mut global.operations[idx].socks5_auth,
                CURLAUTH_BASIC,
            );
        }
        OptId::Socks5Gssapi => {
            togglebit(
                toggle,
                &mut global.operations[idx].socks5_auth,
                CURLAUTH_GSSAPI,
            );
        }
        OptId::FailEarly => global.fail_early = toggle,
        OptId::StyledOutput => global.styled_output = toggle,
        OptId::MailRcptAllowfails => global.operations[idx].mail_rcpt_allowfails = toggle,
        OptId::RemoveOnError => {
            if global.operations[idx].use_resume && toggle {
                errorf(
                    global,
                    "--continue-at is mutually exclusive with --remove-on-error",
                );
                return Err(ParameterError::BadUse);
            }
            global.operations[idx].rm_partial = toggle;
        }
        OptId::Fail => {
            if toggle && global.operations[idx].fail == FailMode::WithBody {
                warnf(global, "--fail deselects --fail-with-body here");
            }
            global.operations[idx].fail = if toggle {
                FailMode::WithoutBody
            } else {
                FailMode::None
            };
        }
        OptId::FailWithBody => {
            if toggle && global.operations[idx].fail == FailMode::WithoutBody {
                warnf(global, "--fail-with-body deselects --fail here");
            }
            global.operations[idx].fail = if toggle {
                FailMode::WithBody
            } else {
                FailMode::None
            };
        }
        OptId::Globoff => global.operations[idx].globoff = toggle,
        OptId::Get => global.operations[idx].use_httpget = toggle,
        OptId::Include | OptId::ShowHeaders => global.operations[idx].show_headers = toggle,
        OptId::JunkSessionCookies => global.operations[idx].cookiesession = toggle,
        OptId::Head => {
            global.operations[idx].no_body = toggle;
            global.operations[idx].show_headers = toggle;
            let req = if global.operations[idx].no_body {
                HttpReq::Head
            } else {
                HttpReq::Get
            };
            if set_httprequest(global, idx, req) {
                return Err(ParameterError::BadUse);
            }
        }
        OptId::RemoteHeaderName => global.operations[idx].content_disposition = toggle,
        OptId::Insecure => global.operations[idx].insecure_ok = toggle,
        OptId::DohInsecure => global.operations[idx].doh_insecure_ok = toggle,
        OptId::ListOnly => global.operations[idx].dirlistonly = toggle,
        OptId::Manual => {
            if toggle {
                return Err(ParameterError::ManualRequested);
            }
        }
        OptId::NetrcOptional => global.operations[idx].netrc_opt = toggle,
        OptId::Netrc => global.operations[idx].netrc = toggle,
        OptId::Buffer => global.operations[idx].nobuffer = !toggle,
        OptId::RemoteNameAll => global.operations[idx].remote_name_all = toggle,
        OptId::Clobber => {
            if global.operations[idx].use_resume && !toggle {
                errorf(
                    global,
                    "--continue-at is mutually exclusive with --no-clobber",
                );
                return Err(ParameterError::BadUse);
            }
            global.operations[idx].file_clobber_mode = if toggle {
                FileClobberMode::Always
            } else {
                FileClobberMode::Never
            };
        }
        OptId::RemoteName => return parse_remote_name(global, toggle),
        OptId::Proxytunnel => global.operations[idx].proxytunnel = toggle,
        OptId::Disable => {} // handled earlier if used first; no-op here
        OptId::RemoteTime => global.operations[idx].remote_time = toggle,
        OptId::Silent => global.silent = toggle,
        OptId::SkipExisting => global.operations[idx].skip_existing = toggle,
        OptId::ShowError => global.showerror = toggle,
        OptId::Verbose => return parse_verbose(global, toggle),
        OptId::Version => {
            if toggle {
                return Err(ParameterError::VersionInfoRequested);
            }
        }
        OptId::Parallel => global.parallel = toggle,
        OptId::ParallelImmediate => global.parallel_connect = toggle,
        OptId::Mptcp => global.operations[idx].mptcp = toggle,
        OptId::LocationTrusted => {
            global.operations[idx].unrestricted_auth = toggle;
            if global.operations[idx].followlocation == CURLFOLLOW_OBEYCODE {
                warnf(global, "--location overrides --follow");
            }
            global.operations[idx].followlocation = if toggle { CURLFOLLOW_ALL } else { 0 };
        }
        OptId::Location => {
            if global.operations[idx].followlocation == CURLFOLLOW_OBEYCODE {
                warnf(global, "--location overrides --follow");
            }
            global.operations[idx].followlocation = if toggle { CURLFOLLOW_ALL } else { 0 };
        }
        OptId::Follow => {
            if global.operations[idx].followlocation == CURLFOLLOW_ALL {
                warnf(global, "--follow overrides --location");
            }
            global.operations[idx].followlocation = if toggle { CURLFOLLOW_OBEYCODE } else { 0 };
        }
        // `default: return PARAM_OPTION_UNKNOWN;`
        _ => return Err(ParameterError::OptionUnknown),
    }
    Ok(())
}

// ===========================================================================
// opt_file (← `tool_getparam.c`) — `ARG_FILE` (filename-valued) options.
// ===========================================================================

/// `opt_file` (`tool_getparam.c`): apply an `ARG_FILE` option (its value is a
/// filename). Emits curl's "looks like a flag" warning for a value beginning
/// with `-`. `--config` recurses through [`crate::parsecfg::parseconfig`] up to
/// `max_recursive` levels.
///
/// # Errors
/// [`ParameterError::BadUse`] for a missing required file or exceeded `--config`
/// recursion; [`ParameterError::LibcurlDoesntSupport`] for `--ssl-sessions`
/// when session export is unavailable; propagated read/parse errors.
fn opt_file(
    global: &mut GlobalConfig,
    id: OptId,
    nextarg: &str,
    max_recursive: i32,
) -> Result<(), ParameterError> {
    let idx = global.current;
    if nextarg.len() > 1 && nextarg.starts_with('-') {
        warnf(
            global,
            &format!("The filename argument '{nextarg}' looks like a flag."),
        );
    }
    match id {
        OptId::AbstractUnixSocket => {
            global.operations[idx].abstract_unix_socket = true;
            getstr(&mut global.operations[idx].unix_socket_path, nextarg, false)?;
        }
        OptId::Cacert => {
            global.operations[idx].cacert = existingfile(global, "cacert", nextarg)?;
        }
        OptId::Capath => getstr(&mut global.operations[idx].capath, nextarg, false)?,
        OptId::Cert => {
            let op = &mut global.operations[idx];
            get_file_and_password(nextarg, &mut op.cert, &mut op.key_passwd)?;
        }
        OptId::Config => {
            let max_recursive = max_recursive - 1;
            if max_recursive < 0 {
                errorf(
                    global,
                    &format!("Max config file recursion level reached ({CONFIG_MAX_LEVELS})"),
                );
                return Err(ParameterError::BadUse);
            }
            // `parseconfig` takes `Option<&str>` (a faithful translation of the
            // C `const char *filename`, where `None` selects the default
            // `~/.curlrc`); an explicit `--config <file>` always names a file.
            crate::parsecfg::parseconfig(global, Some(nextarg), max_recursive)?;
        }
        OptId::Crlfile => {
            global.operations[idx].crlfile = existingfile(global, "crlfile", nextarg)?;
        }
        OptId::DumpHeader => getstr(&mut global.operations[idx].headerfile, nextarg, false)?,
        OptId::EtagSave => {
            if global.operations[idx].num_urls > 1 {
                errorf(global, "The etag options only work on a single URL");
                return Err(ParameterError::BadUse);
            }
            getstr(&mut global.operations[idx].etag_save_file, nextarg, false)?;
        }
        OptId::EtagCompare => {
            if global.operations[idx].num_urls > 1 {
                errorf(global, "The etag options only work on a single URL");
                return Err(ParameterError::BadUse);
            }
            getstr(
                &mut global.operations[idx].etag_compare_file,
                nextarg,
                false,
            )?;
        }
        OptId::Key => getstr(&mut global.operations[idx].key, nextarg, false)?,
        OptId::Knownhosts => {
            global.operations[idx].knownhosts = existingfile(global, "knownhosts", nextarg)?;
        }
        OptId::NetrcFile => {
            global.operations[idx].netrc_file = existingfile(global, "netrc-file", nextarg)?;
        }
        OptId::Output => parse_output(global, Some(nextarg))?,
        OptId::ProxyCacert => {
            global.operations[idx].proxy_cacert = existingfile(global, "proxy-cacert", nextarg)?;
        }
        OptId::ProxyCapath => getstr(&mut global.operations[idx].proxy_capath, nextarg, false)?,
        OptId::ProxyCert => {
            let op = &mut global.operations[idx];
            get_file_and_password(nextarg, &mut op.proxy_cert, &mut op.proxy_key_passwd)?;
        }
        OptId::ProxyCrlfile => {
            global.operations[idx].proxy_crlfile = existingfile(global, "proxy-crlfile", nextarg)?;
        }
        OptId::ProxyKey => getstr(&mut global.operations[idx].proxy_key, nextarg, true)?,
        OptId::SslSessions => {
            if feat::ssls_export() {
                getstr(&mut global.ssl_sessions, nextarg, false)?;
            } else {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
        }
        OptId::Stderr => set_stderr_file(global, nextarg),
        OptId::Trace => {
            getstr(&mut global.trace_dump, nextarg, false)?;
            if global.tracetype != TraceType::None && global.tracetype != TraceType::Bin {
                warnf(global, "--trace overrides an earlier trace/verbose option");
            }
            global.tracetype = TraceType::Bin;
        }
        OptId::TraceAscii => {
            getstr(&mut global.trace_dump, nextarg, false)?;
            if global.tracetype != TraceType::None && global.tracetype != TraceType::Ascii {
                warnf(
                    global,
                    "--trace-ascii overrides an earlier trace/verbose option",
                );
            }
            global.tracetype = TraceType::Ascii;
        }
        OptId::UnixSocket => {
            global.operations[idx].abstract_unix_socket = false;
            getstr(&mut global.operations[idx].unix_socket_path, nextarg, false)?;
        }
        OptId::UploadFile => parse_upload_file(global, nextarg)?,
        // Any other id reaching opt_file is a table/dispatch mismatch.
        _ => {}
    }
    Ok(())
}

// ===========================================================================
// opt_string (← `tool_getparam.c`) — `ARG_STRG` (string-valued) options.
//
// This is the largest dispatcher (~140 options). A missing value is treated as
// the empty string, exactly as curl does (`if(!nextarg) nextarg = ""`).
// ===========================================================================

/// `opt_string` (`tool_getparam.c`): apply an `ARG_STRG` option (its value is a
/// string). Numeric/size/protocol values are parsed via the Phase-D helpers;
/// several options delegate to a `parse_*` helper or return a `*_REQUESTED`
/// sentinel.
///
/// # Errors
/// The full range of [`ParameterError`]s the individual options can raise
/// (numeric, blank-string, unsupported-feature, bad-use, and the `*_REQUESTED`
/// sentinels).
#[allow(clippy::too_many_lines)]
fn opt_string(global: &mut GlobalConfig, id: OptId, nextarg: &str) -> Result<(), ParameterError> {
    let idx = global.current;
    match id {
        OptId::DnsIpv4Addr => {
            if !feat::ares() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            getstr(&mut global.operations[idx].dns_ipv4_addr, nextarg, false)?;
        }
        OptId::DnsIpv6Addr => {
            if !feat::ares() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            getstr(&mut global.operations[idx].dns_ipv6_addr, nextarg, false)?;
        }
        OptId::Oauth2Bearer => {
            global.operations[idx].authtype |= CURLAUTH_BEARER;
            getstr(&mut global.operations[idx].oauth_bearer, nextarg, false)?;
        }
        OptId::ConnectTimeout => {
            global.operations[idx].connecttimeout_ms = secs2ms(nextarg)?;
        }
        OptId::DohUrl => {
            getstr(&mut global.operations[idx].doh_url, nextarg, true)?;
            if global.operations[idx].doh_url.as_deref() == Some("") {
                global.operations[idx].doh_url = None;
            }
        }
        OptId::Ciphers => getstr(&mut global.operations[idx].cipher_list, nextarg, false)?,
        OptId::DnsInterface => {
            if !feat::ares() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            getstr(&mut global.operations[idx].dns_interface, nextarg, false)?;
        }
        OptId::DnsServers => {
            if !feat::ares() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            getstr(&mut global.operations[idx].dns_servers, nextarg, false)?;
        }
        OptId::LimitRate => {
            let value = get_size_parameter(nextarg)?;
            global.operations[idx].recvpersecond = value;
            global.operations[idx].sendpersecond = value;
        }
        OptId::Rate => set_rate(global, nextarg)?,
        OptId::CreateFileMode => {
            global.operations[idx].create_file_mode = oct2nummax(nextarg, 0o777)?;
        }
        OptId::MaxRedirs => {
            // accepts -1 as a special "unlimited" value
            let v = str2num(nextarg)?;
            global.operations[idx].maxredirs = v;
            if v < -1 {
                return Err(ParameterError::BadNumeric);
            }
        }
        OptId::IpfsGateway => getstr(&mut global.operations[idx].ipfs_gateway, nextarg, false)?,
        OptId::AwsSigv4 => {
            global.operations[idx].authtype |= CURLAUTH_AWS_SIGV4;
            getstr(&mut global.operations[idx].aws_sigv4, nextarg, true)?;
        }
        OptId::Interface => getstr(&mut global.operations[idx].iface, nextarg, false)?,
        OptId::HaproxyClientip => {
            getstr(&mut global.operations[idx].haproxy_clientip, nextarg, false)?;
        }
        OptId::MaxFilesize => {
            global.operations[idx].max_filesize = get_size_parameter(nextarg)?;
        }
        OptId::Url => parse_url(global, nextarg)?,
        OptId::Socks5 => {
            getstr(&mut global.operations[idx].proxy, nextarg, false)?;
            global.operations[idx].proxyver = CURLPROXY_SOCKS5;
        }
        OptId::Socks4 => {
            getstr(&mut global.operations[idx].proxy, nextarg, false)?;
            global.operations[idx].proxyver = CURLPROXY_SOCKS4;
        }
        OptId::Socks4a => {
            getstr(&mut global.operations[idx].proxy, nextarg, false)?;
            global.operations[idx].proxyver = CURLPROXY_SOCKS4A;
        }
        OptId::Socks5Hostname => {
            getstr(&mut global.operations[idx].proxy, nextarg, false)?;
            global.operations[idx].proxyver = CURLPROXY_SOCKS5_HOSTNAME;
        }
        OptId::IpTos => {
            if let Some(v) = find_tos(nextarg) {
                global.operations[idx].ip_tos = v;
            } else {
                global.operations[idx].ip_tos = str2unummax(nextarg, 0xFF)?;
            }
        }
        OptId::VlanPriority => {
            global.operations[idx].vlan_priority = str2unummax(nextarg, 7)?;
        }
        OptId::Retry => global.operations[idx].req_retry = str2unum(nextarg)?,
        OptId::RetryDelay => global.operations[idx].retry_delay_ms = secs2ms(nextarg)?,
        OptId::RetryMaxTime => global.operations[idx].retry_maxtime_ms = secs2ms(nextarg)?,
        OptId::FtpAccount => getstr(&mut global.operations[idx].ftp_account, nextarg, false)?,
        OptId::FtpMethod => {
            let v = ftpfilemethod(global, nextarg);
            global.operations[idx].ftp_filemethod = v;
        }
        OptId::LocalPort => parse_localport(global, nextarg)?,
        OptId::FtpAlternativeToUser => {
            getstr(
                &mut global.operations[idx].ftp_alternative_to_user,
                nextarg,
                false,
            )?;
        }
        OptId::Libcurl => getstr(&mut global.libcurl, nextarg, false)?,
        OptId::KeepaliveTime => global.operations[idx].alivetime = str2unum(nextarg)?,
        OptId::KeepaliveCnt => global.operations[idx].alivecnt = str2unum(nextarg)?,
        OptId::Noproxy => getstr(&mut global.operations[idx].noproxy, nextarg, true)?,
        OptId::Proxy10 => {
            getstr(&mut global.operations[idx].proxy, nextarg, false)?;
            global.operations[idx].proxyver = CURLPROXY_HTTP_1_0;
        }
        OptId::TftpBlksize => global.operations[idx].tftp_blksize = str2unum(nextarg)?,
        OptId::MailFrom => getstr(&mut global.operations[idx].mail_from, nextarg, false)?,
        OptId::MailRcpt => add2list(&mut global.operations[idx].mail_rcpt, nextarg),
        OptId::Proto => {
            global.operations[idx].proto_present = true;
            let v = proto2num(global, version::protocols(), nextarg)?;
            global.operations[idx].proto_str = Some(v);
        }
        OptId::ProtoRedir => {
            global.operations[idx].proto_redir_present = true;
            match proto2num(global, REDIR_PROTOS, nextarg) {
                Ok(v) => global.operations[idx].proto_redir_str = Some(v),
                Err(_) => return Err(ParameterError::BadUse),
            }
        }
        OptId::Resolve => add2list(&mut global.operations[idx].resolve, nextarg),
        OptId::Delegation => {
            let v = delegation(global, nextarg);
            global.operations[idx].gssapi_delegation = v;
        }
        OptId::MailAuth => getstr(&mut global.operations[idx].mail_auth, nextarg, false)?,
        OptId::SaslAuthzid => getstr(&mut global.operations[idx].sasl_authzid, nextarg, false)?,
        OptId::ProxyServiceName => {
            getstr(
                &mut global.operations[idx].proxy_service_name,
                nextarg,
                false,
            )?;
        }
        OptId::ServiceName => getstr(&mut global.operations[idx].service_name, nextarg, false)?,
        OptId::ProtoDefault => {
            getstr(&mut global.operations[idx].proto_default, nextarg, false)?;
            check_protocol(global.operations[idx].proto_default.as_deref())?;
        }
        OptId::Expect100Timeout => {
            global.operations[idx].expect100timeout_ms = secs2ms(nextarg)?;
        }
        OptId::ConnectTo => add2list(&mut global.operations[idx].connect_to, nextarg),
        OptId::TlsMax => {
            let v = str2tls_max(Some(nextarg))?;
            global.operations[idx].ssl_version_max = v;
            if v < global.operations[idx].ssl_version {
                errorf(global, "--tls-max set lower than minimum accepted version");
                return Err(ParameterError::BadUse);
            }
        }
        OptId::HappyEyeballsTimeoutMs => {
            // 0 is a valid value for this timeout
            global.operations[idx].happy_eyeballs_timeout_ms = str2unum(nextarg)?;
        }
        OptId::TraceConfig => {
            global.trace_set = true;
            set_trace_config(global, nextarg);
        }
        OptId::Variable => global.set_variable(nextarg)?,
        OptId::Tls13Ciphers => getstr(&mut global.operations[idx].cipher13_list, nextarg, false)?,
        OptId::ProxyTls13Ciphers => {
            getstr(
                &mut global.operations[idx].proxy_cipher13_list,
                nextarg,
                false,
            )?;
        }
        OptId::UserAgent => getstr(&mut global.operations[idx].useragent, nextarg, true)?,
        OptId::AltSvc => {
            if !feat::altsvc() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            getstr(&mut global.operations[idx].altsvc, nextarg, true)?;
        }
        OptId::Hsts => {
            if !feat::hsts() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            getstr(&mut global.operations[idx].hsts, nextarg, true)?;
        }
        OptId::Cookie => {
            if nextarg.contains('=') {
                add2list(&mut global.operations[idx].cookies, nextarg);
            } else {
                add2list(&mut global.operations[idx].cookiefiles, nextarg);
            }
        }
        OptId::CookieJar => getstr(&mut global.operations[idx].cookiejar, nextarg, false)?,
        OptId::ContinueAt => parse_continue_at(global, nextarg)?,
        OptId::Data
        | OptId::DataAscii
        | OptId::DataBinary
        | OptId::DataUrlencode
        | OptId::Json
        | OptId::DataRaw => set_data(global, id, nextarg)?,
        OptId::UrlQuery => url_query(global, nextarg)?,
        OptId::Referer => {
            let mut len = nextarg.len();
            // does it end with ";auto" ?
            if len >= 5 && nextarg.ends_with(";auto") {
                global.operations[idx].autoreferer = true;
                len -= 5;
            } else {
                global.operations[idx].autoreferer = false;
            }
            if len > 0 {
                getstrn(&mut global.operations[idx].referer, nextarg, len, true)?;
            } else {
                global.operations[idx].referer = None;
            }
        }
        OptId::CertType => getstr(&mut global.operations[idx].cert_type, nextarg, false)?,
        OptId::KeyType => getstr(&mut global.operations[idx].key_type, nextarg, false)?,
        OptId::Pass => getstr(&mut global.operations[idx].key_passwd, nextarg, false)?,
        OptId::Engine => {
            getstr(&mut global.operations[idx].engine, nextarg, false)?;
            if global.operations[idx].engine.as_deref() == Some("list") {
                return Err(ParameterError::EnginesRequested);
            }
        }
        OptId::Ech => parse_ech(global, nextarg)?,
        OptId::Pubkey => getstr(&mut global.operations[idx].pubkey, nextarg, false)?,
        OptId::Hostpubmd5 => {
            getstr(&mut global.operations[idx].hostpubmd5, nextarg, false)?;
            match global.operations[idx].hostpubmd5.as_deref() {
                Some(s) if s.len() == 32 => {}
                _ => return Err(ParameterError::BadUse),
            }
        }
        OptId::Hostpubsha256 => {
            // C gates `--hostpubsha256` on `feature_libssh2` (a libssh2 new
            // enough to hash host keys with SHA256). This build's `russh`
            // backend *always* supports SHA256 host-key fingerprints — the
            // `verify_host_key` SHA256 path honors `CURLOPT_SSH_HOST_PUBLIC_KEY_
            // SHA256` and rejects on mismatch — so the faithful capability gate
            // is SSH-backend presence rather than the (always-false) libssh2 bit.
            if !feat::ssh() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            getstr(&mut global.operations[idx].hostpubsha256, nextarg, false)?;
        }
        OptId::Tlsuser => {
            if !feat::tls_srp() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            getstr(&mut global.operations[idx].tls_username, nextarg, false)?;
        }
        OptId::Tlspassword => {
            if !feat::tls_srp() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            getstr(&mut global.operations[idx].tls_password, nextarg, true)?;
        }
        OptId::Tlsauthtype => {
            if !feat::tls_srp() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            getstr(&mut global.operations[idx].tls_authtype, nextarg, false)?;
            if let Some(s) = global.operations[idx].tls_authtype.as_deref() {
                if s != "SRP" {
                    return Err(ParameterError::LibcurlDoesntSupport);
                }
            }
        }
        OptId::Pinnedpubkey => getstr(&mut global.operations[idx].pinnedpubkey, nextarg, false)?,
        OptId::ProxyPinnedpubkey => {
            getstr(
                &mut global.operations[idx].proxy_pinnedpubkey,
                nextarg,
                false,
            )?;
        }
        OptId::ProxyTlsuser => {
            if !feat::tls_srp() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            getstr(
                &mut global.operations[idx].proxy_tls_username,
                nextarg,
                true,
            )?;
        }
        OptId::ProxyTlspassword => {
            if !feat::tls_srp() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            getstr(
                &mut global.operations[idx].proxy_tls_password,
                nextarg,
                false,
            )?;
        }
        OptId::ProxyTlsauthtype => {
            if !feat::tls_srp() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            getstr(
                &mut global.operations[idx].proxy_tls_authtype,
                nextarg,
                false,
            )?;
            if let Some(s) = global.operations[idx].proxy_tls_authtype.as_deref() {
                if s != "SRP" {
                    return Err(ParameterError::LibcurlDoesntSupport);
                }
            }
        }
        OptId::ProxyCertType => {
            getstr(&mut global.operations[idx].proxy_cert_type, nextarg, false)?
        }
        OptId::ProxyKeyType => getstr(&mut global.operations[idx].proxy_key_type, nextarg, false)?,
        OptId::ProxyPass => getstr(&mut global.operations[idx].proxy_key_passwd, nextarg, true)?,
        OptId::ProxyCiphers => {
            getstr(
                &mut global.operations[idx].proxy_cipher_list,
                nextarg,
                false,
            )?;
        }
        OptId::LoginOptions => getstr(&mut global.operations[idx].login_options, nextarg, true)?,
        OptId::Curves => getstr(&mut global.operations[idx].ssl_ec_curves, nextarg, false)?,
        OptId::SignatureAlgorithms => {
            getstr(
                &mut global.operations[idx].ssl_signature_algorithms,
                nextarg,
                false,
            )?;
        }
        OptId::Form | OptId::FormString => {
            let literal = id == OptId::FormString;
            // `formparse` borrows `global` (for `warnf` diagnostics) and the
            // operation it mutates (`&mut OperationConfig`) as separate
            // parameters. Here that operation is `global.operations[idx]` — a
            // field of `global` — so passing both directly would be a
            // shared/mutable borrow conflict. Swap the operation out to a local
            // for the duration of the call (its accumulated `mimeroot` state
            // travels with it) and restore it immediately afterward. The
            // diagnostic functions read only top-level `global` flags, so the
            // temporary `Default` placeholder left in the slot is invisible.
            let mut op = std::mem::take(&mut global.operations[idx]);
            let formres = crate::formparse::formparse(global, &mut op, nextarg, literal);
            global.operations[idx] = op;
            if formres.is_err() {
                return Err(ParameterError::BadUse);
            }
            if set_httprequest(global, idx, HttpReq::MimePost) {
                return Err(ParameterError::BadUse);
            }
        }
        OptId::RequestTarget => getstr(&mut global.operations[idx].request_target, nextarg, false)?,
        OptId::Header | OptId::ProxyHeader => parse_header(global, id, nextarg)?,
        OptId::MaxTime => global.operations[idx].timeout_ms = secs2ms(nextarg)?,
        OptId::OutputDir => getstr(&mut global.operations[idx].output_dir, nextarg, false)?,
        OptId::FtpPort => getstr(&mut global.operations[idx].ftpport, nextarg, false)?,
        OptId::FtpSslCccMode => {
            global.operations[idx].ftp_ssl_ccc = true;
            let v = ftpcccmethod(global, nextarg);
            global.operations[idx].ftp_ssl_ccc_mode = v;
        }
        OptId::Quote => parse_quote(global, nextarg)?,
        OptId::Range => parse_range(global, nextarg)?,
        OptId::TelnetOption => add2list(&mut global.operations[idx].telnet_options, nextarg),
        OptId::User => getstr(&mut global.operations[idx].userpwd, nextarg, true)?,
        OptId::ProxyUser => getstr(&mut global.operations[idx].proxyuserpwd, nextarg, true)?,
        OptId::WriteOut => parse_writeout(global, nextarg)?,
        OptId::Preproxy => getstr(&mut global.operations[idx].preproxy, nextarg, false)?,
        OptId::Proxy => {
            getstr(&mut global.operations[idx].proxy, nextarg, true)?;
            if global.operations[idx].proxyver != CURLPROXY_HTTPS2 {
                global.operations[idx].proxyver = CURLPROXY_HTTP;
            }
        }
        OptId::Request => getstr(&mut global.operations[idx].customrequest, nextarg, false)?,
        OptId::SpeedTime => {
            global.operations[idx].low_speed_time = str2unum(nextarg)?;
            if global.operations[idx].low_speed_limit == 0 {
                global.operations[idx].low_speed_limit = 1;
            }
        }
        OptId::SpeedLimit => {
            global.operations[idx].low_speed_limit = str2unum(nextarg)?;
            if global.operations[idx].low_speed_time == 0 {
                global.operations[idx].low_speed_time = 30;
            }
        }
        OptId::ParallelHost => {
            let val = str2unum(nextarg)?;
            global.parallel_host = if val > i64::from(MAX_PARALLEL_HOST) {
                MAX_PARALLEL_HOST
            } else if val < 1 {
                PARALLEL_HOST_DEFAULT
            } else {
                val as u16
            };
        }
        OptId::ParallelMax => {
            let val = str2unum(nextarg)?;
            global.parallel_max = if val > i64::from(MAX_PARALLEL) {
                MAX_PARALLEL
            } else if val < 1 {
                PARALLEL_DEFAULT
            } else {
                val as u16
            };
        }
        OptId::TimeCond => parse_time_cond(global, nextarg)?,
        OptId::UploadFlags => parse_upload_flags(global, nextarg)?,
        // Any other id reaching opt_string is a table/dispatch mismatch.
        _ => {}
    }
    Ok(())
}

// ===========================================================================
// get_parameter / parse_args — the top-level argv resolver and driver
// (← `getparameter` / `parse_args`, `src/tool_getparam.c`).
//
// `get_parameter` resolves a single `flag` (long or short, with `--no-`/
// `--expand-` prefixes, inline `=value`/`-ovalue` forms, and short clusters)
// to one or more options and applies each via the `opt_*` sub-dispatchers.
// `parse_args` walks the whole argv vector, feeding flags to `get_parameter`
// and bare arguments to the synthetic `--url` option, honoring `--` (end of
// options) and `--next` (start a new transfer).
// ===========================================================================

/// The longest command-line option, excluding the leading `--`
/// (C `MAX_OPTION_LEN`, `tool_getparam.c`). The option *name* preceding an
/// inline `=value` is bounded by this length when splitting long options.
const MAX_OPTION_LEN: usize = 26;

/// `has_leading_unicode` (`tool_getparam.c`): `true` when `arg` begins with the
/// UTF-8 lead bytes `0xE2 0x80 …` — the block that holds "smart" quotes and
/// dashes (U+2000–U+203x). curl warns in this case because the user most likely
/// pasted a Unicode look-alike where ASCII was intended.
fn has_leading_unicode(arg: &str) -> bool {
    let b = arg.as_bytes();
    b.len() >= 3 && b[0] == 0xe2 && b[1] == 0x80 && (b[2] & 0x80) != 0
}

/// `getparameter` (`tool_getparam.c`): resolve `flag` to an option (or, for a
/// short cluster, a sequence of options) and apply each one to `global`.
///
/// This is a faithful port of curl's `getparameter`:
/// * **Long options** (`flag` is `--name`, or has no leading dash at all when
///   called from a config file): an optional `no-` prefix flips the boolean
///   toggle (and requires an `ARG_BOOL` option, else
///   [`ParameterError::NoPrefix`]); an optional `expand-` prefix runs
///   [`GlobalConfig::var_expand`] on the value (only valid for string/filename
///   options, else [`ParameterError::ExpandError`]); an inline `=value`
///   (name ≤ [`MAX_OPTION_LEN`] bytes) supplies the argument without consuming
///   the next argv element.
/// * **Short options** (`-x`): each letter in the cluster is resolved via
///   [`find_short_opt`]; a value-taking letter consumes the rest of the cluster
///   as its argument (`-ovalue`) or the separate next argv element (`-o value`).
/// * The `ARG_TLS` gate, the `--help` special-case, the deprecation
///   interception ([`opt_depr`]), the leading-Unicode warning, and the
///   `verbose_nopts` counter (for `-vvv` escalation) are reproduced exactly.
///
/// `usedarg` is set to `true` when the *separate* next argv element was consumed
/// as this option's value (so the caller skips it).
///
/// # Errors
/// Returns the precise [`ParameterError`] curl would for the same input —
/// including the "informational" sentinels ([`ParameterError::HelpRequested`],
/// [`ParameterError::NextOperation`], …) that the caller interprets specially.
pub fn get_parameter(
    global: &mut GlobalConfig,
    flag: &str,
    sep_nextarg: Option<&str>,
    usedarg: &mut bool,
    max_recursive: i32,
) -> Result<(), ParameterError> {
    // verbose_nopts = 0; — reset the per-flag option counter so the first `-v`
    // in a `-vvv` cluster resets verbosity (see `parse_verbose`).
    VERBOSE_NOPTS.with(|c| c.set(0));

    // default is that we do not use the separate arg
    *usedarg = false;

    // how to switch boolean options, on or off (controlled by `--no-`)
    let mut toggle = true;
    // whether the value argument is separate (consumes the next argv element)
    let mut consumearg = true;
    // when true means `-o foo` was given as `-ofoo` (do not loop anymore)
    let mut singleopt = false;
    let longopt;
    // the pre-resolved option for a long flag (None while parsing a short
    // cluster, where the option is resolved per letter inside the loop)
    let long_a: Option<&'static Alias>;
    // owns an expanded `--expand-…` value for the lifetime of this call (stays
    // `None` for short options and for long options without expansion)
    let mut expanded_holder: Option<String> = None;
    // the value passed to the option (inline `=value`, the separate arg, or an
    // expanded value); may be replaced by the `-ovalue` form inside the loop
    let mut cur_nextarg: Option<&str>;

    let bytes = flag.as_bytes();
    // C inspects flag[0] and flag[1]; flag is NUL-terminated there, so flag[1]
    // of a one-character flag is '\0'. Mirror that with a 0 sentinel.
    let first = bytes.first().copied().unwrap_or(0);
    let second = bytes.get(1).copied().unwrap_or(0);

    if first != b'-' || second == b'-' {
        // ---- this should be a long name ----
        longopt = true;
        // word = ('-' == flag[0]) ? flag + 2 : flag
        let mut word: &str = if first == b'-' { &flag[2..] } else { flag };
        let mut noflagged = false;
        let mut expand = false;

        if let Some(rest) = word.strip_prefix("no-") {
            // disable this option but ignore the "no-" part when looking for it
            word = rest;
            toggle = false;
            noflagged = true;
        } else if let Some(rest) = word.strip_prefix("expand-") {
            // variable expansions is to be done on the argument
            word = rest;
            expand = true;
        }

        // is there an '=' within the first MAX_OPTION_LEN bytes of the name?
        let mut inline_val: Option<&str> = None;
        let resolved = match word.find('=') {
            Some(eq) if (1..=MAX_OPTION_LEN).contains(&eq) => {
                // there is an equal sign: split name=value
                inline_val = Some(&word[eq + 1..]);
                consumearg = false; // it is not separate
                find_long_opt(&word[..eq])?
            }
            _ => find_long_opt(word)?,
        };
        long_a = Some(resolved);

        // inline value (if any) overrides the separate next argv element
        let candidate = inline_val.or(sep_nextarg);

        if noflagged && resolved.argtype() != ARG_BOOL {
            // --no- prefixed an option that is not boolean!
            return Err(ParameterError::NoPrefix);
        }

        if expand {
            if let Some(na) = candidate {
                if resolved.argtype() != ARG_STRG && resolved.argtype() != ARG_FILE {
                    // --expand on an option that is not a string or filename
                    return Err(ParameterError::ExpandError);
                }
                let (expanded, replaced) = global.var_expand(na)?;
                if replaced {
                    expanded_holder = Some(expanded);
                }
            }
        }
        cur_nextarg = match &expanded_holder {
            Some(s) => Some(s.as_str()),
            None => candidate,
        };
    } else {
        // ---- prefixed with one dash: short option(s) ----
        longopt = false;
        long_a = None;
        cur_nextarg = sep_nextarg;
    }

    // The short-cluster cursor. For a long option these are unused (the loop
    // runs exactly once and breaks on `longopt`).
    let short: &str = if longopt { "" } else { &flag[1..] };
    let short_bytes = short.as_bytes();
    let mut pos = 0usize;

    let mut err: Result<(), ParameterError> = Ok(());

    loop {
        // we can loop here if we have multiple single-letters
        let a: &'static Alias = if let Some(la) = long_a {
            la
        } else {
            // findshortopt(*parse); a one-char flag ("-") yields '\0', which
            // `find_short_opt` rejects exactly as curl's range check does.
            let letter = if pos < short_bytes.len() {
                char::from(short_bytes[pos])
            } else {
                '\0'
            };
            match find_short_opt(letter) {
                Ok(x) => {
                    toggle = !x.arg_no();
                    x
                }
                Err(e) => {
                    err = Err(e);
                    break;
                }
            }
        };

        if a.tls() && !feat::ssl() {
            // option requires TLS support the build lacks (never reached when
            // rustls is compiled in, but kept for parity)
            err = Err(ParameterError::LibcurlDoesntSupport);
            break;
        } else if a.requires_arg() {
            // this option requires an extra parameter
            if !longopt && pos + 1 < short_bytes.len() {
                // `-ofoo`: the rest of the cluster is the actual parameter
                cur_nextarg = Some(&short[pos + 1..]);
                singleopt = true; // do not loop anymore after this
            } else if a.id == OptId::Help {
                // --help is special: rendering is performed by the caller
                // (operate.rs → crate::help::tool_help). Capture the optional
                // category argument exactly as C does
                // (`tool_help((nextarg && *nextarg) ? nextarg : NULL)`): a
                // present, non-empty token becomes the category, otherwise the
                // default page is requested. The outer parse loop stops on this
                // `Err`, so the captured token is never reprocessed as a URL.
                global.help_category = cur_nextarg.filter(|s| !s.is_empty()).map(str::to_string);
                err = Err(ParameterError::HelpRequested);
                break;
            } else if cur_nextarg.is_none() {
                err = Err(ParameterError::RequiresParameter);
                break;
            } else {
                *usedarg = consumearg; // mark it as used
            }
            if a.deprecated() {
                opt_depr(global, a.lname);
                break;
            }
            let na = cur_nextarg.expect("requires-arg path guarantees a value");
            if has_leading_unicode(na) {
                warnf(
                    global,
                    &format!(
                        "The argument '{na}' starts with a Unicode character. \
                         Maybe ASCII was intended?"
                    ),
                );
            }
            err = if a.is_file() {
                opt_file(global, a.id, na, max_recursive)
            } else {
                opt_string(global, a.id, na)
            };
            // ARG_CLEAR (scrub the argv buffer after use) is a no-op in safe
            // Rust — `argv` is owned `String`s the OS never re-reads.
        } else {
            // ARG_NONE | ARG_BOOL
            if a.deprecated() {
                opt_depr(global, a.lname);
                break;
            }
            err = if a.is_bool() {
                opt_bool(global, a.id, toggle)
            } else {
                opt_none(global, a.id)
            };
        }

        // processed one option from `flag` input, loop for more
        VERBOSE_NOPTS.with(|c| c.set(c.get() + 1));

        // while(!longopt && !singleopt && *++parse && !*usedarg && !err)
        if longopt || singleopt {
            break;
        }
        pos += 1;
        if pos >= short_bytes.len() {
            break;
        }
        if *usedarg || err.is_err() {
            break;
        }
    }

    err
}

/// `parse_args` (`tool_getparam.c`): the argv driver loop.
///
/// Walks `argv[1..]`, classifying each element:
/// * `--` switches off flag processing (so a subsequent URL may start with `-`).
/// * Any other element starting with `-` is a flag, dispatched to
///   [`get_parameter`] (with the following element offered as its value); when
///   the value is consumed the loop skips that element.
/// * Everything else is a bare argument, fed to the synthetic `--url` option
///   (appended to the current transfer's URL list).
///
/// [`ParameterError::NextOperation`] (from `--next`) is handled here: a new
/// [`OperationConfig`] is started via [`GlobalConfig::add_operation`], but only
/// when the current transfer already has a URL (else `missing URL before
/// --next` and [`ParameterError::BadUse`]). On a terminal error the curl-style
/// `helpf` diagnostic is emitted (prefixed with the offending option when
/// known), except for the informational request sentinels.
///
/// `argv` includes `argv[0]` (the program name), which is skipped, matching the
/// C entry contract.
///
/// # Errors
/// Propagates the first [`ParameterError`] encountered (after emitting the
/// `helpf` hint for non-informational errors), or the
/// [`ParameterError::ContdispResumeFrom`] consistency error detected after the
/// scan.
pub fn parse_args(global: &mut GlobalConfig, argv: &[String]) -> Result<(), ParameterError> {
    let argc = argv.len();
    let mut stillflags = true;
    // the option text most recently seen, used for the `helpf` diagnostic; it
    // is cleared (set to None) once an element parses without error
    let mut orig_opt: Option<&str> = None;
    let mut err: Result<(), ParameterError> = Ok(());

    let mut i = 1usize;
    while i < argc && err.is_ok() {
        let cur = argv[i].as_str();
        orig_opt = Some(cur);

        if stillflags && cur.as_bytes().first() == Some(&b'-') {
            if cur == "--" {
                // end of the flags; the following (URL) argument may start
                // with '-'
                stillflags = false;
            } else {
                let nextarg: Option<&str> = if i + 1 < argc {
                    Some(argv[i + 1].as_str())
                } else {
                    None
                };
                let mut passarg = false;
                err = get_parameter(global, cur, nextarg, &mut passarg, CONFIG_MAX_LEVELS);

                // config = global->last — the "current" operation is always
                // global.operations[global.current]; nothing to reassign here.
                match err {
                    Err(ParameterError::NextOperation) => {
                        // PARAM_NEXT_OPERATION is only used here and not
                        // returned from this function
                        err = Ok(());
                        let idx = global.current;
                        let has_url = global.operations[idx]
                            .url_list
                            .first()
                            .is_some_and(|g| g.url.is_some());
                        if has_url {
                            // allocate and move onto the next config
                            global.add_operation();
                        } else {
                            errorf(global, "missing URL before --next");
                            err = Err(ParameterError::BadUse);
                        }
                    }
                    Ok(()) => {
                        if passarg {
                            i += 1; // we are supposed to skip this
                        }
                    }
                    Err(_) => {}
                }
            }
        } else {
            // Just add the URL please
            let mut used = false;
            err = get_parameter(global, "--url", Some(cur), &mut used, 0);
        }

        if err.is_ok() {
            orig_opt = None;
        }
        i += 1;
    }

    if err.is_ok() {
        let idx = global.current;
        if global.operations[idx].content_disposition && global.operations[idx].resume_from_current
        {
            err = Err(ParameterError::ContdispResumeFrom);
        }
    }

    if let Err(e) = err {
        if !matches!(
            e,
            ParameterError::HelpRequested
                | ParameterError::ManualRequested
                | ParameterError::VersionInfoRequested
                | ParameterError::EnginesRequested
                | ParameterError::CaEmbedRequested
        ) {
            let reason = param2text(e);
            match orig_opt {
                Some(o) if o != ":" => helpf(Some(&format!("option {o}: {reason}"))),
                _ => helpf(Some(reason)),
            }
        }
    }

    err
}

// ===========================================================================
// build_cli — the clap command model (← the help/usage/completion half of the
// dual model; prompt Phase C). Replaces tool_help.c / tool_hugehelp.c, which
// are OUT OF SCOPE to port: help/usage text and shell completions are produced
// by clap from this model plus `curl_rs_lib::version` data.
// ===========================================================================

/// Build the `clap` command model from the [`ALIASES`] table — the
/// help / usage / completion half of curl-rs's **dual parsing model**.
///
/// `curl-rs` deliberately does NOT parse argv with `clap`. The authoritative,
/// curl-faithful semantics — exact (non-prefix) long-option matching, the
/// `--no-`/`--expand-` prefixes, short-option cluster splitting, repeated-option
/// accumulation, and each option's precise argument arity — live in
/// [`get_parameter`] / [`parse_args`]. `clap` does not reproduce those behaviors
/// identically, so it is used ONLY to render `--help` / `--help all`, the usage
/// line, and shell completions (via `clap_complete`), and as a structural
/// cross-check that every row in the table is a well-formed option.
///
/// One [`clap::Arg`] is emitted per [`ALIASES`] row:
/// * `--<lname>` for the long name, plus `-<letter>` when `letter != ' '`;
/// * a value-taking action ([`clap::ArgAction::Set`]) for `ARG_STRG`/`ARG_FILE`
///   options, or a flag action ([`clap::ArgAction::SetTrue`]) for
///   `ARG_BOOL`/`ARG_NONE` options.
///
/// Intentional, documented omissions (they are parsing concerns handled by
/// [`get_parameter`], not help/completion concerns): curl's `--no-<name>`
/// negations do not appear as separate clap args, and the per-option help-text
/// bodies (curl's `tool_hugehelp.c`) are out of scope — only the flag
/// *structure* is modeled. clap's built-in `-h`/`--help` and `-V`/`--version`
/// auto-flags are disabled so the `help` and `version` rows from the table own
/// those letters exactly as curl does. The `<url>` operand is shown via the
/// usage override rather than a clap positional, keeping the model strictly
/// option-table-driven.
#[must_use]
pub fn build_cli() -> clap::Command {
    use clap::{Arg, ArgAction, Command};

    let mut cmd = Command::new("curl")
        .version(version::VERSION)
        .about("curl-rs — a memory-safe Rust reimplementation of curl: transfer a URL")
        .override_usage("curl [options...] <url>")
        // curl supplies its own `--help`/`-h` and `--version`/`-V` through the
        // option table, so clap's auto-generated flags are disabled to avoid
        // colliding with the `help` and `version` rows.
        .disable_help_flag(true)
        .disable_version_flag(true);

    for a in ALIASES {
        let mut arg = Arg::new(a.lname).long(a.lname);
        if a.letter != ' ' {
            arg = arg.short(a.letter);
        }
        arg = if a.requires_arg() {
            // ARG_STRG / ARG_FILE — takes exactly one value
            arg.action(ArgAction::Set).num_args(1)
        } else {
            // ARG_BOOL / ARG_NONE — a flag with no value
            arg.action(ArgAction::SetTrue)
        };
        cmd = cmd.arg(arg);
    }

    cmd
}

#[cfg(test)]
mod phase_d_tests {
    //! Focused tests for the numeric/string/proto/file helpers
    //! (← `tool_paramhlp.c` / `tool_getparam.c`). These verify the
    //! parity-critical edge cases called out in the AAP validation checklist.
    use super::*;

    #[test]
    fn str2num_basic_and_edges() {
        assert_eq!(str2num("123"), Ok(123));
        assert_eq!(str2num("0"), Ok(0));
        assert_eq!(str2num("-5"), Ok(-5));
        // non-numeric -> BadNumeric
        assert_eq!(str2num("abc"), Err(ParameterError::BadNumeric));
        assert_eq!(str2num(""), Err(ParameterError::BadNumeric));
        // trailing garbage -> BadNumeric
        assert_eq!(str2num("12x"), Err(ParameterError::BadNumeric));
        // overflow folds into BadNumeric here (curl behavior)
        assert_eq!(
            str2num("99999999999999999999999"),
            Err(ParameterError::BadNumeric)
        );
    }

    #[test]
    fn str2unum_rejects_negative() {
        assert_eq!(str2unum("5"), Ok(5));
        assert_eq!(str2unum("-5"), Err(ParameterError::NegativeNumeric));
        assert_eq!(str2unum("x"), Err(ParameterError::BadNumeric));
    }

    #[test]
    fn str2unummax_bounds() {
        assert_eq!(str2unummax("40", 50), Ok(40));
        assert_eq!(str2unummax("50", 50), Ok(50));
        assert_eq!(str2unummax("100", 50), Err(ParameterError::NumberTooLarge));
        assert_eq!(str2unummax("-1", 50), Err(ParameterError::NegativeNumeric));
    }

    #[test]
    fn oct2nummax_parses_octal() {
        assert_eq!(oct2nummax("0", 0o7777), Ok(0));
        assert_eq!(oct2nummax("644", 0o7777), Ok(0o644));
        assert_eq!(oct2nummax("777", 0o7777), Ok(0o777));
        // '8' is not an octal digit -> no number -> BadNumeric
        assert_eq!(oct2nummax("8", 0o7777), Err(ParameterError::BadNumeric));
        // beyond max -> NumberTooLarge
        assert_eq!(
            oct2nummax("77777", 0o7777),
            Err(ParameterError::NumberTooLarge)
        );
    }

    #[test]
    fn str2offset_positive_only() {
        assert_eq!(str2offset("1048576"), Ok(1_048_576));
        assert_eq!(str2offset("-1"), Err(ParameterError::BadNumeric));
        assert_eq!(str2offset("12x"), Err(ParameterError::BadNumeric));
    }

    #[test]
    fn secs2ms_fractions() {
        assert_eq!(secs2ms("1"), Ok(1000));
        assert_eq!(secs2ms("1.5"), Ok(1500));
        assert_eq!(secs2ms("0.001"), Ok(1));
        assert_eq!(secs2ms("2.345"), Ok(2345));
    }

    #[test]
    fn get_size_parameter_suffixes() {
        assert_eq!(get_size_parameter("1024"), Ok(1024));
        assert_eq!(get_size_parameter("1k"), Ok(1024));
        assert_eq!(get_size_parameter("1K"), Ok(1024));
        assert_eq!(get_size_parameter("2M"), Ok(2 * 1024 * 1024));
        assert_eq!(get_size_parameter("1.5k"), Ok(1536));
        assert_eq!(get_size_parameter("1b"), Ok(1));
        // partial bytes are rejected
        assert_eq!(get_size_parameter("1.5b"), Err(ParameterError::BadUse));
        // multi-char or unknown suffix
        assert_eq!(get_size_parameter("1xy"), Err(ParameterError::BadUse));
        assert_eq!(get_size_parameter("1q"), Err(ParameterError::BadUse));
    }

    #[test]
    fn str2tls_max_table() {
        assert_eq!(str2tls_max(Some("default")), Ok(0));
        assert_eq!(str2tls_max(Some("1.0")), Ok(1));
        assert_eq!(str2tls_max(Some("1.3")), Ok(4));
        assert_eq!(str2tls_max(None), Err(ParameterError::RequiresParameter));
        assert_eq!(str2tls_max(Some("9.9")), Err(ParameterError::BadUse));
    }

    #[test]
    fn proto_token_case_insensitive() {
        assert_eq!(proto_token("HTTP"), Some("http"));
        assert_eq!(proto_token("https"), Some("https"));
        assert_eq!(proto_token("definitely-not-a-proto"), None);
    }

    #[test]
    fn check_protocol_validates() {
        assert_eq!(check_protocol(Some("http")), Ok(()));
        assert_eq!(check_protocol(None), Err(ParameterError::RequiresParameter));
        assert_eq!(
            check_protocol(Some("zzz")),
            Err(ParameterError::LibcurlUnsupportedProtocol)
        );
    }

    #[test]
    fn parse_cert_parameter_splits() {
        assert_eq!(
            parse_cert_parameter("cert.pem"),
            Ok(("cert.pem".to_string(), None))
        );
        assert_eq!(
            parse_cert_parameter("cert.pem:secret"),
            Ok(("cert.pem".to_string(), Some("secret".to_string())))
        );
        // pkcs11 URIs are used verbatim
        assert_eq!(
            parse_cert_parameter("pkcs11:token"),
            Ok(("pkcs11:token".to_string(), None))
        );
        // escaped colon stays in the name; the next bare colon splits
        assert_eq!(
            parse_cert_parameter("c\\:d:pass"),
            Ok(("c:d".to_string(), Some("pass".to_string())))
        );
        assert_eq!(parse_cert_parameter(""), Err(ParameterError::BlankString));
    }
}

#[cfg(test)]
mod parse_tests {
    //! Runtime tests for [`get_parameter`] and [`parse_args`] — the long/short
    //! resolver and the argv driver (← `getparameter` / `parse_args`,
    //! `src/tool_getparam.c`). These verify the externally observable parsing
    //! contract: short clusters, inline values, `--no-`/`=value` forms, `--`
    //! end-of-options, bare-URL collection, `--next`, exact (non-prefix)
    //! long-option matching, and the precise [`ParameterError`] outcomes.

    use super::*;

    /// Build an argv vector with a synthetic `argv[0]` program name (which
    /// [`parse_args`] skips, mirroring the C entry contract).
    fn argv(items: &[&str]) -> Vec<String> {
        let mut v = vec!["curl".to_string()];
        v.extend(items.iter().map(|s| (*s).to_string()));
        v
    }

    /// Parse `items` into a fresh [`GlobalConfig`] and return both for asserts.
    fn run(items: &[&str]) -> (GlobalConfig, Result<(), ParameterError>) {
        let mut g = GlobalConfig::new();
        let r = parse_args(&mut g, &argv(items));
        (g, r)
    }

    #[test]
    fn short_verbose_sets_verbosity() {
        let (g, r) = run(&["-v"]);
        assert_eq!(r, Ok(()));
        assert_eq!(g.verbosity, 1);
        assert_eq!(g.tracetype, TraceType::Plain);
    }

    #[test]
    fn long_verbose_sets_verbosity() {
        let (g, r) = run(&["--verbose"]);
        assert_eq!(r, Ok(()));
        assert_eq!(g.verbosity, 1);
    }

    #[test]
    fn super_verbose_cluster_escalates() {
        // `-vvv` is a single flag: verbose_nopts resets once, then escalates.
        let (g, r) = run(&["-vvv"]);
        assert_eq!(r, Ok(()));
        assert_eq!(g.verbosity, 3);
    }

    #[test]
    fn double_verbose_cluster_escalates_to_two() {
        let (g, r) = run(&["-vv"]);
        assert_eq!(r, Ok(()));
        assert_eq!(g.verbosity, 2);
    }

    #[test]
    fn separate_verbose_flags_do_not_escalate() {
        // Each separate `-v` resets verbose_nopts, so verbosity stays at 1.
        let (g, r) = run(&["-v", "-v", "-v"]);
        assert_eq!(r, Ok(()));
        assert_eq!(g.verbosity, 1);
    }

    #[test]
    fn bare_argument_becomes_url() {
        let (g, r) = run(&["http://example.com/"]);
        assert_eq!(r, Ok(()));
        assert_eq!(
            g.operations[0].url_list[0].url.as_deref(),
            Some("http://example.com/")
        );
    }

    #[test]
    fn short_output_separate_arg() {
        let (g, r) = run(&["-o", "out.txt"]);
        assert_eq!(r, Ok(()));
        assert_eq!(
            g.operations[0].url_list[0].outfile.as_deref(),
            Some("out.txt")
        );
    }

    #[test]
    fn short_output_inline_value() {
        // `-oout.txt` — the rest of the cluster is the value (singleopt).
        let (g, r) = run(&["-oout.txt"]);
        assert_eq!(r, Ok(()));
        assert_eq!(
            g.operations[0].url_list[0].outfile.as_deref(),
            Some("out.txt")
        );
    }

    #[test]
    fn long_output_inline_equals_value() {
        let (g, r) = run(&["--output=out.txt"]);
        assert_eq!(r, Ok(()));
        assert_eq!(
            g.operations[0].url_list[0].outfile.as_deref(),
            Some("out.txt")
        );
    }

    #[test]
    fn negation_prefix_toggles_boolean() {
        // BUFFER maps nobuffer = !toggle; `--no-buffer` => nobuffer == true.
        let (g, r) = run(&["--no-buffer"]);
        assert_eq!(r, Ok(()));
        assert!(g.operations[0].nobuffer);
    }

    #[test]
    fn positive_boolean_clears_flag() {
        let (g, r) = run(&["--buffer"]);
        assert_eq!(r, Ok(()));
        assert!(!g.operations[0].nobuffer);
    }

    #[test]
    fn no_prefix_on_non_boolean_is_no_prefix_error() {
        // `--no-output` — Output is ARG_FILE, not ARG_BOOL => PARAM_NO_PREFIX.
        let (_g, r) = run(&["--no-output", "x"]);
        assert_eq!(r, Err(ParameterError::NoPrefix));
    }

    #[test]
    fn unknown_long_option_is_option_unknown() {
        let (_g, r) = run(&["--frobnicate"]);
        assert_eq!(r, Err(ParameterError::OptionUnknown));
    }

    #[test]
    fn partial_long_option_is_not_accepted() {
        // curl 8.19 does EXACT matching (bsearch+strcmp); `--verb` must NOT
        // resolve to `--verbose`.
        let (_g, r) = run(&["--verb"]);
        assert_eq!(r, Err(ParameterError::OptionUnknown));
    }

    #[test]
    fn missing_required_parameter() {
        let (_g, r) = run(&["-o"]);
        assert_eq!(r, Err(ParameterError::RequiresParameter));
    }

    #[test]
    fn double_dash_ends_option_processing() {
        // After `--`, an argument starting with '-' is a URL, not a flag.
        let (g, r) = run(&["--", "-weird-url"]);
        assert_eq!(r, Ok(()));
        assert_eq!(
            g.operations[0].url_list[0].url.as_deref(),
            Some("-weird-url")
        );
    }

    #[test]
    fn next_without_url_is_bad_use() {
        let (g, r) = run(&["--next"]);
        assert_eq!(r, Err(ParameterError::BadUse));
        assert_eq!(g.operations.len(), 1);
    }

    #[test]
    fn next_with_url_starts_new_operation() {
        let (g, r) = run(&["http://a/", "--next", "http://b/"]);
        assert_eq!(r, Ok(()));
        assert_eq!(g.operations.len(), 2);
        assert_eq!(
            g.operations[0].url_list[0].url.as_deref(),
            Some("http://a/")
        );
        assert_eq!(
            g.operations[1].url_list[0].url.as_deref(),
            Some("http://b/")
        );
    }

    #[test]
    fn data_option_populates_postdata() {
        let (g, r) = run(&["--data", "name=value"]);
        assert_eq!(r, Ok(()));
        let body = String::from_utf8_lossy(&g.operations[0].postdata);
        assert!(body.contains("name=value"), "postdata was {body:?}");
    }

    #[test]
    fn short_cluster_of_booleans_all_apply() {
        // `-sS`: silent + show-error (both global booleans).
        let (g, r) = run(&["-sS"]);
        assert_eq!(r, Ok(()));
        assert!(g.silent);
        assert!(g.showerror);
    }

    #[test]
    fn expand_prefix_on_value_without_variable_is_noop() {
        // `--expand-data plain` with no `{{...}}` expands to the input
        // unchanged (replaced == false), behaving like `--data plain`.
        let (g, r) = run(&["--expand-data", "plain"]);
        assert_eq!(r, Ok(()));
        let body = String::from_utf8_lossy(&g.operations[0].postdata);
        assert!(body.contains("plain"), "postdata was {body:?}");
    }

    #[test]
    fn expand_prefix_on_non_string_option_is_expand_error() {
        // `--expand-verbose foo`: Verbose is ARG_BOOL, not a string/filename,
        // so applying `--expand-` with an argument is PARAM_EXPAND_ERROR.
        let (_g, r) = run(&["--expand-verbose", "foo"]);
        assert_eq!(r, Err(ParameterError::ExpandError));
    }

    // ---- build_cli (the clap help/usage/completion model) -------------------

    #[test]
    fn build_cli_is_structurally_valid() {
        // clap's internal validation (duplicate ids/shorts, malformed names,
        // …) runs in debug_assert; it panics on any conflict, so a clean run
        // proves the whole ALIASES table maps to a well-formed clap command.
        build_cli().debug_assert();
    }

    #[test]
    fn build_cli_models_every_alias_plus_curl_help_version() {
        let cmd = build_cli();
        // Every option carries a long flag; the help/version rows keep their
        // short letters (clap's auto -h/-V are disabled).
        let has_long = |name: &str| cmd.get_arguments().any(|a| a.get_long() == Some(name));
        assert!(has_long("verbose"));
        assert!(has_long("help"));
        assert!(has_long("version"));
        assert!(has_long("abstract-unix-socket"));
        // -h and -V belong to curl's own rows, not clap.
        let short = |c: char| {
            cmd.get_arguments()
                .find(|a| a.get_short() == Some(c))
                .and_then(clap::Arg::get_long)
        };
        assert_eq!(short('h'), Some("help"));
        assert_eq!(short('V'), Some("version"));
        assert_eq!(short('v'), Some("verbose"));
    }

    #[test]
    fn build_cli_renders_help_without_panicking() {
        let mut cmd = build_cli();
        let help = cmd.render_help().to_string();
        assert!(help.contains("curl"));
        assert!(help.contains("--verbose"));
    }
}

// ===========================================================================
// Phase 7 — Parity audit & unit tests.
//
// These tests lock down the parity-critical invariants of the option
// inventory and of the public helper surface that the runtime parser tests
// (`parse_tests`) and the Phase D helper tests (`phase_d_tests`) do not assert
// directly:
//   * the 282-row `aliases[]` parity contract (count, ordering, uniqueness),
//   * the `find_long_opt` / `find_short_opt` lookups in isolation,
//   * the `Alias` descriptor accessor methods,
//   * the precise numeric-error mapping that drives curl's exit codes, and
//   * the `param2text` / `as_code` / `is_informational` exit-code surface.
// ===========================================================================
#[cfg(test)]
mod audit_tests {
    use super::*;

    // ---- 282-row parity audit -------------------------------------------

    /// The single most important invariant: the option inventory must contain
    /// exactly curl 8.x's 282 `aliases[]` rows. Any drift is a CLI-surface
    /// parity defect.
    #[test]
    fn aliases_row_count_is_exactly_282() {
        assert_eq!(
            ALIASES.len(),
            282,
            "ALIASES must mirror curl's 282 aliases[] rows"
        );
    }

    /// `find_long_opt` binary-searches [`ALIASES`], so the table MUST be sorted
    /// strictly ascending by `lname`. "Strictly" also proves there are no
    /// duplicate long names.
    #[test]
    fn aliases_sorted_ascending_and_unique_by_lname() {
        for w in ALIASES.windows(2) {
            assert!(
                w[0].lname < w[1].lname,
                "ALIASES not strictly ascending: {:?} >= {:?}",
                w[0].lname,
                w[1].lname
            );
        }
    }

    /// Every option must be reachable as `--<lname>`, so no row may carry an
    /// empty long name.
    #[test]
    fn aliases_have_nonempty_long_names() {
        for a in ALIASES {
            assert!(!a.lname.is_empty(), "empty lname for id {:?}", a.id);
        }
    }

    /// Each assigned short letter (anything other than the `' '` sentinel) must
    /// be unique — curl's `findshortopt` resolves a letter to exactly one
    /// option.
    #[test]
    fn short_letters_are_unique() {
        let mut seen: Vec<char> = Vec::new();
        for a in ALIASES {
            if a.letter != ' ' {
                assert!(
                    !seen.contains(&a.letter),
                    "duplicate short letter {:?}",
                    a.letter
                );
                seen.push(a.letter);
            }
        }
    }

    /// The id space must hold 282 *distinct* ids; combined with the row-count
    /// test this proves the `OptId` enum and [`ALIASES`] are 1:1 (every option
    /// has exactly one row).
    #[test]
    fn option_ids_are_all_distinct() {
        let mut ids: Vec<u16> = ALIASES.iter().map(|a| a.id as u16).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids.len(),
            282,
            "ALIASES must carry 282 distinct OptId values"
        );
    }

    // ---- direct lookups --------------------------------------------------

    #[test]
    fn find_long_opt_exact_hits() {
        assert_eq!(find_long_opt("output").unwrap().id, OptId::Output);
        assert_eq!(find_long_opt("verbose").unwrap().id, OptId::Verbose);
        assert_eq!(find_long_opt("url").unwrap().id, OptId::Url);
        assert_eq!(
            find_long_opt("abstract-unix-socket").unwrap().id,
            OptId::AbstractUnixSocket
        );
    }

    /// Exact-match semantics: both a wholly unknown name and a *prefix* of a
    /// real option miss (curl's `findlongopt` uses `strcmp`, never abbreviates).
    #[test]
    fn find_long_opt_miss_is_option_unknown() {
        assert_eq!(
            find_long_opt("frobnicate").unwrap_err(),
            ParameterError::OptionUnknown
        );
        assert_eq!(
            find_long_opt("verb").unwrap_err(),
            ParameterError::OptionUnknown
        );
        assert_eq!(
            find_long_opt("").unwrap_err(),
            ParameterError::OptionUnknown
        );
    }

    #[test]
    fn find_short_opt_valid_letters() {
        assert_eq!(find_short_opt('o').unwrap().id, OptId::Output);
        assert_eq!(find_short_opt('v').unwrap().id, OptId::Verbose);
        assert_eq!(find_short_opt('d').unwrap().id, OptId::Data);
    }

    /// curl's range guard rejects `letter <= ' '` and `letter >= 127`; `' '` is
    /// also the no-short-option sentinel.
    #[test]
    fn find_short_opt_rejects_space_and_out_of_range() {
        assert_eq!(
            find_short_opt(' ').unwrap_err(),
            ParameterError::OptionUnknown
        );
        assert_eq!(
            find_short_opt('\0').unwrap_err(),
            ParameterError::OptionUnknown
        );
        assert_eq!(
            find_short_opt('\u{7f}').unwrap_err(),
            ParameterError::OptionUnknown
        );
        assert_eq!(
            find_short_opt('\u{100}').unwrap_err(),
            ParameterError::OptionUnknown
        );
    }

    /// `'W'`, `'5'`, `'7'` are printable ASCII but assigned to no curl option,
    /// so they must miss.
    #[test]
    fn find_short_opt_unassigned_printable_letter_misses() {
        assert_eq!(
            find_short_opt('W').unwrap_err(),
            ParameterError::OptionUnknown
        );
        assert_eq!(
            find_short_opt('5').unwrap_err(),
            ParameterError::OptionUnknown
        );
        assert_eq!(
            find_short_opt('7').unwrap_err(),
            ParameterError::OptionUnknown
        );
    }

    // ---- Alias descriptor methods ---------------------------------------

    /// The argument-type predicates partition each option into exactly one of
    /// NONE / BOOL / STRG / FILE, and `requires_arg` is the `>= ARG_STRG` test.
    #[test]
    fn alias_argtype_methods() {
        let output = find_long_opt("output").unwrap(); // ARG_FILE
        let data = find_long_opt("data").unwrap(); // ARG_STRG
        let verbose = find_long_opt("verbose").unwrap(); // ARG_BOOL
        let tlsv1 = find_long_opt("tlsv1").unwrap(); // ARG_NONE | ARG_TLS

        // requires_arg: true for FILE/STRG, false for BOOL/NONE.
        assert!(output.requires_arg());
        assert!(data.requires_arg());
        assert!(!verbose.requires_arg());
        assert!(!tlsv1.requires_arg());

        // ARG_FILE row.
        assert!(output.is_file());
        assert!(!output.is_string());
        assert!(!output.is_bool());
        assert!(!output.is_none());

        // ARG_STRG row.
        assert!(data.is_string());
        assert!(!data.is_file());
        assert!(!data.is_bool());
        assert!(!data.is_none());

        // ARG_BOOL row.
        assert!(verbose.is_bool());
        assert!(!verbose.is_string());
        assert!(!verbose.is_file());
        assert!(!verbose.is_none());

        // ARG_NONE row (the TLS modifier does not change the type bits).
        assert!(tlsv1.is_none());
        assert!(!tlsv1.is_bool());
    }

    /// The high modifier bits (`ARG_NO`, `ARG_TLS`, `ARG_DEPR`) are independent
    /// of the argument type and must be read back exactly.
    #[test]
    fn alias_modifier_bits() {
        let alpn = find_long_opt("alpn").unwrap(); // ARG_BOOL | ARG_NO | ARG_TLS
        let sslv3 = find_long_opt("sslv3").unwrap(); // ARG_NONE | ARG_DEPR
        let output = find_long_opt("output").unwrap(); // ARG_FILE (no modifiers)

        assert!(alpn.arg_no(), "alpn carries ARG_NO");
        assert!(alpn.tls(), "alpn carries ARG_TLS");
        assert!(!alpn.deprecated());

        assert!(sslv3.deprecated(), "sslv3 carries ARG_DEPR");
        assert!(!sslv3.arg_no());

        assert!(!output.arg_no());
        assert!(!output.tls());
        assert!(!output.deprecated());
    }

    // ---- numeric edge cases (exit-code-critical) ------------------------

    #[test]
    fn str2num_non_numeric_is_bad_numeric() {
        assert_eq!(str2num("abc").unwrap_err(), ParameterError::BadNumeric);
        assert_eq!(str2num("12x").unwrap_err(), ParameterError::BadNumeric);
        assert_eq!(str2num("").unwrap_err(), ParameterError::BadNumeric);
    }

    /// `str2num` accepts a leading sign, and (matching curl) folds numeric
    /// overflow into `BadNumeric` rather than `NumberTooLarge`.
    #[test]
    fn str2num_accepts_sign_and_overflow_folds_to_bad_numeric() {
        assert_eq!(str2num("-5").unwrap(), -5);
        assert_eq!(str2num("0").unwrap(), 0);
        assert_eq!(
            str2num("99999999999999999999999999").unwrap_err(),
            ParameterError::BadNumeric
        );
    }

    #[test]
    fn str2unum_rejects_negative_value() {
        assert_eq!(str2unum("-1").unwrap_err(), ParameterError::NegativeNumeric);
        assert_eq!(str2unum("7").unwrap(), 7);
    }

    /// `str2unummax` must surface each distinct failure class with its own
    /// `ParameterError`, and the `max` bound is inclusive.
    #[test]
    fn str2unummax_distinguishes_each_failure() {
        assert_eq!(
            str2unummax("abc", 100).unwrap_err(),
            ParameterError::BadNumeric
        );
        assert_eq!(
            str2unummax("-1", 100).unwrap_err(),
            ParameterError::NegativeNumeric
        );
        assert_eq!(
            str2unummax("101", 100).unwrap_err(),
            ParameterError::NumberTooLarge
        );
        assert_eq!(str2unummax("100", 100).unwrap(), 100);
    }

    /// `oct2nummax` maps a bound overflow to `NumberTooLarge` and a non-octal
    /// digit to `BadNumeric`.
    #[test]
    fn oct2nummax_overflow_is_number_too_large() {
        // 0o1000 (=512) exceeds the 0o777 (=511) bound.
        assert_eq!(
            oct2nummax("1000", 0o777).unwrap_err(),
            ParameterError::NumberTooLarge
        );
        assert_eq!(oct2nummax("777", 0o777).unwrap(), 0o777);
        // '8' is not an octal digit.
        assert_eq!(
            oct2nummax("8", 0o777).unwrap_err(),
            ParameterError::BadNumeric
        );
    }

    /// `str2offset` accepts no sign, so a leading `-` is `BadNumeric`.
    #[test]
    fn str2offset_rejects_sign() {
        assert_eq!(str2offset("-1").unwrap_err(), ParameterError::BadNumeric);
        assert_eq!(str2offset("12345").unwrap(), 12345);
    }

    // ---- param2text / as_code / is_informational ------------------------

    /// `param2text` strings are part of the observable CLI surface; assert the
    /// representative set against curl's exact `param2text()` strings.
    #[test]
    fn param2text_matches_curl_strings() {
        assert_eq!(param2text(ParameterError::OptionUnknown), "is unknown");
        assert_eq!(
            param2text(ParameterError::RequiresParameter),
            "requires parameter"
        );
        assert_eq!(param2text(ParameterError::BadUse), "is badly used here");
        assert_eq!(
            param2text(ParameterError::BadNumeric),
            "expected a proper numerical parameter"
        );
        assert_eq!(
            param2text(ParameterError::NegativeNumeric),
            "expected a positive numerical parameter"
        );
        assert_eq!(
            param2text(ParameterError::NumberTooLarge),
            "too large number"
        );
        assert_eq!(param2text(ParameterError::NoMem), "out of memory");
        assert_eq!(
            param2text(ParameterError::NoPrefix),
            "the given option cannot be reversed with a --no- prefix"
        );
        assert_eq!(
            param2text(ParameterError::ContdispResumeFrom),
            "--continue-at and --remote-header-name cannot be combined"
        );
        assert_eq!(
            param2text(ParameterError::ReadError),
            "error encountered when reading a file"
        );
        assert_eq!(
            param2text(ParameterError::ExpandError),
            "variable expansion failure"
        );
        assert_eq!(
            param2text(ParameterError::BlankString),
            "blank argument where content is expected"
        );
        assert_eq!(
            param2text(ParameterError::VarSyntax),
            "syntax error in --variable argument"
        );
        assert_eq!(
            param2text(ParameterError::GotExtraParameter),
            "had unsupported trailing garbage"
        );
        assert_eq!(
            param2text(ParameterError::ConfigOptionUnknown),
            "found an unknown config option"
        );
        assert_eq!(
            param2text(ParameterError::LibcurlDoesntSupport),
            "the installed libcurl version does not support this"
        );
        assert_eq!(
            param2text(ParameterError::LibcurlUnsupportedProtocol),
            "a specified protocol is unsupported by libcurl"
        );
    }

    /// Codes with no dedicated C message fall through to curl's `default:` arm.
    #[test]
    fn param2text_default_is_unknown_error() {
        assert_eq!(param2text(ParameterError::Recursion), "unknown error");
        assert_eq!(param2text(ParameterError::NextOperation), "unknown error");
    }

    /// `as_code` returns the exact C discriminant used for exit-code mapping in
    /// `operate.rs`.
    #[test]
    fn as_code_matches_c_discriminants() {
        assert_eq!(ParameterError::OptionUnknown.as_code(), 1);
        assert_eq!(ParameterError::ConfigOptionUnknown.as_code(), 2);
        assert_eq!(ParameterError::RequiresParameter.as_code(), 3);
        assert_eq!(ParameterError::BadUse.as_code(), 4);
        assert_eq!(ParameterError::BadNumeric.as_code(), 11);
        assert_eq!(ParameterError::NextOperation.as_code(), 16);
        assert_eq!(ParameterError::NoPrefix.as_code(), 17);
        assert_eq!(ParameterError::NumberTooLarge.as_code(), 18);
        assert_eq!(ParameterError::Recursion.as_code(), 24);
    }

    /// Exactly the five request codes are "informational" (handled specially by
    /// `operate.rs` and excluded from the `parse_args` error diagnostic); all
    /// other codes are fatal parse errors.
    #[test]
    fn is_informational_only_for_request_codes() {
        for info in [
            ParameterError::HelpRequested,
            ParameterError::ManualRequested,
            ParameterError::VersionInfoRequested,
            ParameterError::EnginesRequested,
            ParameterError::CaEmbedRequested,
        ] {
            assert!(info.is_informational(), "{info:?} should be informational");
        }
        for fatal in [
            ParameterError::OptionUnknown,
            ParameterError::RequiresParameter,
            ParameterError::BadNumeric,
            ParameterError::NextOperation,
            ParameterError::NoPrefix,
        ] {
            assert!(
                !fatal.is_informational(),
                "{fatal:?} should not be informational"
            );
        }
    }
}
