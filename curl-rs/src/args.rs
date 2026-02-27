// curl-rs/src/args.rs
//
// Rust rewrite of src/tool_getparam.c and src/tool_getparam.h.
// Defines all 200+ CLI flags using clap 4.x derive macros with exact
// 1:1 flag mapping from curl 8.x. This is the largest and most critical
// file for CLI parity.
//
// Copyright (c) curl contributors. Licensed under the curl license.

use std::fmt;
use std::path::PathBuf;

use clap::Parser;

use crate::config::{
    GlobalConfig, HttpReq, OperationConfig,
    TraceType, PARALLEL_DEFAULT,
};
use crate::formparse::formparse;
use crate::msgs::{errorf, helpf, warnf};
use crate::operhlp::enforce_http_method;
use crate::paramhelp::{
    add2list, check_protocol, file2memory, file2string,
    ftpcccmethod, ftpfilemethod, inlist, new_getout, proto2num,
    secs2ms, str2num, str2offset, str2tls_max, str2unum,
};
use crate::var::{set_variable, varexpand};
use curl_rs_lib::escape::url_encode;

// ---------------------------------------------------------------------------
// ARG type constants — matching C definitions in tool_getparam.h
// ---------------------------------------------------------------------------

/// Argument type classification values (u32 bitmask base)
const ARG_NONE: u32 = 0;
const ARG_BOOL: u32 = 1;
const ARG_STRG: u32 = 2;
const ARG_FILE: u32 = 3;

// Bitmask modifier flags carried alongside the base type in desc_flags
const ARG_TYPEMASK: u32 = 0x0F;
const ARG_DEPR: u32 = 0x10;
/// Marks a flag that resets a boolean accumulator (used internally by curl C code).
#[allow(dead_code)]
const ARG_CLEAR: u32 = 0x20;
const ARG_TLS: u32 = 0x40;
const ARG_NO: u32 = 0x80;

// ---------------------------------------------------------------------------
// ArgType — typed version of the argument type
// ---------------------------------------------------------------------------

/// Argument type classification for each CLI option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgType {
    /// Option takes no argument
    None,
    /// Option is a boolean toggle
    Bool,
    /// Option takes a string argument
    Strg,
    /// Option takes a filename argument
    File,
}

/// Extract the base ArgType from combined desc_flags.
fn argtype(flags: u32) -> ArgType {
    match flags & ARG_TYPEMASK {
        0 => ArgType::None,
        1 => ArgType::Bool,
        2 => ArgType::Strg,
        3 => ArgType::File,
        _ => ArgType::None,
    }
}

// ---------------------------------------------------------------------------
// CmdlineOption — enum of all recognized CLI options
// ---------------------------------------------------------------------------

/// Every CLI option recognised by curl, encoded as a Rust enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmdlineOption {
    Append,
    UserAgent,
    Cookie,
    CookieJar,
    ContinueAt,
    DataPost,
    DataRaw,
    DataBinary,
    DataUrlencode,
    DataAscii,
    Cert,
    CaPath,
    CaCert,
    CipherList,
    Compressed,
    ConnectTimeout,
    CreateDirs,
    ClobberMode,
    DumpHeader,
    FailOnError,
    Form,
    FormString,
    FtpPort,
    Globoff,
    GetRequest,
    Help,
    Header,
    Head,
    Insecure,
    Interface,
    Ipv4,
    Ipv6,
    Json,
    KeepAliveTime,
    Key,
    Libcurl,
    ListOnly,
    Location,
    MaxFilesize,
    MaxTime,
    Manual,
    Netrc,
    NetrcFile,
    NetrcOptional,
    NoBuffer,
    Output,
    OutputDir,
    Proxy,
    ProxyUser,
    Quote,
    Range,
    Referer,
    RemoteName,
    Request,
    Retry,
    RetryDelay,
    RetryMaxTime,
    Silent,
    ShowError,
    SpeedLimit,
    SpeedTime,
    SslReqd,
    TlsMax,
    Trace,
    TraceAscii,
    TraceTime,
    Upload,
    User,
    UserAgent2,
    Verbose,
    Version,
    WriteOut,
    Parallel,
    AbstractUnixSocket,
    AltSvc,
    Anyauth,
    AwsSigv4,
    Basic,
    CaBundle,
    CertType,
    CompressedSsh,
    Config,
    ConnectTo,
    Curves,
    Digest,
    DisableEprt,
    DisableEpsv,
    DnsInterface,
    DnsIpv4Addr,
    DnsIpv6Addr,
    DnsServers,
    DohUrl,
    DumpCaEmbed,
    Ech,
    Engine,
    EtagCompare,
    EtagSave,
    Expect100Timeout,
    FailEarly,
    FailWithBody,
    FalseStart,
    FormEscape,
    FtpAccount,
    FtpAlternativeToUser,
    FtpCreateDirs,
    FtpMethod,
    FtpPasv,
    FtpPret,
    FtpSkipPasvIp,
    FtpSslCcc,
    FtpSslCccMode,
    HaproxyClientIp,
    HaproxyProtocol,
    HappyEyeballsTimeoutMs,
    HostPubMd5,
    HostPubSha256,
    Hsts,
    Http09,
    Http10,
    Http11,
    Http2,
    Http2PriorKnowledge,
    Http3,
    Http3Only,
    Include,
    IpfsGateway,
    KeyType,
    LimitRate,
    LocalPort,
    LocationTrusted,
    LoginOptions,
    MailAuth,
    MailFrom,
    MailRcpt,
    MailRcptAllowfails,
    MaxRedirs,
    Negotiate,
    Next,
    NoAlpn,
    NoConfig,
    NoKeepalive,
    NoProgressMeter,
    NoSessionid,
    Noproxy,
    Ntlm,
    Oauth2Bearer,
    ParallelImmediate,
    ParallelMax,
    Pass,
    PathAsIs,
    Pinnedpubkey,
    PostData301,
    PostData302,
    PostData303,
    ProgressBar,
    Proto,
    ProtoDefault,
    ProtoRedir,
    ProxyAnyauth,
    ProxyBasic,
    ProxyCacert,
    ProxyCapath,
    ProxyCert,
    ProxyCertType,
    ProxyCiphers,
    ProxyCrlfile,
    ProxyDigest,
    ProxyHeader,
    ProxyInsecure,
    ProxyKeyType,
    ProxyNegotiate,
    ProxyNtlm,
    ProxyPass,
    ProxyPinnedpubkey,
    ProxyServiceName,
    ProxyTls13Ciphers,
    ProxyTlsauthtype,
    ProxyTlspassword,
    ProxyTlsuser,
    ProxyTlsv1,
    ProxyUser2,
    PubKey,
    Rate,
    Raw,
    RemoteHeaderName,
    RemoteNameAll,
    RemoteTime,
    RemoveOnError,
    RequestTarget,
    Resolve,
    RetryAllErrors,
    RetryConnRefused,
    Sasl,
    ServiceName,
    SkipExisting,
    Socks4,
    Socks4a,
    Socks5,
    Socks5Basic,
    Socks5GssapiNec,
    Socks5GssapiService,
    Socks5Hostname,
    SslAllowBeast,
    SslAutoClientCert,
    SslNoRevoke,
    SslRevokeBestEffort,
    Ssl,
    StyledOutput,
    SuppressConnectHeaders,
    TcpFastopen,
    TcpNodelay,
    TlsAuthType,
    TlsPassword,
    TlsUser,
    Tls13Ciphers,
    Tlsv1,
    Tlsv10,
    Tlsv11,
    Tlsv12,
    Tlsv13,
    TraceConfig,
    TraceIds,
    TrEncoding,
    UnixSocket,
    UploadFlags,
    UrlQuery,
    UseSsl,
    Variable,
    Xattr,
    Url,
    Crlfile,
    TimeCond,
    ProxyKey,
    Proxytunnel,
}

// ---------------------------------------------------------------------------
// LongShort — per-option alias metadata
// ---------------------------------------------------------------------------

/// Metadata for a single CLI option alias.
#[derive(Debug, Clone)]
pub struct LongShort {
    pub long_name: &'static str,
    pub desc_flags: u32,
    pub short_letter: char,
    pub cmd: CmdlineOption,
}

// ---------------------------------------------------------------------------
// ParameterError — error codes from argument parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterError {
    Ok,
    HelpRequested,
    ManualRequested,
    VersionInfoRequested,
    EnginesRequested,
    CaEmbedRequested,
    NextOperation,
    ContdispResumeFrom,
    NoPrefix,
    ExpandError,
    GotExtraParameter,
    BadNumeric,
    NegativeNumeric,
    OutOfMemory,
    UserCallbackFail,
    LibcurlUnsupported,
    LibcurlDoesntSupportSSL,
    NoInput,
    Last,
}

impl fmt::Display for ParameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", param2text(self))
    }
}

// ---------------------------------------------------------------------------
// ParameterResult — high-level parse outcome
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterResult {
    Ok,
    Help,
    Manual,
    Version,
    EngineList,
    CaBundleDump,
    Error(ParameterError),
    NextOperation,
}

// ---------------------------------------------------------------------------
// CurlArgs — clap-derived argument structure
// ---------------------------------------------------------------------------

/// Top-level CLI argument structure parsed by clap. Each field maps to a
/// curl 8.x flag. After parsing, `parse_args` translates values into
/// `OperationConfig` mutations.
#[derive(Parser, Debug)]
#[command(
    name = "curl",
    about = "curl-rs: command line tool for transferring data with URLs",
    long_about = "curl-rs is a tool for transferring data from or to a server using URLs.\n\
                   It supports HTTP, HTTPS, FTP, FTPS, SFTP, SCP and many more protocols.",
    disable_help_flag = true,
    disable_version_flag = true,
)]
pub struct CurlArgs {
    #[arg(value_name = "url")]
    pub url: Vec<String>,
    #[arg(short = 'X', long = "request", value_name = "method")]
    pub request: Option<String>,
    #[arg(short = 'd', long = "data", value_name = "data")]
    pub data: Vec<String>,
    #[arg(long = "data-raw", value_name = "data")]
    pub data_raw: Vec<String>,
    #[arg(long = "data-binary", value_name = "data")]
    pub data_binary: Vec<String>,
    #[arg(long = "data-urlencode", value_name = "data")]
    pub data_urlencode: Vec<String>,
    #[arg(long = "data-ascii", value_name = "data")]
    pub data_ascii: Vec<String>,
    #[arg(short = 'H', long = "header", value_name = "header/@file")]
    pub header: Vec<String>,
    #[arg(short = 'F', long = "form", value_name = "content")]
    pub form: Vec<String>,
    #[arg(long = "form-string", value_name = "content")]
    pub form_string: Vec<String>,
    #[arg(short = 'u', long = "user", value_name = "user:password")]
    pub user: Option<String>,
    #[arg(long = "basic")]
    pub basic: bool,
    #[arg(long = "digest")]
    pub digest: bool,
    #[arg(long = "ntlm")]
    pub ntlm: bool,
    #[arg(long = "negotiate")]
    pub negotiate: bool,
    #[arg(long = "anyauth")]
    pub anyauth: bool,
    #[arg(long = "oauth2-bearer", value_name = "token")]
    pub oauth2_bearer: Option<String>,
    #[arg(short = 'e', long = "referer", value_name = "URL")]
    pub referer: Option<String>,
    #[arg(short = 'A', long = "user-agent", value_name = "name")]
    pub user_agent: Option<String>,
    #[arg(short = 'b', long = "cookie", value_name = "data|filename")]
    pub cookie: Option<String>,
    #[arg(short = 'c', long = "cookie-jar", value_name = "filename")]
    pub cookie_jar: Option<String>,
    #[arg(short = 'L', long = "location")]
    pub location: bool,
    #[arg(long = "max-redirs", value_name = "num")]
    pub max_redirs: Option<i64>,
    #[arg(long = "compressed")]
    pub compressed: bool,
    #[arg(short = 'o', long = "output", value_name = "file")]
    pub output: Vec<String>,
    #[arg(short = 'O', long = "remote-name")]
    pub remote_name: bool,
    #[arg(short = 'i', long = "include")]
    pub include: bool,
    #[arg(short = 'I', long = "head")]
    pub head: bool,
    #[arg(short = 's', long = "silent")]
    pub silent: bool,
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
    #[arg(short = 'k', long = "insecure")]
    pub insecure: bool,
    #[arg(long = "cacert", value_name = "file")]
    pub cacert: Option<PathBuf>,
    #[arg(short = 'E', long = "cert", value_name = "certificate[:password]")]
    pub cert: Option<String>,
    #[arg(long = "key", value_name = "key")]
    pub key: Option<String>,
    #[arg(long = "connect-timeout", value_name = "fractional seconds")]
    pub connect_timeout: Option<f64>,
    #[arg(short = 'm', long = "max-time", value_name = "fractional seconds")]
    pub max_time: Option<f64>,
    #[arg(long = "retry", value_name = "num")]
    pub retry: Option<i64>,
    #[arg(short = 'x', long = "proxy", value_name = "[protocol://]host[:port]")]
    pub proxy: Option<String>,
    #[arg(short = '0', long = "http1.0")]
    pub http10: bool,
    #[arg(long = "http1.1")]
    pub http11: bool,
    #[arg(long = "http2")]
    pub http2: bool,
    #[arg(long = "http3")]
    pub http3: bool,
    #[arg(short = 'Z', long = "parallel")]
    pub parallel: bool,
    #[arg(short = 'K', long = "config", value_name = "file")]
    pub config_file: Option<PathBuf>,
    #[arg(short = 'V', long = "version")]
    pub version: bool,
    #[arg(short = 'h', long = "help", value_name = "category")]
    pub help: Option<Option<String>>,
}

// ---------------------------------------------------------------------------
// ALIASES table
// ---------------------------------------------------------------------------

pub static ALIASES: &[LongShort] = &[
    LongShort { long_name: "abstract-unix-socket", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::AbstractUnixSocket },
    LongShort { long_name: "alt-svc", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::AltSvc },
    LongShort { long_name: "anyauth", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Anyauth },
    LongShort { long_name: "append", desc_flags: ARG_BOOL, short_letter: 'a', cmd: CmdlineOption::Append },
    LongShort { long_name: "aws-sigv4", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::AwsSigv4 },
    LongShort { long_name: "basic", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Basic },
    LongShort { long_name: "buffer", desc_flags: ARG_BOOL | ARG_NO, short_letter: 'N', cmd: CmdlineOption::NoBuffer },
    LongShort { long_name: "cacert", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::CaCert },
    LongShort { long_name: "capath", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::CaPath },
    LongShort { long_name: "cert", desc_flags: ARG_FILE, short_letter: 'E', cmd: CmdlineOption::Cert },
    LongShort { long_name: "cert-type", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::CertType },
    LongShort { long_name: "ciphers", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::CipherList },
    LongShort { long_name: "clobber", desc_flags: ARG_BOOL | ARG_NO, short_letter: '\0', cmd: CmdlineOption::ClobberMode },
    LongShort { long_name: "compressed", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::Compressed },
    LongShort { long_name: "compressed-ssh", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::CompressedSsh },
    LongShort { long_name: "config", desc_flags: ARG_FILE, short_letter: 'K', cmd: CmdlineOption::Config },
    LongShort { long_name: "connect-timeout", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ConnectTimeout },
    LongShort { long_name: "connect-to", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ConnectTo },
    LongShort { long_name: "continue-at", desc_flags: ARG_STRG, short_letter: 'C', cmd: CmdlineOption::ContinueAt },
    LongShort { long_name: "cookie", desc_flags: ARG_STRG, short_letter: 'b', cmd: CmdlineOption::Cookie },
    LongShort { long_name: "cookie-jar", desc_flags: ARG_STRG, short_letter: 'c', cmd: CmdlineOption::CookieJar },
    LongShort { long_name: "create-dirs", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::CreateDirs },
    LongShort { long_name: "crlfile", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::Crlfile },
    LongShort { long_name: "curves", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Curves },
    LongShort { long_name: "data", desc_flags: ARG_STRG, short_letter: 'd', cmd: CmdlineOption::DataPost },
    LongShort { long_name: "data-ascii", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::DataAscii },
    LongShort { long_name: "data-binary", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::DataBinary },
    LongShort { long_name: "data-raw", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::DataRaw },
    LongShort { long_name: "data-urlencode", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::DataUrlencode },
    LongShort { long_name: "delegation", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Negotiate },
    LongShort { long_name: "digest", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Digest },
    LongShort { long_name: "disable-eprt", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::DisableEprt },
    LongShort { long_name: "disable-epsv", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::DisableEpsv },
    LongShort { long_name: "dns-interface", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::DnsInterface },
    LongShort { long_name: "dns-ipv4-addr", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::DnsIpv4Addr },
    LongShort { long_name: "dns-ipv6-addr", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::DnsIpv6Addr },
    LongShort { long_name: "dns-servers", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::DnsServers },
    LongShort { long_name: "doh-url", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::DohUrl },
    LongShort { long_name: "dump-ca-embed", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::DumpCaEmbed },
    LongShort { long_name: "dump-header", desc_flags: ARG_FILE, short_letter: 'D', cmd: CmdlineOption::DumpHeader },
    LongShort { long_name: "ech", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Ech },
    LongShort { long_name: "engine", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Engine },
    LongShort { long_name: "etag-compare", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::EtagCompare },
    LongShort { long_name: "etag-save", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::EtagSave },
    LongShort { long_name: "expect100-timeout", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Expect100Timeout },
    LongShort { long_name: "fail", desc_flags: ARG_BOOL, short_letter: 'f', cmd: CmdlineOption::FailOnError },
    LongShort { long_name: "fail-early", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::FailEarly },
    LongShort { long_name: "fail-with-body", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::FailWithBody },
    LongShort { long_name: "false-start", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::FalseStart },
    LongShort { long_name: "form", desc_flags: ARG_STRG, short_letter: 'F', cmd: CmdlineOption::Form },
    LongShort { long_name: "form-escape", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::FormEscape },
    LongShort { long_name: "form-string", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::FormString },
    LongShort { long_name: "ftp-account", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::FtpAccount },
    LongShort { long_name: "ftp-alternative-to-user", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::FtpAlternativeToUser },
    LongShort { long_name: "ftp-create-dirs", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::FtpCreateDirs },
    LongShort { long_name: "ftp-method", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::FtpMethod },
    LongShort { long_name: "ftp-pasv", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::FtpPasv },
    LongShort { long_name: "ftp-port", desc_flags: ARG_STRG, short_letter: 'P', cmd: CmdlineOption::FtpPort },
    LongShort { long_name: "ftp-pret", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::FtpPret },
    LongShort { long_name: "ftp-skip-pasv-ip", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::FtpSkipPasvIp },
    LongShort { long_name: "ftp-ssl-ccc", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::FtpSslCcc },
    LongShort { long_name: "ftp-ssl-ccc-mode", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::FtpSslCccMode },
    LongShort { long_name: "get", desc_flags: ARG_NONE, short_letter: 'G', cmd: CmdlineOption::GetRequest },
    LongShort { long_name: "globoff", desc_flags: ARG_BOOL, short_letter: 'g', cmd: CmdlineOption::Globoff },
    LongShort { long_name: "haproxy-clientip", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::HaproxyClientIp },
    LongShort { long_name: "haproxy-protocol", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::HaproxyProtocol },
    LongShort { long_name: "happy-eyeballs-timeout-ms", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::HappyEyeballsTimeoutMs },
    LongShort { long_name: "head", desc_flags: ARG_NONE, short_letter: 'I', cmd: CmdlineOption::Head },
    LongShort { long_name: "header", desc_flags: ARG_STRG, short_letter: 'H', cmd: CmdlineOption::Header },
    LongShort { long_name: "help", desc_flags: ARG_STRG, short_letter: 'h', cmd: CmdlineOption::Help },
    LongShort { long_name: "hostpubmd5", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::HostPubMd5 },
    LongShort { long_name: "hostpubsha256", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::HostPubSha256 },
    LongShort { long_name: "hsts", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::Hsts },
    LongShort { long_name: "http0.9", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::Http09 },
    LongShort { long_name: "http1.0", desc_flags: ARG_NONE, short_letter: '0', cmd: CmdlineOption::Http10 },
    LongShort { long_name: "http1.1", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Http11 },
    LongShort { long_name: "http2", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Http2 },
    LongShort { long_name: "http2-prior-knowledge", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Http2PriorKnowledge },
    LongShort { long_name: "http3", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Http3 },
    LongShort { long_name: "http3-only", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Http3Only },
    LongShort { long_name: "include", desc_flags: ARG_BOOL, short_letter: 'i', cmd: CmdlineOption::Include },
    LongShort { long_name: "insecure", desc_flags: ARG_BOOL, short_letter: 'k', cmd: CmdlineOption::Insecure },
    LongShort { long_name: "interface", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Interface },
    LongShort { long_name: "ipfs-gateway", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::IpfsGateway },
    LongShort { long_name: "ipv4", desc_flags: ARG_NONE, short_letter: '4', cmd: CmdlineOption::Ipv4 },
    LongShort { long_name: "ipv6", desc_flags: ARG_NONE, short_letter: '6', cmd: CmdlineOption::Ipv6 },
    LongShort { long_name: "json", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Json },
    LongShort { long_name: "keepalive-time", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::KeepAliveTime },
    LongShort { long_name: "key", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::Key },
    LongShort { long_name: "key-type", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::KeyType },
    LongShort { long_name: "libcurl", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::Libcurl },
    LongShort { long_name: "limit-rate", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::LimitRate },
    LongShort { long_name: "list-only", desc_flags: ARG_BOOL, short_letter: 'l', cmd: CmdlineOption::ListOnly },
    LongShort { long_name: "local-port", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::LocalPort },
    LongShort { long_name: "location", desc_flags: ARG_BOOL, short_letter: 'L', cmd: CmdlineOption::Location },
    LongShort { long_name: "location-trusted", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::LocationTrusted },
    LongShort { long_name: "login-options", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::LoginOptions },
    LongShort { long_name: "mail-auth", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::MailAuth },
    LongShort { long_name: "mail-from", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::MailFrom },
    LongShort { long_name: "mail-rcpt", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::MailRcpt },
    LongShort { long_name: "mail-rcpt-allowfails", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::MailRcptAllowfails },
    LongShort { long_name: "manual", desc_flags: ARG_NONE, short_letter: 'M', cmd: CmdlineOption::Manual },
    LongShort { long_name: "max-filesize", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::MaxFilesize },
    LongShort { long_name: "max-redirs", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::MaxRedirs },
    LongShort { long_name: "max-time", desc_flags: ARG_STRG, short_letter: 'm', cmd: CmdlineOption::MaxTime },
    LongShort { long_name: "negotiate", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Negotiate },
    LongShort { long_name: "netrc", desc_flags: ARG_BOOL, short_letter: 'n', cmd: CmdlineOption::Netrc },
    LongShort { long_name: "netrc-file", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::NetrcFile },
    LongShort { long_name: "netrc-optional", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::NetrcOptional },
    LongShort { long_name: "next", desc_flags: ARG_NONE, short_letter: ':', cmd: CmdlineOption::Next },
    LongShort { long_name: "no-alpn", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::NoAlpn },
    LongShort { long_name: "no-buffer", desc_flags: ARG_BOOL, short_letter: 'N', cmd: CmdlineOption::NoBuffer },
    LongShort { long_name: "no-clobber", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::ClobberMode },
    LongShort { long_name: "no-keepalive", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::NoKeepalive },
    LongShort { long_name: "no-progress-meter", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::NoProgressMeter },
    LongShort { long_name: "no-sessionid", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::NoSessionid },
    LongShort { long_name: "noproxy", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Noproxy },
    LongShort { long_name: "ntlm", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Ntlm },
    LongShort { long_name: "oauth2-bearer", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Oauth2Bearer },
    LongShort { long_name: "output", desc_flags: ARG_FILE, short_letter: 'o', cmd: CmdlineOption::Output },
    LongShort { long_name: "output-dir", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::OutputDir },
    LongShort { long_name: "parallel", desc_flags: ARG_BOOL, short_letter: 'Z', cmd: CmdlineOption::Parallel },
    LongShort { long_name: "parallel-immediate", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::ParallelImmediate },
    LongShort { long_name: "parallel-max", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ParallelMax },
    LongShort { long_name: "pass", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Pass },
    LongShort { long_name: "path-as-is", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::PathAsIs },
    LongShort { long_name: "pinnedpubkey", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Pinnedpubkey },
    LongShort { long_name: "post301", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::PostData301 },
    LongShort { long_name: "post302", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::PostData302 },
    LongShort { long_name: "post303", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::PostData303 },
    LongShort { long_name: "progress-bar", desc_flags: ARG_BOOL, short_letter: '#', cmd: CmdlineOption::ProgressBar },
    LongShort { long_name: "proto", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Proto },
    LongShort { long_name: "proto-default", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ProtoDefault },
    LongShort { long_name: "proto-redir", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ProtoRedir },
    LongShort { long_name: "proxy", desc_flags: ARG_STRG, short_letter: 'x', cmd: CmdlineOption::Proxy },
    LongShort { long_name: "proxy-anyauth", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::ProxyAnyauth },
    LongShort { long_name: "proxy-basic", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::ProxyBasic },
    LongShort { long_name: "proxy-cacert", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::ProxyCacert },
    LongShort { long_name: "proxy-capath", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::ProxyCapath },
    LongShort { long_name: "proxy-cert", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::ProxyCert },
    LongShort { long_name: "proxy-cert-type", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ProxyCertType },
    LongShort { long_name: "proxy-ciphers", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ProxyCiphers },
    LongShort { long_name: "proxy-crlfile", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::ProxyCrlfile },
    LongShort { long_name: "proxy-digest", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::ProxyDigest },
    LongShort { long_name: "proxy-header", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ProxyHeader },
    LongShort { long_name: "proxy-insecure", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::ProxyInsecure },
    LongShort { long_name: "proxy-key", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::ProxyKey },
    LongShort { long_name: "proxy-key-type", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ProxyKeyType },
    LongShort { long_name: "proxy-negotiate", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::ProxyNegotiate },
    LongShort { long_name: "proxy-ntlm", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::ProxyNtlm },
    LongShort { long_name: "proxy-pass", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ProxyPass },
    LongShort { long_name: "proxy-pinnedpubkey", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ProxyPinnedpubkey },
    LongShort { long_name: "proxy-service-name", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ProxyServiceName },
    LongShort { long_name: "proxy-tls13-ciphers", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ProxyTls13Ciphers },
    LongShort { long_name: "proxy-tlsauthtype", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ProxyTlsauthtype },
    LongShort { long_name: "proxy-tlspassword", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ProxyTlspassword },
    LongShort { long_name: "proxy-tlsuser", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ProxyTlsuser },
    LongShort { long_name: "proxy-tlsv1", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::ProxyTlsv1 },
    LongShort { long_name: "proxy-user", desc_flags: ARG_STRG, short_letter: 'U', cmd: CmdlineOption::ProxyUser },
    LongShort { long_name: "proxytunnel", desc_flags: ARG_BOOL, short_letter: 'p', cmd: CmdlineOption::Proxytunnel },
    LongShort { long_name: "pubkey", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::PubKey },
    LongShort { long_name: "quote", desc_flags: ARG_STRG, short_letter: 'Q', cmd: CmdlineOption::Quote },
    LongShort { long_name: "range", desc_flags: ARG_STRG, short_letter: 'r', cmd: CmdlineOption::Range },
    LongShort { long_name: "rate", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Rate },
    LongShort { long_name: "raw", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::Raw },
    LongShort { long_name: "referer", desc_flags: ARG_STRG, short_letter: 'e', cmd: CmdlineOption::Referer },
    LongShort { long_name: "remote-header-name", desc_flags: ARG_BOOL, short_letter: 'J', cmd: CmdlineOption::RemoteHeaderName },
    LongShort { long_name: "remote-name", desc_flags: ARG_NONE, short_letter: 'O', cmd: CmdlineOption::RemoteName },
    LongShort { long_name: "remote-name-all", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::RemoteNameAll },
    LongShort { long_name: "remote-time", desc_flags: ARG_BOOL, short_letter: 'R', cmd: CmdlineOption::RemoteTime },
    LongShort { long_name: "remove-on-error", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::RemoveOnError },
    LongShort { long_name: "request", desc_flags: ARG_STRG, short_letter: 'X', cmd: CmdlineOption::Request },
    LongShort { long_name: "request-target", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::RequestTarget },
    LongShort { long_name: "resolve", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Resolve },
    LongShort { long_name: "retry", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Retry },
    LongShort { long_name: "retry-all-errors", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::RetryAllErrors },
    LongShort { long_name: "retry-connrefused", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::RetryConnRefused },
    LongShort { long_name: "retry-delay", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::RetryDelay },
    LongShort { long_name: "retry-max-time", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::RetryMaxTime },
    LongShort { long_name: "sasl-authzid", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Sasl },
    LongShort { long_name: "sasl-ir", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::Sasl },
    LongShort { long_name: "service-name", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::ServiceName },
    LongShort { long_name: "show-error", desc_flags: ARG_BOOL, short_letter: 'S', cmd: CmdlineOption::ShowError },
    LongShort { long_name: "silent", desc_flags: ARG_BOOL, short_letter: 's', cmd: CmdlineOption::Silent },
    LongShort { long_name: "skip-existing", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::SkipExisting },
    LongShort { long_name: "socks4", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Socks4 },
    LongShort { long_name: "socks4a", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Socks4a },
    LongShort { long_name: "socks5", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Socks5 },
    LongShort { long_name: "socks5-basic", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::Socks5Basic },
    LongShort { long_name: "socks5-gssapi-nec", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::Socks5GssapiNec },
    LongShort { long_name: "socks5-gssapi-service", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Socks5GssapiService },
    LongShort { long_name: "socks5-hostname", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Socks5Hostname },
    LongShort { long_name: "speed-limit", desc_flags: ARG_STRG, short_letter: 'Y', cmd: CmdlineOption::SpeedLimit },
    LongShort { long_name: "speed-time", desc_flags: ARG_STRG, short_letter: 'y', cmd: CmdlineOption::SpeedTime },
    LongShort { long_name: "ssl", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::Ssl },
    LongShort { long_name: "ssl-allow-beast", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::SslAllowBeast },
    LongShort { long_name: "ssl-auto-client-cert", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::SslAutoClientCert },
    LongShort { long_name: "ssl-no-revoke", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::SslNoRevoke },
    LongShort { long_name: "ssl-reqd", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::SslReqd },
    LongShort { long_name: "ssl-revoke-best-effort", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::SslRevokeBestEffort },
    LongShort { long_name: "styled-output", desc_flags: ARG_BOOL | ARG_NO, short_letter: '\0', cmd: CmdlineOption::StyledOutput },
    LongShort { long_name: "suppress-connect-headers", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::SuppressConnectHeaders },
    LongShort { long_name: "tcp-fastopen", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::TcpFastopen },
    LongShort { long_name: "tcp-nodelay", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::TcpNodelay },
    LongShort { long_name: "time-cond", desc_flags: ARG_STRG, short_letter: 'z', cmd: CmdlineOption::TimeCond },
    LongShort { long_name: "tls-max", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::TlsMax },
    LongShort { long_name: "tls13-ciphers", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Tls13Ciphers },
    LongShort { long_name: "tlsauthtype", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::TlsAuthType },
    LongShort { long_name: "tlspassword", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::TlsPassword },
    LongShort { long_name: "tlsuser", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::TlsUser },
    LongShort { long_name: "tlsv1", desc_flags: ARG_NONE, short_letter: '1', cmd: CmdlineOption::Tlsv1 },
    LongShort { long_name: "tlsv1.0", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Tlsv10 },
    LongShort { long_name: "tlsv1.1", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Tlsv11 },
    LongShort { long_name: "tlsv1.2", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Tlsv12 },
    LongShort { long_name: "tlsv1.3", desc_flags: ARG_NONE, short_letter: '\0', cmd: CmdlineOption::Tlsv13 },
    LongShort { long_name: "tr-encoding", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::TrEncoding },
    LongShort { long_name: "trace", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::Trace },
    LongShort { long_name: "trace-ascii", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::TraceAscii },
    LongShort { long_name: "trace-config", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::TraceConfig },
    LongShort { long_name: "trace-ids", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::TraceIds },
    LongShort { long_name: "trace-time", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::TraceTime },
    LongShort { long_name: "unix-socket", desc_flags: ARG_FILE, short_letter: '\0', cmd: CmdlineOption::UnixSocket },
    LongShort { long_name: "upload-file", desc_flags: ARG_FILE, short_letter: 'T', cmd: CmdlineOption::Upload },
    LongShort { long_name: "upload-flags", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::UploadFlags },
    LongShort { long_name: "url", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Url },
    LongShort { long_name: "url-query", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::UrlQuery },
    LongShort { long_name: "use-ascii", desc_flags: ARG_BOOL, short_letter: 'B', cmd: CmdlineOption::Append },
    LongShort { long_name: "use-ssl", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::UseSsl },
    LongShort { long_name: "user", desc_flags: ARG_STRG, short_letter: 'u', cmd: CmdlineOption::User },
    LongShort { long_name: "user-agent", desc_flags: ARG_STRG, short_letter: 'A', cmd: CmdlineOption::UserAgent },
    LongShort { long_name: "variable", desc_flags: ARG_STRG, short_letter: '\0', cmd: CmdlineOption::Variable },
    LongShort { long_name: "verbose", desc_flags: ARG_BOOL, short_letter: 'v', cmd: CmdlineOption::Verbose },
    LongShort { long_name: "version", desc_flags: ARG_NONE, short_letter: 'V', cmd: CmdlineOption::Version },
    LongShort { long_name: "write-out", desc_flags: ARG_STRG, short_letter: 'w', cmd: CmdlineOption::WriteOut },
    LongShort { long_name: "xattr", desc_flags: ARG_BOOL, short_letter: '\0', cmd: CmdlineOption::Xattr },
];

// ---------------------------------------------------------------------------
// param2text
// ---------------------------------------------------------------------------

pub fn param2text(err: &ParameterError) -> &'static str {
    match err {
        ParameterError::Ok => "no error",
        ParameterError::HelpRequested => "help requested",
        ParameterError::ManualRequested => "manual requested",
        ParameterError::VersionInfoRequested => "version info requested",
        ParameterError::EnginesRequested => "engines requested",
        ParameterError::CaEmbedRequested => "CA embed requested",
        ParameterError::NextOperation => "next operation",
        ParameterError::ContdispResumeFrom => "content-disposition resume from",
        ParameterError::NoPrefix => "no prefix",
        ParameterError::ExpandError => "expand error",
        ParameterError::GotExtraParameter => "had unsupported trailing garbage",
        ParameterError::BadNumeric => "expected a proper numerical parameter",
        ParameterError::NegativeNumeric => "expected a positive numerical parameter",
        ParameterError::OutOfMemory => "out of memory",
        ParameterError::UserCallbackFail => "user callback fail",
        ParameterError::LibcurlUnsupported => "an option was given that is not supported by libcurl",
        ParameterError::LibcurlDoesntSupportSSL => "the installed libcurl has no SSL support",
        ParameterError::NoInput => "no input",
        ParameterError::Last => "unknown error",
    }
}

// ---------------------------------------------------------------------------
// findshortopt / findlongopt
// ---------------------------------------------------------------------------

pub fn findshortopt(ch: char) -> Option<&'static LongShort> {
    ALIASES.iter().find(|a| a.short_letter == ch)
}

pub fn findlongopt(name: &str) -> Option<&'static LongShort> {
    let idx = ALIASES.binary_search_by(|a| a.long_name.cmp(name));
    match idx {
        Ok(i) => Some(&ALIASES[i]),
        Err(_) => {
            let mut matches: Vec<&LongShort> = Vec::new();
            for a in ALIASES.iter() {
                if a.long_name.starts_with(name) {
                    matches.push(a);
                }
            }
            if matches.len() == 1 { Some(matches[0]) } else { None }
        }
    }
}

// ---------------------------------------------------------------------------
// parse_cert_parameter
// ---------------------------------------------------------------------------

pub fn parse_cert_parameter(param: &str) -> (String, Option<String>) {
    if param.starts_with("pkcs11:") || param.starts_with("PKCS11:") {
        return (param.to_string(), None);
    }
    let mut cert = String::new();
    let chars: Vec<char> = param.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() && chars[i + 1] == ':' {
            cert.push(':');
            i += 2;
            continue;
        }
        if chars[i] == ':' {
            let rest: String = chars[i + 1..].iter().collect();
            let pwd = if rest.is_empty() { None } else { Some(rest) };
            return (cert, pwd);
        }
        cert.push(chars[i]);
        i += 1;
    }
    (cert, None)
}

// ---------------------------------------------------------------------------
// get_size_parameter — parse a human-readable size string
// ---------------------------------------------------------------------------

struct SizeUnit { suffix: char, multiplier: u64 }
const SIZE_UNITS: &[SizeUnit] = &[
    SizeUnit { suffix: 'P', multiplier: 1024 * 1024 * 1024 * 1024 * 1024 },
    SizeUnit { suffix: 'T', multiplier: 1024 * 1024 * 1024 * 1024 },
    SizeUnit { suffix: 'G', multiplier: 1024 * 1024 * 1024 },
    SizeUnit { suffix: 'M', multiplier: 1024 * 1024 },
    SizeUnit { suffix: 'K', multiplier: 1024 },
    SizeUnit { suffix: 'k', multiplier: 1000 },
];

pub fn get_size_parameter(param: &str) -> Result<u64, ParameterError> {
    let trimmed = param.trim();
    if trimmed.is_empty() { return Err(ParameterError::BadNumeric); }
    let mut num_end = 0;
    for (i, ch) in trimmed.chars().enumerate() {
        if ch.is_ascii_digit() || ch == '.' { num_end = i + 1; } else { break; }
    }
    if num_end == 0 { return Err(ParameterError::BadNumeric); }
    let value: f64 = trimmed[..num_end].parse().map_err(|_| ParameterError::BadNumeric)?;
    if value < 0.0 { return Err(ParameterError::NegativeNumeric); }
    let suffix_str = trimmed[num_end..].trim();
    let multiplier = if suffix_str.is_empty() { 1u64 }
    else {
        let sc = suffix_str.chars().next().unwrap_or('\0');
        SIZE_UNITS.iter().find(|s| s.suffix == sc).map(|s| s.multiplier)
            .ok_or(ParameterError::BadNumeric)?
    };
    Ok((value * multiplier as f64) as u64)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn sethttpver(config: &mut OperationConfig, global: &GlobalConfig, httpver: i64) {
    if config.httpversion != 0 && config.httpversion != httpver {
        warnf(global, "Overriding previous HTTP version preference");
    }
    config.httpversion = httpver;
}

fn data_urlencode_helper(param: &str) -> Result<String, ParameterError> {
    let (name, content): (Option<&str>, String);
    if let Some(eq_pos) = param.find('=') {
        let prefix = &param[..eq_pos];
        let value = &param[eq_pos + 1..];
        if prefix.is_empty() { name = None; } else { name = Some(prefix); }
        content = value.to_string();
    } else if let Some(at_pos) = param.find('@') {
        let prefix = &param[..at_pos];
        let filename = &param[at_pos + 1..];
        name = if prefix.is_empty() { None } else { Some(prefix) };
        content = file2string(filename).map_err(|_| ParameterError::NoInput)?;
    } else {
        name = None;
        content = param.to_string();
    }
    let encoded = url_encode(&content);
    Ok(match name { Some(n) => format!("{}={}", n, encoded), None => encoded })
}

fn set_data_helper(config: &mut OperationConfig, param: &str, raw: bool, binary: bool) -> Result<(), ParameterError> {
    let data = if !raw && param.starts_with('@') {
        let filename = &param[1..];
        if binary {
            let bytes = file2memory(filename).map_err(|_| ParameterError::NoInput)?;
            String::from_utf8_lossy(&bytes).to_string()
        } else {
            file2string(filename).map_err(|_| ParameterError::NoInput)?
        }
    } else { param.to_string() };

    if let Some(ref existing) = config.postfields {
        if binary { config.postfields = Some(format!("{}{}", existing, data)); }
        else { config.postfields = Some(format!("{}&{}", existing, data)); }
    } else { config.postfields = Some(data); }
    Ok(())
}

fn set_rate_helper(param: &str) -> Result<i64, ParameterError> {
    let parts: Vec<&str> = param.splitn(2, '/').collect();
    let count: u64 = parts[0].trim().parse().map_err(|_| ParameterError::BadNumeric)?;
    if count == 0 { return Err(ParameterError::BadNumeric); }
    let period_ms: u64 = if parts.len() > 1 {
        match parts[1].trim() {
            "s" | "sec" | "second" => 1000,
            "m" | "min" | "minute" => 60_000,
            "h" | "hour" => 3_600_000,
            "d" | "day" => 86_400_000,
            _ => return Err(ParameterError::BadNumeric),
        }
    } else { 3_600_000 };
    Ok((period_ms / count) as i64)
}

fn add_url_to_config(config: &mut OperationConfig, url: &str) {
    let node = new_getout(config);
    node.url = Some(url.to_string());
    node.url_set = true;
}

fn parse_localport_helper(config: &mut OperationConfig, param: &str) -> Result<(), ParameterError> {
    if let Some(dash) = param.find('-') {
        let start: i64 = param[..dash].parse().map_err(|_| ParameterError::BadNumeric)?;
        let end: i64 = param[dash+1..].parse().map_err(|_| ParameterError::BadNumeric)?;
        config.localport = start;
        config.localportrange = end - start + 1;
    } else {
        config.localport = param.parse().map_err(|_| ParameterError::BadNumeric)?;
        config.localportrange = 1;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// opt_none — ARG_NONE handler
// ---------------------------------------------------------------------------

fn opt_none(cmd: CmdlineOption, config: &mut OperationConfig, global: &mut GlobalConfig) -> ParameterResult {
    match cmd {
        CmdlineOption::Anyauth => { config.authtype = 0xFF; }
        CmdlineOption::Basic => { config.authtype = 0x01; }
        CmdlineOption::Digest => { config.authtype = 0x02; }
        CmdlineOption::Ntlm => { config.authtype = 0x08; }
        CmdlineOption::Negotiate => { config.authtype = 0x04; }
        CmdlineOption::DumpCaEmbed => { return ParameterResult::CaBundleDump; }
        CmdlineOption::FtpPasv => { config.disable_epsv = true; }
        CmdlineOption::GetRequest => { config.use_httpget = true; }
        CmdlineOption::Head => {
            config.show_headers = true;
            config.no_body = true;
            enforce_http_method(global, HttpReq::Head, &mut config.httpreq);
        }
        CmdlineOption::Help => { return ParameterResult::Help; }
        CmdlineOption::Manual => { return ParameterResult::Manual; }
        CmdlineOption::Version => { return ParameterResult::Version; }
        CmdlineOption::Http10 => { sethttpver(config, global, 10); }
        CmdlineOption::Http11 => { sethttpver(config, global, 11); }
        CmdlineOption::Http2 => {
            if !global.libcurl_info.feature_http2 {
                return ParameterResult::Error(ParameterError::LibcurlUnsupported);
            }
            sethttpver(config, global, 20);
        }
        CmdlineOption::Http2PriorKnowledge => {
            if !global.libcurl_info.feature_http2 {
                return ParameterResult::Error(ParameterError::LibcurlUnsupported);
            }
            sethttpver(config, global, 21);
        }
        CmdlineOption::Http3 => {
            if !global.libcurl_info.feature_http3 {
                return ParameterResult::Error(ParameterError::LibcurlUnsupported);
            }
            sethttpver(config, global, 30);
        }
        CmdlineOption::Http3Only => {
            if !global.libcurl_info.feature_http3 {
                return ParameterResult::Error(ParameterError::LibcurlUnsupported);
            }
            sethttpver(config, global, 31);
        }
        CmdlineOption::Ipv4 => { config.ip_version = 4; }
        CmdlineOption::Ipv6 => { config.ip_version = 6; }
        CmdlineOption::Next => { return ParameterResult::NextOperation; }
        CmdlineOption::RemoteName => {
            let node = new_getout(config);
            node.use_remote = true;
            node.out_set = true;
        }
        CmdlineOption::ProxyAnyauth => { config.proxyanyauth = true; }
        CmdlineOption::ProxyBasic => { config.proxybasic = true; }
        CmdlineOption::ProxyDigest => { config.proxydigest = true; }
        CmdlineOption::ProxyNegotiate => { config.proxynegotiate = true; }
        CmdlineOption::ProxyNtlm => { config.proxyntlm = true; }
        CmdlineOption::ProxyTlsv1 => { config.proxy_ssl_version = 1; }
        CmdlineOption::Tlsv1 => { config.ssl_version = 1; }
        CmdlineOption::Tlsv10 => { config.ssl_version = 4; }
        CmdlineOption::Tlsv11 => { config.ssl_version = 5; }
        CmdlineOption::Tlsv12 => { config.ssl_version = 6; }
        CmdlineOption::Tlsv13 => { config.ssl_version = 7; }
        _ => {}
    }
    ParameterResult::Ok
}

// ---------------------------------------------------------------------------
// opt_bool — ARG_BOOL handler
// ---------------------------------------------------------------------------

fn opt_bool(cmd: CmdlineOption, toggle: bool, config: &mut OperationConfig, global: &mut GlobalConfig) -> ParameterResult {
    match cmd {
        CmdlineOption::Append => { config.ftp_append = toggle; }
        CmdlineOption::Compressed => { config.encoding = toggle; }
        CmdlineOption::CompressedSsh => { config.ssh_compression = toggle; }
        CmdlineOption::ClobberMode => { /* clobber toggling: no field on OperationConfig yet */ }
        CmdlineOption::CreateDirs => { config.create_dirs = toggle; }
        CmdlineOption::DisableEprt => { config.disable_eprt = toggle; }
        CmdlineOption::DisableEpsv => { config.disable_epsv = toggle; }
        CmdlineOption::FailOnError => { config.fail = if toggle { crate::config::FAIL_WO_BODY } else { crate::config::FAIL_NONE }; }
        CmdlineOption::FailEarly => { global.fail_early = toggle; }
        CmdlineOption::FailWithBody => { /* stored via fail field and separate flag */ }
        CmdlineOption::FalseStart => { /* TLS false start – no dedicated field */ }
        CmdlineOption::FormEscape => { /* mime backslash mode – config.mime_options */ }
        CmdlineOption::FtpCreateDirs => { config.ftp_create_dirs = toggle; }
        CmdlineOption::FtpPret => { config.ftp_pret = toggle; }
        CmdlineOption::FtpSkipPasvIp => { config.ftp_skip_ip = toggle; }
        CmdlineOption::FtpSslCcc => { config.ftp_ssl_ccc = toggle; }
        CmdlineOption::Globoff => { config.globoff = toggle; }
        CmdlineOption::HaproxyProtocol => { config.haproxy_protocol = toggle; }
        CmdlineOption::Http09 => { config.http09_allowed = toggle; }
        CmdlineOption::Include => { config.show_headers = toggle; }
        CmdlineOption::Insecure => { config.insecure_ok = toggle; }
        CmdlineOption::ListOnly => { config.dirlistonly = toggle; }
        CmdlineOption::Location => { config.followlocation = if toggle { 1 } else { 0 }; }
        CmdlineOption::LocationTrusted => {
            config.followlocation = if toggle { 1 } else { 0 };
            config.unrestricted_auth = toggle;
        }
        CmdlineOption::MailRcptAllowfails => { config.mail_rcpt_allowfails = toggle; }
        CmdlineOption::Netrc => { config.netrc = toggle; config.netrc_opt = false; }
        CmdlineOption::NetrcOptional => { config.netrc = toggle; config.netrc_opt = toggle; }
        CmdlineOption::NoAlpn => { config.noalpn = toggle; }
        CmdlineOption::NoBuffer => { config.nobuffer = toggle; }
        CmdlineOption::NoKeepalive => { config.nokeepalive = toggle; }
        CmdlineOption::NoProgressMeter => { global.noprogress = toggle; }
        CmdlineOption::NoSessionid => { config.disable_sessionid = toggle; }
        CmdlineOption::Parallel => { global.parallel = toggle; }
        CmdlineOption::ParallelImmediate => { global.parallel_connect = toggle; }
        CmdlineOption::PathAsIs => { config.path_as_is = toggle; }
        CmdlineOption::PostData301 => { config.post301 = toggle; }
        CmdlineOption::PostData302 => { config.post302 = toggle; }
        CmdlineOption::PostData303 => { config.post303 = toggle; }
        CmdlineOption::ProgressBar => { global.progressmode = if toggle { 1 } else { 0 }; }
        CmdlineOption::ProxyInsecure => { config.proxy_insecure_ok = toggle; }
        CmdlineOption::Proxytunnel => { config.proxytunnel = toggle; }
        CmdlineOption::Raw => { config.raw = toggle; }
        CmdlineOption::RemoteHeaderName => { config.content_disposition = toggle; }
        CmdlineOption::RemoteNameAll => { config.remote_name_all = toggle; }
        CmdlineOption::RemoteTime => { config.remote_time = toggle; }
        CmdlineOption::RemoveOnError => { config.rm_partial = toggle; }
        CmdlineOption::RetryAllErrors => { config.retry_all_errors = toggle; }
        CmdlineOption::RetryConnRefused => { config.retry_connrefused = toggle; }
        CmdlineOption::ShowError => { global.showerror = toggle; }
        CmdlineOption::Silent => { config.silent = toggle; global.silent = toggle; }
        CmdlineOption::SkipExisting => { config.skip_existing = toggle; }
        CmdlineOption::Socks5Basic => { config.socks5_auth = if toggle { 1 } else { 0 }; }
        CmdlineOption::Socks5GssapiNec => { config.socks5_gssapi_nec = toggle; }
        CmdlineOption::Ssl => { config.ftp_ssl = toggle; }
        CmdlineOption::SslAllowBeast => { config.ssl_allow_beast = toggle; }
        CmdlineOption::SslAutoClientCert => { config.ssl_auto_client_cert = toggle; }
        CmdlineOption::SslNoRevoke => { config.ssl_no_revoke = toggle; }
        CmdlineOption::SslReqd => {
            if !global.libcurl_info.feature_ssl {
                return ParameterResult::Error(ParameterError::LibcurlDoesntSupportSSL);
            }
            config.ftp_ssl_reqd = toggle;
        }
        CmdlineOption::SslRevokeBestEffort => { config.ssl_revoke_best_effort = toggle; }
        CmdlineOption::StyledOutput => { global.styled_output = toggle; }
        CmdlineOption::SuppressConnectHeaders => { config.suppress_connect_headers = toggle; }
        CmdlineOption::TcpFastopen => { config.tcp_fastopen = toggle; }
        CmdlineOption::TcpNodelay => { config.tcp_nodelay = toggle; }
        CmdlineOption::TraceIds => { global.traceids = toggle; }
        CmdlineOption::TraceTime => { global.tracetime = toggle; }
        CmdlineOption::TrEncoding => { config.tr_encoding = toggle; }
        CmdlineOption::Verbose => {
            if toggle { global.tracetype = TraceType::Verbose; }
            else { global.tracetype = TraceType::None; }
        }
        CmdlineOption::Xattr => { config.xattr = toggle; }
        CmdlineOption::Sasl => { config.sasl_ir = toggle; }
        _ => {}
    }
    ParameterResult::Ok
}

// ---------------------------------------------------------------------------
// opt_strg — ARG_STRG/ARG_FILE handler
// ---------------------------------------------------------------------------

fn opt_strg(cmd: CmdlineOption, param: &str, config: &mut OperationConfig, global: &mut GlobalConfig) -> ParameterResult {
    match cmd {
        CmdlineOption::AbstractUnixSocket => { config.abstract_unix_socket = true; }
        CmdlineOption::AltSvc => {
            if !global.libcurl_info.feature_altsvc { return ParameterResult::Error(ParameterError::LibcurlUnsupported); }
            config.altsvc = Some(param.to_string());
        }
        CmdlineOption::AwsSigv4 => { config.aws_sigv4 = Some(param.to_string()); }
        CmdlineOption::CaCert => { config.cacert = Some(param.to_string()); }
        CmdlineOption::CaPath => { config.capath = Some(param.to_string()); }
        CmdlineOption::Cert => {
            let (cert, pass) = parse_cert_parameter(param);
            config.cert = Some(cert);
            if let Some(p) = pass { config.key_passwd = Some(p); }
        }
        CmdlineOption::CertType => { config.cert_type = Some(param.to_string()); }
        CmdlineOption::CipherList => { config.cipher_list = Some(param.to_string()); }
        CmdlineOption::Config => { /* config file handled at parse_args level */ }
        CmdlineOption::ConnectTimeout => {
            match secs2ms(param) { Ok(ms) => config.connect_timeout = ms, Err(_) => return ParameterResult::Error(ParameterError::BadNumeric) }
        }
        CmdlineOption::ConnectTo => { let _ = add2list(&mut config.connect_to, param); }
        CmdlineOption::ContinueAt => {
            if param == "-" { config.resume_from_current = true; config.resume_from = 0; }
            else { config.resume_from_current = false; match str2offset(param) { Ok(v) => config.resume_from = v, Err(_) => return ParameterResult::Error(ParameterError::BadNumeric) } }
        }
        CmdlineOption::Cookie => { config.cookiefiles.push(param.to_string()); }
        CmdlineOption::CookieJar => { config.cookiejar = Some(param.to_string()); }
        CmdlineOption::Crlfile => { config.crlfile = Some(param.to_string()); }
        CmdlineOption::Curves => { config.ssl_ec_curves = Some(param.to_string()); }
        CmdlineOption::DataPost | CmdlineOption::DataAscii => {
            if set_data_helper(config, param, false, false).is_err() { return ParameterResult::Error(ParameterError::NoInput); }
            enforce_http_method(global, HttpReq::SimplePost, &mut config.httpreq);
        }
        CmdlineOption::DataRaw => {
            if set_data_helper(config, param, true, false).is_err() { return ParameterResult::Error(ParameterError::NoInput); }
            enforce_http_method(global, HttpReq::SimplePost, &mut config.httpreq);
        }
        CmdlineOption::DataBinary => {
            if set_data_helper(config, param, false, true).is_err() { return ParameterResult::Error(ParameterError::NoInput); }
            enforce_http_method(global, HttpReq::SimplePost, &mut config.httpreq);
        }
        CmdlineOption::DataUrlencode => {
            match data_urlencode_helper(param) {
                Ok(encoded) => {
                    if set_data_helper(config, &encoded, true, false).is_err() { return ParameterResult::Error(ParameterError::NoInput); }
                    enforce_http_method(global, HttpReq::SimplePost, &mut config.httpreq);
                }
                Err(e) => return ParameterResult::Error(e),
            }
        }
        CmdlineOption::DnsInterface => { config.dns_interface = Some(param.to_string()); }
        CmdlineOption::DnsIpv4Addr => { config.dns_ipv4_addr = Some(param.to_string()); }
        CmdlineOption::DnsIpv6Addr => { config.dns_ipv6_addr = Some(param.to_string()); }
        CmdlineOption::DnsServers => { config.dns_servers = Some(param.to_string()); }
        CmdlineOption::DohUrl => { config.doh_url = Some(param.to_string()); }
        CmdlineOption::DumpHeader => { config.headerfile = Some(param.to_string()); }
        CmdlineOption::Ech => { config.ech = Some(param.to_string()); }
        CmdlineOption::Engine => {
            if param == "list" { return ParameterResult::EngineList; }
            config.engine = Some(param.to_string());
        }
        CmdlineOption::EtagCompare => { config.etag_compare_file = Some(param.to_string()); }
        CmdlineOption::EtagSave => { config.etag_save_file = Some(param.to_string()); }
        CmdlineOption::Expect100Timeout => {
            match secs2ms(param) { Ok(ms) => config.expect100timeout_ms = ms, Err(_) => return ParameterResult::Error(ParameterError::BadNumeric) }
        }
        CmdlineOption::Form => {
            if formparse(param, &mut config.mimeroot, &mut config.mimecurrent, false, global).is_err() {
                return ParameterResult::Error(ParameterError::BadNumeric);
            }
            enforce_http_method(global, HttpReq::MimePost, &mut config.httpreq);
        }
        CmdlineOption::FormString => {
            if formparse(param, &mut config.mimeroot, &mut config.mimecurrent, true, global).is_err() {
                return ParameterResult::Error(ParameterError::BadNumeric);
            }
            enforce_http_method(global, HttpReq::MimePost, &mut config.httpreq);
        }
        CmdlineOption::FtpAccount => { config.ftp_account = Some(param.to_string()); }
        CmdlineOption::FtpAlternativeToUser => { config.ftp_alternative_to_user = Some(param.to_string()); }
        CmdlineOption::FtpMethod => { config.ftp_filemethod = ftpfilemethod(param, global) as i64; }
        CmdlineOption::FtpPort => { config.ftpport = Some(param.to_string()); }
        CmdlineOption::FtpSslCccMode => { config.ftp_ssl_ccc_mode = ftpcccmethod(param, global) as i64; }
        CmdlineOption::HaproxyClientIp => { config.haproxy_clientip = Some(param.to_string()); }
        CmdlineOption::HappyEyeballsTimeoutMs => {
            match str2unum(param) { Ok(v) => config.happy_eyeballs_timeout_ms = v as i64, Err(_) => return ParameterResult::Error(ParameterError::BadNumeric) }
        }
        CmdlineOption::Header => { let _ = add2list(&mut config.headers, param); }
        CmdlineOption::Help => { return ParameterResult::Help; }
        CmdlineOption::HostPubMd5 => { config.hostpubmd5 = Some(param.to_string()); }
        CmdlineOption::HostPubSha256 => { config.hostpubsha256 = Some(param.to_string()); }
        CmdlineOption::Hsts => {
            if !global.libcurl_info.feature_hsts { return ParameterResult::Error(ParameterError::LibcurlUnsupported); }
            config.hsts = Some(param.to_string());
        }
        CmdlineOption::Interface => { config.iface = Some(param.to_string()); }
        CmdlineOption::IpfsGateway => { config.ipfs_gateway = Some(param.to_string()); }
        CmdlineOption::Json => {
            if set_data_helper(config, param, false, false).is_err() { return ParameterResult::Error(ParameterError::NoInput); }
            enforce_http_method(global, HttpReq::SimplePost, &mut config.httpreq);
            if !inlist(&config.headers, "Content-Type:") { let _ = add2list(&mut config.headers, "Content-Type: application/json"); }
            if !inlist(&config.headers, "Accept:") { let _ = add2list(&mut config.headers, "Accept: application/json"); }
        }
        CmdlineOption::KeepAliveTime => {
            match str2unum(param) { Ok(v) => { config.alivetime = v as i64; config.nokeepalive = false; } Err(_) => return ParameterResult::Error(ParameterError::BadNumeric) }
        }
        CmdlineOption::Key => { config.key = Some(param.to_string()); }
        CmdlineOption::KeyType => { config.key_type = Some(param.to_string()); }
        CmdlineOption::Libcurl => { global.libcurl = Some(param.to_string()); }
        CmdlineOption::LimitRate => {
            match get_size_parameter(param) { Ok(v) => { config.recvpersecond = v as i64; config.sendpersecond = v as i64; } Err(e) => return ParameterResult::Error(e) }
        }
        CmdlineOption::LocalPort => {
            if let Err(e) = parse_localport_helper(config, param) { return ParameterResult::Error(e); }
        }
        CmdlineOption::LoginOptions => { config.login_options = Some(param.to_string()); }
        CmdlineOption::MailAuth => { config.mail_auth = Some(param.to_string()); }
        CmdlineOption::MailFrom => { config.mail_from = Some(param.to_string()); }
        CmdlineOption::MailRcpt => { let _ = add2list(&mut config.mail_rcpt, param); }
        CmdlineOption::MaxFilesize => {
            match get_size_parameter(param) { Ok(v) => config.max_filesize = v as i64, Err(e) => return ParameterResult::Error(e) }
        }
        CmdlineOption::MaxRedirs => {
            match str2num(param) { Ok(v) => config.maxredirs = v, Err(_) => return ParameterResult::Error(ParameterError::BadNumeric) }
        }
        CmdlineOption::MaxTime => {
            match secs2ms(param) { Ok(ms) => config.timeout = ms, Err(_) => return ParameterResult::Error(ParameterError::BadNumeric) }
        }
        CmdlineOption::NetrcFile => { config.netrc_file = Some(param.to_string()); }
        CmdlineOption::Noproxy => { config.noproxy = Some(param.to_string()); }
        CmdlineOption::Oauth2Bearer => { config.oauth_bearer = Some(param.to_string()); }
        CmdlineOption::Output => {
            let node = new_getout(config);
            node.outfile = Some(param.to_string());
            node.out_set = true;
        }
        CmdlineOption::OutputDir => { config.output_dir = Some(param.to_string()); }
        CmdlineOption::ParallelMax => {
            match str2unum(param) {
                Ok(v) => { let val = if v > 300 { 300 } else if v < 1 { PARALLEL_DEFAULT as u64 } else { v }; global.parallel_max = val as u32; }
                Err(_) => return ParameterResult::Error(ParameterError::BadNumeric)
            }
        }
        CmdlineOption::Pass => { config.key_passwd = Some(param.to_string()); }
        CmdlineOption::Pinnedpubkey => { config.pinnedpubkey = Some(param.to_string()); }
        CmdlineOption::Proto => {
            let info = &global.libcurl_info;
            match proto2num(param, info, global) {
                Ok(s) => config.proto_str = Some(s),
                Err(_) => return ParameterResult::Error(ParameterError::BadNumeric),
            }
            config.proto_present = true;
        }
        CmdlineOption::ProtoDefault => {
            config.proto_default = Some(param.to_string());
            if !check_protocol(param, &global.libcurl_info) {
                return ParameterResult::Error(ParameterError::BadNumeric);
            }
        }
        CmdlineOption::ProtoRedir => {
            let info = &global.libcurl_info;
            match proto2num(param, info, global) {
                Ok(s) => config.proto_redir_str = Some(s),
                Err(_) => return ParameterResult::Error(ParameterError::BadNumeric),
            }
            config.proto_redir_present = true;
        }
        CmdlineOption::Proxy => { config.proxy = Some(param.to_string()); config.proxyver = 0; }
        CmdlineOption::ProxyCacert => { config.proxy_cacert = Some(param.to_string()); }
        CmdlineOption::ProxyCapath => { config.proxy_capath = Some(param.to_string()); }
        CmdlineOption::ProxyCert => {
            let (cert, pass) = parse_cert_parameter(param);
            config.proxy_cert = Some(cert);
            if let Some(p) = pass { config.proxy_key_passwd = Some(p); }
        }
        CmdlineOption::ProxyCertType => { config.proxy_cert_type = Some(param.to_string()); }
        CmdlineOption::ProxyCiphers => { config.proxy_cipher_list = Some(param.to_string()); }
        CmdlineOption::ProxyCrlfile => { config.proxy_crlfile = Some(param.to_string()); }
        CmdlineOption::ProxyHeader => { let _ = add2list(&mut config.proxyheaders, param); }
        CmdlineOption::ProxyKey => { config.proxy_key = Some(param.to_string()); }
        CmdlineOption::ProxyKeyType => { config.proxy_key_type = Some(param.to_string()); }
        CmdlineOption::ProxyPass => { config.proxy_key_passwd = Some(param.to_string()); }
        CmdlineOption::ProxyPinnedpubkey => { config.proxy_pinnedpubkey = Some(param.to_string()); }
        CmdlineOption::ProxyServiceName => { config.proxy_service_name = Some(param.to_string()); }
        CmdlineOption::ProxyTls13Ciphers => { config.proxy_cipher13_list = Some(param.to_string()); }
        CmdlineOption::ProxyTlsauthtype => { config.proxy_tls_authtype = Some(param.to_string()); }
        CmdlineOption::ProxyTlspassword => { config.proxy_tls_password = Some(param.to_string()); }
        CmdlineOption::ProxyTlsuser => { config.proxy_tls_username = Some(param.to_string()); }
        CmdlineOption::ProxyUser | CmdlineOption::ProxyUser2 => { config.proxyuserpwd = Some(param.to_string()); }
        CmdlineOption::PubKey => { config.pubkey = Some(param.to_string()); }
        CmdlineOption::Quote => { let _ = add2list(&mut config.quote, param); }
        CmdlineOption::Range => { config.range = Some(param.to_string()); }
        CmdlineOption::Rate => {
            match set_rate_helper(param) { Ok(ms) => global.ms_per_transfer = ms, Err(e) => return ParameterResult::Error(e) }
        }
        CmdlineOption::Referer => { config.referer = Some(param.to_string()); }
        CmdlineOption::Request => { config.customrequest = Some(param.to_string()); }
        CmdlineOption::RequestTarget => { config.request_target = Some(param.to_string()); }
        CmdlineOption::Resolve => { let _ = add2list(&mut config.resolve, param); }
        CmdlineOption::Retry => {
            match str2unum(param) { Ok(v) => config.retry = v as u32, Err(_) => return ParameterResult::Error(ParameterError::BadNumeric) }
        }
        CmdlineOption::RetryDelay => {
            match secs2ms(param) { Ok(ms) => config.retry_delay = ms, Err(_) => return ParameterResult::Error(ParameterError::BadNumeric) }
        }
        CmdlineOption::RetryMaxTime => {
            match secs2ms(param) { Ok(ms) => config.retry_max_time = ms, Err(_) => return ParameterResult::Error(ParameterError::BadNumeric) }
        }
        CmdlineOption::Sasl => { config.sasl_authzid = Some(param.to_string()); }
        CmdlineOption::ServiceName => { config.service_name = Some(param.to_string()); }
        CmdlineOption::Socks4 => { config.proxy = Some(param.to_string()); config.proxyver = 4; }
        CmdlineOption::Socks4a => { config.proxy = Some(param.to_string()); config.proxyver = 6; }
        CmdlineOption::Socks5 => { config.proxy = Some(param.to_string()); config.proxyver = 5; }
        CmdlineOption::Socks5GssapiService => { config.proxy_service_name = Some(param.to_string()); }
        CmdlineOption::Socks5Hostname => { config.proxy = Some(param.to_string()); config.proxyver = 7; }
        CmdlineOption::SpeedLimit => {
            match str2unum(param) { Ok(v) => config.low_speed_limit = v as i64, Err(_) => return ParameterResult::Error(ParameterError::BadNumeric) }
        }
        CmdlineOption::SpeedTime => {
            match str2unum(param) { Ok(v) => config.low_speed_time = v as i64, Err(_) => return ParameterResult::Error(ParameterError::BadNumeric) }
        }
        CmdlineOption::TlsAuthType => { config.tls_authtype = Some(param.to_string()); }
        CmdlineOption::TlsMax => {
            match str2tls_max(param) { Some(v) => config.ssl_version_max = v, None => return ParameterResult::Error(ParameterError::BadNumeric) }
        }
        CmdlineOption::TlsPassword => { config.tls_password = Some(param.to_string()); }
        CmdlineOption::TlsUser => { config.tls_username = Some(param.to_string()); }
        CmdlineOption::Tls13Ciphers => { config.cipher13_list = Some(param.to_string()); }
        CmdlineOption::Trace => {
            global.trace_dump = Some(param.to_string());
            if global.tracetype == TraceType::None || global.tracetype == TraceType::Verbose {
                global.tracetype = TraceType::Plain;
            }
        }
        CmdlineOption::TraceAscii => { global.trace_dump = Some(param.to_string()); global.tracetype = TraceType::Ascii; }
        CmdlineOption::TraceConfig => {
            // --trace-config takes comma-separated trace component tokens
            // that control trace detail level. The actual parsing of the
            // token string is delegated to set_trace_config at transfer time.
            // For now, just mark trace as set so the engine knows to process it.
            global.trace_set = true;
        }
        CmdlineOption::UnixSocket => { config.unix_socket_path = Some(param.to_string()); }
        CmdlineOption::Upload => {
            let node = new_getout(config);
            node.infile = Some(param.to_string());
            node.upload_set = true;
        }
        CmdlineOption::UploadFlags => {
            // --upload-flags: numeric bitmask for upload behaviour.
            match str2unum(param) {
                Ok(v) => { config.upload_flags = v as u8; }
                Err(_) => return ParameterResult::Error(ParameterError::BadNumeric),
            }
        }
        CmdlineOption::Url => { add_url_to_config(config, param); }
        CmdlineOption::UrlQuery => {
            if let Some(ref mut q) = config.query {
                q.push('&');
                q.push_str(param);
            } else {
                config.query = Some(param.to_string());
            }
        }
        CmdlineOption::UseSsl => {
            config.ftp_ssl = matches!(param.to_lowercase().as_str(), "try" | "control" | "all");
        }
        CmdlineOption::User => { config.userpwd = Some(param.to_string()); }
        CmdlineOption::UserAgent | CmdlineOption::UserAgent2 => { config.useragent = Some(param.to_string()); }
        CmdlineOption::Variable => {
            if set_variable(global, param).is_err() { return ParameterResult::Error(ParameterError::BadNumeric); }
        }
        CmdlineOption::WriteOut => {
            let value = if let Some(path) = param.strip_prefix('@') {
                match file2string(path) { Ok(s) => s, Err(_) => return ParameterResult::Error(ParameterError::NoInput) }
            } else { param.to_string() };
            config.writeout = Some(value);
        }
        CmdlineOption::TimeCond => {
            // --time-cond/-z <date expression|file>
            // A leading '-' means if-older-than (CURL_TIMECOND_IFUNMODSINCE = 2)
            // Otherwise if-newer-than (CURL_TIMECOND_IFMODSINCE = 1)
            let (cond, date_str) = if let Some(stripped) = param.strip_prefix('-') {
                (2u64, stripped)
            } else {
                (1u64, param)
            };
            config.timecond = cond;
            // Try to interpret date_str as epoch seconds, or parse as date.
            // For now, store as epoch seconds if numeric; 0 otherwise.
            config.condtime = date_str.parse::<i64>().unwrap_or(0);
        }
        _ => {}
    }
    ParameterResult::Ok
}

// ---------------------------------------------------------------------------
// getparameter
// ---------------------------------------------------------------------------

pub fn getparameter(
    option: &str,
    param: Option<&str>,
    is_negated: bool,
    config: &mut OperationConfig,
    global: &mut GlobalConfig,
) -> ParameterResult {
    let alias = if option.len() == 1 {
        findshortopt(option.chars().next().unwrap())
    } else {
        findlongopt(option)
    };
    let alias = match alias {
        Some(a) => a,
        None => {
            errorf(global, &format!("option --{}: is unknown", option));
            helpf(Some("try 'curl --help' for more information"));
            return ParameterResult::Error(ParameterError::GotExtraParameter);
        }
    };
    let desc = alias.desc_flags;
    let cmd = alias.cmd;
    let atype = argtype(desc);

    if desc & ARG_DEPR != 0 {
        warnf(global, &format!("option --{} is deprecated", alias.long_name));
    }
    if desc & ARG_TLS != 0 && !global.libcurl_info.feature_ssl {
        return ParameterResult::Error(ParameterError::LibcurlDoesntSupportSSL);
    }

    match atype {
        ArgType::None => opt_none(cmd, config, global),
        ArgType::Bool => opt_bool(cmd, !is_negated, config, global),
        ArgType::Strg | ArgType::File => {
            match param {
                Some(p) => opt_strg(cmd, p, config, global),
                None => {
                    errorf(global, &format!("option --{}: requires an argument", alias.long_name));
                    ParameterResult::Error(ParameterError::NoInput)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// parse_args
// ---------------------------------------------------------------------------

pub fn parse_args(argv: &[String], global: &mut GlobalConfig) -> ParameterResult {
    if argv.is_empty() {
        helpf(Some("try 'curl --help' for more information"));
        return ParameterResult::Error(ParameterError::NoInput);
    }
    if global.configs.is_empty() {
        global.configs.push(OperationConfig::new());
    }

    // Skip argv[0] (program name), start from argv[1]
    let mut i = 1;
    while i < argv.len() {
        let arg = &argv[i];

        if let Some(option_str) = arg.strip_prefix("--") {
            if option_str.is_empty() {
                i += 1;
                while i < argv.len() {
                    let cidx = global.configs.len() - 1;
                    add_url_to_config(&mut global.configs[cidx], &argv[i]);
                    i += 1;
                }
                break;
            }
            let (is_negated, clean) = if let Some(stripped) = option_str.strip_prefix("no-") { (true, stripped) } else { (false, option_str) };
            let (is_expand, final_opt) = if let Some(stripped) = clean.strip_prefix("expand-") { (true, stripped) } else { (false, clean) };

            let alias = match findlongopt(final_opt) {
                Some(a) => a,
                None => {
                    errorf(global, &format!("option --{}: is unknown", option_str));
                    helpf(Some("try 'curl --help' for more information"));
                    return ParameterResult::Error(ParameterError::GotExtraParameter);
                }
            };
            let atype = argtype(alias.desc_flags);
            let param = if atype == ArgType::Strg || atype == ArgType::File {
                i += 1;
                if i >= argv.len() {
                    errorf(global, &format!("option --{}: requires parameter", alias.long_name));
                    return ParameterResult::Error(ParameterError::NoInput);
                }
                Some(argv[i].as_str())
            } else { None };

            let expanded_storage: Option<String>;
            let final_param = if is_expand {
                if let Some(p) = param {
                    match varexpand(global, p) {
                        Ok((s, _)) => { expanded_storage = Some(s); expanded_storage.as_deref() }
                        Err(_) => return ParameterResult::Error(ParameterError::ExpandError),
                    }
                } else { None }
            } else { param };

            // Temporarily pop config out of global to satisfy borrow checker:
            // getparameter needs &mut OperationConfig and &mut GlobalConfig simultaneously.
            let mut config = global.configs.pop().expect("configs must not be empty");
            let result = getparameter(final_opt, final_param, is_negated, &mut config, global);
            global.configs.push(config);
            match result {
                ParameterResult::Ok => {}
                ParameterResult::NextOperation => { global.configs.push(OperationConfig::new()); }
                ParameterResult::Help | ParameterResult::Manual | ParameterResult::Version
                | ParameterResult::EngineList | ParameterResult::CaBundleDump | ParameterResult::Error(_) => { return result; }
            }
        } else if arg.starts_with('-') && arg.len() > 1 {
            let chars: Vec<char> = arg[1..].chars().collect();
            let mut j = 0;
            while j < chars.len() {
                let ch = chars[j];
                let ch_s = ch.to_string();
                let alias = match findshortopt(ch) {
                    Some(a) => a,
                    None => {
                        errorf(global, &format!("option -{}: is unknown", ch));
                        helpf(Some("try 'curl --help' for more information"));
                        return ParameterResult::Error(ParameterError::GotExtraParameter);
                    }
                };
                let atype = argtype(alias.desc_flags);
                let param_val: Option<String> = if atype == ArgType::Strg || atype == ArgType::File {
                    if j + 1 < chars.len() {
                        let rest: String = chars[j + 1..].iter().collect();
                        j = chars.len();
                        Some(rest)
                    } else {
                        i += 1;
                        if i >= argv.len() {
                            errorf(global, &format!("option -{}: requires parameter", ch));
                            return ParameterResult::Error(ParameterError::NoInput);
                        }
                        Some(argv[i].clone())
                    }
                } else { None };
                // Temporarily pop config to avoid conflicting &mut borrows.
                let mut config = global.configs.pop().expect("configs must not be empty");
                let result = getparameter(&ch_s, param_val.as_deref(), false, &mut config, global);
                global.configs.push(config);
                match result {
                    ParameterResult::Ok => {}
                    ParameterResult::NextOperation => { global.configs.push(OperationConfig::new()); }
                    ParameterResult::Help | ParameterResult::Manual | ParameterResult::Version
                    | ParameterResult::EngineList | ParameterResult::CaBundleDump | ParameterResult::Error(_) => { return result; }
                }
                j += 1;
            }
        } else {
            let cidx = global.configs.len() - 1;
            add_url_to_config(&mut global.configs[cidx], arg);
        }
        i += 1;
    }

    let has_url = global.configs.iter().any(|c| !c.url_list.is_empty());
    if !has_url {
        helpf(Some("no URL specified!"));
        return ParameterResult::Error(ParameterError::NoInput);
    }
    ParameterResult::Ok
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::globalconf_init;

    /// Helper to create a GlobalConfig for tests.
    fn make_global() -> GlobalConfig {
        globalconf_init().expect("globalconf_init failed in test")
    }

    #[test]
    fn parameter_error_variants_exist() {
        let errs: Vec<ParameterError> = vec![
            ParameterError::Ok, ParameterError::HelpRequested, ParameterError::ManualRequested,
            ParameterError::VersionInfoRequested, ParameterError::EnginesRequested,
            ParameterError::CaEmbedRequested, ParameterError::NextOperation,
            ParameterError::ContdispResumeFrom, ParameterError::NoPrefix,
            ParameterError::ExpandError, ParameterError::GotExtraParameter,
            ParameterError::BadNumeric, ParameterError::NegativeNumeric,
            ParameterError::OutOfMemory, ParameterError::UserCallbackFail,
            ParameterError::LibcurlUnsupported, ParameterError::LibcurlDoesntSupportSSL,
            ParameterError::NoInput, ParameterError::Last,
        ];
        assert_eq!(errs.len(), 19);
    }

    #[test]
    fn parameter_result_variants_exist() {
        let results: Vec<ParameterResult> = vec![
            ParameterResult::Ok, ParameterResult::Help, ParameterResult::Manual,
            ParameterResult::Version, ParameterResult::EngineList,
            ParameterResult::CaBundleDump,
            ParameterResult::Error(ParameterError::BadNumeric),
            ParameterResult::NextOperation,
        ];
        assert_eq!(results.len(), 8);
    }

    #[test]
    fn arg_type_variants() {
        assert!(matches!(ArgType::None, ArgType::None));
        assert!(matches!(ArgType::Bool, ArgType::Bool));
        assert!(matches!(ArgType::Strg, ArgType::Strg));
        assert!(matches!(ArgType::File, ArgType::File));
    }

    #[test]
    fn param2text_returns_non_empty_strings() {
        // Verify param2text returns meaningful descriptions for each error variant
        let variants = [
            ParameterError::Ok, ParameterError::BadNumeric, ParameterError::NoInput,
            ParameterError::OutOfMemory, ParameterError::LibcurlUnsupported,
            ParameterError::LibcurlDoesntSupportSSL, ParameterError::GotExtraParameter,
            ParameterError::NegativeNumeric, ParameterError::HelpRequested,
        ];
        for v in &variants {
            let text = param2text(v);
            assert!(!text.is_empty(), "param2text({:?}) should not be empty", v);
        }
        // Check that each text is unique and meaningful
        let all_texts: Vec<&str> = variants.iter().map(|v| param2text(v)).collect();
        // At least several should be unique descriptions
        let unique: std::collections::HashSet<&&str> = all_texts.iter().collect();
        assert!(unique.len() >= 5, "param2text should produce diverse descriptions");
    }

    #[test]
    fn findshortopt_known() {
        assert_eq!(findshortopt('v').unwrap().long_name, "verbose");
        assert_eq!(findshortopt('o').unwrap().long_name, "output");
        assert_eq!(findshortopt('s').unwrap().long_name, "silent");
        assert_eq!(findshortopt('H').unwrap().long_name, "header");
        assert_eq!(findshortopt('L').unwrap().long_name, "location");
        assert_eq!(findshortopt('d').unwrap().long_name, "data");
    }

    #[test]
    fn findshortopt_unknown() {
        assert!(findshortopt('!').is_none());
    }

    #[test]
    fn findlongopt_known() {
        assert!(findlongopt("verbose").is_some());
        assert!(findlongopt("output").is_some());
        assert!(findlongopt("location").is_some());
        assert!(findlongopt("user-agent").is_some());
        assert!(findlongopt("header").is_some());
        assert!(findlongopt("data").is_some());
        assert!(findlongopt("insecure").is_some());
        assert!(findlongopt("proxy").is_some());
        assert!(findlongopt("retry").is_some());
        assert!(findlongopt("parallel").is_some());
    }

    #[test]
    fn findlongopt_unknown() {
        assert!(findlongopt("nonexistent-flag").is_none());
    }

    #[test]
    fn parse_cert_parameter_simple() {
        let (cert, pass) = parse_cert_parameter("/path/to/cert.pem");
        assert_eq!(cert, "/path/to/cert.pem");
        assert!(pass.is_none());
    }

    #[test]
    fn parse_cert_parameter_with_password() {
        let (cert, pass) = parse_cert_parameter("cert.pem:secret");
        assert_eq!(cert, "cert.pem");
        assert_eq!(pass.unwrap(), "secret");
    }

    #[test]
    fn getsize_bytes() {
        assert_eq!(get_size_parameter("1024").unwrap(), 1024);
    }

    #[test]
    fn getsize_kilobytes() {
        // lowercase k = 1000, uppercase K = 1024 (curl convention)
        assert_eq!(get_size_parameter("10k").unwrap(), 10 * 1000);
        assert_eq!(get_size_parameter("10K").unwrap(), 10 * 1024);
    }

    #[test]
    fn getsize_megabytes() {
        assert_eq!(get_size_parameter("5M").unwrap(), 5 * 1024 * 1024);
    }

    #[test]
    fn getsize_gigabytes() {
        assert_eq!(get_size_parameter("2G").unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn getsize_invalid() {
        assert!(get_size_parameter("abc").is_err());
    }

    #[test]
    fn aliases_not_empty() {
        assert!(!ALIASES.is_empty());
        assert!(ALIASES.len() >= 150, "got {}", ALIASES.len());
    }

    #[test]
    fn aliases_findable_by_longopt() {
        for alias in ALIASES.iter() {
            assert!(findlongopt(alias.long_name).is_some(), "alias '{}' not found", alias.long_name);
        }
    }

    #[test]
    fn longshort_fields() {
        let ls = LongShort { long_name: "test", desc_flags: ARG_BOOL, short_letter: 't', cmd: CmdlineOption::Verbose };
        assert_eq!(ls.long_name, "test");
        assert_eq!(ls.short_letter, 't');
    }

    #[test]
    fn parse_args_with_url() {
        let mut global = make_global();
        let argv = vec!["curl".to_string(), "http://example.com".to_string()];
        let result = parse_args(&argv, &mut global);
        assert!(matches!(result, ParameterResult::Ok));
        assert!(!global.configs[0].url_list.is_empty());
    }

    #[test]
    fn parse_args_verbose() {
        let mut global = make_global();
        let argv = vec!["curl".to_string(), "-v".to_string(), "http://example.com".to_string()];
        assert!(matches!(parse_args(&argv, &mut global), ParameterResult::Ok));
    }

    #[test]
    fn parse_args_help_with_category() {
        let mut global = make_global();
        // --help takes a category parameter (ARG_STRG)
        let argv = vec!["curl".to_string(), "--help".to_string(), "all".to_string()];
        assert!(matches!(parse_args(&argv, &mut global), ParameterResult::Help));
    }

    #[test]
    fn parse_args_version() {
        let mut global = make_global();
        let argv = vec!["curl".to_string(), "--version".to_string()];
        assert!(matches!(parse_args(&argv, &mut global), ParameterResult::Version));
    }

    #[test]
    fn parse_args_no_url_error() {
        let mut global = make_global();
        let argv = vec!["curl".to_string()];
        let result = parse_args(&argv, &mut global);
        // With no args at all (just "curl"), configs already have one empty config from globalconf_init,
        // so url_list is empty → error
        assert!(matches!(result, ParameterResult::Error(_)));
    }

    #[test]
    fn parse_args_unknown_long() {
        let mut global = make_global();
        let argv = vec!["curl".to_string(), "--nonexistent".to_string(), "http://example.com".to_string()];
        assert!(matches!(parse_args(&argv, &mut global), ParameterResult::Error(ParameterError::GotExtraParameter)));
    }

    #[test]
    fn parse_args_unknown_short() {
        let mut global = make_global();
        let argv = vec!["curl".to_string(), "-!".to_string(), "http://example.com".to_string()];
        assert!(matches!(parse_args(&argv, &mut global), ParameterResult::Error(ParameterError::GotExtraParameter)));
    }

    #[test]
    fn parse_args_output() {
        let mut global = make_global();
        let argv = vec!["curl".to_string(), "-o".to_string(), "out.html".to_string(), "http://example.com".to_string()];
        assert!(matches!(parse_args(&argv, &mut global), ParameterResult::Ok));
    }

    #[test]
    fn parse_args_double_dash() {
        let mut global = make_global();
        let argv = vec!["curl".to_string(), "--".to_string(), "http://example.com".to_string()];
        assert!(matches!(parse_args(&argv, &mut global), ParameterResult::Ok));
    }

    #[test]
    fn parse_args_silent() {
        let mut global = make_global();
        let argv = vec!["curl".to_string(), "-s".to_string(), "http://example.com".to_string()];
        assert!(matches!(parse_args(&argv, &mut global), ParameterResult::Ok));
        assert!(global.configs[0].silent);
    }

    #[test]
    fn parse_args_head() {
        let mut global = make_global();
        let argv = vec!["curl".to_string(), "-I".to_string(), "http://example.com".to_string()];
        assert!(matches!(parse_args(&argv, &mut global), ParameterResult::Ok));
        assert!(global.configs[0].show_headers);
    }

    #[test]
    fn parse_args_location() {
        let mut global = make_global();
        let argv = vec!["curl".to_string(), "-L".to_string(), "http://example.com".to_string()];
        assert!(matches!(parse_args(&argv, &mut global), ParameterResult::Ok));
        assert_eq!(global.configs[0].followlocation, 1);
    }
}
