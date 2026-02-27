//! CLI configuration management for the curl-rs binary crate.
//!
//! This module is the Rust rewrite of `src/tool_cfgable.c`,
//! `src/tool_cfgable.h`, and `src/tool_sdecls.h` from curl 8.19.0-DEV.
//! It defines the [`GlobalConfig`] and [`OperationConfig`] types that hold
//! all CLI-parsed state, with constructor defaults, field cleanup, and
//! global lifecycle management.
//!
//! # Design Notes
//!
//! The C implementation uses:
//! - A global `struct GlobalConfig` containing process-wide settings.
//! - A linked list of `struct OperationConfig` nodes, one per `--next`
//!   separated URL block.
//! - Manual `malloc`/`free` lifecycle via `config_alloc`/`config_free`/
//!   `free_config_fields`/`globalconf_init`/`globalconf_free`.
//!
//! The Rust rewrite replaces all manual memory management with ownership
//! semantics:
//! - `OperationConfig` uses `Vec`, `Option<String>`, and `Box` for all
//!   dynamically sized data.
//! - The linked-list chain of `OperationConfig` nodes is replaced by a
//!   `Vec<OperationConfig>` in `GlobalConfig`.
//! - Cleanup is automatic via `Drop`; `free_config_fields` is provided
//!   for explicit field reset when reusing a config node.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks.

use std::io::{self, BufWriter, Write};

use crate::libinfo::{get_libcurl_info, LibCurlInfo};
use curl_rs_lib::{CurlError, CurlResult, global_init, global_cleanup};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum number of HTTP redirects to follow (`-L`).
///
/// Matches the C constant `DEFAULT_MAXREDIRS` (50).
pub const DEFAULT_MAXREDIRS: i64 = 50;

/// Default maximum number of parallel transfers (`--parallel-max`).
///
/// Matches the C constant `PARALLEL_DEFAULT` (50).
pub const PARALLEL_DEFAULT: u32 = 50;

/// Maximum size (in bytes) for file-to-memory reads (40 MiB).
///
/// Matches the C constant `MAX_FILE2MEMORY` (40 * 1024 * 1024).
pub const MAX_FILE2MEMORY: usize = 40 * 1024 * 1024;

/// Maximum length of a single configuration file line (10 MiB).
///
/// Matches the C constant `MAX_CONFIG_LINE_LENGTH`.
pub const MAX_CONFIG_LINE_LENGTH: usize = 10 * 1024 * 1024;

/// Default Happy Eyeballs timeout in milliseconds.
///
/// Matches the C constant `CURL_HET_DEFAULT` (200 ms).
pub const CURL_HET_DEFAULT: i64 = 200;

/// Default clobber mode constant.
///
/// Provides compatibility with previous versions of curl: `-o` and `-O`
/// overwrite, while `-J` does not.
pub const CLOBBER_DEFAULT: ClobberMode = ClobberMode::Always;

/// Upload flag sentinel indicating `--upload-flags` has been processed.
///
/// Matches the C constant `CURLULFLAG_SEEN`.
pub const CURLULFLAG_SEEN: u8 = 0x01;

/// No failure mode for `--fail` variants.
pub const FAIL_NONE: u8 = 0;
/// `--fail-with-body` mode.
pub const FAIL_WITH_BODY: u8 = 1;
/// `--fail` (without body) mode.
pub const FAIL_WO_BODY: u8 = 2;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// File overwrite policy for output files (`-o`, `-O`, `-J`).
///
/// Maps 1:1 to the C anonymous enum inside `struct OperationConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClobberMode {
    /// Always overwrite existing files (default for `-o`/`-O`).
    Always,
    /// Never overwrite — fail if the file already exists.
    Never,
    /// Rename the new file to avoid collision (e.g., append `.1`, `.2`).
    Rename,
}

/// Trace/verbose output mode.
///
/// Maps 1:1 to the C `trace` enum in `tool_sdecls.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceType {
    /// No trace or verbose output.
    None,
    /// ASCII trace output (`--trace-ascii`).
    Ascii,
    /// Plain binary/hex trace output (`--trace`).
    Plain,
    /// Verbose mode (`-v` / `--verbose`).
    Verbose,
}

/// HTTP request method selector.
///
/// Used for explicit `-X`/`--request` overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Head,
    Delete,
    Patch,
    /// A custom method string provided via `-X`.
    Custom(String),
}

/// Internal HTTP request type classification.
///
/// Maps 1:1 to the C `HttpReq` enum (`TOOL_HTTPREQ_*`) in `tool_sdecls.h`.
/// Used to select the appropriate request body handling strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpReq {
    /// No specific request type selected yet.
    Unspec = 0,
    /// GET request (possibly with query data via `--get`).
    Get = 1,
    /// HEAD request (`-I`/`--head`).
    Head = 2,
    /// MIME multipart POST (`-F`/`--form`).
    MimePost = 3,
    /// Simple POST with body data (`-d`/`--data`).
    SimplePost = 4,
    /// PUT upload (`-T`/`--upload-file` with HTTP).
    Put = 5,
}

/// Sanitize error codes for path/filename sanitization.
///
/// Maps 1:1 to the C `SANITIZEcode` enum in `tool_sdecls.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizeCode {
    /// Sanitization succeeded.
    Ok = 0,
    /// The path is invalid.
    InvalidPath = 1,
    /// Bad function parameter.
    BadArgument = 2,
    /// Out of memory.
    OutOfMemory = 3,
}

// ---------------------------------------------------------------------------
// MIME tree types (for -F/--form)
// ---------------------------------------------------------------------------

/// Classification of a MIME part's content source.
///
/// Maps 1:1 to the C `toolmime` enum values (`TOOLMIME_PARTS`, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolMimeKind {
    /// Multipart container (opened with `(`).
    Parts,
    /// Literal data content.
    Data,
    /// File content to be read and embedded.
    FileData,
    /// File reference (sent as an upload).
    File,
    /// Content read from stdin.
    Stdin,
}

/// A node in the MIME tree built from `-F`/`--form` arguments.
///
/// Maps to the C `struct tool_mime`. Rust's `Vec<ToolMime>` for subparts
/// replaces the C linked list.
#[derive(Debug, Clone)]
pub struct ToolMime {
    /// Content source classification.
    pub kind: ToolMimeKind,
    /// Part name (the `name` in `name=value`).
    pub name: Option<String>,
    /// Literal data content or file path.
    pub data: Option<String>,
    /// Override filename for file uploads.
    pub filename: Option<String>,
    /// MIME content type override.
    pub content_type: Option<String>,
    /// Transfer encoding (e.g., `base64`).
    pub encoder: Option<String>,
    /// Per-part custom headers.
    pub headers: Vec<String>,
    /// Nested subparts for multipart containers.
    pub subparts: Vec<ToolMime>,
    /// Original source path for file-backed parts.
    pub origin: Option<String>,
}

impl ToolMime {
    /// Creates a new, empty MIME node of the given kind.
    pub fn new(kind: ToolMimeKind) -> Self {
        Self {
            kind,
            name: None,
            data: None,
            filename: None,
            content_type: None,
            encoder: None,
            headers: Vec::new(),
            subparts: Vec::new(),
            origin: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Variable storage (--variable)
// ---------------------------------------------------------------------------

/// A user-defined variable set via `--variable name=value`.
///
/// Maps to the C `struct tool_var`. Content is stored as raw bytes for
/// binary safety.
#[derive(Debug, Clone)]
pub struct ToolVar {
    /// Variable name (alphanumeric + underscore, max 127 chars).
    pub name: String,
    /// Variable content (binary-safe).
    pub content: Vec<u8>,
}

// ---------------------------------------------------------------------------
// URL output node (GetOut)
// ---------------------------------------------------------------------------

/// A single URL entry in the transfer list.
///
/// Maps 1:1 to the C `struct getout` in `tool_sdecls.h`. The C linked list
/// is replaced by `Vec<GetOut>` on [`OperationConfig`].
#[derive(Debug, Clone)]
pub struct GetOut {
    /// The URL to transfer.
    pub url: Option<String>,
    /// Output file path (for `-o`).
    pub outfile: Option<String>,
    /// Input file path (for `-T` upload).
    pub infile: Option<String>,
    /// Sequential number of this URL in the invocation.
    pub num: i64,
    /// Whether `--url` was explicitly used to set this URL.
    pub url_set: bool,
    /// Whether `-o` was used to set the output file.
    pub out_set: bool,
    /// Whether `-T` was used to set an upload file.
    pub upload_set: bool,
    /// Use remote filename as local filename (`-O`).
    pub use_remote: bool,
    /// Upload disabled (`-T ""`).
    pub no_upload: bool,
    /// Disable globbing for this URL (`-g`).
    pub no_glob: bool,
    /// Discard output for this URL.
    pub out_null: bool,
}

impl GetOut {
    /// Creates a new, empty URL output node.
    pub fn new() -> Self {
        Self {
            url: None,
            outfile: None,
            infile: None,
            num: 0,
            url_set: false,
            out_set: false,
            upload_set: false,
            use_remote: false,
            no_upload: false,
            no_glob: false,
            out_null: false,
        }
    }
}

impl Default for GetOut {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Transfer iteration state
// ---------------------------------------------------------------------------

/// Iteration state for URL globbing and upload file processing within a
/// single [`OperationConfig`] block.
///
/// Maps to the C `struct State` in `tool_cfgable.h`.
#[derive(Debug, Clone)]
pub struct TransferState {
    /// Index into `url_list` for the current URL node.
    pub url_node_idx: Option<usize>,
    /// HTTP GET query fields accumulated via `--get`.
    pub httpgetfields: Option<String>,
    /// Current upload filename (from URL glob expansion).
    pub uploadfile: Option<String>,
    /// Total number of files to upload (from glob).
    pub up_num: i64,
    /// Current upload file index.
    pub up_idx: i64,
    /// Total number of URL iterations (with ranges/globs).
    pub url_num: i64,
    /// Current URL iteration index.
    pub url_idx: i64,
}

impl TransferState {
    /// Creates a new, zeroed transfer iteration state.
    pub fn new() -> Self {
        Self {
            url_node_idx: None,
            httpgetfields: None,
            uploadfile: None,
            up_num: 0,
            up_idx: 0,
            url_num: 0,
            url_idx: 0,
        }
    }
}

impl Default for TransferState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Terminal state (Windows terminal buffer abstraction)
// ---------------------------------------------------------------------------

/// Terminal output buffer state, primarily used for Windows console handling.
///
/// On Windows, this wraps a wide-character buffer for UTF-16 output. On
/// non-Windows platforms it is an empty struct (zero-cost).
#[derive(Debug, Clone, Default)]
pub struct TerminalState {
    /// Wide-character output buffer (used on Windows for console writes).
    #[cfg(windows)]
    pub buf: Vec<u16>,
    /// Buffer length in characters (Windows only).
    #[cfg(windows)]
    pub len: u32,
    /// Placeholder field so the struct is non-empty on all platforms.
    /// This enables consistent handling across OS targets.
    #[cfg(not(windows))]
    _phantom: (),
}

impl TerminalState {
    /// Creates a new, empty terminal state.
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// OperationConfig
// ---------------------------------------------------------------------------

/// Per-URL-block configuration for a single transfer or group of transfers.
///
/// This is the Rust equivalent of the C `struct OperationConfig` defined in
/// `tool_cfgable.h`. Each `--next` separator on the CLI creates a new
/// `OperationConfig` node. Fields are grouped by subsystem and documented
/// with the corresponding C field name for cross-reference.
///
/// All `Option<String>` fields default to `None`, all `bool` fields default
/// to `false`, and all numeric fields default to `0` unless otherwise noted
/// in [`OperationConfig::new`].
#[derive(Debug, Clone)]
pub struct OperationConfig {
    // -- POST data (C: struct dynbuf postdata) --
    /// Accumulated POST data buffer.
    pub postdata: Vec<u8>,

    // -- User agent --
    /// Custom User-Agent string (`-A`/`--user-agent`).
    pub useragent: Option<String>,

    // -- Cookies --
    /// Inline cookie strings to serialize (`-b` with data).
    pub cookies: Vec<String>,
    /// Cookie jar output file (`-c`/`--cookie-jar`).
    pub cookiejar: Option<String>,
    /// Cookie files to load from (`-b` with filename).
    pub cookiefiles: Vec<String>,

    // -- Alt-Svc / HSTS --
    /// Alt-Svc cache filename (`--alt-svc`).
    pub altsvc: Option<String>,
    /// HSTS cache filename (`--hsts`).
    pub hsts: Option<String>,

    // -- Protocol strings --
    /// Protocol allow string (`--proto`).
    pub proto_str: Option<String>,
    /// Protocol redirect allow string (`--proto-redir`).
    pub proto_redir_str: Option<String>,
    /// Default protocol (`--proto-default`).
    pub proto_default: Option<String>,

    // -- Resume --
    /// Resume offset (`-C`/`--continue-at`).
    pub resume_from: i64,

    // -- POST fields (raw string form) --
    /// Raw postfields string.
    pub postfields: Option<String>,

    // -- Referer / query --
    /// Referer header (`-e`/`--referer`).
    pub referer: Option<String>,
    /// URL query data (`--url-query`).
    pub query: Option<String>,

    // -- Limits --
    /// Maximum file size (`--max-filesize`).
    pub max_filesize: i64,

    // -- Output --
    /// Output file path (`-o`/`--output`). Per-URL output files also live
    /// in [`GetOut::outfile`]; this field serves as a top-level shorthand
    /// that consumers may set before URL list construction.
    pub outfile: Option<String>,
    /// Output directory (`--output-dir`).
    pub output_dir: Option<String>,
    /// Header output file (`-D`/`--dump-header`).
    pub headerfile: Option<String>,

    // -- FTP --
    /// FTP PORT address (`-P`/`--ftp-port`).
    pub ftpport: Option<String>,

    // -- Network interface --
    /// Bind to interface (`--interface`).
    pub iface: Option<String>,

    // -- Range --
    /// Byte range (`-r`/`--range`).
    pub range: Option<String>,

    // -- DNS --
    /// DNS server list (`--dns-servers`).
    pub dns_servers: Option<String>,
    /// DNS interface (`--dns-interface`).
    pub dns_interface: Option<String>,
    /// DNS IPv4 address (`--dns-ipv4-addr`).
    pub dns_ipv4_addr: Option<String>,
    /// DNS IPv6 address (`--dns-ipv6-addr`).
    pub dns_ipv6_addr: Option<String>,

    // -- Credentials --
    /// User credentials (`-u`/`--user` as `user:password`).
    pub userpwd: Option<String>,
    /// Login options string.
    pub login_options: Option<String>,
    /// TLS-SRP username (`--tlsuser`).
    pub tls_username: Option<String>,
    /// TLS-SRP password (`--tlspassword`).
    pub tls_password: Option<String>,
    /// TLS-SRP auth type (`--tlsauthtype`).
    pub tls_authtype: Option<String>,
    /// Proxy TLS-SRP username.
    pub proxy_tls_username: Option<String>,
    /// Proxy TLS-SRP password.
    pub proxy_tls_password: Option<String>,
    /// Proxy TLS-SRP auth type.
    pub proxy_tls_authtype: Option<String>,
    /// Proxy credentials (`-U`/`--proxy-user`).
    pub proxyuserpwd: Option<String>,

    // -- Proxy --
    /// Proxy URL (`-x`/`--proxy`).
    pub proxy: Option<String>,
    /// No-proxy host list (`--noproxy`).
    pub noproxy: Option<String>,

    // -- SSH --
    /// Known hosts file path (`--hostpubmd5` discovery).
    pub knownhosts: Option<String>,

    // -- Mail --
    /// Mail sender (`--mail-from`).
    pub mail_from: Option<String>,
    /// Mail recipients (`--mail-rcpt`).
    pub mail_rcpt: Vec<String>,
    /// Mail auth identity (`--mail-auth`).
    pub mail_auth: Option<String>,

    // -- SASL --
    /// SASL authorization identity (`--sasl-authzid`).
    pub sasl_authzid: Option<String>,

    // -- Netrc --
    /// Netrc file path (`--netrc-file`).
    pub netrc_file: Option<String>,

    // -- URL list --
    /// List of URL output nodes.
    pub url_list: Vec<GetOut>,

    // -- IPFS --
    /// IPFS gateway URL (`--ipfs-gateway`).
    pub ipfs_gateway: Option<String>,

    // -- DoH --
    /// DNS-over-HTTPS URL (`--doh-url`).
    pub doh_url: Option<String>,

    // -- TLS / Ciphers --
    /// Cipher list (`--ciphers`).
    pub cipher_list: Option<String>,
    /// Proxy cipher list (`--proxy-ciphers`).
    pub proxy_cipher_list: Option<String>,
    /// TLS 1.3 cipher list (`--tls13-ciphers`).
    pub cipher13_list: Option<String>,
    /// Proxy TLS 1.3 cipher list.
    pub proxy_cipher13_list: Option<String>,

    // -- Certificates --
    /// Client certificate (`-E`/`--cert`).
    pub cert: Option<String>,
    /// Proxy client certificate.
    pub proxy_cert: Option<String>,
    /// Certificate type (PEM, DER, P12).
    pub cert_type: Option<String>,
    /// Proxy certificate type.
    pub proxy_cert_type: Option<String>,
    /// CA certificate file (`--cacert`).
    pub cacert: Option<String>,
    /// Proxy CA certificate.
    pub proxy_cacert: Option<String>,
    /// CA certificate directory (`--capath`).
    pub capath: Option<String>,
    /// Proxy CA directory.
    pub proxy_capath: Option<String>,
    /// CRL file (`--crlfile`).
    pub crlfile: Option<String>,
    /// Proxy CRL file.
    pub proxy_crlfile: Option<String>,
    /// Pinned public key (`--pinnedpubkey`).
    pub pinnedpubkey: Option<String>,
    /// Proxy pinned public key.
    pub proxy_pinnedpubkey: Option<String>,

    // -- Private keys --
    /// Private key file (`--key`).
    pub key: Option<String>,
    /// Proxy private key.
    pub proxy_key: Option<String>,
    /// Key type (PEM, DER, ENG).
    pub key_type: Option<String>,
    /// Proxy key type.
    pub proxy_key_type: Option<String>,
    /// Key passphrase (`--pass`).
    pub key_passwd: Option<String>,
    /// Proxy key passphrase.
    pub proxy_key_passwd: Option<String>,

    // -- SSH keys --
    /// SSH public key file (`--pubkey`).
    pub pubkey: Option<String>,
    /// Expected host public key MD5 (`--hostpubmd5`).
    pub hostpubmd5: Option<String>,
    /// Expected host public key SHA-256 (`--hostpubsha256`).
    pub hostpubsha256: Option<String>,

    // -- Engine / ETag / Custom request --
    /// SSL engine (`--engine`).
    pub engine: Option<String>,
    /// ETag save file (`--etag-save`).
    pub etag_save_file: Option<String>,
    /// ETag compare file (`--etag-compare`).
    pub etag_compare_file: Option<String>,
    /// Custom HTTP method (`-X`/`--request`).
    pub customrequest: Option<String>,

    // -- TLS curves / signature algorithms --
    /// SSL EC curves (`--curves`).
    pub ssl_ec_curves: Option<String>,
    /// SSL signature algorithms.
    pub ssl_signature_algorithms: Option<String>,

    // -- Kerberos / request target / write-out --
    /// Kerberos security level (`--krb`).
    pub krblevel: Option<String>,
    /// Request target (`--request-target`).
    pub request_target: Option<String>,
    /// Write-out format string (`-w`/`--write-out`).
    pub writeout: Option<String>,

    // -- FTP quote commands --
    /// Pre-transfer FTP commands (`-Q`/`--quote`).
    pub quote: Vec<String>,
    /// Post-transfer FTP commands (`--quote` after transfer).
    pub postquote: Vec<String>,
    /// Pre-quote commands (before CWD).
    pub prequote: Vec<String>,

    // -- Headers --
    /// Custom request headers (`-H`/`--header`).
    pub headers: Vec<String>,
    /// Proxy request headers (`--proxy-header`).
    pub proxyheaders: Vec<String>,

    // -- MIME --
    /// Root of the MIME tree for `-F`/`--form` data.
    pub mimeroot: Option<ToolMime>,
    /// Current MIME node during form parsing (index into tree).
    pub mimecurrent: Option<usize>,

    // -- Telnet --
    /// Telnet options (`-t`/`--telnet-option`).
    pub telnet_options: Vec<String>,

    // -- Resolve / connect-to --
    /// DNS resolve overrides (`--resolve`).
    pub resolve: Vec<String>,
    /// Connect-to overrides (`--connect-to`).
    pub connect_to: Vec<String>,

    // -- Proxy (advanced) --
    /// Pre-proxy URL (`--preproxy`).
    pub preproxy: Option<String>,
    /// Proxy authentication service name.
    pub proxy_service_name: Option<String>,
    /// Authentication service name (Digest/Kerberos/SPNEGO).
    pub service_name: Option<String>,

    // -- FTP (advanced) --
    /// FTP ACCT data (`--ftp-account`).
    pub ftp_account: Option<String>,
    /// Alternative USER command (`--ftp-alternative-to-user`).
    pub ftp_alternative_to_user: Option<String>,

    // -- OAuth --
    /// OAuth 2.0 bearer token (`--oauth2-bearer`).
    pub oauth_bearer: Option<String>,

    // -- Unix socket --
    /// Unix domain socket path (`--unix-socket`).
    pub unix_socket_path: Option<String>,

    // -- HAProxy --
    /// HAProxy client IP (`--haproxy-clientip`).
    pub haproxy_clientip: Option<String>,

    // -- AWS --
    /// AWS Signature V4 parameters (`--aws-sigv4`).
    pub aws_sigv4: Option<String>,

    // -- ECH --
    /// ECH configuration (`--ech`).
    pub ech: Option<String>,
    /// ECH ESL configuration.
    pub ech_config: Option<String>,
    /// ECH public name.
    pub ech_public: Option<String>,

    // -- SSL sessions --
    /// SSL session file path (`--ssl-sessions`).
    pub ssl_sessions_file: Option<String>,

    // -- Numeric fields --
    /// Conditional time for time-based requests.
    pub condtime: i64,
    /// Upload bandwidth limit (`--limit-rate` send).
    pub sendpersecond: i64,
    /// Download bandwidth limit (`--limit-rate` receive).
    pub recvpersecond: i64,
    /// Proxy SSL version.
    pub proxy_ssl_version: i64,
    /// IP version preference (`-4`/`-6`).
    pub ip_version: i64,
    /// File creation mode (CURLOPT_NEW_FILE_PERMS).
    pub create_file_mode: i64,
    /// Low speed limit (`-Y`/`--speed-limit`).
    pub low_speed_limit: i64,
    /// Low speed time (`-y`/`--speed-time`).
    pub low_speed_time: i64,
    /// IP Type of Service.
    pub ip_tos: i64,
    /// VLAN priority.
    pub vlan_priority: i64,
    /// Local port (`--local-port`).
    pub localport: i64,
    /// Local port range.
    pub localportrange: i64,
    /// Authentication bitmask (`--anyauth`, `--basic`, etc.).
    pub authtype: u64,
    /// Timeout in milliseconds (`-m`/`--max-time`).
    pub timeout: i64,
    /// Connection timeout in milliseconds (`--connect-timeout`).
    pub connect_timeout: i64,
    /// Maximum redirects (`--max-redirs`).
    pub maxredirs: i64,
    /// HTTP version preference (`--http1.1`, `--http2`, etc.).
    pub httpversion: i64,
    /// SOCKS5 authentication bitmask.
    pub socks5_auth: u64,
    /// Number of retries (`--retry`).
    pub retry: u32,
    /// Retry delay in milliseconds (`--retry-delay`).
    pub retry_delay: i64,
    /// Maximum retry time in milliseconds (`--retry-max-time`).
    pub retry_max_time: i64,
    /// MIME option flags.
    pub mime_options: u64,
    /// TFTP block size (`--tftp-blksize`).
    pub tftp_blksize: i64,
    /// TCP keepalive interval (`--keepalive-time`).
    pub alivetime: i64,
    /// TCP keepalive probe count.
    pub alivecnt: i64,
    /// GSSAPI delegation level (`--delegation`).
    pub gssapi_delegation: i64,
    /// Expect-100 timeout in milliseconds (`--expect100-timeout`).
    pub expect100timeout_ms: i64,
    /// Happy Eyeballs timeout in milliseconds (`--happy-eyeballs-timeout-ms`).
    pub happy_eyeballs_timeout_ms: i64,
    /// Time condition type (C: `unsigned long timecond`).
    pub timecond: u64,
    /// Follow-location mode (0 = off, 1 = on) (`-L`).
    pub followlocation: i64,

    // -- HTTP request type --
    /// Internal HTTP request type classification.
    pub httpreq: HttpReq,
    /// Proxy version (CURLPROXY_HTTP, CURLPROXY_SOCKS5, etc.).
    pub proxyver: i64,
    /// FTP SSL CCC mode.
    pub ftp_ssl_ccc_mode: i64,
    /// FTP file method (multicwd, singlecwd, nocwd).
    pub ftp_filemethod: i64,

    // -- Clobber --
    /// File overwrite policy (`-o` overwrite / `-J` rename / skip).
    pub clobber: ClobberMode,

    // -- Upload flags --
    /// Upload flags bitmask.
    pub upload_flags: u8,

    // -- Port --
    /// Port to use for the transfer.
    pub porttouse: u16,

    // -- SSL version --
    /// Minimum SSL/TLS version (0–4, 0 = default).
    pub ssl_version: u8,
    /// Maximum SSL/TLS version (0–4, 0 = default).
    pub ssl_version_max: u8,

    // -- Fail mode --
    /// Fail behaviour selector (FAIL_NONE / FAIL_WITH_BODY / FAIL_WO_BODY).
    pub fail: u8,

    // -- Per-operation overrides (also accessible on GlobalConfig) --
    /// Enable verbose output for this operation (`-v`/`--verbose`).
    pub verbose: bool,
    /// Suppress non-error output for this operation (`-s`/`--silent`).
    pub silent: bool,
    /// Enable parallel transfers for this operation block (`-Z`/`--parallel`).
    pub parallel: bool,
    /// Maximum parallel transfers for this block (`--parallel-max`).
    pub parallel_max: u32,

    // -- Boolean flags --
    // These map 1:1 to the C `BIT(name)` fields in `struct OperationConfig`.
    // Grouped in the same order as the C header for easy cross-reference.

    /// Use remote name for all URLs (`--remote-name-all`).
    pub remote_name_all: bool,
    /// Set file modification time to remote time (`-R`/`--remote-time`).
    pub remote_time: bool,
    /// Start a new cookie session (`-b` with no file).
    pub cookiesession: bool,
    /// Request compressed transfer (`--compressed`).
    pub encoding: bool,
    /// Request transfer encoding (`--tr-encoding`).
    pub tr_encoding: bool,
    /// Resume transfer (`-C`).
    pub use_resume: bool,
    /// Resume from current file end.
    pub resume_from_current: bool,
    /// Disable EPSV (`--disable-epsv`).
    pub disable_epsv: bool,
    /// Disable EPRT (`--disable-eprt`).
    pub disable_eprt: bool,
    /// Send PRET before PASV (`--ftp-pret`).
    pub ftp_pret: bool,
    /// Whether `--proto` was explicitly given.
    pub proto_present: bool,
    /// Whether `--proto-redir` was explicitly given.
    pub proto_redir_present: bool,
    /// Allow RCPT failures (`--mail-rcpt-allowfails`).
    pub mail_rcpt_allowfails: bool,
    /// Enable SASL initial response (`--sasl-ir`).
    pub sasl_ir: bool,
    /// Use proxy tunnel (`-p`/`--proxytunnel`).
    pub proxytunnel: bool,
    /// Append to remote file (`-a`/`--append`).
    pub ftp_append: bool,
    /// Use ASCII transfer (`-B`/`--use-ascii`).
    pub use_ascii: bool,
    /// Automatically set Referer on redirect (`--autoreferer`).
    pub autoreferer: bool,
    /// Include response headers in output (`-i`/`--include`).
    pub show_headers: bool,
    /// Do not download the body (`-I`/`--head`).
    pub no_body: bool,
    /// Only list directory (`-l`/`--list-only`).
    pub dirlistonly: bool,
    /// Send auth on redirect even if hostname changes.
    pub unrestricted_auth: bool,
    /// Use `.netrc` optionally (`--netrc-optional`).
    pub netrc_opt: bool,
    /// Use `.netrc` (`-n`/`--netrc`).
    pub netrc: bool,
    /// Convert LF to CRLF on upload (`--crlf`).
    pub crlf: bool,
    /// Allow HTTP/0.9 responses (`--http0.9`).
    pub http09_allowed: bool,
    /// Disable output buffering (`-N`/`--no-buffer`).
    pub nobuffer: bool,
    /// Read callback returned EAGAIN; internal flag.
    pub readbusy: bool,
    /// Disable URL globbing (`-g`/`--globoff`).
    pub globoff: bool,
    /// Force GET method (`-G`/`--get`).
    pub use_httpget: bool,
    /// Allow insecure TLS connections (`-k`/`--insecure`).
    pub insecure_ok: bool,
    /// Allow insecure DoH connections.
    pub doh_insecure_ok: bool,
    /// Allow insecure proxy TLS.
    pub proxy_insecure_ok: bool,
    /// Terminal can handle binary output.
    pub terminal_binary_ok: bool,
    /// Request OCSP stapling (`--cert-status`).
    pub verifystatus: bool,
    /// Request DoH OCSP stapling.
    pub doh_verifystatus: bool,
    /// Create output directories (`--create-dirs`).
    pub create_dirs: bool,
    /// Create remote FTP directories (`--ftp-create-dirs`).
    pub ftp_create_dirs: bool,
    /// Skip PASV IP address (`--ftp-skip-pasv-ip`).
    pub ftp_skip_ip: bool,
    /// Proxy Negotiate auth.
    pub proxynegotiate: bool,
    /// Proxy NTLM auth.
    pub proxyntlm: bool,
    /// Proxy Digest auth.
    pub proxydigest: bool,
    /// Proxy Basic auth.
    pub proxybasic: bool,
    /// Proxy anyauth.
    pub proxyanyauth: bool,
    /// Added JSON content type (`--json`).
    pub jsoned: bool,
    /// FTP with TLS (`--ssl`).
    pub ftp_ssl: bool,
    /// FTP requires TLS (`--ssl-reqd`).
    pub ftp_ssl_reqd: bool,
    /// FTP SSL for control connection only.
    pub ftp_ssl_control: bool,
    /// FTP SSL CCC (`--ftp-ssl-ccc`).
    pub ftp_ssl_ccc: bool,
    /// SOCKS5 GSSAPI NEC mode.
    pub socks5_gssapi_nec: bool,
    /// Enable TCP_NODELAY (`--tcp-nodelay`).
    pub tcp_nodelay: bool,
    /// Enable TCP Fast Open (`--tcp-fastopen`).
    pub tcp_fastopen: bool,
    /// Retry on all errors (`--retry-all-errors`).
    pub retry_all_errors: bool,
    /// Retry on connection refused.
    pub retry_connrefused: bool,
    /// Disable TFTP options.
    pub tftp_no_options: bool,
    /// Ignore Content-Length (`--ignore-content-length`).
    pub ignorecl: bool,
    /// Disable TLS session ID reuse.
    pub disable_sessionid: bool,
    /// Raw transfer (`--raw`).
    pub raw: bool,
    /// Follow POST after 301 redirect.
    pub post301: bool,
    /// Follow POST after 302 redirect.
    pub post302: bool,
    /// Follow POST after 303 redirect.
    pub post303: bool,
    /// Disable keepalive (`--no-keepalive`).
    pub nokeepalive: bool,
    /// Use Content-Disposition filename (`-J`).
    pub content_disposition: bool,
    /// Store metadata as extended attributes (`--xattr`).
    pub xattr: bool,
    /// Allow SSL BEAST vulnerability (`--ssl-allow-beast`).
    pub ssl_allow_beast: bool,
    /// Allow TLS 1.3 early data.
    pub ssl_allow_earlydata: bool,
    /// Proxy SSL allow BEAST.
    pub proxy_ssl_allow_beast: bool,
    /// Disable SSL certificate revocation checks.
    pub ssl_no_revoke: bool,
    /// Ignore revocation check failures.
    pub ssl_revoke_best_effort: bool,
    /// Use native OS CA store.
    pub native_ca_store: bool,
    /// Use native OS CA store for proxy.
    pub proxy_native_ca_store: bool,
    /// Auto-locate client certificate.
    pub ssl_auto_client_cert: bool,
    /// Proxy auto-locate client certificate.
    pub proxy_ssl_auto_client_cert: bool,
    /// Disable ALPN negotiation (`--no-alpn`).
    pub noalpn: bool,
    /// Use abstract Unix domain socket.
    pub abstract_unix_socket: bool,
    /// Use URL path as-is (`--path-as-is`).
    pub path_as_is: bool,
    /// Suppress CONNECT response headers.
    pub suppress_connect_headers: bool,
    /// This is a tool-internal synthetic error.
    pub synthetic_error: bool,
    /// Enable SSH compression (`--compressed-ssh`).
    pub ssh_compression: bool,
    /// Send HAProxy PROXY protocol v1 header.
    pub haproxy_protocol: bool,
    /// Disallow usernames in URLs.
    pub disallow_username_in_url: bool,
    /// Enable MPTCP (`--mptcp`).
    pub mptcp: bool,
    /// Remove partially written output files on error.
    pub rm_partial: bool,
    /// Skip download if file already exists.
    pub skip_existing: bool,
}

impl OperationConfig {
    /// Creates a new `OperationConfig` with all defaults matching curl 8.x.
    ///
    /// This is the Rust equivalent of the C `config_alloc()` function.
    /// Key non-zero defaults:
    /// - `tcp_nodelay`: `true`
    /// - `ftp_skip_ip`: `true`
    /// - `maxredirs`: [`DEFAULT_MAXREDIRS`] (50)
    /// - `happy_eyeballs_timeout_ms`: [`CURL_HET_DEFAULT`] (200)
    /// - `clobber`: [`CLOBBER_DEFAULT`] (`ClobberMode::Always`)
    /// - `upload_flags`: [`CURLULFLAG_SEEN`]
    pub fn new() -> Self {
        Self {
            // POST data buffer (replaces C dynbuf init with MAX_FILE2MEMORY)
            postdata: Vec::new(),

            // String fields — all default to None
            useragent: None,
            cookies: Vec::new(),
            cookiejar: None,
            cookiefiles: Vec::new(),
            altsvc: None,
            hsts: None,
            proto_str: None,
            proto_redir_str: None,
            proto_default: None,
            resume_from: 0,
            postfields: None,
            referer: None,
            query: None,
            max_filesize: 0,
            outfile: None,
            output_dir: None,
            headerfile: None,
            ftpport: None,
            iface: None,
            range: None,
            dns_servers: None,
            dns_interface: None,
            dns_ipv4_addr: None,
            dns_ipv6_addr: None,
            userpwd: None,
            login_options: None,
            tls_username: None,
            tls_password: None,
            tls_authtype: None,
            proxy_tls_username: None,
            proxy_tls_password: None,
            proxy_tls_authtype: None,
            proxyuserpwd: None,
            proxy: None,
            noproxy: None,
            knownhosts: None,
            mail_from: None,
            mail_rcpt: Vec::new(),
            mail_auth: None,
            sasl_authzid: None,
            netrc_file: None,
            url_list: Vec::new(),
            ipfs_gateway: None,
            doh_url: None,
            cipher_list: None,
            proxy_cipher_list: None,
            cipher13_list: None,
            proxy_cipher13_list: None,
            cert: None,
            proxy_cert: None,
            cert_type: None,
            proxy_cert_type: None,
            cacert: None,
            proxy_cacert: None,
            capath: None,
            proxy_capath: None,
            crlfile: None,
            proxy_crlfile: None,
            pinnedpubkey: None,
            proxy_pinnedpubkey: None,
            key: None,
            proxy_key: None,
            key_type: None,
            proxy_key_type: None,
            key_passwd: None,
            proxy_key_passwd: None,
            pubkey: None,
            hostpubmd5: None,
            hostpubsha256: None,
            engine: None,
            etag_save_file: None,
            etag_compare_file: None,
            customrequest: None,
            ssl_ec_curves: None,
            ssl_signature_algorithms: None,
            krblevel: None,
            request_target: None,
            writeout: None,
            quote: Vec::new(),
            postquote: Vec::new(),
            prequote: Vec::new(),
            headers: Vec::new(),
            proxyheaders: Vec::new(),
            mimeroot: None,
            mimecurrent: None,
            telnet_options: Vec::new(),
            resolve: Vec::new(),
            connect_to: Vec::new(),
            preproxy: None,
            proxy_service_name: None,
            service_name: None,
            ftp_account: None,
            ftp_alternative_to_user: None,
            oauth_bearer: None,
            unix_socket_path: None,
            haproxy_clientip: None,
            aws_sigv4: None,
            ech: None,
            ech_config: None,
            ech_public: None,
            ssl_sessions_file: None,

            // Numeric fields — all default to 0 unless noted
            condtime: 0,
            sendpersecond: 0,
            recvpersecond: 0,
            proxy_ssl_version: 0,
            ip_version: 0,
            create_file_mode: 0,
            low_speed_limit: 0,
            low_speed_time: 0,
            ip_tos: 0,
            vlan_priority: 0,
            localport: 0,
            localportrange: 0,
            authtype: 0,
            timeout: 0,
            connect_timeout: 0,
            httpversion: 0,
            socks5_auth: 0,
            retry: 0,
            retry_delay: 0,
            retry_max_time: 0,
            mime_options: 0,
            tftp_blksize: 0,
            alivetime: 0,
            alivecnt: 0,
            gssapi_delegation: 0,
            expect100timeout_ms: 0,
            timecond: 0,
            followlocation: 0,
            httpreq: HttpReq::Unspec,
            proxyver: 0,
            ftp_ssl_ccc_mode: 0,
            ftp_filemethod: 0,
            upload_flags: CURLULFLAG_SEEN,
            porttouse: 0,
            ssl_version: 0,
            ssl_version_max: 0,
            fail: FAIL_NONE,

            // Non-zero defaults matching C config_alloc()
            maxredirs: DEFAULT_MAXREDIRS,
            happy_eyeballs_timeout_ms: CURL_HET_DEFAULT,
            clobber: CLOBBER_DEFAULT,
            tcp_nodelay: true,
            ftp_skip_ip: true,

            // Per-operation overrides (default to false/0)
            verbose: false,
            silent: false,
            parallel: false,
            parallel_max: 0,

            // All other booleans default to false
            remote_name_all: false,
            remote_time: false,
            cookiesession: false,
            encoding: false,
            tr_encoding: false,
            use_resume: false,
            resume_from_current: false,
            disable_epsv: false,
            disable_eprt: false,
            ftp_pret: false,
            proto_present: false,
            proto_redir_present: false,
            mail_rcpt_allowfails: false,
            sasl_ir: false,
            proxytunnel: false,
            ftp_append: false,
            use_ascii: false,
            autoreferer: false,
            show_headers: false,
            no_body: false,
            dirlistonly: false,
            unrestricted_auth: false,
            netrc_opt: false,
            netrc: false,
            crlf: false,
            http09_allowed: false,
            nobuffer: false,
            readbusy: false,
            globoff: false,
            use_httpget: false,
            insecure_ok: false,
            doh_insecure_ok: false,
            proxy_insecure_ok: false,
            terminal_binary_ok: false,
            verifystatus: false,
            doh_verifystatus: false,
            create_dirs: false,
            ftp_create_dirs: false,
            proxynegotiate: false,
            proxyntlm: false,
            proxydigest: false,
            proxybasic: false,
            proxyanyauth: false,
            jsoned: false,
            ftp_ssl: false,
            ftp_ssl_reqd: false,
            ftp_ssl_control: false,
            ftp_ssl_ccc: false,
            socks5_gssapi_nec: false,
            tcp_fastopen: false,
            retry_all_errors: false,
            retry_connrefused: false,
            tftp_no_options: false,
            ignorecl: false,
            disable_sessionid: false,
            raw: false,
            post301: false,
            post302: false,
            post303: false,
            nokeepalive: false,
            content_disposition: false,
            xattr: false,
            ssl_allow_beast: false,
            ssl_allow_earlydata: false,
            proxy_ssl_allow_beast: false,
            ssl_no_revoke: false,
            ssl_revoke_best_effort: false,
            native_ca_store: false,
            proxy_native_ca_store: false,
            ssl_auto_client_cert: false,
            proxy_ssl_auto_client_cert: false,
            noalpn: false,
            abstract_unix_socket: false,
            path_as_is: false,
            suppress_connect_headers: false,
            synthetic_error: false,
            ssh_compression: false,
            haproxy_protocol: false,
            disallow_username_in_url: false,
            mptcp: false,
            rm_partial: false,
            skip_existing: false,
        }
    }
}

impl Default for OperationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Resets all owned fields in an `OperationConfig` to their defaults.
///
/// This is the Rust equivalent of the C `free_config_fields()` function.
/// In Rust, `Drop` handles deallocation automatically, but this function
/// is useful for explicitly resetting a config node for reuse (e.g.,
/// during retry or after `--next`).
pub fn free_config_fields(config: &mut OperationConfig) {
    // Reset all Option<String> fields to None
    config.useragent = None;
    config.cookies.clear();
    config.cookiejar = None;
    config.cookiefiles.clear();
    config.altsvc = None;
    config.hsts = None;
    config.proto_str = None;
    config.proto_redir_str = None;
    config.proto_default = None;
    config.postfields = None;
    config.referer = None;
    config.query = None;
    config.outfile = None;
    config.output_dir = None;
    config.headerfile = None;
    config.ftpport = None;
    config.iface = None;
    config.range = None;
    config.dns_servers = None;
    config.dns_interface = None;
    config.dns_ipv4_addr = None;
    config.dns_ipv6_addr = None;
    config.userpwd = None;
    config.login_options = None;
    config.tls_username = None;
    config.tls_password = None;
    config.tls_authtype = None;
    config.proxy_tls_username = None;
    config.proxy_tls_password = None;
    config.proxy_tls_authtype = None;
    config.proxyuserpwd = None;
    config.proxy = None;
    config.noproxy = None;
    config.knownhosts = None;
    config.mail_from = None;
    config.mail_rcpt.clear();
    config.mail_auth = None;
    config.sasl_authzid = None;
    config.netrc_file = None;
    config.url_list.clear();
    config.ipfs_gateway = None;
    config.doh_url = None;
    config.cipher_list = None;
    config.proxy_cipher_list = None;
    config.cipher13_list = None;
    config.proxy_cipher13_list = None;
    config.cert = None;
    config.proxy_cert = None;
    config.cert_type = None;
    config.proxy_cert_type = None;
    config.cacert = None;
    config.proxy_cacert = None;
    config.capath = None;
    config.proxy_capath = None;
    config.crlfile = None;
    config.proxy_crlfile = None;
    config.pinnedpubkey = None;
    config.proxy_pinnedpubkey = None;
    config.key = None;
    config.proxy_key = None;
    config.key_type = None;
    config.proxy_key_type = None;
    config.key_passwd = None;
    config.proxy_key_passwd = None;
    config.pubkey = None;
    config.hostpubmd5 = None;
    config.hostpubsha256 = None;
    config.engine = None;
    config.etag_save_file = None;
    config.etag_compare_file = None;
    config.customrequest = None;
    config.ssl_ec_curves = None;
    config.ssl_signature_algorithms = None;
    config.krblevel = None;
    config.request_target = None;
    config.writeout = None;
    config.quote.clear();
    config.postquote.clear();
    config.prequote.clear();
    config.headers.clear();
    config.proxyheaders.clear();
    config.mimeroot = None;
    config.mimecurrent = None;
    config.telnet_options.clear();
    config.resolve.clear();
    config.connect_to.clear();
    config.preproxy = None;
    config.proxy_service_name = None;
    config.service_name = None;
    config.ftp_account = None;
    config.ftp_alternative_to_user = None;
    config.oauth_bearer = None;
    config.unix_socket_path = None;
    config.haproxy_clientip = None;
    config.aws_sigv4 = None;
    config.ech = None;
    config.ech_config = None;
    config.ech_public = None;
    config.ssl_sessions_file = None;

    // Clear the POST data buffer
    config.postdata.clear();
}

// ---------------------------------------------------------------------------
// GlobalConfig
// ---------------------------------------------------------------------------

/// Process-wide configuration for the curl-rs CLI session.
///
/// This is the Rust equivalent of the C `struct GlobalConfig` defined in
/// `tool_cfgable.h`. There is exactly one `GlobalConfig` per process
/// invocation. It owns the chain of [`OperationConfig`] nodes (one per
/// `--next` separator) and holds global settings such as trace mode,
/// parallel execution, and library info.
pub struct GlobalConfig {
    /// Transfer iteration state shared across operations.
    pub state: TransferState,

    /// Trace output file path (`--trace` / `--trace-ascii`).
    pub trace_dump: Option<String>,

    /// Trace output stream (file or stderr).
    pub trace_stream: Option<Box<dyn Write + Send>>,

    /// Output file for `--libcurl` code generation.
    pub libcurl: Option<String>,

    /// Cached SSL session data for session persistence across transfers.
    pub ssl_sessions: Option<Vec<u8>>,

    /// User-defined variables (`--variable`).
    pub variables: Vec<ToolVar>,

    /// Chain of per-URL-block operation configs. Index 0 is always the
    /// first (and default) config. Additional entries are created by `--next`.
    pub configs: Vec<OperationConfig>,

    /// Index of the current config being populated during argument parsing.
    pub current: usize,

    /// Rate limit: minimum milliseconds between transfer starts (`--rate`).
    pub ms_per_transfer: i64,

    /// Trace output mode.
    pub tracetype: TraceType,

    /// Progress display mode (0 = bar, 1 = stats).
    pub progressmode: i32,

    /// Maximum number of parallel connections per host.
    pub parallel_host: u16,

    /// Maximum number of parallel transfers (`--parallel-max`).
    pub parallel_max: u32,

    /// Verbosity level.
    pub verbosity: u8,

    /// Enable parallel transfers (`-Z`/`--parallel`).
    pub parallel: bool,

    /// Enable parallel connection reuse.
    pub parallel_connect: bool,

    /// Exit on first transfer error (`--fail-early`).
    pub fail_early: bool,

    /// Enable styled terminal output detection.
    pub styled_output: bool,

    /// Whether the trace file was opened by us (needs closing).
    pub trace_fopened: bool,

    /// Include timestamps in trace output (`--trace-time`).
    pub tracetime: bool,

    /// Include transfer/connection IDs in trace output (`--trace-ids`).
    pub traceids: bool,

    /// Show errors even when `--silent` is active (`-S`/`--show-error`).
    pub showerror: bool,

    /// Suppress all non-error output (`-s`/`--silent`).
    pub silent: bool,

    /// Suppress the progress meter (`--no-progress-meter`).
    pub noprogress: bool,

    /// Whether stdout is connected to a terminal (auto-detected).
    pub isatty: bool,

    /// Whether `--trace-config` has been used.
    pub trace_set: bool,

    /// Cached library capability info (populated once during init).
    pub libcurl_info: LibCurlInfo,

    /// Terminal output buffer state (primarily for Windows console).
    pub term: TerminalState,

    /// Cached libcurl version string (e.g., `"curl-rs/8.19.0-DEV"`).
    pub libcurl_version: Option<String>,
}

impl std::fmt::Debug for GlobalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalConfig")
            .field("state", &self.state)
            .field("trace_dump", &self.trace_dump)
            .field(
                "trace_stream",
                &if self.trace_stream.is_some() {
                    "Some(<dyn Write>)"
                } else {
                    "None"
                },
            )
            .field("libcurl", &self.libcurl)
            .field("ssl_sessions", &self.ssl_sessions)
            .field("variables", &self.variables)
            .field("configs", &self.configs)
            .field("current", &self.current)
            .field("ms_per_transfer", &self.ms_per_transfer)
            .field("tracetype", &self.tracetype)
            .field("progressmode", &self.progressmode)
            .field("parallel_host", &self.parallel_host)
            .field("parallel_max", &self.parallel_max)
            .field("verbosity", &self.verbosity)
            .field("parallel", &self.parallel)
            .field("parallel_connect", &self.parallel_connect)
            .field("fail_early", &self.fail_early)
            .field("styled_output", &self.styled_output)
            .field("trace_fopened", &self.trace_fopened)
            .field("tracetime", &self.tracetime)
            .field("traceids", &self.traceids)
            .field("showerror", &self.showerror)
            .field("silent", &self.silent)
            .field("noprogress", &self.noprogress)
            .field("isatty", &self.isatty)
            .field("trace_set", &self.trace_set)
            .field("libcurl_info", &self.libcurl_info)
            .field("term", &self.term)
            .field("libcurl_version", &self.libcurl_version)
            .finish()
    }
}

impl GlobalConfig {
    /// Creates a new `GlobalConfig` with a single default `OperationConfig`.
    ///
    /// This does NOT perform library initialization — call
    /// [`globalconf_init`] for the full lifecycle.
    fn new_with_defaults() -> Self {
        Self {
            state: TransferState::new(),
            trace_dump: None,
            trace_stream: None,
            libcurl: None,
            ssl_sessions: None,
            variables: Vec::new(),
            configs: vec![OperationConfig::new()],
            current: 0,
            ms_per_transfer: 0,
            tracetype: TraceType::None,
            progressmode: 0,
            parallel_host: 0,
            parallel_max: PARALLEL_DEFAULT,
            verbosity: 0,
            parallel: false,
            parallel_connect: false,
            fail_early: false,
            styled_output: true,
            trace_fopened: false,
            tracetime: false,
            traceids: false,
            showerror: false,
            silent: false,
            noprogress: false,
            isatty: false,
            trace_set: false,
            libcurl_info: LibCurlInfo::default(),
            term: TerminalState::new(),
            libcurl_version: None,
        }
    }

    /// Returns a reference to the first (default) operation config.
    pub fn first(&self) -> &OperationConfig {
        &self.configs[0]
    }

    /// Returns a mutable reference to the first (default) operation config.
    pub fn first_mut(&mut self) -> &mut OperationConfig {
        &mut self.configs[0]
    }

    /// Returns a reference to the last operation config in the chain.
    pub fn last(&self) -> &OperationConfig {
        self.configs.last().expect("configs is never empty")
    }

    /// Returns a mutable reference to the last operation config.
    pub fn last_mut(&mut self) -> &mut OperationConfig {
        self.configs.last_mut().expect("configs is never empty")
    }

    /// Returns a reference to the currently active operation config.
    pub fn current_config(&self) -> &OperationConfig {
        &self.configs[self.current]
    }

    /// Returns a mutable reference to the currently active operation config.
    pub fn current_config_mut(&mut self) -> &mut OperationConfig {
        &mut self.configs[self.current]
    }

    /// Appends a new `OperationConfig` to the chain (for `--next`).
    ///
    /// Returns a mutable reference to the newly created config.
    pub fn add_config(&mut self) -> &mut OperationConfig {
        self.configs.push(OperationConfig::new());
        let idx = self.configs.len() - 1;
        self.current = idx;
        &mut self.configs[idx]
    }

    /// Opens a trace output file and sets it as the trace stream.
    ///
    /// The file is wrapped in a [`BufWriter`] for efficient I/O. Sets
    /// `trace_fopened` to `true` so the stream is closed on cleanup.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be created.
    pub fn set_trace_file(&mut self, path: &str) -> io::Result<()> {
        let file = std::fs::File::create(path)?;
        self.trace_stream = Some(Box::new(BufWriter::new(file)));
        self.trace_dump = Some(path.to_string());
        self.trace_fopened = true;
        Ok(())
    }

    /// Sets the trace stream to an arbitrary writer (e.g., stderr).
    ///
    /// Unlike [`set_trace_file`](Self::set_trace_file), this does NOT set
    /// `trace_fopened` — the caller retains ownership of the stream's
    /// lifecycle.
    pub fn set_trace_stream(&mut self, writer: Box<dyn Write + Send>) {
        self.trace_stream = Some(writer);
        self.trace_fopened = false;
    }

    /// Returns the total number of operation configs in the chain.
    pub fn config_count(&self) -> usize {
        self.configs.len()
    }
}

// ---------------------------------------------------------------------------
// Lifecycle functions
// ---------------------------------------------------------------------------

/// Initializes the global configuration for the curl-rs CLI session.
///
/// This is the Rust equivalent of the C `globalconf_init()` function.
/// It performs the following steps:
///
/// 1. Creates a `GlobalConfig` with default settings:
///    - `showerror`: `false`
///    - `styled_output`: `true`
///    - `parallel_max`: [`PARALLEL_DEFAULT`] (50)
/// 2. Allocates the initial `OperationConfig` (always present).
/// 3. Queries library capability info via [`get_libcurl_info`].
///
/// # Errors
///
/// Returns `CurlError::FailedInit` if library initialization fails.
pub fn globalconf_init() -> CurlResult<GlobalConfig> {
    // Initialize the underlying library (TLS provider, tracing subscriber).
    // This mirrors the C call to curl_global_init(CURL_GLOBAL_DEFAULT).
    // CURL_GLOBAL_DEFAULT is 3 (CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32).
    global_init(3).map_err(|_| CurlError::FailedInit)?;

    let mut global = GlobalConfig::new_with_defaults();

    // Query library capabilities (replaces C get_libcurl_info())
    let info = get_libcurl_info();
    global.libcurl_version = Some(info.version.clone());
    global.libcurl_info = info;

    Ok(global)
}

/// Tears down the global configuration, releasing all resources.
///
/// This is the Rust equivalent of the C `globalconf_free()` function.
/// In Rust, most cleanup happens automatically via `Drop`, but this
/// function explicitly:
/// - Closes the trace stream if it was opened.
/// - Clears all operation configs in the chain.
/// - Clears all variables.
///
/// After calling this, the `GlobalConfig` should not be used.
pub fn globalconf_free(global: &mut GlobalConfig) {
    // Perform global library cleanup (mirrors C curl_global_cleanup())
    global_cleanup();

    // Close trace stream if we opened it
    if global.trace_fopened {
        global.trace_stream = None;
        global.trace_fopened = false;
    }

    // Clear trace dump path
    global.trace_dump = None;

    // Clear SSL sessions data
    global.ssl_sessions = None;

    // Clear libcurl output path
    global.libcurl = None;

    // Clear version string
    global.libcurl_version = None;

    // Clear all variables
    global.variables.clear();

    // Free all operation config fields explicitly, then clear the vector
    for config in &mut global.configs {
        free_config_fields(config);
    }
    global.configs.clear();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_config_defaults() {
        let config = OperationConfig::new();

        // Verify non-zero defaults matching C config_alloc()
        assert!(config.tcp_nodelay, "tcp_nodelay should be true by default");
        assert!(config.ftp_skip_ip, "ftp_skip_ip should be true by default");
        assert_eq!(config.maxredirs, DEFAULT_MAXREDIRS);
        assert_eq!(config.happy_eyeballs_timeout_ms, CURL_HET_DEFAULT);
        assert_eq!(config.clobber, ClobberMode::Always);
        assert_eq!(config.upload_flags, CURLULFLAG_SEEN);
        assert_eq!(config.fail, FAIL_NONE);

        // Verify zero/false defaults
        assert!(!config.insecure_ok);
        assert!(!config.verbose);
        assert!(!config.silent);
        assert!(!config.encoding);
        assert!(!config.use_httpget);
        assert!(!config.parallel);
        assert_eq!(config.parallel_max, 0);
        assert_eq!(config.httpreq, HttpReq::Unspec);
        assert_eq!(config.timeout, 0);
        assert_eq!(config.connect_timeout, 0);
        assert_eq!(config.retry, 0);
        assert_eq!(config.retry_delay, 0);
        assert!(config.userpwd.is_none());
        assert!(config.proxy.is_none());
        assert!(config.outfile.is_none());
        assert!(config.headers.is_empty());
    }

    #[test]
    fn test_global_config_defaults() {
        let global = GlobalConfig::new_with_defaults();

        assert!(!global.showerror);
        assert!(global.styled_output);
        assert_eq!(global.parallel_max, PARALLEL_DEFAULT);
        assert!(!global.parallel);
        assert!(!global.fail_early);
        assert!(!global.silent);
        assert!(!global.noprogress);
        assert_eq!(global.tracetype, TraceType::None);
        assert_eq!(global.configs.len(), 1);
        assert_eq!(global.current, 0);
    }

    #[test]
    fn test_global_config_add_config() {
        let mut global = GlobalConfig::new_with_defaults();
        assert_eq!(global.configs.len(), 1);

        let _new = global.add_config();
        assert_eq!(global.configs.len(), 2);
        assert_eq!(global.current, 1);

        let _another = global.add_config();
        assert_eq!(global.configs.len(), 3);
        assert_eq!(global.current, 2);
    }

    #[test]
    fn test_free_config_fields() {
        let mut config = OperationConfig::new();

        // Set some fields
        config.userpwd = Some("user:pass".to_string());
        config.proxy = Some("http://proxy:8080".to_string());
        config.headers.push("X-Custom: value".to_string());
        config.cookies.push("name=value".to_string());
        config.url_list.push(GetOut::new());
        config.postdata = vec![1, 2, 3];

        // Reset
        free_config_fields(&mut config);

        // Verify all fields are cleared
        assert!(config.userpwd.is_none());
        assert!(config.proxy.is_none());
        assert!(config.headers.is_empty());
        assert!(config.cookies.is_empty());
        assert!(config.url_list.is_empty());
        assert!(config.postdata.is_empty());
    }

    #[test]
    fn test_globalconf_free() {
        let mut global = GlobalConfig::new_with_defaults();
        global.trace_dump = Some("/tmp/trace".to_string());
        global.ssl_sessions = Some(b"session_data_bytes".to_vec());
        global.variables.push(ToolVar {
            name: "test".to_string(),
            content: b"value".to_vec(),
        });

        globalconf_free(&mut global);

        assert!(global.trace_dump.is_none());
        assert!(global.ssl_sessions.is_none());
        assert!(global.variables.is_empty());
        assert!(global.configs.is_empty());
    }

    #[test]
    fn test_clobber_mode_variants() {
        assert_eq!(CLOBBER_DEFAULT, ClobberMode::Always);
        assert_ne!(ClobberMode::Never, ClobberMode::Always);
        assert_ne!(ClobberMode::Rename, ClobberMode::Never);
    }

    #[test]
    fn test_trace_type_variants() {
        assert_ne!(TraceType::None, TraceType::Verbose);
        assert_ne!(TraceType::Ascii, TraceType::Plain);
        assert_ne!(TraceType::Verbose, TraceType::Plain);
    }

    #[test]
    fn test_http_req_values() {
        assert_eq!(HttpReq::Unspec as i32, 0);
        assert_eq!(HttpReq::Get as i32, 1);
        assert_eq!(HttpReq::Head as i32, 2);
        assert_eq!(HttpReq::MimePost as i32, 3);
        assert_eq!(HttpReq::SimplePost as i32, 4);
        assert_eq!(HttpReq::Put as i32, 5);
    }

    #[test]
    fn test_getout_default() {
        let getout = GetOut::new();
        assert!(getout.url.is_none());
        assert!(getout.outfile.is_none());
        assert!(getout.infile.is_none());
        assert_eq!(getout.num, 0);
        assert!(!getout.url_set);
        assert!(!getout.use_remote);
        assert!(!getout.no_glob);
    }

    #[test]
    fn test_tool_mime_new() {
        let mime = ToolMime::new(ToolMimeKind::Data);
        assert_eq!(mime.kind, ToolMimeKind::Data);
        assert!(mime.name.is_none());
        assert!(mime.data.is_none());
        assert!(mime.subparts.is_empty());
        assert!(mime.headers.is_empty());
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_MAXREDIRS, 50);
        assert_eq!(PARALLEL_DEFAULT, 50u32);
        assert_eq!(MAX_FILE2MEMORY, 40 * 1024 * 1024);
        assert_eq!(CURL_HET_DEFAULT, 200);
        assert_eq!(FAIL_NONE, 0);
        assert_eq!(FAIL_WITH_BODY, 1);
        assert_eq!(FAIL_WO_BODY, 2);
    }

    #[test]
    fn test_globalconf_init_lifecycle() {
        let result = globalconf_init();
        assert!(result.is_ok(), "globalconf_init should succeed");

        let mut global = result.unwrap();

        // Verify libcurl_info is populated
        assert!(!global.libcurl_info.version.is_empty());
        assert!(global.libcurl_info.feature_ssl);

        // Verify libcurl_version is populated
        assert!(global.libcurl_version.is_some());

        // Verify ssl_sessions type is Vec<u8>
        assert!(global.ssl_sessions.is_none());
        global.ssl_sessions = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(global.ssl_sessions.as_ref().unwrap().len(), 4);

        // Verify term field exists
        let _t = &global.term;

        // Verify first/last/current work
        assert_eq!(global.first().maxredirs, DEFAULT_MAXREDIRS);
        assert_eq!(global.last().maxredirs, DEFAULT_MAXREDIRS);
        assert_eq!(global.current_config().maxredirs, DEFAULT_MAXREDIRS);

        globalconf_free(&mut global);
        assert!(global.configs.is_empty());
        assert!(global.libcurl_version.is_none());
    }

    #[test]
    fn test_http_method_custom_variant() {
        let m = HttpMethod::Custom("PURGE".to_string());
        if let HttpMethod::Custom(s) = &m {
            assert_eq!(s, "PURGE");
        } else {
            panic!("Expected Custom variant");
        }
    }

    #[test]
    fn test_tool_mime_kind_all_variants() {
        let kinds = [
            ToolMimeKind::Parts,
            ToolMimeKind::Data,
            ToolMimeKind::FileData,
            ToolMimeKind::File,
            ToolMimeKind::Stdin,
        ];
        // All must be distinct
        for (i, a) in kinds.iter().enumerate() {
            for (j, b) in kinds.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn test_new_getout_inherits_remote_name_all() {
        let mut config = OperationConfig::new();
        config.remote_name_all = true;

        let getout = config.new_getout();
        assert!(getout.use_remote, "should inherit remote_name_all");
        assert_eq!(getout.num, 0);

        let getout2 = config.new_getout();
        assert_eq!(getout2.num, 1);
        assert_eq!(config.url_count(), 2);
    }

    #[test]
    fn test_free_config_fields_clears_all_vecs() {
        let mut config = OperationConfig::new();
        config.cookies.push("a=b".into());
        config.cookiefiles.push("f".into());
        config.mail_rcpt.push("r@x.com".into());
        config.quote.push("CWD /".into());
        config.postquote.push("QUIT".into());
        config.prequote.push("PWD".into());
        config.headers.push("H: V".into());
        config.proxyheaders.push("PH: PV".into());
        config.telnet_options.push("O".into());
        config.resolve.push("host:80:127.0.0.1".into());
        config.connect_to.push("::localhost:".into());

        free_config_fields(&mut config);

        assert!(config.cookies.is_empty());
        assert!(config.cookiefiles.is_empty());
        assert!(config.mail_rcpt.is_empty());
        assert!(config.quote.is_empty());
        assert!(config.postquote.is_empty());
        assert!(config.prequote.is_empty());
        assert!(config.headers.is_empty());
        assert!(config.proxyheaders.is_empty());
        assert!(config.telnet_options.is_empty());
        assert!(config.resolve.is_empty());
        assert!(config.connect_to.is_empty());
    }

    #[test]
    fn test_operation_config_default_trait() {
        let config: OperationConfig = Default::default();
        assert_eq!(config.maxredirs, DEFAULT_MAXREDIRS);
        assert!(config.tcp_nodelay);
    }

    #[test]
    fn test_getout_default_trait() {
        let getout: GetOut = Default::default();
        assert!(getout.url.is_none());
        assert_eq!(getout.num, 0);
    }

    #[test]
    fn test_transfer_state_default() {
        let state = TransferState::new();
        assert!(state.url_node_idx.is_none());
        assert!(state.httpgetfields.is_none());
        assert!(state.uploadfile.is_none());
        assert_eq!(state.up_num, 0);
        assert_eq!(state.url_num, 0);

        let state2: TransferState = Default::default();
        assert!(state2.url_node_idx.is_none());
    }

    #[test]
    fn test_set_trace_file() {
        let mut global = GlobalConfig::new_with_defaults();
        let tmp = std::env::temp_dir().join("blitzy_test_trace.txt");
        let path = tmp.to_str().unwrap();

        let result = global.set_trace_file(path);
        assert!(result.is_ok());
        assert!(global.trace_fopened);
        assert!(global.trace_stream.is_some());
        assert_eq!(global.trace_dump.as_deref(), Some(path));

        // Write to verify the stream works
        if let Some(ref mut stream) = global.trace_stream {
            stream.write_all(b"trace test\n").unwrap();
            stream.flush().unwrap();
        }

        // Clean up
        global.trace_stream = None;
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_set_trace_stream_no_fopened() {
        let mut global = GlobalConfig::new_with_defaults();
        let buf: Vec<u8> = Vec::new();
        global.set_trace_stream(Box::new(buf));
        assert!(!global.trace_fopened);
        assert!(global.trace_stream.is_some());
    }

    #[test]
    fn test_config_count() {
        let mut global = GlobalConfig::new_with_defaults();
        assert_eq!(global.config_count(), 1);
        global.add_config();
        assert_eq!(global.config_count(), 2);
    }

    #[test]
    fn test_tool_var_binary_content() {
        let var = ToolVar {
            name: "bin_var".to_string(),
            content: vec![0x00, 0xFF, 0x7F, 0x80],
        };
        assert_eq!(var.name, "bin_var");
        assert_eq!(var.content.len(), 4);
        assert_eq!(var.content[0], 0x00);
        assert_eq!(var.content[3], 0x80);
    }
}

// ---------------------------------------------------------------------------
// Convenience methods on OperationConfig
// ---------------------------------------------------------------------------

impl OperationConfig {
    /// Returns the number of URL entries in this config's transfer list.
    pub fn url_count(&self) -> usize {
        self.url_list.len()
    }

    /// Appends a new [`GetOut`] node to the URL list and returns a mutable
    /// reference to it.
    ///
    /// This is the Rust equivalent of C's `new_getout()`.
    pub fn new_getout(&mut self) -> &mut GetOut {
        let num = self.url_list.len() as i64;
        let mut getout = GetOut::new();
        getout.num = num;
        getout.use_remote = self.remote_name_all;
        self.url_list.push(getout);
        self.url_list.last_mut().expect("just pushed")
    }
}
