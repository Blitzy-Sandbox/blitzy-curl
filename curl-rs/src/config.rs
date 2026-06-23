// curl-rs — CLI configuration state.
//
// SPDX-License-Identifier: curl
//
// This module is the Rust reimplementation of curl's command-line configuration
// state. The original C sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).
//
// It is the behavioral port of three C translation units of the `src/` CLI tree:
//   * `src/tool_cfgable.h` / `src/tool_cfgable.c` — the `State`,
//     `OperationConfig`, and `GlobalConfig` structures plus their
//     allocate/initialize/free lifecycle (`config_alloc`, `config_free`,
//     `globalconf_init`, `globalconf_free`).
//   * `src/var.h` / `src/var.c` — the `--variable` store (`setvariable`,
//     `varexpand`, `varcleanup`) and its `{{name}}` / `{{name:func}}` expander.
//
// The C constructs are consumed as a behavioral oracle, not transliterated: the
// manual `malloc`/`free` lifecycle becomes Rust ownership + `Drop`, the
// `OperationConfig` doubly-linked `--next` list becomes a `Vec` owned by
// `GlobalConfig`, the per-protocol `curl_slist*` accumulators become
// `Vec<String>`, and the `tool_var` linked list becomes a `Vec<ToolVar>`. No CLI
// flag, semantic, or default is altered (the minimal-change / CLI-parity mandate,
// AAP §0.8.2): every field below exists solely to hold the value of a curl 8.x
// command-line option, so the field set is a 1:1 shadow of curl's option set.

//! CLI configuration state for `curl-rs` — the in-memory shadow of curl's
//! command-line option set.
//!
//! This module mirrors curl's `src/tool_cfgable.*` and `src/var.*`. Three
//! structures form the configuration tree:
//!
//! * [`OperationConfig`] — the large per-transfer configuration (one block per
//!   URL group, separated on the command line by `--next`). It reproduces every
//!   field of the C `struct OperationConfig`.
//! * [`State`] — transient iteration state for URL/upload globbing
//!   (`struct State`).
//! * [`GlobalConfig`] — process-wide configuration: the ordered list of
//!   operations, the trace/verbosity/parallel settings, and the `--variable`
//!   store (`struct GlobalConfig`).
//!
//! # Modeling decisions (safe-Rust equivalents of C idioms)
//!
//! * **`--next` list.** C threads `OperationConfig` instances on a manual
//!   doubly-linked list (`prev`/`next`). Rust models the same ordering as a
//!   [`Vec<OperationConfig>`](Vec) owned by [`GlobalConfig`] plus a `current`
//!   cursor — preserving `--next` "start a new operation block" semantics with
//!   no raw pointers and no `unsafe`. The `prev`/`next` fields are therefore
//!   absent from [`OperationConfig`]; the list owns ordering.
//! * **String lists.** Each C `struct curl_slist*` accumulator (`headers`,
//!   `quote`, `resolve`, …) becomes a [`Vec<String>`](Vec). Accumulation on the
//!   CLI side is simpler as a `Vec`; conversion to the libcurl `SList` happens
//!   later in `setopt.rs`.
//! * **`getout` list.** curl's per-URL `struct getout` linked list becomes a
//!   [`Vec<GetOut>`](GetOut) with `Option<usize>` fill cursors.
//! * **Owned strings.** Each C `char*` option becomes an
//!   [`Option<String>`](Option); deterministic `Drop` replaces every
//!   `tool_safefree`, so `config_free` reduces to dropping the value.
//!
//! # Dependency direction
//!
//! This module depends only on the Rust standard library and on sibling modules
//! of the `curl-rs` binary crate (via field types `crate::urlglob::UrlGlob`,
//! `crate::formparse::ToolMime`, and the `crate::args::ParameterError` returned
//! by the `--variable` API). It never references the FFI crate, and it needs no
//! item from `curl_rs_lib` — the configuration is plain owned data (AAP §0.4:
//! `curl-rs` depends on `curl-rs-lib` only, never on `curl-rs-ffi`).

use std::fs;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};

// ===========================================================================
// curl default constants (mirrored from the C headers so the defaults applied
// by `OperationConfig::new` / `GlobalConfig::new` match curl byte-for-byte).
// ===========================================================================

/// Default value of `CURLOPT_MAXREDIRS` applied by `config_alloc`
/// (`DEFAULT_MAXREDIRS`, `src/tool_main.h`).
pub const DEFAULT_MAXREDIRS: i64 = 50;

/// Default Happy-Eyeballs timeout in milliseconds (`CURL_HET_DEFAULT`,
/// `include/curl/curl.h`); applied by `config_alloc`.
pub const CURL_HET_DEFAULT: i64 = 200;

/// `--upload-flags` default bit set by `config_alloc`: `CURLULFLAG_SEEN`
/// (`1 << 4`, `include/curl/curl.h`).
pub const CURLULFLAG_SEEN: u8 = 1 << 4;

/// Default maximum number of parallel transfers (`PARALLEL_DEFAULT`,
/// `src/tool_main.h`); applied by `globalconf_init`.
pub const PARALLEL_DEFAULT: u16 = 50;

/// Maximum permitted value for `--parallel-max` (`MAX_PARALLEL`,
/// `src/tool_main.h`).
pub const MAX_PARALLEL: u16 = 65535;

/// Maximum permitted value for the per-host parallel cap (`MAX_PARALLEL_HOST`,
/// `src/tool_main.h`).
pub const MAX_PARALLEL_HOST: u16 = 65535;

/// Maximum length of a `--variable` name, including the limit used to size the
/// expander's name buffer (`MAX_VAR_LEN`, `src/var.c`).
const MAX_VAR_LEN: usize = 128;

/// Process-global monotonic counter backing the `num` field of [`GetOut`]
/// nodes, mirroring the function-local `static int outnum` in C's `new_getout`
/// (`src/tool_paramhlp.c`). An atomic keeps the exact "increments once per
/// added URL across the whole invocation" semantics without `unsafe` mutable
/// statics.
static GETOUT_OUTNUM: AtomicU64 = AtomicU64::new(0);

// ===========================================================================
// Enumerations mirroring the C configuration enums.
// ===========================================================================

/// File-overwrite policy for `-o`/`-O`/`-J` output, mirroring the anonymous
/// `file_clobber_mode` enum in `struct OperationConfig` (`src/tool_cfgable.h`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FileClobberMode {
    /// `CLOBBER_DEFAULT`: legacy behavior — `-o`/`-O` overwrite, `-J` does not.
    #[default]
    Default,
    /// `CLOBBER_NEVER`: if the file exists, always fail (`--no-clobber`).
    Never,
    /// `CLOBBER_ALWAYS`: if the file exists, always overwrite (`--clobber`).
    Always,
}

/// `-f`/`--fail` family selector, mirroring the `unsigned char fail` field of
/// `struct OperationConfig` with its `FAIL_NONE` / `FAIL_WITH_BODY` /
/// `FAIL_WO_BODY` values (`src/tool_cfgable.h`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FailMode {
    /// `FAIL_NONE` (0): do not treat HTTP error responses as failures.
    #[default]
    None,
    /// `FAIL_WITH_BODY` (1): fail on HTTP errors but still output the body
    /// (`--fail-with-body`).
    WithBody,
    /// `FAIL_WO_BODY` (2): fail on HTTP errors and suppress the body
    /// (`-f`/`--fail`).
    WithoutBody,
}

/// HTTP request type, mirroring the `HttpReq` enum (`src/tool_sdecls.h`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum HttpReq {
    /// `TOOL_HTTPREQ_UNSPEC`: request type not yet chosen.
    #[default]
    Unspec,
    /// `TOOL_HTTPREQ_GET`.
    Get,
    /// `TOOL_HTTPREQ_HEAD`.
    Head,
    /// `TOOL_HTTPREQ_MIMEPOST`: multipart/form-data POST (`-F`).
    MimePost,
    /// `TOOL_HTTPREQ_SIMPLEPOST`: `application/x-www-form-urlencoded` POST
    /// (`-d`).
    SimplePost,
    /// `TOOL_HTTPREQ_PUT`.
    Put,
}

/// Verbose/trace output style, mirroring the `trace` enum (`src/tool_sdecls.h`).
///
/// The discriminant order matches C so that "trace enabled" is exactly
/// `!= TraceType::None` (C tests the enum for non-zero).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum TraceType {
    /// `TRACE_NONE`: no trace/verbose output.
    #[default]
    None,
    /// `TRACE_BIN`: tcpdump-style hex+ASCII dump (`--trace`).
    Bin,
    /// `TRACE_ASCII`: like [`Bin`](TraceType::Bin) without the hex column
    /// (`--trace-ascii`).
    Ascii,
    /// `TRACE_PLAIN`: `-v`/`--verbose`-style output.
    Plain,
}

// ===========================================================================
// getout — per-URL fetch/store/upload descriptor.
// ===========================================================================

/// 1-bit flags of a [`GetOut`] node, mirroring the `BIT(...)` members of
/// `struct getout` (`src/tool_sdecls.h`).
#[derive(Clone, Copy, Debug, Default)]
pub struct GetOutFlags {
    /// `outset`: an output target (`-o`) has been set for this URL.
    pub outset: bool,
    /// `urlset`: a URL has been set for this node.
    pub urlset: bool,
    /// `uploadset`: an upload file (`-T`) has been set.
    pub uploadset: bool,
    /// `useremote`: use the remote file name locally (`-O`).
    pub useremote: bool,
    /// `noupload`: `-T ""` was given, explicitly disabling upload.
    pub noupload: bool,
    /// `noglob`: URL globbing is disabled for this URL (`-g` / `--globoff`).
    pub noglob: bool,
    /// `out_null`: discard this URL's output.
    pub out_null: bool,
}

/// A single URL to fetch, together with where its output is stored and which
/// file (if any) is uploaded — the Rust analog of `struct getout`
/// (`src/tool_sdecls.h`).
///
/// curl threads these on a linked list; here they live in
/// [`OperationConfig::url_list`] in order, so the `next` pointer is implicit in
/// the [`Vec`] ordering.
#[derive(Clone, Debug, Default)]
pub struct GetOut {
    /// The URL to operate on (`getout.url`).
    pub url: Option<String>,
    /// Where to store the output (`getout.outfile`).
    pub outfile: Option<String>,
    /// File to upload when [`GetOutFlags::uploadset`] is set (`getout.infile`).
    pub infile: Option<String>,
    /// Sequence number assigned when the node is created (`getout.num`).
    pub num: i64,
    /// The node's 1-bit flags (`getout`'s `BIT(...)` members).
    pub flags: GetOutFlags,
}

// ===========================================================================
// OperationConfig — the per-transfer configuration (one block per URL group).
// ===========================================================================

/// The per-transfer command-line configuration, mirroring
/// `struct OperationConfig` (`src/tool_cfgable.h`).
///
/// One [`OperationConfig`] holds the options for a single URL group; consecutive
/// groups separated by `--next` are stored in order in
/// [`GlobalConfig::operations`]. Every field corresponds to a curl 8.x option
/// and is `pub` so the option parser (`args.rs`), the config-file parser
/// (`parsecfg.rs`), and the libcurl-option mapper (`setopt.rs`) can read and
/// write it directly, exactly as the C tool accesses the struct.
///
/// [`OperationConfig::new`] is the analog of C's `config_alloc`: it applies
/// curl's documented non-zero defaults. [`Default`] is derived for ergonomic
/// `..Default::default()` construction (an all-zero/empty base); the
/// curl-faithful constructor used everywhere in this crate is
/// [`new`](OperationConfig::new), and [`GlobalConfig`] always creates operations
/// through it, so the curl defaults are never bypassed in practice.
///
/// The C `prev`/`next` self-pointers are intentionally absent — ordering is
/// owned by the [`Vec`] in [`GlobalConfig`] (see the module docs).
//
// curl genuinely exposes ~90 boolean command-line flags; reproducing them as
// `bool` fields is required for CLI parity, not a design smell — hence the
// `struct_excessive_bools` allow.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
pub struct OperationConfig {
    // ---- request body / general ------------------------------------------
    /// Accumulated `--data`/`--data-binary` body (`struct dynbuf postdata`).
    pub postdata: Vec<u8>,
    pub useragent: Option<String>,
    /// `-b` cookie data to serialize into a single request line (`cookies`).
    pub cookies: Vec<String>,
    /// `-c` file to write the cookie jar to (`cookiejar`).
    pub cookiejar: Option<String>,
    /// Files to load cookies from (`cookiefiles`).
    pub cookiefiles: Vec<String>,
    pub altsvc: Option<String>,
    pub hsts: Option<String>,
    pub proto_str: Option<String>,
    pub proto_redir_str: Option<String>,
    pub proto_default: Option<String>,
    pub resume_from: i64,
    pub postfields: Option<String>,
    pub referer: Option<String>,
    pub query: Option<String>,
    pub max_filesize: i64,
    pub output_dir: Option<String>,
    pub headerfile: Option<String>,
    pub ftpport: Option<String>,
    pub iface: Option<String>,
    pub range: Option<String>,

    // ---- DNS --------------------------------------------------------------
    pub dns_servers: Option<String>,
    pub dns_interface: Option<String>,
    pub dns_ipv4_addr: Option<String>,
    pub dns_ipv6_addr: Option<String>,

    // ---- identity / authentication ---------------------------------------
    pub userpwd: Option<String>,
    pub login_options: Option<String>,
    pub tls_username: Option<String>,
    pub tls_password: Option<String>,
    pub tls_authtype: Option<String>,
    pub proxy_tls_username: Option<String>,
    pub proxy_tls_password: Option<String>,
    pub proxy_tls_authtype: Option<String>,
    pub proxyuserpwd: Option<String>,
    pub proxy: Option<String>,
    pub noproxy: Option<String>,
    pub knownhosts: Option<String>,

    // ---- mail (SMTP) ------------------------------------------------------
    pub mail_from: Option<String>,
    pub mail_rcpt: Vec<String>,
    pub mail_auth: Option<String>,
    pub sasl_authzid: Option<String>,
    pub netrc_file: Option<String>,

    // ---- URL / output list (the `getout` chain) --------------------------
    /// All URLs to operate on, in order (C `url_list`/`url_last` chain).
    pub url_list: Vec<GetOut>,
    /// Index of the node awaiting a URL value (C `url_get`).
    pub url_get: Option<usize>,
    /// Index of the node awaiting an output target (C `url_out`).
    pub url_out: Option<usize>,
    /// Index of the node awaiting an upload file (C `url_ul`).
    pub url_ul: Option<usize>,
    /// Number of URL arguments added (C `num_urls`). Incremented exactly once
    /// per URL by [`add_url`](crate::args), mirroring curl's
    /// `++config->num_urls` (`tool_getparam.c` L1118). This counts URL
    /// arguments only — not output (`-o`/`-O`) or upload (`-T`) nodes, and not
    /// glob expansion — so the "etag options only work on a single URL" guard
    /// fires correctly. It is therefore not necessarily equal to
    /// `url_list.len()`.
    pub num_urls: usize,

    /// `--ipfs-gateway` (C field guarded by `CURL_DISABLE_IPFS`; always present
    /// here, defaulting to `None`, which is equivalent to the disabled build).
    pub ipfs_gateway: Option<String>,
    pub doh_url: Option<String>,

    // ---- TLS (and proxy_ variants) ---------------------------------------
    pub cipher_list: Option<String>,
    pub proxy_cipher_list: Option<String>,
    pub cipher13_list: Option<String>,
    pub proxy_cipher13_list: Option<String>,
    pub cert: Option<String>,
    pub proxy_cert: Option<String>,
    pub cert_type: Option<String>,
    pub proxy_cert_type: Option<String>,
    pub cacert: Option<String>,
    pub proxy_cacert: Option<String>,
    pub capath: Option<String>,
    pub proxy_capath: Option<String>,
    pub crlfile: Option<String>,
    pub proxy_crlfile: Option<String>,
    pub pinnedpubkey: Option<String>,
    pub proxy_pinnedpubkey: Option<String>,
    pub key: Option<String>,
    pub proxy_key: Option<String>,
    pub key_type: Option<String>,
    pub proxy_key_type: Option<String>,
    pub key_passwd: Option<String>,
    pub proxy_key_passwd: Option<String>,
    pub pubkey: Option<String>,
    pub hostpubmd5: Option<String>,
    pub hostpubsha256: Option<String>,
    pub engine: Option<String>,
    pub ssl_ec_curves: Option<String>,
    pub ssl_signature_algorithms: Option<String>,

    // ---- etag / request --------------------------------------------------
    pub etag_save_file: Option<String>,
    pub etag_compare_file: Option<String>,
    pub customrequest: Option<String>,
    pub krblevel: Option<String>,
    pub request_target: Option<String>,
    /// `--write-out` format string (C `writeout`).
    pub writeout: Option<String>,

    // ---- per-protocol command lists --------------------------------------
    pub quote: Vec<String>,
    pub postquote: Vec<String>,
    pub prequote: Vec<String>,
    pub headers: Vec<String>,
    pub proxyheaders: Vec<String>,

    /// Root of the `-F` MIME/form tree built by `formparse.rs` (C `mimeroot`).
    ///
    /// C also keeps `mimecurrent` (a parse cursor into this tree) and `mimepost`
    /// (the built libcurl `curl_mime` object). Both are modeled elsewhere: the
    /// parse cursor lives inside `formparse`, and the libcurl `Mime` object is
    /// constructed later by `setopt.rs`. Only the owned CLI-side root is held
    /// here.
    pub mimeroot: Option<crate::formparse::ToolMime>,

    pub telnet_options: Vec<String>,
    pub resolve: Vec<String>,
    pub connect_to: Vec<String>,

    // ---- proxy / service names -------------------------------------------
    pub preproxy: Option<String>,
    pub proxy_service_name: Option<String>,
    pub service_name: Option<String>,

    // ---- FTP / SSH --------------------------------------------------------
    pub ftp_account: Option<String>,
    pub ftp_alternative_to_user: Option<String>,
    pub oauth_bearer: Option<String>,
    pub unix_socket_path: Option<String>,
    pub haproxy_clientip: Option<String>,
    pub aws_sigv4: Option<String>,

    // ---- ECH (Encrypted Client Hello) ------------------------------------
    pub ech: Option<String>,
    pub ech_config: Option<String>,
    pub ech_public: Option<String>,

    // ---- time / bandwidth (curl_off_t -> i64) ----------------------------
    pub condtime: i64,
    /// Upload bandwidth cap, bytes/s (`sendpersecond`).
    pub sendpersecond: i64,
    /// Download bandwidth cap, bytes/s (`recvpersecond`).
    pub recvpersecond: i64,

    // ---- numeric options (C `long` -> i64) -------------------------------
    pub proxy_ssl_version: i64,
    /// IP version preference (`CURL_IPRESOLVE_*`; default `WHATEVER` == 0).
    pub ip_version: i64,
    pub create_file_mode: i64,
    pub low_speed_limit: i64,
    pub low_speed_time: i64,
    pub ip_tos: i64,
    pub vlan_priority: i64,
    pub localport: i64,
    pub localportrange: i64,
    /// HTTP authentication bitmask (C `unsigned long authtype`).
    pub authtype: u64,
    pub timeout_ms: i64,
    pub connecttimeout_ms: i64,
    pub maxredirs: i64,
    pub httpversion: i64,
    /// SOCKS5 authentication bitmask (C `unsigned long socks5_auth`).
    pub socks5_auth: u64,
    pub req_retry: i64,
    pub retry_delay_ms: i64,
    pub retry_maxtime_ms: i64,
    /// MIME option flags (C `unsigned long mime_options`).
    pub mime_options: u64,
    pub tftp_blksize: i64,
    pub alivetime: i64,
    pub alivecnt: i64,
    pub gssapi_delegation: i64,
    pub expect100timeout_ms: i64,
    /// Happy-Eyeballs timeout, ms (default [`CURL_HET_DEFAULT`]).
    pub happy_eyeballs_timeout_ms: i64,
    /// Time-condition selector (C `unsigned long timecond`).
    pub timecond: u64,
    pub followlocation: i64,
    pub proxyver: i64,
    pub ftp_ssl_ccc_mode: i64,
    pub ftp_filemethod: i64,

    // ---- enums / small integers ------------------------------------------
    pub httpreq: HttpReq,
    pub file_clobber_mode: FileClobberMode,
    /// `--upload-flags` bitmask (default [`CURLULFLAG_SEEN`]).
    pub upload_flags: u8,
    /// `--local-port` value to use (C `unsigned short porttouse`).
    pub porttouse: u16,
    /// Minimum TLS version, 0..=4 (0 = default).
    pub ssl_version: u8,
    /// Maximum TLS version, 0..=4 (0 = default).
    pub ssl_version_max: u8,
    /// `-f`/`--fail` family selector (C `unsigned char fail`).
    pub fail: FailMode,

    // ---- 1-bit flags (C `BIT(...)`); default `false` ---------------------
    pub remote_name_all: bool,
    pub remote_time: bool,
    pub cookiesession: bool,
    pub encoding: bool,
    pub tr_encoding: bool,
    pub use_resume: bool,
    pub resume_from_current: bool,
    pub disable_epsv: bool,
    pub disable_eprt: bool,
    pub ftp_pret: bool,
    pub proto_present: bool,
    pub proto_redir_present: bool,
    pub mail_rcpt_allowfails: bool,
    pub sasl_ir: bool,
    pub proxytunnel: bool,
    pub ftp_append: bool,
    pub use_ascii: bool,
    pub autoreferer: bool,
    pub show_headers: bool,
    pub no_body: bool,
    pub dirlistonly: bool,
    pub unrestricted_auth: bool,
    pub netrc_opt: bool,
    pub netrc: bool,
    pub crlf: bool,
    pub http09_allowed: bool,
    pub nobuffer: bool,
    pub readbusy: bool,
    pub globoff: bool,
    pub use_httpget: bool,
    pub insecure_ok: bool,
    pub doh_insecure_ok: bool,
    pub proxy_insecure_ok: bool,
    pub terminal_binary_ok: bool,
    pub verifystatus: bool,
    pub doh_verifystatus: bool,
    pub create_dirs: bool,
    pub ftp_create_dirs: bool,
    pub ftp_skip_ip: bool,
    pub proxynegotiate: bool,
    pub proxyntlm: bool,
    pub proxydigest: bool,
    pub proxybasic: bool,
    pub proxyanyauth: bool,
    pub jsoned: bool,
    pub ftp_ssl: bool,
    pub ftp_ssl_reqd: bool,
    pub ftp_ssl_control: bool,
    pub ftp_ssl_ccc: bool,
    pub socks5_gssapi_nec: bool,
    pub tcp_nodelay: bool,
    pub tcp_fastopen: bool,
    pub retry_all_errors: bool,
    pub retry_connrefused: bool,
    pub tftp_no_options: bool,
    pub ignorecl: bool,
    pub disable_sessionid: bool,
    pub raw: bool,
    pub post301: bool,
    pub post302: bool,
    pub post303: bool,
    pub nokeepalive: bool,
    pub content_disposition: bool,
    pub xattr: bool,
    pub ssl_allow_beast: bool,
    pub ssl_allow_earlydata: bool,
    pub proxy_ssl_allow_beast: bool,
    pub ssl_no_revoke: bool,
    pub ssl_revoke_best_effort: bool,
    pub native_ca_store: bool,
    pub proxy_native_ca_store: bool,
    pub ssl_auto_client_cert: bool,
    pub proxy_ssl_auto_client_cert: bool,
    pub noalpn: bool,
    pub abstract_unix_socket: bool,
    pub path_as_is: bool,
    pub suppress_connect_headers: bool,
    pub synthetic_error: bool,
    pub ssh_compression: bool,
    pub haproxy_protocol: bool,
    pub disallow_username_in_url: bool,
    pub mptcp: bool,
    pub rm_partial: bool,
    pub skip_existing: bool,
}

impl OperationConfig {
    /// Creates a per-transfer configuration with curl's documented defaults —
    /// the analog of `config_alloc` (`src/tool_cfgable.c`).
    ///
    /// Every field not listed below keeps its zero/`false`/`None`/empty value
    /// (matching `curlx_calloc`), including `ip_version == 0`
    /// (`CURL_IPRESOLVE_WHATEVER`) and `file_clobber_mode == CLOBBER_DEFAULT`.
    /// The non-zero defaults reproduced from `config_alloc` are exactly:
    ///
    /// * `maxredirs = DEFAULT_MAXREDIRS` (50)
    /// * `tcp_nodelay = true` (enabled by default)
    /// * `happy_eyeballs_timeout_ms = CURL_HET_DEFAULT` (200)
    /// * `ftp_skip_ip = true`
    /// * `upload_flags = CURLULFLAG_SEEN`
    #[must_use]
    pub fn new() -> Self {
        Self {
            maxredirs: DEFAULT_MAXREDIRS,
            tcp_nodelay: true,
            happy_eyeballs_timeout_ms: CURL_HET_DEFAULT,
            ftp_skip_ip: true,
            upload_flags: CURLULFLAG_SEEN,
            ..Self::default()
        }
    }

    /// Appends a fresh [`GetOut`] node and returns its index in
    /// [`url_list`](OperationConfig::url_list) — the analog of `new_getout`
    /// (`src/tool_paramhlp.c`).
    ///
    /// The new node inherits `useremote` from
    /// [`remote_name_all`](OperationConfig::remote_name_all) (curl's `-O` /
    /// `--remote-name-all` behavior) and receives a process-global sequence
    /// number (C's `static int outnum`).
    ///
    /// This does **not** touch [`num_urls`](OperationConfig::num_urls): in curl
    /// `new_getout` (`tool_getparam.c`) is the shared node allocator for URL,
    /// output (`-o`/`-O`), and upload (`-T`) nodes alike, and only the URL-add
    /// path (`add_url`) increments `num_urls` (`++config->num_urls`,
    /// `tool_getparam.c` L1118). Syncing `num_urls` to the list length here
    /// would double-count a single URL (the allocator bumps it, then `add_url`
    /// bumps it again) and also miscount when `-o`/`-T` allocate body-less
    /// nodes, breaking the "etag options only work on a single URL" guard.
    pub fn new_getout(&mut self) -> usize {
        let node = GetOut {
            num: GETOUT_OUTNUM.fetch_add(1, Ordering::Relaxed) as i64,
            flags: GetOutFlags {
                useremote: self.remote_name_all,
                ..GetOutFlags::default()
            },
            ..GetOut::default()
        };
        self.url_list.push(node);
        self.url_list.len() - 1
    }

    /// Drops every [`GetOut`] node and resets the fill cursors — the analog of
    /// curl's `clean_getout` / the `url_list` teardown loop in
    /// `free_config_fields` (`src/tool_cfgable.c`). Owned strings are released
    /// automatically when the [`Vec`] is cleared.
    pub fn clean_getout(&mut self) {
        self.url_list.clear();
        self.url_get = None;
        self.url_out = None;
        self.url_ul = None;
        self.num_urls = 0;
    }
}

// ===========================================================================
// State — transient URL/upload globbing iteration state.
// ===========================================================================

/// Transient iteration state used while expanding globbed URLs and upload file
/// names, mirroring `struct State` (`src/tool_cfgable.h`). It is driven by the
/// operation loop in `operate.rs`.
#[derive(Debug, Default)]
pub struct State {
    /// Index of the [`GetOut`] node currently being processed within the
    /// current operation's [`url_list`](OperationConfig::url_list) (C `urlnode`,
    /// a `struct getout*`).
    pub urlnode: Option<usize>,
    /// Glob state for the upload file pattern (C `struct URLGlob inglob`);
    /// `None` while no upload glob is active.
    pub inglob: Option<crate::urlglob::UrlGlob>,
    /// Glob state for the URL pattern (C `struct URLGlob urlglob`); `None` while
    /// no URL glob is active.
    pub urlglob: Option<crate::urlglob::UrlGlob>,
    /// `-G`/`--get` query fields gathered for the current URL
    /// (C `char* httpgetfields`).
    pub httpgetfields: Option<String>,
    /// The upload file name for the current iteration (C `char* uploadfile`).
    pub uploadfile: Option<String>,
    /// Number of files to upload in the current glob (C `curl_off_t upnum`).
    pub upnum: i64,
    /// Index into the upload glob (C `curl_off_t upidx`).
    pub upidx: i64,
    /// Number of iterations this URL expands to via ranges/globs
    /// (C `curl_off_t urlnum`).
    pub urlnum: i64,
    /// Index into the globbed URLs (C `curl_off_t urlidx`).
    pub urlidx: i64,
}

// ===========================================================================
// ToolVar — a single `--variable` entry.
// ===========================================================================

/// One `--variable` entry, mirroring `struct tool_var` (`src/var.h`).
///
/// C stores the variable list as a singly-linked list of `tool_var` nodes whose
/// content is a length-counted byte buffer (`content` + `clen`). Here the store
/// is a [`Vec<ToolVar>`] on [`GlobalConfig`] and the content is an owned
/// [`Vec<u8>`] — **raw bytes**, not a `String`. `--variable` content read from a
/// file, stdin, or an environment value may be arbitrary binary (`src/var.c`
/// keeps it length-counted and only rejects NUL bytes at expansion time), so a
/// lossy UTF-8 conversion at storage would irreversibly corrupt non-UTF-8 input.
/// The byte length (C `clen`) is `content.len()`; decoding to text happens only
/// at the expansion output boundary, exactly as curl does.
#[derive(Clone, Debug, Default)]
pub struct ToolVar {
    /// The variable name (C `name`).
    pub name: String,
    /// The variable content as raw bytes (C `content` + `clen`).
    pub content: Vec<u8>,
}

// ===========================================================================
// GlobalConfig — process-wide configuration.
// ===========================================================================

/// Process-wide command-line configuration, mirroring `struct GlobalConfig`
/// (`src/tool_cfgable.h`).
///
/// It owns the ordered list of [`OperationConfig`] blocks (the `--next` chain),
/// the trace/verbosity/parallel settings, and the [`--variable`](GlobalConfig::set_variable)
/// store. [`GlobalConfig::new`] is the analog of `globalconf_init`;
/// [`globalconf_free`](GlobalConfig::globalconf_free) is the analog of
/// `globalconf_free` (a no-op beyond `Drop`, kept for call-site symmetry).
///
/// The C `first`/`current`/`last` `OperationConfig*` pointers are replaced by
/// [`operations`](GlobalConfig::operations) plus the
/// [`current`](GlobalConfig::current) cursor (see the module docs). The
/// Windows-only `struct termout term` field has no Rust analog and is omitted
/// (out-of-scope platform shim, AAP §0.3.2).
//
// Like `OperationConfig`, this aggregates several boolean CLI flags; the
// `struct_excessive_bools` allow documents that this mirrors curl's flag set.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
pub struct GlobalConfig {
    /// Transient globbing iteration state (C `struct State state`).
    pub state: State,
    /// `--trace`/`--trace-ascii` dump target file name (C `trace_dump`).
    pub trace_dump: Option<String>,
    /// Open trace output stream when tracing to a file (C `FILE* trace_stream`);
    /// `None` means trace output goes to stderr (curl's default).
    pub trace_stream: Option<fs::File>,
    /// `--libcurl` output file name (C `libcurl`).
    pub libcurl: Option<String>,
    /// `--ssl-sessions` load/save file name (C `ssl_sessions`).
    pub ssl_sessions: Option<String>,
    /// The `--variable` store (C `struct tool_var* variables`).
    pub variables: Vec<ToolVar>,
    /// Ordered operation blocks; index 0 is the first, the last is the most
    /// recently added by `--next` (replaces C `first`/`last`).
    pub operations: Vec<OperationConfig>,
    /// Cursor into [`operations`](GlobalConfig::operations) identifying the
    /// operation currently being configured (replaces C `current`).
    pub current: usize,
    /// `--rate`: minimum milliseconds between successive transfers
    /// (C `timediff_t ms_per_transfer`).
    pub ms_per_transfer: i64,
    /// Trace output style (C `trace tracetype`).
    pub tracetype: TraceType,
    /// Progress display mode: bar vs. stats (C `int progressmode`).
    pub progressmode: i32,
    /// Per-host parallel transfer cap (C `unsigned short parallel_host`).
    pub parallel_host: u16,
    /// Maximum number of parallel transfers (C `unsigned short parallel_max`).
    pub parallel_max: u16,
    /// Verbosity level (C `unsigned char verbosity`).
    pub verbosity: u8,

    // ---- 1-bit flags (C `BIT(...)`); default `false` ---------------------
    /// `--test-duphandle` (C field present only in `DEBUGBUILD`; always present
    /// here, defaulting to `false`).
    pub test_duphandle: bool,
    /// `--test-event` (C field present only in `DEBUGBUILD`; always present
    /// here, defaulting to `false`).
    pub test_event_based: bool,
    pub parallel: bool,
    pub parallel_connect: bool,
    /// `--fail-early`: exit on the first transfer error.
    pub fail_early: bool,
    /// Fancy styled output detection enabled (default `true` via
    /// [`new`](GlobalConfig::new)).
    pub styled_output: bool,
    /// Whether [`trace_stream`](GlobalConfig::trace_stream) was opened by the
    /// tool and must be closed (C `trace_fopened`; `Drop` handles the close).
    pub trace_fopened: bool,
    /// Include timestamps in trace output (C `tracetime`).
    pub tracetime: bool,
    /// Include transfer/connection ids in trace output (C `traceids`).
    pub traceids: bool,
    /// Show errors even when `--silent` is set (C `showerror`).
    pub showerror: bool,
    /// `--silent`: suppress progress and messages (C `silent`).
    pub silent: bool,
    /// Suppress the progress meter (C `noprogress`).
    pub noprogress: bool,
    /// Updated internally when output is a TTY (C `isatty`).
    pub isatty: bool,
    /// `--trace-config` has been used (C `trace_set`).
    pub trace_set: bool,

    /// The optional category argument captured for a pending `-h`/`--help`
    /// request (C passes `(nextarg && *nextarg) ? nextarg : NULL` to
    /// `tool_help`). `None` means the bare `--help`/`-h` default page; `Some`
    /// holds the category token (e.g. `"all"`, `"http"`, `"category"`, or a
    /// `-`-prefixed option name). Consumed by the `HelpRequested` arm in
    /// `operate.rs`.
    pub help_category: Option<String>,
}

impl GlobalConfig {
    /// Creates the global configuration with curl's defaults and one initial
    /// operation block — the analog of `globalconf_init`
    /// (`src/tool_cfgable.c`).
    ///
    /// Reproduces `globalconf_init`'s non-zero defaults exactly: `showerror`
    /// stays `false`, `styled_output` is `true`, `parallel_max` is
    /// [`PARALLEL_DEFAULT`] (50), and the first [`OperationConfig`] is allocated
    /// via [`OperationConfig::new`] (the `config_alloc` analog). The
    /// process-global libcurl init that `globalconf_init` also performs is the
    /// responsibility of the FFI/library layer, not of this CLI-side state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            operations: vec![OperationConfig::new()],
            current: 0,
            styled_output: true,
            parallel_max: PARALLEL_DEFAULT,
            ..Self::default()
        }
    }

    /// Returns a shared reference to the operation currently being configured
    /// (C `global->current`).
    ///
    /// # Panics
    ///
    /// Panics if [`operations`](GlobalConfig::operations) is empty. A
    /// [`GlobalConfig`] built with [`new`](GlobalConfig::new) always holds at
    /// least one operation, so this never panics in normal use.
    #[must_use]
    pub fn current(&self) -> &OperationConfig {
        &self.operations[self.current]
    }

    /// Returns a mutable reference to the operation currently being configured.
    ///
    /// # Panics
    ///
    /// Panics if [`operations`](GlobalConfig::operations) is empty (see
    /// [`current`](GlobalConfig::current)).
    pub fn current_mut(&mut self) -> &mut OperationConfig {
        let idx = self.current;
        &mut self.operations[idx]
    }

    /// Appends a fresh operation block (the `--next` action) and makes it
    /// current, returning a mutable reference to it.
    ///
    /// This is the analog of `config_alloc` followed by the `prev`/`next`
    /// linking performed when `tool_getparam` returns `PARAM_NEXT_OPERATION`
    /// (`src/tool_operate.c`). The new block is created via
    /// [`OperationConfig::new`] so curl's defaults apply.
    pub fn add_operation(&mut self) -> &mut OperationConfig {
        self.operations.push(OperationConfig::new());
        self.current = self.operations.len() - 1;
        self.operations
            .last_mut()
            .expect("just pushed an operation")
    }

    /// Returns the first operation block (C `global->first`).
    ///
    /// # Panics
    ///
    /// Panics if [`operations`](GlobalConfig::operations) is empty (see
    /// [`current`](GlobalConfig::current)).
    #[must_use]
    pub fn first(&self) -> &OperationConfig {
        &self.operations[0]
    }

    /// Returns a mutable reference to the last operation block
    /// (C `global->last`).
    ///
    /// # Panics
    ///
    /// Panics if [`operations`](GlobalConfig::operations) is empty (see
    /// [`current`](GlobalConfig::current)).
    pub fn last_mut(&mut self) -> &mut OperationConfig {
        self.operations
            .last_mut()
            .expect("operations is non-empty for a GlobalConfig built via new()")
    }

    /// Releases the global configuration — the analog of `globalconf_free`
    /// (`src/tool_cfgable.c`).
    ///
    /// In Rust, all owned data (operations, variables, strings, the trace
    /// stream) is reclaimed automatically by [`Drop`], so this clears the owned
    /// collections eagerly and is otherwise a no-op. It is retained so callers
    /// (`operate.rs`/`main.rs`) can mirror the C teardown call site. The
    /// matching process-global libcurl cleanup is owned by the FFI/library
    /// layer, not by this CLI-side state.
    pub fn globalconf_free(&mut self) {
        self.var_cleanup();
        self.operations.clear();
        self.trace_stream = None;
        self.trace_fopened = false;
    }
}

// ===========================================================================
// The `--variable` store (port of `src/var.c` / `src/var.h`).
//
// curl stores command-line variables in a `struct tool_var` singly-linked list
// hung off `GlobalConfig`. They are referenced from option values and config
// files through `{{name}}` / `{{name:func}}` expansions. This block reproduces
// `setvariable`, `varexpand`, and `varcleanup` exactly, including the precise
// error codes (so malformed `--variable` usage yields curl's exact exit code)
// and the byte-for-byte behavior of the `trim` / `json` / `url` / `b64` /
// `64dec` functions.
// ===========================================================================

impl GlobalConfig {
    /// Defines or imports a `--variable` entry — the analog of `setvariable`
    /// (`src/var.c`).
    ///
    /// `input` is the raw argument to `--variable`. Accepted forms:
    ///
    /// * `name=content` — literal content.
    /// * `name@file` / `name@-` — content read from a file or from stdin.
    /// * `%name` — import `name` from the environment (an optional trailing
    ///   `=content` / `@file` acts as a fallback when the variable is unset).
    /// * An optional `[start-end]` / `[start-]` byte range may follow the name
    ///   to select a slice of literal or file content (ignored for an imported
    ///   environment value, matching curl).
    ///
    /// A malformed name length or unrecognized trailing syntax is a non-fatal
    /// warning (returns `Ok(())`, exactly like curl). Returns the matching
    /// [`ParameterError`](crate::args::ParameterError) for the hard failures:
    /// `ExpandError` for a failed required import, `VarSyntax` for a bad byte
    /// range, and `ReadError` when a `@file` cannot be opened.
    ///
    /// # Note on content storage
    ///
    /// File content is read as raw bytes, the byte range is applied, and the
    /// result is stored as a [`String`] via lossy UTF-8 conversion (curl keeps
    /// raw bytes; non-UTF-8 file content is therefore stored lossily here).
    pub fn set_variable(&mut self, input: &str) -> Result<(), crate::args::ParameterError> {
        use crate::args::ParameterError;

        let silent = self.silent;
        let showerror = self.showerror;

        // A leading '%' selects environment import.
        let (line, import) = match input.strip_prefix('%') {
            Some(rest) => (rest, true),
            None => (input, false),
        };

        // The name is a run of [A-Za-z0-9_].
        let name_len = line
            .bytes()
            .take_while(|&b| b.is_ascii_alphanumeric() || b == b'_')
            .count();
        let name = &line[..name_len];
        let mut rest = &line[name_len..];

        if name_len == 0 || name_len >= MAX_VAR_LEN {
            var_warn(
                silent,
                &format!("Bad variable name length ({name_len}), skipping"),
            );
            return Ok(());
        }

        // Environment import: a present value (even empty) becomes the content.
        // The trailing text, if any, is a fallback used only when unset.
        let mut env_content: Option<Vec<u8>> = None;
        if import {
            // `var_os` mirrors `getenv` presence semantics (Some even for an
            // empty value — curl explicitly supports blank content) better than
            // `var`, which additionally errors on non-UTF-8.
            let env_val =
                std::env::var_os(name).map(|v| v.to_string_lossy().into_owned().into_bytes());
            if rest.is_empty() && env_val.is_none() {
                var_error(
                    silent,
                    showerror,
                    &format!("Variable '{name}' import fail, not set"),
                );
                return Err(ParameterError::ExpandError);
            }
            env_content = env_val;
        }

        // Optional byte range `[start-end]` / `[start-]`. Parsed even for an env
        // import (so a malformed range still errors), but only *applied* below
        // to literal/file content — curl ignores the range for imported values.
        let mut startoffset: i64 = 0;
        let mut endoffset: i64 = i64::MAX;
        {
            let rb = rest.as_bytes();
            if rb.first() == Some(&b'[') && rb.get(1).is_some_and(u8::is_ascii_digit) {
                let p = &rest[1..]; // past '['
                let (s, p) = str_number(p).ok_or(ParameterError::VarSyntax)?;
                let p = str_single(p, b'-').ok_or(ParameterError::VarSyntax)?;
                startoffset = s;
                match str_single(p, b']') {
                    // `[start-]` open-ended: end stays at i64::MAX.
                    Some(p2) => rest = p2,
                    None => {
                        let (e, p2) = str_number(p).ok_or(ParameterError::VarSyntax)?;
                        let p3 = str_single(p2, b']').ok_or(ParameterError::VarSyntax)?;
                        endoffset = e;
                        rest = p3;
                    }
                }
                if startoffset > endoffset {
                    return Err(ParameterError::VarSyntax);
                }
            }
        }

        // Resolve the content: an imported env value wins; otherwise `@file` /
        // `@-` (stdin), or `=literal`.
        let content_bytes: Vec<u8> = if let Some(c) = env_content {
            c
        } else if let Some(path) = rest.strip_prefix('@') {
            let raw: Vec<u8> = if path == "-" {
                let mut buf = Vec::new();
                if std::io::stdin().read_to_end(&mut buf).is_err() {
                    return Err(ParameterError::ReadError);
                }
                buf
            } else {
                match fs::read(path) {
                    Ok(b) => b,
                    Err(e) => {
                        var_error(silent, showerror, &format!("Failed to open {path}: {e}"));
                        return Err(ParameterError::ReadError);
                    }
                }
            };
            apply_range(&raw, startoffset, endoffset)
        } else if let Some(lit) = rest.strip_prefix('=') {
            apply_range(lit.as_bytes(), startoffset, endoffset)
        } else {
            var_warn(silent, &format!("Bad --variable syntax, skipping: {input}"));
            return Ok(());
        };

        // Store the raw bytes verbatim — curl keeps `--variable` content as a
        // length-counted byte buffer (`src/var.c`), so non-UTF-8 file/stdin/env
        // content must survive intact. Any text decoding is deferred to the
        // expansion output boundary (`var_expand`), matching the C oracle.
        self.add_variable(name.to_string(), content_bytes);
        Ok(())
    }

    /// Expands `{{name}}` and `{{name:func}}` references in `line` — the analog
    /// of `varexpand` (`src/var.c`).
    ///
    /// Returns the expanded string together with a `replaced` flag. When
    /// nothing was substituted the original `line` is returned with
    /// `replaced == false` (this also means a stray `\{{` escape is only
    /// "un-escaped" when at least one real substitution occurs — matching
    /// curl, which discards the rebuilt buffer when nothing was replaced).
    ///
    /// Semantics mirrored from the C oracle:
    ///
    /// * `\{{` emits a literal `{{`.
    /// * A `{{` with no matching `}}` emits a warning and stops expansion.
    /// * A name that is empty, `>= 128` bytes, or contains a non
    ///   `[A-Za-z0-9_]` byte is left verbatim (with a warning).
    /// * An **undefined** variable expands to the empty string (this is *not*
    ///   an error in this curl revision — only an unknown *function* is).
    /// * A value containing a null byte is an error (`ExpandError`).
    /// * Functions after a `:` run left-to-right, each feeding the next.
    pub fn var_expand(&self, line: &str) -> Result<(String, bool), crate::args::ParameterError> {
        use crate::args::ParameterError;

        let silent = self.silent;
        let showerror = self.showerror;
        let input = line;
        let mut line = line;
        // The expansion buffer is assembled as raw bytes so a variable value
        // containing non-UTF-8 bytes is carried through verbatim (the C oracle
        // writes the value into a byte `dynbuf`). The buffer is decoded to text
        // only once, at the return — the single output boundary.
        let mut out: Vec<u8> = Vec::new();
        let mut added = false;

        while let Some(pos) = line.find("{{") {
            // A backslash immediately before "{{" escapes it: emit the text up
            // to (but excluding) the backslash, then a literal "{{".
            if pos > 0 && line.as_bytes()[pos - 1] == b'\\' {
                out.extend_from_slice(&line.as_bytes()[..pos - 1]);
                out.extend_from_slice(b"{{");
                line = &line[pos + 2..];
                continue;
            }

            let after_open = &line[pos + 2..];
            let Some(close_rel) = after_open.find("}}") else {
                var_warn(silent, &format!("missing close '}}}}' in '{input}'"));
                break;
            };
            // Byte index just past the closing "}}" within `line`.
            let upto = pos + 2 + close_rel + 2;

            let inner = &after_open[..close_rel];
            let (name, func_region) = match inner.find(':') {
                Some(ci) => (&inner[..ci], Some(&inner[ci..])),
                None => (inner, None),
            };
            let nlen = name.len();

            if nlen == 0 || nlen >= MAX_VAR_LEN {
                var_warn(silent, &format!("bad variable name length '{input}'"));
                // Not a variable reference: keep the whole "{{...}}" verbatim.
                out.extend_from_slice(&line.as_bytes()[..upto]);
                line = &line[upto..];
                continue;
            }

            // Emit the text preceding "{{".
            out.extend_from_slice(&line.as_bytes()[..pos]);

            if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                var_warn(silent, &format!("bad variable name: {name}"));
                out.extend_from_slice(&line.as_bytes()[pos..upto]);
                line = &line[upto..];
                continue;
            }

            // Resolve the value as raw bytes (an unset variable expands to
            // empty), then apply any `:func` chain — all byte-preserving.
            let value: Vec<u8> = match func_region {
                Some(funcs) => {
                    let base = self.varcontent(name).unwrap_or(&[]);
                    self.varfunc(base, funcs)?
                }
                None => self.varcontent(name).unwrap_or(&[]).to_vec(),
            };

            // A value containing a null byte cannot be represented (matches the
            // C oracle's `memchr(value, '\0', vlen)` check at expansion time).
            if !value.is_empty() && value.contains(&0u8) {
                var_error(silent, showerror, "variable contains null byte");
                return Err(ParameterError::ExpandError);
            }

            out.extend_from_slice(&value);
            added = true;
            line = &line[upto..];
        }

        if added {
            if !line.is_empty() {
                out.extend_from_slice(line.as_bytes());
            }
            // Decode the assembled bytes to text at the output boundary only —
            // the lone place curl converts, and the lone unavoidable lossy point
            // for a raw (non-encoded) non-UTF-8 expansion in a String-based CLI.
            Ok((String::from_utf8_lossy(&out).into_owned(), true))
        } else {
            // Nothing substituted: use the original line verbatim.
            Ok((input.to_string(), false))
        }
    }

    /// Releases the `--variable` store — the analog of `varcleanup`
    /// (`src/var.c`). Owned data is dropped automatically; this clears the
    /// collection eagerly.
    pub fn var_cleanup(&mut self) {
        self.variables.clear();
    }

    /// Looks up a variable's content by exact name (C `varcontent`).
    fn varcontent(&self, name: &str) -> Option<&[u8]> {
        self.variables
            .iter()
            .find(|v| v.name == name)
            .map(|v| v.content.as_slice())
    }

    /// Applies the `:`-separated function chain in `funcs` (which begins with a
    /// `:`) to `content`, left-to-right — the analog of `varfunc` (`src/var.c`).
    ///
    /// Each function feeds the next. Supported functions: `trim`, `json`,
    /// `url`, `b64`, `64dec`. An empty content yields empty for every function
    /// (curl skips the transform when the length is zero — notably `64dec` does
    /// not fail on empty input). An unrecognized function is an error.
    fn varfunc(&self, content: &[u8], funcs: &str) -> Result<Vec<u8>, crate::args::ParameterError> {
        use crate::args::ParameterError;

        let mut cur: Vec<u8> = content.to_vec();
        let mut f = funcs; // begins with ':'

        // Consume the leading ':' (guaranteed on entry and after each match by
        // the end-of-function check). An exhausted list ends the chain.
        while let Some(rest) = f.strip_prefix(':') {
            f = rest;

            if let Some(r) = match_func(f, "trim") {
                cur = trim_ws(&cur);
                f = r;
            } else if let Some(r) = match_func(f, "json") {
                cur = if cur.is_empty() {
                    Vec::new()
                } else {
                    json_escape_bytes(&cur)
                };
                f = r;
            } else if let Some(r) = match_func(f, "url") {
                cur = if cur.is_empty() {
                    Vec::new()
                } else {
                    url_escape_bytes(&cur)
                };
                f = r;
            } else if let Some(r) = match_func(f, "b64") {
                cur = if cur.is_empty() {
                    Vec::new()
                } else {
                    base64_encode_bytes(&cur)
                };
                f = r;
            } else if let Some(r) = match_func(f, "64dec") {
                cur = if cur.is_empty() {
                    Vec::new()
                } else {
                    base64_decode_bytes(&cur).unwrap_or_else(|| b"[64dec-fail]".to_vec())
                };
                f = r;
            } else {
                var_error(
                    self.silent,
                    self.showerror,
                    &format!("unknown variable function in '{funcs}'"),
                );
                return Err(ParameterError::ExpandError);
            }
        }

        // Return the raw bytes — the caller (`var_expand`) keeps the value as
        // bytes and only decodes at its output boundary. Encoders (`json`/`url`/
        // `b64`) already yield ASCII; `64dec`/`trim` may yield binary, which is
        // now carried through losslessly instead of being UTF-8-mangled here.
        Ok(cur)
    }

    /// Inserts or overwrites a variable (last definition wins) — the analog of
    /// `addvariable` (`src/var.c`).
    ///
    /// curl prepends a duplicate node and warns; the observable result (the
    /// value returned by [`varcontent`](GlobalConfig::varcontent) and the
    /// `Note:` message) is preserved here by updating in place.
    fn add_variable(&mut self, name: String, content: Vec<u8>) {
        let trace_on = self.tracetype != TraceType::None;
        if let Some(existing) = self.variables.iter_mut().find(|v| v.name == name) {
            var_note(trace_on, &format!("Overwriting variable '{name}'"));
            existing.content = content;
        } else {
            self.variables.push(ToolVar { name, content });
        }
    }
}

// ===========================================================================
// Module-private helpers for the `--variable` store.
//
// Diagnostic helpers mirror `src/tool_msgs.c` gating (`warnf` / `notef` /
// `errorf`). The remainder reproduce the small parsers and the `trim` / `json`
// / `url` / `b64` / `64dec` encoders that `var.c` borrows from `curlx`
// (`strparse.c`, `base64.c`, `escape.c`, `tool_writeout_json.c`). They are
// implemented inline because the CLI crate declares no base64/url dependency.
// ===========================================================================

/// Emits a `Warning:` to stderr unless silenced (C `warnf`,
/// gated on `!global->silent`).
fn var_warn(silent: bool, msg: &str) {
    if !silent {
        eprintln!("Warning: {msg}");
    }
}

/// Emits a `Note:` to stderr when tracing is enabled (C `notef`,
/// gated on `global->tracetype`).
fn var_note(trace_on: bool, msg: &str) {
    if trace_on {
        eprintln!("Note: {msg}");
    }
}

/// Emits a `curl:` error to stderr (C `errorf`,
/// gated on `!global->silent || global->showerror`).
fn var_error(silent: bool, showerror: bool, msg: &str) {
    if !silent || showerror {
        eprintln!("curl: {msg}");
    }
}

/// Parses a leading run of base-10 digits into an `i64`, returning the value
/// and the unconsumed tail — the analog of `curlx_str_number`
/// (`lib/curlx/strparse.c`). Returns `None` when there is no leading digit or
/// the value would overflow `i64` (`CURL_OFF_T_MAX`).
fn str_number(s: &str) -> Option<(i64, &str)> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return None;
    }
    let mut num: i64 = 0;
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        let d = i64::from(bytes[i] - b'0');
        // Overflow guard equivalent to C's `num > (max - n) / base`.
        if num > (i64::MAX - d) / 10 {
            return None;
        }
        num = num * 10 + d;
        i += 1;
    }
    Some((num, &s[i..]))
}

/// Consumes a single expected byte, returning the tail — the analog of
/// `curlx_str_single` (`lib/curlx/strparse.c`). Returns `None` when the first
/// byte does not match.
fn str_single(s: &str, ch: u8) -> Option<&str> {
    if s.as_bytes().first() == Some(&ch) {
        // `ch` is always ASCII here (`-` or `]`), so the boundary is valid.
        Some(&s[1..])
    } else {
        None
    }
}

/// Applies a `[start-end]` byte range to `bytes`, mirroring the slicing done in
/// `setvariable` (`src/var.c`) and `file2memory_range`.
///
/// When no range is specified (`start == 0 && end == i64::MAX`) the input is
/// returned whole. A start at or past the end yields empty; the end is clamped
/// to the last byte.
fn apply_range(bytes: &[u8], start: i64, end: i64) -> Vec<u8> {
    let clen = bytes.len() as i64;
    if start == 0 && end == i64::MAX {
        return bytes.to_vec();
    }
    if start >= clen {
        return Vec::new();
    }
    let e = if end >= clen { clen - 1 } else { end };
    let s = start as usize;
    let n = (e - start + 1) as usize;
    bytes[s..s + n].to_vec()
}

/// Matches a function name at the start of `f`, requiring it to be followed by
/// a `:` (another function) or the end of the string (the `}` terminator in
/// curl). Returns the tail after the name — the analog of the `FUNCMATCH` /
/// `ENDOFFUNC` macros (`src/var.c`).
fn match_func<'a>(f: &'a str, name: &str) -> Option<&'a str> {
    f.strip_prefix(name)
        .filter(|rest| rest.is_empty() || rest.starts_with(':'))
}

/// curl's `ISSPACE` (`lib/curl_ctype.h`): space, tab, and `0x0a..=0x0d`
/// (`\n`, `\v`, `\f`, `\r`). Note this includes the vertical tab `0x0b`, which
/// `u8::is_ascii_whitespace` omits.
fn is_curl_space(b: u8) -> bool {
    b == b' ' || b == b'\t' || (0x0a..=0x0d).contains(&b)
}

/// Trims leading and trailing whitespace (curl `ISSPACE`) — the `trim`
/// function of `varfunc` (`src/var.c`).
fn trim_ws(bytes: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start < bytes.len() && is_curl_space(bytes[start]) {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && is_curl_space(bytes[end - 1]) {
        end -= 1;
    }
    bytes[start..end].to_vec()
}

/// JSON-escapes `input` exactly as `jsonquoted(..., lowercase = false)`
/// (`src/tool_writeout_json.c`) — the `json` function of `varfunc`.
///
/// Escapes `\`, `"`, and the C0 controls `\b \f \n \r \t`; any other byte below
/// `0x20` becomes `\u00xx` (lowercase hex); all other bytes pass through
/// unchanged (notably `/`, `DEL`, and bytes `>= 0x80` are not escaped).
fn json_escape_bytes(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            _ => {
                if b < 32 {
                    out.extend_from_slice(format!("\\u{b:04x}").as_bytes());
                } else {
                    out.push(b);
                }
            }
        }
    }
    out
}

/// URL-encodes `input` exactly as `curl_easy_escape` (`lib/escape.c`) — the
/// `url` function of `varfunc`.
///
/// Unreserved bytes (`A-Z a-z 0-9 - . _ ~`) pass through; every other byte
/// becomes `%` followed by two uppercase hex digits.
fn url_escape_bytes(input: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        let unreserved =
            b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~';
        if unreserved {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0f) as usize]);
        }
    }
    out
}

/// The base64 alphabet shared by the encoder and decoder
/// (`curlx_base64encdec`, `lib/curlx/base64.c`).
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64-encodes `input` (standard alphabet, `=` padding) — the `b64`
/// function of `varfunc` (`curlx_base64_encode`, `lib/curlx/base64.c`).
fn base64_encode_bytes(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(BASE64_ALPHABET[((n >> 18) & 0x3f) as usize]);
        out.push(BASE64_ALPHABET[((n >> 12) & 0x3f) as usize]);
        out.push(if chunk.len() > 1 {
            BASE64_ALPHABET[((n >> 6) & 0x3f) as usize]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            BASE64_ALPHABET[(n & 0x3f) as usize]
        } else {
            b'='
        });
    }
    out
}

/// Base64-decodes `input` — the `64dec` function of `varfunc`
/// (`curlx_base64_decode`, `lib/curlx/base64.c`). Returns `None` (which
/// `varfunc` renders as the literal `[64dec-fail]`) on any of curl's failure
/// conditions: empty input, length not a multiple of 4, more than two `=`
/// padding characters, a misplaced `=`, or a non-alphabet byte.
fn base64_decode_bytes(input: &[u8]) -> Option<Vec<u8>> {
    let srclen = input.len();
    if srclen == 0 || srclen % 4 != 0 {
        return None;
    }

    let mut lookup = [0xffu8; 256];
    for (i, &c) in BASE64_ALPHABET.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    // Count trailing '=' padding (a maximum of two is permitted).
    let mut padding = 0usize;
    while input[srclen - 1 - padding] == b'=' {
        padding += 1;
        if padding > 2 {
            return None;
        }
    }

    let num_quantums = srclen / 4;
    let full_quantums = num_quantums - usize::from(padding > 0);
    let rawlen = num_quantums * 3 - padding;
    let mut out = Vec::with_capacity(rawlen);
    let mut idx = 0;

    // Decode the complete 4-char → 3-byte quantums.
    for _ in 0..full_quantums {
        let mut x: u32 = 0;
        for _ in 0..4 {
            let v = lookup[input[idx] as usize];
            if v == 0xff {
                return None;
            }
            x = (x << 6) | u32::from(v);
            idx += 1;
        }
        out.push(((x >> 16) & 0xff) as u8);
        out.push(((x >> 8) & 0xff) as u8);
        out.push((x & 0xff) as u8);
    }

    // The final padded quantum yields one or two bytes.
    if padding > 0 {
        let mut x: u32 = 0;
        let mut padc = 0usize;
        for _ in 0..4 {
            if input[idx] == b'=' {
                x <<= 6;
                idx += 1;
                padc += 1;
                if padc > padding {
                    return None;
                }
            } else {
                let v = lookup[input[idx] as usize];
                if v == 0xff {
                    return None;
                }
                x = (x << 6) | u32::from(v);
                idx += 1;
            }
        }
        out.push(((x >> 16) & 0xff) as u8);
        if padding == 1 {
            out.push(((x >> 8) & 0xff) as u8);
        }
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::ParameterError;

    /// Builds a `GlobalConfig` pre-populated with the given variables (bypassing
    /// `set_variable` so the expander can be tested in isolation).
    fn cfg_with(vars: &[(&str, &str)]) -> GlobalConfig {
        let mut g = GlobalConfig::new();
        for (n, c) in vars {
            g.variables.push(ToolVar {
                name: (*n).to_string(),
                content: (*c).as_bytes().to_vec(),
            });
        }
        g
    }

    // -- var_expand ---------------------------------------------------------

    #[test]
    fn expand_simple_and_affixes() {
        let g = cfg_with(&[("foo", "bar")]);
        assert_eq!(g.var_expand("{{foo}}").unwrap(), ("bar".to_string(), true));
        assert_eq!(
            g.var_expand("a{{foo}}b").unwrap(),
            ("abarb".to_string(), true)
        );
        assert_eq!(
            g.var_expand("pre {{foo}}").unwrap(),
            ("pre bar".to_string(), true)
        );
    }

    #[test]
    fn expand_no_substitution_returns_original() {
        let g = cfg_with(&[]);
        let (s, replaced) = g.var_expand("nothing here").unwrap();
        assert_eq!(s, "nothing here");
        assert!(!replaced);
    }

    #[test]
    fn expand_undefined_variable_is_empty_not_error() {
        // The C oracle expands an unset variable to empty with replaced = true.
        let g = cfg_with(&[]);
        assert_eq!(g.var_expand("{{undef}}").unwrap(), (String::new(), true));
        assert_eq!(
            g.var_expand("x{{undef}}y").unwrap(),
            ("xy".to_string(), true)
        );
    }

    #[test]
    fn expand_backslash_escape() {
        let g = cfg_with(&[("foo", "bar")]);
        // No real substitution: the original (with backslash) is kept.
        let (s, replaced) = g.var_expand("\\{{foo}}").unwrap();
        assert_eq!(s, "\\{{foo}}");
        assert!(!replaced);
        // With a real substitution elsewhere, the escape "wins" → literal "{{".
        let (s, replaced) = g.var_expand("\\{{x}} {{foo}}").unwrap();
        assert_eq!(s, "{{x}} bar");
        assert!(replaced);
    }

    #[test]
    fn expand_missing_close_keeps_original() {
        let g = cfg_with(&[("foo", "bar")]);
        let (s, replaced) = g.var_expand("{{foo}").unwrap();
        assert_eq!(s, "{{foo}");
        assert!(!replaced);
    }

    #[test]
    fn expand_bad_name_kept_verbatim() {
        let g = cfg_with(&[]);
        // Empty name.
        assert_eq!(g.var_expand("{{}}").unwrap(), ("{{}}".to_string(), false));
        // Invalid character (space) in the name.
        assert_eq!(
            g.var_expand("{{a b}}").unwrap(),
            ("{{a b}}".to_string(), false)
        );
    }

    #[test]
    fn expand_func_trim() {
        let g = cfg_with(&[("v", "  hi  ")]);
        assert_eq!(g.var_expand("{{v:trim}}").unwrap().0, "hi");
        // curl's ISSPACE includes the vertical tab (0x0b).
        let g = cfg_with(&[("v", "\x0bhi\x0b")]);
        assert_eq!(g.var_expand("{{v:trim}}").unwrap().0, "hi");
    }

    #[test]
    fn expand_func_json() {
        let g = cfg_with(&[("v", "a\"b\\c")]);
        assert_eq!(g.var_expand("{{v:json}}").unwrap().0, "a\\\"b\\\\c");
        let g = cfg_with(&[("v", "x\ny\tz")]);
        assert_eq!(g.var_expand("{{v:json}}").unwrap().0, "x\\ny\\tz");
    }

    #[test]
    fn expand_func_url() {
        let g = cfg_with(&[("v", "a b/c~-._Z9")]);
        assert_eq!(g.var_expand("{{v:url}}").unwrap().0, "a%20b%2Fc~-._Z9");
    }

    #[test]
    fn expand_func_b64_and_64dec() {
        let g = cfg_with(&[("v", "hello")]);
        assert_eq!(g.var_expand("{{v:b64}}").unwrap().0, "aGVsbG8=");
        let g = cfg_with(&[("v", "aGVsbG8=")]);
        assert_eq!(g.var_expand("{{v:64dec}}").unwrap().0, "hello");
        // Invalid base64 → literal "[64dec-fail]".
        let g = cfg_with(&[("v", "@@@@")]);
        assert_eq!(g.var_expand("{{v:64dec}}").unwrap().0, "[64dec-fail]");
    }

    #[test]
    fn expand_func_chained() {
        // b64 then 64dec round-trips the content.
        let g = cfg_with(&[("v", "world")]);
        assert_eq!(g.var_expand("{{v:b64:64dec}}").unwrap().0, "world");
        // trim then json.
        let g = cfg_with(&[("v", "  a\"b  ")]);
        assert_eq!(g.var_expand("{{v:trim:json}}").unwrap().0, "a\\\"b");
    }

    #[test]
    fn expand_unknown_function_is_error() {
        let g = cfg_with(&[("v", "x")]);
        assert!(matches!(
            g.var_expand("{{v:nope}}"),
            Err(ParameterError::ExpandError)
        ));
        // Empty function (trailing colon) is also an error, matching curl.
        assert!(matches!(
            g.var_expand("{{v:}}"),
            Err(ParameterError::ExpandError)
        ));
    }

    #[test]
    fn expand_null_byte_is_error() {
        let g = cfg_with(&[("v", "a\0b")]);
        assert!(matches!(
            g.var_expand("{{v}}"),
            Err(ParameterError::ExpandError)
        ));
    }

    // -- set_variable -------------------------------------------------------

    #[test]
    fn set_literal_and_last_wins() {
        let mut g = GlobalConfig::new();
        g.set_variable("x=hello").unwrap();
        assert_eq!(g.varcontent("x"), Some(b"hello".as_slice()));
        g.set_variable("y=").unwrap();
        assert_eq!(g.varcontent("y"), Some(b"".as_slice()));
        // Last definition wins; the store keeps a single entry per name.
        g.set_variable("x=world").unwrap();
        assert_eq!(g.varcontent("x"), Some(b"world".as_slice()));
        assert_eq!(g.variables.iter().filter(|v| v.name == "x").count(), 1);
    }

    #[test]
    fn set_bad_name_and_syntax_are_nonfatal() {
        let mut g = GlobalConfig::new();
        // Empty name → warning, no variable, but Ok.
        g.set_variable("=oops").unwrap();
        assert!(g.variables.is_empty());
        // No '='/'@' → bad syntax warning, Ok.
        g.set_variable("lonely").unwrap();
        assert!(g.variables.is_empty());
    }

    #[test]
    fn set_byte_range() {
        let mut g = GlobalConfig::new();
        g.set_variable("a[1-3]=hello").unwrap();
        assert_eq!(g.varcontent("a"), Some(b"ell".as_slice()));
        g.set_variable("b[2-]=hello").unwrap();
        assert_eq!(g.varcontent("b"), Some(b"llo".as_slice()));
        // Start past the end yields empty.
        g.set_variable("c[9-]=hi").unwrap();
        assert_eq!(g.varcontent("c"), Some(b"".as_slice()));
    }

    #[test]
    fn set_bad_range_is_var_syntax() {
        let mut g = GlobalConfig::new();
        assert!(matches!(
            g.set_variable("a[1-=y"),
            Err(ParameterError::VarSyntax)
        ));
        assert!(matches!(
            g.set_variable("a[5-2]=hello"),
            Err(ParameterError::VarSyntax)
        ));
    }

    #[test]
    fn set_env_import() {
        let key = "CURLRS_CFG_TEST_IMPORT_UNIQUE_4711";
        std::env::set_var(key, "fromenv");
        let mut g = GlobalConfig::new();
        g.set_variable(&format!("%{key}")).unwrap();
        assert_eq!(g.varcontent(key), Some(b"fromenv".as_slice()));
        std::env::remove_var(key);
    }

    #[test]
    fn set_env_import_missing_is_error() {
        let key = "CURLRS_CFG_TEST_MISSING_UNIQUE_9988";
        std::env::remove_var(key);
        let mut g = GlobalConfig::new();
        assert!(matches!(
            g.set_variable(&format!("%{key}")),
            Err(ParameterError::ExpandError)
        ));
    }

    #[test]
    fn set_env_import_fallback() {
        let key = "CURLRS_CFG_TEST_FALLBACK_UNIQUE_7766";
        std::env::remove_var(key);
        let mut g = GlobalConfig::new();
        // Unset variable with a trailing literal fallback uses the fallback.
        g.set_variable(&format!("%{key}=defaultval")).unwrap();
        assert_eq!(g.varcontent(key), Some(b"defaultval".as_slice()));
    }

    #[test]
    fn set_from_file_with_range() {
        let mut path = std::env::temp_dir();
        path.push(format!("curlrs_cfg_test_{}_file.bin", std::process::id()));
        fs::write(&path, b"hello").expect("write temp file");

        let mut g = GlobalConfig::new();
        g.set_variable(&format!("fv@{}", path.display())).unwrap();
        assert_eq!(g.varcontent("fv"), Some(b"hello".as_slice()));
        g.set_variable(&format!("fr[1-3]@{}", path.display()))
            .unwrap();
        assert_eq!(g.varcontent("fr"), Some(b"ell".as_slice()));

        let _ = fs::remove_file(&path);
    }

    /// `--variable name@file` with **non-UTF-8** file content must be stored
    /// byte-for-byte (the CP3 F6 fix). Before the fix the bytes were run through
    /// `String::from_utf8_lossy` at storage, replacing each invalid byte with
    /// U+FFFD and irreversibly corrupting the value — so even `{{v:b64}}` would
    /// encode the mangled bytes. This proves the raw bytes survive and that an
    /// encoder sees the originals.
    #[test]
    fn set_from_file_preserves_non_utf8_bytes() {
        // 0xFF, 0xFE, 0x80 are all invalid as standalone UTF-8; mixed with ASCII.
        let raw: &[u8] = &[0xFF, 0xFE, 0x80, b'A', 0x7F];
        let mut path = std::env::temp_dir();
        path.push(format!("curlrs_cfg_test_{}_binary.bin", std::process::id()));
        fs::write(&path, raw).expect("write temp file");

        let mut g = GlobalConfig::new();
        g.set_variable(&format!("bin@{}", path.display())).unwrap();

        // Storage is byte-exact — no U+FFFD substitution.
        assert_eq!(g.varcontent("bin"), Some(raw));

        // An encoder applied at expansion sees the original bytes: the base64 of
        // the value must equal the base64 of the raw input, not of a mangled
        // (lossy) version.
        let expected_b64 = String::from_utf8(base64_encode_bytes(raw)).unwrap();
        assert_eq!(g.var_expand("{{bin:b64}}").unwrap().0, expected_b64);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn set_from_missing_file_is_read_error() {
        let mut g = GlobalConfig::new();
        let missing = "/nonexistent/curlrs/definitely/not/here.bin";
        assert!(matches!(
            g.set_variable(&format!("x@{missing}")),
            Err(ParameterError::ReadError)
        ));
    }

    #[test]
    fn var_cleanup_clears_store() {
        let mut g = GlobalConfig::new();
        g.set_variable("x=1").unwrap();
        assert!(!g.variables.is_empty());
        g.var_cleanup();
        assert!(g.variables.is_empty());
    }

    // -- encoders (direct) --------------------------------------------------

    #[test]
    fn json_escape_low_controls() {
        assert_eq!(json_escape_bytes(b"\x01"), b"\\u0001");
        assert_eq!(json_escape_bytes(b"\x1f"), b"\\u001f");
        // Vertical tab is not one of the named escapes → \u000b.
        assert_eq!(json_escape_bytes(b"\x0b"), b"\\u000b");
        // Forward slash and high bytes pass through unchanged.
        assert_eq!(json_escape_bytes(b"/\x80"), b"/\x80");
    }

    #[test]
    fn url_escape_table() {
        assert_eq!(url_escape_bytes(b"-._~AZ09"), b"-._~AZ09");
        assert_eq!(url_escape_bytes(b" /?"), b"%20%2F%3F");
    }

    #[test]
    fn base64_roundtrip_and_failures() {
        for s in ["", "a", "ab", "abc", "hello world"] {
            let enc = base64_encode_bytes(s.as_bytes());
            let dec = base64_decode_bytes(&enc).map(|d| String::from_utf8_lossy(&d).into_owned());
            // The empty input encodes to empty, which fails the decoder's
            // non-empty precondition; every non-empty input round-trips.
            if s.is_empty() {
                assert!(enc.is_empty());
            } else {
                assert_eq!(dec.as_deref(), Some(s));
            }
        }
        assert_eq!(base64_encode_bytes(b"hello"), b"aGVsbG8=");
        // Bad length, bad symbol, and over-padding all fail.
        assert_eq!(base64_decode_bytes(b""), None);
        assert_eq!(base64_decode_bytes(b"abc"), None);
        assert_eq!(base64_decode_bytes(b"####"), None);
        assert_eq!(base64_decode_bytes(b"a==="), None);
    }

    #[test]
    fn str_number_and_single() {
        assert_eq!(str_number("123abc"), Some((123, "abc")));
        assert_eq!(str_number("x"), None);
        assert_eq!(str_single("-y", b'-'), Some("y"));
        assert_eq!(str_single("y", b'-'), None);
    }

    // -- defaults & accessors ----------------------------------------------

    #[test]
    fn operation_defaults_match_config_alloc() {
        let c = OperationConfig::new();
        assert_eq!(c.maxredirs, DEFAULT_MAXREDIRS);
        assert!(c.tcp_nodelay);
        assert_eq!(c.happy_eyeballs_timeout_ms, CURL_HET_DEFAULT);
        assert!(c.ftp_skip_ip);
        assert_eq!(c.upload_flags, CURLULFLAG_SEEN);
        assert_eq!(c.file_clobber_mode, FileClobberMode::Default);
    }

    #[test]
    fn global_defaults_match_globalconf_init() {
        let g = GlobalConfig::new();
        assert_eq!(g.operations.len(), 1);
        assert_eq!(g.current, 0);
        assert!(g.styled_output);
        assert_eq!(g.parallel_max, PARALLEL_DEFAULT);
        assert!(!g.showerror);
        assert!(!g.silent);
    }

    #[test]
    fn add_operation_advances_cursor() {
        let mut g = GlobalConfig::new();
        assert_eq!(g.operations.len(), 1);
        g.add_operation();
        assert_eq!(g.operations.len(), 2);
        assert_eq!(g.current, 1);
        // The current accessor tracks the freshly added block.
        g.current_mut().userpwd = Some("u:p".to_string());
        assert_eq!(g.current().userpwd.as_deref(), Some("u:p"));
    }
}
