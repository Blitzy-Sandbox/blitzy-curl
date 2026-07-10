// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_getparam.c, tool_paramhlp.c, tool_cfgable.c.

//! # `args` — command-line configuration model and argument parser
//!
//! This module is the foundational CLI layer of the `curl-rs` binary: a faithful,
//! idiomatic-Rust rewrite of curl 8.19.0-DEV's hand-rolled option parser
//! (`src/tool_getparam.c`), its parameter-validation helpers (`src/tool_paramhlp.c`),
//! and its configuration model (`src/tool_cfgable.c`). Every other CLI sub-module
//! (`setopt`, `operate`, `parsecfg`, `var`, `writeout`, `urlglob`, `formparse`, `ipfs`,
//! `filetime`, `xattr`, and the `callbacks/*` group) consumes the vocabulary defined here.
//!
//! ## Parity contract (AAP §0.7 — non-negotiable)
//!
//! The curl 8.x command-line surface is **frozen**. Long-names, short-letters, help
//! text, argument-taking behavior, `Multi:` semantics, and defaults match curl 8.x
//! exactly — no flag is invented, none is removed, and no default is altered. The
//! authoritative source for the flag surface is the `docs/cmdline-opts/*.md` catalog
//! (one page per option) cross-checked against the C `aliases[]` table; that catalog is
//! reproduced verbatim in [`OPTIONS`].
//!
//! ## Structure
//!
//! * ABI constants ([`curlabi`]) — the frozen `CURL*` integer values the parser assigns
//!   into the config (auth bitmasks, SSL-version ids, follow/timecond/ftp-method enums,
//!   proxy types, HTTP-version ids). Reproduced byte-exactly from `include/curl/curl.h`
//!   so downstream `setopt` translation and FFI error-code parity remain intact.
//! * [`ParameterError`] — the exact `ParameterError` code set from `tool_getparam.h`,
//!   with [`param_geterror`] returning curl's verbatim diagnostic text.
//! * The configuration model — [`OperationConfig`] (per-operation), [`State`]
//!   (per-URL iteration), and [`GlobalConfig`] (process-global), plus the supporting
//!   [`GetOut`], [`ToolMime`], and [`ToolVar`] types and the [`ClobberMode`],
//!   [`FailMode`], [`HttpReq`], [`TraceType`], and [`ProgressMode`] enums.
//! * Parameter validators — safe-Rust ports of the `tool_paramhlp.c` numeric/string
//!   parsers, each returning `Result<_, ParameterError>`.
//! * The option table [`OPTIONS`] plus [`getparameter`] / [`parse_args`] — the parser
//!   itself, preserving curl's `--no-`/`--expand-`/`=value`/bundled-short/`@file`
//!   semantics and the `--next` operation chain.
//! * [`build_cli_command`] — a `clap` v4 [`clap::Command`] built 1:1 from [`OPTIONS`],
//!   used for `--help`/`--manual` rendering and shell-completion generation.
//!
//! ## No `unsafe`
//!
//! Argument parsing is pure, safe Rust; this module contains no `unsafe` blocks
//! (AAP §0.7.2).
//!
//! ## Note on visibility
//!
//! `curl-rs` is a binary crate, so most of the public API surface defined here has no
//! consumer *within `main.rs` yet* — the operation-dispatch wiring that drives it is
//! layered on in a later checkpoint (AAP §0.7.3). The crate-level `#![allow(dead_code)]`
//! below reflects that: these items are the deliberate, stable vocabulary the sibling CLI
//! modules import by name, not accidental dead code.

#![allow(dead_code)]

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::Read;

// ===========================================================================
// ABI constants
// ===========================================================================

/// Frozen `CURL*` integer constants reproduced byte-exactly from `include/curl/curl.h`.
///
/// The argument parser assigns these values directly into [`OperationConfig`] fields
/// (`authtype`, `ssl_version`, `httpversion`, `timecond`, ...). They are re-declared
/// here — rather than imported from `curl-rs-lib` — because they are part of the frozen
/// libcurl ABI (AAP §0.6.1): a downstream consumer relying on, e.g.,
/// `CURLAUTH_NTLM == (1 << 3)` must keep working, and `setopt.rs` reproduces these exact
/// values when translating the config into `curl_easy_setopt` calls.
pub mod curlabi {
    // --- CURLAUTH_* : HTTP/proxy authentication method bitmask (curl.h) ---
    // Modeled as `u64` to match C `unsigned long` on the 64-bit target platforms.
    /// No authentication method.
    pub const CURLAUTH_NONE: u64 = 0;
    /// HTTP Basic authentication.
    pub const CURLAUTH_BASIC: u64 = 1 << 0;
    /// HTTP Digest authentication.
    pub const CURLAUTH_DIGEST: u64 = 1 << 1;
    /// HTTP Negotiate (SPNEGO) authentication.
    pub const CURLAUTH_NEGOTIATE: u64 = 1 << 2;
    /// Alias preserved from curl.h: `CURLAUTH_GSSNEGOTIATE == CURLAUTH_NEGOTIATE`.
    pub const CURLAUTH_GSSNEGOTIATE: u64 = CURLAUTH_NEGOTIATE;
    /// Alias preserved from curl.h: `CURLAUTH_GSSAPI == CURLAUTH_NEGOTIATE`.
    pub const CURLAUTH_GSSAPI: u64 = CURLAUTH_NEGOTIATE;
    /// HTTP NTLM authentication.
    pub const CURLAUTH_NTLM: u64 = 1 << 3;
    /// HTTP Digest with IE-flavor quirks.
    pub const CURLAUTH_DIGEST_IE: u64 = 1 << 4;
    /// NTLM delegated to a winbind helper (deprecated in curl 8.x).
    pub const CURLAUTH_NTLM_WB: u64 = 1 << 5;
    /// OAuth 2.0 Bearer-token authentication.
    pub const CURLAUTH_BEARER: u64 = 1 << 6;
    /// AWS Signature V4 request signing.
    pub const CURLAUTH_AWS_SIGV4: u64 = 1 << 7;
    /// "Only" flag: restrict to methods the server advertises support for.
    pub const CURLAUTH_ONLY: u64 = 1 << 31;
    /// Any method except IE-flavor Digest (curl.h: `~CURLAUTH_DIGEST_IE`, 32-bit mask).
    pub const CURLAUTH_ANY: u64 = (!CURLAUTH_DIGEST_IE) & 0xffff_ffff;
    /// Any "safe" method (excludes Basic and IE-flavor Digest), 32-bit mask.
    pub const CURLAUTH_ANYSAFE: u64 = (!(CURLAUTH_BASIC | CURLAUTH_DIGEST_IE)) & 0xffff_ffff;

    // --- CURL_SSLVERSION_* : minimum TLS version selector (curl.h) ---
    /// Let the TLS backend pick the default minimum version.
    pub const CURL_SSLVERSION_DEFAULT: i64 = 0;
    /// TLS 1.x (any).
    pub const CURL_SSLVERSION_TLSV1: i64 = 1;
    /// SSL v2 (obsolete; retained for id stability).
    pub const CURL_SSLVERSION_SSLV2: i64 = 2;
    /// SSL v3 (obsolete; retained for id stability).
    pub const CURL_SSLVERSION_SSLV3: i64 = 3;
    /// TLS 1.0.
    pub const CURL_SSLVERSION_TLSV1_0: i64 = 4;
    /// TLS 1.1.
    pub const CURL_SSLVERSION_TLSV1_1: i64 = 5;
    /// TLS 1.2.
    pub const CURL_SSLVERSION_TLSV1_2: i64 = 6;
    /// TLS 1.3.
    pub const CURL_SSLVERSION_TLSV1_3: i64 = 7;
    /// One past the last valid version id (never used as a value).
    pub const CURL_SSLVERSION_LAST: i64 = 8;

    // --- CURLFOLLOW_* : redirect-following mode (curl.h) ---
    /// Follow all redirects (generic `--location`).
    pub const CURLFOLLOW_ALL: i64 = 1;
    /// Follow but obey RFC method-change codes (`--location` internal default).
    pub const CURLFOLLOW_OBEYCODE: i64 = 2;
    /// Follow only the first redirect.
    pub const CURLFOLLOW_FIRSTONLY: i64 = 3;

    // --- CURLGSSAPI_DELEGATION_* : Kerberos credential delegation (curl.h) ---
    /// No delegation (default).
    pub const CURLGSSAPI_DELEGATION_NONE: i64 = 0;
    /// Delegate if permitted by KDC policy.
    pub const CURLGSSAPI_DELEGATION_POLICY_FLAG: i64 = 1 << 0;
    /// Always delegate.
    pub const CURLGSSAPI_DELEGATION_FLAG: i64 = 1 << 1;

    // --- CURLFTPSSL_CCC_* : FTP "clear command channel" mode (curl.h) ---
    /// Do not send CCC.
    pub const CURLFTPSSL_CCC_NONE: i64 = 0;
    /// Let the server initiate the TLS shutdown.
    pub const CURLFTPSSL_CCC_PASSIVE: i64 = 1;
    /// Initiate the TLS shutdown ourselves.
    pub const CURLFTPSSL_CCC_ACTIVE: i64 = 2;

    // --- CURLFTPMETHOD_* : FTP directory-traversal method (curl.h) ---
    /// Let libcurl pick.
    pub const CURLFTPMETHOD_DEFAULT: i64 = 0;
    /// One CWD per path component.
    pub const CURLFTPMETHOD_MULTICWD: i64 = 1;
    /// No CWD at all.
    pub const CURLFTPMETHOD_NOCWD: i64 = 2;
    /// One CWD to the full directory, then operate on the file.
    pub const CURLFTPMETHOD_SINGLECWD: i64 = 3;

    // --- CURLULFLAG_* : upload flags for IMAP APPEND (curl.h) ---
    /// Mark the appended message `\Answered`.
    pub const CURLULFLAG_ANSWERED: u64 = 1 << 0;
    /// Mark the appended message `\Deleted`.
    pub const CURLULFLAG_DELETED: u64 = 1 << 1;
    /// Mark the appended message `\Draft`.
    pub const CURLULFLAG_DRAFT: u64 = 1 << 2;
    /// Mark the appended message `\Flagged`.
    pub const CURLULFLAG_FLAGGED: u64 = 1 << 3;
    /// Mark the appended message `\Seen` (curl's `config_alloc` default).
    pub const CURLULFLAG_SEEN: u64 = 1 << 4;

    // --- CURL_IPRESOLVE_* : address-family preference (curl.h) ---
    /// Use whatever address family resolves.
    pub const CURL_IPRESOLVE_WHATEVER: i64 = 0;
    /// IPv4 only (`-4`).
    pub const CURL_IPRESOLVE_V4: i64 = 1;
    /// IPv6 only (`-6`).
    pub const CURL_IPRESOLVE_V6: i64 = 2;

    // --- CURL_HTTP_VERSION_* : requested HTTP version (curl.h) ---
    /// No preference.
    pub const CURL_HTTP_VERSION_NONE: i64 = 0;
    /// HTTP/1.0.
    pub const CURL_HTTP_VERSION_1_0: i64 = 1;
    /// HTTP/1.1.
    pub const CURL_HTTP_VERSION_1_1: i64 = 2;
    /// HTTP/2.
    pub const CURL_HTTP_VERSION_2_0: i64 = 3;
    /// HTTP/2 for HTTPS, HTTP/1.1 for HTTP.
    pub const CURL_HTTP_VERSION_2TLS: i64 = 4;
    /// HTTP/2 over cleartext with prior knowledge.
    pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: i64 = 5;
    /// HTTP/3 with fallback.
    pub const CURL_HTTP_VERSION_3: i64 = 30;
    /// HTTP/3 only (no fallback).
    pub const CURL_HTTP_VERSION_3ONLY: i64 = 31;

    // --- CURLPROXY_* : proxy type (curl.h) ---
    /// HTTP proxy (default).
    pub const CURLPROXY_HTTP: i64 = 0;
    /// HTTP proxy forced to CONNECT via HTTP/1.0.
    pub const CURLPROXY_HTTP_1_0: i64 = 1;
    /// HTTPS proxy, HTTP/1 only.
    pub const CURLPROXY_HTTPS: i64 = 2;
    /// HTTPS proxy, attempt HTTP/2.
    pub const CURLPROXY_HTTPS2: i64 = 3;
    /// SOCKS4 proxy.
    pub const CURLPROXY_SOCKS4: i64 = 4;
    /// SOCKS5 proxy.
    pub const CURLPROXY_SOCKS5: i64 = 5;
    /// SOCKS4a proxy (proxy resolves the hostname).
    pub const CURLPROXY_SOCKS4A: i64 = 6;
    /// SOCKS5 proxy (proxy resolves the hostname).
    pub const CURLPROXY_SOCKS5_HOSTNAME: i64 = 7;

    // --- CURL_TIMECOND_* : time-condition selector (curl.h) ---
    /// No time condition.
    pub const CURL_TIMECOND_NONE: i64 = 0;
    /// Transfer only if modified since the given time.
    pub const CURL_TIMECOND_IFMODSINCE: i64 = 1;
    /// Transfer only if *not* modified since the given time.
    pub const CURL_TIMECOND_IFUNMODSINCE: i64 = 2;
    /// Set the local file's mtime from `Last-Modified`.
    pub const CURL_TIMECOND_LASTMOD: i64 = 3;

    // --- CURLMIMEOPT_* : MIME/form options bitmask (curl.h) ---
    /// Use backslash-escaping for multipart form field names.
    pub const CURLMIMEOPT_FORMESCAPE: u64 = 1 << 0;
}

// ===========================================================================
// Tool-level constants (from src/tool_*.h)
// ===========================================================================

/// Maximum config-file recursion depth (`CONFIG_MAX_LEVELS`, `tool_parsecfg.h`).
pub const CONFIG_MAX_LEVELS: i32 = 5;

/// Longest long-option name excluding the leading `--` (`MAX_OPTION_LEN`, tool_getparam.c).
pub const MAX_OPTION_LEN: usize = 26;

/// Default per-transfer parallel connection cap (`PARALLEL_DEFAULT`, tool_operate.h).
pub const PARALLEL_DEFAULT: i64 = 50;

/// Default per-host parallel cap — `0` means "no per-host limit" (`PARALLEL_HOST_DEFAULT`).
pub const PARALLEL_HOST_DEFAULT: i64 = 0;

/// Absolute ceiling for `--parallel-max` (`MAX_PARALLEL`, tool_operate.h).
pub const MAX_PARALLEL: i64 = 65_535;

/// Absolute ceiling for `--parallel-max-host` (`MAX_PARALLEL_HOST`, tool_operate.h).
pub const MAX_PARALLEL_HOST: i64 = 65_535;

/// Default `--max-redirs` value set by curl's `config_alloc` (`DEFAULT_MAXREDIRS`).
pub const DEFAULT_MAXREDIRS: i64 = 50;

/// Default Happy-Eyeballs timeout in ms set by `config_alloc` (`CURL_HET_DEFAULT`).
pub const CURL_HET_DEFAULT: i64 = 200;

/// Upper bound (in bytes) for `@file` / `--data` style in-memory file reads
/// (`MAX_FILE2MEMORY`): 16 GiB, matching curl's dynbuf cap on the 64-bit targets.
pub const MAX_FILE2MEMORY: u64 = 16 * 1024 * 1024 * 1024;

/// `getstr` policy flag: permit an empty (blank) argument value.
pub const ALLOW_BLANK: bool = true;
/// `getstr` policy flag: reject an empty (blank) argument value with
/// [`ParameterError::BlankString`].
pub const DENY_BLANK: bool = false;

// --- ARG_* : the `LongShort.desc` type/flag bitmask (tool_getparam.h) ---

/// `ARG_NONE`: a stand-alone option that is not a boolean (takes no argument, no `--no-`).
pub const ARG_NONE: u8 = 0;
/// `ARG_BOOL`: a boolean option (accepts a `--no-<name>` prefix).
pub const ARG_BOOL: u8 = 1;
/// `ARG_STRG`: requires an argument (an arbitrary string).
pub const ARG_STRG: u8 = 2;
/// `ARG_FILE`: requires an argument, usually a filename.
pub const ARG_FILE: u8 = 3;
/// Mask selecting the [`ARG_NONE`]/[`ARG_BOOL`]/[`ARG_STRG`]/[`ARG_FILE`] type bits.
pub const ARG_TYPEMASK: u8 = 0x03;
/// `ARG_DEPR`: the option is deprecated (accepted but hidden from `--help`; warns).
pub const ARG_DEPR: u8 = 0x10;
/// `ARG_CLEAR`: scrub the argument text after use (secrets such as passwords).
pub const ARG_CLEAR: u8 = 0x20;
/// `ARG_TLS`: the option requires TLS support in the underlying library.
pub const ARG_TLS: u8 = 0x40;
/// `ARG_NO`: the option is documented in its `--no-<name>` form.
pub const ARG_NO: u8 = 0x80;

// ===========================================================================
// Option-table value kinds
// ===========================================================================

/// The argument-taking kind of an option, i.e. `ARGTYPE(LongShort.desc)`
/// (`tool_getparam.h`). Determines whether the parser consumes a following argument
/// and how a bare short letter behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgType {
    /// `ARG_NONE` — stand-alone, non-boolean, takes no argument (e.g. `--next`).
    None_,
    /// `ARG_BOOL` — boolean toggle; accepts a `--no-<name>` prefix.
    Bool,
    /// `ARG_STRG` — requires an argument (an arbitrary string).
    Strg,
    /// `ARG_FILE` — requires an argument, conventionally a filename.
    File,
}

impl ArgType {
    /// True when the option requires a following value (`ARGTYPE(desc) >= ARG_STRG`).
    #[inline]
    pub fn takes_arg(self) -> bool {
        matches!(self, ArgType::Strg | ArgType::File)
    }
}

/// The `Multi:` behavior of an option, mirroring the `docs/cmdline-opts` front-matter
/// key of the same name. Governs how repeated occurrences combine and whether the
/// option participates in a `--no-` negation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Multi {
    /// `Multi: boolean` — on/off toggle, also reachable via `--no-<name>`.
    Boolean,
    /// `Multi: single` — last occurrence wins.
    Single,
    /// `Multi: append` — each occurrence is accumulated.
    Append,
    /// `Multi: mutex` — mutually exclusive with its siblings (last wins).
    Mutex,
    /// `Multi: per-URL` — applies to the current operation and resets across `--next`.
    PerUrl,
    /// `Multi: custom` — bespoke handling (e.g. `--help`, `--version`, `--manual`).
    Custom,
}

// ===========================================================================
// ParameterError — the parse-result code set (tool_getparam.h)
// ===========================================================================

/// The result code returned by [`getparameter`] / [`parse_args`], reproduced with the
/// exact variant order of curl's `ParameterError` enum (`tool_getparam.h`), with
/// [`ParameterError::Ok`] first (value `0`) and [`ParameterError::Last`] last.
///
/// Discriminants are assigned implicitly `0, 1, 2, …` — identical to the C enum — so a
/// numeric comparison or `as i32` cast yields the same integer curl uses.
///
/// # Flow-control variants
///
/// Five `*Requested` variants together with [`ParameterError::NextOperation`] are **not
/// hard errors**: they are control-flow signals consumed by `operate.rs` / `main.rs`.
/// [`ParameterError::HelpRequested`], [`ParameterError::ManualRequested`],
/// [`ParameterError::VersionInfoRequested`], [`ParameterError::EnginesRequested`], and
/// [`ParameterError::CaEmbedRequested`] each trigger an informational output followed by
/// a clean exit, while [`ParameterError::NextOperation`] advances the parser to a fresh
/// [`OperationConfig`] in the `--next` chain. [`param_geterror`] deliberately does not
/// print a diagnostic for these (it returns the generic text), matching `parse_args`,
/// which suppresses the `helpf` message for exactly this set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterError {
    /// `PARAM_OK` — success.
    Ok,
    /// `PARAM_OPTION_UNKNOWN` — the option is not recognized.
    OptionUnknown,
    /// `PARAM_CONFIG_OPTION_UNKNOWN` — an unknown option inside a config file.
    ConfigOptionUnknown,
    /// `PARAM_REQUIRES_PARAMETER` — the option needs an argument that was not supplied.
    RequiresParameter,
    /// `PARAM_BAD_USE` — the option was used incorrectly.
    BadUse,
    /// `PARAM_HELP_REQUESTED` — `--help` (flow-control, not an error).
    HelpRequested,
    /// `PARAM_MANUAL_REQUESTED` — `--manual` (flow-control, not an error).
    ManualRequested,
    /// `PARAM_VERSION_INFO_REQUESTED` — `--version` (flow-control, not an error).
    VersionInfoRequested,
    /// `PARAM_ENGINES_REQUESTED` — `--engine list` (flow-control, not an error).
    EnginesRequested,
    /// `PARAM_CA_EMBED_REQUESTED` — `--dump-ca-embed` (flow-control, not an error).
    CaEmbedRequested,
    /// `PARAM_GOT_EXTRA_PARAMETER` — unsupported trailing garbage on the option.
    GotExtraParameter,
    /// `PARAM_BAD_NUMERIC` — a numeric argument failed to parse.
    BadNumeric,
    /// `PARAM_NEGATIVE_NUMERIC` — a numeric argument was negative where non-negative
    /// was required.
    NegativeNumeric,
    /// `PARAM_LIBCURL_DOESNT_SUPPORT` — the feature is not compiled into the library.
    LibcurlDoesntSupport,
    /// `PARAM_LIBCURL_UNSUPPORTED_PROTOCOL` — a named protocol is unsupported.
    LibcurlUnsupportedProtocol,
    /// `PARAM_NO_MEM` — out of memory.
    NoMem,
    /// `PARAM_NEXT_OPERATION` — `--next` (flow-control, not an error).
    NextOperation,
    /// `PARAM_NO_PREFIX` — a `--no-` prefix applied to a non-boolean option.
    NoPrefix,
    /// `PARAM_NUMBER_TOO_LARGE` — a numeric argument exceeded its permitted maximum.
    NumberTooLarge,
    /// `PARAM_CONTDISP_RESUME_FROM` — `--continue-at` combined with `--remote-header-name`.
    ContdispResumeFrom,
    /// `PARAM_READ_ERROR` — an error occurred reading a file argument.
    ReadError,
    /// `PARAM_EXPAND_ERROR` — a `--expand-` variable expansion failed.
    ExpandError,
    /// `PARAM_BLANK_STRING` — a blank argument was given where content is required.
    BlankString,
    /// `PARAM_VAR_SYNTAX` — a syntax error in a `--variable` argument.
    VarSyntax,
    /// `PARAM_RECURSION` — config-file inclusion nested deeper than [`CONFIG_MAX_LEVELS`].
    Recursion,
    /// `PARAM_LAST` — sentinel; never returned as a real result.
    Last,
}

impl ParameterError {
    /// True for the six control-flow signals that `parse_args` must not report as errors
    /// (`--help`, `--manual`, `--version`, `--engine list`, `--dump-ca-embed`, `--next`).
    #[inline]
    pub fn is_flow_control(self) -> bool {
        matches!(
            self,
            ParameterError::HelpRequested
                | ParameterError::ManualRequested
                | ParameterError::VersionInfoRequested
                | ParameterError::EnginesRequested
                | ParameterError::CaEmbedRequested
                | ParameterError::NextOperation
        )
    }
}

/// Human-readable diagnostic text for a [`ParameterError`], reproduced verbatim from
/// curl's `param2text` (`tool_helpers.c`). Used by the `helpf`/`errorf` diagnostics in
/// [`parse_args`]. Codes without dedicated text — including [`ParameterError::Ok`] and
/// the flow-control signals — return the generic `"unknown error"`, exactly as the C
/// switch's `default` arm does.
pub fn param_geterror(error: ParameterError) -> &'static str {
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
        // PARAM_OK, the *_REQUESTED flow-control signals, NEXT_OPERATION, RECURSION and
        // LAST have no dedicated text in curl's param2text; they map to the default.
        _ => "unknown error",
    }
}

impl fmt::Display for ParameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(param_geterror(*self))
    }
}

impl std::error::Error for ParameterError {}

// ===========================================================================
// Configuration enums (tool_cfgable.h / tool_sdecls.h)
// ===========================================================================

/// Output-file clobber policy (`file_clobber_mode`, tool_cfgable.h), selected by
/// `--clobber` / `--no-clobber`. [`ClobberMode::Default`] is curl's `config_alloc`
/// default and lets `--continue-at`/`--remote-header-name` decide overwrite behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClobberMode {
    /// `CLOBBER_DEFAULT` — legacy behavior (overwrite unless a resume/header-name rule
    /// applies).
    #[default]
    Default,
    /// `CLOBBER_NEVER` — never overwrite an existing output file (`--no-clobber`).
    Never,
    /// `CLOBBER_ALWAYS` — always overwrite (`--clobber`).
    Always,
}

/// `--fail` / `--fail-with-body` mode (`fail`, tool_cfgable.h; `FAIL_*` in the C source).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailMode {
    /// `FAIL_NONE` — do not fail on HTTP error status.
    #[default]
    None,
    /// `FAIL_WITH_BODY` — fail on error status but still emit the body (`--fail-with-body`).
    WithBody,
    /// `FAIL_WO_BODY` — fail on error status and suppress the body (`--fail`).
    WoBody,
}

/// The kind of HTTP request the CLI has been steered toward (`HttpReq httpreq`,
/// tool_sdecls.h `enum` `TOOL_HTTPREQ_*`). Used to detect conflicting request-shaping
/// options (e.g. `-d` after `-I`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpReq {
    /// `TOOL_HTTPREQ_UNSPEC` — no explicit request kind chosen yet.
    #[default]
    Unspec,
    /// `TOOL_HTTPREQ_GET` — `-G` / default GET.
    Get,
    /// `TOOL_HTTPREQ_HEAD` — `-I` (HEAD).
    Head,
    /// `TOOL_HTTPREQ_MIMEPOST` — `-F` multipart POST.
    Mimepost,
    /// `TOOL_HTTPREQ_SIMPLEPOST` — `-d` / `--data*` POST.
    Simplepost,
    /// `TOOL_HTTPREQ_PUT` — `-T` upload (PUT).
    Put,
}

/// The verbosity/format of `--trace`/`--trace-ascii` output (`enum trace`, tool_sdecls.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TraceType {
    /// `TRACE_NONE` — no protocol trace.
    #[default]
    None,
    /// `TRACE_BIN` — `--trace` (full binary/hex dump).
    Bin,
    /// `TRACE_ASCII` — `--trace-ascii` (ASCII-only dump).
    Ascii,
    /// `TRACE_PLAIN` — `-v` verbose (plain, no hex).
    Plain,
}

/// Progress-output style (`progressmode`, tool_cfgable.h). The discriminants mirror
/// curl's `CURL_PROGRESS_STATS == 0` (default) and `CURL_PROGRESS_BAR == 1` so any
/// integer comparison stays faithful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProgressMode {
    /// `CURL_PROGRESS_STATS` — the classic multi-column stats meter (default).
    #[default]
    Stats = 0,
    /// `CURL_PROGRESS_BAR` — the single-line progress bar (`-#` / `--progress-bar`).
    Bar = 1,
}

// ===========================================================================
// GetOut — a single URL "get-out" node (struct getout, tool_sdecls.h)
// ===========================================================================

/// One entry of curl's per-operation URL/output/upload list (`struct getout`).
///
/// curl threads these as an intrusive singly linked list (`config->url_list`); here they
/// are owned elements of a `Vec<GetOut>` (see [`OperationConfig::url_list`]). Every C
/// `BIT()` flag is preserved as a named `bool` — downstream (`operate.rs`, `urlglob.rs`)
/// reads them by name (`node.useremote`, `node.noglob`, ...).
#[derive(Debug, Clone, Default)]
pub struct GetOut {
    /// The URL this node deals with (C `url`).
    pub url: Option<String>,
    /// Where to store the output (C `outfile`); `-o`/`-O` target.
    pub outfile: Option<String>,
    /// File to upload when [`GetOut::uploadset`] is true (C `infile`); `-T` source.
    pub infile: Option<String>,
    /// Ordinal of this URL within the invocation (C `num`, `curl_off_t`).
    pub num: i64,
    /// `outset` — an output file has been set (C `BIT(outset)`).
    pub outset: bool,
    /// `urlset` — a URL has been set (C `BIT(urlset)`).
    pub urlset: bool,
    /// `uploadset` — `-T` was given (C `BIT(uploadset)`).
    pub uploadset: bool,
    /// `useremote` — derive the local filename from the remote name (C `BIT(useremote)`).
    pub useremote: bool,
    /// `noupload` — `-T ""` was used, i.e. explicitly no upload (C `BIT(noupload)`).
    pub noupload: bool,
    /// `noglob` — disable URL globbing for this URL (C `BIT(noglob)`).
    pub noglob: bool,
    /// `out_null` — discard output for this URL (C `BIT(out_null)`).
    pub out_null: bool,
}

// ===========================================================================
// ToolMime — the CLI-side `-F`/`--form` MIME tree (struct tool_mime)
// ===========================================================================

/// The kind of a [`ToolMime`] node (`toolmimekind`, tool_formparse.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ToolMimeKind {
    /// `TOOLMIME_NONE`.
    #[default]
    None,
    /// `TOOLMIME_PARTS` — an interior node holding [`ToolMime::subparts`].
    Parts,
    /// `TOOLMIME_DATA` — inline literal data.
    Data,
    /// `TOOLMIME_FILE` — a file attachment read from `data` as a path.
    File,
    /// `TOOLMIME_FILEDATA` — file contents inlined as data.
    FileData,
    /// `TOOLMIME_STDIN` — a stdin-sourced file part.
    Stdin,
    /// `TOOLMIME_STDINDATA` — stdin contents inlined as data.
    StdinData,
}

/// The CLI's `-F`/`--form` MIME tree node (`struct tool_mime`).
///
/// Per AAP §0.2 the CLI is permitted to model the form tree with a CLI-side builder that
/// later feeds `curl-rs-lib`'s MIME model; this is that builder representation. The C
/// intrusive `parent`/`prev` links are replaced by ownership: children live in
/// [`ToolMime::subparts`], so a node is fully self-describing without back-pointers.
/// `formparse.rs` populates the tree; `setopt.rs`/the library translate it into the wire
/// multipart body.
#[derive(Debug, Clone, Default)]
pub struct ToolMime {
    /// Part kind (C `kind`).
    pub kind: ToolMimeKind,
    /// Actual data, or the data filename depending on [`ToolMime::kind`] (C `data`).
    pub data: Option<String>,
    /// Part name (C `name`).
    pub name: Option<String>,
    /// Part filename (C `filename`).
    pub filename: Option<String>,
    /// Part MIME type (C `type`; renamed to avoid the Rust `type` keyword).
    pub mime_type: Option<String>,
    /// Requested content-transfer encoding (C `encoder`).
    pub encoder: Option<String>,
    /// User-defined part headers (C `headers`, a `curl_slist`).
    pub headers: Vec<String>,
    /// Child parts for a [`ToolMimeKind::Parts`] node (C `subparts`, owned here).
    pub subparts: Vec<ToolMime>,
    /// Stdin read origin offset (C `origin`, `curl_off_t`).
    pub origin: i64,
    /// Stdin data size (C `size`, `curl_off_t`).
    pub size: i64,
    /// Stdin current read position (C `curpos`, `curl_off_t`).
    pub curpos: i64,
}

// ===========================================================================
// ToolVar — a single `--variable` entry (struct tool_var, var.h)
// ===========================================================================

/// One `--variable` store entry (`struct tool_var`).
///
/// curl stores these in an intrusive list off `GlobalConfig`; here they are owned
/// elements of a `Vec<ToolVar>` (see [`GlobalConfig::variables`]). The C `clen` field is
/// implicit in `content.len()`. `var.rs` owns the higher-level `--variable`/`--expand-`
/// semantics; [`GlobalConfig`] merely holds the store.
#[derive(Debug, Clone, Default)]
pub struct ToolVar {
    /// The variable name (C flexible-array `name`).
    pub name: String,
    /// The variable content; `None` distinguishes an unset variable from an empty one
    /// (C `content` pointer, with `clen` == `content.len()` when set).
    pub content: Option<String>,
}

// ===========================================================================
// OperationConfig — the per-operation configuration (struct OperationConfig)
// ===========================================================================

/// Per-operation CLI configuration — an idiomatic-Rust port of curl's
/// `struct OperationConfig` (`tool_cfgable.h`), the giant record mutated by
/// [`getparameter`]. One instance exists per operation in the `--next` chain (owned by
/// [`GlobalConfig::operations`]).
///
/// Field intent is preserved 1:1 with the C struct: C `char *` become `Option<String>`,
/// `curl_slist *` become `Vec<String>`, `curl_off_t`/`long` become `i64`, `unsigned long`
/// bitmasks become `u64`, and each `BIT()` flag becomes a named `bool`. The intrusive
/// `prev`/`next` links are intentionally NOT reproduced — the chain is an owning `Vec` in
/// [`GlobalConfig`] (AAP §0.3.1: "model as … an owning `Vec<OperationConfig>` … do NOT use
/// raw pointers"). Construct with [`OperationConfig::new`] (the `config_alloc` equivalent),
/// which applies curl's non-zero defaults; the derived [`Default`] yields the all-zero base
/// used internally by `new`.
#[derive(Debug, Default, Clone)]
pub struct OperationConfig {
    // --- request body accumulator ---
    /// `-d`/`--data*` request-body accumulator (C `postdata` dynbuf), capped at
    /// [`MAX_FILE2MEMORY`]. Bytes are appended (with `&` separators) as data options are
    /// parsed.
    pub postdata: Vec<u8>,
    /// Textual view of the POST body (C `postfields`); mirrors [`OperationConfig::postdata`]
    /// for the simple `application/x-www-form-urlencoded` case.
    pub postfields: Option<String>,

    // --- string options ---
    /// `-A`/`--user-agent` (C `useragent`).
    pub useragent: Option<String>,
    /// `-c`/`--cookie-jar` write target (C `cookiejar`).
    pub cookiejar: Option<String>,
    /// `--alt-svc` cache filename (C `altsvc`).
    pub altsvc: Option<String>,
    /// `--hsts` cache filename (C `hsts`).
    pub hsts: Option<String>,
    /// `--proto` protocol string (C `proto_str`).
    pub proto_str: Option<String>,
    /// `--proto-redir` protocol string (C `proto_redir_str`).
    pub proto_redir_str: Option<String>,
    /// `--proto-default` (C `proto_default`).
    pub proto_default: Option<String>,
    /// `-e`/`--referer` (C `referer`).
    pub referer: Option<String>,
    /// `--url-query` accumulator (C `query`).
    pub query: Option<String>,
    /// `--output-dir` (C `output_dir`).
    pub output_dir: Option<String>,
    /// `-D`/`--dump-header` target (C `headerfile`).
    pub headerfile: Option<String>,
    /// `-P`/`--ftp-port` (C `ftpport`).
    pub ftpport: Option<String>,
    /// `--interface` (C `iface`).
    pub iface: Option<String>,
    /// `-r`/`--range` (C `range`).
    pub range: Option<String>,
    /// `--dns-servers` (C `dns_servers`).
    pub dns_servers: Option<String>,
    /// `--dns-interface` (C `dns_interface`).
    pub dns_interface: Option<String>,
    /// `--dns-ipv4-addr` (C `dns_ipv4_addr`).
    pub dns_ipv4_addr: Option<String>,
    /// `--dns-ipv6-addr` (C `dns_ipv6_addr`).
    pub dns_ipv6_addr: Option<String>,
    /// `-u`/`--user` (C `userpwd`).
    pub userpwd: Option<String>,
    /// `--login-options` (C `login_options`).
    pub login_options: Option<String>,
    /// `--tlsuser` (C `tls_username`).
    pub tls_username: Option<String>,
    /// `--tlspassword` (C `tls_password`).
    pub tls_password: Option<String>,
    /// `--tlsauthtype` (C `tls_authtype`).
    pub tls_authtype: Option<String>,
    /// `--proxy-tlsuser` (C `proxy_tls_username`).
    pub proxy_tls_username: Option<String>,
    /// `--proxy-tlspassword` (C `proxy_tls_password`).
    pub proxy_tls_password: Option<String>,
    /// `--proxy-tlsauthtype` (C `proxy_tls_authtype`).
    pub proxy_tls_authtype: Option<String>,
    /// `-U`/`--proxy-user` (C `proxyuserpwd`).
    pub proxyuserpwd: Option<String>,
    /// `-x`/`--proxy` (C `proxy`).
    pub proxy: Option<String>,
    /// `--noproxy` (C `noproxy`).
    pub noproxy: Option<String>,
    /// `--pubkey`/known-hosts file (C `knownhosts`).
    pub knownhosts: Option<String>,
    /// `--mail-from` (C `mail_from`).
    pub mail_from: Option<String>,
    /// `--mail-auth` (C `mail_auth`).
    pub mail_auth: Option<String>,
    /// `--sasl-authzid` (C `sasl_authzid`).
    pub sasl_authzid: Option<String>,
    /// `--netrc-file` (C `netrc_file`).
    pub netrc_file: Option<String>,
    /// IPFS/IPNS gateway (`--ipfs-gateway`, C `ipfs_gateway`); gated on the `ipfs` feature
    /// mirroring curl's `#ifndef CURL_DISABLE_IPFS`.
    #[cfg(feature = "ipfs")]
    pub ipfs_gateway: Option<String>,
    /// `--doh-url` (C `doh_url`).
    pub doh_url: Option<String>,
    /// `--ciphers` (C `cipher_list`).
    pub cipher_list: Option<String>,
    /// `--proxy-ciphers` (C `proxy_cipher_list`).
    pub proxy_cipher_list: Option<String>,
    /// `--tls13-ciphers` (C `cipher13_list`).
    pub cipher13_list: Option<String>,
    /// `--proxy-tls13-ciphers` (C `proxy_cipher13_list`).
    pub proxy_cipher13_list: Option<String>,
    /// `-E`/`--cert` (C `cert`).
    pub cert: Option<String>,
    /// `--proxy-cert` (C `proxy_cert`).
    pub proxy_cert: Option<String>,
    /// `--cert-type` (C `cert_type`).
    pub cert_type: Option<String>,
    /// `--proxy-cert-type` (C `proxy_cert_type`).
    pub proxy_cert_type: Option<String>,
    /// `--cacert` (C `cacert`).
    pub cacert: Option<String>,
    /// `--proxy-cacert` (C `proxy_cacert`).
    pub proxy_cacert: Option<String>,
    /// `--capath` (C `capath`).
    pub capath: Option<String>,
    /// `--proxy-capath` (C `proxy_capath`).
    pub proxy_capath: Option<String>,
    /// `--crlfile` (C `crlfile`).
    pub crlfile: Option<String>,
    /// `--proxy-crlfile` (C `proxy_crlfile`).
    pub proxy_crlfile: Option<String>,
    /// `--pinnedpubkey` (C `pinnedpubkey`).
    pub pinnedpubkey: Option<String>,
    /// `--proxy-pinnedpubkey` (C `proxy_pinnedpubkey`).
    pub proxy_pinnedpubkey: Option<String>,
    /// `--key` (C `key`).
    pub key: Option<String>,
    /// `--proxy-key` (C `proxy_key`).
    pub proxy_key: Option<String>,
    /// `--key-type` (C `key_type`).
    pub key_type: Option<String>,
    /// `--proxy-key-type` (C `proxy_key_type`).
    pub proxy_key_type: Option<String>,
    /// `--pass` private-key passphrase (C `key_passwd`).
    pub key_passwd: Option<String>,
    /// `--proxy-pass` (C `proxy_key_passwd`).
    pub proxy_key_passwd: Option<String>,
    /// `--pubkey` SSH public key (C `pubkey`).
    pub pubkey: Option<String>,
    /// `--hostpubmd5` (C `hostpubmd5`).
    pub hostpubmd5: Option<String>,
    /// `--hostpubsha256` (C `hostpubsha256`).
    pub hostpubsha256: Option<String>,
    /// `--engine` (C `engine`).
    pub engine: Option<String>,
    /// `--etag-save` target (C `etag_save_file`).
    pub etag_save_file: Option<String>,
    /// `--etag-compare` source (C `etag_compare_file`).
    pub etag_compare_file: Option<String>,
    /// `-X`/`--request` custom method (C `customrequest`).
    pub customrequest: Option<String>,
    /// `--curves` (C `ssl_ec_curves`).
    pub ssl_ec_curves: Option<String>,
    /// `--sigalgs` (C `ssl_signature_algorithms`).
    pub ssl_signature_algorithms: Option<String>,
    /// `--krb` level (C `krblevel`).
    pub krblevel: Option<String>,
    /// `--request-target` (C `request_target`).
    pub request_target: Option<String>,
    /// `-w`/`--write-out` format string (C `writeout`).
    pub writeout: Option<String>,
    /// `--preproxy` (C `preproxy`).
    pub preproxy: Option<String>,
    /// `--proxy-service-name` (C `proxy_service_name`).
    pub proxy_service_name: Option<String>,
    /// `--service-name` (C `service_name`).
    pub service_name: Option<String>,
    /// `--ftp-account` (C `ftp_account`).
    pub ftp_account: Option<String>,
    /// `--ftp-alternative-to-user` (C `ftp_alternative_to_user`).
    pub ftp_alternative_to_user: Option<String>,
    /// `--oauth2-bearer` token (C `oauth_bearer`).
    pub oauth_bearer: Option<String>,
    /// `--unix-socket`/`--abstract-unix-socket` path (C `unix_socket_path`).
    pub unix_socket_path: Option<String>,
    /// `--haproxy-clientip` (C `haproxy_clientip`).
    pub haproxy_clientip: Option<String>,
    /// `--aws-sigv4` (C `aws_sigv4`).
    pub aws_sigv4: Option<String>,
    /// `--ech` keyword config (C `ech`).
    pub ech: Option<String>,
    /// `--ech ecl:` config (C `ech_config`).
    pub ech_config: Option<String>,
    /// `--ech pn:` public name (C `ech_public`).
    pub ech_public: Option<String>,

    // --- slist-style options (curl_slist -> Vec<String>) ---
    /// `-b`/`--cookie` cookies to serialize into one line (C `cookies`).
    pub cookies: Vec<String>,
    /// `-b`/`--cookie` files to load cookies from (C `cookiefiles`).
    pub cookiefiles: Vec<String>,
    /// `--mail-rcpt` recipients (C `mail_rcpt`).
    pub mail_rcpt: Vec<String>,
    /// `-Q`/`--quote` commands (C `quote`).
    pub quote: Vec<String>,
    /// `--quote` post-transfer commands (C `postquote`).
    pub postquote: Vec<String>,
    /// `--quote` pre-transfer commands (C `prequote`).
    pub prequote: Vec<String>,
    /// `-H`/`--header` request headers (C `headers`).
    pub headers: Vec<String>,
    /// `--proxy-header` headers (C `proxyheaders`).
    pub proxyheaders: Vec<String>,
    /// `-t`/`--telnet-option` options (C `telnet_options`).
    pub telnet_options: Vec<String>,
    /// `--resolve` host mappings (C `resolve`).
    pub resolve: Vec<String>,
    /// `--connect-to` host mappings (C `connect_to`).
    pub connect_to: Vec<String>,

    // --- MIME/form tree (-F/--form) ---
    /// Root of the `-F` MIME tree (C `mimeroot`).
    pub mimeroot: Option<ToolMime>,
    /// Index path (from the root) to the current `-F` tree node being built
    /// (C `mimecurrent`); empty means the root.
    pub mimecurrent: Vec<usize>,
    /// The finalized MIME post tree handed to the library (C `mimepost`, a `curl_mime`).
    pub mimepost: Option<ToolMime>,

    // --- URL / getout list ---
    /// The per-operation URL/output/upload node list (C `url_list`, an intrusive list;
    /// here an owning `Vec`). See [`GetOut`].
    pub url_list: Vec<GetOut>,
    /// Index of the node awaiting a URL (C `url_get`); `None` means "allocate a new node".
    pub url_get: Option<usize>,
    /// Index of the node awaiting an output filename (C `url_out`).
    pub url_out: Option<usize>,
    /// Index of the node awaiting an upload filename (C `url_ul`).
    pub url_ul: Option<usize>,
    /// Number of URLs added to the list (C `num_urls`).
    pub num_urls: usize,

    // --- curl_off_t numerics ---
    /// `-C`/`--continue-at` offset (C `resume_from`).
    pub resume_from: i64,
    /// `--max-filesize` (C `max_filesize`).
    pub max_filesize: i64,
    /// `-z`/`--time-cond` reference time (C `condtime`).
    pub condtime: i64,
    /// `--limit-rate` send cap, bytes/s (C `sendpersecond`).
    pub sendpersecond: i64,
    /// `--limit-rate` receive cap, bytes/s (C `recvpersecond`).
    pub recvpersecond: i64,

    // --- long / unsigned long numerics ---
    /// `--proxy-tlsv1`/proxy SSL version (C `proxy_ssl_version`).
    pub proxy_ssl_version: i64,
    /// `-4`/`-6` address-family preference (C `ip_version`, a `CURL_IPRESOLVE_*` id).
    pub ip_version: i64,
    /// `--create-file-mode` (C `create_file_mode`).
    pub create_file_mode: i64,
    /// `-Y`/`--speed-limit` (C `low_speed_limit`).
    pub low_speed_limit: i64,
    /// `-y`/`--speed-time` (C `low_speed_time`).
    pub low_speed_time: i64,
    /// `--ip-tos` (C `ip_tos`).
    pub ip_tos: i64,
    /// `--vlan-priority` (C `vlan_priority`).
    pub vlan_priority: i64,
    /// `--local-port` base (C `localport`).
    pub localport: i64,
    /// `--local-port` range width (C `localportrange`).
    pub localportrange: i64,
    /// HTTP/proxy auth method bitmask (C `authtype`, a `CURLAUTH_*` mask).
    pub authtype: u64,
    /// `-m`/`--max-time` in ms (C `timeout_ms`).
    pub timeout_ms: i64,
    /// `--connect-timeout` in ms (C `connecttimeout_ms`).
    pub connecttimeout_ms: i64,
    /// `--max-redirs` (C `maxredirs`; `config_alloc` default [`DEFAULT_MAXREDIRS`]).
    pub maxredirs: i64,
    /// Requested HTTP version (C `httpversion`, a `CURL_HTTP_VERSION_*` id).
    pub httpversion: i64,
    /// SOCKS5 proxy auth method bitmask (C `socks5_auth`).
    pub socks5_auth: u64,
    /// `--retry` count (C `req_retry`).
    pub req_retry: i64,
    /// `--retry-delay` in ms; `0` means exponential backoff (C `retry_delay_ms`).
    pub retry_delay_ms: i64,
    /// `--retry-max-time` in ms (C `retry_maxtime_ms`).
    pub retry_maxtime_ms: i64,
    /// `--form-escape` and related MIME option flags (C `mime_options`, `CURLMIMEOPT_*`).
    pub mime_options: u64,
    /// `--tftp-blksize` (C `tftp_blksize`).
    pub tftp_blksize: i64,
    /// `--keepalive-time` in s (C `alivetime`).
    pub alivetime: i64,
    /// `--keepalive-cnt` (C `alivecnt`).
    pub alivecnt: i64,
    /// `--delegation` GSSAPI flag (C `gssapi_delegation`, `CURLGSSAPI_DELEGATION_*`).
    pub gssapi_delegation: i64,
    /// `--expect100-timeout` in ms (C `expect100timeout_ms`).
    pub expect100timeout_ms: i64,
    /// `--happy-eyeballs-timeout-ms` (C `happy_eyeballs_timeout_ms`; default
    /// [`CURL_HET_DEFAULT`]).
    pub happy_eyeballs_timeout_ms: i64,
    /// `-z`/`--time-cond` selector (C `timecond`, a `CURL_TIMECOND_*` id).
    pub timecond: i64,
    /// `-L`/`--location` follow mode (C `followlocation`, a `CURLFOLLOW_*` id).
    pub followlocation: i64,
    /// Selected HTTP request kind (C `httpreq`).
    pub httpreq: HttpReq,
    /// Proxy type (C `proxyver`, a `CURLPROXY_*` id).
    pub proxyver: i64,
    /// `--ftp-ssl-ccc-mode` (C `ftp_ssl_ccc_mode`, `CURLFTPSSL_CCC_*`).
    pub ftp_ssl_ccc_mode: i64,
    /// `--ftp-method` (C `ftp_filemethod`, `CURLFTPMETHOD_*`).
    pub ftp_filemethod: i64,

    // --- small enumerations / fixed-width numerics ---
    /// `--clobber`/`--no-clobber` policy (C `file_clobber_mode`).
    pub file_clobber_mode: ClobberMode,
    /// `--upload-flags` IMAP APPEND bitmask (C `upload_flags`; default
    /// [`curlabi::CURLULFLAG_SEEN`]).
    pub upload_flags: u64,
    /// Resolved local port for the current transfer (C `porttouse`).
    pub porttouse: u16,
    /// Minimum TLS version selector `0..=4` (C `ssl_version`).
    pub ssl_version: u8,
    /// Maximum TLS version selector `0..=4` (C `ssl_version_max`).
    pub ssl_version_max: u8,
    /// `--fail`/`--fail-with-body` mode (C `fail`).
    pub fail: FailMode,

    // --- BIT() boolean flags ---
    /// `--remote-name-all` (C `remote_name_all`).
    pub remote_name_all: bool,
    /// `-R`/`--remote-time` (C `remote_time`).
    pub remote_time: bool,
    /// `-j`/`--junk-session-cookies` (C `cookiesession`).
    pub cookiesession: bool,
    /// `--compressed` Accept-Encoding (C `encoding`).
    pub encoding: bool,
    /// `--tr-encoding` Transfer-Encoding (C `tr_encoding`).
    pub tr_encoding: bool,
    /// `-C`/`--continue-at` resume active (C `use_resume`).
    pub use_resume: bool,
    /// `-C -` resume from current file size (C `resume_from_current`).
    pub resume_from_current: bool,
    /// `--disable-epsv` (C `disable_epsv`).
    pub disable_epsv: bool,
    /// `--disable-eprt` (C `disable_eprt`).
    pub disable_eprt: bool,
    /// `--ftp-pret` (C `ftp_pret`).
    pub ftp_pret: bool,
    /// `--proto` was given (C `proto_present`).
    pub proto_present: bool,
    /// `--proto-redir` was given (C `proto_redir_present`).
    pub proto_redir_present: bool,
    /// `--mail-rcpt-allowfails` (C `mail_rcpt_allowfails`).
    pub mail_rcpt_allowfails: bool,
    /// `--sasl-ir` (C `sasl_ir`).
    pub sasl_ir: bool,
    /// `-p`/`--proxytunnel` (C `proxytunnel`).
    pub proxytunnel: bool,
    /// `-a`/`--append` (C `ftp_append`).
    pub ftp_append: bool,
    /// `-B`/`--use-ascii` (C `use_ascii`).
    pub use_ascii: bool,
    /// `-e ;auto` automatic referer (C `autoreferer`).
    pub autoreferer: bool,
    /// `-i`/`--show-headers`/`--include` (C `show_headers`).
    pub show_headers: bool,
    /// `-I`/`--head` (no body) (C `no_body`).
    pub no_body: bool,
    /// `-l`/`--list-only` (C `dirlistonly`).
    pub dirlistonly: bool,
    /// `--location-trusted` keep auth across hosts (C `unrestricted_auth`).
    pub unrestricted_auth: bool,
    /// `--netrc-optional` (C `netrc_opt`).
    pub netrc_opt: bool,
    /// `-n`/`--netrc` (C `netrc`).
    pub netrc: bool,
    /// `--crlf` (C `crlf`).
    pub crlf: bool,
    /// `--http0.9` (C `http09_allowed`).
    pub http09_allowed: bool,
    /// `-N`/`--no-buffer` (C `nobuffer`).
    pub nobuffer: bool,
    /// Set when reading input returns `EAGAIN` (C `readbusy`).
    pub readbusy: bool,
    /// `-g`/`--globoff` (C `globoff`).
    pub globoff: bool,
    /// `-G`/`--get` (C `use_httpget`).
    pub use_httpget: bool,
    /// `-k`/`--insecure` (C `insecure_ok`).
    pub insecure_ok: bool,
    /// `--doh-insecure` (C `doh_insecure_ok`).
    pub doh_insecure_ok: bool,
    /// `--proxy-insecure` (C `proxy_insecure_ok`).
    pub proxy_insecure_ok: bool,
    /// Output target is a terminal but binary output was allowed (C `terminal_binary_ok`).
    pub terminal_binary_ok: bool,
    /// `--cert-status` (C `verifystatus`).
    pub verifystatus: bool,
    /// `--doh-cert-status` (C `doh_verifystatus`).
    pub doh_verifystatus: bool,
    /// `--create-dirs` (C `create_dirs`).
    pub create_dirs: bool,
    /// `--ftp-create-dirs` (C `ftp_create_dirs`).
    pub ftp_create_dirs: bool,
    /// `--ftp-skip-pasv-ip` (C `ftp_skip_ip`; `config_alloc` default `true`).
    pub ftp_skip_ip: bool,
    /// `--proxy-negotiate` (C `proxynegotiate`).
    pub proxynegotiate: bool,
    /// `--proxy-ntlm` (C `proxyntlm`).
    pub proxyntlm: bool,
    /// `--proxy-digest` (C `proxydigest`).
    pub proxydigest: bool,
    /// `--proxy-basic` (C `proxybasic`).
    pub proxybasic: bool,
    /// `--proxy-anyauth` (C `proxyanyauth`).
    pub proxyanyauth: bool,
    /// `--json` added a JSON content-type (C `jsoned`).
    pub jsoned: bool,
    /// `--ssl` (C `ftp_ssl`).
    pub ftp_ssl: bool,
    /// `--ssl-reqd` (C `ftp_ssl_reqd`).
    pub ftp_ssl_reqd: bool,
    /// `--ftp-ssl-control` (C `ftp_ssl_control`).
    pub ftp_ssl_control: bool,
    /// `--ftp-ssl-ccc` (C `ftp_ssl_ccc`).
    pub ftp_ssl_ccc: bool,
    /// `--socks5-gssapi-nec` (C `socks5_gssapi_nec`).
    pub socks5_gssapi_nec: bool,
    /// `--tcp-nodelay` (C `tcp_nodelay`; `config_alloc` default `true`).
    pub tcp_nodelay: bool,
    /// `--tcp-fastopen` (C `tcp_fastopen`).
    pub tcp_fastopen: bool,
    /// `--retry-all-errors` (C `retry_all_errors`).
    pub retry_all_errors: bool,
    /// `--retry-connrefused` (C `retry_connrefused`).
    pub retry_connrefused: bool,
    /// `--tftp-no-options` (C `tftp_no_options`).
    pub tftp_no_options: bool,
    /// `--ignore-content-length` (C `ignorecl`).
    pub ignorecl: bool,
    /// `--no-sessionid` disables TLS session-id reuse (C `disable_sessionid`).
    pub disable_sessionid: bool,
    /// `--raw` (C `raw`).
    pub raw: bool,
    /// `--post301` (C `post301`).
    pub post301: bool,
    /// `--post302` (C `post302`).
    pub post302: bool,
    /// `--post303` (C `post303`).
    pub post303: bool,
    /// `--no-keepalive` (C `nokeepalive`).
    pub nokeepalive: bool,
    /// `-J`/`--remote-header-name` (C `content_disposition`).
    pub content_disposition: bool,
    /// `--xattr` (C `xattr`).
    pub xattr: bool,
    /// `--ssl-allow-beast` (C `ssl_allow_beast`).
    pub ssl_allow_beast: bool,
    /// `--tls-earlydata` (C `ssl_allow_earlydata`).
    pub ssl_allow_earlydata: bool,
    /// `--proxy-ssl-allow-beast` (C `proxy_ssl_allow_beast`).
    pub proxy_ssl_allow_beast: bool,
    /// `--ssl-no-revoke` (C `ssl_no_revoke`).
    pub ssl_no_revoke: bool,
    /// `--ssl-revoke-best-effort` (C `ssl_revoke_best_effort`).
    pub ssl_revoke_best_effort: bool,
    /// `--ca-native` (C `native_ca_store`).
    pub native_ca_store: bool,
    /// `--proxy-ca-native` (C `proxy_native_ca_store`).
    pub proxy_native_ca_store: bool,
    /// `--ssl-auto-client-cert` (C `ssl_auto_client_cert`).
    pub ssl_auto_client_cert: bool,
    /// `--proxy-ssl-auto-client-cert` (C `proxy_ssl_auto_client_cert`).
    pub proxy_ssl_auto_client_cert: bool,
    /// `--no-alpn` (C `noalpn`).
    pub noalpn: bool,
    /// `--abstract-unix-socket` selected (C `abstract_unix_socket`).
    pub abstract_unix_socket: bool,
    /// `--path-as-is` (C `path_as_is`).
    pub path_as_is: bool,
    /// `--suppress-connect-headers` (C `suppress_connect_headers`).
    pub suppress_connect_headers: bool,
    /// Tool-internal synthetic error marker (C `synthetic_error`).
    pub synthetic_error: bool,
    /// `--compressed-ssh` (C `ssh_compression`).
    pub ssh_compression: bool,
    /// `--haproxy-protocol` (C `haproxy_protocol`).
    pub haproxy_protocol: bool,
    /// `--disallow-username-in-url` (C `disallow_username_in_url`).
    pub disallow_username_in_url: bool,
    /// `--mptcp` (C `mptcp`).
    pub mptcp: bool,
    /// `--remove-on-error` (C `rm_partial`).
    pub rm_partial: bool,
    /// `--skip-existing` (C `skip_existing`).
    pub skip_existing: bool,
}

impl OperationConfig {
    /// Create a fresh per-operation config with curl's `config_alloc` defaults applied
    /// (`tool_cfgable.c`). This is the constructor the CLI always uses — both for the
    /// first operation and for each `--next` operation; the derived [`Default`] provides
    /// only the all-zero base that this method builds upon.
    ///
    /// The non-zero defaults reproduced here are exactly those set by `config_alloc`:
    /// `maxredirs = DEFAULT_MAXREDIRS`, `tcp_nodelay = true`,
    /// `happy_eyeballs_timeout_ms = CURL_HET_DEFAULT`, `ftp_skip_ip = true`,
    /// `upload_flags = CURLULFLAG_SEEN`, and `file_clobber_mode = CLOBBER_DEFAULT`.
    pub fn new() -> Self {
        OperationConfig {
            maxredirs: DEFAULT_MAXREDIRS,
            tcp_nodelay: true,
            happy_eyeballs_timeout_ms: CURL_HET_DEFAULT,
            ftp_skip_ip: true,
            upload_flags: curlabi::CURLULFLAG_SEEN,
            file_clobber_mode: ClobberMode::Default,
            ..Default::default()
        }
    }
}

// ===========================================================================
// State — per-URL iteration state (struct State)
// ===========================================================================

/// Per-URL iteration state used while a single operation's URL list is expanded and
/// transferred (`struct State`, tool_cfgable.h). Consumed by `operate.rs` and
/// `urlglob.rs`.
///
/// Two representational choices differ from the C struct because the types they reference
/// are owned elsewhere in the Rust design:
/// * `urlnode` is an index into the active [`OperationConfig::url_list`] rather than a raw
///   `struct getout *`.
/// * `inglob`/`urlglob` hold the raw glob *pattern* strings; the parsed [`URLGlob`] state
///   machine is owned by `urlglob.rs` (added in a later checkpoint), which will refine
///   these once that module exists.
///
/// [`URLGlob`]: https://curl.se/
#[derive(Debug, Default, Clone)]
pub struct State {
    /// Index of the current node in the active operation's `url_list` (C `urlnode`).
    pub urlnode: Option<usize>,
    /// Raw input (upload) glob pattern (C `inglob`, a `URLGlob`).
    pub inglob: Option<String>,
    /// Raw URL glob pattern (C `urlglob`, a `URLGlob`).
    pub urlglob: Option<String>,
    /// Synthesized `-G` query fields moved out of the body (C `httpgetfields`).
    pub httpgetfields: Option<String>,
    /// The upload source for the current glob iteration (C `uploadfile`).
    pub uploadfile: Option<String>,
    /// Number of files to upload (C `upnum`, `curl_off_t`).
    pub upnum: i64,
    /// Index into the upload glob (C `upidx`, `curl_off_t`).
    pub upidx: i64,
    /// How many iterations this URL expands to (C `urlnum`, `curl_off_t`).
    pub urlnum: i64,
    /// Index into the globbed URLs (C `urlidx`, `curl_off_t`).
    pub urlidx: i64,
}

// ===========================================================================
// GlobalConfig — the process-global configuration (struct GlobalConfig)
// ===========================================================================

/// Hook that parses an included config file (`--config`). Wired by `main.rs` to
/// `parsecfg.rs`'s `parseconfig`. Arguments are the filename, the remaining recursion
/// budget (already decremented), and the mutable global config the file's options mutate.
/// Mirrors the C call `parseconfig(nextarg, max_recursive, NULL)`.
pub type ConfigParserHook = fn(&str, i32, &mut GlobalConfig) -> Result<(), ParameterError>;

/// Hook that registers a `--variable` definition. Wired by `main.rs` to `var.rs`'s
/// `setvariable`. The definition (`name=value`, `name@file`, or `%name`) is applied
/// immediately so a later `--expand-<opt>` on the same command line can reference it.
pub type VariableSetterHook = fn(&str, &mut GlobalConfig) -> Result<(), ParameterError>;

/// Hook that performs `--expand-<opt>` variable expansion on an argument. Wired by
/// `main.rs` to `var.rs`'s `varexpand`. Returns `Some(expanded)` when at least one
/// `{{var}}` reference was substituted (C `replaced == TRUE`), or `None` when the
/// argument is used verbatim. Reads the variable store but does not mutate it.
pub type VariableExpanderHook = fn(&str, &GlobalConfig) -> Result<Option<String>, ParameterError>;

/// Hook that parses a `-F`/`--form` (or `--form-string`) argument into the MIME tree.
/// Wired by `main.rs` to `formparse.rs`'s `formparse`. The `bool` is the "literal"
/// flag (`true` for `--form-string`, i.e. do not interpret a leading `@`/`<`).
pub type FormParserHook = fn(&str, &mut OperationConfig, bool) -> Result<(), ParameterError>;

/// Process-global CLI configuration (`struct GlobalConfig`, tool_cfgable.h): the options
/// that apply across all operations plus the owning store of the `--next` operation chain.
///
/// The C `first`/`current`/`last` `OperationConfig *` triplet is replaced by an owning
/// [`Vec<OperationConfig>`](GlobalConfig::operations) plus a [`current`](GlobalConfig::current)
/// index (AAP §0.3.1); `first` is `operations[0]` and `last` is the final element. The
/// DEBUGBUILD-only `test_duphandle`/`test_event_based` fields are intentionally dropped
/// (not carried forward). Construct with [`GlobalConfig::globalconf_init`] (equivalently
/// [`GlobalConfig::new`] / [`Default`]), which reproduces curl's `globalconf_init`
/// defaults and seeds the chain with one [`OperationConfig::new`].
///
/// This type is deliberately not `Clone`: it owns process-unique resources (the trace
/// output stream) and the entire operation chain.
///
/// # Sibling-module hooks
///
/// A handful of options delegate to logic that lives in *sibling* CLI modules which
/// themselves depend on this module's vocabulary — `--config` → `parsecfg.rs`
/// (`parseconfig`), `--variable` → `var.rs` (`setvariable`), `--expand-<opt>` → `var.rs`
/// (`varexpand`), and `-F`/`--form*` → `formparse.rs` (`formparse`). Because those modules
/// consume [`OperationConfig`]/[`GlobalConfig`]/[`ParameterError`], importing them here
/// would create a dependency cycle. Instead they are injected as function-pointer hooks
/// that `main.rs` wires once at startup (see [`GlobalConfig::config_parser`] et al.). When
/// a hook is left unset (e.g. in unit tests that never exercise the corresponding option),
/// the dispatch degrades gracefully rather than panicking — see each field's docs.
#[derive(Debug)]
pub struct GlobalConfig {
    /// Per-URL iteration state used by `create_transfer()` (C `state`).
    pub state: State,
    /// `--trace`/`--trace-ascii` dump filename (C `trace_dump`).
    pub trace_dump: Option<String>,
    /// The opened trace output stream, if any (C `trace_stream`). Opened by `main`/`operate`
    /// once parsing is complete; `None` during argument parsing.
    pub trace_stream: Option<fs::File>,
    /// `--libcurl` source-output filename (C `libcurl`); consumed by `setopt.rs`'s easysrc.
    pub libcurl: Option<String>,
    /// `--ssl-sessions` load/save file (C `ssl_sessions`).
    pub ssl_sessions: Option<String>,
    /// The `--variable` store (C `variables`); higher-level semantics owned by `var.rs`.
    pub variables: Vec<ToolVar>,
    /// The owning `--next` operation chain (C `first`/`current`/`last`). Never empty:
    /// [`GlobalConfig::new`] seeds it with one operation.
    pub operations: Vec<OperationConfig>,
    /// Index of the operation currently being configured (C `current`/`last`).
    pub current: usize,
    /// `--rate`: minimum milliseconds between successive transfers (C `ms_per_transfer`,
    /// `timediff_t`).
    pub ms_per_transfer: i64,
    /// Active protocol-trace verbosity/format (C `tracetype`).
    pub tracetype: TraceType,
    /// Progress-output style (C `progressmode`).
    pub progressmode: ProgressMode,
    /// `--parallel-max-host` cap (C `parallel_host`; `0` == no per-host limit).
    pub parallel_host: u16,
    /// `--parallel-max` cap (C `parallel_max`; `globalconf_init` default
    /// [`PARALLEL_DEFAULT`]).
    pub parallel_max: u16,
    /// `-v`/`--verbose` repeat count (C `verbosity`).
    pub verbosity: u8,
    /// `-Z`/`--parallel` (C `parallel`).
    pub parallel: bool,
    /// `--parallel-immediate` (C `parallel_connect`).
    pub parallel_connect: bool,
    /// `--fail-early` (C `fail_early`).
    pub fail_early: bool,
    /// `--styled-output` fancy-output detection (C `styled_output`; `globalconf_init`
    /// default `true`).
    pub styled_output: bool,
    /// Whether [`GlobalConfig::trace_stream`] is an owned file we opened (C `trace_fopened`).
    pub trace_fopened: bool,
    /// `--trace-time` include timestamps (C `tracetime`).
    pub tracetime: bool,
    /// `--trace-ids` include xfer/conn ids (C `traceids`).
    pub traceids: bool,
    /// `-S`/`--show-error` show errors even when silent (C `showerror`).
    pub showerror: bool,
    /// `-s`/`--silent` (C `silent`).
    pub silent: bool,
    /// `--no-progress-meter` (C `noprogress`).
    pub noprogress: bool,
    /// Set internally when the output is a TTY (C `isatty`).
    pub isatty: bool,
    /// `--trace-config` has been used (C `trace_set`).
    pub trace_set: bool,
    /// Library-directed trace tokens accumulated from `--trace-config` / `-v` levels
    /// (the strings the C forwards to `curl_global_trace`). Since this rewrite has no
    /// C global-trace side effect, they are owned here for `main.rs`/`setopt.rs` to
    /// apply to the library once parsing completes. Not present as a distinct field in
    /// the C `GlobalConfig` (there the effect is a `curl_global_trace()` side effect);
    /// added as the idiomatic Rust equivalent that carries the same state.
    pub trace_config: Vec<String>,
    /// `--stderr <file>` redirect target (C `tool_set_stderr_file` side effect). The C
    /// tool stores the reopened stream in a `tool_stderr.c` static; this rewrite records
    /// the requested filename here for `main.rs` to apply once parsing completes. `Some`
    /// with the literal `"-"` requests stdout, matching curl.
    pub stderr_file: Option<String>,
    /// Optional `<category>` subject captured from `--help [category]`. curl passes this
    /// directly to `tool_help(category)`; this rewrite defers help rendering until after
    /// parsing (see `operate.rs`), so the subject is stashed here when `--help` is seen.
    /// `None` for a bare `--help` (the default, curated help page).
    pub help_category: Option<String>,
    /// `--config` parser hook (see [`ConfigParserHook`]). `None` until `main.rs` wires
    /// `parsecfg.rs`; when unset, `--config` is accepted but its file is skipped.
    pub config_parser: Option<ConfigParserHook>,
    /// `--variable` setter hook (see [`VariableSetterHook`]). `None` until `main.rs`
    /// wires `var.rs`; when unset, `--variable` is accepted but stores nothing.
    pub variable_setter: Option<VariableSetterHook>,
    /// `--expand-<opt>` expander hook (see [`VariableExpanderHook`]). `None` until
    /// `main.rs` wires `var.rs`; when unset, `--expand-` arguments are used verbatim.
    pub variable_expander: Option<VariableExpanderHook>,
    /// `-F`/`--form*` parser hook (see [`FormParserHook`]). `None` until `main.rs` wires
    /// `formparse.rs`; when unset, `-F` is accepted and the request method is still set
    /// to multipart POST, but no MIME part is appended.
    pub form_parser: Option<FormParserHook>,
}

impl Default for GlobalConfig {
    /// Delegates to [`GlobalConfig::new`] so that `default()` reproduces curl's
    /// `globalconf_init` non-zero defaults (`styled_output = true`,
    /// `parallel_max = PARALLEL_DEFAULT`, …) rather than the all-zero base a derived
    /// `Default` would yield.
    #[inline]
    fn default() -> Self {
        GlobalConfig::new()
    }
}

impl GlobalConfig {
    /// Create an initialized process-global config, reproducing curl's `globalconf_init`
    /// (`tool_cfgable.c`): `showerror = false`, `styled_output = true`,
    /// `parallel_max = PARALLEL_DEFAULT`, and a chain seeded with a single
    /// [`OperationConfig::new`].
    pub fn new() -> Self {
        GlobalConfig {
            state: State::default(),
            trace_dump: None,
            trace_stream: None,
            libcurl: None,
            ssl_sessions: None,
            variables: Vec::new(),
            operations: vec![OperationConfig::new()],
            current: 0,
            ms_per_transfer: 0,
            tracetype: TraceType::None,
            progressmode: ProgressMode::Stats,
            parallel_host: PARALLEL_HOST_DEFAULT as u16,
            parallel_max: PARALLEL_DEFAULT as u16,
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
            trace_config: Vec::new(),
            stderr_file: None,
            help_category: None,
            config_parser: None,
            variable_setter: None,
            variable_expander: None,
            form_parser: None,
        }
    }

    /// `globalconf_init` equivalent — an alias for [`GlobalConfig::new`] provided for
    /// call-site parity with `main.rs`'s port of `tool_main.c`.
    #[inline]
    pub fn globalconf_init() -> Self {
        GlobalConfig::new()
    }

    /// `globalconf_free` equivalent. In Rust, ownership frees the operation chain, the
    /// variable store, and the trace stream automatically when the config is dropped;
    /// this method exists only for call-site parity and simply consumes `self`.
    #[inline]
    pub fn globalconf_free(self) {}

    /// Mutable access to the operation currently being configured (C `config`/`global->last`).
    #[inline]
    pub fn op(&mut self) -> &mut OperationConfig {
        &mut self.operations[self.current]
    }

    /// Shared access to the operation currently being configured.
    #[inline]
    pub fn op_ref(&self) -> &OperationConfig {
        &self.operations[self.current]
    }

    /// Capture a [`Diag`] snapshot of the diagnostic-gating fields. Call this
    /// *before* borrowing an operation mutably out of [`Self::op`], then pass the
    /// returned value (by copy) to [`warnf`], [`errorf`], `notef`, and the
    /// warning-emitting validators.
    #[inline]
    pub fn diag(&self) -> Diag {
        Diag {
            silent: self.silent,
            showerror: self.showerror,
            tracing: self.tracetype != TraceType::None,
        }
    }

    /// Append a fresh [`OperationConfig`] to the chain and make it current, returning the
    /// new index. This is the structural half of `--next`; [`parse_args`] performs the
    /// "URL must precede `--next`" guard around it.
    pub fn push_operation(&mut self) -> usize {
        self.operations.push(OperationConfig::new());
        self.current = self.operations.len() - 1;
        self.current
    }
}

// ===========================================================================
// Part 7 — parameter validators (port of tool_paramhlp.c + the three
// UNITTEST helpers that live in tool_getparam.c: parse_cert_parameter,
// getunit, GetSizeParameter).
//
// Every validator returns `Result<_, ParameterError>` (or, for the
// enum-string helpers that fall back to a default and warn, a plain integer),
// matching the C originals byte-for-byte in behavior. There is NO `unsafe`
// anywhere in this module — all parsing is pure safe Rust.
// ===========================================================================

/// `LONG_MAX` on the four supported (LP64) targets, where C `long` is 64-bit.
pub const LONG_MAX: i64 = i64::MAX;

/// `CURL_OFF_T_MAX` — the maximum `curl_off_t` (a signed 64-bit integer).
pub const CURL_OFF_T_MAX: i64 = i64::MAX;

/// Upper bound for `file2string` reads (`MAX_FILE2STRING`, aliased to
/// [`MAX_FILE2MEMORY`] in tool_paramhlp.c).
pub const MAX_FILE2STRING: u64 = MAX_FILE2MEMORY;

/// Maximum combined `user:password` length accepted / prompted for
/// (`MAX_USERPWDLENGTH`, tool_paramhlp.c).
pub const MAX_USERPWDLENGTH: usize = 100 * 1024;

/// Maximum number of protocol tokens `--proto`/`--proto-redir` may resolve to
/// (`MAX_PROTOS`, tool_paramhlp.c). The built-in set below is comfortably under
/// this ceiling.
pub const MAX_PROTOS: usize = 34;

/// The set of protocol scheme names recognized by `--proto` / `--proto-redir`,
/// derived from curl 8.x's built-in scheme table (`lib/url.c`, `all_schemes[]`)
/// minus the RTMP/RTMPS family which is dropped from this rewrite per AAP
/// §1.3.2.5 (no pure-Rust `librtmp` equivalent exists). Names are canonical
/// lowercase; matching is case-insensitive. IPFS/IPNS are CLI-level URL schemes
/// (translated to HTTP by `ipfs.rs`), not libcurl protocols, so they are not
/// `--proto` tokens — matching curl, where `proto_token("ipfs")` is `NULL`.
pub const PROTO_TOKENS: &[&str] = &[
    "dict", "file", "ftp", "ftps", "gopher", "gophers", "http", "https", "imap", "imaps", "ldap",
    "ldaps", "mqtt", "mqtts", "pop3", "pop3s", "rtsp", "scp", "sftp", "smb", "smbs", "smtp",
    "smtps", "telnet", "tftp", "ws", "wss",
];

/// The seed set for `--proto-redir` (curl's static `redir_protos[]`). `--proto`
/// instead seeds from the full built-in set ([`PROTO_TOKENS`]).
pub const REDIR_PROTOS: &[&str] = &["http", "https", "ftp", "ftps"];

// ---------------------------------------------------------------------------
// Diagnostics — faithful ports of tool_msgs.c's warnf/notef/errorf/helpf.
//
// `voutf` reproduces the terminal-width word-wrapping of the C `voutf`; the
// message text and the "Warning: " / "Note: " / "curl: " prefixes are
// preserved exactly so downstream stderr scrapers keep working.
// ---------------------------------------------------------------------------

/// Determine the terminal width used to wrap diagnostics, mirroring
/// Terminal width, in columns, used by [`voutf`] for word-wrapping.
///
/// This must match curl's `get_terminal_columns()` (src/terminal.c) exactly so the
/// wrap column — and therefore the byte-for-byte stderr output that log scrapers
/// depend on (AAP §0.7.1) — is identical to curl in every environment. curl's
/// resolution order is: honor `$COLUMNS` (when it parses to a number in the
/// `(20, 10000]` range), otherwise query `ioctl(TIOCGWINSZ)` on stdin, otherwise
/// fall back to the fixed default of 79.
///
/// Earlier this port omitted the `ioctl` leg (believing it required forbidden
/// `unsafe`), which made `voutf` wrap at 79 even inside a wide interactive terminal
/// — diverging from curl, whose `ioctl` reports the true width. The crate now has a
/// faithful [`crate::terminal::get_terminal_columns`] whose single narrow `unsafe`
/// `ioctl` call is an AAP-sanctioned OS-integration primitive, so this delegates to
/// it and reproduces all three legs of curl's algorithm.
fn terminal_columns() -> usize {
    crate::terminal::get_terminal_columns() as usize
}

/// A small `Copy` snapshot of the [`GlobalConfig`] fields that gate diagnostic
/// output. Because an [`OperationConfig`] is borrowed out of
/// `GlobalConfig.operations` while options are applied, the diagnostic helpers
/// cannot also borrow `&GlobalConfig`; this value is captured once (via
/// [`GlobalConfig::diag`]) before the operation borrow and passed by copy.
#[derive(Clone, Copy, Debug, Default)]
pub struct Diag {
    /// `--silent` — suppresses warnings and (unless `showerror`) errors.
    pub silent: bool,
    /// `--show-error` — forces errors to print even under `--silent`.
    pub showerror: bool,
    /// True when any trace mode is active (`tracetype != None`); gates `Note:`.
    pub tracing: bool,
}

/// Port of the static `voutf` (tool_msgs.c): print `msg` to stderr, each output
/// line prefixed with `prefix` and wrapped to the terminal width. Bytes are
/// written verbatim (no UTF-8 re-encoding), so the output matches the C exactly.
fn voutf(prefix: &str, msg: &str) {
    use std::io::Write;
    let termw = terminal_columns();
    let prefw = prefix.len();
    // width == SIZE_MAX in C when the prefix is wider than the terminal.
    let width = if termw > prefw {
        termw - prefw
    } else {
        usize::MAX
    };
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    let bytes = msg.as_bytes();
    let mut ptr = 0usize;
    let mut len = bytes.len();
    while len > 0 {
        let _ = h.write_all(prefix.as_bytes());
        if len > width {
            // Break on the last blank at or before the wrap column.
            let mut cut = width - 1;
            while cut > 0 && !(bytes[ptr + cut] == b' ' || bytes[ptr + cut] == b'\t') {
                cut -= 1;
            }
            if cut == 0 {
                // No blank found — hard-break at the max width.
                cut = width - 1;
            }
            let _ = h.write_all(&bytes[ptr..ptr + cut + 1]);
            let _ = h.write_all(b"\n");
            ptr += cut + 1;
            len -= cut + 1;
        } else {
            let _ = h.write_all(&bytes[ptr..ptr + len]);
            let _ = h.write_all(b"\n");
            len = 0;
        }
    }
}

/// Emit a `Warning:`-prefixed diagnostic, suppressed when `--silent` is in
/// effect (port of `warnf`, tool_msgs.c).
pub fn warnf(diag: Diag, msg: &str) {
    if !diag.silent {
        voutf("Warning: ", msg);
    }
}

/// Emit a `Note:`-prefixed diagnostic, shown only while tracing is active (port
/// of `notef`, tool_msgs.c).
pub fn notef(diag: Diag, msg: &str) {
    if diag.tracing {
        voutf("Note: ", msg);
    }
}

/// Emit a `curl:`-prefixed error diagnostic, shown unless silenced without
/// `--show-error` (port of `errorf`, tool_msgs.c).
pub fn errorf(diag: Diag, msg: &str) {
    if !diag.silent || diag.showerror {
        voutf("curl: ", msg);
    }
}

/// Port of `helpf` (tool_msgs.c): print an optional `curl: <msg>` line followed
/// by the standard "try 'curl --help' ..." hint. Always prints (never silenced).
pub fn helpf(msg: Option<&str>) {
    use std::io::Write;
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    if let Some(m) = msg {
        let _ = writeln!(h, "curl: {m}");
    }
    let _ = writeln!(
        h,
        "curl: try 'curl --help' or 'curl --manual' for more information"
    );
}

// ---------------------------------------------------------------------------
// Low-level numeric scanners — ports of lib/curlx/strparse.c primitives.
// ---------------------------------------------------------------------------

/// The subset of `STRE_*` outcomes the numeric validators care about
/// (`lib/curlx/strparse.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumScan {
    /// No digit was present at the start of the input (`STRE_NO_NUM`).
    NoNum,
    /// The accumulated value would exceed `max` (`STRE_OVERFLOW`).
    Overflow,
}

/// Value of an ASCII digit `c` in `base` (8, 10, or 16), or `None` if `c` is not
/// a valid digit for that base. Mirrors `valid_digit()` + `curlx_hexasciitable`
/// (strparse.c): only `0-9`, `a-f`, `A-F` are digits, and the character must be
/// numerically below `base`.
#[inline]
fn digit_val(c: u8, base: u32) -> Option<u32> {
    let v = match c {
        b'0'..=b'9' => u32::from(c - b'0'),
        b'a'..=b'f' => u32::from(c - b'a') + 10,
        b'A'..=b'F' => u32::from(c - b'A') + 10,
        _ => return None,
    };
    if v < base {
        Some(v)
    } else {
        None
    }
}

/// Port of `str_num_base` (strparse.c): parse an unsigned integer in `base` (8,
/// 10, or 16) from the front of `s`, capped at `max`. No `0x` prefix, no leading
/// sign or whitespace; leading zeroes are accepted. On success returns
/// `(value, rest)` with `rest` the unconsumed tail. Requires at least one digit
/// (else [`NumScan::NoNum`]) and reports [`NumScan::Overflow`] past `max`.
fn str_num_base(s: &str, max: i64, base: u32) -> Result<(i64, &str), NumScan> {
    let bytes = s.as_bytes();
    // Require at least one valid digit.
    if bytes.is_empty() || digit_val(bytes[0], base).is_none() {
        return Err(NumScan::NoNum);
    }
    let base_i = base as i64;
    let mut num: i64 = 0;
    let mut idx = 0usize;
    if max < base_i {
        // Special-case a tiny `max` where the general overflow test misbehaves.
        loop {
            let n = i64::from(digit_val(bytes[idx], base).unwrap());
            idx += 1;
            num = num * base_i + n;
            if num > max {
                return Err(NumScan::Overflow);
            }
            if idx >= bytes.len() || digit_val(bytes[idx], base).is_none() {
                break;
            }
        }
    } else {
        loop {
            let n = i64::from(digit_val(bytes[idx], base).unwrap());
            idx += 1;
            if num > (max - n) / base_i {
                return Err(NumScan::Overflow);
            }
            num = num * base_i + n;
            if idx >= bytes.len() || digit_val(bytes[idx], base).is_none() {
                break;
            }
        }
    }
    Ok((num, &s[idx..]))
}

/// Port of `curlx_str_number`: decimal [`str_num_base`].
#[inline]
fn str_number(s: &str, max: i64) -> Result<(i64, &str), NumScan> {
    str_num_base(s, max, 10)
}

/// Port of `curlx_str_octal`: octal [`str_num_base`].
#[inline]
fn str_octal(s: &str, max: i64) -> Result<(i64, &str), NumScan> {
    str_num_base(s, max, 8)
}

/// Port of `curlx_str_single`: consume the single byte `byte` from the front of
/// `s`, returning the remaining tail. `Err(())` (mirroring `STRE_BYTE`) if the
/// next byte differs or the input is empty.
#[inline]
fn str_single(s: &str, byte: u8) -> Result<&str, ()> {
    if s.as_bytes().first() == Some(&byte) {
        Ok(&s[1..])
    } else {
        Err(())
    }
}

// ---------------------------------------------------------------------------
// Numeric validators (tool_paramhlp.c). Each returns the parsed value rather
// than writing through an out-parameter as the C does.
// ---------------------------------------------------------------------------

/// Port of `str2num`: parse a signed `long` (optionally `-`-prefixed) that
/// consumes the whole string. Any parse failure or trailing garbage is
/// [`ParameterError::BadNumeric`].
pub fn str2num(str: &str) -> Result<i64, ParameterError> {
    let mut rest = str;
    let mut is_neg = false;
    if let Ok(r) = str_single(rest, b'-') {
        is_neg = true;
        rest = r;
    }
    let (num, rest) = match str_number(rest, LONG_MAX) {
        Ok(v) => v,
        Err(_) => return Err(ParameterError::BadNumeric),
    };
    // curlx_str_single(&str, '\0'): the entire string must be consumed.
    if !rest.is_empty() {
        return Err(ParameterError::BadNumeric);
    }
    Ok(if is_neg { -num } else { num })
}

/// Port of `oct2nummax`: parse an octal `long` in `0..=max`, distinguishing
/// overflow ([`ParameterError::NumberTooLarge`]) from malformed input
/// ([`ParameterError::BadNumeric`]); negatives are impossible but preserved as
/// [`ParameterError::NegativeNumeric`] for fidelity.
pub fn oct2nummax(str: &str, max: i64) -> Result<i64, ParameterError> {
    let (num, rest) = match str_octal(str, max) {
        Ok(v) => v,
        Err(NumScan::Overflow) => return Err(ParameterError::NumberTooLarge),
        Err(NumScan::NoNum) => return Err(ParameterError::BadNumeric),
    };
    if !rest.is_empty() {
        return Err(ParameterError::BadNumeric);
    }
    if num < 0 {
        return Err(ParameterError::NegativeNumeric);
    }
    Ok(num)
}

/// Port of `str2unum`: [`str2num`] restricted to non-negative values.
pub fn str2unum(str: &str) -> Result<i64, ParameterError> {
    let val = str2num(str)?;
    if val < 0 {
        return Err(ParameterError::NegativeNumeric);
    }
    Ok(val)
}

/// Port of `str2unummax`: [`str2unum`] with an inclusive upper bound of `max`.
pub fn str2unummax(str: &str, max: i64) -> Result<i64, ParameterError> {
    let val = str2unum(str)?;
    if val > max {
        return Err(ParameterError::NumberTooLarge);
    }
    Ok(val)
}

/// Port of `secs2ms`: parse a decimal number of seconds with an optional
/// fractional part and return the value in milliseconds. The integer part is
/// capped at `LONG_MAX/1000 - 1`; a trailing non-`.` character ends the scan and
/// is ignored (matching the C, which performs no end-of-string check here).
pub fn secs2ms(str: &str) -> Result<i64, ParameterError> {
    // 10^0 .. 10^8 — used to scale the fractional digits down to milliseconds.
    const DIGS: [i64; 9] = [
        1,
        10,
        100,
        1000,
        10_000,
        100_000,
        1_000_000,
        10_000_000,
        100_000_000,
    ];
    let (secs, rest) = match str_number(str, LONG_MAX / 1000 - 1) {
        Ok(v) => v,
        Err(_) => return Err(ParameterError::BadNumeric),
    };
    let mut ms: i64 = 0;
    if let Ok(after_dot) = str_single(rest, b'.') {
        let (mut fracs, tail) = match str_number(after_dot, CURL_OFF_T_MAX) {
            Ok(v) => v,
            Err(_) => return Err(ParameterError::NumberTooLarge),
        };
        // Number of fractional digits actually consumed.
        let mut len = after_dot.len() - tail.len();
        // Reduce to at most 9 significant digits without overflowing the *100 scale.
        while len > DIGS.len() || fracs > LONG_MAX / 100 {
            fracs /= 10;
            len -= 1;
        }
        ms = (fracs * 100) / DIGS[len - 1];
    }
    Ok(secs * 1000 + ms)
}

/// Port of `str2offset`: parse a non-negative `curl_off_t` consuming the whole
/// string; any failure (including overflow) is [`ParameterError::BadNumeric`].
pub fn str2offset(str: &str) -> Result<i64, ParameterError> {
    let (val, rest) = match str_number(str, CURL_OFF_T_MAX) {
        Ok(v) => v,
        Err(_) => return Err(ParameterError::BadNumeric),
    };
    if !rest.is_empty() {
        return Err(ParameterError::BadNumeric);
    }
    Ok(val)
}

/// Port of `str2tls_max`: map a `--tls-max` argument to the internal max-TLS
/// selector (`0`=default, `1`=1.0 .. `4`=1.3). Unknown values are
/// [`ParameterError::BadUse`]. (The C `NULL` → `REQUIRES_PARAMETER` case is
/// handled by the caller, which only invokes this with a present argument.)
pub fn str2tls_max(str: &str) -> Result<u8, ParameterError> {
    match str {
        "default" => Ok(0),
        "1.0" => Ok(1),
        "1.1" => Ok(2),
        "1.2" => Ok(3),
        "1.3" => Ok(4),
        _ => Err(ParameterError::BadUse),
    }
}

// ---------------------------------------------------------------------------
// Enum-string validators (tool_paramhlp.c). These never fail: an unknown value
// warns and returns the documented default.
// ---------------------------------------------------------------------------

/// Port of `ftpfilemethod`: map `--ftp-method` to a `CURLFTPMETHOD_*` value,
/// defaulting to `MULTICWD` (with a warning) for anything unrecognized.
pub fn ftpfilemethod(diag: Diag, str: &str) -> i64 {
    if str.eq_ignore_ascii_case("singlecwd") {
        return curlabi::CURLFTPMETHOD_SINGLECWD;
    }
    if str.eq_ignore_ascii_case("nocwd") {
        return curlabi::CURLFTPMETHOD_NOCWD;
    }
    if str.eq_ignore_ascii_case("multicwd") {
        return curlabi::CURLFTPMETHOD_MULTICWD;
    }
    warnf(
        diag,
        &format!("unrecognized ftp file method '{str}', using default"),
    );
    curlabi::CURLFTPMETHOD_MULTICWD
}

/// Port of `ftpcccmethod`: map `--ftp-ssl-ccc-mode` to a `CURLFTPSSL_CCC_*`
/// value, defaulting to `PASSIVE` (with a warning) for anything unrecognized.
pub fn ftpcccmethod(diag: Diag, str: &str) -> i64 {
    if str.eq_ignore_ascii_case("passive") {
        return curlabi::CURLFTPSSL_CCC_PASSIVE;
    }
    if str.eq_ignore_ascii_case("active") {
        return curlabi::CURLFTPSSL_CCC_ACTIVE;
    }
    warnf(
        diag,
        &format!("unrecognized ftp CCC method '{str}', using default"),
    );
    curlabi::CURLFTPSSL_CCC_PASSIVE
}

/// Port of `delegation`: map `--delegation` to a `CURLGSSAPI_DELEGATION_*` value,
/// defaulting to `NONE` (with a warning) for anything unrecognized.
pub fn delegation(diag: Diag, str: &str) -> i64 {
    if str.eq_ignore_ascii_case("none") {
        return curlabi::CURLGSSAPI_DELEGATION_NONE;
    }
    if str.eq_ignore_ascii_case("policy") {
        return curlabi::CURLGSSAPI_DELEGATION_POLICY_FLAG;
    }
    if str.eq_ignore_ascii_case("always") {
        return curlabi::CURLGSSAPI_DELEGATION_FLAG;
    }
    warnf(
        diag,
        &format!("unrecognized delegation method '{str}', using none"),
    );
    curlabi::CURLGSSAPI_DELEGATION_NONE
}

// ---------------------------------------------------------------------------
// Protocol-set parsing (tool_paramhlp.c + tool_libinfo.c proto_token).
// ---------------------------------------------------------------------------

/// Port of `proto_token` (src/tool_libinfo.c): return the canonical
/// (case-insensitive) name for `proto`, or `None` if it is not a recognized
/// built-in scheme. Comparing the returned `&'static str` by identity matches
/// the C pointer-comparison idiom.
pub fn proto_token(proto: &str) -> Option<&'static str> {
    PROTO_TOKENS
        .iter()
        .copied()
        .find(|p| p.eq_ignore_ascii_case(proto))
}

/// Port of `check_protocol` (tool_paramhlp.c): accept a single protocol name,
/// mapping an unknown one to [`ParameterError::LibcurlUnsupportedProtocol`].
/// (The C `NULL` → `REQUIRES_PARAMETER` case is handled by the caller.)
pub fn check_protocol(str: &str) -> Result<(), ParameterError> {
    if proto_token(str).is_some() {
        Ok(())
    } else {
        Err(ParameterError::LibcurlUnsupportedProtocol)
    }
}

/// The modifier applied to a single entry in a `--proto`/`--proto-redir` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtoAction {
    /// `+p` or a bare `p` — add to the permitted set.
    Allow,
    /// `-p` — remove from the permitted set.
    Deny,
    /// `=p` — clear the set, then add `p`.
    Set,
}

/// Port of `proto2num` (tool_paramhlp.c): evaluate the comma-separated protocol
/// specification `spec` (each entry an optional `+`/`-`/`=` modifier followed by
/// a protocol name or `all`) against the seed set `seed`, and return the
/// resulting alphabetically-sorted, comma-joined protocol string. Unknown
/// protocols emit a warning (and, under `=`, clear the set). An empty result is
/// [`ParameterError::BadUse`].
pub fn proto2num(diag: Diag, seed: &[&'static str], spec: &str) -> Result<String, ParameterError> {
    use std::collections::BTreeSet;

    // Seed the working set (only recognized tokens are retained). A BTreeSet
    // keeps entries unique and case-insensitively sorted (all tokens are
    // lowercase), reproducing curl's `struplocompare4sort` qsort ordering.
    let mut set: BTreeSet<&'static str> = BTreeSet::new();
    for p in seed {
        if let Some(tok) = proto_token(p) {
            set.insert(tok);
        }
    }

    for seg in spec.split(',') {
        // Empty entries (leading/rogue commas, trailing comma) are skipped,
        // matching both the C `str == next` guard and its `while(*str)` bound.
        if seg.is_empty() {
            continue;
        }
        let (action, token) = match seg.as_bytes()[0] {
            b'=' => (ProtoAction::Set, &seg[1..]),
            b'-' => (ProtoAction::Deny, &seg[1..]),
            b'+' => (ProtoAction::Allow, &seg[1..]),
            _ => (ProtoAction::Allow, seg),
        };
        // The C copies the token into a 32-byte buffer (snprintf truncates at
        // 31). Reproduce that cap for the warning text; recognized names are all
        // <= 7 chars so this only affects unknown-token diagnostics.
        let token_disp: String = token.chars().take(31).collect();

        if token_disp.eq_ignore_ascii_case("all") {
            match action {
                ProtoAction::Deny => set.clear(),
                ProtoAction::Allow | ProtoAction::Set => {
                    // "all" always means the full built-in set, regardless of seed.
                    set = PROTO_TOKENS.iter().copied().collect();
                }
            }
        } else {
            match proto_token(&token_disp) {
                Some(tok) => match action {
                    ProtoAction::Deny => {
                        set.remove(tok);
                    }
                    ProtoAction::Set => {
                        set.clear();
                        set.insert(tok);
                    }
                    ProtoAction::Allow => {
                        set.insert(tok);
                    }
                },
                None => {
                    if action == ProtoAction::Set {
                        set.clear();
                    }
                    warnf(diag, &format!("unrecognized protocol '{token_disp}'"));
                }
            }
        }
    }

    if set.is_empty() {
        return Err(ParameterError::BadUse);
    }
    Ok(set.into_iter().collect::<Vec<_>>().join(","))
}

// ---------------------------------------------------------------------------
// Certificate parameter splitting (parse_cert_parameter, tool_getparam.c).
// ---------------------------------------------------------------------------

/// Port of `parse_cert_parameter` (tool_getparam.c): split a `--cert`-style
/// argument into a certificate name and an optional passphrase. A leading
/// `pkcs11:` URI, or an argument containing neither `:` nor `\`, is returned as
/// the certificate name with no passphrase. Otherwise a `:` separates name from
/// passphrase, and `\` escapes the next character (`\\`→`\`, `\:`→`:`, any other
/// `\x` is kept verbatim as `\x`). An empty argument is
/// [`ParameterError::BlankString`].
///
/// The C source contains a Windows drive-letter special-case (`c:\file`), which
/// is `#ifdef _WIN32` only; Windows is not a supported target here, so `:` is
/// always treated as the name/passphrase separator.
pub fn parse_cert_parameter(
    cert_parameter: &str,
) -> Result<(String, Option<String>), ParameterError> {
    if cert_parameter.is_empty() {
        return Err(ParameterError::BlankString);
    }
    let raw = cert_parameter.as_bytes();
    // RFC7512 PKCS#11 URI, or no `:`/`\` at all → whole string is the name.
    let is_pkcs11 = raw.len() >= 7 && raw[..7].eq_ignore_ascii_case(b"pkcs11:");
    let has_sep = raw.iter().any(|&c| c == b':' || c == b'\\');
    if is_pkcs11 || !has_sep {
        return Ok((cert_parameter.to_string(), None));
    }

    let mut certname: Vec<u8> = Vec::with_capacity(raw.len());
    let mut i = 0usize;
    while i < raw.len() {
        // Copy the run of characters that are neither ':' nor '\'.
        let start = i;
        while i < raw.len() && raw[i] != b':' && raw[i] != b'\\' {
            i += 1;
        }
        certname.extend_from_slice(&raw[start..i]);
        if i >= raw.len() {
            break;
        }
        match raw[i] {
            b'\\' => {
                i += 1;
                if i >= raw.len() {
                    // Trailing backslash — keep it literally.
                    certname.push(b'\\');
                    break;
                }
                match raw[i] {
                    b'\\' => {
                        certname.push(b'\\');
                        i += 1;
                    }
                    b':' => {
                        certname.push(b':');
                        i += 1;
                    }
                    other => {
                        certname.push(b'\\');
                        certname.push(other);
                        i += 1;
                    }
                }
            }
            b':' => {
                // Separating colon: the remainder (if any) is the passphrase.
                i += 1;
                let passphrase = if i < raw.len() {
                    Some(String::from_utf8_lossy(&raw[i..]).into_owned())
                } else {
                    None
                };
                let name = String::from_utf8_lossy(&certname).into_owned();
                return Ok((name, passphrase));
            }
            _ => unreachable!("scan stops only at ':' or '\\'"),
        }
    }
    Ok((String::from_utf8_lossy(&certname).into_owned(), None))
}

// ---------------------------------------------------------------------------
// Human-readable size parsing (getunit + GetSizeParameter, tool_getparam.c).
// ---------------------------------------------------------------------------

/// A size-unit suffix: its multiplier and the number of decimal digits in that
/// multiplier (`struct sizeunit`, tool_getparam.c). Used to scale the optional
/// fractional part of a `--limit-rate`/`--max-filesize` value.
struct SizeUnit {
    mul: i64,
    mlen: usize,
}

/// Port of `getunit`: resolve a single (case-insensitive) size-suffix letter to
/// its multiplier. Supports `P`, `T`, `G`, `M`, `K`.
fn getunit(unit: u8) -> Option<SizeUnit> {
    match unit | 0x20 {
        b'p' => Some(SizeUnit {
            mul: 1_125_899_906_842_624,
            mlen: 16,
        }),
        b't' => Some(SizeUnit {
            mul: 1_099_511_627_776,
            mlen: 13,
        }),
        b'g' => Some(SizeUnit {
            mul: 1_073_741_824,
            mlen: 10,
        }),
        b'm' => Some(SizeUnit {
            mul: 1_048_576,
            mlen: 7,
        }),
        b'k' => Some(SizeUnit { mul: 1024, mlen: 4 }),
        _ => None,
    }
}

/// Port of `GetSizeParameter` (tool_getparam.c): parse a size such as `2K`,
/// `1.5M`, `10G` (case-insensitive `P`/`T`/`G`/`M`/`K`, optional trailing `B`)
/// into a byte count. A fractional part is only permitted with a real unit
/// suffix; more than one trailing character, or a fraction without a unit, is
/// [`ParameterError::BadUse`]. Overflow is [`ParameterError::NumberTooLarge`].
pub fn get_size_parameter(arg: &str) -> Result<i64, ParameterError> {
    let (value, rest) = match str_number(arg, CURL_OFF_T_MAX) {
        Ok(v) => v,
        Err(NumScan::Overflow) => return Err(ParameterError::NumberTooLarge),
        Err(NumScan::NoNum) => return Err(ParameterError::BadNumeric),
    };

    let mut prec: i64 = 0;
    let mut plen: usize = 0;
    let mut unit = rest;
    if let Ok(after_dot) = str_single(unit, b'.') {
        let (p, tail) = match str_number(after_dot, CURL_OFF_T_MAX) {
            Ok(v) => v,
            Err(_) => return Err(ParameterError::BadNumeric),
        };
        prec = p;
        plen = after_dot.len() - tail.len();
        unit = tail;
    }

    let mut mul: i64 = 1;
    let mut add: i64 = 0;
    if unit.len() > 1 {
        return Err(ParameterError::BadUse);
    } else if unit.is_empty() || (unit.as_bytes()[0] | 0x20) == b'b' {
        // Bare number or an explicit `B` suffix: a fraction makes no sense.
        if plen != 0 {
            return Err(ParameterError::BadUse);
        }
    } else {
        let su = match getunit(unit.as_bytes()[0]) {
            Some(su) => su,
            None => return Err(ParameterError::BadUse),
        };
        mul = su.mul;
        if prec != 0 {
            let mut frac: i64 = 1;
            let mut prec_v = prec;
            let mut plen_v = plen;
            // Drop fractional digits that exceed the unit's precision.
            while su.mlen <= plen_v {
                prec_v /= 10;
                plen_v -= 1;
            }
            while plen_v > 0 {
                frac *= 10;
                plen_v -= 1;
            }
            if (CURL_OFF_T_MAX / mul) > prec_v {
                add = mul * prec_v / frac;
            } else {
                add = (mul / frac) * prec_v;
            }
        }
    }

    if value > (CURL_OFF_T_MAX - add) / mul {
        return Err(ParameterError::NumberTooLarge);
    }
    Ok(value * mul + add)
}

// ---------------------------------------------------------------------------
// File readers (file2string / file2memory, tool_paramhlp.c). A path of "-"
// reads from standard input, matching the C which is handed an already-open
// FILE* (stdin for "-").
// ---------------------------------------------------------------------------

/// Read the entire contents of `path` (or stdin when `path == "-"`) as raw
/// bytes, up to [`MAX_FILE2MEMORY`]. I/O failures map to
/// [`ParameterError::ReadError`]. This is the shared backend for
/// [`file2string`] and [`file2memory`].
fn read_file_capped(path: &str, cap: u64) -> Result<Vec<u8>, ParameterError> {
    let mut buf: Vec<u8> = Vec::new();
    let read_res = if path == "-" {
        let stdin = std::io::stdin();
        let mut lock = stdin.lock();
        read_all_capped(&mut lock, &mut buf, cap)
    } else {
        match std::fs::File::open(path) {
            Ok(mut f) => read_all_capped(&mut f, &mut buf, cap),
            Err(_) => return Err(ParameterError::ReadError),
        }
    };
    match read_res {
        Ok(()) => Ok(buf),
        Err(()) => Err(ParameterError::ReadError),
    }
}

/// Read from `r` into `buf`, stopping once `cap` bytes have been collected.
/// Any read error is reported as `Err(())`.
fn read_all_capped<R: Read>(r: &mut R, buf: &mut Vec<u8>, cap: u64) -> Result<(), ()> {
    let mut chunk = [0u8; 65536];
    loop {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let room = cap.saturating_sub(buf.len() as u64) as usize;
                let take = n.min(room);
                buf.extend_from_slice(&chunk[..take]);
                if (buf.len() as u64) >= cap {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

/// Port of `file2string` (tool_paramhlp.c): read `path` (or stdin for "-"),
/// stripping every CR and LF byte and concatenating the remainder, capped at
/// [`MAX_FILE2STRING`]. Used for `@file` arguments to string options such as
/// `--variable`.
pub fn file2string(path: &str) -> Result<String, ParameterError> {
    let raw = read_file_capped(path, MAX_FILE2STRING)?;
    let mut out = String::with_capacity(raw.len());
    for &b in &raw {
        if b != b'\r' && b != b'\n' {
            out.push(b as char);
        }
    }
    Ok(out)
}

/// Port of `file2memory` (tool_paramhlp.c): read `path` (or stdin for "-") as raw
/// bytes, unchanged, capped at [`MAX_FILE2MEMORY`]. Used for `@file` arguments to
/// data options such as `--data-binary`.
pub fn file2memory(path: &str) -> Result<Vec<u8>, ParameterError> {
    read_file_capped(path, MAX_FILE2MEMORY)
}

// ---------------------------------------------------------------------------
// slist / header / getout helpers (tool_paramhlp.c).
// ---------------------------------------------------------------------------

/// Port of `add2list`: append `ptr` to a string list. (The C `NO_MEM` outcome
/// cannot occur with a `Vec`, so this is infallible in practice but keeps the
/// `Result` signature for call-site parity.)
pub fn add2list(list: &mut Vec<String>, ptr: &str) -> Result<(), ParameterError> {
    list.push(ptr.to_string());
    Ok(())
}

/// Port of the static `inlist` (tool_paramhlp.c): return `true` when a header
/// named `checkfor` (matched case-insensitively and terminated by `:` or `;`)
/// is already present in `list`.
pub fn inlist(list: &[String], checkfor: &str) -> bool {
    let needle = checkfor.as_bytes();
    let thislen = needle.len();
    for item in list {
        let data = item.as_bytes();
        if data.len() >= thislen
            && data[..thislen].eq_ignore_ascii_case(needle)
            && matches!(data.get(thislen), Some(&b':') | Some(&b';'))
        {
            return true;
        }
    }
    false
}

/// Process-wide monotonically increasing counter for [`new_getout`], mirroring
/// the C `static int outnum` inside `new_getout`.
static OUTNUM: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// Port of `new_getout` (tool_paramhlp.c): append a fresh [`GetOut`] node to the
/// operation's URL list and return its index. `useremote` is seeded from the
/// operation's `remote_name_all`; `num` is assigned from the global counter so
/// download/upload ordering matches curl's.
pub fn new_getout(config: &mut OperationConfig) -> usize {
    let num = OUTNUM.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let idx = config.url_list.len();
    config.url_list.push(GetOut {
        num,
        useremote: config.remote_name_all,
        ..GetOut::default()
    });
    idx
}

/// Delegate a no-echo terminal password read to the crate's `getpass` module
/// (the port of `tool_getpass.c`'s `getpass_r`), used by [`checkpasswd`]. This
/// is the single interactive-input touch-point of the argument parser; the
/// module contains no `unsafe`, so the platform-specific terminal handling lives
/// entirely in `getpass.rs`.
#[inline]
fn passwd_prompt(prompt: &str) -> Option<String> {
    crate::getpass::getpass_r(prompt, 2048)
}

/// Port of the static `checkpasswd` (tool_paramhlp.c): if `userpwd` names a user
/// with no password (no `:` separator and not a bare `;options` string), prompt
/// interactively for the password and fold it into `user:password` form. The
/// prompt text distinguishes the single-URL case from the "URL #N" case exactly
/// as the C does.
fn checkpasswd(kind: &str, i: usize, last: bool, userpwd: &mut Option<String>) {
    let pw = match userpwd.as_deref() {
        Some(p) if !p.is_empty() => p,
        _ => return,
    };
    // Already carries a password, or is a bare `;options` string → nothing to do.
    if pw.contains(':') || pw.starts_with(';') {
        return;
    }
    // The username shown in the prompt excludes any trailing `;options`.
    let user_for_prompt = match pw.find(';') {
        Some(idx) => &pw[..idx],
        None => pw,
    };
    let prompt = if i == 0 && last {
        format!("Enter {kind} password for user '{user_for_prompt}':")
    } else {
        format!(
            "Enter {kind} password for user '{user_for_prompt}' on URL #{}:",
            i + 1
        )
    };
    let passwd = passwd_prompt(&prompt).unwrap_or_default();
    let full = pw.to_string();
    *userpwd = Some(format!("{full}:{passwd}"));
}

/// Port of `get_args` (tool_paramhlp.c): finalize one operation's configuration.
/// When `--json` was used, inject the `Content-Type`/`Accept: application/json`
/// headers unless the user already set them with `-H`. Then, for host and proxy
/// credentials lacking a password, prompt for one via [`checkpasswd`]. `i` is the
/// zero-based operation index and `last` is true for the final operation (used
/// only to shape the password prompt).
pub fn get_args(config: &mut OperationConfig, i: usize, last: bool) -> Result<(), ParameterError> {
    if config.jsoned {
        if !inlist(&config.headers, "Content-Type") {
            add2list(&mut config.headers, "Content-Type: application/json")?;
        }
        if !inlist(&config.headers, "Accept") {
            add2list(&mut config.headers, "Accept: application/json")?;
        }
    }

    if config.userpwd.is_some() && config.oauth_bearer.is_none() {
        checkpasswd("host", i, last, &mut config.userpwd);
    }
    if config.proxyuserpwd.is_some() {
        checkpasswd("proxy", i, last, &mut config.proxyuserpwd);
    }
    Ok(())
}

// ===========================================================================
// Part 8 — special option parsers (the multi-line helpers in tool_getparam.c
// that the per-option dispatch in Part 10 calls). Config-mutating parsers take
// `&mut OperationConfig` plus a `Diag` (captured before the operation borrow);
// global-mutating parsers take `&mut GlobalConfig`.
// ===========================================================================

/// `MAX_DATAURLENCODE` — cap on a single `--data-urlencode` value (tool_getparam.c).
pub const MAX_DATAURLENCODE: u64 = 500 * 1024 * 1024;

/// `MAX_QUERY_LEN` — cap on the assembled `--url-query` string (tool_getparam.c).
pub const MAX_QUERY_LEN: usize = 100_000;

/// Port of `getstr` (tool_getparam.c): replace `*store` with a copy of `val`.
/// With `allowblank == false` an empty `val` is [`ParameterError::BlankString`].
/// (`ALLOW_BLANK` / `DENY_BLANK` are the boolean constants defined above.)
pub fn getstr(
    store: &mut Option<String>,
    val: &str,
    allowblank: bool,
) -> Result<(), ParameterError> {
    *store = None;
    if !allowblank && val.is_empty() {
        return Err(ParameterError::BlankString);
    }
    *store = Some(val.to_string());
    Ok(())
}

/// Uppercase hex digit for a nibble in `0..=15`.
#[inline]
fn hex_upper(n: u8) -> char {
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'A' + (n - 10)) as char
    }
}

/// Port of `curl_easy_escape` (lib/escape.c): percent-encode every byte that is
/// not in the RFC 3986 unreserved set (`ALPHA` / `DIGIT` / `-` `.` `_` `~`) using
/// uppercase `%XX`. Binary-safe (operates on raw bytes).
pub fn url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_upper(b >> 4));
            out.push(hex_upper(b & 0x0f));
        }
    }
    out
}

/// Port of `replace_url_encoded_space_by_plus` (tool_getparam.c): rewrite each
/// `%20` sequence as `+` (used after url-encoding a `--data-urlencode` value).
fn replace_url_encoded_space_by_plus(s: &str) -> String {
    s.replace("%20", "+")
}

/// Port of `data_urlencode` (tool_getparam.c): parse a `name=value`, `name@file`,
/// or bare `value`/`@file` spec, url-encode the value part (leaving the name
/// literal), and return the assembled bytes (`name=<encoded>` when a name is
/// present, otherwise just the encoded value). A leading `@` reads the value
/// from a file (or stdin for `@-`).
fn data_urlencode(diag: Diag, nextarg: &str) -> Result<Vec<u8>, ParameterError> {
    // Locate the name/value separator: '=' takes precedence over '@'.
    let (nlen, is_file, value_part) = if let Some(eq) = nextarg.find('=') {
        (eq, b'=', &nextarg[eq + 1..])
    } else if let Some(at) = nextarg.find('@') {
        (at, b'@', &nextarg[at + 1..])
    } else {
        (0usize, 0u8, nextarg)
    };
    let name = &nextarg[..nlen];

    // Obtain the raw value bytes. For a file source, an empty read reproduces the
    // C's `!postdata` path (result is empty and the name prefix is dropped).
    let (postdata, is_null) = if is_file == b'@' {
        match file2memory(value_part) {
            Ok(v) => {
                let empty = v.is_empty();
                (v, empty)
            }
            Err(_) => {
                errorf(diag, &format!("Failed to open {value_part}"));
                return Err(ParameterError::ReadError);
            }
        }
    } else {
        // getstr(ALLOW_BLANK): never "null", even when empty.
        (value_part.as_bytes().to_vec(), false)
    };

    if is_null {
        return Ok(Vec::new());
    }

    let enc = replace_url_encoded_space_by_plus(&url_encode(&postdata));
    if nlen > 0 {
        let mut result = Vec::with_capacity(name.len() + 1 + enc.len());
        result.extend_from_slice(name.as_bytes());
        result.push(b'=');
        result.extend_from_slice(enc.as_bytes());
        Ok(result)
    } else {
        Ok(enc.into_bytes())
    }
}

/// Port of `sethttpver` (tool_getparam.c): set the HTTP version, warning when it
/// overrides a previously chosen (different) version.
fn sethttpver(diag: Diag, config: &mut OperationConfig, httpversion: i64) {
    if config.httpversion != 0 && config.httpversion != httpversion {
        warnf(diag, "Overrides previous HTTP version option");
    }
    config.httpversion = httpversion;
}

/// Port of `opt_sslver` (tool_getparam.c): set the minimum TLS version, rejecting
/// a value that would exceed an already-set maximum ([`ParameterError::BadUse`]).
fn opt_sslver(diag: Diag, config: &mut OperationConfig, ver: u8) -> Result<(), ParameterError> {
    if config.ssl_version_max != 0 && config.ssl_version_max < ver {
        errorf(diag, "Minimum TLS version set higher than max");
        return Err(ParameterError::BadUse);
    }
    config.ssl_version = ver;
    Ok(())
}

/// Port of `opt_depr` (tool_getparam.c): warn that a deprecated option is a no-op.
fn opt_depr(diag: Diag, lname: &str) {
    warnf(
        diag,
        &format!("--{lname} is deprecated and has no function anymore"),
    );
}

/// Port of `togglebit` (tool_getparam.c): set or clear `bits` in `modify`.
fn togglebit(toggle: bool, modify: &mut u64, bits: u64) {
    if toggle {
        *modify |= bits;
    } else {
        *modify &= !bits;
    }
}

/// Port of `existingfile` (tool_getparam.c): store `filename` only if it exists on
/// disk, else emit an error naming the option and return [`ParameterError::BadUse`].
fn existingfile(
    store: &mut Option<String>,
    diag: Diag,
    lname: &str,
    filename: &str,
) -> Result<(), ParameterError> {
    if std::fs::metadata(filename).is_err() {
        errorf(
            diag,
            &format!("The file '{filename}' provided to --{lname} does not exist"),
        );
        return Err(ParameterError::BadUse);
    }
    getstr(store, filename, DENY_BLANK)
}

/// Port of `GetFileAndPassword` (tool_getparam.c): split a `cert[:passphrase]`
/// argument via [`parse_cert_parameter`], storing the certificate name in `file`
/// and, when present, the passphrase in `password`.
fn get_file_and_password(
    nextarg: &str,
    file: &mut Option<String>,
    password: &mut Option<String>,
) -> Result<(), ParameterError> {
    let (certname, passphrase) = parse_cert_parameter(nextarg)?;
    *file = Some(certname);
    if let Some(pass) = passphrase {
        *password = Some(pass);
    }
    Ok(())
}

/// Which cursor/flag a getout-slot search uses (see [`getout_slot`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum GetoutKind {
    /// The URL cursor (`url_get`), skipping nodes whose `urlset` is already true.
    Url,
    /// The output cursor (`url_out`), skipping nodes whose `outset` is already true.
    Out,
    /// The upload cursor (`url_ul`), skipping nodes whose `uploadset` is already true.
    Upload,
}

/// Shared port of the "find the next unused getout node, else append one" idiom
/// used by `add_url`, `parse_output`, `parse_remote_name`, and
/// `parse_upload_file`. Advances the relevant cursor past already-set nodes and
/// returns the index of the node to populate, creating one via [`new_getout`]
/// when the list is exhausted.
fn getout_slot(config: &mut OperationConfig, kind: GetoutKind) -> usize {
    // Read/initialize the cursor for this kind.
    let cursor = match kind {
        GetoutKind::Url => config.url_get,
        GetoutKind::Out => config.url_out,
        GetoutKind::Upload => config.url_ul,
    };
    let mut idx = match cursor {
        Some(i) => i,
        None => {
            if config.url_list.is_empty() {
                // No nodes yet — append one and point the cursor at it.
                let new = new_getout(config);
                set_getout_cursor(config, kind, Some(new));
                return new;
            }
            0
        }
    };
    // Skip nodes that already have this slot set.
    loop {
        let set = match config.url_list.get(idx) {
            Some(node) => match kind {
                GetoutKind::Url => node.urlset,
                GetoutKind::Out => node.outset,
                GetoutKind::Upload => node.uploadset,
            },
            None => {
                // Walked off the end — append a fresh node.
                let new = new_getout(config);
                set_getout_cursor(config, kind, Some(new));
                return new;
            }
        };
        if set {
            idx += 1;
        } else {
            break;
        }
    }
    set_getout_cursor(config, kind, Some(idx));
    idx
}

/// Assign the cursor field corresponding to `kind`.
#[inline]
fn set_getout_cursor(config: &mut OperationConfig, kind: GetoutKind, v: Option<usize>) {
    match kind {
        GetoutKind::Url => config.url_get = v,
        GetoutKind::Out => config.url_out = v,
        GetoutKind::Upload => config.url_ul = v,
    }
}

/// Port of `add_url` (tool_getparam.c): attach `thisurl` to the next unused
/// getout node (creating one if needed). `remote_noglob` (set when a URL comes
/// from a `--url`/config `@file`) marks the node `useremote` + `noglob`.
/// Enforces the "etag options only work on a single URL" rule.
fn add_url(
    config: &mut OperationConfig,
    diag: Diag,
    thisurl: &str,
    remote_noglob: bool,
) -> Result<(), ParameterError> {
    let idx = getout_slot(config, GetoutKind::Url);
    let blank = thisurl.is_empty();
    {
        let node = &mut config.url_list[idx];
        node.url = if blank {
            None
        } else {
            Some(thisurl.to_string())
        };
        node.urlset = true;
        if remote_noglob {
            node.useremote = true;
            node.noglob = true;
        }
    }
    if !blank {
        config.num_urls += 1;
        if config.num_urls > 1
            && (config.etag_save_file.is_some() || config.etag_compare_file.is_some())
        {
            errorf(diag, "The etag options only work on a single URL");
            return Err(ParameterError::BadUse);
        }
    }
    if blank {
        return Err(ParameterError::BlankString);
    }
    Ok(())
}

/// Port of `parse_url` (tool_getparam.c): handle a `--url` argument. A leading `@`
/// reads URLs one per line from a file (or stdin for `@-`), each added via
/// [`add_url`] with globbing disabled; otherwise the argument is a single URL.
fn parse_url(
    config: &mut OperationConfig,
    diag: Diag,
    nextarg: &str,
) -> Result<(), ParameterError> {
    if let Some(rest) = nextarg.strip_prefix('@') {
        let data = match read_file_capped(rest, MAX_FILE2MEMORY) {
            Ok(v) => v,
            Err(_) => return Err(ParameterError::ReadError),
        };
        // Iterate lines (LF-terminated; a trailing CR is trimmed), matching
        // my_get_line's text-mode read.
        let text = String::from_utf8_lossy(&data);
        for line in text.lines() {
            add_url(config, diag, line, true)?;
        }
        Ok(())
    } else {
        add_url(config, diag, nextarg, false)
    }
}

/// Port of `set_data` (tool_getparam.c): implement the `--data*` family. A leading
/// `@` (for every variant except `--data-raw`) reads the payload from a file (or
/// stdin for `@-`); `--data-urlencode` runs the value through [`data_urlencode`];
/// `--json` sets the `jsoned` flag. Chunks accumulate in `config.postdata`,
/// joined with `&` (except for `--json`, which concatenates verbatim).
fn set_data(
    config: &mut OperationConfig,
    diag: Diag,
    cmd: Cmd,
    nextarg: &str,
) -> Result<(), ParameterError> {
    let postdata: Vec<u8> = if cmd == Cmd::DataUrlencode {
        data_urlencode(diag, nextarg)?
    } else if nextarg.starts_with('@') && cmd != Cmd::DataRaw {
        let path = &nextarg[1..];
        let read = if cmd == Cmd::DataBinary || cmd == Cmd::Json {
            // Binary/JSON: preserve bytes verbatim.
            file2memory(path)
        } else {
            // Text: strip CR/LF as curl does for --data / --data-ascii.
            file2string(path).map(|s| s.into_bytes())
        };
        match read {
            Ok(v) => v,
            Err(_) => {
                errorf(diag, &format!("Failed to open {path}"));
                return Err(ParameterError::ReadError);
            }
        }
    } else {
        // getstr(ALLOW_BLANK): the argument bytes verbatim.
        nextarg.as_bytes().to_vec()
    };

    if cmd == Cmd::Json {
        config.jsoned = true;
    }

    // Join chunks: '&' between successive --data* values, but --json concatenates
    // directly. The separator is only inserted when prior data already exists.
    if !config.postdata.is_empty() && cmd != Cmd::Json {
        config.postdata.push(b'&');
    }
    config.postdata.extend_from_slice(&postdata);
    // `postdata` is the authoritative byte buffer; `postfields` mirrors it as a
    // lossy string view for FFI/setopt consumers.
    config.postfields = Some(String::from_utf8_lossy(&config.postdata).into_owned());
    Ok(())
}

/// Port of `url_query` (tool_getparam.c): implement `--url-query`. A leading `+`
/// appends the remainder literally; otherwise the argument is url-encoded via
/// [`data_urlencode`]. Successive queries are joined with `&`, capped at
/// [`MAX_QUERY_LEN`] ([`ParameterError::BadUse`] on overflow).
fn url_query(
    config: &mut OperationConfig,
    diag: Diag,
    nextarg: &str,
) -> Result<(), ParameterError> {
    let addition: Vec<u8> = if let Some(rest) = nextarg.strip_prefix('+') {
        rest.as_bytes().to_vec()
    } else {
        data_urlencode(diag, nextarg)?
    };

    let mut query = config.query.take().unwrap_or_default().into_bytes();
    if !query.is_empty() {
        query.push(b'&');
    }
    query.extend_from_slice(&addition);
    if query.len() > MAX_QUERY_LEN {
        errorf(diag, "too large --url-query argument");
        return Err(ParameterError::BadUse);
    }
    config.query = Some(String::from_utf8_lossy(&query).into_owned());
    Ok(())
}

/// Port of `set_rate` (tool_getparam.c): parse `--rate` into the inter-transfer
/// delay `global.ms_per_transfer`. The first number is the transfer count
/// (`denominator`); an optional `/<count><unit>` gives the time window
/// (`numerator`, in ms) where the unit is one of `s`/`m`/`h`/`d` (default per
/// hour). The resulting delay is `numerator / denominator`.
fn set_rate(global: &mut GlobalConfig, nextarg: &str) -> Result<(), ParameterError> {
    let diag = global.diag();

    // denominator = number of transfers (must be positive).
    let (denominator, mut rest) =
        str_number(nextarg, CURL_OFF_T_MAX).map_err(|_| ParameterError::BadNumeric)?;
    if denominator < 1 {
        return Err(ParameterError::BadUse);
    }

    // numerator = time window in ms; defaults to one hour.
    let mut numerator: i64 = 60 * 60 * 1000;
    if let Ok(after) = str_single(rest, b'/') {
        rest = after;
        // Optional count of units (defaults to 1 when absent).
        let numunits = match str_number(rest, CURL_OFF_T_MAX) {
            Ok((n, r)) => {
                rest = r;
                n
            }
            Err(_) => 1,
        };
        // A single unit letter selects the base window; trailing bytes are
        // ignored, matching the C `switch(*p)`.
        match rest.as_bytes().first() {
            Some(b's') => numerator = 1000,
            Some(b'm') => numerator = 60 * 1000,
            Some(b'h') => {} // per hour (default, unchanged)
            Some(b'd') => numerator = 24 * 60 * 60 * 1000,
            _ => {
                errorf(diag, "unsupported --rate unit");
                return Err(ParameterError::BadUse);
            }
        }
        if CURL_OFF_T_MAX / numerator < numunits {
            errorf(diag, "too large --rate unit");
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

/// Port of `set_trace_config` (tool_getparam.c): parse a comma-separated trace
/// configuration (`--trace-config`). A leading `+` enables and `-` disables the
/// following token; a bare token enables. `all`/`ids`/`time` (case-insensitive)
/// toggle the corresponding global flags directly; any other token names a
/// library trace domain, recorded in `global.trace_config` exactly as the C hands
/// it to `curl_global_trace` (`+name,-lib-ids` / `-name,-lib-ids`, `all,-lib-ids`
/// for enable-all, and the raw `-all` token for disable-all) for the tracing
/// layer to apply later. Matched token comparisons are length-exact.
fn set_trace_config(global: &mut GlobalConfig, token: &str) {
    for raw in token.split(',') {
        // Empty tokens (e.g. leading/trailing/double commas) are skipped; the C
        // loop's `strchr`/`+1` walk produces the same effect.
        if raw.is_empty() {
            continue;
        }
        let (toggle, name) = match raw.as_bytes()[0] {
            b'-' => (false, &raw[1..]),
            b'+' => (true, &raw[1..]),
            _ => (true, raw),
        };
        if name.eq_ignore_ascii_case("all") {
            global.traceids = toggle;
            global.tracetime = toggle;
            if toggle {
                global.trace_config.push("all,-lib-ids".to_string());
            } else {
                // C passes the raw current token (including its sign) through.
                global.trace_config.push(raw.to_string());
            }
        } else if name.eq_ignore_ascii_case("ids") {
            global.traceids = toggle;
        } else if name.eq_ignore_ascii_case("time") {
            global.tracetime = toggle;
        } else {
            // A library trace domain: record the +/- directive and suppress the
            // library's own ids so the CLI's ids win.
            let sign = if toggle { '+' } else { '-' };
            global.trace_config.push(format!("{sign}{name},-lib-ids"));
        }
    }
}

/// Port of `parse_localport` (tool_getparam.c): parse `--local-port <num>[-num]`.
/// The leading digits are the base port; an optional `- <end>` (blanks allowed
/// around the dash) sets the range end, from which `localportrange` is derived
/// as `end - (localport - 1)`. Any numeric-parse failure maps to
/// [`ParameterError::BadUse`] (matching the C).
fn parse_localport(config: &mut OperationConfig, nextarg: &str) -> Result<(), ParameterError> {
    let b = nextarg.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    let plen = i;

    // Optional " - <end>": one blank, a mandatory dash, one blank, then digits.
    let mut range_str: Option<&str> = None;
    if i < b.len() {
        let mut j = i;
        if j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
            j += 1;
        }
        if j >= b.len() || b[j] != b'-' {
            return Err(ParameterError::BadUse);
        }
        j += 1; // past '-'
        if j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
            j += 1;
        }
        range_str = Some(&nextarg[j..]);
    }

    config.localport = str2unummax(&nextarg[..plen], 65535).map_err(|_| ParameterError::BadUse)?;
    match range_str {
        None => config.localportrange = 1,
        Some(r) => {
            let mut range = str2unummax(r, 65535).map_err(|_| ParameterError::BadUse)?;
            range -= config.localport - 1;
            if range < 1 {
                return Err(ParameterError::BadUse);
            }
            config.localportrange = range;
        }
    }
    Ok(())
}

/// Port of `parse_continue_at` (tool_getparam.c): parse `-C`/`--continue-at`.
/// Mutually exclusive with `--range`, `--remove-on-error`, and `--no-clobber`.
/// A `-` argument resumes at the current output size (`resume_from_current`);
/// otherwise the numeric offset is stored in `resume_from`. `use_resume` is set
/// regardless (mirroring the C, which sets it even on a numeric-parse error).
fn parse_continue_at(
    config: &mut OperationConfig,
    diag: Diag,
    nextarg: &str,
) -> Result<(), ParameterError> {
    if config.range.is_some() {
        errorf(diag, "--continue-at is mutually exclusive with --range");
        return Err(ParameterError::BadUse);
    }
    if config.rm_partial {
        errorf(
            diag,
            "--continue-at is mutually exclusive with --remove-on-error",
        );
        return Err(ParameterError::BadUse);
    }
    if config.file_clobber_mode == ClobberMode::Never {
        errorf(
            diag,
            "--continue-at is mutually exclusive with --no-clobber",
        );
        return Err(ParameterError::BadUse);
    }
    let mut err = Ok(());
    if nextarg != "-" {
        match str2offset(nextarg) {
            Ok(v) => config.resume_from = v,
            Err(e) => err = Err(e),
        }
        config.resume_from_current = false;
    } else {
        config.resume_from_current = true;
        config.resume_from = 0;
    }
    config.use_resume = true;
    err
}

/// Port of `parse_ech` (tool_getparam.c): parse `--ech <config>`. A `pn:` prefix
/// (len > 4) sets the public name; an `ecl:` prefix (len > 5) sets an ECHConfigList
/// either inline or, when written `ecl:@file` (or `ecl:@-` for stdin), read from a
/// file and re-prefixed with `ecl:`; anything else is a keyword stored verbatim.
/// (ECH support is always compiled in this build, so the C `feature_ech` guard is
/// omitted.)
fn parse_ech(
    config: &mut OperationConfig,
    diag: Diag,
    nextarg: &str,
) -> Result<(), ParameterError> {
    let bytes = nextarg.as_bytes();
    if nextarg.len() > 4 && bytes[..3].eq_ignore_ascii_case(b"pn:") {
        // A public_name: stored verbatim (prefix included), matching the C.
        getstr(&mut config.ech_public, nextarg, DENY_BLANK)
    } else if nextarg.len() > 5 && bytes[..4].eq_ignore_ascii_case(b"ecl:") {
        if bytes[4] != b'@' {
            getstr(&mut config.ech_config, nextarg, DENY_BLANK)
        } else {
            // Indirect: read the ECHConfigList from a file (or stdin for "-").
            let path = &nextarg[5..]; // skip "ecl:@"
            match file2string(path) {
                Ok(s) => {
                    config.ech_config = Some(format!("ecl:{s}"));
                    Ok(())
                }
                Err(_) => {
                    warnf(
                        diag,
                        &format!(
                            "Could not read file \"{path}\" specified for \"--ech ecl:\" option"
                        ),
                    );
                    Err(ParameterError::BadUse)
                }
            }
        }
    } else {
        getstr(&mut config.ech, nextarg, DENY_BLANK)
    }
}

/// Port of `parse_header` (tool_getparam.c): implement `-H`/`--header` and
/// `--proxy-header`. A leading `@` reads one header per line from a file (or
/// stdin for `@-`); otherwise the single header is appended, warning when it
/// contains neither `:` nor `;` (i.e. does not look like a header). `cmd`
/// selects the destination list (`proxyheaders` vs `headers`).
fn parse_header(
    config: &mut OperationConfig,
    diag: Diag,
    cmd: Cmd,
    nextarg: &str,
) -> Result<(), ParameterError> {
    if nextarg.as_bytes().first() == Some(&b'@') {
        let path = &nextarg[1..];
        let data = match read_file_capped(path, MAX_FILE2MEMORY) {
            Ok(v) => v,
            Err(_) => {
                errorf(diag, &format!("Failed to open {path}"));
                return Err(ParameterError::ReadError);
            }
        };
        let text = String::from_utf8_lossy(&data);
        for line in text.lines() {
            let list = if cmd == Cmd::ProxyHeader {
                &mut config.proxyheaders
            } else {
                &mut config.headers
            };
            add2list(list, line)?;
        }
        Ok(())
    } else {
        if !nextarg.contains(':') && !nextarg.contains(';') {
            let kind = if cmd == Cmd::ProxyHeader {
                "proxy"
            } else {
                "HTTP"
            };
            warnf(
                diag,
                &format!("The provided {kind} header '{nextarg}' does not look like a header?"),
            );
        }
        let list = if cmd == Cmd::ProxyHeader {
            &mut config.proxyheaders
        } else {
            &mut config.headers
        };
        add2list(list, nextarg)
    }
}

/// Port of `parse_output` (tool_getparam.c): implement `-o`/`--output`. Finds the
/// next getout node without an output target (appending one if needed) and stores
/// `nextarg` as its `outfile`; a `None` argument marks the node as discarding
/// output (`out_null`). Clears `useremote` (an explicit `-o` overrides `-O`).
fn parse_output(config: &mut OperationConfig, nextarg: Option<&str>) -> Result<(), ParameterError> {
    let idx = getout_slot(config, GetoutKind::Out);
    let node = &mut config.url_list[idx];
    let err = match nextarg {
        Some(n) => getstr(&mut node.outfile, n, DENY_BLANK),
        None => {
            node.outfile = None;
            Ok(())
        }
    };
    node.useremote = false;
    node.outset = true;
    node.out_null = nextarg.is_none();
    err
}

/// Port of `parse_remote_name` (tool_getparam.c): implement `-O`/`--remote-name`
/// (and its `--no-remote-name` negation). Selects the next output-free getout node
/// and marks it to derive the local filename from the remote name (`useremote`).
/// A no-op when toggled off and `--remote-name-all` is not in effect.
fn parse_remote_name(config: &mut OperationConfig, toggle: bool) -> Result<(), ParameterError> {
    if !toggle && !config.remote_name_all {
        return Ok(()); // nothing to do
    }
    let idx = getout_slot(config, GetoutKind::Out);
    let node = &mut config.url_list[idx];
    node.outfile = None;
    node.useremote = toggle;
    node.outset = true;
    node.out_null = false;
    Ok(())
}

/// Port of `parse_quote` (tool_getparam.c): implement `-Q`/`--quote`. A leading
/// `-` routes the command to `postquote` (after transfer), a leading `+` to
/// `prequote` (just before transfer), and anything else to `quote` (before
/// transfer). The prefix byte is stripped for the `-`/`+` forms.
fn parse_quote(config: &mut OperationConfig, nextarg: &str) -> Result<(), ParameterError> {
    match nextarg.as_bytes().first() {
        Some(b'-') => add2list(&mut config.postquote, &nextarg[1..]),
        Some(b'+') => add2list(&mut config.prequote, &nextarg[1..]),
        _ => add2list(&mut config.quote, nextarg),
    }
}

/// Port of `parse_range` (tool_getparam.c): implement `-r`/`--range`. Mutually
/// exclusive with `--continue-at`. A bare number with no trailing dash has a `-`
/// appended (with a warning); otherwise the argument is validated to contain only
/// digits, `-`, and `,` (warning on any other character) and stored verbatim.
fn parse_range(
    config: &mut OperationConfig,
    diag: Diag,
    nextarg: &str,
) -> Result<(), ParameterError> {
    if config.use_resume {
        errorf(diag, "--continue-at is mutually exclusive with --range");
        return Err(ParameterError::BadUse);
    }

    // Mirror the C pointer walk: str_number consumes a leading number, then
    // str_single consumes a following '-' when present.
    let mut cur = nextarg;
    let mut value = 0i64;
    let number_ok = match str_number(cur, CURL_OFF_T_MAX) {
        Ok((v, rest)) => {
            value = v;
            cur = rest;
            true
        }
        Err(_) => false,
    };
    let dash_matched = if number_ok {
        match str_single(cur, b'-') {
            Ok(rest) => {
                cur = rest;
                true
            }
            Err(_) => false,
        }
    } else {
        false
    };

    if number_ok && !dash_matched {
        // A range without a dash is not a valid HTTP range; append one.
        warnf(
            diag,
            "A specified range MUST include at least one dash (-). Appending one for you",
        );
        config.range = Some(format!("{value}-"));
        return Ok(());
    }

    // Byte range requested: validate the remaining characters (from the advanced
    // position, as the C does) but store the full original argument.
    for &c in cur.as_bytes() {
        if !c.is_ascii_digit() && c != b'-' && c != b',' {
            warnf(
                diag,
                "Invalid character is found in given range. A specified range MUST have only \
                 digits in 'start'-'stop'. The server's response to this request is uncertain.",
            );
            break;
        }
    }
    getstr(&mut config.range, nextarg, DENY_BLANK)
}

/// Port of `parse_upload_file` (tool_getparam.c): implement `-T`/`--upload-file`.
/// Marks the next upload-free getout node as an upload; an empty argument means
/// "no upload" (`noupload`), otherwise `nextarg` (with `-` denoting stdin) is
/// stored as the node's `infile`.
fn parse_upload_file(config: &mut OperationConfig, nextarg: &str) -> Result<(), ParameterError> {
    let idx = getout_slot(config, GetoutKind::Upload);
    let node = &mut config.url_list[idx];
    node.uploadset = true;
    if nextarg.is_empty() {
        node.noupload = true;
        Ok(())
    } else {
        getstr(&mut node.infile, nextarg, DENY_BLANK)
    }
}

/// Per-`getparameter`-call counter of how many times `-v` has been seen within a
/// single bundled short-option argument (e.g. `-vvv`), mirroring the C file-scoped
/// `verbose_nopts`. Reset to zero at the top of [`getparameter`]; incremented in
/// the short-option loop. Governs the "first `-v` resets to base verbosity" rule.
static VERBOSE_NOPTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Port of `parse_verbose` (tool_getparam.c): implement the super-boolean `-v`/
/// `--verbose` (and `--no-verbose`). Toggling off resets verbosity and disables
/// tracing. Each successive `-v` in one argument escalates the verbosity level
/// (0→1 plain trace to stderr, 1→2 ids/time/protocol, 2→3 ASCII ssl/read/write,
/// 3→4 network), recording the library trace directives via [`set_trace_config`].
fn parse_verbose(global: &mut GlobalConfig, toggle: bool) -> Result<(), ParameterError> {
    let diag = global.diag();

    if !toggle {
        global.verbosity = 0;
        set_trace_config(global, "-all");
        global.tracetype = TraceType::None;
        return Ok(());
    } else if VERBOSE_NOPTS.load(std::sync::atomic::Ordering::Relaxed) == 0 {
        // First `-v` in an argument resets to base verbosity.
        global.verbosity = 0;
        if !global.trace_set {
            set_trace_config(global, "-all");
        }
    }

    // The `%` sink causes the trace to be written to stderr.
    match global.verbosity {
        0 => {
            global.verbosity = 1;
            global.trace_dump = Some("%".to_string());
            if global.tracetype != TraceType::None && global.tracetype != TraceType::Plain {
                warnf(diag, "-v, --verbose overrides an earlier trace option");
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
        _ => {} // no further effect
    }
    Ok(())
}

/// Port of `parse_writeout` (tool_getparam.c): implement `-w`/`--write-out`. A
/// leading `@` reads the format from a file (or stdin for `@-`); an inline value
/// is stored verbatim (blanks allowed). A real file that cannot be opened yields
/// an error naming the file and [`ParameterError::ReadError`].
fn parse_writeout(
    config: &mut OperationConfig,
    diag: Diag,
    nextarg: &str,
) -> Result<(), ParameterError> {
    if let Some(arg) = nextarg.strip_prefix('@') {
        if arg == "-" {
            // stdin: cannot fail to "open"; a read failure is a plain read error.
            let s = file2string("-")?;
            config.writeout = Some(s);
            Ok(())
        } else {
            // Distinguish an open failure so the exact message can be emitted.
            if fs::File::open(arg).is_err() {
                errorf(diag, &format!("Failed to open {arg}"));
                return Err(ParameterError::ReadError);
            }
            let s = file2string(arg)?;
            config.writeout = Some(s);
            Ok(())
        }
    } else {
        getstr(&mut config.writeout, nextarg, ALLOW_BLANK)
    }
}

/// Port of `curl_getdate` (lib/parsedate.c) sufficient for `-z`/`--time-cond`:
/// parse an absolute date string in the formats curl accepts (RFC 822/1123,
/// RFC 850, ANSI C `asctime`, and ISO-8601 variants, with GMT/UTC or a numeric
/// offset, or date-only at midnight UTC) into a Unix timestamp. Returns `None`
/// when no format matches (the caller then treats the argument as a filename).
fn curl_getdate(s: &str) -> Option<i64> {
    use chrono::{DateTime, NaiveDate, NaiveDateTime};

    let t = s.trim();
    if t.is_empty() {
        return None;
    }

    // Formats carrying an explicit zone/offset.
    if let Ok(dt) = DateTime::parse_from_rfc2822(t) {
        return Some(dt.timestamp());
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(t) {
        return Some(dt.timestamp());
    }
    const OFFSET_FMTS: &[&str] = &[
        "%a, %d %b %Y %H:%M:%S %z",
        "%d %b %Y %H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%z",
    ];
    for fmt in OFFSET_FMTS {
        if let Ok(dt) = DateTime::parse_from_str(t, fmt) {
            return Some(dt.timestamp());
        }
    }

    // Zone-less formats, interpreted as UTC (curl treats a missing zone as GMT).
    const NAIVE_FMTS: &[&str] = &[
        "%a, %d %b %Y %H:%M:%S GMT",
        "%a, %d %b %Y %H:%M:%S",
        "%d %b %Y %H:%M:%S GMT",
        "%d %b %Y %H:%M:%S",
        "%A, %d-%b-%y %H:%M:%S GMT", // RFC 850
        "%A, %d-%b-%y %H:%M:%S",
        "%a %b %e %H:%M:%S %Y", // ANSI C asctime()
        "%b %e %H:%M:%S %Y",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y%m%dT%H%M%S",
    ];
    for fmt in NAIVE_FMTS {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(t, fmt) {
            return Some(ndt.and_utc().timestamp());
        }
    }

    // Date-only forms default to midnight UTC.
    const DATE_FMTS: &[&str] = &["%Y-%m-%d", "%d %b %Y", "%d-%b-%Y", "%d-%b-%y"];
    for fmt in DATE_FMTS {
        if let Ok(nd) = NaiveDate::parse_from_str(t, fmt) {
            if let Some(ndt) = nd.and_hms_opt(0, 0, 0) {
                return Some(ndt.and_utc().timestamp());
            }
        }
    }

    None
}

/// Port of `getfiletime` (tool_filetime.c, non-Windows path): return the file's
/// modification time as seconds since the Unix epoch, or `None` (with a warning)
/// when the file cannot be stat'd. Pre-epoch timestamps are returned as negatives.
fn getfiletime(filename: &str, diag: Diag) -> Option<i64> {
    match fs::metadata(filename).and_then(|m| m.modified()) {
        Ok(mtime) => match mtime.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => Some(d.as_secs() as i64),
            Err(e) => Some(-(e.duration().as_secs() as i64)),
        },
        Err(e) => {
            warnf(diag, &format!("Failed to get filetime: {e}"));
            None
        }
    }
}

/// Port of `parse_time_cond` (tool_getparam.c): implement `-z`/`--time-cond`. A
/// leading `+`/none selects If-Modified-Since, `-` selects If-Unmodified-Since,
/// and `=` selects Last-Modified. The remaining text is parsed as a date via
/// [`curl_getdate`]; failing that, as a filename via [`getfiletime`]; failing both,
/// the time condition is disabled with a warning.
fn parse_time_cond(
    config: &mut OperationConfig,
    diag: Diag,
    nextarg: &str,
) -> Result<(), ParameterError> {
    let arg = match nextarg.as_bytes().first() {
        Some(b'+') => {
            config.timecond = curlabi::CURL_TIMECOND_IFMODSINCE;
            &nextarg[1..]
        }
        Some(b'-') => {
            config.timecond = curlabi::CURL_TIMECOND_IFUNMODSINCE;
            &nextarg[1..]
        }
        Some(b'=') => {
            config.timecond = curlabi::CURL_TIMECOND_LASTMOD;
            &nextarg[1..]
        }
        _ => {
            config.timecond = curlabi::CURL_TIMECOND_IFMODSINCE;
            nextarg
        }
    };

    match curl_getdate(arg) {
        Some(t) => config.condtime = t,
        None => match getfiletime(arg, diag) {
            Some(v) => config.condtime = v,
            None => {
                config.timecond = curlabi::CURL_TIMECOND_NONE;
                warnf(
                    diag,
                    "Illegal date format for -z, --time-cond (and not a filename). \
                     Disabling time condition. See curl_getdate(3) for valid date syntax.",
                );
            }
        },
    }
    Ok(())
}

/// Port of `parse_upload_flags` (tool_getparam.c): implement `--upload-flags`, a
/// comma-separated list of IMAP APPEND flags (`answered`, `deleted`, `draft`,
/// `flagged`, `seen`), each optionally prefixed with `-` to clear it. An
/// unrecognized token is [`ParameterError::OptionUnknown`].
fn parse_upload_flags(config: &mut OperationConfig, flag: &str) -> Result<(), ParameterError> {
    for token in flag.split(',') {
        let (negate, name) = match token.as_bytes().first() {
            Some(b'-') => (true, &token[1..]),
            _ => (false, token),
        };
        let bit = match name {
            "answered" => curlabi::CURLULFLAG_ANSWERED,
            "deleted" => curlabi::CURLULFLAG_DELETED,
            "draft" => curlabi::CURLULFLAG_DRAFT,
            "flagged" => curlabi::CURLULFLAG_FLAGGED,
            "seen" => curlabi::CURLULFLAG_SEEN,
            _ => return Err(ParameterError::OptionUnknown),
        };
        if negate {
            config.upload_flags &= !bit;
        } else {
            config.upload_flags |= bit;
        }
    }
    Ok(())
}

// ===========================================================================
// Part 9 — the option table: command ids, option rows, and name lookups
// ===========================================================================

/// The per-option command identifier, one variant per supported command-line
/// option — the Rust analog of curl's `cmdline_t` enum (`tool_getparam.h`). The
/// variant is carried in each [`OptDef`] row and matched in [`getparameter`] to
/// apply the option to the configuration.
///
/// Three `cmdline_t` values are intentionally absent (matching [`OPTIONS`]): the
/// `#ifdef DEBUGBUILD` `C_TEST_DUPHANDLE`/`C_TEST_EVENT` (dropped per AAP §0.2.2)
/// and the `#ifdef USE_WATT32` `C_WDEBUG` (a legacy DOS/Watt-32 platform, out of
/// scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    AbstractUnixSocket,
    Alpn,
    AltSvc,
    Anyauth,
    Append,
    AwsSigv4,
    Basic,
    Buffer,
    CaNative,
    Cacert,
    Capath,
    Cert,
    CertStatus,
    CertType,
    Ciphers,
    Clobber,
    Compressed,
    CompressedSsh,
    Config,
    ConnectTimeout,
    ConnectTo,
    ContinueAt,
    Cookie,
    CookieJar,
    CreateDirs,
    CreateFileMode,
    Crlf,
    Crlfile,
    Curves,
    Data,
    DataAscii,
    DataBinary,
    DataRaw,
    DataUrlencode,
    Delegation,
    Digest,
    Disable,
    DisableEprt,
    DisableEpsv,
    DisallowUsernameInUrl,
    DnsInterface,
    DnsIpv4Addr,
    DnsIpv6Addr,
    DnsServers,
    DohCertStatus,
    DohInsecure,
    DohUrl,
    DumpCaEmbed,
    DumpHeader,
    Ech,
    EgdFile,
    Engine,
    Eprt,
    Epsv,
    EtagCompare,
    EtagSave,
    Expect100Timeout,
    Fail,
    FailEarly,
    FailWithBody,
    FalseStart,
    Follow,
    Form,
    FormEscape,
    FormString,
    FtpAccount,
    FtpAlternativeToUser,
    FtpCreateDirs,
    FtpMethod,
    FtpPasv,
    FtpPort,
    FtpPret,
    FtpSkipPasvIp,
    FtpSsl,
    FtpSslCcc,
    FtpSslCccMode,
    FtpSslControl,
    FtpSslReqd,
    Get,
    Globoff,
    HappyEyeballsTimeoutMs,
    HaproxyClientip,
    HaproxyProtocol,
    Head,
    Header,
    Help,
    Hostpubmd5,
    Hostpubsha256,
    Hsts,
    Http09,
    Http10,
    Http11,
    Http2,
    Http2PriorKnowledge,
    Http3,
    Http3Only,
    IgnoreContentLength,
    Include,
    Insecure,
    Interface,
    IpTos,
    IpfsGateway,
    Ipv4,
    Ipv6,
    Json,
    JunkSessionCookies,
    Keepalive,
    KeepaliveCnt,
    KeepaliveTime,
    Key,
    KeyType,
    Knownhosts,
    Krb,
    Krb4,
    Libcurl,
    LimitRate,
    ListOnly,
    LocalPort,
    Location,
    LocationTrusted,
    LoginOptions,
    MailAuth,
    MailFrom,
    MailRcpt,
    MailRcptAllowfails,
    Manual,
    MaxFilesize,
    MaxRedirs,
    MaxTime,
    Metalink,
    Mptcp,
    Negotiate,
    Netrc,
    NetrcFile,
    NetrcOptional,
    Next,
    Noproxy,
    Npn,
    Ntlm,
    NtlmWb,
    Oauth2Bearer,
    OutNull,
    Output,
    OutputDir,
    Parallel,
    ParallelImmediate,
    ParallelMax,
    ParallelHost,
    Pass,
    PathAsIs,
    Pinnedpubkey,
    Post301,
    Post302,
    Post303,
    Preproxy,
    ProgressBar,
    ProgressMeter,
    Proto,
    ProtoDefault,
    ProtoRedir,
    Proxy,
    ProxyAnyauth,
    ProxyBasic,
    ProxyCaNative,
    ProxyCacert,
    ProxyCapath,
    ProxyCert,
    ProxyCertType,
    ProxyCiphers,
    ProxyCrlfile,
    ProxyDigest,
    ProxyHeader,
    ProxyHttp2,
    ProxyInsecure,
    ProxyKey,
    ProxyKeyType,
    ProxyNegotiate,
    ProxyNtlm,
    ProxyPass,
    ProxyPinnedpubkey,
    ProxyServiceName,
    ProxySslAllowBeast,
    ProxySslAutoClientCert,
    ProxyTls13Ciphers,
    ProxyTlsauthtype,
    ProxyTlspassword,
    ProxyTlsuser,
    ProxyTlsv1,
    ProxyUser,
    Proxy10,
    Proxytunnel,
    Pubkey,
    Quote,
    RandomFile,
    Range,
    Rate,
    Raw,
    Referer,
    RemoteHeaderName,
    RemoteName,
    RemoteNameAll,
    RemoteTime,
    RemoveOnError,
    Request,
    RequestTarget,
    Resolve,
    Retry,
    RetryAllErrors,
    RetryConnrefused,
    RetryDelay,
    RetryMaxTime,
    SaslAuthzid,
    SaslIr,
    ServiceName,
    Sessionid,
    ShowError,
    ShowHeaders,
    SignatureAlgorithms,
    Silent,
    SkipExisting,
    Socks4,
    Socks4a,
    Socks5,
    Socks5Basic,
    Socks5Gssapi,
    Socks5GssapiNec,
    Socks5GssapiService,
    Socks5Hostname,
    SpeedLimit,
    SpeedTime,
    Ssl,
    SslAllowBeast,
    SslAutoClientCert,
    SslNoRevoke,
    SslReqd,
    SslRevokeBestEffort,
    SslSessions,
    Sslv2,
    Sslv3,
    Stderr,
    StyledOutput,
    SuppressConnectHeaders,
    TcpFastopen,
    TcpNodelay,
    TelnetOption,
    TftpBlksize,
    TftpNoOptions,
    TimeCond,
    TlsEarlydata,
    TlsMax,
    Tls13Ciphers,
    Tlsauthtype,
    Tlspassword,
    Tlsuser,
    Tlsv1,
    Tlsv10,
    Tlsv11,
    Tlsv12,
    Tlsv13,
    TrEncoding,
    Trace,
    TraceAscii,
    TraceConfig,
    TraceIds,
    TraceTime,
    UnixSocket,
    UploadFile,
    UploadFlags,
    Url,
    UrlQuery,
    UseAscii,
    User,
    UserAgent,
    Variable,
    Verbose,
    Version,
    VlanPriority,
    WriteOut,
    Xattr,
}

/// A single row of the option table: the Rust analog of curl's `struct LongShort`
/// (`tool_getparam.h`) enriched with the `docs/cmdline-opts` front-matter fields
/// (`arg` placeholder, `help` text, `Multi:` behavior) so one table drives both the
/// parser and the `clap`-based `--help` renderer.
#[derive(Debug, Clone, Copy)]
pub struct OptDef {
    /// Long option name without leading dashes (C `LongShort.lname`).
    pub lname: &'static str,
    /// Short option as an ASCII byte, or `0` for none (C `LongShort.letter`, where
    /// `' '` denotes "no short letter").
    pub letter: u8,
    /// Argument-taking kind (`ARGTYPE(LongShort.desc)`).
    pub typ: ArgType,
    /// `ARG_*` flag bits beyond the type (`ARG_NO`/`ARG_CLEAR`/`ARG_TLS`/`ARG_DEPR`).
    pub flags: u8,
    /// Command id (C `LongShort.cmd`), dispatched in [`getparameter`].
    pub cmd: Cmd,
    /// `Multi:` combine behavior from the option's `docs/cmdline-opts` page.
    pub multi: Multi,
    /// Value placeholder shown in help (e.g. `<file>`); empty when no argument.
    pub arg: &'static str,
    /// One-line help text, preserved verbatim for `--help` parity.
    pub help: &'static str,
}

/// Const constructor for an [`OptDef`] row, keeping the [`OPTIONS`] table terse.
#[allow(clippy::too_many_arguments)]
const fn od(
    lname: &'static str,
    letter: u8,
    typ: ArgType,
    flags: u8,
    cmd: Cmd,
    multi: Multi,
    arg: &'static str,
    help: &'static str,
) -> OptDef {
    OptDef {
        lname,
        letter,
        typ,
        flags,
        cmd,
        multi,
        arg,
        help,
    }
}

/// The complete curl 8.19.0-DEV command-line option table — one row per option,
/// alphasorted by long name exactly like the C `aliases[]` array (`tool_getparam.c`).
///
/// This is the frozen flag surface (AAP §0.7.1): 279 options for the four target
/// platforms in a release build. The three `aliases[]` rows absent here are the two
/// `#ifdef DEBUGBUILD` test options (`--test-duphandle`, `--test-event`; dropped per
/// AAP §0.2.2) and the `#ifdef USE_WATT32` `--wdebug` (a DOS/Watt-32 legacy platform,
/// out of scope per AAP §0.2.2). No other flag is added, removed, or renamed.
pub static OPTIONS: &[OptDef] = &[
    od(
        "abstract-unix-socket",
        0,
        ArgType::File,
        0,
        Cmd::AbstractUnixSocket,
        Multi::Single,
        "<path>",
        "Connect via abstract Unix domain socket",
    ),
    od(
        "alpn",
        0,
        ArgType::Bool,
        ARG_NO | ARG_TLS,
        Cmd::Alpn,
        Multi::Boolean,
        "",
        "Disable the ALPN TLS extension",
    ),
    od(
        "alt-svc",
        0,
        ArgType::Strg,
        0,
        Cmd::AltSvc,
        Multi::Append,
        "<filename>",
        "Enable alt-svc with this cache file",
    ),
    od(
        "anyauth",
        0,
        ArgType::None_,
        0,
        Cmd::Anyauth,
        Multi::Custom,
        "",
        "Pick any authentication method",
    ),
    od(
        "append",
        b'a',
        ArgType::Bool,
        0,
        Cmd::Append,
        Multi::Boolean,
        "",
        "Append to target file when uploading",
    ),
    od(
        "aws-sigv4",
        0,
        ArgType::Strg,
        0,
        Cmd::AwsSigv4,
        Multi::Single,
        "<provider1[:prvdr2[:reg[:srv]]]>",
        "AWS V4 signature auth",
    ),
    od(
        "basic",
        0,
        ArgType::Bool,
        0,
        Cmd::Basic,
        Multi::Boolean,
        "",
        "HTTP Basic Authentication",
    ),
    od(
        "buffer",
        b'N',
        ArgType::Bool,
        ARG_NO,
        Cmd::Buffer,
        Multi::Boolean,
        "",
        "Disable buffering of the output stream",
    ),
    od(
        "ca-native",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::CaNative,
        Multi::Boolean,
        "",
        "Load CA certs from the OS",
    ),
    od(
        "cacert",
        0,
        ArgType::File,
        ARG_TLS,
        Cmd::Cacert,
        Multi::Single,
        "<file>",
        "CA certificate to verify peer against",
    ),
    od(
        "capath",
        0,
        ArgType::File,
        ARG_TLS,
        Cmd::Capath,
        Multi::Single,
        "<dir>",
        "CA directory to verify peer against",
    ),
    od(
        "cert",
        b'E',
        ArgType::File,
        ARG_CLEAR | ARG_TLS,
        Cmd::Cert,
        Multi::Single,
        "<certificate[:password]>",
        "Client certificate file and password",
    ),
    od(
        "cert-status",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::CertStatus,
        Multi::Boolean,
        "",
        "Verify server cert status OCSP-staple",
    ),
    od(
        "cert-type",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::CertType,
        Multi::Single,
        "<type>",
        "Certificate type (DER/PEM/ENG/PROV/P12)",
    ),
    od(
        "ciphers",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::Ciphers,
        Multi::Single,
        "<list>",
        "TLS 1.2 (1.1, 1.0) ciphers to use",
    ),
    od(
        "clobber",
        0,
        ArgType::Bool,
        ARG_NO,
        Cmd::Clobber,
        Multi::Boolean,
        "",
        "Do not overwrite files that already exist",
    ),
    od(
        "compressed",
        0,
        ArgType::Bool,
        0,
        Cmd::Compressed,
        Multi::Boolean,
        "",
        "Request compressed response",
    ),
    od(
        "compressed-ssh",
        0,
        ArgType::Bool,
        0,
        Cmd::CompressedSsh,
        Multi::Boolean,
        "",
        "Enable SSH compression",
    ),
    od(
        "config",
        b'K',
        ArgType::File,
        0,
        Cmd::Config,
        Multi::Append,
        "<file>",
        "Read config from a file",
    ),
    od(
        "connect-timeout",
        0,
        ArgType::Strg,
        0,
        Cmd::ConnectTimeout,
        Multi::Single,
        "<seconds>",
        "Maximum time allowed to connect",
    ),
    od(
        "connect-to",
        0,
        ArgType::Strg,
        0,
        Cmd::ConnectTo,
        Multi::Append,
        "<HOST1:PORT1:HOST2:PORT2>",
        "Connect to host2 instead of host1",
    ),
    od(
        "continue-at",
        b'C',
        ArgType::Strg,
        0,
        Cmd::ContinueAt,
        Multi::Single,
        "<offset>",
        "Resumed transfer offset",
    ),
    od(
        "cookie",
        b'b',
        ArgType::Strg,
        0,
        Cmd::Cookie,
        Multi::Append,
        "<data|filename>",
        "Send cookies from string/load from file",
    ),
    od(
        "cookie-jar",
        b'c',
        ArgType::Strg,
        0,
        Cmd::CookieJar,
        Multi::Single,
        "<filename>",
        "Save cookies to <filename> after operation",
    ),
    od(
        "create-dirs",
        0,
        ArgType::Bool,
        0,
        Cmd::CreateDirs,
        Multi::Boolean,
        "",
        "Create necessary local directory hierarchy",
    ),
    od(
        "create-file-mode",
        0,
        ArgType::Strg,
        0,
        Cmd::CreateFileMode,
        Multi::Single,
        "<mode>",
        "File mode for created files",
    ),
    od(
        "crlf",
        0,
        ArgType::Bool,
        0,
        Cmd::Crlf,
        Multi::Boolean,
        "",
        "Convert LF to CRLF in upload",
    ),
    od(
        "crlfile",
        0,
        ArgType::File,
        ARG_TLS,
        Cmd::Crlfile,
        Multi::Single,
        "<file>",
        "Certificate Revocation list",
    ),
    od(
        "curves",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::Curves,
        Multi::Single,
        "<list>",
        "(EC) TLS key exchange algorithms to request",
    ),
    od(
        "data",
        b'd',
        ArgType::Strg,
        0,
        Cmd::Data,
        Multi::Append,
        "<data>",
        "HTTP POST data",
    ),
    od(
        "data-ascii",
        0,
        ArgType::Strg,
        0,
        Cmd::DataAscii,
        Multi::Append,
        "<data>",
        "HTTP POST ASCII data",
    ),
    od(
        "data-binary",
        0,
        ArgType::Strg,
        0,
        Cmd::DataBinary,
        Multi::Append,
        "<data>",
        "HTTP POST binary data",
    ),
    od(
        "data-raw",
        0,
        ArgType::Strg,
        0,
        Cmd::DataRaw,
        Multi::Append,
        "<data>",
        "HTTP POST data, '@' allowed",
    ),
    od(
        "data-urlencode",
        0,
        ArgType::Strg,
        0,
        Cmd::DataUrlencode,
        Multi::Append,
        "<data>",
        "HTTP POST data URL encoded",
    ),
    od(
        "delegation",
        0,
        ArgType::Strg,
        0,
        Cmd::Delegation,
        Multi::Single,
        "<LEVEL>",
        "GSS-API delegation permission",
    ),
    od(
        "digest",
        0,
        ArgType::Bool,
        0,
        Cmd::Digest,
        Multi::Boolean,
        "",
        "HTTP Digest Authentication",
    ),
    od(
        "disable",
        b'q',
        ArgType::Bool,
        0,
        Cmd::Disable,
        Multi::Boolean,
        "",
        "Disable .curlrc",
    ),
    od(
        "disable-eprt",
        0,
        ArgType::Bool,
        0,
        Cmd::DisableEprt,
        Multi::Boolean,
        "",
        "Inhibit using EPRT or LPRT",
    ),
    od(
        "disable-epsv",
        0,
        ArgType::Bool,
        0,
        Cmd::DisableEpsv,
        Multi::Boolean,
        "",
        "Inhibit using EPSV",
    ),
    od(
        "disallow-username-in-url",
        0,
        ArgType::Bool,
        0,
        Cmd::DisallowUsernameInUrl,
        Multi::Boolean,
        "",
        "Disallow username in URL",
    ),
    od(
        "dns-interface",
        0,
        ArgType::Strg,
        0,
        Cmd::DnsInterface,
        Multi::Single,
        "<interface>",
        "Interface to use for DNS requests",
    ),
    od(
        "dns-ipv4-addr",
        0,
        ArgType::Strg,
        0,
        Cmd::DnsIpv4Addr,
        Multi::Single,
        "<address>",
        "IPv4 address to use for DNS requests",
    ),
    od(
        "dns-ipv6-addr",
        0,
        ArgType::Strg,
        0,
        Cmd::DnsIpv6Addr,
        Multi::Single,
        "<address>",
        "IPv6 address to use for DNS requests",
    ),
    od(
        "dns-servers",
        0,
        ArgType::Strg,
        0,
        Cmd::DnsServers,
        Multi::Single,
        "<addresses>",
        "DNS server addrs to use",
    ),
    od(
        "doh-cert-status",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::DohCertStatus,
        Multi::Boolean,
        "",
        "Verify DoH server cert status OCSP-staple",
    ),
    od(
        "doh-insecure",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::DohInsecure,
        Multi::Boolean,
        "",
        "Allow insecure DoH server connections",
    ),
    od(
        "doh-url",
        0,
        ArgType::Strg,
        0,
        Cmd::DohUrl,
        Multi::Single,
        "<URL>",
        "Resolve hostnames over DoH",
    ),
    od(
        "dump-ca-embed",
        0,
        ArgType::None_,
        ARG_TLS,
        Cmd::DumpCaEmbed,
        Multi::Boolean,
        "",
        "Write the embedded CA bundle to standard output",
    ),
    od(
        "dump-header",
        b'D',
        ArgType::File,
        0,
        Cmd::DumpHeader,
        Multi::Single,
        "<filename>",
        "Write the received headers to <filename>",
    ),
    od(
        "ech",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::Ech,
        Multi::Single,
        "<config>",
        "Configure ECH",
    ),
    od(
        "egd-file",
        0,
        ArgType::Strg,
        ARG_DEPR,
        Cmd::EgdFile,
        Multi::Single,
        "<file>",
        "EGD socket path for random data",
    ),
    od(
        "engine",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::Engine,
        Multi::Single,
        "<name>",
        "Crypto engine to use",
    ),
    od(
        "eprt",
        0,
        ArgType::Bool,
        0,
        Cmd::Eprt,
        Multi::Boolean,
        "",
        "Inhibit using EPRT or LPRT",
    ),
    od(
        "epsv",
        0,
        ArgType::Bool,
        0,
        Cmd::Epsv,
        Multi::Boolean,
        "",
        "Inhibit using EPSV",
    ),
    od(
        "etag-compare",
        0,
        ArgType::File,
        0,
        Cmd::EtagCompare,
        Multi::Single,
        "<file>",
        "Load ETag from file",
    ),
    od(
        "etag-save",
        0,
        ArgType::File,
        0,
        Cmd::EtagSave,
        Multi::Single,
        "<file>",
        "Parse incoming ETag and save to a file",
    ),
    od(
        "expect100-timeout",
        0,
        ArgType::Strg,
        0,
        Cmd::Expect100Timeout,
        Multi::Single,
        "<seconds>",
        "How long to wait for 100-continue",
    ),
    od(
        "fail",
        b'f',
        ArgType::Bool,
        0,
        Cmd::Fail,
        Multi::Boolean,
        "",
        "Fail fast with no output on HTTP errors",
    ),
    od(
        "fail-early",
        0,
        ArgType::Bool,
        0,
        Cmd::FailEarly,
        Multi::Boolean,
        "",
        "Fail on first transfer error",
    ),
    od(
        "fail-with-body",
        0,
        ArgType::Bool,
        0,
        Cmd::FailWithBody,
        Multi::Boolean,
        "",
        "Fail on HTTP errors but save the body",
    ),
    od(
        "false-start",
        0,
        ArgType::Bool,
        0,
        Cmd::FalseStart,
        Multi::Boolean,
        "",
        "Enable TLS False Start",
    ),
    od(
        "follow",
        0,
        ArgType::Bool,
        0,
        Cmd::Follow,
        Multi::Boolean,
        "",
        "Follow redirects per spec",
    ),
    od(
        "form",
        b'F',
        ArgType::Strg,
        0,
        Cmd::Form,
        Multi::Append,
        "<name=content>",
        "Specify multipart MIME data",
    ),
    od(
        "form-escape",
        0,
        ArgType::Bool,
        0,
        Cmd::FormEscape,
        Multi::Single,
        "",
        "Escape form fields using backslash",
    ),
    od(
        "form-string",
        0,
        ArgType::Strg,
        0,
        Cmd::FormString,
        Multi::Append,
        "<name=string>",
        "Specify multipart MIME data",
    ),
    od(
        "ftp-account",
        0,
        ArgType::Strg,
        0,
        Cmd::FtpAccount,
        Multi::Single,
        "<data>",
        "Account data string",
    ),
    od(
        "ftp-alternative-to-user",
        0,
        ArgType::Strg,
        0,
        Cmd::FtpAlternativeToUser,
        Multi::Single,
        "<command>",
        "String to replace USER [name]",
    ),
    od(
        "ftp-create-dirs",
        0,
        ArgType::Bool,
        0,
        Cmd::FtpCreateDirs,
        Multi::Boolean,
        "",
        "Create the remote dirs if not present",
    ),
    od(
        "ftp-method",
        0,
        ArgType::Strg,
        0,
        Cmd::FtpMethod,
        Multi::Single,
        "<method>",
        "Control CWD usage",
    ),
    od(
        "ftp-pasv",
        0,
        ArgType::None_,
        0,
        Cmd::FtpPasv,
        Multi::Mutex,
        "",
        "Send PASV/EPSV instead of PORT",
    ),
    od(
        "ftp-port",
        b'P',
        ArgType::Strg,
        0,
        Cmd::FtpPort,
        Multi::Single,
        "<address>",
        "Send PORT instead of PASV",
    ),
    od(
        "ftp-pret",
        0,
        ArgType::Bool,
        0,
        Cmd::FtpPret,
        Multi::Boolean,
        "",
        "Send PRET before PASV",
    ),
    od(
        "ftp-skip-pasv-ip",
        0,
        ArgType::Bool,
        0,
        Cmd::FtpSkipPasvIp,
        Multi::Boolean,
        "",
        "Skip the IP address for PASV",
    ),
    od(
        "ftp-ssl",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::FtpSsl,
        Multi::Boolean,
        "",
        "Try enabling TLS",
    ),
    od(
        "ftp-ssl-ccc",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::FtpSslCcc,
        Multi::Boolean,
        "",
        "Send CCC after authenticating",
    ),
    od(
        "ftp-ssl-ccc-mode",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::FtpSslCccMode,
        Multi::Boolean,
        "<active/passive>",
        "Set CCC mode",
    ),
    od(
        "ftp-ssl-control",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::FtpSslControl,
        Multi::Boolean,
        "",
        "Require TLS for login, clear for transfer",
    ),
    od(
        "ftp-ssl-reqd",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::FtpSslReqd,
        Multi::Boolean,
        "",
        "Require SSL/TLS",
    ),
    od(
        "get",
        b'G',
        ArgType::Bool,
        0,
        Cmd::Get,
        Multi::Boolean,
        "",
        "Put the post data in the URL and use GET",
    ),
    od(
        "globoff",
        b'g',
        ArgType::Bool,
        0,
        Cmd::Globoff,
        Multi::Boolean,
        "",
        "Disable URL globbing with {} and []",
    ),
    od(
        "happy-eyeballs-timeout-ms",
        0,
        ArgType::Strg,
        0,
        Cmd::HappyEyeballsTimeoutMs,
        Multi::Single,
        "<ms>",
        "Time for IPv6 before IPv4",
    ),
    od(
        "haproxy-clientip",
        0,
        ArgType::Strg,
        0,
        Cmd::HaproxyClientip,
        Multi::Single,
        "<ip>",
        "Set address in HAProxy PROXY",
    ),
    od(
        "haproxy-protocol",
        0,
        ArgType::Bool,
        0,
        Cmd::HaproxyProtocol,
        Multi::Boolean,
        "",
        "Send HAProxy PROXY protocol v1 header",
    ),
    od(
        "head",
        b'I',
        ArgType::Bool,
        0,
        Cmd::Head,
        Multi::Boolean,
        "",
        "Show document info only",
    ),
    od(
        "header",
        b'H',
        ArgType::Strg,
        0,
        Cmd::Header,
        Multi::Append,
        "<header/@file>",
        "Pass custom header(s) to server",
    ),
    od(
        "help",
        b'h',
        ArgType::Strg,
        0,
        Cmd::Help,
        Multi::Custom,
        "<subject>",
        "Get help for commands",
    ),
    od(
        "hostpubmd5",
        0,
        ArgType::Strg,
        0,
        Cmd::Hostpubmd5,
        Multi::Single,
        "<md5>",
        "Acceptable MD5 hash of host public key",
    ),
    od(
        "hostpubsha256",
        0,
        ArgType::Strg,
        0,
        Cmd::Hostpubsha256,
        Multi::Single,
        "<sha256>",
        "Acceptable SHA256 hash of host public key",
    ),
    od(
        "hsts",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::Hsts,
        Multi::Append,
        "<filename>",
        "Enable HSTS with this cache file",
    ),
    od(
        "http0.9",
        0,
        ArgType::Bool,
        0,
        Cmd::Http09,
        Multi::Boolean,
        "",
        "Allow HTTP/0.9 responses",
    ),
    od(
        "http1.0",
        b'0',
        ArgType::None_,
        0,
        Cmd::Http10,
        Multi::Mutex,
        "",
        "Use HTTP/1.0",
    ),
    od(
        "http1.1",
        0,
        ArgType::None_,
        0,
        Cmd::Http11,
        Multi::Mutex,
        "",
        "Use HTTP/1.1",
    ),
    od(
        "http2",
        0,
        ArgType::None_,
        0,
        Cmd::Http2,
        Multi::Mutex,
        "",
        "Use HTTP/2",
    ),
    od(
        "http2-prior-knowledge",
        0,
        ArgType::None_,
        0,
        Cmd::Http2PriorKnowledge,
        Multi::Boolean,
        "",
        "Use HTTP/2 without HTTP/1.1 Upgrade",
    ),
    od(
        "http3",
        0,
        ArgType::None_,
        ARG_TLS,
        Cmd::Http3,
        Multi::Mutex,
        "",
        "Use HTTP/3",
    ),
    od(
        "http3-only",
        0,
        ArgType::None_,
        ARG_TLS,
        Cmd::Http3Only,
        Multi::Mutex,
        "",
        "Use HTTP/3 only",
    ),
    od(
        "ignore-content-length",
        0,
        ArgType::Bool,
        0,
        Cmd::IgnoreContentLength,
        Multi::Boolean,
        "",
        "Ignore the size of the remote resource",
    ),
    od(
        "include",
        0,
        ArgType::Bool,
        0,
        Cmd::Include,
        Multi::Boolean,
        "",
        "Show response headers in output",
    ),
    od(
        "insecure",
        b'k',
        ArgType::Bool,
        0,
        Cmd::Insecure,
        Multi::Boolean,
        "",
        "Allow insecure server connections",
    ),
    od(
        "interface",
        0,
        ArgType::Strg,
        0,
        Cmd::Interface,
        Multi::Single,
        "<name>",
        "Use network interface",
    ),
    od(
        "ip-tos",
        0,
        ArgType::Strg,
        0,
        Cmd::IpTos,
        Multi::Single,
        "<string>",
        "Set IP Type of Service or Traffic Class",
    ),
    od(
        "ipfs-gateway",
        0,
        ArgType::Strg,
        0,
        Cmd::IpfsGateway,
        Multi::Single,
        "<URL>",
        "Gateway for IPFS",
    ),
    od(
        "ipv4",
        b'4',
        ArgType::None_,
        0,
        Cmd::Ipv4,
        Multi::Mutex,
        "",
        "Resolve names to IPv4 addresses",
    ),
    od(
        "ipv6",
        b'6',
        ArgType::None_,
        0,
        Cmd::Ipv6,
        Multi::Mutex,
        "",
        "Resolve names to IPv6 addresses",
    ),
    od(
        "json",
        0,
        ArgType::Strg,
        0,
        Cmd::Json,
        Multi::Append,
        "<data>",
        "HTTP POST JSON",
    ),
    od(
        "junk-session-cookies",
        b'j',
        ArgType::Bool,
        0,
        Cmd::JunkSessionCookies,
        Multi::Boolean,
        "",
        "Ignore session cookies read from file",
    ),
    od(
        "keepalive",
        0,
        ArgType::Bool,
        ARG_NO,
        Cmd::Keepalive,
        Multi::Boolean,
        "",
        "Disable TCP keepalive on the connection",
    ),
    od(
        "keepalive-cnt",
        0,
        ArgType::Strg,
        0,
        Cmd::KeepaliveCnt,
        Multi::Single,
        "<integer>",
        "Maximum number of keepalive probes",
    ),
    od(
        "keepalive-time",
        0,
        ArgType::Strg,
        0,
        Cmd::KeepaliveTime,
        Multi::Single,
        "<seconds>",
        "Interval time for keepalive probes",
    ),
    od(
        "key",
        0,
        ArgType::File,
        0,
        Cmd::Key,
        Multi::Single,
        "<key>",
        "Private key filename",
    ),
    od(
        "key-type",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::KeyType,
        Multi::Single,
        "<type>",
        "Private key file type (DER/PEM/ENG)",
    ),
    od(
        "knownhosts",
        0,
        ArgType::File,
        0,
        Cmd::Knownhosts,
        Multi::Single,
        "<file>",
        "Specify knownhosts path",
    ),
    od(
        "krb",
        0,
        ArgType::Strg,
        ARG_DEPR,
        Cmd::Krb,
        Multi::Single,
        "<level>",
        "Enable Kerberos with security <level>",
    ),
    od(
        "krb4",
        0,
        ArgType::Strg,
        ARG_DEPR,
        Cmd::Krb4,
        Multi::Single,
        "<level>",
        "Enable Kerberos with security <level>",
    ),
    od(
        "libcurl",
        0,
        ArgType::Strg,
        0,
        Cmd::Libcurl,
        Multi::Single,
        "<file>",
        "Generate libcurl code for this command line",
    ),
    od(
        "limit-rate",
        0,
        ArgType::Strg,
        0,
        Cmd::LimitRate,
        Multi::Single,
        "<speed>",
        "Limit transfer speed to RATE",
    ),
    od(
        "list-only",
        b'l',
        ArgType::Bool,
        0,
        Cmd::ListOnly,
        Multi::Boolean,
        "",
        "List only mode",
    ),
    od(
        "local-port",
        0,
        ArgType::Strg,
        0,
        Cmd::LocalPort,
        Multi::Single,
        "<range>",
        "Use a local port number within RANGE",
    ),
    od(
        "location",
        b'L',
        ArgType::Bool,
        0,
        Cmd::Location,
        Multi::Boolean,
        "",
        "Follow redirects",
    ),
    od(
        "location-trusted",
        0,
        ArgType::Bool,
        0,
        Cmd::LocationTrusted,
        Multi::Boolean,
        "",
        "As --location, but send secrets to other hosts",
    ),
    od(
        "login-options",
        0,
        ArgType::Strg,
        0,
        Cmd::LoginOptions,
        Multi::Single,
        "<options>",
        "Server login options",
    ),
    od(
        "mail-auth",
        0,
        ArgType::Strg,
        0,
        Cmd::MailAuth,
        Multi::Single,
        "<address>",
        "Originator address of the original email",
    ),
    od(
        "mail-from",
        0,
        ArgType::Strg,
        0,
        Cmd::MailFrom,
        Multi::Single,
        "<address>",
        "Mail from this address",
    ),
    od(
        "mail-rcpt",
        0,
        ArgType::Strg,
        0,
        Cmd::MailRcpt,
        Multi::Append,
        "<address>",
        "Mail to this address",
    ),
    od(
        "mail-rcpt-allowfails",
        0,
        ArgType::Bool,
        0,
        Cmd::MailRcptAllowfails,
        Multi::Boolean,
        "",
        "Allow RCPT TO command to fail",
    ),
    od(
        "manual",
        b'M',
        ArgType::Bool,
        0,
        Cmd::Manual,
        Multi::Custom,
        "",
        "Display the full manual",
    ),
    od(
        "max-filesize",
        0,
        ArgType::Strg,
        0,
        Cmd::MaxFilesize,
        Multi::Single,
        "<bytes>",
        "Maximum file size to download",
    ),
    od(
        "max-redirs",
        0,
        ArgType::Strg,
        0,
        Cmd::MaxRedirs,
        Multi::Single,
        "<num>",
        "Maximum number of redirects allowed",
    ),
    od(
        "max-time",
        b'm',
        ArgType::Strg,
        0,
        Cmd::MaxTime,
        Multi::Single,
        "<seconds>",
        "Maximum time allowed for transfer",
    ),
    od(
        "metalink",
        0,
        ArgType::Bool,
        ARG_DEPR,
        Cmd::Metalink,
        Multi::Single,
        "",
        "Process given URLs as metalink XML file",
    ),
    od(
        "mptcp",
        0,
        ArgType::Bool,
        0,
        Cmd::Mptcp,
        Multi::Boolean,
        "",
        "Enable Multipath TCP",
    ),
    od(
        "negotiate",
        0,
        ArgType::Bool,
        0,
        Cmd::Negotiate,
        Multi::Boolean,
        "",
        "Use HTTP Negotiate (SPNEGO) authentication",
    ),
    od(
        "netrc",
        b'n',
        ArgType::Bool,
        0,
        Cmd::Netrc,
        Multi::Boolean,
        "",
        "Must read .netrc for username and password",
    ),
    od(
        "netrc-file",
        0,
        ArgType::File,
        0,
        Cmd::NetrcFile,
        Multi::Single,
        "<filename>",
        "Specify FILE for netrc",
    ),
    od(
        "netrc-optional",
        0,
        ArgType::Bool,
        0,
        Cmd::NetrcOptional,
        Multi::Boolean,
        "",
        "Use either .netrc or URL",
    ),
    od(
        "next",
        b':',
        ArgType::None_,
        0,
        Cmd::Next,
        Multi::Append,
        "",
        "Make next URL use separate options",
    ),
    od(
        "noproxy",
        0,
        ArgType::Strg,
        0,
        Cmd::Noproxy,
        Multi::Single,
        "<no-proxy-list>",
        "List of hosts which do not use proxy",
    ),
    od(
        "npn",
        0,
        ArgType::Bool,
        ARG_DEPR,
        Cmd::Npn,
        Multi::Boolean,
        "",
        "Disable the NPN TLS extension",
    ),
    od(
        "ntlm",
        0,
        ArgType::Bool,
        0,
        Cmd::Ntlm,
        Multi::Boolean,
        "",
        "HTTP NTLM authentication",
    ),
    od(
        "ntlm-wb",
        0,
        ArgType::Bool,
        ARG_DEPR,
        Cmd::NtlmWb,
        Multi::Mutex,
        "",
        "HTTP NTLM authentication with winbind",
    ),
    od(
        "oauth2-bearer",
        0,
        ArgType::Strg,
        ARG_CLEAR,
        Cmd::Oauth2Bearer,
        Multi::Single,
        "<token>",
        "OAuth 2 Bearer Token",
    ),
    od(
        "out-null",
        0,
        ArgType::Bool,
        0,
        Cmd::OutNull,
        Multi::PerUrl,
        "",
        "Discard response data into the void",
    ),
    od(
        "output",
        b'o',
        ArgType::File,
        0,
        Cmd::Output,
        Multi::PerUrl,
        "<file>",
        "Write to file instead of stdout",
    ),
    od(
        "output-dir",
        0,
        ArgType::Strg,
        0,
        Cmd::OutputDir,
        Multi::Single,
        "<dir>",
        "Directory to save files in",
    ),
    od(
        "parallel",
        b'Z',
        ArgType::Bool,
        0,
        Cmd::Parallel,
        Multi::Boolean,
        "",
        "Perform transfers in parallel",
    ),
    od(
        "parallel-immediate",
        0,
        ArgType::Bool,
        0,
        Cmd::ParallelImmediate,
        Multi::Boolean,
        "",
        "Do not wait for multiplexing",
    ),
    od(
        "parallel-max",
        0,
        ArgType::Strg,
        0,
        Cmd::ParallelMax,
        Multi::Single,
        "<num>",
        "Maximum concurrency for parallel transfers",
    ),
    od(
        "parallel-max-host",
        0,
        ArgType::Strg,
        0,
        Cmd::ParallelHost,
        Multi::Single,
        "<num>",
        "Maximum connections to a single host",
    ),
    od(
        "pass",
        0,
        ArgType::Strg,
        ARG_CLEAR,
        Cmd::Pass,
        Multi::Single,
        "<phrase>",
        "Passphrase for the private key",
    ),
    od(
        "path-as-is",
        0,
        ArgType::Bool,
        0,
        Cmd::PathAsIs,
        Multi::Boolean,
        "",
        "Do not squash .. sequences in URL path",
    ),
    od(
        "pinnedpubkey",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::Pinnedpubkey,
        Multi::Single,
        "<hashes>",
        "Public key to verify peer against",
    ),
    od(
        "post301",
        0,
        ArgType::Bool,
        0,
        Cmd::Post301,
        Multi::Boolean,
        "",
        "Do not switch to GET after a 301 redirect",
    ),
    od(
        "post302",
        0,
        ArgType::Bool,
        0,
        Cmd::Post302,
        Multi::Boolean,
        "",
        "Do not switch to GET after a 302 redirect",
    ),
    od(
        "post303",
        0,
        ArgType::Bool,
        0,
        Cmd::Post303,
        Multi::Boolean,
        "",
        "Do not switch to GET after a 303 redirect",
    ),
    od(
        "preproxy",
        0,
        ArgType::Strg,
        0,
        Cmd::Preproxy,
        Multi::Single,
        "<[protocol://]host[:port]>",
        "Use this proxy first",
    ),
    od(
        "progress-bar",
        b'#',
        ArgType::Bool,
        0,
        Cmd::ProgressBar,
        Multi::Boolean,
        "",
        "Display transfer progress as a bar",
    ),
    od(
        "progress-meter",
        0,
        ArgType::Bool,
        ARG_NO,
        Cmd::ProgressMeter,
        Multi::Boolean,
        "",
        "Do not show the progress meter",
    ),
    od(
        "proto",
        0,
        ArgType::Strg,
        0,
        Cmd::Proto,
        Multi::Single,
        "<protocols>",
        "Enable/disable PROTOCOLS",
    ),
    od(
        "proto-default",
        0,
        ArgType::Strg,
        0,
        Cmd::ProtoDefault,
        Multi::Single,
        "<protocol>",
        "Use PROTOCOL for any URL missing a scheme",
    ),
    od(
        "proto-redir",
        0,
        ArgType::Strg,
        0,
        Cmd::ProtoRedir,
        Multi::Single,
        "<protocols>",
        "Enable/disable PROTOCOLS on redirect",
    ),
    od(
        "proxy",
        b'x',
        ArgType::Strg,
        0,
        Cmd::Proxy,
        Multi::Single,
        "<[protocol://]host[:port]>",
        "Use this proxy",
    ),
    od(
        "proxy-anyauth",
        0,
        ArgType::Bool,
        0,
        Cmd::ProxyAnyauth,
        Multi::Custom,
        "",
        "Pick any proxy authentication method",
    ),
    od(
        "proxy-basic",
        0,
        ArgType::Bool,
        0,
        Cmd::ProxyBasic,
        Multi::Boolean,
        "",
        "Use Basic authentication on the proxy",
    ),
    od(
        "proxy-ca-native",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::ProxyCaNative,
        Multi::Boolean,
        "",
        "Load CA certs from the OS to verify proxy",
    ),
    od(
        "proxy-cacert",
        0,
        ArgType::File,
        ARG_TLS,
        Cmd::ProxyCacert,
        Multi::Single,
        "<file>",
        "CA certificates to verify proxy against",
    ),
    od(
        "proxy-capath",
        0,
        ArgType::File,
        ARG_TLS,
        Cmd::ProxyCapath,
        Multi::Single,
        "<dir>",
        "CA directory to verify proxy against",
    ),
    od(
        "proxy-cert",
        0,
        ArgType::File,
        ARG_CLEAR | ARG_TLS,
        Cmd::ProxyCert,
        Multi::Single,
        "<cert[:passwd]>",
        "Set client certificate for proxy",
    ),
    od(
        "proxy-cert-type",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::ProxyCertType,
        Multi::Single,
        "<type>",
        "Client certificate type for HTTPS proxy",
    ),
    od(
        "proxy-ciphers",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::ProxyCiphers,
        Multi::Single,
        "<list>",
        "TLS 1.2 (1.1, 1.0) ciphers to use for proxy",
    ),
    od(
        "proxy-crlfile",
        0,
        ArgType::File,
        ARG_TLS,
        Cmd::ProxyCrlfile,
        Multi::Single,
        "<file>",
        "Set a CRL list for proxy",
    ),
    od(
        "proxy-digest",
        0,
        ArgType::Bool,
        0,
        Cmd::ProxyDigest,
        Multi::Boolean,
        "",
        "Digest auth with the proxy",
    ),
    od(
        "proxy-header",
        0,
        ArgType::Strg,
        0,
        Cmd::ProxyHeader,
        Multi::Append,
        "<header/@file>",
        "Pass custom header(s) to proxy",
    ),
    od(
        "proxy-http2",
        0,
        ArgType::Bool,
        0,
        Cmd::ProxyHttp2,
        Multi::Boolean,
        "",
        "Use HTTP/2 with HTTPS proxy",
    ),
    od(
        "proxy-insecure",
        0,
        ArgType::Bool,
        0,
        Cmd::ProxyInsecure,
        Multi::Boolean,
        "",
        "Skip HTTPS proxy cert verification",
    ),
    od(
        "proxy-key",
        0,
        ArgType::File,
        ARG_TLS,
        Cmd::ProxyKey,
        Multi::Single,
        "<key>",
        "Private key for HTTPS proxy",
    ),
    od(
        "proxy-key-type",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::ProxyKeyType,
        Multi::Single,
        "<type>",
        "Private key file type for proxy",
    ),
    od(
        "proxy-negotiate",
        0,
        ArgType::Bool,
        0,
        Cmd::ProxyNegotiate,
        Multi::Mutex,
        "",
        "HTTP Negotiate (SPNEGO) auth with the proxy",
    ),
    od(
        "proxy-ntlm",
        0,
        ArgType::Bool,
        0,
        Cmd::ProxyNtlm,
        Multi::Boolean,
        "",
        "NTLM authentication with the proxy",
    ),
    od(
        "proxy-pass",
        0,
        ArgType::Strg,
        ARG_CLEAR,
        Cmd::ProxyPass,
        Multi::Single,
        "<phrase>",
        "Passphrase for private key for HTTPS proxy",
    ),
    od(
        "proxy-pinnedpubkey",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::ProxyPinnedpubkey,
        Multi::Single,
        "<hashes>",
        "FILE/HASHES public key to verify proxy with",
    ),
    od(
        "proxy-service-name",
        0,
        ArgType::Strg,
        0,
        Cmd::ProxyServiceName,
        Multi::Single,
        "<name>",
        "SPNEGO proxy service name",
    ),
    od(
        "proxy-ssl-allow-beast",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::ProxySslAllowBeast,
        Multi::Boolean,
        "",
        "Allow this security flaw for HTTPS proxy",
    ),
    od(
        "proxy-ssl-auto-client-cert",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::ProxySslAutoClientCert,
        Multi::Boolean,
        "",
        "Auto client certificate for proxy",
    ),
    od(
        "proxy-tls13-ciphers",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::ProxyTls13Ciphers,
        Multi::Single,
        "<list>",
        "TLS 1.3 proxy cipher suites",
    ),
    od(
        "proxy-tlsauthtype",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::ProxyTlsauthtype,
        Multi::Single,
        "<type>",
        "TLS authentication type for HTTPS proxy",
    ),
    od(
        "proxy-tlspassword",
        0,
        ArgType::Strg,
        ARG_CLEAR | ARG_TLS,
        Cmd::ProxyTlspassword,
        Multi::Single,
        "<string>",
        "TLS password for HTTPS proxy",
    ),
    od(
        "proxy-tlsuser",
        0,
        ArgType::Strg,
        ARG_CLEAR | ARG_TLS,
        Cmd::ProxyTlsuser,
        Multi::Single,
        "<name>",
        "TLS username for HTTPS proxy",
    ),
    od(
        "proxy-tlsv1",
        0,
        ArgType::None_,
        ARG_TLS,
        Cmd::ProxyTlsv1,
        Multi::Mutex,
        "",
        "TLSv1 for HTTPS proxy",
    ),
    od(
        "proxy-user",
        b'U',
        ArgType::Strg,
        ARG_CLEAR,
        Cmd::ProxyUser,
        Multi::Single,
        "<user:password>",
        "Proxy user and password",
    ),
    od(
        "proxy1.0",
        0,
        ArgType::Strg,
        0,
        Cmd::Proxy10,
        Multi::Mutex,
        "<host[:port]>",
        "Use HTTP/1.0 proxy on given port",
    ),
    od(
        "proxytunnel",
        b'p',
        ArgType::Bool,
        0,
        Cmd::Proxytunnel,
        Multi::Boolean,
        "",
        "HTTP proxy tunnel (using CONNECT)",
    ),
    od(
        "pubkey",
        0,
        ArgType::Strg,
        0,
        Cmd::Pubkey,
        Multi::Single,
        "<key>",
        "SSH Public key filename",
    ),
    od(
        "quote",
        b'Q',
        ArgType::Strg,
        0,
        Cmd::Quote,
        Multi::Append,
        "<command>",
        "Send command(s) to server before transfer",
    ),
    od(
        "random-file",
        0,
        ArgType::File,
        ARG_DEPR,
        Cmd::RandomFile,
        Multi::Single,
        "<file>",
        "File for reading random data from",
    ),
    od(
        "range",
        b'r',
        ArgType::Strg,
        0,
        Cmd::Range,
        Multi::Single,
        "<range>",
        "Retrieve only the bytes within RANGE",
    ),
    od(
        "rate",
        0,
        ArgType::Strg,
        0,
        Cmd::Rate,
        Multi::Single,
        "<max request rate>",
        "Request rate for serial transfers",
    ),
    od(
        "raw",
        0,
        ArgType::Bool,
        0,
        Cmd::Raw,
        Multi::Boolean,
        "",
        "Do HTTP raw; no transfer decoding",
    ),
    od(
        "referer",
        b'e',
        ArgType::Strg,
        0,
        Cmd::Referer,
        Multi::Single,
        "<URL>",
        "Referrer URL",
    ),
    od(
        "remote-header-name",
        b'J',
        ArgType::Bool,
        0,
        Cmd::RemoteHeaderName,
        Multi::Boolean,
        "",
        "Use the header-provided filename",
    ),
    od(
        "remote-name",
        b'O',
        ArgType::Bool,
        0,
        Cmd::RemoteName,
        Multi::PerUrl,
        "",
        "Write output to file named as remote file",
    ),
    od(
        "remote-name-all",
        0,
        ArgType::Bool,
        0,
        Cmd::RemoteNameAll,
        Multi::Boolean,
        "",
        "Use the remote filename for all URLs",
    ),
    od(
        "remote-time",
        b'R',
        ArgType::Bool,
        0,
        Cmd::RemoteTime,
        Multi::Boolean,
        "",
        "Set remote file's time on local output",
    ),
    od(
        "remove-on-error",
        0,
        ArgType::Bool,
        0,
        Cmd::RemoveOnError,
        Multi::Boolean,
        "",
        "Remove output file on errors",
    ),
    od(
        "request",
        b'X',
        ArgType::Strg,
        0,
        Cmd::Request,
        Multi::Single,
        "<method>",
        "Specify request method to use",
    ),
    od(
        "request-target",
        0,
        ArgType::Strg,
        0,
        Cmd::RequestTarget,
        Multi::Single,
        "<path>",
        "Specify the target for this request",
    ),
    od(
        "resolve",
        0,
        ArgType::Strg,
        0,
        Cmd::Resolve,
        Multi::Append,
        "<[+]host:port:addr[,addr]...>",
        "Resolve host+port to address",
    ),
    od(
        "retry",
        0,
        ArgType::Strg,
        0,
        Cmd::Retry,
        Multi::Single,
        "<num>",
        "Retry request if transient problems occur",
    ),
    od(
        "retry-all-errors",
        0,
        ArgType::Bool,
        0,
        Cmd::RetryAllErrors,
        Multi::Boolean,
        "",
        "Retry all errors (with --retry)",
    ),
    od(
        "retry-connrefused",
        0,
        ArgType::Bool,
        0,
        Cmd::RetryConnrefused,
        Multi::Boolean,
        "",
        "Retry on connection refused (with --retry)",
    ),
    od(
        "retry-delay",
        0,
        ArgType::Strg,
        0,
        Cmd::RetryDelay,
        Multi::Single,
        "<seconds>",
        "Wait time between retries",
    ),
    od(
        "retry-max-time",
        0,
        ArgType::Strg,
        0,
        Cmd::RetryMaxTime,
        Multi::Single,
        "<seconds>",
        "Retry only within this period",
    ),
    od(
        "sasl-authzid",
        0,
        ArgType::Strg,
        0,
        Cmd::SaslAuthzid,
        Multi::Single,
        "<identity>",
        "Identity for SASL PLAIN authentication",
    ),
    od(
        "sasl-ir",
        0,
        ArgType::Bool,
        0,
        Cmd::SaslIr,
        Multi::Boolean,
        "",
        "Initial response in SASL authentication",
    ),
    od(
        "service-name",
        0,
        ArgType::Strg,
        0,
        Cmd::ServiceName,
        Multi::Single,
        "<name>",
        "SPNEGO service name",
    ),
    od(
        "sessionid",
        0,
        ArgType::Bool,
        ARG_NO,
        Cmd::Sessionid,
        Multi::Boolean,
        "",
        "Disable SSL session-ID reusing",
    ),
    od(
        "show-error",
        b'S',
        ArgType::Bool,
        0,
        Cmd::ShowError,
        Multi::Boolean,
        "",
        "Show error even when -s is used",
    ),
    od(
        "show-headers",
        b'i',
        ArgType::Bool,
        0,
        Cmd::ShowHeaders,
        Multi::Boolean,
        "",
        "Show response headers in output",
    ),
    od(
        "sigalgs",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::SignatureAlgorithms,
        Multi::Single,
        "<list>",
        "TLS signature algorithms to use",
    ),
    od(
        "silent",
        b's',
        ArgType::Bool,
        0,
        Cmd::Silent,
        Multi::Boolean,
        "",
        "Silent mode",
    ),
    od(
        "skip-existing",
        0,
        ArgType::Bool,
        0,
        Cmd::SkipExisting,
        Multi::Boolean,
        "",
        "Skip download if local file already exists",
    ),
    od(
        "socks4",
        0,
        ArgType::Strg,
        0,
        Cmd::Socks4,
        Multi::Single,
        "<host[:port]>",
        "SOCKS4 proxy on given host + port",
    ),
    od(
        "socks4a",
        0,
        ArgType::Strg,
        0,
        Cmd::Socks4a,
        Multi::Single,
        "<host[:port]>",
        "SOCKS4a proxy on given host + port",
    ),
    od(
        "socks5",
        0,
        ArgType::Strg,
        0,
        Cmd::Socks5,
        Multi::Single,
        "<host[:port]>",
        "SOCKS5 proxy on given host + port",
    ),
    od(
        "socks5-basic",
        0,
        ArgType::Bool,
        0,
        Cmd::Socks5Basic,
        Multi::Mutex,
        "",
        "Username/password auth for SOCKS5 proxies",
    ),
    od(
        "socks5-gssapi",
        0,
        ArgType::Bool,
        0,
        Cmd::Socks5Gssapi,
        Multi::Boolean,
        "",
        "Enable GSS-API auth for SOCKS5 proxies",
    ),
    od(
        "socks5-gssapi-nec",
        0,
        ArgType::Bool,
        0,
        Cmd::Socks5GssapiNec,
        Multi::Boolean,
        "",
        "Compatibility with NEC SOCKS5 server",
    ),
    od(
        "socks5-gssapi-service",
        0,
        ArgType::Strg,
        0,
        Cmd::Socks5GssapiService,
        Multi::Single,
        "<name>",
        "SOCKS5 proxy service name for GSS-API",
    ),
    od(
        "socks5-hostname",
        0,
        ArgType::Strg,
        0,
        Cmd::Socks5Hostname,
        Multi::Single,
        "<host[:port]>",
        "SOCKS5 proxy, pass hostname to proxy",
    ),
    od(
        "speed-limit",
        b'Y',
        ArgType::Strg,
        0,
        Cmd::SpeedLimit,
        Multi::Single,
        "<speed>",
        "Stop transfers slower than this",
    ),
    od(
        "speed-time",
        b'y',
        ArgType::Strg,
        0,
        Cmd::SpeedTime,
        Multi::Single,
        "<seconds>",
        "Trigger 'speed-limit' abort after this time",
    ),
    od(
        "ssl",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::Ssl,
        Multi::Boolean,
        "",
        "Try enabling TLS",
    ),
    od(
        "ssl-allow-beast",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::SslAllowBeast,
        Multi::Boolean,
        "",
        "Allow security flaw to improve interop",
    ),
    od(
        "ssl-auto-client-cert",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::SslAutoClientCert,
        Multi::Boolean,
        "",
        "Use auto client certificate (Schannel)",
    ),
    od(
        "ssl-no-revoke",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::SslNoRevoke,
        Multi::Boolean,
        "",
        "Disable cert revocation checks (Schannel)",
    ),
    od(
        "ssl-reqd",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::SslReqd,
        Multi::Boolean,
        "",
        "Require SSL/TLS",
    ),
    od(
        "ssl-revoke-best-effort",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::SslRevokeBestEffort,
        Multi::Boolean,
        "",
        "Ignore missing cert CRL dist points",
    ),
    od(
        "ssl-sessions",
        0,
        ArgType::File,
        ARG_TLS,
        Cmd::SslSessions,
        Multi::Single,
        "<filename>",
        "Load/save SSL session tickets from/to this file",
    ),
    od(
        "sslv2",
        b'2',
        ArgType::None_,
        ARG_DEPR,
        Cmd::Sslv2,
        Multi::Mutex,
        "",
        "SSLv2",
    ),
    od(
        "sslv3",
        b'3',
        ArgType::None_,
        ARG_DEPR,
        Cmd::Sslv3,
        Multi::Mutex,
        "",
        "SSLv3",
    ),
    od(
        "stderr",
        0,
        ArgType::File,
        0,
        Cmd::Stderr,
        Multi::Single,
        "<file>",
        "Where to redirect stderr",
    ),
    od(
        "styled-output",
        0,
        ArgType::Bool,
        0,
        Cmd::StyledOutput,
        Multi::Boolean,
        "",
        "Enable styled output for HTTP headers",
    ),
    od(
        "suppress-connect-headers",
        0,
        ArgType::Bool,
        0,
        Cmd::SuppressConnectHeaders,
        Multi::Boolean,
        "",
        "Suppress proxy CONNECT response headers",
    ),
    od(
        "tcp-fastopen",
        0,
        ArgType::Bool,
        0,
        Cmd::TcpFastopen,
        Multi::Boolean,
        "",
        "Use TCP Fast Open",
    ),
    od(
        "tcp-nodelay",
        0,
        ArgType::Bool,
        0,
        Cmd::TcpNodelay,
        Multi::Boolean,
        "",
        "Set TCP_NODELAY",
    ),
    od(
        "telnet-option",
        b't',
        ArgType::Strg,
        0,
        Cmd::TelnetOption,
        Multi::Append,
        "<opt=val>",
        "Set telnet option",
    ),
    od(
        "tftp-blksize",
        0,
        ArgType::Strg,
        0,
        Cmd::TftpBlksize,
        Multi::Single,
        "<value>",
        "Set TFTP BLKSIZE option",
    ),
    od(
        "tftp-no-options",
        0,
        ArgType::Bool,
        0,
        Cmd::TftpNoOptions,
        Multi::Boolean,
        "",
        "Do not send any TFTP options",
    ),
    od(
        "time-cond",
        b'z',
        ArgType::Strg,
        0,
        Cmd::TimeCond,
        Multi::Single,
        "<time>",
        "Transfer based on a time condition",
    ),
    od(
        "tls-earlydata",
        0,
        ArgType::Bool,
        ARG_TLS,
        Cmd::TlsEarlydata,
        Multi::Boolean,
        "",
        "Allow use of TLSv1.3 early data (0RTT)",
    ),
    od(
        "tls-max",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::TlsMax,
        Multi::Single,
        "<VERSION>",
        "Maximum allowed TLS version",
    ),
    od(
        "tls13-ciphers",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::Tls13Ciphers,
        Multi::Single,
        "<list>",
        "TLS 1.3 cipher suites to use",
    ),
    od(
        "tlsauthtype",
        0,
        ArgType::Strg,
        ARG_TLS,
        Cmd::Tlsauthtype,
        Multi::Single,
        "<type>",
        "TLS authentication type",
    ),
    od(
        "tlspassword",
        0,
        ArgType::Strg,
        ARG_CLEAR | ARG_TLS,
        Cmd::Tlspassword,
        Multi::Single,
        "<string>",
        "TLS password",
    ),
    od(
        "tlsuser",
        0,
        ArgType::Strg,
        ARG_CLEAR | ARG_TLS,
        Cmd::Tlsuser,
        Multi::Single,
        "<name>",
        "TLS username",
    ),
    od(
        "tlsv1",
        b'1',
        ArgType::None_,
        ARG_TLS,
        Cmd::Tlsv1,
        Multi::Mutex,
        "",
        "TLSv1.0 or greater",
    ),
    od(
        "tlsv1.0",
        0,
        ArgType::None_,
        ARG_TLS,
        Cmd::Tlsv10,
        Multi::Mutex,
        "",
        "TLSv1.0 or greater",
    ),
    od(
        "tlsv1.1",
        0,
        ArgType::None_,
        ARG_TLS,
        Cmd::Tlsv11,
        Multi::Mutex,
        "",
        "TLSv1.1 or greater",
    ),
    od(
        "tlsv1.2",
        0,
        ArgType::None_,
        ARG_TLS,
        Cmd::Tlsv12,
        Multi::Mutex,
        "",
        "TLSv1.2 or greater",
    ),
    od(
        "tlsv1.3",
        0,
        ArgType::None_,
        ARG_TLS,
        Cmd::Tlsv13,
        Multi::Mutex,
        "",
        "TLSv1.3 or greater",
    ),
    od(
        "tr-encoding",
        0,
        ArgType::Bool,
        0,
        Cmd::TrEncoding,
        Multi::Boolean,
        "",
        "Request compressed transfer encoding",
    ),
    od(
        "trace",
        0,
        ArgType::File,
        0,
        Cmd::Trace,
        Multi::Single,
        "<file>",
        "Write a debug trace to FILE",
    ),
    od(
        "trace-ascii",
        0,
        ArgType::File,
        0,
        Cmd::TraceAscii,
        Multi::Single,
        "<file>",
        "Like --trace, but without hex output",
    ),
    od(
        "trace-config",
        0,
        ArgType::Strg,
        0,
        Cmd::TraceConfig,
        Multi::Append,
        "<string>",
        "Details to log in trace/verbose output",
    ),
    od(
        "trace-ids",
        0,
        ArgType::Bool,
        0,
        Cmd::TraceIds,
        Multi::Boolean,
        "",
        "Transfer + connection ids in verbose output",
    ),
    od(
        "trace-time",
        0,
        ArgType::Bool,
        0,
        Cmd::TraceTime,
        Multi::Boolean,
        "",
        "Add time stamps to trace/verbose output",
    ),
    od(
        "unix-socket",
        0,
        ArgType::File,
        0,
        Cmd::UnixSocket,
        Multi::Single,
        "<path>",
        "Connect through this Unix domain socket",
    ),
    od(
        "upload-file",
        b'T',
        ArgType::File,
        0,
        Cmd::UploadFile,
        Multi::PerUrl,
        "<file>",
        "Transfer local FILE to destination",
    ),
    od(
        "upload-flags",
        0,
        ArgType::Strg,
        0,
        Cmd::UploadFlags,
        Multi::Single,
        "<flags>",
        "IMAP upload behavior",
    ),
    od(
        "url",
        0,
        ArgType::Strg,
        0,
        Cmd::Url,
        Multi::Append,
        "<url/file>",
        "URL(s) to work with",
    ),
    od(
        "url-query",
        0,
        ArgType::Strg,
        0,
        Cmd::UrlQuery,
        Multi::Append,
        "<data>",
        "Add a URL query part",
    ),
    od(
        "use-ascii",
        b'B',
        ArgType::Bool,
        0,
        Cmd::UseAscii,
        Multi::Boolean,
        "",
        "Use ASCII/text transfer",
    ),
    od(
        "user",
        b'u',
        ArgType::Strg,
        ARG_CLEAR,
        Cmd::User,
        Multi::Single,
        "<user:password>",
        "Server user and password",
    ),
    od(
        "user-agent",
        b'A',
        ArgType::Strg,
        0,
        Cmd::UserAgent,
        Multi::Single,
        "<name>",
        "Send User-Agent <name> to server",
    ),
    od(
        "variable",
        0,
        ArgType::Strg,
        0,
        Cmd::Variable,
        Multi::Append,
        "<[%]name=text/@file>",
        "Set variable",
    ),
    od(
        "verbose",
        b'v',
        ArgType::Bool,
        0,
        Cmd::Verbose,
        Multi::Boolean,
        "",
        "Make the operation more talkative",
    ),
    od(
        "version",
        b'V',
        ArgType::Bool,
        0,
        Cmd::Version,
        Multi::Custom,
        "",
        "Show version number and quit",
    ),
    od(
        "vlan-priority",
        0,
        ArgType::Strg,
        0,
        Cmd::VlanPriority,
        Multi::Single,
        "<priority>",
        "Set VLAN priority",
    ),
    od(
        "write-out",
        b'w',
        ArgType::Strg,
        0,
        Cmd::WriteOut,
        Multi::Single,
        "<format>",
        "Output FORMAT after completion",
    ),
    od(
        "xattr",
        0,
        ArgType::Bool,
        0,
        Cmd::Xattr,
        Multi::Boolean,
        "",
        "Store metadata in extended file attributes",
    ),
];

/// Port of `findlongopt` (tool_getparam.c): exact-match lookup of a long option by
/// name — no abbreviation, matching curl's `bsearch` over the sorted table.
pub fn findlongopt(opt: &str) -> Option<&'static OptDef> {
    OPTIONS.iter().find(|o| o.lname == opt)
}

/// Port of `findshortopt` (tool_getparam.c): lookup of a short option by its ASCII
/// letter. Returns `None` for the "no letter" sentinel (`0`) and for bytes outside
/// the printable-ASCII range the C table indexes.
pub fn findshortopt(letter: u8) -> Option<&'static OptDef> {
    if letter <= b' ' || letter >= 127 {
        return None;
    }
    OPTIONS.iter().find(|o| o.letter == letter)
}

// ===========================================================================
// Part 10 — the four per-option dispatch functions
// (opt_none / opt_file / opt_bool / opt_string, tool_getparam.c) plus the
// small helpers they need (SetHTTPrequest, getstrn, the `--ip-tos` DSCP table).
//
// Each function is a faithful port of the like-named C `switch(a->cmd)`. The
// only systematic divergence from the C source is that the compile-time
// *feature-capability* gates (`if(!feature_http2) return
// PARAM_LIBCURL_DOESNT_SUPPORT;`, the `feature_ssl`/`feature_tls_srp`/
// `feature_altsvc`/c-ares/… guards) are OMITTED here: this module records the
// requested configuration unconditionally, and the runtime capability decision
// is made later by `setopt.rs` when the config is translated into libcurl
// calls. Every *intrinsic* validation (mutex conflicts, the single-request-
// method rule, the TLS-SRP "SRP-only" value check, `--hostpubmd5` length,
// the etag/`num_urls` rule, `--max-redirs >= -1`, …) is preserved exactly.
//
// Borrow discipline: because the operation being configured lives *inside*
// `GlobalConfig.operations`, a `Diag` snapshot is captured once at the top of
// each function (it is `Copy`, so it holds no borrow), after which per-arm
// access uses `global.op()` for operation fields and `global.<field>` for the
// process-global fields. Hook fields (`config_parser`, …) are copied into a
// local before the call so the closure can take `&mut GlobalConfig`.
// ===========================================================================

/// Human-readable request-method names indexed by [`HttpReq`] discriminant, mirroring
/// the C `reqname[]` table in `SetHTTPrequest` (tool_helpers.c). Used only for the
/// "you can only select one HTTP request method" diagnostic.
fn reqname(req: HttpReq) -> &'static str {
    match req {
        HttpReq::Unspec => "",
        HttpReq::Get => "GET (-G, --get)",
        HttpReq::Head => "HEAD (-I, --head)",
        HttpReq::Mimepost => "multipart formpost (-F, --form)",
        HttpReq::Simplepost => "POST (-d, --data)",
        HttpReq::Put => "PUT (-T, --upload-file)",
    }
}

/// Port of `SetHTTPrequest` (tool_helpers.c): record the requested HTTP method in
/// `store`, rejecting a second, conflicting choice. Returns `Ok(())` when `store`
/// was unset or already equal to `req`; otherwise warns and returns
/// [`ParameterError::BadUse`] (the C `return 1` that the callers map to
/// `PARAM_BAD_USE`).
fn set_http_request(diag: Diag, req: HttpReq, store: &mut HttpReq) -> Result<(), ParameterError> {
    if *store == HttpReq::Unspec || *store == req {
        *store = req;
        Ok(())
    } else {
        warnf(
            diag,
            &format!(
                "You can only select one HTTP request method! You asked for both {} and {}.",
                reqname(req),
                reqname(*store)
            ),
        );
        Err(ParameterError::BadUse)
    }
}

/// Port of `getstrn` (tool_getparam.c): store the first `len` bytes of `val`
/// into `store`. Like [`getstr`] but truncating to `len` — used by `--referer`
/// to drop a trailing `;auto`. With `!allowblank`, an empty *source* string
/// (`val`) is rejected as [`ParameterError::BlankString`] (the C checks
/// `val[0]`, i.e. the full argument, before truncation).
fn getstrn(
    store: &mut Option<String>,
    val: &str,
    len: usize,
    allowblank: bool,
) -> Result<(), ParameterError> {
    if !allowblank && val.is_empty() {
        return Err(ParameterError::BlankString);
    }
    // `len` is always on a char boundary for the sole caller (`;auto` is ASCII),
    // but guard defensively so a hypothetical mid-codepoint length cannot panic.
    let slice = val.get(..len).unwrap_or(val);
    *store = Some(slice.to_string());
    Ok(())
}

/// The `--ip-tos` DSCP/TOS name table (`tos_entries[]`, tool_getparam.c). Looked up
/// case-insensitively (C `find_tos` uses `curl_strequal`); an unrecognized argument
/// falls back to a numeric parse capped at `0xFF`.
const TOS_ENTRIES: &[(&str, i64)] = &[
    ("AF11", 0x28),
    ("AF12", 0x30),
    ("AF13", 0x38),
    ("AF21", 0x48),
    ("AF22", 0x50),
    ("AF23", 0x58),
    ("AF31", 0x68),
    ("AF32", 0x70),
    ("AF33", 0x78),
    ("AF41", 0x88),
    ("AF42", 0x90),
    ("AF43", 0x98),
    ("CE", 0x03),
    ("CS0", 0x00),
    ("CS1", 0x20),
    ("CS2", 0x40),
    ("CS3", 0x60),
    ("CS4", 0x80),
    ("CS5", 0xa0),
    ("CS6", 0xc0),
    ("CS7", 0xe0),
    ("ECT0", 0x02),
    ("ECT1", 0x01),
    ("EF", 0xb8),
    ("LE", 0x04),
    ("LOWCOST", 0x02),
    ("LOWDELAY", 0x10),
    ("MINCOST", 0x02),
    ("RELIABILITY", 0x04),
    ("THROUGHPUT", 0x08),
    ("VOICE-ADMIT", 0xb0),
];

// ---------------------------------------------------------------------------
// opt_none — options that take no argument (ARG_NONE).
// ---------------------------------------------------------------------------

/// Port of `opt_none` (tool_getparam.c): the `switch` over argument-less options.
/// Feature-capability gates are omitted (see the Part 10 banner); the HTTP-version
/// and TLS-version selectors defer their real capability checks to `setopt.rs`.
fn opt_none(global: &mut GlobalConfig, cmd: Cmd) -> Result<(), ParameterError> {
    let diag = global.diag();
    match cmd {
        Cmd::Anyauth => {
            global.op().authtype = curlabi::CURLAUTH_ANY;
            Ok(())
        }
        Cmd::DumpCaEmbed => Err(ParameterError::CaEmbedRequested),
        Cmd::FtpPasv => {
            // curl frees any earlier --ftp-port so PASV is used.
            global.op().ftpport = None;
            Ok(())
        }
        Cmd::Http10 => {
            sethttpver(diag, global.op(), curlabi::CURL_HTTP_VERSION_1_0);
            Ok(())
        }
        Cmd::Http11 => {
            sethttpver(diag, global.op(), curlabi::CURL_HTTP_VERSION_1_1);
            Ok(())
        }
        Cmd::Http2 => {
            sethttpver(diag, global.op(), curlabi::CURL_HTTP_VERSION_2_0);
            Ok(())
        }
        Cmd::Http2PriorKnowledge => {
            sethttpver(
                diag,
                global.op(),
                curlabi::CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE,
            );
            Ok(())
        }
        Cmd::Http3 => {
            sethttpver(diag, global.op(), curlabi::CURL_HTTP_VERSION_3);
            Ok(())
        }
        Cmd::Http3Only => {
            sethttpver(diag, global.op(), curlabi::CURL_HTTP_VERSION_3ONLY);
            Ok(())
        }
        Cmd::Tlsv1 => opt_sslver(diag, global.op(), 1),
        Cmd::Tlsv10 => opt_sslver(diag, global.op(), 1),
        Cmd::Tlsv11 => opt_sslver(diag, global.op(), 2),
        Cmd::Tlsv12 => opt_sslver(diag, global.op(), 3),
        Cmd::Tlsv13 => opt_sslver(diag, global.op(), 4),
        Cmd::Ipv4 => {
            global.op().ip_version = curlabi::CURL_IPRESOLVE_V4;
            Ok(())
        }
        Cmd::Ipv6 => {
            global.op().ip_version = curlabi::CURL_IPRESOLVE_V6;
            Ok(())
        }
        Cmd::Next => Err(ParameterError::NextOperation),
        Cmd::ProxyTlsv1 => {
            global.op().proxy_ssl_version = curlabi::CURL_SSLVERSION_TLSV1;
            Ok(())
        }
        // Deprecated ARG_NONE options (sslv2/sslv3) never reach here — getparameter
        // routes ARG_DEPR to opt_depr first — so any other cmd is a no-op (matching
        // the C switch's fall-through with err == PARAM_OK).
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// opt_file — options whose argument is a filename (ARG_FILE).
// ---------------------------------------------------------------------------

/// Port of `opt_file` (tool_getparam.c): the `switch` over filename options. The
/// leading "filename looks like a flag" heuristic and the `existingfile`
/// pre-checks are preserved. `--config` decrements `max_recursive` and delegates
/// to the [`GlobalConfig::config_parser`] hook (curl's `parseconfig`); `--stderr`
/// records the target for `main.rs` (curl's `tool_set_stderr_file`).
fn opt_file(
    global: &mut GlobalConfig,
    cmd: Cmd,
    lname: &str,
    nextarg: &str,
    mut max_recursive: i32,
) -> Result<(), ParameterError> {
    let diag = global.diag();
    if nextarg.as_bytes().first() == Some(&b'-') && nextarg.len() > 1 {
        warnf(
            diag,
            &format!("The filename argument '{nextarg}' looks like a flag."),
        );
    }
    match cmd {
        Cmd::AbstractUnixSocket => {
            global.op().abstract_unix_socket = true;
            getstr(&mut global.op().unix_socket_path, nextarg, DENY_BLANK)
        }
        Cmd::Cacert => existingfile(&mut global.op().cacert, diag, lname, nextarg),
        Cmd::Capath => getstr(&mut global.op().capath, nextarg, DENY_BLANK),
        Cmd::Cert => {
            let op = global.op();
            get_file_and_password(nextarg, &mut op.cert, &mut op.key_passwd)
        }
        Cmd::Config => {
            max_recursive -= 1;
            if max_recursive < 0 {
                errorf(
                    diag,
                    &format!("Max config file recursion level reached ({CONFIG_MAX_LEVELS})"),
                );
                return Err(ParameterError::BadUse);
            }
            let cp = global.config_parser;
            match cp {
                Some(f) => f(nextarg, max_recursive, global),
                None => Ok(()),
            }
        }
        Cmd::Crlfile => existingfile(&mut global.op().crlfile, diag, lname, nextarg),
        Cmd::DumpHeader => getstr(&mut global.op().headerfile, nextarg, DENY_BLANK),
        Cmd::EtagSave => {
            if global.op().num_urls > 1 {
                errorf(diag, "The etag options only work on a single URL");
                Err(ParameterError::BadUse)
            } else {
                getstr(&mut global.op().etag_save_file, nextarg, DENY_BLANK)
            }
        }
        Cmd::EtagCompare => {
            if global.op().num_urls > 1 {
                errorf(diag, "The etag options only work on a single URL");
                Err(ParameterError::BadUse)
            } else {
                getstr(&mut global.op().etag_compare_file, nextarg, DENY_BLANK)
            }
        }
        Cmd::Key => getstr(&mut global.op().key, nextarg, DENY_BLANK),
        Cmd::Knownhosts => existingfile(&mut global.op().knownhosts, diag, lname, nextarg),
        Cmd::NetrcFile => existingfile(&mut global.op().netrc_file, diag, lname, nextarg),
        Cmd::Output => parse_output(global.op(), Some(nextarg)),
        Cmd::ProxyCacert => existingfile(&mut global.op().proxy_cacert, diag, lname, nextarg),
        Cmd::ProxyCapath => getstr(&mut global.op().proxy_capath, nextarg, DENY_BLANK),
        Cmd::ProxyCert => {
            let op = global.op();
            get_file_and_password(nextarg, &mut op.proxy_cert, &mut op.proxy_key_passwd)
        }
        Cmd::ProxyCrlfile => existingfile(&mut global.op().proxy_crlfile, diag, lname, nextarg),
        Cmd::ProxyKey => getstr(&mut global.op().proxy_key, nextarg, ALLOW_BLANK),
        Cmd::SslSessions => getstr(&mut global.ssl_sessions, nextarg, DENY_BLANK),
        Cmd::Stderr => {
            // curl's tool_set_stderr_file side effect; recorded for main.rs to apply.
            global.stderr_file = Some(nextarg.to_string());
            Ok(())
        }
        Cmd::Trace => {
            getstr(&mut global.trace_dump, nextarg, DENY_BLANK)?;
            if global.tracetype != TraceType::None && global.tracetype != TraceType::Bin {
                warnf(diag, "--trace overrides an earlier trace/verbose option");
            }
            global.tracetype = TraceType::Bin;
            Ok(())
        }
        Cmd::TraceAscii => {
            getstr(&mut global.trace_dump, nextarg, DENY_BLANK)?;
            if global.tracetype != TraceType::None && global.tracetype != TraceType::Ascii {
                warnf(
                    diag,
                    "--trace-ascii overrides an earlier trace/verbose option",
                );
            }
            global.tracetype = TraceType::Ascii;
            Ok(())
        }
        Cmd::UnixSocket => {
            global.op().abstract_unix_socket = false;
            getstr(&mut global.op().unix_socket_path, nextarg, DENY_BLANK)
        }
        Cmd::UploadFile => parse_upload_file(global.op(), nextarg),
        // Deprecated ARG_FILE (random-file) is routed to opt_depr by getparameter.
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// opt_bool — boolean options (ARG_BOOL), toggled by --OPT / --no-OPT.
// ---------------------------------------------------------------------------

/// Port of `opt_bool` (tool_getparam.c): the `switch` over boolean options. `toggle`
/// is `true` for `--OPT` and `false` for `--no-OPT` (computed by [`getparameter`]).
/// Feature-capability gates are omitted; every intrinsic mutex/consistency check is
/// preserved. Unknown commands return [`ParameterError::OptionUnknown`] (the C
/// `default`).
fn opt_bool(
    global: &mut GlobalConfig,
    cmd: Cmd,
    lname: &str,
    toggle: bool,
) -> Result<(), ParameterError> {
    let diag = global.diag();
    match cmd {
        Cmd::Alpn => {
            global.op().noalpn = !toggle;
            Ok(())
        }
        Cmd::Append => {
            global.op().ftp_append = toggle;
            Ok(())
        }
        Cmd::Basic => {
            togglebit(toggle, &mut global.op().authtype, curlabi::CURLAUTH_BASIC);
            Ok(())
        }
        Cmd::Buffer => {
            global.op().nobuffer = !toggle;
            Ok(())
        }
        Cmd::CaNative => {
            global.op().native_ca_store = toggle;
            Ok(())
        }
        Cmd::CertStatus => {
            global.op().verifystatus = toggle;
            Ok(())
        }
        Cmd::Clobber => {
            if global.op().use_resume && !toggle {
                errorf(
                    diag,
                    "--continue-at is mutually exclusive with --no-clobber",
                );
                return Err(ParameterError::BadUse);
            }
            global.op().file_clobber_mode = if toggle {
                ClobberMode::Always
            } else {
                ClobberMode::Never
            };
            Ok(())
        }
        Cmd::Compressed => {
            global.op().encoding = toggle;
            Ok(())
        }
        Cmd::CompressedSsh => {
            global.op().ssh_compression = toggle;
            Ok(())
        }
        Cmd::CreateDirs => {
            global.op().create_dirs = toggle;
            Ok(())
        }
        Cmd::Crlf => {
            global.op().crlf = toggle;
            Ok(())
        }
        Cmd::Digest => {
            togglebit(toggle, &mut global.op().authtype, curlabi::CURLAUTH_DIGEST);
            Ok(())
        }
        Cmd::Disable => {
            // --disable (disable .curlrc) is handled before parsing; a no-op here so
            // it does not error (mirrors the C empty case).
            Ok(())
        }
        Cmd::DisableEprt => {
            global.op().disable_eprt = toggle;
            Ok(())
        }
        Cmd::DisableEpsv => {
            global.op().disable_epsv = toggle;
            Ok(())
        }
        Cmd::DisallowUsernameInUrl => {
            global.op().disallow_username_in_url = toggle;
            Ok(())
        }
        Cmd::DohCertStatus => {
            global.op().doh_verifystatus = toggle;
            Ok(())
        }
        Cmd::DohInsecure => {
            global.op().doh_insecure_ok = toggle;
            Ok(())
        }
        Cmd::Eprt => {
            global.op().disable_eprt = !toggle;
            Ok(())
        }
        Cmd::Epsv => {
            global.op().disable_epsv = !toggle;
            Ok(())
        }
        Cmd::Fail => {
            if toggle && global.op().fail == FailMode::WithBody {
                warnf(diag, "--fail deselects --fail-with-body here");
            }
            global.op().fail = if toggle {
                FailMode::WoBody
            } else {
                FailMode::None
            };
            Ok(())
        }
        Cmd::FailEarly => {
            global.fail_early = toggle;
            Ok(())
        }
        Cmd::FailWithBody => {
            if toggle && global.op().fail == FailMode::WoBody {
                warnf(diag, "--fail-with-body deselects --fail here");
            }
            global.op().fail = if toggle {
                FailMode::WithBody
            } else {
                FailMode::None
            };
            Ok(())
        }
        Cmd::FalseStart => {
            // Kept as an accepted no-op with a deprecation notice (C calls opt_depr).
            opt_depr(diag, lname);
            Ok(())
        }
        Cmd::Follow => {
            if global.op().followlocation == curlabi::CURLFOLLOW_ALL {
                warnf(diag, "--follow overrides --location");
            }
            global.op().followlocation = if toggle {
                curlabi::CURLFOLLOW_OBEYCODE
            } else {
                0
            };
            Ok(())
        }
        Cmd::FormEscape => {
            togglebit(
                toggle,
                &mut global.op().mime_options,
                curlabi::CURLMIMEOPT_FORMESCAPE,
            );
            Ok(())
        }
        Cmd::FtpCreateDirs => {
            global.op().ftp_create_dirs = toggle;
            Ok(())
        }
        Cmd::FtpPret => {
            global.op().ftp_pret = toggle;
            Ok(())
        }
        Cmd::FtpSkipPasvIp => {
            global.op().ftp_skip_ip = toggle;
            Ok(())
        }
        Cmd::FtpSsl | Cmd::Ssl => {
            global.op().ftp_ssl = toggle;
            if global.op().ftp_ssl {
                warnf(
                    diag,
                    &format!("--{lname} is an insecure option, consider --ssl-reqd instead"),
                );
            }
            Ok(())
        }
        Cmd::FtpSslCcc => {
            global.op().ftp_ssl_ccc = toggle;
            if global.op().ftp_ssl_ccc_mode == 0 {
                global.op().ftp_ssl_ccc_mode = curlabi::CURLFTPSSL_CCC_PASSIVE;
            }
            Ok(())
        }
        Cmd::FtpSslControl => {
            global.op().ftp_ssl_control = toggle;
            Ok(())
        }
        Cmd::FtpSslReqd | Cmd::SslReqd => {
            global.op().ftp_ssl_reqd = toggle;
            Ok(())
        }
        Cmd::Get => {
            global.op().use_httpget = toggle;
            Ok(())
        }
        Cmd::Globoff => {
            global.op().globoff = toggle;
            Ok(())
        }
        Cmd::HaproxyProtocol => {
            global.op().haproxy_protocol = toggle;
            Ok(())
        }
        Cmd::Head => {
            let config = global.op();
            config.no_body = toggle;
            config.show_headers = toggle;
            let req = if config.no_body {
                HttpReq::Head
            } else {
                HttpReq::Get
            };
            set_http_request(diag, req, &mut config.httpreq)
        }
        Cmd::Http09 => {
            global.op().http09_allowed = toggle;
            Ok(())
        }
        Cmd::IgnoreContentLength => {
            global.op().ignorecl = toggle;
            Ok(())
        }
        Cmd::Include | Cmd::ShowHeaders => {
            global.op().show_headers = toggle;
            Ok(())
        }
        Cmd::Insecure => {
            global.op().insecure_ok = toggle;
            Ok(())
        }
        Cmd::JunkSessionCookies => {
            global.op().cookiesession = toggle;
            Ok(())
        }
        Cmd::Keepalive => {
            global.op().nokeepalive = !toggle;
            Ok(())
        }
        Cmd::ListOnly => {
            global.op().dirlistonly = toggle;
            Ok(())
        }
        Cmd::LocationTrusted => {
            global.op().unrestricted_auth = toggle;
            // FALLTHROUGH to --location behavior.
            if global.op().followlocation == curlabi::CURLFOLLOW_OBEYCODE {
                warnf(diag, "--location overrides --follow");
            }
            global.op().followlocation = if toggle { curlabi::CURLFOLLOW_ALL } else { 0 };
            Ok(())
        }
        Cmd::Location => {
            if global.op().followlocation == curlabi::CURLFOLLOW_OBEYCODE {
                warnf(diag, "--location overrides --follow");
            }
            global.op().followlocation = if toggle { curlabi::CURLFOLLOW_ALL } else { 0 };
            Ok(())
        }
        Cmd::MailRcptAllowfails => {
            global.op().mail_rcpt_allowfails = toggle;
            Ok(())
        }
        Cmd::Manual => {
            if toggle {
                return Err(ParameterError::ManualRequested);
            }
            Ok(())
        }
        Cmd::Mptcp => {
            global.op().mptcp = toggle;
            Ok(())
        }
        Cmd::Negotiate => {
            togglebit(
                toggle,
                &mut global.op().authtype,
                curlabi::CURLAUTH_NEGOTIATE,
            );
            Ok(())
        }
        Cmd::Netrc => {
            global.op().netrc = toggle;
            Ok(())
        }
        Cmd::NetrcOptional => {
            global.op().netrc_opt = toggle;
            Ok(())
        }
        Cmd::Ntlm => {
            togglebit(toggle, &mut global.op().authtype, curlabi::CURLAUTH_NTLM);
            Ok(())
        }
        Cmd::OutNull => parse_output(global.op(), None),
        Cmd::Parallel => {
            global.parallel = toggle;
            Ok(())
        }
        Cmd::ParallelImmediate => {
            global.parallel_connect = toggle;
            Ok(())
        }
        Cmd::PathAsIs => {
            global.op().path_as_is = toggle;
            Ok(())
        }
        Cmd::Post301 => {
            global.op().post301 = toggle;
            Ok(())
        }
        Cmd::Post302 => {
            global.op().post302 = toggle;
            Ok(())
        }
        Cmd::Post303 => {
            global.op().post303 = toggle;
            Ok(())
        }
        Cmd::ProgressBar => {
            global.progressmode = if toggle {
                ProgressMode::Bar
            } else {
                ProgressMode::Stats
            };
            Ok(())
        }
        Cmd::ProgressMeter => {
            global.noprogress = !toggle;
            Ok(())
        }
        Cmd::ProxyAnyauth => {
            global.op().proxyanyauth = toggle;
            Ok(())
        }
        Cmd::ProxyBasic => {
            global.op().proxybasic = toggle;
            Ok(())
        }
        Cmd::ProxyCaNative => {
            global.op().proxy_native_ca_store = toggle;
            Ok(())
        }
        Cmd::ProxyDigest => {
            global.op().proxydigest = toggle;
            Ok(())
        }
        Cmd::ProxyHttp2 => {
            global.op().proxyver = if toggle {
                curlabi::CURLPROXY_HTTPS2
            } else {
                curlabi::CURLPROXY_HTTPS
            };
            Ok(())
        }
        Cmd::ProxyInsecure => {
            global.op().proxy_insecure_ok = toggle;
            Ok(())
        }
        Cmd::ProxyNegotiate => {
            global.op().proxynegotiate = toggle;
            Ok(())
        }
        Cmd::ProxyNtlm => {
            global.op().proxyntlm = toggle;
            Ok(())
        }
        Cmd::ProxySslAllowBeast => {
            global.op().proxy_ssl_allow_beast = toggle;
            Ok(())
        }
        Cmd::ProxySslAutoClientCert => {
            global.op().proxy_ssl_auto_client_cert = toggle;
            Ok(())
        }
        Cmd::Proxytunnel => {
            global.op().proxytunnel = toggle;
            Ok(())
        }
        Cmd::Raw => {
            global.op().raw = toggle;
            Ok(())
        }
        Cmd::RemoteHeaderName => {
            global.op().content_disposition = toggle;
            Ok(())
        }
        Cmd::RemoteName => parse_remote_name(global.op(), toggle),
        Cmd::RemoteNameAll => {
            global.op().remote_name_all = toggle;
            Ok(())
        }
        Cmd::RemoteTime => {
            global.op().remote_time = toggle;
            Ok(())
        }
        Cmd::RemoveOnError => {
            if global.op().use_resume && toggle {
                errorf(
                    diag,
                    "--continue-at is mutually exclusive with --remove-on-error",
                );
                return Err(ParameterError::BadUse);
            }
            global.op().rm_partial = toggle;
            Ok(())
        }
        Cmd::RetryAllErrors => {
            global.op().retry_all_errors = toggle;
            Ok(())
        }
        Cmd::RetryConnrefused => {
            global.op().retry_connrefused = toggle;
            Ok(())
        }
        Cmd::SaslIr => {
            global.op().sasl_ir = toggle;
            Ok(())
        }
        Cmd::Sessionid => {
            global.op().disable_sessionid = !toggle;
            Ok(())
        }
        Cmd::ShowError => {
            global.showerror = toggle;
            Ok(())
        }
        Cmd::Silent => {
            global.silent = toggle;
            Ok(())
        }
        Cmd::SkipExisting => {
            global.op().skip_existing = toggle;
            Ok(())
        }
        Cmd::Socks5Basic => {
            togglebit(
                toggle,
                &mut global.op().socks5_auth,
                curlabi::CURLAUTH_BASIC,
            );
            Ok(())
        }
        Cmd::Socks5Gssapi => {
            togglebit(
                toggle,
                &mut global.op().socks5_auth,
                curlabi::CURLAUTH_GSSAPI,
            );
            Ok(())
        }
        Cmd::Socks5GssapiNec => {
            global.op().socks5_gssapi_nec = toggle;
            Ok(())
        }
        Cmd::SslAllowBeast => {
            global.op().ssl_allow_beast = toggle;
            Ok(())
        }
        Cmd::SslAutoClientCert => {
            global.op().ssl_auto_client_cert = toggle;
            Ok(())
        }
        Cmd::SslNoRevoke => {
            global.op().ssl_no_revoke = toggle;
            Ok(())
        }
        Cmd::SslRevokeBestEffort => {
            global.op().ssl_revoke_best_effort = toggle;
            Ok(())
        }
        Cmd::StyledOutput => {
            global.styled_output = toggle;
            Ok(())
        }
        Cmd::SuppressConnectHeaders => {
            global.op().suppress_connect_headers = toggle;
            Ok(())
        }
        Cmd::TcpFastopen => {
            global.op().tcp_fastopen = toggle;
            Ok(())
        }
        Cmd::TcpNodelay => {
            global.op().tcp_nodelay = toggle;
            Ok(())
        }
        Cmd::TftpNoOptions => {
            global.op().tftp_no_options = toggle;
            Ok(())
        }
        Cmd::TlsEarlydata => {
            global.op().ssl_allow_earlydata = toggle;
            Ok(())
        }
        Cmd::TrEncoding => {
            global.op().tr_encoding = toggle;
            Ok(())
        }
        Cmd::TraceIds => {
            global.traceids = toggle;
            Ok(())
        }
        Cmd::TraceTime => {
            global.tracetime = toggle;
            Ok(())
        }
        Cmd::UseAscii => {
            global.op().use_ascii = toggle;
            Ok(())
        }
        Cmd::Verbose => parse_verbose(global, toggle),
        Cmd::Version => {
            if toggle {
                return Err(ParameterError::VersionInfoRequested);
            }
            Ok(())
        }
        Cmd::Xattr => {
            global.op().xattr = toggle;
            Ok(())
        }
        // C `default:` — an unknown boolean command.
        _ => Err(ParameterError::OptionUnknown),
    }
}

// ---------------------------------------------------------------------------
// opt_string — options whose argument is an arbitrary string (ARG_STRG).
// ---------------------------------------------------------------------------

/// Port of `opt_string` (tool_getparam.c): the `switch` over string options — the
/// largest of the four dispatchers. Feature-capability gates are omitted (see the
/// Part 10 banner); intrinsic validations (`--max-redirs >= -1`, `--hostpubmd5`
/// length, TLS-SRP "SRP-only", `--tls-max` ordering, …) are preserved. `--variable`
/// and `-F`/`--form*` delegate to the [`GlobalConfig::variable_setter`] /
/// [`GlobalConfig::form_parser`] hooks.
fn opt_string(global: &mut GlobalConfig, cmd: Cmd, nextarg: &str) -> Result<(), ParameterError> {
    let diag = global.diag();
    match cmd {
        Cmd::AltSvc => getstr(&mut global.op().altsvc, nextarg, ALLOW_BLANK),
        Cmd::AwsSigv4 => {
            global.op().authtype |= curlabi::CURLAUTH_AWS_SIGV4;
            getstr(&mut global.op().aws_sigv4, nextarg, ALLOW_BLANK)
        }
        Cmd::CertType => getstr(&mut global.op().cert_type, nextarg, DENY_BLANK),
        Cmd::Ciphers => getstr(&mut global.op().cipher_list, nextarg, DENY_BLANK),
        Cmd::ConnectTimeout => {
            global.op().connecttimeout_ms = secs2ms(nextarg)?;
            Ok(())
        }
        Cmd::ConnectTo => add2list(&mut global.op().connect_to, nextarg),
        Cmd::ContinueAt => parse_continue_at(global.op(), diag, nextarg),
        Cmd::Cookie => {
            if nextarg.contains('=') {
                add2list(&mut global.op().cookies, nextarg)
            } else {
                add2list(&mut global.op().cookiefiles, nextarg)
            }
        }
        Cmd::CookieJar => getstr(&mut global.op().cookiejar, nextarg, DENY_BLANK),
        Cmd::CreateFileMode => {
            global.op().create_file_mode = oct2nummax(nextarg, 0o777)?;
            Ok(())
        }
        Cmd::Curves => getstr(&mut global.op().ssl_ec_curves, nextarg, DENY_BLANK),
        Cmd::Data
        | Cmd::DataAscii
        | Cmd::DataBinary
        | Cmd::DataRaw
        | Cmd::DataUrlencode
        | Cmd::Json => set_data(global.op(), diag, cmd, nextarg),
        Cmd::Delegation => {
            global.op().gssapi_delegation = delegation(diag, nextarg);
            Ok(())
        }
        Cmd::DnsInterface => getstr(&mut global.op().dns_interface, nextarg, DENY_BLANK),
        Cmd::DnsIpv4Addr => getstr(&mut global.op().dns_ipv4_addr, nextarg, DENY_BLANK),
        Cmd::DnsIpv6Addr => getstr(&mut global.op().dns_ipv6_addr, nextarg, DENY_BLANK),
        Cmd::DnsServers => getstr(&mut global.op().dns_servers, nextarg, DENY_BLANK),
        Cmd::DohUrl => {
            getstr(&mut global.op().doh_url, nextarg, ALLOW_BLANK)?;
            if global.op().doh_url.as_deref() == Some("") {
                global.op().doh_url = None;
            }
            Ok(())
        }
        Cmd::Ech => parse_ech(global.op(), diag, nextarg),
        Cmd::Engine => {
            getstr(&mut global.op().engine, nextarg, DENY_BLANK)?;
            if global.op().engine.as_deref() == Some("list") {
                return Err(ParameterError::EnginesRequested);
            }
            Ok(())
        }
        Cmd::Expect100Timeout => {
            global.op().expect100timeout_ms = secs2ms(nextarg)?;
            Ok(())
        }
        Cmd::Form | Cmd::FormString => {
            let literal = cmd == Cmd::FormString;
            let fp = global.form_parser;
            if let Some(f) = fp {
                f(nextarg, global.op(), literal)?;
            }
            set_http_request(diag, HttpReq::Mimepost, &mut global.op().httpreq)
        }
        Cmd::FtpAccount => getstr(&mut global.op().ftp_account, nextarg, DENY_BLANK),
        Cmd::FtpAlternativeToUser => getstr(
            &mut global.op().ftp_alternative_to_user,
            nextarg,
            DENY_BLANK,
        ),
        Cmd::FtpMethod => {
            global.op().ftp_filemethod = ftpfilemethod(diag, nextarg);
            Ok(())
        }
        Cmd::FtpPort => getstr(&mut global.op().ftpport, nextarg, DENY_BLANK),
        Cmd::FtpSslCccMode => {
            global.op().ftp_ssl_ccc = true;
            global.op().ftp_ssl_ccc_mode = ftpcccmethod(diag, nextarg);
            Ok(())
        }
        Cmd::HappyEyeballsTimeoutMs => {
            global.op().happy_eyeballs_timeout_ms = str2unum(nextarg)?;
            Ok(())
        }
        Cmd::HaproxyClientip => getstr(&mut global.op().haproxy_clientip, nextarg, DENY_BLANK),
        Cmd::Header | Cmd::ProxyHeader => parse_header(global.op(), diag, cmd, nextarg),
        // --help is intercepted by getparameter (returns HelpRequested); this arm is a
        // defensive duplicate so the signal is preserved even if reached directly.
        Cmd::Help => Err(ParameterError::HelpRequested),
        Cmd::Hostpubmd5 => {
            getstr(&mut global.op().hostpubmd5, nextarg, DENY_BLANK)?;
            match global.op().hostpubmd5.as_deref() {
                Some(s) if s.len() == 32 => Ok(()),
                _ => Err(ParameterError::BadUse),
            }
        }
        Cmd::Hostpubsha256 => getstr(&mut global.op().hostpubsha256, nextarg, DENY_BLANK),
        Cmd::Hsts => getstr(&mut global.op().hsts, nextarg, ALLOW_BLANK),
        Cmd::Interface => getstr(&mut global.op().iface, nextarg, DENY_BLANK),
        Cmd::IpTos => {
            if let Some(&(_, v)) = TOS_ENTRIES
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(nextarg))
            {
                global.op().ip_tos = v;
                Ok(())
            } else {
                global.op().ip_tos = str2unummax(nextarg, 0xFF)?;
                Ok(())
            }
        }
        #[cfg(feature = "ipfs")]
        Cmd::IpfsGateway => getstr(&mut global.op().ipfs_gateway, nextarg, DENY_BLANK),
        Cmd::KeepaliveCnt => {
            global.op().alivecnt = str2unum(nextarg)?;
            Ok(())
        }
        Cmd::KeepaliveTime => {
            global.op().alivetime = str2unum(nextarg)?;
            Ok(())
        }
        Cmd::KeyType => getstr(&mut global.op().key_type, nextarg, DENY_BLANK),
        Cmd::Libcurl => getstr(&mut global.libcurl, nextarg, DENY_BLANK),
        Cmd::LimitRate => {
            let v = get_size_parameter(nextarg)?;
            let op = global.op();
            op.recvpersecond = v;
            op.sendpersecond = v;
            Ok(())
        }
        Cmd::LocalPort => parse_localport(global.op(), nextarg),
        Cmd::LoginOptions => getstr(&mut global.op().login_options, nextarg, ALLOW_BLANK),
        Cmd::MailAuth => getstr(&mut global.op().mail_auth, nextarg, DENY_BLANK),
        Cmd::MailFrom => getstr(&mut global.op().mail_from, nextarg, DENY_BLANK),
        Cmd::MailRcpt => add2list(&mut global.op().mail_rcpt, nextarg),
        Cmd::MaxFilesize => {
            global.op().max_filesize = get_size_parameter(nextarg)?;
            Ok(())
        }
        Cmd::MaxRedirs => {
            let v = str2num(nextarg)?;
            if v < -1 {
                return Err(ParameterError::BadNumeric);
            }
            global.op().maxredirs = v;
            Ok(())
        }
        Cmd::MaxTime => {
            global.op().timeout_ms = secs2ms(nextarg)?;
            Ok(())
        }
        Cmd::Noproxy => getstr(&mut global.op().noproxy, nextarg, ALLOW_BLANK),
        Cmd::Oauth2Bearer => {
            global.op().authtype |= curlabi::CURLAUTH_BEARER;
            getstr(&mut global.op().oauth_bearer, nextarg, DENY_BLANK)
        }
        Cmd::OutputDir => getstr(&mut global.op().output_dir, nextarg, DENY_BLANK),
        Cmd::ParallelHost => {
            let v = str2unum(nextarg)?;
            global.parallel_host = if v > MAX_PARALLEL_HOST {
                MAX_PARALLEL_HOST as u16
            } else if v < 1 {
                PARALLEL_HOST_DEFAULT as u16
            } else {
                v as u16
            };
            Ok(())
        }
        Cmd::ParallelMax => {
            let v = str2unum(nextarg)?;
            global.parallel_max = if v > MAX_PARALLEL {
                MAX_PARALLEL as u16
            } else if v < 1 {
                PARALLEL_DEFAULT as u16
            } else {
                v as u16
            };
            Ok(())
        }
        Cmd::Pass => getstr(&mut global.op().key_passwd, nextarg, DENY_BLANK),
        Cmd::Pinnedpubkey => getstr(&mut global.op().pinnedpubkey, nextarg, DENY_BLANK),
        Cmd::Preproxy => getstr(&mut global.op().preproxy, nextarg, DENY_BLANK),
        Cmd::Proto => {
            global.op().proto_present = true;
            let s = proto2num(diag, PROTO_TOKENS, nextarg)?;
            global.op().proto_str = Some(s);
            Ok(())
        }
        Cmd::ProtoDefault => {
            getstr(&mut global.op().proto_default, nextarg, DENY_BLANK)?;
            let pd = global.op().proto_default.clone();
            if let Some(p) = pd {
                check_protocol(&p)?;
            }
            Ok(())
        }
        Cmd::ProtoRedir => {
            global.op().proto_redir_present = true;
            let s = proto2num(diag, REDIR_PROTOS, nextarg).map_err(|_| ParameterError::BadUse)?;
            global.op().proto_redir_str = Some(s);
            Ok(())
        }
        Cmd::Proxy => {
            getstr(&mut global.op().proxy, nextarg, ALLOW_BLANK)?;
            if global.op().proxyver != curlabi::CURLPROXY_HTTPS2 {
                global.op().proxyver = curlabi::CURLPROXY_HTTP;
            }
            Ok(())
        }
        Cmd::ProxyCertType => getstr(&mut global.op().proxy_cert_type, nextarg, DENY_BLANK),
        Cmd::ProxyCiphers => getstr(&mut global.op().proxy_cipher_list, nextarg, DENY_BLANK),
        Cmd::ProxyKeyType => getstr(&mut global.op().proxy_key_type, nextarg, DENY_BLANK),
        Cmd::ProxyPass => getstr(&mut global.op().proxy_key_passwd, nextarg, ALLOW_BLANK),
        Cmd::ProxyPinnedpubkey => getstr(&mut global.op().proxy_pinnedpubkey, nextarg, DENY_BLANK),
        Cmd::ProxyServiceName => getstr(&mut global.op().proxy_service_name, nextarg, DENY_BLANK),
        Cmd::ProxyTls13Ciphers => getstr(&mut global.op().proxy_cipher13_list, nextarg, DENY_BLANK),
        Cmd::ProxyTlsauthtype => {
            getstr(&mut global.op().proxy_tls_authtype, nextarg, DENY_BLANK)?;
            match global.op().proxy_tls_authtype.as_deref() {
                Some(t) if t != "SRP" => Err(ParameterError::LibcurlDoesntSupport),
                _ => Ok(()),
            }
        }
        Cmd::ProxyTlspassword => getstr(&mut global.op().proxy_tls_password, nextarg, DENY_BLANK),
        Cmd::ProxyTlsuser => getstr(&mut global.op().proxy_tls_username, nextarg, ALLOW_BLANK),
        Cmd::ProxyUser => getstr(&mut global.op().proxyuserpwd, nextarg, ALLOW_BLANK),
        Cmd::Proxy10 => {
            getstr(&mut global.op().proxy, nextarg, DENY_BLANK)?;
            global.op().proxyver = curlabi::CURLPROXY_HTTP_1_0;
            Ok(())
        }
        Cmd::Pubkey => getstr(&mut global.op().pubkey, nextarg, DENY_BLANK),
        Cmd::Quote => parse_quote(global.op(), nextarg),
        Cmd::Range => parse_range(global.op(), diag, nextarg),
        Cmd::Rate => set_rate(global, nextarg),
        Cmd::Referer => {
            let mut len = nextarg.len();
            if len >= 5 && &nextarg[len - 5..] == ";auto" {
                global.op().autoreferer = true;
                len -= 5;
            } else {
                global.op().autoreferer = false;
            }
            if len > 0 {
                getstrn(&mut global.op().referer, nextarg, len, ALLOW_BLANK)
            } else {
                global.op().referer = None;
                Ok(())
            }
        }
        Cmd::Request => getstr(&mut global.op().customrequest, nextarg, DENY_BLANK),
        Cmd::RequestTarget => getstr(&mut global.op().request_target, nextarg, DENY_BLANK),
        Cmd::Resolve => add2list(&mut global.op().resolve, nextarg),
        Cmd::Retry => {
            global.op().req_retry = str2unum(nextarg)?;
            Ok(())
        }
        Cmd::RetryDelay => {
            global.op().retry_delay_ms = secs2ms(nextarg)?;
            Ok(())
        }
        Cmd::RetryMaxTime => {
            global.op().retry_maxtime_ms = secs2ms(nextarg)?;
            Ok(())
        }
        Cmd::SaslAuthzid => getstr(&mut global.op().sasl_authzid, nextarg, DENY_BLANK),
        Cmd::ServiceName => getstr(&mut global.op().service_name, nextarg, DENY_BLANK),
        Cmd::SignatureAlgorithms => getstr(
            &mut global.op().ssl_signature_algorithms,
            nextarg,
            DENY_BLANK,
        ),
        Cmd::Socks4 => {
            getstr(&mut global.op().proxy, nextarg, DENY_BLANK)?;
            global.op().proxyver = curlabi::CURLPROXY_SOCKS4;
            Ok(())
        }
        Cmd::Socks4a => {
            getstr(&mut global.op().proxy, nextarg, DENY_BLANK)?;
            global.op().proxyver = curlabi::CURLPROXY_SOCKS4A;
            Ok(())
        }
        Cmd::Socks5 => {
            getstr(&mut global.op().proxy, nextarg, DENY_BLANK)?;
            global.op().proxyver = curlabi::CURLPROXY_SOCKS5;
            Ok(())
        }
        // --socks5-gssapi-service has a table entry but no handler in curl 8.x
        // (the arg is consumed and ignored); preserved here as an explicit no-op.
        Cmd::Socks5GssapiService => Ok(()),
        Cmd::Socks5Hostname => {
            getstr(&mut global.op().proxy, nextarg, DENY_BLANK)?;
            global.op().proxyver = curlabi::CURLPROXY_SOCKS5_HOSTNAME;
            Ok(())
        }
        Cmd::SpeedLimit => {
            global.op().low_speed_limit = str2unum(nextarg)?;
            if global.op().low_speed_time == 0 {
                global.op().low_speed_time = 30;
            }
            Ok(())
        }
        Cmd::SpeedTime => {
            global.op().low_speed_time = str2unum(nextarg)?;
            if global.op().low_speed_limit == 0 {
                global.op().low_speed_limit = 1;
            }
            Ok(())
        }
        Cmd::TelnetOption => add2list(&mut global.op().telnet_options, nextarg),
        Cmd::TftpBlksize => {
            global.op().tftp_blksize = str2unum(nextarg)?;
            Ok(())
        }
        Cmd::TimeCond => parse_time_cond(global.op(), diag, nextarg),
        Cmd::TlsMax => {
            let v = str2tls_max(nextarg)?;
            global.op().ssl_version_max = v;
            if global.op().ssl_version_max < global.op().ssl_version {
                errorf(diag, "--tls-max set lower than minimum accepted version");
                return Err(ParameterError::BadUse);
            }
            Ok(())
        }
        Cmd::Tls13Ciphers => getstr(&mut global.op().cipher13_list, nextarg, DENY_BLANK),
        Cmd::Tlsauthtype => {
            getstr(&mut global.op().tls_authtype, nextarg, DENY_BLANK)?;
            match global.op().tls_authtype.as_deref() {
                Some(t) if t != "SRP" => Err(ParameterError::LibcurlDoesntSupport),
                _ => Ok(()),
            }
        }
        Cmd::Tlspassword => getstr(&mut global.op().tls_password, nextarg, ALLOW_BLANK),
        Cmd::Tlsuser => getstr(&mut global.op().tls_username, nextarg, DENY_BLANK),
        Cmd::TraceConfig => {
            global.trace_set = true;
            set_trace_config(global, nextarg);
            Ok(())
        }
        Cmd::UploadFlags => parse_upload_flags(global.op(), nextarg),
        Cmd::Url => parse_url(global.op(), diag, nextarg),
        Cmd::UrlQuery => url_query(global.op(), diag, nextarg),
        Cmd::User => getstr(&mut global.op().userpwd, nextarg, ALLOW_BLANK),
        Cmd::UserAgent => getstr(&mut global.op().useragent, nextarg, ALLOW_BLANK),
        Cmd::Variable => {
            let vs = global.variable_setter;
            match vs {
                Some(f) => f(nextarg, global),
                None => Ok(()),
            }
        }
        Cmd::VlanPriority => {
            global.op().vlan_priority = str2unummax(nextarg, 7)?;
            Ok(())
        }
        Cmd::WriteOut => parse_writeout(global.op(), diag, nextarg),
        // Deprecated ARG_STRG (egd-file/krb/krb4) route to opt_depr; any other cmd is a
        // no-op (matching the C switch's fall-through with err == PARAM_OK).
        _ => Ok(()),
    }
}

// ===========================================================================
// Part 11 — public entry points: getparameter + parse_args
//
// Faithful ports of tool_getparam.c's `getparameter()` (decode one
// `flag`/`nextarg` pair and mutate the current operation) and `parse_args()`
// (walk `argv`, drive getparameter, thread the `--next` operation chain, and
// treat bare arguments as URLs).
//
// Threading model: the C functions take an explicit `struct OperationConfig
// *config`; here the current operation is reached through [`GlobalConfig::op`],
// and the Part 10 dispatchers (`opt_none`/`opt_bool`/`opt_file`/`opt_string`)
// all accept `&mut GlobalConfig`. The C out-parameter `bool *usedarg` becomes
// the `Ok(bool)` payload of [`getparameter`].
//
// Flow-control signals (`PARAM_NEXT_OPERATION`, `PARAM_HELP_REQUESTED`,
// `PARAM_MANUAL_REQUESTED`, `PARAM_VERSION_INFO_REQUESTED`,
// `PARAM_ENGINES_REQUESTED`, `PARAM_CA_EMBED_REQUESTED`) are modeled as `Err`
// variants of [`ParameterError`]; [`parse_args`] intercepts them exactly as the
// C control flow does and converts `NextOperation` into an operation push
// rather than an error return.
// ===========================================================================

/// Port of `has_leading_unicode` (tool_getparam.c): detect an argument whose
/// first bytes are the UTF-8 encoding of a "fancy" Unicode dash/space lookalike
/// (`0xE2 0x80 ..`), used to warn when such a character was likely pasted in
/// place of an ASCII `-`. The explicit length guard replaces C's reliance on
/// the NUL terminator — a borrowed `&str` is not guaranteed to hold three bytes.
fn has_leading_unicode(arg: &[u8]) -> bool {
    arg.len() >= 3 && arg[0] == 0xe2 && arg[1] == 0x80 && (arg[2] & 0x80) != 0
}

/// Apply a single command-line option, mirroring `getparameter()`
/// (tool_getparam.c).
///
/// `flag` is the raw option token — a bundle of short letters (`-sS`), a long
/// name (`--verbose`), an attached long value (`--data=x`), a `--no-<name>`
/// negation, an `--expand-<name>` variable expansion, or (from a config file) a
/// bare word. `nextarg` is the *following* argv element (the candidate value),
/// or `None` when `flag` is the last token.
///
/// On success the returned `bool` is C's `*usedarg`: `true` when `nextarg` was
/// consumed as this option's value (the caller must skip it), `false` otherwise
/// (bundled short options, attached `-ovalue`, `--opt=value`, and value-less
/// options). `max_recursive` is the remaining config-file inclusion budget
/// threaded into [`opt_file`] for `--config` (C `CONFIG_MAX_LEVELS`).
///
/// # Deviations
/// * The C `ARG_TLS`/`feature_ssl` capability gate is intentionally omitted:
///   this build always has TLS (rustls), so no option is rejected as
///   unsupported here (runtime capability checks live in `setopt.rs`).
/// * `ARG_CLEAR` (C `cleanarg`, which zeroes a password argument in place in
///   `argv`) cannot be honored: `nextarg` is a borrowed `&str` into memory this
///   function does not own, so the sensitive bytes are left untouched. This is a
///   documented parity gap with no effect on parsing behavior.
pub fn getparameter(
    flag: &str,
    nextarg: Option<&str>,
    global: &mut GlobalConfig,
    max_recursive: i32,
) -> Result<bool, ParameterError> {
    // Reset the per-`flag` short-option counter consulted by `parse_verbose`
    // (so a bundle such as `-vv` escalates verbosity level by level).
    VERBOSE_NOPTS.store(0, std::sync::atomic::Ordering::Relaxed);

    let mut usedarg = false; // C `*usedarg`, default FALSE
    let mut longopt = false;
    let mut singleopt = false; // "-ofoo" attached form: do not loop further
    let mut toggle = true; // boolean sense, flipped by a `--no-` prefix
    let mut consumearg = true; // the value is a separate argv element
                               // Working copy of the candidate value; may be replaced by the `=value` split
                               // or by `--expand-` variable expansion, so it is owned rather than borrowed.
    let mut nextarg: Option<String> = nextarg.map(str::to_owned);
    let mut a: Option<&'static OptDef> = None;

    let flagb = flag.as_bytes();
    // C: `('-' != flag[0]) || ('-' == flag[1])` — a long name is either a bare
    // word (no leading dash) or a token beginning with "--".
    let is_long = flagb.first() != Some(&b'-') || flagb.get(1) == Some(&b'-');

    if is_long {
        // Strip a leading "--" (a config-file key arrives with no dashes).
        let word_full: &str = if flagb.first() == Some(&b'-') {
            &flag[2..]
        } else {
            flag
        };
        let mut word = word_full;
        let mut noflagged = false;
        let mut expand = false;

        if let Some(rest) = word.strip_prefix("no-") {
            // Disable this option; look it up without the "no-" part.
            word = rest;
            toggle = false;
            noflagged = true;
        } else if let Some(rest) = word.strip_prefix("expand-") {
            // Variable expansion is to be performed on the argument.
            word = rest;
            expand = true;
        }

        // Is there an '='? C caps the name at MAX_OPTION_LEN before the '='
        // (curlx_str_until); a name longer than that cannot match an option, so
        // the split is only taken when the '=' falls within the cap.
        match word.find('=') {
            Some(eq) if eq <= MAX_OPTION_LEN => {
                let (name, rest) = word.split_at(eq);
                a = findlongopt(name);
                nextarg = Some(rest[1..].to_owned()); // value after the '='
                consumearg = false; // it is attached, not separate
            }
            _ => {
                a = findlongopt(word);
            }
        }

        let ad = match a {
            Some(ad) => ad,
            None => return Err(ParameterError::OptionUnknown),
        };
        longopt = true;

        if noflagged && ad.typ != ArgType::Bool {
            // `--no-` prefixed an option that is not boolean.
            return Err(ParameterError::NoPrefix);
        } else if expand {
            // C only expands when a value is present (`expand && nextarg`).
            if let Some(na) = nextarg.clone() {
                if ad.typ != ArgType::Strg && ad.typ != ArgType::File {
                    // `--expand-` on an option that is not a string or filename.
                    return Err(ParameterError::ExpandError);
                }
                // Delegate to var.rs's `varexpand` via the wired hook. When no
                // hook is installed (e.g. unit tests) the argument is used
                // verbatim, matching C's `replaced == FALSE` path.
                let expander = global.variable_expander;
                if let Some(f) = expander {
                    if let Some(replaced) = f(na.as_str(), &*global)? {
                        nextarg = Some(replaced);
                    }
                }
            }
        }
    }

    // The short-option letters to iterate (empty for a long option, which runs
    // the body exactly once — C's `do { } while(!longopt && ...)`).
    let short_bytes: &[u8] = if longopt { &[] } else { &flagb[1..] };
    let mut idx = 0usize;

    loop {
        let ad: &'static OptDef = if !longopt {
            // C: `a = findshortopt(*parse); toggle = !(a->desc & ARG_NO);`
            let letter = match short_bytes.get(idx) {
                Some(&b) => b,
                None => return Err(ParameterError::OptionUnknown),
            };
            match findshortopt(letter) {
                Some(x) => {
                    toggle = (x.flags & ARG_NO) == 0;
                    x
                }
                None => return Err(ParameterError::OptionUnknown),
            }
        } else {
            a.unwrap()
        };

        // NOTE: the C `(a->desc & ARG_TLS) && !feature_ssl` rejection is omitted
        // (see the function docstring) — TLS is always available in this build.
        if ad.typ.takes_arg() {
            // This option requires an extra parameter.
            if !longopt && idx + 1 < short_bytes.len() {
                // Attached short value: `-ovalue`. The rest of the bundle is it.
                let rest = &short_bytes[idx + 1..];
                nextarg = Some(String::from_utf8_lossy(rest).into_owned());
                singleopt = true; // do not loop anymore after this
            } else if ad.cmd == Cmd::Help {
                // `--help`/`-h` is special: signal help regardless of any arg. Capture the
                // optional `<category>` subject (curl's `tool_help(category)` argument) so the
                // deferred render site in `operate.rs` can filter by category (← the
                // `num_args(0..=1)` optional-subject handling; `src/tool_help.c`).
                global.help_category = nextarg.clone();
                return Err(ParameterError::HelpRequested);
            } else if nextarg.is_none() {
                return Err(ParameterError::RequiresParameter);
            } else {
                usedarg = consumearg; // mark the separate arg as used
            }

            if ad.flags & ARG_DEPR != 0 {
                // Deprecated option: warn and stop (the value is still consumed).
                opt_depr(global.diag(), ad.lname);
                break;
            }

            let na = nextarg.clone().unwrap_or_default();
            if has_leading_unicode(na.as_bytes()) {
                let diag = global.diag();
                warnf(
                    diag,
                    &format!(
                        "The argument '{na}' starts with a Unicode character. \
                         Maybe ASCII was intended?"
                    ),
                );
            }
            if ad.typ == ArgType::File {
                opt_file(global, ad.cmd, ad.lname, &na, max_recursive)?;
            } else {
                opt_string(global, ad.cmd, &na)?;
            }
            // ARG_CLEAR (`cleanarg`) is a documented no-op here (see docstring).
        } else {
            // ARG_NONE | ARG_BOOL — a value-less option.
            if ad.flags & ARG_DEPR != 0 {
                opt_depr(global.diag(), ad.lname);
                break;
            }
            if ad.typ == ArgType::Bool {
                opt_bool(global, ad.cmd, ad.lname, toggle)?;
            } else {
                opt_none(global, ad.cmd)?;
            }
        }

        // Processed one option from `flag`; count it for `parse_verbose`.
        VERBOSE_NOPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // C loop condition: `!longopt && !singleopt && *++parse && !*usedarg`
        // (the `!err` term is handled by `?` above, which returns early).
        if longopt || singleopt {
            break;
        }
        idx += 1;
        if idx >= short_bytes.len() {
            break; // `*++parse == '\0'`
        }
        if usedarg {
            break;
        }
    }

    Ok(usedarg)
}

/// Walk `argv` and apply every option and URL, mirroring `parse_args()`
/// (tool_getparam.c).
///
/// `argv[0]` is the program name and is skipped (C starts its loop at `i == 1`);
/// the remaining elements are options, their values, and URLs. Bare arguments
/// (not beginning with `-`, or anything following a lone `--`) are added as URLs
/// via the synthetic `--url` option, exactly as C does. `--next` is handled
/// here: on `PARAM_NEXT_OPERATION` a fresh [`OperationConfig`] is pushed
/// (provided the current one already carries a URL), matching C's `config_alloc`
/// / `global->last` advance.
///
/// On a hard parse error the curl-style diagnostic (`curl: option <opt>:
/// <reason>` or `curl: <reason>`) is emitted before returning; the flow-control
/// signals (`HelpRequested`, `ManualRequested`, `VersionInfoRequested`,
/// `EnginesRequested`, `CaEmbedRequested`) are returned untouched so
/// `main.rs`/`operate.rs` can act on them (print help/version, then exit clean).
///
/// # Deviations
/// * Arguments that are not valid UTF-8 are rejected with
///   [`ParameterError::NoMem`], mirroring C's treatment of a failed
///   `convert_tchar_to_UTF8`. The rest of the parser operates on `&str`, so a
///   lossless `OsStr` path is not threaded through.
pub fn parse_args(argv: &[OsString], global: &mut GlobalConfig) -> Result<(), ParameterError> {
    let argc = argv.len();
    let mut stillflags = true;
    let mut err: Result<(), ParameterError> = Ok(());
    // The token currently under consideration, kept for the trailing diagnostic
    // (C keeps `orig_opt` live across the loop and frees it only on success).
    let mut orig_opt: Option<String> = None;

    let mut i = 1usize;
    while i < argc && err.is_ok() {
        let opt: String = match argv[i].to_str() {
            Some(s) => s.to_owned(),
            None => return Err(ParameterError::NoMem),
        };
        orig_opt = Some(opt.clone());

        if stillflags && opt.as_bytes().first() == Some(&b'-') {
            if opt == "--" {
                // End of flags: subsequent args (even leading-dash) are URLs.
                stillflags = false;
            } else {
                // The following argv element is the candidate value.
                let nextarg: Option<String> = if i < argc - 1 {
                    match argv[i + 1].to_str() {
                        Some(s) => Some(s.to_owned()),
                        None => return Err(ParameterError::NoMem),
                    }
                } else {
                    None
                };

                match getparameter(&opt, nextarg.as_deref(), global, CONFIG_MAX_LEVELS) {
                    Err(ParameterError::NextOperation) => {
                        // Not a real error: advance the operation chain, but only
                        // when the just-finished operation already has a URL.
                        let has_url = global
                            .op_ref()
                            .url_list
                            .first()
                            .map(|g| g.url.is_some())
                            .unwrap_or(false);
                        if has_url {
                            global.push_operation();
                        } else {
                            errorf(global.diag(), "missing URL before --next");
                            err = Err(ParameterError::BadUse);
                        }
                    }
                    Err(e) => err = Err(e),
                    Ok(passarg) => {
                        if passarg {
                            i += 1; // skip the value we just consumed
                        }
                    }
                }
            }
        } else {
            // Bare argument: add it as a URL.
            err = getparameter("--url", Some(&opt), global, 0).map(|_| ());
        }

        if err.is_ok() {
            orig_opt = None;
        }
        i += 1;
    }

    // A `-C -` (resume from the content-disposition target) combined with `-J`
    // (`content_disposition`) is contradictory.
    if err.is_ok() {
        let op = global.op_ref();
        if op.content_disposition && op.resume_from_current {
            err = Err(ParameterError::ContdispResumeFrom);
        }
    }

    // Emit the diagnostic for hard failures; flow-control signals pass through.
    if let Err(e) = err {
        if !matches!(
            e,
            ParameterError::HelpRequested
                | ParameterError::ManualRequested
                | ParameterError::VersionInfoRequested
                | ParameterError::EnginesRequested
                | ParameterError::CaEmbedRequested
        ) {
            let reason = param_geterror(e);
            match orig_opt.as_deref() {
                Some(opt) if opt != ":" => {
                    helpf(Some(&format!("option {opt}: {reason}")));
                }
                _ => helpf(Some(reason)),
            }
        }
    }

    err
}

// ===========================================================================
// Part 12 — clap command surface (help rendering + shell completion)
//
// The authoritative *parser* is the hand-rolled [`getparameter`]/[`parse_args`]
// pair above, which reproduces curl's byte-exact option grammar (bundled short
// flags, `--no-`/`--expand-` prefixes, `=value`, `@file`, etc.). This section
// builds the parallel `clap` v4 command surface mandated by AAP §0.1.1 /
// §0.3.2, driven by the same [`OPTIONS`] table (the analog of curl's C
// `aliases[]`), so it is 1:1 with `docs/cmdline-opts/*.md` by construction. It
// is used for `--help`/`--help all` rendering parity and for `clap_complete`
// shell-completion generation — never as a second, divergent parser.
// ===========================================================================

/// Derive a `clap` value-name from an option's `Arg:` placeholder as written in
/// its `docs/cmdline-opts` page (e.g. `<file>` → `file`, `<[%]name=text/@file>`
/// → `[%]name=text/@file`). One surrounding `<...>` layer is stripped; an empty
/// placeholder falls back to a generic `value`.
fn value_name_of(arg: &str) -> String {
    let t = arg.trim();
    let t = t.strip_prefix('<').unwrap_or(t);
    let t = t.strip_suffix('>').unwrap_or(t);
    if t.is_empty() {
        "value".to_string()
    } else {
        t.to_string()
    }
}

/// Build the `clap` [`Command`](clap::Command) mirroring curl's option surface,
/// generated 1:1 from the [`OPTIONS`] table.
///
/// Mapping rules (from `docs/cmdline-opts/MANPAGE.md`):
/// * `lname` → [`Arg::long`](clap::Arg::long); a non-zero `letter` →
///   [`Arg::short`](clap::Arg::short).
/// * `help` → the one-line help text, preserved verbatim for `--help` parity.
/// * A value-taking option ([`ArgType::Strg`]/[`ArgType::File`]) gets
///   `num_args(1)` and a value-name from its `Arg:` placeholder; `--help`
///   (`Cmd::Help`) is special-cased to `num_args(0..=1)` because its `<subject>`
///   is optional.
/// * `Multi: append` → [`ArgAction::Append`](clap::ArgAction::Append); other
///   value-taking multis → [`ArgAction::Set`](clap::ArgAction::Set) (last wins).
/// * A value-less boolean/none option → [`ArgAction::SetTrue`]; every
///   [`ArgType::Bool`] option additionally gets a hidden `--no-<name>` negation,
///   mirroring [`getparameter`]'s `--no-` handling and curl's `ARG_BOOL|ARG_NO`.
/// * Deprecated options (`ARG_DEPR`) are accepted but [`hidden`](clap::Arg::hide)
///   from the help output.
///
/// clap's own auto `-h/--help` and `-V/--version` flags are disabled because the
/// table already supplies `help`/`version` (curl's canonical spellings).
pub fn build_cli_command() -> clap::Command {
    use clap::{Arg, ArgAction, Command};

    let mut cmd = Command::new("curl")
        .bin_name("curl")
        .version(env!("CARGO_PKG_VERSION"))
        .about("transfer a URL — reimplemented in safe Rust (curl 8.x flag surface)")
        .override_usage("curl [options / URLs]")
        .disable_help_flag(true)
        .disable_version_flag(true);

    for od in OPTIONS.iter() {
        let mut arg = Arg::new(od.lname).long(od.lname);

        // Short letter (0 / ' ' means "no short option" in the table).
        if od.letter != 0 && od.letter != b' ' {
            arg = arg.short(od.letter as char);
        }
        if !od.help.is_empty() {
            arg = arg.help(od.help);
        }

        if od.typ.takes_arg() {
            arg = arg.value_name(value_name_of(od.arg));
            // `--help` takes an OPTIONAL subject; every other value option
            // requires exactly one value.
            arg = if od.cmd == Cmd::Help {
                arg.num_args(0..=1)
            } else {
                arg.num_args(1)
            };
            arg = match od.multi {
                Multi::Append => arg.action(ArgAction::Append),
                _ => arg.action(ArgAction::Set),
            };
        } else {
            // ARG_NONE | ARG_BOOL — a flag that stores `true` when present.
            arg = arg.action(ArgAction::SetTrue);
        }

        if od.flags & ARG_DEPR != 0 {
            arg = arg.hide(true);
        }

        cmd = cmd.arg(arg);

        // Boolean options also accept a hidden `--no-<name>` negation. No
        // canonical option name begins with `no-`, so these IDs never collide.
        if matches!(od.typ, ArgType::Bool) {
            let no_long = format!("no-{}", od.lname);
            let no_arg = Arg::new(no_long.clone())
                .long(no_long)
                .action(ArgAction::SetTrue)
                .hide(true);
            cmd = cmd.arg(no_arg);
        }
    }

    // Positional URL operands: curl accepts zero or more bare URLs (globbing and
    // the getout list are resolved by the real parser / `urlglob.rs`). The id is
    // `urls` to avoid colliding with the `--url` option's id (`url`).
    cmd = cmd.arg(
        Arg::new("urls")
            .action(ArgAction::Append)
            .num_args(0..)
            .value_name("URL")
            .help("URL(s) to work with"),
    );

    cmd
}

/// Write a shell-completion script for `shell` to `out`, using the
/// [`build_cli_command`] surface. This is the `clap_complete` counterpart to
/// curl's packaged completion scripts (AAP §0.1.1: "clap + clap_complete … CLI
/// argument parsing + shell completion"). The command is named `curl` in the
/// generated script to match the completions users expect.
pub fn generate_completion<W: std::io::Write>(shell: clap_complete::Shell, out: &mut W) {
    let mut cmd = build_cli_command();
    clap_complete::generate(shell, &mut cmd, "curl", out);
}

// ===========================================================================
// Part 13 — unit tests
//
// These exercise the option vocabulary and the two public entry points against
// curl's documented behavior: the `ParameterError` code set, the `OPTIONS`
// table's integrity (size + uniqueness), the finders, the clap surface, and the
// byte-exact parsing rules of `getparameter`/`parse_args` (bundled short flags,
// attached vs. separate values, `--no-`/`--expand-`/`=value` prefixes, `--next`
// operation chaining, bare-URL handling, and the help/version flow-control
// signals). They are self-contained: no filesystem, network, or sibling-module
// hook is required (hooks default to `None`, which the parser tolerates).
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    /// Build an `argv`-shaped `Vec<OsString>` (element 0 is the program name).
    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    // ---- ParameterError -----------------------------------------------------

    #[test]
    fn param_ok_is_zero_and_last_is_final() {
        assert_eq!(ParameterError::Ok as u32, 0);
        // `Recursion` is the last real code; `Last` is the sentinel just past it.
        assert_eq!(
            ParameterError::Recursion as u32 + 1,
            ParameterError::Last as u32
        );
    }

    #[test]
    fn param_geterror_is_nonempty_for_real_errors() {
        for e in [
            ParameterError::OptionUnknown,
            ParameterError::RequiresParameter,
            ParameterError::BadUse,
            ParameterError::BadNumeric,
            ParameterError::NoPrefix,
            ParameterError::ExpandError,
            ParameterError::ContdispResumeFrom,
        ] {
            assert!(!param_geterror(e).is_empty(), "empty text for {e:?}");
        }
    }

    // ---- OPTIONS table integrity -------------------------------------------

    #[test]
    fn options_table_has_expected_size() {
        // 279 = the curl 8.x option surface minus the 3 dropped build-only rows
        // (DEBUGBUILD test-duphandle/test-event, USE_WATT32 wdebug).
        assert_eq!(OPTIONS.len(), 279);
    }

    #[test]
    fn options_long_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for o in OPTIONS.iter() {
            assert!(seen.insert(o.lname), "duplicate long name: {}", o.lname);
        }
    }

    #[test]
    fn options_short_letters_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for o in OPTIONS.iter() {
            if o.letter != 0 && o.letter != b' ' {
                assert!(
                    seen.insert(o.letter),
                    "duplicate short letter: -{}",
                    o.letter as char
                );
            }
        }
    }

    #[test]
    fn options_table_is_sorted_by_long_name() {
        // curl's `aliases[]` is alphasorted; `findlongopt` relies on the names,
        // but preserving the order keeps `--help` output identical to curl.
        for w in OPTIONS.windows(2) {
            assert!(
                w[0].lname < w[1].lname,
                "table out of order: {} then {}",
                w[0].lname,
                w[1].lname
            );
        }
    }

    #[test]
    fn finders_resolve_known_options() {
        assert_eq!(findlongopt("verbose").map(|o| o.cmd), Some(Cmd::Verbose));
        assert_eq!(findlongopt("output").map(|o| o.cmd), Some(Cmd::Output));
        assert!(findlongopt("definitely-not-an-option").is_none());
        assert_eq!(findshortopt(b'o').map(|o| o.cmd), Some(Cmd::Output));
        assert_eq!(findshortopt(b'v').map(|o| o.cmd), Some(Cmd::Verbose));
        assert!(findshortopt(0).is_none());
        assert!(findshortopt(b' ').is_none());
        // `-W` is not assigned by curl 8.x (unlike `-Z` = --parallel).
        assert!(findshortopt(b'W').is_none());
    }

    // ---- clap surface -------------------------------------------------------

    #[test]
    fn clap_command_builds_without_conflicts() {
        // clap's debug_assert validates unique ids/longs/shorts and panics on any
        // conflict — this proves the table-driven surface is internally consistent.
        build_cli_command().debug_assert();
    }

    #[test]
    fn completion_generation_produces_output() {
        let mut buf: Vec<u8> = Vec::new();
        generate_completion(clap_complete::Shell::Bash, &mut buf);
        assert!(!buf.is_empty(), "empty completion script");
        assert!(String::from_utf8_lossy(&buf).contains("curl"));
    }

    // ---- getparameter: prefixes, bundling, attached/separate values ---------

    #[test]
    fn long_bool_sets_state() {
        let mut g = GlobalConfig::new();
        let used = getparameter("--verbose", None, &mut g, CONFIG_MAX_LEVELS).unwrap();
        assert!(!used, "a value-less bool must not consume the next arg");
        assert_eq!(g.verbosity, 1);
    }

    #[test]
    fn no_prefix_toggles_a_bool_off() {
        let mut g = GlobalConfig::new();
        // `--no-buffer` (curl's ARG_NO `buffer`) sets `nobuffer = true`.
        getparameter("--no-buffer", None, &mut g, CONFIG_MAX_LEVELS).unwrap();
        assert!(g.op_ref().nobuffer);
    }

    #[test]
    fn no_prefix_on_nonbool_is_error() {
        let mut g = GlobalConfig::new();
        let e = getparameter("--no-output", Some("f"), &mut g, CONFIG_MAX_LEVELS).unwrap_err();
        assert_eq!(e, ParameterError::NoPrefix);
    }

    #[test]
    fn short_separate_value_is_consumed() {
        let mut g = GlobalConfig::new();
        let used = getparameter("-o", Some("out.txt"), &mut g, CONFIG_MAX_LEVELS).unwrap();
        assert!(used, "`-o file` must consume the following arg");
        assert!(g
            .op_ref()
            .url_list
            .iter()
            .any(|n| n.outfile.as_deref() == Some("out.txt")));
    }

    #[test]
    fn short_attached_value_is_not_consumed() {
        let mut g = GlobalConfig::new();
        let used = getparameter("-oout.txt", Some("UNUSED"), &mut g, CONFIG_MAX_LEVELS).unwrap();
        assert!(
            !used,
            "`-ofile` attaches the value; must not consume next arg"
        );
        assert!(g
            .op_ref()
            .url_list
            .iter()
            .any(|n| n.outfile.as_deref() == Some("out.txt")));
    }

    #[test]
    fn long_equals_value_is_not_consumed() {
        let mut g = GlobalConfig::new();
        let used =
            getparameter("--output=eq.txt", Some("UNUSED"), &mut g, CONFIG_MAX_LEVELS).unwrap();
        assert!(!used, "`--opt=value` attaches the value");
        assert!(g
            .op_ref()
            .url_list
            .iter()
            .any(|n| n.outfile.as_deref() == Some("eq.txt")));
    }

    #[test]
    fn long_string_option_sets_field() {
        let mut g = GlobalConfig::new();
        let used = getparameter("--user-agent", Some("me/1.0"), &mut g, CONFIG_MAX_LEVELS).unwrap();
        assert!(used);
        assert_eq!(g.op_ref().useragent.as_deref(), Some("me/1.0"));
    }

    #[test]
    fn bundled_short_flags_all_apply() {
        let mut g = GlobalConfig::new();
        // `-sS` = silent + show-error (two value-less global bools in one token).
        let used = getparameter("-sS", None, &mut g, CONFIG_MAX_LEVELS).unwrap();
        assert!(!used);
        assert!(g.silent, "-s should set silent");
        assert!(g.showerror, "-S should set showerror");
    }

    #[test]
    fn unknown_options_error() {
        let mut g = GlobalConfig::new();
        assert_eq!(
            getparameter("--totally-unknown", None, &mut g, CONFIG_MAX_LEVELS).unwrap_err(),
            ParameterError::OptionUnknown
        );
        // `-W` is an unassigned short letter in curl 8.x.
        assert_eq!(
            getparameter("-W", None, &mut g, CONFIG_MAX_LEVELS).unwrap_err(),
            ParameterError::OptionUnknown
        );
    }

    #[test]
    fn missing_required_parameter_errors() {
        let mut g = GlobalConfig::new();
        assert_eq!(
            getparameter("--user-agent", None, &mut g, CONFIG_MAX_LEVELS).unwrap_err(),
            ParameterError::RequiresParameter
        );
    }

    // ---- getparameter: flow-control signals ---------------------------------

    #[test]
    fn help_and_version_are_flow_control_signals() {
        let mut g = GlobalConfig::new();
        assert_eq!(
            getparameter("--help", None, &mut g, CONFIG_MAX_LEVELS).unwrap_err(),
            ParameterError::HelpRequested
        );
        assert_eq!(
            getparameter("--version", None, &mut g, CONFIG_MAX_LEVELS).unwrap_err(),
            ParameterError::VersionInfoRequested
        );
        assert_eq!(
            getparameter("-h", None, &mut g, CONFIG_MAX_LEVELS).unwrap_err(),
            ParameterError::HelpRequested
        );
    }

    // ---- getparameter: --expand- --------------------------------------------

    #[test]
    fn expand_without_hook_uses_argument_verbatim() {
        let mut g = GlobalConfig::new();
        getparameter(
            "--expand-user-agent",
            Some("{{x}}"),
            &mut g,
            CONFIG_MAX_LEVELS,
        )
        .unwrap();
        assert_eq!(g.op_ref().useragent.as_deref(), Some("{{x}}"));
    }

    #[test]
    fn expand_on_bool_option_is_error() {
        let mut g = GlobalConfig::new();
        assert_eq!(
            getparameter("--expand-verbose", Some("x"), &mut g, CONFIG_MAX_LEVELS).unwrap_err(),
            ParameterError::ExpandError
        );
    }

    #[test]
    fn expand_with_hook_substitutes() {
        fn expander(arg: &str, _g: &GlobalConfig) -> Result<Option<String>, ParameterError> {
            if arg.contains("{{") {
                Ok(Some("EXPANDED".to_string()))
            } else {
                Ok(None)
            }
        }
        let mut g = GlobalConfig::new();
        g.variable_expander = Some(expander);
        getparameter(
            "--expand-user-agent",
            Some("{{v}}"),
            &mut g,
            CONFIG_MAX_LEVELS,
        )
        .unwrap();
        assert_eq!(g.op_ref().useragent.as_deref(), Some("EXPANDED"));
    }

    // ---- parse_args ---------------------------------------------------------

    #[test]
    fn parse_args_adds_a_bare_url() {
        let mut g = GlobalConfig::new();
        parse_args(&argv(&["curl", "https://example.com/"]), &mut g).unwrap();
        assert_eq!(g.op_ref().num_urls, 1);
        assert!(g
            .op_ref()
            .url_list
            .iter()
            .any(|n| n.url.as_deref() == Some("https://example.com/")));
    }

    #[test]
    fn parse_args_output_then_url_merge_into_one_node() {
        let mut g = GlobalConfig::new();
        parse_args(&argv(&["curl", "-o", "out", "https://x/"]), &mut g).unwrap();
        let op = g.op_ref();
        assert!(op
            .url_list
            .iter()
            .any(|n| n.outfile.as_deref() == Some("out")));
        assert!(op
            .url_list
            .iter()
            .any(|n| n.url.as_deref() == Some("https://x/")));
    }

    #[test]
    fn parse_args_double_dash_ends_flag_parsing() {
        let mut g = GlobalConfig::new();
        // After `--`, a leading-dash token is treated as a URL, not an option.
        parse_args(&argv(&["curl", "--", "-weird-url"]), &mut g).unwrap();
        assert!(g
            .op_ref()
            .url_list
            .iter()
            .any(|n| n.url.as_deref() == Some("-weird-url")));
    }

    #[test]
    fn parse_args_next_creates_a_second_operation() {
        let mut g = GlobalConfig::new();
        parse_args(
            &argv(&["curl", "https://a/", "--next", "https://b/"]),
            &mut g,
        )
        .unwrap();
        assert_eq!(g.operations.len(), 2);
        assert!(g.operations[0]
            .url_list
            .iter()
            .any(|n| n.url.as_deref() == Some("https://a/")));
        assert!(g.operations[1]
            .url_list
            .iter()
            .any(|n| n.url.as_deref() == Some("https://b/")));
    }

    #[test]
    fn parse_args_next_without_prior_url_is_bad_use() {
        let mut g = GlobalConfig::new();
        assert_eq!(
            parse_args(&argv(&["curl", "--next", "https://b/"]), &mut g).unwrap_err(),
            ParameterError::BadUse
        );
    }

    #[test]
    fn parse_args_propagates_help_signal() {
        let mut g = GlobalConfig::new();
        assert_eq!(
            parse_args(&argv(&["curl", "--help"]), &mut g).unwrap_err(),
            ParameterError::HelpRequested
        );
    }

    #[test]
    fn parse_args_reports_unknown_option() {
        let mut g = GlobalConfig::new();
        assert_eq!(
            parse_args(&argv(&["curl", "--no-such-flag"]), &mut g).unwrap_err(),
            ParameterError::OptionUnknown
        );
    }

    #[test]
    fn parse_args_multiple_options_and_url() {
        let mut g = GlobalConfig::new();
        parse_args(
            &argv(&["curl", "-sS", "--user-agent", "ua/2", "https://z/"]),
            &mut g,
        )
        .unwrap();
        assert!(g.silent);
        assert!(g.showerror);
        assert_eq!(g.op_ref().useragent.as_deref(), Some("ua/2"));
        assert!(g
            .op_ref()
            .url_list
            .iter()
            .any(|n| n.url.as_deref() == Some("https://z/")));
    }

    // ---- numeric parameter helpers (tool_paramhlp.c) ------------------------

    fn qdiag() -> Diag {
        Diag {
            silent: true,
            showerror: false,
            tracing: false,
        }
    }

    #[test]
    fn str2num_parses_signed_and_rejects_trailing_or_garbage() {
        assert_eq!(str2num("10").unwrap(), 10);
        assert_eq!(str2num("-5").unwrap(), -5);
        assert_eq!(str2num("0").unwrap(), 0);
        assert_eq!(str2num("abc").unwrap_err(), ParameterError::BadNumeric);
        // The whole string must be consumed (curlx_str_single(&str, '\0')).
        assert_eq!(str2num("10x").unwrap_err(), ParameterError::BadNumeric);
        assert_eq!(str2num("").unwrap_err(), ParameterError::BadNumeric);
    }

    #[test]
    fn str2unum_rejects_negative() {
        assert_eq!(str2unum("7").unwrap(), 7);
        assert_eq!(str2unum("-1").unwrap_err(), ParameterError::NegativeNumeric);
    }

    #[test]
    fn str2unummax_enforces_upper_bound() {
        assert_eq!(str2unummax("5", 10).unwrap(), 5);
        assert_eq!(str2unummax("10", 10).unwrap(), 10);
        assert_eq!(
            str2unummax("11", 10).unwrap_err(),
            ParameterError::NumberTooLarge
        );
    }

    #[test]
    fn oct2nummax_parses_octal_and_flags_overflow_and_garbage() {
        // 0o755 == 493; within the 0o777 cap.
        assert_eq!(oct2nummax("755", 0o777).unwrap(), 0o755);
        // '8' is not an octal digit.
        assert_eq!(
            oct2nummax("8", 0o777).unwrap_err(),
            ParameterError::BadNumeric
        );
        // 0o7777 == 4095 exceeds the 0o777 cap.
        assert_eq!(
            oct2nummax("7777", 0o777).unwrap_err(),
            ParameterError::NumberTooLarge
        );
    }

    #[test]
    fn secs2ms_scales_seconds_and_fraction_to_milliseconds() {
        assert_eq!(secs2ms("1").unwrap(), 1000);
        assert_eq!(secs2ms("1.5").unwrap(), 1500);
        assert_eq!(secs2ms("0.25").unwrap(), 250);
        assert_eq!(secs2ms("abc").unwrap_err(), ParameterError::BadNumeric);
    }

    #[test]
    fn str2offset_is_nonnegative_and_whole_string() {
        assert_eq!(str2offset("100").unwrap(), 100);
        // No negative handling: a leading '-' is not a number.
        assert_eq!(str2offset("-1").unwrap_err(), ParameterError::BadNumeric);
        assert_eq!(str2offset("12ab").unwrap_err(), ParameterError::BadNumeric);
    }

    #[test]
    fn str2tls_max_maps_known_versions() {
        assert_eq!(str2tls_max("default").unwrap(), 0);
        assert_eq!(str2tls_max("1.0").unwrap(), 1);
        assert_eq!(str2tls_max("1.3").unwrap(), 4);
        assert_eq!(str2tls_max("9.9").unwrap_err(), ParameterError::BadUse);
    }

    #[test]
    fn get_size_parameter_handles_units_and_fractions() {
        assert_eq!(get_size_parameter("10").unwrap(), 10);
        assert_eq!(get_size_parameter("1B").unwrap(), 1);
        assert_eq!(get_size_parameter("2K").unwrap(), 2048);
        // 1*1024 + (0.5 * 1024) == 1536.
        assert_eq!(get_size_parameter("1.5K").unwrap(), 1536);
        // Unknown unit letter.
        assert_eq!(
            get_size_parameter("5X").unwrap_err(),
            ParameterError::BadUse
        );
        // A fraction with no unit is meaningless.
        assert_eq!(
            get_size_parameter("1.5").unwrap_err(),
            ParameterError::BadUse
        );
    }

    // ---- enum-string validators (never fail; unknown -> default + warn) -----

    #[test]
    fn ftpfilemethod_maps_known_and_defaults_unknown() {
        let d = qdiag();
        assert_eq!(
            ftpfilemethod(d, "singlecwd"),
            curlabi::CURLFTPMETHOD_SINGLECWD
        );
        assert_eq!(ftpfilemethod(d, "NOCWD"), curlabi::CURLFTPMETHOD_NOCWD);
        assert_eq!(
            ftpfilemethod(d, "multicwd"),
            curlabi::CURLFTPMETHOD_MULTICWD
        );
        // Unknown -> documented default (MULTICWD).
        assert_eq!(ftpfilemethod(d, "bogus"), curlabi::CURLFTPMETHOD_MULTICWD);
    }

    #[test]
    fn ftpcccmethod_maps_known_and_defaults_unknown() {
        let d = qdiag();
        assert_eq!(ftpcccmethod(d, "active"), curlabi::CURLFTPSSL_CCC_ACTIVE);
        assert_eq!(ftpcccmethod(d, "passive"), curlabi::CURLFTPSSL_CCC_PASSIVE);
        assert_eq!(ftpcccmethod(d, "bogus"), curlabi::CURLFTPSSL_CCC_PASSIVE);
    }

    #[test]
    fn delegation_maps_known_and_defaults_unknown() {
        let d = qdiag();
        assert_eq!(delegation(d, "none"), curlabi::CURLGSSAPI_DELEGATION_NONE);
        assert_eq!(
            delegation(d, "policy"),
            curlabi::CURLGSSAPI_DELEGATION_POLICY_FLAG
        );
        assert_eq!(delegation(d, "always"), curlabi::CURLGSSAPI_DELEGATION_FLAG);
        assert_eq!(delegation(d, "bogus"), curlabi::CURLGSSAPI_DELEGATION_NONE);
    }

    // ---- protocol-set parsing ----------------------------------------------

    #[test]
    fn proto_token_is_case_insensitive_and_rejects_unknown() {
        assert_eq!(proto_token("HTTP"), Some("http"));
        assert_eq!(proto_token("sFtP"), Some("sftp"));
        assert!(proto_token("notaproto").is_none());
    }

    #[test]
    fn check_protocol_accepts_builtins_and_rejects_others() {
        assert!(check_protocol("https").is_ok());
        assert!(check_protocol("ftp").is_ok());
        assert_eq!(
            check_protocol("frobnicate").unwrap_err(),
            ParameterError::LibcurlUnsupportedProtocol
        );
    }

    #[test]
    fn proto2num_evaluates_modifiers_against_seed() {
        let d = qdiag();
        let empty: &[&'static str] = &[];
        // `=p` clears then sets a single scheme.
        assert_eq!(proto2num(d, empty, "=https").unwrap(), "https");
        // A bare/`+p` adds onto the seed.
        assert_eq!(proto2num(d, empty, "http").unwrap(), "http");
        assert_eq!(proto2num(d, empty, "+ftp").unwrap(), "ftp");
        // A deny against an empty set yields nothing -> BadUse.
        assert_eq!(
            proto2num(d, empty, "-http").unwrap_err(),
            ParameterError::BadUse
        );
        // An unknown scheme after `=` clears the set and leaves it empty -> BadUse.
        assert_eq!(
            proto2num(d, empty, "=bogus").unwrap_err(),
            ParameterError::BadUse
        );
    }

    // ---- certificate / string / list helpers --------------------------------

    #[test]
    fn parse_cert_parameter_splits_name_and_passphrase() {
        // No separator -> whole string is the name.
        assert_eq!(
            parse_cert_parameter("cert.pem").unwrap(),
            ("cert.pem".to_string(), None)
        );
        // First unescaped ':' separates name from passphrase.
        assert_eq!(
            parse_cert_parameter("cert.pem:secret").unwrap(),
            ("cert.pem".to_string(), Some("secret".to_string()))
        );
        // A PKCS#11 URI is taken verbatim (its ':' is not a separator).
        assert_eq!(
            parse_cert_parameter("pkcs11:token=foo").unwrap(),
            ("pkcs11:token=foo".to_string(), None)
        );
        // A backslash escapes a literal colon into the name.
        assert_eq!(
            parse_cert_parameter("c\\:d").unwrap(),
            ("c:d".to_string(), None)
        );
        assert_eq!(
            parse_cert_parameter("").unwrap_err(),
            ParameterError::BlankString
        );
    }

    #[test]
    fn getstr_stores_and_enforces_blank_policy() {
        let mut store: Option<String> = None;
        getstr(&mut store, "value", DENY_BLANK).unwrap();
        assert_eq!(store.as_deref(), Some("value"));
        // DENY_BLANK rejects an empty value.
        assert_eq!(
            getstr(&mut store, "", DENY_BLANK).unwrap_err(),
            ParameterError::BlankString
        );
        // ALLOW_BLANK stores the empty string.
        getstr(&mut store, "", ALLOW_BLANK).unwrap();
        assert_eq!(store.as_deref(), Some(""));
    }

    #[test]
    fn url_encode_percent_encodes_reserved_bytes() {
        assert_eq!(url_encode(b"abcXYZ0-9_.~"), "abcXYZ0-9_.~");
        assert_eq!(url_encode(b"a b/c"), "a%20b%2Fc");
        assert_eq!(url_encode(&[0x00, 0xff]), "%00%FF");
    }

    #[test]
    fn add2list_and_inlist_track_header_membership() {
        let mut list: Vec<String> = Vec::new();
        add2list(&mut list, "Host: example.com").unwrap();
        add2list(&mut list, "Accept: */*").unwrap();
        assert_eq!(list.len(), 2);
        // Case-insensitive, name terminated by ':' or ';'.
        assert!(inlist(&list, "host"));
        assert!(inlist(&list, "Accept"));
        // A prefix that is not colon/semicolon-terminated does not match.
        assert!(!inlist(&list, "Hos"));
        assert!(!inlist(&list, "Content-Type"));
    }

    #[test]
    fn file2string_strips_newlines_and_file2memory_is_raw() {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"line1\r\nline2\n").unwrap();
        f.flush().unwrap();
        let p = f.path().to_str().unwrap();
        // file2string drops CR/LF (curl reads a "string" line-joined).
        assert_eq!(file2string(p).unwrap(), "line1line2");
        // file2memory returns the bytes unchanged.
        assert_eq!(file2memory(p).unwrap(), b"line1\r\nline2\n");
    }

    // ---- dispatcher-completeness invariants over the whole OPTIONS table ----

    /// The flow-control commands never "apply" — they short-circuit `getparameter`
    /// with a signal (`--help`/`--manual`/`--version`/`--engine list`/
    /// `--dump-ca-embed`) or split the operation (`--next`), so they are excluded
    /// from the "applies cleanly" invariants below.
    fn is_flow_control_cmd(cmd: Cmd) -> bool {
        matches!(
            cmd,
            Cmd::Help | Cmd::Manual | Cmd::Version | Cmd::Engine | Cmd::DumpCaEmbed | Cmd::Next
        )
    }

    #[test]
    fn every_boolean_option_applies_cleanly() {
        // Invariant: `opt_bool` must handle every ARG_BOOL row in OPTIONS. On a fresh
        // config, `--<name>` must apply without error for all of them (only the
        // flow-control rows signal instead of applying).
        let mut checked = 0usize;
        for o in OPTIONS.iter().filter(|o| o.typ == ArgType::Bool) {
            if is_flow_control_cmd(o.cmd) {
                continue;
            }
            let mut g = GlobalConfig::new();
            g.silent = true; // suppress any parity warnings to stderr
            let flag = format!("--{}", o.lname);
            let r = getparameter(&flag, None, &mut g, CONFIG_MAX_LEVELS);
            assert!(r.is_ok(), "{flag} (bool) errored: {:?}", r.err());
            checked += 1;
        }
        assert!(checked > 40, "expected many boolean options, saw {checked}");
    }

    #[test]
    fn every_valueless_none_option_applies_cleanly() {
        // Invariant: every ARG_NONE row (except flow-control) is handled by `opt_none`
        // and applies without error.
        let mut checked = 0usize;
        for o in OPTIONS.iter().filter(|o| o.typ == ArgType::None_) {
            if is_flow_control_cmd(o.cmd) {
                continue;
            }
            let mut g = GlobalConfig::new();
            g.silent = true;
            let flag = format!("--{}", o.lname);
            let r = getparameter(&flag, None, &mut g, CONFIG_MAX_LEVELS);
            assert!(r.is_ok(), "{flag} (none) errored: {:?}", r.err());
            checked += 1;
        }
        assert!(
            checked > 5,
            "expected several ARG_NONE options, saw {checked}"
        );
    }

    #[test]
    fn every_value_option_is_dispatch_reachable() {
        // Invariant: every ARG_STRG/ARG_FILE row is wired into `opt_string`/`opt_file`
        // — i.e. it never falls through to the `default` arm that returns
        // OptionUnknown. A benign value ("1") may still be rejected by an option's own
        // validator (e.g. BadNumeric, or BadUse from `existingfile` on a path that does
        // not exist), which is acceptable here; we assert only that the handler exists.
        let mut checked = 0usize;
        for o in OPTIONS.iter().filter(|o| o.typ.takes_arg()) {
            if is_flow_control_cmd(o.cmd) {
                continue;
            }
            let mut g = GlobalConfig::new();
            g.silent = true;
            let flag = format!("--{}", o.lname);
            // Most options accept a benign numeric value; `--upload-flags` validates its
            // value against a fixed IMAP-flag vocabulary (an unknown *token* legitimately
            // yields OptionUnknown, faithful to curl's `parse_upload_flags`), so hand it a
            // real flag name to exercise the success path instead.
            let val = if o.cmd == Cmd::UploadFlags {
                "seen"
            } else {
                "1"
            };
            let r = getparameter(&flag, Some(val), &mut g, CONFIG_MAX_LEVELS);
            assert_ne!(
                r.err(),
                Some(ParameterError::OptionUnknown),
                "{flag} (value) fell through to OptionUnknown — missing from the switch"
            );
            checked += 1;
        }
        assert!(checked > 100, "expected many value options, saw {checked}");
    }
}
