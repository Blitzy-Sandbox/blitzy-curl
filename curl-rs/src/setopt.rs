// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_setopt.c + config2setopts.c + tool_easysrc.c.

//! Translate a parsed [`OperationConfig`] into an easy-handle configuration —
//! the command-line tool's `curl_easy_setopt` layer — and, when `--libcurl` is
//! in effect, emit an equivalent standalone C program.
//!
//! This module is a faithful, byte-behavior-preserving port of three upstream
//! curl 8.19.0-DEV translation units:
//!
//! * `src/config2setopts.c` — [`config2setopts`], the master option-applier
//!   that walks every relevant field of the CLI configuration and drives the
//!   library's easy handle. Its grouping helpers (`ssl_setopts`,
//!   `http_setopts`, `ftp_setopts`, …) are preserved one-to-one.
//! * `src/tool_setopt.c` — the `tool_setopt*` wrappers plus the `NameValue`
//!   symbol tables that turn integer option values back into their `CURL*`
//!   symbolic names for the generated source.
//! * `src/tool_easysrc.c` — the `--libcurl` accumulation buffers
//!   (declarations / data / code / clean-up / "too hard") and the final
//!   dumper that writes a compilable `.c` file.
//!
//! # Security mandate
//!
//! `curl-rs` is built on `rustls`, whose defaults are secure: the library's
//! [`SslConfig`](curl_rs_lib::url::SslConfig) initialises
//! `CURLOPT_SSL_VERIFYPEER` to `1` and `CURLOPT_SSL_VERIFYHOST` to `2`. Unlike
//! the historical C build, verification is therefore **on** unless the user
//! explicitly disables it. When `-k`/`--insecure` (or `--proxy-insecure` /
//! `--doh-insecure`) is supplied, this module emits a warning to **stderr
//! before** lowering the verification level — a hard requirement of the Rust
//! rewrite (AAP §0.7.3, §0.6.4).
//!
//! # `--libcurl` feature gate
//!
//! The C-source emission mirrors curl's `#ifndef CURL_DISABLE_LIBCURL_OPTION`
//! guard through the default-on `libcurl-option` Cargo feature. With the
//! feature disabled the accumulation type collapses to a zero-cost no-op that
//! preserves the exact method surface, so the calling code is identical in
//! both builds.

// The transfer-dispatch layer (`operate.rs`) that calls [`config2setopts`] is
// added in a later checkpoint (AAP §0.7.3), so — like the sibling CLI modules —
// this module carries a crate-conventional `dead_code` allowance until wired.
#![allow(dead_code)]

use std::path::PathBuf;

use crate::args::{
    curlabi, errorf, notef, proto_token, warnf, Diag, FailMode, GlobalConfig,
    HttpReq as CfgHttpReq, OperationConfig, ProgressMode, TraceType, CURL_HET_DEFAULT,
};
use crate::formparse::tool2curlmime;
#[cfg(feature = "ipfs")]
use crate::ipfs::ipfs_url_rewrite;

use curl_rs_lib::error::CurlUCode;
use curl_rs_lib::mime::Mime;
use curl_rs_lib::url::{FtpFileMethod, HttpReq as ReqMethod, IpResolve, NetrcLevel, ProxyType};
use curl_rs_lib::urlapi::{self, CurlUPart, Url};
use curl_rs_lib::{CurlCode, Easy};

// ---------------------------------------------------------------------------
// Local ABI constants
//
// These mirror `include/curl/curl.h` symbols that are consumed here as plain
// integer option arguments (and, for `--libcurl`, whose *names* are emitted by
// the `NameValue` tables further below). They are kept local — rather than
// pulled from `curlabi` — where the emitted C symbol string must differ from
// the Rust constant identifier (for example the lowercase-`v`
// `CURL_SSLVERSION_TLSv1_2`).
// ---------------------------------------------------------------------------

/// Default transfer buffer size (`CURL_MAX_WRITE_SIZE` * 100 in curl's tool),
/// matching `BUFFER_SIZE` in `config2setopts.c`.
const BUFFER_SIZE: i64 = 102_400;

/// `CURLOPT_POSTREDIR` bit for keeping POST across a 301 redirect.
const CURL_REDIR_POST_301: i64 = 1;
/// `CURLOPT_POSTREDIR` bit for keeping POST across a 302 redirect.
const CURL_REDIR_POST_302: i64 = 2;
/// `CURLOPT_POSTREDIR` bit for keeping POST across a 303 redirect.
const CURL_REDIR_POST_303: i64 = 4;

/// `CURLOPT_FTP_CREATE_MISSING_DIRS`: do not create missing directories.
const CURLFTP_CREATE_DIR_NONE: i64 = 0;
/// `CURLOPT_FTP_CREATE_MISSING_DIRS`: retry the CWD, creating dirs as needed.
const CURLFTP_CREATE_DIR_RETRY: i64 = 2;

/// `CURLOPT_HEADEROPT`: keep proxy and server headers separate.
const CURLHEADER_SEPARATE: i64 = 1;

/// `CURLOPT_USE_SSL`: try upgrading to TLS but continue on failure.
const CURLUSESSL_TRY: i64 = 1;
/// `CURLOPT_USE_SSL`: require TLS for the control channel only.
const CURLUSESSL_CONTROL: i64 = 2;
/// `CURLOPT_USE_SSL`: require TLS for both control and data channels.
const CURLUSESSL_ALL: i64 = 3;

/// `CURLSSLOPT_ALLOW_BEAST` — permit the 1/n-1 BEAST workaround to be skipped.
const CURLSSLOPT_ALLOW_BEAST: u64 = 1 << 0;
/// `CURLSSLOPT_NO_REVOKE` — disable certificate revocation checks.
const CURLSSLOPT_NO_REVOKE: u64 = 1 << 1;
/// `CURLSSLOPT_REVOKE_BEST_EFFORT` — ignore missing/offline revocation info.
const CURLSSLOPT_REVOKE_BEST_EFFORT: u64 = 1 << 3;
/// `CURLSSLOPT_NATIVE_CA` — use the operating system's native CA store.
const CURLSSLOPT_NATIVE_CA: u64 = 1 << 4;
/// `CURLSSLOPT_AUTO_CLIENT_CERT` — allow automatic client-certificate use.
const CURLSSLOPT_AUTO_CLIENT_CERT: u64 = 1 << 5;
/// `CURLSSLOPT_EARLYDATA` — permit TLS 1.3 early data (0-RTT).
const CURLSSLOPT_EARLYDATA: u64 = 1 << 6;

/// `CURL_SSLVERSION_MAX_*` shift: the maximum version occupies the high 16 bits.
const CURL_SSLVERSION_MAX_TLSV1_0: i64 = 4 << 16;
/// `CURL_SSLVERSION_MAX_TLSv1_1`.
const CURL_SSLVERSION_MAX_TLSV1_1: i64 = 5 << 16;
/// `CURL_SSLVERSION_MAX_TLSv1_2`.
const CURL_SSLVERSION_MAX_TLSV1_2: i64 = 6 << 16;
/// `CURL_SSLVERSION_MAX_TLSv1_3`.
const CURL_SSLVERSION_MAX_TLSV1_3: i64 = 7 << 16;

/// The largest cookie line curl will hand to `CURLOPT_COOKIE`
/// (`MAX_COOKIE_LINE` in `config2setopts.c`).
const MAX_COOKIE_LINE: usize = 8200;

/// Build-time feature reflection. `curl-rs` always links `rustls`, so the TLS
/// stack is unconditionally present; SRP and ECH are not offered by the rustls
/// backend, matching curl's `feature_tls_srp` / `feature_ech` being unset.
const FEATURE_SSL: bool = true;
/// TLS-SRP is unavailable with the rustls backend.
const FEATURE_TLS_SRP: bool = false;
/// Encrypted Client Hello is not exposed by the rustls backend here.
const FEATURE_ECH: bool = false;

// ---------------------------------------------------------------------------
// NameValue selectors
//
// `config2setopts` applies enum- and bitmask-typed options through a handful of
// `NameValue` tables. Rather than pass table pointers around (as C does), the
// grouping functions name the table they need via these selectors; the
// `--libcurl` emitter resolves the selector to the concrete table.
// ---------------------------------------------------------------------------

/// Selects the enum `NameValue` table used to render an option's symbolic name
/// in `--libcurl` output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NvEnum {
    /// `setopt_nv_CURLPROXY` — proxy type (`CURLOPT_PROXYTYPE`).
    Proxy,
    /// `setopt_nv_CURL_HTTP_VERSION` — negotiated HTTP version.
    HttpVersion,
    /// `setopt_nv_CURL_TIMECOND` — time-condition selector.
    TimeCond,
    /// `setopt_nv_CURLFTPSSL_CCC` — FTP clear-command-channel mode.
    FtpSslCcc,
    /// `setopt_nv_CURLUSESSL` — FTP/SMTP/… explicit-TLS level.
    UseSsl,
    /// `setopt_nv_CURL_NETRC` — `.netrc` usage level.
    Netrc,
}

/// Selects the unsigned bitmask `NameValue` table used to render an option's
/// combined flag names in `--libcurl` output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NvMask {
    /// `setopt_nv_CURLAUTH` — HTTP/proxy/SOCKS5 authentication method mask.
    Auth,
    /// `setopt_nv_CURLSSLOPT` — `CURLOPT_SSL_OPTIONS` flag mask.
    SslOpt,
}

// ---------------------------------------------------------------------------
// Enum mapping helpers (args CLI representation -> curl-rs-lib representation)
// ---------------------------------------------------------------------------

/// Map the CLI's request kind onto the library's [`ReqMethod`]. Mirrors the
/// implicit method curl infers from `-d`/`-F`/`-T`/`-I` before any explicit
/// `-X` override.
fn map_method(req: CfgHttpReq) -> ReqMethod {
    match req {
        CfgHttpReq::Head => ReqMethod::Head,
        CfgHttpReq::Mimepost => ReqMethod::PostMime,
        CfgHttpReq::Simplepost => ReqMethod::Post,
        CfgHttpReq::Put => ReqMethod::Put,
        CfgHttpReq::Get | CfgHttpReq::Unspec => ReqMethod::Get,
    }
}

/// Map `CURL_IPRESOLVE_*` integers onto the library [`IpResolve`] enum.
fn map_ipresolve(v: i64) -> IpResolve {
    match v {
        x if x == curlabi::CURL_IPRESOLVE_V4 => IpResolve::V4,
        x if x == curlabi::CURL_IPRESOLVE_V6 => IpResolve::V6,
        _ => IpResolve::Whatever,
    }
}

/// Map `CURLPROXY_*` integers onto the library [`ProxyType`] enum.
fn map_proxytype(v: i64) -> ProxyType {
    match v {
        x if x == curlabi::CURLPROXY_HTTP_1_0 => ProxyType::Http1_0,
        x if x == curlabi::CURLPROXY_HTTPS => ProxyType::Https,
        x if x == curlabi::CURLPROXY_HTTPS2 => ProxyType::Https2,
        x if x == curlabi::CURLPROXY_SOCKS4 => ProxyType::Socks4,
        x if x == curlabi::CURLPROXY_SOCKS5 => ProxyType::Socks5,
        x if x == curlabi::CURLPROXY_SOCKS4A => ProxyType::Socks4a,
        x if x == curlabi::CURLPROXY_SOCKS5_HOSTNAME => ProxyType::Socks5Hostname,
        _ => ProxyType::Http,
    }
}

/// Map `CURLFTPMETHOD_*` integers onto the library [`FtpFileMethod`] enum.
fn map_ftpmethod(v: i64) -> FtpFileMethod {
    match v {
        x if x == curlabi::CURLFTPMETHOD_NOCWD => FtpFileMethod::NoCwd,
        x if x == curlabi::CURLFTPMETHOD_SINGLECWD => FtpFileMethod::SingleCwd,
        _ => FtpFileMethod::MultiCwd,
    }
}

/// Map the CLI's `.netrc` level onto the library [`NetrcLevel`] enum.
fn map_netrc(level: i64) -> NetrcLevel {
    match level {
        1 => NetrcLevel::Optional,
        2 => NetrcLevel::Required,
        _ => NetrcLevel::Ignored,
    }
}

// ---------------------------------------------------------------------------
// TLS version selector
// ---------------------------------------------------------------------------

/// Combine the CLI's minimum (`--tlsv1.x`) and maximum (`--tls-max`) selectors
/// into the packed `CURLOPT_SSLVERSION` value (minimum in the low 16 bits,
/// maximum shifted into the high bits).
///
/// This is a direct port of `tlsversion()` in `config2setopts.c`. The default
/// minimum is TLS 1.2, preserving curl 8.x behaviour.
fn tlsversion(mintls: u8, maxtls: u8) -> i64 {
    let mut mintls = mintls;
    // If only a maximum below TLS 1.2 was requested, pin the minimum to it so
    // the range stays coherent (mirrors the C special-case).
    if mintls == 0 && maxtls != 0 && maxtls < 3 {
        mintls = maxtls;
    }

    let mut tlsver = match mintls {
        1 => curlabi::CURL_SSLVERSION_TLSV1_0,
        2 => curlabi::CURL_SSLVERSION_TLSV1_1,
        0 | 3 => curlabi::CURL_SSLVERSION_TLSV1_2,
        _ => curlabi::CURL_SSLVERSION_TLSV1_3,
    };

    tlsver |= match maxtls {
        0 => 0,
        1 => CURL_SSLVERSION_MAX_TLSV1_0,
        2 => CURL_SSLVERSION_MAX_TLSV1_1,
        3 => CURL_SSLVERSION_MAX_TLSV1_2,
        _ => CURL_SSLVERSION_MAX_TLSV1_3,
    };

    tlsver
}

// ---------------------------------------------------------------------------
// Error-code classification
// ---------------------------------------------------------------------------

/// Return `true` when a `curl_easy_setopt` result is "lethal" — i.e. a genuine
/// failure rather than the benign "this option is not compiled in / unknown"
/// codes that the tool tolerates. Direct port of `setopt_bad()`.
#[must_use]
pub fn setopt_bad(result: CurlCode) -> bool {
    result != CurlCode::Ok && result != CurlCode::NotBuiltIn && result != CurlCode::UnknownOption
}

/// Best-effort search for the user's `~/.ssh/known_hosts`, mirroring curl's
/// `findfile()` for the SSH known-hosts default. Returns the path only when the
/// file exists so the caller can distinguish "found" from "absent".
fn find_known_hosts() -> Option<String> {
    let home = std::env::var_os("HOME")?;
    let mut path = PathBuf::from(home);
    path.push(".ssh");
    path.push("known_hosts");
    if path.is_file() {
        path.to_str().map(str::to_owned)
    } else {
        None
    }
}

// ===========================================================================
// Part 2 — `--libcurl` C-source emission (port of tool_setopt.c NameValue
// tables + emission wrappers, and the whole of tool_easysrc.c).
//
// Gated behind the default-on `libcurl-option` feature, mirroring curl's
// `#ifndef CURL_DISABLE_LIBCURL_OPTION`. The [`EasySrc`] type accumulates the
// generated program across the whole `config2setopts` walk and writes it out
// in [`EasySrc::finish`].
// ===========================================================================

#[cfg(feature = "libcurl-option")]
mod easysrc {
    use super::{NvEnum, NvMask};
    use crate::args::{warnf, Diag, GlobalConfig, ToolMime, ToolMimeKind};
    use std::fmt::Write as _;
    use std::io::Write as _;

    /// Cap emitted string literals so a pathological argument cannot produce a
    /// multi-megabyte `.c` file (`MAX_STRING_LENGTH_OUTPUT` in tool_setopt.c).
    const MAX_STRING_LENGTH_OUTPUT: usize = 2000;

    // -- NameValue tables (byte-exact symbol strings and integer values) -----

    /// `setopt_nv_CURLPROXY` — note `CURLPROXY_HTTPS2` is intentionally absent,
    /// matching curl 8.x (value `3` therefore renders as an explicit literal).
    const NV_CURLPROXY: &[(&str, i64)] = &[
        ("CURLPROXY_HTTP", 0),
        ("CURLPROXY_HTTP_1_0", 1),
        ("CURLPROXY_HTTPS", 2),
        ("CURLPROXY_SOCKS4", 4),
        ("CURLPROXY_SOCKS5", 5),
        ("CURLPROXY_SOCKS4A", 6),
        ("CURLPROXY_SOCKS5_HOSTNAME", 7),
    ];

    /// `setopt_nv_CURL_HTTP_VERSION`.
    const NV_CURL_HTTP_VERSION: &[(&str, i64)] = &[
        ("CURL_HTTP_VERSION_NONE", 0),
        ("CURL_HTTP_VERSION_1_0", 1),
        ("CURL_HTTP_VERSION_1_1", 2),
        ("CURL_HTTP_VERSION_2_0", 3),
        ("CURL_HTTP_VERSION_2TLS", 4),
        ("CURL_HTTP_VERSION_3", 30),
        ("CURL_HTTP_VERSION_3ONLY", 31),
    ];

    /// `setopt_nv_CURL_TIMECOND`.
    const NV_CURL_TIMECOND: &[(&str, i64)] = &[
        ("CURL_TIMECOND_IFMODSINCE", 1),
        ("CURL_TIMECOND_IFUNMODSINCE", 2),
        ("CURL_TIMECOND_LASTMOD", 3),
        ("CURL_TIMECOND_NONE", 0),
    ];

    /// `setopt_nv_CURLFTPSSL_CCC`.
    const NV_CURLFTPSSL_CCC: &[(&str, i64)] = &[
        ("CURLFTPSSL_CCC_NONE", 0),
        ("CURLFTPSSL_CCC_PASSIVE", 1),
        ("CURLFTPSSL_CCC_ACTIVE", 2),
    ];

    /// `setopt_nv_CURLUSESSL`.
    const NV_CURLUSESSL: &[(&str, i64)] = &[
        ("CURLUSESSL_NONE", 0),
        ("CURLUSESSL_TRY", 1),
        ("CURLUSESSL_CONTROL", 2),
        ("CURLUSESSL_ALL", 3),
    ];

    /// `setopt_nv_CURL_NETRC`.
    const NV_CURL_NETRC: &[(&str, i64)] = &[
        ("CURL_NETRC_IGNORED", 0),
        ("CURL_NETRC_OPTIONAL", 1),
        ("CURL_NETRC_REQUIRED", 2),
    ];

    /// `setopt_nv_CURL_SSLVERSION` — the low-16-bit minimum-version selector.
    /// Symbol strings preserve curl's lowercase `v` (`TLSv1_2`).
    const NV_CURL_SSLVERSION: &[(&str, i64)] = &[
        ("CURL_SSLVERSION_DEFAULT", 0),
        ("CURL_SSLVERSION_TLSv1", 1),
        ("CURL_SSLVERSION_SSLv2", 2),
        ("CURL_SSLVERSION_SSLv3", 3),
        ("CURL_SSLVERSION_TLSv1_0", 4),
        ("CURL_SSLVERSION_TLSv1_1", 5),
        ("CURL_SSLVERSION_TLSv1_2", 6),
        ("CURL_SSLVERSION_TLSv1_3", 7),
    ];

    /// `setopt_nv_CURL_SSLVERSION_MAX` — the high-bits maximum-version selector.
    /// The leading empty-name entry marks "no maximum".
    const NV_CURL_SSLVERSION_MAX: &[(&str, i64)] = &[
        ("", 0),
        ("CURL_SSLVERSION_MAX_DEFAULT", 1 << 16),
        ("CURL_SSLVERSION_MAX_TLSv1_0", 4 << 16),
        ("CURL_SSLVERSION_MAX_TLSv1_1", 5 << 16),
        ("CURL_SSLVERSION_MAX_TLSv1_2", 6 << 16),
        ("CURL_SSLVERSION_MAX_TLSv1_3", 7 << 16),
    ];

    /// `setopt_nv_CURLAUTH` — the combined authentication method mask. The two
    /// combination values lead so the bitmask walker prefers them.
    const NV_CURLAUTH: &[(&str, u64)] = &[
        ("CURLAUTH_ANY", 0xffff_ffef),
        ("CURLAUTH_ANYSAFE", 0xffff_ffee),
        ("CURLAUTH_BASIC", 1),
        ("CURLAUTH_DIGEST", 2),
        ("CURLAUTH_GSSNEGOTIATE", 4),
        ("CURLAUTH_NTLM", 8),
        ("CURLAUTH_DIGEST_IE", 16),
        ("CURLAUTH_ONLY", 0x8000_0000),
        ("CURLAUTH_NONE", 0),
    ];

    /// `setopt_nv_CURLSSLOPT` — the `CURLOPT_SSL_OPTIONS` flag mask.
    const NV_CURLSSLOPT: &[(&str, u64)] = &[
        ("CURLSSLOPT_ALLOW_BEAST", 1),
        ("CURLSSLOPT_NO_REVOKE", 2),
        ("CURLSSLOPT_NO_PARTIALCHAIN", 4),
        ("CURLSSLOPT_REVOKE_BEST_EFFORT", 8),
        ("CURLSSLOPT_NATIVE_CA", 16),
        ("CURLSSLOPT_AUTO_CLIENT_CERT", 32),
    ];

    /// `setopt_nv_CURLNONZERODEFAULTS` — long options whose library default is
    /// non-zero, so an explicit `0` must still be emitted.
    const NONZERO_DEFAULTS: &[(&str, i64)] = &[
        ("CURLOPT_SSL_VERIFYPEER", 1),
        ("CURLOPT_SSL_VERIFYHOST", 1),
        ("CURLOPT_SSL_ENABLE_NPN", 1),
        ("CURLOPT_SSL_ENABLE_ALPN", 1),
        ("CURLOPT_TCP_NODELAY", 1),
        ("CURLOPT_PROXY_SSL_VERIFYPEER", 1),
        ("CURLOPT_PROXY_SSL_VERIFYHOST", 1),
        ("CURLOPT_SOCKS5_AUTH", 1),
        ("CURLOPT_UPLOAD_FLAGS", 16), // CURLULFLAG_SEEN
    ];

    /// Header lines emitted verbatim at the top of the generated program
    /// (`srchead[]`).
    const SRCHEAD: &[&str] = &[
        "/********* Sample code generated by the curl command line tool **********",
        " * All curl_easy_setopt() options are documented at:",
        " * https://curl.se/libcurl/c/curl_easy_setopt.html",
        " ************************************************************************/",
        "#include <curl/curl.h>",
        "",
        "int main(int argc, char *argv[])",
        "{",
        "  CURLcode result;",
        "  CURL *curl;",
    ];

    /// Preamble for the "too hard to generate" remarks block (`srchard[]`).
    const SRCHARD: &[&str] = &[
        "/* Here is a list of options the curl code used that cannot get generated",
        "   as source easily. You may choose to either not use them or implement",
        "   them yourself.",
        "",
    ];

    /// Trailing lines emitted verbatim at the end of the program (`srcend[]`).
    const SRCEND: &[&str] = &[
        "",
        "  return (int)result;",
        "}",
        "/**** End of sample code ****/",
    ];

    /// Resolve an enum selector to its concrete `NameValue` table.
    fn enum_table(sel: NvEnum) -> &'static [(&'static str, i64)] {
        match sel {
            NvEnum::Proxy => NV_CURLPROXY,
            NvEnum::HttpVersion => NV_CURL_HTTP_VERSION,
            NvEnum::TimeCond => NV_CURL_TIMECOND,
            NvEnum::FtpSslCcc => NV_CURLFTPSSL_CCC,
            NvEnum::UseSsl => NV_CURLUSESSL,
            NvEnum::Netrc => NV_CURL_NETRC,
        }
    }

    /// Resolve a bitmask selector to its concrete `NameValueUnsigned` table.
    fn mask_table(sel: NvMask) -> &'static [(&'static str, u64)] {
        match sel {
            NvMask::Auth => NV_CURLAUTH,
            NvMask::SslOpt => NV_CURLSSLOPT,
        }
    }

    /// `true` for bytes the C locale treats as printable (`0x20..=0x7e`).
    fn is_print(b: u8) -> bool {
        (0x20..=0x7e).contains(&b)
    }

    /// Escape a byte string to C source-literal syntax. Direct port of
    /// `c_escape()`: `\t \r \n \? \" \\` are mapped explicitly, other printable
    /// bytes pass through, and the rest become `\ooo` octal (when the next byte
    /// is a hex digit, to avoid an over-long `\xNN`) or `\xNN` hex. Over-long
    /// inputs are capped and suffixed with `...`.
    fn c_escape(bytes: &[u8]) -> String {
        let (slice, cutoff) = if bytes.len() > MAX_STRING_LENGTH_OUTPUT {
            (&bytes[..MAX_STRING_LENGTH_OUTPUT], true)
        } else {
            (bytes, false)
        };

        let mut out = String::with_capacity(slice.len());
        for (i, &b) in slice.iter().enumerate() {
            match b {
                b'\t' => out.push_str("\\t"),
                b'\r' => out.push_str("\\r"),
                b'\n' => out.push_str("\\n"),
                b'?' => out.push_str("\\?"),
                b'"' => out.push_str("\\\""),
                b'\\' => out.push_str("\\\\"),
                _ if is_print(b) => out.push(b as char),
                _ => {
                    let next_is_xdigit = i + 1 < slice.len() && slice[i + 1].is_ascii_hexdigit();
                    if next_is_xdigit {
                        let _ = write!(out, "\\{b:03o}");
                    } else {
                        let _ = write!(out, "\\x{b:02x}");
                    }
                }
            }
        }
        if cutoff {
            out.push_str("...");
        }
        out
    }

    /// Accumulator for the `--libcurl` generated program. When `enabled` is
    /// `false` every method is a no-op, so callers need not special-case the
    /// feature or the absence of `--libcurl`.
    pub(crate) struct EasySrc {
        enabled: bool,
        /// Variable declarations (`slistN`, `mimeN`, `partN`).
        decl: Vec<String>,
        /// Complex-value construction (slist/mime build-up).
        data: Vec<String>,
        /// `curl_easy_setopt` calls and the perform/cleanup tail.
        code: Vec<String>,
        /// Options that cannot be rendered as source (function/object pointers).
        toohard: Vec<String>,
        /// Clean-up calls for anything declared in `decl`.
        clean: Vec<String>,
        mime_count: i32,
        slist_count: i32,
    }

    impl EasySrc {
        /// Create an accumulator. When enabled, seeds the code buffer with the
        /// `curl_easy_init()` call (curl's `easysrc_init`).
        pub(crate) fn new(enabled: bool) -> Self {
            let mut s = Self {
                enabled,
                decl: Vec::new(),
                data: Vec::new(),
                code: Vec::new(),
                toohard: Vec::new(),
                clean: Vec::new(),
                mime_count: 0,
                slist_count: 0,
            };
            if enabled {
                s.code.push("curl = curl_easy_init();".to_string());
            }
            s
        }

        /// Emit a `long`-typed option (`tool_setopt_long`): rendered only when
        /// the value differs from the option's non-zero default.
        pub(crate) fn long(&mut self, name: &str, lval: i64) {
            if !self.enabled {
                return;
            }
            let defval = NONZERO_DEFAULTS
                .iter()
                .find(|(n, _)| *n == name)
                .map_or(0, |(_, v)| *v);
            if lval != defval {
                self.code
                    .push(format!("curl_easy_setopt(curl, {name}, {lval}L);"));
            }
        }

        /// Emit a `curl_off_t`-typed option (`tool_setopt_offt`): rendered only
        /// when non-zero.
        pub(crate) fn offt(&mut self, name: &str, lval: i64) {
            if !self.enabled || lval == 0 {
                return;
            }
            self.code.push(format!(
                "curl_easy_setopt(curl, {name}, (curl_off_t){lval});"
            ));
        }

        /// Emit a string option (`tool_setopt_str`).
        pub(crate) fn str(&mut self, name: &str, val: &str) {
            if !self.enabled {
                return;
            }
            let esc = c_escape(val.as_bytes());
            self.code
                .push(format!("curl_easy_setopt(curl, {name}, \"{esc}\");"));
        }

        /// Emit `CURLOPT_POSTFIELDS`, escaping the raw POST body with its
        /// explicit length (which may contain NUL bytes).
        pub(crate) fn postfields(&mut self, name: &str, data: &[u8]) {
            if !self.enabled {
                return;
            }
            let esc = c_escape(data);
            self.code
                .push(format!("curl_easy_setopt(curl, {name}, \"{esc}\");"));
        }

        /// Emit an enum option (`tool_setopt_enum`): skipped when the value is
        /// `0`, otherwise rendered as `(long)SYMBOL` or an explicit literal.
        pub(crate) fn enum_nv(&mut self, name: &str, sel: NvEnum, lval: i64) {
            if !self.enabled || lval == 0 {
                return;
            }
            match enum_table(sel).iter().find(|(_, v)| *v == lval) {
                Some((sym, _)) => self
                    .code
                    .push(format!("curl_easy_setopt(curl, {name}, (long){sym});")),
                None => self
                    .code
                    .push(format!("curl_easy_setopt(curl, {name}, {lval}L);")),
            }
        }

        /// Emit `CURLOPT_SSLVERSION` (`tool_setopt_SSLVERSION`): resolves the
        /// minimum (low 16 bits) and optional maximum (high bits) separately.
        pub(crate) fn sslversion(&mut self, name: &str, lval: i64) {
            if !self.enabled || lval == 0 {
                return;
            }
            let min = NV_CURL_SSLVERSION
                .iter()
                .find(|(_, v)| *v == (lval & 0xffff));
            let max = NV_CURL_SSLVERSION_MAX
                .iter()
                .find(|(_, v)| *v == (lval & !0xffff));
            match min {
                None => self
                    .code
                    .push(format!("curl_easy_setopt(curl, {name}, {lval}L);")),
                Some((n1, _)) => match max {
                    Some((n2, _)) if !n2.is_empty() => self.code.push(format!(
                        "curl_easy_setopt(curl, {name}, (long)({n1} | {n2}));"
                    )),
                    _ => self
                        .code
                        .push(format!("curl_easy_setopt(curl, {name}, (long){n1});")),
                },
            }
        }

        /// Emit a bitmask option (`tool_setopt_bitmask`): greedily decomposes
        /// the value into named flags, aligning continuation lines and spilling
        /// any leftover bits as a `UL` literal.
        pub(crate) fn bitmask(&mut self, name: &str, sel: NvMask, lval: u64) {
            if !self.enabled || lval == 0 {
                return;
            }
            let table = mask_table(sel);
            let mut rest = lval;
            let mut preamble = format!("curl_easy_setopt(curl, {name}, ");
            for (sym, val) in table {
                if (val & !rest) == 0 {
                    rest &= !val;
                    let tail = if rest != 0 { " |" } else { ");" };
                    self.code.push(format!("{preamble}(long){sym}{tail}"));
                    if rest == 0 {
                        break;
                    }
                    preamble = " ".repeat(preamble.len());
                }
            }
            if rest != 0 {
                self.code.push(format!("{preamble}{rest}UL);"));
            }
        }

        /// Record a function-pointer option in the "too hard" block.
        pub(crate) fn ptr_fn(&mut self, name: &str) {
            if !self.enabled {
                return;
            }
            self.toohard
                .push(format!("{name} was set to a function pointer"));
        }

        /// Record an object-pointer option in the "too hard" block.
        pub(crate) fn ptr_obj(&mut self, name: &str) {
            if !self.enabled {
                return;
            }
            self.toohard
                .push(format!("{name} was set to an object pointer"));
        }

        /// Emit a `curl_slist`-typed option (`tool_setopt_slist`): builds the
        /// list in `data`/`clean` then references it from `code`. Empty lists
        /// are skipped, matching the C null-list guard.
        pub(crate) fn slist(&mut self, name: &str, items: &[String]) {
            if !self.enabled || items.is_empty() {
                return;
            }
            let n = self.gen_slist(items);
            self.code
                .push(format!("curl_easy_setopt(curl, {name}, slist{n});"));
        }

        /// Generate the declaration/data/clean-up for one `curl_slist` and
        /// return its index (`libcurl_generate_slist`).
        fn gen_slist(&mut self, items: &[String]) -> i32 {
            self.slist_count += 1;
            let n = self.slist_count;
            self.decl.push(format!("struct curl_slist *slist{n};"));
            self.data.push(format!("slist{n} = NULL;"));
            self.clean.push(format!("curl_slist_free_all(slist{n});"));
            self.clean.push(format!("slist{n} = NULL;"));
            for item in items {
                let esc = c_escape(item.as_bytes());
                self.data.push(format!(
                    "slist{n} = curl_slist_append(slist{n}, \"{esc}\");"
                ));
            }
            n
        }

        /// Emit `CURLOPT_MIMEPOST` (`tool_setopt_mimepost`) from the tool's mime
        /// tree root.
        pub(crate) fn mimepost(&mut self, name: &str, root: Option<&ToolMime>) {
            if !self.enabled {
                return;
            }
            if let Some(m) = root {
                let n = self.gen_mime(m);
                self.code
                    .push(format!("curl_easy_setopt(curl, {name}, mime{n});"));
            }
        }

        /// Generate the code for a `curl_mime` structure and return its index
        /// (`libcurl_generate_mime`).
        fn gen_mime(&mut self, toolmime: &ToolMime) -> i32 {
            self.mime_count += 1;
            let n = self.mime_count;
            self.decl.push(format!("curl_mime *mime{n};"));
            self.data.push(format!("mime{n} = NULL;"));
            self.code.push(format!("mime{n} = curl_mime_init(curl);"));
            self.clean.push(format!("curl_mime_free(mime{n});"));
            self.clean.push(format!("mime{n} = NULL;"));

            if !toolmime.subparts.is_empty() {
                self.decl.push(format!("curl_mimepart *part{n};"));
                for part in &toolmime.subparts {
                    self.gen_mime_part(part, n);
                }
            }
            n
        }

        /// Generate the code for one mime part (`libcurl_generate_mime_part`).
        fn gen_mime_part(&mut self, part: &ToolMime, mimeno: i32) {
            self.code
                .push(format!("part{mimeno} = curl_mime_addpart(mime{mimeno});"));

            match part.kind {
                ToolMimeKind::Parts => {
                    let sub = self.gen_mime(part);
                    self.code
                        .push(format!("curl_mime_subparts(part{mimeno}, mime{sub});"));
                    // Avoid a double free — ownership passes to the parent.
                    self.code.push(format!("mime{sub} = NULL;"));
                }
                ToolMimeKind::Data => {
                    if let Some(d) = &part.data {
                        let esc = c_escape(d.as_bytes());
                        self.code.push(format!(
                            "curl_mime_data(part{mimeno}, \"{esc}\", CURL_ZERO_TERMINATED);"
                        ));
                    }
                }
                ToolMimeKind::File | ToolMimeKind::FileData => {
                    if let Some(d) = &part.data {
                        let esc = c_escape(d.as_bytes());
                        self.code
                            .push(format!("curl_mime_filedata(part{mimeno}, \"{esc}\");"));
                    }
                    if part.kind == ToolMimeKind::FileData && part.filename.is_none() {
                        self.code
                            .push(format!("curl_mime_filename(part{mimeno}, NULL);"));
                    }
                }
                ToolMimeKind::Stdin | ToolMimeKind::StdinData => {
                    self.code.push(format!(
                        "curl_mime_data_cb(part{mimeno}, -1, (curl_read_callback)fread, \\"
                    ));
                    self.code.push(
                        "                  (curl_seek_callback)fseek, NULL, stdin);".to_string(),
                    );
                }
                ToolMimeKind::None => {}
            }

            if let Some(enc) = &part.encoder {
                let esc = c_escape(enc.as_bytes());
                self.code
                    .push(format!("curl_mime_encoder(part{mimeno}, \"{esc}\");"));
            }

            // Stdin parts default their filename to "-" (matching curl).
            let filename = match (&part.filename, part.kind) {
                (Some(f), _) => Some(f.clone()),
                (None, ToolMimeKind::Stdin) => Some("-".to_string()),
                _ => None,
            };
            if let Some(f) = filename {
                let esc = c_escape(f.as_bytes());
                self.code
                    .push(format!("curl_mime_filename(part{mimeno}, \"{esc}\");"));
            }

            if let Some(nm) = &part.name {
                let esc = c_escape(nm.as_bytes());
                self.code
                    .push(format!("curl_mime_name(part{mimeno}, \"{esc}\");"));
            }

            if let Some(ty) = &part.mime_type {
                let esc = c_escape(ty.as_bytes());
                self.code
                    .push(format!("curl_mime_type(part{mimeno}, \"{esc}\");"));
            }

            if !part.headers.is_empty() {
                let sn = self.gen_slist(&part.headers);
                self.code
                    .push(format!("curl_mime_headers(part{mimeno}, slist{sn}, 1);"));
                self.code.push(format!("slist{sn} = NULL;"));
            }
        }

        /// Flush the "too hard" remarks and append the perform tail
        /// (`easysrc_perform`).
        fn perform(&mut self) {
            if !self.toohard.is_empty() {
                self.code.push(String::new());
                for line in SRCHARD {
                    self.code.push((*line).to_string());
                }
                let hard = std::mem::take(&mut self.toohard);
                for h in hard {
                    self.code.push(h);
                }
                self.code.push(String::new());
                self.code.push("*/".to_string());
            }
            self.code.push(String::new());
            self.code
                .push("result = curl_easy_perform(curl);".to_string());
            self.code.push(String::new());
        }

        /// Append the handle clean-up tail (`easysrc_cleanup`).
        fn cleanup(&mut self) {
            self.code.push("curl_easy_cleanup(curl);".to_string());
            self.code.push("curl = NULL;".to_string());
        }

        /// Finalize the generated program and write it to `--libcurl`'s target
        /// (`-` for stdout). No-op when disabled or when `--libcurl` was not
        /// requested. Ports `easysrc_perform` + `easysrc_cleanup` + `dumpeasysrc`.
        pub(crate) fn finish(&mut self, global: &GlobalConfig, diag: Diag) {
            if !self.enabled {
                return;
            }
            self.perform();
            self.cleanup();
            self.dump(global, diag);
        }

        /// Render the accumulated buffers into the final C program text and
        /// write it out (`dumpeasysrc`).
        fn dump(&self, global: &GlobalConfig, diag: Diag) {
            let Some(path) = global.libcurl.as_deref() else {
                return;
            };

            let mut buf = String::new();
            for line in SRCHEAD {
                buf.push_str(line);
                buf.push('\n');
            }
            // Declarations of complex setopt values.
            for l in &self.decl {
                buf.push_str("  ");
                buf.push_str(l);
                buf.push('\n');
            }
            // Complex-value construction.
            if !self.data.is_empty() {
                buf.push('\n');
                for l in &self.data {
                    buf.push_str("  ");
                    buf.push_str(l);
                    buf.push('\n');
                }
            }
            // Setopt calls / perform / cleanup.
            buf.push('\n');
            for l in &self.code {
                if l.is_empty() {
                    buf.push('\n');
                } else {
                    buf.push_str("  ");
                    buf.push_str(l);
                    buf.push('\n');
                }
            }
            // Clean-up of complex values.
            for l in &self.clean {
                buf.push_str("  ");
                buf.push_str(l);
                buf.push('\n');
            }
            for line in SRCEND {
                buf.push_str(line);
                buf.push('\n');
            }

            if path == "-" {
                let _ = std::io::stdout().write_all(buf.as_bytes());
            } else {
                match std::fs::File::create(path) {
                    Ok(mut f) => {
                        let _ = f.write_all(buf.as_bytes());
                    }
                    Err(_) => {
                        warnf(
                            diag,
                            &format!("Failed to open {path} to write libcurl code"),
                        );
                    }
                }
            }
        }
    }
}

#[cfg(feature = "libcurl-option")]
use easysrc::EasySrc;

// ---------------------------------------------------------------------------
// No-op `EasySrc` for builds without the `libcurl-option` feature. It mirrors
// the real emitter's method surface exactly (mirroring the C
// `CURL_DISABLE_LIBCURL_OPTION` build), so `config2setopts` and its grouping
// helpers compile and run identically regardless of the feature.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "libcurl-option"))]
mod easysrc_stub {
    use super::{NvEnum, NvMask};
    use crate::args::{Diag, GlobalConfig, ToolMime};

    /// Zero-sized stand-in for [`super::easysrc::EasySrc`]; every method is a
    /// no-op.
    pub(crate) struct EasySrc;

    impl EasySrc {
        #[inline]
        pub(crate) fn new(_enabled: bool) -> Self {
            EasySrc
        }
        #[inline]
        pub(crate) fn long(&mut self, _name: &str, _lval: i64) {}
        #[inline]
        pub(crate) fn offt(&mut self, _name: &str, _lval: i64) {}
        #[inline]
        pub(crate) fn str(&mut self, _name: &str, _val: &str) {}
        #[inline]
        pub(crate) fn postfields(&mut self, _name: &str, _data: &[u8]) {}
        #[inline]
        pub(crate) fn enum_nv(&mut self, _name: &str, _sel: NvEnum, _lval: i64) {}
        #[inline]
        pub(crate) fn sslversion(&mut self, _name: &str, _lval: i64) {}
        #[inline]
        pub(crate) fn bitmask(&mut self, _name: &str, _sel: NvMask, _lval: u64) {}
        #[inline]
        pub(crate) fn ptr_fn(&mut self, _name: &str) {}
        #[inline]
        pub(crate) fn ptr_obj(&mut self, _name: &str) {}
        #[inline]
        pub(crate) fn slist(&mut self, _name: &str, _items: &[String]) {}
        #[inline]
        pub(crate) fn mimepost(&mut self, _name: &str, _root: Option<&ToolMime>) {}
        #[inline]
        pub(crate) fn finish(&mut self, _global: &GlobalConfig, _diag: Diag) {}
    }
}

#[cfg(not(feature = "libcurl-option"))]
use easysrc_stub::EasySrc;

// ===========================================================================
// Part 1 — grouping functions (port of the config2setopts.c helpers).
//
// Each function mirrors one C grouping function one-to-one. Where the library's
// partial [`UserDefined`] model exposes a field, the handle is configured; the
// `--libcurl` source is emitted for the complete option set regardless.
// ===========================================================================

/// Split a `user:password` credential the way libcurl's `CURLOPT_*USERPWD`
/// does: everything before the first `:` is the user, the remainder (if any)
/// is the password.
fn split_userpwd(s: &str) -> (String, Option<String>) {
    match s.split_once(':') {
        Some((u, p)) => (u.to_string(), Some(p.to_string())),
        None => (s.to_string(), None),
    }
}

/// Scheme predicates. `proto_token` returns canonical lowercase scheme names,
/// so a value comparison is sufficient (mirrors curl's interned `proto_*`
/// pointer identity checks).
fn is_http(p: &str) -> bool {
    p == "http" || p == "https"
}
/// `true` for the FTP family.
fn is_ftp(p: &str) -> bool {
    p == "ftp" || p == "ftps"
}
/// `true` for the SSH family.
fn is_ssh(p: &str) -> bool {
    p == "scp" || p == "sftp"
}

/// `CURLOPT_BUFFERSIZE` (`buffersize`): clamp to the download rate limit when
/// that is smaller than the default transfer buffer.
fn buffersize(easy: &mut Easy, config: &OperationConfig, src: &mut EasySrc) {
    let bs = if config.recvpersecond != 0 && config.recvpersecond < BUFFER_SIZE {
        config.recvpersecond
    } else {
        BUFFER_SIZE
    };
    if let Ok(v) = usize::try_from(bs) {
        easy.set.buffer_size = v;
    }
    src.long("CURLOPT_BUFFERSIZE", bs);
}

/// `gen_trace_setopts`: install the debug callback and enable verbose output
/// when tracing is active. The actual trace sink is wired through
/// `tracing-subscriber` in `main.rs`; here only the C-source equivalents and
/// the verbose flag are recorded.
fn gen_trace_setopts(global: &GlobalConfig, src: &mut EasySrc) {
    if global.tracetype != TraceType::None {
        src.ptr_fn("CURLOPT_DEBUGFUNCTION");
        src.ptr_obj("CURLOPT_DEBUGDATA");
        src.long("CURLOPT_VERBOSE", 1);
    }
}

/// `gen_cb_setopts`: install the transfer callbacks. Every entry is a function
/// or object pointer, so for `--libcurl` they are recorded in the "too hard"
/// block; the live callbacks are installed by the operation layer. The
/// stdin-unpause branch is elided because it depends on per-transfer state that
/// does not exist at this layer.
fn gen_cb_setopts(global: &GlobalConfig, src: &mut EasySrc) {
    src.ptr_obj("CURLOPT_WRITEDATA");
    src.ptr_obj("CURLOPT_INTERLEAVEDATA");
    src.ptr_fn("CURLOPT_WRITEFUNCTION");
    src.ptr_obj("CURLOPT_READDATA");
    src.ptr_fn("CURLOPT_READFUNCTION");
    src.ptr_obj("CURLOPT_SEEKDATA");
    src.ptr_fn("CURLOPT_SEEKFUNCTION");

    if global.progressmode == ProgressMode::Bar && !global.noprogress && !global.silent {
        src.ptr_fn("CURLOPT_XFERINFOFUNCTION");
        src.ptr_obj("CURLOPT_XFERINFODATA");
    }

    src.ptr_fn("CURLOPT_HEADERFUNCTION");
    src.ptr_obj("CURLOPT_HEADERDATA");
}

/// `proxy_setopts`: proxy URL, type, credentials, tunnelling and auth. Setting
/// a proxy never fails in this build (rustls-backed proxying is always
/// available), so the C "proxy support disabled" synthetic-error branch is
/// unreachable and omitted.
fn proxy_setopts(easy: &mut Easy, config: &OperationConfig, src: &mut EasySrc) {
    if let Some(proxy) = &config.proxy {
        easy.set.proxy = Some(proxy.clone());
        src.str("CURLOPT_PROXY", proxy);
        easy.set.proxytype = map_proxytype(config.proxyver);
        src.enum_nv("CURLOPT_PROXYTYPE", NvEnum::Proxy, config.proxyver);
    }

    if let Some(pu) = &config.proxyuserpwd {
        let (user, password) = split_userpwd(pu);
        easy.set.proxy_user = Some(user);
        easy.set.proxy_password = password;
        src.str("CURLOPT_PROXYUSERPWD", pu);
    }

    src.long("CURLOPT_HTTPPROXYTUNNEL", i64::from(config.proxytunnel));

    if let Some(pp) = &config.preproxy {
        src.str("CURLOPT_PRE_PROXY", pp);
    }

    let proxyauth = if config.proxyanyauth {
        curlabi::CURLAUTH_ANY
    } else if config.proxynegotiate {
        curlabi::CURLAUTH_NEGOTIATE
    } else if config.proxyntlm {
        curlabi::CURLAUTH_NTLM
    } else if config.proxydigest {
        curlabi::CURLAUTH_DIGEST
    } else if config.proxybasic {
        curlabi::CURLAUTH_BASIC
    } else {
        0
    };
    if proxyauth != 0 {
        easy.set.proxyauth = proxyauth;
        src.bitmask("CURLOPT_PROXYAUTH", NvMask::Auth, proxyauth);
    }

    if let Some(np) = &config.noproxy {
        easy.set.no_proxy = Some(np.clone());
        src.str("CURLOPT_NOPROXY", np);
    }

    src.long(
        "CURLOPT_SUPPRESS_CONNECT_HEADERS",
        i64::from(config.suppress_connect_headers),
    );

    if let Some(sn) = &config.proxy_service_name {
        src.str("CURLOPT_PROXY_SERVICE_NAME", sn);
    }

    if config.haproxy_protocol {
        src.long("CURLOPT_HAPROXYPROTOCOL", 1);
    }

    if let Some(ip) = &config.haproxy_clientip {
        src.str("CURLOPT_HAPROXY_CLIENT_IP", ip);
    }
}

/// `cookie_setopts`: assemble the `-b` cookie header, load cookie files, set the
/// jar, and mark a new session. Returns an error if the joined cookie header
/// would exceed `MAX_COOKIE_LINE`, matching curl's dynbuf cap.
fn cookie_setopts(config: &OperationConfig, diag: Diag, src: &mut EasySrc) -> Result<(), CurlCode> {
    if !config.cookies.is_empty() {
        let mut cookies = String::new();
        for (idx, c) in config.cookies.iter().enumerate() {
            if idx == 0 {
                cookies.push_str(c);
            } else {
                cookies.push(';');
                if !c.starts_with([' ', '\t']) {
                    cookies.push(' ');
                }
                cookies.push_str(c);
            }
            if cookies.len() > MAX_COOKIE_LINE {
                warnf(
                    diag,
                    &format!(
                        "skipped provided cookie, the cookie header would go over {MAX_COOKIE_LINE} bytes"
                    ),
                );
                return Err(CurlCode::OutOfMemory);
            }
        }
        src.str("CURLOPT_COOKIE", &cookies);
    }

    for cf in &config.cookiefiles {
        src.str("CURLOPT_COOKIEFILE", cf);
    }

    if let Some(jar) = &config.cookiejar {
        src.str("CURLOPT_COOKIEJAR", jar);
    }

    src.long("CURLOPT_COOKIESESSION", i64::from(config.cookiesession));
    Ok(())
}

/// `http_setopts`: redirect, auth-scope, header, encoding and version options
/// that apply only to HTTP(S). No-op for other schemes.
fn http_setopts(
    easy: &mut Easy,
    config: &OperationConfig,
    use_proto: &str,
    diag: Diag,
    src: &mut EasySrc,
) -> Result<(), CurlCode> {
    if !is_http(use_proto) {
        return Ok(());
    }

    easy.set.follow_location = config.followlocation != 0;
    easy.set.follow_first_only = config.followlocation == curlabi::CURLFOLLOW_FIRSTONLY;
    src.long("CURLOPT_FOLLOWLOCATION", config.followlocation);

    easy.set.allow_auth_to_other_hosts = config.unrestricted_auth;
    src.long(
        "CURLOPT_UNRESTRICTED_AUTH",
        i64::from(config.unrestricted_auth),
    );

    if let Some(sigv4) = &config.aws_sigv4 {
        src.str("CURLOPT_AWS_SIGV4", sigv4);
    }

    easy.set.http_auto_referer = config.autoreferer;
    src.long("CURLOPT_AUTOREFERER", i64::from(config.autoreferer));

    if !config.proxyheaders.is_empty() {
        src.slist("CURLOPT_PROXYHEADER", &config.proxyheaders);
    }

    easy.set.maxredirs = config.maxredirs;
    src.long("CURLOPT_MAXREDIRS", config.maxredirs);

    if config.httpversion != 0 {
        easy.set.httpwant = config.httpversion;
        src.enum_nv(
            "CURLOPT_HTTP_VERSION",
            NvEnum::HttpVersion,
            config.httpversion,
        );
    }

    let mut post_redir = 0i64;
    if config.post301 {
        post_redir |= CURL_REDIR_POST_301;
    }
    if config.post302 {
        post_redir |= CURL_REDIR_POST_302;
    }
    if config.post303 {
        post_redir |= CURL_REDIR_POST_303;
    }
    easy.set.post301 = config.post301;
    easy.set.post302 = config.post302;
    easy.set.post303 = config.post303;
    src.long("CURLOPT_POSTREDIR", post_redir);

    if config.encoding {
        src.str("CURLOPT_ACCEPT_ENCODING", "");
    }

    if config.tr_encoding {
        src.long("CURLOPT_TRANSFER_ENCODING", 1);
    }

    easy.set.http09_allowed = config.http09_allowed;
    src.long("CURLOPT_HTTP09_ALLOWED", i64::from(config.http09_allowed));

    if let Some(altsvc) = &config.altsvc {
        src.str("CURLOPT_ALTSVC", altsvc);
    }

    if let Some(hsts) = &config.hsts {
        src.str("CURLOPT_HSTS", hsts);
    }

    if config.expect100timeout_ms > 0 {
        easy.set.expect_100_timeout = config.expect100timeout_ms;
        src.long("CURLOPT_EXPECT_100_TIMEOUT_MS", config.expect100timeout_ms);
    }

    cookie_setopts(config, diag, src)?;

    // Keep proxy and origin headers separate over an HTTPS proxy or an explicit
    // tunnel, so `--header` content does not leak into CONNECT requests.
    if (config.proxy.is_some() || !config.proxyheaders.is_empty())
        && (use_proto == "https" || config.proxytunnel)
    {
        src.long("CURLOPT_HEADEROPT", CURLHEADER_SEPARATE);
    }

    Ok(())
}

/// `ftp_setopts`: FTP(S)-only transfer options. No-op for other schemes.
fn ftp_setopts(easy: &mut Easy, config: &OperationConfig, use_proto: &str, src: &mut EasySrc) {
    if !is_ftp(use_proto) {
        return;
    }

    if let Some(port) = &config.ftpport {
        src.str("CURLOPT_FTPPORT", port);
    }

    if config.disable_epsv {
        easy.set.ftp_use_epsv = false;
        src.long("CURLOPT_FTP_USE_EPSV", 0);
    }

    if config.disable_eprt {
        easy.set.ftp_use_eprt = false;
        src.long("CURLOPT_FTP_USE_EPRT", 0);
    }

    if config.ftp_ssl_ccc {
        src.enum_nv(
            "CURLOPT_FTP_SSL_CCC",
            NvEnum::FtpSslCcc,
            config.ftp_ssl_ccc_mode,
        );
    }

    if let Some(account) = &config.ftp_account {
        src.str("CURLOPT_FTP_ACCOUNT", account);
    }

    easy.set.ftp_skip_ip = config.ftp_skip_ip;
    src.long("CURLOPT_FTP_SKIP_PASV_IP", i64::from(config.ftp_skip_ip));

    easy.set.ftp_filemethod = map_ftpmethod(config.ftp_filemethod);
    src.long("CURLOPT_FTP_FILEMETHOD", config.ftp_filemethod);

    if let Some(alt) = &config.ftp_alternative_to_user {
        src.str("CURLOPT_FTP_ALTERNATIVE_TO_USER", alt);
    }

    if config.ftp_pret {
        easy.set.ftp_use_pret = true;
        src.long("CURLOPT_FTP_USE_PRET", 1);
    }
}

/// `tcp_setopts`: TCP_NODELAY, Fast Open, MPTCP and keep-alive tuning.
fn tcp_setopts(easy: &mut Easy, config: &OperationConfig, src: &mut EasySrc) {
    if !config.tcp_nodelay {
        easy.set.tcp_nodelay = false;
        src.long("CURLOPT_TCP_NODELAY", 0);
    }

    if config.tcp_fastopen {
        easy.set.tcp_fastopen = true;
        src.long("CURLOPT_TCP_FASTOPEN", 1);
    }

    if config.mptcp {
        // MPTCP is enabled through a custom open-socket callback.
        src.ptr_fn("CURLOPT_OPENSOCKETFUNCTION");
    }

    if config.nokeepalive {
        easy.set.tcp_keepalive = false;
        src.long("CURLOPT_TCP_KEEPALIVE", 0);
    } else {
        easy.set.tcp_keepalive = true;
        src.long("CURLOPT_TCP_KEEPALIVE", 1);
        if config.alivetime != 0 {
            easy.set.tcp_keepidle = config.alivetime;
            easy.set.tcp_keepintvl = config.alivetime;
            src.long("CURLOPT_TCP_KEEPIDLE", config.alivetime);
            src.long("CURLOPT_TCP_KEEPINTVL", config.alivetime);
        }
        if config.alivecnt != 0 {
            easy.set.tcp_keepcnt = config.alivecnt;
            src.long("CURLOPT_TCP_KEEPCNT", config.alivecnt);
        }
    }
}

/// `ssh_setopts`: SCP/SFTP-only options. No-op for other schemes. Enforces the
/// known-hosts safety net: unless `--insecure` was given, a missing
/// `known_hosts` file with no host-key fingerprint is a hard failure.
fn ssh_setopts(
    config: &OperationConfig,
    use_proto: &str,
    diag: Diag,
    src: &mut EasySrc,
) -> Result<(), CurlCode> {
    if !is_ssh(use_proto) {
        return Ok(());
    }

    // The SSH and SSL private-key options share a command-line flag.
    if let Some(key) = &config.key {
        src.str("CURLOPT_SSH_PRIVATE_KEYFILE", key);
    }
    if let Some(pubkey) = &config.pubkey {
        src.str("CURLOPT_SSH_PUBLIC_KEYFILE", pubkey);
    }
    if let Some(md5) = &config.hostpubmd5 {
        src.str("CURLOPT_SSH_HOST_PUBLIC_KEY_MD5", md5);
    }
    if let Some(sha256) = &config.hostpubsha256 {
        src.str("CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256", sha256);
    }

    if config.ssh_compression {
        src.long("CURLOPT_SSH_COMPRESSION", 1);
    }

    if !config.insecure_ok {
        let known = config.knownhosts.clone().or_else(find_known_hosts);
        if let Some(known) = known {
            src.str("CURLOPT_SSH_KNOWNHOSTS", &known);
        } else if config.hostpubmd5.is_none() && config.hostpubsha256.is_none() {
            errorf(diag, "Could not find a known_hosts file");
            return Err(CurlCode::FailedInit);
        } else {
            warnf(diag, "Could not find a known_hosts file");
        }
    }

    Ok(())
}

/// `ssl_ca_setopts`: CA bundle / directory for the transfer and the proxy.
/// When only `--capath` is given it is reused for the proxy (curl issue #1257).
/// The `CURL_CA_EMBED` blob path is not compiled here (no embedded bundle).
fn ssl_ca_setopts(easy: &mut Easy, config: &OperationConfig, src: &mut EasySrc) {
    if let Some(cacert) = &config.cacert {
        easy.set.ssl.ca_info = Some(cacert.clone());
        src.str("CURLOPT_CAINFO", cacert);
    }
    if let Some(proxy_cacert) = &config.proxy_cacert {
        easy.set.proxy_ssl.ca_info = Some(proxy_cacert.clone());
        src.str("CURLOPT_PROXY_CAINFO", proxy_cacert);
    }
    if let Some(capath) = &config.capath {
        easy.set.ssl.ca_path = Some(capath.clone());
        src.str("CURLOPT_CAPATH", capath);
    }

    // If --proxy-capath is unset, fall back to --capath for the proxy.
    if config.proxy_capath.is_some() || config.capath.is_some() {
        let proxy_capath = config
            .proxy_capath
            .as_ref()
            .or(config.capath.as_ref())
            .expect("guarded by the is_some checks above");
        easy.set.proxy_ssl.ca_path = Some(proxy_capath.clone());
        src.str("CURLOPT_PROXY_CAPATH", proxy_capath);
    }
}

/// `ssl_setopts`: the security-critical TLS configuration.
///
/// **Mandate (AAP §0.7.3 / §0.6.4):** because the rustls-backed library
/// defaults to `SSL_VERIFYPEER = 1` / `SSL_VERIFYHOST = 2`, any request to
/// disable verification (`--insecure`, `--proxy-insecure`, `--doh-insecure`)
/// emits a warning to **stderr before** the verification level is lowered.
fn ssl_setopts(easy: &mut Easy, config: &OperationConfig, diag: Diag, src: &mut EasySrc) {
    if let Some(crlfile) = &config.crlfile {
        src.str("CURLOPT_CRLFILE", crlfile);
    }
    if let Some(proxy_crlfile) = &config.proxy_crlfile {
        src.str("CURLOPT_PROXY_CRLFILE", proxy_crlfile);
    } else if let Some(crlfile) = &config.crlfile {
        // CURLOPT_PROXY_CRLFILE defaults to the transfer's CRL file.
        src.str("CURLOPT_PROXY_CRLFILE", crlfile);
    }

    if let Some(pinned) = &config.pinnedpubkey {
        easy.set.ssl.pinned_key = Some(pinned.clone());
        src.str("CURLOPT_PINNEDPUBLICKEY", pinned);
    }
    if let Some(pinned) = &config.proxy_pinnedpubkey {
        easy.set.proxy_ssl.pinned_key = Some(pinned.clone());
        src.str("CURLOPT_PROXY_PINNEDPUBLICKEY", pinned);
    }

    if let Some(curves) = &config.ssl_ec_curves {
        src.str("CURLOPT_SSL_EC_CURVES", curves);
    }
    if let Some(sigalgs) = &config.ssl_signature_algorithms {
        src.str("CURLOPT_SSL_SIGNATURE_ALGORITHMS", sigalgs);
    }

    if config.writeout.is_some() {
        src.long("CURLOPT_CERTINFO", 1);
    }

    if let Some(cert) = &config.cert {
        easy.set.ssl.cert = Some(cert.clone());
        src.str("CURLOPT_SSLCERT", cert);
    }
    if let Some(cert) = &config.proxy_cert {
        easy.set.proxy_ssl.cert = Some(cert.clone());
        src.str("CURLOPT_PROXY_SSLCERT", cert);
    }
    if let Some(t) = &config.cert_type {
        src.str("CURLOPT_SSLCERTTYPE", t);
    }
    if let Some(t) = &config.proxy_cert_type {
        src.str("CURLOPT_PROXY_SSLCERTTYPE", t);
    }
    if let Some(key) = &config.key {
        easy.set.ssl.key = Some(key.clone());
        src.str("CURLOPT_SSLKEY", key);
    }
    if let Some(key) = &config.proxy_key {
        easy.set.proxy_ssl.key = Some(key.clone());
        src.str("CURLOPT_PROXY_SSLKEY", key);
    }
    if let Some(t) = &config.key_type {
        src.str("CURLOPT_SSLKEYTYPE", t);
    }
    if let Some(t) = &config.proxy_key_type {
        src.str("CURLOPT_PROXY_SSLKEYTYPE", t);
    }

    // --- Verification disable paths: WARN BEFORE lowering (hard mandate). ---
    if config.insecure_ok {
        warnf(
            diag,
            "--insecure is in use; disabling certificate verification \
             (CURLOPT_SSL_VERIFYPEER/VERIFYHOST) leaves the transfer unprotected \
             against man-in-the-middle attacks",
        );
        easy.set.ssl.verify_peer = false;
        easy.set.ssl.verify_host = 0;
        src.long("CURLOPT_SSL_VERIFYPEER", 0);
        src.long("CURLOPT_SSL_VERIFYHOST", 0);
    }

    if config.doh_insecure_ok {
        warnf(
            diag,
            "--doh-insecure is in use; disabling certificate verification for \
             DoH requests leaves DNS resolution unprotected against \
             man-in-the-middle attacks",
        );
        easy.set.doh_verifypeer = false;
        easy.set.doh_verifyhost = false;
        src.long("CURLOPT_DOH_SSL_VERIFYPEER", 0);
        src.long("CURLOPT_DOH_SSL_VERIFYHOST", 0);
    }

    if config.proxy_insecure_ok {
        warnf(
            diag,
            "--proxy-insecure is in use; disabling certificate verification for \
             the proxy connection leaves it unprotected against \
             man-in-the-middle attacks",
        );
        easy.set.proxy_ssl.verify_peer = false;
        easy.set.proxy_ssl.verify_host = 0;
        src.long("CURLOPT_PROXY_SSL_VERIFYPEER", 0);
        src.long("CURLOPT_PROXY_SSL_VERIFYHOST", 0);
    }

    if config.verifystatus {
        easy.set.ssl.verify_status = true;
        src.long("CURLOPT_SSL_VERIFYSTATUS", 1);
    }
    if config.doh_verifystatus {
        src.long("CURLOPT_DOH_SSL_VERIFYSTATUS", 1);
    }

    // The tool always pins a minimum TLS version (TLS 1.2 by default).
    let sslver = tlsversion(config.ssl_version, config.ssl_version_max);
    easy.set.ssl.version = sslver;
    src.sslversion("CURLOPT_SSLVERSION", sslver);
    if config.proxy.is_some() {
        easy.set.proxy_ssl.version = config.proxy_ssl_version;
        src.sslversion("CURLOPT_PROXY_SSLVERSION", config.proxy_ssl_version);
    }

    let ssl_options = (if config.ssl_allow_beast {
        CURLSSLOPT_ALLOW_BEAST
    } else {
        0
    }) | (if config.ssl_allow_earlydata {
        CURLSSLOPT_EARLYDATA
    } else {
        0
    }) | (if config.ssl_no_revoke {
        CURLSSLOPT_NO_REVOKE
    } else {
        0
    }) | (if config.ssl_revoke_best_effort {
        CURLSSLOPT_REVOKE_BEST_EFFORT
    } else {
        0
    }) | (if config.native_ca_store {
        CURLSSLOPT_NATIVE_CA
    } else {
        0
    }) | (if config.ssl_auto_client_cert {
        CURLSSLOPT_AUTO_CLIENT_CERT
    } else {
        0
    });
    if ssl_options != 0 {
        src.bitmask("CURLOPT_SSL_OPTIONS", NvMask::SslOpt, ssl_options);
    }

    let proxy_ssl_options = (if config.proxy_ssl_allow_beast {
        CURLSSLOPT_ALLOW_BEAST
    } else {
        0
    }) | (if config.proxy_ssl_auto_client_cert {
        CURLSSLOPT_AUTO_CLIENT_CERT
    } else {
        0
    }) | (if config.proxy_native_ca_store {
        CURLSSLOPT_NATIVE_CA
    } else {
        0
    });
    if proxy_ssl_options != 0 {
        src.bitmask(
            "CURLOPT_PROXY_SSL_OPTIONS",
            NvMask::SslOpt,
            proxy_ssl_options,
        );
    }

    if let Some(ciphers) = &config.cipher_list {
        easy.set.ssl.ciphers = Some(ciphers.clone());
        src.str("CURLOPT_SSL_CIPHER_LIST", ciphers);
    }
    if let Some(ciphers) = &config.proxy_cipher_list {
        easy.set.proxy_ssl.ciphers = Some(ciphers.clone());
        src.str("CURLOPT_PROXY_SSL_CIPHER_LIST", ciphers);
    }
    if let Some(ciphers) = &config.cipher13_list {
        src.str("CURLOPT_TLS13_CIPHERS", ciphers);
    }
    if let Some(ciphers) = &config.proxy_cipher13_list {
        src.str("CURLOPT_PROXY_TLS13_CIPHERS", ciphers);
    }

    if config.disable_sessionid {
        src.long("CURLOPT_SSL_SESSIONID_CACHE", 0);
    }

    // ECH is only wired when the backend advertises support (rustls: off).
    if FEATURE_ECH {
        if let Some(ech) = &config.ech {
            src.str("CURLOPT_ECH", ech);
        }
        if let Some(ech) = &config.ech_public {
            src.str("CURLOPT_ECH", ech);
        }
        if let Some(ech) = &config.ech_config {
            src.str("CURLOPT_ECH", ech);
        }
    }

    if let Some(engine) = &config.engine {
        src.str("CURLOPT_SSLENGINE", engine);
    }

    if config.ftp_ssl_reqd {
        src.enum_nv("CURLOPT_USE_SSL", NvEnum::UseSsl, CURLUSESSL_ALL);
    } else if config.ftp_ssl {
        src.enum_nv("CURLOPT_USE_SSL", NvEnum::UseSsl, CURLUSESSL_TRY);
    } else if config.ftp_ssl_control {
        src.enum_nv("CURLOPT_USE_SSL", NvEnum::UseSsl, CURLUSESSL_CONTROL);
    }

    if config.noalpn {
        easy.set.ssl_enable_alpn = false;
        src.long("CURLOPT_SSL_ENABLE_ALPN", 0);
    }
}

/// `tls_srp_setopts`: TLS-SRP credentials. The rustls backend does not offer
/// SRP, so no handle field is touched; the `--libcurl` source is still emitted
/// for completeness when the user supplied the options.
fn tls_srp_setopts(config: &OperationConfig, src: &mut EasySrc) {
    if let Some(user) = &config.tls_username {
        src.str("CURLOPT_TLSAUTH_USERNAME", user);
    }
    if let Some(password) = &config.tls_password {
        src.str("CURLOPT_TLSAUTH_PASSWORD", password);
    }
    if let Some(authtype) = &config.tls_authtype {
        src.str("CURLOPT_TLSAUTH_TYPE", authtype);
    }
    if let Some(user) = &config.proxy_tls_username {
        src.str("CURLOPT_PROXY_TLSAUTH_USERNAME", user);
    }
    if let Some(password) = &config.proxy_tls_password {
        src.str("CURLOPT_PROXY_TLSAUTH_PASSWORD", password);
    }
    if let Some(authtype) = &config.proxy_tls_authtype {
        src.str("CURLOPT_PROXY_TLSAUTH_TYPE", authtype);
    }
}

/// `setopt_post`: install the POST body — either `--data` (raw bytes) or `-F`
/// (a multipart mime tree). Mixing either with `--continue-at` is an error, as
/// in curl. The built library mime is returned through `mimepost` so the caller
/// can keep it alive for the duration of the transfer.
fn setopt_post(
    easy: &mut Easy,
    config: &OperationConfig,
    mimepost: &mut Option<Mime>,
    diag: Diag,
    src: &mut EasySrc,
) -> Result<(), CurlCode> {
    match config.httpreq {
        CfgHttpReq::Simplepost => {
            if config.resume_from != 0 {
                errorf(diag, "cannot mix --continue-at with --data");
                return Err(CurlCode::FailedInit);
            }
            let len = i64::try_from(config.postdata.len()).unwrap_or(i64::MAX);
            easy.set.postfieldsize = len;
            src.postfields("CURLOPT_POSTFIELDS", &config.postdata);
            src.offt("CURLOPT_POSTFIELDSIZE_LARGE", len);
        }
        CfgHttpReq::Mimepost => {
            *mimepost = None;
            if config.resume_from != 0 {
                errorf(diag, "cannot mix --continue-at with --form");
                return Err(CurlCode::FailedInit);
            }
            if let Some(root) = &config.mimeroot {
                let built = tool2curlmime(easy, root)?;
                *mimepost = Some(built);
                src.mimepost("CURLOPT_MIMEPOST", Some(root));
            }
        }
        _ => {}
    }
    Ok(())
}

/// `customrequest_helper`: advise the user when `-X` merely restates the method
/// curl already inferred, or when overriding to `HEAD` (which usually should be
/// `-I`). Purely diagnostic — mirrors `tool_helpers.c`.
fn customrequest_helper(config: &OperationConfig, diag: Diag) {
    let Some(method) = &config.customrequest else {
        return;
    };
    // Indexed exactly like the C `dflt[]` (the HttpReq enum order).
    let dflt = match config.httpreq {
        CfgHttpReq::Unspec | CfgHttpReq::Get => "GET",
        CfgHttpReq::Head => "HEAD",
        CfgHttpReq::Mimepost | CfgHttpReq::Simplepost => "POST",
        CfgHttpReq::Put => "PUT",
    };
    if method.eq_ignore_ascii_case(dflt) {
        notef(
            diag,
            &format!("Unnecessary use of -X or --request, {dflt} is already inferred."),
        );
    } else if method.eq_ignore_ascii_case("head") {
        warnf(
            diag,
            "Setting custom HTTP method to HEAD with -X/--request may not work \
             the way you want. Consider using -I/--head instead.",
        );
    }
}

/// `url_proto_and_rewrite`: parse the transfer URL to discover its scheme and,
/// for `ipfs://` / `ipns://`, rewrite it to the configured gateway URL in place.
/// Returns the canonical protocol token (`"?"` when unknown). A rewrite failure
/// records a synthetic error (a specific message was already printed).
///
/// The `&mut String` URL, the `&mut` configuration, and the mutable `uh` handle
/// are all consumed by the `ipfs://` / `ipns://` rewrite path; when the `ipfs`
/// feature is disabled that path is compiled out, so the resulting "unused"
/// lints are silenced only for that configuration.
#[cfg_attr(
    not(feature = "ipfs"),
    allow(unused_variables, unused_mut, clippy::ptr_arg)
)]
fn url_proto_and_rewrite(
    url: &mut String,
    config: &mut OperationConfig,
) -> Result<String, CurlCode> {
    let mut uh = match Url::parse(url, urlapi::GUESS_SCHEME | urlapi::NON_SUPPORT_SCHEME) {
        Ok(u) => u,
        Err(CurlUCode::OutOfMemory) => return Err(CurlCode::OutOfMemory),
        Err(_) => return Ok("?".to_string()),
    };

    let scheme = match uh.get(CurlUPart::Scheme, urlapi::DEFAULT_SCHEME) {
        Ok(s) => s,
        Err(CurlUCode::OutOfMemory) => return Err(CurlCode::OutOfMemory),
        Err(_) => return Ok("?".to_string()),
    };

    #[cfg(feature = "ipfs")]
    if scheme.eq_ignore_ascii_case("ipfs") || scheme.eq_ignore_ascii_case("ipns") {
        let proto = if scheme.eq_ignore_ascii_case("ipfs") {
            "ipfs"
        } else {
            "ipns"
        };
        match ipfs_url_rewrite(&mut uh, &scheme, config) {
            Ok(()) => {
                if let Ok(rewritten) = uh.get(CurlUPart::Url, urlapi::URLENCODE) {
                    *url = rewritten;
                }
            }
            Err(e) => {
                config.synthetic_error = true;
                return Err(e);
            }
        }
        return Ok(proto.to_string());
    }

    Ok(proto_token(&scheme).unwrap_or("?").to_string())
}

/// Default `User-Agent` emitted when the user supplied none. curl derives this
/// from the libcurl version banner; the rewrite pins the matching product token.
const DEFAULT_USER_AGENT: &str = "curl-rs/8.19.0-DEV";

/// Apply a fully parsed CLI [`OperationConfig`] to a library easy handle — the
/// Rust port of curl's `config2setopts()` (`src/config2setopts.c`).
///
/// Every relevant configuration field is walked in the exact upstream order and
/// translated into the equivalent `curl-rs-lib` handle setting. When `--libcurl`
/// is in effect (and the `libcurl-option` feature is compiled in), each applied
/// option additionally records a line of C source through `src`, reproducing the
/// transfer as a standalone libcurl program.
///
/// # Signature rationale
///
/// * `easy: &mut Easy` — the handle is mutated in place. curl-rs-lib's
///   `EasyBuilder` wraps a private handle behind consuming (`self`) setters that
///   cover only a fraction of the option surface, so the CLI drives the handle's
///   [`UserDefined`](curl_rs_lib::url::Easy) block directly, exactly as the C
///   tool drives a `CURL *`.
/// * `config: &mut OperationConfig` — [`url_proto_and_rewrite`] may flag a
///   synthetic error and rewrite an `ipfs://` URL, both of which mutate the
///   configuration, mirroring the C `char **url` / `config->synthetic_error`.
/// * `url: &mut String` — the effective transfer URL, replaced in place by the
///   IPFS gateway rewrite (curl's `char **url` out-parameter).
/// * `mimepost: &mut Option<Mime>` — receives the multipart body built for `-F`;
///   the caller owns it for the lifetime of the transfer.
///
/// # Security
///
/// SSL verification defaults (`VERIFYPEER = 1` / `VERIFYHOST = 2`) are preserved
/// unless the user explicitly opted out, in which case [`ssl_setopts`] warns to
/// stderr *before* lowering them (AAP §0.7.3).
pub fn config2setopts(
    easy: &mut Easy,
    config: &mut OperationConfig,
    global: &GlobalConfig,
    url: &mut String,
    mimepost: &mut Option<Mime>,
) -> Result<(), CurlCode> {
    let diag = global.diag();
    let mut src = EasySrc::new(global.libcurl.is_some());

    // Discover the scheme and, for ipfs:// / ipns://, rewrite `url` in place.
    let use_proto = url_proto_and_rewrite(url, config)?;

    // CURLOPT_SHARE and (non-debug) CURLOPT_QUICK_EXIT are handle-model concerns
    // that curl does not reproduce in --libcurl output. The CLI performs exactly
    // one transfer per handle, so a fast teardown is always appropriate.
    easy.set.quick_exit = true;

    gen_trace_setopts(global, &mut src);
    buffersize(easy, config, &mut src);

    // The library consults `path_as_is` while parsing the URL, so the handle
    // flag must be set before `set_url`; the matching --libcurl line is emitted
    // later, in upstream order.
    easy.set.path_as_is = config.path_as_is;
    easy.set.method = map_method(config.httpreq);
    easy.set_url(url.as_str()).map_err(|e| e.code())?;
    src.str("CURLOPT_URL", url.as_str());

    src.long(
        "CURLOPT_NOPROGRESS",
        i64::from(global.noprogress || global.silent),
    );
    gen_cb_setopts(global, &mut src);
    src.long("CURLOPT_NOBODY", i64::from(config.no_body));

    if let Some(bearer) = &config.oauth_bearer {
        src.str("CURLOPT_XOAUTH2_BEARER", bearer);
    }

    proxy_setopts(easy, config, &mut src);
    if config.synthetic_error {
        return Err(CurlCode::FailedInit);
    }

    src.long(
        "CURLOPT_FAILONERROR",
        i64::from(config.fail == FailMode::WoBody),
    );
    if let Some(target) = &config.request_target {
        src.str("CURLOPT_REQUEST_TARGET", target);
    }
    // Upload is driven by an explicit --upload-file (mapped to a PUT request).
    src.long(
        "CURLOPT_UPLOAD",
        i64::from(config.httpreq == CfgHttpReq::Put),
    );
    src.long("CURLOPT_DIRLISTONLY", i64::from(config.dirlistonly));
    src.long("CURLOPT_APPEND", i64::from(config.ftp_append));

    // NETRC precedence: --netrc-optional is weaker than --netrc / --netrc-file.
    let netrc_level = if config.netrc_opt {
        1
    } else if config.netrc || config.netrc_file.is_some() {
        2
    } else {
        0
    };
    easy.set.use_netrc = map_netrc(netrc_level);
    src.enum_nv("CURLOPT_NETRC", NvEnum::Netrc, netrc_level);
    if let Some(file) = &config.netrc_file {
        easy.set.netrc_file = Some(PathBuf::from(file));
        src.str("CURLOPT_NETRC_FILE", file);
    }

    src.long("CURLOPT_TRANSFERTEXT", i64::from(config.use_ascii));
    if let Some(login) = &config.login_options {
        easy.set.login_options = Some(login.clone());
        src.str("CURLOPT_LOGIN_OPTIONS", login);
    }
    if let Some(userpwd) = &config.userpwd {
        src.str("CURLOPT_USERPWD", userpwd);
    }
    if let Some(range) = &config.range {
        src.str("CURLOPT_RANGE", range);
    }
    src.ptr_obj("CURLOPT_ERRORBUFFER");
    src.long("CURLOPT_TIMEOUT_MS", config.timeout_ms);

    setopt_post(easy, config, mimepost, diag, &mut src)?;

    if config.mime_options != 0 {
        src.long("CURLOPT_MIME_OPTIONS", config.mime_options as i64);
    }
    if config.authtype != 0 {
        easy.set.httpauth = config.authtype;
        src.bitmask("CURLOPT_HTTPAUTH", NvMask::Auth, config.authtype);
    }
    src.slist("CURLOPT_HTTPHEADER", &config.headers);

    // proto_http || proto_rtsp is unconditionally true in curl-rs, so the
    // referer and user-agent are always applied.
    if let Some(referer) = &config.referer {
        src.str("CURLOPT_REFERER", referer);
    }
    src.str(
        "CURLOPT_USERAGENT",
        config.useragent.as_deref().unwrap_or(DEFAULT_USER_AGENT),
    );

    http_setopts(easy, config, &use_proto, diag, &mut src)?;
    ftp_setopts(easy, config, &use_proto, &mut src);

    src.long("CURLOPT_LOW_SPEED_LIMIT", config.low_speed_limit);
    src.long("CURLOPT_LOW_SPEED_TIME", config.low_speed_time);
    src.offt("CURLOPT_MAX_SEND_SPEED_LARGE", config.sendpersecond);
    src.offt("CURLOPT_MAX_RECV_SPEED_LARGE", config.recvpersecond);
    src.offt(
        "CURLOPT_RESUME_FROM_LARGE",
        if config.use_resume {
            config.resume_from
        } else {
            0
        },
    );

    if let Some(passwd) = &config.key_passwd {
        src.str("CURLOPT_KEYPASSWD", passwd);
    }
    if let Some(passwd) = &config.proxy_key_passwd {
        src.str("CURLOPT_PROXY_KEYPASSWD", passwd);
    }

    ssh_setopts(config, &use_proto, diag, &mut src)?;

    if FEATURE_SSL {
        ssl_ca_setopts(easy, config, &mut src);
        ssl_setopts(easy, config, diag, &mut src);
    }

    if config.path_as_is {
        src.long("CURLOPT_PATH_AS_IS", 1);
    }
    if config.no_body || config.remote_time {
        src.long("CURLOPT_FILETIME", 1);
    }
    src.long("CURLOPT_CRLF", i64::from(config.crlf));
    src.slist("CURLOPT_QUOTE", &config.quote);
    src.slist("CURLOPT_POSTQUOTE", &config.postquote);
    src.slist("CURLOPT_PREQUOTE", &config.prequote);

    src.enum_nv("CURLOPT_TIMECONDITION", NvEnum::TimeCond, config.timecond);
    src.offt("CURLOPT_TIMEVALUE_LARGE", config.condtime);

    if let Some(custom) = &config.customrequest {
        src.str("CURLOPT_CUSTOMREQUEST", custom);
    }
    customrequest_helper(config, diag);

    src.ptr_obj("CURLOPT_STDERR");

    if let Some(iface) = &config.iface {
        easy.set.localdev = Some(iface.clone());
        src.str("CURLOPT_INTERFACE", iface);
    }

    if let Some(v) = &config.dns_servers {
        src.str("CURLOPT_DNS_SERVERS", v);
    }
    if let Some(v) = &config.dns_interface {
        src.str("CURLOPT_DNS_INTERFACE", v);
    }
    if let Some(v) = &config.dns_ipv4_addr {
        src.str("CURLOPT_DNS_LOCAL_IP4", v);
    }
    if let Some(v) = &config.dns_ipv6_addr {
        src.str("CURLOPT_DNS_LOCAL_IP6", v);
    }

    src.slist("CURLOPT_TELNETOPTIONS", &config.telnet_options);
    src.long("CURLOPT_CONNECTTIMEOUT_MS", config.connecttimeout_ms);

    if let Some(doh) = &config.doh_url {
        src.str("CURLOPT_DOH_URL", doh);
    }

    src.long(
        "CURLOPT_FTP_CREATE_MISSING_DIRS",
        if config.ftp_create_dirs {
            CURLFTP_CREATE_DIR_RETRY
        } else {
            CURLFTP_CREATE_DIR_NONE
        },
    );

    src.offt("CURLOPT_MAXFILESIZE_LARGE", config.max_filesize);

    easy.set.ipver = map_ipresolve(config.ip_version);
    src.long("CURLOPT_IPRESOLVE", config.ip_version);

    if config.socks5_gssapi_nec {
        easy.set.socks5_gssapi_nec = true;
        src.long("CURLOPT_SOCKS5_GSSAPI_NEC", 1);
    }
    if config.socks5_auth != 0 {
        easy.set.socks5auth = config.socks5_auth;
        src.bitmask("CURLOPT_SOCKS5_AUTH", NvMask::Auth, config.socks5_auth);
    }
    if let Some(service) = &config.service_name {
        src.str("CURLOPT_SERVICE_NAME", service);
    }
    src.long("CURLOPT_IGNORE_CONTENT_LENGTH", i64::from(config.ignorecl));

    if config.localport != 0 {
        easy.set.localport = config.localport as u16;
        easy.set.localportrange = config.localportrange as u16;
        src.long("CURLOPT_LOCALPORT", config.localport);
        src.long("CURLOPT_LOCALPORTRANGE", config.localportrange);
    }

    if config.raw {
        src.long("CURLOPT_HTTP_CONTENT_DECODING", 0);
        src.long("CURLOPT_HTTP_TRANSFER_DECODING", 0);
    }

    tcp_setopts(easy, config, &mut src);

    // proto_tftp is unconditionally true in curl-rs.
    if config.tftp_blksize != 0 {
        src.long("CURLOPT_TFTP_BLKSIZE", config.tftp_blksize);
    }

    if let Some(from) = &config.mail_from {
        src.str("CURLOPT_MAIL_FROM", from);
    }
    src.slist("CURLOPT_MAIL_RCPT", &config.mail_rcpt);
    src.long(
        "CURLOPT_MAIL_RCPT_ALLOWFAILS",
        i64::from(config.mail_rcpt_allowfails),
    );

    if config.create_file_mode != 0 {
        easy.set.new_file_perms = config.create_file_mode as u32;
        src.long("CURLOPT_NEW_FILE_PERMS", config.create_file_mode);
    }

    if config.proto_present {
        if let Some(p) = &config.proto_str {
            src.str("CURLOPT_PROTOCOLS_STR", p);
        }
    }
    if config.proto_redir_present {
        if let Some(p) = &config.proto_redir_str {
            src.str("CURLOPT_REDIR_PROTOCOLS_STR", p);
        }
    }

    src.slist("CURLOPT_RESOLVE", &config.resolve);
    src.slist("CURLOPT_CONNECT_TO", &config.connect_to);

    // TLS-SRP is unavailable with the rustls backend; the group is retained for
    // --libcurl fidelity and gated by the (currently false) capability flag.
    if FEATURE_TLS_SRP {
        tls_srp_setopts(config, &mut src);
    }

    if config.gssapi_delegation != 0 {
        src.long("CURLOPT_GSSAPI_DELEGATION", config.gssapi_delegation);
    }
    if let Some(auth) = &config.mail_auth {
        src.str("CURLOPT_MAIL_AUTH", auth);
    }
    if let Some(authzid) = &config.sasl_authzid {
        src.str("CURLOPT_SASL_AUTHZID", authzid);
    }
    src.long("CURLOPT_SASL_IR", i64::from(config.sasl_ir));

    if let Some(path) = &config.unix_socket_path {
        if config.abstract_unix_socket {
            src.str("CURLOPT_ABSTRACT_UNIX_SOCKET", path);
        } else {
            src.str("CURLOPT_UNIX_SOCKET_PATH", path);
        }
    }

    if let Some(proto) = &config.proto_default {
        src.str("CURLOPT_DEFAULT_PROTOCOL", proto);
    }

    src.long("CURLOPT_TFTP_NO_OPTIONS", i64::from(config.tftp_no_options));

    if config.happy_eyeballs_timeout_ms != CURL_HET_DEFAULT {
        easy.set.happy_eyeballs_timeout = config.happy_eyeballs_timeout_ms as u64;
        src.long(
            "CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS",
            config.happy_eyeballs_timeout_ms,
        );
    }

    src.long(
        "CURLOPT_DISALLOW_USERNAME_IN_URL",
        i64::from(config.disallow_username_in_url),
    );

    // --ip-tos / --vlan-priority are applied through the socket-option callback
    // (the real setsockopt lives in callbacks/socket.rs); here it is installed.
    if config.ip_tos > 0 || config.vlan_priority > 0 {
        src.ptr_fn("CURLOPT_SOCKOPTFUNCTION");
        src.ptr_obj("CURLOPT_SOCKOPTDATA");
    }

    src.long("CURLOPT_UPLOAD_FLAGS", config.upload_flags as i64);

    // Emit the perform / cleanup calls and write out the --libcurl program.
    src.finish(global, diag);
    Ok(())
}
