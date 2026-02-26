// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! Typed option dispatch for `curl_easy_setopt()`.
//!
//! This module is the Rust rewrite of `lib/setopt.c` (2,975 lines in C).
//! It replaces the C's massive switch statement with typed Rust enum dispatch,
//! implementing a type-safe, validated option-setting pipeline.
//!
//! # Architecture
//!
//! The C `curl_easy_setopt()` function uses a variadic argument list and a
//! giant `switch` on `CURLoption` integer values.  This Rust implementation
//! replaces that with:
//!
//! * [`CurlOpt`] — enum whose discriminants match C `CURLoption` values exactly
//! * [`CurlOptValue`] — typed union of all option value categories
//! * [`HandleOptions`] — typed configuration struct replacing C's `UserDefined`
//! * [`set_option`] — dispatch function with per-option validation
//!
//! # FFI Compatibility
//!
//! Every [`CurlOpt`] variant carries an explicit `#[repr(u32)]` discriminant
//! identical to the C `CURLoption` value from `include/curl/curl.h`.  This
//! allows the FFI crate to convert raw `u32` option IDs into Rust enum values
//! with zero translation overhead.

use crate::error::{CurlError, CurlResult};
use crate::slist::SList;

// ---------------------------------------------------------------------------
// C-compatible constants — option type bases from include/curl/curl.h
// ---------------------------------------------------------------------------

/// Base offset for `CURLOPTTYPE_LONG` options (integer values).
pub const CURLOPTTYPE_LONG: u32 = 0;

/// Base offset for `CURLOPTTYPE_OBJECTPOINT` options (strings, blobs, objects).
pub const CURLOPTTYPE_OBJECTPOINT: u32 = 10_000;

/// Base offset for `CURLOPTTYPE_FUNCTIONPOINT` options (callbacks).
pub const CURLOPTTYPE_FUNCTIONPOINT: u32 = 20_000;

/// Base offset for `CURLOPTTYPE_OFF_T` options (64-bit offsets).
pub const CURLOPTTYPE_OFF_T: u32 = 30_000;

/// Base offset for `CURLOPTTYPE_BLOB` options (binary data).
pub const CURLOPTTYPE_BLOB: u32 = 40_000;

/// Alias — string options share the OBJECTPOINT base.
pub const CURLOPTTYPE_STRINGPOINT: u32 = CURLOPTTYPE_OBJECTPOINT;

/// Alias — slist options share the OBJECTPOINT base.
pub const CURLOPTTYPE_SLISTPOINT: u32 = CURLOPTTYPE_OBJECTPOINT;

/// Alias — callback-data options share the OBJECTPOINT base.
pub const CURLOPTTYPE_CBPOINT: u32 = CURLOPTTYPE_OBJECTPOINT;

/// Alias — "values" (enumerated integers) share the LONG base.
pub const CURLOPTTYPE_VALUES: u32 = CURLOPTTYPE_LONG;

/// Maximum allowed input string length, matching C `CURL_MAX_INPUT_LENGTH`.
pub const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

// ---------------------------------------------------------------------------
// HTTP version constants — from include/curl/curl.h
// ---------------------------------------------------------------------------

/// Let the library decide.
pub const CURL_HTTP_VERSION_NONE: i64 = 0;
/// Use HTTP/1.0.
pub const CURL_HTTP_VERSION_1_0: i64 = 1;
/// Use HTTP/1.1.
pub const CURL_HTTP_VERSION_1_1: i64 = 2;
/// Use HTTP/2 via upgrade.
pub const CURL_HTTP_VERSION_2_0: i64 = 3;
/// Use HTTP/2 on HTTPS only, HTTP/1.1 on plain.
pub const CURL_HTTP_VERSION_2TLS: i64 = 4;
/// Use HTTP/2 with prior knowledge (no upgrade).
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: i64 = 5;
/// Use HTTP/3 (fallback to earlier versions allowed).
pub const CURL_HTTP_VERSION_3: i64 = 30;
/// Use HTTP/3 only — no fallback.
pub const CURL_HTTP_VERSION_3ONLY: i64 = 31;

// ---------------------------------------------------------------------------
// SSL version constants — from include/curl/curl.h
// ---------------------------------------------------------------------------

/// Default SSL version selection.
pub const CURL_SSLVERSION_DEFAULT: i64 = 0;
/// TLS 1.x (auto-negotiated minor version).
pub const CURL_SSLVERSION_TLSV1: i64 = 1;
/// SSLv2 — always rejected by rustls.
pub const CURL_SSLVERSION_SSLV2: i64 = 2;
/// SSLv3 — always rejected by rustls.
pub const CURL_SSLVERSION_SSLV3: i64 = 3;
/// TLS 1.0 minimum.
pub const CURL_SSLVERSION_TLSV1_0: i64 = 4;
/// TLS 1.1 minimum.
pub const CURL_SSLVERSION_TLSV1_1: i64 = 5;
/// TLS 1.2 minimum.
pub const CURL_SSLVERSION_TLSV1_2: i64 = 6;
/// TLS 1.3 minimum.
pub const CURL_SSLVERSION_TLSV1_3: i64 = 7;
/// One past the last valid version (used for range checks).
pub const CURL_SSLVERSION_LAST: i64 = 8;
/// SSL max version — no maximum constraint.
pub const CURL_SSLVERSION_MAX_NONE: i64 = 0;
/// SSL max version — one past last (upper bound sentinel).
pub const CURL_SSLVERSION_MAX_LAST: i64 = CURL_SSLVERSION_LAST << 16;

// ---------------------------------------------------------------------------
// Proxy type constants — from include/curl/curl.h
// ---------------------------------------------------------------------------

/// HTTP proxy (default).
pub const CURLPROXY_HTTP: i64 = 0;
/// HTTP/1.0 proxy.
pub const CURLPROXY_HTTP_1_0: i64 = 1;
/// HTTPS proxy.
pub const CURLPROXY_HTTPS: i64 = 2;
/// HTTPS/2 proxy.
pub const CURLPROXY_HTTPS2: i64 = 3;
/// SOCKS4 proxy.
pub const CURLPROXY_SOCKS4: i64 = 4;
/// SOCKS5 proxy.
pub const CURLPROXY_SOCKS5: i64 = 5;
/// SOCKS4a proxy.
pub const CURLPROXY_SOCKS4A: i64 = 6;
/// SOCKS5 hostname proxy (DNS resolved by proxy).
pub const CURLPROXY_SOCKS5_HOSTNAME: i64 = 7;

// ---------------------------------------------------------------------------
// Auth bitmask constants — from include/curl/curl.h
// ---------------------------------------------------------------------------

/// No authentication.
pub const CURLAUTH_NONE: u64 = 0;
/// HTTP Basic authentication.
pub const CURLAUTH_BASIC: u64 = 1 << 0;
/// HTTP Digest authentication.
pub const CURLAUTH_DIGEST: u64 = 1 << 1;
/// HTTP Negotiate (SPNEGO) authentication.
pub const CURLAUTH_NEGOTIATE: u64 = 1 << 2;
/// HTTP NTLM authentication.
pub const CURLAUTH_NTLM: u64 = 1 << 3;
/// HTTP Digest with IE flavour.
pub const CURLAUTH_DIGEST_IE: u64 = 1 << 4;
/// HTTP Bearer/OAuth2 authentication.
pub const CURLAUTH_BEARER: u64 = 1 << 6;
/// Only flag — used in combination with a single auth type.
pub const CURLAUTH_ONLY: u64 = 1 << 31;
/// All known authentication types combined.
pub const CURLAUTH_ANY: u64 = !(CURLAUTH_DIGEST_IE);

// ---------------------------------------------------------------------------
// CurlOpt — option identifier enum
// ---------------------------------------------------------------------------

/// All supported `CURLoption` identifiers with C-compatible integer values.
///
/// Each variant's discriminant matches the corresponding C macro exactly:
/// `CURLOPT(name, type_base, number)` ⇒ `name = type_base + number`.
///
/// The set of variants here covers the 40 options specified in the schema.
/// Unrecognised raw IDs are rejected via [`CurlOpt::try_from_u32`] returning
/// [`CurlError::UnknownOption`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum CurlOpt {
    // -- URL options --
    /// URL to work with (CURLOPTTYPE_STRINGPOINT + 2).
    CURLOPT_URL = 10_002,
    /// Byte range to request (CURLOPTTYPE_STRINGPOINT + 7).
    CURLOPT_RANGE = 10_007,

    // -- Network / proxy options --
    /// Proxy URL (CURLOPTTYPE_STRINGPOINT + 4).
    CURLOPT_PROXY = 10_004,
    /// Proxy type (CURLOPTTYPE_VALUES + 101).
    CURLOPT_PROXYTYPE = 101,
    /// Hosts to bypass proxy (CURLOPTTYPE_STRINGPOINT + 177).
    CURLOPT_NOPROXY = 10_177,

    // -- Authentication --
    /// "user:password" for the connection (CURLOPTTYPE_STRINGPOINT + 5).
    CURLOPT_USERPWD = 10_005,
    /// HTTP auth bitmask (CURLOPTTYPE_VALUES + 107).
    CURLOPT_HTTPAUTH = 107,

    // -- TLS options --
    /// SSL version selection (CURLOPTTYPE_VALUES + 32).
    CURLOPT_SSLVERSION = 32,
    /// Enable peer certificate verification (CURLOPTTYPE_LONG + 64).
    CURLOPT_SSL_VERIFYPEER = 64,
    /// Client certificate file (CURLOPTTYPE_STRINGPOINT + 25).
    CURLOPT_SSLCERT = 10_025,
    /// Private key file (CURLOPTTYPE_STRINGPOINT + 87).
    CURLOPT_SSLKEY = 10_087,

    // -- HTTP options --
    /// Custom HTTP headers list (CURLOPTTYPE_SLISTPOINT + 23).
    CURLOPT_HTTPHEADER = 10_023,
    /// Request POST (CURLOPTTYPE_LONG + 47).
    CURLOPT_POST = 47,
    /// POST data (CURLOPTTYPE_OBJECTPOINT + 15).
    CURLOPT_POSTFIELDS = 10_015,
    /// Custom HTTP method (CURLOPTTYPE_STRINGPOINT + 36).
    CURLOPT_CUSTOMREQUEST = 10_036,
    /// User-Agent header (CURLOPTTYPE_STRINGPOINT + 18).
    CURLOPT_USERAGENT = 10_018,
    /// Cookie header string (CURLOPTTYPE_STRINGPOINT + 22).
    CURLOPT_COOKIE = 10_022,
    /// Cookie file to read (CURLOPTTYPE_STRINGPOINT + 31).
    CURLOPT_COOKIEFILE = 10_031,
    /// Cookie jar file to write (CURLOPTTYPE_STRINGPOINT + 82).
    CURLOPT_COOKIEJAR = 10_082,
    /// HTTP version to use (CURLOPTTYPE_VALUES + 84).
    CURLOPT_HTTP_VERSION = 84,
    /// Follow redirects (CURLOPTTYPE_LONG + 52).
    CURLOPT_FOLLOWLOCATION = 52,
    /// Maximum number of redirects (CURLOPTTYPE_LONG + 68).
    CURLOPT_MAXREDIRS = 68,
    /// Accept-Encoding header (CURLOPTTYPE_STRINGPOINT + 102).
    CURLOPT_ACCEPT_ENCODING = 10_102,
    /// MIME POST data (CURLOPTTYPE_OBJECTPOINT + 269).
    CURLOPT_MIMEPOST = 10_269,

    // -- Callback options --
    /// Write callback function (CURLOPTTYPE_FUNCTIONPOINT + 11).
    CURLOPT_WRITEFUNCTION = 20_011,
    /// Read callback function (CURLOPTTYPE_FUNCTIONPOINT + 12).
    CURLOPT_READFUNCTION = 20_012,
    /// Header callback function (CURLOPTTYPE_FUNCTIONPOINT + 79).
    CURLOPT_HEADERFUNCTION = 20_079,
    /// Transfer info callback (CURLOPTTYPE_FUNCTIONPOINT + 219).
    CURLOPT_XFERINFOFUNCTION = 20_219,

    // -- Connection options --
    /// Overall timeout in seconds (CURLOPTTYPE_LONG + 13).
    CURLOPT_TIMEOUT = 13,
    /// Connection timeout in seconds (CURLOPTTYPE_LONG + 78).
    CURLOPT_CONNECTTIMEOUT = 78,
    /// TCP_NODELAY on/off (CURLOPTTYPE_LONG + 121).
    CURLOPT_TCP_NODELAY = 121,

    // -- Transfer / progress options --
    /// Verbose output on/off (CURLOPTTYPE_LONG + 41).
    CURLOPT_VERBOSE = 41,
    /// Disable progress meter (CURLOPTTYPE_LONG + 43).
    CURLOPT_NOPROGRESS = 43,
    /// Do not include body in output (CURLOPTTYPE_LONG + 44).
    CURLOPT_NOBODY = 44,
    /// Upload mode on/off (CURLOPTTYPE_LONG + 46).
    CURLOPT_UPLOAD = 46,

    // -- Share handle --
    /// Shared handle object (CURLOPTTYPE_OBJECTPOINT + 100).
    CURLOPT_SHARE = 10_100,

    // -- FTP options --
    /// Use EPSV for FTP (CURLOPTTYPE_LONG + 85).
    CURLOPT_FTP_USE_EPSV = 85,
    /// Use EPRT for FTP (CURLOPTTYPE_LONG + 106).
    CURLOPT_FTP_USE_EPRT = 106,

    // -- SSH options --
    /// Public key file path (CURLOPTTYPE_STRINGPOINT + 152).
    CURLOPT_SSH_PUBLIC_KEYFILE = 10_152,
    /// Private key file path (CURLOPTTYPE_STRINGPOINT + 153).
    CURLOPT_SSH_PRIVATE_KEYFILE = 10_153,
}

impl CurlOpt {
    /// Attempts to convert a raw `u32` option identifier to a [`CurlOpt`] variant.
    ///
    /// Returns `None` if the value does not correspond to any known option.
    /// The FFI layer uses this to translate C `CURLoption` integers.
    #[must_use]
    pub fn try_from_u32(value: u32) -> Option<Self> {
        match value {
            10_002 => Some(Self::CURLOPT_URL),
            10_007 => Some(Self::CURLOPT_RANGE),
            10_004 => Some(Self::CURLOPT_PROXY),
            101 => Some(Self::CURLOPT_PROXYTYPE),
            10_177 => Some(Self::CURLOPT_NOPROXY),
            10_005 => Some(Self::CURLOPT_USERPWD),
            107 => Some(Self::CURLOPT_HTTPAUTH),
            32 => Some(Self::CURLOPT_SSLVERSION),
            64 => Some(Self::CURLOPT_SSL_VERIFYPEER),
            10_025 => Some(Self::CURLOPT_SSLCERT),
            10_087 => Some(Self::CURLOPT_SSLKEY),
            10_023 => Some(Self::CURLOPT_HTTPHEADER),
            47 => Some(Self::CURLOPT_POST),
            10_015 => Some(Self::CURLOPT_POSTFIELDS),
            10_036 => Some(Self::CURLOPT_CUSTOMREQUEST),
            10_018 => Some(Self::CURLOPT_USERAGENT),
            10_022 => Some(Self::CURLOPT_COOKIE),
            10_031 => Some(Self::CURLOPT_COOKIEFILE),
            10_082 => Some(Self::CURLOPT_COOKIEJAR),
            84 => Some(Self::CURLOPT_HTTP_VERSION),
            52 => Some(Self::CURLOPT_FOLLOWLOCATION),
            68 => Some(Self::CURLOPT_MAXREDIRS),
            10_102 => Some(Self::CURLOPT_ACCEPT_ENCODING),
            10_269 => Some(Self::CURLOPT_MIMEPOST),
            20_011 => Some(Self::CURLOPT_WRITEFUNCTION),
            20_012 => Some(Self::CURLOPT_READFUNCTION),
            20_079 => Some(Self::CURLOPT_HEADERFUNCTION),
            20_219 => Some(Self::CURLOPT_XFERINFOFUNCTION),
            13 => Some(Self::CURLOPT_TIMEOUT),
            78 => Some(Self::CURLOPT_CONNECTTIMEOUT),
            121 => Some(Self::CURLOPT_TCP_NODELAY),
            41 => Some(Self::CURLOPT_VERBOSE),
            43 => Some(Self::CURLOPT_NOPROGRESS),
            44 => Some(Self::CURLOPT_NOBODY),
            46 => Some(Self::CURLOPT_UPLOAD),
            10_100 => Some(Self::CURLOPT_SHARE),
            85 => Some(Self::CURLOPT_FTP_USE_EPSV),
            106 => Some(Self::CURLOPT_FTP_USE_EPRT),
            10_152 => Some(Self::CURLOPT_SSH_PUBLIC_KEYFILE),
            10_153 => Some(Self::CURLOPT_SSH_PRIVATE_KEYFILE),
            _ => None,
        }
    }

    /// Returns the expected [`CurlOptValue`] kind name for diagnostic messages.
    #[must_use]
    pub fn expected_value_kind(&self) -> &'static str {
        let raw = *self as u32;
        if raw >= CURLOPTTYPE_BLOB {
            "Blob"
        } else if raw >= CURLOPTTYPE_OFF_T {
            "OffT"
        } else if raw >= CURLOPTTYPE_FUNCTIONPOINT {
            "FunctionPoint"
        } else if raw >= CURLOPTTYPE_OBJECTPOINT {
            // Could be ObjectPoint, StringPoint, SListPoint, or CbPoint.
            // We distinguish further in set_option.
            "ObjectPoint/SList"
        } else {
            "Long"
        }
    }
}

// ---------------------------------------------------------------------------
// CurlOptValue — typed option value container
// ---------------------------------------------------------------------------

/// A typed container for option values passed to [`set_option`].
///
/// Each variant corresponds to one of the C `CURLOPTTYPE_*` categories:
///
/// | C Type                | Rust Variant        |
/// |-----------------------|---------------------|
/// | `CURLOPTTYPE_LONG`    | `Long(i64)`         |
/// | `CURLOPTTYPE_OBJECTPOINT` / `STRINGPOINT` | `ObjectPoint(String)` |
/// | `CURLOPTTYPE_FUNCTIONPOINT` | `FunctionPoint` |
/// | `CURLOPTTYPE_OFF_T`   | `OffT(i64)`         |
/// | `CURLOPTTYPE_BLOB`    | `Blob(Vec<u8>)`     |
/// | `CURLOPTTYPE_SLISTPOINT` | `SList(SList)`   |
#[derive(Debug, Clone)]
pub enum CurlOptValue {
    /// Integer / boolean / enumerated value.
    Long(i64),
    /// String value (URL, path, header, etc.).
    ObjectPoint(String),
    /// Callback function pointer — stored opaquely.  The actual function
    /// pointer is registered separately via the handle API; this variant
    /// serves as a marker that the callback was set.
    FunctionPoint,
    /// 64-bit offset value (file sizes, resume offsets).
    OffT(i64),
    /// Binary data blob (certificates, keys as in-memory data).
    Blob(Vec<u8>),
    /// String list (HTTP headers, FTP commands, resolve entries).
    SList(SList),
}

impl CurlOptValue {
    /// Returns a human-readable name for the variant, used in diagnostics.
    #[must_use]
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Long(_) => "Long",
            Self::ObjectPoint(_) => "ObjectPoint",
            Self::FunctionPoint => "FunctionPoint",
            Self::OffT(_) => "OffT",
            Self::Blob(_) => "Blob",
            Self::SList(_) => "SList",
        }
    }

    /// Extracts the inner `i64` if `self` is `Long`, otherwise returns
    /// `Err(CurlError::BadFunctionArgument)`.
    pub fn as_long(&self) -> CurlResult<i64> {
        match self {
            Self::Long(v) => Ok(*v),
            _ => {
                tracing::error!(
                    "expected Long value, got {}",
                    self.kind_name()
                );
                Err(CurlError::BadFunctionArgument)
            }
        }
    }

    /// Extracts a reference to the inner `String` if `self` is `ObjectPoint`,
    /// otherwise returns `Err(CurlError::BadFunctionArgument)`.
    pub fn as_str(&self) -> CurlResult<&str> {
        match self {
            Self::ObjectPoint(s) => Ok(s.as_str()),
            _ => {
                tracing::error!(
                    "expected ObjectPoint value, got {}",
                    self.kind_name()
                );
                Err(CurlError::BadFunctionArgument)
            }
        }
    }

    /// Extracts the inner `SList` if `self` is `SList`, otherwise returns
    /// `Err(CurlError::BadFunctionArgument)`.
    pub fn into_slist(self) -> CurlResult<SList> {
        match self {
            Self::SList(s) => Ok(s),
            _ => {
                tracing::error!(
                    "expected SList value, got {}",
                    self.kind_name()
                );
                Err(CurlError::BadFunctionArgument)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HandleOptions — typed configuration struct
// ---------------------------------------------------------------------------

/// Stores all option values set via [`set_option`].
///
/// This struct is the Rust replacement for C's `struct UserDefined` within
/// `struct Curl_easy`.  It is designed to be embedded inside `EasyHandle`
/// (defined in `easy.rs`) and populated via the [`set_option`] dispatch.
///
/// All fields default to curl 8.x defaults (see [`Default`] implementation).
#[derive(Debug, Clone)]
pub struct HandleOptions {
    // -- URL --
    /// Target URL.
    pub url: Option<String>,
    /// Byte range ("N-M" format).
    pub range: Option<String>,

    // -- Network / proxy --
    /// Proxy URL.
    pub proxy: Option<String>,
    /// Proxy type (one of `CURLPROXY_*` constants).
    pub proxytype: i64,
    /// Comma-separated list of hosts that bypass the proxy.
    pub noproxy: Option<String>,

    // -- Authentication --
    /// "user:password" credential string.
    pub userpwd: Option<String>,
    /// HTTP authentication bitmask (combination of `CURLAUTH_*` constants).
    pub httpauth: u64,

    // -- TLS --
    /// Selected SSL/TLS version (one of `CURL_SSLVERSION_*`).
    pub sslversion: i64,
    /// Enable peer certificate verification.
    pub ssl_verifypeer: bool,
    /// Client certificate file path.
    pub sslcert: Option<String>,
    /// Client private key file path.
    pub sslkey: Option<String>,

    // -- HTTP --
    /// Custom HTTP headers to send.
    pub httpheader: Option<SList>,
    /// When `true`, perform a POST request.
    pub post: bool,
    /// POST body data.
    pub postfields: Option<String>,
    /// Custom HTTP method (e.g. "PATCH", "DELETE").
    pub customrequest: Option<String>,
    /// User-Agent header value.
    pub useragent: Option<String>,
    /// Cookie header value.
    pub cookie: Option<String>,
    /// File to read cookies from.
    pub cookiefile: Option<String>,
    /// File to write cookies to on cleanup.
    pub cookiejar: Option<String>,
    /// Requested HTTP version (one of `CURL_HTTP_VERSION_*`).
    pub http_version: i64,
    /// Follow HTTP redirects (0 = off, 1 = on, 2 = same-method, 3 = any).
    pub followlocation: i64,
    /// Maximum number of redirects to follow (-1 = unlimited).
    pub maxredirs: i64,
    /// Accept-Encoding header value (empty string = all supported).
    pub accept_encoding: Option<String>,
    /// MIME POST data blob (serialised representation).
    pub mimepost: Option<Vec<u8>>,

    // -- Callbacks (flags indicating whether a callback is registered) --
    /// Whether a write callback has been set.
    pub has_write_function: bool,
    /// Whether a read callback has been set.
    pub has_read_function: bool,
    /// Whether a header callback has been set.
    pub has_header_function: bool,
    /// Whether a transfer-info progress callback has been set.
    pub has_xferinfo_function: bool,

    // -- Connection --
    /// Overall timeout in milliseconds (0 = no timeout).
    pub timeout_ms: i64,
    /// Connection-phase timeout in milliseconds (0 = default 300 s).
    pub connecttimeout_ms: i64,
    /// Enable TCP_NODELAY (Nagle algorithm off).
    pub tcp_nodelay: bool,

    // -- Transfer / progress --
    /// Enable verbose output.
    pub verbose: bool,
    /// Suppress the built-in progress meter.
    pub noprogress: bool,
    /// Do not include the body in the output.
    pub nobody: bool,
    /// Enable upload mode.
    pub upload: bool,

    // -- Share handle --
    /// Indicates that a shared handle is attached.
    pub share_enabled: bool,

    // -- FTP --
    /// Use EPSV for FTP passive mode.
    pub ftp_use_epsv: bool,
    /// Use EPRT for FTP active mode.
    pub ftp_use_eprt: bool,

    // -- SSH --
    /// Path to the SSH public key file.
    pub ssh_public_keyfile: Option<String>,
    /// Path to the SSH private key file.
    pub ssh_private_keyfile: Option<String>,
}

impl Default for HandleOptions {
    /// Creates a `HandleOptions` with all values matching curl 8.x defaults.
    fn default() -> Self {
        Self {
            // URL
            url: None,
            range: None,

            // Network / proxy
            proxy: None,
            proxytype: CURLPROXY_HTTP,
            noproxy: None,

            // Authentication
            userpwd: None,
            httpauth: CURLAUTH_NONE,

            // TLS — verification ON by default (curl 8.x default)
            sslversion: CURL_SSLVERSION_DEFAULT,
            ssl_verifypeer: true,
            sslcert: None,
            sslkey: None,

            // HTTP
            httpheader: None,
            post: false,
            postfields: None,
            customrequest: None,
            useragent: None,
            cookie: None,
            cookiefile: None,
            cookiejar: None,
            http_version: CURL_HTTP_VERSION_NONE,
            followlocation: 0,
            maxredirs: 30, // curl 8.x default: 30 redirects
            accept_encoding: None,
            mimepost: None,

            // Callbacks
            has_write_function: false,
            has_read_function: false,
            has_header_function: false,
            has_xferinfo_function: false,

            // Connection
            timeout_ms: 0,
            connecttimeout_ms: 0,
            tcp_nodelay: true, // curl 8.x default: TCP_NODELAY enabled

            // Transfer / progress
            verbose: false,
            noprogress: true, // curl 8.x default: progress meter off
            nobody: false,
            upload: false,

            // Share
            share_enabled: false,

            // FTP — EPSV and EPRT enabled by default (curl 8.x)
            ftp_use_epsv: true,
            ftp_use_eprt: true,

            // SSH
            ssh_public_keyfile: None,
            ssh_private_keyfile: None,
        }
    }
}

impl HandleOptions {
    /// Creates a new `HandleOptions` with curl 8.x defaults.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validates that `s` does not exceed [`CURL_MAX_INPUT_LENGTH`].
///
/// This mirrors the C check `if(strlen(s) > CURL_MAX_INPUT_LENGTH)` used
/// throughout `setopt.c`.
fn validate_string_length(s: &str) -> CurlResult<()> {
    if s.len() > CURL_MAX_INPUT_LENGTH {
        tracing::warn!(
            "string length {} exceeds maximum {}",
            s.len(),
            CURL_MAX_INPUT_LENGTH
        );
        return Err(CurlError::BadFunctionArgument);
    }
    Ok(())
}

/// Validates and converts a timeout value from seconds to milliseconds.
///
/// Negative values are rejected with `BadFunctionArgument`.
/// Very large values are clamped to `i64::MAX` to prevent overflow.
fn timeout_sec_to_ms(secs: i64) -> CurlResult<i64> {
    if secs < 0 {
        return Err(CurlError::BadFunctionArgument);
    }
    // Clamp to prevent overflow: i64::MAX / 1000 ≈ 9.2 × 10^15
    let max_secs = i64::MAX / 1000;
    if secs > max_secs {
        Ok(i64::MAX)
    } else {
        Ok(secs * 1000)
    }
}

/// Validates that the given HTTP version value is supported.
///
/// Matches the behaviour of C `setopt_HTTP_VERSION`:
/// - `CURL_HTTP_VERSION_NONE` through `CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE` (0..=5): accepted
/// - `CURL_HTTP_VERSION_3` (30) and `CURL_HTTP_VERSION_3ONLY` (31): accepted
/// - Negative values: `BadFunctionArgument`
/// - Anything else: `UnsupportedProtocol`
fn validate_http_version(version: i64) -> CurlResult<()> {
    match version {
        CURL_HTTP_VERSION_NONE
        | CURL_HTTP_VERSION_1_0
        | CURL_HTTP_VERSION_1_1
        | CURL_HTTP_VERSION_2_0
        | CURL_HTTP_VERSION_2TLS
        | CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE
        | CURL_HTTP_VERSION_3
        | CURL_HTTP_VERSION_3ONLY => Ok(()),
        v if v < CURL_HTTP_VERSION_NONE => {
            tracing::warn!("invalid negative HTTP version: {}", v);
            Err(CurlError::BadFunctionArgument)
        }
        v => {
            tracing::warn!("unsupported HTTP version: {}", v);
            Err(CurlError::UnsupportedProtocol)
        }
    }
}

/// Validates the SSL version argument.
///
/// Mirrors `Curl_setopt_SSLVERSION` from C:
/// - SSLv2 (2) and SSLv3 (3) are always rejected
/// - Versions below `CURL_SSLVERSION_DEFAULT` or >= `CURL_SSLVERSION_LAST` are rejected
/// - The max-version portion (upper 16 bits) is also range-checked
fn validate_ssl_version(arg: i64) -> CurlResult<i64> {
    let version = arg & 0xFFFF;
    let version_max = arg & 0xFFFF_0000_u32 as i64;

    if version < CURL_SSLVERSION_DEFAULT
        || version == CURL_SSLVERSION_SSLV2
        || version == CURL_SSLVERSION_SSLV3
        || version >= CURL_SSLVERSION_LAST
        || !(CURL_SSLVERSION_MAX_NONE..CURL_SSLVERSION_MAX_LAST).contains(&version_max)
    {
        tracing::warn!(
            "invalid SSL version: version={}, version_max={}",
            version,
            version_max
        );
        return Err(CurlError::BadFunctionArgument);
    }

    // Default maps to TLS 1.2 (matching C behaviour)
    let effective = if version == CURL_SSLVERSION_DEFAULT {
        CURL_SSLVERSION_TLSV1_2
    } else {
        version
    };
    Ok(effective | version_max)
}

/// Validates the proxy type value.
fn validate_proxy_type(ptype: i64) -> CurlResult<()> {
    if !(CURLPROXY_HTTP..=CURLPROXY_SOCKS5_HOSTNAME).contains(&ptype) {
        tracing::warn!("invalid proxy type: {}", ptype);
        return Err(CurlError::BadFunctionArgument);
    }
    Ok(())
}

/// Validates an HTTP authentication bitmask.
///
/// Mirrors the C `httpauth()` function: strips `DIGEST_IE` into standard
/// `DIGEST`, then verifies at least one valid auth bit remains.
fn validate_httpauth(auth: u64) -> CurlResult<u64> {
    if auth == CURLAUTH_NONE {
        return Ok(auth);
    }

    let mut effective = auth;

    // DIGEST_IE implies standard DIGEST
    if effective & CURLAUTH_DIGEST_IE != 0 {
        effective |= CURLAUTH_DIGEST;
        effective &= !CURLAUTH_DIGEST_IE;
    }

    // Check that at least one auth type below the ONLY bit is set
    let lower_bits = effective & ((1u64 << 31) - 1);
    if lower_bits == 0 {
        tracing::warn!(
            "no supported authentication types in bitmask: {:#x}",
            auth
        );
        return Err(CurlError::NotBuiltIn);
    }
    Ok(effective)
}

/// Validates a redirect-follow mode value (0..=3).
fn validate_followlocation(arg: i64) -> CurlResult<()> {
    if !(0..=3).contains(&arg) {
        tracing::warn!("invalid FOLLOWLOCATION value: {}", arg);
        return Err(CurlError::BadFunctionArgument);
    }
    Ok(())
}

/// Validates and clamps `MAXREDIRS` to the range `-1..=32767`.
fn validate_maxredirs(arg: i64) -> CurlResult<i64> {
    if arg < -1 {
        tracing::warn!("invalid MAXREDIRS value: {}", arg);
        return Err(CurlError::BadFunctionArgument);
    }
    Ok(arg.min(0x7FFF))
}

// ---------------------------------------------------------------------------
// set_option — main dispatch function
// ---------------------------------------------------------------------------

/// Sets an option on the given [`HandleOptions`] configuration, performing
/// full validation of the option identifier and value.
///
/// This function is the Rust equivalent of C's `Curl_vsetopt()`.  It:
///
/// 1. Converts the raw `option` ID to a [`CurlOpt`] variant — returns
///    [`CurlError::UnknownOption`] if the ID is unrecognised.
/// 2. Validates that the [`CurlOptValue`] variant matches the expected
///    type for the option — returns [`CurlError::BadFunctionArgument`]
///    on mismatch.
/// 3. Performs per-option value validation (range checks, format checks,
///    protocol support) — returns the appropriate error on failure.
/// 4. Stores the validated value in `opts`.
///
/// # Errors
///
/// | Error Variant | Condition |
/// |---|---|
/// | [`CurlError::UnknownOption`] | `option` ID not recognised |
/// | [`CurlError::BadFunctionArgument`] | Wrong value type or value out of range |
/// | [`CurlError::UnsupportedProtocol`] | Requested feature/version not supported |
/// | [`CurlError::NotBuiltIn`] | Auth type not available in build |
/// | [`CurlError::OutOfMemory`] | Allocation failure (SList duplication) |
pub fn set_option(
    opts: &mut HandleOptions,
    option: u32,
    value: CurlOptValue,
) -> CurlResult<()> {
    let opt = match CurlOpt::try_from_u32(option) {
        Some(o) => o,
        None => {
            tracing::warn!("unknown option ID: {}", option);
            return Err(CurlError::UnknownOption);
        }
    };

    tracing::debug!("set_option({:?}, {})", opt, value.kind_name());

    match opt {
        // ----------------------------------------------------------------
        // URL options
        // ----------------------------------------------------------------
        CurlOpt::CURLOPT_URL => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting URL: {}", s);
            opts.url = Some(s.to_owned());
        }
        CurlOpt::CURLOPT_RANGE => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting range: {}", s);
            opts.range = Some(s.to_owned());
        }

        // ----------------------------------------------------------------
        // Network / proxy
        // ----------------------------------------------------------------
        CurlOpt::CURLOPT_PROXY => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting proxy: {}", s);
            opts.proxy = Some(s.to_owned());
        }
        CurlOpt::CURLOPT_PROXYTYPE => {
            let v = value.as_long()?;
            validate_proxy_type(v)?;
            tracing::debug!("setting proxy type: {}", v);
            opts.proxytype = v;
        }
        CurlOpt::CURLOPT_NOPROXY => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting noproxy: {}", s);
            opts.noproxy = Some(s.to_owned());
        }

        // ----------------------------------------------------------------
        // Authentication
        // ----------------------------------------------------------------
        CurlOpt::CURLOPT_USERPWD => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting userpwd");
            opts.userpwd = Some(s.to_owned());
        }
        CurlOpt::CURLOPT_HTTPAUTH => {
            let v = value.as_long()?;
            let effective = validate_httpauth(v as u64)?;
            tracing::debug!("setting httpauth: {:#x}", effective);
            opts.httpauth = effective;
        }

        // ----------------------------------------------------------------
        // TLS
        // ----------------------------------------------------------------
        CurlOpt::CURLOPT_SSLVERSION => {
            let v = value.as_long()?;
            let effective = validate_ssl_version(v)?;
            tracing::debug!("setting sslversion: {}", effective);
            opts.sslversion = effective;
        }
        CurlOpt::CURLOPT_SSL_VERIFYPEER => {
            let v = value.as_long()?;
            let enabled = v != 0;
            if !enabled {
                tracing::warn!(
                    "SSL peer verification disabled — connections are insecure"
                );
            }
            tracing::debug!("setting ssl_verifypeer: {}", enabled);
            opts.ssl_verifypeer = enabled;
        }
        CurlOpt::CURLOPT_SSLCERT => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting sslcert: {}", s);
            opts.sslcert = Some(s.to_owned());
        }
        CurlOpt::CURLOPT_SSLKEY => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting sslkey: {}", s);
            opts.sslkey = Some(s.to_owned());
        }

        // ----------------------------------------------------------------
        // HTTP options
        // ----------------------------------------------------------------
        CurlOpt::CURLOPT_HTTPHEADER => {
            let slist = value.into_slist()?;
            // Duplicate the list to ensure independent ownership, matching C
            // semantics where the library takes a reference to the caller's
            // slist (here we own a copy for safety).
            let dup = slist.duplicate();
            tracing::debug!("setting httpheader: {} entries", dup.len());
            opts.httpheader = Some(dup);
        }
        CurlOpt::CURLOPT_POST => {
            let v = value.as_long()?;
            let enabled = v != 0;
            tracing::debug!("setting post: {}", enabled);
            opts.post = enabled;
            if enabled {
                opts.nobody = false; // implied by C semantics
            }
        }
        CurlOpt::CURLOPT_POSTFIELDS => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!(
                "setting postfields: {} bytes",
                s.len()
            );
            opts.postfields = Some(s.to_owned());
            opts.post = true; // implied
            opts.nobody = false; // implied
        }
        CurlOpt::CURLOPT_CUSTOMREQUEST => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting custom request: {}", s);
            opts.customrequest = Some(s.to_owned());
        }
        CurlOpt::CURLOPT_USERAGENT => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting useragent: {}", s);
            opts.useragent = Some(s.to_owned());
        }
        CurlOpt::CURLOPT_COOKIE => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting cookie header");
            opts.cookie = Some(s.to_owned());
        }
        CurlOpt::CURLOPT_COOKIEFILE => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting cookiefile: {}", s);
            opts.cookiefile = Some(s.to_owned());
        }
        CurlOpt::CURLOPT_COOKIEJAR => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting cookiejar: {}", s);
            opts.cookiejar = Some(s.to_owned());
        }
        CurlOpt::CURLOPT_HTTP_VERSION => {
            let v = value.as_long()?;
            validate_http_version(v)?;
            tracing::debug!("setting http_version: {}", v);
            opts.http_version = v;
        }
        CurlOpt::CURLOPT_FOLLOWLOCATION => {
            let v = value.as_long()?;
            validate_followlocation(v)?;
            tracing::debug!("setting followlocation: {}", v);
            opts.followlocation = v;
        }
        CurlOpt::CURLOPT_MAXREDIRS => {
            let v = value.as_long()?;
            let clamped = validate_maxredirs(v)?;
            tracing::debug!("setting maxredirs: {}", clamped);
            opts.maxredirs = clamped;
        }
        CurlOpt::CURLOPT_ACCEPT_ENCODING => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting accept_encoding: {}", s);
            opts.accept_encoding = Some(s.to_owned());
        }
        CurlOpt::CURLOPT_MIMEPOST => {
            // MIMEPOST accepts an ObjectPoint or Blob depending on caller.
            // We store the raw data for downstream processing.
            match value {
                CurlOptValue::Blob(data) => {
                    tracing::debug!(
                        "setting mimepost: {} bytes (blob)",
                        data.len()
                    );
                    opts.mimepost = Some(data);
                    opts.post = true;
                    opts.nobody = false;
                }
                CurlOptValue::ObjectPoint(s) => {
                    tracing::debug!(
                        "setting mimepost: {} bytes (string)",
                        s.len()
                    );
                    opts.mimepost = Some(s.into_bytes());
                    opts.post = true;
                    opts.nobody = false;
                }
                _ => {
                    tracing::error!(
                        "MIMEPOST requires Blob or ObjectPoint value"
                    );
                    return Err(CurlError::BadFunctionArgument);
                }
            }
        }

        // ----------------------------------------------------------------
        // Callback options
        // ----------------------------------------------------------------
        CurlOpt::CURLOPT_WRITEFUNCTION => {
            // The actual callback registration is handled at the handle
            // level.  Here we just mark that a write callback was set.
            if !matches!(value, CurlOptValue::FunctionPoint) {
                tracing::error!("WRITEFUNCTION requires FunctionPoint value");
                return Err(CurlError::BadFunctionArgument);
            }
            tracing::debug!("setting write function callback");
            opts.has_write_function = true;
        }
        CurlOpt::CURLOPT_READFUNCTION => {
            if !matches!(value, CurlOptValue::FunctionPoint) {
                tracing::error!("READFUNCTION requires FunctionPoint value");
                return Err(CurlError::BadFunctionArgument);
            }
            tracing::debug!("setting read function callback");
            opts.has_read_function = true;
        }
        CurlOpt::CURLOPT_HEADERFUNCTION => {
            if !matches!(value, CurlOptValue::FunctionPoint) {
                tracing::error!(
                    "HEADERFUNCTION requires FunctionPoint value"
                );
                return Err(CurlError::BadFunctionArgument);
            }
            tracing::debug!("setting header function callback");
            opts.has_header_function = true;
        }
        CurlOpt::CURLOPT_XFERINFOFUNCTION => {
            if !matches!(value, CurlOptValue::FunctionPoint) {
                tracing::error!(
                    "XFERINFOFUNCTION requires FunctionPoint value"
                );
                return Err(CurlError::BadFunctionArgument);
            }
            tracing::debug!("setting xferinfo function callback");
            opts.has_xferinfo_function = true;
        }

        // ----------------------------------------------------------------
        // Connection options
        // ----------------------------------------------------------------
        CurlOpt::CURLOPT_TIMEOUT => {
            let secs = value.as_long()?;
            let ms = timeout_sec_to_ms(secs)?;
            tracing::debug!("setting timeout: {} s ({} ms)", secs, ms);
            opts.timeout_ms = ms;
        }
        CurlOpt::CURLOPT_CONNECTTIMEOUT => {
            let secs = value.as_long()?;
            let ms = timeout_sec_to_ms(secs)?;
            tracing::debug!(
                "setting connecttimeout: {} s ({} ms)",
                secs,
                ms
            );
            opts.connecttimeout_ms = ms;
        }
        CurlOpt::CURLOPT_TCP_NODELAY => {
            let v = value.as_long()?;
            let enabled = v != 0;
            tracing::debug!("setting tcp_nodelay: {}", enabled);
            opts.tcp_nodelay = enabled;
        }

        // ----------------------------------------------------------------
        // Transfer / progress options
        // ----------------------------------------------------------------
        CurlOpt::CURLOPT_VERBOSE => {
            let v = value.as_long()?;
            let enabled = v != 0;
            tracing::debug!("setting verbose: {}", enabled);
            opts.verbose = enabled;
        }
        CurlOpt::CURLOPT_NOPROGRESS => {
            let v = value.as_long()?;
            let enabled = v != 0;
            tracing::debug!("setting noprogress: {}", enabled);
            opts.noprogress = enabled;
        }
        CurlOpt::CURLOPT_NOBODY => {
            let v = value.as_long()?;
            let enabled = v != 0;
            tracing::debug!("setting nobody: {}", enabled);
            opts.nobody = enabled;
        }
        CurlOpt::CURLOPT_UPLOAD => {
            let v = value.as_long()?;
            let enabled = v != 0;
            tracing::debug!("setting upload: {}", enabled);
            opts.upload = enabled;
            if enabled {
                opts.nobody = false; // upload implies body
            }
        }

        // ----------------------------------------------------------------
        // Share handle
        // ----------------------------------------------------------------
        CurlOpt::CURLOPT_SHARE => {
            // The actual share-handle attachment is managed at the EasyHandle
            // level.  Here we simply record that sharing was requested.
            tracing::debug!("setting share handle");
            opts.share_enabled = true;
        }

        // ----------------------------------------------------------------
        // FTP options
        // ----------------------------------------------------------------
        CurlOpt::CURLOPT_FTP_USE_EPSV => {
            let v = value.as_long()?;
            let enabled = v != 0;
            tracing::debug!("setting ftp_use_epsv: {}", enabled);
            opts.ftp_use_epsv = enabled;
        }
        CurlOpt::CURLOPT_FTP_USE_EPRT => {
            let v = value.as_long()?;
            let enabled = v != 0;
            tracing::debug!("setting ftp_use_eprt: {}", enabled);
            opts.ftp_use_eprt = enabled;
        }

        // ----------------------------------------------------------------
        // SSH options
        // ----------------------------------------------------------------
        CurlOpt::CURLOPT_SSH_PUBLIC_KEYFILE => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting ssh_public_keyfile: {}", s);
            opts.ssh_public_keyfile = Some(s.to_owned());
        }
        CurlOpt::CURLOPT_SSH_PRIVATE_KEYFILE => {
            let s = value.as_str()?;
            validate_string_length(s)?;
            tracing::debug!("setting ssh_private_keyfile: {}", s);
            opts.ssh_private_keyfile = Some(s.to_owned());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curlopt_values_match_c() {
        // Verify a representative set of option IDs against known C values.
        assert_eq!(CurlOpt::CURLOPT_URL as u32, 10_002);
        assert_eq!(CurlOpt::CURLOPT_PROXY as u32, 10_004);
        assert_eq!(CurlOpt::CURLOPT_TIMEOUT as u32, 13);
        assert_eq!(CurlOpt::CURLOPT_WRITEFUNCTION as u32, 20_011);
        assert_eq!(CurlOpt::CURLOPT_HTTPHEADER as u32, 10_023);
        assert_eq!(CurlOpt::CURLOPT_VERBOSE as u32, 41);
        assert_eq!(CurlOpt::CURLOPT_POST as u32, 47);
        assert_eq!(CurlOpt::CURLOPT_FOLLOWLOCATION as u32, 52);
        assert_eq!(CurlOpt::CURLOPT_SSL_VERIFYPEER as u32, 64);
        assert_eq!(CurlOpt::CURLOPT_MAXREDIRS as u32, 68);
        assert_eq!(CurlOpt::CURLOPT_CONNECTTIMEOUT as u32, 78);
        assert_eq!(CurlOpt::CURLOPT_HTTP_VERSION as u32, 84);
        assert_eq!(CurlOpt::CURLOPT_FTP_USE_EPSV as u32, 85);
        assert_eq!(CurlOpt::CURLOPT_SSLKEY as u32, 10_087);
        assert_eq!(CurlOpt::CURLOPT_PROXYTYPE as u32, 101);
        assert_eq!(CurlOpt::CURLOPT_HTTPAUTH as u32, 107);
        assert_eq!(CurlOpt::CURLOPT_TCP_NODELAY as u32, 121);
        assert_eq!(CurlOpt::CURLOPT_SSH_PUBLIC_KEYFILE as u32, 10_152);
        assert_eq!(CurlOpt::CURLOPT_XFERINFOFUNCTION as u32, 20_219);
        assert_eq!(CurlOpt::CURLOPT_MIMEPOST as u32, 10_269);
    }

    #[test]
    fn test_try_from_u32_known() {
        assert_eq!(
            CurlOpt::try_from_u32(10_002),
            Some(CurlOpt::CURLOPT_URL)
        );
        assert_eq!(
            CurlOpt::try_from_u32(20_011),
            Some(CurlOpt::CURLOPT_WRITEFUNCTION)
        );
    }

    #[test]
    fn test_try_from_u32_unknown() {
        assert_eq!(CurlOpt::try_from_u32(99_999), None);
        assert_eq!(CurlOpt::try_from_u32(0), None);
    }

    #[test]
    fn test_default_options() {
        let opts = HandleOptions::new();
        assert!(opts.url.is_none());
        assert!(opts.ssl_verifypeer);
        assert!(opts.tcp_nodelay);
        assert!(opts.noprogress);
        assert!(!opts.verbose);
        assert!(!opts.post);
        assert!(!opts.nobody);
        assert!(!opts.upload);
        assert!(opts.ftp_use_epsv);
        assert!(opts.ftp_use_eprt);
        assert_eq!(opts.maxredirs, 30);
        assert_eq!(opts.http_version, CURL_HTTP_VERSION_NONE);
        assert_eq!(opts.proxytype, CURLPROXY_HTTP);
        assert_eq!(opts.httpauth, CURLAUTH_NONE);
        assert_eq!(opts.timeout_ms, 0);
        assert_eq!(opts.connecttimeout_ms, 0);
    }

    #[test]
    fn test_set_url() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_URL as u32,
            CurlOptValue::ObjectPoint("https://example.com".to_string()),
        );
        assert!(result.is_ok());
        assert_eq!(opts.url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn test_set_url_too_long() {
        let mut opts = HandleOptions::new();
        let long_url = "x".repeat(CURL_MAX_INPUT_LENGTH + 1);
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_URL as u32,
            CurlOptValue::ObjectPoint(long_url),
        );
        assert_eq!(result, Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_set_url_wrong_type() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_URL as u32,
            CurlOptValue::Long(42),
        );
        assert_eq!(result, Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_unknown_option() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            99_999,
            CurlOptValue::Long(1),
        );
        assert_eq!(result, Err(CurlError::UnknownOption));
    }

    #[test]
    fn test_set_timeout() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_TIMEOUT as u32,
            CurlOptValue::Long(30),
        );
        assert!(result.is_ok());
        assert_eq!(opts.timeout_ms, 30_000);
    }

    #[test]
    fn test_set_timeout_negative() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_TIMEOUT as u32,
            CurlOptValue::Long(-1),
        );
        assert_eq!(result, Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_set_verbose() {
        let mut opts = HandleOptions::new();
        assert!(!opts.verbose);
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_VERBOSE as u32,
            CurlOptValue::Long(1),
        );
        assert!(result.is_ok());
        assert!(opts.verbose);
    }

    #[test]
    fn test_set_http_version_valid() {
        let mut opts = HandleOptions::new();
        for &v in &[
            CURL_HTTP_VERSION_NONE,
            CURL_HTTP_VERSION_1_0,
            CURL_HTTP_VERSION_1_1,
            CURL_HTTP_VERSION_2_0,
            CURL_HTTP_VERSION_3,
        ] {
            let result = set_option(
                &mut opts,
                CurlOpt::CURLOPT_HTTP_VERSION as u32,
                CurlOptValue::Long(v),
            );
            assert!(result.is_ok(), "version {} should be valid", v);
        }
    }

    #[test]
    fn test_set_http_version_invalid() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_HTTP_VERSION as u32,
            CurlOptValue::Long(99),
        );
        assert_eq!(result, Err(CurlError::UnsupportedProtocol));
    }

    #[test]
    fn test_set_ssl_version_rejects_sslv2() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_SSLVERSION as u32,
            CurlOptValue::Long(CURL_SSLVERSION_SSLV2),
        );
        assert_eq!(result, Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_set_ssl_version_rejects_sslv3() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_SSLVERSION as u32,
            CurlOptValue::Long(CURL_SSLVERSION_SSLV3),
        );
        assert_eq!(result, Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_set_ssl_version_default_maps_to_tls12() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_SSLVERSION as u32,
            CurlOptValue::Long(CURL_SSLVERSION_DEFAULT),
        );
        assert!(result.is_ok());
        // Default maps to TLS 1.2
        assert_eq!(opts.sslversion & 0xFFFF, CURL_SSLVERSION_TLSV1_2);
    }

    #[test]
    fn test_set_httpauth() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_HTTPAUTH as u32,
            CurlOptValue::Long(CURLAUTH_BASIC as i64),
        );
        assert!(result.is_ok());
        assert_eq!(opts.httpauth, CURLAUTH_BASIC);
    }

    #[test]
    fn test_set_httpauth_digest_ie() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_HTTPAUTH as u32,
            CurlOptValue::Long(CURLAUTH_DIGEST_IE as i64),
        );
        assert!(result.is_ok());
        // DIGEST_IE should be converted to standard DIGEST
        assert!(opts.httpauth & CURLAUTH_DIGEST != 0);
        assert!(opts.httpauth & CURLAUTH_DIGEST_IE == 0);
    }

    #[test]
    fn test_set_proxy_type_valid() {
        let mut opts = HandleOptions::new();
        for pt in 0..=7 {
            let result = set_option(
                &mut opts,
                CurlOpt::CURLOPT_PROXYTYPE as u32,
                CurlOptValue::Long(pt),
            );
            assert!(result.is_ok(), "proxy type {} should be valid", pt);
        }
    }

    #[test]
    fn test_set_proxy_type_invalid() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_PROXYTYPE as u32,
            CurlOptValue::Long(100),
        );
        assert_eq!(result, Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_set_followlocation() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_FOLLOWLOCATION as u32,
            CurlOptValue::Long(1),
        );
        assert!(result.is_ok());
        assert_eq!(opts.followlocation, 1);
    }

    #[test]
    fn test_set_followlocation_invalid() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_FOLLOWLOCATION as u32,
            CurlOptValue::Long(5),
        );
        assert_eq!(result, Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_set_maxredirs_clamp() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_MAXREDIRS as u32,
            CurlOptValue::Long(100_000),
        );
        assert!(result.is_ok());
        assert_eq!(opts.maxredirs, 0x7FFF);
    }

    #[test]
    fn test_set_maxredirs_negative_one() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_MAXREDIRS as u32,
            CurlOptValue::Long(-1),
        );
        assert!(result.is_ok());
        assert_eq!(opts.maxredirs, -1);
    }

    #[test]
    fn test_set_maxredirs_too_negative() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_MAXREDIRS as u32,
            CurlOptValue::Long(-2),
        );
        assert_eq!(result, Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_set_httpheader() {
        let mut opts = HandleOptions::new();
        let mut list = SList::new();
        list.append("Content-Type: application/json");
        list.append("Accept: */*");
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_HTTPHEADER as u32,
            CurlOptValue::SList(list),
        );
        assert!(result.is_ok());
        let headers = opts.httpheader.as_ref().unwrap();
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn test_set_writefunction() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_WRITEFUNCTION as u32,
            CurlOptValue::FunctionPoint,
        );
        assert!(result.is_ok());
        assert!(opts.has_write_function);
    }

    #[test]
    fn test_set_writefunction_wrong_type() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_WRITEFUNCTION as u32,
            CurlOptValue::Long(1),
        );
        assert_eq!(result, Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_upload_implies_no_nobody() {
        let mut opts = HandleOptions::new();
        opts.nobody = true;
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_UPLOAD as u32,
            CurlOptValue::Long(1),
        );
        assert!(result.is_ok());
        assert!(opts.upload);
        assert!(!opts.nobody); // upload clears nobody
    }

    #[test]
    fn test_post_implies_no_nobody() {
        let mut opts = HandleOptions::new();
        opts.nobody = true;
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_POST as u32,
            CurlOptValue::Long(1),
        );
        assert!(result.is_ok());
        assert!(opts.post);
        assert!(!opts.nobody);
    }

    #[test]
    fn test_set_ftp_options() {
        let mut opts = HandleOptions::new();
        // Disable EPSV
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_FTP_USE_EPSV as u32,
            CurlOptValue::Long(0),
        );
        assert!(result.is_ok());
        assert!(!opts.ftp_use_epsv);

        // Disable EPRT
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_FTP_USE_EPRT as u32,
            CurlOptValue::Long(0),
        );
        assert!(result.is_ok());
        assert!(!opts.ftp_use_eprt);
    }

    #[test]
    fn test_set_ssh_keyfiles() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_SSH_PUBLIC_KEYFILE as u32,
            CurlOptValue::ObjectPoint("/home/user/.ssh/id_rsa.pub".into()),
        );
        assert!(result.is_ok());
        assert_eq!(
            opts.ssh_public_keyfile.as_deref(),
            Some("/home/user/.ssh/id_rsa.pub")
        );

        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_SSH_PRIVATE_KEYFILE as u32,
            CurlOptValue::ObjectPoint("/home/user/.ssh/id_rsa".into()),
        );
        assert!(result.is_ok());
        assert_eq!(
            opts.ssh_private_keyfile.as_deref(),
            Some("/home/user/.ssh/id_rsa")
        );
    }

    #[test]
    fn test_timeout_overflow_protection() {
        let mut opts = HandleOptions::new();
        // Very large timeout should be clamped, not overflow
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_TIMEOUT as u32,
            CurlOptValue::Long(i64::MAX),
        );
        assert!(result.is_ok());
        assert_eq!(opts.timeout_ms, i64::MAX);
    }

    #[test]
    fn test_set_connecttimeout() {
        let mut opts = HandleOptions::new();
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_CONNECTTIMEOUT as u32,
            CurlOptValue::Long(60),
        );
        assert!(result.is_ok());
        assert_eq!(opts.connecttimeout_ms, 60_000);
    }

    #[test]
    fn test_set_mimepost_blob() {
        let mut opts = HandleOptions::new();
        let data = vec![0u8, 1, 2, 3];
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_MIMEPOST as u32,
            CurlOptValue::Blob(data.clone()),
        );
        assert!(result.is_ok());
        assert_eq!(opts.mimepost, Some(data));
        assert!(opts.post);
    }

    #[test]
    fn test_set_share() {
        let mut opts = HandleOptions::new();
        assert!(!opts.share_enabled);
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_SHARE as u32,
            CurlOptValue::ObjectPoint(String::new()),
        );
        assert!(result.is_ok());
        assert!(opts.share_enabled);
    }

    #[test]
    fn test_ssl_verifypeer_disable() {
        let mut opts = HandleOptions::new();
        assert!(opts.ssl_verifypeer);
        let result = set_option(
            &mut opts,
            CurlOpt::CURLOPT_SSL_VERIFYPEER as u32,
            CurlOptValue::Long(0),
        );
        assert!(result.is_ok());
        assert!(!opts.ssl_verifypeer);
    }

    #[test]
    fn test_curlopt_value_kind_name() {
        assert_eq!(CurlOptValue::Long(0).kind_name(), "Long");
        assert_eq!(
            CurlOptValue::ObjectPoint(String::new()).kind_name(),
            "ObjectPoint"
        );
        assert_eq!(CurlOptValue::FunctionPoint.kind_name(), "FunctionPoint");
        assert_eq!(CurlOptValue::OffT(0).kind_name(), "OffT");
        assert_eq!(CurlOptValue::Blob(vec![]).kind_name(), "Blob");
        assert_eq!(
            CurlOptValue::SList(SList::new()).kind_name(),
            "SList"
        );
    }
}
