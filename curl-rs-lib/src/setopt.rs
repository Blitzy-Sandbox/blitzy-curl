// Typed option application for the curl-rs workspace — the `curl_easy_setopt`
// dispatch core.
//
// SPDX-License-Identifier: curl
//
// This file is a memory-safe Rust reimplementation of curl's option-setting
// logic (`lib/setopt.c`, primarily `Curl_vsetopt` and its `switch(option)`
// over every `CURLOPT_*`, with default values cross-referenced against
// `Curl_init_userdefined` in `lib/url.c`). The original C sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).
// This Rust port preserves the observable option *semantics*, *defaults* and
// *validation* of that logic — it is a behavioral translation, not a
// line-by-line one (AAP §0.8.2, the minimal-change / parity mandate).

//! Typed option application — the safe half of curl's variadic
//! `curl_easy_setopt` (`lib/setopt.c`).
//!
//! curl's public `curl_easy_setopt(handle, option, ...)` is C-variadic: it
//! reads a single trailing argument whose C type is determined by the
//! option's `CURLOPTTYPE_*` group. Defining a variadic `extern "C"` function
//! and reading a `va_list` is inherently `unsafe`, so the rewrite splits the
//! work in two (AAP §0.7.2):
//!
//! * The **FFI crate** (`curl-rs-ffi`) owns the dangerous part: it reads the
//!   one trailing vararg, converts it into a typed [`OptionValue`] based on the
//!   option's group (looked up via [`crate::options`]), and then calls
//!   [`apply`].
//! * This module owns the **typed, `unsafe`-free** part: [`apply`] validates
//!   the value and stores it onto the easy handle's [`UserDefined`] settings,
//!   exactly mirroring the `set.*` field each `CURLOPT_*` writes in
//!   `lib/setopt.c`, including range checks, clamping and the small number of
//!   side effects (for example `CURLOPT_POST` selecting the HTTP method).
//!
//! Because the dispatch never touches a raw pointer or `va_list`, the whole
//! module compiles under `#![forbid(unsafe_code)]`. Pointers that genuinely
//! cannot be modelled safely here — C `FILE *`, application `void *`
//! callback-data, function pointers, and the legacy `curl_httppost` /
//! `curl_mime` objects — are carried as their integer addresses in the
//! [`CDataPtr`] / [`CCallback`] newtypes; storing an address is a safe
//! operation, and the FFI layer is solely responsible for ever dereferencing
//! them.
//!
//! # Error mapping
//!
//! The return type is [`crate::error::Result`]. The three error codes the C
//! `switch` produces are reproduced exactly:
//!
//! * unknown / unrecognised option id → [`CurlError::UnknownOption`]
//!   (`CURLE_UNKNOWN_OPTION`),
//! * a value that fails validation → [`CurlError::BadFunctionArgument`]
//!   (`CURLE_BAD_FUNCTION_ARGUMENT`),
//! * an option whose capability is compiled out → [`CurlError::NotBuiltIn`]
//!   (`CURLE_NOT_BUILT_IN`).
//!
//! # Feature gating
//!
//! curl gates options behind `#ifdef CURL_DISABLE_*` / `USE_*`. The rewrite
//! maps those to Cargo features (AAP §0.6.2). Every [`UserDefined`] field is
//! always present so the type is stable across feature sets; only the
//! *behavior* of an option is gated, via compile-time [`cfg!`] checks, and a
//! disabled option returns [`CurlError::NotBuiltIn`]. This keeps the crate
//! compiling under `--no-default-features` while reporting `CURLE_NOT_BUILT_IN`
//! for the options whose feature is off.

#![forbid(unsafe_code)]

use crate::error::{CurlError, Result};
use crate::share::Share;
use crate::slist::SList;
use crate::url::CurlUrl;

// Re-export the shared option identifier space so dependents (and the FFI
// crate) can refer to `setopt::CurlOption` / `setopt::CurloptTypeGroup`
// alongside the value model and [`apply`] defined here.
pub use crate::options::{CurlOption, CurloptTypeGroup};

// ===========================================================================
// Opaque pointer / callback carriers
// ===========================================================================

/// A C function pointer, carried as its integer address.
///
/// curl stores raw `curl_*_callback` function pointers directly on the handle
/// (`set.fwrite_func`, `set.fread_func_set`, …). A function pointer cannot be
/// modelled in safe Rust, so the FFI layer passes the address and this module
/// stores it verbatim. A value of `0` denotes a `NULL` callback, which curl
/// treats as "use the built-in default" for several callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CCallback(pub usize);

impl CCallback {
    /// The `NULL` callback sentinel (address `0`).
    pub const NULL: CCallback = CCallback(0);

    /// Returns `true` when no callback is set (a `NULL` function pointer).
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// An opaque application data pointer (`void *`, `FILE *`, `CURL *`,
/// `curl_httppost *`, `curl_mime *`), carried as its integer address.
///
/// These are values curl stores but never interprets within `setopt`
/// (`set.out`, `set.in_set`, `set.debugdata`, the deprecated form/MIME
/// objects, …). Holding the address is a safe operation; only the FFI layer
/// dereferences it. A value of `0` denotes a `NULL` pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CDataPtr(pub usize);

impl CDataPtr {
    /// The `NULL` pointer sentinel (address `0`).
    pub const NULL: CDataPtr = CDataPtr(0);

    /// Returns `true` when the pointer is `NULL`.
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

// ===========================================================================
// Blob value (`struct curl_blob`)
// ===========================================================================

/// An owned copy of a `struct curl_blob` payload (the `CURLOPTTYPE_BLOB`
/// argument used by `CURLOPT_SSLCERT_BLOB`, `CURLOPT_CAINFO_BLOB`, …).
///
/// curl's `struct curl_blob` is `{ void *data; size_t len; unsigned int flags; }`
/// where `data`/`len` point at caller memory. To stay memory-safe the FFI
/// layer copies the bytes into [`Blob::data`] (honouring `CURL_BLOB_COPY`
/// semantics for the caller regardless), so the stored blob always owns its
/// payload. [`Blob::flags`] preserves the `CURL_BLOB_*` flag bits.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Blob {
    /// The blob payload bytes (owned).
    pub data: Vec<u8>,
    /// The `CURL_BLOB_*` flag bits supplied with the blob.
    pub flags: u32,
}

// ===========================================================================
// The typed option value model
// ===========================================================================

/// The typed value the FFI variadic shim marshals a `curl_easy_setopt`
/// trailing argument into, before handing it to [`apply`].
///
/// Which variant the FFI builds is determined by the option's
/// `CURLOPTTYPE_*` group and — within the object-pointer group — by the
/// specific option (curl itself distinguishes slist, object and string
/// pointers by an explicit option list in `Curl_vsetopt`). [`apply`] expects
/// the variant that matches the option; a mismatch is reported as
/// [`CurlError::BadFunctionArgument`], mirroring curl's treatment of a bad
/// argument.
// `OptionValue` is a transient dispatch value: the FFI builds exactly one per
// `curl_easy_setopt` call and `apply` consumes it immediately, so the size
// disparity between, e.g., `Long(i64)` and `Slist(Option<SList>)` carries no
// memory cost worth an extra heap indirection. Boxing the large variants would
// only complicate the FFI marshaling for no practical benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum OptionValue {
    /// A C `long` argument (`CURLOPTTYPE_LONG` / `CURLOPTTYPE_VALUES`).
    Long(i64),
    /// A `curl_off_t` argument (`CURLOPTTYPE_OFF_T`).
    OffT(i64),
    /// A C string (`char *`) argument; `None` is a `NULL` pointer (which curl
    /// generally treats as "clear this option").
    Str(Option<String>),
    /// Raw bytes for the binary `CURLOPT_COPYPOSTFIELDS` payload (the FFI has
    /// already applied curl's `NUL`-terminate-vs-`postfieldsize` length rule).
    /// `None` is a `NULL` pointer.
    Bytes(Option<Vec<u8>>),
    /// A `struct curl_blob *` argument (`CURLOPTTYPE_BLOB`); `None` is `NULL`.
    Blob(Option<Blob>),
    /// A `struct curl_slist *` argument, captured as an owned [`SList`];
    /// `None` is a `NULL` list.
    Slist(Option<SList>),
    /// A `CURLSH *` share-handle argument; `None` disconnects the share.
    Share(Option<Share>),
    /// A function pointer argument (`CURLOPTTYPE_FUNCTIONPOINT`).
    Callback(CCallback),
    /// An opaque object / data pointer argument (`void *`, `FILE *`, `CURL *`,
    /// `curl_httppost *`, `curl_mime *`).
    Ptr(CDataPtr),
}

impl OptionValue {
    /// Extracts a `long` value, or [`CurlError::BadFunctionArgument`] if the
    /// FFI built the wrong variant for this option.
    fn as_long(&self) -> Result<i64> {
        match self {
            OptionValue::Long(v) => Ok(*v),
            _ => Err(CurlError::BadFunctionArgument),
        }
    }

    /// Extracts a `curl_off_t` value.
    fn as_offt(&self) -> Result<i64> {
        match self {
            OptionValue::OffT(v) => Ok(*v),
            _ => Err(CurlError::BadFunctionArgument),
        }
    }

    /// Consumes the value as an optional owned string (`char *`).
    fn into_str(self) -> Result<Option<String>> {
        match self {
            OptionValue::Str(s) => Ok(s),
            _ => Err(CurlError::BadFunctionArgument),
        }
    }

    /// Consumes the value as optional raw bytes (`CURLOPT_COPYPOSTFIELDS`).
    fn into_bytes(self) -> Result<Option<Vec<u8>>> {
        match self {
            OptionValue::Bytes(b) => Ok(b),
            // A `NULL` char* arrives as `Str(None)`; treat it as empty/clear.
            OptionValue::Str(None) => Ok(None),
            _ => Err(CurlError::BadFunctionArgument),
        }
    }

    /// Consumes the value as an optional [`Blob`].
    fn into_blob(self) -> Result<Option<Blob>> {
        match self {
            OptionValue::Blob(b) => Ok(b),
            _ => Err(CurlError::BadFunctionArgument),
        }
    }

    /// Consumes the value as an optional [`SList`].
    fn into_slist(self) -> Result<Option<SList>> {
        match self {
            OptionValue::Slist(s) => Ok(s),
            _ => Err(CurlError::BadFunctionArgument),
        }
    }

    /// Consumes the value as an optional [`Share`].
    fn into_share(self) -> Result<Option<Share>> {
        match self {
            OptionValue::Share(s) => Ok(s),
            _ => Err(CurlError::BadFunctionArgument),
        }
    }

    /// Extracts a function-pointer address.
    fn as_callback(&self) -> Result<CCallback> {
        match self {
            OptionValue::Callback(c) => Ok(*c),
            _ => Err(CurlError::BadFunctionArgument),
        }
    }

    /// Extracts an opaque data-pointer address.
    fn as_ptr(&self) -> Result<CDataPtr> {
        match self {
            OptionValue::Ptr(p) => Ok(*p),
            _ => Err(CurlError::BadFunctionArgument),
        }
    }
}

// ===========================================================================
// String storage slots (`enum dupstring` in `lib/urldata.h`)
// ===========================================================================

/// Index into [`UserDefined::strings`], one slot per curl `STRING_*` value.
///
/// curl stores its string options in a flat `char *str[STRING_LAST]` array
/// (`lib/urldata.h`); this enum is the safe equivalent index, preserving
/// curl's slot ordering so the mapping from each `CURLOPT_*` to its backing
/// slot matches `lib/setopt.c` exactly. `#[allow(dead_code)]` is required
/// because which slots are actually written depends on the active Cargo
/// feature set (a `--no-default-features` build leaves many slots unused).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum StrId {
    Cert,
    CertType,
    Key,
    KeyPasswd,
    KeyType,
    SslCapath,
    SslCafile,
    SslPinnedPublicKey,
    SslCipherList,
    SslCipher13List,
    SslCrlfile,
    SslIssuercert,
    ServiceName,
    CertProxy,
    CertTypeProxy,
    KeyProxy,
    KeyPasswdProxy,
    KeyTypeProxy,
    SslCapathProxy,
    SslCafileProxy,
    SslPinnedPublicKeyProxy,
    SslCipherListProxy,
    SslCipher13ListProxy,
    SslCrlfileProxy,
    SslIssuercertProxy,
    ProxyServiceName,
    Cookie,
    Cookiejar,
    Customrequest,
    DefaultProtocol,
    Device,
    Interface,
    Bindhost,
    Encoding,
    FtpAccount,
    FtpAlternativeToUser,
    Ftpport,
    NetrcFile,
    Proxy,
    PreProxy,
    SetRange,
    SetReferer,
    SetUrl,
    Useragent,
    SslEngine,
    Username,
    Password,
    Options,
    Proxyusername,
    Proxypassword,
    Noproxy,
    RtspSessionId,
    RtspStreamUri,
    RtspTransport,
    SshPrivateKey,
    SshPublicKey,
    SshHostPublicKeyMd5,
    SshHostPublicKeySha256,
    SshKnownhosts,
    MailFrom,
    MailAuth,
    TlsauthUsername,
    TlsauthPassword,
    TlsauthUsernameProxy,
    TlsauthPasswordProxy,
    Bearer,
    UnixSocketPath,
    Target,
    Doh,
    Altsvc,
    Hsts,
    SaslAuthzid,
    DnsServers,
    DnsInterface,
    DnsLocalIp4,
    DnsLocalIp6,
    SslEcCurves,
    AwsSigv4,
    HaproxyClientIp,
    SslSignatureAlgorithms,
    /// Sentinel marking the slot count; never used as a real slot.
    Last,
}

impl StrId {
    /// Number of string slots (curl's `STRING_LAST`).
    pub const COUNT: usize = StrId::Last as usize;

    /// This slot's array index.
    #[must_use]
    const fn idx(self) -> usize {
        self as usize
    }
}

// ===========================================================================
// Blob storage slots (`enum dupblob` in `lib/urldata.h`)
// ===========================================================================

/// Index into [`UserDefined::blobs`], one slot per curl `BLOB_*` value.
///
/// Mirrors curl's `struct curl_blob *blobs[BLOB_LAST]`. As with [`StrId`],
/// `#[allow(dead_code)]` is required because slot usage is feature-conditional.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum BlobId {
    Cert,
    Key,
    SslIssuercert,
    Cainfo,
    CertProxy,
    KeyProxy,
    SslIssuercertProxy,
    CainfoProxy,
    /// Sentinel marking the slot count; never used as a real slot.
    Last,
}

impl BlobId {
    /// Number of blob slots (curl's `BLOB_LAST`).
    pub const COUNT: usize = BlobId::Last as usize;

    /// This slot's array index.
    #[must_use]
    const fn idx(self) -> usize {
        self as usize
    }
}

// ===========================================================================
// Validation constants (mirroring `lib/setopt.c` / public headers)
// ===========================================================================

/// Maximum accepted length of a string option, in bytes (`CURL_MAX_INPUT_LENGTH`).
const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

/// Minimum receive-buffer size (`READBUFFER_MIN`).
const READBUFFER_MIN: i64 = 1024;
/// Maximum receive-buffer size (`READBUFFER_MAX`).
const READBUFFER_MAX: i64 = 10 * 1024 * 1024;
/// Minimum upload-buffer size (`UPLOADBUFFER_MIN`).
const UPLOADBUFFER_MIN: i64 = 16 * 1024;
/// Maximum upload-buffer size (`UPLOADBUFFER_MAX`).
const UPLOADBUFFER_MAX: i64 = 2 * 1024 * 1024;

/// 16-bit unsigned maximum, used for port ranges and `LOW_SPEED_TIME`.
const U16_MAX_L: i64 = 0xffff;
/// 32-bit signed maximum (`INT_MAX`), used for several keep-alive / timeout caps.
const I32_MAX_L: i64 = i32::MAX as i64;
/// 32-bit unsigned maximum (`UINT_MAX`), the `CURLOPT_ADDRESS_SCOPE` ceiling.
const U32_MAX_L: i64 = 0xffff_ffff;

// `CURLPROTO_*` protocol bits (`include/curl/curl.h`).
const CURLPROTO_ALL: u32 = 0xffff_ffff;
/// Default redirect-protocol set: HTTP | HTTPS | FTP | FTPS.
const CURLPROTO_REDIR: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3);

// `CURLAUTH_*` HTTP authentication bits (`include/curl/curl.h`).
const CURLAUTH_BASIC: u32 = 1 << 0;
const CURLAUTH_DIGEST: u32 = 1 << 1;
const CURLAUTH_NEGOTIATE: u32 = 1 << 2;
const CURLAUTH_NTLM: u32 = 1 << 3;
const CURLAUTH_DIGEST_IE: u32 = 1 << 4;
const CURLAUTH_AWS_SIGV4: u32 = 1 << 7;
const CURLAUTH_GSSAPI: u32 = 1 << 2; // alias of CURLAUTH_NEGOTIATE

// `CURLSSLOPT_*` bits (`include/curl/curl.h`).
const CURLSSLOPT_ALLOW_BEAST: i64 = 1 << 0;
const CURLSSLOPT_NO_REVOKE: i64 = 1 << 1;
const CURLSSLOPT_NO_PARTIALCHAIN: i64 = 1 << 2;
const CURLSSLOPT_REVOKE_BEST_EFFORT: i64 = 1 << 3;
const CURLSSLOPT_NATIVE_CA: i64 = 1 << 4;
const CURLSSLOPT_AUTO_CLIENT_CERT: i64 = 1 << 5;
const CURLSSLOPT_EARLYDATA: i64 = 1 << 6;

// `CURL_SSLVERSION_*` (`include/curl/curl.h`).
const CURL_SSLVERSION_DEFAULT: i64 = 0;
const CURL_SSLVERSION_SSLV2: i64 = 2;
const CURL_SSLVERSION_SSLV3: i64 = 3;
const CURL_SSLVERSION_TLSV1_2: i64 = 6;
const CURL_SSLVERSION_LAST: i64 = 8;
const CURL_SSLVERSION_MAX_NONE: i64 = 0;
const CURL_SSLVERSION_MAX_LAST: i64 = CURL_SSLVERSION_LAST << 16;

// `CURL_HTTP_VERSION_*` (`include/curl/curl.h`).
const CURL_HTTP_VERSION_NONE: i64 = 0;
const CURL_HTTP_VERSION_1_0: i64 = 1;
const CURL_HTTP_VERSION_1_1: i64 = 2;
const CURL_HTTP_VERSION_2_0: i64 = 3;
const CURL_HTTP_VERSION_2TLS: i64 = 4;
const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: i64 = 5;
const CURL_HTTP_VERSION_3: i64 = 30;
const CURL_HTTP_VERSION_3ONLY: i64 = 31;

// Miscellaneous range bounds used by the `LONG` handlers.
const CURLHEADER_SEPARATE: i64 = 1 << 1;
const CURL_REDIR_GET_ALL: i64 = 0;
const CURL_REDIR_POST_301: i64 = 1;
const CURL_REDIR_POST_302: i64 = 2;
const CURL_REDIR_POST_303: i64 = 4;
const CURLUSESSL_LAST: i64 = 4;
const CURL_NETRC_LAST: i64 = 3;
const CURL_FTPMETHOD_LAST: i64 = 4;
const CURL_FTPSSL_CCC_LAST: i64 = 3;
const CURL_FTPAUTH_LAST: i64 = 3;
const CURL_TIMECOND_LAST: i64 = 5;
const TFTP_BLKSIZE_MIN: i64 = 8;
const TFTP_BLKSIZE_MAX: i64 = 65464;
const CURLPROXY_TYPE_MAX: i64 = 7; // CURLPROXY_SOCKS5_HOSTNAME
const MIMEPOST_OPT_FORMESCAPE: i64 = 1 << 0;
const CURLHSTS_ENABLE: i64 = 1 << 0;
const CURLFTP_CREATE_DIR_RETRY: i64 = 2;
const PERMS_MAX: i64 = 0o777;
const STREAM_WEIGHT_MIN: i64 = 1;
const STREAM_WEIGHT_MAX: i64 = 256;
const FOLLOW_MODE_MAX: i64 = 3; // CURLFOLLOW_ALL
/// `CURLWS_RAW_MODE` WebSocket raw-mode bit.
const CURLWS_RAW_MODE: i64 = 1 << 0;
/// `CURLWS_NOAUTOPONG` WebSocket auto-pong-suppression bit.
const CURLWS_NOAUTOPONG: i64 = 1 << 1;
/// First public RTSP request value (`CURL_RTSPREQ_OPTIONS`).
const CURL_RTSPREQ_OPTIONS: i64 = 1;
/// Last public RTSP request value (`CURL_RTSPREQ_RECEIVE`).
const CURL_RTSPREQ_RECEIVE: i64 = 11;

// --- Default values used by `UserDefined::default` (Curl_init_userdefined) --

/// Default Happy Eyeballs timeout in ms (`CURL_HET_DEFAULT`).
const CURL_HET_DEFAULT: i64 = 200;
/// Default connection-upkeep interval in ms (`CURL_UPKEEP_INTERVAL_DEFAULT`).
const CURL_UPKEEP_INTERVAL_DEFAULT: i64 = 60_000;
/// Default receive buffer size (`CURL_MAX_WRITE_SIZE`, 16 KiB).
const CURL_READ_BUFFER_DEFAULT: u32 = 16_384;
/// Default upload buffer size (`UPLOADBUFFER_DEFAULT`, 64 KiB).
const CURL_UPLOAD_BUFFER_DEFAULT: u32 = 65_536;
/// Default allowed SSH auth methods (`CURLSSH_AUTH_DEFAULT` = any).
const CURLSSH_AUTH_DEFAULT: u32 = 0xffff_ffff;
/// Default connection-cache size (`set->maxconnects` initial = 5).
const CURL_DEFAULT_MAXCONNECTS: u32 = 5;
/// `CURLPROXY_HTTP` proxy-type discriminant.
const CURLPROXY_HTTP: u8 = 0;
/// `CURLFTPMETHOD_MULTICWD` FTP file-method discriminant.
const CURL_FTPMETHOD_MULTICWD: u8 = 1;

// ===========================================================================
// HTTP request method (`Curl_HttpReq` in `lib/http.h`)
// ===========================================================================

/// The HTTP request kind selected by the method-shaping options
/// (`CURLOPT_HTTPGET` / `POST` / `PUT` / `UPLOAD` / `NOBODY` / `MIMEPOST` /
/// `HTTPPOST`). Values match curl's `Curl_HttpReq` enum exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum HttpReq {
    /// `HTTPREQ_GET` — the default.
    #[default]
    Get = 0,
    /// `HTTPREQ_POST` — `Content-Type: application/x-www-form-urlencoded` POST.
    Post = 1,
    /// `HTTPREQ_POST_FORM` — legacy `curl_httppost` multipart POST.
    PostForm = 2,
    /// `HTTPREQ_POST_MIME` — `curl_mime` multipart POST.
    PostMime = 3,
    /// `HTTPREQ_PUT` — upload via PUT.
    Put = 4,
    /// `HTTPREQ_HEAD` — HEAD (no body).
    Head = 5,
}

// ===========================================================================
// TLS configuration sub-structs (`ssl_primary_config` / `ssl_config_data` /
// `ssl_general_config`)
// ===========================================================================

/// The per-connection TLS parameters an easy handle carries
/// (`struct ssl_primary_config`), restricted to the fields `setopt` writes.
///
/// Certificate validation is **on by default** (`verifypeer` / `verifyhost`),
/// matching curl; disabling it via `CURLOPT_SSL_VERIFYPEER 0` is accepted here
/// (the `--insecure` warning is emitted at the CLI edge, AAP §0.8.1, not in
/// this typed core).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslPrimaryConfig {
    /// Verify the peer certificate chain (`CURLOPT_SSL_VERIFYPEER`).
    pub verifypeer: bool,
    /// Verify the certificate hostname (`CURLOPT_SSL_VERIFYHOST`).
    pub verifyhost: bool,
    /// Verify the certificate status / OCSP staple (`CURLOPT_SSL_VERIFYSTATUS`).
    pub verifystatus: bool,
    /// Requested minimum TLS version (`CURL_SSLVERSION_*`).
    pub version: u8,
    /// Requested maximum TLS version (`CURL_SSLVERSION_MAX_*`, already shifted).
    pub version_max: u32,
    /// Raw `CURLSSLOPT_*` option bits (low byte; `CURLOPT_SSL_OPTIONS`).
    pub ssl_options: u8,
    /// Reuse cached TLS sessions (`CURLOPT_SSL_SESSIONID_CACHE`).
    pub cache_session: bool,
}

impl Default for SslPrimaryConfig {
    fn default() -> Self {
        // curl initialises verifypeer/verifyhost TRUE and the session cache on
        // (see `Curl_init_userdefined` / `ssl_easy_config_init`).
        SslPrimaryConfig {
            verifypeer: true,
            verifyhost: true,
            verifystatus: false,
            version: 0, // CURL_SSLVERSION_DEFAULT
            version_max: 0,
            ssl_options: 0,
            cache_session: true,
        }
    }
}

/// The full per-direction TLS config (`struct ssl_config_data`), restricted to
/// the fields `setopt` writes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SslConfig {
    /// The primary (negotiable) TLS parameters.
    pub primary: SslPrimaryConfig,
    /// Gather certificate info (`CURLOPT_CERTINFO`).
    pub certinfo: bool,
    /// Allow the BEAST workaround (`CURLSSLOPT_ALLOW_BEAST`).
    pub enable_beast: bool,
    /// Disable revocation checking (`CURLSSLOPT_NO_REVOKE`).
    pub no_revoke: bool,
    /// Accept partial certificate chains (`CURLSSLOPT_NO_PARTIALCHAIN`).
    pub no_partialchain: bool,
    /// Best-effort revocation checking (`CURLSSLOPT_REVOKE_BEST_EFFORT`).
    pub revoke_best_effort: bool,
    /// Use the OS-native CA store (`CURLSSLOPT_NATIVE_CA`).
    pub native_ca_store: bool,
    /// Auto-select a client certificate (`CURLSSLOPT_AUTO_CLIENT_CERT`).
    pub auto_client_cert: bool,
    /// Enable TLS 1.3 early data (`CURLSSLOPT_EARLYDATA`).
    pub earlydata: bool,
    /// The application set a custom CA file (`CURLOPT_CAINFO`).
    pub custom_cafile: bool,
    /// The application set a custom CA path (`CURLOPT_CAPATH`).
    pub custom_capath: bool,
    /// The application set a custom CA blob (`CURLOPT_CAINFO_BLOB`).
    pub custom_cablob: bool,
}

/// Process-wide / handle-wide general TLS config (`struct ssl_general_config`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslGeneralConfig {
    /// CA-store cache lifetime in seconds, `-1` for unlimited
    /// (`CURLOPT_CA_CACHE_TIMEOUT`).
    pub ca_cache_timeout: i64,
}

impl Default for SslGeneralConfig {
    fn default() -> Self {
        // curl's default is 24 hours (86400 s).
        SslGeneralConfig {
            ca_cache_timeout: 86_400,
        }
    }
}

// ===========================================================================
// HTTP/2 + HTTP/3 stream priority (`struct Curl_data_priority`)
// ===========================================================================

/// Stream priority / dependency settings for HTTP/2 and HTTP/3
/// (`CURLOPT_STREAM_WEIGHT` / `CURLOPT_STREAM_DEPENDS` /
/// `CURLOPT_STREAM_DEPENDS_E`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Priority {
    /// The dependency target easy handle, carried as an address.
    pub dependent: CDataPtr,
    /// Whether the dependency is exclusive (`CURLOPT_STREAM_DEPENDS_E`).
    pub exclusive: bool,
    /// The stream weight, 1..=256 (`CURLOPT_STREAM_WEIGHT`); `0` = unset.
    pub weight: i32,
}

// ===========================================================================
// The user-defined settings block (`struct UserDefined` in `lib/urldata.h`)
// ===========================================================================

/// The complete set of user-configurable options on an easy handle — the safe
/// equivalent of curl's `struct UserDefined set`.
///
/// Every `CURLOPT_*` writes exactly one (occasionally two) of these fields;
/// [`apply`] is the dispatcher that performs those writes. The field names
/// deliberately track curl's so the mapping stays greppable against
/// `lib/setopt.c` and `lib/urldata.h`. The struct does **not** derive `Clone`:
/// curl's handle duplication (`curl_easy_duphandle`) is a bespoke deep copy
/// that the easy-handle layer will implement, not a blanket clone.
///
/// All fields are present in every build; feature gating affects only whether
/// an option is *accepted* (see the module docs), never the layout.
#[derive(Debug)]
pub struct UserDefined {
    // ---- opaque application data pointers (`void *` / `FILE *` / `CURL *`) --
    /// `CURLOPT_WRITEDATA` write-callback userdata (curl `set.out`).
    pub out: CDataPtr,
    /// `CURLOPT_READDATA` read-callback userdata (curl `set.in_set`).
    pub in_set: CDataPtr,
    /// `CURLOPT_HEADERDATA` header-callback userdata (curl `set.writeheader`).
    pub writeheader: CDataPtr,
    /// `CURLOPT_STDERR` error/verbose stream (curl `set.err`).
    pub err: CDataPtr,
    /// `CURLOPT_DEBUGDATA` debug-callback userdata.
    pub debugdata: CDataPtr,
    /// `CURLOPT_PROGRESSDATA` / `CURLOPT_XFERINFODATA` userdata.
    pub progress_client: CDataPtr,
    /// `CURLOPT_SEEKDATA` seek-callback userdata.
    pub seek_client: CDataPtr,
    /// `CURLOPT_IOCTLDATA` ioctl-callback userdata.
    pub ioctl_client: CDataPtr,
    /// `CURLOPT_SOCKOPTDATA` sockopt-callback userdata.
    pub sockopt_client: CDataPtr,
    /// `CURLOPT_OPENSOCKETDATA` open-socket-callback userdata.
    pub opensocket_client: CDataPtr,
    /// `CURLOPT_CLOSESOCKETDATA` close-socket-callback userdata.
    pub closesocket_client: CDataPtr,
    /// `CURLOPT_PREREQDATA` pre-request-callback userdata.
    pub prereq_userp: CDataPtr,
    /// `CURLOPT_RESOLVER_START_DATA` resolver-start-callback userdata.
    pub resolver_start_client: CDataPtr,
    /// `CURLOPT_INTERLEAVEDATA` RTSP interleave userdata.
    pub interleave_client: CDataPtr,
    /// `CURLOPT_CHUNK_DATA` wildcard chunk-callback userdata (curl `set.wildcardptr`).
    pub wildcardptr: CDataPtr,
    /// `CURLOPT_FNMATCH_DATA` fnmatch-callback userdata.
    pub fnmatch_data: CDataPtr,
    /// `CURLOPT_SSH_KEYDATA` SSH key-callback userdata.
    pub ssh_keyfunc_userp: CDataPtr,
    /// `CURLOPT_SSH_HOSTKEYDATA` SSH hostkey-callback userdata.
    pub ssh_hostkeyfunc_userp: CDataPtr,
    /// `CURLOPT_HSTSREADDATA` HSTS read-callback userdata.
    pub hsts_read_userp: CDataPtr,
    /// `CURLOPT_HSTSWRITEDATA` HSTS write-callback userdata.
    pub hsts_write_userp: CDataPtr,
    /// `CURLOPT_TRAILERDATA` trailer-callback userdata.
    pub trailer_data: CDataPtr,
    /// `CURLOPT_PRIVATE` application-private pointer.
    pub private_data: CDataPtr,
    /// `CURLOPT_ERRORBUFFER` caller error buffer.
    pub errorbuffer: CDataPtr,
    /// `CURLOPT_POSTFIELDS` borrowed POST body pointer (not owned).
    pub postfields: Option<CDataPtr>,
    /// `CURLOPT_HTTPPOST` legacy multipart form (opaque `curl_httppost *`).
    pub httppost: CDataPtr,
    /// `CURLOPT_MIMEPOST` MIME post object (opaque `curl_mime *`). Retained for
    /// C-ABI parity (the FFI layer stores the caller's `curl_mime *` here); the
    /// safe core cannot deref it, so the *serialized* form below is what the
    /// transfer engine consumes.
    pub mimepost: CDataPtr,
    /// The serialized `multipart/form-data` request body produced from the MIME
    /// tree (`Mime::to_bytes`), owned so the `#![forbid(unsafe_code)]` core can
    /// stream it without dereferencing the opaque `mimepost` pointer. Set via
    /// [`Easy::set_mime_body`](crate::easy::Easy::set_mime_body) on the direct
    /// (CLI) path and by the FFI shim on the C-ABI path.
    pub mime_body: Option<Vec<u8>>,
    /// The `Content-Type` header value for [`mime_body`](Self::mime_body), e.g.
    /// `multipart/form-data; boundary=…`, applied unless the application supplied
    /// its own `Content-Type` (curl's `Curl_mime_contenttype` behavior).
    pub mime_content_type: Option<String>,

    // ---- callback function pointers ----------------------------------------
    /// `CURLOPT_WRITEFUNCTION` body writer.
    pub fwrite_func: CCallback,
    /// `CURLOPT_READFUNCTION` body reader.
    pub fread_func_set: CCallback,
    /// `CURLOPT_HEADERFUNCTION` header writer.
    pub fwrite_header: CCallback,
    /// `CURLOPT_INTERLEAVEFUNCTION` RTSP interleave writer.
    pub fwrite_rtp: CCallback,
    /// `CURLOPT_PROGRESSFUNCTION` (deprecated) progress callback.
    pub fprogress: CCallback,
    /// `CURLOPT_XFERINFOFUNCTION` progress callback.
    pub fxferinfo: CCallback,
    /// `CURLOPT_DEBUGFUNCTION` debug callback.
    pub fdebug: CCallback,
    /// `CURLOPT_IOCTLFUNCTION` (deprecated) ioctl callback.
    pub ioctl_func: CCallback,
    /// `CURLOPT_SEEKFUNCTION` seek callback.
    pub seek_func: CCallback,
    /// `CURLOPT_SOCKOPTFUNCTION` sockopt callback.
    pub fsockopt: CCallback,
    /// `CURLOPT_OPENSOCKETFUNCTION` open-socket callback.
    pub fopensocket: CCallback,
    /// `CURLOPT_CLOSESOCKETFUNCTION` close-socket callback.
    pub fclosesocket: CCallback,
    /// `CURLOPT_PREREQFUNCTION` pre-request callback.
    pub fprereq: CCallback,
    /// `CURLOPT_RESOLVER_START_FUNCTION` resolver-start callback.
    pub resolver_start: CCallback,
    /// `CURLOPT_SSH_KEYFUNCTION` SSH key callback.
    pub ssh_keyfunc: CCallback,
    /// `CURLOPT_SSH_HOSTKEYFUNCTION` SSH hostkey callback.
    pub ssh_hostkeyfunc: CCallback,
    /// `CURLOPT_CHUNK_BGN_FUNCTION` wildcard chunk-begin callback.
    pub chunk_bgn: CCallback,
    /// `CURLOPT_CHUNK_END_FUNCTION` wildcard chunk-end callback.
    pub chunk_end: CCallback,
    /// `CURLOPT_FNMATCH_FUNCTION` wildcard fnmatch callback.
    pub fnmatch: CCallback,
    /// `CURLOPT_TRAILERFUNCTION` trailing-header callback.
    pub trailer_callback: CCallback,
    /// `CURLOPT_HSTSREADFUNCTION` HSTS read callback.
    pub hsts_read: CCallback,
    /// `CURLOPT_HSTSWRITEFUNCTION` HSTS write callback.
    pub hsts_write: CCallback,

    // ---- authentication masks ----------------------------------------------
    /// `CURLOPT_HTTPAUTH` allowed auth methods (`CURLAUTH_*` bitmask).
    pub httpauth: u32,
    /// `CURLOPT_PROXYAUTH` allowed proxy auth methods.
    pub proxyauth: u32,
    /// IE-style digest marker for host auth (from `CURLAUTH_DIGEST_IE`).
    pub httpauth_iestyle: bool,
    /// IE-style digest marker for proxy auth.
    pub proxyauth_iestyle: bool,
    /// `CURLOPT_SOCKS5_AUTH` allowed SOCKS5 auth methods.
    pub socks5auth: u32,

    // ---- sizes, offsets and timeouts (`curl_off_t` / `timediff_t`) ---------
    /// `CURLOPT_POSTFIELDSIZE(_LARGE)`; `-1` means "use strlen".
    pub postfieldsize: i64,
    /// `CURLOPT_INFILESIZE(_LARGE)`; `-1` means unknown.
    pub filesize: i64,
    /// `CURLOPT_LOW_SPEED_LIMIT` bytes/second floor.
    pub low_speed_limit: i64,
    /// `CURLOPT_MAX_SEND_SPEED_LARGE` upload rate cap (bytes/s).
    pub max_send_speed: i64,
    /// `CURLOPT_MAX_RECV_SPEED_LARGE` download rate cap (bytes/s).
    pub max_recv_speed: i64,
    /// `CURLOPT_RESUME_FROM(_LARGE)` transfer resume offset.
    pub set_resume_from: i64,
    /// `CURLOPT_MAXFILESIZE(_LARGE)` download size cap.
    pub max_filesize: i64,
    /// `CURLOPT_TIMEOUT(_MS)` whole-transfer timeout (ms).
    pub timeout: i64,
    /// `CURLOPT_CONNECTTIMEOUT(_MS)` connect timeout (ms).
    pub connecttimeout: i64,
    /// `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`.
    pub happy_eyeballs_timeout: i64,
    /// `CURLOPT_SERVER_RESPONSE_TIMEOUT(_MS)`.
    pub server_response_timeout: i64,
    /// `CURLOPT_ACCEPTTIMEOUT_MS` FTP active-mode accept timeout.
    pub accepttimeout: i64,
    /// `CURLOPT_DNS_CACHE_TIMEOUT` (ms); `-1` = forever.
    pub dns_cache_timeout_ms: i64,
    /// `CURLOPT_UPKEEP_INTERVAL_MS` connection-upkeep interval.
    pub upkeep_interval_ms: i64,
    /// `CURLOPT_MAXAGE_CONN` max idle time for reuse (ms).
    pub conn_max_idle_ms: i64,
    /// `CURLOPT_MAXLIFETIME_CONN` max connection age for reuse (ms).
    pub conn_max_age_ms: i64,
    /// `CURLOPT_TIMEVALUE(_LARGE)` time to compare against.
    pub timevalue: i64,

    // ---- string lists (`struct curl_slist *`) ------------------------------
    /// `CURLOPT_HTTPHEADER` extra request headers.
    pub headers: Option<SList>,
    /// `CURLOPT_PROXYHEADER` extra CONNECT headers.
    pub proxyheaders: Option<SList>,
    /// `CURLOPT_TELNETOPTIONS` telnet options.
    pub telnet_options: Option<SList>,
    /// `CURLOPT_RESOLVE` resolver cache overrides.
    pub resolve: Option<SList>,
    /// `CURLOPT_CONNECT_TO` connect-to overrides.
    pub connect_to: Option<SList>,
    /// `CURLOPT_HTTP200ALIASES` HTTP/200 aliases.
    pub http200aliases: Option<SList>,
    /// `CURLOPT_QUOTE` FTP/SFTP commands run after connect.
    pub quote: Option<SList>,
    /// `CURLOPT_POSTQUOTE` FTP/SFTP commands run after transfer.
    pub postquote: Option<SList>,
    /// `CURLOPT_PREQUOTE` FTP/SFTP commands run before transfer.
    pub prequote: Option<SList>,
    /// `CURLOPT_MAIL_RCPT` SMTP recipients.
    pub mail_rcpt: Option<SList>,

    // ---- string / blob / binary storage ------------------------------------
    /// String options, indexed by [`StrId`].
    pub strings: Vec<Option<String>>,
    /// Blob options, indexed by [`BlobId`].
    pub blobs: Vec<Option<Blob>>,
    /// `CURLOPT_COPYPOSTFIELDS` owned binary POST body.
    pub copypostfields: Option<Vec<u8>>,

    // ---- handle-state file/command lists -----------------------------------
    // curl keeps these on `data->state` (not in `set`), because the relevant
    // options append to a list rather than replacing a single value. The easy
    // layer replays them into the live cookie/HSTS engines. They are modeled
    // here so the typed setter surface remains the single source of truth.
    /// `CURLOPT_COOKIEFILE` files to read cookies from (`state.cookielist`).
    pub cookiefiles: Vec<String>,
    /// `CURLOPT_COOKIELIST` cookie commands/lines to apply (verbs + raw lines).
    pub cookie_commands: Vec<String>,
    /// `CURLOPT_HSTS` files to read/persist HSTS entries (`state.hstslist`).
    pub hstsfiles: Vec<String>,

    // ---- URL handle --------------------------------------------------------
    /// `CURLOPT_CURLU` pre-parsed URL handle, **resolved** to an owned,
    /// independent [`CurlUrl`] clone.
    ///
    /// curl's `CURLOPT_CURLU` contract is store-only: `lib/setopt.c` keeps the
    /// caller's `CURLU *` pointer (`s->uh = (CURLU *)ptr;`) and only reads it at
    /// perform time. The raw caller pointer therefore lives in [`Self::uh_ptr`];
    /// the FFI layer dereferences it and deposits an owned clone here just
    /// before a transfer is driven (see `curl-rs-ffi`'s `resolve_curlu`). The
    /// transfer engine, in turn, reads this resolved handle (see
    /// `Easy::pre_perform`). When the core is driven without the FFI (e.g. unit
    /// tests set this field directly) `uh_ptr` stays `NULL` and this field is
    /// authoritative on its own.
    pub uh: Option<CurlUrl>,

    /// The raw `CURLU *` address supplied to `CURLOPT_CURLU`, stored verbatim
    /// (`0` = `NULL`) without being dereferenced — the safe equivalent of curl's
    /// `s->uh = (CURLU *)ptr;`.
    ///
    /// Holding the address is a safe operation; only the FFI layer dereferences
    /// it (at perform time, into [`Self::uh`]). Deferring the dereference is what
    /// makes `curl_easy_setopt(CURLOPT_CURLU, ptr)` honour curl's store-only
    /// contract: a caller (notably `tests/libtest/lib1521`) may pass a dummy
    /// pointer that is never read, and setopt must accept it without touching it.
    pub uh_ptr: CDataPtr,

    // ---- shared state ------------------------------------------------------
    /// `CURLOPT_SHARE` attached shared-state handle (`data->share` in curl).
    pub share: Option<Share>,

    // ---- TLS configuration -------------------------------------------------
    /// Host TLS config (`set.ssl`).
    pub ssl: SslConfig,
    /// Proxy TLS config (`set.proxy_ssl`).
    pub proxy_ssl: SslConfig,
    /// General TLS config (`set.general_ssl`).
    pub general_ssl: SslGeneralConfig,

    // ---- HTTP/2 + HTTP/3 priority ------------------------------------------
    /// Stream priority / dependency (`set.priority`).
    pub priority: Priority,

    // ---- 32-bit unsigned settings ------------------------------------------
    /// `CURLOPT_BUFFERSIZE` receive buffer size.
    pub buffer_size: u32,
    /// `CURLOPT_UPLOAD_BUFFERSIZE` send buffer size.
    pub upload_buffer_size: u32,
    /// `CURLOPT_SSH_AUTH_TYPES` allowed SSH auth methods.
    pub ssh_auth_types: u32,
    /// `CURLOPT_NEW_DIRECTORY_PERMS` mode for created remote dirs.
    pub new_directory_perms: u32,
    /// `CURLOPT_NEW_FILE_PERMS` mode for created remote files.
    pub new_file_perms: u32,
    /// `CURLOPT_ADDRESS_SCOPE` IPv6 scope id.
    pub scope_id: u32,
    /// `CURLOPT_PROTOCOLS(_STR)` allowed protocol bitmask.
    pub allowed_protocols: u32,
    /// `CURLOPT_REDIR_PROTOCOLS(_STR)` allowed redirect-protocol bitmask.
    pub redir_protocols: u32,
    /// `CURLOPT_MAXCONNECTS` connection-cache size.
    pub maxconnects: u32,
    /// `CURLOPT_RTSP_CLIENT_CSEQ` next client CSeq.
    pub rtsp_next_client_cseq: u32,
    /// `CURLOPT_RTSP_SERVER_CSEQ` next server CSeq.
    pub rtsp_next_server_cseq: u32,

    // ---- TCP keep-alive (`int`) --------------------------------------------
    /// `CURLOPT_TCP_KEEPIDLE` idle seconds before probing.
    pub tcp_keepidle: i32,
    /// `CURLOPT_TCP_KEEPINTVL` seconds between probes.
    pub tcp_keepintvl: i32,
    /// `CURLOPT_TCP_KEEPCNT` max probes.
    pub tcp_keepcnt: i32,

    // ---- 16-bit unsigned settings ------------------------------------------
    /// `CURLOPT_PROXYPORT`; `0` means "use default/derived".
    pub proxyport: u16,
    /// `CURLOPT_PORT`; `0` means "use default".
    pub use_port: u16,
    /// `CURLOPT_LOCALPORT` local bind port.
    pub localport: u16,
    /// `CURLOPT_LOCALPORTRANGE` local bind port range.
    pub localportrange: u16,
    /// `CURLOPT_EXPECT_100_TIMEOUT_MS`.
    pub expect_100_timeout: u16,
    /// `CURLOPT_LOW_SPEED_TIME` seconds.
    pub low_speed_time: u16,
    /// `CURLOPT_TFTP_BLKSIZE`; `0` = default.
    pub tftp_blksize: u16,

    // ---- 8-bit / enum settings ---------------------------------------------
    /// `CURLOPT_PROXYTYPE` (`curl_proxytype`).
    pub proxytype: u8,
    /// `CURLOPT_FTP_FILEMETHOD` (`curl_ftpfile`).
    pub ftp_filemethod: u8,
    /// `CURLOPT_FTPSSLAUTH` (`curl_ftpauth`).
    pub ftpsslauth: u8,
    /// `CURLOPT_FTP_SSL_CCC` (`curl_ftpccc`).
    pub ftp_ccc: u8,
    /// `CURLOPT_NETRC` (`CURL_NETRC_OPTION`).
    pub use_netrc: u8,
    /// `CURLOPT_FTP_CREATE_MISSING_DIRS` (0..=2).
    pub ftp_create_missing_dirs: u8,
    /// `CURLOPT_USE_SSL` (`curl_usessl`).
    pub use_ssl: u8,
    /// `CURLOPT_TIMECONDITION` (`curl_TimeCond`).
    pub timecondition: u8,
    /// The HTTP request method shaped by the method options.
    pub method: HttpReq,
    /// `CURLOPT_HTTP_VERSION` requested version (`CURL_HTTP_VERSION_*`).
    pub httpwant: u8,
    /// `CURLOPT_IPRESOLVE` (0=any, 1=v4, 2=v6).
    pub ipver: u8,
    /// `CURLOPT_UPLOAD_FLAGS` bitmask.
    pub upload_flags: u8,
    /// `CURLOPT_GSSAPI_DELEGATION` policy.
    pub gssapi_delegation: u8,
    /// `CURLOPT_FOLLOWLOCATION` follow mode (`CURLFOLLOW_*`).
    pub http_follow_mode: u8,
    /// `CURLOPT_RTSP_REQUEST` request kind (internal `Curl_RtspReq`, 0..=11).
    pub rtspreq: u8,

    // ---- signed 32-bit settings --------------------------------------------
    /// `CURLOPT_MAXREDIRS`; `-1` means unlimited.
    pub maxredirs: i32,

    // ---- boolean (`BIT()`) settings ----------------------------------------
    /// `CURLOPT_CONNECT_ONLY` (level 1).
    pub connect_only: bool,
    /// `CURLOPT_CONNECT_ONLY` level 2 (websocket connect-only).
    pub connect_only_ws: bool,
    /// `CURLOPT_MAIL_RCPT_ALLOWFAILS`.
    pub mail_rcpt_allowfails: bool,
    /// `CURLOPT_MIME_OPTIONS` form-escape bit.
    pub mime_formescape: bool,
    /// Whether `CURLOPT_READFUNCTION` was set to a non-NULL callback.
    pub is_fread_set: bool,
    /// `CURLOPT_TFTP_NO_OPTIONS`.
    pub tftp_no_options: bool,
    /// `CURLOPT_HEADEROPT` separate-headers bit.
    pub sep_headers: bool,
    /// `CURLOPT_COOKIESESSION`.
    pub cookiesession: bool,
    /// `CURLOPT_CRLF` line-ending conversion.
    pub crlf: bool,
    /// `CURLOPT_SSH_COMPRESSION`.
    pub ssh_compression: bool,
    /// `CURLOPT_QUICK_EXIT`.
    pub quick_exit: bool,
    /// `CURLOPT_FILETIME`.
    pub get_filetime: bool,
    /// `CURLOPT_HTTPPROXYTUNNEL`.
    pub tunnel_thru_httpproxy: bool,
    /// `CURLOPT_TRANSFERTEXT` (ASCII FTP transfers).
    pub prefer_ascii: bool,
    /// `CURLOPT_APPEND` (upload append).
    pub remote_append: bool,
    /// `CURLOPT_DIRLISTONLY`.
    pub list_only: bool,
    /// `CURLOPT_FTPPORT` was given (use active FTP).
    pub ftp_use_port: bool,
    /// `CURLOPT_FTP_USE_EPSV`.
    pub ftp_use_epsv: bool,
    /// `CURLOPT_FTP_USE_EPRT`.
    pub ftp_use_eprt: bool,
    /// `CURLOPT_FTP_USE_PRET`.
    pub ftp_use_pret: bool,
    /// `CURLOPT_FTP_SKIP_PASV_IP`.
    pub ftp_skip_ip: bool,
    /// `CURLOPT_WILDCARDMATCH`.
    pub wildcard_enabled: bool,
    /// `CURLOPT_FAILONERROR`.
    pub http_fail_on_error: bool,
    /// `CURLOPT_KEEP_SENDING_ON_ERROR`.
    pub http_keep_sending_on_error: bool,
    /// `CURLOPT_TRANSFER_ENCODING`.
    pub http_transfer_encoding: bool,
    /// `CURLOPT_UNRESTRICTED_AUTH`.
    pub allow_auth_to_other_hosts: bool,
    /// `CURLOPT_HEADER` (include headers in body output).
    pub include_header: bool,
    /// `CURLOPT_AUTOREFERER`.
    pub http_auto_referer: bool,
    /// `CURLOPT_NOBODY`.
    pub opt_no_body: bool,
    /// `CURLOPT_VERBOSE`.
    pub verbose: bool,
    /// `CURLOPT_NOPROGRESS` — hide the progress meter (curl `progress.hide`).
    pub noprogress: bool,
    /// `CURLOPT_FORBID_REUSE`.
    pub reuse_forbid: bool,
    /// `CURLOPT_FRESH_CONNECT`.
    pub reuse_fresh: bool,
    /// `CURLOPT_NOSIGNAL`.
    pub no_signal: bool,
    /// `CURLOPT_TCP_NODELAY`.
    pub tcp_nodelay: bool,
    /// `CURLOPT_IGNORE_CONTENT_LENGTH`.
    pub ignorecl: bool,
    /// `CURLOPT_HTTP_TRANSFER_DECODING` disabled (note: stored inverted).
    pub http_te_skip: bool,
    /// `CURLOPT_HTTP_CONTENT_DECODING` disabled (note: stored inverted).
    pub http_ce_skip: bool,
    /// `CURLOPT_PROXY_TRANSFER_MODE`.
    pub proxy_transfer_mode: bool,
    /// `CURLOPT_SOCKS5_GSSAPI_NEC`.
    pub socks5_gssapi_nec: bool,
    /// `CURLOPT_SASL_IR`.
    pub sasl_ir: bool,
    /// `CURLOPT_TCP_KEEPALIVE`.
    pub tcp_keepalive: bool,
    /// `CURLOPT_TCP_FASTOPEN`.
    pub tcp_fastopen: bool,
    /// `CURLOPT_SSL_ENABLE_ALPN`.
    pub ssl_enable_alpn: bool,
    /// `CURLOPT_PATH_AS_IS`.
    pub path_as_is: bool,
    /// `CURLOPT_PIPEWAIT`.
    pub pipewait: bool,
    /// `CURLOPT_SUPPRESS_CONNECT_HEADERS`.
    pub suppress_connect_headers: bool,
    /// `CURLOPT_DNS_SHUFFLE_ADDRESSES`.
    pub dns_shuffle_addresses: bool,
    /// `CURLOPT_HAPROXYPROTOCOL`.
    pub haproxyprotocol: bool,
    /// `CURLOPT_ABSTRACT_UNIX_SOCKET` (vs `CURLOPT_UNIX_SOCKET_PATH`).
    pub abstract_unix_socket: bool,
    /// `CURLOPT_DISALLOW_USERNAME_IN_URL`.
    pub disallow_username_in_url: bool,
    /// `CURLOPT_DOH_URL` was set (DoH enabled).
    pub doh: bool,
    /// `CURLOPT_DOH_SSL_VERIFYPEER`.
    pub doh_verifypeer: bool,
    /// `CURLOPT_DOH_SSL_VERIFYHOST`.
    pub doh_verifyhost: bool,
    /// `CURLOPT_DOH_SSL_VERIFYSTATUS`.
    pub doh_verifystatus: bool,
    /// `CURLOPT_HTTP09_ALLOWED`.
    pub http09_allowed: bool,
    /// `CURLOPT_WS_OPTIONS` raw-mode bit.
    pub ws_raw_mode: bool,
    /// `CURLOPT_WS_OPTIONS` no-auto-pong bit.
    pub ws_no_auto_pong: bool,
    /// `CURLOPT_POSTREDIR` keep POST after 301.
    pub post301: bool,
    /// `CURLOPT_POSTREDIR` keep POST after 302.
    pub post302: bool,
    /// `CURLOPT_POSTREDIR` keep POST after 303.
    pub post303: bool,
    /// `CURLOPT_COOKIEJAR` set: the cookie engine is enabled for writing.
    pub cookie_engine: bool,
    /// `CURLOPT_HSTS_CTRL` requested the HSTS engine be enabled
    /// (`CURLHSTS_ENABLE`). The easy-handle layer materialises the engine.
    pub hsts_enable: bool,
    /// `CURLOPT_ALTSVC_CTRL` flags (`CURLALTSVC_*`); `0` means unset. The
    /// easy-handle layer materialises the Alt-Svc cache with these flags.
    pub altsvc_ctrl: i64,
}

impl Default for UserDefined {
    /// Establishes the same initial option values as curl's
    /// `Curl_init_userdefined` (`lib/url.c`). Anything not explicitly listed
    /// here begins zeroed/empty/`false`, exactly as curl relies on the
    /// `calloc` of the handle.
    fn default() -> Self {
        UserDefined {
            // Opaque application pointers — all NULL ("use the default stream"
            // for out/in_set/err, "no userdata" for the rest).
            out: CDataPtr::NULL,
            in_set: CDataPtr::NULL,
            writeheader: CDataPtr::NULL,
            err: CDataPtr::NULL,
            debugdata: CDataPtr::NULL,
            progress_client: CDataPtr::NULL,
            seek_client: CDataPtr::NULL,
            ioctl_client: CDataPtr::NULL,
            sockopt_client: CDataPtr::NULL,
            opensocket_client: CDataPtr::NULL,
            closesocket_client: CDataPtr::NULL,
            prereq_userp: CDataPtr::NULL,
            resolver_start_client: CDataPtr::NULL,
            interleave_client: CDataPtr::NULL,
            wildcardptr: CDataPtr::NULL,
            fnmatch_data: CDataPtr::NULL,
            ssh_keyfunc_userp: CDataPtr::NULL,
            ssh_hostkeyfunc_userp: CDataPtr::NULL,
            hsts_read_userp: CDataPtr::NULL,
            hsts_write_userp: CDataPtr::NULL,
            trailer_data: CDataPtr::NULL,
            private_data: CDataPtr::NULL,
            errorbuffer: CDataPtr::NULL,
            postfields: None,
            httppost: CDataPtr::NULL,
            mimepost: CDataPtr::NULL,
            mime_body: None,
            mime_content_type: None,

            // Callback pointers — all NULL; curl substitutes built-in
            // fwrite/fread shims at transfer time when these stay unset.
            fwrite_func: CCallback::NULL,
            fread_func_set: CCallback::NULL,
            fwrite_header: CCallback::NULL,
            fwrite_rtp: CCallback::NULL,
            fprogress: CCallback::NULL,
            fxferinfo: CCallback::NULL,
            fdebug: CCallback::NULL,
            ioctl_func: CCallback::NULL,
            seek_func: CCallback::NULL,
            fsockopt: CCallback::NULL,
            fopensocket: CCallback::NULL,
            fclosesocket: CCallback::NULL,
            fprereq: CCallback::NULL,
            resolver_start: CCallback::NULL,
            ssh_keyfunc: CCallback::NULL,
            ssh_hostkeyfunc: CCallback::NULL,
            chunk_bgn: CCallback::NULL,
            chunk_end: CCallback::NULL,
            fnmatch: CCallback::NULL,
            trailer_callback: CCallback::NULL,
            hsts_read: CCallback::NULL,
            hsts_write: CCallback::NULL,

            // Authentication: host + proxy default to Basic; SOCKS5 defaults to
            // Basic|GSSAPI (curl: `CURLAUTH_BASIC` and `BASIC|GSSAPI`).
            httpauth: CURLAUTH_BASIC,
            proxyauth: CURLAUTH_BASIC,
            httpauth_iestyle: false,
            proxyauth_iestyle: false,
            socks5auth: CURLAUTH_BASIC | CURLAUTH_GSSAPI,

            // Sizes/offsets: filesize and postfieldsize start "unknown" (-1).
            postfieldsize: -1,
            filesize: -1,
            low_speed_limit: 0,
            max_send_speed: 0,
            max_recv_speed: 0,
            set_resume_from: 0,
            max_filesize: 0,
            timeout: 0,
            connecttimeout: 0,
            happy_eyeballs_timeout: CURL_HET_DEFAULT,
            server_response_timeout: 0,
            accepttimeout: 0,
            dns_cache_timeout_ms: 60_000,
            upkeep_interval_ms: CURL_UPKEEP_INTERVAL_DEFAULT,
            conn_max_idle_ms: 118_000,
            conn_max_age_ms: 0,
            timevalue: 0,

            // String lists — empty.
            headers: None,
            proxyheaders: None,
            telnet_options: None,
            resolve: None,
            connect_to: None,
            http200aliases: None,
            quote: None,
            postquote: None,
            prequote: None,
            mail_rcpt: None,

            // String/blob/binary storage sized to the id enums.
            strings: vec![None; StrId::COUNT],
            blobs: vec![None; BlobId::COUNT],
            copypostfields: None,
            cookiefiles: Vec::new(),
            cookie_commands: Vec::new(),
            hstsfiles: Vec::new(),

            uh: None,
            uh_ptr: CDataPtr::NULL,
            share: None,

            // TLS: validation ON by default for host TLS; proxy TLS likewise.
            ssl: SslConfig::default(),
            proxy_ssl: SslConfig::default(),
            general_ssl: SslGeneralConfig::default(),

            priority: Priority::default(),

            // 32-bit unsigned settings.
            buffer_size: CURL_READ_BUFFER_DEFAULT,
            upload_buffer_size: CURL_UPLOAD_BUFFER_DEFAULT,
            ssh_auth_types: CURLSSH_AUTH_DEFAULT,
            new_directory_perms: 0o755,
            new_file_perms: 0o644,
            scope_id: 0,
            allowed_protocols: CURLPROTO_ALL,
            redir_protocols: CURLPROTO_REDIR,
            maxconnects: CURL_DEFAULT_MAXCONNECTS,
            rtsp_next_client_cseq: 0,
            rtsp_next_server_cseq: 0,

            // TCP keep-alive defaults (curl: 60/60/9).
            tcp_keepidle: 60,
            tcp_keepintvl: 60,
            tcp_keepcnt: 9,

            // 16-bit settings.
            proxyport: 0,
            use_port: 0,
            localport: 0,
            localportrange: 0,
            expect_100_timeout: 1000,
            low_speed_time: 0,
            tftp_blksize: 0,

            // Enum/8-bit settings.
            proxytype: CURLPROXY_HTTP,
            ftp_filemethod: CURL_FTPMETHOD_MULTICWD,
            ftpsslauth: 0,
            ftp_ccc: 0,
            use_netrc: 0,
            ftp_create_missing_dirs: 0,
            use_ssl: 0,
            timecondition: 0,
            method: HttpReq::Get,
            httpwant: CURL_HTTP_VERSION_NONE as u8,
            ipver: 0,
            upload_flags: 0,
            gssapi_delegation: 0,
            http_follow_mode: 0,
            // curl initialises the RTSP request to OPTIONS, not NONE
            // (`set->rtspreq = RTSPREQ_OPTIONS;` in `Curl_init_userdefined`,
            // lib/url.c:367). The internal value equals the public
            // `CURL_RTSPREQ_OPTIONS` (1), since `set_rtsp_request` is identity.
            // Preserving this default is required for RTSP behavioral parity
            // (e.g. `curl rtsp://host/` issues OPTIONS without an explicit
            // `CURLOPT_RTSP_REQUEST`).
            rtspreq: CURL_RTSPREQ_OPTIONS as u8,

            maxredirs: 30,

            // Boolean flags. Only those curl initialises to a non-zero value
            // are set true here; everything else stays false.
            connect_only: false,
            connect_only_ws: false,
            mail_rcpt_allowfails: false,
            mime_formescape: false,
            is_fread_set: false,
            tftp_no_options: false,
            sep_headers: true,
            cookiesession: false,
            crlf: false,
            ssh_compression: false,
            quick_exit: false,
            get_filetime: false,
            tunnel_thru_httpproxy: false,
            prefer_ascii: false,
            remote_append: false,
            list_only: false,
            ftp_use_port: false,
            ftp_use_epsv: true,
            ftp_use_eprt: true,
            ftp_use_pret: false,
            ftp_skip_ip: true,
            wildcard_enabled: false,
            http_fail_on_error: false,
            http_keep_sending_on_error: false,
            http_transfer_encoding: false,
            allow_auth_to_other_hosts: false,
            include_header: false,
            http_auto_referer: false,
            opt_no_body: false,
            verbose: false,
            noprogress: false,
            reuse_forbid: false,
            reuse_fresh: false,
            no_signal: false,
            tcp_nodelay: true,
            ignorecl: false,
            http_te_skip: false,
            http_ce_skip: false,
            proxy_transfer_mode: false,
            socks5_gssapi_nec: false,
            sasl_ir: false,
            tcp_keepalive: false,
            tcp_fastopen: false,
            ssl_enable_alpn: true,
            path_as_is: false,
            pipewait: false,
            suppress_connect_headers: false,
            dns_shuffle_addresses: false,
            haproxyprotocol: false,
            abstract_unix_socket: false,
            disallow_username_in_url: false,
            doh: false,
            doh_verifypeer: true,
            doh_verifyhost: true,
            doh_verifystatus: false,
            http09_allowed: false,
            ws_raw_mode: false,
            ws_no_auto_pong: false,
            post301: false,
            post302: false,
            post303: false,
            cookie_engine: false,
            hsts_enable: false,
            altsvc_ctrl: 0,
        }
    }
}

impl UserDefined {
    /// Creates a settings block populated with curl's documented defaults.
    ///
    /// This is the safe analogue of curl's `Curl_init_userdefined`; the
    /// easy-handle layer calls it during handle construction.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the currently stored value for a string option, if any.
    ///
    /// Used by tests and by the engine layers that consume the settings.
    #[must_use]
    pub fn str(&self, id: StrId) -> Option<&str> {
        self.strings[id.idx()].as_deref()
    }

    /// Returns the currently stored value for a blob option, if any.
    #[must_use]
    pub fn blob(&self, id: BlobId) -> Option<&Blob> {
        self.blobs[id.idx()].as_ref()
    }

    /// Stores (or clears, when `value` is `None`) a string option.
    fn set_str(&mut self, id: StrId, value: Option<String>) {
        self.strings[id.idx()] = value;
    }

    /// Stores (or clears, when `value` is `None`) a blob option.
    fn set_blob(&mut self, id: BlobId, value: Option<Blob>) {
        self.blobs[id.idx()] = value;
    }
}

// ===========================================================================
// Validation / parsing helpers (mirroring the static helpers in lib/setopt.c)
// ===========================================================================

/// Reject `value` below `below_error`, otherwise clamp it into `[min, max]`.
///
/// Faithful port of curl's `value_range` (`lib/setopt.c`): the order of checks
/// means a single value is never both clamped up and down.
fn value_range(value: i64, below_error: i64, min: i64, max: i64) -> Result<i64> {
    if value < below_error {
        Err(CurlError::BadFunctionArgument)
    } else if value < min {
        Ok(min)
    } else if value > max {
        Ok(max)
    } else {
        Ok(value)
    }
}

/// Convert a timeout expressed in seconds to milliseconds, rejecting negatives
/// and saturating at the `timediff_t` maximum (`setopt_set_timeout_sec`).
fn timeout_sec_to_ms(secs: i64) -> Result<i64> {
    if secs < 0 {
        return Err(CurlError::BadFunctionArgument);
    }
    // `timediff_t` is `i64`; saturate the `* 1000` to mirror curl's clamp to
    // `TIMEDIFF_T_MAX` rather than overflowing.
    Ok(secs.saturating_mul(1000))
}

/// Validate a timeout already expressed in milliseconds, rejecting negatives
/// (`setopt_set_timeout_ms`).
fn timeout_ms(ms: i64) -> Result<i64> {
    if ms < 0 {
        Err(CurlError::BadFunctionArgument)
    } else {
        Ok(ms)
    }
}

/// Decompose a TLS-options bitmask onto an [`SslConfig`] exactly as curl's
/// `set_ssl_options` does. The low byte is preserved as `ssl_options`.
fn set_ssl_options(ssl: &mut SslConfig, arg: i64) {
    ssl.primary.ssl_options = (arg & 0xff) as u8;
    ssl.enable_beast = (arg & CURLSSLOPT_ALLOW_BEAST) != 0;
    ssl.no_revoke = (arg & CURLSSLOPT_NO_REVOKE) != 0;
    ssl.no_partialchain = (arg & CURLSSLOPT_NO_PARTIALCHAIN) != 0;
    ssl.revoke_best_effort = (arg & CURLSSLOPT_REVOKE_BEST_EFFORT) != 0;
    ssl.native_ca_store = (arg & CURLSSLOPT_NATIVE_CA) != 0;
    ssl.auto_client_cert = (arg & CURLSSLOPT_AUTO_CLIENT_CERT) != 0;
    ssl.earlydata = (arg & CURLSSLOPT_EARLYDATA) != 0;
}

/// Apply `CURLOPT_SSLVERSION` / `CURLOPT_PROXY_SSLVERSION` semantics onto a
/// primary TLS config. Port of `Curl_setopt_SSLVERSION` (`lib/setopt.c`):
/// the low 16 bits select the minimum version, the high 16 bits the maximum.
fn set_sslversion(primary: &mut SslPrimaryConfig, arg: i64) -> Result<()> {
    let mut version = arg & 0xffff;
    let version_max = ((arg as u64) & 0xffff_0000) as i64;
    if version < CURL_SSLVERSION_DEFAULT
        || version == CURL_SSLVERSION_SSLV2
        || version == CURL_SSLVERSION_SSLV3
        || version >= CURL_SSLVERSION_LAST
        || !(CURL_SSLVERSION_MAX_NONE..CURL_SSLVERSION_MAX_LAST).contains(&version_max)
    {
        return Err(CurlError::BadFunctionArgument);
    }
    if version == CURL_SSLVERSION_DEFAULT {
        version = CURL_SSLVERSION_TLSV1_2;
    }
    primary.version = version as u8;
    primary.version_max = version_max as u32;
    Ok(())
}

/// Validate a requested HTTP version and return the stored `httpwant` byte.
/// Port of `setopt_HTTP_VERSION` (`lib/setopt.c`): HTTP/2 and HTTP/3 values are
/// only accepted when the corresponding feature is built in.
fn set_http_version(arg: i64) -> Result<u8> {
    match arg {
        CURL_HTTP_VERSION_NONE | CURL_HTTP_VERSION_1_0 | CURL_HTTP_VERSION_1_1 => {}
        CURL_HTTP_VERSION_2_0 | CURL_HTTP_VERSION_2TLS | CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE
            if cfg!(feature = "http2") => {}
        CURL_HTTP_VERSION_3 | CURL_HTTP_VERSION_3ONLY if cfg!(feature = "http3") => {}
        _ => {
            return if arg < CURL_HTTP_VERSION_NONE {
                Err(CurlError::BadFunctionArgument)
            } else {
                Err(CurlError::UnsupportedProtocol)
            };
        }
    }
    Ok(arg as u8)
}

/// Apply `CURLOPT_HTTPAUTH` / `CURLOPT_PROXYAUTH` semantics. Port of curl's
/// `httpauth`: the IE-digest marker is split off, unsupported schemes are
/// masked out per feature, and an all-unsupported request yields
/// `CURLE_NOT_BUILT_IN`.
fn apply_httpauth(set: &mut UserDefined, proxy: bool, mut auth: u32) -> Result<()> {
    // CURLAUTH_NONE == 0.
    if auth != 0 {
        let iestyle = (auth & CURLAUTH_DIGEST_IE) != 0;
        if proxy {
            set.proxyauth_iestyle = iestyle;
        } else {
            set.httpauth_iestyle = iestyle;
        }
        if auth & CURLAUTH_DIGEST_IE != 0 {
            auth |= CURLAUTH_DIGEST; // set the standard digest bit
            auth &= !CURLAUTH_DIGEST_IE; // unset the IE digest marker
        }
        // Switch off schemes that are not built in.
        if !cfg!(feature = "ntlm") {
            auth &= !CURLAUTH_NTLM;
        }
        if !cfg!(feature = "spnego") {
            auth &= !CURLAUTH_NEGOTIATE;
        }
        // Any auth bit below CURLAUTH_ONLY (bit 31) still set?
        let mut authbits = false;
        for bit in 0..31u32 {
            if auth & (1u32 << bit) != 0 {
                authbits = true;
                break;
            }
        }
        if !authbits {
            return Err(CurlError::NotBuiltIn);
        }
    }
    if proxy {
        set.proxyauth = auth;
    } else {
        set.httpauth = auth;
    }
    Ok(())
}

/// Map a single URL scheme token to its `CURLPROTO_*` bit, or `None` when the
/// scheme is not built into this implementation (RTMP variants are out of
/// scope per the migration plan and therefore unrecognized).
fn scheme_to_proto(token: &str) -> Option<u32> {
    // Scheme matching is case-insensitive, like curl's `Curl_getn_scheme`.
    let bit = match token.to_ascii_lowercase().as_str() {
        "http" => 1 << 0,
        "https" => 1 << 1,
        "ftp" => 1 << 2,
        "ftps" => 1 << 3,
        "scp" => 1 << 4,
        "sftp" => 1 << 5,
        "telnet" => 1 << 6,
        "ldap" => 1 << 7,
        "ldaps" => 1 << 8,
        "dict" => 1 << 9,
        "file" => 1 << 10,
        "tftp" => 1 << 11,
        "imap" => 1 << 12,
        "imaps" => 1 << 13,
        "pop3" => 1 << 14,
        "pop3s" => 1 << 15,
        "smtp" => 1 << 16,
        "smtps" => 1 << 17,
        "rtsp" => 1 << 18,
        "gopher" => 1 << 25,
        "smb" => 1 << 26,
        "smbs" => 1 << 27,
        "mqtt" => 1 << 28,
        "gophers" => 1 << 29,
        "ws" => 1 << 30,
        "wss" => 1u32 << 31,
        _ => return None,
    };
    Some(bit)
}

/// Parse a comma-separated protocol list into a bitmask. Port of curl's
/// `protocol2num`: `"all"` enables everything, an empty result or unknown
/// scheme is rejected.
fn protocol2num(str_val: Option<&str>) -> Result<u32> {
    let s = str_val.ok_or(CurlError::BadFunctionArgument)?;
    if s.eq_ignore_ascii_case("all") {
        return Ok(CURLPROTO_ALL);
    }
    let mut val: u32 = 0;
    for token in s.split(',') {
        if token.is_empty() {
            // curl skips zero-length tokens (e.g. trailing comma).
            continue;
        }
        match scheme_to_proto(token) {
            Some(bit) => val |= bit,
            None => return Err(CurlError::UnsupportedProtocol),
        }
    }
    if val == 0 {
        return Err(CurlError::BadFunctionArgument);
    }
    Ok(val)
}

/// Split a `user[:password]` login string. Port of `Curl_parse_login_details`
/// used with `optionsp == NULL`: the user portion is always present (possibly
/// empty), and the password is present only when a `:` separator exists.
fn parse_login_details(login: &str) -> (Option<String>, Option<String>) {
    match login.find(':') {
        Some(idx) => (
            Some(login[..idx].to_string()),
            Some(login[idx + 1..].to_string()),
        ),
        None => (Some(login.to_string()), None),
    }
}

/// Decompose a `CURLOPT_INTERFACE` string into `(device, interface, host)`.
/// Faithful port of `Curl_parse_interface` (`lib/cf-socket.c`), which is not a
/// declared dependency and is therefore re-implemented here.
#[allow(clippy::type_complexity)]
fn parse_interface(input: &str) -> Result<(Option<String>, Option<String>, Option<String>)> {
    if input.len() > 512 {
        return Err(CurlError::BadFunctionArgument);
    }
    if let Some(rest) = input.strip_prefix("if!") {
        if rest.is_empty() {
            return Err(CurlError::BadFunctionArgument);
        }
        return Ok((None, Some(rest.to_string()), None));
    }
    if let Some(rest) = input.strip_prefix("host!") {
        if rest.is_empty() {
            return Err(CurlError::BadFunctionArgument);
        }
        return Ok((None, None, Some(rest.to_string())));
    }
    if let Some(rest) = input.strip_prefix("ifhost!") {
        // The interface part may be empty, but the host part must not be.
        return match rest.split_once('!') {
            Some((iface, host)) if !host.is_empty() => {
                Ok((None, Some(iface.to_string()), Some(host.to_string())))
            }
            _ => Err(CurlError::BadFunctionArgument),
        };
    }
    if input.is_empty() {
        return Err(CurlError::BadFunctionArgument);
    }
    Ok((Some(input.to_string()), None, None))
}

/// Validate a public `CURL_RTSPREQ_*` value and return the internal request
/// discriminant. The public constants (1..=11) map 1:1 onto the internal
/// `Curl_RtspReq` values, so the port reduces to a range check
/// (`setopt_RTSP_REQUEST`).
fn set_rtsp_request(arg: i64) -> Result<u8> {
    if (CURL_RTSPREQ_OPTIONS..=CURL_RTSPREQ_RECEIVE).contains(&arg) {
        Ok(arg as u8)
    } else {
        Err(CurlError::BadFunctionArgument)
    }
}

/// Build the `Accept-Encoding` value that enumerates every content encoding
/// this build supports, mirroring `Curl_get_content_encodings`: the order is
/// `deflate, gzip, br, zstd` with Brotli and Zstandard gated by feature.
fn all_content_encodings() -> String {
    let mut parts: Vec<&str> = vec!["deflate", "gzip"];
    if cfg!(feature = "brotli") {
        parts.push("br");
    }
    if cfg!(feature = "zstd") {
        parts.push("zstd");
    }
    parts.join(", ")
}

// ===========================================================================
// Central dispatch — the safe equivalent of `Curl_vsetopt` (lib/setopt.c)
// ===========================================================================

/// Return `Ok(())` when `built_in` is true, otherwise [`CurlError::NotBuiltIn`].
///
/// Used to honor the documented contract that an option whose backing Cargo
/// feature is disabled reports `CURLE_NOT_BUILT_IN`. The argument is a
/// `cfg!(feature = "…")` constant, so the disabled branch is a trivial early
/// return that still compiles under `--no-default-features`.
#[inline]
fn require_feature(built_in: bool) -> Result<()> {
    if built_in {
        Ok(())
    } else {
        Err(CurlError::NotBuiltIn)
    }
}

/// curl's `!!arg` idiom: any non-zero value is "enabled".
#[inline]
fn enabled_i(arg: i64) -> bool {
    arg != 0
}

/// Apply a single option to a settings block.
///
/// This is the typed core of `curl_easy_setopt`: the FFI crate marshals the C
/// variadic trailing argument into the [`OptionValue`] matching `opt`'s
/// `CURLOPTTYPE_*` group, then calls here. Routing mirrors `Curl_vsetopt`:
/// the option's type group selects the family handler.
///
/// # Errors
///
/// Returns [`CurlError::UnknownOption`] for ids this build does not handle,
/// [`CurlError::BadFunctionArgument`] for out-of-range or malformed values, and
/// [`CurlError::NotBuiltIn`] for options whose backing feature is disabled.
pub fn apply(set: &mut UserDefined, opt: CurlOption, val: OptionValue) -> Result<()> {
    match opt.type_group() {
        CurloptTypeGroup::Long => apply_long(set, opt, val.as_long()?),
        CurloptTypeGroup::ObjectPoint => apply_objectpoint(set, opt, val),
        CurloptTypeGroup::FunctionPoint => apply_func(set, opt, val.as_callback()?),
        CurloptTypeGroup::OffT => apply_offt(set, opt, val.as_offt()?),
        CurloptTypeGroup::Blob => apply_blob(set, opt, val.into_blob()?),
    }
}

/// Dispatch a `long`-typed option through the family handlers in curl's order,
/// falling through to the next handler whenever one reports
/// [`CurlError::UnknownOption`] (`setopt_long`).
fn apply_long(set: &mut UserDefined, opt: CurlOption, arg: i64) -> Result<()> {
    type Handler = fn(&mut UserDefined, CurlOption, i64) -> Result<()>;
    const HANDLERS: [Handler; 7] = [
        setopt_long_bool,
        setopt_long_net,
        setopt_long_http,
        setopt_long_proxy,
        setopt_long_ssl,
        setopt_long_proto,
        setopt_long_misc,
    ];
    for handler in HANDLERS {
        match handler(set, opt, arg) {
            Err(CurlError::UnknownOption) => continue,
            other => return other,
        }
    }
    Err(CurlError::UnknownOption)
}

/// Boolean / flag options (`setopt_long_bool`). The stored value is `arg != 0`;
/// curl additionally logs (but still accepts) values outside `0..=ok`, which is
/// purely diagnostic and therefore omitted here.
fn setopt_long_bool(set: &mut UserDefined, opt: CurlOption, arg: i64) -> Result<()> {
    use CurlOption as O;
    let enabled = arg != 0;
    match opt {
        O::CURLOPT_FORBID_REUSE => set.reuse_forbid = enabled,
        O::CURLOPT_FRESH_CONNECT => set.reuse_fresh = enabled,
        O::CURLOPT_VERBOSE => set.verbose = enabled,
        O::CURLOPT_HEADER => set.include_header = enabled,
        O::CURLOPT_NOPROGRESS => set.noprogress = enabled,
        O::CURLOPT_NOBODY => {
            set.opt_no_body = enabled;
            // In HTTP, "no body" means a HEAD request; clearing it reverts a
            // prior HEAD back to GET. Gated exactly as curl's `#ifndef
            // CURL_DISABLE_HTTP`.
            if cfg!(feature = "http") {
                if set.opt_no_body {
                    set.method = HttpReq::Head;
                } else if set.method == HttpReq::Head {
                    set.method = HttpReq::Get;
                }
            }
        }
        O::CURLOPT_FAILONERROR => set.http_fail_on_error = enabled,
        O::CURLOPT_KEEP_SENDING_ON_ERROR => set.http_keep_sending_on_error = enabled,
        O::CURLOPT_UPLOAD | O::CURLOPT_PUT => {
            // Uploading implies PUT in HTTP; the opposite is GET.
            if enabled {
                set.method = HttpReq::Put;
                set.opt_no_body = false;
            } else {
                set.method = HttpReq::Get;
            }
        }
        O::CURLOPT_FILETIME => set.get_filetime = enabled,
        O::CURLOPT_HTTP09_ALLOWED => {
            require_feature(cfg!(feature = "http"))?;
            set.http09_allowed = enabled;
        }
        O::CURLOPT_COOKIESESSION => {
            require_feature(cfg!(feature = "cookies"))?;
            set.cookiesession = enabled;
        }
        O::CURLOPT_AUTOREFERER => {
            require_feature(cfg!(feature = "http"))?;
            set.http_auto_referer = enabled;
        }
        O::CURLOPT_TRANSFER_ENCODING => {
            require_feature(cfg!(feature = "http"))?;
            set.http_transfer_encoding = enabled;
        }
        O::CURLOPT_UNRESTRICTED_AUTH => {
            require_feature(cfg!(feature = "http"))?;
            set.allow_auth_to_other_hosts = enabled;
        }
        O::CURLOPT_HTTP_TRANSFER_DECODING => {
            require_feature(cfg!(feature = "http"))?;
            set.http_te_skip = !enabled; // reversed in curl
        }
        O::CURLOPT_HTTP_CONTENT_DECODING => {
            require_feature(cfg!(feature = "http"))?;
            set.http_ce_skip = !enabled; // reversed in curl
        }
        O::CURLOPT_HTTPGET => {
            require_feature(cfg!(feature = "http"))?;
            if enabled {
                set.method = HttpReq::Get;
                set.opt_no_body = false;
            }
        }
        O::CURLOPT_POST => {
            require_feature(cfg!(feature = "http"))?;
            if enabled {
                set.method = HttpReq::Post;
                set.opt_no_body = false;
            } else {
                set.method = HttpReq::Get;
            }
        }
        O::CURLOPT_HTTPPROXYTUNNEL => {
            require_feature(cfg!(feature = "proxy"))?;
            set.tunnel_thru_httpproxy = enabled;
        }
        O::CURLOPT_HAPROXYPROTOCOL => {
            require_feature(cfg!(feature = "proxy"))?;
            set.haproxyprotocol = enabled;
        }
        O::CURLOPT_PROXY_SSL_VERIFYPEER => {
            require_feature(cfg!(feature = "proxy"))?;
            set.proxy_ssl.primary.verifypeer = enabled;
        }
        O::CURLOPT_PROXY_SSL_VERIFYHOST => {
            require_feature(cfg!(feature = "proxy"))?;
            set.proxy_ssl.primary.verifyhost = enabled;
        }
        O::CURLOPT_PROXY_TRANSFER_MODE => {
            require_feature(cfg!(feature = "proxy"))?;
            set.proxy_transfer_mode = enabled;
        }
        O::CURLOPT_SOCKS5_GSSAPI_NEC => {
            require_feature(cfg!(feature = "gssapi"))?;
            set.socks5_gssapi_nec = enabled;
        }
        O::CURLOPT_DIRLISTONLY => {
            require_feature(cfg!(any(
                feature = "ftp",
                feature = "pop3",
                feature = "sftp"
            )))?;
            set.list_only = enabled;
        }
        O::CURLOPT_APPEND => set.remote_append = enabled,
        O::CURLOPT_FTP_USE_EPRT => {
            require_feature(cfg!(feature = "ftp"))?;
            set.ftp_use_eprt = enabled;
        }
        O::CURLOPT_FTP_USE_EPSV => {
            require_feature(cfg!(feature = "ftp"))?;
            set.ftp_use_epsv = enabled;
        }
        O::CURLOPT_FTP_USE_PRET => {
            require_feature(cfg!(feature = "ftp"))?;
            set.ftp_use_pret = enabled;
        }
        O::CURLOPT_FTP_SKIP_PASV_IP => {
            require_feature(cfg!(feature = "ftp"))?;
            set.ftp_skip_ip = enabled;
        }
        O::CURLOPT_WILDCARDMATCH => {
            require_feature(cfg!(feature = "ftp"))?;
            set.wildcard_enabled = enabled;
        }
        O::CURLOPT_CRLF => set.crlf = enabled,
        O::CURLOPT_TFTP_NO_OPTIONS => {
            require_feature(cfg!(feature = "tftp"))?;
            set.tftp_no_options = enabled;
        }
        O::CURLOPT_TRANSFERTEXT => set.prefer_ascii = enabled,
        O::CURLOPT_SSL_VERIFYPEER => set.ssl.primary.verifypeer = enabled,
        O::CURLOPT_DOH_SSL_VERIFYPEER => set.doh_verifypeer = enabled,
        O::CURLOPT_DOH_SSL_VERIFYHOST => set.doh_verifyhost = enabled,
        // TLS is always built in (rustls), so cert-status requests are
        // accepted and stored; the TLS layer owns the actual OCSP handling.
        O::CURLOPT_DOH_SSL_VERIFYSTATUS => set.doh_verifystatus = enabled,
        O::CURLOPT_SSL_VERIFYHOST => set.ssl.primary.verifyhost = enabled,
        O::CURLOPT_SSL_VERIFYSTATUS => set.ssl.primary.verifystatus = enabled,
        O::CURLOPT_CERTINFO => set.ssl.certinfo = enabled,
        O::CURLOPT_NOSIGNAL => set.no_signal = enabled,
        O::CURLOPT_TCP_NODELAY => set.tcp_nodelay = enabled,
        O::CURLOPT_IGNORE_CONTENT_LENGTH => set.ignorecl = enabled,
        O::CURLOPT_SSL_SESSIONID_CACHE => {
            set.ssl.primary.cache_session = enabled;
            set.proxy_ssl.primary.cache_session = enabled;
        }
        O::CURLOPT_SSH_COMPRESSION => {
            require_feature(cfg!(any(feature = "scp", feature = "sftp")))?;
            set.ssh_compression = enabled;
        }
        O::CURLOPT_MAIL_RCPT_ALLOWFAILS => {
            require_feature(cfg!(feature = "smtp"))?;
            set.mail_rcpt_allowfails = enabled;
        }
        O::CURLOPT_SASL_IR => set.sasl_ir = enabled,
        O::CURLOPT_TCP_KEEPALIVE => set.tcp_keepalive = enabled,
        // TCP Fast Open is available on the Linux/macOS targets we build for.
        O::CURLOPT_TCP_FASTOPEN => set.tcp_fastopen = enabled,
        O::CURLOPT_SSL_ENABLE_ALPN => set.ssl_enable_alpn = enabled,
        O::CURLOPT_PATH_AS_IS => set.path_as_is = enabled,
        O::CURLOPT_PIPEWAIT => set.pipewait = enabled,
        O::CURLOPT_SUPPRESS_CONNECT_HEADERS => set.suppress_connect_headers = enabled,
        O::CURLOPT_DNS_SHUFFLE_ADDRESSES => set.dns_shuffle_addresses = enabled,
        O::CURLOPT_DISALLOW_USERNAME_IN_URL => set.disallow_username_in_url = enabled,
        O::CURLOPT_QUICK_EXIT => set.quick_exit = enabled,
        _ => return Err(CurlError::UnknownOption),
    }
    Ok(())
}

/// Networking / connection options (`setopt_long_net`).
fn setopt_long_net(set: &mut UserDefined, opt: CurlOption, arg: i64) -> Result<()> {
    use CurlOption as O;
    match opt {
        O::CURLOPT_DNS_CACHE_TIMEOUT => {
            if arg != -1 {
                set.dns_cache_timeout_ms = timeout_sec_to_ms(arg)?;
            } else {
                set.dns_cache_timeout_ms = -1;
            }
        }
        O::CURLOPT_MAXCONNECTS => {
            set.maxconnects = value_range(arg, 1, 1, I32_MAX_L)? as u32;
        }
        O::CURLOPT_SERVER_RESPONSE_TIMEOUT => {
            set.server_response_timeout = timeout_sec_to_ms(arg)?;
        }
        O::CURLOPT_SERVER_RESPONSE_TIMEOUT_MS => {
            set.server_response_timeout = timeout_ms(arg)?;
        }
        O::CURLOPT_LOW_SPEED_LIMIT => {
            if arg < 0 {
                return Err(CurlError::BadFunctionArgument);
            }
            set.low_speed_limit = arg;
        }
        O::CURLOPT_LOW_SPEED_TIME => {
            set.low_speed_time = value_range(arg, 0, 0, U16_MAX_L)? as u16;
        }
        O::CURLOPT_PORT => {
            if !(0..=65535).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.use_port = arg as u16;
        }
        O::CURLOPT_TIMEOUT => set.timeout = timeout_sec_to_ms(arg)?,
        O::CURLOPT_TIMEOUT_MS => set.timeout = timeout_ms(arg)?,
        O::CURLOPT_CONNECTTIMEOUT => set.connecttimeout = timeout_sec_to_ms(arg)?,
        O::CURLOPT_CONNECTTIMEOUT_MS => set.connecttimeout = timeout_ms(arg)?,
        O::CURLOPT_LOCALPORT => {
            if !(0..=65535).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.localport = arg as u16;
        }
        O::CURLOPT_LOCALPORTRANGE => {
            if !(0..=65535).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.localportrange = arg as u16;
        }
        O::CURLOPT_BUFFERSIZE => {
            set.buffer_size = value_range(arg, 0, READBUFFER_MIN, READBUFFER_MAX)? as u32;
        }
        O::CURLOPT_UPLOAD_BUFFERSIZE => {
            set.upload_buffer_size =
                value_range(arg, 0, UPLOADBUFFER_MIN, UPLOADBUFFER_MAX)? as u32;
        }
        O::CURLOPT_MAXFILESIZE => {
            if arg < 0 {
                return Err(CurlError::BadFunctionArgument);
            }
            set.max_filesize = arg;
        }
        O::CURLOPT_IPRESOLVE => {
            // CURL_IPRESOLVE_WHATEVER(0)..=CURL_IPRESOLVE_V6(2)
            if !(0..=2).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.ipver = arg as u8;
        }
        O::CURLOPT_CONNECT_ONLY => {
            if !(0..=2).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.connect_only = enabled_i(arg);
            set.connect_only_ws = arg == 2;
        }
        O::CURLOPT_ADDRESS_SCOPE => {
            require_feature(cfg!(feature = "ipv6"))?;
            if (arg as u64) > U32_MAX_L as u64 {
                return Err(CurlError::BadFunctionArgument);
            }
            set.scope_id = arg as u32;
        }
        O::CURLOPT_TCP_KEEPIDLE => {
            set.tcp_keepidle = value_range(arg, 0, 0, I32_MAX_L)? as i32;
        }
        O::CURLOPT_TCP_KEEPINTVL => {
            set.tcp_keepintvl = value_range(arg, 0, 0, I32_MAX_L)? as i32;
        }
        O::CURLOPT_TCP_KEEPCNT => {
            set.tcp_keepcnt = value_range(arg, 0, 0, I32_MAX_L)? as i32;
        }
        O::CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS => {
            set.happy_eyeballs_timeout = timeout_ms(arg)?;
        }
        O::CURLOPT_UPKEEP_INTERVAL_MS => set.upkeep_interval_ms = timeout_ms(arg)?,
        O::CURLOPT_MAXAGE_CONN => set.conn_max_idle_ms = timeout_sec_to_ms(arg)?,
        O::CURLOPT_MAXLIFETIME_CONN => set.conn_max_age_ms = timeout_sec_to_ms(arg)?,
        // Deprecated and a documented no-op; accepted for source compatibility.
        O::CURLOPT_DNS_USE_GLOBAL_CACHE => {}
        _ => return Err(CurlError::UnknownOption),
    }
    Ok(())
}

/// HTTP options (`setopt_long_http`). The whole family is gated on the `http`
/// feature; with it disabled every option here reports `CURLE_NOT_BUILT_IN`.
fn setopt_long_http(set: &mut UserDefined, opt: CurlOption, arg: i64) -> Result<()> {
    use CurlOption as O;
    // Only claim options this handler owns; unrelated ids must fall through.
    let owned = matches!(
        opt,
        O::CURLOPT_FOLLOWLOCATION
            | O::CURLOPT_MAXREDIRS
            | O::CURLOPT_POSTREDIR
            | O::CURLOPT_HEADEROPT
            | O::CURLOPT_HTTPAUTH
            | O::CURLOPT_HTTP_VERSION
            | O::CURLOPT_EXPECT_100_TIMEOUT_MS
            | O::CURLOPT_STREAM_WEIGHT
    );
    if !owned {
        return Err(CurlError::UnknownOption);
    }
    require_feature(cfg!(feature = "http"))?;
    match opt {
        O::CURLOPT_FOLLOWLOCATION => {
            if (arg as u64) > FOLLOW_MODE_MAX as u64 {
                return Err(CurlError::BadFunctionArgument);
            }
            set.http_follow_mode = arg as u8;
        }
        O::CURLOPT_MAXREDIRS => {
            set.maxredirs = value_range(arg, -1, -1, 0x7fff)? as i32;
        }
        O::CURLOPT_POSTREDIR => {
            if arg < CURL_REDIR_GET_ALL {
                return Err(CurlError::BadFunctionArgument);
            }
            set.post301 = (arg & CURL_REDIR_POST_301) != 0;
            set.post302 = (arg & CURL_REDIR_POST_302) != 0;
            set.post303 = (arg & CURL_REDIR_POST_303) != 0;
        }
        O::CURLOPT_HEADEROPT => {
            set.sep_headers = (arg & CURLHEADER_SEPARATE) != 0;
        }
        O::CURLOPT_HTTPAUTH => return apply_httpauth(set, false, arg as u32),
        O::CURLOPT_HTTP_VERSION => set.httpwant = set_http_version(arg)?,
        O::CURLOPT_EXPECT_100_TIMEOUT_MS => {
            set.expect_100_timeout = value_range(arg, 0, 0, U16_MAX_L)? as u16;
        }
        O::CURLOPT_STREAM_WEIGHT => {
            require_feature(cfg!(any(feature = "http2", feature = "http3")))?;
            if (STREAM_WEIGHT_MIN..=STREAM_WEIGHT_MAX).contains(&arg) {
                set.priority.weight = arg as i32;
            }
        }
        _ => unreachable!("option set checked above"),
    }
    Ok(())
}

/// Proxy options (`setopt_long_proxy`). Gated on the `proxy` feature.
fn setopt_long_proxy(set: &mut UserDefined, opt: CurlOption, arg: i64) -> Result<()> {
    use CurlOption as O;
    let owned = matches!(
        opt,
        O::CURLOPT_PROXYPORT | O::CURLOPT_PROXYAUTH | O::CURLOPT_PROXYTYPE | O::CURLOPT_SOCKS5_AUTH
    );
    if !owned {
        return Err(CurlError::UnknownOption);
    }
    require_feature(cfg!(feature = "proxy"))?;
    match opt {
        O::CURLOPT_PROXYPORT => {
            if !(0..=U16_MAX_L).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.proxyport = arg as u16;
        }
        O::CURLOPT_PROXYAUTH => return apply_httpauth(set, true, arg as u32),
        O::CURLOPT_PROXYTYPE => {
            // CURLPROXY_HTTP(0)..=CURLPROXY_SOCKS5_HOSTNAME(7)
            if !(CURLPROXY_HTTP as i64..=CURLPROXY_TYPE_MAX).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.proxytype = arg as u8;
        }
        O::CURLOPT_SOCKS5_AUTH => {
            // Only Basic and GSSAPI are valid SOCKS5 auth methods.
            if arg & !((CURLAUTH_BASIC | CURLAUTH_GSSAPI) as i64) != 0 {
                return Err(CurlError::NotBuiltIn);
            }
            set.socks5auth = arg as u32;
        }
        _ => unreachable!("option set checked above"),
    }
    Ok(())
}

/// TLS options (`setopt_long_ssl`). TLS (rustls) is always built in, so the
/// family is not feature-gated; individual options may still be unsupported.
fn setopt_long_ssl(set: &mut UserDefined, opt: CurlOption, arg: i64) -> Result<()> {
    use CurlOption as O;
    match opt {
        O::CURLOPT_CA_CACHE_TIMEOUT => {
            set.general_ssl.ca_cache_timeout = value_range(arg, -1, -1, I32_MAX_L)?;
        }
        O::CURLOPT_SSLVERSION => set_sslversion(&mut set.ssl.primary, arg)?,
        O::CURLOPT_PROXY_SSLVERSION => {
            require_feature(cfg!(feature = "proxy"))?;
            set_sslversion(&mut set.proxy_ssl.primary, arg)?;
        }
        // No backend exposes TLS False Start; curl returns NOT_BUILT_IN.
        O::CURLOPT_SSL_FALSESTART => return Err(CurlError::NotBuiltIn),
        O::CURLOPT_USE_SSL => {
            // CURLUSESSL_NONE(0)..=CURLUSESSL_LAST-1(3)
            if !(0..CURLUSESSL_LAST).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.use_ssl = arg as u8;
        }
        O::CURLOPT_SSL_OPTIONS => set_ssl_options(&mut set.ssl, arg),
        O::CURLOPT_PROXY_SSL_OPTIONS => {
            require_feature(cfg!(feature = "proxy"))?;
            set_ssl_options(&mut set.proxy_ssl, arg);
        }
        // NPN was removed from curl; accepting the option is a documented no-op.
        O::CURLOPT_SSL_ENABLE_NPN => {}
        // Clearing the engine name is the only effect; rustls has no engines.
        O::CURLOPT_SSLENGINE_DEFAULT => set.set_str(StrId::SslEngine, None),
        _ => return Err(CurlError::UnknownOption),
    }
    Ok(())
}

/// Protocol-specific long options (`setopt_long_proto`).
fn setopt_long_proto(set: &mut UserDefined, opt: CurlOption, arg: i64) -> Result<()> {
    use CurlOption as O;
    match opt {
        O::CURLOPT_TFTP_BLKSIZE => {
            require_feature(cfg!(feature = "tftp"))?;
            set.tftp_blksize = value_range(arg, 0, TFTP_BLKSIZE_MIN, TFTP_BLKSIZE_MAX)? as u16;
        }
        O::CURLOPT_NETRC => {
            // CURL_NETRC_IGNORED(0)..=CURL_NETRC_LAST-1(2)
            if !(0..CURL_NETRC_LAST).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.use_netrc = arg as u8;
        }
        O::CURLOPT_FTP_FILEMETHOD => {
            require_feature(cfg!(feature = "ftp"))?;
            // CURLFTPMETHOD_DEFAULT(0)..=CURLFTPMETHOD_LAST-1(3)
            if !(0..CURL_FTPMETHOD_LAST).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.ftp_filemethod = arg as u8;
        }
        O::CURLOPT_FTP_SSL_CCC => {
            require_feature(cfg!(feature = "ftp"))?;
            if !(0..CURL_FTPSSL_CCC_LAST).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.ftp_ccc = arg as u8;
        }
        O::CURLOPT_FTPSSLAUTH => {
            require_feature(cfg!(feature = "ftp"))?;
            if !(0..CURL_FTPAUTH_LAST).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.ftpsslauth = arg as u8;
        }
        O::CURLOPT_ACCEPTTIMEOUT_MS => {
            require_feature(cfg!(feature = "ftp"))?;
            set.accepttimeout = timeout_ms(arg)?;
        }
        O::CURLOPT_FTP_CREATE_MISSING_DIRS => {
            require_feature(cfg!(any(
                feature = "ftp",
                feature = "scp",
                feature = "sftp"
            )))?;
            // CURLFTP_CREATE_DIR_NONE(0)..=CURLFTP_CREATE_DIR_RETRY(2)
            if !(0..=CURLFTP_CREATE_DIR_RETRY).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.ftp_create_missing_dirs = arg as u8;
        }
        O::CURLOPT_NEW_FILE_PERMS => {
            require_feature(cfg!(any(
                feature = "ftp",
                feature = "scp",
                feature = "sftp"
            )))?;
            if !(0..=PERMS_MAX).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.new_file_perms = arg as u32;
        }
        O::CURLOPT_RTSP_REQUEST => {
            require_feature(cfg!(feature = "rtsp"))?;
            set.rtspreq = set_rtsp_request(arg)?;
        }
        O::CURLOPT_RTSP_CLIENT_CSEQ => {
            require_feature(cfg!(feature = "rtsp"))?;
            set.rtsp_next_client_cseq = value_range(arg, 0, 0, I32_MAX_L)? as u32;
        }
        O::CURLOPT_RTSP_SERVER_CSEQ => {
            require_feature(cfg!(feature = "rtsp"))?;
            set.rtsp_next_server_cseq = value_range(arg, 0, 0, I32_MAX_L)? as u32;
        }
        O::CURLOPT_SSH_AUTH_TYPES => {
            require_feature(cfg!(any(feature = "scp", feature = "sftp")))?;
            set.ssh_auth_types = arg as u32;
        }
        O::CURLOPT_NEW_DIRECTORY_PERMS => {
            require_feature(cfg!(any(feature = "scp", feature = "sftp")))?;
            if !(0..=PERMS_MAX).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.new_directory_perms = arg as u32;
        }
        O::CURLOPT_PROTOCOLS => set.allowed_protocols = arg as u32,
        O::CURLOPT_REDIR_PROTOCOLS => set.redir_protocols = arg as u32,
        O::CURLOPT_WS_OPTIONS => {
            require_feature(cfg!(feature = "websockets"))?;
            set.ws_raw_mode = (arg & CURLWS_RAW_MODE) != 0;
            set.ws_no_auto_pong = (arg & CURLWS_NOAUTOPONG) != 0;
        }
        _ => return Err(CurlError::UnknownOption),
    }
    Ok(())
}

/// Miscellaneous long options (`setopt_long_misc`).
fn setopt_long_misc(set: &mut UserDefined, opt: CurlOption, arg: i64) -> Result<()> {
    use CurlOption as O;
    match opt {
        O::CURLOPT_TIMECONDITION => {
            // CURL_TIMECOND_NONE(0)..=CURL_TIMECOND_LAST-1(4)
            if !(0..CURL_TIMECOND_LAST).contains(&arg) {
                return Err(CurlError::BadFunctionArgument);
            }
            set.timecondition = arg as u8;
        }
        O::CURLOPT_TIMEVALUE => set.timevalue = arg,
        O::CURLOPT_POSTFIELDSIZE => {
            if arg < -1 {
                return Err(CurlError::BadFunctionArgument);
            }
            // Growing the declared size past an owned copy invalidates it.
            if set.postfieldsize < arg && set.copypostfields.is_some() {
                set.copypostfields = None;
                set.postfields = None;
            }
            set.postfieldsize = arg;
        }
        O::CURLOPT_INFILESIZE => {
            if arg < -1 {
                return Err(CurlError::BadFunctionArgument);
            }
            set.filesize = arg;
        }
        O::CURLOPT_RESUME_FROM => {
            if arg < -1 {
                return Err(CurlError::BadFunctionArgument);
            }
            set.set_resume_from = arg;
        }
        O::CURLOPT_UPLOAD_FLAGS => set.upload_flags = arg as u8,
        O::CURLOPT_MIME_OPTIONS => {
            require_feature(cfg!(any(
                feature = "http",
                feature = "smtp",
                feature = "imap"
            )))?;
            set.mime_formescape = (arg & MIMEPOST_OPT_FORMESCAPE) != 0;
        }
        O::CURLOPT_HSTS_CTRL => {
            require_feature(cfg!(feature = "hsts"))?;
            set.hsts_enable = (arg & CURLHSTS_ENABLE) != 0;
        }
        O::CURLOPT_ALTSVC_CTRL => {
            require_feature(cfg!(feature = "alt-svc"))?;
            if arg == 0 {
                return Err(CurlError::BadFunctionArgument);
            }
            set.altsvc_ctrl = arg;
        }
        O::CURLOPT_GSSAPI_DELEGATION => {
            require_feature(cfg!(feature = "gssapi"))?;
            set.gssapi_delegation = arg as u8;
        }
        _ => return Err(CurlError::UnknownOption),
    }
    Ok(())
}

// ===========================================================================
// ObjectPoint dispatch (CURLOPTTYPE_OBJECTPOINT / _STRINGPOINT / _CBPOINT)
//
// Mirrors curl's `Curl_vsetopt` second branch: `curl_slist *` options route to
// `setopt_slist`, the handful of distinct pointer types route to
// `setopt_pointers`, and everything else (`char *` plus `void *` userdata) goes
// to `setopt_cptr` (which first consults `setopt_cptr_proxy`).
// ===========================================================================

/// Dispatch an object-pointer option to the correct typed handler.
fn apply_objectpoint(set: &mut UserDefined, opt: CurlOption, val: OptionValue) -> Result<()> {
    use CurlOption as O;
    match opt {
        // ---- curl_slist * options (setopt_slist) ---------------------------
        O::CURLOPT_PROXYHEADER
        | O::CURLOPT_HTTP200ALIASES
        | O::CURLOPT_POSTQUOTE
        | O::CURLOPT_PREQUOTE
        | O::CURLOPT_QUOTE
        | O::CURLOPT_RESOLVE
        | O::CURLOPT_HTTPHEADER
        | O::CURLOPT_TELNETOPTIONS
        | O::CURLOPT_MAIL_RCPT
        | O::CURLOPT_CONNECT_TO => apply_slist(set, opt, val.into_slist()?),
        // ---- assorted pointer-type options (setopt_pointers) ---------------
        O::CURLOPT_HTTPPOST
        | O::CURLOPT_MIMEPOST
        | O::CURLOPT_STDERR
        | O::CURLOPT_SHARE
        | O::CURLOPT_STREAM_DEPENDS
        | O::CURLOPT_STREAM_DEPENDS_E => apply_pointers(set, opt, val),
        // ---- char * (and void * userdata) options (setopt_cptr) ------------
        _ => apply_cptr(set, opt, val),
    }
}

/// `curl_slist *` options (`setopt_slist`). Each option simply stores (or
/// clears, when the list is `None`) the owned list into its `set` field.
fn apply_slist(set: &mut UserDefined, opt: CurlOption, list: Option<SList>) -> Result<()> {
    use CurlOption as O;
    match opt {
        O::CURLOPT_PROXYHEADER => {
            require_feature(cfg!(feature = "proxy"))?;
            set.proxyheaders = list;
        }
        O::CURLOPT_HTTP200ALIASES => {
            require_feature(cfg!(feature = "http"))?;
            set.http200aliases = list;
        }
        // FTP and SSH both consume raw command quotes.
        O::CURLOPT_POSTQUOTE => {
            require_feature(cfg!(any(
                feature = "ftp",
                feature = "scp",
                feature = "sftp"
            )))?;
            set.postquote = list;
        }
        O::CURLOPT_PREQUOTE => {
            require_feature(cfg!(any(
                feature = "ftp",
                feature = "scp",
                feature = "sftp"
            )))?;
            set.prequote = list;
        }
        O::CURLOPT_QUOTE => {
            require_feature(cfg!(any(
                feature = "ftp",
                feature = "scp",
                feature = "sftp"
            )))?;
            set.quote = list;
        }
        // CURLOPT_RESOLVE is always available (no feature gate in curl).
        O::CURLOPT_RESOLVE => set.resolve = list,
        // HTTPHEADER is available whenever the MIME machinery is (HTTP, SMTP or
        // IMAP), matching curl's `!CURL_DISABLE_HTTP || !CURL_DISABLE_MIME`.
        O::CURLOPT_HTTPHEADER => {
            require_feature(cfg!(any(
                feature = "http",
                feature = "smtp",
                feature = "imap"
            )))?;
            set.headers = list;
        }
        O::CURLOPT_TELNETOPTIONS => {
            require_feature(cfg!(feature = "telnet"))?;
            set.telnet_options = list;
        }
        O::CURLOPT_MAIL_RCPT => {
            require_feature(cfg!(feature = "smtp"))?;
            set.mail_rcpt = list;
        }
        O::CURLOPT_CONNECT_TO => set.connect_to = list,
        _ => return Err(CurlError::UnknownOption),
    }
    Ok(())
}

/// Assorted distinct pointer-type options (`setopt_pointers`). The complex
/// share rewiring and HTTP/2 priority-tree bookkeeping that curl performs on
/// the live handle is the easy layer's responsibility; here we only record the
/// typed values onto `set`.
fn apply_pointers(set: &mut UserDefined, opt: CurlOption, val: OptionValue) -> Result<()> {
    use CurlOption as O;
    match opt {
        O::CURLOPT_HTTPPOST => {
            require_feature(cfg!(feature = "http"))?;
            set.httppost = val.as_ptr()?;
            set.method = HttpReq::PostForm;
            set.opt_no_body = false;
        }
        O::CURLOPT_MIMEPOST => {
            require_feature(cfg!(any(
                feature = "http",
                feature = "smtp",
                feature = "imap"
            )))?;
            set.mimepost = val.as_ptr()?;
            set.method = HttpReq::PostMime;
            set.opt_no_body = false;
        }
        // A NULL FILE * means "fall back to stderr"; the writer layer treats a
        // null [`CDataPtr`] as that sentinel, so we just store whatever we get.
        O::CURLOPT_STDERR => set.err = val.as_ptr()?,
        O::CURLOPT_SHARE => set.share = val.into_share()?,
        O::CURLOPT_STREAM_DEPENDS => {
            require_feature(cfg!(feature = "http2"))?;
            set.priority.dependent = val.as_ptr()?;
            set.priority.exclusive = false;
        }
        O::CURLOPT_STREAM_DEPENDS_E => {
            require_feature(cfg!(feature = "http2"))?;
            set.priority.dependent = val.as_ptr()?;
            set.priority.exclusive = true;
        }
        _ => return Err(CurlError::UnknownOption),
    }
    Ok(())
}

// ===========================================================================
// char * / void * userdata options (setopt_cptr + setopt_cptr_proxy)
//
// `setopt_cptr` handles three intermixed kinds of options that all arrive as a
// pointer in C: opaque `void *` userdata (stored as an address), the binary
// POST-body options, and genuine `char *` strings. Proxy-related strings are
// peeled off first by `setopt_cptr_proxy`.
// ===========================================================================

/// Top-level `char *`/`void *` option handler (`setopt_cptr`).
fn apply_cptr(set: &mut UserDefined, opt: CurlOption, val: OptionValue) -> Result<()> {
    use CurlOption as O;
    use StrId as S;

    // ---- void * userdata options (stored as opaque addresses) -------------
    // `as_ptr` borrows the value, so these arms can return immediately.
    match opt {
        O::CURLOPT_HEADERDATA => {
            set.writeheader = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_READDATA => {
            set.in_set = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_WRITEDATA => {
            set.out = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_DEBUGDATA => {
            set.debugdata = val.as_ptr()?;
            return Ok(());
        }
        // CURLOPT_PROGRESSDATA shares this id with CURLOPT_XFERINFODATA.
        O::CURLOPT_XFERINFODATA => {
            set.progress_client = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_SEEKDATA => {
            set.seek_client = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_IOCTLDATA => {
            set.ioctl_client = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_SOCKOPTDATA => {
            set.sockopt_client = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_OPENSOCKETDATA => {
            set.opensocket_client = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_RESOLVER_START_DATA => {
            set.resolver_start_client = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_CLOSESOCKETDATA => {
            set.closesocket_client = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_PREREQDATA => {
            set.prereq_userp = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_ERRORBUFFER => {
            set.errorbuffer = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_PRIVATE => {
            set.private_data = val.as_ptr()?;
            return Ok(());
        }
        // rustls exposes no SSL_CTX, so the SSL_CTX userdata pointer is refused.
        O::CURLOPT_SSL_CTX_DATA => return Err(CurlError::NotBuiltIn),
        O::CURLOPT_CHUNK_DATA => {
            require_feature(cfg!(feature = "ftp"))?;
            set.wildcardptr = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_FNMATCH_DATA => {
            require_feature(cfg!(feature = "ftp"))?;
            set.fnmatch_data = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_TRAILERDATA => {
            require_feature(cfg!(feature = "http"))?;
            set.trailer_data = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_INTERLEAVEDATA => {
            require_feature(cfg!(feature = "rtsp"))?;
            set.interleave_client = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_SSH_KEYDATA => {
            require_feature(cfg!(any(feature = "scp", feature = "sftp")))?;
            set.ssh_keyfunc_userp = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_SSH_HOSTKEYDATA => {
            require_feature(cfg!(any(feature = "scp", feature = "sftp")))?;
            set.ssh_hostkeyfunc_userp = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_HSTSREADDATA => {
            require_feature(cfg!(feature = "hsts"))?;
            set.hsts_read_userp = val.as_ptr()?;
            return Ok(());
        }
        O::CURLOPT_HSTSWRITEDATA => {
            require_feature(cfg!(feature = "hsts"))?;
            set.hsts_write_userp = val.as_ptr()?;
            return Ok(());
        }
        // POSTFIELDS keeps a *borrowed* body pointer (no copy). The owned
        // COPYPOSTFIELDS copy, if any, is released.
        O::CURLOPT_POSTFIELDS => {
            require_feature(cfg!(any(feature = "http", feature = "mqtt")))?;
            set.postfields = Some(val.as_ptr()?);
            set.copypostfields = None;
            set.method = HttpReq::Post;
            return Ok(());
        }
        _ => {}
    }

    // ---- COPYPOSTFIELDS: owned binary body --------------------------------
    if opt == O::CURLOPT_COPYPOSTFIELDS {
        require_feature(cfg!(any(feature = "http", feature = "mqtt")))?;
        // The FFI shim has already applied curl's "NUL-terminate when
        // postfieldsize == -1, otherwise copy exactly postfieldsize bytes"
        // rule, so the bytes (or None for a NULL pointer) are stored verbatim.
        set.copypostfields = val.into_bytes()?;
        set.postfields = None;
        set.method = HttpReq::Post;
        return Ok(());
    }

    // ---- CURLU: pre-parsed URL handle -------------------------------------
    if opt == O::CURLOPT_CURLU {
        // curl's contract is store-only (`lib/setopt.c`: `s->uh = (CURLU *)ptr;`):
        // the caller's `CURLU *` is kept verbatim and only read at perform time.
        // We therefore store the raw address WITHOUT dereferencing it (the FFI
        // resolves it into `set.uh` just before a transfer, mirroring curl's
        // read-at-perform behaviour). Eagerly dereferencing here would crash on
        // the dummy pointer `tests/libtest/lib1521` deliberately passes to verify
        // this contract. Setting a URL handle clears any string URL previously
        // stored, and the stale resolved handle (if any) so the next perform
        // re-resolves from the freshly stored pointer.
        set.set_str(S::SetUrl, None);
        set.uh_ptr = val.as_ptr()?;
        set.uh = None;
        return Ok(());
    }

    // ---- genuine char * string options ------------------------------------
    let s = val.into_str()?;

    // Proxy strings get first refusal, exactly like setopt_cptr → _proxy.
    match apply_cptr_proxy(set, opt, &s) {
        Err(CurlError::UnknownOption) => {}
        result => return result,
    }

    apply_cptr_string(set, opt, s)
}

/// Proxy-related `char *` options (`setopt_cptr_proxy`). Returns
/// [`CurlError::UnknownOption`] for any non-proxy option so the caller can fall
/// through to the general string handler. The entire family is gated behind the
/// `proxy` feature.
fn apply_cptr_proxy(set: &mut UserDefined, opt: CurlOption, s: &Option<String>) -> Result<()> {
    use CurlOption as O;
    use StrId as S;

    let owned = matches!(
        opt,
        O::CURLOPT_PROXYUSERPWD
            | O::CURLOPT_PROXYUSERNAME
            | O::CURLOPT_PROXYPASSWORD
            | O::CURLOPT_NOPROXY
            | O::CURLOPT_PROXY_SSLCERT
            | O::CURLOPT_PROXY_SSLCERTTYPE
            | O::CURLOPT_PROXY_SSLKEY
            | O::CURLOPT_PROXY_KEYPASSWD
            | O::CURLOPT_PROXY_SSLKEYTYPE
            | O::CURLOPT_PROXY_SSL_CIPHER_LIST
            | O::CURLOPT_PROXY_TLS13_CIPHERS
            | O::CURLOPT_PROXY
            | O::CURLOPT_PRE_PROXY
            | O::CURLOPT_SOCKS5_GSSAPI_SERVICE
            | O::CURLOPT_PROXY_SERVICE_NAME
            | O::CURLOPT_PROXY_PINNEDPUBLICKEY
            | O::CURLOPT_HAPROXY_CLIENT_IP
            | O::CURLOPT_PROXY_CAINFO
            | O::CURLOPT_PROXY_CRLFILE
            | O::CURLOPT_PROXY_ISSUERCERT
            | O::CURLOPT_PROXY_CAPATH
    );
    if !owned {
        return Err(CurlError::UnknownOption);
    }
    require_feature(cfg!(feature = "proxy"))?;

    match opt {
        O::CURLOPT_PROXYUSERPWD => match s {
            Some(login) => {
                if login.len() > CURL_MAX_INPUT_LENGTH {
                    return Err(CurlError::BadFunctionArgument);
                }
                // NOTE: curl percent-decodes (REJECT_ZERO) the split proxy
                // credentials via Curl_urldecode. escape.rs is not a declared
                // dependency of this module, so the raw components are stored
                // here and the proxy auth layer applies the identical decoding
                // when the credentials are consumed.
                let (u, p) = parse_login_details(login);
                set.set_str(S::Proxyusername, u);
                set.set_str(S::Proxypassword, p);
            }
            None => {
                set.set_str(S::Proxyusername, None);
                set.set_str(S::Proxypassword, None);
            }
        },
        O::CURLOPT_PROXYUSERNAME => set.set_str(S::Proxyusername, s.clone()),
        O::CURLOPT_PROXYPASSWORD => set.set_str(S::Proxypassword, s.clone()),
        O::CURLOPT_NOPROXY => set.set_str(S::Noproxy, s.clone()),
        O::CURLOPT_PROXY_SSLCERT => set.set_str(S::CertProxy, s.clone()),
        O::CURLOPT_PROXY_SSLCERTTYPE => set.set_str(S::CertTypeProxy, s.clone()),
        O::CURLOPT_PROXY_SSLKEY => set.set_str(S::KeyProxy, s.clone()),
        O::CURLOPT_PROXY_KEYPASSWD => set.set_str(S::KeyPasswdProxy, s.clone()),
        O::CURLOPT_PROXY_SSLKEYTYPE => set.set_str(S::KeyTypeProxy, s.clone()),
        // rustls supports cipher configuration, so these are accepted (stored).
        O::CURLOPT_PROXY_SSL_CIPHER_LIST => set.set_str(S::SslCipherListProxy, s.clone()),
        O::CURLOPT_PROXY_TLS13_CIPHERS => set.set_str(S::SslCipher13ListProxy, s.clone()),
        O::CURLOPT_PROXY => set.set_str(S::Proxy, s.clone()),
        O::CURLOPT_PRE_PROXY => set.set_str(S::PreProxy, s.clone()),
        // Both option ids write the same proxy service-name slot.
        O::CURLOPT_SOCKS5_GSSAPI_SERVICE | O::CURLOPT_PROXY_SERVICE_NAME => {
            set.set_str(S::ProxyServiceName, s.clone())
        }
        O::CURLOPT_PROXY_PINNEDPUBLICKEY => set.set_str(S::SslPinnedPublicKeyProxy, s.clone()),
        O::CURLOPT_HAPROXY_CLIENT_IP => {
            set.set_str(S::HaproxyClientIp, s.clone());
            // Providing a client IP implicitly enables the HAProxy protocol.
            set.haproxyprotocol = s.is_some();
        }
        O::CURLOPT_PROXY_CAINFO => {
            set.proxy_ssl.custom_cafile = true;
            set.set_str(S::SslCafileProxy, s.clone());
        }
        O::CURLOPT_PROXY_CRLFILE => set.set_str(S::SslCrlfileProxy, s.clone()),
        O::CURLOPT_PROXY_ISSUERCERT => set.set_str(S::SslIssuercertProxy, s.clone()),
        O::CURLOPT_PROXY_CAPATH => {
            set.proxy_ssl.custom_capath = true;
            set.set_str(S::SslCapathProxy, s.clone());
        }
        _ => unreachable!("owned guard restricts opt to the proxy string family"),
    }
    Ok(())
}

/// General (non-proxy) `char *` string options (the main body of
/// `setopt_cptr`). Consumes the owned string `s`.
fn apply_cptr_string(set: &mut UserDefined, opt: CurlOption, s: Option<String>) -> Result<()> {
    use CurlOption as O;
    use StrId as S;

    match opt {
        // ---- TLS material (rustls accepts all of these) -------------------
        O::CURLOPT_CAINFO => {
            set.ssl.custom_cafile = true;
            set.set_str(S::SslCafile, s);
        }
        O::CURLOPT_CAPATH => {
            set.ssl.custom_capath = true;
            set.set_str(S::SslCapath, s);
        }
        O::CURLOPT_CRLFILE => set.set_str(S::SslCrlfile, s),
        O::CURLOPT_SSL_CIPHER_LIST => set.set_str(S::SslCipherList, s),
        O::CURLOPT_TLS13_CIPHERS => set.set_str(S::SslCipher13List, s),
        O::CURLOPT_SSLCERT => set.set_str(S::Cert, s),
        O::CURLOPT_SSLCERTTYPE => set.set_str(S::CertType, s),
        O::CURLOPT_SSLKEY => set.set_str(S::Key, s),
        O::CURLOPT_SSLKEYTYPE => set.set_str(S::KeyType, s),
        O::CURLOPT_KEYPASSWD => set.set_str(S::KeyPasswd, s),
        O::CURLOPT_ISSUERCERT => set.set_str(S::SslIssuercert, s),
        O::CURLOPT_SSL_EC_CURVES => set.set_str(S::SslEcCurves, s),
        O::CURLOPT_SSL_SIGNATURE_ALGORITHMS => set.set_str(S::SslSignatureAlgorithms, s),
        O::CURLOPT_PINNEDPUBLICKEY => set.set_str(S::SslPinnedPublicKey, s),
        O::CURLOPT_SSLENGINE => {
            // rustls has no crypto-engine concept. curl only stores/activates a
            // non-empty engine name; we store it (without activation) so that
            // round-tripping the option is lossless, and treat NULL/empty as a
            // no-op exactly like curl's `if(ptr && ptr[0])` guard.
            let non_empty = matches!(s, Some(ref e) if !e.is_empty());
            if non_empty {
                set.set_str(S::SslEngine, s);
            }
        }

        // ---- entropy sources: accepted no-ops (deprecated in curl) --------
        O::CURLOPT_RANDOM_FILE | O::CURLOPT_EGDSOCKET => {}

        // ---- generic request / netrc / target ----------------------------
        O::CURLOPT_REQUEST_TARGET => set.set_str(S::Target, s),
        O::CURLOPT_NETRC_FILE => set.set_str(S::NetrcFile, s),
        // CUSTOMREQUEST deliberately does NOT change the request method.
        O::CURLOPT_CUSTOMREQUEST => set.set_str(S::Customrequest, s),
        O::CURLOPT_SERVICE_NAME => set.set_str(S::ServiceName, s),
        O::CURLOPT_DEFAULT_PROTOCOL => set.set_str(S::DefaultProtocol, s),
        O::CURLOPT_SASL_AUTHZID => set.set_str(S::SaslAuthzid, s),

        // ---- URL --------------------------------------------------------
        O::CURLOPT_URL => set.set_str(S::SetUrl, s),

        // ---- credentials -------------------------------------------------
        O::CURLOPT_USERPWD => match s {
            Some(login) => {
                if login.len() > CURL_MAX_INPUT_LENGTH {
                    return Err(CurlError::BadFunctionArgument);
                }
                let (u, p) = parse_login_details(&login);
                set.set_str(S::Username, u);
                set.set_str(S::Password, p);
            }
            None => {
                set.set_str(S::Username, None);
                set.set_str(S::Password, None);
            }
        },
        O::CURLOPT_USERNAME => set.set_str(S::Username, s),
        O::CURLOPT_PASSWORD => set.set_str(S::Password, s),
        O::CURLOPT_LOGIN_OPTIONS => set.set_str(S::Options, s),
        O::CURLOPT_XOAUTH2_BEARER => set.set_str(S::Bearer, s),
        O::CURLOPT_RANGE => set.set_str(S::SetRange, s),

        // ---- interface binding ------------------------------------------
        O::CURLOPT_INTERFACE => match s {
            Some(input) => {
                let (dev, iface, host) = parse_interface(&input)?;
                set.set_str(S::Device, dev);
                set.set_str(S::Interface, iface);
                set.set_str(S::Bindhost, host);
            }
            None => {
                set.set_str(S::Device, None);
                set.set_str(S::Interface, None);
                set.set_str(S::Bindhost, None);
            }
        },

        // ---- HTTP-only strings -------------------------------------------
        O::CURLOPT_ACCEPT_ENCODING => {
            require_feature(cfg!(feature = "http"))?;
            // "" expands to every supported encoding; NULL disables the header.
            match s {
                Some(ref e) if e.is_empty() => {
                    set.set_str(S::Encoding, Some(all_content_encodings()))
                }
                other => set.set_str(S::Encoding, other),
            }
        }
        O::CURLOPT_REFERER => {
            require_feature(cfg!(feature = "http"))?;
            set.set_str(S::SetReferer, s);
        }
        O::CURLOPT_USERAGENT => {
            require_feature(cfg!(feature = "http"))?;
            set.set_str(S::Useragent, s);
        }

        // ---- AWS SigV4 ---------------------------------------------------
        O::CURLOPT_AWS_SIGV4 => {
            require_feature(cfg!(feature = "aws-sigv4"))?;
            let is_set = s.is_some();
            set.set_str(S::AwsSigv4, s);
            // SigV4 overrides the default Basic auth selection.
            if is_set {
                set.httpauth = CURLAUTH_AWS_SIGV4;
            }
        }

        // ---- cookies -----------------------------------------------------
        O::CURLOPT_COOKIE => {
            require_feature(cfg!(feature = "cookies"))?;
            set.set_str(S::Cookie, s);
        }
        O::CURLOPT_COOKIEFILE => {
            require_feature(cfg!(feature = "cookies"))?;
            match s {
                Some(file) => {
                    if file.len() > CURL_MAX_INPUT_LENGTH {
                        return Err(CurlError::BadFunctionArgument);
                    }
                    set.cookiefiles.push(file);
                }
                // A NULL filename clears the pending cookie-file list.
                None => set.cookiefiles.clear(),
            }
        }
        O::CURLOPT_COOKIEJAR => {
            require_feature(cfg!(feature = "cookies"))?;
            set.set_str(S::Cookiejar, s);
            set.cookie_engine = true;
        }
        O::CURLOPT_COOKIELIST => {
            require_feature(cfg!(feature = "cookies"))?;
            if let Some(cmd) = s {
                // The control verbs act on the live jar (applied by the easy
                // layer); only the raw Set-Cookie/Netscape add path is bounded
                // and activates the cookie engine, matching curl's cookielist().
                let is_verb = cmd.eq_ignore_ascii_case("ALL")
                    || cmd.eq_ignore_ascii_case("SESS")
                    || cmd.eq_ignore_ascii_case("FLUSH")
                    || cmd.eq_ignore_ascii_case("RELOAD");
                if !is_verb {
                    if cmd.len() > CURL_MAX_INPUT_LENGTH {
                        return Err(CurlError::BadFunctionArgument);
                    }
                    set.cookie_engine = true;
                }
                set.cookie_commands.push(cmd);
            }
            // A NULL argument is a no-op (curl returns CURLE_OK).
        }

        // ---- SMTP --------------------------------------------------------
        O::CURLOPT_MAIL_FROM => {
            require_feature(cfg!(feature = "smtp"))?;
            set.set_str(S::MailFrom, s);
        }
        O::CURLOPT_MAIL_AUTH => {
            require_feature(cfg!(feature = "smtp"))?;
            set.set_str(S::MailAuth, s);
        }

        // ---- RTSP --------------------------------------------------------
        O::CURLOPT_RTSP_SESSION_ID => {
            require_feature(cfg!(feature = "rtsp"))?;
            set.set_str(S::RtspSessionId, s);
        }
        O::CURLOPT_RTSP_STREAM_URI => {
            require_feature(cfg!(feature = "rtsp"))?;
            set.set_str(S::RtspStreamUri, s);
        }
        O::CURLOPT_RTSP_TRANSPORT => {
            require_feature(cfg!(feature = "rtsp"))?;
            set.set_str(S::RtspTransport, s);
        }

        // ---- SSH ---------------------------------------------------------
        O::CURLOPT_SSH_PUBLIC_KEYFILE => {
            require_feature(cfg!(any(feature = "scp", feature = "sftp")))?;
            set.set_str(S::SshPublicKey, s);
        }
        O::CURLOPT_SSH_PRIVATE_KEYFILE => {
            require_feature(cfg!(any(feature = "scp", feature = "sftp")))?;
            set.set_str(S::SshPrivateKey, s);
        }
        O::CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 => {
            require_feature(cfg!(any(feature = "scp", feature = "sftp")))?;
            set.set_str(S::SshHostPublicKeyMd5, s);
        }
        O::CURLOPT_SSH_KNOWNHOSTS => {
            require_feature(cfg!(any(feature = "scp", feature = "sftp")))?;
            set.set_str(S::SshKnownhosts, s);
        }
        O::CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 => {
            require_feature(cfg!(any(feature = "scp", feature = "sftp")))?;
            set.set_str(S::SshHostPublicKeySha256, s);
        }

        // ---- FTP ---------------------------------------------------------
        O::CURLOPT_FTPPORT => {
            require_feature(cfg!(feature = "ftp"))?;
            let is_set = s.is_some();
            set.set_str(S::Ftpport, s);
            set.ftp_use_port = is_set;
        }
        O::CURLOPT_FTP_ACCOUNT => {
            require_feature(cfg!(feature = "ftp"))?;
            set.set_str(S::FtpAccount, s);
        }
        O::CURLOPT_FTP_ALTERNATIVE_TO_USER => {
            require_feature(cfg!(feature = "ftp"))?;
            set.set_str(S::FtpAlternativeToUser, s);
        }

        // ---- protocol allow-lists (string form) --------------------------
        O::CURLOPT_PROTOCOLS_STR => match s {
            Some(p) => set.allowed_protocols = protocol2num(Some(&p))?,
            None => set.allowed_protocols = CURLPROTO_ALL,
        },
        O::CURLOPT_REDIR_PROTOCOLS_STR => match s {
            Some(p) => set.redir_protocols = protocol2num(Some(&p))?,
            None => set.redir_protocols = CURLPROTO_REDIR,
        },

        // ---- DoH ---------------------------------------------------------
        O::CURLOPT_DOH_URL => {
            let is_set = s.is_some();
            set.set_str(S::Doh, s);
            set.doh = is_set;
        }

        // ---- HSTS / Alt-Svc ----------------------------------------------
        O::CURLOPT_HSTS => {
            require_feature(cfg!(feature = "hsts"))?;
            match s {
                Some(file) => {
                    set.set_str(S::Hsts, Some(file.clone()));
                    set.hstsfiles.push(file);
                }
                None => {
                    set.set_str(S::Hsts, None);
                    set.hstsfiles.clear();
                }
            }
        }
        O::CURLOPT_ALTSVC => {
            require_feature(cfg!(feature = "alt-svc"))?;
            set.set_str(S::Altsvc, s);
        }

        // ---- Unix domain sockets -----------------------------------------
        O::CURLOPT_UNIX_SOCKET_PATH => {
            require_feature(cfg!(feature = "unix-sockets"))?;
            set.abstract_unix_socket = false;
            set.set_str(S::UnixSocketPath, s);
        }
        O::CURLOPT_ABSTRACT_UNIX_SOCKET => {
            require_feature(cfg!(feature = "unix-sockets"))?;
            set.abstract_unix_socket = true;
            set.set_str(S::UnixSocketPath, s);
        }

        // ---- TLS-SRP -----------------------------------------------------
        // rustls has no TLS-SRP backend, but the option ids remain valid: the
        // username/password are stored and the type is validated, mirroring
        // curl's USE_TLS_SRP handlers. Only "SRP" is accepted as the type.
        O::CURLOPT_TLSAUTH_USERNAME => set.set_str(S::TlsauthUsername, s),
        O::CURLOPT_TLSAUTH_PASSWORD => set.set_str(S::TlsauthPassword, s),
        O::CURLOPT_TLSAUTH_TYPE => {
            if matches!(s, Some(ref t) if !t.eq_ignore_ascii_case("SRP")) {
                return Err(CurlError::BadFunctionArgument);
            }
        }
        O::CURLOPT_PROXY_TLSAUTH_USERNAME => {
            require_feature(cfg!(feature = "proxy"))?;
            set.set_str(S::TlsauthUsernameProxy, s);
        }
        O::CURLOPT_PROXY_TLSAUTH_PASSWORD => {
            require_feature(cfg!(feature = "proxy"))?;
            set.set_str(S::TlsauthPasswordProxy, s);
        }
        O::CURLOPT_PROXY_TLSAUTH_TYPE => {
            require_feature(cfg!(feature = "proxy"))?;
            if matches!(s, Some(ref t) if !t.eq_ignore_ascii_case("SRP")) {
                return Err(CurlError::BadFunctionArgument);
            }
        }

        // ---- async-resolver (c-ares analog → hickory-dns) ----------------
        // curl gates these behind CURLRES_ARES; the Rust async resolver is the
        // closest analog, so they are available only with the `hickory-dns`
        // feature and otherwise report "not built in".
        O::CURLOPT_DNS_SERVERS => {
            require_feature(cfg!(feature = "hickory-dns"))?;
            set.set_str(S::DnsServers, s);
        }
        O::CURLOPT_DNS_INTERFACE => {
            require_feature(cfg!(feature = "hickory-dns"))?;
            set.set_str(S::DnsInterface, s);
        }
        O::CURLOPT_DNS_LOCAL_IP4 => {
            require_feature(cfg!(feature = "hickory-dns"))?;
            set.set_str(S::DnsLocalIp4, s);
        }
        O::CURLOPT_DNS_LOCAL_IP6 => {
            require_feature(cfg!(feature = "hickory-dns"))?;
            set.set_str(S::DnsLocalIp6, s);
        }

        // ---- removed / unsupported ---------------------------------------
        // CURLOPT_KRBLEVEL was removed in curl 8.17.0.
        O::CURLOPT_KRBLEVEL => return Err(CurlError::NotBuiltIn),

        _ => return Err(CurlError::UnknownOption),
    }
    Ok(())
}

// ===========================================================================
// FunctionPoint / OffT / Blob handlers (setopt_func, setopt_offt, setopt_blob)
// ===========================================================================

/// Callback-pointer options (`setopt_func`). Each stores the opaque callback
/// address; a NULL callback is a valid value that selects curl's internal
/// default behavior for that hook.
fn apply_func(set: &mut UserDefined, opt: CurlOption, cb: CCallback) -> Result<()> {
    use CurlOption as O;
    match opt {
        // Progress + transfer-info callbacks. The transfer layer treats a
        // non-null callback as "use the application's progress meter".
        O::CURLOPT_PROGRESSFUNCTION => set.fprogress = cb,
        O::CURLOPT_XFERINFOFUNCTION => set.fxferinfo = cb,
        O::CURLOPT_DEBUGFUNCTION => set.fdebug = cb,
        O::CURLOPT_HEADERFUNCTION => set.fwrite_header = cb,
        // NULL resets to the internal default writer; the writer layer maps a
        // null [`CCallback`] onto that default.
        O::CURLOPT_WRITEFUNCTION => set.fwrite_func = cb,
        O::CURLOPT_READFUNCTION => {
            set.fread_func_set = cb;
            // A NULL read callback reverts to the internal default reader.
            set.is_fread_set = !cb.is_null();
        }
        O::CURLOPT_SEEKFUNCTION => set.seek_func = cb,
        O::CURLOPT_IOCTLFUNCTION => set.ioctl_func = cb,
        // rustls has no SSL_CTX, so the OpenSSL-style SSL_CTX hook is refused.
        O::CURLOPT_SSL_CTX_FUNCTION => return Err(CurlError::NotBuiltIn),
        O::CURLOPT_SOCKOPTFUNCTION => set.fsockopt = cb,
        O::CURLOPT_OPENSOCKETFUNCTION => set.fopensocket = cb,
        O::CURLOPT_CLOSESOCKETFUNCTION => set.fclosesocket = cb,
        O::CURLOPT_RESOLVER_START_FUNCTION => set.resolver_start = cb,
        O::CURLOPT_SSH_HOSTKEYFUNCTION => {
            require_feature(cfg!(any(feature = "scp", feature = "sftp")))?;
            set.ssh_hostkeyfunc = cb;
        }
        O::CURLOPT_SSH_KEYFUNCTION => {
            require_feature(cfg!(any(feature = "scp", feature = "sftp")))?;
            set.ssh_keyfunc = cb;
        }
        O::CURLOPT_INTERLEAVEFUNCTION => {
            require_feature(cfg!(feature = "rtsp"))?;
            set.fwrite_rtp = cb;
        }
        O::CURLOPT_CHUNK_BGN_FUNCTION => {
            require_feature(cfg!(feature = "ftp"))?;
            set.chunk_bgn = cb;
        }
        O::CURLOPT_CHUNK_END_FUNCTION => {
            require_feature(cfg!(feature = "ftp"))?;
            set.chunk_end = cb;
        }
        O::CURLOPT_FNMATCH_FUNCTION => {
            require_feature(cfg!(feature = "ftp"))?;
            set.fnmatch = cb;
        }
        O::CURLOPT_TRAILERFUNCTION => {
            require_feature(cfg!(feature = "http"))?;
            set.trailer_callback = cb;
        }
        O::CURLOPT_HSTSREADFUNCTION => {
            require_feature(cfg!(feature = "hsts"))?;
            set.hsts_read = cb;
        }
        O::CURLOPT_HSTSWRITEFUNCTION => {
            require_feature(cfg!(feature = "hsts"))?;
            set.hsts_write = cb;
        }
        O::CURLOPT_PREREQFUNCTION => set.fprereq = cb,
        // Any other function-pointer id (e.g. the removed CONV_* hooks) is not
        // handled and reports an unknown option.
        _ => return Err(CurlError::UnknownOption),
    }
    Ok(())
}

/// `curl_off_t` options (`setopt_offt`). The negative-value guards exactly
/// reproduce curl's per-option validation.
fn apply_offt(set: &mut UserDefined, opt: CurlOption, offt: i64) -> Result<()> {
    use CurlOption as O;
    match opt {
        O::CURLOPT_TIMEVALUE_LARGE => set.timevalue = offt,
        O::CURLOPT_POSTFIELDSIZE_LARGE => {
            if offt < -1 {
                return Err(CurlError::BadFunctionArgument);
            }
            // Growing the declared size past a previously copied body
            // invalidates that copy (curl compares postfields == copy).
            if set.postfieldsize < offt && set.copypostfields.is_some() {
                set.copypostfields = None;
                set.postfields = None;
            }
            set.postfieldsize = offt;
        }
        O::CURLOPT_INFILESIZE_LARGE => {
            if offt < -1 {
                return Err(CurlError::BadFunctionArgument);
            }
            set.filesize = offt;
        }
        O::CURLOPT_MAX_SEND_SPEED_LARGE => {
            if offt < 0 {
                return Err(CurlError::BadFunctionArgument);
            }
            set.max_send_speed = offt;
        }
        O::CURLOPT_MAX_RECV_SPEED_LARGE => {
            if offt < 0 {
                return Err(CurlError::BadFunctionArgument);
            }
            set.max_recv_speed = offt;
        }
        O::CURLOPT_RESUME_FROM_LARGE => {
            if offt < -1 {
                return Err(CurlError::BadFunctionArgument);
            }
            set.set_resume_from = offt;
        }
        O::CURLOPT_MAXFILESIZE_LARGE => {
            if offt < 0 {
                return Err(CurlError::BadFunctionArgument);
            }
            set.max_filesize = offt;
        }
        _ => return Err(CurlError::UnknownOption),
    }
    Ok(())
}

/// `struct curl_blob *` options (`setopt_blob`). Mirrors `Curl_setblobopt`:
/// the destination slot is cleared first, then the size cap is enforced, then
/// the (copied) blob is stored.
fn apply_blob(set: &mut UserDefined, opt: CurlOption, blob: Option<Blob>) -> Result<()> {
    use BlobId as B;
    use CurlOption as O;

    // Resolve the destination slot (and any per-option side effects) first so
    // that the clear-then-validate ordering matches Curl_setblobopt exactly.
    let id = match opt {
        O::CURLOPT_SSLCERT_BLOB => B::Cert,
        O::CURLOPT_SSLKEY_BLOB => B::Key,
        O::CURLOPT_ISSUERCERT_BLOB => B::SslIssuercert,
        O::CURLOPT_CAINFO_BLOB => {
            set.ssl.custom_cablob = true;
            B::Cainfo
        }
        O::CURLOPT_PROXY_SSLCERT_BLOB => {
            require_feature(cfg!(feature = "proxy"))?;
            B::CertProxy
        }
        O::CURLOPT_PROXY_SSLKEY_BLOB => {
            require_feature(cfg!(feature = "proxy"))?;
            B::KeyProxy
        }
        O::CURLOPT_PROXY_CAINFO_BLOB => {
            require_feature(cfg!(feature = "proxy"))?;
            B::CainfoProxy
        }
        O::CURLOPT_PROXY_ISSUERCERT_BLOB => {
            require_feature(cfg!(feature = "proxy"))?;
            B::SslIssuercertProxy
        }
        _ => return Err(CurlError::UnknownOption),
    };

    // Free the previous storage before validating the new blob (curl frees
    // first, then range-checks).
    set.set_blob(id, None);
    if let Some(b) = blob {
        if b.data.len() > CURL_MAX_INPUT_LENGTH {
            return Err(CurlError::BadFunctionArgument);
        }
        set.set_blob(id, Some(b));
    }
    Ok(())
}

// ===========================================================================
// Unit tests
// ===========================================================================
//
// These tests pin the option-application semantics against the C oracle
// (`lib/setopt.c` `Curl_vsetopt` + `lib/url.c` `Curl_init_userdefined`). They
// deliberately exercise one representative option per `CURLOPTTYPE_*` group
// plus the cross-cutting behaviours that the rewrite must preserve byte for
// byte: the default settings, range clamping, value validation, the
// unknown/bad-argument/not-built-in error mapping, and the feature gating.
//
// Tests that depend on an optional Cargo feature are themselves feature-gated
// so the suite is correct under any feature configuration (including
// `--no-default-features`).
#[cfg(test)]
mod tests {
    use super::*;
    use CurlOption as O;
    use OptionValue as V;

    // -- defaults ----------------------------------------------------------

    /// Every default below is taken from `Curl_init_userdefined` (lib/url.c).
    /// If any of these drift the CLI/FFI inherit the wrong starting state.
    #[test]
    fn defaults_match_curl_init_userdefined() {
        let s = UserDefined::new();
        assert_eq!(s.httpauth, CURLAUTH_BASIC, "auth defaults to Basic");
        assert_eq!(s.postfieldsize, -1, "no POST body size known yet");
        assert_eq!(s.filesize, -1, "INFILESIZE unknown");
        assert_eq!(s.max_filesize, 0, "no download size cap");
        assert_eq!(s.maxredirs, 30, "curl's default redirect cap");
        assert_eq!(s.method, HttpReq::Get, "GET unless changed");
        assert_eq!(s.use_port, 0, "no explicit port");
        assert_eq!(s.buffer_size, CURL_READ_BUFFER_DEFAULT);
        assert_eq!(s.upload_buffer_size, CURL_UPLOAD_BUFFER_DEFAULT);
        assert_eq!(s.timeout, 0, "no overall timeout");
        assert_eq!(s.connecttimeout, 0, "no connect timeout");
        assert_eq!(s.allowed_protocols, CURLPROTO_ALL);
        assert_eq!(s.redir_protocols, CURLPROTO_REDIR);
        assert_eq!(s.expect_100_timeout, 1000, "1s Expect: 100 wait");
        assert_eq!(s.new_directory_perms, 0o755);
        assert_eq!(s.new_file_perms, 0o644);
        assert_eq!(s.ftp_filemethod, CURL_FTPMETHOD_MULTICWD);
        assert!(s.ssl_enable_alpn, "ALPN on by default");
        assert!(s.tcp_nodelay, "TCP_NODELAY on by default");
        assert!(s.ftp_use_epsv, "EPSV on by default");
        // The cornerstone safety default: certificate validation is ON.
        assert!(s.ssl.primary.verifypeer);
        assert!(s.ssl.primary.verifyhost);
        assert!(s.ssl.primary.cache_session);
        // No string/blob option is populated on a fresh handle.
        assert_eq!(s.str(StrId::SetUrl), None);
        assert_eq!(s.str(StrId::Username), None);
        assert_eq!(s.blob(BlobId::Cert), None);
    }

    // -- LONG group: booleans + method shaping -----------------------------

    #[test]
    fn long_bool_flags_round_trip() {
        let mut s = UserDefined::new();
        apply(&mut s, O::CURLOPT_VERBOSE, V::Long(1)).unwrap();
        assert!(s.verbose);
        apply(&mut s, O::CURLOPT_VERBOSE, V::Long(0)).unwrap();
        assert!(!s.verbose);
        apply(&mut s, O::CURLOPT_HEADER, V::Long(1)).unwrap();
        assert!(s.include_header);
        apply(&mut s, O::CURLOPT_NOPROGRESS, V::Long(1)).unwrap();
        assert!(s.noprogress);
    }

    #[test]
    fn long_upload_sets_put_method() {
        let mut s = UserDefined::new();
        apply(&mut s, O::CURLOPT_UPLOAD, V::Long(1)).unwrap();
        assert_eq!(s.method, HttpReq::Put);
        assert!(!s.opt_no_body);
        // Disabling upload reverts to GET (curl's documented behaviour).
        apply(&mut s, O::CURLOPT_UPLOAD, V::Long(0)).unwrap();
        assert_eq!(s.method, HttpReq::Get);
    }

    // -- LONG group: range validation + clamping ---------------------------

    #[test]
    fn long_port_range_validated() {
        let mut s = UserDefined::new();
        apply(&mut s, O::CURLOPT_PORT, V::Long(8080)).unwrap();
        assert_eq!(s.use_port, 8080);
        assert_eq!(
            apply(&mut s, O::CURLOPT_PORT, V::Long(70_000)),
            Err(CurlError::BadFunctionArgument),
            "ports above 65535 are rejected"
        );
        assert_eq!(
            apply(&mut s, O::CURLOPT_PORT, V::Long(-1)),
            Err(CurlError::BadFunctionArgument),
            "negative ports are rejected"
        );
    }

    #[test]
    fn long_buffersize_clamps_both_ends() {
        let mut s = UserDefined::new();
        // Below the floor clamps up to READBUFFER_MIN.
        apply(&mut s, O::CURLOPT_BUFFERSIZE, V::Long(100)).unwrap();
        assert_eq!(s.buffer_size, READBUFFER_MIN as u32);
        // Above the ceiling clamps down to READBUFFER_MAX.
        apply(&mut s, O::CURLOPT_BUFFERSIZE, V::Long(i64::from(i32::MAX))).unwrap();
        assert_eq!(s.buffer_size, READBUFFER_MAX as u32);
        // Negative is an outright error (value_range `below_error` == 0).
        assert_eq!(
            apply(&mut s, O::CURLOPT_BUFFERSIZE, V::Long(-1)),
            Err(CurlError::BadFunctionArgument)
        );
    }

    #[test]
    fn long_timeout_seconds_scaled_to_ms() {
        let mut s = UserDefined::new();
        apply(&mut s, O::CURLOPT_TIMEOUT, V::Long(30)).unwrap();
        assert_eq!(s.timeout, 30_000, "seconds are multiplied by 1000");
        apply(&mut s, O::CURLOPT_TIMEOUT_MS, V::Long(1500)).unwrap();
        assert_eq!(s.timeout, 1500, "the _MS variant is stored verbatim");
        assert_eq!(
            apply(&mut s, O::CURLOPT_TIMEOUT, V::Long(-1)),
            Err(CurlError::BadFunctionArgument)
        );
    }

    #[test]
    fn long_maxredirs_allows_unlimited_sentinel() {
        let mut s = UserDefined::new();
        apply(&mut s, O::CURLOPT_MAXREDIRS, V::Long(5)).unwrap();
        assert_eq!(s.maxredirs, 5);
        // -1 means "unlimited" and is accepted (value_range below_error == -1).
        apply(&mut s, O::CURLOPT_MAXREDIRS, V::Long(-1)).unwrap();
        assert_eq!(s.maxredirs, -1);
        // Anything below -1 is rejected.
        assert_eq!(
            apply(&mut s, O::CURLOPT_MAXREDIRS, V::Long(-2)),
            Err(CurlError::BadFunctionArgument)
        );
    }

    #[test]
    fn long_httpauth_basic_selected() {
        let mut s = UserDefined::new();
        apply(
            &mut s,
            O::CURLOPT_HTTPAUTH,
            V::Long(i64::from(CURLAUTH_BASIC)),
        )
        .unwrap();
        assert_eq!(s.httpauth, CURLAUTH_BASIC);
    }

    // -- LONG group: SSL version validation (TLS is always built) ----------

    #[test]
    fn long_sslversion_validates() {
        let mut s = UserDefined::new();
        apply(
            &mut s,
            O::CURLOPT_SSLVERSION,
            V::Long(CURL_SSLVERSION_TLSV1_2),
        )
        .unwrap();
        assert_eq!(s.ssl.primary.version, CURL_SSLVERSION_TLSV1_2 as u8);
        // SSLv2 is forbidden outright.
        assert_eq!(
            apply(
                &mut s,
                O::CURLOPT_SSLVERSION,
                V::Long(CURL_SSLVERSION_SSLV2)
            ),
            Err(CurlError::BadFunctionArgument)
        );
    }

    // -- STRINGPOINT group -------------------------------------------------

    #[test]
    fn string_url_stored_and_cleared() {
        let mut s = UserDefined::new();
        apply(
            &mut s,
            O::CURLOPT_URL,
            V::Str(Some("https://example.com/".into())),
        )
        .unwrap();
        assert_eq!(s.str(StrId::SetUrl), Some("https://example.com/"));
        // A NULL argument clears the option.
        apply(&mut s, O::CURLOPT_URL, V::Str(None)).unwrap();
        assert_eq!(s.str(StrId::SetUrl), None);
    }

    #[test]
    fn string_userpwd_splits_on_first_colon() {
        let mut s = UserDefined::new();
        apply(
            &mut s,
            O::CURLOPT_USERPWD,
            V::Str(Some("alice:secret".into())),
        )
        .unwrap();
        assert_eq!(s.str(StrId::Username), Some("alice"));
        assert_eq!(s.str(StrId::Password), Some("secret"));
        // A NULL argument clears both halves.
        apply(&mut s, O::CURLOPT_USERPWD, V::Str(None)).unwrap();
        assert_eq!(s.str(StrId::Username), None);
        assert_eq!(s.str(StrId::Password), None);
    }

    #[test]
    fn string_interface_parses_prefixes() {
        let mut s = UserDefined::new();
        // Bare name → device.
        apply(&mut s, O::CURLOPT_INTERFACE, V::Str(Some("eth0".into()))).unwrap();
        assert_eq!(s.str(StrId::Device), Some("eth0"));
        // "if!" prefix → interface, and the device slot is cleared.
        apply(
            &mut s,
            O::CURLOPT_INTERFACE,
            V::Str(Some("if!wlan0".into())),
        )
        .unwrap();
        assert_eq!(s.str(StrId::Interface), Some("wlan0"));
        assert_eq!(s.str(StrId::Device), None);
    }

    #[test]
    fn string_over_input_limit_rejected() {
        let mut s = UserDefined::new();
        let huge = "x".repeat(CURL_MAX_INPUT_LENGTH + 1);
        assert_eq!(
            apply(&mut s, O::CURLOPT_USERPWD, V::Str(Some(huge))),
            Err(CurlError::BadFunctionArgument),
            "strings longer than CURL_MAX_INPUT_LENGTH are rejected"
        );
    }

    // -- OFF_T group -------------------------------------------------------

    #[test]
    fn offt_infilesize_and_speed_limits() {
        let mut s = UserDefined::new();
        apply(&mut s, O::CURLOPT_INFILESIZE_LARGE, V::OffT(1024)).unwrap();
        assert_eq!(s.filesize, 1024);
        // -1 (unknown size) is accepted for INFILESIZE_LARGE...
        apply(&mut s, O::CURLOPT_INFILESIZE_LARGE, V::OffT(-1)).unwrap();
        assert_eq!(s.filesize, -1);
        // ...but anything below -1 is rejected.
        assert_eq!(
            apply(&mut s, O::CURLOPT_INFILESIZE_LARGE, V::OffT(-2)),
            Err(CurlError::BadFunctionArgument)
        );
        // Speed caps reject any negative value.
        apply(&mut s, O::CURLOPT_MAX_RECV_SPEED_LARGE, V::OffT(5000)).unwrap();
        assert_eq!(s.max_recv_speed, 5000);
        assert_eq!(
            apply(&mut s, O::CURLOPT_MAX_RECV_SPEED_LARGE, V::OffT(-1)),
            Err(CurlError::BadFunctionArgument)
        );
    }

    // -- BLOB group --------------------------------------------------------

    #[test]
    fn blob_stored_then_size_limited_clears_first() {
        let mut s = UserDefined::new();
        let blob = Blob {
            data: vec![1, 2, 3, 4],
            flags: 0,
        };
        apply(&mut s, O::CURLOPT_SSLCERT_BLOB, V::Blob(Some(blob.clone()))).unwrap();
        assert_eq!(s.blob(BlobId::Cert), Some(&blob));
        // An oversized blob is rejected, and — matching curl's free-then-check
        // order — the previously stored blob is cleared first.
        let huge = Blob {
            data: vec![0u8; CURL_MAX_INPUT_LENGTH + 1],
            flags: 0,
        };
        assert_eq!(
            apply(&mut s, O::CURLOPT_SSLCERT_BLOB, V::Blob(Some(huge))),
            Err(CurlError::BadFunctionArgument)
        );
        assert_eq!(
            s.blob(BlobId::Cert),
            None,
            "old blob freed before validation"
        );
    }

    // -- OBJECTPOINT group: slist (ungated option) -------------------------

    #[test]
    fn slist_resolve_stored() {
        let mut s = UserDefined::new();
        let mut list = SList::default();
        list.append("example.com:443:127.0.0.1").unwrap();
        apply(&mut s, O::CURLOPT_RESOLVE, V::Slist(Some(list.clone()))).unwrap();
        assert_eq!(s.resolve, Some(list));
    }

    // -- FUNCTIONPOINT group -----------------------------------------------

    #[test]
    fn func_write_and_read_callbacks() {
        let mut s = UserDefined::new();
        apply(
            &mut s,
            O::CURLOPT_WRITEFUNCTION,
            V::Callback(CCallback(0x1234)),
        )
        .unwrap();
        assert_eq!(s.fwrite_func, CCallback(0x1234));
        // A non-null read callback flips the "user reader installed" flag.
        apply(
            &mut s,
            O::CURLOPT_READFUNCTION,
            V::Callback(CCallback(0x99)),
        )
        .unwrap();
        assert!(s.is_fread_set);
        // A NULL read callback reverts to the internal default reader.
        apply(
            &mut s,
            O::CURLOPT_READFUNCTION,
            V::Callback(CCallback::NULL),
        )
        .unwrap();
        assert!(!s.is_fread_set);
    }

    #[test]
    fn func_ssl_ctx_function_not_built_in() {
        let mut s = UserDefined::new();
        // rustls exposes no OpenSSL-style SSL_CTX hook.
        assert_eq!(
            apply(
                &mut s,
                O::CURLOPT_SSL_CTX_FUNCTION,
                V::Callback(CCallback(0x1))
            ),
            Err(CurlError::NotBuiltIn)
        );
    }

    // -- OBJECTPOINT group: data pointers + share --------------------------

    #[test]
    fn pointers_data_private_and_share() {
        let mut s = UserDefined::new();
        apply(&mut s, O::CURLOPT_WRITEDATA, V::Ptr(CDataPtr(0xdead))).unwrap();
        assert_eq!(s.out, CDataPtr(0xdead));
        apply(&mut s, O::CURLOPT_PRIVATE, V::Ptr(CDataPtr(0xbeef))).unwrap();
        assert_eq!(s.private_data, CDataPtr(0xbeef));
        // Attaching and detaching a share handle.
        apply(&mut s, O::CURLOPT_SHARE, V::Share(Some(Share::new()))).unwrap();
        assert!(s.share.is_some());
        apply(&mut s, O::CURLOPT_SHARE, V::Share(None)).unwrap();
        assert!(s.share.is_none());
    }

    // -- error mapping -----------------------------------------------------

    #[test]
    fn unknown_option_reported() {
        let mut s = UserDefined::new();
        // A real curl option id that this rewrite does not implement maps to
        // CURLE_UNKNOWN_OPTION (it is a FUNCTIONPOINT with no handler arm).
        assert_eq!(
            apply(
                &mut s,
                O::CURLOPT_CONV_FROM_NETWORK_FUNCTION,
                V::Callback(CCallback(0x1))
            ),
            Err(CurlError::UnknownOption)
        );
    }

    #[test]
    fn ssl_ctx_data_not_built_in() {
        let mut s = UserDefined::new();
        assert_eq!(
            apply(&mut s, O::CURLOPT_SSL_CTX_DATA, V::Ptr(CDataPtr(0x1))),
            Err(CurlError::NotBuiltIn)
        );
    }

    #[test]
    fn type_mismatch_is_bad_argument() {
        let mut s = UserDefined::new();
        // PORT is a LONG option; handing it a string is a bad argument, exactly
        // as the variadic FFI would surface a wrongly-typed trailing argument.
        assert_eq!(
            apply(&mut s, O::CURLOPT_PORT, V::Str(Some("80".into()))),
            Err(CurlError::BadFunctionArgument)
        );
    }

    // -- feature gating: HTTP ---------------------------------------------

    #[cfg(feature = "http")]
    #[test]
    fn http_nobody_sets_head_request() {
        let mut s = UserDefined::new();
        apply(&mut s, O::CURLOPT_NOBODY, V::Long(1)).unwrap();
        assert!(s.opt_no_body);
        assert_eq!(s.method, HttpReq::Head);
        // Clearing NOBODY reverts a HEAD back to GET.
        apply(&mut s, O::CURLOPT_NOBODY, V::Long(0)).unwrap();
        assert!(!s.opt_no_body);
        assert_eq!(s.method, HttpReq::Get);
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_post_then_get_methods() {
        let mut s = UserDefined::new();
        apply(&mut s, O::CURLOPT_POST, V::Long(1)).unwrap();
        assert_eq!(s.method, HttpReq::Post);
        apply(&mut s, O::CURLOPT_HTTPGET, V::Long(1)).unwrap();
        assert_eq!(s.method, HttpReq::Get);
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_useragent_and_referer_strings() {
        let mut s = UserDefined::new();
        apply(
            &mut s,
            O::CURLOPT_USERAGENT,
            V::Str(Some("curl-rs/1.0".into())),
        )
        .unwrap();
        assert_eq!(s.str(StrId::Useragent), Some("curl-rs/1.0"));
        apply(
            &mut s,
            O::CURLOPT_REFERER,
            V::Str(Some("https://ref.example/".into())),
        )
        .unwrap();
        assert_eq!(s.str(StrId::SetReferer), Some("https://ref.example/"));
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_accept_encoding_empty_expands_to_all() {
        let mut s = UserDefined::new();
        // An empty string expands to the full supported-encoding list.
        apply(
            &mut s,
            O::CURLOPT_ACCEPT_ENCODING,
            V::Str(Some(String::new())),
        )
        .unwrap();
        let enc = all_content_encodings();
        assert_eq!(s.str(StrId::Encoding), Some(enc.as_str()));
        // A specific value is stored verbatim.
        apply(
            &mut s,
            O::CURLOPT_ACCEPT_ENCODING,
            V::Str(Some("gzip".into())),
        )
        .unwrap();
        assert_eq!(s.str(StrId::Encoding), Some("gzip"));
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_header_slist_stored() {
        let mut s = UserDefined::new();
        let mut list = SList::default();
        list.append("X-Test: 1").unwrap();
        apply(&mut s, O::CURLOPT_HTTPHEADER, V::Slist(Some(list.clone()))).unwrap();
        assert_eq!(s.headers, Some(list));
    }

    #[cfg(not(feature = "http"))]
    #[test]
    fn http_option_not_built_in_when_disabled() {
        let mut s = UserDefined::new();
        assert_eq!(
            apply(&mut s, O::CURLOPT_HTTPGET, V::Long(1)),
            Err(CurlError::NotBuiltIn)
        );
    }

    // -- feature gating: proxy --------------------------------------------

    #[cfg(feature = "proxy")]
    #[test]
    fn proxy_string_stored_when_enabled() {
        let mut s = UserDefined::new();
        apply(
            &mut s,
            O::CURLOPT_PROXY,
            V::Str(Some("http://proxy:3128".into())),
        )
        .unwrap();
        assert_eq!(s.str(StrId::Proxy), Some("http://proxy:3128"));
    }

    #[cfg(not(feature = "proxy"))]
    #[test]
    fn proxy_option_not_built_in_when_disabled() {
        let mut s = UserDefined::new();
        assert_eq!(
            apply(&mut s, O::CURLOPT_PROXY, V::Str(Some("http://p".into()))),
            Err(CurlError::NotBuiltIn)
        );
    }

    // -- feature gating: cookies ------------------------------------------

    #[cfg(feature = "cookies")]
    #[test]
    fn cookie_string_and_jar_enable_engine() {
        let mut s = UserDefined::new();
        apply(&mut s, O::CURLOPT_COOKIE, V::Str(Some("a=b".into()))).unwrap();
        assert_eq!(s.str(StrId::Cookie), Some("a=b"));
        apply(&mut s, O::CURLOPT_COOKIEJAR, V::Str(Some("jar.txt".into()))).unwrap();
        assert_eq!(s.str(StrId::Cookiejar), Some("jar.txt"));
        assert!(s.cookie_engine, "setting a cookie jar turns the engine on");
    }

    // -- feature gating: AWS SigV4 ----------------------------------------

    #[cfg(feature = "aws-sigv4")]
    #[test]
    fn aws_sigv4_overrides_auth_selection() {
        let mut s = UserDefined::new();
        apply(&mut s, O::CURLOPT_AWS_SIGV4, V::Str(Some("aws:amz".into()))).unwrap();
        assert_eq!(s.str(StrId::AwsSigv4), Some("aws:amz"));
        assert_eq!(s.httpauth, CURLAUTH_AWS_SIGV4);
    }

    // -- feature gating: hickory-dns (off by default) ---------------------

    #[cfg(not(feature = "hickory-dns"))]
    #[test]
    fn dns_servers_not_built_in_by_default() {
        let mut s = UserDefined::new();
        assert_eq!(
            apply(
                &mut s,
                O::CURLOPT_DNS_SERVERS,
                V::Str(Some("8.8.8.8".into()))
            ),
            Err(CurlError::NotBuiltIn)
        );
    }
}
