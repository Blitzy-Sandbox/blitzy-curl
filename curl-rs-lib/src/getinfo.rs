// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
// Rust rewrite of lib/getinfo.c (676 lines) — implements info retrieval
// after a transfer completes, equivalent to `curl_easy_getinfo()`.
//
// Design notes:
//   * `CurlInfo` is a `#[repr(i32)]` enum whose discriminant values match
//     the C `CURLINFO` integer values defined in `include/curl/curl.h`
//     exactly — this is critical for FFI compatibility.
//   * `PureInfo` consolidates the session/transfer state fields that the C
//     implementation scatters across `struct Curl_easy`, `struct Progress`,
//     `struct PureInfo`, and `struct UrlState`. The `EasyHandle` (defined
//     elsewhere) owns a `PureInfo` and passes a reference to these
//     retrieval functions.
//   * Five typed retrieval functions (`get_info_string`, `get_info_long`,
//     `get_info_double`, `get_info_off_t`, `get_info_slist`) replace the C
//     variadic `Curl_getinfo`. Each validates the info ID against its own
//     type category and returns `CurlError::UnknownOption` on mismatch.
//   * Zero `unsafe` blocks — all data is stored in Rust-native types.

use crate::error::{CurlError, CurlResult};
use crate::slist::SList;

// ---------------------------------------------------------------------------
// CURLINFO type-mask constants (matching include/curl/curl.h exactly)
// ---------------------------------------------------------------------------

/// Type mask for string-returning CURLINFO values.
pub const CURLINFO_STRING: i32 = 0x100000;

/// Type mask for long-returning CURLINFO values.
pub const CURLINFO_LONG: i32 = 0x200000;

/// Type mask for double-returning CURLINFO values.
pub const CURLINFO_DOUBLE: i32 = 0x300000;

/// Type mask for slist/ptr-returning CURLINFO values.
pub const CURLINFO_SLIST: i32 = 0x400000;

/// Type mask for socket-returning CURLINFO values.
pub const CURLINFO_SOCKET: i32 = 0x500000;

/// Type mask for off_t-returning CURLINFO values.
pub const CURLINFO_OFF_T: i32 = 0x600000;

/// Mask to extract the info ID number (low 20 bits) from a CURLINFO value.
pub const CURLINFO_MASK: i32 = 0x0f_ffff;

/// Mask to extract the type category (high nibble of the third byte) from a
/// CURLINFO value.
pub const CURLINFO_TYPEMASK: i32 = 0xf0_0000;

// ---------------------------------------------------------------------------
// CurlInfoType — runtime type category
// ---------------------------------------------------------------------------

/// Runtime type category of a [`CurlInfo`] value.
///
/// Determined by applying [`CURLINFO_TYPEMASK`] to the raw integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlInfoType {
    /// String value (`const char **`).
    String,
    /// Long integer value (`long *`).
    Long,
    /// Double-precision float value (`double *`).
    Double,
    /// Linked-list / pointer value (`struct curl_slist **`).
    SList,
    /// Socket descriptor value (`curl_socket_t *`).
    Socket,
    /// Large integer value (`curl_off_t *`).
    OffT,
}

// ---------------------------------------------------------------------------
// CurlInfo — the complete CURLINFO enum
// ---------------------------------------------------------------------------

/// Identifies a piece of transfer information to retrieve via
/// `curl_easy_getinfo`.
///
/// Every variant carries the exact integer discriminant value from
/// `include/curl/curl.h`, making FFI round-trips lossless.
///
/// Deprecated variants (e.g. `SizeUpload`, `LastSocket`) are retained for
/// ABI compatibility but should be avoided in new code in favour of their
/// `_T` / `ActiveSocket` replacements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlInfo {
    /// Sentinel — never use this (CURLINFO_NONE = 0).
    None = 0,

    // -- String values (CURLINFO_STRING = 0x100000) --
    /// Last effective URL (CURLINFO_EFFECTIVE_URL).
    EffectiveUrl          = CURLINFO_STRING + 1,
    /// Content-Type header value (CURLINFO_CONTENT_TYPE).
    ContentType           = CURLINFO_STRING + 18,
    /// Private pointer previously set (CURLINFO_PRIVATE).
    Private               = CURLINFO_STRING + 21,
    /// FTP entry path (CURLINFO_FTP_ENTRY_PATH).
    FtpEntryPath          = CURLINFO_STRING + 30,
    /// Redirect URL if redirects were not followed (CURLINFO_REDIRECT_URL).
    RedirectUrl           = CURLINFO_STRING + 31,
    /// IP address of the last connection (CURLINFO_PRIMARY_IP).
    PrimaryIp             = CURLINFO_STRING + 32,
    /// RTSP session ID (CURLINFO_RTSP_SESSION_ID).
    RtspSessionId         = CURLINFO_STRING + 36,
    /// Local-side IP address (CURLINFO_LOCAL_IP).
    LocalIp               = CURLINFO_STRING + 41,
    /// URL scheme used (CURLINFO_SCHEME).
    Scheme                = CURLINFO_STRING + 49,
    /// Effective HTTP method (CURLINFO_EFFECTIVE_METHOD).
    EffectiveMethod       = CURLINFO_STRING + 58,
    /// Referrer header (CURLINFO_REFERER).
    Referer               = CURLINFO_STRING + 60,
    /// Default CA info path (CURLINFO_CAINFO).
    CaInfo                = CURLINFO_STRING + 61,
    /// Default CA path (CURLINFO_CAPATH).
    CaPath                = CURLINFO_STRING + 62,

    // -- Long values (CURLINFO_LONG = 0x200000) --
    /// Last HTTP response code (CURLINFO_RESPONSE_CODE).
    ResponseCode          = CURLINFO_LONG + 2,
    /// HTTP response header size in bytes (CURLINFO_HEADER_SIZE).
    HeaderSize            = CURLINFO_LONG + 11,
    /// HTTP request size in bytes (CURLINFO_REQUEST_SIZE).
    RequestSize           = CURLINFO_LONG + 12,
    /// SSL certificate verification result (CURLINFO_SSL_VERIFYRESULT).
    SslVerifyResult       = CURLINFO_LONG + 13,
    /// Remote file modification time (deprecated) (CURLINFO_FILETIME).
    Filetime              = CURLINFO_LONG + 14,
    /// Number of redirects followed (CURLINFO_REDIRECT_COUNT).
    RedirectCount         = CURLINFO_LONG + 20,
    /// Last proxy CONNECT response code (CURLINFO_HTTP_CONNECTCODE).
    HttpConnectCode       = CURLINFO_LONG + 22,
    /// Bitmask of available HTTP auth methods (CURLINFO_HTTPAUTH_AVAIL).
    HttpAuthAvail         = CURLINFO_LONG + 23,
    /// Bitmask of available proxy auth methods (CURLINFO_PROXYAUTH_AVAIL).
    ProxyAuthAvail        = CURLINFO_LONG + 24,
    /// OS errno from last connect failure (CURLINFO_OS_ERRNO).
    OsErrno               = CURLINFO_LONG + 25,
    /// Number of new connections opened (CURLINFO_NUM_CONNECTS).
    NumConnects           = CURLINFO_LONG + 26,
    /// Last socket used (deprecated) (CURLINFO_LASTSOCKET).
    LastSocket            = CURLINFO_LONG + 29,
    /// Whether time-condition was unmet (CURLINFO_CONDITION_UNMET).
    ConditionUnmet        = CURLINFO_LONG + 35,
    /// RTSP client CSeq (CURLINFO_RTSP_CLIENT_CSEQ).
    RtspClientCseq        = CURLINFO_LONG + 37,
    /// RTSP server CSeq (CURLINFO_RTSP_SERVER_CSEQ).
    RtspServerCseq        = CURLINFO_LONG + 38,
    /// RTSP CSeq received (CURLINFO_RTSP_CSEQ_RECV).
    RtspCseqRecv          = CURLINFO_LONG + 39,
    /// Remote port of last connection (CURLINFO_PRIMARY_PORT).
    PrimaryPort           = CURLINFO_LONG + 40,
    /// Local port of last connection (CURLINFO_LOCAL_PORT).
    LocalPort             = CURLINFO_LONG + 42,
    /// HTTP version used (CURLINFO_HTTP_VERSION).
    HttpVersion           = CURLINFO_LONG + 46,
    /// Proxy SSL certificate verification result
    /// (CURLINFO_PROXY_SSL_VERIFYRESULT).
    ProxySslVerifyResult  = CURLINFO_LONG + 47,
    /// Protocol used (deprecated) (CURLINFO_PROTOCOL).
    Protocol              = CURLINFO_LONG + 48,
    /// Detailed proxy error code (CURLINFO_PROXY_ERROR).
    ProxyError            = CURLINFO_LONG + 59,
    /// Whether a proxy was used (CURLINFO_USED_PROXY).
    UsedProxy             = CURLINFO_LONG + 66,
    /// Bitmask of HTTP auth method used (CURLINFO_HTTPAUTH_USED).
    HttpAuthUsed          = CURLINFO_LONG + 69,
    /// Bitmask of proxy auth method used (CURLINFO_PROXYAUTH_USED).
    ProxyAuthUsed         = CURLINFO_LONG + 70,

    // -- Double values (CURLINFO_DOUBLE = 0x300000) --
    /// Total transfer time in seconds (CURLINFO_TOTAL_TIME).
    TotalTime             = CURLINFO_DOUBLE + 3,
    /// DNS resolution time in seconds (CURLINFO_NAMELOOKUP_TIME).
    NamelookupTime        = CURLINFO_DOUBLE + 4,
    /// TCP connection time in seconds (CURLINFO_CONNECT_TIME).
    ConnectTime           = CURLINFO_DOUBLE + 5,
    /// Pre-transfer time in seconds (CURLINFO_PRETRANSFER_TIME).
    PretransferTime       = CURLINFO_DOUBLE + 6,
    /// Bytes uploaded (deprecated double) (CURLINFO_SIZE_UPLOAD).
    SizeUpload            = CURLINFO_DOUBLE + 7,
    /// Bytes downloaded (deprecated double) (CURLINFO_SIZE_DOWNLOAD).
    SizeDownload          = CURLINFO_DOUBLE + 8,
    /// Average download speed in bytes/sec (deprecated)
    /// (CURLINFO_SPEED_DOWNLOAD).
    SpeedDownload         = CURLINFO_DOUBLE + 9,
    /// Average upload speed in bytes/sec (deprecated)
    /// (CURLINFO_SPEED_UPLOAD).
    SpeedUpload           = CURLINFO_DOUBLE + 10,
    /// Content-Length of download (deprecated double)
    /// (CURLINFO_CONTENT_LENGTH_DOWNLOAD).
    ContentLengthDownload = CURLINFO_DOUBLE + 15,
    /// Content-Length of upload (deprecated double)
    /// (CURLINFO_CONTENT_LENGTH_UPLOAD).
    ContentLengthUpload   = CURLINFO_DOUBLE + 16,
    /// Time to first byte in seconds (CURLINFO_STARTTRANSFER_TIME).
    StarttransferTime     = CURLINFO_DOUBLE + 17,
    /// Total redirect time in seconds (CURLINFO_REDIRECT_TIME).
    RedirectTime          = CURLINFO_DOUBLE + 19,
    /// TLS handshake time in seconds (CURLINFO_APPCONNECT_TIME).
    AppconnectTime        = CURLINFO_DOUBLE + 33,

    // -- SList / Ptr values (CURLINFO_SLIST = 0x400000) --
    /// List of SSL engines (CURLINFO_SSL_ENGINES).
    SslEngines            = CURLINFO_SLIST + 27,
    /// List of cookies (CURLINFO_COOKIELIST).
    CookieList            = CURLINFO_SLIST + 28,
    /// Certificate chain info (CURLINFO_CERTINFO).
    CertInfo              = CURLINFO_SLIST + 34,
    /// TLS session info (deprecated) (CURLINFO_TLS_SESSION).
    TlsSession            = CURLINFO_SLIST + 43,
    /// TLS SSL pointer info (CURLINFO_TLS_SSL_PTR).
    TlsSslPtr             = CURLINFO_SLIST + 45,

    // -- Socket values (CURLINFO_SOCKET = 0x500000) --
    /// Active socket descriptor (CURLINFO_ACTIVESOCKET).
    ActiveSocket          = CURLINFO_SOCKET + 44,

    // -- Off-T values (CURLINFO_OFF_T = 0x600000) --
    /// Bytes uploaded (CURLINFO_SIZE_UPLOAD_T).
    SizeUploadT           = CURLINFO_OFF_T + 7,
    /// Bytes downloaded (CURLINFO_SIZE_DOWNLOAD_T).
    SizeDownloadT         = CURLINFO_OFF_T + 8,
    /// Average download speed in bytes/sec (CURLINFO_SPEED_DOWNLOAD_T).
    SpeedDownloadT        = CURLINFO_OFF_T + 9,
    /// Average upload speed in bytes/sec (CURLINFO_SPEED_UPLOAD_T).
    SpeedUploadT          = CURLINFO_OFF_T + 10,
    /// Remote file modification time (CURLINFO_FILETIME_T).
    FiletimeT             = CURLINFO_OFF_T + 14,
    /// Content-Length of download (CURLINFO_CONTENT_LENGTH_DOWNLOAD_T).
    ContentLengthDownloadT = CURLINFO_OFF_T + 15,
    /// Content-Length of upload (CURLINFO_CONTENT_LENGTH_UPLOAD_T).
    ContentLengthUploadT  = CURLINFO_OFF_T + 16,
    /// Total transfer time in microseconds (CURLINFO_TOTAL_TIME_T).
    TotalTimeT            = CURLINFO_OFF_T + 50,
    /// DNS resolution time in microseconds (CURLINFO_NAMELOOKUP_TIME_T).
    NamelookupTimeT       = CURLINFO_OFF_T + 51,
    /// TCP connection time in microseconds (CURLINFO_CONNECT_TIME_T).
    ConnectTimeT          = CURLINFO_OFF_T + 52,
    /// Pre-transfer time in microseconds (CURLINFO_PRETRANSFER_TIME_T).
    PretransferTimeT      = CURLINFO_OFF_T + 53,
    /// Time to first byte in microseconds (CURLINFO_STARTTRANSFER_TIME_T).
    StarttransferTimeT    = CURLINFO_OFF_T + 54,
    /// Total redirect time in microseconds (CURLINFO_REDIRECT_TIME_T).
    RedirectTimeT         = CURLINFO_OFF_T + 55,
    /// TLS handshake time in microseconds (CURLINFO_APPCONNECT_TIME_T).
    AppconnectTimeT       = CURLINFO_OFF_T + 56,
    /// Retry-After header value in seconds (CURLINFO_RETRY_AFTER).
    RetryAfter            = CURLINFO_OFF_T + 57,
    /// Transfer ID (CURLINFO_XFER_ID).
    XferId                = CURLINFO_OFF_T + 63,
    /// Connection ID (CURLINFO_CONN_ID).
    ConnId                = CURLINFO_OFF_T + 64,
    /// Queue wait time in microseconds (CURLINFO_QUEUE_TIME_T).
    QueueTimeT            = CURLINFO_OFF_T + 65,
    /// Post-transfer time in microseconds (CURLINFO_POSTTRANSFER_TIME_T).
    PosttransferTimeT     = CURLINFO_OFF_T + 67,
    /// Early-data bytes sent (CURLINFO_EARLYDATA_SENT_T).
    EarlydataSentT        = CURLINFO_OFF_T + 68,
}

impl CurlInfo {
    /// Converts a raw C `CURLINFO` integer into the corresponding Rust
    /// variant, or `None` if the value is unrecognised.
    pub fn from_raw(raw: i32) -> Option<CurlInfo> {
        match raw {
            x if x == CurlInfo::None as i32                   => Some(CurlInfo::None),
            // String
            x if x == CurlInfo::EffectiveUrl as i32           => Some(CurlInfo::EffectiveUrl),
            x if x == CurlInfo::ContentType as i32            => Some(CurlInfo::ContentType),
            x if x == CurlInfo::Private as i32                => Some(CurlInfo::Private),
            x if x == CurlInfo::FtpEntryPath as i32           => Some(CurlInfo::FtpEntryPath),
            x if x == CurlInfo::RedirectUrl as i32            => Some(CurlInfo::RedirectUrl),
            x if x == CurlInfo::PrimaryIp as i32              => Some(CurlInfo::PrimaryIp),
            x if x == CurlInfo::RtspSessionId as i32          => Some(CurlInfo::RtspSessionId),
            x if x == CurlInfo::LocalIp as i32                => Some(CurlInfo::LocalIp),
            x if x == CurlInfo::Scheme as i32                 => Some(CurlInfo::Scheme),
            x if x == CurlInfo::EffectiveMethod as i32        => Some(CurlInfo::EffectiveMethod),
            x if x == CurlInfo::Referer as i32                => Some(CurlInfo::Referer),
            x if x == CurlInfo::CaInfo as i32                 => Some(CurlInfo::CaInfo),
            x if x == CurlInfo::CaPath as i32                 => Some(CurlInfo::CaPath),
            // Long
            x if x == CurlInfo::ResponseCode as i32           => Some(CurlInfo::ResponseCode),
            x if x == CurlInfo::HeaderSize as i32             => Some(CurlInfo::HeaderSize),
            x if x == CurlInfo::RequestSize as i32            => Some(CurlInfo::RequestSize),
            x if x == CurlInfo::SslVerifyResult as i32        => Some(CurlInfo::SslVerifyResult),
            x if x == CurlInfo::Filetime as i32               => Some(CurlInfo::Filetime),
            x if x == CurlInfo::RedirectCount as i32          => Some(CurlInfo::RedirectCount),
            x if x == CurlInfo::HttpConnectCode as i32        => Some(CurlInfo::HttpConnectCode),
            x if x == CurlInfo::HttpAuthAvail as i32          => Some(CurlInfo::HttpAuthAvail),
            x if x == CurlInfo::ProxyAuthAvail as i32         => Some(CurlInfo::ProxyAuthAvail),
            x if x == CurlInfo::OsErrno as i32                => Some(CurlInfo::OsErrno),
            x if x == CurlInfo::NumConnects as i32            => Some(CurlInfo::NumConnects),
            x if x == CurlInfo::LastSocket as i32             => Some(CurlInfo::LastSocket),
            x if x == CurlInfo::ConditionUnmet as i32         => Some(CurlInfo::ConditionUnmet),
            x if x == CurlInfo::RtspClientCseq as i32         => Some(CurlInfo::RtspClientCseq),
            x if x == CurlInfo::RtspServerCseq as i32         => Some(CurlInfo::RtspServerCseq),
            x if x == CurlInfo::RtspCseqRecv as i32           => Some(CurlInfo::RtspCseqRecv),
            x if x == CurlInfo::PrimaryPort as i32            => Some(CurlInfo::PrimaryPort),
            x if x == CurlInfo::LocalPort as i32              => Some(CurlInfo::LocalPort),
            x if x == CurlInfo::HttpVersion as i32            => Some(CurlInfo::HttpVersion),
            x if x == CurlInfo::ProxySslVerifyResult as i32   => Some(CurlInfo::ProxySslVerifyResult),
            x if x == CurlInfo::Protocol as i32               => Some(CurlInfo::Protocol),
            x if x == CurlInfo::ProxyError as i32             => Some(CurlInfo::ProxyError),
            x if x == CurlInfo::UsedProxy as i32              => Some(CurlInfo::UsedProxy),
            x if x == CurlInfo::HttpAuthUsed as i32           => Some(CurlInfo::HttpAuthUsed),
            x if x == CurlInfo::ProxyAuthUsed as i32          => Some(CurlInfo::ProxyAuthUsed),
            // Double
            x if x == CurlInfo::TotalTime as i32              => Some(CurlInfo::TotalTime),
            x if x == CurlInfo::NamelookupTime as i32         => Some(CurlInfo::NamelookupTime),
            x if x == CurlInfo::ConnectTime as i32            => Some(CurlInfo::ConnectTime),
            x if x == CurlInfo::PretransferTime as i32        => Some(CurlInfo::PretransferTime),
            x if x == CurlInfo::SizeUpload as i32             => Some(CurlInfo::SizeUpload),
            x if x == CurlInfo::SizeDownload as i32           => Some(CurlInfo::SizeDownload),
            x if x == CurlInfo::SpeedDownload as i32          => Some(CurlInfo::SpeedDownload),
            x if x == CurlInfo::SpeedUpload as i32            => Some(CurlInfo::SpeedUpload),
            x if x == CurlInfo::ContentLengthDownload as i32  => Some(CurlInfo::ContentLengthDownload),
            x if x == CurlInfo::ContentLengthUpload as i32    => Some(CurlInfo::ContentLengthUpload),
            x if x == CurlInfo::StarttransferTime as i32      => Some(CurlInfo::StarttransferTime),
            x if x == CurlInfo::RedirectTime as i32           => Some(CurlInfo::RedirectTime),
            x if x == CurlInfo::AppconnectTime as i32         => Some(CurlInfo::AppconnectTime),
            // SList / Ptr
            x if x == CurlInfo::SslEngines as i32             => Some(CurlInfo::SslEngines),
            x if x == CurlInfo::CookieList as i32             => Some(CurlInfo::CookieList),
            x if x == CurlInfo::CertInfo as i32               => Some(CurlInfo::CertInfo),
            x if x == CurlInfo::TlsSession as i32             => Some(CurlInfo::TlsSession),
            x if x == CurlInfo::TlsSslPtr as i32              => Some(CurlInfo::TlsSslPtr),
            // Socket
            x if x == CurlInfo::ActiveSocket as i32           => Some(CurlInfo::ActiveSocket),
            // Off-T
            x if x == CurlInfo::SizeUploadT as i32            => Some(CurlInfo::SizeUploadT),
            x if x == CurlInfo::SizeDownloadT as i32          => Some(CurlInfo::SizeDownloadT),
            x if x == CurlInfo::SpeedDownloadT as i32         => Some(CurlInfo::SpeedDownloadT),
            x if x == CurlInfo::SpeedUploadT as i32           => Some(CurlInfo::SpeedUploadT),
            x if x == CurlInfo::FiletimeT as i32              => Some(CurlInfo::FiletimeT),
            x if x == CurlInfo::ContentLengthDownloadT as i32 => Some(CurlInfo::ContentLengthDownloadT),
            x if x == CurlInfo::ContentLengthUploadT as i32   => Some(CurlInfo::ContentLengthUploadT),
            x if x == CurlInfo::TotalTimeT as i32             => Some(CurlInfo::TotalTimeT),
            x if x == CurlInfo::NamelookupTimeT as i32        => Some(CurlInfo::NamelookupTimeT),
            x if x == CurlInfo::ConnectTimeT as i32           => Some(CurlInfo::ConnectTimeT),
            x if x == CurlInfo::PretransferTimeT as i32       => Some(CurlInfo::PretransferTimeT),
            x if x == CurlInfo::StarttransferTimeT as i32     => Some(CurlInfo::StarttransferTimeT),
            x if x == CurlInfo::RedirectTimeT as i32          => Some(CurlInfo::RedirectTimeT),
            x if x == CurlInfo::AppconnectTimeT as i32        => Some(CurlInfo::AppconnectTimeT),
            x if x == CurlInfo::RetryAfter as i32             => Some(CurlInfo::RetryAfter),
            x if x == CurlInfo::XferId as i32                 => Some(CurlInfo::XferId),
            x if x == CurlInfo::ConnId as i32                 => Some(CurlInfo::ConnId),
            x if x == CurlInfo::QueueTimeT as i32             => Some(CurlInfo::QueueTimeT),
            x if x == CurlInfo::PosttransferTimeT as i32      => Some(CurlInfo::PosttransferTimeT),
            x if x == CurlInfo::EarlydataSentT as i32         => Some(CurlInfo::EarlydataSentT),
            _ => Option::None,
        }
    }

    /// Returns the raw C `CURLINFO` integer value for this variant.
    #[inline]
    pub fn to_raw(self) -> i32 {
        self as i32
    }
}

// ---------------------------------------------------------------------------
// InfoValue — typed return value
// ---------------------------------------------------------------------------

/// A typed value returned by the info-retrieval functions.
///
/// This replaces the C union + type-dispatch pattern used in `Curl_getinfo`.
#[derive(Debug, Clone)]
pub enum InfoValue {
    /// A string value (may be absent).
    String(Option<String>),
    /// A long integer value.
    Long(i64),
    /// A double-precision float value.
    Double(f64),
    /// A large integer value (`curl_off_t`).
    OffT(i64),
    /// A string list value.
    SList(SList),
    /// A socket descriptor value.
    Socket(i64),
    /// No value (sentinel).
    None,
}

// ---------------------------------------------------------------------------
// PureInfo — consolidated transfer information
// ---------------------------------------------------------------------------

/// Holds all transfer information collected during a curl operation.
///
/// This consolidates the fields that the C implementation scatters across
/// `struct PureInfo`, `struct Progress`, `struct UrlState`, and
/// `struct UserDefined` within `struct Curl_easy`. The `EasyHandle` owns
/// a `PureInfo` and the typed `get_info_*` functions read from it.
#[derive(Debug, Clone)]
pub struct PureInfo {
    // -- String fields --
    /// The last effective URL used (set after all redirects).
    pub effective_url: Option<String>,
    /// The effective HTTP method used (GET, POST, PUT, HEAD, etc.).
    pub effective_method: Option<String>,
    /// The Content-Type header value from the response.
    pub content_type: Option<String>,
    /// URL the server would have redirected to (when redirects are disabled).
    pub redirect_url: Option<String>,
    /// IP address of the remote end of the most recent connection.
    pub primary_ip: Option<String>,
    /// IP address of the local end of the most recent connection.
    pub local_ip: Option<String>,
    /// RTSP session identifier.
    pub rtsp_session_id: Option<String>,
    /// URL scheme of the most recent connection (e.g. "https").
    pub scheme: Option<String>,
    /// Default CA info path for TLS verification.
    pub cainfo: Option<String>,
    /// Default CA path for TLS verification.
    pub capath: Option<String>,
    /// FTP entry path returned by the server.
    pub ftp_entry_path: Option<String>,
    /// Referrer header value.
    pub referer: Option<String>,
    /// User-set private data (stored as an opaque string for the string API).
    pub private_data: Option<String>,

    // -- Long (integer) fields --
    /// The last HTTP response code.
    pub response_code: i64,
    /// The last HTTP CONNECT response code (proxy).
    pub http_connectcode: i64,
    /// Remote file modification time (seconds since epoch, -1 = unknown).
    /// Deprecated long variant — use `filetime_t` instead.
    pub filetime: i64,
    /// Remote file modification time (`curl_off_t`, seconds since epoch).
    pub filetime_t: i64,
    /// HTTP response header size in bytes.
    pub header_size: i64,
    /// HTTP request size in bytes.
    pub request_size: i64,
    /// SSL certificate verification result.
    pub ssl_verifyresult: i64,
    /// Proxy SSL certificate verification result.
    pub proxy_ssl_verifyresult: i64,
    /// Number of redirects followed.
    pub redirect_count: i64,
    /// Bitmask of available HTTP authentication methods.
    pub httpauth_avail: u64,
    /// Bitmask of available proxy authentication methods.
    pub proxyauth_avail: u64,
    /// Bitmask of HTTP authentication method actually used.
    pub httpauth_used: u64,
    /// Bitmask of proxy authentication method actually used.
    pub proxyauth_used: u64,
    /// OS errno from the most recent connect failure.
    pub os_errno: i64,
    /// Number of new connections opened during the transfer.
    pub num_connects: i64,
    /// Whether the time-condition was unmet (boolean as long).
    pub condition_unmet: bool,
    /// RTSP client CSeq number.
    pub rtsp_client_cseq: i64,
    /// RTSP server CSeq number.
    pub rtsp_server_cseq: i64,
    /// RTSP CSeq last received.
    pub rtsp_cseq_recv: i64,
    /// Remote port of the most recent connection.
    pub primary_port: i64,
    /// Local port of the most recent connection.
    pub local_port: i64,
    /// HTTP version used (encoded: 0x10 = 1.0, 0x11 = 1.1, etc.).
    pub http_version: i64,
    /// Detailed proxy error code.
    pub proxy_error: i64,
    /// Whether a proxy was used (boolean as long).
    pub used_proxy: bool,

    // -- Timing fields (microseconds, for *_T variants) --
    /// Total transfer time in microseconds.
    pub total_time_us: i64,
    /// DNS resolution time in microseconds.
    pub namelookup_time_us: i64,
    /// TCP connection time in microseconds.
    pub connect_time_us: i64,
    /// TLS/SSL handshake time in microseconds.
    pub appconnect_time_us: i64,
    /// Pre-transfer preparation time in microseconds.
    pub pretransfer_time_us: i64,
    /// Post-transfer time in microseconds.
    pub posttransfer_time_us: i64,
    /// Time to first byte in microseconds.
    pub starttransfer_time_us: i64,
    /// Queue wait time in microseconds.
    pub queue_time_us: i64,
    /// Total redirect time in microseconds.
    pub redirect_time_us: i64,

    // -- Size and speed fields --
    /// Bytes uploaded.
    pub size_upload: i64,
    /// Bytes downloaded.
    pub size_download: i64,
    /// Average download speed in bytes/second.
    pub speed_download: i64,
    /// Average upload speed in bytes/second.
    pub speed_upload: i64,
    /// Content-Length of the download (-1 = unknown).
    pub content_length_download: i64,
    /// Content-Length of the upload (-1 = unknown).
    pub content_length_upload: i64,

    // -- Off-T only fields --
    /// Retry-After header value in seconds.
    pub retry_after: i64,
    /// Transfer identifier.
    pub xfer_id: i64,
    /// Connection identifier.
    pub conn_id: i64,
    /// Early-data bytes sent (TLS 0-RTT).
    pub earlydata_sent: i64,

    // -- Socket field --
    /// Active socket descriptor (-1 = none).
    pub active_socket: i64,
}

impl PureInfo {
    /// Creates a new `PureInfo` with all fields set to their defaults.
    ///
    /// String fields are `None`, numeric fields are `0`, the `filetime`
    /// fields default to `-1` (meaning unknown, matching C behaviour),
    /// and `active_socket` defaults to `-1` (CURL_SOCKET_BAD).
    pub fn new() -> Self {
        Self {
            // String fields
            effective_url: Option::None,
            effective_method: Option::None,
            content_type: Option::None,
            redirect_url: Option::None,
            primary_ip: Option::None,
            local_ip: Option::None,
            rtsp_session_id: Option::None,
            scheme: Option::None,
            cainfo: Option::None,
            capath: Option::None,
            ftp_entry_path: Option::None,
            referer: Option::None,
            private_data: Option::None,

            // Long fields
            response_code: 0,
            http_connectcode: 0,
            filetime: -1,
            filetime_t: -1,
            header_size: 0,
            request_size: 0,
            ssl_verifyresult: 0,
            proxy_ssl_verifyresult: 0,
            redirect_count: 0,
            httpauth_avail: 0,
            proxyauth_avail: 0,
            httpauth_used: 0,
            proxyauth_used: 0,
            os_errno: 0,
            num_connects: 0,
            condition_unmet: false,
            rtsp_client_cseq: 0,
            rtsp_server_cseq: 0,
            rtsp_cseq_recv: 0,
            primary_port: 0,
            local_port: 0,
            http_version: 0,
            proxy_error: 0,
            used_proxy: false,

            // Timing fields (microseconds)
            total_time_us: 0,
            namelookup_time_us: 0,
            connect_time_us: 0,
            appconnect_time_us: 0,
            pretransfer_time_us: 0,
            posttransfer_time_us: 0,
            starttransfer_time_us: 0,
            queue_time_us: 0,
            redirect_time_us: 0,

            // Size and speed
            size_upload: 0,
            size_download: 0,
            speed_download: 0,
            speed_upload: 0,
            content_length_download: -1,
            content_length_upload: -1,

            // Off-T only
            retry_after: 0,
            xfer_id: -1,
            conn_id: -1,
            earlydata_sent: 0,

            // Socket
            active_socket: -1,
        }
    }

    /// Resets all fields to their initial defaults.
    ///
    /// This mirrors `Curl_initinfo` in the C implementation and is called
    /// at the start of every new perform session and from
    /// `curl_easy_reset`.
    pub fn reset(&mut self) {
        // String fields
        self.effective_url = Option::None;
        self.effective_method = Option::None;
        self.content_type = Option::None;
        self.redirect_url = Option::None;
        self.primary_ip = Option::None;
        self.local_ip = Option::None;
        self.rtsp_session_id = Option::None;
        self.scheme = Option::None;
        // cainfo and capath are NOT reset — they are compile-time defaults.
        self.ftp_entry_path = Option::None;
        self.referer = Option::None;
        // private_data is NOT reset — it persists across transfers.

        // Long fields
        self.response_code = 0;
        self.http_connectcode = 0;
        self.filetime = -1;
        self.filetime_t = -1;
        self.header_size = 0;
        self.request_size = 0;
        // ssl_verifyresult is NOT reset — persists for inspection.
        // proxy_ssl_verifyresult is NOT reset.
        self.redirect_count = 0;
        self.httpauth_avail = 0;
        self.proxyauth_avail = 0;
        self.httpauth_used = 0;
        self.proxyauth_used = 0;
        self.os_errno = 0;
        self.num_connects = 0;
        self.condition_unmet = false;
        self.rtsp_client_cseq = 0;
        self.rtsp_server_cseq = 0;
        self.rtsp_cseq_recv = 0;
        self.primary_port = 0;
        self.local_port = 0;
        self.http_version = 0;
        self.proxy_error = 0;
        self.used_proxy = false;

        // Timing fields
        self.total_time_us = 0;
        self.namelookup_time_us = 0;
        self.connect_time_us = 0;
        self.appconnect_time_us = 0;
        self.pretransfer_time_us = 0;
        self.posttransfer_time_us = 0;
        self.starttransfer_time_us = 0;
        self.queue_time_us = 0;
        self.redirect_time_us = 0;

        // Size and speed
        self.size_upload = 0;
        self.size_download = 0;
        self.speed_download = 0;
        self.speed_upload = 0;
        self.content_length_download = -1;
        self.content_length_upload = -1;

        // Off-T only
        self.retry_after = 0;
        // xfer_id and conn_id are NOT reset — they are connection-scoped.
        self.earlydata_sent = 0;

        // Socket — reset to invalid.
        self.active_socket = -1;
    }
}

impl Default for PureInfo {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// get_info_type — determine the type category of a CURLINFO value
// ---------------------------------------------------------------------------

/// Returns the [`CurlInfoType`] for a given [`CurlInfo`] value.
///
/// The type is extracted from the high nibble of the raw integer value using
/// [`CURLINFO_TYPEMASK`].
pub fn get_info_type(info: CurlInfo) -> CurlResult<CurlInfoType> {
    let raw = info.to_raw();
    let type_bits = raw & CURLINFO_TYPEMASK;
    match type_bits {
        CURLINFO_STRING => Ok(CurlInfoType::String),
        CURLINFO_LONG   => Ok(CurlInfoType::Long),
        CURLINFO_DOUBLE => Ok(CurlInfoType::Double),
        CURLINFO_SLIST  => Ok(CurlInfoType::SList),
        CURLINFO_SOCKET => Ok(CurlInfoType::Socket),
        CURLINFO_OFF_T  => Ok(CurlInfoType::OffT),
        _ => {
            // The None variant (0) and any unknown value fall here.
            Err(CurlError::UnknownOption)
        }
    }
}

// ---------------------------------------------------------------------------
// init_info — factory function (alias for PureInfo::new)
// ---------------------------------------------------------------------------

/// Creates a new [`PureInfo`] with default values.
///
/// This is the Rust equivalent of `Curl_initinfo` — a convenience entry
/// point that external modules can call without directly constructing the
/// struct.
#[inline]
pub fn init_info() -> PureInfo {
    PureInfo::new()
}

// ---------------------------------------------------------------------------
// Microseconds → seconds helper
// ---------------------------------------------------------------------------

/// Converts a microsecond timing value to seconds as a double.
///
/// Matches the C macro: `#define DOUBLE_SECS(x) ((double)(x) / 1000000)`.
#[inline]
fn us_to_secs(us: i64) -> f64 {
    (us as f64) / 1_000_000.0
}

// ---------------------------------------------------------------------------
// get_info_string
// ---------------------------------------------------------------------------

/// Retrieves a string-valued piece of transfer information from `info`.
///
/// Returns `Ok(Some(value))` when the field is populated, `Ok(None)` when the
/// field is empty/unset, and `Err(CurlError::UnknownOption)` when `what` is
/// not a string-type CURLINFO.
pub fn get_info_string(info: &PureInfo, what: CurlInfo) -> CurlResult<Option<String>> {
    match what {
        CurlInfo::EffectiveUrl    => Ok(info.effective_url.clone()),
        CurlInfo::EffectiveMethod => Ok(info.effective_method.clone()),
        CurlInfo::ContentType     => Ok(info.content_type.clone()),
        CurlInfo::Private         => Ok(info.private_data.clone()),
        CurlInfo::FtpEntryPath    => Ok(info.ftp_entry_path.clone()),
        CurlInfo::RedirectUrl     => Ok(info.redirect_url.clone()),
        CurlInfo::PrimaryIp       => Ok(info.primary_ip.clone()),
        CurlInfo::LocalIp         => Ok(info.local_ip.clone()),
        CurlInfo::RtspSessionId   => Ok(info.rtsp_session_id.clone()),
        CurlInfo::Scheme          => Ok(info.scheme.clone()),
        CurlInfo::Referer         => Ok(info.referer.clone()),
        CurlInfo::CaInfo          => Ok(info.cainfo.clone()),
        CurlInfo::CaPath          => Ok(info.capath.clone()),
        _ => Err(CurlError::UnknownOption),
    }
}

// ---------------------------------------------------------------------------
// get_info_long
// ---------------------------------------------------------------------------

/// Retrieves a long-valued piece of transfer information from `info`.
///
/// Returns `Ok(value)` on success, or `Err(CurlError::UnknownOption)` when
/// `what` is not a long-type CURLINFO.
pub fn get_info_long(info: &PureInfo, what: CurlInfo) -> CurlResult<i64> {
    match what {
        CurlInfo::ResponseCode        => Ok(info.response_code),
        CurlInfo::HttpConnectCode     => Ok(info.http_connectcode),
        CurlInfo::Filetime            => {
            // The deprecated CURLINFO_FILETIME returns a `long`. Clamp the
            // underlying i64 to `i32::MAX` / `i32::MIN` to mirror the C
            // behaviour on platforms where `long` is 32 bits.
            let ft = info.filetime;
            if ft > i64::from(i32::MAX) {
                Ok(i64::from(i32::MAX))
            } else if ft < i64::from(i32::MIN) {
                Ok(i64::from(i32::MIN))
            } else {
                Ok(ft)
            }
        }
        CurlInfo::HeaderSize          => Ok(info.header_size),
        CurlInfo::RequestSize         => Ok(info.request_size),
        CurlInfo::SslVerifyResult     => Ok(info.ssl_verifyresult),
        CurlInfo::ProxySslVerifyResult => Ok(info.proxy_ssl_verifyresult),
        CurlInfo::RedirectCount       => Ok(info.redirect_count),
        CurlInfo::HttpAuthAvail       => Ok(info.httpauth_avail as i64),
        CurlInfo::ProxyAuthAvail      => Ok(info.proxyauth_avail as i64),
        CurlInfo::HttpAuthUsed        => Ok(info.httpauth_used as i64),
        CurlInfo::ProxyAuthUsed       => Ok(info.proxyauth_used as i64),
        CurlInfo::OsErrno             => Ok(info.os_errno),
        CurlInfo::NumConnects         => Ok(info.num_connects),
        CurlInfo::LastSocket          => {
            // Deprecated — returns the active socket as a long, or -1 if
            // no socket is available.
            if info.active_socket >= 0 {
                Ok(info.active_socket)
            } else {
                Ok(-1)
            }
        }
        CurlInfo::ConditionUnmet      => {
            // The C code returns 1 if the HTTP status was 304 OR the
            // time-condition was explicitly unmet. We store the boolean
            // directly.
            Ok(if info.condition_unmet || info.response_code == 304 {
                1
            } else {
                0
            })
        }
        CurlInfo::RtspClientCseq      => Ok(info.rtsp_client_cseq),
        CurlInfo::RtspServerCseq      => Ok(info.rtsp_server_cseq),
        CurlInfo::RtspCseqRecv        => Ok(info.rtsp_cseq_recv),
        CurlInfo::PrimaryPort         => Ok(info.primary_port),
        CurlInfo::LocalPort           => Ok(info.local_port),
        CurlInfo::HttpVersion         => Ok(info.http_version),
        CurlInfo::ProxyError          => Ok(info.proxy_error),
        CurlInfo::Protocol            => {
            // Deprecated since curl 7.85.0 — replaced by CURLINFO_SCHEME.
            // The C code returns `data->info.conn_protocol`, which is a
            // bitmask. We return 0 (unknown) as the default; the transfer
            // engine would set this if protocol tracking is implemented.
            Ok(0)
        }
        CurlInfo::UsedProxy           => Ok(if info.used_proxy { 1 } else { 0 }),
        _ => Err(CurlError::UnknownOption),
    }
}

// ---------------------------------------------------------------------------
// get_info_double
// ---------------------------------------------------------------------------

/// Retrieves a double-valued piece of transfer information from `info`.
///
/// Timing values are stored internally as microseconds and converted to
/// seconds for this interface (matching the C `DOUBLE_SECS` macro).
///
/// Returns `Err(CurlError::UnknownOption)` when `what` is not a double-type
/// CURLINFO.
pub fn get_info_double(info: &PureInfo, what: CurlInfo) -> CurlResult<f64> {
    match what {
        CurlInfo::TotalTime             => Ok(us_to_secs(info.total_time_us)),
        CurlInfo::NamelookupTime        => Ok(us_to_secs(info.namelookup_time_us)),
        CurlInfo::ConnectTime           => Ok(us_to_secs(info.connect_time_us)),
        CurlInfo::PretransferTime       => Ok(us_to_secs(info.pretransfer_time_us)),
        CurlInfo::StarttransferTime     => Ok(us_to_secs(info.starttransfer_time_us)),
        CurlInfo::RedirectTime          => Ok(us_to_secs(info.redirect_time_us)),
        CurlInfo::AppconnectTime        => Ok(us_to_secs(info.appconnect_time_us)),
        CurlInfo::SizeUpload            => Ok(info.size_upload as f64),
        CurlInfo::SizeDownload          => Ok(info.size_download as f64),
        CurlInfo::SpeedDownload         => Ok(info.speed_download as f64),
        CurlInfo::SpeedUpload           => Ok(info.speed_upload as f64),
        CurlInfo::ContentLengthDownload => {
            if info.content_length_download >= 0 {
                Ok(info.content_length_download as f64)
            } else {
                Ok(-1.0)
            }
        }
        CurlInfo::ContentLengthUpload   => {
            if info.content_length_upload >= 0 {
                Ok(info.content_length_upload as f64)
            } else {
                Ok(-1.0)
            }
        }
        _ => Err(CurlError::UnknownOption),
    }
}

// ---------------------------------------------------------------------------
// get_info_off_t
// ---------------------------------------------------------------------------

/// Retrieves a `curl_off_t`-valued piece of transfer information from `info`.
///
/// Timing values are in microseconds. Size/speed values are in bytes.
///
/// Returns `Err(CurlError::UnknownOption)` when `what` is not an off_t-type
/// CURLINFO.
pub fn get_info_off_t(info: &PureInfo, what: CurlInfo) -> CurlResult<i64> {
    match what {
        CurlInfo::FiletimeT             => Ok(info.filetime_t),
        CurlInfo::SizeUploadT           => Ok(info.size_upload),
        CurlInfo::SizeDownloadT         => Ok(info.size_download),
        CurlInfo::SpeedDownloadT        => Ok(info.speed_download),
        CurlInfo::SpeedUploadT          => Ok(info.speed_upload),
        CurlInfo::ContentLengthDownloadT => Ok(info.content_length_download),
        CurlInfo::ContentLengthUploadT  => Ok(info.content_length_upload),
        CurlInfo::TotalTimeT            => Ok(info.total_time_us),
        CurlInfo::NamelookupTimeT       => Ok(info.namelookup_time_us),
        CurlInfo::ConnectTimeT          => Ok(info.connect_time_us),
        CurlInfo::AppconnectTimeT       => Ok(info.appconnect_time_us),
        CurlInfo::PretransferTimeT      => Ok(info.pretransfer_time_us),
        CurlInfo::PosttransferTimeT     => Ok(info.posttransfer_time_us),
        CurlInfo::StarttransferTimeT    => Ok(info.starttransfer_time_us),
        CurlInfo::QueueTimeT            => Ok(info.queue_time_us),
        CurlInfo::RedirectTimeT         => Ok(info.redirect_time_us),
        CurlInfo::RetryAfter            => Ok(info.retry_after),
        CurlInfo::XferId                => Ok(info.xfer_id),
        CurlInfo::ConnId                => Ok(info.conn_id),
        CurlInfo::EarlydataSentT        => Ok(info.earlydata_sent),
        _ => Err(CurlError::UnknownOption),
    }
}

// ---------------------------------------------------------------------------
// get_info_slist
// ---------------------------------------------------------------------------

/// Retrieves a string-list-valued piece of transfer information from `info`.
///
/// In the C implementation, SSL engine lists and cookie lists are generated
/// on the fly. This Rust version returns an empty [`SList`] as a placeholder
/// that the caller (EasyHandle / Multi) populates via the appropriate
/// subsystem.
///
/// Returns `Err(CurlError::UnknownOption)` when `what` is not an slist-type
/// CURLINFO.
pub fn get_info_slist(_info: &PureInfo, what: CurlInfo) -> CurlResult<SList> {
    match what {
        CurlInfo::SslEngines => Ok(SList::new()),
        CurlInfo::CookieList => Ok(SList::new()),
        CurlInfo::CertInfo   => Ok(SList::new()),
        CurlInfo::TlsSession => Ok(SList::new()),
        CurlInfo::TlsSslPtr  => Ok(SList::new()),
        _ => Err(CurlError::UnknownOption),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CurlInfo raw value tests --

    #[test]
    fn curlinfo_none_is_zero() {
        assert_eq!(CurlInfo::None.to_raw(), 0);
    }

    #[test]
    fn curlinfo_effective_url_value() {
        assert_eq!(CurlInfo::EffectiveUrl.to_raw(), CURLINFO_STRING + 1);
    }

    #[test]
    fn curlinfo_response_code_value() {
        assert_eq!(CurlInfo::ResponseCode.to_raw(), CURLINFO_LONG + 2);
    }

    #[test]
    fn curlinfo_total_time_value() {
        assert_eq!(CurlInfo::TotalTime.to_raw(), CURLINFO_DOUBLE + 3);
    }

    #[test]
    fn curlinfo_size_upload_t_value() {
        assert_eq!(CurlInfo::SizeUploadT.to_raw(), CURLINFO_OFF_T + 7);
    }

    #[test]
    fn curlinfo_active_socket_value() {
        assert_eq!(CurlInfo::ActiveSocket.to_raw(), CURLINFO_SOCKET + 44);
    }

    #[test]
    fn curlinfo_ssl_engines_value() {
        assert_eq!(CurlInfo::SslEngines.to_raw(), CURLINFO_SLIST + 27);
    }

    #[test]
    fn curlinfo_lastone_value() {
        // CURLINFO_PROXYAUTH_USED is #70, the last defined value.
        assert_eq!(CurlInfo::ProxyAuthUsed.to_raw(), CURLINFO_LONG + 70);
    }

    // -- from_raw / to_raw round-trip --

    #[test]
    fn from_raw_round_trip() {
        let cases = [
            CurlInfo::EffectiveUrl,
            CurlInfo::ResponseCode,
            CurlInfo::TotalTime,
            CurlInfo::SslEngines,
            CurlInfo::ActiveSocket,
            CurlInfo::TotalTimeT,
            CurlInfo::ProxyAuthUsed,
        ];
        for info in cases {
            let raw = info.to_raw();
            let back = CurlInfo::from_raw(raw).expect("round-trip failed");
            assert_eq!(back, info);
        }
    }

    #[test]
    fn from_raw_unknown_returns_none() {
        assert!(CurlInfo::from_raw(-1).is_none());
        assert!(CurlInfo::from_raw(0x999999).is_none());
    }

    // -- get_info_type tests --

    #[test]
    fn info_type_string() {
        assert_eq!(
            get_info_type(CurlInfo::EffectiveUrl).unwrap(),
            CurlInfoType::String
        );
    }

    #[test]
    fn info_type_long() {
        assert_eq!(
            get_info_type(CurlInfo::ResponseCode).unwrap(),
            CurlInfoType::Long
        );
    }

    #[test]
    fn info_type_double() {
        assert_eq!(
            get_info_type(CurlInfo::TotalTime).unwrap(),
            CurlInfoType::Double
        );
    }

    #[test]
    fn info_type_slist() {
        assert_eq!(
            get_info_type(CurlInfo::SslEngines).unwrap(),
            CurlInfoType::SList
        );
    }

    #[test]
    fn info_type_socket() {
        assert_eq!(
            get_info_type(CurlInfo::ActiveSocket).unwrap(),
            CurlInfoType::Socket
        );
    }

    #[test]
    fn info_type_off_t() {
        assert_eq!(
            get_info_type(CurlInfo::TotalTimeT).unwrap(),
            CurlInfoType::OffT
        );
    }

    #[test]
    fn info_type_none_is_error() {
        assert!(get_info_type(CurlInfo::None).is_err());
    }

    // -- PureInfo tests --

    #[test]
    fn pure_info_defaults() {
        let info = PureInfo::new();
        assert_eq!(info.response_code, 0);
        assert_eq!(info.filetime, -1);
        assert_eq!(info.filetime_t, -1);
        assert!(info.effective_url.is_none());
        assert_eq!(info.active_socket, -1);
        assert_eq!(info.content_length_download, -1);
    }

    #[test]
    fn pure_info_reset_restores_defaults() {
        let mut info = PureInfo::new();
        info.response_code = 200;
        info.effective_url = Some("https://example.com".to_owned());
        info.total_time_us = 1_500_000;
        info.size_download = 4096;
        info.reset();
        assert_eq!(info.response_code, 0);
        assert!(info.effective_url.is_none());
        assert_eq!(info.total_time_us, 0);
        assert_eq!(info.size_download, 0);
    }

    #[test]
    fn pure_info_default_trait() {
        let info = PureInfo::default();
        assert_eq!(info.response_code, 0);
        assert_eq!(info.filetime, -1);
    }

    // -- get_info_string tests --

    #[test]
    fn get_string_effective_url() {
        let mut info = PureInfo::new();
        info.effective_url = Some("https://curl.se".to_owned());
        let result = get_info_string(&info, CurlInfo::EffectiveUrl).unwrap();
        assert_eq!(result.as_deref(), Some("https://curl.se"));
    }

    #[test]
    fn get_string_none_field() {
        let info = PureInfo::new();
        let result = get_info_string(&info, CurlInfo::ContentType).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_string_wrong_type_returns_error() {
        let info = PureInfo::new();
        let result = get_info_string(&info, CurlInfo::ResponseCode);
        assert!(result.is_err());
    }

    // -- get_info_long tests --

    #[test]
    fn get_long_response_code() {
        let mut info = PureInfo::new();
        info.response_code = 200;
        assert_eq!(get_info_long(&info, CurlInfo::ResponseCode).unwrap(), 200);
    }

    #[test]
    fn get_long_condition_unmet_304() {
        let mut info = PureInfo::new();
        info.response_code = 304;
        assert_eq!(get_info_long(&info, CurlInfo::ConditionUnmet).unwrap(), 1);
    }

    #[test]
    fn get_long_condition_unmet_flag() {
        let mut info = PureInfo::new();
        info.condition_unmet = true;
        assert_eq!(get_info_long(&info, CurlInfo::ConditionUnmet).unwrap(), 1);
    }

    #[test]
    fn get_long_wrong_type_returns_error() {
        let info = PureInfo::new();
        assert!(get_info_long(&info, CurlInfo::TotalTime).is_err());
    }

    // -- get_info_double tests --

    #[test]
    fn get_double_total_time() {
        let mut info = PureInfo::new();
        info.total_time_us = 1_500_000;
        let result = get_info_double(&info, CurlInfo::TotalTime).unwrap();
        assert!((result - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn get_double_size_download() {
        let mut info = PureInfo::new();
        info.size_download = 4096;
        let result = get_info_double(&info, CurlInfo::SizeDownload).unwrap();
        assert!((result - 4096.0).abs() < f64::EPSILON);
    }

    #[test]
    fn get_double_content_length_unknown() {
        let info = PureInfo::new();
        let result = get_info_double(&info, CurlInfo::ContentLengthDownload).unwrap();
        assert!((result - (-1.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn get_double_wrong_type_returns_error() {
        let info = PureInfo::new();
        assert!(get_info_double(&info, CurlInfo::ResponseCode).is_err());
    }

    // -- get_info_off_t tests --

    #[test]
    fn get_off_t_total_time() {
        let mut info = PureInfo::new();
        info.total_time_us = 2_500_000;
        assert_eq!(
            get_info_off_t(&info, CurlInfo::TotalTimeT).unwrap(),
            2_500_000
        );
    }

    #[test]
    fn get_off_t_size_download() {
        let mut info = PureInfo::new();
        info.size_download = 65536;
        assert_eq!(
            get_info_off_t(&info, CurlInfo::SizeDownloadT).unwrap(),
            65536
        );
    }

    #[test]
    fn get_off_t_wrong_type_returns_error() {
        let info = PureInfo::new();
        assert!(get_info_off_t(&info, CurlInfo::EffectiveUrl).is_err());
    }

    // -- get_info_slist tests --

    #[test]
    fn get_slist_ssl_engines() {
        let info = PureInfo::new();
        let result = get_info_slist(&info, CurlInfo::SslEngines).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn get_slist_wrong_type_returns_error() {
        let info = PureInfo::new();
        assert!(get_info_slist(&info, CurlInfo::ResponseCode).is_err());
    }

    // -- init_info test --

    #[test]
    fn init_info_returns_defaults() {
        let info = init_info();
        assert_eq!(info.response_code, 0);
        assert_eq!(info.filetime, -1);
        assert!(info.effective_url.is_none());
    }

    // -- Type mask constant tests --

    #[test]
    fn type_mask_constants_match_c() {
        assert_eq!(CURLINFO_STRING, 0x10_0000);
        assert_eq!(CURLINFO_LONG, 0x20_0000);
        assert_eq!(CURLINFO_DOUBLE, 0x30_0000);
        assert_eq!(CURLINFO_SLIST, 0x40_0000);
        assert_eq!(CURLINFO_SOCKET, 0x50_0000);
        assert_eq!(CURLINFO_OFF_T, 0x60_0000);
        assert_eq!(CURLINFO_MASK, 0x0f_ffff);
        assert_eq!(CURLINFO_TYPEMASK, 0xf0_0000);
    }

    // -- Edge case: CURLINFO_FILETIME clamping --

    #[test]
    fn filetime_clamps_to_i32_max() {
        let mut info = PureInfo::new();
        info.filetime = i64::from(i32::MAX) + 100;
        let val = get_info_long(&info, CurlInfo::Filetime).unwrap();
        assert_eq!(val, i64::from(i32::MAX));
    }

    #[test]
    fn filetime_clamps_to_i32_min() {
        let mut info = PureInfo::new();
        info.filetime = i64::from(i32::MIN) - 100;
        let val = get_info_long(&info, CurlInfo::Filetime).unwrap();
        assert_eq!(val, i64::from(i32::MIN));
    }
}
