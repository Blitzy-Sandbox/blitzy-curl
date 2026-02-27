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
//! * [`CurlOpt`] \u2014 enum whose discriminants match C `CURLoption` values exactly
//! * [`CurlOptValue`] \u2014 typed union of all option value categories
//! * [`HandleOptions`] \u2014 typed configuration struct replacing C's `UserDefined`
//! * [`set_option`] \u2014 dispatch function with per-option validation
//!
//! # FFI Compatibility
//!
//! Every [`CurlOpt`] variant carries an explicit `#[repr(u32)]` discriminant
//! identical to the C `CURLoption` value from `include/curl/curl.h`.

use crate::error::{CurlError, CurlResult};
use crate::slist::SList;

// ---------------------------------------------------------------------------
// C-compatible constants
// ---------------------------------------------------------------------------

/// Base offset for `CURLOPTTYPE_LONG` options (integer values).
pub const CURLOPTTYPE_LONG: u32 = 0;
/// Base offset for `CURLOPTTYPE_OBJECTPOINT` options.
pub const CURLOPTTYPE_OBJECTPOINT: u32 = 10_000;
/// Base offset for `CURLOPTTYPE_FUNCTIONPOINT` options (callbacks).
pub const CURLOPTTYPE_FUNCTIONPOINT: u32 = 20_000;
/// Base offset for `CURLOPTTYPE_OFF_T` options (64-bit offsets).
pub const CURLOPTTYPE_OFF_T: u32 = 30_000;
/// Base offset for `CURLOPTTYPE_BLOB` options (binary data).
pub const CURLOPTTYPE_BLOB: u32 = 40_000;
/// Alias for string options.
pub const CURLOPTTYPE_STRINGPOINT: u32 = CURLOPTTYPE_OBJECTPOINT;
/// Alias for slist options.
pub const CURLOPTTYPE_SLISTPOINT: u32 = CURLOPTTYPE_OBJECTPOINT;
/// Alias for callback-data options.
pub const CURLOPTTYPE_CBPOINT: u32 = CURLOPTTYPE_OBJECTPOINT;
/// Alias for enumerated integer options.
pub const CURLOPTTYPE_VALUES: u32 = CURLOPTTYPE_LONG;
/// Maximum allowed input string length, matching C `CURL_MAX_INPUT_LENGTH`.
pub const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

// HTTP version constants

/// No preferred HTTP version; let the library decide.
pub const CURL_HTTP_VERSION_NONE: i64 = 0;
/// Enforce HTTP/1.0 requests.
pub const CURL_HTTP_VERSION_1_0: i64 = 1;
/// Enforce HTTP/1.1 requests.
pub const CURL_HTTP_VERSION_1_1: i64 = 2;
/// Attempt HTTP/2 via Upgrade or ALPN negotiation, falling back to HTTP/1.1.
pub const CURL_HTTP_VERSION_2_0: i64 = 3;
/// Attempt HTTP/2 via ALPN on TLS connections only.
pub const CURL_HTTP_VERSION_2TLS: i64 = 4;
/// Use HTTP/2 without negotiation (prior knowledge).
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: i64 = 5;
/// Attempt HTTP/3 via QUIC, falling back to earlier versions.
pub const CURL_HTTP_VERSION_3: i64 = 30;
/// Require HTTP/3 exclusively — fail if QUIC is unavailable.
pub const CURL_HTTP_VERSION_3ONLY: i64 = 31;

// SSL version constants

/// Use the default TLS version negotiation.
pub const CURL_SSLVERSION_DEFAULT: i64 = 0;
/// Use TLS 1.x (library selects minor version).
pub const CURL_SSLVERSION_TLSV1: i64 = 1;
/// Use SSLv2 (obsolete, typically rejected by servers).
pub const CURL_SSLVERSION_SSLV2: i64 = 2;
/// Use SSLv3 (obsolete, typically rejected by servers).
pub const CURL_SSLVERSION_SSLV3: i64 = 3;
/// Use TLS 1.0 as the minimum version.
pub const CURL_SSLVERSION_TLSV1_0: i64 = 4;
/// Use TLS 1.1 as the minimum version.
pub const CURL_SSLVERSION_TLSV1_1: i64 = 5;
/// Use TLS 1.2 as the minimum version.
pub const CURL_SSLVERSION_TLSV1_2: i64 = 6;
/// Use TLS 1.3 as the minimum version.
pub const CURL_SSLVERSION_TLSV1_3: i64 = 7;
/// Sentinel value: number of defined SSL version entries.
pub const CURL_SSLVERSION_LAST: i64 = 8;
/// No maximum TLS version constraint.
pub const CURL_SSLVERSION_MAX_NONE: i64 = 0;
/// Sentinel for the maximum SSL version range.
pub const CURL_SSLVERSION_MAX_LAST: i64 = CURL_SSLVERSION_LAST << 16;

// Proxy type constants

/// HTTP proxy (default).
pub const CURLPROXY_HTTP: i64 = 0;
/// HTTP/1.0 proxy.
pub const CURLPROXY_HTTP_1_0: i64 = 1;
/// HTTPS proxy (TLS connection to the proxy itself).
pub const CURLPROXY_HTTPS: i64 = 2;
/// HTTPS proxy with HTTP/2 to the proxy.
pub const CURLPROXY_HTTPS2: i64 = 3;
/// SOCKS4 proxy.
pub const CURLPROXY_SOCKS4: i64 = 4;
/// SOCKS5 proxy.
pub const CURLPROXY_SOCKS5: i64 = 5;
/// SOCKS4a proxy (hostname resolution on the proxy side).
pub const CURLPROXY_SOCKS4A: i64 = 6;
/// SOCKS5 proxy with hostname resolution on the proxy side.
pub const CURLPROXY_SOCKS5_HOSTNAME: i64 = 7;

// Auth bitmask constants

/// No authentication.
pub const CURLAUTH_NONE: u64 = 0;
/// HTTP Basic authentication.
pub const CURLAUTH_BASIC: u64 = 1 << 0;
/// HTTP Digest authentication (RFC 2617 / RFC 7616).
pub const CURLAUTH_DIGEST: u64 = 1 << 1;
/// HTTP Negotiate (SPNEGO) authentication.
pub const CURLAUTH_NEGOTIATE: u64 = 1 << 2;
/// HTTP NTLM authentication.
pub const CURLAUTH_NTLM: u64 = 1 << 3;
/// HTTP Digest authentication with IE-compatible flavour.
pub const CURLAUTH_DIGEST_IE: u64 = 1 << 4;
/// HTTP Bearer token authentication (RFC 6750).
pub const CURLAUTH_BEARER: u64 = 1 << 6;
/// Used with another auth type to force that single type only.
pub const CURLAUTH_ONLY: u64 = 1 << 31;
/// Convenience bitmask: any authentication method (excluding Digest-IE).
pub const CURLAUTH_ANY: u64 = !(CURLAUTH_DIGEST_IE);

// IP resolve constants

/// Resolve using whatever address family is available.
pub const CURL_IPRESOLVE_WHATEVER: i64 = 0;
/// Resolve to IPv4 addresses only.
pub const CURL_IPRESOLVE_V4: i64 = 1;
/// Resolve to IPv6 addresses only.
pub const CURL_IPRESOLVE_V6: i64 = 2;

// Netrc constants

/// Ignore `.netrc` file completely.
pub const CURL_NETRC_IGNORED: i64 = 0;
/// Use `.netrc` file for missing credentials (default).
pub const CURL_NETRC_OPTIONAL: i64 = 1;
/// Require `.netrc` credentials; fail if not found.
pub const CURL_NETRC_REQUIRED: i64 = 2;

// Time condition constants

/// No time condition.
pub const CURL_TIMECOND_NONE: i64 = 0;
/// Transfer only if modified since the given time.
pub const CURL_TIMECOND_IFMODSINCE: i64 = 1;
/// Transfer only if unmodified since the given time.
pub const CURL_TIMECOND_IFUNMODSINCE: i64 = 2;
/// Transfer only if last-modified matches the given time.
pub const CURL_TIMECOND_LASTMOD: i64 = 3;

// SSH auth type bitmask constants

/// Allow any SSH authentication method.
pub const CURLSSH_AUTH_ANY: i64 = !0;
/// No SSH authentication.
pub const CURLSSH_AUTH_NONE: i64 = 0;
/// SSH public-key authentication.
pub const CURLSSH_AUTH_PUBLICKEY: i64 = 1 << 0;
/// SSH password authentication.
pub const CURLSSH_AUTH_PASSWORD: i64 = 1 << 1;
/// SSH host-based authentication.
pub const CURLSSH_AUTH_HOST: i64 = 1 << 2;
/// SSH keyboard-interactive authentication.
pub const CURLSSH_AUTH_KEYBOARD: i64 = 1 << 3;
/// SSH agent-based authentication.
pub const CURLSSH_AUTH_AGENT: i64 = 1 << 4;
/// Default SSH auth methods (equivalent to `CURLSSH_AUTH_ANY`).
pub const CURLSSH_AUTH_DEFAULT: i64 = CURLSSH_AUTH_ANY;

// USE_SSL constants

/// Do not use SSL/TLS at all.
pub const CURLUSESSL_NONE: i64 = 0;
/// Try using SSL/TLS, but proceed without if unavailable.
pub const CURLUSESSL_TRY: i64 = 1;
/// Require SSL/TLS for the control connection.
pub const CURLUSESSL_CONTROL: i64 = 2;
/// Require SSL/TLS for both control and data connections.
pub const CURLUSESSL_ALL: i64 = 3;

// Header option constants

/// Pass all headers in a single unified list.
pub const CURLHEADER_UNIFIED: i64 = 0;
/// Pass proxy and server headers in separate lists.
pub const CURLHEADER_SEPARATE: i64 = 1 << 0;

// Post redirect constants

/// Convert POST to GET on all redirect types.
pub const CURL_REDIR_GET_ALL: i64 = 0;
/// Keep POST on 301 redirect.
pub const CURL_REDIR_POST_301: i64 = 1;
/// Keep POST on 302 redirect.
pub const CURL_REDIR_POST_302: i64 = 2;
/// Keep POST on 303 redirect.
pub const CURL_REDIR_POST_303: i64 = 4;
/// Keep POST on all redirect types (301, 302, 303).
pub const CURL_REDIR_POST_ALL: i64 = CURL_REDIR_POST_301 | CURL_REDIR_POST_302 | CURL_REDIR_POST_303;

/// All supported `CURLoption` identifiers (291 variants).
///
/// Each variant's discriminant matches the C `CURLoption` integer value
/// defined in `include/curl/curl.h` exactly. The variant names are kept
/// identical to the C macro names for FFI compatibility; refer to the
/// [curl_easy_setopt(3)](https://curl.se/libcurl/c/curl_easy_setopt.html)
/// man page for per-option documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[allow(non_camel_case_types, missing_docs)]
pub enum CurlOpt {
    // -- LONG/VALUES (base 0) --
    CURLOPT_PORT = 3,
    CURLOPT_TIMEOUT = 13,
    CURLOPT_INFILESIZE = 14,
    CURLOPT_LOW_SPEED_LIMIT = 19,
    CURLOPT_LOW_SPEED_TIME = 20,
    CURLOPT_RESUME_FROM = 21,
    CURLOPT_CRLF = 27,
    CURLOPT_SSLVERSION = 32,
    CURLOPT_TIMECONDITION = 33,
    CURLOPT_TIMEVALUE = 34,
    CURLOPT_VERBOSE = 41,
    CURLOPT_HEADER = 42,
    CURLOPT_NOPROGRESS = 43,
    CURLOPT_NOBODY = 44,
    CURLOPT_FAILONERROR = 45,
    CURLOPT_UPLOAD = 46,
    CURLOPT_POST = 47,
    CURLOPT_DIRLISTONLY = 48,
    CURLOPT_APPEND = 50,
    CURLOPT_NETRC = 51,
    CURLOPT_FOLLOWLOCATION = 52,
    CURLOPT_TRANSFERTEXT = 53,
    CURLOPT_AUTOREFERER = 58,
    CURLOPT_PROXYPORT = 59,
    CURLOPT_POSTFIELDSIZE = 60,
    CURLOPT_HTTPPROXYTUNNEL = 61,
    CURLOPT_SSL_VERIFYPEER = 64,
    CURLOPT_MAXREDIRS = 68,
    CURLOPT_FILETIME = 69,
    CURLOPT_MAXCONNECTS = 71,
    CURLOPT_FRESH_CONNECT = 74,
    CURLOPT_FORBID_REUSE = 75,
    CURLOPT_CONNECTTIMEOUT = 78,
    CURLOPT_HTTPGET = 80,
    CURLOPT_SSL_VERIFYHOST = 81,
    CURLOPT_HTTP_VERSION = 84,
    CURLOPT_FTP_USE_EPSV = 85,
    CURLOPT_SSLENGINE_DEFAULT = 90,
    CURLOPT_DNS_CACHE_TIMEOUT = 92,
    CURLOPT_COOKIESESSION = 96,
    CURLOPT_BUFFERSIZE = 98,
    CURLOPT_NOSIGNAL = 99,
    CURLOPT_PROXYTYPE = 101,
    CURLOPT_UNRESTRICTED_AUTH = 105,
    CURLOPT_FTP_USE_EPRT = 106,
    CURLOPT_HTTPAUTH = 107,
    CURLOPT_FTP_CREATE_MISSING_DIRS = 110,
    CURLOPT_PROXYAUTH = 111,
    CURLOPT_SERVER_RESPONSE_TIMEOUT = 112,
    CURLOPT_IPRESOLVE = 113,
    CURLOPT_MAXFILESIZE = 114,
    CURLOPT_USE_SSL = 119,
    CURLOPT_TCP_NODELAY = 121,
    CURLOPT_FTPSSLAUTH = 129,
    CURLOPT_IGNORE_CONTENT_LENGTH = 136,
    CURLOPT_FTP_SKIP_PASV_IP = 137,
    CURLOPT_FTP_FILEMETHOD = 138,
    CURLOPT_LOCALPORT = 139,
    CURLOPT_LOCALPORTRANGE = 140,
    CURLOPT_CONNECT_ONLY = 141,
    CURLOPT_SSL_SESSIONID_CACHE = 150,
    CURLOPT_SSH_AUTH_TYPES = 151,
    CURLOPT_FTP_SSL_CCC = 154,
    CURLOPT_TIMEOUT_MS = 155,
    CURLOPT_CONNECTTIMEOUT_MS = 156,
    CURLOPT_HTTP_TRANSFER_DECODING = 157,
    CURLOPT_HTTP_CONTENT_DECODING = 158,
    CURLOPT_NEW_FILE_PERMS = 159,
    CURLOPT_NEW_DIRECTORY_PERMS = 160,
    CURLOPT_POSTREDIR = 161,
    CURLOPT_PROXY_TRANSFER_MODE = 166,
    CURLOPT_ADDRESS_SCOPE = 171,
    CURLOPT_CERTINFO = 172,
    CURLOPT_TFTP_BLKSIZE = 178,
    CURLOPT_SOCKS5_GSSAPI_NEC = 180,
    CURLOPT_FTP_USE_PRET = 188,
    CURLOPT_RTSP_REQUEST = 189,
    CURLOPT_RTSP_CLIENT_CSEQ = 193,
    CURLOPT_RTSP_SERVER_CSEQ = 194,
    CURLOPT_WILDCARDMATCH = 197,
    CURLOPT_TRANSFER_ENCODING = 207,
    CURLOPT_GSSAPI_DELEGATION = 210,
    CURLOPT_ACCEPTTIMEOUT_MS = 212,
    CURLOPT_TCP_KEEPALIVE = 213,
    CURLOPT_TCP_KEEPIDLE = 214,
    CURLOPT_TCP_KEEPINTVL = 215,
    CURLOPT_SSL_OPTIONS = 216,
    CURLOPT_SASL_IR = 218,
    CURLOPT_SSL_ENABLE_ALPN = 226,
    CURLOPT_EXPECT_100_TIMEOUT_MS = 227,
    CURLOPT_HEADEROPT = 229,
    CURLOPT_SSL_VERIFYSTATUS = 232,
    CURLOPT_PATH_AS_IS = 234,
    CURLOPT_PIPEWAIT = 237,
    CURLOPT_STREAM_WEIGHT = 239,
    CURLOPT_TFTP_NO_OPTIONS = 242,
    CURLOPT_TCP_FASTOPEN = 244,
    CURLOPT_KEEP_SENDING_ON_ERROR = 245,
    CURLOPT_PROXY_SSL_VERIFYPEER = 248,
    CURLOPT_PROXY_SSL_VERIFYHOST = 249,
    CURLOPT_PROXY_SSLVERSION = 250,
    CURLOPT_PROXY_SSL_OPTIONS = 261,
    CURLOPT_SUPPRESS_CONNECT_HEADERS = 265,
    CURLOPT_SOCKS5_AUTH = 267,
    CURLOPT_SSH_COMPRESSION = 268,
    CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS = 271,
    CURLOPT_HAPROXYPROTOCOL = 274,
    CURLOPT_DNS_SHUFFLE_ADDRESSES = 275,
    CURLOPT_DISALLOW_USERNAME_IN_URL = 278,
    CURLOPT_UPLOAD_BUFFERSIZE = 280,
    CURLOPT_UPKEEP_INTERVAL_MS = 281,
    CURLOPT_HTTP09_ALLOWED = 285,
    CURLOPT_ALTSVC_CTRL = 286,
    CURLOPT_MAXAGE_CONN = 288,
    CURLOPT_MAIL_RCPT_ALLOWFAILS = 290,
    CURLOPT_HSTS_CTRL = 299,
    CURLOPT_DOH_SSL_VERIFYPEER = 306,
    CURLOPT_DOH_SSL_VERIFYHOST = 307,
    CURLOPT_DOH_SSL_VERIFYSTATUS = 308,
    CURLOPT_MAXLIFETIME_CONN = 314,
    CURLOPT_MIME_OPTIONS = 315,
    CURLOPT_WS_OPTIONS = 320,
    CURLOPT_CA_CACHE_TIMEOUT = 321,
    CURLOPT_QUICK_EXIT = 322,
    CURLOPT_SERVER_RESPONSE_TIMEOUT_MS = 324,
    CURLOPT_TCP_KEEPCNT = 326,
    CURLOPT_UPLOAD_FLAGS = 327,

    // -- OBJECTPOINT/STRINGPOINT/SLISTPOINT/CBPOINT (base 10_000) --
    CURLOPT_WRITEDATA = 10_001,
    CURLOPT_URL = 10_002,
    CURLOPT_PROXY = 10_004,
    CURLOPT_USERPWD = 10_005,
    CURLOPT_PROXYUSERPWD = 10_006,
    CURLOPT_RANGE = 10_007,
    CURLOPT_READDATA = 10_009,
    CURLOPT_ERRORBUFFER = 10_010,
    CURLOPT_POSTFIELDS = 10_015,
    CURLOPT_REFERER = 10_016,
    CURLOPT_FTPPORT = 10_017,
    CURLOPT_USERAGENT = 10_018,
    CURLOPT_COOKIE = 10_022,
    CURLOPT_HTTPHEADER = 10_023,
    CURLOPT_SSLCERT = 10_025,
    CURLOPT_KEYPASSWD = 10_026,
    CURLOPT_QUOTE = 10_028,
    CURLOPT_HEADERDATA = 10_029,
    CURLOPT_COOKIEFILE = 10_031,
    CURLOPT_CUSTOMREQUEST = 10_036,
    CURLOPT_STDERR = 10_037,
    CURLOPT_POSTQUOTE = 10_039,
    CURLOPT_XFERINFODATA = 10_057,
    CURLOPT_INTERFACE = 10_062,
    CURLOPT_CAINFO = 10_065,
    CURLOPT_TELNETOPTIONS = 10_070,
    CURLOPT_COOKIEJAR = 10_082,
    CURLOPT_SSL_CIPHER_LIST = 10_083,
    CURLOPT_SSLCERTTYPE = 10_086,
    CURLOPT_SSLKEY = 10_087,
    CURLOPT_SSLKEYTYPE = 10_088,
    CURLOPT_SSLENGINE = 10_089,
    CURLOPT_PREQUOTE = 10_093,
    CURLOPT_DEBUGDATA = 10_095,
    CURLOPT_CAPATH = 10_097,
    CURLOPT_SHARE = 10_100,
    CURLOPT_ACCEPT_ENCODING = 10_102,
    CURLOPT_PRIVATE = 10_103,
    CURLOPT_HTTP200ALIASES = 10_104,
    CURLOPT_SSL_CTX_DATA = 10_109,
    CURLOPT_NETRC_FILE = 10_118,
    CURLOPT_FTP_ACCOUNT = 10_134,
    CURLOPT_COOKIELIST = 10_135,
    CURLOPT_FTP_ALTERNATIVE_TO_USER = 10_147,
    CURLOPT_SOCKOPTDATA = 10_149,
    CURLOPT_SSH_PUBLIC_KEYFILE = 10_152,
    CURLOPT_SSH_PRIVATE_KEYFILE = 10_153,
    CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 = 10_162,
    CURLOPT_OPENSOCKETDATA = 10_164,
    CURLOPT_COPYPOSTFIELDS = 10_165,
    CURLOPT_SEEKDATA = 10_168,
    CURLOPT_CRLFILE = 10_169,
    CURLOPT_ISSUERCERT = 10_170,
    CURLOPT_USERNAME = 10_173,
    CURLOPT_PASSWORD = 10_174,
    CURLOPT_PROXYUSERNAME = 10_175,
    CURLOPT_PROXYPASSWORD = 10_176,
    CURLOPT_NOPROXY = 10_177,
    CURLOPT_SSH_KNOWNHOSTS = 10_183,
    CURLOPT_SSH_KEYDATA = 10_185,
    CURLOPT_MAIL_FROM = 10_186,
    CURLOPT_MAIL_RCPT = 10_187,
    CURLOPT_RTSP_SESSION_ID = 10_190,
    CURLOPT_RTSP_STREAM_URI = 10_191,
    CURLOPT_RTSP_TRANSPORT = 10_192,
    CURLOPT_INTERLEAVEDATA = 10_195,
    CURLOPT_CHUNK_DATA = 10_201,
    CURLOPT_FNMATCH_DATA = 10_202,
    CURLOPT_RESOLVE = 10_203,
    CURLOPT_TLSAUTH_USERNAME = 10_204,
    CURLOPT_TLSAUTH_PASSWORD = 10_205,
    CURLOPT_TLSAUTH_TYPE = 10_206,
    CURLOPT_CLOSESOCKETDATA = 10_209,
    CURLOPT_DNS_SERVERS = 10_211,
    CURLOPT_MAIL_AUTH = 10_217,
    CURLOPT_XOAUTH2_BEARER = 10_220,
    CURLOPT_DNS_INTERFACE = 10_221,
    CURLOPT_DNS_LOCAL_IP4 = 10_222,
    CURLOPT_DNS_LOCAL_IP6 = 10_223,
    CURLOPT_LOGIN_OPTIONS = 10_224,
    CURLOPT_PROXYHEADER = 10_228,
    CURLOPT_PINNEDPUBLICKEY = 10_230,
    CURLOPT_UNIX_SOCKET_PATH = 10_231,
    CURLOPT_PROXY_SERVICE_NAME = 10_235,
    CURLOPT_SERVICE_NAME = 10_236,
    CURLOPT_DEFAULT_PROTOCOL = 10_238,
    CURLOPT_STREAM_DEPENDS = 10_240,
    CURLOPT_STREAM_DEPENDS_E = 10_241,
    CURLOPT_CONNECT_TO = 10_243,
    CURLOPT_PROXY_CAINFO = 10_246,
    CURLOPT_PROXY_CAPATH = 10_247,
    CURLOPT_PROXY_TLSAUTH_USERNAME = 10_251,
    CURLOPT_PROXY_TLSAUTH_PASSWORD = 10_252,
    CURLOPT_PROXY_TLSAUTH_TYPE = 10_253,
    CURLOPT_PROXY_SSLCERT = 10_254,
    CURLOPT_PROXY_SSLCERTTYPE = 10_255,
    CURLOPT_PROXY_SSLKEY = 10_256,
    CURLOPT_PROXY_SSLKEYTYPE = 10_257,
    CURLOPT_PROXY_KEYPASSWD = 10_258,
    CURLOPT_PROXY_SSL_CIPHER_LIST = 10_259,
    CURLOPT_PROXY_CRLFILE = 10_260,
    CURLOPT_PRE_PROXY = 10_262,
    CURLOPT_PROXY_PINNEDPUBLICKEY = 10_263,
    CURLOPT_ABSTRACT_UNIX_SOCKET = 10_264,
    CURLOPT_REQUEST_TARGET = 10_266,
    CURLOPT_MIMEPOST = 10_269,
    CURLOPT_RESOLVER_START_DATA = 10_273,
    CURLOPT_TLS13_CIPHERS = 10_276,
    CURLOPT_PROXY_TLS13_CIPHERS = 10_277,
    CURLOPT_DOH_URL = 10_279,
    CURLOPT_CURLU = 10_282,
    CURLOPT_TRAILERDATA = 10_284,
    CURLOPT_ALTSVC = 10_287,
    CURLOPT_SASL_AUTHZID = 10_289,
    CURLOPT_PROXY_ISSUERCERT = 10_296,
    CURLOPT_SSL_EC_CURVES = 10_298,
    CURLOPT_HSTS = 10_300,
    CURLOPT_HSTSREADDATA = 10_302,
    CURLOPT_HSTSWRITEDATA = 10_304,
    CURLOPT_AWS_SIGV4 = 10_305,
    CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 = 10_311,
    CURLOPT_PREREQDATA = 10_313,
    CURLOPT_SSH_HOSTKEYDATA = 10_317,
    CURLOPT_PROTOCOLS_STR = 10_318,
    CURLOPT_REDIR_PROTOCOLS_STR = 10_319,
    CURLOPT_HAPROXY_CLIENT_IP = 10_323,
    CURLOPT_ECH = 10_325,
    CURLOPT_SSL_SIGNATURE_ALGORITHMS = 10_328,

    // -- FUNCTIONPOINT (base 20_000) --
    CURLOPT_WRITEFUNCTION = 20_011,
    CURLOPT_READFUNCTION = 20_012,
    CURLOPT_HEADERFUNCTION = 20_079,
    CURLOPT_DEBUGFUNCTION = 20_094,
    CURLOPT_SSL_CTX_FUNCTION = 20_108,
    CURLOPT_SOCKOPTFUNCTION = 20_148,
    CURLOPT_OPENSOCKETFUNCTION = 20_163,
    CURLOPT_SEEKFUNCTION = 20_167,
    CURLOPT_SSH_KEYFUNCTION = 20_184,
    CURLOPT_INTERLEAVEFUNCTION = 20_196,
    CURLOPT_CHUNK_BGN_FUNCTION = 20_198,
    CURLOPT_CHUNK_END_FUNCTION = 20_199,
    CURLOPT_FNMATCH_FUNCTION = 20_200,
    CURLOPT_CLOSESOCKETFUNCTION = 20_208,
    CURLOPT_XFERINFOFUNCTION = 20_219,
    CURLOPT_RESOLVER_START_FUNCTION = 20_272,
    CURLOPT_TRAILERFUNCTION = 20_283,
    CURLOPT_HSTSREADFUNCTION = 20_301,
    CURLOPT_HSTSWRITEFUNCTION = 20_303,
    CURLOPT_PREREQFUNCTION = 20_312,
    CURLOPT_SSH_HOSTKEYFUNCTION = 20_316,

    // -- OFF_T (base 30_000) --
    CURLOPT_INFILESIZE_LARGE = 30_115,
    CURLOPT_RESUME_FROM_LARGE = 30_116,
    CURLOPT_MAXFILESIZE_LARGE = 30_117,
    CURLOPT_POSTFIELDSIZE_LARGE = 30_120,
    CURLOPT_MAX_SEND_SPEED_LARGE = 30_145,
    CURLOPT_MAX_RECV_SPEED_LARGE = 30_146,
    CURLOPT_TIMEVALUE_LARGE = 30_270,

    // -- BLOB (base 40_000) --
    CURLOPT_SSLCERT_BLOB = 40_291,
    CURLOPT_SSLKEY_BLOB = 40_292,
    CURLOPT_PROXY_SSLCERT_BLOB = 40_293,
    CURLOPT_PROXY_SSLKEY_BLOB = 40_294,
    CURLOPT_ISSUERCERT_BLOB = 40_295,
    CURLOPT_PROXY_ISSUERCERT_BLOB = 40_297,
    CURLOPT_CAINFO_BLOB = 40_309,
    CURLOPT_PROXY_CAINFO_BLOB = 40_310,

}

impl CurlOpt {
    /// Converts a raw `u32` option identifier to a [`CurlOpt`] variant.
    #[must_use]
    pub fn try_from_u32(value: u32) -> Option<Self> {
        match value {
            3 => Some(Self::CURLOPT_PORT),
            13 => Some(Self::CURLOPT_TIMEOUT),
            14 => Some(Self::CURLOPT_INFILESIZE),
            19 => Some(Self::CURLOPT_LOW_SPEED_LIMIT),
            20 => Some(Self::CURLOPT_LOW_SPEED_TIME),
            21 => Some(Self::CURLOPT_RESUME_FROM),
            27 => Some(Self::CURLOPT_CRLF),
            32 => Some(Self::CURLOPT_SSLVERSION),
            33 => Some(Self::CURLOPT_TIMECONDITION),
            34 => Some(Self::CURLOPT_TIMEVALUE),
            41 => Some(Self::CURLOPT_VERBOSE),
            42 => Some(Self::CURLOPT_HEADER),
            43 => Some(Self::CURLOPT_NOPROGRESS),
            44 => Some(Self::CURLOPT_NOBODY),
            45 => Some(Self::CURLOPT_FAILONERROR),
            46 => Some(Self::CURLOPT_UPLOAD),
            47 => Some(Self::CURLOPT_POST),
            48 => Some(Self::CURLOPT_DIRLISTONLY),
            50 => Some(Self::CURLOPT_APPEND),
            51 => Some(Self::CURLOPT_NETRC),
            52 => Some(Self::CURLOPT_FOLLOWLOCATION),
            53 => Some(Self::CURLOPT_TRANSFERTEXT),
            58 => Some(Self::CURLOPT_AUTOREFERER),
            59 => Some(Self::CURLOPT_PROXYPORT),
            60 => Some(Self::CURLOPT_POSTFIELDSIZE),
            61 => Some(Self::CURLOPT_HTTPPROXYTUNNEL),
            64 => Some(Self::CURLOPT_SSL_VERIFYPEER),
            68 => Some(Self::CURLOPT_MAXREDIRS),
            69 => Some(Self::CURLOPT_FILETIME),
            71 => Some(Self::CURLOPT_MAXCONNECTS),
            74 => Some(Self::CURLOPT_FRESH_CONNECT),
            75 => Some(Self::CURLOPT_FORBID_REUSE),
            78 => Some(Self::CURLOPT_CONNECTTIMEOUT),
            80 => Some(Self::CURLOPT_HTTPGET),
            81 => Some(Self::CURLOPT_SSL_VERIFYHOST),
            84 => Some(Self::CURLOPT_HTTP_VERSION),
            85 => Some(Self::CURLOPT_FTP_USE_EPSV),
            90 => Some(Self::CURLOPT_SSLENGINE_DEFAULT),
            92 => Some(Self::CURLOPT_DNS_CACHE_TIMEOUT),
            96 => Some(Self::CURLOPT_COOKIESESSION),
            98 => Some(Self::CURLOPT_BUFFERSIZE),
            99 => Some(Self::CURLOPT_NOSIGNAL),
            101 => Some(Self::CURLOPT_PROXYTYPE),
            105 => Some(Self::CURLOPT_UNRESTRICTED_AUTH),
            106 => Some(Self::CURLOPT_FTP_USE_EPRT),
            107 => Some(Self::CURLOPT_HTTPAUTH),
            110 => Some(Self::CURLOPT_FTP_CREATE_MISSING_DIRS),
            111 => Some(Self::CURLOPT_PROXYAUTH),
            112 => Some(Self::CURLOPT_SERVER_RESPONSE_TIMEOUT),
            113 => Some(Self::CURLOPT_IPRESOLVE),
            114 => Some(Self::CURLOPT_MAXFILESIZE),
            119 => Some(Self::CURLOPT_USE_SSL),
            121 => Some(Self::CURLOPT_TCP_NODELAY),
            129 => Some(Self::CURLOPT_FTPSSLAUTH),
            136 => Some(Self::CURLOPT_IGNORE_CONTENT_LENGTH),
            137 => Some(Self::CURLOPT_FTP_SKIP_PASV_IP),
            138 => Some(Self::CURLOPT_FTP_FILEMETHOD),
            139 => Some(Self::CURLOPT_LOCALPORT),
            140 => Some(Self::CURLOPT_LOCALPORTRANGE),
            141 => Some(Self::CURLOPT_CONNECT_ONLY),
            150 => Some(Self::CURLOPT_SSL_SESSIONID_CACHE),
            151 => Some(Self::CURLOPT_SSH_AUTH_TYPES),
            154 => Some(Self::CURLOPT_FTP_SSL_CCC),
            155 => Some(Self::CURLOPT_TIMEOUT_MS),
            156 => Some(Self::CURLOPT_CONNECTTIMEOUT_MS),
            157 => Some(Self::CURLOPT_HTTP_TRANSFER_DECODING),
            158 => Some(Self::CURLOPT_HTTP_CONTENT_DECODING),
            159 => Some(Self::CURLOPT_NEW_FILE_PERMS),
            160 => Some(Self::CURLOPT_NEW_DIRECTORY_PERMS),
            161 => Some(Self::CURLOPT_POSTREDIR),
            166 => Some(Self::CURLOPT_PROXY_TRANSFER_MODE),
            171 => Some(Self::CURLOPT_ADDRESS_SCOPE),
            172 => Some(Self::CURLOPT_CERTINFO),
            178 => Some(Self::CURLOPT_TFTP_BLKSIZE),
            180 => Some(Self::CURLOPT_SOCKS5_GSSAPI_NEC),
            188 => Some(Self::CURLOPT_FTP_USE_PRET),
            189 => Some(Self::CURLOPT_RTSP_REQUEST),
            193 => Some(Self::CURLOPT_RTSP_CLIENT_CSEQ),
            194 => Some(Self::CURLOPT_RTSP_SERVER_CSEQ),
            197 => Some(Self::CURLOPT_WILDCARDMATCH),
            207 => Some(Self::CURLOPT_TRANSFER_ENCODING),
            210 => Some(Self::CURLOPT_GSSAPI_DELEGATION),
            212 => Some(Self::CURLOPT_ACCEPTTIMEOUT_MS),
            213 => Some(Self::CURLOPT_TCP_KEEPALIVE),
            214 => Some(Self::CURLOPT_TCP_KEEPIDLE),
            215 => Some(Self::CURLOPT_TCP_KEEPINTVL),
            216 => Some(Self::CURLOPT_SSL_OPTIONS),
            218 => Some(Self::CURLOPT_SASL_IR),
            226 => Some(Self::CURLOPT_SSL_ENABLE_ALPN),
            227 => Some(Self::CURLOPT_EXPECT_100_TIMEOUT_MS),
            229 => Some(Self::CURLOPT_HEADEROPT),
            232 => Some(Self::CURLOPT_SSL_VERIFYSTATUS),
            234 => Some(Self::CURLOPT_PATH_AS_IS),
            237 => Some(Self::CURLOPT_PIPEWAIT),
            239 => Some(Self::CURLOPT_STREAM_WEIGHT),
            242 => Some(Self::CURLOPT_TFTP_NO_OPTIONS),
            244 => Some(Self::CURLOPT_TCP_FASTOPEN),
            245 => Some(Self::CURLOPT_KEEP_SENDING_ON_ERROR),
            248 => Some(Self::CURLOPT_PROXY_SSL_VERIFYPEER),
            249 => Some(Self::CURLOPT_PROXY_SSL_VERIFYHOST),
            250 => Some(Self::CURLOPT_PROXY_SSLVERSION),
            261 => Some(Self::CURLOPT_PROXY_SSL_OPTIONS),
            265 => Some(Self::CURLOPT_SUPPRESS_CONNECT_HEADERS),
            267 => Some(Self::CURLOPT_SOCKS5_AUTH),
            268 => Some(Self::CURLOPT_SSH_COMPRESSION),
            271 => Some(Self::CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS),
            274 => Some(Self::CURLOPT_HAPROXYPROTOCOL),
            275 => Some(Self::CURLOPT_DNS_SHUFFLE_ADDRESSES),
            278 => Some(Self::CURLOPT_DISALLOW_USERNAME_IN_URL),
            280 => Some(Self::CURLOPT_UPLOAD_BUFFERSIZE),
            281 => Some(Self::CURLOPT_UPKEEP_INTERVAL_MS),
            285 => Some(Self::CURLOPT_HTTP09_ALLOWED),
            286 => Some(Self::CURLOPT_ALTSVC_CTRL),
            288 => Some(Self::CURLOPT_MAXAGE_CONN),
            290 => Some(Self::CURLOPT_MAIL_RCPT_ALLOWFAILS),
            299 => Some(Self::CURLOPT_HSTS_CTRL),
            306 => Some(Self::CURLOPT_DOH_SSL_VERIFYPEER),
            307 => Some(Self::CURLOPT_DOH_SSL_VERIFYHOST),
            308 => Some(Self::CURLOPT_DOH_SSL_VERIFYSTATUS),
            314 => Some(Self::CURLOPT_MAXLIFETIME_CONN),
            315 => Some(Self::CURLOPT_MIME_OPTIONS),
            320 => Some(Self::CURLOPT_WS_OPTIONS),
            321 => Some(Self::CURLOPT_CA_CACHE_TIMEOUT),
            322 => Some(Self::CURLOPT_QUICK_EXIT),
            324 => Some(Self::CURLOPT_SERVER_RESPONSE_TIMEOUT_MS),
            326 => Some(Self::CURLOPT_TCP_KEEPCNT),
            327 => Some(Self::CURLOPT_UPLOAD_FLAGS),
            10_001 => Some(Self::CURLOPT_WRITEDATA),
            10_002 => Some(Self::CURLOPT_URL),
            10_004 => Some(Self::CURLOPT_PROXY),
            10_005 => Some(Self::CURLOPT_USERPWD),
            10_006 => Some(Self::CURLOPT_PROXYUSERPWD),
            10_007 => Some(Self::CURLOPT_RANGE),
            10_009 => Some(Self::CURLOPT_READDATA),
            10_010 => Some(Self::CURLOPT_ERRORBUFFER),
            10_015 => Some(Self::CURLOPT_POSTFIELDS),
            10_016 => Some(Self::CURLOPT_REFERER),
            10_017 => Some(Self::CURLOPT_FTPPORT),
            10_018 => Some(Self::CURLOPT_USERAGENT),
            10_022 => Some(Self::CURLOPT_COOKIE),
            10_023 => Some(Self::CURLOPT_HTTPHEADER),
            10_025 => Some(Self::CURLOPT_SSLCERT),
            10_026 => Some(Self::CURLOPT_KEYPASSWD),
            10_028 => Some(Self::CURLOPT_QUOTE),
            10_029 => Some(Self::CURLOPT_HEADERDATA),
            10_031 => Some(Self::CURLOPT_COOKIEFILE),
            10_036 => Some(Self::CURLOPT_CUSTOMREQUEST),
            10_037 => Some(Self::CURLOPT_STDERR),
            10_039 => Some(Self::CURLOPT_POSTQUOTE),
            10_057 => Some(Self::CURLOPT_XFERINFODATA),
            10_062 => Some(Self::CURLOPT_INTERFACE),
            10_065 => Some(Self::CURLOPT_CAINFO),
            10_070 => Some(Self::CURLOPT_TELNETOPTIONS),
            10_082 => Some(Self::CURLOPT_COOKIEJAR),
            10_083 => Some(Self::CURLOPT_SSL_CIPHER_LIST),
            10_086 => Some(Self::CURLOPT_SSLCERTTYPE),
            10_087 => Some(Self::CURLOPT_SSLKEY),
            10_088 => Some(Self::CURLOPT_SSLKEYTYPE),
            10_089 => Some(Self::CURLOPT_SSLENGINE),
            10_093 => Some(Self::CURLOPT_PREQUOTE),
            10_095 => Some(Self::CURLOPT_DEBUGDATA),
            10_097 => Some(Self::CURLOPT_CAPATH),
            10_100 => Some(Self::CURLOPT_SHARE),
            10_102 => Some(Self::CURLOPT_ACCEPT_ENCODING),
            10_103 => Some(Self::CURLOPT_PRIVATE),
            10_104 => Some(Self::CURLOPT_HTTP200ALIASES),
            10_109 => Some(Self::CURLOPT_SSL_CTX_DATA),
            10_118 => Some(Self::CURLOPT_NETRC_FILE),
            10_134 => Some(Self::CURLOPT_FTP_ACCOUNT),
            10_135 => Some(Self::CURLOPT_COOKIELIST),
            10_147 => Some(Self::CURLOPT_FTP_ALTERNATIVE_TO_USER),
            10_149 => Some(Self::CURLOPT_SOCKOPTDATA),
            10_152 => Some(Self::CURLOPT_SSH_PUBLIC_KEYFILE),
            10_153 => Some(Self::CURLOPT_SSH_PRIVATE_KEYFILE),
            10_162 => Some(Self::CURLOPT_SSH_HOST_PUBLIC_KEY_MD5),
            10_164 => Some(Self::CURLOPT_OPENSOCKETDATA),
            10_165 => Some(Self::CURLOPT_COPYPOSTFIELDS),
            10_168 => Some(Self::CURLOPT_SEEKDATA),
            10_169 => Some(Self::CURLOPT_CRLFILE),
            10_170 => Some(Self::CURLOPT_ISSUERCERT),
            10_173 => Some(Self::CURLOPT_USERNAME),
            10_174 => Some(Self::CURLOPT_PASSWORD),
            10_175 => Some(Self::CURLOPT_PROXYUSERNAME),
            10_176 => Some(Self::CURLOPT_PROXYPASSWORD),
            10_177 => Some(Self::CURLOPT_NOPROXY),
            10_183 => Some(Self::CURLOPT_SSH_KNOWNHOSTS),
            10_185 => Some(Self::CURLOPT_SSH_KEYDATA),
            10_186 => Some(Self::CURLOPT_MAIL_FROM),
            10_187 => Some(Self::CURLOPT_MAIL_RCPT),
            10_190 => Some(Self::CURLOPT_RTSP_SESSION_ID),
            10_191 => Some(Self::CURLOPT_RTSP_STREAM_URI),
            10_192 => Some(Self::CURLOPT_RTSP_TRANSPORT),
            10_195 => Some(Self::CURLOPT_INTERLEAVEDATA),
            10_201 => Some(Self::CURLOPT_CHUNK_DATA),
            10_202 => Some(Self::CURLOPT_FNMATCH_DATA),
            10_203 => Some(Self::CURLOPT_RESOLVE),
            10_204 => Some(Self::CURLOPT_TLSAUTH_USERNAME),
            10_205 => Some(Self::CURLOPT_TLSAUTH_PASSWORD),
            10_206 => Some(Self::CURLOPT_TLSAUTH_TYPE),
            10_209 => Some(Self::CURLOPT_CLOSESOCKETDATA),
            10_211 => Some(Self::CURLOPT_DNS_SERVERS),
            10_217 => Some(Self::CURLOPT_MAIL_AUTH),
            10_220 => Some(Self::CURLOPT_XOAUTH2_BEARER),
            10_221 => Some(Self::CURLOPT_DNS_INTERFACE),
            10_222 => Some(Self::CURLOPT_DNS_LOCAL_IP4),
            10_223 => Some(Self::CURLOPT_DNS_LOCAL_IP6),
            10_224 => Some(Self::CURLOPT_LOGIN_OPTIONS),
            10_228 => Some(Self::CURLOPT_PROXYHEADER),
            10_230 => Some(Self::CURLOPT_PINNEDPUBLICKEY),
            10_231 => Some(Self::CURLOPT_UNIX_SOCKET_PATH),
            10_235 => Some(Self::CURLOPT_PROXY_SERVICE_NAME),
            10_236 => Some(Self::CURLOPT_SERVICE_NAME),
            10_238 => Some(Self::CURLOPT_DEFAULT_PROTOCOL),
            10_240 => Some(Self::CURLOPT_STREAM_DEPENDS),
            10_241 => Some(Self::CURLOPT_STREAM_DEPENDS_E),
            10_243 => Some(Self::CURLOPT_CONNECT_TO),
            10_246 => Some(Self::CURLOPT_PROXY_CAINFO),
            10_247 => Some(Self::CURLOPT_PROXY_CAPATH),
            10_251 => Some(Self::CURLOPT_PROXY_TLSAUTH_USERNAME),
            10_252 => Some(Self::CURLOPT_PROXY_TLSAUTH_PASSWORD),
            10_253 => Some(Self::CURLOPT_PROXY_TLSAUTH_TYPE),
            10_254 => Some(Self::CURLOPT_PROXY_SSLCERT),
            10_255 => Some(Self::CURLOPT_PROXY_SSLCERTTYPE),
            10_256 => Some(Self::CURLOPT_PROXY_SSLKEY),
            10_257 => Some(Self::CURLOPT_PROXY_SSLKEYTYPE),
            10_258 => Some(Self::CURLOPT_PROXY_KEYPASSWD),
            10_259 => Some(Self::CURLOPT_PROXY_SSL_CIPHER_LIST),
            10_260 => Some(Self::CURLOPT_PROXY_CRLFILE),
            10_262 => Some(Self::CURLOPT_PRE_PROXY),
            10_263 => Some(Self::CURLOPT_PROXY_PINNEDPUBLICKEY),
            10_264 => Some(Self::CURLOPT_ABSTRACT_UNIX_SOCKET),
            10_266 => Some(Self::CURLOPT_REQUEST_TARGET),
            10_269 => Some(Self::CURLOPT_MIMEPOST),
            10_273 => Some(Self::CURLOPT_RESOLVER_START_DATA),
            10_276 => Some(Self::CURLOPT_TLS13_CIPHERS),
            10_277 => Some(Self::CURLOPT_PROXY_TLS13_CIPHERS),
            10_279 => Some(Self::CURLOPT_DOH_URL),
            10_282 => Some(Self::CURLOPT_CURLU),
            10_284 => Some(Self::CURLOPT_TRAILERDATA),
            10_287 => Some(Self::CURLOPT_ALTSVC),
            10_289 => Some(Self::CURLOPT_SASL_AUTHZID),
            10_296 => Some(Self::CURLOPT_PROXY_ISSUERCERT),
            10_298 => Some(Self::CURLOPT_SSL_EC_CURVES),
            10_300 => Some(Self::CURLOPT_HSTS),
            10_302 => Some(Self::CURLOPT_HSTSREADDATA),
            10_304 => Some(Self::CURLOPT_HSTSWRITEDATA),
            10_305 => Some(Self::CURLOPT_AWS_SIGV4),
            10_311 => Some(Self::CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256),
            10_313 => Some(Self::CURLOPT_PREREQDATA),
            10_317 => Some(Self::CURLOPT_SSH_HOSTKEYDATA),
            10_318 => Some(Self::CURLOPT_PROTOCOLS_STR),
            10_319 => Some(Self::CURLOPT_REDIR_PROTOCOLS_STR),
            10_323 => Some(Self::CURLOPT_HAPROXY_CLIENT_IP),
            10_325 => Some(Self::CURLOPT_ECH),
            10_328 => Some(Self::CURLOPT_SSL_SIGNATURE_ALGORITHMS),
            20_011 => Some(Self::CURLOPT_WRITEFUNCTION),
            20_012 => Some(Self::CURLOPT_READFUNCTION),
            20_079 => Some(Self::CURLOPT_HEADERFUNCTION),
            20_094 => Some(Self::CURLOPT_DEBUGFUNCTION),
            20_108 => Some(Self::CURLOPT_SSL_CTX_FUNCTION),
            20_148 => Some(Self::CURLOPT_SOCKOPTFUNCTION),
            20_163 => Some(Self::CURLOPT_OPENSOCKETFUNCTION),
            20_167 => Some(Self::CURLOPT_SEEKFUNCTION),
            20_184 => Some(Self::CURLOPT_SSH_KEYFUNCTION),
            20_196 => Some(Self::CURLOPT_INTERLEAVEFUNCTION),
            20_198 => Some(Self::CURLOPT_CHUNK_BGN_FUNCTION),
            20_199 => Some(Self::CURLOPT_CHUNK_END_FUNCTION),
            20_200 => Some(Self::CURLOPT_FNMATCH_FUNCTION),
            20_208 => Some(Self::CURLOPT_CLOSESOCKETFUNCTION),
            20_219 => Some(Self::CURLOPT_XFERINFOFUNCTION),
            20_272 => Some(Self::CURLOPT_RESOLVER_START_FUNCTION),
            20_283 => Some(Self::CURLOPT_TRAILERFUNCTION),
            20_301 => Some(Self::CURLOPT_HSTSREADFUNCTION),
            20_303 => Some(Self::CURLOPT_HSTSWRITEFUNCTION),
            20_312 => Some(Self::CURLOPT_PREREQFUNCTION),
            20_316 => Some(Self::CURLOPT_SSH_HOSTKEYFUNCTION),
            30_115 => Some(Self::CURLOPT_INFILESIZE_LARGE),
            30_116 => Some(Self::CURLOPT_RESUME_FROM_LARGE),
            30_117 => Some(Self::CURLOPT_MAXFILESIZE_LARGE),
            30_120 => Some(Self::CURLOPT_POSTFIELDSIZE_LARGE),
            30_145 => Some(Self::CURLOPT_MAX_SEND_SPEED_LARGE),
            30_146 => Some(Self::CURLOPT_MAX_RECV_SPEED_LARGE),
            30_270 => Some(Self::CURLOPT_TIMEVALUE_LARGE),
            40_291 => Some(Self::CURLOPT_SSLCERT_BLOB),
            40_292 => Some(Self::CURLOPT_SSLKEY_BLOB),
            40_293 => Some(Self::CURLOPT_PROXY_SSLCERT_BLOB),
            40_294 => Some(Self::CURLOPT_PROXY_SSLKEY_BLOB),
            40_295 => Some(Self::CURLOPT_ISSUERCERT_BLOB),
            40_297 => Some(Self::CURLOPT_PROXY_ISSUERCERT_BLOB),
            40_309 => Some(Self::CURLOPT_CAINFO_BLOB),
            40_310 => Some(Self::CURLOPT_PROXY_CAINFO_BLOB),
            _ => None,
        }
    }

    /// Returns the expected value kind name for diagnostics.
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
            "ObjectPoint/SList"
        } else {
            "Long"
        }
    }
}

/// A typed container for option values passed to [`set_option`].
#[derive(Debug, Clone)]
pub enum CurlOptValue {
    /// Integer / boolean / enumerated value.
    Long(i64),
    /// String value (URL, path, header, etc.).
    ObjectPoint(String),
    /// Callback function pointer marker.
    FunctionPoint,
    /// 64-bit offset value.
    OffT(i64),
    /// Binary data blob.
    Blob(Vec<u8>),
    /// String list.
    SList(SList),
}

impl CurlOptValue {
    /// Returns a human-readable name for the variant.
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

    /// Extracts the inner `i64` if `self` is `Long`.
    pub fn as_long(&self) -> CurlResult<i64> {
        match self {
            Self::Long(v) => Ok(*v),
            _ => {
                tracing::error!("expected Long, got {}", self.kind_name());
                Err(CurlError::BadFunctionArgument)
            }
        }
    }

    /// Extracts the inner `i64` if `self` is `OffT`.
    pub fn as_offt(&self) -> CurlResult<i64> {
        match self {
            Self::OffT(v) => Ok(*v),
            _ => {
                tracing::error!("expected OffT, got {}", self.kind_name());
                Err(CurlError::BadFunctionArgument)
            }
        }
    }

    /// Extracts a reference to the inner `String` if `self` is `ObjectPoint`.
    pub fn as_str(&self) -> CurlResult<&str> {
        match self {
            Self::ObjectPoint(s) => Ok(s.as_str()),
            _ => {
                tracing::error!("expected ObjectPoint, got {}", self.kind_name());
                Err(CurlError::BadFunctionArgument)
            }
        }
    }

    /// Extracts the inner `SList` if `self` is `SList`.
    pub fn into_slist(self) -> CurlResult<SList> {
        match self {
            Self::SList(s) => Ok(s),
            _ => {
                tracing::error!("expected SList, got {}", self.kind_name());
                Err(CurlError::BadFunctionArgument)
            }
        }
    }

    /// Extracts the inner `Vec<u8>` if `self` is `Blob`.
    pub fn into_blob(self) -> CurlResult<Vec<u8>> {
        match self {
            Self::Blob(b) => Ok(b),
            _ => {
                tracing::error!("expected Blob, got {}", self.kind_name());
                Err(CurlError::BadFunctionArgument)
            }
        }
    }
}

/// Stores all option values set via [`set_option`].
#[derive(Debug, Clone)]
pub struct HandleOptions {
    /// Storage for `CURLOPT_PORT`.
    pub port: i64,
    /// Storage for `CURLOPT_TIMEOUT`.
    pub timeout_ms: i64,
    /// Storage for `CURLOPT_INFILESIZE`.
    pub infilesize: i64,
    /// Storage for `CURLOPT_LOW_SPEED_LIMIT`.
    pub low_speed_limit: i64,
    /// Storage for `CURLOPT_LOW_SPEED_TIME`.
    pub low_speed_time: i64,
    /// Storage for `CURLOPT_RESUME_FROM`.
    pub resume_from: i64,
    /// Storage for `CURLOPT_CRLF`.
    pub crlf: bool,
    /// Storage for `CURLOPT_SSLVERSION`.
    pub sslversion: i64,
    /// Storage for `CURLOPT_TIMECONDITION`.
    pub timecondition: i64,
    /// Storage for `CURLOPT_TIMEVALUE`.
    pub timevalue: i64,
    /// Storage for `CURLOPT_VERBOSE`.
    pub verbose: bool,
    /// Storage for `CURLOPT_HEADER`.
    pub header: bool,
    /// Storage for `CURLOPT_NOPROGRESS`.
    pub noprogress: bool,
    /// Storage for `CURLOPT_NOBODY`.
    pub nobody: bool,
    /// Storage for `CURLOPT_FAILONERROR`.
    pub failonerror: bool,
    /// Storage for `CURLOPT_UPLOAD`.
    pub upload: bool,
    /// Storage for `CURLOPT_POST`.
    pub post: bool,
    /// Storage for `CURLOPT_DIRLISTONLY`.
    pub dirlistonly: bool,
    /// Storage for `CURLOPT_APPEND`.
    pub append: bool,
    /// Storage for `CURLOPT_NETRC`.
    pub netrc: i64,
    /// Storage for `CURLOPT_FOLLOWLOCATION`.
    pub followlocation: i64,
    /// Storage for `CURLOPT_TRANSFERTEXT`.
    pub transfertext: bool,
    /// Storage for `CURLOPT_AUTOREFERER`.
    pub autoreferer: bool,
    /// Storage for `CURLOPT_PROXYPORT`.
    pub proxyport: i64,
    /// Storage for `CURLOPT_POSTFIELDSIZE`.
    pub postfieldsize: i64,
    /// Storage for `CURLOPT_HTTPPROXYTUNNEL`.
    pub httpproxytunnel: bool,
    /// Storage for `CURLOPT_SSL_VERIFYPEER`.
    pub ssl_verifypeer: bool,
    /// Storage for `CURLOPT_MAXREDIRS`.
    pub maxredirs: i64,
    /// Storage for `CURLOPT_FILETIME`.
    pub filetime: bool,
    /// Storage for `CURLOPT_MAXCONNECTS`.
    pub maxconnects: i64,
    /// Storage for `CURLOPT_FRESH_CONNECT`.
    pub fresh_connect: bool,
    /// Storage for `CURLOPT_FORBID_REUSE`.
    pub forbid_reuse: bool,
    /// Storage for `CURLOPT_CONNECTTIMEOUT`.
    pub connecttimeout_ms: i64,
    /// Storage for `CURLOPT_HTTPGET`.
    pub httpget: bool,
    /// Storage for `CURLOPT_SSL_VERIFYHOST`.
    pub ssl_verifyhost: i64,
    /// Storage for `CURLOPT_HTTP_VERSION`.
    pub http_version: i64,
    /// Storage for `CURLOPT_FTP_USE_EPSV`.
    pub ftp_use_epsv: bool,
    /// Storage for `CURLOPT_SSLENGINE_DEFAULT`.
    pub sslengine_default: bool,
    /// Storage for `CURLOPT_DNS_CACHE_TIMEOUT`.
    pub dns_cache_timeout: i64,
    /// Storage for `CURLOPT_COOKIESESSION`.
    pub cookiesession: bool,
    /// Storage for `CURLOPT_BUFFERSIZE`.
    pub buffersize: i64,
    /// Storage for `CURLOPT_NOSIGNAL`.
    pub nosignal: bool,
    /// Storage for `CURLOPT_PROXYTYPE`.
    pub proxytype: i64,
    /// Storage for `CURLOPT_UNRESTRICTED_AUTH`.
    pub unrestricted_auth: bool,
    /// Storage for `CURLOPT_FTP_USE_EPRT`.
    pub ftp_use_eprt: bool,
    /// Storage for `CURLOPT_HTTPAUTH`.
    pub httpauth: u64,
    /// Storage for `CURLOPT_FTP_CREATE_MISSING_DIRS`.
    pub ftp_create_missing_dirs: i64,
    /// Storage for `CURLOPT_PROXYAUTH`.
    pub proxyauth: u64,
    /// Storage for `CURLOPT_SERVER_RESPONSE_TIMEOUT`.
    pub server_response_timeout: i64,
    /// Storage for `CURLOPT_IPRESOLVE`.
    pub ipresolve: i64,
    /// Storage for `CURLOPT_MAXFILESIZE`.
    pub maxfilesize: i64,
    /// Storage for `CURLOPT_USE_SSL`.
    pub use_ssl: i64,
    /// Storage for `CURLOPT_TCP_NODELAY`.
    pub tcp_nodelay: bool,
    /// Storage for `CURLOPT_FTPSSLAUTH`.
    pub ftpsslauth: i64,
    /// Storage for `CURLOPT_IGNORE_CONTENT_LENGTH`.
    pub ignore_content_length: bool,
    /// Storage for `CURLOPT_FTP_SKIP_PASV_IP`.
    pub ftp_skip_pasv_ip: bool,
    /// Storage for `CURLOPT_FTP_FILEMETHOD`.
    pub ftp_filemethod: i64,
    /// Storage for `CURLOPT_LOCALPORT`.
    pub localport: i64,
    /// Storage for `CURLOPT_LOCALPORTRANGE`.
    pub localportrange: i64,
    /// Storage for `CURLOPT_CONNECT_ONLY`.
    pub connect_only: i64,
    /// Storage for `CURLOPT_SSL_SESSIONID_CACHE`.
    pub ssl_sessionid_cache: bool,
    /// Storage for `CURLOPT_SSH_AUTH_TYPES`.
    pub ssh_auth_types: i64,
    /// Storage for `CURLOPT_FTP_SSL_CCC`.
    pub ftp_ssl_ccc: i64,
    /// Storage for `CURLOPT_HTTP_TRANSFER_DECODING`.
    pub http_transfer_decoding: bool,
    /// Storage for `CURLOPT_HTTP_CONTENT_DECODING`.
    pub http_content_decoding: bool,
    /// Storage for `CURLOPT_NEW_FILE_PERMS`.
    pub new_file_perms: i64,
    /// Storage for `CURLOPT_NEW_DIRECTORY_PERMS`.
    pub new_directory_perms: i64,
    /// Storage for `CURLOPT_POSTREDIR`.
    pub postredir: i64,
    /// Storage for `CURLOPT_PROXY_TRANSFER_MODE`.
    pub proxy_transfer_mode: bool,
    /// Storage for `CURLOPT_ADDRESS_SCOPE`.
    pub address_scope: i64,
    /// Storage for `CURLOPT_CERTINFO`.
    pub certinfo: bool,
    /// Storage for `CURLOPT_TFTP_BLKSIZE`.
    pub tftp_blksize: i64,
    /// Storage for `CURLOPT_SOCKS5_GSSAPI_NEC`.
    pub socks5_gssapi_nec: bool,
    /// Storage for `CURLOPT_FTP_USE_PRET`.
    pub ftp_use_pret: bool,
    /// Storage for `CURLOPT_RTSP_REQUEST`.
    pub rtsp_request: i64,
    /// Storage for `CURLOPT_RTSP_CLIENT_CSEQ`.
    pub rtsp_client_cseq: i64,
    /// Storage for `CURLOPT_RTSP_SERVER_CSEQ`.
    pub rtsp_server_cseq: i64,
    /// Storage for `CURLOPT_WILDCARDMATCH`.
    pub wildcardmatch: bool,
    /// Storage for `CURLOPT_TRANSFER_ENCODING`.
    pub transfer_encoding: bool,
    /// Storage for `CURLOPT_GSSAPI_DELEGATION`.
    pub gssapi_delegation: i64,
    /// Storage for `CURLOPT_ACCEPTTIMEOUT_MS`.
    pub accepttimeout_ms: i64,
    /// Storage for `CURLOPT_TCP_KEEPALIVE`.
    pub tcp_keepalive: bool,
    /// Storage for `CURLOPT_TCP_KEEPIDLE`.
    pub tcp_keepidle: i64,
    /// Storage for `CURLOPT_TCP_KEEPINTVL`.
    pub tcp_keepintvl: i64,
    /// Storage for `CURLOPT_SSL_OPTIONS`.
    pub ssl_options: i64,
    /// Storage for `CURLOPT_SASL_IR`.
    pub sasl_ir: bool,
    /// Storage for `CURLOPT_SSL_ENABLE_ALPN`.
    pub ssl_enable_alpn: bool,
    /// Storage for `CURLOPT_EXPECT_100_TIMEOUT_MS`.
    pub expect_100_timeout_ms: i64,
    /// Storage for `CURLOPT_HEADEROPT`.
    pub headeropt: i64,
    /// Storage for `CURLOPT_SSL_VERIFYSTATUS`.
    pub ssl_verifystatus: bool,
    /// Storage for `CURLOPT_PATH_AS_IS`.
    pub path_as_is: bool,
    /// Storage for `CURLOPT_PIPEWAIT`.
    pub pipewait: bool,
    /// Storage for `CURLOPT_STREAM_WEIGHT`.
    pub stream_weight: i64,
    /// Storage for `CURLOPT_TFTP_NO_OPTIONS`.
    pub tftp_no_options: bool,
    /// Storage for `CURLOPT_TCP_FASTOPEN`.
    pub tcp_fastopen: bool,
    /// Storage for `CURLOPT_KEEP_SENDING_ON_ERROR`.
    pub keep_sending_on_error: bool,
    /// Storage for `CURLOPT_PROXY_SSL_VERIFYPEER`.
    pub proxy_ssl_verifypeer: bool,
    /// Storage for `CURLOPT_PROXY_SSL_VERIFYHOST`.
    pub proxy_ssl_verifyhost: i64,
    /// Storage for `CURLOPT_PROXY_SSLVERSION`.
    pub proxy_sslversion: i64,
    /// Storage for `CURLOPT_PROXY_SSL_OPTIONS`.
    pub proxy_ssl_options: i64,
    /// Storage for `CURLOPT_SUPPRESS_CONNECT_HEADERS`.
    pub suppress_connect_headers: bool,
    /// Storage for `CURLOPT_SOCKS5_AUTH`.
    pub socks5_auth: i64,
    /// Storage for `CURLOPT_SSH_COMPRESSION`.
    pub ssh_compression: bool,
    /// Storage for `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`.
    pub happy_eyeballs_timeout_ms: i64,
    /// Storage for `CURLOPT_HAPROXYPROTOCOL`.
    pub haproxyprotocol: bool,
    /// Storage for `CURLOPT_DNS_SHUFFLE_ADDRESSES`.
    pub dns_shuffle_addresses: bool,
    /// Storage for `CURLOPT_DISALLOW_USERNAME_IN_URL`.
    pub disallow_username_in_url: bool,
    /// Storage for `CURLOPT_UPLOAD_BUFFERSIZE`.
    pub upload_buffersize: i64,
    /// Storage for `CURLOPT_UPKEEP_INTERVAL_MS`.
    pub upkeep_interval_ms: i64,
    /// Storage for `CURLOPT_HTTP09_ALLOWED`.
    pub http09_allowed: bool,
    /// Storage for `CURLOPT_ALTSVC_CTRL`.
    pub altsvc_ctrl: i64,
    /// Storage for `CURLOPT_MAXAGE_CONN`.
    pub maxage_conn: i64,
    /// Storage for `CURLOPT_MAIL_RCPT_ALLOWFAILS`.
    pub mail_rcpt_allowfails: bool,
    /// Storage for `CURLOPT_HSTS_CTRL`.
    pub hsts_ctrl: i64,
    /// Storage for `CURLOPT_DOH_SSL_VERIFYPEER`.
    pub doh_ssl_verifypeer: bool,
    /// Storage for `CURLOPT_DOH_SSL_VERIFYHOST`.
    pub doh_ssl_verifyhost: bool,
    /// Storage for `CURLOPT_DOH_SSL_VERIFYSTATUS`.
    pub doh_ssl_verifystatus: bool,
    /// Storage for `CURLOPT_MAXLIFETIME_CONN`.
    pub maxlifetime_conn: i64,
    /// Storage for `CURLOPT_MIME_OPTIONS`.
    pub mime_options: i64,
    /// Storage for `CURLOPT_WS_OPTIONS`.
    pub ws_options: i64,
    /// Storage for `CURLOPT_CA_CACHE_TIMEOUT`.
    pub ca_cache_timeout: i64,
    /// Storage for `CURLOPT_QUICK_EXIT`.
    pub quick_exit: bool,
    /// Storage for `CURLOPT_SERVER_RESPONSE_TIMEOUT_MS`.
    pub server_response_timeout_ms: i64,
    /// Storage for `CURLOPT_TCP_KEEPCNT`.
    pub tcp_keepcnt: i64,
    /// Storage for `CURLOPT_UPLOAD_FLAGS`.
    pub upload_flags: i64,
    /// Storage for `CURLOPT_WRITEDATA`.
    pub has_writedata: bool,
    /// Storage for `CURLOPT_URL`.
    pub url: Option<String>,
    /// Storage for `CURLOPT_PROXY`.
    pub proxy: Option<String>,
    /// Storage for `CURLOPT_USERPWD`.
    pub userpwd: Option<String>,
    /// Storage for `CURLOPT_PROXYUSERPWD`.
    pub proxyuserpwd: Option<String>,
    /// Storage for `CURLOPT_RANGE`.
    pub range: Option<String>,
    /// Storage for `CURLOPT_READDATA`.
    pub has_readdata: bool,
    /// Storage for `CURLOPT_ERRORBUFFER`.
    pub errorbuffer: bool,
    /// Storage for `CURLOPT_POSTFIELDS`.
    pub postfields: Option<String>,
    /// Storage for `CURLOPT_REFERER`.
    pub referer: Option<String>,
    /// Storage for `CURLOPT_FTPPORT`.
    pub ftpport: Option<String>,
    /// Storage for `CURLOPT_USERAGENT`.
    pub useragent: Option<String>,
    /// Storage for `CURLOPT_COOKIE`.
    pub cookie: Option<String>,
    /// Storage for `CURLOPT_HTTPHEADER`.
    pub httpheader: Option<SList>,
    /// Storage for `CURLOPT_SSLCERT`.
    pub sslcert: Option<String>,
    /// Storage for `CURLOPT_KEYPASSWD`.
    pub keypasswd: Option<String>,
    /// Storage for `CURLOPT_QUOTE`.
    pub quote: Option<SList>,
    /// Storage for `CURLOPT_HEADERDATA`.
    pub has_headerdata: bool,
    /// Storage for `CURLOPT_COOKIEFILE`.
    pub cookiefile: Option<String>,
    /// Storage for `CURLOPT_CUSTOMREQUEST`.
    pub customrequest: Option<String>,
    /// Storage for `CURLOPT_STDERR`.
    pub stderr: bool,
    /// Storage for `CURLOPT_POSTQUOTE`.
    pub postquote: Option<SList>,
    /// Storage for `CURLOPT_XFERINFODATA`.
    pub has_xferinfodata: bool,
    /// Storage for `CURLOPT_INTERFACE`.
    pub interface: Option<String>,
    /// Storage for `CURLOPT_CAINFO`.
    pub cainfo: Option<String>,
    /// Storage for `CURLOPT_TELNETOPTIONS`.
    pub telnetoptions: Option<SList>,
    /// Storage for `CURLOPT_COOKIEJAR`.
    pub cookiejar: Option<String>,
    /// Storage for `CURLOPT_SSL_CIPHER_LIST`.
    pub ssl_cipher_list: Option<String>,
    /// Storage for `CURLOPT_SSLCERTTYPE`.
    pub sslcerttype: Option<String>,
    /// Storage for `CURLOPT_SSLKEY`.
    pub sslkey: Option<String>,
    /// Storage for `CURLOPT_SSLKEYTYPE`.
    pub sslkeytype: Option<String>,
    /// Storage for `CURLOPT_SSLENGINE`.
    pub sslengine: Option<String>,
    /// Storage for `CURLOPT_PREQUOTE`.
    pub prequote: Option<SList>,
    /// Storage for `CURLOPT_DEBUGDATA`.
    pub has_debugdata: bool,
    /// Storage for `CURLOPT_CAPATH`.
    pub capath: Option<String>,
    /// Storage for `CURLOPT_SHARE`.
    pub share: bool,
    /// Storage for `CURLOPT_ACCEPT_ENCODING`.
    pub accept_encoding: Option<String>,
    /// Storage for `CURLOPT_PRIVATE`.
    pub private: bool,
    /// Storage for `CURLOPT_HTTP200ALIASES`.
    pub http200aliases: Option<SList>,
    /// Storage for `CURLOPT_SSL_CTX_DATA`.
    pub has_ssl_ctx_data: bool,
    /// Storage for `CURLOPT_NETRC_FILE`.
    pub netrc_file: Option<String>,
    /// Storage for `CURLOPT_FTP_ACCOUNT`.
    pub ftp_account: Option<String>,
    /// Storage for `CURLOPT_COOKIELIST`.
    pub cookielist: Option<String>,
    /// Storage for `CURLOPT_FTP_ALTERNATIVE_TO_USER`.
    pub ftp_alternative_to_user: Option<String>,
    /// Storage for `CURLOPT_SOCKOPTDATA`.
    pub has_sockoptdata: bool,
    /// Storage for `CURLOPT_SSH_PUBLIC_KEYFILE`.
    pub ssh_public_keyfile: Option<String>,
    /// Storage for `CURLOPT_SSH_PRIVATE_KEYFILE`.
    pub ssh_private_keyfile: Option<String>,
    /// Storage for `CURLOPT_SSH_HOST_PUBLIC_KEY_MD5`.
    pub ssh_host_public_key_md5: Option<String>,
    /// Storage for `CURLOPT_OPENSOCKETDATA`.
    pub has_opensocketdata: bool,
    /// Storage for `CURLOPT_COPYPOSTFIELDS`.
    pub copypostfields: Option<String>,
    /// Storage for `CURLOPT_SEEKDATA`.
    pub has_seekdata: bool,
    /// Storage for `CURLOPT_CRLFILE`.
    pub crlfile: Option<String>,
    /// Storage for `CURLOPT_ISSUERCERT`.
    pub issuercert: Option<String>,
    /// Storage for `CURLOPT_USERNAME`.
    pub username: Option<String>,
    /// Storage for `CURLOPT_PASSWORD`.
    pub password: Option<String>,
    /// Storage for `CURLOPT_PROXYUSERNAME`.
    pub proxyusername: Option<String>,
    /// Storage for `CURLOPT_PROXYPASSWORD`.
    pub proxypassword: Option<String>,
    /// Storage for `CURLOPT_NOPROXY`.
    pub noproxy: Option<String>,
    /// Storage for `CURLOPT_SSH_KNOWNHOSTS`.
    pub ssh_knownhosts: Option<String>,
    /// Storage for `CURLOPT_SSH_KEYDATA`.
    pub has_ssh_keydata: bool,
    /// Storage for `CURLOPT_MAIL_FROM`.
    pub mail_from: Option<String>,
    /// Storage for `CURLOPT_MAIL_RCPT`.
    pub mail_rcpt: Option<SList>,
    /// Storage for `CURLOPT_RTSP_SESSION_ID`.
    pub rtsp_session_id: Option<String>,
    /// Storage for `CURLOPT_RTSP_STREAM_URI`.
    pub rtsp_stream_uri: Option<String>,
    /// Storage for `CURLOPT_RTSP_TRANSPORT`.
    pub rtsp_transport: Option<String>,
    /// Storage for `CURLOPT_INTERLEAVEDATA`.
    pub has_interleavedata: bool,
    /// Storage for `CURLOPT_CHUNK_DATA`.
    pub has_chunk_data: bool,
    /// Storage for `CURLOPT_FNMATCH_DATA`.
    pub has_fnmatch_data: bool,
    /// Storage for `CURLOPT_RESOLVE`.
    pub resolve: Option<SList>,
    /// Storage for `CURLOPT_TLSAUTH_USERNAME`.
    pub tlsauth_username: Option<String>,
    /// Storage for `CURLOPT_TLSAUTH_PASSWORD`.
    pub tlsauth_password: Option<String>,
    /// Storage for `CURLOPT_TLSAUTH_TYPE`.
    pub tlsauth_type: Option<String>,
    /// Storage for `CURLOPT_CLOSESOCKETDATA`.
    pub has_closesocketdata: bool,
    /// Storage for `CURLOPT_DNS_SERVERS`.
    pub dns_servers: Option<String>,
    /// Storage for `CURLOPT_MAIL_AUTH`.
    pub mail_auth: Option<String>,
    /// Storage for `CURLOPT_XOAUTH2_BEARER`.
    pub xoauth2_bearer: Option<String>,
    /// Storage for `CURLOPT_DNS_INTERFACE`.
    pub dns_interface: Option<String>,
    /// Storage for `CURLOPT_DNS_LOCAL_IP4`.
    pub dns_local_ip4: Option<String>,
    /// Storage for `CURLOPT_DNS_LOCAL_IP6`.
    pub dns_local_ip6: Option<String>,
    /// Storage for `CURLOPT_LOGIN_OPTIONS`.
    pub login_options: Option<String>,
    /// Storage for `CURLOPT_PROXYHEADER`.
    pub proxyheader: Option<SList>,
    /// Storage for `CURLOPT_PINNEDPUBLICKEY`.
    pub pinnedpublickey: Option<String>,
    /// Storage for `CURLOPT_UNIX_SOCKET_PATH`.
    pub unix_socket_path: Option<String>,
    /// Storage for `CURLOPT_PROXY_SERVICE_NAME`.
    pub proxy_service_name: Option<String>,
    /// Storage for `CURLOPT_SERVICE_NAME`.
    pub service_name: Option<String>,
    /// Storage for `CURLOPT_DEFAULT_PROTOCOL`.
    pub default_protocol: Option<String>,
    /// Storage for `CURLOPT_STREAM_DEPENDS`.
    pub stream_depends: bool,
    /// Storage for `CURLOPT_STREAM_DEPENDS_E`.
    pub stream_depends_e: bool,
    /// Storage for `CURLOPT_CONNECT_TO`.
    pub connect_to: Option<SList>,
    /// Storage for `CURLOPT_PROXY_CAINFO`.
    pub proxy_cainfo: Option<String>,
    /// Storage for `CURLOPT_PROXY_CAPATH`.
    pub proxy_capath: Option<String>,
    /// Storage for `CURLOPT_PROXY_TLSAUTH_USERNAME`.
    pub proxy_tlsauth_username: Option<String>,
    /// Storage for `CURLOPT_PROXY_TLSAUTH_PASSWORD`.
    pub proxy_tlsauth_password: Option<String>,
    /// Storage for `CURLOPT_PROXY_TLSAUTH_TYPE`.
    pub proxy_tlsauth_type: Option<String>,
    /// Storage for `CURLOPT_PROXY_SSLCERT`.
    pub proxy_sslcert: Option<String>,
    /// Storage for `CURLOPT_PROXY_SSLCERTTYPE`.
    pub proxy_sslcerttype: Option<String>,
    /// Storage for `CURLOPT_PROXY_SSLKEY`.
    pub proxy_sslkey: Option<String>,
    /// Storage for `CURLOPT_PROXY_SSLKEYTYPE`.
    pub proxy_sslkeytype: Option<String>,
    /// Storage for `CURLOPT_PROXY_KEYPASSWD`.
    pub proxy_keypasswd: Option<String>,
    /// Storage for `CURLOPT_PROXY_SSL_CIPHER_LIST`.
    pub proxy_ssl_cipher_list: Option<String>,
    /// Storage for `CURLOPT_PROXY_CRLFILE`.
    pub proxy_crlfile: Option<String>,
    /// Storage for `CURLOPT_PRE_PROXY`.
    pub pre_proxy: Option<String>,
    /// Storage for `CURLOPT_PROXY_PINNEDPUBLICKEY`.
    pub proxy_pinnedpublickey: Option<String>,
    /// Storage for `CURLOPT_ABSTRACT_UNIX_SOCKET`.
    pub abstract_unix_socket: Option<String>,
    /// Storage for `CURLOPT_REQUEST_TARGET`.
    pub request_target: Option<String>,
    /// Storage for `CURLOPT_MIMEPOST`.
    pub mimepost: Option<Vec<u8>>,
    /// Storage for `CURLOPT_RESOLVER_START_DATA`.
    pub has_resolver_start_data: bool,
    /// Storage for `CURLOPT_TLS13_CIPHERS`.
    pub tls13_ciphers: Option<String>,
    /// Storage for `CURLOPT_PROXY_TLS13_CIPHERS`.
    pub proxy_tls13_ciphers: Option<String>,
    /// Storage for `CURLOPT_DOH_URL`.
    pub doh_url: Option<String>,
    /// Storage for `CURLOPT_CURLU`.
    pub curlu: bool,
    /// Storage for `CURLOPT_TRAILERDATA`.
    pub has_trailerdata: bool,
    /// Storage for `CURLOPT_ALTSVC`.
    pub altsvc: Option<String>,
    /// Storage for `CURLOPT_SASL_AUTHZID`.
    pub sasl_authzid: Option<String>,
    /// Storage for `CURLOPT_PROXY_ISSUERCERT`.
    pub proxy_issuercert: Option<String>,
    /// Storage for `CURLOPT_SSL_EC_CURVES`.
    pub ssl_ec_curves: Option<String>,
    /// Storage for `CURLOPT_HSTS`.
    pub hsts: Option<String>,
    /// Storage for `CURLOPT_HSTSREADDATA`.
    pub has_hstsreaddata: bool,
    /// Storage for `CURLOPT_HSTSWRITEDATA`.
    pub has_hstswritedata: bool,
    /// Storage for `CURLOPT_AWS_SIGV4`.
    pub aws_sigv4: Option<String>,
    /// Storage for `CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256`.
    pub ssh_host_public_key_sha256: Option<String>,
    /// Storage for `CURLOPT_PREREQDATA`.
    pub has_prereqdata: bool,
    /// Storage for `CURLOPT_SSH_HOSTKEYDATA`.
    pub has_ssh_hostkeydata: bool,
    /// Storage for `CURLOPT_PROTOCOLS_STR`.
    pub protocols_str: Option<String>,
    /// Storage for `CURLOPT_REDIR_PROTOCOLS_STR`.
    pub redir_protocols_str: Option<String>,
    /// Storage for `CURLOPT_HAPROXY_CLIENT_IP`.
    pub haproxy_client_ip: Option<String>,
    /// Storage for `CURLOPT_ECH`.
    pub ech: Option<String>,
    /// Storage for `CURLOPT_SSL_SIGNATURE_ALGORITHMS`.
    pub ssl_signature_algorithms: Option<String>,
    /// Storage for `CURLOPT_WRITEFUNCTION`.
    pub has_writefunction: bool,
    /// Storage for `CURLOPT_READFUNCTION`.
    pub has_readfunction: bool,
    /// Storage for `CURLOPT_HEADERFUNCTION`.
    pub has_headerfunction: bool,
    /// Storage for `CURLOPT_DEBUGFUNCTION`.
    pub has_debugfunction: bool,
    /// Storage for `CURLOPT_SSL_CTX_FUNCTION`.
    pub has_ssl_ctx_function: bool,
    /// Storage for `CURLOPT_SOCKOPTFUNCTION`.
    pub has_sockoptfunction: bool,
    /// Storage for `CURLOPT_OPENSOCKETFUNCTION`.
    pub has_opensocketfunction: bool,
    /// Storage for `CURLOPT_SEEKFUNCTION`.
    pub has_seekfunction: bool,
    /// Storage for `CURLOPT_SSH_KEYFUNCTION`.
    pub has_ssh_keyfunction: bool,
    /// Storage for `CURLOPT_INTERLEAVEFUNCTION`.
    pub has_interleavefunction: bool,
    /// Storage for `CURLOPT_CHUNK_BGN_FUNCTION`.
    pub has_chunk_bgn_function: bool,
    /// Storage for `CURLOPT_CHUNK_END_FUNCTION`.
    pub has_chunk_end_function: bool,
    /// Storage for `CURLOPT_FNMATCH_FUNCTION`.
    pub has_fnmatch_function: bool,
    /// Storage for `CURLOPT_CLOSESOCKETFUNCTION`.
    pub has_closesocketfunction: bool,
    /// Storage for `CURLOPT_XFERINFOFUNCTION`.
    pub has_xferinfofunction: bool,
    /// Storage for `CURLOPT_RESOLVER_START_FUNCTION`.
    pub has_resolver_start_function: bool,
    /// Storage for `CURLOPT_TRAILERFUNCTION`.
    pub has_trailerfunction: bool,
    /// Storage for `CURLOPT_HSTSREADFUNCTION`.
    pub has_hstsreadfunction: bool,
    /// Storage for `CURLOPT_HSTSWRITEFUNCTION`.
    pub has_hstswritefunction: bool,
    /// Storage for `CURLOPT_PREREQFUNCTION`.
    pub has_prereqfunction: bool,
    /// Storage for `CURLOPT_SSH_HOSTKEYFUNCTION`.
    pub has_ssh_hostkeyfunction: bool,
    /// Storage for `CURLOPT_INFILESIZE_LARGE`.
    pub infilesize_large: i64,
    /// Storage for `CURLOPT_RESUME_FROM_LARGE`.
    pub resume_from_large: i64,
    /// Storage for `CURLOPT_MAXFILESIZE_LARGE`.
    pub maxfilesize_large: i64,
    /// Storage for `CURLOPT_POSTFIELDSIZE_LARGE`.
    pub postfieldsize_large: i64,
    /// Storage for `CURLOPT_MAX_SEND_SPEED_LARGE`.
    pub max_send_speed_large: i64,
    /// Storage for `CURLOPT_MAX_RECV_SPEED_LARGE`.
    pub max_recv_speed_large: i64,
    /// Storage for `CURLOPT_TIMEVALUE_LARGE`.
    pub timevalue_large: i64,
    /// Storage for `CURLOPT_SSLCERT_BLOB`.
    pub sslcert_blob: Option<Vec<u8>>,
    /// Storage for `CURLOPT_SSLKEY_BLOB`.
    pub sslkey_blob: Option<Vec<u8>>,
    /// Storage for `CURLOPT_PROXY_SSLCERT_BLOB`.
    pub proxy_sslcert_blob: Option<Vec<u8>>,
    /// Storage for `CURLOPT_PROXY_SSLKEY_BLOB`.
    pub proxy_sslkey_blob: Option<Vec<u8>>,
    /// Storage for `CURLOPT_ISSUERCERT_BLOB`.
    pub issuercert_blob: Option<Vec<u8>>,
    /// Storage for `CURLOPT_PROXY_ISSUERCERT_BLOB`.
    pub proxy_issuercert_blob: Option<Vec<u8>>,
    /// Storage for `CURLOPT_CAINFO_BLOB`.
    pub cainfo_blob: Option<Vec<u8>>,
    /// Storage for `CURLOPT_PROXY_CAINFO_BLOB`.
    pub proxy_cainfo_blob: Option<Vec<u8>>,
}

impl Default for HandleOptions {
    fn default() -> Self {
        Self {
            port: 0,
            timeout_ms: 0,
            infilesize: 0,
            low_speed_limit: 0,
            low_speed_time: 0,
            resume_from: 0,
            crlf: false,
            sslversion: CURL_SSLVERSION_DEFAULT,
            timecondition: 0,
            timevalue: 0,
            verbose: false,
            header: false,
            noprogress: true,
            nobody: false,
            failonerror: false,
            upload: false,
            post: false,
            dirlistonly: false,
            append: false,
            netrc: 0,
            followlocation: 0,
            transfertext: false,
            autoreferer: false,
            proxyport: 0,
            postfieldsize: 0,
            httpproxytunnel: false,
            ssl_verifypeer: true,
            maxredirs: 30,
            filetime: false,
            maxconnects: 5,
            fresh_connect: false,
            forbid_reuse: false,
            connecttimeout_ms: 0,
            httpget: false,
            ssl_verifyhost: 2,
            http_version: CURL_HTTP_VERSION_NONE,
            ftp_use_epsv: true,
            sslengine_default: false,
            dns_cache_timeout: 60,
            cookiesession: false,
            buffersize: 16384,
            nosignal: true,
            proxytype: CURLPROXY_HTTP,
            unrestricted_auth: false,
            ftp_use_eprt: true,
            httpauth: CURLAUTH_NONE,
            ftp_create_missing_dirs: 0,
            proxyauth: CURLAUTH_NONE,
            server_response_timeout: 0,
            ipresolve: 0,
            maxfilesize: 0,
            use_ssl: 0,
            tcp_nodelay: true,
            ftpsslauth: 0,
            ignore_content_length: false,
            ftp_skip_pasv_ip: false,
            ftp_filemethod: 0,
            localport: 0,
            localportrange: 0,
            connect_only: 0,
            ssl_sessionid_cache: true,
            ssh_auth_types: -1,
            ftp_ssl_ccc: 0,
            http_transfer_decoding: true,
            http_content_decoding: true,
            new_file_perms: 0o644_i64,
            new_directory_perms: 0o755_i64,
            postredir: 0,
            proxy_transfer_mode: false,
            address_scope: 0,
            certinfo: false,
            tftp_blksize: 0,
            socks5_gssapi_nec: false,
            ftp_use_pret: false,
            rtsp_request: 0,
            rtsp_client_cseq: 0,
            rtsp_server_cseq: 0,
            wildcardmatch: false,
            transfer_encoding: false,
            gssapi_delegation: 0,
            accepttimeout_ms: 0,
            tcp_keepalive: false,
            tcp_keepidle: 0,
            tcp_keepintvl: 0,
            ssl_options: 0,
            sasl_ir: false,
            ssl_enable_alpn: true,
            expect_100_timeout_ms: 1000,
            headeropt: 0,
            ssl_verifystatus: false,
            path_as_is: false,
            pipewait: false,
            stream_weight: 16,
            tftp_no_options: false,
            tcp_fastopen: false,
            keep_sending_on_error: false,
            proxy_ssl_verifypeer: true,
            proxy_ssl_verifyhost: 2,
            proxy_sslversion: CURL_SSLVERSION_DEFAULT,
            proxy_ssl_options: 0,
            suppress_connect_headers: false,
            socks5_auth: 3,
            ssh_compression: false,
            happy_eyeballs_timeout_ms: 200,
            haproxyprotocol: false,
            dns_shuffle_addresses: false,
            disallow_username_in_url: false,
            upload_buffersize: 65536,
            upkeep_interval_ms: 0,
            http09_allowed: false,
            altsvc_ctrl: 0,
            maxage_conn: 118,
            mail_rcpt_allowfails: false,
            hsts_ctrl: 0,
            doh_ssl_verifypeer: true,
            doh_ssl_verifyhost: true,
            doh_ssl_verifystatus: false,
            maxlifetime_conn: 0,
            mime_options: 0,
            ws_options: 0,
            ca_cache_timeout: 86400,
            quick_exit: false,
            server_response_timeout_ms: 0,
            tcp_keepcnt: 0,
            upload_flags: 0,
            has_writedata: false,
            url: None,
            proxy: None,
            userpwd: None,
            proxyuserpwd: None,
            range: None,
            has_readdata: false,
            errorbuffer: false,
            postfields: None,
            referer: None,
            ftpport: None,
            useragent: None,
            cookie: None,
            httpheader: None,
            sslcert: None,
            keypasswd: None,
            quote: None,
            has_headerdata: false,
            cookiefile: None,
            customrequest: None,
            stderr: false,
            postquote: None,
            has_xferinfodata: false,
            interface: None,
            cainfo: None,
            telnetoptions: None,
            cookiejar: None,
            ssl_cipher_list: None,
            sslcerttype: None,
            sslkey: None,
            sslkeytype: None,
            sslengine: None,
            prequote: None,
            has_debugdata: false,
            capath: None,
            share: false,
            accept_encoding: None,
            private: false,
            http200aliases: None,
            has_ssl_ctx_data: false,
            netrc_file: None,
            ftp_account: None,
            cookielist: None,
            ftp_alternative_to_user: None,
            has_sockoptdata: false,
            ssh_public_keyfile: None,
            ssh_private_keyfile: None,
            ssh_host_public_key_md5: None,
            has_opensocketdata: false,
            copypostfields: None,
            has_seekdata: false,
            crlfile: None,
            issuercert: None,
            username: None,
            password: None,
            proxyusername: None,
            proxypassword: None,
            noproxy: None,
            ssh_knownhosts: None,
            has_ssh_keydata: false,
            mail_from: None,
            mail_rcpt: None,
            rtsp_session_id: None,
            rtsp_stream_uri: None,
            rtsp_transport: None,
            has_interleavedata: false,
            has_chunk_data: false,
            has_fnmatch_data: false,
            resolve: None,
            tlsauth_username: None,
            tlsauth_password: None,
            tlsauth_type: None,
            has_closesocketdata: false,
            dns_servers: None,
            mail_auth: None,
            xoauth2_bearer: None,
            dns_interface: None,
            dns_local_ip4: None,
            dns_local_ip6: None,
            login_options: None,
            proxyheader: None,
            pinnedpublickey: None,
            unix_socket_path: None,
            proxy_service_name: None,
            service_name: None,
            default_protocol: None,
            stream_depends: false,
            stream_depends_e: false,
            connect_to: None,
            proxy_cainfo: None,
            proxy_capath: None,
            proxy_tlsauth_username: None,
            proxy_tlsauth_password: None,
            proxy_tlsauth_type: None,
            proxy_sslcert: None,
            proxy_sslcerttype: None,
            proxy_sslkey: None,
            proxy_sslkeytype: None,
            proxy_keypasswd: None,
            proxy_ssl_cipher_list: None,
            proxy_crlfile: None,
            pre_proxy: None,
            proxy_pinnedpublickey: None,
            abstract_unix_socket: None,
            request_target: None,
            mimepost: None,
            has_resolver_start_data: false,
            tls13_ciphers: None,
            proxy_tls13_ciphers: None,
            doh_url: None,
            curlu: false,
            has_trailerdata: false,
            altsvc: None,
            sasl_authzid: None,
            proxy_issuercert: None,
            ssl_ec_curves: None,
            hsts: None,
            has_hstsreaddata: false,
            has_hstswritedata: false,
            aws_sigv4: None,
            ssh_host_public_key_sha256: None,
            has_prereqdata: false,
            has_ssh_hostkeydata: false,
            protocols_str: None,
            redir_protocols_str: None,
            haproxy_client_ip: None,
            ech: None,
            ssl_signature_algorithms: None,
            has_writefunction: false,
            has_readfunction: false,
            has_headerfunction: false,
            has_debugfunction: false,
            has_ssl_ctx_function: false,
            has_sockoptfunction: false,
            has_opensocketfunction: false,
            has_seekfunction: false,
            has_ssh_keyfunction: false,
            has_interleavefunction: false,
            has_chunk_bgn_function: false,
            has_chunk_end_function: false,
            has_fnmatch_function: false,
            has_closesocketfunction: false,
            has_xferinfofunction: false,
            has_resolver_start_function: false,
            has_trailerfunction: false,
            has_hstsreadfunction: false,
            has_hstswritefunction: false,
            has_prereqfunction: false,
            has_ssh_hostkeyfunction: false,
            infilesize_large: 0,
            resume_from_large: 0,
            maxfilesize_large: 0,
            postfieldsize_large: 0,
            max_send_speed_large: 0,
            max_recv_speed_large: 0,
            timevalue_large: 0,
            sslcert_blob: None,
            sslkey_blob: None,
            proxy_sslcert_blob: None,
            proxy_sslkey_blob: None,
            issuercert_blob: None,
            proxy_issuercert_blob: None,
            cainfo_blob: None,
            proxy_cainfo_blob: None,
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

// Validation helpers

fn validate_string_length(s: &str) -> CurlResult<()> {
    if s.len() > CURL_MAX_INPUT_LENGTH {
        tracing::warn!("string too long: {} > {}", s.len(), CURL_MAX_INPUT_LENGTH);
        return Err(CurlError::BadFunctionArgument);
    }
    Ok(())
}

fn timeout_sec_to_ms(secs: i64) -> CurlResult<i64> {
    if secs < 0 { return Err(CurlError::BadFunctionArgument); }
    let max_secs = i64::MAX / 1000;
    if secs > max_secs { Ok(i64::MAX) } else { Ok(secs * 1000) }
}

fn validate_http_version(version: i64) -> CurlResult<()> {
    match version {
        CURL_HTTP_VERSION_NONE | CURL_HTTP_VERSION_1_0 | CURL_HTTP_VERSION_1_1
        | CURL_HTTP_VERSION_2_0 | CURL_HTTP_VERSION_2TLS
        | CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE
        | CURL_HTTP_VERSION_3 | CURL_HTTP_VERSION_3ONLY => Ok(()),
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

fn validate_ssl_version(arg: i64) -> CurlResult<i64> {
    let version = arg & 0xFFFF;
    let version_max = arg & 0xFFFF_0000_u32 as i64;
    if version < CURL_SSLVERSION_DEFAULT
        || version == CURL_SSLVERSION_SSLV2
        || version == CURL_SSLVERSION_SSLV3
        || version >= CURL_SSLVERSION_LAST
        || !(CURL_SSLVERSION_MAX_NONE..CURL_SSLVERSION_MAX_LAST).contains(&version_max)
    {
        tracing::warn!("invalid SSL version: {}", arg);
        return Err(CurlError::BadFunctionArgument);
    }
    let effective = if version == CURL_SSLVERSION_DEFAULT {
        CURL_SSLVERSION_TLSV1_2
    } else { version };
    Ok(effective | version_max)
}

fn validate_proxy_type(ptype: i64) -> CurlResult<()> {
    if !(CURLPROXY_HTTP..=CURLPROXY_SOCKS5_HOSTNAME).contains(&ptype) {
        tracing::warn!("invalid proxy type: {}", ptype);
        return Err(CurlError::BadFunctionArgument);
    }
    Ok(())
}

fn validate_httpauth(auth: u64) -> CurlResult<u64> {
    if auth == CURLAUTH_NONE { return Ok(auth); }
    let mut effective = auth;
    if effective & CURLAUTH_DIGEST_IE != 0 {
        effective |= CURLAUTH_DIGEST;
        effective &= !CURLAUTH_DIGEST_IE;
    }
    let lower_bits = effective & ((1u64 << 31) - 1);
    if lower_bits == 0 {
        tracing::warn!("no supported auth types: {:#x}", auth);
        return Err(CurlError::NotBuiltIn);
    }
    Ok(effective)
}

fn validate_followlocation(arg: i64) -> CurlResult<()> {
    if !(0..=3).contains(&arg) {
        tracing::warn!("invalid FOLLOWLOCATION: {}", arg);
        return Err(CurlError::BadFunctionArgument);
    }
    Ok(())
}

fn validate_maxredirs(arg: i64) -> CurlResult<i64> {
    if arg < -1 {
        tracing::warn!("invalid MAXREDIRS: {}", arg);
        return Err(CurlError::BadFunctionArgument);
    }
    Ok(arg.min(0x7FFF))
}

fn validate_nonneg_long(val: i64, name: &str) -> CurlResult<()> {
    if val < 0 {
        tracing::warn!("invalid negative value for {}: {}", name, val);
        return Err(CurlError::BadFunctionArgument);
    }
    Ok(())
}

/// Sets an option on the given [`HandleOptions`], with full validation.
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
        CurlOpt::CURLOPT_PORT => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_PORT")?; opts.port = v; }
        CurlOpt::CURLOPT_TIMEOUT => { let s = value.as_long()?; opts.timeout_ms = timeout_sec_to_ms(s)?; }
        CurlOpt::CURLOPT_INFILESIZE => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_INFILESIZE")?; opts.infilesize = v; }
        CurlOpt::CURLOPT_LOW_SPEED_LIMIT => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_LOW_SPEED_LIMIT")?; opts.low_speed_limit = v; }
        CurlOpt::CURLOPT_LOW_SPEED_TIME => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_LOW_SPEED_TIME")?; opts.low_speed_time = v; }
        CurlOpt::CURLOPT_RESUME_FROM => { opts.resume_from = value.as_long()?; }
        CurlOpt::CURLOPT_CRLF => { let v = value.as_long()?; opts.crlf = v != 0; }
        CurlOpt::CURLOPT_SSLVERSION => { let v = value.as_long()?; opts.sslversion = validate_ssl_version(v)?; }
        CurlOpt::CURLOPT_TIMECONDITION => { opts.timecondition = value.as_long()?; }
        CurlOpt::CURLOPT_TIMEVALUE => { opts.timevalue = value.as_long()?; }
        CurlOpt::CURLOPT_VERBOSE => { let v = value.as_long()?; opts.verbose = v != 0; }
        CurlOpt::CURLOPT_HEADER => { let v = value.as_long()?; opts.header = v != 0; }
        CurlOpt::CURLOPT_NOPROGRESS => { let v = value.as_long()?; opts.noprogress = v != 0; }
        CurlOpt::CURLOPT_NOBODY => { let v = value.as_long()?; opts.nobody = v != 0; }
        CurlOpt::CURLOPT_FAILONERROR => { let v = value.as_long()?; opts.failonerror = v != 0; }
        CurlOpt::CURLOPT_UPLOAD => { let v = value.as_long()?; opts.upload = v != 0; if opts.upload { opts.nobody = false; } }
        CurlOpt::CURLOPT_POST => { let v = value.as_long()?; opts.post = v != 0; if opts.post { opts.nobody = false; } }
        CurlOpt::CURLOPT_DIRLISTONLY => { let v = value.as_long()?; opts.dirlistonly = v != 0; }
        CurlOpt::CURLOPT_APPEND => { let v = value.as_long()?; opts.append = v != 0; }
        CurlOpt::CURLOPT_NETRC => { opts.netrc = value.as_long()?; }
        CurlOpt::CURLOPT_FOLLOWLOCATION => { let v = value.as_long()?; validate_followlocation(v)?; opts.followlocation = v; }
        CurlOpt::CURLOPT_TRANSFERTEXT => { let v = value.as_long()?; opts.transfertext = v != 0; }
        CurlOpt::CURLOPT_AUTOREFERER => { let v = value.as_long()?; opts.autoreferer = v != 0; }
        CurlOpt::CURLOPT_PROXYPORT => { opts.proxyport = value.as_long()?; }
        CurlOpt::CURLOPT_POSTFIELDSIZE => { opts.postfieldsize = value.as_long()?; }
        CurlOpt::CURLOPT_HTTPPROXYTUNNEL => { let v = value.as_long()?; opts.httpproxytunnel = v != 0; }
        CurlOpt::CURLOPT_SSL_VERIFYPEER => { let v = value.as_long()?; opts.ssl_verifypeer = v != 0; if !opts.ssl_verifypeer { tracing::warn!("SSL peer verification disabled"); } }
        CurlOpt::CURLOPT_MAXREDIRS => { let v = value.as_long()?; opts.maxredirs = validate_maxredirs(v)?; }
        CurlOpt::CURLOPT_FILETIME => { let v = value.as_long()?; opts.filetime = v != 0; }
        CurlOpt::CURLOPT_MAXCONNECTS => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_MAXCONNECTS")?; opts.maxconnects = v; }
        CurlOpt::CURLOPT_FRESH_CONNECT => { let v = value.as_long()?; opts.fresh_connect = v != 0; }
        CurlOpt::CURLOPT_FORBID_REUSE => { let v = value.as_long()?; opts.forbid_reuse = v != 0; }
        CurlOpt::CURLOPT_CONNECTTIMEOUT => { let s = value.as_long()?; opts.connecttimeout_ms = timeout_sec_to_ms(s)?; }
        CurlOpt::CURLOPT_HTTPGET => { let v = value.as_long()?; opts.httpget = v != 0; if opts.httpget { opts.post = false; opts.upload = false; opts.nobody = false; } }
        CurlOpt::CURLOPT_SSL_VERIFYHOST => { opts.ssl_verifyhost = value.as_long()?; }
        CurlOpt::CURLOPT_HTTP_VERSION => { let v = value.as_long()?; validate_http_version(v)?; opts.http_version = v; }
        CurlOpt::CURLOPT_FTP_USE_EPSV => { let v = value.as_long()?; opts.ftp_use_epsv = v != 0; }
        CurlOpt::CURLOPT_SSLENGINE_DEFAULT => { let v = value.as_long()?; opts.sslengine_default = v != 0; }
        CurlOpt::CURLOPT_DNS_CACHE_TIMEOUT => { opts.dns_cache_timeout = value.as_long()?; }
        CurlOpt::CURLOPT_COOKIESESSION => { let v = value.as_long()?; opts.cookiesession = v != 0; }
        CurlOpt::CURLOPT_BUFFERSIZE => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_BUFFERSIZE")?; opts.buffersize = v; }
        CurlOpt::CURLOPT_NOSIGNAL => { let v = value.as_long()?; opts.nosignal = v != 0; }
        CurlOpt::CURLOPT_PROXYTYPE => { let v = value.as_long()?; validate_proxy_type(v)?; opts.proxytype = v; }
        CurlOpt::CURLOPT_UNRESTRICTED_AUTH => { let v = value.as_long()?; opts.unrestricted_auth = v != 0; }
        CurlOpt::CURLOPT_FTP_USE_EPRT => { let v = value.as_long()?; opts.ftp_use_eprt = v != 0; }
        CurlOpt::CURLOPT_HTTPAUTH => { let v = value.as_long()?; opts.httpauth = validate_httpauth(v as u64)?; }
        CurlOpt::CURLOPT_FTP_CREATE_MISSING_DIRS => { opts.ftp_create_missing_dirs = value.as_long()?; }
        CurlOpt::CURLOPT_PROXYAUTH => { let v = value.as_long()?; opts.proxyauth = validate_httpauth(v as u64)?; }
        CurlOpt::CURLOPT_SERVER_RESPONSE_TIMEOUT => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_SERVER_RESPONSE_TIMEOUT")?; opts.server_response_timeout = v; }
        CurlOpt::CURLOPT_IPRESOLVE => { opts.ipresolve = value.as_long()?; }
        CurlOpt::CURLOPT_MAXFILESIZE => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_MAXFILESIZE")?; opts.maxfilesize = v; }
        CurlOpt::CURLOPT_USE_SSL => { opts.use_ssl = value.as_long()?; }
        CurlOpt::CURLOPT_TCP_NODELAY => { let v = value.as_long()?; opts.tcp_nodelay = v != 0; }
        CurlOpt::CURLOPT_FTPSSLAUTH => { opts.ftpsslauth = value.as_long()?; }
        CurlOpt::CURLOPT_IGNORE_CONTENT_LENGTH => { let v = value.as_long()?; opts.ignore_content_length = v != 0; }
        CurlOpt::CURLOPT_FTP_SKIP_PASV_IP => { let v = value.as_long()?; opts.ftp_skip_pasv_ip = v != 0; }
        CurlOpt::CURLOPT_FTP_FILEMETHOD => { opts.ftp_filemethod = value.as_long()?; }
        CurlOpt::CURLOPT_LOCALPORT => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_LOCALPORT")?; opts.localport = v; }
        CurlOpt::CURLOPT_LOCALPORTRANGE => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_LOCALPORTRANGE")?; opts.localportrange = v; }
        CurlOpt::CURLOPT_CONNECT_ONLY => { opts.connect_only = value.as_long()?; }
        CurlOpt::CURLOPT_SSL_SESSIONID_CACHE => { let v = value.as_long()?; opts.ssl_sessionid_cache = v != 0; }
        CurlOpt::CURLOPT_SSH_AUTH_TYPES => { opts.ssh_auth_types = value.as_long()?; }
        CurlOpt::CURLOPT_FTP_SSL_CCC => { opts.ftp_ssl_ccc = value.as_long()?; }
        CurlOpt::CURLOPT_TIMEOUT_MS => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_TIMEOUT_MS")?; opts.timeout_ms = v; }
        CurlOpt::CURLOPT_CONNECTTIMEOUT_MS => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_CONNECTTIMEOUT_MS")?; opts.connecttimeout_ms = v; }
        CurlOpt::CURLOPT_HTTP_TRANSFER_DECODING => { let v = value.as_long()?; opts.http_transfer_decoding = v != 0; }
        CurlOpt::CURLOPT_HTTP_CONTENT_DECODING => { let v = value.as_long()?; opts.http_content_decoding = v != 0; }
        CurlOpt::CURLOPT_NEW_FILE_PERMS => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_NEW_FILE_PERMS")?; opts.new_file_perms = v; }
        CurlOpt::CURLOPT_NEW_DIRECTORY_PERMS => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_NEW_DIRECTORY_PERMS")?; opts.new_directory_perms = v; }
        CurlOpt::CURLOPT_POSTREDIR => { opts.postredir = value.as_long()?; }
        CurlOpt::CURLOPT_PROXY_TRANSFER_MODE => { let v = value.as_long()?; opts.proxy_transfer_mode = v != 0; }
        CurlOpt::CURLOPT_ADDRESS_SCOPE => { opts.address_scope = value.as_long()?; }
        CurlOpt::CURLOPT_CERTINFO => { let v = value.as_long()?; opts.certinfo = v != 0; }
        CurlOpt::CURLOPT_TFTP_BLKSIZE => { opts.tftp_blksize = value.as_long()?; }
        CurlOpt::CURLOPT_SOCKS5_GSSAPI_NEC => { let v = value.as_long()?; opts.socks5_gssapi_nec = v != 0; }
        CurlOpt::CURLOPT_FTP_USE_PRET => { let v = value.as_long()?; opts.ftp_use_pret = v != 0; }
        CurlOpt::CURLOPT_RTSP_REQUEST => { opts.rtsp_request = value.as_long()?; }
        CurlOpt::CURLOPT_RTSP_CLIENT_CSEQ => { opts.rtsp_client_cseq = value.as_long()?; }
        CurlOpt::CURLOPT_RTSP_SERVER_CSEQ => { opts.rtsp_server_cseq = value.as_long()?; }
        CurlOpt::CURLOPT_WILDCARDMATCH => { let v = value.as_long()?; opts.wildcardmatch = v != 0; }
        CurlOpt::CURLOPT_TRANSFER_ENCODING => { let v = value.as_long()?; opts.transfer_encoding = v != 0; }
        CurlOpt::CURLOPT_GSSAPI_DELEGATION => { opts.gssapi_delegation = value.as_long()?; }
        CurlOpt::CURLOPT_ACCEPTTIMEOUT_MS => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_ACCEPTTIMEOUT_MS")?; opts.accepttimeout_ms = v; }
        CurlOpt::CURLOPT_TCP_KEEPALIVE => { let v = value.as_long()?; opts.tcp_keepalive = v != 0; }
        CurlOpt::CURLOPT_TCP_KEEPIDLE => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_TCP_KEEPIDLE")?; opts.tcp_keepidle = v; }
        CurlOpt::CURLOPT_TCP_KEEPINTVL => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_TCP_KEEPINTVL")?; opts.tcp_keepintvl = v; }
        CurlOpt::CURLOPT_SSL_OPTIONS => { opts.ssl_options = value.as_long()?; }
        CurlOpt::CURLOPT_SASL_IR => { let v = value.as_long()?; opts.sasl_ir = v != 0; }
        CurlOpt::CURLOPT_SSL_ENABLE_ALPN => { let v = value.as_long()?; opts.ssl_enable_alpn = v != 0; }
        CurlOpt::CURLOPT_EXPECT_100_TIMEOUT_MS => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_EXPECT_100_TIMEOUT_MS")?; opts.expect_100_timeout_ms = v; }
        CurlOpt::CURLOPT_HEADEROPT => { opts.headeropt = value.as_long()?; }
        CurlOpt::CURLOPT_SSL_VERIFYSTATUS => { let v = value.as_long()?; opts.ssl_verifystatus = v != 0; }
        CurlOpt::CURLOPT_PATH_AS_IS => { let v = value.as_long()?; opts.path_as_is = v != 0; }
        CurlOpt::CURLOPT_PIPEWAIT => { let v = value.as_long()?; opts.pipewait = v != 0; }
        CurlOpt::CURLOPT_STREAM_WEIGHT => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_STREAM_WEIGHT")?; opts.stream_weight = v; }
        CurlOpt::CURLOPT_TFTP_NO_OPTIONS => { let v = value.as_long()?; opts.tftp_no_options = v != 0; }
        CurlOpt::CURLOPT_TCP_FASTOPEN => { let v = value.as_long()?; opts.tcp_fastopen = v != 0; }
        CurlOpt::CURLOPT_KEEP_SENDING_ON_ERROR => { let v = value.as_long()?; opts.keep_sending_on_error = v != 0; }
        CurlOpt::CURLOPT_PROXY_SSL_VERIFYPEER => { let v = value.as_long()?; opts.proxy_ssl_verifypeer = v != 0; }
        CurlOpt::CURLOPT_PROXY_SSL_VERIFYHOST => { opts.proxy_ssl_verifyhost = value.as_long()?; }
        CurlOpt::CURLOPT_PROXY_SSLVERSION => { let v = value.as_long()?; opts.proxy_sslversion = validate_ssl_version(v)?; }
        CurlOpt::CURLOPT_PROXY_SSL_OPTIONS => { opts.proxy_ssl_options = value.as_long()?; }
        CurlOpt::CURLOPT_SUPPRESS_CONNECT_HEADERS => { let v = value.as_long()?; opts.suppress_connect_headers = v != 0; }
        CurlOpt::CURLOPT_SOCKS5_AUTH => { opts.socks5_auth = value.as_long()?; }
        CurlOpt::CURLOPT_SSH_COMPRESSION => { let v = value.as_long()?; opts.ssh_compression = v != 0; }
        CurlOpt::CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS")?; opts.happy_eyeballs_timeout_ms = v; }
        CurlOpt::CURLOPT_HAPROXYPROTOCOL => { let v = value.as_long()?; opts.haproxyprotocol = v != 0; }
        CurlOpt::CURLOPT_DNS_SHUFFLE_ADDRESSES => { let v = value.as_long()?; opts.dns_shuffle_addresses = v != 0; }
        CurlOpt::CURLOPT_DISALLOW_USERNAME_IN_URL => { let v = value.as_long()?; opts.disallow_username_in_url = v != 0; }
        CurlOpt::CURLOPT_UPLOAD_BUFFERSIZE => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_UPLOAD_BUFFERSIZE")?; opts.upload_buffersize = v; }
        CurlOpt::CURLOPT_UPKEEP_INTERVAL_MS => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_UPKEEP_INTERVAL_MS")?; opts.upkeep_interval_ms = v; }
        CurlOpt::CURLOPT_HTTP09_ALLOWED => { let v = value.as_long()?; opts.http09_allowed = v != 0; }
        CurlOpt::CURLOPT_ALTSVC_CTRL => { opts.altsvc_ctrl = value.as_long()?; }
        CurlOpt::CURLOPT_MAXAGE_CONN => { opts.maxage_conn = value.as_long()?; }
        CurlOpt::CURLOPT_MAIL_RCPT_ALLOWFAILS => { let v = value.as_long()?; opts.mail_rcpt_allowfails = v != 0; }
        CurlOpt::CURLOPT_HSTS_CTRL => { opts.hsts_ctrl = value.as_long()?; }
        CurlOpt::CURLOPT_DOH_SSL_VERIFYPEER => { let v = value.as_long()?; opts.doh_ssl_verifypeer = v != 0; }
        CurlOpt::CURLOPT_DOH_SSL_VERIFYHOST => { let v = value.as_long()?; opts.doh_ssl_verifyhost = v != 0; }
        CurlOpt::CURLOPT_DOH_SSL_VERIFYSTATUS => { let v = value.as_long()?; opts.doh_ssl_verifystatus = v != 0; }
        CurlOpt::CURLOPT_MAXLIFETIME_CONN => { opts.maxlifetime_conn = value.as_long()?; }
        CurlOpt::CURLOPT_MIME_OPTIONS => { opts.mime_options = value.as_long()?; }
        CurlOpt::CURLOPT_WS_OPTIONS => { opts.ws_options = value.as_long()?; }
        CurlOpt::CURLOPT_CA_CACHE_TIMEOUT => { opts.ca_cache_timeout = value.as_long()?; }
        CurlOpt::CURLOPT_QUICK_EXIT => { let v = value.as_long()?; opts.quick_exit = v != 0; }
        CurlOpt::CURLOPT_SERVER_RESPONSE_TIMEOUT_MS => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_SERVER_RESPONSE_TIMEOUT_MS")?; opts.server_response_timeout_ms = v; }
        CurlOpt::CURLOPT_TCP_KEEPCNT => { let v = value.as_long()?; validate_nonneg_long(v, "CURLOPT_TCP_KEEPCNT")?; opts.tcp_keepcnt = v; }
        CurlOpt::CURLOPT_UPLOAD_FLAGS => { opts.upload_flags = value.as_long()?; }
        CurlOpt::CURLOPT_WRITEDATA => { opts.has_writedata = true; }
        CurlOpt::CURLOPT_URL => { let s = value.as_str()?; validate_string_length(s)?; opts.url = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy = Some(s.to_owned()); }
        CurlOpt::CURLOPT_USERPWD => { let s = value.as_str()?; validate_string_length(s)?; opts.userpwd = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXYUSERPWD => { let s = value.as_str()?; validate_string_length(s)?; opts.proxyuserpwd = Some(s.to_owned()); }
        CurlOpt::CURLOPT_RANGE => { let s = value.as_str()?; validate_string_length(s)?; opts.range = Some(s.to_owned()); }
        CurlOpt::CURLOPT_READDATA => { opts.has_readdata = true; }
        CurlOpt::CURLOPT_ERRORBUFFER => { opts.errorbuffer = true; }
        CurlOpt::CURLOPT_POSTFIELDS => { let s = value.as_str()?; validate_string_length(s)?; opts.postfields = Some(s.to_owned()); opts.post = true; opts.nobody = false; }
        CurlOpt::CURLOPT_REFERER => { let s = value.as_str()?; validate_string_length(s)?; opts.referer = Some(s.to_owned()); }
        CurlOpt::CURLOPT_FTPPORT => { let s = value.as_str()?; validate_string_length(s)?; opts.ftpport = Some(s.to_owned()); }
        CurlOpt::CURLOPT_USERAGENT => { let s = value.as_str()?; validate_string_length(s)?; opts.useragent = Some(s.to_owned()); }
        CurlOpt::CURLOPT_COOKIE => { let s = value.as_str()?; validate_string_length(s)?; opts.cookie = Some(s.to_owned()); }
        CurlOpt::CURLOPT_HTTPHEADER => { opts.httpheader = Some(value.into_slist()?.duplicate()); }
        CurlOpt::CURLOPT_SSLCERT => { let s = value.as_str()?; validate_string_length(s)?; opts.sslcert = Some(s.to_owned()); }
        CurlOpt::CURLOPT_KEYPASSWD => { let s = value.as_str()?; validate_string_length(s)?; opts.keypasswd = Some(s.to_owned()); }
        CurlOpt::CURLOPT_QUOTE => { opts.quote = Some(value.into_slist()?.duplicate()); }
        CurlOpt::CURLOPT_HEADERDATA => { opts.has_headerdata = true; }
        CurlOpt::CURLOPT_COOKIEFILE => { let s = value.as_str()?; validate_string_length(s)?; opts.cookiefile = Some(s.to_owned()); }
        CurlOpt::CURLOPT_CUSTOMREQUEST => { let s = value.as_str()?; validate_string_length(s)?; opts.customrequest = Some(s.to_owned()); }
        CurlOpt::CURLOPT_STDERR => { opts.stderr = true; }
        CurlOpt::CURLOPT_POSTQUOTE => { opts.postquote = Some(value.into_slist()?.duplicate()); }
        CurlOpt::CURLOPT_XFERINFODATA => { opts.has_xferinfodata = true; }
        CurlOpt::CURLOPT_INTERFACE => { let s = value.as_str()?; validate_string_length(s)?; opts.interface = Some(s.to_owned()); }
        CurlOpt::CURLOPT_CAINFO => { let s = value.as_str()?; validate_string_length(s)?; opts.cainfo = Some(s.to_owned()); }
        CurlOpt::CURLOPT_TELNETOPTIONS => { opts.telnetoptions = Some(value.into_slist()?.duplicate()); }
        CurlOpt::CURLOPT_COOKIEJAR => { let s = value.as_str()?; validate_string_length(s)?; opts.cookiejar = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SSL_CIPHER_LIST => { let s = value.as_str()?; validate_string_length(s)?; opts.ssl_cipher_list = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SSLCERTTYPE => { let s = value.as_str()?; validate_string_length(s)?; opts.sslcerttype = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SSLKEY => { let s = value.as_str()?; validate_string_length(s)?; opts.sslkey = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SSLKEYTYPE => { let s = value.as_str()?; validate_string_length(s)?; opts.sslkeytype = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SSLENGINE => { let s = value.as_str()?; validate_string_length(s)?; opts.sslengine = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PREQUOTE => { opts.prequote = Some(value.into_slist()?.duplicate()); }
        CurlOpt::CURLOPT_DEBUGDATA => { opts.has_debugdata = true; }
        CurlOpt::CURLOPT_CAPATH => { let s = value.as_str()?; validate_string_length(s)?; opts.capath = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SHARE => { opts.share = true; }
        CurlOpt::CURLOPT_ACCEPT_ENCODING => { let s = value.as_str()?; validate_string_length(s)?; opts.accept_encoding = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PRIVATE => { opts.private = true; }
        CurlOpt::CURLOPT_HTTP200ALIASES => { opts.http200aliases = Some(value.into_slist()?.duplicate()); }
        CurlOpt::CURLOPT_SSL_CTX_DATA => { opts.has_ssl_ctx_data = true; }
        CurlOpt::CURLOPT_NETRC_FILE => { let s = value.as_str()?; validate_string_length(s)?; opts.netrc_file = Some(s.to_owned()); }
        CurlOpt::CURLOPT_FTP_ACCOUNT => { let s = value.as_str()?; validate_string_length(s)?; opts.ftp_account = Some(s.to_owned()); }
        CurlOpt::CURLOPT_COOKIELIST => { let s = value.as_str()?; validate_string_length(s)?; opts.cookielist = Some(s.to_owned()); }
        CurlOpt::CURLOPT_FTP_ALTERNATIVE_TO_USER => { let s = value.as_str()?; validate_string_length(s)?; opts.ftp_alternative_to_user = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SOCKOPTDATA => { opts.has_sockoptdata = true; }
        CurlOpt::CURLOPT_SSH_PUBLIC_KEYFILE => { let s = value.as_str()?; validate_string_length(s)?; opts.ssh_public_keyfile = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SSH_PRIVATE_KEYFILE => { let s = value.as_str()?; validate_string_length(s)?; opts.ssh_private_keyfile = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 => { let s = value.as_str()?; validate_string_length(s)?; opts.ssh_host_public_key_md5 = Some(s.to_owned()); }
        CurlOpt::CURLOPT_OPENSOCKETDATA => { opts.has_opensocketdata = true; }
        CurlOpt::CURLOPT_COPYPOSTFIELDS => { let s = value.as_str()?; validate_string_length(s)?; opts.copypostfields = Some(s.to_owned()); opts.post = true; opts.nobody = false; }
        CurlOpt::CURLOPT_SEEKDATA => { opts.has_seekdata = true; }
        CurlOpt::CURLOPT_CRLFILE => { let s = value.as_str()?; validate_string_length(s)?; opts.crlfile = Some(s.to_owned()); }
        CurlOpt::CURLOPT_ISSUERCERT => { let s = value.as_str()?; validate_string_length(s)?; opts.issuercert = Some(s.to_owned()); }
        CurlOpt::CURLOPT_USERNAME => { let s = value.as_str()?; validate_string_length(s)?; opts.username = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PASSWORD => { let s = value.as_str()?; validate_string_length(s)?; opts.password = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXYUSERNAME => { let s = value.as_str()?; validate_string_length(s)?; opts.proxyusername = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXYPASSWORD => { let s = value.as_str()?; validate_string_length(s)?; opts.proxypassword = Some(s.to_owned()); }
        CurlOpt::CURLOPT_NOPROXY => { let s = value.as_str()?; validate_string_length(s)?; opts.noproxy = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SSH_KNOWNHOSTS => { let s = value.as_str()?; validate_string_length(s)?; opts.ssh_knownhosts = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SSH_KEYDATA => { opts.has_ssh_keydata = true; }
        CurlOpt::CURLOPT_MAIL_FROM => { let s = value.as_str()?; validate_string_length(s)?; opts.mail_from = Some(s.to_owned()); }
        CurlOpt::CURLOPT_MAIL_RCPT => { opts.mail_rcpt = Some(value.into_slist()?.duplicate()); }
        CurlOpt::CURLOPT_RTSP_SESSION_ID => { let s = value.as_str()?; validate_string_length(s)?; opts.rtsp_session_id = Some(s.to_owned()); }
        CurlOpt::CURLOPT_RTSP_STREAM_URI => { let s = value.as_str()?; validate_string_length(s)?; opts.rtsp_stream_uri = Some(s.to_owned()); }
        CurlOpt::CURLOPT_RTSP_TRANSPORT => { let s = value.as_str()?; validate_string_length(s)?; opts.rtsp_transport = Some(s.to_owned()); }
        CurlOpt::CURLOPT_INTERLEAVEDATA => { opts.has_interleavedata = true; }
        CurlOpt::CURLOPT_CHUNK_DATA => { opts.has_chunk_data = true; }
        CurlOpt::CURLOPT_FNMATCH_DATA => { opts.has_fnmatch_data = true; }
        CurlOpt::CURLOPT_RESOLVE => { opts.resolve = Some(value.into_slist()?.duplicate()); }
        CurlOpt::CURLOPT_TLSAUTH_USERNAME => { let s = value.as_str()?; validate_string_length(s)?; opts.tlsauth_username = Some(s.to_owned()); }
        CurlOpt::CURLOPT_TLSAUTH_PASSWORD => { let s = value.as_str()?; validate_string_length(s)?; opts.tlsauth_password = Some(s.to_owned()); }
        CurlOpt::CURLOPT_TLSAUTH_TYPE => { let s = value.as_str()?; validate_string_length(s)?; opts.tlsauth_type = Some(s.to_owned()); }
        CurlOpt::CURLOPT_CLOSESOCKETDATA => { opts.has_closesocketdata = true; }
        CurlOpt::CURLOPT_DNS_SERVERS => { let s = value.as_str()?; validate_string_length(s)?; opts.dns_servers = Some(s.to_owned()); }
        CurlOpt::CURLOPT_MAIL_AUTH => { let s = value.as_str()?; validate_string_length(s)?; opts.mail_auth = Some(s.to_owned()); }
        CurlOpt::CURLOPT_XOAUTH2_BEARER => { let s = value.as_str()?; validate_string_length(s)?; opts.xoauth2_bearer = Some(s.to_owned()); }
        CurlOpt::CURLOPT_DNS_INTERFACE => { let s = value.as_str()?; validate_string_length(s)?; opts.dns_interface = Some(s.to_owned()); }
        CurlOpt::CURLOPT_DNS_LOCAL_IP4 => { let s = value.as_str()?; validate_string_length(s)?; opts.dns_local_ip4 = Some(s.to_owned()); }
        CurlOpt::CURLOPT_DNS_LOCAL_IP6 => { let s = value.as_str()?; validate_string_length(s)?; opts.dns_local_ip6 = Some(s.to_owned()); }
        CurlOpt::CURLOPT_LOGIN_OPTIONS => { let s = value.as_str()?; validate_string_length(s)?; opts.login_options = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXYHEADER => { opts.proxyheader = Some(value.into_slist()?.duplicate()); }
        CurlOpt::CURLOPT_PINNEDPUBLICKEY => { let s = value.as_str()?; validate_string_length(s)?; opts.pinnedpublickey = Some(s.to_owned()); }
        CurlOpt::CURLOPT_UNIX_SOCKET_PATH => { let s = value.as_str()?; validate_string_length(s)?; opts.unix_socket_path = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_SERVICE_NAME => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_service_name = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SERVICE_NAME => { let s = value.as_str()?; validate_string_length(s)?; opts.service_name = Some(s.to_owned()); }
        CurlOpt::CURLOPT_DEFAULT_PROTOCOL => { let s = value.as_str()?; validate_string_length(s)?; opts.default_protocol = Some(s.to_owned()); }
        CurlOpt::CURLOPT_STREAM_DEPENDS => { opts.stream_depends = true; }
        CurlOpt::CURLOPT_STREAM_DEPENDS_E => { opts.stream_depends_e = true; }
        CurlOpt::CURLOPT_CONNECT_TO => { opts.connect_to = Some(value.into_slist()?.duplicate()); }
        CurlOpt::CURLOPT_PROXY_CAINFO => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_cainfo = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_CAPATH => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_capath = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_TLSAUTH_USERNAME => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_tlsauth_username = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_TLSAUTH_PASSWORD => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_tlsauth_password = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_TLSAUTH_TYPE => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_tlsauth_type = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_SSLCERT => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_sslcert = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_SSLCERTTYPE => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_sslcerttype = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_SSLKEY => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_sslkey = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_SSLKEYTYPE => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_sslkeytype = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_KEYPASSWD => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_keypasswd = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_SSL_CIPHER_LIST => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_ssl_cipher_list = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_CRLFILE => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_crlfile = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PRE_PROXY => { let s = value.as_str()?; validate_string_length(s)?; opts.pre_proxy = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_PINNEDPUBLICKEY => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_pinnedpublickey = Some(s.to_owned()); }
        CurlOpt::CURLOPT_ABSTRACT_UNIX_SOCKET => { let s = value.as_str()?; validate_string_length(s)?; opts.abstract_unix_socket = Some(s.to_owned()); }
        CurlOpt::CURLOPT_REQUEST_TARGET => { let s = value.as_str()?; validate_string_length(s)?; opts.request_target = Some(s.to_owned()); }
        CurlOpt::CURLOPT_MIMEPOST => {
            match value {
                CurlOptValue::Blob(d) => { opts.mimepost = Some(d); opts.post = true; opts.nobody = false; }
                CurlOptValue::ObjectPoint(s) => { opts.mimepost = Some(s.into_bytes()); opts.post = true; opts.nobody = false; }
                _ => return Err(CurlError::BadFunctionArgument),
            }
        }
        CurlOpt::CURLOPT_RESOLVER_START_DATA => { opts.has_resolver_start_data = true; }
        CurlOpt::CURLOPT_TLS13_CIPHERS => { let s = value.as_str()?; validate_string_length(s)?; opts.tls13_ciphers = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_TLS13_CIPHERS => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_tls13_ciphers = Some(s.to_owned()); }
        CurlOpt::CURLOPT_DOH_URL => { let s = value.as_str()?; validate_string_length(s)?; opts.doh_url = Some(s.to_owned()); }
        CurlOpt::CURLOPT_CURLU => { opts.curlu = true; }
        CurlOpt::CURLOPT_TRAILERDATA => { opts.has_trailerdata = true; }
        CurlOpt::CURLOPT_ALTSVC => { let s = value.as_str()?; validate_string_length(s)?; opts.altsvc = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SASL_AUTHZID => { let s = value.as_str()?; validate_string_length(s)?; opts.sasl_authzid = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PROXY_ISSUERCERT => { let s = value.as_str()?; validate_string_length(s)?; opts.proxy_issuercert = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SSL_EC_CURVES => { let s = value.as_str()?; validate_string_length(s)?; opts.ssl_ec_curves = Some(s.to_owned()); }
        CurlOpt::CURLOPT_HSTS => { let s = value.as_str()?; validate_string_length(s)?; opts.hsts = Some(s.to_owned()); }
        CurlOpt::CURLOPT_HSTSREADDATA => { opts.has_hstsreaddata = true; }
        CurlOpt::CURLOPT_HSTSWRITEDATA => { opts.has_hstswritedata = true; }
        CurlOpt::CURLOPT_AWS_SIGV4 => { let s = value.as_str()?; validate_string_length(s)?; opts.aws_sigv4 = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 => { let s = value.as_str()?; validate_string_length(s)?; opts.ssh_host_public_key_sha256 = Some(s.to_owned()); }
        CurlOpt::CURLOPT_PREREQDATA => { opts.has_prereqdata = true; }
        CurlOpt::CURLOPT_SSH_HOSTKEYDATA => { opts.has_ssh_hostkeydata = true; }
        CurlOpt::CURLOPT_PROTOCOLS_STR => { let s = value.as_str()?; validate_string_length(s)?; opts.protocols_str = Some(s.to_owned()); }
        CurlOpt::CURLOPT_REDIR_PROTOCOLS_STR => { let s = value.as_str()?; validate_string_length(s)?; opts.redir_protocols_str = Some(s.to_owned()); }
        CurlOpt::CURLOPT_HAPROXY_CLIENT_IP => { let s = value.as_str()?; validate_string_length(s)?; opts.haproxy_client_ip = Some(s.to_owned()); }
        CurlOpt::CURLOPT_ECH => { let s = value.as_str()?; validate_string_length(s)?; opts.ech = Some(s.to_owned()); }
        CurlOpt::CURLOPT_SSL_SIGNATURE_ALGORITHMS => { let s = value.as_str()?; validate_string_length(s)?; opts.ssl_signature_algorithms = Some(s.to_owned()); }
        CurlOpt::CURLOPT_WRITEFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_writefunction = true; }
        CurlOpt::CURLOPT_READFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_readfunction = true; }
        CurlOpt::CURLOPT_HEADERFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_headerfunction = true; }
        CurlOpt::CURLOPT_DEBUGFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_debugfunction = true; }
        CurlOpt::CURLOPT_SSL_CTX_FUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_ssl_ctx_function = true; }
        CurlOpt::CURLOPT_SOCKOPTFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_sockoptfunction = true; }
        CurlOpt::CURLOPT_OPENSOCKETFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_opensocketfunction = true; }
        CurlOpt::CURLOPT_SEEKFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_seekfunction = true; }
        CurlOpt::CURLOPT_SSH_KEYFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_ssh_keyfunction = true; }
        CurlOpt::CURLOPT_INTERLEAVEFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_interleavefunction = true; }
        CurlOpt::CURLOPT_CHUNK_BGN_FUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_chunk_bgn_function = true; }
        CurlOpt::CURLOPT_CHUNK_END_FUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_chunk_end_function = true; }
        CurlOpt::CURLOPT_FNMATCH_FUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_fnmatch_function = true; }
        CurlOpt::CURLOPT_CLOSESOCKETFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_closesocketfunction = true; }
        CurlOpt::CURLOPT_XFERINFOFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_xferinfofunction = true; }
        CurlOpt::CURLOPT_RESOLVER_START_FUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_resolver_start_function = true; }
        CurlOpt::CURLOPT_TRAILERFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_trailerfunction = true; }
        CurlOpt::CURLOPT_HSTSREADFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_hstsreadfunction = true; }
        CurlOpt::CURLOPT_HSTSWRITEFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_hstswritefunction = true; }
        CurlOpt::CURLOPT_PREREQFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_prereqfunction = true; }
        CurlOpt::CURLOPT_SSH_HOSTKEYFUNCTION => { if !matches!(value, CurlOptValue::FunctionPoint) { return Err(CurlError::BadFunctionArgument); } opts.has_ssh_hostkeyfunction = true; }
        CurlOpt::CURLOPT_INFILESIZE_LARGE => { opts.infilesize_large = value.as_offt()?; }
        CurlOpt::CURLOPT_RESUME_FROM_LARGE => { opts.resume_from_large = value.as_offt()?; }
        CurlOpt::CURLOPT_MAXFILESIZE_LARGE => { opts.maxfilesize_large = value.as_offt()?; }
        CurlOpt::CURLOPT_POSTFIELDSIZE_LARGE => { opts.postfieldsize_large = value.as_offt()?; }
        CurlOpt::CURLOPT_MAX_SEND_SPEED_LARGE => { opts.max_send_speed_large = value.as_offt()?; }
        CurlOpt::CURLOPT_MAX_RECV_SPEED_LARGE => { opts.max_recv_speed_large = value.as_offt()?; }
        CurlOpt::CURLOPT_TIMEVALUE_LARGE => { opts.timevalue_large = value.as_offt()?; }
        CurlOpt::CURLOPT_SSLCERT_BLOB => { opts.sslcert_blob = Some(value.into_blob()?); }
        CurlOpt::CURLOPT_SSLKEY_BLOB => { opts.sslkey_blob = Some(value.into_blob()?); }
        CurlOpt::CURLOPT_PROXY_SSLCERT_BLOB => { opts.proxy_sslcert_blob = Some(value.into_blob()?); }
        CurlOpt::CURLOPT_PROXY_SSLKEY_BLOB => { opts.proxy_sslkey_blob = Some(value.into_blob()?); }
        CurlOpt::CURLOPT_ISSUERCERT_BLOB => { opts.issuercert_blob = Some(value.into_blob()?); }
        CurlOpt::CURLOPT_PROXY_ISSUERCERT_BLOB => { opts.proxy_issuercert_blob = Some(value.into_blob()?); }
        CurlOpt::CURLOPT_CAINFO_BLOB => { opts.cainfo_blob = Some(value.into_blob()?); }
        CurlOpt::CURLOPT_PROXY_CAINFO_BLOB => { opts.proxy_cainfo_blob = Some(value.into_blob()?); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curlopt_values_match_c() {
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
    fn test_new_option_values_match_c() {
        assert_eq!(CurlOpt::CURLOPT_PORT as u32, 3);
        assert_eq!(CurlOpt::CURLOPT_REFERER as u32, 10_016);
        assert_eq!(CurlOpt::CURLOPT_INTERFACE as u32, 10_062);
        assert_eq!(CurlOpt::CURLOPT_CAINFO as u32, 10_065);
        assert_eq!(CurlOpt::CURLOPT_SSL_VERIFYHOST as u32, 81);
        assert_eq!(CurlOpt::CURLOPT_DNS_CACHE_TIMEOUT as u32, 92);
        assert_eq!(CurlOpt::CURLOPT_BUFFERSIZE as u32, 98);
        assert_eq!(CurlOpt::CURLOPT_IPRESOLVE as u32, 113);
        assert_eq!(CurlOpt::CURLOPT_RESOLVE as u32, 10_203);
        assert_eq!(CurlOpt::CURLOPT_SSL_OPTIONS as u32, 216);
        assert_eq!(CurlOpt::CURLOPT_HSTS as u32, 10_300);
        assert_eq!(CurlOpt::CURLOPT_ALTSVC as u32, 10_287);
        assert_eq!(CurlOpt::CURLOPT_NETRC as u32, 51);
        assert_eq!(CurlOpt::CURLOPT_PROTOCOLS_STR as u32, 10_318);
        assert_eq!(CurlOpt::CURLOPT_REDIR_PROTOCOLS_STR as u32, 10_319);
        assert_eq!(CurlOpt::CURLOPT_WRITEDATA as u32, 10_001);
        assert_eq!(CurlOpt::CURLOPT_READDATA as u32, 10_009);
        assert_eq!(CurlOpt::CURLOPT_DEBUGFUNCTION as u32, 20_094);
        assert_eq!(CurlOpt::CURLOPT_INFILESIZE_LARGE as u32, 30_115);
        assert_eq!(CurlOpt::CURLOPT_RESUME_FROM_LARGE as u32, 30_116);
        assert_eq!(CurlOpt::CURLOPT_SSLCERT_BLOB as u32, 40_291);
        assert_eq!(CurlOpt::CURLOPT_CAINFO_BLOB as u32, 40_309);
        assert_eq!(CurlOpt::CURLOPT_SSH_AUTH_TYPES as u32, 151);
        assert_eq!(CurlOpt::CURLOPT_LOW_SPEED_LIMIT as u32, 19);
        assert_eq!(CurlOpt::CURLOPT_LOW_SPEED_TIME as u32, 20);
        assert_eq!(CurlOpt::CURLOPT_RESUME_FROM as u32, 21);
        assert_eq!(CurlOpt::CURLOPT_NETRC_FILE as u32, 10_118);
        assert_eq!(CurlOpt::CURLOPT_CAPATH as u32, 10_097);
        assert_eq!(CurlOpt::CURLOPT_AWS_SIGV4 as u32, 10_305);
        assert_eq!(CurlOpt::CURLOPT_DOH_URL as u32, 10_279);
        assert_eq!(CurlOpt::CURLOPT_SSL_SIGNATURE_ALGORITHMS as u32, 10_328);
    }

    #[test]
    fn test_try_from_u32_known() {
        assert_eq!(CurlOpt::try_from_u32(10_002), Some(CurlOpt::CURLOPT_URL));
        assert_eq!(CurlOpt::try_from_u32(20_011), Some(CurlOpt::CURLOPT_WRITEFUNCTION));
        assert_eq!(CurlOpt::try_from_u32(10_203), Some(CurlOpt::CURLOPT_RESOLVE));
        assert_eq!(CurlOpt::try_from_u32(40_291), Some(CurlOpt::CURLOPT_SSLCERT_BLOB));
    }

    #[test]
    fn test_try_from_u32_unknown() {
        assert!(CurlOpt::try_from_u32(99_999).is_none());
        assert!(CurlOpt::try_from_u32(0).is_none());
    }

    #[test]
    fn test_try_from_u32_all_known() {
        let all_vals: Vec<u32> = vec![
            3, 13, 14, 19, 20, 21, 27, 32, 33, 34, 41, 42,
            43, 44, 45, 46, 47, 48, 50, 51, 52, 53, 58, 59,
            60, 61, 64, 68, 69, 71, 74, 75, 78, 80, 81, 84,
            85, 90, 92, 96, 98, 99, 101, 105, 106, 107, 110, 111,
            112, 113, 114, 119, 121, 129, 136, 137, 138, 139, 140, 141,
            150, 151, 154, 155, 156, 157, 158, 159, 160, 161, 166, 171,
            172, 178, 180, 188, 189, 193, 194, 197, 207, 210, 212, 213,
            214, 215, 216, 218, 226, 227, 229, 232, 234, 237, 239, 242,
            244, 245, 248, 249, 250, 261, 265, 267, 268, 271, 274, 275,
            278, 280, 281, 285, 286, 288, 290, 299, 306, 307, 308, 314,
            315, 320, 321, 322, 324, 326, 327, 10001, 10002, 10004, 10005, 10006,
            10007, 10009, 10010, 10015, 10016, 10017, 10018, 10022, 10023, 10025, 10026, 10028,
            10029, 10031, 10036, 10037, 10039, 10057, 10062, 10065, 10070, 10082, 10083, 10086,
            10087, 10088, 10089, 10093, 10095, 10097, 10100, 10102, 10103, 10104, 10109, 10118,
            10134, 10135, 10147, 10149, 10152, 10153, 10162, 10164, 10165, 10168, 10169, 10170,
            10173, 10174, 10175, 10176, 10177, 10183, 10185, 10186, 10187, 10190, 10191, 10192,
            10195, 10201, 10202, 10203, 10204, 10205, 10206, 10209, 10211, 10217, 10220, 10221,
            10222, 10223, 10224, 10228, 10230, 10231, 10235, 10236, 10238, 10240, 10241, 10243,
            10246, 10247, 10251, 10252, 10253, 10254, 10255, 10256, 10257, 10258, 10259, 10260,
            10262, 10263, 10264, 10266, 10269, 10273, 10276, 10277, 10279, 10282, 10284, 10287,
            10289, 10296, 10298, 10300, 10302, 10304, 10305, 10311, 10313, 10317, 10318, 10319,
            10323, 10325, 10328, 20011, 20012, 20079, 20094, 20108, 20148, 20163, 20167, 20184,
            20196, 20198, 20199, 20200, 20208, 20219, 20272, 20283, 20301, 20303, 20312, 20316,
            30115, 30116, 30117, 30120, 30145, 30146, 30270, 40291, 40292, 40293, 40294, 40295,
            40297, 40309, 40310,
        ];
        assert_eq!(all_vals.len(), 291);
        for v in all_vals {
            assert!(CurlOpt::try_from_u32(v).is_some(), "try_from_u32({}) failed", v);
        }
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
        assert!(opts.ftp_use_epsv);
        assert!(opts.ftp_use_eprt);
        assert_eq!(opts.maxredirs, 30);
        assert_eq!(opts.http_version, CURL_HTTP_VERSION_NONE);
        assert_eq!(opts.proxytype, CURLPROXY_HTTP);
        assert_eq!(opts.httpauth, CURLAUTH_NONE);
        assert_eq!(opts.timeout_ms, 0);
        assert_eq!(opts.ssl_verifyhost, 2);
        assert_eq!(opts.dns_cache_timeout, 60);
        assert_eq!(opts.buffersize, 16384);
        assert_eq!(opts.maxconnects, 5);
        assert_eq!(opts.maxage_conn, 118);
        assert_eq!(opts.ssh_auth_types, -1);
        assert_eq!(opts.socks5_auth, 3);
        assert_eq!(opts.expect_100_timeout_ms, 1000);
        assert_eq!(opts.happy_eyeballs_timeout_ms, 200);
        assert_eq!(opts.stream_weight, 16);
        assert_eq!(opts.ca_cache_timeout, 86400);
        assert!(opts.doh_ssl_verifypeer);
        assert!(opts.doh_ssl_verifyhost);
        assert!(opts.proxy_ssl_verifypeer);
        assert_eq!(opts.proxy_ssl_verifyhost, 2);
    }

    #[test]
    fn test_set_url() {
        let mut opts = HandleOptions::new();
        let r = set_option(&mut opts, CurlOpt::CURLOPT_URL as u32, CurlOptValue::ObjectPoint("https://example.com".into()));
        assert!(r.is_ok());
        assert_eq!(opts.url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn test_set_url_too_long() {
        let mut opts = HandleOptions::new();
        let long_url = "x".repeat(CURL_MAX_INPUT_LENGTH + 1);
        let r = set_option(&mut opts, CurlOpt::CURLOPT_URL as u32, CurlOptValue::ObjectPoint(long_url));
        assert_eq!(r, Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_set_url_wrong_type() {
        let mut opts = HandleOptions::new();
        let r = set_option(&mut opts, CurlOpt::CURLOPT_URL as u32, CurlOptValue::Long(42));
        assert_eq!(r, Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_unknown_option() {
        let mut opts = HandleOptions::new();
        assert_eq!(set_option(&mut opts, 99_999, CurlOptValue::Long(1)), Err(CurlError::UnknownOption));
    }

    #[test]
    fn test_set_timeout() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_TIMEOUT as u32, CurlOptValue::Long(30)).is_ok());
        assert_eq!(opts.timeout_ms, 30_000);
    }

    #[test]
    fn test_set_timeout_negative() {
        let mut opts = HandleOptions::new();
        assert_eq!(set_option(&mut opts, CurlOpt::CURLOPT_TIMEOUT as u32, CurlOptValue::Long(-1)), Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_set_verbose() {
        let mut opts = HandleOptions::new();
        assert!(!opts.verbose);
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_VERBOSE as u32, CurlOptValue::Long(1)).is_ok());
        assert!(opts.verbose);
    }

    #[test]
    fn test_set_http_version_valid() {
        let mut opts = HandleOptions::new();
        for v in [CURL_HTTP_VERSION_NONE, CURL_HTTP_VERSION_1_0, CURL_HTTP_VERSION_1_1, CURL_HTTP_VERSION_2_0, CURL_HTTP_VERSION_3] {
            assert!(set_option(&mut opts, CurlOpt::CURLOPT_HTTP_VERSION as u32, CurlOptValue::Long(v)).is_ok(), "version {} failed", v);
        }
    }

    #[test]
    fn test_set_http_version_invalid() {
        let mut opts = HandleOptions::new();
        assert_eq!(set_option(&mut opts, CurlOpt::CURLOPT_HTTP_VERSION as u32, CurlOptValue::Long(99)), Err(CurlError::UnsupportedProtocol));
    }

    #[test]
    fn test_set_ssl_version_rejects_sslv2() {
        let mut opts = HandleOptions::new();
        assert_eq!(set_option(&mut opts, CurlOpt::CURLOPT_SSLVERSION as u32, CurlOptValue::Long(CURL_SSLVERSION_SSLV2)), Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_set_ssl_version_default_maps_to_tls12() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_SSLVERSION as u32, CurlOptValue::Long(CURL_SSLVERSION_DEFAULT)).is_ok());
        assert_eq!(opts.sslversion & 0xFFFF, CURL_SSLVERSION_TLSV1_2);
    }

    #[test]
    fn test_set_httpauth() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_HTTPAUTH as u32, CurlOptValue::Long(CURLAUTH_BASIC as i64)).is_ok());
        assert_eq!(opts.httpauth, CURLAUTH_BASIC);
    }

    #[test]
    fn test_set_httpauth_digest_ie() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_HTTPAUTH as u32, CurlOptValue::Long(CURLAUTH_DIGEST_IE as i64)).is_ok());
        assert!(opts.httpauth & CURLAUTH_DIGEST != 0);
        assert!(opts.httpauth & CURLAUTH_DIGEST_IE == 0);
    }

    #[test]
    fn test_set_proxy_type_invalid() {
        let mut opts = HandleOptions::new();
        assert_eq!(set_option(&mut opts, CurlOpt::CURLOPT_PROXYTYPE as u32, CurlOptValue::Long(100)), Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_set_followlocation() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_FOLLOWLOCATION as u32, CurlOptValue::Long(1)).is_ok());
        assert_eq!(opts.followlocation, 1);
    }

    #[test]
    fn test_set_maxredirs_clamp() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_MAXREDIRS as u32, CurlOptValue::Long(100_000)).is_ok());
        assert_eq!(opts.maxredirs, 0x7FFF);
    }

    #[test]
    fn test_set_maxredirs_negative_one() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_MAXREDIRS as u32, CurlOptValue::Long(-1)).is_ok());
        assert_eq!(opts.maxredirs, -1);
    }

    #[test]
    fn test_set_maxredirs_too_negative() {
        let mut opts = HandleOptions::new();
        assert_eq!(set_option(&mut opts, CurlOpt::CURLOPT_MAXREDIRS as u32, CurlOptValue::Long(-2)), Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_set_httpheader() {
        let mut opts = HandleOptions::new();
        let mut list = SList::new();
        list.append("Content-Type: application/json");
        list.append("Accept: */*");
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_HTTPHEADER as u32, CurlOptValue::SList(list)).is_ok());
        assert_eq!(opts.httpheader.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_set_writefunction() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_WRITEFUNCTION as u32, CurlOptValue::FunctionPoint).is_ok());
        assert!(opts.has_writefunction);
    }

    #[test]
    fn test_set_writefunction_wrong_type() {
        let mut opts = HandleOptions::new();
        assert_eq!(set_option(&mut opts, CurlOpt::CURLOPT_WRITEFUNCTION as u32, CurlOptValue::Long(1)), Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn test_upload_implies_no_nobody() {
        let mut opts = HandleOptions::new();
        opts.nobody = true;
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_UPLOAD as u32, CurlOptValue::Long(1)).is_ok());
        assert!(opts.upload);
        assert!(!opts.nobody);
    }

    #[test]
    fn test_post_implies_no_nobody() {
        let mut opts = HandleOptions::new();
        opts.nobody = true;
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_POST as u32, CurlOptValue::Long(1)).is_ok());
        assert!(opts.post);
        assert!(!opts.nobody);
    }

    #[test]
    fn test_set_ftp_options() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_FTP_USE_EPSV as u32, CurlOptValue::Long(0)).is_ok());
        assert!(!opts.ftp_use_epsv);
    }

    #[test]
    fn test_timeout_overflow_protection() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_TIMEOUT as u32, CurlOptValue::Long(i64::MAX)).is_ok());
        assert_eq!(opts.timeout_ms, i64::MAX);
    }

    #[test]
    fn test_set_connecttimeout() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_CONNECTTIMEOUT as u32, CurlOptValue::Long(60)).is_ok());
        assert_eq!(opts.connecttimeout_ms, 60_000);
    }

    #[test]
    fn test_httpget_clears_post_upload() {
        let mut opts = HandleOptions::new();
        opts.post = true; opts.upload = true; opts.nobody = true;
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_HTTPGET as u32, CurlOptValue::Long(1)).is_ok());
        assert!(!opts.post); assert!(!opts.upload); assert!(!opts.nobody);
    }

    #[test]
    fn test_set_port() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_PORT as u32, CurlOptValue::Long(8080)).is_ok());
        assert_eq!(opts.port, 8080);
    }

    #[test]
    fn test_set_referer() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_REFERER as u32, CurlOptValue::ObjectPoint("https://example.com".into())).is_ok());
        assert_eq!(opts.referer.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn test_set_cainfo() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_CAINFO as u32, CurlOptValue::ObjectPoint("/etc/ssl/certs/ca.crt".into())).is_ok());
        assert_eq!(opts.cainfo.as_deref(), Some("/etc/ssl/certs/ca.crt"));
    }

    #[test]
    fn test_set_resolve() {
        let mut opts = HandleOptions::new();
        let mut list = SList::new();
        list.append("example.com:443:127.0.0.1");
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_RESOLVE as u32, CurlOptValue::SList(list)).is_ok());
        assert!(opts.resolve.is_some());
    }

    #[test]
    fn test_set_hsts() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_HSTS as u32, CurlOptValue::ObjectPoint("/tmp/hsts.txt".into())).is_ok());
        assert_eq!(opts.hsts.as_deref(), Some("/tmp/hsts.txt"));
    }

    #[test]
    fn test_set_netrc() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_NETRC as u32, CurlOptValue::Long(CURL_NETRC_OPTIONAL)).is_ok());
        assert_eq!(opts.netrc, CURL_NETRC_OPTIONAL);
    }

    #[test]
    fn test_set_infilesize_large() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_INFILESIZE_LARGE as u32, CurlOptValue::OffT(1024*1024)).is_ok());
        assert_eq!(opts.infilesize_large, 1024*1024);
    }

    #[test]
    fn test_set_sslcert_blob() {
        let mut opts = HandleOptions::new();
        let d = vec![0x30, 0x82];
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_SSLCERT_BLOB as u32, CurlOptValue::Blob(d.clone())).is_ok());
        assert_eq!(opts.sslcert_blob, Some(d));
    }

    #[test]
    fn test_set_debugfunction() {
        let mut opts = HandleOptions::new();
        assert!(set_option(&mut opts, CurlOpt::CURLOPT_DEBUGFUNCTION as u32, CurlOptValue::FunctionPoint).is_ok());
        assert!(opts.has_debugfunction);
    }

    #[test]
    fn test_curlopt_value_kind_name() {
        assert_eq!(CurlOptValue::Long(0).kind_name(), "Long");
        assert_eq!(CurlOptValue::ObjectPoint(String::new()).kind_name(), "ObjectPoint");
        assert_eq!(CurlOptValue::FunctionPoint.kind_name(), "FunctionPoint");
        assert_eq!(CurlOptValue::OffT(0).kind_name(), "OffT");
        assert_eq!(CurlOptValue::Blob(vec![]).kind_name(), "Blob");
        assert_eq!(CurlOptValue::SList(SList::new()).kind_name(), "SList");
    }

    #[test]
    fn test_enum_count() {
        let mut count = 0u32;
        for v in 0..50_000u32 {
            if CurlOpt::try_from_u32(v).is_some() { count += 1; }
        }
        assert_eq!(count, 291, "variant count mismatch");
    }

}
