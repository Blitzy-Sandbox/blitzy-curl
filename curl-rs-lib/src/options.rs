//! Easy-option metadata: the Rust reimplementation of curl's generated
//! `Curl_easyopts[]` table (`lib/easyoptions.c`) together with the
//! `curl_easy_option_*` runtime-introspection API (`include/curl/options.h`)
//! and the `CURLoption` / `CURLINFO` identifier spaces from
//! `include/curl/curl.h`.
//!
//! # Why this module exists
//!
//! Two distinct consumers depend on this data:
//!
//! * The public introspection API -- `curl_easy_option_by_name`,
//!   `curl_easy_option_by_id` and `curl_easy_option_next` -- is exposed by the
//!   FFI crate (`curl-rs-ffi`) by reading [`EASY_OPTIONS`] and wrapping each
//!   matched [`EasyOption`] in the C `struct curl_easyoption`.
//! * The variadic `curl_easy_setopt` shim must, given a `CURLoption` tag,
//!   decide which C type the single trailing vararg has (a `long`, a pointer, a
//!   function pointer, a `curl_off_t`, or a `struct curl_blob *`) before it can
//!   read it. [`option_type_group`] answers exactly that question.
//!
//! # ABI contract (must not drift)
//!
//! The option names, their numeric `CURLoption` ids, and their `CURLOT_*` value
//! types are an externally observable part of curl's ABI: the `tests/libtest`
//! programs and real consumers read them directly. Every entry here is
//! reproduced verbatim from curl 8.x -- including curl's intentional quirks such
//! as the legacy alias spelling `MAIL_RCPT_ALLLOWFAILS` (three `L`s) and the
//! `CURLOT_FLAG_ALIAS` markers. The numeric ids are computed from the
//! `CURLOPTTYPE_*` bases exactly as the C `CURLOPT()` macro does
//! (`id = type_base + number`), so they match `include/curl/curl.h`
//! value-for-value. The unit tests at the bottom pin a representative spread of
//! these values so any drift fails the build.
//!
//! # Single home for identifier enums
//!
//! By design this module is the one canonical home for the `CURLoption`
//! ([`CurlOption`]) and `CURLINFO` ([`CurlInfo`]) identifier enums and the
//! option value-type classifier ([`CurlOptType`]). The `setopt` and `getinfo`
//! layers build their typed value handling and dispatch on top of these ids
//! rather than redefining them, keeping a single source of truth for the
//! integer contract. The companion `error` module owns the result-code space
//! (`CURLcode` and friends) in the same spirit.
//!
//! # Memory safety
//!
//! The module is pure, immutable data plus total lookups. It contains **zero**
//! `unsafe` and compiles cleanly under the crate-root `#![forbid(unsafe_code)]`.
//! [`EASY_OPTIONS`] is a `static` (not a `const`) so that the references handed
//! out by the lookups have a single stable address, which [`option_next`]
//! relies on to locate an entry by identity.

/// Value-type classifier for an easy option, mirroring curl's `curl_easytype`
/// enumeration (the `CURLOT_*` values in `include/curl/options.h`).
///
/// The discriminants match the C enumerators one-for-one (`Long` = 0 through
/// `Function` = 8), so the value can be handed across the FFI boundary as the C
/// `curl_easytype` without translation.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlOptType {
    /// `CURLOT_LONG` -- a C `long` taking a range of values.
    Long = 0,
    /// `CURLOT_VALUES` -- a C `long` taking a defined set or bitmask.
    Values = 1,
    /// `CURLOT_OFF_T` -- a `curl_off_t` taking a range of values.
    OffT = 2,
    /// `CURLOT_OBJECT` -- an opaque `void *`.
    Object = 3,
    /// `CURLOT_STRING` -- a `char *` to a NUL-terminated buffer.
    String = 4,
    /// `CURLOT_SLIST` -- a `struct curl_slist *`.
    Slist = 5,
    /// `CURLOT_CBPTR` -- a `void *` passed untouched to a callback.
    Cbptr = 6,
    /// `CURLOT_BLOB` -- a `struct curl_blob *`.
    Blob = 7,
    /// `CURLOT_FUNCTION` -- a function pointer.
    Function = 8,
}

impl CurlOptType {
    /// Returns the integer value of the matching `CURLOT_*` enumerator, for
    /// handing back across the C boundary as a `curl_easytype`.
    #[must_use]
    pub const fn as_c_int(self) -> i32 {
        self as i32
    }
}

/// `CURLOT_FLAG_ALIAS` -- marks a table entry that exists only so older programs
/// keep working; a non-alias entry with the preferred name maps to the same
/// `CURLoption` id. Name lookups still resolve aliases, but [`option_by_id`]
/// deliberately skips them so that an id resolves to its canonical entry.
pub const CURLOT_FLAG_ALIAS: u32 = 1 << 0;

/// The `CURLOPTTYPE_*` base group of a `CURLoption` id.
///
/// Every `CURLoption` numeric id is `base + ordinal`, where `base` is one of the
/// `CURLOPTTYPE_*` constants (a multiple of 10000). The base alone determines
/// the C type of the single trailing argument that `curl_easy_setopt` expects,
/// which is precisely what the variadic FFI shim must know to read the vararg
/// correctly. Note that `STRINGPOINT`, `SLISTPOINT` and `CBPOINT` are all
/// aliases of `OBJECTPOINT`, and `VALUES` is an alias of `LONG`, so they
/// collapse into the [`Long`](Self::Long) and [`ObjectPoint`](Self::ObjectPoint)
/// groups here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurloptTypeGroup {
    /// `CURLOPTTYPE_LONG` (base 0) -- read a C `long`.
    Long,
    /// `CURLOPTTYPE_OBJECTPOINT` (base 10000) -- read a pointer (`void *`,
    /// `char *` or `struct curl_slist *`).
    ObjectPoint,
    /// `CURLOPTTYPE_FUNCTIONPOINT` (base 20000) -- read a function pointer.
    FunctionPoint,
    /// `CURLOPTTYPE_OFF_T` (base 30000) -- read a `curl_off_t`.
    OffT,
    /// `CURLOPTTYPE_BLOB` (base 40000) -- read a `struct curl_blob *`.
    Blob,
}

/// Classifies a raw `CURLoption` integer id into its [`CurloptTypeGroup`].
///
/// This is the helper the variadic `curl_easy_setopt` shim uses: it works for
/// any well-formed id because it relies only on the `base + ordinal` structure,
/// not on the option being present in [`EASY_OPTIONS`]. Returns `None` for a
/// negative id or one whose base is outside the defined `CURLOPTTYPE_*` range.
#[must_use]
pub fn option_type_group(id: i32) -> Option<CurloptTypeGroup> {
    if id < 0 {
        return None;
    }
    match id / 10_000 {
        0 => Some(CurloptTypeGroup::Long),
        1 => Some(CurloptTypeGroup::ObjectPoint),
        2 => Some(CurloptTypeGroup::FunctionPoint),
        3 => Some(CurloptTypeGroup::OffT),
        4 => Some(CurloptTypeGroup::Blob),
        _ => None,
    }
}

/// The `CURLoption` identifier space (`include/curl/curl.h`).
///
/// Each variant keeps curl's exact `CURLOPT_*` spelling and its exact integer
/// value, computed as `CURLOPTTYPE_* base + ordinal` just like the C `CURLOPT()`
/// macro. This is the single shared definition of the option ids for the whole
/// crate (the `setopt` value handling and the FFI marshaler both build on it).
///
/// The variant names intentionally retain curl's screaming-snake-case rather
/// than being renamed to Rust style, because the names are an ABI-facing
/// contract and must stay greppable against the C headers; the naming lints are
/// therefore allowed for this type.
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlOption {
    // CURLOPTTYPE_LONG / CURLOPTTYPE_VALUES  -> C `long`
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
    CURLOPT_PUT = 54,
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
    CURLOPT_DNS_USE_GLOBAL_CACHE = 91,
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
    CURLOPT_PROTOCOLS = 181,
    CURLOPT_REDIR_PROTOCOLS = 182,
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
    CURLOPT_SSL_ENABLE_NPN = 225,
    CURLOPT_SSL_ENABLE_ALPN = 226,
    CURLOPT_EXPECT_100_TIMEOUT_MS = 227,
    CURLOPT_HEADEROPT = 229,
    CURLOPT_SSL_VERIFYSTATUS = 232,
    CURLOPT_SSL_FALSESTART = 233,
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

    // CURLOPTTYPE_OBJECTPOINT (STRINGPOINT / SLISTPOINT / CBPOINT) -> C pointer
    CURLOPT_WRITEDATA = 10001,
    CURLOPT_URL = 10002,
    CURLOPT_PROXY = 10004,
    CURLOPT_USERPWD = 10005,
    CURLOPT_PROXYUSERPWD = 10006,
    CURLOPT_RANGE = 10007,
    CURLOPT_READDATA = 10009,
    CURLOPT_ERRORBUFFER = 10010,
    CURLOPT_POSTFIELDS = 10015,
    CURLOPT_REFERER = 10016,
    CURLOPT_FTPPORT = 10017,
    CURLOPT_USERAGENT = 10018,
    CURLOPT_COOKIE = 10022,
    CURLOPT_HTTPHEADER = 10023,
    CURLOPT_HTTPPOST = 10024,
    CURLOPT_SSLCERT = 10025,
    CURLOPT_KEYPASSWD = 10026,
    CURLOPT_QUOTE = 10028,
    CURLOPT_HEADERDATA = 10029,
    CURLOPT_COOKIEFILE = 10031,
    CURLOPT_CUSTOMREQUEST = 10036,
    CURLOPT_STDERR = 10037,
    CURLOPT_POSTQUOTE = 10039,
    CURLOPT_XFERINFODATA = 10057,
    CURLOPT_INTERFACE = 10062,
    CURLOPT_KRBLEVEL = 10063,
    CURLOPT_CAINFO = 10065,
    CURLOPT_TELNETOPTIONS = 10070,
    CURLOPT_RANDOM_FILE = 10076,
    CURLOPT_EGDSOCKET = 10077,
    CURLOPT_COOKIEJAR = 10082,
    CURLOPT_SSL_CIPHER_LIST = 10083,
    CURLOPT_SSLCERTTYPE = 10086,
    CURLOPT_SSLKEY = 10087,
    CURLOPT_SSLKEYTYPE = 10088,
    CURLOPT_SSLENGINE = 10089,
    CURLOPT_PREQUOTE = 10093,
    CURLOPT_DEBUGDATA = 10095,
    CURLOPT_CAPATH = 10097,
    CURLOPT_SHARE = 10100,
    CURLOPT_ACCEPT_ENCODING = 10102,
    CURLOPT_PRIVATE = 10103,
    CURLOPT_HTTP200ALIASES = 10104,
    CURLOPT_SSL_CTX_DATA = 10109,
    CURLOPT_NETRC_FILE = 10118,
    CURLOPT_IOCTLDATA = 10131,
    CURLOPT_FTP_ACCOUNT = 10134,
    CURLOPT_COOKIELIST = 10135,
    CURLOPT_FTP_ALTERNATIVE_TO_USER = 10147,
    CURLOPT_SOCKOPTDATA = 10149,
    CURLOPT_SSH_PUBLIC_KEYFILE = 10152,
    CURLOPT_SSH_PRIVATE_KEYFILE = 10153,
    CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 = 10162,
    CURLOPT_OPENSOCKETDATA = 10164,
    CURLOPT_COPYPOSTFIELDS = 10165,
    CURLOPT_SEEKDATA = 10168,
    CURLOPT_CRLFILE = 10169,
    CURLOPT_ISSUERCERT = 10170,
    CURLOPT_USERNAME = 10173,
    CURLOPT_PASSWORD = 10174,
    CURLOPT_PROXYUSERNAME = 10175,
    CURLOPT_PROXYPASSWORD = 10176,
    CURLOPT_NOPROXY = 10177,
    CURLOPT_SOCKS5_GSSAPI_SERVICE = 10179,
    CURLOPT_SSH_KNOWNHOSTS = 10183,
    CURLOPT_SSH_KEYDATA = 10185,
    CURLOPT_MAIL_FROM = 10186,
    CURLOPT_MAIL_RCPT = 10187,
    CURLOPT_RTSP_SESSION_ID = 10190,
    CURLOPT_RTSP_STREAM_URI = 10191,
    CURLOPT_RTSP_TRANSPORT = 10192,
    CURLOPT_INTERLEAVEDATA = 10195,
    CURLOPT_CHUNK_DATA = 10201,
    CURLOPT_FNMATCH_DATA = 10202,
    CURLOPT_RESOLVE = 10203,
    CURLOPT_TLSAUTH_USERNAME = 10204,
    CURLOPT_TLSAUTH_PASSWORD = 10205,
    CURLOPT_TLSAUTH_TYPE = 10206,
    CURLOPT_CLOSESOCKETDATA = 10209,
    CURLOPT_DNS_SERVERS = 10211,
    CURLOPT_MAIL_AUTH = 10217,
    CURLOPT_XOAUTH2_BEARER = 10220,
    CURLOPT_DNS_INTERFACE = 10221,
    CURLOPT_DNS_LOCAL_IP4 = 10222,
    CURLOPT_DNS_LOCAL_IP6 = 10223,
    CURLOPT_LOGIN_OPTIONS = 10224,
    CURLOPT_PROXYHEADER = 10228,
    CURLOPT_PINNEDPUBLICKEY = 10230,
    CURLOPT_UNIX_SOCKET_PATH = 10231,
    CURLOPT_PROXY_SERVICE_NAME = 10235,
    CURLOPT_SERVICE_NAME = 10236,
    CURLOPT_DEFAULT_PROTOCOL = 10238,
    CURLOPT_STREAM_DEPENDS = 10240,
    CURLOPT_STREAM_DEPENDS_E = 10241,
    CURLOPT_CONNECT_TO = 10243,
    CURLOPT_PROXY_CAINFO = 10246,
    CURLOPT_PROXY_CAPATH = 10247,
    CURLOPT_PROXY_TLSAUTH_USERNAME = 10251,
    CURLOPT_PROXY_TLSAUTH_PASSWORD = 10252,
    CURLOPT_PROXY_TLSAUTH_TYPE = 10253,
    CURLOPT_PROXY_SSLCERT = 10254,
    CURLOPT_PROXY_SSLCERTTYPE = 10255,
    CURLOPT_PROXY_SSLKEY = 10256,
    CURLOPT_PROXY_SSLKEYTYPE = 10257,
    CURLOPT_PROXY_KEYPASSWD = 10258,
    CURLOPT_PROXY_SSL_CIPHER_LIST = 10259,
    CURLOPT_PROXY_CRLFILE = 10260,
    CURLOPT_PRE_PROXY = 10262,
    CURLOPT_PROXY_PINNEDPUBLICKEY = 10263,
    CURLOPT_ABSTRACT_UNIX_SOCKET = 10264,
    CURLOPT_REQUEST_TARGET = 10266,
    CURLOPT_MIMEPOST = 10269,
    CURLOPT_RESOLVER_START_DATA = 10273,
    CURLOPT_TLS13_CIPHERS = 10276,
    CURLOPT_PROXY_TLS13_CIPHERS = 10277,
    CURLOPT_DOH_URL = 10279,
    CURLOPT_CURLU = 10282,
    CURLOPT_TRAILERDATA = 10284,
    CURLOPT_ALTSVC = 10287,
    CURLOPT_SASL_AUTHZID = 10289,
    CURLOPT_PROXY_ISSUERCERT = 10296,
    CURLOPT_SSL_EC_CURVES = 10298,
    CURLOPT_HSTS = 10300,
    CURLOPT_HSTSREADDATA = 10302,
    CURLOPT_HSTSWRITEDATA = 10304,
    CURLOPT_AWS_SIGV4 = 10305,
    CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 = 10311,
    CURLOPT_PREREQDATA = 10313,
    CURLOPT_SSH_HOSTKEYDATA = 10317,
    CURLOPT_PROTOCOLS_STR = 10318,
    CURLOPT_REDIR_PROTOCOLS_STR = 10319,
    CURLOPT_HAPROXY_CLIENT_IP = 10323,
    CURLOPT_ECH = 10325,
    CURLOPT_SSL_SIGNATURE_ALGORITHMS = 10328,

    // CURLOPTTYPE_FUNCTIONPOINT -> C function pointer
    CURLOPT_WRITEFUNCTION = 20011,
    CURLOPT_READFUNCTION = 20012,
    CURLOPT_PROGRESSFUNCTION = 20056,
    CURLOPT_HEADERFUNCTION = 20079,
    CURLOPT_DEBUGFUNCTION = 20094,
    CURLOPT_SSL_CTX_FUNCTION = 20108,
    CURLOPT_IOCTLFUNCTION = 20130,
    CURLOPT_CONV_FROM_NETWORK_FUNCTION = 20142,
    CURLOPT_CONV_TO_NETWORK_FUNCTION = 20143,
    CURLOPT_CONV_FROM_UTF8_FUNCTION = 20144,
    CURLOPT_SOCKOPTFUNCTION = 20148,
    CURLOPT_OPENSOCKETFUNCTION = 20163,
    CURLOPT_SEEKFUNCTION = 20167,
    CURLOPT_SSH_KEYFUNCTION = 20184,
    CURLOPT_INTERLEAVEFUNCTION = 20196,
    CURLOPT_CHUNK_BGN_FUNCTION = 20198,
    CURLOPT_CHUNK_END_FUNCTION = 20199,
    CURLOPT_FNMATCH_FUNCTION = 20200,
    CURLOPT_CLOSESOCKETFUNCTION = 20208,
    CURLOPT_XFERINFOFUNCTION = 20219,
    CURLOPT_RESOLVER_START_FUNCTION = 20272,
    CURLOPT_TRAILERFUNCTION = 20283,
    CURLOPT_HSTSREADFUNCTION = 20301,
    CURLOPT_HSTSWRITEFUNCTION = 20303,
    CURLOPT_PREREQFUNCTION = 20312,
    CURLOPT_SSH_HOSTKEYFUNCTION = 20316,

    // CURLOPTTYPE_OFF_T -> C `curl_off_t`
    CURLOPT_INFILESIZE_LARGE = 30115,
    CURLOPT_RESUME_FROM_LARGE = 30116,
    CURLOPT_MAXFILESIZE_LARGE = 30117,
    CURLOPT_POSTFIELDSIZE_LARGE = 30120,
    CURLOPT_MAX_SEND_SPEED_LARGE = 30145,
    CURLOPT_MAX_RECV_SPEED_LARGE = 30146,
    CURLOPT_TIMEVALUE_LARGE = 30270,

    // CURLOPTTYPE_BLOB -> C `struct curl_blob *`
    CURLOPT_SSLCERT_BLOB = 40291,
    CURLOPT_SSLKEY_BLOB = 40292,
    CURLOPT_PROXY_SSLCERT_BLOB = 40293,
    CURLOPT_PROXY_SSLKEY_BLOB = 40294,
    CURLOPT_ISSUERCERT_BLOB = 40295,
    CURLOPT_PROXY_ISSUERCERT_BLOB = 40297,
    CURLOPT_CAINFO_BLOB = 40309,
    CURLOPT_PROXY_CAINFO_BLOB = 40310,
}

impl CurlOption {
    /// Returns the exact `CURLoption` integer value of this option.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Returns the `CURLOPTTYPE_*` group of this option, i.e. the C type its
    /// `curl_easy_setopt` argument has.
    ///
    /// Total: every variant's value lies in `0..50000`, so the base is always
    /// one of the five defined groups.
    #[must_use]
    pub const fn type_group(self) -> CurloptTypeGroup {
        match (self as i32) / 10_000 {
            0 => CurloptTypeGroup::Long,
            1 => CurloptTypeGroup::ObjectPoint,
            2 => CurloptTypeGroup::FunctionPoint,
            3 => CurloptTypeGroup::OffT,
            _ => CurloptTypeGroup::Blob,
        }
    }

    /// Resolves a raw integer to its [`CurlOption`], or `None` if no option has
    /// that value.
    ///
    /// The lookup scans the canonical (non-alias) rows of [`EASY_OPTIONS`],
    /// which contain every defined `CURLoption` id exactly once, so this is a
    /// total inverse of [`as_i32`](Self::as_i32) over the option space.
    #[must_use]
    pub fn from_i32(value: i32) -> Option<CurlOption> {
        EASY_OPTIONS
            .iter()
            .find(|o| (o.flags & CURLOT_FLAG_ALIAS) == 0 && o.id.as_i32() == value)
            .map(|o| o.id)
    }
}

/// `CURLINFO_*` type bases and masks (`include/curl/curl.h`).
///
/// A `CURLINFO` id encodes its return type in its high bits. `getinfo` dispatch
/// uses these to decide whether a query yields a `char *`, a `long`, a `double`,
/// a `struct curl_slist *` / `void *`, a socket, or a `curl_off_t`.
pub mod info_type {
    /// `CURLINFO_STRING` -- query returns a `char *`.
    pub const CURLINFO_STRING: i32 = 0x10_0000;
    /// `CURLINFO_LONG` -- query returns a `long`.
    pub const CURLINFO_LONG: i32 = 0x20_0000;
    /// `CURLINFO_DOUBLE` -- query returns a `double`.
    pub const CURLINFO_DOUBLE: i32 = 0x30_0000;
    /// `CURLINFO_SLIST` -- query returns a `struct curl_slist *`.
    pub const CURLINFO_SLIST: i32 = 0x40_0000;
    /// `CURLINFO_PTR` -- query returns a `void *` (same base as `SLIST`).
    pub const CURLINFO_PTR: i32 = 0x40_0000;
    /// `CURLINFO_SOCKET` -- query returns a `curl_socket_t`.
    pub const CURLINFO_SOCKET: i32 = 0x50_0000;
    /// `CURLINFO_OFF_T` -- query returns a `curl_off_t`.
    pub const CURLINFO_OFF_T: i32 = 0x60_0000;
    /// Mask isolating the ordinal (low bits) of a `CURLINFO` id.
    pub const CURLINFO_MASK: i32 = 0x0f_ffff;
    /// Mask isolating the type base (high bits) of a `CURLINFO` id.
    pub const CURLINFO_TYPEMASK: i32 = 0xf0_0000;
}

/// The `CURLINFO` identifier space queried by `curl_easy_getinfo`
/// (`include/curl/curl.h`).
///
/// Co-located with [`CurlOption`] so the crate has a single home for the libcurl
/// identifier enums. Values are reproduced exactly, including the deprecated
/// `double`-typed variants that coexist with their `_T` (`curl_off_t`)
/// successors, and the `CURLINFO_NONE` / `CURLINFO_LASTONE` sentinels.
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlInfo {
    CURLINFO_NONE = 0,
    CURLINFO_EFFECTIVE_URL = 1048577,
    CURLINFO_RESPONSE_CODE = 2097154,
    CURLINFO_TOTAL_TIME = 3145731,
    CURLINFO_NAMELOOKUP_TIME = 3145732,
    CURLINFO_CONNECT_TIME = 3145733,
    CURLINFO_PRETRANSFER_TIME = 3145734,
    CURLINFO_SIZE_UPLOAD = 3145735,
    CURLINFO_SIZE_UPLOAD_T = 6291463,
    CURLINFO_SIZE_DOWNLOAD = 3145736,
    CURLINFO_SIZE_DOWNLOAD_T = 6291464,
    CURLINFO_SPEED_DOWNLOAD = 3145737,
    CURLINFO_SPEED_DOWNLOAD_T = 6291465,
    CURLINFO_SPEED_UPLOAD = 3145738,
    CURLINFO_SPEED_UPLOAD_T = 6291466,
    CURLINFO_HEADER_SIZE = 2097163,
    CURLINFO_REQUEST_SIZE = 2097164,
    CURLINFO_SSL_VERIFYRESULT = 2097165,
    CURLINFO_FILETIME = 2097166,
    CURLINFO_FILETIME_T = 6291470,
    CURLINFO_CONTENT_LENGTH_DOWNLOAD = 3145743,
    CURLINFO_CONTENT_LENGTH_DOWNLOAD_T = 6291471,
    CURLINFO_CONTENT_LENGTH_UPLOAD = 3145744,
    CURLINFO_CONTENT_LENGTH_UPLOAD_T = 6291472,
    CURLINFO_STARTTRANSFER_TIME = 3145745,
    CURLINFO_CONTENT_TYPE = 1048594,
    CURLINFO_REDIRECT_TIME = 3145747,
    CURLINFO_REDIRECT_COUNT = 2097172,
    CURLINFO_PRIVATE = 1048597,
    CURLINFO_HTTP_CONNECTCODE = 2097174,
    CURLINFO_HTTPAUTH_AVAIL = 2097175,
    CURLINFO_PROXYAUTH_AVAIL = 2097176,
    CURLINFO_OS_ERRNO = 2097177,
    CURLINFO_NUM_CONNECTS = 2097178,
    CURLINFO_SSL_ENGINES = 4194331,
    CURLINFO_COOKIELIST = 4194332,
    CURLINFO_LASTSOCKET = 2097181,
    CURLINFO_FTP_ENTRY_PATH = 1048606,
    CURLINFO_REDIRECT_URL = 1048607,
    CURLINFO_PRIMARY_IP = 1048608,
    CURLINFO_APPCONNECT_TIME = 3145761,
    CURLINFO_CERTINFO = 4194338,
    CURLINFO_CONDITION_UNMET = 2097187,
    CURLINFO_RTSP_SESSION_ID = 1048612,
    CURLINFO_RTSP_CLIENT_CSEQ = 2097189,
    CURLINFO_RTSP_SERVER_CSEQ = 2097190,
    CURLINFO_RTSP_CSEQ_RECV = 2097191,
    CURLINFO_PRIMARY_PORT = 2097192,
    CURLINFO_LOCAL_IP = 1048617,
    CURLINFO_LOCAL_PORT = 2097194,
    CURLINFO_TLS_SESSION = 4194347,
    CURLINFO_ACTIVESOCKET = 5242924,
    CURLINFO_TLS_SSL_PTR = 4194349,
    CURLINFO_HTTP_VERSION = 2097198,
    CURLINFO_PROXY_SSL_VERIFYRESULT = 2097199,
    CURLINFO_PROTOCOL = 2097200,
    CURLINFO_SCHEME = 1048625,
    CURLINFO_TOTAL_TIME_T = 6291506,
    CURLINFO_NAMELOOKUP_TIME_T = 6291507,
    CURLINFO_CONNECT_TIME_T = 6291508,
    CURLINFO_PRETRANSFER_TIME_T = 6291509,
    CURLINFO_STARTTRANSFER_TIME_T = 6291510,
    CURLINFO_REDIRECT_TIME_T = 6291511,
    CURLINFO_APPCONNECT_TIME_T = 6291512,
    CURLINFO_RETRY_AFTER = 6291513,
    CURLINFO_EFFECTIVE_METHOD = 1048634,
    CURLINFO_PROXY_ERROR = 2097211,
    CURLINFO_REFERER = 1048636,
    CURLINFO_CAINFO = 1048637,
    CURLINFO_CAPATH = 1048638,
    CURLINFO_XFER_ID = 6291519,
    CURLINFO_CONN_ID = 6291520,
    CURLINFO_QUEUE_TIME_T = 6291521,
    CURLINFO_USED_PROXY = 2097218,
    CURLINFO_POSTTRANSFER_TIME_T = 6291523,
    CURLINFO_EARLYDATA_SENT_T = 6291524,
    CURLINFO_HTTPAUTH_USED = 2097221,
    CURLINFO_PROXYAUTH_USED = 2097222,
    CURLINFO_LASTONE = 70,
}

/// Every [`CurlInfo`] variant, used to invert the integer mapping.
const CURLINFO_ALL: [CurlInfo; 79] = [
    CurlInfo::CURLINFO_NONE,
    CurlInfo::CURLINFO_EFFECTIVE_URL,
    CurlInfo::CURLINFO_RESPONSE_CODE,
    CurlInfo::CURLINFO_TOTAL_TIME,
    CurlInfo::CURLINFO_NAMELOOKUP_TIME,
    CurlInfo::CURLINFO_CONNECT_TIME,
    CurlInfo::CURLINFO_PRETRANSFER_TIME,
    CurlInfo::CURLINFO_SIZE_UPLOAD,
    CurlInfo::CURLINFO_SIZE_UPLOAD_T,
    CurlInfo::CURLINFO_SIZE_DOWNLOAD,
    CurlInfo::CURLINFO_SIZE_DOWNLOAD_T,
    CurlInfo::CURLINFO_SPEED_DOWNLOAD,
    CurlInfo::CURLINFO_SPEED_DOWNLOAD_T,
    CurlInfo::CURLINFO_SPEED_UPLOAD,
    CurlInfo::CURLINFO_SPEED_UPLOAD_T,
    CurlInfo::CURLINFO_HEADER_SIZE,
    CurlInfo::CURLINFO_REQUEST_SIZE,
    CurlInfo::CURLINFO_SSL_VERIFYRESULT,
    CurlInfo::CURLINFO_FILETIME,
    CurlInfo::CURLINFO_FILETIME_T,
    CurlInfo::CURLINFO_CONTENT_LENGTH_DOWNLOAD,
    CurlInfo::CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
    CurlInfo::CURLINFO_CONTENT_LENGTH_UPLOAD,
    CurlInfo::CURLINFO_CONTENT_LENGTH_UPLOAD_T,
    CurlInfo::CURLINFO_STARTTRANSFER_TIME,
    CurlInfo::CURLINFO_CONTENT_TYPE,
    CurlInfo::CURLINFO_REDIRECT_TIME,
    CurlInfo::CURLINFO_REDIRECT_COUNT,
    CurlInfo::CURLINFO_PRIVATE,
    CurlInfo::CURLINFO_HTTP_CONNECTCODE,
    CurlInfo::CURLINFO_HTTPAUTH_AVAIL,
    CurlInfo::CURLINFO_PROXYAUTH_AVAIL,
    CurlInfo::CURLINFO_OS_ERRNO,
    CurlInfo::CURLINFO_NUM_CONNECTS,
    CurlInfo::CURLINFO_SSL_ENGINES,
    CurlInfo::CURLINFO_COOKIELIST,
    CurlInfo::CURLINFO_LASTSOCKET,
    CurlInfo::CURLINFO_FTP_ENTRY_PATH,
    CurlInfo::CURLINFO_REDIRECT_URL,
    CurlInfo::CURLINFO_PRIMARY_IP,
    CurlInfo::CURLINFO_APPCONNECT_TIME,
    CurlInfo::CURLINFO_CERTINFO,
    CurlInfo::CURLINFO_CONDITION_UNMET,
    CurlInfo::CURLINFO_RTSP_SESSION_ID,
    CurlInfo::CURLINFO_RTSP_CLIENT_CSEQ,
    CurlInfo::CURLINFO_RTSP_SERVER_CSEQ,
    CurlInfo::CURLINFO_RTSP_CSEQ_RECV,
    CurlInfo::CURLINFO_PRIMARY_PORT,
    CurlInfo::CURLINFO_LOCAL_IP,
    CurlInfo::CURLINFO_LOCAL_PORT,
    CurlInfo::CURLINFO_TLS_SESSION,
    CurlInfo::CURLINFO_ACTIVESOCKET,
    CurlInfo::CURLINFO_TLS_SSL_PTR,
    CurlInfo::CURLINFO_HTTP_VERSION,
    CurlInfo::CURLINFO_PROXY_SSL_VERIFYRESULT,
    CurlInfo::CURLINFO_PROTOCOL,
    CurlInfo::CURLINFO_SCHEME,
    CurlInfo::CURLINFO_TOTAL_TIME_T,
    CurlInfo::CURLINFO_NAMELOOKUP_TIME_T,
    CurlInfo::CURLINFO_CONNECT_TIME_T,
    CurlInfo::CURLINFO_PRETRANSFER_TIME_T,
    CurlInfo::CURLINFO_STARTTRANSFER_TIME_T,
    CurlInfo::CURLINFO_REDIRECT_TIME_T,
    CurlInfo::CURLINFO_APPCONNECT_TIME_T,
    CurlInfo::CURLINFO_RETRY_AFTER,
    CurlInfo::CURLINFO_EFFECTIVE_METHOD,
    CurlInfo::CURLINFO_PROXY_ERROR,
    CurlInfo::CURLINFO_REFERER,
    CurlInfo::CURLINFO_CAINFO,
    CurlInfo::CURLINFO_CAPATH,
    CurlInfo::CURLINFO_XFER_ID,
    CurlInfo::CURLINFO_CONN_ID,
    CurlInfo::CURLINFO_QUEUE_TIME_T,
    CurlInfo::CURLINFO_USED_PROXY,
    CurlInfo::CURLINFO_POSTTRANSFER_TIME_T,
    CurlInfo::CURLINFO_EARLYDATA_SENT_T,
    CurlInfo::CURLINFO_HTTPAUTH_USED,
    CurlInfo::CURLINFO_PROXYAUTH_USED,
    CurlInfo::CURLINFO_LASTONE,
];

impl CurlInfo {
    /// Returns the exact `CURLINFO` integer value of this query id.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Resolves a raw integer to its [`CurlInfo`], or `None` if unknown.
    #[must_use]
    pub fn from_i32(value: i32) -> Option<CurlInfo> {
        CURLINFO_ALL
            .iter()
            .copied()
            .find(|info| info.as_i32() == value)
    }
}

/// One row of curl's easy-option metadata table -- the Rust analogue of
/// `struct curl_easyoption` (`include/curl/options.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EasyOption {
    /// The option's name with the `CURLOPT_` prefix stripped, exactly as curl
    /// stores it (for example `"URL"` or `"WRITEFUNCTION"`).
    pub name: &'static str,
    /// The `CURLoption` identifier this name maps to.
    pub id: CurlOption,
    /// The option's value type.
    pub typ: CurlOptType,
    /// Bit flags; currently only [`CURLOT_FLAG_ALIAS`] is defined.
    pub flags: u32,
}

impl EasyOption {
    /// Returns `true` if this entry is a backwards-compatibility alias
    /// (its [`flags`](Self::flags) carry [`CURLOT_FLAG_ALIAS`]).
    #[must_use]
    pub const fn is_alias(&self) -> bool {
        (self.flags & CURLOT_FLAG_ALIAS) != 0
    }
}

/// The complete easy-option metadata table -- the Rust analogue of curl's
/// generated `Curl_easyopts[]` (`lib/easyoptions.c`).
///
/// Entries are in curl's original order (ASCII-ascending by name). Unlike the C
/// array this slice carries no trailing sentinel row; its length is the exact
/// number of options. It is a `static` so that every `&'static EasyOption`
/// returned by the lookups has a stable identity (relied upon by
/// [`option_next`]).
pub static EASY_OPTIONS: &[EasyOption] = &[
    EasyOption {
        name: "ABSTRACT_UNIX_SOCKET",
        id: CurlOption::CURLOPT_ABSTRACT_UNIX_SOCKET,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "ACCEPTTIMEOUT_MS",
        id: CurlOption::CURLOPT_ACCEPTTIMEOUT_MS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "ACCEPT_ENCODING",
        id: CurlOption::CURLOPT_ACCEPT_ENCODING,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "ADDRESS_SCOPE",
        id: CurlOption::CURLOPT_ADDRESS_SCOPE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "ALTSVC",
        id: CurlOption::CURLOPT_ALTSVC,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "ALTSVC_CTRL",
        id: CurlOption::CURLOPT_ALTSVC_CTRL,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "APPEND",
        id: CurlOption::CURLOPT_APPEND,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "AUTOREFERER",
        id: CurlOption::CURLOPT_AUTOREFERER,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "AWS_SIGV4",
        id: CurlOption::CURLOPT_AWS_SIGV4,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "BUFFERSIZE",
        id: CurlOption::CURLOPT_BUFFERSIZE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "CAINFO",
        id: CurlOption::CURLOPT_CAINFO,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "CAINFO_BLOB",
        id: CurlOption::CURLOPT_CAINFO_BLOB,
        typ: CurlOptType::Blob,
        flags: 0,
    },
    EasyOption {
        name: "CAPATH",
        id: CurlOption::CURLOPT_CAPATH,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "CA_CACHE_TIMEOUT",
        id: CurlOption::CURLOPT_CA_CACHE_TIMEOUT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "CERTINFO",
        id: CurlOption::CURLOPT_CERTINFO,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "CHUNK_BGN_FUNCTION",
        id: CurlOption::CURLOPT_CHUNK_BGN_FUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "CHUNK_DATA",
        id: CurlOption::CURLOPT_CHUNK_DATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "CHUNK_END_FUNCTION",
        id: CurlOption::CURLOPT_CHUNK_END_FUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "CLOSESOCKETDATA",
        id: CurlOption::CURLOPT_CLOSESOCKETDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "CLOSESOCKETFUNCTION",
        id: CurlOption::CURLOPT_CLOSESOCKETFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "CONNECTTIMEOUT",
        id: CurlOption::CURLOPT_CONNECTTIMEOUT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "CONNECTTIMEOUT_MS",
        id: CurlOption::CURLOPT_CONNECTTIMEOUT_MS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "CONNECT_ONLY",
        id: CurlOption::CURLOPT_CONNECT_ONLY,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "CONNECT_TO",
        id: CurlOption::CURLOPT_CONNECT_TO,
        typ: CurlOptType::Slist,
        flags: 0,
    },
    EasyOption {
        name: "CONV_FROM_NETWORK_FUNCTION",
        id: CurlOption::CURLOPT_CONV_FROM_NETWORK_FUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "CONV_FROM_UTF8_FUNCTION",
        id: CurlOption::CURLOPT_CONV_FROM_UTF8_FUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "CONV_TO_NETWORK_FUNCTION",
        id: CurlOption::CURLOPT_CONV_TO_NETWORK_FUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "COOKIE",
        id: CurlOption::CURLOPT_COOKIE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "COOKIEFILE",
        id: CurlOption::CURLOPT_COOKIEFILE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "COOKIEJAR",
        id: CurlOption::CURLOPT_COOKIEJAR,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "COOKIELIST",
        id: CurlOption::CURLOPT_COOKIELIST,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "COOKIESESSION",
        id: CurlOption::CURLOPT_COOKIESESSION,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "COPYPOSTFIELDS",
        id: CurlOption::CURLOPT_COPYPOSTFIELDS,
        typ: CurlOptType::Object,
        flags: 0,
    },
    EasyOption {
        name: "CRLF",
        id: CurlOption::CURLOPT_CRLF,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "CRLFILE",
        id: CurlOption::CURLOPT_CRLFILE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "CURLU",
        id: CurlOption::CURLOPT_CURLU,
        typ: CurlOptType::Object,
        flags: 0,
    },
    EasyOption {
        name: "CUSTOMREQUEST",
        id: CurlOption::CURLOPT_CUSTOMREQUEST,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "DEBUGDATA",
        id: CurlOption::CURLOPT_DEBUGDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "DEBUGFUNCTION",
        id: CurlOption::CURLOPT_DEBUGFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "DEFAULT_PROTOCOL",
        id: CurlOption::CURLOPT_DEFAULT_PROTOCOL,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "DIRLISTONLY",
        id: CurlOption::CURLOPT_DIRLISTONLY,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "DISALLOW_USERNAME_IN_URL",
        id: CurlOption::CURLOPT_DISALLOW_USERNAME_IN_URL,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "DNS_CACHE_TIMEOUT",
        id: CurlOption::CURLOPT_DNS_CACHE_TIMEOUT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "DNS_INTERFACE",
        id: CurlOption::CURLOPT_DNS_INTERFACE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "DNS_LOCAL_IP4",
        id: CurlOption::CURLOPT_DNS_LOCAL_IP4,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "DNS_LOCAL_IP6",
        id: CurlOption::CURLOPT_DNS_LOCAL_IP6,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "DNS_SERVERS",
        id: CurlOption::CURLOPT_DNS_SERVERS,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "DNS_SHUFFLE_ADDRESSES",
        id: CurlOption::CURLOPT_DNS_SHUFFLE_ADDRESSES,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "DNS_USE_GLOBAL_CACHE",
        id: CurlOption::CURLOPT_DNS_USE_GLOBAL_CACHE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "DOH_SSL_VERIFYHOST",
        id: CurlOption::CURLOPT_DOH_SSL_VERIFYHOST,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "DOH_SSL_VERIFYPEER",
        id: CurlOption::CURLOPT_DOH_SSL_VERIFYPEER,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "DOH_SSL_VERIFYSTATUS",
        id: CurlOption::CURLOPT_DOH_SSL_VERIFYSTATUS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "DOH_URL",
        id: CurlOption::CURLOPT_DOH_URL,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "ECH",
        id: CurlOption::CURLOPT_ECH,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "EGDSOCKET",
        id: CurlOption::CURLOPT_EGDSOCKET,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "ENCODING",
        id: CurlOption::CURLOPT_ACCEPT_ENCODING,
        typ: CurlOptType::String,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "ERRORBUFFER",
        id: CurlOption::CURLOPT_ERRORBUFFER,
        typ: CurlOptType::Object,
        flags: 0,
    },
    EasyOption {
        name: "EXPECT_100_TIMEOUT_MS",
        id: CurlOption::CURLOPT_EXPECT_100_TIMEOUT_MS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "FAILONERROR",
        id: CurlOption::CURLOPT_FAILONERROR,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "FILE",
        id: CurlOption::CURLOPT_WRITEDATA,
        typ: CurlOptType::Cbptr,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "FILETIME",
        id: CurlOption::CURLOPT_FILETIME,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "FNMATCH_DATA",
        id: CurlOption::CURLOPT_FNMATCH_DATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "FNMATCH_FUNCTION",
        id: CurlOption::CURLOPT_FNMATCH_FUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "FOLLOWLOCATION",
        id: CurlOption::CURLOPT_FOLLOWLOCATION,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "FORBID_REUSE",
        id: CurlOption::CURLOPT_FORBID_REUSE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "FRESH_CONNECT",
        id: CurlOption::CURLOPT_FRESH_CONNECT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "FTPAPPEND",
        id: CurlOption::CURLOPT_APPEND,
        typ: CurlOptType::Long,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "FTPLISTONLY",
        id: CurlOption::CURLOPT_DIRLISTONLY,
        typ: CurlOptType::Long,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "FTPPORT",
        id: CurlOption::CURLOPT_FTPPORT,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "FTPSSLAUTH",
        id: CurlOption::CURLOPT_FTPSSLAUTH,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "FTP_ACCOUNT",
        id: CurlOption::CURLOPT_FTP_ACCOUNT,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "FTP_ALTERNATIVE_TO_USER",
        id: CurlOption::CURLOPT_FTP_ALTERNATIVE_TO_USER,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "FTP_CREATE_MISSING_DIRS",
        id: CurlOption::CURLOPT_FTP_CREATE_MISSING_DIRS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "FTP_FILEMETHOD",
        id: CurlOption::CURLOPT_FTP_FILEMETHOD,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "FTP_RESPONSE_TIMEOUT",
        id: CurlOption::CURLOPT_SERVER_RESPONSE_TIMEOUT,
        typ: CurlOptType::Long,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "FTP_SKIP_PASV_IP",
        id: CurlOption::CURLOPT_FTP_SKIP_PASV_IP,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "FTP_SSL",
        id: CurlOption::CURLOPT_USE_SSL,
        typ: CurlOptType::Values,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "FTP_SSL_CCC",
        id: CurlOption::CURLOPT_FTP_SSL_CCC,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "FTP_USE_EPRT",
        id: CurlOption::CURLOPT_FTP_USE_EPRT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "FTP_USE_EPSV",
        id: CurlOption::CURLOPT_FTP_USE_EPSV,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "FTP_USE_PRET",
        id: CurlOption::CURLOPT_FTP_USE_PRET,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "GSSAPI_DELEGATION",
        id: CurlOption::CURLOPT_GSSAPI_DELEGATION,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "HAPPY_EYEBALLS_TIMEOUT_MS",
        id: CurlOption::CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "HAPROXYPROTOCOL",
        id: CurlOption::CURLOPT_HAPROXYPROTOCOL,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "HAPROXY_CLIENT_IP",
        id: CurlOption::CURLOPT_HAPROXY_CLIENT_IP,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "HEADER",
        id: CurlOption::CURLOPT_HEADER,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "HEADERDATA",
        id: CurlOption::CURLOPT_HEADERDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "HEADERFUNCTION",
        id: CurlOption::CURLOPT_HEADERFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "HEADEROPT",
        id: CurlOption::CURLOPT_HEADEROPT,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "HSTS",
        id: CurlOption::CURLOPT_HSTS,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "HSTSREADDATA",
        id: CurlOption::CURLOPT_HSTSREADDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "HSTSREADFUNCTION",
        id: CurlOption::CURLOPT_HSTSREADFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "HSTSWRITEDATA",
        id: CurlOption::CURLOPT_HSTSWRITEDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "HSTSWRITEFUNCTION",
        id: CurlOption::CURLOPT_HSTSWRITEFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "HSTS_CTRL",
        id: CurlOption::CURLOPT_HSTS_CTRL,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "HTTP09_ALLOWED",
        id: CurlOption::CURLOPT_HTTP09_ALLOWED,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "HTTP200ALIASES",
        id: CurlOption::CURLOPT_HTTP200ALIASES,
        typ: CurlOptType::Slist,
        flags: 0,
    },
    EasyOption {
        name: "HTTPAUTH",
        id: CurlOption::CURLOPT_HTTPAUTH,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "HTTPGET",
        id: CurlOption::CURLOPT_HTTPGET,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "HTTPHEADER",
        id: CurlOption::CURLOPT_HTTPHEADER,
        typ: CurlOptType::Slist,
        flags: 0,
    },
    EasyOption {
        name: "HTTPPOST",
        id: CurlOption::CURLOPT_HTTPPOST,
        typ: CurlOptType::Object,
        flags: 0,
    },
    EasyOption {
        name: "HTTPPROXYTUNNEL",
        id: CurlOption::CURLOPT_HTTPPROXYTUNNEL,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "HTTP_CONTENT_DECODING",
        id: CurlOption::CURLOPT_HTTP_CONTENT_DECODING,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "HTTP_TRANSFER_DECODING",
        id: CurlOption::CURLOPT_HTTP_TRANSFER_DECODING,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "HTTP_VERSION",
        id: CurlOption::CURLOPT_HTTP_VERSION,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "IGNORE_CONTENT_LENGTH",
        id: CurlOption::CURLOPT_IGNORE_CONTENT_LENGTH,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "INFILE",
        id: CurlOption::CURLOPT_READDATA,
        typ: CurlOptType::Cbptr,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "INFILESIZE",
        id: CurlOption::CURLOPT_INFILESIZE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "INFILESIZE_LARGE",
        id: CurlOption::CURLOPT_INFILESIZE_LARGE,
        typ: CurlOptType::OffT,
        flags: 0,
    },
    EasyOption {
        name: "INTERFACE",
        id: CurlOption::CURLOPT_INTERFACE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "INTERLEAVEDATA",
        id: CurlOption::CURLOPT_INTERLEAVEDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "INTERLEAVEFUNCTION",
        id: CurlOption::CURLOPT_INTERLEAVEFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "IOCTLDATA",
        id: CurlOption::CURLOPT_IOCTLDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "IOCTLFUNCTION",
        id: CurlOption::CURLOPT_IOCTLFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "IPRESOLVE",
        id: CurlOption::CURLOPT_IPRESOLVE,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "ISSUERCERT",
        id: CurlOption::CURLOPT_ISSUERCERT,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "ISSUERCERT_BLOB",
        id: CurlOption::CURLOPT_ISSUERCERT_BLOB,
        typ: CurlOptType::Blob,
        flags: 0,
    },
    EasyOption {
        name: "KEEP_SENDING_ON_ERROR",
        id: CurlOption::CURLOPT_KEEP_SENDING_ON_ERROR,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "KEYPASSWD",
        id: CurlOption::CURLOPT_KEYPASSWD,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "KRB4LEVEL",
        id: CurlOption::CURLOPT_KRBLEVEL,
        typ: CurlOptType::String,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "KRBLEVEL",
        id: CurlOption::CURLOPT_KRBLEVEL,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "LOCALPORT",
        id: CurlOption::CURLOPT_LOCALPORT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "LOCALPORTRANGE",
        id: CurlOption::CURLOPT_LOCALPORTRANGE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "LOGIN_OPTIONS",
        id: CurlOption::CURLOPT_LOGIN_OPTIONS,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "LOW_SPEED_LIMIT",
        id: CurlOption::CURLOPT_LOW_SPEED_LIMIT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "LOW_SPEED_TIME",
        id: CurlOption::CURLOPT_LOW_SPEED_TIME,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "MAIL_AUTH",
        id: CurlOption::CURLOPT_MAIL_AUTH,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "MAIL_FROM",
        id: CurlOption::CURLOPT_MAIL_FROM,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "MAIL_RCPT",
        id: CurlOption::CURLOPT_MAIL_RCPT,
        typ: CurlOptType::Slist,
        flags: 0,
    },
    EasyOption {
        name: "MAIL_RCPT_ALLLOWFAILS",
        id: CurlOption::CURLOPT_MAIL_RCPT_ALLOWFAILS,
        typ: CurlOptType::Long,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "MAIL_RCPT_ALLOWFAILS",
        id: CurlOption::CURLOPT_MAIL_RCPT_ALLOWFAILS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "MAXAGE_CONN",
        id: CurlOption::CURLOPT_MAXAGE_CONN,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "MAXCONNECTS",
        id: CurlOption::CURLOPT_MAXCONNECTS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "MAXFILESIZE",
        id: CurlOption::CURLOPT_MAXFILESIZE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "MAXFILESIZE_LARGE",
        id: CurlOption::CURLOPT_MAXFILESIZE_LARGE,
        typ: CurlOptType::OffT,
        flags: 0,
    },
    EasyOption {
        name: "MAXLIFETIME_CONN",
        id: CurlOption::CURLOPT_MAXLIFETIME_CONN,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "MAXREDIRS",
        id: CurlOption::CURLOPT_MAXREDIRS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "MAX_RECV_SPEED_LARGE",
        id: CurlOption::CURLOPT_MAX_RECV_SPEED_LARGE,
        typ: CurlOptType::OffT,
        flags: 0,
    },
    EasyOption {
        name: "MAX_SEND_SPEED_LARGE",
        id: CurlOption::CURLOPT_MAX_SEND_SPEED_LARGE,
        typ: CurlOptType::OffT,
        flags: 0,
    },
    EasyOption {
        name: "MIMEPOST",
        id: CurlOption::CURLOPT_MIMEPOST,
        typ: CurlOptType::Object,
        flags: 0,
    },
    EasyOption {
        name: "MIME_OPTIONS",
        id: CurlOption::CURLOPT_MIME_OPTIONS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "NETRC",
        id: CurlOption::CURLOPT_NETRC,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "NETRC_FILE",
        id: CurlOption::CURLOPT_NETRC_FILE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "NEW_DIRECTORY_PERMS",
        id: CurlOption::CURLOPT_NEW_DIRECTORY_PERMS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "NEW_FILE_PERMS",
        id: CurlOption::CURLOPT_NEW_FILE_PERMS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "NOBODY",
        id: CurlOption::CURLOPT_NOBODY,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "NOPROGRESS",
        id: CurlOption::CURLOPT_NOPROGRESS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "NOPROXY",
        id: CurlOption::CURLOPT_NOPROXY,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "NOSIGNAL",
        id: CurlOption::CURLOPT_NOSIGNAL,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "OPENSOCKETDATA",
        id: CurlOption::CURLOPT_OPENSOCKETDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "OPENSOCKETFUNCTION",
        id: CurlOption::CURLOPT_OPENSOCKETFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "PASSWORD",
        id: CurlOption::CURLOPT_PASSWORD,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PATH_AS_IS",
        id: CurlOption::CURLOPT_PATH_AS_IS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "PINNEDPUBLICKEY",
        id: CurlOption::CURLOPT_PINNEDPUBLICKEY,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PIPEWAIT",
        id: CurlOption::CURLOPT_PIPEWAIT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "PORT",
        id: CurlOption::CURLOPT_PORT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "POST",
        id: CurlOption::CURLOPT_POST,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "POST301",
        id: CurlOption::CURLOPT_POSTREDIR,
        typ: CurlOptType::Values,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "POSTFIELDS",
        id: CurlOption::CURLOPT_POSTFIELDS,
        typ: CurlOptType::Object,
        flags: 0,
    },
    EasyOption {
        name: "POSTFIELDSIZE",
        id: CurlOption::CURLOPT_POSTFIELDSIZE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "POSTFIELDSIZE_LARGE",
        id: CurlOption::CURLOPT_POSTFIELDSIZE_LARGE,
        typ: CurlOptType::OffT,
        flags: 0,
    },
    EasyOption {
        name: "POSTQUOTE",
        id: CurlOption::CURLOPT_POSTQUOTE,
        typ: CurlOptType::Slist,
        flags: 0,
    },
    EasyOption {
        name: "POSTREDIR",
        id: CurlOption::CURLOPT_POSTREDIR,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "PREQUOTE",
        id: CurlOption::CURLOPT_PREQUOTE,
        typ: CurlOptType::Slist,
        flags: 0,
    },
    EasyOption {
        name: "PREREQDATA",
        id: CurlOption::CURLOPT_PREREQDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "PREREQFUNCTION",
        id: CurlOption::CURLOPT_PREREQFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "PRE_PROXY",
        id: CurlOption::CURLOPT_PRE_PROXY,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PRIVATE",
        id: CurlOption::CURLOPT_PRIVATE,
        typ: CurlOptType::Object,
        flags: 0,
    },
    EasyOption {
        name: "PROGRESSDATA",
        id: CurlOption::CURLOPT_XFERINFODATA,
        typ: CurlOptType::Cbptr,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "PROGRESSFUNCTION",
        id: CurlOption::CURLOPT_PROGRESSFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "PROTOCOLS",
        id: CurlOption::CURLOPT_PROTOCOLS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "PROTOCOLS_STR",
        id: CurlOption::CURLOPT_PROTOCOLS_STR,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY",
        id: CurlOption::CURLOPT_PROXY,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXYAUTH",
        id: CurlOption::CURLOPT_PROXYAUTH,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "PROXYHEADER",
        id: CurlOption::CURLOPT_PROXYHEADER,
        typ: CurlOptType::Slist,
        flags: 0,
    },
    EasyOption {
        name: "PROXYPASSWORD",
        id: CurlOption::CURLOPT_PROXYPASSWORD,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXYPORT",
        id: CurlOption::CURLOPT_PROXYPORT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "PROXYTYPE",
        id: CurlOption::CURLOPT_PROXYTYPE,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "PROXYUSERNAME",
        id: CurlOption::CURLOPT_PROXYUSERNAME,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXYUSERPWD",
        id: CurlOption::CURLOPT_PROXYUSERPWD,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_CAINFO",
        id: CurlOption::CURLOPT_PROXY_CAINFO,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_CAINFO_BLOB",
        id: CurlOption::CURLOPT_PROXY_CAINFO_BLOB,
        typ: CurlOptType::Blob,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_CAPATH",
        id: CurlOption::CURLOPT_PROXY_CAPATH,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_CRLFILE",
        id: CurlOption::CURLOPT_PROXY_CRLFILE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_ISSUERCERT",
        id: CurlOption::CURLOPT_PROXY_ISSUERCERT,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_ISSUERCERT_BLOB",
        id: CurlOption::CURLOPT_PROXY_ISSUERCERT_BLOB,
        typ: CurlOptType::Blob,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_KEYPASSWD",
        id: CurlOption::CURLOPT_PROXY_KEYPASSWD,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_PINNEDPUBLICKEY",
        id: CurlOption::CURLOPT_PROXY_PINNEDPUBLICKEY,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_SERVICE_NAME",
        id: CurlOption::CURLOPT_PROXY_SERVICE_NAME,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_SSLCERT",
        id: CurlOption::CURLOPT_PROXY_SSLCERT,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_SSLCERTTYPE",
        id: CurlOption::CURLOPT_PROXY_SSLCERTTYPE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_SSLCERT_BLOB",
        id: CurlOption::CURLOPT_PROXY_SSLCERT_BLOB,
        typ: CurlOptType::Blob,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_SSLKEY",
        id: CurlOption::CURLOPT_PROXY_SSLKEY,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_SSLKEYTYPE",
        id: CurlOption::CURLOPT_PROXY_SSLKEYTYPE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_SSLKEY_BLOB",
        id: CurlOption::CURLOPT_PROXY_SSLKEY_BLOB,
        typ: CurlOptType::Blob,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_SSLVERSION",
        id: CurlOption::CURLOPT_PROXY_SSLVERSION,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_SSL_CIPHER_LIST",
        id: CurlOption::CURLOPT_PROXY_SSL_CIPHER_LIST,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_SSL_OPTIONS",
        id: CurlOption::CURLOPT_PROXY_SSL_OPTIONS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_SSL_VERIFYHOST",
        id: CurlOption::CURLOPT_PROXY_SSL_VERIFYHOST,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_SSL_VERIFYPEER",
        id: CurlOption::CURLOPT_PROXY_SSL_VERIFYPEER,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_TLS13_CIPHERS",
        id: CurlOption::CURLOPT_PROXY_TLS13_CIPHERS,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_TLSAUTH_PASSWORD",
        id: CurlOption::CURLOPT_PROXY_TLSAUTH_PASSWORD,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_TLSAUTH_TYPE",
        id: CurlOption::CURLOPT_PROXY_TLSAUTH_TYPE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_TLSAUTH_USERNAME",
        id: CurlOption::CURLOPT_PROXY_TLSAUTH_USERNAME,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "PROXY_TRANSFER_MODE",
        id: CurlOption::CURLOPT_PROXY_TRANSFER_MODE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "PUT",
        id: CurlOption::CURLOPT_PUT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "QUICK_EXIT",
        id: CurlOption::CURLOPT_QUICK_EXIT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "QUOTE",
        id: CurlOption::CURLOPT_QUOTE,
        typ: CurlOptType::Slist,
        flags: 0,
    },
    EasyOption {
        name: "RANDOM_FILE",
        id: CurlOption::CURLOPT_RANDOM_FILE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "RANGE",
        id: CurlOption::CURLOPT_RANGE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "READDATA",
        id: CurlOption::CURLOPT_READDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "READFUNCTION",
        id: CurlOption::CURLOPT_READFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "REDIR_PROTOCOLS",
        id: CurlOption::CURLOPT_REDIR_PROTOCOLS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "REDIR_PROTOCOLS_STR",
        id: CurlOption::CURLOPT_REDIR_PROTOCOLS_STR,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "REFERER",
        id: CurlOption::CURLOPT_REFERER,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "REQUEST_TARGET",
        id: CurlOption::CURLOPT_REQUEST_TARGET,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "RESOLVE",
        id: CurlOption::CURLOPT_RESOLVE,
        typ: CurlOptType::Slist,
        flags: 0,
    },
    EasyOption {
        name: "RESOLVER_START_DATA",
        id: CurlOption::CURLOPT_RESOLVER_START_DATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "RESOLVER_START_FUNCTION",
        id: CurlOption::CURLOPT_RESOLVER_START_FUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "RESUME_FROM",
        id: CurlOption::CURLOPT_RESUME_FROM,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "RESUME_FROM_LARGE",
        id: CurlOption::CURLOPT_RESUME_FROM_LARGE,
        typ: CurlOptType::OffT,
        flags: 0,
    },
    EasyOption {
        name: "RTSPHEADER",
        id: CurlOption::CURLOPT_HTTPHEADER,
        typ: CurlOptType::Slist,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "RTSP_CLIENT_CSEQ",
        id: CurlOption::CURLOPT_RTSP_CLIENT_CSEQ,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "RTSP_REQUEST",
        id: CurlOption::CURLOPT_RTSP_REQUEST,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "RTSP_SERVER_CSEQ",
        id: CurlOption::CURLOPT_RTSP_SERVER_CSEQ,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "RTSP_SESSION_ID",
        id: CurlOption::CURLOPT_RTSP_SESSION_ID,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "RTSP_STREAM_URI",
        id: CurlOption::CURLOPT_RTSP_STREAM_URI,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "RTSP_TRANSPORT",
        id: CurlOption::CURLOPT_RTSP_TRANSPORT,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SASL_AUTHZID",
        id: CurlOption::CURLOPT_SASL_AUTHZID,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SASL_IR",
        id: CurlOption::CURLOPT_SASL_IR,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SEEKDATA",
        id: CurlOption::CURLOPT_SEEKDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "SEEKFUNCTION",
        id: CurlOption::CURLOPT_SEEKFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "SERVER_RESPONSE_TIMEOUT",
        id: CurlOption::CURLOPT_SERVER_RESPONSE_TIMEOUT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SERVER_RESPONSE_TIMEOUT_MS",
        id: CurlOption::CURLOPT_SERVER_RESPONSE_TIMEOUT_MS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SERVICE_NAME",
        id: CurlOption::CURLOPT_SERVICE_NAME,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SHARE",
        id: CurlOption::CURLOPT_SHARE,
        typ: CurlOptType::Object,
        flags: 0,
    },
    EasyOption {
        name: "SOCKOPTDATA",
        id: CurlOption::CURLOPT_SOCKOPTDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "SOCKOPTFUNCTION",
        id: CurlOption::CURLOPT_SOCKOPTFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "SOCKS5_AUTH",
        id: CurlOption::CURLOPT_SOCKS5_AUTH,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SOCKS5_GSSAPI_NEC",
        id: CurlOption::CURLOPT_SOCKS5_GSSAPI_NEC,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SOCKS5_GSSAPI_SERVICE",
        id: CurlOption::CURLOPT_SOCKS5_GSSAPI_SERVICE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSH_AUTH_TYPES",
        id: CurlOption::CURLOPT_SSH_AUTH_TYPES,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "SSH_COMPRESSION",
        id: CurlOption::CURLOPT_SSH_COMPRESSION,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SSH_HOSTKEYDATA",
        id: CurlOption::CURLOPT_SSH_HOSTKEYDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "SSH_HOSTKEYFUNCTION",
        id: CurlOption::CURLOPT_SSH_HOSTKEYFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "SSH_HOST_PUBLIC_KEY_MD5",
        id: CurlOption::CURLOPT_SSH_HOST_PUBLIC_KEY_MD5,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSH_HOST_PUBLIC_KEY_SHA256",
        id: CurlOption::CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSH_KEYDATA",
        id: CurlOption::CURLOPT_SSH_KEYDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "SSH_KEYFUNCTION",
        id: CurlOption::CURLOPT_SSH_KEYFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "SSH_KNOWNHOSTS",
        id: CurlOption::CURLOPT_SSH_KNOWNHOSTS,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSH_PRIVATE_KEYFILE",
        id: CurlOption::CURLOPT_SSH_PRIVATE_KEYFILE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSH_PUBLIC_KEYFILE",
        id: CurlOption::CURLOPT_SSH_PUBLIC_KEYFILE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSLCERT",
        id: CurlOption::CURLOPT_SSLCERT,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSLCERTPASSWD",
        id: CurlOption::CURLOPT_KEYPASSWD,
        typ: CurlOptType::String,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "SSLCERTTYPE",
        id: CurlOption::CURLOPT_SSLCERTTYPE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSLCERT_BLOB",
        id: CurlOption::CURLOPT_SSLCERT_BLOB,
        typ: CurlOptType::Blob,
        flags: 0,
    },
    EasyOption {
        name: "SSLENGINE",
        id: CurlOption::CURLOPT_SSLENGINE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSLENGINE_DEFAULT",
        id: CurlOption::CURLOPT_SSLENGINE_DEFAULT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SSLKEY",
        id: CurlOption::CURLOPT_SSLKEY,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSLKEYPASSWD",
        id: CurlOption::CURLOPT_KEYPASSWD,
        typ: CurlOptType::String,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "SSLKEYTYPE",
        id: CurlOption::CURLOPT_SSLKEYTYPE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSLKEY_BLOB",
        id: CurlOption::CURLOPT_SSLKEY_BLOB,
        typ: CurlOptType::Blob,
        flags: 0,
    },
    EasyOption {
        name: "SSLVERSION",
        id: CurlOption::CURLOPT_SSLVERSION,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "SSL_CIPHER_LIST",
        id: CurlOption::CURLOPT_SSL_CIPHER_LIST,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSL_CTX_DATA",
        id: CurlOption::CURLOPT_SSL_CTX_DATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "SSL_CTX_FUNCTION",
        id: CurlOption::CURLOPT_SSL_CTX_FUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "SSL_EC_CURVES",
        id: CurlOption::CURLOPT_SSL_EC_CURVES,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSL_ENABLE_ALPN",
        id: CurlOption::CURLOPT_SSL_ENABLE_ALPN,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SSL_ENABLE_NPN",
        id: CurlOption::CURLOPT_SSL_ENABLE_NPN,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SSL_FALSESTART",
        id: CurlOption::CURLOPT_SSL_FALSESTART,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SSL_OPTIONS",
        id: CurlOption::CURLOPT_SSL_OPTIONS,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "SSL_SESSIONID_CACHE",
        id: CurlOption::CURLOPT_SSL_SESSIONID_CACHE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SSL_SIGNATURE_ALGORITHMS",
        id: CurlOption::CURLOPT_SSL_SIGNATURE_ALGORITHMS,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "SSL_VERIFYHOST",
        id: CurlOption::CURLOPT_SSL_VERIFYHOST,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SSL_VERIFYPEER",
        id: CurlOption::CURLOPT_SSL_VERIFYPEER,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SSL_VERIFYSTATUS",
        id: CurlOption::CURLOPT_SSL_VERIFYSTATUS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "STDERR",
        id: CurlOption::CURLOPT_STDERR,
        typ: CurlOptType::Object,
        flags: 0,
    },
    EasyOption {
        name: "STREAM_DEPENDS",
        id: CurlOption::CURLOPT_STREAM_DEPENDS,
        typ: CurlOptType::Object,
        flags: 0,
    },
    EasyOption {
        name: "STREAM_DEPENDS_E",
        id: CurlOption::CURLOPT_STREAM_DEPENDS_E,
        typ: CurlOptType::Object,
        flags: 0,
    },
    EasyOption {
        name: "STREAM_WEIGHT",
        id: CurlOption::CURLOPT_STREAM_WEIGHT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "SUPPRESS_CONNECT_HEADERS",
        id: CurlOption::CURLOPT_SUPPRESS_CONNECT_HEADERS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "TCP_FASTOPEN",
        id: CurlOption::CURLOPT_TCP_FASTOPEN,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "TCP_KEEPALIVE",
        id: CurlOption::CURLOPT_TCP_KEEPALIVE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "TCP_KEEPCNT",
        id: CurlOption::CURLOPT_TCP_KEEPCNT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "TCP_KEEPIDLE",
        id: CurlOption::CURLOPT_TCP_KEEPIDLE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "TCP_KEEPINTVL",
        id: CurlOption::CURLOPT_TCP_KEEPINTVL,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "TCP_NODELAY",
        id: CurlOption::CURLOPT_TCP_NODELAY,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "TELNETOPTIONS",
        id: CurlOption::CURLOPT_TELNETOPTIONS,
        typ: CurlOptType::Slist,
        flags: 0,
    },
    EasyOption {
        name: "TFTP_BLKSIZE",
        id: CurlOption::CURLOPT_TFTP_BLKSIZE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "TFTP_NO_OPTIONS",
        id: CurlOption::CURLOPT_TFTP_NO_OPTIONS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "TIMECONDITION",
        id: CurlOption::CURLOPT_TIMECONDITION,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "TIMEOUT",
        id: CurlOption::CURLOPT_TIMEOUT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "TIMEOUT_MS",
        id: CurlOption::CURLOPT_TIMEOUT_MS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "TIMEVALUE",
        id: CurlOption::CURLOPT_TIMEVALUE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "TIMEVALUE_LARGE",
        id: CurlOption::CURLOPT_TIMEVALUE_LARGE,
        typ: CurlOptType::OffT,
        flags: 0,
    },
    EasyOption {
        name: "TLS13_CIPHERS",
        id: CurlOption::CURLOPT_TLS13_CIPHERS,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "TLSAUTH_PASSWORD",
        id: CurlOption::CURLOPT_TLSAUTH_PASSWORD,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "TLSAUTH_TYPE",
        id: CurlOption::CURLOPT_TLSAUTH_TYPE,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "TLSAUTH_USERNAME",
        id: CurlOption::CURLOPT_TLSAUTH_USERNAME,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "TRAILERDATA",
        id: CurlOption::CURLOPT_TRAILERDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "TRAILERFUNCTION",
        id: CurlOption::CURLOPT_TRAILERFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "TRANSFERTEXT",
        id: CurlOption::CURLOPT_TRANSFERTEXT,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "TRANSFER_ENCODING",
        id: CurlOption::CURLOPT_TRANSFER_ENCODING,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "UNIX_SOCKET_PATH",
        id: CurlOption::CURLOPT_UNIX_SOCKET_PATH,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "UNRESTRICTED_AUTH",
        id: CurlOption::CURLOPT_UNRESTRICTED_AUTH,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "UPKEEP_INTERVAL_MS",
        id: CurlOption::CURLOPT_UPKEEP_INTERVAL_MS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "UPLOAD",
        id: CurlOption::CURLOPT_UPLOAD,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "UPLOAD_BUFFERSIZE",
        id: CurlOption::CURLOPT_UPLOAD_BUFFERSIZE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "UPLOAD_FLAGS",
        id: CurlOption::CURLOPT_UPLOAD_FLAGS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "URL",
        id: CurlOption::CURLOPT_URL,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "USERAGENT",
        id: CurlOption::CURLOPT_USERAGENT,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "USERNAME",
        id: CurlOption::CURLOPT_USERNAME,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "USERPWD",
        id: CurlOption::CURLOPT_USERPWD,
        typ: CurlOptType::String,
        flags: 0,
    },
    EasyOption {
        name: "USE_SSL",
        id: CurlOption::CURLOPT_USE_SSL,
        typ: CurlOptType::Values,
        flags: 0,
    },
    EasyOption {
        name: "VERBOSE",
        id: CurlOption::CURLOPT_VERBOSE,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "WILDCARDMATCH",
        id: CurlOption::CURLOPT_WILDCARDMATCH,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "WRITEDATA",
        id: CurlOption::CURLOPT_WRITEDATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "WRITEFUNCTION",
        id: CurlOption::CURLOPT_WRITEFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "WRITEHEADER",
        id: CurlOption::CURLOPT_HEADERDATA,
        typ: CurlOptType::Cbptr,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOption {
        name: "WS_OPTIONS",
        id: CurlOption::CURLOPT_WS_OPTIONS,
        typ: CurlOptType::Long,
        flags: 0,
    },
    EasyOption {
        name: "XFERINFODATA",
        id: CurlOption::CURLOPT_XFERINFODATA,
        typ: CurlOptType::Cbptr,
        flags: 0,
    },
    EasyOption {
        name: "XFERINFOFUNCTION",
        id: CurlOption::CURLOPT_XFERINFOFUNCTION,
        typ: CurlOptType::Function,
        flags: 0,
    },
    EasyOption {
        name: "XOAUTH2_BEARER",
        id: CurlOption::CURLOPT_XOAUTH2_BEARER,
        typ: CurlOptType::String,
        flags: 0,
    },
];

/// Finds the option whose name equals `name`, case-insensitively -- the
/// behavioural mirror of `curl_easy_option_by_name`.
///
/// The comparison is ASCII case-insensitive (curl uses `curl_strequal`), and --
/// like curl -- alias entries are eligible matches, so for example `"ENCODING"`
/// resolves to the alias of `CURLOPT_ACCEPT_ENCODING`.
#[must_use]
pub fn option_by_name(name: &str) -> Option<&'static EasyOption> {
    EASY_OPTIONS
        .iter()
        .find(|o| o.name.eq_ignore_ascii_case(name))
}

/// Finds the canonical (non-alias) option with the given id -- the behavioural
/// mirror of `curl_easy_option_by_id`.
///
/// Alias entries are skipped, so an id that has both a canonical entry and one
/// or more aliases always resolves to the canonical one.
#[must_use]
pub fn option_by_id(id: CurlOption) -> Option<&'static EasyOption> {
    EASY_OPTIONS
        .iter()
        .find(|o| o.id == id && (o.flags & CURLOT_FLAG_ALIAS) == 0)
}

/// Iterates the option table -- the behavioural mirror of
/// `curl_easy_option_next`.
///
/// Passing `None` returns the first entry; passing the entry previously returned
/// yields the next one; passing the last entry -- or a reference that is not
/// part of [`EASY_OPTIONS`] -- returns `None`.
#[must_use]
pub fn option_next(prev: Option<&'static EasyOption>) -> Option<&'static EasyOption> {
    match prev {
        None => EASY_OPTIONS.first(),
        Some(prev) => {
            let idx = EASY_OPTIONS.iter().position(|o| core::ptr::eq(o, prev))?;
            EASY_OPTIONS.get(idx + 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_exact_length() {
        // curl 8.x `Curl_easyopts[]` carries 323 named rows (plus a C sentinel
        // row that this slice does not need).
        assert_eq!(EASY_OPTIONS.len(), 323);
    }

    #[test]
    fn alias_and_canonical_counts() {
        let aliases = EASY_OPTIONS.iter().filter(|o| o.is_alias()).count();
        let canonical = EASY_OPTIONS.iter().filter(|o| !o.is_alias()).count();
        assert_eq!(aliases, 15, "expected 15 CURLOT_FLAG_ALIAS rows");
        assert_eq!(canonical, 308, "expected 308 canonical rows");
        assert_eq!(aliases + canonical, EASY_OPTIONS.len());
    }

    #[test]
    fn names_are_unique_and_ascii_ascending() {
        // curl keeps the table sorted ASCII-ascending by name; preserving that
        // order (and hence uniqueness) is part of matching the oracle.
        for w in EASY_OPTIONS.windows(2) {
            assert!(
                w[0].name < w[1].name,
                "table not strictly ascending at {} -> {}",
                w[0].name,
                w[1].name
            );
        }
    }

    #[test]
    fn canonical_ids_are_distinct_and_total() {
        let mut ids: Vec<i32> = EASY_OPTIONS
            .iter()
            .filter(|o| !o.is_alias())
            .map(|o| o.id.as_i32())
            .collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate canonical ids found");
        assert_eq!(total, 308);
    }

    #[test]
    fn url_name_and_id_agree() {
        let by_name = option_by_name("URL").expect("URL present");
        let by_id = option_by_id(CurlOption::CURLOPT_URL).expect("CURLOPT_URL present");
        assert!(core::ptr::eq(by_name, by_id));
        assert_eq!(by_name.id, CurlOption::CURLOPT_URL);
        assert_eq!(by_name.typ, CurlOptType::String);
        assert!(!by_name.is_alias());
    }

    #[test]
    fn name_lookup_is_case_insensitive() {
        let canonical = option_by_name("URL").unwrap();
        for variant in ["url", "Url", "uRL", "URL"] {
            let found = option_by_name(variant).expect("case-insensitive match");
            assert!(core::ptr::eq(found, canonical));
        }
        assert!(option_by_name("definitely_not_an_option").is_none());
    }

    #[test]
    fn name_lookup_resolves_aliases() {
        // "ENCODING" is an alias of CURLOPT_ACCEPT_ENCODING and must resolve by
        // name (curl does not skip aliases for name lookups).
        let enc = option_by_name("ENCODING").expect("ENCODING alias present");
        assert!(enc.is_alias());
        assert_eq!(enc.id, CurlOption::CURLOPT_ACCEPT_ENCODING);
        // The legacy triple-L spelling is preserved verbatim.
        let typo = option_by_name("MAIL_RCPT_ALLLOWFAILS").expect("legacy spelling present");
        assert!(typo.is_alias());
        assert_eq!(typo.id, CurlOption::CURLOPT_MAIL_RCPT_ALLOWFAILS);
    }

    #[test]
    fn id_lookup_skips_aliases() {
        // CURLOPT_ACCEPT_ENCODING has both a canonical row ("ACCEPT_ENCODING")
        // and an alias ("ENCODING"); by-id must return the canonical one.
        let by_id = option_by_id(CurlOption::CURLOPT_ACCEPT_ENCODING).unwrap();
        assert_eq!(by_id.name, "ACCEPT_ENCODING");
        assert!(!by_id.is_alias());
        // CURLOPT_KEYPASSWD is referenced by two aliases (SSLCERTPASSWD and
        // SSLKEYPASSWD) plus its canonical row.
        let kp = option_by_id(CurlOption::CURLOPT_KEYPASSWD).unwrap();
        assert_eq!(kp.name, "KEYPASSWD");
        assert!(!kp.is_alias());
    }

    #[test]
    fn next_iterates_every_entry_once_in_order() {
        let mut count = 0usize;
        let mut idx = 0usize;
        let mut cur = option_next(None);
        while let Some(opt) = cur {
            assert!(core::ptr::eq(opt, &EASY_OPTIONS[idx]));
            count += 1;
            idx += 1;
            cur = option_next(Some(opt));
        }
        assert_eq!(count, EASY_OPTIONS.len());
        assert_eq!(count, 323);
    }

    #[test]
    fn next_on_last_entry_is_none() {
        let last = EASY_OPTIONS.last().unwrap();
        assert!(option_next(Some(last)).is_none());
    }

    #[test]
    fn exact_curloption_values() {
        // A representative spread across every CURLOPTTYPE_* base, pinned so any
        // drift from include/curl/curl.h fails the build.
        assert_eq!(CurlOption::CURLOPT_WRITEDATA.as_i32(), 10_001);
        assert_eq!(CurlOption::CURLOPT_URL.as_i32(), 10_002);
        assert_eq!(CurlOption::CURLOPT_PORT.as_i32(), 3);
        assert_eq!(CurlOption::CURLOPT_READDATA.as_i32(), 10_009);
        assert_eq!(CurlOption::CURLOPT_WRITEFUNCTION.as_i32(), 20_011);
        assert_eq!(CurlOption::CURLOPT_POSTFIELDS.as_i32(), 10_015);
        assert_eq!(CurlOption::CURLOPT_HTTPHEADER.as_i32(), 10_023);
        assert_eq!(CurlOption::CURLOPT_KEYPASSWD.as_i32(), 10_026);
        assert_eq!(CurlOption::CURLOPT_XFERINFODATA.as_i32(), 10_057);
        assert_eq!(CurlOption::CURLOPT_KRBLEVEL.as_i32(), 10_063);
        assert_eq!(CurlOption::CURLOPT_ACCEPT_ENCODING.as_i32(), 10_102);
        assert_eq!(CurlOption::CURLOPT_USE_SSL.as_i32(), 119);
        assert_eq!(CurlOption::CURLOPT_SERVER_RESPONSE_TIMEOUT.as_i32(), 112);
        assert_eq!(CurlOption::CURLOPT_INFILESIZE_LARGE.as_i32(), 30_115);
        assert_eq!(CurlOption::CURLOPT_CAINFO_BLOB.as_i32(), 40_309);
    }

    #[test]
    fn type_groups_classify_each_base() {
        assert_eq!(
            option_type_group(CurlOption::CURLOPT_PORT.as_i32()),
            Some(CurloptTypeGroup::Long)
        );
        assert_eq!(
            option_type_group(CurlOption::CURLOPT_URL.as_i32()),
            Some(CurloptTypeGroup::ObjectPoint)
        );
        assert_eq!(
            option_type_group(CurlOption::CURLOPT_WRITEFUNCTION.as_i32()),
            Some(CurloptTypeGroup::FunctionPoint)
        );
        assert_eq!(
            option_type_group(CurlOption::CURLOPT_INFILESIZE_LARGE.as_i32()),
            Some(CurloptTypeGroup::OffT)
        );
        assert_eq!(
            option_type_group(CurlOption::CURLOPT_CAINFO_BLOB.as_i32()),
            Some(CurloptTypeGroup::Blob)
        );
        // Out-of-range ids have no group.
        assert_eq!(option_type_group(-1), None);
        assert_eq!(option_type_group(50_000), None);
        // The const method agrees with the free function for valid ids.
        assert_eq!(
            CurlOption::CURLOPT_URL.type_group(),
            CurloptTypeGroup::ObjectPoint
        );
        assert_eq!(
            CurlOption::CURLOPT_WRITEFUNCTION.type_group(),
            CurloptTypeGroup::FunctionPoint
        );
    }

    #[test]
    fn value_type_matches_base_for_every_row() {
        // The fine-grained CURLOT_* type must be consistent with the coarse
        // CURLOPTTYPE_* base encoded in the id, for every row in the table.
        for o in EASY_OPTIONS {
            let group = option_type_group(o.id.as_i32()).expect("valid base");
            let expected = match o.typ {
                CurlOptType::Long | CurlOptType::Values => CurloptTypeGroup::Long,
                CurlOptType::Object
                | CurlOptType::String
                | CurlOptType::Slist
                | CurlOptType::Cbptr => CurloptTypeGroup::ObjectPoint,
                CurlOptType::Function => CurloptTypeGroup::FunctionPoint,
                CurlOptType::OffT => CurloptTypeGroup::OffT,
                CurlOptType::Blob => CurloptTypeGroup::Blob,
            };
            assert_eq!(group, expected, "type/base mismatch for {}", o.name);
        }
    }

    #[test]
    fn from_i32_round_trips_every_canonical_id() {
        for o in EASY_OPTIONS.iter().filter(|o| !o.is_alias()) {
            assert_eq!(CurlOption::from_i32(o.id.as_i32()), Some(o.id));
        }
        assert_eq!(CurlOption::from_i32(-1), None);
        assert_eq!(CurlOption::from_i32(987_654), None);
    }

    #[test]
    fn curlopttype_discriminants() {
        assert_eq!(CurlOptType::Long.as_c_int(), 0);
        assert_eq!(CurlOptType::Values.as_c_int(), 1);
        assert_eq!(CurlOptType::OffT.as_c_int(), 2);
        assert_eq!(CurlOptType::Object.as_c_int(), 3);
        assert_eq!(CurlOptType::String.as_c_int(), 4);
        assert_eq!(CurlOptType::Slist.as_c_int(), 5);
        assert_eq!(CurlOptType::Cbptr.as_c_int(), 6);
        assert_eq!(CurlOptType::Blob.as_c_int(), 7);
        assert_eq!(CurlOptType::Function.as_c_int(), 8);
    }

    #[test]
    fn exact_curlinfo_values_and_round_trip() {
        assert_eq!(CurlInfo::CURLINFO_NONE.as_i32(), 0);
        assert_eq!(CurlInfo::CURLINFO_EFFECTIVE_URL.as_i32(), 0x10_0001);
        assert_eq!(CurlInfo::CURLINFO_RESPONSE_CODE.as_i32(), 0x20_0002);
        assert_eq!(CurlInfo::CURLINFO_TOTAL_TIME.as_i32(), 0x30_0003);
        assert_eq!(CurlInfo::CURLINFO_SIZE_UPLOAD_T.as_i32(), 0x60_0007);
        assert_eq!(CurlInfo::CURLINFO_ACTIVESOCKET.as_i32(), 0x50_002c);
        assert_eq!(CurlInfo::CURLINFO_LASTONE.as_i32(), 70);
        for info in CURLINFO_ALL {
            assert_eq!(CurlInfo::from_i32(info.as_i32()), Some(info));
        }
        assert_eq!(CurlInfo::from_i32(-1), None);
    }
}
