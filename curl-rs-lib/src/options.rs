//! Option metadata tables for the curl introspection API.
//!
//! Rust rewrite of `lib/easyoptions.c` and `lib/easygetopt.c`. Provides the
//! complete table of all `CURLoption` values with their names, numeric IDs,
//! types, and flags. Supports lookup by name (case-insensitive binary search),
//! by ID (linear scan skipping aliases), and sequential iteration.
//!
//! This module maps to the 3 `CURL_EXTERN` symbols in `include/curl/options.h`:
//! - `curl_easy_option_by_name`
//! - `curl_easy_option_by_id`
//! - `curl_easy_option_next`

// ---------------------------------------------------------------------------
// Flag constants
// ---------------------------------------------------------------------------

/// Flag indicating that an option entry is an alias for another option name.
/// Alias entries are skipped during `option_by_id` lookups so that only the
/// canonical name is returned. Matches the C `CURLOT_FLAG_ALIAS` constant
/// `(1 << 0)`.
pub const CURLOT_FLAG_ALIAS: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// OptionType enum
// ---------------------------------------------------------------------------

/// Classification of a curl easy option's value type, matching the C
/// `curl_easytype` enum. The discriminant values are identical to the C
/// integer constants for FFI compatibility.
///
/// Variant ordering and values:
/// - `Long`          = 0  (`CURLOT_LONG`)
/// - `Values`        = 1  (`CURLOT_VALUES`)
/// - `OffT`          = 2  (`CURLOT_OFF_T`)
/// - `ObjectPoint`   = 3  (`CURLOT_OBJECT`)
/// - `StringPoint`   = 4  (`CURLOT_STRING`)
/// - `SList`         = 5  (`CURLOT_SLIST`)
/// - `CbPoint`       = 6  (`CURLOT_CBPTR`)
/// - `Blob`          = 7  (`CURLOT_BLOB`)
/// - `FunctionPoint` = 8  (`CURLOT_FUNCTION`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum OptionType {
    /// `CURLOT_LONG` — a `long` value (or range of values).
    Long = 0,
    /// `CURLOT_VALUES` — a defined set or bitmask stored as `long`.
    Values = 1,
    /// `CURLOT_OFF_T` — a `curl_off_t` (64-bit offset) value.
    OffT = 2,
    /// `CURLOT_OBJECT` — an opaque `void *` pointer.
    ObjectPoint = 3,
    /// `CURLOT_STRING` — a null-terminated `char *` string.
    StringPoint = 4,
    /// `CURLOT_SLIST` — a `struct curl_slist *` linked list.
    SList = 5,
    /// `CURLOT_CBPTR` — a `void *` passed as-is to a callback.
    CbPoint = 6,
    /// `CURLOT_BLOB` — a `struct curl_blob *`.
    Blob = 7,
    /// `CURLOT_FUNCTION` — a function pointer.
    FunctionPoint = 8,
}

// ---------------------------------------------------------------------------
// CurlOption struct
// ---------------------------------------------------------------------------

/// Metadata describing a single `curl_easy_setopt` option.
///
/// Each entry in the [`OPTIONS`] table corresponds to one curl option name
/// together with its numeric `CURLoption` ID, its value type, and any flags
/// (currently only [`CURLOT_FLAG_ALIAS`]).
///
/// This struct mirrors the C `struct curl_easyoption` from
/// `include/curl/options.h`.
#[derive(Debug, Clone, Copy)]
pub struct CurlOption {
    /// The option name without the `CURLOPT_` prefix (e.g. `"URL"`).
    pub name: &'static str,
    /// The numeric `CURLoption` ID as defined in `include/curl/curl.h`.
    /// Computed as `CURLOPTTYPE_<base> + <number>`.
    pub id: u32,
    /// The type classification of the option's value.
    pub option_type: OptionType,
    /// Bit-flags — currently only [`CURLOT_FLAG_ALIAS`] is defined.
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// Static option table — sorted alphabetically by name for binary search
// ---------------------------------------------------------------------------

/// Complete table of all curl easy options, sorted alphabetically by name.
///
/// This table is the Rust equivalent of the C `Curl_easyopts[]` array in
/// `lib/easyoptions.c`. It contains 323 entries (including alias entries)
/// covering every `CURLoption` value defined in curl 8.19.0-DEV.
///
/// The table is sorted by name to enable O(log n) lookup via binary search
/// in [`option_by_name`].
pub static OPTIONS: &[CurlOption] = &[
    CurlOption { name: "ABSTRACT_UNIX_SOCKET", id: 10264, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "ACCEPTTIMEOUT_MS", id: 212, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "ACCEPT_ENCODING", id: 10102, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "ADDRESS_SCOPE", id: 171, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "ALTSVC", id: 10287, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "ALTSVC_CTRL", id: 286, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "APPEND", id: 50, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "AUTOREFERER", id: 58, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "AWS_SIGV4", id: 10305, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "BUFFERSIZE", id: 98, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "CAINFO", id: 10065, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "CAINFO_BLOB", id: 40309, option_type: OptionType::Blob, flags: 0 },
    CurlOption { name: "CAPATH", id: 10097, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "CA_CACHE_TIMEOUT", id: 321, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "CERTINFO", id: 172, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "CHUNK_BGN_FUNCTION", id: 20198, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "CHUNK_DATA", id: 10201, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "CHUNK_END_FUNCTION", id: 20199, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "CLOSESOCKETDATA", id: 10209, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "CLOSESOCKETFUNCTION", id: 20208, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "CONNECTTIMEOUT", id: 78, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "CONNECTTIMEOUT_MS", id: 156, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "CONNECT_ONLY", id: 141, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "CONNECT_TO", id: 10243, option_type: OptionType::SList, flags: 0 },
    CurlOption { name: "CONV_FROM_NETWORK_FUNCTION", id: 20142, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "CONV_FROM_UTF8_FUNCTION", id: 20144, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "CONV_TO_NETWORK_FUNCTION", id: 20143, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "COOKIE", id: 10022, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "COOKIEFILE", id: 10031, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "COOKIEJAR", id: 10082, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "COOKIELIST", id: 10135, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "COOKIESESSION", id: 96, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "COPYPOSTFIELDS", id: 10165, option_type: OptionType::ObjectPoint, flags: 0 },
    CurlOption { name: "CRLF", id: 27, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "CRLFILE", id: 10169, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "CURLU", id: 10282, option_type: OptionType::ObjectPoint, flags: 0 },
    CurlOption { name: "CUSTOMREQUEST", id: 10036, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "DEBUGDATA", id: 10095, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "DEBUGFUNCTION", id: 20094, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "DEFAULT_PROTOCOL", id: 10238, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "DIRLISTONLY", id: 48, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "DISALLOW_USERNAME_IN_URL", id: 278, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "DNS_CACHE_TIMEOUT", id: 92, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "DNS_INTERFACE", id: 10221, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "DNS_LOCAL_IP4", id: 10222, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "DNS_LOCAL_IP6", id: 10223, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "DNS_SERVERS", id: 10211, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "DNS_SHUFFLE_ADDRESSES", id: 275, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "DNS_USE_GLOBAL_CACHE", id: 91, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "DOH_SSL_VERIFYHOST", id: 307, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "DOH_SSL_VERIFYPEER", id: 306, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "DOH_SSL_VERIFYSTATUS", id: 308, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "DOH_URL", id: 10279, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "ECH", id: 10325, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "EGDSOCKET", id: 10077, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "ENCODING", id: 10102, option_type: OptionType::StringPoint, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "ERRORBUFFER", id: 10010, option_type: OptionType::ObjectPoint, flags: 0 },
    CurlOption { name: "EXPECT_100_TIMEOUT_MS", id: 227, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "FAILONERROR", id: 45, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "FILE", id: 10001, option_type: OptionType::CbPoint, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "FILETIME", id: 69, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "FNMATCH_DATA", id: 10202, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "FNMATCH_FUNCTION", id: 20200, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "FOLLOWLOCATION", id: 52, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "FORBID_REUSE", id: 75, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "FRESH_CONNECT", id: 74, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "FTPAPPEND", id: 50, option_type: OptionType::Long, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "FTPLISTONLY", id: 48, option_type: OptionType::Long, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "FTPPORT", id: 10017, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "FTPSSLAUTH", id: 129, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "FTP_ACCOUNT", id: 10134, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "FTP_ALTERNATIVE_TO_USER", id: 10147, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "FTP_CREATE_MISSING_DIRS", id: 110, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "FTP_FILEMETHOD", id: 138, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "FTP_RESPONSE_TIMEOUT", id: 112, option_type: OptionType::Long, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "FTP_SKIP_PASV_IP", id: 137, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "FTP_SSL", id: 119, option_type: OptionType::Values, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "FTP_SSL_CCC", id: 154, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "FTP_USE_EPRT", id: 106, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "FTP_USE_EPSV", id: 85, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "FTP_USE_PRET", id: 188, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "GSSAPI_DELEGATION", id: 210, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "HAPPY_EYEBALLS_TIMEOUT_MS", id: 271, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "HAPROXYPROTOCOL", id: 274, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "HAPROXY_CLIENT_IP", id: 10323, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "HEADER", id: 42, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "HEADERDATA", id: 10029, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "HEADERFUNCTION", id: 20079, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "HEADEROPT", id: 229, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "HSTS", id: 10300, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "HSTSREADDATA", id: 10302, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "HSTSREADFUNCTION", id: 20301, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "HSTSWRITEDATA", id: 10304, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "HSTSWRITEFUNCTION", id: 20303, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "HSTS_CTRL", id: 299, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "HTTP09_ALLOWED", id: 285, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "HTTP200ALIASES", id: 10104, option_type: OptionType::SList, flags: 0 },
    CurlOption { name: "HTTPAUTH", id: 107, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "HTTPGET", id: 80, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "HTTPHEADER", id: 10023, option_type: OptionType::SList, flags: 0 },
    CurlOption { name: "HTTPPOST", id: 10024, option_type: OptionType::ObjectPoint, flags: 0 },
    CurlOption { name: "HTTPPROXYTUNNEL", id: 61, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "HTTP_CONTENT_DECODING", id: 158, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "HTTP_TRANSFER_DECODING", id: 157, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "HTTP_VERSION", id: 84, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "IGNORE_CONTENT_LENGTH", id: 136, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "INFILE", id: 10009, option_type: OptionType::CbPoint, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "INFILESIZE", id: 14, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "INFILESIZE_LARGE", id: 30115, option_type: OptionType::OffT, flags: 0 },
    CurlOption { name: "INTERFACE", id: 10062, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "INTERLEAVEDATA", id: 10195, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "INTERLEAVEFUNCTION", id: 20196, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "IOCTLDATA", id: 10131, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "IOCTLFUNCTION", id: 20130, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "IPRESOLVE", id: 113, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "ISSUERCERT", id: 10170, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "ISSUERCERT_BLOB", id: 40295, option_type: OptionType::Blob, flags: 0 },
    CurlOption { name: "KEEP_SENDING_ON_ERROR", id: 245, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "KEYPASSWD", id: 10026, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "KRB4LEVEL", id: 10063, option_type: OptionType::StringPoint, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "KRBLEVEL", id: 10063, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "LOCALPORT", id: 139, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "LOCALPORTRANGE", id: 140, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "LOGIN_OPTIONS", id: 10224, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "LOW_SPEED_LIMIT", id: 19, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "LOW_SPEED_TIME", id: 20, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "MAIL_AUTH", id: 10217, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "MAIL_FROM", id: 10186, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "MAIL_RCPT", id: 10187, option_type: OptionType::SList, flags: 0 },
    CurlOption { name: "MAIL_RCPT_ALLLOWFAILS", id: 290, option_type: OptionType::Long, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "MAIL_RCPT_ALLOWFAILS", id: 290, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "MAXAGE_CONN", id: 288, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "MAXCONNECTS", id: 71, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "MAXFILESIZE", id: 114, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "MAXFILESIZE_LARGE", id: 30117, option_type: OptionType::OffT, flags: 0 },
    CurlOption { name: "MAXLIFETIME_CONN", id: 314, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "MAXREDIRS", id: 68, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "MAX_RECV_SPEED_LARGE", id: 30146, option_type: OptionType::OffT, flags: 0 },
    CurlOption { name: "MAX_SEND_SPEED_LARGE", id: 30145, option_type: OptionType::OffT, flags: 0 },
    CurlOption { name: "MIMEPOST", id: 10269, option_type: OptionType::ObjectPoint, flags: 0 },
    CurlOption { name: "MIME_OPTIONS", id: 315, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "NETRC", id: 51, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "NETRC_FILE", id: 10118, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "NEW_DIRECTORY_PERMS", id: 160, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "NEW_FILE_PERMS", id: 159, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "NOBODY", id: 44, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "NOPROGRESS", id: 43, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "NOPROXY", id: 10177, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "NOSIGNAL", id: 99, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "OPENSOCKETDATA", id: 10164, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "OPENSOCKETFUNCTION", id: 20163, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "PASSWORD", id: 10174, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PATH_AS_IS", id: 234, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "PINNEDPUBLICKEY", id: 10230, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PIPEWAIT", id: 237, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "PORT", id: 3, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "POST", id: 47, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "POST301", id: 161, option_type: OptionType::Values, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "POSTFIELDS", id: 10015, option_type: OptionType::ObjectPoint, flags: 0 },
    CurlOption { name: "POSTFIELDSIZE", id: 60, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "POSTFIELDSIZE_LARGE", id: 30120, option_type: OptionType::OffT, flags: 0 },
    CurlOption { name: "POSTQUOTE", id: 10039, option_type: OptionType::SList, flags: 0 },
    CurlOption { name: "POSTREDIR", id: 161, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "PREQUOTE", id: 10093, option_type: OptionType::SList, flags: 0 },
    CurlOption { name: "PREREQDATA", id: 10313, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "PREREQFUNCTION", id: 20312, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "PRE_PROXY", id: 10262, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PRIVATE", id: 10103, option_type: OptionType::ObjectPoint, flags: 0 },
    CurlOption { name: "PROGRESSDATA", id: 10057, option_type: OptionType::CbPoint, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "PROGRESSFUNCTION", id: 20056, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "PROTOCOLS", id: 181, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "PROTOCOLS_STR", id: 10318, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY", id: 10004, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXYAUTH", id: 111, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "PROXYHEADER", id: 10228, option_type: OptionType::SList, flags: 0 },
    CurlOption { name: "PROXYPASSWORD", id: 10176, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXYPORT", id: 59, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "PROXYTYPE", id: 101, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "PROXYUSERNAME", id: 10175, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXYUSERPWD", id: 10006, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_CAINFO", id: 10246, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_CAINFO_BLOB", id: 40310, option_type: OptionType::Blob, flags: 0 },
    CurlOption { name: "PROXY_CAPATH", id: 10247, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_CRLFILE", id: 10260, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_ISSUERCERT", id: 10296, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_ISSUERCERT_BLOB", id: 40297, option_type: OptionType::Blob, flags: 0 },
    CurlOption { name: "PROXY_KEYPASSWD", id: 10258, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_PINNEDPUBLICKEY", id: 10263, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_SERVICE_NAME", id: 10235, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_SSLCERT", id: 10254, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_SSLCERTTYPE", id: 10255, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_SSLCERT_BLOB", id: 40293, option_type: OptionType::Blob, flags: 0 },
    CurlOption { name: "PROXY_SSLKEY", id: 10256, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_SSLKEYTYPE", id: 10257, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_SSLKEY_BLOB", id: 40294, option_type: OptionType::Blob, flags: 0 },
    CurlOption { name: "PROXY_SSLVERSION", id: 250, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "PROXY_SSL_CIPHER_LIST", id: 10259, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_SSL_OPTIONS", id: 261, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "PROXY_SSL_VERIFYHOST", id: 249, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "PROXY_SSL_VERIFYPEER", id: 248, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "PROXY_TLS13_CIPHERS", id: 10277, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_TLSAUTH_PASSWORD", id: 10252, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_TLSAUTH_TYPE", id: 10253, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_TLSAUTH_USERNAME", id: 10251, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "PROXY_TRANSFER_MODE", id: 166, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "PUT", id: 54, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "QUICK_EXIT", id: 322, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "QUOTE", id: 10028, option_type: OptionType::SList, flags: 0 },
    CurlOption { name: "RANDOM_FILE", id: 10076, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "RANGE", id: 10007, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "READDATA", id: 10009, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "READFUNCTION", id: 20012, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "REDIR_PROTOCOLS", id: 182, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "REDIR_PROTOCOLS_STR", id: 10319, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "REFERER", id: 10016, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "REQUEST_TARGET", id: 10266, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "RESOLVE", id: 10203, option_type: OptionType::SList, flags: 0 },
    CurlOption { name: "RESOLVER_START_DATA", id: 10273, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "RESOLVER_START_FUNCTION", id: 20272, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "RESUME_FROM", id: 21, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "RESUME_FROM_LARGE", id: 30116, option_type: OptionType::OffT, flags: 0 },
    CurlOption { name: "RTSPHEADER", id: 10023, option_type: OptionType::SList, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "RTSP_CLIENT_CSEQ", id: 193, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "RTSP_REQUEST", id: 189, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "RTSP_SERVER_CSEQ", id: 194, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "RTSP_SESSION_ID", id: 10190, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "RTSP_STREAM_URI", id: 10191, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "RTSP_TRANSPORT", id: 10192, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SASL_AUTHZID", id: 10289, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SASL_IR", id: 218, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SEEKDATA", id: 10168, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "SEEKFUNCTION", id: 20167, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "SERVER_RESPONSE_TIMEOUT", id: 112, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SERVER_RESPONSE_TIMEOUT_MS", id: 324, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SERVICE_NAME", id: 10236, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SHARE", id: 10100, option_type: OptionType::ObjectPoint, flags: 0 },
    CurlOption { name: "SOCKOPTDATA", id: 10149, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "SOCKOPTFUNCTION", id: 20148, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "SOCKS5_AUTH", id: 267, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SOCKS5_GSSAPI_NEC", id: 180, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SOCKS5_GSSAPI_SERVICE", id: 10179, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSH_AUTH_TYPES", id: 151, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "SSH_COMPRESSION", id: 268, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SSH_HOSTKEYDATA", id: 10317, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "SSH_HOSTKEYFUNCTION", id: 20316, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "SSH_HOST_PUBLIC_KEY_MD5", id: 10162, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSH_HOST_PUBLIC_KEY_SHA256", id: 10311, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSH_KEYDATA", id: 10185, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "SSH_KEYFUNCTION", id: 20184, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "SSH_KNOWNHOSTS", id: 10183, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSH_PRIVATE_KEYFILE", id: 10153, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSH_PUBLIC_KEYFILE", id: 10152, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSLCERT", id: 10025, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSLCERTPASSWD", id: 10026, option_type: OptionType::StringPoint, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "SSLCERTTYPE", id: 10086, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSLCERT_BLOB", id: 40291, option_type: OptionType::Blob, flags: 0 },
    CurlOption { name: "SSLENGINE", id: 10089, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSLENGINE_DEFAULT", id: 90, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SSLKEY", id: 10087, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSLKEYPASSWD", id: 10026, option_type: OptionType::StringPoint, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "SSLKEYTYPE", id: 10088, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSLKEY_BLOB", id: 40292, option_type: OptionType::Blob, flags: 0 },
    CurlOption { name: "SSLVERSION", id: 32, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "SSL_CIPHER_LIST", id: 10083, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSL_CTX_DATA", id: 10109, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "SSL_CTX_FUNCTION", id: 20108, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "SSL_EC_CURVES", id: 10298, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSL_ENABLE_ALPN", id: 226, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SSL_ENABLE_NPN", id: 225, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SSL_FALSESTART", id: 233, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SSL_OPTIONS", id: 216, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "SSL_SESSIONID_CACHE", id: 150, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SSL_SIGNATURE_ALGORITHMS", id: 10328, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "SSL_VERIFYHOST", id: 81, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SSL_VERIFYPEER", id: 64, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SSL_VERIFYSTATUS", id: 232, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "STDERR", id: 10037, option_type: OptionType::ObjectPoint, flags: 0 },
    CurlOption { name: "STREAM_DEPENDS", id: 10240, option_type: OptionType::ObjectPoint, flags: 0 },
    CurlOption { name: "STREAM_DEPENDS_E", id: 10241, option_type: OptionType::ObjectPoint, flags: 0 },
    CurlOption { name: "STREAM_WEIGHT", id: 239, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "SUPPRESS_CONNECT_HEADERS", id: 265, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "TCP_FASTOPEN", id: 244, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "TCP_KEEPALIVE", id: 213, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "TCP_KEEPCNT", id: 326, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "TCP_KEEPIDLE", id: 214, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "TCP_KEEPINTVL", id: 215, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "TCP_NODELAY", id: 121, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "TELNETOPTIONS", id: 10070, option_type: OptionType::SList, flags: 0 },
    CurlOption { name: "TFTP_BLKSIZE", id: 178, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "TFTP_NO_OPTIONS", id: 242, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "TIMECONDITION", id: 33, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "TIMEOUT", id: 13, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "TIMEOUT_MS", id: 155, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "TIMEVALUE", id: 34, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "TIMEVALUE_LARGE", id: 30270, option_type: OptionType::OffT, flags: 0 },
    CurlOption { name: "TLS13_CIPHERS", id: 10276, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "TLSAUTH_PASSWORD", id: 10205, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "TLSAUTH_TYPE", id: 10206, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "TLSAUTH_USERNAME", id: 10204, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "TRAILERDATA", id: 10284, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "TRAILERFUNCTION", id: 20283, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "TRANSFERTEXT", id: 53, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "TRANSFER_ENCODING", id: 207, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "UNIX_SOCKET_PATH", id: 10231, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "UNRESTRICTED_AUTH", id: 105, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "UPKEEP_INTERVAL_MS", id: 281, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "UPLOAD", id: 46, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "UPLOAD_BUFFERSIZE", id: 280, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "UPLOAD_FLAGS", id: 327, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "URL", id: 10002, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "USERAGENT", id: 10018, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "USERNAME", id: 10173, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "USERPWD", id: 10005, option_type: OptionType::StringPoint, flags: 0 },
    CurlOption { name: "USE_SSL", id: 119, option_type: OptionType::Values, flags: 0 },
    CurlOption { name: "VERBOSE", id: 41, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "WILDCARDMATCH", id: 197, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "WRITEDATA", id: 10001, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "WRITEFUNCTION", id: 20011, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "WRITEHEADER", id: 10029, option_type: OptionType::CbPoint, flags: CURLOT_FLAG_ALIAS },
    CurlOption { name: "WS_OPTIONS", id: 320, option_type: OptionType::Long, flags: 0 },
    CurlOption { name: "XFERINFODATA", id: 10057, option_type: OptionType::CbPoint, flags: 0 },
    CurlOption { name: "XFERINFOFUNCTION", id: 20219, option_type: OptionType::FunctionPoint, flags: 0 },
    CurlOption { name: "XOAUTH2_BEARER", id: 10220, option_type: OptionType::StringPoint, flags: 0 },
];

// ---------------------------------------------------------------------------
// Lookup API
// ---------------------------------------------------------------------------

/// Look up an option by its name (case-insensitive binary search).
///
/// The `name` parameter is the option name without the `CURLOPT_` prefix.
/// Comparison is case-insensitive so `"url"`, `"URL"`, and `"Url"` all match
/// the `URL` entry.
///
/// Returns `Some(&CurlOption)` if found, `None` otherwise.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::options::option_by_name;
///
/// let opt = option_by_name("URL").unwrap();
/// assert_eq!(opt.id, 10002);
///
/// // Case-insensitive
/// let opt2 = option_by_name("url").unwrap();
/// assert_eq!(opt2.id, 10002);
/// ```
pub fn option_by_name(name: &str) -> Option<&'static CurlOption> {
    // All names in OPTIONS are uppercase ASCII. Convert the search key to
    // uppercase for a standard binary search comparison.
    let upper: String = name
        .chars()
        .map(|c| c.to_ascii_uppercase())
        .collect();

    OPTIONS
        .binary_search_by(|opt| opt.name.cmp(upper.as_str()))
        .ok()
        .map(|idx| &OPTIONS[idx])
}

/// Look up the canonical (non-alias) option entry by its numeric
/// `CURLoption` ID.
///
/// Alias entries (those with [`CURLOT_FLAG_ALIAS`] set) are skipped so that
/// the returned entry is always the canonical name for the given ID.
///
/// Returns `Some(&CurlOption)` if a non-alias entry with the given ID exists,
/// `None` otherwise.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::options::{option_by_id, OptionType};
///
/// let opt = option_by_id(10002).unwrap();
/// assert_eq!(opt.name, "URL");
/// assert_eq!(opt.option_type, OptionType::StringPoint);
/// ```
pub fn option_by_id(id: u32) -> Option<&'static CurlOption> {
    OPTIONS.iter().find(|opt| opt.id == id && (opt.flags & CURLOT_FLAG_ALIAS) == 0)
}

/// Iterate over all option entries sequentially.
///
/// Pass `None` to get the first entry. Pass `Some(prev)` where `prev` is a
/// reference previously returned by this function (or by [`option_by_name`] /
/// [`option_by_id`]) to get the next entry.
///
/// Returns `None` when iteration is complete (after the last entry).
///
/// # Examples
///
/// ```
/// use curl_rs_lib::options::option_next;
///
/// let mut count = 0;
/// let mut current = option_next(None);
/// while let Some(opt) = current {
///     count += 1;
///     current = option_next(Some(opt));
/// }
/// assert!(count > 300);
/// ```
pub fn option_next(prev: Option<&CurlOption>) -> Option<&'static CurlOption> {
    match prev {
        None => OPTIONS.first(),
        Some(p) => {
            // Locate `prev` in the static OPTIONS slice by pointer identity.
            // This is safe — std::ptr::eq compares raw addresses without
            // dereferencing anything extra.
            let idx = OPTIONS
                .iter()
                .position(|opt| std::ptr::eq(opt, p));
            match idx {
                Some(i) if i + 1 < OPTIONS.len() => Some(&OPTIONS[i + 1]),
                _ => None,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_by_name() {
        for window in OPTIONS.windows(2) {
            assert!(
                window[0].name <= window[1].name,
                "OPTIONS table is not sorted: {} > {}",
                window[0].name,
                window[1].name,
            );
        }
    }

    #[test]
    fn option_type_discriminants_match_c() {
        assert_eq!(OptionType::Long as u32, 0);
        assert_eq!(OptionType::Values as u32, 1);
        assert_eq!(OptionType::OffT as u32, 2);
        assert_eq!(OptionType::ObjectPoint as u32, 3);
        assert_eq!(OptionType::StringPoint as u32, 4);
        assert_eq!(OptionType::SList as u32, 5);
        assert_eq!(OptionType::CbPoint as u32, 6);
        assert_eq!(OptionType::Blob as u32, 7);
        assert_eq!(OptionType::FunctionPoint as u32, 8);
    }

    #[test]
    fn flag_alias_value() {
        assert_eq!(CURLOT_FLAG_ALIAS, 1);
    }

    #[test]
    fn lookup_url_by_name() {
        let opt = option_by_name("URL").expect("URL should exist");
        assert_eq!(opt.name, "URL");
        assert_eq!(opt.id, 10002);
        assert_eq!(opt.option_type, OptionType::StringPoint);
        assert_eq!(opt.flags, 0);
    }

    #[test]
    fn lookup_by_name_case_insensitive() {
        let opt = option_by_name("url").expect("url (lowercase) should match URL");
        assert_eq!(opt.name, "URL");
        assert_eq!(opt.id, 10002);
    }

    #[test]
    fn lookup_by_name_nonexistent() {
        assert!(option_by_name("DOES_NOT_EXIST").is_none());
    }

    #[test]
    fn lookup_verbose_by_id() {
        let opt = option_by_id(41).expect("VERBOSE (id 41) should exist");
        assert_eq!(opt.name, "VERBOSE");
        assert_eq!(opt.option_type, OptionType::Long);
    }

    #[test]
    fn lookup_by_id_returns_canonical() {
        // CURLOPT_ACCEPT_ENCODING (id 10002 is URL, let us use a known alias)
        // "ENCODING" is an alias for ACCEPT_ENCODING (id 10102)
        let opt = option_by_id(10102).expect("ACCEPT_ENCODING should exist by id");
        assert_eq!(opt.name, "ACCEPT_ENCODING");
        assert_eq!(opt.flags & CURLOT_FLAG_ALIAS, 0);
    }

    #[test]
    fn lookup_by_id_nonexistent() {
        assert!(option_by_id(99999).is_none());
    }

    #[test]
    fn iterate_all_options() {
        let mut count = 0usize;
        let mut current = option_next(None);
        while let Some(opt) = current {
            count += 1;
            // Sanity: name should be non-empty and ASCII uppercase
            assert!(!opt.name.is_empty());
            current = option_next(Some(opt));
        }
        // Must have all 323 entries
        assert_eq!(count, OPTIONS.len());
        assert_eq!(count, 323);
    }

    #[test]
    fn iterate_first_entry() {
        let first = option_next(None).expect("first entry should exist");
        assert_eq!(first.name, "ABSTRACT_UNIX_SOCKET");
    }

    #[test]
    fn iterate_last_entry() {
        let last = &OPTIONS[OPTIONS.len() - 1];
        assert_eq!(last.name, "XOAUTH2_BEARER");
        assert!(option_next(Some(last)).is_none());
    }

    #[test]
    fn alias_entries_have_flag() {
        // "ENCODING" is an alias for ACCEPT_ENCODING
        let opt = option_by_name("ENCODING").expect("ENCODING alias should exist");
        assert_ne!(opt.flags & CURLOT_FLAG_ALIAS, 0);
    }

    #[test]
    fn all_off_t_options_present() {
        let off_t_names = [
            "INFILESIZE_LARGE",
            "RESUME_FROM_LARGE",
            "MAXFILESIZE_LARGE",
            "POSTFIELDSIZE_LARGE",
            "MAX_SEND_SPEED_LARGE",
            "MAX_RECV_SPEED_LARGE",
            "TIMEVALUE_LARGE",
        ];
        for name in &off_t_names {
            let opt = option_by_name(name)
                .unwrap_or_else(|| panic!("{name} should be in OPTIONS"));
            assert_eq!(opt.option_type, OptionType::OffT, "{name} should be OffT");
        }
    }

    #[test]
    fn specific_id_values() {
        // Verify a sample of well-known option IDs match curl 8.x exactly.
        let checks: &[(&str, u32)] = &[
            ("WRITEDATA", 10001),
            ("URL", 10002),
            ("PORT", 3),
            ("VERBOSE", 41),
            ("HEADER", 42),
            ("NOBODY", 44),
            ("UPLOAD", 46),
            ("POST", 47),
            ("TIMEOUT", 13),
            ("FOLLOWLOCATION", 52),
            ("SSL_VERIFYPEER", 64),
            ("CAINFO", 10065),
            ("WRITEFUNCTION", 20011),
            ("READFUNCTION", 20012),
            ("HTTPHEADER", 10023),
            ("INFILESIZE_LARGE", 30115),
            ("SSLCERT_BLOB", 40291),
        ];
        for &(name, expected_id) in checks {
            let opt = option_by_name(name)
                .unwrap_or_else(|| panic!("{name} should be in OPTIONS"));
            assert_eq!(
                opt.id, expected_id,
                "{name}: expected id {expected_id}, got {}",
                opt.id
            );
        }
    }
}
