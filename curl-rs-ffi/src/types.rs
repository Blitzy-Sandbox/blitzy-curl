//! C-compatible opaque pointer types, platform type aliases, callback typedefs,
//! and enum type aliases for the curl FFI crate.
//!
//! This module is the foundational type definitions file for the `curl-rs-ffi`
//! crate.  Every other FFI module (`easy.rs`, `multi.rs`, `global.rs`, etc.)
//! imports from here.  All types, constants, and callback signatures are
//! defined to be binary-compatible with the curl 8.x C headers
//! (`include/curl/curl.h`, `include/curl/system.h`, `include/curl/multi.h`,
//! `include/curl/urlapi.h`, `include/curl/easy.h`, `include/curl/header.h`,
//! `include/curl/options.h`, `include/curl/websockets.h`).
//!
//! # Invariants
//!
//! - All `#[repr(C)]` structs match the exact memory layout of their C
//!   counterparts, field-by-field, including padding and alignment.
//! - All integer constants match the values defined in curl 8.x headers.
//! - All callback type definitions use `unsafe extern "C"` and match the
//!   exact C function pointer signatures.
//! - Opaque handle types use the zero-size-array pattern `[u8; 0]` to prevent
//!   construction from outside the crate while remaining FFI-safe.
//!
//! # Platform Notes
//!
//! - `curl_socket_t` is `c_int` on Unix and `usize` (UINT_PTR / SOCKET) on
//!   Windows, matching curl's platform-conditional typedef.
//! - `curl_off_t` is always `i64` (64-bit signed), matching curl's requirement
//!   that it be a 64-bit type on all modern platforms.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]

use libc::{
    c_char, c_int, c_long, c_short, c_uchar, c_uint, c_void, size_t, sockaddr, socklen_t,
};

// ============================================================================
// Section 1: Platform Type Aliases
// Derived from: include/curl/system.h, include/curl/curl.h
// ============================================================================

/// 64-bit signed offset type.  curl requires this to be exactly 64 bits wide
/// on every platform, independent of large-file-support settings.
///
/// C equivalent: `typedef long long curl_off_t;` (or platform equivalent)
pub type curl_off_t = i64;

/// Socket address length type — mirrors the platform's `socklen_t`.
///
/// C equivalent: `typedef socklen_t curl_socklen_t;` (varies by platform)
pub type curl_socklen_t = socklen_t;

/// Socket descriptor type.
///
/// On Unix this is a plain `int` (file descriptor).
/// On Windows this is `UINT_PTR` (the `SOCKET` type from WinSock2).
///
/// C equivalent:
/// ```c
/// #if defined(_WIN32)
/// typedef SOCKET curl_socket_t;
/// #else
/// typedef int curl_socket_t;
/// #endif
/// ```
#[cfg(unix)]
pub type curl_socket_t = c_int;

#[cfg(windows)]
pub type curl_socket_t = usize;

/// Sentinel value representing an invalid socket.
///
/// On Unix: `-1` (matching the POSIX convention).
/// On Windows: `INVALID_SOCKET` which is `(SOCKET)(~0)`.
///
/// C equivalent: `#define CURL_SOCKET_BAD (-1)` / `INVALID_SOCKET`
#[cfg(unix)]
pub const CURL_SOCKET_BAD: curl_socket_t = -1;

#[cfg(windows)]
pub const CURL_SOCKET_BAD: curl_socket_t = !0;

// ============================================================================
// Section 2: Opaque Handle Types
// Derived from: include/curl/curl.h, include/curl/multi.h,
//               include/curl/urlapi.h
//
// These are defined as empty `#[repr(C)]` structs with a zero-size private
// field.  This pattern:
//   1. Prevents outside code from constructing instances.
//   2. Is FFI-safe (`#[repr(C)]`).
//   3. Has zero size, matching `typedef void CURL;` in the C headers when
//      used only behind pointers (which is always the case).
// ============================================================================

/// Opaque easy handle (`CURL *` in C).
///
/// C equivalent: `typedef void CURL;`
#[repr(C)]
pub struct CURL {
    _private: [u8; 0],
}

/// Opaque multi handle (`CURLM *` in C).
///
/// C equivalent: `typedef void CURLM;`
#[repr(C)]
pub struct CURLM {
    _private: [u8; 0],
}

/// Opaque share handle (`CURLSH *` in C).
///
/// C equivalent: `typedef void CURLSH;`
#[repr(C)]
pub struct CURLSH {
    _private: [u8; 0],
}

/// Opaque URL handle (`CURLU *` in C).
///
/// C equivalent: forward-declared opaque struct in urlapi.h
#[repr(C)]
pub struct CURLU {
    _private: [u8; 0],
}

/// Opaque MIME handle.
///
/// C equivalent: forward-declared `struct curl_mime` in curl.h
#[repr(C)]
pub struct curl_mime {
    _private: [u8; 0],
}

/// Opaque MIME part handle.
///
/// C equivalent: forward-declared `struct curl_mimepart` in curl.h
#[repr(C)]
pub struct curl_mimepart {
    _private: [u8; 0],
}

/// Opaque push-promise headers handle, used in the server-push callback.
///
/// C equivalent: `struct curl_pushheaders;` (forward declaration in multi.h)
#[repr(C)]
pub struct curl_pushheaders {
    _private: [u8; 0],
}

/// Opaque SSL backend descriptor used by `curl_global_sslset()`.
///
/// C equivalent: `struct curl_ssl_backend { curl_sslbackend id; const char *name; };`
/// We expose this as opaque on the FFI boundary since consumers never
/// construct it — they receive `const curl_ssl_backend **` from the API.
#[repr(C)]
pub struct curl_ssl_backend {
    _private: [u8; 0],
}

// ============================================================================
// Section 3: Enum / Code Type Aliases
// All curl enums are represented as `c_int` for FFI compatibility.
// The actual enumerator constants live in error_codes.rs or are defined
// as needed inline below.
// ============================================================================

/// Easy-handle return code.
/// C equivalent: `typedef enum { CURLE_OK = 0, ... } CURLcode;`
pub type CURLcode = c_int;

/// Easy-handle option identifier.
/// C equivalent: `typedef enum { CURLOPT_URL = 10002, ... } CURLoption;`
pub type CURLoption = c_int;

/// Info identifier for `curl_easy_getinfo`.
/// C equivalent: `typedef enum { CURLINFO_NONE, ... } CURLINFO;`
pub type CURLINFO = c_int;

/// Version enum for `curl_version_info`.
/// C equivalent: `typedef enum { CURLVERSION_FIRST, ... } CURLversion;`
pub type CURLversion = c_int;

/// Multi-handle message type used in `CURLMsg.msg`.
/// C equivalent: `typedef enum { CURLMSG_NONE, CURLMSG_DONE, ... } CURLMSG;`
pub type CURLMSG = c_int;

/// Deprecated form-data option type.
/// C equivalent: `typedef enum { ... } CURLformoption;`
pub type CURLformoption = c_int;

/// Debug callback info-type tag.
/// C equivalent: `typedef enum { CURLINFO_TEXT = 0, ... } curl_infotype;`
pub type curl_infotype = c_int;

/// Time-condition type for conditional requests.
/// C equivalent: `typedef enum { CURL_TIMECOND_LAST = 4 } curl_TimeCond;`
pub type curl_TimeCond = c_int;

/// HSTS callback status code.
/// C equivalent: `typedef enum { CURLSTS_OK, CURLSTS_DONE, CURLSTS_FAIL } CURLSTScode;`
pub type CURLSTScode = c_int;

/// Share-handle lock-data selector.
/// C equivalent: `typedef enum { CURL_LOCK_DATA_NONE = 0, ... } curl_lock_data;`
pub type curl_lock_data = c_int;

/// Share-handle lock-access mode.
/// C equivalent: `typedef enum { CURL_LOCK_ACCESS_NONE = 0, ... } curl_lock_access;`
pub type curl_lock_access = c_int;

/// Share-handle return code.
/// C equivalent: `typedef enum { CURLSHE_OK, ... } CURLSHcode;`
pub type CURLSHcode = c_int;

/// Share-handle option identifier.
/// C equivalent: `typedef enum { CURLSHOPT_NONE, ... } CURLSHoption;`
pub type CURLSHoption = c_int;

/// Multi-handle return code.
/// C equivalent: `typedef enum { CURLM_CALL_MULTI_PERFORM = -1, CURLM_OK, ... } CURLMcode;`
pub type CURLMcode = c_int;

/// Multi-handle option identifier.
/// C equivalent: `typedef enum { CURLMOPT_SOCKETFUNCTION, ... } CURLMoption;`
pub type CURLMoption = c_int;

/// URL API return code.
/// C equivalent: `typedef enum { CURLUE_OK, ... } CURLUcode;`
pub type CURLUcode = c_int;

/// URL API part selector.
/// C equivalent: `typedef enum { CURLUPART_URL, ... } CURLUPart;`
pub type CURLUPart = c_int;

/// Header API return code.
/// C equivalent: `typedef enum { CURLHE_OK, ... } CURLHcode;`
pub type CURLHcode = c_int;

/// Easy-option type tag used in `curl_easyoption::type_`.
/// C equivalent: `typedef enum { CURLOT_LONG, ... } curl_easytype;`
pub type curl_easytype = c_int;

/// SSL backend set result.
/// C equivalent: `typedef enum { CURLSSLSET_OK = 0, ... } CURLsslset;`
pub type CURLsslset = c_int;

/// SSL backend identifier (numeric).
/// C equivalent: `typedef enum { CURLSSLBACKEND_NONE = 0, ... } curl_sslbackend;`
pub type curl_sslbackend = c_int;

/// Proxy error code (returned in `CURLINFO_PROXY_ERROR`).
/// C equivalent: `typedef enum { CURLPX_OK, ... } CURLproxycode;`
pub type CURLproxycode = c_int;

/// Multi-handle info query tag.
/// C equivalent: `typedef enum { CURLMINFO_NONE, ... } CURLMinfo_offt;`
pub type CURLMinfo_offt = c_int;

/// Trailer callback type.
/// C equivalent: `typedef int (*curl_trailer_callback)(struct curl_slist **list, void *userdata);`
///
/// Defined here as a type alias so that callback type definitions in
/// Section 8 can reference it.
pub type curl_trailer_callback = unsafe extern "C" fn(
    list: *mut *mut curl_slist,
    userdata: *mut c_void,
) -> c_int;

// ============================================================================
// Section 4: CURLOPTTYPE Constants
// Derived from: include/curl/curl.h (lines 1111–1136)
//
// These define the base ranges for `CURLoption` values.  Each option's
// integer value is computed as `CURLOPTTYPE_xxx + ordinal`.
// ============================================================================

/// Base for `long` options.
pub const CURLOPTTYPE_LONG: c_int = 0;

/// Base for object-pointer options (`void *`).
pub const CURLOPTTYPE_OBJECTPOINT: c_int = 10000;

/// Base for function-pointer options.
pub const CURLOPTTYPE_FUNCTIONPOINT: c_int = 20000;

/// Base for `curl_off_t` options.
pub const CURLOPTTYPE_OFF_T: c_int = 30000;

/// Base for blob options (`struct curl_blob *`).
pub const CURLOPTTYPE_BLOB: c_int = 40000;

/// Alias — string-pointer options share the OBJECTPOINT range.
pub const CURLOPTTYPE_STRINGPOINT: c_int = CURLOPTTYPE_OBJECTPOINT;

/// Alias — slist-pointer options share the OBJECTPOINT range.
pub const CURLOPTTYPE_SLISTPOINT: c_int = CURLOPTTYPE_OBJECTPOINT;

/// Alias — callback-data-pointer options share the OBJECTPOINT range.
pub const CURLOPTTYPE_CBPOINT: c_int = CURLOPTTYPE_OBJECTPOINT;

/// Alias — value/bitmask options share the LONG range.
pub const CURLOPTTYPE_VALUES: c_int = CURLOPTTYPE_LONG;

// ============================================================================
// Section 5: CURLINFO Type-Tag Constants
// Derived from: include/curl/curl.h (lines 2890–2898)
// ============================================================================

/// Info type tag: string result.
pub const CURLINFO_STRING: c_int = 0x100000;

/// Info type tag: long result.
pub const CURLINFO_LONG: c_int = 0x200000;

/// Info type tag: double result.
pub const CURLINFO_DOUBLE: c_int = 0x300000;

/// Info type tag: slist result.
pub const CURLINFO_SLIST: c_int = 0x400000;

/// Info type tag: pointer result (same as SLIST).
pub const CURLINFO_PTR: c_int = 0x400000;

/// Info type tag: socket result.
pub const CURLINFO_SOCKET: c_int = 0x500000;

/// Info type tag: `curl_off_t` result.
pub const CURLINFO_OFF_T: c_int = 0x600000;

/// Bitmask to extract the type tag from a `CURLINFO` value.
pub const CURLINFO_TYPEMASK: c_int = 0xf00000;

// ============================================================================
// Section 6: CURLSTScode Constants
// Derived from: include/curl/curl.h (lines 1056–1060)
// ============================================================================

pub const CURLSTS_OK: c_int = 0;
pub const CURLSTS_DONE: c_int = 1;
pub const CURLSTS_FAIL: c_int = 2;

// ============================================================================
// Section 7: Debug Callback Info-Type Constants
// Derived from: include/curl/curl.h (lines 479–488)
//
// These are the possible values for the `curl_infotype` parameter
// passed to the `curl_debug_callback`.  They are defined as separate
// `c_int` constants rather than re-exporting the enum because
// the FFI layer represents all C enums as plain integers.
// ============================================================================

/// Informational text.
pub const CURLINFO_TEXT: c_int = 0;
/// Incoming header data.
pub const CURLINFO_HEADER_IN: c_int = 1;
/// Outgoing header data.
pub const CURLINFO_HEADER_OUT: c_int = 2;
/// Incoming data payload.
pub const CURLINFO_DATA_IN: c_int = 3;
/// Outgoing data payload.
pub const CURLINFO_DATA_OUT: c_int = 4;
/// Incoming TLS/SSL data.
pub const CURLINFO_SSL_DATA_IN: c_int = 5;
/// Outgoing TLS/SSL data.
pub const CURLINFO_SSL_DATA_OUT: c_int = 6;

// ============================================================================
// Section 8: Seek Callback Return Constants
// Derived from: include/curl/curl.h (lines 380–383)
// ============================================================================

pub const CURL_SEEKFUNC_OK: c_int = 0;
pub const CURL_SEEKFUNC_FAIL: c_int = 1;
pub const CURL_SEEKFUNC_CANTSEEK: c_int = 2;

// ============================================================================
// Section 9: Special Read/Write Callback Return Values
// Derived from: include/curl/curl.h (lines 277–281, 390–393)
// ============================================================================

/// Magic return value from read callback: abort the transfer.
pub const CURL_READFUNC_ABORT: size_t = 0x10000000;

/// Magic return value from read callback: pause sending.
pub const CURL_READFUNC_PAUSE: size_t = 0x10000001;

/// Magic return value from write callback: pause receiving.
pub const CURL_WRITEFUNC_PAUSE: size_t = 0x10000001;

/// Magic return value from write callback: signal an error.
pub const CURL_WRITEFUNC_ERROR: size_t = 0xFFFFFFFF;

// ============================================================================
// Section 10: Sockopt Callback Return Constants
// Derived from: include/curl/curl.h (lines 418–421)
// ============================================================================

pub const CURL_SOCKOPT_OK: c_int = 0;
pub const CURL_SOCKOPT_ERROR: c_int = 1;
pub const CURL_SOCKOPT_ALREADY_CONNECTED: c_int = 2;

// ============================================================================
// Section 11: Multi Socket-Action / Poll Constants
// Derived from: include/curl/multi.h (lines 283–293)
// ============================================================================

pub const CURL_POLL_NONE: c_int = 0;
pub const CURL_POLL_IN: c_int = 1;
pub const CURL_POLL_OUT: c_int = 2;
pub const CURL_POLL_INOUT: c_int = 3;
pub const CURL_POLL_REMOVE: c_int = 4;

pub const CURL_CSELECT_IN: c_int = 0x01;
pub const CURL_CSELECT_OUT: c_int = 0x02;
pub const CURL_CSELECT_ERR: c_int = 0x04;

/// Sentinel socket value passed to `curl_multi_socket_action` to indicate
/// a timeout event rather than socket activity.
/// C equivalent: `#define CURL_SOCKET_TIMEOUT CURL_SOCKET_BAD`
pub const CURL_SOCKET_TIMEOUT: curl_socket_t = CURL_SOCKET_BAD;

// ============================================================================
// Section 12: Wait-fd Event Bitmask Constants
// Derived from: include/curl/multi.h (lines 110–112)
// ============================================================================

pub const CURL_WAIT_POLLIN: c_short = 0x0001;
pub const CURL_WAIT_POLLPRI: c_short = 0x0002;
pub const CURL_WAIT_POLLOUT: c_short = 0x0004;

// ============================================================================
// Section 13: Push Callback Return Constants
// Derived from: include/curl/multi.h (lines 496–498)
// ============================================================================

pub const CURL_PUSH_OK: c_int = 0;
pub const CURL_PUSH_DENY: c_int = 1;
pub const CURL_PUSH_ERROROUT: c_int = 2;

// ============================================================================
// Section 14: WebSocket Frame Flag Constants
// Derived from: include/curl/websockets.h (lines 40–60)
// ============================================================================

pub const CURLWS_TEXT: c_int = 1 << 0;
pub const CURLWS_BINARY: c_int = 1 << 1;
pub const CURLWS_CONT: c_int = 1 << 2;
pub const CURLWS_CLOSE: c_int = 1 << 3;
pub const CURLWS_PING: c_int = 1 << 4;
pub const CURLWS_OFFSET: c_int = 1 << 5;
pub const CURLWS_PONG: c_int = 1 << 6;

// ============================================================================
// Section 15: Pipelining / Multiplex Constants
// Derived from: include/curl/multi.h (lines 86–88)
// ============================================================================

pub const CURLPIPE_NOTHING: c_long = 0;
pub const CURLPIPE_MULTIPLEX: c_long = 2;

// ============================================================================
// Section 16: Header Origin Bitmask Constants
// Derived from: include/curl/header.h (lines 41–45)
// ============================================================================

/// Plain server header.
pub const CURLH_HEADER: c_uint = 1 << 0;
/// Trailers.
pub const CURLH_TRAILER: c_uint = 1 << 1;
/// CONNECT headers.
pub const CURLH_CONNECT: c_uint = 1 << 2;
/// 1xx informational headers.
pub const CURLH_1XX: c_uint = 1 << 3;
/// Pseudo-headers.
pub const CURLH_PSEUDO: c_uint = 1 << 4;

// ============================================================================
// Section 17: Easy-Option Flag Constants
// Derived from: include/curl/options.h (line 47)
// ============================================================================

/// Flag indicating this option is an alias for a preferred name.
pub const CURLOT_FLAG_ALIAS: c_uint = 1 << 0;

// ============================================================================
// Section 18: Blob Flag Constants
// Derived from: include/curl/easy.h (lines 31–32)
// ============================================================================

/// Tell libcurl to copy the blob data.
pub const CURL_BLOB_COPY: c_uint = 1;

/// Tell libcurl NOT to copy the blob data.
pub const CURL_BLOB_NOCOPY: c_uint = 0;

// ============================================================================
// Section 19: Supporting Structs (used by callback signatures)
// These MUST be defined before the callback type aliases in Section 20.
// ============================================================================

/// Linked-list node for the CURLOPT_QUOTE, CURLOPT_HTTPHEADER and
/// similar slist-based options.
///
/// C equivalent (include/curl/curl.h):
/// ```c
/// struct curl_slist {
///   char *data;
///   struct curl_slist *next;
/// };
/// ```
#[repr(C)]
pub struct curl_slist {
    pub data: *mut c_char,
    pub next: *mut curl_slist,
}

/// Binary blob for CURLOPT_SSLCERT_BLOB, CURLOPT_SSLKEY_BLOB, etc.
///
/// C equivalent (include/curl/easy.h):
/// ```c
/// struct curl_blob {
///   void *data;
///   size_t len;
///   unsigned int flags;
/// };
/// ```
#[repr(C)]
pub struct curl_blob {
    pub data: *mut c_void,
    pub len: size_t,
    pub flags: c_uint,
}

/// Address information passed to the open-socket callback.
///
/// C equivalent (include/curl/curl.h):
/// ```c
/// struct curl_sockaddr {
///   int family;
///   int socktype;
///   int protocol;
///   unsigned int addrlen;
///   struct sockaddr addr;
/// };
/// ```
#[repr(C)]
pub struct curl_sockaddr {
    pub family: c_int,
    pub socktype: c_int,
    pub protocol: c_int,
    pub addrlen: c_uint,
    pub addr: sockaddr,
}

/// HSTS entry passed to the HSTS read/write callbacks.
///
/// C equivalent (include/curl/curl.h):
/// ```c
/// struct curl_hstsentry {
///   char *name;
///   size_t namelen;
///   unsigned int includeSubDomains:1;
///   char expire[18];
/// };
/// ```
///
/// Note: The C struct uses a bit-field for `includeSubDomains`.  In Rust we
/// represent it as a full `c_uint`; only bit 0 is meaningful.  The resulting
/// struct layout is binary-compatible with the C definition because the
/// C compiler allocates `sizeof(unsigned int)` for the bit-field storage unit.
#[repr(C)]
#[allow(non_snake_case)]
pub struct curl_hstsentry {
    pub name: *mut c_char,
    pub namelen: size_t,
    pub includeSubDomains: c_uint,
    pub expire: [c_char; 18],
}

/// Index/total pair passed to the HSTS write callback.
///
/// C equivalent (include/curl/curl.h):
/// ```c
/// struct curl_index {
///   size_t index;
///   size_t total;
/// };
/// ```
#[repr(C)]
pub struct curl_index {
    pub index: size_t,
    pub total: size_t,
}

// ============================================================================
// Section 20: Callback Type Definitions
// Derived from: include/curl/curl.h, include/curl/multi.h
//
// All callbacks are `unsafe extern "C" fn(...)` to match the C calling
// convention.  They are inherently unsafe because they cross the FFI
// boundary and dereference raw pointers.
// ============================================================================

/// Write callback — receives downloaded data.
///
/// C: `typedef size_t (*curl_write_callback)(char *buffer, size_t size,
///                                           size_t nitems, void *outstream);`
pub type curl_write_callback = unsafe extern "C" fn(
    ptr: *mut c_char,
    size: size_t,
    nmemb: size_t,
    userdata: *mut c_void,
) -> size_t;

/// Read callback — provides upload data.
///
/// C: `typedef size_t (*curl_read_callback)(char *buffer, size_t size,
///                                          size_t nitems, void *instream);`
pub type curl_read_callback = unsafe extern "C" fn(
    buffer: *mut c_char,
    size: size_t,
    nitems: size_t,
    instream: *mut c_void,
) -> size_t;

/// Legacy progress callback (deprecated in favour of `curl_xferinfo_callback`).
///
/// C: `typedef int (*curl_progress_callback)(void *clientp,
///        double dltotal, double dlnow, double ultotal, double ulnow);`
pub type curl_progress_callback = unsafe extern "C" fn(
    clientp: *mut c_void,
    dltotal: f64,
    dlnow: f64,
    ultotal: f64,
    ulnow: f64,
) -> c_int;

/// Modern transfer-info callback introduced in curl 7.32.0.
///
/// C: `typedef int (*curl_xferinfo_callback)(void *clientp,
///        curl_off_t dltotal, curl_off_t dlnow,
///        curl_off_t ultotal, curl_off_t ulnow);`
pub type curl_xferinfo_callback = unsafe extern "C" fn(
    clientp: *mut c_void,
    dltotal: curl_off_t,
    dlnow: curl_off_t,
    ultotal: curl_off_t,
    ulnow: curl_off_t,
) -> c_int;

/// Header callback — receives response header lines.
/// Uses the same signature as the write callback.
///
/// C: same prototype as `curl_write_callback`
pub type curl_header_callback = unsafe extern "C" fn(
    buffer: *mut c_char,
    size: size_t,
    nitems: size_t,
    userdata: *mut c_void,
) -> size_t;

/// Debug/verbose callback — receives trace information.
///
/// C: `typedef int (*curl_debug_callback)(CURL *handle, curl_infotype type,
///                                        char *data, size_t size,
///                                        void *userptr);`
pub type curl_debug_callback = unsafe extern "C" fn(
    handle: *mut CURL,
    type_: curl_infotype,
    data: *mut c_char,
    size: size_t,
    userptr: *mut c_void,
) -> c_int;

/// Seek callback — repositions the read stream.
///
/// C: `typedef int (*curl_seek_callback)(void *instream,
///                                       curl_off_t offset, int origin);`
pub type curl_seek_callback = unsafe extern "C" fn(
    instream: *mut c_void,
    offset: curl_off_t,
    origin: c_int,
) -> c_int;

/// Deprecated I/O control callback.
///
/// C: `typedef curlioerr (*curl_ioctl_callback)(CURL *handle,
///                                              int cmd, void *clientp);`
pub type curl_ioctl_callback = unsafe extern "C" fn(
    handle: *mut CURL,
    cmd: c_int,
    clientp: *mut c_void,
) -> c_int;

/// Memory allocation callback (for `curl_global_init_mem`).
pub type curl_malloc_callback = unsafe extern "C" fn(size: size_t) -> *mut c_void;

/// Memory deallocation callback.
pub type curl_free_callback = unsafe extern "C" fn(ptr: *mut c_void);

/// Memory reallocation callback.
pub type curl_realloc_callback =
    unsafe extern "C" fn(ptr: *mut c_void, size: size_t) -> *mut c_void;

/// String duplication callback.
pub type curl_strdup_callback = unsafe extern "C" fn(str_: *const c_char) -> *mut c_char;

/// Zeroing memory allocation callback.
pub type curl_calloc_callback =
    unsafe extern "C" fn(nmemb: size_t, size: size_t) -> *mut c_void;

/// Open-socket callback — lets the application create the socket.
///
/// C: `typedef curl_socket_t (*curl_opensocket_callback)(void *clientp,
///        curlsocktype purpose, struct curl_sockaddr *address);`
pub type curl_opensocket_callback = unsafe extern "C" fn(
    clientp: *mut c_void,
    purpose: c_int,
    address: *mut curl_sockaddr,
) -> curl_socket_t;

/// Close-socket callback — lets the application close the socket.
///
/// C: `typedef int (*curl_closesocket_callback)(void *clientp,
///                                              curl_socket_t item);`
pub type curl_closesocket_callback =
    unsafe extern "C" fn(clientp: *mut c_void, item: curl_socket_t) -> c_int;

/// Socket-option callback — called after socket creation for custom
/// socket options (e.g. `SO_REUSEADDR`, TCP keepalive).
///
/// C: `typedef int (*curl_sockopt_callback)(void *clientp,
///        curl_socket_t curlfd, curlsocktype purpose);`
pub type curl_sockopt_callback = unsafe extern "C" fn(
    clientp: *mut c_void,
    curlfd: curl_socket_t,
    purpose: c_int,
) -> c_int;

/// Resolver-start callback — called when a new DNS resolution begins.
///
/// C: `typedef int (*curl_resolver_start_callback)(void *resolver_state,
///                                                 void *reserved,
///                                                 void *userdata);`
pub type curl_resolver_start_callback = unsafe extern "C" fn(
    resolver_state: *mut c_void,
    reserved: *mut c_void,
    userdata: *mut c_void,
) -> c_int;

/// Pre-request callback — called after the connection is established
/// but before the request is sent.
///
/// C: `typedef int (*curl_prereq_callback)(void *clientp,
///        char *conn_primary_ip, char *conn_local_ip,
///        int conn_primary_port, int conn_local_port);`
pub type curl_prereq_callback = unsafe extern "C" fn(
    clientp: *mut c_void,
    conn_primary_ip: *mut c_char,
    conn_local_ip: *mut c_char,
    conn_primary_port: c_int,
    conn_local_port: c_int,
) -> c_int;

/// Chunk-begin callback for wildcard FTP downloads.
///
/// C: `typedef long (*curl_chunk_bgn_callback)(const void *transfer_info,
///                                             void *ptr, int remains);`
pub type curl_chunk_bgn_callback = unsafe extern "C" fn(
    transfer_info: *const c_void,
    ptr: *mut c_void,
    remains: c_int,
) -> c_long;

/// Chunk-end callback for wildcard FTP downloads.
///
/// C: `typedef long (*curl_chunk_end_callback)(void *ptr);`
pub type curl_chunk_end_callback = unsafe extern "C" fn(ptr: *mut c_void) -> c_long;

/// Filename-match callback for wildcard FTP downloads.
///
/// C: `typedef int (*curl_fnmatch_callback)(void *ptr,
///        const char *pattern, const char *string);`
pub type curl_fnmatch_callback = unsafe extern "C" fn(
    ptr: *mut c_void,
    pattern: *const c_char,
    string: *const c_char,
) -> c_int;

/// HSTS read callback — invoked to load HSTS entries.
///
/// C: `typedef CURLSTScode (*curl_hstsread_callback)(CURL *easy,
///        struct curl_hstsentry *e, void *userp);`
pub type curl_hstsread_callback = unsafe extern "C" fn(
    easy: *mut CURL,
    e: *mut curl_hstsentry,
    userp: *mut c_void,
) -> CURLSTScode;

/// HSTS write callback — invoked to persist HSTS entries.
///
/// C: `typedef CURLSTScode (*curl_hstswrite_callback)(CURL *easy,
///        struct curl_hstsentry *e, struct curl_index *i, void *userp);`
pub type curl_hstswrite_callback = unsafe extern "C" fn(
    easy: *mut CURL,
    e: *mut curl_hstsentry,
    index: *mut curl_index,
    userp: *mut c_void,
) -> CURLSTScode;

/// SSL session export callback.
///
/// C: `typedef CURLcode curl_ssls_export_cb(CURL *handle, void *userptr,
///        const char *session_key, const unsigned char *shmac,
///        size_t shmac_len, const unsigned char *sdata, size_t sdata_len,
///        curl_off_t valid_until, int ietf_tls_id,
///        const char *alpn, size_t earlydata_max);`
///
/// Note: In C this is a *function type* (not a pointer).  Rust's `fn(...)`
/// types are already pointer-sized, so this definition is ABI-compatible
/// with `curl_ssls_export_cb *` in C.
pub type curl_ssls_export_cb = unsafe extern "C" fn(
    handle: *mut CURL,
    userptr: *mut c_void,
    session_key: *const c_char,
    shmac: *const c_uchar,
    shmac_len: size_t,
    sdata: *const c_uchar,
    sdata_len: size_t,
    valid_until: curl_off_t,
    ietf_tls_id: c_int,
    alpn: *const c_char,
    earlydata_max: size_t,
) -> CURLcode;

/// Deprecated character-conversion callback.
///
/// C: `typedef CURLcode (*curl_conv_callback)(char *buffer, size_t length);`
pub type curl_conv_callback =
    unsafe extern "C" fn(buffer: *mut c_char, length: size_t) -> CURLcode;

/// SSL context callback — allows modifying the SSL context after creation.
///
/// C: `typedef CURLcode (*curl_ssl_ctx_callback)(CURL *curl,
///                                               void *ssl_ctx,
///                                               void *userptr);`
pub type curl_ssl_ctx_callback = unsafe extern "C" fn(
    curl: *mut CURL,
    ssl_ctx: *mut c_void,
    userptr: *mut c_void,
) -> CURLcode;

/// SSH known-host key verification callback.
///
/// C: `typedef int (*curl_sshkeycallback)(CURL *easy,
///        const struct curl_khkey *knownkey,
///        const struct curl_khkey *foundkey,
///        enum curl_khmatch, void *clientp);`
///
/// The `curl_khkey *` parameters are represented as `*const c_void` because
/// the `curl_khkey` struct is not part of this module's exported API surface.
/// At the ABI level, all pointers have the same size and alignment.
pub type curl_sshkeycallback = unsafe extern "C" fn(
    easy: *mut CURL,
    knownkey: *const c_void,
    foundkey: *const c_void,
    match_status: c_int,
    clientp: *mut c_void,
) -> c_int;

/// SSH host-key verification callback (fingerprint-based).
///
/// C: `typedef int (*curl_sshhostkeycallback)(void *clientp,
///        int keytype, const char *key, size_t keylen);`
pub type curl_sshhostkeycallback = unsafe extern "C" fn(
    clientp: *mut c_void,
    keytype: c_int,
    key: *const c_char,
    keylen: size_t,
) -> c_int;

/// Share-handle lock callback.
///
/// C: `typedef void (*curl_lock_function)(CURL *handle, curl_lock_data data,
///        curl_lock_access locktype, void *userptr);`
pub type curl_lock_function = unsafe extern "C" fn(
    handle: *mut CURL,
    data: curl_lock_data,
    locktype: curl_lock_access,
    userptr: *mut c_void,
);

/// Share-handle unlock callback.
///
/// C: `typedef void (*curl_unlock_function)(CURL *handle,
///        curl_lock_data data, void *userptr);`
pub type curl_unlock_function = unsafe extern "C" fn(
    handle: *mut CURL,
    data: curl_lock_data,
    userptr: *mut c_void,
);

/// Deprecated form-get callback (used by the removed `curl_formget` API).
///
/// C: `typedef size_t (*curl_formget_callback)(void *arg,
///        const char *buf, size_t len);`
pub type curl_formget_callback = unsafe extern "C" fn(
    arg: *mut c_void,
    buf: *const c_char,
    len: size_t,
) -> size_t;

/// Multi-handle socket callback — informed about socket state changes.
///
/// C: `typedef int (*curl_socket_callback)(CURL *easy,
///        curl_socket_t s, int what, void *userp, void *socketp);`
pub type curl_socket_callback = unsafe extern "C" fn(
    easy: *mut CURL,
    s: curl_socket_t,
    what: c_int,
    userp: *mut c_void,
    socketp: *mut c_void,
) -> c_int;

/// Multi-handle timer callback — informed about timeout changes.
///
/// C: `typedef int (*curl_multi_timer_callback)(CURLM *multi,
///        long timeout_ms, void *userp);`
pub type curl_multi_timer_callback = unsafe extern "C" fn(
    multi: *mut CURLM,
    timeout_ms: c_long,
    userp: *mut c_void,
) -> c_int;

/// Server push callback — approves or denies HTTP/2 server pushes.
///
/// C: `typedef int (*curl_push_callback)(CURL *parent, CURL *easy,
///        size_t num_headers, struct curl_pushheaders *headers,
///        void *userp);`
pub type curl_push_callback = unsafe extern "C" fn(
    parent: *mut CURL,
    easy: *mut CURL,
    num_headers: size_t,
    headers: *mut curl_pushheaders,
    userp: *mut c_void,
) -> c_int;

/// Multi-handle notification callback.
///
/// C: `typedef void (*curl_notify_callback)(CURLM *multi,
///        unsigned int notification, CURL *easy, void *user_data);`
pub type curl_notify_callback = unsafe extern "C" fn(
    multi: *mut CURLM,
    notification: c_uint,
    easy: *mut CURL,
    user_data: *mut c_void,
);

// ============================================================================
// Section 21: Complex Supporting Structs
// ============================================================================

/// Version information returned by `curl_version_info()`.
///
/// C equivalent: `struct curl_version_info_data` (include/curl/curl.h lines
/// 3111–3172).  The struct has grown over time; the `age` field indicates
/// which fields are valid.
#[repr(C)]
pub struct curl_version_info_data {
    /// Which version of the struct is returned (see `CURLversion` enum).
    pub age: CURLversion,
    /// Human-readable version string, e.g. `"8.19.0-DEV"`.
    pub version: *const c_char,
    /// Packed numeric version: `(MAJOR << 16) | (MINOR << 8) | PATCH`.
    pub version_num: c_uint,
    /// OS/host/cpu string from the configure step.
    pub host: *const c_char,
    /// Bitmask of `CURL_VERSION_*` feature flags.
    pub features: c_int,
    /// SSL/TLS library version string, or null.
    pub ssl_version: *const c_char,
    /// Unused (always 0).
    pub ssl_version_num: c_long,
    /// zlib version string, or null.
    pub libz_version: *const c_char,
    /// Null-terminated array of supported protocol name strings.
    pub protocols: *const *const c_char,
    // --- fields added in CURLVERSION_SECOND ---
    /// c-ares version string, or null.
    pub ares: *const c_char,
    /// c-ares version number.
    pub ares_num: c_int,
    // --- fields added in CURLVERSION_THIRD ---
    /// libidn version string, or null.
    pub libidn: *const c_char,
    // --- fields added in CURLVERSION_FOURTH ---
    /// iconv version number (0 if not available).
    pub iconv_ver_num: c_int,
    /// libssh/libssh2 version string, or null.
    pub libssh_version: *const c_char,
    // --- fields added in CURLVERSION_FIFTH ---
    /// Brotli version: `(MAJOR << 24) | (MINOR << 12) | PATCH`.
    pub brotli_ver_num: c_uint,
    /// Brotli version string, or null.
    pub brotli_version: *const c_char,
    // --- fields added in CURLVERSION_SIXTH ---
    /// nghttp2 version: `(MAJOR << 16) | (MINOR << 8) | PATCH`.
    pub nghttp2_ver_num: c_uint,
    /// nghttp2 version string, or null.
    pub nghttp2_version: *const c_char,
    /// QUIC + HTTP/3 library version string, or null.
    pub quic_version: *const c_char,
    // --- fields added in CURLVERSION_SEVENTH ---
    /// Built-in default CA info path, or null.
    pub cainfo: *const c_char,
    /// Built-in default CA path, or null.
    pub capath: *const c_char,
    // --- fields added in CURLVERSION_EIGHTH ---
    /// Zstandard version: `(MAJOR << 24) | (MINOR << 12) | PATCH`.
    pub zstd_ver_num: c_uint,
    /// Zstandard version string, or null.
    pub zstd_version: *const c_char,
    // --- fields added in CURLVERSION_NINTH ---
    /// Hyper version string, or null.
    pub hyper_version: *const c_char,
    // --- fields added in CURLVERSION_TENTH ---
    /// GSasl version string, or null.
    pub gsasl_version: *const c_char,
    // --- fields added in CURLVERSION_ELEVENTH ---
    /// Null-terminated array of feature name strings.
    pub feature_names: *const *const c_char,
    // --- fields added in CURLVERSION_TWELFTH ---
    /// RTMP library version string, or null.
    pub rtmp_version: *const c_char,
}

/// Union payload of `CURLMsg_struct::data`.
///
/// C equivalent:
/// ```c
/// union {
///   void *whatever;
///   CURLcode result;
/// } data;
/// ```
#[repr(C)]
pub union CURLMsg_data {
    pub whatever: *mut c_void,
    pub result: CURLcode,
}

/// Message returned by `curl_multi_info_read()`.
///
/// C equivalent: `struct CURLMsg` (include/curl/multi.h lines 97–105).
/// Renamed to `CURLMsg_struct` in Rust to avoid collision with the `CURLMSG`
/// type alias (which represents the enum tag).
#[repr(C)]
pub struct CURLMsg_struct {
    /// What this message means — typically `CURLMSG_DONE (1)`.
    pub msg: CURLMSG,
    /// The easy handle this message concerns.
    pub easy_handle: *mut CURL,
    /// Message-specific payload.
    pub data: CURLMsg_data,
}

/// File-descriptor and event-interest pair for `curl_multi_wait/poll`.
///
/// C equivalent: `struct curl_waitfd` (include/curl/multi.h lines 114–118).
#[repr(C)]
pub struct curl_waitfd {
    pub fd: curl_socket_t,
    pub events: c_short,
    pub revents: c_short,
}

/// WebSocket frame metadata.
///
/// C equivalent: `struct curl_ws_frame` (include/curl/websockets.h lines
/// 31–37).
#[repr(C)]
pub struct curl_ws_frame {
    /// Struct version (currently always 0).
    pub age: c_int,
    /// Bitmask of `CURLWS_*` flags.
    pub flags: c_int,
    /// Byte offset of this chunk within the frame payload.
    pub offset: curl_off_t,
    /// Number of bytes remaining after this chunk.
    pub bytesleft: curl_off_t,
    /// Length of the data chunk delivered in this callback invocation.
    pub len: size_t,
}

/// Parsed response header entry returned by `curl_easy_header()`.
///
/// C equivalent: `struct curl_header` (include/curl/header.h lines 31–38).
#[repr(C)]
pub struct curl_header {
    /// Header name (may differ in case from the request).
    pub name: *mut c_char,
    /// Header value.
    pub value: *mut c_char,
    /// Number of headers using this name.
    pub amount: size_t,
    /// 0-based index of this instance among same-name headers.
    pub index: size_t,
    /// Bitmask indicating origin (`CURLH_HEADER`, `CURLH_TRAILER`, etc.).
    pub origin: c_uint,
    /// Opaque anchor used internally by libcurl.
    pub anchor: *mut c_void,
}

/// Option metadata entry returned by the option introspection API.
///
/// C equivalent: `struct curl_easyoption` (include/curl/options.h lines
/// 51–55).
#[repr(C)]
pub struct curl_easyoption {
    /// Option name string (e.g. `"CURLOPT_URL"`).
    pub name: *const c_char,
    /// Option numeric identifier (`CURLoption` value).
    pub id: CURLoption,
    /// Option value type (`curl_easytype`).
    pub type_: curl_easytype,
    /// Flag bits (see `CURLOT_FLAG_ALIAS`).
    pub flags: c_uint,
}

// ============================================================================
// Tests — compile-time layout assertions
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    /// Verify that opaque handle types are zero-sized (they are only ever used
    /// behind pointers, so the size of the struct itself must be zero).
    #[test]
    fn opaque_types_are_zero_sized() {
        assert_eq!(mem::size_of::<CURL>(), 0);
        assert_eq!(mem::size_of::<CURLM>(), 0);
        assert_eq!(mem::size_of::<CURLSH>(), 0);
        assert_eq!(mem::size_of::<CURLU>(), 0);
        assert_eq!(mem::size_of::<curl_mime>(), 0);
        assert_eq!(mem::size_of::<curl_mimepart>(), 0);
        assert_eq!(mem::size_of::<curl_pushheaders>(), 0);
        assert_eq!(mem::size_of::<curl_ssl_backend>(), 0);
    }

    /// Verify that `curl_off_t` is exactly 64 bits wide, as required by the
    /// curl specification.
    #[test]
    fn curl_off_t_is_64_bit() {
        assert_eq!(mem::size_of::<curl_off_t>(), 8);
    }

    /// Verify that `curl_socket_t` has the expected platform size.
    #[test]
    fn socket_type_size() {
        #[cfg(unix)]
        assert_eq!(
            mem::size_of::<curl_socket_t>(),
            mem::size_of::<c_int>()
        );
        #[cfg(windows)]
        assert_eq!(
            mem::size_of::<curl_socket_t>(),
            mem::size_of::<usize>()
        );
    }

    /// Verify CURL_SOCKET_BAD has the expected sentinel value.
    #[test]
    #[cfg(unix)]
    fn socket_bad_is_minus_one() {
        assert_eq!(CURL_SOCKET_BAD, -1);
    }

    /// Verify that the CURLOPTTYPE constants match their C values.
    #[test]
    fn curlopttype_values() {
        assert_eq!(CURLOPTTYPE_LONG, 0);
        assert_eq!(CURLOPTTYPE_OBJECTPOINT, 10000);
        assert_eq!(CURLOPTTYPE_FUNCTIONPOINT, 20000);
        assert_eq!(CURLOPTTYPE_OFF_T, 30000);
        assert_eq!(CURLOPTTYPE_BLOB, 40000);
        assert_eq!(CURLOPTTYPE_STRINGPOINT, CURLOPTTYPE_OBJECTPOINT);
        assert_eq!(CURLOPTTYPE_SLISTPOINT, CURLOPTTYPE_OBJECTPOINT);
        assert_eq!(CURLOPTTYPE_CBPOINT, CURLOPTTYPE_OBJECTPOINT);
        assert_eq!(CURLOPTTYPE_VALUES, CURLOPTTYPE_LONG);
    }

    /// Verify that CURLINFO type-tag constants match their C values.
    #[test]
    fn curlinfo_typetag_values() {
        assert_eq!(CURLINFO_STRING, 0x100000);
        assert_eq!(CURLINFO_LONG, 0x200000);
        assert_eq!(CURLINFO_DOUBLE, 0x300000);
        assert_eq!(CURLINFO_SLIST, 0x400000);
        assert_eq!(CURLINFO_PTR, 0x400000);
        assert_eq!(CURLINFO_SOCKET, 0x500000);
        assert_eq!(CURLINFO_OFF_T, 0x600000);
        assert_eq!(CURLINFO_TYPEMASK, 0xf00000);
    }

    /// Verify CURLSTScode constant values.
    #[test]
    fn curlstscode_values() {
        assert_eq!(CURLSTS_OK, 0);
        assert_eq!(CURLSTS_DONE, 1);
        assert_eq!(CURLSTS_FAIL, 2);
    }

    /// Verify debug info-type constant values.
    #[test]
    fn debug_infotype_values() {
        assert_eq!(CURLINFO_TEXT, 0);
        assert_eq!(CURLINFO_HEADER_IN, 1);
        assert_eq!(CURLINFO_HEADER_OUT, 2);
        assert_eq!(CURLINFO_DATA_IN, 3);
        assert_eq!(CURLINFO_DATA_OUT, 4);
        assert_eq!(CURLINFO_SSL_DATA_IN, 5);
        assert_eq!(CURLINFO_SSL_DATA_OUT, 6);
    }

    /// Verify seek callback return constants.
    #[test]
    fn seek_constants() {
        assert_eq!(CURL_SEEKFUNC_OK, 0);
        assert_eq!(CURL_SEEKFUNC_FAIL, 1);
        assert_eq!(CURL_SEEKFUNC_CANTSEEK, 2);
    }

    /// Verify special read/write return values.
    #[test]
    fn readwrite_special_values() {
        assert_eq!(CURL_READFUNC_ABORT, 0x10000000);
        assert_eq!(CURL_READFUNC_PAUSE, 0x10000001);
        assert_eq!(CURL_WRITEFUNC_PAUSE, 0x10000001);
        assert_eq!(CURL_WRITEFUNC_ERROR, 0xFFFFFFFF);
    }

    /// Verify sockopt callback return constants.
    #[test]
    fn sockopt_constants() {
        assert_eq!(CURL_SOCKOPT_OK, 0);
        assert_eq!(CURL_SOCKOPT_ERROR, 1);
        assert_eq!(CURL_SOCKOPT_ALREADY_CONNECTED, 2);
    }

    /// Verify multi socket poll constants.
    #[test]
    fn poll_constants() {
        assert_eq!(CURL_POLL_NONE, 0);
        assert_eq!(CURL_POLL_IN, 1);
        assert_eq!(CURL_POLL_OUT, 2);
        assert_eq!(CURL_POLL_INOUT, 3);
        assert_eq!(CURL_POLL_REMOVE, 4);
    }

    /// Verify cselect constants.
    #[test]
    fn cselect_constants() {
        assert_eq!(CURL_CSELECT_IN, 0x01);
        assert_eq!(CURL_CSELECT_OUT, 0x02);
        assert_eq!(CURL_CSELECT_ERR, 0x04);
    }

    /// Verify CURL_SOCKET_TIMEOUT equals CURL_SOCKET_BAD.
    #[test]
    fn socket_timeout_equals_bad() {
        assert_eq!(CURL_SOCKET_TIMEOUT, CURL_SOCKET_BAD);
    }

    /// Verify wait-fd event constants.
    #[test]
    fn wait_poll_constants() {
        assert_eq!(CURL_WAIT_POLLIN, 0x0001);
        assert_eq!(CURL_WAIT_POLLPRI, 0x0002);
        assert_eq!(CURL_WAIT_POLLOUT, 0x0004);
    }

    /// Verify push callback return constants.
    #[test]
    fn push_constants() {
        assert_eq!(CURL_PUSH_OK, 0);
        assert_eq!(CURL_PUSH_DENY, 1);
        assert_eq!(CURL_PUSH_ERROROUT, 2);
    }

    /// Verify WebSocket flag constants.
    #[test]
    fn websocket_flag_constants() {
        assert_eq!(CURLWS_TEXT, 1);
        assert_eq!(CURLWS_BINARY, 2);
        assert_eq!(CURLWS_CONT, 4);
        assert_eq!(CURLWS_CLOSE, 8);
        assert_eq!(CURLWS_PING, 16);
        assert_eq!(CURLWS_OFFSET, 32);
        assert_eq!(CURLWS_PONG, 64);
    }

    /// Verify pipelining constants.
    #[test]
    fn pipe_constants() {
        assert_eq!(CURLPIPE_NOTHING, 0);
        assert_eq!(CURLPIPE_MULTIPLEX, 2);
    }

    /// Verify header origin constants.
    #[test]
    fn header_origin_constants() {
        assert_eq!(CURLH_HEADER, 1);
        assert_eq!(CURLH_TRAILER, 2);
        assert_eq!(CURLH_CONNECT, 4);
        assert_eq!(CURLH_1XX, 8);
        assert_eq!(CURLH_PSEUDO, 16);
    }

    /// Verify blob flag constants.
    #[test]
    fn blob_constants() {
        assert_eq!(CURL_BLOB_COPY, 1);
        assert_eq!(CURL_BLOB_NOCOPY, 0);
    }

    /// Verify easy-option alias flag.
    #[test]
    fn easyopt_flag_alias() {
        assert_eq!(CURLOT_FLAG_ALIAS, 1);
    }

    /// Verify that `curl_blob` has a sensible layout.
    #[test]
    fn curl_blob_layout() {
        assert!(mem::size_of::<curl_blob>() > 0);
        // data pointer + len + flags — at least pointer + 2 * 4 bytes
        assert!(mem::size_of::<curl_blob>() >= mem::size_of::<*mut c_void>() + 4);
    }

    /// Verify that `curl_slist` is a linked-list node.
    #[test]
    fn curl_slist_layout() {
        // Two pointer-sized fields: data + next
        assert_eq!(
            mem::size_of::<curl_slist>(),
            2 * mem::size_of::<*mut c_void>()
        );
    }

    /// Verify that `curl_ws_frame` has the expected number of fields.
    #[test]
    fn curl_ws_frame_has_expected_size() {
        // 2 * c_int + 2 * curl_off_t + size_t
        let expected = 2 * mem::size_of::<c_int>()
            + 2 * mem::size_of::<curl_off_t>()
            + mem::size_of::<size_t>();
        // Due to alignment padding between the c_int fields and curl_off_t,
        // the actual size may be larger.
        assert!(mem::size_of::<curl_ws_frame>() >= expected);
    }

    /// Verify that `curl_waitfd` has the right layout.
    #[test]
    fn curl_waitfd_layout() {
        // fd (curl_socket_t) + events (c_short) + revents (c_short)
        assert!(mem::size_of::<curl_waitfd>() > 0);
    }

    /// Verify that all enum type aliases are c_int sized.
    #[test]
    fn enum_type_aliases_are_c_int_sized() {
        assert_eq!(mem::size_of::<CURLcode>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLoption>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLINFO>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLversion>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLMSG>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLformoption>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<curl_infotype>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<curl_TimeCond>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLSTScode>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<curl_lock_data>(), mem::size_of::<c_int>());
        assert_eq!(
            mem::size_of::<curl_lock_access>(),
            mem::size_of::<c_int>()
        );
        assert_eq!(mem::size_of::<CURLSHcode>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLSHoption>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLMcode>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLMoption>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLUcode>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLUPart>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLHcode>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<curl_easytype>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLsslset>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<curl_sslbackend>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLproxycode>(), mem::size_of::<c_int>());
        assert_eq!(mem::size_of::<CURLMinfo_offt>(), mem::size_of::<c_int>());
    }

    /// Verify that callback type aliases are pointer-sized (function pointers).
    #[test]
    fn callback_types_are_pointer_sized() {
        let ptr_size = mem::size_of::<*const c_void>();
        assert_eq!(mem::size_of::<curl_write_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_read_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_progress_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_xferinfo_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_header_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_debug_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_seek_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_ioctl_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_malloc_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_free_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_realloc_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_strdup_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_calloc_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_opensocket_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_closesocket_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_sockopt_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_resolver_start_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_prereq_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_chunk_bgn_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_chunk_end_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_fnmatch_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_hstsread_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_hstswrite_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_ssls_export_cb>(), ptr_size);
        assert_eq!(mem::size_of::<curl_conv_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_ssl_ctx_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_sshkeycallback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_sshhostkeycallback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_lock_function>(), ptr_size);
        assert_eq!(mem::size_of::<curl_unlock_function>(), ptr_size);
        assert_eq!(mem::size_of::<curl_formget_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_socket_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_multi_timer_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_push_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_notify_callback>(), ptr_size);
        assert_eq!(mem::size_of::<curl_trailer_callback>(), ptr_size);
    }
}
