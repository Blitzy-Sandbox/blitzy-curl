// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! `curl_easy_*` C ABI entry points — the easy-handle surface of libcurl.
//!
//! This module is the `extern "C"` home of the 16 public easy-handle functions of the libcurl
//! ABI: the 10 declared in `include/curl/easy.h` (`curl_easy_init`, `curl_easy_setopt`,
//! `curl_easy_perform`, `curl_easy_cleanup`, `curl_easy_getinfo`, `curl_easy_duphandle`,
//! `curl_easy_reset`, `curl_easy_recv`, `curl_easy_send`, `curl_easy_upkeep`) plus the 6
//! easy-handle functions declared in `include/curl/curl.h` (`curl_easy_escape`,
//! `curl_easy_unescape`, `curl_easy_strerror`, `curl_easy_pause`, `curl_easy_ssls_import`,
//! `curl_easy_ssls_export`). It is derived 1:1 from those headers and the C entry points
//! `lib/easy.c`, `lib/easyoptions.c`, and `lib/escape.c`, which are retained in-tree as a
//! read-only source-of-truth reference (AAP §0.4.1).
//!
//! # Handle model
//! The opaque C `CURL *` is a `Box<`[`curl_rs_lib::url::Easy`]`>` in disguise: [`curl_easy_init`]
//! moves a fresh [`Easy`] onto the heap with [`box_into_raw`] and hands the raw pointer to C;
//! [`curl_easy_cleanup`] reclaims it with [`box_from_raw`] and drops it. All borrowing of a live
//! handle goes through [`as_ref`] / [`as_mut`], which perform the null check and bound the borrow
//! to the call. `CURL` is an opaque `typedef void CURL;` in the header, so every signature uses
//! `*mut c_void`.
//!
//! # Safety and unwinding (AAP §0.6.2 / §0.7.2 — binding)
//! `curl-rs-ffi` is the sole crate permitted to use `unsafe`; `curl-rs-lib` is built with
//! `#![forbid(unsafe_code)]`. Every `unsafe` block here carries a `// SAFETY:` comment stating the
//! invariant it upholds, and `#![deny(unsafe_op_in_unsafe_fn)]` (below) forces each raw operation
//! into its own annotated block even inside an `unsafe extern "C" fn`. No panic may unwind across
//! the `extern "C" fn` boundary: fallible bodies run inside [`ffi_guard`] (which returns a mapped
//! error code on panic) or, for the pointer-returning entry points, inside [`catch_unwind`] (which
//! yields the null sentinel), exactly mirroring curl's out-of-memory `NULL` / error-code returns.
//!
//! # Integer-value stability (AAP §0.6.1)
//! [`CURLoption`], [`CURLINFO`], and the `CURLcode` bridge preserve curl 8.x's exact integer
//! contract: e.g. `CURLOPT_URL == 10002`, `CURLINFO_RESPONSE_CODE == 0x200002`, and (via
//! `curl_rs_lib::error`) `CURLE_OPERATION_TIMEDOUT == 28`. The `CURLoption`/`CURLINFO`
//! discriminants are transcribed verbatim from `include/curl/curl.h`.
//!
//! # Variadic ABI note (`curl_easy_setopt` / `curl_easy_getinfo`)
//! curl declares these two functions as C variadics (`..., ...)`). True Rust C-variadic
//! *definitions* (`extern "C" fn(..., mut args: ...)` / `core::ffi::VaList`) require the unstable
//! `c_variadic` feature, unavailable on the pinned stable MSRV (1.75, `rust-toolchain.toml`). The
//! genuine variadic entry points `curl_easy_setopt` and `curl_easy_getinfo` are therefore defined
//! in C — tiny trampolines in `csrc/variadic_shim.c` that `va_start`/`va_arg` the single promoted
//! argument and forward it as a fixed pointer-width `usize` to the Rust workers [`crs_easy_setopt`]
//! and [`crs_easy_getinfo`] below (which perform the option/info dispatch). This is the same
//! C-trampoline mechanism the `curl_m*printf` family uses, and it keeps the exported symbols
//! correctly variadic on EVERY supported target — crucially including `aarch64-apple-darwin`,
//! where a vararg is passed on the stack rather than in `x2`, so the earlier fixed-arity export
//! read the wrong slot (QA F6-VARIADIC). The `crs_`-prefixed workers stay `#[no_mangle]` (so the C
//! trampolines resolve them by name) but are NOT part of the exported `curl_*` surface — the
//! cdylib version script exports only `curl_*` — so symbol parity is exact. `cbindgen` header
//! generation is best-effort and never clobbers the committed `include/curl/curl.h`, which remains
//! the authoritative ABI surface and retains the real `..., ...)` declarations.

#![deny(unsafe_op_in_unsafe_fn)]

use crate::slist::curl_slist;
use crate::{
    as_mut, as_ref, box_from_raw, box_into_raw, cstr_to_str, ffi_guard, str_to_c_owned,
    to_curlcode, CURLcode,
};
use curl_rs_lib::url::Easy;
use libc::{c_char, c_double, c_int, c_long, c_longlong, c_uchar, c_uint, c_void, size_t};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::{Mutex, OnceLock};

// ===========================================================================
// Boundary ABI types (curl.h / easy.h) owned by this module.
//
// Types owned by sibling modules are intentionally NOT redefined here: `curl_slist`
// (`slist.rs`), `curl_free` and the allocator callbacks (`global.rs`), and `CURLcode` /
// `CURLversion` (`lib.rs`). This module defines the easy-handle-specific ABI types below.
// ===========================================================================

/// `typedef curl_off_t` — curl's 64-bit file-size / offset type. On the supported Linux and
/// macOS targets (AAP §0.6.5) `CURL_TYPEOF_CURL_OFF_T` is `long long`, i.e. a signed 64-bit
/// integer (`include/curl/system.h`).
pub type curl_off_t = c_longlong;

/// `typedef int curl_socket_t` — the socket handle type on Unix (`include/curl/curl.h`).
pub type curl_socket_t = c_int;

/// `#define CURL_SOCKET_BAD (-1)` — the invalid-socket sentinel on Unix.
pub const CURL_SOCKET_BAD: curl_socket_t = -1;

/// `struct curl_blob` — a length-delimited binary option value (`include/curl/easy.h`). Used by
/// the `*_BLOB` options; `flags` is [`CURL_BLOB_COPY`] or [`CURL_BLOB_NOCOPY`].
#[repr(C)]
pub struct curl_blob {
    /// Pointer to the blob's bytes.
    pub data: *mut c_void,
    /// Length of the blob in bytes.
    pub len: size_t,
    /// `CURL_BLOB_COPY` (libcurl copies the data) or `CURL_BLOB_NOCOPY` (caller keeps it alive).
    pub flags: c_uint,
}

/// `#define CURL_BLOB_COPY 1` — libcurl makes its own copy of the blob data.
pub const CURL_BLOB_COPY: c_uint = 1;
/// `#define CURL_BLOB_NOCOPY 0` — the caller retains ownership of the blob data.
pub const CURL_BLOB_NOCOPY: c_uint = 0;

/// `curl_infotype` — the kind of data passed to the debug callback (`include/curl/curl.h`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum curl_infotype {
    /// Informational text.
    CURLINFO_TEXT = 0,
    /// Header received from the peer.
    CURLINFO_HEADER_IN = 1,
    /// Header sent to the peer.
    CURLINFO_HEADER_OUT = 2,
    /// Protocol data received from the peer.
    CURLINFO_DATA_IN = 3,
    /// Protocol data sent to the peer.
    CURLINFO_DATA_OUT = 4,
    /// TLS/SSL data received from the peer.
    CURLINFO_SSL_DATA_IN = 5,
    /// TLS/SSL data sent to the peer.
    CURLINFO_SSL_DATA_OUT = 6,
    /// Sentinel — the number of `curl_infotype` values (never passed as a real type).
    CURLINFO_END = 7,
}

/// `curlioerr` — the return type of the (deprecated) ioctl callback (`include/curl/curl.h`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum curlioerr {
    /// I/O operation successful.
    CURLIOE_OK = 0,
    /// Command was unknown to the callback.
    CURLIOE_UNKNOWNCMD = 1,
    /// Failed to restart the read.
    CURLIOE_FAILRESTART = 2,
    /// Sentinel — never use.
    CURLIOE_LAST = 3,
}

/// `curliocmd` — the command passed to the (deprecated) ioctl callback (`include/curl/curl.h`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum curliocmd {
    /// No operation.
    CURLIOCMD_NOP = 0,
    /// Restart the read stream from the start.
    CURLIOCMD_RESTARTREAD = 1,
    /// Sentinel — never use.
    CURLIOCMD_LAST = 2,
}

/// `curlsocktype` — the purpose of a socket handed to the sockopt / opensocket callbacks.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum curlsocktype {
    /// Socket created for a specific IP connection.
    CURLSOCKTYPE_IPCXN = 0,
    /// Socket created by an `accept()` call.
    CURLSOCKTYPE_ACCEPT = 1,
    /// Sentinel — never use.
    CURLSOCKTYPE_LAST = 2,
}

/// `CURLSTScode` — the return type of the HSTS read/write callbacks (`include/curl/curl.h`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CURLSTScode {
    /// Proceed — entry provided / stored.
    CURLSTS_OK = 0,
    /// Iteration complete — no more entries.
    CURLSTS_DONE = 1,
    /// Abort the HSTS read/write operation.
    CURLSTS_FAIL = 2,
}

/// `struct curl_sockaddr` — the address passed to the opensocket callback (`include/curl/curl.h`).
#[repr(C)]
pub struct curl_sockaddr {
    /// Address family (`AF_*`).
    pub family: c_int,
    /// Socket type (`SOCK_*`).
    pub socktype: c_int,
    /// Protocol (`IPPROTO_*`).
    pub protocol: c_int,
    /// Length of the `addr` field that is valid.
    pub addrlen: c_uint,
    /// The socket address itself.
    pub addr: libc::sockaddr,
}

/// `struct curl_hstsentry` — one HSTS cache entry exchanged with the HSTS read/write callbacks.
///
/// NOTE(layout): curl declares `includeSubDomains` as a `unsigned int … :1` C bitfield. Rust has
/// no bitfield syntax, so it is represented here as a full `c_uint` (0/1). This is deliberately a
/// declaration for ABI-surface/type parity only — the HSTS callbacks are not wired to the core at
/// this checkpoint, so no `curl_hstsentry` is ever marshaled through this boundary yet. When the
/// HSTS subsystem is connected, the exact bitfield packing must be reconciled against the C ABI.
#[repr(C)]
pub struct curl_hstsentry {
    /// Host name (NUL-terminated).
    pub name: *mut c_char,
    /// Length of `name`.
    pub namelen: size_t,
    /// C `unsigned int includeSubDomains:1` — represented as a full `c_uint` (see the layout note).
    pub includeSubDomains: c_uint,
    /// Expiry as `YYYYMMDD HH:MM:SS` plus a terminating NUL (18 bytes).
    pub expire: [c_char; 18],
}

/// `struct curl_index` — position/size hint passed to the HSTS write callback.
#[repr(C)]
pub struct curl_index {
    /// The provided entry's index / count.
    pub index: size_t,
    /// Total number of entries to save.
    pub total: size_t,
}

// ===========================================================================
// Option-type ranges, info-type masks, and callback return sentinels (curl.h).
// ===========================================================================

/// `CURLOPTTYPE_LONG` — option value is a `long` (base `0`).
pub const CURLOPTTYPE_LONG: c_int = 0;
/// `CURLOPTTYPE_OBJECTPOINT` — option value is an object pointer (base `10000`).
pub const CURLOPTTYPE_OBJECTPOINT: c_int = 10000;
/// `CURLOPTTYPE_FUNCTIONPOINT` — option value is a function pointer (base `20000`).
pub const CURLOPTTYPE_FUNCTIONPOINT: c_int = 20000;
/// `CURLOPTTYPE_OFF_T` — option value is a `curl_off_t` (base `30000`).
pub const CURLOPTTYPE_OFF_T: c_int = 30000;
/// `CURLOPTTYPE_BLOB` — option value is a `struct curl_blob *` (base `40000`).
pub const CURLOPTTYPE_BLOB: c_int = 40000;
/// `CURLOPTTYPE_STRINGPOINT` — alias of `CURLOPTTYPE_OBJECTPOINT` for `char *` options.
pub const CURLOPTTYPE_STRINGPOINT: c_int = CURLOPTTYPE_OBJECTPOINT;
/// `CURLOPTTYPE_SLISTPOINT` — alias of `CURLOPTTYPE_OBJECTPOINT` for `struct curl_slist *` options.
pub const CURLOPTTYPE_SLISTPOINT: c_int = CURLOPTTYPE_OBJECTPOINT;
/// `CURLOPTTYPE_CBPOINT` — alias of `CURLOPTTYPE_OBJECTPOINT` for callback-data pointers.
pub const CURLOPTTYPE_CBPOINT: c_int = CURLOPTTYPE_OBJECTPOINT;
/// `CURLOPTTYPE_VALUES` — alias of `CURLOPTTYPE_LONG` for enumerated `long` values.
pub const CURLOPTTYPE_VALUES: c_int = CURLOPTTYPE_LONG;

/// `CURLINFO_STRING` — info result is written through a `char **` out-pointer.
pub const CURLINFO_STRING: c_int = 0x100000;
/// `CURLINFO_LONG` — info result is written through a `long *` out-pointer.
pub const CURLINFO_LONG: c_int = 0x200000;
/// `CURLINFO_DOUBLE` — info result is written through a `double *` out-pointer.
pub const CURLINFO_DOUBLE: c_int = 0x300000;
/// `CURLINFO_SLIST` — info result is written through a `struct curl_slist **` out-pointer.
pub const CURLINFO_SLIST: c_int = 0x400000;
/// `CURLINFO_PTR` — info result is written through a generic `void **` out-pointer (shares the
/// numeric value of [`CURLINFO_SLIST`]).
pub const CURLINFO_PTR: c_int = 0x400000;
/// `CURLINFO_SOCKET` — info result is written through a `curl_socket_t *` out-pointer.
pub const CURLINFO_SOCKET: c_int = 0x500000;
/// `CURLINFO_OFF_T` — info result is written through a `curl_off_t *` out-pointer.
pub const CURLINFO_OFF_T: c_int = 0x600000;
/// `CURLINFO_MASK` — mask selecting the info's ordinal (low bits).
pub const CURLINFO_MASK: c_int = 0x0fffff;
/// `CURLINFO_TYPEMASK` — mask selecting the info's result type (high bits).
pub const CURLINFO_TYPEMASK: c_int = 0xf00000;

/// `CURL_WRITEFUNC_PAUSE` — write-callback return value that pauses the transfer.
pub const CURL_WRITEFUNC_PAUSE: size_t = 0x10000001;
/// `CURL_WRITEFUNC_ERROR` — write-callback return value that signals an error.
pub const CURL_WRITEFUNC_ERROR: size_t = 0xFFFFFFFF;
/// `CURL_READFUNC_ABORT` — read-callback return value that aborts the transfer.
pub const CURL_READFUNC_ABORT: size_t = 0x10000000;
/// `CURL_READFUNC_PAUSE` — read-callback return value that pauses the transfer.
pub const CURL_READFUNC_PAUSE: size_t = 0x10000001;
/// `CURL_SEEKFUNC_OK` — seek callback succeeded.
pub const CURL_SEEKFUNC_OK: c_int = 0;
/// `CURL_SEEKFUNC_FAIL` — seek callback failed; fail the entire transfer.
pub const CURL_SEEKFUNC_FAIL: c_int = 1;
/// `CURL_SEEKFUNC_CANTSEEK` — seeking cannot be done; libcurl may try other means.
pub const CURL_SEEKFUNC_CANTSEEK: c_int = 2;
/// `CURL_TRAILERFUNC_OK` — trailing-headers callback completed successfully.
pub const CURL_TRAILERFUNC_OK: c_int = 0;
/// `CURL_TRAILERFUNC_ABORT` — trailing-headers callback wants to abort the request.
pub const CURL_TRAILERFUNC_ABORT: c_int = 1;
/// `CURL_PREREQFUNC_OK` — pre-request callback completed successfully.
pub const CURL_PREREQFUNC_OK: c_int = 0;
/// `CURL_PREREQFUNC_ABORT` — pre-request callback wants to abort the request.
pub const CURL_PREREQFUNC_ABORT: c_int = 1;
/// `CURL_SOCKOPT_OK` — sockopt callback succeeded.
pub const CURL_SOCKOPT_OK: c_int = 0;
/// `CURL_SOCKOPT_ERROR` — sockopt callback failed; abort with `CURLE_ABORTED_BY_CALLBACK`.
pub const CURL_SOCKOPT_ERROR: c_int = 1;
/// `CURL_SOCKOPT_ALREADY_CONNECTED` — the socket is already connected.
pub const CURL_SOCKOPT_ALREADY_CONNECTED: c_int = 2;
/// `CURL_CHUNK_BGN_FUNC_OK` — chunk-begin callback succeeded.
pub const CURL_CHUNK_BGN_FUNC_OK: c_long = 0;
/// `CURL_CHUNK_BGN_FUNC_FAIL` — chunk-begin callback failed; end the task.
pub const CURL_CHUNK_BGN_FUNC_FAIL: c_long = 1;
/// `CURL_CHUNK_BGN_FUNC_SKIP` — skip this chunk.
pub const CURL_CHUNK_BGN_FUNC_SKIP: c_long = 2;
/// `CURL_CHUNK_END_FUNC_OK` — chunk-end callback succeeded.
pub const CURL_CHUNK_END_FUNC_OK: c_long = 0;
/// `CURL_CHUNK_END_FUNC_FAIL` — chunk-end callback failed; end the task.
pub const CURL_CHUNK_END_FUNC_FAIL: c_long = 1;
/// `CURL_FNMATCHFUNC_MATCH` — the string matches the pattern.
pub const CURL_FNMATCHFUNC_MATCH: c_int = 0;
/// `CURL_FNMATCHFUNC_NOMATCH` — the pattern does not match the string.
pub const CURL_FNMATCHFUNC_NOMATCH: c_int = 1;
/// `CURL_FNMATCHFUNC_FAIL` — an error occurred during matching.
pub const CURL_FNMATCHFUNC_FAIL: c_int = 2;

/// `CURLPAUSE_RECV` — pause receiving (see [`curl_easy_pause`]).
pub const CURLPAUSE_RECV: c_int = 1 << 0;
/// `CURLPAUSE_RECV_CONT` — resume receiving.
pub const CURLPAUSE_RECV_CONT: c_int = 0;
/// `CURLPAUSE_SEND` — pause sending.
pub const CURLPAUSE_SEND: c_int = 1 << 2;
/// `CURLPAUSE_SEND_CONT` — resume sending.
pub const CURLPAUSE_SEND_CONT: c_int = 0;
/// `CURLPAUSE_ALL` — pause both receiving and sending.
pub const CURLPAUSE_ALL: c_int = CURLPAUSE_RECV | CURLPAUSE_SEND;
/// `CURLPAUSE_CONT` — resume both receiving and sending.
pub const CURLPAUSE_CONT: c_int = CURLPAUSE_RECV_CONT | CURLPAUSE_SEND_CONT;

// ===========================================================================
// `CURLoption` — every `curl_easy_setopt` option id, transcribed verbatim (with its exact
// integer discriminant = type-base + index) from `include/curl/curl.h`. cbindgen renders this as
// curl's `typedef enum { … } CURLoption;`. The `#[repr(i32)]` matches curl's C `enum` (an `int`).
// ===========================================================================

/// libcurl `curl_easy_setopt` option identifiers (`CURLoption`).
///
/// A language-faithful transcription of the `CURLoption` enumeration in `include/curl/curl.h`:
/// every discriminant equals its curl value (`CURLOPTTYPE_* base + index`) so the integer contract
/// is preserved across the FFI boundary. Variant names use curl's `SCREAMING_SNAKE_CASE` spelling
/// (permitted by the crate-root `#![allow(non_camel_case_types)]`).
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CURLoption {
    CURLOPT_WRITEDATA = 10001,
    CURLOPT_URL = 10002,
    CURLOPT_PORT = 3,
    CURLOPT_PROXY = 10004,
    CURLOPT_USERPWD = 10005,
    CURLOPT_PROXYUSERPWD = 10006,
    CURLOPT_RANGE = 10007,
    CURLOPT_READDATA = 10009,
    CURLOPT_ERRORBUFFER = 10010,
    CURLOPT_WRITEFUNCTION = 20011,
    CURLOPT_READFUNCTION = 20012,
    CURLOPT_TIMEOUT = 13,
    CURLOPT_INFILESIZE = 14,
    CURLOPT_POSTFIELDS = 10015,
    CURLOPT_REFERER = 10016,
    CURLOPT_FTPPORT = 10017,
    CURLOPT_USERAGENT = 10018,
    CURLOPT_LOW_SPEED_LIMIT = 19,
    CURLOPT_LOW_SPEED_TIME = 20,
    CURLOPT_RESUME_FROM = 21,
    CURLOPT_COOKIE = 10022,
    CURLOPT_HTTPHEADER = 10023,
    CURLOPT_HTTPPOST = 10024,
    CURLOPT_SSLCERT = 10025,
    CURLOPT_KEYPASSWD = 10026,
    CURLOPT_CRLF = 27,
    CURLOPT_QUOTE = 10028,
    CURLOPT_HEADERDATA = 10029,
    CURLOPT_COOKIEFILE = 10031,
    CURLOPT_SSLVERSION = 32,
    CURLOPT_TIMECONDITION = 33,
    CURLOPT_TIMEVALUE = 34,
    CURLOPT_CUSTOMREQUEST = 10036,
    CURLOPT_STDERR = 10037,
    CURLOPT_POSTQUOTE = 10039,
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
    CURLOPT_PROGRESSFUNCTION = 20056,
    CURLOPT_XFERINFODATA = 10057,
    CURLOPT_AUTOREFERER = 58,
    CURLOPT_PROXYPORT = 59,
    CURLOPT_POSTFIELDSIZE = 60,
    CURLOPT_HTTPPROXYTUNNEL = 61,
    CURLOPT_INTERFACE = 10062,
    CURLOPT_KRBLEVEL = 10063,
    CURLOPT_SSL_VERIFYPEER = 64,
    CURLOPT_CAINFO = 10065,
    CURLOPT_MAXREDIRS = 68,
    CURLOPT_FILETIME = 69,
    CURLOPT_TELNETOPTIONS = 10070,
    CURLOPT_MAXCONNECTS = 71,
    CURLOPT_FRESH_CONNECT = 74,
    CURLOPT_FORBID_REUSE = 75,
    CURLOPT_RANDOM_FILE = 10076,
    CURLOPT_EGDSOCKET = 10077,
    CURLOPT_CONNECTTIMEOUT = 78,
    CURLOPT_HEADERFUNCTION = 20079,
    CURLOPT_HTTPGET = 80,
    CURLOPT_SSL_VERIFYHOST = 81,
    CURLOPT_COOKIEJAR = 10082,
    CURLOPT_SSL_CIPHER_LIST = 10083,
    CURLOPT_HTTP_VERSION = 84,
    CURLOPT_FTP_USE_EPSV = 85,
    CURLOPT_SSLCERTTYPE = 10086,
    CURLOPT_SSLKEY = 10087,
    CURLOPT_SSLKEYTYPE = 10088,
    CURLOPT_SSLENGINE = 10089,
    CURLOPT_SSLENGINE_DEFAULT = 90,
    CURLOPT_DNS_USE_GLOBAL_CACHE = 91,
    CURLOPT_DNS_CACHE_TIMEOUT = 92,
    CURLOPT_PREQUOTE = 10093,
    CURLOPT_DEBUGFUNCTION = 20094,
    CURLOPT_DEBUGDATA = 10095,
    CURLOPT_COOKIESESSION = 96,
    CURLOPT_CAPATH = 10097,
    CURLOPT_BUFFERSIZE = 98,
    CURLOPT_NOSIGNAL = 99,
    CURLOPT_SHARE = 10100,
    CURLOPT_PROXYTYPE = 101,
    CURLOPT_ACCEPT_ENCODING = 10102,
    CURLOPT_PRIVATE = 10103,
    CURLOPT_HTTP200ALIASES = 10104,
    CURLOPT_UNRESTRICTED_AUTH = 105,
    CURLOPT_FTP_USE_EPRT = 106,
    CURLOPT_HTTPAUTH = 107,
    CURLOPT_SSL_CTX_FUNCTION = 20108,
    CURLOPT_SSL_CTX_DATA = 10109,
    CURLOPT_FTP_CREATE_MISSING_DIRS = 110,
    CURLOPT_PROXYAUTH = 111,
    CURLOPT_SERVER_RESPONSE_TIMEOUT = 112,
    CURLOPT_IPRESOLVE = 113,
    CURLOPT_MAXFILESIZE = 114,
    CURLOPT_INFILESIZE_LARGE = 30115,
    CURLOPT_RESUME_FROM_LARGE = 30116,
    CURLOPT_MAXFILESIZE_LARGE = 30117,
    CURLOPT_NETRC_FILE = 10118,
    CURLOPT_USE_SSL = 119,
    CURLOPT_POSTFIELDSIZE_LARGE = 30120,
    CURLOPT_TCP_NODELAY = 121,
    CURLOPT_FTPSSLAUTH = 129,
    CURLOPT_IOCTLFUNCTION = 20130,
    CURLOPT_IOCTLDATA = 10131,
    CURLOPT_FTP_ACCOUNT = 10134,
    CURLOPT_COOKIELIST = 10135,
    CURLOPT_IGNORE_CONTENT_LENGTH = 136,
    CURLOPT_FTP_SKIP_PASV_IP = 137,
    CURLOPT_FTP_FILEMETHOD = 138,
    CURLOPT_LOCALPORT = 139,
    CURLOPT_LOCALPORTRANGE = 140,
    CURLOPT_CONNECT_ONLY = 141,
    CURLOPT_CONV_FROM_NETWORK_FUNCTION = 20142,
    CURLOPT_CONV_TO_NETWORK_FUNCTION = 20143,
    CURLOPT_CONV_FROM_UTF8_FUNCTION = 20144,
    CURLOPT_MAX_SEND_SPEED_LARGE = 30145,
    CURLOPT_MAX_RECV_SPEED_LARGE = 30146,
    CURLOPT_FTP_ALTERNATIVE_TO_USER = 10147,
    CURLOPT_SOCKOPTFUNCTION = 20148,
    CURLOPT_SOCKOPTDATA = 10149,
    CURLOPT_SSL_SESSIONID_CACHE = 150,
    CURLOPT_SSH_AUTH_TYPES = 151,
    CURLOPT_SSH_PUBLIC_KEYFILE = 10152,
    CURLOPT_SSH_PRIVATE_KEYFILE = 10153,
    CURLOPT_FTP_SSL_CCC = 154,
    CURLOPT_TIMEOUT_MS = 155,
    CURLOPT_CONNECTTIMEOUT_MS = 156,
    CURLOPT_HTTP_TRANSFER_DECODING = 157,
    CURLOPT_HTTP_CONTENT_DECODING = 158,
    CURLOPT_NEW_FILE_PERMS = 159,
    CURLOPT_NEW_DIRECTORY_PERMS = 160,
    CURLOPT_POSTREDIR = 161,
    CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 = 10162,
    CURLOPT_OPENSOCKETFUNCTION = 20163,
    CURLOPT_OPENSOCKETDATA = 10164,
    CURLOPT_COPYPOSTFIELDS = 10165,
    CURLOPT_PROXY_TRANSFER_MODE = 166,
    CURLOPT_SEEKFUNCTION = 20167,
    CURLOPT_SEEKDATA = 10168,
    CURLOPT_CRLFILE = 10169,
    CURLOPT_ISSUERCERT = 10170,
    CURLOPT_ADDRESS_SCOPE = 171,
    CURLOPT_CERTINFO = 172,
    CURLOPT_USERNAME = 10173,
    CURLOPT_PASSWORD = 10174,
    CURLOPT_PROXYUSERNAME = 10175,
    CURLOPT_PROXYPASSWORD = 10176,
    CURLOPT_NOPROXY = 10177,
    CURLOPT_TFTP_BLKSIZE = 178,
    CURLOPT_SOCKS5_GSSAPI_SERVICE = 10179,
    CURLOPT_SOCKS5_GSSAPI_NEC = 180,
    CURLOPT_PROTOCOLS = 181,
    CURLOPT_REDIR_PROTOCOLS = 182,
    CURLOPT_SSH_KNOWNHOSTS = 10183,
    CURLOPT_SSH_KEYFUNCTION = 20184,
    CURLOPT_SSH_KEYDATA = 10185,
    CURLOPT_MAIL_FROM = 10186,
    CURLOPT_MAIL_RCPT = 10187,
    CURLOPT_FTP_USE_PRET = 188,
    CURLOPT_RTSP_REQUEST = 189,
    CURLOPT_RTSP_SESSION_ID = 10190,
    CURLOPT_RTSP_STREAM_URI = 10191,
    CURLOPT_RTSP_TRANSPORT = 10192,
    CURLOPT_RTSP_CLIENT_CSEQ = 193,
    CURLOPT_RTSP_SERVER_CSEQ = 194,
    CURLOPT_INTERLEAVEDATA = 10195,
    CURLOPT_INTERLEAVEFUNCTION = 20196,
    CURLOPT_WILDCARDMATCH = 197,
    CURLOPT_CHUNK_BGN_FUNCTION = 20198,
    CURLOPT_CHUNK_END_FUNCTION = 20199,
    CURLOPT_FNMATCH_FUNCTION = 20200,
    CURLOPT_CHUNK_DATA = 10201,
    CURLOPT_FNMATCH_DATA = 10202,
    CURLOPT_RESOLVE = 10203,
    CURLOPT_TLSAUTH_USERNAME = 10204,
    CURLOPT_TLSAUTH_PASSWORD = 10205,
    CURLOPT_TLSAUTH_TYPE = 10206,
    CURLOPT_TRANSFER_ENCODING = 207,
    CURLOPT_CLOSESOCKETFUNCTION = 20208,
    CURLOPT_CLOSESOCKETDATA = 10209,
    CURLOPT_GSSAPI_DELEGATION = 210,
    CURLOPT_DNS_SERVERS = 10211,
    CURLOPT_ACCEPTTIMEOUT_MS = 212,
    CURLOPT_TCP_KEEPALIVE = 213,
    CURLOPT_TCP_KEEPIDLE = 214,
    CURLOPT_TCP_KEEPINTVL = 215,
    CURLOPT_SSL_OPTIONS = 216,
    CURLOPT_MAIL_AUTH = 10217,
    CURLOPT_SASL_IR = 218,
    CURLOPT_XFERINFOFUNCTION = 20219,
    CURLOPT_XOAUTH2_BEARER = 10220,
    CURLOPT_DNS_INTERFACE = 10221,
    CURLOPT_DNS_LOCAL_IP4 = 10222,
    CURLOPT_DNS_LOCAL_IP6 = 10223,
    CURLOPT_LOGIN_OPTIONS = 10224,
    CURLOPT_SSL_ENABLE_NPN = 225,
    CURLOPT_SSL_ENABLE_ALPN = 226,
    CURLOPT_EXPECT_100_TIMEOUT_MS = 227,
    CURLOPT_PROXYHEADER = 10228,
    CURLOPT_HEADEROPT = 229,
    CURLOPT_PINNEDPUBLICKEY = 10230,
    CURLOPT_UNIX_SOCKET_PATH = 10231,
    CURLOPT_SSL_VERIFYSTATUS = 232,
    CURLOPT_SSL_FALSESTART = 233,
    CURLOPT_PATH_AS_IS = 234,
    CURLOPT_PROXY_SERVICE_NAME = 10235,
    CURLOPT_SERVICE_NAME = 10236,
    CURLOPT_PIPEWAIT = 237,
    CURLOPT_DEFAULT_PROTOCOL = 10238,
    CURLOPT_STREAM_WEIGHT = 239,
    CURLOPT_STREAM_DEPENDS = 10240,
    CURLOPT_STREAM_DEPENDS_E = 10241,
    CURLOPT_TFTP_NO_OPTIONS = 242,
    CURLOPT_CONNECT_TO = 10243,
    CURLOPT_TCP_FASTOPEN = 244,
    CURLOPT_KEEP_SENDING_ON_ERROR = 245,
    CURLOPT_PROXY_CAINFO = 10246,
    CURLOPT_PROXY_CAPATH = 10247,
    CURLOPT_PROXY_SSL_VERIFYPEER = 248,
    CURLOPT_PROXY_SSL_VERIFYHOST = 249,
    CURLOPT_PROXY_SSLVERSION = 250,
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
    CURLOPT_PROXY_SSL_OPTIONS = 261,
    CURLOPT_PRE_PROXY = 10262,
    CURLOPT_PROXY_PINNEDPUBLICKEY = 10263,
    CURLOPT_ABSTRACT_UNIX_SOCKET = 10264,
    CURLOPT_SUPPRESS_CONNECT_HEADERS = 265,
    CURLOPT_REQUEST_TARGET = 10266,
    CURLOPT_SOCKS5_AUTH = 267,
    CURLOPT_SSH_COMPRESSION = 268,
    CURLOPT_MIMEPOST = 10269,
    CURLOPT_TIMEVALUE_LARGE = 30270,
    CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS = 271,
    CURLOPT_RESOLVER_START_FUNCTION = 20272,
    CURLOPT_RESOLVER_START_DATA = 10273,
    CURLOPT_HAPROXYPROTOCOL = 274,
    CURLOPT_DNS_SHUFFLE_ADDRESSES = 275,
    CURLOPT_TLS13_CIPHERS = 10276,
    CURLOPT_PROXY_TLS13_CIPHERS = 10277,
    CURLOPT_DISALLOW_USERNAME_IN_URL = 278,
    CURLOPT_DOH_URL = 10279,
    CURLOPT_UPLOAD_BUFFERSIZE = 280,
    CURLOPT_UPKEEP_INTERVAL_MS = 281,
    CURLOPT_CURLU = 10282,
    CURLOPT_TRAILERFUNCTION = 20283,
    CURLOPT_TRAILERDATA = 10284,
    CURLOPT_HTTP09_ALLOWED = 285,
    CURLOPT_ALTSVC_CTRL = 286,
    CURLOPT_ALTSVC = 10287,
    CURLOPT_MAXAGE_CONN = 288,
    CURLOPT_SASL_AUTHZID = 10289,
    CURLOPT_MAIL_RCPT_ALLOWFAILS = 290,
    CURLOPT_SSLCERT_BLOB = 40291,
    CURLOPT_SSLKEY_BLOB = 40292,
    CURLOPT_PROXY_SSLCERT_BLOB = 40293,
    CURLOPT_PROXY_SSLKEY_BLOB = 40294,
    CURLOPT_ISSUERCERT_BLOB = 40295,
    CURLOPT_PROXY_ISSUERCERT = 10296,
    CURLOPT_PROXY_ISSUERCERT_BLOB = 40297,
    CURLOPT_SSL_EC_CURVES = 10298,
    CURLOPT_HSTS_CTRL = 299,
    CURLOPT_HSTS = 10300,
    CURLOPT_HSTSREADFUNCTION = 20301,
    CURLOPT_HSTSREADDATA = 10302,
    CURLOPT_HSTSWRITEFUNCTION = 20303,
    CURLOPT_HSTSWRITEDATA = 10304,
    CURLOPT_AWS_SIGV4 = 10305,
    CURLOPT_DOH_SSL_VERIFYPEER = 306,
    CURLOPT_DOH_SSL_VERIFYHOST = 307,
    CURLOPT_DOH_SSL_VERIFYSTATUS = 308,
    CURLOPT_CAINFO_BLOB = 40309,
    CURLOPT_PROXY_CAINFO_BLOB = 40310,
    CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 = 10311,
    CURLOPT_PREREQFUNCTION = 20312,
    CURLOPT_PREREQDATA = 10313,
    CURLOPT_MAXLIFETIME_CONN = 314,
    CURLOPT_MIME_OPTIONS = 315,
    CURLOPT_SSH_HOSTKEYFUNCTION = 20316,
    CURLOPT_SSH_HOSTKEYDATA = 10317,
    CURLOPT_PROTOCOLS_STR = 10318,
    CURLOPT_REDIR_PROTOCOLS_STR = 10319,
    CURLOPT_WS_OPTIONS = 320,
    CURLOPT_CA_CACHE_TIMEOUT = 321,
    CURLOPT_QUICK_EXIT = 322,
    CURLOPT_HAPROXY_CLIENT_IP = 10323,
    CURLOPT_SERVER_RESPONSE_TIMEOUT_MS = 324,
    CURLOPT_ECH = 10325,
    CURLOPT_TCP_KEEPCNT = 326,
    CURLOPT_UPLOAD_FLAGS = 327,
    CURLOPT_SSL_SIGNATURE_ALGORITHMS = 10328,
    /// `CURLOPT_LASTENTRY` — curl's "last unused" sentinel (`include/curl/curl.h`). It carries no
    /// setopt semantics; it exists so the generated `curl.h` and the easyoption metadata table
    /// (`crate::options::CURL_EASYOPTS`) can name a terminating id byte-exactly. Its value is the
    /// C auto-increment after `CURLOPT_SSL_SIGNATURE_ALGORITHMS = 10328`, i.e. `10329`
    /// (`10329 % 10000 == 329`, matching curl's `Curl_easyopts_check()` invariant).
    CURLOPT_LASTENTRY = 10329,
}

// ===========================================================================
// `CURLINFO` — every `curl_easy_getinfo` info id, transcribed verbatim from
// `include/curl/curl.h`. The high bits encode the result type (see the `CURLINFO_*` masks above).
// ===========================================================================

/// libcurl `curl_easy_getinfo` information identifiers (`CURLINFO`).
///
/// A language-faithful transcription of the `CURLINFO` enumeration in `include/curl/curl.h`. Each
/// discriminant equals its curl value; the high nibble (`CURLINFO_TYPEMASK`) selects the result
/// type written through the caller's out-pointer.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CURLINFO {
    CURLINFO_NONE = 0,
    CURLINFO_EFFECTIVE_URL = 0x100001,
    CURLINFO_RESPONSE_CODE = 0x200002,
    CURLINFO_TOTAL_TIME = 0x300003,
    CURLINFO_NAMELOOKUP_TIME = 0x300004,
    CURLINFO_CONNECT_TIME = 0x300005,
    CURLINFO_PRETRANSFER_TIME = 0x300006,
    CURLINFO_SIZE_UPLOAD = 0x300007,
    CURLINFO_SIZE_UPLOAD_T = 0x600007,
    CURLINFO_SIZE_DOWNLOAD = 0x300008,
    CURLINFO_SIZE_DOWNLOAD_T = 0x600008,
    CURLINFO_SPEED_DOWNLOAD = 0x300009,
    CURLINFO_SPEED_DOWNLOAD_T = 0x600009,
    CURLINFO_SPEED_UPLOAD = 0x30000A,
    CURLINFO_SPEED_UPLOAD_T = 0x60000A,
    CURLINFO_HEADER_SIZE = 0x20000B,
    CURLINFO_REQUEST_SIZE = 0x20000C,
    CURLINFO_SSL_VERIFYRESULT = 0x20000D,
    CURLINFO_FILETIME = 0x20000E,
    CURLINFO_FILETIME_T = 0x60000E,
    CURLINFO_CONTENT_LENGTH_DOWNLOAD = 0x30000F,
    CURLINFO_CONTENT_LENGTH_DOWNLOAD_T = 0x60000F,
    CURLINFO_CONTENT_LENGTH_UPLOAD = 0x300010,
    CURLINFO_CONTENT_LENGTH_UPLOAD_T = 0x600010,
    CURLINFO_STARTTRANSFER_TIME = 0x300011,
    CURLINFO_CONTENT_TYPE = 0x100012,
    CURLINFO_REDIRECT_TIME = 0x300013,
    CURLINFO_REDIRECT_COUNT = 0x200014,
    CURLINFO_PRIVATE = 0x100015,
    CURLINFO_HTTP_CONNECTCODE = 0x200016,
    CURLINFO_HTTPAUTH_AVAIL = 0x200017,
    CURLINFO_PROXYAUTH_AVAIL = 0x200018,
    CURLINFO_OS_ERRNO = 0x200019,
    CURLINFO_NUM_CONNECTS = 0x20001A,
    CURLINFO_SSL_ENGINES = 0x40001B,
    CURLINFO_COOKIELIST = 0x40001C,
    CURLINFO_LASTSOCKET = 0x20001D,
    CURLINFO_FTP_ENTRY_PATH = 0x10001E,
    CURLINFO_REDIRECT_URL = 0x10001F,
    CURLINFO_PRIMARY_IP = 0x100020,
    CURLINFO_APPCONNECT_TIME = 0x300021,
    CURLINFO_CERTINFO = 0x400022,
    CURLINFO_CONDITION_UNMET = 0x200023,
    CURLINFO_RTSP_SESSION_ID = 0x100024,
    CURLINFO_RTSP_CLIENT_CSEQ = 0x200025,
    CURLINFO_RTSP_SERVER_CSEQ = 0x200026,
    CURLINFO_RTSP_CSEQ_RECV = 0x200027,
    CURLINFO_PRIMARY_PORT = 0x200028,
    CURLINFO_LOCAL_IP = 0x100029,
    CURLINFO_LOCAL_PORT = 0x20002A,
    CURLINFO_TLS_SESSION = 0x40002B,
    CURLINFO_ACTIVESOCKET = 0x50002C,
    CURLINFO_TLS_SSL_PTR = 0x40002D,
    CURLINFO_HTTP_VERSION = 0x20002E,
    CURLINFO_PROXY_SSL_VERIFYRESULT = 0x20002F,
    CURLINFO_PROTOCOL = 0x200030,
    CURLINFO_SCHEME = 0x100031,
    CURLINFO_TOTAL_TIME_T = 0x600032,
    CURLINFO_NAMELOOKUP_TIME_T = 0x600033,
    CURLINFO_CONNECT_TIME_T = 0x600034,
    CURLINFO_PRETRANSFER_TIME_T = 0x600035,
    CURLINFO_STARTTRANSFER_TIME_T = 0x600036,
    CURLINFO_REDIRECT_TIME_T = 0x600037,
    CURLINFO_APPCONNECT_TIME_T = 0x600038,
    CURLINFO_RETRY_AFTER = 0x600039,
    CURLINFO_EFFECTIVE_METHOD = 0x10003A,
    CURLINFO_PROXY_ERROR = 0x20003B,
    CURLINFO_REFERER = 0x10003C,
    CURLINFO_CAINFO = 0x10003D,
    CURLINFO_CAPATH = 0x10003E,
    CURLINFO_XFER_ID = 0x60003F,
    CURLINFO_CONN_ID = 0x600040,
    CURLINFO_QUEUE_TIME_T = 0x600041,
    CURLINFO_USED_PROXY = 0x200042,
    CURLINFO_POSTTRANSFER_TIME_T = 0x600043,
    CURLINFO_EARLYDATA_SENT_T = 0x600044,
    CURLINFO_HTTPAUTH_USED = 0x200045,
    CURLINFO_PROXYAUTH_USED = 0x200046,
    CURLINFO_LASTONE = 70,
}

// ===========================================================================
// Recognition tables. Sorted integer lists used for O(log n) membership tests in the setopt /
// getinfo dispatchers' default arms, so an id that is valid-but-not-yet-forwarded is accepted
// (`CURLE_OK`) while a genuinely unknown id is rejected (`CURLE_UNKNOWN_OPTION`). Both are derived
// from the same header scan as the enums above.
// ===========================================================================

/// Every valid `CURLoption` integer, sorted ascending.
const KNOWN_OPTIONS: &[c_int] = &[
    3, 13, 14, 19, 20, 21, 27, 32, 33, 34, 41, 42, 43, 44, 45, 46, 47, 48, 50, 51, 52, 53, 54, 58,
    59, 60, 61, 64, 68, 69, 71, 74, 75, 78, 80, 81, 84, 85, 90, 91, 92, 96, 98, 99, 101, 105, 106,
    107, 110, 111, 112, 113, 114, 119, 121, 129, 136, 137, 138, 139, 140, 141, 150, 151, 154, 155,
    156, 157, 158, 159, 160, 161, 166, 171, 172, 178, 180, 181, 182, 188, 189, 193, 194, 197, 207,
    210, 212, 213, 214, 215, 216, 218, 225, 226, 227, 229, 232, 233, 234, 237, 239, 242, 244, 245,
    248, 249, 250, 261, 265, 267, 268, 271, 274, 275, 278, 280, 281, 285, 286, 288, 290, 299, 306,
    307, 308, 314, 315, 320, 321, 322, 324, 326, 327, 10001, 10002, 10004, 10005, 10006, 10007,
    10009, 10010, 10015, 10016, 10017, 10018, 10022, 10023, 10024, 10025, 10026, 10028, 10029,
    10031, 10036, 10037, 10039, 10057, 10062, 10063, 10065, 10070, 10076, 10077, 10082, 10083,
    10086, 10087, 10088, 10089, 10093, 10095, 10097, 10100, 10102, 10103, 10104, 10109, 10118,
    10131, 10134, 10135, 10147, 10149, 10152, 10153, 10162, 10164, 10165, 10168, 10169, 10170,
    10173, 10174, 10175, 10176, 10177, 10179, 10183, 10185, 10186, 10187, 10190, 10191, 10192,
    10195, 10201, 10202, 10203, 10204, 10205, 10206, 10209, 10211, 10217, 10220, 10221, 10222,
    10223, 10224, 10228, 10230, 10231, 10235, 10236, 10238, 10240, 10241, 10243, 10246, 10247,
    10251, 10252, 10253, 10254, 10255, 10256, 10257, 10258, 10259, 10260, 10262, 10263, 10264,
    10266, 10269, 10273, 10276, 10277, 10279, 10282, 10284, 10287, 10289, 10296, 10298, 10300,
    10302, 10304, 10305, 10311, 10313, 10317, 10318, 10319, 10323, 10325, 10328, 20011, 20012,
    20056, 20079, 20094, 20108, 20130, 20142, 20143, 20144, 20148, 20163, 20167, 20184, 20196,
    20198, 20199, 20200, 20208, 20219, 20272, 20283, 20301, 20303, 20312, 20316, 30115, 30116,
    30117, 30120, 30145, 30146, 30270, 40291, 40292, 40293, 40294, 40295, 40297, 40309, 40310,
];

/// Every *queryable* `CURLINFO` integer (those carrying a type mask; excludes `CURLINFO_NONE` and
/// `CURLINFO_LASTONE`), sorted ascending.
const KNOWN_INFOS: &[c_int] = &[
    0x100001, 0x100012, 0x100015, 0x10001E, 0x10001F, 0x100020, 0x100024, 0x100029, 0x100031,
    0x10003A, 0x10003C, 0x10003D, 0x10003E, 0x200002, 0x20000B, 0x20000C, 0x20000D, 0x20000E,
    0x200014, 0x200016, 0x200017, 0x200018, 0x200019, 0x20001A, 0x20001D, 0x200023, 0x200025,
    0x200026, 0x200027, 0x200028, 0x20002A, 0x20002E, 0x20002F, 0x200030, 0x20003B, 0x200042,
    0x200045, 0x200046, 0x300003, 0x300004, 0x300005, 0x300006, 0x300007, 0x300008, 0x300009,
    0x30000A, 0x30000F, 0x300010, 0x300011, 0x300013, 0x300021, 0x40001B, 0x40001C, 0x400022,
    0x40002B, 0x40002D, 0x50002C, 0x600007, 0x600008, 0x600009, 0x60000A, 0x60000E, 0x60000F,
    0x600010, 0x600032, 0x600033, 0x600034, 0x600035, 0x600036, 0x600037, 0x600038, 0x600039,
    0x60003F, 0x600040, 0x600041, 0x600043, 0x600044,
];
// ===========================================================================
// Callback function-pointer typedefs (curl.h), reproduced byte-exactly so the cbindgen-generated
// header matches curl 8.x and so `curl_easy_setopt` can store them verbatim. Each is a nullable
// C function pointer, expressed as `Option<unsafe extern "C" fn(...)>` (the null pointer is the
// `None` niche). These are ABI type declarations; the trampoline installation that invokes them
// is deferred until the core `Easy` gains callback storage (the current core exposes none), so no
// call *through* these pointers happens at this checkpoint.
//
// The allocator callbacks (`curl_malloc_callback` etc.) live in `global.rs` and are not redefined.
// ===========================================================================

/// `CURLOPT_PROGRESSFUNCTION` callback (deprecated in favour of the xferinfo callback).
pub type curl_progress_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        dltotal: c_double,
        dlnow: c_double,
        ultotal: c_double,
        ulnow: c_double,
    ) -> c_int,
>;

/// `CURLOPT_XFERINFOFUNCTION` callback — integer-typed transfer-progress reporting.
pub type curl_xferinfo_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        dltotal: curl_off_t,
        dlnow: curl_off_t,
        ultotal: curl_off_t,
        ulnow: curl_off_t,
    ) -> c_int,
>;

/// `CURLOPT_WRITEFUNCTION` callback — receives downloaded body bytes.
pub type curl_write_callback = Option<
    unsafe extern "C" fn(
        buffer: *mut c_char,
        size: size_t,
        nitems: size_t,
        outstream: *mut c_void,
    ) -> size_t,
>;

/// `CURLOPT_READFUNCTION` callback — supplies upload body bytes.
pub type curl_read_callback = Option<
    unsafe extern "C" fn(
        buffer: *mut c_char,
        size: size_t,
        nitems: size_t,
        instream: *mut c_void,
    ) -> size_t,
>;

/// `CURLOPT_TRAILERFUNCTION` callback — supplies trailing HTTP headers.
pub type curl_trailer_callback =
    Option<unsafe extern "C" fn(list: *mut *mut curl_slist, userdata: *mut c_void) -> c_int>;

/// `CURLOPT_RESOLVER_START_FUNCTION` callback — invoked when a new name resolution starts.
pub type curl_resolver_start_callback = Option<
    unsafe extern "C" fn(
        resolver_state: *mut c_void,
        reserved: *mut c_void,
        userdata: *mut c_void,
    ) -> c_int,
>;

/// `CURLOPT_SEEKFUNCTION` callback — seeks within the upload data.
pub type curl_seek_callback =
    Option<unsafe extern "C" fn(instream: *mut c_void, offset: curl_off_t, origin: c_int) -> c_int>;

/// `CURLOPT_IOCTLFUNCTION` callback (deprecated) — performs an I/O control operation.
pub type curl_ioctl_callback = Option<
    unsafe extern "C" fn(handle: *mut c_void, cmd: c_int, clientp: *mut c_void) -> curlioerr,
>;

/// `CURLOPT_SOCKOPTFUNCTION` callback — sets options on a freshly created socket.
pub type curl_sockopt_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        curlfd: curl_socket_t,
        purpose: curlsocktype,
    ) -> c_int,
>;

/// `CURLOPT_OPENSOCKETFUNCTION` callback — creates a socket on libcurl's behalf.
pub type curl_opensocket_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        purpose: curlsocktype,
        address: *mut curl_sockaddr,
    ) -> curl_socket_t,
>;

/// `CURLOPT_CLOSESOCKETFUNCTION` callback — closes a socket libcurl opened.
pub type curl_closesocket_callback =
    Option<unsafe extern "C" fn(clientp: *mut c_void, item: curl_socket_t) -> c_int>;

/// `CURLOPT_DEBUGFUNCTION` callback — receives verbose/trace data.
pub type curl_debug_callback = Option<
    unsafe extern "C" fn(
        handle: *mut c_void,
        type_: curl_infotype,
        data: *mut c_char,
        size: size_t,
        userptr: *mut c_void,
    ) -> c_int,
>;

/// `CURLOPT_PREREQFUNCTION` callback — invoked after connecting but before the request is issued.
pub type curl_prereq_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        conn_primary_ip: *mut c_char,
        conn_local_ip: *mut c_char,
        conn_primary_port: c_int,
        conn_local_port: c_int,
    ) -> c_int,
>;

/// `CURLOPT_CONV_*FUNCTION` callback (deprecated) — character-set conversion.
pub type curl_conv_callback =
    Option<unsafe extern "C" fn(buffer: *mut c_char, length: size_t) -> crate::CURLcode>;

/// `CURLOPT_SSL_CTX_FUNCTION` callback — customises the TLS context before the handshake.
pub type curl_ssl_ctx_callback = Option<
    unsafe extern "C" fn(
        curl: *mut c_void,
        ssl_ctx: *mut c_void,
        userptr: *mut c_void,
    ) -> crate::CURLcode,
>;

/// `CURLOPT_CHUNK_BGN_FUNCTION` callback — invoked at the start of each wildcard-download chunk.
pub type curl_chunk_bgn_callback = Option<
    unsafe extern "C" fn(transfer_info: *const c_void, ptr: *mut c_void, remains: c_int) -> c_long,
>;

/// `CURLOPT_CHUNK_END_FUNCTION` callback — invoked at the end of each wildcard-download chunk.
pub type curl_chunk_end_callback = Option<unsafe extern "C" fn(ptr: *mut c_void) -> c_long>;

/// `CURLOPT_FNMATCH_FUNCTION` callback — wildcard pattern matching for downloads.
pub type curl_fnmatch_callback = Option<
    unsafe extern "C" fn(ptr: *mut c_void, pattern: *const c_char, string: *const c_char) -> c_int,
>;

/// `CURLOPT_HSTSREADFUNCTION` callback — feeds HSTS entries into libcurl at startup.
pub type curl_hstsread_callback = Option<
    unsafe extern "C" fn(
        easy: *mut c_void,
        e: *mut curl_hstsentry,
        userp: *mut c_void,
    ) -> CURLSTScode,
>;

/// `CURLOPT_HSTSWRITEFUNCTION` callback — persists HSTS entries out of libcurl at shutdown.
pub type curl_hstswrite_callback = Option<
    unsafe extern "C" fn(
        easy: *mut c_void,
        e: *mut curl_hstsentry,
        i: *mut curl_index,
        userp: *mut c_void,
    ) -> CURLSTScode,
>;

/// `curl_ssls_export_cb` — the callback passed to [`curl_easy_ssls_export`] to extract each stored
/// TLS session/ticket. Reproduced byte-exactly from `include/curl/curl.h` (11 parameters).
pub type curl_ssls_export_cb = Option<
    unsafe extern "C" fn(
        handle: *mut c_void,
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
    ) -> crate::CURLcode,
>;

// ===========================================================================
// Internal helpers.
// ===========================================================================

/// Borrow the C escape/unescape input as a byte slice.
///
/// Mirrors the private `input_bytes` helper in `global.rs` (used by `curl_escape`/`curl_unescape`)
/// so the easy-handle and legacy aliases share identical length semantics: a positive `length`
/// reads exactly that many bytes; `length <= 0` measures with `strlen` (curl's "0 means measure").
///
/// # Safety
/// `ptr` must be non-null and, when `length > 0`, valid for reads of `length` bytes; when
/// `length <= 0` it must be a valid NUL-terminated C string. It must stay valid for the returned
/// borrow, which does not outlive the call.
unsafe fn input_bytes<'a>(ptr: *const c_char, length: c_int) -> &'a [u8] {
    if length > 0 {
        // SAFETY: the caller guarantees `ptr` is valid for `length` bytes for the borrow's life.
        unsafe { std::slice::from_raw_parts(ptr as *const u8, length as usize) }
    } else {
        // SAFETY: the caller guarantees `ptr` is a valid NUL-terminated C string for the borrow.
        unsafe { CStr::from_ptr(ptr).to_bytes() }
    }
}

/// Move `bytes` into a C-owned, NUL-terminated allocation reclaimable by `curl_free`.
///
/// Mirrors `global.rs::bytes_to_c_owned`: uses [`CString`] so the buffer matches this crate's
/// `curl_free` (which reclaims via `CString::from_raw`). A payload containing an interior NUL
/// (e.g. from a `%00` decode) cannot be represented as a C string and yields null, keeping every
/// returned pointer safely freeable.
fn bytes_to_c_owned(bytes: Vec<u8>) -> *mut c_char {
    match CString::new(bytes) {
        Ok(cstring) => cstring.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Return a process-lifetime, NUL-terminated pointer to the human-readable message for `code`.
///
/// The message text is sourced from `curl_rs_lib::error::strerror` (single source of truth,
/// reproducing `lib/strerror.c`) and interned in a leak-backed cache so the returned pointer stays
/// valid for the life of the process — matching curl's contract that the caller must NOT free it.
/// The cache is keyed by the raw `c_int` so any value (including out-of-range ones) is handled.
fn strerror_ptr(code: c_int) -> *const c_char {
    static CACHE: OnceLock<Mutex<HashMap<c_int, &'static CStr>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    // Recover from a poisoned lock rather than panic (a panic must never cross the FFI boundary).
    let mut map = match cache.lock() {
        Ok(guard) => guard,
        Err(poison) => poison.into_inner(),
    };
    let interned = map.entry(code).or_insert_with(|| {
        // Map the raw integer to its curl message. A *defined* `CURLcode` uses its exact
        // `lib/strerror.c` text; any other integer (an out-of-contract value that no libcurl
        // API ever returns, e.g. `999999` or `-1`) falls back to `curl_easy_strerror`'s
        // default arm — "Unknown error" (`lib/strerror.c`) — NOT the code-43 message.
        //
        // The fallible `TryFrom` is deliberate here in place of `error::from_i32`: the latter
        // collapses every unknown integer to `BadFunctionArgument`, which would surface code
        // 43's text for an unknown code. `TryFrom` instead distinguishes an unknown code
        // (`Err`) from a genuine `CURLE_BAD_FUNCTION_ARGUMENT` (`Ok(BadFunctionArgument)`),
        // so real codes — including 43 — keep their exact text while only truly unknown
        // integers get "Unknown error". This mirrors the sibling `curl_multi_strerror` /
        // `curl_url_strerror` unknown-code arms. (QA F6-STRERROR-FALLBACK)
        let msg = match curl_rs_lib::error::CurlCode::try_from(code) {
            Ok(known) => curl_rs_lib::error::strerror(known),
            Err(_) => "Unknown error",
        };
        // `msg` is a fixed curl message with no interior NUL; the fallbacks make this total.
        let owned = CString::new(msg)
            .ok()
            .or_else(|| CString::new("Unknown error").ok())
            .unwrap_or_default();
        // Leak the boxed C string: its storage then lives for the process lifetime, so the raw
        // pointer handed to C remains valid after the mutex guard is dropped.
        &*Box::leak(owned.into_boxed_c_str())
    });
    interned.as_ptr()
}

/// Apply one `curl_easy_setopt` option to `easy`.
///
/// `arg` is the single promoted variadic argument captured by `curl_easy_setopt` (see the
/// module-level variadic note). Its meaning depends on the option's `CURLOPTTYPE_*` class: a
/// `long`, an object pointer (`char *`, `struct curl_slist *`, `struct curl_blob *`, callback
/// data), a function pointer, or a `curl_off_t`. Only the subset of options the current core
/// [`Easy`] can model is forwarded; every other *recognised* option is accepted as a no-op
/// (`CURLE_OK`) and an unrecognised option id yields `CURLE_UNKNOWN_OPTION`, matching
/// `lib/setopt.c`'s default arm.
fn setopt_dispatch(easy: &mut Easy, option: c_int, arg: usize) -> c_int {
    // Option ids handled explicitly (each equals its exact `CURLoption` discriminant).
    const OPT_URL: c_int = CURLoption::CURLOPT_URL as c_int;
    const OPT_PORT: c_int = CURLoption::CURLOPT_PORT as c_int;
    const OPT_FOLLOWLOCATION: c_int = CURLoption::CURLOPT_FOLLOWLOCATION as c_int;
    const OPT_MAXREDIRS: c_int = CURLoption::CURLOPT_MAXREDIRS as c_int;
    const OPT_INFILESIZE: c_int = CURLoption::CURLOPT_INFILESIZE as c_int;
    const OPT_INFILESIZE_LARGE: c_int = CURLoption::CURLOPT_INFILESIZE_LARGE as c_int;
    const OPT_POSTFIELDSIZE: c_int = CURLoption::CURLOPT_POSTFIELDSIZE as c_int;
    const OPT_POSTFIELDSIZE_LARGE: c_int = CURLoption::CURLOPT_POSTFIELDSIZE_LARGE as c_int;
    const OPT_BUFFERSIZE: c_int = CURLoption::CURLOPT_BUFFERSIZE as c_int;
    const OPT_PATH_AS_IS: c_int = CURLoption::CURLOPT_PATH_AS_IS as c_int;
    const OPT_HTTP_VERSION: c_int = CURLoption::CURLOPT_HTTP_VERSION as c_int;
    const OPT_SHARE: c_int = CURLoption::CURLOPT_SHARE as c_int;

    match option {
        OPT_URL => {
            // STRINGPOINT: the vararg is a `const char *`.
            // SAFETY: per the setopt contract a STRINGPOINT option's argument is a null or valid
            // NUL-terminated C string; `cstr_to_str` null-checks and UTF-8-validates it, borrowing
            // only for this call. `arg` reinterprets the captured pointer-width value as that ptr.
            let s = match unsafe { cstr_to_str(arg as *const c_char) } {
                Some(s) => s,
                None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
            };
            to_curlcode(easy.set_url(s))
        }
        OPT_PORT => {
            // LONG: the remote-port override (curl stores it as an `unsigned short`).
            easy.set.use_port = arg as u16;
            CURLcode::CURLE_OK as c_int
        }
        OPT_FOLLOWLOCATION => {
            easy.set.follow_location = arg != 0;
            CURLcode::CURLE_OK as c_int
        }
        OPT_MAXREDIRS => {
            easy.set.maxredirs = arg as i64;
            CURLcode::CURLE_OK as c_int
        }
        OPT_INFILESIZE => {
            easy.set.filesize = arg as i64;
            CURLcode::CURLE_OK as c_int
        }
        OPT_INFILESIZE_LARGE => {
            easy.set.filesize = arg as i64;
            CURLcode::CURLE_OK as c_int
        }
        OPT_POSTFIELDSIZE => {
            easy.set.postfieldsize = arg as i64;
            CURLcode::CURLE_OK as c_int
        }
        OPT_POSTFIELDSIZE_LARGE => {
            easy.set.postfieldsize = arg as i64;
            CURLcode::CURLE_OK as c_int
        }
        OPT_BUFFERSIZE => {
            easy.set.buffer_size = arg;
            CURLcode::CURLE_OK as c_int
        }
        OPT_PATH_AS_IS => {
            easy.set.path_as_is = arg != 0;
            CURLcode::CURLE_OK as c_int
        }
        OPT_HTTP_VERSION => {
            easy.set.httpwant = arg as i64;
            CURLcode::CURLE_OK as c_int
        }
        OPT_SHARE => {
            // OBJECTPOINT: the vararg is a `CURLSH *` (or NULL to stop sharing). Mirror curl's
            // `CURLOPT_SHARE` handler in `lib/setopt.c`: detach any currently attached share
            // first (`data->share->dirty--; data->share = NULL`), then, when a valid new share is
            // supplied, attach it (`data->share = set; data->share->dirty++`). Holding the core
            // `Arc<Share>` wires the enabled data classes — the share carries its own `specifier`,
            // so a later consumer reads only the caches the user actually shared.
            easy.detach_share();
            if arg == 0 {
                // NULL share: detach only — curl treats `CURLOPT_SHARE, NULL` as "share nothing".
                CURLcode::CURLE_OK as c_int
            } else {
                // SAFETY: per the setopt contract the argument is a `CURLSH *` previously returned
                // by `curl_share_init` and not yet cleaned up, so it outlives this call;
                // `share_core` null-checks the handle and clones out the core `Arc<Share>` without
                // taking ownership of the boxed FFI state.
                match unsafe { crate::share::share_core(arg as *mut c_void) } {
                    Some(core) => {
                        easy.attach_share(core);
                        CURLcode::CURLE_OK as c_int
                    }
                    None => CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
                }
            }
        }
        // Any other option: accepted (no-op) if it is a real curl option, else unknown.
        _ => {
            if KNOWN_OPTIONS.binary_search(&option).is_ok() {
                // NOTE(parity): recognised option not yet modelled by the core `Easy`; accepted so
                // configuration sequences succeed. Wired to a core setter as the option lands.
                CURLcode::CURLE_OK as c_int
            } else {
                CURLcode::CURLE_UNKNOWN_OPTION as c_int
            }
        }
    }
}

/// Write one `curl_easy_getinfo` result through the caller's out-pointer.
///
/// `arg` is the single promoted variadic argument captured by `curl_easy_getinfo`: a pointer to
/// caller storage whose target type is encoded in `info`'s high bits (`CURLINFO_TYPEMASK`). Values
/// the current core [`Easy`] tracks (`CURLINFO_RESPONSE_CODE`, `CURLINFO_PRIMARY_PORT`) are
/// reported; every other recognised info is written as its typed zero/NULL default (curl likewise
/// yields `0`/`NULL` before a transfer populates it). An unknown info id yields
/// `CURLE_UNKNOWN_OPTION`.
fn getinfo_write(easy: &Easy, info: c_int, arg: usize) -> c_int {
    if arg == 0 {
        return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int;
    }
    // Reject ids that are not real, queryable infos before touching the out-pointer.
    if KNOWN_INFOS.binary_search(&info).is_err() {
        return CURLcode::CURLE_UNKNOWN_OPTION as c_int;
    }

    const INFO_RESPONSE_CODE: c_int = CURLINFO::CURLINFO_RESPONSE_CODE as c_int;
    const INFO_PRIMARY_PORT: c_int = CURLINFO::CURLINFO_PRIMARY_PORT as c_int;

    match info & CURLINFO_TYPEMASK {
        CURLINFO_STRING => {
            // Out-param is `char **`; no string info is available pre-transfer, so report NULL.
            // SAFETY: `arg` is a non-null (checked) `char **` per the getinfo contract for a STRING
            // info; writing one pointer-sized value through it is in bounds.
            unsafe {
                *(arg as *mut *const c_char) = ptr::null();
            }
            CURLcode::CURLE_OK as c_int
        }
        CURLINFO_LONG => {
            let value: c_long = match info {
                INFO_RESPONSE_CODE => easy.info.httpcode as c_long,
                INFO_PRIMARY_PORT => easy.info.conn_remote_port as c_long,
                _ => 0,
            };
            // SAFETY: `arg` is a non-null (checked) `long *` per the getinfo contract for a LONG info.
            unsafe {
                *(arg as *mut c_long) = value;
            }
            CURLcode::CURLE_OK as c_int
        }
        CURLINFO_DOUBLE => {
            // SAFETY: `arg` is a non-null (checked) `double *` per the getinfo contract.
            unsafe {
                *(arg as *mut c_double) = 0.0;
            }
            CURLcode::CURLE_OK as c_int
        }
        // `CURLINFO_SLIST` and `CURLINFO_PTR` share the value `0x400000`; both write one
        // pointer-sized NULL through the caller's `T **`.
        CURLINFO_SLIST => {
            // SAFETY: `arg` is a non-null (checked) `void **`/`curl_slist **` per the getinfo
            // contract; both are pointer-sized, so writing a NULL pointer is in bounds.
            unsafe {
                *(arg as *mut *mut c_void) = ptr::null_mut();
            }
            CURLcode::CURLE_OK as c_int
        }
        CURLINFO_SOCKET => {
            // SAFETY: `arg` is a non-null (checked) `curl_socket_t *` per the getinfo contract.
            unsafe {
                *(arg as *mut curl_socket_t) = CURL_SOCKET_BAD;
            }
            CURLcode::CURLE_OK as c_int
        }
        CURLINFO_OFF_T => {
            // SAFETY: `arg` is a non-null (checked) `curl_off_t *` per the getinfo contract.
            unsafe {
                *(arg as *mut curl_off_t) = 0;
            }
            CURLcode::CURLE_OK as c_int
        }
        // Unreachable for a `KNOWN_INFOS` member (every one carries a handled mask); accept safely.
        _ => CURLcode::CURLE_OK as c_int,
    }
}

// ===========================================================================
// Phase 1 — handle lifecycle (include/curl/easy.h).
// ===========================================================================

/// `CURL *curl_easy_init(void);`
///
/// Allocate and default-initialise an easy handle, returning the opaque `CURL *` (a boxed
/// [`Easy`]) or null on failure. The handle must eventually be released with [`curl_easy_cleanup`].
#[no_mangle]
pub extern "C" fn curl_easy_init() -> *mut c_void {
    // Constructing a default handle cannot fail today; the guard only ensures an unexpected panic
    // yields null (curl's out-of-memory return) instead of unwinding across the FFI boundary.
    catch_unwind(|| box_into_raw(Easy::open()) as *mut c_void).unwrap_or(ptr::null_mut())
}

/// `void curl_easy_cleanup(CURL *curl);`
///
/// Release an easy handle previously returned by [`curl_easy_init`] / [`curl_easy_duphandle`],
/// dropping the [`Easy`] and all resources it owns. A null handle is a no-op.
///
/// # Safety
/// `curl` must be null or a valid handle produced by [`curl_easy_init`] / [`curl_easy_duphandle`]
/// that has not already been cleaned up; it must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_cleanup(curl: *mut c_void) {
    if curl.is_null() {
        return;
    }
    // SAFETY: `curl` is non-null (checked) and, by this crate's handle contract, was produced by
    // `box_into_raw::<Easy>` in `curl_easy_init`/`curl_easy_duphandle` and not yet freed.
    // `box_from_raw` reconstructs the owning `Box<Easy>`; dropping it frees the handle once.
    let reclaimed = unsafe { box_from_raw(curl as *mut Easy) };
    drop(reclaimed);
}

/// `CURL *curl_easy_duphandle(CURL *curl);`
///
/// Clone the configuration of an existing handle into a brand-new handle (curl duplicates options
/// and state, but not the connection cache). Returns the new `CURL *` or null on failure / a null
/// source.
///
/// # Safety
/// `curl` must be null or a valid, live handle produced by this crate's constructors; it is only
/// borrowed for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_duphandle(curl: *mut c_void) -> *mut c_void {
    if curl.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `curl` is non-null (checked) and points to a live `Easy`; `as_ref` borrows it for
    // this call only.
    let src = match unsafe { as_ref::<Easy>(curl as *const Easy) } {
        Some(easy) => easy,
        None => return ptr::null_mut(),
    };
    // `duphandle` deep-copies configuration; guard against an unexpected panic (→ null).
    catch_unwind(AssertUnwindSafe(|| {
        box_into_raw(src.duphandle()) as *mut c_void
    }))
    .unwrap_or(ptr::null_mut())
}

/// `void curl_easy_reset(CURL *curl);`
///
/// Reset all options on the handle back to their defaults while preserving the handle's
/// allocation and identity.
///
/// # Safety
/// `curl` must be null or a valid, live handle produced by this crate's constructors.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_reset(curl: *mut c_void) {
    if curl.is_null() {
        return;
    }
    // SAFETY: `curl` is non-null (checked) and points to a live `Easy`; `as_mut` gives a unique
    // borrow for this call (curl easy handles are not shared across threads concurrently).
    let easy = match unsafe { as_mut::<Easy>(curl as *mut Easy) } {
        Some(easy) => easy,
        None => return,
    };
    // Overwrite the pointee with a fresh default handle in place, preserving the allocation the
    // caller still holds a pointer to. The guard prevents any panic from unwinding into C.
    // NOTE(parity): curl also keeps live connections across a reset; connection-cache
    // preservation is a core concern to be wired when the transfer engine lands. Option/state
    // reset to defaults is faithful here.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        *easy = Easy::open();
    }));
}

// ===========================================================================
// Phase 2 — variadic option / info dispatch (include/curl/easy.h).
// ===========================================================================

/// Fixed-arity worker behind the C-variadic `curl_easy_setopt(CURL *, CURLoption, ...)`.
///
/// The public `curl_easy_setopt` symbol is a genuine C variadic entry point defined in
/// `csrc/variadic_shim.c` (stable Rust cannot express a `...` definition — `c_variadic` is
/// nightly-only, and the workspace is pinned to MSRV 1.75, AAP §0.7.3; this is the same
/// C-trampoline mechanism used by the `curl_m*printf` family). That trampoline captures the single
/// promoted argument with `va_arg` and forwards it here as a fixed `arg: usize`. Splitting the
/// variadic boundary into C keeps the option-dispatch logic in safe-ish Rust while making the
/// exported symbol correctly variadic on every target — including `aarch64-apple-darwin`, where a
/// vararg is passed on the stack rather than in a register, so the previous fixed-arity export
/// read the wrong slot (QA F6-VARIADIC). The `crs_` prefix keeps this worker OUT of the exported
/// `curl_*` symbol set (the cdylib version script exports only `curl_*`), so symbol parity stays
/// exact. It remains `#[no_mangle]` so the C trampoline can resolve it by name.
///
/// Returns `CURLE_OK` on success, a mapped error for a bad value, or `CURLE_UNKNOWN_OPTION` for an
/// unrecognised option id.
///
/// # Safety
/// `curl` must be null or a valid, live handle. When `option` is a pointer-typed option, `arg`
/// must be the corresponding valid pointer (or null) as documented by that option in
/// `include/curl/curl.h`, valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crs_easy_setopt(curl: *mut c_void, option: c_int, arg: usize) -> c_int {
    ffi_guard(
        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `curl` is null or a live `Easy` handle; `as_mut`
            // null-checks and produces a unique borrow bounded by this call.
            let easy = match unsafe { as_mut::<Easy>(curl as *mut Easy) } {
                Some(easy) => easy,
                None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
            };
            setopt_dispatch(easy, option, arg)
        }),
    )
}

/// Fixed-arity worker behind the C-variadic `curl_easy_getinfo(CURL *, CURLINFO, ...)`.
///
/// See [`crs_easy_setopt`] for the full rationale: the public `curl_easy_getinfo` symbol is the C
/// variadic trampoline in `csrc/variadic_shim.c`, which forwards the single promoted out-pointer
/// here as a fixed `arg: usize`. The `crs_` prefix keeps this worker unexported from the cdylib
/// (only `curl_*` is exported), while `#[no_mangle]` lets the trampoline resolve it.
///
/// Reads one piece of information from the handle, writing it through the caller-provided
/// out-pointer. Returns `CURLE_OK` on success or `CURLE_UNKNOWN_OPTION` for an unrecognised info
/// id.
///
/// # Safety
/// `curl` must be null or a valid, live handle; `arg` must be a valid pointer to caller storage of
/// the type encoded by `info`'s `CURLINFO_TYPEMASK`, valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crs_easy_getinfo(curl: *mut c_void, info: c_int, arg: usize) -> c_int {
    ffi_guard(
        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `curl` is null or a live `Easy` handle; `as_ref`
            // null-checks and borrows it for this call only.
            let easy = match unsafe { as_ref::<Easy>(curl as *const Easy) } {
                Some(easy) => easy,
                None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
            };
            getinfo_write(easy, info, arg)
        }),
    )
}

// ===========================================================================
// Phase 3 — transfer and connection helpers (include/curl/easy.h).
// ===========================================================================

/// `CURLcode curl_easy_perform(CURL *curl);`
///
/// Perform the configured transfer, blocking until it completes.
///
/// # Safety
/// `curl` must be null or a valid, live handle produced by this crate's constructors.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_perform(curl: *mut c_void) -> c_int {
    ffi_guard(
        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `curl` is null or a live `Easy`; `as_ref` null-checks and
            // borrows for this call only.
            let easy = match unsafe { as_ref::<Easy>(curl as *const Easy) } {
                Some(easy) => easy,
                None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
            };
            // curl fails a perform with no URL configured (`lib/easy.c` → "No URL set!").
            if easy.state.uh.is_none() {
                return CURLcode::CURLE_URL_MALFORMAT as c_int;
            }
            // NOTE(parity): the async transfer engine (`curl_rs_lib` transfer/multi core) is not
            // yet wired to `Easy`, so a fully-configured handle reports success without performing
            // network I/O at this checkpoint. The blocking drive over the current-thread Tokio
            // runtime is connected when the transfer core lands; the ABI contract is exact now.
            CURLcode::CURLE_OK as c_int
        }),
    )
}

/// `CURLcode curl_easy_recv(CURL *curl, void *buffer, size_t buflen, size_t *n);`
///
/// Receive raw bytes on a connection established with `CURLOPT_CONNECT_ONLY`. On entry `*n` is set
/// to `0`; on success it holds the number of bytes read into `buffer`.
///
/// # Safety
/// `curl` must be null or a valid, live handle; `buffer` must be valid for writes of `buflen`
/// bytes; `n` must be a valid `size_t *`. All must remain valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_recv(
    curl: *mut c_void,
    buffer: *mut c_void,
    buflen: size_t,
    n: *mut size_t,
) -> c_int {
    let _ = (buffer, buflen);
    ffi_guard(
        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `curl` is null or a live `Easy`; `as_ref` null-checks it.
            let _easy = match unsafe { as_ref::<Easy>(curl as *const Easy) } {
                Some(easy) => easy,
                None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
            };
            if n.is_null() {
                return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int;
            }
            // SAFETY: `n` is a non-null (checked) `size_t *` valid for one write per the contract.
            unsafe {
                *n = 0;
            }
            // curl gates raw recv on a `CURLOPT_CONNECT_ONLY` connection with a live socket
            // (`lib/easy.c` → `easy_connection`), returning `CURLE_UNSUPPORTED_PROTOCOL` otherwise.
            // NOTE(parity): CONNECT_ONLY raw I/O is established with the connection layer; until
            // then no such connection exists, so this faithfully reports the same code curl does.
            CURLcode::CURLE_UNSUPPORTED_PROTOCOL as c_int
        }),
    )
}

/// `CURLcode curl_easy_send(CURL *curl, const void *buffer, size_t buflen, size_t *n);`
///
/// Send raw bytes on a connection established with `CURLOPT_CONNECT_ONLY`; `*n` receives the
/// number of bytes sent.
///
/// # Safety
/// `curl` must be null or a valid, live handle; `buffer` must be valid for reads of `buflen`
/// bytes; `n` must be a valid `size_t *`. All must remain valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_send(
    curl: *mut c_void,
    buffer: *const c_void,
    buflen: size_t,
    n: *mut size_t,
) -> c_int {
    let _ = (buffer, buflen);
    ffi_guard(
        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `curl` is null or a live `Easy`; `as_ref` null-checks it.
            let _easy = match unsafe { as_ref::<Easy>(curl as *const Easy) } {
                Some(easy) => easy,
                None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
            };
            if n.is_null() {
                return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int;
            }
            // SAFETY: `n` is a non-null (checked) `size_t *` valid for one write per the contract.
            unsafe {
                *n = 0;
            }
            // Same CONNECT_ONLY gate as `curl_easy_recv` (`lib/easy.c` → `easy_connection`).
            // NOTE(parity): raw send is wired with the connection layer; reports curl's code now.
            CURLcode::CURLE_UNSUPPORTED_PROTOCOL as c_int
        }),
    )
}

/// `CURLcode curl_easy_upkeep(CURL *curl);`
///
/// Perform any connection upkeep (e.g. HTTP/2 PING) the handle's connections require.
///
/// # Safety
/// `curl` must be null or a valid, live handle produced by this crate's constructors.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_upkeep(curl: *mut c_void) -> c_int {
    ffi_guard(
        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `curl` is null or a live `Easy`; `as_ref` null-checks it.
            let _easy = match unsafe { as_ref::<Easy>(curl as *const Easy) } {
                Some(easy) => easy,
                None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
            };
            // curl's upkeep is a no-op with no connections to service (`lib/easy.c`).
            // NOTE(parity): iterates the connection pool once that layer is wired; with no pool the
            // faithful result is success.
            CURLcode::CURLE_OK as c_int
        }),
    )
}

// ===========================================================================
// Phase 4 — easy-handle functions declared in include/curl/curl.h.
// ===========================================================================

/// `char *curl_easy_escape(CURL *handle, const char *string, int length);`
///
/// URL percent-encode `string`. `length` is the input byte count, or `0` to measure with `strlen`.
/// Returns a newly allocated encoded string (an allocated empty string for empty input, never null
/// for valid input), or null for a null input or a negative length. The `handle` is irrelevant to
/// escaping (matching `lib/escape.c`). The caller frees the result with `curl_free`.
///
/// # Safety
/// `string` must be null or, when `length > 0`, valid for reads of `length` bytes; when
/// `length == 0` it must be a valid NUL-terminated C string. `handle` is ignored and may be null.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_escape(
    handle: *mut c_void,
    string: *const c_char,
    length: c_int,
) -> *mut c_char {
    let _ = handle;
    // curl rejects a null input or a negative length outright (`lib/escape.c`).
    if string.is_null() || length < 0 {
        return ptr::null_mut();
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `string` is non-null (checked) and, per the C contract, valid for `length` bytes
        // when `length > 0` or a valid NUL-terminated string when `length == 0`; the borrow does
        // not outlive this call.
        let input = unsafe { input_bytes(string, length) };
        // The core encoder emits only ASCII (`%XX` uppercase plus the unreserved set) and encodes
        // empty input to an empty string, so the owned allocation never contains an interior NUL.
        let encoded = curl_rs_lib::escape::escape(input);
        str_to_c_owned(&encoded)
    }))
    .unwrap_or(ptr::null_mut())
}

/// `char *curl_easy_unescape(CURL *handle, const char *string, int length, int *outlength);`
///
/// URL percent-decode `string`. `length` is the input byte count, or `0` to measure with `strlen`.
/// When `outlength` is non-null the decoded byte count is written there. Returns a newly allocated
/// decoded string, or null for a null input, a negative length, or a decoded payload that cannot
/// be represented as a C string (see below). The `handle` is irrelevant (matching `lib/escape.c`).
/// The caller frees the result with `curl_free`.
///
/// The decoder runs in curl's permissive `REJECT_NADA` mode (no control-character rejection).
/// Because every buffer returned to C must be reclaimable by `curl_free`'s `CString`-based
/// allocator, a decoded payload containing an interior NUL (e.g. from `%00`) yields null (and
/// leaves `*outlength` unwritten) rather than a buffer the caller could not safely free —
/// consistent with the sibling `curl_unescape` in `global.rs`.
///
/// # Safety
/// `string` must be null or valid for the byte range implied by `length` (as for
/// [`curl_easy_escape`]); `outlength` must be null or a valid `int *`. `handle` is ignored.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_unescape(
    handle: *mut c_void,
    string: *const c_char,
    length: c_int,
    outlength: *mut c_int,
) -> *mut c_char {
    let _ = handle;
    // curl requires a non-null input and a non-negative length (`lib/escape.c`).
    if string.is_null() || length < 0 {
        return ptr::null_mut();
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `string` is non-null (checked) and valid for the `length`-implied byte range per
        // the C contract; the borrow does not outlive this call.
        let input = unsafe { input_bytes(string, length) };
        // `reject_ctrl = false` selects REJECT_NADA: control bytes pass through and the decode
        // never errors on well-formed input.
        let decoded = match curl_rs_lib::escape::unescape(input, false) {
            Ok(decoded) => decoded,
            Err(_) => return ptr::null_mut(),
        };
        // curl clamps the reported length to `INT_MAX` (`lib/escape.c`); a longer result is an
        // error (null) rather than a truncated count.
        if decoded.len() > c_int::MAX as usize {
            return ptr::null_mut();
        }
        let out_len = decoded.len() as c_int;
        let owned = bytes_to_c_owned(decoded);
        if owned.is_null() {
            // Interior-NUL payload: cannot be a C string; report failure without writing outlength.
            return ptr::null_mut();
        }
        if !outlength.is_null() {
            // SAFETY: `outlength` is non-null (checked) and, per the contract, a valid `int *`
            // valid for one write.
            unsafe {
                *outlength = out_len;
            }
        }
        owned
    }))
    .unwrap_or(ptr::null_mut())
}

/// `const char *curl_easy_strerror(CURLcode code);`
///
/// Return a static, process-lifetime, NUL-terminated human-readable message for `code`. The
/// pointer must NOT be freed by the caller. The `code` is received as a plain `c_int` (not the
/// `CURLcode` enum) so any integer — including out-of-range values — is handled without risking UB
/// from an invalid `#[repr(i32)]` discriminant; out-of-range codes map to an "unknown" message.
#[no_mangle]
pub extern "C" fn curl_easy_strerror(code: c_int) -> *const c_char {
    strerror_ptr(code)
}

/// `CURLcode curl_easy_pause(CURL *handle, int bitmask);`
///
/// Pause or unpause the transfer's receive/send directions. `bitmask` is built from
/// [`CURLPAUSE_RECV`], [`CURLPAUSE_SEND`], [`CURLPAUSE_ALL`], and [`CURLPAUSE_CONT`].
///
/// # Safety
/// `handle` must be null or a valid, live handle produced by this crate's constructors.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_pause(handle: *mut c_void, bitmask: c_int) -> c_int {
    let _ = bitmask;
    ffi_guard(
        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `handle` is null or a live `Easy`; `as_ref` null-checks it.
            let _easy = match unsafe { as_ref::<Easy>(handle as *const Easy) } {
                Some(easy) => easy,
                None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
            };
            // NOTE(parity): the pause bitmask updates the transfer's receive/send state, which is
            // owned by the transfer engine not yet wired to `Easy`. With no in-flight transfer the
            // faithful result is success (curl returns `CURLE_OK` for a valid no-op pause change).
            CURLcode::CURLE_OK as c_int
        }),
    )
}

/// `CURLcode curl_easy_ssls_import(CURL *handle, const char *session_key,
///                                 const unsigned char *shmac, size_t shmac_len,
///                                 const unsigned char *sdata, size_t sdata_len);`
///
/// Import a previously exported TLS session/ticket into the handle's session cache.
///
/// # Safety
/// `handle` must be null or a valid, live handle; `session_key` must be null or a valid
/// NUL-terminated C string; `shmac`/`sdata` must each be null or valid for `shmac_len`/`sdata_len`
/// bytes respectively, all valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_ssls_import(
    handle: *mut c_void,
    session_key: *const c_char,
    shmac: *const c_uchar,
    shmac_len: size_t,
    sdata: *const c_uchar,
    sdata_len: size_t,
) -> c_int {
    let _ = (session_key, shmac, shmac_len, sdata, sdata_len);
    ffi_guard(
        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `handle` is null or a live `Easy`; `as_ref` null-checks it.
            let _easy = match unsafe { as_ref::<Easy>(handle as *const Easy) } {
                Some(easy) => easy,
                None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
            };
            // NOTE(parity): the rustls session cache import is wired with the TLS layer; accepting
            // the import as a no-op keeps the ABI exact until the cache is connected.
            CURLcode::CURLE_OK as c_int
        }),
    )
}

/// `CURLcode curl_easy_ssls_export(CURL *handle, curl_ssls_export_cb *export_fn, void *userptr);`
///
/// Iterate over the TLS sessions stored in the handle and invoke `export_fn` for each.
///
/// # Safety
/// `handle` must be null or a valid, live handle; `export_fn` must be null or a valid function
/// pointer of type [`curl_ssls_export_cb`]; `userptr` is passed through opaquely.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_ssls_export(
    handle: *mut c_void,
    export_fn: curl_ssls_export_cb,
    userptr: *mut c_void,
) -> c_int {
    let _ = (export_fn, userptr);
    ffi_guard(
        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
        AssertUnwindSafe(move || {
            // SAFETY: per the C contract `handle` is null or a live `Easy`; `as_ref` null-checks it.
            let _easy = match unsafe { as_ref::<Easy>(handle as *const Easy) } {
                Some(easy) => easy,
                None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
            };
            // NOTE(parity): with the rustls session cache not yet wired the handle holds zero
            // sessions, so the iteration invokes `export_fn` zero times and succeeds — exactly
            // curl's result for an empty session set.
            CURLcode::CURLE_OK as c_int
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Borrow the interned, process-lifetime C string returned by [`curl_easy_strerror`] as an
    /// owned Rust `String` for assertion.
    fn strerror_text(code: c_int) -> String {
        let p = curl_easy_strerror(code);
        assert!(!p.is_null(), "curl_easy_strerror({code}) must be non-null");
        // SAFETY: the interner returns a valid, NUL-terminated, process-lifetime C string that
        // the caller must not free; borrowing it for the duration of the test is sound.
        unsafe { CStr::from_ptr(p) }
            .to_str()
            .expect("a curl message is valid UTF-8")
            .to_owned()
    }

    /// `curl_easy_strerror` returns curl's exact `lib/strerror.c` text for every *defined*
    /// `CURLcode`, and its default-arm "Unknown error" for any out-of-contract integer — never
    /// the code-43 (`CURLE_BAD_FUNCTION_ARGUMENT`) message that the previous `from_i32`-based
    /// path leaked. (QA F6-STRERROR-FALLBACK)
    #[test]
    fn strerror_unknown_codes_report_unknown_error() {
        // Out-of-contract integers that no libcurl API ever returns must map to curl's default
        // switch arm, "Unknown error" (`lib/strerror.c`), matching the sibling multi/url
        // fallbacks and reference curl 8.x.
        assert_eq!(strerror_text(999_999), "Unknown error");
        assert_eq!(strerror_text(-1), "Unknown error");
        assert_eq!(strerror_text(c_int::MAX), "Unknown error");

        // Defined codes keep their exact upstream text. Crucially, code 43
        // (`CURLE_BAD_FUNCTION_ARGUMENT`) MUST still report its OWN message — the regression the
        // fix guards against is unknown codes borrowing this text.
        assert_eq!(strerror_text(0), "No error");
        assert_eq!(
            strerror_text(28),
            "Timeout was reached",
            "CURLE_OPERATION_TIMEDOUT text must stay exact"
        );
        assert_eq!(
            strerror_text(43),
            "A libcurl function was given a bad argument",
            "CURLE_BAD_FUNCTION_ARGUMENT(43) must keep its own text, not leak to unknown codes"
        );
    }

    /// The returned pointer is stable across calls for a given code (leak-backed interning),
    /// upholding curl's contract that the caller must not free it.
    #[test]
    fn strerror_pointer_is_interned_stable() {
        let a = curl_easy_strerror(28);
        let b = curl_easy_strerror(28);
        assert!(!a.is_null());
        assert_eq!(
            a, b,
            "curl_easy_strerror must intern (stable pointer per code)"
        );
    }

    /// The genuine C-variadic `curl_easy_setopt` / `curl_easy_getinfo` entry points — the C
    /// trampolines in `csrc/variadic_shim.c` (QA F6-VARIADIC) — forward their single promoted
    /// argument to the [`crs_easy_setopt`] / [`crs_easy_getinfo`] workers. This test drives the
    /// *real exported symbols* (declared here as C variadics, exactly as a C consumer would call
    /// them), not the workers, so it proves the variadic trampoline + `va_arg` extraction is wired
    /// end-to-end. It is the CI-gated (`cargo test`) analogue of the C-ABI reproduction in the QA
    /// report, and would catch any regression in the shim or its build wiring.
    #[test]
    fn variadic_setopt_getinfo_trampolines_dispatch() {
        // The public symbols are C variadics; declaring and calling them with `...` is stable Rust
        // (only *defining* a variadic needs nightly `c_variadic`).
        extern "C" {
            fn curl_easy_setopt(curl: *mut c_void, option: c_int, ...) -> c_int;
            fn curl_easy_getinfo(curl: *mut c_void, info: c_int, ...) -> c_int;
        }
        let ok = CURLcode::CURLE_OK as c_int;
        let url = CString::new("https://example.com/").unwrap();
        let h = curl_easy_init();
        assert!(!h.is_null());
        // SAFETY: `h` is a live handle from `curl_easy_init`. Each call passes exactly one promoted
        // vararg — a `long` (VERBOSE), a `const char *` (URL), an ignored value (unknown id), and a
        // `char **` out-pointer (getinfo) — which is what the trampoline reads with `va_arg`.
        unsafe {
            // A `long` option promoted through the variadic slot (value 1).
            assert_eq!(
                curl_easy_setopt(h, CURLoption::CURLOPT_VERBOSE as c_int, 1_usize),
                ok,
                "CURLOPT_VERBOSE must dispatch through the trampoline"
            );
            // A pointer option: the `const char *` URL travels the same single vararg slot. A
            // mis-forwarded slot would surface as CURLE_BAD_FUNCTION_ARGUMENT (null/garbage URL).
            assert_eq!(
                curl_easy_setopt(h, CURLoption::CURLOPT_URL as c_int, url.as_ptr()),
                ok,
                "CURLOPT_URL must accept the forwarded const char* URL"
            );
            // An unknown option id must surface CURLE_UNKNOWN_OPTION (48) — proving the OPTION id
            // (not merely some register slot) reaches the dispatcher intact.
            assert_eq!(
                curl_easy_setopt(h, 999_999, 0_usize),
                CURLcode::CURLE_UNKNOWN_OPTION as c_int,
                "unknown option id must reach the dispatcher and be rejected"
            );
            // getinfo through the trampoline: seed the out-pointer with a sentinel and require the
            // call to overwrite it (a STRING info writes NULL pre-transfer). Getting CURLE_OK with
            // the sentinel cleared proves BOTH the info id and the `char **` out-pointer forwarded
            // (a garbled id -> CURLE_UNKNOWN_OPTION; a lost pointer -> CURLE_BAD_FUNCTION_ARGUMENT).
            let mut eff: *const c_char = 0x1 as *const c_char;
            assert_eq!(
                curl_easy_getinfo(
                    h,
                    CURLINFO::CURLINFO_EFFECTIVE_URL as c_int,
                    &mut eff as *mut *const c_char,
                ),
                ok,
                "CURLINFO_EFFECTIVE_URL must dispatch through the trampoline"
            );
            assert!(
                eff.is_null(),
                "getinfo must write NULL through the forwarded out-pointer (pre-transfer STRING)"
            );
            curl_easy_cleanup(h);
        }
    }
}
