//! libcurl result-code enums (`CURLcode` & friends) and the `curl_easy_strerror`
//! export.
//!
//! This module is the FFI crate's **authoritative C-ABI definition** of curl's
//! result-code enums. It declares, with `#[repr(i32)]` and explicit
//! discriminants, the C enums that `cbindgen` emits into the generated header:
//!
//! * [`CURLcode`]     — the easy-handle result code (`include/curl/curl.h`).
//! * [`CURLMcode`]    — the multi-interface result code (`include/curl/multi.h`).
//! * [`CURLUcode`]    — the URL-API result code (`include/curl/urlapi.h`).
//! * [`CURLSHcode`]   — the share-interface result code (`include/curl/curl.h`).
//! * [`CURLHcode`]    — the header-API result code (`include/curl/header.h`).
//! * [`CURLFORMcode`] — the legacy `curl_formadd` result code (`curl.h`).
//! * [`CURLsslset`]   — the `curl_global_sslset` result code (`curl.h`).
//!
//! It also provides total, allocation-free conversions between the idiomatic
//! [`curl_rs_lib::error`] types (`CurlError`, `CurlMError`, …) and these C
//! integers, and exports exactly **one** `curl_*` symbol:
//! [`curl_easy_strerror`].
//!
//! # ABI contract (do not break)
//!
//! The integer value of every code is part of curl's stable ABI: C consumers
//! and the `tests/libtest` programs observe these values directly, and any
//! off-by-one breaks every consumer. The discriminants are therefore written as
//! **explicit literals** (so `cbindgen`, which runs with `parse_deps = false`,
//! can read them without resolving the dependency crate) and are pinned in two
//! ways:
//!
//! 1. A compile-time `const` block asserts that **every** variant equals the
//!    corresponding constant in [`curl_rs_lib::error::codes`] — the workspace's
//!    single source of truth for the integers — so the two can never diverge.
//! 2. The unit tests at the bottom re-check the values and the string tables.
//!
//! The trailing `CURL*_LAST` sentinels and the out-of-band
//! `CURLE_ALREADY_COMPLETE` value are deliberately exposed as `pub const`s
//! rather than enum variants: they are never real result codes (curl's headers
//! use them only as bounds / internal markers), and modelling them as variants
//! would create usable-but-bogus enum values.
//!
//! # MSRV / C-string handling
//!
//! The crate MSRV is 1.75, so C-string literals (`c"…"`, stabilized in 1.77)
//! are **not** used. Every static C string handed to a caller is built from a
//! byte-string literal with an explicit NUL via
//! [`CStr::from_bytes_with_nul_unchecked`] (const-stable on 1.75) in the single
//! [`cstr`] helper below.
//!
//! # Memory safety
//!
//! `curl-rs-ffi` is the only crate permitted `unsafe`. The `unsafe` here is
//! confined to (a) the [`cstr`] helper, which materialises `&'static CStr` from
//! compile-time byte-string literals, and (b) the range-checked
//! `int_to_*` constructors, which transmute an integer that has already been
//! proven to be a valid, in-range discriminant. Every `unsafe` block carries a
//! `// SAFETY:` comment.

// The C result-code type names use C `SCREAMING_CASE` spelling (`CURLcode`,
// `CURLM_OK`, …) which is not Rust's `UpperCamelCase` convention. The crate root
// also sets this allow, but declaring it here keeps the module warning-free when
// compiled or linted in isolation (mirrors `types.rs`).
#![allow(non_camel_case_types)]

use core::ffi::{c_char, CStr};

// The integer constants are owned by `curl-rs-lib` (single source of truth); the
// idiomatic error enums convert into the C enums declared here.
use curl_rs_lib::error::codes;
use curl_rs_lib::error::Result as CurlResult;
use curl_rs_lib::error::{CurlError, CurlHError, CurlMError, CurlShError, CurlUError};

// =============================================================================
// Static C-string helper (MSRV-safe; no `c"…"` literals)
// =============================================================================

/// Builds a `&'static CStr` from a `&'static` byte-string literal that already
/// ends in an explicit NUL.
///
/// This is the single place the module constructs C strings, so the safety
/// reasoning lives here once. It is a `const fn`, so the result can be used in
/// `const`/`static` position and the pointer it yields is genuinely `'static`
/// (it points at the program's read-only data, never freed — exactly the
/// ownership contract `curl_easy_strerror` documents).
#[inline]
#[must_use]
const fn cstr(bytes: &'static [u8]) -> &'static CStr {
    // SAFETY: every caller passes a byte-string literal of the form `b"…\0"`
    // that ends in exactly one NUL terminator and contains no interior NUL,
    // which is precisely the precondition of `from_bytes_with_nul_unchecked`.
    // The unit tests additionally verify, for representative codes, that the
    // produced bytes match the expected C string.
    unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
}

// =============================================================================
// CURLcode — easy-handle result code (include/curl/curl.h)
// =============================================================================

/// The easy-handle result code, mirroring C's `CURLcode`
/// (`include/curl/curl.h`).
///
/// The enumeration is **sequential** from `0`; retired codes are preserved as
/// `CURLE_OBSOLETE*` placeholder slots precisely so that the active codes never
/// shift value. This is the closed `#[repr(i32)]` enum that `cbindgen` reads to
/// emit the C `CURLcode` typedef, so it lists every slot in `0..=101` with an
/// explicit discriminant.
///
/// `CURL_LAST` (the trailing sentinel, value `102`) and `CURLE_ALREADY_COMPLETE`
/// (the out-of-band internal value, `99999`) are **not** variants here — see the
/// module documentation — but are available as [`CURL_LAST`] and
/// [`CURLE_ALREADY_COMPLETE`].
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CURLcode {
    CURLE_OK = 0,
    CURLE_UNSUPPORTED_PROTOCOL = 1,
    CURLE_FAILED_INIT = 2,
    CURLE_URL_MALFORMAT = 3,
    CURLE_NOT_BUILT_IN = 4,
    CURLE_COULDNT_RESOLVE_PROXY = 5,
    CURLE_COULDNT_RESOLVE_HOST = 6,
    CURLE_COULDNT_CONNECT = 7,
    CURLE_WEIRD_SERVER_REPLY = 8,
    CURLE_REMOTE_ACCESS_DENIED = 9,
    CURLE_FTP_ACCEPT_FAILED = 10,
    CURLE_FTP_WEIRD_PASS_REPLY = 11,
    CURLE_FTP_ACCEPT_TIMEOUT = 12,
    CURLE_FTP_WEIRD_PASV_REPLY = 13,
    CURLE_FTP_WEIRD_227_FORMAT = 14,
    CURLE_FTP_CANT_GET_HOST = 15,
    CURLE_HTTP2 = 16,
    CURLE_FTP_COULDNT_SET_TYPE = 17,
    CURLE_PARTIAL_FILE = 18,
    CURLE_FTP_COULDNT_RETR_FILE = 19,
    /// Retired slot (`NOT USED`) — kept so later codes keep their values.
    CURLE_OBSOLETE20 = 20,
    CURLE_QUOTE_ERROR = 21,
    CURLE_HTTP_RETURNED_ERROR = 22,
    CURLE_WRITE_ERROR = 23,
    /// Retired slot (`NOT USED`).
    CURLE_OBSOLETE24 = 24,
    CURLE_UPLOAD_FAILED = 25,
    CURLE_READ_ERROR = 26,
    CURLE_OUT_OF_MEMORY = 27,
    CURLE_OPERATION_TIMEDOUT = 28,
    /// Retired slot (`NOT USED`).
    CURLE_OBSOLETE29 = 29,
    CURLE_FTP_PORT_FAILED = 30,
    CURLE_FTP_COULDNT_USE_REST = 31,
    /// Retired slot (`NOT USED`).
    CURLE_OBSOLETE32 = 32,
    CURLE_RANGE_ERROR = 33,
    /// Retired slot.
    CURLE_OBSOLETE34 = 34,
    CURLE_SSL_CONNECT_ERROR = 35,
    CURLE_BAD_DOWNLOAD_RESUME = 36,
    CURLE_FILE_COULDNT_READ_FILE = 37,
    CURLE_LDAP_CANNOT_BIND = 38,
    CURLE_LDAP_SEARCH_FAILED = 39,
    /// Retired slot (`NOT USED`).
    CURLE_OBSOLETE40 = 40,
    /// Retired slot (`NOT USED` starting with 7.53.0).
    CURLE_OBSOLETE41 = 41,
    CURLE_ABORTED_BY_CALLBACK = 42,
    CURLE_BAD_FUNCTION_ARGUMENT = 43,
    /// Retired slot (`NOT USED`).
    CURLE_OBSOLETE44 = 44,
    CURLE_INTERFACE_FAILED = 45,
    /// Retired slot (`NOT USED`).
    CURLE_OBSOLETE46 = 46,
    CURLE_TOO_MANY_REDIRECTS = 47,
    CURLE_UNKNOWN_OPTION = 48,
    CURLE_SETOPT_OPTION_SYNTAX = 49,
    /// Retired slot (`NOT USED`).
    CURLE_OBSOLETE50 = 50,
    /// Retired slot (`NOT USED`).
    CURLE_OBSOLETE51 = 51,
    CURLE_GOT_NOTHING = 52,
    CURLE_SSL_ENGINE_NOTFOUND = 53,
    CURLE_SSL_ENGINE_SETFAILED = 54,
    CURLE_SEND_ERROR = 55,
    CURLE_RECV_ERROR = 56,
    /// Retired slot (`NOT IN USE`).
    CURLE_OBSOLETE57 = 57,
    CURLE_SSL_CERTPROBLEM = 58,
    CURLE_SSL_CIPHER = 59,
    CURLE_PEER_FAILED_VERIFICATION = 60,
    CURLE_BAD_CONTENT_ENCODING = 61,
    /// Retired slot (`NOT IN USE` since 7.82.0).
    CURLE_OBSOLETE62 = 62,
    CURLE_FILESIZE_EXCEEDED = 63,
    CURLE_USE_SSL_FAILED = 64,
    CURLE_SEND_FAIL_REWIND = 65,
    CURLE_SSL_ENGINE_INITFAILED = 66,
    CURLE_LOGIN_DENIED = 67,
    CURLE_TFTP_NOTFOUND = 68,
    CURLE_TFTP_PERM = 69,
    CURLE_REMOTE_DISK_FULL = 70,
    CURLE_TFTP_ILLEGAL = 71,
    CURLE_TFTP_UNKNOWNID = 72,
    CURLE_REMOTE_FILE_EXISTS = 73,
    CURLE_TFTP_NOSUCHUSER = 74,
    /// Retired slot (`NOT IN USE` since 7.82.0).
    CURLE_OBSOLETE75 = 75,
    /// Retired slot (`NOT IN USE` since 7.82.0).
    CURLE_OBSOLETE76 = 76,
    CURLE_SSL_CACERT_BADFILE = 77,
    CURLE_REMOTE_FILE_NOT_FOUND = 78,
    CURLE_SSH = 79,
    CURLE_SSL_SHUTDOWN_FAILED = 80,
    CURLE_AGAIN = 81,
    CURLE_SSL_CRL_BADFILE = 82,
    CURLE_SSL_ISSUER_ERROR = 83,
    CURLE_FTP_PRET_FAILED = 84,
    CURLE_RTSP_CSEQ_ERROR = 85,
    CURLE_RTSP_SESSION_ERROR = 86,
    CURLE_FTP_BAD_FILE_LIST = 87,
    CURLE_CHUNK_FAILED = 88,
    CURLE_NO_CONNECTION_AVAILABLE = 89,
    CURLE_SSL_PINNEDPUBKEYNOTMATCH = 90,
    CURLE_SSL_INVALIDCERTSTATUS = 91,
    CURLE_HTTP2_STREAM = 92,
    CURLE_RECURSIVE_API_CALL = 93,
    CURLE_AUTH_ERROR = 94,
    CURLE_HTTP3 = 95,
    CURLE_QUIC_CONNECT_ERROR = 96,
    CURLE_PROXY = 97,
    CURLE_SSL_CLIENTCERT = 98,
    CURLE_UNRECOVERABLE_POLL = 99,
    CURLE_TOO_LARGE = 100,
    CURLE_ECH_REQUIRED = 101,
}

/// One past the last defined `CURLcode` (`CURL_LAST`, value `102`).
///
/// `CURL_LAST` is never a real result code — curl's header uses it only as an
/// upper bound. Active codes occupy `0..CURL_LAST`. Exposed as a `pub const`
/// (not an enum variant) so it cannot be constructed as a bogus `CURLcode`.
pub const CURL_LAST: i32 = 102;

/// Out-of-band internal sentinel (`#define CURLE_ALREADY_COMPLETE 99999`).
///
/// This value is **not** part of the sequential `CURLcode` enum; curl `#define`s
/// it separately and uses it internally to signal that a transfer has already
/// finished. `curl_easy_strerror()` has no case for it and returns
/// `"Unknown error"`.
pub const CURLE_ALREADY_COMPLETE: i32 = 99999;

// -----------------------------------------------------------------------------
// Compile-time ABI guard: every `CURLcode` variant MUST equal the corresponding
// constant in `curl_rs_lib::error::codes` (the workspace's single source of
// truth for the integers). If anyone edits a discriminant here or a constant in
// the core crate so the two diverge, this block fails to compile — making an
// off-by-one ABI break impossible to land. `assert!` in `const` context is
// stable since Rust 1.57 (well within MSRV 1.75).
// -----------------------------------------------------------------------------
const _: () = {
    assert!(CURLcode::CURLE_OK as i32 == codes::CURLE_OK);
    assert!(CURLcode::CURLE_UNSUPPORTED_PROTOCOL as i32 == codes::CURLE_UNSUPPORTED_PROTOCOL);
    assert!(CURLcode::CURLE_FAILED_INIT as i32 == codes::CURLE_FAILED_INIT);
    assert!(CURLcode::CURLE_URL_MALFORMAT as i32 == codes::CURLE_URL_MALFORMAT);
    assert!(CURLcode::CURLE_NOT_BUILT_IN as i32 == codes::CURLE_NOT_BUILT_IN);
    assert!(CURLcode::CURLE_COULDNT_RESOLVE_PROXY as i32 == codes::CURLE_COULDNT_RESOLVE_PROXY);
    assert!(CURLcode::CURLE_COULDNT_RESOLVE_HOST as i32 == codes::CURLE_COULDNT_RESOLVE_HOST);
    assert!(CURLcode::CURLE_COULDNT_CONNECT as i32 == codes::CURLE_COULDNT_CONNECT);
    assert!(CURLcode::CURLE_WEIRD_SERVER_REPLY as i32 == codes::CURLE_WEIRD_SERVER_REPLY);
    assert!(CURLcode::CURLE_REMOTE_ACCESS_DENIED as i32 == codes::CURLE_REMOTE_ACCESS_DENIED);
    assert!(CURLcode::CURLE_FTP_ACCEPT_FAILED as i32 == codes::CURLE_FTP_ACCEPT_FAILED);
    assert!(CURLcode::CURLE_FTP_WEIRD_PASS_REPLY as i32 == codes::CURLE_FTP_WEIRD_PASS_REPLY);
    assert!(CURLcode::CURLE_FTP_ACCEPT_TIMEOUT as i32 == codes::CURLE_FTP_ACCEPT_TIMEOUT);
    assert!(CURLcode::CURLE_FTP_WEIRD_PASV_REPLY as i32 == codes::CURLE_FTP_WEIRD_PASV_REPLY);
    assert!(CURLcode::CURLE_FTP_WEIRD_227_FORMAT as i32 == codes::CURLE_FTP_WEIRD_227_FORMAT);
    assert!(CURLcode::CURLE_FTP_CANT_GET_HOST as i32 == codes::CURLE_FTP_CANT_GET_HOST);
    assert!(CURLcode::CURLE_HTTP2 as i32 == codes::CURLE_HTTP2);
    assert!(CURLcode::CURLE_FTP_COULDNT_SET_TYPE as i32 == codes::CURLE_FTP_COULDNT_SET_TYPE);
    assert!(CURLcode::CURLE_PARTIAL_FILE as i32 == codes::CURLE_PARTIAL_FILE);
    assert!(CURLcode::CURLE_FTP_COULDNT_RETR_FILE as i32 == codes::CURLE_FTP_COULDNT_RETR_FILE);
    assert!(CURLcode::CURLE_OBSOLETE20 as i32 == codes::CURLE_OBSOLETE20);
    assert!(CURLcode::CURLE_QUOTE_ERROR as i32 == codes::CURLE_QUOTE_ERROR);
    assert!(CURLcode::CURLE_HTTP_RETURNED_ERROR as i32 == codes::CURLE_HTTP_RETURNED_ERROR);
    assert!(CURLcode::CURLE_WRITE_ERROR as i32 == codes::CURLE_WRITE_ERROR);
    assert!(CURLcode::CURLE_OBSOLETE24 as i32 == codes::CURLE_OBSOLETE24);
    assert!(CURLcode::CURLE_UPLOAD_FAILED as i32 == codes::CURLE_UPLOAD_FAILED);
    assert!(CURLcode::CURLE_READ_ERROR as i32 == codes::CURLE_READ_ERROR);
    assert!(CURLcode::CURLE_OUT_OF_MEMORY as i32 == codes::CURLE_OUT_OF_MEMORY);
    assert!(CURLcode::CURLE_OPERATION_TIMEDOUT as i32 == codes::CURLE_OPERATION_TIMEDOUT);
    assert!(CURLcode::CURLE_OBSOLETE29 as i32 == codes::CURLE_OBSOLETE29);
    assert!(CURLcode::CURLE_FTP_PORT_FAILED as i32 == codes::CURLE_FTP_PORT_FAILED);
    assert!(CURLcode::CURLE_FTP_COULDNT_USE_REST as i32 == codes::CURLE_FTP_COULDNT_USE_REST);
    assert!(CURLcode::CURLE_OBSOLETE32 as i32 == codes::CURLE_OBSOLETE32);
    assert!(CURLcode::CURLE_RANGE_ERROR as i32 == codes::CURLE_RANGE_ERROR);
    assert!(CURLcode::CURLE_OBSOLETE34 as i32 == codes::CURLE_OBSOLETE34);
    assert!(CURLcode::CURLE_SSL_CONNECT_ERROR as i32 == codes::CURLE_SSL_CONNECT_ERROR);
    assert!(CURLcode::CURLE_BAD_DOWNLOAD_RESUME as i32 == codes::CURLE_BAD_DOWNLOAD_RESUME);
    assert!(CURLcode::CURLE_FILE_COULDNT_READ_FILE as i32 == codes::CURLE_FILE_COULDNT_READ_FILE);
    assert!(CURLcode::CURLE_LDAP_CANNOT_BIND as i32 == codes::CURLE_LDAP_CANNOT_BIND);
    assert!(CURLcode::CURLE_LDAP_SEARCH_FAILED as i32 == codes::CURLE_LDAP_SEARCH_FAILED);
    assert!(CURLcode::CURLE_OBSOLETE40 as i32 == codes::CURLE_OBSOLETE40);
    assert!(CURLcode::CURLE_OBSOLETE41 as i32 == codes::CURLE_OBSOLETE41);
    assert!(CURLcode::CURLE_ABORTED_BY_CALLBACK as i32 == codes::CURLE_ABORTED_BY_CALLBACK);
    assert!(CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as i32 == codes::CURLE_BAD_FUNCTION_ARGUMENT);
    assert!(CURLcode::CURLE_OBSOLETE44 as i32 == codes::CURLE_OBSOLETE44);
    assert!(CURLcode::CURLE_INTERFACE_FAILED as i32 == codes::CURLE_INTERFACE_FAILED);
    assert!(CURLcode::CURLE_OBSOLETE46 as i32 == codes::CURLE_OBSOLETE46);
    assert!(CURLcode::CURLE_TOO_MANY_REDIRECTS as i32 == codes::CURLE_TOO_MANY_REDIRECTS);
    assert!(CURLcode::CURLE_UNKNOWN_OPTION as i32 == codes::CURLE_UNKNOWN_OPTION);
    assert!(CURLcode::CURLE_SETOPT_OPTION_SYNTAX as i32 == codes::CURLE_SETOPT_OPTION_SYNTAX);
    assert!(CURLcode::CURLE_OBSOLETE50 as i32 == codes::CURLE_OBSOLETE50);
    assert!(CURLcode::CURLE_OBSOLETE51 as i32 == codes::CURLE_OBSOLETE51);
    assert!(CURLcode::CURLE_GOT_NOTHING as i32 == codes::CURLE_GOT_NOTHING);
    assert!(CURLcode::CURLE_SSL_ENGINE_NOTFOUND as i32 == codes::CURLE_SSL_ENGINE_NOTFOUND);
    assert!(CURLcode::CURLE_SSL_ENGINE_SETFAILED as i32 == codes::CURLE_SSL_ENGINE_SETFAILED);
    assert!(CURLcode::CURLE_SEND_ERROR as i32 == codes::CURLE_SEND_ERROR);
    assert!(CURLcode::CURLE_RECV_ERROR as i32 == codes::CURLE_RECV_ERROR);
    assert!(CURLcode::CURLE_OBSOLETE57 as i32 == codes::CURLE_OBSOLETE57);
    assert!(CURLcode::CURLE_SSL_CERTPROBLEM as i32 == codes::CURLE_SSL_CERTPROBLEM);
    assert!(CURLcode::CURLE_SSL_CIPHER as i32 == codes::CURLE_SSL_CIPHER);
    assert!(
        CURLcode::CURLE_PEER_FAILED_VERIFICATION as i32 == codes::CURLE_PEER_FAILED_VERIFICATION
    );
    assert!(CURLcode::CURLE_BAD_CONTENT_ENCODING as i32 == codes::CURLE_BAD_CONTENT_ENCODING);
    assert!(CURLcode::CURLE_OBSOLETE62 as i32 == codes::CURLE_OBSOLETE62);
    assert!(CURLcode::CURLE_FILESIZE_EXCEEDED as i32 == codes::CURLE_FILESIZE_EXCEEDED);
    assert!(CURLcode::CURLE_USE_SSL_FAILED as i32 == codes::CURLE_USE_SSL_FAILED);
    assert!(CURLcode::CURLE_SEND_FAIL_REWIND as i32 == codes::CURLE_SEND_FAIL_REWIND);
    assert!(CURLcode::CURLE_SSL_ENGINE_INITFAILED as i32 == codes::CURLE_SSL_ENGINE_INITFAILED);
    assert!(CURLcode::CURLE_LOGIN_DENIED as i32 == codes::CURLE_LOGIN_DENIED);
    assert!(CURLcode::CURLE_TFTP_NOTFOUND as i32 == codes::CURLE_TFTP_NOTFOUND);
    assert!(CURLcode::CURLE_TFTP_PERM as i32 == codes::CURLE_TFTP_PERM);
    assert!(CURLcode::CURLE_REMOTE_DISK_FULL as i32 == codes::CURLE_REMOTE_DISK_FULL);
    assert!(CURLcode::CURLE_TFTP_ILLEGAL as i32 == codes::CURLE_TFTP_ILLEGAL);
    assert!(CURLcode::CURLE_TFTP_UNKNOWNID as i32 == codes::CURLE_TFTP_UNKNOWNID);
    assert!(CURLcode::CURLE_REMOTE_FILE_EXISTS as i32 == codes::CURLE_REMOTE_FILE_EXISTS);
    assert!(CURLcode::CURLE_TFTP_NOSUCHUSER as i32 == codes::CURLE_TFTP_NOSUCHUSER);
    assert!(CURLcode::CURLE_OBSOLETE75 as i32 == codes::CURLE_OBSOLETE75);
    assert!(CURLcode::CURLE_OBSOLETE76 as i32 == codes::CURLE_OBSOLETE76);
    assert!(CURLcode::CURLE_SSL_CACERT_BADFILE as i32 == codes::CURLE_SSL_CACERT_BADFILE);
    assert!(CURLcode::CURLE_REMOTE_FILE_NOT_FOUND as i32 == codes::CURLE_REMOTE_FILE_NOT_FOUND);
    assert!(CURLcode::CURLE_SSH as i32 == codes::CURLE_SSH);
    assert!(CURLcode::CURLE_SSL_SHUTDOWN_FAILED as i32 == codes::CURLE_SSL_SHUTDOWN_FAILED);
    assert!(CURLcode::CURLE_AGAIN as i32 == codes::CURLE_AGAIN);
    assert!(CURLcode::CURLE_SSL_CRL_BADFILE as i32 == codes::CURLE_SSL_CRL_BADFILE);
    assert!(CURLcode::CURLE_SSL_ISSUER_ERROR as i32 == codes::CURLE_SSL_ISSUER_ERROR);
    assert!(CURLcode::CURLE_FTP_PRET_FAILED as i32 == codes::CURLE_FTP_PRET_FAILED);
    assert!(CURLcode::CURLE_RTSP_CSEQ_ERROR as i32 == codes::CURLE_RTSP_CSEQ_ERROR);
    assert!(CURLcode::CURLE_RTSP_SESSION_ERROR as i32 == codes::CURLE_RTSP_SESSION_ERROR);
    assert!(CURLcode::CURLE_FTP_BAD_FILE_LIST as i32 == codes::CURLE_FTP_BAD_FILE_LIST);
    assert!(CURLcode::CURLE_CHUNK_FAILED as i32 == codes::CURLE_CHUNK_FAILED);
    assert!(CURLcode::CURLE_NO_CONNECTION_AVAILABLE as i32 == codes::CURLE_NO_CONNECTION_AVAILABLE);
    assert!(
        CURLcode::CURLE_SSL_PINNEDPUBKEYNOTMATCH as i32 == codes::CURLE_SSL_PINNEDPUBKEYNOTMATCH
    );
    assert!(CURLcode::CURLE_SSL_INVALIDCERTSTATUS as i32 == codes::CURLE_SSL_INVALIDCERTSTATUS);
    assert!(CURLcode::CURLE_HTTP2_STREAM as i32 == codes::CURLE_HTTP2_STREAM);
    assert!(CURLcode::CURLE_RECURSIVE_API_CALL as i32 == codes::CURLE_RECURSIVE_API_CALL);
    assert!(CURLcode::CURLE_AUTH_ERROR as i32 == codes::CURLE_AUTH_ERROR);
    assert!(CURLcode::CURLE_HTTP3 as i32 == codes::CURLE_HTTP3);
    assert!(CURLcode::CURLE_QUIC_CONNECT_ERROR as i32 == codes::CURLE_QUIC_CONNECT_ERROR);
    assert!(CURLcode::CURLE_PROXY as i32 == codes::CURLE_PROXY);
    assert!(CURLcode::CURLE_SSL_CLIENTCERT as i32 == codes::CURLE_SSL_CLIENTCERT);
    assert!(CURLcode::CURLE_UNRECOVERABLE_POLL as i32 == codes::CURLE_UNRECOVERABLE_POLL);
    assert!(CURLcode::CURLE_TOO_LARGE as i32 == codes::CURLE_TOO_LARGE);
    assert!(CURLcode::CURLE_ECH_REQUIRED as i32 == codes::CURLE_ECH_REQUIRED);
    // Sentinels / out-of-band values agree with the single source of truth too.
    assert!(CURL_LAST == codes::CURL_LAST);
    assert!(CURLE_ALREADY_COMPLETE == codes::CURLE_ALREADY_COMPLETE);
};

// =============================================================================
// CURLcode <-> integer / CurlError conversions
// =============================================================================

/// Returns the raw C integer for a [`CURLcode`].
///
/// A plain `#[repr(i32)]` cast; total and allocation-free.
#[inline]
#[must_use]
pub fn code_to_int(c: CURLcode) -> i32 {
    c as i32
}

/// Builds a [`CURLcode`] from a raw C integer.
///
/// Every value in `0..CURL_LAST` (i.e. `0..=101`) is a defined `CURLcode`
/// discriminant — including the retired `CURLE_OBSOLETE*` slots — and round-trips
/// exactly. Any other integer (the out-of-band `CURLE_ALREADY_COMPLETE`, the
/// `CURL_LAST` sentinel, or anything outside the range) has no `CURLcode` of its
/// own and is mapped to [`CURLcode::CURLE_OK`], mirroring the
/// guidance in the implementation plan; in practice this branch is only ever
/// reached by the internal `CURLE_ALREADY_COMPLETE` sentinel, which is never
/// surfaced to C consumers.
#[inline]
#[must_use]
pub fn int_to_code(n: i32) -> CURLcode {
    if (codes::CURLE_OK..CURL_LAST).contains(&n) {
        // SAFETY: `CURLcode` is `#[repr(i32)]` and declares an explicit variant
        // for every contiguous integer in `0..CURL_LAST` (0..=101) — enforced by
        // the compile-time agreement block above and by the exhaustive
        // `int_to_code` round-trip unit test. The range check guarantees `n` is
        // one of those defined discriminants, so transmuting it yields a valid,
        // fully-initialised enum value (never an invalid bit pattern).
        unsafe { core::mem::transmute::<i32, CURLcode>(n) }
    } else {
        CURLcode::CURLE_OK
    }
}

/// Alias of [`int_to_code`]; named per the implementation plan for the benefit
/// of sibling FFI modules that prefer the explicit `curlcode_from_i32` spelling.
#[inline]
#[must_use]
pub fn curlcode_from_i32(n: i32) -> CURLcode {
    int_to_code(n)
}

impl From<CurlError> for CURLcode {
    /// Maps the idiomatic core error onto its exact C `CURLcode`.
    ///
    /// Delegates to [`CurlError::code`] (the single source of truth for the
    /// integer) and re-wraps it as the C enum via [`int_to_code`]. Every active
    /// `CurlError` variant has a matching `CURLcode`, so the mapping is exact;
    /// the only values that fall back to `CURLE_OK` are the internal
    /// `AlreadyComplete` sentinel (`99999`) and any out-of-range
    /// `Unknown(n)` — neither of which is a public C return value.
    #[inline]
    fn from(error: CurlError) -> Self {
        int_to_code(error.code())
    }
}

impl From<&CurlError> for CURLcode {
    #[inline]
    fn from(error: &CurlError) -> Self {
        int_to_code(error.code())
    }
}

/// Collapses a core [`Result`](CurlResult) to a C [`CURLcode`].
///
/// `Ok(_)` becomes [`CURLcode::CURLE_OK`] and `Err(e)` becomes `e`'s mapped
/// code. This is the helper the sibling `extern "C"` shims (`easy.rs`,
/// `multi.rs`, …) use pervasively to return a `CURLcode` from an internal
/// `Result`.
#[inline]
#[must_use]
pub fn result_to_code<T>(r: CurlResult<T>) -> CURLcode {
    match r {
        Ok(_) => CURLcode::CURLE_OK,
        Err(e) => CURLcode::from(e),
    }
}

// =============================================================================
// curl_easy_strerror — the ONE exported `curl_*` symbol in this module
// =============================================================================

/// Returns the static, NUL-terminated English description for an easy-handle
/// result `code`.
///
/// The strings are reproduced **byte-for-byte** from the verbose branch of
/// `lib/strerror.c`'s `curl_easy_strerror` (the read-only behavioural oracle),
/// so output is identical to curl 8.x. Retired (`CURLE_OBSOLETE*`) codes and any
/// out-of-range integer are not listed and therefore fall through to
/// `"Unknown error"`, exactly as the C `switch`'s `default` arm does.
///
/// We match on `code as i32` (rather than on the enum variants) so that an
/// out-of-range integer passed across the FFI boundary by a C caller is handled
/// gracefully instead of being treated as an exhaustive-match miss.
fn easy_strerror_cstr(code: CURLcode) -> &'static CStr {
    match code as i32 {
        codes::CURLE_OK => cstr(b"No error\0"),
        codes::CURLE_UNSUPPORTED_PROTOCOL => cstr(b"Unsupported protocol\0"),
        codes::CURLE_FAILED_INIT => cstr(b"Failed initialization\0"),
        codes::CURLE_URL_MALFORMAT => cstr(b"URL using bad/illegal format or missing URL\0"),
        codes::CURLE_NOT_BUILT_IN => cstr(
            b"A requested feature, protocol or option was not found built-in in this libcurl due to a build-time decision.\0",
        ),
        codes::CURLE_COULDNT_RESOLVE_PROXY => cstr(b"Could not resolve proxy name\0"),
        codes::CURLE_COULDNT_RESOLVE_HOST => cstr(b"Could not resolve hostname\0"),
        codes::CURLE_COULDNT_CONNECT => cstr(b"Could not connect to server\0"),
        codes::CURLE_WEIRD_SERVER_REPLY => cstr(b"Weird server reply\0"),
        codes::CURLE_REMOTE_ACCESS_DENIED => cstr(b"Access denied to remote resource\0"),
        codes::CURLE_FTP_ACCEPT_FAILED => {
            cstr(b"FTP: The server failed to connect to data port\0")
        }
        codes::CURLE_FTP_ACCEPT_TIMEOUT => {
            cstr(b"FTP: Accepting server connect has timed out\0")
        }
        codes::CURLE_FTP_PRET_FAILED => cstr(b"FTP: The server did not accept the PRET command.\0"),
        codes::CURLE_FTP_WEIRD_PASS_REPLY => cstr(b"FTP: unknown PASS reply\0"),
        codes::CURLE_FTP_WEIRD_PASV_REPLY => cstr(b"FTP: unknown PASV reply\0"),
        codes::CURLE_FTP_WEIRD_227_FORMAT => cstr(b"FTP: unknown 227 response format\0"),
        codes::CURLE_FTP_CANT_GET_HOST => {
            cstr(b"FTP: cannot figure out the host in the PASV response\0")
        }
        codes::CURLE_HTTP2 => cstr(b"Error in the HTTP2 framing layer\0"),
        codes::CURLE_FTP_COULDNT_SET_TYPE => cstr(b"FTP: could not set file type\0"),
        codes::CURLE_PARTIAL_FILE => cstr(b"Transferred a partial file\0"),
        codes::CURLE_FTP_COULDNT_RETR_FILE => {
            cstr(b"FTP: could not retrieve (RETR failed) the specified file\0")
        }
        codes::CURLE_QUOTE_ERROR => cstr(b"Quote command returned error\0"),
        codes::CURLE_HTTP_RETURNED_ERROR => cstr(b"HTTP response code said error\0"),
        codes::CURLE_WRITE_ERROR => cstr(b"Failed writing received data to disk/application\0"),
        codes::CURLE_UPLOAD_FAILED => cstr(b"Upload failed (at start/before it took off)\0"),
        codes::CURLE_READ_ERROR => {
            cstr(b"Failed to open/read local data from file/application\0")
        }
        codes::CURLE_OUT_OF_MEMORY => cstr(b"Out of memory\0"),
        codes::CURLE_OPERATION_TIMEDOUT => cstr(b"Timeout was reached\0"),
        codes::CURLE_FTP_PORT_FAILED => cstr(b"FTP: command PORT failed\0"),
        codes::CURLE_FTP_COULDNT_USE_REST => cstr(b"FTP: command REST failed\0"),
        codes::CURLE_RANGE_ERROR => cstr(b"Requested range was not delivered by the server\0"),
        codes::CURLE_SSL_CONNECT_ERROR => cstr(b"SSL connect error\0"),
        codes::CURLE_BAD_DOWNLOAD_RESUME => cstr(b"Could not resume download\0"),
        codes::CURLE_FILE_COULDNT_READ_FILE => cstr(b"Could not read a file:// file\0"),
        codes::CURLE_LDAP_CANNOT_BIND => cstr(b"LDAP: cannot bind\0"),
        codes::CURLE_LDAP_SEARCH_FAILED => cstr(b"LDAP: search failed\0"),
        codes::CURLE_ABORTED_BY_CALLBACK => {
            cstr(b"Operation was aborted by an application callback\0")
        }
        codes::CURLE_BAD_FUNCTION_ARGUMENT => {
            cstr(b"A libcurl function was given a bad argument\0")
        }
        codes::CURLE_INTERFACE_FAILED => cstr(b"Failed binding local connection end\0"),
        codes::CURLE_TOO_MANY_REDIRECTS => cstr(b"Number of redirects hit maximum amount\0"),
        codes::CURLE_UNKNOWN_OPTION => cstr(b"An unknown option was passed in to libcurl\0"),
        codes::CURLE_SETOPT_OPTION_SYNTAX => cstr(b"Malformed option provided in a setopt\0"),
        codes::CURLE_GOT_NOTHING => cstr(b"Server returned nothing (no headers, no data)\0"),
        codes::CURLE_SSL_ENGINE_NOTFOUND => cstr(b"SSL crypto engine not found\0"),
        codes::CURLE_SSL_ENGINE_SETFAILED => {
            cstr(b"Can not set SSL crypto engine as default\0")
        }
        codes::CURLE_SSL_ENGINE_INITFAILED => cstr(b"Failed to initialise SSL crypto engine\0"),
        codes::CURLE_SEND_ERROR => cstr(b"Failed sending data to the peer\0"),
        codes::CURLE_RECV_ERROR => cstr(b"Failure when receiving data from the peer\0"),
        codes::CURLE_SSL_CERTPROBLEM => cstr(b"Problem with the local SSL certificate\0"),
        codes::CURLE_SSL_CIPHER => cstr(b"Could not use specified SSL cipher\0"),
        codes::CURLE_PEER_FAILED_VERIFICATION => {
            cstr(b"SSL peer certificate or SSH remote key was not OK\0")
        }
        codes::CURLE_SSL_CACERT_BADFILE => {
            cstr(b"Problem with the SSL CA cert (path? access rights?)\0")
        }
        codes::CURLE_BAD_CONTENT_ENCODING => {
            cstr(b"Unrecognized or bad HTTP Content or Transfer-Encoding\0")
        }
        codes::CURLE_FILESIZE_EXCEEDED => cstr(b"Maximum file size exceeded\0"),
        codes::CURLE_USE_SSL_FAILED => cstr(b"Requested SSL level failed\0"),
        codes::CURLE_SSL_SHUTDOWN_FAILED => cstr(b"Failed to shut down the SSL connection\0"),
        codes::CURLE_SSL_CRL_BADFILE => {
            cstr(b"Failed to load CRL file (path? access rights?, format?)\0")
        }
        codes::CURLE_SSL_ISSUER_ERROR => cstr(b"Issuer check against peer certificate failed\0"),
        codes::CURLE_SEND_FAIL_REWIND => {
            cstr(b"Send failed since rewinding of the data stream failed\0")
        }
        codes::CURLE_LOGIN_DENIED => cstr(b"Login denied\0"),
        codes::CURLE_TFTP_NOTFOUND => cstr(b"TFTP: File Not Found\0"),
        codes::CURLE_TFTP_PERM => cstr(b"TFTP: Access Violation\0"),
        codes::CURLE_REMOTE_DISK_FULL => cstr(b"Disk full or allocation exceeded\0"),
        codes::CURLE_TFTP_ILLEGAL => cstr(b"TFTP: Illegal operation\0"),
        codes::CURLE_TFTP_UNKNOWNID => cstr(b"TFTP: Unknown transfer ID\0"),
        codes::CURLE_REMOTE_FILE_EXISTS => cstr(b"Remote file already exists\0"),
        codes::CURLE_TFTP_NOSUCHUSER => cstr(b"TFTP: No such user\0"),
        codes::CURLE_REMOTE_FILE_NOT_FOUND => cstr(b"Remote file not found\0"),
        codes::CURLE_SSH => cstr(b"Error in the SSH layer\0"),
        codes::CURLE_AGAIN => cstr(b"Socket not ready for send/recv\0"),
        codes::CURLE_RTSP_CSEQ_ERROR => cstr(b"RTSP CSeq mismatch or invalid CSeq\0"),
        codes::CURLE_RTSP_SESSION_ERROR => cstr(b"RTSP session error\0"),
        codes::CURLE_FTP_BAD_FILE_LIST => cstr(b"Unable to parse FTP file list\0"),
        codes::CURLE_CHUNK_FAILED => cstr(b"Chunk callback failed\0"),
        codes::CURLE_NO_CONNECTION_AVAILABLE => cstr(b"The max connection limit is reached\0"),
        codes::CURLE_SSL_PINNEDPUBKEYNOTMATCH => {
            cstr(b"SSL public key does not match pinned public key\0")
        }
        codes::CURLE_SSL_INVALIDCERTSTATUS => {
            cstr(b"SSL server certificate status verification FAILED\0")
        }
        codes::CURLE_HTTP2_STREAM => cstr(b"Stream error in the HTTP/2 framing layer\0"),
        codes::CURLE_RECURSIVE_API_CALL => cstr(b"API function called from within callback\0"),
        codes::CURLE_AUTH_ERROR => cstr(b"An authentication function returned an error\0"),
        codes::CURLE_HTTP3 => cstr(b"HTTP/3 error\0"),
        codes::CURLE_QUIC_CONNECT_ERROR => cstr(b"QUIC connection error\0"),
        codes::CURLE_PROXY => cstr(b"proxy handshake error\0"),
        codes::CURLE_SSL_CLIENTCERT => cstr(b"SSL Client Certificate required\0"),
        codes::CURLE_UNRECOVERABLE_POLL => cstr(b"Unrecoverable error in select/poll\0"),
        codes::CURLE_TOO_LARGE => cstr(b"A value or data field grew larger than allowed\0"),
        codes::CURLE_ECH_REQUIRED => cstr(b"ECH attempted but failed\0"),
        // Retired codes (`CURLE_OBSOLETE*`), the internal `CURLE_ALREADY_COMPLETE`
        // sentinel, and any out-of-range integer all map to curl's default text.
        _ => cstr(b"Unknown error\0"),
    }
}

/// `curl_easy_strerror` — return a human-readable string for a `CURLcode`.
///
/// This is the **only** `#[no_mangle] extern "C"` symbol exported from this
/// module; the sibling `curl_multi_strerror` / `curl_share_strerror` /
/// `curl_url_strerror` live in their own modules and call the description
/// helpers below.
///
/// The returned pointer references a `'static`, read-only, NUL-terminated string
/// that is **never freed**; the caller must not pass it to `free()`/`curl_free`.
/// This matches `lib/strerror.c`, which returns string literals.
///
/// # Safety
///
/// This function performs no pointer dereferences and is sound for every
/// possible bit pattern of `code` (out-of-range integers are mapped to
/// `"Unknown error"`). It is declared `unsafe extern "C"` only to match curl's
/// published FFI surface; callers must nonetheless treat the returned pointer as
/// borrowed `'static` data and must not free or mutate it.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_strerror(code: CURLcode) -> *const c_char {
    easy_strerror_cstr(code).as_ptr()
}

// =============================================================================
// CURLMcode — multi-interface result code (include/curl/multi.h)
// =============================================================================

/// The multi-interface result code, mirroring C's `CURLMcode`
/// (`include/curl/multi.h`).
///
/// Unlike [`CURLcode`], this enum starts at `-1`
/// ([`CURLMcode::CURLM_CALL_MULTI_PERFORM`]) and runs contiguously to `12`. The
/// trailing `CURLM_LAST` sentinel (`13`) and the `CURLM_CALL_MULTI_SOCKET` alias
/// (a `#define` equal to `CURLM_CALL_MULTI_PERFORM`, i.e. `-1`) are exposed as
/// `pub const`s — see [`CURLM_LAST`] and [`CURLM_CALL_MULTI_SOCKET`].
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CURLMcode {
    /// Call `curl_multi_perform()` again soon (legacy signalling value, `-1`).
    CURLM_CALL_MULTI_PERFORM = -1,
    CURLM_OK = 0,
    CURLM_BAD_HANDLE = 1,
    CURLM_BAD_EASY_HANDLE = 2,
    CURLM_OUT_OF_MEMORY = 3,
    CURLM_INTERNAL_ERROR = 4,
    CURLM_BAD_SOCKET = 5,
    CURLM_UNKNOWN_OPTION = 6,
    CURLM_ADDED_ALREADY = 7,
    CURLM_RECURSIVE_API_CALL = 8,
    CURLM_WAKEUP_FAILURE = 9,
    CURLM_BAD_FUNCTION_ARGUMENT = 10,
    CURLM_ABORTED_BY_CALLBACK = 11,
    CURLM_UNRECOVERABLE_POLL = 12,
}

/// One past the last defined [`CURLMcode`] (`13`). Never a real result code.
pub const CURLM_LAST: i32 = 13;

/// `#define CURLM_CALL_MULTI_SOCKET CURLM_CALL_MULTI_PERFORM` from `multi.h`:
/// an alias of [`CURLMcode::CURLM_CALL_MULTI_PERFORM`] (`-1`).
pub const CURLM_CALL_MULTI_SOCKET: i32 = CURLMcode::CURLM_CALL_MULTI_PERFORM as i32;

// Compile-time ABI guard against `curl_rs_lib::error::codes::multi`.
const _: () = {
    use codes::multi as m;
    assert!(CURLMcode::CURLM_CALL_MULTI_PERFORM as i32 == m::CURLM_CALL_MULTI_PERFORM);
    assert!(CURLMcode::CURLM_OK as i32 == m::CURLM_OK);
    assert!(CURLMcode::CURLM_BAD_HANDLE as i32 == m::CURLM_BAD_HANDLE);
    assert!(CURLMcode::CURLM_BAD_EASY_HANDLE as i32 == m::CURLM_BAD_EASY_HANDLE);
    assert!(CURLMcode::CURLM_OUT_OF_MEMORY as i32 == m::CURLM_OUT_OF_MEMORY);
    assert!(CURLMcode::CURLM_INTERNAL_ERROR as i32 == m::CURLM_INTERNAL_ERROR);
    assert!(CURLMcode::CURLM_BAD_SOCKET as i32 == m::CURLM_BAD_SOCKET);
    assert!(CURLMcode::CURLM_UNKNOWN_OPTION as i32 == m::CURLM_UNKNOWN_OPTION);
    assert!(CURLMcode::CURLM_ADDED_ALREADY as i32 == m::CURLM_ADDED_ALREADY);
    assert!(CURLMcode::CURLM_RECURSIVE_API_CALL as i32 == m::CURLM_RECURSIVE_API_CALL);
    assert!(CURLMcode::CURLM_WAKEUP_FAILURE as i32 == m::CURLM_WAKEUP_FAILURE);
    assert!(CURLMcode::CURLM_BAD_FUNCTION_ARGUMENT as i32 == m::CURLM_BAD_FUNCTION_ARGUMENT);
    assert!(CURLMcode::CURLM_ABORTED_BY_CALLBACK as i32 == m::CURLM_ABORTED_BY_CALLBACK);
    assert!(CURLMcode::CURLM_UNRECOVERABLE_POLL as i32 == m::CURLM_UNRECOVERABLE_POLL);
    assert!(CURLM_LAST == m::CURLM_LAST);
    assert!(CURLM_CALL_MULTI_SOCKET == m::CURLM_CALL_MULTI_PERFORM);
};

/// Builds a [`CURLMcode`] from a raw C integer.
///
/// Every value in `CURLM_CALL_MULTI_PERFORM..CURLM_LAST` (i.e. `-1..=12`) is a
/// defined discriminant and round-trips exactly. Any other integer maps to
/// [`CURLMcode::CURLM_OK`] (a defensive default that is unreachable in practice,
/// since callers only ever pass codes produced by `curl-rs-lib`).
#[inline]
#[must_use]
pub fn int_to_mcode(n: i32) -> CURLMcode {
    if (codes::multi::CURLM_CALL_MULTI_PERFORM..CURLM_LAST).contains(&n) {
        // SAFETY: `CURLMcode` is `#[repr(i32)]` with an explicit variant for
        // every contiguous integer in `-1..CURLM_LAST` (-1..=12), enforced by the
        // agreement block above and the `int_to_mcode` round-trip test. The range
        // check guarantees `n` is one of those discriminants, so the transmute
        // yields a valid, initialised enum value.
        unsafe { core::mem::transmute::<i32, CURLMcode>(n) }
    } else {
        CURLMcode::CURLM_OK
    }
}

impl From<CurlMError> for CURLMcode {
    #[inline]
    fn from(error: CurlMError) -> Self {
        int_to_mcode(error.code())
    }
}

impl From<&CurlMError> for CURLMcode {
    #[inline]
    fn from(error: &CurlMError) -> Self {
        int_to_mcode(error.code())
    }
}

/// Collapses a multi-interface `Result` to a [`CURLMcode`]: `Ok` ->
/// [`CURLMcode::CURLM_OK`], `Err(e)` -> `e`'s mapped code.
#[inline]
#[must_use]
pub fn result_to_mcode<T>(r: core::result::Result<T, CurlMError>) -> CURLMcode {
    match r {
        Ok(_) => CURLMcode::CURLM_OK,
        Err(e) => CURLMcode::from(e),
    }
}

/// Static, NUL-terminated description for a [`CURLMcode`], byte-for-byte from
/// `lib/strerror.c`'s `curl_multi_strerror`.
///
/// Not exported here; `multi.rs` wraps this in its `#[no_mangle]`
/// `curl_multi_strerror` shim.
#[must_use]
pub fn multi_strerror_cstr(code: CURLMcode) -> &'static CStr {
    match code as i32 {
        codes::multi::CURLM_CALL_MULTI_PERFORM => cstr(b"Please call curl_multi_perform() soon\0"),
        codes::multi::CURLM_OK => cstr(b"No error\0"),
        codes::multi::CURLM_BAD_HANDLE => cstr(b"Invalid multi handle\0"),
        codes::multi::CURLM_BAD_EASY_HANDLE => cstr(b"Invalid easy handle\0"),
        codes::multi::CURLM_OUT_OF_MEMORY => cstr(b"Out of memory\0"),
        codes::multi::CURLM_INTERNAL_ERROR => cstr(b"Internal error\0"),
        codes::multi::CURLM_BAD_SOCKET => cstr(b"Invalid socket argument\0"),
        codes::multi::CURLM_UNKNOWN_OPTION => cstr(b"Unknown option\0"),
        codes::multi::CURLM_ADDED_ALREADY => {
            cstr(b"The easy handle is already added to a multi handle\0")
        }
        codes::multi::CURLM_RECURSIVE_API_CALL => {
            cstr(b"API function called from within callback\0")
        }
        codes::multi::CURLM_WAKEUP_FAILURE => cstr(b"Wakeup is unavailable or failed\0"),
        codes::multi::CURLM_BAD_FUNCTION_ARGUMENT => {
            cstr(b"A libcurl function was given a bad argument\0")
        }
        codes::multi::CURLM_ABORTED_BY_CALLBACK => {
            cstr(b"Operation was aborted by an application callback\0")
        }
        codes::multi::CURLM_UNRECOVERABLE_POLL => cstr(b"Unrecoverable error in select/poll\0"),
        _ => cstr(b"Unknown error\0"),
    }
}

/// `*const c_char` form of [`multi_strerror_cstr`] for `multi.rs`'s FFI shim.
#[inline]
#[must_use]
pub fn multi_strerror(code: CURLMcode) -> *const c_char {
    multi_strerror_cstr(code).as_ptr()
}

// =============================================================================
// CURLUcode — URL-API result code (include/curl/urlapi.h)
// =============================================================================

/// The URL-API result code, mirroring C's `CURLUcode`
/// (`include/curl/urlapi.h`). Sequential from `0` to `31`; the trailing
/// `CURLUE_LAST` sentinel (`32`) is exposed as [`CURLUE_LAST`].
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CURLUcode {
    CURLUE_OK = 0,
    CURLUE_BAD_HANDLE = 1,
    CURLUE_BAD_PARTPOINTER = 2,
    CURLUE_MALFORMED_INPUT = 3,
    CURLUE_BAD_PORT_NUMBER = 4,
    CURLUE_UNSUPPORTED_SCHEME = 5,
    CURLUE_URLDECODE = 6,
    CURLUE_OUT_OF_MEMORY = 7,
    CURLUE_USER_NOT_ALLOWED = 8,
    CURLUE_UNKNOWN_PART = 9,
    CURLUE_NO_SCHEME = 10,
    CURLUE_NO_USER = 11,
    CURLUE_NO_PASSWORD = 12,
    CURLUE_NO_OPTIONS = 13,
    CURLUE_NO_HOST = 14,
    CURLUE_NO_PORT = 15,
    CURLUE_NO_QUERY = 16,
    CURLUE_NO_FRAGMENT = 17,
    CURLUE_NO_ZONEID = 18,
    CURLUE_BAD_FILE_URL = 19,
    CURLUE_BAD_FRAGMENT = 20,
    CURLUE_BAD_HOSTNAME = 21,
    CURLUE_BAD_IPV6 = 22,
    CURLUE_BAD_LOGIN = 23,
    CURLUE_BAD_PASSWORD = 24,
    CURLUE_BAD_PATH = 25,
    CURLUE_BAD_QUERY = 26,
    CURLUE_BAD_SCHEME = 27,
    CURLUE_BAD_SLASHES = 28,
    CURLUE_BAD_USER = 29,
    CURLUE_LACKS_IDN = 30,
    CURLUE_TOO_LARGE = 31,
}

/// One past the last defined [`CURLUcode`] (`32`). Never a real result code.
pub const CURLUE_LAST: i32 = 32;

// Compile-time ABI guard against `curl_rs_lib::error::codes::url`.
const _: () = {
    use codes::url as u;
    assert!(CURLUcode::CURLUE_OK as i32 == u::CURLUE_OK);
    assert!(CURLUcode::CURLUE_BAD_HANDLE as i32 == u::CURLUE_BAD_HANDLE);
    assert!(CURLUcode::CURLUE_BAD_PARTPOINTER as i32 == u::CURLUE_BAD_PARTPOINTER);
    assert!(CURLUcode::CURLUE_MALFORMED_INPUT as i32 == u::CURLUE_MALFORMED_INPUT);
    assert!(CURLUcode::CURLUE_BAD_PORT_NUMBER as i32 == u::CURLUE_BAD_PORT_NUMBER);
    assert!(CURLUcode::CURLUE_UNSUPPORTED_SCHEME as i32 == u::CURLUE_UNSUPPORTED_SCHEME);
    assert!(CURLUcode::CURLUE_URLDECODE as i32 == u::CURLUE_URLDECODE);
    assert!(CURLUcode::CURLUE_OUT_OF_MEMORY as i32 == u::CURLUE_OUT_OF_MEMORY);
    assert!(CURLUcode::CURLUE_USER_NOT_ALLOWED as i32 == u::CURLUE_USER_NOT_ALLOWED);
    assert!(CURLUcode::CURLUE_UNKNOWN_PART as i32 == u::CURLUE_UNKNOWN_PART);
    assert!(CURLUcode::CURLUE_NO_SCHEME as i32 == u::CURLUE_NO_SCHEME);
    assert!(CURLUcode::CURLUE_NO_USER as i32 == u::CURLUE_NO_USER);
    assert!(CURLUcode::CURLUE_NO_PASSWORD as i32 == u::CURLUE_NO_PASSWORD);
    assert!(CURLUcode::CURLUE_NO_OPTIONS as i32 == u::CURLUE_NO_OPTIONS);
    assert!(CURLUcode::CURLUE_NO_HOST as i32 == u::CURLUE_NO_HOST);
    assert!(CURLUcode::CURLUE_NO_PORT as i32 == u::CURLUE_NO_PORT);
    assert!(CURLUcode::CURLUE_NO_QUERY as i32 == u::CURLUE_NO_QUERY);
    assert!(CURLUcode::CURLUE_NO_FRAGMENT as i32 == u::CURLUE_NO_FRAGMENT);
    assert!(CURLUcode::CURLUE_NO_ZONEID as i32 == u::CURLUE_NO_ZONEID);
    assert!(CURLUcode::CURLUE_BAD_FILE_URL as i32 == u::CURLUE_BAD_FILE_URL);
    assert!(CURLUcode::CURLUE_BAD_FRAGMENT as i32 == u::CURLUE_BAD_FRAGMENT);
    assert!(CURLUcode::CURLUE_BAD_HOSTNAME as i32 == u::CURLUE_BAD_HOSTNAME);
    assert!(CURLUcode::CURLUE_BAD_IPV6 as i32 == u::CURLUE_BAD_IPV6);
    assert!(CURLUcode::CURLUE_BAD_LOGIN as i32 == u::CURLUE_BAD_LOGIN);
    assert!(CURLUcode::CURLUE_BAD_PASSWORD as i32 == u::CURLUE_BAD_PASSWORD);
    assert!(CURLUcode::CURLUE_BAD_PATH as i32 == u::CURLUE_BAD_PATH);
    assert!(CURLUcode::CURLUE_BAD_QUERY as i32 == u::CURLUE_BAD_QUERY);
    assert!(CURLUcode::CURLUE_BAD_SCHEME as i32 == u::CURLUE_BAD_SCHEME);
    assert!(CURLUcode::CURLUE_BAD_SLASHES as i32 == u::CURLUE_BAD_SLASHES);
    assert!(CURLUcode::CURLUE_BAD_USER as i32 == u::CURLUE_BAD_USER);
    assert!(CURLUcode::CURLUE_LACKS_IDN as i32 == u::CURLUE_LACKS_IDN);
    assert!(CURLUcode::CURLUE_TOO_LARGE as i32 == u::CURLUE_TOO_LARGE);
    assert!(CURLUE_LAST == u::CURLUE_LAST);
};

/// Builds a [`CURLUcode`] from a raw C integer.
///
/// Every value in `0..CURLUE_LAST` (`0..=31`) is a defined discriminant and
/// round-trips exactly; any other integer maps to the defensive default
/// [`CURLUcode::CURLUE_OK`] (unreachable in practice).
#[inline]
#[must_use]
pub fn int_to_ucode(n: i32) -> CURLUcode {
    if (codes::url::CURLUE_OK..CURLUE_LAST).contains(&n) {
        // SAFETY: `CURLUcode` is `#[repr(i32)]` with an explicit variant for every
        // contiguous integer in `0..CURLUE_LAST` (0..=31), enforced by the
        // agreement block above and the `int_to_ucode` round-trip test. The range
        // check guarantees `n` is one of those discriminants, so the transmute
        // yields a valid, initialised enum value.
        unsafe { core::mem::transmute::<i32, CURLUcode>(n) }
    } else {
        CURLUcode::CURLUE_OK
    }
}

impl From<CurlUError> for CURLUcode {
    #[inline]
    fn from(error: CurlUError) -> Self {
        int_to_ucode(error.code())
    }
}

impl From<&CurlUError> for CURLUcode {
    #[inline]
    fn from(error: &CurlUError) -> Self {
        int_to_ucode(error.code())
    }
}

/// Collapses a URL-API `Result` to a [`CURLUcode`].
#[inline]
#[must_use]
pub fn result_to_ucode<T>(r: core::result::Result<T, CurlUError>) -> CURLUcode {
    match r {
        Ok(_) => CURLUcode::CURLUE_OK,
        Err(e) => CURLUcode::from(e),
    }
}

/// Static, NUL-terminated description for a [`CURLUcode`], byte-for-byte from
/// `lib/strerror.c`'s `curl_url_strerror`.
///
/// Not exported here; `url.rs` wraps this in its `#[no_mangle]`
/// `curl_url_strerror` shim.
#[must_use]
pub fn url_strerror_cstr(code: CURLUcode) -> &'static CStr {
    match code as i32 {
        codes::url::CURLUE_OK => cstr(b"No error\0"),
        codes::url::CURLUE_BAD_HANDLE => cstr(b"An invalid CURLU pointer was passed as argument\0"),
        codes::url::CURLUE_BAD_PARTPOINTER => {
            cstr(b"An invalid 'part' argument was passed as argument\0")
        }
        codes::url::CURLUE_MALFORMED_INPUT => cstr(b"Malformed input to a URL function\0"),
        codes::url::CURLUE_BAD_PORT_NUMBER => {
            cstr(b"Port number was not a decimal number between 0 and 65535\0")
        }
        codes::url::CURLUE_UNSUPPORTED_SCHEME => cstr(b"Unsupported URL scheme\0"),
        codes::url::CURLUE_URLDECODE => {
            cstr(b"URL decode error, most likely because of rubbish in the input\0")
        }
        codes::url::CURLUE_OUT_OF_MEMORY => cstr(b"A memory function failed\0"),
        codes::url::CURLUE_USER_NOT_ALLOWED => {
            cstr(b"Credentials was passed in the URL when prohibited\0")
        }
        codes::url::CURLUE_UNKNOWN_PART => {
            cstr(b"An unknown part ID was passed to a URL API function\0")
        }
        codes::url::CURLUE_NO_SCHEME => cstr(b"No scheme part in the URL\0"),
        codes::url::CURLUE_NO_USER => cstr(b"No user part in the URL\0"),
        codes::url::CURLUE_NO_PASSWORD => cstr(b"No password part in the URL\0"),
        codes::url::CURLUE_NO_OPTIONS => cstr(b"No options part in the URL\0"),
        codes::url::CURLUE_NO_HOST => cstr(b"No host part in the URL\0"),
        codes::url::CURLUE_NO_PORT => cstr(b"No port part in the URL\0"),
        codes::url::CURLUE_NO_QUERY => cstr(b"No query part in the URL\0"),
        codes::url::CURLUE_NO_FRAGMENT => cstr(b"No fragment part in the URL\0"),
        codes::url::CURLUE_NO_ZONEID => cstr(b"No zoneid part in the URL\0"),
        codes::url::CURLUE_BAD_FILE_URL => cstr(b"Bad file:// URL\0"),
        codes::url::CURLUE_BAD_FRAGMENT => cstr(b"Bad fragment\0"),
        codes::url::CURLUE_BAD_HOSTNAME => cstr(b"Bad hostname\0"),
        codes::url::CURLUE_BAD_IPV6 => cstr(b"Bad IPv6 address\0"),
        codes::url::CURLUE_BAD_LOGIN => cstr(b"Bad login part\0"),
        codes::url::CURLUE_BAD_PASSWORD => cstr(b"Bad password\0"),
        codes::url::CURLUE_BAD_PATH => cstr(b"Bad path\0"),
        codes::url::CURLUE_BAD_QUERY => cstr(b"Bad query\0"),
        codes::url::CURLUE_BAD_SCHEME => cstr(b"Bad scheme\0"),
        codes::url::CURLUE_BAD_SLASHES => cstr(b"Unsupported number of slashes following scheme\0"),
        codes::url::CURLUE_BAD_USER => cstr(b"Bad user\0"),
        codes::url::CURLUE_LACKS_IDN => cstr(b"libcurl lacks IDN support\0"),
        codes::url::CURLUE_TOO_LARGE => cstr(b"A value or data field is larger than allowed\0"),
        _ => cstr(b"CURLUcode unknown\0"),
    }
}

/// `*const c_char` form of [`url_strerror_cstr`] for `url.rs`'s FFI shim.
#[inline]
#[must_use]
pub fn url_strerror(code: CURLUcode) -> *const c_char {
    url_strerror_cstr(code).as_ptr()
}

// =============================================================================
// CURLSHcode — share-interface result code (include/curl/curl.h)
// =============================================================================

/// The share-interface result code, mirroring C's `CURLSHcode`
/// (`include/curl/curl.h`). Sequential from `0` to `5`; the trailing
/// `CURLSHE_LAST` sentinel (`6`) is exposed as [`CURLSHE_LAST`].
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CURLSHcode {
    CURLSHE_OK = 0,
    CURLSHE_BAD_OPTION = 1,
    CURLSHE_IN_USE = 2,
    CURLSHE_INVALID = 3,
    CURLSHE_NOMEM = 4,
    CURLSHE_NOT_BUILT_IN = 5,
}

/// One past the last defined [`CURLSHcode`] (`6`). Never a real result code.
pub const CURLSHE_LAST: i32 = 6;

// Compile-time ABI guard against `curl_rs_lib::error::codes::share`.
const _: () = {
    use codes::share as s;
    assert!(CURLSHcode::CURLSHE_OK as i32 == s::CURLSHE_OK);
    assert!(CURLSHcode::CURLSHE_BAD_OPTION as i32 == s::CURLSHE_BAD_OPTION);
    assert!(CURLSHcode::CURLSHE_IN_USE as i32 == s::CURLSHE_IN_USE);
    assert!(CURLSHcode::CURLSHE_INVALID as i32 == s::CURLSHE_INVALID);
    assert!(CURLSHcode::CURLSHE_NOMEM as i32 == s::CURLSHE_NOMEM);
    assert!(CURLSHcode::CURLSHE_NOT_BUILT_IN as i32 == s::CURLSHE_NOT_BUILT_IN);
    assert!(CURLSHE_LAST == s::CURLSHE_LAST);
};

/// Builds a [`CURLSHcode`] from a raw C integer.
///
/// Every value in `0..CURLSHE_LAST` (`0..=5`) is a defined discriminant and
/// round-trips exactly; any other integer maps to the defensive default
/// [`CURLSHcode::CURLSHE_OK`] (unreachable in practice).
#[inline]
#[must_use]
pub fn int_to_shcode(n: i32) -> CURLSHcode {
    if (codes::share::CURLSHE_OK..CURLSHE_LAST).contains(&n) {
        // SAFETY: `CURLSHcode` is `#[repr(i32)]` with an explicit variant for
        // every contiguous integer in `0..CURLSHE_LAST` (0..=5), enforced by the
        // agreement block above and the `int_to_shcode` round-trip test. The range
        // check guarantees `n` is one of those discriminants, so the transmute
        // yields a valid, initialised enum value.
        unsafe { core::mem::transmute::<i32, CURLSHcode>(n) }
    } else {
        CURLSHcode::CURLSHE_OK
    }
}

impl From<CurlShError> for CURLSHcode {
    #[inline]
    fn from(error: CurlShError) -> Self {
        int_to_shcode(error.code())
    }
}

impl From<&CurlShError> for CURLSHcode {
    #[inline]
    fn from(error: &CurlShError) -> Self {
        int_to_shcode(error.code())
    }
}

/// Collapses a share-interface `Result` to a [`CURLSHcode`].
#[inline]
#[must_use]
pub fn result_to_shcode<T>(r: core::result::Result<T, CurlShError>) -> CURLSHcode {
    match r {
        Ok(_) => CURLSHcode::CURLSHE_OK,
        Err(e) => CURLSHcode::from(e),
    }
}

/// Static, NUL-terminated description for a [`CURLSHcode`], byte-for-byte from
/// `lib/strerror.c`'s `curl_share_strerror`.
///
/// Not exported here; `share.rs` wraps this in its `#[no_mangle]`
/// `curl_share_strerror` shim.
#[must_use]
pub fn share_strerror_cstr(code: CURLSHcode) -> &'static CStr {
    match code as i32 {
        codes::share::CURLSHE_OK => cstr(b"No error\0"),
        codes::share::CURLSHE_BAD_OPTION => cstr(b"Unknown share option\0"),
        codes::share::CURLSHE_IN_USE => cstr(b"Share currently in use\0"),
        codes::share::CURLSHE_INVALID => cstr(b"Invalid share handle\0"),
        codes::share::CURLSHE_NOMEM => cstr(b"Out of memory\0"),
        codes::share::CURLSHE_NOT_BUILT_IN => cstr(b"Feature not enabled in this library\0"),
        _ => cstr(b"CURLSHcode unknown\0"),
    }
}

/// `*const c_char` form of [`share_strerror_cstr`] for `share.rs`'s FFI shim.
#[inline]
#[must_use]
pub fn share_strerror(code: CURLSHcode) -> *const c_char {
    share_strerror_cstr(code).as_ptr()
}

// =============================================================================
// CURLHcode — header-API result code (include/curl/header.h)
// =============================================================================

/// The header-API result code, mirroring C's `CURLHcode`
/// (`include/curl/header.h`). Sequential from `0` to `7`.
///
/// Note: unlike the other code enums, `header.h` declares **no** trailing
/// `CURLHE_LAST` sentinel, so none is exposed here. (`curl-rs-lib` keeps a
/// private `codes::header::CURLHE_LAST` bound for range checks only.) There is
/// also no `curl_header_strerror` symbol in libcurl, so no description helper is
/// provided.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CURLHcode {
    CURLHE_OK = 0,
    CURLHE_BADINDEX = 1,
    CURLHE_MISSING = 2,
    CURLHE_NOHEADERS = 3,
    CURLHE_NOREQUEST = 4,
    CURLHE_OUT_OF_MEMORY = 5,
    CURLHE_BAD_ARGUMENT = 6,
    CURLHE_NOT_BUILT_IN = 7,
}

// Compile-time ABI guard against `curl_rs_lib::error::codes::header`.
const _: () = {
    use codes::header as h;
    assert!(CURLHcode::CURLHE_OK as i32 == h::CURLHE_OK);
    assert!(CURLHcode::CURLHE_BADINDEX as i32 == h::CURLHE_BADINDEX);
    assert!(CURLHcode::CURLHE_MISSING as i32 == h::CURLHE_MISSING);
    assert!(CURLHcode::CURLHE_NOHEADERS as i32 == h::CURLHE_NOHEADERS);
    assert!(CURLHcode::CURLHE_NOREQUEST as i32 == h::CURLHE_NOREQUEST);
    assert!(CURLHcode::CURLHE_OUT_OF_MEMORY as i32 == h::CURLHE_OUT_OF_MEMORY);
    assert!(CURLHcode::CURLHE_BAD_ARGUMENT as i32 == h::CURLHE_BAD_ARGUMENT);
    assert!(CURLHcode::CURLHE_NOT_BUILT_IN as i32 == h::CURLHE_NOT_BUILT_IN);
};

/// Builds a [`CURLHcode`] from a raw C integer.
///
/// Every value in `0..CURLHE_LAST` (`0..=7`) is a defined discriminant and
/// round-trips exactly; any other integer maps to the defensive default
/// [`CURLHcode::CURLHE_OK`] (unreachable in practice). The upper bound is taken
/// from `curl-rs-lib`'s private `codes::header::CURLHE_LAST` (`8`).
#[inline]
#[must_use]
pub fn int_to_hcode(n: i32) -> CURLHcode {
    if (codes::header::CURLHE_OK..codes::header::CURLHE_LAST).contains(&n) {
        // SAFETY: `CURLHcode` is `#[repr(i32)]` with an explicit variant for every
        // contiguous integer in `0..CURLHE_LAST` (0..=7), enforced by the
        // agreement block above and the `int_to_hcode` round-trip test. The range
        // check guarantees `n` is one of those discriminants, so the transmute
        // yields a valid, initialised enum value.
        unsafe { core::mem::transmute::<i32, CURLHcode>(n) }
    } else {
        CURLHcode::CURLHE_OK
    }
}

impl From<CurlHError> for CURLHcode {
    #[inline]
    fn from(error: CurlHError) -> Self {
        int_to_hcode(error.code())
    }
}

impl From<&CurlHError> for CURLHcode {
    #[inline]
    fn from(error: &CurlHError) -> Self {
        int_to_hcode(error.code())
    }
}

/// Collapses a header-API `Result` to a [`CURLHcode`].
#[inline]
#[must_use]
pub fn result_to_hcode<T>(r: core::result::Result<T, CurlHError>) -> CURLHcode {
    match r {
        Ok(_) => CURLHcode::CURLHE_OK,
        Err(e) => CURLHcode::from(e),
    }
}

// =============================================================================
// CURLFORMcode — legacy curl_formadd() result code (include/curl/curl.h)
// =============================================================================

/// The legacy `curl_formadd()` result code, mirroring C's `CURLFORMcode`
/// (`include/curl/curl.h`). Sequential from `0` to `7`; the trailing
/// `CURL_FORMADD_LAST` sentinel (`8`) is exposed as [`CURL_FORMADD_LAST`].
///
/// `curl-rs-lib` has no idiomatic error type for this deprecated form API
/// (it is superseded by the MIME API), so there is no `From`/`description`
/// conversion — `mime.rs` constructs these values directly.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CURLFORMcode {
    CURL_FORMADD_OK = 0,
    CURL_FORMADD_MEMORY = 1,
    CURL_FORMADD_OPTION_TWICE = 2,
    CURL_FORMADD_NULL = 3,
    CURL_FORMADD_UNKNOWN_OPTION = 4,
    CURL_FORMADD_INCOMPLETE = 5,
    CURL_FORMADD_ILLEGAL_ARRAY = 6,
    /// libcurl was built with the form API disabled.
    CURL_FORMADD_DISABLED = 7,
}

/// One past the last defined [`CURLFORMcode`] (`8`). Never a real result code.
pub const CURL_FORMADD_LAST: i32 = 8;

// Compile-time guard pinning the literal discriminants (no core constants exist
// for the deprecated form API, so the literals are the source of truth here).
const _: () = {
    assert!(CURLFORMcode::CURL_FORMADD_OK as i32 == 0);
    assert!(CURLFORMcode::CURL_FORMADD_MEMORY as i32 == 1);
    assert!(CURLFORMcode::CURL_FORMADD_OPTION_TWICE as i32 == 2);
    assert!(CURLFORMcode::CURL_FORMADD_NULL as i32 == 3);
    assert!(CURLFORMcode::CURL_FORMADD_UNKNOWN_OPTION as i32 == 4);
    assert!(CURLFORMcode::CURL_FORMADD_INCOMPLETE as i32 == 5);
    assert!(CURLFORMcode::CURL_FORMADD_ILLEGAL_ARRAY as i32 == 6);
    assert!(CURLFORMcode::CURL_FORMADD_DISABLED as i32 == 7);
    assert!(CURL_FORMADD_LAST == 8);
};

/// Builds a [`CURLFORMcode`] from a raw C integer; out-of-range values map to
/// the defensive default [`CURLFORMcode::CURL_FORMADD_OK`].
#[inline]
#[must_use]
pub fn int_to_formcode(n: i32) -> CURLFORMcode {
    if (0..CURL_FORMADD_LAST).contains(&n) {
        // SAFETY: `CURLFORMcode` is `#[repr(i32)]` with an explicit variant for
        // every contiguous integer in `0..CURL_FORMADD_LAST` (0..=7), enforced by
        // the guard block above and the `int_to_formcode` round-trip test. The
        // range check guarantees `n` is one of those discriminants, so the
        // transmute yields a valid, initialised enum value.
        unsafe { core::mem::transmute::<i32, CURLFORMcode>(n) }
    } else {
        CURLFORMcode::CURL_FORMADD_OK
    }
}

// =============================================================================
// CURLsslset — curl_global_sslset() result code (include/curl/curl.h)
// =============================================================================

/// The `curl_global_sslset()` result code, mirroring C's `CURLsslset`
/// (`include/curl/curl.h`). Sequential from `0` to `3`.
///
/// `curl-rs-lib` has no idiomatic error type for this selector, so there is no
/// `From`/`description` conversion — `global.rs` returns these values directly.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CURLsslset {
    CURLSSLSET_OK = 0,
    CURLSSLSET_UNKNOWN_BACKEND = 1,
    CURLSSLSET_TOO_LATE = 2,
    /// libcurl was built without any SSL support.
    CURLSSLSET_NO_BACKENDS = 3,
}

/// One past the last defined [`CURLsslset`] (`4`). Used only as a range bound;
/// not part of curl's header (kept private-by-convention via this crate).
const CURLSSLSET_BOUND: i32 = 4;

// Compile-time guard pinning the literal discriminants.
const _: () = {
    assert!(CURLsslset::CURLSSLSET_OK as i32 == 0);
    assert!(CURLsslset::CURLSSLSET_UNKNOWN_BACKEND as i32 == 1);
    assert!(CURLsslset::CURLSSLSET_TOO_LATE as i32 == 2);
    assert!(CURLsslset::CURLSSLSET_NO_BACKENDS as i32 == 3);
};

/// Builds a [`CURLsslset`] from a raw C integer; out-of-range values map to the
/// defensive default [`CURLsslset::CURLSSLSET_OK`].
#[inline]
#[must_use]
pub fn int_to_sslset(n: i32) -> CURLsslset {
    if (0..CURLSSLSET_BOUND).contains(&n) {
        // SAFETY: `CURLsslset` is `#[repr(i32)]` with an explicit variant for
        // every contiguous integer in `0..CURLSSLSET_BOUND` (0..=3), enforced by
        // the guard block above and the `int_to_sslset` round-trip test. The range
        // check guarantees `n` is one of those discriminants, so the transmute
        // yields a valid, initialised enum value.
        unsafe { core::mem::transmute::<i32, CURLsslset>(n) }
    } else {
        CURLsslset::CURLSSLSET_OK
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Mandated ABI discriminant spot-checks (guard off-by-one breaks) ----
    #[test]
    fn mandated_discriminants() {
        assert_eq!(CURLcode::CURLE_OK as i32, 0);
        assert_eq!(CURLcode::CURLE_ECH_REQUIRED as i32, 101);
        assert_eq!(CURLE_ALREADY_COMPLETE, 99999);
        assert_eq!(CURLMcode::CURLM_CALL_MULTI_PERFORM as i32, -1);
        assert_eq!(CURLUcode::CURLUE_TOO_LARGE as i32, 31);
        assert_eq!(CURLSHcode::CURLSHE_NOT_BUILT_IN as i32, 5);
    }

    // ---- Trailing sentinels / aliases ----
    #[test]
    fn sentinels_and_aliases() {
        assert_eq!(CURL_LAST, 102);
        assert_eq!(CURLM_LAST, 13);
        assert_eq!(CURLM_CALL_MULTI_SOCKET, -1);
        assert_eq!(CURLUE_LAST, 32);
        assert_eq!(CURLSHE_LAST, 6);
        assert_eq!(CURL_FORMADD_LAST, 8);
    }

    // ---- curl_easy_strerror byte-exactness (the single exported symbol) ----
    #[test]
    fn easy_strerror_no_error_is_byte_exact() {
        // SAFETY: `curl_easy_strerror` returns a non-null, 'static,
        // NUL-terminated pointer that the caller must not free.
        let p = unsafe { curl_easy_strerror(CURLcode::CURLE_OK) };
        assert!(!p.is_null());
        // SAFETY: `p` points at a 'static NUL-terminated C string (see above).
        let s = unsafe { CStr::from_ptr(p) };
        assert_eq!(s.to_bytes_with_nul(), b"No error\0");
    }

    #[test]
    fn easy_strerror_obsolete_maps_to_unknown() {
        // An obsolete (reserved) code is a valid enum variant that is absent from
        // the description table, so it must hit curl's default "Unknown error".
        // SAFETY: as above.
        let p = unsafe { curl_easy_strerror(CURLcode::CURLE_OBSOLETE20) };
        // SAFETY: as above.
        let s = unsafe { CStr::from_ptr(p) };
        assert_eq!(s.to_bytes(), b"Unknown error");
    }

    // ---- int <-> code round trips across every defined discriminant ----
    #[test]
    fn curlcode_roundtrip_and_helpers() {
        for n in codes::CURLE_OK..CURL_LAST {
            assert_eq!(int_to_code(n) as i32, n, "CURLcode {n}");
        }
        // Out-of-range / out-of-band values fall back to the defensive default.
        assert_eq!(int_to_code(CURLE_ALREADY_COMPLETE), CURLcode::CURLE_OK);
        assert_eq!(int_to_code(CURL_LAST), CURLcode::CURLE_OK);
        assert_eq!(int_to_code(-12_345), CURLcode::CURLE_OK);
        // Helper spellings agree.
        assert_eq!(curlcode_from_i32(7), CURLcode::CURLE_COULDNT_CONNECT);
        assert_eq!(code_to_int(CURLcode::CURLE_AGAIN), 81);
    }

    #[test]
    fn mcode_roundtrip() {
        for n in codes::multi::CURLM_CALL_MULTI_PERFORM..CURLM_LAST {
            assert_eq!(int_to_mcode(n) as i32, n, "CURLMcode {n}");
        }
        assert_eq!(int_to_mcode(CURLM_LAST), CURLMcode::CURLM_OK);
        assert_eq!(int_to_mcode(-2), CURLMcode::CURLM_OK);
    }

    #[test]
    fn ucode_roundtrip() {
        for n in codes::url::CURLUE_OK..CURLUE_LAST {
            assert_eq!(int_to_ucode(n) as i32, n, "CURLUcode {n}");
        }
        assert_eq!(int_to_ucode(CURLUE_LAST), CURLUcode::CURLUE_OK);
    }

    #[test]
    fn shcode_roundtrip() {
        for n in codes::share::CURLSHE_OK..CURLSHE_LAST {
            assert_eq!(int_to_shcode(n) as i32, n, "CURLSHcode {n}");
        }
        assert_eq!(int_to_shcode(CURLSHE_LAST), CURLSHcode::CURLSHE_OK);
    }

    #[test]
    fn hcode_roundtrip() {
        for n in codes::header::CURLHE_OK..codes::header::CURLHE_LAST {
            assert_eq!(int_to_hcode(n) as i32, n, "CURLHcode {n}");
        }
        assert_eq!(
            int_to_hcode(codes::header::CURLHE_LAST),
            CURLHcode::CURLHE_OK
        );
    }

    #[test]
    fn formcode_and_sslset_roundtrip() {
        for n in 0..CURL_FORMADD_LAST {
            assert_eq!(int_to_formcode(n) as i32, n, "CURLFORMcode {n}");
        }
        assert_eq!(
            int_to_formcode(CURL_FORMADD_LAST),
            CURLFORMcode::CURL_FORMADD_OK
        );
        for n in 0..4 {
            assert_eq!(int_to_sslset(n) as i32, n, "CURLsslset {n}");
        }
        assert_eq!(int_to_sslset(4), CURLsslset::CURLSSLSET_OK);
    }

    // ---- From<core error> and result_to_* helpers ----
    #[test]
    fn from_curlerror_and_result_to_code() {
        assert_eq!(
            CURLcode::from(CurlError::CouldntConnect),
            CURLcode::CURLE_COULDNT_CONNECT
        );
        assert_eq!(CURLcode::from(&CurlError::Ok), CURLcode::CURLE_OK);
        // `AlreadyComplete` (99999) is internal-only and has no C enum slot, so it
        // collapses to the defensive default.
        assert_eq!(
            CURLcode::from(CurlError::AlreadyComplete),
            CURLcode::CURLE_OK
        );

        let ok: CurlResult<u8> = Ok(1);
        let err: CurlResult<u8> = Err(CurlError::TooLarge);
        assert_eq!(result_to_code(ok), CURLcode::CURLE_OK);
        assert_eq!(result_to_code(err), CURLcode::CURLE_TOO_LARGE);
    }

    #[test]
    fn from_sibling_errors_and_results() {
        assert_eq!(
            CURLMcode::from(CurlMError::BadHandle),
            CURLMcode::CURLM_BAD_HANDLE
        );
        assert_eq!(
            CURLUcode::from(CurlUError::TooLarge),
            CURLUcode::CURLUE_TOO_LARGE
        );
        assert_eq!(
            CURLSHcode::from(CurlShError::NotBuiltIn),
            CURLSHcode::CURLSHE_NOT_BUILT_IN
        );
        assert_eq!(
            CURLHcode::from(CurlHError::NotBuiltIn),
            CURLHcode::CURLHE_NOT_BUILT_IN
        );

        let m_ok: core::result::Result<(), CurlMError> = Ok(());
        let m_err: core::result::Result<(), CurlMError> = Err(CurlMError::OutOfMemory);
        assert_eq!(result_to_mcode(m_ok), CURLMcode::CURLM_OK);
        assert_eq!(result_to_mcode(m_err), CURLMcode::CURLM_OUT_OF_MEMORY);

        let u_err: core::result::Result<(), CurlUError> = Err(CurlUError::BadPortNumber);
        assert_eq!(result_to_ucode(u_err), CURLUcode::CURLUE_BAD_PORT_NUMBER);

        let sh_err: core::result::Result<(), CurlShError> = Err(CurlShError::InUse);
        assert_eq!(result_to_shcode(sh_err), CURLSHcode::CURLSHE_IN_USE);

        let h_err: core::result::Result<(), CurlHError> = Err(CurlHError::Missing);
        assert_eq!(result_to_hcode(h_err), CURLHcode::CURLHE_MISSING);
    }

    // ---- String tables cross-checked against core `description()` ----
    // `curl-rs-lib`'s `description()` reproduces `lib/strerror.c` verbatim and is
    // itself unit-tested there, so equality here proves byte-exact parity with
    // curl 8.x for every code without duplicating the assertions.
    #[test]
    fn easy_strings_match_core_description() {
        for n in codes::CURLE_OK..CURL_LAST {
            let mine = easy_strerror_cstr(int_to_code(n))
                .to_str()
                .expect("valid UTF-8");
            let core_desc = CurlError::from_code(n).description();
            assert_eq!(mine, core_desc, "CURLcode {n} string mismatch");
        }
    }

    #[test]
    fn multi_strings_match_core_description() {
        for n in codes::multi::CURLM_CALL_MULTI_PERFORM..CURLM_LAST {
            let mine = multi_strerror_cstr(int_to_mcode(n))
                .to_str()
                .expect("valid UTF-8");
            let core_desc = CurlMError::from_code(n)
                .expect("defined CURLMcode")
                .description();
            assert_eq!(mine, core_desc, "CURLMcode {n} string mismatch");
        }
    }

    #[test]
    fn share_strings_match_core_description() {
        for n in codes::share::CURLSHE_OK..CURLSHE_LAST {
            let mine = share_strerror_cstr(int_to_shcode(n))
                .to_str()
                .expect("valid UTF-8");
            let core_desc = CurlShError::from_code(n)
                .expect("defined CURLSHcode")
                .description();
            assert_eq!(mine, core_desc, "CURLSHcode {n} string mismatch");
        }
    }

    #[test]
    fn url_strings_match_core_description() {
        for n in codes::url::CURLUE_OK..CURLUE_LAST {
            let mine = url_strerror_cstr(int_to_ucode(n))
                .to_str()
                .expect("valid UTF-8");
            let core_desc = CurlUError::from_code(n)
                .expect("defined CURLUcode")
                .description();
            assert_eq!(mine, core_desc, "CURLUcode {n} string mismatch");
        }
    }

    // ---- The pointer-returning description helpers yield usable C strings ----
    #[test]
    fn strerror_pointer_helpers_are_non_null_nonempty() {
        // SAFETY: each helper returns a 'static NUL-terminated pointer.
        let cases: [*const c_char; 3] = [
            multi_strerror(CURLMcode::CURLM_OK),
            share_strerror(CURLSHcode::CURLSHE_OK),
            url_strerror(CURLUcode::CURLUE_OK),
        ];
        for p in cases {
            assert!(!p.is_null());
            // SAFETY: `p` is a 'static NUL-terminated C string (see above).
            let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
            assert!(!bytes.is_empty());
        }
    }
}
