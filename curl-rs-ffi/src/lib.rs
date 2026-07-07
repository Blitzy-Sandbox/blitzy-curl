// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! # curl-rs-ffi — C ABI compatibility layer for the curl/libcurl 8.19.0-DEV rewrite
//!
//! This crate is the `extern "C"` surface of the three-crate workspace. It re-exposes the
//! functionality implemented in the safe-Rust core ([`curl_rs_lib`]) as `libcurl`-compatible
//! C symbols so that existing C/C++ consumers relink without recompilation, and it is the
//! **only** workspace member permitted to contain `unsafe` (AAP §0.7.2). Its produced
//! artifacts are `libcurl_rs_ffi.{so,a}` (the `cdylib` / `staticlib`) plus an `rlib` for the
//! sibling CLI.
//!
//! ## What this foundation checkpoint establishes
//!
//! The public C surface is anchored by the frozen [`CURLcode`] result-code enum defined
//! below. Its integer values are a **frozen ABI contract** transcribed verbatim from
//! `include/curl/curl.h`: a consumer that hard-codes `CURLE_OPERATION_TIMEDOUT == 28` must
//! keep working, so the discriminants here are pinned and unit-tested against the
//! authoritative [`curl_rs_lib::error::CurlCode`] enum. The build script
//! (`build.rs`) feeds this crate to `cbindgen`, which renders the `CURLcode` declaration
//! into a verification header used to byte-diff the generated output against the committed
//! `include/curl/curl.h`.
//!
//! The concrete `curl_easy_*` / `curl_multi_*` / `curl_*` entry points that operate on the
//! core are layered on top of this enum in later checkpoints, following the build-order
//! dependency sequence (AAP §0.7.3); each will convert the core's typed
//! [`curl_rs_lib::error::Error`] into one of the [`CURLcode`] integers defined here at the
//! boundary.

/// libcurl result codes (`CURLcode`).
///
/// This is a language-faithful transcription of the `CURLcode` enumeration in
/// `include/curl/curl.h` for the curl 8.19.0-DEV reference tree. Every discriminant — including
/// the retained `CURLE_OBSOLETE*` gap-fillers — matches the C header exactly so the integer
/// contract is preserved across the FFI boundary (`cbindgen` regenerates the C declaration
/// from this definition). The variant names use curl's `SCREAMING_SNAKE_CASE` spelling and
/// are therefore permitted to break Rust's usual type-casing convention.
///
/// The representation is `i32`, matching curl's C `enum` (a plain `int`) and the
/// [`curl_rs_lib::error::CurlCode`] mirror in the core crate; a fieldless `#[repr(i32)]`
/// enum can be cast to its discriminant with `code as i32`, which is exactly the value an
/// FFI caller observes.
#[repr(i32)]
#[allow(non_camel_case_types)]
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
    CURLE_OBSOLETE20 = 20,
    CURLE_QUOTE_ERROR = 21,
    CURLE_HTTP_RETURNED_ERROR = 22,
    CURLE_WRITE_ERROR = 23,
    CURLE_OBSOLETE24 = 24,
    CURLE_UPLOAD_FAILED = 25,
    CURLE_READ_ERROR = 26,
    CURLE_OUT_OF_MEMORY = 27,
    CURLE_OPERATION_TIMEDOUT = 28,
    CURLE_OBSOLETE29 = 29,
    CURLE_FTP_PORT_FAILED = 30,
    CURLE_FTP_COULDNT_USE_REST = 31,
    CURLE_OBSOLETE32 = 32,
    CURLE_RANGE_ERROR = 33,
    CURLE_OBSOLETE34 = 34,
    CURLE_SSL_CONNECT_ERROR = 35,
    CURLE_BAD_DOWNLOAD_RESUME = 36,
    CURLE_FILE_COULDNT_READ_FILE = 37,
    CURLE_LDAP_CANNOT_BIND = 38,
    CURLE_LDAP_SEARCH_FAILED = 39,
    CURLE_OBSOLETE40 = 40,
    CURLE_OBSOLETE41 = 41,
    CURLE_ABORTED_BY_CALLBACK = 42,
    CURLE_BAD_FUNCTION_ARGUMENT = 43,
    CURLE_OBSOLETE44 = 44,
    CURLE_INTERFACE_FAILED = 45,
    CURLE_OBSOLETE46 = 46,
    CURLE_TOO_MANY_REDIRECTS = 47,
    CURLE_UNKNOWN_OPTION = 48,
    CURLE_SETOPT_OPTION_SYNTAX = 49,
    CURLE_OBSOLETE50 = 50,
    CURLE_OBSOLETE51 = 51,
    CURLE_GOT_NOTHING = 52,
    CURLE_SSL_ENGINE_NOTFOUND = 53,
    CURLE_SSL_ENGINE_SETFAILED = 54,
    CURLE_SEND_ERROR = 55,
    CURLE_RECV_ERROR = 56,
    CURLE_OBSOLETE57 = 57,
    CURLE_SSL_CERTPROBLEM = 58,
    CURLE_SSL_CIPHER = 59,
    CURLE_PEER_FAILED_VERIFICATION = 60,
    CURLE_BAD_CONTENT_ENCODING = 61,
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
    CURLE_OBSOLETE75 = 75,
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

#[cfg(test)]
mod tests {
    use super::CURLcode;
    use curl_rs_lib::error::CurlCode;

    /// The public integer contract: a handful of load-bearing discriminants must equal their
    /// exact `include/curl/curl.h` values. `CURLE_OPERATION_TIMEDOUT == 28` is the canonical
    /// example an FFI consumer hard-codes.
    #[test]
    fn curlcode_discriminants_match_frozen_abi() {
        assert_eq!(CURLcode::CURLE_OK as i32, 0);
        assert_eq!(CURLcode::CURLE_UNSUPPORTED_PROTOCOL as i32, 1);
        assert_eq!(CURLcode::CURLE_OPERATION_TIMEDOUT as i32, 28);
        assert_eq!(CURLcode::CURLE_BAD_CONTENT_ENCODING as i32, 61);
        assert_eq!(CURLcode::CURLE_TOO_LARGE as i32, 100);
        assert_eq!(CURLcode::CURLE_ECH_REQUIRED as i32, 101);
    }

    /// The FFI enum and the core-crate [`CurlCode`] mirror must agree on every shared code, so
    /// that boundary conversions are lossless in both directions. A representative spread is
    /// asserted here; both enums are `#[repr(i32)]` transcriptions of the same C header.
    #[test]
    fn curlcode_agrees_with_core_curlcode() {
        assert_eq!(CURLcode::CURLE_OK as i32, CurlCode::Ok as i32);
        assert_eq!(
            CURLcode::CURLE_UNSUPPORTED_PROTOCOL as i32,
            CurlCode::UnsupportedProtocol as i32
        );
        assert_eq!(
            CURLcode::CURLE_OPERATION_TIMEDOUT as i32,
            CurlCode::OperationTimedout as i32
        );
        assert_eq!(
            CURLcode::CURLE_ECH_REQUIRED as i32,
            CurlCode::EchRequired as i32
        );
    }
}
