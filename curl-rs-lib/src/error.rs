//! Canonical error and result-code definitions for `curl-rs-lib`.
//!
//! This module is the **single source of truth** for every libcurl result-code
//! enum and the exact C integer that each code maps to. It defines:
//!
//! * [`CurlError`] — the idiomatic, crate-internal error type returned through
//!   the crate-wide [`Result`] alias. Each variant corresponds 1:1 to an active
//!   `CURLcode` from `include/curl/curl.h`, and its [`Display`](core::fmt::Display)
//!   text reproduces, byte-for-byte, the string that
//!   `curl_easy_strerror()` returns in upstream curl (`lib/strerror.c`).
//! * [`CurlMError`], [`CurlUError`], [`CurlShError`] — the multi (`CURLMcode`),
//!   URL-API (`CURLUcode`) and share (`CURLSHcode`) result-code enums, mirroring
//!   `include/curl/multi.h`, `include/curl/urlapi.h` and the `CURLSHcode`
//!   definition in `include/curl/curl.h` respectively.
//! * [`codes`] — named `i32` constants for **every** numbered slot (active *and*
//!   retired/obsolete) so the FFI crate and internal code can refer to the exact
//!   integers by name.
//!
//! # ABI contract (do not break)
//!
//! curl's public result-code enums are part of its stable ABI. The integer value
//! of each code is observed directly by C consumers and by the `tests/libtest`
//! programs, so the values defined here MUST match curl 8.x exactly. The C enums
//! are *sequential*: retired codes are kept as placeholder slots (e.g.
//! `CURLE_OBSOLETE20 = 20`) precisely so that later codes never shift. Every such
//! placeholder is preserved in [`codes`]. An off-by-one anywhere breaks ABI
//! parity, so the values are pinned by the unit tests at the bottom of this file.
//!
//! Because the workspace dependency graph is strictly one-directional
//! (`curl-rs-ffi` depends on `curl-rs-lib`, never the reverse), the integer
//! mappings live here and are re-exposed verbatim by `curl-rs-ffi`. This module
//! therefore must **never** import from `curl-rs-ffi` or `curl-rs`.
//!
//! # Memory safety
//!
//! This module is pure data and total conversions. It contains **zero** `unsafe`
//! and compiles cleanly under the crate-root `#![forbid(unsafe_code)]`.

/// C-compatible result code, equivalent to curl's `CURLcode`/`CURLMcode`/
/// `CURLUcode`/`CURLSHcode` (a C `int`).
///
/// All of the result-code enums in this module convert to and from this type so
/// that the FFI layer can hand raw integers across the C boundary without any
/// further translation.
pub type CurlCode = i32;

/// Named integer constants for every libcurl result code.
///
/// The top level holds the `CURLcode` (easy-handle) constants, including the
/// retired `CURLE_OBSOLETE*` placeholders and the out-of-band
/// [`CURLE_ALREADY_COMPLETE`](codes::CURLE_ALREADY_COMPLETE) sentinel. The
/// [`multi`](codes::multi), [`url`](codes::url) and [`share`](codes::share)
/// submodules hold the `CURLMcode`, `CURLUcode` and `CURLSHcode` constants.
///
/// These mirror the values in `include/curl/curl.h`, `include/curl/multi.h` and
/// `include/curl/urlapi.h` and are the authoritative integers re-exported by the
/// FFI crate.
pub mod codes {
    // ---- CURLcode (easy handle) — include/curl/curl.h ----------------------
    // Sequential from 0; obsolete slots are intentionally retained so that the
    // active codes never change value.

    /// No error (`CURLE_OK`).
    pub const CURLE_OK: i32 = 0;
    pub const CURLE_UNSUPPORTED_PROTOCOL: i32 = 1;
    pub const CURLE_FAILED_INIT: i32 = 2;
    pub const CURLE_URL_MALFORMAT: i32 = 3;
    pub const CURLE_NOT_BUILT_IN: i32 = 4;
    pub const CURLE_COULDNT_RESOLVE_PROXY: i32 = 5;
    pub const CURLE_COULDNT_RESOLVE_HOST: i32 = 6;
    pub const CURLE_COULDNT_CONNECT: i32 = 7;
    pub const CURLE_WEIRD_SERVER_REPLY: i32 = 8;
    pub const CURLE_REMOTE_ACCESS_DENIED: i32 = 9;
    pub const CURLE_FTP_ACCEPT_FAILED: i32 = 10;
    pub const CURLE_FTP_WEIRD_PASS_REPLY: i32 = 11;
    pub const CURLE_FTP_ACCEPT_TIMEOUT: i32 = 12;
    pub const CURLE_FTP_WEIRD_PASV_REPLY: i32 = 13;
    pub const CURLE_FTP_WEIRD_227_FORMAT: i32 = 14;
    pub const CURLE_FTP_CANT_GET_HOST: i32 = 15;
    pub const CURLE_HTTP2: i32 = 16;
    pub const CURLE_FTP_COULDNT_SET_TYPE: i32 = 17;
    pub const CURLE_PARTIAL_FILE: i32 = 18;
    pub const CURLE_FTP_COULDNT_RETR_FILE: i32 = 19;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE20: i32 = 20;
    pub const CURLE_QUOTE_ERROR: i32 = 21;
    pub const CURLE_HTTP_RETURNED_ERROR: i32 = 22;
    pub const CURLE_WRITE_ERROR: i32 = 23;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE24: i32 = 24;
    pub const CURLE_UPLOAD_FAILED: i32 = 25;
    pub const CURLE_READ_ERROR: i32 = 26;
    pub const CURLE_OUT_OF_MEMORY: i32 = 27;
    pub const CURLE_OPERATION_TIMEDOUT: i32 = 28;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE29: i32 = 29;
    pub const CURLE_FTP_PORT_FAILED: i32 = 30;
    pub const CURLE_FTP_COULDNT_USE_REST: i32 = 31;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE32: i32 = 32;
    pub const CURLE_RANGE_ERROR: i32 = 33;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE34: i32 = 34;
    pub const CURLE_SSL_CONNECT_ERROR: i32 = 35;
    pub const CURLE_BAD_DOWNLOAD_RESUME: i32 = 36;
    pub const CURLE_FILE_COULDNT_READ_FILE: i32 = 37;
    pub const CURLE_LDAP_CANNOT_BIND: i32 = 38;
    pub const CURLE_LDAP_SEARCH_FAILED: i32 = 39;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE40: i32 = 40;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE41: i32 = 41;
    pub const CURLE_ABORTED_BY_CALLBACK: i32 = 42;
    pub const CURLE_BAD_FUNCTION_ARGUMENT: i32 = 43;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE44: i32 = 44;
    pub const CURLE_INTERFACE_FAILED: i32 = 45;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE46: i32 = 46;
    pub const CURLE_TOO_MANY_REDIRECTS: i32 = 47;
    pub const CURLE_UNKNOWN_OPTION: i32 = 48;
    pub const CURLE_SETOPT_OPTION_SYNTAX: i32 = 49;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE50: i32 = 50;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE51: i32 = 51;
    pub const CURLE_GOT_NOTHING: i32 = 52;
    pub const CURLE_SSL_ENGINE_NOTFOUND: i32 = 53;
    pub const CURLE_SSL_ENGINE_SETFAILED: i32 = 54;
    pub const CURLE_SEND_ERROR: i32 = 55;
    pub const CURLE_RECV_ERROR: i32 = 56;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE57: i32 = 57;
    pub const CURLE_SSL_CERTPROBLEM: i32 = 58;
    pub const CURLE_SSL_CIPHER: i32 = 59;
    pub const CURLE_PEER_FAILED_VERIFICATION: i32 = 60;
    pub const CURLE_BAD_CONTENT_ENCODING: i32 = 61;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE62: i32 = 62;
    pub const CURLE_FILESIZE_EXCEEDED: i32 = 63;
    pub const CURLE_USE_SSL_FAILED: i32 = 64;
    pub const CURLE_SEND_FAIL_REWIND: i32 = 65;
    pub const CURLE_SSL_ENGINE_INITFAILED: i32 = 66;
    pub const CURLE_LOGIN_DENIED: i32 = 67;
    pub const CURLE_TFTP_NOTFOUND: i32 = 68;
    pub const CURLE_TFTP_PERM: i32 = 69;
    pub const CURLE_REMOTE_DISK_FULL: i32 = 70;
    pub const CURLE_TFTP_ILLEGAL: i32 = 71;
    pub const CURLE_TFTP_UNKNOWNID: i32 = 72;
    pub const CURLE_REMOTE_FILE_EXISTS: i32 = 73;
    pub const CURLE_TFTP_NOSUCHUSER: i32 = 74;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE75: i32 = 75;
    /// Retired slot — kept so later codes keep their values.
    pub const CURLE_OBSOLETE76: i32 = 76;
    pub const CURLE_SSL_CACERT_BADFILE: i32 = 77;
    pub const CURLE_REMOTE_FILE_NOT_FOUND: i32 = 78;
    pub const CURLE_SSH: i32 = 79;
    pub const CURLE_SSL_SHUTDOWN_FAILED: i32 = 80;
    pub const CURLE_AGAIN: i32 = 81;
    pub const CURLE_SSL_CRL_BADFILE: i32 = 82;
    pub const CURLE_SSL_ISSUER_ERROR: i32 = 83;
    pub const CURLE_FTP_PRET_FAILED: i32 = 84;
    pub const CURLE_RTSP_CSEQ_ERROR: i32 = 85;
    pub const CURLE_RTSP_SESSION_ERROR: i32 = 86;
    pub const CURLE_FTP_BAD_FILE_LIST: i32 = 87;
    pub const CURLE_CHUNK_FAILED: i32 = 88;
    pub const CURLE_NO_CONNECTION_AVAILABLE: i32 = 89;
    pub const CURLE_SSL_PINNEDPUBKEYNOTMATCH: i32 = 90;
    pub const CURLE_SSL_INVALIDCERTSTATUS: i32 = 91;
    pub const CURLE_HTTP2_STREAM: i32 = 92;
    pub const CURLE_RECURSIVE_API_CALL: i32 = 93;
    pub const CURLE_AUTH_ERROR: i32 = 94;
    pub const CURLE_HTTP3: i32 = 95;
    pub const CURLE_QUIC_CONNECT_ERROR: i32 = 96;
    pub const CURLE_PROXY: i32 = 97;
    pub const CURLE_SSL_CLIENTCERT: i32 = 98;
    pub const CURLE_UNRECOVERABLE_POLL: i32 = 99;
    pub const CURLE_TOO_LARGE: i32 = 100;
    pub const CURLE_ECH_REQUIRED: i32 = 101;
    /// One past the last defined `CURLcode`. `CURL_LAST` is never a real result
    /// code — it exists only as an upper bound. Active codes are in `0..CURL_LAST`.
    pub const CURL_LAST: i32 = 102;

    /// Out-of-band internal sentinel (`#define CURLE_ALREADY_COMPLETE 99999`).
    ///
    /// This value is **not** part of the sequential `CURLcode` enum; curl
    /// `#define`s it separately and uses it internally to signal that a transfer
    /// has already finished. `curl_easy_strerror()` has no case for it and
    /// returns `"Unknown error"`.
    pub const CURLE_ALREADY_COMPLETE: i32 = 99999;

    /// `CURLMcode` constants — `include/curl/multi.h`.
    pub mod multi {
        /// Signals the caller to call `curl_multi_perform()` again soon (`-1`).
        pub const CURLM_CALL_MULTI_PERFORM: i32 = -1;
        pub const CURLM_OK: i32 = 0;
        pub const CURLM_BAD_HANDLE: i32 = 1;
        pub const CURLM_BAD_EASY_HANDLE: i32 = 2;
        pub const CURLM_OUT_OF_MEMORY: i32 = 3;
        pub const CURLM_INTERNAL_ERROR: i32 = 4;
        pub const CURLM_BAD_SOCKET: i32 = 5;
        pub const CURLM_UNKNOWN_OPTION: i32 = 6;
        pub const CURLM_ADDED_ALREADY: i32 = 7;
        pub const CURLM_RECURSIVE_API_CALL: i32 = 8;
        pub const CURLM_WAKEUP_FAILURE: i32 = 9;
        pub const CURLM_BAD_FUNCTION_ARGUMENT: i32 = 10;
        pub const CURLM_ABORTED_BY_CALLBACK: i32 = 11;
        pub const CURLM_UNRECOVERABLE_POLL: i32 = 12;
        /// One past the last defined `CURLMcode`; never a real result code.
        pub const CURLM_LAST: i32 = 13;
    }

    /// `CURLUcode` constants — `include/curl/urlapi.h`.
    pub mod url {
        pub const CURLUE_OK: i32 = 0;
        pub const CURLUE_BAD_HANDLE: i32 = 1;
        pub const CURLUE_BAD_PARTPOINTER: i32 = 2;
        pub const CURLUE_MALFORMED_INPUT: i32 = 3;
        pub const CURLUE_BAD_PORT_NUMBER: i32 = 4;
        pub const CURLUE_UNSUPPORTED_SCHEME: i32 = 5;
        pub const CURLUE_URLDECODE: i32 = 6;
        pub const CURLUE_OUT_OF_MEMORY: i32 = 7;
        pub const CURLUE_USER_NOT_ALLOWED: i32 = 8;
        pub const CURLUE_UNKNOWN_PART: i32 = 9;
        pub const CURLUE_NO_SCHEME: i32 = 10;
        pub const CURLUE_NO_USER: i32 = 11;
        pub const CURLUE_NO_PASSWORD: i32 = 12;
        pub const CURLUE_NO_OPTIONS: i32 = 13;
        pub const CURLUE_NO_HOST: i32 = 14;
        pub const CURLUE_NO_PORT: i32 = 15;
        pub const CURLUE_NO_QUERY: i32 = 16;
        pub const CURLUE_NO_FRAGMENT: i32 = 17;
        pub const CURLUE_NO_ZONEID: i32 = 18;
        pub const CURLUE_BAD_FILE_URL: i32 = 19;
        pub const CURLUE_BAD_FRAGMENT: i32 = 20;
        pub const CURLUE_BAD_HOSTNAME: i32 = 21;
        pub const CURLUE_BAD_IPV6: i32 = 22;
        pub const CURLUE_BAD_LOGIN: i32 = 23;
        pub const CURLUE_BAD_PASSWORD: i32 = 24;
        pub const CURLUE_BAD_PATH: i32 = 25;
        pub const CURLUE_BAD_QUERY: i32 = 26;
        pub const CURLUE_BAD_SCHEME: i32 = 27;
        pub const CURLUE_BAD_SLASHES: i32 = 28;
        pub const CURLUE_BAD_USER: i32 = 29;
        pub const CURLUE_LACKS_IDN: i32 = 30;
        pub const CURLUE_TOO_LARGE: i32 = 31;
        /// One past the last defined `CURLUcode`; never a real result code.
        pub const CURLUE_LAST: i32 = 32;
    }

    /// `CURLSHcode` constants — `include/curl/curl.h`.
    pub mod share {
        pub const CURLSHE_OK: i32 = 0;
        pub const CURLSHE_BAD_OPTION: i32 = 1;
        pub const CURLSHE_IN_USE: i32 = 2;
        pub const CURLSHE_INVALID: i32 = 3;
        pub const CURLSHE_NOMEM: i32 = 4;
        pub const CURLSHE_NOT_BUILT_IN: i32 = 5;
        /// One past the last defined `CURLSHcode`; never a real result code.
        pub const CURLSHE_LAST: i32 = 6;
    }

    /// `CURLHcode` constants — `include/curl/header.h`.
    ///
    /// The header-API result codes returned by `curl_easy_header()`. The C enum
    /// is sequential from `0`; these integers are observed by C consumers and the
    /// `tests/data` header-API tests, so the values are pinned exactly.
    pub mod header {
        pub const CURLHE_OK: i32 = 0;
        pub const CURLHE_BADINDEX: i32 = 1;
        pub const CURLHE_MISSING: i32 = 2;
        pub const CURLHE_NOHEADERS: i32 = 3;
        pub const CURLHE_NOREQUEST: i32 = 4;
        pub const CURLHE_OUT_OF_MEMORY: i32 = 5;
        pub const CURLHE_BAD_ARGUMENT: i32 = 6;
        pub const CURLHE_NOT_BUILT_IN: i32 = 7;
        /// One past the last defined `CURLHcode`; never a real result code.
        pub const CURLHE_LAST: i32 = 8;
    }
}

/// The crate-internal error type, modelling curl's `CURLcode` result space.
///
/// Every active `CURLcode` from `include/curl/curl.h` has exactly one variant
/// here, named idiomatically (e.g. `CURLE_COULDNT_RESOLVE_HOST` becomes
/// [`CurlError::CouldntResolveHost`]). The [`Display`](core::fmt::Display)
/// implementation — derived via [`thiserror`] — yields the *exact* string that
/// upstream `curl_easy_strerror()` returns for that code (see `lib/strerror.c`),
/// because the CLI and the regression suite compare those strings verbatim.
///
/// Retired `CURLE_OBSOLETE*` slots are deliberately **not** represented as
/// variants (they are not real errors); their integers still round-trip through
/// the [`Unknown`](CurlError::Unknown) catch-all and are available by name in
/// [`codes`]. The exact integer for any value is obtained with
/// [`CurlError::code`] (or `i32::from`), and the reverse mapping with
/// [`CurlError::from_code`].
///
/// The type is `Copy` because it carries no owned data: contextual errors (I/O,
/// TLS, …) are mapped *into* the appropriate code at the conversion boundary
/// (see [`From<std::io::Error>`](#impl-From<Error>-for-CurlError)) rather than
/// being stored. Keeping it `Copy`/`Eq` makes the integer mapping that the FFI
/// layer re-exposes trivial and allocation-free.
///
/// # Note on [`Ok`](CurlError::Ok)
///
/// `CURLE_OK` (value `0`) is modelled for completeness of the ABI mapping so
/// that `code`/`from_code` form a total bijection over the active code space.
/// Idiomatic code should represent success with [`Result::Ok`] and reserve
/// `CurlError` for the error path; `CurlError::Ok` exists primarily so the FFI
/// layer can name the zero code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum CurlError {
    /// `CURLE_OK` (0) — success sentinel. See the type-level note above.
    #[error("No error")]
    Ok,
    /// `CURLE_UNSUPPORTED_PROTOCOL` (1).
    #[error("Unsupported protocol")]
    UnsupportedProtocol,
    /// `CURLE_FAILED_INIT` (2).
    #[error("Failed initialization")]
    FailedInit,
    /// `CURLE_URL_MALFORMAT` (3).
    #[error("URL using bad/illegal format or missing URL")]
    UrlMalformat,
    /// `CURLE_NOT_BUILT_IN` (4).
    #[error(
        "A requested feature, protocol or option was not found built-in in \
         this libcurl due to a build-time decision."
    )]
    NotBuiltIn,
    /// `CURLE_COULDNT_RESOLVE_PROXY` (5).
    #[error("Could not resolve proxy name")]
    CouldntResolveProxy,
    /// `CURLE_COULDNT_RESOLVE_HOST` (6).
    #[error("Could not resolve hostname")]
    CouldntResolveHost,
    /// `CURLE_COULDNT_CONNECT` (7).
    #[error("Could not connect to server")]
    CouldntConnect,
    /// `CURLE_WEIRD_SERVER_REPLY` (8).
    #[error("Weird server reply")]
    WeirdServerReply,
    /// `CURLE_REMOTE_ACCESS_DENIED` (9).
    #[error("Access denied to remote resource")]
    RemoteAccessDenied,
    /// `CURLE_FTP_ACCEPT_FAILED` (10).
    #[error("FTP: The server failed to connect to data port")]
    FtpAcceptFailed,
    /// `CURLE_FTP_WEIRD_PASS_REPLY` (11).
    #[error("FTP: unknown PASS reply")]
    FtpWeirdPassReply,
    /// `CURLE_FTP_ACCEPT_TIMEOUT` (12).
    #[error("FTP: Accepting server connect has timed out")]
    FtpAcceptTimeout,
    /// `CURLE_FTP_WEIRD_PASV_REPLY` (13).
    #[error("FTP: unknown PASV reply")]
    FtpWeirdPasvReply,
    /// `CURLE_FTP_WEIRD_227_FORMAT` (14).
    #[error("FTP: unknown 227 response format")]
    FtpWeird227Format,
    /// `CURLE_FTP_CANT_GET_HOST` (15).
    #[error("FTP: cannot figure out the host in the PASV response")]
    FtpCantGetHost,
    /// `CURLE_HTTP2` (16).
    #[error("Error in the HTTP2 framing layer")]
    Http2,
    /// `CURLE_FTP_COULDNT_SET_TYPE` (17).
    #[error("FTP: could not set file type")]
    FtpCouldntSetType,
    /// `CURLE_PARTIAL_FILE` (18).
    #[error("Transferred a partial file")]
    PartialFile,
    /// `CURLE_FTP_COULDNT_RETR_FILE` (19).
    #[error("FTP: could not retrieve (RETR failed) the specified file")]
    FtpCouldntRetrFile,
    /// `CURLE_QUOTE_ERROR` (21).
    #[error("Quote command returned error")]
    QuoteError,
    /// `CURLE_HTTP_RETURNED_ERROR` (22).
    #[error("HTTP response code said error")]
    HttpReturnedError,
    /// `CURLE_WRITE_ERROR` (23).
    #[error("Failed writing received data to disk/application")]
    WriteError,
    /// `CURLE_UPLOAD_FAILED` (25).
    #[error("Upload failed (at start/before it took off)")]
    UploadFailed,
    /// `CURLE_READ_ERROR` (26).
    #[error("Failed to open/read local data from file/application")]
    ReadError,
    /// `CURLE_OUT_OF_MEMORY` (27).
    #[error("Out of memory")]
    OutOfMemory,
    /// `CURLE_OPERATION_TIMEDOUT` (28).
    #[error("Timeout was reached")]
    OperationTimedout,
    /// `CURLE_FTP_PORT_FAILED` (30).
    #[error("FTP: command PORT failed")]
    FtpPortFailed,
    /// `CURLE_FTP_COULDNT_USE_REST` (31).
    #[error("FTP: command REST failed")]
    FtpCouldntUseRest,
    /// `CURLE_RANGE_ERROR` (33).
    #[error("Requested range was not delivered by the server")]
    RangeError,
    /// `CURLE_SSL_CONNECT_ERROR` (35).
    #[error("SSL connect error")]
    SslConnectError,
    /// `CURLE_BAD_DOWNLOAD_RESUME` (36).
    #[error("Could not resume download")]
    BadDownloadResume,
    /// `CURLE_FILE_COULDNT_READ_FILE` (37).
    #[error("Could not read a file:// file")]
    FileCouldntReadFile,
    /// `CURLE_LDAP_CANNOT_BIND` (38).
    #[error("LDAP: cannot bind")]
    LdapCannotBind,
    /// `CURLE_LDAP_SEARCH_FAILED` (39).
    #[error("LDAP: search failed")]
    LdapSearchFailed,
    /// `CURLE_ABORTED_BY_CALLBACK` (42).
    #[error("Operation was aborted by an application callback")]
    AbortedByCallback,
    /// `CURLE_BAD_FUNCTION_ARGUMENT` (43).
    #[error("A libcurl function was given a bad argument")]
    BadFunctionArgument,
    /// `CURLE_INTERFACE_FAILED` (45).
    #[error("Failed binding local connection end")]
    InterfaceFailed,
    /// `CURLE_TOO_MANY_REDIRECTS` (47).
    #[error("Number of redirects hit maximum amount")]
    TooManyRedirects,
    /// `CURLE_UNKNOWN_OPTION` (48).
    #[error("An unknown option was passed in to libcurl")]
    UnknownOption,
    /// `CURLE_SETOPT_OPTION_SYNTAX` (49).
    #[error("Malformed option provided in a setopt")]
    SetoptOptionSyntax,
    /// `CURLE_GOT_NOTHING` (52).
    #[error("Server returned nothing (no headers, no data)")]
    GotNothing,
    /// `CURLE_SSL_ENGINE_NOTFOUND` (53).
    #[error("SSL crypto engine not found")]
    SslEngineNotfound,
    /// `CURLE_SSL_ENGINE_SETFAILED` (54).
    #[error("Can not set SSL crypto engine as default")]
    SslEngineSetfailed,
    /// `CURLE_SEND_ERROR` (55).
    #[error("Failed sending data to the peer")]
    SendError,
    /// `CURLE_RECV_ERROR` (56).
    #[error("Failure when receiving data from the peer")]
    RecvError,
    /// `CURLE_SSL_CERTPROBLEM` (58).
    #[error("Problem with the local SSL certificate")]
    SslCertproblem,
    /// `CURLE_SSL_CIPHER` (59).
    #[error("Could not use specified SSL cipher")]
    SslCipher,
    /// `CURLE_PEER_FAILED_VERIFICATION` (60).
    #[error("SSL peer certificate or SSH remote key was not OK")]
    PeerFailedVerification,
    /// `CURLE_BAD_CONTENT_ENCODING` (61).
    #[error("Unrecognized or bad HTTP Content or Transfer-Encoding")]
    BadContentEncoding,
    /// `CURLE_FILESIZE_EXCEEDED` (63).
    #[error("Maximum file size exceeded")]
    FilesizeExceeded,
    /// `CURLE_USE_SSL_FAILED` (64).
    #[error("Requested SSL level failed")]
    UseSslFailed,
    /// `CURLE_SEND_FAIL_REWIND` (65).
    #[error("Send failed since rewinding of the data stream failed")]
    SendFailRewind,
    /// `CURLE_SSL_ENGINE_INITFAILED` (66).
    #[error("Failed to initialise SSL crypto engine")]
    SslEngineInitfailed,
    /// `CURLE_LOGIN_DENIED` (67).
    #[error("Login denied")]
    LoginDenied,
    /// `CURLE_TFTP_NOTFOUND` (68).
    #[error("TFTP: File Not Found")]
    TftpNotfound,
    /// `CURLE_TFTP_PERM` (69).
    #[error("TFTP: Access Violation")]
    TftpPerm,
    /// `CURLE_REMOTE_DISK_FULL` (70).
    #[error("Disk full or allocation exceeded")]
    RemoteDiskFull,
    /// `CURLE_TFTP_ILLEGAL` (71).
    #[error("TFTP: Illegal operation")]
    TftpIllegal,
    /// `CURLE_TFTP_UNKNOWNID` (72).
    #[error("TFTP: Unknown transfer ID")]
    TftpUnknownid,
    /// `CURLE_REMOTE_FILE_EXISTS` (73).
    #[error("Remote file already exists")]
    RemoteFileExists,
    /// `CURLE_TFTP_NOSUCHUSER` (74).
    #[error("TFTP: No such user")]
    TftpNosuchuser,
    /// `CURLE_SSL_CACERT_BADFILE` (77).
    #[error("Problem with the SSL CA cert (path? access rights?)")]
    SslCacertBadfile,
    /// `CURLE_REMOTE_FILE_NOT_FOUND` (78).
    #[error("Remote file not found")]
    RemoteFileNotFound,
    /// `CURLE_SSH` (79).
    #[error("Error in the SSH layer")]
    Ssh,
    /// `CURLE_SSL_SHUTDOWN_FAILED` (80).
    #[error("Failed to shut down the SSL connection")]
    SslShutdownFailed,
    /// `CURLE_AGAIN` (81).
    #[error("Socket not ready for send/recv")]
    Again,
    /// `CURLE_SSL_CRL_BADFILE` (82).
    #[error("Failed to load CRL file (path? access rights?, format?)")]
    SslCrlBadfile,
    /// `CURLE_SSL_ISSUER_ERROR` (83).
    #[error("Issuer check against peer certificate failed")]
    SslIssuerError,
    /// `CURLE_FTP_PRET_FAILED` (84).
    #[error("FTP: The server did not accept the PRET command.")]
    FtpPretFailed,
    /// `CURLE_RTSP_CSEQ_ERROR` (85).
    #[error("RTSP CSeq mismatch or invalid CSeq")]
    RtspCseqError,
    /// `CURLE_RTSP_SESSION_ERROR` (86).
    #[error("RTSP session error")]
    RtspSessionError,
    /// `CURLE_FTP_BAD_FILE_LIST` (87).
    #[error("Unable to parse FTP file list")]
    FtpBadFileList,
    /// `CURLE_CHUNK_FAILED` (88).
    #[error("Chunk callback failed")]
    ChunkFailed,
    /// `CURLE_NO_CONNECTION_AVAILABLE` (89).
    #[error("The max connection limit is reached")]
    NoConnectionAvailable,
    /// `CURLE_SSL_PINNEDPUBKEYNOTMATCH` (90).
    #[error("SSL public key does not match pinned public key")]
    SslPinnedpubkeynotmatch,
    /// `CURLE_SSL_INVALIDCERTSTATUS` (91).
    #[error("SSL server certificate status verification FAILED")]
    SslInvalidcertstatus,
    /// `CURLE_HTTP2_STREAM` (92).
    #[error("Stream error in the HTTP/2 framing layer")]
    Http2Stream,
    /// `CURLE_RECURSIVE_API_CALL` (93).
    #[error("API function called from within callback")]
    RecursiveApiCall,
    /// `CURLE_AUTH_ERROR` (94).
    #[error("An authentication function returned an error")]
    AuthError,
    /// `CURLE_HTTP3` (95).
    #[error("HTTP/3 error")]
    Http3,
    /// `CURLE_QUIC_CONNECT_ERROR` (96).
    #[error("QUIC connection error")]
    QuicConnectError,
    /// `CURLE_PROXY` (97).
    #[error("proxy handshake error")]
    Proxy,
    /// `CURLE_SSL_CLIENTCERT` (98).
    #[error("SSL Client Certificate required")]
    SslClientcert,
    /// `CURLE_UNRECOVERABLE_POLL` (99).
    #[error("Unrecoverable error in select/poll")]
    UnrecoverablePoll,
    /// `CURLE_TOO_LARGE` (100).
    #[error("A value or data field grew larger than allowed")]
    TooLarge,
    /// `CURLE_ECH_REQUIRED` (101).
    #[error("ECH attempted but failed")]
    EchRequired,
    /// `CURLE_ALREADY_COMPLETE` (99999) — out-of-band internal sentinel.
    ///
    /// Not part of the sequential `CURLcode` enum and never produced by
    /// `curl_easy_strerror()`, which would return `"Unknown error"` for this
    /// value; the [`Display`](core::fmt::Display) text therefore matches that.
    #[error("Unknown error")]
    AlreadyComplete,
    /// Any result code without a dedicated variant — retired `CURLE_OBSOLETE*`
    /// slots and any integer outside the known range. Preserves the original
    /// integer so it round-trips exactly through [`code`](CurlError::code) /
    /// [`from_code`](CurlError::from_code). Matches `curl_easy_strerror()`'s
    /// default `"Unknown error"`.
    #[error("Unknown error")]
    Unknown(CurlCode),
}

impl CurlError {
    /// Returns the exact C `CURLcode` integer for this error.
    ///
    /// This is the value a C caller observes across the FFI boundary, so it must
    /// match curl 8.x precisely. The mapping is total and round-trips with
    /// [`from_code`](CurlError::from_code) for every active code.
    #[must_use]
    pub const fn code(&self) -> CurlCode {
        match self {
            CurlError::Ok => codes::CURLE_OK,
            CurlError::UnsupportedProtocol => codes::CURLE_UNSUPPORTED_PROTOCOL,
            CurlError::FailedInit => codes::CURLE_FAILED_INIT,
            CurlError::UrlMalformat => codes::CURLE_URL_MALFORMAT,
            CurlError::NotBuiltIn => codes::CURLE_NOT_BUILT_IN,
            CurlError::CouldntResolveProxy => codes::CURLE_COULDNT_RESOLVE_PROXY,
            CurlError::CouldntResolveHost => codes::CURLE_COULDNT_RESOLVE_HOST,
            CurlError::CouldntConnect => codes::CURLE_COULDNT_CONNECT,
            CurlError::WeirdServerReply => codes::CURLE_WEIRD_SERVER_REPLY,
            CurlError::RemoteAccessDenied => codes::CURLE_REMOTE_ACCESS_DENIED,
            CurlError::FtpAcceptFailed => codes::CURLE_FTP_ACCEPT_FAILED,
            CurlError::FtpWeirdPassReply => codes::CURLE_FTP_WEIRD_PASS_REPLY,
            CurlError::FtpAcceptTimeout => codes::CURLE_FTP_ACCEPT_TIMEOUT,
            CurlError::FtpWeirdPasvReply => codes::CURLE_FTP_WEIRD_PASV_REPLY,
            CurlError::FtpWeird227Format => codes::CURLE_FTP_WEIRD_227_FORMAT,
            CurlError::FtpCantGetHost => codes::CURLE_FTP_CANT_GET_HOST,
            CurlError::Http2 => codes::CURLE_HTTP2,
            CurlError::FtpCouldntSetType => codes::CURLE_FTP_COULDNT_SET_TYPE,
            CurlError::PartialFile => codes::CURLE_PARTIAL_FILE,
            CurlError::FtpCouldntRetrFile => codes::CURLE_FTP_COULDNT_RETR_FILE,
            CurlError::QuoteError => codes::CURLE_QUOTE_ERROR,
            CurlError::HttpReturnedError => codes::CURLE_HTTP_RETURNED_ERROR,
            CurlError::WriteError => codes::CURLE_WRITE_ERROR,
            CurlError::UploadFailed => codes::CURLE_UPLOAD_FAILED,
            CurlError::ReadError => codes::CURLE_READ_ERROR,
            CurlError::OutOfMemory => codes::CURLE_OUT_OF_MEMORY,
            CurlError::OperationTimedout => codes::CURLE_OPERATION_TIMEDOUT,
            CurlError::FtpPortFailed => codes::CURLE_FTP_PORT_FAILED,
            CurlError::FtpCouldntUseRest => codes::CURLE_FTP_COULDNT_USE_REST,
            CurlError::RangeError => codes::CURLE_RANGE_ERROR,
            CurlError::SslConnectError => codes::CURLE_SSL_CONNECT_ERROR,
            CurlError::BadDownloadResume => codes::CURLE_BAD_DOWNLOAD_RESUME,
            CurlError::FileCouldntReadFile => codes::CURLE_FILE_COULDNT_READ_FILE,
            CurlError::LdapCannotBind => codes::CURLE_LDAP_CANNOT_BIND,
            CurlError::LdapSearchFailed => codes::CURLE_LDAP_SEARCH_FAILED,
            CurlError::AbortedByCallback => codes::CURLE_ABORTED_BY_CALLBACK,
            CurlError::BadFunctionArgument => codes::CURLE_BAD_FUNCTION_ARGUMENT,
            CurlError::InterfaceFailed => codes::CURLE_INTERFACE_FAILED,
            CurlError::TooManyRedirects => codes::CURLE_TOO_MANY_REDIRECTS,
            CurlError::UnknownOption => codes::CURLE_UNKNOWN_OPTION,
            CurlError::SetoptOptionSyntax => codes::CURLE_SETOPT_OPTION_SYNTAX,
            CurlError::GotNothing => codes::CURLE_GOT_NOTHING,
            CurlError::SslEngineNotfound => codes::CURLE_SSL_ENGINE_NOTFOUND,
            CurlError::SslEngineSetfailed => codes::CURLE_SSL_ENGINE_SETFAILED,
            CurlError::SendError => codes::CURLE_SEND_ERROR,
            CurlError::RecvError => codes::CURLE_RECV_ERROR,
            CurlError::SslCertproblem => codes::CURLE_SSL_CERTPROBLEM,
            CurlError::SslCipher => codes::CURLE_SSL_CIPHER,
            CurlError::PeerFailedVerification => codes::CURLE_PEER_FAILED_VERIFICATION,
            CurlError::BadContentEncoding => codes::CURLE_BAD_CONTENT_ENCODING,
            CurlError::FilesizeExceeded => codes::CURLE_FILESIZE_EXCEEDED,
            CurlError::UseSslFailed => codes::CURLE_USE_SSL_FAILED,
            CurlError::SendFailRewind => codes::CURLE_SEND_FAIL_REWIND,
            CurlError::SslEngineInitfailed => codes::CURLE_SSL_ENGINE_INITFAILED,
            CurlError::LoginDenied => codes::CURLE_LOGIN_DENIED,
            CurlError::TftpNotfound => codes::CURLE_TFTP_NOTFOUND,
            CurlError::TftpPerm => codes::CURLE_TFTP_PERM,
            CurlError::RemoteDiskFull => codes::CURLE_REMOTE_DISK_FULL,
            CurlError::TftpIllegal => codes::CURLE_TFTP_ILLEGAL,
            CurlError::TftpUnknownid => codes::CURLE_TFTP_UNKNOWNID,
            CurlError::RemoteFileExists => codes::CURLE_REMOTE_FILE_EXISTS,
            CurlError::TftpNosuchuser => codes::CURLE_TFTP_NOSUCHUSER,
            CurlError::SslCacertBadfile => codes::CURLE_SSL_CACERT_BADFILE,
            CurlError::RemoteFileNotFound => codes::CURLE_REMOTE_FILE_NOT_FOUND,
            CurlError::Ssh => codes::CURLE_SSH,
            CurlError::SslShutdownFailed => codes::CURLE_SSL_SHUTDOWN_FAILED,
            CurlError::Again => codes::CURLE_AGAIN,
            CurlError::SslCrlBadfile => codes::CURLE_SSL_CRL_BADFILE,
            CurlError::SslIssuerError => codes::CURLE_SSL_ISSUER_ERROR,
            CurlError::FtpPretFailed => codes::CURLE_FTP_PRET_FAILED,
            CurlError::RtspCseqError => codes::CURLE_RTSP_CSEQ_ERROR,
            CurlError::RtspSessionError => codes::CURLE_RTSP_SESSION_ERROR,
            CurlError::FtpBadFileList => codes::CURLE_FTP_BAD_FILE_LIST,
            CurlError::ChunkFailed => codes::CURLE_CHUNK_FAILED,
            CurlError::NoConnectionAvailable => codes::CURLE_NO_CONNECTION_AVAILABLE,
            CurlError::SslPinnedpubkeynotmatch => codes::CURLE_SSL_PINNEDPUBKEYNOTMATCH,
            CurlError::SslInvalidcertstatus => codes::CURLE_SSL_INVALIDCERTSTATUS,
            CurlError::Http2Stream => codes::CURLE_HTTP2_STREAM,
            CurlError::RecursiveApiCall => codes::CURLE_RECURSIVE_API_CALL,
            CurlError::AuthError => codes::CURLE_AUTH_ERROR,
            CurlError::Http3 => codes::CURLE_HTTP3,
            CurlError::QuicConnectError => codes::CURLE_QUIC_CONNECT_ERROR,
            CurlError::Proxy => codes::CURLE_PROXY,
            CurlError::SslClientcert => codes::CURLE_SSL_CLIENTCERT,
            CurlError::UnrecoverablePoll => codes::CURLE_UNRECOVERABLE_POLL,
            CurlError::TooLarge => codes::CURLE_TOO_LARGE,
            CurlError::EchRequired => codes::CURLE_ECH_REQUIRED,
            CurlError::AlreadyComplete => codes::CURLE_ALREADY_COMPLETE,
            CurlError::Unknown(code) => *code,
        }
    }

    /// Returns the static human-readable description for this error.
    ///
    /// This reproduces, verbatim, the string `curl_easy_strerror()` returns for
    /// the corresponding `CURLcode` (`lib/strerror.c`). It is identical to the
    /// [`Display`](core::fmt::Display) output; a unit test guards that invariant.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            CurlError::Ok => "No error",
            CurlError::UnsupportedProtocol => "Unsupported protocol",
            CurlError::FailedInit => "Failed initialization",
            CurlError::UrlMalformat => "URL using bad/illegal format or missing URL",
            CurlError::NotBuiltIn => {
                "A requested feature, protocol or option was not found built-in in \
                 this libcurl due to a build-time decision."
            }
            CurlError::CouldntResolveProxy => "Could not resolve proxy name",
            CurlError::CouldntResolveHost => "Could not resolve hostname",
            CurlError::CouldntConnect => "Could not connect to server",
            CurlError::WeirdServerReply => "Weird server reply",
            CurlError::RemoteAccessDenied => "Access denied to remote resource",
            CurlError::FtpAcceptFailed => "FTP: The server failed to connect to data port",
            CurlError::FtpWeirdPassReply => "FTP: unknown PASS reply",
            CurlError::FtpAcceptTimeout => "FTP: Accepting server connect has timed out",
            CurlError::FtpWeirdPasvReply => "FTP: unknown PASV reply",
            CurlError::FtpWeird227Format => "FTP: unknown 227 response format",
            CurlError::FtpCantGetHost => "FTP: cannot figure out the host in the PASV response",
            CurlError::Http2 => "Error in the HTTP2 framing layer",
            CurlError::FtpCouldntSetType => "FTP: could not set file type",
            CurlError::PartialFile => "Transferred a partial file",
            CurlError::FtpCouldntRetrFile => {
                "FTP: could not retrieve (RETR failed) the specified file"
            }
            CurlError::QuoteError => "Quote command returned error",
            CurlError::HttpReturnedError => "HTTP response code said error",
            CurlError::WriteError => "Failed writing received data to disk/application",
            CurlError::UploadFailed => "Upload failed (at start/before it took off)",
            CurlError::ReadError => "Failed to open/read local data from file/application",
            CurlError::OutOfMemory => "Out of memory",
            CurlError::OperationTimedout => "Timeout was reached",
            CurlError::FtpPortFailed => "FTP: command PORT failed",
            CurlError::FtpCouldntUseRest => "FTP: command REST failed",
            CurlError::RangeError => "Requested range was not delivered by the server",
            CurlError::SslConnectError => "SSL connect error",
            CurlError::BadDownloadResume => "Could not resume download",
            CurlError::FileCouldntReadFile => "Could not read a file:// file",
            CurlError::LdapCannotBind => "LDAP: cannot bind",
            CurlError::LdapSearchFailed => "LDAP: search failed",
            CurlError::AbortedByCallback => "Operation was aborted by an application callback",
            CurlError::BadFunctionArgument => "A libcurl function was given a bad argument",
            CurlError::InterfaceFailed => "Failed binding local connection end",
            CurlError::TooManyRedirects => "Number of redirects hit maximum amount",
            CurlError::UnknownOption => "An unknown option was passed in to libcurl",
            CurlError::SetoptOptionSyntax => "Malformed option provided in a setopt",
            CurlError::GotNothing => "Server returned nothing (no headers, no data)",
            CurlError::SslEngineNotfound => "SSL crypto engine not found",
            CurlError::SslEngineSetfailed => "Can not set SSL crypto engine as default",
            CurlError::SendError => "Failed sending data to the peer",
            CurlError::RecvError => "Failure when receiving data from the peer",
            CurlError::SslCertproblem => "Problem with the local SSL certificate",
            CurlError::SslCipher => "Could not use specified SSL cipher",
            CurlError::PeerFailedVerification => {
                "SSL peer certificate or SSH remote key was not OK"
            }
            CurlError::BadContentEncoding => {
                "Unrecognized or bad HTTP Content or Transfer-Encoding"
            }
            CurlError::FilesizeExceeded => "Maximum file size exceeded",
            CurlError::UseSslFailed => "Requested SSL level failed",
            CurlError::SendFailRewind => "Send failed since rewinding of the data stream failed",
            CurlError::SslEngineInitfailed => "Failed to initialise SSL crypto engine",
            CurlError::LoginDenied => "Login denied",
            CurlError::TftpNotfound => "TFTP: File Not Found",
            CurlError::TftpPerm => "TFTP: Access Violation",
            CurlError::RemoteDiskFull => "Disk full or allocation exceeded",
            CurlError::TftpIllegal => "TFTP: Illegal operation",
            CurlError::TftpUnknownid => "TFTP: Unknown transfer ID",
            CurlError::RemoteFileExists => "Remote file already exists",
            CurlError::TftpNosuchuser => "TFTP: No such user",
            CurlError::SslCacertBadfile => "Problem with the SSL CA cert (path? access rights?)",
            CurlError::RemoteFileNotFound => "Remote file not found",
            CurlError::Ssh => "Error in the SSH layer",
            CurlError::SslShutdownFailed => "Failed to shut down the SSL connection",
            CurlError::Again => "Socket not ready for send/recv",
            CurlError::SslCrlBadfile => "Failed to load CRL file (path? access rights?, format?)",
            CurlError::SslIssuerError => "Issuer check against peer certificate failed",
            CurlError::FtpPretFailed => "FTP: The server did not accept the PRET command.",
            CurlError::RtspCseqError => "RTSP CSeq mismatch or invalid CSeq",
            CurlError::RtspSessionError => "RTSP session error",
            CurlError::FtpBadFileList => "Unable to parse FTP file list",
            CurlError::ChunkFailed => "Chunk callback failed",
            CurlError::NoConnectionAvailable => "The max connection limit is reached",
            CurlError::SslPinnedpubkeynotmatch => "SSL public key does not match pinned public key",
            CurlError::SslInvalidcertstatus => "SSL server certificate status verification FAILED",
            CurlError::Http2Stream => "Stream error in the HTTP/2 framing layer",
            CurlError::RecursiveApiCall => "API function called from within callback",
            CurlError::AuthError => "An authentication function returned an error",
            CurlError::Http3 => "HTTP/3 error",
            CurlError::QuicConnectError => "QUIC connection error",
            CurlError::Proxy => "proxy handshake error",
            CurlError::SslClientcert => "SSL Client Certificate required",
            CurlError::UnrecoverablePoll => "Unrecoverable error in select/poll",
            CurlError::TooLarge => "A value or data field grew larger than allowed",
            CurlError::EchRequired => "ECH attempted but failed",
            // Neither value below has a case in `curl_easy_strerror`, which falls
            // through to its default "Unknown error".
            CurlError::AlreadyComplete => "Unknown error",
            CurlError::Unknown(_) => "Unknown error",
        }
    }

    /// Builds a [`CurlError`] from a raw C result code.
    ///
    /// Active codes map to their dedicated variant and `99999` maps to
    /// [`AlreadyComplete`](CurlError::AlreadyComplete). Every other integer
    /// (including the retired `CURLE_OBSOLETE*` slots) is preserved in
    /// [`Unknown`](CurlError::Unknown) so the value round-trips through
    /// [`code`](CurlError::code) losslessly.
    #[must_use]
    pub const fn from_code(code: CurlCode) -> CurlError {
        match code {
            codes::CURLE_OK => CurlError::Ok,
            codes::CURLE_UNSUPPORTED_PROTOCOL => CurlError::UnsupportedProtocol,
            codes::CURLE_FAILED_INIT => CurlError::FailedInit,
            codes::CURLE_URL_MALFORMAT => CurlError::UrlMalformat,
            codes::CURLE_NOT_BUILT_IN => CurlError::NotBuiltIn,
            codes::CURLE_COULDNT_RESOLVE_PROXY => CurlError::CouldntResolveProxy,
            codes::CURLE_COULDNT_RESOLVE_HOST => CurlError::CouldntResolveHost,
            codes::CURLE_COULDNT_CONNECT => CurlError::CouldntConnect,
            codes::CURLE_WEIRD_SERVER_REPLY => CurlError::WeirdServerReply,
            codes::CURLE_REMOTE_ACCESS_DENIED => CurlError::RemoteAccessDenied,
            codes::CURLE_FTP_ACCEPT_FAILED => CurlError::FtpAcceptFailed,
            codes::CURLE_FTP_WEIRD_PASS_REPLY => CurlError::FtpWeirdPassReply,
            codes::CURLE_FTP_ACCEPT_TIMEOUT => CurlError::FtpAcceptTimeout,
            codes::CURLE_FTP_WEIRD_PASV_REPLY => CurlError::FtpWeirdPasvReply,
            codes::CURLE_FTP_WEIRD_227_FORMAT => CurlError::FtpWeird227Format,
            codes::CURLE_FTP_CANT_GET_HOST => CurlError::FtpCantGetHost,
            codes::CURLE_HTTP2 => CurlError::Http2,
            codes::CURLE_FTP_COULDNT_SET_TYPE => CurlError::FtpCouldntSetType,
            codes::CURLE_PARTIAL_FILE => CurlError::PartialFile,
            codes::CURLE_FTP_COULDNT_RETR_FILE => CurlError::FtpCouldntRetrFile,
            codes::CURLE_QUOTE_ERROR => CurlError::QuoteError,
            codes::CURLE_HTTP_RETURNED_ERROR => CurlError::HttpReturnedError,
            codes::CURLE_WRITE_ERROR => CurlError::WriteError,
            codes::CURLE_UPLOAD_FAILED => CurlError::UploadFailed,
            codes::CURLE_READ_ERROR => CurlError::ReadError,
            codes::CURLE_OUT_OF_MEMORY => CurlError::OutOfMemory,
            codes::CURLE_OPERATION_TIMEDOUT => CurlError::OperationTimedout,
            codes::CURLE_FTP_PORT_FAILED => CurlError::FtpPortFailed,
            codes::CURLE_FTP_COULDNT_USE_REST => CurlError::FtpCouldntUseRest,
            codes::CURLE_RANGE_ERROR => CurlError::RangeError,
            codes::CURLE_SSL_CONNECT_ERROR => CurlError::SslConnectError,
            codes::CURLE_BAD_DOWNLOAD_RESUME => CurlError::BadDownloadResume,
            codes::CURLE_FILE_COULDNT_READ_FILE => CurlError::FileCouldntReadFile,
            codes::CURLE_LDAP_CANNOT_BIND => CurlError::LdapCannotBind,
            codes::CURLE_LDAP_SEARCH_FAILED => CurlError::LdapSearchFailed,
            codes::CURLE_ABORTED_BY_CALLBACK => CurlError::AbortedByCallback,
            codes::CURLE_BAD_FUNCTION_ARGUMENT => CurlError::BadFunctionArgument,
            codes::CURLE_INTERFACE_FAILED => CurlError::InterfaceFailed,
            codes::CURLE_TOO_MANY_REDIRECTS => CurlError::TooManyRedirects,
            codes::CURLE_UNKNOWN_OPTION => CurlError::UnknownOption,
            codes::CURLE_SETOPT_OPTION_SYNTAX => CurlError::SetoptOptionSyntax,
            codes::CURLE_GOT_NOTHING => CurlError::GotNothing,
            codes::CURLE_SSL_ENGINE_NOTFOUND => CurlError::SslEngineNotfound,
            codes::CURLE_SSL_ENGINE_SETFAILED => CurlError::SslEngineSetfailed,
            codes::CURLE_SEND_ERROR => CurlError::SendError,
            codes::CURLE_RECV_ERROR => CurlError::RecvError,
            codes::CURLE_SSL_CERTPROBLEM => CurlError::SslCertproblem,
            codes::CURLE_SSL_CIPHER => CurlError::SslCipher,
            codes::CURLE_PEER_FAILED_VERIFICATION => CurlError::PeerFailedVerification,
            codes::CURLE_BAD_CONTENT_ENCODING => CurlError::BadContentEncoding,
            codes::CURLE_FILESIZE_EXCEEDED => CurlError::FilesizeExceeded,
            codes::CURLE_USE_SSL_FAILED => CurlError::UseSslFailed,
            codes::CURLE_SEND_FAIL_REWIND => CurlError::SendFailRewind,
            codes::CURLE_SSL_ENGINE_INITFAILED => CurlError::SslEngineInitfailed,
            codes::CURLE_LOGIN_DENIED => CurlError::LoginDenied,
            codes::CURLE_TFTP_NOTFOUND => CurlError::TftpNotfound,
            codes::CURLE_TFTP_PERM => CurlError::TftpPerm,
            codes::CURLE_REMOTE_DISK_FULL => CurlError::RemoteDiskFull,
            codes::CURLE_TFTP_ILLEGAL => CurlError::TftpIllegal,
            codes::CURLE_TFTP_UNKNOWNID => CurlError::TftpUnknownid,
            codes::CURLE_REMOTE_FILE_EXISTS => CurlError::RemoteFileExists,
            codes::CURLE_TFTP_NOSUCHUSER => CurlError::TftpNosuchuser,
            codes::CURLE_SSL_CACERT_BADFILE => CurlError::SslCacertBadfile,
            codes::CURLE_REMOTE_FILE_NOT_FOUND => CurlError::RemoteFileNotFound,
            codes::CURLE_SSH => CurlError::Ssh,
            codes::CURLE_SSL_SHUTDOWN_FAILED => CurlError::SslShutdownFailed,
            codes::CURLE_AGAIN => CurlError::Again,
            codes::CURLE_SSL_CRL_BADFILE => CurlError::SslCrlBadfile,
            codes::CURLE_SSL_ISSUER_ERROR => CurlError::SslIssuerError,
            codes::CURLE_FTP_PRET_FAILED => CurlError::FtpPretFailed,
            codes::CURLE_RTSP_CSEQ_ERROR => CurlError::RtspCseqError,
            codes::CURLE_RTSP_SESSION_ERROR => CurlError::RtspSessionError,
            codes::CURLE_FTP_BAD_FILE_LIST => CurlError::FtpBadFileList,
            codes::CURLE_CHUNK_FAILED => CurlError::ChunkFailed,
            codes::CURLE_NO_CONNECTION_AVAILABLE => CurlError::NoConnectionAvailable,
            codes::CURLE_SSL_PINNEDPUBKEYNOTMATCH => CurlError::SslPinnedpubkeynotmatch,
            codes::CURLE_SSL_INVALIDCERTSTATUS => CurlError::SslInvalidcertstatus,
            codes::CURLE_HTTP2_STREAM => CurlError::Http2Stream,
            codes::CURLE_RECURSIVE_API_CALL => CurlError::RecursiveApiCall,
            codes::CURLE_AUTH_ERROR => CurlError::AuthError,
            codes::CURLE_HTTP3 => CurlError::Http3,
            codes::CURLE_QUIC_CONNECT_ERROR => CurlError::QuicConnectError,
            codes::CURLE_PROXY => CurlError::Proxy,
            codes::CURLE_SSL_CLIENTCERT => CurlError::SslClientcert,
            codes::CURLE_UNRECOVERABLE_POLL => CurlError::UnrecoverablePoll,
            codes::CURLE_TOO_LARGE => CurlError::TooLarge,
            codes::CURLE_ECH_REQUIRED => CurlError::EchRequired,
            codes::CURLE_ALREADY_COMPLETE => CurlError::AlreadyComplete,
            other => CurlError::Unknown(other),
        }
    }

    /// Returns `true` if this represents success (`CURLE_OK`).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, CurlError::Ok)
    }
}

impl From<CurlError> for CurlCode {
    /// Converts an error into its exact C `CURLcode` integer.
    fn from(error: CurlError) -> Self {
        error.code()
    }
}

impl From<&CurlError> for CurlCode {
    /// Converts a borrowed error into its exact C `CURLcode` integer.
    fn from(error: &CurlError) -> Self {
        error.code()
    }
}

impl From<std::io::Error> for CurlError {
    /// Maps a standard I/O error onto the closest `CURLcode`-bearing variant.
    ///
    /// The mapping is driven by [`std::io::ErrorKind`] so that the resulting
    /// `CurlError` still carries a meaningful, ABI-correct integer. The original
    /// [`std::io::Error`] is intentionally not retained: keeping `CurlError`
    /// `Copy` and free of owned state is what lets the FFI layer translate it to
    /// an integer without allocation. Callers that have directional context
    /// (send vs. receive) should prefer to select a more specific variant
    /// explicitly rather than relying on this best-effort conversion.
    fn from(error: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match error.kind() {
            ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::NotConnected
            | ErrorKind::AddrNotAvailable
            | ErrorKind::AddrInUse => CurlError::CouldntConnect,
            ErrorKind::TimedOut => CurlError::OperationTimedout,
            ErrorKind::BrokenPipe => CurlError::SendError,
            ErrorKind::WriteZero => CurlError::WriteError,
            ErrorKind::UnexpectedEof => CurlError::RecvError,
            ErrorKind::OutOfMemory => CurlError::OutOfMemory,
            ErrorKind::NotFound | ErrorKind::PermissionDenied => CurlError::ReadError,
            // Anything else is treated as a generic receive-side failure, which
            // is the most common bucket for unclassified transport errors.
            _ => CurlError::RecvError,
        }
    }
}

/// The multi-interface result code, mirroring C's `CURLMcode`
/// (`include/curl/multi.h`).
///
/// Unlike [`CurlError`], this enum models the *whole* `CURLMcode` space — it
/// includes the success code [`Ok`](CurlMError::Ok) and the out-of-band
/// [`CallMultiPerform`](CurlMError::CallMultiPerform) signal (`-1`), which the
/// multi driver uses to ask the caller to call `curl_multi_perform()` again.
/// The discriminants are pinned to the C integers via `#[repr(i32)]`, so
/// [`code`](CurlMError::code) is a direct, allocation-free cast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[repr(i32)]
pub enum CurlMError {
    /// `CURLM_CALL_MULTI_PERFORM` (-1) — call `curl_multi_perform()` again soon.
    #[error("Please call curl_multi_perform() soon")]
    CallMultiPerform = -1,
    /// `CURLM_OK` (0).
    #[error("No error")]
    Ok = 0,
    /// `CURLM_BAD_HANDLE` (1).
    #[error("Invalid multi handle")]
    BadHandle = 1,
    /// `CURLM_BAD_EASY_HANDLE` (2).
    #[error("Invalid easy handle")]
    BadEasyHandle = 2,
    /// `CURLM_OUT_OF_MEMORY` (3).
    #[error("Out of memory")]
    OutOfMemory = 3,
    /// `CURLM_INTERNAL_ERROR` (4).
    #[error("Internal error")]
    InternalError = 4,
    /// `CURLM_BAD_SOCKET` (5).
    #[error("Invalid socket argument")]
    BadSocket = 5,
    /// `CURLM_UNKNOWN_OPTION` (6).
    #[error("Unknown option")]
    UnknownOption = 6,
    /// `CURLM_ADDED_ALREADY` (7).
    #[error("The easy handle is already added to a multi handle")]
    AddedAlready = 7,
    /// `CURLM_RECURSIVE_API_CALL` (8).
    #[error("API function called from within callback")]
    RecursiveApiCall = 8,
    /// `CURLM_WAKEUP_FAILURE` (9).
    #[error("Wakeup is unavailable or failed")]
    WakeupFailure = 9,
    /// `CURLM_BAD_FUNCTION_ARGUMENT` (10).
    #[error("A libcurl function was given a bad argument")]
    BadFunctionArgument = 10,
    /// `CURLM_ABORTED_BY_CALLBACK` (11).
    #[error("Operation was aborted by an application callback")]
    AbortedByCallback = 11,
    /// `CURLM_UNRECOVERABLE_POLL` (12).
    #[error("Unrecoverable error in select/poll")]
    UnrecoverablePoll = 12,
}

impl CurlMError {
    /// Returns the exact C `CURLMcode` integer for this code.
    #[must_use]
    pub const fn code(&self) -> CurlCode {
        *self as CurlCode
    }

    /// Returns the static description, matching `curl_multi_strerror()`
    /// (`lib/strerror.c`) verbatim.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            CurlMError::CallMultiPerform => "Please call curl_multi_perform() soon",
            CurlMError::Ok => "No error",
            CurlMError::BadHandle => "Invalid multi handle",
            CurlMError::BadEasyHandle => "Invalid easy handle",
            CurlMError::OutOfMemory => "Out of memory",
            CurlMError::InternalError => "Internal error",
            CurlMError::BadSocket => "Invalid socket argument",
            CurlMError::UnknownOption => "Unknown option",
            CurlMError::AddedAlready => "The easy handle is already added to a multi handle",
            CurlMError::RecursiveApiCall => "API function called from within callback",
            CurlMError::WakeupFailure => "Wakeup is unavailable or failed",
            CurlMError::BadFunctionArgument => "A libcurl function was given a bad argument",
            CurlMError::AbortedByCallback => "Operation was aborted by an application callback",
            CurlMError::UnrecoverablePoll => "Unrecoverable error in select/poll",
        }
    }

    /// Builds a [`CurlMError`] from a raw `CURLMcode` integer.
    ///
    /// Returns `None` for any value outside the defined range (curl renders such
    /// values as `"Unknown error"`).
    #[must_use]
    pub const fn from_code(code: CurlCode) -> Option<CurlMError> {
        match code {
            codes::multi::CURLM_CALL_MULTI_PERFORM => Some(CurlMError::CallMultiPerform),
            codes::multi::CURLM_OK => Some(CurlMError::Ok),
            codes::multi::CURLM_BAD_HANDLE => Some(CurlMError::BadHandle),
            codes::multi::CURLM_BAD_EASY_HANDLE => Some(CurlMError::BadEasyHandle),
            codes::multi::CURLM_OUT_OF_MEMORY => Some(CurlMError::OutOfMemory),
            codes::multi::CURLM_INTERNAL_ERROR => Some(CurlMError::InternalError),
            codes::multi::CURLM_BAD_SOCKET => Some(CurlMError::BadSocket),
            codes::multi::CURLM_UNKNOWN_OPTION => Some(CurlMError::UnknownOption),
            codes::multi::CURLM_ADDED_ALREADY => Some(CurlMError::AddedAlready),
            codes::multi::CURLM_RECURSIVE_API_CALL => Some(CurlMError::RecursiveApiCall),
            codes::multi::CURLM_WAKEUP_FAILURE => Some(CurlMError::WakeupFailure),
            codes::multi::CURLM_BAD_FUNCTION_ARGUMENT => Some(CurlMError::BadFunctionArgument),
            codes::multi::CURLM_ABORTED_BY_CALLBACK => Some(CurlMError::AbortedByCallback),
            codes::multi::CURLM_UNRECOVERABLE_POLL => Some(CurlMError::UnrecoverablePoll),
            _ => None,
        }
    }

    /// Returns `true` if this represents success (`CURLM_OK`).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, CurlMError::Ok)
    }
}

impl From<CurlMError> for CurlCode {
    fn from(error: CurlMError) -> Self {
        error.code()
    }
}

impl From<&CurlMError> for CurlCode {
    fn from(error: &CurlMError) -> Self {
        error.code()
    }
}

/// The URL-API result code, mirroring C's `CURLUcode`
/// (`include/curl/urlapi.h`).
///
/// Discriminants follow the header's enumeration order (the authoritative
/// integers); note that `curl_url_strerror()` lists the cases in a *different*
/// order in `lib/strerror.c`, so the strings below are matched by name, not by
/// position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[repr(i32)]
pub enum CurlUError {
    /// `CURLUE_OK` (0).
    #[error("No error")]
    Ok = 0,
    /// `CURLUE_BAD_HANDLE` (1).
    #[error("An invalid CURLU pointer was passed as argument")]
    BadHandle = 1,
    /// `CURLUE_BAD_PARTPOINTER` (2).
    #[error("An invalid 'part' argument was passed as argument")]
    BadPartpointer = 2,
    /// `CURLUE_MALFORMED_INPUT` (3).
    #[error("Malformed input to a URL function")]
    MalformedInput = 3,
    /// `CURLUE_BAD_PORT_NUMBER` (4).
    #[error("Port number was not a decimal number between 0 and 65535")]
    BadPortNumber = 4,
    /// `CURLUE_UNSUPPORTED_SCHEME` (5).
    #[error("Unsupported URL scheme")]
    UnsupportedScheme = 5,
    /// `CURLUE_URLDECODE` (6).
    #[error("URL decode error, most likely because of rubbish in the input")]
    Urldecode = 6,
    /// `CURLUE_OUT_OF_MEMORY` (7).
    #[error("A memory function failed")]
    OutOfMemory = 7,
    /// `CURLUE_USER_NOT_ALLOWED` (8).
    #[error("Credentials was passed in the URL when prohibited")]
    UserNotAllowed = 8,
    /// `CURLUE_UNKNOWN_PART` (9).
    #[error("An unknown part ID was passed to a URL API function")]
    UnknownPart = 9,
    /// `CURLUE_NO_SCHEME` (10).
    #[error("No scheme part in the URL")]
    NoScheme = 10,
    /// `CURLUE_NO_USER` (11).
    #[error("No user part in the URL")]
    NoUser = 11,
    /// `CURLUE_NO_PASSWORD` (12).
    #[error("No password part in the URL")]
    NoPassword = 12,
    /// `CURLUE_NO_OPTIONS` (13).
    #[error("No options part in the URL")]
    NoOptions = 13,
    /// `CURLUE_NO_HOST` (14).
    #[error("No host part in the URL")]
    NoHost = 14,
    /// `CURLUE_NO_PORT` (15).
    #[error("No port part in the URL")]
    NoPort = 15,
    /// `CURLUE_NO_QUERY` (16).
    #[error("No query part in the URL")]
    NoQuery = 16,
    /// `CURLUE_NO_FRAGMENT` (17).
    #[error("No fragment part in the URL")]
    NoFragment = 17,
    /// `CURLUE_NO_ZONEID` (18).
    #[error("No zoneid part in the URL")]
    NoZoneid = 18,
    /// `CURLUE_BAD_FILE_URL` (19).
    #[error("Bad file:// URL")]
    BadFileUrl = 19,
    /// `CURLUE_BAD_FRAGMENT` (20).
    #[error("Bad fragment")]
    BadFragment = 20,
    /// `CURLUE_BAD_HOSTNAME` (21).
    #[error("Bad hostname")]
    BadHostname = 21,
    /// `CURLUE_BAD_IPV6` (22).
    #[error("Bad IPv6 address")]
    BadIpv6 = 22,
    /// `CURLUE_BAD_LOGIN` (23).
    #[error("Bad login part")]
    BadLogin = 23,
    /// `CURLUE_BAD_PASSWORD` (24).
    #[error("Bad password")]
    BadPassword = 24,
    /// `CURLUE_BAD_PATH` (25).
    #[error("Bad path")]
    BadPath = 25,
    /// `CURLUE_BAD_QUERY` (26).
    #[error("Bad query")]
    BadQuery = 26,
    /// `CURLUE_BAD_SCHEME` (27).
    #[error("Bad scheme")]
    BadScheme = 27,
    /// `CURLUE_BAD_SLASHES` (28).
    #[error("Unsupported number of slashes following scheme")]
    BadSlashes = 28,
    /// `CURLUE_BAD_USER` (29).
    #[error("Bad user")]
    BadUser = 29,
    /// `CURLUE_LACKS_IDN` (30).
    #[error("libcurl lacks IDN support")]
    LacksIdn = 30,
    /// `CURLUE_TOO_LARGE` (31).
    #[error("A value or data field is larger than allowed")]
    TooLarge = 31,
}

impl CurlUError {
    /// Returns the exact C `CURLUcode` integer for this code.
    #[must_use]
    pub const fn code(&self) -> CurlCode {
        *self as CurlCode
    }

    /// Returns the static description, matching `curl_url_strerror()`
    /// (`lib/strerror.c`) verbatim.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            CurlUError::Ok => "No error",
            CurlUError::BadHandle => "An invalid CURLU pointer was passed as argument",
            CurlUError::BadPartpointer => "An invalid 'part' argument was passed as argument",
            CurlUError::MalformedInput => "Malformed input to a URL function",
            CurlUError::BadPortNumber => "Port number was not a decimal number between 0 and 65535",
            CurlUError::UnsupportedScheme => "Unsupported URL scheme",
            CurlUError::Urldecode => {
                "URL decode error, most likely because of rubbish in the input"
            }
            CurlUError::OutOfMemory => "A memory function failed",
            CurlUError::UserNotAllowed => "Credentials was passed in the URL when prohibited",
            CurlUError::UnknownPart => "An unknown part ID was passed to a URL API function",
            CurlUError::NoScheme => "No scheme part in the URL",
            CurlUError::NoUser => "No user part in the URL",
            CurlUError::NoPassword => "No password part in the URL",
            CurlUError::NoOptions => "No options part in the URL",
            CurlUError::NoHost => "No host part in the URL",
            CurlUError::NoPort => "No port part in the URL",
            CurlUError::NoQuery => "No query part in the URL",
            CurlUError::NoFragment => "No fragment part in the URL",
            CurlUError::NoZoneid => "No zoneid part in the URL",
            CurlUError::BadFileUrl => "Bad file:// URL",
            CurlUError::BadFragment => "Bad fragment",
            CurlUError::BadHostname => "Bad hostname",
            CurlUError::BadIpv6 => "Bad IPv6 address",
            CurlUError::BadLogin => "Bad login part",
            CurlUError::BadPassword => "Bad password",
            CurlUError::BadPath => "Bad path",
            CurlUError::BadQuery => "Bad query",
            CurlUError::BadScheme => "Bad scheme",
            CurlUError::BadSlashes => "Unsupported number of slashes following scheme",
            CurlUError::BadUser => "Bad user",
            CurlUError::LacksIdn => "libcurl lacks IDN support",
            CurlUError::TooLarge => "A value or data field is larger than allowed",
        }
    }

    /// Builds a [`CurlUError`] from a raw `CURLUcode` integer.
    ///
    /// Returns `None` for any value outside the defined range (curl renders such
    /// values as `"CURLUcode unknown"`).
    #[must_use]
    pub const fn from_code(code: CurlCode) -> Option<CurlUError> {
        match code {
            codes::url::CURLUE_OK => Some(CurlUError::Ok),
            codes::url::CURLUE_BAD_HANDLE => Some(CurlUError::BadHandle),
            codes::url::CURLUE_BAD_PARTPOINTER => Some(CurlUError::BadPartpointer),
            codes::url::CURLUE_MALFORMED_INPUT => Some(CurlUError::MalformedInput),
            codes::url::CURLUE_BAD_PORT_NUMBER => Some(CurlUError::BadPortNumber),
            codes::url::CURLUE_UNSUPPORTED_SCHEME => Some(CurlUError::UnsupportedScheme),
            codes::url::CURLUE_URLDECODE => Some(CurlUError::Urldecode),
            codes::url::CURLUE_OUT_OF_MEMORY => Some(CurlUError::OutOfMemory),
            codes::url::CURLUE_USER_NOT_ALLOWED => Some(CurlUError::UserNotAllowed),
            codes::url::CURLUE_UNKNOWN_PART => Some(CurlUError::UnknownPart),
            codes::url::CURLUE_NO_SCHEME => Some(CurlUError::NoScheme),
            codes::url::CURLUE_NO_USER => Some(CurlUError::NoUser),
            codes::url::CURLUE_NO_PASSWORD => Some(CurlUError::NoPassword),
            codes::url::CURLUE_NO_OPTIONS => Some(CurlUError::NoOptions),
            codes::url::CURLUE_NO_HOST => Some(CurlUError::NoHost),
            codes::url::CURLUE_NO_PORT => Some(CurlUError::NoPort),
            codes::url::CURLUE_NO_QUERY => Some(CurlUError::NoQuery),
            codes::url::CURLUE_NO_FRAGMENT => Some(CurlUError::NoFragment),
            codes::url::CURLUE_NO_ZONEID => Some(CurlUError::NoZoneid),
            codes::url::CURLUE_BAD_FILE_URL => Some(CurlUError::BadFileUrl),
            codes::url::CURLUE_BAD_FRAGMENT => Some(CurlUError::BadFragment),
            codes::url::CURLUE_BAD_HOSTNAME => Some(CurlUError::BadHostname),
            codes::url::CURLUE_BAD_IPV6 => Some(CurlUError::BadIpv6),
            codes::url::CURLUE_BAD_LOGIN => Some(CurlUError::BadLogin),
            codes::url::CURLUE_BAD_PASSWORD => Some(CurlUError::BadPassword),
            codes::url::CURLUE_BAD_PATH => Some(CurlUError::BadPath),
            codes::url::CURLUE_BAD_QUERY => Some(CurlUError::BadQuery),
            codes::url::CURLUE_BAD_SCHEME => Some(CurlUError::BadScheme),
            codes::url::CURLUE_BAD_SLASHES => Some(CurlUError::BadSlashes),
            codes::url::CURLUE_BAD_USER => Some(CurlUError::BadUser),
            codes::url::CURLUE_LACKS_IDN => Some(CurlUError::LacksIdn),
            codes::url::CURLUE_TOO_LARGE => Some(CurlUError::TooLarge),
            _ => None,
        }
    }

    /// Returns `true` if this represents success (`CURLUE_OK`).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, CurlUError::Ok)
    }
}

impl From<CurlUError> for CurlCode {
    fn from(error: CurlUError) -> Self {
        error.code()
    }
}

impl From<&CurlUError> for CurlCode {
    fn from(error: &CurlUError) -> Self {
        error.code()
    }
}

/// The share-interface result code, mirroring C's `CURLSHcode`
/// (`include/curl/curl.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[repr(i32)]
pub enum CurlShError {
    /// `CURLSHE_OK` (0).
    #[error("No error")]
    Ok = 0,
    /// `CURLSHE_BAD_OPTION` (1).
    #[error("Unknown share option")]
    BadOption = 1,
    /// `CURLSHE_IN_USE` (2).
    #[error("Share currently in use")]
    InUse = 2,
    /// `CURLSHE_INVALID` (3).
    #[error("Invalid share handle")]
    Invalid = 3,
    /// `CURLSHE_NOMEM` (4).
    #[error("Out of memory")]
    Nomem = 4,
    /// `CURLSHE_NOT_BUILT_IN` (5).
    #[error("Feature not enabled in this library")]
    NotBuiltIn = 5,
}

impl CurlShError {
    /// Returns the exact C `CURLSHcode` integer for this code.
    #[must_use]
    pub const fn code(&self) -> CurlCode {
        *self as CurlCode
    }

    /// Returns the static description, matching `curl_share_strerror()`
    /// (`lib/strerror.c`) verbatim.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            CurlShError::Ok => "No error",
            CurlShError::BadOption => "Unknown share option",
            CurlShError::InUse => "Share currently in use",
            CurlShError::Invalid => "Invalid share handle",
            CurlShError::Nomem => "Out of memory",
            CurlShError::NotBuiltIn => "Feature not enabled in this library",
        }
    }

    /// Builds a [`CurlShError`] from a raw `CURLSHcode` integer.
    ///
    /// Returns `None` for any value outside the defined range (curl renders such
    /// values as `"CURLSHcode unknown"`).
    #[must_use]
    pub const fn from_code(code: CurlCode) -> Option<CurlShError> {
        match code {
            codes::share::CURLSHE_OK => Some(CurlShError::Ok),
            codes::share::CURLSHE_BAD_OPTION => Some(CurlShError::BadOption),
            codes::share::CURLSHE_IN_USE => Some(CurlShError::InUse),
            codes::share::CURLSHE_INVALID => Some(CurlShError::Invalid),
            codes::share::CURLSHE_NOMEM => Some(CurlShError::Nomem),
            codes::share::CURLSHE_NOT_BUILT_IN => Some(CurlShError::NotBuiltIn),
            _ => None,
        }
    }

    /// Returns `true` if this represents success (`CURLSHE_OK`).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, CurlShError::Ok)
    }
}

impl From<CurlShError> for CurlCode {
    fn from(error: CurlShError) -> Self {
        error.code()
    }
}

impl From<&CurlShError> for CurlCode {
    fn from(error: &CurlShError) -> Self {
        error.code()
    }
}

/// The header-API result code, mirroring C's `CURLHcode`
/// (`include/curl/header.h`).
///
/// Returned by `curl_easy_header()` (and produced internally by
/// [`crate::headers`]) to describe the outcome of a response-header lookup. The
/// integer value of each variant matches curl 8.x exactly (`CURLHE_OK = 0`
/// through `CURLHE_NOT_BUILT_IN = 7`); the values are observed directly by C
/// consumers and the `tests/data` header-API tests, so they are part of the ABI.
///
/// Unlike [`CurlError`], curl exposes no `curl_*_strerror()` for `CURLHcode`,
/// so the [`Display`](core::fmt::Display) strings here are derived from the
/// descriptive comments in `include/curl/header.h` rather than from
/// `lib/strerror.c`.
///
/// In idiomatic Rust the success case (`CURLHE_OK`) is represented with
/// [`Result::Ok`]; [`CurlHError::Ok`] exists so that the FFI layer and
/// [`from_code`](CurlHError::from_code)/[`code`](CurlHError::code) form a total
/// mapping over the C code space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[repr(i32)]
pub enum CurlHError {
    /// `CURLHE_OK` (0) — success.
    #[error("No error")]
    Ok = 0,
    /// `CURLHE_BADINDEX` (1) — the header exists but not with this index.
    #[error("header exists but not with this index")]
    BadIndex = 1,
    /// `CURLHE_MISSING` (2) — no such header exists.
    #[error("no such header exists")]
    Missing = 2,
    /// `CURLHE_NOHEADERS` (3) — no headers at all exist (yet).
    #[error("no headers at all exist (yet)")]
    NoHeaders = 3,
    /// `CURLHE_NOREQUEST` (4) — no request with this number was used.
    #[error("no request with this number was used")]
    NoRequest = 4,
    /// `CURLHE_OUT_OF_MEMORY` (5) — out of memory while processing.
    #[error("out of memory while processing")]
    OutOfMemory = 5,
    /// `CURLHE_BAD_ARGUMENT` (6) — a function argument was not okay.
    #[error("a function argument was not okay")]
    BadArgument = 6,
    /// `CURLHE_NOT_BUILT_IN` (7) — the header API was disabled in the build.
    #[error("the header API was disabled in the build")]
    NotBuiltIn = 7,
}

impl CurlHError {
    /// Returns the exact C `CURLHcode` integer for this code.
    #[must_use]
    pub const fn code(&self) -> CurlCode {
        *self as CurlCode
    }

    /// Returns a static description for this code.
    ///
    /// curl has no `curl_*_strerror()` for `CURLHcode`; these strings mirror the
    /// descriptive comments next to each value in `include/curl/header.h`.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            CurlHError::Ok => "No error",
            CurlHError::BadIndex => "header exists but not with this index",
            CurlHError::Missing => "no such header exists",
            CurlHError::NoHeaders => "no headers at all exist (yet)",
            CurlHError::NoRequest => "no request with this number was used",
            CurlHError::OutOfMemory => "out of memory while processing",
            CurlHError::BadArgument => "a function argument was not okay",
            CurlHError::NotBuiltIn => "the header API was disabled in the build",
        }
    }

    /// Builds a [`CurlHError`] from a raw `CURLHcode` integer.
    ///
    /// Returns `None` for any value outside the defined `0..=7` range.
    #[must_use]
    pub const fn from_code(code: CurlCode) -> Option<CurlHError> {
        match code {
            codes::header::CURLHE_OK => Some(CurlHError::Ok),
            codes::header::CURLHE_BADINDEX => Some(CurlHError::BadIndex),
            codes::header::CURLHE_MISSING => Some(CurlHError::Missing),
            codes::header::CURLHE_NOHEADERS => Some(CurlHError::NoHeaders),
            codes::header::CURLHE_NOREQUEST => Some(CurlHError::NoRequest),
            codes::header::CURLHE_OUT_OF_MEMORY => Some(CurlHError::OutOfMemory),
            codes::header::CURLHE_BAD_ARGUMENT => Some(CurlHError::BadArgument),
            codes::header::CURLHE_NOT_BUILT_IN => Some(CurlHError::NotBuiltIn),
            _ => None,
        }
    }

    /// Returns `true` if this represents success (`CURLHE_OK`).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, CurlHError::Ok)
    }
}

impl From<CurlHError> for CurlCode {
    fn from(error: CurlHError) -> Self {
        error.code()
    }
}

impl From<&CurlHError> for CurlCode {
    fn from(error: &CurlHError) -> Self {
        error.code()
    }
}

/// The crate-wide result type.
///
/// Equivalent to [`core::result::Result<T, CurlError>`]. Internal APIs return
/// this; success is `Ok(value)` and failure is `Err(CurlError::…)`. The FFI
/// layer collapses it to a raw [`CurlCode`] at the C boundary
/// (`Ok(_) => CURLE_OK`, `Err(e) => e.code()`).
pub type Result<T> = core::result::Result<T, CurlError>;

/// Asserts at compile time that a `&'static str` is preserved exactly.
///
/// Used only to document intent at the type level; the heavy lifting of string
/// parity is done by the runtime tests below.
const _: () = {
    // `CurlError` must remain a zero-cost, `Copy` value type so the FFI layer
    // can translate it to an integer without allocation. If a future edit adds
    // an owned field (e.g. a `String`), this assertion fails to compile,
    // flagging the ABI/cost regression for review.
    const fn assert_copy<T: Copy>() {}
    assert_copy::<CurlError>();
    assert_copy::<CurlMError>();
    assert_copy::<CurlUError>();
    assert_copy::<CurlShError>();
    assert_copy::<CurlHError>();
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Every active `CurlError` variant, in `CURLcode` order. Excludes the
    /// retired `CURLE_OBSOLETE*` slots, the out-of-band `AlreadyComplete`
    /// sentinel and the `Unknown` catch-all.
    const ACTIVE: &[CurlError] = &[
        CurlError::Ok,
        CurlError::UnsupportedProtocol,
        CurlError::FailedInit,
        CurlError::UrlMalformat,
        CurlError::NotBuiltIn,
        CurlError::CouldntResolveProxy,
        CurlError::CouldntResolveHost,
        CurlError::CouldntConnect,
        CurlError::WeirdServerReply,
        CurlError::RemoteAccessDenied,
        CurlError::FtpAcceptFailed,
        CurlError::FtpWeirdPassReply,
        CurlError::FtpAcceptTimeout,
        CurlError::FtpWeirdPasvReply,
        CurlError::FtpWeird227Format,
        CurlError::FtpCantGetHost,
        CurlError::Http2,
        CurlError::FtpCouldntSetType,
        CurlError::PartialFile,
        CurlError::FtpCouldntRetrFile,
        CurlError::QuoteError,
        CurlError::HttpReturnedError,
        CurlError::WriteError,
        CurlError::UploadFailed,
        CurlError::ReadError,
        CurlError::OutOfMemory,
        CurlError::OperationTimedout,
        CurlError::FtpPortFailed,
        CurlError::FtpCouldntUseRest,
        CurlError::RangeError,
        CurlError::SslConnectError,
        CurlError::BadDownloadResume,
        CurlError::FileCouldntReadFile,
        CurlError::LdapCannotBind,
        CurlError::LdapSearchFailed,
        CurlError::AbortedByCallback,
        CurlError::BadFunctionArgument,
        CurlError::InterfaceFailed,
        CurlError::TooManyRedirects,
        CurlError::UnknownOption,
        CurlError::SetoptOptionSyntax,
        CurlError::GotNothing,
        CurlError::SslEngineNotfound,
        CurlError::SslEngineSetfailed,
        CurlError::SendError,
        CurlError::RecvError,
        CurlError::SslCertproblem,
        CurlError::SslCipher,
        CurlError::PeerFailedVerification,
        CurlError::BadContentEncoding,
        CurlError::FilesizeExceeded,
        CurlError::UseSslFailed,
        CurlError::SendFailRewind,
        CurlError::SslEngineInitfailed,
        CurlError::LoginDenied,
        CurlError::TftpNotfound,
        CurlError::TftpPerm,
        CurlError::RemoteDiskFull,
        CurlError::TftpIllegal,
        CurlError::TftpUnknownid,
        CurlError::RemoteFileExists,
        CurlError::TftpNosuchuser,
        CurlError::SslCacertBadfile,
        CurlError::RemoteFileNotFound,
        CurlError::Ssh,
        CurlError::SslShutdownFailed,
        CurlError::Again,
        CurlError::SslCrlBadfile,
        CurlError::SslIssuerError,
        CurlError::FtpPretFailed,
        CurlError::RtspCseqError,
        CurlError::RtspSessionError,
        CurlError::FtpBadFileList,
        CurlError::ChunkFailed,
        CurlError::NoConnectionAvailable,
        CurlError::SslPinnedpubkeynotmatch,
        CurlError::SslInvalidcertstatus,
        CurlError::Http2Stream,
        CurlError::RecursiveApiCall,
        CurlError::AuthError,
        CurlError::Http3,
        CurlError::QuicConnectError,
        CurlError::Proxy,
        CurlError::SslClientcert,
        CurlError::UnrecoverablePoll,
        CurlError::TooLarge,
        CurlError::EchRequired,
    ];

    /// The retired `CURLcode` slots that intentionally have no variant.
    const OBSOLETE: &[CurlCode] = &[20, 24, 29, 32, 34, 40, 41, 44, 46, 50, 51, 57, 62, 75, 76];

    // ---- CURLcode (easy) ---------------------------------------------------

    #[test]
    fn easy_exact_integer_spot_checks() {
        // The representative spread mandated by the implementation plan.
        assert_eq!(CurlError::Ok.code(), 0);
        assert_eq!(CurlError::UnsupportedProtocol.code(), 1);
        assert_eq!(CurlError::NotBuiltIn.code(), 4);
        assert_eq!(CurlError::CouldntResolveHost.code(), 6);
        assert_eq!(CurlError::Http2.code(), 16);
        assert_eq!(CurlError::OperationTimedout.code(), 28);
        assert_eq!(CurlError::TooLarge.code(), 100);
        assert_eq!(CurlError::EchRequired.code(), 101);
        assert_eq!(CurlError::AlreadyComplete.code(), 99999);

        // Same checks via the named constants.
        assert_eq!(codes::CURLE_OK, 0);
        assert_eq!(codes::CURLE_UNSUPPORTED_PROTOCOL, 1);
        assert_eq!(codes::CURLE_NOT_BUILT_IN, 4);
        assert_eq!(codes::CURLE_COULDNT_RESOLVE_HOST, 6);
        assert_eq!(codes::CURLE_HTTP2, 16);
        assert_eq!(codes::CURLE_OPERATION_TIMEDOUT, 28);
        assert_eq!(codes::CURLE_TOO_LARGE, 100);
        assert_eq!(codes::CURLE_ECH_REQUIRED, 101);
        assert_eq!(codes::CURLE_ALREADY_COMPLETE, 99999);
        assert_eq!(codes::CURL_LAST, 102);
    }

    #[test]
    fn easy_active_codes_are_strictly_ascending() {
        // The ACTIVE list is authored in CURLcode order. Codes must strictly
        // increase (the retired OBSOLETE slots create the gaps), the first must
        // be 0 (`CURLE_OK`) and the last 101 (`CURLE_ECH_REQUIRED`). This catches
        // any transcription or ordering slip without assuming index == code.
        let mut prev: Option<CurlCode> = None;
        for &err in ACTIVE {
            let c = err.code();
            if let Some(p) = prev {
                assert!(c > p, "codes must strictly ascend: {err:?}={c} follows {p}");
            }
            prev = Some(c);
        }
        assert_eq!(ACTIVE[0].code(), 0);
        assert_eq!(ACTIVE[ACTIVE.len() - 1].code(), 101);
    }

    #[test]
    fn easy_roundtrip_all_active_codes() {
        for &err in ACTIVE {
            assert_eq!(
                CurlError::from_code(err.code()),
                err,
                "from_code({}) should return {err:?}",
                err.code(),
            );
            // i32::from must agree with code().
            assert_eq!(CurlCode::from(err), err.code());
            assert_eq!(CurlCode::from(&err), err.code());
        }
    }

    #[test]
    fn easy_already_complete_roundtrips() {
        assert_eq!(CurlError::AlreadyComplete.code(), 99999);
        assert_eq!(CurlError::from_code(99999), CurlError::AlreadyComplete);
        assert_eq!(CurlError::AlreadyComplete.description(), "Unknown error");
    }

    #[test]
    fn easy_obsolete_and_unknown_codes_map_to_unknown() {
        for &code in OBSOLETE {
            assert_eq!(CurlError::from_code(code), CurlError::Unknown(code));
            assert_eq!(CurlError::from_code(code).code(), code);
        }
        // Arbitrary out-of-range integers round-trip losslessly too.
        for code in [-7, 200, 1000, 12345, i32::MAX, i32::MIN] {
            assert_eq!(CurlError::from_code(code), CurlError::Unknown(code));
            assert_eq!(CurlError::from_code(code).code(), code);
            assert_eq!(CurlError::Unknown(code).description(), "Unknown error");
        }
    }

    #[test]
    fn easy_display_equals_description() {
        for &err in ACTIVE {
            assert_eq!(
                err.to_string(),
                err.description(),
                "Display and description disagree for {err:?}",
            );
        }
        assert_eq!(CurlError::AlreadyComplete.to_string(), "Unknown error");
        assert_eq!(CurlError::Unknown(4242).to_string(), "Unknown error");
    }

    #[test]
    fn easy_multiline_string_is_exact() {
        // Guards the line-continuation in the `NotBuiltIn` message: it must equal
        // curl's two concatenated literals from lib/strerror.c with a single space.
        assert_eq!(
            CurlError::NotBuiltIn.to_string(),
            "A requested feature, protocol or option was not found built-in in \
             this libcurl due to a build-time decision.",
        );
        assert_eq!(
            CurlError::NotBuiltIn.description(),
            "A requested feature, protocol or option was not found built-in in \
             this libcurl due to a build-time decision.",
        );
    }

    #[test]
    fn easy_code_space_is_complete_and_disjoint() {
        // Every integer in 0..CURL_LAST is EXACTLY one of: an active variant code
        // or a retired/obsolete slot. This proves no gaps, no overlaps, and that
        // the sequential numbering is unbroken — the heart of ABI parity.
        for code in 0..codes::CURL_LAST {
            let is_active = ACTIVE.iter().any(|e| e.code() == code);
            let is_obsolete = OBSOLETE.contains(&code);
            assert!(
                is_active ^ is_obsolete,
                "code {code} must be exactly one of active/obsolete (active={is_active}, obsolete={is_obsolete})",
            );
        }
        // Counts: 87 active + 15 obsolete == 102 == CURL_LAST.
        assert_eq!(ACTIVE.len(), 87);
        assert_eq!(OBSOLETE.len(), 15);
        assert_eq!(
            ACTIVE.len() as CurlCode + OBSOLETE.len() as CurlCode,
            codes::CURL_LAST
        );
    }

    #[test]
    fn easy_active_codes_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for &err in ACTIVE {
            assert!(seen.insert(err.code()), "duplicate code for {err:?}");
        }
    }

    #[test]
    fn io_error_maps_to_correct_codes() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            CurlError::from(Error::from(ErrorKind::TimedOut)),
            CurlError::OperationTimedout,
        );
        assert_eq!(
            CurlError::from(Error::from(ErrorKind::ConnectionRefused)),
            CurlError::CouldntConnect,
        );
        assert_eq!(
            CurlError::from(Error::from(ErrorKind::BrokenPipe)),
            CurlError::SendError,
        );
        assert_eq!(
            CurlError::from(Error::from(ErrorKind::UnexpectedEof)),
            CurlError::RecvError,
        );
        assert_eq!(
            CurlError::from(Error::from(ErrorKind::OutOfMemory)),
            CurlError::OutOfMemory,
        );
        assert_eq!(
            CurlError::from(Error::from(ErrorKind::PermissionDenied)),
            CurlError::ReadError,
        );
        // The `?` operator should convert io::Error into CurlError transparently.
        fn fallible() -> Result<()> {
            Err(Error::from(ErrorKind::TimedOut))?;
            Ok(())
        }
        assert_eq!(fallible(), Err(CurlError::OperationTimedout));
    }

    #[test]
    fn error_trait_is_implemented() {
        // thiserror must give us a std::error::Error implementation.
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&CurlError::CouldntConnect);
        assert_error(&CurlMError::BadHandle);
        assert_error(&CurlUError::BadHandle);
        assert_error(&CurlShError::BadOption);
    }

    // ---- CURLMcode (multi) -------------------------------------------------

    #[test]
    fn multi_exact_integers_and_strings() {
        assert_eq!(CurlMError::CallMultiPerform.code(), -1);
        assert_eq!(CurlMError::Ok.code(), 0);
        assert_eq!(CurlMError::BadHandle.code(), 1);
        assert_eq!(CurlMError::UnrecoverablePoll.code(), 12);
        assert_eq!(codes::multi::CURLM_CALL_MULTI_PERFORM, -1);
        assert_eq!(codes::multi::CURLM_LAST, 13);

        assert_eq!(
            CurlMError::CallMultiPerform.description(),
            "Please call curl_multi_perform() soon",
        );
        assert_eq!(CurlMError::Ok.description(), "No error");
        assert_eq!(
            CurlMError::AddedAlready.description(),
            "The easy handle is already added to a multi handle",
        );
    }

    #[test]
    fn multi_roundtrip_and_invariants() {
        const ALL: &[CurlMError] = &[
            CurlMError::CallMultiPerform,
            CurlMError::Ok,
            CurlMError::BadHandle,
            CurlMError::BadEasyHandle,
            CurlMError::OutOfMemory,
            CurlMError::InternalError,
            CurlMError::BadSocket,
            CurlMError::UnknownOption,
            CurlMError::AddedAlready,
            CurlMError::RecursiveApiCall,
            CurlMError::WakeupFailure,
            CurlMError::BadFunctionArgument,
            CurlMError::AbortedByCallback,
            CurlMError::UnrecoverablePoll,
        ];
        for &m in ALL {
            assert_eq!(CurlMError::from_code(m.code()), Some(m));
            assert_eq!(CurlCode::from(m), m.code());
            assert_eq!(m.to_string(), m.description());
        }
        // Out-of-range -> None (curl renders these as "Unknown error").
        assert_eq!(CurlMError::from_code(13), None);
        assert_eq!(CurlMError::from_code(-2), None);
        assert_eq!(CurlMError::from_code(999), None);
    }

    // ---- CURLUcode (url) ---------------------------------------------------

    #[test]
    fn url_exact_integers_and_ordering() {
        assert_eq!(CurlUError::Ok.code(), 0);
        assert_eq!(CurlUError::BadHandle.code(), 1);
        assert_eq!(CurlUError::TooLarge.code(), 31);
        assert_eq!(codes::url::CURLUE_LAST, 32);
        // The header order differs from strerror.c's case order: BadFragment is
        // 20 (not BadHostname), BadIpv6 is 22, BadLogin is 23.
        assert_eq!(CurlUError::BadFileUrl.code(), 19);
        assert_eq!(CurlUError::BadFragment.code(), 20);
        assert_eq!(CurlUError::BadHostname.code(), 21);
        assert_eq!(CurlUError::BadIpv6.code(), 22);
        assert_eq!(CurlUError::BadLogin.code(), 23);
        assert_eq!(
            CurlUError::BadHandle.description(),
            "An invalid CURLU pointer was passed as argument"
        );
        assert_eq!(CurlUError::BadIpv6.description(), "Bad IPv6 address");
    }

    #[test]
    fn url_roundtrip_all_codes() {
        // CURLUcode is contiguous 0..=31.
        for code in 0..codes::url::CURLUE_LAST {
            let u = CurlUError::from_code(code).expect("0..LAST must be defined");
            assert_eq!(u.code(), code);
            assert_eq!(CurlCode::from(u), code);
            assert_eq!(u.to_string(), u.description());
        }
        assert_eq!(CurlUError::from_code(32), None);
        assert_eq!(CurlUError::from_code(-1), None);
    }

    // ---- CURLSHcode (share) ------------------------------------------------

    #[test]
    fn share_exact_integers_strings_and_roundtrip() {
        assert_eq!(CurlShError::Ok.code(), 0);
        assert_eq!(CurlShError::BadOption.code(), 1);
        assert_eq!(CurlShError::InUse.code(), 2);
        assert_eq!(CurlShError::Invalid.code(), 3);
        assert_eq!(CurlShError::Nomem.code(), 4);
        assert_eq!(CurlShError::NotBuiltIn.code(), 5);
        assert_eq!(codes::share::CURLSHE_LAST, 6);

        assert_eq!(CurlShError::BadOption.description(), "Unknown share option");
        assert_eq!(
            CurlShError::NotBuiltIn.description(),
            "Feature not enabled in this library"
        );

        for code in 0..codes::share::CURLSHE_LAST {
            let s = CurlShError::from_code(code).expect("0..LAST must be defined");
            assert_eq!(s.code(), code);
            assert_eq!(CurlCode::from(s), code);
            assert_eq!(s.to_string(), s.description());
        }
        assert_eq!(CurlShError::from_code(6), None);
        assert_eq!(CurlShError::from_code(-1), None);
    }

    // ---- CURLHcode (header API) --------------------------------------------

    #[test]
    fn header_exact_integers_strings_and_roundtrip() {
        // Pin the exact CURLHcode integers from include/curl/header.h.
        assert_eq!(CurlHError::Ok.code(), 0);
        assert_eq!(CurlHError::BadIndex.code(), 1);
        assert_eq!(CurlHError::Missing.code(), 2);
        assert_eq!(CurlHError::NoHeaders.code(), 3);
        assert_eq!(CurlHError::NoRequest.code(), 4);
        assert_eq!(CurlHError::OutOfMemory.code(), 5);
        assert_eq!(CurlHError::BadArgument.code(), 6);
        assert_eq!(CurlHError::NotBuiltIn.code(), 7);
        assert_eq!(codes::header::CURLHE_LAST, 8);

        // Named constants agree with the variant integers.
        assert_eq!(CurlHError::Ok.code(), codes::header::CURLHE_OK);
        assert_eq!(
            CurlHError::NotBuiltIn.code(),
            codes::header::CURLHE_NOT_BUILT_IN
        );

        // Display text matches description() for every variant.
        for code in 0..codes::header::CURLHE_LAST {
            let h = CurlHError::from_code(code).expect("0..LAST must be defined");
            assert_eq!(h.code(), code);
            assert_eq!(CurlCode::from(h), code);
            assert_eq!(CurlCode::from(&h), code);
            assert_eq!(h.to_string(), h.description());
        }
        assert_eq!(CurlHError::from_code(8), None);
        assert_eq!(CurlHError::from_code(-1), None);
        assert!(CurlHError::Ok.is_ok());
        assert!(!CurlHError::Missing.is_ok());
    }

    // ---- Ergonomics --------------------------------------------------------

    #[test]
    fn result_alias_and_copy_semantics() {
        let ok: Result<u32> = Ok(7);
        assert_eq!(ok, Ok(7));
        let err: Result<u32> = Err(CurlError::CouldntConnect);
        assert_eq!(err, Err(CurlError::CouldntConnect));

        // Copy: using a value after passing it by value must still compile.
        let e = CurlError::Http2;
        let _ = e.code();
        let _ = e.code();
        assert!(CurlError::Ok.is_ok());
        assert!(!CurlError::Http2.is_ok());
    }
}
