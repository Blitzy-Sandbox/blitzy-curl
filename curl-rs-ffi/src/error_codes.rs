//! All error and return code integer constants for the curl FFI layer.
//!
//! This module defines every `CURLcode`, `CURLMcode`, `CURLSHcode`,
//! `CURLUcode`, `CURLHcode`, and `CURLsslset` constant as `pub const` values.
//! Each constant matches the integer value from the corresponding C enum in the
//! curl 8.x headers **exactly** — this is a hard requirement for ABI
//! compatibility (see AAP Section 0.7.2).
//!
//! # Source References
//!
//! - `CURLcode`  — `include/curl/curl.h` (enum, lines ~518–648)
//! - `CURLMcode` — `include/curl/multi.h` (enum, lines ~59–78)
//! - `CURLSHcode` — `include/curl/curl.h` (enum, lines ~3064–3071)
//! - `CURLUcode` — `include/curl/urlapi.h` (enum, lines ~34–68)
//! - `CURLHcode` — `include/curl/header.h` (enum, lines ~47–56)
//! - `CURLsslset` — `include/curl/curl.h` (enum, lines ~2837–2841)
//!
//! # Design Notes
//!
//! - Type aliases (`CURLcode`, `CURLMcode`, etc.) are imported from
//!   [`crate::types`] rather than redefined here, avoiding ambiguity when
//!   `lib.rs` performs glob re-exports of both modules.
//! - Legacy compatibility aliases (`CURLE_HTTP_POST_ERROR`,
//!   `CURLE_FUNCTION_NOT_FOUND`) are provided at the same integer values as
//!   their `CURLE_OBSOLETE*` counterparts, matching the `#define` aliases in
//!   the C headers.
//! - No `unsafe` code exists in this file — it contains only constant
//!   definitions (per AAP Section 0.7.1).
//! - This file is foundational: every other module in the `curl-rs-ffi` crate
//!   imports from here.

#![allow(non_upper_case_globals)]

use crate::types::{CURLHcode, CURLMcode, CURLSHcode, CURLUcode, CURLcode, CURLsslset};

// ============================================================================
// Section 1: CURLcode — Easy-handle return codes
// Source: include/curl/curl.h, typedef enum { CURLE_OK = 0, ... } CURLcode;
//
// Values 0–101 are defined members of the C enum.  Value 102 (`CURL_LAST`)
// is the sentinel that MUST NEVER be used as an actual error code.
// All integer assignments match the C source exactly.
// ============================================================================

/// No error.
pub const CURLE_OK: CURLcode = 0;

/// The URL used an unsupported protocol.
pub const CURLE_UNSUPPORTED_PROTOCOL: CURLcode = 1;

/// Very early initialization code failed (internal error).
pub const CURLE_FAILED_INIT: CURLcode = 2;

/// The URL was not properly formatted.
pub const CURLE_URL_MALFORMAT: CURLcode = 3;

/// A requested feature, protocol, or option was not found built-in.
pub const CURLE_NOT_BUILT_IN: CURLcode = 4;

/// Could not resolve proxy.
pub const CURLE_COULDNT_RESOLVE_PROXY: CURLcode = 5;

/// Could not resolve host.
pub const CURLE_COULDNT_RESOLVE_HOST: CURLcode = 6;

/// Failed to connect to host or proxy.
pub const CURLE_COULDNT_CONNECT: CURLcode = 7;

/// The server sent data libcurl could not parse (weird reply).
pub const CURLE_WEIRD_SERVER_REPLY: CURLcode = 8;

/// Access denied by the remote server.
pub const CURLE_REMOTE_ACCESS_DENIED: CURLcode = 9;

/// FTP accept failed.
pub const CURLE_FTP_ACCEPT_FAILED: CURLcode = 10;

/// FTP: weird PASS reply.
pub const CURLE_FTP_WEIRD_PASS_REPLY: CURLcode = 11;

/// Timeout waiting for the FTP server to connect back.
pub const CURLE_FTP_ACCEPT_TIMEOUT: CURLcode = 12;

/// FTP: weird PASV reply.
pub const CURLE_FTP_WEIRD_PASV_REPLY: CURLcode = 13;

/// FTP: weird 227 format.
pub const CURLE_FTP_WEIRD_227_FORMAT: CURLcode = 14;

/// FTP: cannot determine the host from the 227 response.
pub const CURLE_FTP_CANT_GET_HOST: CURLcode = 15;

/// A problem was detected in the HTTP/2 framing layer.
pub const CURLE_HTTP2: CURLcode = 16;

/// FTP: could not set binary/ASCII transfer type.
pub const CURLE_FTP_COULDNT_SET_TYPE: CURLcode = 17;

/// Transfer closed with outstanding data remaining (partial file).
pub const CURLE_PARTIAL_FILE: CURLcode = 18;

/// FTP: could not retrieve (RETR failed) the specified file.
pub const CURLE_FTP_COULDNT_RETR_FILE: CURLcode = 19;

/// Obsolete error code 20 — not used.
pub const CURLE_OBSOLETE20: CURLcode = 20;

/// Quote command returned error from server.
pub const CURLE_QUOTE_ERROR: CURLcode = 21;

/// HTTP server returned an error code ≥ 400.
pub const CURLE_HTTP_RETURNED_ERROR: CURLcode = 22;

/// An error occurred when writing received data to a local file.
pub const CURLE_WRITE_ERROR: CURLcode = 23;

/// Obsolete error code 24 — not used.
pub const CURLE_OBSOLETE24: CURLcode = 24;

/// Upload failed (e.g., STOR command did not succeed).
pub const CURLE_UPLOAD_FAILED: CURLcode = 25;

/// There was a problem reading a local file for upload.
pub const CURLE_READ_ERROR: CURLcode = 26;

/// Out of memory.
pub const CURLE_OUT_OF_MEMORY: CURLcode = 27;

/// The operation timed out according to the configured timeout.
pub const CURLE_OPERATION_TIMEDOUT: CURLcode = 28;

/// Obsolete error code 29 — not used.
pub const CURLE_OBSOLETE29: CURLcode = 29;

/// FTP PORT command failed.
pub const CURLE_FTP_PORT_FAILED: CURLcode = 30;

/// FTP REST command failed.
pub const CURLE_FTP_COULDNT_USE_REST: CURLcode = 31;

/// Obsolete error code 32 — not used.
pub const CURLE_OBSOLETE32: CURLcode = 32;

/// The RANGE request did not work.
pub const CURLE_RANGE_ERROR: CURLcode = 33;

/// Obsolete error code 34 — preserved for ABI compatibility.
/// See also [`CURLE_HTTP_POST_ERROR`] (legacy alias at the same value).
pub const CURLE_OBSOLETE34: CURLcode = 34;

/// SSL connect error.
pub const CURLE_SSL_CONNECT_ERROR: CURLcode = 35;

/// Could not resume the download (RESUME_FROM failed).
pub const CURLE_BAD_DOWNLOAD_RESUME: CURLcode = 36;

/// FILE: could not read file.
pub const CURLE_FILE_COULDNT_READ_FILE: CURLcode = 37;

/// LDAP cannot bind — LDAP bind operation failed.
pub const CURLE_LDAP_CANNOT_BIND: CURLcode = 38;

/// LDAP search failed.
pub const CURLE_LDAP_SEARCH_FAILED: CURLcode = 39;

/// Obsolete error code 40 — not used.
pub const CURLE_OBSOLETE40: CURLcode = 40;

/// Obsolete error code 41 — not used since 7.53.0.
/// The legacy alias [`CURLE_FUNCTION_NOT_FOUND`] refers to this value.
pub const CURLE_OBSOLETE41: CURLcode = 41;

/// A callback returned "abort" to libcurl.
pub const CURLE_ABORTED_BY_CALLBACK: CURLcode = 42;

/// A function was called with a bad parameter.
pub const CURLE_BAD_FUNCTION_ARGUMENT: CURLcode = 43;

/// Obsolete error code 44 — not used.
pub const CURLE_OBSOLETE44: CURLcode = 44;

/// Binding the local end of the connection (CURLOPT_INTERFACE) failed.
pub const CURLE_INTERFACE_FAILED: CURLcode = 45;

/// Obsolete error code 46 — not used.
pub const CURLE_OBSOLETE46: CURLcode = 46;

/// Too many redirects; the redirect limit was reached.
pub const CURLE_TOO_MANY_REDIRECTS: CURLcode = 47;

/// An unknown option was passed to setopt.
pub const CURLE_UNKNOWN_OPTION: CURLcode = 48;

/// Malformed setopt option syntax.
pub const CURLE_SETOPT_OPTION_SYNTAX: CURLcode = 49;

/// Obsolete error code 50 — not used.
pub const CURLE_OBSOLETE50: CURLcode = 50;

/// Obsolete error code 51 — not used.
pub const CURLE_OBSOLETE51: CURLcode = 51;

/// Server returned nothing (no headers, no data).
pub const CURLE_GOT_NOTHING: CURLcode = 52;

/// The specified SSL crypto engine was not found.
pub const CURLE_SSL_ENGINE_NOTFOUND: CURLcode = 53;

/// Cannot set the selected SSL crypto engine as the default.
pub const CURLE_SSL_ENGINE_SETFAILED: CURLcode = 54;

/// Failed sending network data.
pub const CURLE_SEND_ERROR: CURLcode = 55;

/// Failure in receiving network data.
pub const CURLE_RECV_ERROR: CURLcode = 56;

/// Obsolete error code 57 — not used.
pub const CURLE_OBSOLETE57: CURLcode = 57;

/// Problem with the local client certificate.
pub const CURLE_SSL_CERTPROBLEM: CURLcode = 58;

/// Could not use the specified SSL cipher.
pub const CURLE_SSL_CIPHER: CURLcode = 59;

/// Peer certificate or fingerprint verification failed.
pub const CURLE_PEER_FAILED_VERIFICATION: CURLcode = 60;

/// Unrecognized or bad content encoding.
pub const CURLE_BAD_CONTENT_ENCODING: CURLcode = 61;

/// Obsolete error code 62 — not used since 7.82.0.
pub const CURLE_OBSOLETE62: CURLcode = 62;

/// Maximum file size exceeded.
pub const CURLE_FILESIZE_EXCEEDED: CURLcode = 63;

/// Requested FTP SSL level failed.
pub const CURLE_USE_SSL_FAILED: CURLcode = 64;

/// Sending the data requires a rewind that failed.
pub const CURLE_SEND_FAIL_REWIND: CURLcode = 65;

/// Failed to initialise the SSL ENGINE.
pub const CURLE_SSL_ENGINE_INITFAILED: CURLcode = 66;

/// Login denied — user, password, or similar was not accepted.
pub const CURLE_LOGIN_DENIED: CURLcode = 67;

/// TFTP: file not found on server.
pub const CURLE_TFTP_NOTFOUND: CURLcode = 68;

/// TFTP: permission problem on server.
pub const CURLE_TFTP_PERM: CURLcode = 69;

/// Out of disk space on the remote server.
pub const CURLE_REMOTE_DISK_FULL: CURLcode = 70;

/// TFTP: illegal operation.
pub const CURLE_TFTP_ILLEGAL: CURLcode = 71;

/// TFTP: unknown transfer ID.
pub const CURLE_TFTP_UNKNOWNID: CURLcode = 72;

/// File already exists and will not be overwritten.
pub const CURLE_REMOTE_FILE_EXISTS: CURLcode = 73;

/// TFTP: no such user.
pub const CURLE_TFTP_NOSUCHUSER: CURLcode = 74;

/// Obsolete error code 75 — not used since 7.82.0.
pub const CURLE_OBSOLETE75: CURLcode = 75;

/// Obsolete error code 76 — not used since 7.82.0.
pub const CURLE_OBSOLETE76: CURLcode = 76;

/// Could not load CACERT file (missing or wrong format).
pub const CURLE_SSL_CACERT_BADFILE: CURLcode = 77;

/// Remote file not found.
pub const CURLE_REMOTE_FILE_NOT_FOUND: CURLcode = 78;

/// Error from the SSH layer — see error message for details.
pub const CURLE_SSH: CURLcode = 79;

/// Failed to shut down the SSL connection.
pub const CURLE_SSL_SHUTDOWN_FAILED: CURLcode = 80;

/// Socket not ready for send/recv — try again.
pub const CURLE_AGAIN: CURLcode = 81;

/// Could not load CRL file (missing or wrong format).
pub const CURLE_SSL_CRL_BADFILE: CURLcode = 82;

/// Issuer check against peer certificate failed.
pub const CURLE_SSL_ISSUER_ERROR: CURLcode = 83;

/// FTP: PRET command failed.
pub const CURLE_FTP_PRET_FAILED: CURLcode = 84;

/// Mismatch of RTSP CSeq numbers.
pub const CURLE_RTSP_CSEQ_ERROR: CURLcode = 85;

/// Mismatch of RTSP session identifiers.
pub const CURLE_RTSP_SESSION_ERROR: CURLcode = 86;

/// Unable to parse FTP file list.
pub const CURLE_FTP_BAD_FILE_LIST: CURLcode = 87;

/// Chunk callback reported error.
pub const CURLE_CHUNK_FAILED: CURLcode = 88;

/// No connection available; the session will be queued.
pub const CURLE_NO_CONNECTION_AVAILABLE: CURLcode = 89;

/// Specified pinned public key did not match.
pub const CURLE_SSL_PINNEDPUBKEYNOTMATCH: CURLcode = 90;

/// Invalid certificate status (OCSP stapling).
pub const CURLE_SSL_INVALIDCERTSTATUS: CURLcode = 91;

/// Stream error in the HTTP/2 framing layer.
pub const CURLE_HTTP2_STREAM: CURLcode = 92;

/// An API function was called from inside a callback.
pub const CURLE_RECURSIVE_API_CALL: CURLcode = 93;

/// An authentication function returned an error.
pub const CURLE_AUTH_ERROR: CURLcode = 94;

/// An HTTP/3 layer problem.
pub const CURLE_HTTP3: CURLcode = 95;

/// QUIC connection error.
pub const CURLE_QUIC_CONNECT_ERROR: CURLcode = 96;

/// Proxy handshake error.
pub const CURLE_PROXY: CURLcode = 97;

/// Client-side certificate required.
pub const CURLE_SSL_CLIENTCERT: CURLcode = 98;

/// Poll/select returned a fatal error.
pub const CURLE_UNRECOVERABLE_POLL: CURLcode = 99;

/// A value or data met its maximum.
pub const CURLE_TOO_LARGE: CURLcode = 100;

/// ECH (Encrypted Client Hello) was tried but failed.
pub const CURLE_ECH_REQUIRED: CURLcode = 101;

/// Sentinel value — never used as an actual error code.
/// Marks the end of the `CURLcode` enum.
pub const CURL_LAST: CURLcode = 102;

// ---------------------------------------------------------------------------
// Legacy / backward-compatibility CURLcode aliases
// These correspond to C preprocessor `#define` directives in curl.h that
// map deprecated names to their CURLE_OBSOLETE* equivalents.
// ---------------------------------------------------------------------------

/// Legacy alias for [`CURLE_OBSOLETE34`] — removed in 7.56.0.
///
/// C equivalent: `#define CURLE_HTTP_POST_ERROR CURLE_OBSOLETE34`
pub const CURLE_HTTP_POST_ERROR: CURLcode = CURLE_OBSOLETE34;

/// Legacy alias for [`CURLE_OBSOLETE41`] — removed in 7.53.0.
///
/// C equivalent: `#define CURLE_FUNCTION_NOT_FOUND CURLE_OBSOLETE41`
pub const CURLE_FUNCTION_NOT_FOUND: CURLcode = CURLE_OBSOLETE41;

// ============================================================================
// Section 2: CURLMcode — Multi-handle return codes
// Source: include/curl/multi.h, typedef enum { ... } CURLMcode;
//
// Note: CURLM_CALL_MULTI_PERFORM has value -1 (the only negative code).
// ============================================================================

/// Deprecated: call `curl_multi_perform()` or `curl_multi_socket*()` again.
pub const CURLM_CALL_MULTI_PERFORM: CURLMcode = -1;

/// No error.
pub const CURLM_OK: CURLMcode = 0;

/// The passed-in handle is not a valid CURLM handle.
pub const CURLM_BAD_HANDLE: CURLMcode = 1;

/// An easy handle was not good/valid.
pub const CURLM_BAD_EASY_HANDLE: CURLMcode = 2;

/// Out of memory.
pub const CURLM_OUT_OF_MEMORY: CURLMcode = 3;

/// This is a libcurl bug (internal error).
pub const CURLM_INTERNAL_ERROR: CURLMcode = 4;

/// The passed-in socket argument did not match.
pub const CURLM_BAD_SOCKET: CURLMcode = 5;

/// `curl_multi_setopt()` called with unsupported option.
pub const CURLM_UNKNOWN_OPTION: CURLMcode = 6;

/// An easy handle already added to a multi handle was added again.
pub const CURLM_ADDED_ALREADY: CURLMcode = 7;

/// An API function was called from inside a callback.
pub const CURLM_RECURSIVE_API_CALL: CURLMcode = 8;

/// Wakeup is unavailable or failed.
pub const CURLM_WAKEUP_FAILURE: CURLMcode = 9;

/// Function called with a bad parameter.
pub const CURLM_BAD_FUNCTION_ARGUMENT: CURLMcode = 10;

/// Aborted by callback.
pub const CURLM_ABORTED_BY_CALLBACK: CURLMcode = 11;

/// Unrecoverable poll/select error.
pub const CURLM_UNRECOVERABLE_POLL: CURLMcode = 12;

/// Sentinel value — never used as an actual error code.
pub const CURLM_LAST: CURLMcode = 13;

// ============================================================================
// Section 3: CURLSHcode — Share-handle return codes
// Source: include/curl/curl.h, typedef enum { ... } CURLSHcode;
// ============================================================================

/// No error.
pub const CURLSHE_OK: CURLSHcode = 0;

/// Bad option passed to `curl_share_setopt`.
pub const CURLSHE_BAD_OPTION: CURLSHcode = 1;

/// The share object is currently in use.
pub const CURLSHE_IN_USE: CURLSHcode = 2;

/// Invalid share handle.
pub const CURLSHE_INVALID: CURLSHcode = 3;

/// Out of memory.
pub const CURLSHE_NOMEM: CURLSHcode = 4;

/// Feature not present in the library build.
pub const CURLSHE_NOT_BUILT_IN: CURLSHcode = 5;

/// Sentinel value — never used as an actual error code.
pub const CURLSHE_LAST: CURLSHcode = 6;

// ============================================================================
// Section 4: CURLUcode — URL API return codes
// Source: include/curl/urlapi.h, typedef enum { ... } CURLUcode;
// ============================================================================

/// No error.
pub const CURLUE_OK: CURLUcode = 0;

/// Bad URL handle.
pub const CURLUE_BAD_HANDLE: CURLUcode = 1;

/// Bad part pointer.
pub const CURLUE_BAD_PARTPOINTER: CURLUcode = 2;

/// Malformed input to a URL function.
pub const CURLUE_MALFORMED_INPUT: CURLUcode = 3;

/// Bad port number.
pub const CURLUE_BAD_PORT_NUMBER: CURLUcode = 4;

/// Unsupported URL scheme.
pub const CURLUE_UNSUPPORTED_SCHEME: CURLUcode = 5;

/// URL decode error.
pub const CURLUE_URLDECODE: CURLUcode = 6;

/// Out of memory.
pub const CURLUE_OUT_OF_MEMORY: CURLUcode = 7;

/// User not allowed in this URL.
pub const CURLUE_USER_NOT_ALLOWED: CURLUcode = 8;

/// Unknown URL part requested.
pub const CURLUE_UNKNOWN_PART: CURLUcode = 9;

/// No scheme part in the URL.
pub const CURLUE_NO_SCHEME: CURLUcode = 10;

/// No user part in the URL.
pub const CURLUE_NO_USER: CURLUcode = 11;

/// No password part in the URL.
pub const CURLUE_NO_PASSWORD: CURLUcode = 12;

/// No options part in the URL.
pub const CURLUE_NO_OPTIONS: CURLUcode = 13;

/// No host part in the URL.
pub const CURLUE_NO_HOST: CURLUcode = 14;

/// No port part in the URL.
pub const CURLUE_NO_PORT: CURLUcode = 15;

/// No query part in the URL.
pub const CURLUE_NO_QUERY: CURLUcode = 16;

/// No fragment part in the URL.
pub const CURLUE_NO_FRAGMENT: CURLUcode = 17;

/// No zone ID part in the URL.
pub const CURLUE_NO_ZONEID: CURLUcode = 18;

/// Bad file:// URL.
pub const CURLUE_BAD_FILE_URL: CURLUcode = 19;

/// Bad fragment in the URL.
pub const CURLUE_BAD_FRAGMENT: CURLUcode = 20;

/// Bad hostname in the URL.
pub const CURLUE_BAD_HOSTNAME: CURLUcode = 21;

/// Bad IPv6 address in the URL.
pub const CURLUE_BAD_IPV6: CURLUcode = 22;

/// Bad login part in the URL.
pub const CURLUE_BAD_LOGIN: CURLUcode = 23;

/// Bad password part in the URL.
pub const CURLUE_BAD_PASSWORD: CURLUcode = 24;

/// Bad path part in the URL.
pub const CURLUE_BAD_PATH: CURLUcode = 25;

/// Bad query part in the URL.
pub const CURLUE_BAD_QUERY: CURLUcode = 26;

/// Bad scheme part in the URL.
pub const CURLUE_BAD_SCHEME: CURLUcode = 27;

/// Bad slashes in the URL.
pub const CURLUE_BAD_SLASHES: CURLUcode = 28;

/// Bad user part in the URL.
pub const CURLUE_BAD_USER: CURLUcode = 29;

/// Internationalized domain name support is lacking.
pub const CURLUE_LACKS_IDN: CURLUcode = 30;

/// A URL component is too large.
pub const CURLUE_TOO_LARGE: CURLUcode = 31;

/// Sentinel value — never used as an actual error code.
pub const CURLUE_LAST: CURLUcode = 32;

// ============================================================================
// Section 5: CURLHcode — Header API return codes
// Source: include/curl/header.h, typedef enum { ... } CURLHcode;
// ============================================================================

/// No error.
pub const CURLHE_OK: CURLHcode = 0;

/// Header exists but not with the requested index.
pub const CURLHE_BADINDEX: CURLHcode = 1;

/// No such header exists.
pub const CURLHE_MISSING: CURLHcode = 2;

/// No headers at all exist (yet).
pub const CURLHE_NOHEADERS: CURLHcode = 3;

/// No request with this number was used.
pub const CURLHE_NOREQUEST: CURLHcode = 4;

/// Out of memory while processing.
pub const CURLHE_OUT_OF_MEMORY: CURLHcode = 5;

/// A function argument was not okay.
pub const CURLHE_BAD_ARGUMENT: CURLHcode = 6;

/// The API was disabled in the build.
pub const CURLHE_NOT_BUILT_IN: CURLHcode = 7;

// ============================================================================
// Section 6: CURLsslset — SSL backend selection return codes
// Source: include/curl/curl.h, typedef enum { ... } CURLsslset;
// ============================================================================

/// SSL backend successfully set.
pub const CURLSSLSET_OK: CURLsslset = 0;

/// The specified SSL backend is unknown.
pub const CURLSSLSET_UNKNOWN_BACKEND: CURLsslset = 1;

/// The SSL backend has already been set and cannot be changed.
pub const CURLSSLSET_TOO_LATE: CURLsslset = 2;

/// libcurl was built without any SSL support.
pub const CURLSSLSET_NO_BACKENDS: CURLsslset = 3;

// ============================================================================
// Module-level compile-time assertions
// Verify key sentinel values to catch any drift from the C headers.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify all CURLcode sentinel values are correct.
    #[test]
    fn curlcode_values_match_c_header() {
        assert_eq!(CURLE_OK, 0);
        assert_eq!(CURLE_UNSUPPORTED_PROTOCOL, 1);
        assert_eq!(CURLE_FAILED_INIT, 2);
        assert_eq!(CURLE_URL_MALFORMAT, 3);
        assert_eq!(CURLE_NOT_BUILT_IN, 4);
        assert_eq!(CURLE_COULDNT_RESOLVE_PROXY, 5);
        assert_eq!(CURLE_COULDNT_RESOLVE_HOST, 6);
        assert_eq!(CURLE_COULDNT_CONNECT, 7);
        assert_eq!(CURLE_WEIRD_SERVER_REPLY, 8);
        assert_eq!(CURLE_REMOTE_ACCESS_DENIED, 9);
        assert_eq!(CURLE_FTP_ACCEPT_FAILED, 10);
        assert_eq!(CURLE_FTP_WEIRD_PASS_REPLY, 11);
        assert_eq!(CURLE_FTP_ACCEPT_TIMEOUT, 12);
        assert_eq!(CURLE_FTP_WEIRD_PASV_REPLY, 13);
        assert_eq!(CURLE_FTP_WEIRD_227_FORMAT, 14);
        assert_eq!(CURLE_FTP_CANT_GET_HOST, 15);
        assert_eq!(CURLE_HTTP2, 16);
        assert_eq!(CURLE_FTP_COULDNT_SET_TYPE, 17);
        assert_eq!(CURLE_PARTIAL_FILE, 18);
        assert_eq!(CURLE_FTP_COULDNT_RETR_FILE, 19);
        assert_eq!(CURLE_OBSOLETE20, 20);
        assert_eq!(CURLE_QUOTE_ERROR, 21);
        assert_eq!(CURLE_HTTP_RETURNED_ERROR, 22);
        assert_eq!(CURLE_WRITE_ERROR, 23);
        assert_eq!(CURLE_OBSOLETE24, 24);
        assert_eq!(CURLE_UPLOAD_FAILED, 25);
        assert_eq!(CURLE_READ_ERROR, 26);
        assert_eq!(CURLE_OUT_OF_MEMORY, 27);
        assert_eq!(CURLE_OPERATION_TIMEDOUT, 28);
        assert_eq!(CURLE_OBSOLETE29, 29);
        assert_eq!(CURLE_FTP_PORT_FAILED, 30);
        assert_eq!(CURLE_FTP_COULDNT_USE_REST, 31);
        assert_eq!(CURLE_OBSOLETE32, 32);
        assert_eq!(CURLE_RANGE_ERROR, 33);
        assert_eq!(CURLE_OBSOLETE34, 34);
        assert_eq!(CURLE_SSL_CONNECT_ERROR, 35);
        assert_eq!(CURLE_BAD_DOWNLOAD_RESUME, 36);
        assert_eq!(CURLE_FILE_COULDNT_READ_FILE, 37);
        assert_eq!(CURLE_LDAP_CANNOT_BIND, 38);
        assert_eq!(CURLE_LDAP_SEARCH_FAILED, 39);
        assert_eq!(CURLE_OBSOLETE40, 40);
        assert_eq!(CURLE_OBSOLETE41, 41);
        assert_eq!(CURLE_ABORTED_BY_CALLBACK, 42);
        assert_eq!(CURLE_BAD_FUNCTION_ARGUMENT, 43);
        assert_eq!(CURLE_OBSOLETE44, 44);
        assert_eq!(CURLE_INTERFACE_FAILED, 45);
        assert_eq!(CURLE_OBSOLETE46, 46);
        assert_eq!(CURLE_TOO_MANY_REDIRECTS, 47);
        assert_eq!(CURLE_UNKNOWN_OPTION, 48);
        assert_eq!(CURLE_SETOPT_OPTION_SYNTAX, 49);
        assert_eq!(CURLE_OBSOLETE50, 50);
        assert_eq!(CURLE_OBSOLETE51, 51);
        assert_eq!(CURLE_GOT_NOTHING, 52);
        assert_eq!(CURLE_SSL_ENGINE_NOTFOUND, 53);
        assert_eq!(CURLE_SSL_ENGINE_SETFAILED, 54);
        assert_eq!(CURLE_SEND_ERROR, 55);
        assert_eq!(CURLE_RECV_ERROR, 56);
        assert_eq!(CURLE_OBSOLETE57, 57);
        assert_eq!(CURLE_SSL_CERTPROBLEM, 58);
        assert_eq!(CURLE_SSL_CIPHER, 59);
        assert_eq!(CURLE_PEER_FAILED_VERIFICATION, 60);
        assert_eq!(CURLE_BAD_CONTENT_ENCODING, 61);
        assert_eq!(CURLE_OBSOLETE62, 62);
        assert_eq!(CURLE_FILESIZE_EXCEEDED, 63);
        assert_eq!(CURLE_USE_SSL_FAILED, 64);
        assert_eq!(CURLE_SEND_FAIL_REWIND, 65);
        assert_eq!(CURLE_SSL_ENGINE_INITFAILED, 66);
        assert_eq!(CURLE_LOGIN_DENIED, 67);
        assert_eq!(CURLE_TFTP_NOTFOUND, 68);
        assert_eq!(CURLE_TFTP_PERM, 69);
        assert_eq!(CURLE_REMOTE_DISK_FULL, 70);
        assert_eq!(CURLE_TFTP_ILLEGAL, 71);
        assert_eq!(CURLE_TFTP_UNKNOWNID, 72);
        assert_eq!(CURLE_REMOTE_FILE_EXISTS, 73);
        assert_eq!(CURLE_TFTP_NOSUCHUSER, 74);
        assert_eq!(CURLE_OBSOLETE75, 75);
        assert_eq!(CURLE_OBSOLETE76, 76);
        assert_eq!(CURLE_SSL_CACERT_BADFILE, 77);
        assert_eq!(CURLE_REMOTE_FILE_NOT_FOUND, 78);
        assert_eq!(CURLE_SSH, 79);
        assert_eq!(CURLE_SSL_SHUTDOWN_FAILED, 80);
        assert_eq!(CURLE_AGAIN, 81);
        assert_eq!(CURLE_SSL_CRL_BADFILE, 82);
        assert_eq!(CURLE_SSL_ISSUER_ERROR, 83);
        assert_eq!(CURLE_FTP_PRET_FAILED, 84);
        assert_eq!(CURLE_RTSP_CSEQ_ERROR, 85);
        assert_eq!(CURLE_RTSP_SESSION_ERROR, 86);
        assert_eq!(CURLE_FTP_BAD_FILE_LIST, 87);
        assert_eq!(CURLE_CHUNK_FAILED, 88);
        assert_eq!(CURLE_NO_CONNECTION_AVAILABLE, 89);
        assert_eq!(CURLE_SSL_PINNEDPUBKEYNOTMATCH, 90);
        assert_eq!(CURLE_SSL_INVALIDCERTSTATUS, 91);
        assert_eq!(CURLE_HTTP2_STREAM, 92);
        assert_eq!(CURLE_RECURSIVE_API_CALL, 93);
        assert_eq!(CURLE_AUTH_ERROR, 94);
        assert_eq!(CURLE_HTTP3, 95);
        assert_eq!(CURLE_QUIC_CONNECT_ERROR, 96);
        assert_eq!(CURLE_PROXY, 97);
        assert_eq!(CURLE_SSL_CLIENTCERT, 98);
        assert_eq!(CURLE_UNRECOVERABLE_POLL, 99);
        assert_eq!(CURLE_TOO_LARGE, 100);
        assert_eq!(CURLE_ECH_REQUIRED, 101);
        assert_eq!(CURL_LAST, 102);
    }

    /// Verify legacy CURLcode aliases map to the same values.
    #[test]
    fn curlcode_legacy_aliases() {
        assert_eq!(CURLE_HTTP_POST_ERROR, CURLE_OBSOLETE34);
        assert_eq!(CURLE_HTTP_POST_ERROR, 34);
        assert_eq!(CURLE_FUNCTION_NOT_FOUND, CURLE_OBSOLETE41);
        assert_eq!(CURLE_FUNCTION_NOT_FOUND, 41);
    }

    /// Verify all CURLMcode values are correct.
    #[test]
    fn curlmcode_values_match_c_header() {
        assert_eq!(CURLM_CALL_MULTI_PERFORM, -1);
        assert_eq!(CURLM_OK, 0);
        assert_eq!(CURLM_BAD_HANDLE, 1);
        assert_eq!(CURLM_BAD_EASY_HANDLE, 2);
        assert_eq!(CURLM_OUT_OF_MEMORY, 3);
        assert_eq!(CURLM_INTERNAL_ERROR, 4);
        assert_eq!(CURLM_BAD_SOCKET, 5);
        assert_eq!(CURLM_UNKNOWN_OPTION, 6);
        assert_eq!(CURLM_ADDED_ALREADY, 7);
        assert_eq!(CURLM_RECURSIVE_API_CALL, 8);
        assert_eq!(CURLM_WAKEUP_FAILURE, 9);
        assert_eq!(CURLM_BAD_FUNCTION_ARGUMENT, 10);
        assert_eq!(CURLM_ABORTED_BY_CALLBACK, 11);
        assert_eq!(CURLM_UNRECOVERABLE_POLL, 12);
        assert_eq!(CURLM_LAST, 13);
    }

    /// Verify all CURLSHcode values are correct.
    #[test]
    fn curlshcode_values_match_c_header() {
        assert_eq!(CURLSHE_OK, 0);
        assert_eq!(CURLSHE_BAD_OPTION, 1);
        assert_eq!(CURLSHE_IN_USE, 2);
        assert_eq!(CURLSHE_INVALID, 3);
        assert_eq!(CURLSHE_NOMEM, 4);
        assert_eq!(CURLSHE_NOT_BUILT_IN, 5);
        assert_eq!(CURLSHE_LAST, 6);
    }

    /// Verify all CURLUcode values are correct.
    #[test]
    fn curlucode_values_match_c_header() {
        assert_eq!(CURLUE_OK, 0);
        assert_eq!(CURLUE_BAD_HANDLE, 1);
        assert_eq!(CURLUE_BAD_PARTPOINTER, 2);
        assert_eq!(CURLUE_MALFORMED_INPUT, 3);
        assert_eq!(CURLUE_BAD_PORT_NUMBER, 4);
        assert_eq!(CURLUE_UNSUPPORTED_SCHEME, 5);
        assert_eq!(CURLUE_URLDECODE, 6);
        assert_eq!(CURLUE_OUT_OF_MEMORY, 7);
        assert_eq!(CURLUE_USER_NOT_ALLOWED, 8);
        assert_eq!(CURLUE_UNKNOWN_PART, 9);
        assert_eq!(CURLUE_NO_SCHEME, 10);
        assert_eq!(CURLUE_NO_USER, 11);
        assert_eq!(CURLUE_NO_PASSWORD, 12);
        assert_eq!(CURLUE_NO_OPTIONS, 13);
        assert_eq!(CURLUE_NO_HOST, 14);
        assert_eq!(CURLUE_NO_PORT, 15);
        assert_eq!(CURLUE_NO_QUERY, 16);
        assert_eq!(CURLUE_NO_FRAGMENT, 17);
        assert_eq!(CURLUE_NO_ZONEID, 18);
        assert_eq!(CURLUE_BAD_FILE_URL, 19);
        assert_eq!(CURLUE_BAD_FRAGMENT, 20);
        assert_eq!(CURLUE_BAD_HOSTNAME, 21);
        assert_eq!(CURLUE_BAD_IPV6, 22);
        assert_eq!(CURLUE_BAD_LOGIN, 23);
        assert_eq!(CURLUE_BAD_PASSWORD, 24);
        assert_eq!(CURLUE_BAD_PATH, 25);
        assert_eq!(CURLUE_BAD_QUERY, 26);
        assert_eq!(CURLUE_BAD_SCHEME, 27);
        assert_eq!(CURLUE_BAD_SLASHES, 28);
        assert_eq!(CURLUE_BAD_USER, 29);
        assert_eq!(CURLUE_LACKS_IDN, 30);
        assert_eq!(CURLUE_TOO_LARGE, 31);
        assert_eq!(CURLUE_LAST, 32);
    }

    /// Verify all CURLHcode values are correct.
    #[test]
    fn curlhcode_values_match_c_header() {
        assert_eq!(CURLHE_OK, 0);
        assert_eq!(CURLHE_BADINDEX, 1);
        assert_eq!(CURLHE_MISSING, 2);
        assert_eq!(CURLHE_NOHEADERS, 3);
        assert_eq!(CURLHE_NOREQUEST, 4);
        assert_eq!(CURLHE_OUT_OF_MEMORY, 5);
        assert_eq!(CURLHE_BAD_ARGUMENT, 6);
        assert_eq!(CURLHE_NOT_BUILT_IN, 7);
    }

    /// Verify all CURLsslset values are correct.
    #[test]
    fn curlsslset_values_match_c_header() {
        assert_eq!(CURLSSLSET_OK, 0);
        assert_eq!(CURLSSLSET_UNKNOWN_BACKEND, 1);
        assert_eq!(CURLSSLSET_TOO_LATE, 2);
        assert_eq!(CURLSSLSET_NO_BACKENDS, 3);
    }

    /// Verify contiguous CURLcode range: every value from 0 through CURL_LAST-1
    /// is covered by a constant (no gaps in the error code space).
    #[test]
    fn curlcode_contiguous_range() {
        let all_codes: [CURLcode; 102] = [
            CURLE_OK,
            CURLE_UNSUPPORTED_PROTOCOL,
            CURLE_FAILED_INIT,
            CURLE_URL_MALFORMAT,
            CURLE_NOT_BUILT_IN,
            CURLE_COULDNT_RESOLVE_PROXY,
            CURLE_COULDNT_RESOLVE_HOST,
            CURLE_COULDNT_CONNECT,
            CURLE_WEIRD_SERVER_REPLY,
            CURLE_REMOTE_ACCESS_DENIED,
            CURLE_FTP_ACCEPT_FAILED,
            CURLE_FTP_WEIRD_PASS_REPLY,
            CURLE_FTP_ACCEPT_TIMEOUT,
            CURLE_FTP_WEIRD_PASV_REPLY,
            CURLE_FTP_WEIRD_227_FORMAT,
            CURLE_FTP_CANT_GET_HOST,
            CURLE_HTTP2,
            CURLE_FTP_COULDNT_SET_TYPE,
            CURLE_PARTIAL_FILE,
            CURLE_FTP_COULDNT_RETR_FILE,
            CURLE_OBSOLETE20,
            CURLE_QUOTE_ERROR,
            CURLE_HTTP_RETURNED_ERROR,
            CURLE_WRITE_ERROR,
            CURLE_OBSOLETE24,
            CURLE_UPLOAD_FAILED,
            CURLE_READ_ERROR,
            CURLE_OUT_OF_MEMORY,
            CURLE_OPERATION_TIMEDOUT,
            CURLE_OBSOLETE29,
            CURLE_FTP_PORT_FAILED,
            CURLE_FTP_COULDNT_USE_REST,
            CURLE_OBSOLETE32,
            CURLE_RANGE_ERROR,
            CURLE_OBSOLETE34,
            CURLE_SSL_CONNECT_ERROR,
            CURLE_BAD_DOWNLOAD_RESUME,
            CURLE_FILE_COULDNT_READ_FILE,
            CURLE_LDAP_CANNOT_BIND,
            CURLE_LDAP_SEARCH_FAILED,
            CURLE_OBSOLETE40,
            CURLE_OBSOLETE41,
            CURLE_ABORTED_BY_CALLBACK,
            CURLE_BAD_FUNCTION_ARGUMENT,
            CURLE_OBSOLETE44,
            CURLE_INTERFACE_FAILED,
            CURLE_OBSOLETE46,
            CURLE_TOO_MANY_REDIRECTS,
            CURLE_UNKNOWN_OPTION,
            CURLE_SETOPT_OPTION_SYNTAX,
            CURLE_OBSOLETE50,
            CURLE_OBSOLETE51,
            CURLE_GOT_NOTHING,
            CURLE_SSL_ENGINE_NOTFOUND,
            CURLE_SSL_ENGINE_SETFAILED,
            CURLE_SEND_ERROR,
            CURLE_RECV_ERROR,
            CURLE_OBSOLETE57,
            CURLE_SSL_CERTPROBLEM,
            CURLE_SSL_CIPHER,
            CURLE_PEER_FAILED_VERIFICATION,
            CURLE_BAD_CONTENT_ENCODING,
            CURLE_OBSOLETE62,
            CURLE_FILESIZE_EXCEEDED,
            CURLE_USE_SSL_FAILED,
            CURLE_SEND_FAIL_REWIND,
            CURLE_SSL_ENGINE_INITFAILED,
            CURLE_LOGIN_DENIED,
            CURLE_TFTP_NOTFOUND,
            CURLE_TFTP_PERM,
            CURLE_REMOTE_DISK_FULL,
            CURLE_TFTP_ILLEGAL,
            CURLE_TFTP_UNKNOWNID,
            CURLE_REMOTE_FILE_EXISTS,
            CURLE_TFTP_NOSUCHUSER,
            CURLE_OBSOLETE75,
            CURLE_OBSOLETE76,
            CURLE_SSL_CACERT_BADFILE,
            CURLE_REMOTE_FILE_NOT_FOUND,
            CURLE_SSH,
            CURLE_SSL_SHUTDOWN_FAILED,
            CURLE_AGAIN,
            CURLE_SSL_CRL_BADFILE,
            CURLE_SSL_ISSUER_ERROR,
            CURLE_FTP_PRET_FAILED,
            CURLE_RTSP_CSEQ_ERROR,
            CURLE_RTSP_SESSION_ERROR,
            CURLE_FTP_BAD_FILE_LIST,
            CURLE_CHUNK_FAILED,
            CURLE_NO_CONNECTION_AVAILABLE,
            CURLE_SSL_PINNEDPUBKEYNOTMATCH,
            CURLE_SSL_INVALIDCERTSTATUS,
            CURLE_HTTP2_STREAM,
            CURLE_RECURSIVE_API_CALL,
            CURLE_AUTH_ERROR,
            CURLE_HTTP3,
            CURLE_QUIC_CONNECT_ERROR,
            CURLE_PROXY,
            CURLE_SSL_CLIENTCERT,
            CURLE_UNRECOVERABLE_POLL,
            CURLE_TOO_LARGE,
            CURLE_ECH_REQUIRED,
        ];
        for (i, &code) in all_codes.iter().enumerate() {
            assert_eq!(
                code, i as CURLcode,
                "CURLcode at index {i} has value {code}, expected {i}"
            );
        }
    }

    /// Verify contiguous CURLMcode range (0 through CURLM_LAST-1).
    #[test]
    fn curlmcode_contiguous_range() {
        let positive_codes: [CURLMcode; 13] = [
            CURLM_OK,
            CURLM_BAD_HANDLE,
            CURLM_BAD_EASY_HANDLE,
            CURLM_OUT_OF_MEMORY,
            CURLM_INTERNAL_ERROR,
            CURLM_BAD_SOCKET,
            CURLM_UNKNOWN_OPTION,
            CURLM_ADDED_ALREADY,
            CURLM_RECURSIVE_API_CALL,
            CURLM_WAKEUP_FAILURE,
            CURLM_BAD_FUNCTION_ARGUMENT,
            CURLM_ABORTED_BY_CALLBACK,
            CURLM_UNRECOVERABLE_POLL,
        ];
        for (i, &code) in positive_codes.iter().enumerate() {
            assert_eq!(
                code, i as CURLMcode,
                "CURLMcode at index {i} has value {code}, expected {i}"
            );
        }
    }

    /// Verify contiguous CURLSHcode range (0 through CURLSHE_LAST-1).
    #[test]
    fn curlshcode_contiguous_range() {
        let codes: [CURLSHcode; 6] = [
            CURLSHE_OK,
            CURLSHE_BAD_OPTION,
            CURLSHE_IN_USE,
            CURLSHE_INVALID,
            CURLSHE_NOMEM,
            CURLSHE_NOT_BUILT_IN,
        ];
        for (i, &code) in codes.iter().enumerate() {
            assert_eq!(
                code, i as CURLSHcode,
                "CURLSHcode at index {i} has value {code}, expected {i}"
            );
        }
    }

    /// Verify contiguous CURLUcode range (0 through CURLUE_LAST-1).
    #[test]
    fn curlucode_contiguous_range() {
        let codes: [CURLUcode; 32] = [
            CURLUE_OK,
            CURLUE_BAD_HANDLE,
            CURLUE_BAD_PARTPOINTER,
            CURLUE_MALFORMED_INPUT,
            CURLUE_BAD_PORT_NUMBER,
            CURLUE_UNSUPPORTED_SCHEME,
            CURLUE_URLDECODE,
            CURLUE_OUT_OF_MEMORY,
            CURLUE_USER_NOT_ALLOWED,
            CURLUE_UNKNOWN_PART,
            CURLUE_NO_SCHEME,
            CURLUE_NO_USER,
            CURLUE_NO_PASSWORD,
            CURLUE_NO_OPTIONS,
            CURLUE_NO_HOST,
            CURLUE_NO_PORT,
            CURLUE_NO_QUERY,
            CURLUE_NO_FRAGMENT,
            CURLUE_NO_ZONEID,
            CURLUE_BAD_FILE_URL,
            CURLUE_BAD_FRAGMENT,
            CURLUE_BAD_HOSTNAME,
            CURLUE_BAD_IPV6,
            CURLUE_BAD_LOGIN,
            CURLUE_BAD_PASSWORD,
            CURLUE_BAD_PATH,
            CURLUE_BAD_QUERY,
            CURLUE_BAD_SCHEME,
            CURLUE_BAD_SLASHES,
            CURLUE_BAD_USER,
            CURLUE_LACKS_IDN,
            CURLUE_TOO_LARGE,
        ];
        for (i, &code) in codes.iter().enumerate() {
            assert_eq!(
                code, i as CURLUcode,
                "CURLUcode at index {i} has value {code}, expected {i}"
            );
        }
    }

    /// Verify contiguous CURLHcode range (0 through 7).
    #[test]
    fn curlhcode_contiguous_range() {
        let codes: [CURLHcode; 8] = [
            CURLHE_OK,
            CURLHE_BADINDEX,
            CURLHE_MISSING,
            CURLHE_NOHEADERS,
            CURLHE_NOREQUEST,
            CURLHE_OUT_OF_MEMORY,
            CURLHE_BAD_ARGUMENT,
            CURLHE_NOT_BUILT_IN,
        ];
        for (i, &code) in codes.iter().enumerate() {
            assert_eq!(
                code, i as CURLHcode,
                "CURLHcode at index {i} has value {code}, expected {i}"
            );
        }
    }

    /// Verify the count of all defined constants matches expectations.
    #[test]
    fn total_constant_count() {
        // CURLcode: 102 enum values (0-101) + CURL_LAST + 2 aliases = 105
        // CURLMcode: 14 (including -1) + CURLM_LAST = 15
        // CURLSHcode: 6 + CURLSHE_LAST = 7
        // CURLUcode: 32 + CURLUE_LAST = 33
        // CURLHcode: 8
        // CURLsslset: 4
        // Total: 105 + 15 + 7 + 33 + 8 + 4 = 172
        //
        // This test simply validates the sentinel values, which implicitly
        // confirms the count of each category.
        assert_eq!(CURL_LAST, 102, "CURLcode sentinel");
        assert_eq!(CURLM_LAST, 13, "CURLMcode sentinel");
        assert_eq!(CURLSHE_LAST, 6, "CURLSHcode sentinel");
        assert_eq!(CURLUE_LAST, 32, "CURLUcode sentinel");
        // CURLHcode has no explicit LAST sentinel — the highest value is 7.
        assert_eq!(CURLHE_NOT_BUILT_IN, 7, "CURLHcode highest value");
        // CURLsslset has no explicit LAST sentinel — the highest value is 3.
        assert_eq!(CURLSSLSET_NO_BACKENDS, 3, "CURLsslset highest value");
    }
}
