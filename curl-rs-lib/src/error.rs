//! Typed error hierarchy and the frozen `CURLcode` integer contract for
//! `curl-rs-lib`.
//!
//! This module is the **foundational** error subsystem of the safe-Rust libcurl
//! core. Every other module in the crate returns [`Result<T>`] (an alias for
//! `Result<T, Error>`). It is a language rewrite of the curl 8.x error
//! subsystem, derived from the source-of-truth `lib/strerror.c`
//! (`curl_easy_strerror` and its siblings) and the canonical enumerations in
//! `include/curl/curl.h`, `include/curl/multi.h`, and `include/curl/urlapi.h`.
//!
//! # Frozen integer ABI contract
//!
//! The integer value of every [`CurlCode`] variant is a **frozen ABI contract**.
//! The `curl-rs-ffi` crate bridges these Rust errors to the C `CURLcode`
//! integers at the FFI boundary, preserving the exact integer values so that a
//! consumer that hard-codes `CURLE_OPERATION_TIMEDOUT == 28` keeps working.
//! For this reason the discriminants below are transcribed verbatim from
//! `include/curl/curl.h`, and the obsolete / reserved slots are preserved as
//! explicit variants (e.g. [`CurlCode::Obsolete20`]) so the numbering can never
//! drift. The same freezing applies to [`CurlMCode`], [`CurlShCode`], and
//! [`CurlUCode`], whose values mirror `include/curl/multi.h`,
//! `include/curl/curl.h`, and `include/curl/urlapi.h` respectively.
//!
//! # Message-string parity
//!
//! [`strerror`], [`multi_strerror`], [`share_strerror`], and [`url_strerror`]
//! return the exact human-readable strings emitted by curl 8.x, so that stderr
//! text stays stable for downstream log scrapers.
//!
//! # Guarantees
//!
//! This module contains only memory-safe Rust: no raw-pointer manipulation, no
//! `panic!`, and no `unwrap()` / `expect()` in library code paths — fallible
//! operations return an [`Error`] instead. All FFI integer conversions are
//! either total or explicitly fallible via [`TryFrom`].

use std::fmt;

/// The libcurl "easy" interface result code, mirroring the C `CURLcode`
/// enumeration in `include/curl/curl.h`.
///
/// Each discriminant is transcribed verbatim from curl 8.x. The obsolete /
/// reserved slots are kept as explicit `ObsoleteNN` variants so that the
/// integer numbering never drifts; the sentinel `CURL_LAST` is intentionally
/// **not** represented. Deprecated compatibility aliases (the historical
/// `CURLE_*` `#define`s) are exposed as associated constants on this type.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlCode {
    /// `CURLE_OK` — no error, the operation succeeded.
    Ok = 0,
    /// `CURLE_UNSUPPORTED_PROTOCOL` — the URL used an unsupported protocol.
    UnsupportedProtocol = 1,
    /// `CURLE_FAILED_INIT` — early initialization code failed.
    FailedInit = 2,
    /// `CURLE_URL_MALFORMAT` — the URL was malformed or missing.
    UrlMalformat = 3,
    /// `CURLE_NOT_BUILT_IN` — a requested feature/protocol/option was not
    /// compiled in.
    NotBuiltIn = 4,
    /// `CURLE_COULDNT_RESOLVE_PROXY` — the proxy host name could not be
    /// resolved.
    CouldntResolveProxy = 5,
    /// `CURLE_COULDNT_RESOLVE_HOST` — the host name could not be resolved.
    CouldntResolveHost = 6,
    /// `CURLE_COULDNT_CONNECT` — failed to connect to the host or proxy.
    CouldntConnect = 7,
    /// `CURLE_WEIRD_SERVER_REPLY` — the server sent an unexpected reply.
    WeirdServerReply = 8,
    /// `CURLE_REMOTE_ACCESS_DENIED` — access to the remote resource was denied.
    RemoteAccessDenied = 9,
    /// `CURLE_FTP_ACCEPT_FAILED` — the server failed to connect to the data
    /// port.
    FtpAcceptFailed = 10,
    /// `CURLE_FTP_WEIRD_PASS_REPLY` — an unknown reply to the FTP `PASS`
    /// command.
    FtpWeirdPassReply = 11,
    /// `CURLE_FTP_ACCEPT_TIMEOUT` — timed out waiting for the server to
    /// connect back.
    FtpAcceptTimeout = 12,
    /// `CURLE_FTP_WEIRD_PASV_REPLY` — an unknown reply to the FTP `PASV`
    /// command.
    FtpWeirdPasvReply = 13,
    /// `CURLE_FTP_WEIRD_227_FORMAT` — an unknown `227` response format.
    FtpWeird227Format = 14,
    /// `CURLE_FTP_CANT_GET_HOST` — could not parse the host from the `PASV`
    /// response.
    FtpCantGetHost = 15,
    /// `CURLE_HTTP2` — a problem in the HTTP/2 framing layer.
    Http2 = 16,
    /// `CURLE_FTP_COULDNT_SET_TYPE` — could not set the FTP transfer type.
    FtpCouldntSetType = 17,
    /// `CURLE_PARTIAL_FILE` — a partial file was transferred.
    PartialFile = 18,
    /// `CURLE_FTP_COULDNT_RETR_FILE` — the FTP `RETR` command failed.
    FtpCouldntRetrFile = 19,
    /// `CURLE_OBSOLETE20` — reserved / not used (kept for numbering stability).
    Obsolete20 = 20,
    /// `CURLE_QUOTE_ERROR` — a quote command returned an error.
    QuoteError = 21,
    /// `CURLE_HTTP_RETURNED_ERROR` — the HTTP response code indicated an error.
    HttpReturnedError = 22,
    /// `CURLE_WRITE_ERROR` — failed writing received data to disk/application.
    WriteError = 23,
    /// `CURLE_OBSOLETE24` — reserved / not used (kept for numbering stability).
    Obsolete24 = 24,
    /// `CURLE_UPLOAD_FAILED` — an upload failed to start.
    UploadFailed = 25,
    /// `CURLE_READ_ERROR` — could not open or read from a local file.
    ReadError = 26,
    /// `CURLE_OUT_OF_MEMORY` — a memory allocation request failed.
    OutOfMemory = 27,
    /// `CURLE_OPERATION_TIMEDOUT` — the operation timed out.
    OperationTimedout = 28,
    /// `CURLE_OBSOLETE29` — reserved / not used (kept for numbering stability).
    Obsolete29 = 29,
    /// `CURLE_FTP_PORT_FAILED` — the FTP `PORT` command failed.
    FtpPortFailed = 30,
    /// `CURLE_FTP_COULDNT_USE_REST` — the FTP `REST` command failed.
    FtpCouldntUseRest = 31,
    /// `CURLE_OBSOLETE32` — reserved / not used (kept for numbering stability).
    Obsolete32 = 32,
    /// `CURLE_RANGE_ERROR` — the `RANGE` command did not work.
    RangeError = 33,
    /// `CURLE_OBSOLETE34` — reserved / not used (kept for numbering stability).
    Obsolete34 = 34,
    /// `CURLE_SSL_CONNECT_ERROR` — an error occurred during the TLS handshake.
    SslConnectError = 35,
    /// `CURLE_BAD_DOWNLOAD_RESUME` — could not resume the download.
    BadDownloadResume = 36,
    /// `CURLE_FILE_COULDNT_READ_FILE` — could not read a `file://` file.
    FileCouldntReadFile = 37,
    /// `CURLE_LDAP_CANNOT_BIND` — the LDAP bind operation failed.
    LdapCannotBind = 38,
    /// `CURLE_LDAP_SEARCH_FAILED` — the LDAP search failed.
    LdapSearchFailed = 39,
    /// `CURLE_OBSOLETE40` — reserved / not used (kept for numbering stability).
    Obsolete40 = 40,
    /// `CURLE_OBSOLETE41` — reserved / not used (kept for numbering stability).
    Obsolete41 = 41,
    /// `CURLE_ABORTED_BY_CALLBACK` — an application callback aborted the
    /// operation.
    AbortedByCallback = 42,
    /// `CURLE_BAD_FUNCTION_ARGUMENT` — a function was passed a bad argument.
    BadFunctionArgument = 43,
    /// `CURLE_OBSOLETE44` — reserved / not used (kept for numbering stability).
    Obsolete44 = 44,
    /// `CURLE_INTERFACE_FAILED` — `CURLOPT_INTERFACE` binding failed.
    InterfaceFailed = 45,
    /// `CURLE_OBSOLETE46` — reserved / not used (kept for numbering stability).
    Obsolete46 = 46,
    /// `CURLE_TOO_MANY_REDIRECTS` — the maximum redirect count was hit.
    TooManyRedirects = 47,
    /// `CURLE_UNKNOWN_OPTION` — an unknown option was passed to libcurl.
    UnknownOption = 48,
    /// `CURLE_SETOPT_OPTION_SYNTAX` — a malformed setopt option was provided.
    SetoptOptionSyntax = 49,
    /// `CURLE_OBSOLETE50` — reserved / not used (kept for numbering stability).
    Obsolete50 = 50,
    /// `CURLE_OBSOLETE51` — reserved / not used (kept for numbering stability).
    Obsolete51 = 51,
    /// `CURLE_GOT_NOTHING` — the server returned nothing (no headers, no data).
    GotNothing = 52,
    /// `CURLE_SSL_ENGINE_NOTFOUND` — the requested TLS crypto engine was not
    /// found.
    SslEngineNotfound = 53,
    /// `CURLE_SSL_ENGINE_SETFAILED` — could not set the TLS crypto engine as
    /// default.
    SslEngineSetfailed = 54,
    /// `CURLE_SEND_ERROR` — failed sending network data.
    SendError = 55,
    /// `CURLE_RECV_ERROR` — failure receiving network data.
    RecvError = 56,
    /// `CURLE_OBSOLETE57` — reserved / not used (kept for numbering stability).
    Obsolete57 = 57,
    /// `CURLE_SSL_CERTPROBLEM` — a problem with the local client certificate.
    SslCertproblem = 58,
    /// `CURLE_SSL_CIPHER` — could not use the specified TLS cipher.
    SslCipher = 59,
    /// `CURLE_PEER_FAILED_VERIFICATION` — the peer certificate or SSH remote
    /// key could not be verified.
    PeerFailedVerification = 60,
    /// `CURLE_BAD_CONTENT_ENCODING` — an unrecognized or bad content encoding.
    BadContentEncoding = 61,
    /// `CURLE_OBSOLETE62` — reserved / not used (kept for numbering stability).
    Obsolete62 = 62,
    /// `CURLE_FILESIZE_EXCEEDED` — the maximum file size was exceeded.
    FilesizeExceeded = 63,
    /// `CURLE_USE_SSL_FAILED` — the requested TLS level could not be reached.
    UseSslFailed = 64,
    /// `CURLE_SEND_FAIL_REWIND` — sending the data required a rewind that
    /// failed.
    SendFailRewind = 65,
    /// `CURLE_SSL_ENGINE_INITFAILED` — the TLS crypto engine failed to
    /// initialize.
    SslEngineInitfailed = 66,
    /// `CURLE_LOGIN_DENIED` — the credentials were not accepted.
    LoginDenied = 67,
    /// `CURLE_TFTP_NOTFOUND` — the file was not found on the TFTP server.
    TftpNotfound = 68,
    /// `CURLE_TFTP_PERM` — a TFTP permission problem on the server.
    TftpPerm = 69,
    /// `CURLE_REMOTE_DISK_FULL` — the server is out of disk space.
    RemoteDiskFull = 70,
    /// `CURLE_TFTP_ILLEGAL` — an illegal TFTP operation.
    TftpIllegal = 71,
    /// `CURLE_TFTP_UNKNOWNID` — an unknown TFTP transfer ID.
    TftpUnknownid = 72,
    /// `CURLE_REMOTE_FILE_EXISTS` — the remote file already exists.
    RemoteFileExists = 73,
    /// `CURLE_TFTP_NOSUCHUSER` — no such TFTP user.
    TftpNosuchuser = 74,
    /// `CURLE_OBSOLETE75` — reserved / not used (kept for numbering stability).
    Obsolete75 = 75,
    /// `CURLE_OBSOLETE76` — reserved / not used (kept for numbering stability).
    Obsolete76 = 76,
    /// `CURLE_SSL_CACERT_BADFILE` — could not load the CA certificate file.
    SslCacertBadfile = 77,
    /// `CURLE_REMOTE_FILE_NOT_FOUND` — the remote file was not found.
    RemoteFileNotFound = 78,
    /// `CURLE_SSH` — an error from the SSH layer.
    Ssh = 79,
    /// `CURLE_SSL_SHUTDOWN_FAILED` — failed to shut down the TLS connection.
    SslShutdownFailed = 80,
    /// `CURLE_AGAIN` — the socket is not ready for send/recv; try again.
    Again = 81,
    /// `CURLE_SSL_CRL_BADFILE` — could not load the CRL file.
    SslCrlBadfile = 82,
    /// `CURLE_SSL_ISSUER_ERROR` — the issuer check failed.
    SslIssuerError = 83,
    /// `CURLE_FTP_PRET_FAILED` — the FTP `PRET` command failed.
    FtpPretFailed = 84,
    /// `CURLE_RTSP_CSEQ_ERROR` — mismatch of RTSP `CSeq` numbers.
    RtspCseqError = 85,
    /// `CURLE_RTSP_SESSION_ERROR` — mismatch of RTSP session identifiers.
    RtspSessionError = 86,
    /// `CURLE_FTP_BAD_FILE_LIST` — unable to parse the FTP file list.
    FtpBadFileList = 87,
    /// `CURLE_CHUNK_FAILED` — the chunk callback reported an error.
    ChunkFailed = 88,
    /// `CURLE_NO_CONNECTION_AVAILABLE` — no connection available; queued.
    NoConnectionAvailable = 89,
    /// `CURLE_SSL_PINNEDPUBKEYNOTMATCH` — the pinned public key did not match.
    SslPinnedpubkeynotmatch = 90,
    /// `CURLE_SSL_INVALIDCERTSTATUS` — an invalid certificate status.
    SslInvalidcertstatus = 91,
    /// `CURLE_HTTP2_STREAM` — a stream error in the HTTP/2 framing layer.
    Http2Stream = 92,
    /// `CURLE_RECURSIVE_API_CALL` — an API function was called from within a
    /// callback.
    RecursiveApiCall = 93,
    /// `CURLE_AUTH_ERROR` — an authentication function returned an error.
    AuthError = 94,
    /// `CURLE_HTTP3` — an HTTP/3 layer problem.
    Http3 = 95,
    /// `CURLE_QUIC_CONNECT_ERROR` — a QUIC connection error.
    QuicConnectError = 96,
    /// `CURLE_PROXY` — a proxy handshake error.
    Proxy = 97,
    /// `CURLE_SSL_CLIENTCERT` — a client-side certificate is required.
    SslClientcert = 98,
    /// `CURLE_UNRECOVERABLE_POLL` — `poll`/`select` returned a fatal error.
    UnrecoverablePoll = 99,
    /// `CURLE_TOO_LARGE` — a value or data field met its maximum.
    TooLarge = 100,
    /// `CURLE_ECH_REQUIRED` — ECH was attempted but failed.
    EchRequired = 101,
}

impl CurlCode {
    /// Returns the frozen integer value of this code as an [`i32`], matching
    /// the C `CURLcode` integer. This is a `const fn` so it can be used in
    /// constant contexts by the FFI layer.
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        self as i32
    }

    /// Returns the exact curl 8.x human-readable message for this code
    /// (equivalent to `curl_easy_strerror`). See [`strerror`].
    #[must_use]
    pub fn message(self) -> &'static str {
        strerror(self)
    }

    // ---------------------------------------------------------------------
    // Deprecated compatibility aliases.
    //
    // These mirror the historical `CURLE_*` `#define`s in
    // `include/curl/curl.h` (the `!CURL_NO_OLDIES` block). Each maps to the
    // canonical variant that currently owns its integer value, so existing
    // callers that reference the old names keep resolving to the correct
    // frozen integer.
    // ---------------------------------------------------------------------

    /// `CURLE_SSL_CACERT` — folded into [`CurlCode::PeerFailedVerification`].
    pub const SSL_CACERT: CurlCode = CurlCode::PeerFailedVerification;
    /// `CURLE_SSL_PEER_CERTIFICATE` — folded into
    /// [`CurlCode::PeerFailedVerification`].
    pub const SSL_PEER_CERTIFICATE: CurlCode = CurlCode::PeerFailedVerification;
    /// `CURLE_FTP_WEIRD_SERVER_REPLY` — folded into
    /// [`CurlCode::WeirdServerReply`].
    pub const FTP_WEIRD_SERVER_REPLY: CurlCode = CurlCode::WeirdServerReply;
    /// `CURLE_FUNCTION_NOT_FOUND` — folded into [`CurlCode::Obsolete41`].
    pub const FUNCTION_NOT_FOUND: CurlCode = CurlCode::Obsolete41;
    /// `CURLE_HTTP_POST_ERROR` — folded into [`CurlCode::Obsolete34`].
    pub const HTTP_POST_ERROR: CurlCode = CurlCode::Obsolete34;
    /// `CURLE_OBSOLETE16` — folded into [`CurlCode::Http2`].
    pub const OBSOLETE16: CurlCode = CurlCode::Http2;
    /// `CURLE_OBSOLETE10` — folded into [`CurlCode::FtpAcceptFailed`].
    pub const OBSOLETE10: CurlCode = CurlCode::FtpAcceptFailed;
    /// `CURLE_OBSOLETE12` — folded into [`CurlCode::FtpAcceptTimeout`].
    pub const OBSOLETE12: CurlCode = CurlCode::FtpAcceptTimeout;
    /// `CURLE_UNKNOWN_TELNET_OPTION` — folded into [`CurlCode::UnknownOption`].
    pub const UNKNOWN_TELNET_OPTION: CurlCode = CurlCode::UnknownOption;
    /// `CURLE_TELNET_OPTION_SYNTAX` — folded into
    /// [`CurlCode::SetoptOptionSyntax`].
    pub const TELNET_OPTION_SYNTAX: CurlCode = CurlCode::SetoptOptionSyntax;
    /// `CURLE_OBSOLETE` — folded into [`CurlCode::Obsolete50`].
    pub const OBSOLETE: CurlCode = CurlCode::Obsolete50;
    /// `CURLE_BAD_PASSWORD_ENTERED` — folded into [`CurlCode::Obsolete46`].
    pub const BAD_PASSWORD_ENTERED: CurlCode = CurlCode::Obsolete46;
    /// `CURLE_BAD_CALLING_ORDER` — folded into [`CurlCode::Obsolete44`].
    pub const BAD_CALLING_ORDER: CurlCode = CurlCode::Obsolete44;
    /// `CURLE_FTP_USER_PASSWORD_INCORRECT` — folded into
    /// [`CurlCode::FtpAcceptFailed`] (integer 10).
    pub const FTP_USER_PASSWORD_INCORRECT: CurlCode = CurlCode::FtpAcceptFailed;
    /// `CURLE_FTP_CANT_RECONNECT` — folded into [`CurlCode::Http2`] (integer
    /// 16).
    pub const FTP_CANT_RECONNECT: CurlCode = CurlCode::Http2;
    /// `CURLE_FTP_COULDNT_GET_SIZE` — folded into [`CurlCode::Obsolete32`].
    pub const FTP_COULDNT_GET_SIZE: CurlCode = CurlCode::Obsolete32;
    /// `CURLE_FTP_COULDNT_SET_ASCII` — folded into [`CurlCode::Obsolete29`].
    pub const FTP_COULDNT_SET_ASCII: CurlCode = CurlCode::Obsolete29;
    /// `CURLE_FTP_WEIRD_USER_REPLY` — folded into
    /// [`CurlCode::FtpAcceptTimeout`] (integer 12).
    pub const FTP_WEIRD_USER_REPLY: CurlCode = CurlCode::FtpAcceptTimeout;
    /// `CURLE_FTP_WRITE_ERROR` — folded into [`CurlCode::Obsolete20`].
    pub const FTP_WRITE_ERROR: CurlCode = CurlCode::Obsolete20;
    /// `CURLE_LIBRARY_NOT_FOUND` — folded into [`CurlCode::Obsolete40`].
    pub const LIBRARY_NOT_FOUND: CurlCode = CurlCode::Obsolete40;
    /// `CURLE_MALFORMAT_USER` — folded into [`CurlCode::Obsolete24`].
    pub const MALFORMAT_USER: CurlCode = CurlCode::Obsolete24;
    /// `CURLE_SHARE_IN_USE` — folded into [`CurlCode::Obsolete57`].
    pub const SHARE_IN_USE: CurlCode = CurlCode::Obsolete57;
    /// `CURLE_URL_MALFORMAT_USER` — folded into [`CurlCode::NotBuiltIn`]
    /// (integer 4).
    pub const URL_MALFORMAT_USER: CurlCode = CurlCode::NotBuiltIn;
    /// `CURLE_FTP_ACCESS_DENIED` — folded into [`CurlCode::RemoteAccessDenied`].
    pub const FTP_ACCESS_DENIED: CurlCode = CurlCode::RemoteAccessDenied;
    /// `CURLE_FTP_COULDNT_SET_BINARY` — folded into
    /// [`CurlCode::FtpCouldntSetType`].
    pub const FTP_COULDNT_SET_BINARY: CurlCode = CurlCode::FtpCouldntSetType;
    /// `CURLE_FTP_QUOTE_ERROR` — folded into [`CurlCode::QuoteError`].
    pub const FTP_QUOTE_ERROR: CurlCode = CurlCode::QuoteError;
    /// `CURLE_TFTP_DISKFULL` — folded into [`CurlCode::RemoteDiskFull`].
    pub const TFTP_DISKFULL: CurlCode = CurlCode::RemoteDiskFull;
    /// `CURLE_TFTP_EXISTS` — folded into [`CurlCode::RemoteFileExists`].
    pub const TFTP_EXISTS: CurlCode = CurlCode::RemoteFileExists;
    /// `CURLE_HTTP_RANGE_ERROR` — folded into [`CurlCode::RangeError`].
    pub const HTTP_RANGE_ERROR: CurlCode = CurlCode::RangeError;
    /// `CURLE_FTP_SSL_FAILED` — folded into [`CurlCode::UseSslFailed`].
    pub const FTP_SSL_FAILED: CurlCode = CurlCode::UseSslFailed;
    /// `CURLE_OPERATION_TIMEOUTED` — folded into
    /// [`CurlCode::OperationTimedout`].
    pub const OPERATION_TIMEOUTED: CurlCode = CurlCode::OperationTimedout;
    /// `CURLE_HTTP_NOT_FOUND` — folded into [`CurlCode::HttpReturnedError`].
    pub const HTTP_NOT_FOUND: CurlCode = CurlCode::HttpReturnedError;
    /// `CURLE_HTTP_PORT_FAILED` — folded into [`CurlCode::InterfaceFailed`].
    pub const HTTP_PORT_FAILED: CurlCode = CurlCode::InterfaceFailed;
    /// `CURLE_FTP_COULDNT_STOR_FILE` — folded into [`CurlCode::UploadFailed`].
    pub const FTP_COULDNT_STOR_FILE: CurlCode = CurlCode::UploadFailed;
    /// `CURLE_FTP_PARTIAL_FILE` — folded into [`CurlCode::PartialFile`].
    pub const FTP_PARTIAL_FILE: CurlCode = CurlCode::PartialFile;
    /// `CURLE_FTP_BAD_DOWNLOAD_RESUME` — folded into
    /// [`CurlCode::BadDownloadResume`].
    pub const FTP_BAD_DOWNLOAD_RESUME: CurlCode = CurlCode::BadDownloadResume;
    /// `CURLE_LDAP_INVALID_URL` — folded into [`CurlCode::Obsolete62`].
    pub const LDAP_INVALID_URL: CurlCode = CurlCode::Obsolete62;
    /// `CURLE_CONV_REQD` — folded into [`CurlCode::Obsolete76`].
    pub const CONV_REQD: CurlCode = CurlCode::Obsolete76;
    /// `CURLE_CONV_FAILED` — folded into [`CurlCode::Obsolete75`].
    pub const CONV_FAILED: CurlCode = CurlCode::Obsolete75;

    /// `CURLE_ALREADY_COMPLETE` — historical error code `99999`. It is no
    /// longer produced by libcurl but is preserved here as a raw integer
    /// constant so that programs referencing it continue to compile. It does
    /// not correspond to any [`CurlCode`] variant.
    pub const ALREADY_COMPLETE: i32 = 99999;
}

impl From<CurlCode> for i32 {
    /// Converts the code to its frozen C `CURLcode` integer value.
    fn from(code: CurlCode) -> i32 {
        code as i32
    }
}

impl TryFrom<i32> for CurlCode {
    /// The rejected integer is returned unchanged on failure.
    type Error = i32;

    /// Converts a raw C `CURLcode` integer into a [`CurlCode`].
    ///
    /// Every value in `0..=101` maps to its canonical variant (including the
    /// reserved / obsolete slots). Any other integer is rejected and returned
    /// unchanged in the [`Err`] arm.
    fn try_from(value: i32) -> core::result::Result<CurlCode, i32> {
        let code = match value {
            0 => CurlCode::Ok,
            1 => CurlCode::UnsupportedProtocol,
            2 => CurlCode::FailedInit,
            3 => CurlCode::UrlMalformat,
            4 => CurlCode::NotBuiltIn,
            5 => CurlCode::CouldntResolveProxy,
            6 => CurlCode::CouldntResolveHost,
            7 => CurlCode::CouldntConnect,
            8 => CurlCode::WeirdServerReply,
            9 => CurlCode::RemoteAccessDenied,
            10 => CurlCode::FtpAcceptFailed,
            11 => CurlCode::FtpWeirdPassReply,
            12 => CurlCode::FtpAcceptTimeout,
            13 => CurlCode::FtpWeirdPasvReply,
            14 => CurlCode::FtpWeird227Format,
            15 => CurlCode::FtpCantGetHost,
            16 => CurlCode::Http2,
            17 => CurlCode::FtpCouldntSetType,
            18 => CurlCode::PartialFile,
            19 => CurlCode::FtpCouldntRetrFile,
            20 => CurlCode::Obsolete20,
            21 => CurlCode::QuoteError,
            22 => CurlCode::HttpReturnedError,
            23 => CurlCode::WriteError,
            24 => CurlCode::Obsolete24,
            25 => CurlCode::UploadFailed,
            26 => CurlCode::ReadError,
            27 => CurlCode::OutOfMemory,
            28 => CurlCode::OperationTimedout,
            29 => CurlCode::Obsolete29,
            30 => CurlCode::FtpPortFailed,
            31 => CurlCode::FtpCouldntUseRest,
            32 => CurlCode::Obsolete32,
            33 => CurlCode::RangeError,
            34 => CurlCode::Obsolete34,
            35 => CurlCode::SslConnectError,
            36 => CurlCode::BadDownloadResume,
            37 => CurlCode::FileCouldntReadFile,
            38 => CurlCode::LdapCannotBind,
            39 => CurlCode::LdapSearchFailed,
            40 => CurlCode::Obsolete40,
            41 => CurlCode::Obsolete41,
            42 => CurlCode::AbortedByCallback,
            43 => CurlCode::BadFunctionArgument,
            44 => CurlCode::Obsolete44,
            45 => CurlCode::InterfaceFailed,
            46 => CurlCode::Obsolete46,
            47 => CurlCode::TooManyRedirects,
            48 => CurlCode::UnknownOption,
            49 => CurlCode::SetoptOptionSyntax,
            50 => CurlCode::Obsolete50,
            51 => CurlCode::Obsolete51,
            52 => CurlCode::GotNothing,
            53 => CurlCode::SslEngineNotfound,
            54 => CurlCode::SslEngineSetfailed,
            55 => CurlCode::SendError,
            56 => CurlCode::RecvError,
            57 => CurlCode::Obsolete57,
            58 => CurlCode::SslCertproblem,
            59 => CurlCode::SslCipher,
            60 => CurlCode::PeerFailedVerification,
            61 => CurlCode::BadContentEncoding,
            62 => CurlCode::Obsolete62,
            63 => CurlCode::FilesizeExceeded,
            64 => CurlCode::UseSslFailed,
            65 => CurlCode::SendFailRewind,
            66 => CurlCode::SslEngineInitfailed,
            67 => CurlCode::LoginDenied,
            68 => CurlCode::TftpNotfound,
            69 => CurlCode::TftpPerm,
            70 => CurlCode::RemoteDiskFull,
            71 => CurlCode::TftpIllegal,
            72 => CurlCode::TftpUnknownid,
            73 => CurlCode::RemoteFileExists,
            74 => CurlCode::TftpNosuchuser,
            75 => CurlCode::Obsolete75,
            76 => CurlCode::Obsolete76,
            77 => CurlCode::SslCacertBadfile,
            78 => CurlCode::RemoteFileNotFound,
            79 => CurlCode::Ssh,
            80 => CurlCode::SslShutdownFailed,
            81 => CurlCode::Again,
            82 => CurlCode::SslCrlBadfile,
            83 => CurlCode::SslIssuerError,
            84 => CurlCode::FtpPretFailed,
            85 => CurlCode::RtspCseqError,
            86 => CurlCode::RtspSessionError,
            87 => CurlCode::FtpBadFileList,
            88 => CurlCode::ChunkFailed,
            89 => CurlCode::NoConnectionAvailable,
            90 => CurlCode::SslPinnedpubkeynotmatch,
            91 => CurlCode::SslInvalidcertstatus,
            92 => CurlCode::Http2Stream,
            93 => CurlCode::RecursiveApiCall,
            94 => CurlCode::AuthError,
            95 => CurlCode::Http3,
            96 => CurlCode::QuicConnectError,
            97 => CurlCode::Proxy,
            98 => CurlCode::SslClientcert,
            99 => CurlCode::UnrecoverablePoll,
            100 => CurlCode::TooLarge,
            101 => CurlCode::EchRequired,
            other => return Err(other),
        };
        Ok(code)
    }
}

/// Converts a raw C `CURLcode` integer into a [`CurlCode`], falling back to a
/// sensible default for unrecognized values.
///
/// Values in `0..=101` map to their canonical variant. Any other integer maps
/// to [`CurlCode::BadFunctionArgument`] (interpreting an unknown code as a bad
/// argument). Callers that need to distinguish unknown values should use the
/// fallible [`TryFrom`] implementation instead.
#[must_use]
pub fn from_i32(code: i32) -> CurlCode {
    match CurlCode::try_from(code) {
        Ok(known) => known,
        Err(_) => CurlCode::BadFunctionArgument,
    }
}

impl fmt::Display for CurlCode {
    /// Formats the code using its curl 8.x message string (see [`strerror`]).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(strerror(*self))
    }
}

/// Returns the exact curl 8.x human-readable message for a [`CurlCode`].
///
/// This reproduces `curl_easy_strerror` from `lib/strerror.c` verbatim
/// (the verbose form built by default in curl 8.x), so that stderr text stays
/// byte-for-byte stable for downstream log scrapers. The reserved / obsolete
/// slots and any value not carrying a dedicated message resolve to
/// `"Unknown error"`, exactly as the C implementation does via its `default`
/// switch arm.
#[must_use]
pub fn strerror(code: CurlCode) -> &'static str {
    match code {
        CurlCode::Ok => "No error",
        CurlCode::UnsupportedProtocol => "Unsupported protocol",
        CurlCode::FailedInit => "Failed initialization",
        CurlCode::UrlMalformat => "URL using bad/illegal format or missing URL",
        CurlCode::NotBuiltIn => {
            "A requested feature, protocol or option was not found built-in in \
             this libcurl due to a build-time decision."
        }
        CurlCode::CouldntResolveProxy => "Could not resolve proxy name",
        CurlCode::CouldntResolveHost => "Could not resolve hostname",
        CurlCode::CouldntConnect => "Could not connect to server",
        CurlCode::WeirdServerReply => "Weird server reply",
        CurlCode::RemoteAccessDenied => "Access denied to remote resource",
        CurlCode::FtpAcceptFailed => "FTP: The server failed to connect to data port",
        CurlCode::FtpWeirdPassReply => "FTP: unknown PASS reply",
        CurlCode::FtpAcceptTimeout => "FTP: Accepting server connect has timed out",
        CurlCode::FtpWeirdPasvReply => "FTP: unknown PASV reply",
        CurlCode::FtpWeird227Format => "FTP: unknown 227 response format",
        CurlCode::FtpCantGetHost => "FTP: cannot figure out the host in the PASV response",
        CurlCode::Http2 => "Error in the HTTP2 framing layer",
        CurlCode::FtpCouldntSetType => "FTP: could not set file type",
        CurlCode::PartialFile => "Transferred a partial file",
        CurlCode::FtpCouldntRetrFile => "FTP: could not retrieve (RETR failed) the specified file",
        CurlCode::QuoteError => "Quote command returned error",
        CurlCode::HttpReturnedError => "HTTP response code said error",
        CurlCode::WriteError => "Failed writing received data to disk/application",
        CurlCode::UploadFailed => "Upload failed (at start/before it took off)",
        CurlCode::ReadError => "Failed to open/read local data from file/application",
        CurlCode::OutOfMemory => "Out of memory",
        CurlCode::OperationTimedout => "Timeout was reached",
        CurlCode::FtpPortFailed => "FTP: command PORT failed",
        CurlCode::FtpCouldntUseRest => "FTP: command REST failed",
        CurlCode::RangeError => "Requested range was not delivered by the server",
        CurlCode::SslConnectError => "SSL connect error",
        CurlCode::BadDownloadResume => "Could not resume download",
        CurlCode::FileCouldntReadFile => "Could not read a file:// file",
        CurlCode::LdapCannotBind => "LDAP: cannot bind",
        CurlCode::LdapSearchFailed => "LDAP: search failed",
        CurlCode::AbortedByCallback => "Operation was aborted by an application callback",
        CurlCode::BadFunctionArgument => "A libcurl function was given a bad argument",
        CurlCode::InterfaceFailed => "Failed binding local connection end",
        CurlCode::TooManyRedirects => "Number of redirects hit maximum amount",
        CurlCode::UnknownOption => "An unknown option was passed in to libcurl",
        CurlCode::SetoptOptionSyntax => "Malformed option provided in a setopt",
        CurlCode::GotNothing => "Server returned nothing (no headers, no data)",
        CurlCode::SslEngineNotfound => "SSL crypto engine not found",
        CurlCode::SslEngineSetfailed => "Can not set SSL crypto engine as default",
        CurlCode::SendError => "Failed sending data to the peer",
        CurlCode::RecvError => "Failure when receiving data from the peer",
        CurlCode::SslCertproblem => "Problem with the local SSL certificate",
        CurlCode::SslCipher => "Could not use specified SSL cipher",
        CurlCode::PeerFailedVerification => "SSL peer certificate or SSH remote key was not OK",
        CurlCode::BadContentEncoding => "Unrecognized or bad HTTP Content or Transfer-Encoding",
        CurlCode::FilesizeExceeded => "Maximum file size exceeded",
        CurlCode::UseSslFailed => "Requested SSL level failed",
        CurlCode::SendFailRewind => "Send failed since rewinding of the data stream failed",
        CurlCode::SslEngineInitfailed => "Failed to initialise SSL crypto engine",
        CurlCode::LoginDenied => "Login denied",
        CurlCode::TftpNotfound => "TFTP: File Not Found",
        CurlCode::TftpPerm => "TFTP: Access Violation",
        CurlCode::RemoteDiskFull => "Disk full or allocation exceeded",
        CurlCode::TftpIllegal => "TFTP: Illegal operation",
        CurlCode::TftpUnknownid => "TFTP: Unknown transfer ID",
        CurlCode::RemoteFileExists => "Remote file already exists",
        CurlCode::TftpNosuchuser => "TFTP: No such user",
        CurlCode::SslCacertBadfile => "Problem with the SSL CA cert (path? access rights?)",
        CurlCode::RemoteFileNotFound => "Remote file not found",
        CurlCode::Ssh => "Error in the SSH layer",
        CurlCode::SslShutdownFailed => "Failed to shut down the SSL connection",
        CurlCode::Again => "Socket not ready for send/recv",
        CurlCode::SslCrlBadfile => "Failed to load CRL file (path? access rights?, format?)",
        CurlCode::SslIssuerError => "Issuer check against peer certificate failed",
        CurlCode::FtpPretFailed => "FTP: The server did not accept the PRET command.",
        CurlCode::RtspCseqError => "RTSP CSeq mismatch or invalid CSeq",
        CurlCode::RtspSessionError => "RTSP session error",
        CurlCode::FtpBadFileList => "Unable to parse FTP file list",
        CurlCode::ChunkFailed => "Chunk callback failed",
        CurlCode::NoConnectionAvailable => "The max connection limit is reached",
        CurlCode::SslPinnedpubkeynotmatch => "SSL public key does not match pinned public key",
        CurlCode::SslInvalidcertstatus => "SSL server certificate status verification FAILED",
        CurlCode::Http2Stream => "Stream error in the HTTP/2 framing layer",
        CurlCode::RecursiveApiCall => "API function called from within callback",
        CurlCode::AuthError => "An authentication function returned an error",
        CurlCode::Http3 => "HTTP/3 error",
        CurlCode::QuicConnectError => "QUIC connection error",
        CurlCode::Proxy => "proxy handshake error",
        CurlCode::SslClientcert => "SSL Client Certificate required",
        CurlCode::UnrecoverablePoll => "Unrecoverable error in select/poll",
        CurlCode::TooLarge => "A value or data field grew larger than allowed",
        CurlCode::EchRequired => "ECH attempted but failed",
        // Reserved / obsolete slots carry no dedicated message, matching the
        // `default` arm of the C `curl_easy_strerror` switch.
        CurlCode::Obsolete20
        | CurlCode::Obsolete24
        | CurlCode::Obsolete29
        | CurlCode::Obsolete32
        | CurlCode::Obsolete34
        | CurlCode::Obsolete40
        | CurlCode::Obsolete41
        | CurlCode::Obsolete44
        | CurlCode::Obsolete46
        | CurlCode::Obsolete50
        | CurlCode::Obsolete51
        | CurlCode::Obsolete57
        | CurlCode::Obsolete62
        | CurlCode::Obsolete75
        | CurlCode::Obsolete76 => "Unknown error",
    }
}

// =========================================================================
// CURLMcode — the multi-interface result code (`include/curl/multi.h`).
// =========================================================================

/// The libcurl "multi" interface result code, mirroring the C `CURLMcode`
/// enumeration in `include/curl/multi.h`.
///
/// As with [`CurlCode`], each discriminant is a frozen ABI integer. Note that
/// [`CurlMCode::CallMultiPerform`] is `-1`; the remaining values start at `0`.
/// The sentinel `CURLM_LAST` is intentionally not represented.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlMCode {
    /// `CURLM_CALL_MULTI_PERFORM` — the application should call
    /// `curl_multi_perform` (or `curl_multi_socket*`) soon. Also aliased as
    /// `CURLM_CALL_MULTI_SOCKET`.
    CallMultiPerform = -1,
    /// `CURLM_OK` — no error.
    Ok = 0,
    /// `CURLM_BAD_HANDLE` — the passed-in handle is not a valid multi handle.
    BadHandle = 1,
    /// `CURLM_BAD_EASY_HANDLE` — an easy handle was not valid.
    BadEasyHandle = 2,
    /// `CURLM_OUT_OF_MEMORY` — a memory allocation request failed.
    OutOfMemory = 3,
    /// `CURLM_INTERNAL_ERROR` — an internal libcurl error (a bug).
    InternalError = 4,
    /// `CURLM_BAD_SOCKET` — the passed-in socket argument did not match.
    BadSocket = 5,
    /// `CURLM_UNKNOWN_OPTION` — an unsupported option was passed to
    /// `curl_multi_setopt`.
    UnknownOption = 6,
    /// `CURLM_ADDED_ALREADY` — the easy handle is already added to a multi
    /// handle.
    AddedAlready = 7,
    /// `CURLM_RECURSIVE_API_CALL` — an API function was called from within a
    /// callback.
    RecursiveApiCall = 8,
    /// `CURLM_WAKEUP_FAILURE` — wakeup is unavailable or failed.
    WakeupFailure = 9,
    /// `CURLM_BAD_FUNCTION_ARGUMENT` — a function was called with a bad
    /// parameter.
    BadFunctionArgument = 10,
    /// `CURLM_ABORTED_BY_CALLBACK` — an application callback aborted the
    /// operation.
    AbortedByCallback = 11,
    /// `CURLM_UNRECOVERABLE_POLL` — `poll`/`select` returned a fatal error.
    UnrecoverablePoll = 12,
}

impl CurlMCode {
    /// `CURLM_CALL_MULTI_SOCKET` — historical alias of
    /// [`CurlMCode::CallMultiPerform`] (integer `-1`).
    pub const CALL_MULTI_SOCKET: CurlMCode = CurlMCode::CallMultiPerform;

    /// Returns the frozen integer value of this code as an [`i32`].
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        self as i32
    }

    /// Returns the exact curl 8.x message for this code (see
    /// [`multi_strerror`]).
    #[must_use]
    pub fn message(self) -> &'static str {
        multi_strerror(self)
    }
}

impl From<CurlMCode> for i32 {
    fn from(code: CurlMCode) -> i32 {
        code as i32
    }
}

impl TryFrom<i32> for CurlMCode {
    /// The rejected integer is returned unchanged on failure.
    type Error = i32;

    fn try_from(value: i32) -> core::result::Result<CurlMCode, i32> {
        let code = match value {
            -1 => CurlMCode::CallMultiPerform,
            0 => CurlMCode::Ok,
            1 => CurlMCode::BadHandle,
            2 => CurlMCode::BadEasyHandle,
            3 => CurlMCode::OutOfMemory,
            4 => CurlMCode::InternalError,
            5 => CurlMCode::BadSocket,
            6 => CurlMCode::UnknownOption,
            7 => CurlMCode::AddedAlready,
            8 => CurlMCode::RecursiveApiCall,
            9 => CurlMCode::WakeupFailure,
            10 => CurlMCode::BadFunctionArgument,
            11 => CurlMCode::AbortedByCallback,
            12 => CurlMCode::UnrecoverablePoll,
            other => return Err(other),
        };
        Ok(code)
    }
}

impl fmt::Display for CurlMCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(multi_strerror(*self))
    }
}

/// Returns the exact curl 8.x message for a [`CurlMCode`], reproducing
/// `curl_multi_strerror` from `lib/strerror.c` verbatim.
#[must_use]
pub fn multi_strerror(code: CurlMCode) -> &'static str {
    match code {
        CurlMCode::CallMultiPerform => "Please call curl_multi_perform() soon",
        CurlMCode::Ok => "No error",
        CurlMCode::BadHandle => "Invalid multi handle",
        CurlMCode::BadEasyHandle => "Invalid easy handle",
        CurlMCode::OutOfMemory => "Out of memory",
        CurlMCode::InternalError => "Internal error",
        CurlMCode::BadSocket => "Invalid socket argument",
        CurlMCode::UnknownOption => "Unknown option",
        CurlMCode::AddedAlready => "The easy handle is already added to a multi handle",
        CurlMCode::RecursiveApiCall => "API function called from within callback",
        CurlMCode::WakeupFailure => "Wakeup is unavailable or failed",
        CurlMCode::BadFunctionArgument => "A libcurl function was given a bad argument",
        CurlMCode::AbortedByCallback => "Operation was aborted by an application callback",
        CurlMCode::UnrecoverablePoll => "Unrecoverable error in select/poll",
    }
}

// =========================================================================
// CURLSHcode — the share-interface result code (`include/curl/curl.h`).
// =========================================================================

/// The libcurl "share" interface result code, mirroring the C `CURLSHcode`
/// enumeration in `include/curl/curl.h`. The sentinel `CURLSHE_LAST` is not
/// represented.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlShCode {
    /// `CURLSHE_OK` — no error.
    Ok = 0,
    /// `CURLSHE_BAD_OPTION` — an unknown share option.
    BadOption = 1,
    /// `CURLSHE_IN_USE` — the share is currently in use.
    InUse = 2,
    /// `CURLSHE_INVALID` — an invalid share handle.
    Invalid = 3,
    /// `CURLSHE_NOMEM` — a memory allocation request failed.
    Nomem = 4,
    /// `CURLSHE_NOT_BUILT_IN` — the feature is not enabled in this library.
    NotBuiltIn = 5,
}

impl CurlShCode {
    /// Returns the frozen integer value of this code as an [`i32`].
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        self as i32
    }

    /// Returns the exact curl 8.x message for this code (see
    /// [`share_strerror`]).
    #[must_use]
    pub fn message(self) -> &'static str {
        share_strerror(self)
    }
}

impl From<CurlShCode> for i32 {
    fn from(code: CurlShCode) -> i32 {
        code as i32
    }
}

impl TryFrom<i32> for CurlShCode {
    /// The rejected integer is returned unchanged on failure.
    type Error = i32;

    fn try_from(value: i32) -> core::result::Result<CurlShCode, i32> {
        let code = match value {
            0 => CurlShCode::Ok,
            1 => CurlShCode::BadOption,
            2 => CurlShCode::InUse,
            3 => CurlShCode::Invalid,
            4 => CurlShCode::Nomem,
            5 => CurlShCode::NotBuiltIn,
            other => return Err(other),
        };
        Ok(code)
    }
}

impl fmt::Display for CurlShCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(share_strerror(*self))
    }
}

/// Returns the exact curl 8.x message for a [`CurlShCode`], reproducing
/// `curl_share_strerror` from `lib/strerror.c` verbatim.
#[must_use]
pub fn share_strerror(code: CurlShCode) -> &'static str {
    match code {
        CurlShCode::Ok => "No error",
        CurlShCode::BadOption => "Unknown share option",
        CurlShCode::InUse => "Share currently in use",
        CurlShCode::Invalid => "Invalid share handle",
        CurlShCode::Nomem => "Out of memory",
        CurlShCode::NotBuiltIn => "Feature not enabled in this library",
    }
}

// =========================================================================
// CURLUcode — the URL-API result code (`include/curl/urlapi.h`).
// =========================================================================

/// The libcurl URL-API result code, mirroring the C `CURLUcode` enumeration in
/// `include/curl/urlapi.h`. The sentinel `CURLUE_LAST` is not represented.
///
/// Note that the C `curl_url_strerror` switch lists these out of numeric order;
/// [`url_strerror`] maps strictly by the frozen integer value below.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlUCode {
    /// `CURLUE_OK` — no error.
    Ok = 0,
    /// `CURLUE_BAD_HANDLE` — an invalid `CURLU` pointer was passed.
    BadHandle = 1,
    /// `CURLUE_BAD_PARTPOINTER` — an invalid `part` argument was passed.
    BadPartpointer = 2,
    /// `CURLUE_MALFORMED_INPUT` — malformed input to a URL function.
    MalformedInput = 3,
    /// `CURLUE_BAD_PORT_NUMBER` — the port was not a decimal `0..=65535`.
    BadPortNumber = 4,
    /// `CURLUE_UNSUPPORTED_SCHEME` — an unsupported URL scheme.
    UnsupportedScheme = 5,
    /// `CURLUE_URLDECODE` — a URL-decode error.
    Urldecode = 6,
    /// `CURLUE_OUT_OF_MEMORY` — a memory function failed.
    OutOfMemory = 7,
    /// `CURLUE_USER_NOT_ALLOWED` — credentials were passed when prohibited.
    UserNotAllowed = 8,
    /// `CURLUE_UNKNOWN_PART` — an unknown part ID was passed.
    UnknownPart = 9,
    /// `CURLUE_NO_SCHEME` — no scheme part in the URL.
    NoScheme = 10,
    /// `CURLUE_NO_USER` — no user part in the URL.
    NoUser = 11,
    /// `CURLUE_NO_PASSWORD` — no password part in the URL.
    NoPassword = 12,
    /// `CURLUE_NO_OPTIONS` — no options part in the URL.
    NoOptions = 13,
    /// `CURLUE_NO_HOST` — no host part in the URL.
    NoHost = 14,
    /// `CURLUE_NO_PORT` — no port part in the URL.
    NoPort = 15,
    /// `CURLUE_NO_QUERY` — no query part in the URL.
    NoQuery = 16,
    /// `CURLUE_NO_FRAGMENT` — no fragment part in the URL.
    NoFragment = 17,
    /// `CURLUE_NO_ZONEID` — no zoneid part in the URL.
    NoZoneid = 18,
    /// `CURLUE_BAD_FILE_URL` — a bad `file://` URL.
    BadFileUrl = 19,
    /// `CURLUE_BAD_FRAGMENT` — a bad fragment.
    BadFragment = 20,
    /// `CURLUE_BAD_HOSTNAME` — a bad hostname.
    BadHostname = 21,
    /// `CURLUE_BAD_IPV6` — a bad IPv6 address.
    BadIpv6 = 22,
    /// `CURLUE_BAD_LOGIN` — a bad login part.
    BadLogin = 23,
    /// `CURLUE_BAD_PASSWORD` — a bad password.
    BadPassword = 24,
    /// `CURLUE_BAD_PATH` — a bad path.
    BadPath = 25,
    /// `CURLUE_BAD_QUERY` — a bad query.
    BadQuery = 26,
    /// `CURLUE_BAD_SCHEME` — a bad scheme.
    BadScheme = 27,
    /// `CURLUE_BAD_SLASHES` — an unsupported number of slashes after the
    /// scheme.
    BadSlashes = 28,
    /// `CURLUE_BAD_USER` — a bad user.
    BadUser = 29,
    /// `CURLUE_LACKS_IDN` — libcurl lacks IDN support.
    LacksIdn = 30,
    /// `CURLUE_TOO_LARGE` — a value or data field is larger than allowed.
    TooLarge = 31,
}

impl CurlUCode {
    /// Returns the frozen integer value of this code as an [`i32`].
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        self as i32
    }

    /// Returns the exact curl 8.x message for this code (see [`url_strerror`]).
    #[must_use]
    pub fn message(self) -> &'static str {
        url_strerror(self)
    }
}

impl From<CurlUCode> for i32 {
    fn from(code: CurlUCode) -> i32 {
        code as i32
    }
}

impl TryFrom<i32> for CurlUCode {
    /// The rejected integer is returned unchanged on failure.
    type Error = i32;

    fn try_from(value: i32) -> core::result::Result<CurlUCode, i32> {
        let code = match value {
            0 => CurlUCode::Ok,
            1 => CurlUCode::BadHandle,
            2 => CurlUCode::BadPartpointer,
            3 => CurlUCode::MalformedInput,
            4 => CurlUCode::BadPortNumber,
            5 => CurlUCode::UnsupportedScheme,
            6 => CurlUCode::Urldecode,
            7 => CurlUCode::OutOfMemory,
            8 => CurlUCode::UserNotAllowed,
            9 => CurlUCode::UnknownPart,
            10 => CurlUCode::NoScheme,
            11 => CurlUCode::NoUser,
            12 => CurlUCode::NoPassword,
            13 => CurlUCode::NoOptions,
            14 => CurlUCode::NoHost,
            15 => CurlUCode::NoPort,
            16 => CurlUCode::NoQuery,
            17 => CurlUCode::NoFragment,
            18 => CurlUCode::NoZoneid,
            19 => CurlUCode::BadFileUrl,
            20 => CurlUCode::BadFragment,
            21 => CurlUCode::BadHostname,
            22 => CurlUCode::BadIpv6,
            23 => CurlUCode::BadLogin,
            24 => CurlUCode::BadPassword,
            25 => CurlUCode::BadPath,
            26 => CurlUCode::BadQuery,
            27 => CurlUCode::BadScheme,
            28 => CurlUCode::BadSlashes,
            29 => CurlUCode::BadUser,
            30 => CurlUCode::LacksIdn,
            31 => CurlUCode::TooLarge,
            other => return Err(other),
        };
        Ok(code)
    }
}

impl fmt::Display for CurlUCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(url_strerror(*self))
    }
}

/// Returns the exact curl 8.x message for a [`CurlUCode`], reproducing
/// `curl_url_strerror` from `lib/strerror.c` verbatim.
#[must_use]
pub fn url_strerror(code: CurlUCode) -> &'static str {
    match code {
        CurlUCode::Ok => "No error",
        CurlUCode::BadHandle => "An invalid CURLU pointer was passed as argument",
        CurlUCode::BadPartpointer => "An invalid 'part' argument was passed as argument",
        CurlUCode::MalformedInput => "Malformed input to a URL function",
        CurlUCode::BadPortNumber => "Port number was not a decimal number between 0 and 65535",
        CurlUCode::UnsupportedScheme => "Unsupported URL scheme",
        CurlUCode::Urldecode => "URL decode error, most likely because of rubbish in the input",
        CurlUCode::OutOfMemory => "A memory function failed",
        CurlUCode::UserNotAllowed => "Credentials was passed in the URL when prohibited",
        CurlUCode::UnknownPart => "An unknown part ID was passed to a URL API function",
        CurlUCode::NoScheme => "No scheme part in the URL",
        CurlUCode::NoUser => "No user part in the URL",
        CurlUCode::NoPassword => "No password part in the URL",
        CurlUCode::NoOptions => "No options part in the URL",
        CurlUCode::NoHost => "No host part in the URL",
        CurlUCode::NoPort => "No port part in the URL",
        CurlUCode::NoQuery => "No query part in the URL",
        CurlUCode::NoFragment => "No fragment part in the URL",
        CurlUCode::NoZoneid => "No zoneid part in the URL",
        CurlUCode::BadFileUrl => "Bad file:// URL",
        CurlUCode::BadFragment => "Bad fragment",
        CurlUCode::BadHostname => "Bad hostname",
        CurlUCode::BadIpv6 => "Bad IPv6 address",
        CurlUCode::BadLogin => "Bad login part",
        CurlUCode::BadPassword => "Bad password",
        CurlUCode::BadPath => "Bad path",
        CurlUCode::BadQuery => "Bad query",
        CurlUCode::BadScheme => "Bad scheme",
        CurlUCode::BadSlashes => "Unsupported number of slashes following scheme",
        CurlUCode::BadUser => "Bad user",
        CurlUCode::LacksIdn => "libcurl lacks IDN support",
        CurlUCode::TooLarge => "A value or data field is larger than allowed",
    }
}

// =========================================================================
// Error — the idiomatic, rich error type used throughout `curl-rs-lib`.
// =========================================================================

/// The idiomatic error type returned throughout `curl-rs-lib`.
///
/// Every variant maps deterministically to a [`CurlCode`] via [`Error::code`],
/// which is the single source of truth the `curl-rs-ffi` crate converts into
/// the frozen C `CURLcode` integer. Variants carry rich Rust context (an
/// underlying [`std::io::Error`], a descriptive [`String`], an HTTP status,
/// etc.) while their [`Display`](fmt::Display) output stays aligned with the
/// curl 8.x [`strerror`] strings so that stderr text remains stable.
///
/// Two general-purpose variants act as escape hatches: [`Error::Code`] wraps an
/// arbitrary [`CurlCode`] with no extra context, and [`Error::WithContext`]
/// pairs an arbitrary [`CurlCode`] with a custom human-readable message.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// An underlying I/O error. The mapped [`CurlCode`] is derived from the
    /// [`std::io::ErrorKind`]; see [`Error::code`].
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// The operation timed out (`CURLE_OPERATION_TIMEDOUT`).
    #[error("Timeout was reached")]
    Timeout,

    /// The maximum number of redirects was hit (`CURLE_TOO_MANY_REDIRECTS`).
    #[error("Number of redirects hit maximum amount")]
    TooManyRedirects,

    /// A host name could not be resolved (`CURLE_COULDNT_RESOLVE_HOST`). The
    /// payload records the host that failed to resolve.
    #[error("Could not resolve hostname")]
    Resolve(String),

    /// A proxy name could not be resolved (`CURLE_COULDNT_RESOLVE_PROXY`).
    #[error("Could not resolve proxy name")]
    ResolveProxy(String),

    /// A connection attempt failed (`CURLE_COULDNT_CONNECT`).
    #[error("Could not connect to server")]
    Connect(String),

    /// A TLS handshake or setup error (`CURLE_SSL_CONNECT_ERROR`).
    #[error("SSL connect error")]
    Tls(String),

    /// Certificate/key verification failed (`CURLE_PEER_FAILED_VERIFICATION`).
    #[error("SSL peer certificate or SSH remote key was not OK")]
    PeerFailedVerification(String),

    /// An authentication mechanism failed (`CURLE_AUTH_ERROR`).
    #[error("An authentication function returned an error")]
    Auth(String),

    /// A problem in the HTTP/2 framing layer (`CURLE_HTTP2`).
    #[error("Error in the HTTP2 framing layer")]
    Http2(String),

    /// A stream error in the HTTP/2 framing layer (`CURLE_HTTP2_STREAM`).
    #[error("Stream error in the HTTP/2 framing layer")]
    Http2Stream(String),

    /// A problem in the HTTP/3 layer (`CURLE_HTTP3`).
    #[error("HTTP/3 error")]
    Http3(String),

    /// A QUIC connection error (`CURLE_QUIC_CONNECT_ERROR`).
    #[error("QUIC connection error")]
    QuicConnect(String),

    /// An error from the SSH layer (`CURLE_SSH`).
    #[error("Error in the SSH layer")]
    Ssh(String),

    /// A proxy handshake error (`CURLE_PROXY`).
    #[error("proxy handshake error")]
    Proxy(String),

    /// The URL was malformed or missing (`CURLE_URL_MALFORMAT`).
    #[error("URL using bad/illegal format or missing URL")]
    Url(String),

    /// The requested protocol is not supported (`CURLE_UNSUPPORTED_PROTOCOL`).
    #[error("Unsupported protocol")]
    UnsupportedProtocol,

    /// Writing received data to the sink failed (`CURLE_WRITE_ERROR`).
    #[error("Failed writing received data to disk/application")]
    Write,

    /// Reading local data to upload failed (`CURLE_READ_ERROR`).
    #[error("Failed to open/read local data from file/application")]
    Read,

    /// Sending network data failed (`CURLE_SEND_ERROR`).
    #[error("Failed sending data to the peer")]
    Send,

    /// Receiving network data failed (`CURLE_RECV_ERROR`).
    #[error("Failure when receiving data from the peer")]
    Recv,

    /// Only a partial file was transferred (`CURLE_PARTIAL_FILE`).
    #[error("Transferred a partial file")]
    PartialFile,

    /// The server returned nothing (`CURLE_GOT_NOTHING`).
    #[error("Server returned nothing (no headers, no data)")]
    GotNothing,

    /// A memory allocation request failed (`CURLE_OUT_OF_MEMORY`).
    #[error("Out of memory")]
    OutOfMemory,

    /// An application callback aborted the transfer (`CURLE_ABORTED_BY_CALLBACK`).
    #[error("Operation was aborted by an application callback")]
    AbortedByCallback,

    /// A function received a bad argument (`CURLE_BAD_FUNCTION_ARGUMENT`).
    #[error("A libcurl function was given a bad argument")]
    BadFunctionArgument(String),

    /// The requested range was not delivered (`CURLE_RANGE_ERROR`).
    #[error("Requested range was not delivered by the server")]
    RangeError,

    /// An unrecognized or bad content encoding (`CURLE_BAD_CONTENT_ENCODING`).
    #[error("Unrecognized or bad HTTP Content or Transfer-Encoding")]
    BadContentEncoding(String),

    /// The maximum file size was exceeded (`CURLE_FILESIZE_EXCEEDED`).
    #[error("Maximum file size exceeded")]
    FilesizeExceeded,

    /// The credentials were rejected (`CURLE_LOGIN_DENIED`).
    #[error("Login denied")]
    LoginDenied,

    /// A value or data field met its maximum (`CURLE_TOO_LARGE`).
    #[error("A value or data field grew larger than allowed")]
    TooLarge,

    /// The socket is not ready; retry later (`CURLE_AGAIN`).
    #[error("Socket not ready for send/recv")]
    Again,

    /// An API function was called from within a callback
    /// (`CURLE_RECURSIVE_API_CALL`).
    #[error("API function called from within callback")]
    RecursiveApiCall,

    /// A chunk callback reported an error (`CURLE_CHUNK_FAILED`).
    #[error("Chunk callback failed")]
    ChunkFailed,

    /// The HTTP response code indicated an error (`CURLE_HTTP_RETURNED_ERROR`).
    /// The payload records the offending HTTP status code.
    #[error("HTTP response code said error")]
    HttpReturnedError(u32),

    /// An arbitrary [`CurlCode`] carried with no additional context. Its
    /// [`Display`](fmt::Display) output is the code's [`strerror`] string.
    #[error("{0}")]
    Code(CurlCode),

    /// An arbitrary [`CurlCode`] paired with a custom human-readable message.
    /// Unlike the other variants, its [`Display`](fmt::Display) output is the
    /// supplied `message` (analogous to curl's contextual `failf` text), while
    /// [`Error::code`] still reports the associated frozen code.
    #[error("{message}")]
    WithContext {
        /// The frozen [`CurlCode`] this error maps to.
        code: CurlCode,
        /// The custom, human-readable detail message.
        message: String,
    },
}

/// Maps a [`std::io::Error`] to the closest curl [`CurlCode`].
///
/// Only the unambiguous [`std::io::ErrorKind`] values are classified. Generic
/// or unclassified I/O errors fall back to [`CurlCode::ReadError`]; call sites
/// that know the transfer direction should construct a more specific variant
/// (for example [`Error::Send`], [`Error::Recv`], or [`Error::Connect`])
/// instead of relying on this fallback.
fn io_error_code(err: &std::io::Error) -> CurlCode {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::TimedOut => CurlCode::OperationTimedout,
        ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::NotConnected
        | ErrorKind::AddrInUse
        | ErrorKind::AddrNotAvailable => CurlCode::CouldntConnect,
        ErrorKind::BrokenPipe | ErrorKind::WriteZero => CurlCode::SendError,
        ErrorKind::UnexpectedEof => CurlCode::GotNothing,
        ErrorKind::OutOfMemory => CurlCode::OutOfMemory,
        ErrorKind::Interrupted | ErrorKind::WouldBlock => CurlCode::Again,
        // `ErrorKind` is `#[non_exhaustive]`; unclassified kinds default to a
        // local read error, as documented above.
        _ => CurlCode::ReadError,
    }
}

impl Error {
    /// Returns the canonical [`CurlCode`] for this error.
    ///
    /// This is the single mapping the FFI layer relies on to produce the frozen
    /// C `CURLcode` integer, so it is exhaustive and deterministic.
    #[must_use]
    pub fn code(&self) -> CurlCode {
        match self {
            Error::Io(err) => io_error_code(err),
            Error::Timeout => CurlCode::OperationTimedout,
            Error::TooManyRedirects => CurlCode::TooManyRedirects,
            Error::Resolve(_) => CurlCode::CouldntResolveHost,
            Error::ResolveProxy(_) => CurlCode::CouldntResolveProxy,
            Error::Connect(_) => CurlCode::CouldntConnect,
            Error::Tls(_) => CurlCode::SslConnectError,
            Error::PeerFailedVerification(_) => CurlCode::PeerFailedVerification,
            Error::Auth(_) => CurlCode::AuthError,
            Error::Http2(_) => CurlCode::Http2,
            Error::Http2Stream(_) => CurlCode::Http2Stream,
            Error::Http3(_) => CurlCode::Http3,
            Error::QuicConnect(_) => CurlCode::QuicConnectError,
            Error::Ssh(_) => CurlCode::Ssh,
            Error::Proxy(_) => CurlCode::Proxy,
            Error::Url(_) => CurlCode::UrlMalformat,
            Error::UnsupportedProtocol => CurlCode::UnsupportedProtocol,
            Error::Write => CurlCode::WriteError,
            Error::Read => CurlCode::ReadError,
            Error::Send => CurlCode::SendError,
            Error::Recv => CurlCode::RecvError,
            Error::PartialFile => CurlCode::PartialFile,
            Error::GotNothing => CurlCode::GotNothing,
            Error::OutOfMemory => CurlCode::OutOfMemory,
            Error::AbortedByCallback => CurlCode::AbortedByCallback,
            Error::BadFunctionArgument(_) => CurlCode::BadFunctionArgument,
            Error::RangeError => CurlCode::RangeError,
            Error::BadContentEncoding(_) => CurlCode::BadContentEncoding,
            Error::FilesizeExceeded => CurlCode::FilesizeExceeded,
            Error::LoginDenied => CurlCode::LoginDenied,
            Error::TooLarge => CurlCode::TooLarge,
            Error::Again => CurlCode::Again,
            Error::RecursiveApiCall => CurlCode::RecursiveApiCall,
            Error::ChunkFailed => CurlCode::ChunkFailed,
            Error::HttpReturnedError(_) => CurlCode::HttpReturnedError,
            Error::Code(code) => *code,
            Error::WithContext { code, .. } => *code,
        }
    }

    /// Returns the frozen C `CURLcode` integer for this error, equivalent to
    /// `self.code() as i32`.
    #[must_use]
    pub fn code_i32(&self) -> i32 {
        self.code() as i32
    }

    /// Returns the canonical curl 8.x [`strerror`] message for this error's
    /// [`code`](Error::code).
    ///
    /// Note that this may differ from the [`Display`](fmt::Display) output of
    /// context-bearing variants such as [`Error::WithContext`], which surface
    /// their custom message instead.
    #[must_use]
    pub fn message(&self) -> &'static str {
        strerror(self.code())
    }

    /// Returns the custom, human-readable context message this error carries, if
    /// any — the analogue of the string curl's `failf()` writes into
    /// `CURLOPT_ERRORBUFFER`.
    ///
    /// Only [`Error::WithContext`] carries such a message; every other variant
    /// returns `None`, so a caller (e.g. the CLI's `curl: (code) <msg>` printer)
    /// can reproduce curl's "error buffer first, else `strerror`" behavior: use
    /// this message when present, otherwise fall back to [`message`](Error::message).
    /// This is what surfaces, for example, the `.onion` rejection text
    /// "Not resolving .onion address (RFC 7686)" instead of the generic
    /// `CURLE_COULDNT_RESOLVE_HOST` strerror (§0.7.1 observability parity).
    #[must_use]
    pub fn context_message(&self) -> Option<&str> {
        match self {
            Error::WithContext { message, .. } => Some(message.as_str()),
            _ => None,
        }
    }

    /// Constructs a host-resolution error ([`Error::Resolve`]).
    pub fn resolve(host: impl Into<String>) -> Self {
        Error::Resolve(host.into())
    }

    /// Constructs a proxy-resolution error ([`Error::ResolveProxy`]).
    pub fn resolve_proxy(proxy: impl Into<String>) -> Self {
        Error::ResolveProxy(proxy.into())
    }

    /// Constructs a connection error ([`Error::Connect`]).
    pub fn connect(detail: impl Into<String>) -> Self {
        Error::Connect(detail.into())
    }

    /// Constructs a TLS error ([`Error::Tls`]).
    pub fn tls(detail: impl Into<String>) -> Self {
        Error::Tls(detail.into())
    }

    /// Constructs a peer-verification error ([`Error::PeerFailedVerification`]).
    pub fn peer_failed_verification(detail: impl Into<String>) -> Self {
        Error::PeerFailedVerification(detail.into())
    }

    /// Constructs an authentication error ([`Error::Auth`]).
    pub fn auth(detail: impl Into<String>) -> Self {
        Error::Auth(detail.into())
    }

    /// Constructs an HTTP/2 framing error ([`Error::Http2`]).
    pub fn http2(detail: impl Into<String>) -> Self {
        Error::Http2(detail.into())
    }

    /// Constructs an HTTP/2 stream error ([`Error::Http2Stream`]).
    pub fn http2_stream(detail: impl Into<String>) -> Self {
        Error::Http2Stream(detail.into())
    }

    /// Constructs an HTTP/3 error ([`Error::Http3`]).
    pub fn http3(detail: impl Into<String>) -> Self {
        Error::Http3(detail.into())
    }

    /// Constructs a QUIC connection error ([`Error::QuicConnect`]).
    pub fn quic_connect(detail: impl Into<String>) -> Self {
        Error::QuicConnect(detail.into())
    }

    /// Constructs an SSH-layer error ([`Error::Ssh`]).
    pub fn ssh(detail: impl Into<String>) -> Self {
        Error::Ssh(detail.into())
    }

    /// Constructs a proxy handshake error ([`Error::Proxy`]).
    pub fn proxy(detail: impl Into<String>) -> Self {
        Error::Proxy(detail.into())
    }

    /// Constructs a malformed-URL error ([`Error::Url`]).
    pub fn url(detail: impl Into<String>) -> Self {
        Error::Url(detail.into())
    }

    /// Constructs a bad-content-encoding error ([`Error::BadContentEncoding`]).
    pub fn bad_content_encoding(detail: impl Into<String>) -> Self {
        Error::BadContentEncoding(detail.into())
    }

    /// Constructs a bad-argument error ([`Error::BadFunctionArgument`]).
    pub fn bad_argument(detail: impl Into<String>) -> Self {
        Error::BadFunctionArgument(detail.into())
    }

    /// Constructs an [`Error::WithContext`] pairing an arbitrary [`CurlCode`]
    /// with a custom message.
    pub fn with_context(code: CurlCode, message: impl Into<String>) -> Self {
        Error::WithContext {
            code,
            message: message.into(),
        }
    }
}

impl From<CurlCode> for Error {
    /// Wraps any [`CurlCode`] as an [`Error::Code`] with no extra context.
    fn from(code: CurlCode) -> Error {
        Error::Code(code)
    }
}

/// The crate-wide result type: `Result<T, Error>`.
///
/// Every fallible operation in `curl-rs-lib` returns this alias.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // CurlCode: frozen integer contract
    // ---------------------------------------------------------------------

    #[test]
    fn curl_code_anchor_values() {
        // Spot-check the anchors called out by the specification.
        assert_eq!(CurlCode::Ok as i32, 0);
        assert_eq!(CurlCode::UnsupportedProtocol as i32, 1);
        assert_eq!(CurlCode::CouldntResolveProxy as i32, 5);
        assert_eq!(CurlCode::CouldntResolveHost as i32, 6);
        assert_eq!(CurlCode::CouldntConnect as i32, 7);
        assert_eq!(CurlCode::OperationTimedout as i32, 28);
        assert_eq!(CurlCode::PeerFailedVerification as i32, 60);
        assert_eq!(CurlCode::Http2Stream as i32, 92);
        assert_eq!(CurlCode::TooLarge as i32, 100);
        assert_eq!(CurlCode::EchRequired as i32, 101);
        // Obsolete slots must keep their reserved integers.
        assert_eq!(CurlCode::Obsolete20 as i32, 20);
        assert_eq!(CurlCode::Obsolete24 as i32, 24);
        assert_eq!(CurlCode::Obsolete57 as i32, 57);
        assert_eq!(CurlCode::Obsolete76 as i32, 76);
    }

    #[test]
    fn curl_code_full_roundtrip_0_to_101() {
        // Every integer 0..=101 must map to a variant whose discriminant is
        // exactly that integer, and `from_i32` must agree.
        for value in 0..=101_i32 {
            let code =
                CurlCode::try_from(value).expect("every value in 0..=101 must be a valid CurlCode");
            assert_eq!(code as i32, value, "discriminant drift at {value}");
            assert_eq!(i32::from(code), value);
            assert_eq!(code.to_i32(), value);
            assert_eq!(from_i32(value), code);
        }
    }

    #[test]
    fn curl_code_tryfrom_rejects_out_of_range() {
        assert_eq!(CurlCode::try_from(-1), Err(-1));
        assert_eq!(CurlCode::try_from(102), Err(102));
        assert_eq!(CurlCode::try_from(99999), Err(99999));
    }

    #[test]
    fn curl_code_from_i32_defaults_unknown_to_bad_argument() {
        assert_eq!(from_i32(28), CurlCode::OperationTimedout);
        assert_eq!(from_i32(0), CurlCode::Ok);
        assert_eq!(from_i32(101), CurlCode::EchRequired);
        // Unknown / out-of-range integers fall back to BadFunctionArgument.
        assert_eq!(from_i32(-5), CurlCode::BadFunctionArgument);
        assert_eq!(from_i32(1_000), CurlCode::BadFunctionArgument);
    }

    #[test]
    fn curl_code_into_i32() {
        let value: i32 = CurlCode::OperationTimedout.into();
        assert_eq!(value, 28);
        assert_eq!(i32::from(CurlCode::EchRequired), 101);
    }

    // ---------------------------------------------------------------------
    // CurlCode: strerror parity (verbatim curl 8.x strings)
    // ---------------------------------------------------------------------

    #[test]
    fn curl_code_strerror_parity() {
        assert_eq!(strerror(CurlCode::Ok), "No error");
        assert_eq!(strerror(CurlCode::OperationTimedout), "Timeout was reached");
        assert_eq!(
            strerror(CurlCode::CouldntConnect),
            "Could not connect to server"
        );
        assert_eq!(
            strerror(CurlCode::CouldntResolveHost),
            "Could not resolve hostname"
        );
        assert_eq!(
            strerror(CurlCode::PeerFailedVerification),
            "SSL peer certificate or SSH remote key was not OK"
        );
        assert_eq!(
            strerror(CurlCode::UnsupportedProtocol),
            "Unsupported protocol"
        );
        assert_eq!(strerror(CurlCode::EchRequired), "ECH attempted but failed");
        assert_eq!(
            strerror(CurlCode::NotBuiltIn),
            "A requested feature, protocol or option was not found built-in in \
             this libcurl due to a build-time decision."
        );
    }

    #[test]
    fn curl_code_strerror_obsolete_is_unknown() {
        // All reserved / obsolete slots resolve to "Unknown error", exactly as
        // the C `default` switch arm does.
        for code in [
            CurlCode::Obsolete20,
            CurlCode::Obsolete24,
            CurlCode::Obsolete29,
            CurlCode::Obsolete32,
            CurlCode::Obsolete34,
            CurlCode::Obsolete40,
            CurlCode::Obsolete41,
            CurlCode::Obsolete44,
            CurlCode::Obsolete46,
            CurlCode::Obsolete50,
            CurlCode::Obsolete51,
            CurlCode::Obsolete57,
            CurlCode::Obsolete62,
            CurlCode::Obsolete75,
            CurlCode::Obsolete76,
        ] {
            assert_eq!(strerror(code), "Unknown error");
        }
    }

    #[test]
    fn curl_code_display_uses_strerror() {
        assert_eq!(
            CurlCode::OperationTimedout.to_string(),
            "Timeout was reached"
        );
        assert_eq!(CurlCode::OperationTimedout.message(), "Timeout was reached");
    }

    // ---------------------------------------------------------------------
    // CurlCode: deprecated aliases resolve to the same frozen integer
    // ---------------------------------------------------------------------

    #[test]
    fn curl_code_alias_equivalence() {
        assert_eq!(CurlCode::SSL_CACERT, CurlCode::PeerFailedVerification);
        assert_eq!(CurlCode::SSL_CACERT as i32, 60);
        assert_eq!(
            CurlCode::SSL_PEER_CERTIFICATE,
            CurlCode::PeerFailedVerification
        );
        assert_eq!(CurlCode::FTP_WEIRD_SERVER_REPLY, CurlCode::WeirdServerReply);
        assert_eq!(CurlCode::FTP_WEIRD_SERVER_REPLY as i32, 8);
        assert_eq!(CurlCode::FUNCTION_NOT_FOUND, CurlCode::Obsolete41);
        assert_eq!(CurlCode::FUNCTION_NOT_FOUND as i32, 41);
        assert_eq!(CurlCode::HTTP_POST_ERROR, CurlCode::Obsolete34);
        assert_eq!(CurlCode::OBSOLETE16, CurlCode::Http2);
        assert_eq!(CurlCode::OBSOLETE16 as i32, 16);
        assert_eq!(CurlCode::UNKNOWN_TELNET_OPTION, CurlCode::UnknownOption);
        assert_eq!(CurlCode::TELNET_OPTION_SYNTAX, CurlCode::SetoptOptionSyntax);
        assert_eq!(CurlCode::BAD_PASSWORD_ENTERED, CurlCode::Obsolete46);
        assert_eq!(CurlCode::BAD_CALLING_ORDER, CurlCode::Obsolete44);
        assert_eq!(CurlCode::FTP_USER_PASSWORD_INCORRECT as i32, 10);
        assert_eq!(CurlCode::FTP_CANT_RECONNECT as i32, 16);
        assert_eq!(CurlCode::FTP_WEIRD_USER_REPLY as i32, 12);
        assert_eq!(CurlCode::URL_MALFORMAT_USER, CurlCode::NotBuiltIn);
        assert_eq!(CurlCode::URL_MALFORMAT_USER as i32, 4);
        assert_eq!(CurlCode::FTP_ACCESS_DENIED, CurlCode::RemoteAccessDenied);
        assert_eq!(CurlCode::HTTP_RANGE_ERROR, CurlCode::RangeError);
        assert_eq!(CurlCode::OPERATION_TIMEOUTED, CurlCode::OperationTimedout);
        assert_eq!(CurlCode::HTTP_NOT_FOUND, CurlCode::HttpReturnedError);
        assert_eq!(CurlCode::CONV_REQD, CurlCode::Obsolete76);
        assert_eq!(CurlCode::CONV_FAILED, CurlCode::Obsolete75);
        assert_eq!(CurlCode::LDAP_INVALID_URL, CurlCode::Obsolete62);
        // Historical standalone integer constant.
        assert_eq!(CurlCode::ALREADY_COMPLETE, 99999);
    }

    // ---------------------------------------------------------------------
    // Error: variant -> code mapping and Display behavior
    // ---------------------------------------------------------------------

    #[test]
    fn error_code_mapping() {
        assert_eq!(Error::Timeout.code(), CurlCode::OperationTimedout);
        assert_eq!(Error::TooManyRedirects.code(), CurlCode::TooManyRedirects);
        assert_eq!(Error::resolve("host").code(), CurlCode::CouldntResolveHost);
        assert_eq!(
            Error::resolve_proxy("p").code(),
            CurlCode::CouldntResolveProxy
        );
        assert_eq!(Error::connect("x").code(), CurlCode::CouldntConnect);
        assert_eq!(Error::tls("x").code(), CurlCode::SslConnectError);
        assert_eq!(
            Error::peer_failed_verification("x").code(),
            CurlCode::PeerFailedVerification
        );
        assert_eq!(Error::auth("x").code(), CurlCode::AuthError);
        assert_eq!(Error::http2("x").code(), CurlCode::Http2);
        assert_eq!(Error::http2_stream("x").code(), CurlCode::Http2Stream);
        assert_eq!(Error::http3("x").code(), CurlCode::Http3);
        assert_eq!(Error::quic_connect("x").code(), CurlCode::QuicConnectError);
        assert_eq!(Error::ssh("x").code(), CurlCode::Ssh);
        assert_eq!(Error::proxy("x").code(), CurlCode::Proxy);
        assert_eq!(Error::url("x").code(), CurlCode::UrlMalformat);
        assert_eq!(
            Error::UnsupportedProtocol.code(),
            CurlCode::UnsupportedProtocol
        );
        assert_eq!(Error::Write.code(), CurlCode::WriteError);
        assert_eq!(Error::Read.code(), CurlCode::ReadError);
        assert_eq!(Error::Send.code(), CurlCode::SendError);
        assert_eq!(Error::Recv.code(), CurlCode::RecvError);
        assert_eq!(Error::PartialFile.code(), CurlCode::PartialFile);
        assert_eq!(Error::GotNothing.code(), CurlCode::GotNothing);
        assert_eq!(Error::OutOfMemory.code(), CurlCode::OutOfMemory);
        assert_eq!(Error::AbortedByCallback.code(), CurlCode::AbortedByCallback);
        assert_eq!(
            Error::bad_argument("x").code(),
            CurlCode::BadFunctionArgument
        );
        assert_eq!(Error::RangeError.code(), CurlCode::RangeError);
        assert_eq!(
            Error::bad_content_encoding("x").code(),
            CurlCode::BadContentEncoding
        );
        assert_eq!(Error::FilesizeExceeded.code(), CurlCode::FilesizeExceeded);
        assert_eq!(Error::LoginDenied.code(), CurlCode::LoginDenied);
        assert_eq!(Error::TooLarge.code(), CurlCode::TooLarge);
        assert_eq!(Error::Again.code(), CurlCode::Again);
        assert_eq!(Error::RecursiveApiCall.code(), CurlCode::RecursiveApiCall);
        assert_eq!(Error::ChunkFailed.code(), CurlCode::ChunkFailed);
        assert_eq!(
            Error::HttpReturnedError(404).code(),
            CurlCode::HttpReturnedError
        );
    }

    #[test]
    fn error_general_variants() {
        assert_eq!(Error::Code(CurlCode::TooLarge).code(), CurlCode::TooLarge);
        assert_eq!(
            Error::with_context(CurlCode::Ssh, "boom").code(),
            CurlCode::Ssh
        );
        // From<CurlCode> for Error goes through the Code escape hatch.
        assert_eq!(Error::from(CurlCode::AuthError).code(), CurlCode::AuthError);
    }

    #[test]
    fn error_code_i32_and_message() {
        assert_eq!(Error::Timeout.code_i32(), 28);
        assert_eq!(Error::Timeout.message(), "Timeout was reached");
        assert_eq!(Error::HttpReturnedError(404).code_i32(), 22);
    }

    #[test]
    fn error_display_parity() {
        // Fixed-message variants mirror the curl strerror strings exactly.
        assert_eq!(Error::Timeout.to_string(), "Timeout was reached");
        assert_eq!(
            Error::resolve("example.com").to_string(),
            "Could not resolve hostname"
        );
        assert_eq!(
            Error::HttpReturnedError(404).to_string(),
            "HTTP response code said error"
        );
        // Code(..) delegates to CurlCode's Display (== strerror).
        assert_eq!(
            Error::Code(CurlCode::CouldntConnect).to_string(),
            "Could not connect to server"
        );
        // WithContext surfaces the custom message instead of strerror.
        assert_eq!(
            Error::with_context(CurlCode::Ssh, "handshake failed").to_string(),
            "handshake failed"
        );
    }

    #[test]
    fn context_message_only_for_with_context() {
        // WithContext exposes its custom detail (the `failf`-equivalent string the
        // CLI surfaces error-buffer-first), preserving the code independently.
        let onion = Error::with_context(
            CurlCode::CouldntResolveHost,
            "Not resolving .onion address (RFC 7686)",
        );
        assert_eq!(
            onion.context_message(),
            Some("Not resolving .onion address (RFC 7686)")
        );
        assert_eq!(onion.code(), CurlCode::CouldntResolveHost);

        // Typed and Code variants carry no context message, so the CLI falls back
        // to `strerror` for them (no text regression for resolve/connect/TLS/etc.).
        assert_eq!(Error::resolve("example.com").context_message(), None);
        assert_eq!(Error::Timeout.context_message(), None);
        assert_eq!(Error::Code(CurlCode::CouldntConnect).context_message(), None);
        assert_eq!(
            Error::peer_failed_verification("bad cert").context_message(),
            None
        );
    }

    #[test]
    fn error_from_io_maps_kind_to_code() {
        use std::io::{Error as IoError, ErrorKind};

        let timed_out: Error = IoError::from(ErrorKind::TimedOut).into();
        assert_eq!(timed_out.code(), CurlCode::OperationTimedout);

        let refused: Error = IoError::from(ErrorKind::ConnectionRefused).into();
        assert_eq!(refused.code(), CurlCode::CouldntConnect);

        let eof: Error = IoError::from(ErrorKind::UnexpectedEof).into();
        assert_eq!(eof.code(), CurlCode::GotNothing);

        let broken: Error = IoError::from(ErrorKind::BrokenPipe).into();
        assert_eq!(broken.code(), CurlCode::SendError);

        // Unclassified kinds fall back to a local read error.
        let other: Error = IoError::from(ErrorKind::Other).into();
        assert_eq!(other.code(), CurlCode::ReadError);
    }

    #[test]
    fn error_is_std_error() {
        // The Error type participates in the std error trait chain via thiserror.
        fn assert_std_error<E: std::error::Error>(_: &E) {}
        assert_std_error(&Error::Timeout);
    }

    // ---------------------------------------------------------------------
    // CURLMcode
    // ---------------------------------------------------------------------

    #[test]
    fn multi_code_anchor_values() {
        assert_eq!(CurlMCode::CallMultiPerform as i32, -1);
        assert_eq!(CurlMCode::Ok as i32, 0);
        assert_eq!(CurlMCode::BadHandle as i32, 1);
        assert_eq!(CurlMCode::BadFunctionArgument as i32, 10);
        assert_eq!(CurlMCode::AbortedByCallback as i32, 11);
        assert_eq!(CurlMCode::UnrecoverablePoll as i32, 12);
        // Historical alias.
        assert_eq!(CurlMCode::CALL_MULTI_SOCKET, CurlMCode::CallMultiPerform);
    }

    #[test]
    fn multi_code_roundtrip_and_strerror() {
        for value in -1..=12_i32 {
            let code = CurlMCode::try_from(value).expect("valid CurlMCode");
            assert_eq!(code as i32, value);
            assert_eq!(i32::from(code), value);
        }
        assert_eq!(CurlMCode::try_from(13), Err(13));
        assert_eq!(CurlMCode::try_from(-2), Err(-2));
        assert_eq!(
            multi_strerror(CurlMCode::CallMultiPerform),
            "Please call curl_multi_perform() soon"
        );
        assert_eq!(multi_strerror(CurlMCode::Ok), "No error");
        assert_eq!(multi_strerror(CurlMCode::BadHandle), "Invalid multi handle");
        assert_eq!(
            multi_strerror(CurlMCode::UnrecoverablePoll),
            "Unrecoverable error in select/poll"
        );
        assert_eq!(CurlMCode::BadHandle.to_string(), "Invalid multi handle");
    }

    // ---------------------------------------------------------------------
    // CURLSHcode
    // ---------------------------------------------------------------------

    #[test]
    fn share_code_roundtrip_and_strerror() {
        for value in 0..=5_i32 {
            let code = CurlShCode::try_from(value).expect("valid CurlShCode");
            assert_eq!(code as i32, value);
        }
        assert_eq!(CurlShCode::try_from(6), Err(6));
        assert_eq!(share_strerror(CurlShCode::Ok), "No error");
        assert_eq!(
            share_strerror(CurlShCode::BadOption),
            "Unknown share option"
        );
        assert_eq!(share_strerror(CurlShCode::InUse), "Share currently in use");
        assert_eq!(share_strerror(CurlShCode::Invalid), "Invalid share handle");
        assert_eq!(share_strerror(CurlShCode::Nomem), "Out of memory");
        assert_eq!(
            share_strerror(CurlShCode::NotBuiltIn),
            "Feature not enabled in this library"
        );
        assert_eq!(CurlShCode::NotBuiltIn as i32, 5);
    }

    // ---------------------------------------------------------------------
    // CURLUcode (enum order differs from the C switch order; map by value)
    // ---------------------------------------------------------------------

    #[test]
    fn url_code_roundtrip_and_strerror() {
        for value in 0..=31_i32 {
            let code = CurlUCode::try_from(value).expect("valid CurlUCode");
            assert_eq!(code as i32, value);
        }
        assert_eq!(CurlUCode::try_from(32), Err(32));
        assert_eq!(CurlUCode::TooLarge as i32, 31);
        assert_eq!(url_strerror(CurlUCode::Ok), "No error");
        assert_eq!(
            url_strerror(CurlUCode::BadPortNumber),
            "Port number was not a decimal number between 0 and 65535"
        );
        // Value 19 is BadFileUrl, 20 is BadFragment, 28 is BadSlashes: verify
        // the by-value mapping despite the C switch being written out of order.
        assert_eq!(url_strerror(CurlUCode::BadFileUrl), "Bad file:// URL");
        assert_eq!(url_strerror(CurlUCode::BadFragment), "Bad fragment");
        assert_eq!(
            url_strerror(CurlUCode::BadSlashes),
            "Unsupported number of slashes following scheme"
        );
        assert_eq!(
            url_strerror(CurlUCode::TooLarge),
            "A value or data field is larger than allowed"
        );
        assert_eq!(CurlUCode::BadIpv6.to_string(), "Bad IPv6 address");
    }

    // ---------------------------------------------------------------------
    // Ergonomics: the `?` operator and Result alias
    // ---------------------------------------------------------------------

    #[test]
    fn result_alias_and_question_mark() {
        fn inner() -> Result<u8> {
            // std::io::Error converts into Error via the #[from] on Io.
            let n: u8 = "42"
                .parse::<u8>()
                .map_err(|_| Error::bad_argument("parse"))?;
            Ok(n)
        }
        assert_eq!(inner().expect("should parse"), 42);

        fn propagates_io() -> Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::TimedOut))?;
            Ok(())
        }
        let err = propagates_io().expect_err("should be an error");
        assert_eq!(err.code(), CurlCode::OperationTimedout);
    }
}
