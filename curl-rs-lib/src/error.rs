//! Error types for the curl-rs library.
//!
//! This module defines the core error enumerations that map 1:1 to their C
//! counterparts in libcurl 8.19.0-DEV. Every variant carries an explicit
//! `#[repr(i32)]` discriminant so that FFI round-trips through integer codes
//! are lossless.
//!
//! # Enums
//!
//! * [`CurlError`] — maps to `CURLcode` (easy-handle errors)
//! * [`CurlMcode`] — maps to `CURLMcode` (multi-handle errors)
//! * [`CurlSHcode`] — maps to `CURLSHcode` (share-handle errors)
//! * [`CurlUrlError`] — maps to `CURLUcode` (URL API errors)
//!
//! # Type Aliases
//!
//! * [`CurlResult<T>`] — `Result<T, CurlError>`

use std::io;

// ---------------------------------------------------------------------------
// CurlError — maps to CURLcode
// ---------------------------------------------------------------------------

/// Error codes returned by easy-handle operations.
///
/// Every variant maps 1:1 to a `CURLcode` integer value defined in
/// `include/curl/curl.h`. Obsolete codes (20, 24, 29, 32, 34, 40, 41, 44,
/// 46, 50, 51, 57, 62, 75, 76) are intentionally omitted — they are not
/// produced by any current libcurl code path and are only kept in the C
/// header for ABI stability. The [`From<i32>`] implementation maps those
/// integers to [`CurlError::UnknownOption`] for backward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[repr(i32)]
pub enum CurlError {
    /// No error (CURLE_OK = 0).
    #[error("No error")]
    Ok = 0,

    /// Unsupported protocol (CURLE_UNSUPPORTED_PROTOCOL = 1).
    #[error("Unsupported protocol")]
    UnsupportedProtocol = 1,

    /// Failed initialization (CURLE_FAILED_INIT = 2).
    #[error("Failed initialization")]
    FailedInit = 2,

    /// URL using bad/illegal format or missing URL (CURLE_URL_MALFORMAT = 3).
    #[error("URL using bad/illegal format or missing URL")]
    UrlMalformat = 3,

    /// Feature not built in (CURLE_NOT_BUILT_IN = 4).
    #[error("A requested feature, protocol or option was not found built-in in this libcurl due to a build-time decision.")]
    NotBuiltIn = 4,

    /// Could not resolve proxy name (CURLE_COULDNT_RESOLVE_PROXY = 5).
    #[error("Could not resolve proxy name")]
    CouldntResolveProxy = 5,

    /// Could not resolve hostname (CURLE_COULDNT_RESOLVE_HOST = 6).
    #[error("Could not resolve hostname")]
    CouldntResolveHost = 6,

    /// Could not connect to server (CURLE_COULDNT_CONNECT = 7).
    #[error("Could not connect to server")]
    CouldntConnect = 7,

    /// Weird server reply (CURLE_WEIRD_SERVER_REPLY = 8).
    #[error("Weird server reply")]
    WeirdServerReply = 8,

    /// Access denied to remote resource (CURLE_REMOTE_ACCESS_DENIED = 9).
    #[error("Access denied to remote resource")]
    RemoteAccessDenied = 9,

    /// FTP: The server failed to connect to data port (CURLE_FTP_ACCEPT_FAILED = 10).
    #[error("FTP: The server failed to connect to data port")]
    FtpAcceptFailed = 10,

    /// FTP: unknown PASS reply (CURLE_FTP_WEIRD_PASS_REPLY = 11).
    #[error("FTP: unknown PASS reply")]
    FtpWeirdPassReply = 11,

    /// FTP: Accepting server connect has timed out (CURLE_FTP_ACCEPT_TIMEOUT = 12).
    #[error("FTP: Accepting server connect has timed out")]
    FtpAcceptTimeout = 12,

    /// FTP: unknown PASV reply (CURLE_FTP_WEIRD_PASV_REPLY = 13).
    #[error("FTP: unknown PASV reply")]
    FtpWeirdPasvReply = 13,

    /// FTP: unknown 227 response format (CURLE_FTP_WEIRD_227_FORMAT = 14).
    #[error("FTP: unknown 227 response format")]
    FtpWeird227Format = 14,

    /// FTP: cannot figure out the host in the PASV response (CURLE_FTP_CANT_GET_HOST = 15).
    #[error("FTP: cannot figure out the host in the PASV response")]
    FtpCantGetHost = 15,

    /// Error in the HTTP2 framing layer (CURLE_HTTP2 = 16).
    #[error("Error in the HTTP2 framing layer")]
    Http2 = 16,

    /// FTP: could not set file type (CURLE_FTP_COULDNT_SET_TYPE = 17).
    #[error("FTP: could not set file type")]
    FtpCouldntSetType = 17,

    /// Transferred a partial file (CURLE_PARTIAL_FILE = 18).
    #[error("Transferred a partial file")]
    PartialFile = 18,

    /// FTP: could not retrieve (RETR failed) the specified file (CURLE_FTP_COULDNT_RETR_FILE = 19).
    #[error("FTP: could not retrieve (RETR failed) the specified file")]
    FtpCouldntRetrFile = 19,

    // 20 — CURLE_OBSOLETE20 (not used)

    /// Quote command returned error (CURLE_QUOTE_ERROR = 21).
    #[error("Quote command returned error")]
    QuoteError = 21,

    /// HTTP response code said error (CURLE_HTTP_RETURNED_ERROR = 22).
    #[error("HTTP response code said error")]
    HttpReturnedError = 22,

    /// Failed writing received data to disk/application (CURLE_WRITE_ERROR = 23).
    #[error("Failed writing received data to disk/application")]
    WriteError = 23,

    // 24 — CURLE_OBSOLETE24 (not used)

    /// Upload failed (at start/before it took off) (CURLE_UPLOAD_FAILED = 25).
    #[error("Upload failed (at start/before it took off)")]
    UploadFailed = 25,

    /// Failed to open/read local data from file/application (CURLE_READ_ERROR = 26).
    #[error("Failed to open/read local data from file/application")]
    ReadError = 26,

    /// Out of memory (CURLE_OUT_OF_MEMORY = 27).
    #[error("Out of memory")]
    OutOfMemory = 27,

    /// Timeout was reached (CURLE_OPERATION_TIMEDOUT = 28).
    #[error("Timeout was reached")]
    OperationTimedOut = 28,

    // 29 — CURLE_OBSOLETE29 (not used)

    /// FTP: command PORT failed (CURLE_FTP_PORT_FAILED = 30).
    #[error("FTP: command PORT failed")]
    FtpPortFailed = 30,

    /// FTP: command REST failed (CURLE_FTP_COULDNT_USE_REST = 31).
    #[error("FTP: command REST failed")]
    FtpCouldntUseRest = 31,

    // 32 — CURLE_OBSOLETE32 (not used)

    /// Requested range was not delivered by the server (CURLE_RANGE_ERROR = 33).
    #[error("Requested range was not delivered by the server")]
    RangeError = 33,

    // 34 — CURLE_OBSOLETE34 (HTTP_POST_ERROR, removed)

    /// SSL connect error (CURLE_SSL_CONNECT_ERROR = 35).
    #[error("SSL connect error")]
    SslConnectError = 35,

    /// Could not resume download (CURLE_BAD_DOWNLOAD_RESUME = 36).
    #[error("Could not resume download")]
    BadDownloadResume = 36,

    /// Could not read a file:// file (CURLE_FILE_COULDNT_READ_FILE = 37).
    #[error("Could not read a file:// file")]
    FileCouldntReadFile = 37,

    /// LDAP: cannot bind (CURLE_LDAP_CANNOT_BIND = 38).
    #[error("LDAP: cannot bind")]
    LdapCannotBind = 38,

    /// LDAP: search failed (CURLE_LDAP_SEARCH_FAILED = 39).
    #[error("LDAP: search failed")]
    LdapSearchFailed = 39,

    // 40 — CURLE_OBSOLETE40 (not used)
    // 41 — CURLE_OBSOLETE41 (FUNCTION_NOT_FOUND, removed in 7.53.0)

    /// Operation was aborted by an application callback (CURLE_ABORTED_BY_CALLBACK = 42).
    #[error("Operation was aborted by an application callback")]
    AbortedByCallback = 42,

    /// A libcurl function was given a bad argument (CURLE_BAD_FUNCTION_ARGUMENT = 43).
    #[error("A libcurl function was given a bad argument")]
    BadFunctionArgument = 43,

    // 44 — CURLE_OBSOLETE44 (not used)

    /// Failed binding local connection end (CURLE_INTERFACE_FAILED = 45).
    #[error("Failed binding local connection end")]
    InterfaceFailed = 45,

    // 46 — CURLE_OBSOLETE46 (not used)

    /// Number of redirects hit maximum amount (CURLE_TOO_MANY_REDIRECTS = 47).
    #[error("Number of redirects hit maximum amount")]
    TooManyRedirects = 47,

    /// An unknown option was passed in to libcurl (CURLE_UNKNOWN_OPTION = 48).
    #[error("An unknown option was passed in to libcurl")]
    UnknownOption = 48,

    /// Malformed option provided in a setopt (CURLE_SETOPT_OPTION_SYNTAX = 49).
    #[error("Malformed option provided in a setopt")]
    SetoptOptionSyntax = 49,

    // 50 — CURLE_OBSOLETE50 (not used)
    // 51 — CURLE_OBSOLETE51 (not used)

    /// Server returned nothing (no headers, no data) (CURLE_GOT_NOTHING = 52).
    #[error("Server returned nothing (no headers, no data)")]
    GotNothing = 52,

    /// SSL crypto engine not found (CURLE_SSL_ENGINE_NOTFOUND = 53).
    #[error("SSL crypto engine not found")]
    SslEngineNotFound = 53,

    /// Can not set SSL crypto engine as default (CURLE_SSL_ENGINE_SETFAILED = 54).
    #[error("Can not set SSL crypto engine as default")]
    SslEngineSetFailed = 54,

    /// Failed sending data to the peer (CURLE_SEND_ERROR = 55).
    #[error("Failed sending data to the peer")]
    SendError = 55,

    /// Failure when receiving data from the peer (CURLE_RECV_ERROR = 56).
    #[error("Failure when receiving data from the peer")]
    RecvError = 56,

    // 57 — CURLE_OBSOLETE57 (not used)

    /// Problem with the local SSL certificate (CURLE_SSL_CERTPROBLEM = 58).
    #[error("Problem with the local SSL certificate")]
    SslCertProblem = 58,

    /// Could not use specified SSL cipher (CURLE_SSL_CIPHER = 59).
    #[error("Could not use specified SSL cipher")]
    SslCipher = 59,

    /// SSL peer certificate or SSH remote key was not OK (CURLE_PEER_FAILED_VERIFICATION = 60).
    #[error("SSL peer certificate or SSH remote key was not OK")]
    PeerFailedVerification = 60,

    /// Unrecognized or bad HTTP Content or Transfer-Encoding (CURLE_BAD_CONTENT_ENCODING = 61).
    #[error("Unrecognized or bad HTTP Content or Transfer-Encoding")]
    BadContentEncoding = 61,

    // 62 — CURLE_OBSOLETE62 (not used since 7.82.0)

    /// Maximum file size exceeded (CURLE_FILESIZE_EXCEEDED = 63).
    #[error("Maximum file size exceeded")]
    FileSizeExceeded = 63,

    /// Requested SSL level failed (CURLE_USE_SSL_FAILED = 64).
    #[error("Requested SSL level failed")]
    UseSslFailed = 64,

    /// Send failed since rewinding of the data stream failed (CURLE_SEND_FAIL_REWIND = 65).
    #[error("Send failed since rewinding of the data stream failed")]
    SendFailRewind = 65,

    /// Failed to initialise SSL crypto engine (CURLE_SSL_ENGINE_INITFAILED = 66).
    #[error("Failed to initialise SSL crypto engine")]
    SslEngineInitFailed = 66,

    /// Login denied (CURLE_LOGIN_DENIED = 67).
    #[error("Login denied")]
    LoginDenied = 67,

    /// TFTP: File Not Found (CURLE_TFTP_NOTFOUND = 68).
    #[error("TFTP: File Not Found")]
    TftpNotFound = 68,

    /// TFTP: Access Violation (CURLE_TFTP_PERM = 69).
    #[error("TFTP: Access Violation")]
    TftpPerm = 69,

    /// Disk full or allocation exceeded (CURLE_REMOTE_DISK_FULL = 70).
    #[error("Disk full or allocation exceeded")]
    RemoteDiskFull = 70,

    /// TFTP: Illegal operation (CURLE_TFTP_ILLEGAL = 71).
    #[error("TFTP: Illegal operation")]
    TftpIllegal = 71,

    /// TFTP: Unknown transfer ID (CURLE_TFTP_UNKNOWNID = 72).
    #[error("TFTP: Unknown transfer ID")]
    TftpUnknownId = 72,

    /// Remote file already exists (CURLE_REMOTE_FILE_EXISTS = 73).
    #[error("Remote file already exists")]
    RemoteFileExists = 73,

    /// TFTP: No such user (CURLE_TFTP_NOSUCHUSER = 74).
    #[error("TFTP: No such user")]
    TftpNoSuchUser = 74,

    // 75 — CURLE_OBSOLETE75 (not used since 7.82.0)
    // 76 — CURLE_OBSOLETE76 (not used since 7.82.0)

    /// Problem with the SSL CA cert (path? access rights?) (CURLE_SSL_CACERT_BADFILE = 77).
    #[error("Problem with the SSL CA cert (path? access rights?)")]
    SslCacertBadfile = 77,

    /// Remote file not found (CURLE_REMOTE_FILE_NOT_FOUND = 78).
    #[error("Remote file not found")]
    RemoteFileNotFound = 78,

    /// Error in the SSH layer (CURLE_SSH = 79).
    #[error("Error in the SSH layer")]
    Ssh = 79,

    /// Failed to shut down the SSL connection (CURLE_SSL_SHUTDOWN_FAILED = 80).
    #[error("Failed to shut down the SSL connection")]
    SslShutdownFailed = 80,

    /// Socket not ready for send/recv (CURLE_AGAIN = 81).
    #[error("Socket not ready for send/recv")]
    Again = 81,

    /// Failed to load CRL file (path? access rights?, format?) (CURLE_SSL_CRL_BADFILE = 82).
    #[error("Failed to load CRL file (path? access rights?, format?)")]
    SslCrlBadfile = 82,

    /// Issuer check against peer certificate failed (CURLE_SSL_ISSUER_ERROR = 83).
    #[error("Issuer check against peer certificate failed")]
    SslIssuerError = 83,

    /// FTP: The server did not accept the PRET command. (CURLE_FTP_PRET_FAILED = 84).
    #[error("FTP: The server did not accept the PRET command.")]
    FtpPretFailed = 84,

    /// RTSP CSeq mismatch or invalid CSeq (CURLE_RTSP_CSEQ_ERROR = 85).
    #[error("RTSP CSeq mismatch or invalid CSeq")]
    RtspCseqError = 85,

    /// RTSP session error (CURLE_RTSP_SESSION_ERROR = 86).
    #[error("RTSP session error")]
    RtspSessionError = 86,

    /// Unable to parse FTP file list (CURLE_FTP_BAD_FILE_LIST = 87).
    #[error("Unable to parse FTP file list")]
    FtpBadFileList = 87,

    /// Chunk callback failed (CURLE_CHUNK_FAILED = 88).
    #[error("Chunk callback failed")]
    ChunkFailed = 88,

    /// The max connection limit is reached (CURLE_NO_CONNECTION_AVAILABLE = 89).
    #[error("The max connection limit is reached")]
    NoConnectionAvailable = 89,

    /// SSL public key does not match pinned public key (CURLE_SSL_PINNEDPUBKEYNOTMATCH = 90).
    #[error("SSL public key does not match pinned public key")]
    SslPinnedPubkeyNotMatch = 90,

    /// SSL server certificate status verification FAILED (CURLE_SSL_INVALIDCERTSTATUS = 91).
    #[error("SSL server certificate status verification FAILED")]
    SslInvalidCertStatus = 91,

    /// Stream error in the HTTP/2 framing layer (CURLE_HTTP2_STREAM = 92).
    #[error("Stream error in the HTTP/2 framing layer")]
    Http2Stream = 92,

    /// API function called from within callback (CURLE_RECURSIVE_API_CALL = 93).
    #[error("API function called from within callback")]
    RecursiveApiCall = 93,

    /// An authentication function returned an error (CURLE_AUTH_ERROR = 94).
    #[error("An authentication function returned an error")]
    AuthError = 94,

    /// HTTP/3 error (CURLE_HTTP3 = 95).
    #[error("HTTP/3 error")]
    Http3 = 95,

    /// QUIC connection error (CURLE_QUIC_CONNECT_ERROR = 96).
    #[error("QUIC connection error")]
    QuicConnectError = 96,

    /// proxy handshake error (CURLE_PROXY = 97).
    #[error("proxy handshake error")]
    Proxy = 97,

    /// SSL Client Certificate required (CURLE_SSL_CLIENTCERT = 98).
    #[error("SSL Client Certificate required")]
    SslClientCert = 98,

    /// Unrecoverable error in select/poll (CURLE_UNRECOVERABLE_POLL = 99).
    #[error("Unrecoverable error in select/poll")]
    UnrecoverablePoll = 99,

    /// A value or data field grew larger than allowed (CURLE_TOO_LARGE = 100).
    #[error("A value or data field grew larger than allowed")]
    TooLarge = 100,

    /// ECH attempted but failed (CURLE_ECH_REQUIRED = 101).
    #[error("ECH attempted but failed")]
    EchRequired = 101,
}

impl CurlError {
    /// Returns the human-readable error message for this error code.
    ///
    /// The returned strings are character-for-character identical to those
    /// produced by `curl_easy_strerror()` in `lib/strerror.c`.
    pub fn strerror(&self) -> &'static str {
        match self {
            Self::Ok => "No error",
            Self::UnsupportedProtocol => "Unsupported protocol",
            Self::FailedInit => "Failed initialization",
            Self::UrlMalformat => "URL using bad/illegal format or missing URL",
            Self::NotBuiltIn => {
                "A requested feature, protocol or option was not found built-in in \
                 this libcurl due to a build-time decision."
            }
            Self::CouldntResolveProxy => "Could not resolve proxy name",
            Self::CouldntResolveHost => "Could not resolve hostname",
            Self::CouldntConnect => "Could not connect to server",
            Self::WeirdServerReply => "Weird server reply",
            Self::RemoteAccessDenied => "Access denied to remote resource",
            Self::FtpAcceptFailed => "FTP: The server failed to connect to data port",
            Self::FtpWeirdPassReply => "FTP: unknown PASS reply",
            Self::FtpAcceptTimeout => "FTP: Accepting server connect has timed out",
            Self::FtpWeirdPasvReply => "FTP: unknown PASV reply",
            Self::FtpWeird227Format => "FTP: unknown 227 response format",
            Self::FtpCantGetHost => "FTP: cannot figure out the host in the PASV response",
            Self::Http2 => "Error in the HTTP2 framing layer",
            Self::FtpCouldntSetType => "FTP: could not set file type",
            Self::PartialFile => "Transferred a partial file",
            Self::FtpCouldntRetrFile => {
                "FTP: could not retrieve (RETR failed) the specified file"
            }
            Self::QuoteError => "Quote command returned error",
            Self::HttpReturnedError => "HTTP response code said error",
            Self::WriteError => "Failed writing received data to disk/application",
            Self::UploadFailed => "Upload failed (at start/before it took off)",
            Self::ReadError => "Failed to open/read local data from file/application",
            Self::OutOfMemory => "Out of memory",
            Self::OperationTimedOut => "Timeout was reached",
            Self::FtpPortFailed => "FTP: command PORT failed",
            Self::FtpCouldntUseRest => "FTP: command REST failed",
            Self::RangeError => "Requested range was not delivered by the server",
            Self::SslConnectError => "SSL connect error",
            Self::BadDownloadResume => "Could not resume download",
            Self::FileCouldntReadFile => "Could not read a file:// file",
            Self::LdapCannotBind => "LDAP: cannot bind",
            Self::LdapSearchFailed => "LDAP: search failed",
            Self::AbortedByCallback => "Operation was aborted by an application callback",
            Self::BadFunctionArgument => "A libcurl function was given a bad argument",
            Self::InterfaceFailed => "Failed binding local connection end",
            Self::TooManyRedirects => "Number of redirects hit maximum amount",
            Self::UnknownOption => "An unknown option was passed in to libcurl",
            Self::SetoptOptionSyntax => "Malformed option provided in a setopt",
            Self::GotNothing => "Server returned nothing (no headers, no data)",
            Self::SslEngineNotFound => "SSL crypto engine not found",
            Self::SslEngineSetFailed => "Can not set SSL crypto engine as default",
            Self::SendError => "Failed sending data to the peer",
            Self::RecvError => "Failure when receiving data from the peer",
            Self::SslCertProblem => "Problem with the local SSL certificate",
            Self::SslCipher => "Could not use specified SSL cipher",
            Self::PeerFailedVerification => {
                "SSL peer certificate or SSH remote key was not OK"
            }
            Self::BadContentEncoding => {
                "Unrecognized or bad HTTP Content or Transfer-Encoding"
            }
            Self::FileSizeExceeded => "Maximum file size exceeded",
            Self::UseSslFailed => "Requested SSL level failed",
            Self::SendFailRewind => {
                "Send failed since rewinding of the data stream failed"
            }
            Self::SslEngineInitFailed => "Failed to initialise SSL crypto engine",
            Self::LoginDenied => "Login denied",
            Self::TftpNotFound => "TFTP: File Not Found",
            Self::TftpPerm => "TFTP: Access Violation",
            Self::RemoteDiskFull => "Disk full or allocation exceeded",
            Self::TftpIllegal => "TFTP: Illegal operation",
            Self::TftpUnknownId => "TFTP: Unknown transfer ID",
            Self::RemoteFileExists => "Remote file already exists",
            Self::TftpNoSuchUser => "TFTP: No such user",
            Self::SslCacertBadfile => "Problem with the SSL CA cert (path? access rights?)",
            Self::RemoteFileNotFound => "Remote file not found",
            Self::Ssh => "Error in the SSH layer",
            Self::SslShutdownFailed => "Failed to shut down the SSL connection",
            Self::Again => "Socket not ready for send/recv",
            Self::SslCrlBadfile => {
                "Failed to load CRL file (path? access rights?, format?)"
            }
            Self::SslIssuerError => "Issuer check against peer certificate failed",
            Self::FtpPretFailed => "FTP: The server did not accept the PRET command.",
            Self::RtspCseqError => "RTSP CSeq mismatch or invalid CSeq",
            Self::RtspSessionError => "RTSP session error",
            Self::FtpBadFileList => "Unable to parse FTP file list",
            Self::ChunkFailed => "Chunk callback failed",
            Self::NoConnectionAvailable => "The max connection limit is reached",
            Self::SslPinnedPubkeyNotMatch => {
                "SSL public key does not match pinned public key"
            }
            Self::SslInvalidCertStatus => {
                "SSL server certificate status verification FAILED"
            }
            Self::Http2Stream => "Stream error in the HTTP/2 framing layer",
            Self::RecursiveApiCall => "API function called from within callback",
            Self::AuthError => "An authentication function returned an error",
            Self::Http3 => "HTTP/3 error",
            Self::QuicConnectError => "QUIC connection error",
            Self::Proxy => "proxy handshake error",
            Self::SslClientCert => "SSL Client Certificate required",
            Self::UnrecoverablePoll => "Unrecoverable error in select/poll",
            Self::TooLarge => "A value or data field grew larger than allowed",
            Self::EchRequired => "ECH attempted but failed",
        }
    }

    /// Returns `true` when this code represents success (`Ok`).
    pub fn is_ok(&self) -> bool {
        *self == Self::Ok
    }

    /// Returns `true` when this code represents an error (anything other than `Ok`).
    pub fn is_err(&self) -> bool {
        *self != Self::Ok
    }
}

// ---------------------------------------------------------------------------
// Integer conversions for CurlError
// ---------------------------------------------------------------------------

impl From<CurlError> for i32 {
    #[inline]
    fn from(e: CurlError) -> i32 {
        e as i32
    }
}

impl From<i32> for CurlError {
    /// Converts a raw C `CURLcode` integer into the corresponding [`CurlError`]
    /// variant. Obsolete and unknown codes are mapped to
    /// [`CurlError::UnknownOption`] (48), which mirrors the "unknown" semantics
    /// in the C implementation.
    fn from(code: i32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::UnsupportedProtocol,
            2 => Self::FailedInit,
            3 => Self::UrlMalformat,
            4 => Self::NotBuiltIn,
            5 => Self::CouldntResolveProxy,
            6 => Self::CouldntResolveHost,
            7 => Self::CouldntConnect,
            8 => Self::WeirdServerReply,
            9 => Self::RemoteAccessDenied,
            10 => Self::FtpAcceptFailed,
            11 => Self::FtpWeirdPassReply,
            12 => Self::FtpAcceptTimeout,
            13 => Self::FtpWeirdPasvReply,
            14 => Self::FtpWeird227Format,
            15 => Self::FtpCantGetHost,
            16 => Self::Http2,
            17 => Self::FtpCouldntSetType,
            18 => Self::PartialFile,
            19 => Self::FtpCouldntRetrFile,
            21 => Self::QuoteError,
            22 => Self::HttpReturnedError,
            23 => Self::WriteError,
            25 => Self::UploadFailed,
            26 => Self::ReadError,
            27 => Self::OutOfMemory,
            28 => Self::OperationTimedOut,
            30 => Self::FtpPortFailed,
            31 => Self::FtpCouldntUseRest,
            33 => Self::RangeError,
            35 => Self::SslConnectError,
            36 => Self::BadDownloadResume,
            37 => Self::FileCouldntReadFile,
            38 => Self::LdapCannotBind,
            39 => Self::LdapSearchFailed,
            42 => Self::AbortedByCallback,
            43 => Self::BadFunctionArgument,
            45 => Self::InterfaceFailed,
            47 => Self::TooManyRedirects,
            48 => Self::UnknownOption,
            49 => Self::SetoptOptionSyntax,
            52 => Self::GotNothing,
            53 => Self::SslEngineNotFound,
            54 => Self::SslEngineSetFailed,
            55 => Self::SendError,
            56 => Self::RecvError,
            58 => Self::SslCertProblem,
            59 => Self::SslCipher,
            60 => Self::PeerFailedVerification,
            61 => Self::BadContentEncoding,
            63 => Self::FileSizeExceeded,
            64 => Self::UseSslFailed,
            65 => Self::SendFailRewind,
            66 => Self::SslEngineInitFailed,
            67 => Self::LoginDenied,
            68 => Self::TftpNotFound,
            69 => Self::TftpPerm,
            70 => Self::RemoteDiskFull,
            71 => Self::TftpIllegal,
            72 => Self::TftpUnknownId,
            73 => Self::RemoteFileExists,
            74 => Self::TftpNoSuchUser,
            77 => Self::SslCacertBadfile,
            78 => Self::RemoteFileNotFound,
            79 => Self::Ssh,
            80 => Self::SslShutdownFailed,
            81 => Self::Again,
            82 => Self::SslCrlBadfile,
            83 => Self::SslIssuerError,
            84 => Self::FtpPretFailed,
            85 => Self::RtspCseqError,
            86 => Self::RtspSessionError,
            87 => Self::FtpBadFileList,
            88 => Self::ChunkFailed,
            89 => Self::NoConnectionAvailable,
            90 => Self::SslPinnedPubkeyNotMatch,
            91 => Self::SslInvalidCertStatus,
            92 => Self::Http2Stream,
            93 => Self::RecursiveApiCall,
            94 => Self::AuthError,
            95 => Self::Http3,
            96 => Self::QuicConnectError,
            97 => Self::Proxy,
            98 => Self::SslClientCert,
            99 => Self::UnrecoverablePoll,
            100 => Self::TooLarge,
            101 => Self::EchRequired,
            // Obsolete or unknown codes fall through to UnknownOption.
            _ => Self::UnknownOption,
        }
    }
}

// ---------------------------------------------------------------------------
// From<std::io::Error> for CurlError
// ---------------------------------------------------------------------------

impl From<io::Error> for CurlError {
    /// Maps standard I/O errors to the most appropriate `CurlError` variant.
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::ConnectionRefused => Self::CouldntConnect,
            io::ErrorKind::ConnectionReset => Self::RecvError,
            io::ErrorKind::ConnectionAborted => Self::RecvError,
            io::ErrorKind::NotConnected => Self::CouldntConnect,
            io::ErrorKind::TimedOut => Self::OperationTimedOut,
            io::ErrorKind::NotFound => Self::FileCouldntReadFile,
            io::ErrorKind::PermissionDenied => Self::RemoteAccessDenied,
            io::ErrorKind::AddrNotAvailable => Self::CouldntConnect,
            io::ErrorKind::AddrInUse => Self::InterfaceFailed,
            io::ErrorKind::BrokenPipe => Self::SendError,
            io::ErrorKind::WriteZero => Self::SendError,
            io::ErrorKind::UnexpectedEof => Self::PartialFile,
            io::ErrorKind::WouldBlock => Self::Again,
            io::ErrorKind::OutOfMemory => Self::OutOfMemory,
            io::ErrorKind::Interrupted => Self::AbortedByCallback,
            _ => Self::RecvError,
        }
    }
}

// ---------------------------------------------------------------------------
// From<url::ParseError> for CurlError
// ---------------------------------------------------------------------------

impl From<url::ParseError> for CurlError {
    /// Any URL parse failure maps to `UrlMalformat` (CURLE_URL_MALFORMAT = 3).
    #[inline]
    fn from(_err: url::ParseError) -> Self {
        Self::UrlMalformat
    }
}

// ---------------------------------------------------------------------------
// From<rustls::Error> for CurlError
// ---------------------------------------------------------------------------

impl From<rustls::Error> for CurlError {
    /// Maps rustls TLS errors to the most appropriate `CurlError` variant.
    fn from(err: rustls::Error) -> Self {
        match err {
            rustls::Error::InvalidCertificate(_) => Self::PeerFailedVerification,
            rustls::Error::NoCertificatesPresented => Self::SslCertProblem,
            rustls::Error::UnsupportedNameType => Self::PeerFailedVerification,
            rustls::Error::InvalidMessage(_) => Self::SslConnectError,
            rustls::Error::EncryptError => Self::SslConnectError,
            rustls::Error::DecryptError => Self::SslConnectError,
            rustls::Error::AlertReceived(_) => Self::SslConnectError,
            rustls::Error::NoApplicationProtocol => Self::SslConnectError,
            rustls::Error::PeerIncompatible(_) => Self::SslConnectError,
            rustls::Error::PeerMisbehaved(_) => Self::SslConnectError,
            rustls::Error::General(_) => Self::SslConnectError,
            rustls::Error::HandshakeNotComplete => Self::SslConnectError,
            rustls::Error::InappropriateHandshakeMessage { .. } => Self::SslConnectError,
            rustls::Error::InappropriateMessage { .. } => Self::SslConnectError,
            // Catch-all for any future rustls error variants.
            _ => Self::SslConnectError,
        }
    }
}

// ---------------------------------------------------------------------------
// From<hyper::Error> for CurlError
// ---------------------------------------------------------------------------

impl From<hyper::Error> for CurlError {
    /// Maps hyper HTTP client errors to the most appropriate `CurlError` variant.
    ///
    /// Hyper 1.x exposes boolean query methods to classify errors. The mapping
    /// uses these in priority order to select the best curl error code.
    fn from(err: hyper::Error) -> Self {
        if err.is_timeout() {
            Self::OperationTimedOut
        } else if err.is_closed() {
            Self::GotNothing
        } else if err.is_parse() {
            Self::WeirdServerReply
        } else if err.is_canceled() {
            Self::AbortedByCallback
        } else if err.is_incomplete_message() {
            Self::PartialFile
        } else if err.is_body_write_aborted() {
            Self::SendError
        } else {
            // Generic fallback for send/recv-like protocol errors.
            Self::RecvError
        }
    }
}

// ---------------------------------------------------------------------------
// CurlResult type alias
// ---------------------------------------------------------------------------

/// A convenience type alias for `Result<T, CurlError>`.
pub type CurlResult<T> = Result<T, CurlError>;

// ---------------------------------------------------------------------------
// CurlMcode — maps to CURLMcode
// ---------------------------------------------------------------------------

/// Error codes returned by multi-handle operations.
///
/// Every variant maps 1:1 to a `CURLMcode` integer value defined in
/// `include/curl/multi.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[repr(i32)]
pub enum CurlMcode {
    /// Please call curl_multi_perform() soon (CURLM_CALL_MULTI_PERFORM = -1).
    #[error("Please call curl_multi_perform() soon")]
    CallMultiPerform = -1,

    /// No error (CURLM_OK = 0).
    #[error("No error")]
    Ok = 0,

    /// Invalid multi handle (CURLM_BAD_HANDLE = 1).
    #[error("Invalid multi handle")]
    BadHandle = 1,

    /// Invalid easy handle (CURLM_BAD_EASY_HANDLE = 2).
    #[error("Invalid easy handle")]
    BadEasyHandle = 2,

    /// Out of memory (CURLM_OUT_OF_MEMORY = 3).
    #[error("Out of memory")]
    OutOfMemory = 3,

    /// Internal error (CURLM_INTERNAL_ERROR = 4).
    #[error("Internal error")]
    InternalError = 4,

    /// Invalid socket argument (CURLM_BAD_SOCKET = 5).
    #[error("Invalid socket argument")]
    BadSocket = 5,

    /// Unknown option (CURLM_UNKNOWN_OPTION = 6).
    #[error("Unknown option")]
    UnknownOption = 6,

    /// The easy handle is already added to a multi handle (CURLM_ADDED_ALREADY = 7).
    #[error("The easy handle is already added to a multi handle")]
    AddedAlready = 7,

    /// API function called from within callback (CURLM_RECURSIVE_API_CALL = 8).
    #[error("API function called from within callback")]
    RecursiveApiCall = 8,

    /// Wakeup is unavailable or failed (CURLM_WAKEUP_FAILURE = 9).
    #[error("Wakeup is unavailable or failed")]
    WakeupFailure = 9,

    /// A libcurl function was given a bad argument (CURLM_BAD_FUNCTION_ARGUMENT = 10).
    #[error("A libcurl function was given a bad argument")]
    BadFunctionArgument = 10,

    /// Operation was aborted by an application callback (CURLM_ABORTED_BY_CALLBACK = 11).
    #[error("Operation was aborted by an application callback")]
    AbortedByCallback = 11,

    /// Unrecoverable error in select/poll (CURLM_UNRECOVERABLE_POLL = 12).
    #[error("Unrecoverable error in select/poll")]
    UnrecoverablePoll = 12,
}

impl CurlMcode {
    /// Returns the human-readable error message for this multi-handle error code.
    ///
    /// Strings are character-for-character identical to `curl_multi_strerror()`.
    pub fn strerror(&self) -> &'static str {
        match self {
            Self::CallMultiPerform => "Please call curl_multi_perform() soon",
            Self::Ok => "No error",
            Self::BadHandle => "Invalid multi handle",
            Self::BadEasyHandle => "Invalid easy handle",
            Self::OutOfMemory => "Out of memory",
            Self::InternalError => "Internal error",
            Self::BadSocket => "Invalid socket argument",
            Self::UnknownOption => "Unknown option",
            Self::AddedAlready => {
                "The easy handle is already added to a multi handle"
            }
            Self::RecursiveApiCall => "API function called from within callback",
            Self::WakeupFailure => "Wakeup is unavailable or failed",
            Self::BadFunctionArgument => {
                "A libcurl function was given a bad argument"
            }
            Self::AbortedByCallback => {
                "Operation was aborted by an application callback"
            }
            Self::UnrecoverablePoll => "Unrecoverable error in select/poll",
        }
    }

    /// Returns `true` when this code represents success (`Ok`).
    pub fn is_ok(&self) -> bool {
        *self == Self::Ok
    }
}

impl From<CurlMcode> for i32 {
    #[inline]
    fn from(e: CurlMcode) -> i32 {
        e as i32
    }
}

impl From<i32> for CurlMcode {
    fn from(code: i32) -> Self {
        match code {
            -1 => Self::CallMultiPerform,
            0 => Self::Ok,
            1 => Self::BadHandle,
            2 => Self::BadEasyHandle,
            3 => Self::OutOfMemory,
            4 => Self::InternalError,
            5 => Self::BadSocket,
            6 => Self::UnknownOption,
            7 => Self::AddedAlready,
            8 => Self::RecursiveApiCall,
            9 => Self::WakeupFailure,
            10 => Self::BadFunctionArgument,
            11 => Self::AbortedByCallback,
            12 => Self::UnrecoverablePoll,
            _ => Self::UnknownOption,
        }
    }
}

// ---------------------------------------------------------------------------
// CurlSHcode — maps to CURLSHcode
// ---------------------------------------------------------------------------

/// Error codes returned by share-handle operations.
///
/// Every variant maps 1:1 to a `CURLSHcode` integer value defined in
/// `include/curl/curl.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[repr(i32)]
pub enum CurlSHcode {
    /// No error (CURLSHE_OK = 0).
    #[error("No error")]
    Ok = 0,

    /// Unknown share option (CURLSHE_BAD_OPTION = 1).
    #[error("Unknown share option")]
    BadOption = 1,

    /// Share currently in use (CURLSHE_IN_USE = 2).
    #[error("Share currently in use")]
    InUse = 2,

    /// Invalid share handle (CURLSHE_INVALID = 3).
    #[error("Invalid share handle")]
    Invalid = 3,

    /// Out of memory (CURLSHE_NOMEM = 4).
    #[error("Out of memory")]
    NoMem = 4,

    /// Feature not enabled in this library (CURLSHE_NOT_BUILT_IN = 5).
    #[error("Feature not enabled in this library")]
    NotBuiltIn = 5,
}

impl CurlSHcode {
    /// Returns the human-readable error message for this share-handle error code.
    ///
    /// Strings are character-for-character identical to `curl_share_strerror()`.
    pub fn strerror(&self) -> &'static str {
        match self {
            Self::Ok => "No error",
            Self::BadOption => "Unknown share option",
            Self::InUse => "Share currently in use",
            Self::Invalid => "Invalid share handle",
            Self::NoMem => "Out of memory",
            Self::NotBuiltIn => "Feature not enabled in this library",
        }
    }

    /// Returns `true` when this code represents success (`Ok`).
    pub fn is_ok(&self) -> bool {
        *self == Self::Ok
    }
}

impl From<CurlSHcode> for i32 {
    #[inline]
    fn from(e: CurlSHcode) -> i32 {
        e as i32
    }
}

impl From<i32> for CurlSHcode {
    fn from(code: i32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::BadOption,
            2 => Self::InUse,
            3 => Self::Invalid,
            4 => Self::NoMem,
            5 => Self::NotBuiltIn,
            _ => Self::Invalid,
        }
    }
}

// ---------------------------------------------------------------------------
// CurlUrlError — maps to CURLUcode
// ---------------------------------------------------------------------------

/// Error codes returned by URL API operations.
///
/// Every variant maps 1:1 to a `CURLUcode` integer value defined in
/// `include/curl/urlapi.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[repr(i32)]
pub enum CurlUrlError {
    /// No error (CURLUE_OK = 0).
    #[error("No error")]
    Ok = 0,

    /// An invalid CURLU pointer was passed as argument (CURLUE_BAD_HANDLE = 1).
    #[error("An invalid CURLU pointer was passed as argument")]
    BadHandle = 1,

    /// An invalid 'part' argument was passed as argument (CURLUE_BAD_PARTPOINTER = 2).
    #[error("An invalid 'part' argument was passed as argument")]
    BadPartPointer = 2,

    /// Malformed input to a URL function (CURLUE_MALFORMED_INPUT = 3).
    #[error("Malformed input to a URL function")]
    MalformedInput = 3,

    /// Port number was not a decimal number between 0 and 65535 (CURLUE_BAD_PORT_NUMBER = 4).
    #[error("Port number was not a decimal number between 0 and 65535")]
    BadPortNumber = 4,

    /// Unsupported URL scheme (CURLUE_UNSUPPORTED_SCHEME = 5).
    #[error("Unsupported URL scheme")]
    UnsupportedScheme = 5,

    /// URL decode error, most likely because of rubbish in the input (CURLUE_URLDECODE = 6).
    #[error("URL decode error, most likely because of rubbish in the input")]
    UrlDecode = 6,

    /// A memory function failed (CURLUE_OUT_OF_MEMORY = 7).
    #[error("A memory function failed")]
    OutOfMemory = 7,

    /// Credentials was passed in the URL when prohibited (CURLUE_USER_NOT_ALLOWED = 8).
    #[error("Credentials was passed in the URL when prohibited")]
    UserNotAllowed = 8,

    /// An unknown part ID was passed to a URL API function (CURLUE_UNKNOWN_PART = 9).
    #[error("An unknown part ID was passed to a URL API function")]
    UnknownPart = 9,

    /// No scheme part in the URL (CURLUE_NO_SCHEME = 10).
    #[error("No scheme part in the URL")]
    NoScheme = 10,

    /// No user part in the URL (CURLUE_NO_USER = 11).
    #[error("No user part in the URL")]
    NoUser = 11,

    /// No password part in the URL (CURLUE_NO_PASSWORD = 12).
    #[error("No password part in the URL")]
    NoPassword = 12,

    /// No options part in the URL (CURLUE_NO_OPTIONS = 13).
    #[error("No options part in the URL")]
    NoOptions = 13,

    /// No host part in the URL (CURLUE_NO_HOST = 14).
    #[error("No host part in the URL")]
    NoHost = 14,

    /// No port part in the URL (CURLUE_NO_PORT = 15).
    #[error("No port part in the URL")]
    NoPort = 15,

    /// No query part in the URL (CURLUE_NO_QUERY = 16).
    #[error("No query part in the URL")]
    NoQuery = 16,

    /// No fragment part in the URL (CURLUE_NO_FRAGMENT = 17).
    #[error("No fragment part in the URL")]
    NoFragment = 17,

    /// No zoneid part in the URL (CURLUE_NO_ZONEID = 18).
    #[error("No zoneid part in the URL")]
    NoZoneId = 18,

    /// Bad file:// URL (CURLUE_BAD_FILE_URL = 19).
    #[error("Bad file:// URL")]
    BadFileUrl = 19,

    /// Bad fragment (CURLUE_BAD_FRAGMENT = 20).
    #[error("Bad fragment")]
    BadFragment = 20,

    /// Bad hostname (CURLUE_BAD_HOSTNAME = 21).
    #[error("Bad hostname")]
    BadHostname = 21,

    /// Bad IPv6 address (CURLUE_BAD_IPV6 = 22).
    #[error("Bad IPv6 address")]
    BadIpv6 = 22,

    /// Bad login part (CURLUE_BAD_LOGIN = 23).
    #[error("Bad login part")]
    BadLogin = 23,

    /// Bad password (CURLUE_BAD_PASSWORD = 24).
    #[error("Bad password")]
    BadPassword = 24,

    /// Bad path (CURLUE_BAD_PATH = 25).
    #[error("Bad path")]
    BadPath = 25,

    /// Bad query (CURLUE_BAD_QUERY = 26).
    #[error("Bad query")]
    BadQuery = 26,

    /// Bad scheme (CURLUE_BAD_SCHEME = 27).
    #[error("Bad scheme")]
    BadScheme = 27,

    /// Unsupported number of slashes following scheme (CURLUE_BAD_SLASHES = 28).
    #[error("Unsupported number of slashes following scheme")]
    BadSlashes = 28,

    /// Bad user (CURLUE_BAD_USER = 29).
    #[error("Bad user")]
    BadUser = 29,

    /// libcurl lacks IDN support (CURLUE_LACKS_IDN = 30).
    #[error("libcurl lacks IDN support")]
    LacksIdn = 30,

    /// A value or data field is larger than allowed (CURLUE_TOO_LARGE = 31).
    #[error("A value or data field is larger than allowed")]
    TooLarge = 31,
}

impl CurlUrlError {
    /// Returns the human-readable error message for this URL error code.
    ///
    /// Strings are character-for-character identical to `curl_url_strerror()`.
    pub fn strerror(&self) -> &'static str {
        match self {
            Self::Ok => "No error",
            Self::BadHandle => "An invalid CURLU pointer was passed as argument",
            Self::BadPartPointer => {
                "An invalid 'part' argument was passed as argument"
            }
            Self::MalformedInput => "Malformed input to a URL function",
            Self::BadPortNumber => {
                "Port number was not a decimal number between 0 and 65535"
            }
            Self::UnsupportedScheme => "Unsupported URL scheme",
            Self::UrlDecode => {
                "URL decode error, most likely because of rubbish in the input"
            }
            Self::OutOfMemory => "A memory function failed",
            Self::UserNotAllowed => {
                "Credentials was passed in the URL when prohibited"
            }
            Self::UnknownPart => {
                "An unknown part ID was passed to a URL API function"
            }
            Self::NoScheme => "No scheme part in the URL",
            Self::NoUser => "No user part in the URL",
            Self::NoPassword => "No password part in the URL",
            Self::NoOptions => "No options part in the URL",
            Self::NoHost => "No host part in the URL",
            Self::NoPort => "No port part in the URL",
            Self::NoQuery => "No query part in the URL",
            Self::NoFragment => "No fragment part in the URL",
            Self::NoZoneId => "No zoneid part in the URL",
            Self::BadFileUrl => "Bad file:// URL",
            Self::BadFragment => "Bad fragment",
            Self::BadHostname => "Bad hostname",
            Self::BadIpv6 => "Bad IPv6 address",
            Self::BadLogin => "Bad login part",
            Self::BadPassword => "Bad password",
            Self::BadPath => "Bad path",
            Self::BadQuery => "Bad query",
            Self::BadScheme => "Bad scheme",
            Self::BadSlashes => "Unsupported number of slashes following scheme",
            Self::BadUser => "Bad user",
            Self::LacksIdn => "libcurl lacks IDN support",
            Self::TooLarge => "A value or data field is larger than allowed",
        }
    }

    /// Returns `true` when this code represents success (`Ok`).
    pub fn is_ok(&self) -> bool {
        *self == Self::Ok
    }
}

impl From<CurlUrlError> for i32 {
    #[inline]
    fn from(e: CurlUrlError) -> i32 {
        e as i32
    }
}

impl From<i32> for CurlUrlError {
    fn from(code: i32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::BadHandle,
            2 => Self::BadPartPointer,
            3 => Self::MalformedInput,
            4 => Self::BadPortNumber,
            5 => Self::UnsupportedScheme,
            6 => Self::UrlDecode,
            7 => Self::OutOfMemory,
            8 => Self::UserNotAllowed,
            9 => Self::UnknownPart,
            10 => Self::NoScheme,
            11 => Self::NoUser,
            12 => Self::NoPassword,
            13 => Self::NoOptions,
            14 => Self::NoHost,
            15 => Self::NoPort,
            16 => Self::NoQuery,
            17 => Self::NoFragment,
            18 => Self::NoZoneId,
            19 => Self::BadFileUrl,
            20 => Self::BadFragment,
            21 => Self::BadHostname,
            22 => Self::BadIpv6,
            23 => Self::BadLogin,
            24 => Self::BadPassword,
            25 => Self::BadPath,
            26 => Self::BadQuery,
            27 => Self::BadScheme,
            28 => Self::BadSlashes,
            29 => Self::BadUser,
            30 => Self::LacksIdn,
            31 => Self::TooLarge,
            _ => Self::BadHandle,
        }
    }
}
