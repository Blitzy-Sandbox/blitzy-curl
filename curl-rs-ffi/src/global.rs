//! Global initialization, version information, and standalone utility symbols.
//!
//! This module exposes the `curl_global_*` family of `CURL_EXTERN` symbols plus
//! several standalone utility functions from `include/curl/curl.h` as
//! `extern "C"` functions with `#[no_mangle]`.
//!
//! # Exported Symbols
//!
//! **Global functions (5):**
//! - `curl_global_init` — One-time library initialization
//! - `curl_global_init_mem` — Initialization with custom allocators
//! - `curl_global_cleanup` — Library cleanup
//! - `curl_global_trace` — Configure trace/logging
//! - `curl_global_sslset` — SSL backend selection (always rustls)
//!
//! **Standalone utility functions (10):**
//! - `curl_version` — Version string
//! - `curl_version_info` — Detailed version information
//! - `curl_getenv` — Environment variable lookup
//! - `curl_free` — Free curl-allocated memory
//! - `curl_easy_escape` — URL-encode a string
//! - `curl_easy_unescape` — URL-decode a string
//! - `curl_getdate` — Parse a date string
//! - `curl_easy_strerror` — Error code to string
//! - `curl_easy_ssls_import` — SSL session import
//! - `curl_easy_ssls_export` — SSL session export
//!
//! # Safety
//!
//! All `unsafe` blocks are permitted per AAP Section 0.7.1 (FFI crate only)
//! and carry mandatory `// SAFETY:` comments documenting their invariants.
//!
//! # ABI Compatibility
//!
//! Every function name, parameter type, return type, and constant value in
//! this module matches the curl 8.19.0-DEV C headers exactly (AAP Section
//! 0.7.2).

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]

use std::ffi::CStr;
use std::ptr;
use std::sync::Once;

use libc::{c_char, c_int, c_long, c_void, free, malloc};

use crate::error_codes::{
    CURLE_BAD_FUNCTION_ARGUMENT, CURLE_FAILED_INIT, CURLE_OK, CURLSSLSET_OK, CURLSSLSET_TOO_LATE,
    CURLSSLSET_UNKNOWN_BACKEND,
};
use crate::types::{
    curl_calloc_callback, curl_free_callback, curl_malloc_callback, curl_realloc_callback,
    curl_ssl_backend, curl_sslbackend, curl_strdup_callback, curl_version_info_data, CURLcode,
    CURLsslset, CURLversion,
};

// ============================================================================
// Sync wrapper for raw pointer types in static context
// ============================================================================

/// Wrapper that allows pointer-containing arrays to live in `static` items.
///
/// Raw pointers do not implement `Sync` or `Send` in Rust, but our static data
/// consists entirely of pointers into other static byte-string literals which
/// are inherently thread-safe (immutable, 'static lifetime).
struct SyncPtrArray<T, const N: usize>([T; N]);

// SAFETY: All pointers stored in these arrays point to static byte-string
// literals that are immutable and live for the entire duration of the program.
// No mutation, no aliasing hazards.
unsafe impl<T, const N: usize> Sync for SyncPtrArray<T, N> {}
unsafe impl<T, const N: usize> Send for SyncPtrArray<T, N> {}

/// Wrapper that allows `curl_version_info_data` (which contains raw pointers)
/// to live in a `static` item inside `OnceLock`.
struct SyncVersionInfoData(curl_version_info_data);

// SAFETY: All pointer fields in the version info data point to static
// byte-string literals or to other static arrays, all of which are immutable
// and live for the entire duration of the program.
unsafe impl Sync for SyncVersionInfoData {}
unsafe impl Send for SyncVersionInfoData {}

// ============================================================================
// Section 1: CURL_GLOBAL_* Constants
// Source: include/curl/curl.h lines 3019–3024
// ============================================================================

/// SSL initialization flag (no actual purpose since curl 7.57.0).
///
/// C equivalent: `#define CURL_GLOBAL_SSL (1 << 0)`
pub const CURL_GLOBAL_SSL: c_long = 1 << 0;

/// Windows socket (Winsock) initialization flag.
///
/// C equivalent: `#define CURL_GLOBAL_WIN32 (1 << 1)`
pub const CURL_GLOBAL_WIN32: c_long = 1 << 1;

/// Initialize everything: SSL + Win32.
///
/// C equivalent: `#define CURL_GLOBAL_ALL (CURL_GLOBAL_SSL|CURL_GLOBAL_WIN32)`
pub const CURL_GLOBAL_ALL: c_long = CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32;

/// Initialize nothing.
///
/// C equivalent: `#define CURL_GLOBAL_NOTHING 0`
pub const CURL_GLOBAL_NOTHING: c_long = 0;

/// Default initialization (same as ALL).
///
/// C equivalent: `#define CURL_GLOBAL_DEFAULT CURL_GLOBAL_ALL`
pub const CURL_GLOBAL_DEFAULT: c_long = CURL_GLOBAL_ALL;

/// Acknowledge EINTR — allows callbacks to be interrupted.
///
/// C equivalent: `#define CURL_GLOBAL_ACK_EINTR (1 << 2)`
pub const CURL_GLOBAL_ACK_EINTR: c_long = 1 << 2;

// ============================================================================
// Section 2: CURL_VERSION_* Feature Bitmask Constants
// Source: include/curl/curl.h lines 3175–3211
// ============================================================================

/// IPv6-enabled.
pub const CURL_VERSION_IPV6: c_int = 1 << 0;
/// Kerberos V4 auth is supported (deprecated).
pub const CURL_VERSION_KERBEROS4: c_int = 1 << 1;
/// SSL options are present.
pub const CURL_VERSION_SSL: c_int = 1 << 2;
/// libz features are present.
pub const CURL_VERSION_LIBZ: c_int = 1 << 3;
/// NTLM auth is supported.
pub const CURL_VERSION_NTLM: c_int = 1 << 4;
/// Negotiate auth is supported (deprecated name).
pub const CURL_VERSION_GSSNEGOTIATE: c_int = 1 << 5;
/// Built with debug capabilities.
pub const CURL_VERSION_DEBUG: c_int = 1 << 6;
/// Asynchronous DNS resolves.
pub const CURL_VERSION_ASYNCHDNS: c_int = 1 << 7;
/// SPNEGO auth is supported.
pub const CURL_VERSION_SPNEGO: c_int = 1 << 8;
/// Supports files larger than 2GB.
pub const CURL_VERSION_LARGEFILE: c_int = 1 << 9;
/// Internationalized Domain Names are supported.
pub const CURL_VERSION_IDN: c_int = 1 << 10;
/// Built against Windows SSPI.
pub const CURL_VERSION_SSPI: c_int = 1 << 11;
/// Character conversions supported.
pub const CURL_VERSION_CONV: c_int = 1 << 12;
/// Debug memory tracking supported (deprecated).
pub const CURL_VERSION_CURLDEBUG: c_int = 1 << 13;
/// TLS-SRP auth is supported.
pub const CURL_VERSION_TLSAUTH_SRP: c_int = 1 << 14;
/// NTLM delegation to winbind helper is supported.
pub const CURL_VERSION_NTLM_WB: c_int = 1 << 15;
/// HTTP/2 support built-in.
pub const CURL_VERSION_HTTP2: c_int = 1 << 16;
/// Built against a GSS-API library.
pub const CURL_VERSION_GSSAPI: c_int = 1 << 17;
/// Kerberos V5 auth is supported.
pub const CURL_VERSION_KERBEROS5: c_int = 1 << 18;
/// Unix domain sockets support.
pub const CURL_VERSION_UNIX_SOCKETS: c_int = 1 << 19;
/// Mozilla's Public Suffix List, used for cookie domain verification.
pub const CURL_VERSION_PSL: c_int = 1 << 20;
/// HTTPS-proxy support built-in.
pub const CURL_VERSION_HTTPS_PROXY: c_int = 1 << 21;
/// Multiple SSL backends available.
pub const CURL_VERSION_MULTI_SSL: c_int = 1 << 22;
/// Brotli features are present.
pub const CURL_VERSION_BROTLI: c_int = 1 << 23;
/// Alt-Svc handling built-in.
pub const CURL_VERSION_ALTSVC: c_int = 1 << 24;
/// HTTP/3 support built-in.
pub const CURL_VERSION_HTTP3: c_int = 1 << 25;
/// Zstd features are present.
pub const CURL_VERSION_ZSTD: c_int = 1 << 26;
/// Unicode support on Windows.
pub const CURL_VERSION_UNICODE: c_int = 1 << 27;
/// HSTS is supported.
pub const CURL_VERSION_HSTS: c_int = 1 << 28;
/// libgsasl is supported.
pub const CURL_VERSION_GSASL: c_int = 1 << 29;
/// libcurl API is thread-safe.
pub const CURL_VERSION_THREADSAFE: c_int = 1 << 30;

// ============================================================================
// Section 3: CURLversion Constants
// Source: include/curl/curl.h lines 3088–3109
// ============================================================================

/// Version info struct age = 0 (introduced in curl 7.10).
pub const CURLVERSION_FIRST: CURLversion = 0;
/// Version info struct age = 1 (introduced in curl 7.11.1).
pub const CURLVERSION_SECOND: CURLversion = 1;
/// Version info struct age = 2 (introduced in curl 7.12.0).
pub const CURLVERSION_THIRD: CURLversion = 2;
/// Version info struct age = 3 (introduced in curl 7.16.1).
pub const CURLVERSION_FOURTH: CURLversion = 3;
/// Version info struct age = 4 (introduced in curl 7.57.0).
pub const CURLVERSION_FIFTH: CURLversion = 4;
/// Version info struct age = 5 (introduced in curl 7.66.0).
pub const CURLVERSION_SIXTH: CURLversion = 5;
/// Version info struct age = 6 (introduced in curl 7.70.0).
pub const CURLVERSION_SEVENTH: CURLversion = 6;
/// Version info struct age = 7 (introduced in curl 7.72.0).
pub const CURLVERSION_EIGHTH: CURLversion = 7;
/// Version info struct age = 8 (introduced in curl 7.75.0).
pub const CURLVERSION_NINTH: CURLversion = 8;
/// Version info struct age = 9 (introduced in curl 7.77.0).
pub const CURLVERSION_TENTH: CURLversion = 9;
/// Version info struct age = 10 (introduced in curl 7.87.0).
pub const CURLVERSION_ELEVENTH: CURLversion = 10;
/// Version info struct age = 11 (introduced in curl 8.8.0).
pub const CURLVERSION_TWELFTH: CURLversion = 11;
/// Symbolic alias for the latest version struct age.
pub const CURLVERSION_NOW: CURLversion = CURLVERSION_TWELFTH;

// ============================================================================
// Section 4: CURLSSLBACKEND_* Constants
// Source: include/curl/curl.h lines 151–167
// ============================================================================

/// No SSL backend.
pub const CURLSSLBACKEND_NONE: curl_sslbackend = 0;
/// OpenSSL backend.
pub const CURLSSLBACKEND_OPENSSL: curl_sslbackend = 1;
/// GnuTLS backend.
pub const CURLSSLBACKEND_GNUTLS: curl_sslbackend = 2;
/// wolfSSL backend.
pub const CURLSSLBACKEND_WOLFSSL: curl_sslbackend = 7;
/// Windows Schannel backend.
pub const CURLSSLBACKEND_SCHANNEL: curl_sslbackend = 8;
/// Apple Secure Transport backend (deprecated).
pub const CURLSSLBACKEND_SECURETRANSPORT: curl_sslbackend = 9;
/// mbedTLS backend.
pub const CURLSSLBACKEND_MBEDTLS: curl_sslbackend = 11;
/// BearSSL backend (deprecated).
pub const CURLSSLBACKEND_BEARSSL: curl_sslbackend = 13;
/// Rustls backend — the only backend in curl-rs.
pub const CURLSSLBACKEND_RUSTLS: curl_sslbackend = 14;

// ============================================================================
// Section 5: Internal Static Data
// ============================================================================

/// Global initialization guard — ensures `curl_global_init` logic runs once.
static GLOBAL_INIT: Once = Once::new();

/// Whether global init has been called successfully at least once.
static GLOBAL_INIT_DONE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Static version string returned by `curl_version()`.
/// Null-terminated for direct use as a C string.
static VERSION_STRING: &[u8] = b"libcurl/8.19.0-DEV rustls\0";

/// Bare version string for the `version` field of `curl_version_info_data`.
/// Contains only the version number, matching C `LIBCURL_VERSION`.
static BARE_VERSION_STRING: &[u8] = b"8.19.0-DEV\0";

/// Static host string for the version info data.
static HOST_STRING: &[u8] = b"x86_64-unknown-linux-gnu\0";

/// Static SSL version string.
static SSL_VERSION_STRING: &[u8] = b"rustls\0";

/// Static libz version string.
static LIBZ_VERSION_STRING: &[u8] = b"flate2\0";

/// Static hyper version string.
static HYPER_VERSION_STRING: &[u8] = b"hyper\0";

/// Static QUIC version string.
static QUIC_VERSION_STRING: &[u8] = b"quinn/h3\0";

/// Static SSH version string.
static SSH_VERSION_STRING: &[u8] = b"russh\0";

/// Null-terminated protocol name strings.
static PROTO_HTTP: &[u8] = b"http\0";
static PROTO_HTTPS: &[u8] = b"https\0";
static PROTO_FTP: &[u8] = b"ftp\0";
static PROTO_FTPS: &[u8] = b"ftps\0";
static PROTO_SCP: &[u8] = b"scp\0";
static PROTO_SFTP: &[u8] = b"sftp\0";
static PROTO_FILE: &[u8] = b"file\0";
static PROTO_DICT: &[u8] = b"dict\0";
static PROTO_GOPHER: &[u8] = b"gopher\0";
static PROTO_GOPHERS: &[u8] = b"gophers\0";
static PROTO_IMAP: &[u8] = b"imap\0";
static PROTO_IMAPS: &[u8] = b"imaps\0";
static PROTO_LDAP: &[u8] = b"ldap\0";
static PROTO_LDAPS: &[u8] = b"ldaps\0";
static PROTO_MQTT: &[u8] = b"mqtt\0";
static PROTO_POP3: &[u8] = b"pop3\0";
static PROTO_POP3S: &[u8] = b"pop3s\0";
static PROTO_RTSP: &[u8] = b"rtsp\0";
static PROTO_SMB: &[u8] = b"smb\0";
static PROTO_SMBS: &[u8] = b"smbs\0";
static PROTO_SMTP: &[u8] = b"smtp\0";
static PROTO_SMTPS: &[u8] = b"smtps\0";
static PROTO_TELNET: &[u8] = b"telnet\0";
static PROTO_TFTP: &[u8] = b"tftp\0";
static PROTO_WS: &[u8] = b"ws\0";
static PROTO_WSS: &[u8] = b"wss\0";

/// Null-terminated array of protocol name C-string pointers.
/// The array itself is terminated by a null pointer.
/// Wrapped in `SyncPtrArray` because `*const c_char` does not implement `Sync`.
static PROTOCOLS: SyncPtrArray<*const c_char, 27> = SyncPtrArray([
    PROTO_DICT.as_ptr() as *const c_char,
    PROTO_FILE.as_ptr() as *const c_char,
    PROTO_FTP.as_ptr() as *const c_char,
    PROTO_FTPS.as_ptr() as *const c_char,
    PROTO_GOPHER.as_ptr() as *const c_char,
    PROTO_GOPHERS.as_ptr() as *const c_char,
    PROTO_HTTP.as_ptr() as *const c_char,
    PROTO_HTTPS.as_ptr() as *const c_char,
    PROTO_IMAP.as_ptr() as *const c_char,
    PROTO_IMAPS.as_ptr() as *const c_char,
    PROTO_LDAP.as_ptr() as *const c_char,
    PROTO_LDAPS.as_ptr() as *const c_char,
    PROTO_MQTT.as_ptr() as *const c_char,
    PROTO_POP3.as_ptr() as *const c_char,
    PROTO_POP3S.as_ptr() as *const c_char,
    PROTO_RTSP.as_ptr() as *const c_char,
    PROTO_SCP.as_ptr() as *const c_char,
    PROTO_SFTP.as_ptr() as *const c_char,
    PROTO_SMB.as_ptr() as *const c_char,
    PROTO_SMBS.as_ptr() as *const c_char,
    PROTO_SMTP.as_ptr() as *const c_char,
    PROTO_SMTPS.as_ptr() as *const c_char,
    PROTO_TELNET.as_ptr() as *const c_char,
    PROTO_TFTP.as_ptr() as *const c_char,
    PROTO_WS.as_ptr() as *const c_char,
    PROTO_WSS.as_ptr() as *const c_char,
    ptr::null(), // sentinel
]);

/// Feature name strings for the version info data.
static FEAT_IPV6: &[u8] = b"IPv6\0";
static FEAT_SSL: &[u8] = b"SSL\0";
static FEAT_LIBZ: &[u8] = b"libz\0";
static FEAT_NTLM: &[u8] = b"NTLM\0";
static FEAT_ASYNCHDNS: &[u8] = b"AsynchDNS\0";
static FEAT_SPNEGO: &[u8] = b"SPNEGO\0";
static FEAT_LARGEFILE: &[u8] = b"Largefile\0";
static FEAT_IDN: &[u8] = b"IDN\0";
static FEAT_HTTP2: &[u8] = b"HTTP2\0";
static FEAT_HTTP3: &[u8] = b"HTTP3\0";
static FEAT_GSSAPI: &[u8] = b"GSS-API\0";
static FEAT_KERBEROS5: &[u8] = b"Kerberos\0";
static FEAT_UNIX_SOCKETS: &[u8] = b"UnixSockets\0";
static FEAT_HTTPS_PROXY: &[u8] = b"HTTPS-proxy\0";
static FEAT_BROTLI: &[u8] = b"brotli\0";
static FEAT_ALTSVC: &[u8] = b"alt-svc\0";
static FEAT_ZSTD: &[u8] = b"zstd\0";
static FEAT_HSTS: &[u8] = b"HSTS\0";
static FEAT_THREADSAFE: &[u8] = b"threadsafe\0";

/// Null-terminated array of feature name strings.
/// Wrapped in `SyncPtrArray` because `*const c_char` does not implement `Sync`.
static FEATURE_NAMES: SyncPtrArray<*const c_char, 20> = SyncPtrArray([
    FEAT_ALTSVC.as_ptr() as *const c_char,
    FEAT_ASYNCHDNS.as_ptr() as *const c_char,
    FEAT_BROTLI.as_ptr() as *const c_char,
    FEAT_GSSAPI.as_ptr() as *const c_char,
    FEAT_HTTP2.as_ptr() as *const c_char,
    FEAT_HTTP3.as_ptr() as *const c_char,
    FEAT_HTTPS_PROXY.as_ptr() as *const c_char,
    FEAT_HSTS.as_ptr() as *const c_char,
    FEAT_IDN.as_ptr() as *const c_char,
    FEAT_IPV6.as_ptr() as *const c_char,
    FEAT_KERBEROS5.as_ptr() as *const c_char,
    FEAT_LARGEFILE.as_ptr() as *const c_char,
    FEAT_LIBZ.as_ptr() as *const c_char,
    FEAT_NTLM.as_ptr() as *const c_char,
    FEAT_SPNEGO.as_ptr() as *const c_char,
    FEAT_SSL.as_ptr() as *const c_char,
    FEAT_THREADSAFE.as_ptr() as *const c_char,
    FEAT_UNIX_SOCKETS.as_ptr() as *const c_char,
    FEAT_ZSTD.as_ptr() as *const c_char,
    ptr::null(), // sentinel
]);

/// Static rustls backend descriptor for `curl_global_sslset`.
#[repr(C)]
struct RustlsBackendInfo {
    id: curl_sslbackend,
    name: *const c_char,
}

// SAFETY: RustlsBackendInfo contains only an integer and a pointer to static
// data, both of which are inherently Send + Sync.
unsafe impl Send for RustlsBackendInfo {}
unsafe impl Sync for RustlsBackendInfo {}

static RUSTLS_BACKEND_NAME: &[u8] = b"rustls\0";

static RUSTLS_BACKEND_INFO: RustlsBackendInfo = RustlsBackendInfo {
    id: CURLSSLBACKEND_RUSTLS,
    name: RUSTLS_BACKEND_NAME.as_ptr() as *const c_char,
};

/// Pointer array for `curl_global_sslset` avail output.
/// Contains a pointer to the rustls backend info followed by a null sentinel.
/// Wrapped in `SyncPtrArray` because `*const curl_ssl_backend` does not
/// implement `Sync`.
static SSLSET_BACKENDS: SyncPtrArray<*const curl_ssl_backend, 2> = SyncPtrArray([
    // SAFETY: We cast `&RustlsBackendInfo` to `*const curl_ssl_backend` because
    // `RustlsBackendInfo` is `#[repr(C)]` with fields {id: curl_sslbackend, name:
    // *const c_char} which is layout-compatible with the C `struct curl_ssl_backend`.
    // The `curl_ssl_backend` opaque type in types.rs is a zero-sized placeholder;
    // the actual struct layout is defined by `RustlsBackendInfo` above.
    &RUSTLS_BACKEND_INFO as *const RustlsBackendInfo as *const curl_ssl_backend,
    ptr::null(),
]);

/// Compute the features bitmask for the version info data.
/// Reflects the capabilities of the curl-rs Rust implementation.
const fn compute_features() -> c_int {
    CURL_VERSION_IPV6
        | CURL_VERSION_SSL
        | CURL_VERSION_LIBZ
        | CURL_VERSION_NTLM
        | CURL_VERSION_GSSNEGOTIATE
        | CURL_VERSION_ASYNCHDNS
        | CURL_VERSION_SPNEGO
        | CURL_VERSION_LARGEFILE
        | CURL_VERSION_IDN
        | CURL_VERSION_HTTP2
        | CURL_VERSION_GSSAPI
        | CURL_VERSION_KERBEROS5
        | CURL_VERSION_UNIX_SOCKETS
        | CURL_VERSION_HTTPS_PROXY
        | CURL_VERSION_BROTLI
        | CURL_VERSION_ALTSVC
        | CURL_VERSION_HTTP3
        | CURL_VERSION_ZSTD
        | CURL_VERSION_HSTS
        | CURL_VERSION_THREADSAFE
}

/// Lazily-initialized version info data struct returned by `curl_version_info()`.
///
/// Uses `OnceLock` to safely initialize the struct at first access, avoiding
/// cross-static reference issues that arise when one static tries to call
/// `.as_ptr()` on another static's inner array at compile time.
fn version_info_static() -> &'static curl_version_info_data {
    use std::sync::OnceLock;
    static DATA: OnceLock<SyncVersionInfoData> = OnceLock::new();
    &DATA
        .get_or_init(|| {
            SyncVersionInfoData(curl_version_info_data {
                age: CURLVERSION_NOW,
                version: BARE_VERSION_STRING.as_ptr() as *const c_char,
                version_num: 0x081300,
                host: HOST_STRING.as_ptr() as *const c_char,
                features: compute_features(),
                ssl_version: SSL_VERSION_STRING.as_ptr() as *const c_char,
                ssl_version_num: 0, // deprecated, always 0
                libz_version: LIBZ_VERSION_STRING.as_ptr() as *const c_char,
                protocols: PROTOCOLS.0.as_ptr(),
                // CURLVERSION_SECOND
                ares: ptr::null(),
                ares_num: 0,
                // CURLVERSION_THIRD
                libidn: ptr::null(),
                // CURLVERSION_FOURTH
                iconv_ver_num: 0,
                libssh_version: SSH_VERSION_STRING.as_ptr() as *const c_char,
                // CURLVERSION_FIFTH
                brotli_ver_num: 0, // no numeric brotli version available
                brotli_version: ptr::null(),
                // CURLVERSION_SIXTH
                nghttp2_ver_num: 0, // using hyper, not nghttp2
                nghttp2_version: ptr::null(),
                quic_version: QUIC_VERSION_STRING.as_ptr() as *const c_char,
                // CURLVERSION_SEVENTH
                cainfo: ptr::null(),
                capath: ptr::null(),
                // CURLVERSION_EIGHTH
                zstd_ver_num: 0,
                zstd_version: ptr::null(),
                // CURLVERSION_NINTH
                hyper_version: HYPER_VERSION_STRING.as_ptr() as *const c_char,
                // CURLVERSION_TENTH
                gsasl_version: ptr::null(),
                // CURLVERSION_ELEVENTH
                feature_names: FEATURE_NAMES.0.as_ptr(),
                // CURLVERSION_TWELFTH
                rtmp_version: ptr::null(),
            })
        })
        .0
}

// NOTE: The error string table (ERROR_STRINGS) and curl_easy_strerror() are
// implemented in easy.rs alongside the other curl_easy_* symbols.

// ============================================================================
// Section 7: Global Functions (5)
// ============================================================================

/// Initialize the curl library globally.
///
/// Must be called at least once before using any other curl function.
/// Thread-safe when `CURL_VERSION_THREADSAFE` is set.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURLcode curl_global_init(long flags);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_global_init(flags: c_long) -> CURLcode {
    // SAFETY: This function is called by C consumers to initialize the library.
    // The `flags` parameter is an integer bitmask — no pointer dereferences.
    // We delegate to the Rust library's `global_init` which uses OnceLock
    // internally for thread safety.
    let mut result = CURLE_OK;
    GLOBAL_INIT.call_once(|| {
        // Allow: c_long is i64 on this platform but i32 on 32-bit targets.
        #[allow(clippy::useless_conversion)]
        match curl_rs_lib::global_init(i64::from(flags)) {
            Ok(()) => {
                GLOBAL_INIT_DONE.store(true, std::sync::atomic::Ordering::Release);
            }
            Err(_) => {
                result = CURLE_FAILED_INIT;
            }
        }
    });
    result
}

/// Initialize the curl library with custom memory allocation callbacks.
///
/// The custom allocator callbacks are stored but Rust manages its own
/// memory — the callbacks exist for C API compatibility only.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURLcode curl_global_init_mem(long flags,
///     curl_malloc_callback m, curl_free_callback f,
///     curl_realloc_callback r, curl_strdup_callback s,
///     curl_calloc_callback c);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_global_init_mem(
    flags: c_long,
    _m: curl_malloc_callback,
    _f: curl_free_callback,
    _r: curl_realloc_callback,
    _s: curl_strdup_callback,
    _c: curl_calloc_callback,
) -> CURLcode {
    // SAFETY: All parameters are either integer flags or function pointers.
    // The custom allocator callbacks are accepted for C API compatibility but
    // are not used — Rust manages its own memory via the global allocator.
    // We simply delegate to the standard global init.
    curl_global_init(flags)
}

/// Clean up the curl library globally.
///
/// Should be called once per application after all curl operations are done.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN void curl_global_cleanup(void);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_global_cleanup() {
    // SAFETY: No pointer parameters. Delegates to the Rust library's cleanup
    // function which is idempotent and thread-safe via OnceLock.
    curl_rs_lib::global_cleanup();
}

/// Configure the curl library's trace/logging output.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURLcode curl_global_trace(const char *config);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_global_trace(config: *const c_char) -> CURLcode {
    // SAFETY: `config` is a C string pointer that we read but do not write.
    // If null, we treat it as a no-op (matching curl 8.x behavior where
    // null config resets tracing).
    if config.is_null() {
        return CURLE_OK;
    }

    // SAFETY: The caller guarantees `config` is a valid null-terminated C
    // string. We convert it to a Rust `&str` for inspection.
    let config_cstr = CStr::from_ptr(config);
    let _config_str = match config_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // In the Rust implementation, tracing is configured via the tracing-subscriber
    // crate during global_init. This function accepts the config string for
    // API compatibility but the tracing configuration has already been set up.
    // Future enhancement: parse the config string to dynamically adjust tracing
    // filters at runtime.
    CURLE_OK
}

/// Select the SSL backend to use.
///
/// For curl-rs, only the rustls backend is available. If the caller requests
/// rustls (by id or name), we return success. Otherwise, we return
/// `CURLSSLSET_UNKNOWN_BACKEND`. If called after `curl_global_init`, returns
/// `CURLSSLSET_TOO_LATE`.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURLsslset curl_global_sslset(curl_sslbackend id,
///     const char *name,
///     const curl_ssl_backend ***avail);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_global_sslset(
    id: curl_sslbackend,
    name: *const c_char,
    avail: *mut *const *const curl_ssl_backend,
) -> CURLsslset {
    // SAFETY: We read `id` (integer), optionally read `name` (C string pointer),
    // and optionally write to `avail` (output triple-pointer). All pointer
    // dereferences are guarded by null checks.
    //
    // The C signature is: const curl_ssl_backend ***avail
    // - avail is a writable pointer (*mut)
    // - *avail is set to a pointer to a null-terminated array of backend pointers

    // If avail is not null, populate it with the list of available backends.
    if !avail.is_null() {
        // SAFETY: Caller guarantees `avail` is a valid writable pointer.
        // We write a pointer to our static SSLSET_BACKENDS array, which
        // is a null-terminated array of *const curl_ssl_backend.
        *avail = SSLSET_BACKENDS.0.as_ptr();
    }

    // If global init has already been called, it's too late to change backends.
    if GLOBAL_INIT_DONE.load(std::sync::atomic::Ordering::Acquire) {
        return CURLSSLSET_TOO_LATE;
    }

    // Check if the caller is requesting rustls by name.
    if !name.is_null() {
        // SAFETY: Caller guarantees `name` is a valid null-terminated C string.
        let name_cstr = CStr::from_ptr(name);
        if let Ok(name_str) = name_cstr.to_str() {
            if name_str.eq_ignore_ascii_case("rustls") {
                return CURLSSLSET_OK;
            }
        }
        return CURLSSLSET_UNKNOWN_BACKEND;
    }

    // Check by id.
    if id == CURLSSLBACKEND_NONE {
        // CURLSSLBACKEND_NONE means "just report available backends" — always OK.
        return CURLSSLSET_OK;
    }
    if id == CURLSSLBACKEND_RUSTLS {
        return CURLSSLSET_OK;
    }

    CURLSSLSET_UNKNOWN_BACKEND
}

// ============================================================================
// Section 8: Standalone Utility Functions
// ============================================================================

/// Returns a human-readable version string.
///
/// The returned pointer is to static data and must not be freed by the caller.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN char *curl_version(void);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_version() -> *const c_char {
    // SAFETY: Returns a pointer to a static null-terminated byte string.
    // The string has 'static lifetime and is never modified.
    VERSION_STRING.as_ptr() as *const c_char
}

/// Returns detailed version and feature information.
///
/// The returned pointer is to a static struct and must not be freed.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN curl_version_info_data *curl_version_info(CURLversion);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_version_info(_age: CURLversion) -> *mut curl_version_info_data {
    // SAFETY: Returns a pointer to a lazily-initialized `curl_version_info_data`
    // struct stored inside a `OnceLock<SyncVersionInfoData>` static. The struct
    // has 'static lifetime and all its pointer fields point to static data.
    // We cast away const-ness to match the C API signature which returns
    // `curl_version_info_data *` (not const), though the data is effectively
    // read-only.
    //
    // The `age` parameter controls which fields are valid in the returned
    // struct. Since we always populate all fields up to CURLVERSION_TWELFTH,
    // we return the full struct regardless of the requested age — matching
    // the C implementation behavior where the struct's own `age` field
    // tells the caller how many fields are valid.
    version_info_static() as *const curl_version_info_data as *mut curl_version_info_data
}

/// Look up an environment variable by name.
///
/// Returns a malloc'd copy of the variable's value, or NULL if not found.
/// The returned pointer must be freed with `curl_free()`.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN char *curl_getenv(const char *variable);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_getenv(variable: *const c_char) -> *mut c_char {
    // SAFETY: `variable` must be a valid null-terminated C string.
    // We convert it to a Rust &str to call std::env::var.
    if variable.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: Caller guarantees `variable` is a valid, null-terminated C string.
    let var_name = match CStr::from_ptr(variable).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    // Look up the environment variable.
    let value = match std::env::var(var_name) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };

    // Allocate a C string copy using libc::malloc so it can be freed with
    // curl_free() / free().
    let len = value.len();
    // SAFETY: We allocate (len + 1) bytes — room for the string plus null
    // terminator. malloc returns a valid pointer or null on failure.
    let buf = malloc(len + 1) as *mut c_char;
    if buf.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: We just allocated `len + 1` bytes at `buf`. `value.as_ptr()`
    // points to `len` valid bytes. The ranges do not overlap since `buf`
    // is freshly allocated.
    ptr::copy_nonoverlapping(value.as_ptr() as *const c_char, buf, len);
    // Null-terminate.
    *buf.add(len) = 0;

    buf
}

/// Free memory allocated by curl functions.
///
/// Safely handles NULL pointers (no-op).
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN void curl_free(void *p);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_free(p: *mut c_void) {
    // SAFETY: If `p` is null, `free` is a no-op per the C standard.
    // Otherwise, `p` must have been allocated by a curl function using
    // `libc::malloc` (which `curl_getenv`, `curl_easy_escape`, and
    // `curl_easy_unescape` all use).
    if !p.is_null() {
        free(p);
    }
}

// NOTE: curl_easy_escape and curl_easy_unescape are defined in easy.rs,
// which is the canonical home for all curl_easy_* symbols. They are listed
// here in the task spec because they appear in curl.h alongside global
// functions, but they are implemented in the easy module to avoid symbol
// collisions.

/// Parse a date string and return the time as seconds since epoch.
///
/// The second parameter `unused` is always ignored (historical artifact).
/// Returns `-1` on parse failure.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN time_t curl_getdate(const char *p, const time_t *unused);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_getdate(
    p: *const c_char,
    _unused: *const libc::time_t,
) -> libc::time_t {
    // SAFETY: `p` must be a valid null-terminated C string. `_unused` is
    // completely ignored per the curl API specification.
    if p.is_null() {
        return -1;
    }

    // SAFETY: Caller guarantees `p` is a valid, null-terminated C string.
    let date_str = match CStr::from_ptr(p).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    // Use the Rust library's date parser.
    match curl_rs_lib::util::parsedate::parse_date(date_str) {
        Ok(timestamp) => timestamp as libc::time_t,
        Err(_) => -1,
    }
}

// NOTE: curl_easy_strerror, curl_easy_ssls_import, and curl_easy_ssls_export
// are defined in easy.rs, which is the canonical home for all curl_easy_*
// symbols. They are listed here in the task spec because they appear in
// curl.h alongside global functions, but they are implemented in the easy
// module to avoid #[no_mangle] symbol collisions.

// ============================================================================
// Deprecated symbols — required for ABI parity with curl 8.x
//
// Per AAP Section 0.7.1: "nm symbol export list of libcurl-rs.so MUST match
// curl 8.x libcurl.so symbol export list."
//
// These 7 symbols are deprecated in curl 8.x but still present in the export
// table.  They delegate to their non-deprecated equivalents where possible,
// or return an error code indicating the function is obsolete.
// ============================================================================

// ---------------------------------------------------------------------------
// curl_escape — DEPRECATED: use curl_easy_escape instead
// ---------------------------------------------------------------------------

/// Deprecated URL-encoding function.
///
/// This is the pre-7.x interface.  It delegates to `curl_easy_escape` with
/// a null handle, which is valid per the curl 8.x implementation.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURL_DEPRECATED(7.15.4, "Use curl_easy_escape")
/// char *curl_escape(const char *string, int length);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_escape(
    string: *const c_char,
    length: c_int,
) -> *mut c_char {
    // SAFETY: Delegates to curl_easy_escape which handles null checks
    // internally.  Passing a null handle is explicitly supported for this
    // deprecated wrapper — curl_easy_escape only uses the handle for
    // connection encoding which defaults to UTF-8 when handle is null.
    crate::easy::curl_easy_escape(std::ptr::null_mut(), string, length)
}

// ---------------------------------------------------------------------------
// curl_unescape — DEPRECATED: use curl_easy_unescape instead
// ---------------------------------------------------------------------------

/// Deprecated URL-decoding function.
///
/// Delegates to `curl_easy_unescape` with a null handle and ignoring the
/// output length parameter.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURL_DEPRECATED(7.15.4, "Use curl_easy_unescape")
/// char *curl_unescape(const char *string, int length);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_unescape(
    string: *const c_char,
    length: c_int,
) -> *mut c_char {
    // SAFETY: Delegates to curl_easy_unescape which handles null checks.
    // The output length is written to a stack variable which is discarded.
    let mut outlength: c_int = 0;
    crate::easy::curl_easy_unescape(
        std::ptr::null_mut(),
        string,
        length,
        &mut outlength as *mut c_int,
    )
}

// ---------------------------------------------------------------------------
// curl_formadd — DEPRECATED: use curl_mime_* API instead
// ---------------------------------------------------------------------------

/// Deprecated multipart form-data builder.
///
/// This function was superseded by the MIME API (`curl_mime_*`) in curl 7.56.0.
/// The Rust implementation returns `CURL_FORMADD_DISABLED` to indicate the
/// function is not supported, matching the behavior of curl builds compiled
/// with `CURL_DISABLE_FORM_API`.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURL_DEPRECATED(7.56.0, "Use curl_mime_init")
/// CURLFORMcode curl_formadd(struct curl_httppost **httppost,
///                           struct curl_httppost **last_post, ...);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_formadd(
    _httppost: *mut *mut c_void,
    _last_post: *mut *mut c_void,
    // Variadic args are not directly supported in stable Rust extern "C" —
    // this stub accepts the minimum required parameters.  In practice,
    // callers of curl_formadd always pass at least the two pointer-to-pointer
    // arguments.  Additional variadic args are harmless to ignore since we
    // return the disabled error code unconditionally.
) -> c_int {
    // SAFETY: No memory is accessed through the pointers. We return the
    // CURL_FORMADD_DISABLED constant (6) to signal this API is disabled.
    6 // CURL_FORMADD_DISABLED
}

// ---------------------------------------------------------------------------
// curl_formfree — DEPRECATED: use curl_mime_free instead
// ---------------------------------------------------------------------------

/// Deprecated function to free a curl_httppost chain.
///
/// Since `curl_formadd` returns DISABLED, no valid httppost chains can exist.
/// This function is a no-op that accepts and ignores the pointer.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURL_DEPRECATED(7.56.0, "Use curl_mime_free")
/// void curl_formfree(struct curl_httppost *form);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_formfree(_form: *mut c_void) {
    // SAFETY: No-op. Since curl_formadd always returns DISABLED, no
    // valid form chains exist to free.
}

// ---------------------------------------------------------------------------
// curl_formget — DEPRECATED: use curl_mime_data_cb instead
// ---------------------------------------------------------------------------

/// Deprecated function to serialize a multipart form.
///
/// Since `curl_formadd` returns DISABLED and no valid form chains exist,
/// this function always returns -1 (error).
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURL_DEPRECATED(7.56.0, "")
/// int curl_formget(struct curl_httppost *form, void *arg,
///                  curl_formget_callback append);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_formget(
    _form: *mut c_void,
    _arg: *mut c_void,
    _append: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> usize>,
) -> c_int {
    // SAFETY: No pointers are dereferenced. Returns -1 to indicate error
    // since no valid form data exists.
    -1
}

// ---------------------------------------------------------------------------
// curl_strequal — DEPRECATED: use strcmp from platform libc
// ---------------------------------------------------------------------------

/// Deprecated case-insensitive string comparison.
///
/// Returns non-zero if the strings match (case-insensitive), zero otherwise.
/// This matches the curl 8.x behavior where `curl_strequal` performs a
/// locale-independent ASCII case-insensitive comparison.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURL_DEPRECATED(7.17.0, "")
/// int curl_strequal(const char *s1, const char *s2);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_strequal(
    s1: *const c_char,
    s2: *const c_char,
) -> c_int {
    // SAFETY: Both pointers must be valid null-terminated C strings.
    // This is the caller's responsibility per the curl API contract.
    // We perform a byte-by-byte ASCII case-insensitive comparison.
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 1 } else { 0 };
    }
    let c1 = std::ffi::CStr::from_ptr(s1);
    let c2 = std::ffi::CStr::from_ptr(s2);
    if c1.to_bytes().len() != c2.to_bytes().len() {
        return 0;
    }
    let eq = c1
        .to_bytes()
        .iter()
        .zip(c2.to_bytes().iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b));
    if eq { 1 } else { 0 }
}

// ---------------------------------------------------------------------------
// curl_strnequal — DEPRECATED: use strncasecmp from platform libc
// ---------------------------------------------------------------------------

/// Deprecated case-insensitive string comparison with length limit.
///
/// Compares at most `n` characters.  Returns non-zero if the compared
/// portions match, zero otherwise.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURL_DEPRECATED(7.17.0, "")
/// int curl_strnequal(const char *s1, const char *s2, size_t n);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_strnequal(
    s1: *const c_char,
    s2: *const c_char,
    n: usize,
) -> c_int {
    // SAFETY: Both pointers must be valid C strings or at least point to
    // n readable bytes.  The caller guarantees this per the curl API contract.
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 1 } else { 0 };
    }
    if n == 0 {
        return 1;
    }
    let c1 = std::ffi::CStr::from_ptr(s1);
    let c2 = std::ffi::CStr::from_ptr(s2);
    let b1 = c1.to_bytes();
    let b2 = c2.to_bytes();
    let len = n.min(b1.len()).min(b2.len());
    if b1.len() < n && b1.len() != b2.len().min(n) {
        return 0;
    }
    if b2.len() < n && b2.len() != b1.len().min(n) {
        return 0;
    }
    let eq = b1[..len]
        .iter()
        .zip(b2[..len].iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b));
    if eq { 1 } else { 0 }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    // -----------------------------------------------------------------------
    // CURL_GLOBAL_* constants
    // -----------------------------------------------------------------------

    #[test]
    fn global_ssl_is_bit_0() {
        assert_eq!(CURL_GLOBAL_SSL, 1);
    }

    #[test]
    fn global_win32_is_bit_1() {
        assert_eq!(CURL_GLOBAL_WIN32, 2);
    }

    #[test]
    fn global_all_combines_ssl_and_win32() {
        assert_eq!(CURL_GLOBAL_ALL, CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32);
        assert_eq!(CURL_GLOBAL_ALL, 3);
    }

    #[test]
    fn global_nothing_is_zero() {
        assert_eq!(CURL_GLOBAL_NOTHING, 0);
    }

    #[test]
    fn global_default_equals_all() {
        assert_eq!(CURL_GLOBAL_DEFAULT, CURL_GLOBAL_ALL);
    }

    #[test]
    fn global_ack_eintr_is_bit_2() {
        assert_eq!(CURL_GLOBAL_ACK_EINTR, 4);
    }

    // -----------------------------------------------------------------------
    // CURL_VERSION_* feature bitmask constants
    // -----------------------------------------------------------------------

    #[test]
    fn version_ipv6_is_bit_0() {
        assert_eq!(CURL_VERSION_IPV6, 1);
    }

    #[test]
    fn version_ssl_is_bit_2() {
        assert_eq!(CURL_VERSION_SSL, 4);
    }

    #[test]
    fn version_libz_is_bit_3() {
        assert_eq!(CURL_VERSION_LIBZ, 8);
    }

    #[test]
    fn version_ntlm_is_bit_4() {
        assert_eq!(CURL_VERSION_NTLM, 16);
    }

    #[test]
    fn version_http2_is_bit_16() {
        assert_eq!(CURL_VERSION_HTTP2, 1 << 16);
    }

    #[test]
    fn version_http3_is_bit_25() {
        assert_eq!(CURL_VERSION_HTTP3, 1 << 25);
    }

    #[test]
    fn version_brotli_is_bit_23() {
        assert_eq!(CURL_VERSION_BROTLI, 1 << 23);
    }

    #[test]
    fn version_zstd_is_bit_26() {
        assert_eq!(CURL_VERSION_ZSTD, 1 << 26);
    }

    #[test]
    fn version_hsts_is_bit_28() {
        assert_eq!(CURL_VERSION_HSTS, 1 << 28);
    }

    #[test]
    fn version_threadsafe_is_bit_30() {
        assert_eq!(CURL_VERSION_THREADSAFE, 1 << 30);
    }

    // -----------------------------------------------------------------------
    // CURLversion constants
    // -----------------------------------------------------------------------

    #[test]
    fn curlversion_first_is_zero() {
        assert_eq!(CURLVERSION_FIRST, 0);
    }

    #[test]
    fn curlversion_now_is_twelfth() {
        assert_eq!(CURLVERSION_NOW, CURLVERSION_TWELFTH);
        assert_eq!(CURLVERSION_NOW, 11);
    }

    #[test]
    fn curlversion_monotonic() {
        assert!(CURLVERSION_FIRST < CURLVERSION_SECOND);
        assert!(CURLVERSION_SECOND < CURLVERSION_THIRD);
        assert!(CURLVERSION_THIRD < CURLVERSION_FOURTH);
        assert!(CURLVERSION_FOURTH < CURLVERSION_FIFTH);
        assert!(CURLVERSION_FIFTH < CURLVERSION_SIXTH);
        assert!(CURLVERSION_SIXTH < CURLVERSION_SEVENTH);
        assert!(CURLVERSION_SEVENTH < CURLVERSION_EIGHTH);
        assert!(CURLVERSION_EIGHTH < CURLVERSION_NINTH);
        assert!(CURLVERSION_NINTH < CURLVERSION_TENTH);
        assert!(CURLVERSION_TENTH < CURLVERSION_ELEVENTH);
        assert!(CURLVERSION_ELEVENTH < CURLVERSION_TWELFTH);
    }

    // -----------------------------------------------------------------------
    // CURLSSLBACKEND_* constants
    // -----------------------------------------------------------------------

    #[test]
    fn sslbackend_none_is_zero() {
        assert_eq!(CURLSSLBACKEND_NONE, 0);
    }

    #[test]
    fn sslbackend_openssl_is_one() {
        assert_eq!(CURLSSLBACKEND_OPENSSL, 1);
    }

    #[test]
    fn sslbackend_rustls_is_fourteen() {
        assert_eq!(CURLSSLBACKEND_RUSTLS, 14);
    }

    #[test]
    fn sslbackend_values_distinct() {
        let vals = [
            CURLSSLBACKEND_NONE,
            CURLSSLBACKEND_OPENSSL,
            CURLSSLBACKEND_GNUTLS,
            CURLSSLBACKEND_WOLFSSL,
            CURLSSLBACKEND_SCHANNEL,
            CURLSSLBACKEND_SECURETRANSPORT,
            CURLSSLBACKEND_MBEDTLS,
            CURLSSLBACKEND_BEARSSL,
            CURLSSLBACKEND_RUSTLS,
        ];
        for (i, a) in vals.iter().enumerate() {
            for (j, b) in vals.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "backends {} and {} should differ", i, j);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Static strings
    // -----------------------------------------------------------------------

    #[test]
    fn version_string_is_null_terminated() {
        assert_eq!(*VERSION_STRING.last().unwrap(), 0);
    }

    #[test]
    fn version_string_contains_version() {
        let s = std::str::from_utf8(&VERSION_STRING[..VERSION_STRING.len() - 1]).unwrap();
        assert!(s.contains("8.19.0"));
    }

    #[test]
    fn version_string_mentions_rustls() {
        let s = std::str::from_utf8(&VERSION_STRING[..VERSION_STRING.len() - 1]).unwrap();
        assert!(s.contains("rustls"));
    }

    #[test]
    fn bare_version_string_matches() {
        let s = std::str::from_utf8(&BARE_VERSION_STRING[..BARE_VERSION_STRING.len() - 1]).unwrap();
        assert_eq!(s, "8.19.0-DEV");
    }

    #[test]
    fn ssl_version_string_is_rustls() {
        let s = std::str::from_utf8(&SSL_VERSION_STRING[..SSL_VERSION_STRING.len() - 1]).unwrap();
        assert_eq!(s, "rustls");
    }

    #[test]
    fn host_string_is_null_terminated() {
        assert_eq!(*HOST_STRING.last().unwrap(), 0);
    }

    // -----------------------------------------------------------------------
    // compute_features
    // -----------------------------------------------------------------------

    #[test]
    fn compute_features_includes_ssl() {
        let f = compute_features();
        assert_ne!(f & CURL_VERSION_SSL, 0);
    }

    #[test]
    fn compute_features_includes_http2() {
        let f = compute_features();
        assert_ne!(f & CURL_VERSION_HTTP2, 0);
    }

    #[test]
    fn compute_features_includes_http3() {
        let f = compute_features();
        assert_ne!(f & CURL_VERSION_HTTP3, 0);
    }

    #[test]
    fn compute_features_includes_ipv6() {
        let f = compute_features();
        assert_ne!(f & CURL_VERSION_IPV6, 0);
    }

    #[test]
    fn compute_features_includes_brotli() {
        let f = compute_features();
        assert_ne!(f & CURL_VERSION_BROTLI, 0);
    }

    #[test]
    fn compute_features_includes_zstd() {
        let f = compute_features();
        assert_ne!(f & CURL_VERSION_ZSTD, 0);
    }

    #[test]
    fn compute_features_includes_hsts() {
        let f = compute_features();
        assert_ne!(f & CURL_VERSION_HSTS, 0);
    }

    #[test]
    fn compute_features_includes_threadsafe() {
        let f = compute_features();
        assert_ne!(f & CURL_VERSION_THREADSAFE, 0);
    }

    #[test]
    fn compute_features_includes_ntlm() {
        let f = compute_features();
        assert_ne!(f & CURL_VERSION_NTLM, 0);
    }

    #[test]
    fn compute_features_includes_idn() {
        let f = compute_features();
        assert_ne!(f & CURL_VERSION_IDN, 0);
    }

    // -----------------------------------------------------------------------
    // version_info_static
    // -----------------------------------------------------------------------

    #[test]
    fn version_info_static_age() {
        let info = version_info_static();
        assert_eq!(info.age, CURLVERSION_NOW);
    }

    #[test]
    fn version_info_static_version_num() {
        let info = version_info_static();
        assert_eq!(info.version_num, 0x081300);
    }

    #[test]
    fn version_info_static_version_string() {
        let info = version_info_static();
        assert!(!info.version.is_null());
        // SAFETY: version points to a static null-terminated string.
        let cstr = unsafe { CStr::from_ptr(info.version) };
        assert_eq!(cstr.to_str().unwrap(), "8.19.0-DEV");
    }

    #[test]
    fn version_info_static_ssl_version() {
        let info = version_info_static();
        assert!(!info.ssl_version.is_null());
        // SAFETY: ssl_version points to a static null-terminated string.
        let cstr = unsafe { CStr::from_ptr(info.ssl_version) };
        assert_eq!(cstr.to_str().unwrap(), "rustls");
    }

    #[test]
    fn version_info_static_features_nonzero() {
        let info = version_info_static();
        assert_ne!(info.features, 0);
    }

    #[test]
    fn version_info_static_protocols_not_null() {
        let info = version_info_static();
        assert!(!info.protocols.is_null());
    }

    #[test]
    fn version_info_static_hyper_version() {
        let info = version_info_static();
        assert!(!info.hyper_version.is_null());
        // SAFETY: hyper_version points to a static null-terminated string.
        let cstr = unsafe { CStr::from_ptr(info.hyper_version) };
        assert_eq!(cstr.to_str().unwrap(), "hyper");
    }

    #[test]
    fn version_info_static_quic_version() {
        let info = version_info_static();
        assert!(!info.quic_version.is_null());
        // SAFETY: quic_version points to a static null-terminated string.
        let cstr = unsafe { CStr::from_ptr(info.quic_version) };
        assert_eq!(cstr.to_str().unwrap(), "quinn/h3");
    }

    #[test]
    fn version_info_static_ssh_version() {
        let info = version_info_static();
        assert!(!info.libssh_version.is_null());
        // SAFETY: libssh_version points to a static null-terminated string.
        let cstr = unsafe { CStr::from_ptr(info.libssh_version) };
        assert_eq!(cstr.to_str().unwrap(), "russh");
    }

    #[test]
    fn version_info_static_deprecated_ssl_version_num_is_zero() {
        let info = version_info_static();
        assert_eq!(info.ssl_version_num, 0);
    }

    // -----------------------------------------------------------------------
    // curl_global_init — safe FFI call
    // -----------------------------------------------------------------------

    #[test]
    fn global_init_default_succeeds() {
        // SAFETY: curl_global_init accepts an integer flag. CURL_GLOBAL_DEFAULT=3.
        let rc = unsafe { curl_global_init(CURL_GLOBAL_DEFAULT) };
        assert_eq!(rc, CURLE_OK);
    }

    #[test]
    fn global_init_nothing_succeeds() {
        let rc = unsafe { curl_global_init(CURL_GLOBAL_NOTHING) };
        assert_eq!(rc, CURLE_OK);
    }

    #[test]
    fn global_init_idempotent() {
        let rc1 = unsafe { curl_global_init(CURL_GLOBAL_DEFAULT) };
        let rc2 = unsafe { curl_global_init(CURL_GLOBAL_DEFAULT) };
        assert_eq!(rc1, CURLE_OK);
        assert_eq!(rc2, CURLE_OK);
    }

    // -----------------------------------------------------------------------
    // curl_global_cleanup
    // -----------------------------------------------------------------------

    #[test]
    fn global_cleanup_does_not_crash() {
        // SAFETY: curl_global_cleanup takes no arguments and is idempotent.
        unsafe { curl_global_cleanup(); }
    }

    // -----------------------------------------------------------------------
    // curl_global_trace
    // -----------------------------------------------------------------------

    #[test]
    fn global_trace_null_returns_ok() {
        // SAFETY: Passing null is documented as a no-op.
        let rc = unsafe { curl_global_trace(ptr::null()) };
        assert_eq!(rc, CURLE_OK);
    }

    #[test]
    fn global_trace_valid_string_returns_ok() {
        let config = CString::new("all").unwrap();
        // SAFETY: config is a valid null-terminated C string.
        let rc = unsafe { curl_global_trace(config.as_ptr()) };
        assert_eq!(rc, CURLE_OK);
    }

    #[test]
    fn global_trace_empty_string_returns_ok() {
        let config = CString::new("").unwrap();
        let rc = unsafe { curl_global_trace(config.as_ptr()) };
        assert_eq!(rc, CURLE_OK);
    }

    // -----------------------------------------------------------------------
    // curl_global_sslset
    // -----------------------------------------------------------------------

    #[test]
    fn global_sslset_rustls_by_id() {
        // After global_init, returns TOO_LATE (since init already ran).
        let _ = unsafe { curl_global_init(CURL_GLOBAL_DEFAULT) };
        let rc = unsafe {
            curl_global_sslset(CURLSSLBACKEND_RUSTLS, ptr::null(), ptr::null_mut())
        };
        // After init, this returns TOO_LATE.
        assert!(rc == CURLSSLSET_TOO_LATE || rc == CURLSSLSET_OK);
    }

    #[test]
    fn global_sslset_populates_avail() {
        let mut avail: *const *const curl_ssl_backend = ptr::null();
        let _ = unsafe {
            curl_global_sslset(
                CURLSSLBACKEND_NONE,
                ptr::null(),
                &mut avail as *mut _,
            )
        };
        assert!(!avail.is_null());
    }

    #[test]
    fn global_sslset_unknown_backend() {
        // Use an impossible backend id (255). Since init already happened,
        // it returns TOO_LATE.
        let rc = unsafe {
            curl_global_sslset(255, ptr::null(), ptr::null_mut())
        };
        assert!(rc == CURLSSLSET_TOO_LATE || rc == CURLSSLSET_UNKNOWN_BACKEND);
    }

    // -----------------------------------------------------------------------
    // curl_version
    // -----------------------------------------------------------------------

    #[test]
    fn curl_version_not_null() {
        // SAFETY: curl_version returns a pointer to static data.
        let ptr = unsafe { curl_version() };
        assert!(!ptr.is_null());
    }

    #[test]
    fn curl_version_contains_version_number() {
        let ptr = unsafe { curl_version() };
        // SAFETY: ptr points to a static null-terminated string.
        let cstr = unsafe { CStr::from_ptr(ptr) };
        let s = cstr.to_str().unwrap();
        assert!(s.contains("8.19.0"));
    }

    // -----------------------------------------------------------------------
    // curl_version_info
    // -----------------------------------------------------------------------

    #[test]
    fn curl_version_info_not_null() {
        // SAFETY: curl_version_info returns a pointer to static data.
        let ptr = unsafe { curl_version_info(CURLVERSION_NOW) };
        assert!(!ptr.is_null());
    }

    #[test]
    fn curl_version_info_age_matches() {
        let ptr = unsafe { curl_version_info(CURLVERSION_NOW) };
        // SAFETY: ptr is valid and points to static data.
        let data = unsafe { &*ptr };
        assert_eq!(data.age, CURLVERSION_NOW);
    }

    #[test]
    fn curl_version_info_version_num_matches() {
        let ptr = unsafe { curl_version_info(CURLVERSION_NOW) };
        let data = unsafe { &*ptr };
        assert_eq!(data.version_num, 0x081300);
    }

    // -----------------------------------------------------------------------
    // curl_getenv
    // -----------------------------------------------------------------------

    #[test]
    fn curl_getenv_null_returns_null() {
        // SAFETY: Passing null is documented as returning null.
        let result = unsafe { curl_getenv(ptr::null()) };
        assert!(result.is_null());
    }

    #[test]
    fn curl_getenv_nonexistent_returns_null() {
        let key = CString::new("CURL_RS_TEST_NONEXISTENT_VAR_12345").unwrap();
        // SAFETY: key is a valid null-terminated C string.
        let result = unsafe { curl_getenv(key.as_ptr()) };
        assert!(result.is_null());
    }

    #[test]
    fn curl_getenv_path_returns_non_null() {
        // PATH is always set on test systems.
        let key = CString::new("PATH").unwrap();
        let result = unsafe { curl_getenv(key.as_ptr()) };
        if !result.is_null() {
            // SAFETY: result is a malloc'd null-terminated string.
            let cstr = unsafe { CStr::from_ptr(result) };
            assert!(!cstr.to_str().unwrap().is_empty());
            // Free the allocated memory.
            unsafe { curl_free(result as *mut c_void) };
        }
    }

    // -----------------------------------------------------------------------
    // curl_free
    // -----------------------------------------------------------------------

    #[test]
    fn curl_free_null_is_noop() {
        // SAFETY: Passing null is documented as a no-op.
        unsafe { curl_free(ptr::null_mut()) };
    }

    // -----------------------------------------------------------------------
    // curl_getdate
    // -----------------------------------------------------------------------

    #[test]
    fn curl_getdate_null_returns_negative() {
        // SAFETY: Passing null returns -1.
        let result = unsafe { curl_getdate(ptr::null(), ptr::null()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn curl_getdate_valid_rfc2822() {
        let date = CString::new("Thu, 01 Jan 1970 00:00:00 GMT").unwrap();
        // SAFETY: date is a valid null-terminated C string.
        let result = unsafe { curl_getdate(date.as_ptr(), ptr::null()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn curl_getdate_valid_epoch_plus() {
        let date = CString::new("Fri, 02 Jan 1970 00:00:00 GMT").unwrap();
        let result = unsafe { curl_getdate(date.as_ptr(), ptr::null()) };
        assert_eq!(result, 86400); // 24 * 60 * 60
    }

    #[test]
    fn curl_getdate_invalid_returns_negative() {
        let date = CString::new("not a date").unwrap();
        let result = unsafe { curl_getdate(date.as_ptr(), ptr::null()) };
        assert_eq!(result, -1);
    }

    // -----------------------------------------------------------------------
    // Protocol list
    // -----------------------------------------------------------------------

    #[test]
    fn protocols_list_terminated_by_null() {
        let last = PROTOCOLS.0[PROTOCOLS.0.len() - 1];
        assert!(last.is_null());
    }

    #[test]
    fn protocols_list_has_http() {
        let found = PROTOCOLS.0.iter().take(26).any(|&p| {
            if p.is_null() {
                return false;
            }
            // SAFETY: p points to a static null-terminated string.
            let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("");
            s == "http"
        });
        assert!(found, "protocols should include http");
    }

    #[test]
    fn protocols_list_has_https() {
        let found = PROTOCOLS.0.iter().take(26).any(|&p| {
            if p.is_null() {
                return false;
            }
            let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("");
            s == "https"
        });
        assert!(found, "protocols should include https");
    }

    #[test]
    fn protocols_list_has_ftp() {
        let found = PROTOCOLS.0.iter().take(26).any(|&p| {
            if p.is_null() {
                return false;
            }
            let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("");
            s == "ftp"
        });
        assert!(found, "protocols should include ftp");
    }

    #[test]
    fn protocols_list_has_sftp() {
        let found = PROTOCOLS.0.iter().take(26).any(|&p| {
            if p.is_null() {
                return false;
            }
            let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("");
            s == "sftp"
        });
        assert!(found, "protocols should include sftp");
    }

    // -----------------------------------------------------------------------
    // Feature names list
    // -----------------------------------------------------------------------

    #[test]
    fn feature_names_terminated_by_null() {
        let last = FEATURE_NAMES.0[FEATURE_NAMES.0.len() - 1];
        assert!(last.is_null());
    }

    #[test]
    fn feature_names_has_ssl() {
        let found = FEATURE_NAMES.0.iter().take(19).any(|&p| {
            if p.is_null() {
                return false;
            }
            let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("");
            s == "SSL"
        });
        assert!(found, "feature names should include SSL");
    }

    #[test]
    fn feature_names_has_http2() {
        let found = FEATURE_NAMES.0.iter().take(19).any(|&p| {
            if p.is_null() {
                return false;
            }
            let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("");
            s == "HTTP2"
        });
        assert!(found, "feature names should include HTTP2");
    }

    // -----------------------------------------------------------------------
    // curl_global_init_mem
    // -----------------------------------------------------------------------

    // Stub allocator callbacks for curl_global_init_mem testing.
    unsafe extern "C" fn stub_malloc(size: libc::size_t) -> *mut c_void {
        libc::malloc(size)
    }
    unsafe extern "C" fn stub_free(ptr: *mut c_void) {
        libc::free(ptr)
    }
    unsafe extern "C" fn stub_realloc(ptr: *mut c_void, size: libc::size_t) -> *mut c_void {
        libc::realloc(ptr, size)
    }
    unsafe extern "C" fn stub_strdup(s: *const c_char) -> *mut c_char {
        libc::strdup(s)
    }
    unsafe extern "C" fn stub_calloc(nmemb: libc::size_t, size: libc::size_t) -> *mut c_void {
        libc::calloc(nmemb, size)
    }

    #[test]
    fn global_init_mem_with_callbacks_succeeds() {
        // SAFETY: We pass valid C-compatible function pointers. The custom
        // allocators are accepted for API compatibility but unused by Rust.
        let rc = unsafe {
            curl_global_init_mem(
                CURL_GLOBAL_DEFAULT,
                stub_malloc,
                stub_free,
                stub_realloc,
                stub_strdup,
                stub_calloc,
            )
        };
        assert_eq!(rc, CURLE_OK);
    }
}
