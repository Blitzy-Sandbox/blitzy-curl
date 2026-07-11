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
//! ## Crate responsibilities
//!
//! As the crate root, this file owns three things:
//!
//! 1. **Module tree** — it declares every sibling module (`easy`, `multi`, `share`, `global`,
//!    `slist`, `url`, `ws`, `mprintf`, `options`, `header`) so the crate compiles as a unit and
//!    `cbindgen` can parse the whole `extern "C"` surface in one pass (`build.rs`).
//! 2. **Shared boundary helpers** — the raw-pointer conversions, the `Result` → `CURLcode`
//!    bridge, and the panic guard live here, in one centrally-audited [`helpers`] module, so
//!    every `unsafe` operation carries its `// SAFETY:` justification in exactly one place.
//! 3. **Version symbols** — the two `CURL_EXTERN` version entry points, [`curl_version`] and
//!    [`curl_version_info`], together with the age-versioned [`curl_version_info_data`] ABI
//!    struct and the [`CURLversion`] enum, are defined and exported here.
//!
//! ## The frozen `CURLcode` contract
//!
//! The public C surface is anchored by the [`CURLcode`] result-code enum defined below. Its
//! integer values are a **frozen ABI contract** transcribed verbatim from
//! `include/curl/curl.h`: a consumer that hard-codes `CURLE_OPERATION_TIMEDOUT == 28` must
//! keep working, so the discriminants here are pinned and unit-tested against the authoritative
//! [`curl_rs_lib::error::CurlCode`] enum. The build script (`build.rs`) feeds this crate to
//! `cbindgen`, which renders these declarations into a verification header used to byte-diff
//! the generated output against the committed `include/curl/curl.h` (AAP §0.6.1). `cbindgen`
//! never overwrites the committed header.
//!
//! ## Unsafe policy (AAP §0.6.2 / §0.7.2)
//!
//! `curl-rs-lib` is compiled with `#![forbid(unsafe_code)]`; this boundary crate is the sole
//! place `unsafe` is allowed. This file therefore deliberately does **not** forbid unsafe.
//! Every `unsafe` block or item below carries a `// SAFETY:` comment (and every `unsafe fn` a
//! `# Safety` doc section) stating the invariant it upholds — enforced by a CI grep and by
//! AddressSanitizer. No panic is allowed to unwind across the FFI boundary: [`helpers::ffi_guard`]
//! converts a panic into an error return for entry points where a panic is conceivable.

// The ABI requires C-style type names (`CURLcode`, `curl_version_info_data`, `CURLversion`,
// `curl_slist`, `curl_ws_frame`, …) and the C `curl_*` snake-case symbol spelling, both of
// which violate Rust's usual casing conventions. These two crate-wide allows are the minimal
// set needed to transcribe the C ABI faithfully; no other conventions are relaxed. Note the
// intentional ABSENCE of `#![forbid(unsafe_code)]` — see the crate docs above.
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use libc::{c_char, c_int, c_long, c_uint};
use std::ffi::CString;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Module tree — every sibling `curl_*` entry-point module (AAP §0.3.1). Declaring the whole
// tree here lets the crate compile as a unit and lets `cbindgen` parse every `extern "C"`
// symbol in a single pass. The shared boundary helpers defined further down in this file are
// consumed by these modules.
// ---------------------------------------------------------------------------

pub mod easy;
pub mod global;
pub mod header;
pub mod mprintf;
pub mod multi;
pub mod options;
pub mod share;
pub mod slist;
pub mod url;
pub mod ws;

// Convenience re-export so the boundary helpers can be reached as `crate::<name>` in addition
// to `crate::helpers::<name>` from the sibling modules.
#[allow(unused_imports)]
pub(crate) use self::helpers::{
    as_mut, as_ref, box_from_raw, box_into_raw, code_from_c_int, cstr_to_str, ffi_guard,
    str_to_c_owned, to_curlcode,
};

/// libcurl result codes (`CURLcode`).
///
/// This is a language-faithful transcription of the `CURLcode` enumeration in
/// `include/curl/curl.h` for the curl 8.19.0-DEV reference tree. Every discriminant — including
/// the retained `CURLE_OBSOLETE*` gap-fillers — matches the C header exactly so the integer
/// contract is preserved across the FFI boundary (`cbindgen` regenerates the C declaration
/// from this definition). The variant names use curl's `SCREAMING_SNAKE_CASE` spelling and
/// are therefore permitted to break Rust's usual type-casing convention (see the crate-level
/// `allow(non_camel_case_types)`).
///
/// The representation is `i32`, matching curl's C `enum` (a plain `int`) and the
/// [`curl_rs_lib::error::CurlCode`] mirror in the core crate; a fieldless `#[repr(i32)]`
/// enum can be cast to its discriminant with `code as i32`, which is exactly the value an
/// FFI caller observes.
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

// ===========================================================================
// Shared FFI boundary helpers
// ===========================================================================

/// Shared, centrally-audited FFI boundary utilities.
///
/// Every raw-pointer conversion the sibling `curl_*` modules perform is funnelled through
/// these helpers so the `unsafe` operations — and the `// SAFETY:` invariants that justify
/// them — live in exactly one audited place (AAP §0.6.2). Sibling modules reach them as
/// `crate::helpers::<name>` or, via the crate-root re-export, as `crate::<name>`.
///
/// These helpers implement the opaque-handle mapping between C pointers and heap-boxed core
/// types:
/// * `CURL*`   ↔ `Box<curl_rs_lib::Easy>`
/// * `CURLM*`  ↔ `Box<curl_rs_lib::multi::Multi>`
/// * `CURLU*`  ↔ `Box<curl_rs_lib::urlapi::Url>`
/// * `CURLSH*` ↔ shared state (`Arc<Mutex<…>>`; `share.rs` boxes the `Arc`)
///
/// The boxing helpers are generic over the concrete core type `T`, so this file needs no
/// direct dependency on those concrete types.
mod helpers {
    // These utilities are the crate's shared boundary toolkit; during incremental build-order
    // development (AAP §0.7.3 step b) some sibling `curl_*` entry-point modules that consume
    // them may still be stubs, so a scoped `dead_code` allow keeps `-D warnings` clean without
    // masking dead code elsewhere in the crate.
    #![allow(dead_code)]
    // Require every unsafe operation to sit inside an explicit `unsafe { … }` block, even
    // within an `unsafe fn`, so each carries its own adjacent `// SAFETY:` note as mandated by
    // AAP §0.7.2. (Without this, an `unsafe fn` body is itself an unsafe context and inner
    // blocks would be flagged `unused_unsafe`.)
    #![deny(unsafe_op_in_unsafe_fn)]

    use curl_rs_lib::error::{from_i32, CurlCode, Error};
    use libc::{c_char, c_int};
    use std::ffi::{CStr, CString};

    /// Move `value` onto the heap and hand the raw owning pointer to the C side.
    ///
    /// This is the outbound half of the opaque-handle mapping. It performs no `unsafe`:
    /// producing the pointer is safe; only *reclaiming* it later (see [`box_from_raw`]) is
    /// unsafe.
    #[inline]
    pub(crate) fn box_into_raw<T>(value: T) -> *mut T {
        Box::into_raw(Box::new(value))
    }

    /// Reclaim a `Box<T>` previously produced by [`box_into_raw`] / [`Box::into_raw`].
    ///
    /// Returns `None` for a null pointer (so a C caller passing `NULL` is handled gracefully),
    /// otherwise `Some(box)`, transferring ownership back to Rust for drop or reuse.
    ///
    /// # Safety
    /// The caller must guarantee that `ptr` is either null or was produced by [`box_into_raw`]
    /// / [`Box::into_raw`] for the **same** `T`, is properly aligned and non-dangling, and is
    /// not used again after this call. Passing a pointer twice, or a pointer to a different
    /// type/allocation, is undefined behavior (double-free / use-after-free / type confusion).
    #[inline]
    pub(crate) unsafe fn box_from_raw<T>(ptr: *mut T) -> Option<Box<T>> {
        if ptr.is_null() {
            None
        } else {
            // SAFETY: `ptr` is non-null here and, per the documented contract, was produced by
            // `Box::into_raw` for the same `T` and not reclaimed before; reconstructing the
            // `Box` transfers ownership back exactly once.
            Some(unsafe { Box::from_raw(ptr) })
        }
    }

    /// Reconstitute a shared reference from a C pointer, null-checked.
    ///
    /// # Safety
    /// The caller must guarantee that, when non-null, `ptr` points to a valid, initialized `T`
    /// that outlives `'a` and is not mutably aliased for the duration of `'a`.
    #[inline]
    pub(crate) unsafe fn as_ref<'a, T>(ptr: *const T) -> Option<&'a T> {
        if ptr.is_null() {
            None
        } else {
            // SAFETY: `ptr` is non-null and, per the documented contract, points to a valid `T`
            // living at least for `'a` with no conflicting mutable alias, so forming a shared
            // reference is sound.
            Some(unsafe { &*ptr })
        }
    }

    /// Reconstitute an exclusive reference from a C pointer, null-checked.
    ///
    /// # Safety
    /// The caller must guarantee that, when non-null, `ptr` points to a valid, initialized `T`
    /// that outlives `'a` and that no other reference (shared or exclusive) to the same `T` is
    /// live for the duration of `'a`.
    #[inline]
    pub(crate) unsafe fn as_mut<'a, T>(ptr: *mut T) -> Option<&'a mut T> {
        if ptr.is_null() {
            None
        } else {
            // SAFETY: `ptr` is non-null and, per the documented contract, points to a valid `T`
            // living at least for `'a` with no other live alias, so forming a unique reference
            // is sound.
            Some(unsafe { &mut *ptr })
        }
    }

    /// Bridge a core-crate `Result` into the C `CURLcode` integer.
    ///
    /// `Ok(())` maps to `0` (`CURLE_OK`); `Err(e)` maps to `e.code()` converted to its frozen
    /// `i32` discriminant via `impl From<CurlCode> for i32`.
    #[inline]
    pub(crate) fn to_curlcode(r: Result<(), Error>) -> c_int {
        match r {
            Ok(()) => CurlCode::Ok.into(),
            Err(e) => e.code().into(),
        }
    }

    /// Map an inbound C `CURLcode` integer to the core-crate [`CurlCode`].
    ///
    // NOTE: the core crate exposes this conversion as the module-level function
    // `curl_rs_lib::error::from_i32` (not an associated `CurlCode::from_i32`, as an earlier
    // draft of the plan assumed). Unknown integers fall back to `CurlCode::BadFunctionArgument`,
    // exactly as the core's `from_i32` documents; callers needing to reject unknown codes
    // should use the core's fallible `TryFrom` instead.
    #[inline]
    pub(crate) fn code_from_c_int(v: c_int) -> CurlCode {
        from_i32(v)
    }

    /// Run an FFI entry-point body under a panic guard, returning `default_err` on panic.
    ///
    /// Unwinding must never cross the `extern "C"` boundary (it is undefined behavior / an
    /// abort). [`std::panic::catch_unwind`] contains any panic within Rust and converts it into
    /// `default_err` — typically the integer for `CURLE_FAILED_INIT` or another generic
    /// failure. Sibling entry points wrap their bodies in this guard wherever a panic is
    /// conceivable.
    ///
    /// The closure is [`UnwindSafe`](std::panic::UnwindSafe), so no caller can observe a broken
    /// invariant after a caught panic: an FFI entry point builds fresh local state and returns
    /// an integer, sharing no mutable state that a partially-executed body could corrupt.
    #[inline]
    pub(crate) fn ffi_guard<F>(default_err: c_int, f: F) -> c_int
    where
        F: FnOnce() -> c_int + std::panic::UnwindSafe,
    {
        std::panic::catch_unwind(f).unwrap_or(default_err)
    }

    /// Borrow a C string as a Rust `&str`, null-checked and UTF-8-validated.
    ///
    /// Returns `None` for a null pointer or for non-UTF-8 content.
    ///
    /// # Safety
    /// The caller must guarantee that, when non-null, `ptr` points to a valid NUL-terminated C
    /// string that remains allocated and unmodified for at least `'a`.
    #[inline]
    pub(crate) unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
        if ptr.is_null() {
            None
        } else {
            // SAFETY: `ptr` is non-null and, per the documented contract, points to a valid
            // NUL-terminated C string that outlives `'a`; `CStr::from_ptr` reads up to the NUL
            // terminator to form the borrow.
            unsafe { CStr::from_ptr(ptr) }.to_str().ok()
        }
    }

    /// Allocate a NUL-terminated owned copy of `s` for the C side.
    ///
    /// Returns a pointer the C side must reclaim with `curl_free` (see `global.rs`, whose
    /// `curl_free` reclaims via `CString::from_raw` — this allocator is deliberately kept
    /// symmetric with it). Returns null if `s` contains an interior NUL, which cannot be
    /// represented as a C string.
    #[inline]
    pub(crate) fn str_to_c_owned(s: &str) -> *mut c_char {
        match CString::new(s) {
            Ok(c) => c.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

// ===========================================================================
// Version symbols and their ABI types (the 2 CURL_EXTERN this file exports)
// ===========================================================================

// NOTE: the canonical version data below mirrors the intended `curl_rs_lib::version()` /
// `curl_rs_lib::VERSION` / `curl_rs_lib::VERSION_NUM` public API (AAP §0.3.1). The core crate's
// root does not yet re-export those accessors, so the spec-fixed values are defined here
// locally; they cannot drift (the specification pins them) and should be reconciled to delegate
// to `curl_rs_lib::version()` once that accessor is available.

/// The full `curl_version()` string, equal to `curl_rs_lib::version()`.
const CURL_RS_VERSION_STRING: &str =
    "curl-rs/8.19.0-DEV rustls flate2 brotli zstd hyper quinn russh";
/// The libcurl version string (`LIBCURL_VERSION`), reported in `curl_version_info_data.version`.
const CURL_RS_VERSION: &str = "8.19.0-DEV";
/// The numeric libcurl version (`LIBCURL_VERSION_NUM`, i.e. `0x081300`), reported in
/// `curl_version_info_data.version_num`.
const CURL_RS_VERSION_NUM: c_uint = 0x08_1300;

/// The `CURLversion` "age" enumeration from `include/curl/curl.h`.
///
/// Each successive `curl_version_info_data` layout revision added a new age value. The enum is
/// `#[repr(i32)]` with explicit discriminants `0..=12` matching the C header exactly, so
/// `cbindgen` and every FFI consumer observe identical integer values.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CURLversion {
    CURLVERSION_FIRST = 0,
    CURLVERSION_SECOND = 1,
    CURLVERSION_THIRD = 2,
    CURLVERSION_FOURTH = 3,
    CURLVERSION_FIFTH = 4,
    CURLVERSION_SIXTH = 5,
    CURLVERSION_SEVENTH = 6,
    CURLVERSION_EIGHTH = 7,
    CURLVERSION_NINTH = 8,
    CURLVERSION_TENTH = 9,
    CURLVERSION_ELEVENTH = 10,
    CURLVERSION_TWELFTH = 11,
    CURLVERSION_LAST = 12,
}

/// The current `curl_version_info_data` age marker
/// (`#define CURLVERSION_NOW CURLVERSION_TWELFTH` in `include/curl/curl.h`).
pub const CURLVERSION_NOW: CURLversion = CURLversion::CURLVERSION_TWELFTH;

/// Runtime version information (`curl_version_info_data`).
///
/// Field order, names, and types are transcribed **exactly** from the `struct
/// curl_version_info_data` in `include/curl/curl.h` (curl 8.19.0-DEV). This is an
/// age-versioned ABI struct: fields were appended across successive `CURLVERSION_*` ages, and
/// the `age` field records which trailing fields are valid. `#[repr(C)]` guarantees the C
/// layout so `cbindgen` regenerates a matching declaration.
#[repr(C)]
pub struct curl_version_info_data {
    /// Age of the returned struct (see [`CURLversion`]); set to [`CURLVERSION_NOW`].
    pub age: CURLversion,
    /// `LIBCURL_VERSION` human-readable string.
    pub version: *const c_char,
    /// `LIBCURL_VERSION_NUM` numeric version.
    pub version_num: c_uint,
    /// OS/host/cpu/machine string.
    pub host: *const c_char,
    /// Feature bitmask (see the `CURL_VERSION_*` constants).
    pub features: c_int,
    /// TLS backend human-readable version string.
    pub ssl_version: *const c_char,
    /// Not used anymore; always 0 (kept for ABI parity).
    pub ssl_version_num: c_long,
    /// zlib-equivalent human-readable version string.
    pub libz_version: *const c_char,
    /// NULL-terminated array of supported protocol scheme strings.
    pub protocols: *const *const c_char,
    // --- fields added in CURLVERSION_SECOND ---
    /// c-ares version string (NULL — replaced by the Tokio resolver).
    pub ares: *const c_char,
    /// c-ares numeric version (0).
    pub ares_num: c_int,
    // --- field added in CURLVERSION_THIRD ---
    /// libidn version string (NULL — IDN provided by the pure-Rust `idna` crate).
    pub libidn: *const c_char,
    // --- fields added in CURLVERSION_FOURTH ---
    /// iconv numeric version (0).
    pub iconv_ver_num: c_int,
    /// SSH backend human-readable version string.
    pub libssh_version: *const c_char,
    // --- fields added in CURLVERSION_FIFTH ---
    /// Numeric Brotli version `(MAJOR << 24) | (MINOR << 12) | PATCH`.
    pub brotli_ver_num: c_uint,
    /// Brotli human-readable version string.
    pub brotli_version: *const c_char,
    // --- fields added in CURLVERSION_SIXTH ---
    /// Numeric nghttp2 version `(MAJOR << 16) | (MINOR << 8) | PATCH`.
    pub nghttp2_ver_num: c_uint,
    /// nghttp2 human-readable version string (NULL — HTTP/2 via `h2`/`hyper`).
    pub nghttp2_version: *const c_char,
    /// QUIC (+ HTTP/3) backend string, or NULL.
    pub quic_version: *const c_char,
    // --- fields added in CURLVERSION_SEVENTH ---
    /// Built-in default `CURLOPT_CAINFO`, or NULL.
    pub cainfo: *const c_char,
    /// Built-in default `CURLOPT_CAPATH`, or NULL.
    pub capath: *const c_char,
    // --- fields added in CURLVERSION_EIGHTH ---
    /// Numeric Zstd version `(MAJOR << 24) | (MINOR << 12) | PATCH`.
    pub zstd_ver_num: c_uint,
    /// Zstd human-readable version string.
    pub zstd_version: *const c_char,
    // --- field added in CURLVERSION_NINTH ---
    /// Hyper (HTTP engine) human-readable version string.
    pub hyper_version: *const c_char,
    // --- field added in CURLVERSION_TENTH ---
    /// libgsasl human-readable version string (NULL — not used).
    pub gsasl_version: *const c_char,
    // --- field added in CURLVERSION_ELEVENTH ---
    /// NULL-terminated array of human-readable feature-name strings.
    pub feature_names: *const *const c_char,
    // --- field added in CURLVERSION_TWELFTH ---
    /// RTMP human-readable version string (NULL — RTMP/RTMPS dropped, AAP §0.2.2).
    pub rtmp_version: *const c_char,
}

// ---------------------------------------------------------------------------
// Feature bitmask constants (`CURL_VERSION_*`), transcribed verbatim from
// `include/curl/curl.h`. All are reproduced for ABI/header parity; only the subset in
// `BUILT_FEATURES` is actually set for this workspace.
// ---------------------------------------------------------------------------

pub const CURL_VERSION_IPV6: c_int = 1 << 0;
pub const CURL_VERSION_KERBEROS4: c_int = 1 << 1;
pub const CURL_VERSION_SSL: c_int = 1 << 2;
pub const CURL_VERSION_LIBZ: c_int = 1 << 3;
pub const CURL_VERSION_NTLM: c_int = 1 << 4;
pub const CURL_VERSION_GSSNEGOTIATE: c_int = 1 << 5;
pub const CURL_VERSION_DEBUG: c_int = 1 << 6;
pub const CURL_VERSION_ASYNCHDNS: c_int = 1 << 7;
pub const CURL_VERSION_SPNEGO: c_int = 1 << 8;
pub const CURL_VERSION_LARGEFILE: c_int = 1 << 9;
pub const CURL_VERSION_IDN: c_int = 1 << 10;
pub const CURL_VERSION_SSPI: c_int = 1 << 11;
pub const CURL_VERSION_CONV: c_int = 1 << 12;
pub const CURL_VERSION_CURLDEBUG: c_int = 1 << 13;
pub const CURL_VERSION_TLSAUTH_SRP: c_int = 1 << 14;
pub const CURL_VERSION_NTLM_WB: c_int = 1 << 15;
pub const CURL_VERSION_HTTP2: c_int = 1 << 16;
pub const CURL_VERSION_GSSAPI: c_int = 1 << 17;
pub const CURL_VERSION_KERBEROS5: c_int = 1 << 18;
pub const CURL_VERSION_UNIX_SOCKETS: c_int = 1 << 19;
pub const CURL_VERSION_PSL: c_int = 1 << 20;
pub const CURL_VERSION_HTTPS_PROXY: c_int = 1 << 21;
pub const CURL_VERSION_MULTI_SSL: c_int = 1 << 22;
pub const CURL_VERSION_BROTLI: c_int = 1 << 23;
pub const CURL_VERSION_ALTSVC: c_int = 1 << 24;
pub const CURL_VERSION_HTTP3: c_int = 1 << 25;
pub const CURL_VERSION_ZSTD: c_int = 1 << 26;
pub const CURL_VERSION_UNICODE: c_int = 1 << 27;
pub const CURL_VERSION_HSTS: c_int = 1 << 28;
pub const CURL_VERSION_GSASL: c_int = 1 << 29;
pub const CURL_VERSION_THREADSAFE: c_int = 1 << 30;

/// Human-readable feature names reported by [`curl_version_info`], alphabetically sorted to
/// match `lib/version.c`'s features table, restricted to features actually built into this
/// workspace. Each corresponds to a `CURL_VERSION_*` bit set in [`BUILT_FEATURES`].
const FEATURE_NAMES: &[&str] = &[
    "alt-svc", "brotli", "HSTS", "HTTP2", "HTTP3", "IDN", "IPv6", "libz", "NTLM", "PSL", "SSL",
    "zstd",
];

/// The `features` bitmask reported by [`curl_version_info`] — only the `CURL_VERSION_*` bits
/// for capabilities actually built into this Rust workspace are set.
//
// NOTE: derived from the crates present in the workspace (rustls→SSL, flate2→libz,
// h2/hyper→HTTP2, quinn/h3→HTTP3, brotli, zstd, idna→IDN, publicsuffix→PSL, pure-Rust NTLM),
// plus IPv6, alt-svc, and HSTS. Reconcile with a `curl-rs-lib` feature accessor if one is
// exposed. Bits for dropped / Windows-only / optional features (SSPI, NTLM_WB, Kerberos unless
// the optional GSSAPI feature is enabled, RTMP, Unicode) are intentionally NOT set.
const BUILT_FEATURES: c_int = CURL_VERSION_IPV6
    | CURL_VERSION_SSL
    | CURL_VERSION_LIBZ
    | CURL_VERSION_NTLM
    | CURL_VERSION_IDN
    | CURL_VERSION_PSL
    | CURL_VERSION_HTTP2
    | CURL_VERSION_BROTLI
    | CURL_VERSION_ALTSVC
    | CURL_VERSION_HTTP3
    | CURL_VERSION_ZSTD
    | CURL_VERSION_HSTS;

/// Newtype wrapping [`curl_version_info_data`] so it can be published through a `static`
/// [`OnceLock`].
struct VersionInfo(curl_version_info_data);

// SAFETY: `curl_version_info_data` holds raw pointers, which make it `!Send + !Sync` by
// default. Here every pointer references leaked (`&'static`), immutable string / array storage
// that lives for the whole process; the value is written exactly once when the `OnceLock`
// initializes and is never mutated afterward. Because the pointees are `'static` and immutable,
// transferring ownership between threads (`Send`) and sharing `&`-references across threads
// (`Sync`) both observe the same read-only data with no data race. Both impls are required so
// that the `static OnceLock<VersionInfo>` below is itself `Sync` (`OnceLock<T>: Sync` needs
// `T: Send + Sync`).
unsafe impl Send for VersionInfo {}
// SAFETY: see the `Send` justification directly above — the wrapped pointers reference
// process-lifetime, write-once, immutable storage, so concurrent shared access is race-free.
unsafe impl Sync for VersionInfo {}

/// Leak a NUL-terminated copy of `s`, returning a process-lifetime `*const c_char`.
///
/// `curl_version_info` returns pointers into static storage that the caller must never free, so
/// leaking once (behind the `OnceLock`) is the intended lifetime, not a leak bug. Returns null
/// if `s` contains an interior NUL.
fn leak_cstr(s: &str) -> *const c_char {
    match CString::new(s) {
        Ok(c) => Box::leak(c.into_boxed_c_str()).as_ptr(),
        Err(_) => std::ptr::null(),
    }
}

/// Build a NULL-terminated, process-lifetime C array of C strings from `items`.
fn leak_cstr_array(items: &[&str]) -> *const *const c_char {
    let mut v: Vec<*const c_char> = items.iter().map(|s| leak_cstr(s)).collect();
    v.push(std::ptr::null()); // NULL terminator, per the curl.h array contract
    Vec::leak(v).as_ptr()
}

/// Runtime approximation of curl's build-time `CURL_OS` host triple.
//
// NOTE: curl bakes in the configure-detected host string (e.g. "x86_64-pc-linux-gnu"). Rust has
// no stable build-time triple accessor in ordinary code, so this reports the runtime
// "<arch>-<os>" (e.g. "x86_64-linux"). Reconcile with a build-script-provided `TARGET` if
// exact-triple parity is later required.
fn host_string() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

/// Construct the process-lifetime [`VersionInfo`], leaking all backing strings/arrays.
fn build_version_info() -> VersionInfo {
    VersionInfo(curl_version_info_data {
        age: CURLVERSION_NOW,
        version: leak_cstr(CURL_RS_VERSION),
        version_num: CURL_RS_VERSION_NUM,
        host: leak_cstr(&host_string()),
        features: BUILT_FEATURES,
        // rustls is the single audited TLS backend (AAP §0.7.3). `ssl_version_num` is kept 0,
        // exactly as curl 8.x keeps it ("not used anymore, always 0").
        ssl_version: leak_cstr("rustls"),
        ssl_version_num: 0,
        // flate2 is the libz-equivalent (gzip/deflate). Reported as "flate2".
        libz_version: leak_cstr("flate2"),
        // Compiled-in protocol schemes, sourced from the core crate's single source of truth
        // ([`curl_rs_lib::supported_protocols`]) so `curl_version_info()->protocols` advertises
        // exactly the schemes built into `curl-rs-lib` (FA-CLI-002) — matching curl's
        // `#ifdef`-driven `supported_protocols[]` and staying in lockstep with the CLI's
        // `--version`. RTMP/RTMPS are absent (dropped, AAP §0.2.2).
        protocols: leak_cstr_array(curl_rs_lib::supported_protocols()),
        // c-ares removed (Tokio system resolver replaces it) → null / 0.
        ares: std::ptr::null(),
        ares_num: 0,
        // IDN is provided by the pure-Rust `idna` crate (reflected in the CURL_VERSION_IDN
        // feature bit); the C `libidn2` field has no Rust equivalent → null.
        libidn: std::ptr::null(),
        iconv_ver_num: 0,
        // SSH is provided by russh.
        libssh_version: leak_cstr("russh"),
        // NOTE: numeric backend version fields have no stable runtime source here, so they are
        // reported as 0 ("not available") while the human-readable string carries the backend
        // name.
        brotli_ver_num: 0,
        brotli_version: leak_cstr("brotli"),
        // HTTP/2 is provided by `h2`/`hyper`, not nghttp2 → nghttp2 fields null / 0 (the
        // CURL_VERSION_HTTP2 bit is the canonical HTTP/2 indicator).
        nghttp2_ver_num: 0,
        nghttp2_version: std::ptr::null(),
        // HTTP/3 + QUIC via quinn (+ h3).
        quic_version: leak_cstr("quinn"),
        // rustls uses the bundled `webpki-roots` trust store, so there is no built-in CA file or
        // path → null / null (matches a curl build without CURL_CA_BUNDLE / CURL_CA_PATH).
        cainfo: std::ptr::null(),
        capath: std::ptr::null(),
        zstd_ver_num: 0,
        zstd_version: leak_cstr("zstd"),
        // HTTP engine reported as "hyper".
        hyper_version: leak_cstr("hyper"),
        // libgsasl is not used → null.
        gsasl_version: std::ptr::null(),
        feature_names: leak_cstr_array(FEATURE_NAMES),
        // RTMP/RTMPS dropped (AAP §0.2.2) → null.
        rtmp_version: std::ptr::null(),
    })
}

/// `char *curl_version(void)` — return the human-readable libcurl version string.
///
/// Returns a pointer to a process-lifetime, NUL-terminated string equal to
/// `curl_rs_lib::version()`:
/// `"curl-rs/8.19.0-DEV rustls flate2 brotli zstd hyper quinn russh"`.
///
/// C callers treat the returned pointer as a static borrow and must **not** free it; the string
/// is built once into a `static OnceLock<CString>` and its pointer returned on every call.
///
/// The committed `include/curl/curl.h` declares `char *curl_version(void)` — a **non-`const`**
/// `char *` — so the return type is `*mut c_char` for byte-exact cbindgen parity (cbindgen renders
/// `*const c_char` as `const char *`, which would diverge from the reference header). The `*mut`
/// is an ABI-shape requirement only: the pointed-to storage is process-lifetime and immutable in
/// practice, and callers must still neither mutate nor free it.
//
// NOTE: the canonical string is defined locally (`CURL_RS_VERSION_STRING`) with the exact spec
// value, because the core crate does not yet re-export `curl_rs_lib::version()`. Reconcile to
// delegate to `curl_rs_lib::version()` once that accessor lands; the value cannot drift.
#[no_mangle]
pub extern "C" fn curl_version() -> *mut c_char {
    static VERSION_CSTRING: OnceLock<CString> = OnceLock::new();
    // `as_ptr()` yields `*const c_char`; the `as *mut c_char` cast only reshapes the pointer type
    // to match the C `char *` prototype (a pointer cast is safe — dereferencing would not be, and
    // never happens on this side). The storage is never mutated through the returned pointer.
    VERSION_CSTRING
        .get_or_init(|| {
            CString::new(CURL_RS_VERSION_STRING).expect("version string has no interior NUL")
        })
        .as_ptr() as *mut c_char
}

/// `curl_version_info_data *curl_version_info(CURLversion age)` — return runtime version info.
///
/// Returns a pointer to a process-lifetime, immutable [`curl_version_info_data`]. Following
/// curl 8.x (`lib/version.c`), the requested `age` does **not** change which data is returned —
/// the full struct pointer is always returned, and the struct's own `age` field
/// ([`CURLVERSION_NOW`]) tells the caller how many trailing fields are valid.
///
/// The return type is `*mut curl_version_info_data` (not `*const`) to byte-match the
/// **non-`const`** `curl_version_info_data *` declaration in the committed `include/curl/curl.h`
/// (cbindgen renders `*const` as `const …*`, which would diverge). The pointed-to struct is a
/// process-lifetime singleton that callers must treat as read-only — the `*mut` is an ABI-shape
/// requirement only and the struct is never mutated through it.
#[no_mangle]
pub extern "C" fn curl_version_info(age: CURLversion) -> *mut curl_version_info_data {
    // curl ignores the requested age for data selection (`(void)stamp;` in lib/version.c); the
    // `age` FIELD of the returned struct is the version marker. The parameter is retained for
    // exact signature parity.
    let _ = age;
    static VERSION_INFO: OnceLock<VersionInfo> = OnceLock::new();
    // The trailing `as *mut …` only reshapes the pointer type to the C `curl_version_info_data *`
    // prototype (a pointer cast is safe; the singleton is never written through this pointer).
    &VERSION_INFO.get_or_init(build_version_info).0 as *const curl_version_info_data
        as *mut curl_version_info_data
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::{
        as_mut as ffi_as_mut, as_ref as ffi_as_ref, box_from_raw, box_into_raw, code_from_c_int,
        cstr_to_str, curl_version, curl_version_info, ffi_guard, str_to_c_owned, to_curlcode,
        CURLcode, CURLversion, BUILT_FEATURES, CURLVERSION_NOW, CURL_RS_VERSION_NUM,
        CURL_RS_VERSION_STRING, CURL_VERSION_HSTS, CURL_VERSION_HTTP2, CURL_VERSION_HTTP3,
        CURL_VERSION_SSL,
    };
    use curl_rs_lib::error::{CurlCode, Error};
    use libc::c_char;
    use std::ffi::{CStr, CString};

    // --- Frozen CURLcode ABI (preserved from the foundation checkpoint) ---------------------

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

    // --- Result <-> CURLcode bridge ---------------------------------------------------------

    #[test]
    fn to_curlcode_maps_ok_and_err() {
        assert_eq!(to_curlcode(Ok(())), 0);
        let e: Error = CurlCode::OperationTimedout.into();
        assert_eq!(to_curlcode(Err(e)), 28);
    }

    #[test]
    fn code_from_c_int_roundtrips() {
        assert_eq!(i32::from(code_from_c_int(0)), 0);
        assert_eq!(i32::from(code_from_c_int(28)), 28);
        assert_eq!(i32::from(code_from_c_int(101)), 101);
    }

    // --- Panic guard ------------------------------------------------------------------------

    #[test]
    fn ffi_guard_passes_through_and_catches_panic() {
        assert_eq!(ffi_guard(2, || 0), 0);
        // Silence the default panic hook for the one intentional panic below so the test output
        // stays clean; the panic is still caught and converted to `default_err`.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let caught = ffi_guard(2, || panic!("intentional test panic"));
        std::panic::set_hook(prev);
        assert_eq!(caught, 2);
    }

    // --- Opaque-handle boxing helpers -------------------------------------------------------

    #[test]
    fn box_roundtrip_reclaims_ownership() {
        let raw = box_into_raw(42u64);
        assert!(!raw.is_null());
        // SAFETY: `raw` was just produced by `box_into_raw` for `u64`, is non-null, and is
        // reclaimed exactly once here.
        let boxed = unsafe { box_from_raw(raw) };
        assert_eq!(boxed.as_deref(), Some(&42u64));
        // SAFETY: a null pointer is explicitly permitted by `box_from_raw`'s contract.
        let none = unsafe { box_from_raw::<u64>(std::ptr::null_mut()) };
        assert!(none.is_none());
    }

    #[test]
    fn as_ref_null_checked() {
        let value = 7i32;
        let p: *const i32 = &value;
        // SAFETY: `p` points to the live local `value` for the duration of this call.
        assert_eq!(unsafe { ffi_as_ref(p) }, Some(&7));
        // SAFETY: null is permitted and yields None.
        assert!(unsafe { ffi_as_ref::<i32>(std::ptr::null()) }.is_none());
    }

    #[test]
    fn as_mut_allows_mutation() {
        let mut value = 7i32;
        let pm: *mut i32 = &mut value;
        // SAFETY: `pm` is the only live pointer to `value`; forming a unique reference is sound.
        if let Some(r) = unsafe { ffi_as_mut(pm) } {
            *r += 1;
        }
        assert_eq!(value, 8);
        // SAFETY: null is permitted and yields None.
        assert!(unsafe { ffi_as_mut::<i32>(std::ptr::null_mut()) }.is_none());
    }

    // --- C-string helpers -------------------------------------------------------------------

    #[test]
    fn str_to_c_owned_roundtrips_and_reclaims() {
        let p = str_to_c_owned("hello");
        assert!(!p.is_null());
        // SAFETY: `p` points to the NUL-terminated string just allocated by `str_to_c_owned`,
        // valid for this borrow.
        let s = unsafe { cstr_to_str(p) };
        assert_eq!(s, Some("hello"));
        // Reclaim symmetrically with `curl_free` (which uses `CString::from_raw`) to avoid a
        // test leak.
        // SAFETY: `p` was produced by `str_to_c_owned` (`CString::into_raw`) and is reclaimed
        // exactly once here.
        unsafe {
            drop(CString::from_raw(p));
        }
    }

    #[test]
    fn cstr_to_str_null_is_none() {
        // SAFETY: null is explicitly permitted and yields None.
        assert!(unsafe { cstr_to_str(std::ptr::null()) }.is_none());
    }

    #[test]
    fn str_to_c_owned_rejects_interior_nul() {
        // "a\0b" has an interior NUL, which cannot be a C string → null is returned.
        assert!(str_to_c_owned("a\0b").is_null());
    }

    // --- Version symbols --------------------------------------------------------------------

    #[test]
    fn curl_version_returns_exact_string() {
        // SAFETY: `curl_version()` returns a process-lifetime, NUL-terminated pointer valid for
        // the whole program; borrowing it as a `CStr` for this check is sound.
        let s = unsafe { CStr::from_ptr(curl_version()) };
        assert_eq!(
            s.to_str().unwrap(),
            "curl-rs/8.19.0-DEV rustls flate2 brotli zstd hyper quinn russh"
        );
        assert_eq!(s.to_str().unwrap(), CURL_RS_VERSION_STRING);
    }

    /// Count entries before the NULL terminator of a C string-pointer array.
    ///
    /// # Safety
    /// The caller must guarantee that `arr` points to a valid array of pointers terminated by a
    /// NULL entry and that every element up to that terminator is dereferenceable.
    unsafe fn count_null_terminated(arr: *const *const c_char) -> usize {
        let mut n = 0usize;
        // SAFETY: `arr` is a valid, process-lifetime, NULL-terminated pointer array; reading
        // each element up to and including the terminator is in-bounds.
        while !(*arr.add(n)).is_null() {
            n += 1;
        }
        n
    }

    #[test]
    fn curl_version_info_matches_contract() {
        let ptr = curl_version_info(CURLVERSION_NOW);
        assert!(!ptr.is_null());
        // SAFETY: `curl_version_info` returns a process-lifetime, immutable struct pointer;
        // forming a shared reference for these read-only assertions is sound.
        let info = unsafe { &*ptr };

        // `age` field is the current marker, whose integer value is 11 (CURLVERSION_TWELFTH).
        assert_eq!(info.age, CURLVERSION_NOW);
        assert_eq!(info.age as i32, CURLversion::CURLVERSION_TWELFTH as i32);
        assert_eq!(CURLVERSION_NOW as i32, 11);

        // version_num == 0x081300.
        assert_eq!(info.version_num, 0x08_1300);
        assert_eq!(info.version_num, CURL_RS_VERSION_NUM);

        // version string == "8.19.0-DEV".
        // SAFETY: `info.version` is a process-lifetime NUL-terminated pointer set at init.
        let ver = unsafe { CStr::from_ptr(info.version) };
        assert_eq!(ver.to_str().unwrap(), "8.19.0-DEV");

        // features carries the representative built bits and equals the declared mask.
        assert_ne!(info.features & CURL_VERSION_SSL, 0);
        assert_ne!(info.features & CURL_VERSION_HTTP2, 0);
        assert_ne!(info.features & CURL_VERSION_HTTP3, 0);
        assert_ne!(info.features & CURL_VERSION_HSTS, 0);
        assert_eq!(info.features, BUILT_FEATURES);
        // Dropped / Windows-only / optional feature bits must be clear.
        assert_eq!(info.features & super::CURL_VERSION_SSPI, 0);
        assert_eq!(info.features & super::CURL_VERSION_GSSAPI, 0);
        assert_eq!(info.features & super::CURL_VERSION_NTLM_WB, 0);

        // TLS backend is rustls.
        // SAFETY: process-lifetime NUL-terminated pointer.
        let ssl = unsafe { CStr::from_ptr(info.ssl_version) };
        assert_eq!(ssl.to_str().unwrap(), "rustls");

        // protocols / feature_names are non-null and NULL-terminated with the expected counts.
        assert!(!info.protocols.is_null());
        assert!(!info.feature_names.is_null());
        // SAFETY: both arrays are process-lifetime and NULL-terminated by construction.
        let proto_count = unsafe { count_null_terminated(info.protocols) };
        assert_eq!(proto_count, curl_rs_lib::supported_protocols().len());
        // SAFETY: as above.
        let feat_count = unsafe { count_null_terminated(info.feature_names) };
        assert_eq!(feat_count, super::FEATURE_NAMES.len());

        // Removed C-backend fields are null.
        assert!(info.nghttp2_version.is_null());
        assert!(info.rtmp_version.is_null());
        assert!(info.ares.is_null());
        assert!(info.gsasl_version.is_null());
        assert!(info.libidn.is_null());
        // ssl_version_num is kept at 0 for ABI parity.
        assert_eq!(info.ssl_version_num, 0);
    }

    #[test]
    fn curl_version_info_ignores_requested_age() {
        // curl returns the full struct regardless of the requested age; the pointer identity is
        // stable across calls (it is a process-lifetime singleton).
        let a = curl_version_info(CURLversion::CURLVERSION_FIRST);
        let b = curl_version_info(CURLVERSION_NOW);
        assert!(!a.is_null());
        assert_eq!(a, b);
    }
}
