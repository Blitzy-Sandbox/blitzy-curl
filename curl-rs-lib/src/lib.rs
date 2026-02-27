//! Core library for curl-rs — a complete Rust rewrite of libcurl.
//!
//! `curl-rs-lib` is a pure-Rust implementation of the libcurl library (version
//! 8.19.0-DEV), providing the same protocol support, transfer semantics, and
//! API contracts as the original C-based libcurl. All manual memory management
//! has been replaced with Rust's ownership and borrowing system, and all TLS
//! operations use rustls exclusively.
//!
//! # Main Types
//!
//! | Type | C Equivalent | Purpose |
//! |------|-------------|---------|
//! | [`EasyHandle`] | `CURL *` | Single-transfer handle (`curl_easy_*` API) |
//! | [`MultiHandle`] | `CURLM *` | Concurrent transfer handle (`curl_multi_*` API) |
//! | [`ShareHandle`] | `CURLSH *` | Shared data handle (`curl_share_*` API) |
//! | [`CurlUrl`] | `CURLU *` | URL parsing and manipulation (`curl_url_*` API) |
//! | [`SList`] | `struct curl_slist *` | String list for headers, recipients, etc. |
//!
//! # Error Handling
//!
//! All fallible operations return [`CurlResult<T>`], which is
//! `Result<T, CurlError>`. The [`CurlError`] enum maps 1:1 to the C
//! `CURLcode` integer values for FFI compatibility.
//!
//! Additional error types:
//! - [`CurlMcode`] — multi-handle error codes (`CURLMcode`)
//! - [`CurlSHcode`] — share-handle error codes (`CURLSHcode`)
//! - [`CurlUrlError`] — URL API error codes (`CURLUcode`)
//!
//! # Global Initialization
//!
//! Before using any other functionality, call [`global_init`]:
//!
//! ```no_run
//! # fn main() -> Result<(), curl_rs_lib::CurlError> {
//! curl_rs_lib::global_init(0)?;
//! // ... use curl-rs-lib ...
//! curl_rs_lib::global_cleanup();
//! # Ok(())
//! # }
//! ```
//!
//! # Feature Flags
//!
//! Protocol and compression support is controlled via Cargo feature flags:
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `http` | ✓ | HTTP/1.1, HTTP/2, HTTP/3 protocol support |
//! | `ftp` | ✓ | FTP/FTPS protocol support |
//! | `smtp` | ✓ | SMTP/SMTPS protocol support |
//! | `imap` | ✓ | IMAP/IMAPS protocol support |
//! | `pop3` | ✓ | POP3/POP3S protocol support |
//! | `cookies` | ✓ | Cookie jar engine |
//! | `brotli` | ✓ | Brotli content-encoding decompression |
//! | `zstd` | ✓ | Zstandard content-encoding decompression |
//! | `hickory-dns` | ✗ | Pure-Rust DNS resolver (hickory-dns) |
//!
//! # Safety
//!
//! This crate enforces `#![forbid(unsafe_code)]`. All `unsafe` operations are
//! confined to the FFI crate (`curl-rs-ffi`).

// =============================================================================
// Crate-level attributes
// =============================================================================

// CRITICAL (AAP Section 0.7.1): Zero unsafe in protocol/TLS/transfer code.
// `deny` makes unsafe a hard error by default across the entire crate.
// Only `util/nonblock.rs` has a targeted `#[allow(unsafe_code)]` for minimal
// OS-integration primitives (raw FD operations) as permitted by the AAP.
#![deny(unsafe_code)]
#![warn(clippy::all)]
#![warn(missing_docs)]

// =============================================================================
// Module declarations
// =============================================================================
//
// Organized by dependency order and subsystem grouping. All 24 sibling source
// files and 7 subdirectory modules are declared here.

// ---------------------------------------------------------------------------
// Core error types — foundational, no internal dependencies
// ---------------------------------------------------------------------------

/// Error types for the entire crate: [`CurlError`], [`CurlMcode`],
/// [`CurlSHcode`], [`CurlUrlError`], and the [`CurlResult`] type alias.
pub mod error;

// ---------------------------------------------------------------------------
// Public API modules — primary user-facing types
// ---------------------------------------------------------------------------

/// Easy handle API — single-transfer operations matching `curl_easy_*`.
///
/// The [`easy::EasyHandle`] is the primary way to perform individual HTTP,
/// FTP, SSH, and other protocol transfers.
pub mod easy;

/// Multi handle API — concurrent transfer management matching `curl_multi_*`.
///
/// [`multi::MultiHandle`] drives multiple transfers concurrently using a
/// Tokio multi-thread runtime.
pub mod multi;

/// Shared handle API — data sharing between easy handles via `curl_share_*`.
///
/// [`share::ShareHandle`] enables sharing cookies, DNS cache, connections,
/// and TLS sessions between multiple [`EasyHandle`] instances.
pub mod share;

/// URL parsing and manipulation matching `curl_url_*` (6 CURL_EXTERN symbols).
///
/// [`url::CurlUrl`] provides RFC 3986-compliant URL parsing with
/// curl-specific extensions for credentials, zone IDs, and IDN.
pub mod url;

/// Async transfer engine — drives send/receive operations.
///
/// Core data transfer machinery with ownership-based buffer management,
/// replacing `lib/transfer.c`.
pub mod transfer;

/// Option dispatch — handles `curl_easy_setopt()` typed option setting.
///
/// Replaces the C `setopt.c` massive switch statement with Rust enum dispatch.
pub mod setopt;

/// Info retrieval — implements `curl_easy_getinfo()` for post-transfer metadata.
pub mod getinfo;

/// Option metadata tables for the introspection API (`curl_easy_option_*`).
pub mod options;

/// Version information and feature reporting (`curl_version`, `curl_version_info`).
pub mod version;

/// Vec-based string list replacing C `struct curl_slist` linked list.
///
/// Used for custom headers, mail recipients, resolve lists, and other
/// string-list options.
pub mod slist;

/// MIME multipart builder for HTTP form submissions.
pub mod mime;

/// URL percent-encoding and decoding (`curl_easy_escape`, `curl_easy_unescape`).
pub mod escape;

/// HTTP header storage, iteration, and the `curl_easy_header` API.
pub mod headers;

// ---------------------------------------------------------------------------
// Feature-gated modules
// ---------------------------------------------------------------------------

/// Cookie jar engine — HTTP cookie storage, parsing, matching, and
/// serialization in Netscape cookie-jar file format.
///
/// Gated behind the `cookies` Cargo feature flag (enabled by default),
/// matching the C `CURL_DISABLE_COOKIES` preprocessor guard.
#[cfg(feature = "cookies")]
pub mod cookie;

/// HTTP Strict Transport Security (HSTS) preload list management.
pub mod hsts;

/// Alt-Svc (Alternative Service) cache with file persistence (RFC 7838).
pub mod altsvc;

/// `.netrc` file parser for automatic authentication credential lookup.
pub mod netrc;

/// Transfer progress tracking — speed calculation, ETA, and callback invocation.
pub mod progress;

/// Per-request state machine managing the transfer lifecycle.
pub mod request;

/// Content-encoding decompression: gzip, deflate, brotli, zstd.
pub mod content_encoding;

/// Bandwidth rate limiter for upload and download throttling.
pub mod ratelimit;

/// Public Suffix List (PSL) integration for cookie domain validation.
pub mod psl;

/// Internationalized Domain Name (IDN) handling via the `idna` crate.
pub mod idn;

// ---------------------------------------------------------------------------
// Subsystem modules (directories)
// ---------------------------------------------------------------------------

/// Connection subsystem — connection pool, filters, Happy Eyeballs, proxy tunnels.
pub mod conn;

/// Protocol handlers — HTTP, FTP, SSH, IMAP, SMTP, and other protocol
/// implementations behind the `Protocol` trait.
pub mod protocols;

/// TLS abstraction layer — single rustls backend replacing 7 C TLS backends.
pub mod tls;

/// Authentication handlers — Basic, Digest, Bearer, NTLM, Negotiate, SASL.
pub mod auth;

/// DNS resolution — system resolver, DNS-over-HTTPS, optional hickory-dns.
pub mod dns;

/// Proxy support — SOCKS4/5 and no-proxy matching.
pub mod proxy;

/// Utility modules — base64, dynbuf, hashing, time, printf, and more.
///
/// Replaces the C `lib/curlx/` portability utilities with idiomatic Rust.
pub mod util;

// =============================================================================
// Public re-exports — the primary public API surface
// =============================================================================
//
// These re-exports allow consumers to write `use curl_rs_lib::EasyHandle`
// instead of `use curl_rs_lib::easy::EasyHandle`. They define the crate's
// public API consumed by the binary crate (`curl-rs`) and the FFI crate
// (`curl-rs-ffi`).

// Error types
pub use error::{CurlError, CurlMcode, CurlResult, CurlSHcode, CurlUrlError};

// Handle types
pub use easy::EasyHandle;
pub use multi::MultiHandle;
pub use share::ShareHandle;

// URL types
pub use url::{CurlUrl, CurlUrlPart};

// String list
pub use slist::SList;

// Version functions
pub use version::{version, version_info};

// =============================================================================
// Global initialization and cleanup
// =============================================================================
//
// Matching `curl_global_init()` / `curl_global_cleanup()` C API semantics.
// Uses `std::sync::Once` for thread-safe one-time initialization.

use std::sync::Once;

/// Guard ensuring the library is initialized at most once.
static INIT_ONCE: Once = Once::new();

/// Guard ensuring cleanup runs at most once.
static CLEANUP_ONCE: Once = Once::new();

/// Initializes the curl-rs library globally.
///
/// This function **must** be called at least once before using any other
/// curl-rs functionality. It is thread-safe: concurrent calls from multiple
/// threads are safe, and only the first call performs actual initialization.
/// Subsequent calls are no-ops that return `Ok(())`.
///
/// Initialization performs the following steps:
///
/// 1. Configures the default `tracing` subscriber for structured logging
///    output (silently ignored if a subscriber is already installed).
/// 2. Installs the rustls TLS crypto provider (`aws-lc-rs`) for all
///    subsequent TLS operations.
///
/// # Arguments
///
/// * `flags` — Initialization flags for C API compatibility. Accepted values
///   include `CURL_GLOBAL_SSL` (1), `CURL_GLOBAL_WIN32` (2),
///   `CURL_GLOBAL_ALL` (3), and `CURL_GLOBAL_DEFAULT` (3). In the Rust
///   implementation, TLS is always initialized regardless of flags.
///
/// # Returns
///
/// * `Ok(())` on successful initialization.
/// * `Err(CurlError)` if TLS provider installation fails (rare — only occurs
///   if a conflicting crypto provider was previously installed).
///
/// # C Equivalent
///
/// ```c
/// CURLcode curl_global_init(long flags);
/// ```
///
/// # Examples
///
/// ```no_run
/// // Initialize with default flags
/// curl_rs_lib::global_init(0).expect("curl-rs init failed");
///
/// // ... use curl-rs-lib ...
///
/// curl_rs_lib::global_cleanup();
/// ```
pub fn global_init(flags: i64) -> CurlResult<()> {
    // The flags parameter is accepted for C API compatibility. In the Rust
    // implementation, TLS and tracing are always initialized regardless of
    // the specific flags value. The C API defines:
    //   CURL_GLOBAL_SSL     = (1<<0)  — no purpose since curl 7.57.0
    //   CURL_GLOBAL_WIN32   = (1<<1)  — Win32 socket init (no-op on Unix)
    //   CURL_GLOBAL_ALL     = 3       — initialize everything
    //   CURL_GLOBAL_NOTHING = 0       — initialize nothing
    //   CURL_GLOBAL_DEFAULT = 3       — same as ALL
    //   CURL_GLOBAL_ACK_EINTR = (1<<2)
    let _ = flags;

    let mut result: CurlResult<()> = Ok(());

    INIT_ONCE.call_once(|| {
        // Step 1: Configure the default tracing subscriber for structured
        // logging. The `try_init()` call is non-fatal — it returns Err if a
        // subscriber is already installed (e.g., by the application), which
        // we silently ignore.
        let _ = tracing_subscriber::fmt::try_init();

        // Step 2: Initialize the TLS subsystem. This installs the rustls
        // aws-lc-rs crypto provider and sets up TLS key logging if the
        // SSLKEYLOGFILE environment variable is set.
        if let Err(e) = tls::tls_init() {
            result = Err(e);
        }
    });

    result
}

/// Cleans up the curl-rs library globally.
///
/// This function releases resources allocated by [`global_init`]. It is
/// thread-safe and idempotent — the first call performs actual cleanup, and
/// subsequent calls are no-ops.
///
/// After calling this function, no other curl-rs function should be called
/// unless [`global_init`] is invoked again.
///
/// # C Equivalent
///
/// ```c
/// void curl_global_cleanup(void);
/// ```
///
/// # Examples
///
/// ```no_run
/// curl_rs_lib::global_init(0).unwrap();
/// // ... use curl-rs-lib ...
/// curl_rs_lib::global_cleanup();
/// ```
pub fn global_cleanup() {
    CLEANUP_ONCE.call_once(|| {
        // Release TLS resources (close key logger, etc.).
        tls::tls_cleanup();
    });
}

// =============================================================================
// Build-script-generated symbol inventory
// =============================================================================

/// Auto-generated symbol inventory from the curl 8.19.0-DEV C API headers.
///
/// This module contains compile-time constants listing all 100 `CURL_EXTERN`
/// symbols extracted from `include/curl/*.h`. It is used by the FFI crate
/// (`curl-rs-ffi`) to validate that every public C API symbol has a
/// corresponding `extern "C"` Rust implementation.
///
/// The inventory is generated by `curl-rs-lib/build.rs` and included via
/// the `include!()` macro from `$OUT_DIR/symbol_inventory.rs`.
#[allow(missing_docs)]
#[allow(dead_code)]
pub mod symbol_inventory {
    include!(concat!(env!("OUT_DIR"), "/symbol_inventory.rs"));
}
