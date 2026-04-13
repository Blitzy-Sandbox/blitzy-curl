// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! FFI compatibility layer exposing all 106 CURL_EXTERN symbols with identical
//! function signatures, parameter types, return types, and error code integer
//! values to curl 8.x (`libcurl.so` / `libcurl.dylib` / `curl.dll`).
//!
//! This crate is the drop-in replacement entry point: the resulting shared
//! library (`libcurl_rs_ffi.so`) can be used by any C program that links
//! against `libcurl` without recompilation.
//!
//! # Architecture
//!
//! The crate is structured as thin FFI wrappers that delegate to the core
//! Rust library `curl-rs-lib`.  Each submodule corresponds to a group of
//! `CURL_EXTERN` symbols:
//!
//! | Module         | Symbols                                | Count |
//! |----------------|----------------------------------------|-------|
//! | `types`        | C-compatible type definitions           | —     |
//! | `error_codes`  | `CURLcode`/`CURLMcode`/… constants     | 170+  |
//! | `easy`         | `curl_easy_*` functions                 | 10+   |
//! | `multi`        | `curl_multi_*` functions                | 24+   |
//! | `share`        | `curl_share_*` functions                | 4     |
//! | `global`       | `curl_global_*` + utility functions     | 15+   |
//! | `url`          | `curl_url_*` functions                  | 6     |
//! | `ws`           | `curl_ws_*` functions                   | 4     |
//! | `mime`         | `curl_mime_*` functions                 | 12+   |
//! | `slist`        | `curl_slist_*` functions                | 2     |
//! | `options`      | `curl_easy_option_*` functions          | 3     |
//! | `header`       | `curl_easy_header*` functions           | 2     |
//! | `mprintf`      | `curl_m*printf` functions               | 10    |
//!
//! # Sync → Async Bridge
//!
//! Per AAP Section 0.4.4 the FFI layer bridges synchronous C callers to
//! async Rust internals using a **thread-local** `tokio::runtime::Runtime`
//! instance.  The helpers [`with_runtime`] and [`ffi_block_on`] encapsulate
//! this pattern so that every `extern "C"` entry point can call
//! `ffi_block_on(async { … })` to execute async operations synchronously.
//!
//! # Global Initialization
//!
//! [`ensure_global_init`] uses `std::sync::Once` to perform exactly-once
//! initialization of any global state required by `curl-rs-lib`, mirroring
//! the semantics of C `curl_global_init()`.

// ---------------------------------------------------------------------------
// Crate-level attributes
//
// These suppress warnings produced by the C naming conventions used in the
// re-exported types and constants from `types` and `error_codes`.
// ---------------------------------------------------------------------------

// C types use snake_case/UPPER_CASE instead of CamelCase.
#![allow(non_camel_case_types)]
// C error-code constants may violate UPPER_CASE expectations.
#![allow(non_upper_case_globals)]
// Some C types use CamelCase (e.g. CURLcode, CURLM).
#![allow(non_snake_case)]
// Safety documentation is provided inline as `// SAFETY:` comments per AAP
// Section 0.7.1 rather than as `# Safety` doc sections.
#![allow(clippy::missing_safety_doc)]
// The pub(crate) runtime helpers (with_runtime, ffi_block_on, ensure_global_init)
// and various #[no_mangle] extern "C" functions may not have direct Rust callers
// within this compilation unit — they are FFI entry points or shared infrastructure
// for sibling modules.
#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Module declarations — 13 submodules covering the full libcurl C API surface
// ---------------------------------------------------------------------------

/// C-compatible opaque pointer types, platform type aliases, callback typedefs,
/// and enum type aliases.  This is the foundational module — every other module
/// imports from here.
pub mod types;

/// All `CURLcode`, `CURLMcode`, `CURLSHcode`, `CURLUcode`, `CURLHcode`, and
/// `CURLsslset` integer constants (170+).  Values match the C enums exactly.
pub mod error_codes;

/// `curl_easy_*` functions (10+ symbols from `include/curl/easy.h`).
pub mod easy;

/// `curl_multi_*` functions (24+ symbols from `include/curl/multi.h`).
pub mod multi;

/// `curl_share_*` functions (4 symbols from `include/curl/curl.h`).
pub mod share;

/// `curl_global_*` functions (5+) and standalone utility symbols
/// (`curl_version`, `curl_free`, `curl_getenv`, `curl_getdate`, etc.).
pub mod global;

/// `curl_url_*` functions (6 symbols from `include/curl/urlapi.h`).
pub mod url;

/// `curl_ws_*` functions (4 symbols from `include/curl/websockets.h`).
pub mod ws;

/// `curl_mime_*` functions (12+ symbols from `include/curl/curl.h` MIME API).
pub mod mime;

/// `curl_slist_append` and `curl_slist_free_all` (2 symbols).
pub mod slist;

/// `curl_easy_option_by_name`, `curl_easy_option_by_id`,
/// `curl_easy_option_next` (3 symbols from `include/curl/options.h`).
pub mod options;

/// `curl_easy_header` and `curl_easy_nextheader` (2 symbols from
/// `include/curl/header.h`).
pub mod header;

/// `curl_m*printf` family of functions (10 symbols from
/// `include/curl/mprintf.h`).
pub mod mprintf;

// ---------------------------------------------------------------------------
// Re-exports
//
// Glob re-exports make all public type definitions and error-code constants
// available at the crate root so that:
//   1. cbindgen can discover them for header generation.
//   2. Sibling modules can use `crate::CURL`, `crate::CURLE_OK`, etc.
//   3. Downstream Rust consumers of the `rlib` target can write
//      `curl_rs_ffi::CURL` without reaching into submodules.
// ---------------------------------------------------------------------------

pub use error_codes::*;
pub use types::*;

// ---------------------------------------------------------------------------
// Thread-local Tokio runtime for the sync → async FFI bridge
//
// Per AAP Section 0.4.4:
//
//   "The FFI layer bridges synchronous C callers to async Rust internals
//    using `tokio::runtime::Runtime::block_on()` within a thread-local
//    runtime instance, preserving the synchronous `curl_easy_perform`
//    semantics expected by C consumers."
//
// Each OS thread that enters the FFI boundary gets its own single-threaded
// Tokio runtime, lazily initialised on first use.  This avoids the overhead
// of creating a runtime on every call while still providing full async
// capability.
// ---------------------------------------------------------------------------

use std::cell::RefCell;
use std::future::Future;
use std::sync::Once;
use tokio::runtime::Runtime;

thread_local! {
    /// Per-thread Tokio runtime for executing async operations from
    /// synchronous `extern "C"` entry points.  Lazily initialised.
    static FFI_RUNTIME: RefCell<Option<Runtime>> = const { RefCell::new(None) };
}

/// Execute a closure with access to the thread-local Tokio runtime.
///
/// The runtime is lazily created on first access for the calling thread.
/// Subsequent calls on the same thread reuse the existing runtime.
///
/// # Panics
///
/// Panics if the Tokio runtime cannot be created (e.g. OS resource
/// exhaustion).  In practice this mirrors the behaviour of C libcurl which
/// would abort on `malloc` failure during `curl_global_init`.
pub(crate) fn with_runtime<F, R>(f: F) -> R
where
    F: FnOnce(&Runtime) -> R,
{
    FFI_RUNTIME.with(|cell| {
        let mut borrow = cell.borrow_mut();
        let runtime = borrow.get_or_insert_with(|| {
            Runtime::new().expect("Failed to create Tokio runtime for FFI")
        });
        f(runtime)
    })
}

/// Block the current thread on an async future using the thread-local
/// Tokio runtime.
///
/// This is the primary bridge used by `extern "C"` functions such as
/// `curl_easy_perform` to execute async transfer operations synchronously.
///
/// # Example (crate-internal)
///
/// ```ignore
/// let result = ffi_block_on(async {
///     handle.perform().await
/// });
/// ```
pub(crate) fn ffi_block_on<F: Future>(future: F) -> F::Output {
    with_runtime(|rt| rt.block_on(future))
}

// ---------------------------------------------------------------------------
// Global initialisation state
//
// `curl_global_init()` is supposed to be called exactly once before any
// other curl function.  We use `std::sync::Once` to guarantee at-most-once
// execution of the initialisation closure, even in the face of concurrent
// calls from multiple threads (which is technically a caller error but we
// handle it gracefully).
// ---------------------------------------------------------------------------

/// Global one-shot initialisation guard.
static GLOBAL_INIT: Once = Once::new();

/// Ensure that global library state has been initialised.
///
/// This is idempotent: the first call runs the initialisation closure;
/// subsequent calls are no-ops.  It is safe to call from any thread at
/// any time.
///
/// Called internally by `curl_global_init()` (in `global.rs`) and as a
/// defensive measure by other entry points that might be reached before
/// the consumer has called `curl_global_init()`.
pub(crate) fn ensure_global_init() {
    GLOBAL_INIT.call_once(|| {
        // Initialise tracing / logging subscriber if the CURL_DEBUG or
        // similar environment variable is set.  For now this is a no-op
        // placeholder that will be wired to curl-rs-lib's global_init()
        // once the core library's initialisation API is finalised.
        //
        // The key invariant is that this block runs exactly once across
        // all threads, matching the semantics of C curl_global_init().
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `with_runtime` successfully creates and provides a
    /// Tokio runtime on the calling thread.
    #[test]
    fn test_with_runtime_creates_runtime() {
        let result = with_runtime(|_rt| 42);
        assert_eq!(result, 42);
    }

    /// Verify that `ffi_block_on` can execute an async block and return
    /// its result synchronously.
    #[test]
    fn test_ffi_block_on_executes_future() {
        let value = ffi_block_on(async { 1 + 2 });
        assert_eq!(value, 3);
    }

    /// Verify that `ffi_block_on` can execute a yielding async operation.
    #[test]
    fn test_ffi_block_on_with_yield() {
        let value = ffi_block_on(async {
            tokio::task::yield_now().await;
            99
        });
        assert_eq!(value, 99);
    }

    /// Verify that `ensure_global_init` can be called multiple times
    /// without panic (idempotency).
    #[test]
    fn test_ensure_global_init_idempotent() {
        ensure_global_init();
        ensure_global_init();
        ensure_global_init();
        // No panic = success.
    }

    /// Verify that the key types from `types` are available at crate root
    /// via the glob re-export.
    #[test]
    fn test_types_reexported() {
        // These type assertions compile only if the glob re-export works.
        let _: curl_off_t = 0i64;
        let _: CURLoption = 0i32;
        let _: CURLINFO = 0i32;
        let _: CURLcode = 0i32;
        let _: CURLMcode = 0i32;
        let _: CURLSHcode = 0i32;
        let _: CURLUcode = 0i32;
        let _: CURLHcode = 0i32;
        let _: CURLsslset = 0i32;
    }

    /// Verify that error code constants from `error_codes` are available
    /// at crate root via the glob re-export.
    #[test]
    fn test_error_codes_reexported() {
        assert_eq!(CURLE_OK, 0);
        assert_eq!(CURLE_FAILED_INIT, 2);
        assert_eq!(CURLE_OUT_OF_MEMORY, 27);
        assert_eq!(CURLE_UNKNOWN_OPTION, 48);
        assert_eq!(CURL_LAST, 102);
        assert_eq!(CURLM_OK, 0);
        assert_eq!(CURLM_LAST, 13);
        assert_eq!(CURLSHE_OK, 0);
        assert_eq!(CURLSHE_LAST, 6);
        assert_eq!(CURLUE_OK, 0);
        assert_eq!(CURLUE_LAST, 32);
        assert_eq!(CURLHE_OK, 0);
        assert_eq!(CURLSSLSET_OK, 0);
    }
}
