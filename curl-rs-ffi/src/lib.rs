//! `curl-rs-ffi` — the `libcurl`-compatible C ABI (drop-in `libcurl`).
//!
//! This crate is the FFI layer of the three-crate curl → Rust workspace. It
//! wraps the safe async core ([`curl_rs_lib`]) in curl's public `extern "C"`
//! C ABI and is compiled into the `libcurl`-compatible shared and static
//! libraries (`libcurl.so` / `libcurl.a` / `libcurl.dylib`) — a drop-in
//! replacement for the C `libcurl` (Agent Action Plan §0.3.1 / §0.4.1).
//!
//! # The only crate that contains `unsafe`
//!
//! Per the memory-safety mandate (AAP §0.7.1), **all** raw-pointer handling at
//! the C boundary is confined to this crate: the `Box::into_raw` /
//! `Box::from_raw` handle lifecycle, the `*mut` / `*const` shims, the
//! `#[repr(C)]` public structs, and the variadic-`setopt` dispatch. The safe
//! core carries `#![forbid(unsafe_code)]` at its protocol/TLS/transfer roots and
//! this crate deliberately does not. The workspace lint policy (inherited via
//! `[lints] workspace = true`) denies `unsafe_op_in_unsafe_fn`, so every unsafe
//! operation inside an `unsafe fn` must still sit in an explicit `unsafe { }`
//! block, keeping the FFI surface auditable.
//!
//! # ABI parity
//!
//! The exported-symbol surface of the produced `cdylib` is determined solely by
//! this crate's `#[no_mangle] pub extern "C"` items, which must reproduce curl's
//! canonical export list (`lib/libcurl.def`, 100 `curl_*` symbols; AAP §0.7.2).
//! The sync-over-async bridge (AAP §0.4.4) drives the async core to completion
//! on each blocking C entrypoint via `block_on` on a thread-local current-thread
//! Tokio runtime.
//!
//! # Header generation
//!
//! `build.rs` invokes `cbindgen` against this crate's `extern "C"` /
//! `#[no_mangle]` / `#[repr(C)]` items to (re)generate a consolidated C header
//! (`generated_curl.h`) used to synchronize and verify the curated
//! `include/curl/*.h` headers, which remain authoritative (see `cbindgen.toml`).
//!
//! # Module organization
//!
//! As of this foundation checkpoint the crate declares the ABI primitive
//! modules that already exist. The full `extern "C"` symbol families (the
//! `curl_easy_*`, `curl_multi_*`, `curl_url_*`, `curl_ws_*`, `curl_mime_*`,
//! `curl_slist_*`, global, options, header, and `mprintf` shims) are authored in
//! subsequent migration steps (AAP §0.8.4 step 13) on top of these primitives.

// C-visible type definitions: opaque handles, `#[repr(C)]` public structs, the
// small C data/enum types, and the `extern "C" fn` callback typedefs. This is
// the single source of truth for every type that crosses the FFI boundary; it
// is intentionally self-contained (cbindgen runs with `parse_deps = false`).
pub mod types;

// Exact `CurlError` ↔ `CURLcode` integer mapping and the `curl_easy_strerror`
// result-string entrypoint. Backed by the canonical integer values defined in
// `curl_rs_lib::error`.
pub mod error_codes;
