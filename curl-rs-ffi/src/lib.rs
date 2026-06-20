//! `curl-rs-ffi` — the `libcurl`-compatible C ABI (drop-in `libcurl`).
//!
//! This crate is the FFI layer of the three-crate curl → Rust workspace. It
//! wraps the safe async core ([`curl_rs_lib`]) in curl's public `extern "C"`
//! C ABI and is compiled into the `libcurl`-compatible shared and static
//! libraries (`libcurl.so` / `libcurl.a` / `libcurl.dylib`) — a drop-in
//! replacement for the C `libcurl` (Agent Action Plan §0.3.1 / §0.4.1).
//!
//! # Crate-root responsibilities
//!
//! `lib.rs` itself exports **zero** `curl_*` symbols; its role is purely
//! structural:
//!
//! 1. **Module wiring.** It declares every sibling module with `pub mod` so
//!    that (a) each module's `#[no_mangle] pub extern "C" fn curl_*` items are
//!    compiled into the crate and linked into the `cdylib` / `staticlib`, and
//!    (b) `cbindgen` — configured with `parse_deps = false` and
//!    `include = ["curl-rs-ffi"]` — can traverse the whole crate tree from this
//!    root to (re)generate the consolidated C header (see `build.rs` /
//!    `cbindgen.toml`).
//! 2. **The sync-over-async bridge.** It provides [`block_on`], the
//!    thread-local *current-thread* Tokio runtime that every blocking C
//!    entrypoint (`curl_easy_perform`, the `curl_multi_*` drive functions, and
//!    the blocking `curl_ws_recv` / `curl_ws_send`) uses to drive the
//!    asynchronous `curl-rs-lib` core to completion under the synchronous C
//!    contract (AAP §0.4.4).
//! 3. **The core-crate alias.** It re-exports the async core as
//!    [`core`](crate::core) so sibling modules may reach it through the short
//!    `crate::core::…` path.
//!
//! # The only crate that contains `unsafe`
//!
//! Per the memory-safety mandate (AAP §0.7.1), **all** raw-pointer handling at
//! the C boundary is confined to this crate: the `Box::into_raw` /
//! `Box::from_raw` handle lifecycle, the `*mut` / `*const` shims, the
//! `#[repr(C)]` public structs, and the variadic-`setopt` dispatch. The safe
//! core carries `#![forbid(unsafe_code)]` at its protocol / TLS / transfer roots
//! and this crate deliberately does **not** (it cannot — the `extern "C"`
//! boundary requires `unsafe`). The workspace lint policy (inherited via
//! `[lints] workspace = true`) denies `unsafe_op_in_unsafe_fn`, so every unsafe
//! operation inside an `unsafe fn` must still sit in an explicit `unsafe { }`
//! block, keeping the FFI surface auditable. `lib.rs` itself contains no
//! `unsafe`.
//!
//! # ABI parity
//!
//! The exported-symbol surface of the produced `cdylib` is determined solely by
//! the sibling modules' `#[no_mangle] pub extern "C"` items, which together must
//! reproduce curl's canonical export list (`lib/libcurl.def`, 100 `curl_*`
//! symbols; AAP §0.7.2) and is verified by the `nm` / `objdump` parity gate.
//! Because this file defines no such items, it contributes nothing to that
//! surface — by design.
//!
//! # Header generation
//!
//! `build.rs` invokes `cbindgen` against this crate's `extern "C"` /
//! `#[no_mangle]` / `#[repr(C)]` items to (re)generate a consolidated C header
//! (`generated_curl.h`) used to synchronize and verify the curated
//! `include/curl/*.h` headers, which remain authoritative (see `cbindgen.toml`).

// NOTE: per AAP §0.7.1 this is the ONLY crate permitted `unsafe`. `lib.rs` holds
// no `unsafe` itself, but every `unsafe` block in the sibling modules must carry
// a `// SAFETY:` comment justifying the upheld invariant.

// ---------------------------------------------------------------------------
// Crate-level lint configuration.
//
// C type names are snake_case (`curl_slist`, `curl_off_t`,
// `curl_version_info_data`, …) and a handful of C-visible types are
// PascalCase-with-caps (`CURLMsg`, `CURLcode`, `CURLMcode`). Allowing these
// naming lints crate-wide lets the `#[repr(C)]` types in the sibling modules
// mirror the C names verbatim, which keeps the cbindgen output and the curated
// headers byte-identical.
//
// `unsafe_code` is intentionally NOT forbidden here (unlike `curl-rs-lib`):
// this crate is the FFI boundary (see the crate doc above). MSRV is stable 1.75
// (edition 2021); no `#![feature(...)]` / nightly-only constructs are used.
// ---------------------------------------------------------------------------
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
// AAP §0.7.1 hard rule: "every `unsafe` block carries a `// SAFETY:` comment
// that states the upheld invariant." This crate is the only one permitted
// `unsafe`, so we enforce the rule here mechanically: `undocumented_unsafe_blocks`
// (a clippy `restriction`-group lint, off by default) is turned on crate-wide so
// that any `unsafe { … }` lacking an immediately-preceding `// SAFETY:` comment
// is reported, and `cargo clippy -- -D warnings` (the AAP §0.8.1 Lint gate)
// promotes it to a hard error. This keeps the safety-documentation invariant
// from silently regressing as new FFI shims are added.
#![warn(clippy::undocumented_unsafe_blocks)]

use std::cell::RefCell;

// ---------------------------------------------------------------------------
// Core-crate alias (AAP §0.4 dependency direction: curl-rs-ffi → curl-rs-lib).
//
// Re-export the safe async core under the short name `core` so sibling modules
// can write `crate::core::Easy`, `crate::core::global_init`, … instead of the
// longer `curl_rs_lib::…`. (Modules may equivalently `use curl_rs_lib as core;`
// locally; both resolve to the same crate.)
//
// This is `pub` rather than `pub(crate)` deliberately: the alias is a
// convenience that a given module may or may not import (some siblings reference
// `curl_rs_lib::…` directly). A `pub` re-export is part of the crate's API
// surface and is therefore exempt from the `unused_imports` lint, so the
// zero-warnings build gate (AAP §0.8.1) holds regardless of which path each
// module chooses. It carries no ABI cost: only `#[no_mangle] extern "C"` items
// become exported C symbols, and this crate has no Rust-library (`lib` / `rlib`)
// consumers — it is `cdylib` + `staticlib` only.
//
// NB: within a child module a bare `core::…` path still resolves to the standard
// library's `core` crate via the extern prelude — this re-export only introduces
// the `crate::core` path and never shadows `core::ffi`, `core::ptr`, etc.
// ---------------------------------------------------------------------------
pub use curl_rs_lib as core;

// ===========================================================================
// Module declarations — the full FFI surface (13 modules).
//
// Every module that defines exported `curl_*` symbols MUST be reachable via
// `mod` from this root, both so the symbols are linked into the library and so
// `cbindgen` can traverse them. All are `pub` so the cbindgen
// `include = ["curl-rs-ffi"]` traversal reaches them. Declaration order is not
// significant to the compiler; the grouping below (foundational first) is for
// readability and mirrors `lib/libcurl.def` symbol families.
// ===========================================================================

// ---- foundational: C-visible types and result-code mapping ----------------

/// C-visible type definitions: opaque handles (`CURL` / `CURLM` / `CURLSH` /
/// `CURLU`), `#[repr(C)]` public structs, the small C data / enum types, and the
/// `extern "C" fn` callback typedefs. The single source of truth for every type
/// that crosses the FFI boundary (cbindgen runs with `parse_deps = false`, so it
/// is intentionally self-contained).
pub mod types;

/// Exact `CurlError` ↔ `CURLcode` integer mapping (and the sibling result-code
/// enums `CURLMcode` / `CURLUcode` / `CURLSHcode` / `CURLHcode`) plus the
/// `result_to_*` helpers the shims use to convert `core::Result<…>` into the C
/// integer contract. Backed by the canonical integers in `curl_rs_lib::error`.
pub mod error_codes;

// ---- public symbol families -----------------------------------------------

/// `curl_slist` string-list API (`curl_slist_append`, `curl_slist_free_all`)
/// operating on the raw `#[repr(C)] curl_slist` linked list.
pub mod slist;

/// Process-global init / cleanup / trace / sslset, version reporting,
/// escape / unescape, `curl_free`, and the misc utilities (`curl_getenv`,
/// `curl_getdate`, `curl_strequal` / `curl_strnequal`). Owns the crate-wide
/// C-heap string allocation contract that `curl_free` reclaims.
pub mod global;

/// The easy-handle API (`curl_easy_init` / `setopt` / `perform` / `getinfo` /
/// `cleanup` / …). The opaque `CURL` handle wraps `core::Easy`;
/// `curl_easy_perform` is the canonical [`block_on`] bridge point (AAP §0.4.4).
pub mod easy;

/// The multi-interface API (`curl_multi_*`, `curl_pushheader_*`). The opaque
/// `CURLM` handle wraps `core::Multi`; the drive functions bridge the
/// synchronous event-loop contract to the core's multi-thread runtime (owned
/// inside `curl-rs-lib`), preserving `curl_multi_socket_action` /
/// `CURLM_CALL_MULTI_PERFORM` semantics for external event loops (AAP §0.7.4).
pub mod multi;

/// The shared-state API (`curl_share_init` / `setopt` / `cleanup` /
/// `strerror`). The opaque `CURLSH` handle wraps `core::Share`
/// (`Arc<Mutex<…>>`-backed).
pub mod share;

/// The URL API (`curl_url`, `curl_url_dup`, `curl_url_get`, `curl_url_set`,
/// `curl_url_strerror`, `curl_url_cleanup`) over `core::url::CurlUrl`. The
/// opaque `CURLU` handle boxes a [`core::url::CurlUrl`]; `curl_url_get` hands
/// out caller-owned strings reclaimed via `curl_free`.
pub mod url;

/// The WebSockets API (`curl_ws_recv` / `curl_ws_send` / `curl_ws_start_frame` /
/// `curl_ws_meta`); the blocking `recv` / `send` also bridge via [`block_on`].
pub mod ws;

/// Option-by-name / by-id introspection (`curl_easy_option_by_name`,
/// `curl_easy_option_by_id`, `curl_easy_option_next`).
pub mod options;

/// The response-header API (`curl_easy_header`, `curl_easy_nextheader`).
pub mod header;

/// The `curl_mprintf` printf family (`curl_mprintf` / `mfprintf` / `msprintf` /
/// `msnprintf` / `maprintf` and the `v*printf` variants). The ten symbols are
/// C-variadic / `va_list`-taking and so cannot be defined in stable Rust; they
/// are provided by the `csrc/mprintf.c` trampoline compiled and linked by
/// `build.rs` (AAP §0.7.2). This module documents that strategy and carries the
/// behavioral tests for it; it defines no `#[no_mangle]` symbols itself.
pub mod mprintf;

/// The MIME / multipart form-data API (`curl_mime_*`) plus the legacy
/// `curl_formadd` / `curl_formget` / `curl_formfree` form symbols. The variadic
/// `curl_formadd` symbol itself is provided by a C trampoline
/// (`csrc/formadd_trampoline.c`) that calls this module's `curlrs_formadd_impl`.
pub mod mime;

// ===========================================================================
// The sync-over-async `block_on` bridge (AAP §0.4.4).
//
// The C ABI is synchronous; `curl-rs-lib` is asynchronous on Tokio. Each
// blocking C entrypoint drives the async core to completion synchronously by
// calling `block_on` on a per-thread current-thread runtime. This is the Rust
// analog of curl's C `easy_perform()` (lib/easy.c), which runs a transfer to
// completion by looping an internal multi handle until done.
// ===========================================================================

thread_local! {
    /// Per-thread, lazily-created current-thread Tokio runtime used by
    /// [`block_on`].
    ///
    /// A `thread_local!` (rather than one shared runtime) gives each OS thread
    /// that calls into libcurl its own runtime, matching libcurl's
    /// per-thread-handle usage model and avoiding cross-thread sharing of this
    /// bridge runtime. The `const` initializer (a `thread_local!` feature stable
    /// since Rust 1.59, well within MSRV 1.75) stores only the `None`
    /// placeholder with no lazy-init machinery; the runtime is built on first
    /// use inside `block_on`.
    static FFI_RT: RefCell<Option<tokio::runtime::Runtime>> = const { RefCell::new(None) };
}

/// Drive a future to completion on this thread's current-thread Tokio runtime,
/// returning its output.
///
/// This is the single sync-over-async bridge for the whole FFI crate
/// (AAP §0.4.4). Blocking C entrypoints — `curl_easy_perform`, the
/// `curl_multi_*` drive functions, and the blocking `curl_ws_recv` /
/// `curl_ws_send` — call this to honor their synchronous C contract while the
/// underlying `curl-rs-lib` engine is asynchronous.
///
/// The runtime is **current-thread** (built via
/// [`tokio::runtime::Builder::new_current_thread`]): the FFI crate only enables
/// Tokio's `rt` feature, and the multi-thread runtime that backs the `Multi`
/// handle is owned *inside* `curl-rs-lib`, never here. `enable_all()` turns on
/// the I/O and time drivers — available through workspace feature unification,
/// since `curl-rs-lib` pulls Tokio's `net` / `time` features — so real network
/// transfers driven through this bridge make progress.
///
/// The per-thread runtime is created on first use and then reused for every
/// subsequent call on the same thread, so repeated `curl_easy_perform` calls on
/// one thread pay runtime-construction cost only once.
///
/// # Re-entrancy
///
/// [`tokio::runtime::Runtime::block_on`] panics if called while already inside a
/// Tokio runtime context. The blocking easy / ws entrypoints are leaf calls and
/// never nest, so this does not arise for them. The `curl_multi_*` interface
/// must **not** call `block_on` recursively: multi drive uses the core's
/// non-blocking `socket_action` / `poll` semantics (see `multi.rs`), so the
/// multi path advances the runtime without re-entering `block_on` from within
/// it. A recursive call fails fast (the thread-local `RefCell` is already
/// mutably borrowed), surfacing the misuse rather than corrupting state.
pub(crate) fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    FFI_RT.with(|cell| {
        let mut slot = cell.borrow_mut();
        // Build the per-thread runtime on first use; reuse it thereafter.
        let rt = slot.get_or_insert_with(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("curl-rs-ffi: failed to build thread-local Tokio runtime")
        });
        rt.block_on(fut)
    })
}

/// Drop a value, then **drive this thread's bridge runtime** so any detached
/// async teardown tasks the drop signalled run to completion before control
/// returns — preventing those tasks from being reaped (and panicking) when the
/// per-thread runtime is later torn down at thread exit.
///
/// # Why this is needed
///
/// Tearing down an easy handle (`curl_easy_cleanup`) reclaims and drops a
/// [`core::Easy`](curl_rs_lib::Easy), which transitively drops any live
/// connection it still owns. An `sftp://` / `scp://` handle owns a russh SSH
/// session. russh runs its session as a **detached** task — the run-loop is
/// `tokio::spawn`ed at connect (`russh/src/client/mod.rs`) and its `JoinHandle`
/// is stored on russh's `Handle`, whose `Drop` only logs (it never aborts or
/// joins the task). russh-sftp likewise drives the SFTP subsystem on its own
/// spawned worker. Dropping our [`core::Easy`] drops russh's `Handle` and the
/// SFTP session handle, which **closes** those tasks' command/request channels
/// but does not itself run the tasks to exit.
///
/// Those tasks then sit idle (the per-thread bridge runtime is not being driven
/// after `curl_easy_perform`'s [`block_on`] returned) until the runtime is
/// dropped at thread exit. Current-thread runtime shutdown *reaps* still-live
/// tasks, dropping the `Channel`s they hold; russh's `ChannelCloseOnDrop::drop`
/// then calls [`tokio::spawn`] for a best-effort channel-close — and spawning
/// during runtime shutdown panics with *"The Tokio context thread-local
/// variable has been destroyed"*. (The CLI never hit this: its
/// `#[tokio::main]` runtime stays active across the handle drop and drives those
/// tasks to exit as part of normal shutdown.)
///
/// # How it fixes the root cause
///
/// The value is dropped **inside** a [`block_on`] (so the runtime context is
/// live: any `Drop`-spawned cleanup, such as the `ChannelCloseOnDrop` spawn,
/// registers on the healthy runtime instead of panicking). The drop closes the
/// detached tasks' channels, so they are now ready to observe EOF and exit. We
/// then [`yield_now`](tokio::task::yield_now) repeatedly: each yield hands
/// control back to the current-thread executor, which polls those ready tasks.
/// Their exit paths require **no I/O-readiness wait** — russh's `run_inner`
/// receiver-closed branch just sets `disconnected` and `break`s, and the
/// best-effort channel-close is an in-memory mpsc send plus an
/// immediately-ready loopback write — so cooperative yields are sufficient to
/// drive them to completion here, while the runtime is healthy. Once they have
/// exited, no live task survives to thread exit, so the eventual runtime drop
/// has nothing to reap and cannot re-enter `tokio::spawn` without a context.
///
/// The yield count is a generous fixed bound (teardown needs only a handful of
/// rounds), so cleanup can never hang on a stuck task, and for a non-SSH handle
/// — which has no such detached teardown task — the loop simply finds nothing
/// ready and returns in microseconds.
pub(crate) fn drop_and_drain<T>(value: T) {
    block_on(async move {
        // Drop inside the live runtime context so best-effort `Drop`-spawned
        // cleanups register on the healthy runtime rather than panicking.
        drop(value);
        // Hand control to the executor so the now-closed detached teardown
        // tasks (russh session run-loop + russh-sftp worker + the best-effort
        // channel-close spawn) are polled to exit *now*. Bounded so a stuck
        // task can never hang `curl_easy_cleanup`.
        for _ in 0..256 {
            tokio::task::yield_now().await;
        }
    });
}

#[cfg(test)]
mod tests {
    //! Unit tests for the sync-over-async bridge. They exercise [`super::block_on`]
    //! at runtime (so the thread-local runtime is actually built and reused)
    //! without performing any network I/O, keeping them hermetic and fast.

    #[test]
    fn block_on_drives_future_to_completion() {
        let v = super::block_on(async { 1 + 1 });
        assert_eq!(v, 2);
    }

    #[test]
    fn block_on_reuses_thread_local_runtime() {
        // The first call builds the per-thread runtime; subsequent calls must
        // reuse it (no panic, correct results) — exercising the lazy-init +
        // reuse path of `get_or_insert_with`.
        assert_eq!(super::block_on(async { 40 + 2 }), 42);
        assert_eq!(super::block_on(async { "ok" }), "ok");
    }

    #[test]
    fn block_on_drives_nested_awaits_within_one_future() {
        // A single future may await sub-futures; the current-thread runtime
        // drives the whole tree to completion in one `block_on` call.
        async fn doubled(x: u64) -> u64 {
            x * 2
        }
        let total = super::block_on(async {
            let a = doubled(10).await;
            let b = doubled(11).await;
            a + b
        });
        assert_eq!(total, 42);
    }
}
