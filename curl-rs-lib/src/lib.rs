//! `curl-rs-lib` — the memory-safe Rust core of the curl rewrite.
//!
//! This crate is the Rust replacement for curl's `libcurl` *internals* (the
//! `lib/` tree of the C project). It hosts the asynchronous transfer engine,
//! the protocol implementations, the single `rustls`-based TLS layer, the
//! connection-filter chain, DNS resolution, authentication, and the stateful
//! subsystems (cookies, HSTS, alt-svc, `.netrc`, IDN, PSL). The crate is
//! consumed by two leaf crates that never depend on each other:
//!
//! * `curl-rs`     — the `curl` command-line tool (a `clap`-based binary).
//! * `curl-rs-ffi` — the `libcurl`-compatible C ABI (`cdylib` + `staticlib`),
//!   exposing `extern "C"` symbols and regenerating `include/curl/curl.h` via
//!   `cbindgen`.
//!
//! See the Agent Action Plan §0.4 for the full target architecture.
//!
//! # Memory-safety policy
//!
//! The hard rule of the rewrite (AAP §0.7.1 / §0.8.1) is **zero `unsafe`
//! outside the FFI crate**. This crate therefore contains no `unsafe` in its
//! protocol, TLS, and transfer logic; the few modules that interact with the
//! operating system at the raw-pointer level (for example non-blocking-socket
//! configuration) keep their `unsafe` minimal and locally documented with a
//! `// SAFETY:` comment.
//!
//! Rather than apply a single crate-wide `#![forbid(unsafe_code)]` — which
//! would block the small, audited OS-integration primitives this core legitimately
//! needs — each leaf module that is provably allocation- and pointer-free opts
//! into `#![forbid(unsafe_code)]` at its own root (see, e.g., [`version`],
//! [`slist`], [`request`]). The workspace lint policy
//! (`[workspace.lints]` in the root `Cargo.toml`, inherited here via
//! `[lints] workspace = true`) additionally denies `unsafe_op_in_unsafe_fn`
//! crate-wide, so any future `unsafe fn` must still wrap its unsafe operations
//! in explicit `unsafe` blocks.
//!
//! # Capability / feature lockstep
//!
//! Optional capabilities are selected by Cargo features whose defaults mirror
//! curl's default build (AAP §0.6.2). Critically, a capability's *implementation*
//! and its *advertised* presence in [`version::version`] are gated on the **same**
//! Cargo feature, so `curl --version` never reports a capability whose code was
//! compiled out. The `idn` and `psl` features are the canonical examples: their
//! implementation modules ([`idn`], [`psl`]) and their version-string tokens are
//! gated identically, and a lockstep test in [`version`] proves the two never
//! drift apart.
//!
//! # Module organization
//!
//! The module tree mirrors the responsibilities of the C `lib/` translation
//! units while grouping related concerns into subtrees. As of this foundation
//! checkpoint the engine (`easy`, `multi`, `transfer`, …), the `conn/`,
//! `protocols/`, `auth/`, and `dns/` subtrees, and the remaining public-API
//! surface are authored in subsequent migration steps (AAP §0.8.4); this root
//! declares the foundation modules that already exist so that the workspace
//! parses and builds as a closed unit.

// ---------------------------------------------------------------------------
// Inherit the workspace lint policy (`[workspace.lints]`); see the root
// `Cargo.toml`. No crate-wide `#![forbid(unsafe_code)]` is applied here on
// purpose — see the "Memory-safety policy" section above.
// ---------------------------------------------------------------------------

// Error handling and result-code mapping. The foundation for every fallible
// path in the crate and the source of the exact `CURLcode`/`CURLMcode`/
// `CURLUcode`/`CURLSHcode` integer values consumed at the FFI boundary.
pub mod error;

// Version and capability reporting (`lib/version.c`). Single source of truth
// for the `curl --version` banner and `curl_version_info`; feature tokens are
// gated in lockstep with the implementation modules they describe.
pub mod version;

// Public-facing helpers and data models.
pub mod escape; // URL percent-encode / -decode (`lib/escape.c`).
pub mod headers; // Response-header data model (`lib/headers.c`).
pub mod options; // Option metadata table (`lib/easyoptions.c`).
pub mod slist; // `curl_slist` string list (`lib/slist.c`).
pub mod url; // URL parsing / building — the URL API (`lib/url.c`, `lib/urlapi.c`).

// Stateful subsystems (`lib/*.c`).
pub mod altsvc; // HTTP Alt-Svc cache.
pub mod cookie; // HTTP cookie engine and jar (feature-gated module, `cookies`).
pub mod hsts; // HTTP Strict-Transport-Security store (feature-gated module).
pub mod idn; // Internationalized Domain Names (feature `idn`).
pub mod netrc; // `.netrc` credential file parsing.
pub mod psl; // Public Suffix List handling (feature `psl`).

// Transfer-support subsystems.
pub mod content_encoding; // gzip/deflate/brotli/zstd decoding dispatch.
pub mod progress; // Transfer progress accounting, timers, and the progress meter.
pub mod ratelimit; // Transfer rate limiting / pacing.
pub mod request; // Per-request buffer and byte accounting.
pub mod transfer; // The async transfer engine (type-state flow) — `lib/transfer.c`.

// Subsystem module trees.
pub mod auth; // Authentication: HTTP schemes + the shared SASL state machine (`lib/vauth/`, `lib/curl_sasl.c`, …).
pub mod conn; // Connection-filter chain + filters (`lib/cfilters.c`, `lib/cf-*.c`).
pub mod proxy; // SOCKS / HTTP proxy + no-proxy matching (`lib/socks.c`, …).
pub mod tls; // The single `rustls` TLS backend (`lib/vtls/`).
pub mod util; // Portable utilities and containers (`lib/curlx/`, `lib/hash.c`, …).
