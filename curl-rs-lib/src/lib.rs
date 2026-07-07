// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! # curl-rs-lib — the safe-Rust core of the curl/libcurl 8.19.0-DEV rewrite
//!
//! `curl-rs-lib` is the foundation crate of the three-crate workspace. It is a language
//! rewrite of curl's `lib/` tree and owns the protocol handlers, the TLS layer, the
//! authentication mechanisms, DNS resolution, connection management, and the transfer core.
//! It is consumed by both sibling crates — the `curl-rs` CLI and the `curl-rs-ffi` C-ABI
//! layer — and depends on neither of them.
//!
//! ## Memory-safety guarantee
//!
//! The entire crate is written in safe Rust: [`forbid(unsafe_code)`](https://doc.rust-lang.org/reference/attributes/codegen.html)
//! is applied crate-wide below, which makes any `unsafe` block anywhere in this crate a hard
//! **compile error** (not merely a lint). `unsafe` is confined to the `curl-rs-ffi` boundary
//! crate (AAP §0.7.2); eliminating it from the core is the entire reason this rewrite exists.
//! A CI grep audit additionally asserts that the token `unsafe` never appears under
//! `curl-rs-lib/src/`.
//!
//! ## Module map
//!
//! The public module tree mirrors the AAP §0.3.1 layout. At this foundation checkpoint the
//! modules that are already implemented are wired up here; the remaining modules named in the
//! layout (for example the concrete protocol handlers and the connection/DNS subtrees) are
//! added, each derived from its C source-of-truth, in later checkpoints.
//!
//! * [`error`] — the typed error hierarchy and the `CURLcode`/`CURLMcode`/`CURLUcode` integer
//!   mirrors (from `lib/strerror.c`).
//! * [`escape`] / [`idn`] — URL percent-encoding and internationalized-domain handling.
//! * [`psl`] — public-suffix-list queries backing cookie-domain validation.
//! * [`progress`] / [`request`] — transfer progress metering and per-request state.
//! * [`content_encoding`] — `Content-Encoding` decompression (gzip/deflate, and — behind
//!   their features — brotli/zstd).
//! * [`hsts`] / [`altsvc`] / [`netrc`] — the byte-compatible on-disk state formats.
//! * [`auth`] — the authentication subsystem (Basic/Digest/Bearer/NTLM/Negotiate/SASL/SCRAM).
//! * [`tls`] — the single rustls-based TLS layer.
//! * [`protocols`] — the protocol-handler subtree.
//!
//! ## Feature matrix
//!
//! The Cargo `[features]` in this crate's manifest reproduce curl's `CURL_DISABLE_*` / `USE_*`
//! guards one-to-one (AAP §0.5.3). Feature-gated modules are attached to the tree under a
//! matching `#[cfg(feature = "...")]` so a disabled protocol compiles out exactly as it does
//! in a stock curl build.

// The memory-safety cornerstone of the whole rewrite: no `unsafe` may appear in this crate.
#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// Foundation modules — always compiled (no curl `CURL_DISABLE_*` guard maps to them).
// ---------------------------------------------------------------------------

pub mod altsvc;
pub mod content_encoding;
pub mod error;
pub mod escape;
pub mod hsts;
pub mod idn;
pub mod netrc;
pub mod progress;
pub mod psl;
pub mod request;

// ---------------------------------------------------------------------------
// Authentication subsystem (root always present; optional GSSAPI/SPNEGO internals are
// feature-gated within the subtree — see `auth::kerberos` / `auth::negotiate`).
// ---------------------------------------------------------------------------

pub mod auth;

// ---------------------------------------------------------------------------
// TLS layer (the single rustls backend).
// ---------------------------------------------------------------------------

pub mod tls;

// ---------------------------------------------------------------------------
// Protocol handlers (individual handlers inside the subtree are feature-gated to match
// curl's per-protocol `CURL_DISABLE_*` guards).
// ---------------------------------------------------------------------------

pub mod protocols;
