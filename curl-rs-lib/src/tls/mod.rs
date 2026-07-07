// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! # TLS layer — the single rustls backend
//!
//! Root of the TLS subtree, a language rewrite of curl's `lib/vtls/` directory. Where curl
//! selected among seven C TLS backends via `#ifdef`, this rewrite collapses them onto a
//! single, always-compiled `rustls` implementation with certificate validation on by default
//! (AAP §0.1.1). The whole subtree is written in safe Rust — the crate root's
//! `#![forbid(unsafe_code)]` applies here, so there is zero `unsafe` in the TLS logic
//! (AAP §0.7.2).
//!
//! ## Submodules
//!
//! * [`config`] — [`rustls::ClientConfig`] construction from curl's SSL option
//!   surface (from `lib/vtls/vtls.c`, `lib/vtls/rustls.c`, and
//!   `lib/vtls/cipher_suite.c`). Certificate validation is on by default and
//!   `--insecure` warns before disabling it.
//! * [`hostname`] — RFC 6125 hostname verification (from `lib/vtls/hostcheck.c`).
//! * [`keylog`] — `SSLKEYLOGFILE` key-material logging for TLS debugging (from
//!   `lib/vtls/keylog.c`).
//! * [`session_cache`] — TLS session-resumption store (from
//!   `lib/vtls/vtls_scache.c`).
//!
//! The remaining piece of the layout (the top-level connector) is added in a
//! later checkpoint, derived from its `lib/vtls/` source-of-truth.

pub mod config;
pub mod hostname;
pub mod keylog;
pub mod session_cache;
