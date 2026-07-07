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
//! At this foundation checkpoint the following pieces are implemented; the remaining pieces of
//! the layout (`config`, `session_cache`, and the top-level connector) are added in later
//! checkpoints, each derived from its `lib/vtls/` source-of-truth.
//!
//! * [`hostname`] — RFC 6125 hostname verification (from `lib/vtls/hostcheck.c`).
//! * [`keylog`] — `SSLKEYLOGFILE` key-material logging for TLS debugging (from
//!   `lib/vtls/keylog.c`).

pub mod hostname;
pub mod keylog;
pub mod session_cache;
