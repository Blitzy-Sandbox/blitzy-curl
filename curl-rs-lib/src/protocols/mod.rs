// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! # Protocol handlers
//!
//! Root of the protocol subtree, a language rewrite of curl's per-protocol `lib/*.c` handlers.
//! In curl the supported protocol set is chosen with `CURL_DISABLE_*` `#ifdef` guards; here
//! each handler module is attached under a matching `#[cfg(feature = "...")]`, so a disabled
//! protocol compiles out exactly as it does in a stock curl build (AAP §0.5.3).
//!
//! ## Submodules
//!
//! At this foundation checkpoint the following handler support is implemented; the remaining
//! handlers named in the AAP §0.3.1 layout (the `http` subtree, `ftp`, the `ssh` subtree,
//! `imap`/`pop3`/`smtp`, and the auxiliary protocols) are added in later checkpoints, each
//! derived from its `lib/*.c` source-of-truth.
//!
//! * [`ftp_list`] — parser for FTP `LIST` directory-listing output, used by the FTP handler
//!   (from `lib/ftplistparser.c`). Gated by the `ftp` feature (curl's `CURL_DISABLE_FTP`).

#[cfg(feature = "ftp")]
pub mod ftp_list;
