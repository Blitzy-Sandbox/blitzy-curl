// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP chunked Transfer-Encoding codec (← `lib/http_chunks.c`).
//!
//! This module implements the RFC 9112 §7.1 chunked transfer-coding decoder and
//! encoder used by the HTTP/1.1 message framing in [`super::h1`]. It is consumed
//! by the response-parsing path in [`super`] when a response carries
//! `Transfer-Encoding: chunked`, and by the request path for chunked uploads.
//!
//! This module contains **zero** `unsafe`: the crate root's
//! [`forbid(unsafe_code)`](crate) makes any `unsafe` token a hard compile error,
//! and a CI grep asserts the token never appears under `curl-rs-lib/src/`.
//!
//! The concrete codec is implemented in the dedicated `http_chunks.c` port that
//! owns this file; [`super`] (the HTTP family root) depends only on the module
//! path existing, not on any particular item, so the two can be developed
//! independently and reconciled without coupling.
