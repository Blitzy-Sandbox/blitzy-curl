// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP/2 multiplexing and framing (← `lib/http2.c`).
//!
//! This module drives HTTP/2 stream multiplexing over `hyper`/`h2`, translating
//! the shared request representation from [`super`] (the HTTP family root) into
//! the HTTP/2 header block via [`super::http_req_to_h2`]. Version negotiation in
//! [`super`] selects this module when ALPN negotiates `h2`, on `h2` prior
//! knowledge, or after an `Upgrade: h2c` handshake.
//!
//! This module contains **zero** `unsafe`: the crate root's
//! [`forbid(unsafe_code)`](crate) makes any `unsafe` token a hard compile error.
//!
//! The concrete HTTP/2 driver is implemented in the `http2.c` port that owns
//! this file; [`super`] depends only on the module path existing.
