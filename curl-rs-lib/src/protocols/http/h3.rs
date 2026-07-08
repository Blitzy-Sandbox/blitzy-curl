// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP/3 over QUIC (← `lib/vquic/curl_ngtcp2.c` + `lib/vquic/curl_quiche.c`).
//!
//! This module collapses curl's two C QUIC backends onto `quinn` + `h3` +
//! `h3-quinn`, translating the shared request representation from [`super`] (the
//! HTTP family root) into the HTTP/3 header block via [`super::http_req_to_h2`]
//! (HTTP/3 reuses the same pseudo-header transform as HTTP/2). Version
//! negotiation in [`super`] selects this module when ALPN negotiates `h3` or on
//! HTTP/3 prior knowledge.
//!
//! This module contains **zero** `unsafe`: the crate root's
//! [`forbid(unsafe_code)`](crate) makes any `unsafe` token a hard compile error.
//!
//! The concrete HTTP/3 driver is implemented in the QUIC port that owns this
//! file; [`super`] depends only on the module path existing.
