// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP proxy request handling (← `lib/http_proxy.c`).
//!
//! This module implements HTTP proxy support — request-target rewriting for
//! forward proxies and the `CONNECT` tunnel establishment path — reusing the
//! shared header machinery and the `Proxy-Authorization` output path from
//! [`super`] (the HTTP family root).
//!
//! This module contains **zero** `unsafe`: the crate root's
//! [`forbid(unsafe_code)`](crate) makes any `unsafe` token a hard compile error.
//!
//! The concrete proxy logic is implemented in the `http_proxy.c` port that owns
//! this file; [`super`] depends only on the module path existing.
