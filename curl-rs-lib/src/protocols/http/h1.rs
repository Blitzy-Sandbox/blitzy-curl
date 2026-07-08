// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP/1.1 message framing and transfer driver (← `lib/http1.c`).
//!
//! This module drives an HTTP/1.x request/response exchange over the connection
//! filter chain, reusing the shared request/response header machinery declared
//! in [`super`] (the HTTP family root). Version negotiation in [`super`] selects
//! this module when the connection speaks HTTP/1.0 or HTTP/1.1.
//!
//! This module contains **zero** `unsafe`: the crate root's
//! [`forbid(unsafe_code)`](crate) makes any `unsafe` token a hard compile error.
//!
//! The concrete HTTP/1.1 driver is implemented in the `http1.c` port that owns
//! this file; [`super`] depends only on the module path existing, keeping the
//! two independently developable and cleanly reconcilable.
