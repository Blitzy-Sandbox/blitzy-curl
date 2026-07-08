// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! AWS SigV4 request signing (← `lib/http_aws_sigv4.c`).
//!
//! This module computes the `Authorization: AWS4-HMAC-SHA256 ...` header for the
//! `CURLAUTH_AWS_SIGV4` mechanism. It is the highest-precedence host
//! authentication scheme in [`super`]'s output-auth ordering
//! (see [`super::http_output_auth`]) and is never used for proxy auth.
//!
//! This module contains **zero** `unsafe`: the crate root's
//! [`forbid(unsafe_code)`](crate) makes any `unsafe` token a hard compile error.
//!
//! The concrete signing logic is implemented in the `http_aws_sigv4.c` port that
//! owns this file; [`super`] depends only on the module path existing.
