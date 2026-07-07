// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! OAuth 2.0 Bearer-token authentication (RFC 6750).
//!
//! Language rewrite of curl's OAuth bearer handling (`lib/vauth/oauth2.c`). For HTTP, Bearer
//! authentication sends the application-supplied token verbatim in an
//! `Authorization: Bearer <token>` header; the token is configured through
//! `CURLOPT_XOAUTH2_BEARER`. This module owns that per-transfer token.

/// OAuth 2.0 Bearer-token state (RFC 6750).
///
/// Holds the bearer token provided by the application. The token is sensitive credential
/// material and is therefore never emitted by the `Debug` output of surrounding types beyond
/// this struct's own derived formatting.
#[derive(Debug, Default, Clone)]
pub struct BearerData {
    /// The bearer token to place after `Bearer ` in the `Authorization` header.
    pub token: String,
}
