// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP Digest authentication state.
//!
//! Language rewrite of curl `lib/vauth/digest.c` + `lib/http_digest.c` and the
//! `struct digestdata` blob (`lib/urldata.h`). curl selected between a crypto-library
//! implementation and a Windows SSPI implementation; this rewrite keeps only the portable,
//! pure-Rust path (SSPI dropped, AAP §0.2.2). This module owns the per-connection Digest
//! challenge state that the request/response handler reads (RFC 7616).

/// Digest hashing algorithm advertised in the `WWW-Authenticate: Digest` challenge
/// (curl's `digest` algorithm selector).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// `MD5` (the RFC 2617 default).
    #[default]
    Md5,
    /// `MD5-sess`.
    Md5Sess,
    /// `SHA-256` (RFC 7616).
    Sha256,
    /// `SHA-256-sess`.
    Sha256Sess,
    /// `SHA-512-256` (RFC 7616).
    Sha512_256,
    /// `SHA-512-256-sess`.
    Sha512_256Sess,
}

/// Per-connection HTTP Digest state (curl's `struct digestdata`).
///
/// Populated from the server's `WWW-Authenticate: Digest` challenge and consumed when building
/// the `Authorization: Digest` response. The `nonce_count` field is the monotonically
/// increasing `nc` value curl maintains across requests that reuse the same nonce.
#[derive(Debug, Default)]
pub struct DigestData {
    /// Server-supplied `nonce`.
    pub nonce: Option<String>,
    /// Client-generated `cnonce`.
    pub cnonce: Option<String>,
    /// Protection space `realm`.
    pub realm: Option<String>,
    /// Opaque value echoed back verbatim.
    pub opaque: Option<String>,
    /// Quality of protection (`qop`), e.g. `auth` or `auth-int`.
    pub qop: Option<String>,
    /// Selected hashing algorithm.
    pub algorithm: DigestAlgorithm,
    /// The `nc` nonce-count for the current nonce.
    pub nonce_count: u32,
    /// Whether the server marked the previous nonce `stale`.
    pub stale: bool,
    /// Whether the server requested username hashing (`userhash`).
    pub userhash: bool,
}
