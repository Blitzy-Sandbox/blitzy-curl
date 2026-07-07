// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! SCRAM-SHA authentication state (RFC 5802 / RFC 7677).
//!
//! Foundation for the SCRAM family of SASL mechanisms (`SCRAM-SHA-1`, `SCRAM-SHA-256`) driven
//! by the SASL engine in [`super::sasl`]. curl gained SCRAM support through its SASL layer;
//! this rewrite implements it in pure Rust rather than via the optional external `gsasl` C
//! library. This module owns the per-exchange SCRAM challenge/response state.

/// Per-exchange SCRAM state (RFC 5802).
///
/// Holds the values exchanged during the client-first / server-first / client-final /
/// server-final message flow: the two nonces are concatenated to form the combined nonce, and
/// the salt plus iteration count parameterize the salted-password PBKDF2 derivation.
#[derive(Debug, Default)]
pub struct ScramData {
    /// The client-generated nonce (from the client-first message).
    pub client_nonce: String,
    /// The server-appended nonce (from the server-first message); combined with
    /// `client_nonce` it forms the full nonce echoed in the client-final message.
    pub server_nonce: String,
    /// The server-supplied salt applied to the password before hashing.
    pub salt: Vec<u8>,
    /// The PBKDF2 iteration count supplied by the server.
    pub iterations: u32,
}
