//! Authentication module — SASL, HTTP Digest, NTLM, Negotiate, OAuth2.
//!
//! This module declares all authentication submodules and provides shared
//! utilities for SPN construction, domain detection, and host authorization.

pub mod basic;
pub mod bearer;
pub mod kerberos;
