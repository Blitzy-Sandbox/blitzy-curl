//! TLS abstraction layer for curl-rs — rustls only.
//!
//! This module provides the TLS subsystem, replacing all 7 C TLS backends
//! (OpenSSL, Schannel, GnuTLS, mbedTLS, wolfSSL, Rustls, Apple Security)
//! with a single rustls-based implementation.

pub mod hostname;
