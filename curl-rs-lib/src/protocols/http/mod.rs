//! HTTP protocol handler implementations for curl-rs.
//!
//! This module contains the HTTP-specific protocol implementations including
//! HTTP/1.x, HTTP/2, HTTP/3, chunked transfer encoding, proxy support, and
//! AWS Signature V4 request signing.

pub mod chunks;
