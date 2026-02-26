//! Proxy support for curl-rs.
//!
//! This module provides:
//! - **No-proxy matching**: Evaluates hostnames and IP addresses against the `NO_PROXY`
//!   environment variable or `--noproxy` option, supporting hostname suffix matching,
//!   IPv4/IPv6 CIDR notation, and wildcard (`*`) entries.

pub mod noproxy;
pub mod socks;

// Re-export key functions for ergonomic access.
pub use noproxy::{check_noproxy, cidr4_match, cidr6_match};
pub use socks::{SocksProxyCode, SocksProxyFilter, SocksVersion};
