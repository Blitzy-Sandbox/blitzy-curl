//! Hickory-DNS resolver (feature-gated).
//!
//! Replaces C: lib/asyn-ares.c (c-ares async DNS) with a pure-Rust resolver.
//! This is a stub file that will be replaced by the implementation agent.

use std::net::SocketAddr;

use async_trait::async_trait;

use crate::error::CurlError;
use super::{IpVersion, Resolver};

/// Pure-Rust DNS resolver powered by hickory-dns.
pub struct HickoryResolver;

impl HickoryResolver {
    /// Create a new hickory-dns resolver instance.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Resolver for HickoryResolver {
    async fn resolve(
        &self,
        host: &str,
        port: u16,
        _ip_version: IpVersion,
    ) -> Result<Vec<SocketAddr>, CurlError> {
        // Stub: full implementation will be provided by the hickory agent.
        let addr_str = format!("{}:{}", host, port);
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&addr_str)
            .await
            .map_err(|_| CurlError::CouldntResolveHost)?
            .collect();
        if addrs.is_empty() {
            return Err(CurlError::CouldntResolveHost);
        }
        Ok(addrs)
    }

    fn name(&self) -> &'static str {
        "hickory-dns"
    }
}
