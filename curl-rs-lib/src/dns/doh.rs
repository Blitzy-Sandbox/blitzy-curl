//! DNS-over-HTTPS (DoH) resolver.
//!
//! Replaces C files: lib/doh.c, lib/doh.h.
//! This is a stub file that will be replaced by the implementation agent.

use std::net::SocketAddr;

use async_trait::async_trait;

use crate::error::CurlError;
use super::{IpVersion, Resolver};

/// DNS-over-HTTPS resolver that sends DNS queries as HTTP requests.
pub struct DohResolver {
    /// The DoH server URL (e.g. `https://dns.google/dns-query`).
    #[allow(dead_code)]
    doh_url: String,
}

impl DohResolver {
    /// Create a new DoH resolver targeting the given URL.
    pub fn new(doh_url: String) -> Self {
        Self { doh_url }
    }
}

#[async_trait]
impl Resolver for DohResolver {
    async fn resolve(
        &self,
        host: &str,
        port: u16,
        _ip_version: IpVersion,
    ) -> Result<Vec<SocketAddr>, CurlError> {
        // Stub: full implementation will be provided by the DoH agent.
        // For now, fall back to system resolution so the module compiles.
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
        "doh"
    }
}
