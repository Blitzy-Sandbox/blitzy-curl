//! System DNS resolver using `tokio::net::lookup_host`.
//!
//! Replaces C files: lib/hostip4.c, lib/hostip6.c, lib/asyn-thrdd.c.
//! This is a stub file that will be replaced by the implementation agent.

use std::net::SocketAddr;

use async_trait::async_trait;

use crate::error::CurlError;
use super::{IpVersion, Resolver};

/// System DNS resolver that delegates to the OS's `getaddrinfo` via Tokio.
#[derive(Default)]
pub struct SystemResolver;

impl SystemResolver {
    /// Create a new system resolver instance.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(
        &self,
        host: &str,
        port: u16,
        ip_version: IpVersion,
    ) -> Result<Vec<SocketAddr>, CurlError> {
        let addr_str = format!("{}:{}", host, port);
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&addr_str)
            .await
            .map_err(|_| CurlError::CouldntResolveHost)?
            .collect();

        let filtered: Vec<SocketAddr> = match ip_version {
            IpVersion::Any => addrs,
            IpVersion::V4Only => addrs.into_iter().filter(|a| a.is_ipv4()).collect(),
            IpVersion::V6Only => addrs.into_iter().filter(|a| a.is_ipv6()).collect(),
        };

        if filtered.is_empty() {
            return Err(CurlError::CouldntResolveHost);
        }

        Ok(filtered)
    }

    fn name(&self) -> &'static str {
        "system"
    }
}

/// Check whether IPv6 is available on this system.
///
/// From C: `Curl_ipv6works()` (lib/hostip.c lines 771-776).
/// Probes by attempting to create a UDP socket bound to `[::1]:0`.
pub fn ipv6_works() -> bool {
    use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
    UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)).is_ok()
}
