//! Proxy support — SOCKS, HTTP-proxy tunnelling, and no-proxy matching.
//!
//! This module is the Rust home of curl's proxy layer (`lib/socks.c`,
//! `lib/http_proxy.c`, `lib/noproxy.c`). It groups the proxy concerns the
//! transfer engine and the connection-filter chain consume through ordinary
//! Rust paths (`crate::proxy::<name>`) rather than via curl's C `#include`
//! graph (Agent Action Plan §0.5.1 / §0.5.2).
//!
//! # Submodules
//!
//! * [`noproxy`] — the `NO_PROXY` / `--noproxy` host-matching logic
//!   (`lib/noproxy.c`): decides whether a given host bypasses the configured
//!   proxy, reproducing curl's domain-suffix, IP, and CIDR matching exactly.
//!
//! Additional proxy concerns enumerated by the AAP (SOCKS handshake, HTTP
//! `CONNECT` tunnelling) are authored as sibling submodules in their own
//! migration steps; this `mod.rs` is the single declaration point that wires
//! them into the crate as they land.

pub mod noproxy;
