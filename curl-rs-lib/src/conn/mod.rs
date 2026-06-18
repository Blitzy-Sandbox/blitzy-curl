//! Connection layer — the connection-filter chain and its filters.
//!
//! This module is the Rust home of curl's connection machinery (`lib/connect.c`,
//! `lib/cfilters.c`, `lib/conncache.c`, `lib/cf-socket.c`, and the `lib/cf-*.c`
//! filter units). Where the C tree dispatched through the `Curl_cftype`
//! function-pointer vtable and a hand-linked `cf->next` chain, the rewrite models
//! each transport/protocol concern (raw socket, Happy Eyeballs, SOCKS, HTTP
//! CONNECT tunnels, the HAProxy PROXY header, TLS) as an implementor of the
//! [`filters::ConnectionFilter`] trait, stacked into a
//! [`filters::FilterChain`] whose ownership-based teardown replaces C's manual
//! `destroy`/`Curl_free` walk (Agent Action Plan §0.4.3 / §0.5.2). The whole
//! subtree consumes its peers through ordinary Rust paths
//! (`crate::conn::<name>`) rather than via curl's C `#include` graph.
//!
//! # Submodules
//!
//! * [`filters`] — the asynchronous [`filters::ConnectionFilter`] trait (the
//!   `Curl_cftype` vtable), the per-filter chain-link/lifecycle state
//!   ([`filters::CfState`]), and the [`filters::FilterChain`] drive logic
//!   (`lib/cfilters.c`). This is the contract every concrete filter implements.
//! * [`haproxy`] — the HAProxy PROXY protocol v1 header emitter filter
//!   (`lib/cf-haproxy.c`): immediately after the transport below connects it
//!   sends a single `PROXY …` header line, then becomes a fully transparent
//!   pass-through (activated by `CURLOPT_HAPROXYPROTOCOL`).
//! * [`shutdown`] — the `cshutdn` graceful-shutdown registry (`lib/cshutdn.c`):
//!   the per-multi-handle set of connections finishing their protocol/TLS close
//!   handshake in the background after the transfer that used them detaches.
//!
//! The remaining connection concerns enumerated by the AAP (the socket /
//! Happy-Eyeballs transport, the connection cache, the SOCKS and HTTP-CONNECT
//! proxy filters, and the SETUP state machine that orders the chain) are
//! authored as sibling submodules in their own migration steps; this `mod.rs`
//! is the single declaration point that wires the connection submodules into
//! the crate as they land.

pub mod filters;
pub mod haproxy;
pub mod shutdown;
