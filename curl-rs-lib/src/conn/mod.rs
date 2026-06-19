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
//! * [`h2_proxy`] — the HTTP/2 `CONNECT`-tunnel filter (`lib/cf-h2-proxy.c`):
//!   establishes a tunnel through an HTTP/2-capable forward proxy and, unlike
//!   the HTTP/1 tunnel, stays active for the connection's lifetime — tunneled
//!   traffic rides inside HTTP/2 `DATA` frames on the CONNECT stream, so the
//!   filter carries real `send`/`recv` implementations over the `h2` crate.
//! * [`haproxy`] — the HAProxy PROXY protocol v1 header emitter filter
//!   (`lib/cf-haproxy.c`): immediately after the transport below connects it
//!   sends a single `PROXY …` header line, then becomes a fully transparent
//!   pass-through (activated by `CURLOPT_HAPROXYPROTOCOL`).
//! * [`h1_proxy`] — the HTTP/1.x `CONNECT` tunnel filter (`lib/cf-h1-proxy.c`):
//!   sends a `CONNECT host:port HTTP/1.x` request through a forward proxy,
//!   processes the response (including `407` proxy-auth challenges and the
//!   multi-pass NTLM/Negotiate handshake), and on a `2xx` becomes a transparent
//!   pass-through so origin TLS and the protocol engine tunnel through. Gated on
//!   the `proxy` **and** `http` features (curl's `!CURL_DISABLE_PROXY &&
//!   !CURL_DISABLE_HTTP`).
//! * [`socket`] — the bottom transport filter (`lib/cf-socket.c`) that owns the
//!   OS socket and performs raw byte I/O: the TCP, UDP/QUIC, UNIX-domain, and
//!   TCP-accept (FTP active-mode) filters, plus the SOCKS proxy connection
//!   filter wrapper (`lib/socks.c` L1198-1415) which, once its transport below
//!   has connected, drives `crate::proxy::socks::socks_handshake` to completion
//!   and then becomes transparent. Every other filter sits above this one.
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
/// The HTTP/1.x `CONNECT` tunnel filter (`lib/cf-h1-proxy.c`), gated on curl's
/// `!CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP` ⇒ the `proxy` + `http` features.
#[cfg(all(feature = "proxy", feature = "http"))]
pub mod h1_proxy;
pub mod h2_proxy;
pub mod haproxy;
pub mod socket;
pub mod shutdown;
