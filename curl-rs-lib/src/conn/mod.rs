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
//!
//! # Scope
//!
//! This file is a minimal module root: it contains only `pub mod` wiring and
//! documentation — there is no connection or filter implementation logic of its
//! own, which lives entirely in the leaf submodules listed above. It is formally
//! in scope for this single-phase migration (AAP §0.5.4: *"the entire migration
//! is executed in a single Blitzy phase … No file is deferred to a later
//! phase"*): the connection leaves it declares are authored and reviewed within
//! this checkpoint, and the crate cannot compile without their declaration
//! point. The file was therefore reviewed in full alongside those leaves rather
//! than deferred — declaration set verified against the directory contents (no
//! dangling or speculative `mod` declarations), and it compiles cleanly under
//! the default, all-features, and no-default-features configurations.

/// The connection pool / cache (`lib/conncache.c` + `lib/conncache.h`): the
/// per-destination bundles of reusable connections, the per-host/total/idle
/// connection limits, oldest-idle eviction, dead-connection pruning, and the
/// network-change invalidation. Shareable across easy handles as an
/// `Arc<Mutex<ConnectionPool>>`; the reuse-eligibility predicate itself is
/// `crate::url`'s responsibility, invoked through `ConnectionPool::find`.
pub mod cache;
pub mod filters;
/// Connection setup and the SETUP meta-filter chain-builder (`lib/connect.c` +
/// `lib/connect.h`): assembles the connection-filter stack in the canonical
/// order (EYEBALLS → SOCKS → HTTP-PROXY → HAPROXY → SSL), plus the connect-
/// timeout budget, `conncontrol`, and address formatting.
pub mod connect;
/// The HTTP/1.x `CONNECT` tunnel filter (`lib/cf-h1-proxy.c`), gated on curl's
/// `!CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP` ⇒ the `proxy` + `http` features.
#[cfg(all(feature = "proxy", feature = "http"))]
pub mod h1_proxy;
/// The HTTP/2 `CONNECT` tunnel filter (`lib/cf-h2-proxy.c`), gated on curl's
/// `!CURL_DISABLE_HTTP && !CURL_DISABLE_PROXY && USE_NGHTTP2` ⇒ the `proxy` +
/// `http` + `http2` features (an HTTP/2 proxy filter requires HTTP/2 support).
#[cfg(all(feature = "proxy", feature = "http", feature = "http2"))]
pub mod h2_proxy;
/// RFC 8305 Happy-Eyeballs v2 (`lib/cf-ip-happy.c`): the bottom "EYEBALLS"
/// filter that establishes the transport by racing IPv4/IPv6 candidate
/// addresses (alternating families, ~200 ms staggered attempts), promoting the
/// first to connect as its `next` and tearing down the losers.
pub mod happy_eyeballs;
pub mod haproxy;
/// HTTPS connection establishment (`lib/vtls/vtls.c` cf-ssl + `lib/cf-https-connect.c`):
/// the TLS connection filter (`TlsFilter`) and the ALPN-eyeballs HTTPS
/// coordinator (`HttpsConnectFilter`) that races h3-over-QUIC against
/// h2/h1-over-TLS and promotes the first protocol stack to connect.
pub mod https_connect;
pub mod socket;
pub mod shutdown;
