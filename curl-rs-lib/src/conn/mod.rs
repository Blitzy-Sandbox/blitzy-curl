//! # Connection Subsystem
//!
//! This module implements curl's connection management layer, organized as a
//! **Tower-like connection filter chain**. Each connection consists of a chain
//! of filters stacked on top of each other, where data flows through each
//! filter in sequence.
//!
//! ## Architecture
//!
//! The filter chain pattern replaces the C `struct Curl_cftype` vtable-based
//! design with Rust's [`ConnectionFilter`] trait. Filters compose as middleware
//! layers:
//!
//! ```text
//! [Protocol Handler] (HTTP, FTP, etc.)
//!        ↕
//! [TLS Filter] (rustls)
//!        ↕
//! [Proxy Filter] (H1 CONNECT, H2 CONNECT, SOCKS, HAProxy)
//!        ↕
//! [Socket Filter] (TCP or UDP)
//! ```
//!
//! ## Filter Chain Model
//!
//! The [`FilterChain`] struct holds an ordered `Vec<Box<dyn ConnectionFilter>>`
//! where index 0 is the outermost ("top") filter and the last index is the
//! innermost ("bottom", typically the raw socket). Data flows top-to-bottom
//! for sends and bottom-to-top for receives. This replaces the C linked-list
//! `cf->next` pointer chain.
//!
//! ## Modules
//!
//! - [`filters`] — Core [`ConnectionFilter`] trait, [`FilterChain`], and all
//!   `CF_CTRL_*`, `CF_QUERY_*`, `CF_TYPE_*` constants
//! - [`cache`] — Connection pool for caching and reusing established connections
//! - [`connect`] — Connection establishment, filter chain assembly, and ALPN
//! - [`socket`] — TCP and UDP socket-level filters (bottom of chain)
//! - [`h1_proxy`] — HTTP/1 CONNECT proxy tunnel filter
//! - [`h2_proxy`] — HTTP/2 CONNECT proxy tunnel filter (via `h2` crate)
//! - [`haproxy`] — HAProxy PROXY protocol v1 filter
//! - [`https_connect`] — HTTPS-connect method racing (H3/H2/H1)
//! - [`happy_eyeballs`] — RFC 8305 Happy Eyeballs v2 dual-stack racing
//! - [`shutdown`] — Graceful connection shutdown management
//!
//! ## Source Mapping
//!
//! | Rust module       | C source file(s)               |
//! |-------------------|-------------------------------|
//! | `filters`         | `lib/cfilters.c`, `lib/cfilters.h` |
//! | `cache`           | `lib/conncache.c`, `lib/conncache.h` |
//! | `connect`         | `lib/connect.c`, `lib/connect.h` |
//! | `socket`          | `lib/cf-socket.c`, `lib/cf-socket.h` |
//! | `h1_proxy`        | `lib/cf-h1-proxy.c`, `lib/cf-h1-proxy.h` |
//! | `h2_proxy`        | `lib/cf-h2-proxy.c`, `lib/cf-h2-proxy.h` |
//! | `haproxy`         | `lib/cf-haproxy.c`, `lib/cf-haproxy.h` |
//! | `https_connect`   | `lib/cf-https-connect.c`, `lib/cf-https-connect.h` |
//! | `happy_eyeballs`  | `lib/cf-ip-happy.c`, `lib/cf-ip-happy.h` |
//! | `shutdown`        | `lib/cshutdn.c`, `lib/cshutdn.h` |
//!
//! ## Safety
//!
//! This module and all its children contain **zero** `unsafe` blocks,
//! per AAP Section 0.7.1.

// ===========================================================================
// Submodule declarations — all 10 child modules of the connection subsystem
// ===========================================================================

pub mod filters;
pub mod cache;
pub mod connect;
pub mod socket;
pub mod h1_proxy;
pub mod h2_proxy;
pub mod haproxy;
#[cfg(feature = "http")]
pub mod https_connect;
pub mod happy_eyeballs;
pub mod shutdown;

// ===========================================================================
// Re-exports from `filters` — core trait, chain, constants, and poll types
// ===========================================================================

// Core filter abstraction and chain management
pub use filters::{ConnectionFilter, FilterChain, FilterTypeFlags, TransferData};

// Query and poll types
pub use filters::{QueryResult, PollSet, PollAction, PollEntry};

// Control event constants (matching C CF_CTRL_* values exactly)
pub use filters::{
    CF_CTRL_DATA_SETUP,
    CF_CTRL_DATA_PAUSE,
    CF_CTRL_DATA_DONE,
    CF_CTRL_DATA_DONE_SEND,
    CF_CTRL_CONN_INFO_UPDATE,
    CF_CTRL_FORGET_SOCKET,
    CF_CTRL_FLUSH,
};

// Query identifier constants (matching C CF_QUERY_* values exactly)
pub use filters::{
    CF_QUERY_MAX_CONCURRENT,
    CF_QUERY_CONNECT_REPLY_MS,
    CF_QUERY_SOCKET,
    CF_QUERY_TIMER_CONNECT,
    CF_QUERY_TIMER_APPCONNECT,
    CF_QUERY_STREAM_ERROR,
    CF_QUERY_NEED_FLUSH,
    CF_QUERY_IP_INFO,
    CF_QUERY_HTTP_VERSION,
    CF_QUERY_REMOTE_ADDR,
    CF_QUERY_HOST_PORT,
    CF_QUERY_SSL_INFO,
    CF_QUERY_SSL_CTX_INFO,
    CF_QUERY_TRANSPORT,
    CF_QUERY_ALPN_NEGOTIATED,
};

// Filter type flag constants (matching C CF_TYPE_* values exactly)
pub use filters::{
    CF_TYPE_IP_CONNECT,
    CF_TYPE_SSL,
    CF_TYPE_MULTIPLEX,
    CF_TYPE_PROXY,
    CF_TYPE_HTTP,
};

// SSL configuration constants (matching C CURL_CF_SSL_* values exactly)
pub use filters::{
    CURL_CF_SSL_DEFAULT,
    CURL_CF_SSL_DISABLE,
    CURL_CF_SSL_ENABLE,
};

// ===========================================================================
// Re-exports from `cache` — connection pool types
// ===========================================================================

pub use cache::{ConnectionPool, PoolBundle, PoolLimitResult, SharedPool};

// ===========================================================================
// Re-exports from `connect` — connection data and ALPN types
// ===========================================================================

pub use connect::{
    AlpnId, ConnControl, ConnectionData, IpInfo, TransportType,
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_SHUTDOWN_TIMEOUT_MS,
};

// ===========================================================================
// Re-exports from `socket` — socket filter types and utilities
// ===========================================================================

pub use socket::{
    TcpSocketFilter, UdpSocketFilter, SocketConfig, SocketType,
    apply_tcp_options, check_alive, parse_interface,
};

// ===========================================================================
// Re-exports from proxy tunnel filters
// ===========================================================================

pub use h1_proxy::H1ProxyFilter;
pub use h2_proxy::H2ProxyFilter;
pub use haproxy::HaproxyFilter;

// ===========================================================================
// Re-exports from connection negotiation filters
// ===========================================================================

#[cfg(feature = "http")]
pub use https_connect::{HttpsConnectFilter, HttpVersionMask, https_setup};

pub use happy_eyeballs::{HappyEyeballsFilter, DEFAULT_HAPPY_EYEBALLS_DELAY_MS};

// ===========================================================================
// Re-exports from shutdown management
// ===========================================================================

pub use shutdown::{ShutdownEntry, ShutdownManager, ShutdownState};
