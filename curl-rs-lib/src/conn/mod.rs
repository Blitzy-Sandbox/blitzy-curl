//! Connection subsystem module.
//!
//! This module contains the connection filter chain framework that replaces
//! the C `lib/cfilters.c` and `lib/cfilters.h` implementation. All connection
//! filters (socket, TLS, proxy, QUIC, HTTP/2) implement the
//! [`ConnectionFilter`] trait and compose into a [`FilterChain`].

pub mod filters;
pub mod haproxy;
pub mod socket;

// Re-export primary types for convenient access.
pub use filters::{
    ConnectionFilter, FilterChain, FilterTypeFlags, PollAction, PollEntry, PollSet, QueryResult,
    TransferData,
};
pub use socket::{
    apply_tcp_options, check_alive, parse_interface, SocketConfig, SocketType, TcpSocketFilter,
    UdpSocketFilter,
};
