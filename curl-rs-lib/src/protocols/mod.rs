//! Protocol handler implementations for curl-rs.
//!
//! This module contains the protocol-specific implementations for all
//! supported transfer protocols, plus the shared pingpong framework
//! used by text-based command/response protocols.

pub mod pingpong;

#[cfg(feature = "ftp")]
pub mod ftp_list;
