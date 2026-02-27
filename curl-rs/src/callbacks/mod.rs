// curl-rs/src/callbacks/mod.rs
//
// Transfer callback functions registered on EasyHandle during transfer setup.
// These callbacks drive I/O and monitoring for each active transfer.
//
// Each sub-module rewrites one of the C src/tool_cb_*.c files into idiomatic
// Rust.  The callbacks module is consumed by setopt.rs (gen_cb_setopts) and
// operate.rs (create_transfer) to wire callbacks onto easy handles.
//
// SPDX-License-Identifier: curl

pub mod debug;
pub mod header;
pub mod progress;
pub mod read;
pub mod seek;
pub mod socket;
pub mod write;

// Re-export header callback types and functions for convenient access.
pub use header::{tool_header_cb, HdrCbData, tool_write_headers};

// Re-export debug callback types and functions for convenient access.
pub use debug::{tool_debug_cb, InfoType};

// Re-export write callback types and functions for convenient access.
pub use write::{tool_write_cb, tool_create_output_file, ClobberPolicy};
