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

pub mod progress;
pub mod seek;
pub mod socket;
