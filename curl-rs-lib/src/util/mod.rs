//! Utility modules replacing `lib/curlx/` and various `lib/*.c` utility files.
//!
//! This module root corresponds to the C `lib/curlx/curlx.h` umbrella header
//! that pulled in all portability and utility helpers. Each submodule replaces
//! one or more C source files with idiomatic Rust equivalents.

pub mod hash;
pub mod llist;
pub mod warnless;
