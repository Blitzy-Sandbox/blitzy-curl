//! Utility modules replacing `lib/curlx/` and various `lib/*.c` utility files.
//!
//! This module root corresponds to the C `lib/curlx/curlx.h` umbrella header
//! that pulled in all portability and utility helpers. Each submodule replaces
//! one or more C source files with idiomatic Rust equivalents.

pub mod bufq;
pub mod dynbuf;
pub mod fnmatch;
pub mod hash;
pub mod hmac;
pub mod llist;
pub mod md5;
pub mod nonblock;
pub mod parsedate;
pub mod rand;
pub mod sha256;
pub mod strparse;
pub mod timeval;
pub mod select;
pub mod splay;
pub mod strerror;
pub mod warnless;
