//! Utility modules replacing `lib/curlx/` and various `lib/*.c` utility files.
//!
//! This module root corresponds to the C `lib/curlx/curlx.h` umbrella header
//! that pulled in all portability and utility helpers. Each submodule replaces
//! one or more C source files with idiomatic Rust equivalents.

pub mod base64;
pub mod bufq;
pub mod dynbuf;
pub mod fnmatch;
pub mod hash;
pub mod hmac;
pub mod llist;
pub mod md5;
pub mod mprintf;
pub mod nonblock;
pub mod parsedate;
pub mod rand;
pub mod select;
pub mod sendf;
pub mod sha256;
pub mod splay;
pub mod strerror;
pub mod strparse;
pub mod timediff;
pub mod timeval;
pub mod warnless;
