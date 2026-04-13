//! Utility modules replacing C `lib/curlx/` and various `lib/*.c` utility files.
//!
//! This module root corresponds to the C `lib/curlx/curlx.h` umbrella header
//! that pulled in all portability and utility helpers via `#include` directives.
//! Each submodule replaces one or more C source files with idiomatic Rust
//! equivalents, eliminating manual memory management (`malloc`/`free`/`realloc`)
//! and platform-specific `#ifdef` branches.
//!
//! # Design Principles
//!
//! 1. **Replace C portability workarounds with Rust standard library equivalents.**
//!    For example, `curlx/timeval.c` provided platform-specific monotonic clocks
//!    (`QueryPerformanceCounter`, `clock_gettime`, `mach_absolute_time`,
//!    `gettimeofday`); in Rust, [`std::time::Instant`] handles all platforms.
//!
//! 2. **Replace C data structures with Rust standard collections.** The C hash
//!    table (`hash.c`, DJB2 buckets) becomes a thin wrapper around
//!    [`std::collections::HashMap`]; the linked list (`llist.c`, intrusive nodes)
//!    becomes [`std::collections::VecDeque`]; the dynamic buffer (`dynbuf.c`,
//!    `malloc`/`realloc`) becomes [`Vec<u8>`] with a size ceiling.
//!
//! 3. **Zero `unsafe` blocks in all utility modules.** Every module in this
//!    subtree is implemented using safe Rust exclusively. No raw pointer
//!    arithmetic, no manual allocator calls, no `transmute`.
//!
//! 4. **MSRV 1.75 compatibility.** All standard library APIs used by these
//!    modules are stable since at least Rust 1.75.
//!
//! # C Correspondence
//!
//! | Rust Module           | C Source File(s)                          | Purpose                                       |
//! |-----------------------|-------------------------------------------|-----------------------------------------------|
//! | [`base64`]            | `lib/curlx/base64.c`                     | Base64 encode/decode (standard + URL-safe)     |
//! | [`dynbuf`]            | `lib/curlx/dynbuf.c`                     | Growable byte buffer with size ceiling         |
//! | [`strparse`]          | `lib/curlx/strparse.c`                   | Zero-copy string tokeniser / numeric parser    |
//! | [`timediff`]          | `lib/curlx/timediff.c`                   | Millisecond ↔ Duration/Timeval conversions     |
//! | [`timeval`]           | `lib/curlx/timeval.c`                    | Monotonic timestamps via `Instant`             |
//! | [`nonblock`]          | `lib/curlx/nonblock.c`                   | Non-blocking socket mode toggle (Tokio-native) |
//! | [`warnless`]          | `lib/curlx/warnless.c`                   | Safe narrowing integer conversions             |
//! | [`fnmatch`]           | `lib/curl_fnmatch.c`                     | FTP wildcard / glob pattern matching           |
//! | [`parsedate`]         | `lib/parsedate.c`                        | HTTP multi-format date parser                  |
//! | [`rand`]              | `lib/rand.c`                             | Cryptographic random bytes and nonce gen       |
//! | [`hash`]              | `lib/hash.c`                             | Hash table (`HashMap` wrapper)                 |
//! | [`llist`]             | `lib/llist.c`                            | Linked list (`VecDeque` wrapper)               |
//! | [`splay`]             | `lib/splay.c`                            | Splay tree for timeout scheduling              |
//! | [`bufq`]              | `lib/bufq.c`, `lib/bufref.c`             | Chunk-based buffer queue for streaming I/O     |
//! | [`select`]            | `lib/select.c`                           | Socket readiness polling (Tokio-native)        |
//! | [`sendf`]             | `lib/sendf.c`                            | Layered client reader/writer I/O stack         |
//! | [`strerror`]          | `lib/strerror.c`                         | OS error message formatting                    |
//! | [`hmac`]              | `lib/hmac.c`                             | HMAC-SHA-256 / HMAC-MD5 via `hmac` crate       |
//! | [`md5`]               | `lib/md5.c`                              | MD5 hashing via `md-5` crate                   |
//! | [`sha256`]            | `lib/sha256.c`                           | SHA-256 / SHA-512/256 via `sha2` crate         |
//! | [`mprintf`]           | `lib/mprintf.c`                          | C-printf compatible formatter (FFI compat)     |
//!
//! # Re-exports
//!
//! The most commonly used types are re-exported at this module level for
//! ergonomic access:
//!
//! - [`DynBuf`] — growable byte buffer (`crate::util::DynBuf`)
//! - [`CurlTime`] — monotonic timestamp (`crate::util::CurlTime`)
//! - [`TimeDiff`] — millisecond time difference (`crate::util::TimeDiff`)
//! - [`BufQ`] — chunk-based buffer queue (`crate::util::BufQ`)
//! - [`SplayTree`] — splay tree for timeout scheduling (`crate::util::SplayTree`)

// ---------------------------------------------------------------------------
// Submodule declarations — all 21 utility modules
// ---------------------------------------------------------------------------

/// Base64 encoding and decoding (standard RFC 4648 + URL-safe alphabets).
pub mod base64;

/// Dynamic growable byte buffer with configurable size ceiling.
pub mod dynbuf;

/// Zero-copy string tokeniser and numeric parser.
pub mod strparse;

/// Millisecond ↔ `Duration` / timeval conversions with overflow clamping.
pub mod timediff;

/// Cross-platform monotonic time source wrapping [`std::time::Instant`].
pub mod timeval;

/// Non-blocking socket mode toggle (largely superseded by Tokio's async I/O).
pub mod nonblock;

/// Safe narrowing integer conversions replacing C warning-suppression casts.
pub mod warnless;

/// FTP wildcard / glob pattern matching with POSIX character classes.
pub mod fnmatch;

/// HTTP multi-format date/time parser (RFC 822, RFC 850, asctime, ISO 8601).
pub mod parsedate;

/// Cryptographically secure random byte and nonce generation.
pub mod rand;

/// Hash table wrapper around [`std::collections::HashMap`].
pub mod hash;

/// Linked list wrapper around [`std::collections::VecDeque`].
pub mod llist;

/// Splay tree for timeout scheduling in the multi interface.
pub mod splay;

/// Chunk-based buffer queue for streaming I/O with configurable pooling.
pub mod bufq;

/// Socket readiness polling abstraction (Tokio `Interest`/`Ready` based).
pub mod select;

/// Layered client reader/writer I/O stack for transfers.
pub mod sendf;

/// OS and socket error message formatting.
pub mod strerror;

/// HMAC computation (SHA-256, MD5) via the `hmac` crate.
pub mod hmac;

/// MD5 hashing via the `md-5` crate.
pub mod md5;

/// SHA-256 / SHA-512/256 hashing via the `sha2` crate.
pub mod sha256;

/// C-printf compatible format engine for FFI compatibility.
pub mod mprintf;

// ---------------------------------------------------------------------------
// Convenience re-exports — most-used types at module root
// ---------------------------------------------------------------------------

pub use dynbuf::DynBuf;
pub use timeval::CurlTime;
pub use timediff::TimeDiff;
pub use bufq::BufQ;
pub use splay::SplayTree;
