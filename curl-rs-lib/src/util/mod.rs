//! Portable utility layer — the Rust home of curl's `lib/curlx/*` helpers and
//! the internal container/buffer types (`lib/hash.c`, `lib/llist.c`,
//! `lib/bufq.c`, …).
//!
//! This module groups the small, dependency-light building blocks that the rest
//! of `curl-rs-lib` (the engine, the protocol handlers, the TLS layer, …) builds
//! on. Each submodule is a focused, memory-safe reimplementation of one C
//! utility, consumed through ordinary Rust paths (`crate::util::<name>`) rather
//! than via curl's C `#include` graph (Agent Action Plan §0.5.2).
//!
//! # Submodules
//!
//! * [`base64`]   — Base64 encode/decode (`lib/curlx/base64.*`).
//! * [`bufq`]     — chunked byte-queue buffer (`lib/bufq.c`).
//! * [`dynbuf`]   — growable dynamic buffer (`lib/curlx/dynbuf.*`).
//! * [`fnmatch`]  — glob-style pattern matching (`lib/curl_fnmatch.c`).
//! * [`hash`]     — hash-map container (`lib/hash.c`).
//! * [`hmac`]     — keyed HMAC over the RustCrypto digests (`lib/hmac.c`).
//! * [`llist`]    — doubly linked list (`lib/llist.c`).
//! * [`md5`]      — MD5 digest wrapper (`lib/md5.c`, parity-required legacy).
//! * [`mprintf`]  — curl's `*printf` family (`lib/mprintf.c`).
//! * [`nonblock`] — non-blocking socket toggling (`lib/curlx/nonblock.*`).
//! * [`rand`]     — randomness (OS RNG by default) (`lib/rand.c`).
//! * [`select`]   — readiness waiting (`lib/curlx/wait.*` / `select.c`).
//! * [`sendf`]    — low-level send/recv movers + the `infof!`/`failf!` macros (`lib/sendf.c`).
//! * [`sha256`]   — SHA-256 digest wrapper (`lib/sha256.c`).
//! * [`strerror`] — OS/error-number to message formatting (`lib/curlx/strerr.*`).
//! * [`strparse`] — the bounds-checked string parser AND curl's ASCII case-insensitive compare helpers (`lib/curlx/strparse.*`).
//! * [`timediff`] — saturating time-difference arithmetic.
//! * [`timeval`]  — monotonic/absolute time values (`lib/curlx/timeval.*`).
//! * [`warnless`] — lossless/saturating numeric conversions (`lib/curlx/warnless.*`).
//!
//! # The `strcase` re-export
//!
//! curl's ASCII case-insensitive comparison helpers (`Curl_strcasecompare` /
//! `Curl_strncasecompare`) are implemented inside [`strparse`] on purpose —
//! there is deliberately no separate `strcase.rs`. They are surfaced under the
//! conventional `crate::util::strcase` path (matching the C `strcase.h` home)
//! through the [`strcase`] re-export module below, so sibling modules such as
//! [`crate::proxy::noproxy`] and [`crate::tls::hostname`] can `use
//! crate::util::strcase::strncasecompare;` exactly as they would have included
//! `strcase.h` in C.

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
pub mod rand;
pub mod select;
pub mod sendf;
pub mod sha256;
pub mod strerror;
pub mod strparse;
pub mod timediff;
pub mod timeval;
pub mod warnless;

/// curl's ASCII case-insensitive comparison helpers, surfaced under the
/// conventional `strcase` path.
///
/// These functions are defined in [`strparse`] (curl folds them into the same
/// translation unit); this module simply re-exports them so call sites can use
/// the `crate::util::strcase::…` path that mirrors curl's `strcase.h`. See the
/// module-level docs in [`strparse`] for the rationale.
pub mod strcase {
    pub use super::strparse::{
        curlx_str_casecompare, curlx_str_cmp, strcasecompare, strncasecompare,
    };
}
