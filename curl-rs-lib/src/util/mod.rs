//! Portable utility layer — the foundational, dependency-light toolkit of the
//! `curl-rs-lib` core crate.
//!
//! This module is the Rust home of curl's `lib/curlx/*` portable helpers
//! together with libcurl's generic containers, buffers, and crypto primitives
//! (`lib/hash.c`, `lib/llist.c`, `lib/splay.c`, `lib/bufq.c`, `lib/md5.c`,
//! `lib/sha256.c`, …). It plays the same "collect the toolkit" role that curl's
//! umbrella header `lib/curlx/curlx.h` plays in the C tree: it gathers the small,
//! self-contained building blocks that the rest of the crate — the engine
//! (`easy`, `multi`, `transfer`), the `conn/`, `protocols/`, `tls/`, `auth/`,
//! `dns/`, and `proxy/` subtrees — composes into higher-level behavior.
//!
//! These primitives are consumed through ordinary Rust module paths
//! (`crate::util::<name>`) rather than via curl's C `#include` graph (Agent
//! Action Plan §0.5.2). Aside from the crate's shared error type
//! ([`crate::error`]), the `util` tree is internally dependency-free: nothing
//! here reaches "upward" into the engine or protocol layers, which keeps it a
//! stable, reusable foundation.
//!
//! # Memory safety
//!
//! Per AAP §0.7.1 the safe core forbids `unsafe`, and that rule is
//! compiler-enforced **crate-wide**: the crate root (`curl-rs-lib/src/lib.rs`)
//! applies `#![forbid(unsafe_code)]`, so every module in this crate — this
//! `util` aggregator and each of its leaves included — is compiled with
//! `unsafe` forbidden. There is therefore **no `unsafe` anywhere in
//! `curl-rs-lib`**; all raw-pointer / `va_list` / C-ABI handling (and hence all
//! `unsafe`) is confined to the `curl-rs-ffi` crate.
//!
//! Several leaf submodules — including the OS-integration primitives
//! [`nonblock`] and [`select`] — additionally restate `#![forbid(unsafe_code)]`
//! at their own root. Re-forbidding an already-forbidden lint is an idempotent
//! no-op; it simply keeps each file's safety contract self-evident when the file
//! is read or audited in isolation. Those primitives perform their work through
//! safe std/`tokio` APIs and contain no `unsafe`. This aggregator file is itself
//! pure module wiring and contains no `unsafe` of its own.
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
//! * [`parsedate`] — permissive HTTP/RFC date-string parser (`lib/parsedate.c`).
//! * [`rand`]     — randomness (OS RNG by default) (`lib/rand.c`).
//! * [`select`]   — readiness waiting (`lib/curlx/wait.*` / `lib/select.c`).
//! * [`sendf`]    — low-level send/recv movers + the `infof!`/`failf!` macros (`lib/sendf.c`).
//! * [`sha256`]   — SHA-256 digest wrapper (`lib/sha256.c`).
//! * [`splay`]    — splay tree backing the multi handle's timer/expiry keys (`lib/splay.c`).
//! * [`strerror`] — OS/error-number to message formatting (`lib/strerror.c`, `lib/curlx/strerr.*`).
//! * [`strparse`] — the bounds-checked string parser **and** curl's ASCII case-insensitive compare helpers (`lib/curlx/strparse.*`).
//! * [`timediff`] — saturating time-difference arithmetic (`lib/curlx/timediff.*`).
//! * [`timeval`]  — monotonic/absolute time values (`lib/curlx/timeval.*`).
//! * [`warnless`] — lossless/saturating numeric conversions (`lib/curlx/warnless.*`).
//!
//! # The `strcase` re-export
//!
//! curl's ASCII case-insensitive comparison helpers (`Curl_strcasecompare` /
//! `Curl_strncasecompare`) are implemented inside [`strparse`] on purpose —
//! there is deliberately no separate `strcase.rs` file. They are surfaced under
//! the conventional `crate::util::strcase` path (mirroring the C `strcase.h`
//! home) through the [`strcase`] re-export module below, so sibling modules such
//! as [`crate::proxy::noproxy`] and [`crate::tls::hostname`] can write
//! `use crate::util::strcase::strncasecompare;` exactly as they would have
//! included `strcase.h` in C.

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

/// curl's ASCII case-insensitive comparison helpers, surfaced under the
/// conventional `strcase` path.
///
/// These functions are defined in [`strparse`] (curl folds the case-compare
/// helpers into the same translation unit as the string parser); this module
/// simply re-exports them so call sites can use the `crate::util::strcase::…`
/// path that mirrors curl's `strcase.h`. The actively consumed helper is
/// [`strncasecompare`](crate::util::strparse::strncasecompare) (used by
/// [`crate::proxy::noproxy`] and [`crate::tls::hostname`]); the full set is
/// re-exported so the `strcase` surface matches curl's. See the module-level
/// docs in [`strparse`] for the rationale.
pub mod strcase {
    pub use super::strparse::{
        curlx_str_casecompare, curlx_str_cmp, strcasecompare, strncasecompare,
    };
}
