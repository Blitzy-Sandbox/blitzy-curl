// curl-rs-lib — the core async library of the curl → Rust rewrite.
//
// SPDX-License-Identifier: curl
//
// This crate is a memory-safe Rust reimplementation of curl's `libcurl` core
// (the C `lib/` tree). The original C sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).
// This Rust port preserves the observable behavior, the public API *names*, and
// the C ABI integer contracts of libcurl; it is a behavioral/ABI translation,
// not a line-by-line transliteration (Agent Action Plan §0.1.2).

// ---------------------------------------------------------------------------
// MANDATORY memory-safety guarantee (AAP §0.7.1 / §0.8.1).
//
// This MUST be the first crate attribute. The hard rule of the rewrite is
// "zero `unsafe` outside the FFI crate": all raw-pointer / `va_list` / C-ABI
// handling lives exclusively in `curl-rs-ffi`, never here. Applying
// `#![forbid(unsafe_code)]` at the crate root makes that rule compiler-enforced
// for every module in this crate (each leaf module additionally restates the
// same forbid for isolation; re-forbidding an already-forbidden lint is an
// idempotent no-op, not an error). The nightly Miri gate
// (`cargo +nightly miri test -p curl-rs-lib`) validates the resulting safe core
// for undefined behavior.
// ---------------------------------------------------------------------------
#![forbid(unsafe_code)]
// The workspace lint policy (`[workspace.lints]` in the root `Cargo.toml`,
// inherited here via `[lints] workspace = true`) additionally denies
// `unsafe_op_in_unsafe_fn` across all three crates. It is a no-op in this safe
// crate (which forbids `unsafe` outright) but keeps the policy uniform.

//! `curl-rs-lib` — the memory-safe, asynchronous Rust core of the curl rewrite
//! (crate import name `curl_rs_lib`).
//!
//! This crate is the Rust replacement for curl's `libcurl` *internals* (the
//! C project's `lib/` tree). It hosts the asynchronous transfer engine, the
//! per-protocol engines, the single `rustls`-based TLS layer, the connection
//! filter chain, DNS resolution, authentication, and the stateful subsystems
//! (cookies, HSTS, Alt-Svc, `.netrc`, IDN, PSL). It has no single C-source
//! analog; structurally it stands in for the umbrella that `lib/curl_setup.h`
//! plus the libcurl-internal include graph (`urldata.h`, `transfer.h`,
//! `vtls/vtls.h`, `url.h`, `getinfo.h`, …) provides to every C translation
//! unit — that `#include` web is replaced here by the typed module tree and the
//! `use crate::…` paths it exposes.
//!
//! # Workspace role and dependency direction (AAP §0.4)
//!
//! This crate is the bottom of a strict, one-directional three-crate graph; it
//! depends on **neither** of the two leaf crates, which never depend on each
//! other:
//!
//! * [`curl-rs`](https://curl.se/) — the `curl` command-line tool (a `clap`
//!   binary). Depends on this crate only.
//! * `curl-rs-ffi` — the `libcurl`-compatible C ABI (`cdylib` + `staticlib`),
//!   exposing `extern "C"` symbols and regenerating `include/curl/curl.h` via
//!   `cbindgen`. Depends on this crate only.
//!
//! Both leaf crates consume this crate through the curated re-export surface
//! below (`use curl_rs_lib::{Easy, Multi, Share, SList, version, …}`) rather
//! than reaching into deep module paths.
//!
//! # The C tree is the behavioral/ABI oracle
//!
//! The C `lib/` and `src/` trees and the public `include/curl/*.h` headers are
//! consumed as a *behavioral and ABI oracle*, not transliterated: wire format,
//! option semantics, `CURLcode` integer values, and the exported-symbol set are
//! reproduced exactly (AAP §0.1.2), while the implementation is idiomatic,
//! safe, async Rust.
//!
//! # Architecture highlights
//!
//! * **TLS is `rustls`, exclusively** (AAP §0.8.1). There is no OpenSSL,
//!   GnuTLS, mbedTLS, wolfSSL, Schannel, Secure Transport, or any C-TLS linkage
//!   anywhere in the crate; the six C backends collapse into the single
//!   [`tls`] layer over `tokio-rustls`. Certificate validation is on by
//!   default.
//! * **Protocols are trait-dispatched.** curl's per-protocol `Curl_handler`
//!   function-pointer vtables become Rust trait objects, and the C
//!   `Curl_cftype` filter chain becomes a composable async filter/layer stack
//!   ([`conn`]).
//! * **The multi handle runs on a Tokio multi-thread runtime.** curl's
//!   hand-rolled `select`/`poll` multi state machine is re-architected onto
//!   Tokio while preserving the synchronous `curl_multi_*` socket/timer
//!   callback contract that event-loop integrations depend on (AAP §0.4.4 /
//!   §0.7.4). The asynchronous machinery stays entirely inside this safe core;
//!   the synchronous C ABI is bridged by `block_on` in `curl-rs-ffi`, **not**
//!   here.
//!
//! # Capability / feature lockstep (parity-critical)
//!
//! Optional capabilities are selected by Cargo features whose defaults mirror
//! curl's default build (AAP §0.6.2). A capability's *implementation* and its
//! *advertised* presence in [`version::version`] / [`version::version_info`]
//! are gated on the **same** Cargo feature, so `curl --version` never reports a
//! capability whose code was compiled out. This matters because curl's
//! regression harness (`runtests`) queries `curl_version_info()` to pick the
//! applicable subset of `tests/data`; if the reported feature/protocol set
//! diverges from curl 8.x's default build, the wrong tests run and suite parity
//! (goal G7) silently fails (AAP §0.7.3).
//!
//! # Memory-safety policy
//!
//! The whole crate compiles under the crate-root `#![forbid(unsafe_code)]`
//! declared above (AAP §0.7.1). It contains zero `unsafe`; every container that
//! C implements with raw pointers (`dynbuf`, `bufq`, the `curl_slist`, the
//! reference-counted share cache) is re-expressed with owning Rust types
//! (`Vec`/`BytesMut`, [`SList`], `Arc<Mutex<…>>`) and deterministic `Drop`.
//!
//! # Module organization
//!
//! The module tree mirrors the responsibilities of the C `lib/` translation
//! units, grouped foundational → public-API surface → engine → transfer-support
//! → stateful subsystems → subsystem trees, to match the on-disk folder layout.

// ===========================================================================
// Module declarations
//
// Every sibling module file and every subfolder of `curl-rs-lib/src/` is
// declared here (24 top-level modules + 7 subfolder module trees). Declaration
// order is not significant to the compiler; the grouping below is purely for
// readability and mirrors the folder layout.
//
// Visibility: every module is `pub` so the FFI and binary crates (and the
// crate-root re-exports below) can reach the engine and public-API types. The
// progress / request / ratelimit modules — which the C design would treat as
// purely internal "transfer support" — are intentionally `pub` as well, because
// their types appear in the *public* surface of the [`transfer`] engine (for
// example `transfer::rate_limit_delay(&mut RateLimit, Direction, …)`,
// `transfer::record_progress(&Progress)`, `transfer::FollowRequest`'s public
// `request` / `progress` fields). Declaring them `pub(crate)` while `transfer`
// is `pub` would trip E0446 ("private type in public interface"); per the file
// brief, modules whose types surface publicly are `pub`.
// ===========================================================================

// ---- foundational ---------------------------------------------------------

/// Canonical error and result-code definitions — the single source of truth for
/// every libcurl result-code enum ([`CurlError`]/`CURLcode`,
/// [`CurlMError`]/`CURLMcode`, [`CurlUError`]/`CURLUcode`,
/// [`CurlShError`]/`CURLSHcode`, [`CurlHError`]/`CURLHcode`) and the exact C
/// integers they map to (`lib/strerror.c`, `include/curl/*.h`).
pub mod error;

/// Version, capability, and protocol reporting — `curl_version()` /
/// `curl_version_info()` (`lib/version.c`). Parity-critical: drives `runtests`
/// feature detection (see the crate-level "Capability / feature lockstep" note).
pub mod version;

// ---- public-facing helpers and data models --------------------------------

/// URL percent-encode / -decode (`lib/escape.c`).
pub mod escape;
/// Typed `curl_easy_getinfo` info retrieval (`lib/getinfo.c`).
pub mod getinfo;
/// Response-header store and the header API (`lib/headers.c`).
pub mod headers;
/// Option metadata table — `curl_easy_option_*` introspection
/// (`lib/easyoptions.c`).
pub mod options;
/// Typed `curl_easy_setopt` option application (`lib/setopt.c`).
pub mod setopt;
/// `curl_slist` owning string-list container (`lib/slist.c`).
pub mod slist;
/// URL parsing / building — the URL API (`lib/url.c`, `lib/urlapi.c`).
pub mod url;
/// MIME / multipart form-data construction (`lib/mime.c`, `lib/formdata.c`).
pub mod mime;

// ---- the easy / multi / share engine --------------------------------------

/// The easy-handle engine: the opaque `CURL` handle lifecycle and the easy API
/// (`init`/`setopt`/`getinfo`/`perform`/`reset`/`duphandle`/`pause`/`recv`/
/// `send`/`upkeep`) plus process-global init/cleanup/sslset (`lib/easy.c`).
pub mod easy;

/// The multi-handle engine: the opaque `CURLM` handle that drives concurrent
/// transfers on a lazily-created Tokio multi-thread runtime while preserving
/// curl's synchronous socket/timer callback contract (`lib/multi.c`).
pub mod multi;

/// The shared-state handle (`curl_share` / `CURLSH`): an `Arc<Mutex<…>>`-backed
/// pool of caches (cookies, HSTS, PSL, DNS, TLS sessions, connections)
/// attachable to many easy handles (`lib/share.c`).
pub mod share;

/// The asynchronous transfer engine — the type-state transfer flow, client
/// read/write pipeline, redirect/retry policy, and post-transfer info
/// recording (`lib/transfer.c`, `lib/sendf.c`).
pub mod transfer;

// ---- transfer-support subsystems ------------------------------------------
//
// `pub` (not `pub(crate)`) because their types appear in `transfer`'s public
// API — see the module-declaration note above.

/// Content-encoding (gzip/deflate/brotli/zstd) decode dispatch
/// (`lib/content_encoding.c`).
pub mod content_encoding;
/// Transfer progress accounting, timers, and the progress-meter callback
/// (`lib/progress.c`).
pub mod progress;
/// Transfer rate limiting / pacing (`CURLOPT_MAX_RECV_SPEED_LARGE` et al.).
pub mod ratelimit;
/// Per-transfer request state: send/receive buffers and byte accounting
/// (`lib/request.c`).
pub mod request;

// ---- stateful subsystems --------------------------------------------------

/// HTTP `Alt-Svc` alternative-service cache (`lib/altsvc.c`).
pub mod altsvc;
/// HTTP cookie engine and jar (`lib/cookie.c`).
pub mod cookie;
/// HTTP Strict-Transport-Security store (`lib/hsts.c`).
pub mod hsts;
/// Internationalized Domain Names — IDNA/Punycode host handling (`lib/idn.c`).
pub mod idn;
/// `.netrc` credential-file parsing (`lib/netrc.c`).
pub mod netrc;
/// Public Suffix List handling for cookie-domain scoping (`lib/psl.c`).
pub mod psl;

// ---- subsystem module trees (each has its own `mod.rs`) --------------------

/// Portable utilities and containers: dynamic buffers, case-insensitive
/// compare, base64, crypto primitives, date parsing, hash/list/splay maps, …
/// (`lib/curlx/`, `lib/hash.c`, `lib/llist.c`, `lib/splay.c`, …).
pub mod util;

/// The single `rustls` / `tokio-rustls` TLS backend: client-config
/// construction, hostname verification, session cache, and key-logging
/// (`lib/vtls/`).
pub mod tls;

/// Name resolution: the system/Tokio resolver, DNS-over-HTTPS, and the optional
/// `hickory` async backend (`lib/hostip.c`, `lib/doh.c`, `lib/asyn-*.c`).
pub mod dns;

/// Authentication: HTTP schemes (Basic/Digest/Bearer/NTLM/Negotiate) and the
/// shared SASL/SCRAM state machine (`lib/vauth/`, `lib/http_*.c`).
pub mod auth;

/// Proxy support: SOCKS, HTTP proxying, and no-proxy matching (`lib/socks.c`,
/// `lib/http_proxy.c`, `lib/noproxy.c`).
pub mod proxy;

/// Connection management: the pool/cache and the composable async connection
/// filter chain (`lib/connect.c`, `lib/conncache.c`, `lib/cfilters.c`,
/// `lib/cf-*.c`).
pub mod conn;

/// Per-protocol engines and codecs: HTTP/1.1+2+3, FTP/FTPS, SFTP/SCP, the mail
/// family, and every remaining test-exercised protocol (`lib/http*.c`,
/// `lib/ftp.c`, `lib/vssh/`, `lib/imap.c`, …).
pub mod protocols;

// ===========================================================================
// Public API re-exports — the crate's curated external surface.
//
// The FFI and binary crates bind to these stable crate-root names (for example
// `curl-rs-ffi/src/slist.rs` does `use curl_rs_lib::SList;`) instead of deep
// module paths. All paths are written `crate::…` so resolution is unambiguous
// even where a local module shares a name with an external crate (notably the
// local [`url`] module vs. the `url` dependency crate).
// ===========================================================================

// ---- error and result-code types ------------------------------------------
pub use crate::error::{
    CurlCode, CurlError, CurlHError, CurlMError, CurlShError, CurlUError, Result,
};

// ---- core handle types ----------------------------------------------------
pub use crate::easy::Easy;
pub use crate::mime::{Mime, MimePart};
pub use crate::multi::Multi;
pub use crate::share::Share;
pub use crate::slist::SList;
// The URL-API handle is re-exported as `Url`; the `crate::url` prefix selects
// this crate's module (not the `url` dependency crate), and the `as Url` alias
// keeps the public name short while avoiding confusion with `url::Url`.
pub use crate::url::CurlUrl as Url;

// ---- version / capability reporting ---------------------------------------
pub use crate::version::{version, version_info, VersionInfo};

// ---- option / info enums (the surface the FFI variadic shims dispatch on) ---
//
// `CurlOption` comes from `options`, `OptionValue` from `setopt`, and `CurlInfo`
// / `InfoValue` from `getinfo` — i.e. exactly the types the [`Easy`] API
// consumes (`Easy::setopt(CurlOption, OptionValue)`,
// `Easy::getinfo(CurlInfo) -> InfoValue`). Note that `options` also defines a
// C-style `CurlInfo`; the canonical, idiomatic `getinfo::CurlInfo` is the one
// re-exported here to keep a single unambiguous crate-root name.
pub use crate::getinfo::{CurlInfo, InfoValue};
pub use crate::options::CurlOption;
pub use crate::setopt::OptionValue;

// ---- process-global init / cleanup entry points ---------------------------
//
// Implemented in `easy` (curl's `lib/easy.c` hosts `curl_global_*`); re-exported
// here so the FFI `curl-rs-ffi/src/global.rs` shim can call them through a
// stable crate-root path without duplicating the one-time-init logic.
pub use crate::easy::{global_cleanup, global_init, global_sslset, SslSetResult};

/// Ergonomic prelude: the handful of handle, error, and version items most
/// downstream code needs. Import the whole set with
/// `use curl_rs_lib::prelude::*;`.
pub mod prelude {
    pub use crate::easy::Easy;
    pub use crate::error::{CurlCode, CurlError, Result};
    pub use crate::mime::{Mime, MimePart};
    pub use crate::multi::Multi;
    pub use crate::share::Share;
    pub use crate::slist::SList;
    pub use crate::url::CurlUrl as Url;
    pub use crate::version::{version, version_info, VersionInfo};
}
