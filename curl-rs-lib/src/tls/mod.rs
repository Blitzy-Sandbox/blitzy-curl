//! TLS layer — the single, safe `rustls` backend.
//!
//! This module is the Rust replacement for curl's `lib/vtls/` backend
//! abstraction. Where the C tree selected one of six interchangeable C TLS
//! backends at build time (`openssl.c`, `gtls.c`, `mbedtls.c`, `wolfssl.c`,
//! `schannel.c`, `apple.c`), the rewrite collapses them to a single, memory-safe
//! backend built on `rustls` / `tokio-rustls` (Agent Action Plan §0.1.1 /
//! §0.8.1). Certificate validation is on by default; there is no OpenSSL,
//! native-tls, or other C-TLS linkage anywhere (enforced by the workspace
//! `deny.toml`).
//!
//! # Submodules
//!
//! * [`config`]   — the curl-TLS-options → `rustls::ClientConfig` builder and the
//!   [`TlsConfig`] model (`lib/vtls/rustls.c` + `lib/vtls/vtls.c`): the
//!   foundational TLS configuration surface, including the custom
//!   `ServerCertVerifier`s, the version/cipher mapping, the pinned-public-key
//!   check, and the rustls-error mapping. [`TlsConfig`] is re-exported here.
//! * [`hostname`] — RFC 6125 hostname / wildcard certificate-name matching
//!   (`lib/vtls/hostcheck.c`): the helper consumed by the certificate verifier
//!   for the paths where curl applies its own name check.
//! * [`keylog`]   — `SSLKEYLOGFILE` (NSS key-log) support
//!   (`lib/vtls/keylog.c`): emits the pre-master/secret key-log lines for
//!   on-the-wire TLS debugging, wired into rustls's key-log hook.
//!
//! The session cache and the connector wiring (`session_cache`, the
//! `mod::connect` entrypoint) are authored in their own migration step
//! (AAP §0.8.4 step 4); this `mod.rs` is the single declaration point that wires
//! the TLS submodules into the crate as they land.

pub mod config;
pub mod hostname;
pub mod keylog;

pub use config::TlsConfig;
