//! The HTTP protocol family — the `protocols/http/` subtree.
//!
//! This module groups curl's HTTP implementation: the version-specific engines
//! (HTTP/1.1 over `hyper`, HTTP/2 over `h2`, HTTP/3 over `quinn` + `h3`) and the
//! shared codecs and helpers they build on. It mirrors the `lib/http*.c`
//! translation units of the C project (`http.c`, `http1.c`, `http2.c`,
//! `http_chunks.c`, `http_aws_sigv4.c`, …), each consumed strictly as a
//! behavioral / ABI oracle rather than transliterated.
//!
//! As of this checkpoint the authored members are:
//!
//! * [`aws_sigv4`] — AWS Signature Version 4 request signing
//!   (`lib/http_aws_sigv4.c`): the canonical request, string-to-sign, signing-key
//!   HMAC chain, and `Authorization: AWS4-HMAC-SHA256 …` header value.
//! * [`h1`] — the HTTP/1.1 protocol engine (`lib/http.c`, `lib/http1.c`): the
//!   request builder (method, target, default + custom headers in curl's exact
//!   order), the `Expect: 100-continue` handshake, the hand-rolled wire codec
//!   (request-head serialization, status-line / header parsing, and
//!   Content-Length / chunked / close-delimited body de-framing), and the
//!   redirect-method-rewrite and connection-reuse policy helpers. It orchestrates
//!   but does not re-implement auth, cookies, content-decoding, the chunked
//!   codec, the proxy target, or AWS signing — those are delegated to their
//!   dedicated modules.
//! * [`chunks`] — the HTTP/1.1 chunked Transfer-Encoding codec
//!   (`lib/http_chunks.c`): a resumable, byte-exact decoder for response bodies
//!   (with trailer capture and the `--raw` pass-through path) and an encoder for
//!   request bodies carrying `Transfer-Encoding: chunked`.
//! * [`proxy`] — forward (non-tunneling) HTTP-proxy request rewriting
//!   (`lib/http.c` `http_target`): the origin-form → absolute-URI request-target
//!   construction plus the forward-proxy custom-header selection rules
//!   (`lib/http_proxy.c` `dynhds_add_custom`). This is **not** the `CONNECT`
//!   tunnel filter (that lives in [`crate::conn`] and [`crate::proxy`]).
//!
//! * [`h2`] — the HTTP/2 protocol engine (`lib/http2.c`): the `h2`-crate client
//!   handshake (spawned connection-driver task), the request mapping that reuses
//!   [`h1`] and translates to HTTP/2 pseudo-headers, and the stream
//!   request/response lifecycle with flow control, multiplexing, trailers, and
//!   GOAWAY/RST handling. Gated by the `http2` Cargo feature (default on), in
//!   lockstep with [`crate::version`]'s `HTTP2` capability (AAP §0.7.3).
//!
//! * [`h3`] — the HTTP/3 protocol engine over `quinn` + `h3` (`lib/vquic/*`),
//!   gated by the `http3` Cargo feature, in lockstep with [`crate::version`]'s
//!   `HTTP3` capability (AAP §0.7.3).
//!
//! The remaining engines — the proxy-connect helpers — are authored by sibling
//! migration steps and declared here as they land.
//!
//! # Memory safety
//!
//! This subtree inherits `#![forbid(unsafe_code)]` from [`crate::protocols`]; it
//! is intentionally **not** re-declared here.
//!
//! # Scope
//!
//! This file is a minimal module root — `pub mod` wiring and documentation only,
//! with no HTTP implementation logic of its own (the codecs live in the leaf
//! modules above). It is formally in scope for this single-phase migration
//! (AAP §0.5.4: one-phase delivery, *"No file is deferred to a later phase"*);
//! the [`aws_sigv4`] and [`chunks`] codecs it declares are authored and reviewed
//! within this checkpoint, and the crate cannot compile without their
//! declaration point. It was therefore reviewed in full rather than deferred —
//! its declarations match the directory contents and it compiles cleanly under
//! the default, all-features, and no-default-features configurations.

pub mod aws_sigv4;
pub mod chunks;
pub mod h1;
#[cfg(feature = "http2")]
pub mod h2;
pub mod proxy;

/// HTTP/3 over QUIC (`lib/vquic/*`), on the pure-Rust `quinn` + `h3` stack.
/// curl `HTTP3` / `USE_HTTP3`. Gated by the `http3` feature (default ON); this
/// `http` module is itself gated on the `http` feature, so [`h3`] compiles only
/// when both are enabled and can always reach the shared [`h1`] helpers.
#[cfg(feature = "http3")]
pub mod h3;
