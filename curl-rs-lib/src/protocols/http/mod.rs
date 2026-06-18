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
//! * [`chunks`] — the HTTP/1.1 chunked Transfer-Encoding codec
//!   (`lib/http_chunks.c`): a resumable, byte-exact decoder for response bodies
//!   (with trailer capture and the `--raw` pass-through path) and an encoder for
//!   request bodies carrying `Transfer-Encoding: chunked`.
//!
//! The remaining engines — `h1`, `h2`, `h3`, and the proxy-connect helpers — are
//! authored by sibling migration steps and declared here as they land.
//!
//! # Memory safety
//!
//! This subtree inherits `#![forbid(unsafe_code)]` from [`crate::protocols`]; it
//! is intentionally **not** re-declared here.

pub mod aws_sigv4;
pub mod chunks;
