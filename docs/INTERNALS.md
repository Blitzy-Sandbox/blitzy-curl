<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# curl internals

The canonical libcurl internals documentation remains in the [everything
curl](https://everything.curl.dev/internals) book as general curl background.
This repository, however, is the idiomatic-Rust reimplementation of curl and
libcurl 8.19.0-DEV: the C tree is retained as a source-of-truth reference while a
three-crate Cargo workspace (`curl-rs-lib`, `curl-rs`, `curl-rs-ffi`) provides the
implementation, with byte-for-byte functional parity to curl 8.x. This file lists
the supported Rust toolchain, the crate dependencies, and the internal
architecture of that workspace.

## Portability

We write curl and libcurl in Rust, targeting the 2021 edition with a Minimum
Supported Rust Version (MSRV) of 1.75, pinned via `rust-toolchain.toml`. The MSRV
floor — rather than any C89/POSIX or `stdint.h` assumption — defines what we build
against.

We support these four target platforms:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Windows (the Schannel paths and the `dllmain.c` entry point) and the legacy
platforms (AmigaOS, OpenVMS, OS-400, RISC-OS) are not carried forward. There is no
`no_std` or embedded target.

## Dependencies

All runtime dependencies are sourced exclusively from crates.io; no C
cryptographic or transport library is linked. We use these crates (the versions
below are the resolved pins from the root `Cargo.toml`):

- Async runtime & utilities: `tokio` 1.49.0 (sole async runtime), `tokio-util`
  0.7, `futures-util` 0.3, `pin-project-lite` 0.2, `bytes` 1, `socket2` 0.5
- HTTP/1.1 & HTTP/2: `hyper` 1.7.0, `hyper-util` 0.1.20, `http` 1, `http-body` 1,
  `http-body-util` 0.1, `h2` 0.4
- HTTP/3 & QUIC: `quinn` 0.11.9, `h3` 0.0.8, `h3-quinn` 0.0.10
- TLS (single backend): `rustls` 0.23.36, `tokio-rustls` 0.26.4,
  `rustls-pki-types` 1, `rustls-pemfile` 2, `webpki-roots` 1
- SSH: `russh` 0.53.0, `russh-sftp` 2.1.1, `russh-keys` 0.49.2
- DNS: `hickory-resolver` 0.25.2 (optional, behind the default-off `hickory-dns`
  feature; the default resolver is the Tokio system resolver)
- CLI: `clap` 4.5.54, `clap_complete` 4
- Authentication crypto (pure Rust): `sha2` 0.10, `md-5` 0.10, `md4` 0.10, `hmac`
  0.12, `des` 0.8, `base64` 0.22, `rand` 0.8
- Content encoding: `flate2` 1, `brotli` 8, `zstd` 0.13
- URL / IDN / PSL: `url` 2, `percent-encoding` 2, `idna` 1, `publicsuffix` 2,
  `glob` 0.3
- Serialization, time & logging: `serde` 1, `serde_json` 1, `chrono` 0.4,
  `tracing` 0.1, `tracing-subscriber` 0.3
- Errors: `thiserror` 2 (library), `anyhow` 1 (CLI)
- FFI & codegen: `cbindgen` 0.29.2 (build-dependency), `libc` 0.2

Two of these pins deviate from the versions named in the original technical
specification, because those versions do not resolve or build and would fail the
mandatory *buildable workspace* and *MSRV 1.75* gates:

- `h3` is pinned to **0.0.8** rather than 0.0.7. The specified `h3-quinn`
  0.0.10 itself depends on `h3` 0.0.8, so pinning `h3` 0.0.7 alongside it pulls
  two incompatible `h3` versions into the graph and fails to compile. `h3` 0.0.8
  unifies the graph and is the version `h3-quinn` 0.0.10 is built against.
- `russh` is pinned to **0.53.0** rather than 0.54.6. `russh` 0.54.6 is
  unresolvable: it pulls the transitive crate `libcrux-ml-kem` 0.0.3, which is
  *yanked* from crates.io. The 0.53.x line (with `russh-sftp` 2.1.1 and
  `russh-keys` 0.49.2) resolves cleanly, while the newer 0.62.x line raises its
  own MSRV above 1.75 and so cannot be used under the pinned toolchain.

These are the only deviations; the root `Cargo.toml` carries the same rationale
inline, and every other pin matches the specification.

The only optional C linkage retained is OS GSSAPI/Kerberos, used for Negotiate
authentication. Every other former C dependency has been removed: OpenSSL,
GnuTLS, mbedTLS, wolfSSL, Schannel, and Apple Secure Transport (replaced by
`rustls`); ngtcp2 + nghttp3 and quiche (replaced by `quinn` + `h3`); libssh and
libssh2 (replaced by `russh`); nghttp2 (replaced by `h2` via `hyper`); c-ares
(replaced by the Tokio resolver, with `hickory-resolver` optional); and zlib,
system brotli, and system zstd (replaced by the `flate2`, `brotli`, and `zstd`
crates). RTMP and RTMPS are dropped — no pure-Rust `librtmp` equivalent exists.

Cargo `[features]` replace the C `#ifdef CURL_DISABLE_*` / `USE_*` guards.
Default-on: `http`, `ftp`, `smtp`, `imap`, `pop3`, `tftp`, `telnet`, `dict`,
`mqtt`, `rtsp`, `cookies`, `brotli`, `zstd`. Default-off: `hickory-dns`.

## Build tools

The build and validation toolchain is Cargo-based:

- `cargo build` / `cargo test` — compile the workspace and run its test suite
- `cargo clippy -- -D warnings` — lint gate (warnings treated as errors)
- `rustfmt` (via `cargo fmt`) — formatting gate
- `cbindgen` 0.29.2 — renders an `include/curl/curl.h` verification artifact
  (invoked from `curl-rs-ffi/build.rs`; the committed header is never overwritten)
- `cargo-deny` — license / advisory / source policy
- `cargo audit` — CVE scanning
- Miri (on the nightly toolchain) — undefined-behavior checking of the safe core
- `cargo llvm-cov` — coverage (requires the `llvm-tools-preview` component)

The MSRV gate is `cargo +1.75 check`.

## Library Symbols

Internal items rely on Rust module visibility — `pub(crate)` items and private
modules — instead of the C `Curl_` prefix plus `static` convention.

The public C ABI is exposed only from the `curl-rs-ffi` crate, as
`#[no_mangle] pub extern "C"` functions that carry the historical `curl_` names.
At build time `cbindgen` renders those annotations into a header *verification
artifact* (written under the Cargo build output directory) that is checked
against the committed `include/curl/curl.h`; the committed header is never
overwritten. Downstream C/C++ consumers keep including the same header path and
relink against `libcurl_rs_ffi` without source changes. The public surface reproduces the curl 8.x `CURL_EXTERN`
functions (about 101 across the 13 public headers), and the `CURLcode`,
`CURLoption`, and `CURLINFO` integer values are frozen for ABI parity.

## Workspace layout

The workspace has three crates:

- `curl-rs-lib` — the core library: protocol handlers, connection management,
  TLS, authentication, DNS, content encoding, URL handling, the transfer core,
  and file-backed state. Replaces `lib/`.
- `curl-rs` — the `clap`-based CLI binary, preserving the full curl flag surface.
  Replaces `src/`.
- `curl-rs-ffi` — the C-ABI compatibility shim (`extern "C"` `curl_*` symbols plus
  the `cbindgen`-generated header). Replaces the hand-authored public headers, and
  builds `libcurl_rs_ffi` as a drop-in for `libcurl.so`.

## Memory-safety model

Manual `malloc` / `free` / `realloc` is replaced by Rust ownership, borrowing, and
lifetimes. `unsafe` is confined to `curl-rs-ffi` (plus a few narrow OS-integration
primitives); there is zero `unsafe` in `protocols/`, `tls/`, and `transfer.rs`,
enforced by a CI grep audit (`grep -rn 'unsafe' curl-rs-lib/src/`). Every `unsafe`
block carries a `// SAFETY:` comment stating its invariant. Miri validates the
safe core and AddressSanitizer validates the FFI boundary. Cross-handle sharing
(`curl_share_*`) uses `Arc<Mutex<…>>` with fine-grained per-data-type locking.

## Design pillars

1. Tokio is the sole async runtime — the `current-thread` flavor for the CLI,
   `multi-thread` for the multi handle.
2. Trait-based protocol dispatch replaces the C `#ifdef` protocol branching.
3. A `tower`-inspired connection filter chain (TCP → TLS → HTTP/2 → application)
   mirrors curl's connection filters.
4. Builder-pattern configuration for the easy and multi handles, while preserving
   the `curl_easy_setopt` C ABI for FFI consumers.
5. `cbindgen` header generation keeps the public C header in sync with the Rust
   source.

## Diagnostic state names

Internal state vocabularies are preserved verbatim so `--trace` / `--verbose`
output stays identical: the multi-handle `MSTATE` enum and per-protocol state
names such as `FTP_*` and `IMAP_*` keep their curl 8.x identities. The version
string likewise keeps its familiar form:
`curl-rs/8.19.0-DEV rustls flate2 brotli zstd hyper quinn russh`.
