<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# curl internals

The canonical libcurl internals documentation is now in the [everything
curl](https://everything.curl.dev/internals) book. This file lists supported
versions of libs and build tools.

## Portability

We write curl and libcurl to compile with C89 compilers on 32-bit and up
machines. Most of libcurl assumes more or less POSIX compliance but that is
not a requirement. The compiler must support a 64-bit integer type as well as
supply a stdint.h header file that defines C99-style fixed-width integer types
like uint32_t.

We write libcurl to build and work with lots of third party tools, and we
want it to remain functional and buildable with these and later versions
(older versions may still work but is not what we work hard to maintain):

## Dependencies

We aim to support these or later versions.

- brotli       1.0.0 (2017-09-21)
- c-ares       1.6.0 (2008-12-09)
- GnuTLS       3.6.5 (2018-12-01)
- libidn2      2.0.0 (2017-03-29)
- LibreSSL     2.9.1 (2019-04-22)
- libssh       0.9.0 (2019-06-28)
- libssh2      1.9.0 (2019-06-20)
- mbedTLS      3.2.0 (2022-07-11)
- MIT Kerberos 1.3 (2003-07-31)
- nghttp2      1.15.0 (2016-09-25)
- OpenLDAP     2.0 (2000-08-01)
- OpenSSL      3.0.0 (2021-09-07)
- Windows      Vista 6.0 (2006-11-08 - 2012-04-10)
- wolfSSL      3.4.6 (2017-09-22)
- zlib         1.2.5.2 (2011-12-11)
- zstd         1.0 (2016-08-31)

## Build tools

When writing code (mostly for generating stuff included in release tarballs)
we use a few "build tools" and we make sure that we remain functional with
these versions:

- clang-tidy     17.0.0 (2023-09-19), recommended: 19.1.0 or later (2024-09-17)
- cmake          3.7 (2016-11-11)
- GNU autoconf   2.59 (2003-11-06)
- GNU automake   1.7 (2002-09-25)
- GNU libtool    1.4.2 (2001-09-11)
- GNU m4         1.4 (2007-09-21)
- mingw-w64      3.0 (2013-09-20)
- perl           5.8 (2002-07-19), on Windows: 5.22 (2015-06-01)
- Visual Studio  2010 10.0 (2010-04-12 - 2020-07-14)

## Library Symbols

All symbols used internally in libcurl must use a `Curl_` prefix if they are
used in more than a single file. Single-file symbols must be made static.
Public ("exported") symbols must use a `curl_` prefix. Public API functions
are marked with `CURL_EXTERN` in the public header files so that all others
can be hidden on platforms where this is possible.

## curl-rs Rust Workspace

The curl-rs Rust workspace is a complete rewrite of the curl C codebase into
idiomatic Rust. It produces a functionally equivalent CLI binary (`curl-rs`),
core library (`curl-rs-lib`), and an FFI compatibility layer (`curl-rs-ffi`)
that preserves the libcurl C ABI.

### Rust Toolchain

- Edition: 2021
- MSRV: 1.75
- Build system: Cargo (workspace with 3 member crates: `curl-rs-lib`,
  `curl-rs`, `curl-rs-ffi`)
- Linting: `cargo clippy --workspace -- -D warnings`
- Testing: `cargo test --workspace`

### Key Rust Dependencies

The Rust workspace replaces all C library dependencies with pure-Rust crate
equivalents. Primary crates and their minimum versions:

- `rustls` 0.23.36 — TLS 1.2/1.3 (replaces OpenSSL, GnuTLS, mbedTLS,
  wolfSSL, Schannel, Secure Transport)
- `hyper` 1.7.0 — HTTP/1.1 + HTTP/2 client (replaces nghttp2)
- `quinn` 0.11.9 — QUIC transport (replaces ngtcp2, quiche)
- `h3` 0.0.8 — HTTP/3 protocol
- `russh` 0.55.0 — SSH client (replaces libssh, libssh2)
- `hickory-resolver` 0.25.2 — DNS resolver (replaces c-ares, optional
  via feature flag)
- `tokio` 1.49.0 — async runtime
- `clap` 4.5.54 — CLI argument parsing
- `flate2` / `brotli` / `zstd` — compression (same role as zlib, brotli,
  and zstd C libraries)

The full dependency list with exact versions is in the workspace root
`Cargo.toml` under `[workspace.dependencies]`.

### Rust Module Conventions

- Internal symbols use Rust module privacy (`pub(crate)`, `pub(super)`)
  instead of the C `Curl_` prefix convention.
- The public API surface is exposed through `curl-rs-lib` crate public
  modules.
- FFI symbols in `curl-rs-ffi` use `#[no_mangle] pub extern "C"` to
  maintain ABI compatibility with the C libcurl interface.
- All 106 `CURL_EXTERN` symbols from the C headers are exposed through
  the FFI crate with identical function signatures, parameter types,
  return types, and error code integer values.
