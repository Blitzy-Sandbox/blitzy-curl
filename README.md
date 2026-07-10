<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# [![curl logo](https://curl.se/logo/curl-logo.svg)](https://curl.se/)

curl is a command-line tool for transferring data from or to a server using
URLs. It supports these protocols: DICT, FILE, FTP, FTPS, GOPHER, GOPHERS,
HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, MQTT, MQTTS, POP3, POP3S, RTSP, SCP,
SFTP, SMB, SMBS, SMTP, SMTPS, TELNET, TFTP, WS and WSS.

Learn how to use curl by reading [the
man page](https://curl.se/docs/manpage.html) or [everything
curl](https://everything.curl.dev/).

Find out how to install curl by reading [the INSTALL
document](https://curl.se/docs/install.html).

libcurl is the library curl is using to do its job. It is readily available to
be used by your software. Read [the libcurl
man page](https://curl.se/libcurl/c/libcurl.html) to learn how.

## About this repository

This repository is a memory-safe [Rust](https://www.rust-lang.org/)
reimplementation of curl and libcurl 8.19.0-DEV that aims for functional
parity with curl 8.x: it behaves identically on the wire, on the command
line, and at the libcurl C API. The original curl C source tree is retained
here as the source-of-truth reference and behavioral parity oracle, and the
Rust code lives alongside it in a three-crate
[Cargo](https://doc.rust-lang.org/cargo/) workspace.

## Workspace structure

The Rust code is organized as a Cargo workspace with three member crates:

- `curl-rs-lib` — the core library: protocol handlers, connection management,
  TLS, authentication, DNS, content encoding, URL handling, the transfer core,
  and file-backed state. It replaces the C `lib/` tree.
- `curl-rs` — the [`clap`](https://docs.rs/clap)-based command-line binary that
  preserves the full curl flag surface; its `clap` argument definitions are
  derived 1:1 from the option pages in `docs/cmdline-opts/`. It replaces the C
  `src/` tree.
- `curl-rs-ffi` — the C-ABI compatibility layer. It exposes
  `libcurl`-compatible `curl_*` symbols; its build runs
  [`cbindgen`](https://github.com/mozilla/cbindgen) to produce a header
  *verification artifact* (written under the Cargo build output directory) that
  is checked against the committed `include/curl/curl.h` — the committed header
  is never overwritten. Existing C/C++ consumers keep including the same header
  path and relink against `libcurl_rs_ffi` without recompilation. It replaces
  the hand-authored public header generation.

## Build

Building requires a Rust toolchain using edition 2021 with a minimum supported
Rust version (MSRV) of 1.75, pinned via `rust-toolchain.toml`.

Build the whole workspace in release mode and run the tests with:

    cargo build --release --workspace
    cargo test --workspace

The build produces the `curl-rs` command-line binary and the `libcurl_rs_ffi`
shared library, a drop-in replacement for `libcurl.so`.

## Backends and dependencies

All dependencies come from [crates.io](https://crates.io/); no C TLS or
transport libraries are linked (only optional OS GSSAPI/Kerberos for Negotiate
authentication). The main building blocks are:

- TLS: [rustls](https://github.com/rustls/rustls), the single TLS backend, with
  certificate validation on by default.
- HTTP/1.1 and HTTP/2: [hyper](https://hyper.rs/).
- HTTP/3: [quinn](https://github.com/quinn-rs/quinn) with
  [h3](https://github.com/hyperium/h3).
- SSH, SFTP, and SCP: [russh](https://github.com/Eugeny/russh).
- Async runtime: [Tokio](https://tokio.rs/).
- Content decompression: flate2, brotli, and zstd.

The version string has the form
`curl-rs/8.19.0-DEV rustls flate2 brotli zstd hyper quinn russh`.

## Supported platforms

The Rust build targets four platforms:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Windows and the legacy platforms carried by the C code (AmigaOS, OpenVMS,
OS-400, RISC-OS) are not carried forward.

## Open Source

curl is Open Source and is distributed under an MIT-like
[license](https://curl.se/docs/copyright.html).

## Contact

Contact us on a suitable [mailing list](https://curl.se/mail/) or
use GitHub [issues](https://github.com/curl/curl/issues)/
[pull requests](https://github.com/curl/curl/pulls)/
[discussions](https://github.com/curl/curl/discussions).

All contributors to the project are listed in [the THANKS
document](https://curl.se/docs/thanks.html).

## Commercial support

For commercial support, maybe private and dedicated help with your problems or
applications using (lib)curl visit [the support page](https://curl.se/support.html).

## Website

Visit the [curl website](https://curl.se/) for the latest news and downloads.

## Source code

Download the latest source from the Git server:

    git clone https://github.com/curl/curl

## Security problems

Report suspected security problems
[privately](https://curl.se/dev/vuln-disclosure.html) and not in public.

## Backers

Thank you to all our backers :pray: [Become a backer](https://opencollective.com/curl#section-contribute).

## Sponsors

Support this project by becoming a [sponsor](https://curl.se/sponsors.html).
