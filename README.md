<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# [![curl logo](https://curl.se/logo/curl-logo.svg)](https://curl.se/)

curl is a command-line tool for transferring data from or to a server using
URLs. It supports these protocols: DICT, FILE, FTP, FTPS, GOPHER, GOPHERS,
HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, MQTT, MQTTS, POP3, POP3S, RTMP, RTMPS,
RTSP, SCP, SFTP, SMB, SMBS, SMTP, SMTPS, TELNET, TFTP, WS and WSS.

## curl-rs: Rust Rewrite

**curl-rs** is a complete rewrite of the curl codebase (version 8.19.0-DEV)
from C into idiomatic Rust, producing a functionally equivalent set of
artifacts:

- **`curl-rs`** — CLI binary with all `--long-option` flags identical to curl 8.x
- **`curl-rs-lib`** — Core library crate (protocols, TLS, transfer, DNS, authentication)
- **`curl-rs-ffi`** — FFI compatibility layer exposing all 106 `CURL_EXTERN` symbols for drop-in C ABI compatibility

### Protocols

HTTP/1.1, HTTP/2, HTTP/3, FTP/FTPS, SFTP, and SCP are fully supported through
pure-Rust implementations:

| Protocol | Rust Backend |
|----------|-------------|
| HTTP/1.1 and HTTP/2 | [hyper](https://crates.io/crates/hyper) |
| HTTP/3 (QUIC) | [quinn](https://crates.io/crates/quinn) + [h3](https://crates.io/crates/h3) |
| TLS | [rustls](https://crates.io/crates/rustls) (exclusive — zero C TLS library linkage) |
| SFTP / SCP | [russh](https://crates.io/crates/russh) |
| FTP / FTPS | Native Rust with rustls for TLS upgrade |

### Rust Toolchain

- **Edition:** 2021
- **MSRV:** 1.75
- **Async runtime:** [Tokio](https://crates.io/crates/tokio) (current-thread for CLI, multi-thread for multi-handle)

## Building from Source (Rust)

### Prerequisites

- Rust stable toolchain **1.75 or later**, installed via [rustup](https://rustup.rs/)
- For development: `rustup component add clippy llvm-tools-preview`
- For Miri testing: `rustup toolchain install nightly && rustup component add --toolchain nightly miri rust-src`

### Workspace Structure

```
curl-rs workspace
├── Cargo.toml        (workspace root manifest)
├── curl-rs-lib/      (core library crate — protocols, TLS, transfer, DNS, auth)
├── curl-rs/          (CLI binary crate — clap 4.x argument parsing)
└── curl-rs-ffi/      (FFI/ABI compatibility crate — cdylib + staticlib, cbindgen)
```

### Build Commands

```bash
# Build all crates (release, zero warnings required)
cargo build --release --workspace

# Run the full test suite
cargo test --workspace

# Lint with Clippy (zero warnings enforced)
cargo clippy --workspace -- -D warnings

# Run Miri on non-FFI modules (requires nightly)
cargo +nightly miri test -p curl-rs-lib
```

The compiled binary is located at `target/release/curl-rs`.

### CI Targets

All builds and tests are validated on four targets via GitHub Actions:

- Linux x86\_64 (`ubuntu-latest`)
- Linux aarch64 (via cross-compilation)
- macOS x86\_64
- macOS arm64

## Installation

### Rust (recommended)

```bash
# Install directly from the workspace
cargo install --path curl-rs

# Or build and copy the binary manually
cargo build --release --workspace
cp target/release/curl-rs /usr/local/bin/
```

### C (original)

Find out how to install curl by reading [the INSTALL
document](https://curl.se/docs/install.html).

## Documentation

Learn how to use curl by reading [the
man page](https://curl.se/docs/manpage.html) or [everything
curl](https://everything.curl.dev/).

libcurl is the library curl is using to do its job. It is readily available to
be used by your software. Read [the libcurl
man page](https://curl.se/libcurl/c/libcurl.html) to learn how. The Rust FFI
crate (`curl-rs-ffi`) provides a drop-in replacement for `libcurl.so` /
`libcurl.a` — downstream C programs can link against the Rust-built library
without recompilation.

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
