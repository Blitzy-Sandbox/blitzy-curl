<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Rustls

[Rustls is a TLS backend written in Rust](https://docs.rs/rustls/). curl can
be built to use it as an alternative to OpenSSL or other TLS backends. We use
the [rustls-ffi C bindings](https://github.com/rustls/rustls-ffi). This
version of curl is compatible with `rustls-ffi` v0.15.x.

## Getting rustls-ffi

To build `curl` with `rustls` support you need to have `rustls-ffi` available first.
There are three options for this:

1. Install it from your package manager, if available.
2. Download pre-built binaries.
3. Build it from source.

### Installing rustls-ffi from a package manager

See the [rustls-ffi README] for packaging status. Availability and details for installation
differ between distributions.

Once installed, build `curl` using `--with-rustls`.

    % git clone https://github.com/curl/curl
    % cd curl
    % autoreconf -fi
    % ./configure --with-rustls
    % make

[rustls-ffi README]: https://github.com/rustls/rustls-ffi?tab=readme-ov-file

### Downloading pre-built rustls-ffi binaries

Pre-built binaries are available on the [releases page] on GitHub for releases since 0.15.0.
Download the appropriate archive for your platform and extract it to a directory of your choice
(e.g. `${HOME}/rustls-ffi-built`).

Once downloaded, build `curl` using `--with-rustls` and the path to the extracted binaries.

    % git clone https://github.com/curl/curl
    % cd curl
    % autoreconf -fi
    % ./configure --with-rustls=${HOME}/rustls-ffi-built
    % make

[releases page]: https://github.com/rustls/rustls-ffi/releases

### Building rustls-ffi from source

Building `rustls-ffi` from source requires both a rust compiler, and the [cargo-c] cargo plugin.

To install a Rust compiler, use [rustup] or your package manager to install
the **1.73+** or newer toolchain.

To install `cargo-c`, use your [package manager][cargo-c pkg], download
[a pre-built archive][cargo-c prebuilt], or build it from source with `cargo install cargo-c`.

Next, check out, build, and install the appropriate version of `rustls-ffi` using `cargo`:

    % git clone https://github.com/rustls/rustls-ffi -b v0.15.0
    % cd rustls-ffi
    % cargo capi install --release --prefix=${HOME}/rustls-ffi-built

Now configure and build `curl` using `--with-rustls`:

    % git clone https://github.com/curl/curl
    % cd curl
    % autoreconf -fi
    % ./configure --with-rustls=${HOME}/rustls-ffi-built
    % make

See the [rustls-ffi README][cryptography provider] for more information on cryptography providers and
their build/platform requirements.

[cargo-c]: https://github.com/lu-zero/cargo-c
[rustup]: https://rustup.rs/
[cargo-c pkg]: https://github.com/lu-zero/cargo-c?tab=readme-ov-file#availability
[cargo-c prebuilt]: https://github.com/lu-zero/cargo-c/releases
[cryptography provider]: https://github.com/cpu/rustls-ffi?tab=readme-ov-file#cryptography-provider

## curl-rs Rust Workspace — Native Rustls

The **curl-rs** Rust workspace uses rustls **natively** as its exclusive TLS
backend. Unlike the C codebase described above (which relies on rustls-ffi C
bindings), the Rust workspace depends on the `rustls` crate directly — no
separate rustls-ffi build step is needed.

### TLS dependency stack

| Crate | Version | Role |
|-------|---------|------|
| `rustls` | 0.23.36 | TLS 1.2/1.3 implementation — sole TLS provider |
| `tokio-rustls` | 0.26.4 | Async TLS stream integration with the Tokio runtime |
| `webpki-roots` | 1.x | Mozilla root certificate bundle for default trust |
| `rustls-pemfile` | 2.x | PEM certificate and private-key file parsing |
| `rustls-pki-types` | 1.x | Shared PKI type definitions (certificates, keys) |

All of these are regular Cargo dependencies resolved automatically from
crates.io — **no manual installation or linking** is required.

### What this replaces

The native Rust TLS stack replaces **all** C TLS backends that were previously
selectable at configure time:

- OpenSSL / LibreSSL
- GnuTLS
- mbedTLS
- wolfSSL
- Apple Security Transport (SecureTransport)
- Windows Schannel (SChannel)

With curl-rs there is **zero C TLS library linkage** in any build
configuration. The `rustls` crate is the only TLS provider.

### Building

TLS support is included automatically when you build the workspace:

    % cargo build --release --workspace

No `--with-rustls` flag or separate configure step is necessary.

### Certificate validation

TLS certificate validation is **ON** by default. If the `--insecure` (`-k`)
flag is passed, a warning is emitted to stderr before the transfer proceeds,
matching the behavior of curl 8.x.

### Minimum Supported Rust Version

The curl-rs workspace requires **Rust 1.75** or newer (the `rustls` 0.23.x
crate itself requires Rust 1.71+). The pinned toolchain is defined in
`rust-toolchain.toml` at the repository root.
