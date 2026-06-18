<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# [![curl logo](https://curl.se/logo/curl-logo.svg)](https://curl.se/)

curl is a command-line tool for transferring data from or to a server using
URLs. It supports these protocols: DICT, FILE, FTP, FTPS, GOPHER, GOPHERS,
HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, MQTT, MQTTS, POP3, POP3S, RTMP, RTMPS,
RTSP, SCP, SFTP, SMB, SMBS, SMTP, SMTPS, TELNET, TFTP, WS and WSS.

Learn how to use curl by reading [the
man page](https://curl.se/docs/manpage.html) or [everything
curl](https://everything.curl.dev/).

Find out how to install curl by reading [the INSTALL
document](https://curl.se/docs/install.html).

libcurl is the library curl is using to do its job. It is readily available to
be used by your software. Read [the libcurl
man page](https://curl.se/libcurl/c/libcurl.html) to learn how.

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

## Building the Rust implementation (curl-rs)

This repository also contains a memory-safe Rust rewrite of curl, organized as a
Cargo workspace. It produces a drop-in `curl` binary and a `libcurl`-compatible
shared/static library, targeting functional parity with curl 8.x. The Rust
workspace lives alongside the original C tree, which is retained as the
behavioral and ABI reference.

The workspace is split into three crates:

- `curl-rs-lib`: the core async library (protocol engines, TLS, transfer,
  connection management, DNS, and authentication).
- `curl-rs`: the command-line binary crate; a drop-in replacement for `curl`.
- `curl-rs-ffi`: the FFI crate that exposes the `extern "C"` libcurl ABI and
  builds the `libcurl`-compatible `cdylib`/`staticlib`.

Building requires a Rust toolchain matching `rust-toolchain.toml` (the stable
channel; MSRV 1.75, edition 2021). The memory-safety gates additionally
require a nightly toolchain with the `miri` and `rust-src` components.

Build everything in release mode, run the CLI (the produced binary acts as a
drop-in `curl`), and run the test and lint gates:

```sh
cargo build --release --workspace
cargo run --release --bin curl-rs -- https://example.com
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

TLS is provided exclusively by [rustls](https://github.com/rustls/rustls); there
is no OpenSSL, native-tls, or C TLS linkage. Certificate validation is on by
default, and `--insecure` emits a warning on stderr.

The produced artifacts substitute for `curl` and `libcurl` at the same
integration points, and the C headers in `include/curl/*.h` continue to define
the stable ABI (regenerated from the Rust sources via
[cbindgen](https://github.com/mozilla/cbindgen)).

## Security problems

Report suspected security problems
[privately](https://curl.se/dev/vuln-disclosure.html) and not in public.

## Backers

Thank you to all our backers :pray: [Become a backer](https://opencollective.com/curl#section-contribute).

## Sponsors

Support this project by becoming a [sponsor](https://curl.se/sponsors.html).
