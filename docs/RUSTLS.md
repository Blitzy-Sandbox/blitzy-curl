<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Rustls

[Rustls](https://docs.rs/rustls/) is the one and only TLS backend in this Rust
rewrite of curl, used natively through the `rustls` crate (version 0.23.36) and
compiled in as an ordinary `crates.io` dependency.

The other TLS backends that curl historically supported (OpenSSL, GnuTLS,
mbedTLS, wolfSSL, Schannel, and Apple Secure Transport) have been removed. There
is no choice of backend, and no C TLS library is linked in any build.

The `rustls` backend is mandatory and always compiled in; it is not optional and
cannot be disabled.

The `rustls` support stack is `tokio-rustls` 0.26.4 (the asynchronous stream
adapter), `rustls-pki-types` 1 and `rustls-pemfile` 2 (certificate and key
parsing), and `webpki-roots` 1 (the bundled root-certificate store).

## Building

The `rustls` crate needs no separate installation, prerequisite, or build flag.
Build curl with Cargo, and `rustls` is pulled in automatically:

```
% git clone https://github.com/curl/curl
% cd curl
% cargo build --release --workspace
```

The build needs the Rust 2021 edition toolchain with a minimum supported Rust
version of 1.75, pinned by `rust-toolchain.toml`. Install the toolchain with
[rustup] if you do not already have it.

## Certificate verification

Because `rustls` is the single audited default, certificate validation is on by
default, matching `CURLOPT_SSL_VERIFYPEER = 1` and `CURLOPT_SSL_VERIFYHOST = 2`.
Peer certificates are validated against the bundled `webpki-roots` trust
anchors, and against the platform trust store where applicable.

The `--insecure` (`-k`) option disables verification. Before it proceeds, curl
prints a warning to stderr, so the security downgrade is always visible. The
option keeps the same name and semantics it has in curl 8.x.

Consolidating on one audited TLS backend is the security rationale for this
change, and the TLS code contains zero `unsafe`.

[rustup]: https://rustup.rs/
