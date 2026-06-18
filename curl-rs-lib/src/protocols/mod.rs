//! Protocol engines — the `protocols/` subtree root.
//!
//! This module groups the per-protocol implementations of the curl rewrite,
//! mirroring the protocol translation units of the C `lib/` tree (`http.c`,
//! `ftp.c`, `imap.c`, …). Each protocol is driven by the asynchronous transfer
//! engine ([`crate::transfer`]) over the connection-filter chain
//! ([`crate::conn`]): the engine decides *when* a protocol's codecs and state
//! machines run, while the modules here decide *how*. Keeping the protocol logic
//! free of socket and event-loop concerns is what lets the same codecs serve the
//! CLI, the FFI, and the test harness unchanged.
//!
//! As of this checkpoint the HTTP family ([`http`]) is the subtree that is
//! authored. The remaining protocol modules named in AAP §0.4.1 — FTP, the SSH
//! family (SFTP/SCP), the mail protocols (IMAP/POP3/SMTP), and the long tail
//! required for test-suite parity (RTSP, MQTT, WebSocket, TELNET, TFTP, GOPHER,
//! SMB, DICT, FILE, LDAP) — are added by sibling migration steps and declared
//! here as they land.
//!
//! # Memory safety
//!
//! The protocol layer is pure, allocation-safe Rust with no operating-system
//! pointer handling (sockets and other raw file-descriptor work live in
//! [`crate::conn`]), so this subtree opts into `#![forbid(unsafe_code)]` at its
//! root. The attribute propagates to every descendant module — including
//! [`http`] and its codecs — which makes the "zero `unsafe` outside the FFI
//! crate" rule (AAP §0.7.1) compiler-enforced across the whole protocol tree.
//! Descendant modules therefore do **not** re-declare it.

#![forbid(unsafe_code)]

/// The HTTP protocol family — the HTTP/1.1, HTTP/2, and HTTP/3 engines together
/// with the shared codecs they build on (chunked Transfer-Encoding, AWS SigV4
/// request signing, …). See [`http`].
pub mod http;
