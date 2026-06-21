//! Socket non-blocking toggle — the Rust rewrite of libcurl's
//! `lib/curlx/nonblock.c` (and its `lib/curlx/nonblock.h` declaration).
//!
//! # Origin and mapping
//!
//! In C, [`curlx_nonblock`] is curl's one-function, "highly portable" helper for
//! switching a socket between blocking and non-blocking mode. The behavioral
//! oracle does this through whichever native primitive the build target offers:
//!
//! * POSIX — `fcntl(F_GETFL)` then `fcntl(F_SETFL, flags ± O_NONBLOCK)`,
//! * Windows — `ioctlsocket(fd, FIONBIO, …)`,
//! * older/other systems — `ioctl(FIONBIO)` / `IoctlSocket` / `setsockopt`,
//!
//! returning the underlying syscall result (`>= 0` on success, `< 0` on error).
//! See `lib/curlx/nonblock.c` for the exact branch ladder this module preserves
//! the *behavior* of.
//!
//! This rewrite reproduces the **semantics** — "set the socket to blocking or
//! non-blocking based on a boolean" — without reproducing the raw syscalls.
//! All of that platform branching is exactly what the [`socket2`] crate already
//! encapsulates behind a single safe method, so [`curlx_nonblock`] is a thin
//! wrapper over [`socket2::SockRef::set_nonblocking`]. `socket2` selects
//! `fcntl`/`ioctlsocket` per target internally, matching the C oracle's intent
//! while keeping this code free of `unsafe`.
//!
//! # Relationship to the async core
//!
//! Sockets owned by Tokio (e.g. `tokio::net::TcpStream`, `UdpSocket`) are
//! configured non-blocking by the runtime when they are created, so the async
//! transfer and connection paths never need to call this function. It is
//! retained purely for **parity** and for the handful of *raw-socket* setup
//! paths that configure a freshly created file descriptor before it is handed to
//! Tokio — for example the `--interface` binding path and the SOCKS proxy
//! handshake, which mirror C call sites that invoke `curlx_nonblock` directly.
//! Keep it minimal: this is a compatibility shim, not a hot path.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` code and is compiled under the
//! module-level `#![forbid(unsafe_code)]` below (consistent with the rest of
//! `curl-rs-lib`'s safe core, per AAP §0.7.1). The non-blocking flag is toggled
//! exclusively through `socket2`'s safe `set_nonblocking` API — the raw
//! `fcntl`/`ioctlsocket` calls of the C original are *not* reintroduced, since
//! doing so would require `unsafe` and violate the crate's safety mandate.

#![forbid(unsafe_code)]

use socket2::SockRef;

use crate::error::Result;

// curl operates on Unix file descriptors and Windows SOCKETs; `socket2`'s
// `SockRef::from(&S)` is correspondingly bounded by `AsFd` on Unix and
// `AsSocket` on Windows. We import the platform-appropriate trait under a single
// local alias (`AsSocketlike`) so that [`curlx_nonblock`] can be written once
// with one generic bound that resolves to the correct trait on each target.
//
// `std::os::fd::AsFd` is the canonical handle trait (re-exported as
// `std::os::unix::io::AsFd`), and is exactly the bound `socket2` requires for
// its `From<&S> for SockRef` implementation, so a value accepted here is always
// accepted by `SockRef::from`.
#[cfg(unix)]
use std::os::fd::AsFd as AsSocketlike;
#[cfg(windows)]
use std::os::windows::io::AsSocket as AsSocketlike;

// Faithful parity with the C oracle's final `#else #error "no non-blocking
// method was found/used/set"` arm: on a target that is neither Unix nor Windows
// there is no socket-handle trait to operate on, so fail at compile time with a
// clear message rather than silently dropping the capability. All curl-rs build
// targets (Linux/macOS x86_64 + aarch64, Windows) satisfy `unix` or `windows`.
#[cfg(not(any(unix, windows)))]
compile_error!(
    "curlx_nonblock: no non-blocking socket method is available for this target \
     (parity with the `#error` arm of lib/curlx/nonblock.c)"
);

/// Set or clear non-blocking mode on a socket — the safe Rust counterpart of
/// C's `int curlx_nonblock(curl_socket_t sockfd, int nonblock)`.
///
/// When `nonblock` is `true` the socket is put into non-blocking mode; when it
/// is `false` the socket is returned to blocking mode. This mirrors the C
/// contract where a non-zero `nonblock` argument enables non-blocking mode and
/// zero disables it.
///
/// # Arguments
///
/// * `sock` — a borrowed socket handle. Any type that exposes its underlying
///   descriptor works: `std::net::TcpStream`, `std::net::TcpListener`,
///   `std::net::UdpSocket`, a [`socket2::Socket`], etc. (Concretely, any `S`
///   that implements [`AsFd`](std::os::fd::AsFd) on Unix or
///   [`AsSocket`](std::os::windows::io::AsSocket) on Windows.)
/// * `nonblock` — `true` to enable non-blocking mode, `false` to disable it.
///
/// # Returns
///
/// `Ok(())` on success. The C function returns the raw syscall result
/// (`>= 0` ok); here that success path collapses to the unit value, which is
/// the idiomatic crate-internal representation and what every safe call site
/// expects.
///
/// # Errors
///
/// Returns a [`CurlError`](crate::error::CurlError) if the underlying
/// `set_nonblocking` syscall fails (the analogue of the C function's negative
/// return). The originating [`std::io::Error`] is mapped onto the closest
/// `CURLcode`-bearing variant by the crate-wide `From<std::io::Error>`
/// conversion, so the error round-trips to a stable integer at the FFI edge.
///
/// # Behavioral note
///
/// The C original first reads the current flags with `fcntl(F_GETFL)` and skips
/// the `F_SETFL` write when the requested state already matches. That is a
/// private micro-optimization with no externally observable effect; `socket2`
/// performs the get/modify/set internally, so the observable outcome — the
/// socket's blocking state and the success/failure result — is identical.
///
/// # Example
///
/// ```ignore
/// use std::net::TcpStream;
/// use curl_rs_lib::util::nonblock::curlx_nonblock;
///
/// let sock = TcpStream::connect("198.51.100.10:80")?;
/// // Enter non-blocking mode (parity with C `curlx_nonblock(fd, 1)`).
/// curlx_nonblock(&sock, true)?;
/// // … and restore blocking mode later (parity with `curlx_nonblock(fd, 0)`).
/// curlx_nonblock(&sock, false)?;
/// # Ok::<(), curl_rs_lib::error::CurlError>(())
/// ```
pub fn curlx_nonblock<S>(sock: &S, nonblock: bool) -> Result<()>
where
    S: AsSocketlike,
{
    // `SockRef::from(sock)` borrows the descriptor without taking ownership, so
    // the caller's socket is untouched aside from the flag change. The `?`
    // converts the returned `std::io::Error` into `CurlError` via the crate's
    // `From<std::io::Error>` implementation (the target error type is fixed by
    // this function's signature, so the conversion is unambiguous).
    SockRef::from(sock).set_nonblocking(nonblock)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    /// Enabling non-blocking mode must actually take effect: a freshly bound
    /// listener with no pending connections must report `WouldBlock` from a
    /// non-blocking `accept()` instead of blocking. This is a portable
    /// functional proof (the `WouldBlock` kind is the same on Unix and Windows)
    /// that the toggle reached the underlying socket, not merely that the call
    /// returned `Ok`.
    #[test]
    fn enabling_nonblock_makes_accept_wouldblock() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");

        curlx_nonblock(&listener, true).expect("enable non-blocking");

        match listener.accept() {
            Err(e) if e.kind() == ErrorKind::WouldBlock => { /* expected */ }
            other => panic!("expected WouldBlock from non-blocking accept, got {other:?}"),
        }

        // Restoring blocking mode must also succeed.
        curlx_nonblock(&listener, false).expect("disable non-blocking");
    }

    /// Toggling the flag on then off then on again must succeed on every cycle,
    /// exercising both branches of the `nonblock` argument repeatedly.
    #[test]
    fn toggle_on_off_on_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");

        for &state in &[true, false, true, false] {
            curlx_nonblock(&listener, state)
                .unwrap_or_else(|e| panic!("toggle to {state} failed: {e:?}"));
        }
    }

    /// The helper accepts a connected `TcpStream`, not just a listener.
    #[test]
    fn works_on_connected_tcp_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let client = TcpStream::connect(addr).expect("connect client");
        // Accept the peer so the connection is fully established before toggling.
        let (server, _peer) = listener.accept().expect("accept server side");

        curlx_nonblock(&client, true).expect("client -> non-blocking");
        curlx_nonblock(&server, true).expect("server -> non-blocking");
        curlx_nonblock(&client, false).expect("client -> blocking");
        curlx_nonblock(&server, false).expect("server -> blocking");
    }

    /// The helper is socket-kind agnostic: a UDP socket toggles just as well as
    /// a TCP one, confirming the generic `AsFd`/`AsSocket` bound is satisfied by
    /// any standard socket handle.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn works_on_udp_socket() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind udp");

        curlx_nonblock(&sock, true).expect("udp -> non-blocking");
        curlx_nonblock(&sock, false).expect("udp -> blocking");
    }
}
