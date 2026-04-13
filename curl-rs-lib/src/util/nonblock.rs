//! Non-blocking socket mode toggle (Tokio-native).
//!
//! Rust replacement for `lib/curlx/nonblock.c` — cross-platform non-blocking
//! socket mode setting. The C code uses `fcntl(O_NONBLOCK)` on Unix,
//! `ioctlsocket(FIONBIO)` on Windows, and `setsockopt(SO_NONBLOCK)` on some
//! niche platforms (Amiga, Orbis OS). In Rust, the `socket2` crate provides a
//! single, safe API (`SockRef::set_nonblocking` / `SockRef::nonblocking`) that
//! abstracts all platform differences.
//!
//! # Design Notes
//!
//! In the Tokio-based Rust rewrite, sockets created through
//! [`tokio::net::TcpStream`] are **always** non-blocking (backed by mio).
//! This module exists primarily for:
//!
//! 1. **FFI compatibility** — C callers that pass raw file descriptors via the
//!    `curl-rs-ffi` crate need a way to toggle blocking mode. The raw-fd-to-
//!    borrowed-fd conversion (which requires `unsafe`) lives in the FFI crate,
//!    not here.
//! 2. **Legacy interop** — converting a standard-library `TcpStream` received
//!    from external code into a Tokio-managed async stream.
//!
//! For new internal Rust code, prefer using [`tokio::net::TcpStream`] directly
//! rather than manipulating raw file descriptors.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks. All socket operations use
//! the safe `socket2::SockRef` API via the `AsFd` / `AsSocket` traits.
//! Raw file descriptor handling that requires `unsafe` is delegated to the
//! FFI crate (`curl-rs-ffi`) as permitted by AAP Section 0.7.1.
//!
//! # Platform Support
//!
//! - **Unix** (`cfg(unix)`): Accepts any type implementing `std::os::unix::io::AsFd`.
//! - **Windows** (`cfg(windows)`): Accepts any type implementing `std::os::windows::io::AsSocket`.
//!
//! The `socket2::SockRef` type handles platform-specific syscalls internally:
//! - Unix: `fcntl(fd, F_GETFL/F_SETFL, O_NONBLOCK)`
//! - Windows: `ioctlsocket(socket, FIONBIO, &flag)`

use crate::error::CurlError;
use socket2::SockRef;

// ---------------------------------------------------------------------------
// Platform-specific imports — Unix
// ---------------------------------------------------------------------------
#[cfg(unix)]
use std::os::unix::io::AsFd;

// ---------------------------------------------------------------------------
// Platform-specific imports — Windows
// ---------------------------------------------------------------------------
#[cfg(windows)]
use std::os::windows::io::AsSocket;

// ---------------------------------------------------------------------------
// set_nonblocking — Unix
// ---------------------------------------------------------------------------

/// Set or unset non-blocking mode on a socket (Unix).
///
/// This is the Rust equivalent of C `curlx_nonblock(sockfd, nonblock)` which
/// uses `fcntl(fd, F_SETFL, O_NONBLOCK)` on Unix. The `socket2::SockRef` type
/// abstracts the platform-specific call so no manual `fcntl` is needed.
///
/// Accepts any type implementing [`AsFd`], such as `std::net::TcpStream`,
/// `std::net::TcpListener`, or `std::os::unix::io::BorrowedFd`. For raw
/// file descriptor operations from the FFI layer, callers should first
/// convert to a `BorrowedFd` in the FFI crate (where `unsafe` is permitted).
///
/// # Arguments
///
/// * `fd` — A reference to any type that safely provides a file descriptor
///   via the `AsFd` trait.
/// * `nonblock` — `true` to enable non-blocking mode, `false` for blocking.
///
/// # Errors
///
/// Returns [`CurlError::CouldntConnect`] if the underlying `fcntl` call fails
/// (e.g., `EBADF` for an invalid file descriptor).
///
/// # Examples
///
/// ```no_run
/// use curl_rs_lib::util::nonblock::set_nonblocking;
///
/// let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
/// set_nonblocking(&listener, true).unwrap();
/// ```
///
/// # Note
///
/// In the Tokio-based Rust rewrite, sockets created through
/// `tokio::net::TcpStream` are already non-blocking. This function is
/// primarily useful for the FFI layer where external sockets need mode
/// adjustment.
#[cfg(unix)]
pub fn set_nonblocking(fd: &impl AsFd, nonblock: bool) -> Result<(), CurlError> {
    let sock = SockRef::from(fd);
    sock.set_nonblocking(nonblock).map_err(io_to_connect_error)
}

/// Set or unset non-blocking mode on a socket (Windows).
///
/// Windows equivalent that uses `ioctlsocket(socket, FIONBIO, &flag)` under
/// the hood via `socket2::SockRef`.
///
/// # Arguments
///
/// * `socket` — A reference to any type that safely provides a socket handle
///   via the `AsSocket` trait.
/// * `nonblock` — `true` to enable non-blocking mode, `false` for blocking.
///
/// # Errors
///
/// Returns [`CurlError::CouldntConnect`] if the underlying `ioctlsocket`
/// call fails.
#[cfg(windows)]
pub fn set_nonblocking(socket: &impl AsSocket, nonblock: bool) -> Result<(), CurlError> {
    let sock = SockRef::from(socket);
    sock.set_nonblocking(nonblock).map_err(io_to_connect_error)
}

// ---------------------------------------------------------------------------
// make_tokio_socket — Unix
// ---------------------------------------------------------------------------

/// Convert a standard-library [`TcpStream`](std::net::TcpStream) into a Tokio
/// async [`TcpStream`](tokio::net::TcpStream).
///
/// This function **takes ownership** of the `std::net::TcpStream`. After a
/// successful call, the caller must NOT use the original stream — ownership
/// is transferred to the returned `tokio::net::TcpStream`, which will close
/// the underlying socket when dropped.
///
/// The stream is set to non-blocking mode (required by Tokio) and then
/// registered with the Tokio reactor.
///
/// # Arguments
///
/// * `stream` — A standard-library TCP stream. The caller transfers ownership
///   to this function.
///
/// # Errors
///
/// * [`CurlError::CouldntConnect`] — if setting non-blocking mode fails.
/// * [`CurlError::FailedInit`] — if Tokio runtime registration fails (e.g.,
///   no active Tokio runtime, or the socket is not suitable for async I/O).
///
/// # Note
///
/// For the FFI layer that receives raw file descriptors from C callers, the
/// raw-fd-to-`std::net::TcpStream` conversion (which requires `unsafe` via
/// `FromRawFd`) should be performed in the FFI crate where `unsafe` is
/// permitted. This function handles the safe `std` → `tokio` conversion.
pub fn make_tokio_socket(
    stream: std::net::TcpStream,
) -> Result<tokio::net::TcpStream, CurlError> {
    // Tokio requires non-blocking mode on all registered sockets.
    stream
        .set_nonblocking(true)
        .map_err(io_to_connect_error)?;

    // Register with the Tokio reactor. `from_std` panics if there is no
    // active Tokio runtime, so we guard with a runtime handle check first.
    // If no runtime is available, return FailedInit gracefully.
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(CurlError::FailedInit);
    }
    tokio::net::TcpStream::from_std(stream).map_err(io_to_init_error)
}

// ---------------------------------------------------------------------------
// is_nonblocking — Unix
// ---------------------------------------------------------------------------

/// Check whether a socket is currently in non-blocking mode (Unix).
///
/// This is primarily useful for assertions and debugging. Under the hood it
/// calls `fcntl(fd, F_GETFL)` and checks for the `O_NONBLOCK` flag, all
/// abstracted by `socket2::SockRef::nonblocking()`.
///
/// # Arguments
///
/// * `fd` — A reference to any type that safely provides a file descriptor
///   via the `AsFd` trait.
///
/// # Returns
///
/// * `Ok(true)` — the socket is in non-blocking mode.
/// * `Ok(false)` — the socket is in blocking mode.
///
/// # Errors
///
/// Returns [`CurlError::CouldntConnect`] if the underlying syscall fails.
#[cfg(unix)]
pub fn is_nonblocking(fd: &impl AsFd) -> Result<bool, CurlError> {
    let sock = SockRef::from(fd);
    sock.nonblocking().map_err(io_to_connect_error)
}

/// Check whether a socket is currently in non-blocking mode (Windows).
///
/// # Important
///
/// On Windows, it is **not possible** to reliably query the non-blocking state
/// of a socket (there is no `ioctlsocket` query for `FIONBIO`). This function
/// always returns `Err(CurlError::CouldntConnect)` on Windows. Use this
/// function only for debugging on Unix, and avoid depending on its result in
/// Windows-targeted code paths.
#[cfg(windows)]
pub fn is_nonblocking<T: AsSocket>(_socket: &T) -> Result<bool, CurlError> {
    // Windows does not support querying the non-blocking state of a socket.
    // The socket2 crate's `nonblocking()` method is not available on Windows.
    Err(CurlError::CouldntConnect)
}

// ---------------------------------------------------------------------------
// Internal error mapping helpers
// ---------------------------------------------------------------------------

/// Map an `std::io::Error` to [`CurlError::CouldntConnect`].
///
/// This mapping is used for socket operation failures (set_nonblocking,
/// nonblocking query) because the C `curlx_nonblock` function returns `-1`
/// on failure, and callers typically interpret this as a connection-level
/// error that maps to `CURLE_COULDNT_CONNECT` (code 7).
#[inline]
fn io_to_connect_error(_err: std::io::Error) -> CurlError {
    CurlError::CouldntConnect
}

/// Map an `std::io::Error` to [`CurlError::FailedInit`].
///
/// This mapping is used for Tokio runtime registration failures in
/// [`make_tokio_socket`], because a failure to register with the async
/// runtime represents an initialization-level problem that maps to
/// `CURLE_FAILED_INIT` (code 2).
#[inline]
fn io_to_init_error(_err: std::io::Error) -> CurlError {
    CurlError::FailedInit
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that a freshly-created TCP listener socket can be toggled
    /// between blocking and non-blocking mode using [`set_nonblocking`].
    #[cfg(unix)]
    #[test]
    fn test_set_and_query_nonblocking_unix() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();

        // Set non-blocking
        set_nonblocking(&listener, true).expect("set_nonblocking(true) should succeed");
        assert!(
            is_nonblocking(&listener).expect("is_nonblocking should succeed"),
            "socket should be non-blocking after set_nonblocking(true)"
        );

        // Set blocking
        set_nonblocking(&listener, false).expect("set_nonblocking(false) should succeed");
        assert!(
            !is_nonblocking(&listener).expect("is_nonblocking should succeed"),
            "socket should be blocking after set_nonblocking(false)"
        );

        // Toggle back to non-blocking
        set_nonblocking(&listener, true).expect("set_nonblocking(true) should succeed again");
        assert!(
            is_nonblocking(&listener).expect("is_nonblocking should succeed"),
            "socket should be non-blocking again"
        );
    }

    /// Verify that setting non-blocking mode is idempotent — calling
    /// `set_nonblocking(&listener, true)` twice does not error.
    #[cfg(unix)]
    #[test]
    fn test_set_nonblocking_idempotent() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();

        set_nonblocking(&listener, true).expect("first call should succeed");
        set_nonblocking(&listener, true).expect("second call should also succeed");
        assert!(is_nonblocking(&listener).unwrap());
    }

    /// Verify that `make_tokio_socket` works on a valid standard TcpStream.
    #[cfg(unix)]
    #[test]
    fn test_make_tokio_socket_no_runtime() {
        // Without a Tokio runtime, `make_tokio_socket` should return
        // FailedInit because from_std requires an active reactor.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = std::net::TcpStream::connect(addr).unwrap();

        let result = make_tokio_socket(stream);
        // Without Tokio runtime, this should fail with FailedInit.
        assert!(
            result.is_err(),
            "make_tokio_socket without runtime should fail"
        );
        assert_eq!(
            result.unwrap_err(),
            CurlError::FailedInit,
            "error variant should be FailedInit"
        );
    }

    /// Verify that `make_tokio_socket` works inside a Tokio runtime context.
    /// We create a connected TCP pair and convert one end to a Tokio stream.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_make_tokio_socket() {
        // Create a TCP listener and connect to it to get a connected socket pair
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client = std::net::TcpStream::connect(addr).unwrap();
        let _server_conn = listener.accept().unwrap();

        // Convert std TcpStream to Tokio TcpStream (safe — no raw fd)
        let tokio_stream = make_tokio_socket(client);
        assert!(
            tokio_stream.is_ok(),
            "make_tokio_socket should succeed, got: {:?}",
            tokio_stream.err()
        );

        // Verify the stream is usable — local_addr should still work
        let stream = tokio_stream.unwrap();
        let local_addr = stream.local_addr();
        assert!(
            local_addr.is_ok(),
            "Tokio TcpStream should be functional"
        );
    }
}
